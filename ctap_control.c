/*
 *
 * Copyright 2019 The wookey project team <wookey@ssi.gouv.fr>
 *   - Ryad     Benadjila
 *   - Arnauld  Michelizza
 *   - Mathieu  Renard
 *   - Philippe Thierry
 *   - Philippe Trebuchet
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * the Free Software Foundation; either version 3 of the License, or (at
 * ur option) any later version.
 *
 * This package is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this package; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "libc/types.h"
#include "libc/string.h"
#include "libc/sync.h"
#include "libc/time.h"
#include "libc/signal.h"
#include "libc/errno.h"
#include "libusbhid.h"
#include "api/libctap.h"
#include "ctap_protocol.h"
#include "ctap_control.h"
#include "ctap_hid.h"
#include "ctap_chan.h"


#define CTAP_POLL_TIME      5 /* FIDO HID interface definition: Poll-time=5ms */
#define CTAP_DESCRIPOR_NUM  1 /* To check */


/* fido contexts .data initialization */
static ctap_context_t ctap_ctx = {
    .ctap_report = NULL,
    .ctap_report_received = false,
    .ctap_report_size = false,
    .idle = false,
    .curr_cid = 0,
    .locked = false,
    .idle_ms = 0,
    .hid_handler = 0,
    .usbxdci_handler = 0,
    .apdu_cmd = NULL,
    .report_sent = true,
    .recv_buf = { 0 },
};



ctap_context_t *ctap_get_context(void)
{
    return &ctap_ctx;
}


mbed_error_t ctaphid_receive_pkt(ctap_context_t *ctx)
{
    mbed_error_t error;

    /* listen on data */
    usbhid_recv_report(ctap_ctx.hid_handler, (uint8_t*)&ctap_ctx.recv_buf, CTAPHID_FRAME_MAXLEN);
    while(!ctx->ctap_report_received);
    ctx->ctap_report_received = false;  

    /* Sanity check on size */
    if(ctx->ctap_report_size != CTAPHID_FRAME_MAXLEN){
        error = MBED_ERROR_INVPARAM;
        goto err;
    }
    ctx->ctap_report_size = 0;

    /* We have a frame, get the CID */
    ctap_init_cmd_t *init_cmd = (ctap_init_cmd_t*)&ctx->recv_buf[0];
    ctx->curr_cid = init_cmd->header.cid;
    /* Check if we are already treating this CID */
    if(!ctap_cid_exists(init_cmd->header.cid) && (init_cmd->header.cid != CTAPHID_BROADCAST_CID)){
        /* We are not treating the CID, and this is not a CTAPHID_BROADCAST_CID */
        log_printf("[CTAPHID] u2f_hid_receive_frame: error in CID %x: neither existing nor CTAPHID_BROADCAST_CID\n", init_cmd->header.cid);
        error = MBED_ERROR_INVPARAM;
        goto err; 
    }
    /* In case of broadcast, we prepare a special broadcast frame */
    if(init_cmd->header.cid == CTAPHID_BROADCAST_CID){
        /* Only INIT accepts broadcast frames */
        if(!(init_cmd->header.cmd & 0x80) || ((init_cmd->header.cmd & 0x7f) != CTAP_INIT)){
            error = MBED_ERROR_INVPARAM;
            goto err;
        }
        error = ctap_cid_add(CTAPHID_BROADCAST_CID);
        /* No more slots available ... return an error */
        if(error != MBED_ERROR_NONE){
            /* The lower layer will respond a "BUSY" channel */
            error = MBED_ERROR_NOMEM;
            goto err;
        }
    }
    /* Get the channel we are treating */
    chan_ctx_t *chan_ctx = ctap_cid_get_chan_ctx(init_cmd->header.cid);
    if(chan_ctx == NULL){
        /* This should not happen */
        error = MBED_ERROR_UNKNOWN;
        goto err;
    }
    /* We should not treat "complete" commands here */
    if(chan_ctx->ctap_cmd_received){
        error = MBED_ERROR_INVSTATE;
        goto err;
    }
    /* Do we have a SYNC frame? */
    if((init_cmd->header.cmd & 0x80) && ((init_cmd->header.cmd & 0x7f) == CTAP_SYNC)){
        /* Resynchronize by deleting our current CID */
        log_printf("[CTAPHID] received SYNC during seq\n");
        ctap_cid_remove(ctx->curr_cid);
        error = MBED_ERROR_NONE;
        goto err;    
    } 
    /* Is it an initialization packet or a sequence packet? */
    if(chan_ctx->ctap_cmd_size == 0){
        /* This is a regular initial packet */
        uint16_t blen = (init_cmd->header.bcnth << 8) | init_cmd->header.bcntl;
        chan_ctx->ctap_cmd_size = blen;
        chan_ctx->ctap_cmd_idx = 0;
        chan_ctx->ctap_cmd_seq = 0;
        /* Embedded command */
        chan_ctx->ctap_cmd.cid = init_cmd->header.cid;
        chan_ctx->ctap_cmd.cmd = init_cmd->header.cmd;
        chan_ctx->ctap_cmd.bcnth = init_cmd->header.bcnth;
        chan_ctx->ctap_cmd.bcntl = init_cmd->header.bcntl;
        uint16_t pkt_data_sz = CTAPHID_FRAME_MAXLEN - sizeof(ctap_init_header_t);
        if(blen <= pkt_data_sz){
            pkt_data_sz = blen;
            /* We do not expect more data: tell that we are done! */
            chan_ctx->ctap_cmd_received = true;
        }
        /* Sanity check */ 
        if(sizeof(chan_ctx->ctap_cmd.data) < pkt_data_sz){
            error = MBED_ERROR_UNKNOWN;
            goto err;
        }
        /* Copy the current data and increment our index */
        memcpy(&(chan_ctx->ctap_cmd.data[0]), &(init_cmd->data[0]), pkt_data_sz);
        chan_ctx->ctap_cmd_idx += pkt_data_sz;
    }
    else{
        /* We are agregating here, we only expect SEQ packets! */
        ctap_seq_cmd_t *seq_cmd = (ctap_seq_cmd_t*)&ctx->recv_buf[0];
        /* Sanity check on sequence */
        if((seq_cmd->header.seq != chan_ctx->ctap_cmd_seq) || (seq_cmd->header.seq > 0x7f)){
            log_printf("[CTAPHID] u2f_hid_receive_frame: error in SEQ %d != %d or > 0x7f ...\n", seq_cmd->header.seq, chan_ctx->ctap_cmd_seq);
            error = MBED_ERROR_INVSTATE;
            goto err;
        }
        /* Sanity checks */
        if(chan_ctx->ctap_cmd_idx >= chan_ctx->ctap_cmd_size){
            error = MBED_ERROR_UNKNOWN;
            goto err;
        } 
        /* Aggregate the data */
        uint16_t pkt_data_sz = CTAPHID_FRAME_MAXLEN - sizeof(ctap_seq_header_t);
        if(pkt_data_sz > (chan_ctx->ctap_cmd_size - chan_ctx->ctap_cmd_idx)){
            pkt_data_sz = (chan_ctx->ctap_cmd_size - chan_ctx->ctap_cmd_idx);
        }
        /* Sanity checks */
        if(sizeof(chan_ctx->ctap_cmd.data) < (chan_ctx->ctap_cmd_idx + pkt_data_sz)){
            error = MBED_ERROR_UNKNOWN;
            goto err;
        }
        /* Aggregate in buffer */
        memcpy(&(chan_ctx->ctap_cmd.data[chan_ctx->ctap_cmd_idx]), &(seq_cmd->data[0]), pkt_data_sz);
        /* Increment sequence to receive */
        chan_ctx->ctap_cmd_seq++;
        /* Increment idx */
        chan_ctx->ctap_cmd_idx += pkt_data_sz;
        /* Are we done? */
        if(chan_ctx->ctap_cmd_idx >= chan_ctx->ctap_cmd_size){
            chan_ctx->ctap_cmd_received = true;
        }
    }
    /* pull down received flag */
    error = MBED_ERROR_NONE;
err:
    return error;

}



/********************************************************************
 * FIDO API
 */

mbed_error_t ctap_declare(uint8_t usbxdci_handler, ctap_handle_apdu_t apdu_handler, ctap_handle_wink_t wink_handler)
{
    mbed_error_t errcode = MBED_ERROR_UNKNOWN;
    /* first initializing basics of local context */
    ctap_ctx.usbxdci_handler = usbxdci_handler;
    ctap_ctx.ctap_report = ctap_get_report();
    if (apdu_handler == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        log_printf("%s: APDU handler is NULL\n", __func__);
        goto err;
    }
    if (wink_handler == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        log_printf("%s: Wink handler is NULL\n", __func__);
        goto err;
    }
    ctap_ctx.apdu_cmd = apdu_handler;
    ctap_ctx.wink_cmd = wink_handler;

    log_printf("[CTAPHID] declare usbhid interface for FIDO CTAP\n");
    errcode = usbhid_declare(usbxdci_handler,
                             USBHID_SUBCLASS_NONE, USBHID_PROTOCOL_NONE,
                             CTAP_DESCRIPOR_NUM, CTAP_POLL_TIME, true,
                             64, &(ctap_ctx.hid_handler),
                                 (uint8_t*)&ctap_ctx.recv_buf,
                                 CTAPHID_FRAME_MAXLEN);
    if (errcode != MBED_ERROR_NONE) {
        log_printf("[CTAPHID] failure while declaring FIDO interface: err=%d\n", errcode);
        goto err;
    }
    /* configure HID interface */
    log_printf("[CTAPHID] configure usbhid device\n");
    errcode = usbhid_configure(ctap_ctx.hid_handler,
                     usbhid_get_report,
                     NULL, /* set report */
                     NULL, /* set proto */
                     usbhid_set_idle);
    if (errcode != MBED_ERROR_NONE) {
        log_printf("[CTAPHID] failure while configuring FIDO interface: err=%d\n", errcode);
        goto err;
    }

    log_printf("[CTAPHID] configuration done\n");
    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}

/**************
 * About timer: an alarm is executed every second to clear used CID older than 1s
 */

void ctap_timer_notify(__sigval_t sig __attribute__((unused))) {
    ctap_cid_periodic_clean();
}

static timer_t timerid;
static struct sigevent sevp = { 0 };
static struct itimerspec its = { 0 };


mbed_error_t ctap_configure(void)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /* in that case, any Set_Report (DATA OUT) is pushed to dedicated OUT EP instead
     * of EP0. This avoid using control plane for DATA content. Althgouh,
     * we have to configure this EP in order to be ready to receive the report */
    usbhid_recv_report(ctap_ctx.hid_handler, ctap_ctx.recv_buf, CTAPHID_FRAME_MAXLEN);

    /* let's start Channel ID auto-cleaner */
    sevp.sigev_notify_function = ctap_timer_notify;
    sevp.sigev_value.sival_ptr = &timerid;
    sevp.sigev_signo = 0;
    sevp.sigev_notify = SIGEV_THREAD;

    memset(&its, 0x0, sizeof(struct itimerspec));
    its.it_interval.tv_sec = 1; /* CID clean every 1 sec */
    its.it_interval.tv_nsec = 0;

    its.it_value.tv_sec = 1; /* CID clean first step: 1 sec */
    its.it_value.tv_nsec = 0;

    if (timer_create(CLOCK_MONOTONIC, &sevp, &timerid) == -1) {
        log_printf("[CTAP] periodic timer create failed with errno %d\n", errno);
        errcode = MBED_ERROR_UNKNOWN;
        goto err;
    } else {
        if (timer_settime(timerid, 0, &its, NULL) == -1) {
            printf("[CTAP] periodic timer settime failed with errno %d\n", errno);
            errcode = MBED_ERROR_UNKNOWN;
            goto err;
        }
    }

err:
    return errcode;
}

/* we initialize our OUT EP to be ready to receive, if needed. */
/*
 * Executing a single loop:
 *  - get back potential cmd
 *  - parse command, request backend execution
 *  - get back backend response
 *  - return potential response to host
 */
mbed_error_t ctap_exec(void)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    /*TODO: 64ms poll time, hardcoded in libusbctrl by now */
    //uint32_t wait_time = CTAP_POLL_TIME;

    /* the Get_Report() request should be transmitted before starting
     * to send periodic reports */
    if (ctap_ctx.report_sent == false) {
        /* wait for previous report to be sent first */
        goto err;
    }
    errcode = ctaphid_receive_pkt(&ctap_ctx);
    switch (errcode) {
        case MBED_ERROR_NONE: {
            /* Parse all the channels to check if we have a complete command, and if yes execute it! */
            ctap_cmd_t *cmd = ctap_cid_get_chan_complete_cmd();
            if(cmd != NULL){
                /* Execute our command */
                errcode = ctap_handle_request(cmd);
                /* Remove any broadcast command */
                ctap_cid_remove(CTAPHID_BROADCAST_CID);
                /* Mark the commands associated to CID as non treated 
                 * since we are ready to treat a new one, and clear its
                 * buffer states!
                 */
                ctap_cid_clear_cmd(cmd->cid);
            }
            /* Else, continue our receive loop! */
            break;
        }
        case MBED_ERROR_NOMEM:{
            ctap_init_cmd_t *cmd = (ctap_init_cmd_t*)&(ctap_ctx.recv_buf[0]);
            errcode = handle_rq_error(cmd->header.cid, U2F_ERR_CHANNEL_BUSY);
            break;
        }
        case MBED_ERROR_INVSTATE:{
            ctap_init_cmd_t *cmd = (ctap_init_cmd_t*)&(ctap_ctx.recv_buf[0]);
            errcode = handle_rq_error(cmd->header.cid, U2F_ERR_INVALID_SEQ);
            break;
        }
        case MBED_ERROR_INVPARAM:{
            ctap_init_cmd_t *cmd = (ctap_init_cmd_t*)&(ctap_ctx.recv_buf[0]);
            errcode = handle_rq_error(cmd->header.cid, U2F_ERR_INVALID_PAR);
            break;
        }
        default: {
            ctap_init_cmd_t *cmd = (ctap_init_cmd_t*)&(ctap_ctx.recv_buf[0]);
            errcode = handle_rq_error(cmd->header.cid, U2F_ERR_INVALID_CMD);
            break;
        }
    }
err:
    return errcode;
}

/* local private API */

uint8_t ctap_get_usbhid_handler(void)
{
    return ctap_ctx.hid_handler;
}
