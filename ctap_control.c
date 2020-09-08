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
#include "libusbhid.h"
#include "api/libctap.h"
#include "ctap_protocol.h"
#include "ctap_control.h"
#include "ctap_hid.h"


#define CTAP_POLL_TIME      5 /* FIDO HID interface definition: Poll-time=5ms */
#define CTAP_DESCRIPOR_NUM  1 /* To check */


/* fido context .data initialization */
static ctap_context_t ctap_ctx = {
    .ctap_report = NULL,
    .idle = false,
    .curr_cid = 0,
    .locked = false,
    .idle_ms = 0,
    .hid_handler = 0,
    .usbxdci_handler = 0,
    .apdu_cmd = NULL,
    .report_sent = true,
    .recv_buf = { 0 },
    .ctap_cmd_buf_state = CTAP_CMD_BUFFER_STATE_EMPTY,
    .ctap_cmd_received = false,
    .ctap_cmd_size = 0,
    .ctap_cmd_idx = 0,
    .ctap_cmd = { 0 }
};

ctap_context_t *ctap_get_context(void)
{
    return &ctap_ctx;
}



mbed_error_t ctap_extract_pkt(ctap_context_t *ctx)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    switch (ctx->ctap_cmd_buf_state) {
        case CTAP_CMD_BUFFER_STATE_COMPLETE:
            errcode = MBED_ERROR_INVSTATE;
            goto err;
            break;
        case CTAP_CMD_BUFFER_STATE_EMPTY:
        {
            ctap_init_header_t *cmd = (ctap_init_header_t*)&ctx->recv_buf[0];
            uint16_t blen = 0;
            /* the pkt chunk in recv_pkt should be the first (maybe the only)
             * chunk. The header is a CTAPHID_INIT header holding bcnth and bcntl
             * fields */
            blen = (cmd->bcnth << 8) | cmd->bcntl;
            /* checking that len is not too long */
            if (blen > 256) {
                log_printf("[FIDO] fragmented packet too big for buffer! (%x bytes)\n", blen);
                errcode = MBED_ERROR_NOMEM;
                goto err;
            }
            ctx->ctap_cmd_size = blen;
            /* whatever the size is, we copy 64 bytes in the cmd into ctap_cmd. */
            memcpy((uint8_t*)(&ctx->ctap_cmd), &(ctx->recv_buf[0]), CTAPHID_FRAME_MAXLEN);
            /* is this the last chunk (no other) ? */
            /* set amount of data written */
            ctx->ctap_cmd_idx = CTAPHID_FRAME_MAXLEN - sizeof(ctap_init_header_t);
            if (ctx->ctap_cmd_idx >= blen) {
                /* all command bytes received, buffer complete */
                ctx->ctap_cmd_buf_state = CTAP_CMD_BUFFER_STATE_COMPLETE;
            } else {
                /* not all requested bytes received. Just buffering and continue */
                ctx->ctap_cmd_buf_state = CTAP_CMD_BUFFER_STATE_BUFFERING;
            }
            break;
        }
        case CTAP_CMD_BUFFER_STATE_BUFFERING:
        {
            /* here a previous chunk has already been received. Continue then */
            /* currently received content *must* be a sequence, not an init
             * frame */
            ctap_seq_header_t *cmd = (ctap_seq_header_t*)&ctx->recv_buf;
            if (cmd->cid != ctx->ctap_cmd.cid) {
                log_printf("[FIDO] current chunk sequence CID does not match intial CID!\n");
                errcode = MBED_ERROR_INVPARAM;
                goto err;
            }
            /* TODO: sequences should be incremental, starting at 0, values, they should
             * be checked for packet ordering...*/

            /* copy the packet data only (sequence header is dropped during refragmentation */
            memcpy((uint8_t*)(&ctx->ctap_cmd.data[ctx->ctap_cmd_idx]),
                   &(ctx->recv_buf[sizeof(ctap_seq_header_t)]),
                   CTAPHID_FRAME_MAXLEN - sizeof(ctap_seq_header_t));

            ctx->ctap_cmd_idx += CTAPHID_FRAME_MAXLEN - sizeof(ctap_seq_header_t);
            if (ctx->ctap_cmd_idx >= ctx->ctap_cmd_size) {
                /* all command bytes received, buffer complete */
                ctx->ctap_cmd_buf_state = CTAP_CMD_BUFFER_STATE_COMPLETE;
            } else {
                /* XXX: TODO: the effective calcuation of the max idx is to be done.
                 * As the packet is fragmented with multiple headers and the data
                 * size effective allowed length is 256, we must calculate how many
                 * packets of MAXLEN we can receive, and as a consequence, the copy
                 * limit properly... */
                if (ctx->ctap_cmd_idx > 210) {
                    /* Not complete, yet nearly no more space ! */
                    log_printf("[FIDO] fragmented packet too big for already consumed buffer!\n");
                    errcode = MBED_ERROR_NOMEM;
                    goto err;
                }
            }
            break;
        }
        default:
            errcode = MBED_ERROR_UNKNOWN;
            goto err;
            break;
    }

err:
    return errcode;
}


/********************************************************************
 * FIDO API
 */

mbed_error_t ctap_declare(uint8_t usbxdci_handler, ctap_handle_apdu_t apdu_handler)
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
    ctap_ctx.apdu_cmd = apdu_handler;

    log_printf("[CTAPHID] declare usbhid interface for FIDO CTAP\n");
    errcode = usbhid_declare(usbxdci_handler,
                             USBHID_SUBCLASS_NONE, USBHID_PROTOCOL_NONE,
                             CTAP_DESCRIPOR_NUM, CTAP_POLL_TIME, false,
                             64, &(ctap_ctx.hid_handler));
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

    errcode = MBED_ERROR_NONE;
err:
    return errcode;
}

mbed_error_t ctap_configure(void)
{
    return MBED_ERROR_NONE;
}

/* we initialize our OUT EP to be ready to receive, if needed. */
mbed_error_t ctap_prepare_exec(void)
{
    /*
     * First tour MUST BE a CTAPHID_INIT packet, which is less than CTAPHID_FRAME_MAXLEN size.
     */
    return usbhid_recv_report(ctap_ctx.hid_handler, (uint8_t*)&ctap_ctx.recv_buf, CTAPHID_FRAME_MAXLEN);
}

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
    /* TODO: set report to 0 */
    if (ctap_ctx.ctap_cmd_received) {
        log_printf("[CTAPHID] input CTAP cmd received\n");
        /* an CTAP command has been received! handle it! */
        /* is the packet fragmented ? If yes, just buffer it and continue.... */
        if ((errcode = ctap_extract_pkt(&ctap_ctx)) != MBED_ERROR_NONE) {
            log_printf("[CTAPHID] error during recv packet refragmentation, err=%x\n", errcode);
            goto err;
        }
        if (ctap_ctx.ctap_cmd_buf_state == CTAP_CMD_BUFFER_STATE_COMPLETE) {
            /* not fragmented ? if the buffer should handle a CTAPHID request that is clean
             * and ready to be handled. Let's treat it. */
            errcode = ctap_handle_request(&ctap_ctx.ctap_cmd);
        }
        ctap_ctx.ctap_cmd_received = false;
        /* XXX: it seems that the FIFO size is hard-coded to 64 bytes */
        usbhid_recv_report(ctap_ctx.hid_handler, (uint8_t*)&ctap_ctx.recv_buf, CTAPHID_FRAME_MAXLEN);
        /* now that current report/response has been consumed, ready to receive
         * new CTAP report. Set reception EP ready */
    }
err:
    return errcode;
}

/* local private API */

uint8_t ctap_get_usbhid_handler(void)
{
    return ctap_ctx.hid_handler;
}
