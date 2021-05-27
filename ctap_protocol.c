#include "libc/string.h"
#include "libc/sync.h"
#include "libusbhid.h"
#include "ctap_control.h"
#include "ctap_chan.h"
#include "ctap_protocol.h"


typedef union {
    ctap_init_header_t     init;
    ctap_seq_header_t      seq;
} ctap_resp_t;




/*******************************************************************
 * local utility functions, that handle errors, response transmission
 * and so on....
 */

/*
 * A CTAP response may be bigger than the CTAP Out endpoint MPSize.
 * If it does, this function is responsible for fragmenting the response
 * into successive blocks to which a ctap_resp_msg_t header is added,
 * and then pushed to the endpoint. The first frame sent is always a CTAP INIT
 * frame (with CID, cmd, bcnt). Others successive ones are CTAP CONT
 * (cid and sequence identifier, no cmd, no bcnt - i.e. bcnt is flow global)
 */
static mbed_error_t ctaphid_send_response(uint8_t *resp, const uint16_t resp_len, uint32_t cid, uint8_t cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint8_t sequence = 0;
    /* sanitize first */
    if (resp == NULL && resp_len != 0) {
        log_printf("[CTAP] invalid response buf %x\n", resp);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    log_printf("[CTAPHID] CID 0x%x: 0x%x (%d) bytes to send\n", cid, resp_len, resp_len);
    /* we know that the effective response buffer is upto ctap_resp_header_t + 256 bytes
     * (defined in the FIDO U2F standard). Finally, we can only push upto 64 bytes at a time.
     */
    /* total response content to handle */
    uint32_t offset = 0;
    uint32_t max_resp_len = 0;
    uint32_t idx = 0;
    bool new_seq = true;
    do {
        uint32_t len = 0;
        offset = 0;
        ctap_init_cmd_t full_init_resp = { 0 };
        ctap_seq_cmd_t full_seq_resp = { 0 };
        if (new_seq == true) {
        /* cleaning potential previous frames */
            log_printf("[CTAP] first response chunk\n");
            /* first pass */
            full_init_resp.header.cid = cid;
            full_init_resp.header.cmd = cmd;
            full_init_resp.header.bcnth = (resp_len & 0xff00) >> 8;
            full_init_resp.header.bcntl = (resp_len & 0xff);
            max_resp_len = CTAPHID_FRAME_MAXLEN - sizeof(ctap_init_header_t);
        } else {
            log_printf("[CTAP] sequence response chunk\n");
            full_seq_resp.header.cid = cid;
            full_seq_resp.header.seq = sequence;
            max_resp_len = CTAPHID_FRAME_MAXLEN - sizeof(ctap_seq_header_t);
            sequence++;
        }
        /* remaining size in frame for data (after header) */

        /*now copy effective response content to current chunk */
        if (new_seq == true) {
            /* if resp is NULL, resp_len is 0, while is not executed */
            while (idx < resp_len && offset < max_resp_len) {
                full_init_resp.data[offset] = resp[idx];
                offset++;
                idx++;
            }
        } else {
            /* if resp is NULL, resp_len is 0, while is not executed */
            while (idx < resp_len && offset < max_resp_len) {
                full_seq_resp.data[offset] = resp[idx];
                offset++;
                idx++;
            }
        }
        /* here, full_resp is ready to be sent. Its size can be 64 bytes length
         * or less (offset value). We send the current report chunk here. */

        if (new_seq == true) {
            /* amount to send */
            len = offset + sizeof(ctap_init_header_t);
            log_printf("[CTAP] Sending response first chunk headersize:%d; data:%d (len %d)\n", sizeof(ctap_init_header_t), offset, len);
            if (len < CTAPHID_FRAME_MAXLEN) {
                /* padding to mpsize */
                len = CTAPHID_FRAME_MAXLEN;
            }
            usbhid_send_response(ctap_get_usbhid_handler(), (uint8_t*)&full_init_resp, len);
        } else {
            len = offset + sizeof(ctap_seq_header_t);
            log_printf("[CTAP] Sending resp seq chunk headersize:%d; data:%d (len %d)\n", sizeof(ctap_seq_header_t), offset, len);
            if (len < CTAPHID_FRAME_MAXLEN) {
                /* padding to mpsize */
                len = CTAPHID_FRAME_MAXLEN;
            }
            usbhid_send_response(ctap_get_usbhid_handler(), (uint8_t*)&full_seq_resp, len);
        }
        /* updated pushed_bytes count */
        log_printf("[CTAP] sending %d bytes on %d\n", idx, resp_len);
        /* the first time we get here, we have send the first chunk. Each other times are consecutive
         * chunks */
        new_seq = false;
    } while (idx < resp_len);

    /* here, all chunk(s) has been sent. All are upto CTAPHID_FRAME_MAXLEN. The total length
     * is defined by resp_len and set in the first chunk header. */
    /* finishing with ZLP */
    //usb_backend_drv_send_zlp(epid);
    usbhid_response_done(ctap_get_usbhid_handler());

err:
    return errcode;
}


/*******************************************************************
 * Each request effective handling. These functions may depend on local utility (see above)
 * or on FIDO cryptographic backend (effective FIDO U2F cryptographic implementation
 * in the Token).
 */


mbed_error_t handle_rq_error(uint32_t cid, uint8_t error)
{
	/* Prepare our frame */
        ctap_init_cmd_t frame;
	memset(&frame, 0, sizeof(frame));

	/* Send the frame on the line */
	if(ctaphid_send_response((uint8_t*)&error, 1, cid, CTAP_ERROR | 0x80)) {
		goto err;
	}

	return MBED_ERROR_NONE;

err:
	log_printf("[CTAPHID] u2f_hid_send_error: send error\n");
	return MBED_ERROR_UNKNOWN;
}

/*
 * Handling CTAPHID_MSG command
 */
static mbed_error_t handle_rq_msg(ctap_cmd_t* cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    ctap_context_t *ctx = ctap_get_context();
    uint32_t cid = cmd->cid;
    /* CTAPHID level sanitation */
    /* endianess... */
    uint16_t bcnt = (cmd->bcnth << 8) | cmd->bcntl;
    if (bcnt < 4) {
        log_printf("[CTAP] CTAP_MSG pkt len must be at least 4, found %d\n", bcnt);
        handle_rq_error(cid, U2F_ERR_INVALID_PAR);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (cid == 0 || cid == CTAPHID_BROADCAST_CID) {
        log_printf("[CTAP] CTAP_INIT CID must be nonzero\n");
        handle_rq_error(cid, U2F_ERR_INVALID_PAR);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    /* TODO channel to handle */
    if (!ctap_cid_exists(cid)) {
        /* invalid channel */
        log_printf("[CTAP][MSG] New CID: %x\n", cid);
        handle_rq_error(cid, U2F_ERR_INVALID_PAR);
        goto err;
    }

    /* now that header is sanitized, let's push the data content
     * to the backend
     * FIXME: by now, calling APDU backend, no APDU vs CBOR detection */
    uint8_t msg_resp[1024] = { 0 };
    uint16_t resp_len = sizeof(msg_resp);

#if 1
    /* MSG in CTAP1 cotains APDU data. This should be passed to backend APDU through
     * predefined callback, in the case where libapdu is handled in a different task.
     * This callback is responsible for passing the APDU content to whatever is
     * responsible for the APDU parsing, FIDO effective execution and result return */
    uint16_t val = (cmd->bcnth << 8) + cmd->bcntl;
    errcode = ctx->apdu_cmd(0, &(cmd->data[0]), val, &(msg_resp[0]), &resp_len);
        //apdu_handle_request(msg_resp, &resp_len);
    if (errcode != MBED_ERROR_NONE) {
        log_printf("[CTAP][MSG] APDU requests handling failed!\n");
        handle_rq_error(cid, U2F_ERR_INVALID_CMD);
        goto err;
    }
#endif
    log_printf("[CTAP][MSG] Sending back response\n");
    errcode = ctaphid_send_response(&msg_resp[0], resp_len, cid, CTAP_MSG|0x80);
err:
    return errcode;
}

static mbed_error_t handle_rq_ping(const ctap_cmd_t* cmd)
{
    uint16_t len = (cmd->bcnth << 8) + cmd->bcntl;
    return ctaphid_send_response((uint8_t*)cmd->data, len, cmd->cid, CTAP_PING|0x80);
}

static mbed_error_t handle_rq_sync(const ctap_cmd_t* cmd)
{
    return ctaphid_send_response(NULL, 0, cmd->cid, CTAP_SYNC|0x80);
}


static mbed_error_t handle_rq_wink(const ctap_cmd_t* cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    ctap_context_t *ctx = ctap_get_context();
    uint16_t len = ((cmd->bcnth << 8) + cmd->bcntl);
	/* We expect 0 data */
    if (len != 0) {
        log_printf("[CTAPHID] invalid size for wink request (len == %d)\n", len);
        errcode = handle_rq_error(cmd->cid, U2F_ERR_INVALID_LEN);
        goto err;
    }
    /* first do something for user interaction (500ms)... */
    if (ctx->wink_cmd != NULL) {
        ctx->wink_cmd(500);
    }
    /* and return back content */
    errcode = ctaphid_send_response(NULL, 0, cmd->cid, cmd->cmd);
err:
    return errcode;
}

static mbed_error_t handle_rq_lock(const ctap_cmd_t*cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    ctap_context_t *ctx = ctap_get_context();

    uint16_t len = (cmd->bcnth << 8) + cmd->bcntl + sizeof(ctap_init_header_t);
	/* We expect 0 data */
    if (len != 1) {
       errcode = handle_rq_error(cmd->cid, U2F_ERR_INVALID_LEN);
       goto err;
    }
    if (cmd->data[0] > 10) {
		/* Only timeouts <= 10 seconds are allowed! */
       errcode = handle_rq_error(cmd->cid, U2F_ERR_INVALID_PAR);
       goto err;
    }
    set_bool_with_membarrier(&(ctx->locked), true);

    errcode = ctaphid_send_response(NULL, 0, cmd->cid, CTAP_LOCK|0x80);

    /**
     * TODO: set ctx as locked for the amount of time set in data[0]
     */

err:
    return errcode;
}


#define INIT_NONCE_SIZE 8
/*
 * Handling CTAPHID_INIT command
 */
static mbed_error_t handle_rq_init(const ctap_cmd_t* cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint32_t curcid = cmd->cid;
    uint32_t newcid = 0;
    /* CTAPHID level sanitation */
    /* endianess... */
    uint16_t bcnt = (cmd->bcnth << 8) | cmd->bcntl;
    if (bcnt != 8) {
        log_printf("[CTAP] CTAP_INIT pkt len must be 8, found %d\n", bcnt);
        log_printf("[CTAP] bcnth: %x, bcntl: %x\n", cmd->bcnth, cmd->bcntl);
        handle_rq_error(curcid, U2F_ERR_INVALID_PAR);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (cmd->cid == 0) {
        log_printf("[CTAP] CTAP_INIT CID must be nonzero\n");
        handle_rq_error(curcid, U2F_ERR_INVALID_PAR);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
        /* new channel request */
    } else {
        newcid = curcid;
    }
    uint8_t resp[17] = { 0 };
    memcpy(&(resp[0]), cmd->data, INIT_NONCE_SIZE);

    if (cmd->cid == CTAPHID_BROADCAST_CID) {
        /* Remove the BROADCAST CID */
        ctap_cid_remove(CTAPHID_BROADCAST_CID);
	/* Allocate next CID */
        ctap_cid_generate(&newcid);
        errcode = ctap_cid_add(newcid);
        if(errcode != MBED_ERROR_NONE){
            handle_rq_error(CTAPHID_BROADCAST_CID, U2F_ERR_CHANNEL_BUSY);
            errcode = MBED_ERROR_NOMEM;
            goto err;
        }
        log_printf("[CTAP][INIT] New CID: %x\n", newcid);
        *(uint32_t*)(&(resp[INIT_NONCE_SIZE])) = newcid;
        curcid = CTAPHID_BROADCAST_CID;
    } else{        
        /* This is a synchronization request, respond with the asking CID that
         * has been checked to be existing by the upper layer.
         */
        curcid = cmd->cid;
     }
     /* Version identifiers */
     resp[12] = USBHID_PROTO_VERSION; // U2FHID protocol version identifier
     resp[13] = 0; // Major device version number
     resp[14] = 0; // Minor device version number
     resp[15] = 0; // Build device version number
     /* Capabilities flag: we accept the WINK command */
     resp[16] = CTAP_CAPA_WINK|CTAP_CAPA_LOCK; // Capabilities flags
     /* Send the frame on the line */

     log_printf("[CTAP][INIT] Sending back response\n");
     errcode = ctaphid_send_response((uint8_t*)&resp, sizeof(resp), curcid, CTAP_INIT|0x80);

err:
    return errcode;
}





/******************************************************
 * Requests dispatcher
 */

mbed_error_t ctap_handle_request(ctap_cmd_t *ctap_cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    ctap_context_t *ctx = ctap_get_context();
    uint8_t cmd;
    if (ctap_cmd == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if ((ctap_cmd->cmd & 0x80) == 0) {
        log_printf("[CTAP] CMD bit 7 must always be set\n");
        handle_rq_error(ctap_cmd->cid, U2F_ERR_INVALID_PAR);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if((ctx->locked == true) && (ctx->curr_cid != ctap_cmd->cid)){
        errcode = handle_rq_error(ctap_cmd->cid, U2F_ERR_CHANNEL_BUSY);
  	return errcode;
    }
    set_u32_with_membarrier(&(ctx->curr_cid), ctap_cmd->cid);

    /* cleaning bit 7 (always set, see above) */
    cmd = ctap_cmd->cmd & 0x7f;
    switch (cmd) {
        case CTAP_INIT:
        {
            log_printf("[CTAPHID] received U2F INIT\n");
            errcode = handle_rq_init(ctap_cmd);
            break;
        }
        case CTAP_PING:
        {
            log_printf("[CTAPHID] received U2F PING\n");
            errcode = handle_rq_ping(ctap_cmd);
            break;
        }
        case CTAP_MSG:
        {
            log_printf("[CTAPHID] received U2F MSG\n");
            errcode = handle_rq_msg(ctap_cmd);
            break;
        }
        case CTAP_ERROR:
        {
            log_printf("[CTAPHID] received U2F ERROR\n");
            errcode = handle_rq_error(ctap_cmd->cid, U2F_ERR_INVALID_CMD);
            break;
        }
        case CTAP_WINK:
        {
            log_printf("[CTAPHID] received U2F WINK\n");
            errcode = handle_rq_wink(ctap_cmd);
            break;
        }
        case CTAP_LOCK:
        {
            log_printf("[CTAPHID] received U2F LOCK\n");
            errcode = handle_rq_lock(ctap_cmd);
            break;
        }
        case CTAP_SYNC:
        {
            log_printf("[CTAPHID] received U2F SYNC\n");
            errcode = handle_rq_sync(ctap_cmd);
            break;
        }
        default:
            log_printf("[CTAPHID] Unkown cmd %d\n", ctap_cmd);
            errcode = handle_rq_error(ctap_cmd->cid, U2F_ERR_INVALID_CMD);
            break;
    }
err:
    return errcode;
}
