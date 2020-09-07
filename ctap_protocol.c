#include "libc/string.h"
#include "libusbhid.h"
#include "ctap_control.h"
#include "ctap_protocol.h"


typedef union {
    ctap_init_header_t     init;
    ctap_seq_header_t seq;
} ctap_resp_headers_t;

/* a response can be seen as a header with a trailing data
 * or a uint8_t data flow of upto 64 bytes len */
typedef union {
    ctap_resp_headers_t  header;
    uint8_t    data[64]; /* all responses are padded to 64 bytes */
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
static mbed_error_t ctaphid_send_response(uint8_t *resp, uint16_t resp_len, uint32_t cid, uint8_t cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint8_t sequence = 0;
    /* sanitize first */
    if (resp == NULL) {
        log_printf("[CTAP] invalid response buf %x\n", resp);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (resp_len == 0) {
        log_printf("[CTAP] invalid response len %x\n", resp_len);
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    if (resp_len > 256) {
        log_printf("[CTAP] invalid response len %x\n", resp_len);
        /* data[] field is defined as upto 256 bytes length. This test is also
         * a protection against integer overflow in the idx++ loop below */
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }

    /* we know that the effective response buffer is upto ctap_resp_header_t + 256 bytes
     * (defined in the FIDO U2F standard). Finally, we can only push upto 64 bytes at a time.
     */
    /* total response content to handle */
    uint32_t pushed_bytes = 0;

    ctap_resp_t full_resp = { 0 };
    uint32_t offset = 0;
    uint32_t max_resp_len = 0;
    do {
        /* cleaning potential previous frames */
        memset(&full_resp.data[0], 0x0, 64);
        if (pushed_bytes == 0) {
            log_printf("[CTAP] first response chunk\n");
            /* first pass */
            full_resp.header.init.cid = cid;
            full_resp.header.init.cmd = cmd;
            full_resp.header.init.bcnth = (resp_len & 0xff00) >> 8;
            full_resp.header.init.bcntl = (resp_len & 0xff);
            offset = sizeof(ctap_init_header_t);
            max_resp_len = CTAPHID_FRAME_MAXLEN - offset;
        } else {
            log_printf("[CTAP] sequence response chunk\n");
            full_resp.header.seq.cid = cid;
            full_resp.header.seq.seq = sequence;
            sequence++;
            offset = sizeof(ctap_seq_header_t);
            max_resp_len = CTAPHID_FRAME_MAXLEN - offset;
        }
        /*now handle effective response content */
        uint32_t idx = pushed_bytes;
        while (idx < resp_len && idx <= max_resp_len) {
            full_resp.data[offset] = resp[idx];
            offset++;
            idx++;
        }
        /* here, full_resp is ready to be sent. Its size can be 64 bytes length
         * or less (offset value). We send the current report chunk here. */
        log_printf("[CTAP] Sending report chunk (offset %d)\n", idx);
        usbhid_send_report(ctap_get_usbhid_handler(), &(full_resp.data[0]), USBHID_OUTPUT_REPORT, 0);
        /* updated pushed_bytes count */
        pushed_bytes = idx;
    } while (pushed_bytes < resp_len);

    /* here, all chunk(s) has been sent. All are upto CTAPHID_FRAME_MAXLEN. The total length
     * is defined by resp_len and set in the first chunk header. */

err:
    return errcode;
}

static inline mbed_error_t handle_rq_error(uint32_t cid, ctab_error_code_t hid_error)
{
    /* C enumerate length may vary depending on the compiler. Thouht, the
     * HID error type is defined to handle unsigned values up to 256 max */
    uint8_t error = hid_error;
    return ctaphid_send_response((uint8_t*)&error, sizeof(uint8_t), cid, CTAP_INIT|0x80);
}


/*******************************************************************
 * Each request effective handling. These functions may depend on local utility (see above)
 * or on FIDO cryptographic backend (effective FIDO U2F cryptographic implementation
 * in the Token).
 */
/*
 * Handling CTAPHID_MSG command
 */
static mbed_error_t handle_rq_msg(const ctap_cmd_t* cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
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
#if 0
    /* TODO channel to handle */
    if (channel_exists(cid) == false) {
        /* invalid channel */
        log_printf("[CTAP][MSG] New CID: %f\n", cid);
        handle_rq_error(cid, U2F_ERR_INVALID_PAR);
        goto err;
    }
#endif

    /* now that header is sanitized, let's push the data content
     * to the backend
     * FIXME: by now, calling APDU backend, no APDU vs CBOR detection */
    uint8_t msg_resp[256] = { 0 };
    uint16_t resp_len = 0;

#if 0
    /* MSG in CTAP1 cotnains APDU data. This should be passed to backend APDU through
     * predefined callback, in the case where libapdu is handled in a different task.
     * This callback is responsible for passing the APDU content to whatever is
     * responsible for the APDU parsing, FIDO effective execution and result return */
    errcode = apdu_handle_request(msg_resp, &resp_len);
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
    }
    if (curcid == CTAPHID_BROADCAST_CID) {
#if 0
        /* new channel request */
        channel_create(&newcid);
        log_printf("[CTAP][INIT] New CID: %x\n", newcid);
#endif
    } else {
        newcid = curcid;
    }
    ctap_resp_init_t init_resp = { 0 };
    for (uint8_t i = 0; i < 8; ++i) {
      init_resp.nonce[i] = cmd->data[i];
    }

    init_resp.chanid = newcid;
    init_resp.proto_version = USBHID_PROTO_VERSION;
    init_resp.major_n = 0;
    init_resp.minor_n = 0;
    init_resp.build_n = 0;
    init_resp.capa_f = CTAP_CAPA_WINK;

    log_printf("[CTAP][INIT] Sending back response\n");
    errcode = ctaphid_send_response((uint8_t*)&init_resp, sizeof(ctap_resp_init_t), curcid, CTAP_INIT|0x80);
err:
    return errcode;
}


/******************************************************
 * Requests dispatcher
 */

mbed_error_t ctap_handle_request(const ctap_cmd_t *ctap_cmd)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
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
            break;
        }
        case CTAP_MSG:
        {
            log_printf("[CTAPHID] received U2F MSG\n");
            break;
        }
        case CTAP_ERROR:
        {
            log_printf("[CTAPHID] received U2F ERROR\n");
            break;
        }
        case CTAP_WINK:
        {
            log_printf("[CTAPHID] received U2F WINK\n");
            break;
        }
        case CTAP_LOCK:
        {
            log_printf("[CTAPHID] received U2F LOCK\n");
            break;
        }
        default:
            log_printf("[CTAPHID] Unkown cmd %d\n", ctap_cmd);
            break;
    }
err:
    return errcode;
}
