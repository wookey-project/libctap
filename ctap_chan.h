#ifndef CTAP_CHANNEL_H_
#define CTAP_CHANNEL_H_

#include "autoconf.h"
#include "libc/types.h"
#include "ctap_control.h"

#define MAX_CIDS 5
#define CID_LIFETIME 4000 /* 4 seconds */

typedef struct {
    uint64_t last_used;
    uint32_t cid;
    bool      busy;
    bool      ctap_cmd_received;
    uint16_t  ctap_cmd_size;
    uint16_t  ctap_cmd_idx;
    uint16_t  ctap_cmd_seq;
    ctap_cmd_t         ctap_cmd;
} chan_ctx_t;

chan_ctx_t *ctap_cid_get_chan_ctx(uint32_t cid);

ctap_cmd_t *ctap_cid_get_chan_complete_cmd(void);

ctap_cmd_t *ctap_cid_get_chan_cmd(uint32_t cid);

mbed_error_t ctap_cid_generate(uint32_t *cid);

mbed_error_t ctap_cid_add(uint32_t newcid);

bool ctap_cid_exists(uint32_t cid);

mbed_error_t ctap_cid_refresh(uint32_t cid);

mbed_error_t ctap_cid_remove(uint32_t cid);

mbed_error_t ctap_cid_periodic_clean(void);

mbed_error_t ctap_cid_clear_cmd(uint32_t cid);

void ctap_cid_dump(void);

#endif/*!CTAP_CHANNEL_H_*/
