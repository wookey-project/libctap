#include "ctap_chan.h"
#include "ctap_control.h"

#define MAX_CIDS 32

typedef struct {
    bool     used;
} chan_ctx_t;

/*XXX: test, 32 concurrent CID at a time */
chan_ctx_t chans[MAX_CIDS] = { 0 };

mbed_error_t ctap_channel_create(uint32_t *newcid)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint32_t i = 0;
    if (newcid == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    while (chans[i].used == true && i < MAX_CIDS) {
        ++i;
    }
    if (i == MAX_CIDS) {
        log_printf("[CTAPHID] no more free CID!\n");
        errcode = MBED_ERROR_BUSY;
        goto err;
    }
    chans[i].used = true;
    *newcid = i + 1;
err:
    return errcode;
}

bool ctap_channel_exists(uint32_t cid)
{
    uint32_t i = 0;
    bool result = false;

    for (i = 0; i < MAX_CIDS; ++i) {
        if (chans[i].used == true) {
            if (cid == i+1) {
                result = true;
                goto end;
            }
        }
    }
end:
    return result;
}
