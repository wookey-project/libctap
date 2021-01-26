#include "ctap_chan.h"
#include "ctap_control.h"
#include "libc/random.h"

#define MAX_CIDS 12
#define CID_LIFETIME 2000 /* 2 seconds */

typedef struct {
    uint64_t last_used;
    uint32_t cid;
    bool     busy;
} chan_ctx_t;

/*XXX: test, 32 concurrent CID at a time */
chan_ctx_t chans[MAX_CIDS] = { 0 };


mbed_error_t ctap_cid_periodic_clean(void)
{
    uint64_t ms;
    uint64_t period;
    mbed_error_t errcode = MBED_ERROR_NONE;

    /* TODO: libstd: implement clock_gettime() abstraction */
    if (sys_get_systick(&ms, PREC_MILLI) != SYS_E_DONE) {
        errcode = MBED_ERROR_DENIED;
        goto err;
    }
    for (uint8_t i = 0; i < MAX_CIDS; ++i) {
        if (chans[i].busy == true) {
            period = ms - chans[i].last_used;
            if (period > CID_LIFETIME) {
                chans[i].busy = false;
            }
        }
    }
err:
    return errcode;
}

mbed_error_t ctap_cid_generate(uint32_t *cid)
{
    mbed_error_t errcode = MBED_ERROR_NONE;

    if (cid == NULL) {
        errcode = MBED_ERROR_INVPARAM;
        goto err;
    }
    /* we use EwoK TRNG source to get back a random CID */
rerun:
    errcode = get_random((uint8_t*)cid, sizeof(uint32_t));

    /* CID has been randomly seed, yet... check that no acive CID
     * is using the same value */
    if (ctap_cid_exists(*cid)) {
        goto rerun;
    }

err:
    return errcode;
}

mbed_error_t ctap_cid_add(uint32_t newcid)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint32_t i = 0;

    while (chans[i].busy == true && i < MAX_CIDS) {
        ++i;
    }
    if (i == MAX_CIDS) {
        log_printf("[CTAPHID] no more free CID!\n");
        errcode = MBED_ERROR_NOMEM;
        goto err;
    }
    chans[i].busy = true;
    chans[i].cid = newcid;
    ctap_cid_refresh(newcid);
err:
    return errcode;
}

bool ctap_cid_exists(uint32_t cid)
{
    for (uint8_t i = 0; i < MAX_CIDS; ++i) {
        if (chans[i].busy == true && chans[i].cid == cid) {
            return true;
        }
    }
    return false;
}

mbed_error_t ctap_cid_refresh(uint32_t cid)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    uint64_t ms;

    /* TODO: libstd: implement clock_gettime() abstraction */
    if (sys_get_systick(&ms, PREC_MILLI) != SYS_E_DONE) {
        errcode = MBED_ERROR_DENIED;
        goto err;
    }
    for (uint8_t i = 0; i < MAX_CIDS; ++i) {
        if (chans[i].busy == true && chans[i].cid == cid) {
            chans[i].last_used = ms;
        }
    }
err:
    return errcode;
}

mbed_error_t ctap_cid_remove(uint32_t cid)
{
    for (uint8_t i = 0; i < MAX_CIDS; ++i) {
        if (chans[i].busy == true && chans[i].cid == cid) {
            chans[i].busy = false;
        }
    }
    return MBED_ERROR_NONE;
}
