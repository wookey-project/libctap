#include "ctap_chan.h"
#include "ctap_control.h"
#include "libc/random.h"
#include "libc/sync.h"

chan_ctx_t chans[MAX_CIDS] = { 0 };

chan_ctx_t *ctap_cid_get_chan_ctx(uint32_t cid)
{
    for (uint8_t i = 0; i < MAX_CIDS; ++i) {
        if(chans[i].busy == true && chans[i].cid == cid){
            return &(chans[i]);
        }
    }
    return NULL;
}

ctap_cmd_t *ctap_cid_get_chan_complete_cmd(void)
{
    for (uint8_t i = 0; i < MAX_CIDS; ++i) {
        if(chans[i].busy == true && chans[i].ctap_cmd_received == true){
            return &(chans[i].ctap_cmd);
        }
    }
    return NULL;
}

ctap_cmd_t *ctap_cid_get_chan_cmd(uint32_t cid)
{
    for (uint8_t i = 0; i < MAX_CIDS; ++i) {
        if(chans[i].busy == true && chans[i].cid == cid){
            return &(chans[i].ctap_cmd);
        }
    }
    return NULL;
}

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
    /* we use EwoK TRNG source to get back a random CID 
     * NOTE: no need for cryptographically secure random here!
     */
rerun:
    random_secure = SEC_RANDOM_NONSECURE;
    errcode = get_random((uint8_t*)cid, sizeof(uint32_t));
    random_secure = SEC_RANDOM_SECURE;


    /* CID has been randomly seed, yet... check that no active CID
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

    while (chans[i].busy == true) {
        i++;
        if(i >= MAX_CIDS){
            log_printf("[CTAPHID] no more free CID!\n");
            errcode = MBED_ERROR_NOMEM;
            goto err;
        }  
    }
    chans[i].busy = true;
    chans[i].cid = newcid;
    chans[i].ctap_cmd_received = false;
    chans[i].ctap_cmd_idx = chans[i].ctap_cmd_size = chans[i].ctap_cmd_seq = 0;
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

mbed_error_t ctap_cid_clear_cmd(uint32_t cid)
{
    for (uint8_t i = 0; i < MAX_CIDS; ++i) {
        if (chans[i].busy == true && chans[i].cid == cid) {
            chans[i].ctap_cmd_received = false;
            chans[i].ctap_cmd_idx = chans[i].ctap_cmd_size = chans[i].ctap_cmd_seq = 0;
        }
    }
    return MBED_ERROR_NONE;
}
