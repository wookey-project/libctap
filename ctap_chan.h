#ifndef CTAP_CHANNEL_H_
#define CTAP_CHANNEL_H_

#include "autoconf.h"
#include "libc/types.h"
#include "ctap_control.h"

mbed_error_t ctap_cid_generate(uint32_t *cid);

mbed_error_t ctap_cid_add(uint32_t newcid);

bool ctap_cid_exists(uint32_t cid);

mbed_error_t ctap_cid_refresh(uint32_t cid);

mbed_error_t ctap_cid_remove(uint32_t cid);

mbed_error_t ctap_cid_periodic_clean(void);

#endif/*!CTAP_CHANNEL_H_*/
