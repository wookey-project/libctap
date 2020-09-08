#ifndef CTAP_CHANNEL_H_
#define CTAP_CHANNEL_H_

#include "autoconf.h"
#include "libc/types.h"
#include "ctap_control.h"

mbed_error_t ctap_channel_create(uint32_t *newcid);

bool ctap_channel_exists(uint32_t cid);

#endif/*!CTAP_CHANNEL_H_*/
