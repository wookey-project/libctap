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

#ifndef LIBCTAP_H_
#define LIBCTAP_H_

#include "autoconf.h"
#include "libc/types.h"

/************************************************************
 * About APDU/CBOR handling
 * Depending on the CTAP version, CTAP_MSG may contains:
 * - APDU messages
 * - CBOR messages
 * These messages are passed to the FIDO APDU manager (handling libapdu)
 * or FIDO CBOR manager (handling libcbor). This manager may be executed
 * in a separated task. To do that, the CTAP library is using prototypes
 * to leave the choice to the global application how APDU/CBOR content
 * is to be passed from one lib to another (IPC, direct access, etc.)
 */

/*
 * TODO: msg_in & msg_out *are* APDU and should be strictly defined as APDUs.
 */
typedef mbed_error_t (*ctap_handle_apdu_t)(uint8_t *msg_in, uint16_t len_in, uint8_t *msg_out, uint16_t len_out);


/************************************************************
 * About channels (CID) handling
 */

/*
 * background callback to any backend which handle the effective channel
 * handling.
 * May return:
 *   - MBED_ERROR_NONE: channel created
 *   - MBED_ERROR_NOMEM: no more space for channel
 *   - MBED_ERROR_DENIED: refused to create a new channel (DoS ?)
 *   - others ?
 *
 */
typedef mbed_error_t (*ctap_channel_create_t)(uint32_t *newcid);

/*
 * Background callback to inform the channel handler that a given non-
 * Broadcast channel is requested.
 * Update the timer associated to the current cid if found.
 * May return:
 *    - MBED_ERROR_NONE: cid found and timestamp updated
 *    - MBED_ERROR_NOTFOUND: cid does not exist
 *    - MBED_ERROR_DENIED: refused to request the CID manager. DoS ?
 */
typedef mbed_error_t (*ctap_channel_update_t)(uint32_t cid);


/************************************************************
 * libCTAP global interface prototypes
 */


/*
 * Declare CTAP HID interfae against USBHID stack.
 */
mbed_error_t ctap_declare(uint8_t usbxdci_handler);

/*
 * Configure the overall CTAP and below stack (including HID & USB stack).
 */
mbed_error_t ctap_configure(void);

/* to be executed once. This set OUT EP in DATA mode, ready to receive, for the fist time.
 * Other successive cases will be handled by ctap_exec()
 * XXX: a cleaner way would be to implement an automaton with a state in the context,
 * separating an INIT mode from a RUNNING mode */
mbed_error_t ctap_prepare_exec(void);

/*
 * Exec once one HID loop, checking for input messages and respond to them
 * if needed.
 */
mbed_error_t ctap_exec(void);

#endif/*!LIBCTAP_H_*/
