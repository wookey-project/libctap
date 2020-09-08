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
#ifndef CTAP_CONTROL_H_
#define CTAP_CONTROL_H_

#include "libc/stdio.h"
#include "libusbhid.h"
#include "api/libctap.h"
#include "ctap_protocol.h"

#if CONFIG_USR_LIB_FIDO_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif

typedef enum {
    CTAP_CMD_BUFFER_STATE_EMPTY,
    CTAP_CMD_BUFFER_STATE_BUFFERING,
    CTAP_CMD_BUFFER_STATE_COMPLETE,
} ctap_buffer_state_t;


/* the current FIDO CTAP context */
typedef struct {
    usbhid_report_infos_t        *ctap_report;
    bool                          idle;
    bool                          locked;
    uint32_t                      curr_cid;
    uint8_t                       idle_ms;
    /* below stacks handlers (not cb, but references) */
    uint8_t                       hid_handler;
    uint8_t                       usbxdci_handler;
    /* upper stack callback */
    ctap_handle_apdu_t            apdu_cmd;
    /* CTAP commands */
    volatile bool                 report_sent;
    uint8_t                       recv_buf[CTAPHID_FRAME_MAXLEN];
    ctap_buffer_state_t           ctap_cmd_buf_state;
    bool                          ctap_cmd_received;
    uint16_t                      ctap_cmd_size;
    uint16_t                      ctap_cmd_idx;
    ctap_cmd_t                    ctap_cmd;
} ctap_context_t;



uint8_t ctap_get_usbhid_handler(void);

ctap_context_t *ctap_get_context(void);

#endif /*!CTAP_CONTROL_H_*/
