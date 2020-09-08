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
#ifndef CTAP_HID_H_
#define CTAP_HID_H_

#include "libc/types.h"
#include "ctap_control.h"

usbhid_report_infos_t   *ctap_get_report(void);

mbed_error_t usbhid_report_received_trigger(uint8_t hid_handler, uint16_t size);

usbhid_report_infos_t *usbhid_get_report(uint8_t hid_handler, uint8_t index);

mbed_error_t           usbhid_set_idle(uint8_t hid_handler, uint8_t idle);

void usbhid_report_sent_trigger(uint8_t hid_handler, uint8_t index);


#endif/*!CTAP_HID_H_*/
