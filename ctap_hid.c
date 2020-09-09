#include "ctap_control.h"
#include "libusbhid.h"

/* Some USAGE attributes are not HID level defines but 'vendor specific'. This is the case for
 * the FIDO usage page, which is a vendor specific usage page, defining its own, cusom USAGE tag values */
#define CTAP_USAGE_CTAP_U2FHID   0x01
#define CTAP_USAGE_CTAP_DATA_IN  0x20
#define CTAP_USAGE_CTAP_DATA_OUT 0x21
#define CTAP_USAGE_PAGE_BYTE1    0xd0
#define CTAP_USAGE_PAGE_BYTE0    0xf1


/*
 * CTAP/HID interactions with HID layer (triggers implementation)
 */

/* The FIDO HID report content declaration */
static usbhid_report_infos_t ctap_std_report = {
    .num_items = 16,
    .report_id = 0,
    .items = {
        /* this is the standard, datasheet defined FIDO2 HID report */
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_USAGE_PAGE, 2, CTAP_USAGE_PAGE_BYTE1, CTAP_USAGE_PAGE_BYTE0 },
        { USBHID_ITEM_TYPE_LOCAL, USBHID_ITEM_LOCAL_TAG_USAGE, 1, CTAP_USAGE_CTAP_U2FHID, 0 },
        { USBHID_ITEM_TYPE_MAIN, USBHID_ITEM_MAIN_TAG_COLLECTION, 1, USBHID_COLL_ITEM_APPLICATION, 0 },
        { USBHID_ITEM_TYPE_LOCAL, USBHID_ITEM_LOCAL_TAG_USAGE, 1, CTAP_USAGE_CTAP_DATA_IN, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_LOGICAL_MIN, 1, 0x0, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_LOGICAL_MAX, 2, 0xff, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_REPORT_SIZE, 1, 0x8, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_REPORT_COUNT, 1, 64, 0 }, /* report count in bytes */
        { USBHID_ITEM_TYPE_MAIN, USBHID_ITEM_MAIN_TAG_INPUT, 1, USBHID_IOF_ITEM_DATA|USBHID_IOF_ITEM_CONST|USBHID_IOF_ITEM_VARIABLE|USBHID_IOF_ITEM_RELATIVE, 0 },
        { USBHID_ITEM_TYPE_LOCAL, USBHID_ITEM_LOCAL_TAG_USAGE, 1, CTAP_USAGE_CTAP_DATA_OUT, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_LOGICAL_MIN, 1, 0x0, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_LOGICAL_MAX, 2, 0xff, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_REPORT_SIZE, 1, 0x8, 0 },
        { USBHID_ITEM_TYPE_GLOBAL, USBHID_ITEM_GLOBAL_TAG_REPORT_COUNT, 1, 64, 0 }, /* report count in bytes */
        { USBHID_ITEM_TYPE_MAIN, USBHID_ITEM_MAIN_TAG_OUTPUT, 1, USBHID_IOF_ITEM_DATA|USBHID_IOF_ITEM_CONST|USBHID_IOF_ITEM_VARIABLE|USBHID_IOF_ITEM_RELATIVE, 0 },
        { USBHID_ITEM_TYPE_MAIN, USBHID_ITEM_MAIN_TAG_END_COLLECTION, 0, 0, 0 }, /* C0 */
    }
};

usbhid_report_infos_t   *ctap_get_report(void)
{
    return &ctap_std_report;
}


/***********************************************************************
 * HID requested callbacks
 */

/* USB HID trigger implementation, required to be triggered on various HID events */
mbed_error_t usbhid_report_received_trigger(uint8_t hid_handler, uint16_t size)
{
    ctap_context_t *ctx = ctap_get_context();

    log_printf("[CTAPHID] Received FIDO cmd (size %d)\n", size);
    ctx->ctap_cmd_received = true;
    ctx->ctap_cmd_size = size;
    /* nothing more to do, as the received  command is already set in .ctap_cmd field */
    hid_handler = hid_handler; /* XXX to use ?*/
    return MBED_ERROR_NONE;
}




mbed_error_t           usbhid_set_idle(uint8_t hid_handler, uint8_t idle)
{
    ctap_context_t *ctx = ctap_get_context();
    hid_handler = hid_handler;
    log_printf("[CTAPHID] triggered on Set_Idle\n");
    ctx->idle_ms = idle;
    ctx->idle = true;
    log_printf("[CTAPHID] set idle time to %d ms\n", idle);
    return MBED_ERROR_NONE;
}


/* trigger for HID layer GET_REPORT event */
usbhid_report_infos_t *usbhid_get_report(uint8_t hid_handler, uint8_t index)
{
    ctap_context_t *ctx = ctap_get_context();
    log_printf("[CTAPHID] triggered on Get_Report\n");
    usbhid_report_infos_t *report = NULL;
    hid_handler = hid_handler; /* only one iface: 0 */
    switch (index) {
        case 0:
            report = ctx->ctap_report;
            break;
        default:
            log_printf("[CTAPHID] unkown report index %d\n", index);
            break;
    }
    return report;
}


void usbhid_report_sent_trigger(uint8_t hid_handler, uint8_t index)
{
    ctap_context_t *ctx = ctap_get_context();
    log_printf("[CTAPHID] report sent!\n");
    hid_handler = hid_handler;
    index = index;
    ctx->report_sent = true;
}



