/*
 * The overall device stacking is the following:
 *
 * [APDU  |  CBOR ]                         <--- CTAPHID1: APDU framing
 *                                               CTAPHID2: CBOR capa: CBOR (Json)
 *  ---------------
 * [ FIDO U2F CMD  ][   FIDO Ctrl         ] <--- CTAPHID cmd level
 *  ---------------  ---------------------
 * [  libUSBHID    ][ libxDCI             ]
 * [ (HID stack)   ][ (USB control plane) ]
 *  -[InEP]-[OutEP]---------[EP0]---------
 * [  USB backend driver                  ]
 */
#ifndef CTAP_PROTOCOL_H_
#define CTAP_PROTOCOL_H_
#include "autoconf.h"
#include "libc/types.h"

/*
 * FIXME to define properly:
 * range of ctaphid_cmd_id for vendor specific commands
 */
#define CTAPHID_VENDOR_FIRST 42
#define CTAPHID_VENDOR_LAST  52

#define CTAPHID_BROADCAST_CID 0xffffffff

#define USBHID_PROTO_VERSION 2
#define CTAPHID_FRAME_MAXLEN 64

/*****************************************
 * About command
 */

typedef enum {
    CTAP_PING      = 0x01,
    CTAP_MSG       = 0x03,
    CTAP_LOCK      = 0x04,
    CTAP_INIT      = 0x06,
    CTAP_WINK      = 0x08,
    CTAP_CBOR      = 0x10,
    CTAP_CANCEL    = 0x11,
    CTAP_KEEPALIVE = 0x3b,
    CTAP_ERROR     = 0x3f,
} ctaphid_cmd_id_t;


/*
 * Considering Full Speed devices, the FIDO Alliance define
 * IN and OUT interrupt endpoint as 64 bits mpsize EP.
 * In interrupt mode, the host and device can forge transfert
 * up to the mpsize (64 bytes) packets.
 * As a consequence, U2F commands can't be bigger than 64 bytes,
 * decomposed on CMD, BCNT (length) and DATA (effective content).
 * Although, to be generic to USB and avoid any risk, considering
 * BCNT as a uint8_t field, data len is up to 256 bytes.
 *
 * In case of CTAP_MSG commands, the data hold APDU formated U2F messages
 * defined below.
 */
typedef struct __packed {
    uint32_t cid;
    uint8_t  cmd;
    uint8_t  bcnth;
    uint8_t  bcntl;
    uint8_t  data[256]; /* data is a blob here, but is a structured content, depending
                           on the cmd value. It can be encoded using APDU format or CBOR
                           format.
CAUTION: the CTAPHID c*/
} ctap_cmd_t;


/******************************************
 * About responses
 */

/*
 * All messages are made of a header, and a differenciated data conent
 * (depending on the message type)
 */
typedef struct __packed {
    uint32_t cid;
    uint8_t cmd;
    uint8_t bcnth;
    uint8_t bcntl;
    /* differenciated resp here */
} ctap_init_header_t;

/* header for fragmented packets */
typedef struct __packed {
    uint32_t cid;
    uint8_t seq;
    /* differenciated resp here */
} ctap_seq_header_t;

typedef struct __packed {
    ctap_init_header_t header;
    uint8_t data[64];
} ctap_init_cmd_t;

typedef struct __packed {
    ctap_seq_header_t header;
    uint8_t data[64];
} ctap_seq_cmd_t;

typedef struct __packed {
    uint8_t nonce[8];
    uint32_t chanid;
    uint8_t proto_version;
    uint8_t major_n;
    uint8_t minor_n;
    uint8_t build_n;
    uint8_t capa_f;
} ctap_resp_init_t;


/*
 * Optional response to WINK command
 */

typedef enum {
    CTAP_CAPA_WINK  = 0x1,
    CTAP_CAPA_LOCK  = 0x1 << 1,
    CTAP_CAPA_CBOR  = 0x1 << 2,
    CTAP_CAPA_NMSG  = 0x1 << 3,
} ctap_capa_id_t;



typedef enum {
    U2F_ERR_NONE         = 0x0,
    U2F_ERR_INVALID_CMD  = 0x1,
    U2F_ERR_INVALID_PAR  = 0x2,
    U2F_ERR_INVALID_LEN  = 0x3,
    U2F_ERR_INVALID_SEQ  = 0x4,
    U2F_ERR_MSG_TIMEOUT  = 0x5,
    U2F_ERR_CHANNEL_BUSY = 0x6,
    /* to continue, there is various CTAP1 vs CTAP2 error codes.
     * Althought, codes are encoded on uint8_t values */
} ctab_error_code_t;

/************************************************************
 * About CTAP_MSG formats
 *
 * There is three types of CTAP messages. All these messages are
 * formatted using the T=0 APDU format.
 */

/*
 * For these commands, the FIDO U2F raw message format datasheets specify the following
 * in chap. 3:
 * REGISTER:        INS=0x1,       P1=0x0,     P2=0x0
 * AUTHENTICATE:    INS=0x2,       P1=0x3|7|8, P2=0x0
 * VERSION:         INS=0x3,       P1=0x0,     P2=0x0
 * VENDOR-SPECIFIC: INS=0x40-0xbf, NA,         NA
 */
typedef enum {
    U2F_INS_REGISTER     = 0x1,
    U2F_INS_AUTHENTICATE = 0x2,
    U2F_INS_VERSION      = 0x3
} ctap_msg_ins_t;


/*
 * Hande U2F commands
 */
mbed_error_t ctap_handle_request(ctap_cmd_t *cmd);

#endif/*!CTAP_PROTOCOL_H_*/
