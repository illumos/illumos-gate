/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019, Joyent, Inc.
 */

#ifndef _SYS_USB_CCID_H
#define	_SYS_USB_CCID_H

/*
 * CCID class driver definitions.
 */

#include <sys/stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Values for various Hardware, Mechanical, and Pin features. These come from
 * the device's class descriptor.
 */
typedef enum ccid_class_voltage {
	CCID_CLASS_VOLT_AUTO	= 0x00,
	CCID_CLASS_VOLT_5_0	= 0x01,
	CCID_CLASS_VOLT_3_0	= 0x02,
	CCID_CLASS_VOLT_1_8	= 0x04
} ccid_class_voltage_t;

typedef enum ccid_class_mechanical {
	CCID_CLASS_MECH_CARD_ACCEPT	= 0x01,
	CCID_CLASS_MECH_CARD_EJECT	= 0x02,
	CCID_CLASS_MECH_CARD_CAPTURE	= 0x04,
	CCID_CLASS_MECH_CARD_LOCK	= 0x08
} ccid_class_mechanical_t;

typedef enum ccid_class_features {
	CCID_CLASS_F_AUTO_PARAM_ATR	= 0x00000002,
	CCID_CLASS_F_AUTO_ICC_ACTIVATE	= 0x00000004,
	CCID_CLASS_F_AUTO_ICC_VOLTAGE	= 0x00000008,
	CCID_CLASS_F_AUTO_ICC_CLOCK	= 0x00000010,
	CCID_CLASS_F_AUTO_BAUD		= 0x00000020,
	CCID_CLASS_F_AUTO_PARAM_NEG	= 0x00000040,
	CCID_CLASS_F_AUTO_PPS		= 0x00000080,
	CCID_CLASS_F_ICC_CLOCK_STOP	= 0x00000100,
	CCID_CLASS_F_ALTNAD_SUP		= 0x00000200,
	CCID_CLASS_F_AUTO_IFSD		= 0x00000400,
	CCID_CLASS_F_TPDU_XCHG		= 0x00010000,
	CCID_CLASS_F_SHORT_APDU_XCHG	= 0x00020000,
	CCID_CLASS_F_EXT_APDU_XCHG	= 0x00040000,
	CCID_CLASS_F_WAKE_UP		= 0x00100000
} ccid_class_features_t;

typedef enum ccid_class_pin {
	CCID_CLASS_PIN_VERIFICATION	= 0x01,
	CCID_CLASS_PIN_MODIFICATION	= 0x02
} ccid_class_pin_t;

/*
 * CCID Class Descriptor
 *
 * This structure represents the CCID class descriptor. Note, it should not be a
 * packed structure. This is designed to be a native representation. The raw
 * structure will be parsed into this instead.
 */
typedef struct ccid_class_descr {
	uint8_t		ccd_bLength;
	uint8_t		ccd_bDescriptorType;
	uint16_t	ccd_bcdCCID;
	uint8_t		ccd_bMaxSlotIndex;
	uint8_t		ccd_bVoltageSupport;
	uint32_t	ccd_dwProtocols;
	uint32_t	ccd_dwDefaultClock;
	uint32_t	ccd_dwMaximumClock;
	uint8_t		ccd_bNumClockSupported;
	uint32_t	ccd_dwDataRate;
	uint32_t	ccd_dwMaxDataRate;
	uint8_t		ccd_bNumDataRatesSupported;
	uint32_t	ccd_dwMaxIFSD;
	uint32_t	ccd_dwSyncProtocols;
	uint32_t	ccd_dwMechanical;
	uint32_t	ccd_dwFeatures;
	uint32_t	ccd_dwMaxCCIDMessageLength;
	uint8_t		ccd_bClassGetResponse;
	uint8_t		ccd_bClassEnvelope;
	uint16_t	ccd_wLcdLayout;
	uint8_t		ccd_bPinSupport;
	uint8_t		ccd_bMaxCCIDBusySlots;
} ccid_class_descr_t;

/*
 * Definitions for the supported versions of the CCID specification. The version
 * is encoded in binary encoded decimal. The major version is in the upper 8
 * bits and the minor version is in the lower 8 bits. We currently check for the
 * major version to match.
 */
#define	CCID_VERSION_MAJOR(ver)	(((ver) & 0xff00) >> 8)
#define	CCID_VERSION_MINOR(ver)	((ver) & 0x00ff)
#define	CCID_VERSION_ONE	0x01

/*
 * This structure is used as the data for the CCID_REQUEST_SET_PARAMS request
 * and the CCID_RESPONSE_PARAMETERS response. There are different structures for
 * T=0 and T=1. These come from CCID r1.1 / Section 6.1.7.
 */
typedef struct ccid_params_t0 {
	uint8_t cp0_bmFindexDindex;
	uint8_t cp0_bmTCCKST0;
	uint8_t cp0_bGuardTimeT0;
	uint8_t cp0_bWaitingIntegerT0;
	uint8_t	cp0_bClockStop;
} __packed ccid_params_t0_t;

#define	CCID_P_TCCKST0_DIRECT	0x00
#define	CCID_P_TCCKST0_INVERSE	0x02

typedef struct ccid_params_t1 {
	uint8_t cp1_bmFindexDindex;
	uint8_t cp1_bmTCCKST1;
	uint8_t cp1_bGuardTimeT1;
	uint8_t cp1_bmWaitingIntegersT1;
	uint8_t cp1_bClockStop;
	uint8_t cp1_bIFSC;
	uint8_t cp1_bNadValue;
} __packed ccid_params_t1_t;

typedef union ccid_params {
	ccid_params_t0_t ccp_t0;
	ccid_params_t1_t ccp_t1;
} ccid_params_t;

#define	CCID_P_FI_DI(fi, di)	((((fi) & 0x0f) << 4) | ((di) & 0x0f))

/*
 * Everything below this point is reserved for the kernel.
 */
#ifdef	_KERNEL

/*
 * These values come from CCID r1.1.0 Table 5.1-1 'Smart Card Device
 * Descriptors'
 */
#define	CCID_DESCR_TYPE		0x21
#define	CCID_DESCR_LENGTH	0x36


/*
 * Minimum and maximum value for a sequence number in the CCID specification.
 * The sequence is a 1 byte unsigned value. The values are inclusive. We reserve
 * the value of 0x00 so that we can use it as a sentinel in the ccid_command_t
 * structure to know when we should or shouldn't free a command structure's
 * sequence number back to the id space.
 */
#define	CCID_SEQ_MIN	0x01
#define	CCID_SEQ_MAX	UINT8_MAX


/*
 * All structures from the specification must be packed.
 */

/*
 * Interrupt-IN messages codes.
 */
typedef enum ccid_intr_code {
	CCID_INTR_CODE_SLOT_CHANGE	= 0x50,
	CCID_INTR_CODE_HW_ERROR		= 0x51
} ccid_intr_code_t;

typedef enum ccid_intr_hwerr_code {
	CCID_INTR_HWERR_OVERCURRENT	= 0x01
} ccid_intr_hwerr_code_t;

typedef struct ccid_intr_slot {
	uint8_t	cis_type;
	uint8_t	cis_state[];
} ccid_intr_slot_t;

typedef struct ccid_intr_hwerr {
	uint8_t	cih_type;
	uint8_t	cih_slot;
	uint8_t	cih_seq;
	uint8_t	cih_code;
} ccid_intr_hwerr_t;

/*
 * Message request codes. These codes are based on CCID r1.1.0 Table 6.1-1
 * 'Summary of Bulk-Out Messages'. The name from the standard is to the right of
 * the enum.
 */
typedef enum ccid_request_code {
	CCID_REQUEST_POWER_ON		= 0x62,	/* PC_to_RDR_IccPowerOn */
	CCID_REQUEST_POWER_OFF		= 0x63,	/* PC_to_RDR_IccPowerOff */
	CCID_REQUEST_SLOT_STATUS	= 0x65,	/* PC_to_RDR_GetSlotStatus */
	CCID_REQUEST_TRANSFER_BLOCK	= 0x6f,	/* PC_to_RDR_XfrBlock */
	CCID_REQUEST_GET_PARAMS		= 0x6c,	/* PC_to_RDR_GetParameters */
	CCID_REQUEST_RESET_PARAMS	= 0x6d,	/* PC_to_RDR_ResetParameters */
	CCID_REQUEST_SET_PARAMS		= 0x61,	/* PC_to_RDR_SetParameters */
	CCID_REQUEST_ESCAPE		= 0x6b,	/* PC_to_RDR_Escape */
	CCID_REQUEST_ICC_CLOCK		= 0x6e,	/* PC_to_RDR_IccClock */
	CCID_REQUEST_T0APDU		= 0x6a,	/* PC_to_RDR_T0APDU */
	CCID_REQUEST_SECURE		= 0x69,	/* PC_to_RDR_Secure */
	CCID_REQUEST_MECHANICAL		= 0x71,	/* PC_to_RDR_Mechanica */
	CCID_REQEUST_ABORT		= 0x72,	/* PC_to_RDR_Abort */
	CCID_REQUEST_DATA_CLOCK		= 0x73	/* PC_to_RDR_SetDataRateAnd */
						/* ClockFrequency */
} ccid_request_code_t;

/*
 * Message request codes. These codes are based on CCID r1.1.0 Table 6.2-1
 * 'Summary of Bulk-In Messages'. The name from the standard is to the right of
 * the enum.
 */
typedef enum ccid_response_code {
	CCID_RESPONSE_DATA_BLOCK	= 0x80,	/* RDR_to_PC_DataBlock */
	CCID_RESPONSE_SLOT_STATUS	= 0x81,	/* RDR_to_PC_SlotStatus */
	CCID_RESPONSE_PARAMETERS	= 0x82, /* RDR_to_PC_Parameters */
	CCID_RESPONSE_ESCAPE		= 0x83,	/* RDR_to_PC_Escape */
	CCID_RESPONSE_DATA_CLOCK	= 0x84	/* RDR_to_PC_DataRateAnd */
						/* ClockFrequency */
} ccid_response_code_t;

/*
 * This represents the CCID command header that is used for every request and
 * response.
 */
typedef struct ccid_header {
	uint8_t		ch_mtype;
	uint32_t	ch_length;	/* Length of ch_data in bytes */
	uint8_t		ch_slot;	/* CCID slot to target */
	uint8_t		ch_seq;		/* Request/Response sequence num */
	uint8_t		ch_param0;	/* Request/Response specific */
	uint8_t		ch_param1;	/* Request/Response specific */
	uint8_t		ch_param2;	/* Request/Response specific */
	uint8_t		ch_data[];	/* Optional Request/Response Data */
} __packed ccid_header_t;

/*
 * This structure is used as the data for the CCID_REQUEST_DATA_CLOCK and
 * CCID_RESPONSE_DATA_CLOCK commands.
 */
typedef struct ccid_data_clock {
	uint32_t	cdc_clock;
	uint32_t	cdc_data;
} __packed ccid_data_clock_t;

/*
 * Macros and constants to take apart the slot status (in ch_param1) when a CCID
 * reply comes in.
 */
#define	CCID_REPLY_ICC(x)	(x & 0x3)
#define	CCID_REPLY_STATUS(x)	((x & 0xc0) >> 6)

typedef enum {
	CCID_REPLY_ICC_ACTIVE = 0,
	CCID_REPLY_ICC_INACTIVE,
	CCID_REPLY_ICC_MISSING
} ccid_reply_icc_status_t;

typedef enum {
	CCID_REPLY_STATUS_COMPLETE = 0,
	CCID_REPLY_STATUS_FAILED,
	CCID_REPLY_STATUS_MORE_TIME
} ccid_reply_command_status_t;

/*
 * Errors that are defined based when commands fail. These are based on CCID
 * r.1.1.0 Table 6.2-2 'Slot error register when bmCommandStatus = 1'.
 */
typedef enum ccid_command_err {
	CCID_ERR_CMD_ABORTED			= 0xff,
	CCID_ERR_ICC_MUTE			= 0xfe,
	CCID_ERR_XFR_PARITY_ERROR		= 0xfd,
	CCID_ERR_XFR_OVERRUN			= 0xfc,
	CCID_ERR_HW_ERROR			= 0xfb,
	CCID_ERR_BAD_ATR_TS			= 0xf8,
	CCID_ERR_BAD_ATR_TCK			= 0xf7,
	CCID_ERR_ICC_PROTOCOL_NOT_SUPPORTED	= 0xf6,
	CCID_ERR_ICC_CLASS_NOT_SUPPORTED	= 0xf5,
	CCID_ERR_PROCEDURE_BYTE_CONFLICT	= 0xf4,
	CCID_ERR_DEACTIVATED_PROTOCOL		= 0xf3,
	CCID_ERR_BUSY_WITH_AUTO_SEQUENCE	= 0xf2,
	CCID_ERR_PIN_TIMEOUT			= 0xf0,
	CCID_ERR_PIN_CANCELLED			= 0xef,
	CCID_ERR_CMD_SLOT_BUSY			= 0xe0,
	CCID_ERR_CMD_NOT_SUPPORTED		= 0x00
} ccid_command_err_t;

/*
 * Maximum size of an APDU (application data unit) payload. There are both short
 * and extended ADPUs. At this time, we only support the short ADPUs.
 */
#define	CCID_APDU_LEN_MAX	261

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_CCID_H */
