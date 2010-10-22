/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _SYS_USB_AUDIO_H
#define	_SYS_USB_AUDIO_H


#ifdef __cplusplus
extern "C" {
#endif

/*
 * macros from audio spec 1.0
 *
 * audio class-specific descriptor types (Appendix A.4)
 */
#define	USB_AUDIO_CS_DEVICE		0x21
#define	USB_AUDIO_CS_CONFIGURATION	0x22
#define	USB_AUDIO_CS_STRING		0x23
#define	USB_AUDIO_CS_INTERFACE		0x24
#define	USB_AUDIO_CS_ENDPOINT		0x25

/* audio class-specific AC Interface Descriptor Subtypes (A.5) */
#define	USB_AUDIO_HEADER		0x01
#define	USB_AUDIO_INPUT_TERMINAL	0x02
#define	USB_AUDIO_OUTPUT_TERMINAL	0x03
#define	USB_AUDIO_MIXER_UNIT		0x04
#define	USB_AUDIO_SELECTOR_UNIT		0x05
#define	USB_AUDIO_FEATURE_UNIT		0x06
#define	USB_AUDIO_PROCESSING_UNIT	0x07
#define	USB_AUDIO_EXTENSION_UNIT	0x08

/* audio class-specific AS Interface descriptor Subtypes (A.6) */
#define	USB_AUDIO_AS_GENERAL		0x01
#define	USB_AUDIO_AS_FORMAT_TYPE	0x02
#define	USB_AUDIO_AS_FORMAT_SPECIFIC	0x03

/* Processing Uniti Process Types (A.7) */
#define	USB_AUDIO_UP_DOWNMIX_PROCESS		0x01
#define	USB_AUDIO_DOLBY_PROLOGIC_PROCESS	0x02
#define	USB_AUDIO_3D_STEREO_EXTENDER_PROCESS	0x03
#define	USB_AUDIO_REVERBERATION_PROCESS		0x04
#define	USB_AUDIO_CHORUS_PROCESS		0x05
#define	USB_AUDIO_DYN_RANGE_COMP_PROCESS	0x06

/* Audio Class-specific endpoint descriptor Subtypes (A.8) */
#define	USB_AUDIO_EP_GENERAL		0x07

/* Audio Class-specific Request Codes */
#define	USB_AUDIO_SET_CUR		0x01
#define	USB_AUDIO_GET_CUR		0x81
#define	USB_AUDIO_SET_MIN		0x02
#define	USB_AUDIO_GET_MIN		0x82
#define	USB_AUDIO_SET_MAX		0x03
#define	USB_AUDIO_GET_MAX		0x83
#define	USB_AUDIO_SET_RES		0x04
#define	USB_AUDIO_GET_RES		0x84
#define	USB_AUDIO_SET_MEM		0x05
#define	USB_AUDIO_GET_MEM		0x85
#define	USB_AUDIO_GET_STAT		0xff

/* Terminal Control Selectors (A.10.1) */
#define	USB_AUDIO_COPY_PROTECT_CONTROL	0x01

/* Feature Unit Control Selectors (A.1.10.2) */
#define	USB_AUDIO_MUTE_CONTROL		0x01
#define	USB_AUDIO_VOLUME_CONTROL	0x02
#define	USB_AUDIO_BASS_CONTROL		0x03
#define	USB_AUDIO_MID_CONTROL		0x04
#define	USB_AUDIO_TREBLE_CONTROL	0x05
#define	USB_AUDIO_GRAPHIC_CONTROL	0x06
#define	USB_AUDIO_AUTOMATIC_GAIN_CONTROL 0x07
#define	USB_AUDIO_DELAY_CONTROL		0x08
#define	USB_AUDIO_BASS_BOOST_CONTROL	0x09
#define	USB_AUDIO_LOUDNESS_CONTROL	0x0A

/* the spec defines volume control value of 0x8000 as silence */
#define	USB_AUDIO_VOLUME_SILENCE	0x8000

/* Up/Down-mix Processing Unit Control Selectors (A.10.3.1) */
#define	USB_AUDIO_UD_ENABLE_CONTROL	0x01
#define	USB_AUDIO_UD_MODE_SELECT_CONTROL 0x02

/* Dolby Prologic Processing Unit Control Selectors (A.10.3.2) */
#define	USB_AUDIO_DP_ENABLE_CONTROL	0x01
#define	USB_AUDIO_DP_MODE_SELECT_CONTROL 0x02

/* Reverberation Processing Unit Control Selectors (A.10.3.3) */
#define	USB_AUDIO_RV_ENABLE_CONTROL	0x01
#define	USB_AUDIO_REVERB_LEVEL_CONTROL	0x02
#define	USB_AUDIO_REVERB_TIME_CONTROL	0x03
#define	USB_AUDIO_REVERB_FEEDBACK_CONTROL 0x04

/* Chorus Processing Unit Control Selectors (A.10.3.5) */
#define	USB_AUDIO_CH_ENABLE_CONTROL	0x01
#define	USB_AUDIO_CHORUS_LEVEL_CONTROL	0x02
#define	USB_AUDIO_CHORUS_RATE_CONTROL	0x03
#define	USB_AUDIO_CHORUS_DEPTH_CONTROL	0x04

/* Dynamic range compressor Processing Unit Control Selectors (A.10.3.6) */
#define	USB_AUDIO_DR_ENABLE_CONTROL	0x01
#define	USB_AUDIO_COMPRESSION_RATE_CONTROL 0x02
#define	USB_AUDIO_MAXAMPL_CONTROL	0x03
#define	USB_AUDIO_THRESHOLD_CONTROL	0x04
#define	USB_AUDIO_ATTACK_TIME		0x05
#define	USB_AUDIO_RELEASE_TIME		0x06

/* Extension Unit Control Selectors (A.10.4) */
#define	USB_AUDIO_XU_ENABLE_CONTROL	0x01

/* Endpoint Control Selectors (A.10.5) */
#define	USB_AUDIO_SAMPLING_FREQ_CONTROL	0x01
#define	USB_AUDIO_PITCH_CONTROL		0x02

/* descriptors */
/* Class specific AC interface header descriptor (4.3.2) */
typedef struct usb_audio_cs_if_descr {
	uint8_t	bLength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* HEADER */
	uint16_t bcdADC;	/* release # */
	uint16_t wTotalLength;	/* the whole wad */
	uint8_t blnCollection;	/* # interfaces */
	uint8_t baInterfaceNr[1]; /* interface # */
} usb_audio_cs_if_descr_t;

#define	CS_AC_IF_HEADER_FORMAT "cccsscc"
#define	CS_AC_IF_HEADER_SIZE 9

/* input terminal descriptor (4.3.2.1) */
typedef struct usb_audio_input_term_descr {
	uint8_t	bLength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* INPUT_TERMINAL */
	uint8_t bTerminalID;	/* unique identifier */
	uint16_t wTerminalType;	/* type of terminal */
	uint8_t bAssocTerminal; /* identifier */
	uint8_t bNrChannels;	/* # channels */
	uint16_t wChannelConfig; /* logical channel loc */
	uint8_t iChannelNames;	/* string index */
	uint8_t iTerminal;	/* terminal string index */
} usb_audio_input_term_descr_t;

#define	CS_AC_INPUT_TERM_FORMAT "ccccsccscc"
#define	CS_AC_INPUT_TERM_SIZE 12

/* output terminal descriptor (4.3.2.2) */
typedef struct usb_audio_output_term_descr {
	uint8_t	bLength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* OUTPUT_TERMINAL */
	uint8_t bTerminalID;	/* unique identifier */
	uint16_t wTerminalType;	/* type of terminal */
	uint8_t bAssocTerminal; /* identifier */
	uint8_t bSourceID;	/* identifier */
	uint8_t iTerminal;	/* terminal string index */
} usb_audio_output_term_descr_t;

#define	CS_AC_OUTPUT_TERM_FORMAT "ccccsccc"
#define	CS_AC_OUTPUT_TERM_SIZE 9

/*
 * mixer unit descriptor (4.3.2.3)
 * this is awkward descriptors because of the variable size array in
 * the middle (baSourceID).
 */
typedef struct usb_audio_mixer_unit_descr1 {
	uint8_t	bLength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* MIXER_UNIT */
	uint8_t bUnitID;	/* identifier */
	uint8_t bNrInPins;	/* # input pins */
	uint8_t baSourceID[1];	/* idenfifiers */
} usb_audio_mixer_unit_descr1_t;

#define	CS_AC_MIXER_UNIT_DESCR1_FORMAT "cccccc"
#define	CS_AC_MIXER_UNIT_DESCR1_SIZE 6

typedef struct usb_audio_mixer_unit_descr2 {
	uint8_t bNrChannels;	/* # channels */
	uint16_t wChannelConfig; /* location of channels */
	uint8_t iChannelNames;	/* string index */
	uint8_t	bmControls[1];	/* bitmap prog. ctlrs */
} usb_audio_mixer_unit_descr2_t;

typedef struct usb_audio_mixer_unit_descr3 {
	uint8_t iMixer;	/* string index */
} usb_audio_mixer_unit_descr3_t;

/* selector unit descriptor (4.3.2.4) */
typedef struct usb_audio_selector_unit_descr1 {
	uint8_t	bLength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* SELECTOR_UNIT */
	uint8_t bUnitID;	/* identifier */
	uint8_t bNrInPins;	/* input pins on the unit */
	uint8_t baSourceID[1];	/* ID of pins */
} usb_audio_selector_unit_descr1_t;

#define	CS_AC_SELECTOR_UNIT_DESCR1_FORMAT "cccccc"
#define	CS_AC_SELECTOR_UNIT_DESCR1_SIZE 6

typedef struct usb_audio_selector_unit_descr2 {
	uint8_t iSelector[1];	/* string index */
} usb_audio_selector_unit_descr2_t;

/* feature unit descriptor (4.3.2.5) */
typedef struct usb_audio_feature_unit_descr1 {
	uint8_t	bLength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* FEATURE_UNIT */
	uint8_t bUnitID;	/* identifier */
	uint8_t bSourceID;	/* identifier */
	uint8_t bControlSize;	/* size of bmaControls */
	uint8_t bmaControls[1];	/* bitmap of features */
} usb_audio_feature_unit_descr1_t;

#define	CS_AC_FEATURE_UNIT_FORMAT	"ccccccc"
#define	CS_AC_FEATURE_UNIT_SIZE		7

typedef struct usb_audio_feature_unit_descr2 {
	uint8_t iFeature;	/* string index */
} usb_audio_feature_unit_descr2_t;

/* processing unit descriptor (4.3.2.6) */
typedef struct usb_audio_processing_unit_descr1 {
	uint8_t	bLength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* PROCESSING_UNIT */
	uint8_t bUnitID;	/* identifier */
	uint8_t	wProcessType;	/* type of processing */
	uint8_t bNrInPins;	/* input pins on the unit */
	uint8_t baSourceID[1];	/* ID of pins */
} usb_audio_processing_unit_descr1_t;

#define	CS_AC_PROCESSING_UNIT_DESCR1_FORMAT	"ccccccc"
#define	CS_AC_PROCESSING_UNIT_DESCR1_SIZE	7

typedef struct usb_audio_processing_unit_descr2 {
	uint8_t	bNrChannels;	/* # log. output channels */
	uint16_t wChannelConfig; /* spatial location */
	uint8_t iChannelnames;	/* index to name */
	uint8_t bControlSize;	/* size in bytes */
	uint8_t bmControls[1];	/* control bits */
} usb_audio_processing_unit_descr2_t;

typedef struct usb_audio_processing_unit_descr3 {
	uint8_t iProcessing;	/* index to string descr */
	uint8_t Process_specific[1];
} usb_audio_processing_unit_descr3_t;

/* extension unit descriptor (4.3.2.7) */
typedef struct usb_audio_extension_unit_descr1 {
	uint8_t	bLength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* PROCESSING_UNIT */
	uint8_t wExtensionCode; /* vendor spec. */
	uint8_t bUnitID;	/* identifier */
	uint8_t bNrInPins;	/* input pins on the unit */
	uint8_t baSourceID[1];	/* ID of pins */
} usb_audio_extension_unit_descr1_t;

#define	CS_AC_EXTENSION_UNIT_DESCR1_FORMAT	"ccccccc"
#define	CS_AC_EXTENSION_UNIT_DESCR1_SIZE	7

typedef struct usb_audio_extension_unit_descr2 {
	uint8_t	bNrChannels;	/* # log. output channels */
	uint16_t wChannelConfig; /* spatial location */
	uint8_t iChannelnames;	/* index to name */
	uint8_t bControlSize;	/* size in bytes */
	uint8_t bmControls[1];	/* control bits */
} usb_audio_extension_unit_descr2_t;

typedef struct usb_audio_extension_unit_descr3 {
	uint8_t iExtension;	/* index to string descr */
} usb_audio_extension_unit_descr3_t;



/* associated interface descriptor (4.3.2.8) */
typedef struct usb_audio_associated_if_descr {
	uint8_t	blength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* ASSOC Interface */
	uint8_t bInterfaceNr;	/* interface number */
} usb_audio_associated_if_descr_t;


/*
 * class specific AS interface descriptor (4.5.2)
 */
typedef struct usb_audio_as_if_descr {
	uint8_t	blength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* AS_GENERAL */
	uint8_t bTerminalLink;	/* identifier */
	uint8_t bDelay;		/* delay in data path */
	uint16_t wFormatTag;	/* data format */
} usb_audio_as_if_descr_t;

#define	AS_IF_DESCR_FORMAT	"cccccs"
#define	AS_IF_DESCR_SIZE	7


/* class specific AS isochronous audio data ep descr (4.6.1.2) */
typedef struct usb_audio_as_isoc_ep_descr {
	uint8_t	blength;	/* size */
	uint8_t	bDescriptorType; /* CS_ENDPOINT */
	uint8_t bDescriptorSubType; /* EP_GENERAL */
	uint8_t bmAttributes;	/* bitmap of attributes */
	uint8_t bLockDelayUnits; /* type of units */
	uint16_t wLockDelay;	/* lock of internal clock */
} usb_audio_as_isoc_ep_descr_t;

#define	AS_ISOC_EP_DESCR_FORMAT "5cs"
#define	AS_ISOC_EP_DESCR_SIZE 7

/*
 * data format descriptor, no need for parse format since
 * all fields are chars
 */
typedef struct usb_audio_type1_format_descr {
	uint8_t	blength;	/* size */
	uint8_t	bDescriptorType; /* CS_INTERFACE */
	uint8_t bDescriptorSubType; /* FORMAT_TYPE */
	uint8_t	bFormatType;	/* FORMAT_TYPE_1 */
	uint8_t bNrChannels;	/* #phys channels */
	uint8_t bSubFrameSize;	/* bytes per frame */
	uint8_t bBitResolution;	/* bits in subframe */
	uint8_t bSamFreqType;	/* sampling freq type */
	uint8_t bSamFreqs[6];	/* sampling freqs */
} usb_audio_type1_format_descr_t;

#define	AUDIO_TYPE1_FORMAT_FORMAT "10c"
#define	AUDIO_TYPE1_FORMAT_SIZE	10

/* audio data format codes */
#define	USB_AUDIO_FORMAT_TYPE1_PCM		0x0001
#define	USB_AUDIO_FORMAT_TYPE1_PCM8		0x0002
#define	USB_AUDIO_FORMAT_TYPE1_IEEE_FLOAT	0x0003
#define	USB_AUDIO_FORMAT_TYPE1_ALAW		0x0004
#define	USB_AUDIO_FORMAT_TYPE1_MULAW		0x0005

#define	USB_AUDIO_FORMAT_TYPE2_MPEG		0x1001
#define	USB_AUDIO_FORMAT_TYPE2_AC		0x1002

#define	USB_AUDIO_FORMAT_TYPE3_IEC1937_AC_3	0x2001
#define	USB_AUDIO_FORMAT_TYPE3_IEC1937_MPEG1_L1	0x2002
#define	USB_AUDIO_FORMAT_TYPE3_IEC1937_MPEG1_L2	0x2003
#define	USB_AUDIO_FORMAT_TYPE3_IEC1937_MPEG2_NOEXT 0x2003
#define	USB_AUDIO_FORMAT_TYPE3_IEC1937_MPEG2_EXT 0x2004
#define	USB_AUDIO_FORMAT_TYPE3_IEC1937_MPEG2_L1_LS 0x2005
#define	USB_AUDIO_FORMAT_TYPE3_IEC1937_MPEG2_L2_LS 0x2006

#define	USB_AUDIO_FORMAT_TYPE_1			0x01
#define	USB_AUDIO_FORMAT_TYPE_2			0x02
#define	USB_AUDIO_FORMAT_TYPE_3			0x03

/* format specific control selectors */
#define	USB_AUDIO_MP_DUAL_CHANNEL_CONTROL	0x01
#define	USB_AUDIO_MP_SECOND_STEREO_CONTROL	0x02
#define	USB_AUDIO_MP_MULTILINGUAL		0x03
#define	USB_AUDIO_MP_DYN_RANGE_CONTROL		0x04
#define	USB_AUDIO_MP_SCALING_CONTROL		0x05
#define	USB_AUDIO_MP_HILO_SCALING_CONTROL	0x06

#define	USB_AUDIO_AC_MODE_CONTROL		0x01
#define	USB_AUDIO_AC_DYN_RANGE_CONTROL		0x02
#define	USB_AUDIO_AC_SCALING_CONTROL		0x03
#define	USB_AUDIO_AC_HILO_SCALING_CONTROL	0x04

/* From USB Device Class Definition for Terminal Types */
/* USB Terminal Types (2.1) */
#define	USB_AUDIO_TERM_TYPE_STREAMING		0x0101
#define	USB_AUDIO_TERM_TYPE_VS			0x01ff

/* Input term types (2.2) */
#define	USB_AUDIO_TERM_TYPE_MICROPHONE		0x0201
#define	USB_AUDIO_TERM_TYPE_DT_MICROPHONE	0x0202
#define	USB_AUDIO_TERM_TYPE_PERS_MICROPHONE	0x0203
#define	USB_AUDIO_TERM_TYPE_OMNI_DIR_MICROPHONE	0x0204
#define	USB_AUDIO_TERM_TYPE_MICROPHONE_ARRAY	0x0205
#define	USB_AUDIO_TERM_TYPE_PROCESSING_MIC_ARRAY 0x0206

/* output term types (2.3) */
#define	USB_AUDIO_TERM_TYPE_SPEAKER		0x0301
#define	USB_AUDIO_TERM_TYPE_HEADPHONES		0x0302
#define	USB_AUDIO_TERM_TYPE_DISPLAY_AUDIO	0x0303
#define	USB_AUDIO_TERM_TYPE_DT_SPEAKER		0x0304
#define	USB_AUDIO_TERM_TYPE_ROOM_SPEAKER	0x0305
#define	USB_AUDIO_TERM_TYPE_COMM_SPEAKER	0x0306
#define	USB_AUDIO_TERM_TYPE_LF_EFFECTS_SPEAKER	0x0307

/* bi-directional terminal types (2.4) */
#define	USB_AUDIO_TERM_TYPE_HANDSET		0x0401
#define	USB_AUDIO_TERM_TYPE_HEADSET		0x0402
#define	USB_AUDIO_TERM_TYPE_SPEAKERPHONE	0x0403
#define	USB_AUDIO_TERM_TYPE_ECHO_SUPP_SPEAKERPHONE 0x0404
#define	USB_AUDIO_TERM_TYPE_ECHO_CANCEL_SPEAKERPHONE 0x0405

/* telephony terminal types (2.5) */
#define	USB_AUDIO_TERM_TYPE_PHONE_LINE		0x0501
#define	USB_AUDIO_TERM_TYPE_TELEPHONE		0x0502
#define	USB_AUDIO_TERM_TYPE_DOWN_LINE_PHONE	0x0503

/* external terminal types (2.6) */
#define	USB_AUDIO_TERM_TYPE_ANALOG_CONNECTOR	0x0601
#define	USB_AUDIO_TERM_TYPE_DIGITAL_AUDIO_IF	0x0602
#define	USB_AUDIO_TERM_TYPE_LINE_CONNECTOR	0x0603
#define	USB_AUDIO_TERM_TYPE_LEGACY_AUDIO_CONNECTOR 0x0604
#define	USB_AUDIO_TERM_TYPE_SPDIF_IF		0x0605
#define	USB_AUDIO_TERM_TYPE_1394_DA_STREAM	0x0606
#define	USB_AUDIO_TERM_TYPE_1394_DV_STREAM_SNDTRCK 0x0607

/* embedded function term types (2.7) */
#define	USB_AUDIO_TERM_TYPE_LVL_CAL_NOISE_SRC	0x0701
#define	USB_AUDIO_TERM_TYPE_EQUAL_NOISE		0x0702
#define	USB_AUDIO_TERM_TYPE_CD_PLAYER		0x0703
#define	USB_AUDIO_TERM_TYPE_DAT			0x0704
#define	USB_AUDIO_TERM_TYPE_DCC			0x0705
#define	USB_AUDIO_TERM_TYPE_MINIDISK		0x0706
#define	USB_AUDIO_TERM_TYPE_ANALOG_TAPE		0x0707
#define	USB_AUDIO_TERM_TYPE_PHONOGRAPH		0x0708
#define	USB_AUDIO_TERM_TYPE_VCR_AUDIO		0x0709
#define	USB_AUDIO_TERM_TYPE_VIDEO_DISK_AUDIO	0x070A
#define	USB_AUDIO_TERM_TYPE_DVD_AUDIO		0x070B
#define	USB_AUDIO_TERM_TYPE_TV_TUNER_AUDIO	0x070C
#define	USB_AUDIO_TERM_TYPE_SATELLITE_RCV_AUDIO	0x070D
#define	USB_AUDIO_TERM_TYPE_CABLE_TUNER_AUDIO	0x070E
#define	USB_AUDIO_TERM_TYPE_CABLE_DSS_AUDIO	0x070F
#define	USB_AUDIO_TERM_TYPE_RADIO_RECEIVER	0x0710
#define	USB_AUDIO_TERM_TYPE_RADIO_TRANSMITTER	0x0711
#define	USB_AUDIO_TERM_TYPE_MULTI_TRACK_RECORDER 0x0712
#define	USB_AUDIO_TERM_TYPE_SYNTHESIZER		0x0713

#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_CLOSE	0x00000002
#define	PRINT_MASK_OPEN		0x00000004
#define	PRINT_MASK_EVENTS	0x00000008
#define	PRINT_MASK_PM		0x00000010
#define	PRINT_MASK_CB		0x00000020
#define	PRINT_MASK_ALL		0xFFFFFFFF

#define	USB_AUDIO_MIN_PKTSZ	0
#define	USB_AUDIO_MAX_PKTSZ	(4 * 1024)

#define	USB_AUDIO_MUTE_ON	1
#define	USB_AUDIO_MUTE_OFF	0

#define	USB_AUDIO_PRECISION_8	8
#define	USB_AUDIO_PRECISION_16	16
#define	USB_AUDIO_PRECISION_24	24
#define	USB_AUDIO_PRECISION_32	32

#define	USB_AUDIO_PLAY		0x0001
#define	USB_AUDIO_RECORD	0x0002

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_AUDIO_H */
