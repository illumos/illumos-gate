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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USB_USBVC_H
#define	_SYS_USB_USBVC_H


#ifdef	__cplusplus
extern "C" {
#endif

/* Video interface class code */
#define	CC_VIDEO			0x0e

/* Video interface subclass code */
#define	SC_UNDEFINED			0x00
#define	SC_VIDEOCONTROL 		0x01
#define	SC_VIDEOSTREAMING		0x02
#define	SC_VIDEO_INTERFACE_COLLECTION	0x03

#define	PC_PROTOCOL_UNDEFINED		0x00

/* Video class specific interface descriptor types */
#define	CS_UNDEFINED			0x20
#define	CS_DEVICE			0x21
#define	CS_CONFIGURATION		0x22
#define	CS_STRING			0x23
#define	CS_INTERFACE			0x24
#define	CS_ENDPOINT			0x25

/* Video class specific, video control interface descriptor subtypes */
#define	VC_DESCRIPTOR_UNDEFINED 	0x00
#define	VC_HEADER			0x01
#define	VC_INPUT_TERMINAL		0x02
#define	VC_OUTPUT_TERMINAL		0x03
#define	VC_SELECTOR_UNIT		0x04
#define	VC_PROCESSING_UNIT		0x05
#define	VC_EXTENSION_UNIT		0x06

/* Video class specific, video stream interface descriptor subtypes */
#define	VS_UNDEFINED			0x00
#define	VS_INPUT_HEADER 		0x01
#define	VS_OUTPUT_HEADER		0x02
#define	VS_STILL_IMAGE_FRAME		0x03
#define	VS_FORMAT_UNCOMPRESSED		0x04
#define	VS_FRAME_UNCOMPRESSED		0x05
#define	VS_FORMAT_MJPEG 		0x06
#define	VS_FRAME_MJPEG			0x07
#define	VS_FORMAT_MPEG2TS		0x0a
#define	VS_FORMAT_DV			0x0c
#define	VS_COLORFORMAT			0x0d
#define	VS_FORMAT_FRAME_BASED		0x10
#define	VS_FRAME_FRAME_BASED		0x11
#define	VS_FORMAT_STREAM_BASED		0x12

/* Endpoint type */
#define	EP_UNDEFINED			0x00
#define	EP_GENERAL			0x01
#define	EP_ENDPOINT			0x02
#define	EP_INTERRUPT			0x03

/* Request codes, bRequest */
#define	RC_UNDEFINED			0x00
#define	SET_CUR 			0x01
#define	GET_CUR 			0x81
#define	GET_MIN 			0x82
#define	GET_MAX 			0x83
#define	GET_RES 			0x84
#define	GET_LEN 			0x85
#define	GET_INFO			0x86
#define	GET_DEF 			0x87

/* Control types of Video Control interface */
#define	VC_CONTROL_UNDEFINED		0x00
#define	VC_VIDEO_POWER_MODE_CONTROL	0x01
#define	VC_REQUEST_ERROR_CODE_CONTROL	0x02

/* Terminal controls */
#define	TE_CONTROL_UNDEFINED		0x00

/* Selector Unit controls */
#define	SU_CONTROL_UNDEFINED		0x00
#define	SU_INPUT_SELECT_CONTROL 	0x01

/* Camera Terminal controls */
#define	CT_CONTROL_UNDEFINED				0x00
#define	CT_SCANNING_MODE_CONTROL			0x01
#define	CT_AE_MODE_CONTROL				0x02
#define	CT_AE_PRIORITY_CONTROL				0x03
#define	CT_EXPOSURE_TIME_ABSOLUTE_CONTROL		0x04
#define	CT_EXPOSURE_TIME_RELATIVE_CONTROL		0x05
#define	CT_FOCUS_ABSOLUTE_CONTROL			0x06
#define	CT_FOCUS_RELATIVE_CONTROL			0x07
#define	CT_FOCUS_AUTO_CONTROL				0x08
#define	CT_IRIS_ABSOLUTE_CONTROL			0x09
#define	CT_IRIS_RELATIVE_CONTROL			0x0a
#define	CT_ZOOM_ABSOLUTE_CONTROL			0x0b
#define	CT_ZOOM_RELATIVE_CONTROL			0x0c
#define	CT_PANTILT_ABSOLUTE_CONTROL			0x0d
#define	CT_PANTILT_RELATIVE_CONTROL			0x0e
#define	CT_ROLL_ABSOLUTE_CONTROL			0x0f
#define	CT_ROLL_RELATIVE_CONTROL			0x10
#define	CT_PRIVACY_CONTROL				0x11

/* Processing Unit controls */
#define	PU_CONTROL_UNDEFINED				0x00
#define	PU_BACKLIGHT_COMPENSATION_CONTROL		0x01
#define	PU_BRIGHTNESS_CONTROL				0x02
#define	PU_CONTRAST_CONTROL				0x03
#define	PU_GAIN_CONTROL 				0x04
#define	PU_POWER_LINE_FREQUENCY_CONTROL 		0x05
#define	PU_HUE_CONTROL					0x06
#define	PU_SATURATION_CONTROL				0x07
#define	PU_SHARPNESS_CONTROL				0x08
#define	PU_GAMMA_CONTROL				0x09
#define	PU_WHITE_BALANCE_TEMPERATURE_CONTROL		0x0a
#define	PU_WHITE_BALANCE_TEMPERATURE_AUTO_CONTROL	0x0b
#define	PU_WHITE_BALANCE_COMPONENT_CONTROL		0x0c
#define	PU_WHITE_BALANCE_COMPONENT_AUTO_CONTROL 	0x0d
#define	PU_DIGITAL_MULTIPLIER_CONTROL			0x0e
#define	PU_DIGITAL_MULTIPLIER_LIMIT_CONTROL		0x0f
#define	PU_HUE_AUTO_CONTROL				0x10
#define	PU_ANALOG_VIDEO_STANDARD_CONTROL		0x11
#define	PU_ANALOG_LOCK_STATUS_CONTROL			0x12

/* VideoStreaming interface controls, wValue */
#define	VS_CONTROL_UNDEFINED		0x00
#define	VS_PROBE_CONTROL		0x01
#define	VS_COMMIT_CONTROL		0x02
#define	VS_STILL_PROBE_CONTROL		0x03
#define	VS_STILL_COMMIT_CONTROL 	0x04
#define	VS_STILL_IMAGE_TRIGGER_CONTROL	0x05
#define	VS_STREAM_ERROR_CODE_CONTROL	0x06
#define	VS_GENERATE_KEY_FRAME_CONTROL	0x07
#define	VS_UPDATE_FRAME_SEGMENT_CONTROL 0x08
#define	VS_SYNC_DELAY_CONTROL		0x09

/* bmRequestType */
#define	USBVC_SET_IF	0x21;
#define	USBVC_GET_IF	0xA1;
#define	USBVC_SET_EP	0x22;
#define	USBVC_GET_EP	0xA2;

/* Terminal types */
#define	TT_VENDOR_SPECIFIC		0x0100
#define	TT_STREAMING			0x0101

/* Input Terminal types */
#define	ITT_VENDOR_SPECIFIC		0x0200
#define	ITT_CAMERA			0x0201
#define	ITT_MEDIA_TRANSPORT_INPUT	0x0202

/* Output Terminal types */
#define	OTT_VENDOR_SPECIFIC		0x0300
#define	OTT_DISPLAY			0x0301
#define	OTT_MEDIA_TRANSPORT_OUTPUT	0x0302

/* External terminal types */
#define	EXTERNAL_VENDOR_SPECIFIC	0x0400
#define	COMPOSITE_CONNECTOR		0x0401
#define	SVIDEO_CONNECTOR		0x0402
#define	COMPONENT_CONNECTOR		0x0403

/*
 * usb video class descriptors
 */

/* usb video class, video control interface, header descriptor */
typedef struct usbvc_vc_header_descr {
	uint8_t	bLength;
	uint8_t	bDescriptorType;
	uint8_t	bDescriptorSubtype;
	uint8_t	bcdUVC[2];
	uint8_t	wTotalLength[2];
	uint8_t	dwClockFrequency[4];

	/* Number of stream interfaces belong to this VC interface */
	uint8_t	bInCollection;
} usbvc_vc_header_descr_t;

typedef struct usbvc_vc_header {
	usbvc_vc_header_descr_t	*descr;

	/* there might be multiple stream interface numbers */
	uint8_t			*baInterfaceNr;
} usbvc_vc_header_t;

/* unit descriptor for all the three kinds of units */
typedef struct usbvc_unit_descr {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bDescriptorSubType;
	uint8_t bUnitID;

	union {
		struct {
			uint8_t bSourceID;
			uint8_t wMaxMultiplier[2];
			uint8_t bControlSize;
		} processing;

		struct {
			uint8_t	bNrInPins;
		} selector;

		struct {
			uint8_t	guidExtensionCode[16];
			uint8_t	bNumControls;
			uint8_t	bNrInPins;
		} extension;
	} unit;
} usbvc_unit_descr_t;

typedef struct usbvc_units {
	/* Point to cvs_buf, for most elements of unit descriptor */
	usbvc_unit_descr_t *descr;

	uint8_t		*bmControls;	/* for processing or extention unit */
	uint8_t		*baSourceID;	/* for selector or extention unit */
	uint8_t		iSelector;	/* for selector  unit */
	uint8_t		iProcessing;	/* for processing  unit */
	uint8_t		bmVideoStandards; /* for processing unit */
	uint8_t		bControlSize;	/* for extention unit */
	uint8_t		iExtension;	/* for extention unit */
	list_node_t	unit_node;
} usbvc_units_t;

/* Terminal descriptor for all the three kinds of video terminals */
typedef struct		usbvc_term_descr {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint8_t		bDescriptorSubType;
	uint8_t		bTerminalID;
	uint16_t	wTerminalType;
	uint8_t		AssocTerminal;

	union {
		struct {
			uint8_t iTerminal;
		} input;

		struct {
			uint8_t	bSourceID;
			uint8_t	iTerminal;
		} output;

		struct {
			uint8_t		iTerminal;
			uint16_t	wObjectiveFocalLengthMin;
			uint16_t	wObjectiveFocalLengthMax;
			uint16_t	wOcularFocalLength;
			uint8_t		bControlSize;
		} camera;
	}term;
} usbvc_term_descr_t;

typedef struct usbvc_terms {
	usbvc_term_descr_t	*descr;	/* interfaces for this cfg */

	/* for input or output terminals, excluding camera terminals */
	uint8_t			*bSpecific;

	uint8_t			*bmControls;  /* for camera terminals only */
	list_node_t		term_node;
} usbvc_terms_t;

/*
 * Stream interface descriptors
 */

/* input header descriptor */
typedef struct usbvc_input_header_descr {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint8_t		bDescriptorSubType;
	uint8_t		bNumFormats;
	uint16_t	wTotalLength;
	uint8_t		bEndpointAddress;
	uint8_t		bmInfo;
	uint8_t		bTerminalLink;
	uint8_t		bStillCaptureMethod;
	uint8_t		bTriggerSupport;
	uint8_t		bTriggerUsage;
	uint8_t		bControlSize;
} usbvc_input_header_descr_t;

/* UVC Spec: only one input header in one stream interface */
typedef struct usbvc_input_header {
	usbvc_input_header_descr_t	*descr;
	uint8_t				*bmaControls;
} usbvc_input_header_t;

/* Do not support output video device at present */
typedef struct usbvc_output_header_descr {
	uint8_t		bLength;
	uint8_t		bDescriptorType;
	uint8_t		bDescriptorSubType;
	uint8_t		bNumFormats;
	uint16_t	wTotalLength;
	uint8_t		bEndpointAddress;
	uint8_t		bTerminalLink;
	uint8_t		bControlSize;
} usbvc_output_header_descr_t;

typedef struct usbvc_output_header {
	usbvc_output_header_descr_t	*descr;
	uint8_t				*bmaControls;
} usbvc_output_header_t;

/*
 * Except bDescriptorSubType value, MJPEG and uncompressed frame descriptor are
 * all the same. So share one structure.
 */
typedef struct usbvc_frame_descr {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bDescriptorSubType;
	uint8_t bFrameIndex;
	uint8_t bmCapabilities;
	uint8_t wWidth[2];
	uint8_t wHeight[2];
	uint8_t dwMinBitRate[4];
	uint8_t dwMaxBitRate[4];
	uint8_t dwMaxVideoFrameBufferSize[4];
	uint8_t dwDefaultFrameInterval[4];
	uint8_t bFrameIntervalType;
} usbvc_frame_descr_t;

/*
 * There may be several frame descriptors immediately follow a format
 * descriptor.
 */
typedef struct usbvc_frames {
	usbvc_frame_descr_t *descr;
	uint32_t dwMinFrameInterval;	/* for continuous frame intervals */
	uint32_t dwMaxFrameInterval;	/* for continuous frame intervals */
	uint32_t dwFrameIntervalStep;	/* for continuous frame intervals */
	uint8_t *dwFrameInterval;	/* for discrete frame intervals */
} usbvc_frames_t;

/* The first several fixed length fields of still image frame descriptor */
typedef struct usbvc_still_image_frame_descr {
	uint8_t	bLength;
	uint8_t	bDescriptorType;
	uint8_t	bDescriptorSubType;
	uint8_t	bEndpointAddress;
	uint8_t	bNumImageSizePatterns;
} usbvc_still_image_frame_descr_t;

/*
 * Width and Hight of the still image.
 * There might be multiple such value pairs in one still image frame descr.
 */
typedef struct width_height {
	uint16_t wWidth;
	uint16_t wHeight;
} width_height_t;

/*
 * The whole still image frame descriptor.
 * UVC Spec: only one still image descriptor for each format group.
 */
typedef struct usbvc_still_image_frame {
	usbvc_still_image_frame_descr_t	*descr;
	width_height_t			*width_height;
	uint8_t				bNumCompressionPattern;
	uint8_t				*bCompression;
} usbvc_still_image_frame_t;

/*
 * All fields of this descr are fixed length.
 * UVC Spec: only one color_matching_descr is allowed for a given format.
 */
typedef struct usbvc_color_matching_descr {
	uint8_t	bLength;
	uint8_t	bDescriptorType;
	uint8_t	bDescriptorSubtype;
	uint8_t	bColorPrimaries;
	uint8_t	bTransferCharacteristics;
	uint8_t	bMatrixCoefficients;
} usbvc_color_matching_descr_t;

/* Mjpeg and uncompressed format descriptor */
typedef struct usbvc_format_descr {
	uint8_t	bLength;
	uint8_t	bDescriptorType;
	uint8_t	bDescriptorSubType;
	uint8_t	bFormatIndex;
	uint8_t	bNumFrameDescriptors;
	union {
		struct {
			uint8_t	bmFlags;
			uint8_t	bDefaultFrameIndex;
			uint8_t	bAspectRatioX;
			uint8_t	bAspectRatioY;
			uint8_t	bmInterlaceFlags;
			uint8_t	bCopyProtect;
		} mjpeg;

		struct {
			uint8_t	guidFormat[16];
			uint8_t	bBitsPerPixel;
			uint8_t	bDefaultFrameIndex;
			uint8_t	bAspectRatioX;
			uint8_t	bAspectRatioY;
			uint8_t	bmInterlaceFlags;
			uint8_t	bCopyProtect;
		} uncompressed;
	}fmt;
} usbvc_format_descr_t;

/*
 *  usb video class requests
 */
typedef struct usbvc_vs_probe_commit {
	uint8_t	bmHint[2];
	uint8_t	bFormatIndex;
	uint8_t	bFrameIndex;
	uint8_t	dwFrameInterval[4];
	uint8_t	wKeyFrameRate[2];
	uint8_t	wPFrameRate[2];
	uint8_t	wCompQuality[2];
	uint8_t	wCompWindowSize[2];
	uint8_t	wDelay[2];
	uint8_t	dwMaxVideoFrameSize[4];
	uint8_t	dwMaxPayloadTransferSize[4];
	uint8_t	wClockFrequency[4];
	uint8_t	bmFramingInfo;
	uint8_t	bPreferedVersion;
	uint8_t	bMinVersion;
	uint8_t	bMaxVersion;
} usbvc_vs_probe_commit_t;

/* Table 2-1 of a sub video class spec: "uncompressed payload spec" */
#define	USBVC_FORMAT_GUID_YUY2	{0x59, 0x55, 0x59, 0x32, 0x00, 0x00, 0x10, \
				0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, \
				0x9b, 0x71}
#define	USBVC_FORMAT_GUID_NV12	{0x4e, 0x56, 0x31, 0x32, 0x00, 0x00, 0x10, \
				0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, \
				0x9b, 0x71}

/* Stream frame's flag bits */
#define	USBVC_STREAM_EOF	(1 << 1)
#define	USBVC_STREAM_FID	(1 << 0)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_USBVC_H */
