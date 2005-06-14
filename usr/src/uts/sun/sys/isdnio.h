/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1991, 1992, 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_ISDNIO_H
#define	_SYS_ISDNIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/audioio.h>

/*
 * ISDN related ioctls
 */

#ifdef	__cplusplus
extern "C" {
#endif

enum isdn_chan {
	ISDN_CHAN_NONE = 0x0,	/* no channel given */
	ISDN_CHAN_SELF,		/* our channel from stream */
	ISDN_CHAN_HOST,		/* Unix STREAM */

	ISDN_CHAN_CTLR_MGT,	/* The management stream for a controller */

	/* TE channel defines */
	ISDN_CHAN_TE_MGT = 0x10,
	ISDN_CHAN_TE_D_TRACE,
	ISDN_CHAN_TE_D,
	ISDN_CHAN_TE_B1,
	ISDN_CHAN_TE_B2,

	/* NT channel defines */
	ISDN_CHAN_NT_MGT = 0x20,
	ISDN_CHAN_NT_D_TRACE,
	ISDN_CHAN_NT_D,
	ISDN_CHAN_NT_B1,
	ISDN_CHAN_NT_B2,

	/* Primary rate ISDN */
	ISDN_CHAN_PRI_MGT = 0x30,
	ISDN_CHAN_PRI_D,
	ISDN_CHAN_PRI_B0, ISDN_CHAN_PRI_B1, ISDN_CHAN_PRI_B2,
	ISDN_CHAN_PRI_B3, ISDN_CHAN_PRI_B4, ISDN_CHAN_PRI_B5,
	ISDN_CHAN_PRI_B6, ISDN_CHAN_PRI_B7, ISDN_CHAN_PRI_B8,
	ISDN_CHAN_PRI_B9, ISDN_CHAN_PRI_B10, ISDN_CHAN_PRI_B11,
	ISDN_CHAN_PRI_B12, ISDN_CHAN_PRI_B13, ISDN_CHAN_PRI_B14,
	ISDN_CHAN_PRI_B15, ISDN_CHAN_PRI_B16, ISDN_CHAN_PRI_B17,
	ISDN_CHAN_PRI_B18, ISDN_CHAN_PRI_B19, ISDN_CHAN_PRI_B20,
	ISDN_CHAN_PRI_B21, ISDN_CHAN_PRI_B22, ISDN_CHAN_PRI_B23,
	ISDN_CHAN_PRI_B24, ISDN_CHAN_PRI_B25, ISDN_CHAN_PRI_B26,
	ISDN_CHAN_PRI_B27, ISDN_CHAN_PRI_B28, ISDN_CHAN_PRI_B29,
	ISDN_CHAN_PRI_B30, ISDN_CHAN_PRI_B31,

	/* Auxiliary channel defines */
	ISDN_CHAN_AUX0_MGT = 0x100, ISDN_CHAN_AUX0,
	ISDN_CHAN_AUX1_MGT, ISDN_CHAN_AUX1,
	ISDN_CHAN_AUX2_MGT, ISDN_CHAN_AUX2,
	ISDN_CHAN_AUX3_MGT, ISDN_CHAN_AUX3,
	ISDN_CHAN_AUX4_MGT, ISDN_CHAN_AUX4,
	ISDN_CHAN_AUX5_MGT, ISDN_CHAN_AUX5,
	ISDN_CHAN_AUX6_MGT, ISDN_CHAN_AUX6,
	ISDN_CHAN_AUX7_MGT, ISDN_CHAN_AUX7
};
typedef enum isdn_chan isdn_chan_t;

/*
 * ISDN-specific status requests
 */
#define	ISDN_INTERFACE_STATUS	_IOWR('A', 8, isdn_interface_info_t)
#define	ISDN_CHANNEL_STATUS	_IOWR('A', 9, isdn_channel_info_t)

/*
 * ISDN_PH_ACTIVATE_REQ - CCITT PH-ACTIVATE.req can only be used with a
 * file descriptor that is connected to a D-Channel.
 */
#define	ISDN_PH_ACTIVATE_REQ	_IO('A', 10)	/* Activate TE interface */

/*
 * ISDN_MPH_DEACTIVATE_REQ - CCITT PH-ACTIVATE.req can only be used with
 * a file descriptor that is connected to a D-Channel. This ioctl is only
 * legal on NT D-Channels.
 */
#define	ISDN_MPH_DEACTIVATE_REQ	_IO('A', 11)	/* deactivate ISDN intface */

/*
 * ISDN_PARAM_POWER_* - Turn power for an ISDN interface on and off.
 * This is equivalent to inserting or removing the ISDN cable from the
 * ISDN equipment on an ISDN-line powerted TE.
 *
 * 	1 = power on
 * 	0 = power off
 *
 * Interfaces that do not support this ioctl return -1 with errno set to
 * EXIO.
 */
#define	ISDN_PARAM_POWER_OFF	(0)
#define	ISDN_PARAM_POWER_ON	(1)

/*
 * ISDN_PARAM_SET and ISDN_PARAM_GET - Set/get an ISDN device parameter.
 */
#define	ISDN_PARAM_SET	_IOW('A', 16, isdn_param_t)
#define	ISDN_PARAM_GET	_IOWR('A', 16, isdn_param_t)
typedef enum {
	ISDN_PARAM_NONE = 0,
	ISDN_PARAM_NT_T101,	/* NT Timer, 5-30 s, in milliseconds */
	ISDN_PARAM_NT_T102,	/* NT Timer, 25-100 ms, in milliseconds */
	ISDN_PARAM_TE_T103,	/* TE Timer, 5-30 s, in milliseconds */
	ISDN_PARAM_TE_T104,	/* TE Timer, 500-1000 ms, in milliseconds */
	ISDN_PARAM_end_of_timers = 99,	/* highest possible timer parameter */

	ISDN_PARAM_MAINT,	/* Manage the TE Maintenence Channel */
	ISDN_PARAM_ASMB,	/* Modify Activation State Machine Behavoir */
	ISDN_PARAM_POWER,	/* ISDN_PARAM_POWER_* */
	ISDN_PARAM_PAUSE,	/* Paused if == 1, else not paused == 0 */

	ISDN_PARAM_vendor = 1000 /* Vendor specific params start at 1000 */
} isdn_param_tag_t;

#define	ISDN_PARAM_VENDOR(x) \
	((isdn_param_tag_t)((int)ISDN_PARAM_vendor+(int)(x)))

/*
 * Modify activation state machine behavior.
 * This parameter takes effect immediately.
 */
enum isdn_param_asmb {
	ISDN_PARAM_TE_ASMB_UNKNOWN = -1,

	/*
	 * 1988 CCITT Blue Book
	 */
	ISDN_PARAM_TE_ASMB_CCITT88,

	/*
	 * Conformance Test Suite 2, used by CNET for France Telecom testing
	 */
	ISDN_PARAM_TE_ASMB_CTS2
};

/*
 * This parameter takes effect the next time the device is opened. XXX?
 */
enum isdn_param_maint {
	/*
	 * ISDN_PARAM_MAINT:
	 * If bit 8 is 0, F(A) will be zero in all conditions
	 */
	ISDN_PARAM_MAINT_OFF,

	/*
	 * ISDN_PARAM_MAINT:
	 * If bit 8 is 1 and there is no source for Q-channel then F(A)
	 * will echo the received F(A)
	 */
	ISDN_PARAM_MAINT_ECHO,

	/*
	 * ISDN_PARAM_MAINT:
	 * If bit 8 is 1 and the TE is transmitting Q-channel data, then
	 * where a 1 is received in the proper place in the multi-frame,
	 * the Q-data but will be transmitted in the F(A) bit of the
	 * current frame.
	 */
	ISDN_PARAM_MAINT_ON
};


typedef struct isdn_param isdn_param_t;
struct isdn_param {
	isdn_param_tag_t tag;	/* parameter name */
	union {
		unsigned int us; /* micro seconds */
		unsigned int ms; /* Timer value in ms */
		unsigned int flag; /* Boolean */
		unsigned int count;
		enum isdn_param_asmb asmb;
		enum isdn_param_maint maint;
		struct {
			isdn_chan_t channel; /* Channel to Pause */
			int paused; /* TRUE or FALSE */
		} pause;
		unsigned int reserved[2]; /* reserved future expansion */
	} value;
};


/*
 * ISDN_ACTIVATION_STATUS - Query the current activation state of an
 * interface. "type" must be set to indicate the interface to query.
 *
 * type == ISDN_TYPE_SELF may be used to get the activation status of the
 * interface connected to the file descriptor used in the ioctl.
 */
#define	ISDN_ACTIVATION_STATUS	_IOWR('A', 13, isdn_activation_status_t)

/*
 * ISDN_SET_LOOPBACK - Set the specified interface into remote loopback
 * mode.
 *
 * ISDN_RESET_LOOPBACK - Clear the specified loopbacks on the specified
 * interface.
 */
#define	ISDN_SET_LOOPBACK	_IOW('A', 14, isdn_loopback_request_t)
#define	ISDN_RESET_LOOPBACK	_IOW('A', 15, isdn_loopback_request_t)

#define	ISDN_SET_FORMAT		_IOWR('A', 16, isdn_format_req_t)
#define	ISDN_GET_FORMAT		_IOWR('A', 17, isdn_format_req_t)

#define	ISDN_SET_CHANNEL	_IOW('A', 18, isdn_conn_req_t)

#define	ISDN_GET_CONFIG		_IOWR('A', 19, isdn_conn_tab_t)

typedef enum {
	ISDN_TYPE_UNKNOWN = -1,	/* Not known or applicable */

	/*
	 * For queries, application may put this value into "type" to
	 * query the state of the file descriptor used in an ioctl.
	 */
	ISDN_TYPE_SELF = 0,

	ISDN_TYPE_OTHER,	/* Not an ISDN interface */
	ISDN_TYPE_TE,
	ISDN_TYPE_NT,
	ISDN_TYPE_PRI
} isdn_interface_t;


typedef enum {
	ISDN_PATH_NOCHANGE = 0,	/* No-operation */
	ISDN_PATH_DISCONNECT,	/* Disconnect data path */
	ISDN_PATH_ONEWAY,	/* Uni-directional data path */
	ISDN_PATH_TWOWAY	/* Bi-directional data path */
} isdn_path_t;


typedef	enum {
	ISDN_MODE_UNKNOWN = 0,	/* mode predefined by def */
	ISDN_MODE_HDLC,		/* HDLC framing and error checking */
	ISDN_MODE_TRANSPARENT	/* Transparent mode */
} isdn_mode_t;


typedef struct isdn_format isdn_format_t;
struct isdn_format {
	isdn_mode_t mode;
	unsigned int sample_rate; /* data frames per second */
	unsigned int channels;	/* number of interleaved channels */
	unsigned int precision;	/* bits per sample */
	unsigned int encoding;	/* AUDIO_ENCODING_* */
	unsigned int reserved[3]; /* must be zero */
};


typedef struct isdn_conn_req isdn_conn_req_t;
struct isdn_conn_req {
	isdn_chan_t from;
	isdn_chan_t to;
	isdn_path_t dir;	/* uni/bi-directional or disconnect */
	isdn_format_t format;	/* data format */
	int reserved[4];
};


typedef struct isdn_conn_tab isdn_conn_tab_t;
struct isdn_conn_tab {
	int maxpaths;
	int npaths;
	isdn_conn_req_t *paths;
};


typedef struct isdn_format_req isdn_format_req_t;
struct isdn_format_req {
	isdn_chan_t channel;	/* controller end channel */
	isdn_format_t format;	/* data format */
	int reserved[4];	/* future use - must be 0 */
};

#define	ISDN_SET_FORMAT_x(p, m, s, c, pr, e) \
{ \
	(p)->mode = (m); \
	(p)->sample_rate = (s); \
	(p)->channels = (c); \
	(p)->precision = (pr); \
	(p)->encoding = (e); \
	(p)->reserved[0] = 0; \
	(p)->reserved[1] = 0; \
	(p)->reserved[2] = 0; \
}

#define	ISDN_SET_FORMAT_BRI_D(p) \
    ISDN_SET_FORMAT_x((p), ISDN_MODE_HDLC, 2000, 1, 8, AUDIO_ENCODING_NONE)
#define	ISDN_SET_FORMAT_PRI_D(p) \
    ISDN_SET_FORMAT_x((p), ISDN_MODE_HDLC, 8000, 1, 8, AUDIO_ENCODING_NONE)
#define	ISDN_SET_FORMAT_HDLC_B56(p) \
    ISDN_SET_FORMAT_x((p), ISDN_MODE_HDLC, 7000, 1, 8, AUDIO_ENCODING_NONE)
#define	ISDN_SET_FORMAT_HDLC_B64(p) \
    ISDN_SET_FORMAT_x((p), ISDN_MODE_HDLC, 8000, 1, 8, AUDIO_ENCODING_NONE)
#define	ISDN_SET_FORMAT_BRI_H(p) \
    ISDN_SET_FORMAT_x((p), ISDN_MODE_HDLC, 16000, 1, 8, AUDIO_ENCODING_NONE)
#define	ISDN_SET_FORMAT_VOICE_ULAW(p) \
    ISDN_SET_FORMAT_x((p), ISDN_MODE_TRANSPARENT, 8000, 1, 8, \
    AUDIO_ENCODING_ULAW)
#define	ISDN_SET_FORMAT_VOICE_ALAW(p) \
    ISDN_SET_FORMAT_x((p), ISDN_MODE_TRANSPARENT, 8000, 1, 8, \
    AUDIO_ENCODING_ALAW)

enum isdn_activation_state {
	ISDN_OFF = 0,		/* Interface is powered down */
	ISDN_UNPLUGGED,		/* Power but no physical-layer connection */
	ISDN_DEACTIVATE_REQ,	/* Pending deactivation, NT only */
	ISDN_DEACTIVATED,	/* Activation is permitted */
	ISDN_ACTIVATE_REQ,	/* Attempting to activate */
	ISDN_ACTIVATED		/* Interface is activated */
};
typedef enum isdn_activation_state isdn_activation_state_t;

enum isdn_iostate {
	ISDN_IO_UNKNOWN = -1,	/* I/O state not known or applicable */
	ISDN_IO_STOPPED,	/* DMA is not enabled */
	ISDN_IO_READY		/* DMA is enabled */
};

#define	ISDN_PROTO_MAGIC (0x6973646e) /* "isdn" */


/*
 * TE sends: ISDN_PH_AI, ISDN_PH_DI, ISDN_MPH_AI, ISDN_MPH_DI, ISDN_MPH_EI1,
 *	ISDN_MPH_EI2, ISDN_MPH_II_C, ISDN_MPH_II_D
 * NT sends: ISDN_PH_AI, ISDN_PH_DI, ISDN_MPH_AI, ISDN_MPH_DI, ISDN_MPH_EI1
 */
enum isdn_message_type {
	ISDN_VPH_VENDOR = 0,	/* Vendor specific messages */

	ISDN_PH_AI,		/* Physical: Activation Ind */
	ISDN_PH_DI,		/* Physical: Deactivation Ind */
	ISDN_PH_AR,		/* Physical: Activation Request */

	ISDN_PH_DATA_RQ,	/* Physical: Request for transmission */
	ISDN_PH_DATA_IN,	/* Physical: Received */

	ISDN_MPH_AI,		/* Management: Activation Ind */
	ISDN_MPH_DI,		/* Management: Deactivation Ind */
	ISDN_MPH_EI1,		/* Management: Error 1 Indication */
	ISDN_MPH_EI2,		/* Management: Error 2 Indication */
	ISDN_MPH_II_C,		/* Management: Info Ind, connection */
	ISDN_MPH_II_D		/* Management: Info Ind, disconn. */
};
typedef enum isdn_message_type isdn_message_type_t;

typedef struct isdn_message isdn_message_t;
struct isdn_message {
	unsigned int magic;	/* ISDN_PROTO_MAGIC */
	isdn_interface_t type;	/* Interface type */
	isdn_message_type_t message; /* CCITT Primitive or Vendor */
	unsigned int vendor[5];	/* Vendor specific content */
};


typedef struct isdn_activation_status isdn_activation_status_t;
struct isdn_activation_status {
	isdn_interface_t type;
	enum isdn_activation_state activation;
};


typedef enum {
	ISDN_LOOPBACK_LOCAL,
	ISDN_LOOPBACK_REMOTE
} isdn_loopback_type_t;


typedef enum {
	ISDN_LOOPBACK_B1 = 0x1,
	ISDN_LOOPBACK_B2 = 0x2,
	ISDN_LOOPBACK_D = 0x4,
	ISDN_LOOPBACK_E_ZERO = 0x8,
	ISDN_LOOPBACK_S = 0x10,
	ISDN_LOOPBACK_Q = 0x20
} isdn_loopback_chan_t;

typedef struct isdn_loopback_request isdn_loopback_request_t;
struct isdn_loopback_request {
	isdn_loopback_type_t type;
	int channels;
};


/*
 * ISDN_INTERFACE_STATUS ioctl uses this data structure.  If the
 * interface is specified as ISDN_TYPE_SELF, the driver will replace it
 * with the true interface value.
 */
typedef struct isdn_interface_info isdn_interface_info_t;
struct isdn_interface_info {
	isdn_interface_t interface; /* to be filled in by user */

	/*
	 * Activation State Machine information
	 */
	isdn_activation_state_t activation;

	/*
	 * Counters for physical layer ASM primitives
	 */
#if defined(_LP64) || defined(_I32LPx)
	uint_t ph_ai;		/* Physical: Activation Ind */
	uint_t ph_di;		/* Physical: Deactivation Ind */
	uint_t mph_ai;		/* Management: Activation Ind */
	uint_t mph_di;		/* Management: Deactivation Ind */
	uint_t mph_ei1;		/* Management: Error 1 Indication */
	uint_t mph_ei2;		/* Management: Error 2 Indication */
	uint_t mph_ii_c;	/* Management: Info Ind, connection */
	uint_t mph_ii_d;	/* Management: Info Ind, disconn. */
#else /* !_LP64 && !_I32LPx */
	ulong_t ph_ai;		/* Physical: Activation Ind */
	ulong_t ph_di;		/* Physical: Deactivation Ind */
	ulong_t mph_ai;		/* Management: Activation Ind */
	ulong_t mph_di;		/* Management: Deactivation Ind */
	ulong_t mph_ei1;	/* Management: Error 1 Indication */
	ulong_t mph_ei2;	/* Management: Error 2 Indication */
	ulong_t mph_ii_c;	/* Management: Info Ind, connection */
	ulong_t mph_ii_d;	/* Management: Info Ind, disconn. */
#endif /* !_LP64 && !_I32LPx */
}; /* struct isdn_interface_info */


/*
 * ISDN_CHANNEL_STATUS ioctl uses this data structure.  If the channel is
 * specified as ISDN_CHAN_SELF, the driver will replace it with the true
 * channel value.
 */
typedef struct isdn_channel_info isdn_channel_info_t;
struct isdn_channel_info {
	isdn_chan_t channel;	/* to be filled in by user */

	/*
	 * Per-channel I/O statistics for receive and transmit
	 */
	enum isdn_iostate iostate;
	struct isdn_io_stats {
#if defined(_LP64) || defined(_I32LPx)
		uint_t packets; /* Number of packets transferred */
		uint_t octets;	/* Number of octets transferred */
		uint_t errors;	/* Number of errors encountered */
#else /* !_LP64 && !_I32LPx */
		ulong_t packets; /* Number of packets transferred */
		ulong_t octets;	/* Number of octets transferred */
		ulong_t errors;	/* Number of errors encountered */
#endif /* !_LP64 && !_I32LPx */
	} transmit, receive;
}; /* struct isdn_channel_info */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ISDNIO_H */
