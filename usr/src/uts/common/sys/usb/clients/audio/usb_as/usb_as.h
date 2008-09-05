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

#ifndef _SYS_USB_AS_H
#define	_SYS_USB_AS_H


#include <sys/usb/usba/usbai_private.h>

#ifdef __cplusplus
extern "C" {
#endif

/* driver specific macros */
#define	USB_AS_HIWATER		(AM_MAX_QUEUED_MSGS_SIZE)
#define	USB_AS_LOWATER		(32*1024)


/* this structure is built from the descriptors */
typedef struct usb_as_alt_descr {
	uchar_t				alt_mode; /* USB_AUDIO_PLAY/RECORD */
	uchar_t				alt_valid;
	uchar_t				alt_format_len;

	uchar_t				alt_n_sample_rates;
	uint_t				*alt_sample_rates;
	uint_t				alt_continuous_sr;

	usb_if_descr_t			*alt_if;
	usb_audio_as_if_descr_t 	*alt_general;
	usb_audio_type1_format_descr_t	*alt_format;
	usb_ep_descr_t			*alt_ep;
	usb_audio_as_isoc_ep_descr_t	*alt_cs_ep;
} usb_as_alt_descr_t;


typedef struct usb_as_power {
	void		*aspm_state;	/* points back to usb_as_state */
	int		aspm_pm_busy;	/* device busy accounting */
	uint8_t		aspm_wakeup_enabled;

	/* this is the bit mask of the power states that device has */
	uint8_t		aspm_pwr_states;

	/* wakeup and power transistion capabilites of an interface */
	uint8_t		aspm_capabilities;

	/* current power level the device is in */
	uint8_t		aspm_current_power;
} usb_as_power_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_power_t::aspm_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_power_t::aspm_wakeup_enabled))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_power_t::aspm_pwr_states))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_power_t::aspm_capabilities))
_NOTE(SCHEME_PROTECTS_DATA("unshared", usb_ctrl_req))


/* usb_as soft state */
typedef struct usb_as_state {
	dev_info_t		*usb_as_dip;
	uint_t			usb_as_instance;
	usb_log_handle_t	usb_as_log_handle;
	uint_t			usb_as_dev_state;
	uint_t			usb_as_ifno;
	kmutex_t		usb_as_mutex;
	queue_t			*usb_as_rq;		/* read q ptr */
	queue_t			*usb_as_wq;		/* write q ptr */
	uint_t			usb_as_streams_flag;	/* streams status */

	/* mblk containing the current control command */
	mblk_t			*usb_as_def_mblk;

	/* serialization */
	usb_serialization_t	usb_as_ser_acc;

	/* registration data */
	usb_client_dev_data_t	*usb_as_dev_data;

	/* info from descriptors per alternate */
	uint_t			usb_as_n_alternates;
	usb_as_alt_descr_t	*usb_as_alts;
	uint_t			usb_as_alternate;

	/* pipe handle */
	usb_pipe_handle_t	usb_as_default_ph;

	/* See below for flags */
	uchar_t			usb_as_xfer_cr;

	/* Isoc pipe stuff */
	usb_pipe_handle_t	usb_as_isoc_ph;
	usb_pipe_policy_t	usb_as_isoc_pp;
	audiohdl_t		usb_as_ahdl;

	uint_t			usb_as_request_count;
	uint_t			usb_as_request_samples;
	usb_audio_formats_t	usb_as_curr_format;

	uint_t			usb_as_pkt_count;
	ushort_t		usb_as_record_pkt_size;

	uchar_t			usb_as_audio_state;
	uchar_t			usb_as_setup_cnt;

	usb_as_power_t		*usb_as_pm; /* power capabilities */

	/* registration data */
	usb_as_registration_t	usb_as_reg;

	/* debug support */
	uint_t			usb_as_send_debug_count;
	uint_t			usb_as_rcv_debug_count;
} usb_as_state_t;

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(usb_as_state_t::usb_as_mutex, usb_as_state_t))
_NOTE(MUTEX_PROTECTS_DATA(usb_as_state_t::usb_as_mutex, usb_as_power_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_pm))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_rq))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_wq))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_default_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_isoc_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_log_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_dev_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_as_state_t::usb_as_ser_acc))

typedef struct usb_as_tq_arg {
	usb_as_state_t	*usb_as_tq_arg_statep;
	int		usb_as_tq_arg_cr;
} usb_as_tq_arg_t;

_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_as_tq_arg_t))


/* Default pipe states */
#define	USB_AS_DEF_AVAILABLE	0
#define	USB_AS_DEF_INUSE	1
#define	USB_AS_DEF_UNAVAILABLE	2


/*
 * If a command has been initiated, the close callback should know
 * how it finished. If there has been an error and ex cb initiaited
 * the async pipe close, an M_ERROR should be sent up. If no error and
 * default xfer cb had initiated close, M_CTL should be sent up. In
 * some other cases, close callback may not send anything up.
 */
#define	USB_AS_SEND_MERR	1
#define	USB_AS_SEND_MCTL	2
#define	USB_AS_SEND_NONE	3


/*
 * States of playing/recording flag
 */
#define	USB_AS_IDLE			0
#define	USB_AS_ACTIVE			1
#define	USB_AS_PLAY_PAUSED		2
#define	USB_AS_STOP_POLLING_STARTED	3

/*
 * Define constants needed for isoc transfer
 */
#define	USB_AS_N_FRAMES			8
#define	USB_AS_MAX_REQUEST_COUNT	3

/*
 * usb_as turns the M_CTL request into a request control request on the
 * default pipe.  usb_as needs the following information in the usb_as_req_t
 * structure.  See the details below for specific values for each command.
 */
typedef struct usb_as_req {
	uint16_t	usb_as_req_wValue;	/* wValue field of request */
	uint16_t	usb_as_req_wIndex;	/* wIndex field of request */
	uint16_t	usb_as_req_wLength;	/* wLength of request */
	mblk_t		*usb_as_req_data;	/* data for send case */
} usb_as_req_t;


/* Streams status */
#define	USB_AS_STREAMS_OPEN		1
#define	USB_AS_STREAMS_DISMANTLING	2

#define	USB_AS_BUFFER_SIZE		256	/* descriptor buffer size */

/* minor node */
#define	USB_AS_CONSTRUCT_MINOR(inst)	(inst)
#define	USB_AS_MINOR_TO_INSTANCE(inst)	(inst)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_AS_H */
