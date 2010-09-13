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

#ifndef _SYS_USB_USB_AH_H
#define	_SYS_USB_USB_AH_H


#ifdef __cplusplus
extern "C" {
#endif

#include <sys/stream.h>

#define	USB_AH_RPT_NUMBER	3

#define	USB_AH_INPUT_RPT	0
#define	USB_AH_OUTPUT_RPT	1
#define	USB_AH_FEATURE_RPT	2

/* definitions for various state machines */
#define	USB_AH_OPEN	0x00000001 /* audio hid is open for business */
#define	USB_AH_QWAIT	0x00000002 /* audio hid is waiting for a response */


typedef struct usb_ah_button_descr {
	uint_t		location;	/* which byte contains button info */
	uint_t		offset;		/* offset of button info */
	uint_t		no_of_bits;	/* size of button info */
	uint_t		pressed;	/* if this button is pressed or not */
	mblk_t		*mblk;		/* mblk for autorepeat feature */
	void		*uahp;		/* Back ptr for timeout routine */
} usb_ah_button_descr_t;

/*
 * structure for each report type, INPUT, OUTPUT or FEATURE
 * Note report id 0 and only one collection is handled
 */

typedef struct usb_ah_rpt {
	hidparser_rpt_t		hid_rpt;
	usb_ah_button_descr_t	button_descr[USAGE_MAX];
} usb_ah_rpt_t;

/* state structure for usb_ah */
typedef struct  usb_ah_state {
	queue_t			*usb_ah_readq;		/* read queue */
	queue_t			*usb_ah_writeq;		/* write queue */
	kmutex_t		usb_ah_mutex;
	int			usb_ah_flags;
	uint_t			usb_ah_packet_size;	/* size usb packet */
	int			usb_ah_uses_report_ids;	/* 1 if rep.ids used */
	int			usb_ah_report_id;	/* report id used by */
							/* the device */

	/* timeout id for re-trigger ctrl */

	timeout_id_t		usb_ah_tid;

	/* Button descr. ptr to the currently pressed autorepeating button */

	usb_ah_button_descr_t	*usb_ah_cur_bd;

	/* Pointer to the parser handle */

	hidparser_handle_t	usb_ah_report_descr;
	usb_ah_rpt_t		usb_ah_report[USB_AH_RPT_NUMBER];
} usb_ah_state_t;

/*
 * Only variable tid is protected by the mutex, all other r/w happens in
 * streams and callback context, thereby ensuring that they are protected
 * by the scheme
 */
_NOTE(MUTEX_PROTECTS_DATA(usb_ah_state_t::usb_ah_mutex, usb_ah_state_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ah_state_t::usb_ah_readq))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ah_state_t::usb_ah_flags))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ah_state_t::usb_ah_tid))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ah_state_t::usb_ah_writeq))
_NOTE(SCHEME_PROTECTS_DATA("unique per call",
			usb_ah_state_t::usb_ah_packet_size))
_NOTE(SCHEME_PROTECTS_DATA("unique per call",
			usb_ah_state_t::usb_ah_uses_report_ids))
_NOTE(SCHEME_PROTECTS_DATA("unique per call",
			usb_ah_state_t::usb_ah_report_id))
_NOTE(SCHEME_PROTECTS_DATA("unique per call",
			usb_ah_state_t::usb_ah_report_descr))
_NOTE(SCHEME_PROTECTS_DATA("unique per call",
			usb_ah_state_t::usb_ah_cur_bd))
_NOTE(SCHEME_PROTECTS_DATA("unique per call",
			usb_ah_state_t::usb_ah_report))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ah_button_descr_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", usb_ah_rpt_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", hidparser_rpt_t))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", hidparser_usage_info_t))

#define	USB_AH_TIMEOUT		50000	/* In usec */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_USB_AH_H */
