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

#ifndef _SYS_USB_AC_H
#define	_SYS_USB_AC_H



#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sunldi.h>
#include <sys/usb/usba/usbai_private.h>

/* driver specific macros */
#define	USB_AC_HIWATER		(AM_MAX_QUEUED_MSGS_SIZE)
#define	USB_AC_LOWATER		(32*1024)


/* structure for each unit described by descriptors */
typedef struct usb_ac_unit_list {
	uint_t		acu_type;
	void		*acu_descriptor;
	size_t		acu_descr_length;
} usb_ac_unit_list_t;

#define	USB_AC_ID_NONE			0

#define	USB_AC_FIND_ONE			0
#define	USB_AC_FIND_ALL			1
#define	USB_AC_MAX_DEPTH		8

/*
 * plumbing data; info per plumbed module
 */
typedef struct usb_ac_plumbed {
	dev_info_t	*acp_dip;	/* devinfo pointer */
	uint_t		acp_ifno;	/* interface number */
	int		acp_linkid;	/* link ID for plumbing */
	int		acp_driver;	/* Plumbed driver, see value below */
	queue_t		*acp_lrq;	/* lower read queue */
	queue_t		*acp_lwq;	/* lower write queue */
	void		*acp_data;	/* ptr to streams or hid data */
} usb_ac_plumbed_t;


/*
 * request structure to usb_as: info per MCTL request;
 * only one active at a time.
 */
typedef struct usb_ac_to_as_req {
	int		acr_wait_flag;	/* an mblk sent wait on this flag */
	kcondvar_t	acr_cv;		/* an mblk sent; wait on this cv */
	mblk_t		*acr_reply_mp;	/* response to current request */
	usb_audio_formats_t acr_curr_format; /* format data from mixer */
	int		acr_curr_dir;
} usb_ac_to_as_req_t;


/* registration and plumbing info per streaming interface */
typedef struct usb_ac_streams_info {
					/* ptr to entry in plumbed list */
	usb_ac_plumbed_t *acs_plumbed;
					/* valid registration data rcvd */
	uint_t		acs_rcvd_reg_data;
					/* pointer to registration data */
	usb_as_registration_t *acs_streams_reg;

	/* request structure to usb_as; one active at a time */
	usb_ac_to_as_req_t acs_ac_to_as_req;

	/* Multiple command management */
	int		acs_setup_teardown_count;

	usb_audio_formats_t acs_cur_fmt; /* format data from mixer */
} usb_ac_streams_info_t;


/* power state */
typedef struct usb_ac_power {
	void		*acpm_state;	/* points back to usb_ac_state */
	int		acpm_pm_busy;	/* device busy accounting */
	uint8_t		acpm_wakeup_enabled;

	/* this is the bit mask of the power states that device has */
	uint8_t		acpm_pwr_states;

	/* wakeup and power transistion capabilites of an interface */
	uint8_t		acpm_capabilities;

	/* current power level the device is in */
	uint8_t		acpm_current_power;
} usb_ac_power_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_power_t::acpm_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_power_t::acpm_wakeup_enabled))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_power_t::acpm_pwr_states))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_power_t::acpm_capabilities))

/* limits */
#define	USB_AC_MAX_PLUMBED		3	/* play, record, hid */
#define	USB_AC_MAX_AS_PLUMBED		2	/* play, record */

/* usb_ac soft state */
typedef struct usb_ac_state {
	dev_info_t		*usb_ac_dip;
	uint_t			usb_ac_instance;
	usb_log_handle_t	usb_ac_log_handle;

	uint_t			usb_ac_dev_state;
	uint_t			usb_ac_ifno;
	kmutex_t		usb_ac_mutex;

	usb_client_dev_data_t	*usb_ac_dev_data; /* registration data */

	/* audio framework */
	audiohdl_t		usb_ac_audiohdl;
	am_ad_info_t		usb_ac_am_ad_info;
	audio_info_t		usb_ac_am_ad_defaults;

	/* descriptors */
	usb_if_descr_t		usb_ac_if_descr;

	/* unit number array, indexed by unit ID */
	uint_t			usb_ac_max_unit;
	usb_ac_unit_list_t	*usb_ac_units;

	/* adjacency matrix for reflecting connections */
	uchar_t			**usb_ac_connections;
	size_t			usb_ac_connections_len;
	uchar_t			*usb_ac_connections_a;
	size_t			usb_ac_connections_a_len;
	uchar_t			*usb_ac_unit_type;
	uchar_t			*usb_ac_traverse_path;
	uchar_t			usb_ac_traverse_path_index;

	/* port types, eg LINE IN, Micr, Speakers */
	uint_t			usb_ac_input_ports;
	uint_t			usb_ac_output_ports;

	/* pipe handle */
	usb_pipe_handle_t	usb_ac_default_ph;

	/* streams management */
	queue_t			*usb_ac_rq;		/* read q ptr */
	queue_t			*usb_ac_wq;		/* write q ptr */
	dev_t			usb_ac_dev;	/* dev_t of plumbing open */

	/* serial access */
	usb_serialization_t	usb_ac_ser_acc;

	/* power management */
	usb_ac_power_t		*usb_ac_pm; /* power capabilities */

	/* mixer registration data */
	uint_t			usb_ac_mixer_mode_enable;
	uint_t			usb_ac_registered_with_mixer;

	/* plumbing management */
	int			usb_ac_mux_minor;
	uint_t			usb_ac_plumbing_state;
	ldi_handle_t		usb_ac_mux_lh;
	ushort_t		usb_ac_busy_count;
	usb_ac_plumbed_t	usb_ac_plumbed[USB_AC_MAX_PLUMBED];

	/* Current plumbed module index to usb_ac_plumbed structure */
	int			usb_ac_current_plumbed_index;

	/* per streams interface info */
	usb_ac_streams_info_t	usb_ac_streams[USB_AC_MAX_AS_PLUMBED];

	/*
	 * preserve streams registration because the mixer does not
	 * copy registration data
	 */
	usb_as_registration_t	usb_ac_streams_reg[USB_AC_MAX_AS_PLUMBED];
} usb_ac_state_t;

typedef struct usb_ac_state_space {
	void			*sp;	/* soft state for the instance */
				/* ptr to usb_ac_restore_audio_state */
	int			(*restore_func)
					(usb_ac_state_t *, int);
				/* ptr to usb_ac_get_featureID */
	uint_t			(* get_featureID_func)
					(usb_ac_state_t *, uchar_t,
					uint_t, uint_t);
				/* ptr to the usb_ac entry points */
	am_ad_entry_t		*ac_entryp;
				/* ptr to pm_busy/idle calls */
	void			(*pm_busy_component)
					(usb_ac_state_t *);
	void			(*pm_idle_component)
					(usb_ac_state_t *);
} usb_ac_state_space_t;

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(usb_ac_state_t::usb_ac_mutex, usb_ac_state_t))
_NOTE(MUTEX_PROTECTS_DATA(usb_ac_state_t::usb_ac_mutex, usb_ac_power_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_ser_acc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_pm))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_default_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_log_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_if_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_audiohdl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_dev_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_ifno))

/* usb_ac driver only care about two states:  plumbed or unplumbed */
#define	USB_AC_STATE_UNPLUMBED		0
#define	USB_AC_STATE_PLUMBED		1
#define	USB_AC_STATE_PLUMBED_RESTORING	2

/* Default pipe states */
#define	USB_AC_DEF_CLOSED		0
#define	USB_AC_DEF_OPENED		1

#define	USB_AC_BUFFER_SIZE		256	/* descriptor buffer size */


/*
 * delay before restoring state
 */
#define	USB_AC_RESTORE_DELAY		drv_usectohz(1000000)

/* value for acp_driver */
#define	USB_AS_PLUMBED	1
#define	USB_AH_PLUMBED	2
#define	UNKNOWN_PLUMBED	3

/* other useful macros */
#define	offsetof(s, m)	((size_t)(&(((s *)0)->m)))

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_AC_H */
