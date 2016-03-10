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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USB_AC_H
#define	_SYS_USB_AC_H



#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sunldi.h>
#include <sys/sysmacros.h>
#include <sys/usb/usba/usbai_private.h>


int usb_ac_open(dev_info_t *);
void usb_ac_close(dev_info_t *);


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
	struct usb_ac_state *acp_uacp;	/* usb_ac state pointer */
	dev_info_t	*acp_dip;	/* devinfo pointer */
	uint_t		acp_ifno;	/* interface number */
	int		acp_driver;	/* Plumbed driver, see value below */

	ldi_handle_t	acp_lh;		/* ldi handle of plumbed driver */
	dev_t		acp_devt;	/* devt of plumbed driver */
	ddi_taskq_t	*acp_tqp;	/* taskq for I/O to plumbed driver */
	int		acp_flags;
#define	ACP_ENABLED	1

	void		*acp_data;	/* ptr to streams or hid data */
} usb_ac_plumbed_t;


/*
 * request structure to usb_as: info per MCTL request;
 * only one active at a time.
 */
typedef struct usb_ac_to_as_req {
	usb_audio_formats_t acr_curr_format; /* format data from mixer */
} usb_ac_to_as_req_t;


/* registration and plumbing info per streaming interface */
typedef struct usb_ac_streams_info {
					/* ptr to entry in plumbed list */
	usb_ac_plumbed_t *acs_plumbed;
					/* valid registration data rcvd */
	uint_t		acs_rcvd_reg_data;
					/* pointer to registration data */
	usb_as_registration_t acs_streams_reg;


	/* Multiple command management */
	int		acs_setup_teardown_count;

	uint8_t 	acs_default_gain;
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

typedef struct usb_audio_format {
	int		sr;	/* sample rate */
	uint_t		ch;	/* channels */
	uint_t		prec;	/* precision */
	uint_t		enc;	/* encoding */
} usb_audio_format_t;


typedef struct usb_audio_eng {
	void  *statep;
	usb_ac_streams_info_t *streams;
	audio_engine_t	*af_engp;

	int		af_eflags;	/* ENGINE_* flags */
	usb_audio_format_t	fmt;
	uint64_t  	af_defgain;

	unsigned	intrate;	/* interrupt rate */
	unsigned	sampsz;		/* sample size */
	unsigned	framesz;	/* frame size */
	unsigned	fragsz;		/* fragment size */
	unsigned	nfrags;		/* number of fragments in buffer */
	unsigned	fragfr;		/* number of frames per fragment */
	unsigned	frsmshift;	/* right shift: frames in sample cnt */
	unsigned	smszshift;	/* left shift: sample cnt * sampsz */


	caddr_t		bufp;		/* I/O buf; framework to/from drv */
	unsigned	bufsz;		/* buffer size */
	caddr_t		bufpos;		/* buffer position */
	caddr_t		bufendp;	/* end of buffer */


	uint64_t	frames;
	uint64_t	io_count;	/* i/o requests from the driver */
	uint64_t	bufio_count;	/* i/o requests to the framework */

	boolean_t	started;
	boolean_t	busy;

	kcondvar_t	usb_audio_cv;

	kmutex_t	lock;
} usb_audio_eng_t;


/* limits */
#define	USB_AC_MAX_PLUMBED		3	/* play, record, hid */
#define	USB_AC_MAX_AS_PLUMBED		2	/* play, record */
typedef struct usb_ac_state  usb_ac_state_t;
typedef struct usb_audio_ctrl {
	audio_ctrl_t		*af_ctrlp;	/* framework handle */
	usb_ac_state_t		*statep;

	kmutex_t	ctrl_mutex;
	uint64_t		cval;		/* current control value */
} usb_audio_ctrl_t;

enum {
	CTL_VOLUME_MONO = 0,
	CTL_VOLUME_STERO,
	CTL_REC_MONO,
	CTL_REC_STERO,
	CTL_REC_SRC,
	CTL_MONITOR_GAIN,
	CTL_MIC_BOOST,
	CTL_NUM
};

#define	USB_AC_ENG_MAX   2

/* usb_ac soft state */
struct usb_ac_state {

	dev_info_t		*usb_ac_dip;
	uint_t			usb_ac_instance;
	usb_log_handle_t	usb_ac_log_handle;

	uint_t			usb_ac_dev_state;
	uint_t			usb_ac_ifno;
	kmutex_t		usb_ac_mutex;

	usb_client_dev_data_t	*usb_ac_dev_data; /* registration data */
	audio_dev_t		*usb_ac_audio_dev;




	usb_audio_eng_t  engines[USB_AC_ENG_MAX];



	int		flags;
	usb_audio_ctrl_t	*controls[CTL_NUM];

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
	uint64_t			usb_ac_input_ports;
	uint64_t			usb_ac_output_ports;

	/* pipe handle */
	usb_pipe_handle_t	usb_ac_default_ph;

	/* serial access */
	usb_serialization_t	usb_ac_ser_acc;

	/* power management */
	usb_ac_power_t		*usb_ac_pm; /* power capabilities */

	/* mixer registration data */
	uint_t			usb_ac_registered_with_mixer;

	/* plumbing management */
	uint_t			usb_ac_plumbing_state;
	ushort_t		usb_ac_busy_count;
	usb_ac_plumbed_t	usb_ac_plumbed[USB_AC_MAX_PLUMBED];

	/* Current plumbed module index to usb_ac_plumbed structure */
	int			usb_ac_current_plumbed_index;

	/* per streams interface info */
	usb_ac_streams_info_t	usb_ac_streams[USB_AC_MAX_AS_PLUMBED];


	ddi_taskq_t		*tqp;

	char			dstr[64];
};

/* warlock directives, stable data */
_NOTE(MUTEX_PROTECTS_DATA(usb_ac_state_t::usb_ac_mutex, usb_ac_state_t))
_NOTE(MUTEX_PROTECTS_DATA(usb_ac_state_t::usb_ac_mutex, usb_ac_power_t))
_NOTE(MUTEX_PROTECTS_DATA(usb_ac_state_t::usb_ac_mutex, usb_ac_plumbed_t))
_NOTE(MUTEX_PROTECTS_DATA(usb_audio_eng_t::lock, usb_audio_eng_t))
_NOTE(MUTEX_PROTECTS_DATA(usb_audio_eng_t::lock, usb_audio_format_t))
_NOTE(MUTEX_PROTECTS_DATA(usb_audio_ctrl_t::ctrl_mutex, usb_audio_ctrl_t))


_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_ser_acc))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_pm))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_default_ph))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_log_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_if_descr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_dev_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_ifno))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::flags))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_input_ports))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::engines))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::usb_ac_audio_dev))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_state_t::controls))

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::af_eflags))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::streams))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::statep))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::fmt))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::fragfr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::frsmshift))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::started))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::af_engp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::io_count))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_eng_t::intrate))

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_ctrl_t::statep))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_ctrl_t::af_ctrlp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_ctrl_t::cval))

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_plumbed_t::acp_tqp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ac_plumbed_t::acp_uacp))

_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_audio_format_t::ch))

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

#define	AF_REGISTERED	0x1
#define	AD_SETUP	0x10


int usb_audio_attach(usb_ac_state_t *);
/*
 * framework gain range
 */
#define	AUDIO_CTRL_STEREO_VAL(l, r)	(((l) & 0xff) | (((r) & 0xff) << 8))
#define	AUDIO_CTRL_STEREO_LEFT(v)	((uint8_t)((v) & 0xff))
#define	AUDIO_CTRL_STEREO_RIGHT(v)	((uint8_t)(((v) >> 8) & 0xff))


#define	AF_MAX_GAIN	100
#define	AF_MIN_GAIN	0



int usb_ac_get_audio(void *, void *, int);

void usb_ac_send_audio(void *, void *, int);

void usb_ac_stop_play(usb_ac_state_t *, usb_audio_eng_t *);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_AC_H */
