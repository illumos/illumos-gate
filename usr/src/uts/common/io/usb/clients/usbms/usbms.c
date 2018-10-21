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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/usb/clients/hidparser/hidparser.h>

#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/systm.h>
#include <sys/vuid_event.h>
#include <sys/vuid_wheel.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/strtty.h>
#include <sys/msreg.h>
#include <sys/msio.h>

#include <sys/usb/clients/usbms/usbms.h>

/* debugging information */
uint_t	usbms_errmask = (uint_t)PRINT_MASK_ALL;
uint_t	usbms_errlevel = USB_LOG_L2;
static usb_log_handle_t usbms_log_handle;

static struct streamtab		usbms_streamtab;

static struct fmodsw fsw = {
			"usbms",
			&usbms_streamtab,
			D_MP | D_MTPERMOD
};

/*
 * Module linkage information for the kernel.
 */
static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"USB mouse streams",
	&fsw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlstrmod,
	NULL
};


int
_init(void)
{
	int rval = mod_install(&modlinkage);

	if (rval == 0) {
		usbms_log_handle = usb_alloc_log_hdl(NULL, "usbms",
		    &usbms_errlevel, &usbms_errmask, NULL, 0);
	}

	return (rval);
}

int
_fini(void)
{
	int rval = mod_remove(&modlinkage);

	if (rval == 0) {
		usb_free_log_hdl(usbms_log_handle);
	}

	return (rval);
}


int
_info(struct modinfo *modinfop)
{

	return (mod_info(&modlinkage, modinfop));
}


/* Function prototypes */
static void usbms_reioctl(void *);
static void usbms_ioctl(queue_t *, mblk_t *);
static int usbms_open(queue_t *, dev_t *, int, int, cred_t *);
static int usbms_close(queue_t *, int, cred_t *);
static int usbms_wput(queue_t *, mblk_t *);
static int usbms_rput(queue_t *, mblk_t *);
static void usbms_mctl_receive(queue_t *, mblk_t *);

static int usbms_rserv(queue_t *);
static void usbms_miocdata(queue_t *, mblk_t *);

static void usbms_resched(void *);

static int usbms_getparms(Ms_parms *, usbms_state_t *);

static int usbms_setparms(Ms_parms *, usbms_state_t *);

static int usbms_get_screen_parms(queue_t *q, mblk_t *);

static void usbms_flush(usbms_state_t *);

static void usbms_incr(void *);
static void usbms_input(usbms_state_t *, mblk_t	*);
static void usbms_rserv_vuid_button(queue_t *, struct usbmouseinfo *,
    mblk_t **);

static void usbms_rserv_vuid_event_y(queue_t *, struct usbmouseinfo *,
    mblk_t **);
static void usbms_rserv_vuid_event_x(queue_t *, struct usbmouseinfo *,
    mblk_t **);
static void usbms_rserv_vuid_event_wheel(queue_t *, struct usbmouseinfo *,
    mblk_t **, ushort_t);
static int usbms_check_for_wheels(usbms_state_t *);
static int usbms_make_copyreq(mblk_t *, uint_t, uint_t, uint_t, uint_t, uint_t);
static int usbms_service_wheel_info(queue_t *, mblk_t *);
static int usbms_service_wheel_state(queue_t *, mblk_t *, uint_t);
static void usbms_ack_ioctl(mblk_t *);
static int usbms_read_input_data_format(usbms_state_t *);
static mblk_t *usbms_setup_abs_mouse_event(void);
static int usbms_get_coordinate(uint_t, uint_t, mblk_t *);

/*
 * Device driver qinit functions
 */
static struct module_info usbms_mod_info = {
	0x0ffff,		/* module id number */
	"usbms",		/* module name */
	0,			/* min packet size accepted */
	INFPSZ,			/* max packet size accepted */
	512,			/* hi-water mark */
	128			/* lo-water mark */
};

/* read side queue information structure */
static struct qinit rinit = {
	usbms_rput,		/* put procedure not needed */
	usbms_rserv,		/* service procedure */
	usbms_open,		/* called on startup */
	usbms_close,		/* called on finish */
	NULL,			/* for future use */
	&usbms_mod_info,	/* module information structure */
	NULL			/* module statistics structure */
};

/* write side queue information structure */
static struct qinit winit = {
	usbms_wput,		/* put procedure */
	NULL,			/* no service proecedure needed */
	NULL,			/* open not used on write side */
	NULL,			/* close not used on write side */
	NULL,			/* for future use */
	&usbms_mod_info,	/* module information structure */
	NULL			/* module statistics structure */
};

static struct streamtab usbms_streamtab = {
	&rinit,
	&winit,
	NULL,			/* not a MUX */
	NULL			/* not a MUX */
};

/*
 * Message when overrun circular buffer
 */
static int			overrun_msg;

/* Increment when overrun circular buffer */
static int			overrun_cnt;

extern int			hz;

/*
 * Mouse buffer size in bytes.	Place here as variable so that one could
 * massage it using adb if it turns out to be too small.
 */
static uint16_t			usbms_buf_bytes = USBMS_BUF_BYTES;


/*
 * Regular STREAMS Entry points
 */

/*
 * usbms_open() :
 *	open() entry point for the USB mouse module.
 */
/*ARGSUSED*/
static int
usbms_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	struct usbmousebuf	*mousebufp;
	struct ms_softc	*msd_soft;
	usbms_state_t			*usbmsp;
	struct iocblk			mctlmsg;
	mblk_t				*mctl_ptr;


	/* Clone opens are not allowed */
	if (sflag != MODOPEN)
		return (EINVAL);

	/* If the module is already open, just return */
	if (q->q_ptr) {
		return (0);
	}

	/* allocate usbms state structure */
	usbmsp = kmem_zalloc(sizeof (usbms_state_t), KM_SLEEP);

	q->q_ptr = usbmsp;
	WR(q)->q_ptr = usbmsp;

	usbmsp->usbms_rq_ptr = q;
	usbmsp->usbms_wq_ptr = WR(q);

	qprocson(q);

	/*
	 * Set up private data.
	 */
	usbmsp->usbms_state = USBMS_WAIT_BUTN;
	usbmsp->usbms_iocpending = NULL;
	usbmsp->usbms_jitter_thresh = USBMS_JITTER_THRESH;
	usbmsp->usbms_speedlimit = USBMS_SPEEDLIMIT;
	usbmsp->usbms_speedlaw = USBMS_SPEEDLAW;
	usbmsp->usbms_speed_count = USBMS_SPEED_COUNT;

	msd_soft = &usbmsp->usbms_softc;

	/*
	 * Initially set the format to MS_VUID_FORMAT
	 */
	msd_soft->ms_readformat = MS_VUID_FORMAT;

	/*
	 * Allocate buffer and initialize data.
	 */
	msd_soft->ms_bufbytes = usbms_buf_bytes;
	mousebufp = kmem_zalloc(msd_soft->ms_bufbytes, KM_SLEEP);

	/* Truncation  will happen */
	mousebufp->mb_size = (uint16_t)((msd_soft->ms_bufbytes -
	    sizeof (struct usbmousebuf)) / sizeof (struct usbmouseinfo));
	mousebufp->mb_info = (struct usbmouseinfo *)((char *)mousebufp +
	    sizeof (struct usbmousebuf));
	usbmsp->usbms_buf = mousebufp;
	msd_soft->ms_vuidaddr = VKEY_FIRST;
	usbmsp->usbms_jittertimeout = JITTER_TIMEOUT;

	/* request hid report descriptor from HID */
	mctlmsg.ioc_cmd = HID_GET_PARSER_HANDLE;
	mctlmsg.ioc_count = 0;

	mctl_ptr = usba_mk_mctl(mctlmsg, NULL, 0);
	if (mctl_ptr == NULL) {
		qprocsoff(q);
		kmem_free(usbmsp->usbms_buf, msd_soft->ms_bufbytes);
		kmem_free(usbmsp, sizeof (usbms_state_t));

		return (ENOMEM);
	}

	usbmsp->usbms_flags |= USBMS_QWAIT;
	putnext(usbmsp->usbms_wq_ptr, mctl_ptr);

	/*
	 * Now that signal has been sent, wait for report descriptor.  Cleanup
	 * if user signals in the mean time (as when this gets opened in an
	 * inappropriate context and the user types a ^C).
	 */
	while (usbmsp->usbms_flags & USBMS_QWAIT) {

		if (qwait_sig(q) == 0) {
			qprocsoff(q);
			kmem_free(usbmsp->usbms_buf, msd_soft->ms_bufbytes);
			kmem_free(usbmsp, sizeof (usbms_state_t));

			return (EINTR);
		}
	}

	if (usbmsp->usbms_report_descr_handle != NULL) {
		if (hidparser_get_usage_attribute(
		    usbmsp->usbms_report_descr_handle,
		    0,
		    HIDPARSER_ITEM_INPUT,
		    USBMS_USAGE_PAGE_BUTTON,
		    0,
		    HIDPARSER_ITEM_REPORT_COUNT,
		    (int32_t *)&usbmsp->usbms_num_buttons) ==
		    HIDPARSER_SUCCESS) {
			if (usbmsp->usbms_num_buttons > USB_MS_MAX_BUTTON_NO)
				usbmsp->usbms_num_buttons =
				    USB_MS_MAX_BUTTON_NO;
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    usbms_log_handle, "Num of buttons is : %d",
			    usbmsp->usbms_num_buttons);
		} else {
			USB_DPRINTF_L3(PRINT_MASK_OPEN,
			    usbms_log_handle,
			    "hidparser_get_usage_attribute failed : "
			    "Set to default number of buttons(3).");

			usbmsp->usbms_num_buttons = USB_MS_DEFAULT_BUTTON_NO;
		}
	} else {
		USB_DPRINTF_L1(PRINT_MASK_ALL,
		    usbms_log_handle, "Invalid HID "
		    "Descriptor Tree. Set to default value(3 buttons).");
		usbmsp->usbms_num_buttons = USB_MS_DEFAULT_BUTTON_NO;
	}

	/* check if this mouse has wheel */
	if (usbms_check_for_wheels(usbmsp) == USB_FAILURE) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, usbms_log_handle,
		    "No wheels detected");
	} else {
		USB_DPRINTF_L2(PRINT_MASK_ALL, usbms_log_handle,
		    "Wheel detected");
	}

	usbms_flush(usbmsp);

	/* get the data format from the hid descriptor */
	if (usbms_read_input_data_format(usbmsp) != USB_SUCCESS) {

		qprocsoff(q);
		kmem_free(usbmsp->usbms_buf, msd_soft->ms_bufbytes);
		kmem_free(usbmsp, sizeof (usbms_state_t));

		return (EINVAL);
	}

	usbmsp->usbms_flags |= USBMS_OPEN;

	USB_DPRINTF_L3(PRINT_MASK_OPEN, usbms_log_handle,
	    "usbms_open exiting");

	return (0);
}


/*
 * usbms_close() :
 *	close() entry point for the USB mouse module.
 */
/*ARGSUSED*/
static int
usbms_close(queue_t *q, int flag, cred_t *credp)
{
	usbms_state_t			*usbmsp = q->q_ptr;
	struct	ms_softc	*ms = &usbmsp->usbms_softc;

	USB_DPRINTF_L3(PRINT_MASK_CLOSE, usbms_log_handle,
	    "usbms_close entering");

	qprocsoff(q);

	if (usbmsp->usbms_jitter) {
		(void) quntimeout(q,
		    (timeout_id_t)(long)usbmsp->usbms_timeout_id);
		usbmsp->usbms_jitter = 0;
	}
	if (usbmsp->usbms_reioctl_id) {
		qunbufcall(q, (bufcall_id_t)(long)usbmsp->usbms_reioctl_id);
		usbmsp->usbms_reioctl_id = 0;
	}
	if (usbmsp->usbms_resched_id) {
		qunbufcall(q, (bufcall_id_t)usbmsp->usbms_resched_id);
		usbmsp->usbms_resched_id = 0;
	}
	if (usbmsp->usbms_iocpending != NULL) {
		/*
		 * We were holding an "ioctl" response pending the
		 * availability of an "mblk" to hold data to be passed up;
		 * another "ioctl" came through, which means that "ioctl"
		 * must have timed out or been aborted.
		 */
		freemsg(usbmsp->usbms_iocpending);
		usbmsp->usbms_iocpending = NULL;
	}


	/* Free mouse buffer */
	if (usbmsp->usbms_buf != NULL) {
		kmem_free(usbmsp->usbms_buf, ms->ms_bufbytes);
	}

	kmem_free(usbmsp, sizeof (usbms_state_t));

	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;


	USB_DPRINTF_L3(PRINT_MASK_CLOSE, usbms_log_handle,
	    "usbms_close exiting");

	return (0);
}


/*
 * usbms_rserv() :
 *	Read queue service routine.
 *	Turn buffered mouse events into stream messages.
 */
static int
usbms_rserv(queue_t		*q)
{
	usbms_state_t		*usbmsp = q->q_ptr;
	struct ms_softc		*ms;
	struct usbmousebuf	*b;
	struct usbmouseinfo	*mi;
	mblk_t			*bp;
	ushort_t		i, loop;
	uchar_t			nbutt = (uchar_t)usbmsp->usbms_num_buttons;

	ms = &usbmsp->usbms_softc;
	b = usbmsp->usbms_buf;

	USB_DPRINTF_L3(PRINT_MASK_SERV, usbms_log_handle,
	    "usbms_rserv entering");

	while (canputnext(q) && ms->ms_oldoff != b->mb_off) {
		mi = &b->mb_info[ms->ms_oldoff];
		switch (ms->ms_readformat) {

		case MS_3BYTE_FORMAT: {
			char	*cp;

			if ((usbmsp->usbms_idf).xlen != 1) {
				USB_DPRINTF_L3(PRINT_MASK_SERV,
				    usbms_log_handle,
				    "Can't set to 3 byte format. Length != 1");

				return (0);
			}
			if ((bp = allocb(3, BPRI_HI)) != NULL) {
				cp = (char *)bp->b_wptr;

				*cp++ = 0x80 | (mi->mi_buttons & 0xFF);
				/* Update read buttons */
				ms->ms_prevbuttons = mi->mi_buttons;

				*cp++ = (mi->mi_x & 0xFF);
				*cp++ = ((-mi->mi_y) & 0xFF);
				/* lower pri to avoid mouse droppings */
				bp->b_wptr = (uchar_t *)cp;
				putnext(q, bp);
			} else {
				if (usbmsp->usbms_resched_id) {
					qunbufcall(q,
					    (bufcall_id_t)usbmsp->
					    usbms_resched_id);
				}
				usbmsp->usbms_resched_id = qbufcall(q,
				    (size_t)3,
				    (uint_t)BPRI_HI,
				    (void (*)())usbms_resched,
				    (void *) usbmsp);
				if (usbmsp->usbms_resched_id == 0)

					return (0);	/* try again later */
				/* bufcall failed; just pitch this event */
				/* or maybe flush queue? */
			}
			ms->ms_oldoff++;	/* next event */

			/* circular buffer wraparound */
			if (ms->ms_oldoff >= b->mb_size) {
				ms->ms_oldoff = 0;
			}
			break;
		}

		case MS_VUID_FORMAT:
		default: {

			do {
				bp = NULL;

				switch (ms->ms_eventstate) {

				case EVENT_WHEEL:
					loop = (usbmsp->usbms_num_wheels ?
					    1 : 0);

					if (usbmsp->usbms_num_wheels) {
						for (i = 0; i < loop; i++) {
						usbms_rserv_vuid_event_wheel
						    (q, mi, &bp, i);
						}
					}

					break;
				case EVENT_BUT8:
				case EVENT_BUT7:
				case EVENT_BUT6:
				case EVENT_BUT5:
				case EVENT_BUT4:
				case EVENT_BUT3:  /* Send right button */
				case EVENT_BUT2:  /* Send middle button */
				case EVENT_BUT1:  /* Send left button */
					usbms_rserv_vuid_button(q, mi, &bp);

					break;
				case EVENT_Y:
					usbms_rserv_vuid_event_y(q, mi, &bp);

					break;
				case EVENT_X:
					usbms_rserv_vuid_event_x(q, mi, &bp);

					break;
				default:
					/* start again */
					ms->ms_eventstate = EVENT_WHEEL;

					break;
				}
				if (bp != NULL) {
					/* lower pri to avoid mouse droppings */
					bp->b_wptr += sizeof (Firm_event);
					putnext(q, bp);
				}
				if (ms->ms_eventstate == EVENT_X) {
					ms->ms_eventstate = EVENT_WHEEL;
				} else if (ms->ms_eventstate == EVENT_WHEEL) {
					ms->ms_oldoff++;	/* next event */
					/* circular buffer wraparound */
					if (ms->ms_oldoff >= b->mb_size) {
						ms->ms_oldoff = 0;
					}
					ms->ms_eventstate = EVENT_BUT(nbutt);
				} else
					ms->ms_eventstate--;
			} while (ms->ms_eventstate != EVENT_BUT(nbutt));
		}
		}
	}
	USB_DPRINTF_L3(PRINT_MASK_SERV, usbms_log_handle,
	    "usbms_rserv exiting");
	return (0);
}


/*
 * usbms_rserv_vuid_event_wheel
 *	convert wheel data to firm events
 */
static void
usbms_rserv_vuid_event_wheel(queue_t *q, struct usbmouseinfo *mi,
    mblk_t **bpaddr, ushort_t id)
{
	Firm_event *fep;
	mblk_t *tmp;
	struct ms_softc *ms;
	usbms_state_t *usbmsp = (usbms_state_t *)q->q_ptr;

	if (!(usbmsp->usbms_wheel_state_bf & (1 << id))) {

		return;
	}
	ms = &usbmsp->usbms_softc;
	if (mi->mi_z) {
		if ((tmp = allocb(sizeof (Firm_event), BPRI_HI)) != NULL) {
			fep = (Firm_event *)tmp->b_wptr;
			fep->id = vuid_id_addr(vuid_first(VUID_WHEEL)) |
			    vuid_id_offset(id);
			fep->pair_type = FE_PAIR_NONE;
			fep->pair = NULL;
			fep->value = mi->mi_z;
			fep->time = mi->mi_time;
			*bpaddr = tmp;
		} else {
			if (usbmsp->usbms_resched_id) {
				qunbufcall(q,
				    (bufcall_id_t)usbmsp->usbms_resched_id);
			}
			usbmsp->usbms_resched_id =
			    qbufcall(q, sizeof (Firm_event), BPRI_HI,
			    (void (*)())usbms_resched, (void *) usbmsp);
			if (usbmsp->usbms_resched_id == 0) {
				/* try again later */

				return;
			}

			/* flush the queue */
			ms->ms_eventstate = EVENT_WHEEL;
		}
	}
}


/*
 * usbms_rserv_vuid_button() :
 *	Process a VUID button event
 */
static void
usbms_rserv_vuid_button(queue_t *q, struct usbmouseinfo	*mi, mblk_t **bpaddr)
{
	usbms_state_t		*usbmsp = q->q_ptr;
	struct ms_softc	*ms;
	int			button_number;
	uchar_t			hwbit = 0x0;
	Firm_event		*fep;
	mblk_t			*bp;
	uchar_t			nbutt;

	ms = &usbmsp->usbms_softc;

	/* Test button. Send an event if it changed. */
	nbutt = (uchar_t)usbmsp->usbms_num_buttons;
	button_number = nbutt - (EVENT_BUT(nbutt) - ms->ms_eventstate) - 1;
	switch (button_number) {
	case	2:
		/* Right button */
		hwbit = 0x01;

		break;
	case	1:
		/*
		 * On two-button mice, the second button is the "right"
		 * button.  There is no "middle".  The vuidps2.c file has
		 * a bmap[] array in sendButtonEvent().  We do something
		 * equivalent here ONLY in the case of two-button mice.
		 */
		if (nbutt == 2) {
			hwbit = 0x01;
			/*
			 * Trick the vuid message into thinking it's a
			 * right-button click also.
			 */
			button_number = 2;
		} else {
			/* ... otherwise, it's just the middle button */
			hwbit = 0x02;
		}
		break;
	case	0:
		/* Left button */
		hwbit = 0x04;

		break;
	default	:
		/* Any other button */
		hwbit = USBMS_BUT(nbutt) >> (EVENT_BUT(nbutt) -
		    ms->ms_eventstate);

		break;
	}

	if ((ms->ms_prevbuttons & hwbit) !=
	    (mi->mi_buttons & hwbit)) {
		if ((bp = allocb(sizeof (Firm_event),
		    BPRI_HI)) != NULL) {
			*bpaddr = bp;
			fep = (Firm_event *)bp->b_wptr;
			fep->id = vuid_id_addr(
			    ms->ms_vuidaddr) |
			    vuid_id_offset(BUT(1)
			    + button_number);
			fep->pair_type = FE_PAIR_NONE;
			fep->pair = 0;

			/*
			 * Update read buttons and set
			 * value
			 */
			if (mi->mi_buttons & hwbit) {
				fep->value = 0;
				ms->ms_prevbuttons |=
				    hwbit;
			} else {
				fep->value = 1;
				ms->ms_prevbuttons &=
				    ~hwbit;
			}
			fep->time = mi->mi_time;
		} else {
			if (usbmsp->usbms_resched_id) {
				qunbufcall(q,
				    (bufcall_id_t)usbmsp->usbms_resched_id);
			}
			usbmsp->usbms_resched_id =
			    qbufcall(q,
			    sizeof (Firm_event),
			    BPRI_HI,
			    (void (*)())usbms_resched,
			    (void *) usbmsp);
			if (usbmsp->usbms_resched_id == 0)
				/* try again later */
				return;
			/*
			 * bufcall failed; just pitch
			 * this event
			 */
			/* or maybe flush queue? */
			ms->ms_eventstate = EVENT_WHEEL;
		}
	}
}

/*
 * usbms_rserv_vuid_event_y() :
 *	Process a VUID y-event
 */
static void
usbms_rserv_vuid_event_y(queue_t *q, struct usbmouseinfo *mi, mblk_t **bpaddr)
{
	usbms_state_t			*usbmsp = q->q_ptr;
	struct ms_softc	*ms;
	Firm_event		*fep;
	mblk_t				*bp;

	ms = &usbmsp->usbms_softc;

	/*
	 * The (max, 0) message and (0, max) message are always sent before
	 * the button click message is sent on the IBM Bladecenter. Stop
	 * their sending may prevent the coordinate from moving to the
	 * (max, max).
	 */
	if (!(((usbmsp->usbms_idf).yattr) & HID_MAIN_ITEM_RELATIVE)) {
		if ((mi->mi_x == 0) &&
		    (mi->mi_y == usbmsp->usbms_logical_Ymax)) {

			return;
		}
	}

	/* Send y if changed. */
	if (mi->mi_y != 0) {
		if ((bp = allocb(sizeof (Firm_event),
		    BPRI_HI)) != NULL) {
			*bpaddr = bp;
			fep = (Firm_event *)bp->b_wptr;
			if (((usbmsp->usbms_idf).yattr) &
			    HID_MAIN_ITEM_RELATIVE) {
				fep->id = vuid_id_addr(
				    ms->ms_vuidaddr) |
				    vuid_id_offset(
				    LOC_Y_DELTA);
				fep->pair_type =
				    FE_PAIR_ABSOLUTE;
				fep->pair =
				    (uchar_t)LOC_Y_ABSOLUTE;
				fep->value = -(mi->mi_y);
			} else {
				fep->id = vuid_id_addr(
				    ms->ms_vuidaddr) |
				    vuid_id_offset(
				    LOC_Y_ABSOLUTE);
				fep->pair_type = FE_PAIR_DELTA;
				fep->pair = (uchar_t)LOC_Y_DELTA;
				fep->value = (mi->mi_y *
				    ((usbmsp->usbms_resolution).height) /
				    usbmsp->usbms_logical_Ymax);
				if ((mi->mi_y *
				    ((usbmsp->usbms_resolution).height) %
				    usbmsp->usbms_logical_Ymax) >=
				    (usbmsp->usbms_logical_Ymax / 2)) {
					fep->value ++;
				}
			}
			fep->time = mi->mi_time;
		} else {
			if (usbmsp->usbms_resched_id) {
				qunbufcall(q,
				    (bufcall_id_t)usbmsp->usbms_resched_id);
			}
			usbmsp->usbms_resched_id =
			    qbufcall(q,
			    sizeof (Firm_event),
			    BPRI_HI,
			    (void (*)())usbms_resched,
			    (void *)usbmsp);
			if (usbmsp->usbms_resched_id == 0) {
				/* try again later */
				return;
			}

			/*
			 * bufcall failed; just pitch
			 * this event
			 */
			/* or maybe flush queue? */
			ms->ms_eventstate = EVENT_WHEEL;
		}
	}
}

/*
 * usbms_rserv_vuid_event_x() :
 *	Process a VUID x-event
 */
static void
usbms_rserv_vuid_event_x(queue_t *q, struct usbmouseinfo *mi, mblk_t **bpaddr)
{
	usbms_state_t			*usbmsp = q->q_ptr;
	struct ms_softc	*ms;
	Firm_event		*fep;
	mblk_t				*bp;

	ms = &usbmsp->usbms_softc;

	/*
	 * The (max, 0) message and (0, max) message are always sent before
	 * the button click message is sent on the IBM Bladecenter. Stop
	 * their sending may prevent the coordinate from moving to the
	 * (max, max).
	 */
	if (!(((usbmsp->usbms_idf).xattr) & HID_MAIN_ITEM_RELATIVE)) {
		if ((mi->mi_y == 0) &&
		    (mi->mi_x == usbmsp->usbms_logical_Xmax)) {

		return;
		}
	}

	/* Send x if changed. */
	if (mi->mi_x != 0) {
		if ((bp = allocb(sizeof (Firm_event),
		    BPRI_HI)) != NULL) {
			*bpaddr = bp;
			fep = (Firm_event *)bp->b_wptr;
			if (((usbmsp->usbms_idf).xattr) &
			    HID_MAIN_ITEM_RELATIVE) {
				fep->id = vuid_id_addr(
				    ms->ms_vuidaddr) |
				    vuid_id_offset(LOC_X_DELTA);
				fep->pair_type =
				    FE_PAIR_ABSOLUTE;
				fep->pair =
				    (uchar_t)LOC_X_ABSOLUTE;
				fep->value = mi->mi_x;
			} else {
				fep->id = vuid_id_addr(ms->ms_vuidaddr) |
				    vuid_id_offset(LOC_X_ABSOLUTE);
				fep->pair_type = FE_PAIR_DELTA;
				fep->pair = (uchar_t)LOC_X_DELTA;
				fep->value = (mi->mi_x *
				    ((usbmsp->usbms_resolution).width) /
				    usbmsp->usbms_logical_Xmax);
				if ((mi->mi_x *
				    ((usbmsp->usbms_resolution).width) %
				    usbmsp->usbms_logical_Xmax) >=
				    (usbmsp->usbms_logical_Xmax / 2)) {
					fep->value ++;
				}
			}
			fep->time = mi->mi_time;
		} else {
			if (usbmsp->usbms_resched_id)
				qunbufcall(q,
				    (bufcall_id_t)usbmsp->usbms_resched_id);
			usbmsp->usbms_resched_id =
			    qbufcall(q,
			    sizeof (Firm_event),
			    BPRI_HI,
			    (void (*)())usbms_resched,
			    (void *) usbmsp);
			if (usbmsp->usbms_resched_id == 0)
				/* try again later */
				return;

			/*
			 * bufcall failed; just
			 * pitch this event
			 */
			/* or maybe flush queue? */
			ms->ms_eventstate = EVENT_WHEEL;
		}
	}
}

/*
 * usbms_resched() :
 *	Callback routine for the qbufcall() in case
 *	of allocb() failure. When buffer becomes
 *	available, this function is called and
 *	enables the queue.
 */
static void
usbms_resched(void *usbmsp)
{
	queue_t	*q;
	usbms_state_t	*tmp_usbmsp = (usbms_state_t *)usbmsp;

	tmp_usbmsp->usbms_resched_id = 0;
	if ((q = tmp_usbmsp->usbms_rq_ptr) != 0)
		qenable(q);	/* run the service procedure */
}

/*
 * usbms_wput() :
 *	wput() routine for the mouse module.
 *	Module below : hid, module above : consms
 */
static int
usbms_wput(queue_t *q, mblk_t *mp)
{
	USB_DPRINTF_L3(PRINT_MASK_ALL, usbms_log_handle,
	    "usbms_wput entering");
	switch (mp->b_datap->db_type) {

	case M_FLUSH:  /* Canonical flush handling */
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
		}

		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHDATA);
		}

		putnext(q, mp); /* pass it down the line. */
		break;

	case M_IOCTL:
		usbms_ioctl(q, mp);
		break;

	case M_IOCDATA:
		usbms_miocdata(q, mp);

		break;
	default:
		putnext(q, mp); /* pass it down the line. */
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, usbms_log_handle,
	    "usbms_wput exiting");

	return (0);
}


/*
 * usbms_ioctl() :
 *	Process ioctls we recognize and own.  Otherwise, NAK.
 */
static void
usbms_ioctl(queue_t *q, mblk_t *mp)
{
	usbms_state_t *usbmsp = (usbms_state_t *)q->q_ptr;
	struct ms_softc		*ms;
	struct iocblk		*iocp;
	Vuid_addr_probe		*addr_probe;
	uint_t			ioctlrespsize;
	int			err = 0;
	mblk_t			*datap;
	ushort_t		transparent = 0;
	boolean_t		report_abs = B_FALSE;
	mblk_t	*mb;

	USB_DPRINTF_L3(PRINT_MASK_IOCTL, usbms_log_handle,
	    "usbms_ioctl entering");

	if (usbmsp == NULL) {
		miocnak(q, mp, 0, EINVAL);

		return;
	}
	ms = &usbmsp->usbms_softc;

	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {

	case VUIDSFORMAT:
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;

		if (*(int *)mp->b_cont->b_rptr == ms->ms_readformat) {
			break;
		}
		ms->ms_readformat = *(int *)mp->b_cont->b_rptr;
		/*
		 * Flush mouse buffer because the messages upstream of us
		 * are in the old format.
		 */

		usbms_flush(usbmsp);
		break;

	case VUIDGFORMAT:
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = ms->ms_readformat;
		datap->b_wptr += sizeof (int);
		freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case VUIDGADDR:
	case VUIDSADDR:
		err = miocpullup(mp, sizeof (Vuid_addr_probe));
		if (err != 0)
			break;

		addr_probe = (Vuid_addr_probe *)mp->b_cont->b_rptr;
		if (addr_probe->base != VKEY_FIRST) {
			err = ENODEV;
			break;
		}
		if (iocp->ioc_cmd == VUIDSADDR)
			ms->ms_vuidaddr = addr_probe->data.next;
		else
			addr_probe->data.current = ms->ms_vuidaddr;
		break;

	case MSIOGETPARMS:
		if ((datap = allocb(sizeof (Ms_parms), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (Ms_parms);
			goto allocfailure;
		}
		err = usbms_getparms((Ms_parms *)datap->b_wptr, usbmsp);
		datap->b_wptr += sizeof (Ms_parms);
		freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (Ms_parms);
		break;

	case MSIOSETPARMS:
		err = miocpullup(mp, sizeof (Ms_parms));
		if (err != 0)
			break;
		err = usbms_setparms((Ms_parms *)mp->b_cont->b_rptr, usbmsp);
		break;

	case MSIOBUTTONS:
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = (int)usbmsp->usbms_num_buttons;
		datap->b_wptr += sizeof (int);
		freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);

		break;
	case VUIDGWHEELCOUNT:
		/*
		 * New IOCTL support. Since it's explicitly mentioned that
		 * you can't add more ioctls to stream head's hard coded
		 * list, we have to do the transparent ioctl processing
		 * which is heavy.
		 */

		/* Currently support for only one wheel */

		if (iocp->ioc_count == TRANSPARENT) {
			transparent = 1;
			if (err = usbms_make_copyreq(mp, 0, 0, sizeof (int),
			    0, M_COPYOUT)) {

				break;
			}
		}
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);

			goto allocfailure;
		}
		*((int *)datap->b_wptr) = (usbmsp->usbms_num_wheels ? 1 : 0);
		datap->b_wptr +=  sizeof (int);
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mp->b_cont = datap;
		if (transparent) {
			qreply(q, mp);

			return;
		}

		break;
	case VUIDGWHEELINFO:
		if (iocp->ioc_count == TRANSPARENT) {
			if (err = usbms_make_copyreq(mp,
			    sizeof (usbms_iocstate_t),
			    USBMS_GETSTRUCT,
			    sizeof (wheel_info),
			    0,
			    M_COPYIN)) {

				break;
			}
			/*
			 * If there is no b_cont the earlier func. will fail.
			 * Hence there is no need for an explicit check here.
			 */
			freemsg(mp->b_cont);
			mp->b_cont = (mblk_t *)NULL;
			qreply(q, mp);

			return;
		}
		if (mp->b_cont == NULL || iocp->ioc_count !=
		    sizeof (wheel_info)) {
			err = EINVAL;
			break;
		}
		datap = mp->b_cont;
		err = usbms_service_wheel_info(q, datap);

		break;
	case VUIDGWHEELSTATE:
		if (iocp->ioc_count == TRANSPARENT) {
			if (err = usbms_make_copyreq(mp,
			    sizeof (usbms_iocstate_t),
			    USBMS_GETSTRUCT,
			    sizeof (wheel_state),
			    0,
			    M_COPYIN)) {

				break;
			}
			freemsg(mp->b_cont);
			mp->b_cont = (mblk_t *)NULL;
			qreply(q, mp);

			return;
		}
		if ((mp->b_cont == NULL) ||
		    (iocp->ioc_count != sizeof (wheel_state))) {
			err = EINVAL;

			break;
		}
		datap = mp->b_cont;
		err = usbms_service_wheel_state(q, datap, VUIDGWHEELSTATE);

		break;
	case VUIDSWHEELSTATE:
		if (iocp->ioc_count == TRANSPARENT) {
			if (err = usbms_make_copyreq(mp,
			    sizeof (usbms_iocstate_t),
			    USBMS_GETSTRUCT,
			    sizeof (wheel_state),
			    0,
			    M_COPYIN)) {

				break;
			}
			freemsg(mp->b_cont);
			mp->b_cont = (mblk_t *)NULL;
			qreply(q, mp);

			return;
		}
		if (mp->b_cont == NULL) {
			err = EINVAL;

			break;
		}
		datap = mp->b_cont;
		err = usbms_service_wheel_state(q, datap, VUIDSWHEELSTATE);

		break;
	case MSIOSRESOLUTION:
		if (iocp->ioc_count == TRANSPARENT) {
			if (err = usbms_make_copyreq(mp,
			    sizeof (usbms_iocstate_t),
			    USBMS_GETSTRUCT,
			    sizeof (Ms_screen_resolution),
			    0,
			    M_COPYIN)) {

				break;
			}

			freemsg(mp->b_cont);
			mp->b_cont = (mblk_t *)NULL;
			qreply(q, mp);

			return;
		}
		if (mp->b_cont == NULL) {
			err = EINVAL;

			break;
		}
		datap = mp->b_cont;
		err = usbms_get_screen_parms(q, datap);
		/*
		 * Create the absolute mouse type event.
		 * It is used for the hotplug absolute mouse.
		 */
		if ((!((usbmsp->usbms_idf).xattr & HID_MAIN_ITEM_RELATIVE)) &&
		    (usbmsp->usbms_rpt_abs == B_FALSE)) {
			report_abs = B_TRUE;
		}

		break;

	default:
		putnext(q, mp); /* pass it down the line */

		return;
	} /* switch */

	if (err != 0)
		miocnak(q, mp, 0, err);
	else {
		iocp->ioc_rval = 0;
		iocp->ioc_error = 0;
		mp->b_datap->db_type = M_IOCACK;
		qreply(q, mp);

		if (report_abs == B_TRUE) {
			/* send the abs mouse type event to the upper level */
			if ((mb = usbms_setup_abs_mouse_event()) != NULL) {
				usbmsp->usbms_rpt_abs = B_TRUE;
				qreply(q, mb);
			}
		}
	}

	return;

allocfailure:
	/*
	 * We needed to allocate something to handle this "ioctl", but
	 * couldn't; save this "ioctl" and arrange to get called back when
	 * it's more likely that we can get what we need.
	 * If there's already one being saved, throw it out, since it
	 * must have timed out.
	 */
	freemsg(usbmsp->usbms_iocpending);
	usbmsp->usbms_iocpending = mp;
	if (usbmsp->usbms_reioctl_id) {
		qunbufcall(q, (bufcall_id_t)usbmsp->usbms_reioctl_id);
	}
	usbmsp->usbms_reioctl_id = qbufcall(q, ioctlrespsize, BPRI_HI,
	    (void (*)())usbms_reioctl,
	    (void *)usbmsp);
}


/*
 * M_IOCDATA processing for IOCTL's: VUIDGWHEELCOUNT, VUIDGWHEELINFO,
 * VUIDGWHEELSTATE, VUIDSWHEELSTATE & MSIOSRESOLUTION.
 */
static void
usbms_miocdata(queue_t *q, mblk_t *mp)
{
	struct copyresp *copyresp;
	struct iocblk *iocbp;
	mblk_t *datap;
	mblk_t *ioctmp;
	usbms_iocstate_t *usbmsioc;
	int err = 0;

	copyresp = (struct copyresp *)mp->b_rptr;
	iocbp = (struct iocblk *)mp->b_rptr;
	if (copyresp->cp_rval) {
		err = EAGAIN;

		goto err;
	}
	switch (copyresp->cp_cmd) {

	case VUIDGWHEELCOUNT:
		usbms_ack_ioctl(mp);

		break;
	case VUIDGWHEELINFO:
		ioctmp = copyresp->cp_private;
		usbmsioc = (usbms_iocstate_t *)ioctmp->b_rptr;
		if (usbmsioc->ioc_state == USBMS_GETSTRUCT) {
			if (mp->b_cont == NULL) {
				err = EINVAL;

				break;
			}
			datap = (mblk_t *)mp->b_cont;
			if (err = usbms_service_wheel_info(q, datap)) {

				goto err;
			}
			if (err = usbms_make_copyreq(mp, 0, USBMS_GETRESULT,
			    sizeof (wheel_info), 0, M_COPYOUT)) {

				goto err;
			}
		} else if (usbmsioc->ioc_state == USBMS_GETRESULT) {
			freemsg(ioctmp);
			usbms_ack_ioctl(mp);
		}

		break;
	case VUIDGWHEELSTATE:
		ioctmp = (mblk_t *)copyresp->cp_private;
		usbmsioc = (usbms_iocstate_t *)ioctmp->b_rptr;
		if (usbmsioc->ioc_state == USBMS_GETSTRUCT) {
			if (mp->b_cont == NULL) {
				err = EINVAL;

				break;
			}
			if (err = usbms_service_wheel_state(q, mp->b_cont,
			    VUIDGWHEELSTATE)) {
				goto err;
			}
			if (err = usbms_make_copyreq(mp, 0, USBMS_GETRESULT,
			    sizeof (wheel_state), 0, M_COPYOUT)) {

				goto err;
			}
		} else if (usbmsioc->ioc_state == USBMS_GETRESULT) {
			freemsg(ioctmp);
			usbms_ack_ioctl(mp);
		}

		break;
	case VUIDSWHEELSTATE:
		ioctmp = (mblk_t *)copyresp->cp_private;
		usbmsioc = (usbms_iocstate_t *)ioctmp->b_rptr;
		if (mp->b_cont == NULL) {
			err = EINVAL;

			break;
		}
		if (err = usbms_service_wheel_state(q, mp->b_cont,
		    VUIDSWHEELSTATE)) {

			goto err;
		}
		freemsg(ioctmp);
		usbms_ack_ioctl(mp);

		break;
	case MSIOSRESOLUTION:
		ioctmp = (mblk_t *)copyresp->cp_private;
		usbmsioc = (usbms_iocstate_t *)ioctmp->b_rptr;
		if (mp->b_cont == NULL) {
			err = EINVAL;

			break;
		}
		if (err = usbms_get_screen_parms(q, mp->b_cont)) {

			goto err;
		}
		freemsg(ioctmp);
		usbms_ack_ioctl(mp);

		break;
	default:
		err = EINVAL;
		break;
	}

err:
	if (err) {
		mp->b_datap->db_type = M_IOCNAK;
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = (mblk_t *)NULL;
		}
		if (copyresp->cp_private) {
			freemsg((mblk_t *)copyresp->cp_private);
			copyresp->cp_private = (mblk_t *)NULL;
		}
		iocbp->ioc_count = 0;
		iocbp->ioc_error = err;
	}
	qreply(q, mp);
}


/*
 * usbms_reioctl() :
 *	This function is set up as call-back function should an ioctl fail.
 *	It retries the ioctl.
 */
static void
usbms_reioctl(void	* usbms_addr)
{
	usbms_state_t *usbmsp = (usbms_state_t *)usbms_addr;
	queue_t	*q;
	mblk_t	*mp;

	q = usbmsp->usbms_wq_ptr;
	if ((mp = usbmsp->usbms_iocpending) != NULL) {
		usbmsp->usbms_iocpending = NULL; /* not pending any more */
		usbms_ioctl(q, mp);
	}
}

/*
 * usbms_getparms() :
 *	Called from MSIOGETPARMS ioctl to get the
 *	current jitter_thesh, speed_law and speed_limit
 *	values.
 */
static int
usbms_getparms(Ms_parms	*data, usbms_state_t *usbmsp)
{
	data->jitter_thresh = usbmsp->usbms_jitter_thresh;
	data->speed_law = usbmsp->usbms_speedlaw;
	data->speed_limit = usbmsp->usbms_speedlimit;

	return (0);
}


/*
 * usbms_setparms() :
 *	Called from MSIOSETPARMS ioctl to set the
 *	current jitter_thesh, speed_law and speed_limit
 *	values.
 */
static int
usbms_setparms(Ms_parms	*data, usbms_state_t *usbmsp)
{
	usbmsp->usbms_jitter_thresh = data->jitter_thresh;
	usbmsp->usbms_speedlaw = data->speed_law;
	usbmsp->usbms_speedlimit = data->speed_limit;

	return (0);
}

/*
 * usbms_flush() :
 *	Resets the ms_softc structure to default values
 *	and sends M_FLUSH above.
 */
static void
usbms_flush(usbms_state_t *usbmsp)
{
	struct ms_softc *ms = &usbmsp->usbms_softc;
	queue_t		*q;

	USB_DPRINTF_L3(PRINT_MASK_ALL, usbms_log_handle,
	    "usbms_flush entering");

	ms->ms_oldoff = 0;
	ms->ms_eventstate = EVENT_BUT(usbmsp->usbms_num_buttons);
	usbmsp->usbms_buf->mb_off = 0;
	ms->ms_prevbuttons = (char)USB_NO_BUT_PRESSED;
	usbmsp->usbms_oldbutt = ms->ms_prevbuttons;
	if ((q = usbmsp->usbms_rq_ptr) != NULL && q->q_next != NULL) {
		(void) putnextctl1(q, M_FLUSH, FLUSHR);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, usbms_log_handle,
	    "usbms_flush exiting");
}


/*
 * usbms_rput() :
 *	Put procedure for input from driver end of stream (read queue).
 */
static int
usbms_rput(queue_t *q, mblk_t *mp)
{
	usbms_state_t *usbmsp = q->q_ptr;
	mblk_t	*tmp_mp;
	ushort_t limit = (usbmsp->usbms_idf).tlen;

	/* Maintain the original mp */
	tmp_mp = mp;

	if (usbmsp == 0) {
		freemsg(mp);	/* nobody's listening */

		return (0);
	}

	switch (mp->b_datap->db_type) {

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(WR(q), FLUSHDATA);
		if (*mp->b_rptr & FLUSHR)
			flushq(q, FLUSHDATA);
		freemsg(mp);

		return (0);

	case M_BREAK:
		/*
		 * We don't have to handle this
		 * because nothing is sent from the downstream
		 */

		freemsg(mp);

		return (0);

	case M_DATA:
		if (!(usbmsp->usbms_flags & USBMS_OPEN)) {
			freemsg(mp);	/* not ready to listen */

			return (0);
		}
		break;

	case M_CTL:
		usbms_mctl_receive(q, mp);

		return (0);

	case M_ERROR:
		usbmsp->usbms_protoerr = 1;
		usbmsp->usbms_flags &= ~USBMS_QWAIT;
		if (*mp->b_rptr == ENODEV) {
			putnext(q, mp);
		} else {
			freemsg(mp);
		}

		return (0);
	default:
		putnext(q, mp);

		return (0);
	}

	/*
	 * A data message, consisting of bytes from the mouse.
	 * Make sure there are atleast "limit" number of bytes.
	 */
	if ((MBLKL(tmp_mp) < limit) || ((MBLKL(tmp_mp) == limit) &&
	    (usbmsp->usbms_rptid != HID_REPORT_ID_UNDEFINED))) {
		freemsg(mp);
		return (0);
	}
	do {
		if (usbmsp->usbms_rptid != HID_REPORT_ID_UNDEFINED) {
			if (*(tmp_mp->b_rptr) != usbmsp->usbms_rptid) {
				freemsg(mp);

				return (0);
			} else {
				/* We skip the report id prefix. */
				tmp_mp->b_rptr++;
			}
		}

		usbms_input(usbmsp, tmp_mp);
	} while ((tmp_mp = tmp_mp->b_cont) != NULL);   /* next block, if any */

	freemsg(mp);
	return (0);
}


/*
 * usbms_mctl_receive() :
 *	Handle M_CTL messages from hid.  If
 *	we don't understand the command, free message.
 */
static void
usbms_mctl_receive(queue_t *q, mblk_t *mp)
{
	usbms_state_t *usbmsd = (usbms_state_t *)q->q_ptr;
	struct iocblk				*iocp;
	caddr_t					data;


	iocp = (struct iocblk *)mp->b_rptr;
	if (mp->b_cont != NULL)
		data = (caddr_t)mp->b_cont->b_rptr;

	switch (iocp->ioc_cmd) {

	case HID_GET_PARSER_HANDLE:
		if ((data != NULL) &&
		    (iocp->ioc_count == sizeof (hidparser_handle_t)) &&
		    (MBLKL(mp->b_cont) == iocp->ioc_count)) {
			usbmsd->usbms_report_descr_handle =
			    *(hidparser_handle_t *)data;
		} else {
			usbmsd->usbms_report_descr_handle = NULL;
		}
		freemsg(mp);
		usbmsd->usbms_flags &= ~USBMS_QWAIT;
		break;
	case HID_SET_PROTOCOL:
		usbmsd->usbms_flags &= ~USBMS_QWAIT;

		/* FALLTHRU */
	default:
		freemsg(mp);
		break;
	}
}


/*
 * usbms_input() :
 *
 *	Mouse input routine; process a byte received from a mouse and
 *	assemble into a mouseinfo message for the window system.
 *
 *	The USB mouse send a three-byte packet organized as
 *		button, dx, dy
 *	where dx and dy can be any signed byte value. The mouseinfo message
 *	is organized as
 *		dx, dy, button, timestamp
 *	Our strategy is to collect but, dx & dy three-byte packet, then
 *	send the mouseinfo message up.
 *
 *	Basic algorithm: throw away bytes until we get a [potential]
 *	button byte. Collect button; Collect dx; Collect dy; Send button,
 *	dx, dy, timestamp.
 *
 *	Watch out for overflow!
 */
static void
usbms_input(usbms_state_t *usbmsp, mblk_t *mp)
{
	struct usbmousebuf	*b;
	struct usbmouseinfo	*mi;
	int			jitter_radius;
	int32_t		nbutt;
	ushort_t			i;
	char				c;

	nbutt = usbmsp->usbms_num_buttons;
	b = usbmsp->usbms_buf;

	USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR, usbms_log_handle,
	    "usbms_input entering");

	if (b == NULL) {

		return;
	}

	mi = &b->mb_info[b->mb_off];

	/*
	 * Lower 3 bits are middle, right, left.
	 */
	c = mp->b_rptr[(usbmsp->usbms_idf).bpos];
	mi->mi_buttons = (char)USB_NO_BUT_PRESSED;
	if (c & USBMS_BUT(1)) {	 /* left button is pressed */
		mi->mi_buttons = mi->mi_buttons & USB_LEFT_BUT_PRESSED;
		USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR,
		    usbms_log_handle,
		    "left button pressed");
	}
	if (c & USBMS_BUT(2)) {	/* right button is pressed */
		mi->mi_buttons = mi->mi_buttons & USB_RIGHT_BUT_PRESSED;
		USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR,
		    usbms_log_handle,
		    "right button pressed");
	}
	if (c & USBMS_BUT(3)) {   /* middle button is pressed */
		mi->mi_buttons = mi->mi_buttons &
		    USB_MIDDLE_BUT_PRESSED;
		USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR,
		    usbms_log_handle,
		    "middle button pressed");
	}

	if (nbutt > 3) {
		for (i = 4; i < (nbutt + 1); i++) {
			if (c & USBMS_BUT(i)) {
				mi->mi_buttons = mi->mi_buttons &
				    USB_BUT_PRESSED(i);
				USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR,
				    usbms_log_handle,
				    "%d button pressed", i);
			}
		}
	}

	/* get the delta X and Y from the sample */
	mi->mi_x += usbms_get_coordinate((usbmsp->usbms_idf).xpos,
	    (usbmsp->usbms_idf).xlen, mp);

	USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR,
	    usbms_log_handle, "x = %d", (int)mi->mi_x);

	uniqtime32(&mi->mi_time); /* record time when sample arrived */

	mi->mi_y += usbms_get_coordinate((usbmsp->usbms_idf).ypos,
	    (usbmsp->usbms_idf).ylen, mp);

	USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR, usbms_log_handle,
	    "y = %d", (int)mi->mi_y);

	/*
	 * Check the wheel data in the current event.
	 * If it exists, the wheel data is got from the sample.
	 */

	if (usbmsp->usbms_num_wheels) {
		mi->mi_z += usbms_get_coordinate((usbmsp->usbms_idf).zpos,
		    (usbmsp->usbms_idf).zlen, mp);

		USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR, usbms_log_handle,
		    "z = %d", (int)mi->mi_z);
	}

	if (usbmsp->usbms_jitter) {
		(void) quntimeout(usbmsp->usbms_rq_ptr,
		    (timeout_id_t)usbmsp->usbms_timeout_id);
		usbmsp->usbms_jitter = 0;
	}

	if (!usbmsp->usbms_num_wheels) {
		mi->mi_z = 0;
	}

	/*
	 * If there is a wheel movement or a change in the button state,
	 * send the data up immediately.
	 */
	if (!(mi->mi_z) && (mi->mi_buttons == usbmsp->usbms_oldbutt)) {
		/*
		 * Buttons did not change; did position?
		 */
		if (mi->mi_x == 0 && mi->mi_y == 0) {
			/* no, position did not change */

			return;
		}

		/*
		 * Did the mouse move more than the jitter threshhold?
		 */
		jitter_radius = usbmsp->usbms_jitter_thresh;
		if (USB_ABS((int)mi->mi_x) <= jitter_radius &&
		    USB_ABS((int)mi->mi_y) <= jitter_radius) {
			/*
			 * Mouse moved less than the jitter threshhold.
			 * Don't indicate an event; keep accumulating motions.
			 * After "jittertimeout" ticks expire, treat
			 * the accumulated delta as the real delta.
			 */
			usbmsp->usbms_jitter = 1;
			usbmsp->usbms_timeout_id =
			    qtimeout(usbmsp->usbms_rq_ptr,
			    (void (*)())usbms_incr,
			    (void *)usbmsp,
			    (clock_t)usbmsp->usbms_jittertimeout);

			return;
		}
	}
	usbmsp->usbms_oldbutt = mi->mi_buttons;
	usbms_incr(usbmsp);

	USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR, usbms_log_handle,
	    "usbms_input exiting");
}


/*
 * usbms_get_coordinate():
 * get the X, Y, WHEEL coordinate values
 */
static int
usbms_get_coordinate(uint_t pos, uint_t len, mblk_t *mp)
{
	uint_t utmp, bitval, val;
	int i, xyz;

	/* get the unsigned int value from the bit stream */
	utmp = 0;
	for (i = (pos + len - 1); i >= (int)pos; i--) {
		bitval = (mp->b_rptr[i/8] & (1 << (i%8))) >> (i%8);
		utmp = utmp * 2 + bitval;
	}

	/* convert the unsigned int value into int value */
	val = 1 << (len - 1);
	xyz = (int)(utmp - val);
	if (xyz < 0)
		xyz += val;
	else if (xyz == 0)
		xyz = -(val - 1);
	else
		xyz -= val;

	return (xyz);
}


/*
 * usbms_incr() :
 *	Increment the mouse sample pointer.
 *	Called either immediately after a sample or after a jitter timeout.
 */
static void
usbms_incr(void				*arg)
{
	usbms_state_t			*usbmsp = arg;
	struct ms_softc	*ms = &usbmsp->usbms_softc;
	struct usbmousebuf	*b;
	struct usbmouseinfo	*mi;
	int			xc, yc, zc;
	int			wake;
	int			speedl = usbmsp->usbms_speedlimit;
	int			xabs, yabs;

	/*
	 * No longer waiting for jitter timeout
	 */
	usbmsp->usbms_jitter = 0;

	b = usbmsp->usbms_buf;

	USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR, usbms_log_handle,
	    "usbms_incr entering");

	if (b == NULL) {

		return;
	}
	mi = &b->mb_info[b->mb_off];
	if (usbmsp->usbms_speedlaw) {
		xabs = USB_ABS((int)mi->mi_x);
		yabs = USB_ABS((int)mi->mi_y);
		if (xabs > speedl || yabs > speedl) {
			usbmsp->usbms_speed_count++;
		}
		if (xabs > speedl) {
			mi->mi_x = 0;
		}
		if (yabs > speedl) {
			mi->mi_y = 0;
		}
	}


	xc = yc = zc = 0;

	/* See if we need to wake up anyone waiting for input */
	wake = b->mb_off == ms->ms_oldoff;

	/* Adjust circular buffer pointer */
	if (++b->mb_off >= b->mb_size) {
		b->mb_off = 0;
		mi = b->mb_info;
	} else {
		mi++;
	}

	/*
	 * If over-took read index then flush buffer so that mouse state
	 * is consistent.
	 */
	if (b->mb_off == ms->ms_oldoff) {
		if (overrun_msg) {
			USB_DPRINTF_L1(PRINT_MASK_ALL, usbms_log_handle,
			    "Mouse buffer flushed when overrun.");
		}
		usbms_flush(usbmsp);
		overrun_cnt++;
		mi = b->mb_info;
	}

	/* Remember current buttons and fractional part of x & y */
	mi->mi_buttons = (char)USB_NO_BUT_PRESSED;
	mi->mi_x = xc;
	mi->mi_y = yc;
	mi->mi_z = zc;

	if (wake) {
		USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR, usbms_log_handle,
		    "usbms_incr run service");
		qenable(usbmsp->usbms_rq_ptr);	/* run the service proc */
	}
	USB_DPRINTF_L3(PRINT_MASK_INPUT_INCR, usbms_log_handle,
	    "usbms_incr exiting");
}


/*
 * usbms_check_for_wheels
 *	return SUCCESS if wheel is found, else return FAILURE
 */
static int
usbms_check_for_wheels(usbms_state_t *usbmsp)
{
	int rval, report_id;


	if (usbmsp->usbms_report_descr_handle) {
		/* Get the report id that has mouse data */
		if (hidparser_get_usage_attribute(
		    usbmsp->usbms_report_descr_handle,
		    0, /* Doesn't matter */
		    HIDPARSER_ITEM_INPUT,
		    HID_GENERIC_DESKTOP,
		    HID_GD_X,
		    HIDPARSER_ITEM_REPORT_ID,
		    &usbmsp->usbms_rptid) == HIDPARSER_NOT_FOUND) {
			usbmsp->usbms_rptid = HID_REPORT_ID_UNDEFINED;
			report_id = 0;
		} else {
			report_id = usbmsp->usbms_rptid;
		}

		/* find no. of wheels in this report */
		rval = hidparser_get_usage_attribute(
		    usbmsp->usbms_report_descr_handle,
		    report_id,
		    HIDPARSER_ITEM_INPUT,
		    HID_GENERIC_DESKTOP,
		    HID_GD_WHEEL,
		    HIDPARSER_ITEM_REPORT_COUNT,
		    &usbmsp->usbms_num_wheels);
		if (rval == HIDPARSER_SUCCESS) {
			/*
			 * Found wheel. By default enable the wheel.
			 * Currently only enable only the first wheel.
			 */
			usbmsp->usbms_wheel_state_bf |=
			    VUID_WHEEL_STATE_ENABLED;

			return (USB_SUCCESS);
		}
	}
	usbmsp->usbms_num_wheels = 0;

	return (USB_FAILURE);
}


/*
 * usbms_make_copyreq
 *	helper function for usbms ioctls
 */
static int
usbms_make_copyreq(mblk_t *mp, uint_t pvtsize, uint_t state, uint_t reqsize,
    uint_t contsize, uint_t copytype)
{

	struct copyreq		*cq;
	struct copyresp		*cr;
	mblk_t			*ioctmp;
	mblk_t			*conttmp;
	usbms_iocstate_t	*usbmsioc;

	if ((!pvtsize) && state) {
		cr = (struct copyresp *)mp->b_rptr;
		ioctmp = cr->cp_private;
	}
	cq = (struct copyreq *)mp->b_rptr;
	if (mp->b_cont == NULL) {

		return (EINVAL);
	}
	cq->cq_addr = *((caddr_t *)mp->b_cont->b_rptr);
	cq->cq_size = reqsize;
	cq->cq_flag = 0;
	if (pvtsize) {
		ioctmp = (mblk_t *)allocb(pvtsize, BPRI_MED);
		if (ioctmp == NULL) {

			return (EAGAIN);
		}
		cq->cq_private = ioctmp;
		ioctmp = cq->cq_private;
	} else {
		/*
		 * Here we need to set cq_private even if there's
		 * no private data, otherwise its value will be
		 * TRANSPARENT (-1) on 64bit systems because it
		 * overlaps iocp->ioc_count. If user address (cq_addr)
		 * is invalid, it would cause panic later in
		 * usbms_miocdata:
		 *	freemsg((mblk_t *)copyresp->cp_private);
		 */
		cq->cq_private = NULL;
		}
	if (state) {
		usbmsioc = (usbms_iocstate_t *)ioctmp->b_rptr;
		usbmsioc->ioc_state = state;
		if (pvtsize) {  /* M_COPYIN */
			usbmsioc->u_addr = cq->cq_addr;
		} else {
			cq->cq_addr = usbmsioc->u_addr;
			cq->cq_private = ioctmp;
		}
		ioctmp->b_wptr = ioctmp->b_rptr + sizeof (usbms_iocstate_t);
	}
	if (contsize) {
		conttmp = (mblk_t *)allocb(contsize, BPRI_MED);
		if (conttmp == NULL) {

			return (EAGAIN);
		}
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = conttmp;
		}
	}
	mp->b_datap->db_type = (unsigned char)copytype;
	mp->b_wptr = mp->b_rptr + sizeof (struct copyreq);

	return (USB_SUCCESS);
}


static int
usbms_service_wheel_info(queue_t *q, mblk_t	*datap)
{

	wheel_info		*wi;
	usbms_state_t		*usbmsp = (usbms_state_t *)q->q_ptr;
	uint_t			err;

	wi = (wheel_info *)datap->b_rptr;
	if (wi->vers != VUID_WHEEL_INFO_VERS) {
		err = EINVAL;

		return (err);
	}
	if (wi->id > (usbmsp->usbms_num_wheels - 1)) {
		err = EINVAL;

		return (err);
	}
	wi->format = (usbmsp->usbms_wheel_orient_bf & (1 << wi->id)) ?
	    VUID_WHEEL_FORMAT_HORIZONTAL : VUID_WHEEL_FORMAT_VERTICAL;

	return (USB_SUCCESS);
}


static int
usbms_service_wheel_state(queue_t *q, mblk_t *datap, uint_t cmd)
{

	wheel_state	*ws;
	uint_t		err;
	usbms_state_t	*usbmsp = (usbms_state_t *)q->q_ptr;

	ws = (wheel_state *)datap->b_rptr;
	if (ws->vers != VUID_WHEEL_STATE_VERS) {
		err = EINVAL;

		return (err);
	}
	if (ws->id > (usbmsp->usbms_num_wheels - 1)) {
		err = EINVAL;

		return (err);
	}

	switch (cmd) {
	case	VUIDGWHEELSTATE:
		ws->stateflags = (usbmsp->usbms_wheel_state_bf >> ws->id) &
		    VUID_WHEEL_STATE_ENABLED;

		break;
	case	VUIDSWHEELSTATE:
		usbmsp->usbms_wheel_state_bf = (ws->stateflags << ws->id) |
		    (~(1 << ws->id) & usbmsp->usbms_wheel_state_bf);

		break;
	default:
		err = EINVAL;

		return (err);
	}

	return (USB_SUCCESS);
}


/*
 * usbms_get_screen_parms() :
 *	Called from MSIOSRESOLUTION ioctl to get the
 *	current screen height/width params from X.
 */
static int
usbms_get_screen_parms(queue_t *q, mblk_t *datap)
{

	usbms_state_t	*usbmsp = (usbms_state_t *)q->q_ptr;
	Ms_screen_resolution	*res = &(usbmsp->usbms_resolution);
	Ms_screen_resolution	*data;

	data = (Ms_screen_resolution *)datap->b_rptr;
	res->height = data->height;
	res->width = data->width;

	return (USB_SUCCESS);
}


static void
usbms_ack_ioctl(mblk_t *mp)
{

	struct iocblk	*iocbp = (struct iocblk *)mp->b_rptr;

	mp->b_datap->db_type = M_IOCACK;
	mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
	iocbp->ioc_error = 0;
	iocbp->ioc_count = 0;
	iocbp->ioc_rval = 0;
	if (mp->b_cont != NULL) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}
}


/*
 * usbms_setup_abs_mouse_event() :
 *	Called from MSIOSRESOLUTION ioctl to create
 *	the absolute mouse type firm event.
 */
static mblk_t *
usbms_setup_abs_mouse_event(void)
{
	mblk_t	*mb;
	Firm_event *fep;

	if ((mb = allocb(sizeof (Firm_event), BPRI_HI)) != NULL) {
		fep = (Firm_event *)mb->b_wptr;
		fep->id = MOUSE_TYPE_ABSOLUTE;
		fep->pair_type = FE_PAIR_NONE;
		fep->pair = NULL;
		fep->value = NULL;
		mb->b_wptr += sizeof (Firm_event);
	} else {
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbms_log_handle,
		    "No resource to report ABS mouse event");
	}

	return (mb);
}


/*
 * usbms_read_input_data_format() :
 *	Get the mouse packet length and usages' length.
 *	Check whether X and Y are relative or absolute.
 *
 *	If they are absolute, the X and Y logical max values
 *	will be got. A firm event will be created and sent
 *	to the upper level.
 */
int
usbms_read_input_data_format(usbms_state_t *usbmsp)
{

	hidparser_rpt_t *ms_rpt;
	uint_t i, button_page;
	uint_t limit = 0;
	uint32_t	rptcnt, rptsz;
	usbms_idf *idf = &(usbmsp->usbms_idf);
	Ms_screen_resolution *res = &(usbmsp->usbms_resolution);
	mblk_t *mb;
	queue_t	*q;
	int	rval;

	usbmsp->usbms_rpt_abs = B_FALSE;

	/* allocate hidparser report structure */
	ms_rpt = kmem_zalloc(sizeof (hidparser_rpt_t), KM_SLEEP);

	/*
	 * Check what is the total length of the mouse packet
	 * and get the usages and their lengths in order
	 */

	rval = hidparser_get_usage_list_in_order(
	    usbmsp->usbms_report_descr_handle,
	    usbmsp->usbms_rptid,
	    HIDPARSER_ITEM_INPUT,
	    ms_rpt);

	if (rval != HIDPARSER_SUCCESS) {

		kmem_free(ms_rpt, sizeof (hidparser_rpt_t));
		return (USB_FAILURE);
	}

	button_page = 0;
	for (i = 0; i < ms_rpt->no_of_usages; i++) {
		rptcnt = ms_rpt->usage_descr[i].rptcnt;
		rptsz = ms_rpt->usage_descr[i].rptsz;
		if ((ms_rpt->usage_descr[i].usage_page ==
		    HID_BUTTON_PAGE) && (!button_page)) {
			idf->bpos = limit;
			limit += (rptcnt * rptsz);
			button_page = 1;
			continue;
		}

		switch (ms_rpt->usage_descr[i].usage_id) {

		case HID_GD_X:
			idf->xpos = limit;
			idf->xlen = rptsz;
			limit += rptsz;
			break;
		case HID_GD_Y:
			idf->ypos = limit;
			idf->ylen = rptsz;
			limit += rptsz;
			break;
		case HID_GD_Z:
			/*
			 * z-axis not yet supported, just skip it.
			 *
			 * It would be ideal if the HID_GD_Z data would be
			 * reported as horizontal wheel, and HID_GD_WHEEL
			 * as vertical wheel.
			 *
			 * We can not use the default case, because
			 * that skips rptcnt*rptsz, but for an
			 * "Apple Might Mouse" rptsz must be used.
			 */
			limit += rptsz;
			break;
		case HID_GD_WHEEL:
			idf->zpos = limit;
			idf->zlen = rptsz;
			limit += rptsz;
			break;
		default:
			limit += rptcnt * rptsz;
			break;
		}
	}

	kmem_free(ms_rpt, sizeof (hidparser_rpt_t));

	/* get the length of sending data */
	idf->tlen = limit / 8;

	/* Check whether X and Y are relative or absolute */
	rval = hidparser_get_main_item_data_descr(
	    usbmsp->usbms_report_descr_handle,
	    usbmsp->usbms_rptid,
	    HIDPARSER_ITEM_INPUT,
	    HID_GENERIC_DESKTOP,
	    HID_GD_X,
	    &idf->xattr);

	if (rval != HIDPARSER_SUCCESS) {

		return (USB_FAILURE);
	}

	/* For the time being assume that Y also has the same attr */
	idf->yattr = idf->xattr;

	/* get the logical_maximum for X and Y respectively */
	if (!(idf->xattr & HID_MAIN_ITEM_RELATIVE)) {

		/* the data format can't be parsed correctly */
		if (limit % 8) {
			USB_DPRINTF_L3(PRINT_MASK_ALL, usbms_log_handle,
			    "Wrong data packet include %d bits", limit);

			return (USB_FAILURE);
		}
		if (hidparser_get_usage_attribute(
		    usbmsp->usbms_report_descr_handle,
		    usbmsp->usbms_rptid,
		    HIDPARSER_ITEM_INPUT,
		    HID_GENERIC_DESKTOP,
		    HID_GD_X,
		    HIDPARSER_ITEM_LOGICAL_MAXIMUM,
		    &usbmsp->usbms_logical_Xmax) != HIDPARSER_SUCCESS) {

			USB_DPRINTF_L3(PRINT_MASK_ALL, usbms_log_handle,
			    "fail to get X logical max.");

			return (USB_FAILURE);
		}
		if (hidparser_get_usage_attribute(
		    usbmsp->usbms_report_descr_handle,
		    usbmsp->usbms_rptid,
		    HIDPARSER_ITEM_INPUT,
		    HID_GENERIC_DESKTOP,
		    HID_GD_Y,
		    HIDPARSER_ITEM_LOGICAL_MAXIMUM,
		    &usbmsp->usbms_logical_Ymax) != HIDPARSER_SUCCESS) {

			USB_DPRINTF_L3(PRINT_MASK_ALL, usbms_log_handle,
			    "fail to get Y logical max.");

			return (USB_FAILURE);
		}

		if (usbmsp->usbms_logical_Xmax == 0) {
			USB_DPRINTF_L3(PRINT_MASK_ALL,
			    usbms_log_handle,
			    "X logical max value is zero");

			return (USB_FAILURE);
		}

		if (usbmsp->usbms_logical_Ymax == 0) {
			USB_DPRINTF_L3(PRINT_MASK_ALL,
			    usbms_log_handle,
			    "Y logical max value is zero");

			return (USB_FAILURE);
		}

		res->height = USBMS_DEFAULT_RES_HEIGHT;
		res->width = USBMS_DEFAULT_RES_WIDTH;

		/* The wheel is not supported in current remote kvms. */
		usbmsp->usbms_num_wheels = 0;
		q = usbmsp->usbms_rq_ptr;
		if ((mb = usbms_setup_abs_mouse_event()) != NULL) {
			putnext(q, mb);
		} else {

			return (USB_NO_RESOURCES);
		}
	}

	return (USB_SUCCESS);
}
