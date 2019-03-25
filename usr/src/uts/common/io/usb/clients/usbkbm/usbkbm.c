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


/*
 * USB keyboard input streams module - processes USB keypacket
 * received from HID driver below to either ASCII or event
 * format for windowing system.
 */
#include <sys/usb/usba/usbai_version.h>

#define	KEYMAP_SIZE_VARIABLE
#include <sys/usb/usba.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/usb/clients/hid/hid_polled.h>
#include <sys/usb/clients/hidparser/hidparser.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/kbio.h>
#include <sys/vuid_event.h>
#include <sys/kbd.h>
#include <sys/consdev.h>
#include <sys/kbtrans.h>
#include <sys/usb/clients/usbkbm/usbkbm.h>
#include <sys/beep.h>
#include <sys/inttypes.h>

/* debugging information */
uint_t	usbkbm_errmask = (uint_t)PRINT_MASK_ALL;
uint_t	usbkbm_errlevel = USB_LOG_L2;
static usb_log_handle_t usbkbm_log_handle;

typedef void (*process_key_callback_t)(usbkbm_state_t *, int, enum keystate);

/*
 * Internal Function Prototypes
 */
static void usbkbm_streams_setled(struct kbtrans_hardware *, int);
static void usbkbm_polled_setled(struct kbtrans_hardware *, int);
static boolean_t usbkbm_polled_keycheck(struct kbtrans_hardware *,
			int *, enum keystate *);
static void usbkbm_poll_callback(usbkbm_state_t *, int, enum keystate);
static void usbkbm_streams_callback(usbkbm_state_t *, int, enum keystate);
static void usbkbm_unpack_usb_packet(usbkbm_state_t *, process_key_callback_t,
			uchar_t *);
static boolean_t usbkbm_is_modkey(uchar_t);
static void usbkbm_reioctl(void	*);
static int usbkbm_polled_getchar(cons_polledio_arg_t);
static boolean_t usbkbm_polled_ischar(cons_polledio_arg_t);
static void usbkbm_polled_enter(cons_polledio_arg_t);
static void usbkbm_polled_exit(cons_polledio_arg_t);
static void usbkbm_mctl_receive(queue_t *, mblk_t *);
static enum kbtrans_message_response usbkbm_ioctl(queue_t *, mblk_t *);
static int usbkbm_kioccmd(usbkbm_state_t *, mblk_t *, char, size_t *);
static void	usbkbm_usb2pc_xlate(usbkbm_state_t *, int, enum keystate);
static void	usbkbm_wrap_kbtrans(usbkbm_state_t *, int, enum keystate);
static int	usbkbm_get_input_format(usbkbm_state_t *);
static int	usbkbm_get_vid_pid(usbkbm_state_t *);

/* stream qinit functions defined here */
static int	usbkbm_open(queue_t *, dev_t *, int, int, cred_t *);
static int	usbkbm_close(queue_t *, int, cred_t *);
static int	usbkbm_wput(queue_t *, mblk_t *);
static int	usbkbm_rput(queue_t *, mblk_t *);
static ushort_t	usbkbm_get_state(usbkbm_state_t *);
static void	usbkbm_get_scancode(usbkbm_state_t *, int *, enum keystate *);

static struct keyboard *usbkbm_keyindex;

/* External Functions */
extern void space_free(char *);
extern uintptr_t space_fetch(char *);
extern int space_store(char *, uintptr_t);
extern struct keyboard *kbtrans_usbkb_maptab_init(void);
extern void kbtrans_usbkb_maptab_fini(struct keyboard **);
extern keymap_entry_t kbtrans_keycode_usb2pc(int);

/*
 * Structure to setup callbacks
 */
struct kbtrans_callbacks kbd_usb_callbacks = {
	usbkbm_streams_setled,
	usbkbm_polled_setled,
	usbkbm_polled_keycheck,
};

/*
 * Global Variables
 */

/* This variable saves the LED state across hotplugging. */
static uchar_t	usbkbm_led_state = 0;

/* This variable saves the layout state */
static uint16_t usbkbm_layout = 0;

/*
 * Function pointer array for mapping of scancodes.
 */
void (*usbkbm_xlate[2])(usbkbm_state_t *, int, enum keystate) = {
	usbkbm_wrap_kbtrans,
	usbkbm_usb2pc_xlate
};

static struct streamtab usbkbm_info;
static struct fmodsw fsw = {
	"usbkbm",
	&usbkbm_info,
	D_MP | D_MTPERMOD
};


/*
 * Module linkage information for the kernel.
 */
static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"USB keyboard streams 1.44",
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
	int	rval = mod_install(&modlinkage);
	usbkbm_save_state_t *sp;

	if (rval != 0) {

		return (rval);
	}

	usbkbm_keyindex = kbtrans_usbkb_maptab_init();

	usbkbm_log_handle = usb_alloc_log_hdl(NULL, "usbkbm",
	    &usbkbm_errlevel, &usbkbm_errmask, NULL, 0);

	sp = (usbkbm_save_state_t *)space_fetch("SUNW,usbkbm_state");

	if (sp == NULL) {

		return (0);
	}

	/* Restore LED information */
	usbkbm_led_state = sp->usbkbm_save_led;

	/* Restore the Layout */
	usbkbm_layout = sp->usbkbm_layout;

	/* Restore abort information */
	usbkbm_keyindex->k_abort1 =
	    sp->usbkbm_save_keyindex.k_abort1;

	usbkbm_keyindex->k_abort2 =
	    sp->usbkbm_save_keyindex.k_abort2;

	usbkbm_keyindex->k_newabort1 =
	    sp->usbkbm_save_keyindex.k_newabort1;

	usbkbm_keyindex->k_newabort2 =
	    sp->usbkbm_save_keyindex.k_newabort2;

	/* Restore keytables */
	bcopy(sp->usbkbm_save_keyindex.k_normal,
	    usbkbm_keyindex->k_normal, USB_KEYTABLE_SIZE);

	bcopy(sp->usbkbm_save_keyindex.k_shifted,
	    usbkbm_keyindex->k_shifted, USB_KEYTABLE_SIZE);

	bcopy(sp->usbkbm_save_keyindex.k_caps,
	    usbkbm_keyindex->k_caps, USB_KEYTABLE_SIZE);

	bcopy(sp->usbkbm_save_keyindex.k_altgraph,
	    usbkbm_keyindex->k_altgraph, USB_KEYTABLE_SIZE);

	bcopy(sp->usbkbm_save_keyindex.k_numlock,
	    usbkbm_keyindex->k_numlock, USB_KEYTABLE_SIZE);

	bcopy(sp->usbkbm_save_keyindex.k_control,
	    usbkbm_keyindex->k_control, USB_KEYTABLE_SIZE);

	bcopy(sp->usbkbm_save_keyindex.k_up,
	    usbkbm_keyindex->k_up, USB_KEYTABLE_SIZE);

	kmem_free(sp->usbkbm_save_keyindex.k_normal,
	    USB_KEYTABLE_SIZE);
	kmem_free(sp->usbkbm_save_keyindex.k_shifted,
	    USB_KEYTABLE_SIZE);
	kmem_free(sp->usbkbm_save_keyindex.k_caps,
	    USB_KEYTABLE_SIZE);
	kmem_free(sp->usbkbm_save_keyindex.k_altgraph,
	    USB_KEYTABLE_SIZE);
	kmem_free(sp->usbkbm_save_keyindex.k_numlock,
	    USB_KEYTABLE_SIZE);
	kmem_free(sp->usbkbm_save_keyindex.k_control,
	    USB_KEYTABLE_SIZE);
	kmem_free(sp->usbkbm_save_keyindex.k_up,
	    USB_KEYTABLE_SIZE);

	kmem_free(sp, sizeof (usbkbm_save_state_t));
	space_free("SUNW,usbkbm_state");

	return (0);
}

int
_fini(void)
{
	usbkbm_save_state_t *sp;
	int sval;
	int rval;

	sp = kmem_alloc(sizeof (usbkbm_save_state_t), KM_SLEEP);
	sval = space_store("SUNW,usbkbm_state", (uintptr_t)sp);

	/*
	 * If it's not possible to store the state, return
	 * EBUSY.
	 */
	if (sval != 0) {
		kmem_free(sp, sizeof (usbkbm_save_state_t));

		return (EBUSY);
	}

	rval = mod_remove(&modlinkage);

	if (rval != 0) {
		kmem_free(sp, sizeof (usbkbm_save_state_t));
		space_free("SUNW,usbkbm_state");

		return (rval);
	}

	usb_free_log_hdl(usbkbm_log_handle);

	/* Save the LED state */
	sp->usbkbm_save_led = usbkbm_led_state;

	/* Save the layout */
	sp->usbkbm_layout = (uchar_t)usbkbm_layout;

	/*
	 * Save entries of the keyboard structure that
	 * have changed.
	 */
	sp->usbkbm_save_keyindex.k_abort1 = usbkbm_keyindex->k_abort1;
	sp->usbkbm_save_keyindex.k_abort2 = usbkbm_keyindex->k_abort2;

	sp->usbkbm_save_keyindex.k_newabort1 = usbkbm_keyindex->k_newabort1;
	sp->usbkbm_save_keyindex.k_newabort2 = usbkbm_keyindex->k_newabort2;

	/* Allocate space for keytables to be stored */
	sp->usbkbm_save_keyindex.k_normal =
	    kmem_alloc(USB_KEYTABLE_SIZE, KM_SLEEP);
	sp->usbkbm_save_keyindex.k_shifted =
	    kmem_alloc(USB_KEYTABLE_SIZE, KM_SLEEP);
	sp->usbkbm_save_keyindex.k_caps =
	    kmem_alloc(USB_KEYTABLE_SIZE, KM_SLEEP);
	sp->usbkbm_save_keyindex.k_altgraph =
	    kmem_alloc(USB_KEYTABLE_SIZE, KM_SLEEP);
	sp->usbkbm_save_keyindex.k_numlock =
	    kmem_alloc(USB_KEYTABLE_SIZE, KM_SLEEP);
	sp->usbkbm_save_keyindex.k_control =
	    kmem_alloc(USB_KEYTABLE_SIZE, KM_SLEEP);
	sp->usbkbm_save_keyindex.k_up =
	    kmem_alloc(USB_KEYTABLE_SIZE, KM_SLEEP);

	/* Copy over the keytables */
	bcopy(usbkbm_keyindex->k_normal,
	    sp->usbkbm_save_keyindex.k_normal, USB_KEYTABLE_SIZE);

	bcopy(usbkbm_keyindex->k_shifted,
	    sp->usbkbm_save_keyindex.k_shifted, USB_KEYTABLE_SIZE);

	bcopy(usbkbm_keyindex->k_caps,
	    sp->usbkbm_save_keyindex.k_caps, USB_KEYTABLE_SIZE);

	bcopy(usbkbm_keyindex->k_altgraph,
	    sp->usbkbm_save_keyindex.k_altgraph, USB_KEYTABLE_SIZE);

	bcopy(usbkbm_keyindex->k_numlock,
	    sp->usbkbm_save_keyindex.k_numlock, USB_KEYTABLE_SIZE);

	bcopy(usbkbm_keyindex->k_control,
	    sp->usbkbm_save_keyindex.k_control, USB_KEYTABLE_SIZE);

	bcopy(usbkbm_keyindex->k_up,
	    sp->usbkbm_save_keyindex.k_up, USB_KEYTABLE_SIZE);

	kbtrans_usbkb_maptab_fini(&usbkbm_keyindex);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Module qinit functions
 */

static struct module_info usbkbm_minfo = {
	0,		/* module id number */
	"usbkbm",	/* module name */
	0,		/* min packet size accepted */
	INFPSZ,		/* max packet size accepted */
	2048,		/* hi-water mark */
	128		/* lo-water mark */
	};

/* read side for key data and ioctl replies */
static struct qinit usbkbm_rinit = {
	usbkbm_rput,
	NULL,		/* service not used */
	usbkbm_open,
	usbkbm_close,
	NULL,
	&usbkbm_minfo
	};

/* write side for ioctls */
static struct qinit usbkbm_winit = {
	usbkbm_wput,
	NULL,
	usbkbm_open,
	usbkbm_close,
	NULL,
	&usbkbm_minfo
	};

static struct streamtab usbkbm_info = {
	&usbkbm_rinit,
	&usbkbm_winit,
	NULL,		/* for muxes */
	NULL,		/* for muxes */
};

/*
 * usbkbm_open :
 *	Open a keyboard
 */
/* ARGSUSED */
static int
usbkbm_open(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *crp)
{
	usbkbm_state_t	*usbkbmd;
	struct iocblk	mctlmsg;
	mblk_t		*mctl_ptr;
	uintptr_t	abortable = (uintptr_t)B_TRUE;
	int		error, ret;

	if (q->q_ptr) {
		USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
		    "usbkbm_open already opened");

		return (0); /* already opened */
	}

	switch (sflag) {

	case MODOPEN:
		break;

	case CLONEOPEN:
		USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
		    "usbkbm_open: Clone open not supported");

		/* FALLTHRU */
	default:

		return (EINVAL);
	}

	/* allocate usb keyboard state structure */

	usbkbmd = kmem_zalloc(sizeof (usbkbm_state_t), KM_SLEEP);

	USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
	    "usbkbm_state= %p", (void *)usbkbmd);

	/*
	 * Set up private data.
	 */
	usbkbmd->usbkbm_readq = q;
	usbkbmd->usbkbm_writeq = WR(q);

	usbkbmd->usbkbm_vkbd_type = KB_USB;
	/*
	 * Set up queue pointers, so that the "put" procedure will accept
	 * the reply to the "ioctl" message we send down.
	 */
	q->q_ptr = (caddr_t)usbkbmd;
	WR(q)->q_ptr = (caddr_t)usbkbmd;

	error = kbtrans_streams_init(q, sflag,
	    (struct kbtrans_hardware *)usbkbmd, &kbd_usb_callbacks,
	    &usbkbmd->usbkbm_kbtrans, usbkbm_led_state, 0);

	if (error != 0) {
		USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
		    "kbdopen:  kbtrans_streams_init failed\n");
		kmem_free(usbkbmd, sizeof (*usbkbmd));

		return (error);
	}

	/*
	 * Set the polled information in the state structure.
	 * This information is set once, and doesn't change
	 */
	usbkbmd->usbkbm_polled_info.cons_polledio_version =
	    CONSPOLLEDIO_V1;

	usbkbmd->usbkbm_polled_info.cons_polledio_argument =
	    (cons_polledio_arg_t)usbkbmd;

	usbkbmd->usbkbm_polled_info.cons_polledio_putchar = NULL;

	usbkbmd->usbkbm_polled_info.cons_polledio_getchar =
	    usbkbm_polled_getchar;

	usbkbmd->usbkbm_polled_info.cons_polledio_ischar =
	    usbkbm_polled_ischar;

	usbkbmd->usbkbm_polled_info.cons_polledio_enter =
	    usbkbm_polled_enter;

	usbkbmd->usbkbm_polled_info.cons_polledio_exit =
	    usbkbm_polled_exit;

	usbkbmd->usbkbm_polled_info.cons_polledio_setled =
	    (void (*)(cons_polledio_arg_t, int))usbkbm_polled_setled;

	usbkbmd->usbkbm_polled_info.cons_polledio_keycheck =
	    (boolean_t (*)(cons_polledio_arg_t, int *,
	    enum keystate *))usbkbm_polled_keycheck;
	/*
	 * The head and the tail pointing at the same byte means empty or
	 * full. usbkbm_polled_buffer_num_characters is used to
	 * tell the difference.
	 */
	usbkbmd->usbkbm_polled_buffer_head =
	    usbkbmd->usbkbm_polled_scancode_buffer;
	usbkbmd->usbkbm_polled_buffer_tail =
	    usbkbmd->usbkbm_polled_scancode_buffer;
	usbkbmd->usbkbm_polled_buffer_num_characters = 0;

	qprocson(q);

	/* request hid report descriptor from HID */
	mctlmsg.ioc_cmd = HID_GET_PARSER_HANDLE;
	mctlmsg.ioc_count = 0;
	mctl_ptr = usba_mk_mctl(mctlmsg, NULL, 0);
	if (mctl_ptr == NULL) {
		/* failure to allocate M_CTL message */
		(void) kbtrans_streams_fini(usbkbmd->usbkbm_kbtrans);
		qprocsoff(q);
		kmem_free(usbkbmd, sizeof (*usbkbmd));

		return (ENOMEM);
	}

	/* send message to hid */
	putnext(usbkbmd->usbkbm_writeq, mctl_ptr);

	/*
	 * Now that M_CTL has been sent, wait for report descriptor.  Cleanup
	 * if user signals in the mean time (as when this gets opened in an
	 * inappropriate context and the user types a ^C).
	 */
	usbkbmd->usbkbm_flags |= USBKBM_QWAIT;
	while (usbkbmd->usbkbm_flags & USBKBM_QWAIT) {

		if (qwait_sig(q) == 0) {
			usbkbmd->usbkbm_flags = 0;
			(void) kbtrans_streams_fini(usbkbmd->usbkbm_kbtrans);
			qprocsoff(q);
			kmem_free(usbkbmd, sizeof (*usbkbmd));

			return (EINTR);
		}
	}


	/* get the input format from the hid descriptor */
	if (usbkbm_get_input_format(usbkbmd) != USB_SUCCESS) {

		USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
		    "usbkbm: Invalid HID Descriptor Tree."
		    "setting default report format");
	}

	/*
	 * Although Sun Japanese type6 and type7 keyboards have the same
	 * layout number(15), they should be recognized for loading the
	 * different keytables on upper apps (e.g. X). The new layout
	 * number (271) is defined for the Sun Japanese type6 keyboards.
	 * The layout number (15) specified in HID spec is used for other
	 * Japanese keyboards. It is a workaround for the old Sun Japanese
	 * type6 keyboards defect.
	 */
	if (usbkbmd->usbkbm_layout == SUN_JAPANESE_TYPE7) {

		if ((ret = usbkbm_get_vid_pid(usbkbmd)) != 0) {

			return (ret);
		}

		if ((usbkbmd->usbkbm_vid_pid.VendorId ==
		    HID_SUN_JAPANESE_TYPE6_KBD_VID) &&
		    (usbkbmd->usbkbm_vid_pid.ProductId ==
		    HID_SUN_JAPANESE_TYPE6_KBD_PID)) {
			usbkbmd->usbkbm_layout = SUN_JAPANESE_TYPE6;
		}
	}

	kbtrans_streams_set_keyboard(usbkbmd->usbkbm_kbtrans, KB_USB,
	    usbkbm_keyindex);

	usbkbmd->usbkbm_flags = USBKBM_OPEN;

	kbtrans_streams_enable(usbkbmd->usbkbm_kbtrans);

	/*
	 * Enable abort sequence on inital. For an internal open, conskbd
	 * will disable driver abort handling (later through M_IOCTL) and
	 * handle it by itself.
	 * For an external (aka. physical) open, this is necessary since
	 * no STREAMS module linked on top of usbkbm handles abort sequence.
	 */
	mctlmsg.ioc_cmd = CONSSETABORTENABLE;
	mctlmsg.ioc_count = TRANSPARENT;
	mctl_ptr = usba_mk_mctl(mctlmsg, &abortable, sizeof (abortable));
	if (mctl_ptr != NULL) {
		DB_TYPE(mctl_ptr) = M_IOCTL;
		if (kbtrans_streams_message(usbkbmd->usbkbm_kbtrans, mctl_ptr)
		    != KBTRANS_MESSAGE_HANDLED) {
			freemsg(mctl_ptr);
		}
	} else {
		USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
		    "usbkbm: enable abort sequence failed");
	}

	USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
	    "usbkbm_open exiting");
	return (0);
}


/*
 * usbkbm_close :
 *	Close a keyboard.
 */
/* ARGSUSED1 */
static int
usbkbm_close(register queue_t *q, int flag, cred_t *crp)
{
	usbkbm_state_t *usbkbmd = (usbkbm_state_t *)q->q_ptr;

	/* If a beep is in progress, stop that */
	(void) beeper_off();

	(void) kbtrans_streams_fini(usbkbmd->usbkbm_kbtrans);

	qprocsoff(q);
	/*
	 * Since we're about to destroy our private data, turn off
	 * our open flag first, so we don't accept any more input
	 * and try to use that data.
	 */
	usbkbmd->usbkbm_flags = 0;

	kmem_free(usbkbmd, sizeof (usbkbm_state_t));

	USB_DPRINTF_L3(PRINT_MASK_CLOSE, usbkbm_log_handle,
	    "usbkbm_close exiting");

	return (0);
}


/*
 * usbkbm_wput :
 *	usb keyboard module output queue put procedure: handles M_IOCTL
 *	messages.
 */
static int
usbkbm_wput(register queue_t *q, register mblk_t *mp)
{
	usbkbm_state_t			*usbkbmd;
	enum kbtrans_message_response	ret;

	USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
	    "usbkbm_wput entering");

	usbkbmd = (usbkbm_state_t *)q->q_ptr;

	/* First, see if kbtrans will handle the message */
	ret = kbtrans_streams_message(usbkbmd->usbkbm_kbtrans, mp);

	if (ret == KBTRANS_MESSAGE_HANDLED) {

		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_wput exiting:2");

		return (0);
	}

	/* kbtrans didn't handle the message.  Try to handle it here */

	switch (mp->b_datap->db_type) {

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
		}

		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHDATA);
		}

		break;

	case M_IOCTL:
		ret = usbkbm_ioctl(q, mp);

		if (ret == KBTRANS_MESSAGE_HANDLED) {

			USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
			    "usbkbm_wput exiting:1");

			return (0);
		}
	default:
		break;
	}

	/*
	 * The message has not been handled
	 * by kbtrans or this module.  Pass it down the stream
	 */
	putnext(q, mp);

	USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
	    "usbkbm_wput exiting:3");
	return (0);
}

/*
 * usbkbm_ioctl :
 *	Handles the ioctls sent from upper module. Returns
 *	ACK/NACK back.
 */
static enum kbtrans_message_response
usbkbm_ioctl(register queue_t *q, register mblk_t *mp)
{
	usbkbm_state_t		*usbkbmd;
	struct iocblk		mctlmsg;
	struct iocblk		*iocp;
	mblk_t			*datap, *mctl_ptr;
	size_t			ioctlrespsize;
	int			err;
	int			tmp;
	int			cycles;
	int			frequency;
	int			msecs;
	char			command;

	err = 0;

	usbkbmd = (usbkbm_state_t *)q->q_ptr;
	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {
	case CONSSETKBDTYPE:
		err = miocpullup(mp, sizeof (int));
		if (err != 0) {
			break;
		}
		tmp = *(int *)mp->b_cont->b_rptr;
		if (tmp != KB_PC && tmp != KB_USB) {
			err = EINVAL;
			break;
		}
		usbkbmd->usbkbm_vkbd_type = tmp;
		break;
	case KIOCLAYOUT:

		datap = allocb(sizeof (int), BPRI_HI);
		if (datap == NULL) {
			ioctlrespsize = sizeof (int);

			goto allocfailure;
		}

		*(int *)datap->b_wptr = usbkbmd->usbkbm_layout;
		datap->b_wptr += sizeof (int);

		freemsg(mp->b_cont);

		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCSLAYOUT:
		/*
		 * Supply a layout if not specified by the hardware, or
		 * override any that was specified.
		 */
		if (iocp->ioc_count != TRANSPARENT) {
			err = EINVAL;
			break;
		}

		usbkbmd->usbkbm_layout = *(intptr_t *)mp->b_cont->b_rptr;

		/*
		 * Save the layout in usbkbm_layout so as to handle the
		 * the case when the user has re-plugged in the non-self
		 * identifying non US keyboard. In this the layout is saved
		 * in global variable, so the user does not have to run
		 * kdmconfig again after the X server reset
		 */

		usbkbm_layout = usbkbmd->usbkbm_layout;
		break;

	case KIOCCMD:
		/*
		 * Check if we have at least the subcommand field; any
		 * other argument validation has to occur inside
		 * usbkbm_kioccmd().
		 */
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;

		/* Subcommand */
		command = (char)(*(int *)mp->b_cont->b_rptr);

		/*
		 * Check if this ioctl is followed by a previous
		 * KBD_CMD_SETLED command, in which case we take
		 * the command byte as the data for setting the LED
		 */
		if (usbkbmd->usbkbm_setled_second_byte) {
			usbkbm_streams_setled((struct kbtrans_hardware *)
			    usbkbmd, command);
			usbkbmd->usbkbm_setled_second_byte = 0;
			break;
		}

		/*
		 * In  case of allocb failure, this will
		 * return the size of the allocation which
		 * failed so that it can be allocated later
		 * through bufcall.
		 */
		ioctlrespsize = 0;

		err = usbkbm_kioccmd(usbkbmd, mp, command, &ioctlrespsize);

		if (ioctlrespsize != 0) {

			goto allocfailure;
		}

		break;

	case CONSOPENPOLLEDIO:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_ioctl CONSOPENPOLLEDIO");

		err = miocpullup(mp, sizeof (struct cons_polledio *));
		if (err != 0) {
			USB_DPRINTF_L2(PRINT_MASK_ALL, usbkbm_log_handle,
			    "usbkbm_ioctl: malformed request");
			break;
		}

		usbkbmd->usbkbm_pending_link = mp;

		/*
		 * Get the polled input structure from hid
		 */
		mctlmsg.ioc_cmd = HID_OPEN_POLLED_INPUT;
		mctlmsg.ioc_count = 0;
		mctl_ptr = usba_mk_mctl(mctlmsg, NULL, 0);
		if (mctl_ptr == NULL) {
			ioctlrespsize = sizeof (mctlmsg);

			goto allocfailure;
		}

		putnext(usbkbmd->usbkbm_writeq, mctl_ptr);

		/*
		 * Do not ack or nack the message, we will wait for the
		 * result of HID_OPEN_POLLED_INPUT
		 */

		return (KBTRANS_MESSAGE_HANDLED);

	case CONSCLOSEPOLLEDIO:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_ioctl CONSCLOSEPOLLEDIO mp = 0x%p", (void *)mp);

		usbkbmd->usbkbm_pending_link = mp;

		/*
		 * Get the polled input structure from hid
		 */
		mctlmsg.ioc_cmd = HID_CLOSE_POLLED_INPUT;
		mctlmsg.ioc_count = 0;
		mctl_ptr = usba_mk_mctl(mctlmsg, NULL, 0);
		if (mctl_ptr == NULL) {
			ioctlrespsize = sizeof (mctlmsg);

			goto allocfailure;
		}

		putnext(usbkbmd->usbkbm_writeq, mctl_ptr);

		/*
		 * Do not ack or nack the message, we will wait for the
		 * result of HID_CLOSE_POLLED_INPUT
		 */

		return (KBTRANS_MESSAGE_HANDLED);

	case CONSSETABORTENABLE:
		/*
		 * Nothing special to do for USB.
		 */
		break;


	case KIOCMKTONE:
		if (iocp->ioc_count != TRANSPARENT) {
			err = EINVAL;
			break;
		}

		tmp = (int)(*(intptr_t *)mp->b_cont->b_rptr);
		cycles = tmp & 0xffff;
		msecs = (tmp >> 16) & 0xffff;

		if (cycles == 0)
			frequency = UINT16_MAX;
		else if (cycles == UINT16_MAX)
			frequency = 0;
		else {
			frequency = (PIT_HZ + cycles / 2) / cycles;
			if (frequency > UINT16_MAX)
				frequency = UINT16_MAX;
		}

		err = beep_mktone(frequency, msecs);
		break;

	default:

		return (KBTRANS_MESSAGE_NOT_HANDLED);
	}

	/*
	 * Send ACK/NACK to upper module for
	 * the messages that have been handled.
	 */
	if (err != 0) {
		iocp->ioc_rval = 0;
		iocp->ioc_error = err;
		mp->b_datap->db_type = M_IOCNAK;
	} else {
		iocp->ioc_rval = 0;
		iocp->ioc_error = 0;	/* brain rot */
		mp->b_datap->db_type = M_IOCACK;
	}

	/* Send the response back up the stream */
	putnext(usbkbmd->usbkbm_readq, mp);

	return (KBTRANS_MESSAGE_HANDLED);

allocfailure:
	/*
	 * We needed to allocate something to handle this "ioctl", but
	 * couldn't; save this "ioctl" and arrange to get called back when
	 * it's more likely that we can get what we need.
	 * If there's already one being saved, throw it out, since it
	 * must have timed out.
	 */
	freemsg(usbkbmd->usbkbm_streams_iocpending);
	usbkbmd->usbkbm_streams_iocpending = mp;

	if (usbkbmd->usbkbm_streams_bufcallid) {

		qunbufcall(usbkbmd->usbkbm_readq,
		    usbkbmd->usbkbm_streams_bufcallid);
	}
	usbkbmd->usbkbm_streams_bufcallid =
	    qbufcall(usbkbmd->usbkbm_readq, ioctlrespsize, BPRI_HI,
	    usbkbm_reioctl, usbkbmd);

	return (KBTRANS_MESSAGE_HANDLED);
}

/*
 * usbkbm_kioccmd :
 *	Handles KIOCCMD ioctl.
 */
static int
usbkbm_kioccmd(usbkbm_state_t *usbkbmd, register mblk_t *mp,
    char command, size_t *ioctlrepsize)
{
	register mblk_t			*datap;
	register struct iocblk		*iocp;
	int				err = 0;

	iocp = (struct iocblk *)mp->b_rptr;

	switch (command) {

		/* Keyboard layout command */
		case KBD_CMD_GETLAYOUT:
			/* layout learned at attached time. */
			datap = allocb(sizeof (int), BPRI_HI);

			/* Return error  on allocation failure */
			if (datap == NULL) {
				*ioctlrepsize = sizeof (int);

				return (EIO);
			}

			*(int *)datap->b_wptr = usbkbmd->usbkbm_layout;
			datap->b_wptr += sizeof (int);
			freemsg(mp->b_cont);
			mp->b_cont = datap;
			iocp->ioc_count = sizeof (int);
			break;

		case KBD_CMD_SETLED:
			/*
			 * Emulate type 4 keyboard :
			 * Ignore this ioctl; the following
			 * ioctl will specify the data byte for
			 * setting the LEDs; setting usbkbm_setled_second_byte
			 * will help recognizing that ioctl
			 */
			usbkbmd->usbkbm_setled_second_byte = 1;
			break;

		case KBD_CMD_RESET:
			break;

		case KBD_CMD_BELL:
			/*
			 * USB keyboards do not have a beeper
			 * in it, the generic beeper interface
			 * is used. Turn the beeper on.
			 */
			(void) beeper_on(BEEP_TYPE4);
			break;

		case KBD_CMD_NOBELL:
			/*
			 * USB keyboards do not have a beeper
			 * in it, the generic beeper interface
			 * is used. Turn the beeper off.
			 */
			(void) beeper_off();
			break;

		case KBD_CMD_CLICK:
			/* FALLTHRU */
		case KBD_CMD_NOCLICK:
			break;

		default:
			err = EIO;
			break;

	}

	return (err);
}


/*
 * usbkbm_rput :
 *	Put procedure for input from driver end of stream (read queue).
 */
static int
usbkbm_rput(register queue_t *q, register mblk_t *mp)
{
	usbkbm_state_t		*usbkbmd;

	usbkbmd = (usbkbm_state_t *)q->q_ptr;

	USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
	    "usbkbm_rput");

	if (usbkbmd == 0) {
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
		 * Will get M_BREAK only if this is not the system
		 * keyboard, otherwise serial port will eat break
		 * and call kmdb/OBP, without passing anything up.
		 */
		freemsg(mp);

		return (0);
	case M_DATA:
		if (!(usbkbmd->usbkbm_flags & USBKBM_OPEN)) {
			freemsg(mp);	/* not ready to listen */

			return (0);
		}

		break;
	case M_CTL:
		usbkbm_mctl_receive(q, mp);

		return (0);
	case M_ERROR:
		usbkbmd->usbkbm_flags &= ~USBKBM_QWAIT;
		if (*mp->b_rptr == ENODEV) {
			putnext(q, mp);
		} else {
			freemsg(mp);
		}

		return (0);
	case M_IOCACK:
	case M_IOCNAK:
		putnext(q, mp);

		return (0);
	default:
		putnext(q, mp);

		return (0);
	}

	/*
	 * A data message, consisting of bytes from the keyboard.
	 * Ram them through the translator, only if there are
	 * correct no. of bytes.
	 */
	if (MBLKL(mp) == usbkbmd->usbkbm_report_format.tlen) {
		if (usbkbmd->usbkbm_report_format.keyid !=
		    HID_REPORT_ID_UNDEFINED) {
			if (*(mp->b_rptr) !=
			    usbkbmd->usbkbm_report_format.keyid) {
				freemsg(mp);

				return (0);
			} else {
				/* We skip the report id prefix */
				mp->b_rptr++;
			}
		}
		usbkbm_unpack_usb_packet(usbkbmd, usbkbm_streams_callback,
		    mp->b_rptr);
	}

	freemsg(mp);
	return (0);
}

/*
 * usbkbm_mctl_receive :
 *	Handle M_CTL messages from hid. If we don't understand
 *	the command, send it up.
 */
static void
usbkbm_mctl_receive(register queue_t *q, register mblk_t *mp)
{
	register usbkbm_state_t *usbkbmd = (usbkbm_state_t *)q->q_ptr;
	register struct iocblk *iocp;
	caddr_t  data = NULL;
	mblk_t	*reply_mp;
	uchar_t	new_buffer[USBKBM_MAXPKTSIZE];
	size_t	 size;

	iocp = (struct iocblk *)mp->b_rptr;
	if (mp->b_cont != NULL)
		data = (caddr_t)mp->b_cont->b_rptr;

	switch (iocp->ioc_cmd) {

	case HID_SET_REPORT:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_mctl_receive HID_SET mctl");
		freemsg(mp);
		/* Setting of the LED is not waiting for this message */

		break;
	case HID_GET_PARSER_HANDLE:
		if ((data != NULL) &&
		    (iocp->ioc_count == sizeof (hidparser_handle_t)) &&
		    (MBLKL(mp->b_cont) == iocp->ioc_count)) {
			usbkbmd->usbkbm_report_descr =
			    *(hidparser_handle_t *)data;
		} else {
			usbkbmd->usbkbm_report_descr = NULL;
		}
		freemsg(mp);
		usbkbmd->usbkbm_flags &= ~USBKBM_QWAIT;

		break;
	case HID_GET_VID_PID:
		if ((data != NULL) &&
		    (iocp->ioc_count == sizeof (hid_vid_pid_t)) &&
		    (MBLKL(mp->b_cont) == iocp->ioc_count)) {
			bcopy(data, &usbkbmd->usbkbm_vid_pid, iocp->ioc_count);
		}
		freemsg(mp);
		usbkbmd->usbkbm_flags &= ~USBKBM_QWAIT;

		break;
	case HID_OPEN_POLLED_INPUT:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_mctl_receive HID_OPEN_POLLED_INPUT");

		size = sizeof (hid_polled_input_callback_t);
		reply_mp = usbkbmd->usbkbm_pending_link;
		if ((data != NULL) &&
		    (iocp->ioc_count == size) &&
		    (MBLKL(mp->b_cont) == size)) {
			/*
			 *  Copy the information from hid into the
			 * state structure
			 */
			bcopy(data, &usbkbmd->usbkbm_hid_callback, size);
			reply_mp->b_datap->db_type = M_IOCACK;

			/*
			 * We are given an appropriate-sized data block,
			 * and return a pointer to our structure in it.
			 * The structure is saved in the states structure
			 */
			*(cons_polledio_t **)reply_mp->b_cont->b_rptr =
			    &usbkbmd->usbkbm_polled_info;

		} else {
			reply_mp->b_datap->db_type = M_IOCNAK;
		}
		freemsg(mp);

		usbkbmd->usbkbm_pending_link = NULL;

		putnext(q, reply_mp);

		break;
	case HID_CLOSE_POLLED_INPUT:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_mctl_receive HID_CLOSE_POLLED_INPUT");


		bzero(&usbkbmd->usbkbm_hid_callback,
		    sizeof (hid_polled_input_callback_t));

		freemsg(mp);

		reply_mp = usbkbmd->usbkbm_pending_link;

		iocp = (struct iocblk *)reply_mp->b_rptr;

		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_mctl_receive reply reply_mp 0x%p cmd 0x%x",
		    (void *)reply_mp, iocp->ioc_cmd);


		reply_mp->b_datap->db_type = M_IOCACK;

		usbkbmd->usbkbm_pending_link = NULL;

		putnext(q, reply_mp);

		break;
	case HID_DISCONNECT_EVENT :
	case HID_POWER_OFF:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_mctl_receive HID_DISCONNECT_EVENT/HID_POWER_OFF");

		/* Indicate all keys have been released */
		bzero(new_buffer, USBKBM_MAXPKTSIZE);
		usbkbm_unpack_usb_packet(usbkbmd, usbkbm_streams_callback,
		    new_buffer);
		freemsg(mp);

		break;
	case HID_CONNECT_EVENT:
	case HID_FULL_POWER :
		USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
		    "usbkbm_mctl_receive restore LEDs");

		/* send setled command down to restore LED states */
		usbkbm_streams_setled((struct kbtrans_hardware *)usbkbmd,
		    usbkbm_led_state);

		freemsg(mp);

		break;
	default:
		putnext(q, mp);

		break;
	}
}


/*
 * usbkbm_streams_setled :
 *	Update the keyboard LEDs to match the current keyboard state.
 *	Send LED state downstreams to hid driver.
 */
static void
usbkbm_streams_setled(struct kbtrans_hardware *kbtrans_hw, int state)
{
	struct iocblk	mctlmsg;
	mblk_t		*mctl_ptr;
	hid_req_t	*LED_report;
	usbkbm_state_t	*usbkbmd;
	uchar_t		led_id, led_state;

	usbkbm_led_state = (uchar_t)state;

	usbkbmd = (usbkbm_state_t *)kbtrans_hw;

	LED_report = kmem_zalloc(sizeof (hid_req_t), KM_NOSLEEP);
	if (LED_report == NULL) {

		return;
	}

	/*
	 * Send the request to the hid driver to set LED.
	 */
	led_id = usbkbmd->usbkbm_report_format.keyid;
	led_state = 0;

	/*
	 * Set the led state based on the state that is passed in.
	 */
	if (state & LED_NUM_LOCK) {
		led_state |= USB_LED_NUM_LOCK;
	}

	if (state & LED_COMPOSE) {
		led_state |= USB_LED_COMPOSE;
	}

	if (state & LED_SCROLL_LOCK) {
		led_state |= USB_LED_SCROLL_LOCK;
	}

	if (state & LED_CAPS_LOCK) {
		led_state |= USB_LED_CAPS_LOCK;
	}

	if (state & LED_KANA) {
		led_state |= USB_LED_KANA;
	}

	LED_report->hid_req_version_no = HID_VERSION_V_0;
	LED_report->hid_req_wValue = REPORT_TYPE_OUTPUT | led_id;
	LED_report->hid_req_wLength = sizeof (uchar_t);
	LED_report->hid_req_data[0] = led_state;

	mctlmsg.ioc_cmd = HID_SET_REPORT;
	mctlmsg.ioc_count = sizeof (LED_report);
	mctl_ptr = usba_mk_mctl(mctlmsg, LED_report, sizeof (hid_req_t));
	if (mctl_ptr != NULL) {
		putnext(usbkbmd->usbkbm_writeq, mctl_ptr);
	}

	/*
	 * We are not waiting for response of HID_SET_REPORT
	 * mctl for setting the LED.
	 */
	kmem_free(LED_report, sizeof (hid_req_t));
}


/*
 * usbkbm_polled_keycheck :
 *	This routine is called to determine if there is a scancode that
 *	is available for input.  This routine is called at poll time and
 *	returns a key/state pair to the caller.  If there are characters
 *	buffered up, the routine returns right away with the key/state pair.
 *	Otherwise, the routine calls down to check for characters and returns
 *	the first key/state pair if there are any characters pending.
 */
static boolean_t
usbkbm_polled_keycheck(struct kbtrans_hardware *hw,
    int *key, enum keystate *state)
{
	usbkbm_state_t			*usbkbmd;
	uchar_t				*buffer;
	unsigned			size;
	hid_polled_handle_t		hid_polled_handle;

	usbkbmd = (usbkbm_state_t *)hw;

	/*
	 * If there are already characters buffered up, then we are done.
	 */
	if (usbkbmd->usbkbm_polled_buffer_num_characters != 0) {

		usbkbm_get_scancode(usbkbmd, key, state);

		return (B_TRUE);
	}

	hid_polled_handle =
	    usbkbmd->usbkbm_hid_callback.hid_polled_input_handle;

	size = (usbkbmd->usbkbm_hid_callback.hid_polled_read)
	    (hid_polled_handle, &buffer);

	/*
	 * If we don't get a valid input report then indicate that,
	 * and we are done.
	 */
	if (size != usbkbmd->usbkbm_report_format.tlen) {
		return (B_FALSE);
	}

	/*
	 * We have a usb packet, so pass this packet to
	 * usbkbm_unpack_usb_packet so that it can be broken up into
	 * individual key/state values.
	 */
	if (usbkbmd->usbkbm_report_format.keyid != HID_REPORT_ID_UNDEFINED) {
		if (*buffer != usbkbmd->usbkbm_report_format.keyid) {
			return (B_FALSE);
		} else {
			/* We skip the report id prefix */
			buffer++;
		}
	}
	usbkbm_unpack_usb_packet(usbkbmd, usbkbm_poll_callback, buffer);

	/*
	 * If a scancode was returned as a result of this packet,
	 * then translate the scancode.
	 */
	if (usbkbmd->usbkbm_polled_buffer_num_characters != 0) {

		usbkbm_get_scancode(usbkbmd, key, state);

		return (B_TRUE);
	}

	return (B_FALSE);
}

static ushort_t	usbkbm_get_state(usbkbm_state_t *usbkbmd)
{
	ushort_t	ret;

	ASSERT(usbkbmd->usbkbm_vkbd_type == KB_PC ||
	    usbkbmd->usbkbm_vkbd_type == KB_USB);

	if (usbkbmd->usbkbm_vkbd_type == KB_PC)
		ret = INDEXTO_PC;
	else
		ret = INDEXTO_USB;

	return (ret);
}
/*
 * usbkbm_streams_callback :
 *	This is the routine that is going to be called when unpacking
 *	usb packets for normal streams-based input.  We pass a pointer
 *	to this routine to usbkbm_unpack_usb_packet.  This routine will
 *	get called with an unpacked key (scancode) and state (press/release).
 *	We pass it to the generic keyboard module.
 *
 *	'index' and the function pointers:
 *	Map USB scancodes to PC scancodes by lookup table.
 *	This fix is mainly meant for x86 platforms. For SPARC systems
 *	this fix doesn't change the way in which the scancodes are processed.
 */
static void
usbkbm_streams_callback(usbkbm_state_t *usbkbmd, int key, enum keystate state)
{
	ushort_t index = usbkbm_get_state(usbkbmd);
	(*usbkbm_xlate[index])(usbkbmd, key, state);
}

/*
 * Don't do any translations. Send to 'kbtrans' for processing.
 */
static void
usbkbm_wrap_kbtrans(usbkbm_state_t *usbkbmd, int key, enum keystate state)
{
	kbtrans_streams_key(usbkbmd->usbkbm_kbtrans, key, state);
}

/*
 * Translate USB scancodes to PC scancodes before sending it to 'kbtrans'
 */
void
usbkbm_usb2pc_xlate(usbkbm_state_t *usbkbmd, int key, enum keystate state)
{
	key = kbtrans_keycode_usb2pc(key);
	kbtrans_streams_key(usbkbmd->usbkbm_kbtrans, key, state);
}

/*
 * usbkbm_poll_callback :
 *	This is the routine that is going to be called when unpacking
 *	usb packets for polled input.  We pass a pointer to this routine
 *	to usbkbm_unpack_usb_packet.  This routine will get called with
 *	an unpacked key (scancode) and state (press/release).  We will
 *	store the key/state pair into a circular buffer so that it can
 *	be translated into an ascii key later.
 */
static void
usbkbm_poll_callback(usbkbm_state_t *usbkbmd, int key, enum keystate state)
{
	/*
	 * Check to make sure that the buffer isn't already full
	 */
	if (usbkbmd->usbkbm_polled_buffer_num_characters ==
	    USB_POLLED_BUFFER_SIZE) {

		/*
		 * The buffer is full, we will drop this character.
		 */
		return;
	}

	/*
	 * Save the scancode in the buffer
	 */
	usbkbmd->usbkbm_polled_buffer_head->poll_key = key;
	usbkbmd->usbkbm_polled_buffer_head->poll_state = state;

	/*
	 * We have one more character in the buffer
	 */
	usbkbmd->usbkbm_polled_buffer_num_characters++;

	/*
	 * Increment to the next available slot.
	 */
	usbkbmd->usbkbm_polled_buffer_head++;

	/*
	 * Check to see if the tail has wrapped.
	 */
	if (usbkbmd->usbkbm_polled_buffer_head -
	    usbkbmd->usbkbm_polled_scancode_buffer ==
	    USB_POLLED_BUFFER_SIZE) {

		usbkbmd->usbkbm_polled_buffer_head =
		    usbkbmd->usbkbm_polled_scancode_buffer;
	}
}

/*
 * usbkbm_get_scancode :
 *	This routine retreives a key/state pair from the circular buffer.
 *	The pair was put in the buffer by usbkbm_poll_callback when a
 *	USB packet was translated into a key/state by usbkbm_unpack_usb_packet.
 */
static void
usbkbm_get_scancode(usbkbm_state_t *usbkbmd, int *key, enum keystate *state)
{
	/*
	 * Copy the character.
	 */
	*key = usbkbmd->usbkbm_polled_buffer_tail->poll_key;
	*state = usbkbmd->usbkbm_polled_buffer_tail->poll_state;

	/*
	 * Increment to the next character to be copied from
	 * and to.
	 */
	usbkbmd->usbkbm_polled_buffer_tail++;

	/*
	 * Check to see if the tail has wrapped.
	 */
	if (usbkbmd->usbkbm_polled_buffer_tail -
	    usbkbmd->usbkbm_polled_scancode_buffer ==
	    USB_POLLED_BUFFER_SIZE) {

		usbkbmd->usbkbm_polled_buffer_tail =
		    usbkbmd->usbkbm_polled_scancode_buffer;
	}

	/*
	 * We have one less character in the buffer.
	 */
	usbkbmd->usbkbm_polled_buffer_num_characters--;
}

/*
 * usbkbm_polled_setled :
 *	This routine is a place holder.  Someday, we may want to allow led
 *	state to be updated from within polled mode.
 */
/* ARGSUSED */
static void
usbkbm_polled_setled(struct kbtrans_hardware *hw, int led_state)
{
	/* nothing to do for now */
}

/*
 * This is a pass-thru routine to get a character at poll time.
 */
static int
usbkbm_polled_getchar(cons_polledio_arg_t arg)
{
	usbkbm_state_t			*usbkbmd;

	usbkbmd = (usbkbm_state_t *)arg;

	return (kbtrans_getchar(usbkbmd->usbkbm_kbtrans));
}

/*
 * This is a pass-thru routine to test if character is available for reading
 * at poll time.
 */
static boolean_t
usbkbm_polled_ischar(cons_polledio_arg_t arg)
{
	usbkbm_state_t			*usbkbmd;

	usbkbmd = (usbkbm_state_t *)arg;

	return (kbtrans_ischar(usbkbmd->usbkbm_kbtrans));
}

/*
 * usbkbm_polled_input_enter :
 *	This is a pass-thru initialization routine for the lower layer drivers.
 *	This routine is called at poll time to set the state for polled input.
 */
static void
usbkbm_polled_enter(cons_polledio_arg_t arg)
{
	usbkbm_state_t		*usbkbmd = (usbkbm_state_t *)arg;
	hid_polled_handle_t	hid_polled_handle;
	int			kbstart, kbend, uindex;

	kbstart = usbkbmd->usbkbm_report_format.kpos;
	kbend = kbstart + usbkbmd->usbkbm_report_format.klen;

	/*
	 * Before switching to POLLED mode, copy the contents of
	 * usbkbm_pendingusbpacket to usbkbm_lastusbpacket since
	 * usbkbm_pendingusbpacket field has currently processed
	 * key events of the current OS mode usb keyboard packet.
	 */
	for (uindex = kbstart + 2; uindex < kbend; uindex++) {
		usbkbmd->usbkbm_lastusbpacket[uindex] =
		    usbkbmd->usbkbm_pendingusbpacket[uindex];

		usbkbmd->usbkbm_pendingusbpacket[uindex] = 0;
	}

	hid_polled_handle =
	    usbkbmd->usbkbm_hid_callback.hid_polled_input_handle;

	(void) (usbkbmd->usbkbm_hid_callback.hid_polled_input_enter)
	    (hid_polled_handle);
}

/*
 * usbkbm_polled_input_exit :
 *	This is a pass-thru restoration routine for the lower layer drivers.
 *	This routine is called at poll time to reset the state back to streams
 *	input.
 */
static void
usbkbm_polled_exit(cons_polledio_arg_t arg)
{
	usbkbm_state_t		*usbkbmd = (usbkbm_state_t *)arg;
	hid_polled_handle_t	hid_polled_handle;
	int			kbstart, kbend, uindex;

	kbstart = usbkbmd->usbkbm_report_format.kpos;
	kbend = kbstart + usbkbmd->usbkbm_report_format.klen;

	/*
	 * Before returning to OS mode, copy the contents of
	 * usbkbm_lastusbpacket to usbkbm_pendingusbpacket since
	 * usbkbm_lastusbpacket field has processed key events
	 * of the last POLLED mode usb keyboard packet.
	 */
	for (uindex = kbstart + 2; uindex < kbend; uindex ++) {
		usbkbmd->usbkbm_pendingusbpacket[uindex] =
		    usbkbmd->usbkbm_lastusbpacket[uindex];

		usbkbmd->usbkbm_lastusbpacket[uindex] = 0;
	}

	hid_polled_handle =
	    usbkbmd->usbkbm_hid_callback.hid_polled_input_handle;

	(void) (usbkbmd->usbkbm_hid_callback.hid_polled_input_exit)
	    (hid_polled_handle);
}

/*
 * usbkbm_unpack_usb_packet :
 *	USB key packets contain 8 bytes while in boot-protocol mode.
 *	The first byte contains bit packed modifier key information.
 *	Second byte is reserved. The last 6 bytes contain bytes of
 *	currently pressed keys. If a key was not recorded on the
 *	previous packet, but present in the current packet, then set
 *	state to KEY_PRESSED. If a key was recorded in the previous packet,
 *	but not present in the current packet, then state to KEY_RELEASED
 *	Follow a similar algorithm for bit packed modifier keys.
 */
static void
usbkbm_unpack_usb_packet(usbkbm_state_t *usbkbmd, process_key_callback_t func,
    uchar_t *usbpacket)
{
	uchar_t		mkb;
	uchar_t		lastmkb;
	uchar_t		*lastusbpacket = usbkbmd->usbkbm_lastusbpacket;
	int		packet_size, kbstart, kbend;
	int		uindex, lindex, rollover;

	packet_size = usbkbmd->usbkbm_report_format.tlen;
	kbstart = usbkbmd->usbkbm_report_format.kpos;
	kbend = kbstart + usbkbmd->usbkbm_report_format.klen;
	mkb = usbpacket[kbstart];
	lastmkb = lastusbpacket[kbstart];

	for (uindex = 0; uindex < packet_size; uindex++) {

		USB_DPRINTF_L3(PRINT_MASK_PACKET, usbkbm_log_handle,
		    " %x ", usbpacket[uindex]);
	}

	USB_DPRINTF_L3(PRINT_MASK_PACKET, usbkbm_log_handle,
	    " is the usbkeypacket");

	/* check to see if modifier keys are different */
	if (mkb != lastmkb) {

		if ((mkb & USB_LSHIFTBIT) != (lastmkb & USB_LSHIFTBIT)) {
			(*func)(usbkbmd, USB_LSHIFTKEY, (mkb&USB_LSHIFTBIT) ?
			    KEY_PRESSED : KEY_RELEASED);
			USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
			    "unpack: sending USB_LSHIFTKEY");
		}

		if ((mkb & USB_LCTLBIT) != (lastmkb & USB_LCTLBIT)) {
			(*func)(usbkbmd, USB_LCTLCKEY, mkb&USB_LCTLBIT ?
			    KEY_PRESSED : KEY_RELEASED);
		}

		if ((mkb & USB_LALTBIT) != (lastmkb & USB_LALTBIT)) {
			(*func)(usbkbmd, USB_LALTKEY, mkb&USB_LALTBIT ?
			    KEY_PRESSED : KEY_RELEASED);
		}

		if ((mkb & USB_LMETABIT) != (lastmkb & USB_LMETABIT)) {
			(*func)(usbkbmd, USB_LMETAKEY, mkb&USB_LMETABIT ?
			    KEY_PRESSED : KEY_RELEASED);
		}

		if ((mkb & USB_RMETABIT) != (lastmkb & USB_RMETABIT)) {
			(*func)(usbkbmd, USB_RMETAKEY, mkb&USB_RMETABIT ?
			    KEY_PRESSED : KEY_RELEASED);
		}

		if ((mkb & USB_RALTBIT) != (lastmkb & USB_RALTBIT)) {
			(*func)(usbkbmd, USB_RALTKEY, mkb&USB_RALTBIT ?
			    KEY_PRESSED : KEY_RELEASED);
		}

		if ((mkb & USB_RCTLBIT) != (lastmkb & USB_RCTLBIT)) {
			(*func)(usbkbmd, USB_RCTLCKEY, mkb&USB_RCTLBIT ?
			    KEY_PRESSED : KEY_RELEASED);
		}

		if ((mkb & USB_RSHIFTBIT) != (lastmkb & USB_RSHIFTBIT)) {
			(*func)(usbkbmd, USB_RSHIFTKEY, mkb&USB_RSHIFTBIT ?
			    KEY_PRESSED : KEY_RELEASED);
			USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
			    "unpack: sending USB_RSHIFTKEY");
		}
	}

	/* save modifier bits */
	lastusbpacket[kbstart] = usbpacket[kbstart];

	/* Check Keyboard rollover error. */
	if (usbpacket[kbstart + 2] == USB_ERRORROLLOVER) {
		rollover = 1;
		for (uindex = kbstart + 3; uindex < kbend;
		    uindex++) {
			if (usbpacket[uindex] != USB_ERRORROLLOVER) {
				rollover = 0;
				break;
			}
		}
		if (rollover) {
			USB_DPRINTF_L3(PRINT_MASK_ALL, usbkbm_log_handle,
			    "unpack: errorrollover");
			return;
		}
	}

	/* check for released keys */
	for (lindex = kbstart + 2; lindex < kbend; lindex++) {
		int released = 1;

		if (lastusbpacket[lindex] == 0) {
			continue;
		}
		for (uindex = kbstart + 2; uindex < kbend; uindex++)
			if (usbpacket[uindex] == lastusbpacket[lindex]) {
				released = 0;
				break;
			}
		if (released) {
			(*func)(usbkbmd, lastusbpacket[lindex], KEY_RELEASED);
		}
	}

	/* check for new presses */
	for (uindex = kbstart + 2; uindex < kbend; uindex++) {
		int newkey = 1;

		usbkbmd->usbkbm_pendingusbpacket[uindex] = usbpacket[uindex];

		if (usbpacket[uindex] == 0) {
			continue;
		}

		for (lindex = kbstart + 2; lindex < kbend; lindex++) {
			if (usbpacket[uindex] == lastusbpacket[lindex]) {
				newkey = 0;
				break;
			}
		}

		if (newkey) {
			/*
			 * Modifier keys can be present as part of both the
			 * first byte and as separate key bytes. In the sec-
			 * ond case ignore it.
			 */

			if (!usbkbm_is_modkey(usbpacket[uindex])) {
				(*func)(usbkbmd, usbpacket[uindex],
				    KEY_PRESSED);
			} else {
				usbkbmd->usbkbm_pendingusbpacket[uindex] = 0;

				continue;
			}
		}
	}

	/*
	 * Copy the processed key events of the current usb keyboard
	 * packet, which is saved in the usbkbm_pendingusbpacket field
	 * to the usbkbm_lastusbpacket field.
	 */
	for (uindex = kbstart + 2; uindex < kbend; uindex++) {
		lastusbpacket[uindex] =
		    usbkbmd->usbkbm_pendingusbpacket[uindex];
		usbkbmd->usbkbm_pendingusbpacket[uindex] = 0;
	}
}

static boolean_t
usbkbm_is_modkey(uchar_t key)
{

	switch (key) {

	case USB_LSHIFTKEY:
	case USB_LCTLCKEY:
	case USB_LALTKEY:
	case USB_LMETAKEY:
	case USB_RCTLCKEY:
	case USB_RSHIFTKEY:
	case USB_RMETAKEY:
	case USB_RALTKEY:

		return (B_TRUE);

	default:

		break;
	}

	return (B_FALSE);
}

/*
 * usbkbm_reioctl :
 *	This function is set up as call-back function should an ioctl fail.
 *	It retries the ioctl
 */
static void
usbkbm_reioctl(void	*arg)
{
	usbkbm_state_t	*usbkbmd;
	mblk_t *mp;

	usbkbmd = (usbkbm_state_t *)arg;

	usbkbmd->usbkbm_streams_bufcallid = 0;

	if ((mp = usbkbmd->usbkbm_streams_iocpending) != NULL) {

		/* not pending any more */
		usbkbmd->usbkbm_streams_iocpending = NULL;

		(void) usbkbm_ioctl(usbkbmd->usbkbm_writeq, mp);
	}
}

/*
 * usbkbm_get_vid_pid
 *	Issue a M_CTL to hid to get the device info
 */
static int
usbkbm_get_vid_pid(usbkbm_state_t *usbkbmd)
{
	struct iocblk mctlmsg;
	mblk_t *mctl_ptr;
	queue_t *q = usbkbmd->usbkbm_readq;

	mctlmsg.ioc_cmd = HID_GET_VID_PID;
	mctlmsg.ioc_count = 0;

	mctl_ptr = usba_mk_mctl(mctlmsg, NULL, 0);
	if (mctl_ptr == NULL) {
		(void) kbtrans_streams_fini(usbkbmd->usbkbm_kbtrans);
		qprocsoff(q);
		kmem_free(usbkbmd, sizeof (usbkbm_state_t));

		return (ENOMEM);
	}

	putnext(usbkbmd->usbkbm_writeq, mctl_ptr);
	usbkbmd->usbkbm_flags |= USBKBM_QWAIT;
	while (usbkbmd->usbkbm_flags & USBKBM_QWAIT) {
		if (qwait_sig(q) == 0) {
			usbkbmd->usbkbm_flags = 0;
			(void) kbtrans_streams_fini(usbkbmd->usbkbm_kbtrans);
			qprocsoff(q);
			kmem_free(usbkbmd, sizeof (usbkbm_state_t));

			return (EINTR);
		}
	}

	return (0);
}

/*
 * usbkbm_get_input_format() :
 *     Get the input report format of keyboard
 */
static int
usbkbm_get_input_format(usbkbm_state_t *usbkbmd)
{

	hidparser_rpt_t *kb_rpt;
	uint_t i, kbd_page = 0, kpos = 0, klen = 0, limit = 0;
	uint32_t rptcnt, rptsz;
	usbkbm_report_format_t *kbd_fmt = &usbkbmd->usbkbm_report_format;
	int rptid, rval;

	/* Setup default input report format */
	kbd_fmt->keyid = HID_REPORT_ID_UNDEFINED;
	kbd_fmt->tlen = USB_KBD_BOOT_PROTOCOL_PACKET_SIZE;
	kbd_fmt->klen = kbd_fmt->tlen;
	kbd_fmt->kpos = 0;

	if (usbkbmd->usbkbm_report_descr == NULL) {
		return (USB_FAILURE);
	}

	/* Get keyboard layout */
	if (hidparser_get_country_code(usbkbmd->usbkbm_report_descr,
	    (uint16_t *)&usbkbmd->usbkbm_layout) == HIDPARSER_FAILURE) {

		USB_DPRINTF_L3(PRINT_MASK_OPEN,
		    usbkbm_log_handle, "get_country_code failed"
		    "setting default layout(0)");

		usbkbmd->usbkbm_layout = usbkbm_layout;
	}

	/* Get the id of the report which contains keyboard data */
	if (hidparser_get_usage_attribute(
	    usbkbmd->usbkbm_report_descr,
	    0, /* Doesn't matter */
	    HIDPARSER_ITEM_INPUT,
	    HID_KEYBOARD_KEYPAD_KEYS,
	    0,
	    HIDPARSER_ITEM_REPORT_ID,
	    &rptid) == HIDPARSER_NOT_FOUND) {

		return (USB_SUCCESS);
	}

	/* Allocate hidparser report structure */
	kb_rpt = kmem_zalloc(sizeof (hidparser_rpt_t), KM_SLEEP);

	/*
	 * Check what is the total length of the keyboard packet
	 * and get the usages and their lengths in order
	 */
	rval = hidparser_get_usage_list_in_order(
	    usbkbmd->usbkbm_report_descr,
	    rptid,
	    HIDPARSER_ITEM_INPUT,
	    kb_rpt);
	if (rval != HIDPARSER_SUCCESS) {

		USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
		    "get_usage_list_in_order failed");
		kmem_free(kb_rpt, sizeof (hidparser_rpt_t));
		return (USB_FAILURE);
	}

	for (i = 0; i < kb_rpt->no_of_usages; i++) {
		rptcnt = kb_rpt->usage_descr[i].rptcnt;
		rptsz = kb_rpt->usage_descr[i].rptsz;

		switch (kb_rpt->usage_descr[i].usage_page) {
		case HID_KEYBOARD_KEYPAD_KEYS:
			if (!kbd_page) {
				kpos = limit;
				kbd_page = 1;
			}
			klen += rptcnt * rptsz;
			/*FALLTHRU*/
		default:
			limit += rptcnt * rptsz;
			break;
		}
	}

	kmem_free(kb_rpt, sizeof (hidparser_rpt_t));

	/* Invalid input report format */
	if (!kbd_page || limit > USBKBM_MAXPKTSIZE * 8 ||
	    kpos + klen > limit || (kpos % 8 != 0)) {

		USB_DPRINTF_L3(PRINT_MASK_OPEN, usbkbm_log_handle,
		    "Invalid input report format: kbd_page (%d), limit (%d), "
		    "kpos (%d), klen (%d)", kbd_page, limit, kpos, klen);
		return (USB_FAILURE);
	}

	/* Set report format */
	kbd_fmt->keyid = (uint8_t)rptid;
	kbd_fmt->tlen = limit / 8 + 1;
	kbd_fmt->klen = klen / 8;
	kbd_fmt->kpos = kpos / 8;

	return (USB_SUCCESS);
}
