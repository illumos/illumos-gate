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
 * Generic keyboard support:  streams and administration.
 */

#define	KEYMAP_SIZE_VARIABLE

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/vuid_event.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/kbd.h>
#include <sys/kbio.h>
#include <sys/consdev.h>
#include <sys/kbtrans.h>
#include <sys/policy.h>
#include <sys/sunldi.h>
#include <sys/class.h>
#include <sys/spl.h>
#include "kbtrans_lower.h"
#include "kbtrans_streams.h"

#ifdef DEBUG
int	kbtrans_errmask;
int	kbtrans_errlevel;
#endif

#define	KB_NR_FUNCKEYS		12

/*
 * Repeat rates set in static variables so they can be tweeked with
 * debugger.
 */
static int kbtrans_repeat_count = -1;
static int kbtrans_repeat_rate;
static int kbtrans_repeat_delay;

/* Printing message on q overflow */
static int kbtrans_overflow_msg = 1;

/*
 * This value corresponds approximately to max 10 fingers
 */
static int	kbtrans_downs_size = 15;

/*
 * modload support
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"kbtrans (key translation)"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void	*)&modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Internal Function Prototypes
 */
static char *kbtrans_strsetwithdecimal(char *, uint_t, uint_t);
static void kbtrans_set_translation_callback(struct kbtrans *);
static void kbtrans_reioctl(void *);
static void kbtrans_send_esc_event(char, struct kbtrans *);
static void kbtrans_keypressed(struct kbtrans *, uchar_t, Firm_event *,
    ushort_t);
static void kbtrans_putbuf(char *, queue_t *);
static void kbtrans_cancelrpt(struct kbtrans *);
static void kbtrans_queuepress(struct kbtrans *, uchar_t, Firm_event *);
static void kbtrans_putcode(register struct kbtrans *, uint_t);
static void kbtrans_keyreleased(struct kbtrans *, uchar_t);
static void kbtrans_queueevent(struct kbtrans *, Firm_event *);
static void kbtrans_untrans_keypressed_raw(struct kbtrans *, kbtrans_key_t);
static void kbtrans_untrans_keyreleased_raw(struct kbtrans *, kbtrans_key_t);
static void kbtrans_ascii_keypressed(struct kbtrans *, uint_t,
    kbtrans_key_t, uint_t);
static void kbtrans_ascii_keyreleased(struct kbtrans *, kbtrans_key_t);
static void kbtrans_ascii_setup_repeat(struct kbtrans *, uint_t, kbtrans_key_t);
static void kbtrans_trans_event_keypressed(struct kbtrans *, uint_t,
    kbtrans_key_t, uint_t);
static void kbtrans_trans_event_keyreleased(struct kbtrans *, kbtrans_key_t);
static void kbtrans_trans_event_setup_repeat(struct kbtrans *, uint_t,
    kbtrans_key_t);
static void kbtrans_rpt(void *);
static void kbtrans_setled(struct kbtrans *);
static void kbtrans_flush(struct kbtrans *);
static enum kbtrans_message_response kbtrans_ioctl(struct kbtrans *, mblk_t *);
static int kbtrans_setkey(struct kbtrans_lower *, struct kiockey *, cred_t *);
static int kbtrans_getkey(struct kbtrans_lower *, struct kiockey *);
static int kbtrans_skey(struct kbtrans_lower *, struct kiockeymap *, cred_t *);
static int kbtrans_gkey(struct kbtrans_lower *, struct kiockeymap *);

/*
 * Keyboard Translation Mode (TR_NONE)
 *
 * Functions to be called when keyboard translation is turned off
 * and up/down key codes are reported.
 */
struct keyboard_callback	untrans_event_callback  = {
	kbtrans_untrans_keypressed_raw,
	kbtrans_untrans_keyreleased_raw,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

/*
 * Keyboard Translation Mode (TR_ASCII)
 *
 * Functions to be called when ISO 8859/1 codes are reported
 */
struct keyboard_callback	ascii_callback  = {
	NULL,
	NULL,
	kbtrans_ascii_keypressed,
	kbtrans_ascii_keyreleased,
	kbtrans_ascii_setup_repeat,
	kbtrans_cancelrpt,
	kbtrans_setled,
};

/*
 * Keyboard Translation Mode (TR_EVENT)
 *
 * Functions to be called when firm_events are reported.
 */
struct keyboard_callback	trans_event_callback  = {
	NULL,
	NULL,
	kbtrans_trans_event_keypressed,
	kbtrans_trans_event_keyreleased,
	kbtrans_trans_event_setup_repeat,
	kbtrans_cancelrpt,
	kbtrans_setled,
};

static void
progressbar_key_abort_thread(struct kbtrans *upper)
{
	ldi_ident_t li;
	extern void progressbar_key_abort(ldi_ident_t);

	if (ldi_ident_from_stream(upper->kbtrans_streams_readq, &li) != 0) {
		cmn_err(CE_NOTE, "!ldi_ident_from_stream failed");
	} else {
		mutex_enter(&upper->progressbar_key_abort_lock);
		while (upper->progressbar_key_abort_flag == 0)
			cv_wait(&upper->progressbar_key_abort_cv,
			    &upper->progressbar_key_abort_lock);
		if (upper->progressbar_key_abort_flag == 1) {
			mutex_exit(&upper->progressbar_key_abort_lock);
			progressbar_key_abort(li);
		} else {
			mutex_exit(&upper->progressbar_key_abort_lock);
		}
		ldi_ident_release(li);
	}

	thread_exit();
}

/*
 * kbtrans_streams_init:
 *	Initialize the stream, keytables, callbacks, etc.
 */
int
kbtrans_streams_init(queue_t *q, int sflag, struct kbtrans_hardware *hw,
    struct kbtrans_callbacks *hw_cb, struct kbtrans **ret_kbd,
    int initial_leds, int initial_led_mask)
{
	struct kbtrans *upper;
	struct kbtrans_lower *lower;
	kthread_t *tid;

	/*
	 * Default to relatively generic tables.
	 */
	extern signed char			kb_compose_map[];
	extern struct compose_sequence_t	kb_compose_table[];
	extern struct fltaccent_sequence_t	kb_fltaccent_table[];
	extern char				keystringtab[][KTAB_STRLEN];
	extern unsigned char			kb_numlock_table[];

	/* Set these up only once so that they could be changed from adb */
	if (!kbtrans_repeat_rate) {
		kbtrans_repeat_rate = (hz + 29) / 30;
		kbtrans_repeat_delay = hz / 2;
	}

	switch (sflag) {

	case MODOPEN:
		break;

	case CLONEOPEN:
		DPRINTF(PRINT_L1, PRINT_MASK_OPEN, (NULL,
		    "kbtrans_streams_init: Clone open not supported"));

		return (EINVAL);
	}

	/* allocate keyboard state structure */
	upper = kmem_zalloc(sizeof (struct kbtrans), KM_SLEEP);

	*ret_kbd = upper;

	upper->kbtrans_polled_buf[0] = '\0';
	upper->kbtrans_polled_pending_chars = upper->kbtrans_polled_buf;

	upper->kbtrans_streams_hw = hw;
	upper->kbtrans_streams_hw_callbacks = hw_cb;
	upper->kbtrans_streams_readq = q;
	upper->kbtrans_streams_iocpending = NULL;
	upper->kbtrans_streams_translatable = TR_CAN;
	upper->kbtrans_overflow_cnt = 0;
	upper->kbtrans_streams_translate_mode = TR_ASCII;

	/* Set the translation callback based on the translation type */
	kbtrans_set_translation_callback(upper);

	lower = &upper->kbtrans_lower;

	/*
	 * Set defaults for relatively generic tables.
	 */
	lower->kbtrans_compose_map = kb_compose_map;
	lower->kbtrans_compose_table = kb_compose_table;
	lower->kbtrans_fltaccent_table = kb_fltaccent_table;
	lower->kbtrans_numlock_table = kb_numlock_table;
	lower->kbtrans_keystringtab = keystringtab;

	lower->kbtrans_upper = upper;
	lower->kbtrans_compat = 1;

	/*
	 * We have a generic default for the LED state, and let the
	 * hardware-specific driver supply overrides.
	 */
	lower->kbtrans_led_state = 0;
	lower->kbtrans_led_state &= ~initial_led_mask;
	lower->kbtrans_led_state |= initial_leds;
	lower->kbtrans_togglemask = 0;

	if (lower->kbtrans_led_state & LED_CAPS_LOCK)
		lower->kbtrans_togglemask |= CAPSMASK;
	if (lower->kbtrans_led_state & LED_NUM_LOCK)
		lower->kbtrans_togglemask |= NUMLOCKMASK;

#if	defined(SCROLLMASK)
	if (lower->kbtrans_led_state & LED_SCROLL_LOCK)
		lower->kbtrans_togglemask |= SCROLLMASK;
#endif

	lower->kbtrans_shiftmask = lower->kbtrans_togglemask;

	upper->kbtrans_streams_vuid_addr.ascii = ASCII_FIRST;
	upper->kbtrans_streams_vuid_addr.top = TOP_FIRST;
	upper->kbtrans_streams_vuid_addr.vkey = VKEY_FIRST;

	/* Allocate dynamic memory for downs table */
	upper->kbtrans_streams_num_downs_entries = kbtrans_downs_size;
	upper->kbtrans_streams_downs_bytes =
	    (uint32_t)(kbtrans_downs_size * sizeof (Key_event));
	upper->kbtrans_streams_downs =
	    kmem_zalloc(upper->kbtrans_streams_downs_bytes, KM_SLEEP);
	upper->kbtrans_streams_abortable = B_FALSE;

	upper->kbtrans_streams_flags = KBTRANS_STREAMS_OPEN;

	upper->progressbar_key_abort_flag = 0;
	cv_init(&upper->progressbar_key_abort_cv, NULL, CV_DEFAULT, NULL);
	/* this counts on no keyboards being above ipl 12 */
	mutex_init(&upper->progressbar_key_abort_lock, NULL, MUTEX_SPIN,
	    (void *)ipltospl(12));
	tid = thread_create(NULL, 0, progressbar_key_abort_thread, upper,
	    0, &p0, TS_RUN, minclsyspri);
	upper->progressbar_key_abort_t_did = tid->t_did;

	DPRINTF(PRINT_L1, PRINT_MASK_OPEN, (upper, "kbtrans_streams_init "
	    "exiting"));
	return (0);
}


/*
 * kbtrans_streams_fini:
 *	Free structures and uninitialize the stream
 */
int
kbtrans_streams_fini(struct kbtrans *upper)
{
	/*
	 * Since we're about to destroy our private data, turn off
	 * our open flag first, so we don't accept any more input
	 * and try to use that data.
	 */
	upper->kbtrans_streams_flags = 0;

	/* clear all timeouts */
	if (upper->kbtrans_streams_bufcallid) {
		qunbufcall(upper->kbtrans_streams_readq,
		    upper->kbtrans_streams_bufcallid);
	}
	if (upper->kbtrans_streams_rptid) {
		(void) quntimeout(upper->kbtrans_streams_readq,
		    upper->kbtrans_streams_rptid);
	}
	kmem_free(upper->kbtrans_streams_downs,
	    upper->kbtrans_streams_downs_bytes);

	mutex_enter(&upper->progressbar_key_abort_lock);
	if (upper->progressbar_key_abort_flag == 0) {
		upper->progressbar_key_abort_flag = 2;
		cv_signal(&upper->progressbar_key_abort_cv);
		mutex_exit(&upper->progressbar_key_abort_lock);
		thread_join(upper->progressbar_key_abort_t_did);
	} else {
		mutex_exit(&upper->progressbar_key_abort_lock);
	}
	cv_destroy(&upper->progressbar_key_abort_cv);
	mutex_destroy(&upper->progressbar_key_abort_lock);

	kmem_free(upper, sizeof (struct kbtrans));

	DPRINTF(PRINT_L1, PRINT_MASK_CLOSE, (upper, "kbtrans_streams_fini "
	    "exiting"));
	return (0);
}

/*
 * kbtrans_streams_releaseall :
 *	This function releases all the held keys.
 */
void
kbtrans_streams_releaseall(struct kbtrans *upper)
{
	register struct key_event *ke;
	register int i;

	DPRINTF(PRINT_L0, PRINT_MASK_ALL, (NULL, "USBKBM RELEASE ALL\n"));

	/* Scan table of down key stations */
	for (i = 0, ke = upper->kbtrans_streams_downs;
	    i < upper->kbtrans_streams_num_downs_entries; i++, ke++) {

		/* Key station not zero */
		if (ke->key_station) {

			kbtrans_keyreleased(upper, ke->key_station);
			/* kbtrans_keyreleased resets downs entry */
		}
	}
}

/*
 * kbtrans_streams_message:
 *	keyboard module output queue put procedure: handles M_IOCTL
 *	messages.
 *
 *	Return KBTRANS_MESSAGE_HANDLED if the message was handled by
 *	kbtrans and KBTRANS_MESSAGE_NOT_HANDLED otherwise. If
 *	KBTRANS_MESSAGE_HANDLED is returned, no further action is required.
 *	If KBTRANS_MESSAGE_NOT_HANDLED is returned, the hardware module
 *	is responsible for any action.
 */
enum kbtrans_message_response
kbtrans_streams_message(struct kbtrans *upper, register mblk_t *mp)
{
	queue_t *q = upper->kbtrans_streams_readq;
	enum kbtrans_message_response ret;

	DPRINTF(PRINT_L1, PRINT_MASK_ALL, (upper,
	    "kbtrans_streams_message entering"));
	/*
	 * Process M_FLUSH, and some M_IOCTL, messages here; pass
	 * everything else down.
	 */
	switch (mp->b_datap->db_type) {

	case M_IOCTL:
		ret = kbtrans_ioctl(upper, mp);
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(q, FLUSHDATA);
		if (*mp->b_rptr & FLUSHR)
			flushq(RD(q), FLUSHDATA);
		/*
		 * White lie:  we say we didn't handle the message,
		 * so that it gets handled by our client.
		 */
		ret = KBTRANS_MESSAGE_NOT_HANDLED;
		break;

	default:
		ret = KBTRANS_MESSAGE_NOT_HANDLED;
		break;

	}
	DPRINTF(PRINT_L1, PRINT_MASK_ALL, (upper,
	    "kbtrans_streams_message exiting\n"));

	return (ret);
}

/*
 * kbtrans_streams_key:
 *	When a key is pressed or released, the hardware module should
 *	call kbtrans, passing the key number and its new
 *	state.  kbtrans is responsible for autorepeat handling;
 *	the hardware module should report only actual press/release
 *	events, suppressing any hardware-generated autorepeat.
 */
void
kbtrans_streams_key(struct kbtrans *upper, kbtrans_key_t key,
    enum keystate state)
{
	struct kbtrans_lower *lower;
	struct keyboard *kp;

	lower = &upper->kbtrans_lower;
	kp = lower->kbtrans_keyboard;

	/* trigger switch back to text mode */
	mutex_enter(&upper->progressbar_key_abort_lock);
	if (upper->progressbar_key_abort_flag == 0) {
		upper->progressbar_key_abort_flag = 1;
		cv_signal(&upper->progressbar_key_abort_cv);
	}
	mutex_exit(&upper->progressbar_key_abort_lock);

	if (upper->kbtrans_streams_abortable) {
		switch (upper->kbtrans_streams_abort_state) {
		case ABORT_NORMAL:
			if (state != KEY_PRESSED)
				break;

			if (key == (kbtrans_key_t)kp->k_abort1 ||
			    key == (kbtrans_key_t)kp->k_abort1a) {
				upper->kbtrans_streams_abort_state =
				    ABORT_ABORT1_RECEIVED;
				upper->kbtrans_streams_abort1_key = key;
				return;
			}
			/* Shift key needs to be sent to upper immediately */
			if (key == (kbtrans_key_t)kp->k_newabort1 ||
			    key == (kbtrans_key_t)kp->k_newabort1a) {
				upper->kbtrans_streams_abort_state =
				    NEW_ABORT_ABORT1_RECEIVED;
				upper->kbtrans_streams_new_abort1_key = key;
			}
			break;
		case ABORT_ABORT1_RECEIVED:
			upper->kbtrans_streams_abort_state = ABORT_NORMAL;
			if (state == KEY_PRESSED &&
			    key == (kbtrans_key_t)kp->k_abort2) {
				abort_sequence_enter((char *)NULL);
				return;
			} else {
				kbtrans_processkey(lower,
				    upper->kbtrans_streams_callback,
				    upper->kbtrans_streams_abort1_key,
				    KEY_PRESSED);
			}
			break;
		case NEW_ABORT_ABORT1_RECEIVED:
			upper->kbtrans_streams_abort_state = ABORT_NORMAL;
			if (state == KEY_PRESSED &&
			    key == (kbtrans_key_t)kp->k_newabort2) {
				abort_sequence_enter((char *)NULL);
				kbtrans_processkey(lower,
				    upper->kbtrans_streams_callback,
				    upper->kbtrans_streams_new_abort1_key,
				    KEY_RELEASED);
				return;
			}
		}
	}

	kbtrans_processkey(lower, upper->kbtrans_streams_callback, key, state);
}

/*
 * kbtrans_streams_set_keyboard:
 *	At any time after calling kbtrans_streams_init, the hardware
 *	module should make this call to report the id of the keyboard
 *	attached. id is the keyboard type, typically KB_SUN4,
 *	KB_PC, or KB_USB.
 */
void
kbtrans_streams_set_keyboard(struct kbtrans *upper, int id, struct keyboard *k)
{
	upper->kbtrans_lower.kbtrans_keyboard = k;
	upper->kbtrans_streams_id = id;
}

/*
 * kbtrans_streams_has_reset:
 *	At any time between kbtrans_streams_init and kbtrans_streams_fini,
 *	the hardware module can call this routine to report that the
 *	keyboard has been reset, e.g. by being unplugged and reattached.
 */
/*ARGSUSED*/
void
kbtrans_streams_has_reset(struct kbtrans *upper)
{
	/*
	 * If this routine is implemented it should probably (a)
	 * simulate releases of all pressed keys and (b) call
	 * the hardware module to set the LEDs.
	 */
}

/*
 * kbtrans_streams_enable:
 *	This is the routine that is called back when the the stream is ready
 *	to take messages.
 */
void
kbtrans_streams_enable(struct kbtrans *upper)
{
	/* Set the LED's */
	kbtrans_setled(upper);
}

/*
 * kbtrans_streams_setled():
 *	This is the routine that is called to only update the led state
 *	in kbtrans.
 */
void
kbtrans_streams_setled(struct kbtrans *upper, int led_state)
{
	struct kbtrans_lower *lower;

	lower = &upper->kbtrans_lower;
	lower->kbtrans_led_state = (uchar_t)led_state;

	if (lower->kbtrans_led_state & LED_CAPS_LOCK)
		lower->kbtrans_togglemask |= CAPSMASK;
	if (lower->kbtrans_led_state & LED_NUM_LOCK)
		lower->kbtrans_togglemask |= NUMLOCKMASK;

#if	defined(SCROLLMASK)
	if (lower->kbtrans_led_state & LED_SCROLL_LOCK)
		lower->kbtrans_togglemask |= SCROLLMASK;
#endif

	lower->kbtrans_shiftmask = lower->kbtrans_togglemask;

}

/*
 * kbtrans_streams_set_queue:
 *      Set the overlying queue, to support multiplexors.
 */
void
kbtrans_streams_set_queue(struct kbtrans *upper, queue_t *q)
{

	upper->kbtrans_streams_readq = q;
}

/*
 * kbtrans_streams_get_queue:
 *      Return the overlying queue.
 */
queue_t *
kbtrans_streams_get_queue(struct kbtrans *upper)
{
	return (upper->kbtrans_streams_readq);
}

/*
 * kbtrans_streams_untimeout
 *      Cancell all timeout
 */
void
kbtrans_streams_untimeout(struct kbtrans *upper)
{
	/* clear all timeouts */
	if (upper->kbtrans_streams_bufcallid) {
		qunbufcall(upper->kbtrans_streams_readq,
		    upper->kbtrans_streams_bufcallid);
		upper->kbtrans_streams_bufcallid = 0;
	}
	if (upper->kbtrans_streams_rptid) {
		(void) quntimeout(upper->kbtrans_streams_readq,
		    upper->kbtrans_streams_rptid);
		upper->kbtrans_streams_rptid = 0;
	}
}

/*
 * kbtrans_reioctl:
 *	This function is set up as call-back function should an ioctl fail
 *	to allocate required resources.
 */
static void
kbtrans_reioctl(void	*arg)
{
	struct kbtrans *upper = (struct kbtrans *)arg;
	mblk_t *mp;

	upper->kbtrans_streams_bufcallid = 0;

	if ((mp = upper->kbtrans_streams_iocpending) != NULL) {
		/* not pending any more */
		upper->kbtrans_streams_iocpending = NULL;
		(void) kbtrans_ioctl(upper, mp);
	}
}

/*
 * kbtrans_ioctl:
 *	process ioctls we recognize and own.  Otherwise, pass it down.
 */
static enum kbtrans_message_response
kbtrans_ioctl(struct kbtrans *upper, register mblk_t *mp)
{
	register struct iocblk *iocp;
	register short	new_translate;
	register Vuid_addr_probe *addr_probe;
	register short	*addr_ptr;
	size_t	ioctlrespsize;
	int	err = 0;
	struct kbtrans_lower *lower;
	mblk_t *datap;
	int	translate;

	static int kiocgetkey, kiocsetkey;

	lower = &upper->kbtrans_lower;

	iocp = (struct iocblk *)mp->b_rptr;

	DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper,
	    "kbtrans_ioctl: ioc_cmd 0x%x - ", iocp->ioc_cmd));
	switch (iocp->ioc_cmd) {

	case VUIDSFORMAT:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "VUIDSFORMAT\n"));

		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;
		new_translate = (*(int *)mp->b_cont->b_rptr == VUID_NATIVE) ?
		    TR_ASCII : TR_EVENT;

		if (new_translate == upper->kbtrans_streams_translate_mode)
			break;
		upper->kbtrans_streams_translate_mode = new_translate;

		kbtrans_set_translation_callback(upper);

		kbtrans_flush(upper);
		break;

	case KIOCTRANS:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCTRANS\n"));
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;
		new_translate = *(int *)mp->b_cont->b_rptr;
		if (new_translate == upper->kbtrans_streams_translate_mode)
			break;
		upper->kbtrans_streams_translate_mode = new_translate;
		kbtrans_set_translation_callback(upper);

		kbtrans_flush(upper);
		break;

	case KIOCSLED:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCSLED\n"));

		err = miocpullup(mp, sizeof (uchar_t));
		if (err != 0)
			break;
		lower->kbtrans_led_state = *(uchar_t *)mp->b_cont->b_rptr;

		kbtrans_setled(upper);
		break;

	case KIOCGLED:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCGLED\n"));
		if ((datap = allocb(sizeof (uchar_t), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}

		*(uchar_t *)datap->b_wptr = lower->kbtrans_led_state;
		datap->b_wptr += sizeof (uchar_t);
		if (mp->b_cont)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (uchar_t);
		break;

	case VUIDGFORMAT:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "VUIDGFORMAT\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr =
		    (upper->kbtrans_streams_translate_mode == TR_EVENT ||
		    upper->kbtrans_streams_translate_mode == TR_UNTRANS_EVENT) ?
		    VUID_FIRM_EVENT: VUID_NATIVE;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCGTRANS:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCGTRANS\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = upper->kbtrans_streams_translate_mode;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case VUIDSADDR:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "VUIDSADDR\n"));

		err = miocpullup(mp, sizeof (Vuid_addr_probe));
		if (err != 0)
			break;
		addr_probe = (Vuid_addr_probe *)mp->b_cont->b_rptr;
		switch (addr_probe->base) {

		case ASCII_FIRST:
			addr_ptr = &upper->kbtrans_streams_vuid_addr.ascii;
			break;

		case TOP_FIRST:
			addr_ptr = &upper->kbtrans_streams_vuid_addr.top;
			break;

		case VKEY_FIRST:
			addr_ptr = &upper->kbtrans_streams_vuid_addr.vkey;
			break;

		default:
			err = ENODEV;
		}

		if ((err == 0) && (*addr_ptr != addr_probe->data.next)) {
			*addr_ptr = addr_probe->data.next;
			kbtrans_flush(upper);
		}
		break;

	case VUIDGADDR:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "VUIDGADDR\n"));

		err = miocpullup(mp, sizeof (Vuid_addr_probe));
		if (err != 0)
			break;
		addr_probe = (Vuid_addr_probe *)mp->b_cont->b_rptr;
		switch (addr_probe->base) {

		case ASCII_FIRST:
			addr_probe->data.current =
			    upper->kbtrans_streams_vuid_addr.ascii;
			break;

		case TOP_FIRST:
			addr_probe->data.current =
			    upper->kbtrans_streams_vuid_addr.top;
			break;

		case VKEY_FIRST:
			addr_probe->data.current =
			    upper->kbtrans_streams_vuid_addr.vkey;
			break;

		default:
			err = ENODEV;
		}
		break;

	case KIOCTRANSABLE:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCTRANSABLE\n"));

		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;
		/*
		 * called during console setup in kbconfig()
		 * If set to false, means we are a serial keyboard,
		 * and we should pass all data up without modification.
		 */
		translate = *(int *)mp->b_cont->b_rptr;
		if (upper->kbtrans_streams_translatable != translate)
			upper->kbtrans_streams_translatable = translate;

		if (translate != TR_CAN)
			DPRINTF(PRINT_L4, PRINT_MASK_ALL, (upper,
			    "Cannot translate keyboard using tables.\n"));
		break;

	case KIOCGTRANSABLE:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCGTRANSABLE\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = upper->kbtrans_streams_translatable;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCSCOMPAT:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCSCOMPAT\n"));

		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;
		lower->kbtrans_compat = *(int *)mp->b_cont->b_rptr;
		break;

	case KIOCGCOMPAT:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCGCOMPAT\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = lower->kbtrans_compat;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCSETKEY:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCSETKEY %d\n",
		    kiocsetkey++));
		err = miocpullup(mp, sizeof (struct kiockey));
		if (err != 0)
			break;
		err = kbtrans_setkey(&upper->kbtrans_lower,
		    (struct kiockey *)mp->b_cont->b_rptr, iocp->ioc_cr);
		/*
		 * Since this only affects any subsequent key presses,
		 * don't flush soft state.  One might want to
		 * toggle the keytable entries dynamically.
		 */
		break;

	case KIOCGETKEY:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCGETKEY %d\n",
		    kiocgetkey++));
		err = miocpullup(mp, sizeof (struct kiockey));
		if (err != 0)
			break;
		err = kbtrans_getkey(&upper->kbtrans_lower,
		    (struct kiockey *)mp->b_cont->b_rptr);
		break;

	case KIOCSKEY:
		err = miocpullup(mp, sizeof (struct kiockeymap));
		if (err != 0)
			break;
		err = kbtrans_skey(&upper->kbtrans_lower,
		    (struct kiockeymap *)mp->b_cont->b_rptr, iocp->ioc_cr);
		/*
		 * Since this only affects any subsequent key presses,
		 * don't flush soft state.  One might want to
		 * toggle the keytable entries dynamically.
		 */
		break;

	case KIOCGKEY:
		err = miocpullup(mp, sizeof (struct kiockeymap));
		if (err != 0)
			break;
		err = kbtrans_gkey(&upper->kbtrans_lower,
		    (struct kiockeymap *)mp->b_cont->b_rptr);
		break;

	case KIOCSDIRECT:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCSDIRECT\n"));
		kbtrans_flush(upper);
		break;

	case KIOCGDIRECT:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCSGDIRECT\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = 1;	/* always direct */
		datap->b_wptr += sizeof (int);
		if (mp->b_cont) /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCTYPE:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCTYPE\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = upper->kbtrans_streams_id;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont) /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case CONSSETABORTENABLE:
		/*
		 * Peek as it goes by; must be a TRANSPARENT ioctl.
		 */
		if (iocp->ioc_count != TRANSPARENT) {
			err = EINVAL;
			break;
		}

		upper->kbtrans_streams_abortable =
		    (boolean_t)*(intptr_t *)mp->b_cont->b_rptr;

		/*
		 * Let the hardware module see it too.
		 */
		return (KBTRANS_MESSAGE_NOT_HANDLED);

	case KIOCGRPTCOUNT:
		/*
		 * Report the autorepeat count
		 */
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCGRPTCOUNT\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = kbtrans_repeat_count;
		datap->b_wptr += sizeof (int);

		/* free msg to prevent memory leak */
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCSRPTCOUNT:
		/*
		 * Set the autorepeat count
		 */
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCSRPTCOUNT\n"));
		err = miocpullup(mp, sizeof (int));

		if (err != 0)
			break;

		/* validate the input */
		if (*(int *)mp->b_cont->b_rptr < -1) {
			err = EINVAL;
			break;
		}
		kbtrans_repeat_count = (*(int *)mp->b_cont->b_rptr);
		break;

	case KIOCGRPTDELAY:
		/*
		 * Report the autorepeat delay, unit in millisecond
		 */
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCGRPTDELAY\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = TICK_TO_MSEC(kbtrans_repeat_delay);
		datap->b_wptr += sizeof (int);

		/* free msg to prevent memory leak */
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCSRPTDELAY:
		/*
		 * Set the autorepeat delay
		 */
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCSRPTDELAY\n"));
		err = miocpullup(mp, sizeof (int));

		if (err != 0)
			break;

		/* validate the input */
		if (*(int *)mp->b_cont->b_rptr < KIOCRPTDELAY_MIN) {
			err = EINVAL;
			break;
		}
		kbtrans_repeat_delay = MSEC_TO_TICK(*(int *)mp->b_cont->b_rptr);
		if (kbtrans_repeat_delay <= 0)
			kbtrans_repeat_delay = 1;
		break;

	case KIOCGRPTRATE:
		/*
		 * Report the autorepeat rate
		 */
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCGRPTRATE\n"));
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = TICK_TO_MSEC(kbtrans_repeat_rate);
		datap->b_wptr += sizeof (int);

		/* free msg to prevent memory leak */
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCSRPTRATE:
		/*
		 * Set the autorepeat rate
		 */
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "KIOCSRPTRATE\n"));
		err = miocpullup(mp, sizeof (int));

		if (err != 0)
			break;

		/* validate the input */
		if (*(int *)mp->b_cont->b_rptr < KIOCRPTRATE_MIN) {
			err = EINVAL;
			break;
		}
		kbtrans_repeat_rate = MSEC_TO_TICK(*(int *)mp->b_cont->b_rptr);
		if (kbtrans_repeat_rate <= 0)
			kbtrans_repeat_rate = 1;
		break;

	default:
		DPRINTF(PRINT_L0, PRINT_MASK_ALL, (upper, "unknown\n"));
		return (KBTRANS_MESSAGE_NOT_HANDLED);
	} /* end switch */

	if (err != 0) {
		iocp->ioc_rval = 0;
		iocp->ioc_error = err;
		mp->b_datap->db_type = M_IOCNAK;
	} else {
		iocp->ioc_rval = 0;
		iocp->ioc_error = 0;	/* brain rot */
		mp->b_datap->db_type = M_IOCACK;
	}
	putnext(upper->kbtrans_streams_readq, mp);

	return (KBTRANS_MESSAGE_HANDLED);

allocfailure:
	/*
	 * We needed to allocate something to handle this "ioctl", but
	 * couldn't; save this "ioctl" and arrange to get called back when
	 * it's more likely that we can get what we need.
	 * If there's already one being saved, throw it out, since it
	 * must have timed out.
	 */
	if (upper->kbtrans_streams_iocpending != NULL)
		freemsg(upper->kbtrans_streams_iocpending);
	upper->kbtrans_streams_iocpending = mp;
	if (upper->kbtrans_streams_bufcallid) {
		qunbufcall(upper->kbtrans_streams_readq,
		    upper->kbtrans_streams_bufcallid);
	}
	upper->kbtrans_streams_bufcallid =
	    qbufcall(upper->kbtrans_streams_readq, ioctlrespsize, BPRI_HI,
	    kbtrans_reioctl, upper);
	/*
	 * This is a white lie... we *will* handle it, eventually.
	 */
	return (KBTRANS_MESSAGE_HANDLED);
}

/*
 * kbtrans_flush:
 *	Flush data upstream
 */
static void
kbtrans_flush(register struct kbtrans *upper)
{
	register queue_t *q;

	/* Flush pending data already sent upstream */
	if ((q = upper->kbtrans_streams_readq) != NULL && q->q_next != NULL)
		(void) putnextctl1(q, M_FLUSH, FLUSHR);

	/* Flush pending ups */
	bzero(upper->kbtrans_streams_downs, upper->kbtrans_streams_downs_bytes);

	kbtrans_cancelrpt(upper);
}

/*
 * kbtrans_setled:
 *	 Update the keyboard LEDs to match the current keyboard state.
 */
static void
kbtrans_setled(struct kbtrans *upper)
{
	upper->kbtrans_streams_hw_callbacks->kbtrans_streams_setled(
	    upper->kbtrans_streams_hw,
	    upper->kbtrans_lower.kbtrans_led_state);
}

/*
 * kbtrans_rpt:
 *	If a key is held down, this function is set up to be called
 *	after kbtrans_repeat_rate time elapses.
 */
static void
kbtrans_rpt(void *arg)
{
	struct kbtrans	*upper = arg;
	struct kbtrans_lower	*lower = &upper->kbtrans_lower;

	DPRINTF(PRINT_L0, PRINT_MASK_ALL, (NULL,
	    "kbtrans_rpt: repeat key %X\n",
	    lower->kbtrans_repeatkey));

	upper->kbtrans_streams_rptid = 0;
	upper->kbtrans_streams_count++;

	/*
	 * NB:  polled code zaps kbtrans_repeatkey without cancelling
	 * timeout.
	 */
	if (kbtrans_repeat_count > 0) {
		/* If limit is set and reached, stop there. */
		if (upper->kbtrans_streams_count > kbtrans_repeat_count)
			lower->kbtrans_repeatkey = 0;
	}

	if (lower->kbtrans_repeatkey != 0) {
		kbtrans_keyreleased(upper, lower->kbtrans_repeatkey);

		kbtrans_processkey(lower,
		    upper->kbtrans_streams_callback,
		    lower->kbtrans_repeatkey,
		    KEY_PRESSED);

		upper->kbtrans_streams_rptid =
		    qtimeout(upper->kbtrans_streams_readq, kbtrans_rpt,
		    (caddr_t)upper, kbtrans_repeat_rate);
	}
}

/*
 * kbtrans_cancelrpt:
 *	Cancel the repeating key
 */
static void
kbtrans_cancelrpt(struct kbtrans	*upper)
{
	upper->kbtrans_lower.kbtrans_repeatkey = 0;

	if (upper->kbtrans_streams_rptid != 0) {
		(void) quntimeout(upper->kbtrans_streams_readq,
		    upper->kbtrans_streams_rptid);
		upper->kbtrans_streams_rptid = 0;
	}
}

/*
 * kbtrans_send_esc_event:
 *	Send character up stream. Used for the case of
 *	sending strings upstream.
 */
static void
kbtrans_send_esc_event(char c, register struct kbtrans *upper)
{
	Firm_event fe;

	fe.id = c;
	fe.value = 1;
	fe.pair_type = FE_PAIR_NONE;
	fe.pair = 0;
	/*
	 * Pretend as if each cp pushed and released
	 * Calling kbtrans_queueevent avoids addr translation
	 * and pair base determination of kbtrans_keypressed.
	 */
	kbtrans_queueevent(upper, &fe);
	fe.value = 0;
	kbtrans_queueevent(upper, &fe);
}

/*
 * kbtrans_strsetwithdecimal:
 *	Used for expanding a function key to the ascii equivalent
 */
static char *
kbtrans_strsetwithdecimal(char *buf, uint_t val, uint_t maxdigs)
{
	int	hradix = 5;
	char	*bp;
	int	lowbit;
	char	*tab = "0123456789abcdef";

	bp = buf + maxdigs;
	*(--bp) = '\0';
	while (val) {
		lowbit = val & 1;
		val = (val >> 1);
		*(--bp) = tab[val % hradix * 2 + lowbit];
		val /= hradix;
	}
	return (bp);
}

/*
 * kbtrans_keypressed:
 *	Modify Firm event to be sent up the stream
 */
static void
kbtrans_keypressed(struct kbtrans *upper, uchar_t key_station,
    Firm_event *fe, ushort_t base)
{

	register short	id_addr;
	struct kbtrans_lower	*lower = &upper->kbtrans_lower;

	/* Set pair values */
	if (fe->id < (ushort_t)VKEY_FIRST) {
		/*
		 * If CTRLed, find the ID that would have been used had it
		 * not been CTRLed.
		 */
		if (lower->kbtrans_shiftmask & (CTRLMASK | CTLSMASK)) {
			keymap_entry_t *ke;
			unsigned int mask;

			mask = lower->kbtrans_shiftmask &
			    ~(CTRLMASK | CTLSMASK | UPMASK);

			ke = kbtrans_find_entry(lower, mask, key_station);
			if (ke == NULL)
				return;

			base = *ke;
		}
		if (base != fe->id) {
			fe->pair_type = FE_PAIR_SET;
			fe->pair = (uchar_t)base;

			goto send;
		}
	}
	fe->pair_type = FE_PAIR_NONE;
	fe->pair = 0;

send:
	/* Adjust event id address for multiple keyboard/workstation support */
	switch (vuid_id_addr(fe->id)) {
	case ASCII_FIRST:
		id_addr = upper->kbtrans_streams_vuid_addr.ascii;
		break;
	case TOP_FIRST:
		id_addr = upper->kbtrans_streams_vuid_addr.top;
		break;
	case VKEY_FIRST:
		id_addr = upper->kbtrans_streams_vuid_addr.vkey;
		break;
	default:
		id_addr = vuid_id_addr(fe->id);
		break;
	}
	fe->id = vuid_id_offset(fe->id) | id_addr;

	kbtrans_queuepress(upper, key_station, fe);
}

/*
 * kbtrans_queuepress:
 *	Add keypress to the "downs" table
 */
static void
kbtrans_queuepress(struct kbtrans *upper,
    uchar_t key_station, Firm_event *fe)
{
	register struct key_event *ke, *ke_free;
	register int i;

	DPRINTF(PRINT_L0, PRINT_MASK_ALL, (NULL, "kbtrans_queuepress:"
	    " key=%d", key_station));

	ke_free = 0;

	/* Scan table of down key stations */

	for (i = 0, ke = upper->kbtrans_streams_downs;
	    i < upper->kbtrans_streams_num_downs_entries; i++, ke++) {

		/* Keycode already down? */
		if (ke->key_station == key_station) {

			DPRINTF(PRINT_L0, PRINT_MASK_ALL,
			    (NULL, "kbtrans: Double "
			    "entry in downs table (%d,%d)!\n",
			    key_station, i));

			goto add_event;
		}

		if (ke->key_station == 0)
			ke_free = ke;
	}

	if (ke_free) {
		ke = ke_free;
		goto add_event;
	}

	ke = upper->kbtrans_streams_downs;

add_event:
	ke->key_station = key_station;
	ke->event = *fe;
	kbtrans_queueevent(upper, fe);
}

/*
 * kbtrans_keyreleased:
 *	Remove entry from the downs table
 */
static void
kbtrans_keyreleased(register struct kbtrans *upper, uchar_t key_station)
{
	register struct key_event *ke;
	register int i;

	DPRINTF(PRINT_L0, PRINT_MASK_ALL, (NULL, "RELEASE key=%d\n",
	    key_station));

	if (upper->kbtrans_streams_translate_mode != TR_EVENT &&
	    upper->kbtrans_streams_translate_mode != TR_UNTRANS_EVENT) {

		return;
	}

	/* Scan table of down key stations */
	for (i = 0, ke = upper->kbtrans_streams_downs;
	    i < upper->kbtrans_streams_num_downs_entries;
	    i++, ke++) {
		/* Found? */
		if (ke->key_station == key_station) {
			ke->key_station = 0;
			ke->event.value = 0;
			kbtrans_queueevent(upper, &ke->event);
		}
	}

	/*
	 * Ignore if couldn't find because may be called twice
	 * for the same key station in the case of the kbtrans_rpt
	 * routine being called unnecessarily.
	 */
}


/*
 * kbtrans_putcode:
 *	 Pass a keycode up the stream, if you can, otherwise throw it away.
 */
static void
kbtrans_putcode(register struct kbtrans *upper, uint_t code)
{
	register mblk_t *bp;

	/*
	 * If we can't send it up, then we just drop it.
	 */
	if (!canputnext(upper->kbtrans_streams_readq)) {

		return;
	}

	/*
	 * Allocate a messsage block to send up.
	 */
	if ((bp = allocb(sizeof (uint_t), BPRI_HI)) == NULL) {

		cmn_err(CE_WARN, "kbtrans_putcode: Can't allocate block\
			for keycode.");

		return;
	}

	/*
	 * We will strip out any high order information here.
	 * Convert to UTF-8.
	 */
	code = KEYCHAR(code);
	if (code < 0x80) {
		*bp->b_wptr++ = (char)code;
	} else if (code < 0x800) {
		*bp->b_wptr++ = 0xc0 | (code >> 6);
		*bp->b_wptr++ = 0x80 | (code & 0x3f);
	} else if (code < 0x10000) {
		*bp->b_wptr++ = 0xe0 | (code >> 12);
		*bp->b_wptr++ = 0x80 | ((code >> 6) & 0x3f);
		*bp->b_wptr++ = 0x80 | (code & 0x3f);
	} else {
		*bp->b_wptr++ = 0xf0 | (code >> 18);
		*bp->b_wptr++ = 0x80 | ((code >> 12) & 0x3f);
		*bp->b_wptr++ = 0x80 | ((code >> 6) & 0x3f);
		*bp->b_wptr++ = 0x80 | (code & 0x3f);
	}

	/*
	 * Send the message up.
	 */
	(void) putnext(upper->kbtrans_streams_readq, bp);
}


/*
 * kbtrans_putbuf:
 *	Pass generated keycode sequence to upstream, if possible.
 */
static void
kbtrans_putbuf(char *buf, queue_t *q)
{
	register mblk_t *bp;

	if (!canputnext(q)) {
		cmn_err(CE_WARN, "kbtrans_putbuf: Can't put block for keycode");
	} else {
		if ((bp = allocb((int)strlen(buf), BPRI_HI)) == NULL) {
			cmn_err(CE_WARN, "kbtrans_putbuf: "
			    "Can't allocate block for keycode");
		} else {
			while (*buf) {
				*bp->b_wptr++ = *buf;
				buf++;
			}
			putnext(q, bp);
		}
	}
}

/*
 * kbtrans_queueevent:
 *	 Pass a VUID "firm event" up the stream, if you can.
 */
static void
kbtrans_queueevent(struct kbtrans *upper, Firm_event *fe)
{
	register queue_t *q;
	register mblk_t *bp;

	if ((q = upper->kbtrans_streams_readq) == NULL)

		return;

	if (!canputnext(q)) {
		if (kbtrans_overflow_msg) {
			DPRINTF(PRINT_L2, PRINT_MASK_ALL, (NULL,
			    "kbtrans: Buffer flushed when overflowed."));
		}

		kbtrans_flush(upper);
		upper->kbtrans_overflow_cnt++;
	} else {
		if ((bp = allocb(sizeof (Firm_event), BPRI_HI)) == NULL) {
			cmn_err(CE_WARN, "kbtrans_queueevent: Can't allocate \
					block for event.");
		} else {
			uniqtime32(&fe->time);
			*(Firm_event *)bp->b_wptr = *fe;
			bp->b_wptr += sizeof (Firm_event);
			(void) putnext(q, bp);


		}
	}
}

/*
 * kbtrans_set_translation_callback:
 *	This code sets the translation_callback pointer based on the
 *	translation mode.
 */
static void
kbtrans_set_translation_callback(register struct kbtrans *upper)
{
	switch (upper->kbtrans_streams_translate_mode) {

	default:
	case TR_ASCII:
		upper->vt_switch_keystate = VT_SWITCH_KEY_NONE;

		/* Discard any obsolete CTRL/ALT/SHIFT keys */
		upper->kbtrans_lower.kbtrans_shiftmask &=
		    ~(CTRLMASK | ALTMASK | SHIFTMASK);
		upper->kbtrans_lower.kbtrans_togglemask &=
		    ~(CTRLMASK | ALTMASK | SHIFTMASK);

		upper->kbtrans_streams_callback = &ascii_callback;

		break;

	case TR_EVENT:
		upper->kbtrans_streams_callback = &trans_event_callback;

		break;

	case TR_UNTRANS_EVENT:
		upper->kbtrans_streams_callback = &untrans_event_callback;

		break;
	}
}

/*
 * kbtrans_untrans_keypressed_raw:
 *	This is the callback we get if we are in TR_UNTRANS_EVENT and a
 *	key is pressed.  This code will just send the scancode up the
 *	stream.
 */
static void
kbtrans_untrans_keypressed_raw(struct kbtrans *upper, kbtrans_key_t key)
{
	Firm_event	fe;

	bzero(&fe, sizeof (fe));

	/*
	 * fill in the event
	 */
	fe.id = (unsigned short)key;
	fe.value = 1;

	/*
	 * Send the event upstream.
	 */
	kbtrans_queuepress(upper, key, &fe);
}

/*
 * kbtrans_untrans_keyreleased_raw:
 *	This is the callback we get if we are in TR_UNTRANS_EVENT mode
 *	and a key is released.  This code will just send the scancode up
 *	the stream.
 */
static void
kbtrans_untrans_keyreleased_raw(struct kbtrans *upper, kbtrans_key_t key)
{
	/*
	 * Deal with a key released event.
	 */
	kbtrans_keyreleased(upper, key);
}

/*
 * kbtrans_vt_compose:
 *   To compose the key sequences for virtual terminal switching.
 *
 *   'ALTL + F#'                for 1-12 terminals
 *   'ALTGR + F#'               for 13-24 terminals
 *   'ALT + UPARROW'            for last terminal
 *   'ALT + LEFTARROW'          for previous terminal
 *   'ALT + RIGHTARROW'         for next terminal
 *
 * the vt switching message is encoded as:
 *
 *   -------------------------------------------------------------
 *   |  \033  |  'Q'  |  vtno + 'A'  |  opcode  |  'z'  |  '\0'  |
 *   -------------------------------------------------------------
 *
 * opcode:
 *   'B'    to switch to previous terminal
 *   'F'    to switch to next terminal
 *   'L'    to switch to last terminal
 *   'H'    to switch to the terminal as specified by vtno,
 *          which is from 1 to 24.
 *
 * Here keyid is the keycode of UPARROW, LEFTARROW, or RIGHTARROW
 * when it is a kind of arrow key as indicated by is_arrow_key,
 * otherwise it indicates a function key and keyid is the number
 * corresponding to that function key.
 */
static void
kbtrans_vt_compose(struct kbtrans *upper, unsigned short keyid,
    boolean_t is_arrow_key, char *buf)
{
	char		*bufp;

	bufp = buf;
	*bufp++ = '\033'; /* Escape */
	*bufp++ = 'Q';
	if (is_arrow_key) {
		*bufp++ = 'A';
		switch (keyid) {
		case UPARROW: /* last vt */
			*bufp++ = 'L';
			break;
		case LEFTARROW: /* previous vt */
			*bufp++ = 'B';
			break;
		case RIGHTARROW: /* next vt */
			*bufp++ = 'F';
			break;
		default:
			break;
		}
	} else {
		/* this is funckey specifying vtno for switch */
		*bufp++ = keyid +
		    (upper->vt_switch_keystate - VT_SWITCH_KEY_ALT) *
		    KB_NR_FUNCKEYS + 'A';
		*bufp++ = 'H';
	}
	*bufp++ = 'z';
	*bufp = '\0';

	/*
	 * Send the result upstream.
	 */
	kbtrans_putbuf(buf, upper->kbtrans_streams_readq);

}

/*
 * kbtrans_ascii_keypressed:
 *	This is the code if we are in TR_ASCII mode and a key
 *	is pressed.  This is where we will do any special processing that
 *	is specific to ASCII key translation.
 */
/* ARGSUSED */
static void
kbtrans_ascii_keypressed(struct kbtrans *upper, uint_t entrytype,
    kbtrans_key_t  key, uint_t entry)
{
	register char	*cp;
	register char	*bufp;
	char		buf[14];
	unsigned short		keyid;
	struct kbtrans_lower	*lower = &upper->kbtrans_lower;

	/*
	 * Based on the type of key, we may need to do some ASCII
	 * specific post processing. Note that the translated entry
	 * is constructed as the actual keycode plus entrytype. See
	 * sys/kbd.h for details of each entrytype.
	 */
	switch (entrytype) {

	case BUCKYBITS:
		return;

	case SHIFTKEYS:
		keyid = entry & 0xFF;
		if (keyid == ALT) {
			upper->vt_switch_keystate = VT_SWITCH_KEY_ALT;
		} else if (keyid == ALTGRAPH) {
			upper->vt_switch_keystate = VT_SWITCH_KEY_ALTGR;
		}
		return;

	case FUNNY:
		/*
		 * There is no ascii equivalent.  We will ignore these
		 * keys
		 */
		return;

	case FUNCKEYS:
		if (upper->vt_switch_keystate > VT_SWITCH_KEY_NONE) {
			if (entry >= TOPFUNC &&
			    entry < (TOPFUNC + KB_NR_FUNCKEYS)) {

				/*
				 * keyid is the number correspoding to F#
				 * and its value is from 1 to 12.
				 */
				keyid = (entry & 0xF) + 1;

				kbtrans_vt_compose(upper, keyid, B_FALSE, buf);
				return;
			}
		}

		/*
		 * We need to expand this key to get the ascii
		 * equivalent.  These are the function keys (F1, F2 ...)
		 */
		bufp = buf;
		cp = kbtrans_strsetwithdecimal(bufp + 2,
		    (uint_t)((entry & 0x003F) + 192),
		    sizeof (buf) - 5);
		*bufp++ = '\033'; /* Escape */
		*bufp++ = '[';
		while (*cp != '\0')
			*bufp++ = *cp++;
		*bufp++ = 'z';
		*bufp = '\0';

		/*
		 * Send the result upstream.
		 */
		kbtrans_putbuf(buf, upper->kbtrans_streams_readq);

		return;

	case STRING:
		if (upper->vt_switch_keystate > VT_SWITCH_KEY_NONE) {
			keyid = entry & 0xFF;
			if (keyid == UPARROW ||
			    keyid == RIGHTARROW ||
			    keyid == LEFTARROW) {

				kbtrans_vt_compose(upper, keyid, B_TRUE, buf);
				return;
			}
		}

		/*
		 * These are the multi byte keys (Home, Up, Down ...)
		 */
		cp = &lower->kbtrans_keystringtab[entry & 0x0F][0];

		/*
		 * Copy the string from the keystringtable, and send it
		 * upstream a character at a time.
		 */
		while (*cp != '\0') {

			kbtrans_putcode(upper, (uchar_t)*cp);

			cp++;
		}

		return;

	case PADKEYS:
		/*
		 * These are the keys on the keypad.  Look up the
		 * answer in the kb_numlock_table and send it upstream.
		 */
		kbtrans_putcode(upper,
		    lower->kbtrans_numlock_table[entry&0x1F]);

		return;

	case 0:	/* normal character */
	default:
		break;
	}

	/*
	 * Send the char upstream.
	 */
	kbtrans_putcode(upper, entry);

}

#define	KB_SCANCODE_ALT		0xe2
#define	KB_SCANCODE_ALTGRAPH	0xe6

/*
 * kbtrans_ascii_keyreleased:
 *	This is the function if we are in TR_ASCII mode and a key
 *	is released.  ASCII doesn't have the concept of released keys,
 *	or make/break codes.  So there is nothing for us to do except
 *      checking 'Alt/AltGraph' release key in order to reset the state
 *      of vt switch key sequence.
 */
/* ARGSUSED */
static void
kbtrans_ascii_keyreleased(struct kbtrans *upper, kbtrans_key_t key)
{
	if (key == KB_SCANCODE_ALT || key == KB_SCANCODE_ALTGRAPH) {
		upper->vt_switch_keystate = VT_SWITCH_KEY_NONE;
	}
}

/*
 * kbtrans_ascii_setup_repeat:
 *	This is the function if we are in TR_ASCII mode and the
 *	translation module has decided that a key needs to be repeated.
 */
/* ARGSUSED */
static void
kbtrans_ascii_setup_repeat(struct kbtrans *upper, uint_t entrytype,
    kbtrans_key_t key)
{
	struct kbtrans_lower *lower = &upper->kbtrans_lower;

	/*
	 * Cancel any currently repeating keys.  This will be a new
	 * key to repeat.
	 */
	kbtrans_cancelrpt(upper);

	/*
	 * Set the value of the key to be repeated.
	 */
	lower->kbtrans_repeatkey = key;

	/*
	 * Start the timeout for repeating this key.  kbtrans_rpt will
	 * be called to repeat the key.
	 */
	upper->kbtrans_streams_count = 0;
	upper->kbtrans_streams_rptid = qtimeout(upper->kbtrans_streams_readq,
	    kbtrans_rpt, (caddr_t)upper, kbtrans_repeat_delay);
}

/*
 * kbtrans_trans_event_keypressed:
 *	This is the function if we are in TR_EVENT mode and a key
 *	is pressed.  This is where we will do any special processing that
 *	is specific to EVENT key translation.
 */
static void
kbtrans_trans_event_keypressed(struct kbtrans *upper, uint_t entrytype,
    kbtrans_key_t key, uint_t entry)
{
	Firm_event	fe;
	register char	*cp;
	struct kbtrans_lower	*lower = &upper->kbtrans_lower;

	/*
	 * Based on the type of key, we may need to do some EVENT
	 * specific post processing.
	 */
	switch (entrytype) {

	case SHIFTKEYS:
		/*
		 * Relying on ordinal correspondence between
		 * vuid_event.h SHIFT_META-SHIFT_TOP &
		 * kbd.h METABIT-SYSTEMBIT in order to
		 * correctly translate entry into fe.id.
		 */
		fe.id = SHIFT_CAPSLOCK + (entry & 0x0F);
		fe.value = 1;
		kbtrans_keypressed(upper, key, &fe, fe.id);

		return;

	case BUCKYBITS:
		/*
		 * Relying on ordinal correspondence between
		 * vuid_event.h SHIFT_CAPSLOCK-SHIFT_RIGHTCTRL &
		 * kbd.h CAPSLOCK-RIGHTCTRL in order to
		 * correctly translate entry into fe.id.
		 */
		fe.id = SHIFT_META + (entry & 0x0F);
		fe.value = 1;
		kbtrans_keypressed(upper, key, &fe, fe.id);

		return;

	case FUNCKEYS:
		/*
		 * Take advantage of the similar
		 * ordering of kbd.h function keys and
		 * vuid_event.h function keys to do a
		 * simple translation to achieve a
		 * mapping between the 2 different
		 * address spaces.
		 */
		fe.id = KEY_LEFTFIRST + (entry & 0x003F);
		fe.value = 1;

		/*
		 * Assume "up" table only generates
		 * shift changes.
		 */
		kbtrans_keypressed(upper, key, &fe, fe.id);

		/*
		 * Function key events can be expanded
		 * by terminal emulator software to
		 * produce the standard escape sequence
		 * generated by the TR_ASCII case above
		 * if a function key event is not used
		 * by terminal emulator software
		 * directly.
		 */
		return;

	case STRING:
		/*
		 * These are the multi byte keys (Home, Up, Down ...)
		 */
		cp = &lower->kbtrans_keystringtab[entry & 0x0F][0];

		/*
		 * Copy the string from the keystringtable, and send it
		 * upstream a character at a time.
		 */
		while (*cp != '\0') {

			kbtrans_send_esc_event(*cp, upper);

			cp++;
		}

		return;

	case PADKEYS:
		/*
		 * Take advantage of the similar
		 * ordering of kbd.h keypad keys and
		 * vuid_event.h keypad keys to do a
		 * simple translation to achieve a
		 * mapping between the 2 different
		 * address spaces.
		 */
		fe.id = VKEY_FIRSTPAD + (entry & 0x001F);
		fe.value = 1;

		/*
		 * Assume "up" table only generates
		 * shift changes.
		 */
		kbtrans_keypressed(upper, key, &fe, fe.id);

		/*
		 * Keypad key events can be expanded
		 * by terminal emulator software to
		 * produce the standard ascii character
		 * generated by the TR_ASCII case above
		 * if a keypad key event is not used
		 * by terminal emulator software
		 * directly.
		 */
		return;

	case FUNNY:
		/*
		 * These are not events.
		 */
		switch (entry) {
		case IDLE:
		case RESET:
		case ERROR:
			/*
			 * Something has happened.  Mark all keys as released.
			 */
			kbtrans_streams_releaseall(upper);
			break;
		}

		return;

	case 0: /* normal character */
	default:
		break;
	}

	/*
	 * Send the event upstream.
	 */
	fe.id = entry;

	fe.value = 1;

	kbtrans_queueevent(upper, &fe);
}

/*
 * kbtrans_trans_event_keyreleased:
 *	This is the function if we are in TR_EVENT mode and a key
 *	is released.
 */
/* ARGSUSED */
static void
kbtrans_trans_event_keyreleased(struct kbtrans *upper, kbtrans_key_t key)
{
	/*
	 * Mark the key as released and send an event upstream.
	 */
	kbtrans_keyreleased(upper, key);
}

/*
 * kbtrans_trans_event_setup_repeat:
 *	This is the function if we are in TR_EVENT mode and the
 *	translation module has decided that a key needs to be repeated.
 *	We will set a timeout to retranslate the repeat key.
 */
static void
kbtrans_trans_event_setup_repeat(struct kbtrans *upper, uint_t entrytype,
    kbtrans_key_t key)
{
	struct kbtrans_lower *lower = &upper->kbtrans_lower;

	/*
	 * Function keys and keypad keys do not repeat when we are in
	 * EVENT mode.
	 */
	if (entrytype == FUNCKEYS || entrytype == PADKEYS) {

		return;
	}

	/*
	 * Cancel any currently repeating keys.  This will be a new
	 * key to repeat.
	 */
	kbtrans_cancelrpt(upper);

	/*
	 * Set the value of the key to be repeated.
	 */
	lower->kbtrans_repeatkey = key;

	/*
	 * Start the timeout for repeating this key.  kbtrans_rpt will
	 * be called to repeat the key.
	 */
	upper->kbtrans_streams_count = 0;
	upper->kbtrans_streams_rptid = qtimeout(upper->kbtrans_streams_readq,
	    kbtrans_rpt, (caddr_t)upper, kbtrans_repeat_delay);
}

/*
 * Administer the key tables.
 */

/*
 * Old special codes.
 */
#define	OLD_SHIFTKEYS	0x80
#define	OLD_BUCKYBITS	0x90
#define	OLD_FUNNY	0xA0
#define	OLD_FA_UMLAUT	0xA9
#define	OLD_FA_CFLEX	0xAA
#define	OLD_FA_TILDE	0xAB
#define	OLD_FA_CEDILLA	0xAC
#define	OLD_FA_ACUTE	0xAD
#define	OLD_FA_GRAVE	0xAE
#define	OLD_ISOCHAR	0xAF
#define	OLD_STRING	0xB0
#define	OLD_LEFTFUNC	0xC0
#define	OLD_RIGHTFUNC	0xD0
#define	OLD_TOPFUNC	0xE0
#define	OLD_BOTTOMFUNC	0xF0

/*
 * Map old special codes to new ones.
 * Indexed by ((old special code) >> 4) & 0x07; add (old special code) & 0x0F.
 */
static keymap_entry_t  special_old_to_new[] = {
	SHIFTKEYS,
	BUCKYBITS,
	FUNNY,
	STRING,
	LEFTFUNC,
	RIGHTFUNC,
	TOPFUNC,
	BOTTOMFUNC,
};


/*
 * kbtrans_setkey:
 *	 Set individual keystation translation from old-style entry.
 */
static int
kbtrans_setkey(struct kbtrans_lower *lower, struct kiockey *key, cred_t *cr)
{
	int	strtabindex, i;
	keymap_entry_t	*ke;
	register int tablemask;
	register keymap_entry_t entry;
	register struct keyboard *kp;

	kp = lower->kbtrans_keyboard;

	if (key->kio_station >= kp->k_keymap_size)
		return (EINVAL);

	if (lower->kbtrans_keyboard == NULL)

		return (EINVAL);

	tablemask = key->kio_tablemask;

	switch (tablemask) {
	case KIOCABORT1:
	case KIOCABORT1A:
	case KIOCABORT2:
		i = secpolicy_console(cr);
		if (i != 0)
			return (i);

		switch (tablemask) {
		case KIOCABORT1:
			kp->k_abort1 = key->kio_station;
			break;
		case KIOCABORT1A:
			kp->k_abort1a = key->kio_station;
			break;
		case KIOCABORT2:
			kp->k_abort2 = key->kio_station;
			break;
		}
		return (0);
	}

	if (tablemask & ALTGRAPHMASK)
		return (EINVAL);

	ke = kbtrans_find_entry(lower, (uint_t)tablemask, key->kio_station);
	if (ke == NULL)
		return (EINVAL);

	if (key->kio_entry >= (uchar_t)OLD_STRING &&
	    key->kio_entry <= (uchar_t)(OLD_STRING + 15)) {
		strtabindex = key->kio_entry - OLD_STRING;
		bcopy(key->kio_string,
		    lower->kbtrans_keystringtab[strtabindex], KTAB_STRLEN);
		lower->kbtrans_keystringtab[strtabindex][KTAB_STRLEN-1] = '\0';
	}

	entry = key->kio_entry;

	/*
	 * There's nothing we need do with OLD_ISOCHAR.
	 */
	if (entry != OLD_ISOCHAR) {
		if (entry & 0x80) {
			if (entry >= OLD_FA_UMLAUT && entry <= OLD_FA_GRAVE)
				entry = FA_CLASS + (entry & 0x0F) - 9;
			else
				entry =
				    special_old_to_new[entry >> 4 & 0x07]
				    + (entry & 0x0F);
		}
	}

	*ke = entry;

	return (0);
}


/*
 * Map new special codes to old ones.
 * Indexed by (new special code) >> 8; add (new special code) & 0xFF.
 */
static uchar_t   special_new_to_old[] = {
	0,			/* normal */
	OLD_SHIFTKEYS,		/* SHIFTKEYS */
	OLD_BUCKYBITS,		/* BUCKYBITS */
	OLD_FUNNY,		/* FUNNY */
	OLD_FA_UMLAUT,		/* FA_CLASS */
	OLD_STRING,		/* STRING */
	OLD_LEFTFUNC,		/* FUNCKEYS */
};


/*
 * kbtrans_getkey:
 *	Get individual keystation translation as old-style entry.
 */
static int
kbtrans_getkey(struct kbtrans_lower *lower, struct kiockey *key)
{
	int	strtabindex;
	keymap_entry_t	*ke;
	register keymap_entry_t entry;
	struct keyboard *kp;

	kp = lower->kbtrans_keyboard;

	if (key->kio_station >= kp->k_keymap_size)
		return (EINVAL);

	if (lower->kbtrans_keyboard == NULL)
		return (EINVAL);

	switch (key->kio_tablemask) {
	case KIOCABORT1:
		key->kio_station = kp->k_abort1;
		return (0);
	case KIOCABORT1A:
		key->kio_station = kp->k_abort1a;
		return (0);
	case KIOCABORT2:
		key->kio_station = kp->k_abort2;
		return (0);
	}

	ke = kbtrans_find_entry(lower, (uint_t)key->kio_tablemask,
	    key->kio_station);
	if (ke == NULL)
		return (EINVAL);

	entry = *ke;

	if (entry & 0xFF00)
		key->kio_entry =
		    special_new_to_old[(ushort_t)(entry & 0xFF00) >> 8]
		    + (entry & 0x00FF);
	else {
		if (entry & 0x80)
			key->kio_entry = (ushort_t)OLD_ISOCHAR;	/* you lose */
		else
			key->kio_entry = (ushort_t)entry;
	}

	if (entry >= STRING && entry <= (uchar_t)(STRING + 15)) {
		strtabindex = entry - STRING;
		bcopy(lower->kbtrans_keystringtab[strtabindex],
		    key->kio_string, KTAB_STRLEN);
	}
	return (0);
}


/*
 * kbtrans_skey:
 *	Set individual keystation translation from new-style entry.
 */
static int
kbtrans_skey(struct kbtrans_lower *lower, struct kiockeymap *key, cred_t *cr)
{
	int	strtabindex, i;
	keymap_entry_t *ke;
	struct keyboard *kp;

	kp = lower->kbtrans_keyboard;

	if (key->kio_station >= kp->k_keymap_size) {
		return (EINVAL);

	}

	if (lower->kbtrans_keyboard == NULL) {
		return (EINVAL);
	}

	switch (key->kio_tablemask) {
	case KIOCABORT1:
	case KIOCABORT1A:
	case KIOCABORT2:
		i = secpolicy_console(cr);
		if (i != 0)
			return (i);
		switch (key->kio_tablemask) {
		case KIOCABORT1:
			kp->k_abort1 = key->kio_station;
			break;
		case KIOCABORT1A:
			kp->k_abort1a = key->kio_station;
			break;
		case KIOCABORT2:
			kp->k_abort2 = key->kio_station;
			break;
		}
		return (0);
	}

	ke = kbtrans_find_entry(lower, (uint_t)key->kio_tablemask,
	    key->kio_station);
	if (ke == NULL)
		return (EINVAL);

	if (key->kio_entry >= STRING &&
	    key->kio_entry <= (STRING + 15)) {
		strtabindex = key->kio_entry-STRING;
		bcopy(key->kio_string,
		    lower->kbtrans_keystringtab[strtabindex], KTAB_STRLEN);
		lower->kbtrans_keystringtab[strtabindex][KTAB_STRLEN-1] = '\0';
	}

	*ke = key->kio_entry;

	return (0);
}


/*
 * kbtrans_gkey:
 *	Get individual keystation translation as new-style entry.
 */
static int
kbtrans_gkey(struct kbtrans_lower *lower, struct kiockeymap *key)
{
	int	strtabindex;
	keymap_entry_t *ke;
	struct keyboard *kp;

	kp = lower->kbtrans_keyboard;

	if (key->kio_station >= kp->k_keymap_size)
		return (EINVAL);

	if (lower->kbtrans_keyboard == NULL)
		return (EINVAL);

	switch (key->kio_tablemask) {
	case KIOCABORT1:
		key->kio_station = kp->k_abort1;
		return (0);
	case KIOCABORT1A:
		key->kio_station = kp->k_abort1a;
		return (0);
	case KIOCABORT2:
		key->kio_station = kp->k_abort2;
		return (0);
	}

	ke = kbtrans_find_entry(lower, (uint_t)key->kio_tablemask,
	    key->kio_station);
	if (ke == NULL)
		return (EINVAL);

	key->kio_entry = *ke;

	if (key->kio_entry >= STRING &&
	    key->kio_entry <= (STRING + 15)) {
		strtabindex = key->kio_entry-STRING;
		bcopy(lower->kbtrans_keystringtab[strtabindex],
		    key->kio_string, KTAB_STRLEN);
	}
	return (0);
}
