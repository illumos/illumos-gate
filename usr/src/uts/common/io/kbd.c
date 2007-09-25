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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
						/* SunOS-4.0 1.60	*/
/*	From:	SunOS4.0	sundev/kbd.c	*/

/*
 * Keyboard input streams module - handles conversion of up/down codes to
 * ASCII or event format.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/consdev.h>
#include <sys/kbd.h>
#include <sys/kbio.h>
#include <sys/kbdreg.h>
#include <sys/vuid_event.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/policy.h>

#include <sys/modctl.h>
#include <sys/beep.h>
#include <sys/int_limits.h>

static struct streamtab kbd_info;

static struct fmodsw fsw = {
	"kb",
	&kbd_info,
	D_MP | D_MTPERMOD
};

/*
 * Module linkage information for the kernel.
 */

static struct modlstrmod modlstrmod = {
	&mod_strmodops, "streams module for keyboard", &fsw
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlstrmod, NULL
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
 * For now these are shared.
 * These data structures are static (defined in keytables.c) thus
 * there is no need to perform any locking.
 */
extern struct keyboards	keytables[];
extern char keystringtab[16][KTAB_STRLEN];
extern struct compose_sequence_t kb_compose_table[];
extern signed char kb_compose_map[];
extern struct fltaccent_sequence_t kb_fltaccent_table[];
extern uchar_t kb_numlock_table[];

/*
 * This value corresponds approximately to max 10 fingers
 */
static int	kbd_downs_size = 15;

typedef	struct	key_event {
	uchar_t	key_station;	/* Physical key station associated with event */
	Firm_event event;	/* Event that sent out on down */
} Key_event;
struct	kbddata {
	queue_t	*kbdd_readq;
	queue_t *kbdd_writeq;
	mblk_t	*kbdd_iocpending;	/* "ioctl" awaiting buffer */
	mblk_t	*kbdd_replypending;	/* "ioctl" reply awaiting result */
	int	kbdd_flags;		/* random flags */
	bufcall_id_t kbdd_bufcallid;	/* bufcall id */
	timeout_id_t kbdd_rptid;	/* timeout id for kbdrpt() */
	timeout_id_t kbdd_layoutid;	/* timeout id for kbdlayout() */
	int	kbdd_iocid;		/* ID of "ioctl" being waited for */
	int	kbdd_iocerror;		/* error return from "ioctl" */
	struct	keyboardstate kbdd_state;
					/*
					 * State of keyboard & keyboard
					 * specific settings, e.g., tables
					 */
	int	kbdd_translate;		/* Translate keycodes? */
	int	kbdd_translatable;	/* Keyboard is translatable? */
	int	kbdd_compat;		/* Generating pre-4.1 events? */
	short	kbdd_ascii_addr;	/* Vuid_id_addr for ascii events */
	short	kbdd_top_addr;		/* Vuid_id_addr for top events */
	short	kbdd_vkey_addr;		/* Vuid_id_addr for vkey events */
	struct	key_event *kbdd_downs;
					/*
					 * Table of key stations currently down
					 * that have firm events that need
					 * to be matched with up transitions
					 * when kbdd_translate is TR_*EVENT
					 */
	int	kbdd_downs_entries; /* # of possible entries in kbdd_downs */
	uint_t	kbdd_downs_bytes; /* # of bytes allocated for kbdd_downs */
	ushort_t compose_key;		/* first compose key */
	ushort_t fltaccent_entry;	/* floating accent keymap entry */
	char	led_state;		/* current state of LEDs */
	unsigned char shiftkey;		/* used for the new abort keys */
};

#define	KBD_OPEN	0x00000001 /* keyboard is open for business */
#define	KBD_IOCWAIT	0x00000002 /* "open" waiting for "ioctl" to finish */

#define	NO_HARD_RESET	0		/* don't do hard reset */
#define	HARD_RESET	1		/* do hard reset */


/*
 * Constants setup during the first open of a kbd (so that they can be patched
 * for debugging purposes).
 */
static int kbd_repeatrate;
static int kbd_repeatdelay;

static int kbd_overflow_cnt;	/* Number of times kbd overflowed input q */
static int kbd_overflow_msg = 1; /* Whether to print message on q overflow */

#ifdef	KBD_DEBUG
int	kbd_debug = 0;
int	kbd_ra_debug = 0;
int	kbd_raw_debug = 0;
int	kbd_rpt_debug = 0;
int	kbd_input_debug = 0;
#endif	/* KBD_DEBUG */

static int	kbdopen(queue_t *, dev_t *, int, int, cred_t *);
static int	kbdclose(queue_t *, int, cred_t *);
static void	kbdwput(queue_t *, mblk_t *);
static void	kbdrput(queue_t *, mblk_t *);

static struct module_info kbdmiinfo = {
	0,
	"kb",
	0,
	INFPSZ,
	2048,
	128
};

static struct qinit kbdrinit = {
	(int (*)())kbdrput,
	(int (*)())NULL,
	kbdopen,
	kbdclose,
	(int (*)())NULL,
	&kbdmiinfo
};

static struct module_info kbdmoinfo = {
	0,
	"kb",
	0,
	INFPSZ,
	2048,
	128
};

static struct qinit kbdwinit = {
	(int (*)())kbdwput,
	(int (*)())NULL,
	kbdopen,
	kbdclose,
	(int (*)())NULL,
	&kbdmoinfo
};

static struct streamtab kbd_info = {
	&kbdrinit,
	&kbdwinit,
	NULL,
	NULL,
};

static void	kbdreioctl(void *);
static void	kbdioctl(queue_t *, mblk_t *);
static void	kbdflush(struct kbddata *);
static void	kbduse(struct kbddata *, unsigned);
static void	kbdsetled(struct kbddata *);
static void	kbd_beep_off(void *arg);
static void	kbd_beep_on(void *arg);
static void	kbdcmd(queue_t *, char);
static void	kbdreset(struct kbddata *, uint_t);
static int	kbdsetkey(struct kbddata *, struct kiockey *,  cred_t *);
static int	kbdgetkey(struct kbddata *, struct kiockey *);
static int	kbdskey(struct kbddata *, struct kiockeymap *,  cred_t *);
static int	kbdgkey(struct kbddata *, struct kiockeymap *);
static void	kbdlayouttimeout(void *);
static void	kbdinput(struct kbddata *, unsigned);
static void	kbdid(struct kbddata *, int);
static struct	keymap *settable(struct kbddata *, uint_t);
static void	kbdrpt(void *);
static void	kbdcancelrpt(struct kbddata *);
static void	kbdtranslate(struct kbddata *, unsigned, queue_t *);
static int	kbd_do_compose(ushort_t, ushort_t, ushort_t *);
static void	kbd_send_esc_event(char, struct kbddata *);
char		*strsetwithdecimal(char *, uint_t, uint_t);
static void	kbdkeypressed(struct kbddata *, uchar_t, Firm_event *,
								ushort_t);
static void	kbdqueuepress(struct kbddata *, uchar_t, Firm_event *);
static void	kbdkeyreleased(struct kbddata *, uchar_t);
static void	kbdreleaseall(struct kbddata *);
static void	kbdputcode(uint_t, queue_t *);
static void	kbdputbuf(char *, queue_t *);
static void	kbdqueueevent(struct kbddata *, Firm_event *);

/*
 * Dummy qbufcall callback routine used by open and close.
 * The framework will wake up qwait_sig when we return from
 * this routine (as part of leaving the perimeters.)
 * (The framework enters the perimeters before calling the qbufcall() callback
 * and leaves the perimeters after the callback routine has executed. The
 * framework performs an implicit wakeup of any thread in qwait/qwait_sig
 * when it leaves the perimeter. See qwait(9E).)
 */
/* ARGSUSED */
static void dummy_callback(void *arg)
{}


/*
 * Open a keyboard.
 * Ttyopen sets line characteristics
 */
/* ARGSUSED */
static int
kbdopen(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *crp)
{
	register int  error;
	register struct	kbddata *kbdd;
	mblk_t *mp;
	mblk_t *datap;
	register struct iocblk *iocb;
	register struct termios *cb;

	/* Set these up only once so that they could be changed from adb */
	if (!kbd_repeatrate) {
		kbd_repeatrate = (hz+29)/30;
		kbd_repeatdelay = hz/2;
	}

	if (q->q_ptr != NULL)
		return (0);		/* already attached */

	/*
	 * Only allow open requests to succeed for privileged users.  This
	 * necessary to prevent users from pushing the "kb" module again
	 * on the stream associated with /dev/kbd.
	 */
	if (secpolicy_console(crp) != 0) {
		return (EPERM);
	}


	switch (sflag) {

	case MODOPEN:
		break;

	case CLONEOPEN:
		return (EINVAL);	/* No Bozos! */
	}

	/* allocate keyboard */

	kbdd = kmem_zalloc(sizeof (struct kbddata), KM_SLEEP);


	/*
	 * Set up queue pointers, so that the "put" procedure will accept
	 * the reply to the "ioctl" message we send down.
	 */
	q->q_ptr = kbdd;
	WR(q)->q_ptr = kbdd;

	qprocson(q);

	/*
	 * Setup tty modes.
	 */
	while ((mp = mkiocb(TCSETSF)) == NULL) {
		timeout_id_t id = qbufcall(q, sizeof (struct iocblk), BPRI_HI,
		    dummy_callback, NULL);
		if (!qwait_sig(q)) {
			qunbufcall(q, id);
			kmem_free(kbdd, sizeof (struct kbddata));
			qprocsoff(q);

			return (EINTR);
		}
	}
	while ((datap = allocb(sizeof (struct termios), BPRI_HI)) ==
	    NULL) {
		timeout_id_t id = qbufcall(q, sizeof (struct termios), BPRI_HI,
		    dummy_callback, NULL);
		if (!qwait_sig(q)) {
			qunbufcall(q, id);
			freemsg(mp);
			kmem_free(kbdd, sizeof (struct kbddata));
			qprocsoff(q);

			return (EINTR);
		}
	}

	iocb		= (struct iocblk *)mp->b_rptr;
	iocb->ioc_count	= sizeof (struct termios);

	cb = (struct termios *)datap->b_rptr;
	cb->c_iflag = 0;
	cb->c_oflag = 0;
	cb->c_cflag = CREAD|CS8|B1200;
	cb->c_lflag = 0;
	bzero(cb->c_cc, NCCS);
	datap->b_wptr += sizeof (struct termios);
	mp->b_cont = datap;
	kbdd->kbdd_flags |= KBD_IOCWAIT;	/* indicate that we're */
	kbdd->kbdd_iocid = iocb->ioc_id;	/* waiting for this response */
	putnext(WR(q), mp);

	/*
	 * Now wait for it.  Let our read queue put routine wake us up
	 * when it arrives.
	 */
	while (kbdd->kbdd_flags & KBD_IOCWAIT) {
		if (!qwait_sig(q)) {
			error = EINTR;
			goto error;
		}
	}
	if ((error = kbdd->kbdd_iocerror) != 0)
		goto error;

	/*
	 * Set up private data.
	 */
	kbdd->kbdd_readq = q;
	kbdd->kbdd_writeq = WR(q);
	kbdd->kbdd_iocpending = NULL;
	kbdd->kbdd_translatable = TR_CAN;
	kbdd->kbdd_translate = TR_ASCII;
	kbdd->kbdd_compat = 1;
	kbdd->kbdd_ascii_addr = ASCII_FIRST;
	kbdd->kbdd_top_addr = TOP_FIRST;
	kbdd->kbdd_vkey_addr = VKEY_FIRST;
	/* Allocate dynamic memory for downs table */
	kbdd->kbdd_downs_entries = kbd_downs_size;
	kbdd->kbdd_downs_bytes = kbd_downs_size * sizeof (Key_event);
	kbdd->kbdd_downs = kmem_alloc(kbdd->kbdd_downs_bytes, KM_SLEEP);
	kbdd->kbdd_flags = KBD_OPEN;
	kbdd->led_state = 0;

	/*
	 * Reset kbd.
	 */
	kbdreset(kbdd, HARD_RESET);

	(void) beep_init((void *)WR(q), kbd_beep_on, kbd_beep_off, NULL);

	return (0);

error:
	qprocsoff(q);
	kmem_free(kbdd, sizeof (struct kbddata));
	return (error);
}

/*
 * Close a keyboard.
 */
/* ARGSUSED1 */
static int
kbdclose(register queue_t *q, int flag, cred_t *crp)
{
	register struct kbddata *kbdd = (struct kbddata *)q->q_ptr;
	register mblk_t *mp;

	qprocsoff(q);
	(void) beep_fini();
	/*
	 * Since we're about to destroy our private data, turn off
	 * our open flag first, so we don't accept any more input
	 * and try to use that data.
	 */
	kbdd->kbdd_flags = 0;

	if ((mp = kbdd->kbdd_replypending) != NULL) {
		/*
		 * There was a KIOCLAYOUT pending; presumably, it timed out.
		 * Throw the reply away.
		 */
		kbdd->kbdd_replypending = NULL;
		freemsg(mp);
	}

	/* clear all timeouts */
	if (kbdd->kbdd_bufcallid)
		qunbufcall(q, kbdd->kbdd_bufcallid);
	if (kbdd->kbdd_rptid)
		(void) quntimeout(q, kbdd->kbdd_rptid);
	if (kbdd->kbdd_layoutid)
		(void) quntimeout(q, kbdd->kbdd_layoutid);
	kmem_free(kbdd->kbdd_downs, kbdd->kbdd_downs_bytes);
	kmem_free(kbdd, sizeof (struct kbddata));
	return (0);
}

/*
 * Line discipline output queue put procedure: handles M_IOCTL
 * messages.
 */
static void
kbdwput(register queue_t *q, register mblk_t *mp)
{
	/*
	 * Process M_FLUSH, and some M_IOCTL, messages here; pass
	 * everything else down.
	 */
	switch (mp->b_datap->db_type) {

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(q, FLUSHDATA);
		if (*mp->b_rptr & FLUSHR)
			flushq(RD(q), FLUSHDATA);

	default:
		putnext(q, mp);	/* pass it down the line */
		break;

	case M_IOCTL:
		kbdioctl(q, mp);
		break;
	}
}


static void
kbdreioctl(void *kbdd_addr)
{
	struct kbddata *kbdd = kbdd_addr;
	queue_t *q;
	mblk_t *mp;

	kbdd->kbdd_bufcallid = 0;
	q = kbdd->kbdd_writeq;
	if ((mp = kbdd->kbdd_iocpending) != NULL) {
		kbdd->kbdd_iocpending = NULL;	/* not pending any more */
		kbdioctl(q, mp);
	}
}

static void
kbdioctl(register queue_t *q, register mblk_t *mp)
{
	register struct kbddata *kbdd = (struct kbddata *)q->q_ptr;
	register struct iocblk *iocp;
	register short	new_translate;
	register Vuid_addr_probe *addr_probe;
	register short	*addr_ptr;
	mblk_t *datap;
	size_t	ioctlrespsize;
	int	err = 0;
	int	tmp;
	int	cycles;
	int	frequency;
	int	msecs;

	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {

	case VUIDSFORMAT:
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;

		new_translate = (*(int *)mp->b_cont->b_rptr == VUID_NATIVE) ?
		    TR_ASCII : TR_EVENT;
		if (new_translate == kbdd->kbdd_translate)
			break;
		kbdd->kbdd_translate = new_translate;
		goto output_format_change;

	case KIOCTRANS:
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;

		new_translate = *(int *)mp->b_cont->b_rptr;
		if (new_translate == kbdd->kbdd_translate)
			break;
		kbdd->kbdd_translate = new_translate;
		goto output_format_change;

	case KIOCCMD:
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;

		tmp = (char)(*(int *)mp->b_cont->b_rptr);
		if (tmp == KBD_CMD_BELL)
			(void) beeper_on(BEEP_TYPE4);
		else if (tmp == KBD_CMD_NOBELL)
			(void) beeper_off();
		else
			kbdcmd(q, tmp);
		break;

	case KIOCMKTONE:
		if (iocp->ioc_count != TRANSPARENT) {
			/*
			 * We don't support non-transparent ioctls,
			 * i.e. I_STR ioctls
			 */
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

	case KIOCSLED:
		err = miocpullup(mp, sizeof (uchar_t));
		if (err != 0)
			break;

		kbdd->led_state = *(uchar_t *)mp->b_cont->b_rptr;
		kbdsetled(kbdd);
		break;

	case KIOCGLED:
		if ((datap = allocb(sizeof (uchar_t), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(uchar_t *)datap->b_wptr = kbdd->led_state;
		datap->b_wptr += sizeof (uchar_t);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (uchar_t);
		break;

	case VUIDGFORMAT:
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr =
		    (kbdd->kbdd_translate == TR_EVENT ||
		    kbdd->kbdd_translate == TR_UNTRANS_EVENT) ?
		    VUID_FIRM_EVENT: VUID_NATIVE;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCGTRANS:
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = kbdd->kbdd_translate;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case VUIDSADDR:
		err = miocpullup(mp, sizeof (Vuid_addr_probe));
		if (err != 0)
			break;

		addr_probe = (Vuid_addr_probe *)mp->b_cont->b_rptr;
		switch (addr_probe->base) {

		case ASCII_FIRST:
			addr_ptr = &kbdd->kbdd_ascii_addr;
			break;

		case TOP_FIRST:
			addr_ptr = &kbdd->kbdd_top_addr;
			break;

		case VKEY_FIRST:
			addr_ptr = &kbdd->kbdd_vkey_addr;
			break;

		default:
			err = ENODEV;
		}
		if ((err == 0) && (*addr_ptr != addr_probe->data.next)) {
			*addr_ptr = addr_probe->data.next;
			goto output_format_change;
		}
		break;

	case VUIDGADDR:
		err = miocpullup(mp, sizeof (Vuid_addr_probe));
		if (err != 0)
			break;

		addr_probe = (Vuid_addr_probe *)mp->b_cont->b_rptr;
		switch (addr_probe->base) {

		case ASCII_FIRST:
			addr_probe->data.current = kbdd->kbdd_ascii_addr;
			break;

		case TOP_FIRST:
			addr_probe->data.current = kbdd->kbdd_top_addr;
			break;

		case VKEY_FIRST:
			addr_probe->data.current = kbdd->kbdd_vkey_addr;
			break;

		default:
			err = ENODEV;
		}
		break;

	case KIOCTRANSABLE:
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;

		if (kbdd->kbdd_translatable != *(int *)mp->b_cont->b_rptr) {
			kbdd->kbdd_translatable = *(int *)mp->b_cont->b_rptr;
			kbdreset(kbdd, HARD_RESET);
			goto output_format_change;
		}
		break;

	case KIOCGTRANSABLE:
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = kbdd->kbdd_translatable;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCSCOMPAT:
		err = miocpullup(mp, sizeof (int));
		if (err != 0)
			break;

		kbdd->kbdd_compat = *(int *)mp->b_cont->b_rptr;
		break;

	case KIOCGCOMPAT:
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = kbdd->kbdd_compat;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont)  /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCSETKEY:
		err = miocpullup(mp, sizeof (struct kiockey));
		if (err != 0)
			break;

		err = kbdsetkey(kbdd, (struct kiockey *)mp->b_cont->b_rptr,
		    iocp->ioc_cr);
		/*
		 * Since this only affects any subsequent key presses,
		 * don't goto output_format_change.  One might want to
		 * toggle the keytable entries dynamically.
		 */
		break;

	case KIOCGETKEY:
		err = miocpullup(mp, sizeof (struct kiockey));
		if (err != 0)
			break;

		err = kbdgetkey(kbdd, (struct kiockey *)mp->b_cont->b_rptr);
		break;

	case KIOCSKEY:
		err = miocpullup(mp, sizeof (struct kiockeymap));
		if (err != 0)
			break;

		err = kbdskey(kbdd, (struct kiockeymap *)mp->b_cont->b_rptr,
		    iocp->ioc_cr);
		/*
		 * Since this only affects any subsequent key presses,
		 * don't goto output_format_change.  One might want to
		 * toggle the keytable entries dynamically.
		 */
		break;

	case KIOCGKEY:
		err = miocpullup(mp, sizeof (struct kiockeymap));
		if (err != 0)
			break;

		err = kbdgkey(kbdd, (struct kiockeymap *)mp->b_cont->b_rptr);
		break;

	case KIOCSDIRECT:
		goto output_format_change;

	case KIOCGDIRECT:
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
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = kbdd->kbdd_state.k_id;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont) /* free msg to prevent memory leak */
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		break;

	case KIOCLAYOUT:
		if ((datap = kbdd->kbdd_replypending) != NULL) {
			/*
			 * There was an earlier KIOCLAYOUT pending; presumably,
			 * it timed out.  Throw the reply away.
			 */
			kbdd->kbdd_replypending = NULL;
			freemsg(datap);
		}

		if (kbdd->kbdd_state.k_id == KB_SUN4 ||
		    kbdd->kbdd_state.k_id == KB_PC) {
			if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
				ioctlrespsize = sizeof (int);
				goto allocfailure;
			}
			iocp->ioc_rval = 0;
			iocp->ioc_error = 0;	/* brain rot */
			iocp->ioc_count = sizeof (int);
			if (mp->b_cont)   /* free msg to prevent memory leak */
				freemsg(mp->b_cont);
			mp->b_cont = datap;
			mp->b_datap->db_type = M_IOCACK;
			kbdd->kbdd_replypending = mp;
			kbdcmd(q, (char)KBD_CMD_GETLAYOUT);
			if (kbdd->kbdd_layoutid)
				(void) quntimeout(q, kbdd->kbdd_layoutid);
			kbdd->kbdd_layoutid = qtimeout(q, kbdlayouttimeout,
			    kbdd, hz / 5);
			return;		/* wait for reply from keyboard */
		} else {
			/*
			 * Not a Type 4 keyboard; return an immediate error.
			 */
			err = EINVAL;
			break;
		}

	case KIOCGRPTDELAY:
		/*
		 * Report the autorepeat delay, unit in millisecond
		 */
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = TICK_TO_MSEC(kbd_repeatdelay);
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
		err = miocpullup(mp, sizeof (int));

		if (err != 0)
			break;

		/* validate the input */
		if (*(int *)mp->b_cont->b_rptr < KIOCRPTDELAY_MIN) {
			err = EINVAL;
			break;
		}
		kbd_repeatdelay = MSEC_TO_TICK(*(int *)mp->b_cont->b_rptr);
		if (kbd_repeatdelay <= 0)
			kbd_repeatdelay = 1;
		break;

	case KIOCGRPTRATE:
		/*
		 * Report the autorepeat rate
		 */
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		*(int *)datap->b_wptr = TICK_TO_MSEC(kbd_repeatrate);
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
		err = miocpullup(mp, sizeof (int));

		if (err != 0)
			break;

		/* validate the input */
		if (*(int *)mp->b_cont->b_rptr < KIOCRPTRATE_MIN) {
			err = EINVAL;
			break;
		}
		kbd_repeatrate = MSEC_TO_TICK(*(int *)mp->b_cont->b_rptr);
		if (kbd_repeatrate <= 0)
			kbd_repeatrate = 1;
		break;

	default:
		putnext(q, mp);	/* pass it down the line */
		return;
	}
	goto done;

output_format_change:
	kbdflush(kbdd);

done:
	if (err != 0) {
		iocp->ioc_rval = 0;
		iocp->ioc_error = err;
		mp->b_datap->db_type = M_IOCNAK;
	} else {
		iocp->ioc_rval = 0;
		iocp->ioc_error = 0;	/* brain rot */
		mp->b_datap->db_type = M_IOCACK;
	}
	qreply(q, mp);
	return;

allocfailure:
	/*
	 * We needed to allocate something to handle this "ioctl", but
	 * couldn't; save this "ioctl" and arrange to get called back when
	 * it's more likely that we can get what we need.
	 * If there's already one being saved, throw it out, since it
	 * must have timed out.
	 */
	if (kbdd->kbdd_iocpending != NULL)
		freemsg(kbdd->kbdd_iocpending);
	kbdd->kbdd_iocpending = mp;
	if (kbdd->kbdd_bufcallid)
		qunbufcall(q, kbdd->kbdd_bufcallid);
	kbdd->kbdd_bufcallid = qbufcall(q, ioctlrespsize, BPRI_HI,
	    kbdreioctl, kbdd);
}

static void
kbdflush(register struct kbddata *kbdd)
{
	register queue_t *q;

	/* Flush pending data already sent upstream */
	if ((q = kbdd->kbdd_readq) != NULL && q->q_next != NULL)
		(void) putnextctl1(q, M_FLUSH, FLUSHR);
	/* Flush pending ups */
	bzero(kbdd->kbdd_downs, kbdd->kbdd_downs_bytes);
	kbdcancelrpt(kbdd);
}

/*
 * Pass keycode upstream, either translated or untranslated.
 */
static void
kbduse(register struct kbddata *kbdd, unsigned keycode)
{
	register queue_t *readq;

#ifdef	KBD_DEBUG
	if (kbd_input_debug) printf("KBD USE key=%d\n", keycode);
#endif

	if ((readq = kbdd->kbdd_readq) == NULL)
		return;
	if (!kbdd->kbdd_translatable ||
	    kbdd->kbdd_translate == TR_NONE)
		kbdputcode(keycode, readq);
	else
		kbdtranslate(kbdd, keycode, readq);
}

static void
kbd_beep_on(void *arg)
{
	kbdcmd((queue_t *)arg, KBD_CMD_BELL);
}


static void
kbd_beep_off(void *arg)
{
	kbdcmd((queue_t *)arg, KBD_CMD_NOBELL);
}


/*
 * kbdclick is used to remember the current click value of the
 * Sun-3 keyboard.  This brain damaged keyboard will reset the
 * clicking to the "default" value after a reset command and
 * there is no way to read out the current click value.  We
 * cannot send a click command immediately after the reset
 * command or the keyboard gets screwed up.  So we wait until
 * we get the ID byte before we send back the click command.
 * Unfortunately, this means that there is a small window
 * where the keyboard can click when it really shouldn't be.
 * A value of -1 means that kbdclick has not been initialized yet.
 */
static int kbdclick = -1;

/*
 * Send command byte to keyboard, if you can.
 */
static void
kbdcmd(register queue_t *q, char cmd)
{
	register mblk_t *bp;

	if (canput(q)) {
		if ((bp = allocb(1, BPRI_MED)) == NULL)
			cmn_err(CE_WARN,
			    "kbdcmd: Can't allocate block for command");
		else {
			*bp->b_wptr++ = cmd;
			putnext(q, bp);
			if (cmd == KBD_CMD_NOCLICK)
				kbdclick = 0;
			else if (cmd == KBD_CMD_CLICK)
				kbdclick = 1;
		}
	}
}

/*
 * Update the keyboard LEDs to match the current keyboard state.
 * Do this only on Type 4 keyboards; other keyboards don't support the
 * KBD_CMD_SETLED command (nor, for that matter, the appropriate LEDs).
 */
static void
kbdsetled(register struct kbddata *kbdd)
{
	if (kbdd->kbdd_state.k_id == KB_SUN4 ||
	    kbdd->kbdd_state.k_id == KB_PC) {
		kbdcmd(kbdd->kbdd_writeq, KBD_CMD_SETLED);
		kbdcmd(kbdd->kbdd_writeq, kbdd->led_state);
	}
}

/*
 * Reset the keyboard
 */
static void
kbdreset(register struct kbddata *kbdd, uint_t hard_reset)
{
	register struct keyboardstate *k;

	k = &kbdd->kbdd_state;
	if (kbdd->kbdd_translatable) {
		k->k_idstate = KID_NONE;
		k->k_id = -1;
		k->k_state = NORMAL;
		if (hard_reset)
			kbdcmd(kbdd->kbdd_writeq, KBD_CMD_RESET);
	} else {
		bzero(k, sizeof (struct keyboardstate));
		k->k_id = KB_ASCII;
		k->k_idstate = KID_OK;
	}
}

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
static ushort_t	special_old_to_new[] = {
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
 * Set individual keystation translation from old-style entry.
 * TODO: Have each keyboard own own translation tables.
 */
static int
kbdsetkey(register struct kbddata *kbdd, struct kiockey *key, cred_t *cr)
{
	int	strtabindex, i;
	struct	keymap *km;
	register int tablemask;
	register ushort_t entry;

	if (key->kio_station >= KEYMAP_SIZE)
		return (EINVAL);
	if (kbdd->kbdd_state.k_curkeyboard == NULL)
		return (EINVAL);
	tablemask = key->kio_tablemask;
	if (tablemask == KIOCABORT1) {
		if (secpolicy_console(cr) != 0)
			return (EPERM);
		kbdd->kbdd_state.k_curkeyboard->k_abort1 = key->kio_station;
		return (0);
	}
	if (tablemask == KIOCABORT2) {
		if (secpolicy_console(cr) != 0)
			return (EPERM);
		kbdd->kbdd_state.k_curkeyboard->k_abort2 = key->kio_station;
		return (0);
	}
	if ((tablemask & ALTGRAPHMASK) ||
	    (km = settable(kbdd, (uint_t)tablemask)) == NULL)
		return (EINVAL);
	if (key->kio_entry >= (uchar_t)OLD_STRING &&
	    key->kio_entry <= (uchar_t)(OLD_STRING + 15)) {
		strtabindex = key->kio_entry - OLD_STRING;
		for (i = 0; i < KTAB_STRLEN; i++)
			keystringtab[strtabindex][i] = key->kio_string[i];
		keystringtab[strtabindex][KTAB_STRLEN-1] = '\0';
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
	km->keymap[key->kio_station] = entry;
	return (0);
}

/*
 * Map new special codes to old ones.
 * Indexed by (new special code) >> 8; add (new special code) & 0xFF.
 */
static uchar_t	special_new_to_old[] = {
	0,			/* normal */
	OLD_SHIFTKEYS,		/* SHIFTKEYS */
	OLD_BUCKYBITS,		/* BUCKYBITS */
	OLD_FUNNY,		/* FUNNY */
	OLD_FA_UMLAUT,		/* FA_CLASS */
	OLD_STRING,		/* STRING */
	OLD_LEFTFUNC,		/* FUNCKEYS */
};

/*
 * Get individual keystation translation as old-style entry.
 */
static int
kbdgetkey(register struct kbddata *kbdd, struct	kiockey *key)
{
	int	strtabindex, i;
	struct	keymap *km;
	register ushort_t entry;

	if (key->kio_station >= KEYMAP_SIZE)
		return (EINVAL);
	if (kbdd->kbdd_state.k_curkeyboard == NULL)
		return (EINVAL);
	if (key->kio_tablemask == KIOCABORT1) {
		key->kio_station = kbdd->kbdd_state.k_curkeyboard->k_abort1;
		return (0);
	}
	if (key->kio_tablemask == KIOCABORT2) {
		key->kio_station = kbdd->kbdd_state.k_curkeyboard->k_abort2;
		return (0);
	}
	if ((km = settable(kbdd, (uint_t)key->kio_tablemask)) == NULL)
		return (EINVAL);
	entry = km->keymap[key->kio_station];
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
		for (i = 0; i < KTAB_STRLEN; i++)
			key->kio_string[i] = keystringtab[strtabindex][i];
	}
	return (0);
}

/*
 * Set individual keystation translation from new-style entry.
 * TODO: Have each keyboard own own translation tables.
 */
static int
kbdskey(register struct kbddata *kbdd, struct kiockeymap *key, cred_t *cr)
{
	int	strtabindex, i;
	struct	keymap *km;

	if (key->kio_station >= KEYMAP_SIZE)
		return (EINVAL);
	if (kbdd->kbdd_state.k_curkeyboard == NULL)
		return (EINVAL);
	if (key->kio_tablemask == KIOCABORT1) {
		if (secpolicy_console(cr) != 0)
			return (EPERM);
		kbdd->kbdd_state.k_curkeyboard->k_abort1 = key->kio_station;
		return (0);
	}
	if (key->kio_tablemask == KIOCABORT2) {
		if (secpolicy_console(cr) != 0)
			return (EPERM);
		kbdd->kbdd_state.k_curkeyboard->k_abort2 = key->kio_station;
		return (0);
	}
	if ((km = settable(kbdd, (uint_t)key->kio_tablemask)) == NULL)
		return (EINVAL);
	if (key->kio_entry >= STRING &&
	    key->kio_entry <= (ushort_t)(STRING + 15)) {
		strtabindex = key->kio_entry-STRING;
		for (i = 0; i < KTAB_STRLEN; i++)
			keystringtab[strtabindex][i] = key->kio_string[i];
		keystringtab[strtabindex][KTAB_STRLEN-1] = '\0';
	}
	km->keymap[key->kio_station] = key->kio_entry;
	return (0);
}

/*
 * Get individual keystation translation as new-style entry.
 */
static int
kbdgkey(register struct kbddata *kbdd, struct	kiockeymap *key)
{
	int	strtabindex, i;
	struct	keymap *km;

	if (key->kio_station >= KEYMAP_SIZE)
		return (EINVAL);
	if (kbdd->kbdd_state.k_curkeyboard == NULL)
		return (EINVAL);
	if (key->kio_tablemask == KIOCABORT1) {
		key->kio_station = kbdd->kbdd_state.k_curkeyboard->k_abort1;
		return (0);
	}
	if (key->kio_tablemask == KIOCABORT2) {
		key->kio_station = kbdd->kbdd_state.k_curkeyboard->k_abort2;
		return (0);
	}
	if ((km = settable(kbdd, (uint_t)key->kio_tablemask)) == NULL)
		return (EINVAL);
	key->kio_entry = km->keymap[key->kio_station];
	if (key->kio_entry >= STRING &&
	    key->kio_entry <= (ushort_t)(STRING + 15)) {
		strtabindex = key->kio_entry-STRING;
		for (i = 0; i < KTAB_STRLEN; i++)
			key->kio_string[i] = keystringtab[strtabindex][i];
	}
	return (0);
}

static void
kbdlayouttimeout(void *arg)
{
	struct kbddata *kbdd = arg;
	mblk_t *mp;

	kbdd->kbdd_layoutid = 0;

	/*
	 * Timed out waiting for reply to "get keyboard layout" command.
	 * Return an ETIME error.
	 */
	if ((mp = kbdd->kbdd_replypending) != NULL) {
		kbdd->kbdd_replypending = NULL;
		mp->b_datap->db_type = M_IOCNAK;
		((struct iocblk *)mp->b_rptr)->ioc_error = ETIME;
		putnext(kbdd->kbdd_readq, mp);
	}
}

/*
 * Put procedure for input from driver end of stream (read queue).
 */
static void
kbdrput(register queue_t *q, register mblk_t *mp)
{
	struct kbddata *kbdd = (struct kbddata *)q->q_ptr;
	register mblk_t *bp;
	register uchar_t *readp;
	struct iocblk *iocp;

	if (kbdd == 0) {
		freemsg(mp);	/* nobody's listening */
		return;
	}

	switch (mp->b_datap->db_type) {

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(WR(q), FLUSHDATA);
		if (*mp->b_rptr & FLUSHR)
			flushq(q, FLUSHDATA);

	default:
		putnext(q, mp);
		return;

	case M_BREAK:
		/*
		 * Will get M_BREAK only if this is not the system
		 * keyboard, otherwise serial port will eat break
		 * and call kmdb/OBP, without passing anything up.
		 */
		freemsg(mp);
		return;

	case M_IOCACK:
	case M_IOCNAK:
		/*
		 * If we are doing an "ioctl" ourselves, check if this
		 * is the reply to that code.  If so, wake up the
		 * "open" routine, and toss the reply, otherwise just
		 * pass it up.
		 */
		iocp = (struct iocblk *)mp->b_rptr;
		if (!(kbdd->kbdd_flags & KBD_IOCWAIT) ||
		    iocp->ioc_id != kbdd->kbdd_iocid) {
			/*
			 * This isn't the reply we're looking for.  Move along.
			 */
			if (kbdd->kbdd_flags & KBD_OPEN)
				putnext(q, mp);
			else
				freemsg(mp);	/* not ready to listen */
		} else {
			kbdd->kbdd_flags &= ~KBD_IOCWAIT;
			kbdd->kbdd_iocerror = iocp->ioc_error;
			freemsg(mp);
		}
		return;

	case M_DATA:
		if (!(kbdd->kbdd_flags & KBD_OPEN)) {
			freemsg(mp);	/* not read to listen */
			return;
		}
		break;
	}

	/*
	 * A data message, consisting of bytes from the keyboard.
	 * Ram them through our state machine.
	 */
	bp = mp;

	do {
		readp = bp->b_rptr;
		while (readp < bp->b_wptr)
			kbdinput(kbdd, *readp++);
		bp->b_rptr = readp;
	} while ((bp = bp->b_cont) != NULL);	/* next block, if any */

	freemsg(mp);
}

/*
 * A keypress was received. Process it through the state machine
 * to check for aborts.
 */
static void
kbdinput(register struct kbddata *kbdd, register unsigned key)
{
	register struct keyboardstate *k;
	register mblk_t *mp;

	k = &kbdd->kbdd_state;
#ifdef	KBD_DEBUG
	if (kbd_input_debug)
		printf("kbdinput key %x\n", key);
#endif

	switch (k->k_idstate) {

	case KID_NONE:
		if (key == RESETKEY) {
			k->k_idstate = KID_GOT_PREFACE;
		} else  {
			kbdreset(kbdd, HARD_RESET);
			/* allows hot plug of kbd after booting without kbd */
		}
		return;

	case KID_GOT_PREFACE:
		kbdid(kbdd, (int)key);

		/*
		 * We just did a reset command to a Type 3 or Type 4
		 * keyboard which sets the click back to the default
		 * (which is currently ON!).  We use the kbdclick
		 * variable to see if the keyboard should be turned on
		 * or off.  If it has not been set, then we use the
		 * keyboard-click? property.
		 */
		switch (kbdclick) {
		case 0:
			kbdcmd(kbdd->kbdd_writeq, KBD_CMD_NOCLICK);
			break;
		case 1:
			kbdcmd(kbdd->kbdd_writeq, KBD_CMD_CLICK);
			break;
		case -1:
		default:
			{
				char wrkbuf[8];
				int len;

				kbdcmd(kbdd->kbdd_writeq, KBD_CMD_NOCLICK);

				bzero(wrkbuf, 8);
				len = 7;
				if (ddi_getlongprop_buf(DDI_DEV_T_ANY,
				    ddi_root_node(), 0, "keyboard-click?",
				    (caddr_t)wrkbuf, &len) ==
				    DDI_PROP_SUCCESS &&
				    len > 0 && len < 8) {
					if (strcmp(wrkbuf, "true") == 0) {
						kbdcmd(kbdd->kbdd_writeq,
						    KBD_CMD_CLICK);
					}
				}
			}
			break;
		}
		/*
		 * A keyboard reset clears the LEDs.
		 * Restore the LEDs from the last value we set
		 * them to.
		 */
		kbdsetled(kbdd);
		return;

	case KID_OK:
		switch (key) {

#if	defined(KBD_PRESSED_PREFIX)
		case KBD_PRESSED_PREFIX:
			k->k_idstate = KID_GOT_PRESSED;
			return;
#endif

#if	defined(KBD_RELEASED_PREFIX)
		case KBD_RELEASED_PREFIX:
			k->k_idstate = KID_GOT_RELEASED;
			return;
#endif

		case 0:
			kbdreset(kbdd, HARD_RESET);
			return;

		/*
		 * we want to check for ID only if we are in
		 * translatable mode.
		 */
		case RESETKEY:
			kbdreset(kbdd, NO_HARD_RESET);
			if (k->k_idstate == KID_NONE) {
				k->k_idstate = KID_GOT_PREFACE;
			}
			return;

		case LAYOUTKEY:
			k->k_idstate = KID_GOT_LAYOUT;
			return;
		}
		break;

#if	defined(KBD_PRESSED_PREFIX)
	case KID_GOT_PRESSED:
		key = BUILDKEY(key, PRESSED);
		k->k_idstate = KID_OK;
		break;
#endif
#if	defined(KBD_RELEASED_PREFIX)
	case KID_GOT_RELEASED:
		key = BUILDKEY(key, RELEASED);
		k->k_idstate = KID_OK;
		break;
#endif

	case KID_GOT_LAYOUT:
		if (kbdd->kbdd_layoutid)
			(void) quntimeout(kbdd->kbdd_readq,
			    kbdd->kbdd_layoutid);
		if ((mp = kbdd->kbdd_replypending) != NULL) {
			kbdd->kbdd_replypending = NULL;
			*(int *)mp->b_cont->b_wptr = key;
			mp->b_cont->b_wptr += sizeof (int);
			putnext(kbdd->kbdd_readq, mp);
		}
		k->k_idstate = KID_OK;
		return;
	}

	switch (k->k_state) {

#if defined(__sparc)
	normalstate:
		k->k_state = NORMAL;
		/* FALLTHRU */
#endif
	case NORMAL:
#if defined(__sparc)
		if (k->k_curkeyboard) {
			if (key == k->k_curkeyboard->k_abort1) {
				k->k_state = ABORT1;
				break;
			}
			if ((key == k->k_curkeyboard->k_newabort1) ||
			    (key == k->k_curkeyboard->k_newabort1a)) {
				k->k_state = NEWABORT1;
				kbdd->shiftkey = key;
			}
		}
#endif
		kbduse(kbdd, key);
		break;

#if defined(__sparc)
	case ABORT1:
		if (k->k_curkeyboard) {
			/*
			 * Only recognize this as an abort sequence if
			 * the "hardware" console is set to be this device.
			 */
			if (key == k->k_curkeyboard->k_abort2 &&
			    rconsvp == wsconsvp) {
				DELAY(100000);
				abort_sequence_enter((char *)NULL);
				k->k_state = NORMAL;
				kbduse(kbdd, IDLEKEY);	/* fake */
				return;
			} else {
				kbduse(kbdd, k->k_curkeyboard->k_abort1);
				goto normalstate;
			}
		}
		break;
	case NEWABORT1:
		if (k->k_curkeyboard) {
			/*
			 * Only recognize this as an abort sequence if
			 * the "hardware" console is set to be this device.
			 */
			if (key == k->k_curkeyboard->k_newabort2 &&
			    rconsvp == wsconsvp) {
				DELAY(100000);
				abort_sequence_enter((char *)NULL);
				k->k_state = NORMAL;
				kbdd->shiftkey |= RELEASED;
				kbduse(kbdd, kbdd->shiftkey);
				kbduse(kbdd, IDLEKEY);	/* fake */
				return;
			} else {
				goto normalstate;
			}
		}
		break;
#endif

	case COMPOSE1:
	case COMPOSE2:
	case FLTACCENT:
		if (key != IDLEKEY)
			kbduse(kbdd, key);
		break;
	}
}

static void
kbdid(register struct kbddata *kbdd, int id)
{
	register struct keyboardstate *k;
	int	i;

	k = &kbdd->kbdd_state;

	k->k_idstate = KID_OK;
	k->k_shiftmask = 0;
	k->k_buckybits = 0;

	/*
	 * Reset k_rptkey to IDLEKEY. We need to cancel
	 * the autorepeat feature, if any.
	 */
	if (k->k_rptkey != IDLEKEY) {
		if (kbdd->kbdd_rptid)
			(void) quntimeout(kbdd->kbdd_readq, kbdd->kbdd_rptid);
		kbdd->kbdd_rptid = 0;
		k->k_rptkey = IDLEKEY;
	}

	k->k_curkeyboard = NULL;
	for (i = 0; keytables[i].table; i++) {
		if (keytables[i].id == id) {
			k->k_id = id;
			k->k_curkeyboard = keytables[i].table;
			break;
		}
	}
	if (!k->k_curkeyboard) {
		k->k_id = keytables[0].id;
		k->k_curkeyboard = keytables[0].table;
		cmn_err(CE_WARN, "kbd: Unknown keyboard type, "
		    "Type %d assumed", k->k_id);
	}
}

/*
 * This routine determines which table we should look in to decode
 * the current keycode.
 */
static struct keymap *
settable(register struct kbddata *kbdd, register uint_t mask)
{
	register struct keyboard *kp;

	kp = kbdd->kbdd_state.k_curkeyboard;
	if (kp == NULL)
		return (NULL);
	if (mask & UPMASK)
		return (kp->k_up);
	if (mask & NUMLOCKMASK)
		return (kp->k_numlock);
	if (mask & CTRLMASK)
		return (kp->k_control);
	if (mask & ALTGRAPHMASK)
		return (kp->k_altgraph);
	if (mask & SHIFTMASK)
		return (kp->k_shifted);
	if (mask & CAPSMASK)
		return (kp->k_caps);
	return (kp->k_normal);
}

static void
kbdrpt(void *arg)
{
	struct kbddata *kbdd = arg;
	struct keyboardstate *k;

	k = &kbdd->kbdd_state;
#ifdef	KBD_DEBUG
	if (kbd_rpt_debug)
		printf("kbdrpt key %x\n", k->k_rptkey);
#endif
	kbdd->kbdd_rptid = 0;

	kbdkeyreleased(kbdd, KEYOF(k->k_rptkey));
	kbduse(kbdd, k->k_rptkey);
	if (k->k_rptkey != IDLEKEY) {
		kbdd->kbdd_rptid = qtimeout(kbdd->kbdd_readq, kbdrpt,
		    kbdd, kbd_repeatrate);
	}
}

static void
kbdcancelrpt(register struct kbddata *kbdd)
{
	register struct keyboardstate *k;

	k = &kbdd->kbdd_state;
	if (k->k_rptkey != IDLEKEY) {
		if (kbdd->kbdd_rptid)
			(void) quntimeout(kbdd->kbdd_readq, kbdd->kbdd_rptid);
		kbdd->kbdd_rptid = 0;
		k->k_rptkey = IDLEKEY;
	}
	ASSERT(kbdd->kbdd_rptid == 0);
}

static void
kbdtranslate(struct kbddata *kbdd, unsigned keycode, queue_t *q)
{
	register uchar_t key;
	register unsigned newstate;
	unsigned shiftmask;
	register ushort_t entry, entrytype;
	register char *cp, *bufp;
	register struct keyboardstate *k;
	ushort_t result_iso;
	struct keymap *km;
	Firm_event fe;
	int i, ret_val;
	char buf[14];

	k = &kbdd->kbdd_state;
	newstate = STATEOF(keycode);
	key = KEYOF(keycode);

#ifdef	KBD_DEBUG
	if (kbd_input_debug) {
		printf("KBD TRANSLATE keycode=0x%x newstate=0x%x key=0x%x\n",
		    keycode, newstate, key);
	}
#endif

	if (kbdd->kbdd_translate == TR_UNTRANS_EVENT) {
		if (newstate == PRESSED) {
			bzero(&fe, sizeof (fe));
			fe.id = key;
			fe.value = 1;
			kbdqueuepress(kbdd, key, &fe);
		} else {
			kbdkeyreleased(kbdd, key);
		}
		return;
	}

	shiftmask = k->k_shiftmask;
	if (newstate == RELEASED)
		shiftmask |= UPMASK;

	km = settable(kbdd, shiftmask);
	if (km == NULL) {		/* gross error */
		kbdcancelrpt(kbdd);
		return;
	}

	if (key >= KEYMAP_SIZE)
		return;
	entry = km->keymap[key];

	if (entry == NONL) {
		/*
		 * NONL appears only in the Num Lock table, and indicates that
		 * this key is not affected by Num Lock.  This means we should
		 * ask for the table we would have gotten had Num Lock not been
		 * down, and translate using that table.
		 */
		km = settable(kbdd, shiftmask & ~NUMLOCKMASK);
		if (km == NULL) {		/* gross error */
			kbdcancelrpt(kbdd);
			return;
		}
		entry = km->keymap[key];
	}
	entrytype = (ushort_t)(entry & 0xFF00) >> 8;

	if (entrytype == (SHIFTKEYS >> 8)) {
		/*
		 * Handle the state of toggle shifts specially.
		 * Ups should be ignored, and downs should be mapped to ups if
		 * that shift is currently on.
		 */
		if ((1 << (entry & 0x0F)) & k->k_curkeyboard->k_toggleshifts) {
			if ((1 << (entry & 0x0F)) & k->k_togglemask) {
				newstate = RELEASED;	/* toggling off */
			} else {
				newstate = PRESSED;	/* toggling on */
			}
		}
	} else {
		/*
		 * Handle Compose and floating accent key sequences
		 */
		if (k->k_state == COMPOSE1) {
			if (newstate == RELEASED)
				return;
			if (entry < ASCII_SET_SIZE) {
				if (kb_compose_map[entry] >= 0) {
					kbdd->compose_key = entry;
					k->k_state = COMPOSE2;
					return;
				}
			}
			k->k_state = NORMAL;
			kbdd->led_state &= ~LED_COMPOSE;
			kbdsetled(kbdd);
			return;
		} else if (k->k_state == COMPOSE2) {
			if (newstate == RELEASED)
				return;
			k->k_state = NORMAL;	/* next state is "normal" */
			kbdd->led_state &= ~LED_COMPOSE;
			kbdsetled(kbdd);
			if (entry < ASCII_SET_SIZE) {
				if (kb_compose_map[entry] >= 0) {
					if (kbdd->compose_key <= entry) {
						ret_val = kbd_do_compose(
						    kbdd->compose_key,
						    entry,
						    &result_iso);
					} else {
						ret_val = kbd_do_compose(
						    entry,
						    kbdd->compose_key,
						    &result_iso);
					}
					if (ret_val == 1) {
						if (kbdd->kbdd_translate ==
						    TR_EVENT) {
							fe.id =
							    (kbdd->kbdd_compat ?
							    ISO_FIRST :
							    EUC_FIRST)
							    + result_iso;
							fe.value = 1;
							kbdqueueevent(
							    kbdd,
							    &fe);
						} else if (
						    kbdd->kbdd_translate ==
						    TR_ASCII)
							kbdputcode(
							    result_iso,
							    q);
					}
				}
			}
			return;
		} else if (k->k_state == FLTACCENT) {
			if (newstate == RELEASED)
				return;
			k->k_state = NORMAL;	/* next state is "normal" */
			for (i = 0;
			    (kb_fltaccent_table[i].fa_entry
			    != kbdd->fltaccent_entry) ||
			    (kb_fltaccent_table[i].ascii != entry);
			    i++) {
				if (kb_fltaccent_table[i].fa_entry == 0)
					/* Invalid second key: ignore key */
					return;
			}
			if (kbdd->kbdd_translate == TR_EVENT) {
				fe.id = (kbdd->kbdd_compat ?
				    ISO_FIRST : EUC_FIRST)
				    + kb_fltaccent_table[i].iso;
				fe.value = 1;
				kbdqueueevent(kbdd, &fe);
			} else if (kbdd->kbdd_translate == TR_ASCII)
				kbdputcode(kb_fltaccent_table[i].iso, q);
			return;
		}
	}

	/*
	 * If the key is going down, and it's not one of the keys that doesn't
	 * auto-repeat, set up the auto-repeat timeout.
	 *
	 * The keys that don't auto-repeat are the Compose key,
	 * the shift keys, the "bucky bit" keys, the "floating accent" keys,
	 * and the function keys when in TR_EVENT mode.
	 */
	if (newstate == PRESSED && entrytype != (SHIFTKEYS >> 8) &&
	    entrytype != (BUCKYBITS >> 8) && entrytype != (FUNNY >> 8) &&
	    entrytype != (FA_CLASS >> 8) &&
	    !((entrytype == (FUNCKEYS >> 8) || entrytype == (PADKEYS >> 8)) &&
	    kbdd->kbdd_translate == TR_EVENT)) {
		if (k->k_rptkey != keycode) {
			kbdcancelrpt(kbdd);
			kbdd->kbdd_rptid = qtimeout(q, kbdrpt, kbdd,
			    kbd_repeatdelay);
			k->k_rptkey = keycode;
		}
	} else if (key == KEYOF(k->k_rptkey))		/* key going up */
		kbdcancelrpt(kbdd);
	if ((newstate == RELEASED) && (kbdd->kbdd_translate == TR_EVENT))
		kbdkeyreleased(kbdd, key);

	/*
	 * We assume here that keys other than shift keys and bucky keys have
	 * entries in the "up" table that cause nothing to be done, and thus we
	 * don't have to check for newstate == RELEASED.
	 */
	switch (entrytype) {

	case 0x0:		/* regular key */
		switch (kbdd->kbdd_translate) {

		case TR_EVENT:
			fe.id = entry | k->k_buckybits;
			fe.value = 1;
			kbdkeypressed(kbdd, key, &fe, entry);
			break;

		case TR_ASCII:
			kbdputcode(entry | k->k_buckybits, q);
			break;
		}
		break;

	case SHIFTKEYS >> 8: {
		uint_t shiftbit = 1 << (entry & 0x0F);

		/* Modify toggle state (see toggle processing above) */
		if (shiftbit & k->k_curkeyboard->k_toggleshifts) {
			if (newstate == RELEASED) {
				if (shiftbit == CAPSMASK) {
					kbdd->led_state &= ~LED_CAPS_LOCK;
					kbdsetled(kbdd);
				} else if (shiftbit == NUMLOCKMASK) {
					kbdd->led_state &= ~LED_NUM_LOCK;
					kbdsetled(kbdd);
				}
				k->k_togglemask &= ~shiftbit;
			} else {
				if (shiftbit == CAPSMASK) {
					kbdd->led_state |= LED_CAPS_LOCK;
					kbdsetled(kbdd);
				} else if (shiftbit == NUMLOCKMASK) {
					kbdd->led_state |= LED_NUM_LOCK;
					kbdsetled(kbdd);
				}
				k->k_togglemask |= shiftbit;
			}
		}

		if (newstate == RELEASED)
			k->k_shiftmask &= ~shiftbit;
		else
			k->k_shiftmask |= shiftbit;

		if (kbdd->kbdd_translate == TR_EVENT && newstate == PRESSED) {
			/*
			 * Relying on ordinal correspondence between
			 * vuid_event.h SHIFT_CAPSLOCK-SHIFT_RIGHTCTRL &
			 * kbd.h CAPSLOCK-RIGHTCTRL in order to
			 * correctly translate entry into fe.id.
			 */
			fe.id = SHIFT_CAPSLOCK + (entry & 0x0F);
			fe.value = 1;
			kbdkeypressed(kbdd, key, &fe, fe.id);
		}
		break;
		}

	case BUCKYBITS >> 8:
		k->k_buckybits ^= 1 << (7 + (entry & 0x0F));
		if (kbdd->kbdd_translate == TR_EVENT && newstate == PRESSED) {
			/*
			 * Relying on ordinal correspondence between
			 * vuid_event.h SHIFT_META-SHIFT_TOP &
			 * kbd.h METABIT-SYSTEMBIT in order to
			 * correctly translate entry into fe.id.
			 */
			fe.id = SHIFT_META + (entry & 0x0F);
			fe.value = 1;
			kbdkeypressed(kbdd, key, &fe, fe.id);
		}
		break;

	case FUNNY >> 8:
		switch (entry) {
		case NOP:
			break;

		case IDLE:
			/* Fall thru into RESET code */
			/* FALLTHRU */
		case RESET:
		gotreset:
			k->k_shiftmask &= k->k_curkeyboard->k_idleshifts;
			k->k_shiftmask |= k->k_togglemask;
			k->k_buckybits &= k->k_curkeyboard->k_idlebuckys;
			kbdcancelrpt(kbdd);
			kbdreleaseall(kbdd);
			break;

		case ERROR:
			cmn_err(CE_WARN, "kbd: Error detected");
			goto gotreset;

		case COMPOSE:
			k->k_state = COMPOSE1;
			kbdd->led_state |= LED_COMPOSE;
			kbdsetled(kbdd);
			break;
		/*
		 * Remember when adding new entries that,
		 * if they should NOT auto-repeat,
		 * they should be put into the IF statement
		 * just above this switch block.
		 */
		default:
			goto badentry;
		}
		break;

	case FA_CLASS >> 8:
		if (k->k_state == NORMAL) {
			kbdd->fltaccent_entry = entry;
			k->k_state = FLTACCENT;
		}
		return;

	case STRING >> 8:
		cp = &keystringtab[entry & 0x0F][0];
		while (*cp != '\0') {
			switch (kbdd->kbdd_translate) {

			case TR_EVENT:
				kbd_send_esc_event(*cp, kbdd);
				break;

			case TR_ASCII:
				kbdputcode((uchar_t)*cp, q);
				break;
			}
			cp++;
		}
		break;

	case FUNCKEYS >> 8:
		switch (kbdd->kbdd_translate) {

		case TR_ASCII:
			bufp = buf;
			cp = strsetwithdecimal(bufp + 2,
			    (uint_t)((entry & 0x003F) + 192),
			    sizeof (buf) - 5);
			*bufp++ = '\033'; /* Escape */
			*bufp++ = '[';
			while (*cp != '\0')
				*bufp++ = *cp++;
			*bufp++ = 'z';
			*bufp = '\0';
			kbdputbuf(buf, q);
			break;

		case TR_EVENT:
			/*
			 * Take advantage of the similar
			 * ordering of kbd.h function keys and
			 * vuid_event.h function keys to do a
			 * simple translation to achieve a
			 * mapping between the 2 different
			 * address spaces.
			 */
			fe.id = (entry & 0x003F) + KEY_LEFTFIRST;
			fe.value = 1;
			/*
			 * Assume "up" table only generates
			 * shift changes.
			 */
			kbdkeypressed(kbdd, key, &fe, fe.id);
			/*
			 * Function key events can be expanded
			 * by terminal emulator software to
			 * produce the standard escape sequence
			 * generated by the TR_ASCII case above
			 * if a function key event is not used
			 * by terminal emulator software
			 * directly.
			 */
			break;
		}
		break;

	/*
	 * Remember when adding new entries that,
	 * if they should NOT auto-repeat,
	 * they should be put into the IF statement
	 * just above this switch block.
	 */
	case PADKEYS >> 8:
		switch (kbdd->kbdd_translate) {

		case TR_ASCII:
			kbdputcode(kb_numlock_table[entry&0x1F], q);
			break;

		case TR_EVENT:
			/*
			 * Take advantage of the similar
			 * ordering of kbd.h keypad keys and
			 * vuid_event.h keypad keys to do a
			 * simple translation to achieve a
			 * mapping between the 2 different
			 * address spaces.
			 */
			fe.id = (entry & 0x001F) + VKEY_FIRSTPAD;
			fe.value = 1;
			/*
			 * Assume "up" table only generates
			 * shift changes.
			 */
			kbdkeypressed(kbdd, key, &fe, fe.id);
			/*
			 * Keypad key events can be expanded
			 * by terminal emulator software to
			 * produce the standard ascii character
			 * generated by the TR_ASCII case above
			 * if a keypad key event is not used
			 * by terminal emulator software
			 * directly.
			 */
			break;
		}

	badentry:
		break;
	}
}

static int
kbd_do_compose(ushort_t first_entry, ushort_t second_entry,
	ushort_t *result_iso_ptr)
{
	struct compose_sequence_t *ptr;

	ptr = &kb_compose_table[kb_compose_map[first_entry]];
	while (ptr->first == first_entry) {
		if (ptr->second == second_entry) {
			*result_iso_ptr = ptr->iso;
			return (1);
		}
		ptr++;
	}
	return (0);
}

static void
kbd_send_esc_event(char c, register struct kbddata *kbdd)
{
	Firm_event fe;

	fe.id = c;
	fe.value = 1;
	fe.pair_type = FE_PAIR_NONE;
	fe.pair = 0;
	/*
	 * Pretend as if each cp pushed and released
	 * Calling kbdqueueevent avoids addr translation
	 * and pair base determination of kbdkeypressed.
	 */
	kbdqueueevent(kbdd, &fe);
	fe.value = 0;
	kbdqueueevent(kbdd, &fe);
}

char *
strsetwithdecimal(char *buf, uint_t val, uint_t maxdigs)
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

static void
kbdkeypressed(struct kbddata *kbdd, uchar_t key_station, Firm_event *fe,
    ushort_t base)
{
	register struct keyboardstate *k;
	register short id_addr;

	/* Set pair values */
	if (fe->id < (ushort_t)VKEY_FIRST) {
		/*
		 * If CTRLed, find the ID that would have been used had it
		 * not been CTRLed.
		 */
		k = &kbdd->kbdd_state;
		if (k->k_shiftmask & (CTRLMASK | CTLSMASK)) {
			struct keymap *km;

			km = settable(kbdd,
			    k->k_shiftmask & ~(CTRLMASK | CTLSMASK | UPMASK));
			if (km == NULL)
				return;
			base = km->keymap[key_station];
		}
		if (base != fe->id) {
			fe->pair_type = FE_PAIR_SET;
			fe->pair = base;
			goto send;
		}
	}
	fe->pair_type = FE_PAIR_NONE;
	fe->pair = 0;
send:
	/* Adjust event id address for multiple keyboard/workstation support */
	switch (vuid_id_addr(fe->id)) {
	case ASCII_FIRST:
		id_addr = kbdd->kbdd_ascii_addr;
		break;
	case TOP_FIRST:
		id_addr = kbdd->kbdd_top_addr;
		break;
	case VKEY_FIRST:
		id_addr = kbdd->kbdd_vkey_addr;
		break;
	default:
		id_addr = vuid_id_addr(fe->id);
	}
	fe->id = vuid_id_offset(fe->id) | id_addr;
	kbdqueuepress(kbdd, key_station, fe);
}

static void
kbdqueuepress(struct kbddata *kbdd, uchar_t key_station, Firm_event *fe)
{
	register struct key_event *ke, *ke_free;
	register int i;

	if (key_station == IDLEKEY)
		return;
#ifdef	KBD_DEBUG
	if (kbd_input_debug) printf("KBD PRESSED key=%d\n", key_station);
#endif
	ke_free = 0;
	/* Scan table of down key stations */
	if (kbdd->kbdd_translate == TR_EVENT ||
	    kbdd->kbdd_translate == TR_UNTRANS_EVENT) {
		for (i = 0, ke = kbdd->kbdd_downs;
		    i < kbdd->kbdd_downs_entries;
		    i++, ke++) {
			/* Keycode already down? */
			if (ke->key_station == key_station) {
#ifdef	KBD_DEBUG
	printf("kbd: Double entry in downs table (%d,%d)!\n", key_station, i);
#endif
				goto add_event;
			}
			if (ke->key_station == 0)
				ke_free = ke;
		}
		if (ke_free) {
			ke = ke_free;
			goto add_event;
		}
		cmn_err(CE_WARN, "kbd: Too many keys down!");
		ke = kbdd->kbdd_downs;
	}
add_event:
	ke->key_station = key_station;
	ke->event = *fe;
	kbdqueueevent(kbdd, fe);
}

static void
kbdkeyreleased(register struct kbddata *kbdd, uchar_t key_station)
{
	register struct key_event *ke;
	register int i;

	if (key_station == IDLEKEY)
		return;
#ifdef	KBD_DEBUG
	if (kbd_input_debug)
		printf("KBD RELEASE key=%d\n", key_station);
#endif
	if (kbdd->kbdd_translate != TR_EVENT &&
	    kbdd->kbdd_translate != TR_UNTRANS_EVENT)
		return;
	/* Scan table of down key stations */
	for (i = 0, ke = kbdd->kbdd_downs;
	    i < kbdd->kbdd_downs_entries;
	    i++, ke++) {
		/* Found? */
		if (ke->key_station == key_station) {
			ke->key_station = 0;
			ke->event.value = 0;
			kbdqueueevent(kbdd, &ke->event);
		}
	}

	/*
	 * Ignore if couldn't find because may be called twice
	 * for the same key station in the case of the kbdrpt
	 * routine being called unnecessarily.
	 */
}

static void
kbdreleaseall(struct kbddata *kbdd)
{
	register struct key_event *ke;
	register int i;

#ifdef	KBD_DEBUG
	if (kbd_debug && kbd_ra_debug) printf("KBD RELEASE ALL\n");
#endif
	/* Scan table of down key stations */
	for (i = 0, ke = kbdd->kbdd_downs;
	    i < kbdd->kbdd_downs_entries; i++, ke++) {
		/* Key station not zero */
		if (ke->key_station)
			kbdkeyreleased(kbdd, ke->key_station);
			/* kbdkeyreleased resets kbdd_downs entry */
	}
}

/*
 * Pass a keycode up the stream, if you can, otherwise throw it away.
 */
static void
kbdputcode(uint_t code, queue_t *q)
{
	register mblk_t *bp;

	if (!canput(q))
		cmn_err(CE_WARN, "kbdputcode: Can't put block for keycode");
	else {
		if ((bp = allocb(sizeof (uint_t), BPRI_HI)) == NULL)
			cmn_err(CE_WARN,
			    "kbdputcode: Can't allocate block for keycode");
		else {
			*bp->b_wptr++ = code;
			putnext(q, bp);
		}
	}
}

/*
 * Pass  generated keycode sequence to upstream, if possible.
 */
static void
kbdputbuf(char *buf, queue_t *q)
{
	register mblk_t *bp;

	if (!canput(q))
		cmn_err(CE_WARN, "kbdputbuf: Can't put block for keycode");
	else {
		if ((bp = allocb((int)strlen(buf), BPRI_HI)) == NULL)
			cmn_err(CE_WARN,
			    "kbdputbuf: Can't allocate block for keycode");
		else {
			while (*buf) {
				*bp->b_wptr++ = *buf;
				buf++;
			}
			putnext(q, bp);
		}
	}
}

/*
 * Pass a VUID "firm event" up the stream, if you can.
 */
static void
kbdqueueevent(struct kbddata *kbdd, Firm_event *fe)
{
	register queue_t *q;
	register mblk_t *bp;

	if ((q = kbdd->kbdd_readq) == NULL)
		return;
	if (!canput(q)) {
		if (kbd_overflow_msg)
			cmn_err(CE_WARN,
			    "kbd: Buffer flushed when overflowed");
		kbdflush(kbdd);
		kbd_overflow_cnt++;
	} else {
		if ((bp = allocb(sizeof (Firm_event), BPRI_HI)) == NULL)
			cmn_err(CE_WARN,
			    "kbdqueueevent: Can't allocate block for event");
		else {
#if 1 /* XX64 */
			struct timeval now;

			/*
			 * XX64: This is something of a compromise.  It
			 * seems justifiable based on the usage of these
			 * timestamps as an ordering relation as opposed
			 * to a strict timing thing.
			 *
			 * But should we restore Firm_event's time stamp
			 * to be a timeval, and send 32-bit and 64-bit
			 * events up the pipe?
			 */
			uniqtime(&now);
			TIMEVAL_TO_TIMEVAL32(&fe->time, &now);
#else
			uniqtime(&fe->time);
#endif
			*(Firm_event *)bp->b_wptr = *fe;
			bp->b_wptr += sizeof (Firm_event);
			putnext(q, bp);
		}
	}
}
