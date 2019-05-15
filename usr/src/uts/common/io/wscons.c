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
 * Copyright (c) 1987, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Toomas Soome <tsoome@me.com>
 * Copyright 2019 Joyent, Inc.
 */

/*
 * "Workstation console" multiplexor driver for Sun.
 *
 * Sends output to the primary frame buffer using the PROM monitor;
 * gets input from a stream linked below us that is the "keyboard
 * driver", below which is linked the primary keyboard.
 */

/*
 * Locking Policy:
 * This module has a D_MTPERMOD inner perimeter which means STREAMS
 * only allows one thread to enter this module through STREAMS entry
 * points each time -- open() close() put() srv() qtimeout().
 * So for the most time we do not need locking in this module, but with
 * the following exceptions:
 *
 *   - wc shares three global variables (wc_dip, vc_active_console,
 *     vc_cons_user, vc_avl_root) with virtual console devname part
 *    (fs/dev/sdev_vtops.c) which get compiled into genunix.
 *
 *   - wc_modechg_cb() is a callback function which will triggered when
 *     framebuffer display mode is changed.
 *
 *   - vt_send_hotkeys() is triggered by timeout() which is not STREAMS MT
 *     safe.
 *
 * Based on the fact that virtual console devname part and wc_modechg_cb()
 * only do read access to the above mentioned shared four global variables,
 * It is safe to do locking this way:
 * 1) all read access to the four global variables in THIS WC MODULE do not
 *    need locking;
 * 2) all write access to the four global variables in THIS WC MODULE must
 *    hold vc_lock;
 * 3) any access to the four global variables in either DEVNAME PART or the
 *    CALLBACK must hold vc_lock;
 * 4) other global variables which are only shared in this wc module and only
 *    accessible through STREAMS entry points such as "vc_last_console",
 *    "vc_inuse_max_minor", "vc_target_console" and "vc_waitactive_list"
 *    do not need explict locking.
 *
 * wc_modechg_cb() does read access to vc_state_t::vc_flags,
 * vc_state_t::vc_state_lock is used to protect concurrently accesses to
 * vc_state_t::vc_flags which may happen from both through STREAMS entry
 * points and wc_modechg_cb().
 * Since wc_modechg_cb() only does read access to vc_state_t::vc_flags,
 * The other parts of wc module (except wc_modechg_cb()) only has to hold
 * vc_state_t::vc_flags when writing to vc_state_t::vc_flags.
 *
 * vt_send_hotkeys() could access vt_pending_vtno at the same time with
 * the rest of wc module, vt_pending_vtno_lock is used to protect
 * vt_pending_vtno.
 *
 * Lock order: vc_lock -> vc_state_t::vc_state_lock.
 * No overlap between vc_lock and vt_pending_vtno_lock.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/ttold.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/tty.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/procset.h>
#include <sys/fault.h>
#include <sys/siginfo.h>
#include <sys/debug.h>
#include <sys/session.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/kbio.h>
#include <sys/strredir.h>
#include <sys/fs/snode.h>
#include <sys/consdev.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/console.h>
#include <sys/promif.h>
#include <sys/note.h>
#include <sys/polled_io.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/sunldi.h>
#include <sys/debug.h>
#include <sys/console.h>
#include <sys/ddi_impldefs.h>
#include <sys/policy.h>
#include <sys/modctl.h>
#include <sys/tem.h>
#include <sys/wscons.h>
#include <sys/vt_impl.h>

/* streams stuff */
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", copyreq))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", copyresp))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", datab))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", msgb))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", queue))

#define	MINLINES	10
#define	MAXLINES	48
#define	LOSCREENLINES	34
#define	HISCREENLINES	48

#define	MINCOLS		10
#define	MAXCOLS		120
#define	LOSCREENCOLS	80
#define	HISCREENCOLS	120

struct wscons_state {
	dev_t	wc_dev;			/* major/minor for this device */
#ifdef _HAVE_TEM_FIRMWARE
	int	wc_defer_output;	/* set if output device is "slow" */
#endif /* _HAVE_TEM_FIRMWARE */
	queue_t	*wc_kbdqueue;		/* "console keyboard" device queue */
					/* below us */
	cons_polledio_t		wc_polledio; /* polled I/O function pointers */
	cons_polledio_t		*wc_kb_polledio; /* keyboard's polledio */
	unsigned int	wc_kb_getpolledio_id; /* id for kb CONSOPENPOLLEDIO */
	queue_t *wc_pending_wq;
	mblk_t	*wc_pending_link;	/* I_PLINK pending for kb polledio */
} wscons;

/*
 * This module has a D_MTPERMOD inner perimeter, so we don't need to protect
 * the variables only shared within this module
 */
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", wscons))
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", wscons_state))
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", vt_stat))
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", vc_waitactive_msg))
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", tty_common))
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", vt_mode))
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", vt_dispinfo))
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", winsize))
_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data", vc_last_console))

#ifdef _HAVE_TEM_FIRMWARE
ssize_t wc_cons_wrtvec(promif_redir_arg_t arg, uchar_t *s, size_t n);
#endif /* _HAVE_TEM_FIRMWARE */

static int	wcopen(queue_t *, dev_t *, int, int, cred_t *);
static int	wcclose(queue_t *, int, cred_t *);
static int	wcuwsrv(queue_t *);
static int	wcuwput(queue_t *, mblk_t *);
static int	wclrput(queue_t *, mblk_t *);

static struct module_info wcm_info = {
	0,
	"wc",
	0,
	INFPSZ,
	2048,
	128
};

static struct qinit wcurinit = {
	putq,
	NULL,
	wcopen,
	wcclose,
	NULL,
	&wcm_info,
	NULL
};

static struct qinit wcuwinit = {
	wcuwput,
	wcuwsrv,
	wcopen,
	wcclose,
	NULL,
	&wcm_info,
	NULL
};

static struct qinit wclrinit = {
	wclrput,
	NULL,
	NULL,
	NULL,
	NULL,
	&wcm_info,
	NULL
};

/*
 * We always putnext directly to the underlying queue.
 */
static struct qinit wclwinit = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&wcm_info,
	NULL
};

static struct streamtab wcinfo = {
	&wcurinit,
	&wcuwinit,
	&wclrinit,
	&wclwinit,
};

static int wc_info(dev_info_t *, ddi_info_cmd_t, void *, void **result);
static int wc_attach(dev_info_t *, ddi_attach_cmd_t);

DDI_DEFINE_STREAM_OPS(wc_ops, nulldev, nulldev, wc_attach, nodev, nodev,
    wc_info, D_MTPERMOD | D_MP, &wcinfo, ddi_quiesce_not_supported);

static void	wcreioctl(void *);
static void	wcioctl(queue_t *, mblk_t *);
#ifdef _HAVE_TEM_FIRMWARE
static void	wcopoll(void *);
#endif /* _HAVE_TEM_FIRMWARE */
static void	wcrstrt(void *);
static void	wc_open_kb_polledio(struct wscons_state *wc, queue_t *q,
		    mblk_t *mp);
static void	wc_close_kb_polledio(struct wscons_state *wc, queue_t *q,
		    mblk_t *mp);
static void	wc_polled_putchar(cons_polledio_arg_t arg,
			unsigned char c);
static boolean_t wc_polled_ischar(cons_polledio_arg_t arg);
static int	wc_polled_getchar(cons_polledio_arg_t arg);
static void	wc_polled_enter(cons_polledio_arg_t arg);
static void	wc_polled_exit(cons_polledio_arg_t arg);
void	wc_get_size(vc_state_t *pvc);
static void	wc_modechg_cb(tem_modechg_cb_arg_t arg);
static tem_vt_state_t wc_get_screen_tem(vc_state_t *);

static struct dev_ops wc_ops;

/*
 * Debug printing
 */
#ifndef DPRINTF
#ifdef DEBUG
/*PRINTFLIKE1*/
static void	wc_dprintf(const char *fmt, ...) __KPRINTFLIKE(1);
#define	DPRINTF(l, m, args) \
	(((l) >= wc_errlevel) && ((m) & wc_errmask) ?	\
		wc_dprintf args :			\
		(void) 0)
/*
 * Severity levels for printing
 */
#define	PRINT_L0	0	/* print every message */
#define	PRINT_L1	1	/* debug */
#define	PRINT_L2	2	/* quiet */

/*
 * Masks
 */
#define	PRINT_MASK_ALL		0xFFFFFFFFU
uint_t	wc_errmask = PRINT_MASK_ALL;
uint_t	wc_errlevel = PRINT_L2;

#else
#define	DPRINTF(l, m, args)	/* NOTHING */
#endif
#endif

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Workstation multiplexer Driver 'wc'",
	&wc_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int rc;
	if ((rc = mod_install(&modlinkage)) == 0)
		vt_init();
	return (rc);
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

/*ARGSUSED*/
static int
wc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	/* create minor node for workstation hard console */
	if (ddi_create_minor_node(devi, "wscons", S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	mutex_enter(&vc_lock);

	wc_dip = devi;

	bzero(&(wscons.wc_polledio), sizeof (wscons.wc_polledio));

	vt_resize(VC_DEFAULT_COUNT);

	mutex_exit(&vc_lock);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
wc_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (wc_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) wc_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static void
wc_init_polledio(void)
{
	static boolean_t polledio_inited = B_FALSE;
	_NOTE(SCHEME_PROTECTS_DATA("D_MTPERMOD protected data",
	    polledio_inited))

	if (polledio_inited)
		return;

	polledio_inited = B_TRUE;

	/*
	 * Initialize the parts of the polled I/O struct that
	 * are common to both input and output modes, but which
	 * don't flag to the upper layers, which if any of the
	 * two modes are available.  We don't know at this point
	 * if system is configured CONS_KFB, but we will when
	 * consconfig_dacf asks us with CONSOPENPOLLED I/O.
	 */
	bzero(&(wscons.wc_polledio), sizeof (wscons.wc_polledio));
	wscons.wc_polledio.cons_polledio_version =
	    CONSPOLLEDIO_V0;
	wscons.wc_polledio.cons_polledio_argument =
	    (cons_polledio_arg_t)&wscons;
	wscons.wc_polledio.cons_polledio_enter =
	    wc_polled_enter;
	wscons.wc_polledio.cons_polledio_exit =
	    wc_polled_exit;

#ifdef _HAVE_TEM_FIRMWARE
	/*
	 * If we're talking directly to a framebuffer, we assume
	 * that it's a "slow" device, so that rendering should
	 * be deferred to a timeout or softcall so that we write
	 * a bunch of characters at once.
	 */
	wscons.wc_defer_output = prom_stdout_is_framebuffer();
#endif /* _HAVE_TEM_FIRMWARE */
}

/*ARGSUSED*/
static int
wcopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	int minor;

	wc_init_polledio();
	minor = (int)getminor(*devp);
	return (vt_open(minor, q, crp));
}

/*ARGSUSED*/
static int
wcclose(queue_t *q, int flag, cred_t *crp)
{
	vc_state_t *pvc = (vc_state_t *)q->q_ptr;

	qprocsoff(q);

	mutex_enter(&vc_lock);

	/*
	 * If we are closing the VT node which
	 * /dev/vt/console_user points to, revert
	 * /dev/vt/console to /dev/console
	 */
	if (vc_cons_user == pvc->vc_minor)
		vc_cons_user = VT_MINOR_INVALID;

	if (pvc->vc_minor == 0 || pvc->vc_minor == vc_active_console) {

		/*
		 * If we lose the system console,
		 * no any other active consoles.
		 */
		if (pvc->vc_minor == 0 && pvc->vc_minor == vc_active_console) {
			vc_active_console = VT_MINOR_INVALID;
			vc_last_console = VT_MINOR_INVALID;
		}

		/*
		 * just clean for our primary console
		 * and active console
		 */
		mutex_enter(&pvc->vc_state_lock);
		vt_clean(q, pvc);
		mutex_exit(&pvc->vc_state_lock);

		mutex_exit(&vc_lock);

		return (0);
	}
	vt_close(q, pvc, crp);

	mutex_exit(&vc_lock);

	return (0);
}

/*
 * Service procedure for upper write queue.
 * We need to have service procedure to make sure the keyboard events
 * are queued up for screen output and are not dependant on the screen
 * updates.
 */
static int
wcuwsrv(queue_t *q)
{
	vc_state_t *pvc = (vc_state_t *)q->q_ptr;
	tem_vt_state_t ptem = NULL;
	mblk_t *mp;
	ssize_t cc;

	while ((mp = getq(q)) != NULL) {
		/*
		 * If we're waiting for something to happen (delay timeout to
		 * expire, current transmission to finish, output to be
		 * restarted, output to finish draining), don't grab anything
		 * new.
		 */
		if (pvc->vc_flags & (WCS_DELAY|WCS_BUSY|WCS_STOPPED)) {
			(void) putbq(q, mp);
			return (0);
		}

		switch (mp->b_datap->db_type) {
		default:	/* drop unknown type */
			freemsg(mp);
			continue;

		case M_IOCTL:
			wcioctl(q, mp);
			continue;

		case M_DELAY:
			/*
			 * Arrange for "wcrstrt" to be called when the
			 * delay expires; it will turn WCS_DELAY off.
			 */
			if (pvc->vc_timeoutid != 0)
				(void) quntimeout(q, pvc->vc_timeoutid);
			pvc->vc_timeoutid = qtimeout(q, wcrstrt, pvc,
			    (clock_t)(*(unsigned char *)mp->b_rptr + 6));

			mutex_enter(&pvc->vc_state_lock);
			pvc->vc_flags |= WCS_DELAY;
			mutex_exit(&pvc->vc_state_lock);

			freemsg(mp);
			continue;

		case M_DATA:
			break;
		}

		if ((cc = mp->b_wptr - mp->b_rptr) == 0) {
			freemsg(mp);
			continue;
		}

#ifdef _HAVE_TEM_FIRMWARE
		if (consmode == CONS_KFB) {
#endif /* _HAVE_TEM_FIRMWARE */
			ptem = wc_get_screen_tem(pvc);

			if (ptem == NULL) {
				freemsg(mp);
				continue;
			}

			for (mblk_t *nbp = mp; nbp != NULL; nbp = nbp->b_cont) {
				cc = nbp->b_wptr - nbp->b_rptr;

				if (cc <= 0)
					continue;

				tem_write(ptem, nbp->b_rptr, cc, kcred);
			}
			freemsg(mp);
#ifdef _HAVE_TEM_FIRMWARE
			continue;
		}

		/* consmode = CONS_FW */
		if (pvc->vc_minor != 0) {
			freemsg(mp);
			continue;
		}

		/*
		 * Direct output to the frame buffer if this device
		 * is not the "hardware" console.
		 */
		if (wscons.wc_defer_output) {
			mutex_enter(&pvc->vc_state_lock);
			pvc->vc_flags |= WCS_BUSY;
			mutex_exit(&pvc->vc_state_lock);

			pvc->vc_pendc = -1;

			for (mblk_t *nbp = mp; nbp != NULL; nbp = nbp->b_cont) {
				cc = nbp->b_wptr - nbp->b_rptr;

				if (cc <= 0)
					continue;

				console_puts((const char *)nbp->b_rptr, cc);
			}
			freemsg(mp);
			mutex_enter(&pvc->vc_state_lock);
			pvc->vc_flags &= ~WCS_BUSY;
			mutex_exit(&pvc->vc_state_lock);
			continue;
		}
		for (boolean_t done = B_FALSE; done != B_TRUE; ) {
			int c;

			c = *mp->b_rptr++;
			cc--;
			if (prom_mayput((char)c) != 0) {

				mutex_enter(&pvc->vc_state_lock);
				pvc->vc_flags |= WCS_BUSY;
				mutex_exit(&pvc->vc_state_lock);

				pvc->vc_pendc = c;
				if (pvc->vc_timeoutid != 0)
					(void) quntimeout(q,
					    pvc->vc_timeoutid);
				pvc->vc_timeoutid = qtimeout(q, wcopoll,
				    pvc, 1);
				if (mp != NULL) {
					/* not done with this message yet */
					(void) putbq(q, mp);
					return (0);
				}
				break;
			}
			while (cc <= 0) {
				mblk_t *nbp = mp;
				mp = mp->b_cont;
				freeb(nbp);
				if (mp == NULL) {
					done = B_TRUE;
					break;
				}
				/* LINTED E_PTRDIFF_OVERFLOW */
				cc = mp->b_wptr - mp->b_rptr;
			}
		}
#endif /* _HAVE_TEM_FIRMWARE */
	}
	return (0);
}

/*
 * Put procedure for upper write queue.
 * Respond to M_STOP, M_START, M_IOCTL, and M_FLUSH messages here;
 * queue up M_BREAK, M_DELAY, and M_DATA messages for processing by
 * the service routine. Discard everything else.
 */
static int
wcuwput(queue_t *q, mblk_t *mp)
{
	vc_state_t *pvc = (vc_state_t *)q->q_ptr;

	switch (mp->b_datap->db_type) {

	case M_STOP:
		mutex_enter(&pvc->vc_state_lock);
		pvc->vc_flags |= WCS_STOPPED;
		mutex_exit(&pvc->vc_state_lock);

		freemsg(mp);
		break;

	case M_START:
		mutex_enter(&pvc->vc_state_lock);
		pvc->vc_flags &= ~WCS_STOPPED;
		mutex_exit(&pvc->vc_state_lock);

		qenable(q);
		freemsg(mp);
		break;

	case M_IOCTL: {
		struct iocblk *iocp;
		struct linkblk *linkp;

		iocp = (struct iocblk *)(void *)mp->b_rptr;
		switch (iocp->ioc_cmd) {

		case I_LINK:	/* stupid, but permitted */
		case I_PLINK:
			if (wscons.wc_kbdqueue != NULL) {
				/* somebody already linked */
				miocnak(q, mp, 0, EINVAL);
				return (0);
			}
			linkp = (struct linkblk *)(void *)mp->b_cont->b_rptr;
			wscons.wc_kbdqueue = WR(linkp->l_qbot);
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_count = 0;
			wc_open_kb_polledio(&wscons, q, mp);
			break;

		case I_UNLINK:	/* stupid, but permitted */
		case I_PUNLINK:
			linkp = (struct linkblk *)(void *)mp->b_cont->b_rptr;
			if (wscons.wc_kbdqueue != WR(linkp->l_qbot)) {
				/* not us */
				miocnak(q, mp, 0, EINVAL);
				return (0);
			}

			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_count = 0;
			wc_close_kb_polledio(&wscons, q, mp);
			break;

		case TCSETSW:
		case TCSETSF:
		case TCSETAW:
		case TCSETAF:
		case TCSBRK:
			/*
			 * The changes do not take effect until all
			 * output queued before them is drained.
			 * Put this message on the queue, so that
			 * "wcuwsrv" will see it when it's done
			 * with the output before it.
			 */
			if (putq(q, mp) == 0)
				freemsg(mp);
			break;

		case CONSSETABORTENABLE:
		case CONSGETABORTENABLE:
		case KIOCSDIRECT:
			if (wscons.wc_kbdqueue != NULL) {
				wscons.wc_pending_wq = q;
				(void) putnext(wscons.wc_kbdqueue, mp);
				break;
			}
			/* fall through */

		default:
			/*
			 * Do it now.
			 */
			wcioctl(q, mp);
			break;
		}
		break;
	}

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			/*
			 * Flush our write queue.
			 */
			flushq(q, FLUSHDATA);	/* XXX doesn't flush M_DELAY */
			*mp->b_rptr &= ~FLUSHW;	/* it has been flushed */
		}
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHDATA);
			qreply(q, mp);	/* give the read queues a crack at it */
		} else
			freemsg(mp);
		break;

	case M_BREAK:
		/*
		 * Ignore these, as they make no sense.
		 */
		freemsg(mp);
		break;

	case M_DELAY:
	case M_DATA:
		/*
		 * Queue the message up to be transmitted.
		 */
		if (putq(q, mp) == 0)
			freemsg(mp);
		break;

	case M_IOCDATA:
		vt_miocdata(q, mp);
		break;

	default:
		/*
		 * "No, I don't want a subscription to Chain Store Age,
		 * thank you anyway."
		 */
		freemsg(mp);
		break;
	}

	return (0);
}

/*
 * Retry an "ioctl", now that "qbufcall" claims we may be able to allocate
 * the buffer we need.
 */
/*ARGSUSED*/
static void
wcreioctl(void *arg)
{
	vc_state_t *pvc = (vc_state_t *)arg;
	queue_t *q;
	mblk_t *mp;

	pvc->vc_bufcallid = 0;
	q = pvc->vc_ttycommon.t_writeq;
	if ((mp = pvc->vc_ttycommon.t_iocpending) != NULL) {
		/* not pending any more */
		pvc->vc_ttycommon.t_iocpending = NULL;
		wcioctl(q, mp);
	}
}

static int
wc_getterm(mblk_t *mp)
{
	char *term;
	intptr_t arg;
	int flag = ((struct iocblk *)(void *)mp->b_rptr)->ioc_flag;

	STRUCT_DECL(cons_getterm, wcterm);
	STRUCT_INIT(wcterm, flag);

	arg = *((intptr_t *)(void *)mp->b_cont->b_rptr);

	if (ddi_copyin((void *)arg, STRUCT_BUF(wcterm),
	    STRUCT_SIZE(wcterm), flag) != 0) {
		return (EFAULT);
	}

	if (consmode == CONS_FW) {
		/* PROM terminal emulator */
		term = "sun";
	} else {
		/* Kernel terminal emulator */
		ASSERT(consmode == CONS_KFB);
		term = "sun-color";
	}

	if (STRUCT_FGET(wcterm, cn_term_len) <
	    strlen(term) + 1) {
		return (EOVERFLOW);
	}

	if (ddi_copyout(term,
	    STRUCT_FGETP(wcterm, cn_term_type),
	    strlen(term) + 1, flag) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * Process an "ioctl" message sent down to us.
 */
static void
wcioctl(queue_t *q, mblk_t *mp)
{
	vc_state_t *pvc = (vc_state_t *)q->q_ptr;
	struct iocblk *iocp;
	size_t datasize;
	int error;
	long len;

	iocp = (struct iocblk *)(void *)mp->b_rptr;

	if ((iocp->ioc_cmd & VTIOC) == VTIOC ||
	    (iocp->ioc_cmd & KDIOC) == KDIOC) {
		vt_ioctl(q, mp);
		return;
	}

	switch (iocp->ioc_cmd) {
	case TIOCSWINSZ:
		/*
		 * Ignore all attempts to set the screen size; the
		 * value in the EEPROM is guaranteed (modulo PROM bugs)
		 * to be the value used by the PROM monitor code, so it
		 * is by definition correct.  Many programs (e.g.,
		 * "login" and "tset") will attempt to reset the size
		 * to (0, 0) or (34, 80), neither of which is
		 * necessarily correct.
		 * We just ACK the message, so as not to disturb
		 * programs that set the sizes.
		 */
		iocp->ioc_count = 0;	/* no data returned */
		mp->b_datap->db_type = M_IOCACK;
		qreply(q, mp);
		return;

	case CONSOPENPOLLEDIO:
		DPRINTF(PRINT_L1, PRINT_MASK_ALL,
		    ("wcioctl: CONSOPENPOLLEDIO\n"));

		error = miocpullup(mp, sizeof (struct cons_polledio *));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		/*
		 * We are given an appropriate-sized data block,
		 * and return a pointer to our structure in it.
		 */
		if (consmode == CONS_KFB)
			wscons.wc_polledio.cons_polledio_putchar =
			    wc_polled_putchar;
		*(struct cons_polledio **)(void *)mp->b_cont->b_rptr =
		    &wscons.wc_polledio;

		mp->b_datap->db_type = M_IOCACK;

		qreply(q, mp);
		break;

	case CONS_GETTERM:
		if ((error = wc_getterm(mp)) != 0)
			miocnak(q, mp, 0, error);
		else
			miocack(q, mp, 0, 0);
		return;

	case WC_OPEN_FB:
		/*
		 * Start out pessimistic, so that we can just jump to
		 * the reply to bail out.
		 */
		mp->b_datap->db_type = M_IOCNAK;

		/*
		 * First test:  really, this should be done only from
		 * inside the kernel.  Unfortunately, that information
		 * doesn't seem to be available in a streams ioctl,
		 * so restrict it to root only.  (Perhaps we could check
		 * for ioc_cr == kcred.)
		 */
		if ((iocp->ioc_error = secpolicy_console(iocp->ioc_cr)) != 0)
			goto open_fail;

		/*
		 * Some miscellaneous checks...
		 */
		iocp->ioc_error = EINVAL;

		/*
		 * If we don't have exactly one continuation block, fail.
		 */
		if (mp->b_cont == NULL ||
		    mp->b_cont->b_cont != NULL)
			goto open_fail;

		/*
		 * If there's no null terminator in the string, fail.
		 */
		/* LINTED E_PTRDIFF_OVERFLOW */
		len = mp->b_cont->b_wptr - mp->b_cont->b_rptr;
		if (memchr(mp->b_cont->b_rptr, 0, len) == NULL)
			goto open_fail;

		/*
		 * NOTE:  should eventually get default
		 * dimensions from a property, e.g. screen-#rows.
		 */
		iocp->ioc_error = tem_info_init((char *)mp->b_cont->b_rptr,
		    iocp->ioc_cr);
		/*
		 * Of course, if the terminal emulator initialization
		 * failed, fail.
		 */
		if (iocp->ioc_error != 0)
			goto open_fail;

#ifdef	_HAVE_TEM_FIRMWARE
		if (prom_stdout_is_framebuffer()) {
			/*
			 * Drivers in the console stream may emit additional
			 * messages before we are ready. This causes text
			 * overwrite on the screen. So we set the redirection
			 * here. It is safe because the ioctl in consconfig_dacf
			 * will succeed and consmode will be set to CONS_KFB.
			 */
			prom_set_stdout_redirect(wc_cons_wrtvec,
			    (promif_redir_arg_t)NULL);

		}
#endif	/* _HAVE_TEM_FIRMWARE */

		tem_register_modechg_cb(wc_modechg_cb,
		    (tem_modechg_cb_arg_t)&wscons);

		/*
		 * ... and succeed.
		 */
		mp->b_datap->db_type = M_IOCACK;

open_fail:
		qreply(q, mp);
		break;

	case WC_CLOSE_FB:
		/*
		 * There's nothing that can call this, so it's not
		 * really implemented.
		 */
		mp->b_datap->db_type = M_IOCNAK;
		/*
		 * However, if it were implemented, it would clearly
		 * be root-only.
		 */
		if ((iocp->ioc_error = secpolicy_console(iocp->ioc_cr)) != 0)
			goto close_fail;

		iocp->ioc_error = EINVAL;

close_fail:
		qreply(q, mp);
		break;

	default:

		/*
		 * The only way in which "ttycommon_ioctl" can fail is
		 * if the "ioctl" requires a response containing data
		 * to be returned to the user, and no mblk could be
		 * allocated for the data.  No such "ioctl" alters our
		 * state.  Thus, we always go ahead and do any
		 * state-changes the "ioctl" calls for.  If we couldn't
		 * allocate the data, "ttycommon_ioctl" has stashed the
		 * "ioctl" away safely, so we just call "qbufcall" to
		 * request that we be called back when we stand a
		 * better chance of allocating the data.
		 */
		datasize = ttycommon_ioctl(&pvc->vc_ttycommon, q, mp, &error);
		if (datasize != 0) {
			if (pvc->vc_bufcallid != 0)
				qunbufcall(q, pvc->vc_bufcallid);
			pvc->vc_bufcallid = qbufcall(q, datasize, BPRI_HI,
			    wcreioctl, pvc);
			return;
		}

		if (error < 0) {
			if (iocp->ioc_cmd == TCSBRK)
				error = 0;
			else
				error = EINVAL;
		}
		if (error != 0) {
			iocp->ioc_error = error;
			mp->b_datap->db_type = M_IOCNAK;
		}
		qreply(q, mp);
		break;
	}
}

/*
 * This function gets the polled I/O structures from the lower
 * keyboard driver.  If any initialization or resource allocation
 * needs to be done by the lower driver, it will be done when
 * the lower driver services this message.
 */
static void
wc_open_kb_polledio(struct wscons_state *wscons, queue_t *q, mblk_t *mp)
{
	mblk_t *mp2;
	struct iocblk *iocp;

	DPRINTF(PRINT_L1, PRINT_MASK_ALL,
	    ("wc_open_kb_polledio: sending CONSOPENPOLLEDIO\n"));

	mp2 = mkiocb(CONSOPENPOLLEDIO);

	if (mp2 == NULL) {
		/*
		 * If we can't get an mblk, then wait for it.
		 */
		goto nomem;
	}

	mp2->b_cont = allocb(sizeof (struct cons_polledio *), BPRI_HI);

	if (mp2->b_cont == NULL) {
		/*
		 * If we can't get an mblk, then wait for it, and release
		 * the mblk that we have already allocated.
		 */
		freemsg(mp2);
		goto nomem;
	}

	iocp = (struct iocblk *)(void *)mp2->b_rptr;

	iocp->ioc_count = sizeof (struct cons_polledio *);
	mp2->b_cont->b_wptr = mp2->b_cont->b_rptr +
	    sizeof (struct cons_polledio *);

	wscons->wc_pending_wq = q;
	wscons->wc_pending_link = mp;
	wscons->wc_kb_getpolledio_id = iocp->ioc_id;

	putnext(wscons->wc_kbdqueue, mp2);

	return;

nomem:
	iocp = (struct iocblk *)(void *)mp->b_rptr;
	iocp->ioc_error = ENOMEM;
	mp->b_datap->db_type = M_IOCNAK;
	qreply(q, mp);
}

/*
 * This function releases the polled I/O structures from the lower
 * keyboard driver.  If any de-initialization needs to be done, or
 * any resources need to be released, it will be done when the lower
 * driver services this message.
 */
static void
wc_close_kb_polledio(struct wscons_state *wscons, queue_t *q, mblk_t *mp)
{
	mblk_t *mp2;
	struct iocblk *iocp;

	DPRINTF(PRINT_L1, PRINT_MASK_ALL,
	    ("wc_close_kb_polledio: sending CONSCLOSEPOLLEDIO\n"));

	mp2 = mkiocb(CONSCLOSEPOLLEDIO);

	if (mp2 == NULL) {
		/*
		 * If we can't get an mblk, then wait for it.
		 */
		goto nomem;
	}

	mp2->b_cont = allocb(sizeof (struct cons_polledio *), BPRI_HI);

	if (mp2->b_cont == NULL) {
		/*
		 * If we can't get an mblk, then wait for it, and release
		 * the mblk that we have already allocated.
		 */
		freemsg(mp2);

		goto nomem;
	}

	iocp = (struct iocblk *)(void *)mp2->b_rptr;

	iocp->ioc_count = 0;

	wscons->wc_pending_wq = q;
	wscons->wc_pending_link = mp;
	wscons->wc_kb_getpolledio_id = iocp->ioc_id;

	putnext(wscons->wc_kbdqueue, mp2);

	return;

nomem:
	iocp = (struct iocblk *)(void *)mp->b_rptr;
	iocp->ioc_error = ENOMEM;
	mp->b_datap->db_type = M_IOCNAK;
	qreply(q, mp);
}

#ifdef _HAVE_TEM_FIRMWARE
/* ARGSUSED */
static void
wcopoll(void *arg)
{
	vc_state_t *pvc = (vc_state_t *)arg;
	queue_t *q;

	q = pvc->vc_ttycommon.t_writeq;
	pvc->vc_timeoutid = 0;

	mutex_enter(&pvc->vc_state_lock);

	/* See if we can continue output */
	if ((pvc->vc_flags & WCS_BUSY) && pvc->vc_pendc != -1) {
		if (prom_mayput((char)pvc->vc_pendc) == 0) {
			pvc->vc_pendc = -1;
			pvc->vc_flags &= ~WCS_BUSY;
			if (!(pvc->vc_flags&(WCS_DELAY|WCS_STOPPED)))
				qenable(q);
		} else
			pvc->vc_timeoutid = qtimeout(q, wcopoll, pvc, 1);
	}

	mutex_exit(&pvc->vc_state_lock);
}
#endif	/* _HAVE_TEM_FIRMWARE */

/*
 * Restart output on the console after a timeout.
 */
/* ARGSUSED */
static void
wcrstrt(void *arg)
{
	vc_state_t *pvc = (vc_state_t *)arg;

	ASSERT(pvc->vc_ttycommon.t_writeq != NULL);

	mutex_enter(&pvc->vc_state_lock);
	pvc->vc_flags &= ~WCS_DELAY;
	mutex_exit(&pvc->vc_state_lock);

	qenable(pvc->vc_ttycommon.t_writeq);
}

/*
 * get screen terminal for current output
 */
static tem_vt_state_t
wc_get_screen_tem(vc_state_t *pvc)
{
	if (!tem_initialized(pvc->vc_tem) ||
	    tem_get_fbmode(pvc->vc_tem) != KD_TEXT)
		return (NULL);

	return (pvc->vc_tem);
}

/*
 * Put procedure for lower read queue.
 * Pass everything up to queue above "upper half".
 */
static int
wclrput(queue_t *q, mblk_t *mp)
{
	vc_state_t *pvc;
	queue_t *upq;
	struct iocblk *iocp;

	pvc = vt_minor2vc(VT_ACTIVE);

	DPRINTF(PRINT_L1, PRINT_MASK_ALL,
	    ("wclrput: wclrput type = 0x%x\n", mp->b_datap->db_type));

	switch (mp->b_datap->db_type) {

	case M_FLUSH:
		if (*mp->b_rptr == FLUSHW || *mp->b_rptr == FLUSHRW) {
			/*
			 * Flush our write queue.
			 */
			/* XXX doesn't flush M_DELAY */
			flushq(WR(q), FLUSHDATA);
			*mp->b_rptr = FLUSHR;	/* it has been flushed */
		}
		if (*mp->b_rptr == FLUSHR || *mp->b_rptr == FLUSHRW) {
			flushq(q, FLUSHDATA);
			*mp->b_rptr = FLUSHW;	/* it has been flushed */
			qreply(q, mp);	/* give the read queues a crack at it */
		} else
			freemsg(mp);
		break;

	case M_DATA:
		if (consmode == CONS_KFB && vt_check_hotkeys(mp)) {
			freemsg(mp);
			break;
		}

		if ((upq = pvc->vc_ttycommon.t_readq) != NULL) {
			if (!canput(upq->q_next)) {
				ttycommon_qfull(&pvc->vc_ttycommon, upq);
				qenable(WR(upq));
				freemsg(mp);
			} else {
				putnext(upq, mp);
			}
		} else
			freemsg(mp);
		break;

	case M_IOCACK:
	case M_IOCNAK:
		iocp = (struct iocblk *)(void *)mp->b_rptr;
		if (wscons.wc_pending_link != NULL &&
		    iocp->ioc_id == wscons.wc_kb_getpolledio_id) {
			switch (mp->b_datap->db_type) {

			case M_IOCACK:
				switch (iocp->ioc_cmd) {

				case CONSOPENPOLLEDIO:
					DPRINTF(PRINT_L1, PRINT_MASK_ALL,
					    ("wclrput: "
					    "ACK CONSOPENPOLLEDIO\n"));
					wscons.wc_kb_polledio =
					    *(struct cons_polledio **)
					    (void *)mp->b_cont->b_rptr;
					wscons.wc_polledio.
					    cons_polledio_getchar =
					    wc_polled_getchar;
					wscons.wc_polledio.
					    cons_polledio_ischar =
					    wc_polled_ischar;
					break;

				case CONSCLOSEPOLLEDIO:
					DPRINTF(PRINT_L1, PRINT_MASK_ALL,
					    ("wclrput: "
					    "ACK CONSCLOSEPOLLEDIO\n"));
					wscons.wc_kb_polledio = NULL;
					wscons.wc_kbdqueue = NULL;
					wscons.wc_polledio.
					    cons_polledio_getchar = NULL;
					wscons.wc_polledio.
					    cons_polledio_ischar = NULL;
					break;
				default:
					DPRINTF(PRINT_L1, PRINT_MASK_ALL,
					    ("wclrput: "
					    "ACK UNKNOWN\n"));
				}

				break;
			case M_IOCNAK:
				/*
				 * Keyboard may or may not support polled I/O.
				 * This ioctl may have been rejected because
				 * we only have the wc->conskbd chain built,
				 * and the keyboard driver has not been linked
				 * underneath conskbd yet.
				 */
				DPRINTF(PRINT_L1, PRINT_MASK_ALL,
				    ("wclrput: NAK\n"));

				switch (iocp->ioc_cmd) {

				case CONSCLOSEPOLLEDIO:
					wscons.wc_kb_polledio = NULL;
					wscons.wc_kbdqueue = NULL;
					wscons.wc_polledio.
					    cons_polledio_getchar = NULL;
					wscons.wc_polledio.
					    cons_polledio_ischar = NULL;
					break;
				}
				break;
			}

			/*
			 * Discard the response, replace it with the
			 * pending response to the I_PLINK, then let it
			 * flow upward.
			 */
			freemsg(mp);
			mp = wscons.wc_pending_link;
			wscons.wc_pending_link = NULL;
			wscons.wc_kb_getpolledio_id = 0;
		}
		/* FALLTHROUGH */

	default:	/* inc M_ERROR, M_HANGUP, M_IOCACK, M_IOCNAK, ... */
		if (wscons.wc_pending_wq != NULL) {
			qreply(wscons.wc_pending_wq, mp);
			wscons.wc_pending_wq = NULL;
			break;
		}

		if ((upq = pvc->vc_ttycommon.t_readq) != NULL) {
			putnext(upq, mp);
		} else {
			DPRINTF(PRINT_L1, PRINT_MASK_ALL,
			    ("wclrput: Message DISCARDED\n"));
			freemsg(mp);
		}
		break;
	}

	return (0);
}

#ifdef _HAVE_TEM_FIRMWARE
/*
 *  This routine exists so that prom_write() can redirect writes
 *  to the framebuffer through the kernel terminal emulator, if
 *  that configuration is selected during consconfig.
 *  When the kernel terminal emulator is enabled, consconfig_dacf
 *  sets up the PROM output redirect vector to enter this function.
 *  During panic the console will already be powered up as part of
 *  calling into the prom_*() layer.
 */
/* ARGSUSED */
ssize_t
wc_cons_wrtvec(promif_redir_arg_t arg, uchar_t *s, size_t n)
{
	vc_state_t *pvc;

	pvc = vt_minor2vc(VT_ACTIVE);

	if (pvc->vc_tem == NULL)
		return (0);

	ASSERT(consmode == CONS_KFB);

	if (panicstr)
		polled_io_cons_write(s, n);
	else
		(void) tem_write(pvc->vc_tem, s, n, kcred);

	return (n);
}
#endif /* _HAVE_TEM_FIRMWARE */

/*
 * These are for systems without OBP, and for devices that cannot be
 * shared between Solaris and the OBP.
 */
static void
wc_polled_putchar(cons_polledio_arg_t arg, unsigned char c)
{
	vc_state_t *pvc;

	pvc = vt_minor2vc(VT_ACTIVE);

	if (c == '\n')
		wc_polled_putchar(arg, '\r');

	if (pvc->vc_tem == NULL) {
		/*
		 * We have no terminal emulator configured.  We have no
		 * recourse but to drop the output on the floor.
		 */
		return;
	}

	tem_safe_polled_write(pvc->vc_tem, &c, 1);
}

/*
 * These are for systems without OBP, and for devices that cannot be
 * shared between Solaris and the OBP.
 */
static int
wc_polled_getchar(cons_polledio_arg_t arg)
{
	struct wscons_state *wscons = (struct wscons_state *)arg;

	if (wscons->wc_kb_polledio == NULL) {
		prom_printf("wscons:  getchar with no keyboard support");
		prom_printf("Halted...");
		for (;;)
			/* HANG FOREVER */;
	}

	return (wscons->wc_kb_polledio->cons_polledio_getchar(
	    wscons->wc_kb_polledio->cons_polledio_argument));
}

static boolean_t
wc_polled_ischar(cons_polledio_arg_t arg)
{
	struct wscons_state *wscons = (struct wscons_state *)arg;

	if (wscons->wc_kb_polledio == NULL)
		return (B_FALSE);

	return (wscons->wc_kb_polledio->cons_polledio_ischar(
	    wscons->wc_kb_polledio->cons_polledio_argument));
}

static void
wc_polled_enter(cons_polledio_arg_t arg)
{
	struct wscons_state *wscons = (struct wscons_state *)arg;

	if (wscons->wc_kb_polledio == NULL)
		return;

	if (wscons->wc_kb_polledio->cons_polledio_enter != NULL) {
		wscons->wc_kb_polledio->cons_polledio_enter(
		    wscons->wc_kb_polledio->cons_polledio_argument);
	}
}

static void
wc_polled_exit(cons_polledio_arg_t arg)
{
	struct wscons_state *wscons = (struct wscons_state *)arg;

	if (wscons->wc_kb_polledio == NULL)
		return;

	if (wscons->wc_kb_polledio->cons_polledio_exit != NULL) {
		wscons->wc_kb_polledio->cons_polledio_exit(
		    wscons->wc_kb_polledio->cons_polledio_argument);
	}
}


#ifdef DEBUG
static void
wc_dprintf(const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	cmn_err(CE_WARN, "wc: %s", buf);
}
#endif

/*ARGSUSED*/
static void
update_property(vc_state_t *pvc, char *name, ushort_t value)
{
	char data[8];

	(void) snprintf(data, sizeof (data), "%u", value);

	(void) ddi_prop_update_string(wscons.wc_dev, wc_dip, name, data);
}

/*
 * Gets the number of text rows and columns and the
 * width and height (in pixels) of the console.
 */
void
wc_get_size(vc_state_t *pvc)
{
	struct winsize *t = &pvc->vc_ttycommon.t_size;
	ushort_t r = LOSCREENLINES, c = LOSCREENCOLS, x = 0, y = 0;

	if (pvc->vc_tem != NULL)
		tem_get_size(&r, &c, &x, &y);
#ifdef _HAVE_TEM_FIRMWARE
	else
		console_get_size(&r, &c, &x, &y);
#endif /* _HAVE_TEM_FIRMWARE */

	mutex_enter(&pvc->vc_ttycommon.t_excl);
	t->ws_col = c;
	t->ws_row = r;
	t->ws_xpixel = x;
	t->ws_ypixel = y;
	mutex_exit(&pvc->vc_ttycommon.t_excl);

	if (pvc->vc_minor != 0)
		return;

	/* only for the wscons:0 */
	update_property(pvc, "screen-#cols",  c);
	update_property(pvc, "screen-#rows",  r);
	update_property(pvc, "screen-width",  x);
	update_property(pvc, "screen-height", y);
}

/*ARGSUSED*/
static void
wc_modechg_cb(tem_modechg_cb_arg_t arg)
{
	minor_t index;
	vc_state_t *pvc;

	mutex_enter(&vc_lock);
	for (index = 0; index < VC_INSTANCES_COUNT; index++) {
		pvc = vt_minor2vc(index);

		mutex_enter(&pvc->vc_state_lock);

		if ((pvc->vc_flags & WCS_ISOPEN) &&
		    (pvc->vc_flags & WCS_INIT))
			wc_get_size(pvc);

		mutex_exit(&pvc->vc_state_lock);
	}
	mutex_exit(&vc_lock);
}
