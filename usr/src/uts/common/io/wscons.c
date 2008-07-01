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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * "Workstation console" multiplexor driver for Sun.
 *
 * Sends output to the primary frame buffer using the PROM monitor;
 * gets input from a stream linked below us that is the "keyboard
 * driver", below which is linked the primary keyboard.
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
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/kbio.h>
#include <sys/strredir.h>
#include <sys/fs/snode.h>
#include <sys/consdev.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/console.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/policy.h>
#include <sys/tem.h>
#include <sys/wscons.h>

#define	MINLINES	10
#define	MAXLINES	48
#define	LOSCREENLINES	34
#define	HISCREENLINES	48

#define	MINCOLS		10
#define	MAXCOLS		120
#define	LOSCREENCOLS	80
#define	HISCREENCOLS	120

struct wscons {
	struct tem *wc_tem;		/* Terminal emulator state */
	int	wc_flags;		/* random flags (protected by */
					/* write-side exclusion lock  */
	dev_t	wc_dev;			/* major/minor for this device */
	tty_common_t wc_ttycommon;	/* data common to all tty drivers */
#ifdef _HAVE_TEM_FIRMWARE
	int	wc_pendc;		/* pending output character */
	int	wc_defer_output;	/* set if output device is "slow" */
#endif /* _HAVE_TEM_FIRMWARE */
	queue_t	*wc_kbdqueue;		/* "console keyboard" device queue */
					/* below us */
	bufcall_id_t wc_bufcallid;	/* id returned by qbufcall */
	timeout_id_t wc_timeoutid;	/* id returned by qtimeout */
	cons_polledio_t		wc_polledio; /* polled I/O function pointers */
	cons_polledio_t		*wc_kb_polledio; /* keyboard's polledio */
	unsigned int	wc_kb_getpolledio_id; /* id for kb CONSOPENPOLLEDIO */
	mblk_t	*wc_pending_link;	/* I_PLINK pending for kb polledio */
} wscons;

#define	WCS_ISOPEN	0x00000001	/* open is complete */
#define	WCS_STOPPED	0x00000002	/* output is stopped */
#define	WCS_DELAY	0x00000004	/* waiting for delay to finish */
#define	WCS_BUSY	0x00000008	/* waiting for transmission to finish */

static int	wcopen(queue_t *, dev_t *, int, int, cred_t *);
static int	wcclose(queue_t *, int, cred_t *);
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
	NULL,
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
static dev_info_t *wc_dip;

DDI_DEFINE_STREAM_OPS(wc_ops, nulldev, nulldev, wc_attach, nodev, nodev,
    wc_info, D_MTPERMOD | D_MP, &wcinfo);

static void	wcreioctl(void *);
static void 	wcioctl(queue_t *, mblk_t *);
#ifdef _HAVE_TEM_FIRMWARE
static void	wcopoll(void *);
static void	wconsout(void *);
#endif /* _HAVE_TEM_FIRMWARE */
static void	wcrstrt(void *);
static void	wcstart(void);
static void	wc_open_kb_polledio(struct wscons *wc, queue_t *q, mblk_t *mp);
static void	wc_close_kb_polledio(struct wscons *wc, queue_t *q, mblk_t *mp);
static void	wc_polled_putchar(cons_polledio_arg_t arg, unsigned char c);
static boolean_t wc_polled_ischar(cons_polledio_arg_t arg);
static int	wc_polled_getchar(cons_polledio_arg_t arg);
static void	wc_polled_enter(cons_polledio_arg_t arg);
static void	wc_polled_exit(cons_polledio_arg_t arg);
static void	wc_get_size(struct wscons *wscons);
static void	wc_modechg_cb(tem_modechg_cb_arg_t arg);

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/modctl.h>

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
	"Workstation multiplexer Driver 'wc' %I%",
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

/*ARGSUSED*/
static int
wc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (ddi_create_minor_node(devi, "wscons", S_IFCHR,
	    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (-1);
	}
	wc_dip = devi;

	bzero(&(wscons.wc_polledio), sizeof (wscons.wc_polledio));

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

#ifdef _HAVE_TEM_FIRMWARE
/*
 * Output buffer. Protected by the per-module inner perimeter.
 */
#define	MAXHIWAT	2000
static char obuf[MAXHIWAT];
#endif /* _HAVE_TEM_FIRMWARE */

/*ARGSUSED*/
static int
wcopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	static boolean_t polledio_inited = B_FALSE;
	struct termios *termiosp;
	int len;

	if (getminor(*devp) != 0)
		return (ENXIO);		/* sorry, only one per customer */

	if (!(wscons.wc_flags & WCS_ISOPEN)) {
		mutex_init(&wscons.wc_ttycommon.t_excl, NULL, MUTEX_DEFAULT,
		    NULL);
		wscons.wc_ttycommon.t_iflag = 0;
		/*
		 * Get the default termios settings (cflag).
		 * These are stored as a property in the
		 * "options" node.
		 */
		if (ddi_getlongprop(DDI_DEV_T_ANY,
		    ddi_root_node(), 0, "ttymodes",
		    (caddr_t)&termiosp, &len) == DDI_PROP_SUCCESS &&
		    len == sizeof (struct termios)) {

			wscons.wc_ttycommon.t_cflag = termiosp->c_cflag;
			kmem_free(termiosp, len);
		} else {
			/*
			 * Gack!  Whine about it.
			 */
			cmn_err(CE_WARN,
			    "wc: Couldn't get ttymodes property!\n");
		}
		wscons.wc_ttycommon.t_iocpending = NULL;
		wscons.wc_flags = WCS_ISOPEN;

		wscons.wc_dev = *devp;
		wc_get_size(&wscons);

		if (!polledio_inited) {
			polledio_inited = B_TRUE;

			/*
			 * Initialize the parts of the polled I/O struct that
			 * are common to both input and output modes, but which
			 * don't flag to the upper layers, which if any of the
			 * two modes are available.  We don't know at this point
			 * if system is configured CONS_KFB, but we will when
			 * consconfig_dacf asks us with CONSOPENPOLLED I/O.
			 */
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
	}

	if (wscons.wc_ttycommon.t_flags & TS_XCLUDE) {
		if (secpolicy_excl_open(crp) != 0) {
			return (EBUSY);
		}
	}
	wscons.wc_ttycommon.t_readq = q;
	wscons.wc_ttycommon.t_writeq = WR(q);
	qprocson(q);
	return (0);
}

/*ARGSUSED*/
static int
wcclose(queue_t *q, int flag, cred_t *crp)
{
	qprocsoff(q);
	if (wscons.wc_bufcallid != 0) {
		qunbufcall(q, wscons.wc_bufcallid);
		wscons.wc_bufcallid = 0;
	}
	if (wscons.wc_timeoutid != 0) {
		(void) quntimeout(q, wscons.wc_timeoutid);
		wscons.wc_timeoutid = 0;
	}
	ttycommon_close(&wscons.wc_ttycommon);
	wscons.wc_flags = 0;
	return (0);
}

/*
 * Put procedure for upper write queue.
 * Respond to M_STOP, M_START, M_IOCTL, and M_FLUSH messages here;
 * queue up M_BREAK, M_DELAY, and M_DATA messages for processing by
 * the start routine, and then call the start routine; discard
 * everything else.
 */
static int
wcuwput(queue_t *q, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {

	case M_STOP:
		wscons.wc_flags |= WCS_STOPPED;
		freemsg(mp);
		break;

	case M_START:
		wscons.wc_flags &= ~WCS_STOPPED;
		wcstart();
		freemsg(mp);
		break;

	case M_IOCTL: {
		struct iocblk *iocp;
		struct linkblk *linkp;

		iocp = (void *)mp->b_rptr;
		switch (iocp->ioc_cmd) {

		case I_LINK:	/* stupid, but permitted */
		case I_PLINK:
			if (wscons.wc_kbdqueue != NULL) {
				/* somebody already linked */
				miocnak(q, mp, 0, EINVAL);
				return (0);
			}
			linkp = (void *)mp->b_cont->b_rptr;
			wscons.wc_kbdqueue = WR(linkp->l_qbot);
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_count = 0;
			wc_open_kb_polledio(&wscons, q, mp);
			break;

		case I_UNLINK:	/* stupid, but permitted */
		case I_PUNLINK:
			linkp = (void *)mp->b_cont->b_rptr;
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
			 * "wcstart" will see it when it's done
			 * with the output before it.  Poke the
			 * start routine, just in case.
			 */
			(void) putq(q, mp);
			wcstart();
			break;

		case CONSSETABORTENABLE:
		case CONSGETABORTENABLE:
		case KIOCSDIRECT:
			if (wscons.wc_kbdqueue != NULL) {
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
		 * Queue the message up to be transmitted,
		 * and poke the start routine.
		 */
		(void) putq(q, mp);
		wcstart();
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
	queue_t *q;
	mblk_t *mp;

	wscons.wc_bufcallid = 0;
	q = wscons.wc_ttycommon.t_writeq;
	if ((mp = wscons.wc_ttycommon.t_iocpending) != NULL) {
		/* not pending any more */
		wscons.wc_ttycommon.t_iocpending = NULL;
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
	struct iocblk *iocp;
	size_t datasize;
	int error;
	long len;

	iocp = (void *)mp->b_rptr;

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
		 * If we're already open, fail.
		 */
		if (wscons.wc_tem != NULL)
			goto open_fail;

		/*
		 * If we don't have exactly one continuation block, fail.
		 */
		if (mp->b_cont == NULL || mp->b_cont->b_cont != NULL)
			goto open_fail;

		/*
		 * If there's no null terminator in the string, fail.
		 */
		len = MBLKL(mp->b_cont);
		if (memchr(mp->b_cont->b_rptr, 0, len) == NULL)
			goto open_fail;

		/*
		 * NOTE:  should eventually get default
		 * dimensions from a property, e.g. screen-#rows.
		 */
		iocp->ioc_error = tem_init(&wscons.wc_tem,
		    (char *)mp->b_cont->b_rptr, iocp->ioc_cr);
		/*
		 * Of course, if the terminal emulator initialization
		 * failed, fail.
		 */
		if (iocp->ioc_error != 0)
			goto open_fail;

		tem_register_modechg_cb(wscons.wc_tem, wc_modechg_cb,
		    (tem_modechg_cb_arg_t)&wscons);

		/*
		 * Refresh terminal size with info from terminal emulator.
		 */
		wc_get_size(&wscons);

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
		datasize = ttycommon_ioctl(&wscons.wc_ttycommon, q, mp, &error);
		if (datasize != 0) {
			if (wscons.wc_bufcallid != 0)
				qunbufcall(q, wscons.wc_bufcallid);
			wscons.wc_bufcallid = qbufcall(q, datasize, BPRI_HI,
			    wcreioctl, NULL);
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
wc_open_kb_polledio(struct wscons *wscons, queue_t *q, mblk_t *mp)
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

	iocp = (void *)mp2->b_rptr;

	iocp->ioc_count = sizeof (struct cons_polledio *);
	mp2->b_cont->b_wptr = mp2->b_cont->b_rptr +
	    sizeof (struct cons_polledio *);

	wscons->wc_pending_link = mp;
	wscons->wc_kb_getpolledio_id = iocp->ioc_id;

	putnext(wscons->wc_kbdqueue, mp2);

	return;

nomem:
	iocp = (void *)mp->b_rptr;
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
wc_close_kb_polledio(struct wscons *wscons, queue_t *q, mblk_t *mp)
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

	iocp = (void *)mp2->b_rptr;

	iocp->ioc_count = 0;

	wscons->wc_pending_link = mp;
	wscons->wc_kb_getpolledio_id = iocp->ioc_id;

	putnext(wscons->wc_kbdqueue, mp2);

	return;

nomem:
	iocp = (void *)mp->b_rptr;
	iocp->ioc_error = ENOMEM;
	mp->b_datap->db_type = M_IOCNAK;
	qreply(q, mp);
}

#ifdef _HAVE_TEM_FIRMWARE
/* ARGSUSED */
static void
wcopoll(void *arg)
{
	queue_t *q;

	q = wscons.wc_ttycommon.t_writeq;
	wscons.wc_timeoutid = 0;
	/* See if we can continue output */
	if ((wscons.wc_flags & WCS_BUSY) && wscons.wc_pendc != -1) {
		if (prom_mayput((char)wscons.wc_pendc) == 0) {
			wscons.wc_pendc = -1;
			wscons.wc_flags &= ~WCS_BUSY;
			if (!(wscons.wc_flags&(WCS_DELAY|WCS_STOPPED)))
				wcstart();
		} else
			wscons.wc_timeoutid = qtimeout(q, wcopoll, NULL, 1);
	}
}
#endif	/* _HAVE_TEM_FIRMWARE */

/*
 * Restart output on the console after a timeout.
 */
/* ARGSUSED */
static void
wcrstrt(void *arg)
{
	ASSERT(wscons.wc_ttycommon.t_writeq != NULL);
	wscons.wc_flags &= ~WCS_DELAY;
	wcstart();
}

/*
 * Start console output
 */
static void
wcstart(void)
{
#ifdef _HAVE_TEM_FIRMWARE
	int c;
	ssize_t cc;
#endif /* _HAVE_TEM_FIRMWARE */
	queue_t *q;
	mblk_t *bp;
	mblk_t *nbp;

	/*
	 * If we're waiting for something to happen (delay timeout to
	 * expire, current transmission to finish, output to be
	 * restarted, output to finish draining), don't grab anything
	 * new.
	 */
	if (wscons.wc_flags & (WCS_DELAY|WCS_BUSY|WCS_STOPPED))
		return;

	q = wscons.wc_ttycommon.t_writeq;
	/*
	 * assumes that we have been called by whoever holds the
	 * exclusionary lock on the write-side queue (protects
	 * wc_flags and wc_pendc).
	 */
	for (;;) {
		if ((bp = getq(q)) == NULL)
			return;	/* nothing to transmit */

		/*
		 * We have a new message to work on.
		 * Check whether it's a delay or an ioctl (the latter
		 * occurs if the ioctl in question was waiting for the output
		 * to drain).  If it's one of those, process it immediately.
		 */
		switch (bp->b_datap->db_type) {

		case M_DELAY:
			/*
			 * Arrange for "wcrstrt" to be called when the
			 * delay expires; it will turn WCS_DELAY off,
			 * and call "wcstart" to grab the next message.
			 */
			if (wscons.wc_timeoutid != 0)
				(void) quntimeout(q, wscons.wc_timeoutid);
			wscons.wc_timeoutid = qtimeout(q, wcrstrt, NULL,
			    (clock_t)(*(unsigned char *)bp->b_rptr + 6));
			wscons.wc_flags |= WCS_DELAY;
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_IOCTL:
			/*
			 * This ioctl was waiting for the output ahead of
			 * it to drain; obviously, it has.  Do it, and
			 * then grab the next message after it.
			 */
			wcioctl(q, bp);
			continue;
		}

#ifdef _HAVE_TEM_FIRMWARE
		if (consmode == CONS_KFB) {
#endif /* _HAVE_TEM_FIRMWARE */
			if (wscons.wc_tem != NULL) {
				for (nbp = bp; nbp != NULL; nbp = nbp->b_cont) {
					if (nbp->b_wptr > nbp->b_rptr) {
						(void) tem_write(wscons.wc_tem,
						    nbp->b_rptr,
						    MBLKL(nbp),
						    kcred);
					}
				}
				freemsg(bp);
			}
#ifdef _HAVE_TEM_FIRMWARE
			continue;
		}

		/* consmode = CONS_FW */
		if ((cc = MBLKL(bp)) == 0) {
			freemsg(bp);
			continue;
		}
		/*
		 * Direct output to the frame buffer if this device
		 * is not the "hardware" console.
		 */
		if (wscons.wc_defer_output) {
			/*
			 * Never do output here;
			 * it takes forever.
			 */
			wscons.wc_flags |= WCS_BUSY;
			wscons.wc_pendc = -1;
			(void) putbq(q, bp);
			if (q->q_count > 128) { /* do it soon */
				softcall(wconsout, NULL);
			} else {	/* wait a bit */
				if (wscons.wc_timeoutid != 0)
					(void) quntimeout(q,
					    wscons.wc_timeoutid);
				wscons.wc_timeoutid = qtimeout(q, wconsout,
				    NULL, hz / 30);
			}
			return;
		}
		for (;;) {
			c = *bp->b_rptr++;
			cc--;
			if (prom_mayput((char)c) != 0) {
				wscons.wc_flags |= WCS_BUSY;
				wscons.wc_pendc = c;
				if (wscons.wc_timeoutid != 0)
					(void) quntimeout(q,
					    wscons.wc_timeoutid);
				wscons.wc_timeoutid = qtimeout(q, wcopoll,
				    NULL, 1);
				if (bp != NULL)
					/* not done with this message yet */
					(void) putbq(q, bp);
				return;
			}
			while (cc <= 0) {
				nbp = bp;
				bp = bp->b_cont;
				freeb(nbp);
				if (bp == NULL)
					return;
				cc = MBLKL(bp);
			}
		}
#endif /* _HAVE_TEM_FIRMWARE */
	}
}

#ifdef _HAVE_TEM_FIRMWARE
/*
 * Output to frame buffer console.
 * It takes a long time to scroll.
 */
/* ARGSUSED */
static void
wconsout(void *dummy)
{
	uchar_t *cp;
	ssize_t cc;
	queue_t *q;
	mblk_t *bp;
	mblk_t *nbp;
	char *current_position;
	ssize_t bytes_left;

	if ((q = wscons.wc_ttycommon.t_writeq) == NULL) {
		return;	/* not attached to a stream */
	}

	/*
	 * Set up to copy up to MAXHIWAT bytes.
	 */
	current_position = &obuf[0];
	bytes_left = MAXHIWAT;
	while ((bp = getq(q)) != NULL) {
		if (bp->b_datap->db_type == M_IOCTL) {
			/*
			 * This ioctl was waiting for the output ahead of
			 * it to drain; obviously, it has.  Put it back
			 * so that "wcstart" can handle it, and transmit
			 * what we've got.
			 */
			(void) putbq(q, bp);
			goto transmit;
		}

		do {
			cp = bp->b_rptr;
			cc = MBLKL(bp);
			while (cc != 0) {
				if (bytes_left == 0) {
					/*
					 * Out of buffer space; put this
					 * buffer back on the queue, and
					 * transmit what we have.
					 */
					bp->b_rptr = cp;
					(void) putbq(q, bp);
					goto transmit;
				}
				*current_position++ = *cp++;
				cc--;
				bytes_left--;
			}
			nbp = bp;
			bp = bp->b_cont;
			freeb(nbp);
		} while (bp != NULL);
	}

transmit:
	if ((cc = MAXHIWAT - bytes_left) != 0)
		console_puts(obuf, cc);

	wscons.wc_flags &= ~WCS_BUSY;
	wcstart();
}
#endif /* _HAVE_TEM_FIRMWARE */

/*
 * Put procedure for lower read queue.
 * Pass everything up to queue above "upper half".
 */
static int
wclrput(queue_t *q, mblk_t *mp)
{
	queue_t *upq;
	struct iocblk *iocp;

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
		if ((upq = wscons.wc_ttycommon.t_readq) != NULL) {
			if (!canput(upq->q_next)) {
				ttycommon_qfull(&wscons.wc_ttycommon, upq);
				wcstart();
				freemsg(mp);
			} else
				putnext(upq, mp);
		} else
			freemsg(mp);
		break;

	case M_IOCACK:
	case M_IOCNAK:
		iocp = (void *)mp->b_rptr;
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
					    *(struct cons_polledio **)(void *)
					    mp->b_cont->b_rptr;
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
					    ("wclrput: ACK UNKNOWN\n"));
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
		DPRINTF(PRINT_L1, PRINT_MASK_ALL,
		    ("wclrput: Message DISCARDED\n"));
		if ((upq = wscons.wc_ttycommon.t_readq) != NULL) {
			putnext(upq, mp);
		} else {
			freemsg(mp);
		}
		break;
	}

	return (0);
}

/*
 * These are for systems without OBP, and for devices that cannot be
 * shared between Solaris and the OBP.
 */
static void
wc_polled_putchar(cons_polledio_arg_t arg, unsigned char c)
{
	if (c == '\n')
		wc_polled_putchar(arg, '\r');

	if (wscons.wc_tem == NULL) {
		/*
		 * We have no terminal emulator configured.  We have no
		 * recourse but to drop the output on the floor.
		 */
		return;
	}

	tem_polled_write(wscons.wc_tem, &c, 1);
}

/*
 * These are for systems without OBP, and for devices that cannot be
 * shared between Solaris and the OBP.
 */
static int
wc_polled_getchar(cons_polledio_arg_t arg)
{
	struct wscons *wscons = (struct wscons *)arg;

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
	struct wscons *wscons = (struct wscons *)arg;

	if (wscons->wc_kb_polledio == NULL)
		return (B_FALSE);

	return (wscons->wc_kb_polledio->cons_polledio_ischar(
	    wscons->wc_kb_polledio->cons_polledio_argument));
}

static void
wc_polled_enter(cons_polledio_arg_t arg)
{
	struct wscons *wscons = (struct wscons *)arg;

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
	struct wscons *wscons = (struct wscons *)arg;

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

static void
update_property(struct wscons *wscons, char *name, ushort_t value)
{
	char data[8];

	(void) snprintf(data, sizeof (data), "%u", value);
	(void) ddi_prop_update_string(wscons->wc_dev, wc_dip, name, data);
}

/*
 * Gets the number of text rows and columns and the
 * width and height (in pixels) of the console.
 */
static void
wc_get_size(struct wscons *wscons)
{
	struct winsize *t = &wscons->wc_ttycommon.t_size;
	ushort_t r = LOSCREENLINES, c = LOSCREENCOLS, x = 0, y = 0;

	if (wscons->wc_tem != NULL)
		tem_get_size(wscons->wc_tem, &r, &c, &x, &y);
#ifdef _HAVE_TEM_FIRMWARE
	else {
		console_get_size(&r, &c, &x, &y);
	}
#endif /* _HAVE_TEM_FIRMWARE */

	update_property(wscons, "screen-#cols",  t->ws_col = c);
	update_property(wscons, "screen-#rows",  t->ws_row = r);
	update_property(wscons, "screen-width",  t->ws_xpixel = x);
	update_property(wscons, "screen-height", t->ws_ypixel = y);
}

static void
wc_modechg_cb(tem_modechg_cb_arg_t arg)
{
	wc_get_size((struct wscons *)arg);
}
