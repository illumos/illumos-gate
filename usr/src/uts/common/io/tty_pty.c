/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015, Joyent, Inc.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * PTY - Stream "pseudo-tty" device.  For each "controller" side
 * it connects to a "slave" side.
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filio.h>
#include <sys/ioccom.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/ttold.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/tty.h>
#include <sys/user.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/vnode.h>	/* 1/0 on the vomit meter */
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/poll.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/procset.h>
#include <sys/cred.h>
#include <sys/ptyvar.h>
#include <sys/suntty.h>
#include <sys/stat.h>

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

extern int npty;	/* number of pseudo-ttys configured in */
extern struct pty *pty_softc;
extern struct pollhead	ptcph;	/* poll head for ptcpoll() use */

int ptcopen(dev_t *, int, int, struct cred *);
int ptcclose(dev_t, int, int, struct cred *);
int ptcwrite(dev_t, struct uio *, struct cred *);
int ptcread(dev_t, struct uio *, struct cred *);
int ptcioctl(dev_t, int, intptr_t, int, struct cred *, int *);
int ptcpoll(dev_t, short, int, short *, struct pollhead **);

static int ptc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ptc_attach(dev_info_t *, ddi_attach_cmd_t);
static dev_info_t *ptc_dip;	/* for dev-to-dip conversions */

static void ptc_init(void), ptc_uninit(void);

static int makemsg(ssize_t count, struct uio *uiop,
    struct pty *pty, mblk_t **mpp);

struct cb_ops	ptc_cb_ops = {
	ptcopen,		/* open */
	ptcclose,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	ptcread,		/* read */
	ptcwrite,		/* write */
	ptcioctl, 		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	ptcpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab */
	D_NEW | D_MP		/* Driver compatibility flag */
};

struct dev_ops	ptc_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	ptc_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	ptc_attach,		/* attach */
	nodev,			/* detach */
	nodev,			/* reset */
	&ptc_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/modctl.h>

extern int dseekneg_flag;
extern struct mod_ops mod_driverops;
extern struct dev_ops ptc_ops;

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"tty pseudo driver control 'ptc'",
	&ptc_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init()
{
	int rc;

	if ((rc = mod_install(&modlinkage)) == 0)
		ptc_init();
	return (rc);
}


int
_fini()
{
	int rc;

	if ((rc = mod_remove(&modlinkage)) == 0)
		ptc_uninit();
	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static char	*pty_banks = PTY_BANKS;
static char	*pty_digits = PTY_DIGITS;

/* ARGSUSED */
static int
ptc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	char	name[8];
	int	pty_num;
	char	*pty_digit = pty_digits;
	char	*pty_bank = pty_banks;

	for (pty_num = 0; pty_num < npty; pty_num++) {
		(void) sprintf(name, "pty%c%c", *pty_bank, *pty_digit);
		if (ddi_create_minor_node(devi, name, S_IFCHR,
		    pty_num, DDI_PSEUDO, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(devi, NULL);
			return (-1);
		}
		if (*(++pty_digit) == '\0') {
			pty_digit = pty_digits;
			if (*(++pty_bank) == '\0')
				break;
		}
	}
	ptc_dip = devi;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
ptc_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (ptc_dip == NULL) {
			*result = (void *)NULL;
			error = DDI_FAILURE;
		} else {
			*result = (void *) ptc_dip;
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
ptc_init(void)
{
	minor_t dev;

	for (dev = 0; dev < npty; dev++) {
		cv_init(&pty_softc[dev].pt_cv_flags, NULL, CV_DEFAULT, NULL);
		cv_init(&pty_softc[dev].pt_cv_readq, NULL, CV_DEFAULT, NULL);
		cv_init(&pty_softc[dev].pt_cv_writeq, NULL, CV_DEFAULT, NULL);
		mutex_init(&pty_softc[dev].ptc_lock, NULL, MUTEX_DEFAULT, NULL);
	}
}

static void
ptc_uninit(void)
{
	minor_t dev;

	for (dev = 0; dev < npty; dev++) {
		cv_destroy(&pty_softc[dev].pt_cv_flags);
		cv_destroy(&pty_softc[dev].pt_cv_readq);
		cv_destroy(&pty_softc[dev].pt_cv_writeq);
		mutex_destroy(&pty_softc[dev].ptc_lock);
	}
}

/*
 * Controller side.  This is not, alas, a streams device; there are too
 * many old features that we must support and that don't work well
 * with streams.
 */

/*ARGSUSED*/
int
ptcopen(dev_t *devp, int flag, int otyp, struct cred *cred)
{
	dev_t dev = *devp;
	struct pty *pty;
	queue_t *q;

	if (getminor(dev) >= npty) {
		return (ENXIO);
	}
	pty = &pty_softc[getminor(dev)];
	mutex_enter(&pty->ptc_lock);
	if (pty->pt_flags & PF_CARR_ON) {
		mutex_exit(&pty->ptc_lock);
		return (EIO);	/* controller is exclusive use */
				/* XXX - should be EBUSY! */
	}
	if (pty->pt_flags & PF_WOPEN) {
		pty->pt_flags &= ~PF_WOPEN;
		cv_broadcast(&pty->pt_cv_flags);
	}

	if ((q = pty->pt_ttycommon.t_readq) != NULL) {
		/*
		 * Send an un-hangup to the slave, since "carrier" is
		 * coming back up.  Make sure we're doing canonicalization.
		 */
		(void) putctl(q, M_UNHANGUP);
		(void) putctl1(q, M_CTL, MC_DOCANON);
	}
	pty->pt_flags |= PF_CARR_ON;
	pty->pt_send = 0;
	pty->pt_ucntl = 0;

	mutex_exit(&pty->ptc_lock);
	return (0);
}

/*ARGSUSED1*/
int
ptcclose(dev_t dev, int flag, int otyp, struct cred *cred)
{
	struct pty *pty;
	mblk_t *bp;
	queue_t *q;

	pty = &pty_softc[getminor(dev)];

	mutex_enter(&pty->ptc_lock);
	if ((q = pty->pt_ttycommon.t_readq) != NULL) {
		/*
		 * Send a hangup to the slave, since "carrier" is dropping.
		 */
		(void) putctl(q, M_HANGUP);
	}

	/*
	 * Clear out all the controller-side state.  This also
	 * clears PF_CARR_ON, which is correct because the
	 * "carrier" is dropping since the controller process
	 * is going away.
	 */
	pty->pt_flags &= (PF_WOPEN|PF_STOPPED|PF_NOSTOP);
	while ((bp = pty->pt_stuffqfirst) != NULL) {
		if ((pty->pt_stuffqfirst = bp->b_next) == NULL)
			pty->pt_stuffqlast = NULL;
		else
			pty->pt_stuffqfirst->b_prev = NULL;
		pty->pt_stuffqlen--;
		bp->b_next = bp->b_prev = NULL;
		freemsg(bp);
	}
	mutex_exit(&pty->ptc_lock);
	return (0);
}

int
ptcread(dev_t dev, struct uio *uio, struct cred *cred)
{
	struct pty *pty = &pty_softc[getminor(dev)];
	mblk_t *bp, *nbp;
	queue_t *q;
	unsigned char tmp;
	ssize_t cc;
	int error;
	off_t off;

#ifdef lint
	cred = cred;
#endif

	off = uio->uio_offset;

	mutex_enter(&pty->ptc_lock);

	for (;;) {
		while (pty->pt_flags & PF_READ) {
			pty->pt_flags |= PF_WREAD;
			cv_wait(&pty->pt_cv_flags, &pty->ptc_lock);
		}
		pty->pt_flags |= PF_READ;

		/*
		 * If there's a TIOCPKT packet waiting, pass it back.
		 */
		while (pty->pt_flags&(PF_PKT|PF_UCNTL) && pty->pt_send) {
			tmp = pty->pt_send;
			pty->pt_send = 0;
			mutex_exit(&pty->ptc_lock);
			error = ureadc((int)tmp, uio);
			uio->uio_offset = off;
			mutex_enter(&pty->ptc_lock);
			if (error) {
				pty->pt_send |= tmp;
				goto out;
			}
			if (pty->pt_send == 0)
				goto out;
		}

		/*
		 * If there's a user-control packet waiting, pass the
		 * "ioctl" code back.
		 */
		while ((pty->pt_flags & (PF_UCNTL|PF_43UCNTL)) &&
		    pty->pt_ucntl) {
			tmp = pty->pt_ucntl;
			pty->pt_ucntl = 0;
			mutex_exit(&pty->ptc_lock);
			error = ureadc((int)tmp, uio);
			uio->uio_offset = off;
			mutex_enter(&pty->ptc_lock);
			if (error) {
				if (pty->pt_ucntl == 0)
					pty->pt_ucntl = tmp;
				goto out;
			}
			if (pty->pt_ucntl == 0)
				goto out;
		}

		/*
		 * If there's any data waiting, pass it back.
		 */
		if ((q = pty->pt_ttycommon.t_writeq) != NULL &&
		    q->q_first != NULL &&
		    !(pty->pt_flags & PF_STOPPED)) {
			if (pty->pt_flags & (PF_PKT|PF_UCNTL|PF_43UCNTL)) {
				/*
				 * We're about to begin a move in packet or
				 * user-control mode; precede the data with a
				 * data header.
				 */
				mutex_exit(&pty->ptc_lock);
				error = ureadc(TIOCPKT_DATA, uio);
				uio->uio_offset = off;
				mutex_enter(&pty->ptc_lock);
				if (error != 0)
					goto out;
				if ((q = pty->pt_ttycommon.t_writeq) == NULL)
					goto out;
			}
			if ((bp = getq(q)) == NULL)
				goto out;
			while (uio->uio_resid > 0) {
				while ((cc = bp->b_wptr - bp->b_rptr) == 0) {
					nbp = bp->b_cont;
					freeb(bp);
					if ((bp = nbp) == NULL) {
						if ((q == NULL) ||
						    (bp = getq(q)) == NULL)
							goto out;
					}
				}
				cc = MIN(cc, uio->uio_resid);
				mutex_exit(&pty->ptc_lock);
				error = uiomove((caddr_t)bp->b_rptr,
				    cc, UIO_READ, uio);
				uio->uio_offset = off;
				mutex_enter(&pty->ptc_lock);
				if (error != 0) {
					freemsg(bp);
					goto out;
				}
				q = pty->pt_ttycommon.t_writeq;
				bp->b_rptr += cc;
			}
			/*
			 * Strip off zero-length blocks from the front of
			 * what we're putting back on the queue.
			 */
			while ((bp->b_wptr - bp->b_rptr) == 0) {
				nbp = bp->b_cont;
				freeb(bp);
				if ((bp = nbp) == NULL)
					goto out;	/* nothing left */
			}
			if (q != NULL)
				(void) putbq(q, bp);
			else
				freemsg(bp);
			goto out;
		}

		/*
		 * If there's any TIOCSTI-stuffed characters, pass
		 * them back.  (They currently arrive after all output;
		 * is this correct?)
		 */
		if (pty->pt_flags&PF_UCNTL && pty->pt_stuffqfirst != NULL) {
			mutex_exit(&pty->ptc_lock);
			error = ureadc(TIOCSTI&0xff, uio);
			mutex_enter(&pty->ptc_lock);
			while (error == 0 &&
			    (bp = pty->pt_stuffqfirst) != NULL &&
			    uio->uio_resid > 0) {
				pty->pt_stuffqlen--;
				if ((pty->pt_stuffqfirst = bp->b_next) == NULL)
					pty->pt_stuffqlast = NULL;
				else
					pty->pt_stuffqfirst->b_prev = NULL;
				mutex_exit(&pty->ptc_lock);
				error = ureadc((int)*bp->b_rptr, uio);
				bp->b_next = bp->b_prev = NULL;
				freemsg(bp);
				mutex_enter(&pty->ptc_lock);
			}
			uio->uio_offset = off;
			goto out;
		}

		/*
		 * There's no data available.
		 * We want to block until the slave is open, and there's
		 * something to read; but if we lost the slave or we're NBIO,
		 * then return the appropriate error instead.  POSIX-style
		 * non-block has top billing and gives -1 with errno = EAGAIN,
		 * BSD-style comes next and gives -1 with errno = EWOULDBLOCK,
		 * SVID-style comes last and gives 0.
		 */
		if (pty->pt_flags & PF_SLAVEGONE) {
			error = EIO;
			goto out;
		}
		if (uio->uio_fmode & FNONBLOCK) {
			error = EAGAIN;
			goto out;
		}
		if (pty->pt_flags & PF_NBIO) {
			error = EWOULDBLOCK;
			goto out;
		}
		if (uio->uio_fmode & FNDELAY)
			goto out;

		if (pty->pt_flags & PF_WREAD)
			cv_broadcast(&pty->pt_cv_flags);

		pty->pt_flags &= ~(PF_READ | PF_WREAD);


		if (!cv_wait_sig(&pty->pt_cv_writeq, &pty->ptc_lock)) {
			mutex_exit(&pty->ptc_lock);
			return (EINTR);
		}
	}

out:
	if (pty->pt_flags & PF_WREAD)
		cv_broadcast(&pty->pt_cv_flags);

	pty->pt_flags &= ~(PF_READ | PF_WREAD);

	mutex_exit(&pty->ptc_lock);
	return (error);
}

int
ptcwrite(dev_t dev, struct uio *uio, struct cred *cred)
{
	struct pty *pty = &pty_softc[getminor(dev)];
	queue_t *q;
	int written;
	mblk_t *mp;
	int fmode = 0;
	int error = 0;

	off_t off;
	off = uio->uio_offset;

#ifdef lint
	cred = cred;
#endif


	mutex_enter(&pty->ptc_lock);

again:
	while (pty->pt_flags & PF_WRITE) {
		pty->pt_flags |= PF_WWRITE;
		cv_wait(&pty->pt_cv_flags, &pty->ptc_lock);
	}

	pty->pt_flags |= PF_WRITE;

	if ((q = pty->pt_ttycommon.t_readq) == NULL) {

		/*
		 * Wait for slave to open.
		 */
		if (pty->pt_flags & PF_SLAVEGONE) {
			error = EIO;
			goto out;
		}
		if (uio->uio_fmode & FNONBLOCK) {
			error = EAGAIN;
			goto out;
		}
		if (pty->pt_flags & PF_NBIO) {
			error = EWOULDBLOCK;
			goto out;
		}
		if (uio->uio_fmode & FNDELAY)
			goto out;

		if (pty->pt_flags & PF_WWRITE)
			cv_broadcast(&pty->pt_cv_flags);

		pty->pt_flags &= ~(PF_WRITE | PF_WWRITE);

		if (!cv_wait_sig(&pty->pt_cv_readq, &pty->ptc_lock)) {
			mutex_exit(&pty->ptc_lock);
			return (EINTR);
		}

		goto again;
	}

	/*
	 * If in remote mode, even zero-length writes generate messages.
	 */
	written = 0;
	if ((pty->pt_flags & PF_REMOTE) || uio->uio_resid > 0) {
		do {
			while (!canput(q)) {
				/*
				 * Wait for slave's read queue to unclog.
				 */
				if (pty->pt_flags & PF_SLAVEGONE) {
					error = EIO;
					goto out;
				}
				if (uio->uio_fmode & FNONBLOCK) {
					if (!written)
						error = EAGAIN;
					goto out;
				}
				if (pty->pt_flags & PF_NBIO) {
					if (!written)
						error = EWOULDBLOCK;
					goto out;
				}
				if (uio->uio_fmode & FNDELAY)
					goto out;

				if (pty->pt_flags & PF_WWRITE)
					cv_broadcast(&pty->pt_cv_flags);

				pty->pt_flags &= ~(PF_WRITE | PF_WWRITE);

				if (!cv_wait_sig(&pty->pt_cv_readq,
				    &pty->ptc_lock)) {
					mutex_exit(&pty->ptc_lock);
					return (EINTR);
				}

				while (pty->pt_flags & PF_WRITE) {
					pty->pt_flags |= PF_WWRITE;
					cv_wait(&pty->pt_cv_flags,
					    &pty->ptc_lock);
				}

				pty->pt_flags |= PF_WRITE;
			}

			if ((pty->pt_flags & PF_NBIO) &&
			    !(uio->uio_fmode & FNONBLOCK)) {
				fmode = uio->uio_fmode;
				uio->uio_fmode |= FNONBLOCK;
			}

			error = makemsg(uio->uio_resid, uio, pty, &mp);
			uio->uio_offset = off;
			if (fmode)
				uio->uio_fmode = fmode;
			if (error != 0) {
				if (error != EAGAIN && error != EWOULDBLOCK)
					goto out;
				if (uio->uio_fmode & FNONBLOCK) {
					if (!written)
						error = EAGAIN;
					goto out;
				}
				if (pty->pt_flags & PF_NBIO) {
					if (!written)
						error = EWOULDBLOCK;
					goto out;
				}
				if (uio->uio_fmode & FNDELAY)
					goto out;
				cmn_err(CE_PANIC,
				    "ptcwrite: non null return from"
				    " makemsg");
			}

			/*
			 * Check again for safety; since "uiomove" can take a
			 * page fault, there's no guarantee that "pt_flags"
			 * didn't change while it was happening.
			 */
			if ((q = pty->pt_ttycommon.t_readq) == NULL) {
				if (mp)
					freemsg(mp);
				error = EIO;
				goto out;
			}
			if (mp)
				(void) putq(q, mp);
			written = 1;
		} while (uio->uio_resid > 0);
	}
out:
	if (pty->pt_flags & PF_WWRITE)
		cv_broadcast(&pty->pt_cv_flags);

	pty->pt_flags &= ~(PF_WRITE | PF_WWRITE);

	mutex_exit(&pty->ptc_lock);
	return (error);
}

#define	copy_in(data, d_arg) \
	if (copyin((caddr_t)data, &d_arg, sizeof (int)) != 0) \
		return (EFAULT)

#define	copy_out(d_arg, data) \
	if (copyout(&d_arg, (caddr_t)data, sizeof (int)) != 0) \
		return (EFAULT)

int
ptcioctl(dev_t dev, int cmd, intptr_t data, int flag, struct cred *cred,
    int *rvalp)
{
	struct pty *pty = &pty_softc[getminor(dev)];
	queue_t *q;
	struct ttysize tty_arg;
	struct winsize win_arg;
	int d_arg;
	int err;

	switch (cmd) {

	case TIOCPKT:
		copy_in(data, d_arg);
		mutex_enter(&pty->ptc_lock);
		if (d_arg) {
			if (pty->pt_flags & (PF_UCNTL|PF_43UCNTL)) {
				mutex_exit(&pty->ptc_lock);
				return (EINVAL);
			}
			pty->pt_flags |= PF_PKT;
		} else
			pty->pt_flags &= ~PF_PKT;
		mutex_exit(&pty->ptc_lock);
		break;

	case TIOCUCNTL:
		copy_in(data, d_arg);
		mutex_enter(&pty->ptc_lock);
		if (d_arg) {
			if (pty->pt_flags & (PF_PKT|PF_UCNTL)) {
				mutex_exit(&pty->ptc_lock);
				return (EINVAL);
			}
			pty->pt_flags |= PF_43UCNTL;
		} else
			pty->pt_flags &= ~PF_43UCNTL;
		mutex_exit(&pty->ptc_lock);
		break;

	case TIOCTCNTL:
		copy_in(data, d_arg);
		mutex_enter(&pty->ptc_lock);
		if (d_arg) {
			if (pty->pt_flags & PF_PKT) {
				mutex_exit(&pty->ptc_lock);
				return (EINVAL);
			}
			pty->pt_flags |= PF_UCNTL;
		} else
			pty->pt_flags &= ~PF_UCNTL;
		mutex_exit(&pty->ptc_lock);
		break;

	case TIOCREMOTE:
		copy_in(data, d_arg);
		mutex_enter(&pty->ptc_lock);
		if (d_arg) {
			if ((q = pty->pt_ttycommon.t_readq) != NULL)
				(void) putctl1(q, M_CTL, MC_NOCANON);
			pty->pt_flags |= PF_REMOTE;
		} else {
			if ((q = pty->pt_ttycommon.t_readq) != NULL)
				(void) putctl1(q, M_CTL, MC_DOCANON);
			pty->pt_flags &= ~PF_REMOTE;
		}
		mutex_exit(&pty->ptc_lock);
		break;

	case TIOCSIGNAL:
		/*
		 * Blast a M_PCSIG message up the slave stream; the
		 * signal number is the argument to the "ioctl".
		 */
		copy_in(data, d_arg);
		mutex_enter(&pty->ptc_lock);
		if ((q = pty->pt_ttycommon.t_readq) != NULL)
			(void) putctl1(q, M_PCSIG, (int)d_arg);
		mutex_exit(&pty->ptc_lock);
		break;

	case FIONBIO:
		copy_in(data, d_arg);
		mutex_enter(&pty->ptc_lock);
		if (d_arg)
			pty->pt_flags |= PF_NBIO;
		else
			pty->pt_flags &= ~PF_NBIO;
		mutex_exit(&pty->ptc_lock);
		break;

	case FIOASYNC:
		copy_in(data, d_arg);
		mutex_enter(&pty->ptc_lock);
		if (d_arg)
			pty->pt_flags |= PF_ASYNC;
		else
			pty->pt_flags &= ~PF_ASYNC;
		mutex_exit(&pty->ptc_lock);
		break;

	/*
	 * These, at least, can work on the controller-side process
	 * group.
	 */
	case FIOGETOWN:
		mutex_enter(&pty->ptc_lock);
		d_arg = -pty->pt_pgrp;
		mutex_exit(&pty->ptc_lock);
		copy_out(d_arg, data);
		break;

	case FIOSETOWN:
		copy_in(data, d_arg);
		mutex_enter(&pty->ptc_lock);
		pty->pt_pgrp = (short)(-d_arg);
		mutex_exit(&pty->ptc_lock);
		break;

	case FIONREAD: {
		/*
		 * Return the total number of bytes of data in all messages
		 * in slave write queue, which is master read queue, unless a
		 * special message would be read.
		 */
		mblk_t *mp;
		size_t count = 0;

		mutex_enter(&pty->ptc_lock);
		if (pty->pt_flags&(PF_PKT|PF_UCNTL) && pty->pt_send)
			count = 1;	/* will return 1 byte */
		else if ((pty->pt_flags & (PF_UCNTL|PF_43UCNTL)) &&
		    pty->pt_ucntl)
			count = 1;	/* will return 1 byte */
		else if ((q = pty->pt_ttycommon.t_writeq) != NULL &&
		    q->q_first != NULL && !(pty->pt_flags & PF_STOPPED)) {
			/*
			 * Will return whatever data is queued up.
			 */
			for (mp = q->q_first; mp != NULL; mp = mp->b_next)
				count += msgdsize(mp);
		} else if ((pty->pt_flags & PF_UCNTL) &&
		    pty->pt_stuffqfirst != NULL) {
			/*
			 * Will return STI'ed data.
			 */
			count = pty->pt_stuffqlen + 1;
		}

		/*
		 * Under LP64 we could have more than INT_MAX bytes to report,
		 * but the interface is defined in terms of int, so we cap it.
		 */
		d_arg = MIN(count, INT_MAX);
		mutex_exit(&pty->ptc_lock);
		copy_out(d_arg, data);
		break;
	}

	case TIOCSWINSZ:
		/*
		 * Unfortunately, TIOCSWINSZ and the old TIOCSSIZE "ioctl"s
		 * share the same code.  If the upper 16 bits of the number
		 * of lines is non-zero, it was probably a TIOCSWINSZ,
		 * with both "ws_row" and "ws_col" non-zero.
		 */
		if (copyin((caddr_t)data,
		    &tty_arg, sizeof (struct ttysize)) != 0)
			return (EFAULT);

		if ((tty_arg.ts_lines & 0xffff0000) != 0) {
			/*
			 * It's a TIOCSWINSZ.
			 */
			win_arg = *(struct winsize *)&tty_arg;

			mutex_enter(&pty->ptc_lock);
			/*
			 * If the window size changed, send a SIGWINCH.
			 */
			if (bcmp(&pty->pt_ttycommon.t_size,
			    &win_arg, sizeof (struct winsize))) {
				pty->pt_ttycommon.t_size = win_arg;
				if ((q = pty->pt_ttycommon.t_readq) != NULL)
					(void) putctl1(q, M_PCSIG, SIGWINCH);
			}
			mutex_exit(&pty->ptc_lock);
			break;
		}
		/* FALLTHROUGH */

	case TIOCSSIZE:
		if (copyin((caddr_t)data,
		    &tty_arg, sizeof (struct ttysize)) != 0)
			return (EFAULT);
		mutex_enter(&pty->ptc_lock);
		pty->pt_ttycommon.t_size.ws_row = (ushort_t)tty_arg.ts_lines;
		pty->pt_ttycommon.t_size.ws_col = (ushort_t)tty_arg.ts_cols;
		pty->pt_ttycommon.t_size.ws_xpixel = 0;
		pty->pt_ttycommon.t_size.ws_ypixel = 0;
		mutex_exit(&pty->ptc_lock);
		break;

	case TIOCGWINSZ:
		mutex_enter(&pty->ptc_lock);
		win_arg = pty->pt_ttycommon.t_size;
		mutex_exit(&pty->ptc_lock);
		if (copyout(&win_arg, (caddr_t)data,
		    sizeof (struct winsize)) != 0)
			return (EFAULT);
		break;

	case TIOCGSIZE:
		mutex_enter(&pty->ptc_lock);
		tty_arg.ts_lines = pty->pt_ttycommon.t_size.ws_row;
		tty_arg.ts_cols = pty->pt_ttycommon.t_size.ws_col;
		mutex_exit(&pty->ptc_lock);
		if (copyout(&tty_arg, (caddr_t)data,
		    sizeof (struct ttysize)) != 0)
			return (EFAULT);
		break;

	/*
	 * XXX These should not be here.  The only reason why an
	 * "ioctl" on the controller side should get the
	 * slave side's process group is so that the process on
	 * the controller side can send a signal to the slave
	 * side's process group; however, this is better done
	 * with TIOCSIGNAL, both because it doesn't require us
	 * to know about the slave side's process group and because
	 * the controller side process may not have permission to
	 * send that signal to the entire process group.
	 *
	 * However, since vanilla 4BSD doesn't provide TIOCSIGNAL,
	 * we can't just get rid of them.
	 */
	case TIOCGPGRP:
	case TIOCSPGRP:
	/*
	 * This is amazingly disgusting, but the stupid semantics of
	 * 4BSD pseudo-ttys makes us do it.  If we do one of these guys
	 * on the controller side, it really applies to the slave-side
	 * stream.  It should NEVER have been possible to do ANY sort
	 * of tty operations on the controller side, but it's too late
	 * to fix that now.  However, we won't waste our time implementing
	 * anything that the original pseudo-tty driver didn't handle.
	 */
	case TIOCGETP:
	case TIOCSETP:
	case TIOCSETN:
	case TIOCGETC:
	case TIOCSETC:
	case TIOCGLTC:
	case TIOCSLTC:
	case TIOCLGET:
	case TIOCLSET:
	case TIOCLBIS:
	case TIOCLBIC:
		mutex_enter(&pty->ptc_lock);
		if (pty->pt_vnode == NULL) {
			mutex_exit(&pty->ptc_lock);
			return (EIO);
		}
		pty->pt_flags |= PF_IOCTL;
		mutex_exit(&pty->ptc_lock);
		err = strioctl(pty->pt_vnode, cmd, data, flag,
		    U_TO_K, cred, rvalp);
		mutex_enter(&pty->ptc_lock);
		if (pty->pt_flags & PF_WAIT)
			cv_signal(&pty->pt_cv_flags);
		pty->pt_flags &= ~(PF_IOCTL|PF_WAIT);
		mutex_exit(&pty->ptc_lock);
		return (err);

	default:
		return (ENOTTY);
	}

	return (0);
}


int
ptcpoll(dev_t dev,
	short events,
	int anyyet,
	short *reventsp,
	struct pollhead **phpp)
{
	struct pty *pty = &pty_softc[getminor(dev)];
	pollhead_t *php = &ptcph;
	queue_t *q;
	int pos = 0;

#ifdef lint
	anyyet = anyyet;
#endif
	if (polllock(php, &pty->ptc_lock) != 0) {
		*reventsp = POLLNVAL;
		return (0);
	}

	ASSERT(MUTEX_HELD(&pty->ptc_lock));

	*reventsp = 0;
	if (pty->pt_flags & PF_SLAVEGONE) {
		if (events & (POLLIN|POLLRDNORM))
			*reventsp |= (events & (POLLIN|POLLRDNORM));
		if (events & (POLLOUT|POLLWRNORM))
			*reventsp |= (events & (POLLOUT|POLLWRNORM));
		mutex_exit(&pty->ptc_lock);
		/*
		 * A non NULL pollhead pointer should be returned in case
		 * user polls for 0 events.
		 */
		*phpp = !anyyet && !*reventsp ? php : (struct pollhead *)NULL;
		return (0);
	}
	if (events & (POLLIN|POLLRDNORM)) {
		if ((q = pty->pt_ttycommon.t_writeq) != NULL &&
		    q->q_first != NULL && !(pty->pt_flags & PF_STOPPED)) {
			/*
			 * Regular data is available.
			 */
			*reventsp |= (events & (POLLIN|POLLRDNORM));
			pos++;
		}
		if (pty->pt_flags & (PF_PKT|PF_UCNTL) && pty->pt_send) {
			/*
			 * A control packet is available.
			 */
			*reventsp |= (events & (POLLIN|POLLRDNORM));
			pos++;
		}
		if ((pty->pt_flags & PF_UCNTL) &&
		    (pty->pt_ucntl || pty->pt_stuffqfirst != NULL)) {
			/*
			 * "ioctl" or TIOCSTI data is available.
			 */
			*reventsp |= (events & (POLLIN|POLLRDNORM));
			pos++;
		}
		if ((pty->pt_flags & PF_43UCNTL) && pty->pt_ucntl) {
			*reventsp |= (events & (POLLIN|POLLRDNORM));
			pos++;
		}
	}
	if (events & (POLLOUT|POLLWRNORM)) {
		if ((q = pty->pt_ttycommon.t_readq) != NULL &&
		    canput(q)) {
			*reventsp |= (events & (POLLOUT|POLLWRNORM));
			pos++;
		}
	}
	if (events & POLLERR) {
		*reventsp |= POLLERR;
		pos++;
	}
	if (events == 0) {	/* "exceptional conditions" */
		if (((pty->pt_flags & (PF_PKT|PF_UCNTL)) && pty->pt_send) ||
		    ((pty->pt_flags & PF_UCNTL) &&
		    (pty->pt_ucntl || pty->pt_stuffqfirst != NULL))) {
			pos++;
		}
		if ((pty->pt_flags & PF_43UCNTL) && pty->pt_ucntl) {
			pos++;
		}
	}

	/*
	 * Arrange to have poll waken up when event occurs.
	 * if (!anyyet)
	 */
	if (!pos) {
		*phpp = php;
		*reventsp = 0;
	}

	mutex_exit(&pty->ptc_lock);
	return (0);
}

void
gsignal(int pid, int sig)
{
	procset_t set;
	sigsend_t v;

	bzero(&v, sizeof (v));
	v.sig = sig;
	v.perm = 0;
	v.checkperm = 1;
	v.value.sival_ptr = NULL;

	setprocset(&set, POP_AND, P_PGID, -pid, P_ALL, P_MYID);
	(void) sigsendset(&set, &v);
}

static int
makemsg(ssize_t count, struct uio *uiop, struct pty *pty, mblk_t **mpp)
{
	int pri = BPRI_LO;
	int error;
	mblk_t *bp = NULL;

	ASSERT(MUTEX_HELD(&pty->ptc_lock));

	*mpp = NULL;

	/*
	 * Create data part of message, if any.
	 */
	if (count >= 0) {
		if ((bp = allocb(count, pri)) == NULL)
			return (ENOSR);

		mutex_exit(&pty->ptc_lock);
		error = uiomove((caddr_t)bp->b_wptr, count, UIO_WRITE, uiop);
		mutex_enter(&pty->ptc_lock);
		if (error) {
			freeb(bp);
			return (error);
		}

		bp->b_wptr += count;
	}

	*mpp = bp;
	return (0);
}
