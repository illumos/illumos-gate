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


/*
 * MT STREAMS Virtual Console Redirection Device Driver
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/debug.h>
#include <sys/thread.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/tty.h>
#include <sys/cvc.h>
#include <sys/conf.h>
#include <sys/modctl.h>


/*
 * Routine to to register/unregister our queue for console output and pass
 * redirected data to the console.  The cvc driver will do a putnext using
 * our queue, so we will not see the redirected console data.
 */
extern int	cvc_redir(mblk_t *);
extern int	cvc_register(queue_t *);
extern int	cvc_unregister(queue_t *);

static int	cvcr_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	cvcr_attach(dev_info_t *, ddi_attach_cmd_t);
static int	cvcr_detach(dev_info_t *, ddi_detach_cmd_t);
static int	cvcr_wput(queue_t *, mblk_t *);
static int	cvcr_open(queue_t *, dev_t *, int, int, cred_t *);
static int	cvcr_close(queue_t *, int, cred_t *);
static void	cvcr_ioctl(queue_t *, mblk_t *);

static dev_info_t	*cvcr_dip;
static int		cvcr_suspend = 0;

static struct module_info minfo = {
	1314,		/* mi_idnum Bad luck number +1  ;-) */
	"cvcredir",	/* mi_idname */
	0,		/* mi_minpsz */
	INFPSZ,		/* mi_maxpsz */
	2048,		/* mi_hiwat */
	2048		/* mi_lowat */
};

static struct qinit	cvcr_rinit = {
	NULL,		/* qi_putp */
	NULL,		/* qi_srvp */
	cvcr_open,	/* qi_qopen */
	cvcr_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&minfo,		/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct qinit	cvcr_winit = {
	cvcr_wput,	/* qi_putp */
	NULL,		/* qi_srvp */
	cvcr_open,	/* qi_qopen */
	cvcr_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&minfo,		/* qi_minfo */
	NULL		/* qi_mstat */
};

struct streamtab	cvcrinfo = {
	&cvcr_rinit,	/* st_rdinit */
	&cvcr_winit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

DDI_DEFINE_STREAM_OPS(cvcrops, nulldev, nulldev, cvcr_attach,
    cvcr_detach, nodev, cvcr_info, (D_MTPERQ | D_MP), &cvcrinfo,
    ddi_quiesce_not_supported);

char _depends_on[] = "drv/cvc";

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"CVC redirect driver 'cvcredir'",
	&cvcrops,	/* driver ops */
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

static int
cvcr_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
#ifdef lint
	cvcr_suspend = cvcr_suspend;
#endif
	if (cmd == DDI_RESUME) {
		cvcr_suspend = 0;
	} else {
		if (ddi_create_minor_node(devi, "cvcredir", S_IFCHR,
		    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
			ddi_remove_minor_node(devi, NULL);
			return (-1);
		}
		cvcr_dip = devi;
	}
	return (DDI_SUCCESS);
}

static int
cvcr_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_SUSPEND) {
		cvcr_suspend = 1;
	} else {
		if (cmd != DDI_DETACH) {
			return (DDI_FAILURE);
		}
		ddi_remove_minor_node(dip, NULL);
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
cvcr_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	register int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (cvcr_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)cvcr_dip;
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

/* ARGSUSED */
static int
cvcr_open(queue_t *q, dev_t *dev, int flag, int sflag, cred_t *cred)
{
	WR(q)->q_ptr = q->q_ptr = (char *)2;
	/*
	 * call into the cvc driver to register our queue.  cvc will use
	 * our queue to send console output data upstream (our stream)to
	 * cvcd which has us open and is reading console data.
	 */
	if (cvc_register(RD(q)) == -1) {
		cmn_err(CE_WARN, "cvcr_open: cvc_register failed for q = 0x%p",
		    q);
	}
	return (0);
}

/* ARGSUSED */
static int
cvcr_close(queue_t *q, int flag, cred_t *cred)
{
	/*
	 * call into the cvc driver to un-register our queue.  cvc will
	 * no longer use our queue to send console output data upstream.
	 */
	cvc_unregister(RD(q));
	WR(q)->q_ptr = q->q_ptr = NULL;
	return (0);
}

static int
cvcr_wput(queue_t *q, mblk_t *mp)
{
	/*
	 * Handle BREAK key for debugger and TIOCSWINSZ.
	 */
	if (mp->b_datap->db_type == M_IOCTL) {
		cvcr_ioctl(q, mp);
		return (0);
	}
	/*
	 * Call into the cvc driver to put console input data on
	 * its upstream queue to be picked up by the console driver.
	 */
	if (cvc_redir(mp) != 0)
		freemsg(mp);
	return (0);
}

static void
cvcr_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	int		error;

	switch (iocp->ioc_cmd) {
	case CVC_BREAK:
		abort_sequence_enter(NULL);
		miocack(q, mp, 0, 0);
		break;

	case CVC_DISCONNECT:
	case TIOCSWINSZ:
		/*
		 * Generate a SIGHUP or SIGWINCH to the console.  Note in this
		 * case cvc_redir does not free up mp, so we can reuse it for
		 * the ACK/NAK.
		 */
		error = cvc_redir(mp);
		if (error != 0)
			miocnak(q, mp, 0, error);
		else
			miocack(q, mp, 0, 0);
		break;

	default:
		miocnak(q, mp, 0, EINVAL);
		break;
	}
}
