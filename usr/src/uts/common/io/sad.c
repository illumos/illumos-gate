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


/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * STREAMS Administrative Driver
 *
 * Currently only handles autopush and module name verification.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/conf.h>
#include <sys/sad.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/zone.h>
#include <sys/policy.h>

static int sadopen(queue_t *, dev_t *, int, int, cred_t *);
static int sadclose(queue_t *, int, cred_t *);
static int sadwput(queue_t *qp, mblk_t *mp);

static int sad_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sad_attach(dev_info_t *, ddi_attach_cmd_t);

static void apush_ioctl(), apush_iocdata();
static void vml_ioctl(), vml_iocdata();
static int valid_major(major_t);

static dev_info_t *sad_dip;		/* private copy of devinfo pointer */

static struct module_info sad_minfo = {
	0x7361, "sad", 0, INFPSZ, 0, 0
};

static struct qinit sad_rinit = {
	NULL, NULL, sadopen, sadclose, NULL, &sad_minfo, NULL
};

static struct qinit sad_winit = {
	sadwput, NULL, NULL, NULL, NULL, &sad_minfo, NULL
};

struct streamtab sadinfo = {
	&sad_rinit, &sad_winit, NULL, NULL
};

DDI_DEFINE_STREAM_OPS(sad_ops, nulldev, nulldev, sad_attach,
    nodev, nodev, sad_info,
    D_MP | D_MTPERQ | D_MTOUTPERIM | D_MTOCEXCL, &sadinfo,
    ddi_quiesce_not_supported);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"STREAMS Administrative Driver 'sad'",
	&sad_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
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
sad_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	ASSERT(instance == 0);
	if (instance != 0)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "user", S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}
	if (ddi_create_minor_node(devi, "admin", S_IFCHR,
	    1, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	sad_dip = devi;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
sad_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (sad_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = sad_dip;
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


/*
 * sadopen() -
 * Allocate a sad device.  Only one
 * open at a time allowed per device.
 */
/* ARGSUSED */
static int
sadopen(
	queue_t *qp,	/* pointer to read queue */
	dev_t *devp,	/* major/minor device of stream */
	int flag,	/* file open flags */
	int sflag,	/* stream open flags */
	cred_t *credp)	/* user credentials */
{
	int i;
	netstack_t *ns;
	str_stack_t *ss;

	if (sflag)		/* no longer called from clone driver */
		return (EINVAL);

	/* Only privileged process can access ADMINDEV */
	if (getminor(*devp) == ADMMIN) {
		int err;

		err = secpolicy_sadopen(credp);

		if (err != 0)
			return (err);
	}

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	ss = ns->netstack_str;
	ASSERT(ss != NULL);

	/*
	 * Both USRMIN and ADMMIN are clone interfaces.
	 */
	for (i = 0; i < ss->ss_sadcnt; i++)
		if (ss->ss_saddev[i].sa_qp == NULL)
			break;
	if (i >= ss->ss_sadcnt) {		/* no such device */
		netstack_rele(ss->ss_netstack);
		return (ENXIO);
	}
	switch (getminor(*devp)) {
	case USRMIN:			/* mere mortal */
		ss->ss_saddev[i].sa_flags = 0;
		break;

	case ADMMIN:			/* privileged user */
		ss->ss_saddev[i].sa_flags = SADPRIV;
		break;

	default:
		netstack_rele(ss->ss_netstack);
		return (EINVAL);
	}

	ss->ss_saddev[i].sa_qp = qp;
	ss->ss_saddev[i].sa_ss = ss;
	qp->q_ptr = (caddr_t)&ss->ss_saddev[i];
	WR(qp)->q_ptr = (caddr_t)&ss->ss_saddev[i];

	/*
	 * NOTE: should the ADMMIN or USRMIN minors change
	 * then so should the offset of 2 below
	 * Both USRMIN and ADMMIN are clone interfaces and
	 * therefore their minor numbers (0 and 1) are reserved.
	 */
	*devp = makedevice(getemajor(*devp), i + 2);
	qprocson(qp);
	return (0);
}

/*
 * sadclose() -
 * Clean up the data structures.
 */
/* ARGSUSED */
static int
sadclose(
	queue_t *qp,	/* pointer to read queue */
	int flag,	/* file open flags */
	cred_t *credp)	/* user credentials */
{
	struct saddev *sadp;

	qprocsoff(qp);
	sadp = (struct saddev *)qp->q_ptr;
	sadp->sa_qp = NULL;
	sadp->sa_addr = NULL;
	netstack_rele(sadp->sa_ss->ss_netstack);
	sadp->sa_ss = NULL;
	qp->q_ptr = NULL;
	WR(qp)->q_ptr = NULL;
	return (0);
}

/*
 * sadwput() -
 * Write side put procedure.
 */
static int
sadwput(
	queue_t *qp,	/* pointer to write queue */
	mblk_t *mp)	/* message pointer */
{
	struct iocblk *iocp;

	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR) {
			*mp->b_rptr &= ~FLUSHW;
			qreply(qp, mp);
		} else
			freemsg(mp);
		break;

	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (SAD_CMD(iocp->ioc_cmd)) {
		case SAD_CMD(SAD_SAP):
		case SAD_CMD(SAD_GAP):
			apush_ioctl(qp, mp);
			break;

		case SAD_VML:
			vml_ioctl(qp, mp);
			break;

		default:
			miocnak(qp, mp, 0, EINVAL);
			break;
		}
		break;

	case M_IOCDATA:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (SAD_CMD(iocp->ioc_cmd)) {
		case SAD_CMD(SAD_SAP):
		case SAD_CMD(SAD_GAP):
			apush_iocdata(qp, mp);
			break;

		case SAD_VML:
			vml_iocdata(qp, mp);
			break;

		default:
			cmn_err(CE_WARN,
			    "sadwput: invalid ioc_cmd in case M_IOCDATA: %d",
			    iocp->ioc_cmd);
			freemsg(mp);
			break;
		}
		break;

	default:
		freemsg(mp);
		break;
	} /* switch (db_type) */
	return (0);
}

/*
 * apush_ioctl() -
 * Handle the M_IOCTL messages associated with
 * the autopush feature.
 */
static void
apush_ioctl(
	queue_t *qp,	/* pointer to write queue */
	mblk_t *mp)	/* message pointer */
{
	struct iocblk	*iocp;
	struct saddev	*sadp;
	uint_t		size;

	iocp = (struct iocblk *)mp->b_rptr;
	if (iocp->ioc_count != TRANSPARENT) {
		miocnak(qp, mp, 0, EINVAL);
		return;
	}
	if (SAD_VER(iocp->ioc_cmd) > AP_VERSION) {
		miocnak(qp, mp, 0, EINVAL);
		return;
	}

	sadp = (struct saddev *)qp->q_ptr;
	switch (SAD_CMD(iocp->ioc_cmd)) {
	case SAD_CMD(SAD_SAP):
		if (!(sadp->sa_flags & SADPRIV)) {
			miocnak(qp, mp, 0, EPERM);
			break;
		}
		/* FALLTHRU */

	case SAD_CMD(SAD_GAP):
		sadp->sa_addr = (caddr_t)*(uintptr_t *)mp->b_cont->b_rptr;
		if (SAD_VER(iocp->ioc_cmd) == 1)
			size = STRAPUSH_V1_LEN;
		else
			size = STRAPUSH_V0_LEN;
		mcopyin(mp, (void *)GETSTRUCT, size, NULL);
		qreply(qp, mp);
		break;

	default:
		ASSERT(0);
		miocnak(qp, mp, 0, EINVAL);
		break;
	} /* switch (ioc_cmd) */
}

/*
 * apush_iocdata() -
 * Handle the M_IOCDATA messages associated with
 * the autopush feature.
 */
static void
apush_iocdata(
	queue_t *qp,	/* pointer to write queue */
	mblk_t *mp)	/* message pointer */
{
	int i, ret;
	struct copyresp *csp;
	struct strapush *sap = NULL;
	struct autopush *ap, *ap_tmp;
	struct saddev *sadp;
	uint_t size;
	dev_t dev;
	str_stack_t *ss;

	sadp = (struct saddev *)qp->q_ptr;
	ss = sadp->sa_ss;

	csp = (struct copyresp *)mp->b_rptr;
	if (csp->cp_rval) {	/* if there was an error */
		freemsg(mp);
		return;
	}
	if (mp->b_cont) {
		/*
		 * sap needed only if mp->b_cont is set.  figure out the
		 * size of the expected sap structure and make sure
		 * enough data was supplied.
		 */
		if (SAD_VER(csp->cp_cmd) == 1)
			size = STRAPUSH_V1_LEN;
		else
			size = STRAPUSH_V0_LEN;
		if (MBLKL(mp->b_cont) < size) {
			miocnak(qp, mp, 0, EINVAL);
			return;
		}
		sap = (struct strapush *)mp->b_cont->b_rptr;
		dev = makedevice(sap->sap_major, sap->sap_minor);
	}
	switch (SAD_CMD(csp->cp_cmd)) {
	case SAD_CMD(SAD_SAP):

		/* currently we only support one SAD_SAP command */
		if (((long)csp->cp_private) != GETSTRUCT) {
			cmn_err(CE_WARN,
			    "apush_iocdata: cp_private bad in SAD_SAP: %p",
			    (void *)csp->cp_private);
			miocnak(qp, mp, 0, EINVAL);
			return;
		}

		switch (sap->sap_cmd) {
		default:
			miocnak(qp, mp, 0, EINVAL);
			return;
		case SAP_ONE:
		case SAP_RANGE:
		case SAP_ALL:
			/* allocate and initialize a new config */
			ap = sad_ap_alloc();
			ap->ap_common = sap->sap_common;
			if (SAD_VER(csp->cp_cmd) > 0)
				ap->ap_anchor = sap->sap_anchor;
			for (i = 0; i < MIN(sap->sap_npush, MAXAPUSH); i++)
				(void) strncpy(ap->ap_list[i],
				    sap->sap_list[i], FMNAMESZ);

			/* sanity check the request */
			if (((ret = sad_ap_verify(ap)) != 0) ||
			    ((ret = valid_major(ap->ap_major)) != 0)) {
				sad_ap_rele(ap, ss);
				miocnak(qp, mp, 0, ret);
				return;
			}

			/* check for overlapping configs */
			mutex_enter(&ss->ss_sad_lock);
			ap_tmp = sad_ap_find(&ap->ap_common, ss);
			if (ap_tmp != NULL) {
				/* already configured */
				mutex_exit(&ss->ss_sad_lock);
				sad_ap_rele(ap_tmp, ss);
				sad_ap_rele(ap, ss);
				miocnak(qp, mp, 0, EEXIST);
				return;
			}

			/* add the new config to our hash */
			sad_ap_insert(ap, ss);
			mutex_exit(&ss->ss_sad_lock);
			miocack(qp, mp, 0, 0);
			return;

		case SAP_CLEAR:
			/* sanity check the request */
			if (ret = valid_major(sap->sap_major)) {
				miocnak(qp, mp, 0, ret);
				return;
			}

			/* search for a matching config */
			if ((ap = sad_ap_find_by_dev(dev, ss)) == NULL) {
				/* no config found */
				miocnak(qp, mp, 0, ENODEV);
				return;
			}

			/*
			 * If we matched a SAP_RANGE config
			 * the minor passed in must match the
			 * beginning of the range exactly.
			 */
			if ((ap->ap_type == SAP_RANGE) &&
			    (ap->ap_minor != sap->sap_minor)) {
				sad_ap_rele(ap, ss);
				miocnak(qp, mp, 0, ERANGE);
				return;
			}

			/*
			 * If we matched a SAP_ALL config
			 * the minor passed in must be 0.
			 */
			if ((ap->ap_type == SAP_ALL) &&
			    (sap->sap_minor != 0)) {
				sad_ap_rele(ap, ss);
				miocnak(qp, mp, 0, EINVAL);
				return;
			}

			/*
			 * make sure someone else hasn't already
			 * removed this config from the hash.
			 */
			mutex_enter(&ss->ss_sad_lock);
			ap_tmp = sad_ap_find(&ap->ap_common, ss);
			if (ap_tmp != ap) {
				mutex_exit(&ss->ss_sad_lock);
				sad_ap_rele(ap_tmp, ss);
				sad_ap_rele(ap, ss);
				miocnak(qp, mp, 0, ENODEV);
				return;
			}

			/* remove the config from the hash and return */
			sad_ap_remove(ap, ss);
			mutex_exit(&ss->ss_sad_lock);

			/*
			 * Release thrice, once for sad_ap_find_by_dev(),
			 * once for sad_ap_find(), and once to free.
			 */
			sad_ap_rele(ap, ss);
			sad_ap_rele(ap, ss);
			sad_ap_rele(ap, ss);
			miocack(qp, mp, 0, 0);
			return;
		} /* switch (sap_cmd) */
		/*NOTREACHED*/

	case SAD_CMD(SAD_GAP):
		switch ((long)csp->cp_private) {

		case GETSTRUCT:
			/* sanity check the request */
			if (ret = valid_major(sap->sap_major)) {
				miocnak(qp, mp, 0, ret);
				return;
			}

			/* search for a matching config */
			if ((ap = sad_ap_find_by_dev(dev, ss)) == NULL) {
				/* no config found */
				miocnak(qp, mp, 0, ENODEV);
				return;
			}

			/* copy out the contents of the config */
			sap->sap_common = ap->ap_common;
			if (SAD_VER(csp->cp_cmd) > 0)
				sap->sap_anchor = ap->ap_anchor;
			for (i = 0; i < ap->ap_npush; i++)
				(void) strcpy(sap->sap_list[i], ap->ap_list[i]);
			for (; i < MAXAPUSH; i++)
				bzero(sap->sap_list[i], FMNAMESZ + 1);

			/* release our hold on the config */
			sad_ap_rele(ap, ss);

			/* copyout the results */
			if (SAD_VER(csp->cp_cmd) == 1)
				size = STRAPUSH_V1_LEN;
			else
				size = STRAPUSH_V0_LEN;

			mcopyout(mp, (void *)GETRESULT, size, sadp->sa_addr,
			    NULL);
			qreply(qp, mp);
			return;
		case GETRESULT:
			miocack(qp, mp, 0, 0);
			return;

		default:
			cmn_err(CE_WARN,
			    "apush_iocdata: cp_private bad case SAD_GAP: %p",
			    (void *)csp->cp_private);
			freemsg(mp);
			return;
		} /* switch (cp_private) */
		/*NOTREACHED*/
	default:	/* can't happen */
		ASSERT(0);
		freemsg(mp);
		return;
	} /* switch (cp_cmd) */
}

/*
 * vml_ioctl() -
 * Handle the M_IOCTL message associated with a request
 * to validate a module list.
 */
static void
vml_ioctl(
	queue_t *qp,	/* pointer to write queue */
	mblk_t *mp)	/* message pointer */
{
	struct iocblk *iocp;

	iocp = (struct iocblk *)mp->b_rptr;
	if (iocp->ioc_count != TRANSPARENT) {
		miocnak(qp, mp, 0, EINVAL);
		return;
	}
	ASSERT(SAD_CMD(iocp->ioc_cmd) == SAD_VML);
	mcopyin(mp, (void *)GETSTRUCT,
	    SIZEOF_STRUCT(str_list, iocp->ioc_flag), NULL);
	qreply(qp, mp);
}

/*
 * vml_iocdata() -
 * Handle the M_IOCDATA messages associated with
 * a request to validate a module list.
 */
static void
vml_iocdata(
	queue_t *qp,	/* pointer to write queue */
	mblk_t *mp)	/* message pointer */
{
	long i;
	int	nmods;
	struct copyresp *csp;
	struct str_mlist *lp;
	STRUCT_HANDLE(str_list, slp);
	struct saddev *sadp;

	csp = (struct copyresp *)mp->b_rptr;
	if (csp->cp_rval) {	/* if there was an error */
		freemsg(mp);
		return;
	}

	ASSERT(SAD_CMD(csp->cp_cmd) == SAD_VML);
	sadp = (struct saddev *)qp->q_ptr;
	switch ((long)csp->cp_private) {
	case GETSTRUCT:
		STRUCT_SET_HANDLE(slp, csp->cp_flag,
		    (struct str_list *)mp->b_cont->b_rptr);
		nmods = STRUCT_FGET(slp, sl_nmods);
		if (nmods <= 0) {
			miocnak(qp, mp, 0, EINVAL);
			break;
		}
		sadp->sa_addr = (caddr_t)(uintptr_t)nmods;

		mcopyin(mp, (void *)GETLIST, nmods * sizeof (struct str_mlist),
		    STRUCT_FGETP(slp, sl_modlist));
		qreply(qp, mp);
		break;

	case GETLIST:
		lp = (struct str_mlist *)mp->b_cont->b_rptr;
		for (i = 0; i < (long)sadp->sa_addr; i++, lp++) {
			lp->l_name[FMNAMESZ] = '\0';
			if (fmodsw_find(lp->l_name, FMODSW_LOAD) == NULL) {
				miocack(qp, mp, 0, 1);
				return;
			}
		}
		miocack(qp, mp, 0, 0);
		break;

	default:
		cmn_err(CE_WARN, "vml_iocdata: invalid cp_private value: %p",
		    (void *)csp->cp_private);
		freemsg(mp);
		break;
	} /* switch (cp_private) */
}

/*
 * Validate a major number and also verify if
 * it is a STREAMS device.
 * Return values: 0 if a valid STREAMS dev
 *		  error code otherwise
 */
static int
valid_major(major_t major)
{
	int ret = 0;

	if (etoimajor(major) == -1)
		return (EINVAL);

	/*
	 * attempt to load the driver 'major' and verify that
	 * it is a STREAMS driver.
	 */
	if (ddi_hold_driver(major) == NULL)
		return (EINVAL);

	if (!STREAMSTAB(major))
		ret = ENOSTR;

	ddi_rele_driver(major);

	return (ret);
}
