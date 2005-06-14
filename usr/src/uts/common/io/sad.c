/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


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
#include <sys/priv_names.h>

static int sadopen(queue_t *, dev_t *, int, int, cred_t *);
static int sadclose(queue_t *, int, cred_t *);
static int sadwput(queue_t *qp, mblk_t *mp);

static int sad_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sad_attach(dev_info_t *, ddi_attach_cmd_t);

static struct autopush *ap_alloc(), *ap_hfind();
static void ap_hadd(), ap_hrmv();
static void apush_ioctl(), apush_iocdata();
static void vml_ioctl(), vml_iocdata();
static int valid_major(major_t);

extern kmutex_t sad_lock;
static dev_info_t *sad_dip;		/* private copy of devinfo pointer */
static struct autopush *strpfreep;	/* autopush freelist */

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
    nodev, nodev, sad_info, D_NEW | D_MTPERQ | D_MP, &sadinfo);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"STREAMS Administrative Driver 'sad' %I%",
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
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "user", S_IFCHR,
	    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	if (ddi_create_priv_minor_node(devi, "admin", S_IFCHR,
	    1, DDI_PSEUDO, PRIVONLY_DEV, PRIV_SYS_CONFIG,
	    PRIV_SYS_CONFIG, 0666) == DDI_FAILURE) {
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
 * sadinit() -
 * Initialize autopush freelist.
 */
void
sadinit()
{
	struct autopush *ap;
	int i;

	/*
	 * build the autopush freelist.
	 */
	strpfreep = autopush;
	ap = autopush;
	for (i = 1; i < nautopush; i++) {
		ap->ap_nextp = &autopush[i];
		ap->ap_flags = APFREE;
		ap = ap->ap_nextp;
	}
	ap->ap_nextp = NULL;
	ap->ap_flags = APFREE;
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

	if (sflag)		/* no longer called from clone driver */
		return (EINVAL);

	/*
	 * Both USRMIN and ADMMIN are clone interfaces.
	 */
	for (i = 0; i < sadcnt; i++)
		if (saddev[i].sa_qp == NULL)
			break;
	if (i >= sadcnt)		/* no such device */
		return (ENXIO);

	switch (getminor(*devp)) {
	case USRMIN:			/* mere mortal */
		saddev[i].sa_flags = 0;
		break;

	case ADMMIN:			/* privileged user */
		saddev[i].sa_flags = SADPRIV;
		break;

	default:
		return (EINVAL);
	}

	saddev[i].sa_qp = qp;
	qp->q_ptr = (caddr_t)&saddev[i];
	WR(qp)->q_ptr = (caddr_t)&saddev[i];

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
	struct strapush *sap;
	struct autopush *ap;
	struct saddev *sadp;
	uint_t size;

	csp = (struct copyresp *)mp->b_rptr;
	if (csp->cp_rval) {	/* if there was an error */
		freemsg(mp);
		return;
	}
	if (mp->b_cont)
		/* sap needed only if mp->b_cont is set */
		sap = (struct strapush *)mp->b_cont->b_rptr;
	switch (SAD_CMD(csp->cp_cmd)) {
	case SAD_CMD(SAD_SAP):
		switch ((long)csp->cp_private) {
		case GETSTRUCT:
			switch (sap->sap_cmd) {
			case SAP_ONE:
			case SAP_RANGE:
			case SAP_ALL:
				if ((sap->sap_npush == 0) ||
				    (sap->sap_npush > MAXAPUSH) ||
				    (sap->sap_npush > nstrpush)) {

					/* invalid number of modules to push */

					miocnak(qp, mp, 0, EINVAL);
					break;
				}
				if (ret = valid_major(sap->sap_major)) {
					miocnak(qp, mp, 0, ret);
					break;
				}
				if ((sap->sap_cmd == SAP_RANGE) &&
				    (sap->sap_lastminor <= sap->sap_minor)) {

					/* bad range */

					miocnak(qp, mp, 0, ERANGE);
					break;
				}

				/*
				 * Validate that the specified list of
				 * modules exist.
				 */
				for (i = 0; i < sap->sap_npush; i++) {
					sap->sap_list[i][FMNAMESZ] = '\0';
					if (fmodsw_find(sap->sap_list[i],
					    FMODSW_LOAD) == NULL) {
						miocnak(qp, mp, 0, EINVAL);
						return;
					}
				}

				mutex_enter(&sad_lock);
				if (ap_hfind(sap->sap_major, sap->sap_minor,
				    sap->sap_lastminor, sap->sap_cmd)) {
					mutex_exit(&sad_lock);

					/* already configured */

					miocnak(qp, mp, 0, EEXIST);
					break;
				}
				if ((ap = ap_alloc()) == NULL) {
					mutex_exit(&sad_lock);

					/* no autopush structures */

					miocnak(qp, mp, 0, ENOSR);
					break;
				}
				ap->ap_cnt++;
				ap->ap_common = sap->sap_common;
				if (SAD_VER(csp->cp_cmd) > 0)
					ap->ap_anchor = sap->sap_anchor;
				else
					ap->ap_anchor = 0;
				for (i = 0; i < ap->ap_npush; i++)
					(void) strcpy(ap->ap_list[i],
					    sap->sap_list[i]);
				ap_hadd(ap);
				mutex_exit(&sad_lock);
				miocack(qp, mp, 0, 0);
				break;

			case SAP_CLEAR:
				if (ret = valid_major(sap->sap_major)) {
					miocnak(qp, mp, 0, ret);
					break;
				}
				mutex_enter(&sad_lock);
				if ((ap = ap_hfind(sap->sap_major,
				    sap->sap_minor, sap->sap_lastminor,
				    sap->sap_cmd)) == NULL) {
					mutex_exit(&sad_lock);

					/* not configured */

					miocnak(qp, mp, 0, ENODEV);
					break;
				}
				if ((ap->ap_type == SAP_RANGE) &&
				    (sap->sap_minor != ap->ap_minor)) {
					mutex_exit(&sad_lock);

					/* starting minors do not match */

					miocnak(qp, mp, 0, ERANGE);
					break;
				}
				if ((ap->ap_type == SAP_ALL) &&
				    (sap->sap_minor != 0)) {
					mutex_exit(&sad_lock);

					/* SAP_ALL must have minor == 0 */

					miocnak(qp, mp, 0, EINVAL);
					break;
				}
				ap_hrmv(ap);
				if (--(ap->ap_cnt) <= 0)
					ap_free(ap);
				mutex_exit(&sad_lock);
				miocack(qp, mp, 0, 0);
				break;

			default:
				miocnak(qp, mp, 0, EINVAL);
				break;
			} /* switch (sap_cmd) */
			break;

		default:
			cmn_err(CE_WARN,
			    "apush_iocdata: cp_private bad in SAD_SAP: %p",
			    (void *)csp->cp_private);
			freemsg(mp);
			break;
		} /* switch (cp_private) */
		break;

	case SAD_CMD(SAD_GAP):
		switch ((long)csp->cp_private) {

		case GETSTRUCT: {
			if (ret = valid_major(sap->sap_major)) {
				miocnak(qp, mp, 0, ret);
				break;
			}
			mutex_enter(&sad_lock);
			if ((ap = ap_hfind(sap->sap_major, sap->sap_minor,
			    sap->sap_lastminor, SAP_ONE)) == NULL) {
				mutex_exit(&sad_lock);

				/* not configured */

				miocnak(qp, mp, 0, ENODEV);
				break;
			}

			sap->sap_common = ap->ap_common;
			if (SAD_VER(csp->cp_cmd) > 0)
				sap->sap_anchor = ap->ap_anchor;
			for (i = 0; i < ap->ap_npush; i++)
				(void) strcpy(sap->sap_list[i], ap->ap_list[i]);
			for (; i < MAXAPUSH; i++)
				bzero(sap->sap_list[i], FMNAMESZ + 1);
			mutex_exit(&sad_lock);

			if (SAD_VER(csp->cp_cmd) == 1)
				size = STRAPUSH_V1_LEN;
			else
				size = STRAPUSH_V0_LEN;

			sadp = (struct saddev *)qp->q_ptr;
			mcopyout(mp, (void *)GETRESULT, size, sadp->sa_addr,
			    NULL);
			qreply(qp, mp);
			break;
			}
		case GETRESULT:
			miocack(qp, mp, 0, 0);
			break;

		default:
			cmn_err(CE_WARN,
			    "apush_iocdata: cp_private bad case SAD_GAP: %p",
			    (void *)csp->cp_private);
			freemsg(mp);
			break;
		} /* switch (cp_private) */
		break;

	default:	/* can't happen */
		ASSERT(0);
		freemsg(mp);
		break;
	} /* switch (cp_cmd) */
}

/*
 * ap_alloc() -
 * Allocate an autopush structure.
 */
static struct autopush *
ap_alloc(void)
{
	struct autopush *ap;

	ASSERT(MUTEX_HELD(&sad_lock));
	if (strpfreep == NULL)
		return (NULL);
	ap = strpfreep;
	if (ap->ap_flags != APFREE)
		cmn_err(CE_PANIC, "ap_alloc: autopush struct not free: %d",
		    ap->ap_flags);
	strpfreep = strpfreep->ap_nextp;
	ap->ap_nextp = NULL;
	ap->ap_flags = APUSED;
	return (ap);
}

/*
 * ap_free() -
 * Give an autopush structure back to the freelist.
 */
void
ap_free(struct autopush *ap)
{
	ASSERT(MUTEX_HELD(&sad_lock));
	if (!(ap->ap_flags & APUSED))
		cmn_err(CE_PANIC, "ap_free: autopush struct not used: %d",
		    ap->ap_flags);
	if (ap->ap_flags & APHASH)
		cmn_err(CE_PANIC, "ap_free: autopush struct not hashed: %d",
		    ap->ap_flags);
	ap->ap_flags = APFREE;
	ap->ap_nextp = strpfreep;
	strpfreep = ap;
}

/*
 * ap_hadd() -
 * Add an autopush structure to the hash list.
 */
static void
ap_hadd(struct autopush *ap)
{
	ASSERT(MUTEX_HELD(&sad_lock));
	if (!(ap->ap_flags & APUSED))
		cmn_err(CE_PANIC, "ap_hadd: autopush struct not used: %d",
		    ap->ap_flags);
	if (ap->ap_flags & APHASH)
		cmn_err(CE_PANIC, "ap_hadd: autopush struct not hashed: %d",
		    ap->ap_flags);
	ap->ap_nextp = strphash(ap->ap_major);
	strphash(ap->ap_major) = ap;
	ap->ap_flags |= APHASH;
}

/*
 * ap_hrmv() -
 * Remove an autopush structure from the hash list.
 */
static void
ap_hrmv(struct autopush *ap)
{
	struct autopush *hap;
	struct autopush *prevp = NULL;

	ASSERT(MUTEX_HELD(&sad_lock));
	if (!(ap->ap_flags & APUSED))
		cmn_err(CE_PANIC, "ap_hrmv: autopush struct not used: %d",
		    ap->ap_flags);
	if (!(ap->ap_flags & APHASH))
		cmn_err(CE_PANIC, "ap_hrmv: autopush struct not hashed: %d",
		    ap->ap_flags);

	hap = strphash(ap->ap_major);
	while (hap) {
		if (ap == hap) {
			hap->ap_flags &= ~APHASH;
			if (prevp)
				prevp->ap_nextp = hap->ap_nextp;
			else
				strphash(ap->ap_major) = hap->ap_nextp;
			return;
		} /* if */
		prevp = hap;
		hap = hap->ap_nextp;
	} /* while */
}

/*
 * ap_hfind() -
 * Look for an autopush structure in the hash list
 * based on major, minor, lastminor, and command.
 */
static struct autopush *
ap_hfind(
	major_t maj,	/* major device number */
	minor_t minor,	/* minor device number */
	minor_t last,	/* last minor device number (SAP_RANGE only) */
	uint_t cmd)	/* who is asking */
{
	struct autopush *ap;

	ASSERT(MUTEX_HELD(&sad_lock));
	ap = strphash(maj);
	while (ap) {
		if (ap->ap_major == maj) {
			if (cmd == SAP_ALL)
				break;
			switch (ap->ap_type) {
			case SAP_ALL:
				break;

			case SAP_ONE:
				if (ap->ap_minor == minor)
					break;
				if ((cmd == SAP_RANGE) &&
				    (ap->ap_minor >= minor) &&
				    (ap->ap_minor <= last))
					break;
				ap = ap->ap_nextp;
				continue;

			case SAP_RANGE:
				if ((cmd == SAP_RANGE) &&
				    (((minor >= ap->ap_minor) &&
				    (minor <= ap->ap_lastminor)) ||
				    ((ap->ap_minor >= minor) &&
				    (ap->ap_minor <= last))))
					break;
				if ((minor >= ap->ap_minor) &&
				    (minor <= ap->ap_lastminor))
					break;
				ap = ap->ap_nextp;
				continue;

			default:
				ASSERT(0);
				break;
			}
			break;
		}
		ap = ap->ap_nextp;
	}
	return (ap);
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
	ASSERT(iocp->ioc_cmd == SAD_VML);
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

	ASSERT(csp->cp_cmd == SAD_VML);
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
