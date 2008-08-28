/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_dev.c,v 1.21 2004/12/13 00:25:18 lindak Exp $
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/pathname.h>
#include <sys/mount.h>
#include <sys/sdt.h>
#include <fs/fs_subr.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/thread.h>
#include <sys/mkdev.h>
#include <sys/types.h>
#include <sys/zone.h>

#ifdef APPLE
#include <sys/smb_apple.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/mchain.h>		/* for "htoles()" */

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>
#include <netsmb/smb_pass.h>

/* for version checks */
const uint32_t nsmb_version = NSMB_VERSION;

/*
 * Userland code loops through minor #s 0 to 1023, looking for one which opens.
 * Intially we create minor 0 and leave it for anyone.  Minor zero will never
 * actually get used - opening triggers creation of another (but private) minor,
 * which userland code will get to and mark busy.
 */
#define	SMBMINORS 1024
static void *statep;
static major_t nsmb_major;
static minor_t nsmb_minor = 1;

#define	NSMB_MAX_MINOR  (1 << 8)
#define	NSMB_MIN_MINOR   (NSMB_MAX_MINOR + 1)

#define	ILP32	1
#define	LP64	2

static kmutex_t  dev_lck;

/* Zone support */
zone_key_t nsmb_zone_key;
extern void nsmb_zone_shutdown(zoneid_t zoneid, void *data);
extern void nsmb_zone_destroy(zoneid_t zoneid, void *data);

/*
 * cb_ops device operations.
 */
static int nsmb_open(dev_t *devp, int flag, int otyp, cred_t *credp);
static int nsmb_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int nsmb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
				cred_t *credp, int *rvalp);
/* smbfs cb_ops */
static struct cb_ops nsmb_cbops = {
	nsmb_open,	/* open */
	nsmb_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	nsmb_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* stream */
	D_MP,		/* cb_flag */
	CB_REV,		/* rev */
	nodev,		/* int (*cb_aread)() */
	nodev		/* int (*cb_awrite)() */
};

/*
 * Device options
 */
static int nsmb_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int nsmb_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int nsmb_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
	void *arg, void **result);

static struct dev_ops nsmb_ops = {
	DEVO_REV,	/* devo_rev, */
	0,		/* refcnt  */
	nsmb_getinfo,	/* info */
	nulldev,	/* identify */
	nulldev,	/* probe */
	nsmb_attach,	/* attach */
	nsmb_detach,	/* detach */
	nodev,		/* reset */
	&nsmb_cbops,	/* driver ops - devctl interfaces */
	NULL,		/* bus operations */
	NULL		/* power */
};

/*
 * Module linkage information.
 */

static struct modldrv nsmb_modldrv = {
	&mod_driverops,				/* Driver module */
	"SMBFS network driver v" NSMB_VER_STR,
	&nsmb_ops				/* Driver ops */
};

static struct modlinkage nsmb_modlinkage = {
	MODREV_1,
	(void *)&nsmb_modldrv,
	NULL
};

int
_init(void)
{
	int error;

	ddi_soft_state_init(&statep, sizeof (smb_dev_t), 1);

	/* Can initialize some mutexes also. */
	mutex_init(&dev_lck, NULL, MUTEX_DRIVER, NULL);
	/*
	 * Create a major name and number.
	 */
	nsmb_major = ddi_name_to_major(NSMB_NAME);
	nsmb_minor = 0;

	/* Connection data structures. */
	(void) smb_sm_init();

	/* Initialize password Key chain DB. */
	smb_pkey_init();

	zone_key_create(&nsmb_zone_key, NULL, nsmb_zone_shutdown,
	    nsmb_zone_destroy);

	/*
	 * Install the module.  Do this after other init,
	 * to prevent entrances before we're ready.
	 */
	if ((error = mod_install((&nsmb_modlinkage))) != 0) {

		/* Same as 2nd half of _fini */
		(void) zone_key_delete(nsmb_zone_key);
		smb_pkey_fini();
		smb_sm_done();
		mutex_destroy(&dev_lck);
		ddi_soft_state_fini(&statep);

		return (error);
	}

	return (0);
}

int
_fini(void)
{
	int status;

	/*
	 * Prevent unload if we have active VCs
	 * or stored passwords
	 */
	if ((status = smb_sm_idle()) != 0)
		return (status);
	if ((status = smb_pkey_idle()) != 0)
		return (status);

	/*
	 * Remove the module.  Do this before destroying things,
	 * to prevent new entrances while we're destorying.
	 */
	if ((status = mod_remove(&nsmb_modlinkage)) != 0) {
		return (status);
	}

	(void) zone_key_delete(nsmb_zone_key);

	/* Destroy password Key chain DB. */
	smb_pkey_fini();

	smb_sm_done();

	mutex_destroy(&dev_lck);
	ddi_soft_state_fini(&statep);

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&nsmb_modlinkage, modinfop));
}

/*ARGSUSED*/
static int
nsmb_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int ret = DDI_SUCCESS;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = 0;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		break;
	default:
		ret = DDI_FAILURE;
	}
	return (ret);
}

static int
nsmb_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	smb_dev_t *sdp;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	/*
	 * only one instance - but we clone using the open routine
	 */
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);

	mutex_enter(&dev_lck);

	/*
	 * This is the Zero'th minor device which is created.
	 */
	if (ddi_soft_state_zalloc(statep, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "nsmb_attach: soft state alloc");
		goto attach_failed;
	}
	if (ddi_create_minor_node(dip, "nsmb", S_IFCHR, 0, DDI_PSEUDO,
	    NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "nsmb_attach: create minor");
		goto attach_failed;
	}
	if ((sdp = ddi_get_soft_state(statep, 0)) == NULL) {
		cmn_err(CE_WARN, "nsmb_attach: get soft state");
		ddi_remove_minor_node(dip, NULL);
		goto attach_failed;
	}

	/*
	 * Need to see if this field is required.
	 * REVISIT
	 */
	sdp->smb_dip = dip;
	sdp->sd_seq = 0;
	sdp->sd_opened = 1;

	mutex_exit(&dev_lck);
	ddi_report_dev(dip);
	return (DDI_SUCCESS);

attach_failed:
	ddi_soft_state_free(statep, 0);
	mutex_exit(&dev_lck);
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
nsmb_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);

	ddi_soft_state_free(statep, 0);
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
nsmb_ioctl(dev_t dev,
	    int cmd,
	    intptr_t arg,
	    int mode,
	    cred_t *credp,
	    int *rvalp)
{
	smb_dev_t *sdp;
	struct smb_vc *vcp = NULL;
	struct smb_share *ssp = NULL;
	struct smb_cred scred;
	int err, error;
	uid_t uid;

	/* Free any+all of these at end of switch. */
	smbioc_lookup_t *sioc = NULL;
	smbioc_rq_t *srq = NULL;
	smbioc_rw_t *rwrq = NULL;
	smbioc_t2rq_t *strq = NULL;
	smbioc_pk_t  *pk = NULL;

	sdp = ddi_get_soft_state(statep, getminor(dev));
	if (sdp == NULL) {
		return (DDI_FAILURE);
	}
	if ((sdp->sd_flags & NSMBFL_OPEN) == 0) {
		return (EBADF);
	}

	/*
	 * Dont give access if the zone id is not as the same as we
	 * set in the nsmb_open or dont belong to the global zone.
	 * Check if the user belongs to this zone..
	 */
	if (sdp->zoneid != getzoneid())
		return (EIO);
	if (cmd != SMBIOC_TDIS &&
	    zone_status_get(curproc->p_zone) >= ZONE_IS_SHUTTING_DOWN)
		return (EIO);


	error = 0;
	smb_credinit(&scred, curproc, credp);
	switch (cmd) {
		case SMBIOC_GETVERS:
			ddi_copyout(&nsmb_version, (void *)arg,
			    sizeof (nsmb_version), mode);
			break;

		case SMBIOC_REQUEST:
			if (sdp->sd_share == NULL) {
				error = ENOTCONN;
				break;
			}
			srq = kmem_alloc(sizeof (*srq), KM_SLEEP);
			if (ddi_copyin((void *) arg, srq,
			    sizeof (*srq), mode)) {
				error = EFAULT;
				break;
			}
			error = smb_usr_simplerequest(sdp->sd_share,
			    srq, &scred);
			ddi_copyout(srq, (void *)arg,
			    SMBIOC_RQ_COPYOUT_SIZE, mode);
			break;

		case SMBIOC_T2RQ:
			if (sdp->sd_share == NULL) {
				error = ENOTCONN;
				break;
			}
			strq = kmem_alloc(sizeof (*strq), KM_SLEEP);
			if (ddi_copyin((void *)arg, strq,
			    sizeof (*strq), mode)) {
				error = EFAULT;
				break;
			}
			error = smb_usr_t2request(sdp->sd_share, strq, &scred);
			ddi_copyout(strq, (void *)arg,
			    SMBIOC_T2RQ_COPYOUT_SIZE, mode);
			break;

		case SMBIOC_READ:
		case SMBIOC_WRITE:
			if ((ssp = sdp->sd_share) == NULL) {
				error = ENOTCONN;
				break;
			}
			rwrq = kmem_alloc(sizeof (*rwrq), KM_SLEEP);
			if (ddi_copyin((void *)arg, rwrq,
			    sizeof (*rwrq), mode)) {
				error = EFAULT;
				break;
			}
			error = smb_usr_rw(ssp, rwrq, cmd, &scred);
			ddi_copyout(rwrq, (void *)arg,
			    SMBIOC_RW_COPYOUT_SIZE, mode);
			break;

		case SMBIOC_FINDVC:
			/* Should be no VC and no share */
			if (sdp->sd_vc || sdp->sd_share) {
				error = EISCONN;
				break;
			}
			sioc = kmem_alloc(sizeof (*sioc), KM_SLEEP);
			if (ddi_copyin((void *)arg, sioc,
			    sizeof (*sioc), mode)) {
				error = EFAULT;
				break;
			}
			vcp = NULL;
			ssp = NULL;
			error = smb_usr_findvc(sioc, &scred, &vcp);
			if (error)
				break;
			if (vcp) {
				/*
				 * The VC has a hold from _findvc
				 * which we keep until nsmb_close().
				 */
				sdp->sd_level = SMBL_VC;
				sdp->sd_vc = vcp;
			}
			(void) ddi_copyout(sioc, (void *)arg,
			    SMBIOC_LOOK_COPYOUT_SIZE, mode);

			break;

		case SMBIOC_NEGOTIATE:
			/* Should be no VC (and no share) */
			if (sdp->sd_vc || sdp->sd_share) {
				error = EISCONN;
				break;
			}
			sioc = kmem_alloc(sizeof (*sioc), KM_SLEEP);
			if (ddi_copyin((void *)arg, sioc,
			    sizeof (*sioc), mode)) {
				error = EFAULT;
				break;
			}
			vcp = NULL;
			ssp = NULL;
			error = smb_usr_negotiate(sioc, &scred, &vcp);
			if (error)
				break;
			if (vcp) {
				/*
				 * The VC has a hold from _negotiate
				 * which we keep until nsmb_close().
				 */
				sdp->sd_level = SMBL_VC;
				sdp->sd_vc = vcp;
				/*
				 * If we just created this VC, and
				 * this minor is doing the setup,
				 * keep track of that fact here.
				 */
				if (vcp->vc_state < SMBIOD_ST_VCACTIVE)
					sdp->sd_flags |= NSMBFL_NEWVC;

			}
			/*
			 * Copyout the "out token" (security blob).
			 *
			 * This code used to be near the end of
			 * smb_usr_negotiate().  Moved the copyout
			 * calls here so we know the "mode"
			 */
			if (vcp->vc_outtok) {
				/*
				 * Note: will copyout sioc below
				 * including sioc.vc_outtoklen,
				 * so we no longer put the length
				 * at the start of the outtok data.
				 */
				sioc->ioc_ssn.ioc_outtoklen =
				    vcp->vc_outtoklen;
				err = ddi_copyout(
				    vcp->vc_outtok,
				    sioc->ioc_ssn.ioc_outtok,
				    vcp->vc_outtoklen, mode);
				if (err) {
					error = EFAULT;
					break;
				}
				/*
				 * Save this blob in vc_negtok.
				 * We need it in case we have to
				 * reconnect.
				 *
				 * Set vc_negtok = vc_outtok
				 * but free vc_negtok first.
				 */
				if (vcp->vc_negtok) {
					kmem_free(
					    vcp->vc_negtok,
					    vcp->vc_negtoklen);
					vcp->vc_negtok = NULL;
					vcp->vc_negtoklen = 0;
				}
				vcp->vc_negtok    = vcp->vc_outtok;
				vcp->vc_negtoklen = vcp->vc_outtoklen;
				vcp->vc_outtok = NULL;
				vcp->vc_outtoklen = 0;
			}
			/*
			 * Added copyout here of (almost)
			 * the whole struct, even though
			 * the lib only needs _outtoklen.
			 * We may put other things in this
			 * struct that user-land needs.
			 */
			err = ddi_copyout(sioc, (void *)arg,
			    SMBIOC_LOOK_COPYOUT_SIZE, mode);
			if (err)
				error = EFAULT;
			break;

		case SMBIOC_SSNSETUP:
			/* Must have a VC, but no share. */
			if (sdp->sd_share) {
				error = EISCONN;
				break;
			}
			if (!sdp->sd_vc) {
				error = ENOTCONN;
				break;
			}
			sioc = kmem_alloc(sizeof (*sioc), KM_SLEEP);
			if (ddi_copyin((void *)arg, sioc,
			    sizeof (*sioc), mode)) {
				error = EFAULT;
				break;
			}
			vcp = sdp->sd_vc;
			ssp = NULL;
			error = smb_usr_ssnsetup(sioc, &scred, vcp);
			if (error)
				break;
			/*
			 * If this minor has finished ssn setup,
			 * turn off the NEWVC flag, otherwise we
			 * will kill this VC when we close.
			 */
			if (vcp->vc_state == SMBIOD_ST_VCACTIVE)
				sdp->sd_flags &= ~NSMBFL_NEWVC;
			/*
			 * Copyout the "out token" (security blob).
			 *
			 * This code used to be near the end of
			 * smb_usr_ssnsetup().  Moved the copyout
			 * calls here so we know the "mode"
			 */
			if (vcp->vc_outtok) {
				/*
				 * Note: will copyout sioc below
				 * including sioc.vc_outtoklen,
				 * so we no longer put the length
				 * at the start of the outtok data.
				 */
				sioc->ioc_ssn.ioc_outtoklen =
				    vcp->vc_outtoklen;
				err = ddi_copyout(
				    vcp->vc_outtok,
				    sioc->ioc_ssn.ioc_outtok,
				    vcp->vc_outtoklen, mode);
				if (err) {
					error = EFAULT;
					break;
				}
				/*
				 * Done with vc_outtok.  Similar,
				 * but NOT the same as after the
				 * smb_usr_negotiate call above.
				 */
				kmem_free(
				    vcp->vc_outtok,
				    vcp->vc_outtoklen);
				vcp->vc_outtok = NULL;
				vcp->vc_outtoklen = 0;
			}
			/* Added copyout here... (see above) */
			err = ddi_copyout(sioc, (void *)arg,
			    SMBIOC_LOOK_COPYOUT_SIZE, mode);
			if (err)
				error = EFAULT;
			break;

		case SMBIOC_TCON:
			/* Must have a VC, but no share. */
			if (sdp->sd_share) {
				error = EISCONN;
				break;
			}
			if (!sdp->sd_vc) {
				error = ENOTCONN;
				break;
			}
			sioc = kmem_alloc(sizeof (*sioc), KM_SLEEP);
			if (ddi_copyin((void *)arg, sioc,
			    sizeof (*sioc), mode)) {
				error = EFAULT;
				break;
			}
			vcp = sdp->sd_vc;
			ssp = NULL;
			error = smb_usr_tcon(sioc, &scred, vcp, &ssp);
			if (error)
				break;
			if (ssp) {
				/*
				 * The share has a hold from _tcon
				 * which we keep until nsmb_close()
				 * or the SMBIOC_TDIS below.
				 */
				sdp->sd_share = ssp;
				sdp->sd_level = SMBL_SHARE;
			}
			/* No need for copyout here. */
			break;

		case SMBIOC_TDIS:
			if (sdp->sd_share == NULL) {
				error = ENOTCONN;
				break;
			}
			smb_share_rele(sdp->sd_share);
			sdp->sd_share = NULL;
			sdp->sd_level = SMBL_VC;
			break;
		case SMBIOC_FLAGS2:
			if (sdp->sd_share == NULL) {
				error = ENOTCONN;
				break;
			}
			if (!sdp->sd_vc) {
				error = ENOTCONN;
				break;
			}
			vcp = sdp->sd_vc;
			/*
			 * Return the flags2 value.
			 */
			ddi_copyout(&vcp->vc_hflags2, (void *)arg,
			    sizeof (u_int16_t), mode);
			break;

		case SMBIOC_PK_ADD:
			pk = kmem_alloc(sizeof (*pk), KM_SLEEP);
			if (ddi_copyin((void *)arg, pk,
			    sizeof (*pk), mode)) {
				error = EFAULT;
				break;
			}
			error = smb_pkey_add(pk, credp);
			break;

		case SMBIOC_PK_DEL:
			pk = kmem_alloc(sizeof (*pk), KM_SLEEP);
			if (ddi_copyin((void *)arg, pk,
			    sizeof (*pk), mode)) {
				error = EFAULT;
				break;
			}
			error = smb_pkey_del(pk, credp);
			break;

		case SMBIOC_PK_CHK:
			pk = kmem_alloc(sizeof (*pk), KM_SLEEP);
			if (ddi_copyin((void *)arg, pk,
			    sizeof (*pk), mode)) {
				error = EFAULT;
				break;
			}
			error = smb_pkey_check(pk, credp);
			/*
			 * Note: Intentionally DO NOT copyout
			 * the pasword here.  It can only be
			 * retrieved by internal calls.  This
			 * ioctl only tells the caller if the
			 * keychain entry exists.
			 */
			break;

		case SMBIOC_PK_DEL_OWNER:
			uid = crgetruid(credp);
			error = smb_pkey_deluid(uid, credp);
			break;

		case SMBIOC_PK_DEL_EVERYONE:
			uid = (uid_t)-1;
			error = smb_pkey_deluid(uid, credp);
			break;

		default:
			error = ENODEV;
	}

	/*
	 * Let's just do all the kmem_free stuff HERE,
	 * instead of at every switch break.
	 */

	/* SMBIOC_REQUEST */
	if (srq)
		kmem_free(srq, sizeof (*srq));

	/* SMBIOC_T2RQ */
	if (strq)
		kmem_free(strq, sizeof (*strq));

	/* SMBIOC_READ */
	/* SMBIOC_WRITE */
	if (rwrq)
		kmem_free(rwrq, sizeof (*rwrq));

	/* SMBIOC_FINDVC */
	/* SMBIOC_NEGOTIATE */
	/* SMBIOC_SSNSETUP */
	/* SMBIOC_TCON */
	if (sioc) {
		/*
		 * This data structure may contain
		 * cleartext passwords, so zap it.
		 */
		bzero(sioc, sizeof (*sioc));
		kmem_free(sioc, sizeof (*sioc));
	}

	/* SMBIOC_PK_... */
	if (pk) {
		/*
		 * This data structure may contain
		 * cleartext passwords, so zap it.
		 */
		bzero(pk, sizeof (*pk));
		kmem_free(pk, sizeof (*pk));
	}

	smb_credrele(&scred);

	return (error);
}

/*ARGSUSED*/
static int
nsmb_open(dev_t *dev, int flags, int otyp, cred_t *cr)
{
	major_t new_major;
	smb_dev_t *sdp, *sdv;

	mutex_enter(&dev_lck);
	for (; ; ) {
		minor_t start = nsmb_minor;
		do {
			if (nsmb_minor >= MAXMIN32) {
				if (nsmb_major == getmajor(*dev))
					nsmb_minor = NSMB_MIN_MINOR;
				else
					nsmb_minor = 0;
			} else {
				nsmb_minor++;
			}
			sdv = ddi_get_soft_state(statep, nsmb_minor);
		} while ((sdv != NULL) && (nsmb_minor != start));
		if (nsmb_minor == start) {
			/*
			 * The condition we need to solve here is  all the
			 * MAXMIN32(~262000) minors numbers are reached. We
			 * need to create a new major number.
			 * zfs uses getudev() to create a new major number.
			 */
			if ((new_major = getudev()) == (major_t)-1) {
				cmn_err(CE_WARN,
				    "nsmb: Can't get unique major "
				    "device number.");
				mutex_exit(&dev_lck);
				return (-1);
			}
			nsmb_major = new_major;
			nsmb_minor = 0;
		} else {
			break;
		}
	}

	/*
	 * This is called by mount or open call.
	 * The open() routine is passed a pointer to a device number so
	 * that  the  driver  can  change the minor number. This allows
	 * drivers to dynamically  create minor instances of  the  dev-
	 * ice.  An  example of this might be a  pseudo-terminal driver
	 * that creates a new pseudo-terminal whenever it   is  opened.
	 * A driver that chooses the minor number dynamically, normally
	 * creates only one  minor  device  node  in   attach(9E)  with
	 * ddi_create_minor_node(9F) then changes the minor number com-
	 * ponent of *devp using makedevice(9F)  and  getmajor(9F)  The
	 * driver needs to keep track of available minor numbers inter-
	 * nally.
	 * Stuff the structure smb_dev.
	 * return.
	 */

	if (ddi_soft_state_zalloc(statep, nsmb_minor) == DDI_FAILURE) {
		mutex_exit(&dev_lck);
		return (ENXIO);
	}
	if ((sdp = ddi_get_soft_state(statep, nsmb_minor)) == NULL) {
		mutex_exit(&dev_lck);
		return (ENXIO);
	}

	sdp->sd_opened = 1;
	sdp->sd_seq = nsmb_minor;
	sdp->smb_cred = cr;
	sdp->sd_flags |= NSMBFL_OPEN;
	sdp->zoneid = crgetzoneid(cr);
	mutex_exit(&dev_lck);

	*dev = makedevice(nsmb_major, nsmb_minor);

	return (0);
}

/*ARGSUSED*/
static int
nsmb_close(dev_t dev, int flags, int otyp, cred_t *cr)
{
	struct smb_vc *vcp;
	struct smb_share *ssp;
	struct smb_cred scred;
	minor_t inst = getminor(dev);
	smb_dev_t *sdp;

	mutex_enter(&dev_lck);
	/*
	 * 1. Check the validity of the minor number.
	 * 2. Release any shares/vc associated  with the connection.
	 * 3. Can close the minor number.
	 * 4. Deallocate any resources allocated in open() call.
	 */
	smb_credinit(&scred, curproc, cr);

	sdp = ddi_get_soft_state(statep, inst);

	/*
	 * time to call ddi_get_soft_state()
	 */
	ssp = sdp->sd_share;
	if (ssp != NULL)
		smb_share_rele(ssp);
	vcp = sdp->sd_vc;
	if (vcp != NULL) {
		/*
		 * If this dev minor was doing session setup
		 * and failed to authenticate (or whatever)
		 * then we need to put the VC in a state that
		 * allows later commands to try again.
		 */
		if (sdp->sd_flags & NSMBFL_NEWVC)
			smb_iod_disconnect(vcp);
		smb_vc_rele(vcp);
	}
	smb_credrele(&scred);

	/*
	 * Free the instance
	 */
	ddi_soft_state_free(statep, inst);
	mutex_exit(&dev_lck);
	return (0);
}

int
smb_dev2share(int fd, struct smb_share **sspp)
{
	register vnode_t *vp;
	smb_dev_t *sdp;
	struct smb_share *ssp;
	dev_t dev;
	file_t *fp;

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));
	vp = fp->f_vnode;
	dev = vp->v_rdev;
	if (dev == NULL) {
		releasef(fd);
		return (EBADF);
	}
	sdp = ddi_get_soft_state(statep, getminor(dev));
	if (sdp == NULL) {
		releasef(fd);
		return (DDI_FAILURE);
	}
	ssp = sdp->sd_share;
	if (ssp == NULL) {
		releasef(fd);
		return (ENOTCONN);
	}
	/*
	 * The share is already locked and referenced by the TCON ioctl
	 * We NULL to hand off share to caller (mount)
	 * This allows further ioctls against connection, for instance
	 * another tree connect and mount, in the automounter case
	 *
	 * We're effectively giving our reference to the mount.
	 *
	 * XXX: I'm not sure I like this.  I'd rather see the ioctl
	 * caller do something explicit to give up this reference,
	 * (i.e. SMBIOC_TDIS above) and increment the hold here.
	 */
	sdp->sd_share = NULL;
	releasef(fd);
	*sspp = ssp;
	return (0);
}
