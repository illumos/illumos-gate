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
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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
#include <sys/socket.h>
#include <sys/zone.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/mchain.h>		/* for "htoles()" */

#include <netsmb/smb.h>
#include <netsmb/smb2.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>
#include <netsmb/smb_pass.h>

#ifndef	_KERNEL
#include <libfknsmb.h>

#define	_init(v)	nsmb_drv_init(v)
#define	_fini(v)	nsmb_drv_fini(v)

#endif	/* _KERNEL */

#define	NSMB_MIN_MINOR	1
#define	NSMB_MAX_MINOR	L_MAXMIN32

/* for version checks */
const uint32_t nsmb_version = NSMB_VERSION;

/* for smb_nbst_create() */
dev_t nsmb_dev_tcp = NODEV;
dev_t nsmb_dev_tcp6 = NODEV;

static void *statep;
static major_t nsmb_major;
static minor_t last_minor = NSMB_MIN_MINOR;
static kmutex_t  dev_lck;

/*
 * cb_ops device operations.
 */
static int nsmb_open(dev_t *devp, int flag, int otyp, cred_t *credp);
static int nsmb_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int nsmb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
				cred_t *credp, int *rvalp);
static int nsmb_close2(smb_dev_t *sdp, cred_t *cr);

#ifdef	_KERNEL

static dev_info_t *nsmb_dip;

/* Zone support */
zone_key_t nsmb_zone_key;
extern void nsmb_zone_shutdown(zoneid_t zoneid, void *data);
extern void nsmb_zone_destroy(zoneid_t zoneid, void *data);

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
	NULL,		/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

/*
 * Module linkage information.
 */

static struct modldrv nsmb_modldrv = {
	&mod_driverops,				/* Driver module */
	"SMBFS network driver",
	&nsmb_ops				/* Driver ops */
};

static struct modlinkage nsmb_modlinkage = {
	MODREV_1,
	(void *)&nsmb_modldrv,
	NULL
};

#endif	/* _KERNEL */

int
_init(void)
{
#ifdef	_KERNEL
	int error;
#endif	/* _KERNEL */

	(void) ddi_soft_state_init(&statep, sizeof (smb_dev_t), 1);

	/* Can initialize some mutexes also. */
	mutex_init(&dev_lck, NULL, MUTEX_DRIVER, NULL);

	/* Connection data structures. */
	(void) smb_sm_init();

	/* Initialize password Key chain DB. */
	smb_pkey_init();

#ifdef	_KERNEL
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
#else	/* _KERNEL */
	streams_msg_init();
	/* No attach, so need to set major. */
	nsmb_major = 1;
	/* And these, for smb_nbst_create() */
	nsmb_dev_tcp = AF_INET;
	nsmb_dev_tcp6 = AF_INET6;
#endif	/* _KERNEL */

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

#ifdef	_KERNEL
	/*
	 * Remove the module.  Do this before destroying things,
	 * to prevent new entrances while we're destorying.
	 */
	if ((status = mod_remove(&nsmb_modlinkage)) != 0) {
		return (status);
	}

	(void) zone_key_delete(nsmb_zone_key);
#endif	/* _KERNEL */

	/* Destroy password Key chain DB. */
	smb_pkey_fini();

	smb_sm_done();

	mutex_destroy(&dev_lck);
	ddi_soft_state_fini(&statep);

	return (status);
}

#ifdef	_KERNEL

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
		*result = nsmb_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		break;
	default:
		ret = DDI_FAILURE;
	}
	return (ret);
}

static int
nsmb_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	major_t tmaj;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * We only support only one "instance".  Note that
	 * "instances" are different from minor units.
	 * We get one (unique) minor unit per open.
	 */
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "nsmb", S_IFCHR, 0, DDI_PSEUDO,
	    NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "nsmb_attach: create minor");
		return (DDI_FAILURE);
	}

	/*
	 * We need the major number a couple places,
	 * i.e. in smb_dev2share()
	 */
	nsmb_major = ddi_name_to_major(NSMB_NAME);

	/*
	 * We also need major numbers for t_kopen
	 */
	tmaj = ddi_name_to_major("tcp");
	if (tmaj == DDI_MAJOR_T_NONE)
		cmn_err(CE_NOTE, "no tcp major?");
	else
		nsmb_dev_tcp = makedevice(tmaj, 0);
	tmaj = ddi_name_to_major("tcp6");
	if (tmaj == DDI_MAJOR_T_NONE)
		cmn_err(CE_NOTE, "no tcp6 major?");
	else
		nsmb_dev_tcp6 = makedevice(tmaj, 0);

	nsmb_dip = dip;
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
nsmb_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);

	nsmb_dip = NULL;
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

#else	/* _KERNEL */

/*
 * Wrappers for libfknsmb: ioctl, open, close, load
 */

/*ARGSUSED*/
int
nsmb_drv_ioctl(dev32_t dev32, int cmd, intptr_t arg, int flags)
{
	dev_t dev = expldev(dev32);
	cred_t *cr = CRED();
	int err;

	err = nsmb_ioctl(dev, cmd, arg, flags, cr, NULL);
	return (err);
}

/*ARGSUSED*/
int
nsmb_drv_open(dev32_t *dev32p, int flags, int otyp)
{
	dev_t dev = expldev(*dev32p);
	int err;

	err = nsmb_open(&dev, flags, otyp, CRED());
	if (err == 0) {
		/*
		 * We have NSMB_MAX_MINOR == L_MAXMIN32
		 * therefore cmpldev never fails.
		 */
		VERIFY(cmpldev(dev32p, dev) != 0);
	}
	return (err);
}

/*ARGSUSED*/
int
nsmb_drv_close(dev32_t dev32, int flags, int otyp)
{
	dev_t dev = expldev(dev32);
	int err;

	err = nsmb_close(dev, flags, otyp, CRED());
	return (err);
}

/*
 * This function intentionally does nothing.  It's used only to
 * force libfknsmb to load at program start so one can set
 * breakpoints etc. without debugger "force load" tricks.
 */
void
nsmb_drv_load(void)
{
}

#endif	/* _KERNEL */

/*ARGSUSED*/
static int
nsmb_ioctl(dev_t dev, int cmd, intptr_t arg, int flags,	/* model.h */
    cred_t *cr, int *rvalp)
{
	smb_dev_t *sdp;
	int err;

	sdp = ddi_get_soft_state(statep, getminor(dev));
	if (sdp == NULL) {
		return (EBADF);
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

	/*
	 * We have a zone_shutdown call back that kills all the VCs
	 * in a zone that's shutting down.  That action will cause
	 * all of these ioctls to fail on such VCs, so no need to
	 * check the zone status here on every ioctl call.
	 */

	err = smb_usr_ioctl(sdp, cmd, arg, flags, cr);

	return (err);
}

/*
 * This does "clone" open, meaning it automatically
 * assigns an available minor unit for each open.
 */
/*ARGSUSED*/
static int
nsmb_open(dev_t *dev, int flags, int otyp, cred_t *cr)
{
	smb_dev_t *sdp;
	minor_t m;

	mutex_enter(&dev_lck);

	for (m = last_minor + 1; m != last_minor; m++) {
		if (m > NSMB_MAX_MINOR)
			m = NSMB_MIN_MINOR;

		if (ddi_get_soft_state(statep, m) == NULL) {
			last_minor = m;
			goto found;
		}
	}

	/* No available minor units. */
	mutex_exit(&dev_lck);
	return (ENXIO);

found:
	/* NB: dev_lck still held */
	if (ddi_soft_state_zalloc(statep, m) == DDI_FAILURE) {
		mutex_exit(&dev_lck);
		return (ENXIO);
	}
	if ((sdp = ddi_get_soft_state(statep, m)) == NULL) {
		mutex_exit(&dev_lck);
		return (ENXIO);
	}
	*dev = makedevice(nsmb_major, m);
	mutex_exit(&dev_lck);

	sdp->sd_flags |= NSMBFL_OPEN;
	sdp->zoneid = crgetzoneid(cr);
	mutex_init(&sdp->sd_lock, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

/*ARGSUSED*/
static int
nsmb_close(dev_t dev, int flags, int otyp, cred_t *cr)
{
	minor_t inst = getminor(dev);
	smb_dev_t *sdp;
	int err;

	/*
	 * 1. Check the validity of the minor number.
	 * 2. Release any shares/vc associated  with the connection.
	 * 3. Can close the minor number.
	 * 4. Deallocate any resources allocated in open() call.
	 */

	sdp = ddi_get_soft_state(statep, inst);
	if (sdp != NULL)
		err = nsmb_close2(sdp, cr);
	else
		err = ENXIO;

	/*
	 * Free the instance
	 */
	mutex_enter(&dev_lck);
	ddi_soft_state_free(statep, inst);
	mutex_exit(&dev_lck);
	return (err);
}

/*ARGSUSED*/
static int
nsmb_close2(smb_dev_t *sdp, cred_t *cr)
{
	struct smb_vc *vcp;
	struct smb_share *ssp;
	struct smb_fh *fhp;

	fhp = sdp->sd_fh;
	if (fhp != NULL)
		smb_fh_rele(fhp);

	ssp = sdp->sd_share;
	if (ssp != NULL)
		smb_share_rele(ssp);

	vcp = sdp->sd_vc;
	if (vcp != NULL) {
		/*
		 * If this dev minor was opened by smbiod,
		 * mark this VC as "dead" because it now
		 * will have no IOD to service it.
		 */
		if (sdp->sd_flags & NSMBFL_IOD)
			smb_iod_disconnect(vcp);
		smb_vc_rele(vcp);
	}
	mutex_destroy(&sdp->sd_lock);

	return (0);
}

/*
 * Helper for SMBIOC_DUP_DEV
 * Duplicate state from the FD @arg ("from") onto
 * the FD for this device instance.
 */
int
smb_usr_dup_dev(smb_dev_t *sdp, intptr_t arg, int flags)
{
#ifdef	_KERNEL
	file_t *fp = NULL;
	vnode_t *vp;
#endif	/* _KERNEL */
	smb_dev_t *from_sdp;
	dev_t dev;
	int32_t ufd;
	int err;

	/* Should be no VC */
	if (sdp->sd_vc != NULL)
		return (EISCONN);

	/*
	 * Get from_sdp (what we will duplicate)
	 */
	if (ddi_copyin((void *) arg, &ufd, sizeof (ufd), flags))
		return (EFAULT);
#ifdef	_KERNEL
	if ((fp = getf(ufd)) == NULL)
		return (EBADF);
	/* rele fp below */
	vp = fp->f_vnode;
	dev = vp->v_rdev;
#else	/* _KERNEL */
	/*
	 * No getf(ufd) -- ufd is really a dev32_t
	 */
	dev = expldev((dev32_t)ufd);
#endif	/* _KERNEL */
	if (dev == 0 || dev == NODEV ||
	    getmajor(dev) != nsmb_major) {
		err = EINVAL;
		goto out;
	}

	from_sdp = ddi_get_soft_state(statep, getminor(dev));
	if (from_sdp == NULL) {
		err = EINVAL;
		goto out;
	}

	/*
	 * Duplicate VC and share references onto this FD.
	 */
	if ((sdp->sd_vc = from_sdp->sd_vc) != NULL)
		smb_vc_hold(sdp->sd_vc);
	if ((sdp->sd_share = from_sdp->sd_share) != NULL)
		smb_share_hold(sdp->sd_share);
	sdp->sd_level = from_sdp->sd_level;
	err = 0;

out:
#ifdef	_KERNEL
	if (fp)
		releasef(ufd);
#endif	/* _KERNEL */
	return (err);
}


/*
 * Helper used by smbfs_mount
 */
int
smb_dev2share(int fd, struct smb_share **sspp)
{
#ifdef	_KERNEL
	file_t *fp = NULL;
	vnode_t *vp;
#endif	/* _KERNEL */
	smb_dev_t *sdp;
	smb_share_t *ssp;
	dev_t dev;
	int err;

#ifdef	_KERNEL
	if ((fp = getf(fd)) == NULL)
		return (EBADF);
	/* rele fp below */
	vp = fp->f_vnode;
	dev = vp->v_rdev;
#else	/* _KERNEL */
	/*
	 * No getf(ufd) -- fd is really a dev32_t
	 */
	dev = expldev((dev32_t)fd);
#endif	/* _KERNEL */
	if (dev == 0 || dev == NODEV ||
	    getmajor(dev) != nsmb_major) {
		err = EINVAL;
		goto out;
	}

	sdp = ddi_get_soft_state(statep, getminor(dev));
	if (sdp == NULL) {
		err = EINVAL;
		goto out;
	}

	ssp = sdp->sd_share;
	if (ssp == NULL) {
		err = ENOTCONN;
		goto out;
	}

	/*
	 * Our caller gains a ref. to this share.
	 */
	*sspp = ssp;
	smb_share_hold(ssp);
	err = 0;

out:
#ifdef	_KERNEL
	if (fp)
		releasef(fd);
#endif	/* _KERNEL */
	return (err);
}
