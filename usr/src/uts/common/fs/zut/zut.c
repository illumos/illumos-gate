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

#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/pathname.h>
#include <sys/proc.h>
#include <sys/mode.h>
#include <sys/vnode.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/uio.h>
#include <sys/attr.h>
#include <sys/acl.h>
#include <sys/fs/zut.h>

ldi_ident_t zut_li = NULL;
dev_info_t *zut_dip;

static int
zut_open_dir(char *path, vnode_t *startvp, cred_t *cr, int flags,
    pathname_t *realpn, vnode_t **dvn)
{
	pathname_t pn;
	vnode_t *vp;
	vnode_t *rootvp;
	proc_t *p = curproc;
	int error;

	pn_alloc(&pn);
	(void) strlcpy(pn.pn_buf, path, MAXPATHLEN);
	pn.pn_pathlen = strlen(path);

	mutex_enter(&p->p_lock);	/* for u_rdir and u_cdir */
	if ((rootvp = PTOU(p)->u_rdir) == NULL)
		rootvp = rootdir;
	else if (rootvp != rootdir)	/* no need to VN_HOLD rootdir */
		VN_HOLD(rootvp);

	if (pn.pn_path[0] == '/') {
		vp = rootvp;
	} else {
		vp = (startvp == NULL) ? PTOU(p)->u_cdir : startvp;
	}
	VN_HOLD(vp);
	mutex_exit(&p->p_lock);

	/*
	 * Skip over leading slashes
	 */
	while (pn.pn_path[0] == '/') {
		pn.pn_path++;
		pn.pn_pathlen--;
	}

	error = lookuppnvp(&pn, realpn, flags | FOLLOW, NULL,
	    dvn, rootvp, vp, cr);

	/*
	 * If we lack read access to the directory, we should error out.
	 */
	if (!error) {
		if (vfs_has_feature((*dvn)->v_vfsp, VFSFT_ACEMASKONACCESS)) {
			error = VOP_ACCESS(*dvn, ACE_LIST_DIRECTORY,
			    V_ACE_MASK, cr, NULL);
		} else {
			error = VOP_ACCESS(*dvn, VREAD, 0, cr, NULL);
		}
	}

	pn_free(&pn);

	return (error);
}

static int
zut_readdir(intptr_t arg, cred_t *cr, int iflag, int *rvalp)
{
	zut_readdir_t *zr;
	struct iovec aiov;
	struct uio auio;
	vnode_t *dvn = NULL;
	vnode_t *fvn = NULL;
	char *kbuf;
	int flags = 0;
	int error, rc;

	zr = kmem_zalloc(sizeof (zut_readdir_t), KM_SLEEP);
	error = ddi_copyin((void *)arg, zr, sizeof (zut_readdir_t), iflag);
	if (error)
		goto zutr_bail;

	kbuf = kmem_zalloc(zr->zr_buflen, KM_SLEEP);

	zr->zr_retcode = zut_open_dir(zr->zr_dir, NULL, cr, flags, NULL, &dvn);
	if (zr->zr_retcode)
		goto zutr_done;

	if (zr->zr_reqflags & ZUT_XATTR) {
		vattr_t vattr;

		zr->zr_retcode = VOP_LOOKUP(dvn, zr->zr_file, &fvn,
		    NULL, flags, NULL, cr, NULL, NULL, NULL);
		VN_RELE(dvn);
		dvn = NULL;
		if (zr->zr_retcode)
			goto zutr_done;

		/*
		 * In order to access hidden attribute directory the
		 * user must have appropriate read access and be able
		 * to stat() the file
		 */
		if (vfs_has_feature(fvn->v_vfsp, VFSFT_ACEMASKONACCESS)) {
			zr->zr_retcode = VOP_ACCESS(fvn, ACE_READ_NAMED_ATTRS,
			    V_ACE_MASK, cr, NULL);
		} else {
			zr->zr_retcode = VOP_ACCESS(fvn, VREAD, 0, cr, NULL);
		}
		if (zr->zr_retcode)
			goto zutr_done;

		vattr.va_mask = AT_ALL;
		zr->zr_retcode = VOP_GETATTR(fvn, &vattr, 0, cr, NULL);
		if (zr->zr_retcode)
			goto zutr_done;

		zr->zr_retcode = VOP_LOOKUP(fvn, "", &dvn, NULL,
		    flags | LOOKUP_XATTR, NULL, cr, NULL, NULL, NULL);
		VN_RELE(fvn);
		if (zr->zr_retcode)
			goto zutr_done;
	}

	aiov.iov_base = kbuf;
	aiov.iov_len = zr->zr_buflen;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = zr->zr_loffset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_resid = zr->zr_buflen;
	auio.uio_fmode = 0;
	auio.uio_extflg = UIO_COPY_CACHED;

	if (zr->zr_reqflags & ZUT_EXTRDDIR)
		flags |= V_RDDIR_ENTFLAGS;
	if (zr->zr_reqflags & ZUT_ACCFILTER)
		flags |= V_RDDIR_ACCFILTER;

	(void) VOP_RWLOCK(dvn, V_WRITELOCK_FALSE, NULL);
	zr->zr_retcode = VOP_READDIR(dvn, &auio, cr, &zr->zr_eof,
	    NULL, flags);
	VOP_RWUNLOCK(dvn, V_WRITELOCK_FALSE, NULL);
	VN_RELE(dvn);

	zr->zr_bytes = aiov.iov_base - kbuf;
	zr->zr_loffset = auio.uio_loffset;

	error = ddi_copyout(kbuf, (void *)(uintptr_t)zr->zr_buf,
	    zr->zr_buflen, iflag);

zutr_done:
	kmem_free(kbuf, zr->zr_buflen);
	rc = ddi_copyout(zr, (void *)arg, sizeof (zut_readdir_t), iflag);
	if (error == 0)
		error = rc;

zutr_bail:
	kmem_free(zr, sizeof (zut_readdir_t));
	if (rvalp)
		*rvalp = error;
	return (error);
}

static int
zut_stat64(vnode_t *vp, struct stat64 *sb, uint64_t *xvs, int flag, cred_t *cr)
{
	xoptattr_t *xoap = NULL;
	xvattr_t xv = { 0 };
	int error;

	xva_init(&xv);

	XVA_SET_REQ(&xv, XAT_ARCHIVE);
	XVA_SET_REQ(&xv, XAT_SYSTEM);
	XVA_SET_REQ(&xv, XAT_READONLY);
	XVA_SET_REQ(&xv, XAT_HIDDEN);
	XVA_SET_REQ(&xv, XAT_NOUNLINK);
	XVA_SET_REQ(&xv, XAT_IMMUTABLE);
	XVA_SET_REQ(&xv, XAT_APPENDONLY);
	XVA_SET_REQ(&xv, XAT_NODUMP);
	XVA_SET_REQ(&xv, XAT_OPAQUE);
	XVA_SET_REQ(&xv, XAT_AV_QUARANTINED);
	XVA_SET_REQ(&xv, XAT_AV_MODIFIED);
	XVA_SET_REQ(&xv, XAT_REPARSE);

	xv.xva_vattr.va_mask |= AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;
	if (error = VOP_GETATTR(vp, &xv.xva_vattr, flag, cr, NULL))
		return (error);

	bzero(sb, sizeof (sb));
	sb->st_dev = xv.xva_vattr.va_fsid;
	sb->st_ino = xv.xva_vattr.va_nodeid;
	sb->st_mode = VTTOIF(xv.xva_vattr.va_type) | xv.xva_vattr.va_mode;
	sb->st_nlink = xv.xva_vattr.va_nlink;
	sb->st_uid = xv.xva_vattr.va_uid;
	sb->st_gid = xv.xva_vattr.va_gid;
	sb->st_rdev = xv.xva_vattr.va_rdev;
	sb->st_size = xv.xva_vattr.va_size;
	sb->st_atim = xv.xva_vattr.va_atime;
	sb->st_mtim = xv.xva_vattr.va_mtime;
	sb->st_ctim = xv.xva_vattr.va_ctime;
	sb->st_blksize = xv.xva_vattr.va_blksize;
	sb->st_blocks = xv.xva_vattr.va_nblocks;
	sb->st_fstype[0] = 0;

	if ((xoap = xva_getxoptattr(&xv)) == NULL)
		return (0);

	if (XVA_ISSET_RTN(&xv, XAT_ARCHIVE) && xoap->xoa_archive)
		*xvs |= (1 << F_ARCHIVE);
	if (XVA_ISSET_RTN(&xv, XAT_SYSTEM) && xoap->xoa_system)
		*xvs |= (1 << F_SYSTEM);
	if (XVA_ISSET_RTN(&xv, XAT_READONLY) && xoap->xoa_readonly)
		*xvs |= (1 << F_READONLY);
	if (XVA_ISSET_RTN(&xv, XAT_HIDDEN) && xoap->xoa_hidden)
		*xvs |= (1 << F_HIDDEN);
	if (XVA_ISSET_RTN(&xv, XAT_NOUNLINK) && xoap->xoa_nounlink)
		*xvs |= (1 << F_NOUNLINK);
	if (XVA_ISSET_RTN(&xv, XAT_IMMUTABLE) && xoap->xoa_immutable)
		*xvs |= (1 << F_IMMUTABLE);
	if (XVA_ISSET_RTN(&xv, XAT_APPENDONLY) && xoap->xoa_appendonly)
		*xvs |= (1 << F_APPENDONLY);
	if (XVA_ISSET_RTN(&xv, XAT_NODUMP) && xoap->xoa_nodump)
		*xvs |= (1 << F_NODUMP);
	if (XVA_ISSET_RTN(&xv, XAT_OPAQUE) && xoap->xoa_opaque)
		*xvs |= (1 << F_OPAQUE);
	if (XVA_ISSET_RTN(&xv, XAT_AV_QUARANTINED) && xoap->xoa_av_quarantined)
		*xvs |= (1 << F_AV_QUARANTINED);
	if (XVA_ISSET_RTN(&xv, XAT_AV_MODIFIED) && xoap->xoa_av_modified)
		*xvs |= (1 << F_AV_MODIFIED);
	if (XVA_ISSET_RTN(&xv, XAT_REPARSE) && xoap->xoa_reparse)
		*xvs |= (1 << F_REPARSE);

	return (0);
}

/*ARGSUSED*/
static int
zut_lookup(intptr_t arg, cred_t *cr, int iflag, int *rvalp)
{
	zut_lookup_t *zl;
	pathname_t rpn;
	vnode_t *dvn = NULL;
	vnode_t *fvn = NULL;
	vnode_t *xdvn = NULL;
	vnode_t *xfvn = NULL;
	vnode_t *release = NULL;
	int flags = 0;
	int error, rc;

	zl = kmem_zalloc(sizeof (zut_lookup_t), KM_SLEEP);

	error = ddi_copyin((void *)arg, zl, sizeof (zut_lookup_t), iflag);
	if (error)
		goto zutl_bail;

	pn_alloc(&rpn);
	bzero(rpn.pn_buf, MAXPATHLEN);

	zl->zl_retcode = zut_open_dir(zl->zl_dir, NULL, cr, flags, &rpn, &dvn);
	if (zl->zl_retcode)
		goto zutl_done;

	if (zl->zl_reqflags & ZUT_IGNORECASE)
		flags |= FIGNORECASE;

	zl->zl_retcode = VOP_LOOKUP(dvn, zl->zl_file, &fvn, NULL, flags, NULL,
	    cr, NULL, &zl->zl_deflags, &rpn);
	if (zl->zl_retcode)
		goto zutl_done;

	release = fvn;

	if (zl->zl_reqflags & ZUT_XATTR) {
		vattr_t vattr;

		/*
		 * In order to access hidden attribute directory the
		 * user must have appropriate read access and be able
		 * to stat() the file
		 */
		if (vfs_has_feature(fvn->v_vfsp, VFSFT_ACEMASKONACCESS)) {
			zl->zl_retcode = VOP_ACCESS(fvn, ACE_READ_NAMED_ATTRS,
			    V_ACE_MASK, cr, NULL);
		} else {
			zl->zl_retcode = VOP_ACCESS(fvn, VREAD, 0, cr, NULL);
		}
		if (zl->zl_retcode)
			goto zutl_done;

		vattr.va_mask = AT_ALL;
		zl->zl_retcode = VOP_GETATTR(fvn, &vattr, 0, cr, NULL);
		if (zl->zl_retcode)
			goto zutl_done;

		zl->zl_retcode = VOP_LOOKUP(fvn, "", &xdvn, NULL,
		    flags | LOOKUP_XATTR, NULL, cr, NULL, NULL, NULL);
		if (zl->zl_retcode)
			goto zutl_done;
		VN_RELE(fvn);
		release = xdvn;

		zl->zl_retcode = VOP_LOOKUP(xdvn, zl->zl_xfile, &xfvn,
		    NULL, flags, NULL, cr, NULL, &zl->zl_deflags, &rpn);
		if (zl->zl_retcode)
			goto zutl_done;
		VN_RELE(xdvn);
		release = xfvn;
	}

	if (zl->zl_reqflags & ZUT_GETSTAT) {
		zl->zl_retcode = zut_stat64(release,
		    &zl->zl_statbuf, &zl->zl_xvattrs, 0, cr);
	}

zutl_done:
	(void) strlcpy(zl->zl_real, rpn.pn_path, MAXPATHLEN);

	rc = ddi_copyout(zl, (void *)arg, sizeof (zut_lookup_t), iflag);
	if (error == 0)
		error = rc;

	if (release)
		VN_RELE(release);
	if (dvn)
		VN_RELE(dvn);
	pn_free(&rpn);

zutl_bail:
	kmem_free(zl, sizeof (zut_lookup_t));
	if (rvalp)
		*rvalp = error;
	return (error);
}

/*ARGSUSED*/
static int
zut_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cr, int *rvalp)
{
	int error;

	if (getminor(dev) != 0)
		return (ENXIO);

	if (cmd <= ZUT_IOC_MIN_CMD || cmd >= ZUT_IOC_MAX_CMD)
		return (EINVAL);

	switch (cmd) {
	case ZUT_IOC_LOOKUP:
		error = zut_lookup(arg, cr, flag, rvalp);
		break;
	case ZUT_IOC_READDIR:
		error = zut_readdir(arg, cr, flag, rvalp);
	default:
		break;
	}

	return (error);
}

static int
zut_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "zut", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE)
		return (DDI_FAILURE);

	zut_dip = dip;

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
zut_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	zut_dip = NULL;

	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
zut_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = zut_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
zut_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	minor_t minor = getminor(*devp);

	if (minor == 0)			/* This is the control device */
		return (0);

	return (ENXIO);
}

/*ARGSUSED*/
int
zut_close(dev_t dev, int flag, int otyp, cred_t *cr)
{
	minor_t minor = getminor(dev);

	if (minor == 0)		/* This is the control device */
		return (0);

	return (ENXIO);
}

/*
 * /dev/zut is the control node, i.e. minor 0.
 *
 * There are no other minor nodes, and /dev/zut basically does nothing
 * other than serve up ioctls.
 */
static struct cb_ops zut_cb_ops = {
	zut_open,	/* open */
	zut_close,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	zut_ioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* prop_op */
	NULL,		/* streamtab */
	D_NEW | D_MP | D_64BIT,		/* Driver compatibility flag */
	CB_REV,		/* version */
	nodev,		/* async read */
	nodev,		/* async write */
};

static struct dev_ops zut_dev_ops = {
	DEVO_REV,	/* version */
	0,		/* refcnt */
	zut_info,	/* info */
	nulldev,	/* identify */
	nulldev,	/* probe */
	zut_attach,	/* attach */
	zut_detach,	/* detach */
	nodev,		/* reset */
	&zut_cb_ops,	/* driver operations */
	NULL		/* no bus operations */
};

static struct modldrv zut_modldrv = {
	&mod_driverops, "ZFS unit test " ZUT_VERSION_STRING,
	    &zut_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&zut_modldrv,
	NULL
};

int
_init(void)
{
	int error;

	if ((error = mod_install(&modlinkage)) != 0) {
		return (error);
	}

	error = ldi_ident_from_mod(&modlinkage, &zut_li);
	ASSERT(error == 0);

	return (0);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	ldi_ident_release(zut_li);
	zut_li = NULL;

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
