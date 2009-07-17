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
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/pathname.h>
#include <sys/atomic.h>
#include <sys/nvpair.h>
#include <sys/fs/zfs.h>
#include <sys/sdt.h>
#include <sys/dkio.h>
#include <sys/zfs_ioctl.h>

#include <stmf.h>
#include <lpif.h>
#include <stmf_ioctl.h>
#include <stmf_sbd.h>
#include <sbd_impl.h>
#include <stmf_sbd_ioctl.h>

#define	SBD_IS_ZVOL(zvol)	(strncmp("/dev/zvol", zvol, 9))

extern sbd_status_t sbd_pgr_meta_init(sbd_lu_t *sl);
extern sbd_status_t sbd_pgr_meta_load(sbd_lu_t *sl);

static int sbd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);
static int sbd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int sbd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int sbd_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int sbd_close(dev_t dev, int flag, int otype, cred_t *credp);
static int stmf_sbd_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);
void sbd_lp_cb(stmf_lu_provider_t *lp, int cmd, void *arg, uint32_t flags);
int sbd_create_register_lu(sbd_create_and_reg_lu_t *slu, int struct_sz,
    uint32_t *err_ret);
int sbd_import_lu(sbd_import_lu_t *ilu, int struct_sz, uint32_t *err_ret,
    int no_register, sbd_lu_t **slr);
int sbd_delete_lu(sbd_delete_lu_t *dlu, int struct_sz, uint32_t *err_ret);
int sbd_modify_lu(sbd_modify_lu_t *mlu, int struct_sz, uint32_t *err_ret);
int sbd_get_lu_props(sbd_lu_props_t *islp, uint32_t islp_sz,
    sbd_lu_props_t *oslp, uint32_t oslp_sz, uint32_t *err_ret);
char *sbd_get_zvol_name(sbd_lu_t *sl);
sbd_status_t sbd_create_zfs_meta_object(sbd_lu_t *sl);
sbd_status_t sbd_open_zfs_meta(sbd_lu_t *sl);
sbd_status_t sbd_read_zfs_meta(sbd_lu_t *sl, uint8_t *buf, uint64_t sz,
    uint64_t off);
sbd_status_t sbd_write_zfs_meta(sbd_lu_t *sl, uint8_t *buf, uint64_t sz,
    uint64_t off);
int sbd_is_zvol(char *path);
int sbd_zvolget(char *zvol_name, char **comstarprop);
int sbd_zvolset(char *zvol_name, char *comstarprop);
char sbd_ctoi(char c);

static ldi_ident_t	sbd_zfs_ident;
static stmf_lu_provider_t *sbd_lp;
static sbd_lu_t		*sbd_lu_list = NULL;
static kmutex_t		sbd_lock;
static dev_info_t	*sbd_dip;
static uint32_t		sbd_lu_count = 0;
char sbd_vendor_id[]	= "SUN     ";
char sbd_product_id[]	= "COMSTAR         ";
char sbd_revision[]	= "1.0 ";
static char sbd_name[] = "sbd";

static struct cb_ops sbd_cb_ops = {
	sbd_open,			/* open */
	sbd_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	stmf_sbd_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_NEW | D_MP,			/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* aread */
	nodev				/* awrite */
};

static struct dev_ops sbd_ops = {
	DEVO_REV,
	0,
	sbd_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	sbd_attach,
	sbd_detach,
	nodev,			/* reset */
	&sbd_cb_ops,
	NULL,			/* bus_ops */
	NULL			/* power */
};

#define	SBD_NAME	"COMSTAR SBD"

static struct modldrv modldrv = {
	&mod_driverops,
	SBD_NAME,
	&sbd_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int ret;

	ret = mod_install(&modlinkage);
	if (ret)
		return (ret);
	sbd_lp = (stmf_lu_provider_t *)stmf_alloc(STMF_STRUCT_LU_PROVIDER,
	    0, 0);
	sbd_lp->lp_lpif_rev = LPIF_REV_1;
	sbd_lp->lp_instance = 0;
	sbd_lp->lp_name = sbd_name;
	sbd_lp->lp_cb = sbd_lp_cb;
	sbd_zfs_ident = ldi_ident_from_anon();

	if (stmf_register_lu_provider(sbd_lp) != STMF_SUCCESS) {
		(void) mod_remove(&modlinkage);
		stmf_free(sbd_lp);
		return (EINVAL);
	}
	mutex_init(&sbd_lock, NULL, MUTEX_DRIVER, NULL);
	return (0);
}

int
_fini(void)
{
	int ret;

	/*
	 * If we have registered lus, then make sure they are all offline
	 * if so then deregister them. This should drop the sbd_lu_count
	 * to zero.
	 */
	if (sbd_lu_count) {
		sbd_lu_t *slu;

		/* See if all of them are offline */
		mutex_enter(&sbd_lock);
		for (slu = sbd_lu_list; slu != NULL; slu = slu->sl_next) {
			if ((slu->sl_state != STMF_STATE_OFFLINE) ||
			    slu->sl_state_not_acked) {
				mutex_exit(&sbd_lock);
				return (EBUSY);
			}
		}
		mutex_exit(&sbd_lock);

#if 0
		/* ok start deregistering them */
		while (sbd_lu_list) {
			sbd_store_t *sst = sbd_lu_list->sl_sst;
			if (sst->sst_deregister_lu(sst) != STMF_SUCCESS)
				return (EBUSY);
		}
#endif
		return (EBUSY);
	}
	if (stmf_deregister_lu_provider(sbd_lp) != STMF_SUCCESS)
		return (EBUSY);
	ret = mod_remove(&modlinkage);
	if (ret != 0) {
		(void) stmf_register_lu_provider(sbd_lp);
		return (ret);
	}
	stmf_free(sbd_lp);
	mutex_destroy(&sbd_lock);
	ldi_ident_release(sbd_zfs_ident);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
sbd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = sbd_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)ddi_get_instance(sbd_dip);
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
sbd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		sbd_dip = dip;

		if (ddi_create_minor_node(dip, "admin", S_IFCHR, 0,
		    DDI_NT_STMF_LP, 0) != DDI_SUCCESS) {
			break;
		}
		ddi_report_dev(dip);
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
sbd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		ddi_remove_minor_node(dip, 0);
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
sbd_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	if (otype != OTYP_CHR)
		return (EINVAL);
	return (0);
}

/* ARGSUSED */
static int
sbd_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	return (0);
}

/* ARGSUSED */
static int
stmf_sbd_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval)
{
	stmf_iocdata_t		*iocd;
	void			*ibuf	= NULL;
	void			*obuf	= NULL;
	sbd_lu_t		*nsl;
	int			i;
	int			ret;

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	ret = stmf_copyin_iocdata(data, mode, &iocd, &ibuf, &obuf);
	if (ret)
		return (ret);
	iocd->stmf_error = 0;

	switch (cmd) {
	case SBD_IOCTL_CREATE_AND_REGISTER_LU:
		if (iocd->stmf_ibuf_size <
		    (sizeof (sbd_create_and_reg_lu_t) - 8)) {
			ret = EFAULT;
			break;
		}
		if ((iocd->stmf_obuf_size == 0) ||
		    (iocd->stmf_obuf_size > iocd->stmf_ibuf_size)) {
			ret = EINVAL;
			break;
		}
		ret = sbd_create_register_lu((sbd_create_and_reg_lu_t *)
		    ibuf, iocd->stmf_ibuf_size, &iocd->stmf_error);
		bcopy(ibuf, obuf, iocd->stmf_obuf_size);
		break;
	case SBD_IOCTL_IMPORT_LU:
		if (iocd->stmf_ibuf_size <
		    (sizeof (sbd_import_lu_t) - 8)) {
			ret = EFAULT;
			break;
		}
		if ((iocd->stmf_obuf_size == 0) ||
		    (iocd->stmf_obuf_size > iocd->stmf_ibuf_size)) {
			ret = EINVAL;
			break;
		}
		ret = sbd_import_lu((sbd_import_lu_t *)ibuf,
		    iocd->stmf_ibuf_size, &iocd->stmf_error, 0, NULL);
		bcopy(ibuf, obuf, iocd->stmf_obuf_size);
		break;
	case SBD_IOCTL_DELETE_LU:
		if (iocd->stmf_ibuf_size < (sizeof (sbd_delete_lu_t) - 8)) {
			ret = EFAULT;
			break;
		}
		if (iocd->stmf_obuf_size) {
			ret = EINVAL;
			break;
		}
		ret = sbd_delete_lu((sbd_delete_lu_t *)ibuf,
		    iocd->stmf_ibuf_size, &iocd->stmf_error);
		break;
	case SBD_IOCTL_MODIFY_LU:
		if (iocd->stmf_ibuf_size < (sizeof (sbd_modify_lu_t) - 8)) {
			ret = EFAULT;
			break;
		}
		if (iocd->stmf_obuf_size) {
			ret = EINVAL;
			break;
		}
		ret = sbd_modify_lu((sbd_modify_lu_t *)ibuf,
		    iocd->stmf_ibuf_size, &iocd->stmf_error);
		break;
	case SBD_IOCTL_GET_LU_PROPS:
		if (iocd->stmf_ibuf_size < (sizeof (sbd_lu_props_t) - 8)) {
			ret = EFAULT;
			break;
		}
		if (iocd->stmf_obuf_size < sizeof (sbd_lu_props_t)) {
			ret = EINVAL;
			break;
		}
		ret = sbd_get_lu_props((sbd_lu_props_t *)ibuf,
		    iocd->stmf_ibuf_size, (sbd_lu_props_t *)obuf,
		    iocd->stmf_obuf_size, &iocd->stmf_error);
		break;
	case SBD_IOCTL_GET_LU_LIST:
		mutex_enter(&sbd_lock);
		iocd->stmf_obuf_max_nentries = sbd_lu_count;
		iocd->stmf_obuf_nentries = min((iocd->stmf_obuf_size >> 4),
		    sbd_lu_count);
		for (nsl = sbd_lu_list, i = 0; nsl &&
		    (i < iocd->stmf_obuf_nentries); i++, nsl = nsl->sl_next) {
			bcopy(nsl->sl_device_id + 4,
			    &(((uint8_t *)obuf)[i << 4]), 16);
		}
		mutex_exit(&sbd_lock);
		ret = 0;
		iocd->stmf_error = 0;
		break;
	default:
		ret = ENOTTY;
	}

	if (ret == 0) {
		ret = stmf_copyout_iocdata(data, mode, iocd, obuf);
	} else if (iocd->stmf_error) {
		(void) stmf_copyout_iocdata(data, mode, iocd, obuf);
	}
	if (obuf) {
		kmem_free(obuf, iocd->stmf_obuf_size);
		obuf = NULL;
	}
	if (ibuf) {
		kmem_free(ibuf, iocd->stmf_ibuf_size);
		ibuf = NULL;
	}
	kmem_free(iocd, sizeof (stmf_iocdata_t));
	return (ret);
}

/* ARGSUSED */
void
sbd_lp_cb(stmf_lu_provider_t *lp, int cmd, void *arg, uint32_t flags)
{
	nvpair_t	*np;
	char		*s;
	sbd_import_lu_t *ilu;
	uint32_t	ilu_sz;
	uint32_t	struct_sz;
	uint32_t	err_ret;
	int		iret;

	if ((cmd != STMF_PROVIDER_DATA_UPDATED) || (arg == NULL)) {
		return;
	}

	if ((flags & (STMF_PCB_STMF_ONLINING | STMF_PCB_PREG_COMPLETE)) == 0) {
		return;
	}

	np = NULL;
	ilu_sz = 1024;
	ilu = (sbd_import_lu_t *)kmem_zalloc(ilu_sz, KM_SLEEP);
	while ((np = nvlist_next_nvpair((nvlist_t *)arg, np)) != NULL) {
		if (nvpair_type(np) != DATA_TYPE_STRING) {
			continue;
		}
		if (nvpair_value_string(np, &s) != 0) {
			continue;
		}
		struct_sz = max(8, strlen(s) + 1);
		struct_sz += sizeof (sbd_import_lu_t) - 8;
		if (struct_sz > ilu_sz) {
			kmem_free(ilu, ilu_sz);
			ilu_sz = struct_sz + 32;
			ilu = (sbd_import_lu_t *)kmem_zalloc(ilu_sz, KM_SLEEP);
		}
		ilu->ilu_struct_size = struct_sz;
		(void) strcpy(ilu->ilu_meta_fname, s);
		iret = sbd_import_lu(ilu, struct_sz, &err_ret, 0, NULL);
		if (iret) {
			stmf_trace(0, "sbd_lp_cb: import_lu failed, ret = %d, "
			    "err_ret = %d", iret, err_ret);
		} else {
			stmf_trace(0, "Imported the LU %s", nvpair_name(np));
		}
	}

	if (ilu) {
		kmem_free(ilu, ilu_sz);
		ilu = NULL;
	}
}

sbd_status_t
sbd_link_lu(sbd_lu_t *sl)
{
	sbd_lu_t *nsl;

	mutex_enter(&sbd_lock);
	mutex_enter(&sl->sl_lock);
	ASSERT(sl->sl_trans_op != SL_OP_NONE);

	if (sl->sl_flags & SL_LINKED) {
		mutex_exit(&sbd_lock);
		mutex_exit(&sl->sl_lock);
		return (SBD_ALREADY);
	}
	for (nsl = sbd_lu_list; nsl; nsl = nsl->sl_next) {
		if (strcmp(nsl->sl_name, sl->sl_name) == 0)
			break;
	}
	if (nsl) {
		mutex_exit(&sbd_lock);
		mutex_exit(&sl->sl_lock);
		return (SBD_ALREADY);
	}
	sl->sl_next = sbd_lu_list;
	sbd_lu_list = sl;
	sl->sl_flags |= SL_LINKED;
	mutex_exit(&sbd_lock);
	mutex_exit(&sl->sl_lock);
	return (SBD_SUCCESS);
}

void
sbd_unlink_lu(sbd_lu_t *sl)
{
	sbd_lu_t **ppnsl;

	mutex_enter(&sbd_lock);
	mutex_enter(&sl->sl_lock);
	ASSERT(sl->sl_trans_op != SL_OP_NONE);

	ASSERT(sl->sl_flags & SL_LINKED);
	for (ppnsl = &sbd_lu_list; *ppnsl; ppnsl = &((*ppnsl)->sl_next)) {
		if (*ppnsl == sl)
			break;
	}
	ASSERT(*ppnsl);
	*ppnsl = (*ppnsl)->sl_next;
	sl->sl_flags &= ~SL_LINKED;
	mutex_exit(&sbd_lock);
	mutex_exit(&sl->sl_lock);
}

sbd_status_t
sbd_find_and_lock_lu(uint8_t *guid, uint8_t *meta_name, uint8_t op,
    sbd_lu_t **ppsl)
{
	sbd_lu_t *sl;
	int found = 0;
	sbd_status_t sret;

	mutex_enter(&sbd_lock);
	for (sl = sbd_lu_list; sl; sl = sl->sl_next) {
		if (guid) {
			found = bcmp(sl->sl_device_id + 4, guid, 16) == 0;
		} else {
			found = strcmp(sl->sl_name, (char *)meta_name) == 0;
		}
		if (found)
			break;
	}
	if (!found) {
		mutex_exit(&sbd_lock);
		return (SBD_NOT_FOUND);
	}
	mutex_enter(&sl->sl_lock);
	if (sl->sl_trans_op == SL_OP_NONE) {
		sl->sl_trans_op = op;
		*ppsl = sl;
		sret = SBD_SUCCESS;
	} else {
		sret = SBD_BUSY;
	}
	mutex_exit(&sl->sl_lock);
	mutex_exit(&sbd_lock);
	return (sret);
}

sbd_status_t
sbd_read_meta(sbd_lu_t *sl, uint64_t offset, uint64_t size, uint8_t *buf)
{
	uint64_t	meta_align;
	uint64_t	starting_off;
	uint64_t	data_off;
	uint64_t	ending_off;
	uint64_t	io_size;
	uint8_t		*io_buf;
	vnode_t		*vp;
	sbd_status_t	ret;
	ssize_t		resid;
	int		vret;

	ASSERT(sl->sl_flags & SL_META_OPENED);
	if (sl->sl_flags & SL_SHARED_META) {
		meta_align = (((uint64_t)1) << sl->sl_data_blocksize_shift) - 1;
		vp = sl->sl_data_vp;
		ASSERT(vp);
	} else {
		meta_align = (((uint64_t)1) << sl->sl_meta_blocksize_shift) - 1;
		if ((sl->sl_flags & SL_ZFS_META) == 0) {
			vp = sl->sl_meta_vp;
			ASSERT(vp);
		}
	}
	starting_off = offset & ~(meta_align);
	data_off = offset & meta_align;
	ending_off = (offset + size + meta_align) & (~meta_align);
	if (ending_off > sl->sl_meta_size_used) {
		bzero(buf, size);
		if (starting_off >= sl->sl_meta_size_used) {
			return (SBD_SUCCESS);
		}
		ending_off = (sl->sl_meta_size_used + meta_align) &
		    (~meta_align);
		if (size > (ending_off - (starting_off + data_off))) {
			size = ending_off - (starting_off + data_off);
		}
	}
	io_size = ending_off - starting_off;
	io_buf = (uint8_t *)kmem_zalloc(io_size, KM_SLEEP);
	ASSERT((starting_off + io_size) <= sl->sl_total_meta_size);

	if (sl->sl_flags & SL_ZFS_META) {
		if ((ret = sbd_read_zfs_meta(sl, io_buf, io_size,
		    starting_off)) != SBD_SUCCESS) {
			goto sbd_read_meta_failure;
		}
	} else {
		vret = vn_rdwr(UIO_READ, vp, (caddr_t)io_buf, (ssize_t)io_size,
		    (offset_t)starting_off, UIO_SYSSPACE, FRSYNC,
		    RLIM64_INFINITY, CRED(), &resid);

		if (vret || resid) {
			ret = SBD_FILEIO_FAILURE | vret;
			goto sbd_read_meta_failure;
		}
	}

	bcopy(io_buf + data_off, buf, size);
	ret = SBD_SUCCESS;

sbd_read_meta_failure:
	kmem_free(io_buf, io_size);
	return (ret);
}

sbd_status_t
sbd_write_meta(sbd_lu_t *sl, uint64_t offset, uint64_t size, uint8_t *buf)
{
	uint64_t	meta_align;
	uint64_t	starting_off;
	uint64_t	data_off;
	uint64_t	ending_off;
	uint64_t	io_size;
	uint8_t		*io_buf;
	vnode_t		*vp;
	sbd_status_t	ret;
	ssize_t		resid;
	int		vret;

	ASSERT(sl->sl_flags & SL_META_OPENED);
	if (sl->sl_flags & SL_SHARED_META) {
		meta_align = (((uint64_t)1) << sl->sl_data_blocksize_shift) - 1;
		vp = sl->sl_data_vp;
		ASSERT(vp);
	} else {
		meta_align = (((uint64_t)1) << sl->sl_meta_blocksize_shift) - 1;
		if ((sl->sl_flags & SL_ZFS_META) == 0) {
			vp = sl->sl_meta_vp;
			ASSERT(vp);
		}
	}
	starting_off = offset & ~(meta_align);
	data_off = offset & meta_align;
	ending_off = (offset + size + meta_align) & (~meta_align);
	io_size = ending_off - starting_off;
	io_buf = (uint8_t *)kmem_zalloc(io_size, KM_SLEEP);
	ret = sbd_read_meta(sl, starting_off, io_size, io_buf);
	if (ret != SBD_SUCCESS) {
		goto sbd_write_meta_failure;
	}
	bcopy(buf, io_buf + data_off, size);
	if (sl->sl_flags & SL_ZFS_META) {
		if ((ret = sbd_write_zfs_meta(sl, io_buf, io_size,
		    starting_off)) != SBD_SUCCESS) {
			goto sbd_write_meta_failure;
		}
	} else {
		vret = vn_rdwr(UIO_WRITE, vp, (caddr_t)io_buf, (ssize_t)io_size,
		    (offset_t)starting_off, UIO_SYSSPACE, FDSYNC,
		    RLIM64_INFINITY, CRED(), &resid);

		if (vret || resid) {
			ret = SBD_FILEIO_FAILURE | vret;
			goto sbd_write_meta_failure;
		}
	}

	ret = SBD_SUCCESS;

sbd_write_meta_failure:
	kmem_free(io_buf, io_size);
	return (ret);
}

uint8_t
sbd_calc_sum(uint8_t *buf, int size)
{
	uint8_t s = 0;

	while (size > 0)
		s += buf[--size];

	return (s);
}

uint8_t
sbd_calc_section_sum(sm_section_hdr_t *sm, uint32_t sz)
{
	uint8_t s, o;

	o = sm->sms_chksum;
	sm->sms_chksum = 0;
	s = sbd_calc_sum((uint8_t *)sm, sz);
	sm->sms_chksum = o;

	return (s);
}

uint32_t
sbd_strlen(char *str, uint32_t maxlen)
{
	uint32_t i;

	for (i = 0; i < maxlen; i++) {
		if (str[i] == 0)
			return (i);
	}
	return (i);
}

void
sbd_swap_meta_start(sbd_meta_start_t *sm)
{
	if (sm->sm_magic == SBD_MAGIC)
		return;
	sm->sm_magic		= BSWAP_64(sm->sm_magic);
	sm->sm_meta_size	= BSWAP_64(sm->sm_meta_size);
	sm->sm_meta_size_used	= BSWAP_64(sm->sm_meta_size_used);
	sm->sm_ver_major	= BSWAP_16(sm->sm_ver_major);
	sm->sm_ver_minor	= BSWAP_16(sm->sm_ver_minor);
	sm->sm_ver_subminor	= BSWAP_16(sm->sm_ver_subminor);
}

void
sbd_swap_section_hdr(sm_section_hdr_t *sm)
{
	if (sm->sms_data_order == SMS_DATA_ORDER)
		return;
	sm->sms_offset		= BSWAP_64(sm->sms_offset);
	sm->sms_size		= BSWAP_32(sm->sms_size);
	sm->sms_id		= BSWAP_16(sm->sms_id);
	sm->sms_chksum		+= SMS_DATA_ORDER - sm->sms_data_order;
	sm->sms_data_order	= SMS_DATA_ORDER;
}

void
sbd_swap_lu_info_1_0(sbd_lu_info_1_0_t *sli)
{
	sbd_swap_section_hdr(&sli->sli_sms_header);
	if (sli->sli_data_order == SMS_DATA_ORDER)
		return;
	sli->sli_sms_header.sms_chksum	+= SMS_DATA_ORDER - sli->sli_data_order;
	sli->sli_data_order		= SMS_DATA_ORDER;
	sli->sli_total_store_size	= BSWAP_64(sli->sli_total_store_size);
	sli->sli_total_meta_size	= BSWAP_64(sli->sli_total_meta_size);
	sli->sli_lu_data_offset		= BSWAP_64(sli->sli_lu_data_offset);
	sli->sli_lu_data_size		= BSWAP_64(sli->sli_lu_data_size);
	sli->sli_flags			= BSWAP_32(sli->sli_flags);
	sli->sli_blocksize		= BSWAP_16(sli->sli_blocksize);
}

void
sbd_swap_lu_info_1_1(sbd_lu_info_1_1_t *sli)
{
	sbd_swap_section_hdr(&sli->sli_sms_header);
	if (sli->sli_data_order == SMS_DATA_ORDER)
		return;
	sli->sli_sms_header.sms_chksum	+= SMS_DATA_ORDER - sli->sli_data_order;
	sli->sli_data_order		= SMS_DATA_ORDER;
	sli->sli_flags			= BSWAP_32(sli->sli_flags);
	sli->sli_lu_size		= BSWAP_64(sli->sli_lu_size);
	sli->sli_meta_fname_offset	= BSWAP_16(sli->sli_meta_fname_offset);
	sli->sli_data_fname_offset	= BSWAP_16(sli->sli_data_fname_offset);
	sli->sli_serial_offset		= BSWAP_16(sli->sli_serial_offset);
	sli->sli_alias_offset		= BSWAP_16(sli->sli_alias_offset);
}

sbd_status_t
sbd_load_section_hdr(sbd_lu_t *sl, sm_section_hdr_t *sms)
{
	sm_section_hdr_t	h;
	uint64_t		st;
	sbd_status_t 		ret;

	for (st = sl->sl_meta_offset + sizeof (sbd_meta_start_t);
	    st < sl->sl_meta_size_used; st += h.sms_size) {
		if ((ret = sbd_read_meta(sl, st, sizeof (sm_section_hdr_t),
		    (uint8_t *)&h)) != SBD_SUCCESS) {
			return (ret);
		}
		if (h.sms_data_order != SMS_DATA_ORDER) {
			sbd_swap_section_hdr(&h);
		}
		if ((h.sms_data_order != SMS_DATA_ORDER) ||
		    (h.sms_offset != st) || (h.sms_size < sizeof (h)) ||
		    ((st + h.sms_size) > sl->sl_meta_size_used)) {
			return (SBD_META_CORRUPTED);
		}
		if (h.sms_id == sms->sms_id) {
			bcopy(&h, sms, sizeof (h));
			return (SBD_SUCCESS);
		}
	}

	return (SBD_NOT_FOUND);
}

sbd_status_t
sbd_load_meta_start(sbd_lu_t *sl)
{
	sbd_meta_start_t *sm;
	sbd_status_t ret;

	/* Fake meta params initially */
	sl->sl_total_meta_size = (uint64_t)-1;
	sl->sl_meta_size_used = sl->sl_meta_offset + sizeof (sbd_meta_start_t);

	sm = kmem_zalloc(sizeof (*sm), KM_SLEEP);
	ret = sbd_read_meta(sl, sl->sl_meta_offset, sizeof (*sm),
	    (uint8_t *)sm);
	if (ret != SBD_SUCCESS) {
		goto load_meta_start_failed;
	}

	if (sm->sm_magic != SBD_MAGIC) {
		sbd_swap_meta_start(sm);
	}

	if ((sm->sm_magic != SBD_MAGIC) || (sbd_calc_sum((uint8_t *)sm,
	    sizeof (*sm) - 1) != sm->sm_chksum)) {
		ret = SBD_META_CORRUPTED;
		goto load_meta_start_failed;
	}

	if (sm->sm_ver_major != SBD_VER_MAJOR) {
		ret = SBD_NOT_SUPPORTED;
		goto load_meta_start_failed;
	}

	sl->sl_total_meta_size = sm->sm_meta_size;
	sl->sl_meta_size_used = sm->sm_meta_size_used;
	ret = SBD_SUCCESS;

load_meta_start_failed:
	kmem_free(sm, sizeof (*sm));
	return (ret);
}

sbd_status_t
sbd_write_meta_start(sbd_lu_t *sl, uint64_t meta_size, uint64_t meta_size_used)
{
	sbd_meta_start_t *sm;
	sbd_status_t ret;

	sm = (sbd_meta_start_t *)kmem_zalloc(sizeof (sbd_meta_start_t),
	    KM_SLEEP);

	sm->sm_magic = SBD_MAGIC;
	sm->sm_meta_size = meta_size;
	sm->sm_meta_size_used = meta_size_used;
	sm->sm_ver_major = SBD_VER_MAJOR;
	sm->sm_ver_minor = SBD_VER_MINOR;
	sm->sm_ver_subminor = SBD_VER_SUBMINOR;
	sm->sm_chksum = sbd_calc_sum((uint8_t *)sm, sizeof (*sm) - 1);

	ret = sbd_write_meta(sl, sl->sl_meta_offset, sizeof (*sm),
	    (uint8_t *)sm);
	kmem_free(sm, sizeof (*sm));

	return (ret);
}

sbd_status_t
sbd_read_meta_section(sbd_lu_t *sl, sm_section_hdr_t **ppsms, uint16_t sms_id)
{
	sbd_status_t ret;
	sm_section_hdr_t sms;
	int alloced = 0;

	if (((*ppsms) == NULL) || ((*ppsms)->sms_offset == 0)) {
		bzero(&sms, sizeof (sm_section_hdr_t));
		sms.sms_id = sms_id;
		if ((ret = sbd_load_section_hdr(sl, &sms)) != SBD_SUCCESS) {
			return (ret);
		} else {
			if ((*ppsms) == NULL) {
				*ppsms = (sm_section_hdr_t *)kmem_zalloc(
				    sms.sms_size, KM_SLEEP);
				alloced = 1;
			}
			bcopy(&sms, *ppsms, sizeof (sm_section_hdr_t));
		}
	}

	ret = sbd_read_meta(sl, (*ppsms)->sms_offset, (*ppsms)->sms_size,
	    (uint8_t *)(*ppsms));
	if (ret == SBD_SUCCESS) {
		uint8_t s;
		if ((*ppsms)->sms_data_order != SMS_DATA_ORDER)
			sbd_swap_section_hdr(*ppsms);
		if ((*ppsms)->sms_id != SMS_ID_UNUSED) {
			s = sbd_calc_section_sum(*ppsms, (*ppsms)->sms_size);
			if (s != (*ppsms)->sms_chksum)
				ret = SBD_META_CORRUPTED;
		}
	}

	if ((ret != SBD_SUCCESS) && alloced)
		kmem_free(*ppsms, sms.sms_size);
	return (ret);
}

sbd_status_t
sbd_write_meta_section(sbd_lu_t *sl, sm_section_hdr_t *sms)
{
	sm_section_hdr_t t;
	uint64_t off, s;
	uint64_t unused_start;
	sbd_status_t ret;
	uint8_t *cb;
	int update_meta_start = 0;

write_meta_section_again:
	if (sms->sms_offset) {
		/* Verify that size has not changed */
		ret = sbd_read_meta(sl, sms->sms_offset, sizeof (t),
		    (uint8_t *)&t);
		if (ret != SBD_SUCCESS)
			return (ret);
		if (t.sms_data_order != SMS_DATA_ORDER) {
			sbd_swap_section_hdr(&t);
		}
		if (t.sms_id != sms->sms_id) {
			return (SBD_INVALID_ARG);
		}
		if (t.sms_size == sms->sms_size) {
			return (sbd_write_meta(sl, sms->sms_offset,
			    sms->sms_size, (uint8_t *)sms));
		}
		t.sms_id = SMS_ID_UNUSED;
		/*
		 * For unused sections we only use chksum of the header. for
		 * all other sections, the chksum is for the entire section.
		 */
		t.sms_chksum = sbd_calc_section_sum(&t, sizeof (t));
		ret = sbd_write_meta(sl, t.sms_offset, sizeof (t),
		    (uint8_t *)&t);
		if (ret != SBD_SUCCESS)
			return (ret);
		sms->sms_offset = 0;
	} else {
		t.sms_id = sms->sms_id;
		t.sms_data_order = SMS_DATA_ORDER;
		ret = sbd_load_section_hdr(sl, &t);
		if (ret == SBD_SUCCESS) {
			sms->sms_offset = t.sms_offset;
			sms->sms_chksum =
			    sbd_calc_section_sum(sms, sms->sms_size);
			goto write_meta_section_again;
		} else if (ret != SBD_NOT_FOUND) {
			return (ret);
		}
	}

	/*
	 * At this point we know that section does not already exist.
	 * find space large enough to hold the section or grow meta if
	 * possible.
	 */
	unused_start = 0;
	s = 0;
	for (off = sl->sl_meta_offset + sizeof (sbd_meta_start_t);
	    off < sl->sl_meta_size_used; off += t.sms_size) {
		ret = sbd_read_meta(sl, off, sizeof (t), (uint8_t *)&t);
		if (ret != SBD_SUCCESS)
			return (ret);
		if (t.sms_data_order != SMS_DATA_ORDER)
			sbd_swap_section_hdr(&t);
		if (t.sms_size == 0)
			return (SBD_META_CORRUPTED);
		if (t.sms_id == SMS_ID_UNUSED) {
			if (unused_start == 0)
				unused_start = off;
			s = t.sms_size - unused_start + off;
			if ((s == sms->sms_size) || (s >= (sms->sms_size +
			    sizeof (t)))) {
				break;
			} else {
				s = 0;
			}
		} else {
			unused_start = 0;
		}
	}

	off = (unused_start == 0) ? sl->sl_meta_size_used : unused_start;
	if (s == 0) {
		s = sl->sl_total_meta_size - off;
		/* Lets see if we can expand the metadata */
		if (s >= sms->sms_size || !(sl->sl_flags & SL_SHARED_META)) {
			s = sms->sms_size;
			update_meta_start = 1;
		} else {
			s = 0;
		}
	}

	if (s == 0)
		return (SBD_ALLOC_FAILURE);

	sms->sms_offset = off;
	sms->sms_chksum = sbd_calc_section_sum(sms, sms->sms_size);
	/*
	 * Since we may have to write more than one section (current +
	 * any unused), use a combined buffer.
	 */
	cb = kmem_zalloc(s, KM_SLEEP);
	bcopy(sms, cb, sms->sms_size);
	if (s > sms->sms_size) {
		t.sms_offset = off + sms->sms_size;
		t.sms_size = s - sms->sms_size;
		t.sms_id = SMS_ID_UNUSED;
		t.sms_data_order = SMS_DATA_ORDER;
		t.sms_chksum = sbd_calc_section_sum(&t, sizeof (t));
		bcopy(&t, cb + sms->sms_size, sizeof (t));
	}
	ret = sbd_write_meta(sl, off, s, cb);
	kmem_free(cb, s);
	if (ret != SBD_SUCCESS)
		return (ret);

	if (update_meta_start) {
		uint64_t old_sz_used = sl->sl_meta_size_used; /* save a copy */
		sl->sl_meta_size_used = off + s;
		s = sl->sl_total_meta_size; /* save a copy */
		if (sl->sl_total_meta_size < sl->sl_meta_size_used) {
			uint64_t meta_align =
			    (((uint64_t)1) << sl->sl_meta_blocksize_shift) - 1;
			sl->sl_total_meta_size = (sl->sl_meta_size_used +
			    meta_align) & (~meta_align);
		}
		ret = sbd_write_meta_start(sl, sl->sl_total_meta_size,
		    sl->sl_meta_size_used);
		if (ret != SBD_SUCCESS) {
			sl->sl_meta_size_used = old_sz_used;
			sl->sl_total_meta_size = s;
		}
	}
	return (ret);
}

sbd_status_t
sbd_write_lu_info(sbd_lu_t *sl)
{
	sbd_lu_info_1_1_t *sli;
	int s;
	uint8_t *p;
	char *zvol_name = NULL;
	sbd_status_t ret;

	mutex_enter(&sl->sl_lock);

	s = sl->sl_serial_no_size;
	if ((sl->sl_flags & (SL_SHARED_META | SL_ZFS_META)) == 0) {
		if (sl->sl_data_filename) {
			s += strlen(sl->sl_data_filename) + 1;
		}
	}
	if (sl->sl_flags & SL_ZFS_META) {
		zvol_name = sbd_get_zvol_name(sl);
		s += strlen(zvol_name) + 1;
	}
	if (sl->sl_alias) {
		s += strlen(sl->sl_alias) + 1;
	}
	if (sl->sl_mgmt_url) {
		s += strlen(sl->sl_mgmt_url) + 1;
	}
	sli = (sbd_lu_info_1_1_t *)kmem_zalloc(sizeof (*sli) + s, KM_SLEEP);
	p = sli->sli_buf;
	if ((sl->sl_flags & (SL_SHARED_META | SL_ZFS_META)) == 0) {
		sli->sli_flags |= SLI_SEPARATE_META;
		(void) strcpy((char *)p, sl->sl_data_filename);
		sli->sli_data_fname_offset =
		    (uintptr_t)p - (uintptr_t)sli->sli_buf;
		sli->sli_flags |= SLI_DATA_FNAME_VALID;
		p += strlen(sl->sl_data_filename) + 1;
	}
	if (sl->sl_flags & SL_ZFS_META) {
		(void) strcpy((char *)p, zvol_name);
		sli->sli_meta_fname_offset =
		    (uintptr_t)p - (uintptr_t)sli->sli_buf;
		sli->sli_flags |= SLI_META_FNAME_VALID | SLI_ZFS_META;
		p += strlen(zvol_name) + 1;
		kmem_free(zvol_name, strlen(zvol_name) + 1);
		zvol_name = NULL;
	}
	if (sl->sl_alias) {
		(void) strcpy((char *)p, sl->sl_alias);
		sli->sli_alias_offset =
		    (uintptr_t)p - (uintptr_t)sli->sli_buf;
		sli->sli_flags |= SLI_ALIAS_VALID;
		p += strlen(sl->sl_alias) + 1;
	}
	if (sl->sl_mgmt_url) {
		(void) strcpy((char *)p, sl->sl_mgmt_url);
		sli->sli_mgmt_url_offset =
		    (uintptr_t)p - (uintptr_t)sli->sli_buf;
		sli->sli_flags |= SLI_MGMT_URL_VALID;
		p += strlen(sl->sl_mgmt_url) + 1;
	}
	if (sl->sl_flags & SL_WRITE_PROTECTED) {
		sli->sli_flags |= SLI_WRITE_PROTECTED;
	}
	if (sl->sl_flags & SL_SAVED_WRITE_CACHE_DISABLE) {
		sli->sli_flags |= SLI_WRITEBACK_CACHE_DISABLE;
	}
	if (sl->sl_flags & SL_VID_VALID) {
		bcopy(sl->sl_vendor_id, sli->sli_vid, 8);
		sli->sli_flags |= SLI_VID_VALID;
	}
	if (sl->sl_flags & SL_PID_VALID) {
		bcopy(sl->sl_product_id, sli->sli_pid, 16);
		sli->sli_flags |= SLI_PID_VALID;
	}
	if (sl->sl_flags & SL_REV_VALID) {
		bcopy(sl->sl_revision, sli->sli_rev, 4);
		sli->sli_flags |= SLI_REV_VALID;
	}
	if (sl->sl_serial_no_size) {
		bcopy(sl->sl_serial_no, p, sl->sl_serial_no_size);
		sli->sli_serial_size = sl->sl_serial_no_size;
		sli->sli_serial_offset =
		    (uintptr_t)p - (uintptr_t)sli->sli_buf;
		sli->sli_flags |= SLI_SERIAL_VALID;
		p += sli->sli_serial_size;
	}
	sli->sli_lu_size = sl->sl_lu_size;
	sli->sli_data_blocksize_shift = sl->sl_data_blocksize_shift;
	sli->sli_data_order = SMS_DATA_ORDER;
	bcopy(sl->sl_device_id, sli->sli_device_id, 20);

	sli->sli_sms_header.sms_size = sizeof (*sli) + s;
	sli->sli_sms_header.sms_id = SMS_ID_LU_INFO_1_1;
	sli->sli_sms_header.sms_data_order = SMS_DATA_ORDER;

	mutex_exit(&sl->sl_lock);
	ret = sbd_write_meta_section(sl, (sm_section_hdr_t *)sli);
	kmem_free(sli, sizeof (*sli) + s);
	return (ret);
}

int
sbd_populate_and_register_lu(sbd_lu_t *sl, uint32_t *err_ret)
{
	stmf_lu_t *lu = sl->sl_lu;
	stmf_status_t ret;

	lu->lu_id = (scsi_devid_desc_t *)sl->sl_device_id;
	if (sl->sl_alias) {
		lu->lu_alias = sl->sl_alias;
	} else {
		lu->lu_alias = sl->sl_name;
	}
	lu->lu_lp = sbd_lp;
	lu->lu_task_alloc = sbd_task_alloc;
	lu->lu_new_task = sbd_new_task;
	lu->lu_dbuf_xfer_done = sbd_dbuf_xfer_done;
	lu->lu_send_status_done = sbd_send_status_done;
	lu->lu_task_free = sbd_task_free;
	lu->lu_abort = sbd_abort;
	lu->lu_ctl = sbd_ctl;
	lu->lu_info = sbd_info;
	sl->sl_state = STMF_STATE_OFFLINE;

	if ((ret = stmf_register_lu(lu)) != STMF_SUCCESS) {
		stmf_trace(0, "Failed to register with framework, ret=%llx",
		    ret);
		if (ret == STMF_ALREADY) {
			*err_ret = SBD_RET_GUID_ALREADY_REGISTERED;
		}
		return (EIO);
	}

	*err_ret = 0;
	return (0);
}

int
sbd_open_data_file(sbd_lu_t *sl, uint32_t *err_ret, int lu_size_valid,
    int vp_valid, int keep_open)
{
	int ret;
	int flag;
	ulong_t	nbits;
	uint64_t supported_size;
	vattr_t vattr;
	enum vtype vt;

	mutex_enter(&sl->sl_lock);
	if (vp_valid) {
		goto odf_over_open;
	}
	if (sl->sl_data_filename[0] != '/') {
		*err_ret = SBD_RET_DATA_PATH_NOT_ABSOLUTE;
		mutex_exit(&sl->sl_lock);
		return (EINVAL);
	}
	if ((ret = lookupname(sl->sl_data_filename, UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &sl->sl_data_vp)) != 0) {
		*err_ret = SBD_RET_DATA_FILE_LOOKUP_FAILED;
		mutex_exit(&sl->sl_lock);
		return (ret);
	}
	sl->sl_data_vtype = vt = sl->sl_data_vp->v_type;
	VN_RELE(sl->sl_data_vp);
	if ((vt != VREG) && (vt != VCHR) && (vt != VBLK)) {
		*err_ret = SBD_RET_WRONG_DATA_FILE_TYPE;
		mutex_exit(&sl->sl_lock);
		return (EINVAL);
	}
	if (sl->sl_flags & SL_WRITE_PROTECTED) {
		flag = FREAD | FOFFMAX;
	} else {
		flag = FREAD | FWRITE | FOFFMAX | FEXCL;
	}
	if ((ret = vn_open(sl->sl_data_filename, UIO_SYSSPACE, flag, 0,
	    &sl->sl_data_vp, 0, 0)) != 0) {
		*err_ret = SBD_RET_DATA_FILE_OPEN_FAILED;
		mutex_exit(&sl->sl_lock);
		return (ret);
	}
odf_over_open:
	vattr.va_mask = AT_SIZE;
	if ((ret = VOP_GETATTR(sl->sl_data_vp, &vattr, 0, CRED(), NULL)) != 0) {
		*err_ret = SBD_RET_DATA_FILE_GETATTR_FAILED;
		goto odf_close_data_and_exit;
	}
	if ((vt != VREG) && (vattr.va_size == 0)) {
		/*
		 * Its a zero byte block or char device. This cannot be
		 * a raw disk.
		 */
		*err_ret = SBD_RET_WRONG_DATA_FILE_TYPE;
		ret = EINVAL;
		goto odf_close_data_and_exit;
	}
	/* sl_data_readable size includes any metadata. */
	sl->sl_data_readable_size = vattr.va_size;
	if (VOP_PATHCONF(sl->sl_data_vp, _PC_FILESIZEBITS, &nbits,
	    CRED(), NULL) != 0) {
		nbits = 0;
	}
	/* nbits cannot be greater than 64 */
	sl->sl_data_fs_nbits = (uint8_t)nbits;
	if (lu_size_valid) {
		sl->sl_total_data_size = sl->sl_lu_size;
		if (sl->sl_flags & SL_SHARED_META) {
			sl->sl_total_data_size += SHARED_META_DATA_SIZE;
		}
		if ((nbits > 0) && (nbits < 64)) {
			/*
			 * The expression below is correct only if nbits is
			 * positive and less than 64.
			 */
			supported_size = (((uint64_t)1) << nbits) - 1;
			if (sl->sl_total_data_size > supported_size) {
				*err_ret = SBD_RET_SIZE_NOT_SUPPORTED_BY_FS;
				ret = EINVAL;
				goto odf_close_data_and_exit;
			}
		}
	} else {
		sl->sl_total_data_size = vattr.va_size;
		if (sl->sl_flags & SL_SHARED_META) {
			if (vattr.va_size > SHARED_META_DATA_SIZE) {
				sl->sl_lu_size = vattr.va_size -
				    SHARED_META_DATA_SIZE;
			} else {
				*err_ret = SBD_RET_FILE_SIZE_ERROR;
				ret = EINVAL;
				goto odf_close_data_and_exit;
			}
		} else {
			sl->sl_lu_size = vattr.va_size;
		}
	}
	if (sl->sl_lu_size < SBD_MIN_LU_SIZE) {
		*err_ret = SBD_RET_FILE_SIZE_ERROR;
		ret = EINVAL;
		goto odf_close_data_and_exit;
	}
	if (sl->sl_lu_size &
	    ((((uint64_t)1) << sl->sl_data_blocksize_shift) - 1)) {
		*err_ret = SBD_RET_FILE_ALIGN_ERROR;
		ret = EINVAL;
		goto odf_close_data_and_exit;
	}
	sl->sl_flags |= SL_MEDIA_LOADED;
	mutex_exit(&sl->sl_lock);
	return (0);

odf_close_data_and_exit:
	if (!keep_open) {
		(void) VOP_CLOSE(sl->sl_data_vp, flag, 1, 0, CRED(), NULL);
		VN_RELE(sl->sl_data_vp);
	}
	mutex_exit(&sl->sl_lock);
	return (ret);
}

int
sbd_close_delete_lu(sbd_lu_t *sl, int ret)
{
	int flag;

	if (((sl->sl_flags & SL_SHARED_META) == 0) &&
	    (sl->sl_flags & SL_META_OPENED)) {
		if (sl->sl_flags & SL_ZFS_META) {
			rw_destroy(&sl->sl_zfs_meta_lock);
			if (sl->sl_zfs_meta) {
				kmem_free(sl->sl_zfs_meta, ZAP_MAXVALUELEN / 2);
			}
		} else {
			flag = FREAD | FWRITE | FOFFMAX | FEXCL;
			(void) VOP_CLOSE(sl->sl_meta_vp, flag, 1, 0,
			    CRED(), NULL);
			VN_RELE(sl->sl_meta_vp);
		}
		sl->sl_flags &= ~SL_META_OPENED;
	}
	if (sl->sl_flags & SL_MEDIA_LOADED) {
		if (sl->sl_flags & SL_WRITE_PROTECTED) {
			flag = FREAD | FOFFMAX;
		} else {
			flag = FREAD | FWRITE | FOFFMAX | FEXCL;
		}
		(void) VOP_CLOSE(sl->sl_data_vp, flag, 1, 0, CRED(), NULL);
		VN_RELE(sl->sl_data_vp);
		sl->sl_flags &= ~SL_MEDIA_LOADED;
		if (sl->sl_flags & SL_SHARED_META) {
			sl->sl_flags &= ~SL_META_OPENED;
		}
	}
	if (sl->sl_flags & SL_LINKED)
		sbd_unlink_lu(sl);
	mutex_destroy(&sl->sl_lock);
	rw_destroy(&sl->sl_pgr->pgr_lock);
	if (sl->sl_serial_no_alloc_size) {
		kmem_free(sl->sl_serial_no, sl->sl_serial_no_alloc_size);
	}
	if (sl->sl_data_fname_alloc_size) {
		kmem_free(sl->sl_data_filename, sl->sl_data_fname_alloc_size);
	}
	if (sl->sl_alias_alloc_size) {
		kmem_free(sl->sl_alias, sl->sl_alias_alloc_size);
	}
	if (sl->sl_mgmt_url_alloc_size) {
		kmem_free(sl->sl_mgmt_url, sl->sl_mgmt_url_alloc_size);
	}
	stmf_free(sl->sl_lu);
	return (ret);
}

int
sbd_create_register_lu(sbd_create_and_reg_lu_t *slu, int struct_sz,
    uint32_t *err_ret)
{
	char *namebuf;
	sbd_lu_t *sl;
	stmf_lu_t *lu;
	sbd_status_t sret;
	char *p;
	int sz;
	int alloc_sz;
	int ret = EIO;
	int flag;
	int wcd = 0;
	enum vtype vt;

	sz = struct_sz - sizeof (sbd_create_and_reg_lu_t) + 8 + 1;

	*err_ret = 0;

	/* Lets validate various offsets */
	if (((slu->slu_meta_fname_valid) &&
	    (slu->slu_meta_fname_off >= sz)) ||
	    (slu->slu_data_fname_off >= sz) ||
	    ((slu->slu_alias_valid) &&
	    (slu->slu_alias_off >= sz)) ||
	    ((slu->slu_mgmt_url_valid) &&
	    (slu->slu_mgmt_url_off >= sz)) ||
	    ((slu->slu_serial_valid) &&
	    ((slu->slu_serial_off + slu->slu_serial_size) >= sz))) {
		return (EINVAL);
	}

	namebuf = kmem_zalloc(sz, KM_SLEEP);
	bcopy(slu->slu_buf, namebuf, sz - 1);
	namebuf[sz - 1] = 0;

	alloc_sz = sizeof (sbd_lu_t) + sizeof (sbd_pgr_t);
	if (slu->slu_meta_fname_valid) {
		alloc_sz += strlen(namebuf + slu->slu_meta_fname_off) + 1;
	}
	alloc_sz += strlen(namebuf + slu->slu_data_fname_off) + 1;
	if (slu->slu_alias_valid) {
		alloc_sz += strlen(namebuf + slu->slu_alias_off) + 1;
	}
	if (slu->slu_mgmt_url_valid) {
		alloc_sz += strlen(namebuf + slu->slu_mgmt_url_off) + 1;
	}
	if (slu->slu_serial_valid) {
		alloc_sz += slu->slu_serial_size;
	}

	lu = (stmf_lu_t *)stmf_alloc(STMF_STRUCT_STMF_LU, alloc_sz, 0);
	if (lu == NULL) {
		kmem_free(namebuf, sz);
		return (ENOMEM);
	}
	sl = (sbd_lu_t *)lu->lu_provider_private;
	bzero(sl, alloc_sz);
	sl->sl_lu = lu;
	sl->sl_alloc_size = alloc_sz;
	sl->sl_pgr = (sbd_pgr_t *)(sl + 1);
	rw_init(&sl->sl_pgr->pgr_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&sl->sl_lock, NULL, MUTEX_DRIVER, NULL);
	p = ((char *)sl) + sizeof (sbd_lu_t) + sizeof (sbd_pgr_t);
	sl->sl_data_filename = p;
	(void) strcpy(sl->sl_data_filename, namebuf + slu->slu_data_fname_off);
	p += strlen(sl->sl_data_filename) + 1;
	sl->sl_meta_offset = SBD_META_OFFSET;
	if (slu->slu_meta_fname_valid) {
		sl->sl_alias = sl->sl_name = sl->sl_meta_filename = p;
		(void) strcpy(sl->sl_meta_filename, namebuf +
		    slu->slu_meta_fname_off);
		p += strlen(sl->sl_meta_filename) + 1;
	} else {
		sl->sl_alias = sl->sl_name = sl->sl_data_filename;
		if (sbd_is_zvol(sl->sl_data_filename)) {
			sl->sl_flags |= SL_ZFS_META;
			sl->sl_meta_offset = 0;
		} else {
			sl->sl_flags |= SL_SHARED_META;
			sl->sl_data_offset = SHARED_META_DATA_SIZE;
			sl->sl_total_meta_size = SHARED_META_DATA_SIZE;
			sl->sl_meta_size_used = 0;
		}
	}
	if (slu->slu_alias_valid) {
		sl->sl_alias = p;
		(void) strcpy(p, namebuf + slu->slu_alias_off);
		p += strlen(sl->sl_alias) + 1;
	}
	if (slu->slu_mgmt_url_valid) {
		sl->sl_mgmt_url = p;
		(void) strcpy(p, namebuf + slu->slu_mgmt_url_off);
		p += strlen(sl->sl_mgmt_url) + 1;
	}
	if (slu->slu_serial_valid) {
		sl->sl_serial_no = (uint8_t *)p;
		bcopy(namebuf + slu->slu_serial_off, sl->sl_serial_no,
		    slu->slu_serial_size);
		sl->sl_serial_no_size = slu->slu_serial_size;
		p += slu->slu_serial_size;
	}
	kmem_free(namebuf, sz);
	if (slu->slu_vid_valid) {
		bcopy(slu->slu_vid, sl->sl_vendor_id, 8);
		sl->sl_flags |= SL_VID_VALID;
	}
	if (slu->slu_pid_valid) {
		bcopy(slu->slu_pid, sl->sl_product_id, 16);
		sl->sl_flags |= SL_PID_VALID;
	}
	if (slu->slu_rev_valid) {
		bcopy(slu->slu_rev, sl->sl_revision, 4);
		sl->sl_flags |= SL_REV_VALID;
	}
	if (slu->slu_write_protected) {
		sl->sl_flags |= SL_WRITE_PROTECTED;
	}
	if (slu->slu_writeback_cache_disable) {
		sl->sl_flags |= SL_WRITEBACK_CACHE_DISABLE |
		    SL_SAVED_WRITE_CACHE_DISABLE;
	}

	if (slu->slu_blksize_valid) {
		if ((slu->slu_blksize & (slu->slu_blksize - 1)) ||
		    (slu->slu_blksize > (32 * 1024)) ||
		    (slu->slu_blksize == 0)) {
			*err_ret = SBD_RET_INVALID_BLKSIZE;
			ret = EINVAL;
			goto scm_err_out;
		}
		while ((1 << sl->sl_data_blocksize_shift) != slu->slu_blksize) {
			sl->sl_data_blocksize_shift++;
		}
	} else {
		sl->sl_data_blocksize_shift = 9;	/* 512 by default */
		slu->slu_blksize = 512;
	}

	/* Now lets start creating meta */
	sl->sl_trans_op = SL_OP_CREATE_REGISTER_LU;
	if (sbd_link_lu(sl) != SBD_SUCCESS) {
		*err_ret = SBD_RET_FILE_ALREADY_REGISTERED;
		ret = EALREADY;
		goto scm_err_out;
	}

	/* 1st focus on the data store */
	if (slu->slu_lu_size_valid) {
		sl->sl_lu_size = slu->slu_lu_size;
	}
	ret = sbd_open_data_file(sl, err_ret, slu->slu_lu_size_valid, 0, 0);
	slu->slu_ret_filesize_nbits = sl->sl_data_fs_nbits;
	slu->slu_lu_size = sl->sl_lu_size;
	if (ret) {
		goto scm_err_out;
	}

	/*
	 * set write cache disable on the device
	 * if it fails, we'll support it using sync/flush
	 */
	if (slu->slu_writeback_cache_disable) {
		(void) sbd_wcd_set(1, sl);
		wcd = 1;
	/*
	 * Attempt to set it to enable, if that fails and it was explicitly set
	 * return an error, otherwise get the current setting and use that
	 */
	} else {
		sret = sbd_wcd_set(0, sl);
		if (slu->slu_writeback_cache_disable_valid &&
		    sret != SBD_SUCCESS) {
			*err_ret = SBD_RET_WRITE_CACHE_SET_FAILED;
			ret = EFAULT;
			goto scm_err_out;
		}
		if (sret != SBD_SUCCESS) {
			sbd_wcd_get(&wcd, sl);
		}
	}

	if (wcd) {
		sl->sl_flags |= SL_WRITEBACK_CACHE_DISABLE |
		    SL_SAVED_WRITE_CACHE_DISABLE;
	}

	if (sl->sl_flags & SL_SHARED_META) {
		goto over_meta_open;
	}
	if (sl->sl_flags & SL_ZFS_META) {
		if (sbd_create_zfs_meta_object(sl) != SBD_SUCCESS) {
			*err_ret = SBD_RET_ZFS_META_CREATE_FAILED;
			ret = ENOMEM;
			goto scm_err_out;
		}
		sl->sl_meta_blocksize_shift = 0;
		goto over_meta_create;
	}
	if ((ret = lookupname(sl->sl_meta_filename, UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &sl->sl_meta_vp)) != 0) {
		*err_ret = SBD_RET_META_FILE_LOOKUP_FAILED;
		goto scm_err_out;
	}
	sl->sl_meta_vtype = vt = sl->sl_meta_vp->v_type;
	VN_RELE(sl->sl_meta_vp);
	if ((vt != VREG) && (vt != VCHR) && (vt != VBLK)) {
		*err_ret = SBD_RET_WRONG_META_FILE_TYPE;
		ret = EINVAL;
		goto scm_err_out;
	}
	if (vt == VREG) {
		sl->sl_meta_blocksize_shift = 0;
	} else {
		sl->sl_meta_blocksize_shift = 9;
	}
	flag = FREAD | FWRITE | FOFFMAX | FEXCL;
	if ((ret = vn_open(sl->sl_meta_filename, UIO_SYSSPACE, flag, 0,
	    &sl->sl_meta_vp, 0, 0)) != 0) {
		*err_ret = SBD_RET_META_FILE_OPEN_FAILED;
		goto scm_err_out;
	}
over_meta_create:
	sl->sl_total_meta_size = sl->sl_meta_offset + sizeof (sbd_meta_start_t);
	sl->sl_total_meta_size +=
	    (((uint64_t)1) << sl->sl_meta_blocksize_shift) - 1;
	sl->sl_total_meta_size &=
	    ~((((uint64_t)1) << sl->sl_meta_blocksize_shift) - 1);
	sl->sl_meta_size_used = 0;
over_meta_open:
	sl->sl_flags |= SL_META_OPENED;

	sl->sl_device_id[3] = 16;
	if (slu->slu_guid_valid) {
		sl->sl_device_id[0] = 0xf1;
		sl->sl_device_id[1] = 3;
		sl->sl_device_id[2] = 0;
		bcopy(slu->slu_guid, sl->sl_device_id + 4, 16);
	} else {
		if (!slu->slu_company_id_valid)
			slu->slu_company_id = COMPANY_ID_SUN;
		if (stmf_scsilib_uniq_lu_id(slu->slu_company_id,
		    (scsi_devid_desc_t *)&sl->sl_device_id[0]) !=
		    STMF_SUCCESS) {
			*err_ret = SBD_RET_META_CREATION_FAILED;
			ret = EIO;
			goto scm_err_out;
		}
		bcopy(sl->sl_device_id + 4, slu->slu_guid, 16);
	}

	/* Lets create the meta now */
	if (sbd_write_meta_start(sl, sl->sl_total_meta_size,
	    sizeof (sbd_meta_start_t)) != SBD_SUCCESS) {
		*err_ret = SBD_RET_META_CREATION_FAILED;
		ret = EIO;
		goto scm_err_out;
	}
	sl->sl_meta_size_used = sl->sl_meta_offset + sizeof (sbd_meta_start_t);

	if (sbd_write_lu_info(sl) != SBD_SUCCESS) {
		*err_ret = SBD_RET_META_CREATION_FAILED;
		ret = EIO;
		goto scm_err_out;
	}

	if (sbd_pgr_meta_init(sl) != SBD_SUCCESS) {
		*err_ret = SBD_RET_META_CREATION_FAILED;
		ret = EIO;
		goto scm_err_out;
	}

	ret = sbd_populate_and_register_lu(sl, err_ret);
	if (ret) {
		goto scm_err_out;
	}

	sl->sl_trans_op = SL_OP_NONE;
	atomic_add_32(&sbd_lu_count, 1);
	return (0);

scm_err_out:
	return (sbd_close_delete_lu(sl, ret));
}

int
sbd_load_sli_1_0(sbd_lu_t *sl, uint32_t *err_ret)
{
	sbd_lu_info_1_0_t *sli = NULL;
	sbd_status_t sret;

	sret = sbd_read_meta_section(sl, (sm_section_hdr_t **)&sli,
	    SMS_ID_LU_INFO_1_0);

	if (sret != SBD_SUCCESS) {
		*err_ret = SBD_RET_NO_META;
		return (EIO);
	}
	if (sli->sli_data_order != SMS_DATA_ORDER) {
		sbd_swap_lu_info_1_0(sli);
		if (sli->sli_data_order != SMS_DATA_ORDER) {
			kmem_free(sli, sli->sli_sms_header.sms_size);
			*err_ret = SBD_RET_NO_META;
			return (EIO);
		}
	}

	sl->sl_flags |= SL_SHARED_META;
	sl->sl_data_blocksize_shift = 9;
	sl->sl_data_offset = SHARED_META_DATA_SIZE;
	sl->sl_lu_size = sli->sli_total_store_size - SHARED_META_DATA_SIZE;
	sl->sl_total_data_size = SHARED_META_DATA_SIZE + sl->sl_lu_size;
	bcopy(sli->sli_lu_devid, sl->sl_device_id, 20);

	kmem_free(sli, sli->sli_sms_header.sms_size);
	return (0);
}

int
sbd_import_lu(sbd_import_lu_t *ilu, int struct_sz, uint32_t *err_ret,
    int no_register, sbd_lu_t **slr)
{
	stmf_lu_t *lu;
	sbd_lu_t *sl;
	sbd_lu_info_1_1_t *sli = NULL;
	int asz;
	int ret = 0;
	int flag;
	int wcd = 0;
	int data_opened;
	uint16_t sli_buf_sz;
	uint8_t *sli_buf_copy = NULL;
	enum vtype vt;
	sbd_status_t sret;

	if (no_register && slr == NULL) {
		return (EINVAL);
	}
	ilu->ilu_meta_fname[struct_sz - sizeof (*ilu) + 8 - 1] = 0;
	asz = strlen(ilu->ilu_meta_fname) + 1;

	lu = (stmf_lu_t *)stmf_alloc(STMF_STRUCT_STMF_LU,
	    sizeof (sbd_lu_t) + sizeof (sbd_pgr_t) + asz, 0);
	if (lu == NULL) {
		return (ENOMEM);
	}
	sl = (sbd_lu_t *)lu->lu_provider_private;
	bzero(sl, sizeof (*sl));
	sl->sl_lu = lu;
	sl->sl_pgr = (sbd_pgr_t *)(sl + 1);
	sl->sl_meta_filename = ((char *)sl) + sizeof (*sl) + sizeof (sbd_pgr_t);
	(void) strcpy(sl->sl_meta_filename, ilu->ilu_meta_fname);
	sl->sl_name = sl->sl_meta_filename;
	rw_init(&sl->sl_pgr->pgr_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&sl->sl_lock, NULL, MUTEX_DRIVER, NULL);
	sl->sl_trans_op = SL_OP_IMPORT_LU;
	/* we're only loading the metadata */
	if (!no_register) {
		if (sbd_link_lu(sl) != SBD_SUCCESS) {
			*err_ret = SBD_RET_FILE_ALREADY_REGISTERED;
			ret = EALREADY;
			goto sim_err_out;
		}
	}
	if ((ret = lookupname(sl->sl_meta_filename, UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &sl->sl_meta_vp)) != 0) {
		*err_ret = SBD_RET_META_FILE_LOOKUP_FAILED;
		goto sim_err_out;
	}
	if (sbd_is_zvol(sl->sl_meta_filename)) {
		sl->sl_flags |= SL_ZFS_META;
		sl->sl_data_filename = sl->sl_meta_filename;
	}
	sl->sl_meta_vtype = vt = sl->sl_meta_vp->v_type;
	VN_RELE(sl->sl_meta_vp);
	if ((vt != VREG) && (vt != VCHR) && (vt != VBLK)) {
		*err_ret = SBD_RET_WRONG_META_FILE_TYPE;
		ret = EINVAL;
		goto sim_err_out;
	}
	if (sl->sl_flags & SL_ZFS_META) {
		if (sbd_open_zfs_meta(sl) != SBD_SUCCESS) {
			/* let see if metadata is in the 64k block */
			sl->sl_flags &= ~SL_ZFS_META;
		}
	}
	if (!(sl->sl_flags & SL_ZFS_META)) {
		/* metadata is always writable */
		flag = FREAD | FWRITE | FOFFMAX | FEXCL;
		if ((ret = vn_open(sl->sl_meta_filename, UIO_SYSSPACE, flag, 0,
		    &sl->sl_meta_vp, 0, 0)) != 0) {
			*err_ret = SBD_RET_META_FILE_OPEN_FAILED;
			goto sim_err_out;
		}
	}
	if ((sl->sl_flags & SL_ZFS_META) || (vt == VREG)) {
		sl->sl_meta_blocksize_shift = 0;
	} else {
		sl->sl_meta_blocksize_shift = 9;
	}
	sl->sl_meta_offset = (sl->sl_flags & SL_ZFS_META) ? 0 : SBD_META_OFFSET;
	sl->sl_flags |= SL_META_OPENED;

	sret = sbd_load_meta_start(sl);
	if (sret != SBD_SUCCESS) {
		if (sret == SBD_META_CORRUPTED) {
			*err_ret = SBD_RET_NO_META;
		} else if (sret == SBD_NOT_SUPPORTED) {
			*err_ret = SBD_RET_VERSION_NOT_SUPPORTED;
		} else {
			*err_ret = SBD_RET_NO_META;
		}
		ret = EINVAL;
		goto sim_err_out;
	}

	/* Now lets see if we can read the most recent LU info */
	sret = sbd_read_meta_section(sl, (sm_section_hdr_t **)&sli,
	    SMS_ID_LU_INFO_1_1);
	if ((sret == SBD_NOT_FOUND) && ((sl->sl_flags & SL_ZFS_META) == 0)) {
		ret = sbd_load_sli_1_0(sl, err_ret);
		if (ret)
			goto sim_err_out;
		goto sim_sli_loaded;
	}
	if (sret != SBD_SUCCESS) {
		*err_ret = SBD_RET_NO_META;
		ret = EIO;
		goto sim_err_out;
	}
	/* load sli 1.1 */
	if (sli->sli_data_order != SMS_DATA_ORDER) {
		sbd_swap_lu_info_1_1(sli);
		if (sli->sli_data_order != SMS_DATA_ORDER) {
			*err_ret = SBD_RET_NO_META;
			ret = EIO;
			goto sim_err_out;
		}
	}

	sli_buf_sz = sli->sli_sms_header.sms_size -
	    sizeof (sbd_lu_info_1_1_t) + 8;
	sli_buf_copy = kmem_alloc(sli_buf_sz + 1, KM_SLEEP);
	bcopy(sli->sli_buf, sli_buf_copy, sli_buf_sz);
	sli_buf_copy[sli_buf_sz] = 0;

	/* Make sure all the offsets are within limits */
	if (((sli->sli_flags & SLI_META_FNAME_VALID) &&
	    (sli->sli_meta_fname_offset > sli_buf_sz)) ||
	    ((sli->sli_flags & SLI_DATA_FNAME_VALID) &&
	    (sli->sli_data_fname_offset > sli_buf_sz)) ||
	    ((sli->sli_flags & SLI_MGMT_URL_VALID) &&
	    (sli->sli_mgmt_url_offset > sli_buf_sz)) ||
	    ((sli->sli_flags & SLI_SERIAL_VALID) &&
	    ((sli->sli_serial_offset + sli->sli_serial_size) > sli_buf_sz)) ||
	    ((sli->sli_flags & SLI_ALIAS_VALID) &&
	    (sli->sli_alias_offset > sli_buf_sz))) {
		*err_ret = SBD_RET_NO_META;
		ret = EIO;
		goto sim_err_out;
	}

	if (sl->sl_flags & SL_ZFS_META) {
		/* Verify that its the right zfs node and not some clone */
		int same_zvol;
		char *zvol_name = sbd_get_zvol_name(sl);

		if ((sli->sli_flags & (SLI_ZFS_META |
		    SLI_META_FNAME_VALID)) == 0) {
			*err_ret = SBD_RET_NO_META;
			ret = EIO;
			kmem_free(zvol_name, strlen(zvol_name) + 1);
			goto sim_err_out;
		}
		if (strcmp(zvol_name, (char *)sli_buf_copy +
		    sli->sli_meta_fname_offset) != 0)
			same_zvol = 0;
		else
			same_zvol = 1;
		kmem_free(zvol_name, strlen(zvol_name) + 1);
		if (!same_zvol) {
			*err_ret = SBD_ZVOL_META_NAME_MISMATCH;
			ret = EINVAL;
			goto sim_err_out;
		}
	}
	sl->sl_lu_size = sli->sli_lu_size;
	sl->sl_data_blocksize_shift = sli->sli_data_blocksize_shift;
	bcopy(sli->sli_device_id, sl->sl_device_id, 20);
	if (sli->sli_flags & SLI_SERIAL_VALID) {
		sl->sl_serial_no_size = sl->sl_serial_no_alloc_size =
		    sli->sli_serial_size;
		sl->sl_serial_no = kmem_zalloc(sli->sli_serial_size, KM_SLEEP);
		bcopy(sli_buf_copy + sli->sli_serial_offset, sl->sl_serial_no,
		    sl->sl_serial_no_size);
	}
	if (sli->sli_flags & SLI_SEPARATE_META) {
		sl->sl_total_data_size = sl->sl_lu_size;
		if (sli->sli_flags & SLI_DATA_FNAME_VALID) {
			sl->sl_data_fname_alloc_size = strlen((char *)
			    sli_buf_copy + sli->sli_data_fname_offset) + 1;
			sl->sl_data_filename = kmem_zalloc(
			    sl->sl_data_fname_alloc_size, KM_SLEEP);
			(void) strcpy(sl->sl_data_filename,
			    (char *)sli_buf_copy + sli->sli_data_fname_offset);
		}
	} else {
		if (sl->sl_flags & SL_ZFS_META) {
			sl->sl_total_data_size = sl->sl_lu_size;
			sl->sl_data_offset = 0;
		} else {
			sl->sl_total_data_size =
			    sl->sl_lu_size + SHARED_META_DATA_SIZE;
			sl->sl_data_offset = SHARED_META_DATA_SIZE;
			sl->sl_flags |= SL_SHARED_META;
		}
	}
	if (sli->sli_flags & SLI_ALIAS_VALID) {
		sl->sl_alias_alloc_size = strlen((char *)sli_buf_copy +
		    sli->sli_alias_offset) + 1;
		sl->sl_alias = kmem_alloc(sl->sl_alias_alloc_size, KM_SLEEP);
		(void) strcpy(sl->sl_alias, (char *)sli_buf_copy +
		    sli->sli_alias_offset);
	}
	if (sli->sli_flags & SLI_MGMT_URL_VALID) {
		sl->sl_mgmt_url_alloc_size = strlen((char *)sli_buf_copy +
		    sli->sli_mgmt_url_offset) + 1;
		sl->sl_mgmt_url = kmem_alloc(sl->sl_mgmt_url_alloc_size,
		    KM_SLEEP);
		(void) strcpy(sl->sl_mgmt_url, (char *)sli_buf_copy +
		    sli->sli_mgmt_url_offset);
	}
	if (sli->sli_flags & SLI_WRITE_PROTECTED) {
		sl->sl_flags |= SL_WRITE_PROTECTED;
	}
	if (sli->sli_flags & SLI_VID_VALID) {
		sl->sl_flags |= SL_VID_VALID;
		bcopy(sli->sli_vid, sl->sl_vendor_id, 8);
	}
	if (sli->sli_flags & SLI_PID_VALID) {
		sl->sl_flags |= SL_PID_VALID;
		bcopy(sli->sli_pid, sl->sl_product_id, 16);
	}
	if (sli->sli_flags & SLI_REV_VALID) {
		sl->sl_flags |= SL_REV_VALID;
		bcopy(sli->sli_rev, sl->sl_revision, 4);
	}
	if (sli->sli_flags & SLI_WRITEBACK_CACHE_DISABLE) {
		sl->sl_flags |= SL_WRITEBACK_CACHE_DISABLE;
	}
sim_sli_loaded:
	if ((sl->sl_flags & SL_SHARED_META) == 0) {
		data_opened = 0;
	} else {
		data_opened = 1;
		sl->sl_data_filename = sl->sl_meta_filename;
		sl->sl_data_vp = sl->sl_meta_vp;
		sl->sl_data_vtype = sl->sl_meta_vtype;
	}

	sret = sbd_pgr_meta_load(sl);
	if (sret != SBD_SUCCESS) {
		*err_ret = SBD_RET_NO_META;
		ret = EIO;
		goto sim_err_out;
	}

	ret = sbd_open_data_file(sl, err_ret, 1, data_opened, 0);
	if (ret)
		goto sim_err_out;

	/*
	 * set write cache disable on the device
	 * Note: this shouldn't fail on import unless the cache capabilities
	 * of the device changed. If that happened, modify will need to
	 * be used to set the cache flag appropriately after import is done.
	 */
	if (sl->sl_flags & SL_WRITEBACK_CACHE_DISABLE) {
		(void) sbd_wcd_set(1, sl);
		wcd = 1;
	/*
	 * if not explicitly set, attempt to set it to enable, if that fails
	 * get the current setting and use that
	 */
	} else {
		sret = sbd_wcd_set(0, sl);
		if (sret != SBD_SUCCESS) {
			sbd_wcd_get(&wcd, sl);
		}
	}

	if (wcd) {
		sl->sl_flags |= SL_WRITEBACK_CACHE_DISABLE |
		    SL_SAVED_WRITE_CACHE_DISABLE;
	}

	/* we're only loading the metadata */
	if (!no_register) {
		ret = sbd_populate_and_register_lu(sl, err_ret);
		if (ret)
			goto sim_err_out;
		atomic_add_32(&sbd_lu_count, 1);
	}

	bcopy(sl->sl_device_id + 4, ilu->ilu_ret_guid, 16);
	sl->sl_trans_op = SL_OP_NONE;
	if (sli) {
		kmem_free(sli, sli->sli_sms_header.sms_size);
		sli = NULL;
	}
	if (sli_buf_copy) {
		kmem_free(sli_buf_copy, sli_buf_sz + 1);
		sli_buf_copy = NULL;
	}
	if (no_register) {
		*slr = sl;
	}
	return (0);

sim_err_out:
	if (sli) {
		kmem_free(sli, sli->sli_sms_header.sms_size);
		sli = NULL;
	}
	if (sli_buf_copy) {
		kmem_free(sli_buf_copy, sli_buf_sz + 1);
		sli_buf_copy = NULL;
	}
	return (sbd_close_delete_lu(sl, ret));
}

int
sbd_modify_lu(sbd_modify_lu_t *mlu, int struct_sz, uint32_t *err_ret)
{
	sbd_lu_t *sl = NULL;
	uint16_t alias_sz;
	int ret = 0;
	sbd_it_data_t *it;
	sbd_status_t sret;
	uint64_t old_size;
	int modify_unregistered = 0;
	int ua = 0;
	sbd_import_lu_t *ilu;
	stmf_lu_t *lu;
	uint32_t ilu_sz;
	uint32_t sz;

	sz = struct_sz - sizeof (*mlu) + 8 + 1;

	/* if there is data in the buf, null terminate it */
	if (struct_sz > sizeof (*mlu)) {
		mlu->mlu_buf[struct_sz - sizeof (*mlu) + 8 - 1] = 0;
	}

	*err_ret = 0;

	/* Lets validate offsets */
	if (((mlu->mlu_alias_valid) &&
	    (mlu->mlu_alias_off >= sz)) ||
	    ((mlu->mlu_mgmt_url_valid) &&
	    (mlu->mlu_mgmt_url_off >= sz)) ||
	    (mlu->mlu_by_fname) &&
	    (mlu->mlu_fname_off >= sz)) {
		return (EINVAL);
	}

	/*
	 * We'll look for the device but if we don't find it registered,
	 * we'll still try to modify the unregistered device.
	 */
	if (mlu->mlu_by_guid) {
		sret = sbd_find_and_lock_lu(mlu->mlu_input_guid, NULL,
		    SL_OP_MODIFY_LU, &sl);
	} else if (mlu->mlu_by_fname) {
		sret = sbd_find_and_lock_lu(NULL,
		    (uint8_t *)&(mlu->mlu_buf[mlu->mlu_fname_off]),
		    SL_OP_MODIFY_LU, &sl);
	} else {
		return (EINVAL);
	}


	if (sret != SBD_SUCCESS) {
		if (sret == SBD_BUSY) {
			*err_ret = SBD_RET_LU_BUSY;
			return (EBUSY);
		} else if (sret != SBD_NOT_FOUND) {
			return (EIO);
		} else if (!mlu->mlu_by_fname) {
			return (EINVAL);
		}
		/* Okay, try to import the device */
		struct_sz = max(8, strlen(&(mlu->mlu_buf[mlu->mlu_fname_off]))
		    + 1);
		struct_sz += sizeof (sbd_import_lu_t) - 8;
		ilu_sz = struct_sz;
		ilu = (sbd_import_lu_t *)kmem_zalloc(ilu_sz, KM_SLEEP);
		ilu->ilu_struct_size = struct_sz;
		(void) strcpy(ilu->ilu_meta_fname,
		    &(mlu->mlu_buf[mlu->mlu_fname_off]));
		ret = sbd_import_lu(ilu, struct_sz, err_ret, 1, &sl);
		kmem_free(ilu, ilu_sz);
		if (ret != SBD_SUCCESS) {
			return (ENOENT);
		}
		modify_unregistered = 1;
	}

	/* check for write cache change */
	if (mlu->mlu_writeback_cache_disable_valid) {
		/* set wce on device */
		sret = sbd_wcd_set(mlu->mlu_writeback_cache_disable, sl);
		if (!mlu->mlu_writeback_cache_disable && sret != SBD_SUCCESS) {
			*err_ret = SBD_RET_WRITE_CACHE_SET_FAILED;
			ret = EFAULT;
			goto smm_err_out;
		}
		mutex_enter(&sl->sl_lock);
		if (!mlu->mlu_writeback_cache_disable) {
			if (sl->sl_flags & SL_WRITEBACK_CACHE_DISABLE) {
				ua = 1;
				sl->sl_flags &= ~SL_WRITEBACK_CACHE_DISABLE;
				sl->sl_flags &= ~SL_SAVED_WRITE_CACHE_DISABLE;
			}
		} else {
			if ((sl->sl_flags & SL_WRITEBACK_CACHE_DISABLE) == 0) {
				ua = 1;
				sl->sl_flags |= SL_WRITEBACK_CACHE_DISABLE;
				sl->sl_flags |= SL_SAVED_WRITE_CACHE_DISABLE;
			}
		}
		for (it = sl->sl_it_list; ua && it != NULL;
		    it = it->sbd_it_next) {
			it->sbd_it_ua_conditions |=
			    SBD_UA_MODE_PARAMETERS_CHANGED;
		}
		mutex_exit(&sl->sl_lock);
	}
	ua = 0;

	if (mlu->mlu_alias_valid) {
		alias_sz = strlen((char *)mlu->mlu_buf +
		    mlu->mlu_alias_off) + 1;
		/*
		 * Use the allocated buffer or alloc a new one.
		 * Don't copy into sl_alias if sl_alias_alloc_size is 0
		 * otherwise or you'll be writing over the data/metadata
		 * filename.
		 */
		mutex_enter(&sl->sl_lock);
		if (sl->sl_alias_alloc_size > 0 &&
		    sl->sl_alias_alloc_size < alias_sz) {
			kmem_free(sl->sl_alias,
			    sl->sl_alias_alloc_size);
			sl->sl_alias_alloc_size = 0;
		}
		if (sl->sl_alias_alloc_size == 0) {
			sl->sl_alias = kmem_alloc(alias_sz, KM_SLEEP);
			sl->sl_alias_alloc_size = alias_sz;
		}
		(void) strcpy(sl->sl_alias, (char *)mlu->mlu_buf +
		    mlu->mlu_alias_off);
		lu = sl->sl_lu;
		lu->lu_alias = sl->sl_alias;
		mutex_exit(&sl->sl_lock);
	}

	if (mlu->mlu_mgmt_url_valid) {
		uint16_t url_sz;

		url_sz = strlen((char *)mlu->mlu_buf + mlu->mlu_mgmt_url_off);
		if (url_sz > 0)
			url_sz++;

		mutex_enter(&sl->sl_lock);
		if (sl->sl_mgmt_url_alloc_size > 0 &&
		    (url_sz == 0 || sl->sl_mgmt_url_alloc_size < url_sz)) {
			kmem_free(sl->sl_mgmt_url, sl->sl_mgmt_url_alloc_size);
			sl->sl_mgmt_url = NULL;
			sl->sl_mgmt_url_alloc_size = 0;
		}
		if (url_sz > 0) {
			if (sl->sl_mgmt_url_alloc_size == 0) {
				sl->sl_mgmt_url = kmem_alloc(url_sz, KM_SLEEP);
				sl->sl_mgmt_url_alloc_size = url_sz;
			}
			(void) strcpy(sl->sl_mgmt_url, (char *)mlu->mlu_buf +
			    mlu->mlu_mgmt_url_off);
		}
		for (it = sl->sl_it_list; it != NULL;
		    it = it->sbd_it_next) {
			it->sbd_it_ua_conditions |=
			    SBD_UA_MODE_PARAMETERS_CHANGED;
		}
		mutex_exit(&sl->sl_lock);
	}

	if (mlu->mlu_write_protected_valid) {
		mutex_enter(&sl->sl_lock);
		if (mlu->mlu_write_protected) {
			if ((sl->sl_flags & SL_WRITE_PROTECTED) == 0) {
				ua = 1;
				sl->sl_flags |= SL_WRITE_PROTECTED;
			}
		} else {
			if (sl->sl_flags & SL_WRITE_PROTECTED) {
				ua = 1;
				sl->sl_flags &= ~SL_WRITE_PROTECTED;
			}
		}
		for (it = sl->sl_it_list; ua && it != NULL;
		    it = it->sbd_it_next) {
			it->sbd_it_ua_conditions |=
			    SBD_UA_MODE_PARAMETERS_CHANGED;
		}
		mutex_exit(&sl->sl_lock);
	}

	if (mlu->mlu_lu_size_valid) {
		/*
		 * validate lu size and set
		 * For open file only (registered lu)
		 */
		mutex_enter(&sl->sl_lock);
		old_size = sl->sl_lu_size;
		sl->sl_lu_size = mlu->mlu_lu_size;
		mutex_exit(&sl->sl_lock);
		ret = sbd_open_data_file(sl, err_ret, 1, 1, 1);
		if (ret) {
			mutex_enter(&sl->sl_lock);
			sl->sl_lu_size = old_size;
			mutex_exit(&sl->sl_lock);
			goto smm_err_out;
		}
		if (old_size != mlu->mlu_lu_size) {
			mutex_enter(&sl->sl_lock);
			for (it = sl->sl_it_list; it != NULL;
			    it = it->sbd_it_next) {
				it->sbd_it_ua_conditions |=
				    SBD_UA_CAPACITY_CHANGED;
			}
			mutex_exit(&sl->sl_lock);
		}
	}

	if (sbd_write_lu_info(sl) != SBD_SUCCESS) {
		*err_ret = SBD_RET_META_CREATION_FAILED;
		ret = EIO;
	}

smm_err_out:
	if (modify_unregistered) {
		(void) sbd_close_delete_lu(sl, 0);
	} else {
		sl->sl_trans_op = SL_OP_NONE;
	}
	return (ret);
}

/* ARGSUSED */
int
sbd_delete_locked_lu(sbd_lu_t *sl, uint32_t *err_ret,
    stmf_state_change_info_t *ssi)
{
	int i;

	if ((sl->sl_state == STMF_STATE_OFFLINE) &&
	    !sl->sl_state_not_acked) {
		goto sdl_do_dereg;
	}

	if ((sl->sl_state != STMF_STATE_ONLINE) ||
	    sl->sl_state_not_acked) {
		return (EBUSY);
	}
	if (stmf_ctl(STMF_CMD_LU_OFFLINE, sl->sl_lu, ssi) != STMF_SUCCESS) {
		return (EBUSY);
	}

	for (i = 0; i < 500; i++) {
		if (sl->sl_state == STMF_STATE_OFFLINE)
			break;
		delay(drv_usectohz(10000));
	}

	if ((sl->sl_state == STMF_STATE_OFFLINE) &&
	    !sl->sl_state_not_acked) {
		goto sdl_do_dereg;
	}

	return (EBUSY);
sdl_do_dereg:;
	if (stmf_deregister_lu(sl->sl_lu) != STMF_SUCCESS)
		return (EBUSY);
	atomic_add_32(&sbd_lu_count, -1);

	return (sbd_close_delete_lu(sl, 0));
}

int
sbd_delete_lu(sbd_delete_lu_t *dlu, int struct_sz, uint32_t *err_ret)
{
	sbd_lu_t *sl;
	sbd_status_t sret;
	stmf_state_change_info_t ssi;
	int ret;

	if (dlu->dlu_by_meta_name) {
		((char *)dlu)[struct_sz - 1] = 0;
		sret = sbd_find_and_lock_lu(NULL, dlu->dlu_meta_name,
		    SL_OP_DELETE_LU, &sl);
	} else {
		sret = sbd_find_and_lock_lu(dlu->dlu_guid, NULL,
		    SL_OP_DELETE_LU, &sl);
	}
	if (sret != SBD_SUCCESS) {
		if (sret == SBD_BUSY) {
			*err_ret = SBD_RET_LU_BUSY;
			return (EBUSY);
		} else if (sret == SBD_NOT_FOUND) {
			*err_ret = SBD_RET_NOT_FOUND;
			return (ENOENT);
		}
		return (EIO);
	}

	ssi.st_rflags = STMF_RFLAG_USER_REQUEST;
	ssi.st_additional_info = "sbd_delete_lu call (ioctl)";
	ret = sbd_delete_locked_lu(sl, err_ret, &ssi);

	if (ret) {
		/* Once its locked, no need to grab mutex again */
		sl->sl_trans_op = SL_OP_NONE;
	}
	return (ret);
}

sbd_status_t
sbd_data_read(sbd_lu_t *sl, uint64_t offset, uint64_t size, uint8_t *buf)
{
	int ret;
	long resid;

	if ((offset + size) > sl->sl_lu_size) {
		return (SBD_IO_PAST_EOF);
	}

	offset += sl->sl_data_offset;

	if ((offset + size) > sl->sl_data_readable_size) {
		uint64_t store_end;
		if (offset > sl->sl_data_readable_size) {
			bzero(buf, size);
			return (SBD_SUCCESS);
		}
		store_end = sl->sl_data_readable_size - offset;
		bzero(buf + store_end, size - store_end);
		size = store_end;
	}

	DTRACE_PROBE4(backing__store__read__start, sbd_lu_t *, sl,
	    uint8_t *, buf, uint64_t, size, uint64_t, offset);

	ret = vn_rdwr(UIO_READ, sl->sl_data_vp, (caddr_t)buf, (ssize_t)size,
	    (offset_t)offset, UIO_SYSSPACE, 0, RLIM64_INFINITY, CRED(),
	    &resid);

	DTRACE_PROBE5(backing__store__read__end, sbd_lu_t *, sl,
	    uint8_t *, buf, uint64_t, size, uint64_t, offset,
	    int, ret);

over_sl_data_read:
	if (ret || resid) {
		stmf_trace(0, "UIO_READ failed, ret = %d, resid = %d", ret,
		    resid);
		return (SBD_FAILURE);
	}

	return (SBD_SUCCESS);
}

sbd_status_t
sbd_data_write(sbd_lu_t *sl, uint64_t offset, uint64_t size, uint8_t *buf)
{
	int ret;
	long resid;
	sbd_status_t sret = SBD_SUCCESS;
	int ioflag;

	if ((offset + size) > sl->sl_lu_size) {
		return (SBD_IO_PAST_EOF);
	}

	offset += sl->sl_data_offset;

	if ((sl->sl_flags & SL_WRITEBACK_CACHE_DISABLE) &&
	    (sl->sl_flags & SL_FLUSH_ON_DISABLED_WRITECACHE)) {
		ioflag = FSYNC;
	} else {
		ioflag = 0;
	}

	DTRACE_PROBE4(backing__store__write__start, sbd_lu_t *, sl,
	    uint8_t *, buf, uint64_t, size, uint64_t, offset);

	ret = vn_rdwr(UIO_WRITE, sl->sl_data_vp, (caddr_t)buf, (ssize_t)size,
	    (offset_t)offset, UIO_SYSSPACE, ioflag, RLIM64_INFINITY, CRED(),
	    &resid);

	DTRACE_PROBE5(backing__store__write__end, sbd_lu_t *, sl,
	    uint8_t *, buf, uint64_t, size, uint64_t, offset,
	    int, ret);

	if ((ret == 0) && (resid == 0) &&
	    (sl->sl_flags & SL_WRITEBACK_CACHE_DISABLE) &&
	    (sl->sl_flags & SL_FLUSH_ON_DISABLED_WRITECACHE)) {
		sret = sbd_flush_data_cache(sl, 1);
	}
over_sl_data_write:

	if ((ret || resid) || (sret != SBD_SUCCESS)) {
		return (SBD_FAILURE);
	} else if ((offset + size) > sl->sl_data_readable_size) {
		uint64_t old_size, new_size;

		do {
			old_size = sl->sl_data_readable_size;
			if ((offset + size) <= old_size)
				break;
			new_size = offset + size;
		} while (atomic_cas_64(&sl->sl_data_readable_size, old_size,
		    new_size) != old_size);
	}

	return (SBD_SUCCESS);
}

int
sbd_get_lu_props(sbd_lu_props_t *islp, uint32_t islp_sz,
    sbd_lu_props_t *oslp, uint32_t oslp_sz, uint32_t *err_ret)
{
	sbd_status_t sret;
	sbd_lu_t *sl = NULL;
	uint32_t sz;
	uint16_t off;

	if (islp->slp_input_guid) {
		sret = sbd_find_and_lock_lu(islp->slp_guid, NULL,
		    SL_OP_LU_PROPS, &sl);
	} else {
		((char *)islp)[islp_sz - 1] = 0;
		sret = sbd_find_and_lock_lu(NULL, islp->slp_buf,
		    SL_OP_LU_PROPS, &sl);
	}
	if (sret != SBD_SUCCESS) {
		if (sret == SBD_BUSY) {
			*err_ret = SBD_RET_LU_BUSY;
			return (EBUSY);
		} else if (sret == SBD_NOT_FOUND) {
			*err_ret = SBD_RET_NOT_FOUND;
			return (ENOENT);
		}
		return (EIO);
	}

	sz = strlen(sl->sl_name) + 1;
	if ((sl->sl_flags & (SL_ZFS_META | SL_SHARED_META)) == 0) {
		if (sl->sl_data_filename) {
			sz += strlen(sl->sl_data_filename) + 1;
		}
	}
	sz += sl->sl_serial_no_size;
	if (sl->sl_alias) {
		sz += strlen(sl->sl_alias) + 1;
	}

	if (sl->sl_mgmt_url) {
		sz += strlen(sl->sl_mgmt_url) + 1;
	}
	bzero(oslp, sizeof (*oslp) - 8);
	oslp->slp_buf_size_needed = sz;

	if (sz > (oslp_sz - sizeof (*oslp) + 8)) {
		sl->sl_trans_op = SL_OP_NONE;
		*err_ret = SBD_RET_INSUFFICIENT_BUF_SPACE;
		return (ENOMEM);
	}

	off = 0;
	(void) strcpy((char *)oslp->slp_buf, sl->sl_name);
	oslp->slp_meta_fname_off = off;
	off += strlen(sl->sl_name) + 1;
	if ((sl->sl_flags & (SL_ZFS_META | SL_SHARED_META)) == 0) {
		oslp->slp_meta_fname_valid = 1;
		oslp->slp_separate_meta = 1;
		if (sl->sl_data_filename) {
			oslp->slp_data_fname_valid = 1;
			oslp->slp_data_fname_off = off;
			(void) strcpy((char *)&oslp->slp_buf[off],
			    sl->sl_data_filename);
			off += strlen(sl->sl_data_filename) + 1;
		}
	} else {
		oslp->slp_data_fname_valid = 1;
		oslp->slp_data_fname_off = oslp->slp_meta_fname_off;
		if (sl->sl_flags & SL_ZFS_META) {
			oslp->slp_zfs_meta = 1;
		}
	}
	if (sl->sl_alias) {
		oslp->slp_alias_valid = 1;
		oslp->slp_alias_off = off;
		(void) strcpy((char *)&oslp->slp_buf[off], sl->sl_alias);
		off += strlen(sl->sl_alias) + 1;
	}
	if (sl->sl_mgmt_url) {
		oslp->slp_mgmt_url_valid = 1;
		oslp->slp_mgmt_url_off = off;
		(void) strcpy((char *)&oslp->slp_buf[off], sl->sl_mgmt_url);
		off += strlen(sl->sl_mgmt_url) + 1;
	}
	if (sl->sl_serial_no_size) {
		oslp->slp_serial_off = off;
		bcopy(sl->sl_serial_no, &oslp->slp_buf[off],
		    sl->sl_serial_no_size);
		oslp->slp_serial_size = sl->sl_serial_no_size;
		oslp->slp_serial_valid = 1;
		off += sl->sl_serial_no_size;
	}

	oslp->slp_lu_size = sl->sl_lu_size;
	oslp->slp_blksize = ((uint16_t)1) << sl->sl_data_blocksize_shift;

	if (sl->sl_flags & SL_VID_VALID) {
		oslp->slp_lu_vid = 1;
		bcopy(sl->sl_vendor_id, oslp->slp_vid, 8);
	} else {
		bcopy(sbd_vendor_id, oslp->slp_vid, 8);
	}
	if (sl->sl_flags & SL_PID_VALID) {
		oslp->slp_lu_pid = 1;
		bcopy(sl->sl_product_id, oslp->slp_pid, 16);
	} else {
		bcopy(sbd_product_id, oslp->slp_pid, 16);
	}
	if (sl->sl_flags & SL_REV_VALID) {
		oslp->slp_lu_rev = 1;
		bcopy(sl->sl_revision, oslp->slp_rev, 4);
	} else {
		bcopy(sbd_revision, oslp->slp_rev, 4);
	}
	bcopy(sl->sl_device_id + 4, oslp->slp_guid, 16);

	if (sl->sl_flags & SL_WRITEBACK_CACHE_DISABLE)
		oslp->slp_writeback_cache_disable_cur = 1;
	if (sl->sl_flags & SL_SAVED_WRITE_CACHE_DISABLE)
		oslp->slp_writeback_cache_disable_saved = 1;
	if (sl->sl_flags & SL_WRITE_PROTECTED)
		oslp->slp_write_protected = 1;

	sl->sl_trans_op = SL_OP_NONE;

	return (0);
}

char *
sbd_get_zvol_name(sbd_lu_t *sl)
{
	char *src;
	char *p;

	if (sl->sl_data_filename)
		src = sl->sl_data_filename;
	else
		src = sl->sl_meta_filename;
	/* There has to be a better way */
	if (SBD_IS_ZVOL(src) != 0) {
		ASSERT(0);
	}
	src += 14;
	if (*src == '/')
		src++;
	p = (char *)kmem_alloc(strlen(src) + 1, KM_SLEEP);
	(void) strcpy(p, src);
	return (p);
}

/*
 * this function creates a local metadata zvol property
 */
sbd_status_t
sbd_create_zfs_meta_object(sbd_lu_t *sl)
{
	/*
	 * -allocate 1/2 the property size, the zfs property
	 *  is 8k in size and stored as ascii hex string, all
	 *  we needed is 4k buffer to store the binary data.
	 * -initialize reader/write lock
	 */
	if ((sl->sl_zfs_meta = kmem_zalloc(ZAP_MAXVALUELEN / 2, KM_SLEEP))
	    == NULL)
		return (SBD_FAILURE);
	rw_init(&sl->sl_zfs_meta_lock, NULL, RW_DRIVER, NULL);
	return (SBD_SUCCESS);
}

char
sbd_ctoi(char c)
{
	if ((c >= '0') && (c <= '9'))
		c -= '0';
	else if ((c >= 'A') && (c <= 'F'))
		c = c - 'A' + 10;
	else if ((c >= 'a') && (c <= 'f'))
		c = c - 'a' + 10;
	else
		c = -1;
	return (c);
}

/*
 * read zvol property and convert to binary
 */
sbd_status_t
sbd_open_zfs_meta(sbd_lu_t *sl)
{
	char		*meta = NULL, cl, ch;
	int		i;
	char		*tmp, *ptr;
	uint64_t	rc = SBD_SUCCESS;
	int		len;
	char		*file;

	if (sbd_create_zfs_meta_object(sl) == SBD_FAILURE)
		return (SBD_FAILURE);

	rw_enter(&sl->sl_zfs_meta_lock, RW_WRITER);
	file = sbd_get_zvol_name(sl);
	if (sbd_zvolget(file, &meta)) {
		rc = SBD_FAILURE;
		goto done;
	}
	tmp = meta;
	/* convert ascii hex to binary meta */
	len = strlen(meta);
	ptr = sl->sl_zfs_meta;
	for (i = 0; i < len; i += 2) {
		ch = sbd_ctoi(*tmp++);
		cl = sbd_ctoi(*tmp++);
		if (ch == -1 || cl == -1) {
			rc = SBD_FAILURE;
			break;
		}
		*ptr++ = (ch << 4) + cl;
	}
done:
	rw_exit(&sl->sl_zfs_meta_lock);
	if (meta)
		kmem_free(meta, len + 1);
	kmem_free(file, strlen(file) + 1);
	return (rc);
}

sbd_status_t
sbd_read_zfs_meta(sbd_lu_t *sl, uint8_t *buf, uint64_t sz, uint64_t off)
{
	ASSERT(sl->sl_zfs_meta);
	rw_enter(&sl->sl_zfs_meta_lock, RW_READER);
	bcopy(&sl->sl_zfs_meta[off], buf, sz);
	rw_exit(&sl->sl_zfs_meta_lock);
	return (SBD_SUCCESS);
}

sbd_status_t
sbd_write_zfs_meta(sbd_lu_t *sl, uint8_t *buf, uint64_t sz, uint64_t off)
{
	char		*ptr, *ah_meta;
	char		*dp = NULL;
	int		i, num;
	char		*file;

	ASSERT(sl->sl_zfs_meta);
	if ((off + sz) > (ZAP_MAXVALUELEN / 2 - 1)) {
		return (SBD_META_CORRUPTED);
	}
	ptr = ah_meta = kmem_zalloc(ZAP_MAXVALUELEN, KM_SLEEP);
	rw_enter(&sl->sl_zfs_meta_lock, RW_WRITER);
	bcopy(buf, &sl->sl_zfs_meta[off], sz);
	/* convert local copy to ascii hex */
	dp = sl->sl_zfs_meta;
	for (i = 0; i < sl->sl_total_meta_size; i++, dp++) {
		num = ((*dp) >> 4) & 0xF;
		*ah_meta++ = (num < 10) ? (num + '0') : (num + ('a' - 10));
		num = (*dp) & 0xF;
		*ah_meta++ = (num < 10) ? (num + '0') : (num + ('a' - 10));
	}
	*ah_meta = NULL;
	file = sbd_get_zvol_name(sl);
	if (sbd_zvolset(file, (char *)ptr)) {
		rw_exit(&sl->sl_zfs_meta_lock);
		kmem_free(ptr, ZAP_MAXVALUELEN);
		kmem_free(file, strlen(file) + 1);
		return (SBD_META_CORRUPTED);
	}
	rw_exit(&sl->sl_zfs_meta_lock);
	kmem_free(ptr, ZAP_MAXVALUELEN);
	kmem_free(file, strlen(file) + 1);
	return (SBD_SUCCESS);
}

int
sbd_is_zvol(char *path)
{
	int is_zfs = 0;

	if (SBD_IS_ZVOL(path) == 0)
		is_zfs = 1;

	return (is_zfs);
}

/*
 * set write cache disable
 * wcd - 1 = disable, 0 = enable
 */
sbd_status_t
sbd_wcd_set(int wcd, sbd_lu_t *sl)
{
	/* translate to wce bit */
	int wce = wcd ? 0 : 1;
	int ret;
	sbd_status_t sret = SBD_SUCCESS;

	mutex_enter(&sl->sl_lock);
	sl->sl_flags &= ~SL_WRITEBACK_CACHE_SET_UNSUPPORTED;

	if (sl->sl_data_vp->v_type == VREG) {
		sl->sl_flags |= SL_FLUSH_ON_DISABLED_WRITECACHE;
		goto done;
	}

	ret = VOP_IOCTL(sl->sl_data_vp, DKIOCSETWCE, (intptr_t)&wce, FKIOCTL,
	    kcred, NULL, NULL);
	if (ret == 0) {
		sl->sl_flags &= ~SL_WRITEBACK_CACHE_SET_UNSUPPORTED;
		sl->sl_flags &= ~SL_FLUSH_ON_DISABLED_WRITECACHE;
	} else {
		sl->sl_flags |= SL_WRITEBACK_CACHE_SET_UNSUPPORTED;
		sl->sl_flags |= SL_FLUSH_ON_DISABLED_WRITECACHE;
		sret = SBD_FAILURE;
		goto done;
	}

done:
	mutex_exit(&sl->sl_lock);
	return (sret);
}

/*
 * get write cache disable
 * wcd - 1 = disable, 0 = enable
 */
void
sbd_wcd_get(int *wcd, sbd_lu_t *sl)
{
	int wce;
	int ret;

	if (sl->sl_data_vp->v_type == VREG) {
		*wcd = 0;
		return;
	}

	ret = VOP_IOCTL(sl->sl_data_vp, DKIOCGETWCE, (intptr_t)&wce, FKIOCTL,
	    kcred, NULL, NULL);
	/* if write cache get failed, assume disabled */
	if (ret) {
		*wcd = 1;
	} else {
		/* translate to wcd bit */
		*wcd = wce ? 0 : 1;
	}
}

int
sbd_zvolget(char *zvol_name, char **comstarprop)
{
	ldi_handle_t	zfs_lh;
	nvlist_t	*nv = NULL, *nv2;
	zfs_cmd_t	*zc;
	char		*ptr;
	int size = 1024;
	int unused;
	int rc;

	if ((rc = ldi_open_by_name("/dev/zfs", FREAD | FWRITE, kcred,
	    &zfs_lh, sbd_zfs_ident)) != 0) {
		cmn_err(CE_WARN, "ldi_open %d", rc);
		return (ENXIO);
	}

	zc = kmem_zalloc(sizeof (zfs_cmd_t), KM_SLEEP);
	(void) strlcpy(zc->zc_name, zvol_name, sizeof (zc->zc_name));
again:
	zc->zc_nvlist_dst = (uint64_t)(intptr_t)kmem_alloc(size,
	    KM_SLEEP);
	zc->zc_nvlist_dst_size = size;
	rc = ldi_ioctl(zfs_lh, ZFS_IOC_OBJSET_STATS, (intptr_t)zc,
	    FKIOCTL, kcred, &unused);
	/*
	 * ENOMEM means the list is larger than what we've allocated
	 * ldi_ioctl will fail with ENOMEM only once
	 */
	if (rc == ENOMEM) {
		int newsize;
		newsize = zc->zc_nvlist_dst_size;
		kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, size);
		size = newsize;
		goto again;
	} else if (rc != 0) {
		goto out;
	}
	rc = nvlist_unpack((char *)(uintptr_t)zc->zc_nvlist_dst,
	    zc->zc_nvlist_dst_size, &nv, 0);
	ASSERT(rc == 0);	/* nvlist_unpack should not fail */
	if ((rc = nvlist_lookup_nvlist(nv, "stmf_sbd_lu", &nv2)) == 0) {
		rc = nvlist_lookup_string(nv2, ZPROP_VALUE, &ptr);
		if (rc != 0) {
			cmn_err(CE_WARN, "couldn't get value");
		} else {
			*comstarprop = kmem_alloc(strlen(ptr) + 1,
			    KM_SLEEP);
			(void) strcpy(*comstarprop, ptr);
		}
	}
out:
	if (nv != NULL)
		nvlist_free(nv);
	kmem_free((void *)(uintptr_t)zc->zc_nvlist_dst, size);
	kmem_free(zc, sizeof (zfs_cmd_t));
	(void) ldi_close(zfs_lh, FREAD|FWRITE, kcred);

	return (rc);
}

int
sbd_zvolset(char *zvol_name, char *comstarprop)
{
	ldi_handle_t	zfs_lh;
	nvlist_t	*nv;
	char		*packed = NULL;
	size_t		len;
	zfs_cmd_t	*zc;
	int unused;
	int rc;

	if ((rc = ldi_open_by_name("/dev/zfs", FREAD | FWRITE, kcred,
	    &zfs_lh, sbd_zfs_ident)) != 0) {
		cmn_err(CE_WARN, "ldi_open %d", rc);
		return (ENXIO);
	}
	(void) nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_string(nv, "stmf_sbd_lu", comstarprop);
	if ((rc = nvlist_pack(nv, &packed, &len, NV_ENCODE_NATIVE, KM_SLEEP))) {
		goto out;
	}

	zc = kmem_zalloc(sizeof (zfs_cmd_t), KM_SLEEP);
	(void) strlcpy(zc->zc_name, zvol_name, sizeof (zc->zc_name));
	zc->zc_nvlist_src = (uint64_t)(intptr_t)packed;
	zc->zc_nvlist_src_size = len;
	rc = ldi_ioctl(zfs_lh, ZFS_IOC_SET_PROP, (intptr_t)zc,
	    FKIOCTL, kcred, &unused);
	if (rc != 0) {
		cmn_err(CE_NOTE, "ioctl failed %d", rc);
	}
	kmem_free(zc, sizeof (zfs_cmd_t));
out:
	nvlist_free(nv);
	(void) ldi_close(zfs_lh, FREAD|FWRITE, kcred);
	return (rc);
}
