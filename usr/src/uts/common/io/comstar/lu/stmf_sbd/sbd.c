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

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/nvpair.h>

#include <stmf.h>
#include <lpif.h>
#include <stmf_ioctl.h>
#include <stmf_sbd.h>
#include <sbd_impl.h>
#include <stmf_sbd_ioctl.h>

static int sbd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int sbd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int sbd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
	void **result);
static int sbd_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int sbd_close(dev_t dev, int flag, int otype, cred_t *credp);
static int stmf_sbd_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval);
void sbd_lp_cb(stmf_lu_provider_t *lp, int cmd, void *arg, uint32_t flags);
uint8_t sbd_calc_sum(uint8_t *buf, int size);
void sbd_swap_meta_start(sbd_meta_start_t *sm);
void sbd_swap_section_hdr(sm_section_hdr_t *h, uint8_t data_order);
void sbd_swap_sli_fields(sbd_lu_info_t *sli, uint8_t data_order);
int sbd_migrate_meta_from_v0_to_v1(sbd_store_t *sst);

extern struct mod_ops mod_driverops;

static stmf_lu_provider_t *sbd_lp;
static dev_info_t *sbd_dip;
static kmutex_t sbd_lock;
sbd_lu_t	*sbd_lu_list = NULL;
static int sbd_lu_count = 0;
static char sbd_name[] = "sbd";
static uint64_t	sbd_meta_offset	= 4096; /* offset to skip label */

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

	if (stmf_register_lu_provider(sbd_lp) != STMF_SUCCESS) {
		(void) mod_remove(&modlinkage);
		stmf_free(sbd_lp);
		return (DDI_FAILURE);
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

		/* ok start deregistering them */
		while (sbd_lu_list) {
			sbd_store_t *sst = sbd_lu_list->sl_sst;
			if (sst->sst_deregister_lu(sst) != STMF_SUCCESS)
				return (EBUSY);
		}
	}
	ASSERT(sbd_lu_count == 0);
	if (stmf_deregister_lu_provider(sbd_lp) != STMF_SUCCESS)
		return (EBUSY);
	ret = mod_remove(&modlinkage);
	if (ret != 0) {
		(void) stmf_register_lu_provider(sbd_lp);
		return (ret);
	}
	stmf_free(sbd_lp);
	mutex_destroy(&sbd_lock);
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
		*result = (void *)(uintptr_t)ddi_get_instance(dip);
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

/*
 * The ioctl code will be re written once the lun mapping and masking
 * has been implemented and ioctl definitions have been cleanned up.
 */
void *
sbd_ioctl_read_struct(intptr_t data, int mode)
{
	void *ptr;
	uint32_t s;

	if (ddi_copyin((void *)data, &s, 4, mode))
		return (NULL);
	ptr = kmem_alloc(s, KM_SLEEP);
	if (ddi_copyin((void *)data, ptr, s, mode))
		return (NULL);
	return (ptr);
}

int
sbd_ioctl_write_struct(intptr_t data, int mode, void *ptr)
{
	int *s = (int *)ptr;
	int ret = 0;

	if (ddi_copyout(ptr, (void *)data, *s, mode)) {
		ret = EFAULT;
	}

	kmem_free(ptr, *s);
	return (ret);
}

/* ARGSUSED */
static int
stmf_sbd_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval)
{
	register_lu_cmd_t	*rlc;
	deregister_lu_cmd_t	*drlc;
	sbd_lu_list_t		*sll;
	sbd_lu_attr_t		*sla;
	sbd_lu_t		*slul;
	void			*p;
	int			ret = 0;
	int			ret1;
	int			cnt;
	int			max_times, idx;
	stmf_state_change_info_t ssi;

	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	ssi.st_rflags = STMF_RFLAG_USER_REQUEST;
	ssi.st_additional_info = NULL;
	if ((cmd != SBD_REGISTER_LU) && (cmd != SBD_GET_LU_ATTR) &&
	    (cmd != SBD_GET_LU_LIST) && (cmd != SBD_DEREGISTER_LU) &&
	    (cmd != SBD_MODIFY_LU)) {
		return (EINVAL);
	}
	if ((p = sbd_ioctl_read_struct(data, mode)) == NULL)
		return (EFAULT);

	switch (cmd) {
	case SBD_REGISTER_LU:
		rlc = (register_lu_cmd_t *)p;
		((char *)p)[rlc->total_struct_size - 1] = 0;
		if (rlc->flags & RLC_LU_TYPE_MEMDISK) {
			if ((rlc->op_ret = memdisk_register_lu(rlc)) !=
			    STMF_SUCCESS) {
				ret = EIO;
			}
		} else if (rlc->flags & RLC_LU_TYPE_FILEDISK) {
			if ((rlc->op_ret = filedisk_register_lu(rlc)) !=
			    STMF_SUCCESS) {
				ret = EIO;
			}
		} else {
			ret = EINVAL;
			break;
		}
		break;
	case SBD_MODIFY_LU: {
		modify_lu_cmd_t *mlc = (modify_lu_cmd_t *)p;
		sbd_lu_t *slu;
		sbd_store_t *sst = NULL;
		if ((mlc->flags & RLC_LU_TYPE_FILEDISK) == 0) {
			ret = EINVAL;
			break;
		}
		if (mlc->name[0] != '\0') {
			mutex_enter(&sbd_lock);
			for (slu = sbd_lu_list; slu != NULL;
			    slu = slu->sl_next) {
				if (strcmp(slu->sl_sst->sst_alias,
				    mlc->name) == 0)
					break;
			}
			mutex_exit(&sbd_lock);
			if (slu == NULL) {
				/* not registered */
				sst = NULL;
			} else {
				sst = slu->sl_sst;
			}
		} else {
			mutex_enter(&sbd_lock);
			for (slu = sbd_lu_list; slu != NULL;
			    slu = slu->sl_next) {
				if (bcmp(slu->sl_lu->lu_id->ident,
				    mlc->guid, 16) == 0)
					break;
			}
			mutex_exit(&sbd_lock);
			if (slu == NULL) {
				/* not registered, this is not allowed */
				ret = ENODEV;
				break;
			}
			sst = slu->sl_sst;
		}

		mlc->op_ret = filedisk_modify_lu(sst, mlc);
		if (mlc->op_ret != STMF_SUCCESS) {
			ret = EIO;
		}
		}
		break;

	case SBD_DEREGISTER_LU:
		drlc = (deregister_lu_cmd_t *)p;

		mutex_enter(&sbd_lock);
		for (slul = sbd_lu_list; slul != NULL; slul = slul->sl_next) {
			ret1 = bcmp(drlc->guid, slul->sl_lu->lu_id->ident, 16);
			if (ret1 == 0) {
				break;
			}
		}

		if (slul == NULL) {
			mutex_exit(&sbd_lock);

			stmf_trace(0, "sbd_ioctl: can't find specified LU");
			ret = ENODEV;
			break;
		}

		if ((slul->sl_state == STMF_STATE_OFFLINE) &&
		    !slul->sl_state_not_acked) {
			mutex_exit(&sbd_lock);

			goto do_lu_dereg;
		}

		if (slul->sl_state != STMF_STATE_ONLINE) {
			mutex_exit(&sbd_lock);

			ret = EBUSY;
			break;
		}
		mutex_exit(&sbd_lock);

		ssi.st_additional_info = "DEREGLU offline LU now";
		(void) stmf_ctl(STMF_CMD_LU_OFFLINE, slul->sl_lu, &ssi);
		max_times = 50;

		mutex_enter(&sbd_lock);
		for (idx = 0; idx < max_times; idx++) {
			if ((slul->sl_state == STMF_STATE_OFFLINE) &&
			    !slul->sl_state_not_acked) {
				break;
			}
			mutex_exit(&sbd_lock);

			delay(drv_usectohz(100000));

			mutex_enter(&sbd_lock);
		}
		mutex_exit(&sbd_lock);

		if (idx == max_times) {
			stmf_trace(0, "sbd_ioctl: LU-%p can't go off", slul);
			ret = ETIMEDOUT;
		} else {
do_lu_dereg:
			if (slul->sl_sst->sst_deregister_lu(slul->sl_sst) !=
			    STMF_SUCCESS) {
				stmf_trace(0, "sbd_ioctl: sst_degregister_lu "
				    "sst-%p failed", slul->sl_sst);
				ret = ENOTSUP;
			}
		}
		break;

	case SBD_GET_LU_LIST:
		sll = (sbd_lu_list_t *)p;
		cnt = sll->total_struct_size - sizeof (sbd_lu_list_t);
		if (cnt < 0) {
			ret = EINVAL;
			break;
		}
		cnt = (cnt >> 3) + 1;
		if (sll->count_in > cnt) {
			ret = EFAULT;
			break;
		}
		mutex_enter(&sbd_lock);
		sll->count_out = 0;
		for (slul = sbd_lu_list; slul != NULL; slul = slul->sl_next) {
			if (sll->count_out < sll->count_in) {
				sll->handles[sll->count_out] =
				    (uint64_t)(unsigned long)slul;
			}
			sll->count_out++;
		}
		mutex_exit(&sbd_lock);
		break;
	case SBD_GET_LU_ATTR:
		sla = (sbd_lu_attr_t *)p;
		if (sla->total_struct_size <
		    (sizeof (sbd_lu_attr_t) + sla->max_name_length - 7)) {
			ret = EFAULT;
			break;
		}
		mutex_enter(&sbd_lock);
		for (slul = sbd_lu_list; slul != NULL; slul = slul->sl_next) {
			if (sla->lu_handle == (uint64_t)(unsigned long)slul)
				break;
		}
		if (slul != NULL) {
			filedisk_fillout_attr(slul->sl_sst, sla);
			memdisk_fillout_attr(slul->sl_sst, sla);
			sla->total_size = slul->sl_sli->sli_total_store_size;
			sla->data_size = slul->sl_sli->sli_lu_data_size;
			bcopy(slul->sl_lu->lu_id->ident, sla->guid, 16);
		} else {
			ret = EINVAL;
		}
		mutex_exit(&sbd_lock);
		break;

	default:
		return (ENOTTY);
	}

	ret1 = sbd_ioctl_write_struct(data, mode, p);
	if (!ret)
		ret = ret1;
	return (ret);
}

/* ARGSUSED */
void
sbd_lp_cb(stmf_lu_provider_t *lp, int cmd, void *arg, uint32_t flags)
{
	nvpair_t *np;
	register_lu_cmd_t *rlc = NULL;
	char *s;
	int rlc_size = 0;
	int sn;

	if ((cmd != STMF_PROVIDER_DATA_UPDATED) || (arg == NULL)) {
		return;
	}

	if ((flags & (STMF_PCB_STMF_ONLINING | STMF_PCB_PREG_COMPLETE)) == 0) {
		return;
	}

	np = NULL;
	while ((np = nvlist_next_nvpair((nvlist_t *)arg, np)) != NULL) {
		if (nvpair_type(np) != DATA_TYPE_STRING) {
			continue;
		}
		if (nvpair_value_string(np, &s) != 0) {
			continue;
		}
		sn = sizeof (register_lu_cmd_t) - 8 + strlen(s) + 1;
		if (sn > rlc_size) {
			if (rlc_size) {
				kmem_free(rlc, rlc_size);
			}
			rlc_size = sn + 32; /* Make it a little bigger */
			rlc = (register_lu_cmd_t *)kmem_zalloc(rlc_size,
								KM_SLEEP);
		}
		bzero(rlc, rlc_size);
		rlc->total_struct_size = rlc_size;
		rlc->flags = RLC_LU_TYPE_FILEDISK | RLC_REGISTER_LU;
		(void) strcpy(rlc->name, s);
		(void) filedisk_register_lu(rlc);
	}

	if (rlc) {
		kmem_free(rlc, rlc_size);
	}
}

/* ARGSUSED */
sbd_store_t *
sbd_sst_alloc(uint32_t additional_size, uint32_t flags)
{
	uint32_t total_as;
	sbd_store_t *sst;
	stmf_lu_t *lu;
	sbd_lu_t *slu;

	total_as = GET_STRUCT_SIZE(sbd_store_t) + GET_STRUCT_SIZE(sbd_lu_t) +
			((additional_size + 7) & ~7);

	lu = (stmf_lu_t *)stmf_alloc(STMF_STRUCT_STMF_LU, total_as, 0);
	if (lu == NULL)
		return (NULL);
	sst = (sbd_store_t *)lu->lu_provider_private;
	sst->sst_sbd_private = GET_BYTE_OFFSET(sst,
				GET_STRUCT_SIZE(sbd_store_t));
	sst->sst_store_private = GET_BYTE_OFFSET(sst->sst_sbd_private,
					GET_STRUCT_SIZE(sbd_lu_t));
	slu = (sbd_lu_t *)sst->sst_sbd_private;
	slu->sl_sst = sst;
	slu->sl_lu = lu;
	slu->sl_total_allocation_size = total_as;
	mutex_init(&slu->sl_it_list_lock, NULL, MUTEX_DRIVER, NULL);

	return (sst);
}

void
sbd_sst_free(sbd_store_t *sst)
{
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;

	mutex_destroy(&slu->sl_it_list_lock);
	stmf_free(slu->sl_lu);
}

#define	DATA_ALIGNMENT		0xfffffffffffff000
#define	DATA_BLOCK_SIZE		4 * 1024

stmf_status_t
sbd_aligned_meta_write(struct sbd_store *sst, uint64_t offset,
    uint64_t size, uint8_t *buf)
{
	uint64_t starting_off = offset & DATA_ALIGNMENT;
	uint64_t off_from_starting = offset & (~DATA_ALIGNMENT);
	uint64_t ending_off =
	    (offset + size + DATA_BLOCK_SIZE) & DATA_ALIGNMENT;
	uint64_t op_size = ending_off - starting_off;
	uint8_t *op_buf = (uint8_t *)kmem_zalloc(op_size, KM_SLEEP);
	stmf_status_t ret;

	/* we should read first to avoid overwrite other data */
	if (sst->sst_meta_read) {
		ret = sst->sst_meta_read(sst, starting_off,
		    op_size, (uint8_t *)op_buf);
	} else {
		ret = sst->sst_data_read(sst, starting_off,
		    op_size, (uint8_t *)op_buf);
	}
	if (ret != STMF_SUCCESS)
		goto aligned_write_ret;

	bcopy(buf, op_buf + off_from_starting, size);

	if (sst->sst_meta_write) {
		ret = sst->sst_meta_write(sst, starting_off,
		    op_size, (uint8_t *)op_buf);
	} else {
		ret = sst->sst_data_write(sst, starting_off,
		    op_size, (uint8_t *)op_buf);
	}

aligned_write_ret:
	if (op_buf)
		kmem_free(op_buf, op_size);
	return (ret);
}

stmf_status_t
sbd_aligned_meta_read(struct sbd_store *sst, uint64_t offset,
    uint64_t size, uint8_t *buf)
{
	uint64_t starting_off = offset & DATA_ALIGNMENT;
	uint64_t off_from_starting = offset & (~DATA_ALIGNMENT);
	uint64_t ending_off =
	    (offset + size + DATA_BLOCK_SIZE) & DATA_ALIGNMENT;
	uint64_t op_size = ending_off - starting_off;
	uint8_t *op_buf = (uint8_t *)kmem_zalloc(op_size, KM_SLEEP);
	stmf_status_t ret;

	if (sst->sst_meta_read) {
		ret = sst->sst_meta_read(sst, starting_off,
		    op_size, (uint8_t *)op_buf);
	} else {
		ret = sst->sst_data_read(sst, starting_off,
		    op_size, (uint8_t *)op_buf);
	}
	if (ret != STMF_SUCCESS)
		goto aligned_read_ret;
	bcopy(op_buf + off_from_starting, buf, size);

aligned_read_ret:
	if (op_buf)
		kmem_free(op_buf, op_size);
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

void
sbd_swap_meta_start(sbd_meta_start_t *sm)
{
	sm->sm_magic		= BSWAP_64(sm->sm_magic);
	sm->sm_meta_size	= BSWAP_64(sm->sm_meta_size);
	sm->sm_meta_size_used	= BSWAP_64(sm->sm_meta_size_used);
	sm->sm_ver_major	= BSWAP_16(sm->sm_ver_major);
	sm->sm_ver_minor	= BSWAP_16(sm->sm_ver_minor);
	sm->sm_ver_subminor	= BSWAP_16(sm->sm_ver_subminor);
}

void
sbd_swap_section_hdr(sm_section_hdr_t *h, uint8_t data_order)
{
	h->sms_offset		= BSWAP_64(h->sms_offset);
	h->sms_size		= BSWAP_32(h->sms_size);
	h->sms_id		= BSWAP_16(h->sms_id);
	h->sms_data_order	= data_order;
}

void
sbd_swap_sli_fields(sbd_lu_info_t *sli, uint8_t data_order)
{
	sli->sli_total_store_size = BSWAP_64(sli->sli_total_store_size);
	sli->sli_total_meta_size = BSWAP_64(sli->sli_total_meta_size);
	sli->sli_lu_data_offset = BSWAP_64(sli->sli_lu_data_offset);
	sli->sli_lu_data_size = BSWAP_64(sli->sli_lu_data_size);
	sli->sli_flags = BSWAP_32(sli->sli_flags);
	sli->sli_blocksize = BSWAP_16(sli->sli_blocksize);
	sli->sli_data_order = data_order;
}

/*
 * will not modify sms.
 */
uint64_t
sbd_find_section_offset(sbd_store_t *sst, sm_section_hdr_t *sms)
{
	stmf_status_t ret;
	sbd_lu_t *slu = (sbd_lu_t *)sst->sst_sbd_private;
	uint64_t ssize;
	uint64_t meta_end;
	sm_section_hdr_t smsh;

	if (slu->sl_sm.sm_magic != SBD_MAGIC) {
		cmn_err(CE_PANIC, "sbd_find section called without reading the"
				" header first.");
	}

	ssize = slu->sl_meta_offset + sizeof (sbd_meta_start_t);
	meta_end = slu->sl_sm.sm_meta_size_used;
	while (ssize < meta_end) {
		ret = sbd_aligned_meta_read(sst, ssize,
		    sizeof (sm_section_hdr_t), (uint8_t *)&smsh);
		if (ret != STMF_SUCCESS)
			return (0);
		if (smsh.sms_data_order != sms->sms_data_order) {
			sbd_swap_section_hdr(&smsh, sms->sms_data_order);
		}
		if (smsh.sms_id == sms->sms_id)
			return (smsh.sms_offset);
		ssize += smsh.sms_size;
	}

	return (0);
}

stmf_status_t
sbd_read_section(sbd_store_t *sst, sm_section_hdr_t *sms)
{
	stmf_status_t			ret;
	uint32_t			sz;
	uint8_t				osum, nsum;

	if (sms->sms_offset == 0) {
		sms->sms_offset = sbd_find_section_offset(sst, sms);
		if (sms->sms_offset == 0)
			return (STMF_FAILURE);
	}
	sz = sms->sms_size;

	ret = sbd_aligned_meta_read(sst, sms->sms_offset,
	    sms->sms_size, (uint8_t *)sms);
	if (ret != STMF_SUCCESS)
		return (ret);

	osum = sms->sms_chksum;
	sms->sms_chksum = 0;
	nsum = sbd_calc_sum((uint8_t *)sms, sz);
	sms->sms_chksum = osum;
	if (osum != nsum) {
		return (STMF_FAILURE);
	}
	if (sms->sms_data_order != SMS_DATA_ORDER) {
		/* Adjust byte order of the header */
		sbd_swap_section_hdr(sms, SMS_DATA_ORDER);
	}

	return (STMF_SUCCESS);
}

stmf_status_t
sbd_write_section(sbd_store_t *sst, sm_section_hdr_t *sms)
{
	stmf_status_t		ret;
	sbd_lu_t		*slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_lu_info_t		*sli = slu->sl_sli;

	if (sms->sms_offset == 0) {
		sms->sms_offset = sbd_find_section_offset(sst, sms);
		if (sms->sms_offset == 0) {
			if (sli->sli_total_meta_size <
			    (slu->sl_sm.sm_meta_size_used + sms->sms_size)) {
				return (STMF_FAILURE);
			}
			sms->sms_offset = slu->sl_sm.sm_meta_size_used;
			slu->sl_sm.sm_meta_size_used += sms->sms_size;
			slu->sl_sm.sm_chksum = 0;
			slu->sl_sm.sm_chksum = sbd_calc_sum((uint8_t *)
			    &slu->sl_sm, sizeof (sbd_meta_start_t));
			ret = sbd_aligned_meta_write(sst, slu->sl_meta_offset,
			    sizeof (sbd_meta_start_t), (uint8_t *)&slu->sl_sm);
			if (ret != STMF_SUCCESS) {
				slu->sl_sm.sm_meta_size_used -= sms->sms_size;
				slu->sl_sm.sm_chksum = 0;
				slu->sl_sm.sm_chksum = sbd_calc_sum((uint8_t *)
				    &slu->sl_sm, sizeof (sbd_meta_start_t));
				return (STMF_FAILURE);
			}
		}
	}

	sms->sms_chksum = 0;
	sms->sms_chksum = sbd_calc_sum((uint8_t *)sms, sms->sms_size);
	ret = sbd_aligned_meta_write(sst, sms->sms_offset,
	    sms->sms_size, (uint8_t *)sms);

	return (ret);
}

stmf_status_t
sbd_create_meta(sbd_store_t *sst, sst_init_data_t *sst_idata)
{
	sbd_lu_t	*slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_lu_info_t	*sli;
	sm_section_hdr_t *h;
	stmf_status_t	ret;
	uint64_t	meta_size;
	uint64_t	lu_data_offset;
	uint64_t	lu_data_size;
	uint16_t	b;

	/* Blocksize should be a non-zero power of 2 */
	b = sst_idata->sst_blocksize;
	if ((b < 2) || ((b & (b - 1)) != 0)) {
		return (STMF_INVALID_ARG);
	}

	/* Store size should be nonzero multiple of blocksize */
	if ((sst_idata->sst_store_size == 0) ||
	    ((sst_idata->sst_store_size % b) != 0)) {
		return (STMF_INVALID_ARG);
	}

	/*
	 * Total metadata size is size of metadata headers + size of
	 * sbd_lu_info_t + any space needed by the store implementation
	 * itself. We should also keep enough space for future expansions.
	 * Also metadat size should be rounded off to blocksize.
	 */
	/*
	 * meta_size = sizeof (sbd_meta_start_t ) + sizeof (sbd_lu_info_t) +
	 *		sst_idata->sst_store_meta_data_size;
	 */
	/*
	 * for now keep a static 64K for metasize. This should be enough to
	 * store metadata as well as any persistent reservations and keys.
	 */
	meta_size = 64 * 1024;
	meta_size = (meta_size + (uint64_t)(b - 1));
	meta_size /= (uint64_t)b;
	meta_size *= (uint64_t)b;

	/*
	 * If metadata is not separate from user data then store size
	 * should be large enough to hold metadata. Also effective data
	 * size should be adjusted.
	 */
	if (sst->sst_meta_write == NULL) {
		if (meta_size >= sst_idata->sst_store_size)
			return (STMF_INVALID_ARG);
		lu_data_offset = meta_size;
		lu_data_size = sst_idata->sst_store_size - meta_size;
	}

	/* Initialize the header and write it */
	bzero(&slu->sl_sm, sizeof (sbd_meta_start_t));
	slu->sl_sm.sm_magic = SBD_MAGIC;
	slu->sl_sm.sm_meta_size = meta_size;
	/*
	 * Note that we already included the size for sli even though
	 * it is going to be written in next step.
	 */
	slu->sl_sm.sm_meta_size_used = sbd_meta_offset +
	    sizeof (sbd_meta_start_t) + sizeof (sbd_lu_info_t);
	slu->sl_sm.sm_ver_major = 1;
	slu->sl_sm.sm_chksum = sbd_calc_sum((uint8_t *)&slu->sl_sm,
	    sizeof (sbd_meta_start_t));

	ret = sbd_aligned_meta_write(sst, sbd_meta_offset,
	    sizeof (sbd_meta_start_t), (uint8_t *)&slu->sl_sm);
	if (ret != STMF_SUCCESS)
		return (ret);

	slu->sl_meta_offset = sbd_meta_offset;
	slu->sl_sli = (sbd_lu_info_t *)kmem_zalloc(sizeof (sbd_lu_info_t),
							KM_SLEEP);
	sli = slu->sl_sli;
	h = &sli->sli_sms_header;
	h->sms_offset = sbd_meta_offset + sizeof (sbd_meta_start_t);
	h->sms_size = sizeof (sbd_lu_info_t);
	h->sms_id = SMS_ID_LU_INFO;
	h->sms_data_order = SMS_DATA_ORDER;
	sli->sli_total_store_size = sst_idata->sst_store_size;
	sli->sli_total_meta_size = meta_size;
	sli->sli_lu_data_offset = lu_data_offset;
	sli->sli_lu_data_size = lu_data_size;
	sli->sli_blocksize = sst_idata->sst_blocksize;
	sli->sli_data_order = SMS_DATA_ORDER;
	sli->sli_lu_devid[3] = 16;
	ret = stmf_scsilib_uniq_lu_id(COMPANY_ID_SUN, (scsi_devid_desc_t *)
					&sli->sli_lu_devid[0]);

	if (ret == STMF_SUCCESS) {
		bcopy(&sli->sli_lu_devid[4], sst_idata->sst_guid, 16);
		ret = sbd_write_section(sst, (sm_section_hdr_t *)slu->sl_sli);
		if (ret != STMF_SUCCESS)
			cmn_err(CE_NOTE, "write section failed");
	} else {
		cmn_err(CE_NOTE, "scsilib failed %llx",
		    (unsigned long long)ret);
	}

	kmem_free(slu->sl_sli, sizeof (sbd_lu_info_t));
	slu->sl_sli = NULL;

	return (ret);
}

/*
 * Used to modify the total store size in meta for a LUN, We only
 * check sst_idata->sst_store_size here.
 * For LUN not registered, we will read meta data first
 */
stmf_status_t
sbd_modify_meta(sbd_store_t *sst, sst_init_data_t *sst_idata)
{
	sbd_lu_t	*slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_lu_info_t	*sli;
	stmf_status_t	ret;
	/* uint64_t	meta_size; */
	uint64_t	lu_data_size;
	sbd_it_data_t	*sid = NULL;
	uint64_t	meta_offset;


	if (sst->sst_meta_write == NULL) {
		if (slu->sl_sm.sm_meta_size >= sst_idata->sst_store_size)
			return (STMF_INVALID_ARG);
		lu_data_size = sst_idata->sst_store_size -
		    slu->sl_sm.sm_meta_size;
	}

	/*
	 * use a copy here in order not to change anything if
	 * sbd_write_section() failed
	 */
	sli = (sbd_lu_info_t *)kmem_zalloc(sizeof (sbd_lu_info_t), KM_SLEEP);
	if (slu->sl_sli)
		bcopy(slu->sl_sli, sli, sizeof (sbd_lu_info_t));
	else { /* not registered, have to read meta data */
		meta_offset = sbd_meta_offset;
read_meta_header:
		ret = sbd_aligned_meta_read(sst, meta_offset,
		    sizeof (sbd_meta_start_t), (uint8_t *)&slu->sl_sm);
		if (ret != STMF_SUCCESS) {
			goto exit_modify_lu;
		}
		if (slu->sl_sm.sm_magic != SBD_MAGIC) {
			if (BSWAP_64(slu->sl_sm.sm_magic) != SBD_MAGIC) {
				if (!sbd_migrate_meta_from_v0_to_v1(sst)) {
					ret = STMF_INVALID_ARG;
					goto exit_modify_lu;
				}
				goto read_meta_header;
			}
			sbd_swap_meta_start(&slu->sl_sm);
		}
		slu->sl_meta_offset = meta_offset;

		sli->sli_sms_header.sms_size = sizeof (sbd_lu_info_t);
		sli->sli_sms_header.sms_id = SMS_ID_LU_INFO;
		sli->sli_sms_header.sms_data_order = SMS_DATA_ORDER;

		ret = sbd_read_section(sst, (sm_section_hdr_t *)sli);

		if (ret != STMF_SUCCESS)
			goto exit_modify_lu;
		if (sli->sli_data_order != SMS_DATA_ORDER) {
			sbd_swap_sli_fields(sli, SMS_DATA_ORDER);
		}
	}

	sli->sli_total_store_size = sst_idata->sst_store_size;
	sli->sli_lu_data_size = lu_data_size;
	bcopy(&sli->sli_lu_devid[4], sst_idata->sst_guid, 16);

	ret = sbd_write_section(sst, (sm_section_hdr_t *)sli);
	if (ret != STMF_SUCCESS)
		cmn_err(CE_NOTE, "write section failed");
	else if (slu->sl_sli) {
		/* for registered LU */
		slu->sl_sli->sli_total_store_size = sli->sli_total_store_size;
		slu->sl_sli->sli_lu_data_size = sli->sli_lu_data_size;
		mutex_enter(&slu->sl_it_list_lock);
		for (sid = slu->sl_it_list; sid; sid = sid->sbd_it_next) {
			sid->sbd_it_ua_conditions |= SBD_UA_CAPACITY_CHANGED;
		}
		mutex_exit(&slu->sl_it_list_lock);
	}
exit_modify_lu:
	kmem_free(sli, sizeof (sbd_lu_info_t));

	return (ret);
}

/*
 * Added sst_idata here because with dynamic LUN, we can only get the
 * LUN size from meta data if we are registering LUN
 */
stmf_status_t
sbd_register_sst(sbd_store_t *sst, sst_init_data_t *sst_idata)
{
	sbd_lu_t	*slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_lu_info_t	*sli;
	stmf_lu_t	*lu;
	stmf_status_t	ret;
	uint16_t	b;
	uint64_t	meta_offset = sbd_meta_offset;

	if (slu->sl_sli) {
		cmn_err(CE_PANIC, "sbd_register_sst called with active data "
		    " from an existing store");
	}
read_meta_header:
	ret = sbd_aligned_meta_read(sst, meta_offset,
	    sizeof (sbd_meta_start_t), (uint8_t *)&slu->sl_sm);
	if (ret != STMF_SUCCESS) {
		return (ret);
	}
	if (slu->sl_sm.sm_magic != SBD_MAGIC) {
		if (BSWAP_64(slu->sl_sm.sm_magic) != SBD_MAGIC) {
			if (!sbd_migrate_meta_from_v0_to_v1(sst))
				return (STMF_INVALID_ARG);
			goto read_meta_header;
		}
		sbd_swap_meta_start(&slu->sl_sm);
		ret = sbd_aligned_meta_write(sst, meta_offset,
		    sizeof (sbd_meta_start_t), (uint8_t *)&slu->sl_sm);
		if (ret != STMF_SUCCESS)
			return (ret);
	}
	slu->sl_meta_offset = meta_offset;

	sli = (sbd_lu_info_t *)kmem_zalloc(sizeof (sbd_lu_info_t),
								KM_SLEEP);
	slu->sl_sli = sli;
	sli->sli_sms_header.sms_size = sizeof (sbd_lu_info_t);
	sli->sli_sms_header.sms_id = SMS_ID_LU_INFO;
	sli->sli_sms_header.sms_data_order = SMS_DATA_ORDER;

	ret = sbd_read_section(sst, (sm_section_hdr_t *)sli);

	if (ret != STMF_SUCCESS) {
		goto exit_store_online;
	}

	if (sli->sli_data_order != SMS_DATA_ORDER) {
		sbd_swap_sli_fields(sli, SMS_DATA_ORDER);
	}
	bcopy(&sli->sli_lu_devid[4], sst_idata->sst_guid, 16);
	b = sli->sli_blocksize;

	/* Calculate shift factor to convert LBA to a linear offset */
	for (slu->sl_shift_count = 0; b != 1; slu->sl_shift_count++)
		b >>= 1;

	/* Initialize LU and register it */
	lu = slu->sl_lu;
	lu->lu_id = (scsi_devid_desc_t *)&sli->sli_lu_devid[0];
	lu->lu_alias = sst->sst_alias;
	lu->lu_lp = sbd_lp;
	lu->lu_task_alloc = sbd_task_alloc;
	lu->lu_new_task = sbd_new_task;
	lu->lu_dbuf_xfer_done = sbd_dbuf_xfer_done;
	lu->lu_send_status_done = sbd_send_status_done;
	lu->lu_task_free = sbd_task_free;
	lu->lu_abort = sbd_abort;
	lu->lu_ctl = sbd_ctl;
	lu->lu_info = sbd_info;
	slu->sl_state = STMF_STATE_OFFLINE;

	if ((ret = stmf_register_lu(lu)) != STMF_SUCCESS) {
		stmf_trace(0, "Failed to register with framework, ret=%llx",
			ret);
		goto exit_store_online;
	}

	mutex_enter(&sbd_lock);
	slu->sl_next = sbd_lu_list;
	sbd_lu_list = slu;
	sbd_lu_count++;
	mutex_exit(&sbd_lock);

	if (sst_idata) {
		sst_idata->sst_store_size = sli->sli_total_store_size;
		sst_idata->sst_blocksize = sli->sli_blocksize;
	}

	return (STMF_SUCCESS);
exit_store_online:;
	kmem_free(slu->sl_sli, sizeof (sbd_lu_info_t));
	slu->sl_sli = NULL;
	return (ret);
}

stmf_status_t
sbd_deregister_sst(sbd_store_t *sst)
{
	sbd_lu_t	*slu = (sbd_lu_t *)sst->sst_sbd_private;
	sbd_lu_t	**ppslu;

	if (slu->sl_state != STMF_STATE_OFFLINE)
		return (STMF_BUSY);

	if (stmf_deregister_lu(slu->sl_lu) != STMF_SUCCESS)
		return (STMF_BUSY);

	mutex_enter(&sbd_lock);
	for (ppslu = &sbd_lu_list; (*ppslu) != NULL;
					ppslu = &((*ppslu)->sl_next)) {
		if ((*ppslu) == slu) {
			*ppslu = (*ppslu)->sl_next;
			sbd_lu_count--;
			break;
		}
	}
	mutex_exit(&sbd_lock);
	if (slu->sl_sli) {
		kmem_free(slu->sl_sli, sizeof (sbd_lu_info_t));
		slu->sl_sli = NULL;
	}
	return (STMF_SUCCESS);
}


/*
 * Version 0 format of metadata was never integrated into solaris. It
 * was the format used by early opensolaris release until feb. 2008.
 * Subsequent opensolaris releases used version 1 and thats what
 * was integrated into solaris as well. At some point V0 stuff should be
 * completely removed.
 */
int
sbd_is_meta_v0(sbd_store_t *sst, uint64_t *meta_size, uint64_t *meta_offset)
{
	sbd_v0_meta_start_t m;

	*meta_offset = 4096;
v0_check:;
	if (sbd_aligned_meta_read(sst, *meta_offset, 16, (uint8_t *)&m) !=
	    STMF_SUCCESS) {
		return (0);
	}

	if (m.sm_magic != SBD_V0_MAGIC) {
		m.sm_magic = BSWAP_64(m.sm_magic);
		if (m.sm_magic != SBD_V0_MAGIC) {
			if (*meta_offset == 4096) {
				*meta_offset = 0;
				goto v0_check;
			}
			return (0);
		}
		m.sm_meta_size = BSWAP_64(m.sm_meta_size);
	}

	*meta_size = m.sm_meta_size;

	return (1);
}

int
sbd_migrate_meta_from_v0_to_v1(sbd_store_t *sst)
{
	uint64_t v0_meta_size;
	uint64_t v0_meta_offset;
	sbd_v0_lu_info_t *v0sli;
	sbd_lu_info_t *sli;
	sbd_meta_start_t *sm;
	sm_section_hdr_t *h;
	int ret = 0;

	if (!sbd_is_meta_v0(sst, &v0_meta_size, &v0_meta_offset))
		return (0);

	v0sli = kmem_zalloc(sizeof (*v0sli), KM_SLEEP);
	sm = kmem_zalloc(sizeof (*sm) + sizeof (*sli), KM_SLEEP);
	sli = (sbd_lu_info_t *)(((uint8_t *)sm) + sizeof (*sm));
	if (sbd_aligned_meta_read(sst, v0_meta_offset + 16, sizeof (*v0sli),
	    (uint8_t *)v0sli) != STMF_SUCCESS) {
		goto mv0v1_exit;
	}
	sm->sm_magic = SBD_MAGIC;
	sm->sm_meta_size = v0_meta_size;
	sm->sm_meta_size_used = sbd_meta_offset + sizeof (*sm) + sizeof (*sli);
	sm->sm_ver_major = 1;
	sm->sm_chksum = sbd_calc_sum((uint8_t *)sm, sizeof (sbd_meta_start_t));

	h = &sli->sli_sms_header;
	h->sms_offset = sbd_meta_offset + sizeof (*sm);
	h->sms_size = sizeof (*sli);
	h->sms_id = SMS_ID_LU_INFO;
	h->sms_data_order = SMS_DATA_ORDER;
	if (v0sli->sli_sms_header.sms_payload_data_order == SMS_DATA_ORDER) {
		sli->sli_total_store_size = v0sli->sli_total_store_size;
		sli->sli_total_meta_size = v0sli->sli_total_meta_size;
		sli->sli_lu_data_offset = v0sli->sli_lu_data_offset;
		sli->sli_lu_data_size = v0sli->sli_lu_data_size;
	} else {
		sli->sli_total_store_size =
		    BSWAP_64(v0sli->sli_total_store_size);
		sli->sli_total_meta_size =
		    BSWAP_64(v0sli->sli_total_meta_size);
		sli->sli_lu_data_offset =
		    BSWAP_64(v0sli->sli_lu_data_offset);
		sli->sli_lu_data_size =
		    BSWAP_64(v0sli->sli_lu_data_size);
	}
	/* sli_flags were not used in v0 */
	sli->sli_blocksize = 512;
	sli->sli_data_order = SMS_DATA_ORDER;
	bcopy(v0sli->sli_lu_devid, sli->sli_lu_devid, 20);
	h->sms_chksum = sbd_calc_sum((uint8_t *)h, h->sms_size);

	if (sbd_aligned_meta_write(sst, sbd_meta_offset,
	    sizeof (*sm) + sizeof (*sli), (uint8_t *)sm) != STMF_SUCCESS) {
		goto mv0v1_exit;
	}

	ret = 1;
mv0v1_exit:
	kmem_free(v0sli, sizeof (*v0sli));
	kmem_free(sm, sizeof (*sm) + sizeof (*sli));

	return (ret);
}
