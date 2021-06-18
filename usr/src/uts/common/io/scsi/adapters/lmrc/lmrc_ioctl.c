/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Racktop Systems, Inc.
 */

/*
 * This file implements the ioctl interface as employed by closed-source
 * the closed-source RAID management utility storcli. As there is no source
 * and no documentation, this closely follows the ioctl implementation of
 * the existing mr_sas(4D) driver for older MegaRAID HBAs.
 *
 * This driver supports three kinds of ioctls:
 * - SCSA HBA ioctls, which are handled by scsi_hba_ioctl()
 * - AEN ioctls, which currently have no known consumer as it seems storcli
 *   doesn't use them. They are left unimplemented for now, logging a warning
 *   if used.
 * - Firmware ioctls as used by storcli, which can be divided into two kinds
 *   - MFI passthru ioctls which are used to send MFI frames containing DCMDs,
 *     LD SCSI I/O, or PD SCSI I/O requests from userspace directly to the HBA.
 *     See the comment at the beginning of lmrc.c for a description of the MFI.
 *   - Driver ioctls, which look like MFI DCMD frames but are actually handled
 *     by the driver. They are used by storcli to query the driver version and
 *     get PCI information of the HBA, including PCI config space header.
 */
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/policy.h>

#include <sys/ddifm.h>
#include <sys/fm/io/ddi.h>

#include "lmrc.h"
#include "lmrc_reg.h"
#include "lmrc_raid.h"
#include "lmrc_ioctl.h"

static int lmrc_drv_ioctl_drv_version(lmrc_t *, void *, size_t, int);
static int lmrc_drv_ioctl_pci_info(lmrc_t *, void *, size_t, int);
static int lmrc_drv_ioctl(lmrc_t *, lmrc_ioctl_t *, int);

static void lmrc_mfi_ioctl_scsi_io(lmrc_t *, lmrc_ioctl_t *, lmrc_mfi_cmd_t *,
    uintptr_t *, uintptr_t *);
static void lmrc_mfi_ioctl_dcmd(lmrc_t *, lmrc_ioctl_t *, lmrc_mfi_cmd_t *,
    uintptr_t *);
static int lmrc_mfi_ioctl(lmrc_t *, lmrc_ioctl_t *, int);
static int lmrc_mfi_aen_ioctl(lmrc_t *, lmrc_aen_t *);
static int lmrc_fw_ioctl(lmrc_t *, intptr_t, int);
static int lmrc_aen_ioctl(lmrc_t *, intptr_t, int);

/*
 * lmrc_drv_ioctl_drv_version
 *
 * Return the driver version information back to userspace.
 */
static int
lmrc_drv_ioctl_drv_version(lmrc_t *lmrc, void *ubuf, size_t len, int mode)
{
	static lmrc_drv_ver_t dv = {
		.dv_signature = "$ILLUMOS$",
		.dv_os_name = "illumos",
		.dv_drv_name = "lmrc",
		.dv_drv_ver = "0.1",
		.dv_drv_rel_date = "Feb 09, 2023"
	};

	int ret;

	ret = ddi_copyout(&dv, ubuf, len, mode);
	if (ret != DDI_SUCCESS)
		return (EFAULT);

	return (0);
}

/*
 * lmrc_drv_ioctl_drv_version
 *
 * Return PCI bus interface information back to userspace.
 */
static int
lmrc_drv_ioctl_pci_info(lmrc_t *lmrc, void *ubuf, size_t len, int mode)
{
	int *props = NULL;
	ddi_acc_handle_t pcih;
	lmrc_pci_info_t pi;
	uint_t nprop;
	int ret;
	int i;

	ret = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, lmrc->l_dip, 0, "reg",
	    &props, &nprop);
	if (ret != DDI_SUCCESS)
		return (EINVAL);

	bzero(&pi, sizeof (pi));
	pi.pi_bus = (props[0] >> 16) & 0xff;
	pi.pi_dev = (props[0] >> 11) & 0x1f;
	pi.pi_func = (props[0] >> 8) & 0x7;

	ddi_prop_free(props);

	if (pci_config_setup(lmrc->l_dip, &pcih) != DDI_SUCCESS)
		return (EINVAL);

	for (i = 0; i != ARRAY_SIZE(pi.pi_header); i++)
		pi.pi_header[i] = pci_config_get8(pcih, i);

	if (lmrc_check_acc_handle(lmrc->l_reghandle) != DDI_SUCCESS) {
		pci_config_teardown(&pcih);
		lmrc_fm_ereport(lmrc, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(lmrc->l_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	pci_config_teardown(&pcih);

	ret = ddi_copyout(&pi, ubuf, len, mode);
	if (ret != DDI_SUCCESS)
		return (EFAULT);

	return (0);
}

/*
 * lmrc_drv_ioctl
 *
 * Process a driver information ioctl request. These come in the form of a
 * MFI DCMD but are processed by the driver and not sent to the hardware.
 */
static int
lmrc_drv_ioctl(lmrc_t *lmrc, lmrc_ioctl_t *ioc, int mode)
{
	lmrc_mfi_header_t *hdr = &ioc->ioc_frame.mf_hdr;
	lmrc_mfi_dcmd_payload_t *dcmd = &ioc->ioc_frame.mf_dcmd;
	size_t xferlen = dcmd->md_sgl.ms64_length;
	void *ubuf = (void *)dcmd->md_sgl.ms64_phys_addr;
	int ret = EINVAL;

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		xferlen = dcmd->md_sgl.ms32_length;
		ubuf = (void *)(uintptr_t)dcmd->md_sgl.ms32_phys_addr;
	} else {
#endif
		xferlen = dcmd->md_sgl.ms64_length;
		ubuf = (void *)(uintptr_t)dcmd->md_sgl.ms64_phys_addr;
#ifdef _MULTI_DATAMODEL
	}
#endif

	switch (dcmd->md_opcode) {
	case LMRC_DRIVER_IOCTL_DRIVER_VERSION:
		ret = lmrc_drv_ioctl_drv_version(lmrc, ubuf, xferlen, mode);
		break;

	case LMRC_DRIVER_IOCTL_PCI_INFORMATION:
		ret = lmrc_drv_ioctl_pci_info(lmrc, ubuf, xferlen, mode);
		break;

	default:
		dev_err(lmrc->l_dip, CE_WARN,
		    "!%s: invalid driver ioctl, cmd = %d",
		    __func__, dcmd->md_opcode);

		ret = EINVAL;
		break;
	}

	if (ret != 0)
		hdr->mh_cmd_status = MFI_STAT_INVALID_CMD;
	else
		hdr->mh_cmd_status = MFI_STAT_OK;

	return (ret);
}

/*
 * lmrc_mfi_ioctl_scsi_io
 *
 * Prepare MFI cmd for SCSI I/O passthru.
 */
static void
lmrc_mfi_ioctl_scsi_io(lmrc_t *lmrc, lmrc_ioctl_t *ioc,
    lmrc_mfi_cmd_t *mfi, uintptr_t *sgloff, uintptr_t *senseoff)
{
	lmrc_mfi_pthru_payload_t *ioc_pthru = &ioc->ioc_frame.mf_pthru;
	lmrc_mfi_pthru_payload_t *mfi_pthru = &mfi->mfi_frame->mf_pthru;

	bcopy(ioc_pthru->mp_cdb, mfi_pthru->mp_cdb, sizeof (mfi_pthru->mp_cdb));

	*sgloff = offsetof(lmrc_mfi_pthru_payload_t, mp_sgl);
	*senseoff = offsetof(lmrc_mfi_pthru_payload_t, mp_sense_buf_phys_addr);
}

/*
 * lmrc_mfi_ioctl_dcmd
 *
 * Prepare MFI cmd for DMCD passthru.
 */
static void
lmrc_mfi_ioctl_dcmd(lmrc_t *lmrc, lmrc_ioctl_t *ioc,
    lmrc_mfi_cmd_t *mfi, uintptr_t *sgloff)
{
	lmrc_mfi_dcmd_payload_t *ioc_dcmd = &ioc->ioc_frame.mf_dcmd;
	lmrc_mfi_dcmd_payload_t *mfi_dcmd = &mfi->mfi_frame->mf_dcmd;

	mfi_dcmd->md_opcode = ioc_dcmd->md_opcode;
	bcopy(ioc_dcmd->md_mbox_8, mfi_dcmd->md_mbox_8,
	    sizeof (mfi_dcmd->md_mbox_8));

	*sgloff = offsetof(lmrc_mfi_dcmd_payload_t, md_sgl);
}

/*
 * lmrc_mfi_ioctl
 *
 * Process a MFI passthru ioctl request. Handle DMA read/write and sense data
 * in a uniform way for all supported MFI commands.
 */
static int
lmrc_mfi_ioctl(lmrc_t *lmrc, lmrc_ioctl_t *ioc, int mode)
{
	uint64_t *mfi_senseaddr = NULL, *ioc_senseaddr = NULL;
	lmrc_dma_t sense;
	size_t xferlen = 0;

	lmrc_mfi_header_t *mfi_hdr, *ioc_hdr;
	lmrc_mfi_sgl_t *mfi_sgl, *ioc_sgl;
	lmrc_mfi_cmd_t *mfi;
	uintptr_t sgloff;
	void *xferbuf;
	int ret;

	ioc_hdr = &ioc->ioc_frame.mf_hdr;
	if (ioc_hdr->mh_sense_len > LMRC_IOC_SENSE_LEN)
		return (EINVAL);

	mfi = lmrc_get_mfi(lmrc);
	mfi_hdr = &mfi->mfi_frame->mf_hdr;

	mfi_hdr->mh_cmd = ioc_hdr->mh_cmd;
	mfi_hdr->mh_sense_len = ioc_hdr->mh_sense_len;
	mfi_hdr->mh_drv_opts = ioc_hdr->mh_drv_opts;
	mfi_hdr->mh_flags = ioc_hdr->mh_flags & ~MFI_FRAME_SGL64;
	mfi_hdr->mh_timeout = ioc_hdr->mh_timeout;
	mfi_hdr->mh_data_xfer_len = ioc_hdr->mh_data_xfer_len;

	switch (mfi_hdr->mh_cmd) {
	case MFI_CMD_LD_SCSI_IO:
	case MFI_CMD_PD_SCSI_IO: {
		uintptr_t senseoff;

		lmrc_mfi_ioctl_scsi_io(lmrc, ioc, mfi, &sgloff, &senseoff);

		mfi_senseaddr = (uint64_t *)&mfi->mfi_frame->mf_raw[senseoff];
		ioc_senseaddr = (uint64_t *)&ioc->ioc_frame.mf_raw[senseoff];

		break;
	}
	case MFI_CMD_DCMD:
		if (mfi_hdr->mh_sense_len != 0) {
			ret = EINVAL;
			goto out;
		}

		lmrc_mfi_ioctl_dcmd(lmrc, ioc, mfi, &sgloff);
		break;

	default:
		dev_err(lmrc->l_dip, CE_WARN,
		    "!%s: invalid MFI ioctl, cmd = %d",
		    __func__, mfi_hdr->mh_cmd);
		ret = EINVAL;
		goto out;

	}

	ASSERT3U(sgloff, !=, 0);
	ioc_sgl = (lmrc_mfi_sgl_t *)&ioc->ioc_frame.mf_raw[sgloff];
	mfi_sgl = (lmrc_mfi_sgl_t *)&mfi->mfi_frame->mf_raw[sgloff];

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		xferlen = ioc_sgl->ms32_length;
		xferbuf = (void *)(uintptr_t)ioc_sgl->ms32_phys_addr;
	} else {
#endif
		xferlen = ioc_sgl->ms64_length;
		xferbuf = (void *)(uintptr_t)ioc_sgl->ms64_phys_addr;
#ifdef _MULTI_DATAMODEL
	}
#endif

	if (xferlen != 0) {
		/* This ioctl uses DMA. */
		ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr,
		    &mfi->mfi_data_dma, xferlen, 1, DDI_DMA_CONSISTENT);
		if (ret != DDI_SUCCESS) {
			ret = EINVAL;
			goto out;
		}

		/* If this ioctl does a DMA write, copy in the user buffer. */
		if ((mfi_hdr->mh_flags & MFI_FRAME_DIR_WRITE) != 0) {
			ret = ddi_copyin(xferbuf, mfi->mfi_data_dma.ld_buf,
			    xferlen, mode);
			if (ret != DDI_SUCCESS) {
				ret = EFAULT;
				goto out;
			}
		}

		mfi_hdr->mh_flags |= MFI_FRAME_SGL64;

		lmrc_dma_set_addr64(&mfi->mfi_data_dma,
		    &mfi_sgl->ms64_phys_addr);
		mfi_sgl->ms64_length = lmrc_dma_get_size(&mfi->mfi_data_dma);
	}

	if (mfi_hdr->mh_sense_len != 0) {
		/* This ioctl needs a sense buffer. */
		ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr, &sense,
		    mfi_hdr->mh_sense_len, 1, DDI_DMA_CONSISTENT);
		if (ret != DDI_SUCCESS) {
			ret = EINVAL;
			goto out;
		}

		lmrc_dma_set_addr64(&sense, mfi_senseaddr);
	}

	mutex_enter(&mfi->mfi_lock);
	lmrc_issue_mfi(lmrc, mfi, lmrc_wakeup_mfi);
	ret = lmrc_wait_mfi(lmrc, mfi, LMRC_INTERNAL_CMD_WAIT_TIME);
	mutex_exit(&mfi->mfi_lock);

	if (ret != DDI_SUCCESS) {
		ret = EAGAIN;
		goto out;
	}

	/* If this ioctl did a DMA read, copy out to the user buffer. */
	if (xferlen != 0 && (mfi_hdr->mh_flags & MFI_FRAME_DIR_READ) != 0) {
		ret = ddi_copyout(mfi->mfi_data_dma.ld_buf, xferbuf, xferlen,
		    mode);
		if (ret != DDI_SUCCESS) {
			ret = EFAULT;
			goto out;
		}
	}

	/* If there is sense data, copy out to the user sense buffer. */
	if (mfi_hdr->mh_sense_len != 0) {
		void *sensebuf = (void *)(uintptr_t)*ioc_senseaddr;

		(void) ddi_dma_sync(sense.ld_hdl, 0, sense.ld_len,
		    DDI_DMA_SYNC_FORKERNEL);
		ret = ddi_copyout(sense.ld_buf, sensebuf, sense.ld_len, mode);
		if (ret != DDI_SUCCESS) {
			ret = EFAULT;
			goto out;
		}
	}

out:
	ioc_hdr->mh_cmd_status = mfi_hdr->mh_cmd_status;
	ioc_hdr->mh_scsi_status = mfi_hdr->mh_scsi_status;

	if (xferlen != 0)
		lmrc_dma_free(&mfi->mfi_data_dma);

	if (mfi_hdr->mh_sense_len != 0)
		lmrc_dma_free(&sense);

	lmrc_put_mfi(mfi);
	if (ret != 0)
		dev_err(lmrc->l_dip, CE_WARN,
		    "%s: failing MFI ioctl, ret = %d",
		    __func__, ret);
	return (ret);
}

/*
 * lmrc_fw_ioctl
 *
 * Process a firmware ioctl request. This includes driver ioctls (which are
 * actually handled by the driver) and MFI passthru ioctls.
 */
static int
lmrc_fw_ioctl(lmrc_t *lmrc, intptr_t arg, int mode)
{
	lmrc_ioctl_t *ioc;
	int ret = EINVAL;

	ioc = kmem_zalloc(sizeof (lmrc_ioctl_t), KM_SLEEP);
	if (ddi_copyin((void *)arg, ioc, sizeof (*ioc), mode) != 0) {
		ret = EFAULT;
		goto out;
	}

	if (ioc->ioc_control_code == LMRC_DRIVER_IOCTL_COMMON) {
		ret = lmrc_drv_ioctl(lmrc, ioc, mode);
	} else {
		sema_p(&lmrc->l_ioctl_sema);
		ret = lmrc_mfi_ioctl(lmrc, ioc, mode);
		sema_v(&lmrc->l_ioctl_sema);
	}

	if (ddi_copyout(ioc, (void *)arg, sizeof (*ioc) - 1, mode) != 0) {
		ret = EFAULT;
		goto out;
	}

out:
	kmem_free(ioc, sizeof (lmrc_ioctl_t));
	return (ret);
}

/*
 * lmrc_mfi_aen_ioctl
 *
 * Supposedly, this will one day send an AEN to the firmware on behalf of
 * user space.
 */
static int
lmrc_mfi_aen_ioctl(lmrc_t *lmrc, lmrc_aen_t *aen)
{
	dev_err(lmrc->l_dip, CE_WARN, "!unimplemented ioctl: MFI AEN");
	return (EINVAL);
}

/*
 * lmrc_aen_ioctl
 *
 * Process a AEN ioctl request.
 */
static int
lmrc_aen_ioctl(lmrc_t *lmrc, intptr_t arg, int mode)
{
	int ret = EINVAL;
	lmrc_aen_t	aen;

	if (ddi_copyin((void *)arg, &aen, sizeof (aen), mode) != 0)
		return (EFAULT);

	ret = lmrc_mfi_aen_ioctl(lmrc, &aen);
	if (ret != 0)
		goto out;

	if (ddi_copyout(&aen, (void *)arg, sizeof (aen), mode) != 0)
		return (EFAULT);
out:
	return (ret);
}

/*
 * DDI ioctl(9e) entry point.
 *
 * Get the ioctl cmd and call the appropriate handlers.
 */
int
lmrc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rval)
{
	lmrc_t *lmrc;
	int inst = MINOR2INST(getminor(dev));
	int ret;

	if (secpolicy_sys_config(credp, B_FALSE) != 0)
		return (EPERM);

	ret = scsi_hba_ioctl(dev, cmd, arg, mode, credp, rval);
	if (ret != ENOTTY)
		return (ret);

	lmrc = ddi_get_soft_state(lmrc_state, inst);
	if (lmrc == NULL)
		return (ENXIO);

	if (lmrc->l_fw_fault)
		return (EIO);

	switch ((uint_t)cmd) {
	case LMRC_IOCTL_FIRMWARE:
		ret = lmrc_fw_ioctl(lmrc, arg, mode);
		break;

	case LMRC_IOCTL_AEN:
		ret = lmrc_aen_ioctl(lmrc, arg, mode);
		break;

	default:
		ret = ENOTTY;
		break;
	}

	return (ret);
}
