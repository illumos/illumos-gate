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

/*
 * hci1394_ioctl.c
 *   Test ioctl's to support test/debug of the 1394 HW. hci1394_ioctl_enum_t is
 *   passed in cmd and a pointer to the appropriate structure (i.e.
 *   hci1394_ioctl_wrreg_t) is passed in arg.
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/mkdev.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/h1394.h>
#include <sys/1394/adapters/hci1394.h>
#include <sys/1394/adapters/hci1394_extern.h>
#include <sys/1394/adapters/hci1394_ioctl.h>


/* HCI1394_IOCTL_READ_SELFID for 32-bit apps in 64-bit kernel */
typedef struct hci1394_ioctl_readselfid32_s {
	uint32_t buf;
	uint_t count;
} hci1394_ioctl_readselfid32_t;


static int hci1394_ioctl_wrreg(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_rdreg(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_wrvreg(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_rdvreg(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_selfid_cnt(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_busgen_cnt(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_wrphy(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_rdphy(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_hbainfo(hci1394_state_t *soft_state, void *arg,
    int mode);
static int hci1394_ioctl_read_selfid(hci1394_state_t *soft_state, void *arg,
    int mode);
#ifdef	_MULTI_DATAMODEL
static int hci1394_ioctl_read_selfid32(hci1394_state_t *soft_state,
    hci1394_ioctl_readselfid32_t *read_selfid, int mode);
#endif


/* ARGSUSED */
int
hci1394_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	hci1394_state_t *soft_state;
	int instance;
	int status;

	instance = getminor(dev);
	if (instance == -1) {
		return (EBADF);
	}

	soft_state = ddi_get_soft_state(hci1394_statep, instance);
	if (soft_state == NULL) {
		return (EBADF);
	}

	status = 0;

	switch (cmd) {
	case HCI1394_IOCTL_WRITE_REG:
		status = hci1394_ioctl_wrreg(soft_state, (void *)arg, mode);
		break;
	case HCI1394_IOCTL_READ_REG:
		status = hci1394_ioctl_rdreg(soft_state, (void *)arg, mode);
		break;
	case HCI1394_IOCTL_READ_VREG:
		status = hci1394_ioctl_rdvreg(soft_state, (void *)arg, mode);
		break;
	case HCI1394_IOCTL_WRITE_VREG:
		status = hci1394_ioctl_wrvreg(soft_state, (void *)arg, mode);
		break;
	case HCI1394_IOCTL_RESET_BUS:
		status = hci1394_ohci_bus_reset(soft_state->ohci);
		break;
	case HCI1394_IOCTL_SELFID_CNT:
		status = hci1394_ioctl_selfid_cnt(soft_state, (void *)arg,
		    mode);
		break;
	case HCI1394_IOCTL_BUSGEN_CNT:
		status = hci1394_ioctl_busgen_cnt(soft_state, (void *)arg,
		    mode);
		break;
	case HCI1394_IOCTL_READ_SELFID:
		status = hci1394_ioctl_read_selfid(soft_state, (void *)arg,
		    mode);
		break;
	case HCI1394_IOCTL_READ_PHY:
		status = hci1394_ioctl_rdphy(soft_state, (void *)arg, mode);
		break;
	case HCI1394_IOCTL_WRITE_PHY:
		status = hci1394_ioctl_wrphy(soft_state, (void *)arg, mode);
		break;
	case HCI1394_IOCTL_HBA_INFO:
		status = hci1394_ioctl_hbainfo(soft_state, (void *)arg, mode);
		break;
	default:
		/*
		 * if we don't know what the ioctl is, forward it on to the
		 * services layer.  The services layer will handle the devctl
		 * ioctl's along with any services layer private ioctls that
		 * it has defined.
		 */
		status = h1394_ioctl(soft_state->drvinfo.di_sl_private, cmd,
		    arg, mode, credp, rvalp);
		break;
	}

	return (status);
}


static int
hci1394_ioctl_wrreg(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_wrreg_t wrreg;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	status = ddi_copyin(arg, &wrreg, sizeof (hci1394_ioctl_wrreg_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	hci1394_ohci_reg_write(soft_state->ohci, wrreg.addr, wrreg.data);

	return (0);
}


static int
hci1394_ioctl_rdreg(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_rdreg_t rdreg;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	status = ddi_copyin(arg, &rdreg, sizeof (hci1394_ioctl_rdreg_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	hci1394_ohci_reg_read(soft_state->ohci, rdreg.addr, &rdreg.data);

	status = ddi_copyout(&rdreg, arg, sizeof (hci1394_ioctl_rdreg_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	return (0);
}


static int
hci1394_ioctl_wrvreg(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_wrvreg_t wrvreg;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	status = ddi_copyin(arg, &wrvreg, sizeof (hci1394_ioctl_wrvreg_t),
	    mode);
	if (status != 0) {
		return (EFAULT);
	}

	status = hci1394_vendor_reg_write(soft_state->vendor,
	    wrvreg.regset, wrvreg.addr, wrvreg.data);
	if (status != DDI_SUCCESS) {
		return (EINVAL);
	}

	return (0);
}


static int
hci1394_ioctl_rdvreg(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_rdvreg_t rdvreg;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	status = ddi_copyin(arg, &rdvreg, sizeof (hci1394_ioctl_rdvreg_t),
	    mode);
	if (status != 0) {
		return (EFAULT);
	}

	status = hci1394_vendor_reg_read(soft_state->vendor,
	    rdvreg.regset, rdvreg.addr, &rdvreg.data);
	if (status != DDI_SUCCESS) {
		return (EINVAL);
	}

	status = ddi_copyout(&rdvreg, arg, sizeof (hci1394_ioctl_rdvreg_t),
	    mode);
	if (status != 0) {
		return (EFAULT);
	}

	return (0);
}


static int
hci1394_ioctl_selfid_cnt(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_selfid_cnt_t selfid_cnt;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	selfid_cnt.count = soft_state->drvinfo.di_stats.st_selfid_count;

	status = ddi_copyout(&selfid_cnt, arg,
	    sizeof (hci1394_ioctl_selfid_cnt_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	return (0);
}


static int
hci1394_ioctl_busgen_cnt(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_busgen_cnt_t busgen_cnt;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	busgen_cnt.count = hci1394_ohci_current_busgen(soft_state->ohci);

	status = ddi_copyout(&busgen_cnt, arg,
	    sizeof (hci1394_ioctl_busgen_cnt_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	return (0);
}


static int
hci1394_ioctl_wrphy(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_wrphy_t wrphy;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	status = ddi_copyin(arg, &wrphy, sizeof (hci1394_ioctl_wrphy_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	status = hci1394_ohci_phy_write(soft_state->ohci, wrphy.addr,
	    wrphy.data);
	if (status != DDI_SUCCESS) {
		return (EINVAL);
	}

	return (0);
}


static int
hci1394_ioctl_rdphy(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_rdphy_t rdphy;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	status = ddi_copyin(arg, &rdphy, sizeof (hci1394_ioctl_rdphy_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	status = hci1394_ohci_phy_read(soft_state->ohci, rdphy.addr,
	    &rdphy.data);
	if (status != DDI_SUCCESS) {
		return (EINVAL);
	}

	status = ddi_copyout(&rdphy, arg, sizeof (hci1394_ioctl_rdphy_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	return (0);
}


static int
hci1394_ioctl_hbainfo(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_hbainfo_t hbainfo;
	int status;


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

	hbainfo.pci_vendor_id = soft_state->vendor_info.vendor_id;
	hbainfo.pci_device_id = soft_state->vendor_info.device_id;
	hbainfo.pci_revision_id = soft_state->vendor_info.revision_id;
	hbainfo.ohci_version = soft_state->vendor_info.ohci_version;
	hbainfo.ohci_vendor_id = soft_state->vendor_info.ohci_vendor_id;
	hbainfo.ohci_vregset_cnt = soft_state->vendor_info.vendor_reg_count;

	status = ddi_copyout(&hbainfo, arg, sizeof (hci1394_ioctl_hbainfo_t),
	    mode);
	if (status != 0) {
		return (EFAULT);
	}

	return (0);
}


static int
hci1394_ioctl_read_selfid(hci1394_state_t *soft_state, void *arg, int mode)
{
	hci1394_ioctl_read_selfid_t read_selfid;
	int status;
	uint_t offset;
	uint32_t data;
#ifdef	_MULTI_DATAMODEL
	hci1394_ioctl_readselfid32_t read_selfid32;
#endif


	ASSERT(soft_state != NULL);
	ASSERT(arg != NULL);

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {

		/* 32-bit app in 64-bit kernel */
	case DDI_MODEL_ILP32:
		/* copy in the 32-bit version of the args */
		status = ddi_copyin(arg, &read_selfid32,
		    sizeof (hci1394_ioctl_readselfid32_t), mode);
		if (status != 0) {
			return (EFAULT);
		}

		/*
		 * Use a special function to process the 32-bit user address
		 * pointer embedded in the structure we pass in arg.
		 */
		status = hci1394_ioctl_read_selfid32(soft_state,
		    &read_selfid32, mode);
		return (status);
	default:
		break;
	}
#endif

	/*
	 * if we got here, we either are a 64-bit app in a 64-bit kernel or a
	 * 32-bit app in a 32-bit kernel
	 */

	/* copy in the args. We don't need to do any special conversions */
	status = ddi_copyin(arg, &read_selfid,
	    sizeof (hci1394_ioctl_read_selfid_t), mode);
	if (status != 0) {
		return (EFAULT);
	}

	/*
	 * make sure we are not trying to copy more data than the selfid buffer
	 * can hold.  count is in quadlets and max_selfid_size is in bytes.
	 */
	if ((read_selfid.count * 4) > OHCI_MAX_SELFID_SIZE) {
		return (EINVAL);
	}

	/*
	 * copy the selfid buffer one word at a time into the user buffer. The
	 * combination between having to do ddi_get32's (for endian reasons)
	 * and a ddi_copyout() make it easier to do it one word at a time.
	 */
	for (offset = 0; offset < read_selfid.count; offset++) {
		/* read word from selfid buffer */
		hci1394_ohci_selfid_read(soft_state->ohci, offset, &data);

		/* copy the selfid word into the user buffer */
		status = ddi_copyout(&data, &read_selfid.buf[offset], 4, mode);
		if (status != 0) {
			return (EFAULT);
		}
	}

	return (0);
}


#ifdef	_MULTI_DATAMODEL
static int
hci1394_ioctl_read_selfid32(hci1394_state_t *soft_state,
    hci1394_ioctl_readselfid32_t *read_selfid, int mode)
{
	int status;
	uint_t offset;
	uint32_t data;


	ASSERT(soft_state != NULL);
	ASSERT(read_selfid != NULL);

	/*
	 * make sure we are not trying to copy more data than the selfid buffer
	 * can hold.  count is in quadlets and max_selfid_size is in bytes.
	 */
	if ((read_selfid->count * 4) > OHCI_MAX_SELFID_SIZE) {
		return (EINVAL);
	}

	/*
	 * copy the selfid buffer one word at a time into the user buffer. The
	 * combination between having to do ddi_get32's (for endian reasons) and
	 * a ddi_copyout() make it easier to do it one word at a time.
	 */
	for (offset = 0; offset < read_selfid->count; offset++) {
		/* read word from selfid buffer */
		hci1394_ohci_selfid_read(soft_state->ohci, offset, &data);
		/* copy the selfid word into the user buffer */
		status = ddi_copyout(&data,
		    (void *)(uintptr_t)(read_selfid->buf + (offset * 4)),
		    4, mode);
		if (status != 0) {
			return (EFAULT);
		}
	}

	return (0);
}
#endif
