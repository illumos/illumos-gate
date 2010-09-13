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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Source file containing the implementation of fma support in driver
 *
 */

#include <oce_impl.h>

static int oce_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err,
    const void *impl_data);

/*
 * function to initialize driver fma support
 *
 * dev - software handle to the device
 *
 * return none
 */

void
oce_fm_init(struct oce_dev *dev)
{
	ddi_iblock_cookie_t ibc;

	if (dev->fm_caps == DDI_FM_NOT_CAPABLE) {
	return;
	}

	oce_set_dma_fma_flags(dev->fm_caps);
	oce_set_reg_fma_flags(dev->fm_caps);
	oce_set_tx_map_dma_fma_flags(dev->fm_caps);

	(void) ddi_fm_init(dev->dip, &dev->fm_caps, &ibc);
	if (DDI_FM_EREPORT_CAP(dev->fm_caps) ||
	    DDI_FM_ERRCB_CAP(dev->fm_caps)) {
		pci_ereport_setup(dev->dip);
	}
	if (DDI_FM_ERRCB_CAP(dev->fm_caps)) {
		ddi_fm_handler_register(dev->dip, oce_fm_error_cb,
		    (void *)dev);
	}
} /* oce_fm_init */

/*
 * function to deinitialize driver fma support
 *
 * dev - software handle to the device
 *
 * return none
 */
void
oce_fm_fini(struct oce_dev *dev)
{
	if (dev->fm_caps == DDI_FM_NOT_CAPABLE) {
		return;
	}
	if (DDI_FM_ERRCB_CAP(dev->fm_caps)) {
		ddi_fm_handler_unregister(dev->dip);
	}
	if (DDI_FM_EREPORT_CAP(dev->fm_caps) ||
	    DDI_FM_ERRCB_CAP(dev->fm_caps)) {
		pci_ereport_teardown(dev->dip);
	}
	(void) ddi_fm_fini(dev->dip);
} /* oce_fm_fini */

/*
 * function to check the access handle
 *
 * dev - software handle to the device
 * acc_handle - access handle
 *
 * return fm error status
 */
int
oce_fm_check_acc_handle(struct oce_dev *dev, ddi_acc_handle_t acc_handle)
{
	ddi_fm_error_t fme;

	if (!DDI_FM_ACC_ERR_CAP(dev->fm_caps)) {
		return (DDI_FM_OK);
	}
	(void) ddi_fm_acc_err_get(acc_handle, &fme, DDI_FME_VERSION);
	(void) ddi_fm_acc_err_clear(acc_handle, DDI_FME_VERSION);

	return (fme.fme_status);
} /* oce_fm_chk_ach */

/*
 * function to check error updates associated with a dma handle
 *
 * dev - software handle to the device
 * dma_handle - dma handle to the resources on which to check for errors
 *
 * return error code. DDI_FM_OK => no error
 */
int
oce_fm_check_dma_handle(struct oce_dev *dev, ddi_dma_handle_t dma_handle)
{
	ddi_fm_error_t fme;

	if (!DDI_FM_DMA_ERR_CAP(dev->fm_caps)) {
		return (DDI_FM_OK);
	}

	(void) ddi_fm_dma_err_get(dma_handle, &fme, DDI_FME_VERSION);
	return (fme.fme_status);
} /* oce_fm_chk_dh */

/*
 * function to report an error to the FMA framework
 *
 * dev - software handle to the device
 * detail - OS defined string that provides the kind of error to report
 */
void
oce_fm_ereport(struct oce_dev *dev, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	if (!DDI_FM_EREPORT_CAP(dev->fm_caps) || detail == NULL) {
		return;
	}
	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(dev->fm_caps)) {
		ddi_fm_ereport_post(dev->dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
} /* oce_fm_ereport */

/*
 * callback function registered with the FMA infrastructure. This callback is
 * called by the nexux driver if there is an error with the device
 *
 * dip - dev_info_t structure for this device
 * err - error information provided by the nexus
 * impl_data - callback data
 *
 * return error code. DDI_FM_OK => no error
 */
static int
oce_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	_NOTE(ARGUNUSED(impl_data));
	/* Driver must  handle the  dma/access error  */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}
