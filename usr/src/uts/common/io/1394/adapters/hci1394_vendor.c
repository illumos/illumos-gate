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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * hci1394_vendor.c
 *   These routines provide initialization, cleanup, and general access to
 *   vendor specific features on the OpenHCI adapter.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>

#include <sys/1394/adapters/hci1394.h>


/*
 * Macro which makes sure vendor register offset is not greater that 0x7FC and
 * that it is quadlet aligned.
 */
#define	VENDOR_ALIGN_ADDR(addr)	(addr & 0x7FC)


/*
 * Patchable variable to have the driver set the GUID on a Sun RIO chip.
 * Normally this will be done by the firmware, but for PPX cards and OBP images
 * without 1394 support, we need to fo this. This is only used for RIO.  Other
 * vendor cards are not effected.
 *   0 - don't set GUID (default)
 *   non zero - set GUID on RIO
 */
int hci1394_set_rio_guid = 0;


static int hci1394_rio_init(hci1394_vendor_t *vendor);
static void hci1394_rio_guid_init(hci1394_vendor_t *vendor);
static int hci1394_rio_resume(hci1394_vendor_t *vendor);


/*
 * hci1394_vendor_init()
 *    Initialize the Vendor Specific portions of the OpenHCI chipset. This is
 *    not required according to the OpenHCI spec, but may be needed for
 *    performance optimizations, etc. dip, accattrp, and vendor_info are inputs.
 *    num_reg_sets and vendor_handle are outputs. num_reg_sets is the number of
 *    registers sets (or mappings) that are present for this device. This will
 *    usually be 0 or 1. vendor_handle is an opaque handle used in rest of
 *    vendor routines.
 */
int
hci1394_vendor_init(hci1394_drvinfo_t *drvinfo,  hci1394_ohci_handle_t ohci,
    hci1394_vendor_info_t *vendor_info, hci1394_vendor_handle_t *vendor_handle)
{
	int status;
	hci1394_vendor_t *vendor;


	ASSERT(drvinfo != NULL);
	ASSERT(vendor_info != NULL);
	ASSERT(vendor_handle != NULL);

	/*
	 * alloc the space to keep track of the vendor registers.
	 */
	vendor = kmem_alloc(sizeof (hci1394_vendor_t), KM_SLEEP);
	vendor->ve_info = *vendor_info;
	vendor->ve_drvinfo = drvinfo;
	vendor->ve_ohci = ohci;

	/* setup the vendor_handle return parameter */
	*vendor_handle = vendor;

	/* call vendor specific initialization routine */
	switch (vendor_info->vendor_id) {

	/* Sun Microsystems 1394 Device */
	case VENDOR_VID_SUN_MICROSYSTEMS:
		switch (vendor_info->device_id) {

		/* RIO base chip. Call the RIO specific init routine */
		case VENDOR_DID_RIO_1394:
			status = hci1394_rio_init(vendor);
			if (status != DDI_SUCCESS) {
				kmem_free(vendor,
				    sizeof (hci1394_vendor_t));
				*vendor_handle = NULL;
				return (DDI_FAILURE);
			}
			break;
			/* VENDOR_DID_RIO_1394 */

		/* unrecognized device - don't map any registers */
		default:
			vendor->ve_reg_count = 0;
			break;
		}
		break;
		/* VENDOR_VID_SUN_MICROSYSTEMS */

	/* unrecognized vendor - don't map any registers */
	default:
		vendor->ve_reg_count = 0;
		break;
	}

	vendor_info->vendor_reg_count = vendor->ve_reg_count;

	return (DDI_SUCCESS);
}


/*
 * hci1394_vendor_fini()
 *    Cleanup after Vendor Specific init.  This includes freeing any allocated
 *    kernel memory and freeing any mapped registers.
 *
 * NOTE: This routine must be called after a successful vendor_init even if the
 *	 num_reg_sets = 0 during init.  This routine is normally called during
 *	 the detach process.
 *
 * NOTE: A pointer to the handle is used for the parameter. fini() will set
 *	 your handle to NULL before returning.
 */
void
hci1394_vendor_fini(hci1394_vendor_handle_t *vendor_handle)
{
	uint_t index;


	ASSERT(vendor_handle != NULL);

	for (index = 0; index < (*vendor_handle)->ve_reg_count; index++) {
		ddi_regs_map_free(&(*vendor_handle)->
		    ve_reg_array[index]->vr_reg_handle);
	}
	kmem_free(*vendor_handle, sizeof (hci1394_vendor_t));

	/* Set the vendor_handle to NULL to help catch bugs */
	*vendor_handle = NULL;
}


/*
 * hci1394_vendor_resume()
 *    Vendor Specific init for a power resume (DDI_RESUME). This includes
 *    re-setting up any vendor specific registers.
 */
int
hci1394_vendor_resume(hci1394_vendor_handle_t vendor_handle)
{
	int status;
	hci1394_vendor_info_t *vendor_info;


	ASSERT(vendor_handle != NULL);

	vendor_info = &vendor_handle->ve_info;

	/* call vendor specific initialization routine */
	switch (vendor_info->vendor_id) {

	/* Sun Microsystems 1394 Device */
	case VENDOR_VID_SUN_MICROSYSTEMS:
		switch (vendor_info->device_id) {

		/* RIO base chip. Call the RIO specific resume routine */
		case VENDOR_DID_RIO_1394:
			status = hci1394_rio_resume(vendor_handle);
			if (status != DDI_SUCCESS) {
				return (DDI_FAILURE);
			}
			break;
			/* VENDOR_DID_RIO_1394 */

		/* unrecognized device - don't map any registers */
		default:
			break;
		}
		break;
		/* VENDOR_VID_SUN_MICROSYSTEMS */

	/* unrecognized vendor - don't map any registers */
	default:
		break;
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_vendor_reg_write()
 *    Write vendor specific register. reg_set is the register set to write. The
 *    first register set would be reg_set = 0, the second reg_set = 1, etc.
 *    offset is the offset into the vendor specific register space. An offset of
 *    0 would be the first vendor register for that register set. data is the
 *    data to write to the vendor register.
 */
int
hci1394_vendor_reg_write(hci1394_vendor_handle_t vendor_handle,
    uint_t reg_set, uint_t offset, uint32_t data)
{
	hci1394_vendor_reg_t *venreg;
	uint32_t *regaddr;


	ASSERT(vendor_handle != NULL);

	if (vendor_handle->ve_reg_count < (reg_set + 1)) {
		return (DDI_FAILURE);
	}

	venreg = vendor_handle->ve_reg_array[reg_set];
	regaddr = (uint32_t *)((uintptr_t)venreg->vr_reg_addr +
	    (uintptr_t)VENDOR_ALIGN_ADDR(offset));

	ddi_put32(venreg->vr_reg_handle, regaddr, data);

	return (DDI_SUCCESS);
}


/*
 * hci1394_vendor_reg_read()
 *    Read vendor specific register. reg_set is the register set to write. The
 *    first register set would be reg_set = 0, the second reg_set = 1, etc.
 *    offset is the offset into the vendor specific register space. An offset
 *    of 0 would be the first vendor register for that register set. data is
 *    the address to put the data read.
 */
int
hci1394_vendor_reg_read(hci1394_vendor_handle_t vendor_handle, uint_t reg_set,
    uint_t offset, uint32_t *data)
{
	hci1394_vendor_reg_t *venreg;
	uint32_t *regaddr;


	ASSERT(vendor_handle != NULL);
	ASSERT(data != NULL);

	if (vendor_handle->ve_reg_count < (reg_set + 1)) {
		return (DDI_FAILURE);
	}

	venreg = vendor_handle->ve_reg_array[reg_set];
	regaddr = (uint32_t *)((uintptr_t)venreg->vr_reg_addr +
	    (uintptr_t)VENDOR_ALIGN_ADDR(offset));

	*data = ddi_get32(venreg->vr_reg_handle, regaddr);

	return (DDI_SUCCESS);
}

/*
 * hci1394_rio_init()
 *    Initialize SUNW RIO vendor specific registers.
 */
static int
hci1394_rio_init(hci1394_vendor_t *vendor)
{
	int status;


	ASSERT(vendor != NULL);

	vendor->ve_reg_count = 1;
	vendor->ve_reg_array[0] = kmem_alloc(sizeof (hci1394_vendor_reg_t),
	    KM_SLEEP);

	status = ddi_regs_map_setup(vendor->ve_drvinfo->di_dip, RIOREG_REG_BASE,
	    &vendor->ve_reg_array[0]->vr_reg_addr, RIOREG_OFFSET, RIOREG_LENGTH,
	    &vendor->ve_drvinfo->di_reg_attr,
	    &vendor->ve_reg_array[0]->vr_reg_handle);
	if (status != DDI_SUCCESS) {
		vendor->ve_reg_count = 0;
		kmem_free(vendor->ve_reg_array[0],
		    sizeof (hci1394_vendor_reg_t));
		return (DDI_FAILURE);
	}

	/* Setup RIO Host Control Register */
	status = hci1394_vendor_reg_write(vendor, 0, RIOREG_HOST_CONTROL,
	    RIOREG_HOST_CONTROL_SETTING);
	if (status != DDI_SUCCESS) {
		ddi_regs_map_free(&vendor->ve_reg_array[0]->vr_reg_handle);
		vendor->ve_reg_count = 0;
		kmem_free(vendor->ve_reg_array[0],
		    sizeof (hci1394_vendor_reg_t));
		vendor->ve_reg_array[0] = NULL;
		return (DDI_FAILURE);
	}

	/* Setup GUID on RIO without firmware support */
	hci1394_rio_guid_init(vendor);

	return (DDI_SUCCESS);
}


/*
 * hci1394_rio_resume()
 *    Re-initialize RIO.  This routine should be called during a resume.
 */
static int
hci1394_rio_resume(hci1394_vendor_t *vendor)
{
	int status;


	ASSERT(vendor != NULL);

	/* Setup RIO Host Control Register */
	status = hci1394_vendor_reg_write(vendor, 0, RIOREG_HOST_CONTROL,
	    RIOREG_HOST_CONTROL_SETTING);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Setup GUID on RIO PPX */
	hci1394_rio_guid_init(vendor);

	return (DDI_SUCCESS);
}


/*
 * hci1394_rio_guid_init()
 *    Setup a GUID in the RIO. Normally firmware would do this for the
 *    motherboard version. This will not hurt a RIO  on the motherboard since we
 *    won't be able to write the GUID. We should not get to this code anyway in
 *    production systems.  Use a timestamp for the lower 40 bits of the GUID.
 */
static void
hci1394_rio_guid_init(hci1394_vendor_t *vendor)
{
	hrtime_t guid_timestamp;

	ASSERT(vendor != NULL);

	if (hci1394_set_rio_guid != 0) {
		guid_timestamp = gethrtime();

		/* mask out the vendor field of the GUID */
		guid_timestamp = guid_timestamp & RIOREG_GUID_MASK;

		/* fill in Sun Microsystems */
		guid_timestamp = guid_timestamp | RIOREG_GUID_SUN_MICROSYSTEMS;

		/* write this to the GUID registers */
		ddi_put32(vendor->ve_ohci->ohci_reg_handle,
		    &vendor->ve_ohci->ohci_regs->guid_hi,
		    (uint32_t)(guid_timestamp >> 32));
		ddi_put32(vendor->ve_ohci->ohci_reg_handle,
		    &vendor->ve_ohci->ohci_regs->guid_lo,
		    (uint32_t)(guid_timestamp & 0xFFFFFFFF));
	}
}
