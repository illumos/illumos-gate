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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * px_msi.c
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/stat.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci_impl.h>
#include "px_obj.h"

static int px_msi_get_props(px_t *px_p);

/*
 * msi_attach()
 */
int
px_msi_attach(px_t *px_p)
{
	dev_info_t		*dip = px_p->px_dip;
	px_msi_state_t		*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	msinum_t		msi_num;
	int			i, ret;

	DBG(DBG_MSIQ, dip, "px_msi_attach\n");

	mutex_init(&msi_state_p->msi_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Check for all MSI related properties and
	 * save all information.
	 */
	if (px_msi_get_props(px_p) != DDI_SUCCESS) {
		px_msi_detach(px_p);
		return (DDI_FAILURE);
	}

	msi_state_p->msi_p = kmem_zalloc(msi_state_p->msi_cnt *
	    sizeof (px_msi_t), KM_SLEEP);

	for (i = 0, msi_num = msi_state_p->msi_1st_msinum;
		i < msi_state_p->msi_cnt; i++, msi_num++) {
		msi_state_p->msi_p[i].msi_msinum = msi_num;
		msi_state_p->msi_p[i].msi_state = MSI_STATE_FREE;
	}

	if ((ret = px_lib_msi_init(dip)) != DDI_SUCCESS)
		px_msi_detach(px_p);

	return (ret);
}


/*
 * msi_detach()
 */
void
px_msi_detach(px_t *px_p)
{
	dev_info_t	*dip = px_p->px_dip;
	px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;

	DBG(DBG_MSIQ, dip, "px_msi_detach\n");

	if (msi_state_p->msi_addr64 && msi_state_p->msi_mem_flg) {
		ndi_ra_free(dip, msi_state_p->msi_addr64,
		    msi_state_p->msi_addr64_len,
		    NDI_RA_TYPE_MEM, NDI_RA_PASS);
	}

	if (msi_state_p->msi_addr32 && msi_state_p->msi_mem_flg) {
		ndi_ra_free(dip, msi_state_p->msi_addr32,
		    msi_state_p->msi_addr32_len,
		    NDI_RA_TYPE_MEM, NDI_RA_PASS);

		pci_resource_destroy(dip);
	}

	if (msi_state_p->msi_p) {
		kmem_free(msi_state_p->msi_p,
		    msi_state_p->msi_cnt * sizeof (px_msi_t));
	}

	mutex_destroy(&msi_state_p->msi_mutex);
	bzero(&px_p->px_ib_p->ib_msi_state, sizeof (px_msi_state_t));
}


/*
 * msi_alloc()
 */
/* ARGSUSED */
int
px_msi_alloc(px_t *px_p, dev_info_t *rdip, int inum, int msi_count,
    int flag, msinum_t *msi_num_p, int *actual_msi_count_p)
{
	px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	int		i, j, count, first_msi, next_msi_range;
	int		orig_msi_count = msi_count;

	DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_alloc: rdip %s:%d "
	    "inum 0x%x msi_count 0x%x\n", ddi_driver_name(rdip),
	    ddi_get_instance(rdip), inum, msi_count);

	mutex_enter(&msi_state_p->msi_mutex);

	*actual_msi_count_p = 0;

retry_alloc:
	first_msi = next_msi_range = msi_state_p->msi_p[0].msi_msinum;

	/*
	 * For MSI, make sure that MSIs are allocated in the power of 2
	 * contiguous range.
	 */
	for (i = 0, count = 0; (i < msi_state_p->msi_cnt) &&
	    (count < msi_count); i++, count++) {
		if (msi_state_p->msi_p[i].msi_state != MSI_STATE_FREE) {
			/* Jump to next MSI range */
			next_msi_range += msi_count;
			first_msi = next_msi_range;

			/* Reset the counter */
			i = next_msi_range - 1;
			count = -1;
		}
	}

	if ((i >= msi_state_p->msi_cnt) || (count < msi_count)) {
		DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_alloc: failed\n");

		if (msi_count > 1) {
			msi_count >>= 1;

			DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_alloc: "
			    "Retry MSI allocation with new msi_count 0x%x\n",
			    msi_count);

			goto retry_alloc;
		}

		mutex_exit(&msi_state_p->msi_mutex);
		return (DDI_FAILURE);
	}

	*actual_msi_count_p = msi_count;

	if ((flag == DDI_INTR_ALLOC_STRICT) && (msi_count < orig_msi_count))
		return (DDI_FAILURE);

	*msi_num_p = first_msi;

	for ((j = i - msi_count); j < i; j++, inum++) {
		msi_state_p->msi_p[j].msi_state = MSI_STATE_INUSE;
		msi_state_p->msi_p[j].msi_dip = rdip;
		msi_state_p->msi_p[j].msi_inum = inum;
	}

	DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_alloc: rdip %s:%d "
	    "msi_num 0x%x count 0x%x\n", ddi_driver_name(rdip),
	    ddi_get_instance(rdip), *msi_num_p, msi_count);

	mutex_exit(&msi_state_p->msi_mutex);
	return (DDI_SUCCESS);
}


/*
 * msi_free()
 */
int
px_msi_free(px_t *px_p, dev_info_t *rdip, int inum, int msi_count)
{
	px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	int		i, j;

	DBG(DBG_R_MSIX, px_p->px_dip, "px_msi_free: rdip 0x%p "
	    "inum 0x%x msi_count 0x%x\n", rdip, inum, msi_count);

	mutex_enter(&msi_state_p->msi_mutex);

	/*
	 * Look for an entry corresponds to first MSI
	 * used by this device.
	 */
	for (i = 0; i < msi_state_p->msi_cnt; i++) {
		if ((msi_state_p->msi_p[i].msi_inum == inum) &&
		    (msi_state_p->msi_p[i].msi_dip == rdip)) {
			break;
		}
	}

	if (i >= msi_state_p->msi_cnt) {
		mutex_exit(&msi_state_p->msi_mutex);
		return (DDI_FAILURE);
	}

	/* Mark all MSIs used by this device as free */
	for (j = i; j < (i + msi_count); j++) {
		msi_state_p->msi_p[j].msi_dip = NULL;
		msi_state_p->msi_p[j].msi_inum = 0;
		msi_state_p->msi_p[j].msi_msiq_id = 0;
		msi_state_p->msi_p[j].msi_state = MSI_STATE_FREE;
	}

	mutex_exit(&msi_state_p->msi_mutex);
	return (DDI_SUCCESS);
}

/*
 * msi_get_msinum()
 */
int
px_msi_get_msinum(px_t *px_p, dev_info_t *rdip, int inum, msinum_t *msi_num_p)
{
	px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	int		i;

	DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_get_msinum: "
	    "rdip 0x%p inum 0x%x\n", rdip, inum);

	mutex_enter(&msi_state_p->msi_mutex);

	for (i = 0; i < msi_state_p->msi_cnt; i++) {
		if ((msi_state_p->msi_p[i].msi_inum == inum) &&
		    (msi_state_p->msi_p[i].msi_dip == rdip)) {

			*msi_num_p = msi_state_p->msi_p[i].msi_msinum;

			DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_get_msinum: "
			    "inum 0x%x msi 0x%x\n", inum, *msi_num_p);

			mutex_exit(&msi_state_p->msi_mutex);
			return (DDI_SUCCESS);
		}
	}

	if (i >= msi_state_p->msi_cnt)
		DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_get_msinum: "
		    "no msi for inum 0x%x\n", inum);

	mutex_exit(&msi_state_p->msi_mutex);
	return (DDI_FAILURE);
}

/*
 * px_msi_get_props()
 */
static int
px_msi_get_props(px_t *px_p)
{
	dev_info_t		*dip = px_p->px_dip;
	px_msi_state_t		*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	int			ret = DDI_SUCCESS;
	int			length = sizeof (int);
	int			*valuep = NULL;
	uint64_t		msi_addr_hi, msi_addr_lo;
	uint64_t		mem_answer, mem_alen;
	ndi_ra_request_t	request;

	DBG(DBG_MSIQ, dip, "px_msi_get_props\n");

	/* #msi */
	msi_state_p->msi_cnt = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "#msi", PX_DEFAULT_MSI_CNT);

	DBG(DBG_MSIQ, dip, "obp: #msi=%d\n",
	    msi_state_p->msi_cnt);

	/* msi-ranges: msi# field */
	ret = ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_ALLOC,
	    DDI_PROP_DONTPASS, "msi-ranges", (caddr_t)&valuep, &length);

	if (ret == DDI_PROP_SUCCESS) {
		msi_state_p->msi_1st_msinum =
		    ((px_msi_ranges_t *)valuep)->msi_no;
		kmem_free(valuep, (size_t)length);
	} else
		msi_state_p->msi_1st_msinum = PX_DEFAULT_MSI_1ST_MSINUM;

	DBG(DBG_MSIQ, dip, "obp: msi_1st_msinum=%d\n",
	    msi_state_p->msi_1st_msinum);

	/* msi-data-mask */
	msi_state_p->msi_data_mask = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "msi-data-mask", PX_DEFAULT_MSI_DATA_MASK);

	DBG(DBG_MSIQ, dip, "obp: msi-data-mask=0x%x\n",
	    msi_state_p->msi_data_mask);

	/* msi-data-width */
	msi_state_p->msi_data_width = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "msix-data-width", PX_DEFAULT_MSI_DATA_WIDTH);

	DBG(DBG_MSIQ, dip, "obp: msix-data-width=%d\n",
	    msi_state_p->msi_data_width);

	/*
	 * Assume MSI is always supported, but also check if MSIX is supported
	 */
	if (msi_state_p->msi_data_width) {
		msi_state_p->msi_type = DDI_INTR_TYPE_MSI;
		if (msi_state_p->msi_data_width == PX_MSIX_WIDTH)
			msi_state_p->msi_type |= DDI_INTR_TYPE_MSIX;
	}

	/* msi-address-ranges */
	ret = ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_ALLOC,
	    DDI_PROP_DONTPASS, "msi-address-ranges", (caddr_t)&valuep,
	    &length);

	if (ret == DDI_PROP_SUCCESS) {
		msi_addr_hi =
		    ((px_msi_address_ranges_t *)valuep)->msi_addr32_hi;
		msi_addr_lo =
		    ((px_msi_address_ranges_t *)valuep)->msi_addr32_lo;
		msi_state_p->msi_addr32 =
		    (msi_addr_hi << 32) | msi_addr_lo;

		msi_state_p->msi_addr32_len =
		    ((px_msi_address_ranges_t *)valuep)->msi_addr32_len;

		msi_addr_hi =
		    ((px_msi_address_ranges_t *)valuep)->msi_addr64_hi;
		msi_addr_lo =
		    ((px_msi_address_ranges_t *)valuep)->msi_addr64_lo;
		msi_state_p->msi_addr64 =
		    (msi_addr_hi << 32) | msi_addr_lo;

		msi_state_p->msi_addr64_len =
		    ((px_msi_address_ranges_t *)valuep)->msi_addr64_len;

		kmem_free(valuep, (size_t)length);

		msi_state_p->msi_mem_flg = B_FALSE;

		DBG(DBG_MSIQ, dip, "obp: msi_addr32=0x%llx\n",
		    msi_state_p->msi_addr32);

		DBG(DBG_MSIQ, dip, "obp: msi_addr64=0x%llx\n",
		    msi_state_p->msi_addr64);

		return (ret);
	}

	/*
	 * If msi-address-ranges property does not exist in OBP, Fire
	 * driver will need to allocate memory.
	 *
	 * Allocate 64KB of memory from unused PCI-E address space for the MSI
	 * transactions and program MSI 32-bit address register.
	 *
	 * This register is used by the Fire hardware to compare against the
	 * address of incoming PCI-E 32-bit addressed memory write commands.
	 * If the address matches bits 31:16 then PCI-E command is considered
	 * to be MSI transaction.
	 *
	 * pci_resource_setup() is called in context of PCI hotplug
	 * initialization.
	 *
	 * Setup resource maps for this bus node.
	 */
	if (pci_resource_setup(dip) != NDI_SUCCESS) {
		DBG(DBG_MSIQ, dip, "px_msi_getprops: dip=%s%d"
		    "pci_resource_setup failed\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (DDI_FAILURE);
	}

	msi_state_p->msi_mem_flg = B_TRUE;

	/*
	 * Reserve PCI MEM 32 resources to perform 32 bit MSI transactions.
	 */
	bzero((caddr_t)&request, sizeof (ndi_ra_request_t));
	request.ra_flags = NDI_RA_ALLOC_BOUNDED;
	request.ra_boundbase = 0;
	request.ra_boundlen = PX_MSI_4GIG_LIMIT;
	request.ra_len = PX_MSI_ADDR_LEN;
	request.ra_align_mask = 0;

	if (ndi_ra_alloc(dip, &request, &mem_answer, &mem_alen,
		NDI_RA_TYPE_MEM, NDI_RA_PASS) != NDI_SUCCESS) {
		DBG(DBG_MSIQ, dip, "px_msi_getprops: Failed to allocate "
		    "64KB mem\n");

		return (DDI_FAILURE);
	}

	msi_state_p->msi_addr32 = mem_answer;
	msi_state_p->msi_addr32_len = mem_alen;

	DBG(DBG_MSIQ, dip, "px_msi_getprops: 32 Addr 0x%llx\n",
	    msi_state_p->msi_addr32);

	/*
	 * Reserve PCI MEM 64 resources to perform 64 bit MSI transactions.
	 *
	 * NOTE:
	 *
	 * Currently OBP do not export any "available" property or range in
	 * the MEM64 space. Hence ndi_ra_alloc() request will return failure.
	 * So, for time being ignore this failure.
	 */
	bzero((caddr_t)&request, sizeof (ndi_ra_request_t));
	request.ra_flags = NDI_RA_ALLOC_BOUNDED;
	request.ra_boundbase = PX_MSI_4GIG_LIMIT + 1;
	request.ra_boundlen = PX_MSI_4GIG_LIMIT;
	request.ra_len = PX_MSI_ADDR_LEN;
	request.ra_align_mask = 0;

	if (ndi_ra_alloc(dip, &request, &mem_answer, &mem_alen,
		NDI_RA_TYPE_MEM, NDI_RA_PASS) != NDI_SUCCESS) {
		DBG(DBG_MSIQ, dip, "px_msi_getprops: Failed to allocate "
		    "64KB mem\n");

		return (DDI_SUCCESS);
	}

	msi_state_p->msi_addr64 = mem_answer;
	msi_state_p->msi_addr64_len = mem_alen;

	DBG(DBG_MSIQ, dip, "px_msi_getprops: 64 Addr 0x%llx\n",
	    msi_state_p->msi_addr64);

	return (DDI_SUCCESS);
}
