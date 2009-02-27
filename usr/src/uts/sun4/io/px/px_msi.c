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
	ddi_irm_pool_t		*irm_pool_p = NULL;
	ddi_irm_params_t	irm_params;
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

	/*
	 * Create IRM pool to manage interrupt allocations.
	 */
	bzero(&irm_params, sizeof (ddi_irm_params_t));
	irm_params.iparams_types = msi_state_p->msi_type;
	irm_params.iparams_total = msi_state_p->msi_cnt;
	if (ndi_irm_create(dip, &irm_params, &irm_pool_p) == DDI_SUCCESS) {
		msi_state_p->msi_pool_p = irm_pool_p;
	} else {
		DBG(DBG_MSIQ, dip, "ndi_irm_create() failed\n");
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

	if (msi_state_p->msi_pool_p) {
		(void) ndi_irm_destroy(msi_state_p->msi_pool_p);
	}

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
px_msi_alloc(px_t *px_p, dev_info_t *rdip, int type, int inum, int msi_count,
    int flag, int *actual_msi_count_p)
{
	px_msi_state_t	*msi_state_p = &px_p->px_ib_p->ib_msi_state;
	int		first, count, i, n;

	DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_alloc: rdip %s:%d "
	    "type 0x%x inum 0x%x msi_count 0x%x\n", ddi_driver_name(rdip),
	    ddi_get_instance(rdip), type, inum, msi_count);

	mutex_enter(&msi_state_p->msi_mutex);

	*actual_msi_count_p = 0;

	/*
	 * MSI interrupts are allocated as contiguous ranges at
	 * power of 2 boundaries from the start of the MSI array.
	 */
	if (type == DDI_INTR_TYPE_MSI) {

		/* Search for a range of available interrupts */
		for (count = msi_count; count; count >>= 1) {
			for (first = 0; (first + count) < msi_state_p->msi_cnt;
			    first += count) {
				for (i = first; i < (first + count); i++) {
					if (msi_state_p->msi_p[i].msi_state
					    != MSI_STATE_FREE) {
						break;
					}
				}
				if (i == (first + count)) {
					goto found_msi;
				}
			}
			DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_alloc: failed\n");
			if (count > 1) {
				DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_alloc: "
				    "Retry MSI allocation with new msi_count "
				    "0x%x\n", count >> 1);
			}
		}

found_msi:
		/* Set number of available interrupts */
		*actual_msi_count_p = count;

		/* Check if successful, and enforce strict behavior */
		if ((count == 0) ||
		    ((flag == DDI_INTR_ALLOC_STRICT) && (count != msi_count))) {
			mutex_exit(&msi_state_p->msi_mutex);
			return (DDI_EAGAIN);
		}

		/* Allocate the interrupts */
		for (i = first; i < (first + count); i++, inum++) {
			msi_state_p->msi_p[i].msi_state = MSI_STATE_INUSE;
			msi_state_p->msi_p[i].msi_dip = rdip;
			msi_state_p->msi_p[i].msi_inum = inum;
		}
	}

	/*
	 * MSI-X interrupts are allocated from the end of the MSI
	 * array.  There are no concerns about power of 2 boundaries
	 * and the allocated interrupts do not have to be contiguous.
	 */
	if (type == DDI_INTR_TYPE_MSIX) {

		/* Count available interrupts, up to count requested */
		for (count = 0, i = (msi_state_p->msi_cnt - 1); i >= 0; i--) {
			if (msi_state_p->msi_p[i].msi_state == MSI_STATE_FREE) {
				if (count == 0)
					first = i;
				count++;
				if (count == msi_count)
					break;
			}
		}

		/* Set number of available interrupts */
		*actual_msi_count_p = count;

		/* Check if successful, and enforce strict behavior */
		if ((count == 0) ||
		    ((flag == DDI_INTR_ALLOC_STRICT) && (count != msi_count))) {
			mutex_exit(&msi_state_p->msi_mutex);
			return (DDI_EAGAIN);
		}

		/* Allocate the interrupts */
		for (n = 0, i = first; n < count; i--) {
			if (msi_state_p->msi_p[i].msi_state != MSI_STATE_FREE)
				continue;
			msi_state_p->msi_p[i].msi_state = MSI_STATE_INUSE;
			msi_state_p->msi_p[i].msi_dip = rdip;
			msi_state_p->msi_p[i].msi_inum = inum;
			inum++;
			n++;
		}
	}

	DBG(DBG_A_MSIX, px_p->px_dip, "px_msi_alloc: rdip %s:%d "
	    "msi_num 0x%x count 0x%x\n", ddi_driver_name(rdip),
	    ddi_get_instance(rdip), first, count);

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
	int		i, n;

	DBG(DBG_R_MSIX, px_p->px_dip, "px_msi_free: rdip 0x%p "
	    "inum 0x%x msi_count 0x%x\n", rdip, inum, msi_count);

	mutex_enter(&msi_state_p->msi_mutex);

	/*
	 * Find and release the specified MSI/X numbers.
	 *
	 * Because the allocations are not always contiguous, perform
	 * a full linear search of the MSI/X table looking for MSI/X
	 * vectors owned by the device with inum values in the range
	 * [inum .. (inum + msi_count - 1)].
	 */
	for (i = 0, n = 0; (i < msi_state_p->msi_cnt) && (n < msi_count); i++) {
		if ((msi_state_p->msi_p[i].msi_dip == rdip) &&
		    (msi_state_p->msi_p[i].msi_inum >= inum) &&
		    (msi_state_p->msi_p[i].msi_inum < (inum + msi_count))) {
			msi_state_p->msi_p[i].msi_dip = NULL;
			msi_state_p->msi_p[i].msi_inum = 0;
			msi_state_p->msi_p[i].msi_msiq_id = 0;
			msi_state_p->msi_p[i].msi_state = MSI_STATE_FREE;
			n++;
		}
	}

	mutex_exit(&msi_state_p->msi_mutex);

	/* Fail if the MSI/X numbers were not found */
	if (n < msi_count)
		return (DDI_FAILURE);

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
