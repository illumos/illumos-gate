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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ib/ibtl/impl/ibtl.h>

/*
 * ibtl_mem.c
 *    These routines implement all of the Memory Region verbs and the alloc/
 *    query/free Memory Window verbs at the TI interface.
 */

static char ibtl_mem[] = "ibtl_mem";

/*
 * Function:
 *	ibt_register_mr()
 * Input:
 *	hca_hdl   - HCA Handle.
 *	pd        - Protection Domain Handle.
 *	mem_attr  - Requested memory region attributes.
 * Output:
 *	mr_hdl_p  - The returned IBT memory region handle.
 *	mem_desc  - Returned memory descriptor.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MR_VA_INVALID
 *	IBT_MR_LEN_INVALID
 *	IBT_MR_ACCESS_REQ_INVALID
 *	IBT_PD_HDL_INVALID
 *	IBT_INSUFF_RESOURCE
 * Description:
 *    Prepares a virtually addressed memory region for use by a HCA. A
 *    description of the registered memory suitable for use in Work Requests
 *    (WRs) is returned in the ibt_mr_desc_t parameter.
 */
ibt_status_t
ibt_register_mr(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd, ibt_mr_attr_t *mem_attr,
    ibt_mr_hdl_t *mr_hdl_p, ibt_mr_desc_t *mem_desc)
{
	ib_vaddr_t 	vaddr;
	ibt_status_t 	status;

	IBTF_DPRINTF_L3(ibtl_mem, "ibt_register_mr(%p, %p, %p)",
	    hca_hdl, pd, mem_attr);

	vaddr = mem_attr->mr_vaddr;

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_register_mr(
	    IBTL_HCA2CIHCA(hca_hdl), pd, mem_attr, IBTL_HCA2CLNT(hca_hdl),
	    mr_hdl_p, mem_desc);
	if (status == IBT_SUCCESS) {
		mem_desc->md_vaddr = vaddr;
		mutex_enter(&hca_hdl->ha_mutex);
		hca_hdl->ha_mr_cnt++;
		mutex_exit(&hca_hdl->ha_mutex);
	}

	return (status);
}


/*
 * Function:
 *	ibt_register_buf()
 * Input:
 *	hca_hdl		HCA Handle.
 *	pd		Protection Domain Handle.
 *	mem_bpattr	Memory Registration attributes (IOVA and flags).
 *	bp		A pointer to a buf(9S) struct.
 * Output:
 *	mr_hdl_p	The returned IBT memory region handle.
 *	mem_desc	Returned memory descriptor.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MR_VA_INVALID
 *	IBT_MR_LEN_INVALID
 *	IBT_MR_ACCESS_REQ_INVALID
 *	IBT_PD_HDL_INVALID
 *	IBT_INSUFF_RESOURCE
 * Description:
 *	Prepares a memory region described by a buf(9S) struct for use by a HCA.
 *	A description of the registered memory suitable for use in
 *	Work Requests (WRs) is returned in the ibt_mr_desc_t parameter.
 */
ibt_status_t
ibt_register_buf(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_smr_attr_t *mem_bpattr, struct buf *bp, ibt_mr_hdl_t *mr_hdl_p,
    ibt_mr_desc_t *mem_desc)
{
	ibt_status_t 	status;

	IBTF_DPRINTF_L3(ibtl_mem, "ibt_register_buf(%p, %p, %p, %p)",
	    hca_hdl, pd, mem_bpattr, bp);

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_register_buf(
	    IBTL_HCA2CIHCA(hca_hdl), pd, mem_bpattr, bp, IBTL_HCA2CLNT(hca_hdl),
	    mr_hdl_p, mem_desc);
	if (status == IBT_SUCCESS) {
		mutex_enter(&hca_hdl->ha_mutex);
		hca_hdl->ha_mr_cnt++;
		mutex_exit(&hca_hdl->ha_mutex);
	}

	return (status);
}


/*
 * Function:
 *	ibt_query_mr()
 * Input:
 *	hca_hdl   - HCA Handle.
 *	mr_hdl    - The IBT Memory Region handle.
 * Output:
 *      attr      - The pointer to Memory region attributes structure.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MR_HDL_INVALID
 * Description:
 *    Retrieves information about a specified memory region.
 */
ibt_status_t
ibt_query_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_mr_query_attr_t *attr)
{
	IBTF_DPRINTF_L3(ibtl_mem, "ibt_query_mr(%p, %p)", hca_hdl, mr_hdl);

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_query_mr(
	    IBTL_HCA2CIHCA(hca_hdl), mr_hdl, attr));
}


/*
 * Function:
 *	ibt_deregister_mr()
 * Input:
 *	hca_hdl   - HCA Handle.
 *	mr_hdl    - The IBT Memory Region handle.
 * Output:
 *      none.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MR_HDL_INVALID
 *	IBT_MR_IN_USE
 * Description:
 *    De-register the registered memory region. Remove a memory region from a
 *    HCA translation table, and free all resources associated with the
 *    memory region.
 */
ibt_status_t
ibt_deregister_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl)
{
	ibt_status_t 	status;

	IBTF_DPRINTF_L3(ibtl_mem, "ibt_deregister_mr(%p, %p)", hca_hdl, mr_hdl);

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_deregister_mr(
	    IBTL_HCA2CIHCA(hca_hdl), mr_hdl);
	if (status == IBT_SUCCESS) {
		mutex_enter(&hca_hdl->ha_mutex);
		hca_hdl->ha_mr_cnt--;
		mutex_exit(&hca_hdl->ha_mutex);
	}
	return (status);
}


/*
 * Function:
 *	ibt_reregister_mr()
 * Input:
 *	hca_hdl   - HCA Handle.
 *	mr_hdl    - The IBT Memory Region handle.
 *	pd        - Optional Protection Domain Handle.
 *	mem_attr  - Requested memory region attributes.
 * Output:
 *	mr_hdl_p  - The reregistered IBT memory region handle.
 *	mem_desc  - Returned memory descriptor for the new memory region.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MR_HDL_INVALID
 *	IBT_MR_VA_INVALID
 *	IBT_MR_LEN_INVALID
 *	IBT_MR_ACCESS_REQ_INVALID
 *	IBT_PD_HDL_INVALID
 *	IBT_INSUFF_RESOURCE
 *	IBT_MR_IN_USE
 * Description:
 *    Modify the attributes of an existing memory region.
 */
ibt_status_t
ibt_reregister_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl, ibt_pd_hdl_t pd,
    ibt_mr_attr_t *mem_attr, ibt_mr_hdl_t *mr_hdl_p, ibt_mr_desc_t *mem_desc)
{
	ibt_status_t 	status;
	ib_vaddr_t 	vaddr = mem_attr->mr_vaddr;

	IBTF_DPRINTF_L3(ibtl_mem, "ibt_reregister_mr(%p, %p, %p, %p)",
	    hca_hdl, mr_hdl, pd, mem_attr);

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_reregister_mr(
	    IBTL_HCA2CIHCA(hca_hdl), mr_hdl, pd, mem_attr,
	    IBTL_HCA2CLNT(hca_hdl), mr_hdl_p, mem_desc);

	if (status == IBT_SUCCESS)
		mem_desc->md_vaddr = vaddr;
	else if (!(status == IBT_MR_IN_USE || status == IBT_HCA_HDL_INVALID ||
	    status == IBT_MR_HDL_INVALID)) {

		IBTF_DPRINTF_L2(ibtl_mem, "ibt_reregister_mr: "
		    "Re-registration Failed: %d", status);

		/* we lost one memory region resource */
		mutex_enter(&hca_hdl->ha_mutex);
		hca_hdl->ha_mr_cnt--;
		mutex_exit(&hca_hdl->ha_mutex);
	}

	return (status);
}


/*
 * Function:
 *	ibt_reregister_buf()
 * Input:
 *	hca_hdl		HCA Handle.
 *	mr_hdl		The IBT Memory Region handle.
 *	pd		Optional Protection Domain Handle.
 *	mem_bpattr	Memory Registration attributes (IOVA and flags).
 *	bp		A pointer to a buf(9S) struct.
 * Output:
 *	mr_hdl_p	The reregistered IBT memory region handle.
 *	mem_desc	Returned memory descriptor for the new memory region.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MR_HDL_INVALID
 *	IBT_MR_VA_INVALID
 *	IBT_MR_LEN_INVALID
 *	IBT_MR_ACCESS_REQ_INVALID
 *	IBT_PD_HDL_INVALID
 *	IBT_INSUFF_RESOURCE
 *	IBT_MR_IN_USE
 * Description:
 *	Modify the attributes of an existing memory region as described by a
 *	buf(9S) struct for use by a HCA.  A description of the registered
 *	memory suitable for use in Work Requests (WRs) is returned in the
 *	ibt_mr_desc_t parameter.
 */
ibt_status_t
ibt_reregister_buf(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_pd_hdl_t pd, ibt_smr_attr_t *mem_bpattr, struct buf *bp,
    ibt_mr_hdl_t *mr_hdl_p, ibt_mr_desc_t *mem_desc)
{
	ibt_status_t 		status;

	IBTF_DPRINTF_L3(ibtl_mem, "ibt_reregister_buf(%p, %p, %p, %p, %p)",
	    hca_hdl, mr_hdl, pd, mem_bpattr, bp);

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_reregister_buf(
	    IBTL_HCA2CIHCA(hca_hdl), mr_hdl, pd, mem_bpattr, bp,
	    IBTL_HCA2CLNT(hca_hdl), mr_hdl_p, mem_desc);

	if (!(status == IBT_SUCCESS || status == IBT_MR_IN_USE ||
	    status == IBT_HCA_HDL_INVALID || status == IBT_MR_HDL_INVALID)) {

		IBTF_DPRINTF_L2(ibtl_mem, "ibt_reregister_buf: "
		    "Re-registration Mem Failed: %d", status);

		/* we lost one memory region resource */
		mutex_enter(&hca_hdl->ha_mutex);
		hca_hdl->ha_mr_cnt--;
		mutex_exit(&hca_hdl->ha_mutex);
	}
	return (status);
}


/*
 * Function:
 *	ibt_register_shared_mr()
 * Input:
 *	hca_hdl   - HCA Handle.
 *	mr_hdl    - The IBT Memory Region handle.
 *	pd        - Protection Domain Handle.
 *	mem_sattr - Requested memory region shared attributes.
 * Output:
 *	mr_hdl_p  - The reregistered IBT memory region handle.
 *	mem_desc  - Returned memory descriptor for the new memory region.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_INSUFF_RESOURCE
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MR_HDL_INVALID
 *	IBT_PD_HDL_INVALID
 *	IBT_MR_ACCESS_REQ_INVALID
 * Description:
 *    Given an existing memory region, a new memory region associated with
 *    the same physical locations is created.
 */
ibt_status_t
ibt_register_shared_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_pd_hdl_t pd, ibt_smr_attr_t *mem_sattr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_mr_desc_t *mem_desc)
{
	ibt_status_t		status;

	IBTF_DPRINTF_L3(ibtl_mem, "ibt_register_shared_mr(%p, %p, %p, %p)",
	    hca_hdl, mr_hdl, pd, mem_sattr);

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_register_shared_mr(
	    IBTL_HCA2CIHCA(hca_hdl), mr_hdl, pd, mem_sattr,
	    IBTL_HCA2CLNT(hca_hdl), mr_hdl_p, mem_desc);
	if (status == IBT_SUCCESS) {
		mutex_enter(&hca_hdl->ha_mutex);
		hca_hdl->ha_mr_cnt++;
		mutex_exit(&hca_hdl->ha_mutex);
	}
	return (status);
}

/*
 * Function:
 *	ibt_sync_mr()
 * Input:
 *	hca_hdl		- HCA Handle.
 *	mr_segments	- A pointer to an array of ibt_mr_sync_t that describes
 *			  the memory regions to sync.
 *	num_segments	- The length of the mr_segments array.
 * Output:
 *	NONE
 * Returns:
 *      IBT_SUCCESS
 *	IBT_HCA_HDL_INVALID
 *	IBT_MR_HDL_INVALID
 *	IBT_INVALID_PARAM
 *	IBT_MR_VA_INVALID
 *	IBT_MR_LEN_INVALID
 * Description:
 *	Make memory changes visible to incoming RDMA reads, or make the affects
 *	of an incoming RDMA writes visible to the consumer.
 */
ibt_status_t
ibt_sync_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_sync_t *mr_segments,
    size_t num_segments)

{
	IBTF_DPRINTF_L3(ibtl_mem, "ibt_sync_mr(%p, %p, %d)", hca_hdl,
	    mr_segments, num_segments);

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_sync_mr(
	    IBTL_HCA2CIHCA(hca_hdl), mr_segments, num_segments));
}


/*
 * Function:
 *	ibt_alloc_mw()
 * Input:
 *	hca_hdl   - HCA Handle.
 *	pd        - Protection Domain Handle.
 *	flags     - Memory Window alloc flags.
 * Output:
 *	mw_hdl_p  - The returned IBT Memory Window handle.
 *	rkey      - The IBT R_Key handle.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_INSUFF_RESOURCE
 *	IBT_CHAN_HDL_INVALID
 *	IBT_PD_HDL_INVALID
 * Description:
 *    Allocate a memory window from the HCA.
 */
ibt_status_t
ibt_alloc_mw(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd, ibt_mw_flags_t flags,
    ibt_mw_hdl_t *mw_hdl_p, ibt_rkey_t *rkey)
{
	ibt_status_t		status;

	IBTF_DPRINTF_L3(ibtl_mem, "ibt_alloc_mw(%p, %p, 0x%x)",
	    hca_hdl, pd, flags);

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_mw(
	    IBTL_HCA2CIHCA(hca_hdl), pd, flags, mw_hdl_p, rkey);

	/*
	 * XXX - We should be able to allocate state and have a IBTF Memory
	 * Window Handle. Memory Windows are meant to be rebound on the fly
	 * (using a post) to make them fast. It is expected that alloc memory
	 * window will be done in a relatively static manner. But, we don't have
	 * a good reason to have local MW state at this point, so we won't.
	 */
	if (status == IBT_SUCCESS) {
		mutex_enter(&hca_hdl->ha_mutex);
		hca_hdl->ha_mw_cnt++;
		mutex_exit(&hca_hdl->ha_mutex);
	}
	return (status);
}


/*
 * Function:
 *	ibt_query_mw()
 * Input:
 *	hca_hdl   - HCA Handle.
 *	mw_hdl    - The IBT Memory Window handle.
 * Output:
 *	pd        - Protection Domain Handle.
 *	rkey      - The IBT R_Key handle.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MW_HDL_INVALID
 * Description:
 *    Retrieves information about a specified memory region.
 */
ibt_status_t
ibt_query_mw(ibt_hca_hdl_t hca_hdl, ibt_mw_hdl_t mw_hdl,
    ibt_mw_query_attr_t *mw_attr_p)
{
	IBTF_DPRINTF_L3(ibtl_mem, "ibt_query_mw(%p, %p)", hca_hdl, mw_hdl);

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_query_mw(
	    IBTL_HCA2CIHCA(hca_hdl), mw_hdl, mw_attr_p));
}


/*
 * Function:
 *	ibt_free_mw()
 * Input:
 *      hca_hdl   - HCA Handle
 *	mw_hdl    - The IBT Memory Window handle.
 * Output:
 *	none.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_CHAN_HDL_INVALID
 *	IBT_MW_HDL_INVALID
 * Description:
 *    De-allocate the Memory Window.
 */
ibt_status_t
ibt_free_mw(ibt_hca_hdl_t hca_hdl, ibt_mw_hdl_t mw_hdl)
{
	ibt_status_t		status;

	IBTF_DPRINTF_L3(ibtl_mem, "ibt_free_mw(%p, %p)", hca_hdl, mw_hdl);

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_free_mw(
	    IBTL_HCA2CIHCA(hca_hdl), mw_hdl);

	if (status == IBT_SUCCESS) {
		mutex_enter(&hca_hdl->ha_mutex);
		hca_hdl->ha_mw_cnt--;
		mutex_exit(&hca_hdl->ha_mutex);
	}
	return (status);
}


/*
 * Function:
 *	ibt_map_mem_area()
 * Input:
 *      hca_hdl		HCA Handle
 *	va_attrs	A pointer to an ibt_va_attr_t that describes the
 *			VA to be translated.
 *	paddr_list_len	The number of entries in the 'paddr_list_p' array.
 * Output:
 *	paddr_list_p	Array of ibt_phys_buf_t (allocated by the caller),
 *			in which the physical buffers that map the virtual
 *			buffer are returned.
 *	num_paddr_p	The actual number of ibt_phys_buf_t that were
 *			returned in the 'paddr_list_p' array.
 *	ma_hdl_p	Memory Area Handle.
 * Returns:
 *      IBT_SUCCESS
 * Description:
 * 	Translate a kernel virtual address range into HCA physical addresses.
 *	A set of physical addresses, that can be used with "Reserved L_Key",
 *	register physical,  and "Fast Registration Work Request" operations
 *	is returned.
 */
ibt_status_t
ibt_map_mem_area(ibt_hca_hdl_t hca_hdl, ibt_va_attr_t *va_attrs,
    uint_t paddr_list_len, ibt_phys_buf_t *paddr_list_p, uint_t *num_paddr_p,
    ibt_ma_hdl_t *ma_hdl_p)
{
	IBTF_DPRINTF_L3(ibtl_mem, "ibt_map_mem_area(%p, %p, %d)",
	    hca_hdl, va_attrs, paddr_list_len);

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_map_mem_area(
	    IBTL_HCA2CIHCA(hca_hdl), va_attrs,
	    NULL, /* IBTL_HCA2MODI_P(hca_hdl)->mi_reserved */
	    paddr_list_len, paddr_list_p,
	    num_paddr_p, ma_hdl_p));
}


/*
 * Function:
 *	ibt_unmap_mem_area()
 * Input:
 *      hca_hdl		HCA Handle
 *	ma_hdl		Memory Area Handle.
 * Output:
 *	None.
 * Returns:
 *      IBT_SUCCESS
 * Description:
 * 	Un pin physical pages pinned during an ibt_map_mem_area() call.
 */
ibt_status_t
ibt_unmap_mem_area(ibt_hca_hdl_t hca_hdl, ibt_ma_hdl_t ma_hdl)
{
	IBTF_DPRINTF_L3(ibtl_mem, "ibt_unmap_mem_area(%p, %p)",
	    hca_hdl, ma_hdl);

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_unmap_mem_area(
	    IBTL_HCA2CIHCA(hca_hdl), ma_hdl));
}


/*
 * Function:
 *	ibt_alloc_lkey()
 * Input:
 *      hca_hdl			HCA Handle
 *	pd			A protection domain handle.
 *	flags			Access control.
 *	phys_buf_list_sz	Requested size of Physical Buffer List (PBL)
 *				resources to be allocated.
 * Output:
 *	mr_hdl_p		The returned IBT memory region handle.
 *	mem_desc_p		Returned memory descriptor.
 * Returns:
 *      IBT_SUCCESS
 * Description:
 * 	Allocates physical buffer list resources for use in memory
 *	registrations.
 */
ibt_status_t
ibt_alloc_lkey(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd, ibt_lkey_flags_t flags,
    uint_t phys_buf_list_sz, ibt_mr_hdl_t *mr_hdl_p,
    ibt_pmr_desc_t *mem_desc_p)
{
	IBTF_DPRINTF_L3(ibtl_mem, "ibt_alloc_lkey(%p, %p, 0x%X, %d)",
	    hca_hdl, pd, flags, phys_buf_list_sz);

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_lkey(
	    IBTL_HCA2CIHCA(hca_hdl), pd, flags, phys_buf_list_sz, mr_hdl_p,
	    mem_desc_p));
}


/*
 * Function:
 *	ibt_register_phys_mr()
 * Input:
 *      hca_hdl		HCA Handle
 *	pd		A protection domain handle.
 *	mem_pattr	Requested memory region physical attributes.
 * Output:
 *	mr_hdl_p	The returned IBT memory region handle.
 *	mem_desc_p	Returned memory descriptor.
 * Returns:
 *      IBT_SUCCESS
 * Description:
 * 	Prepares a physically addressed memory region for use by a HCA.
 */
ibt_status_t
ibt_register_phys_mr(ibt_hca_hdl_t hca_hdl, ibt_pd_hdl_t pd,
    ibt_pmr_attr_t *mem_pattr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_pmr_desc_t *mem_desc_p)
{
	IBTF_DPRINTF_L3(ibtl_mem, "ibt_register_phys_mr(%p, %p, %p)",
	    hca_hdl, pd, mem_pattr);

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_register_physical_mr(
	    IBTL_HCA2CIHCA(hca_hdl), pd, mem_pattr,
	    NULL, /* IBTL_HCA2MODI_P(hca_hdl)->mi_reserved */
	    mr_hdl_p, mem_desc_p));
}


/*
 * Function:
 *	ibt_reregister_phys_mr()
 * Input:
 *      hca_hdl		HCA Handle
 *	mr_hdl		The IBT memory region handle.
 *	pd		A protection domain handle.
 *	mem_pattr	Requested memory region physical attributes.
 * Output:
 *	mr_hdl_p	The returned IBT memory region handle.
 *	mem_desc_p	Returned memory descriptor.
 * Returns:
 *      IBT_SUCCESS
 * Description:
 * 	Prepares a physically addressed memory region for use by a HCA.
 */
ibt_status_t
ibt_reregister_phys_mr(ibt_hca_hdl_t hca_hdl, ibt_mr_hdl_t mr_hdl,
    ibt_pd_hdl_t pd, ibt_pmr_attr_t *mem_pattr, ibt_mr_hdl_t *mr_hdl_p,
    ibt_pmr_desc_t *mem_desc_p)
{
	IBTF_DPRINTF_L3(ibtl_mem, "ibt_reregister_phys_mr(%p, %p, %p, %p)",
	    hca_hdl, mr_hdl, pd, mem_pattr);

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_reregister_physical_mr(
	    IBTL_HCA2CIHCA(hca_hdl), mr_hdl, pd, mem_pattr,
	    NULL, /* IBTL_HCA2MODI_P(hca_hdl)->mi_reserved */
	    mr_hdl_p, mem_desc_p));
}
