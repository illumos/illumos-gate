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
 * Hypervisor calls called by px nexus driver.
*/

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>
#include <sys/dditypes.h>
#include <px_ioapi.h>
#include "px_lib4v.h"

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
uint64_t
hvio_config_get(devhandle_t dev_hdl, pci_device_t bdf, pci_config_offset_t off, 
    pci_config_size_t size, pci_cfg_data_t *data_p)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_config_put(devhandle_t dev_hdl, pci_device_t bdf, pci_config_offset_t off, 
    pci_config_size_t size, pci_cfg_data_t data)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_iommu_map(devhandle_t dev_hdl, tsbid_t tsbid, pages_t pages,
    io_attributes_t attr, io_page_list_t *io_page_list_p,
    pages_t *pages_mapped)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_iommu_demap(devhandle_t dev_hdl, tsbid_t tsbid, pages_t pages,
    pages_t *pages_demapped)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_iommu_getmap(devhandle_t dev_hdl, tsbid_t tsbid, io_attributes_t *attr_p,
    r_addr_t *r_addr_p)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_iommu_getbypass(devhandle_t dev_hdl, r_addr_t ra, io_attributes_t attr,
    io_addr_t *io_addr_p)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_peek(devhandle_t dev_hdl, r_addr_t ra, size_t size, uint32_t *status,
    uint64_t *data_p)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_poke(devhandle_t dev_hdl, r_addr_t ra, uint64_t sizes, uint64_t data,
    r_addr_t ra2, uint32_t *rdbk_status)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_dma_sync(devhandle_t dev_hdl, r_addr_t ra, size_t num_bytes,
    io_sync_direction_t io_sync_direction, size_t *bytes_synched)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msiq_conf(devhandle_t dev_hdl, msiqid_t msiq_id, r_addr_t ra,
    uint_t msiq_rec_cnt)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msiq_info(devhandle_t dev_hdl, msiqid_t msiq_id, r_addr_t *r_addr_p,
    uint_t *msiq_rec_cnt_p)
{ return (0); }
	
/*ARGSUSED*/
uint64_t
hvio_msiq_getvalid(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_valid_state_t *msiq_valid_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msiq_setvalid(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_valid_state_t msiq_valid_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msiq_getstate(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_state_t *msiq_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msiq_setstate(devhandle_t dev_hdl, msiqid_t msiq_id,
    pci_msiq_state_t msiq_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msiq_gethead(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqhead_t *msiq_head)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msiq_sethead(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqhead_t msiq_head)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msiq_gettail(devhandle_t dev_hdl, msiqid_t msiq_id,
    msiqtail_t *msiq_tail)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msi_getmsiq(devhandle_t dev_hdl, msinum_t msi_num,
    msiqid_t *msiq_id)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msi_setmsiq(devhandle_t dev_hdl, msinum_t msi_num,
    msiqid_t msiq_id, msi_type_t msitype)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msi_getvalid(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_valid_state_t *msi_valid_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msi_setvalid(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_valid_state_t msi_valid_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msi_getstate(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_state_t *msi_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msi_setstate(devhandle_t dev_hdl, msinum_t msi_num,
    pci_msi_state_t msi_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msg_getmsiq(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    msiqid_t *msiq_id)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msg_setmsiq(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    msiqid_t msiq_id)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msg_getvalid(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t *msg_valid_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_msg_setvalid(devhandle_t dev_hdl, pcie_msg_type_t msg_type,
    pcie_msg_valid_state_t msg_valid_state)
{ return (0); }

/*
 * First arg to both of these functions is a dummy, to accomodate how
 * hv_hpriv() works.
 */
/*ARGSUSED*/
int
px_phys_acc_4v(uint64_t dummy, uint64_t from_addr, uint64_t to_addr)
{ return (0); }

#else	/* lint || __lint */

	/*
	 * arg0 - devhandle
	 * arg1 - pci_device
	 * arg2 - pci_config_offset
	 * arg3 - pci_config_size
	 *
	 * ret0 - status
	 * ret1 - error_flag
	 * ret2 - pci_cfg_data
	 */
	ENTRY(hvio_config_get)
	mov	HVIO_CONFIG_GET, %o5
	ta	FAST_TRAP
	brnz	%o0, 1f
	movrnz	%o1, -1, %o2
	brz,a	%o1, 1f
	stuw	%o2, [%o4]
1:	retl
	nop
	SET_SIZE(hvio_config_get)

	/*
	 * arg0 - devhandle
	 * arg1 - pci_device
	 * arg2 - pci_config_offset
	 * arg3 - pci_config_size
	 * arg4 - pci_cfg_data
	 *
	 * ret0 - status
	 * ret1 - error_flag
	 */
	ENTRY(hvio_config_put)
	mov	HVIO_CONFIG_PUT, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_config_put)

	/*
	 * arg0 - devhandle
	 * arg1 - tsbid
	 * arg2 - pages
	 * arg3 - io_attributes
	 * arg4 - io_page_list_p
	 *
	 * ret1 - pages_mapped
	 */
	ENTRY(hvio_iommu_map)
	save	%sp, -SA(MINFRAME64), %sp
	mov	%i0, %o0
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	%i4, %o4
	mov	HVIO_IOMMU_MAP, %o5
	ta	FAST_TRAP
	brnz	%o0, 1f
	mov	%o0, %i0
	stuw	%o1, [%i5]
1:
	ret
	restore
	SET_SIZE(hvio_iommu_map)

	/*
	 * arg0 - devhandle
	 * arg1 - tsbid
	 * arg2 - pages
	 *
	 * ret1 - pages_demapped
	 */
	ENTRY(hvio_iommu_demap)
	mov	HVIO_IOMMU_DEMAP, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o3]
1:	retl
	nop
	SET_SIZE(hvio_iommu_demap)

	/*
	 * arg0 - devhandle
	 * arg1 - tsbid
	 *
	 *
	 * ret0 - status
	 * ret1 - io_attributes
	 * ret2 - r_addr
	 */
	ENTRY(hvio_iommu_getmap)
	mov	%o2, %o4
	mov	HVIO_IOMMU_GETMAP, %o5
	ta	FAST_TRAP
	brnz	%o0, 1f
	nop
	stx	%o2, [%o3]
	st	%o1, [%o4]
1:
	retl
	nop
	SET_SIZE(hvio_iommu_getmap)

	/*
	 * arg0 - devhandle
	 * arg1 - r_addr
	 * arg2 - io_attributes
	 *
	 *
	 * ret0 - status
	 * ret1 - io_addr
	 */
	ENTRY(hvio_iommu_getbypass)
	mov	HVIO_IOMMU_GETBYPASS, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o3]
1:	retl
	nop
	SET_SIZE(hvio_iommu_getbypass)

	/*
	 * arg0 - devhandle
	 * arg1 - r_addr
	 * arg2 - size
	 *
	 * ret1 - error_flag
	 * ret2 - data
	 */
	ENTRY(hvio_peek)
	mov	HVIO_PEEK, %o5
	ta	FAST_TRAP
	brnz	%o0, 1f
	nop
	stx	%o2, [%o4]
	st	%o1, [%o3]
1:
	retl
	nop
	SET_SIZE(hvio_peek)

	/*
	 * arg0 - devhandle
	 * arg1 - r_addr
	 * arg2 - sizes
	 * arg3 - data
	 * arg4 - r_addr2
	 *
	 * ret1 - error_flag
	 */
	ENTRY(hvio_poke)
	save	%sp, -SA(MINFRAME64), %sp
	mov	%i0, %o0
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	%i4, %o4
	mov	HVIO_POKE, %o5
	ta	FAST_TRAP
	brnz	%o0, 1f
	mov	%o0, %i0
	stuw	%o1, [%i5]
1:
	ret
	restore
	SET_SIZE(hvio_poke)

	/*
	 * arg0 - devhandle
	 * arg1 - r_addr
	 * arg2 - num_bytes
	 * arg3 - io_sync_direction
	 *
	 * ret0 - status
	 * ret1 - bytes_synched
	 */
	ENTRY(hvio_dma_sync)
	mov	HVIO_DMA_SYNC, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o4]
1:	retl
	nop
	SET_SIZE(hvio_dma_sync)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 * arg2 - r_addr
	 * arg3 - nentries
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msiq_conf)
	mov	HVIO_MSIQ_CONF, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msiq_conf)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 *
	 * ret0 - status
	 * ret1 - r_addr
	 * ret1 - nentries
	 */
	ENTRY(hvio_msiq_info)
	mov     %o2, %o4
	mov     HVIO_MSIQ_INFO, %o5
	ta      FAST_TRAP
	brnz	%o0, 1f
	nop
	stx     %o1, [%o4]
	stuw    %o2, [%o3]
1:      retl
	nop
	SET_SIZE(hvio_msiq_info)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 *
	 * ret0 - status
	 * ret1 - msiq_valid_state
	 */
	ENTRY(hvio_msiq_getvalid)
	mov	HVIO_MSIQ_GETVALID, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msiq_getvalid)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 * arg2 - msiq_valid_state
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msiq_setvalid)
	mov	HVIO_MSIQ_SETVALID, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msiq_setvalid)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 *
	 * ret0 - status
	 * ret1 - msiq_state
	 */
	ENTRY(hvio_msiq_getstate)
	mov	HVIO_MSIQ_GETSTATE, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msiq_getstate)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 * arg2 - msiq_state
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msiq_setstate)
	mov	HVIO_MSIQ_SETSTATE, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msiq_setstate)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 *
	 * ret0 - status
	 * ret1 - msiq_head
	 */
	ENTRY(hvio_msiq_gethead)
	mov	HVIO_MSIQ_GETHEAD, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msiq_gethead)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 * arg2 - msiq_head
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msiq_sethead)
	mov	HVIO_MSIQ_SETHEAD, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msiq_sethead)

	/*
	 * arg0 - devhandle
	 * arg1 - msiq_id
	 *
	 * ret0 - status
	 * ret1 - msiq_tail
	 */
	ENTRY(hvio_msiq_gettail)
	mov	HVIO_MSIQ_GETTAIL, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msiq_gettail)

	/*
	 * arg0 - devhandle
	 * arg1 - msi_num
	 *
	 * ret0 - status
	 * ret1 - msiq_id
	 */
	ENTRY(hvio_msi_getmsiq)
	mov	HVIO_MSI_GETMSIQ, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msi_getmsiq)

	/*
	 * arg0 - devhandle
	 * arg1 - msi_num
	 * arg2 - msiq_id
	 * arg2 - msitype
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msi_setmsiq)
	mov	HVIO_MSI_SETMSIQ, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msi_setmsiq)

	/*
	 * arg0 - devhandle
	 * arg1 - msi_num
	 *
	 * ret0 - status
	 * ret1 - msi_valid_state
	 */
	ENTRY(hvio_msi_getvalid)
	mov	HVIO_MSI_GETVALID, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msi_getvalid)

	/*
	 * arg0 - devhandle
	 * arg1 - msi_num
	 * arg2 - msi_valid_state
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msi_setvalid)
	mov	HVIO_MSI_SETVALID, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msi_setvalid)

	/*
	 * arg0 - devhandle
	 * arg1 - msi_num
	 *
	 * ret0 - status
	 * ret1 - msi_state
	 */
	ENTRY(hvio_msi_getstate)
	mov	HVIO_MSI_GETSTATE, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msi_getstate)

	/*
	 * arg0 - devhandle
	 * arg1 - msi_num
	 * arg2 - msi_state
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msi_setstate)
	mov	HVIO_MSI_SETSTATE, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msi_setstate)

	/*
	 * arg0 - devhandle
	 * arg1 - msg_type
	 *
	 * ret0 - status
	 * ret1 - msiq_id
	 */
	ENTRY(hvio_msg_getmsiq)
	mov	HVIO_MSG_GETMSIQ, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msg_getmsiq)

	/*
	 * arg0 - devhandle
	 * arg1 - msg_type
	 * arg2 - msiq_id
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msg_setmsiq)
	mov	HVIO_MSG_SETMSIQ, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msg_setmsiq)

	/*
	 * arg0 - devhandle
	 * arg1 - msg_type
	 *
	 * ret0 - status
	 * ret1 - msg_valid_state
	 */
	ENTRY(hvio_msg_getvalid)
	mov	HVIO_MSG_GETVALID, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_msg_getvalid)

	/*
	 * arg0 - devhandle
	 * arg1 - msg_type
	 * arg2 - msg_valid_state
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_msg_setvalid)
	mov	HVIO_MSG_SETVALID, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_msg_setvalid)

#define	SHIFT_REGS	mov %o1,%o0; mov %o2,%o1; mov %o3,%o2; mov %o4,%o3

! px_phys_acc_4v: Do physical address read.
!
! After SHIFT_REGS:
! %o0 is "from" address
! %o1 is "to" address
!
! Assumes 8 byte data and that alignment is correct.
!
! Always returns success (0) in %o0

	! px_phys_acc_4v must not be split across pages.
	!
	! ATTN: Be sure that the alignment value is larger than the size of
	! the px_phys_acc_4v function.
	!
	.align	0x40

	ENTRY(px_phys_acc_4v)

	SHIFT_REGS
	ldx	[%o0], %g1
	stx	%g1, [%o1]
	membar	#Sync			! Make sure the loads take
	mov     %g0, %o0
	done
	SET_SIZE(px_phys_acc_4v)

#endif	/* lint || __lint */
