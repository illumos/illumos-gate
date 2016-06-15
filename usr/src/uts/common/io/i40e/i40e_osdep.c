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
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#include "i40e_sw.h"
#include "i40e_type.h"
#include "i40e_alloc.h"
#include "i40e_osdep.h"

#include <sys/dtrace.h>

/* ARGSUSED */
i40e_status
i40e_allocate_virt_mem(struct i40e_hw *hw, struct i40e_virt_mem *mem, u32 size)
{
	mem->va = kmem_zalloc(size, KM_SLEEP);
	mem->size = size;
	return (I40E_SUCCESS);
}

/* ARGSUSED */
i40e_status
i40e_free_virt_mem(struct i40e_hw *hw, struct i40e_virt_mem *mem)
{
	if (mem->va != NULL)
		kmem_free(mem->va, mem->size);
	return (I40E_SUCCESS);
}

/* ARGSUSED */
i40e_status
i40e_allocate_dma_mem(struct i40e_hw *hw, struct i40e_dma_mem *mem,
    enum i40e_memory_type type, u64 size, u32 alignment)
{
	int rc;
	i40e_t *i40e = OS_DEP(hw)->ios_i40e;
	dev_info_t *dip = i40e->i40e_dip;
	size_t len;
	ddi_dma_cookie_t cookie;
	uint_t cookie_num;
	ddi_dma_attr_t attr;

	/*
	 * Because we need to honor the specified alignment, we need to
	 * dynamically construct the attributes. We save the alignment for
	 * debugging purposes.
	 */
	bcopy(&i40e->i40e_static_dma_attr, &attr, sizeof (ddi_dma_attr_t));
	attr.dma_attr_align = alignment;
	mem->idm_alignment = alignment;
	rc = ddi_dma_alloc_handle(dip, &i40e->i40e_static_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &mem->idm_dma_handle);
	if (rc != DDI_SUCCESS) {
		mem->idm_dma_handle = NULL;
		i40e_error(i40e, "failed to allocate DMA handle for common "
		    "code: %d", rc);

		/*
		 * Swallow unknown errors and treat them like we do
		 * DDI_DMA_NORESOURCES, in other words, a memory error.
		 */
		if (rc == DDI_DMA_BADATTR)
			return (I40E_ERR_PARAM);
		return (I40E_ERR_NO_MEMORY);
	}

	rc = ddi_dma_mem_alloc(mem->idm_dma_handle, size,
	    &i40e->i40e_buf_acc_attr, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
	    NULL, (caddr_t *)&mem->va, &len, &mem->idm_acc_handle);
	if (rc != DDI_SUCCESS) {
		mem->idm_acc_handle = NULL;
		mem->va = NULL;
		ASSERT(mem->idm_dma_handle != NULL);
		ddi_dma_free_handle(&mem->idm_dma_handle);
		mem->idm_dma_handle = NULL;

		i40e_error(i40e, "failed to allocate %" PRIu64 " bytes of DMA "
		    "memory for common code", size);
		return (I40E_ERR_NO_MEMORY);
	}

	bzero(mem->va, len);

	rc = ddi_dma_addr_bind_handle(mem->idm_dma_handle, NULL, mem->va, len,
	    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
	    &cookie, &cookie_num);
	if (rc != DDI_DMA_MAPPED) {
		mem->pa = NULL;
		ASSERT(mem->idm_acc_handle != NULL);
		ddi_dma_mem_free(&mem->idm_acc_handle);
		mem->idm_acc_handle = NULL;
		mem->va = NULL;
		ASSERT(mem->idm_dma_handle != NULL);
		ddi_dma_free_handle(&mem->idm_dma_handle);
		mem->idm_dma_handle = NULL;

		i40e_error(i40e, "failed to bind %ld byte sized dma region: %d",
		    len, rc);
		switch (rc) {
		case DDI_DMA_INUSE:
			return (I40E_ERR_NOT_READY);
		case DDI_DMA_TOOBIG:
			return (I40E_ERR_INVALID_SIZE);
		case DDI_DMA_NOMAPPING:
		case DDI_DMA_NORESOURCES:
		default:
			return (I40E_ERR_NO_MEMORY);
		}
	}

	ASSERT(cookie_num == 1);
	mem->pa = cookie.dmac_laddress;
	/*
	 * Lint doesn't like this because the common code gives us a uint64_t as
	 * input, but the common code then asks us to assign it to a size_t. So
	 * lint's right, but in this case there isn't much we can do.
	 */
	mem->size = (size_t)size;

	return (I40E_SUCCESS);
}

/* ARGSUSED */
i40e_status
i40e_free_dma_mem(struct i40e_hw *hw, struct i40e_dma_mem *mem)
{
	if (mem->pa != 0) {
		VERIFY(mem->idm_dma_handle != NULL);
		(void) ddi_dma_unbind_handle(mem->idm_dma_handle);
		mem->pa = 0;
		mem->size = 0;
	}

	if (mem->idm_acc_handle != NULL) {
		ddi_dma_mem_free(&mem->idm_acc_handle);
		mem->idm_acc_handle = NULL;
		mem->va = NULL;
	}

	if (mem->idm_dma_handle != NULL) {
		ddi_dma_free_handle(&mem->idm_dma_handle);
		mem->idm_dma_handle = NULL;
	}

	/*
	 * Watch out for sloppiness.
	 */
	ASSERT(mem->pa == 0);
	ASSERT(mem->va == NULL);
	ASSERT(mem->size == 0);
	mem->idm_alignment = UINT32_MAX;

	return (I40E_SUCCESS);
}

/*
 * The common code wants to initialize its 'spinlocks' here, aka adaptive
 * mutexes. At this time these are only used to maintain the adminq's data and
 * as such it will only be used outside of interrupt context and even then,
 * we're not going to actually end up ever doing anything above lock level and
 * up in doing stuff with high level interrupts.
 */
void
i40e_init_spinlock(struct i40e_spinlock *lock)
{
	mutex_init(&lock->ispl_mutex, NULL, MUTEX_DRIVER, NULL);
}

void
i40e_acquire_spinlock(struct i40e_spinlock *lock)
{
	mutex_enter(&lock->ispl_mutex);
}

void
i40e_release_spinlock(struct i40e_spinlock *lock)
{
	mutex_exit(&lock->ispl_mutex);
}

void
i40e_destroy_spinlock(struct i40e_spinlock *lock)
{
	mutex_destroy(&lock->ispl_mutex);
}

boolean_t
i40e_set_hw_bus_info(struct i40e_hw *hw)
{
	uint8_t pcie_id = PCI_CAP_ID_PCI_E;
	uint16_t pcie_cap, value;
	int status;

	/* locate the pci-e capability block */
	status = pci_lcap_locate((OS_DEP(hw))->ios_cfg_handle, pcie_id,
	    &pcie_cap);
	if (status != DDI_SUCCESS) {
		i40e_error(OS_DEP(hw)->ios_i40e, "failed to locate PCIe "
		    "capability block: %d",
		    status);
		return (B_FALSE);
	}

	value = pci_config_get16(OS_DEP(hw)->ios_cfg_handle,
	    pcie_cap + PCIE_LINKSTS);

	i40e_set_pci_config_data(hw, value);

	return (B_TRUE);
}

/* ARGSUSED */
void
i40e_debug(void *hw, u32 mask, char *fmt, ...)
{
	char buf[1024];
	va_list args;

	va_start(args, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, args);
	va_end(args);

	DTRACE_PROBE2(i40e__debug, uint32_t, mask, char *, buf);
}
