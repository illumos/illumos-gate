/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#include "qede.h"
#include <sys/pci.h>
#include <sys/pcie.h>
extern ddi_dma_attr_t qede_gen_buf_dma_attr;
extern struct ddi_device_acc_attr qede_desc_acc_attr;

/*
 * Find the dma_handle corresponding to the tx, rx data structures
 */
int
qede_osal_find_dma_handle_for_block(qede_t *qede, void *addr,
    ddi_dma_handle_t *dma_handle)
{
	qede_phys_mem_entry_t *entry;
	int ret = DDI_FAILURE;

	mutex_enter(&qede->phys_mem_list.lock);
	QEDE_LIST_FOR_EACH_ENTRY(entry,
	    /* LINTED E_BAD_PTR_CAST_ALIGN */
	    &qede->phys_mem_list.head,
	    qede_phys_mem_entry_t,
	    list_entry) {
		if (entry->paddr == addr) {
			*dma_handle = entry->dma_handle;
			ret = DDI_SUCCESS;
			break;
		}
	}

	mutex_exit(&qede->phys_mem_list.lock);

	return (ret);
}

void
qede_osal_dma_sync(struct ecore_dev *edev, void* addr, u32 size, bool is_post)
{
	qede_t *qede = (qede_t *)edev;
	qede_phys_mem_entry_t *entry;
	ddi_dma_handle_t *dma_handle = NULL;
	uint_t type = (is_post == false) ? DDI_DMA_SYNC_FORDEV :
	    DDI_DMA_SYNC_FORKERNEL;

	mutex_enter(&qede->phys_mem_list.lock);

	/* LINTED E_BAD_PTR_CAST_ALIGN */	
	QEDE_LIST_FOR_EACH_ENTRY(entry, &qede->phys_mem_list.head,
	    qede_phys_mem_entry_t, list_entry) {
		if (entry->paddr == addr) {
			dma_handle = &entry->dma_handle;
		}
	}

	if (dma_handle == NULL) {
		qede_print_err("!%s(%d): addr %p not found in list",
		    __func__, qede->instance, addr);
		mutex_exit(&qede->phys_mem_list.lock);
		return;
	} else {
		(void) ddi_dma_sync(*dma_handle,
		    0 /* offset into the mem block */,
		    size, type);
	}

	mutex_exit(&qede->phys_mem_list.lock);
}

void *
qede_osal_zalloc(struct ecore_dev *edev, int flags, size_t size)
{
	qede_t *qede = (qede_t *)edev;
	qede_mem_list_entry_t *new_entry;
	void *buf;

	if ((new_entry = kmem_zalloc(sizeof (qede_mem_list_entry_t), flags))
	    == NULL) {
		qede_print_err("%s(%d): Failed to alloc new list entry",
		    __func__, qede->instance);
		return (NULL);
	}

	if ((buf = kmem_zalloc(size, flags)) == NULL) {
		qede_print_err("%s(%d): Failed to alloc mem, size %d",
		    __func__, qede->instance, size);
		kmem_free(new_entry, sizeof (qede_mem_list_entry_t));
		return (NULL);
	}

	new_entry->size = size;
	new_entry->buf = buf;

	mutex_enter(&qede->mem_list.mem_list_lock);
	QEDE_LIST_ADD(&new_entry->mem_entry, &qede->mem_list.mem_list_head);
	mutex_exit(&qede->mem_list.mem_list_lock);

	return (buf);
}


void *
qede_osal_alloc(struct ecore_dev *edev, int flags, size_t size)
{
	qede_t *qede = (qede_t *)edev;
	qede_mem_list_entry_t *new_entry;
	void *buf;

	if ((new_entry = kmem_zalloc(sizeof (qede_mem_list_entry_t), flags))
	    == NULL) {
		qede_print_err("%s(%d): Failed to alloc new list entry",
		    __func__, qede->instance);
		return (NULL);
	}

	if ((buf = kmem_alloc(size, flags)) == NULL) {
		qede_print_err("%s(%d): Failed to alloc %d bytes",
		    __func__, qede->instance, size);
		kmem_free(new_entry, sizeof (qede_mem_list_t));
		return (NULL);
	}

	new_entry->size = size;
	new_entry->buf = buf;

	mutex_enter(&qede->mem_list.mem_list_lock);
	QEDE_LIST_ADD(&new_entry->mem_entry, &qede->mem_list.mem_list_head);
	mutex_exit(&qede->mem_list.mem_list_lock);

	return (buf);
}

void
qede_osal_free(struct ecore_dev *edev, void *addr)
{
	qede_t *qede = (qede_t *)edev;
	qede_mem_list_entry_t *mem_entry;

	mutex_enter(&qede->mem_list.mem_list_lock);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	QEDE_LIST_FOR_EACH_ENTRY(mem_entry, &qede->mem_list.mem_list_head,
	    qede_mem_list_entry_t, mem_entry) {
		if (mem_entry->buf == addr) {
			QEDE_LIST_REMOVE(&mem_entry->mem_entry, 
			    &qede->mem_list.mem_list_head);
			kmem_free(addr, mem_entry->size);
			kmem_free(mem_entry, sizeof (qede_mem_list_entry_t));
			break;
		}
	}

	mutex_exit(&qede->mem_list.mem_list_lock);
}

/*
 * @VB: What are the alignment requirements here ??
 */
void *
qede_osal_dma_alloc_coherent(struct ecore_dev *edev, dma_addr_t *paddr, 
    size_t size)
{
	qede_t *qede = (qede_t *)edev;
	qede_phys_mem_entry_t *new_entry;
	ddi_dma_handle_t *dma_handle;
	ddi_acc_handle_t *dma_acc_handle;
	ddi_dma_cookie_t cookie;
	int ret;
	caddr_t pbuf;
	unsigned int count;

	memset(&cookie, 0, sizeof (cookie));

	if ((new_entry = 
	    kmem_zalloc(sizeof (qede_phys_mem_entry_t), KM_NOSLEEP)) == NULL) {
		qede_print_err("%s(%d): Failed to alloc new list entry",
		    __func__, qede->instance);
		return (NULL);
	}

	dma_handle = &new_entry->dma_handle;
	dma_acc_handle = &new_entry->dma_acc_handle;

	if ((ret = 
	    ddi_dma_alloc_handle(qede->dip, &qede_gen_buf_dma_attr, 
	    DDI_DMA_DONTWAIT,
	    NULL, dma_handle)) != DDI_SUCCESS) {
		qede_print_err("%s(%d): Failed to alloc dma handle",
		    __func__, qede->instance);
		qede_stacktrace(qede);
		goto free;
	}

	if ((ret = ddi_dma_mem_alloc(*dma_handle, size, &qede_desc_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL, &pbuf, &size, 
	    dma_acc_handle)) != DDI_SUCCESS) {
		qede_print_err("%s(%d): Failed to alloc dma mem %d bytes",
		    __func__, qede->instance, size);
		qede_stacktrace(qede);
		goto free_hdl;
	}

	if ((ret = ddi_dma_addr_bind_handle(*dma_handle, NULL, pbuf, size, 
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &cookie, &count)) != DDI_DMA_MAPPED) {
		qede_print("!%s(%d): failed to bind dma addr to handle,"
		   " ret %d",
		    __func__, qede->instance, ret);
		goto free_dma_mem;
	}

	if (count != 1) {
		qede_print("%s(%d): ncookies = %d for phys addr %p, "
		    "discard dma buffer",
		    __func__, qede->instance, count, &cookie.dmac_laddress);
		goto free_dma_mem;
	}

	new_entry->size = size;
	new_entry->virt_addr = pbuf;

	new_entry->paddr = (void *)cookie.dmac_laddress;

	*paddr = (dma_addr_t)new_entry->paddr;

	mutex_enter(&qede->phys_mem_list.lock);
	QEDE_LIST_ADD(&new_entry->list_entry, &qede->phys_mem_list.head);
	mutex_exit(&qede->phys_mem_list.lock);

	return (new_entry->virt_addr);

free_dma_mem:
	ddi_dma_mem_free(dma_acc_handle);
free_hdl:
	ddi_dma_free_handle(dma_handle);
free:
	kmem_free(new_entry, sizeof (qede_phys_mem_entry_t));
	return (NULL);
}

void 
qede_osal_dma_free_coherent(struct ecore_dev *edev, void *vaddr,
    dma_addr_t paddr, size_t size)
{
	qede_t *qede = (qede_t *)edev;
	qede_phys_mem_entry_t *entry;

	mutex_enter(&qede->phys_mem_list.lock);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	QEDE_LIST_FOR_EACH_ENTRY(entry, &qede->phys_mem_list.head,
	    qede_phys_mem_entry_t, list_entry) {
		if (entry->virt_addr == vaddr) {
			QEDE_LIST_REMOVE(&entry->list_entry, 
			    &qede->phys_mem_list.head);
			ddi_dma_unbind_handle(entry->dma_handle);
			ddi_dma_mem_free(&entry->dma_acc_handle);
			ddi_dma_free_handle(&entry->dma_handle);
			kmem_free(entry, sizeof (qede_phys_mem_entry_t));
			break;
		}
	}

	mutex_exit(&qede->phys_mem_list.lock);
}

static int 
qede_get_port_type(uint32_t media_type)
{
        uint32_t port_type;

        switch (media_type) {
        case MEDIA_SFPP_10G_FIBER:
        case MEDIA_SFP_1G_FIBER:
        case MEDIA_XFP_FIBER:
        case MEDIA_KR:
                port_type = GLDM_FIBER;
                break;
        case MEDIA_DA_TWINAX:
                port_type = GLDM_BNC; /* Check? */
                break;
        case MEDIA_BASE_T:
                port_type = GLDM_TP;
                break;
        case MEDIA_NOT_PRESENT:
        case MEDIA_UNSPECIFIED:
        default:
                port_type = GLDM_UNKNOWN;
                break;
        }
        return (port_type);
}

void
qede_get_link_info(struct ecore_hwfn *hwfn, struct qede_link_cfg *lnkCfg)
{
        struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
        qede_t *qede = (qede_t *)(void *)edev;
        uint32_t media_type;
        struct ecore_mcp_link_state lnk_state;
        struct ecore_mcp_link_params lnk_params;
        struct ecore_mcp_link_capabilities lnk_caps;

        ecore_mcp_get_media_type(edev, &media_type);
        lnkCfg->port = qede_get_port_type(media_type);

        memcpy(&lnk_state, ecore_mcp_get_link_state(hwfn), 
	    sizeof (lnk_state));
        memcpy(&lnk_params, ecore_mcp_get_link_params(hwfn), 
	    sizeof (lnk_params));
        memcpy(&lnk_caps, ecore_mcp_get_link_capabilities(hwfn), 
	    sizeof (lnk_caps));

	if (lnk_state.link_up) {
		lnkCfg->link_up = B_TRUE;
		lnkCfg->speed = lnk_state.speed;
		lnkCfg->duplex = DUPLEX_FULL;
	}

	if (lnk_params.speed.autoneg) {
		lnkCfg->supp_capab.autoneg = B_TRUE;
		lnkCfg->adv_capab.autoneg = B_TRUE;
	}
	if (lnk_params.speed.autoneg || 
		(lnk_params.pause.forced_rx && lnk_params.pause.forced_tx)) {
		lnkCfg->supp_capab.asym_pause = B_TRUE;
		lnkCfg->adv_capab.asym_pause = B_TRUE;
	}
	if (lnk_params.speed.autoneg ||
		lnk_params.pause.forced_rx || lnk_params.pause.forced_tx) {
		lnkCfg->supp_capab.pause = B_TRUE;
		lnkCfg->adv_capab.pause = B_TRUE;
	}

	if (lnk_params.speed.advertised_speeds & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_10G) {
		lnkCfg->adv_capab.param_10000fdx = B_TRUE;
	}
	if(lnk_params.speed.advertised_speeds & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_25G) {
                lnkCfg->adv_capab.param_25000fdx = B_TRUE;
	}
	if (lnk_params.speed.advertised_speeds & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_40G) {
		lnkCfg->adv_capab.param_40000fdx = B_TRUE;
	}
	if (lnk_params.speed.advertised_speeds & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_50G) {
		lnkCfg->adv_capab.param_50000fdx = B_TRUE;
	}
	if (lnk_params.speed.advertised_speeds & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_BB_100G) {
		lnkCfg->adv_capab.param_100000fdx = B_TRUE;
	}
	if (lnk_params.speed.advertised_speeds & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_1G) {
		lnkCfg->adv_capab.param_1000fdx = B_TRUE;
		lnkCfg->adv_capab.param_1000hdx = B_TRUE;
	}

	lnkCfg->autoneg = lnk_params.speed.autoneg;

	if (lnk_caps.speed_capabilities & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_10G) {
		lnkCfg->supp_capab.param_10000fdx = B_TRUE;
	}
	if(lnk_caps.speed_capabilities & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_25G) {
                lnkCfg->supp_capab.param_25000fdx = B_TRUE;
	}
	if (lnk_caps.speed_capabilities & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_40G) {
		lnkCfg->supp_capab.param_40000fdx = B_TRUE;
	}
	if (lnk_caps.speed_capabilities & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_50G) {
		lnkCfg->supp_capab.param_50000fdx = B_TRUE;
	}
	if (lnk_caps.speed_capabilities & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_BB_100G) {
		lnkCfg->supp_capab.param_100000fdx = B_TRUE;
	}
	if (lnk_caps.speed_capabilities & 
	    NVM_CFG1_PORT_DRV_SPEED_CAPABILITY_MASK_1G) {
		lnkCfg->supp_capab.param_1000fdx = B_TRUE;
		lnkCfg->supp_capab.param_1000hdx = B_TRUE;
	}
	
	if (lnk_params.pause.autoneg) {
                lnkCfg->pause_cfg |= QEDE_LINK_PAUSE_AUTONEG_ENABLE;
	}
        if (lnk_params.pause.forced_rx) {
                lnkCfg->pause_cfg |= QEDE_LINK_PAUSE_RX_ENABLE;
	}
        if (lnk_params.pause.forced_tx) {
                lnkCfg->pause_cfg |= QEDE_LINK_PAUSE_TX_ENABLE;
	}
	
	
	if(lnk_state.partner_adv_speed &
		ECORE_LINK_PARTNER_SPEED_1G_HD) {
		lnkCfg->rem_capab.param_1000hdx = B_TRUE;
	}
	if(lnk_state.partner_adv_speed &
		ECORE_LINK_PARTNER_SPEED_1G_FD) {
		lnkCfg->rem_capab.param_1000fdx = B_TRUE;
	}
	if(lnk_state.partner_adv_speed &
		ECORE_LINK_PARTNER_SPEED_10G) {
		lnkCfg->rem_capab.param_10000fdx = B_TRUE;
	}
	if(lnk_state.partner_adv_speed &
		ECORE_LINK_PARTNER_SPEED_40G) {
		lnkCfg->rem_capab.param_40000fdx = B_TRUE;
	}
	if(lnk_state.partner_adv_speed &
		ECORE_LINK_PARTNER_SPEED_50G) {
		lnkCfg->rem_capab.param_50000fdx = B_TRUE;
	}
	if(lnk_state.partner_adv_speed &
		ECORE_LINK_PARTNER_SPEED_100G) {
		lnkCfg->rem_capab.param_100000fdx = B_TRUE;
	}
	
	if(lnk_state.an_complete) {
	    lnkCfg->rem_capab.autoneg = B_TRUE;
	}
	
	if(lnk_state.partner_adv_pause) {
	    lnkCfg->rem_capab.pause = B_TRUE;
	}
	if(lnk_state.partner_adv_pause == 
	    ECORE_LINK_PARTNER_ASYMMETRIC_PAUSE ||
	    lnk_state.partner_adv_pause == ECORE_LINK_PARTNER_BOTH_PAUSE) {
	    lnkCfg->rem_capab.asym_pause = B_TRUE;
	}
}

void
qede_osal_link_update(struct ecore_hwfn *hwfn)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;
	struct qede_link_cfg link_cfg;	
	
        memset(&link_cfg, 0 , sizeof (struct qede_link_cfg));	
	qede_get_link_info(hwfn, &link_cfg);	
	
	if (link_cfg.duplex == DUPLEX_FULL) {
		qede->props.link_duplex = DUPLEX_FULL;
	} else {
		qede->props.link_duplex = DUPLEX_HALF;
	}

	if (!link_cfg.link_up) {
		qede_print("!%s(%d): Link marked down",
		    __func__, qede->instance);
		qede->params.link_state = 0;
	 	qede->props.link_duplex = B_FALSE;
		qede->props.link_speed = 0;
		qede->props.tx_pause = B_FALSE;
		qede->props.rx_pause = B_FALSE;
		qede->props.uptime = 0;
		mac_link_update(qede->mac_handle, LINK_STATE_DOWN);
	} else if (link_cfg.link_up) {
		qede_print("!%s(%d): Link marked up",
		    __func__, qede->instance);
		qede->params.link_state = 1;
		qede->props.link_speed = link_cfg.speed;
		qede->props.link_duplex = link_cfg.duplex;
		qede->props.tx_pause = (link_cfg.pause_cfg & 
		    QEDE_LINK_PAUSE_TX_ENABLE) ? B_TRUE : B_FALSE;
		qede->props.rx_pause = (link_cfg.pause_cfg & 
		    QEDE_LINK_PAUSE_RX_ENABLE) ? B_TRUE : B_FALSE;
		qede->props.uptime = ddi_get_time();
		mac_link_update(qede->mac_handle, LINK_STATE_UP);
	}
}

unsigned long 
log2_align(unsigned long n)
{
	unsigned long ret = n ? 1 : 0;
	unsigned long _n  = n >> 1;
	
	while (_n) {
		_n >>= 1;
		ret <<= 1;
	}

	if (ret < n) {
		ret <<= 1;
	}

	return (ret);
}

u32
LOG2(u32 v)
{
	u32 r = 0;
	while (v >>= 1) {
		r++;
	}
	return (r);
}

int
/* LINTED E_FUNC_ARG_UNUSED */
qede_osal_pci_find_ext_capab(struct ecore_dev *edev, u16 pcie_id)
{
	int offset = 0;

	return (offset);
}

void
qede_osal_pci_write32(struct ecore_hwfn *hwfn, u32 offset, u32 val)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;
	u64 addr = qede->pci_bar0_base;

	addr += offset;

	ddi_put32(qede->regs_handle, (u32 *)addr, val);
}

void
qede_osal_pci_write16(struct ecore_hwfn *hwfn, u32 offset, u16 val)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;
	u64 addr = qede->pci_bar0_base;

	addr += offset;

	ddi_put16(qede->regs_handle, (u16 *)addr, val);
}

u32
qede_osal_pci_read32(struct ecore_hwfn *hwfn, u32 offset)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;
	u32 val = 0;
	u64 addr = qede->pci_bar0_base;

	addr += offset;

	val = ddi_get32(qede->regs_handle, (u32 *)addr);

	return (val);
}

void
qede_osal_pci_bar2_write32(struct ecore_hwfn *hwfn, u32 offset, u32 val)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;
	u64 addr = qede->pci_bar2_base;

	addr += offset;
	ddi_put32(qede->doorbell_handle, (u32 *)addr, val);
}

u32
qede_osal_direct_reg_read32(struct ecore_hwfn *hwfn, void *addr)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;

	return (ddi_get32(qede->regs_handle, (u32 *)addr));
}

void
qede_osal_direct_reg_write32(struct ecore_hwfn *hwfn, void *addr, u32 value)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;
	
	ddi_put32(qede->regs_handle, (u32 *)addr, value);
}

u32 *
qede_osal_reg_addr(struct ecore_hwfn *hwfn, u32 addr)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;

	return ((u32 *)(qede->pci_bar0_base + addr));
}

void
qede_osal_pci_read_config_byte(struct ecore_dev *edev, u32 addr, u8 *val)
{

	qede_t *qede = (qede_t *)edev;

	*val = pci_config_get8(qede->pci_cfg_handle, (off_t)addr);
}

void
qede_osal_pci_read_config_word(struct ecore_dev *edev, u32 addr, u16 *val)
{
	qede_t *qede = (qede_t *)edev;

	*val = pci_config_get16(qede->pci_cfg_handle, (off_t)addr);
}

void
qede_osal_pci_read_config_dword(struct ecore_dev *edev, u32 addr, u32 *val)
{
	qede_t *qede = (qede_t *)edev;

	*val = pci_config_get32(qede->pci_cfg_handle, (off_t)addr);
	
}

void 
qede_print(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vcmn_err(CE_NOTE, format, ap);
	va_end(ap);
}

void 
qede_print_err(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vcmn_err(CE_WARN, format, ap);
	va_end(ap);
}

/*
 * Check if any mem/dma entries are left behind
 * after unloading the ecore. If found
 * then make sure they are freed
 */
u32
qede_osal_cleanup(qede_t *qede)
{
	qede_mem_list_entry_t *entry = NULL;
	qede_mem_list_entry_t *temp = NULL;
	qede_phys_mem_entry_t *entry_phys;
	qede_phys_mem_entry_t *temp_phys;

	/* 
	 * Check for misplaced mem. blocks(if any)
	 */
	mutex_enter(&qede->mem_list.mem_list_lock);

	if (!QEDE_LIST_EMPTY(&qede->mem_list.mem_list_head)) {
		/*
		 * Something went wrong either in ecore
		 * or the osal mem management routines
		 * and the mem entry was not freed
		 */
		qede_print_err("!%s(%d): Mem entries left behind",
		    __func__, qede->instance);

		QEDE_LIST_FOR_EACH_ENTRY_SAFE(entry,
		    temp,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    &qede->mem_list.mem_list_head,
		    mem_entry,
		    qede_mem_list_entry_t) {
			qede_print("!%s(%d): Cleaning-up entry %p",
			    __func__, qede->instance, entry);
			QEDE_LIST_REMOVE(&entry->mem_entry,
			    &qede->mem_list.mem_list_head);
			if (entry->buf) {
				kmem_free(entry->buf, entry->size);
				kmem_free(entry,
				    sizeof (qede_mem_list_entry_t));
			}
		}
	} 

	mutex_exit(&qede->mem_list.mem_list_lock);

	/*
	 * Check for misplaced dma blocks (if any)
	 */
	mutex_enter(&qede->phys_mem_list.lock);
	
	if (!QEDE_LIST_EMPTY(&qede->phys_mem_list.head)) {
		qede_print("!%s(%d): Dma entries left behind",
		    __func__, qede->instance);

		QEDE_LIST_FOR_EACH_ENTRY_SAFE(entry_phys,
		    temp_phys,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    &qede->phys_mem_list.head,
		    list_entry,
		    qede_phys_mem_entry_t) {
			qede_print("!%s(%d): Cleaning-up entry %p",
			    __func__, qede->instance, entry_phys);
			QEDE_LIST_REMOVE(&entry_phys->list_entry,
			    &qede->phys_mem_list.head);

			if (entry_phys->virt_addr) {
				ddi_dma_unbind_handle(entry_phys->dma_handle);
				ddi_dma_mem_free(&entry_phys->dma_acc_handle);
				ddi_dma_free_handle(&entry_phys->dma_handle);
				kmem_free(entry_phys,
				    sizeof (qede_phys_mem_entry_t));
			}
		}
	}

	mutex_exit(&qede->phys_mem_list.lock);

	return (0);
}


void
qede_osal_recovery_handler(struct ecore_hwfn *hwfn)
{
	struct ecore_dev *edev = (struct ecore_dev *)hwfn->p_dev;
	qede_t *qede = (qede_t *)(void *)edev;

	 cmn_err(CE_WARN, "!%s(%d):Not implemented !",
            __func__, qede->instance);

}


enum _ecore_status_t 
qede_osal_iov_vf_acquire(struct ecore_hwfn *p_hwfn, int vf_id)
{
	return (ECORE_SUCCESS);
}


void 
qede_osal_pci_write_config_word(struct ecore_dev *dev, u32 addr, u16 pcie_id)
{
	qede_t *qede = (qede_t *)dev;
	ddi_acc_handle_t pci_cfg_handle = qede->pci_cfg_handle;
	
	pci_config_put16(pci_cfg_handle, (off_t)addr, pcie_id);
}

void * 
qede_osal_valloc(struct ecore_dev *dev, u32 size)
{
	void *ptr = 0;

	return (ptr);
}

void 
qede_osal_vfree(struct ecore_dev *dev, void* mem)
{
}

int 
/* LINTED E_FUNC_ARG_UNUSED */
qede_osal_pci_find_capability(struct ecore_dev *dev, u16 pcie_id)
{
	return 1;
}

void 
qede_osal_poll_mode_dpc(struct ecore_hwfn *p_hwfn)
{
}

int 
/* LINTED E_FUNC_ARG_UNUSED */
qede_osal_bitmap_weight(unsigned long *bitmap, uint32_t nbits)
{
	uint32_t count = 0, temp = *bitmap;
	return count;
}

void 
/* LINTED E_FUNC_ARG_UNUSED */
qede_osal_mfw_tlv_req(struct ecore_hwfn *p_hwfn)
{
}

u32 
/* LINTED E_FUNC_ARG_UNUSED */
qede_osal_crc32(u32 crc, u8 *buf, u64 length)
{
	return 1;
}

void 
/* LINTED E_FUNC_ARG_UNUSED */
qede_osal_hw_info_change(struct ecore_hwfn *p_hwfn, int change)
{
}

void 
/* LINTED E_FUNC_ARG_UNUSED */
OSAL_CRC8_POPULATE(u8 * cdu_crc8_table, u8 polynomial)
{
}
u8 
/* LINTED E_FUNC_ARG_UNUSED */
OSAL_CRC8(u8 * cdu_crc8_table, u8 * data_to_crc, int data_to_crc_len, 
    u8 init_value)
{
	return (0); 
}
void 
/* LINTED E_FUNC_ARG_UNUSED */
OSAL_DPC_SYNC(struct ecore_hwfn *p_hwfn)
{
	//Do nothing right now.
}
