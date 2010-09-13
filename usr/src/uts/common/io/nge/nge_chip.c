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

#include "nge.h"
static uint32_t	nge_watchdog_count	= 1 << 5;
static uint32_t	nge_watchdog_check	= 1 << 3;
extern boolean_t nge_enable_msi;
static void nge_sync_mac_modes(nge_t *);

#undef NGE_DBG
#define	NGE_DBG		NGE_DBG_CHIP

/*
 * Operating register get/set access routines
 */
uint8_t nge_reg_get8(nge_t *ngep, nge_regno_t regno);
#pragma	inline(nge_reg_get8)

uint8_t
nge_reg_get8(nge_t *ngep, nge_regno_t regno)
{
	NGE_TRACE(("nge_reg_get8($%p, 0x%lx)", (void *)ngep, regno));

	return (ddi_get8(ngep->io_handle, PIO_ADDR(ngep, regno)));
}

void nge_reg_put8(nge_t *ngep, nge_regno_t regno, uint8_t data);
#pragma	inline(nge_reg_put8)

void
nge_reg_put8(nge_t *ngep, nge_regno_t regno, uint8_t data)
{
	NGE_TRACE(("nge_reg_put8($%p, 0x%lx, 0x%x)",
	    (void *)ngep, regno, data));
	ddi_put8(ngep->io_handle, PIO_ADDR(ngep, regno), data);

}

uint16_t nge_reg_get16(nge_t *ngep, nge_regno_t regno);
#pragma	inline(nge_reg_get16)

uint16_t
nge_reg_get16(nge_t *ngep, nge_regno_t regno)
{
	NGE_TRACE(("nge_reg_get16($%p, 0x%lx)", (void *)ngep, regno));
	return (ddi_get16(ngep->io_handle, PIO_ADDR(ngep, regno)));
}

void nge_reg_put16(nge_t *ngep, nge_regno_t regno, uint16_t data);
#pragma	inline(nge_reg_put16)

void
nge_reg_put16(nge_t *ngep, nge_regno_t regno, uint16_t data)
{
	NGE_TRACE(("nge_reg_put16($%p, 0x%lx, 0x%x)",
	    (void *)ngep, regno, data));
	ddi_put16(ngep->io_handle, PIO_ADDR(ngep, regno), data);

}

uint32_t nge_reg_get32(nge_t *ngep, nge_regno_t regno);
#pragma	inline(nge_reg_get32)

uint32_t
nge_reg_get32(nge_t *ngep, nge_regno_t regno)
{
	NGE_TRACE(("nge_reg_get32($%p, 0x%lx)", (void *)ngep, regno));
	return (ddi_get32(ngep->io_handle, PIO_ADDR(ngep, regno)));
}

void nge_reg_put32(nge_t *ngep, nge_regno_t regno, uint32_t data);
#pragma	inline(nge_reg_put32)

void
nge_reg_put32(nge_t *ngep, nge_regno_t regno, uint32_t data)
{
	NGE_TRACE(("nge_reg_put32($%p, 0x%lx, 0x%x)",
	    (void *)ngep, regno, data));
	ddi_put32(ngep->io_handle, PIO_ADDR(ngep, regno), data);

}


static int nge_chip_peek_cfg(nge_t *ngep, nge_peekpoke_t *ppd);
#pragma	no_inline(nge_chip_peek_cfg)

static int
nge_chip_peek_cfg(nge_t *ngep, nge_peekpoke_t *ppd)
{
	int err;
	uint64_t regval;
	uint64_t regno;

	NGE_TRACE(("nge_chip_peek_cfg($%p, $%p)",
	    (void *)ngep, (void *)ppd));

	err = DDI_SUCCESS;
	regno = ppd->pp_acc_offset;

	switch (ppd->pp_acc_size) {
	case 1:
		regval = pci_config_get8(ngep->cfg_handle, regno);
		break;

	case 2:
		regval = pci_config_get16(ngep->cfg_handle, regno);
		break;

	case 4:
		regval = pci_config_get32(ngep->cfg_handle, regno);
		break;

	case 8:
		regval = pci_config_get64(ngep->cfg_handle, regno);
		break;
	}
	ppd->pp_acc_data = regval;
	return (err);
}

static int nge_chip_poke_cfg(nge_t *ngep, nge_peekpoke_t *ppd);

static int
nge_chip_poke_cfg(nge_t *ngep, nge_peekpoke_t *ppd)
{
	int err;
	uint64_t regval;
	uint64_t regno;

	NGE_TRACE(("nge_chip_poke_cfg($%p, $%p)",
	    (void *)ngep, (void *)ppd));

	err = DDI_SUCCESS;
	regno = ppd->pp_acc_offset;
	regval = ppd->pp_acc_data;

	switch (ppd->pp_acc_size) {
	case 1:
		pci_config_put8(ngep->cfg_handle, regno, regval);
		break;

	case 2:
		pci_config_put16(ngep->cfg_handle, regno, regval);
		break;

	case 4:
		pci_config_put32(ngep->cfg_handle, regno, regval);
		break;

	case 8:
		pci_config_put64(ngep->cfg_handle, regno, regval);
		break;
	}

	return (err);

}

static int nge_chip_peek_reg(nge_t *ngep, nge_peekpoke_t *ppd);

static int
nge_chip_peek_reg(nge_t *ngep, nge_peekpoke_t *ppd)
{
	int err;
	uint64_t regval;
	void *regaddr;

	NGE_TRACE(("nge_chip_peek_reg($%p, $%p)",
	    (void *)ngep, (void *)ppd));

	err = DDI_SUCCESS;
	regaddr = PIO_ADDR(ngep, ppd->pp_acc_offset);

	switch (ppd->pp_acc_size) {
	case 1:
		regval = ddi_get8(ngep->io_handle, regaddr);
	break;

	case 2:
		regval = ddi_get16(ngep->io_handle, regaddr);
	break;

	case 4:
		regval = ddi_get32(ngep->io_handle, regaddr);
	break;

	case 8:
		regval = ddi_get64(ngep->io_handle, regaddr);
	break;

	default:
		regval = 0x0ull;
	break;
	}
	ppd->pp_acc_data = regval;
	return (err);
}

static int nge_chip_poke_reg(nge_t *ngep, nge_peekpoke_t *ppd);

static int
nge_chip_poke_reg(nge_t *ngep, nge_peekpoke_t *ppd)
{
	int err;
	uint64_t regval;
	void *regaddr;

	NGE_TRACE(("nge_chip_poke_reg($%p, $%p)",
	    (void *)ngep, (void *)ppd));

	err = DDI_SUCCESS;
	regaddr = PIO_ADDR(ngep, ppd->pp_acc_offset);
	regval = ppd->pp_acc_data;

	switch (ppd->pp_acc_size) {
	case 1:
		ddi_put8(ngep->io_handle, regaddr, regval);
		break;

	case 2:
		ddi_put16(ngep->io_handle, regaddr, regval);
		break;

	case 4:
		ddi_put32(ngep->io_handle, regaddr, regval);
		break;

	case 8:
		ddi_put64(ngep->io_handle, regaddr, regval);
		break;
	}
	return (err);
}

static int nge_chip_peek_mii(nge_t *ngep, nge_peekpoke_t *ppd);
#pragma	no_inline(nge_chip_peek_mii)

static int
nge_chip_peek_mii(nge_t *ngep, nge_peekpoke_t *ppd)
{
	int err;

	err = DDI_SUCCESS;
	ppd->pp_acc_data = nge_mii_get16(ngep, ppd->pp_acc_offset/2);
	return (err);
}

static int nge_chip_poke_mii(nge_t *ngep, nge_peekpoke_t *ppd);
#pragma	no_inline(nge_chip_poke_mii)

static int
nge_chip_poke_mii(nge_t *ngep, nge_peekpoke_t *ppd)
{
	int err;
	err = DDI_SUCCESS;
	nge_mii_put16(ngep, ppd->pp_acc_offset/2, ppd->pp_acc_data);
	return (err);
}

/*
 * Basic SEEPROM get/set access routine
 *
 * This uses the chip's SEEPROM auto-access method, controlled by the
 * Serial EEPROM Address/Data Registers at 0x504h, so the CPU
 * doesn't have to fiddle with the individual bits.
 *
 * The caller should hold <genlock> and *also* have already acquired
 * the right to access the SEEPROM.
 *
 * Return value:
 *	0 on success,
 *	ENODATA on access timeout (maybe retryable: device may just be busy)
 *	EPROTO on other h/w or s/w errors.
 *
 * <*dp> is an input to a SEEPROM_ACCESS_WRITE operation, or an output
 * from a (successful) SEEPROM_ACCESS_READ.
 */

static int
nge_seeprom_access(nge_t *ngep, uint32_t cmd, nge_regno_t addr, uint16_t *dp)
{
	uint32_t tries;
	nge_ep_cmd cmd_reg;
	nge_ep_data data_reg;

	NGE_TRACE(("nge_seeprom_access($%p, %d, %x, $%p)",
	    (void *)ngep, cmd, addr, (void *)dp));

	ASSERT(mutex_owned(ngep->genlock));

	/*
	 * Check there's no command in progress.
	 *
	 * Note: this *shouldn't* ever find that there is a command
	 * in progress, because we already hold the <genlock> mutex.
	 * Also, to ensure we don't have a conflict with the chip's
	 * internal firmware or a process accessing the same (shared)
	 * So this is just a final consistency check: we shouldn't
	 * see EITHER the START bit (command started but not complete)
	 * OR the COMPLETE bit (command completed but not cleared).
	 */
	cmd_reg.cmd_val = nge_reg_get32(ngep, NGE_EP_CMD);
	for (tries = 0; tries < 30; tries++) {
		if (cmd_reg.cmd_bits.sts == SEEPROM_READY)
			break;
		drv_usecwait(10);
		cmd_reg.cmd_val = nge_reg_get32(ngep, NGE_EP_CMD);
	}

	/*
	 * This should not happen. If so, we have to restart eeprom
	 *  state machine
	 */
	if (tries == 30) {
		cmd_reg.cmd_bits.sts = SEEPROM_READY;
		nge_reg_put32(ngep, NGE_EP_CMD, cmd_reg.cmd_val);
		drv_usecwait(10);
		/*
		 * Polling the status bit to make assure the eeprom is ready
		 */
		cmd_reg.cmd_val = nge_reg_get32(ngep, NGE_EP_CMD);
		for (tries = 0; tries < 30; tries++) {
			if (cmd_reg.cmd_bits.sts == SEEPROM_READY)
				break;
			drv_usecwait(10);
			cmd_reg.cmd_val = nge_reg_get32(ngep, NGE_EP_CMD);
		}
	}

	/*
	 * Assemble the command ...
	 */
	cmd_reg.cmd_bits.addr = (uint32_t)addr;
	cmd_reg.cmd_bits.cmd = cmd;
	cmd_reg.cmd_bits.sts = 0;

	nge_reg_put32(ngep, NGE_EP_CMD, cmd_reg.cmd_val);

	/*
	 * Polling whether the access is successful.
	 *
	 */
	cmd_reg.cmd_val = nge_reg_get32(ngep, NGE_EP_CMD);
	for (tries = 0; tries < 30; tries++) {
		if (cmd_reg.cmd_bits.sts == SEEPROM_READY)
			break;
		drv_usecwait(10);
		cmd_reg.cmd_val = nge_reg_get32(ngep, NGE_EP_CMD);
	}

	if (tries == 30) {
		nge_report(ngep, NGE_HW_ROM);
		return (DDI_FAILURE);
	}
	switch (cmd) {
	default:
	case SEEPROM_CMD_WRITE_ENABLE:
	case SEEPROM_CMD_ERASE:
	case SEEPROM_CMD_ERALSE_ALL:
	case SEEPROM_CMD_WRITE_DIS:
	break;

	case SEEPROM_CMD_READ:
		data_reg.data_val = nge_reg_get32(ngep, NGE_EP_DATA);
		*dp = data_reg.data_bits.data;
	break;

	case SEEPROM_CMD_WRITE:
		data_reg.data_val = nge_reg_get32(ngep, NGE_EP_DATA);
		data_reg.data_bits.data = *dp;
		nge_reg_put32(ngep, NGE_EP_DATA, data_reg.data_val);
	break;
	}

	return (DDI_SUCCESS);
}


static int
nge_chip_peek_seeprom(nge_t *ngep, nge_peekpoke_t *ppd)
{
	uint16_t data;
	int err;

	err = nge_seeprom_access(ngep, SEEPROM_CMD_READ,
	    ppd->pp_acc_offset, &data);
	ppd->pp_acc_data =  data;
	return (err);
}

static int
nge_chip_poke_seeprom(nge_t *ngep, nge_peekpoke_t *ppd)
{
	uint16_t data;
	int err;

	data = ppd->pp_acc_data;
	err = nge_seeprom_access(ngep, SEEPROM_CMD_WRITE,
	    ppd->pp_acc_offset, &data);
	return (err);
}

void
nge_init_dev_spec_param(nge_t *ngep)
{
	nge_dev_spec_param_t	*dev_param_p;
	chip_info_t	*infop;

	dev_param_p = &ngep->dev_spec_param;
	infop = (chip_info_t *)&ngep->chipinfo;

	switch (infop->device) {
	case DEVICE_ID_NF3_E6:
	case DEVICE_ID_NF3_DF:
	case DEVICE_ID_MCP04_37:
	case DEVICE_ID_MCP04_38:
		dev_param_p->msi = B_FALSE;
		dev_param_p->msi_x = B_FALSE;
		dev_param_p->vlan = B_FALSE;
		dev_param_p->advanced_pm = B_FALSE;
		dev_param_p->mac_addr_order = B_FALSE;
		dev_param_p->tx_pause_frame = B_FALSE;
		dev_param_p->rx_pause_frame = B_FALSE;
		dev_param_p->jumbo = B_FALSE;
		dev_param_p->tx_rx_64byte = B_FALSE;
		dev_param_p->rx_hw_checksum = B_FALSE;
		dev_param_p->tx_hw_checksum = 0;
		dev_param_p->desc_type = DESC_OFFLOAD;
		dev_param_p->rx_desc_num = NGE_RECV_SLOTS_DESC_1024;
		dev_param_p->tx_desc_num = NGE_SEND_SLOTS_DESC_1024;
		dev_param_p->nge_split = NGE_SPLIT_32;
		break;

	case DEVICE_ID_CK804_56:
	case DEVICE_ID_CK804_57:
		dev_param_p->msi = B_TRUE;
		dev_param_p->msi_x = B_TRUE;
		dev_param_p->vlan = B_FALSE;
		dev_param_p->advanced_pm = B_FALSE;
		dev_param_p->mac_addr_order = B_FALSE;
		dev_param_p->tx_pause_frame = B_FALSE;
		dev_param_p->rx_pause_frame = B_TRUE;
		dev_param_p->jumbo = B_TRUE;
		dev_param_p->tx_rx_64byte = B_FALSE;
		dev_param_p->rx_hw_checksum = B_TRUE;
		dev_param_p->tx_hw_checksum = HCKSUM_IPHDRCKSUM;
		dev_param_p->desc_type = DESC_HOT;
		dev_param_p->rx_desc_num = NGE_RECV_SLOTS_DESC_3072;
		dev_param_p->tx_desc_num = NGE_SEND_SLOTS_DESC_3072;
		dev_param_p->nge_split = NGE_SPLIT_96;
		break;

	case DEVICE_ID_MCP51_268:
	case DEVICE_ID_MCP51_269:
		dev_param_p->msi = B_FALSE;
		dev_param_p->msi_x = B_FALSE;
		dev_param_p->vlan = B_FALSE;
		dev_param_p->advanced_pm = B_TRUE;
		dev_param_p->mac_addr_order = B_FALSE;
		dev_param_p->tx_pause_frame = B_FALSE;
		dev_param_p->rx_pause_frame = B_FALSE;
		dev_param_p->jumbo = B_FALSE;
		dev_param_p->tx_rx_64byte = B_TRUE;
		dev_param_p->rx_hw_checksum = B_FALSE;
		dev_param_p->tx_hw_checksum = 0;
		dev_param_p->desc_type = DESC_OFFLOAD;
		dev_param_p->rx_desc_num = NGE_RECV_SLOTS_DESC_1024;
		dev_param_p->tx_desc_num = NGE_SEND_SLOTS_DESC_1024;
		dev_param_p->nge_split = NGE_SPLIT_32;
		break;

	case DEVICE_ID_MCP55_372:
	case DEVICE_ID_MCP55_373:
		dev_param_p->msi = B_TRUE;
		dev_param_p->msi_x = B_TRUE;
		dev_param_p->vlan = B_TRUE;
		dev_param_p->advanced_pm = B_TRUE;
		dev_param_p->mac_addr_order = B_FALSE;
		dev_param_p->tx_pause_frame = B_TRUE;
		dev_param_p->rx_pause_frame = B_TRUE;
		dev_param_p->jumbo = B_TRUE;
		dev_param_p->tx_rx_64byte = B_TRUE;
		dev_param_p->rx_hw_checksum = B_TRUE;
		dev_param_p->tx_hw_checksum = HCKSUM_IPHDRCKSUM;
		dev_param_p->desc_type = DESC_HOT;
		dev_param_p->rx_desc_num = NGE_RECV_SLOTS_DESC_3072;
		dev_param_p->tx_desc_num = NGE_SEND_SLOTS_DESC_3072;
		dev_param_p->nge_split = NGE_SPLIT_96;
		break;

	case DEVICE_ID_MCP61_3EE:
	case DEVICE_ID_MCP61_3EF:
		dev_param_p->msi = B_FALSE;
		dev_param_p->msi_x = B_FALSE;
		dev_param_p->vlan = B_FALSE;
		dev_param_p->advanced_pm = B_TRUE;
		dev_param_p->mac_addr_order = B_TRUE;
		dev_param_p->tx_pause_frame = B_FALSE;
		dev_param_p->rx_pause_frame = B_FALSE;
		dev_param_p->jumbo = B_FALSE;
		dev_param_p->tx_rx_64byte = B_TRUE;
		dev_param_p->rx_hw_checksum = B_FALSE;
		dev_param_p->tx_hw_checksum = 0;
		dev_param_p->desc_type = DESC_OFFLOAD;
		dev_param_p->rx_desc_num = NGE_RECV_SLOTS_DESC_1024;
		dev_param_p->tx_desc_num = NGE_SEND_SLOTS_DESC_1024;
		dev_param_p->nge_split = NGE_SPLIT_32;
		break;

	case DEVICE_ID_MCP77_760:
	case DEVICE_ID_MCP79_AB0:
		dev_param_p->msi = B_FALSE;
		dev_param_p->msi_x = B_FALSE;
		dev_param_p->vlan = B_FALSE;
		dev_param_p->advanced_pm = B_TRUE;
		dev_param_p->mac_addr_order = B_TRUE;
		dev_param_p->tx_pause_frame = B_FALSE;
		dev_param_p->rx_pause_frame = B_FALSE;
		dev_param_p->jumbo = B_FALSE;
		dev_param_p->tx_rx_64byte = B_TRUE;
		dev_param_p->rx_hw_checksum = B_FALSE;
		dev_param_p->tx_hw_checksum = 0;
		dev_param_p->desc_type = DESC_HOT;
		dev_param_p->rx_desc_num = NGE_RECV_SLOTS_DESC_1024;
		dev_param_p->tx_desc_num = NGE_SEND_SLOTS_DESC_1024;
		dev_param_p->nge_split = NGE_SPLIT_32;
		break;

	default:
		dev_param_p->msi = B_FALSE;
		dev_param_p->msi_x = B_FALSE;
		dev_param_p->vlan = B_FALSE;
		dev_param_p->advanced_pm = B_FALSE;
		dev_param_p->mac_addr_order = B_FALSE;
		dev_param_p->tx_pause_frame = B_FALSE;
		dev_param_p->rx_pause_frame = B_FALSE;
		dev_param_p->jumbo = B_FALSE;
		dev_param_p->tx_rx_64byte = B_FALSE;
		dev_param_p->rx_hw_checksum = B_FALSE;
		dev_param_p->tx_hw_checksum = 0;
		dev_param_p->desc_type = DESC_OFFLOAD;
		dev_param_p->rx_desc_num = NGE_RECV_SLOTS_DESC_1024;
		dev_param_p->tx_desc_num = NGE_SEND_SLOTS_DESC_1024;
		dev_param_p->nge_split = NGE_SPLIT_32;
		return;
	}
}
/*
 * Perform first-stage chip (re-)initialisation, using only config-space
 * accesses:
 *
 * + Read the vendor/device/revision/subsystem/cache-line-size registers,
 *   returning the data in the structure pointed to by <infop>.
 */
void nge_chip_cfg_init(nge_t *ngep, chip_info_t *infop, boolean_t reset);
#pragma	no_inline(nge_chip_cfg_init)

void
nge_chip_cfg_init(nge_t *ngep, chip_info_t *infop, boolean_t reset)
{
	uint16_t command;
	ddi_acc_handle_t handle;
	nge_interbus_conf interbus_conf;
	nge_msi_mask_conf msi_mask_conf;
	nge_msi_map_cap_conf cap_conf;

	NGE_TRACE(("nge_chip_cfg_init($%p, $%p, %d)",
	    (void *)ngep, (void *)infop, reset));

	/*
	 * save PCI cache line size and subsystem vendor ID
	 *
	 * Read all the config-space registers that characterise the
	 * chip, specifically vendor/device/revision/subsystem vendor
	 * and subsystem device id.  We expect (but don't check) that
	 */
	handle = ngep->cfg_handle;
	/* reading the vendor information once */
	if (reset == B_FALSE) {
		infop->command = pci_config_get16(handle,
		    PCI_CONF_COMM);
		infop->vendor = pci_config_get16(handle,
		    PCI_CONF_VENID);
		infop->device = pci_config_get16(handle,
		    PCI_CONF_DEVID);
		infop->subven = pci_config_get16(handle,
		    PCI_CONF_SUBVENID);
		infop->subdev = pci_config_get16(handle,
		    PCI_CONF_SUBSYSID);
		infop->class_code = pci_config_get8(handle,
		    PCI_CONF_BASCLASS);
		infop->revision = pci_config_get8(handle,
		    PCI_CONF_REVID);
		infop->clsize = pci_config_get8(handle,
		    PCI_CONF_CACHE_LINESZ);
		infop->latency = pci_config_get8(handle,
		    PCI_CONF_LATENCY_TIMER);
	}
	if (nge_enable_msi) {
		/* Disable the hidden for MSI support */
		interbus_conf.conf_val = pci_config_get32(handle,
		    PCI_CONF_HT_INTERNAL);
		if ((infop->device == DEVICE_ID_MCP55_373) ||
		    (infop->device == DEVICE_ID_MCP55_372))
			interbus_conf.conf_bits.msix_off = NGE_SET;
		interbus_conf.conf_bits.msi_off = NGE_CLEAR;
		pci_config_put32(handle, PCI_CONF_HT_INTERNAL,
		    interbus_conf.conf_val);

		if ((infop->device == DEVICE_ID_MCP55_373) ||
		    (infop->device == DEVICE_ID_MCP55_372)) {

			/* Disable the vector off for mcp55 */
			msi_mask_conf.msi_mask_conf_val =
			    pci_config_get32(handle, PCI_CONF_HT_MSI_MASK);
			msi_mask_conf.msi_mask_bits.vec0_off = NGE_CLEAR;
			msi_mask_conf.msi_mask_bits.vec1_off = NGE_CLEAR;
			msi_mask_conf.msi_mask_bits.vec2_off = NGE_CLEAR;
			msi_mask_conf.msi_mask_bits.vec3_off = NGE_CLEAR;
			msi_mask_conf.msi_mask_bits.vec4_off = NGE_CLEAR;
			msi_mask_conf.msi_mask_bits.vec5_off = NGE_CLEAR;
			msi_mask_conf.msi_mask_bits.vec6_off = NGE_CLEAR;
			msi_mask_conf.msi_mask_bits.vec7_off = NGE_CLEAR;
			pci_config_put32(handle, PCI_CONF_HT_MSI_MASK,
			    msi_mask_conf.msi_mask_conf_val);

			/* Enable the MSI mapping */
			cap_conf.msi_map_cap_conf_val =
			    pci_config_get32(handle, PCI_CONF_HT_MSI_MAP_CAP);
			cap_conf.map_cap_conf_bits.map_en = NGE_SET;
			pci_config_put32(handle, PCI_CONF_HT_MSI_MAP_CAP,
			    cap_conf.msi_map_cap_conf_val);
		}
	} else {
		interbus_conf.conf_val = pci_config_get32(handle,
		    PCI_CONF_HT_INTERNAL);
		interbus_conf.conf_bits.msi_off = NGE_SET;
		pci_config_put32(handle, PCI_CONF_HT_INTERNAL,
		    interbus_conf.conf_val);
	}
	command = infop->command | PCI_COMM_MAE;
	command &= ~PCI_COMM_MEMWR_INVAL;
	command |= PCI_COMM_ME;
	pci_config_put16(handle, PCI_CONF_COMM, command);
	pci_config_put16(handle, PCI_CONF_STAT, ~0);

}

int
nge_chip_stop(nge_t *ngep, boolean_t fault)
{
	int err;
	uint32_t reg_val;
	uint32_t	tries;
	nge_mintr_src mintr_src;
	nge_mii_cs mii_cs;
	nge_rx_poll rx_poll;
	nge_tx_poll tx_poll;
	nge_rx_en rx_en;
	nge_tx_en tx_en;
	nge_tx_sta tx_sta;
	nge_rx_sta rx_sta;
	nge_mode_cntl mode;
	nge_pmu_cntl2 pmu_cntl2;

	NGE_TRACE(("nge_chip_stop($%p, %d)", (void *)ngep, fault));

	err = DDI_SUCCESS;

	/* Clear any pending PHY interrupt */
	mintr_src.src_val = nge_reg_get8(ngep, NGE_MINTR_SRC);
	nge_reg_put8(ngep, NGE_MINTR_SRC, mintr_src.src_val);

	/* Mask all interrupts */
	reg_val = nge_reg_get32(ngep, NGE_INTR_MASK);
	reg_val &= ~NGE_INTR_ALL_EN;
	nge_reg_put32(ngep, NGE_INTR_MASK, reg_val);

	/* Disable auto-polling of phy */
	mii_cs.cs_val = nge_reg_get32(ngep, NGE_MII_CS);
	mii_cs.cs_bits.ap_en = NGE_CLEAR;
	nge_reg_put32(ngep, NGE_MII_CS, mii_cs.cs_val);

	/* Reset buffer management & DMA */
	mode.mode_val = nge_reg_get32(ngep, NGE_MODE_CNTL);
	mode.mode_bits.dma_dis = NGE_SET;
	mode.mode_bits.desc_type = ngep->desc_mode;
	nge_reg_put32(ngep, NGE_MODE_CNTL, mode.mode_val);

	for (tries = 0; tries < 10000; tries++) {
		drv_usecwait(10);
		mode.mode_val = nge_reg_get32(ngep, NGE_MODE_CNTL);
		if (mode.mode_bits.dma_status == NGE_SET)
			break;
	}
	if (tries == 10000) {
		ngep->nge_chip_state = NGE_CHIP_ERROR;
		return (DDI_FAILURE);
	}

	/* Disable rx's machine */
	rx_en.val = nge_reg_get8(ngep, NGE_RX_EN);
	rx_en.bits.rx_en = NGE_CLEAR;
	nge_reg_put8(ngep, NGE_RX_EN, rx_en.val);

	/* Disable tx's machine */
	tx_en.val = nge_reg_get8(ngep, NGE_TX_EN);
	tx_en.bits.tx_en = NGE_CLEAR;
	nge_reg_put8(ngep, NGE_TX_EN, tx_en.val);

	/*
	 * Clean the status of tx's state machine
	 * and Make assure the tx's channel is idle
	 */
	tx_sta.sta_val = nge_reg_get32(ngep, NGE_TX_STA);
	for (tries = 0; tries < 1000; tries++) {
		if (tx_sta.sta_bits.tx_chan_sta == NGE_CLEAR)
			break;
		drv_usecwait(10);
		tx_sta.sta_val = nge_reg_get32(ngep, NGE_TX_STA);
	}
	if (tries == 1000) {
		ngep->nge_chip_state = NGE_CHIP_ERROR;
		return (DDI_FAILURE);
	}
	nge_reg_put32(ngep, NGE_TX_STA,  tx_sta.sta_val);

	/*
	 * Clean the status of rx's state machine
	 * and Make assure the tx's channel is idle
	 */
	rx_sta.sta_val = nge_reg_get32(ngep, NGE_RX_STA);
	for (tries = 0; tries < 1000; tries++) {
		if (rx_sta.sta_bits.rx_chan_sta == NGE_CLEAR)
			break;
		drv_usecwait(10);
		rx_sta.sta_val = nge_reg_get32(ngep, NGE_RX_STA);
	}
	if (tries == 1000) {
		ngep->nge_chip_state = NGE_CHIP_ERROR;
		return (DDI_FAILURE);
	}
	nge_reg_put32(ngep, NGE_RX_STA, rx_sta.sta_val);

	/* Disable auto-poll of rx's state machine */
	rx_poll.poll_val = nge_reg_get32(ngep, NGE_RX_POLL);
	rx_poll.poll_bits.rpen = NGE_CLEAR;
	rx_poll.poll_bits.rpi = NGE_CLEAR;
	nge_reg_put32(ngep, NGE_RX_POLL, rx_poll.poll_val);

	/* Disable auto-polling of tx's  state machine */
	tx_poll.poll_val = nge_reg_get32(ngep, NGE_TX_POLL);
	tx_poll.poll_bits.tpen = NGE_CLEAR;
	tx_poll.poll_bits.tpi = NGE_CLEAR;
	nge_reg_put32(ngep, NGE_TX_POLL, tx_poll.poll_val);

	/* Restore buffer management */
	mode.mode_val = nge_reg_get32(ngep, NGE_MODE_CNTL);
	mode.mode_bits.bm_reset = NGE_SET;
	mode.mode_bits.tx_rcom_en = NGE_SET;
	nge_reg_put32(ngep, NGE_MODE_CNTL, mode.mode_val);

	if (ngep->dev_spec_param.advanced_pm) {

		nge_reg_put32(ngep, NGE_PMU_CIDLE_LIMIT, 0);
		nge_reg_put32(ngep, NGE_PMU_DIDLE_LIMIT, 0);

		pmu_cntl2.cntl2_val = nge_reg_get32(ngep, NGE_PMU_CNTL2);
		pmu_cntl2.cntl2_bits.cidle_timer = NGE_CLEAR;
		pmu_cntl2.cntl2_bits.didle_timer = NGE_CLEAR;
		nge_reg_put32(ngep, NGE_PMU_CNTL2, pmu_cntl2.cntl2_val);
	}
	if (fault)
		ngep->nge_chip_state = NGE_CHIP_FAULT;
	else
		ngep->nge_chip_state = NGE_CHIP_STOPPED;

	return (err);
}

static void
nge_rx_setup(nge_t *ngep)
{
	uint64_t desc_addr;
	nge_rxtx_dlen dlen;
	nge_rx_poll rx_poll;

	/*
	 * Filling the address and length of rx's descriptors
	 */
	desc_addr = ngep->recv->desc.cookie.dmac_laddress;
	nge_reg_put32(ngep, NGE_RX_DADR, desc_addr);
	nge_reg_put32(ngep, NGE_RX_DADR_HI, desc_addr >> 32);
	dlen.dlen_val = nge_reg_get32(ngep, NGE_RXTX_DLEN);
	dlen.dlen_bits.rdlen = ngep->recv->desc.nslots - 1;
	nge_reg_put32(ngep, NGE_RXTX_DLEN, dlen.dlen_val);

	rx_poll.poll_val = nge_reg_get32(ngep, NGE_RX_POLL);
	rx_poll.poll_bits.rpi = RX_POLL_INTV_1G;
	rx_poll.poll_bits.rpen = NGE_SET;
	nge_reg_put32(ngep, NGE_RX_POLL, rx_poll.poll_val);
}

static void
nge_tx_setup(nge_t *ngep)
{
	uint64_t desc_addr;
	nge_rxtx_dlen dlen;

	/*
	 * Filling the address and length of tx's descriptors
	 */
	desc_addr = ngep->send->desc.cookie.dmac_laddress;
	nge_reg_put32(ngep, NGE_TX_DADR, desc_addr);
	nge_reg_put32(ngep, NGE_TX_DADR_HI, desc_addr >> 32);
	dlen.dlen_val = nge_reg_get32(ngep, NGE_RXTX_DLEN);
	dlen.dlen_bits.tdlen = ngep->send->desc.nslots - 1;
	nge_reg_put32(ngep, NGE_RXTX_DLEN, dlen.dlen_val);
}

static int
nge_buff_setup(nge_t *ngep)
{
	nge_mode_cntl mode_cntl;
	nge_dev_spec_param_t	*dev_param_p;

	dev_param_p = &ngep->dev_spec_param;

	/*
	 * Configure Rx&Tx's buffer
	 */
	nge_rx_setup(ngep);
	nge_tx_setup(ngep);

	/*
	 * Configure buffer attribute
	 */
	mode_cntl.mode_val = nge_reg_get32(ngep, NGE_MODE_CNTL);

	/*
	 * Enable Dma access request
	 */
	mode_cntl.mode_bits.dma_dis = NGE_CLEAR;

	/*
	 * Enbale Buffer management
	 */
	mode_cntl.mode_bits.bm_reset = NGE_CLEAR;

	/*
	 * Support Standoffload Descriptor
	 */
	mode_cntl.mode_bits.desc_type = ngep->desc_mode;

	/*
	 * Support receive hardware checksum
	 */
	if (dev_param_p->rx_hw_checksum) {
		mode_cntl.mode_bits.rx_sum_en = NGE_SET;
	} else
		mode_cntl.mode_bits.rx_sum_en = NGE_CLEAR;

	/*
	 * Disable Tx PRD coarse update
	 */
	mode_cntl.mode_bits.tx_prd_cu_en = NGE_CLEAR;

	/*
	 * Disable 64-byte access
	 */
	mode_cntl.mode_bits.w64_dis = NGE_SET;

	/*
	 * Skip Rx Error Frame is not supported and if
	 * enable it, jumbo frame does not work any more.
	 */
	mode_cntl.mode_bits.rx_filter_en = NGE_CLEAR;

	/*
	 * Can not support hot mode now
	 */
	mode_cntl.mode_bits.resv15 = NGE_CLEAR;

	if (dev_param_p->vlan) {
		/* Disable the vlan strip for devices which support vlan */
		mode_cntl.mode_bits.vlan_strip = NGE_CLEAR;

		/* Disable the vlan insert for devices which supprot vlan */
		mode_cntl.mode_bits.vlan_ins = NGE_CLEAR;
	}

	if (dev_param_p->tx_rx_64byte) {

		/* Set the maximum TX PRD fetch size to 64 bytes */
		mode_cntl.mode_bits.tx_fetch_prd = NGE_SET;

		/* Set the maximum RX PRD fetch size to 64 bytes */
		mode_cntl.mode_bits.rx_fetch_prd = NGE_SET;
	}
	/*
	 * Upload Rx data as it arrives, rather than waiting for full frame
	 */
	mode_cntl.mode_bits.resv16 = NGE_CLEAR;

	/*
	 * Normal HOT table accesses
	 */
	mode_cntl.mode_bits.resv17 = NGE_CLEAR;

	/*
	 * Normal HOT buffer requesting
	 */
	mode_cntl.mode_bits.resv18 = NGE_CLEAR;
	nge_reg_put32(ngep, NGE_MODE_CNTL, mode_cntl.mode_val);

	/*
	 * Signal controller to check for new Rx descriptors
	 */
	mode_cntl.mode_val = nge_reg_get32(ngep, NGE_MODE_CNTL);
	mode_cntl.mode_bits.rxdm = NGE_SET;
	mode_cntl.mode_bits.tx_rcom_en = NGE_SET;
	nge_reg_put32(ngep, NGE_MODE_CNTL, mode_cntl.mode_val);


	return (DDI_SUCCESS);
}

/*
 * When chipset resets, the chipset can not restore  the orignial
 * mac address to the mac address registers.
 *
 * When the driver is dettached, the function will write the orignial
 * mac address to the mac address registers.
 */

void
nge_restore_mac_addr(nge_t *ngep)
{
	uint32_t mac_addr;

	mac_addr = (uint32_t)ngep->chipinfo.hw_mac_addr;
	nge_reg_put32(ngep, NGE_UNI_ADDR0, mac_addr);
	mac_addr = (uint32_t)(ngep->chipinfo.hw_mac_addr >> 32);
	nge_reg_put32(ngep, NGE_UNI_ADDR1, mac_addr);
}

int
nge_chip_reset(nge_t *ngep)
{
	int err;
	uint8_t i;
	uint32_t regno;
	uint64_t mac = 0;
	nge_uni_addr1 uaddr1;
	nge_cp_cntl ee_cntl;
	nge_soft_misc soft_misc;
	nge_pmu_cntl0 pmu_cntl0;
	nge_pmu_cntl2 pmu_cntl2;
	nge_pm_cntl2 pm_cntl2;
	const nge_ksindex_t *ksip;

	NGE_TRACE(("nge_chip_reset($%p)", (void *)ngep));

	/*
	 * Clear the statistics by reading the statistics register
	 */
	for (ksip = nge_statistics; ksip->name != NULL; ++ksip) {
		regno = KS_BASE + ksip->index * sizeof (uint32_t);
		(void) nge_reg_get32(ngep, regno);
	}

	/*
	 * Setup seeprom control
	 */
	ee_cntl.cntl_val = nge_reg_get32(ngep, NGE_EP_CNTL);
	ee_cntl.cntl_bits.clkdiv = EEPROM_CLKDIV;
	ee_cntl.cntl_bits.rom_size = EEPROM_32K;
	ee_cntl.cntl_bits.word_wid = ACCESS_16BIT;
	ee_cntl.cntl_bits.wait_slots = EEPROM_WAITCLK;
	nge_reg_put32(ngep, NGE_EP_CNTL, ee_cntl.cntl_val);

	/*
	 * Reading the unicast mac address table
	 */
	if (ngep->nge_chip_state == NGE_CHIP_INITIAL) {
		uaddr1.addr_val = nge_reg_get32(ngep, NGE_UNI_ADDR1);
		mac = uaddr1.addr_bits.addr;
		mac <<= 32;
		mac |= nge_reg_get32(ngep, NGE_UNI_ADDR0);
			ngep->chipinfo.hw_mac_addr = mac;
			if (ngep->dev_spec_param.mac_addr_order) {
				for (i = 0; i < ETHERADDRL; i++) {
					ngep->chipinfo.vendor_addr.addr[i] =
					    (uchar_t)mac;
					ngep->cur_uni_addr.addr[i] =
					    (uchar_t)mac;
					mac >>= 8;
				}
			} else {
				for (i = ETHERADDRL; i-- != 0; ) {
					ngep->chipinfo.vendor_addr.addr[i] =
					    (uchar_t)mac;
					ngep->cur_uni_addr.addr[i] =
					    (uchar_t)mac;
					mac >>= 8;
				}
			}
			ngep->chipinfo.vendor_addr.set = 1;
	}
	pci_config_put8(ngep->cfg_handle, PCI_CONF_CACHE_LINESZ,
	    ngep->chipinfo.clsize);
	pci_config_put8(ngep->cfg_handle, PCI_CONF_LATENCY_TIMER,
	    ngep->chipinfo.latency);


	if (ngep->dev_spec_param.advanced_pm) {

		/* Program software misc register */
		soft_misc.misc_val = nge_reg_get32(ngep, NGE_SOFT_MISC);
		soft_misc.misc_bits.rx_clk_vx_rst = NGE_SET;
		soft_misc.misc_bits.tx_clk_vx_rst = NGE_SET;
		soft_misc.misc_bits.clk12m_vx_rst = NGE_SET;
		soft_misc.misc_bits.fpci_clk_vx_rst = NGE_SET;
		soft_misc.misc_bits.rx_clk_vc_rst = NGE_SET;
		soft_misc.misc_bits.tx_clk_vc_rst = NGE_SET;
		soft_misc.misc_bits.fs_clk_vc_rst = NGE_SET;
		soft_misc.misc_bits.rst_ex_m2pintf = NGE_SET;
		nge_reg_put32(ngep, NGE_SOFT_MISC, soft_misc.misc_val);

		/* wait for 32 us */
		drv_usecwait(32);

		soft_misc.misc_val = nge_reg_get32(ngep, NGE_SOFT_MISC);
		soft_misc.misc_bits.rx_clk_vx_rst = NGE_CLEAR;
		soft_misc.misc_bits.tx_clk_vx_rst = NGE_CLEAR;
		soft_misc.misc_bits.clk12m_vx_rst = NGE_CLEAR;
		soft_misc.misc_bits.fpci_clk_vx_rst = NGE_CLEAR;
		soft_misc.misc_bits.rx_clk_vc_rst = NGE_CLEAR;
		soft_misc.misc_bits.tx_clk_vc_rst = NGE_CLEAR;
		soft_misc.misc_bits.fs_clk_vc_rst = NGE_CLEAR;
		soft_misc.misc_bits.rst_ex_m2pintf = NGE_CLEAR;
		nge_reg_put32(ngep, NGE_SOFT_MISC, soft_misc.misc_val);

		/* Program PMU registers */
		pmu_cntl0.cntl0_val = nge_reg_get32(ngep, NGE_PMU_CNTL0);
		pmu_cntl0.cntl0_bits.core_spd10_fp =
		    NGE_PMU_CORE_SPD10_BUSY;
		pmu_cntl0.cntl0_bits.core_spd10_idle =
		    NGE_PMU_CORE_SPD10_IDLE;
		pmu_cntl0.cntl0_bits.core_spd100_fp =
		    NGE_PMU_CORE_SPD100_BUSY;
		pmu_cntl0.cntl0_bits.core_spd100_idle =
		    NGE_PMU_CORE_SPD100_IDLE;
		pmu_cntl0.cntl0_bits.core_spd1000_fp =
		    NGE_PMU_CORE_SPD1000_BUSY;
		pmu_cntl0.cntl0_bits.core_spd1000_idle =
		    NGE_PMU_CORE_SPD100_IDLE;
		pmu_cntl0.cntl0_bits.core_spd10_idle =
		    NGE_PMU_CORE_SPD10_IDLE;
		nge_reg_put32(ngep, NGE_PMU_CNTL0, pmu_cntl0.cntl0_val);

		/* Set the core idle limit value */
		nge_reg_put32(ngep, NGE_PMU_CIDLE_LIMIT,
		    NGE_PMU_CIDLE_LIMIT_DEF);

		/* Set the device idle limit value */
		nge_reg_put32(ngep, NGE_PMU_DIDLE_LIMIT,
		    NGE_PMU_DIDLE_LIMIT_DEF);

		/* Enable the core/device idle timer in PMU control 2 */
		pmu_cntl2.cntl2_val = nge_reg_get32(ngep, NGE_PMU_CNTL2);
		pmu_cntl2.cntl2_bits.cidle_timer = NGE_SET;
		pmu_cntl2.cntl2_bits.didle_timer = NGE_SET;
		pmu_cntl2.cntl2_bits.core_enable = NGE_SET;
		pmu_cntl2.cntl2_bits.dev_enable = NGE_SET;
		nge_reg_put32(ngep, NGE_PMU_CNTL2, pmu_cntl2.cntl2_val);
	}
	/*
	 * Stop the chipset and clear buffer management
	 */
	err = nge_chip_stop(ngep, B_FALSE);
	if (err == DDI_FAILURE)
		return (err);
	/*
	 * Clear the power state bits for phy since interface no longer
	 * works after rebooting from Windows on a multi-boot machine
	 */
	if (ngep->chipinfo.device == DEVICE_ID_MCP51_268 ||
	    ngep->chipinfo.device == DEVICE_ID_MCP51_269 ||
	    ngep->chipinfo.device == DEVICE_ID_MCP55_372 ||
	    ngep->chipinfo.device == DEVICE_ID_MCP55_373 ||
	    ngep->chipinfo.device == DEVICE_ID_MCP61_3EE ||
	    ngep->chipinfo.device == DEVICE_ID_MCP61_3EF ||
	    ngep->chipinfo.device == DEVICE_ID_MCP77_760 ||
	    ngep->chipinfo.device == DEVICE_ID_MCP79_AB0) {

		pm_cntl2.cntl_val = nge_reg_get32(ngep, NGE_PM_CNTL2);
		/* bring phy out of coma mode */
		pm_cntl2.cntl_bits.phy_coma_set = NGE_CLEAR;
		/* disable auto reset coma bits */
		pm_cntl2.cntl_bits.resv4 = NGE_CLEAR;
		/* restore power to gated clocks */
		pm_cntl2.cntl_bits.resv8_11 = NGE_CLEAR;
		nge_reg_put32(ngep, NGE_PM_CNTL2, pm_cntl2.cntl_val);
	}

	ngep->nge_chip_state = NGE_CHIP_RESET;
	return (DDI_SUCCESS);
}

int
nge_chip_start(nge_t *ngep)
{
	int err;
	nge_itc itc;
	nge_tx_cntl tx_cntl;
	nge_rx_cntrl0 rx_cntl0;
	nge_rx_cntl1 rx_cntl1;
	nge_tx_en tx_en;
	nge_rx_en rx_en;
	nge_mii_cs mii_cs;
	nge_swtr_cntl swtr_cntl;
	nge_rx_fifo_wm rx_fifo;
	nge_intr_mask intr_mask;
	nge_mintr_mask mintr_mask;
	nge_dev_spec_param_t	*dev_param_p;

	NGE_TRACE(("nge_chip_start($%p)", (void *)ngep));

	/*
	 * Setup buffer management
	 */
	err = nge_buff_setup(ngep);
	if (err == DDI_FAILURE)
		return (err);

	dev_param_p = &ngep->dev_spec_param;

	/*
	 * Enable polling attribute
	 */
	mii_cs.cs_val = nge_reg_get32(ngep, NGE_MII_CS);
	mii_cs.cs_bits.ap_paddr = ngep->phy_xmii_addr;
	mii_cs.cs_bits.ap_en = NGE_SET;
	mii_cs.cs_bits.ap_intv = MII_POLL_INTV;
	nge_reg_put32(ngep, NGE_MII_CS, mii_cs.cs_val);

	/*
	 * Setup link
	 */
	(*ngep->physops->phys_update)(ngep);

	/*
	 * Configure the tx's parameters
	 */
	tx_cntl.cntl_val = nge_reg_get32(ngep, NGE_TX_CNTL);
	if (dev_param_p->tx_pause_frame)
		tx_cntl.cntl_bits.paen = NGE_SET;
	else
		tx_cntl.cntl_bits.paen = NGE_CLEAR;
	tx_cntl.cntl_bits.retry_en = NGE_SET;
	tx_cntl.cntl_bits.pad_en = NGE_SET;
	tx_cntl.cntl_bits.fappend_en = NGE_SET;
	tx_cntl.cntl_bits.two_def_en = NGE_SET;
	tx_cntl.cntl_bits.max_retry = 15;
	tx_cntl.cntl_bits.burst_en = NGE_CLEAR;
	tx_cntl.cntl_bits.uflo_err_mask = NGE_CLEAR;
	tx_cntl.cntl_bits.tlcol_mask = NGE_CLEAR;
	tx_cntl.cntl_bits.lcar_mask = NGE_CLEAR;
	tx_cntl.cntl_bits.def_mask = NGE_CLEAR;
	tx_cntl.cntl_bits.exdef_mask = NGE_SET;
	tx_cntl.cntl_bits.lcar_mask = NGE_SET;
	tx_cntl.cntl_bits.tlcol_mask = NGE_SET;
	tx_cntl.cntl_bits.uflo_err_mask = NGE_SET;
	tx_cntl.cntl_bits.jam_seq_en = NGE_CLEAR;
	nge_reg_put32(ngep, NGE_TX_CNTL, tx_cntl.cntl_val);


	/*
	 * Configure the parameters of Rx's state machine
	 * Enabe the parameters:
	 * 1). Pad Strip
	 * 2). FCS Relay
	 * 3). Pause
	 * 4). Address filter
	 * 5). Runt Packet receive
	 * 6). Broadcast
	 * 7). Receive Deferral
	 *
	 * Disable the following parameters for decreasing
	 * the number of interrupts:
	 * 1). Runt Inerrupt.
	 * 2). Rx's Late Collision interrupt.
	 * 3). Rx's Max length Error Interrupt.
	 * 4). Rx's Length Field error Interrupt.
	 * 5). Rx's FCS error interrupt.
	 * 6). Rx's overflow error interrupt.
	 * 7). Rx's Frame alignment error interrupt.
	 */
	rx_cntl0.cntl_val = nge_reg_get32(ngep, NGE_RX_CNTL0);
	rx_cntl0.cntl_bits.padsen = NGE_CLEAR;
	rx_cntl0.cntl_bits.fcsren = NGE_CLEAR;
	if (dev_param_p->rx_pause_frame)
		rx_cntl0.cntl_bits.paen = NGE_SET;
	else
		rx_cntl0.cntl_bits.paen = NGE_CLEAR;
	rx_cntl0.cntl_bits.lben = NGE_CLEAR;
	rx_cntl0.cntl_bits.afen = NGE_SET;
	rx_cntl0.cntl_bits.runten = NGE_CLEAR;
	rx_cntl0.cntl_bits.brdis = NGE_CLEAR;
	rx_cntl0.cntl_bits.rdfen = NGE_CLEAR;
	rx_cntl0.cntl_bits.runtm = NGE_CLEAR;
	rx_cntl0.cntl_bits.slfb = NGE_CLEAR;
	rx_cntl0.cntl_bits.rlcolm = NGE_CLEAR;
	rx_cntl0.cntl_bits.maxerm = NGE_CLEAR;
	rx_cntl0.cntl_bits.lferm = NGE_CLEAR;
	rx_cntl0.cntl_bits.crcm = NGE_CLEAR;
	rx_cntl0.cntl_bits.ofolm = NGE_CLEAR;
	rx_cntl0.cntl_bits.framerm = NGE_CLEAR;
	nge_reg_put32(ngep, NGE_RX_CNTL0, rx_cntl0.cntl_val);

	/*
	 * Configure the watermark for the rx's statemachine
	 */
	rx_fifo.wm_val = nge_reg_get32(ngep, NGE_RX_FIFO_WM);
	rx_fifo.wm_bits.data_hwm = ngep->rx_datahwm;
	rx_fifo.wm_bits.prd_lwm = ngep->rx_prdlwm;
	rx_fifo.wm_bits.prd_hwm = ngep->rx_prdhwm;
	nge_reg_put32(ngep, NGE_RX_FIFO_WM, rx_fifo.wm_val);

	/*
	 * Configure the deffer time slot for rx's state machine
	 */
	nge_reg_put8(ngep, NGE_RX_DEf, ngep->rx_def);

	/*
	 * Configure the length of rx's packet
	 */
	rx_cntl1.cntl_val = nge_reg_get32(ngep, NGE_RX_CNTL1);
	rx_cntl1.cntl_bits.length = ngep->max_sdu;
	nge_reg_put32(ngep, NGE_RX_CNTL1, rx_cntl1.cntl_val);
	/*
	 * Enable Tx's state machine
	 */
	tx_en.val = nge_reg_get8(ngep, NGE_TX_EN);
	tx_en.bits.tx_en = NGE_SET;
	nge_reg_put8(ngep, NGE_TX_EN, tx_en.val);

	/*
	 * Enable Rx's state machine
	 */
	rx_en.val = nge_reg_get8(ngep, NGE_RX_EN);
	rx_en.bits.rx_en = NGE_SET;
	nge_reg_put8(ngep, NGE_RX_EN, rx_en.val);

	itc.itc_val = nge_reg_get32(ngep, NGE_SWTR_ITC);
	itc.itc_bits.sw_intv = ngep->sw_intr_intv;
	nge_reg_put32(ngep, NGE_SWTR_ITC, itc.itc_val);

	swtr_cntl.ctrl_val = nge_reg_get8(ngep, NGE_SWTR_CNTL);
	swtr_cntl.cntl_bits.sten = NGE_SET;
	swtr_cntl.cntl_bits.stren = NGE_SET;
	nge_reg_put32(ngep, NGE_SWTR_CNTL, swtr_cntl.ctrl_val);

	/*
	 * Disable all mii read/write operation Interrupt
	 */
	mintr_mask.mask_val = nge_reg_get8(ngep, NGE_MINTR_MASK);
	mintr_mask.mask_bits.mrei = NGE_CLEAR;
	mintr_mask.mask_bits.mcc2 = NGE_CLEAR;
	mintr_mask.mask_bits.mcc1 = NGE_CLEAR;
	mintr_mask.mask_bits.mapi = NGE_SET;
	mintr_mask.mask_bits.mpdi = NGE_SET;
	nge_reg_put8(ngep, NGE_MINTR_MASK, mintr_mask.mask_val);

	/*
	 * Enable all interrupt event
	 */
	intr_mask.mask_val = nge_reg_get32(ngep, NGE_INTR_MASK);
	intr_mask.mask_bits.reint = NGE_SET;
	intr_mask.mask_bits.rcint = NGE_SET;
	intr_mask.mask_bits.miss = NGE_SET;
	intr_mask.mask_bits.teint = NGE_SET;
	intr_mask.mask_bits.tcint = NGE_CLEAR;
	intr_mask.mask_bits.stint = NGE_CLEAR;
	intr_mask.mask_bits.mint = NGE_CLEAR;
	intr_mask.mask_bits.rfint = NGE_CLEAR;
	intr_mask.mask_bits.tfint = NGE_SET;
	intr_mask.mask_bits.feint = NGE_SET;
	intr_mask.mask_bits.resv10 = NGE_CLEAR;
	intr_mask.mask_bits.resv11 = NGE_CLEAR;
	intr_mask.mask_bits.resv12 = NGE_CLEAR;
	intr_mask.mask_bits.resv13 = NGE_CLEAR;
	intr_mask.mask_bits.phyint = NGE_CLEAR;
	ngep->intr_masks = intr_mask.mask_val;
	nge_reg_put32(ngep, NGE_INTR_MASK, intr_mask.mask_val);
	ngep->nge_chip_state = NGE_CHIP_RUNNING;
	return (DDI_SUCCESS);
}

/*
 * nge_chip_sync() -- program the chip with the unicast MAC address,
 * the multicast hash table, the required level of promiscuity.
 */
void
nge_chip_sync(nge_t *ngep)
{
	uint8_t i;
	uint64_t macaddr;
	uint64_t mul_addr;
	uint64_t mul_mask;
	nge_rx_cntrl0 rx_cntl;
	nge_uni_addr1 uni_adr1;

	NGE_TRACE(("nge_chip_sync($%p)", (void *)ngep));

	macaddr = 0x0ull;
	mul_addr = 0x0ull;
	mul_mask = 0x0ull;
	rx_cntl.cntl_val = nge_reg_get32(ngep, NGE_RX_CNTL0);

	if (ngep->promisc) {
		rx_cntl.cntl_bits.afen = NGE_CLEAR;
		rx_cntl.cntl_bits.brdis = NGE_SET;
	} else {
		rx_cntl.cntl_bits.afen = NGE_SET;
		rx_cntl.cntl_bits.brdis = NGE_CLEAR;
	}

	/*
	 * Transform the MAC address from host to chip format, the unicast
	 * MAC address(es) ...
	 */
	for (i = ETHERADDRL, macaddr = 0ull; i != 0; --i) {
		macaddr |= ngep->cur_uni_addr.addr[i-1];
		macaddr <<= (i > 1) ? 8 : 0;
	}

	nge_reg_put32(ngep, NGE_UNI_ADDR0, (uint32_t)macaddr);
	macaddr = macaddr >>32;
	uni_adr1.addr_val = nge_reg_get32(ngep, NGE_UNI_ADDR1);
	uni_adr1.addr_bits.addr = (uint16_t)macaddr;
	uni_adr1.addr_bits.resv16_31 = (uint16_t)0;
	nge_reg_put32(ngep, NGE_UNI_ADDR1, uni_adr1.addr_val);

	/*
	 * Reprogram the  multicast address table ...
	 */
	for (i = ETHERADDRL, mul_addr = 0ull; i != 0; --i) {
		mul_addr |= ngep->cur_mul_addr.addr[i-1];
		mul_addr <<= (i > 1) ? 8 : 0;
		mul_mask |= ngep->cur_mul_mask.addr[i-1];
		mul_mask <<= (i > 1) ? 8 : 0;
	}
	nge_reg_put32(ngep, NGE_MUL_ADDR0, (uint32_t)mul_addr);
	mul_addr >>= 32;
	nge_reg_put32(ngep, NGE_MUL_ADDR1, mul_addr);
	nge_reg_put32(ngep, NGE_MUL_MASK, (uint32_t)mul_mask);
	mul_mask >>= 32;
	nge_reg_put32(ngep, NGE_MUL_MASK1, mul_mask);
	/*
	 * Set or clear the PROMISCUOUS mode bit
	 */
	nge_reg_put32(ngep, NGE_RX_CNTL0, rx_cntl.cntl_val);
	/*
	 * For internal PHY loopback, the link will
	 * not be up, so it need to sync mac modes directly.
	 */
	if (ngep->param_loop_mode == NGE_LOOP_INTERNAL_PHY)
		nge_sync_mac_modes(ngep);
}

static void
nge_chip_err(nge_t *ngep)
{
	nge_reg010 reg010_ins;
	nge_sw_statistics_t *psw_stat;
	nge_intr_mask intr_mask;

	NGE_TRACE(("nge_chip_err($%p)", (void *)ngep));

	psw_stat = (nge_sw_statistics_t *)&ngep->statistics.sw_statistics;
	reg010_ins.reg010_val = nge_reg_get32(ngep, NGE_REG010);
	if (reg010_ins.reg010_bits.resv0)
		psw_stat->fe_err.tso_err_mss ++;

	if (reg010_ins.reg010_bits.resv1)
		psw_stat->fe_err.tso_dis ++;

	if (reg010_ins.reg010_bits.resv2)
		psw_stat->fe_err.tso_err_nosum ++;

	if (reg010_ins.reg010_bits.resv3)
		psw_stat->fe_err.tso_err_hov ++;

	if (reg010_ins.reg010_bits.resv4)
		psw_stat->fe_err.tso_err_huf ++;

	if (reg010_ins.reg010_bits.resv5)
		psw_stat->fe_err.tso_err_l2 ++;

	if (reg010_ins.reg010_bits.resv6)
		psw_stat->fe_err.tso_err_ip ++;

	if (reg010_ins.reg010_bits.resv7)
		psw_stat->fe_err.tso_err_l4 ++;

	if (reg010_ins.reg010_bits.resv8)
		psw_stat->fe_err.tso_err_tcp ++;

	if (reg010_ins.reg010_bits.resv9)
		psw_stat->fe_err.hsum_err_ip ++;

	if (reg010_ins.reg010_bits.resv10)
		psw_stat->fe_err.hsum_err_l4 ++;

	if (reg010_ins.reg010_val != 0) {

		/*
		 * Fatal error is triggered by malformed driver commands.
		 * Disable unless debugging.
		 */
		intr_mask.mask_val = nge_reg_get32(ngep, NGE_INTR_MASK);
		intr_mask.mask_bits.feint = NGE_CLEAR;
		nge_reg_put32(ngep, NGE_INTR_MASK, intr_mask.mask_val);
		ngep->intr_masks = intr_mask.mask_val;

	}
}

static void
nge_sync_mac_modes(nge_t *ngep)
{
	nge_tx_def tx_def;
	nge_tx_fifo_wm tx_fifo;
	nge_bkoff_cntl bk_cntl;
	nge_mac2phy m2p;
	nge_rx_cntrl0 rx_cntl0;
	nge_tx_cntl tx_cntl;
	nge_dev_spec_param_t	*dev_param_p;

	dev_param_p = &ngep->dev_spec_param;

	tx_def.def_val = nge_reg_get32(ngep, NGE_TX_DEF);
	m2p.m2p_val = nge_reg_get32(ngep, NGE_MAC2PHY);
	tx_fifo.wm_val = nge_reg_get32(ngep, NGE_TX_FIFO_WM);
	bk_cntl.cntl_val = nge_reg_get32(ngep, NGE_BKOFF_CNTL);
	bk_cntl.bkoff_bits.rseed = BKOFF_RSEED;
	switch (ngep->param_link_speed) {
	case 10:
		m2p.m2p_bits.speed = low_speed;
		tx_def.def_bits.ifg1_def = TX_IFG1_DEFAULT;
		if (ngep->phy_mode == RGMII_IN) {
			tx_def.def_bits.ifg2_def = TX_IFG2_RGMII_10_100;
			tx_def.def_bits.if_def = TX_IFG_RGMII_OTHER;
		} else {
			tx_def.def_bits.if_def = TX_TIFG_MII;
			tx_def.def_bits.ifg2_def = TX_IFG2_MII;
		}
		tx_fifo.wm_bits.nbfb_wm = TX_FIFO_NOB_WM_MII;
		bk_cntl.bkoff_bits.sltm = BKOFF_SLIM_MII;
		break;

	case 100:
		m2p.m2p_bits.speed = fast_speed;
		tx_def.def_bits.ifg1_def = TX_IFG1_DEFAULT;
		if (ngep->phy_mode == RGMII_IN) {
			tx_def.def_bits.ifg2_def = TX_IFG2_RGMII_10_100;
			tx_def.def_bits.if_def = TX_IFG_RGMII_OTHER;
		} else {
			tx_def.def_bits.if_def = TX_TIFG_MII;
			tx_def.def_bits.ifg2_def = TX_IFG2_MII;
		}
		tx_fifo.wm_bits.nbfb_wm = TX_FIFO_NOB_WM_MII;
		bk_cntl.bkoff_bits.sltm = BKOFF_SLIM_MII;
		break;

	case 1000:
		m2p.m2p_bits.speed = giga_speed;
		tx_def.def_bits.ifg1_def = TX_IFG1_DEFAULT;
		if (ngep->param_link_duplex == LINK_DUPLEX_FULL) {
			tx_def.def_bits.ifg2_def = TX_IFG2_RGMII_1000;
			tx_def.def_bits.if_def = TX_IFG_RGMII_1000_FD;
		} else {
			tx_def.def_bits.ifg2_def = TX_IFG2_RGMII_1000;
			tx_def.def_bits.if_def = TX_IFG_RGMII_OTHER;
		}

		tx_fifo.wm_bits.nbfb_wm = TX_FIFO_NOB_WM_GMII;
		bk_cntl.bkoff_bits.sltm = BKOFF_SLIM_GMII;
		break;
	}

	if (ngep->chipinfo.device == DEVICE_ID_MCP55_373 ||
	    ngep->chipinfo.device == DEVICE_ID_MCP55_372) {
		m2p.m2p_bits.phyintr = NGE_CLEAR;
		m2p.m2p_bits.phyintrlvl = NGE_CLEAR;
	}
	if (ngep->param_link_duplex == LINK_DUPLEX_HALF) {
		m2p.m2p_bits.hdup_en = NGE_SET;
	}
	else
		m2p.m2p_bits.hdup_en = NGE_CLEAR;
	nge_reg_put32(ngep, NGE_MAC2PHY, m2p.m2p_val);
	nge_reg_put32(ngep, NGE_TX_DEF, tx_def.def_val);

	tx_fifo.wm_bits.data_lwm = TX_FIFO_DATA_LWM;
	tx_fifo.wm_bits.prd_lwm = TX_FIFO_PRD_LWM;
	tx_fifo.wm_bits.uprd_hwm = TX_FIFO_PRD_HWM;
	tx_fifo.wm_bits.fb_wm = TX_FIFO_TBFW;
	nge_reg_put32(ngep, NGE_TX_FIFO_WM, tx_fifo.wm_val);

	nge_reg_put32(ngep, NGE_BKOFF_CNTL, bk_cntl.cntl_val);

	rx_cntl0.cntl_val = nge_reg_get32(ngep, NGE_RX_CNTL0);
	if (ngep->param_link_rx_pause && dev_param_p->rx_pause_frame) {
		if (rx_cntl0.cntl_bits.paen == NGE_CLEAR) {
			rx_cntl0.cntl_bits.paen = NGE_SET;
			nge_reg_put32(ngep, NGE_RX_CNTL0, rx_cntl0.cntl_val);
	}
	} else {
		if (rx_cntl0.cntl_bits.paen == NGE_SET) {
			rx_cntl0.cntl_bits.paen = NGE_CLEAR;
			nge_reg_put32(ngep, NGE_RX_CNTL0, rx_cntl0.cntl_val);
		}
	}

	tx_cntl.cntl_val = nge_reg_get32(ngep, NGE_TX_CNTL);
	if (ngep->param_link_tx_pause && dev_param_p->tx_pause_frame) {
		if (tx_cntl.cntl_bits.paen == NGE_CLEAR) {
			tx_cntl.cntl_bits.paen = NGE_SET;
			nge_reg_put32(ngep, NGE_TX_CNTL, tx_cntl.cntl_val);
		}
	} else {
		if (tx_cntl.cntl_bits.paen == NGE_SET) {
			tx_cntl.cntl_bits.paen = NGE_CLEAR;
			nge_reg_put32(ngep, NGE_TX_CNTL, tx_cntl.cntl_val);
		}
	}
}

/*
 * Handler for hardware link state change.
 *
 * When this routine is called, the hardware link state has changed
 * and the new state is reflected in the param_* variables.  Here
 * we must update the softstate, reprogram the MAC to match, and
 * record the change in the log and/or on the console.
 */
static void
nge_factotum_link_handler(nge_t *ngep)
{
	/*
	 * Update the s/w link_state
	 */
	if (ngep->param_link_up)
		ngep->link_state = LINK_STATE_UP;
	else
		ngep->link_state = LINK_STATE_DOWN;

	/*
	 * Reprogram the MAC modes to match
	 */
	nge_sync_mac_modes(ngep);
}

static boolean_t
nge_factotum_link_check(nge_t *ngep)
{
	boolean_t lchg;
	boolean_t check;

	ASSERT(mutex_owned(ngep->genlock));

	(*ngep->physops->phys_check)(ngep);
	switch (ngep->link_state) {
	case LINK_STATE_UP:
		lchg = (ngep->param_link_up == B_FALSE);
		check = (ngep->param_link_up == B_FALSE);
		break;

	case LINK_STATE_DOWN:
		lchg = (ngep->param_link_up == B_TRUE);
		check = (ngep->param_link_up == B_TRUE);
		break;

	default:
		check = B_TRUE;
		break;
	}

	/*
	 * If <check> is false, we're sure the link hasn't changed.
	 * If true, however, it's not yet definitive; we have to call
	 * nge_phys_check() to determine whether the link has settled
	 * into a new state yet ... and if it has, then call the link
	 * state change handler.But when the chip is 5700 in Dell 6650
	 * ,even if check is false, the link may have changed.So we
	 * have to call nge_phys_check() to determine the link state.
	 */
	if (check)
		nge_factotum_link_handler(ngep);

	return (lchg);
}

/*
 * Factotum routine to check for Tx stall, using the 'watchdog' counter
 */
static boolean_t nge_factotum_stall_check(nge_t *ngep);

static boolean_t
nge_factotum_stall_check(nge_t *ngep)
{
	uint32_t dogval;
	send_ring_t *srp;
	srp = ngep->send;
	/*
	 * Specific check for Tx stall ...
	 *
	 * The 'watchdog' counter is incremented whenever a packet
	 * is queued, reset to 1 when some (but not all) buffers
	 * are reclaimed, reset to 0 (disabled) when all buffers
	 * are reclaimed, and shifted left here.  If it exceeds the
	 * threshold value, the chip is assumed to have stalled and
	 * is put into the ERROR state.  The factotum will then reset
	 * it on the next pass.
	 *
	 * All of which should ensure that we don't get into a state
	 * where packets are left pending indefinitely!
	 */
	if (ngep->watchdog == 0 &&
	    srp->tx_free < srp->desc.nslots)
		ngep->watchdog = 1;
	dogval = nge_atomic_shl32(&ngep->watchdog, 1);
	if (dogval >= nge_watchdog_check)
		nge_tx_recycle(ngep, B_FALSE);
	if (dogval < nge_watchdog_count)
		return (B_FALSE);
	else {
		ngep->statistics.sw_statistics.tx_stall++;
		return (B_TRUE);
	}
}


/*
 * The factotum is woken up when there's something to do that we'd rather
 * not do from inside a hardware interrupt handler or high-level cyclic.
 * Its two main tasks are:
 *	reset & restart the chip after an error
 *	check the link status whenever necessary
 */
/* ARGSUSED */
uint_t
nge_chip_factotum(caddr_t args1, caddr_t args2)
{
	uint_t result;
	nge_t *ngep;
	boolean_t err;
	boolean_t linkchg;

	ngep = (nge_t *)args1;

	NGE_TRACE(("nge_chip_factotum($%p)", (void *)ngep));

	mutex_enter(ngep->softlock);
	if (ngep->factotum_flag == 0) {
		mutex_exit(ngep->softlock);
		return (DDI_INTR_UNCLAIMED);
	}
	ngep->factotum_flag = 0;
	mutex_exit(ngep->softlock);
	err = B_FALSE;
	linkchg = B_FALSE;
	result = DDI_INTR_CLAIMED;

	mutex_enter(ngep->genlock);
	switch (ngep->nge_chip_state) {
	default:
		break;

	case NGE_CHIP_RUNNING:
		linkchg = nge_factotum_link_check(ngep);
		err = nge_factotum_stall_check(ngep);
		break;

	case NGE_CHIP_FAULT:
		(void) nge_restart(ngep);
		NGE_REPORT((ngep, "automatic recovery activated"));
		break;
	}

	if (err)
		(void) nge_chip_stop(ngep, B_TRUE);
	mutex_exit(ngep->genlock);

	/*
	 * If the link state changed, tell the world about it (if
	 * this version of MAC supports link state notification).
	 * Note: can't do this while still holding the mutex.
	 */
	if (linkchg)
		mac_link_update(ngep->mh, ngep->link_state);

	return (result);

}

static void
nge_intr_handle(nge_t *ngep, nge_intr_src *pintr_src)
{
	boolean_t brx;
	boolean_t btx;
	nge_mintr_src mintr_src;

	brx = B_FALSE;
	btx = B_FALSE;
	ngep->statistics.sw_statistics.intr_count++;
	ngep->statistics.sw_statistics.intr_lval = pintr_src->intr_val;
	brx = (pintr_src->int_bits.reint | pintr_src->int_bits.miss
	    | pintr_src->int_bits.rcint | pintr_src->int_bits.stint)
	    != 0 ? B_TRUE : B_FALSE;
	if (pintr_src->int_bits.reint)
		ngep->statistics.sw_statistics.rx_err++;
	if (pintr_src->int_bits.miss)
		ngep->statistics.sw_statistics.rx_nobuffer++;

	btx = (pintr_src->int_bits.teint | pintr_src->int_bits.tfint)
	    != 0 ? B_TRUE : B_FALSE;
	if (btx)
		nge_tx_recycle(ngep, B_TRUE);
	if (brx)
		nge_receive(ngep);
	if (pintr_src->int_bits.teint)
		ngep->statistics.sw_statistics.tx_stop_err++;
	if (ngep->intr_moderation && brx) {
		if (ngep->poll) {
			if (ngep->recv_count < ngep->param_rx_intr_hwater) {
				ngep->quiet_time++;
				if (ngep->quiet_time ==
				    ngep->param_poll_quiet_time) {
					ngep->poll = B_FALSE;
					ngep->quiet_time = 0;
				}
			} else
				ngep->quiet_time = 0;
		} else {
			if (ngep->recv_count > ngep->param_rx_intr_lwater) {
				ngep->busy_time++;
				if (ngep->busy_time ==
				    ngep->param_poll_busy_time) {
					ngep->poll = B_TRUE;
					ngep->busy_time = 0;
				}
			} else
				ngep->busy_time = 0;
		}
	}
	ngep->recv_count = 0;
	if (pintr_src->int_bits.feint)
		nge_chip_err(ngep);
	/* link interrupt, check the link state */
	if (pintr_src->int_bits.mint) {
		mintr_src.src_val = nge_reg_get32(ngep, NGE_MINTR_SRC);
		nge_reg_put32(ngep, NGE_MINTR_SRC, mintr_src.src_val);
		nge_wake_factotum(ngep);
	}
}

/*
 *	nge_chip_intr() -- handle chip interrupts
 */
/* ARGSUSED */
uint_t
nge_chip_intr(caddr_t arg1, caddr_t arg2)
{
	nge_t *ngep = (nge_t *)arg1;
	nge_intr_src intr_src;
	nge_intr_mask intr_mask;

	mutex_enter(ngep->genlock);

	if (ngep->suspended) {
		mutex_exit(ngep->genlock);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Check whether chip's says it's asserting #INTA;
	 * if not, don't process or claim the interrupt.
	 */
	intr_src.intr_val = nge_reg_get32(ngep, NGE_INTR_SRC);
	if (intr_src.intr_val == 0) {
		mutex_exit(ngep->genlock);
		return (DDI_INTR_UNCLAIMED);
	}
	/*
	 * Ack the interrupt
	 */
	nge_reg_put32(ngep, NGE_INTR_SRC, intr_src.intr_val);

	if (ngep->nge_chip_state != NGE_CHIP_RUNNING) {
		mutex_exit(ngep->genlock);
		return (DDI_INTR_CLAIMED);
	}
	nge_intr_handle(ngep, &intr_src);
	if (ngep->poll && !ngep->ch_intr_mode) {
		intr_mask.mask_val = nge_reg_get32(ngep, NGE_INTR_MASK);
		intr_mask.mask_bits.stint = NGE_SET;
		intr_mask.mask_bits.rcint = NGE_CLEAR;
		nge_reg_put32(ngep, NGE_INTR_MASK, intr_mask.mask_val);
		ngep->ch_intr_mode = B_TRUE;
	} else if ((ngep->ch_intr_mode) && (!ngep->poll)) {
		nge_reg_put32(ngep, NGE_INTR_MASK, ngep->intr_masks);
		ngep->ch_intr_mode = B_FALSE;
	}
	mutex_exit(ngep->genlock);
	return (DDI_INTR_CLAIMED);
}

static enum ioc_reply
nge_pp_ioctl(nge_t *ngep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	int err;
	uint64_t sizemask;
	uint64_t mem_va;
	uint64_t maxoff;
	boolean_t peek;
	nge_peekpoke_t *ppd;
	int (*ppfn)(nge_t *ngep, nge_peekpoke_t *ppd);

	switch (cmd) {
	default:
		return (IOC_INVAL);

	case NGE_PEEK:
		peek = B_TRUE;
		break;

	case NGE_POKE:
		peek = B_FALSE;
		break;
	}

	/*
	 * Validate format of ioctl
	 */
	if (iocp->ioc_count != sizeof (nge_peekpoke_t))
		return (IOC_INVAL);
	if (mp->b_cont == NULL)
		return (IOC_INVAL);
	ppd = (nge_peekpoke_t *)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters
	 */
	switch (ppd->pp_acc_space) {
	default:
		return (IOC_INVAL);

	case NGE_PP_SPACE_CFG:
		/*
		 * Config space
		 */
		sizemask = 8|4|2|1;
		mem_va = 0;
		maxoff = PCI_CONF_HDR_SIZE;
		ppfn = peek ? nge_chip_peek_cfg : nge_chip_poke_cfg;
		break;

	case NGE_PP_SPACE_REG:
		/*
		 * Memory-mapped I/O space
		 */
		sizemask = 8|4|2|1;
		mem_va = 0;
		maxoff = NGE_REG_SIZE;
		ppfn = peek ? nge_chip_peek_reg : nge_chip_poke_reg;
		break;

	case NGE_PP_SPACE_MII:
		sizemask = 4|2|1;
		mem_va = 0;
		maxoff = NGE_MII_SIZE;
		ppfn = peek ? nge_chip_peek_mii : nge_chip_poke_mii;
		break;

	case NGE_PP_SPACE_SEEPROM:
		sizemask = 4|2|1;
		mem_va = 0;
		maxoff = NGE_SEEROM_SIZE;
		ppfn = peek ? nge_chip_peek_seeprom : nge_chip_poke_seeprom;
		break;
	}

	switch (ppd->pp_acc_size) {
	default:
		return (IOC_INVAL);

	case 8:
	case 4:
	case 2:
	case 1:
		if ((ppd->pp_acc_size & sizemask) == 0)
			return (IOC_INVAL);
		break;
	}

	if ((ppd->pp_acc_offset % ppd->pp_acc_size) != 0)
		return (IOC_INVAL);

	if (ppd->pp_acc_offset >= maxoff)
		return (IOC_INVAL);

	if (ppd->pp_acc_offset+ppd->pp_acc_size > maxoff)
		return (IOC_INVAL);

	/*
	 * All OK - go do it!
	 */
	ppd->pp_acc_offset += mem_va;
	if (ppfn)
		err = (*ppfn)(ngep, ppd);
	if (err != DDI_SUCCESS)
		return (IOC_INVAL);
	return (peek ? IOC_REPLY : IOC_ACK);
}

static enum ioc_reply nge_diag_ioctl(nge_t *ngep, int cmd, mblk_t *mp,
					struct iocblk *iocp);
#pragma	no_inline(nge_diag_ioctl)

static enum ioc_reply
nge_diag_ioctl(nge_t *ngep, int cmd, mblk_t *mp, struct iocblk *iocp)
{
	ASSERT(mutex_owned(ngep->genlock));

	switch (cmd) {
	default:
		nge_error(ngep, "nge_diag_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case NGE_DIAG:
		return (IOC_ACK);

	case NGE_PEEK:
	case NGE_POKE:
		return (nge_pp_ioctl(ngep, cmd, mp, iocp));

	case NGE_PHY_RESET:
		return (IOC_RESTART_ACK);

	case NGE_SOFT_RESET:
	case NGE_HARD_RESET:
		return (IOC_ACK);
	}

	/* NOTREACHED */
}

enum ioc_reply
nge_chip_ioctl(nge_t *ngep, mblk_t *mp, struct iocblk *iocp)
{
	int cmd;

	ASSERT(mutex_owned(ngep->genlock));

	cmd = iocp->ioc_cmd;

	switch (cmd) {
	default:
		return (IOC_INVAL);

	case NGE_DIAG:
	case NGE_PEEK:
	case NGE_POKE:
	case NGE_PHY_RESET:
	case NGE_SOFT_RESET:
	case NGE_HARD_RESET:
#if	NGE_DEBUGGING
		return (nge_diag_ioctl(ngep, cmd, mp, iocp));
#else
		return (IOC_INVAL);
#endif

	case NGE_MII_READ:
	case NGE_MII_WRITE:
		return (IOC_INVAL);

#if	NGE_SEE_IO32
	case NGE_SEE_READ:
	case NGE_SEE_WRITE:
		return (IOC_INVAL);
#endif

#if	NGE_FLASH_IO32
	case NGE_FLASH_READ:
	case NGE_FLASH_WRITE:
		return (IOC_INVAL);
#endif
	}
}
