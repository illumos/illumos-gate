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

#include <hxge_impl.h>
#include <hpi_pfc.h>

#define	TCAM_COMPLETION_TRY_COUNT	10
#define	HXGE_VLAN_TABLE_ENTRIES		128
#define	HXGE_PFC_INT_STATUS_CLEAR	0x7ULL

static uint64_t
hpi_pfc_tcam_check_completion(hpi_handle_t handle, tcam_op_t op_type)
{
	uint32_t	try_counter, tcam_delay = 10;
	pfc_tcam_ctrl_t	tctl;

	try_counter = TCAM_COMPLETION_TRY_COUNT;

	switch (op_type) {
	case TCAM_RWC_STAT:
		READ_TCAM_REG_CTL(handle, &tctl.value);
		while ((try_counter) &&
		    (tctl.bits.status != TCAM_CTL_RWC_RWC_STAT)) {
			try_counter--;
			HXGE_DELAY(tcam_delay);
			READ_TCAM_REG_CTL(handle, &tctl.value);
		}

		if (!try_counter) {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    " TCAM RWC_STAT operation"
			    " failed to complete \n"));
			return (HPI_PFC_TCAM_HW_ERROR);
		}

		tctl.value = 0;
		break;
	case TCAM_RWC_MATCH:
		READ_TCAM_REG_CTL(handle, &tctl.value);

		while ((try_counter) &&
		    (tctl.bits.match != TCAM_CTL_RWC_RWC_MATCH)) {
			try_counter--;
			HXGE_DELAY(tcam_delay);
			READ_TCAM_REG_CTL(handle, &tctl.value);
		}

		if (!try_counter) {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    " TCAM Match operationfailed to find match \n"));
		}

		break;
	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " Invalid TCAM completion Request \n"));
		return (HPI_PFC_ERROR | HPI_TCAM_ERROR | OPCODE_INVALID);
	}

	return (tctl.value);
}

hpi_status_t
hpi_pfc_tcam_entry_read(hpi_handle_t handle, uint32_t location,
    hxge_tcam_entry_t *tcam_ptr)
{
	pfc_tcam_ctrl_t tctl;
	pfc_tcam_ctrl_t tctl_rv;

	/*
	 * Hydra doesn't allow to read TCAM entries. Use compare instead.
	 */
	WRITE_TCAM_REG_MASK0(handle, tcam_ptr->mask0);
	WRITE_TCAM_REG_MASK1(handle, tcam_ptr->mask1);

	WRITE_TCAM_REG_KEY0(handle, tcam_ptr->key0);
	WRITE_TCAM_REG_KEY1(handle, tcam_ptr->key1);

	tctl.value = 0;
	tctl.bits.addr = location;
	tctl.bits.cmd = TCAM_CTL_RWC_TCAM_CMP;

	WRITE_TCAM_REG_CTL(handle, tctl.value);

	tctl_rv.value = hpi_pfc_tcam_check_completion(handle, TCAM_RWC_MATCH);

	if (tctl_rv.bits.match)
		return (HPI_SUCCESS);
	else
		return (HPI_FAILURE);
}

hpi_status_t
hpi_pfc_tcam_asc_ram_entry_read(hpi_handle_t handle,
    uint32_t location, uint64_t *ram_data)
{
	uint64_t tcam_stat;
	pfc_tcam_ctrl_t tctl;

	tctl.value = 0;
	tctl.bits.addr = location;
	tctl.bits.cmd = TCAM_CTL_RWC_RAM_RD;

	WRITE_TCAM_REG_CTL(handle, tctl.value);

	tcam_stat = hpi_pfc_tcam_check_completion(handle, TCAM_RWC_STAT);

	if (tcam_stat & HPI_FAILURE) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "TCAM RAM read failed loc %d \n", location));
		return (HPI_PFC_ASC_RAM_RD_ERROR);
	}

	READ_TCAM_REG_KEY0(handle, ram_data);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_tcam_asc_ram_entry_write(hpi_handle_t handle, uint32_t location,
    uint64_t ram_data)
{
	uint64_t	tcam_stat = 0;
	pfc_tcam_ctrl_t	tctl;

	WRITE_TCAM_REG_KEY0(handle, ram_data);

	tctl.value = 0;
	tctl.bits.addr = location;
	tctl.bits.cmd = TCAM_CTL_RWC_RAM_WR;

	HPI_DEBUG_MSG((handle.function, HPI_PFC_CTL,
	    " tcam ascr write: location %x data %llx ctl value %llx \n",
	    location, ram_data, tctl.value));
	WRITE_TCAM_REG_CTL(handle, tctl.value);
	tcam_stat = hpi_pfc_tcam_check_completion(handle, TCAM_RWC_STAT);

	if (tcam_stat & HPI_FAILURE) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "TCAM RAM write failed loc %d \n", location));
		return (HPI_PFC_ASC_RAM_WR_ERROR);
	}

	return (HPI_SUCCESS);
}

static hpi_status_t
hpi_pfc_set_config(hpi_handle_t handle, pfc_config_t config)
{
	uint64_t offset;

	offset = PFC_CONFIG;
	REG_PIO_WRITE64(handle, offset, config.value);

	return (HPI_SUCCESS);
}

static hpi_status_t
hpi_pfc_get_config(hpi_handle_t handle, pfc_config_t *configp)
{
	uint64_t offset;

	offset = PFC_CONFIG;
	REG_PIO_READ64(handle, offset, &configp->value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_tcam_enable(hpi_handle_t handle, boolean_t tcam)
{
	pfc_config_t	config;

	/*
	 * Read the register first.
	 */
	(void) hpi_pfc_get_config(handle, &config);

	if (tcam)
		config.bits.tcam_en = 1;
	else
		config.bits.tcam_en = 0;

	return (hpi_pfc_set_config(handle, config));
}

hpi_status_t
hpi_pfc_set_l2_hash(hpi_handle_t handle, boolean_t l2_hash)
{
	pfc_config_t	config;

	/*
	 * Read the register first.
	 */
	(void) hpi_pfc_get_config(handle, &config);

	if (l2_hash)
		config.bits.l2_hash_en = 1;
	else
		config.bits.l2_hash_en = 0;

	return (hpi_pfc_set_config(handle, config));
}

hpi_status_t
hpi_pfc_set_tcp_cksum(hpi_handle_t handle, boolean_t cksum)
{
	pfc_config_t	config;

	/*
	 * Read the register first.
	 */
	(void) hpi_pfc_get_config(handle, &config);

	if (cksum)
		config.bits.tcp_cs_en = 1;
	else
		config.bits.tcp_cs_en = 0;

	return (hpi_pfc_set_config(handle, config));
}

hpi_status_t
hpi_pfc_set_default_dma(hpi_handle_t handle, uint32_t dma_channel_no)
{
	pfc_config_t	config;

	(void) hpi_pfc_get_config(handle, &config);

	if (dma_channel_no > PFC_MAX_DMA_CHANNELS)
		return (HPI_FAILURE);

	config.bits.default_dma = dma_channel_no;

	return (hpi_pfc_set_config(handle, config));
}

hpi_status_t
hpi_pfc_mac_addr_enable(hpi_handle_t handle, uint32_t slot)
{
	pfc_config_t	config;
	uint32_t	bit;

	if (slot >= PFC_N_MAC_ADDRESSES) {
		return (HPI_FAILURE);
	}

	(void) hpi_pfc_get_config(handle, &config);

	if (slot < 24) {
		bit = 1 << slot;
		config.bits.mac_addr_en_l = config.bits.mac_addr_en_l | bit;
	} else {
		bit = 1 << (slot - 24);
		config.bits.mac_addr_en = config.bits.mac_addr_en | bit;
	}

	return (hpi_pfc_set_config(handle, config));
}

hpi_status_t
hpi_pfc_mac_addr_disable(hpi_handle_t handle, uint32_t slot)
{
	pfc_config_t	config;
	uint32_t	bit;

	if (slot >= PFC_N_MAC_ADDRESSES) {
		return (HPI_FAILURE);
	}

	(void) hpi_pfc_get_config(handle, &config);

	if (slot < 24) {
		bit = 1 << slot;
		config.bits.mac_addr_en_l = config.bits.mac_addr_en_l & ~bit;
	} else {
		bit = 1 << (slot - 24);
		config.bits.mac_addr_en = config.bits.mac_addr_en & ~bit;
	}

	return (hpi_pfc_set_config(handle, config));
}

hpi_status_t
hpi_pfc_set_force_csum(hpi_handle_t handle, boolean_t force)
{
	pfc_config_t	config;

	(void) hpi_pfc_get_config(handle, &config);

	if (force)
		config.bits.force_cs_en = 1;
	else
		config.bits.force_cs_en = 0;

	return (hpi_pfc_set_config(handle, config));
}

hpi_status_t
hpi_pfc_cfg_vlan_table_clear(hpi_handle_t handle)
{
	int			i;
	int			offset;
	int			step = 8;
	pfc_vlan_table_t	table_entry;

	table_entry.value = 0;
	for (i = 0; i < HXGE_VLAN_TABLE_ENTRIES; i++) {
		table_entry.bits.member = 0;
		offset = PFC_VLAN_TABLE + i * step;
		REG_PIO_WRITE64(handle, offset, table_entry.value);
	}

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_cfg_vlan_table_entry_clear(hpi_handle_t handle, vlan_id_t vlan_id)
{
	uint64_t		offset;
	pfc_vlan_table_t	vlan_tbl_entry;
	uint64_t		bit;

	/*
	 * Assumes that the hardware will generate the new parity
	 * data.
	 */
	offset = PFC_VLAN_REG_OFFSET(vlan_id);
	REG_PIO_READ64(handle, offset, (uint64_t *)&vlan_tbl_entry.value);

	bit = PFC_VLAN_BIT_OFFSET(vlan_id);
	bit = 1 << bit;
	vlan_tbl_entry.bits.member = vlan_tbl_entry.bits.member & ~bit;

	REG_PIO_WRITE64(handle, offset, vlan_tbl_entry.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_cfg_vlan_table_entry_set(hpi_handle_t handle, vlan_id_t vlan_id)
{
	uint64_t		offset;
	pfc_vlan_table_t	vlan_tbl_entry;
	uint64_t		bit;

	/*
	 * Assumes that the hardware will generate the new parity
	 * data.
	 */
	offset = PFC_VLAN_REG_OFFSET(vlan_id);
	REG_PIO_READ64(handle, offset, (uint64_t *)&vlan_tbl_entry.value);

	bit = PFC_VLAN_BIT_OFFSET(vlan_id);
	bit = 1 << bit;
	vlan_tbl_entry.bits.member = vlan_tbl_entry.bits.member | bit;

	REG_PIO_WRITE64(handle, offset, vlan_tbl_entry.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_cfg_vlan_control_set(hpi_handle_t handle, boolean_t parity,
    boolean_t valid, vlan_id_t vlan_id)
{
	pfc_vlan_ctrl_t	vlan_control;

	vlan_control.value = 0;

	if (parity)
		vlan_control.bits.par_en = 1;
	else
		vlan_control.bits.par_en = 0;

	if (valid)
		vlan_control.bits.valid = 1;
	else
		vlan_control.bits.valid = 0;

	vlan_control.bits.id = vlan_id;

	REG_PIO_WRITE64(handle, PFC_VLAN_CTRL, vlan_control.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_vlan_parity_log(hpi_handle_t handle, pfc_vlan_par_err_log_t *logp)
{
	uint64_t offset;

	offset = PFC_VLAN_PAR_ERR_LOG;
	REG_PIO_READ64(handle, offset, &logp->value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_mac_address(hpi_handle_t handle, uint32_t slot, uint64_t address)
{
	uint64_t		offset;
	uint64_t		moffset;
	pfc_mac_addr_mask_t	mask;
	pfc_mac_addr_t		addr;

	if (slot >= PFC_N_MAC_ADDRESSES)
		return (HPI_FAILURE);

	offset = PFC_MAC_ADDRESS(slot);
	moffset = PFC_MAC_ADDRESS_MASK(slot);

	addr.bits.addr = address >> 32;
	addr.bits.addr_l = address & 0xffffffff;
	mask.bits.mask = 0x0;
	mask.bits.mask_l = 0x0;

	REG_PIO_WRITE64(handle, offset, addr.value);
	REG_PIO_WRITE64(handle, moffset, mask.value);

	return (hpi_pfc_mac_addr_enable(handle, slot));
}

hpi_status_t
hpi_pfc_clear_mac_address(hpi_handle_t handle, uint32_t slot)
{
	uint64_t offset, moffset;
	uint64_t zaddr = 0x0ULL;
	uint64_t zmask = 0x0ULL;

	if (slot >= PFC_N_MAC_ADDRESSES)
		return (HPI_FAILURE);

	(void) hpi_pfc_mac_addr_disable(handle, slot);

	offset = PFC_MAC_ADDRESS(slot);
	moffset = PFC_MAC_ADDRESS_MASK(slot);

	REG_PIO_WRITE64(handle, offset, zaddr);
	REG_PIO_WRITE64(handle, moffset, zmask);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_clear_multicast_hash_table(hpi_handle_t handle, uint32_t slot)
{
	uint64_t offset;

	if (slot >= PFC_N_MAC_ADDRESSES)
		return (HPI_FAILURE);

	offset = PFC_HASH_ADDR(slot);
	REG_PIO_WRITE64(handle, offset, 0ULL);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_multicast_hash_table(hpi_handle_t handle, uint32_t slot,
	uint64_t address)
{
	uint64_t offset;

	if (slot >= PFC_N_MAC_ADDRESSES)
		return (HPI_FAILURE);

	offset = PFC_HASH_ADDR(slot);
	REG_PIO_WRITE64(handle, offset, address);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_l2_class_slot(hpi_handle_t handle, uint16_t etype, boolean_t valid,
    int slot)
{
	pfc_l2_class_config_t	l2_config;
	uint64_t		offset;

	if (slot >= PFC_N_MAC_ADDRESSES)
		return (HPI_FAILURE);

	l2_config.value = 0;

	if (valid)
		l2_config.bits.valid = 1;
	else
		l2_config.bits.valid = 0;

	l2_config.bits.etype = etype;
	l2_config.bits.rsrvd = 0;

	offset = PFC_L2_CONFIG(slot);
	REG_PIO_WRITE64(handle, offset, l2_config.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_l3_class_config(hpi_handle_t handle, tcam_class_t slot,
    tcam_key_cfg_t cfg)
{
	pfc_l3_class_config_t	l3_config;
	uint64_t		offset;

	if (slot >= PFC_N_MAC_ADDRESSES)
		return (HPI_FAILURE);

	l3_config.value = 0;

	if (cfg.lookup_enable)
		l3_config.bits.tsel = 1;
	else
		l3_config.bits.tsel = 0;

	if (cfg.discard)
		l3_config.bits.discard = 1;
	else
		l3_config.bits.discard = 0;

	offset = PFC_L3_CONFIG(slot);
	REG_PIO_WRITE64(handle, offset, l3_config.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_l3_class_config(hpi_handle_t handle, tcam_class_t slot,
    tcam_key_cfg_t *cfg)
{
	pfc_l3_class_config_t	l3_config;
	uint64_t		offset;

	if (slot >= PFC_N_MAC_ADDRESSES)
		return (HPI_FAILURE);

	offset = PFC_L3_CONFIG(slot);
	REG_PIO_READ64(handle, offset, &l3_config.value);

	if (l3_config.bits.tsel)
		cfg->lookup_enable = 1;
	else
		cfg->lookup_enable = 0;

	if (l3_config.bits.discard)
		cfg->discard = 1;
	else
		cfg->discard = 0;

	return (HPI_SUCCESS);
}

static hpi_status_t
hpi_pfc_set_tcam_control(hpi_handle_t handle, pfc_tcam_ctrl_t *tcontrolp)
{
	uint64_t offset;

	offset = PFC_TCAM_CTRL;
	REG_PIO_WRITE64(handle, offset, tcontrolp->value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_tcam_entry_invalidate(hpi_handle_t handle, uint32_t location)
{
	hxge_tcam_entry_t	tcam_ptr;

	(void) memset(&tcam_ptr, 0, sizeof (hxge_tcam_entry_t));
	(void) hpi_pfc_tcam_entry_write(handle, location, &tcam_ptr);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_tcam_invalidate_all(hpi_handle_t handle)
{
	int		i;
	pfc_tcam_ctrl_t	tcontrol;

	tcontrol.value = 0;
	for (i = 0; i < PFC_N_TCAM_ENTRIES; i++) {
		(void) hpi_pfc_set_tcam_control(handle, &tcontrol);
		(void) hpi_pfc_tcam_entry_invalidate(handle, i);
	}

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_tcam_entry_write(hpi_handle_t handle, uint32_t location,
    hxge_tcam_entry_t *tcam_ptr)
{
	uint64_t	tcam_stat;
	pfc_tcam_ctrl_t	tctl;

	WRITE_TCAM_REG_MASK0(handle, tcam_ptr->mask0);
	WRITE_TCAM_REG_MASK1(handle, tcam_ptr->mask1);

	WRITE_TCAM_REG_KEY0(handle, tcam_ptr->key0);
	WRITE_TCAM_REG_KEY1(handle, tcam_ptr->key1);

	HPI_DEBUG_MSG((handle.function, HPI_PFC_CTL,
	    " tcam write: location %x\n key:  %llx %llx\n mask: %llx %llx\n",
	    location, tcam_ptr->key0, tcam_ptr->key1,
	    tcam_ptr->mask0, tcam_ptr->mask1));

	tctl.value = 0;
	tctl.bits.addr = location;
	tctl.bits.cmd = TCAM_CTL_RWC_TCAM_WR;

	HPI_DEBUG_MSG((handle.function, HPI_PFC_CTL,
	    " tcam write: ctl value %llx \n", tctl.value));

	WRITE_TCAM_REG_CTL(handle, tctl.value);

	tcam_stat = hpi_pfc_tcam_check_completion(handle, TCAM_RWC_STAT);

	if (tcam_stat & HPI_FAILURE) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "TCAM Write failed loc %d \n", location));
		return (HPI_PFC_TCAM_WR_ERROR);
	}

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_tcam_parity_log(hpi_handle_t handle, pfc_tcam_par_err_log_t *logp)
{
	uint64_t offset;

	offset = PFC_TCAM_PAR_ERR_LOG;
	REG_PIO_READ64(handle, offset, &logp->value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_tcam_auto_init(hpi_handle_t handle, pfc_auto_init_t *autoinitp)
{
	uint64_t offset;

	offset = PFC_AUTO_INIT;
	REG_PIO_READ64(handle, offset, &autoinitp->value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_tcp_control_discard(hpi_handle_t handle, boolean_t discard)
{
	uint64_t	offset;
	tcp_ctrl_mask_t	tcp;

	tcp.value = 0;

	offset = TCP_CTRL_MASK;
	REG_PIO_READ64(handle, offset, &tcp.value);

	if (discard)
		tcp.bits.discard = 1;
	else
		tcp.bits.discard = 0;

	REG_PIO_WRITE64(handle, offset, tcp.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_tcp_control_fin(hpi_handle_t handle, boolean_t fin)
{
	uint64_t	offset;
	tcp_ctrl_mask_t	tcp;

	tcp.value = 0;

	offset = TCP_CTRL_MASK;
	REG_PIO_READ64(handle, offset, &tcp.value);

	if (fin)
		tcp.bits.fin = 1;
	else
		tcp.bits.fin = 0;

	REG_PIO_WRITE64(handle, offset, tcp.value);
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_tcp_control_syn(hpi_handle_t handle, boolean_t syn)
{
	uint64_t	offset;
	tcp_ctrl_mask_t	tcp;

	tcp.value = 0;

	offset = TCP_CTRL_MASK;
	REG_PIO_READ64(handle, offset, &tcp.value);

	if (syn)
		tcp.bits.syn = 1;
	else
		tcp.bits.syn = 0;

	REG_PIO_WRITE64(handle, offset, tcp.value);
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_tcp_control_rst(hpi_handle_t handle, boolean_t rst)
{
	uint64_t	offset;
	tcp_ctrl_mask_t	tcp;

	tcp.value = 0;

	offset = TCP_CTRL_MASK;
	REG_PIO_READ64(handle, offset, &tcp.value);

	if (rst)
		tcp.bits.rst = 1;
	else
		tcp.bits.rst = 0;

	REG_PIO_WRITE64(handle, offset, tcp.value);
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_tcp_control_psh(hpi_handle_t handle, boolean_t push)
{
	uint64_t	offset;
	tcp_ctrl_mask_t	tcp;

	tcp.value = 0;

	offset = TCP_CTRL_MASK;
	REG_PIO_READ64(handle, offset, &tcp.value);

	if (push)
		tcp.bits.psh = 1;
	else
		tcp.bits.psh = 0;

	REG_PIO_WRITE64(handle, offset, tcp.value);
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_tcp_control_ack(hpi_handle_t handle, boolean_t ack)
{
	uint64_t	offset;
	tcp_ctrl_mask_t	tcp;

	tcp.value = 0;

	offset = TCP_CTRL_MASK;
	REG_PIO_READ64(handle, offset, &tcp.value);

	if (ack)
		tcp.bits.ack = 1;
	else
		tcp.bits.ack = 0;

	REG_PIO_WRITE64(handle, offset, tcp.value);
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_hash_seed_value(hpi_handle_t handle, uint32_t seed)
{
	uint64_t	offset;
	src_hash_val_t	src_hash_seed;

	src_hash_seed.value = 0;
	src_hash_seed.bits.seed = seed;

	offset = SRC_HASH_VAL;
	REG_PIO_WRITE64(handle, offset, src_hash_seed.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_interrupt_status(hpi_handle_t handle, pfc_int_status_t *statusp)
{
	uint64_t offset;

	offset = PFC_INT_STATUS;
	REG_PIO_READ64(handle, offset, &statusp->value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_clear_interrupt_status(hpi_handle_t handle)
{
	uint64_t offset;

	offset = PFC_INT_STATUS;
	REG_PIO_WRITE64(handle, offset, HXGE_PFC_INT_STATUS_CLEAR);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_interrupt_mask(hpi_handle_t handle, boolean_t drop,
	boolean_t tcam_parity_error, boolean_t vlan_parity_error)
{
	pfc_int_mask_t	mask;
	uint64_t	offset;

	mask.value = 0;

	if (drop)
		mask.bits.pkt_drop_mask = 1;
	else
		mask.bits.pkt_drop_mask = 0;

	if (tcam_parity_error)
		mask.bits.tcam_parity_err_mask = 1;
	else
		mask.bits.tcam_parity_err_mask = 0;

	if (vlan_parity_error)
		mask.bits.vlan_parity_err_mask = 1;
	else
		mask.bits.vlan_parity_err_mask = 0;

	offset = PFC_INT_MASK;
	REG_PIO_WRITE64(handle, offset, mask.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_drop_log(hpi_handle_t handle, pfc_drop_log_t *logp)
{
	uint64_t offset;

	offset = PFC_DROP_LOG;
	REG_PIO_READ64(handle, offset, &logp->value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_drop_log_mask(hpi_handle_t handle, boolean_t vlan_drop,
    boolean_t tcam_drop, boolean_t class_code_drop, boolean_t l2_addr_drop,
    boolean_t tcp_ctrl_drop)
{
	uint64_t		offset;
	pfc_drop_log_mask_t	log;

	log.value = 0;

	if (vlan_drop)
		log.bits.vlan_drop_mask = 1;
	if (tcam_drop)
		log.bits.tcam_drop_mask = 1;
	if (class_code_drop)
		log.bits.class_code_drop_mask = 1;
	if (l2_addr_drop)
		log.bits.l2_addr_drop_mask = 1;
	if (tcp_ctrl_drop)
		log.bits.tcp_ctrl_drop_mask = 1;

	offset = PFC_DROP_LOG_MASK;
	REG_PIO_WRITE64(handle, offset, log.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_bad_csum_counter(hpi_handle_t handle, uint64_t *countp)
{
	uint64_t offset;

	offset = PFC_BAD_CS_COUNTER;
	REG_PIO_READ64(handle, offset, countp);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_drop_counter(hpi_handle_t handle, uint64_t *countp)
{
	uint64_t offset;

	offset = PFC_DROP_COUNTER;
	REG_PIO_READ64(handle, offset, countp);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_get_number_mac_addrs(hpi_handle_t handle, uint32_t *n_of_addrs)
{
	HXGE_REG_RD32(handle, HCR_REG + HCR_N_MAC_ADDRS, n_of_addrs);
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_mac_addr_get_i(hpi_handle_t handle, uint8_t *data, int slot)
{
	uint32_t step = sizeof (uint32_t);
	uint32_t addr_hi = 0, addr_lo = 0;

	if (slot >= PFC_N_MAC_ADDRESSES)
		return (HPI_FAILURE);

	/*
	 * Read the MAC address out of the SPROM at the blade's
	 * specific location.
	 */
	HXGE_REG_RD32(handle, HCR_REG + HCR_ADDR_LO + slot * step, &addr_lo);
	HXGE_REG_RD32(handle, HCR_REG + HCR_ADDR_HI + slot * step, &addr_hi);

	data[0] = addr_lo & 0x000000ff;
	data[1] = (addr_lo & 0x0000ff00) >> 8;
	data[2] = (addr_lo & 0x00ff0000) >> 16;
	data[3] = (addr_lo & 0xff000000) >> 24;
	data[4] = (addr_hi & 0x0000000ff);
	data[5] = (addr_hi & 0x00000ff00) >> 8;

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_num_macs_get(hpi_handle_t handle, uint8_t *data)
{
	uint8_t	addr[6];
	uint8_t	num = 0;
	int	i;

	for (i = 0; i < 16; i++) {
		(void) hpi_pfc_mac_addr_get_i(handle, addr, i);
		if (addr[0] || addr[1] || addr[2] ||
		    addr[3] || addr[4] || addr[5])
			num++;
	}

	*data = num;

	return (HPI_SUCCESS);
}
