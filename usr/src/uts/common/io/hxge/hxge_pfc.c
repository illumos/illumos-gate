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
#include <hxge_classify.h>
#include <hxge_pfc.h>
#include <hpi_pfc.h>
#include <sys/ethernet.h>

static uint32_t crc32_mchash(p_ether_addr_t addr);
static hxge_status_t hxge_pfc_load_hash_table(p_hxge_t hxgep);
static uint32_t hxge_get_blade_id(p_hxge_t hxgep);
static hxge_status_t hxge_tcam_default_add_entry(p_hxge_t hxgep,
	tcam_class_t class);
static hxge_status_t hxge_tcam_default_config(p_hxge_t hxgep);

hxge_status_t
hxge_classify_init(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_classify_init"));

	status = hxge_classify_init_sw(hxgep);
	if (status != HXGE_OK)
		return (status);

	status = hxge_classify_init_hw(hxgep);
	if (status != HXGE_OK) {
		(void) hxge_classify_exit_sw(hxgep);
		return (status);
	}

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_classify_init"));

	return (HXGE_OK);
}

hxge_status_t
hxge_classify_uninit(p_hxge_t hxgep)
{
	return (hxge_classify_exit_sw(hxgep));
}

static hxge_status_t
hxge_tcam_dump_entry(p_hxge_t hxgep, uint32_t location)
{
	hxge_tcam_entry_t	tcam_rdptr;
	uint64_t		asc_ram = 0;
	hpi_handle_t		handle;
	hpi_status_t		status;

	handle = hxgep->hpi_reg_handle;

	/* Retrieve the saved entry */
	bcopy((void *)&hxgep->classifier.tcam_entries[location].tce,
	    (void *)&tcam_rdptr, sizeof (hxge_tcam_entry_t));

	/* Compare the entry */
	status = hpi_pfc_tcam_entry_read(handle, location, &tcam_rdptr);
	if (status == HPI_FAILURE) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_tcam_dump_entry: tcam read failed at location %d ",
		    location));
		return (HXGE_ERROR);
	}

	status = hpi_pfc_tcam_asc_ram_entry_read(handle, location, &asc_ram);

	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "location %x\n"
	    " key:  %llx %llx\n mask: %llx %llx\n ASC RAM %llx \n", location,
	    tcam_rdptr.key0, tcam_rdptr.key1,
	    tcam_rdptr.mask0, tcam_rdptr.mask1, asc_ram));
	return (HXGE_OK);
}

void
hxge_get_tcam(p_hxge_t hxgep, p_mblk_t mp)
{
	uint32_t	tcam_loc;
	uint32_t	*lptr;
	int		location;
	int		start_location = 0;
	int		stop_location = hxgep->classifier.tcam_size;

	lptr = (uint32_t *)mp->b_rptr;
	location = *lptr;

	if ((location >= hxgep->classifier.tcam_size) || (location < -1)) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_tcam_dump: Invalid location %d \n", location));
		return;
	}
	if (location == -1) {
		start_location = 0;
		stop_location = hxgep->classifier.tcam_size;
	} else {
		start_location = location;
		stop_location = location + 1;
	}
	for (tcam_loc = start_location; tcam_loc < stop_location; tcam_loc++)
		(void) hxge_tcam_dump_entry(hxgep, tcam_loc);
}

/*ARGSUSED*/
static hxge_status_t
hxge_add_tcam_entry(p_hxge_t hxgep, flow_resource_t *flow_res)
{
	return (HXGE_OK);
}

void
hxge_put_tcam(p_hxge_t hxgep, p_mblk_t mp)
{
	flow_resource_t *fs;
	fs = (flow_resource_t *)mp->b_rptr;

	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "hxge_put_tcam addr fs $%p  type %x offset %x",
	    fs, fs->flow_spec.flow_type, fs->channel_cookie));

	(void) hxge_add_tcam_entry(hxgep, fs);
}

static uint32_t
hxge_get_blade_id(p_hxge_t hxgep)
{
	phy_debug_training_vec_t	blade_id;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_get_blade_id"));
	HXGE_REG_RD32(hxgep->hpi_reg_handle, PHY_DEBUG_TRAINING_VEC,
	    &blade_id.value);
	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_get_blade_id: id = %d",
	    blade_id.bits.bld_num));

	return (blade_id.bits.bld_num);
}

static hxge_status_t
hxge_tcam_default_add_entry(p_hxge_t hxgep, tcam_class_t class)
{
	hpi_status_t		rs = HPI_SUCCESS;
	uint32_t		location;
	hxge_tcam_entry_t	entry;
	hxge_tcam_spread_t	*key = NULL;
	hxge_tcam_spread_t	*mask = NULL;
	hpi_handle_t		handle;
	p_hxge_hw_list_t	hw_p;

	if ((hw_p = hxgep->hxge_hw_p) == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_tcam_default_add_entry: common hardware not set"));
		return (HXGE_ERROR);
	}

	bzero(&entry, sizeof (hxge_tcam_entry_t));

	/*
	 * The class id and blade id are common for all classes
	 * Only use the blade id for matching and the rest are wild cards.
	 * This will allow one TCAM entry to match all traffic in order
	 * to spread the traffic using source hash.
	 */
	key = &entry.key.spread;
	mask = &entry.mask.spread;

	key->blade_id = hxge_get_blade_id(hxgep);

	mask->class_code = 0xf;
	mask->class_code_l = 0x1;
	mask->blade_id = 0;
	mask->wild1 = 0x7ffffff;
	mask->wild = 0xffffffff;
	mask->wild_l = 0xffffffff;

	location = class;

	handle = hxgep->hpi_reg_handle;

	MUTEX_ENTER(&hw_p->hxge_tcam_lock);
	rs = hpi_pfc_tcam_entry_write(handle, location, &entry);
	if (rs & HPI_PFC_ERROR) {
		MUTEX_EXIT(&hw_p->hxge_tcam_lock);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_tcam_default_add_entry tcam entry write"
		    " failed for location %d", location));
		return (HXGE_ERROR);
	}

	/* Add the associative portion */
	entry.match_action.value = 0;

	/* Use source hash to spread traffic */
	entry.match_action.bits.channel_d = 0;
	entry.match_action.bits.channel_c = 1;
	entry.match_action.bits.channel_b = 2;
	entry.match_action.bits.channel_a = 3;
	entry.match_action.bits.source_hash = 1;
	entry.match_action.bits.discard = 0;

	rs = hpi_pfc_tcam_asc_ram_entry_write(handle,
	    location, entry.match_action.value);
	if (rs & HPI_PFC_ERROR) {
		MUTEX_EXIT(&hw_p->hxge_tcam_lock);
		HXGE_DEBUG_MSG((hxgep, PFC_CTL,
		    " hxge_tcam_default_add_entry tcam entry write"
		    " failed for ASC RAM location %d", location));
		return (HXGE_ERROR);
	}

	bcopy((void *) &entry,
	    (void *) &hxgep->classifier.tcam_entries[location].tce,
	    sizeof (hxge_tcam_entry_t));

	MUTEX_EXIT(&hw_p->hxge_tcam_lock);

	return (HXGE_OK);
}

/*
 * Configure one TCAM entry for each class and make it match
 * everything within the class in order to spread the traffic
 * among the DMA channels based on the source hash.
 *
 * This is the default for now. This may change when Crossbow is
 * available for configuring TCAM.
 */
static hxge_status_t
hxge_tcam_default_config(p_hxge_t hxgep)
{
	uint8_t		class;
	uint32_t	class_config;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_tcam_default_config"));

	/*
	 * Add TCAM and its associative ram entries
	 * A wild card will be used for the class code in order to match
	 * any classes.
	 */
	class = 0;
	status = hxge_tcam_default_add_entry(hxgep, class);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_tcam_default_config "
		    "hxge_tcam_default_add_entry failed class %d ",
		    class));
		return (HXGE_ERROR);
	}

	/* Enable the classes */
	for (class = TCAM_CLASS_TCP_IPV4;
	    class <= TCAM_CLASS_SCTP_IPV6; class++) {
		/*
		 * By default, it is set to HXGE_CLASS_TCAM_LOOKUP in
		 * hxge_ndd.c. It may be overwritten in hxge.conf.
		 */
		class_config = hxgep->class_config.class_cfg[class];

		status = hxge_pfc_ip_class_config(hxgep, class, class_config);
		if (status & HPI_PFC_ERROR) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "hxge_tcam_default_config "
			    "hxge_pfc_ip_class_config failed "
			    " class %d config %x ", class, class_config));
			return (HXGE_ERROR);
		}
	}

	status = hxge_pfc_config_tcam_enable(hxgep);

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_tcam_default_config"));

	return (status);
}

hxge_status_t
hxge_pfc_set_default_mac_addr(p_hxge_t hxgep)
{
	hxge_status_t status;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_pfc_set_default_mac_addr"));

	MUTEX_ENTER(&hxgep->ouraddr_lock);

	/*
	 * Set new interface local address and re-init device.
	 * This is destructive to any other streams attached
	 * to this device.
	 */
	RW_ENTER_WRITER(&hxgep->filter_lock);
	status = hxge_pfc_set_mac_address(hxgep,
	    HXGE_MAC_DEFAULT_ADDR_SLOT, &hxgep->ouraddr);
	RW_EXIT(&hxgep->filter_lock);

	MUTEX_EXIT(&hxgep->ouraddr_lock);

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_set_default_mac_addr"));
	return (status);
}

/*
 * Add a multicast address entry into the HW hash table
 */
hxge_status_t
hxge_add_mcast_addr(p_hxge_t hxgep, struct ether_addr *addrp)
{
	uint32_t	mchash;
	p_hash_filter_t	hash_filter;
	uint16_t	hash_bit;
	boolean_t	rx_init = B_FALSE;
	uint_t		j;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_add_mcast_addr"));

	RW_ENTER_WRITER(&hxgep->filter_lock);
	mchash = crc32_mchash(addrp);

	if (hxgep->hash_filter == NULL) {
		HXGE_DEBUG_MSG((NULL, STR_CTL,
		    "Allocating hash filter storage."));
		hxgep->hash_filter = KMEM_ZALLOC(sizeof (hash_filter_t),
		    KM_SLEEP);
	}

	hash_filter = hxgep->hash_filter;
	/*
	 * Note that mchash is an 8 bit value and thus 0 <= mchash <= 255.
	 * Consequently, 0 <= j <= 15 and 0 <= mchash % HASH_REG_WIDTH <= 15.
	 */
	j = mchash / HASH_REG_WIDTH;
	hash_bit = (1 << (mchash % HASH_REG_WIDTH));
	hash_filter->hash_filter_regs[j] |= hash_bit;

	hash_filter->hash_bit_ref_cnt[mchash]++;
	if (hash_filter->hash_bit_ref_cnt[mchash] == 1) {
		hash_filter->hash_ref_cnt++;
		rx_init = B_TRUE;
	}

	if (rx_init) {
		(void) hpi_pfc_set_l2_hash(hxgep->hpi_reg_handle, B_FALSE);
		(void) hxge_pfc_load_hash_table(hxgep);
		(void) hpi_pfc_set_l2_hash(hxgep->hpi_reg_handle, B_TRUE);
	}

	RW_EXIT(&hxgep->filter_lock);

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_add_mcast_addr"));

	return (HXGE_OK);
fail:
	RW_EXIT(&hxgep->filter_lock);
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "hxge_add_mcast_addr: "
	    "Unable to add multicast address"));

	return (status);
}

/*
 * Remove a multicast address entry from the HW hash table
 */
hxge_status_t
hxge_del_mcast_addr(p_hxge_t hxgep, struct ether_addr *addrp)
{
	uint32_t	mchash;
	p_hash_filter_t	hash_filter;
	uint16_t	hash_bit;
	boolean_t	rx_init = B_FALSE;
	uint_t		j;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_del_mcast_addr"));
	RW_ENTER_WRITER(&hxgep->filter_lock);
	mchash = crc32_mchash(addrp);
	if (hxgep->hash_filter == NULL) {
		HXGE_DEBUG_MSG((NULL, STR_CTL,
		    "Hash filter already de_allocated."));
		RW_EXIT(&hxgep->filter_lock);
		HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_del_mcast_addr"));
		return (HXGE_OK);
	}

	hash_filter = hxgep->hash_filter;
	hash_filter->hash_bit_ref_cnt[mchash]--;
	if (hash_filter->hash_bit_ref_cnt[mchash] == 0) {
		j = mchash / HASH_REG_WIDTH;
		hash_bit = (1 << (mchash % HASH_REG_WIDTH));
		hash_filter->hash_filter_regs[j] &= ~hash_bit;
		hash_filter->hash_ref_cnt--;
		rx_init = B_TRUE;
	}

	if (hash_filter->hash_ref_cnt == 0) {
		HXGE_DEBUG_MSG((NULL, STR_CTL,
		    "De-allocating hash filter storage."));
		KMEM_FREE(hash_filter, sizeof (hash_filter_t));
		hxgep->hash_filter = NULL;
	}

	if (rx_init) {
		(void) hpi_pfc_set_l2_hash(hxgep->hpi_reg_handle, B_FALSE);
		(void) hxge_pfc_load_hash_table(hxgep);

		/* Enable hash only if there are any hash entries */
		if (hxgep->hash_filter != NULL)
			(void) hpi_pfc_set_l2_hash(hxgep->hpi_reg_handle,
			    B_TRUE);
	}

	RW_EXIT(&hxgep->filter_lock);
	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_del_mcast_addr"));

	return (HXGE_OK);
fail:
	RW_EXIT(&hxgep->filter_lock);
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "hxge_del_mcast_addr: "
	    "Unable to remove multicast address"));

	return (status);
}

hxge_status_t
hxge_pfc_clear_mac_address(p_hxge_t hxgep, uint32_t slot)
{
	hpi_status_t status;

	status = hpi_pfc_clear_mac_address(hxgep->hpi_reg_handle, slot);
	if (status != HPI_SUCCESS)
		return (HXGE_ERROR);

	return (HXGE_OK);
}

hxge_status_t
hxge_pfc_set_mac_address(p_hxge_t hxgep, uint32_t slot,
    struct ether_addr *addrp)
{
	hpi_handle_t		handle;
	uint64_t		addr;
	hpi_status_t		hpi_status;
	uint8_t			*address = addrp->ether_addr_octet;
	uint64_t		tmp;
	int			i;

	if (hxgep->hxge_hw_p == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_set_mac_address: common hardware not set"));
		return (HXGE_ERROR);
	}

	/*
	 * Convert a byte array to a 48 bit value.
	 * Need to check endianess if in doubt
	 */
	addr = 0;
	for (i = 0; i < ETHERADDRL; i++) {
		tmp = address[i];
		addr <<= 8;
		addr |= tmp;
	}

	handle = hxgep->hpi_reg_handle;
	hpi_status = hpi_pfc_set_mac_address(handle, slot, addr);

	if (hpi_status != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_set_mac_address: failed to set address"));
		return (HXGE_ERROR);
	}

	return (HXGE_OK);
}

/*ARGSUSED*/
hxge_status_t
hxge_pfc_num_macs_get(p_hxge_t hxgep, uint8_t *nmacs)
{
	*nmacs = PFC_N_MAC_ADDRESSES;
	return (HXGE_OK);
}


hxge_status_t
hxge_pfc_set_hash(p_hxge_t hxgep, uint32_t seed)
{
	hpi_status_t		rs = HPI_SUCCESS;
	hpi_handle_t		handle;
	p_hxge_class_pt_cfg_t 	p_class_cfgp;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, " ==> hxge_pfc_set_hash"));

	p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;
	p_class_cfgp->init_hash = seed;
	handle = hxgep->hpi_reg_handle;

	rs = hpi_pfc_set_hash_seed_value(handle, seed);
	if (rs & HPI_PFC_ERROR) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_set_hash %x failed ", seed));
		return (HXGE_ERROR | rs);
	}

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, " <== hxge_pfc_set_hash"));

	return (HXGE_OK);
}

hxge_status_t
hxge_pfc_config_tcam_enable(p_hxge_t hxgep)
{
	hpi_handle_t		handle;
	boolean_t		enable = B_TRUE;
	hpi_status_t		hpi_status;

	handle = hxgep->hpi_reg_handle;
	if (hxgep->hxge_hw_p == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_config_tcam_enable: common hardware not set"));
		return (HXGE_ERROR);
	}

	hpi_status = hpi_pfc_set_tcam_enable(handle, enable);
	if (hpi_status != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hpi_pfc_set_tcam_enable: enable tcam failed"));
		return (HXGE_ERROR);
	}

	return (HXGE_OK);
}

hxge_status_t
hxge_pfc_config_tcam_disable(p_hxge_t hxgep)
{
	hpi_handle_t		handle;
	boolean_t		enable = B_FALSE;
	hpi_status_t		hpi_status;

	handle = hxgep->hpi_reg_handle;
	if (hxgep->hxge_hw_p == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_config_tcam_disable: common hardware not set"));
		return (HXGE_ERROR);
	}

	hpi_status = hpi_pfc_set_tcam_enable(handle, enable);
	if (hpi_status != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hpi_pfc_set_tcam_enable: disable tcam failed"));
		return (HXGE_ERROR);
	}

	return (HXGE_OK);
}

static hxge_status_t
hxge_cfg_tcam_ip_class_get(p_hxge_t hxgep, tcam_class_t class,
    uint32_t *class_config)
{
	hpi_status_t	rs = HPI_SUCCESS;
	tcam_key_cfg_t	cfg;
	hpi_handle_t	handle;
	uint32_t	ccfg = 0;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_cfg_tcam_ip_class_get"));

	bzero(&cfg, sizeof (tcam_key_cfg_t));
	handle = hxgep->hpi_reg_handle;

	rs = hpi_pfc_get_l3_class_config(handle, class, &cfg);
	if (rs & HPI_PFC_ERROR) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_cfg_tcam_ip_class opt %x for class %d failed ",
		    class_config, class));
		return (HXGE_ERROR | rs);
	}
	if (cfg.discard)
		ccfg |=  HXGE_CLASS_DISCARD;

	if (cfg.lookup_enable)
		ccfg |= HXGE_CLASS_TCAM_LOOKUP;

	*class_config = ccfg;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, " ==> hxge_cfg_tcam_ip_class_get %x",
	    ccfg));

	return (HXGE_OK);
}

hxge_status_t
hxge_pfc_ip_class_config_get(p_hxge_t hxgep, tcam_class_t class,
    uint32_t *config)
{
	uint32_t	t_class_config;
	int		t_status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, " ==> hxge_pfc_ip_class_config_get"));
	t_class_config = 0;
	t_status = hxge_cfg_tcam_ip_class_get(hxgep, class, &t_class_config);

	if (t_status & HPI_PFC_ERROR) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_ip_class_config_get for class %d tcam failed",
		    class));
		return (t_status);
	}

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, " hxge_pfc_ip_class_config tcam %x",
	    t_class_config));

	*config = t_class_config;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_ip_class_config_get"));
	return (HXGE_OK);
}

static hxge_status_t
hxge_pfc_config_init(p_hxge_t hxgep)
{
	hpi_handle_t		handle;
	block_reset_t		reset_reg;

	handle = hxgep->hpi_reg_handle;
	if (hxgep->hxge_hw_p == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_config_init: common hardware not set"));
		return (HXGE_ERROR);
	}

	/* Reset PFC block from PEU to clear any previous state */
	reset_reg.value = 0;
	reset_reg.bits.pfc_rst = 1;
	HXGE_REG_WR32(hxgep->hpi_handle, BLOCK_RESET, reset_reg.value);
	HXGE_DELAY(1000);

	(void) hpi_pfc_set_tcam_enable(handle, B_FALSE);
	(void) hpi_pfc_set_l2_hash(handle, B_FALSE);
	(void) hpi_pfc_set_tcp_cksum(handle, B_TRUE);
	(void) hpi_pfc_set_default_dma(handle, 0);
	(void) hpi_pfc_mac_addr_enable(handle, 0);
	(void) hpi_pfc_set_force_csum(handle, B_FALSE);

	/* Set the drop log mask to ignore the logs */
	(void) hpi_pfc_set_drop_log_mask(handle, 1, 1, 1, 1, 1);

	/* Clear the interrupt masks to receive interrupts */
	(void) hpi_pfc_set_interrupt_mask(handle, 0, 0, 0);

	/* Clear the interrupt status */
	(void) hpi_pfc_clear_interrupt_status(handle);

	return (HXGE_OK);
}

static hxge_status_t
hxge_pfc_tcam_invalidate_all(p_hxge_t hxgep)
{
	hpi_status_t		rs = HPI_SUCCESS;
	hpi_handle_t		handle;
	p_hxge_hw_list_t	hw_p;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL,
	    "==> hxge_pfc_tcam_invalidate_all"));
	handle = hxgep->hpi_reg_handle;
	if ((hw_p = hxgep->hxge_hw_p) == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_tcam_invalidate_all: common hardware not set"));
		return (HXGE_ERROR);
	}

	MUTEX_ENTER(&hw_p->hxge_tcam_lock);
	rs = hpi_pfc_tcam_invalidate_all(handle);
	MUTEX_EXIT(&hw_p->hxge_tcam_lock);

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_tcam_invalidate_all"));
	if (rs != HPI_SUCCESS)
		return (HXGE_ERROR);

	return (HXGE_OK);
}

static hxge_status_t
hxge_pfc_tcam_init(p_hxge_t hxgep)
{
	hpi_status_t	rs = HPI_SUCCESS;
	hpi_handle_t	handle;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_pfc_tcam_init"));
	handle = hxgep->hpi_reg_handle;

	if (hxgep->hxge_hw_p == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_tcam_init: common hardware not set"));
		return (HXGE_ERROR);
	}

	/*
	 * Disable the TCAM.
	 */
	rs = hpi_pfc_set_tcam_enable(handle, B_FALSE);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "failed TCAM Disable\n"));
		return (HXGE_ERROR | rs);
	}

	/*
	 * Invalidate all the TCAM entries for this blade.
	 */
	rs = hxge_pfc_tcam_invalidate_all(hxgep);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "failed TCAM Disable\n"));
		return (HXGE_ERROR | rs);
	}

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_tcam_init"));
	return (HXGE_OK);
}

static hxge_status_t
hxge_pfc_vlan_tbl_clear_all(p_hxge_t hxgep)
{
	hpi_handle_t		handle;
	hpi_status_t		rs = HPI_SUCCESS;
	p_hxge_hw_list_t	hw_p;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_pfc_vlan_tbl_clear_all "));

	handle = hxgep->hpi_reg_handle;
	if ((hw_p = hxgep->hxge_hw_p) == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_pfc_vlan_tbl_clear_all: common hardware not set"));
		return (HXGE_ERROR);
	}

	MUTEX_ENTER(&hw_p->hxge_vlan_lock);
	rs = hpi_pfc_cfg_vlan_table_clear(handle);
	MUTEX_EXIT(&hw_p->hxge_vlan_lock);

	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "failed vlan table clear\n"));
		return (HXGE_ERROR | rs);
	}

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_vlan_tbl_clear_all "));
	return (HXGE_OK);
}

hxge_status_t
hxge_pfc_ip_class_config(p_hxge_t hxgep, tcam_class_t class, uint32_t config)
{
	uint32_t		class_config;
	p_hxge_class_pt_cfg_t 	p_class_cfgp;
	tcam_key_cfg_t		cfg;
	hpi_handle_t		handle;
	hpi_status_t		rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, " ==> hxge_pfc_ip_class_config"));
	p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;
	class_config = p_class_cfgp->class_cfg[class];

	if (class_config != config) {
		p_class_cfgp->class_cfg[class] = config;
		class_config = config;
	}

	handle = hxgep->hpi_reg_handle;

	if (class == TCAM_CLASS_ETYPE_1 || class == TCAM_CLASS_ETYPE_2) {
		rs = hpi_pfc_set_l2_class_slot(handle,
		    class_config & HXGE_CLASS_ETHER_TYPE_MASK,
		    class_config & HXGE_CLASS_VALID,
		    class - TCAM_CLASS_ETYPE_1);
	} else {
		if (class_config & HXGE_CLASS_DISCARD)
			cfg.discard = 1;
		else
			cfg.discard = 0;
		if (class_config & HXGE_CLASS_TCAM_LOOKUP)
			cfg.lookup_enable = 1;
		else
			cfg.lookup_enable = 0;

		rs = hpi_pfc_set_l3_class_config(handle, class, cfg);
	}

	if (rs & HPI_PFC_ERROR) {
		HXGE_DEBUG_MSG((hxgep, PFC_CTL,
		    " hxge_pfc_ip_class_config %x for class %d tcam failed",
		    config, class));
		return (HXGE_ERROR);
	}

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_ip_class_config"));
	return (HXGE_OK);
}

hxge_status_t
hxge_pfc_ip_class_config_all(p_hxge_t hxgep)
{
	uint32_t	class_config;
	tcam_class_t	cl;
	int		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_pfc_ip_class_config_all"));

	for (cl = TCAM_CLASS_ETYPE_1; cl <= TCAM_CLASS_SCTP_IPV6; cl++) {
		if (cl == TCAM_CLASS_RESERVED_4 ||
		    cl == TCAM_CLASS_RESERVED_5 ||
		    cl == TCAM_CLASS_RESERVED_6 ||
		    cl == TCAM_CLASS_RESERVED_7)
			continue;

		class_config = hxgep->class_config.class_cfg[cl];
		status = hxge_pfc_ip_class_config(hxgep, cl, class_config);
		if (status & HPI_PFC_ERROR) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "hxge_pfc_ip_class_config failed "
			    " class %d config %x ", cl, class_config));
		}
	}

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_ip_class_config_all"));
	return (HXGE_OK);
}

static hxge_status_t
hxge_pfc_update_hw(p_hxge_t hxgep)
{
	hxge_status_t	status = HXGE_OK;
	hpi_handle_t	handle;
	p_hxge_param_t	pa;
	int		i;
	boolean_t	parity = 0;
	boolean_t	implicit_valid = 0;
	vlan_id_t	implicit_vlan_id;
	uint32_t	vlanid_group;
	uint64_t	offset;
	int		max_vlan_groups;
	int		vlan_group_step;

	p_hxge_class_pt_cfg_t 	p_class_cfgp;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_pfc_update_hw"));
	p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;
	handle = hxgep->hpi_reg_handle;

	status = hxge_pfc_set_hash(hxgep, p_class_cfgp->init_hash);
	if (status != HXGE_OK) {
		HXGE_DEBUG_MSG((hxgep, PFC_CTL, "hxge_pfc_set_hash Failed"));
		return (HXGE_ERROR);
	}

	/*
	 * configure vlan table to join all vlans in order for Solaris
	 * network to receive vlan packets of any acceptible VIDs.
	 * This may change when Solaris network passes VIDs down.
	 */
	vlanid_group = 0xffffffff;
	max_vlan_groups = 128;
	vlan_group_step = 8;
	for (i = 0; i < max_vlan_groups; i++) {
		offset = PFC_VLAN_TABLE + i * vlan_group_step;
		REG_PIO_WRITE64(handle, offset, vlanid_group);
	}

	/* Configure the vlan_ctrl register */
	/* Let hw generate the parity bits in pfc_vlan_table */
	parity = 0;

	pa = (p_hxge_param_t)&hxgep->param_arr[param_implicit_vlan_id];
	implicit_vlan_id = (vlan_id_t)pa->value;

	/*
	 * Enable it only if there is a valid implicity vlan id either in
	 * NDD table or the .conf file.
	 */
	if (implicit_vlan_id >= VLAN_ID_MIN && implicit_vlan_id <= VLAN_ID_MAX)
		implicit_valid = 1;

	status = hpi_pfc_cfg_vlan_control_set(handle, parity, implicit_valid,
	    implicit_vlan_id);
	if (status != HPI_SUCCESS) {
		HXGE_DEBUG_MSG((hxgep, PFC_CTL,
		    "hxge_pfc_update_hw: hpi_pfc_cfg_vlan_control_set failed"));
		return (HXGE_ERROR);
	}

	/* config MAC addresses */
	/* Need to think about this */

	/* Configure hash value and classes */
	status = hxge_pfc_ip_class_config_all(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_pfc_ip_class_config_all Failed"));
		return (HXGE_ERROR);
	}

	return (HXGE_OK);
}

hxge_status_t
hxge_pfc_hw_reset(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, " ==> hxge_pfc_hw_reset"));

	status = hxge_pfc_config_init(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "failed PFC config init."));
		return (status);
	}

	status = hxge_pfc_tcam_init(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "failed TCAM init."));
		return (status);
	}

	/*
	 * invalidate VLAN RDC tables
	 */
	status = hxge_pfc_vlan_tbl_clear_all(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "failed VLAN Table Invalidate. "));
		return (status);
	}
	hxgep->classifier.state |= HXGE_PFC_HW_RESET;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_hw_reset"));

	return (HXGE_OK);
}

hxge_status_t
hxge_classify_init_hw(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_classify_init_hw"));

	if (hxgep->classifier.state & HXGE_PFC_HW_INIT) {
		HXGE_DEBUG_MSG((hxgep, PFC_CTL,
		    "hxge_classify_init_hw already init"));
		return (HXGE_OK);
	}

	/* Now do a real configuration */
	status = hxge_pfc_update_hw(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_pfc_update_hw failed"));
		return (HXGE_ERROR);
	}

	status = hxge_tcam_default_config(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_tcam_default_config failed"));
		return (status);
	}

	hxgep->classifier.state |= HXGE_PFC_HW_INIT;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_classify_init_hw"));

	return (HXGE_OK);
}

hxge_status_t
hxge_classify_init_sw(p_hxge_t hxgep)
{
	int		alloc_size;
	hxge_classify_t	*classify_ptr;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_classify_init_sw"));
	classify_ptr = &hxgep->classifier;

	if (classify_ptr->state & HXGE_PFC_SW_INIT) {
		HXGE_DEBUG_MSG((hxgep, PFC_CTL,
		    "hxge_classify_init_sw already init"));
		return (HXGE_OK);
	}

	/* Init SW structures */
	classify_ptr->tcam_size = TCAM_HXGE_TCAM_MAX_ENTRY;

	alloc_size = sizeof (tcam_flow_spec_t) * classify_ptr->tcam_size;
	classify_ptr->tcam_entries = KMEM_ZALLOC(alloc_size, NULL);
	bzero(classify_ptr->class_usage, sizeof (classify_ptr->class_usage));

	/* Start from the beginning of TCAM */
	hxgep->classifier.tcam_location = 0;
	classify_ptr->state |= HXGE_PFC_SW_INIT;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_classify_init_sw"));

	return (HXGE_OK);
}

hxge_status_t
hxge_classify_exit_sw(p_hxge_t hxgep)
{
	int		alloc_size;
	hxge_classify_t	*classify_ptr;
	int		fsize;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_classify_exit_sw"));
	classify_ptr = &hxgep->classifier;

	fsize = sizeof (tcam_flow_spec_t);
	if (classify_ptr->tcam_entries) {
		alloc_size = fsize * classify_ptr->tcam_size;
		KMEM_FREE((void *) classify_ptr->tcam_entries, alloc_size);
	}
	hxgep->classifier.state = NULL;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_classify_exit_sw"));

	return (HXGE_OK);
}

/*ARGSUSED*/
hxge_status_t
hxge_pfc_handle_sys_errors(p_hxge_t hxgep)
{
	return (HXGE_OK);
}

uint_t
hxge_pfc_intr(caddr_t arg1, caddr_t arg2)
{
	p_hxge_ldv_t		ldvp = (p_hxge_ldv_t)arg1;
	p_hxge_t		hxgep = (p_hxge_t)arg2;
	hpi_handle_t		handle;
	p_hxge_pfc_stats_t	statsp;
	pfc_int_status_t	int_status;
	pfc_bad_cs_counter_t	bad_cs_count;
	pfc_drop_counter_t	drop_count;
	pfc_drop_log_t		drop_log;
	pfc_vlan_par_err_log_t	vlan_par_err_log;
	pfc_tcam_par_err_log_t	tcam_par_err_log;

	if (ldvp == NULL) {
		HXGE_DEBUG_MSG((NULL, INT_CTL,
		    "<== hxge_pfc_intr: hxgep $%p ldvp $%p", hxgep, ldvp));
		return (DDI_INTR_UNCLAIMED);
	}

	if (arg2 == NULL || (void *) ldvp->hxgep != arg2) {
		hxgep = ldvp->hxgep;
	}

	handle = hxgep->hpi_reg_handle;
	statsp = (p_hxge_pfc_stats_t)&hxgep->statsp->pfc_stats;

	/*
	 * need to read the pfc interrupt status register to figure out
	 * what is happenning
	 */
	(void) hpi_pfc_get_interrupt_status(handle, &int_status);

	if (int_status.bits.pkt_drop) {
		statsp->pkt_drop++;
		if (statsp->pkt_drop == 1)
			HXGE_ERROR_MSG((hxgep, INT_CTL, "PFC pkt_drop"));

		/* Collect each individual drops */
		(void) hpi_pfc_get_drop_log(handle, &drop_log);

		if (drop_log.bits.tcp_ctrl_drop)
			statsp->errlog.tcp_ctrl_drop++;
		if (drop_log.bits.l2_addr_drop)
			statsp->errlog.l2_addr_drop++;
		if (drop_log.bits.class_code_drop)
			statsp->errlog.class_code_drop++;
		if (drop_log.bits.tcam_drop)
			statsp->errlog.tcam_drop++;
		if (drop_log.bits.vlan_drop)
			statsp->errlog.vlan_drop++;

		/* Collect the total drops for all kinds */
		(void) hpi_pfc_get_drop_counter(handle, &drop_count.value);
		statsp->drop_count += drop_count.bits.drop_count;
	}

	if (int_status.bits.tcam_parity_err) {
		statsp->tcam_parity_err++;

		(void) hpi_pfc_get_tcam_parity_log(handle, &tcam_par_err_log);
		statsp->errlog.tcam_par_err_log = tcam_par_err_log.bits.addr;

		if (statsp->tcam_parity_err == 1)
			HXGE_ERROR_MSG((hxgep,
			    INT_CTL, " TCAM parity error addr: 0x%x",
			    tcam_par_err_log.bits.addr));
	}

	if (int_status.bits.vlan_parity_err) {
		statsp->vlan_parity_err++;

		(void) hpi_pfc_get_vlan_parity_log(handle, &vlan_par_err_log);
		statsp->errlog.vlan_par_err_log = vlan_par_err_log.bits.addr;

		if (statsp->vlan_parity_err == 1)
			HXGE_ERROR_MSG((hxgep, INT_CTL,
			    " vlan table parity error addr: 0x%x",
			    vlan_par_err_log.bits.addr));
	}

	(void) hpi_pfc_get_bad_csum_counter(handle, &bad_cs_count.value);
	statsp->bad_cs_count += bad_cs_count.bits.bad_cs_count;

	(void) hpi_pfc_clear_interrupt_status(handle);
	return (DDI_INTR_CLAIMED);
}

static void
hxge_pfc_get_next_mac_addr(uint8_t *st_mac, struct ether_addr *final_mac)
{
	uint64_t	mac[ETHERADDRL];
	uint64_t	mac_addr = 0;
	int		i, j;

	for (i = ETHERADDRL - 1, j = 0; j < ETHERADDRL; i--, j++) {
		mac[j] = st_mac[i];
		mac_addr |= (mac[j] << (j*8));
	}

	final_mac->ether_addr_octet[0] = (mac_addr & 0xff0000000000) >> 40;
	final_mac->ether_addr_octet[1] = (mac_addr & 0xff00000000) >> 32;
	final_mac->ether_addr_octet[2] = (mac_addr & 0xff000000) >> 24;
	final_mac->ether_addr_octet[3] = (mac_addr & 0xff0000) >> 16;
	final_mac->ether_addr_octet[4] = (mac_addr & 0xff00) >> 8;
	final_mac->ether_addr_octet[5] = (mac_addr & 0xff);
}

hxge_status_t
hxge_pfc_mac_addrs_get(p_hxge_t hxgep)
{
	hxge_status_t	status = HXGE_OK;
	hpi_status_t	hpi_status = HPI_SUCCESS;
	hpi_handle_t	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	uint8_t		mac_addr[ETHERADDRL];

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_pfc_mac_addr_get"));

	hpi_status = hpi_pfc_mac_addr_get_i(handle, mac_addr, 0);
	if (hpi_status != HPI_SUCCESS) {
		status = (HXGE_ERROR | hpi_status);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_pfc_mac_addr_get: pfc_mac_addr_get_i failed"));
		goto exit;
	}

	hxge_pfc_get_next_mac_addr(mac_addr, &hxgep->factaddr);
	HXGE_ERROR_MSG((hxgep, PFC_CTL, "MAC Addr(0): %x:%x:%x:%x:%x:%x\n",
	    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
	    mac_addr[4], mac_addr[5]));

exit:
	HXGE_DEBUG_MSG((hxgep, CFG_CTL, "<== hxge_pfc_mac_addr_get, "
	    "status [0x%x]", status));
	return (status);
}

/*
 * Calculate the bit in the multicast address filter
 * that selects the given * address.
 * Note: For Hydra, the last 8-bits are used.
 */
static uint32_t
crc32_mchash(p_ether_addr_t addr)
{
	uint8_t		*cp;
	uint32_t	crc;
	uint32_t	c;
	int		byte;
	int		bit;

	cp = (uint8_t *)addr;
	crc = (uint32_t)0xffffffff;
	for (byte = 0; byte < ETHERADDRL; byte++) {
		/* Hydra calculates the hash backwardly */
		c = (uint32_t)cp[ETHERADDRL - 1 - byte];
		for (bit = 0; bit < 8; bit++) {
			if ((c & 0x1) ^ (crc & 0x1))
				crc = (crc >> 1)^0xedb88320;
			else
				crc = (crc >> 1);
			c >>= 1;
		}
	}
	return ((~crc) >> (32 - HASH_BITS));
}

static hxge_status_t
hxge_pfc_load_hash_table(p_hxge_t hxgep)
{
	uint32_t		i;
	uint16_t		hashtab_e;
	p_hash_filter_t		hash_filter;
	hpi_handle_t		handle;

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "==> hxge_pfc_load_hash_table\n"));
	handle = hxgep->hpi_reg_handle;

	/*
	 * Load the multicast hash filter bits.
	 */
	hash_filter = hxgep->hash_filter;
	for (i = 0; i < MAC_MAX_HASH_ENTRY; i++) {
		if (hash_filter != NULL) {
			hashtab_e = (uint16_t)hash_filter->hash_filter_regs[i];
		} else {
			hashtab_e = 0;
		}

		if (hpi_pfc_set_multicast_hash_table(handle, i,
		    hashtab_e) != HPI_SUCCESS)
			return (HXGE_ERROR);
	}

	HXGE_DEBUG_MSG((hxgep, PFC_CTL, "<== hxge_pfc_load_hash_table\n"));

	return (HXGE_OK);
}
