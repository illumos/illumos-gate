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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * nxge_hio.c
 *
 * This file manages the virtualization resources for Neptune
 * devices.  That is, it implements a hybrid I/O (HIO) approach in the
 * Solaris kernel, whereby a guest domain on an LDOMs server may
 * request & use hardware resources from the service domain.
 *
 */

#include <sys/mac_provider.h>
#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_fzc.h>
#include <sys/nxge/nxge_rxdma.h>
#include <sys/nxge/nxge_txdma.h>
#include <sys/nxge/nxge_hio.h>

/*
 * External prototypes
 */
extern npi_status_t npi_rxdma_dump_rdc_table(npi_handle_t, uint8_t);

/* The following function may be found in nxge_main.c */
extern int nxge_m_mmac_remove(void *arg, int slot);
extern int nxge_m_mmac_add_g(void *arg, const uint8_t *maddr, int rdctbl,
	boolean_t usetbl);
extern int nxge_rx_ring_start(mac_ring_driver_t rdriver, uint64_t mr_gen_num);

/* The following function may be found in nxge_[t|r]xdma.c */
extern npi_status_t nxge_txdma_channel_disable(nxge_t *, int);
extern nxge_status_t nxge_disable_rxdma_channel(nxge_t *, uint16_t);

/*
 * Local prototypes
 */
static void nxge_grp_dc_append(nxge_t *, nxge_grp_t *, nxge_hio_dc_t *);
static nxge_hio_dc_t *nxge_grp_dc_unlink(nxge_t *, nxge_grp_t *, int);
static void nxge_grp_dc_map(nxge_grp_t *group);

/*
 * These functions are used by both service & guest domains to
 * decide whether they're running in an LDOMs/XEN environment
 * or not.  If so, then the Hybrid I/O (HIO) module is initialized.
 */

/*
 * nxge_get_environs
 *
 *	Figure out if we are in a guest domain or not.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *
 * Context:
 *	Any domain
 */
void
nxge_get_environs(
	nxge_t *nxge)
{
	char *string;

	/*
	 * In the beginning, assume that we are running sans LDOMs/XEN.
	 */
	nxge->environs = SOLARIS_DOMAIN;

	/*
	 * Are we a hybrid I/O (HIO) guest domain driver?
	 */
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, nxge->dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "niutype", &string)) == DDI_PROP_SUCCESS) {
		if (strcmp(string, "n2niu") == 0) {
			nxge->environs = SOLARIS_GUEST_DOMAIN;
			/* So we can allocate properly-aligned memory. */
			nxge->niu_type = N2_NIU;
			NXGE_DEBUG_MSG((nxge, HIO_CTL,
			    "Hybrid IO-capable guest domain"));
		}
		ddi_prop_free(string);
	}
}

#if !defined(sun4v)

/*
 * nxge_hio_init
 *
 *	Initialize the HIO module of the NXGE driver.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *	This is the non-hybrid I/O version of this function.
 *
 * Context:
 *	Any domain
 */
int
nxge_hio_init(nxge_t *nxge)
{
	nxge_hio_data_t *nhd;
	int i;

	nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	if (nhd == NULL) {
		nhd = KMEM_ZALLOC(sizeof (*nhd), KM_SLEEP);
		MUTEX_INIT(&nhd->lock, NULL, MUTEX_DRIVER, NULL);
		nhd->type = NXGE_HIO_TYPE_SERVICE;
		nxge->nxge_hw_p->hio = (uintptr_t)nhd;
	}

	/*
	 * Initialize share and ring group structures.
	 */
	for (i = 0; i < NXGE_MAX_TDCS; i++)
		nxge->tdc_is_shared[i] = B_FALSE;

	for (i = 0; i < NXGE_MAX_TDC_GROUPS; i++) {
		nxge->tx_hio_groups[i].ghandle = NULL;
		nxge->tx_hio_groups[i].nxgep = nxge;
		nxge->tx_hio_groups[i].type = MAC_RING_TYPE_TX;
		nxge->tx_hio_groups[i].gindex = 0;
		nxge->tx_hio_groups[i].sindex = 0;
	}

	for (i = 0; i < NXGE_MAX_RDC_GROUPS; i++) {
		nxge->rx_hio_groups[i].ghandle = NULL;
		nxge->rx_hio_groups[i].nxgep = nxge;
		nxge->rx_hio_groups[i].type = MAC_RING_TYPE_RX;
		nxge->rx_hio_groups[i].gindex = 0;
		nxge->rx_hio_groups[i].sindex = 0;
		nxge->rx_hio_groups[i].started = B_FALSE;
		nxge->rx_hio_groups[i].port_default_grp = B_FALSE;
		nxge->rx_hio_groups[i].rdctbl = -1;
		nxge->rx_hio_groups[i].n_mac_addrs = 0;
	}

	nhd->hio.ldoms = B_FALSE;

	return (NXGE_OK);
}

#endif

void
nxge_hio_uninit(nxge_t *nxge)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	ASSERT(nxge->nxge_hw_p->ndevs == 0);

	if (nhd != NULL) {
		MUTEX_DESTROY(&nhd->lock);
		KMEM_FREE(nhd, sizeof (*nhd));
		nxge->nxge_hw_p->hio = 0;
	}
}

/*
 * nxge_dci_map
 *
 *	Map a DMA channel index to a channel number.
 *
 * Arguments:
 * 	instance	The instance number of the driver.
 * 	type		The type of channel this is: Tx or Rx.
 * 	index		The index to convert to a channel number
 *
 * Notes:
 *	This function is called by nxge_ndd.c:nxge_param_set_port_rdc()
 *
 * Context:
 *	Any domain
 */
int
nxge_dci_map(
	nxge_t *nxge,
	vpc_type_t type,
	int index)
{
	nxge_grp_set_t *set;
	int dc;

	switch (type) {
	case VP_BOUND_TX:
		set = &nxge->tx_set;
		break;
	case VP_BOUND_RX:
		set = &nxge->rx_set;
		break;
	}

	for (dc = 0; dc < NXGE_MAX_TDCS; dc++) {
		if ((1 << dc) & set->owned.map) {
			if (index == 0)
				return (dc);
			else
				index--;
		}
	}

	return (-1);
}

/*
 * ---------------------------------------------------------------------
 * These are the general-purpose DMA channel group functions.  That is,
 * these functions are used to manage groups of TDCs or RDCs in an HIO
 * environment.
 *
 * But is also expected that in the future they will be able to manage
 * Crossbow groups.
 * ---------------------------------------------------------------------
 */

/*
 * nxge_grp_cleanup(p_nxge_t nxge)
 *
 *	Remove all outstanding groups.
 *
 * Arguments:
 *	nxge
 */
void
nxge_grp_cleanup(p_nxge_t nxge)
{
	nxge_grp_set_t *set;
	int i;

	MUTEX_ENTER(&nxge->group_lock);

	/*
	 * Find RX groups that need to be cleaned up.
	 */
	set = &nxge->rx_set;
	for (i = 0; i < NXGE_LOGICAL_GROUP_MAX; i++) {
		if (set->group[i] != NULL) {
			KMEM_FREE(set->group[i], sizeof (nxge_grp_t));
			set->group[i] = NULL;
		}
	}

	/*
	 * Find TX groups that need to be cleaned up.
	 */
	set = &nxge->tx_set;
	for (i = 0; i < NXGE_LOGICAL_GROUP_MAX; i++) {
		if (set->group[i] != NULL) {
			KMEM_FREE(set->group[i], sizeof (nxge_grp_t));
			set->group[i] = NULL;
		}
	}
	MUTEX_EXIT(&nxge->group_lock);
}


/*
 * nxge_grp_add
 *
 *	Add a group to an instance of NXGE.
 *
 * Arguments:
 * 	nxge
 * 	type	Tx or Rx
 *
 * Notes:
 *
 * Context:
 *	Any domain
 */
nxge_grp_t *
nxge_grp_add(
	nxge_t *nxge,
	nxge_grp_type_t type)
{
	nxge_grp_set_t *set;
	nxge_grp_t *group;
	int i;

	group = KMEM_ZALLOC(sizeof (*group), KM_SLEEP);
	group->nxge = nxge;

	MUTEX_ENTER(&nxge->group_lock);
	switch (type) {
	case NXGE_TRANSMIT_GROUP:
	case EXT_TRANSMIT_GROUP:
		set = &nxge->tx_set;
		break;
	default:
		set = &nxge->rx_set;
		break;
	}

	group->type = type;
	group->active = B_TRUE;
	group->sequence = set->sequence++;

	/* Find an empty slot for this logical group. */
	for (i = 0; i < NXGE_LOGICAL_GROUP_MAX; i++) {
		if (set->group[i] == 0) {
			group->index = i;
			set->group[i] = group;
			NXGE_DC_SET(set->lg.map, i);
			set->lg.count++;
			break;
		}
	}
	MUTEX_EXIT(&nxge->group_lock);

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_grp_add: %cgroup = %d.%d",
	    type == NXGE_TRANSMIT_GROUP ? 't' : 'r',
	    nxge->mac.portnum, group->sequence));

	return (group);
}

void
nxge_grp_remove(
	nxge_t *nxge,
	nxge_grp_t *group)	/* The group to remove. */
{
	nxge_grp_set_t *set;
	vpc_type_t type;

	if (group == NULL)
		return;

	MUTEX_ENTER(&nxge->group_lock);
	switch (group->type) {
	case NXGE_TRANSMIT_GROUP:
	case EXT_TRANSMIT_GROUP:
		set = &nxge->tx_set;
		break;
	default:
		set = &nxge->rx_set;
		break;
	}

	if (set->group[group->index] != group) {
		MUTEX_EXIT(&nxge->group_lock);
		return;
	}

	set->group[group->index] = 0;
	NXGE_DC_RESET(set->lg.map, group->index);
	set->lg.count--;

	/* While inside the mutex, deactivate <group>. */
	group->active = B_FALSE;

	MUTEX_EXIT(&nxge->group_lock);

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_grp_remove(%c.%d.%d) called",
	    group->type == NXGE_TRANSMIT_GROUP ? 't' : 'r',
	    nxge->mac.portnum, group->sequence));

	/* Now, remove any DCs which are still active. */
	switch (group->type) {
	default:
		type = VP_BOUND_TX;
		break;
	case NXGE_RECEIVE_GROUP:
	case EXT_RECEIVE_GROUP:
		type = VP_BOUND_RX;
	}

	while (group->dc) {
		nxge_grp_dc_remove(nxge, type, group->dc->channel);
	}

	KMEM_FREE(group, sizeof (*group));
}

/*
 * nxge_grp_dc_add
 *
 *	Add a DMA channel to a VR/Group.
 *
 * Arguments:
 * 	nxge
 * 	channel	The channel to add.
 * Notes:
 *
 * Context:
 *	Any domain
 */
/* ARGSUSED */
int
nxge_grp_dc_add(
	nxge_t *nxge,
	nxge_grp_t *group,	/* The group to add <channel> to. */
	vpc_type_t type,	/* Rx or Tx */
	int channel)		/* A physical/logical channel number */
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_dc_t *dc;
	nxge_grp_set_t *set;
	nxge_status_t status = NXGE_OK;
	int error = 0;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_grp_dc_add"));

	if (group == 0)
		return (0);

	switch (type) {
	case VP_BOUND_TX:
		set = &nxge->tx_set;
		if (channel > NXGE_MAX_TDCS) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "nxge_grp_dc_add: TDC = %d", channel));
			return (NXGE_ERROR);
		}
		break;
	case VP_BOUND_RX:
		set = &nxge->rx_set;
		if (channel > NXGE_MAX_RDCS) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "nxge_grp_dc_add: RDC = %d", channel));
			return (NXGE_ERROR);
		}
		break;

	default:
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_grp_dc_add: unknown type channel(%d)", channel));
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_grp_dc_add: %cgroup = %d.%d.%d, channel = %d",
	    type == VP_BOUND_TX ? 't' : 'r',
	    nxge->mac.portnum, group->sequence, group->count, channel));

	MUTEX_ENTER(&nxge->group_lock);
	if (group->active != B_TRUE) {
		/* We may be in the process of removing this group. */
		MUTEX_EXIT(&nxge->group_lock);
		return (NXGE_ERROR);
	}
	MUTEX_EXIT(&nxge->group_lock);

	if (!(dc = nxge_grp_dc_find(nxge, type, channel))) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_grp_dc_add(%d): DC FIND failed", channel));
		return (NXGE_ERROR);
	}

	MUTEX_ENTER(&nhd->lock);

	if (dc->group) {
		MUTEX_EXIT(&nhd->lock);
		/* This channel is already in use! */
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_grp_dc_add(%d): channel already in group", channel));
		return (NXGE_ERROR);
	}

	dc->next = 0;
	dc->page = channel;
	dc->channel = (nxge_channel_t)channel;

	dc->type = type;
	if (type == VP_BOUND_RX) {
		dc->init = nxge_init_rxdma_channel;
		dc->uninit = nxge_uninit_rxdma_channel;
	} else {
		dc->init = nxge_init_txdma_channel;
		dc->uninit = nxge_uninit_txdma_channel;
	}

	dc->group = group;

	if (isLDOMguest(nxge)) {
		error = nxge_hio_ldsv_add(nxge, dc);
		if (error != 0) {
			MUTEX_EXIT(&nhd->lock);
			return (NXGE_ERROR);
		}
	}

	NXGE_DC_SET(set->owned.map, channel);
	set->owned.count++;

	MUTEX_EXIT(&nhd->lock);

	if ((status = (*dc->init)(nxge, channel)) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_grp_dc_add(%d): channel init failed", channel));
		MUTEX_ENTER(&nhd->lock);
		(void) memset(dc, 0, sizeof (*dc));
		NXGE_DC_RESET(set->owned.map, channel);
		set->owned.count--;
		MUTEX_EXIT(&nhd->lock);
		return (NXGE_ERROR);
	}

	nxge_grp_dc_append(nxge, group, dc);

	if (type == VP_BOUND_TX) {
		MUTEX_ENTER(&nhd->lock);
		nxge->tdc_is_shared[channel] = B_FALSE;
		MUTEX_EXIT(&nhd->lock);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_grp_dc_add"));

	return ((int)status);
}

void
nxge_grp_dc_remove(
	nxge_t *nxge,
	vpc_type_t type,
	int channel)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_dc_t *dc;
	nxge_grp_set_t *set;
	nxge_grp_t *group;

	dc_uninit_t uninit;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_grp_dc_remove"));

	if ((dc = nxge_grp_dc_find(nxge, type, channel)) == 0)
		goto nxge_grp_dc_remove_exit;

	if ((dc->group == NULL) && (dc->next == 0) &&
	    (dc->channel == 0) && (dc->page == 0) && (dc->type == 0)) {
		goto nxge_grp_dc_remove_exit;
	}

	group = (nxge_grp_t *)dc->group;

	if (isLDOMguest(nxge)) {
		(void) nxge_hio_intr_remove(nxge, type, channel);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "DC remove: group = %d.%d.%d, %cdc %d",
	    nxge->mac.portnum, group->sequence, group->count,
	    type == VP_BOUND_TX ? 't' : 'r', dc->channel));

	MUTEX_ENTER(&nhd->lock);

	set = dc->type == VP_BOUND_TX ? &nxge->tx_set : &nxge->rx_set;

	/* Remove the DC from its group. */
	if (nxge_grp_dc_unlink(nxge, group, channel) != dc) {
		MUTEX_EXIT(&nhd->lock);
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_grp_dc_remove(%d) failed", channel));
		goto nxge_grp_dc_remove_exit;
	}

	uninit = dc->uninit;
	channel = dc->channel;

	NXGE_DC_RESET(set->owned.map, channel);
	set->owned.count--;

	(void) memset(dc, 0, sizeof (*dc));

	MUTEX_EXIT(&nhd->lock);

	(*uninit)(nxge, channel);

nxge_grp_dc_remove_exit:
	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_grp_dc_remove"));
}

nxge_hio_dc_t *
nxge_grp_dc_find(
	nxge_t *nxge,
	vpc_type_t type,	/* Rx or Tx */
	int channel)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_dc_t *current;

	current = (type == VP_BOUND_TX) ? &nhd->tdc[0] : &nhd->rdc[0];

	if (!isLDOMguest(nxge)) {
		return (&current[channel]);
	} else {
		/* We're in a guest domain. */
		int i, limit = (type == VP_BOUND_TX) ?
		    NXGE_MAX_TDCS : NXGE_MAX_RDCS;

		MUTEX_ENTER(&nhd->lock);
		for (i = 0; i < limit; i++, current++) {
			if (current->channel == channel) {
				if (current->vr && current->vr->nxge ==
				    (uintptr_t)nxge) {
					MUTEX_EXIT(&nhd->lock);
					return (current);
				}
			}
		}
		MUTEX_EXIT(&nhd->lock);
	}

	return (0);
}

/*
 * nxge_grp_dc_append
 *
 *	Append a DMA channel to a group.
 *
 * Arguments:
 * 	nxge
 * 	group	The group to append to
 * 	dc	The DMA channel to append
 *
 * Notes:
 *
 * Context:
 *	Any domain
 */
static
void
nxge_grp_dc_append(
	nxge_t *nxge,
	nxge_grp_t *group,
	nxge_hio_dc_t *dc)
{
	MUTEX_ENTER(&nxge->group_lock);

	if (group->dc == 0) {
		group->dc = dc;
	} else {
		nxge_hio_dc_t *current = group->dc;
		do {
			if (current->next == 0) {
				current->next = dc;
				break;
			}
			current = current->next;
		} while (current);
	}

	NXGE_DC_SET(group->map, dc->channel);

	nxge_grp_dc_map(group);
	group->count++;

	MUTEX_EXIT(&nxge->group_lock);
}

/*
 * nxge_grp_dc_unlink
 *
 *	Unlink a DMA channel fromits linked list (group).
 *
 * Arguments:
 * 	nxge
 * 	group	The group (linked list) to unlink from
 * 	dc	The DMA channel to append
 *
 * Notes:
 *
 * Context:
 *	Any domain
 */
nxge_hio_dc_t *
nxge_grp_dc_unlink(
	nxge_t *nxge,
	nxge_grp_t *group,
	int channel)
{
	nxge_hio_dc_t *current, *previous;

	MUTEX_ENTER(&nxge->group_lock);

	if (group == NULL) {
		MUTEX_EXIT(&nxge->group_lock);
		return (0);
	}

	if ((current = group->dc) == 0) {
		MUTEX_EXIT(&nxge->group_lock);
		return (0);
	}

	previous = 0;
	do {
		if (current->channel == channel) {
			if (previous)
				previous->next = current->next;
			else
				group->dc = current->next;
			break;
		}
		previous = current;
		current = current->next;
	} while (current);

	if (current == 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "DC unlink: DC %d not found", channel));
	} else {
		current->next = 0;
		current->group = 0;

		NXGE_DC_RESET(group->map, channel);
		group->count--;
	}

	nxge_grp_dc_map(group);

	MUTEX_EXIT(&nxge->group_lock);

	return (current);
}

/*
 * nxge_grp_dc_map
 *
 *	Map a linked list to an array of channel numbers.
 *
 * Arguments:
 * 	nxge
 * 	group	The group to remap.
 *
 * Notes:
 *	It is expected that the caller will hold the correct mutex.
 *
 * Context:
 *	Service domain
 */
void
nxge_grp_dc_map(
	nxge_grp_t *group)
{
	nxge_channel_t *legend;
	nxge_hio_dc_t *dc;

	(void) memset(group->legend, 0, sizeof (group->legend));

	legend = group->legend;
	dc = group->dc;
	while (dc) {
		*legend = dc->channel;
		legend++;
		dc = dc->next;
	}
}

/*
 * ---------------------------------------------------------------------
 * These are HIO debugging functions.
 * ---------------------------------------------------------------------
 */

/*
 * nxge_delay
 *
 *	Delay <seconds> number of seconds.
 *
 * Arguments:
 * 	nxge
 * 	group	The group to append to
 * 	dc	The DMA channel to append
 *
 * Notes:
 *	This is a developer-only function.
 *
 * Context:
 *	Any domain
 */
void
nxge_delay(
	int seconds)
{
	delay(drv_usectohz(seconds * 1000000));
}

static dmc_reg_name_t rx_names[] = {
	{ "RXDMA_CFIG1",	0 },
	{ "RXDMA_CFIG2",	8 },
	{ "RBR_CFIG_A",		0x10 },
	{ "RBR_CFIG_B",		0x18 },
	{ "RBR_KICK",		0x20 },
	{ "RBR_STAT",		0x28 },
	{ "RBR_HDH",		0x30 },
	{ "RBR_HDL",		0x38 },
	{ "RCRCFIG_A",		0x40 },
	{ "RCRCFIG_B",		0x48 },
	{ "RCRSTAT_A",		0x50 },
	{ "RCRSTAT_B",		0x58 },
	{ "RCRSTAT_C",		0x60 },
	{ "RX_DMA_ENT_MSK",	0x68 },
	{ "RX_DMA_CTL_STAT",	0x70 },
	{ "RCR_FLSH",		0x78 },
	{ "RXMISC",		0x90 },
	{ "RX_DMA_CTL_STAT_DBG", 0x98 },
	{ 0, -1 }
};

static dmc_reg_name_t tx_names[] = {
	{ "Tx_RNG_CFIG",	0 },
	{ "Tx_RNG_HDL",		0x10 },
	{ "Tx_RNG_KICK",	0x18 },
	{ "Tx_ENT_MASK",	0x20 },
	{ "Tx_CS",		0x28 },
	{ "TxDMA_MBH",		0x30 },
	{ "TxDMA_MBL",		0x38 },
	{ "TxDMA_PRE_ST",	0x40 },
	{ "Tx_RNG_ERR_LOGH",	0x48 },
	{ "Tx_RNG_ERR_LOGL",	0x50 },
	{ "TDMC_INTR_DBG",	0x60 },
	{ "Tx_CS_DBG",		0x68 },
	{ 0, -1 }
};

/*
 * nxge_xx2str
 *
 *	Translate a register address into a string.
 *
 * Arguments:
 * 	offset	The address of the register to translate.
 *
 * Notes:
 *	These are developer-only function.
 *
 * Context:
 *	Any domain
 */
const char *
nxge_rx2str(
	int offset)
{
	dmc_reg_name_t *reg = &rx_names[0];

	offset &= DMA_CSR_MASK;

	while (reg->name) {
		if (offset == reg->offset)
			return (reg->name);
		reg++;
	}

	return (0);
}

const char *
nxge_tx2str(
	int offset)
{
	dmc_reg_name_t *reg = &tx_names[0];

	offset &= DMA_CSR_MASK;

	while (reg->name) {
		if (offset == reg->offset)
			return (reg->name);
		reg++;
	}

	return (0);
}

/*
 * nxge_ddi_perror
 *
 *	Map a DDI error number to a string.
 *
 * Arguments:
 * 	ddi_error	The DDI error number to map.
 *
 * Notes:
 *
 * Context:
 *	Any domain
 */
const char *
nxge_ddi_perror(
	int ddi_error)
{
	switch (ddi_error) {
	case DDI_SUCCESS:
		return ("DDI_SUCCESS");
	case DDI_FAILURE:
		return ("DDI_FAILURE");
	case DDI_NOT_WELL_FORMED:
		return ("DDI_NOT_WELL_FORMED");
	case DDI_EAGAIN:
		return ("DDI_EAGAIN");
	case DDI_EINVAL:
		return ("DDI_EINVAL");
	case DDI_ENOTSUP:
		return ("DDI_ENOTSUP");
	case DDI_EPENDING:
		return ("DDI_EPENDING");
	case DDI_ENOMEM:
		return ("DDI_ENOMEM");
	case DDI_EBUSY:
		return ("DDI_EBUSY");
	case DDI_ETRANSPORT:
		return ("DDI_ETRANSPORT");
	case DDI_ECONTEXT:
		return ("DDI_ECONTEXT");
	default:
		return ("Unknown error");
	}
}

/*
 * ---------------------------------------------------------------------
 * These are Sun4v HIO function definitions
 * ---------------------------------------------------------------------
 */

#if defined(sun4v)

/*
 * Local prototypes
 */
static nxge_hio_vr_t *nxge_hio_vr_share(nxge_t *);
static void nxge_hio_unshare(nxge_hio_vr_t *);

static int nxge_hio_addres(nxge_hio_vr_t *, mac_ring_type_t, uint64_t *);
static void nxge_hio_remres(nxge_hio_vr_t *, mac_ring_type_t, res_map_t);

static void nxge_hio_tdc_unshare(nxge_t *nxge, int dev_grpid, int channel);
static void nxge_hio_rdc_unshare(nxge_t *nxge, int dev_grpid, int channel);
static int nxge_hio_dc_share(nxge_t *, nxge_hio_vr_t *, mac_ring_type_t, int);
static void nxge_hio_dc_unshare(nxge_t *, nxge_hio_vr_t *,
    mac_ring_type_t, int);

/*
 * nxge_hio_init
 *
 *	Initialize the HIO module of the NXGE driver.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *
 * Context:
 *	Any domain
 */
int
nxge_hio_init(nxge_t *nxge)
{
	nxge_hio_data_t *nhd;
	int i, region;

	nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	if (nhd == 0) {
		nhd = KMEM_ZALLOC(sizeof (*nhd), KM_SLEEP);
		MUTEX_INIT(&nhd->lock, NULL, MUTEX_DRIVER, NULL);
		if (isLDOMguest(nxge))
			nhd->type = NXGE_HIO_TYPE_GUEST;
		else
			nhd->type = NXGE_HIO_TYPE_SERVICE;
		nxge->nxge_hw_p->hio = (uintptr_t)nhd;
	}

	if ((nxge->environs == SOLARIS_DOMAIN) &&
	    (nxge->niu_type == N2_NIU)) {
		if (nxge->niu_hsvc_available == B_TRUE) {
			hsvc_info_t *niu_hsvc = &nxge->niu_hsvc;
			/*
			 * Versions supported now are:
			 *  - major number >= 1 (NIU_MAJOR_VER).
			 */
			if ((niu_hsvc->hsvc_major >= NIU_MAJOR_VER) ||
			    (niu_hsvc->hsvc_major == 1 &&
			    niu_hsvc->hsvc_minor == 1)) {
				nxge->environs = SOLARIS_SERVICE_DOMAIN;
				NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
				    "nxge_hio_init: hypervisor services "
				    "version %d.%d",
				    niu_hsvc->hsvc_major,
				    niu_hsvc->hsvc_minor));
			}
		}
	}

	/*
	 * Initialize share and ring group structures.
	 */
	for (i = 0; i < NXGE_MAX_TDC_GROUPS; i++) {
		nxge->tx_hio_groups[i].ghandle = NULL;
		nxge->tx_hio_groups[i].nxgep = nxge;
		nxge->tx_hio_groups[i].type = MAC_RING_TYPE_TX;
		nxge->tx_hio_groups[i].gindex = 0;
		nxge->tx_hio_groups[i].sindex = 0;
	}

	for (i = 0; i < NXGE_MAX_RDC_GROUPS; i++) {
		nxge->rx_hio_groups[i].ghandle = NULL;
		nxge->rx_hio_groups[i].nxgep = nxge;
		nxge->rx_hio_groups[i].type = MAC_RING_TYPE_RX;
		nxge->rx_hio_groups[i].gindex = 0;
		nxge->rx_hio_groups[i].sindex = 0;
		nxge->rx_hio_groups[i].started = B_FALSE;
		nxge->rx_hio_groups[i].port_default_grp = B_FALSE;
		nxge->rx_hio_groups[i].rdctbl = -1;
		nxge->rx_hio_groups[i].n_mac_addrs = 0;
	}

	if (!isLDOMs(nxge)) {
		nhd->hio.ldoms = B_FALSE;
		return (NXGE_OK);
	}

	nhd->hio.ldoms = B_TRUE;

	/*
	 * Fill in what we can.
	 */
	for (region = 0; region < NXGE_VR_SR_MAX; region++) {
		nhd->vr[region].region = region;
	}
	nhd->vrs = NXGE_VR_SR_MAX - 2;

	/*
	 * Initialize the share stuctures.
	 */
	for (i = 0; i < NXGE_MAX_TDCS; i++)
		nxge->tdc_is_shared[i] = B_FALSE;

	for (i = 0; i < NXGE_VR_SR_MAX; i++) {
		nxge->shares[i].nxgep = nxge;
		nxge->shares[i].index = 0;
		nxge->shares[i].vrp = NULL;
		nxge->shares[i].tmap = 0;
		nxge->shares[i].rmap = 0;
		nxge->shares[i].rxgroup = 0;
		nxge->shares[i].active = B_FALSE;
	}

	/* Fill in the HV HIO function pointers. */
	nxge_hio_hv_init(nxge);

	if (isLDOMservice(nxge)) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL,
		    "Hybrid IO-capable service domain"));
		return (NXGE_OK);
	}

	return (0);
}
#endif /* defined(sun4v) */

static int
nxge_hio_group_mac_add(nxge_t *nxge, nxge_ring_group_t *g,
    const uint8_t *macaddr)
{
	int rv;
	nxge_rdc_grp_t *group;

	mutex_enter(nxge->genlock);

	/*
	 * Initialize the NXGE RDC table data structure.
	 */
	group = &nxge->pt_config.rdc_grps[g->rdctbl];
	if (!group->flag) {
		group->port = NXGE_GET_PORT_NUM(nxge->function_num);
		group->config_method = RDC_TABLE_ENTRY_METHOD_REP;
		group->flag = B_TRUE;	/* This group has been configured. */
	}

	mutex_exit(nxge->genlock);

	/*
	 * Add the MAC address.
	 */
	if ((rv = nxge_m_mmac_add_g((void *)nxge, macaddr,
	    g->rdctbl, B_TRUE)) != 0) {
		return (rv);
	}

	mutex_enter(nxge->genlock);
	g->n_mac_addrs++;
	mutex_exit(nxge->genlock);
	return (0);
}

static int
nxge_hio_set_unicst(void *arg, const uint8_t *macaddr)
{
	p_nxge_t		nxgep = (p_nxge_t)arg;
	struct ether_addr	addrp;

	bcopy(macaddr, (uint8_t *)&addrp, ETHERADDRL);
	if (nxge_set_mac_addr(nxgep, &addrp)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_m_unicst: set unitcast failed"));
		return (EINVAL);
	}

	nxgep->primary = B_TRUE;

	return (0);
}

/*ARGSUSED*/
static int
nxge_hio_clear_unicst(p_nxge_t nxgep, const uint8_t *mac_addr)
{
	nxgep->primary = B_FALSE;
	return (0);
}

static int
nxge_hio_add_mac(void *arg, const uint8_t *mac_addr)
{
	nxge_ring_group_t	*group = (nxge_ring_group_t *)arg;
	p_nxge_t		nxge = group->nxgep;
	int			rv;
	nxge_hio_vr_t		*vr;	/* The Virtualization Region */

	ASSERT(group->type == MAC_RING_TYPE_RX);
	ASSERT(group->nxgep != NULL);

	if (isLDOMguest(group->nxgep))
		return (0);

	mutex_enter(nxge->genlock);

	if (!nxge->primary && group->port_default_grp) {
		rv = nxge_hio_set_unicst((void *)nxge, mac_addr);
		mutex_exit(nxge->genlock);
		return (rv);
	}

	/*
	 * If the group is associated with a VR, then only one
	 * address may be assigned to the group.
	 */
	vr = (nxge_hio_vr_t *)nxge->shares[group->sindex].vrp;
	if ((vr != NULL) && (group->n_mac_addrs)) {
		mutex_exit(nxge->genlock);
		return (ENOSPC);
	}

	mutex_exit(nxge->genlock);

	/*
	 * Program the mac address for the group.
	 */
	if ((rv = nxge_hio_group_mac_add(nxge, group, mac_addr)) != 0) {
		return (rv);
	}

	return (0);
}

static int
find_mac_slot(nxge_mmac_t *mmac_info, const uint8_t *mac_addr)
{
	int i;
	for (i = 0; i <= mmac_info->num_mmac; i++) {
		if (memcmp(mmac_info->mac_pool[i].addr, mac_addr,
		    ETHERADDRL) == 0) {
			return (i);
		}
	}
	return (-1);
}

/* ARGSUSED */
static int
nxge_hio_rem_mac(void *arg, const uint8_t *mac_addr)
{
	nxge_ring_group_t *group = (nxge_ring_group_t *)arg;
	struct ether_addr addrp;
	p_nxge_t nxge = group->nxgep;
	nxge_mmac_t *mmac_info;
	int rv, slot;

	ASSERT(group->type == MAC_RING_TYPE_RX);
	ASSERT(group->nxgep != NULL);

	if (isLDOMguest(group->nxgep))
		return (0);

	mutex_enter(nxge->genlock);

	mmac_info = &nxge->nxge_mmac_info;
	slot = find_mac_slot(mmac_info, mac_addr);
	if (slot < 0) {
		if (group->port_default_grp && nxge->primary) {
			bcopy(mac_addr, (uint8_t *)&addrp, ETHERADDRL);
			if (ether_cmp(&addrp, &nxge->ouraddr) == 0) {
				rv = nxge_hio_clear_unicst(nxge, mac_addr);
				mutex_exit(nxge->genlock);
				return (rv);
			} else {
				mutex_exit(nxge->genlock);
				return (EINVAL);
			}
		} else {
			mutex_exit(nxge->genlock);
			return (EINVAL);
		}
	}

	mutex_exit(nxge->genlock);

	/*
	 * Remove the mac address for the group
	 */
	if ((rv = nxge_m_mmac_remove(nxge, slot)) != 0) {
		return (rv);
	}

	mutex_enter(nxge->genlock);
	group->n_mac_addrs--;
	mutex_exit(nxge->genlock);

	return (0);
}

static int
nxge_hio_group_start(mac_group_driver_t gdriver)
{
	nxge_ring_group_t	*group = (nxge_ring_group_t *)gdriver;
	nxge_rdc_grp_t		*rdc_grp_p;
	int			rdctbl;
	int			dev_gindex;

	ASSERT(group->type == MAC_RING_TYPE_RX);
	ASSERT(group->nxgep != NULL);

	ASSERT(group->nxgep->nxge_mac_state == NXGE_MAC_STARTED);
	if (group->nxgep->nxge_mac_state != NXGE_MAC_STARTED)
		return (ENXIO);

	mutex_enter(group->nxgep->genlock);
	if (isLDOMguest(group->nxgep))
		goto nxge_hio_group_start_exit;

	dev_gindex = group->nxgep->pt_config.hw_config.def_mac_rxdma_grpid +
	    group->gindex;
	rdc_grp_p = &group->nxgep->pt_config.rdc_grps[dev_gindex];

	/*
	 * Get an rdc table for this group.
	 * Group ID is given by the caller, and that's the group it needs
	 * to bind to.  The default group is already bound when the driver
	 * was attached.
	 *
	 * For Group 0, it's RDC table was allocated at attach time
	 * no need to allocate a new table.
	 */
	if (group->gindex != 0) {
		rdctbl = nxge_fzc_rdc_tbl_bind(group->nxgep,
		    dev_gindex, B_TRUE);
		if (rdctbl < 0) {
			mutex_exit(group->nxgep->genlock);
			return (rdctbl);
		}
	} else {
		rdctbl = group->nxgep->pt_config.hw_config.def_mac_rxdma_grpid;
	}

	group->rdctbl = rdctbl;

	(void) nxge_init_fzc_rdc_tbl(group->nxgep, rdc_grp_p, rdctbl);

nxge_hio_group_start_exit:
	group->started = B_TRUE;
	mutex_exit(group->nxgep->genlock);
	return (0);
}

static void
nxge_hio_group_stop(mac_group_driver_t gdriver)
{
	nxge_ring_group_t *group = (nxge_ring_group_t *)gdriver;

	ASSERT(group->type == MAC_RING_TYPE_RX);

	mutex_enter(group->nxgep->genlock);
	group->started = B_FALSE;

	if (isLDOMguest(group->nxgep))
		goto nxge_hio_group_stop_exit;

	/*
	 * Unbind the RDC table previously bound for this group.
	 *
	 * Since RDC table for group 0 was allocated at attach
	 * time, no need to unbind the table here.
	 */
	if (group->gindex != 0)
		(void) nxge_fzc_rdc_tbl_unbind(group->nxgep, group->rdctbl);

nxge_hio_group_stop_exit:
	mutex_exit(group->nxgep->genlock);
}

/* ARGSUSED */
void
nxge_hio_group_get(void *arg, mac_ring_type_t type, int groupid,
	mac_group_info_t *infop, mac_group_handle_t ghdl)
{
	p_nxge_t		nxgep = (p_nxge_t)arg;
	nxge_ring_group_t	*group;
	int			dev_gindex;

	switch (type) {
	case MAC_RING_TYPE_RX:
		group = &nxgep->rx_hio_groups[groupid];
		group->nxgep = nxgep;
		group->ghandle = ghdl;
		group->gindex = groupid;
		group->sindex = 0;	/* not yet bound to a share */

		if (!isLDOMguest(nxgep)) {
			dev_gindex =
			    nxgep->pt_config.hw_config.def_mac_rxdma_grpid +
			    groupid;

			if (nxgep->pt_config.hw_config.def_mac_rxdma_grpid ==
			    dev_gindex)
				group->port_default_grp = B_TRUE;

			infop->mgi_count =
			    nxgep->pt_config.rdc_grps[dev_gindex].max_rdcs;
		} else {
			infop->mgi_count = NXGE_HIO_SHARE_MAX_CHANNELS;
		}

		infop->mgi_driver = (mac_group_driver_t)group;
		infop->mgi_start = nxge_hio_group_start;
		infop->mgi_stop = nxge_hio_group_stop;
		infop->mgi_addmac = nxge_hio_add_mac;
		infop->mgi_remmac = nxge_hio_rem_mac;
		break;

	case MAC_RING_TYPE_TX:
		/*
		 * 'groupid' for TX should be incremented by one since
		 * the default group (groupid 0) is not known by the MAC layer
		 */
		group = &nxgep->tx_hio_groups[groupid + 1];
		group->nxgep = nxgep;
		group->ghandle = ghdl;
		group->gindex = groupid + 1;
		group->sindex = 0;	/* not yet bound to a share */

		infop->mgi_driver = (mac_group_driver_t)group;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = NULL;	/* not needed */
		infop->mgi_remmac = NULL;	/* not needed */
		/* no rings associated with group initially */
		infop->mgi_count = 0;
		break;
	}
}

#if defined(sun4v)

int
nxge_hio_share_assign(
	nxge_t *nxge,
	uint64_t cookie,
	res_map_t *tmap,
	res_map_t *rmap,
	nxge_hio_vr_t *vr)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	uint64_t slot, hv_rv;
	nxge_hio_dc_t *dc;
	nxhv_vr_fp_t *fp;
	int i;
	uint64_t major;

	/*
	 * Ask the Hypervisor to set up the VR for us
	 */
	fp = &nhd->hio.vr;
	major = nxge->niu_hsvc.hsvc_major;
	switch (major) {
	case NIU_MAJOR_VER: /* 1 */
		if ((hv_rv = (*fp->assign)(vr->region, cookie, &vr->cookie))) {
			NXGE_ERROR_MSG((nxge, HIO_CTL,
			    "nxge_hio_share_assign: major %d "
			    "vr->assign() returned %d", major, hv_rv));
			nxge_hio_unshare(vr);
			return (-EIO);
		}

		break;

	case NIU_MAJOR_VER_2: /* 2 */
	default:
		if ((hv_rv = (*fp->cfgh_assign)
		    (nxge->niu_cfg_hdl, vr->region, cookie, &vr->cookie))) {
			NXGE_ERROR_MSG((nxge, HIO_CTL,
			    "nxge_hio_share_assign: major %d "
			    "vr->assign() returned %d", major, hv_rv));
			nxge_hio_unshare(vr);
			return (-EIO);
		}

		break;
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_hio_share_assign: major %d "
	    "vr->assign() success", major));

	/*
	 * For each shared TDC, ask the HV to find us an empty slot.
	 */
	dc = vr->tx_group.dc;
	for (i = 0; i < NXGE_MAX_TDCS; i++) {
		nxhv_dc_fp_t *tx = &nhd->hio.tx;
		while (dc) {
			hv_rv = (*tx->assign)
			    (vr->cookie, dc->channel, &slot);
			if (hv_rv != 0) {
				NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
				    "nxge_hio_share_assign: "
				    "tx->assign(%x, %d) failed: %ld",
				    vr->cookie, dc->channel, hv_rv));
				return (-EIO);
			}

			dc->cookie = vr->cookie;
			dc->page = (vp_channel_t)slot;

			/* Inform the caller about the slot chosen. */
			(*tmap) |= 1 << slot;

			dc = dc->next;
		}
	}

	/*
	 * For each shared RDC, ask the HV to find us an empty slot.
	 */
	dc = vr->rx_group.dc;
	for (i = 0; i < NXGE_MAX_RDCS; i++) {
		nxhv_dc_fp_t *rx = &nhd->hio.rx;
		while (dc) {
			hv_rv = (*rx->assign)
			    (vr->cookie, dc->channel, &slot);
			if (hv_rv != 0) {
				NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
				    "nxge_hio_share_assign: "
				    "rx->assign(%x, %d) failed: %ld",
				    vr->cookie, dc->channel, hv_rv));
				return (-EIO);
			}

			dc->cookie = vr->cookie;
			dc->page = (vp_channel_t)slot;

			/* Inform the caller about the slot chosen. */
			(*rmap) |= 1 << slot;

			dc = dc->next;
		}
	}

	return (0);
}

void
nxge_hio_share_unassign(
	nxge_hio_vr_t *vr)
{
	nxge_t *nxge = (nxge_t *)vr->nxge;
	nxge_hio_data_t *nhd;
	nxge_hio_dc_t *dc;
	nxhv_vr_fp_t *fp;
	uint64_t hv_rv;

	nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	dc = vr->tx_group.dc;
	while (dc) {
		nxhv_dc_fp_t *tx = &nhd->hio.tx;
		hv_rv = (*tx->unassign)(vr->cookie, dc->page);
		if (hv_rv != 0) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "nxge_hio_share_unassign: "
			    "tx->unassign(%x, %d) failed: %ld",
			    vr->cookie, dc->page, hv_rv));
		}
		dc = dc->next;
	}

	dc = vr->rx_group.dc;
	while (dc) {
		nxhv_dc_fp_t *rx = &nhd->hio.rx;
		hv_rv = (*rx->unassign)(vr->cookie, dc->page);
		if (hv_rv != 0) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "nxge_hio_share_unassign: "
			    "rx->unassign(%x, %d) failed: %ld",
			    vr->cookie, dc->page, hv_rv));
		}
		dc = dc->next;
	}

	fp = &nhd->hio.vr;
	if (fp->unassign) {
		hv_rv = (*fp->unassign)(vr->cookie);
		if (hv_rv != 0) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "nxge_hio_share_unassign: "
			    "vr->assign(%x) failed: %ld",
			    vr->cookie, hv_rv));
		}
	}
}

int
nxge_hio_share_alloc(void *arg, mac_share_handle_t *shandle)
{
	p_nxge_t		nxge = (p_nxge_t)arg;
	nxge_share_handle_t	*shp;
	nxge_hio_vr_t		*vr;	/* The Virtualization Region */
	nxge_hio_data_t		*nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_share"));

	if (nhd->hio.vr.assign == 0 || nhd->hio.tx.assign == 0 ||
	    nhd->hio.rx.assign == 0) {
		NXGE_ERROR_MSG((nxge, HIO_CTL, "HV assign function(s) NULL"));
		return (EIO);
	}

	/*
	 * Get a VR.
	 */
	if ((vr = nxge_hio_vr_share(nxge)) == 0)
		return (EAGAIN);

	shp = &nxge->shares[vr->region];
	shp->nxgep = nxge;
	shp->index = vr->region;
	shp->vrp = (void *)vr;
	shp->tmap = shp->rmap = 0;	/* to be assigned by ms_sbind */
	shp->rxgroup = 0;		/* to be assigned by ms_sadd */
	shp->active = B_FALSE;		/* not bound yet */

	*shandle = (mac_share_handle_t)shp;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_share"));
	return (0);
}


void
nxge_hio_share_free(mac_share_handle_t shandle)
{
	nxge_share_handle_t	*shp = (nxge_share_handle_t *)shandle;
	nxge_hio_vr_t		*vr;

	/*
	 * Clear internal handle state.
	 */
	vr = shp->vrp;
	shp->vrp = (void *)NULL;
	shp->index = 0;
	shp->tmap = 0;
	shp->rmap = 0;
	shp->rxgroup = 0;
	shp->active = B_FALSE;

	/*
	 * Free VR resource.
	 */
	nxge_hio_unshare(vr);
}


void
nxge_hio_share_query(mac_share_handle_t shandle, mac_ring_type_t type,
    mac_ring_handle_t *rings, uint_t *n_rings)
{
	nxge_t			*nxge;
	nxge_share_handle_t	*shp = (nxge_share_handle_t *)shandle;
	nxge_ring_handle_t	*rh;
	uint32_t		offset;

	nxge = shp->nxgep;

	switch (type) {
	case MAC_RING_TYPE_RX:
		rh = nxge->rx_ring_handles;
		offset = nxge->pt_config.hw_config.start_rdc;
		break;

	case MAC_RING_TYPE_TX:
		rh = nxge->tx_ring_handles;
		offset = nxge->pt_config.hw_config.tdc.start;
		break;
	}

	/*
	 * In version 1.0, we may only give a VR 2 RDCs/TDCs.  Not only that,
	 * but the HV has statically assigned the channels like so:
	 * VR0: RDC0 & RDC1
	 * VR1: RDC2 & RDC3, etc.
	 * The TDCs are assigned in exactly the same way.
	 */
	if (rings != NULL) {
		rings[0] = rh[(shp->index * 2) - offset].ring_handle;
		rings[1] = rh[(shp->index * 2 + 1) - offset].ring_handle;
	}
	if (n_rings != NULL) {
		*n_rings = 2;
	}
}

int
nxge_hio_share_add_group(mac_share_handle_t shandle,
    mac_group_driver_t ghandle)
{
	nxge_t			*nxge;
	nxge_share_handle_t	*shp = (nxge_share_handle_t *)shandle;
	nxge_ring_group_t	*rg = (nxge_ring_group_t *)ghandle;
	nxge_hio_vr_t		*vr;	/* The Virtualization Region */
	nxge_grp_t		*group;
	int			i;

	if (rg->sindex != 0) {
		/* the group is already bound to a share */
		return (EALREADY);
	}

	/*
	 * If we are adding a group 0 to a share, this
	 * is not correct.
	 */
	ASSERT(rg->gindex != 0);

	nxge = rg->nxgep;
	vr = shp->vrp;

	switch (rg->type) {
	case MAC_RING_TYPE_RX:
		/*
		 * Make sure that the group has the right rings associated
		 * for the share. In version 1.0, we may only give a VR
		 * 2 RDCs.  Not only that, but the HV has statically
		 * assigned the channels like so:
		 * VR0: RDC0 & RDC1
		 * VR1: RDC2 & RDC3, etc.
		 */
		group = nxge->rx_set.group[rg->gindex];

		if (group->count > 2) {
			/* a share can have at most 2 rings */
			return (EINVAL);
		}

		for (i = 0; i < NXGE_MAX_RDCS; i++) {
			if (group->map & (1 << i)) {
				if ((i != shp->index * 2) &&
				    (i != (shp->index * 2 + 1))) {
					/*
					 * A group with invalid rings was
					 * attempted to bind to this share
					 */
					return (EINVAL);
				}
			}
		}

		rg->sindex = vr->region;
		vr->rdc_tbl = rg->rdctbl;
		shp->rxgroup = vr->rdc_tbl;
		break;

	case MAC_RING_TYPE_TX:
		/*
		 * Make sure that the group has the right rings associated
		 * for the share. In version 1.0, we may only give a VR
		 * 2 TDCs.  Not only that, but the HV has statically
		 * assigned the channels like so:
		 * VR0: TDC0 & TDC1
		 * VR1: TDC2 & TDC3, etc.
		 */
		group = nxge->tx_set.group[rg->gindex];

		if (group->count > 2) {
			/* a share can have at most 2 rings */
			return (EINVAL);
		}

		for (i = 0; i < NXGE_MAX_TDCS; i++) {
			if (group->map & (1 << i)) {
				if ((i != shp->index * 2) &&
				    (i != (shp->index * 2 + 1))) {
					/*
					 * A group with invalid rings was
					 * attempted to bind to this share
					 */
					return (EINVAL);
				}
			}
		}

		vr->tdc_tbl = nxge->pt_config.hw_config.def_mac_txdma_grpid +
		    rg->gindex;
		rg->sindex = vr->region;
		break;
	}
	return (0);
}

int
nxge_hio_share_rem_group(mac_share_handle_t shandle,
    mac_group_driver_t ghandle)
{
	nxge_share_handle_t	*shp = (nxge_share_handle_t *)shandle;
	nxge_ring_group_t	*group = (nxge_ring_group_t *)ghandle;
	nxge_hio_vr_t		*vr;	/* The Virtualization Region */
	int			rv = 0;

	vr = shp->vrp;

	switch (group->type) {
	case MAC_RING_TYPE_RX:
		group->sindex = 0;
		vr->rdc_tbl = 0;
		shp->rxgroup = 0;
		break;

	case MAC_RING_TYPE_TX:
		group->sindex = 0;
		vr->tdc_tbl = 0;
		break;
	}

	return (rv);
}

int
nxge_hio_share_bind(mac_share_handle_t shandle, uint64_t cookie,
    uint64_t *rcookie)
{
	nxge_t			*nxge;
	nxge_share_handle_t	*shp = (nxge_share_handle_t *)shandle;
	nxge_hio_vr_t		*vr;
	uint64_t		rmap, tmap, hv_rmap, hv_tmap;
	int			rv;

	ASSERT(shp != NULL);
	ASSERT(shp->nxgep != NULL);
	ASSERT(shp->vrp != NULL);

	nxge = shp->nxgep;
	vr = (nxge_hio_vr_t *)shp->vrp;

	/*
	 * Add resources to the share.
	 * For each DMA channel associated with the VR, bind its resources
	 * to the VR.
	 */
	tmap = 0;
	rv = nxge_hio_addres(vr, MAC_RING_TYPE_TX, &tmap);
	if (rv != 0) {
		return (rv);
	}

	rmap = 0;
	rv = nxge_hio_addres(vr, MAC_RING_TYPE_RX, &rmap);
	if (rv != 0) {
		nxge_hio_remres(vr, MAC_RING_TYPE_TX, tmap);
		return (rv);
	}

	/*
	 * Ask the Hypervisor to set up the VR and allocate slots for
	 * each rings associated with the VR.
	 */
	hv_tmap = hv_rmap = 0;
	if ((rv = nxge_hio_share_assign(nxge, cookie,
	    &hv_tmap, &hv_rmap, vr))) {
		nxge_hio_remres(vr, MAC_RING_TYPE_TX, tmap);
		nxge_hio_remres(vr, MAC_RING_TYPE_RX, rmap);
		return (rv);
	}

	shp->active = B_TRUE;
	shp->tmap = hv_tmap;
	shp->rmap = hv_rmap;

	/* high 32 bits are cfg_hdl and low 32 bits are HV cookie */
	*rcookie = (((uint64_t)nxge->niu_cfg_hdl) << 32) | vr->cookie;

	return (0);
}

void
nxge_hio_share_unbind(mac_share_handle_t shandle)
{
	nxge_share_handle_t *shp = (nxge_share_handle_t *)shandle;

	/*
	 * First, unassign the VR (take it back),
	 * so we can enable interrupts again.
	 */
	nxge_hio_share_unassign(shp->vrp);

	/*
	 * Free Ring Resources for TX and RX
	 */
	nxge_hio_remres(shp->vrp, MAC_RING_TYPE_TX, shp->tmap);
	nxge_hio_remres(shp->vrp, MAC_RING_TYPE_RX, shp->rmap);
}


/*
 * nxge_hio_vr_share
 *
 *	Find an unused Virtualization Region (VR).
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *
 * Context:
 *	Service domain
 */
nxge_hio_vr_t *
nxge_hio_vr_share(
	nxge_t *nxge)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_vr_t *vr;

	int first, limit, region;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_vr_share"));

	MUTEX_ENTER(&nhd->lock);

	if (nhd->vrs == 0) {
		MUTEX_EXIT(&nhd->lock);
		return (0);
	}

	/* Find an empty virtual region (VR). */
	if (nxge->function_num == 0) {
		// FUNC0_VIR0 'belongs' to NIU port 0.
		first = FUNC0_VIR1;
		limit = FUNC2_VIR0;
	} else if (nxge->function_num == 1) {
		// FUNC2_VIR0 'belongs' to NIU port 1.
		first = FUNC2_VIR1;
		limit = FUNC_VIR_MAX;
	} else {
		cmn_err(CE_WARN,
		    "Shares not supported on function(%d) at this time.\n",
		    nxge->function_num);
	}

	for (region = first; region < limit; region++) {
		if (nhd->vr[region].nxge == 0)
			break;
	}

	if (region == limit) {
		MUTEX_EXIT(&nhd->lock);
		return (0);
	}

	vr = &nhd->vr[region];
	vr->nxge = (uintptr_t)nxge;
	vr->region = (uintptr_t)region;

	nhd->vrs--;

	MUTEX_EXIT(&nhd->lock);

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_vr_share"));

	return (vr);
}

void
nxge_hio_unshare(
	nxge_hio_vr_t *vr)
{
	nxge_t *nxge = (nxge_t *)vr->nxge;
	nxge_hio_data_t *nhd;

	vr_region_t region;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_unshare"));

	if (!nxge) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_unshare: "
		    "vr->nxge is NULL"));
		return;
	}

	/*
	 * This function is no longer called, but I will keep it
	 * here in case we want to revisit this topic in the future.
	 *
	 * nxge_hio_hostinfo_uninit(nxge, vr);
	 */

	/*
	 * XXX: This is done by ms_sremove?
	 * (void) nxge_fzc_rdc_tbl_unbind(nxge, vr->rdc_tbl);
	 */

	nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	MUTEX_ENTER(&nhd->lock);

	region = vr->region;
	(void) memset(vr, 0, sizeof (*vr));
	vr->region = region;

	nhd->vrs++;

	MUTEX_EXIT(&nhd->lock);

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_unshare"));
}

int
nxge_hio_addres(nxge_hio_vr_t *vr, mac_ring_type_t type, uint64_t *map)
{
	nxge_t		*nxge;
	nxge_grp_t	*group;
	int		groupid;
	int		i, rv = 0;
	int		max_dcs;

	ASSERT(vr != NULL);
	ASSERT(vr->nxge != NULL);
	nxge = (nxge_t *)vr->nxge;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_addres"));

	/*
	 * For each ring associated with the group, add the resources
	 * to the group and bind.
	 */
	max_dcs = (type == MAC_RING_TYPE_TX) ? NXGE_MAX_TDCS : NXGE_MAX_RDCS;
	if (type == MAC_RING_TYPE_TX) {
		/* set->group is an array of group indexed by a port group id */
		groupid = vr->tdc_tbl -
		    nxge->pt_config.hw_config.def_mac_txdma_grpid;
		group = nxge->tx_set.group[groupid];
	} else {
		/* set->group is an array of group indexed by a port group id */
		groupid = vr->rdc_tbl -
		    nxge->pt_config.hw_config.def_mac_rxdma_grpid;
		group = nxge->rx_set.group[groupid];
	}

	ASSERT(group != NULL);

	if (group->map == 0) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL, "There is no rings associated "
		    "with this VR"));
		return (EINVAL);
	}

	for (i = 0; i < max_dcs; i++) {
		if (group->map & (1 << i)) {
			if ((rv = nxge_hio_dc_share(nxge, vr, type, i)) < 0) {
				if (*map == 0) /* Couldn't get even one DC. */
					return (-rv);
				else
					break;
			}
			*map |= (1 << i);
		}
	}

	if ((*map == 0) || (rv != 0)) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL,
		    "<== nxge_hio_addres: rv(%x)", rv));
		return (EIO);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_addres"));
	return (0);
}

/* ARGSUSED */
void
nxge_hio_remres(
	nxge_hio_vr_t *vr,
	mac_ring_type_t type,
	res_map_t res_map)
{
	nxge_t *nxge = (nxge_t *)vr->nxge;
	nxge_grp_t *group;

	if (!nxge) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_remres: "
		    "vr->nxge is NULL"));
		return;
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_remres(%lx)", res_map));

	/*
	 * For each ring bound to the group, remove the DMA resources
	 * from the group and unbind.
	 */
	group = (type == MAC_RING_TYPE_TX ? &vr->tx_group : &vr->rx_group);
	while (group->dc) {
		nxge_hio_dc_t *dc = group->dc;
		NXGE_DC_RESET(res_map, dc->page);
		nxge_hio_dc_unshare(nxge, vr, type, dc->channel);
	}

	if (res_map) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_remres: "
		    "res_map %lx", res_map));
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_remres"));
}

/*
 * nxge_hio_tdc_share
 *
 *	Share an unused TDC channel.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *
 * A.7.3 Reconfigure Tx DMA channel
 *	Disable TxDMA			A.9.6.10
 *     [Rebind TxDMA channel to Port	A.9.6.7]
 *
 * We don't have to Rebind the TDC to the port - it always already bound.
 *
 *	Soft Reset TxDMA		A.9.6.2
 *
 * This procedure will be executed by nxge_init_txdma_channel() in the
 * guest domain:
 *
 *	Re-initialize TxDMA		A.9.6.8
 *	Reconfigure TxDMA
 *	Enable TxDMA			A.9.6.9
 *
 * Context:
 *	Service domain
 */
int
nxge_hio_tdc_share(
	nxge_t *nxge,
	int channel)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_grp_set_t *set = &nxge->tx_set;
	tx_ring_t *ring;
	int count;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_tdc_share"));

	/*
	 * Wait until this channel is idle.
	 */
	ring = nxge->tx_rings->rings[channel];
	ASSERT(ring != NULL);

	(void) atomic_swap_32(&ring->tx_ring_offline, NXGE_TX_RING_OFFLINING);
	if (ring->tx_ring_busy) {
		/*
		 * Wait for 30 seconds.
		 */
		for (count = 30 * 1000; count; count--) {
			if (ring->tx_ring_offline & NXGE_TX_RING_OFFLINED) {
				break;
			}

			drv_usecwait(1000);
		}

		if (count == 0) {
			(void) atomic_swap_32(&ring->tx_ring_offline,
			    NXGE_TX_RING_ONLINE);
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "nxge_hio_tdc_share: "
			    "Tx ring %d was always BUSY", channel));
			return (-EIO);
		}
	} else {
		(void) atomic_swap_32(&ring->tx_ring_offline,
		    NXGE_TX_RING_OFFLINED);
	}

	MUTEX_ENTER(&nhd->lock);
	nxge->tdc_is_shared[channel] = B_TRUE;
	MUTEX_EXIT(&nhd->lock);

	if (nxge_intr_remove(nxge, VP_BOUND_TX, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_tdc_share: "
		    "Failed to remove interrupt for TxDMA channel %d",
		    channel));
		return (-EINVAL);
	}

	/* Disable TxDMA A.9.6.10 */
	(void) nxge_txdma_channel_disable(nxge, channel);

	/* The SD is sharing this channel. */
	NXGE_DC_SET(set->shared.map, channel);
	set->shared.count++;

	/* Soft Reset TxDMA A.9.6.2 */
	nxge_grp_dc_remove(nxge, VP_BOUND_TX, channel);

	/*
	 * Initialize the DC-specific FZC control registers.
	 * -----------------------------------------------------
	 */
	if (nxge_init_fzc_tdc(nxge, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_tdc_share: FZC TDC failed: %d", channel));
		return (-EIO);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_tdc_share"));

	return (0);
}

/*
 * nxge_hio_rdc_share
 *
 *	Share an unused RDC channel.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *
 * This is the latest version of the procedure to
 * Reconfigure an Rx DMA channel:
 *
 * A.6.3 Reconfigure Rx DMA channel
 *	Stop RxMAC		A.9.2.6
 *	Drain IPP Port		A.9.3.6
 *	Stop and reset RxDMA	A.9.5.3
 *
 * This procedure will be executed by nxge_init_rxdma_channel() in the
 * guest domain:
 *
 *	Initialize RxDMA	A.9.5.4
 *	Reconfigure RxDMA
 *	Enable RxDMA		A.9.5.5
 *
 * We will do this here, since the RDC is a canalis non grata:
 *	Enable RxMAC		A.9.2.10
 *
 * Context:
 *	Service domain
 */
int
nxge_hio_rdc_share(
	nxge_t *nxge,
	nxge_hio_vr_t *vr,
	int channel)
{
	nxge_grp_set_t *set = &nxge->rx_set;
	nxge_rdc_grp_t *rdc_grp;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_rdc_share"));

	/* Disable interrupts. */
	if (nxge_intr_remove(nxge, VP_BOUND_RX, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_rdc_share: "
		    "Failed to remove interrupt for RxDMA channel %d",
		    channel));
		return (NXGE_ERROR);
	}

	/* Stop RxMAC = A.9.2.6 */
	if (nxge_rx_mac_disable(nxge) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_rdc_share: "
		    "Failed to disable RxMAC"));
	}

	/* Drain IPP Port = A.9.3.6 */
	(void) nxge_ipp_drain(nxge);

	/* Stop and reset RxDMA = A.9.5.3 */
	// De-assert EN: RXDMA_CFIG1[31] = 0 (DMC+00000 )
	if (nxge_disable_rxdma_channel(nxge, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_rdc_share: "
		    "Failed to disable RxDMA channel %d", channel));
	}

	/* The SD is sharing this channel. */
	NXGE_DC_SET(set->shared.map, channel);
	set->shared.count++;

	// Assert RST: RXDMA_CFIG1[30] = 1
	nxge_grp_dc_remove(nxge, VP_BOUND_RX, channel);

	/*
	 * The guest domain will reconfigure the RDC later.
	 *
	 * But in the meantime, we must re-enable the Rx MAC so
	 * that we can start receiving packets again on the
	 * remaining RDCs:
	 *
	 * Enable RxMAC = A.9.2.10
	 */
	if (nxge_rx_mac_enable(nxge) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_rdc_share: Rx MAC still disabled"));
	}

	/*
	 * Initialize the DC-specific FZC control registers.
	 * -----------------------------------------------------
	 */
	if (nxge_init_fzc_rdc(nxge, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_rdc_share: RZC RDC failed: %ld", channel));
		return (-EIO);
	}

	/*
	 * Update the RDC group.
	 */
	rdc_grp = &nxge->pt_config.rdc_grps[vr->rdc_tbl];
	NXGE_DC_SET(rdc_grp->map, channel);

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_rdc_share"));

	return (0);
}

/*
 * nxge_hio_dc_share
 *
 *	Share a DMA channel with a guest domain.
 *
 * Arguments:
 * 	nxge
 * 	vr	The VR that <channel> will belong to.
 * 	type	Tx or Rx.
 * 	channel	Channel to share
 *
 * Notes:
 *
 * Context:
 *	Service domain
 */
int
nxge_hio_dc_share(
	nxge_t *nxge,
	nxge_hio_vr_t *vr,
	mac_ring_type_t type,
	int channel)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_dc_t *dc;
	nxge_grp_t *group;
	int slot;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_dc_share(%cdc %d",
	    type == MAC_RING_TYPE_TX ? 't' : 'r', channel));


	/* -------------------------------------------------- */
	slot = (type == MAC_RING_TYPE_TX) ?
	    nxge_hio_tdc_share(nxge, channel) :
	    nxge_hio_rdc_share(nxge, vr, channel);

	if (slot < 0) {
		if (type == MAC_RING_TYPE_RX) {
			nxge_hio_rdc_unshare(nxge, vr->rdc_tbl, channel);
		} else {
			nxge_hio_tdc_unshare(nxge, vr->tdc_tbl, channel);
		}
		return (slot);
	}

	MUTEX_ENTER(&nhd->lock);

	/*
	 * Tag this channel.
	 * --------------------------------------------------
	 */
	dc = type == MAC_RING_TYPE_TX ? &nhd->tdc[channel] : &nhd->rdc[channel];

	dc->vr = vr;
	dc->channel = (nxge_channel_t)channel;

	MUTEX_EXIT(&nhd->lock);

	/*
	 * vr->[t|r]x_group is used by the service domain to
	 * keep track of its shared DMA channels.
	 */
	MUTEX_ENTER(&nxge->group_lock);
	group = (type == MAC_RING_TYPE_TX ? &vr->tx_group : &vr->rx_group);

	dc->group = group;
	/* Initialize <group>, if necessary */
	if (group->count == 0) {
		group->nxge = nxge;
		group->type = (type == MAC_RING_TYPE_TX) ?
		    VP_BOUND_TX : VP_BOUND_RX;
		group->sequence	= nhd->sequence++;
		group->active = B_TRUE;
	}

	MUTEX_EXIT(&nxge->group_lock);

	NXGE_ERROR_MSG((nxge, HIO_CTL,
	    "DC share: %cDC %d was assigned to slot %d",
	    type == MAC_RING_TYPE_TX ? 'T' : 'R', channel, slot));

	nxge_grp_dc_append(nxge, group, dc);

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_dc_share"));

	return (0);
}

/*
 * nxge_hio_tdc_unshare
 *
 *	Unshare a TDC.
 *
 * Arguments:
 * 	nxge
 * 	channel	The channel to unshare (add again).
 *
 * Notes:
 *
 * Context:
 *	Service domain
 */
void
nxge_hio_tdc_unshare(
	nxge_t *nxge,
	int dev_grpid,
	int channel)
{
	nxge_grp_set_t *set = &nxge->tx_set;
	nxge_grp_t *group;
	int grpid;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_tdc_unshare"));

	NXGE_DC_RESET(set->shared.map, channel);
	set->shared.count--;

	grpid = dev_grpid - nxge->pt_config.hw_config.def_mac_txdma_grpid;
	group = set->group[grpid];

	if ((nxge_grp_dc_add(nxge, group, VP_BOUND_TX, channel))) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_tdc_unshare: "
		    "Failed to initialize TxDMA channel %d", channel));
		return;
	}

	/* Re-add this interrupt. */
	if (nxge_intr_add(nxge, VP_BOUND_TX, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_tdc_unshare: "
		    "Failed to add interrupt for TxDMA channel %d", channel));
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_tdc_unshare"));
}

/*
 * nxge_hio_rdc_unshare
 *
 *	Unshare an RDC: add it to the SD's RDC groups (tables).
 *
 * Arguments:
 * 	nxge
 * 	channel	The channel to unshare (add again).
 *
 * Notes:
 *
 * Context:
 *	Service domain
 */
void
nxge_hio_rdc_unshare(
	nxge_t *nxge,
	int dev_grpid,
	int channel)
{
	nxge_grp_set_t		*set = &nxge->rx_set;
	nxge_grp_t		*group;
	int			grpid;
	int			i;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_rdc_unshare"));

	/* Stop RxMAC = A.9.2.6 */
	if (nxge_rx_mac_disable(nxge) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_rdc_unshare: "
		    "Failed to disable RxMAC"));
	}

	/* Drain IPP Port = A.9.3.6 */
	(void) nxge_ipp_drain(nxge);

	/* Stop and reset RxDMA = A.9.5.3 */
	// De-assert EN: RXDMA_CFIG1[31] = 0 (DMC+00000 )
	if (nxge_disable_rxdma_channel(nxge, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_rdc_unshare: "
		    "Failed to disable RxDMA channel %d", channel));
	}

	NXGE_DC_RESET(set->shared.map, channel);
	set->shared.count--;

	grpid = dev_grpid - nxge->pt_config.hw_config.def_mac_rxdma_grpid;
	group = set->group[grpid];

	/*
	 * Assert RST: RXDMA_CFIG1[30] = 1
	 *
	 * Initialize RxDMA	A.9.5.4
	 * Reconfigure RxDMA
	 * Enable RxDMA		A.9.5.5
	 */
	if ((nxge_grp_dc_add(nxge, group, VP_BOUND_RX, channel))) {
		/* Be sure to re-enable the RX MAC. */
		if (nxge_rx_mac_enable(nxge) != NXGE_OK) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "nxge_hio_rdc_share: Rx MAC still disabled"));
		}
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_rdc_unshare: "
		    "Failed to initialize RxDMA channel %d", channel));
		return;
	}

	/*
	 * Enable RxMAC = A.9.2.10
	 */
	if (nxge_rx_mac_enable(nxge) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_rdc_share: Rx MAC still disabled"));
		return;
	}

	/* Re-add this interrupt. */
	if (nxge_intr_add(nxge, VP_BOUND_RX, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_rdc_unshare: Failed to add interrupt for "
		    "RxDMA CHANNEL %d", channel));
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_rdc_unshare"));

	for (i = 0; i < NXGE_MAX_RDCS; i++) {
		if (nxge->rx_ring_handles[i].channel == channel) {
			(void) nxge_rx_ring_start(
			    (mac_ring_driver_t)&nxge->rx_ring_handles[i],
			    nxge->rx_ring_handles[i].ring_gen_num);
		}
	}
}

/*
 * nxge_hio_dc_unshare
 *
 *	Unshare (reuse) a DMA channel.
 *
 * Arguments:
 * 	nxge
 * 	vr	The VR that <channel> belongs to.
 * 	type	Tx or Rx.
 * 	channel	The DMA channel to reuse.
 *
 * Notes:
 *
 * Context:
 *	Service domain
 */
void
nxge_hio_dc_unshare(
	nxge_t *nxge,
	nxge_hio_vr_t *vr,
	mac_ring_type_t type,
	int channel)
{
	nxge_grp_t *group;
	nxge_hio_dc_t *dc;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_dc_unshare(%cdc %d)",
	    type == MAC_RING_TYPE_TX ? 't' : 'r', channel));

	/* Unlink the channel from its group. */
	/* -------------------------------------------------- */
	group = (type == MAC_RING_TYPE_TX) ? &vr->tx_group : &vr->rx_group;
	NXGE_DC_RESET(group->map, channel);
	if ((dc = nxge_grp_dc_unlink(nxge, group, channel)) == 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_dc_unshare(%d) failed", channel));
		return;
	}

	dc->vr = 0;
	dc->cookie = 0;

	if (type == MAC_RING_TYPE_RX) {
		nxge_hio_rdc_unshare(nxge, vr->rdc_tbl, channel);
	} else {
		nxge_hio_tdc_unshare(nxge, vr->tdc_tbl, channel);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_dc_unshare"));
}


/*
 * nxge_hio_rxdma_bind_intr():
 *
 *	For the guest domain driver, need to bind the interrupt group
 *	and state to the rx_rcr_ring_t.
 */

int
nxge_hio_rxdma_bind_intr(nxge_t *nxge, rx_rcr_ring_t *ring, int channel)
{
	nxge_hio_dc_t	*dc;
	nxge_ldgv_t	*control;
	nxge_ldg_t	*group;
	nxge_ldv_t	*device;

	/*
	 * Find the DMA channel.
	 */
	if (!(dc = nxge_grp_dc_find(nxge, VP_BOUND_RX, channel))) {
		return (NXGE_ERROR);
	}

	/*
	 * Get the control structure.
	 */
	control = nxge->ldgvp;
	if (control == NULL) {
		return (NXGE_ERROR);
	}

	group = &control->ldgp[dc->ldg.vector];
	device = &control->ldvp[dc->ldg.ldsv];

	MUTEX_ENTER(&ring->lock);
	ring->ldgp = group;
	ring->ldvp = device;
	MUTEX_EXIT(&ring->lock);

	return (NXGE_OK);
}
#endif	/* if defined(sun4v) */
