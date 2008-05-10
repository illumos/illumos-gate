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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nxge_hio.c
 *
 * This file manages the virtualization resources for Neptune
 * devices.  That is, it implements a hybrid I/O (HIO) approach in the
 * Solaris kernel, whereby a guest domain on an LDOMs server may
 * request & use hardware resources from the service domain.
 *
 */

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_fzc.h>
#include <sys/nxge/nxge_rxdma.h>
#include <sys/nxge/nxge_txdma.h>
#include <sys/nxge/nxge_hio.h>

#define	NXGE_HIO_SHARE_MIN_CHANNELS 2
#define	NXGE_HIO_SHARE_MAX_CHANNELS 2

/*
 * External prototypes
 */
extern npi_status_t npi_rxdma_dump_rdc_table(npi_handle_t, uint8_t);

/* The following function may be found in nxge_main.c */
extern int nxge_m_mmac_remove(void *arg, mac_addr_slot_t slot);

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
nxge_hio_init(
	nxge_t *nxge)
{
	nxge_hio_data_t *nhd;

	nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	if (nhd == 0) {
		nhd = KMEM_ZALLOC(sizeof (*nhd), KM_SLEEP);
		MUTEX_INIT(&nhd->lock, NULL, MUTEX_DRIVER, NULL);
		nxge->nxge_hw_p->hio = (uintptr_t)nhd;
	}

	nhd->hio.ldoms = B_FALSE;

	return (NXGE_OK);
}

#endif

void
nxge_hio_uninit(
	nxge_t *nxge)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	ASSERT(nhd != NULL);
	ASSERT(nxge->nxge_hw_p->ndevs == 0);

	MUTEX_DESTROY(&nhd->lock);

	KMEM_FREE(nhd, sizeof (*nhd));

	nxge->nxge_hw_p->hio = 0;
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
vr_handle_t
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

	return ((vr_handle_t)group);
}

void
nxge_grp_remove(
	nxge_t *nxge,
	vr_handle_t handle)	/* The group to remove. */
{
	nxge_grp_set_t *set;
	nxge_grp_t *group;
	vpc_type_t type;

	group = (nxge_grp_t *)handle;

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
 * nx_hio_dc_add
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
	vr_handle_t handle,	/* The group to add <channel> to. */
	vpc_type_t type,	/* Rx or Tx */
	int channel)		/* A physical/logical channel number */
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_dc_t *dc;
	nxge_grp_set_t *set;
	nxge_grp_t *group;
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_grp_dc_add"));

	if (handle == 0)
		return (0);

	switch (type) {
	default:
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
	}

	group = (nxge_grp_t *)handle;
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

	dc->group = handle;

	if (isLDOMguest(nxge))
		(void) nxge_hio_ldsv_add(nxge, dc);

	NXGE_DC_SET(set->owned.map, channel);
	set->owned.count++;

	MUTEX_EXIT(&nhd->lock);

	if ((status = (*dc->init)(nxge, channel)) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_grp_dc_add(%d): channel init failed", channel));
		return (NXGE_ERROR);	
	}

	nxge_grp_dc_append(nxge, group, dc);

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

	if ((dc = nxge_grp_dc_find(nxge, type, channel)) == 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_dc_remove: find(%d) failed", channel));
		return;
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
	if (isLDOMs(nxge) && ((1 << channel) && set->shared.map)) {
		NXGE_DC_RESET(group->map, channel);
	}

	/* Remove the DC from its group. */
	if (nxge_grp_dc_unlink(nxge, group, channel) != dc) {
		MUTEX_EXIT(&nhd->lock);
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_dc_remove(%d) failed", channel));
		return;
	}

	uninit = dc->uninit;
	channel = dc->channel;

	NXGE_DC_RESET(set->owned.map, channel);
	set->owned.count--;

	(void) memset(dc, 0, sizeof (*dc));

	MUTEX_EXIT(&nhd->lock);

	(*uninit)(nxge, channel);

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
static vr_handle_t nxge_hio_vr_share(nxge_t *);

static int nxge_hio_dc_share(nxge_t *, nxge_hio_vr_t *, mac_ring_type_t);
static void nxge_hio_unshare(vr_handle_t);

static int nxge_hio_addres(vr_handle_t, mac_ring_type_t, int);
static void nxge_hio_remres(vr_handle_t, mac_ring_type_t, res_map_t);

static void nxge_hio_tdc_unshare(nxge_t *nxge, int channel);
static void nxge_hio_rdc_unshare(nxge_t *nxge, int channel);
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
nxge_hio_init(
	nxge_t *nxge)
{
	nxge_hio_data_t *nhd;
	int i, region;

	nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	if (nhd == 0) {
		nhd = KMEM_ZALLOC(sizeof (*nhd), KM_SLEEP);
		MUTEX_INIT(&nhd->lock, NULL, MUTEX_DRIVER, NULL);
		nxge->nxge_hw_p->hio = (uintptr_t)nhd;
	}

	if (nxge->environs == SOLARIS_DOMAIN) {
		if (nxge->niu_hsvc_available == B_TRUE) {
			hsvc_info_t *niu_hsvc = &nxge->niu_hsvc;
			if (niu_hsvc->hsvc_major == 1 &&
			    niu_hsvc->hsvc_minor == 1)
				nxge->environs = SOLARIS_SERVICE_DOMAIN;
			NXGE_DEBUG_MSG((nxge, HIO_CTL,
			    "nxge_hio_init: hypervisor services "
			    "version %d.%d",
			    niu_hsvc->hsvc_major, niu_hsvc->hsvc_minor));
		}
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
	nhd->available.vrs = NXGE_VR_SR_MAX - 2;

	/*
	 * Initialize share and ring group structures.
	 */
	for (i = 0; i < NXGE_MAX_RDC_GROUPS; i++) {
		nxge->rx_hio_groups[i].ghandle = NULL;
		nxge->rx_hio_groups[i].nxgep = nxge;
		nxge->rx_hio_groups[i].gindex = 0;
		nxge->rx_hio_groups[i].sindex = 0;
	}

	for (i = 0; i < NXGE_VR_SR_MAX; i++) {
		nxge->shares[i].nxgep = nxge;
		nxge->shares[i].index = 0;
		nxge->shares[i].vrp = (void *)NULL;
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
	} else {
		/*
		 * isLDOMguest(nxge) == B_TRUE
		 */
		nx_vio_fp_t *vio;
		nhd->type = NXGE_HIO_TYPE_GUEST;

		vio = &nhd->hio.vio;
		vio->__register = (vio_net_resource_reg_t)
		    modgetsymvalue("vio_net_resource_reg", 0);
		vio->unregister = (vio_net_resource_unreg_t)
		    modgetsymvalue("vio_net_resource_unreg", 0);

		if (vio->__register == 0 || vio->unregister == 0) {
			NXGE_ERROR_MSG((nxge, VIR_CTL, "vio_net is absent!"));
			return (NXGE_ERROR);
		}
	}

	return (0);
}

static int
nxge_hio_add_mac(void *arg, const uint8_t *mac_addr)
{
	nxge_rx_ring_group_t *rxgroup = (nxge_rx_ring_group_t *)arg;
	p_nxge_t nxge = rxgroup->nxgep;
	int group = rxgroup->gindex;
	int rv, sindex;
	nxge_hio_vr_t *vr;	/* The Virtualization Region */

	sindex = nxge->rx_hio_groups[group].sindex;
	vr = (nxge_hio_vr_t *)nxge->shares[sindex].vrp;

	/*
	 * Program the mac address for the group/share.
	 */
	if ((rv = nxge_hio_hostinfo_init(nxge, vr,
	    (ether_addr_t *)mac_addr)) != 0) {
		return (rv);
	}

	return (0);
}

/* ARGSUSED */
static int
nxge_hio_rem_mac(void *arg, const uint8_t *mac_addr)
{
	nxge_rx_ring_group_t *rxgroup = (nxge_rx_ring_group_t *)arg;
	p_nxge_t nxge = rxgroup->nxgep;
	int group = rxgroup->gindex;
	int sindex;
	nxge_hio_vr_t *vr;	/* The Virtualization Region */

	sindex = nxge->rx_hio_groups[group].sindex;
	vr = (nxge_hio_vr_t *)nxge->shares[sindex].vrp;

	/*
	 * Remove the mac address for the group/share.
	 */
	nxge_hio_hostinfo_uninit(nxge, vr);

	return (0);
}

/* ARGSUSED */
void
nxge_hio_group_get(void *arg, mac_ring_type_t type, int group,
	mac_group_info_t *infop, mac_group_handle_t ghdl)
{
	p_nxge_t nxgep = (p_nxge_t)arg;
	nxge_rx_ring_group_t *rxgroup;

	switch (type) {
	case MAC_RING_TYPE_RX:
		rxgroup = &nxgep->rx_hio_groups[group];
		rxgroup->gindex = group;

		infop->mrg_driver = (mac_group_driver_t)rxgroup;
		infop->mrg_start = NULL;
		infop->mrg_stop = NULL;
		infop->mrg_addmac = nxge_hio_add_mac;
		infop->mrg_remmac = nxge_hio_rem_mac;
		infop->mrg_count = NXGE_HIO_SHARE_MAX_CHANNELS;
		break;

	case MAC_RING_TYPE_TX:
		break;
	}
}

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

	/*
	 * Ask the Hypervisor to set up the VR for us
	 */
	fp = &nhd->hio.vr;
	if ((hv_rv = (*fp->assign)(vr->region, cookie, &vr->cookie))) {
		NXGE_ERROR_MSG((nxge, HIO_CTL,
			"nx_hio_share_assign: "
			"vr->assign() returned %d", hv_rv));
		nxge_hio_unshare((vr_handle_t)vr);
		return (-EIO);
	}

	/*
	 * For each shared TDC, ask the HV to find us an empty slot.
	 * -----------------------------------------------------
	 */
	dc = vr->tx_group.dc;
	for (i = 0; i < NXGE_MAX_TDCS; i++) {
		nxhv_dc_fp_t *tx = &nhd->hio.tx;
		while (dc) {
			hv_rv = (*tx->assign)
			    (vr->cookie, dc->channel, &slot);
cmn_err(CE_CONT, "tx->assign(%d, %d)", dc->channel, dc->page);
			if (hv_rv != 0) {
				NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
				    "nx_hio_share_assign: "
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
	 * -----------------------------------------------------
	 */
	dc = vr->rx_group.dc;
	for (i = 0; i < NXGE_MAX_RDCS; i++) {
		nxhv_dc_fp_t *rx = &nhd->hio.rx;
		while (dc) {
			hv_rv = (*rx->assign)
			    (vr->cookie, dc->channel, &slot);
cmn_err(CE_CONT, "rx->assign(%d, %d)", dc->channel, dc->page);
			if (hv_rv != 0) {
				NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
				    "nx_hio_share_assign: "
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

	cmn_err(CE_CONT, "tmap %lx, rmap %lx", *tmap, *rmap);
	return (0);
}

int
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
			    "nx_hio_dc_unshare: "
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
			    "nx_hio_dc_unshare: "
			    "rx->unassign(%x, %d) failed: %ld",
			    vr->cookie, dc->page, hv_rv));
		}
		dc = dc->next;
	}

	fp = &nhd->hio.vr;
	if (fp->unassign) {
		hv_rv = (*fp->unassign)(vr->cookie);
		if (hv_rv != 0) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nx_hio_unshare: "
			    "vr->assign(%x) failed: %ld",
			    vr->cookie, hv_rv));
		}
	}

	return (0);
}

int
nxge_hio_share_alloc(void *arg, uint64_t cookie, uint64_t *rcookie,
	mac_share_handle_t *shandle)
{
	p_nxge_t nxge = (p_nxge_t)arg;
	nxge_rx_ring_group_t *rxgroup;
	nxge_share_handle_t *shp;

	vr_handle_t shared;	/* The VR being shared */
	nxge_hio_vr_t *vr;	/* The Virtualization Region */
	uint64_t rmap, tmap;
	int rv;

	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_share"));

	if (nhd->hio.vr.assign == 0 || nhd->hio.tx.assign == 0 ||
	    nhd->hio.rx.assign == 0) {
		NXGE_ERROR_MSG((nxge, HIO_CTL, "HV assign function(s) NULL"));
		return (EIO);
	}

	/*
	 * Get a VR.
	 */
	if ((shared = nxge_hio_vr_share(nxge)) == 0)
		return (EAGAIN);
	vr = (nxge_hio_vr_t *)shared;

	/*
	 * Get an RDC group for us to use.
	 */
	if ((vr->rdc_tbl = nxge_hio_hostinfo_get_rdc_table(nxge)) < 0) {
		nxge_hio_unshare(shared);
		return (EBUSY);
	}

	/*
	 * Add resources to the share.
	 */
	tmap = 0;
	rv = nxge_hio_addres(shared, MAC_RING_TYPE_TX,
	    NXGE_HIO_SHARE_MAX_CHANNELS);
	if (rv != 0) {
		nxge_hio_unshare(shared);
		return (rv);
	}

	rmap = 0;
	rv = nxge_hio_addres(shared, MAC_RING_TYPE_RX,
	    NXGE_HIO_SHARE_MAX_CHANNELS);
	if (rv != 0) {
		nxge_hio_remres(shared, MAC_RING_TYPE_TX, tmap);
		nxge_hio_unshare(shared);
		return (rv);
	}

	if ((rv = nxge_hio_share_assign(nxge, cookie, &tmap, &rmap, vr))) {
		nxge_hio_remres(shared, MAC_RING_TYPE_RX, tmap);
		nxge_hio_remres(shared, MAC_RING_TYPE_TX, tmap);
		nxge_hio_unshare(shared);
		return (rv);
	}

	rxgroup = &nxge->rx_hio_groups[vr->rdc_tbl];
	rxgroup->gindex = vr->rdc_tbl;
	rxgroup->sindex = vr->region;

	shp = &nxge->shares[vr->region];
	shp->index = vr->region;
	shp->vrp = (void *)vr;
	shp->tmap = tmap;
	shp->rmap = rmap;
	shp->rxgroup = vr->rdc_tbl;
	shp->active = B_TRUE;

	/* high 32 bits are cfg_hdl and low 32 bits are HV cookie */
	*rcookie = (((uint64_t)nxge->niu_cfg_hdl) << 32) | vr->cookie;

	*shandle = (mac_share_handle_t)shp;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_share"));
	return (0);
}

void
nxge_hio_share_free(mac_share_handle_t shandle)
{
	nxge_share_handle_t *shp = (nxge_share_handle_t *)shandle;

	/*
	 * First, unassign the VR (take it back),
	 * so we can enable interrupts again.
	 */
	(void) nxge_hio_share_unassign(shp->vrp);

	/*
	 * Free Ring Resources for TX and RX
	 */
	nxge_hio_remres((vr_handle_t)shp->vrp, MAC_RING_TYPE_TX, shp->tmap);
	nxge_hio_remres((vr_handle_t)shp->vrp, MAC_RING_TYPE_RX, shp->rmap);

	/*
	 * Free VR resource.
	 */
	nxge_hio_unshare((vr_handle_t)shp->vrp);

	/*
	 * Clear internal handle state.
	 */
	shp->index = 0;
	shp->vrp = (void *)NULL;
	shp->tmap = 0;
	shp->rmap = 0;
	shp->rxgroup = 0;
	shp->active = B_FALSE;
}

void
nxge_hio_share_query(mac_share_handle_t shandle, mac_ring_type_t type,
	uint32_t *rmin, uint32_t *rmax, uint64_t *rmap, uint64_t *gnum)
{
	nxge_share_handle_t *shp = (nxge_share_handle_t *)shandle;

	switch (type) {
	case MAC_RING_TYPE_RX:
		*rmin = NXGE_HIO_SHARE_MIN_CHANNELS;
		*rmax = NXGE_HIO_SHARE_MAX_CHANNELS;
		*rmap = shp->rmap;
		*gnum = shp->rxgroup;
		break;

	case MAC_RING_TYPE_TX:
		*rmin = NXGE_HIO_SHARE_MIN_CHANNELS;
		*rmax = NXGE_HIO_SHARE_MAX_CHANNELS;
		*rmap = shp->tmap;
		*gnum = 0;
		break;
	}
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
vr_handle_t
nxge_hio_vr_share(
	nxge_t *nxge)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_vr_t *vr;

	int first, limit, region;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_vr_share"));

	MUTEX_ENTER(&nhd->lock);

	if (nhd->available.vrs == 0) {
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

	nhd->available.vrs--;

	MUTEX_EXIT(&nhd->lock);

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_vr_share"));

	return ((vr_handle_t)vr);
}

void
nxge_hio_unshare(
	vr_handle_t shared)
{
	nxge_hio_vr_t *vr = (nxge_hio_vr_t *)shared;
	nxge_t *nxge = (nxge_t *)vr->nxge;
	nxge_hio_data_t *nhd;

	vr_region_t region;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_unshare"));

	if (!nxge) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nx_hio_unshare: "
		    "vr->nxge is NULL"));
		return;
	}

	/*
	 * This function is no longer called, but I will keep it
	 * here in case we want to revisit this topic in the future.
	 *
	 * nxge_hio_hostinfo_uninit(nxge, vr);
	 */
	(void) nxge_fzc_rdc_tbl_unbind(nxge, vr->rdc_tbl);

	nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	MUTEX_ENTER(&nhd->lock);

	region = vr->region;
	(void) memset(vr, 0, sizeof (*vr));
	vr->region = region;

	nhd->available.vrs++;

	MUTEX_EXIT(&nhd->lock);

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_unshare"));
}

int
nxge_hio_addres(
	vr_handle_t shared,
	mac_ring_type_t type,
	int count)
{
	nxge_hio_vr_t *vr = (nxge_hio_vr_t *)shared;
	nxge_t *nxge = (nxge_t *)vr->nxge;
	int i;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_addres"));

	if (!nxge)
		return (EINVAL);

	for (i = 0; i < count; i++) {
		int rv;
		if ((rv = nxge_hio_dc_share(nxge, vr, type)) < 0) {
			if (i == 0) /* Couldn't get even one DC. */
				return (-rv);
			else
				break;
		}
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_addres"));

	return (0);
}

/* ARGSUSED */
void
nxge_hio_remres(
	vr_handle_t shared,
	mac_ring_type_t type,
	res_map_t res_map)
{
	nxge_hio_vr_t *vr = (nxge_hio_vr_t *)shared;
	nxge_t *nxge = (nxge_t *)vr->nxge;
	nxge_grp_t *group;

	if (!nxge) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nx_hio_remres: "
		    "vr->nxge is NULL"));
		return;
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_remres(%lx)", res_map));

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
	nxge_grp_set_t *set = &nxge->tx_set;
	tx_ring_t *ring;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_tdc_share"));

	/*
	 * Wait until this channel is idle.
	 */
	ring = nxge->tx_rings->rings[channel];
	MUTEX_ENTER(&ring->lock);
	switch (ring->tx_ring_state) {
		int count;
	case TX_RING_STATE_OFFLINE:
		break;
	case TX_RING_STATE_IDLE:
		ring->tx_ring_state = TX_RING_STATE_OFFLINE;
		break;
	case TX_RING_STATE_BUSY:
		/* 30 seconds */
		for (count = 30 * 1000; count; count--) {
			MUTEX_EXIT(&ring->lock);
			drv_usecwait(1000); /* 1 millisecond */
			MUTEX_ENTER(&ring->lock);
			if (ring->tx_ring_state == TX_RING_STATE_IDLE) {
				ring->tx_ring_state = TX_RING_STATE_OFFLINE;
				break;
			}
		}
		if (count == 0) {
			MUTEX_EXIT(&ring->lock);
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nx_hio_tdc_share: "
			    "Tx ring %d was always BUSY", channel));
			return (-EIO);
		}
		break;
	default:
		MUTEX_EXIT(&ring->lock);
		return (-EIO);
	}
	MUTEX_EXIT(&ring->lock);

	if (nxge_intr_remove(nxge, VP_BOUND_TX, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nx_hio_tdc_share: "
		    "Failed to remove interrupt for TxDMA channel %d",
		    channel));
		return (NXGE_ERROR);
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
		    "nx_hio_dc_share: FZC TDC failed: %d", channel));
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
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hw_pt_cfg_t *hardware = &nxge->pt_config.hw_config;
	nxge_grp_set_t *set = &nxge->rx_set;
	nxge_rdc_grp_t *rdc_grp;

	int current, last;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_rdc_share"));

	/* Disable interrupts. */
	if (nxge_intr_remove(nxge, VP_BOUND_RX, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nx_hio_rdc_share: "
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
	 * We have to reconfigure the RDC table(s)
	 * to which this channel belongs.
	 */
	current = hardware->def_mac_rxdma_grpid;
	last = current + hardware->max_rdc_grpids;
	for (; current < last; current++) {
		if (nhd->rdc_tbl[current].nxge == (uintptr_t)nxge) {
			rdc_grp = &nxge->pt_config.rdc_grps[current];
			rdc_grp->map = set->owned.map;
			rdc_grp->max_rdcs--;
			(void) nxge_init_fzc_rdc_tbl(nxge, current);
		}
	}

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
		    "nx_hio_rdc_share: Rx MAC still disabled"));
	}

	/*
	 * Initialize the DC-specific FZC control registers.
	 * -----------------------------------------------------
	 */
	if (nxge_init_fzc_rdc(nxge, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_rdc_share: RZC RDC failed: %ld", channel));
		return (-EIO);
	}

	/*
	 * We have to initialize the guest's RDC table, too.
	 * -----------------------------------------------------
	 */
	rdc_grp = &nxge->pt_config.rdc_grps[vr->rdc_tbl];
	if (rdc_grp->max_rdcs == 0) {
		rdc_grp->start_rdc = (uint8_t)channel;
		rdc_grp->def_rdc = (uint8_t)channel;
		rdc_grp->max_rdcs = 1;
	} else {
		rdc_grp->max_rdcs++;
	}
	NXGE_DC_SET(rdc_grp->map, channel);

	if (nxge_init_fzc_rdc_tbl(nxge, vr->rdc_tbl) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_rdc_share: nxge_init_fzc_rdc_tbl failed"));
		return (-EIO);
	}

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
 * 	res_map	The resource map used by the caller, which we will
 *		update if successful.
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
	mac_ring_type_t type)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hw_pt_cfg_t *hardware;
	nxge_hio_dc_t *dc;
	int channel, limit;

	nxge_grp_set_t *set;
	nxge_grp_t *group;

	int slot;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_dc_share(%cdc %d",
	    type == MAC_RING_TYPE_TX ? 't' : 'r', channel));

	/*
	 * In version 1.0, we may only give a VR 2 RDCs or TDCs.
	 * Not only that, but the HV has statically assigned the
	 * channels like so:
	 * VR0: RDC0 & RDC1
	 * VR1: RDC2 & RDC3, etc.
	 * The TDCs are assigned in exactly the same way.
	 *
	 * So, for example
	 *	hardware->start_rdc + vr->region * 2;
	 *	VR1: hardware->start_rdc + 1 * 2;
	 *	VR3: hardware->start_rdc + 3 * 2;
	 *	If start_rdc is 0, we end up with 2 or 6.
	 *	If start_rdc is 8, we end up with 10 or 14.
	 */

	set = (type == MAC_RING_TYPE_TX ? &nxge->tx_set : &nxge->rx_set);
	hardware = &nxge->pt_config.hw_config;

	// This code is still NIU-specific (assuming only 2 ports)
	channel = hardware->start_rdc + (vr->region % 4) * 2;
	limit = channel + 2;

	MUTEX_ENTER(&nhd->lock);
	for (; channel < limit; channel++) {
		if ((1 << channel) & set->owned.map) {
			break;
		}
	}

	if (channel == limit) {
		MUTEX_EXIT(&nhd->lock);
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_dc_share: there are no channels to share"));
		return (-EIO);
	}

	MUTEX_EXIT(&nhd->lock);

	/* -------------------------------------------------- */
	slot = (type == MAC_RING_TYPE_TX) ?
	    nxge_hio_tdc_share(nxge, channel) :
	    nxge_hio_rdc_share(nxge, vr, channel);

	if (slot < 0) {
		if (type == MAC_RING_TYPE_RX) {
			nxge_hio_rdc_unshare(nxge, channel);
		} else {
			nxge_hio_tdc_unshare(nxge, channel);
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

	dc->group = (vr_handle_t)group;

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
	int channel)
{
	nxge_grp_set_t *set = &nxge->tx_set;
	vr_handle_t handle = (vr_handle_t)set->group[0];

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_tdc_unshare"));

	NXGE_DC_RESET(set->shared.map, channel);
	set->shared.count--;

	if ((nxge_grp_dc_add(nxge, handle, VP_BOUND_TX, channel))) {
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
	int channel)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hw_pt_cfg_t *hardware = &nxge->pt_config.hw_config;

	nxge_grp_set_t *set = &nxge->rx_set;
	vr_handle_t handle = (vr_handle_t)set->group[0];
	int current, last;

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

	/*
	 * Assert RST: RXDMA_CFIG1[30] = 1
	 *
	 * Initialize RxDMA	A.9.5.4
	 * Reconfigure RxDMA
	 * Enable RxDMA		A.9.5.5
	 */
	if ((nxge_grp_dc_add(nxge, handle, VP_BOUND_RX, channel))) {
		/* Be sure to re-enable the RX MAC. */
		if (nxge_rx_mac_enable(nxge) != NXGE_OK) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "nx_hio_rdc_share: Rx MAC still disabled"));
		}
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_rdc_unshare: "
		    "Failed to initialize RxDMA channel %d", channel));
		return;
	}

	/*
	 * We have to reconfigure the RDC table(s)
	 * to which this channel once again belongs.
	 */
	current = hardware->def_mac_rxdma_grpid;
	last = current + hardware->max_rdc_grpids;
	for (; current < last; current++) {
		if (nhd->rdc_tbl[current].nxge == (uintptr_t)nxge) {
			nxge_rdc_grp_t *group;
			group = &nxge->pt_config.rdc_grps[current];
			group->map = set->owned.map;
			group->max_rdcs++;
			(void) nxge_init_fzc_rdc_tbl(nxge, current);
		}
	}

	/*
	 * Enable RxMAC = A.9.2.10
	 */
	if (nxge_rx_mac_enable(nxge) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_rdc_share: Rx MAC still disabled"));
		return;
	}

	/* Re-add this interrupt. */
	if (nxge_intr_add(nxge, VP_BOUND_RX, channel) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_rdc_unshare: Failed to add interrupt for "
		    "RxDMA CHANNEL %d", channel));
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_rdc_unshare"));
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
		    "nx_hio_dc_unshare(%d) failed", channel));
		return;
	}

	dc->vr = 0;
	dc->cookie = 0;

	if (type == MAC_RING_TYPE_RX) {
		nxge_hio_rdc_unshare(nxge, channel);
	} else {
		nxge_hio_tdc_unshare(nxge, channel);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_dc_unshare"));
}

#endif	/* if defined(sun4v) */
