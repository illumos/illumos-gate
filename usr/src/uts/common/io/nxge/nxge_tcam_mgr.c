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

#define	NXGE_DEBUG

#include <sys/flow.h>
#include <netinet/in.h>

#include <npi_fflp.h>
#include <npi_mac.h>
#include <nxge_defs.h>
#include <nxge_flow.h>
#include <nxge_fflp.h>
#include <nxge_impl.h>
#include <nxge_fflp_hash.h>
#include <nxge_common.h>
#include <nxge_tcam.h>

#define	TCAM_LOCK(nxge)	&nxge->nxge_hw_p->nxge_tcam_lock

#define	TCAM_GET_SOFT_STATE(nxge, control)	\
	if (!(control = (tcam_control_t *)ddi_get_soft_state( \
	    tcam_state, nxge->pci_slot))) \
		    return (ENOENT);

void *tcam_state;		/* The TCAM's soft state array */

extern nxge_status_t nxge_fflp_tcam_init(p_nxge_t);

static int nxge_classify_add(nxge_t *, flow_desc_t *, flow_resource_t *);
static tcam_location_t nxge_tcam_location_get(p_nxge_t, tcam_control_t *, int);
static int nxge_tcam_shuffle(nxge_t *, tcam_control_t *,
    tcam_range_t *, boolean_t);

static int nxge_tcam_ad_write(nxge_t *, nxge_tcam_entry_t *);
static void nxge_tcam_entry_invalidate(nxge_t *, tcam_control_t *,
    tcam_location_t);
static void nxge_tcam_entry_move(nxge_t *, tcam_control_t *,
    tcam_location_t old, tcam_location_t new);

static int nxge_ipv4_key_build(nxge_t *, flow_desc_t *, flow_spec_t *,
    nxge_tcam_entry_t *);
static int nxge_ipv6_key_build(nxge_t *, flow_desc_t *, flow_spec_t *,
    nxge_tcam_entry_t *);
static int nxge_en_key_build(nxge_t *, flow_desc_t *, flow_spec_t *,
    nxge_tcam_entry_t *);

static int nxge_vid_enable(nxge_t *, flow_desc_t *);
static int nxge_vid_disable(nxge_t *, flow_desc_t *);

static int nxge_altmac_enable(nxge_t *nxge, flow_desc_t *flow);

/*
 * -------------------------------------------------------------
 * nxge_ipv4_entry_dump
 *
 * Dump an ipv4 TCAM key
 *
 * Input
 *     entry		The key holder.
 *
 * Output
 *	void
 *
 * -------------------------------------------------------------
 */
static
void
nxge_ipv4_entry_dump(
	nxge_t *nxge,
	nxge_tcam_entry_t *entry)
{
	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
	    "TCAM @ %d: cls %d, rdc %d, proto %d, "
	    "port %d, src %x, dst %x",
	    entry->location,
	    entry->data.key.ipv4_e.cls_code,
	    entry->data.key.ipv4_e.l2rd_tbl_num,
	    entry->data.key.ipv4_e.proto,
	    entry->data.key.ipv4_e.l4_port_spi,
	    entry->data.key.ipv4_e.ip_src,
	    entry->data.key.ipv4_e.ip_dest));
}

/*
 * -------------------------------------------------------------
 * nxge_fflp_tcam_init
 *
 * Initialize the Neptune TCAM.
 *
 * Input
 *     nxge		An nxge_t instance.
 *
 * Output
 *	NXGE_OK if successful; an error code otherwise.
 *
 * -------------------------------------------------------------
 */
nxge_status_t
nxge_fflp_tcam_init(
	p_nxge_t nxge)
{
	uint8_t access_ratio;
	tcam_class_t class;
	npi_status_t rs = NPI_SUCCESS;
	npi_handle_t handle;

	int size, index, gap, i;
	tcam_range_t *range;

	tcam_control_t *tcam;

	NXGE_DEBUG_MSG((nxge, FFLP_CTL, "==> nxge_fflp_tcam_init"));
	handle = nxge->npi_reg_handle;

	rs = npi_fflp_cfg_tcam_disable(handle);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, FFLP_CTL, "failed TCAM Disable\n"));
		return (NXGE_ERROR | rs);
	}

	access_ratio = nxge->param_arr[param_tcam_access_ratio].value;
	rs = npi_fflp_cfg_tcam_access(handle, access_ratio);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, FFLP_CTL,
		    "failed TCAM Access cfg\n"));
		return (NXGE_ERROR | rs);
	}

	/* Disable all the programmable classes. */

	/* First, the two ethernet classes. */
	for (class = TCAM_CLASS_ETYPE_1; class <= TCAM_CLASS_ETYPE_2;
	    class++) {
		rs = npi_fflp_cfg_enet_usr_cls_disable(handle, class);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxge, FFLP_CTL,
			    "TCAM USR Ether Class config failed."));
			return (NXGE_ERROR | rs);
		}
	}

	/* Then the 4 IP classes. */
	for (class = TCAM_CLASS_IP_USER_4;
	    class <= TCAM_CLASS_IP_USER_7; class++) {
		rs = npi_fflp_cfg_ip_usr_cls_disable(handle, class);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxge, FFLP_CTL,
			    "TCAM USR IP Class cnfg failed."));
			return (NXGE_ERROR | rs);
		}
	}

	/* If this is the first time through... */
	if (tcam_state == 0) {
		if ((ddi_soft_state_init(&tcam_state,
			    sizeof (tcam_control_t), 0)) != 0) {
			NXGE_ERROR_MSG((nxge, FFLP_CTL,
				"failed to init TCAM soft state"));
			return (NXGE_ERROR);
		}
		if (ddi_soft_state_zalloc(tcam_state, nxge->pci_slot)
		    == DDI_FAILURE) {
			ddi_soft_state_fini(&tcam_state);
			return (NXGE_ERROR);
		}
	}

	if (!(tcam = (tcam_control_t *)ddi_get_soft_state(
		tcam_state, nxge->pci_slot))) {
		NXGE_ERROR_MSG((nxge, FFLP_CTL,
			"ddi_get_soft_state() failed"));
		return (NXGE_ERROR);
	}

	/* Initialize the TCAM data structures. */
	size = (nxge->niu_type == NEPTUNE) ?
	    TCAM_NXGE_TCAM_MAX_ENTRY : TCAM_NIU_TCAM_MAX_ENTRY;
	tcam->size = size;

	if (tcam->slot == 0) {
		tcam->slot = KMEM_ZALLOC(size * sizeof (uintptr_t),
		    KM_SLEEP);
	} else {
		bzero(tcam->slot, size * sizeof (uintptr_t));
	}

	tcam->limit = TCAM_REGION_MAX;

	/* We must reserve the top <nports> slots for UDP fragments. */
	range = &tcam->legend.reserved;
	index = nxge->nports;
	range->top = 0;
	range->bottom = index - 1;

	/* <gap> is just a heuristic. */
	gap = (size - index) / tcam->limit;

	for (i = 0; i <= tcam->limit; i++) {
		range++;
		range->top = (tcam_location_t)index;
		range->bottom = range->top;
		range->region = i;
		index += gap;
	}

	NXGE_DEBUG_MSG((nxge, FFLP_CTL, "<== nxge_fflp_tcam_init"));
	return (NXGE_OK);
}

/*
 * -------------------------------------------------------------
 * nxge_tcam_key_get
 * nxge_tcam_key_set
 *
 * Get the current <tsel> bit in a TCAM key for an IP class.  Or,
 * set the <tsel> bit in the TCAM key for an IP class.
 *
 * Input
 *     nxge
 *     class		The IP class to get or set.
 *
 * Output
 *	0 or 1, depending on tsel.  -1 if there was an error.
 *
 * -------------------------------------------------------------
 */
int
nxge_tcam_key_get(
	p_nxge_t nxge,
	tcam_class_t class)
{
	tcam_key_cfg_t cfg;
	npi_status_t rs;

	bzero(&cfg, sizeof (tcam_key_cfg_t));

	rs = npi_fflp_cfg_ip_cls_tcam_key_get(
		nxge->npi_reg_handle, class, &cfg);
	if (rs & NPI_FFLP_ERROR) {
		return (-1);
	}

	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
		"TCAM tsel bit for class %d set to %d",
		class, cfg.lookup_enable));

	return (cfg.lookup_enable);
}

int
nxge_tcam_key_set(
	p_nxge_t nxge,
	tcam_class_t class,
	flow_desc_t *flow)
{
	tcam_key_cfg_t configuration;
	npi_status_t rs;

	bzero(&configuration, sizeof (tcam_key_cfg_t));
	configuration.lookup_enable = 1;

	if (flow->fd_mask & FLOW_IP_PROTOCOL &&
	    flow->fd_ipversion == IPV6_VERSION) {
		if (flow->fd_mask & FLOW_IP_REMOTE)
			configuration.use_ip_saddr = 1;
	}

	rs = npi_fflp_cfg_ip_cls_tcam_key(nxge->npi_reg_handle,
	    class, &configuration);
	if (rs & NPI_FFLP_ERROR) {
		return (-1);
	}

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_tcam_entry_invalidate
 * nxge_tcam_entry_move
 *
 * A couple of TCAM utility functions.
 *
 * Input
 *     nxge
 *     location		The slot to invalidate. [invalidate]
 *
 *     old		The old (soon to be former) slot [move].
 *     new		The new slot [move].
 *
 * Output
 *	void.
 *
 * -------------------------------------------------------------
 */
void
nxge_tcam_entry_invalidate(
	nxge_t *nxge,
	tcam_control_t *tcam,
	tcam_location_t location)
{
	tcam->slot[location] = 0;

	MUTEX_ENTER(TCAM_LOCK(nxge));
	npi_fflp_tcam_entry_invalidate(nxge->npi_reg_handle, location);
	MUTEX_EXIT(TCAM_LOCK(nxge));
}

void
nxge_tcam_entry_move(
	nxge_t *nxge,
	tcam_control_t *tcam,
	tcam_location_t old,
	tcam_location_t new)
{
	npi_handle_t handle = nxge->npi_reg_handle;
	nxge_tcam_entry_t *entry;

	MUTEX_ENTER(TCAM_LOCK(nxge));
	tcam->slot[new] = tcam->slot[old];
	tcam->slot[old] = 0;

	entry = (nxge_tcam_entry_t *)tcam->slot[new];

	npi_fflp_tcam_entry_write(handle, new, &entry->data);
	npi_fflp_tcam_entry_invalidate(handle, old);
	MUTEX_EXIT(TCAM_LOCK(nxge));
}

/*
 * -------------------------------------------------------------
 * nxge_tcam_location_get
 *
 * Find an empty slot in TCAM region <region>.  If <region> is
 * is full, expand the region by 1 slot.
 *
 * Input
 *     nxge
 *     region		The region to use.
 *
 * Output
 *	A valid slot number (nxge->nports-255) if successful;
 *	0 otherwise.
 *
 * -------------------------------------------------------------
 */
tcam_location_t
nxge_tcam_location_get(
	p_nxge_t nxge,
	tcam_control_t *tcam,
	int region)
{
	tcam_range_t *home, *neighbor;
	tcam_location_t locus;
	int i;

	if (region > tcam->limit)
		region = 1;

	/* region 5 -> .region[0] */
	/* region 4 -> .region[1], etc. */
	home = &tcam->legend.region[tcam->limit - region];

	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
	    "region: %d, get: %d: top: %d / bottom: %d",
	    region, (int)(tcam->limit - region), home->top, home->bottom));

	if (tcam->limit == 0)
		return (0);

	MUTEX_ENTER(TCAM_LOCK(nxge));
	/* Is there an empty slot between top & bottom? */
	for (i = home->top; i <= home->bottom; i++) {
		if (tcam->slot[i] == 0) {
			MUTEX_EXIT(TCAM_LOCK(nxge));
			return ((tcam_location_t)i);
		}
	}

	/* Can we append it? */
	neighbor = home + 1;
	if ((home->bottom + 1) < neighbor->top) {
		locus = (tcam_location_t)++home->bottom;
		MUTEX_EXIT(TCAM_LOCK(nxge));
		return (locus);
	}

	/* That didn't work.  Can we prepend it? */
	neighbor = home - 1;
	if ((home->top - 1) < neighbor->bottom) {
		locus = (tcam_location_t)--home->top;
		MUTEX_EXIT(TCAM_LOCK(nxge));
		return (locus);
	}

	/* Try to append it first. */
	if (nxge_tcam_shuffle(nxge, tcam, home, B_TRUE) == 0) {
		locus = (tcam_location_t)++home->bottom;
		MUTEX_EXIT(TCAM_LOCK(nxge));
		return (locus);
	}

	/* Ok, try to prepend it. */
	if (nxge_tcam_shuffle(nxge, tcam, home, B_FALSE) == 0) {
		locus = (tcam_location_t)--home->top;
		MUTEX_EXIT(TCAM_LOCK(nxge));
		return (locus);
	}

	MUTEX_EXIT(TCAM_LOCK(nxge));

	/* There's no place left to insert this. */
	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_tcam_shuffle
 *
 * Shuffle the TCAM entries until we have a free slot.  In other
 * words, expand a TCAM region on the top or the bottom, thereby
 * creating one new slot.
 *
 * Input
 *     nxge		The nxge_t instance.
 *     tcam		The TCAM control data structure.
 *     range		The slotless region we want to expand.
 *     down		Shuffle everything down (or up).
 *
 * Output
 *	0 if successful; -1 otherwise.
 *
 * Notes: The TCAM lock must be held by the calling function.
 * -------------------------------------------------------------
 */
int
nxge_tcam_shuffle(
	nxge_t *nxge,
	tcam_control_t *tcam,
	tcam_range_t *range,
	boolean_t down)
{
	tcam_range_t *neighbor;
	int levels;

	if (down) {
		neighbor = range + 1;
		levels = 0;

		while ((range->bottom - 1) == neighbor->top) {
			if (neighbor->region == tcam->limit) {
				/* We can't go down again. */
				if (neighbor->bottom == (tcam->size - 1)) {
					/* There's simply no room. */
					return (-1);
				}
				range = neighbor;
				levels++;
				break;
			}
			neighbor++;
			range++;
			levels++;
		}

		while (levels) {
			range->bottom++;
			nxge_tcam_entry_move(nxge, tcam,
			    range->top, range->bottom);
			range->top--;

			range--;
			levels--;
		}

		return (0);
	} else {
		neighbor = range - 1;
		levels = 0;

		while ((range->top + 1) == neighbor->bottom) {
			if (neighbor->region == 0) {
				return (-1);
			}
			neighbor--;
			range--;
			levels++;
		}

		while (levels) {
			range->top++;
			nxge_tcam_entry_move(nxge, tcam,
			    range->bottom, range->top);
			range->bottom++;

			range++;
			levels--;
		}

		return (0);
	}
}

/*
 * -------------------------------------------------------------
 * nxge_tcam_ad_write
 *
 * Write a TCAM entry's associated data (ad) register.
 *
 * Input
 *     nxge		The nxge_t instance.
 *     entry		The TCAM entry in question.
 *
 * Output
 *	NPI success/failure status code
 *
 * (I'm a little unsure of this code.)
 * -------------------------------------------------------------
 */
int
nxge_tcam_ad_write(
	nxge_t *nxge,
	nxge_tcam_entry_t *entry)
{
	tcam_res_t *data = &entry->data.match_action;
	npi_handle_t handle;
	int rv;

	data->value = 0;	/* Zeroize the register. */

	data->bits.ldw.rdctbl = entry->l2rdc_tbl_num;
	data->bits.ldw.offset = entry->offset;
	data->bits.ldw.tres = TRES_TERM_OVRD_L2RDC; /* XXX I suppose... */

	/* Crossbow cannot tell us to discard a stream. */
	data->bits.ldw.disc = 0;

	handle = nxge->npi_reg_handle;

	MUTEX_ENTER(TCAM_LOCK(nxge));
	rv = npi_fflp_tcam_asc_ram_entry_write(handle,
	    entry->location, data->value);
	MUTEX_EXIT(TCAM_LOCK(nxge));

	if (rv & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxge, FFLP_CTL,
		    " tcam__ad_write:"
		    " failed to write associated RAM @ %d",
		    entry->location));
		return (NXGE_ERROR | rv);
	}

	return (NXGE_OK);
}

/*
 * -------------------------------------------------------------
 * nxge_classify_add
 *
 * Build & store a new TCAM entry.
 *
 * Input
 *	nxge
 *	flow		A Crossbow flow description.
 *	resource	The flow_resource_t data structure.
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * Algorithm
 *  1. Check for illegal combinations of flows.
 *  2. Allocate an nxge_tcam_entry_t data structure.  This is
 *	where we keep all the data concerning this TCAM entry.
 *  3. If this is a VLAN flow, initialize an entry in the VLAN
 *	table.
 *  4. Build a TCAM key.
 *  5. Write a TCAM entry.
 * -------------------------------------------------------------
 */
int
nxge_classify_add(
	nxge_t *nxge,
	flow_desc_t *flow,
	flow_resource_t *resource)
{
	flow_spec_t 	*spec = &resource->flow_spec;
	flow_mask_t	vlan_flow, en_flow, ip_flow;
	int		rv;	/* Return Value */

	nxge_tcam_entry_t *entry;
	npi_handle_t	handle;

	nxge_dma_pt_cfg_t *dma_conf;
	nxge_hw_pt_cfg_t *config;

	tcam_control_t *tcam = (tcam_control_t *)nxge->nxge_hw_p->tcam;

	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
	    "==> nxge_classify_add: "
	    "mask %lx / IP ver %d / proto %d / "
	    "rp: %d / lp: %d",
	    flow->fd_mask, flow->fd_ipversion, flow->fd_protocol,
	    flow->fd_remoteport, flow->fd_localport));

	if (flow->fd_mask == 0 || (flow->fd_mask & ~SUPPORTED_FLOWS) != 0)
		return (EINVAL);

	vlan_flow = flow->fd_mask & VLAN_FLOWS;
	en_flow = flow->fd_mask & ETHER_FLOWS;
	ip_flow = flow->fd_mask & IP_FLOWS;

	/* Check for any possibly illegal combinations. */
	if (en_flow && ip_flow) {
		if (flow->fd_mask & FLOW_ETHER_TYPE) {
			if (flow->fd_mac.ether_type != ETHERTYPE_IP)
				return (EINVAL);
		}
	}

	/*
	 * Allocate an nxge_tcam_entry_t.
	 */
	entry = (nxge_tcam_entry_t *)KMEM_ZALLOC(sizeof (*entry), KM_SLEEP);
	if (entry == 0)
		return (ENOMEM);
	resource->tcam_handle = entry;

	bcopy(flow, &entry->fd, sizeof (entry->fd));

	/* Set up the RDC table, and offset that we will use. */
	dma_conf = (nxge_dma_pt_cfg_t *)&nxge->pt_config;
	config = (nxge_hw_pt_cfg_t *)&dma_conf->hw_config;

	/* XXX Fix this later! */
	entry->l2rdc_tbl_num = config->def_mac_rdc_grpid +
	    (resource->channel_cookie & 1);
	entry->offset = resource->channel_cookie; /* XXX For now... */

	/* VLAN flows are defined outside of the TCAM. */
	if (vlan_flow) {
		/* 802.1Q packets only. */
		if (flow->fd_mask & FLOW_ETHER_TPID) {
			if (flow->fd_mac.ether_tpid != ETHERTYPE_VLAN)
				return (EINVAL);
		} else if (!(flow->fd_mask & FLOW_ETHER_TCI)) {
			/* There's no VID? */
			return (EINVAL);
		}
		rv = nxge_vid_enable(nxge, flow);
		if (rv)
			goto failure;
	}

	/* Has the ethernet type been set? */
	if (en_flow) {
		if (flow->fd_mask & FLOW_ETHER_TYPE &&
		    flow->fd_mac.ether_type != ETHERTYPE_IP) {
			if ((rv = nxge_en_key_build(nxge, flow, spec, entry)))
				goto failure;
		}
		if (flow->fd_mask & FLOW_ETHER_DHOST) {
			if ((rv = nxge_altmac_enable(nxge, flow))) {
				return (rv);
			}
		}
	}

	if (ip_flow) {
		tcam_ipv4_t *key;

		/* As far as I know, Crossbow always sets this bit. */
		if (flow->fd_mask & FLOW_IP_VERSION) {
			switch (flow->fd_ipversion) {
			case IPV4_VERSION:
				rv = nxge_ipv4_key_build(
				    nxge, flow, spec, entry);
				break;
			case IPV6_VERSION:
				rv = nxge_ipv6_key_build(
				    nxge, flow, spec, entry);
				break;
			default:
				KMEM_FREE(entry, sizeof (*entry));
				return (EINVAL);
			}
		} else {
			rv = EINVAL;
		}
		if (rv)
			goto failure;

		/* <tsel> may be 0. */
		key = &entry->data.key.ipv4_e;
		switch (nxge_tcam_key_get(nxge, key->cls_code)) {
		case 0:
			nxge_tcam_key_set(nxge, key->cls_code, flow);
			break;
		case -1:
			rv = EINVAL;
			goto failure;
		default:
			break;
		}
	}

	/* It's possible that the only flow variable was the vlan id. */
	if (entry->region == 0)	/* <entry> was zalloced... */
		return (0);

	entry->location = nxge_tcam_location_get(nxge, tcam, entry->region);
	if (entry->location == 0) {
		rv = EIO;
		goto failure;
	}

	handle = nxge->npi_reg_handle;

	nxge_ipv4_entry_dump(nxge, entry);

	MUTEX_ENTER(TCAM_LOCK(nxge));
	rv = npi_fflp_tcam_entry_write(handle, entry->location, &entry->data);
	if (rv & NPI_FFLP_ERROR) {
		MUTEX_EXIT(TCAM_LOCK(nxge));
		NXGE_ERROR_MSG((nxge, FFLP_CTL,
		    " nxge_classify_add()"
		    " failed for location %d", entry->location));
		rv = EIO;
		goto failure;
	}

	/* Mark this slot as in use. */
	tcam->slot[entry->location] = (uintptr_t)entry;
	MUTEX_EXIT(TCAM_LOCK(nxge));

	return (nxge_tcam_ad_write(nxge, entry));

failure:
	if (entry)
		KMEM_FREE((caddr_t)entry, sizeof (*entry));
	return (rv);
}

/*
 * -------------------------------------------------------------
 * nxge_ipv4_key_build
 *
 * Build an ethernet TCAM key.
 *
 * Input
 *	nxge
 *	flow		The Crossbow flow description
 *	spec		A flow specification (going away).
 *	entry		A TCAM entry data structure.
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * -------------------------------------------------------------
 */
int
nxge_ipv4_key_build(
	/* ARGSUSED */
	nxge_t *nxge,
	flow_desc_t *flow,
	flow_spec_t *spec,
	nxge_tcam_entry_t *entry)
{
	tcam_ipv4_t *key = &entry->data.key.ipv4_e;
	tcam_ipv4_t *mask = &entry->data.mask.ipv4_e;
	uint32_t tmp32;

	/* The class code. */
	switch ((uint8_t)flow->fd_protocol) {
	default:
	case IPPROTO_TCP:
		key->cls_code = TCAM_CLASS_TCP_IPV4;
		spec->flow_type = FSPEC_TCPIP4;
		break;
	case IPPROTO_UDP:
		key->cls_code = TCAM_CLASS_UDP_IPV4;
		spec->flow_type = FSPEC_UDPIP4;
		break;
	case IPPROTO_SCTP:
		key->cls_code = TCAM_CLASS_SCTP_IPV4;
		spec->flow_type = FSPEC_SCTPIP4;
		break;
	}
	mask->cls_code = CLS_CODE_MASK;
	/* How does Crossbow select AH/ESP? */

	/* The Layer 2 RDC Table Number. */
	key->l2rd_tbl_num = entry->l2rdc_tbl_num;
	mask->l2rd_tbl_num = L2RDC_TBL_NUM_MASK;

	if (!(flow->fd_mask & PORT_FLOWS)) {
		key->noport = 1;
		mask->noport = 1;
	} else {
		uint16_t tmp16;
		uint32_t l4pts = 0;

		/* We'll assume that it is remote, then local. */
		/* That is, ordered as it is in a ULP header. */
		if (flow->fd_mask & FLOW_ULP_PORT_REMOTE) {
			bcopy(&flow->fd_remoteport, &tmp16, sizeof (tmp16));
			/* tmp16 = ntohl(tmp16); */
			key->l4_port_spi = tmp16 << 16;
			mask->l4_port_spi = 0xffff0000;
			spec->uh.tcpip4spec.psrc = tmp16;
		}
		if (flow->fd_mask & FLOW_ULP_PORT_LOCAL) {
			bcopy(&flow->fd_localport, &tmp16, sizeof (tmp16));
			/* tmp16 = ntohs(tmp16); */
			l4pts |= tmp16;
			mask->l4_port_spi |= IP_PORT_MASK;
			spec->uh.tcpip4spec.pdst = tmp16;
		}

		key->l4_port_spi = l4pts;
		entry->region++;
	}

	if (flow->fd_mask & FLOW_IP_PROTOCOL) {
		key->proto = flow->fd_protocol;
		mask->proto = PID_MASK;
		entry->region++;
	}

	bcopy(&flow->fd_localaddr.s6_addr32[3], &tmp32, sizeof (tmp32));
/*	tmp32 = ntohl(tmp32); */

	if (flow->fd_mask & FLOW_IP_REMOTE) {
		key->ip_src = tmp32;
		spec->uh.tcpip4spec.ip4src = tmp32;
		mask->ip_src = IP_ADDR_DA_MASK;
		entry->region++;
	}

	if (flow->fd_mask & FLOW_IP_LOCAL) {
		key->ip_dest = tmp32;
		spec->uh.tcpip4spec.ip4dst = tmp32;
		mask->ip_dest = IP_ADDR_SA_MASK;
		entry->region++;
	}

	/* Entry->region <= 4. */

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_ipv6_key_build
 *
 * Build an ethernet TCAM key.
 *
 * Input
 *	nxge
 *	flow		The Crossbow flow description
 *	spec		A flow specification (going away).
 *	entry		A TCAM entry data structure.
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * -------------------------------------------------------------
 */
int
nxge_ipv6_key_build(
	/* ARGSUSED */
	nxge_t *nxge,
	flow_desc_t *flow,
	flow_spec_t *spec,
	nxge_tcam_entry_t *entry)
{
	tcam_ipv6_t *key = &entry->data.key.ipv6_e;
	tcam_ipv6_t *mask = &entry->data.mask.ipv6_e;

	/* The class code. */
	switch ((uint8_t)flow->fd_protocol) {
	default:
	case IPPROTO_TCP:
		key->cls_code = TCAM_CLASS_TCP_IPV6;
		spec->flow_type = FSPEC_TCPIP6;
		break;
	case IPPROTO_UDP:
		key->cls_code = TCAM_CLASS_UDP_IPV6;
		spec->flow_type = FSPEC_UDPIP6;
		break;
	case IPPROTO_SCTP:
		key->cls_code = TCAM_CLASS_SCTP_IPV6;
		spec->flow_type = FSPEC_SCTPIP6;
		break;
	}
	mask->cls_code = CLS_CODE_MASK;
	/* How does Crossbow select AH/ESP? */

	/* The Layer 2 RDC Table Number. */
	key->l2rd_tbl_num = entry->l2rdc_tbl_num;
	mask->l2rd_tbl_num = L2RDC_TBL_NUM_MASK;

	if ((flow->fd_mask & PORT_FLOWS)) {
		uint16_t tmp16;
		uint32_t l4pts = 0;

		/* We'll assume that it is remote, then local. */
		/* That is, ordered as it is in a ULP header. */
		if (flow->fd_mask & FLOW_ULP_PORT_REMOTE) {
			bcopy(&flow->fd_remoteport, &tmp16, sizeof (tmp16));
			/* tmp16 = ntohl(tmp16); */
			key->l4_port_spi = tmp16 << 16;
			mask->l4_port_spi = 0xffff0000;
			spec->uh.tcpip4spec.psrc = tmp16;
		}
		if (flow->fd_mask & FLOW_ULP_PORT_LOCAL) {
			bcopy(&flow->fd_localport, &tmp16, sizeof (tmp16));
			/* tmp16 = ntohs(tmp16); */
			l4pts |= tmp16;
			mask->l4_port_spi |= IP_PORT_MASK;
			spec->uh.tcpip4spec.pdst = tmp16;
		}

		key->l4_port_spi = l4pts;
		entry->region++;
	}

	if (flow->fd_mask & ADDR_FLOWS) {
		struct in6_addr *to, *from;
		tcam_reg_t *regs;

		if (flow->fd_mask & FLOW_IP_REMOTE) {
			from = &flow->fd_remoteaddr;
			to = &spec->uh.tcpip6spec.ip6src;

		} else if (flow->fd_mask & FLOW_IP_LOCAL) {
			from = &flow->fd_localaddr;
			to = &spec->uh.tcpip6spec.ip6dst;
		}

		*to = *from;
		/* XXX Do we need to ntohl()? */

		regs = &entry->data.mask.regs_e;
		regs->reg2 = ULONG_MAX;
		regs->reg3 = ULONG_MAX;

		entry->region++;
	}

	/* Add two (2) for the missing nxt_hdr & second address. */
	entry->region += 2;
	/* Entry->region <= 4. */

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_en_key_build
 *
 * Build an ethernet TCAM key.
 *
 * Input
 *	nxge
 *	flow		The Crossbow flow description
 *	spec		A flow specification (going away).
 *	entry		A TCAM entry data structure.
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * -------------------------------------------------------------
 */
int
nxge_en_key_build(
	nxge_t *nxge,
	flow_desc_t *flow,
	flow_spec_t *spec,
	nxge_tcam_entry_t *entry)
{
	tcam_ether_t *key = &entry->data.key.ether_e;
	tcam_ether_t *mask = &entry->data.mask.ether_e;

	struct ether_vlan_header *vlan = &flow->fd_mac;

	tcam_user_class_t *pet;	/* Programmable Ether Type */
	tcam_control_t *tcam = (tcam_control_t *)nxge->nxge_hw_p->tcam;

	/* Almost all of the key is a don't care. */
	(void)memset(mask, 0, sizeof (*mask));
	mask->cls_code = CLS_CODE_MASK;

	/* The class code. */
	switch (vlan->ether_type) {
	case ETHERTYPE_ARP:
		key->cls_code = TCAM_CLASS_ARP;
		spec->flow_type = FSPEC_ARPIP;
		entry->region++; /* := 1 */
		return (0);
	case ETHERTYPE_REVARP:
		key->cls_code = TCAM_CLASS_RARP;
		spec->flow_type = 0; /* XXX ? */
		entry->region++; /* := 1 */
		return (0);
	default:
		/* Are both programmable ethernet classes in use? */
		pet = &tcam->pc[0];
		if (pet->count && (pet + 1)->count)
			return (EAGAIN);
		key->cls_code = TCAM_CLASS_ETYPE_1;
		break;
	}

	/* If ETYPE_1 is in use, then use ETYPE_2. */
	if (pet->count) {
		pet++;
		key->cls_code++;
	}

	/* Mark this programmable ethertype IN USE. */
	pet->entry = entry;
	pet->count = 1;

	npi_fflp_cfg_enet_usr_cls_set(nxge->npi_reg_handle, key->cls_code,
	    vlan->ether_type);
	npi_fflp_cfg_enet_usr_cls_enable(nxge->npi_reg_handle, key->cls_code);

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_vid_enable
 *
 * Define and enable a hardware vlan table entry.
 *
 * Input
 *	nxge
 *	flow		A Crossbow flow description.
 *			(All we need is the TCI).
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * -------------------------------------------------------------
 */
int
nxge_vid_enable(
	nxge_t *nxge,
	flow_desc_t *flow)
{
	p_nxge_hw_list_t hardware;
	p_nxge_mv_cfg_t vlan_table;
	int vid;

	npi_status_t status;

	vlan_table = ((p_nxge_class_pt_cfg_t)&nxge->class_config)->vlan_tbl;
	/*
	 * A TCI looks like this:
	 * 15:13 		12 	11:0
	 * user_priority 	CFI 	VID
	 *
	 * All we want is the VID.
	 */
	vid = flow->fd_mac.ether_tci & VID_MASK;

	if (vlan_table[vid].flag == 0) {
		NXGE_ERROR_MSG((nxge, FFLP_CTL,
		    " nxge_vid_enable:"
		    " vlan id '%d' unconfigured", vid));
		return (EIO);
	}

	/* Enable the VLAN preference. */
	hardware = nxge->nxge_hw_p;
	MUTEX_ENTER(&hardware->nxge_vlan_lock);
	status = npi_fflp_cfg_enet_vlan_table_assoc(
	    nxge->npi_reg_handle, nxge->mac.portnum,
	    vid, vlan_table[vid].rdctbl,
	    VLANRDCTBLN);
	MUTEX_EXIT(&hardware->nxge_vlan_lock);

	NXGE_DEBUG_MSG((nxge, FFLP_CTL, " nxge_vid_enable:"
	    " port %d / vid %d / RDC table %d",
	    nxge->mac.portnum, vid, vlan_table[vid].rdctbl));

	if (status & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxge, FFLP_CTL,
		    " nxge_vid_enable:"
		    " npi_fflp_cfg_enet_vlan_table_assoc() failed"));
		return (EIO);
	}

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_vid_disable
 *
 * Disnable a hardware vlan table entry.
 *
 * Input
 *	nxge
 *	flow		A Crossbow flow description.
 *			(All we need is the TCI).
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * -------------------------------------------------------------
 */
int
nxge_vid_disable(
	nxge_t *nxge,
	flow_desc_t *flow)
{
	p_nxge_hw_list_t hardware;
	p_nxge_mv_cfg_t vlan_table;
	int vid;

	npi_status_t status;

	vlan_table = ((p_nxge_class_pt_cfg_t)&nxge->class_config)->vlan_tbl;
	vid = flow->fd_mac.ether_tci & VID_MASK;

	/* Disable the VLAN preference. */
	hardware = nxge->nxge_hw_p;
	MUTEX_ENTER(&hardware->nxge_vlan_lock);
	status = npi_fflp_cfg_enet_vlan_table_set_pri(
	    nxge->npi_reg_handle, nxge->mac.portnum,
	    vid, MACRDCTBLN); /* Disable */
	MUTEX_EXIT(&hardware->nxge_vlan_lock);

	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
	    " nxge_vid_disable:"
	    " port %d / vid %d / RDC table %d)",
	    nxge->mac.portnum, vid, vlan_table[vid].rdctbl));

	if (status & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxge, FFLP_CTL,
		    " nxge_vid_disable:"
			" npi_fflp_cfg_enet_vlan_table_assoc(failed)"));
		return (EIO);
	}

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_altmac_enable
 *
 * Add a Layer 2 classification rule.
 *
 * Input
 *	nxge
 *	flow		The Crossbow flow description
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * -------------------------------------------------------------
 */
int
nxge_altmac_enable(
	nxge_t *nxge,
	flow_desc_t *flow)
{
	struct ether_vlan_header *mac = &flow->fd_mac;
	nxge_mac_addr_t *address;
	nxge_mmac_t *mmac;
	int i;

	mutex_enter(nxge->genlock);
	/* Verify that the alternate address has been configured. */
	mmac = &nxge->nxge_mmac_info;
	for (i = 0, address = &mmac->mac_pool[0];
	    i < mmac->num_mmac; i++, address++) {
		if (address->flags & MMAC_SLOT_USED) {
			if (bcmp(mac->ether_dhost.ether_addr_octet,
				address->addr,
				sizeof (address->addr))) {
				continue;
			}
			/* We found a match. */
			break;
		}
	}
	mutex_exit(nxge->genlock);

	if (i == mmac->num_mmac) {
		return (EINVAL);
	}

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_m_classify_add
 *
 * Add a hardware classification rule.
 *
 * Input
 *	arg		An nxge_t data structure.
 *	mrh		Receive Completion Ring pointer.
 *	flow		A Crossbow flow description
 *
 *	The next 3 args are provided by Crossbow, & are opaque.
 *
 *	rx_func		A Crossbow receive function pointer.
 *	rx_arg1		The first argument to <rx_func>.
 *	rx_arg2
 *
 *	handle		We will point this at a private data
 *			structure below.  It will turn out to
 *			be a flow_resource_t.
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * -------------------------------------------------------------
 */
int
nxge_m_classify_add(
	/* ARGSUSED */
	void *arg,			/* p_nxge_t */
	mac_resource_handle_t mrh, 	/* p_rx_rcr_ring_t */
	flow_desc_t *flow,
	mac_rx_func_t rx_func,		/* The next 3 args are opaque */
	void *rx_arg1,
	mac_resource_handle_t rx_arg2,
	mac_rule_handle_t *handle) 	/* We fill this in below */
{
	p_nxge_t	nxge = (p_nxge_t)arg;
	p_rx_rcr_ring_t rcr_p = (p_rx_rcr_ring_t)mrh;

	flow_resource_t *resource;
	int		rv;

	NXGE_DEBUG_MSG((nxge, FFLP_CTL, "==> nxge_m_classify_add"));
	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
	    "==> nxge_m_classify_add: arg $%p mrh $%p nxge $%p "
	    "rx_func $%p rx_arg1 $%p rx_arg2 $%p",
	    arg, mrh, nxge,
	    rx_func, rx_arg1, rx_arg2));

	if (nxge->nxge_hw_p == 0) {
		NXGE_ERROR_MSG((nxge, FFLP_CTL,
		    "nxge_tcam_ad_write: %s hardware uninitialized",
		    nxge->niu_type == NEPTUNE ?
		    "Neptune" : "Niagara 2 NIU"));
		return (ENODEV);
	}

	if (!(resource = kmem_zalloc(sizeof (flow_resource_t), KM_NOSLEEP))) {
		return (ENOMEM);
	}
	resource->channel_cookie = rcr_p->rdc;

	if ((rv = nxge_classify_add(nxge, flow, resource)) != 0) {
		return (rv);
	}

	MUTEX_ENTER(TCAM_LOCK(nxge));
	rcr_p->mac_rx_func = rx_func;
	rcr_p->mac_rx_arg = rx_arg1;
	rcr_p->rcr_mac_handle = rx_arg2;
	MUTEX_EXIT(TCAM_LOCK(nxge));

	*handle = (mac_rule_handle_t)resource;

	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
	    "==> nxge_m_classify_add (exit): "
	    "flow type %d "
	    "rcrp $%p arg $%p mrh $%p nxge $%p "
	    "rx_func $%p rx_arg1 $%p rx_arg2 $%p",
	    resource->flow_spec.flow_type,
	    rcr_p,
	    arg, mrh, nxge,
	    rcr_p->mac_rx_func,
	    rcr_p->mac_rx_arg,
	    rcr_p->rcr_mac_handle));

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_m_classify_add
 *
 * Add a hardware classification rule.
 *
 * Input
 *	arg		An nxge_t data structure.
 *	mrh		Receive Completion Ring pointer.
 *	handle		The private data structure we created in
 *			nxge_m_classify_add() above.
 *			A flow_resource_t.
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * -------------------------------------------------------------
 */
int
nxge_m_classify_remove(
	void *arg,			/* p_nxge_t */
	mac_resource_handle_t mrh,	/* p_rx_rcr_ring_t */
	mac_rule_handle_t handle)	/* flow_resource_t */
{
	p_nxge_t nxge = (p_nxge_t)arg;
	p_rx_rcr_ring_t rcr_p = (p_rx_rcr_ring_t)mrh;
	flow_resource_t *fh = (flow_resource_t *)handle;

	nxge_tcam_entry_t *entry = (nxge_tcam_entry_t *)fh->tcam_handle;
	flow_desc_t *flow = &entry->fd;

	tcam_control_t *tcam = (tcam_control_t *)nxge->nxge_hw_p->tcam;

	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
	    "==> nxge_m_classify_remove: "
	    "arg $%p mrh %p handle %p slot %d",
		arg, mrh, handle, entry->location));


	MUTEX_ENTER(TCAM_LOCK(nxge));
	/* This slot may be reused. */
	tcam->slot[entry->location] = 0;

	/* mac_rx_func() is no longer current. */
	rcr_p->mac_rx_func = 0;
	rcr_p->mac_rx_arg = 0;
	MUTEX_EXIT(TCAM_LOCK(nxge));

	/* This object may be a VLAN flow. */
	if (flow->fd_mask & VLAN_FLOWS) {
		nxge_vid_disable(nxge, flow);
	}

	/* This object may be a VLAN-only flow. */
	if (entry->location) {
		tcam_ether_t *key; /* It could have been tcam_ipv4_t, etc. */

		nxge_tcam_entry_invalidate(nxge, tcam, entry->location);

		/* Does this flow belong to a programmable class? */
		key = &entry->data.key.ether_e;

		if (key->cls_code >= TCAM_CLASS_ETYPE_1 &&
		    key->cls_code <= TCAM_CLASS_IP_USER_7) {
			/* If no one is using this class anymore, disable it. */
			tcam_user_class_t *class = &tcam->pc
			    [key->cls_code - TCAM_CLASS_ETYPE_1];
			MUTEX_ENTER(TCAM_LOCK(nxge));
			--class->count;
			if (class->count == 0) {
				(void) npi_fflp_cfg_enet_usr_cls_disable(
				    nxge->npi_reg_handle, key->cls_code);
			}
			MUTEX_EXIT(TCAM_LOCK(nxge));
		}
	}

	KMEM_FREE((caddr_t)entry, sizeof (*entry));
	KMEM_FREE((caddr_t)fh, sizeof (*fh));

	NXGE_DEBUG_MSG((nxge, FFLP_CTL, "<== nxge_m_classify_remove"));

	return (0);
}

/*
 * -------------------------------------------------------------
 * nxge_m_classify_update
 *
 * Update a hardware classification rule.  In other words, change it.
 *
 * Input
 *	arg		Receive Completion Ring pointer.
 *	rx_func		The new Crossbow receive function.
 *	rx_arg		The new first argument to <rx_func>.
 *	mrh		What is this?
 *
 * Output
 *	0 if successful; a standard error number otherwise.
 *
 * TBD: check if the ring is valid.
 * -------------------------------------------------------------
 */
void
nxge_m_classify_update(
	void *arg,
	mac_rx_func_t rx_func,
	void *mac_rx_arg,
	mac_resource_handle_t mrh)
{
	p_rx_rcr_ring_t	rcr_p = (p_rx_rcr_ring_t)arg;
	p_nxge_t nxge = rcr_p->nxgep;

	NXGE_DEBUG_MSG((nxge, FFLP_CTL, "==> nxge_m_classify_update"));

	NXGE_DEBUG_MSG((nxge, FFLP_CTL,
	    "==> nxge_m_classify_update: "
	    "rcrp $%p arg $%p mrh $%p nxge $%p "
	    "rx_func $%p mac_rx_arg $%p rcr_mac_handle $%p",
	    rcr_p,
	    arg, mrh, nxge,
	    rcr_p->mac_rx_func,
	    rcr_p->mac_rx_arg,
	    rcr_p->rcr_mac_handle));

	MUTEX_ENTER(TCAM_LOCK(nxge));
	rcr_p->mac_rx_func = rx_func;
	rcr_p->mac_rx_arg = mac_rx_arg;
	rcr_p->rcr_mac_handle = mrh;
	MUTEX_EXIT(TCAM_LOCK(nxge));
}
