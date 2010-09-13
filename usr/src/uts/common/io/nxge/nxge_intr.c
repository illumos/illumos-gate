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
 * nxge_intr.c
 *
 * This file manages the interrupts for a hybrid I/O (hio) device.
 * In the future, it may manage interrupts for all Neptune-based
 * devices.
 *
 */

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_hio.h>

/*
 * External prototypes
 */

/* The following function may be found in nxge_[t|r]xdma.c */
extern uint_t nxge_tx_intr(void *, void *);
extern uint_t nxge_rx_intr(void *, void *);

/*
 * Local prototypes
 */
static int nxge_intr_vec_find(nxge_t *, vpc_type_t, int);

/*
 * nxge_intr_add
 *
 *	Add <channel>'s interrupt.
 *
 * Arguments:
 * 	nxge
 * 	type	Tx or Rx
 * 	channel	The channel whose interrupt we want to add.
 *
 * Notes:
 *	Add here means: add a handler, enable, & arm the interrupt.
 *
 * Context:
 *	Service domain
 *
 */
nxge_status_t
nxge_intr_add(
	nxge_t *nxge,
	vpc_type_t type,
	int channel)
{
	nxge_intr_t	*interrupts; /* The global interrupt data. */
	nxge_ldg_t	*group;	/* The logical device group data. */
	nxge_ldv_t	*ldvp;

	uint_t		*inthandler; /* A parameter to ddi_intr_add_handler */
	int		vector;
	int		status1, status2;

	char c = (type == VP_BOUND_TX ? 'T' : 'R');

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_intr_add"));

	if ((vector = nxge_intr_vec_find(nxge, type, channel)) == -1) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_intr_add(%cDC %d): vector not found", c, channel));
		return (NXGE_ERROR);
	}

	ldvp = &nxge->ldgvp->ldvp[vector];
	group = ldvp->ldgp;

	if (group->nldvs == 1) {
		inthandler = (uint_t *)group->ldvp->ldv_intr_handler;
	} else if (group->nldvs > 1) {
		inthandler = (uint_t *)group->sys_intr_handler;
	}

	interrupts = (nxge_intr_t *)&nxge->nxge_intr_type;

	status1 = DDI_SUCCESS;

	if ((status2 = ddi_intr_add_handler(interrupts->htable[vector],
	    (ddi_intr_handler_t *)inthandler, group->ldvp, nxge))
	    != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_intr_add(%cDC %d): "
		    "ddi_intr_add_handler(%d) returned %s",
		    c, channel, vector, nxge_ddi_perror(status2)));
		status1 += status2;
	}

	interrupts->intr_added++;

	/* Enable the interrupt. */
	if ((status2 = ddi_intr_enable(interrupts->htable[vector]))
	    != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_intr_add(%cDC %d): "
		    "ddi_intr_enable(%d) returned %s",
		    c, channel, vector, nxge_ddi_perror(status2)));
		status1 += status2;
	}

	if (status1 == DDI_SUCCESS) {
		interrupts->intr_enabled = B_TRUE;

		/* Finally, arm the interrupt. */
		if (group->nldvs == 1) {
			npi_handle_t handle = NXGE_DEV_NPI_HANDLE(nxge);
			(void) npi_intr_ldg_mgmt_set(handle, group->ldg,
			    B_TRUE, group->ldg_timer);
		}
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_intr_add"));

	return (NXGE_OK);
}

/*
 * nxge_intr_remove
 *
 *	Remove <channel>'s interrupt.
 *
 * Arguments:
 * 	nxge
 * 	type	Tx or Rx
 * 	channel	The channel whose interrupt we want to remove.
 *
 * Notes:
 *	Remove here means: disarm, disable, & remove the handler.
 *
 * Context:
 *	Service domain
 *
 */
nxge_status_t
nxge_intr_remove(
	nxge_t *nxge,
	vpc_type_t type,
	int channel)
{
	nxge_intr_t	*interrupts; /* The global interrupt data. */
	nxge_ldg_t	*group;	/* The logical device group data. */
	nxge_ldv_t	*ldvp;

	int		vector;
	int		status1, status2;

	char c = (type == VP_BOUND_TX ? 'T' : 'R');

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_intr_remove"));

	if ((vector = nxge_intr_vec_find(nxge, type, channel)) == -1) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_intr_remove(%cDC %d): vector not found", c, channel));
		return (NXGE_ERROR);
	}

	ldvp = &nxge->ldgvp->ldvp[vector];
	group = ldvp->ldgp;

	/* Disarm the interrupt. */
	if (group->nldvs == 1) {
		npi_handle_t handle = NXGE_DEV_NPI_HANDLE(nxge);
		group->arm = B_FALSE;
		(void) npi_intr_ldg_mgmt_set(handle, group->ldg,
		    B_TRUE, group->ldg_timer);
		group->arm = B_TRUE; /* HIOXXX There IS a better way */
	}

	interrupts = (nxge_intr_t *)&nxge->nxge_intr_type;

	status1 = DDI_SUCCESS;

	/* Disable the interrupt. */
	if ((status2 = ddi_intr_disable(interrupts->htable[vector]))
	    != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_intr_remove(%cDC %d)"
		    ": ddi_intr_disable(%d) returned %s",
		    c, channel, vector, nxge_ddi_perror(status2)));
		status1 += status2;
	}

	/* Remove the interrupt handler. */
	if ((status2 = ddi_intr_remove_handler(interrupts->htable[vector]))
	    != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_intr_remove(%cDC %d)"
		    ": ddi_intr_remove_handler(%d) returned %s",
		    c, channel, vector, nxge_ddi_perror(status2)));
		status1 += status2;
	}

	if (status1 == DDI_SUCCESS) {
		interrupts->intr_added--;
		if (interrupts->intr_added == 0)
			interrupts->intr_enabled = B_FALSE;
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_intr_remove"));

	return (NXGE_OK);
}

/*
 * nxge_intr_vec_find
 *
 *	Find the interrupt vector associated with <channel>.
 *
 * Arguments:
 * 	nxge
 * 	type	Tx or Rx
 * 	channel	The channel whose vector we want to find.
 *
 * Notes:
 *
 * Context:
 *	Service domain
 *
 */
static
int
nxge_intr_vec_find(
	nxge_t *nxge,
	vpc_type_t type,
	int channel)
{
	nxge_hw_pt_cfg_t *hardware;
	nxge_ldgv_t	*ldgvp;
	nxge_ldv_t	*ldvp;

	int		first, limit, vector;

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "==> nxge_intr_vec_find(%cDC %d)",
	    type == VP_BOUND_TX ? 'T' : 'R', channel));

	if (nxge->ldgvp == 0) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL,
		    "nxge_hio_intr_vec_find(%cDC %d): ldgvp == 0",
		    type == VP_BOUND_TX ? 'T' : 'R', channel));
		return (-1);
	}

	hardware = &nxge->pt_config.hw_config;

	first = hardware->ldg_chn_start;
	if (type == VP_BOUND_TX) {
		first += 8;	/* HIOXXX N2/NIU hack */
		limit = first + hardware->tdc.count;
	} else {
		limit = first + hardware->max_rdcs;
	}

	ldgvp = nxge->ldgvp;
	for (vector = first; vector < limit; vector++) {
		ldvp = &ldgvp->ldvp[vector];
		if (ldvp->channel == channel)
			break;
	}

	if (vector == limit) {
		return (-1);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_intr_vec_find"));

	return (vector);
}

/*
 * ---------------------------------------------------------------------
 * HIO-specific interrupt functions.
 * ---------------------------------------------------------------------
 */

/*
 * nxge_hio_intr_add
 *
 *	Add <channel>'s interrupt.
 *
 * Arguments:
 * 	nxge
 * 	type	Tx or Rx
 * 	channel	The channel whose interrupt we want to remove.
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 *
 */
nxge_status_t
nxge_hio_intr_add(
	nxge_t *nxge,
	vpc_type_t type,
	int channel)
{
	nxge_hio_dc_t	*dc;	/* The relevant DMA channel data structure. */
	nxge_intr_t	*interrupts; /* The global interrupt data. */
	nxge_ldg_t	*group;	/* The logical device group data. */
	uint_t		*inthandler; /* A parameter to ddi_intr_add_handler */

	int		vector;	/* A shorthand variable */
	int		ddi_status; /* The response to ddi_intr_add_handler */

	char c = (type == VP_BOUND_TX ? 'T' : 'R');

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "==> nxge_hio_intr_add(%cDC %d)", c, channel));

	if (nxge->ldgvp == 0) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL,
		    "nxge_hio_intr_add(%cDC %d): ldgvp == 0", c, channel));
		return (NXGE_ERROR);
	}

	if ((dc = nxge_grp_dc_find(nxge, type, channel)) == 0) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL,
		    "nxge_hio_intr_add: find(%s, %d) failed", c, channel));
		return (NXGE_ERROR);
	}

	/* 'nxge_intr_type' is a bad name for this data structure. */
	interrupts = (nxge_intr_t *)&nxge->nxge_intr_type;

	/* Set <vector> here to make the following code easier to read. */
	vector = dc->ldg.vector;

	group = &nxge->ldgvp->ldgp[vector];

	if (group->nldvs == 1) {
		inthandler = (uint_t *)group->ldvp->ldv_intr_handler;
	} else if (group->nldvs > 1) {
		inthandler = (uint_t *)group->sys_intr_handler;
	}

	if ((ddi_status = ddi_intr_add_handler(interrupts->htable[vector],
	    (ddi_intr_handler_t *)inthandler, group->ldvp, nxge))
	    != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_intr_add(%cDC %d): "
		    "ddi_intr_add_handler(%d) returned %s",
		    c, channel, vector, nxge_ddi_perror(ddi_status)));
		return (NXGE_ERROR);
	}

	interrupts->intr_added++;

	/* Enable the interrupt. */
	if ((ddi_status = ddi_intr_enable(interrupts->htable[vector]))
	    != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_intr_add(%cDC %d): "
		    "ddi_intr_enable(%d) returned %s",
		    c, channel, vector, nxge_ddi_perror(ddi_status)));
		return (NXGE_ERROR);
	}

	interrupts->intr_enabled = B_TRUE;

	/*
	 * Note: RDC interrupts will be armed in nxge_m_start(). This
	 * prevents us from getting an interrupt before we are ready
	 * to process packets.
	 */
	if (type == VP_BOUND_TX) {
		nxge_hio_ldgimgn(nxge, group);
	}

	dc->interrupting = B_TRUE;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_intr_add"));

	return (NXGE_OK);
}

/*
 * nxge_hio_intr_remove
 *
 *	Remove <channel>'s interrupt.
 *
 * Arguments:
 * 	nxge
 * 	type	Tx or Rx
 * 	channel	The channel whose interrupt we want to remove.
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 *
 */
nxge_status_t
nxge_hio_intr_remove(
	nxge_t *nxge,
	vpc_type_t type,
	int channel)
{
	nxge_hio_dc_t	*dc;	/* The relevant DMA channel data structure. */
	nxge_intr_t	*interrupts; /* The global interrupt data. */
	nxge_ldg_t	*group;	/* The logical device group data. */

	int		vector;	/* A shorthand variable */
	int		status1, status2;

	char c = (type == VP_BOUND_TX ? 'T' : 'R');

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "==> nxge_hio_intr_remove(%cDC %d)", c, channel));

	if (nxge->ldgvp == 0) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL,
		    "nxge_hio_intr_remove(%cDC %d): ldgvp == 0", c, channel));
		return (NXGE_ERROR);
	}

	if ((dc = nxge_grp_dc_find(nxge, type, channel)) == 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_intr_remove(%cDC %d): DC FIND failed",
		    c, channel));
		return (NXGE_ERROR);
	}

	if (dc->interrupting == B_FALSE) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL,
		    "nxge_hio_intr_remove(%cDC %d): interrupting == FALSE",
		    c, channel));
		return (NXGE_OK);
	}

	/* 'nxge_intr_type' is a bad name for this data structure. */
	interrupts = (nxge_intr_t *)&nxge->nxge_intr_type;

	/* Set <vector> here to make the following code easier to read. */
	vector = dc->ldg.vector;

	group = &nxge->ldgvp->ldgp[vector];

	/* Disarm the interrupt. */
	group->arm = B_FALSE;
	nxge_hio_ldgimgn(nxge, group);
	group->arm = B_TRUE;	/* HIOXXX There IS a better way */

	status1 = DDI_SUCCESS;

	/* Disable the interrupt. */
	if ((status2 = ddi_intr_disable(interrupts->htable[vector]))
	    != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_intr_remove(%cDC %d): "
		    "ddi_intr_disable(%d) returned %s",
		    c, channel, vector, nxge_ddi_perror(status2)));
		status1 += status2;
	}

	/* Remove the interrupt handler. */
	if ((status2 = ddi_intr_remove_handler(interrupts->htable[vector]))
	    != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_intr_remove(%cDC %d): "
		    "ddi_intr_remove_handle(%d) returned %s",
		    c, channel, vector, nxge_ddi_perror(status2)));
		status1 += status2;
	}

	if (status1 == DDI_SUCCESS) {
		dc->interrupting = B_FALSE;

		interrupts->intr_added--;
		if (interrupts->intr_added == 0)
			interrupts->intr_enabled = B_FALSE;
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_intr_remove"));

	return (NXGE_OK);
}

/*
 * nxge_hio_intr_init
 *
 *	Initialize interrupts in a guest domain.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 *
 */
nxge_status_t
nxge_hio_intr_init(
	nxge_t *nxge)
{
	int		*prop_val;
	uint_t		prop_len;

	nxge_intr_t	*interrupts;

	int		intr_type, behavior;
	int		nintrs, navail, nactual;
	int		inum = 0;
	int		ddi_status = DDI_SUCCESS;

	nxge_hw_pt_cfg_t *hardware = &nxge->pt_config.hw_config;
	int i;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_intr_init"));

	/* Look up the "interrupts" property. */
	if ((ddi_prop_lookup_int_array(DDI_DEV_T_ANY, nxge->dip, 0,
	    "interrupts", &prop_val, &prop_len)) != DDI_PROP_SUCCESS) {
		NXGE_ERROR_MSG((nxge, HIO_CTL,
		    "==> nxge_hio_intr_init(obp): no 'interrupts' property"));
		return (NXGE_ERROR);
	}

	/*
	 * For each device assigned, the content of each interrupts
	 * property is its logical device group.
	 *
	 * Assignment of interrupts property is in the the following
	 * order:
	 *
	 * two receive channels
	 * two transmit channels
	 */
	for (i = 0; i < prop_len; i++) {
		hardware->ldg[i] = prop_val[i];
		NXGE_DEBUG_MSG((nxge, HIO_CTL,
		    "==> nxge_hio_intr_init(obp): F%d: interrupt #%d, ldg %d",
		    nxge->function_num, i, hardware->ldg[i]));
	}
	ddi_prop_free(prop_val);

	hardware->max_grpids = prop_len;
	hardware->max_ldgs = prop_len;
	hardware->ldg_chn_start = 0;

	/* ----------------------------------------------------- */
	interrupts = (nxge_intr_t *)&nxge->nxge_intr_type;

	interrupts->intr_registered = B_FALSE;
	interrupts->intr_enabled = B_FALSE;
	interrupts->start_inum = 0;

	ddi_status = ddi_intr_get_supported_types(
	    nxge->dip, &interrupts->intr_types);
	if (ddi_status != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "ddi_intr_get_supported_types() returned 0x%x, "
		    "types = 0x%x", ddi_status, interrupts->intr_types));
		return (NXGE_ERROR);
	}

	NXGE_ERROR_MSG((nxge, HIO_CTL, "ddi_intr_get_supported_types() "
	    "returned 0x%x, types = 0x%x", ddi_status, interrupts->intr_types));

	/* HIOXXX hack */
	interrupts->intr_type = DDI_INTR_TYPE_FIXED;
	/* HIOXXX hack */

	intr_type = interrupts->intr_type;

	ddi_status = ddi_intr_get_navail(nxge->dip, intr_type, &navail);
	if (ddi_status != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "ddi_intr_get_navail() returned %s, navail: %d",
		    ddi_status == DDI_FAILURE ? "DDI_FAILURE" :
		    "DDI_INTR_NOTFOUND", navail));
		return (NXGE_ERROR);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_hio_intr_init: number of available interrupts: %d", navail));

	ddi_status = ddi_intr_get_nintrs(nxge->dip, intr_type, &nintrs);
	if (ddi_status != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "ddi_intr_get_nintrs() returned %s, nintrs: %d",
		    ddi_status == DDI_FAILURE ? "DDI_FAILURE" :
		    "DDI_INTR_NOTFOUND", nintrs));
		return (NXGE_ERROR);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_hio_intr_init: number of interrupts: %d", nintrs));

	interrupts->intr_size = navail * sizeof (ddi_intr_handle_t);
	interrupts->htable = kmem_alloc(interrupts->intr_size, KM_SLEEP);

	/*
	 * When <behavior> is set to  DDI_INTR_ALLOC_STRICT,
	 * ddi_intr_alloc() succeeds if and only if <navail>
	 * interrupts are are allocated. Otherwise, it fails.
	 */
	behavior = ((intr_type == DDI_INTR_TYPE_FIXED) ?
	    DDI_INTR_ALLOC_STRICT : DDI_INTR_ALLOC_NORMAL);

	ddi_status = ddi_intr_alloc(nxge->dip, interrupts->htable, intr_type,
	    inum, navail, &nactual, behavior);
	if (ddi_status != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "ddi_intr_alloc() returned 0x%x%, "
		    "number allocated: %d", ddi_status, nactual));
		return (NXGE_ERROR);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_hio_intr_init: number of interrupts allocated: %d", nactual));

	/* <ninterrupts> is a dead variable: we may as well use it. */
	hardware->ninterrupts = nactual;

	/* FOI: Get the interrupt priority. */
	if ((ddi_status = ddi_intr_get_pri(interrupts->htable[0],
	    (uint_t *)&interrupts->pri)) != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    " ddi_intr_get_pri() failed: %d", ddi_status));
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_hio_intr_init: interrupt priority: %d", interrupts->pri));

	/* FOI: Get our interrupt capability flags. */
	if ((ddi_status = ddi_intr_get_cap(interrupts->htable[0],
	    &interrupts->intr_cap)) != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "ddi_intr_get_cap() failed: %d", ddi_status));
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nxge_hio_intr_init: interrupt capabilities: %d",
	    interrupts->intr_cap));

	interrupts->intr_registered = B_TRUE;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_intr_init"));

	return (NXGE_OK);
}

/*
 * nxge_hio_intr_uninit
 *
 *	Uninitialize interrupts in a guest domain.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 */
void
nxge_hio_intr_uninit(
	nxge_t *nxge)
{
	nxge_hw_pt_cfg_t *hardware;
	nxge_intr_t *interrupts;
	nxge_ldgv_t *control;
	int i;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_intr_uninit"));

	/* ----------------------------------------------------- */
	interrupts = (nxge_intr_t *)&nxge->nxge_intr_type;

	/*
	 * If necessary, disable any currently active interrupts.
	 */
	if (interrupts->intr_enabled) {
		nxge_grp_set_t *set;
		nxge_grp_t *group;
		int channel;

		set = &nxge->tx_set;
		group = set->group[0];	/* Assumption: only one group! */
		for (channel = 0; channel < NXGE_MAX_TDCS; channel++) {
			if ((1 << channel) & group->map) {
				(void) nxge_hio_intr_remove(
				    nxge, VP_BOUND_TX, channel);
			}
		}

		set = &nxge->rx_set;
		group = set->group[0];	/* Assumption: only one group! */
		for (channel = 0; channel < NXGE_MAX_RDCS; channel++) {
			if ((1 << channel) & group->map) {
				(void) nxge_hio_intr_remove(
				    nxge, VP_BOUND_RX, channel);
			}
		}
	}

	/*
	 * Free all of our allocated interrupts.
	 */
	hardware = &nxge->pt_config.hw_config;
	for (i = 0; i < hardware->ninterrupts; i++) {
		if (interrupts->htable[i])
			(void) ddi_intr_free(interrupts->htable[i]);
		interrupts->htable[i] = 0;
	}

	interrupts->intr_registered = B_FALSE;
	KMEM_FREE(interrupts->htable, interrupts->intr_size);
	interrupts->htable = NULL;

	if (nxge->ldgvp == NULL)
		goto nxge_hio_intr_uninit_exit;

	control = nxge->ldgvp;
	if (control->ldgp) {
		KMEM_FREE(control->ldgp,
		    sizeof (nxge_ldg_t) * NXGE_INT_MAX_LDGS);
		control->ldgp = 0;
	}

	if (control->ldvp) {
		KMEM_FREE(control->ldvp,
		    sizeof (nxge_ldv_t) * NXGE_INT_MAX_LDS);
		control->ldvp = 0;
	}

	KMEM_FREE(control, sizeof (nxge_ldgv_t));
	nxge->ldgvp = NULL;

nxge_hio_intr_uninit_exit:
	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_intr_uninit"));
}

/*
 * nxge_hio_tdsv_add
 *
 *	Add a transmit device interrupt.
 *
 * Arguments:
 * 	nxge
 * 	dc	The TDC whose interrupt we're adding
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 */
static
hv_rv_t
nxge_hio_tdsv_add(
	nxge_t *nxge,
	nxge_hio_dc_t *dc)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hw_pt_cfg_t *hardware = &nxge->pt_config.hw_config;
	nxhv_dc_fp_t *tx = &nhd->hio.tx;
	hv_rv_t hv_rv;

	if (tx->getinfo == 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_tdsv_add: tx->getinfo absent"));
		return (EINVAL);
	}

	/*
	 * Get the dma channel information.
	 */
	hv_rv = (*tx->getinfo)(dc->cookie, dc->page, &dc->ldg.index,
	    &dc->ldg.ldsv);
	if (hv_rv != 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_tdsv_add: tx->getinfo failed: %ld", hv_rv));
		return (EIO);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nx_hio_tdsv_add: VRgroup = %d, LDSV = %d",
	    (int)dc->ldg.index, (int)dc->ldg.ldsv));

	if (hardware->tdc.count == 0) {
		hardware->tdc.start = dc->channel;
	}

	hardware->tdc.count++;
	hardware->tdc.owned++;

	/*
	 * In version 1.0 of the hybrid I/O driver, there
	 * are eight interrupt vectors per VR.
	 *
	 * Vectors 0 - 3 are reserved for RDCs.
	 * Vectors 4 - 7 are reserved for TDCs.
	 */
	dc->ldg.vector = (dc->ldg.ldsv % 2) + HIO_INTR_BLOCK_SIZE;
	// Version 1.0 hack only!

	return (0);
}

/*
 * nxge_hio_rdsv_add
 *
 *	Add a transmit device interrupt.
 *
 * Arguments:
 * 	nxge
 * 	dc	The RDC whose interrupt we're adding
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 */
static
hv_rv_t
nxge_hio_rdsv_add(
	nxge_t *nxge,
	nxge_hio_dc_t *dc)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hw_pt_cfg_t *hardware = &nxge->pt_config.hw_config;
	nxhv_dc_fp_t *rx = &nhd->hio.rx;
	hv_rv_t hv_rv;

	if (rx->getinfo == 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_tdsv_add: rx->getinfo absent"));
		return (EINVAL);
	}

	/*
	 * Get DMA channel information.
	 */
	hv_rv = (*rx->getinfo)(dc->cookie, dc->page, &dc->ldg.index,
	    &dc->ldg.ldsv);
	if (hv_rv != 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nx_hio_tdsv_add: rx->getinfo failed: %ld", hv_rv));
		return (EIO);
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "nx_hio_rdsv_add: VRgroup = %d, LDSV = %d",
	    (int)dc->ldg.index, (int)dc->ldg.ldsv));

	if (hardware->max_rdcs == 0) {
		hardware->start_rdc = dc->channel;
		hardware->def_rdc = dc->channel;
	}

	hardware->max_rdcs++;

	/*
	 * In version 1.0 of the hybrid I/O driver, there
	 * are eight interrupt vectors per VR.
	 *
	 * Vectors 0 - 3 are reserved for RDCs.
	 */
	dc->ldg.vector = (dc->ldg.ldsv % 2);
	// Version 1.0 hack only!

	return (0);
}

/*
 * nxge_hio_ldsv_add
 *
 *	Add a transmit or receive interrupt.
 *
 * Arguments:
 * 	nxge
 * 	dc	The DMA channel whose interrupt we're adding
 *
 * Notes:
 *	Guest domains can only add interrupts for DMA channels.
 *	They cannot access the MAC, MIF, or SYSERR interrupts.
 *
 * Context:
 *	Guest domain
 */
int
nxge_hio_ldsv_add(nxge_t *nxge, nxge_hio_dc_t *dc)
{
	nxge_ldgv_t *control;
	nxge_ldg_t *group;
	nxge_ldv_t *device;

	if (dc->type == VP_BOUND_TX) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_ldsv_add(TDC %d)",
		    dc->channel));
		if (nxge_hio_tdsv_add(nxge, dc) != 0)
			return (EIO);
	} else {
		NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_ldsv_add(RDC %d)",
		    dc->channel));
		if (nxge_hio_rdsv_add(nxge, dc) != 0)
			return (EIO);
	}

	dc->ldg.map |= (1 << dc->ldg.ldsv);

	control = nxge->ldgvp;
	if (control == NULL) {
		control = KMEM_ZALLOC(sizeof (nxge_ldgv_t), KM_SLEEP);
		nxge->ldgvp = control;
		control->maxldgs = 1;
		control->maxldvs = 1;
		control->ldgp = KMEM_ZALLOC(
		    sizeof (nxge_ldg_t) * NXGE_INT_MAX_LDGS, KM_SLEEP);
		control->ldvp = KMEM_ZALLOC(
		    sizeof (nxge_ldv_t) * NXGE_INT_MAX_LDS, KM_SLEEP);
	} else {
		control->maxldgs++;
		control->maxldvs++;
	}

	/*
	 * Initialize the logical device group data structure first.
	 */
	group = &control->ldgp[dc->ldg.vector];

	(void) memset(group, 0, sizeof (*group));

	/*
	 * <hw_config.ldg> is a copy of the "interrupts" property.
	 */
	group->ldg = nxge->pt_config.hw_config.ldg[dc->ldg.vector];
	group->vldg_index = (uint8_t)dc->ldg.index;
	/*
	 * Since <vldg_index> is a dead variable, I'm reusing
	 * it in Hybrid I/O to calculate the offset into the
	 * virtual PIO_LDSV space.
	 */

	group->arm = B_TRUE;
	group->ldg_timer = NXGE_TIMER_LDG;
	group->func = nxge->function_num;
	group->vector = dc->ldg.vector;
	/*
	 * <intdata> appears to be a dead variable.
	 * Though it is not used anywhere in the driver,
	 * we'll set it anyway.
	 */
	group->intdata = SID_DATA(group->func, group->vector);

	group->sys_intr_handler = nxge_intr; /* HIOXXX Does this work? */
	group->nxgep = nxge;

	/*
	 * Initialize the logical device state vector next.
	 */
	device = &control->ldvp[dc->ldg.ldsv];

	device->ldg_assigned = group->ldg;
	device->ldv = dc->ldg.ldsv;

	if (dc->type == VP_BOUND_TX) {
		device->is_txdma = B_TRUE;
		device->is_rxdma = B_FALSE;
		device->ldv_intr_handler = nxge_tx_intr;
	} else {
		device->is_rxdma = B_TRUE;
		device->is_txdma = B_FALSE;
		device->ldv_intr_handler = nxge_rx_intr;
	}
	device->is_mif = B_FALSE;
	device->is_mac = B_FALSE;
	device->is_syserr = B_FALSE;
	device->use_timer = B_FALSE; /* Set to B_TRUE for syserr only. */

	device->channel = dc->channel;
	device->vdma_index = dc->page;
	device->func = nxge->function_num;
	device->ldgp = group;
	device->ldv_flags = 0;
	device->ldv_ldf_masks = 0;

	device->nxgep = nxge;

	/*
	 * This code seems to imply a strict 1-to-1 correspondence.
	 */
	group->nldvs++;
	group->ldvp = device;

	control->nldvs++;
	control->ldg_intrs++;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_ldsv_add"));

	return (0);
}

/*
 * nxge_hio_ldsv_im
 *
 *	Manage a VLDG's interrupts.
 *
 * Arguments:
 * 	nxge
 * 	group	The VLDG to manage
 *
 * Notes:
 *	There are 8 sets of 4 64-bit registers per VR, 1 per LDG.
 *	That sums to 256 bytes of virtual PIO_LDSV space.
 *
 *		VLDG0 starts at offset 0,
 *		VLDG1 starts at offset 32, etc.
 *
 *	Each set consists of 4 registers:
 *		Logical Device State Vector 0. LDSV0
 *		Logical Device State Vector 1. LDSV1
 *		Logical Device State Vector 2. LDSV2
 *		Logical Device Group Interrupt Management. LDGIMGN
 *
 *	The first three (LDSVx) are read-only.  The 4th register is the
 *	LDGIMGN, the LDG Interrupt Management register, which is used to
 *	arm the LDG, or set its timer.
 *
 *	The offset to write to is calculated as follows:
 *
 *		0x2000 + (VLDG << 4) + offset, where:
 *		VDLG is the virtual group, i.e., index of the LDG.
 *		offset is the offset (alignment 8) of the register
 *		       to read or write.
 *
 *	So, for example, if we wanted to arm the first TDC of VRx, we would
 *	calculate the address as:
 *
 *	0x2000 + (0 << 4) + 0x18 = 0x18
 *
 * Context:
 *	Guest domain
 *
 */
void
nxge_hio_ldsv_im(
	/* Read any register in the PIO_LDSV space. */
	nxge_t *nxge,
	nxge_ldg_t *group,
	pio_ld_op_t op,
	uint64_t *value)
{
	uint64_t offset = VLDG_OFFSET;

	offset += group->vldg_index << VLDG_SLL; /* bits 7:5 */
	offset += (op * sizeof (uint64_t)); /* 0, 8, 16, 24 */

	NXGE_REG_RD64(nxge->npi_handle, offset, value);
}

void
nxge_hio_ldgimgn(
	/* Write the PIO_LDGIMGN register. */
	nxge_t *nxge,
	nxge_ldg_t *group)
{
	uint64_t offset = VLDG_OFFSET;
	ldgimgm_t mgm;

	offset += group->vldg_index << VLDG_SLL; /* bits 7:5 */
	offset += (PIO_LDGIMGN * sizeof (uint64_t)); /* 24 */

	mgm.value = 0;
	if (group->arm) {
		mgm.bits.ldw.arm = 1;
		mgm.bits.ldw.timer = group->ldg_timer;
	} else {
		mgm.bits.ldw.arm = 0;
		mgm.bits.ldw.timer = 0;
	}
	NXGE_REG_WR64(nxge->npi_handle, offset, mgm.value);
}
