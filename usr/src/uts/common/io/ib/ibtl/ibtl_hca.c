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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ibtl_hca.c
 *
 * This file contains Transport API functions related to
 * Host Channel Adapter (HCA) Verbs.
 */

#include <sys/ib/ibtl/impl/ibtl.h>

static char ibtf_hca[] = "ibtl_hca";

/* Prototype declarations. */
static ibt_status_t ibtl_query_hca_ports(ibtl_hca_devinfo_t *hca_devp,
    uint8_t port, ibt_hca_portinfo_t **port_info_p, uint_t *ports_p,
    uint_t *size_p, int use_cache);

/*
 * Function:
 *      ibt_open_hca
 * Input:
 *      ibt_hdl    - IBT Client Handle
 *      hca_guid   - HCA's node GUID.
 * Output:
 *      hca_hdl_p  - IBT HCA Handle.
 * Returns:
 *      IBT_SUCCESS
 *      IBT_HCA_IN_USE
 *      IBT_HCA_INVALID
 * Description:
 *      Open a HCA. HCA can only be opened/closed once. This routine allocates
 *      and returns a unique IBT Client HCA handle. Clients passes this
 *      handle on its subsequent references to this device. Once opened by a
 *      client, a specific HCA cannot be opened again until after it is closed.
 *      The IBT_HCA_IN_USE error is returned if client tries to open multiple
 *      times. In this case, previously allocated IBT HCA handle is returned to
 *      the client. Opening the HCA prepares the HCA for use by the client.
 */
ibt_status_t
ibt_open_hca(ibt_clnt_hdl_t ibt_hdl, ib_guid_t hca_guid,
    ibt_hca_hdl_t *hca_hdl_p)
{
	ibtl_hca_t  		*hca_infop;
	ibtl_hca_devinfo_t	*hca_devp;		/* HCA Dev Info */

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_open_hca(%p, %llX)", ibt_hdl, hca_guid);


	/*
	 * Get HCA Device Info Structure, referenced by HCA GUID.
	 */
	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		/*
		 * If we are here, then the requested HCA device is not present.
		 * Return the status as Invalid HCA GUID.
		 */
		mutex_exit(&ibtl_clnt_list_mutex);

		IBTF_DPRINTF_L2(ibtf_hca, "ibt_open_hca: "
		    "HCA Device Not Found: Invalid HCA GUID");

		*hca_hdl_p = NULL;
		return (IBT_HCA_INVALID);
	}

	/*
	 * Check whether open is allowed for this dip
	 */
	if (ibt_hdl->clnt_dip) {
		if (ddi_get_parent(ibt_hdl->clnt_dip) == hca_devp->hd_hca_dip) {
			if (hca_guid != hca_devp->hd_hca_attr->hca_node_guid) {
				mutex_exit(&ibtl_clnt_list_mutex);
				return (IBT_FAILURE);
			}
		}
	}

	if (hca_devp->hd_state != IBTL_HCA_DEV_ATTACHED) {
		/*
		 * If we are here, then the requested HCA device has detached,
		 * or is in the process of detaching.
		 */
		mutex_exit(&ibtl_clnt_list_mutex);

		IBTF_DPRINTF_L2(ibtf_hca, "ibt_open_hca: "
		    "HCA is busy trying to detach");

		*hca_hdl_p = NULL;
		return (IBT_HCA_BUSY_DETACHING);
	}

	/*
	 * Yes, we found a HCA Device registered with IBTF, which matches with
	 * the requested HCA_GUID.
	 *
	 * Check out whether this client has already opened this HCA device,
	 * if yes return the status as IBT_HCA_IN_USE.
	 */
	hca_infop = hca_devp->hd_clnt_list;

	while (hca_infop != NULL) {
		if (ibt_hdl == hca_infop->ha_clnt_devp) {
			IBTF_DPRINTF_L3(ibtf_hca,
			    "ibt_open_hca: Already Open");

			if (hca_infop->ha_flags & IBTL_HA_CLOSING) {
				mutex_exit(&ibtl_clnt_list_mutex);
				*hca_hdl_p = NULL;
				return (IBT_HCA_BUSY_CLOSING);
			}
			mutex_exit(&ibtl_clnt_list_mutex);

			/* Already Opened. Return back old HCA Handle. */
			*hca_hdl_p = hca_infop;

			return (IBT_HCA_IN_USE);
		}
		hca_infop = hca_infop->ha_clnt_link;
	}

	/* Create a new HCA Info entity. */
	hca_infop = kmem_zalloc(sizeof (ibtl_hca_t), KM_SLEEP);

	/* Initialize HCA Mutex. */
	mutex_init(&hca_infop->ha_mutex, NULL, MUTEX_DEFAULT, NULL);

	/* Update the HCA Info entity */
	hca_infop->ha_hca_devp  = hca_devp;	/* HCA Device Info */
	hca_infop->ha_clnt_devp = ibt_hdl;	/* Client Info */

	/* Update the HCA List, to keep track about the clients using it. */
	hca_infop->ha_clnt_link = hca_devp->hd_clnt_list;
	hca_devp->hd_clnt_list = hca_infop;


	/* Update the client's list to depict that it uses this HCA device. */
	hca_infop->ha_hca_link = ibt_hdl->clnt_hca_list;
	ibt_hdl->clnt_hca_list = hca_infop;

	mutex_exit(&ibtl_clnt_list_mutex);

	/*
	 * Return back the address of ibtl_hca_t structure as an opaque
	 * IBT HCA handle for the clients, to be used in future calls.
	 */
	*hca_hdl_p = hca_infop;

	return (IBT_SUCCESS);
}


/*
 * Function:
 *      ibt_close_hca
 * Input:
 *      hca_hdl  - The HCA handle as returned during its open.
 * Output:
 *      none
 * Returns:
 *      IBT_SUCCESS
 *      IBT_HCA_HDL_INVALID
 *      IBT_HCA_RESOURCES_NOT_FREED
 * Description:
 *      Close a HCA.
 */
ibt_status_t
ibt_close_hca(ibt_hca_hdl_t hca_hdl)
{
	ibtl_hca_devinfo_t	*hca_devp, *tmp_devp;
	ibtl_hca_t		**hcapp;
	ibtl_clnt_t		*clntp = hca_hdl->ha_clnt_devp;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_close_hca(%p)", hca_hdl);

	/*
	 * Verify the Input HCA Handle, if fake return error as
	 * invalid HCA Handle.
	 */
	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = hca_hdl->ha_hca_devp;
	tmp_devp = ibtl_hca_list;

	for (; tmp_devp != NULL; tmp_devp = tmp_devp->hd_hca_dev_link)
		if (tmp_devp == hca_devp)
			break;

	if (tmp_devp == NULL) {
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_close_hca: "
		    "Unable to find this on global HCA list");
		return (IBT_HCA_HDL_INVALID);
	}

	mutex_enter(&hca_hdl->ha_mutex);

	/* Make sure resources have been freed. */
	if (hca_hdl->ha_qp_cnt | hca_hdl->ha_cq_cnt | hca_hdl->ha_eec_cnt |
	    hca_hdl->ha_ah_cnt | hca_hdl->ha_mr_cnt | hca_hdl->ha_mw_cnt |
	    hca_hdl->ha_pd_cnt | hca_hdl->ha_fmr_pool_cnt |
	    hca_hdl->ha_ma_cnt) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_close_hca: "
		    "some resources have not been freed by '%s': hca_hdl = %p",
		    hca_hdl->ha_clnt_devp->clnt_modinfop->mi_clnt_name,
		    hca_hdl);
		mutex_exit(&hca_hdl->ha_mutex);
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_HCA_RESOURCES_NOT_FREED);
	}
	mutex_exit(&hca_hdl->ha_mutex);	/* ok to drop this now */

	/* we are now committed to closing the HCA */
	hca_hdl->ha_flags |= IBTL_HA_CLOSING;
	while (hca_hdl->ha_qpn_cnt > 0)
		cv_wait(&ibtl_close_hca_cv, &ibtl_clnt_list_mutex);

	/*
	 * Remove this HCA Device entry form Client's current list of HCA
	 * Device Instances being used by it.
	 */
	hcapp = &clntp->clnt_hca_list;

	for (; *hcapp != NULL; hcapp = &(*hcapp)->ha_hca_link)
		if (*hcapp == hca_hdl)
			break;

	if (*hcapp == NULL) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_close_hca: "
		    "Unable to find this HCA on client list");
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_HCA_HDL_INVALID);
	}

	/* hcapp now points to a link that points to us */
	*hcapp = hca_hdl->ha_hca_link;		/* remove us */

	/*
	 * Remove this Client's entry from this HCA Device's Clients list.
	 */
	hcapp = &hca_devp->hd_clnt_list;

	for (; *hcapp != NULL; hcapp = &(*hcapp)->ha_clnt_link)
		if (*hcapp == hca_hdl)
			break;

	if (*hcapp == NULL) {
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_close_hca: "
		    "Unable to find this HCA on the client's HCA list");
		return (IBT_HCA_HDL_INVALID);
	}

	/* hcapp now points to a link that points to us */
	*hcapp = hca_hdl->ha_clnt_link;		/* remove us */
	mutex_exit(&ibtl_clnt_list_mutex);

	/* Un-Initialize HCA Mutex. */
	mutex_destroy(&hca_hdl->ha_mutex);

	/* Free memory for this HCA Handle */
	ibtl_free_hca_async_check(hca_hdl);

	return (IBT_SUCCESS);
}

void
ibtl_close_hca_check(ibt_hca_hdl_t hca_hdl)
{
	IBTF_DPRINTF_L3(ibtf_hca, "ibtl_close_hca_check(%p)", hca_hdl);

	mutex_enter(&ibtl_clnt_list_mutex);
	if ((--hca_hdl->ha_qpn_cnt == 0) &&
	    (hca_hdl->ha_flags & IBTL_HA_CLOSING)) {
		cv_signal(&ibtl_close_hca_cv);
	}
	mutex_exit(&ibtl_clnt_list_mutex);
}

/*
 * Function:
 *      ibt_get_hca_list
 * Input:
 *      hca_list_p -  Address of pointer updated here.
 * Output:
 *      hca_list_p -  Points to an array of ib_guid_t's allocated here.
 * Returns:
 *      The actual number of valid ib_guid_t's returned.
 * Description:
 *	If hca_list_p is not NULL then the memory for the array of GUIDs is
 *	allocated here and should be freed by the caller using
 *	ibt_free_hca_list(). If hca_list_p is NULL then no memory is allocated
 *	by ibt_get_hca_list and only the number of HCAs in a system is returned.
 */
uint_t
ibt_get_hca_list(ib_guid_t **hca_list_p)
{
	uint_t			hca_count = 0;
	ibtl_hca_devinfo_t	*hca_devp;
	ib_guid_t		*hca_listp;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_get_hca_list(%p)", hca_list_p);

	mutex_enter(&ibtl_clnt_list_mutex);

	hca_devp = ibtl_hca_list;
	while (hca_devp != NULL) {
		hca_count++;
		hca_devp = hca_devp->hd_hca_dev_link;
	}

	if (hca_count == 0)
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_get_hca_list: "
		    "HCA device not found");

	if ((hca_count == 0) || (hca_list_p == NULL)) {
		mutex_exit(&ibtl_clnt_list_mutex);
		return (hca_count);
	}

	hca_listp = kmem_alloc(hca_count * sizeof (ib_guid_t), KM_SLEEP);
	*hca_list_p = hca_listp;

	hca_devp = ibtl_hca_list;
	while (hca_devp != NULL) {
		/* Traverse Global HCA List & retrieve HCA Node GUIDs. */
		*hca_listp++ = hca_devp->hd_hca_attr->hca_node_guid;
		hca_devp = hca_devp->hd_hca_dev_link;
	}
	mutex_exit(&ibtl_clnt_list_mutex);

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_get_hca_list: "
	    "Returned <%d> entries @0x%p", hca_count, *hca_list_p);

	return (hca_count);
}

/*
 * Function:
 *      ibt_free_hca_list
 * Input:
 *      hca_list  - The address of an ib_guid_t pointer.
 *      entries   - The number of ib_guid_t entries to be freed.
 * Output:
 *      none.
 * Returns:
 *      none.
 * Description:
 *      The memory allocated in ibt_get_hca_list() is freed in this function.
 */
void
ibt_free_hca_list(ib_guid_t *hca_list, uint_t entries)
{
	IBTF_DPRINTF_L3(ibtf_hca, "ibt_free_hca_list: "
	    "Free <%d> entries from 0x%p", entries, hca_list);

	if ((hca_list != NULL) && (entries > 0))
		kmem_free(hca_list, entries * sizeof (ib_guid_t));
}

/*
 * ibtl_portinfo_locked() is called when the portinfo cache is being
 * updated.  If this port's info update is in progress, we return 0
 * immediately and have the c
 * unless it's already in progress (distinguished by return value).
 * When done updating the portinfo, they call ibtl_portinfo_unlock().
 */

static int
ibtl_portinfo_locked(ibtl_hca_devinfo_t *hca_devp, uint8_t port)
{
	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	for (;;) {
		if (hca_devp->hd_portinfo_locked_port == 0) {
			hca_devp->hd_portinfo_locked_port = port;
			return (1); /* not busy, so OK to initiate update */
		} else if (hca_devp->hd_portinfo_locked_port == port) {
			IBTF_DPRINTF_L3(ibtf_hca, "ibtl_portinfo_locked: "
			    "HCA %p port %d is already locked",
			    hca_devp, port);
			hca_devp->hd_portinfo_waiters = 1;
			cv_wait(&hca_devp->hd_portinfo_cv,
			    &ibtl_clnt_list_mutex);
			return (0); /* it's now done, so no need to initiate */
		} else {
			/* need to wait for other port before we try again */
			hca_devp->hd_portinfo_waiters = 1;
			cv_wait(&hca_devp->hd_portinfo_cv,
			    &ibtl_clnt_list_mutex);
		}
	}
}

static void
ibtl_portinfo_unlock(ibtl_hca_devinfo_t *hca_devp, uint8_t port)
{
	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));
	ASSERT(hca_devp->hd_portinfo_locked_port == port);
	hca_devp->hd_portinfo_locked_port = 0;
	if (hca_devp->hd_portinfo_waiters) {
		hca_devp->hd_portinfo_waiters = 0;
		cv_broadcast(&hca_devp->hd_portinfo_cv);
		IBTF_DPRINTF_L3(ibtf_hca, "ibtl_portinfo_unlock: "
		    "waking up waiters for port %d info on HCA %p",
		    port, hca_devp);
	}
}

/*
 * Function:
 *      ibt_get_port_state
 * Input:
 *      hca_devp    - The HCA Dev Info pointer.
 *	port        - Port number to query.
 * Output:
 *      sgid_p	    - Returned sgid[0], NULL implies no return value.
 *      base_lid_p  - Returned base_lid, NULL implies no return value.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_HCA_PORT_INVALID
 * Description:
 *      Returns HCA port attributes for one of the HCA ports.
 */
static ibt_status_t
ibtl_get_port_state(ibtl_hca_devinfo_t *hca_devp, uint8_t port,
    ib_gid_t *sgid_p, ib_lid_t *base_lid_p)
{
	ibt_hca_portinfo_t *portinfop;

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	if ((port < 1) || (port > hca_devp->hd_hca_attr->hca_nports)) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibtl_get_port_state: "
		    "invalid port %d, nports = %d", port,
		    hca_devp->hd_hca_attr->hca_nports);
		return (IBT_HCA_PORT_INVALID);
	}
	portinfop = hca_devp->hd_portinfop + port - 1;
	if (portinfop->p_linkstate != IBT_PORT_ACTIVE)
		ibtl_reinit_hca_portinfo(hca_devp, port);

	if (sgid_p)
		*sgid_p = portinfop->p_sgid_tbl[0];
	if (base_lid_p)
		*base_lid_p = portinfop->p_base_lid;
	if (portinfop->p_linkstate != IBT_PORT_ACTIVE) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibtl_get_port_state: "
		    "port %d, port_state %d, base_lid %d",
		    port, portinfop->p_linkstate, portinfop->p_base_lid);
		return (IBT_HCA_PORT_NOT_ACTIVE);
	}
	IBTF_DPRINTF_L3(ibtf_hca, "ibtl_get_port_state: "
	    "port %d, port_state %d, base_lid %d",
	    port, portinfop->p_linkstate, portinfop->p_base_lid);
	return (IBT_SUCCESS);
}

/*
 * Function:
 *      ibt_get_port_state
 * Input:
 *      hca_hdl	    - The HCA handle.
 *	port        - Port number to query.
 * Output:
 *      sgid_p	    - Returned sgid[0], NULL implies no return value.
 *      base_lid_p  - Returned base_lid, NULL implies no return value.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_HCA_PORT_INVALID
 * Description:
 *      Returns HCA port attributes for one of the HCA ports.
 */
ibt_status_t
ibt_get_port_state(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ib_gid_t *sgid_p, ib_lid_t *base_lid_p)
{
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_get_port_state(%p, %d, %p, %p)",
	    hca_hdl, port, sgid_p, base_lid_p);
	mutex_enter(&ibtl_clnt_list_mutex);
	retval = ibtl_get_port_state(hca_hdl->ha_hca_devp, port, sgid_p,
	    base_lid_p);
	mutex_exit(&ibtl_clnt_list_mutex);
	return (retval);
}


/*
 * Function:
 *      ibt_get_port_state_byguid
 * Input:
 *      hca_guid    - The HCA node GUID.
 *	port        - Port number to query.
 * Output:
 *      sgid_p	    - Returned sgid[0], NULL implies no return value.
 *      base_lid_p  - Returned base_lid, NULL implies no return value.
 * Returns:
 *      IBT_SUCCESS
 *	IBT_HCA_PORT_INVALID
 *      IBT_HCA_INVALID
 * Description:
 *      Returns HCA port attributes for one of the HCA ports.
 */
ibt_status_t
ibt_get_port_state_byguid(ib_guid_t hca_guid, uint8_t port,
    ib_gid_t *sgid_p, ib_lid_t *base_lid_p)
{
	ibtl_hca_devinfo_t	*hca_devp;		/* HCA Dev Info */
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_get_port_state_byguid(%llx, %d, %p, "
	    "%p)", (longlong_t)hca_guid, port, sgid_p, base_lid_p);
	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL)
		retval = IBT_HCA_INVALID;
	else
		retval = ibtl_get_port_state(hca_devp, port, sgid_p,
		    base_lid_p);
	mutex_exit(&ibtl_clnt_list_mutex);
	return (retval);
}


/*
 * Function:
 *      ibt_query_hca_byguid
 * Input:
 *      hca_guid  - The HCA node GUID.
 * Output:
 *      hca_attrs - A pointer to a ibt_hca_attr_t allocated by the caller,
 *                  into which the HCA Attributes are copied.
 * Returns:
 *      IBT_SUCCESS
 *      IBT_INVALID_PARAM
 *      IBT_HCA_INVALID
 * Description:
 *      Returns the static attributes of the specified HCA.
 */
ibt_status_t
ibt_query_hca_byguid(ib_guid_t hca_guid, ibt_hca_attr_t *hca_attrs)
{
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info. */

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_query_hca_byguid(%llX)", hca_guid);

	mutex_enter(&ibtl_clnt_list_mutex);
	/* Get HCA Dev Info Structure, referenced by HCA GUID. */
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		/*
		 * If we are here, then the requested HCA device is not present.
		 */
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_query_hca_byguid: "
		    "Device Not Found");
		return (IBT_HCA_INVALID);
	}

	/* Return back the static HCA attributes */
	bcopy(hca_devp->hd_hca_attr, hca_attrs, sizeof (ibt_hca_attr_t));

	mutex_exit(&ibtl_clnt_list_mutex);

	return (IBT_SUCCESS);
}


/*
 * Function:
 *      ibt_query_hca
 * Input:
 *      hca_hdl   - The HCA handle.
 * Output:
 *      hca_attrs - A pointer to a ibt_hca_attr_t allocated by the caller,
 *                  into which the HCA Attributes are copied.
 * Returns:
 *      IBT_SUCCESS
 *
 * Description:
 *      Returns the static attributes of the specified HCA.
 */
ibt_status_t
ibt_query_hca(ibt_hca_hdl_t hca_hdl, ibt_hca_attr_t *hca_attrs)
{
	IBTF_DPRINTF_L3(ibtf_hca, "ibt_query_hca(%p)", hca_hdl);

	/* Return back the static HCA attributes */
	bcopy(hca_hdl->ha_hca_devp->hd_hca_attr, hca_attrs,
	    sizeof (ibt_hca_attr_t));

	return (IBT_SUCCESS);
}

#define	ROUNDUP(x, y)	((((x)+((y)-1))/(y))*(y))

/*
 * Function:
 *      ibt_query_hca_ports
 * Input:
 *      hca_hdl	    - The HCA handle.
 *	port        - Port number.  If "0", then query ALL Ports.
 * Output:
 *      port_info_p - The address of a pointer to a ibt_hca_portinfo_t struct.
 *      ports_p     - The number of hca ports on the specified HCA.
 *      size_p      - Size of the memory allocated by IBTL to get portinfo,
 *                   to be freed by calling ibt_free_portinfo().
 * Returns:
 *      IBT_SUCCESS
 *      IBT_HCA_HDL_INVALID
 *      IBT_HCA_INVALID
 * Description:
 *      Returns HCA port attributes for either "one", or "all" of the HCA ports.
 */
ibt_status_t
ibt_query_hca_ports(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p)
{
	ibt_status_t	retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_query_hca_ports(%p, %d)",
	    hca_hdl, port);

	mutex_enter(&ibtl_clnt_list_mutex);

	retval = ibtl_query_hca_ports(hca_hdl->ha_hca_devp, port, port_info_p,
	    ports_p, size_p, 0);

	mutex_exit(&ibtl_clnt_list_mutex);

	return (retval);
}

/*
 * Function:
 *      ibt_query_hca_ports_byguid
 * Input:
 *      hca_guid    - The HCA node GUID.
 *	port        - Port number.  If "0", then query ALL Ports.
 * Output:
 *      port_info_p - The address of a pointer to a ibt_hca_portinfo_t struct.
 *      ports_p     - The number of hca ports on the specified HCA.
 *      size_p      - Size of the memory allocated by IBTL to get portinfo,
 *                   to be freed by calling ibt_free_portinfo().
 * Returns:
 *      IBT_SUCCESS
 *      IBT_HCA_HDL_INVALID
 *      IBT_HCA_INVALID
 * Description:
 *      Returns HCA port attributes for either "one", or "all" of the HCA ports.
 */
ibt_status_t
ibt_query_hca_ports_byguid(ib_guid_t hca_guid, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p)
{
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info */
	ibt_status_t		retval;

	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		/*
		 * If we are here, then the requested HCA device is not present.
		 * Return the status as Invalid HCA GUID.
		 */
		*ports_p = *size_p = 0;
		*port_info_p = NULL;
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_query_hca_ports_byguid: "
		    "HCA Device Not Found. ");
		return (IBT_HCA_INVALID);
	}

	retval = ibtl_query_hca_ports(hca_devp, port, port_info_p, ports_p,
	    size_p, 0);

	mutex_exit(&ibtl_clnt_list_mutex);

	return (retval);
}

/*
 * Define the above function for CM's use that uses the cached copy.
 */
ibt_status_t
ibtl_cm_query_hca_ports_byguid(ib_guid_t hca_guid, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p)
{
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info */
	ibt_status_t		retval;

	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		/*
		 * If we are here, then the requested HCA device is not present.
		 * Return the status as Invalid HCA GUID.
		 */
		*ports_p = *size_p = 0;
		*port_info_p = NULL;
		mutex_exit(&ibtl_clnt_list_mutex);
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_query_hca_ports_byguid: "
		    "HCA Device Not Found. ");
		return (IBT_HCA_INVALID);
	}

	retval = ibtl_query_hca_ports(hca_devp, port, port_info_p, ports_p,
	    size_p, 1);

	mutex_exit(&ibtl_clnt_list_mutex);

	return (retval);
}


/*
 * ibtl_query_one_port - fill in portinfo for one port.
 */
static ibt_status_t
ibtl_query_one_port(ibtl_hca_devinfo_t *hca_devp, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p,
    int use_cache)
{
	ibt_hca_portinfo_t	*sp1;	/* src */
	ibt_hca_portinfo_t	*p1;	/* dst */
	caddr_t			p2;
	uint_t			len;
	uint_t			sgid_tbl_len, pkey_tbl_len;

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	IBTF_DPRINTF_L3(ibtf_hca, "ibtl_query_one_port(%p, %d)",
	    hca_devp, port);

	if (port > hca_devp->hd_hca_attr->hca_nports) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibtl_query_one_port: "
		    "invalid port %d", port);
		return (IBT_HCA_PORT_INVALID);
	}

	/* If the PORT_UP event is not supported, we need to query */
	sp1 = hca_devp->hd_portinfop + port - 1;
	if (use_cache == 0)
		ibtl_reinit_hca_portinfo(hca_devp, port);

	*ports_p = 1;

	/*
	 * Calculate how much memory we need for one port, and allocate it.
	 */
	sgid_tbl_len = ROUNDUP(sp1->p_sgid_tbl_sz * sizeof (ib_gid_t),
	    _LONG_LONG_ALIGNMENT);
	pkey_tbl_len = ROUNDUP(sp1->p_pkey_tbl_sz * sizeof (ib_pkey_t),
	    _LONG_LONG_ALIGNMENT);

	len = sizeof (ibt_hca_portinfo_t) + sgid_tbl_len + pkey_tbl_len;
	*size_p = len;

	p1 = kmem_zalloc(len, KM_SLEEP);
	*port_info_p = p1;
	bcopy(sp1, p1, sizeof (ibt_hca_portinfo_t));

	/* initialize the p_pkey_tbl & p_sgid_tbl pointers. */
	p2 = (caddr_t)(p1 + 1);	/* pkeys follow the struct ibt_hca_portinfo_s */
	bcopy(sp1->p_pkey_tbl, p2, pkey_tbl_len);
	p1->p_pkey_tbl = (ib_pkey_t *)p2;

	p2 += pkey_tbl_len;	/* sgids follow the pkeys */
	bcopy(sp1->p_sgid_tbl, p2, sgid_tbl_len);
	p1->p_sgid_tbl = (ib_gid_t *)p2;

	return (IBT_SUCCESS);
}

/*
 * ibtl_query_hca_ports - worker routine to get port_info for clients.
 */
static ibt_status_t
ibtl_query_hca_ports(ibtl_hca_devinfo_t *hca_devp, uint8_t port,
    ibt_hca_portinfo_t **port_info_p, uint_t *ports_p, uint_t *size_p,
    int use_cache)
{
	ibt_hca_portinfo_t	*sp1;	/* src */
	ibt_hca_portinfo_t	*p1;	/* dst */
	uint_t			i, nports;
	caddr_t			p2;
	uint_t			len;
	uint_t			sgid_tbl_len, pkey_tbl_len;

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	/*
	 * If user has specified the port num, then query only that port,
	 * else query all ports.
	 */
	if (port)
		return (ibtl_query_one_port(hca_devp, port, port_info_p,
		    ports_p, size_p, use_cache));

	IBTF_DPRINTF_L3(ibtf_hca, "ibtl_query_hca_ports(%p, ALL)", hca_devp);

	nports = hca_devp->hd_hca_attr->hca_nports;
	*ports_p = nports;

	/* If the PORT_UP event is not supported, we need to query */
	if (use_cache == 0)
		for (i = 0; i < nports; i++)
			ibtl_reinit_hca_portinfo(hca_devp, i + 1);

	sp1 = hca_devp->hd_portinfop;

	/*
	 * Calculate how much memory we need for all ports, and allocate it.
	 */
	sgid_tbl_len = ROUNDUP(sp1->p_sgid_tbl_sz * sizeof (ib_gid_t),
	    _LONG_LONG_ALIGNMENT);
	pkey_tbl_len = ROUNDUP(sp1->p_pkey_tbl_sz * sizeof (ib_pkey_t),
	    _LONG_LONG_ALIGNMENT);

	len = (sizeof (ibt_hca_portinfo_t) + sgid_tbl_len + pkey_tbl_len) *
	    nports;
	*size_p = len;

	ASSERT(len == hca_devp->hd_portinfo_len);

	p1 = kmem_zalloc(len, KM_SLEEP);
	*port_info_p = p1;
	bcopy(sp1, p1, len);	/* start with an exact copy of our cache */

	p2 = (caddr_t)(p1 + nports);

	/* For each port, update the p_pkey_tbl & p_sgid_tbl ptrs. */
	for (i = 0; i < nports; i++) {
		p1->p_pkey_tbl = (ib_pkey_t *)p2;
		p2 += pkey_tbl_len;
		p1->p_sgid_tbl = (ib_gid_t *)p2;
		p2 += sgid_tbl_len;
		p1++;
	}
	return (IBT_SUCCESS);
}

/*
 *	Search for a Full pkey.  Use the pkey at index 0 if not found.
 */
static void
ibtl_set_default_pkey_ix(ibt_hca_portinfo_t *p1)
{
	uint16_t	pkey_ix;

	for (pkey_ix = 0; pkey_ix < p1->p_pkey_tbl_sz; pkey_ix++) {
		if ((p1->p_pkey_tbl[pkey_ix] & 0x8000) &&
		    (p1->p_pkey_tbl[pkey_ix] != IB_PKEY_INVALID_FULL)) {
			p1->p_def_pkey_ix = pkey_ix;
			IBTF_DPRINTF_L3(ibtf_hca,
			    "ibtl_set_default_pkey_ix: portinfop %p, "
			    "FULL PKEY 0x%x found, pkey_ix is %d",
			    p1, p1->p_pkey_tbl[pkey_ix], pkey_ix);
			return;
		}
	}
	IBTF_DPRINTF_L2(ibtf_hca,
	    "ibtl_set_default_pkey_ix: portinfop %p: failed "
	    "to find a default PKEY in the table, using PKey 0x%x",
	    p1, p1->p_pkey_tbl[0]);
	p1->p_def_pkey_ix = 0;
}

/*
 * ibtl_reinit_hca_portinfo - update the portinfo cache for use by IBTL.
 *
 * We have the HCA driver fill in a temporary portinfo, then we bcopy
 * it into our cache while holding the appropriate lock.
 */
void
ibtl_reinit_hca_portinfo(ibtl_hca_devinfo_t *hca_devp, uint8_t port)
{
	ibt_status_t		status;
	ibt_hca_portinfo_t	*p1, *sp1;
	ibt_port_state_t	old_linkstate;
	uint_t			len, sgid_tbl_len, pkey_tbl_len;
	ib_pkey_t		*saved_pkey_tbl;
	ib_gid_t		*saved_sgid_tbl;
	ib_sn_prefix_t		sn_pfx = 0;
	uint_t			multiSM;
	int			i;

	IBTF_DPRINTF_L3(ibtf_hca, "ibtl_reinit_hca_portinfo(%p, %d)",
	    hca_devp, port);

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));
	ASSERT(port != 0);

	if (ibtl_portinfo_locked(hca_devp, port)) {
		/* we got the lock, so we need to do the portinfo update */

		/* invalidate fast_gid_cache */
		ibtl_fast_gid_cache_valid = B_FALSE;

		p1 = hca_devp->hd_portinfop + port - 1;
		sgid_tbl_len = ROUNDUP(p1->p_sgid_tbl_sz * sizeof (ib_gid_t),
		    _LONG_LONG_ALIGNMENT);
		pkey_tbl_len = ROUNDUP(p1->p_pkey_tbl_sz * sizeof (ib_pkey_t),
		    _LONG_LONG_ALIGNMENT);
		len = sizeof (ibt_hca_portinfo_t) + sgid_tbl_len + pkey_tbl_len;

		/* update was NOT in progress, so we do it here */
		mutex_exit(&ibtl_clnt_list_mutex);

		IBTF_DPRINTF_L3(ibtf_hca, "ibtl_reinit_hca_portinfo(%p, %d): "
		    "calling ibc_query_hca_ports", hca_devp, port);

		sp1 = kmem_zalloc(len, KM_SLEEP);
		sp1->p_pkey_tbl = (ib_pkey_t *)(sp1 + 1);
		sp1->p_sgid_tbl =
		    (ib_gid_t *)((caddr_t)sp1->p_pkey_tbl + pkey_tbl_len);
		status = IBTL_HDIP2CIHCAOPS_P(hca_devp)->ibc_query_hca_ports(
		    IBTL_HDIP2CIHCA(hca_devp), port, sp1);

		mutex_enter(&ibtl_clnt_list_mutex);
		if (status != IBT_SUCCESS) {
			IBTF_DPRINTF_L2(ibtf_hca,
			    "ibtl_reinit_hca_portinfo(%p, %d): "
			    "ibc_query_hca_ports() failed: status = %d",
			    hca_devp, port, status);
		} else {
			old_linkstate = p1->p_linkstate;
			bcopy(sp1->p_pkey_tbl, p1->p_pkey_tbl, pkey_tbl_len);
			bcopy(sp1->p_sgid_tbl, p1->p_sgid_tbl, sgid_tbl_len);
			saved_pkey_tbl = p1->p_pkey_tbl;
			saved_sgid_tbl = p1->p_sgid_tbl;
			bcopy(sp1, p1, sizeof (ibt_hca_portinfo_t));
			p1->p_pkey_tbl = saved_pkey_tbl;
			p1->p_sgid_tbl = saved_sgid_tbl;
			if (p1->p_linkstate == IBT_PORT_ACTIVE) {
				ibtl_set_default_pkey_ix(p1);
				if (p1->p_linkstate != old_linkstate)
					IBTF_DPRINTF_L2(ibtf_hca,
					    "ibtl_reinit_hca_portinfo(%p, %d): "
					    "PORT UP", hca_devp, port);
			} else {
				if (p1->p_linkstate != IBT_PORT_ARM)
					p1->p_base_lid = 0;
				if (p1->p_linkstate != old_linkstate)
					IBTF_DPRINTF_L2(ibtf_hca,
					    "ibtl_reinit_hca_portinfo(%p, %d): "
					    "PORT DOWN", hca_devp, port);
			}
		}
		kmem_free(sp1, len);

		/* Set multism bit accordingly. */
		multiSM = 0;
		p1 = hca_devp->hd_portinfop;
		for (i = 0; i < hca_devp->hd_hca_attr->hca_nports; i++) {
			if (p1->p_linkstate == IBT_PORT_ACTIVE) {
				if (sn_pfx == 0) {
					sn_pfx = p1->p_sgid_tbl[0].gid_prefix;
				} else if (sn_pfx !=
				    p1->p_sgid_tbl[0].gid_prefix) {
					multiSM = 1;
					IBTF_DPRINTF_L3(ibtf_hca,
					    "ibtl_reinit_hca_portinfo: "
					    "MULTI SM, Port1 SnPfx=0x%llX, "
					    "Port2 SnPfx=0x%llX", sn_pfx,
					    p1->p_sgid_tbl[0].gid_prefix);
				}
			}
			p1++;
		}
		hca_devp->hd_multism = multiSM;

		ibtl_portinfo_unlock(hca_devp, port);
	}
}

/*
 * ibtl_init_hca_portinfo - fill in the portinfo cache for use by IBTL.
 */
ibt_status_t
ibtl_init_hca_portinfo(ibtl_hca_devinfo_t *hca_devp)
{
	ibt_hca_portinfo_t	*p1;
	ibt_status_t		retval;
	uint_t			i, nports;
	caddr_t			p2;
	uint_t			len;
	uint_t			sgid_tbl_len, pkey_tbl_len;
	uint_t			sgid_tbl_sz, pkey_tbl_sz;
	ib_sn_prefix_t		sn_pfx = 0;
	uint_t			multiSM;

	IBTF_DPRINTF_L2(ibtf_hca, "ibtl_init_hca_portinfo(%p)", hca_devp);

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	nports = hca_devp->hd_hca_attr->hca_nports;

	/*
	 * Calculate how much memory we need for all ports, and allocate it.
	 */
	pkey_tbl_sz = IBTL_HDIP2PKEYTBLSZ(hca_devp);
	sgid_tbl_sz = IBTL_HDIP2SGIDTBLSZ(hca_devp);
	pkey_tbl_len = ROUNDUP(pkey_tbl_sz * sizeof (ib_pkey_t),
	    _LONG_LONG_ALIGNMENT);
	sgid_tbl_len = ROUNDUP(sgid_tbl_sz * sizeof (ib_gid_t),
	    _LONG_LONG_ALIGNMENT);

	len = (sizeof (ibt_hca_portinfo_t) + sgid_tbl_len + pkey_tbl_len) *
	    nports;

	p1 = kmem_zalloc(len, KM_SLEEP);
	p2 = (caddr_t)(p1 + nports);

	hca_devp->hd_portinfop = p1;
	hca_devp->hd_portinfo_len = len;

	/* For each port initialize the p_pkey_tbl & p_sgid_tbl ptrs. */
	for (i = 0; i < nports; i++) {
		p1->p_pkey_tbl_sz = pkey_tbl_sz;
		p1->p_sgid_tbl_sz = sgid_tbl_sz;
		p1->p_pkey_tbl = (ib_pkey_t *)p2;
		p2 += pkey_tbl_len;
		p1->p_sgid_tbl = (ib_gid_t *)p2;
		p2 += sgid_tbl_len;
		p1++;
	}
	p1 = hca_devp->hd_portinfop;
	mutex_exit(&ibtl_clnt_list_mutex);

	/* re-direct the call to CI's call */
	retval = IBTL_HDIP2CIHCAOPS_P(hca_devp)->ibc_query_hca_ports(
	    IBTL_HDIP2CIHCA(hca_devp), 0, p1);

	mutex_enter(&ibtl_clnt_list_mutex);
	if (retval != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibtl_init_hca_portinfo(%p): "
		    "ibc_query_hca_ports() failed: status = %d",
		    hca_devp, retval);
		kmem_free(hca_devp->hd_portinfop, len);
		hca_devp->hd_portinfop = NULL;
		hca_devp->hd_portinfo_len = 0;
		return (retval);
	}

	p1 = hca_devp->hd_portinfop;
	multiSM = 0;
	for (i = 0; i < nports; i++) {
		if (p1->p_linkstate == IBT_PORT_ACTIVE) {
			ibtl_set_default_pkey_ix(p1);
			if (sn_pfx == 0) {
				sn_pfx = p1->p_sgid_tbl[0].gid_prefix;
			} else if (p1->p_sgid_tbl[0].gid_prefix != sn_pfx) {
				multiSM = 1;
				IBTF_DPRINTF_L3(ibtf_hca,
				    "ibtl_init_hca_portinfo: MULTI SM, "
				    "Port1 SnPfx=0x%llX, Port2 SnPfx=0x%llX",
				    sn_pfx, p1->p_sgid_tbl[0].gid_prefix);
			}
		} else {
			if (p1->p_linkstate != IBT_PORT_ARM)
				p1->p_base_lid = 0;
		}
		p1++;
	}
	hca_devp->hd_multism = multiSM;

	return (IBT_SUCCESS);
}

/*
 * Function:
 *	ibt_modify_system_image
 * Input:
 *	hca_hdl	 - The HCA handle.
 *	sys_guid - The New system image GUID.
 * Description:
 *	Modify specified HCA's system image GUID.
 */
ibt_status_t
ibt_modify_system_image(ibt_hca_hdl_t hca_hdl, ib_guid_t sys_guid)
{
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_modify_system_image(%p, %llX)",
	    hca_hdl, sys_guid);

	mutex_enter(&ibtl_clnt_list_mutex);
	/* Get HCA Dev Info Structure, referenced by HCA GUID. */

	/* re-direct the call to CI's call */
	retval = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_modify_system_image(
	    IBTL_HCA2CIHCA(hca_hdl), sys_guid);

	mutex_exit(&ibtl_clnt_list_mutex);
	return (retval);
}

/*
 * Function:
 *	ibt_modify_system_image_byguid
 *
 * Input:
 *	hca_guid - The HCA Node GUID.
 *	sys_guid - The New system image GUID.
 * Description:
 *	Modify specified HCA's system image GUID.
 */
ibt_status_t
ibt_modify_system_image_byguid(ib_guid_t hca_guid, ib_guid_t sys_guid)
{
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info. */
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_modify_system_image_byguid(%llX, %llX)",
	    hca_guid, sys_guid);

	mutex_enter(&ibtl_clnt_list_mutex);
	/* Get HCA Dev Info Structure, referenced by HCA GUID. */
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		/*
		 * If we are here, then the requested HCA device is not present.
		 */
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_HCA_INVALID);
	}

	/* re-direct the call to CI's call */
	retval = IBTL_HDIP2CIHCAOPS_P(hca_devp)->ibc_modify_system_image(
	    IBTL_HDIP2CIHCA(hca_devp), sys_guid);

	mutex_exit(&ibtl_clnt_list_mutex);
	return (retval);
}

/*
 * Function:
 *      ibt_modify_port_byguid
 * Input:
 *      hca_guid - The HCA Guid.
 *      cmds     - A pointer to an array of ibt_port_modify_t cmds. The
 *                 pmod_port field specifies the port to modify (all ports if 0)
 *                 and the pmod_flags field specifies which attribute to reset.
 *      num_cmds - The number of commands in the cmds array.
 * Output:
 *      none.
 * Returns:
 *      IBT_SUCCESS
 *      IBT_HCA_HDL_INVALID
 *      IBT_HCA_CNTR_INVALID
 *      IBT_HCA_CNTR_VAL_INVALID
 * Description:
 *      Reset the specified port, or all ports attribute(s).
 */
ibt_status_t
ibt_modify_port_byguid(ib_guid_t hca_guid,  uint8_t port,
    ibt_port_modify_flags_t flags, uint8_t init_type)
{
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info. */
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_modify_port_byguid(%llX, %d, %X, %X)",
	    hca_guid, port, flags, init_type);

	mutex_enter(&ibtl_clnt_list_mutex);
	/* Get HCA Dev Info Structure, referenced by HCA GUID. */
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		/*
		 * If we are here, then the requested HCA device is not present.
		 */
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_HCA_INVALID);
	}

	/* re-direct the call to CI's call */
	retval = IBTL_HDIP2CIHCAOPS_P(hca_devp)->ibc_modify_ports(
	    IBTL_HDIP2CIHCA(hca_devp), port, flags, init_type);

	mutex_exit(&ibtl_clnt_list_mutex);
	return (retval);
}

/*
 * Function:
 *      ibt_modify_port
 * Input:
 *      hca_hdl  - The HCA handle.
 *      cmds     - A pointer to an array of ibt_port_modify_t cmds. The
 *                 pmod_port field specifies the port to modify (all ports if 0)
 *                 and the pmod_flags field specifies which attribute to reset.
 *      num_cmds - The number of commands in the cmds array.
 * Output:
 *      none.
 * Returns:
 *      IBT_SUCCESS
 *      IBT_HCA_HDL_INVALID
 *      IBT_HCA_CNTR_INVALID
 *      IBT_HCA_CNTR_VAL_INVALID
 * Description:
 *      Reset the specified port, or all ports attribute(s).
 */
ibt_status_t
ibt_modify_port(ibt_hca_hdl_t hca_hdl, uint8_t port,
    ibt_port_modify_flags_t flags, uint8_t init_type)

{
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_modify_port(%p, %d, %X, %X)",
	    hca_hdl, port, flags, init_type);

	mutex_enter(&ibtl_clnt_list_mutex);

	/* re-direct the call to CI's call */
	retval = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_modify_ports(
	    IBTL_HCA2CIHCA(hca_hdl), port, flags, init_type);

	mutex_exit(&ibtl_clnt_list_mutex);
	return (retval);
}

/*
 * Function:
 *      ibt_free_portinfo
 * Input:
 *      port_info  - The address of an array to a ibt_hca_portinfo_t struct.
 *	size	   - Memory Size as returned from ibt_query_hca_ports().
 * Output:
 *      none
 * Returns:
 *      none
 * Description:
 *      Frees the memory allocated for a specified ibt_hca_portinfo_t struct.
 */
void
ibt_free_portinfo(ibt_hca_portinfo_t *port_info, uint_t size)
{
	IBTF_DPRINTF_L3(ibtf_hca, "ibt_free_portinfo(%p, %d)",
	    port_info, size);

	if ((port_info == NULL) || (size == 0)) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_free_portinfo: NULL Pointer");
	} else {
		kmem_free(port_info, size);
	}
}


/*
 * Function:
 *      ibt_get_hcadevinfo
 * Input:
 *      hca_guid - The HCA's node GUID.
 * Output:
 *      none.
 * Returns:
 *      Pointer to HCA Device Info structure whose HCA GUID is requested or NULL
 * Description:
 *      Get a pointer to HCA Device Info Structure for the requested HCA GUID.
 *      If no matching HCA GUID Device info is found, NULL is returned.
 */
ibtl_hca_devinfo_t *
ibtl_get_hcadevinfo(ib_guid_t hca_guid)
{
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info */

	IBTF_DPRINTF_L3(ibtf_hca, "ibtl_get_hcadevinfo(%llX)", hca_guid);

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	hca_devp = ibtl_hca_list;

	/*
	 * Check whether a HCA device with requested Node GUID is available.
	 * This is done, by searching the global HCA devinfo list and
	 * comparing the Node GUID from the device attribute info.
	 */
	while (hca_devp != NULL) {
		if (hca_devp->hd_hca_attr->hca_node_guid == hca_guid) {
			/* Match Found. */
			break;
		}
		hca_devp = hca_devp->hd_hca_dev_link;
	}
	return (hca_devp);
}


/*
 * Function:
 *      ibtl_pkey2index
 * Input:
 *      hca_devp     - The IBTL HCA Device Info.
 *      port_num     - The HCA port number.
 *      pkey         - The input PKey value, whose index we are interested in.
 * Output:
 *      pkey_ix      - The PKey index returned for the specified PKey.
 * Returns:
 *      IBT_SUCCESS/IBT_HCA_PORT_INVALID/IBT_INVALID_PARAM
 * Description:
 *      Returns the PKey Index for the specified PKey, the device as specified
 *      by IBT HCA Handle.
 */
static ibt_status_t
ibtl_pkey2index(ibtl_hca_devinfo_t *hca_devp, uint8_t port_num,
    ib_pkey_t pkey, uint16_t *pkey_ix)
{
	ibt_hca_portinfo_t 	*port_infop;
	uint_t			ports;
	uint_t			i;

	IBTF_DPRINTF_L3(ibtf_hca, "ibtl_pkey2index(%p, %d, %d)",
	    hca_devp, port_num, pkey);

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	if ((pkey == IB_PKEY_INVALID_FULL) ||
	    (pkey == IB_PKEY_INVALID_LIMITED))
		return (IBT_INVALID_PARAM);

	ports = hca_devp->hd_hca_attr->hca_nports;
	if ((port_num == 0) || (port_num > ports)) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibtl_pkey2index: "
		    "Invalid port_num %d, range is (1 to %d)", port_num, ports);
		return (IBT_HCA_PORT_INVALID);
	}

	port_infop = hca_devp->hd_portinfop + port_num - 1;
	for (i = 0; i < port_infop->p_pkey_tbl_sz; i++) {
		if (pkey == port_infop->p_pkey_tbl[i]) {
			*pkey_ix = i;
			return (IBT_SUCCESS);
		}
	}
	return (IBT_INVALID_PARAM);
}

/*
 * Function:
 *      ibtl_index2pkey
 * Input:
 *      hca_devp     - The IBTL HCA Device Info.
 *      port_num     - The HCA port
 *      pkey_ix      - The input PKey index, whose PKey we are interested in.
 * Output:
 *      pkey         - The returned PKey value.
 * Returns:
 *      IBT_SUCCESS/IBT_PKEY_IX_ILLEGAL/IBT_PKEY_IX_INVALID/IBT_HCA_PORT_INVALID
 * Description:
 *      Returns the PKey value for the specified PKey index, the device as
 *      specified by IBT HCA Handle.
 */
static ibt_status_t
ibtl_index2pkey(ibtl_hca_devinfo_t *hca_devp, uint8_t port_num,
    uint16_t pkey_ix, ib_pkey_t *pkey)
{
	ibt_hca_portinfo_t 	*port_infop;
	uint_t			ports;

	IBTF_DPRINTF_L3(ibtf_hca, "ibtl_index2pkey(%p, %d, %d)",
	    hca_devp, port_num, pkey_ix);

	ASSERT(MUTEX_HELD(&ibtl_clnt_list_mutex));

	ports = hca_devp->hd_hca_attr->hca_nports;
	if ((port_num == 0) || (port_num > ports)) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibtl_index2pkey: "
		    "Invalid port_num %d, range is (1 to %d)", port_num, ports);
		return (IBT_HCA_PORT_INVALID);
	}

	port_infop = hca_devp->hd_portinfop + port_num - 1;
	if (pkey_ix >= port_infop->p_pkey_tbl_sz) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibtl_index2pkey: "
		    "pkey index %d out of range (0, %d)",
		    pkey_ix, port_infop->p_pkey_tbl_sz - 1);
		return (IBT_PKEY_IX_ILLEGAL);
	}

	*pkey = port_infop->p_pkey_tbl[pkey_ix];
	if ((*pkey == IB_PKEY_INVALID_FULL) ||
	    (*pkey == IB_PKEY_INVALID_LIMITED))
		return (IBT_PKEY_IX_INVALID);
	return (IBT_SUCCESS);
}

/*
 * Function:
 *      ibt_pkey2index
 * Input:
 *      hca_hdl      - The IBT HCA handle.
 *      port_num     - The HCA port number.
 *      pkey         - The input PKey value, whose index we are interested in.
 * Output:
 *      pkey_ix      - The PKey index returned for the specified PKey.
 * Returns:
 *      IBT_SUCCESS/IBT_HCA_PORT_INVALID/IBT_INVALID_PARAM
 * Description:
 *      Returns the PKey Index for the specified PKey, the device as specified
 *      by IBT HCA Handle.
 */
ibt_status_t
ibt_pkey2index(ibt_hca_hdl_t hca_hdl, uint8_t port_num, ib_pkey_t pkey,
    uint16_t *pkey_ix)
{
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_pkey2index(%p, %d, %d)",
	    hca_hdl, port_num, pkey);

	mutex_enter(&ibtl_clnt_list_mutex);
	retval = ibtl_pkey2index(hca_hdl->ha_hca_devp, port_num, pkey, pkey_ix);
	mutex_exit(&ibtl_clnt_list_mutex);

	return (retval);
}

/*
 * Function:
 *      ibt_pkey2index_byguid
 * Input:
 *      hca_guid     - The HCA's node GUID.
 *      port_num     - The HCA port number.
 *      pkey         - The input PKey value, whose index we are interested in.
 * Output:
 *      pkey_ix      - The PKey Index returned for the specified PKey.
 * Returns:
 *      IBT_SUCCESS/IBT_HCA_PORT_INVALID/IBT_INVALID_PARAM/IBT_HCA_INVALID
 * Description:
 *      Returns the PKey Index for the specified PKey, the device as specified
 *      by HCA GUID Info.
 */
ibt_status_t
ibt_pkey2index_byguid(ib_guid_t hca_guid, uint8_t port_num, ib_pkey_t pkey,
    uint16_t *pkey_ix)
{
	ibt_status_t		retval;
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info */

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_pkey2index_byguid(%llX, %d, %d)",
	    hca_guid, port_num, pkey);

	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_pkey2index_byguid: "
		    "Invalid HCA GUID 0x%llx", hca_guid);
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_HCA_INVALID);
	}
	retval = ibtl_pkey2index(hca_devp, port_num, pkey, pkey_ix);
	mutex_exit(&ibtl_clnt_list_mutex);

	return (retval);
}


/*
 * Function:
 *      ibt_index2pkey
 * Input:
 *      hca_hdl      - The IBT HCA handle.
 *      port_num     - The HCA port
 *      pkey_ix      - The input PKey index, whose PKey we are interested in.
 * Output:
 *      pkey         - The returned PKey value.
 * Returns:
 *      IBT_SUCCESS/IBT_PKEY_IX_ILLEGAL/IBT_PKEY_IX_INVALID/IBT_HCA_PORT_INVALID
 * Description:
 *      Returns the PKey value for the specified PKey index, the device as
 *      specified by IBT HCA Handle.
 */
ibt_status_t
ibt_index2pkey(ibt_hca_hdl_t hca_hdl, uint8_t port_num, uint16_t pkey_ix,
    ib_pkey_t *pkey)
{
	ibt_status_t		retval;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_index2pkey(%p, %d, %d)",
	    hca_hdl, port_num, pkey_ix);

	mutex_enter(&ibtl_clnt_list_mutex);
	retval = ibtl_index2pkey(hca_hdl->ha_hca_devp, port_num, pkey_ix, pkey);
	mutex_exit(&ibtl_clnt_list_mutex);

	return (retval);
}

/*
 * Function:
 *      ibt_index2pkey_byguid
 * Input:
 *      hca_guid     - The HCA's node GUID.
 *      port_num     - The HCA port
 *      pkey_ix      - The input PKey index, whose PKey we are interested in.
 * Output:
 *      pkey         - The returned PKey value, for the specified index.
 * Returns:
 *      IBT_SUCCESS/IBT_PKEY_IX_ILLEGAL/IBT_PKEY_IX_INVALID/
 *	IBT_HCA_PORT_INVALID/IBT_HCA_INVALID
 * Description:
 *      Returns the PKey Index for the specified PKey, the device as specified
 *      by HCA GUID Info.
 */
ibt_status_t
ibt_index2pkey_byguid(ib_guid_t hca_guid, uint8_t port_num, uint16_t pkey_ix,
    ib_pkey_t *pkey)
{
	ibt_status_t		retval;
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info */

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_index2pkey_byguid(%llX, %d, %d)",
	    hca_guid, port_num, pkey_ix);

	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		IBTF_DPRINTF_L2(ibtf_hca, "ibt_index2pkey_byguid: "
		    "Invalid HCA GUID 0x%llx", hca_guid);
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_HCA_INVALID);
	}
	retval = ibtl_index2pkey(hca_devp, port_num, pkey_ix, pkey);
	mutex_exit(&ibtl_clnt_list_mutex);

	return (retval);
}


_NOTE(SCHEME_PROTECTS_DATA("client managed", ibtl_hca_s::ha_clnt_private))

/*
 * Function:
 *      ibt_set_hca_private
 * Input:
 *      hca_hdl		The ibt_hca_hdl_t of the opened HCA.
 *      clnt_private	The client private data.
 * Output:
 *	none.
 * Returns:
 *      none
 * Description:
 *      Sets the client private data.
 */
void
ibt_set_hca_private(ibt_hca_hdl_t hca_hdl, void *clnt_private)
{
	hca_hdl->ha_clnt_private = clnt_private;
}


/*
 * Function:
 *      ibt_get_hca_private
 * Input:
 *      hca_hdl		The ibt_hca_hdl_t of the opened HCA.
 * Output:
 *      none
 * Returns:
 *      The client private data.
 * Description:
 *      Retrieves the private data from a specified HCA.
 */
void *
ibt_get_hca_private(ibt_hca_hdl_t hca_hdl)
{
	return (hca_hdl->ha_clnt_private);
}

/*
 * Function:
 *	ibt_hca_handle_to_guid
 * Input:
 *	hca		HCA Handle.
 * Output:
 *	none.
 * Returns:
 *	hca_guid	Returned HCA GUID on which the specified Channel is
 *			allocated. Valid if it is non-NULL on return.
 * Description:
 *	A helper function to retrieve HCA GUID for the specified handle.
 */
ib_guid_t
ibt_hca_handle_to_guid(ibt_hca_hdl_t hca)
{
	IBTF_DPRINTF_L3(ibtf_hca, "ibt_hca_handle_to_guid(%p)", hca);
	return (IBTL_HCA2HCAGUID(hca));
}

/*
 * Function:
 *	ibt_hca_guid_to_handle
 * Input:
 *	ibt_hdl		The handle returned to the client by the IBTF from
 *                      an ibt_attach() call.
 *	hca_guid	HCA GUID
 * Output:
 *	hca_hdl		Returned ibt_hca_hdl_t.
 * Returns:
 *      IBT_SUCCESS
 *      IBT_HCA_INVALID
 * Description:
 *	A helper function to retrieve a hca handle from a HCA GUID.
 */
ibt_status_t
ibt_hca_guid_to_handle(ibt_clnt_hdl_t ibt_hdl, ib_guid_t hca_guid,
    ibt_hca_hdl_t *hca_hdl)
{
	ibtl_hca_t  		*hca_infop;
	ibtl_hca_devinfo_t	*hca_devp;		/* HCA Dev Info */
	ibt_status_t		rval = IBT_HCA_INVALID;

	IBTF_DPRINTF_L3(ibtf_hca, "ibt_hca_guid_to_handle(%p, %llX)",
	    ibt_hdl, hca_guid);

	mutex_enter(&ibtl_clnt_list_mutex);

	/*
	 * Get HCA Device Info Structure, referenced by HCA GUID.
	 */
	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		/*
		 * If we are here, then the requested HCA device is not present.
		 * Return the status as Invalid HCA GUID.
		 */
		mutex_exit(&ibtl_clnt_list_mutex);

		IBTF_DPRINTF_L2(ibtf_hca, "ibt_hca_guid_to_handle: "
		    "HCA Device Not Found: Invalid HCA GUID");

		*hca_hdl = NULL;
		return (rval);
	}

	/*
	 * Yes, we found a HCA Device registered with IBTF, which matches with
	 * the requested HCA_GUID.
	 */
	hca_infop = hca_devp->hd_clnt_list;

	while (hca_infop != NULL) {
		if (ibt_hdl == hca_infop->ha_clnt_devp) {
			rval = IBT_SUCCESS;
			break;
		}
		hca_infop = hca_infop->ha_clnt_link;
	}

	mutex_exit(&ibtl_clnt_list_mutex);
	*hca_hdl = hca_infop;
	return (rval);
}
