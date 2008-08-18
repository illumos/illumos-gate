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

#include <sys/ib/ibtl/impl/ibtl.h>
#include <sys/ib/ibtl/impl/ibtl_cm.h>

/*
 * ibtl_cm.c
 *    These routines tie the Communication Manager into IBTL.
 */

/*
 * Globals.
 */
static char 		ibtf_cm[] = "ibtl_cm";
boolean_t		ibtl_fast_gid_cache_valid = B_FALSE;

/*
 * Function:
 *	ibtl_cm_set_chan_private
 * Input:
 *	chan		Channel Handle.
 *	cm_private	CM private data.
 * Output:
 *	none.
 * Returns:
 *	none.
 * Description:
 *	A helper function to store CM's Private data in the specified channel.
 */
void
ibtl_cm_set_chan_private(ibt_channel_hdl_t chan, void *cm_private)
{
	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_set_chan_private(%p, %p)",
	    chan, cm_private);

	mutex_enter(&chan->ch_cm_mutex);
	chan->ch_cm_private = cm_private;
	if (cm_private == NULL)
		cv_signal(&chan->ch_cm_cv);
	mutex_exit(&chan->ch_cm_mutex);
}


/*
 * Function:
 *	ibtl_cm_get_chan_private
 * Input:
 *	chan		Channel Handle.
 * Output:
 *	cm_private_p	The CM private data.
 * Returns:
 *	CM private data.
 * Description:
 *	A helper function to get CM's Private data for the specified channel.
 */
void *
ibtl_cm_get_chan_private(ibt_channel_hdl_t chan)
{
	void *cm_private;

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_chan_private(%p)", chan);
	mutex_enter(&chan->ch_cm_mutex);
	cm_private = chan->ch_cm_private;
#ifndef __lock_lint
	/* IBCM will call the release function if cm_private is non-NULL */
	if (cm_private == NULL)
#endif
		mutex_exit(&chan->ch_cm_mutex);
	return (cm_private);
}

void
ibtl_cm_release_chan_private(ibt_channel_hdl_t chan)
{
#ifndef __lock_lint
	mutex_exit(&chan->ch_cm_mutex);
#endif
}

void
ibtl_cm_wait_chan_private(ibt_channel_hdl_t chan)
{
	mutex_enter(&chan->ch_cm_mutex);
	if (chan->ch_cm_private != NULL)
		cv_wait(&chan->ch_cm_cv, &chan->ch_cm_mutex);
	mutex_exit(&chan->ch_cm_mutex);
	delay(drv_usectohz(50000));
}


/*
 * Function:
 *	ibtl_cm_get_chan_type
 * Input:
 *	chan		Channel Handle.
 * Output:
 *	none.
 * Returns:
 *	Channel transport type.
 * Description:
 *	A helper function to get channel transport type.
 */
ibt_tran_srv_t
ibtl_cm_get_chan_type(ibt_channel_hdl_t chan)
{
	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_chan_type(%p)", chan);

	return (chan->ch_qp.qp_type);
}

/*
 * Function:
 *	ibtl_cm_change_service_cnt
 * Input:
 *	ibt_hdl		Client's IBT Handle.
 *	delta_num_sids	The change in the number of service ids
 *			(positive for ibt_register_service() and
 *			negative fo ibt_service_deregister()).
 */
void
ibtl_cm_change_service_cnt(ibt_clnt_hdl_t ibt_hdl, int delta_num_sids)
{
	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_change_service_cnt(%p. %d)",
	    ibt_hdl, delta_num_sids);

	mutex_enter(&ibtl_clnt_list_mutex);
	if ((delta_num_sids < 0) && (-delta_num_sids > ibt_hdl->clnt_srv_cnt)) {
		IBTF_DPRINTF_L2(ibtf_cm, "ibtl_cm_change_service_cnt: "
		    "ERROR: service registration counter underflow\n"
		    "current count = %d, requested delta = %d",
		    ibt_hdl->clnt_srv_cnt, delta_num_sids);
	}
	ibt_hdl->clnt_srv_cnt += delta_num_sids;
	mutex_exit(&ibtl_clnt_list_mutex);
}


/*
 * Function:
 *	ibtl_cm_get_hca_port
 * Input:
 *	gid		Source GID.
 *	hca_guid	Optional source HCA GUID on which SGID is available.
 *			Ignored if zero.
 * Output:
 *	hca_port	Pointer to ibtl_cm_hca_port_t struct.
 * Returns:
 *	IBT_SUCCESS.
 * Description:
 *	A helper function to get HCA node GUID, Base LID, SGID Index,
 *	port number, LMC and MTU for the specified SGID.
 *	Also filling default SGID, to be used in ibmf_sa_session_open.
 */
ibt_status_t
ibtl_cm_get_hca_port(ib_gid_t gid, ib_guid_t hca_guid,
    ibtl_cm_hca_port_t *hca_port)
{
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info */
	ibt_hca_portinfo_t	*portinfop;
	uint_t			ports, port;
	uint_t			i;
	ib_gid_t		*sgid;
	static ib_gid_t		fast_gid;	/* fast_gid_cache data */
	static uint8_t		fast_sgid_ix;
	static ibt_hca_portinfo_t *fast_portinfop;
	static ib_guid_t	fast_node_guid;
	static ib_guid_t	fast_port_guid;

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_hca_port(%llX:%llX, %llX)",
	    gid.gid_prefix, gid.gid_guid, hca_guid);

	if ((gid.gid_prefix == 0) || (gid.gid_guid == 0)) {
		IBTF_DPRINTF_L2(ibtf_cm, "ibtl_cm_get_hca_port: "
		    "NULL SGID specified.");
		return (IBT_INVALID_PARAM);
	}

	mutex_enter(&ibtl_clnt_list_mutex);

	if ((ibtl_fast_gid_cache_valid == B_TRUE) &&
	    (gid.gid_guid == fast_gid.gid_guid) &&
	    (gid.gid_prefix == fast_gid.gid_prefix)) {

		if ((hca_guid != 0) && (hca_guid != fast_node_guid)) {
			IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_hca_port: "
			    "Mis-match hca_guid v/s sgid combination.");
			mutex_exit(&ibtl_clnt_list_mutex);
			return (IBT_INVALID_PARAM);
		}

		portinfop = fast_portinfop;
		hca_port->hp_base_lid = portinfop->p_base_lid;
		hca_port->hp_port = portinfop->p_port_num;
		hca_port->hp_sgid_ix = fast_sgid_ix;
		hca_port->hp_lmc = portinfop->p_lmc;
		hca_port->hp_mtu = portinfop->p_mtu;
		hca_port->hp_hca_guid = fast_node_guid;
		hca_port->hp_port_guid = fast_port_guid;

		mutex_exit(&ibtl_clnt_list_mutex);

		return (IBT_SUCCESS);
	}

	/* If HCA GUID is specified, then lookup in that device only. */
	if (hca_guid) {
		hca_devp = ibtl_get_hcadevinfo(hca_guid);
	} else {
		hca_devp = ibtl_hca_list;
	}

	while (hca_devp != NULL) {

		ports = hca_devp->hd_hca_attr->hca_nports;
		portinfop = hca_devp->hd_portinfop;

		for (port = 0; port < ports; port++, portinfop++) {
			if (portinfop->p_linkstate != IBT_PORT_ACTIVE)
				continue;
			sgid = &portinfop->p_sgid_tbl[0];
			for (i = 0; i < portinfop->p_sgid_tbl_sz; i++, sgid++) {
				if ((gid.gid_guid != sgid->gid_guid) ||
				    (gid.gid_prefix != sgid->gid_prefix))
					continue;

				/*
				 * Found the matching GID.
				 */
				ibtl_fast_gid_cache_valid = B_TRUE;
				fast_gid = gid;
				fast_portinfop = portinfop;
				fast_node_guid = hca_port->hp_hca_guid =
				    hca_devp->hd_hca_attr->hca_node_guid;
				fast_sgid_ix = hca_port->hp_sgid_ix = i;
				fast_port_guid =
				    portinfop->p_sgid_tbl[0].gid_guid;
				hca_port->hp_port_guid = fast_port_guid;
				hca_port->hp_base_lid = portinfop->p_base_lid;
				hca_port->hp_port = portinfop->p_port_num;
				hca_port->hp_lmc = portinfop->p_lmc;
				hca_port->hp_mtu = portinfop->p_mtu;

				mutex_exit(&ibtl_clnt_list_mutex);

				return (IBT_SUCCESS);
			}
		}

		/* Asked to look in the specified HCA device only?. */
		if (hca_guid)
			break;

		/* Get next in the list */
		hca_devp = hca_devp->hd_hca_dev_link;
	}

	mutex_exit(&ibtl_clnt_list_mutex);

	/* If we are here, then we failed to get a match, so return error. */
	return (IBT_INVALID_PARAM);
}


static ibt_status_t
ibtl_cm_get_cnt(ibt_path_attr_t *attr, ibt_path_flags_t flags,
    ibtl_cm_port_list_t *plistp, uint_t *count)
{
	ibtl_hca_devinfo_t	*hdevp;
	ibt_hca_portinfo_t	*pinfop;
	ib_guid_t		hca_guid, tmp_hca_guid = 0;
	ib_gid_t		gid;
	uint_t			pcount = 0, tmp_pcount = 0;
	uint_t			cnt = *count;
	ibt_status_t		retval = IBT_SUCCESS;
	uint_t			i, j;

	*count = 0;

	/* If HCA GUID is specified, then lookup in that device only. */
	if (attr->pa_hca_guid) {
		hdevp = ibtl_get_hcadevinfo(attr->pa_hca_guid);
	} else {
		hdevp = ibtl_hca_list;
	}

	while (hdevp != NULL) {
		hca_guid = hdevp->hd_hca_attr->hca_node_guid;

		if ((flags & IBT_PATH_APM) &&
		    (!(hdevp->hd_hca_attr->hca_flags &
		    IBT_HCA_AUTO_PATH_MIG))) {

			IBTF_DPRINTF_L2(ibtf_cm, "ibtl_cm_get_cnt: "
			    "HCA (%llX) - APM NOT SUPPORTED ", hca_guid);

			retval = IBT_APM_NOT_SUPPORTED;

			if (attr->pa_hca_guid)
				break;
			goto search_next;
		}

		for (i = 0; i < hdevp->hd_hca_attr->hca_nports; i++) {

			if ((attr->pa_hca_port_num) &&
			    (attr->pa_hca_port_num != (i + 1))) {
				IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_cnt: "
				    "Asked only on Port# %d, so skip this "
				    "port(%d)", attr->pa_hca_port_num, (i + 1));
				continue;
			}
			pinfop = hdevp->hd_portinfop + i;

			if (pinfop->p_linkstate != IBT_PORT_ACTIVE) {
				retval = IBT_HCA_PORT_NOT_ACTIVE;
				continue;
			}
			if (attr->pa_mtu.r_mtu) {
				if ((attr->pa_mtu.r_selector == IBT_GT) &&
				    (attr->pa_mtu.r_mtu >= pinfop->p_mtu))
					continue;
				else if ((attr->pa_mtu.r_selector == IBT_EQU) &&
				    (attr->pa_mtu.r_mtu > pinfop->p_mtu))
					continue;
			}

			if ((flags & IBT_PATH_APM) && (!attr->pa_hca_guid) &&
			    attr->pa_sgid.gid_prefix &&
			    attr->pa_sgid.gid_guid) {
				for (j = 0; j < pinfop->p_sgid_tbl_sz; j++) {
					gid = pinfop->p_sgid_tbl[j];
					if (gid.gid_prefix && gid.gid_guid) {
						if ((attr->pa_sgid.gid_prefix !=
						    gid.gid_prefix) ||
						    (attr->pa_sgid.gid_guid !=
						    gid.gid_guid)) {
							continue;
						} else {
							attr->pa_hca_guid =
							    hca_guid;
							goto got_apm_hca_info;
						}
					}
				}
				goto search_next;
			}
got_apm_hca_info:
			for (j = 0; j < pinfop->p_sgid_tbl_sz; j++) {
				gid = pinfop->p_sgid_tbl[j];
				if (gid.gid_prefix && gid.gid_guid) {
					if (!(flags & IBT_PATH_APM) &&
					    attr->pa_sgid.gid_prefix &&
					    attr->pa_sgid.gid_guid) {
						if ((attr->pa_sgid.gid_prefix !=
						    gid.gid_prefix) ||
						    (attr->pa_sgid.gid_guid !=
						    gid.gid_guid))
							continue;
					}
					pcount++;
					if (plistp) {
						plistp->p_hca_guid = hca_guid;
						plistp->p_mtu = pinfop->p_mtu;
						plistp->p_base_lid =
						    pinfop->p_base_lid;
						plistp->p_port_num =
						    pinfop->p_port_num;
						plistp->p_sgid_ix = j;
						plistp->p_sgid = gid;
						plistp->p_count = cnt;
						if (hdevp->hd_multism)
							plistp->p_multi |=
							    IBTL_CM_MULTI_SM;

						IBTF_DPRINTF_L3(ibtf_cm,
						    "ibtl_cm_get_cnt: HCA"
						    "(%llX,%d) SGID(%llX:%llX)",
						    plistp->p_hca_guid,
						    plistp->p_port_num,
						    plistp->p_sgid.gid_prefix,
						    plistp->p_sgid.gid_guid);

						plistp++;
					}
				}
			}
		}
		/* Asked to look in the specified HCA device only?. */
		if (attr->pa_hca_guid)
			break;

		if (flags & IBT_PATH_APM) {
			if (pcount == 2) {
				attr->pa_hca_guid = hca_guid;
				break;
			} else if (pcount == 1) {
				if (hdevp->hd_hca_dev_link) {
					tmp_hca_guid = hca_guid;
					tmp_pcount = pcount;
					pcount = 0;
				} else if (tmp_hca_guid) {
					attr->pa_hca_guid = tmp_hca_guid;
				} else {
					attr->pa_hca_guid = hca_guid;
				}
			} else if ((pcount == 0) && (tmp_hca_guid)) {
				attr->pa_hca_guid = tmp_hca_guid;
				pcount = tmp_pcount;
			}
		}
search_next:
		hdevp = hdevp->hd_hca_dev_link;
	}

	*count = pcount;

	if (pcount) {
		retval = IBT_SUCCESS;
	} else {
		IBTF_DPRINTF_L2(ibtf_cm, "ibtl_cm_get_cnt: "
		    "Appropriate Source Points NOT found");
		if (retval == IBT_SUCCESS)
			retval = IBT_NO_HCAS_AVAILABLE;
	}

	return (retval);
}


ibt_status_t
ibtl_cm_get_active_plist(ibt_path_attr_t *attr, ibt_path_flags_t flags,
    ibtl_cm_port_list_t **port_list_p)
{
	ibtl_cm_port_list_t	*p_listp, tmp;
	uint_t			i, j;
	uint_t			count, rcount;
	boolean_t		multi_hca = B_FALSE;
	ibt_status_t		retval = IBT_SUCCESS;

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_active_plist(%p, %X)",
	    attr, flags);

get_plist_start:
	*port_list_p = NULL;

	/* Get "number of active src points" so that we can allocate memory. */
	mutex_enter(&ibtl_clnt_list_mutex);
	retval = ibtl_cm_get_cnt(attr, flags, NULL, &count);
	mutex_exit(&ibtl_clnt_list_mutex);

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_active_plist: Found %d SrcPoint",
	    count);
	if (retval != IBT_SUCCESS)
		return (retval);

	/* Allocate Memory to hold Src Point information. */
	p_listp = kmem_zalloc(count * sizeof (ibtl_cm_port_list_t), KM_SLEEP);

	/*
	 * Verify that the count we got previously is still valid, as we had
	 * dropped mutex to allocate memory. If not, restart the process.
	 */
	mutex_enter(&ibtl_clnt_list_mutex);
	retval = ibtl_cm_get_cnt(attr, flags, NULL, &rcount);
	if (retval != IBT_SUCCESS) {
		mutex_exit(&ibtl_clnt_list_mutex);
		kmem_free(p_listp, count * sizeof (ibtl_cm_port_list_t));
		return (retval);
	} else if (rcount != count) {
		mutex_exit(&ibtl_clnt_list_mutex);
		kmem_free(p_listp, count * sizeof (ibtl_cm_port_list_t));
		goto get_plist_start;
	}

	*port_list_p = p_listp;
	/*
	 * Src count hasn't changed, still holding the lock fill-in the
	 * required source point information.
	 */
	retval = ibtl_cm_get_cnt(attr, flags, p_listp, &rcount);
	mutex_exit(&ibtl_clnt_list_mutex);
	if (retval != IBT_SUCCESS) {
		kmem_free(p_listp, count * sizeof (ibtl_cm_port_list_t));
		*port_list_p = NULL;
		return (retval);
	}

	p_listp = *port_list_p;

	_NOTE(NO_COMPETING_THREADS_NOW)

	for (i = 0; i < count - 1; i++) {
		for (j = 0; j < count - 1 - i; j++) {
			if (p_listp[j].p_hca_guid != p_listp[j+1].p_hca_guid) {
				multi_hca = B_TRUE;
				break;
			}
		}
		if (multi_hca == B_TRUE)
			break;
	}

	if (multi_hca == B_TRUE)
		for (i = 0; i < count; i++)
			p_listp[i].p_multi |= IBTL_CM_MULTI_HCA;

	/*
	 * Sort (bubble sort) the list based on MTU quality (higher on top).
	 * Sorting is only performed, if IBT_PATH_AVAIL is set.
	 */
	if (((attr->pa_mtu.r_selector == IBT_GT) || (flags & IBT_PATH_AVAIL)) &&
	    (!(flags & IBT_PATH_APM))) {
		for (i = 0; i < count - 1; i++) {
			for (j = 0; j < count - 1 - i; j++) {
				if (p_listp[j].p_mtu < p_listp[j+1].p_mtu) {
					tmp = p_listp[j];
					p_listp[j] = p_listp[j+1];
					p_listp[j+1] = tmp;
				}
			}
		}
	}

	if ((p_listp->p_multi & IBTL_CM_MULTI_HCA) &&
	    (flags & IBT_PATH_AVAIL) && (!(flags & IBT_PATH_APM))) {
		/* Avoid having same HCA next to each other in the list. */
		for (i = 0; i < count - 1; i++) {
			for (j = 0; j < (count - 1 - i); j++) {
				if ((p_listp[j].p_hca_guid ==
				    p_listp[j+1].p_hca_guid) &&
				    (j+2 < count)) {
					tmp = p_listp[j+1];
					p_listp[j+1] = p_listp[j+2];
					p_listp[j+2] = tmp;
				}
			}
		}
	}

	/*
	 * If SGID is specified, then make sure that SGID info is first
	 * in the array.
	 */
	if (attr->pa_sgid.gid_guid && (p_listp->p_count > 1) &&
	    (p_listp[0].p_sgid.gid_guid != attr->pa_sgid.gid_guid)) {
		for (i = 1; i < count; i++) {
			if (p_listp[i].p_sgid.gid_guid ==
			    attr->pa_sgid.gid_guid) {
				tmp = p_listp[i];
				p_listp[i] = p_listp[0];
				p_listp[0] = tmp;
			}
		}
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW)
#endif

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_active_plist: "
	    "Returned <%d> entries @0x%p", count, *port_list_p);

	return (retval);
}


void
ibtl_cm_free_active_plist(ibtl_cm_port_list_t *plist)
{
	int count;

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_free_active_plist(%p)", plist);

	if (plist != NULL) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*plist))
		count = plist->p_count;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*plist))

		kmem_free(plist, count * sizeof (ibtl_cm_port_list_t));
	}
}

/*
 * Function:
 *	ibtl_cm_get_1st_full_pkey_ix
 * Input:
 *	hca_guid	HCA GUID.
 *	port		Port Number.
 * Output:
 *	None.
 * Returns:
 *	P_Key Index of the first full member available from the P_Key table
 *	of the specified HCA<->Port.
 * Description:
 *	A helper function to get P_Key Index of the first full member P_Key
 *	available on the specified HCA and Port combination.
 */
uint16_t
ibtl_cm_get_1st_full_pkey_ix(ib_guid_t hca_guid, uint8_t port)
{
	ibtl_hca_devinfo_t	*hca_devp;	/* HCA Dev Info */
	uint16_t		pkey_ix = 0;

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_1st_full_pkey_ix(%llX, %d)",
	    hca_guid, port);

	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_get_hcadevinfo(hca_guid);

	if ((hca_devp != NULL) && (port <= hca_devp->hd_hca_attr->hca_nports) &&
	    (port != 0)) {
		pkey_ix = hca_devp->hd_portinfop[port - 1].p_def_pkey_ix;
	} else {
		IBTF_DPRINTF_L2(ibtf_cm, "ibtl_cm_get_1st_full_pkey_ix: "
		    "Invalid HCA (%llX), Port (%d) specified.", hca_guid, port);
	}
	mutex_exit(&ibtl_clnt_list_mutex);

	return (pkey_ix);
}


ibt_status_t
ibtl_cm_get_local_comp_gids(ib_guid_t hca_guid, ib_gid_t gid, ib_gid_t **gids_p,
    uint_t *num_gids_p)
{
	ibtl_hca_devinfo_t	*hdevp;	/* HCA Dev Info */
	ibt_hca_portinfo_t	*pinfop;
	ib_gid_t		sgid;
	ib_gid_t		*gidp = NULL;
	int			i, j, k;
	int			count = 0;
	int			gid_specified;

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_local_comp_gids(%llX, %llX:%llX)",
	    hca_guid, gid.gid_prefix, gid.gid_guid);

	mutex_enter(&ibtl_clnt_list_mutex);
	hdevp = ibtl_get_hcadevinfo(hca_guid);

	if (hdevp == NULL) {
		IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_get_local_comp_gids: ",
		    "NO HCA (%llX) availble", hca_guid);
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_NO_HCAS_AVAILABLE);
	}

	if (gid.gid_prefix && gid.gid_guid)
		gid_specified = 1;
	else
		gid_specified = 0;

	for (i = 0; i < hdevp->hd_hca_attr->hca_nports; i++) {
		pinfop = hdevp->hd_portinfop + i;

		if (pinfop->p_linkstate != IBT_PORT_ACTIVE)
			continue;

		for (j = 0; j < pinfop->p_sgid_tbl_sz; j++) {
			sgid = pinfop->p_sgid_tbl[j];
			if (sgid.gid_prefix && sgid.gid_guid) {
				if (gid_specified &&
				    ((gid.gid_prefix == sgid.gid_prefix) &&
				    (gid.gid_guid == sgid.gid_guid))) {
					/*
					 * Don't return the input specified
					 * GID
					 */
					continue;
				}
				count++;
			}
		}
	}

	if (count == 0) {
		IBTF_DPRINTF_L2(ibtf_cm, "ibtl_cm_get_local_comp_gids: "
		    "Companion GIDs not available");
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_GIDS_NOT_FOUND);
	}

	gidp = kmem_zalloc(count * sizeof (ib_gid_t), KM_SLEEP);
	*num_gids_p = count;
	*gids_p = gidp;
	k = 0;

	for (i = 0; i < hdevp->hd_hca_attr->hca_nports; i++) {
		pinfop = hdevp->hd_portinfop + i;

		if (pinfop->p_linkstate != IBT_PORT_ACTIVE)
			continue;

		for (j = 0; j < pinfop->p_sgid_tbl_sz; j++) {
			sgid = pinfop->p_sgid_tbl[j];
			if (sgid.gid_prefix && sgid.gid_guid) {
				if (gid_specified &&
				    ((gid.gid_prefix == sgid.gid_prefix) &&
				    (gid.gid_guid == sgid.gid_guid)))
					continue;

				gidp[k].gid_prefix = sgid.gid_prefix;
				gidp[k].gid_guid = sgid.gid_guid;

				IBTF_DPRINTF_L3(ibtf_cm,
				    "ibtl_cm_get_local_comp_gids: GID[%d]="
				    "%llX:%llX", k, gidp[k].gid_prefix,
				    gidp[k].gid_guid);
				k++;
				if (k == count)
					break;
			}
		}
		if (k == count)
			break;
	}
	mutex_exit(&ibtl_clnt_list_mutex);

	return (IBT_SUCCESS);
}


int
ibtl_cm_is_multi_sm(ib_guid_t hca_guid)
{
	ibtl_hca_devinfo_t	*hdevp;	/* HCA Dev Info */
	uint_t			multi_sm;

	mutex_enter(&ibtl_clnt_list_mutex);
	hdevp = ibtl_get_hcadevinfo(hca_guid);
	if (hdevp == NULL) {
		IBTF_DPRINTF_L2(ibtf_cm, "ibtl_cm_is_multi_sm: NO HCA (%llX) "
		    "availble", hca_guid);
		mutex_exit(&ibtl_clnt_list_mutex);
		return (-1);
	}
	multi_sm = hdevp->hd_multism;
	mutex_exit(&ibtl_clnt_list_mutex);

	IBTF_DPRINTF_L3(ibtf_cm, "ibtl_cm_is_multi_sm(%llX): %d", hca_guid,
	    multi_sm);

	return (multi_sm);
}
