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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/systm.h>
#include <sys/sunndi.h>
#include <sys/sunmdi.h>
#include <sys/ib/ibtl/impl/ibtl.h>
#include <sys/ib/ibtl/impl/ibtl_ibnex.h>

/*
 * ibtl_ibnex.c
 *    These routines tie the Device Manager into IBTL.
 *
 *    ibt_reprobe_dev which can be called by IBTF clients.
 *    This results in calls to IBnexus callback.
 */

/*
 * Globals.
 */
static char		ibtl_ibnex[] = "ibtl_ibnex";
ibtl_ibnex_callback_t	ibtl_ibnex_callback_routine = NULL;

/*
 * Function:
 *	ibtl_ibnex_get_hca_info
 * Input:
 *	hca_guid	- The HCA's node GUID.
 *	flag		- Tells what to do
 *			IBTL_IBNEX_LIST_CLNTS_FLAG - Build a NVLIST containing
 *						client's names, their AP_IDs and
 *						alternate_HCA information.
 *						(-x list_clients option)
 *			IBTL_IBNEX_UNCFG_CLNTS_FLAG - Build a NVLIST containing
 *						clients' devpaths and their
 *						AP_IDs. (-x unconfig_clients)
 *	callback	- Callback function to get ap_id from ib(4D)
 * Output:
 *	buffer		- The information is returned in this buffer
 *      bufsiz		- The size of the information buffer
 * Returns:
 *	IBT_SUCCESS/IBT_HCA_INVALID/IBT_INVALID_PARAM
 * Description:
 *      For a given HCA node GUID it figures out the registered clients
 *	(ie. ones who called ibt_open_hca(9f) on this GUID) and creates
 *	a NVL packed buffer (of client names/ap_ids or devpaths) and returns
 *	it. If flag is not specified, then an error is returned.
 */
ibt_status_t
ibtl_ibnex_get_hca_info(ib_guid_t hca_guid, int flag, char **buffer,
    size_t *bufsiz, void (*callback)(dev_info_t *, char **))
{
	char			*node_name;
	char			*ret_apid;
	nvlist_t		*nvl;
	ibtl_hca_t		*ibt_hca;
	ibtl_clnt_t		*clntp;
	dev_info_t		*child;
	dev_info_t		*parent;
	ibtl_hca_devinfo_t	*hca_devp;

	IBTF_DPRINTF_L3(ibtl_ibnex, "ibtl_ibnex_get_hca_info: "
	    "GUID  0x%llX, flag = 0x%x", hca_guid, flag);

	*buffer = NULL;
	*bufsiz = 0;

	/* verify that valid "flag" is passed */
	if (flag != IBTL_IBNEX_LIST_CLNTS_FLAG &&
	    flag != IBTL_IBNEX_UNCFG_CLNTS_FLAG) {
		return (IBT_INVALID_PARAM);
	}

	mutex_enter(&ibtl_clnt_list_mutex);

	if ((hca_devp = ibtl_get_hcadevinfo(hca_guid)) == NULL) {
		mutex_exit(&ibtl_clnt_list_mutex);

		/*
		 * If we are here, then the requested HCA device is not
		 * present. Return the status as Invalid HCA GUID.
		 */
		IBTF_DPRINTF_L2(ibtl_ibnex, "ibtl_ibnex_get_hca_info: "
		    "HCA Not Found, Invalid HCA GUID 0x%llX", hca_guid);
		return (IBT_HCA_INVALID);
	}

	/* Walk the client list */
	ibt_hca = hca_devp->hd_clnt_list;
	(void) nvlist_alloc(&nvl, 0, KM_SLEEP);

	/* Allocate memory for ret_apid, instead of using stack */
	ret_apid = kmem_alloc(IBTL_IBNEX_APID_LEN, KM_SLEEP);

	while (ibt_hca != NULL) {
		clntp = ibt_hca->ha_clnt_devp;
		child = clntp->clnt_dip;
		IBTF_DPRINTF_L4(ibtl_ibnex, "ibtl_ibnex_get_hca_info: "
		    "Client = %s", clntp->clnt_modinfop->mi_clnt_name);

		if (flag == IBTL_IBNEX_LIST_CLNTS_FLAG) {
			(void) nvlist_add_string(nvl, "Client",
			    clntp->clnt_modinfop->mi_clnt_name);

			/*
			 * Always check, first, if this client exists
			 * under this HCA anymore? If not, continue.
			 */
			if (clntp->clnt_hca_list == NULL) {
				(void) nvlist_add_string(nvl, "Alt_HCA", "no");
				(void) nvlist_add_string(nvl, "ApID", "-");
				ibt_hca = ibt_hca->ha_clnt_link;
				continue;
			}

			/* Check if this client has more than one HCAs */
			if (clntp->clnt_hca_list->ha_hca_link == NULL)
				(void) nvlist_add_string(nvl, "Alt_HCA", "no");
			else
				(void) nvlist_add_string(nvl, "Alt_HCA", "yes");

			if (child == NULL) {
				(void) nvlist_add_string(nvl, "ApID", "-");
				ibt_hca = ibt_hca->ha_clnt_link;
				continue;
			}

			/*
			 * All IB clients (IOC, VPPA, Port, Pseudo etc.)
			 * need to be looked at. The parent of IOC nodes
			 * is "ib" nexus and node-name is "ioc". "VPPA/Port"s
			 * should have HCA as parent and node-name is "ibport".
			 * HCA validity is checked by looking at parent's "dip"
			 * and the dip saved in the ibtl_hca_devinfo_t.
			 * NOTE: We only want to list this HCA's IB clients.
			 * All others clients are ignored.
			 */
			parent = ddi_get_parent(child);
			if (parent == NULL || /* No parent? */
			    ddi_get_parent_data(child) == NULL) {
				(void) nvlist_add_string(nvl, "ApID", "-");
				ibt_hca = ibt_hca->ha_clnt_link;
				continue;
			}

			node_name = ddi_node_name(child);
			if ((strcmp(ddi_node_name(parent), "ib") == 0) ||
			    ((hca_devp->hd_hca_dip == parent) &&
			    (strncmp(node_name, IBNEX_IBPORT_CNAME, 6) == 0))) {
				ASSERT(callback != NULL);
				/*
				 * Callback is invoked to figure out the
				 * ap_id string.
				 */
				callback(child, &ret_apid);
				(void) nvlist_add_string(nvl, "ApID", ret_apid);
			} else {
				(void) nvlist_add_string(nvl, "ApID", "-");
			}

		} else if (flag == IBTL_IBNEX_UNCFG_CLNTS_FLAG) {
			char		path[MAXPATHLEN];

			if (child == NULL) {
				IBTF_DPRINTF_L4(ibtl_ibnex,
				    "ibtl_ibnex_get_hca_info: No dip exists");
				ibt_hca = ibt_hca->ha_clnt_link;
				continue;
			}

			/*
			 * if the child has a alternate HCA then skip it
			 */
			if (clntp->clnt_hca_list->ha_hca_link) {
				IBTF_DPRINTF_L4(ibtl_ibnex,
				    "ibtl_ibnex_get_hca_info: Alt HCA exists");
				ibt_hca = ibt_hca->ha_clnt_link;
				continue;
			}

			/*
			 * See earlier comments on how to check if a client
			 * is IOC, VPPA, Port or a Pseudo node.
			 */
			parent = ddi_get_parent(child);
			if (parent == NULL || /* No parent? */
			    ddi_get_parent_data(child) == NULL) {
				IBTF_DPRINTF_L4(ibtl_ibnex,
				    "ibtl_ibnex_get_hca_info: no parent");
				ibt_hca = ibt_hca->ha_clnt_link;
				continue;
			}

			node_name = ddi_node_name(child);
			if ((strcmp(ddi_node_name(parent), "ib") == 0) ||
			    ((hca_devp->hd_hca_dip == parent) &&
			    (strncmp(node_name, IBNEX_IBPORT_CNAME, 6) == 0))) {
				ASSERT(callback != NULL);
				/*
				 * Callback is invoked to figure out the
				 * ap_id string.
				 */
				callback(child, &ret_apid);
				(void) nvlist_add_string(nvl, "ApID", ret_apid);

				/*
				 * ddi_pathname() doesn't supply /devices,
				 * so we do
				 */
				(void) strcpy(path, "/devices");
				(void) ddi_pathname(child, path + strlen(path));
				IBTF_DPRINTF_L4(ibtl_ibnex,
				    "ibtl_ibnex_get_hca_info: "
				    "device path = %s", path);

				if (nvlist_add_string(nvl, "devpath", path)) {
					IBTF_DPRINTF_L2(ibtl_ibnex,
					    "ibtl_ibnex_get_hca_info: "
					    "failed to fill in path %s", path);
					mutex_exit(&ibtl_clnt_list_mutex);
					nvlist_free(nvl);
					kmem_free(ret_apid,
					    IBTL_IBNEX_APID_LEN);
					return (ibt_get_module_failure(
					    IBT_FAILURE_IBTL, 0));
				}
			} /* end of if */
		} /* end of while */

		ibt_hca = ibt_hca->ha_clnt_link;
	} /* End of while */
	mutex_exit(&ibtl_clnt_list_mutex);

	kmem_free(ret_apid, IBTL_IBNEX_APID_LEN);

	/* Pack all data into "buffer" */
	if (nvlist_pack(nvl, buffer, bufsiz, NV_ENCODE_NATIVE, KM_SLEEP)) {
		IBTF_DPRINTF_L2(ibtl_ibnex, "ibtl_ibnex_get_hca_info: "
		    "nvlist_pack failed");
		nvlist_free(nvl);
		return (ibt_get_module_failure(IBT_FAILURE_IBTL, 0));
	}

	IBTF_DPRINTF_L4(ibtl_ibnex, "ibtl_ibnex_get_hca_info: size = %x",
	    *bufsiz);
	nvlist_free(nvl);
	return (IBT_SUCCESS);
}


/*
 * Function:
 *	ibtl_ibnex_register_callback()
 * Input:
 *	ibnex_cb	- IB nexus driver callback routine
 * Output:
 *	none
 * Returns:
 *	none
 * Description:
 *	Register a callback routine for IB nexus driver
 */
void
ibtl_ibnex_register_callback(ibtl_ibnex_callback_t ibnex_cb)
{
	IBTF_DPRINTF_L5(ibtl_ibnex, "ibtl_ibnex_register_callback:");

	mutex_enter(&ibtl_clnt_list_mutex);
	ibtl_ibnex_callback_routine = ibnex_cb;
	mutex_exit(&ibtl_clnt_list_mutex);
}

/*
 * Function:
 *	ibtl_ibnex_unregister_callback()
 * Input:
 *	none
 * Output:
 *	none
 * Returns:
 *	none
 * Description:
 *	Un-register a callback routine for IB nexus driver
 */
void
ibtl_ibnex_unregister_callback()
{
	IBTF_DPRINTF_L5(ibtl_ibnex, "ibtl_ibnex_unregister_callback: ibnex cb");

	mutex_enter(&ibtl_clnt_list_mutex);
	ibtl_ibnex_callback_routine = NULL;
	mutex_exit(&ibtl_clnt_list_mutex);
}


/*
 * Function:
 *	ibtl_ibnex_hcadip2guid
 * Input:
 *	dev_info_t	- The "dip" of this HCA
 * Output:
 *	hca_guid	- The HCA's node GUID.
 * Returns:
 *	"HCA GUID" on SUCCESS, NULL on FAILURE
 * Description:
 *      For a given HCA node GUID it figures out the HCA GUID
 *	and returns it. If not found, NULL is returned.
 */
ib_guid_t
ibtl_ibnex_hcadip2guid(dev_info_t *hca_dip)
{
	ib_guid_t		hca_guid = 0LL;
	ibtl_hca_devinfo_t	*hca_devp;

	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_hca_list;

	while (hca_devp) {
		if (hca_devp->hd_hca_dip == hca_dip) {
			hca_guid = hca_devp->hd_hca_attr->hca_node_guid;
			break;
		}
		hca_devp = hca_devp->hd_hca_dev_link;
	}
	mutex_exit(&ibtl_clnt_list_mutex);
	IBTF_DPRINTF_L4(ibtl_ibnex, "ibtl_ibnex_hcadip_guid: hca_guid 0x%llX",
	    hca_guid);
	return (hca_guid);
}


/*
 * Function:
 *	ibtl_ibnex_hcaguid2dip
 * Input:
 *	hca_guid	- The HCA's node GUID.
 * Output:
 *	dev_info_t	- The "dip" of this HCA
 * Returns:
 *	"dip" on SUCCESS, NULL on FAILURE
 * Description:
 *      For a given HCA node GUID it figures out the "dip"
 *	and returns it. If not found, NULL is returned.
 */
dev_info_t *
ibtl_ibnex_hcaguid2dip(ib_guid_t hca_guid)
{
	dev_info_t		*dip = NULL;
	ibtl_hca_devinfo_t	*hca_devp;

	IBTF_DPRINTF_L4(ibtl_ibnex, "ibtl_ibnex_hcaguid2dip:");

	mutex_enter(&ibtl_clnt_list_mutex);
	hca_devp = ibtl_hca_list;

	while (hca_devp) {
		if (hca_devp->hd_hca_attr->hca_node_guid == hca_guid) {
			dip = hca_devp->hd_hca_dip;
			break;
		}
		hca_devp = hca_devp->hd_hca_dev_link;
	}
	mutex_exit(&ibtl_clnt_list_mutex);
	return (dip);
}


/*
 * Function:
 *	ibtl_ibnex_get_hca_verbose_data
 * Input:
 *	hca_guid	- The HCA's node GUID.
 * Output:
 *	buffer		- The information is returned in this buffer
 *      bufsiz		- The size of the information buffer
 * Returns:
 *	IBT_SUCCESS/IBT_HCA_INVALID
 * Description:
 *      For a given HCA node GUID it figures out the verbose listing display.
 */
ibt_status_t
ibtl_ibnex_get_hca_verbose_data(ib_guid_t hca_guid, char **buffer,
    size_t *bufsiz)
{
	char			path[IBTL_IBNEX_STR_LEN];
	char			tmp[MAXPATHLEN];
	uint_t			ii;
	ibt_hca_portinfo_t	*pinfop;
	ibtl_hca_devinfo_t	*hca_devp;

	IBTF_DPRINTF_L3(ibtl_ibnex, "ibtl_ibnex_get_hca_verbose_data: "
	    "HCA GUID 0x%llX", hca_guid);

	*buffer = NULL;
	*bufsiz = 0;

	mutex_enter(&ibtl_clnt_list_mutex);
	if ((hca_devp = ibtl_get_hcadevinfo(hca_guid)) == NULL) {
		mutex_exit(&ibtl_clnt_list_mutex);

		/*
		 * If we are here, then the requested HCA device is not
		 * present. Return the status as Invalid HCA GUID.
		 */
		IBTF_DPRINTF_L2(ibtl_ibnex, "ibtl_ibnex_get_hca_verbose_data: "
		    "HCA Not Found, Invalid HCA GUID");
		return (IBT_HCA_INVALID);
	}

	(void) snprintf(tmp, MAXPATHLEN, "VID: 0x%x, PID: 0x%x, #ports: 0x%x",
	    hca_devp->hd_hca_attr->hca_vendor_id,
	    hca_devp->hd_hca_attr->hca_device_id,
	    hca_devp->hd_hca_attr->hca_nports);

	pinfop = hca_devp->hd_portinfop;
	for (ii = 0; ii < hca_devp->hd_hca_attr->hca_nports; ii++) {
		(void) snprintf(path, IBTL_IBNEX_STR_LEN,
		    ", port%d GUID: 0x%llX", ii + 1,
		    (longlong_t)pinfop[ii].p_sgid_tbl->gid_guid);
		(void) strcat(tmp, path);
	}
	mutex_exit(&ibtl_clnt_list_mutex);

	*bufsiz =  strlen(tmp);
	*buffer = kmem_alloc(*bufsiz, KM_SLEEP);
	(void) strncpy(*buffer, tmp, *bufsiz);

	IBTF_DPRINTF_L4(ibtl_ibnex, "ibtl_ibnex_get_hca_verbose_data: "
	    "data = %s, size = 0x%x", *buffer, *bufsiz);
	return (IBT_SUCCESS);
}

/*
 * Function:
 *	ibt_reprobe_dev()
 * Input:
 *	dev_info_t	*dip
 * Output:
 *	none
 * Returns:
 *      Return value from IBnexus callback handler
 *		IBT_ILLEGAL_OP if IBnexus callback is not installed.
 * Description:
 *		This function passes the IBTF client's "reprobe device
 *		properties" request to IBnexus. See ibt_reprobe_dev(9f)
 *		for details.
 */
ibt_status_t
ibt_reprobe_dev(dev_info_t *dip)
{
	ibt_status_t		rv;
	ibtl_ibnex_cb_args_t	cb_args;

	if (dip == NULL)
		return (IBT_NOT_SUPPORTED);

	/*
	 * Restricting the reprobe request to the children of
	 * ibnexus. Note the IB_CONF_UPDATE_EVENT DDI event can
	 * be subscribed by any device on the IBnexus device tree.
	 */
	if (strcmp(ddi_node_name(ddi_get_parent(dip)), "ib") != 0)
		return (IBT_NOT_SUPPORTED);

	/* Reprobe for IOC nodes only */
	if (strncmp(ddi_node_name(dip), IBNEX_IBPORT_CNAME, 6) == 0)
		return (IBT_NOT_SUPPORTED);

	cb_args.cb_flag = IBTL_IBNEX_REPROBE_DEV_REQ;
	cb_args.cb_dip = dip;
	mutex_enter(&ibtl_clnt_list_mutex);
	if (ibtl_ibnex_callback_routine) {
		rv = (*ibtl_ibnex_callback_routine)(&cb_args);
		mutex_exit(&ibtl_clnt_list_mutex);
		return (rv);
	}
	mutex_exit(&ibtl_clnt_list_mutex);

	/* Should -not- come here */
	IBTF_DPRINTF_L2("ibtl", "ibt_reprobe_dev: ibnex not registered!!");
	return (IBT_ILLEGAL_OP);
}


/*
 * Function:
 *	ibtl_ibnex_valid_hca_parent
 * Input:
 *	pdip		- The parent dip from client's child dev_info_t
 * Output:
 *	NONE
 * Returns:
 *	IBT_SUCCESS/IBT_NO_HCAS_AVAILABLE
 * Description:
 *	For a given pdip, of Port/VPPA devices, match it against all the
 *	registered HCAs's dip.  If match found return IBT_SUCCESS,
 *	else IBT_NO_HCAS_AVAILABLE.
 *
 *	For IOC/Pseudo devices check if the given pdip is that of
 *	the ib(4D) nexus or that of the eoib(4D) nexus. If yes
 *	return IBT_SUCCESS, else IBT_NO_HCAS_AVAILABLE.
 */
ibt_status_t
ibtl_ibnex_valid_hca_parent(dev_info_t *pdip)
{
	ibtl_hca_devinfo_t	*hca_devp;

	IBTF_DPRINTF_L4(ibtl_ibnex, "ibtl_ibnex_valid_hca_parent: pdip %p",
	    pdip);

	/* For Pseudo devices and IOCs */
	if (strncmp(ddi_node_name(pdip), "ib", 2) == 0 ||
	    strncmp(ddi_node_name(pdip), "eibnx", 5) == 0) {
		return (IBT_SUCCESS);
	} else {
		/* For Port devices and VPPAs */
		mutex_enter(&ibtl_clnt_list_mutex);
		hca_devp = ibtl_hca_list;
		while (hca_devp) {
			if (hca_devp->hd_hca_dip == pdip) {
				mutex_exit(&ibtl_clnt_list_mutex);
				return (IBT_SUCCESS);
			}
			hca_devp = hca_devp->hd_hca_dev_link;
		}
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_NO_HCAS_AVAILABLE);
	}
}

/*
 * Function:
 *	ibtl_ibnex_phci_register
 * Input:
 *	hca_dip		- The HCA dip
 * Output:
 *	NONE
 * Returns:
 *	IBT_SUCCESS/IBT_FAILURE
 * Description:
 *	Register the HCA dip as the MPxIO PCHI.
 */
ibt_status_t
ibtl_ibnex_phci_register(dev_info_t *hca_dip)
{
	/* Register the with MPxIO as PHCI */
	if (mdi_phci_register(MDI_HCI_CLASS_IB, hca_dip, 0) !=
	    MDI_SUCCESS) {
		return (IBT_FAILURE);
	}
	return (IBT_SUCCESS);
}

/*
 * Function:
 *	ibtl_ibnex_phci_unregister
 * Input:
 *	hca_dip		- The HCA dip
 * Output:
 *	NONE
 * Returns:
 *	IBT_SUCCESS/IBT_FAILURE
 * Description:
 *	Free up any pending MPxIO Pathinfos and unregister the HCA dip as the
 *	MPxIO PCHI.
 */
ibt_status_t
ibtl_ibnex_phci_unregister(dev_info_t *hca_dip)
{
	mdi_pathinfo_t *pip = NULL;
	dev_info_t *vdip = 0;

	/*
	 * Should free all the Pathinfos associated with the HCA pdip before
	 * unregistering the PHCI.
	 *
	 * mdi_pi_free will call ib_vhci_pi_uninit() callbackfor each PI where
	 * the ibnex internal datastructures (ibnex_node_data) will have to be
	 * cleaned up if needed.
	 */
	vdip = mdi_devi_get_vdip(hca_dip);
	ndi_devi_enter(vdip);
	ndi_devi_enter(hca_dip);
	while (pip = mdi_get_next_client_path(hca_dip, NULL)) {
		if (mdi_pi_free(pip, 0) == MDI_SUCCESS) {
			continue;
		}
		ndi_devi_exit(hca_dip);
		ndi_devi_exit(vdip);
		IBTF_DPRINTF_L1(ibtl_ibnex, "ibtl_ibnex_phci_unregister: "
		    "mdi_pi_free failed");
		return (IBT_FAILURE);
	}
	ndi_devi_exit(hca_dip);
	ndi_devi_exit(vdip);

	if (mdi_phci_unregister(hca_dip, 0) != MDI_SUCCESS) {
		IBTF_DPRINTF_L1(ibtl_ibnex, "ibtl_ibnex_phci_unregister: PHCI "
		    "unregister failed");
		return (IBT_FAILURE);
	}
	return (IBT_SUCCESS);
}

/*
 * Function:
 *	ibtl_ibnex_query_hca_byguid
 * Input:
 *	hca_guid	- The HCA's node GUID.
 *	driver_name_size- size of the caller allocated driver_name buffer
 * Output:
 *	hca_attrs	- caller allocated buffer which will contain
 *			  HCA attributes upon success
 *	driver_name	- caller allocated buffer which will contain
 *			  HCA driver name upon success
 *	driver_instance - HCA driver instance
 *	hca_device_path	- caller allocated buffer of size MAXPATHLEN which
 *			  will contain hca device path upon success.
 * Returns:
 *	IBT_SUCCESS/IBT_FAILURE
 * Description:
 *	Get the HCA attributes, driver name and instance number of the
 *	specified HCA.
 */
ibt_status_t
ibtl_ibnex_query_hca_byguid(ib_guid_t hca_guid, ibt_hca_attr_t *hca_attrs,
    char *driver_name, size_t driver_name_size, int *driver_instance,
    char *hca_device_path)
{
	ibtl_hca_devinfo_t	*hca_devp;

	IBTF_DPRINTF_L4(ibtl_ibnex, "ibtl_ibnex_query_hca_byguid("
	    "hca_guid = 0x%llx, hca_attrs = 0x%p, driver_name = 0x%p, "
	    "driver_name_size = 0x%d, driver_instancep = 0x%p)", hca_guid,
	    hca_attrs, driver_name, (int)driver_name_size, driver_instance);

	mutex_enter(&ibtl_clnt_list_mutex);

	hca_devp = ibtl_get_hcadevinfo(hca_guid);
	if (hca_devp == NULL) {
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_HCA_INVALID);
	}

	if (strlcpy(driver_name,
	    ddi_driver_name(hca_devp->hd_hca_dip), driver_name_size) >=
	    driver_name_size) {
		mutex_exit(&ibtl_clnt_list_mutex);
		return (IBT_INSUFF_KERNEL_RESOURCE);
	}

	(void) ddi_pathname(hca_devp->hd_hca_dip, hca_device_path);
	*driver_instance = ddi_get_instance(hca_devp->hd_hca_dip);
	bcopy(hca_devp->hd_hca_attr, hca_attrs, sizeof (ibt_hca_attr_t));

	mutex_exit(&ibtl_clnt_list_mutex);
	return (IBT_SUCCESS);
}
