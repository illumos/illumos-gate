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

#ifndef _SYS_IB_IBTL_IMPL_IBTL_IBNEX_H
#define	_SYS_IB_IBTL_IMPL_IBTL_IBNEX_H

/*
 * ibtl_ibnex.h
 *
 * All data structures and function prototypes that are specific to the
 * IBTL<--->IB nexus private interface.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Cfgadm restricts ap_id length to 30 bytes (See CFGA_LOG_EXT_LEN)
 */
#define	IBTL_IBNEX_APID_LEN	31
#define	IBTL_IBNEX_STR_LEN	64

/*
 * "ioc" and "ibport" child device names
 */
#define	IBNEX_IOC_CNAME		"ioc"
#define	IBNEX_IBPORT_CNAME	"ibport"

/*
 * These two defines are used by the function ibtl_ibnex_get_hca_info().
 * If IBTL_IBNEX_LIST_CLNTS_FLAG is specified then an NVL packed list
 * of only client names/ap_ids/alternate_HCA is returned.
 * If IBTL_IBNEX_UNCFG_CLNTS_FLAG is specified then an NVL packed list
 * of only client ap_ids/devpaths is returned.
 */
#define	IBTL_IBNEX_LIST_CLNTS_FLAG	0x1	/* -x list_clients option */
#define	IBTL_IBNEX_UNCFG_CLNTS_FLAG	0x2	/* -x unconfig_clients option */

typedef struct ibtl_ibnex_cb_args_s {
	uint_t			cb_flag;
	dev_info_t		*cb_dip;
	struct modlinkage	*cb_modlp;
	ib_guid_t		cb_hca_guid;
} ibtl_ibnex_cb_args_t;

/* Possible values for cb_flag */
#define	IBTL_IBNEX_IBC_INIT		0x11
#define	IBTL_IBNEX_IBC_FINI		0x22
#define	IBTL_IBNEX_REPROBE_DEV_REQ	0x33

/*
 * Function:
 *	ibtl_ibnex_callback_t
 * Inputs:
 *	cb_args		- Arguments for the callback
 * Returns:
 *	IBT_SUCCESS/IBT_FAILURE
 * Description:
 *	Currently this routine provides function to check wheter
 *	particular client has access to open HCA or not.
 */
typedef ibt_status_t (*ibtl_ibnex_callback_t)(ibtl_ibnex_cb_args_t *);

/*
 * Function:
 *	ibtl_ibnex_register_callback
 * Inputs:
 *	ibnex_ibtl_callback	- IBTL's IB nexus driver callback function
 * Returns:
 *	NONE
 * Description:
 *	Register a callback routine for IB nexus driver.
 */
void	ibtl_ibnex_register_callback(ibtl_ibnex_callback_t);

/*
 * Function:
 *	ibtl_ibnex_unregister_callback
 * Inputs:
 *	NONE
 * Returns:
 *	NONE
 * Description:
 *	Un-register the callback routine for IB nexus driver.
 */
void	ibtl_ibnex_unregister_callback();

/*
 * Function:
 *	ibtl_ibnex_get_hca_info
 * Input:
 *	hca_guid	- The HCA's node GUID.
 *	flag		- Tells what to do
 *			IBTL_IBNEX_LIST_CLNTS_FLAG - Build client names/ap_ids/
 *			    alternate_HCA database
 *			IBTL_IBNEX_UNCFG_CLNTS_FLAG - Build client devpaths/
 *			    ap_id database
 *	callback	- Callback function to get ap_id from ib(7d)
 * Output:
 *	buffer		- The information is returned in this buffer
 *      bufsiz		- The size of the information buffer
 * Returns:
 *	IBT_SUCCESS/IBT_HCA_INVALID/IBT_FAILURE
 * Description:
 *      For a given HCA node GUID it figures out the registered clients
 *	(ie. ones who called ibt_attach(9f) on this GUID) and creates
 *	a NVL packed buffer (of either names/ap_ids/alternate_HCA or
 *	devpaths/ap_ids) and returns it. If a valid flag is not specified
 *	then an error is returned.
 */
ibt_status_t	ibtl_ibnex_get_hca_info(ib_guid_t hca_guid, int flag,
		    char **buffer, size_t *bufsiz,
		    void (*callback)(dev_info_t *, char **));

/*
 * Function:
 *	ibtl_ibnex_hcadip2guid
 * Input:
 *	dev_info_t	- The "dip" of this HCA
 * Output:
 *	hca_guid	- The HCA's node GUID.
 * Description:
 *	For a given HCA dip it figures out the GUID
 *	and returns it. If not found, NULL is returned.
 */
ib_guid_t	ibtl_ibnex_hcadip2guid(dev_info_t *);

/*
 * Function:
 *	ibtl_ibnex_hcaguid2dip
 * Input:
 *	hca_guid	- The HCA's node GUID.
 * Output:
 *	dev_info_t	- The "dip" of this HCA
 * Returns:
 *	 "dip" on SUCCESS, NULL on FAILURE
 * Description:
 *	For a given HCA node GUID it figures out the "dip"
 *	and returns it. If not found, NULL is returned.
 */
dev_info_t	*ibtl_ibnex_hcaguid2dip(ib_guid_t);

/*
 * Function:
 *	ibtl_ibnex_get_hca_verbose_data
 * Input:
 *	hca_guid	- The HCA's node GUID.
 * Output:
 *	buffer		- The information is returned in this buffer
 *      bufsiz		- The size of the information buffer
 * Returns:
 *	IBT_SUCCESS/IBT_HCA_INVALID/IBT_FAILURE
 * Description:
 *      For a given HCA node GUID it figures out the verbose listing display.
 */
ibt_status_t	ibtl_ibnex_get_hca_verbose_data(ib_guid_t, char **, size_t *);

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
 *	For IOC/Pseudo devices check if the given pdip is that of
 *	the ib(7d) nexus. If yes return IBT_SUCCESS,
 *	else IBT_NO_HCAS_AVAILABLE.
 */
ibt_status_t	ibtl_ibnex_valid_hca_parent(dev_info_t *);

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
 * 	Register the HCA dip as the MPxIO PCHI.
 */
ibt_status_t	ibtl_ibnex_phci_register(dev_info_t *hca_dip);

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
 * 	Free up any pending MPxIO Pathinfos and unregister the HCA dip as the
 * 	MPxIO PCHI.
 */
ibt_status_t	ibtl_ibnex_phci_unregister(dev_info_t *hca_dip);

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
ibtl_ibnex_query_hca_byguid(ib_guid_t, ibt_hca_attr_t *, char *, size_t, int *,
    char *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IMPL_IBTL_IBNEX_H */
