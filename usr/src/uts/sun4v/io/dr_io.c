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

/*
 * sun4v VIO DR Module
 */

#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/note.h>
#include <sys/sysevent/dr.h>
#include <sys/hypervisor_api.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>
#include <sys/ds.h>
#include <sys/drctl.h>
#include <sys/dr_util.h>
#include <sys/dr_io.h>
#include <sys/promif.h>
#include <sys/machsystm.h>
#include <sys/ethernet.h>
#include <sys/hotplug/pci/pcicfg.h>


static struct modlmisc modlmisc = {
	&mod_miscops,
	"sun4v VIO DR"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};


/*
 * VIO DS Interface
 */

/*
 * Global DS Handle
 */
static ds_svc_hdl_t ds_vio_handle;

/*
 * Supported DS Capability Versions
 */
static ds_ver_t		dr_vio_vers[] = { { 1, 0 } };
#define	DR_VIO_NVERS	(sizeof (dr_vio_vers) / sizeof (dr_vio_vers[0]))

/*
 * DS Capability Description
 */
static ds_capability_t dr_vio_cap = {
	DR_VIO_DS_ID,		/* svc_id */
	dr_vio_vers,		/* vers */
	DR_VIO_NVERS		/* nvers */
};

/*
 * DS Callbacks
 */
static void dr_vio_reg_handler(ds_cb_arg_t, ds_ver_t *, ds_svc_hdl_t);
static void dr_vio_unreg_handler(ds_cb_arg_t arg);
static void dr_vio_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);

/*
 * DS Client Ops Vector
 */
static ds_clnt_ops_t dr_vio_ops = {
	dr_vio_reg_handler,	/* ds_reg_cb */
	dr_vio_unreg_handler,	/* ds_unreg_cb */
	dr_vio_data_handler,	/* ds_data_cb */
	NULL			/* cb_arg */
};


typedef struct {
	char		*name;
	uint64_t	devid;
	dev_info_t	*dip;
} dr_search_arg_t;

static int
dr_io_check_node(dev_info_t *dip, void *arg)
{
	char 		*name;
	uint64_t	devid;
	dr_search_arg_t	*sarg = (dr_search_arg_t *)arg;

	name = ddi_node_name(dip);

	if (strcmp(name, sarg->name) != 0)
		return (DDI_WALK_CONTINUE);

	devid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", -1);

	DR_DBG_IO("%s: found devid=%ld, looking for %ld\n",
	    __func__, devid, sarg->devid);

	if (devid == sarg->devid) {
		DR_DBG_IO("%s: matched", __func__);

		/* matching node must be returned held */
		if (!e_ddi_branch_held(dip))
			e_ddi_branch_hold(dip);

		sarg->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * Walk the device tree to find the dip corresponding to the devid
 * passed in. If present, the dip is returned held. The caller must
 * release the hold on the dip once it is no longer required. If no
 * matching node if found, NULL is returned.
 */
static dev_info_t *
dr_io_find_node(char *name, uint64_t devid)
{
	dr_search_arg_t	arg;

	DR_DBG_IO("dr_io_find_node...\n");

	arg.name = name;
	arg.devid = devid;
	arg.dip = NULL;

	ddi_walk_devs(ddi_root_node(), dr_io_check_node, &arg);

	ASSERT((arg.dip == NULL) || (e_ddi_branch_held(arg.dip)));

	return ((arg.dip) ? arg.dip : NULL);
}

/*
 * Look up a particular IO node in the MD. Returns the mde_cookie_t
 * representing that IO node if present, and MDE_INVAL_ELEM_COOKIE otherwise.
 * It is assumed the scratch array has already been allocated so that
 * it can accommodate the worst case scenario, every node in the MD.
 */
static mde_cookie_t
dr_io_find_node_md(md_t *mdp, char *name, uint64_t id, mde_cookie_t *listp)
{
	int		i;
	int		nnodes;
	char		*devnm;
	uint64_t	devid;
	mde_cookie_t	rootnode;
	mde_cookie_t	result = MDE_INVAL_ELEM_COOKIE;

	DR_DBG_IO("%s: %s@%ld\n", __func__, name, id);

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	/*
	 * Scan the DAG for all candidate nodes.
	 */
	nnodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "virtual-device"),
	    md_find_name(mdp, "fwd"), listp);

	if (nnodes < 0) {
		DR_DBG_IO("%s: scan for "
		    "'virtual-device' nodes failed\n", __func__);
		return (result);
	}

	DR_DBG_IO("%s: found %d nodes in the MD\n", __func__, nnodes);

	/*
	 * Find the node of interest
	 */
	for (i = 0; i < nnodes; i++) {

		if (md_get_prop_str(mdp, listp[i], "name", &devnm)) {
			DR_DBG_IO("%s: missing 'name' property for"
			    " IO node %d\n", __func__, i);
			return (DDI_WALK_ERROR);
		}

		if (strcmp(devnm, name) != 0)
			continue;

		if (md_get_prop_val(mdp, listp[i], "cfg-handle", &devid)) {
			DR_DBG_IO("%s: missing 'cfg-handle' property for"
			    " IO node %d\n", __func__, i);
			break;
		}

		if (devid == id) {
			/* found a match */
			DR_DBG_IO("%s: found IO node %s@%ld "
			    "in MD\n", __func__, name, id);
			result = listp[i];
			break;
		}
	}

	if (result == MDE_INVAL_ELEM_COOKIE)
		DR_DBG_IO("%s: IO node %ld not in MD\n", __func__, id);

	return (result);
}

typedef struct {
	md_t		*mdp;
	mde_cookie_t	node;
	dev_info_t	*dip;
} cb_arg_t;

#define	STR_ARR_LEN	5

static int
new_dev_node(dev_info_t *new_node, void *arg, uint_t flags)
{
	_NOTE(ARGUNUSED(flags))

	cb_arg_t	*cba;
	char		*devnm, *devtype;
	char		*compat;
	uint64_t	devid;
	int		len = 0;
	char		*curr;
	int		i = 0;
	char		*str_arr[STR_ARR_LEN];

	cba = (cb_arg_t *)arg;

	/*
	 * Add 'name' property
	 */
	if (md_get_prop_str(cba->mdp, cba->node, "name", &devnm)) {
		DR_DBG_IO("%s: failed to read 'name' prop from MD\n", __func__);
		return (DDI_WALK_ERROR);
	}
	DR_DBG_IO("%s: device name is %s\n", __func__, devnm);

	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_node,
	    "name", devnm) != DDI_SUCCESS) {
		DR_DBG_IO("%s: failed to create 'name' prop\n", __func__);
		return (DDI_WALK_ERROR);
	}

	/*
	 * Add 'compatible' property
	 */
	if (md_get_prop_data(cba->mdp, cba->node, "compatible",
	    (uint8_t **)&compat, &len)) {
		DR_DBG_IO("%s: failed to read "
		    "'compatible' prop from MD\n", __func__);
		return (DDI_WALK_ERROR);
	}

	/* parse the MD string array */
	curr = compat;
	while (curr < (compat + len)) {

		DR_DBG_IO("%s: adding '%s' to "
		    "'compatible' prop\n", __func__, curr);

		str_arr[i++] = curr;
		curr += strlen(curr) + 1;

		if (i == STR_ARR_LEN) {
			DR_DBG_CPU("exceeded str_arr len (%d)\n", STR_ARR_LEN);
			break;
		}
	}


	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, new_node,
	    "compatible", str_arr, i) != DDI_SUCCESS) {
		DR_DBG_IO("%s: cannot create 'compatible' prop\n", __func__);
		return (DDI_WALK_ERROR);
	}

	/*
	 * Add 'device_type' property
	 */
	if (md_get_prop_str(cba->mdp, cba->node, "device-type", &devtype)) {
		DR_DBG_IO("%s: failed to read "
		    "'device-type' prop from MD\n", __func__);
		return (DDI_WALK_ERROR);
	}
	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_node,
	    "device_type", devtype) != DDI_SUCCESS) {
		DR_DBG_IO("%s: failed to create "
		    "'device-type' prop\n", __func__);
		return (DDI_WALK_ERROR);
	}

	DR_DBG_IO("%s: device type is %s\n", __func__, devtype);

	/*
	 * Add 'reg' (cfg-handle) property
	 */
	if (md_get_prop_val(cba->mdp, cba->node, "cfg-handle", &devid)) {
		DR_DBG_IO("%s: failed to read "
		    "'cfg-handle' prop from MD\n", __func__);
		return (DDI_WALK_ERROR);
	}

	DR_DBG_IO("%s: new device is %s@%ld\n", __func__, devnm, devid);

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_node, "reg", devid)
	    != DDI_SUCCESS) {
		DR_DBG_IO("%s: failed to create 'reg' prop\n", __func__);
		return (DDI_WALK_ERROR);
	}

	/* if vnet/vswitch, probe and add mac-address and mtu properties */
	if (strcmp(devnm, "vsw") == 0 || strcmp(devnm, "network") == 0) {

		int i, j;
		uint64_t mtu, macaddr;
		uchar_t maddr_arr[ETHERADDRL];

		if (md_get_prop_val(cba->mdp, cba->node, "local-mac-address",
		    &macaddr)) {
			DR_DBG_IO("%s: failed to read "
			    "'local-mac-address' prop from MD\n", __func__);
			return (DDI_WALK_ERROR);
		}

		for (i = 0, j = (ETHERADDRL - 1); i < ETHERADDRL; i++, j--)
			maddr_arr[j] = (macaddr >> (i * 8)) & 0xff;

		if (ndi_prop_update_byte_array(DDI_DEV_T_NONE, new_node,
		    "local-mac-address", maddr_arr, ETHERADDRL)
		    != DDI_SUCCESS) {
			DR_DBG_IO("%s: failed to create "
			    "'local-mac-address' prop\n", __func__);
			return (DDI_WALK_ERROR);
		}

		if (md_get_prop_val(cba->mdp, cba->node, "mtu", &mtu)) {
			DR_DBG_IO("%s: failed to read "
			    "'mtu' prop from MD\n", __func__);
			return (DDI_WALK_ERROR);
		}

		if (ndi_prop_update_int64(DDI_DEV_T_NONE, new_node, "mtu",
		    mtu) != DDI_SUCCESS) {
			DR_DBG_IO("%s: failed to "
			    "create 'mtu' prop\n", __func__);
			return (DDI_WALK_ERROR);
		}

		DR_DBG_IO("%s: Added properties for %s@%ld, "
		    "mac=%ld, mtu=%ld\n", __func__, devnm, devid, macaddr, mtu);
	}

	cba->dip = new_node;

	return (DDI_WALK_TERMINATE);
}

/*
 * Find the parent node of the argument virtual device node in
 * the MD.  For virtual devices, the parent is always
 * "channel-devices", so scan the MD using the "back" arcs
 * looking for a node with that name.
 */
static mde_cookie_t
dr_vio_find_parent_md(md_t *mdp, mde_cookie_t node)
{
	int		max_nodes;
	int		num_nodes;
	int		listsz;
	mde_cookie_t    *listp;
	mde_cookie_t	pnode = MDE_INVAL_ELEM_COOKIE;

	max_nodes = md_node_count(mdp);
	listsz = max_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);
	DR_DBG_KMEM("%s: alloc addr %p size %d\n",
	    __func__, (void *)listp, listsz);

	num_nodes = md_scan_dag(mdp, node,
	    md_find_name(mdp, "channel-devices"),
	    md_find_name(mdp, "back"), listp);

	ASSERT(num_nodes == 1);

	if (num_nodes == 1)
		pnode = listp[0];

	DR_DBG_KMEM("%s: free addr %p size %d\n",
	    __func__, (void *)listp, listsz);
	kmem_free(listp, listsz);

	return (pnode);
}

static int
dr_io_configure(dr_vio_req_t *req, dr_vio_res_t *res)
{
	int		rv = ENXIO;
	int		listsz;
	int		nnodes;
	uint64_t	devid = req->dev_id;
	uint64_t	pdevid;
	char		*name = req->name;
	char		*pname;
	md_t		*mdp = NULL;
	mde_cookie_t	*listp = NULL;
	mde_cookie_t	node;
	mde_cookie_t	pnode;
	dev_info_t	*pdip = NULL;
	dev_info_t	*dip;
	devi_branch_t	br;
	cb_arg_t	cba;
	int		drctl_cmd;
	int		drctl_flags = 0;
	drctl_rsrc_t	*drctl_req;
	size_t		drctl_req_len;
	drctl_rsrc_t	*drctl_rsrc = NULL;
	drctl_cookie_t	drctl_res_ck;
	char		*p;
	drctl_resp_t	*drctl_resp;
	size_t		drctl_resp_len = 0;

	res->result = DR_VIO_RES_FAILURE;

	if ((dip = dr_io_find_node(name, devid)) != NULL) {
		DR_DBG_IO("%s: %s@%ld already configured\n",
		    __func__, name, devid);

		/* Return success if resources is already there. */
		res->result = DR_VIO_RES_OK;
		res->status = DR_VIO_STAT_CONFIGURED;
		e_ddi_branch_rele(dip);
		return (0);
	}

	/* Assume we fail to find the node to be added. */
	res->status = DR_VIO_STAT_NOT_PRESENT;

	if ((mdp = md_get_handle()) == NULL) {
		DR_DBG_IO("%s: unable to initialize MD\n", __func__);
		return (ENXIO);
	}

	nnodes = md_node_count(mdp);
	ASSERT(nnodes > 0);

	listsz = nnodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);
	DR_DBG_KMEM("%s: alloc addr %p size %d\n",
	    __func__, (void *)listp, listsz);

	/*
	 * Get the MD device node.
	 */
	node = dr_io_find_node_md(mdp, name, devid, listp);

	if (node == MDE_INVAL_ELEM_COOKIE) {
		DR_DBG_IO("%s: scan for %s name node failed\n", __func__, name);
		res->result = DR_VIO_RES_NOT_IN_MD;
		goto done;
	}

	/*
	 * Get the MD parent node.
	 */
	pnode = dr_vio_find_parent_md(mdp, node);
	if (pnode == MDE_INVAL_ELEM_COOKIE) {
		DR_DBG_IO("%s: failed to find MD parent of %lx\n",
		    __func__, pnode);
		goto done;
	}

	if (md_get_prop_str(mdp, pnode, "name", &pname)) {
		DR_DBG_IO("%s: failed to read "
		    "'name' for pnode %lx from MD\n", __func__, pnode);
		goto done;
	}

	if (md_get_prop_val(mdp, pnode, "cfg-handle", &pdevid)) {
		DR_DBG_IO("%s: failed to read 'cfg-handle' "
		    "for pnode '%s' from MD\n", __func__, pname);
		goto done;
	}

	DR_DBG_IO("%s: parent device %s@%lx\n", __func__, pname, pdevid);

	/*
	 * Get the devinfo parent node.
	 */
	if ((pdip = dr_io_find_node(pname, pdevid)) == NULL) {
		DR_DBG_IO("%s: parent device %s@%ld not found\n",
		    __func__, pname, pdevid);
		goto done;
	}

	drctl_req_len = sizeof (drctl_rsrc_t) + MAXPATHLEN;
	drctl_req = kmem_zalloc(drctl_req_len, KM_SLEEP);
	DR_DBG_KMEM("%s: alloc addr %p size %ld\n",
	    __func__, (void *)drctl_req, drctl_req_len);
	drctl_req->status = DRCTL_STATUS_INIT;

	drctl_cmd = DRCTL_IO_CONFIG_REQUEST;

	/*
	 * Construct the path of the device as it will be if it
	 * is successfully added.
	 */
	p = drctl_req->res_dev_path;
	(void) sprintf(p, "/devices");
	(void) ddi_pathname(pdip, p + strlen(p));
	(void) sprintf(p + strlen(p), "/%s@%ld", name, devid);
	DR_DBG_IO("%s: devpath=%s\n", __func__, drctl_req->res_dev_path);

	rv = drctl_config_init(drctl_cmd, drctl_flags, drctl_req,
	    1, &drctl_resp, &drctl_resp_len, &drctl_res_ck);

	ASSERT((drctl_resp != NULL) && (drctl_resp_len != 0));

	drctl_rsrc = drctl_resp->resp_resources;

	if (rv != 0) {
		DR_DBG_IO("%s: drctl_config_init failed: %d\n", __func__, rv);

		ASSERT(drctl_resp->resp_type == DRCTL_RESP_ERR);

		(void) strlcpy(res->reason,
		    drctl_resp->resp_err_msg, DR_VIO_MAXREASONLEN);

		DR_DBG_IO("%s: %s\n", __func__, res->reason);

		goto done;

	}

	ASSERT(drctl_resp->resp_type == DRCTL_RESP_OK);

	if (drctl_rsrc->status == DRCTL_STATUS_DENY) {

		res->result = DR_VIO_RES_BLOCKED;

		DR_DBG_IO("%s: drctl_config_init denied\n", __func__);
		p = (char *)drctl_rsrc + drctl_rsrc->offset;

		(void) strlcpy(res->reason, p, DR_VIO_MAXREASONLEN);

		DR_DBG_IO("%s: %s\n", __func__, res->reason);

		drctl_req->status = DRCTL_STATUS_CONFIG_FAILURE;

		rv = EPERM;
	} else {
		cba.mdp = mdp;
		cba.node = node;

		br.arg = (void *)&cba;
		br.type = DEVI_BRANCH_SID;
		br.create.sid_branch_create = new_dev_node;
		br.devi_branch_callback = NULL;

		rv = e_ddi_branch_create(pdip,
		    &br, NULL, DEVI_BRANCH_CONFIGURE);

		drctl_req->status = (rv == 0) ?
		    DRCTL_STATUS_CONFIG_SUCCESS : DRCTL_STATUS_CONFIG_FAILURE;

		DR_DBG_IO("%s: %s@%ld = %d\n", __func__, name, devid, rv);
	}

	if (drctl_config_fini(&drctl_res_ck, drctl_req, 1) != 0)
		DR_DBG_IO("%s: drctl_config_fini returned: %d\n", __func__, rv);

done:
	if (listp) {
		DR_DBG_KMEM("%s: free addr %p size %d\n",
		    __func__, (void *)listp, listsz);
		kmem_free(listp, listsz);
	}

	if (mdp)
		(void) md_fini_handle(mdp);

	if (pdip)
		e_ddi_branch_rele(pdip);

	DR_DBG_KMEM("%s: free addr %p size %ld\n",
	    __func__, (void *)drctl_req, drctl_req_len);
	kmem_free(drctl_req, drctl_req_len);

	if (drctl_resp) {
		DR_DBG_KMEM("%s: free addr %p size %ld\n",
		    __func__, (void *)drctl_resp, drctl_resp_len);
		kmem_free(drctl_resp, drctl_resp_len);
	}

	if (rv == 0) {
		res->result = DR_VIO_RES_OK;
		res->status = DR_VIO_STAT_CONFIGURED;

		/* notify interested parties about the operation */
		dr_generate_event(DR_TYPE_VIO, SE_HINT_INSERT);
	} else {
		res->status = DR_VIO_STAT_UNCONFIGURED;
	}

	return (rv);
}

static int
dr_io_unconfigure(dr_vio_req_t *req, dr_vio_res_t *res)
{
	int		rv;
	char		*name = req->name;
	char		*p;
	uint64_t	devid = req->dev_id;
	dev_info_t	*dip;
	dev_info_t	*fdip = NULL;
	int		drctl_cmd;
	int		drctl_flags = 0;
	drctl_rsrc_t	*drctl_req;
	size_t		drctl_req_len;
	drctl_rsrc_t	*drctl_rsrc = NULL;
	drctl_cookie_t	drctl_res_ck;
	drctl_resp_t	*drctl_resp;
	size_t		drctl_resp_len;

	if ((dip = dr_io_find_node(name, devid)) == NULL) {
		DR_DBG_IO("%s: %s@%ld already unconfigured\n",
		    __func__, name, devid);
		res->result = DR_VIO_RES_OK;
		res->status = DR_VIO_STAT_NOT_PRESENT;
		return (0);
	}

	res->result = DR_VIO_RES_FAILURE;

	ASSERT(e_ddi_branch_held(dip));

	/* Assume we fail to unconfigure the resource. */
	res->status = DR_VIO_STAT_CONFIGURED;

	drctl_req_len = sizeof (drctl_rsrc_t) + MAXPATHLEN;
	drctl_req = kmem_zalloc(drctl_req_len, KM_SLEEP);
	DR_DBG_KMEM("%s: alloc addr %p size %ld\n",
	    __func__, (void *)drctl_req, drctl_req_len);
	drctl_req->status = DRCTL_STATUS_INIT;

	drctl_cmd = DRCTL_IO_UNCONFIG_REQUEST;

	if (req->msg_type == DR_VIO_FORCE_UNCONFIG)
		drctl_flags = DRCTL_FLAG_FORCE;

	p = drctl_req->res_dev_path;
	(void) sprintf(p, "/devices");
	(void) ddi_pathname(dip, p + strlen(p));
	DR_DBG_IO("%s: devpath=%s\n", __func__, drctl_req->res_dev_path);

	rv = drctl_config_init(drctl_cmd, drctl_flags, drctl_req,
	    1, &drctl_resp, &drctl_resp_len, &drctl_res_ck);

	ASSERT((drctl_resp != NULL) && (drctl_resp_len != 0));

	drctl_rsrc = drctl_resp->resp_resources;

	if (rv != 0) {

		DR_DBG_IO("%s: drctl_config_init failed: %d\n", __func__, rv);

		ASSERT(drctl_resp->resp_type == DRCTL_RESP_ERR);

		(void) strlcpy(res->reason,
		    drctl_resp->resp_err_msg, DR_VIO_MAXREASONLEN);

		DR_DBG_IO("%s: %s\n", __func__, res->reason);

		goto done;
	}

	if (drctl_rsrc->status == DRCTL_STATUS_DENY) {
		res->result = DR_VIO_RES_BLOCKED;

		DR_DBG_IO("%s: drctl_config_init denied\n", __func__);
		p = (char *)drctl_rsrc + drctl_rsrc->offset;

		(void) strlcpy(res->reason, p, DR_VIO_MAXREASONLEN);

		DR_DBG_IO("%s: %s\n", __func__, res->reason);

		drctl_req->status = DRCTL_STATUS_CONFIG_FAILURE;

		rv = EPERM;
	} else if (rv = e_ddi_branch_destroy(dip, &fdip, 0)) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		DR_DBG_KMEM("%s: alloc addr %p size %d\n",
		    __func__, (void *)path, MAXPATHLEN);
		/*
		 * If non-NULL, fdip is held and must be released.
		 */
		if (fdip != NULL) {
			(void) ddi_pathname(fdip, path);
			ddi_release_devi(fdip);
		} else {
			(void) ddi_pathname(dip, path);
		}

		DR_DBG_IO("%s: node removal failed: %s (%p)",
		    __func__, path, (fdip) ? (void *)fdip : (void *)dip);

		drctl_req->status = DRCTL_STATUS_CONFIG_FAILURE;

		DR_DBG_KMEM("%s: free addr %p size %d\n",
		    __func__, (void *)path, MAXPATHLEN);
		kmem_free(path, MAXPATHLEN);
	} else {
		drctl_req->status = DRCTL_STATUS_CONFIG_SUCCESS;
	}

	if (drctl_config_fini(&drctl_res_ck, drctl_req, 1) != 0)
		DR_DBG_IO("%s: drctl_config_fini returned: %d\n", __func__, rv);

	DR_DBG_IO("%s: (%s@%ld) = %d\n", __func__, name, devid, rv);

	if (rv == 0) {
		res->result = DR_VIO_RES_OK;
		res->status = DR_VIO_STAT_UNCONFIGURED;

		/* Notify interested parties about the operation. */
		dr_generate_event(DR_TYPE_VIO, SE_HINT_REMOVE);
	}
done:
	DR_DBG_KMEM("%s: free addr %p size %ld\n",
	    __func__, (void *)drctl_req, drctl_req_len);
	kmem_free(drctl_req, drctl_req_len);

	if (drctl_resp) {
		DR_DBG_KMEM("%s: free addr %p size %ld\n",
		    __func__, (void *)drctl_resp, drctl_resp_len);
		kmem_free(drctl_resp, drctl_resp_len);
	}

	return (rv);
}

static void
dr_vio_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	_NOTE(ARGUNUSED(arg))

	size_t		res_len;
	dr_vio_res_t	*res;
	dr_vio_req_t	*req;

	/*
	 * Allocate a response buffer, because we always want to
	 * send back a response message.
	 */
	res_len = sizeof (dr_vio_res_t) + DR_VIO_MAXREASONLEN;
	res = kmem_zalloc(res_len, KM_SLEEP);
	DR_DBG_KMEM("%s: alloc addr %p size %ld\n",
	    __func__, (void *)res, res_len);
	res->result = DR_VIO_RES_FAILURE;

	/*
	 * Sanity check the message
	 */
	if (buf == NULL) {
		DR_DBG_IO("empty message: expected at least %ld bytes\n",
		    sizeof (dr_vio_req_t));
		goto done;
	}
	if (buflen < sizeof (dr_vio_req_t)) {
		DR_DBG_IO("incoming message short: expected at least %ld "
		    "bytes, received %ld\n", sizeof (dr_vio_req_t), buflen);
		goto done;
	}

	DR_DBG_TRANS("incoming request:\n");
	DR_DBG_DUMP_MSG(buf, buflen);

	req = buf;
	switch (req->msg_type) {
	case DR_VIO_CONFIGURE:
		(void) dr_io_configure(req, res);
		break;
	case DR_VIO_FORCE_UNCONFIG:
	case DR_VIO_UNCONFIGURE:
		(void) dr_io_unconfigure(req, res);
		break;
	default:
		cmn_err(CE_NOTE, "bad msg_type %d\n", req->msg_type);
		break;
	}
done:
	res->req_num = (req) ? req->req_num : 0;

	DR_DBG_TRANS("outgoing response:\n");
	DR_DBG_DUMP_MSG(res, res_len);

	/* send back the response */
	if (ds_cap_send(ds_vio_handle, res, res_len) != 0)
		DR_DBG_IO("ds_send failed\n");

	if (res) {
		DR_DBG_KMEM("%s: free addr %p size %ld\n",
		    __func__, (void *)res, res_len);
		kmem_free(res, res_len);
	}
}

static void
dr_vio_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	DR_DBG_IO("vio_reg_handler: arg=0x%p, ver=%d.%d, hdl=0x%lx\n",
	    arg, ver->major, ver->minor, hdl);

	ds_vio_handle = hdl;
}

static void
dr_vio_unreg_handler(ds_cb_arg_t arg)
{
	DR_DBG_IO("vio_unreg_handler: arg=0x%p\n", arg);

	ds_vio_handle = DS_INVALID_HDL;
}

static int
dr_io_init(void)
{
	int	rv;

	if ((rv = ds_cap_init(&dr_vio_cap, &dr_vio_ops)) != 0) {
		cmn_err(CE_NOTE, "ds_cap_init vio failed: %d", rv);
		return (-1);
	}

	return (0);
}

static int
dr_io_fini(void)
{
	int	rv;

	if ((rv = ds_cap_fini(&dr_vio_cap)) != 0) {
		cmn_err(CE_NOTE, "ds_cap_fini vio failed: %d", rv);
		return (-1);
	}

	return (0);
}

int
_init(void)
{
	int	status;

	/* check that IO DR is enabled */
	if (dr_is_disabled(DR_TYPE_VIO)) {
		cmn_err(CE_CONT, "!VIO DR is disabled\n");
		return (-1);
	}

	if ((status = dr_io_init()) != 0) {
		cmn_err(CE_NOTE, "VIO DR initialization failed");
		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		(void) dr_io_fini();
	}

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int dr_io_allow_unload = 0;

int
_fini(void)
{
	int	status;

	if (dr_io_allow_unload == 0)
		return (EBUSY);

	if ((status = mod_remove(&modlinkage)) == 0) {
		(void) dr_io_fini();
	}

	return (status);
}
