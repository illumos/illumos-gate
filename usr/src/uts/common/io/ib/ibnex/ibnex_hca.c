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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/taskq.h>
#include <sys/mdi_impldefs.h>
#include <sys/sunmdi.h>
#include <sys/sunpm.h>
#include <sys/ib/mgt/ibdm/ibdm_impl.h>
#include <sys/ib/ibnex/ibnex.h>
#include <sys/ib/ibnex/ibnex_devctl.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/impl/ibtl_ibnex.h>
#include <sys/file.h>
#include <sys/hwconf.h>
#include <sys/fs/dv_node.h>

void ibnex_handle_hca_attach(void *);
static int ibnex_hca_bus_config_one(dev_info_t *, void *,
		ddi_bus_config_op_t, uint_t *, dev_info_t **);

static ibnex_node_data_t *ibnex_get_cdip_info(dev_info_t *, char *,
		dev_info_t **, ibnex_node_type_t *);
static int ibnex_prom_devname_to_pkey_n_portnum(
		char *, ib_pkey_t *, uint8_t *);
static dev_info_t *ibnex_config_obp_args(dev_info_t *, char *);

extern int	ibnex_busctl(dev_info_t *,
		    dev_info_t *, ddi_ctl_enum_t, void *, void *);
extern int	ibnex_map_fault(dev_info_t *,
		    dev_info_t *, struct hat *, struct seg *,
			caddr_t, struct devpage *, pfn_t, uint_t, uint_t);
static int	ibnex_hca_bus_config(dev_info_t *, uint_t,
		    ddi_bus_config_op_t, void *, dev_info_t **);
static int	ibnex_hca_bus_unconfig(dev_info_t *,
		    uint_t, ddi_bus_config_op_t, void *);
extern dev_info_t	*ibnex_config_port_node(dev_info_t *, char *);
extern dev_info_t	*ibnex_config_obp_args(dev_info_t *, char *);
extern int		ibnex_ioc_bus_config_one(dev_info_t **, uint_t,
			    ddi_bus_config_op_t, void *, dev_info_t **, int *);
extern int		ibnex_pseudo_config_one(
		    ibnex_node_data_t *, char *, dev_info_t *);
extern void		ibnex_config_all_children(dev_info_t *);
extern void			ibnex_pseudo_initnodes(void);

extern int		ibnex_pseudo_mdi_config_one(int, void *, dev_info_t **,
			    char *, char *);
extern int			ibnex_get_dip_from_guid(ib_guid_t, int,
			    ib_pkey_t, dev_info_t **);
extern dev_info_t	*ibnex_commsvc_initnode(dev_info_t *,
			    ibdm_port_attr_t *, int, int, ib_pkey_t, int *,
			    int);
extern uint64_t		ibnex_str2hex(char *, int, int *);
extern int		ibnex_str2int(char *, int, int *);
extern void		ibnex_create_hcasvc_nodes(
			    dev_info_t *, ibdm_port_attr_t *);
extern void		ibnex_create_port_nodes(
			    dev_info_t *, ibdm_port_attr_t *);
extern void		ibnex_create_vppa_nodes(
			    dev_info_t *, ibdm_port_attr_t *);
extern int		ibnex_get_pkey_commsvc_index_portnum(
			    char *, int *, ib_pkey_t *, uint8_t *);

extern ibnex_t	ibnex;
extern int	ibnex_port_settling_time;

/*
 * The bus_ops structure defines the capabilities of HCA nexus driver.
 */
struct bus_ops ibnex_ci_busops = {
	BUSO_REV,
	nullbusmap,		/* bus_map */
	NULL,			/* bus_get_intrspec */
	NULL,			/* bus_add_intrspec */
	NULL,			/* bus_remove_intrspec */
	ibnex_map_fault,	/* Map Fault */
	ddi_no_dma_map,		/* DMA related entry points */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	ibnex_busctl,		/* bus_ctl */
	ddi_bus_prop_op,	/* bus_prop_op */
	NULL,			/* bus_get_eventcookie	*/
	NULL,			/* bus_add_eventcall	*/
	NULL,			/* bus_remove_eventcall	*/
	NULL,			/* bus_post_event	*/
	NULL,
	ibnex_hca_bus_config,	/* bus config */
	ibnex_hca_bus_unconfig	/* bus unconfig */
};

/*
 * ibnex_hca_bus_config()
 *
 * BUS_CONFIG_ONE:
 *	Enumerate the exact instance of the driver. Use the device node name
 *	to locate the exact instance.
 *	Query IBDM to find whether the hardware exits for the instance of the
 *	driver. If exists, create a device node and return NDI_SUCCESS.
 *
 * BUS_CONFIG_ALL:
 *	Enumerate all the instances of all the possible children (seen before
 *	and never seen before).
 *
 * BUS_CONFIG_DRIVER:
 *	Enumerate all the instances of a particular driver.
 */
static int
ibnex_hca_bus_config(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *devname, dev_info_t **child)
{
	int			ret = IBNEX_SUCCESS, circ;
	char			*srvname, nameaddr[MAXNAMELEN];
	dev_info_t		*cdip;
	ibnex_node_data_t	*node_data;
	ibnex_port_node_t	*port_node;

	/*
	 * In a normal case HCA is setup as a phci.
	 * If an HCA is in maintenance mode, its phci is not set up
	 * but the driver is attached to update the firmware. In this
	 * case, do not configure the MPxIO clients.
	 */
	if (mdi_component_is_phci(parent, NULL) == MDI_FAILURE) {
		if (op == BUS_CONFIG_ALL || op == BUS_CONFIG_DRIVER)
			return (NDI_SUCCESS);
		else
			return (NDI_FAILURE);
	}

	switch (op) {
	case BUS_CONFIG_ONE:
		IBTF_DPRINTF_L4("ibnex", "\thca_bus_config: CONFIG_ONE, "
		    "parent %p", parent);
		ret = ibnex_hca_bus_config_one(
		    parent, devname, op, &flag, child);
		break;

	case BUS_CONFIG_OBP_ARGS:
		mdi_devi_enter(parent, &circ);
		cdip = ibnex_config_obp_args(parent, devname);
		if (cdip) {
			/*
			 * Boot case.
			 * Special handling because the "devname"
			 * format for the enumerated device is
			 * different.
			 */
			node_data = ddi_get_parent_data(cdip);
			port_node = &node_data->node_data.port_node;
			if (node_data->node_type ==
			    IBNEX_VPPA_COMMSVC_NODE) {
				srvname =
				    ibnex.ibnex_vppa_comm_svc_names[
				    port_node->port_commsvc_idx];
				(void) snprintf(nameaddr, MAXNAMELEN,
				    "ibport@%x,%x,%s",
				    port_node->port_num,
				    port_node->port_pkey, srvname);
			}
			devname = (void *)nameaddr;
		} else {
			IBTF_DPRINTF_L2("ibnex", "\thca_bus_config: "
			    "CONFIG_OBP_ARGS : invalid state!!");

			ret = IBNEX_FAILURE;
		}
		mdi_devi_exit(parent, circ);
		break;

	case BUS_CONFIG_ALL:
		IBTF_DPRINTF_L4("ibnex",
		    "\thca_bus_config: CONFIG_ALL parent %p", parent);
		ibnex_config_all_children(parent);
		break;

	case BUS_CONFIG_DRIVER:
		IBTF_DPRINTF_L4("ibnex", "\thca_bus_config: "
		    "CONFIG_DRIVER parent %p", parent);
		ibnex_config_all_children(parent);
		break;

	default:
		IBTF_DPRINTF_L4("ibnex", "\thca_bus_config: error");
		ret = IBNEX_FAILURE;
		break;
	}


	if (ret == IBNEX_SUCCESS) {
		if (op == BUS_CONFIG_OBP_ARGS)
			op = BUS_CONFIG_ONE;

		ret = ndi_busop_bus_config(
		    parent, flag, op, devname, child, 0);
		IBTF_DPRINTF_L4("ibnex", "\thca_bus_config:"
		    "ndi_busop_bus_config : retval %d", ret);
		return (ret);
	}

	return (NDI_FAILURE);
}

/*
 * ibnex_hca_bus_unconfig()
 *
 *	Unconfigure a particular device node or all instance of a device
 *	driver device or all children of IBnex
 */
static int
ibnex_hca_bus_unconfig(dev_info_t *parent,
    uint_t flag, ddi_bus_config_op_t op, void *device_name)
{

	if (ndi_busop_bus_unconfig(parent, flag, op, device_name) !=
	    DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((op == BUS_UNCONFIG_ALL || op == BUS_UNCONFIG_DRIVER) &&
	    (flag & NDI_UNCONFIG)) {
		ibnex_node_data_t	*ndp;
		dev_info_t		*dip = NULL;
		major_t			major = (major_t)(uintptr_t)device_name;

		mutex_enter(&ibnex.ibnex_mutex);

		if (major == -1) {
			/*
			 * HCA dip. When major number is -1 HCA is
			 * going away cleanup all the port nodes.
			 */
			for (ndp = ibnex.ibnex_port_node_head;
			    ndp; ndp = ndp->node_next) {
				ibnex_port_node_t	*port_node;

				port_node = &ndp->node_data.port_node;
				if (port_node->port_pdip == parent) {
					port_node->port_pdip = NULL;
					ndp->node_dip = NULL;
					ndp->node_state =
					    IBNEX_CFGADM_UNCONFIGURED;
				}
			}
		} else {
			/*
			 * HCA dip. Cleanup only the port nodes that
			 * match the major number.
			 */
			for (ndp = ibnex.ibnex_port_node_head;
			    ndp; ndp = ndp->node_next) {
				ibnex_port_node_t	*port_node;

				port_node = &ndp->node_data.port_node;
				dip = ndp->node_dip;
				if (dip && (ddi_driver_major(dip) ==
				    major) && port_node->port_pdip ==
				    parent) {
					port_node->port_pdip = NULL;
					ndp->node_dip = NULL;
					ndp->node_state =
					    IBNEX_CFGADM_UNCONFIGURED;
				}
			}
		}
		mutex_exit(&ibnex.ibnex_mutex);
	}
	return (DDI_SUCCESS);
}

/*
 * ibnex_config_obp_args()
 *	Configures a particular port node for a IP over IB communication
 *	service.
 *	The format of the input string "devname" is
 *		port=x,pkey=y,protocol=ip
 *	Thr format of the node name created here is
 *		ibport@<Port#>,<pkey>,<service name>
 *	where pkey = 0 for port communication service nodes
 *	Returns "dev_info_t" of the "child" node just created
 *	NULL when failed to enumerate the child node
 *
 */
static dev_info_t *
ibnex_config_obp_args(dev_info_t *parent, char *devname)
{
	int			ii, index;
	int			rval, iter = 0;
	char			*temp;
	uint8_t			port_num;
	ib_guid_t		hca_guid, port_guid;
	ib_pkey_t		pkey;
	dev_info_t		*cdip;
	boolean_t		displayed = B_FALSE;
	ibdm_port_attr_t	*port_attr;

	IBTF_DPRINTF_L4("ibnex", "\tconfig_obp_args: %s", devname);

	/* Is this OBP node for IPoIB ? */
	temp = devname;
	do {
		temp = strstr(temp, ",protocol=ip");
		if (temp == NULL)
			break;

		if (strlen(devname) > (int)((temp - devname) + 12)) {
			if (temp[12] == ',')
				break;
		} else {
			break;
		}
		temp++;
	} while (temp);

	if (temp == NULL)
		return (NULL);
	if (ibnex_prom_devname_to_pkey_n_portnum(
	    devname, &pkey, &port_num) != IBNEX_SUCCESS) {
		return (NULL);
	}
	for (index = 0; index < ibnex.ibnex_nvppa_comm_svcs; index++) {
		if (strcmp(ibnex.ibnex_vppa_comm_svc_names[index],
		    "ipib") == 0) {
			break;
		}
	}

	hca_guid = ibtl_ibnex_hcadip2guid(parent);
	if ((port_attr = ibdm_ibnex_probe_hcaport(
	    hca_guid, port_num)) == NULL) {
		IBTF_DPRINTF_L2("ibnex",
		    "\tconfig_port_node: Port does not exist");
		return (NULL);
	}

	/* Wait until "port is up" */
	while (port_attr->pa_state != IBT_PORT_ACTIVE) {
		ibdm_ibnex_free_port_attr(port_attr);
		delay(drv_usectohz(10000));
		if ((port_attr = ibdm_ibnex_probe_hcaport(
		    hca_guid, port_num)) == NULL) {
			return (NULL);
		}
		if (iter++ == 400) {
			if (displayed == B_FALSE) {
				cmn_err(CE_NOTE, "\tWaiting for Port %d "
				    "initialization", port_attr->pa_port_num);
				displayed = B_TRUE;
			}
		}
	}
	IBTF_DPRINTF_L4("ibnex", "\tPort is initialized");

	mutex_enter(&ibnex.ibnex_mutex);
	port_guid = port_attr->pa_port_guid;
	rval = ibnex_get_dip_from_guid(port_guid, index, pkey, &cdip);
	if (rval == IBNEX_SUCCESS && cdip != NULL) {
		IBTF_DPRINTF_L4("ibnex", "\tconfig_port_node: Node exists");
		mutex_exit(&ibnex.ibnex_mutex);
		ibdm_ibnex_free_port_attr(port_attr);
		return (cdip);
	}
	for (ii = 0; ii < port_attr->pa_npkeys; ii++) {
		if (pkey == port_attr->pa_pkey_tbl[ii].pt_pkey) {
			cdip = ibnex_commsvc_initnode(parent, port_attr,
			    index, IBNEX_VPPA_COMMSVC_NODE, pkey, &rval,
			    IBNEX_CFGADM_ENUMERATE);
			IBTF_DPRINTF_L5("ibnex",
			    "\t ibnex_commsvc_initnode rval %x", rval);
			break;
		}
	}
	mutex_exit(&ibnex.ibnex_mutex);

	ibdm_ibnex_free_port_attr(port_attr);
	return (cdip);
}


/*
 * ibnex_prom_devname_to_pkey_n_portnum()
 *	Parses the device node name and extracts "PKEY" and "port#"
 *	Returns IBNEX_SUCCESS/IBNEX_FAILURE
 */
static int
ibnex_prom_devname_to_pkey_n_portnum(
    char *devname, ib_pkey_t *pkey, uint8_t *port)
{
	int	ret = IBNEX_SUCCESS;
	char	*tmp, *tmp1;

	if ((tmp = strstr(devname, "port=")) != NULL) {
		if ((tmp = strchr(++tmp, '=')) != NULL)
			if ((tmp1 = strchr(++tmp, ',')) != NULL)
				*port = ibnex_str2int(tmp, (tmp1 - tmp), &ret);
	} else
		ret = IBNEX_FAILURE;

	if ((ret == IBNEX_SUCCESS) &&
	    (tmp = strstr(devname, "pkey=")) != NULL) {
		if ((tmp = strchr(++tmp, '=')) != NULL)
			if ((tmp1 = strchr(++tmp, ',')) != NULL)
				*pkey = ibnex_str2hex(tmp, (tmp1 - tmp), &ret);
	} else
		ret = IBNEX_FAILURE;

	return (ret);
}

static ibnex_node_data_t *
ibnex_get_cdip_info(dev_info_t *parent,
    char *devname, dev_info_t **cdip, ibnex_node_type_t *type)
{
	char 			*device_name, *cname = NULL, *caddr = NULL;
	int			len;
	ibnex_node_data_t	*node_data = NULL;

	len = strlen((char *)devname) + 1;
	device_name = i_ddi_strdup(devname, KM_SLEEP);
	i_ddi_parse_name(device_name, &cname, &caddr, NULL);

	IBTF_DPRINTF_L4("ibnex",
	    "\tfind_child_dip: cname %s addr %s", cname, caddr);

	if (strncmp(cname, IBNEX_IOC_CNAME, 3) ==  0)
		*type = IBNEX_IOC_NODE;
	else if (strncmp(cname, IBNEX_IBPORT_CNAME, 3) ==  0)
		*type = IBNEX_HCA_CHILD_NODE;
	else
		*type = IBNEX_PSEUDO_NODE;

	*cdip = ndi_devi_findchild(parent, devname);

	IBTF_DPRINTF_L4("ibnex",
	    "\tfind_child_dip: cdip %p type %x", *cdip, *type);

	if (*cdip)
		node_data = ddi_get_parent_data(*cdip);
	kmem_free(device_name, len);

	return (node_data);
}

static int
ibnex_hca_bus_config_one(dev_info_t *parent, void *devname,
    ddi_bus_config_op_t op, uint_t *flag, dev_info_t **child)
{
	int			ret = IBNEX_SUCCESS, len, circ, need_bus_config;
	char 			*device_name, *caddr, *cname;
	dev_info_t		*cdip;
	ibnex_node_data_t	*node_data;
	ibnex_node_type_t	node_type;
	int			index;
	uint8_t			port_num;
	ib_pkey_t		pkey;

	len = strlen((char *)devname) + 1;
	device_name = i_ddi_strdup(devname, KM_SLEEP);
	i_ddi_parse_name(device_name, &cname, &caddr, NULL);

	if (caddr == NULL || (strlen(caddr) == 0)) {
		IBTF_DPRINTF_L2("ibnex",
		    "\thca_bus_config: Invalid device node address");
		kmem_free(device_name, len);
		return (IBNEX_FAILURE);
	}

	ndi_devi_enter(parent, &circ);
	node_data = ibnex_get_cdip_info(
	    parent, devname, &cdip, &node_type);
	ndi_devi_exit(parent, circ);

	if (cdip) {
		if ((node_data) && (node_data->node_type ==
		    IBNEX_PORT_COMMSVC_NODE)) {
			if (node_data->node_dip == NULL) {
				node_data->node_dip = cdip;
				node_data->node_data.port_node.port_pdip =
				    parent;
			}
		}
	}

	/*
	 * If child dip is present, just return
	 * from here.
	 */
	if (cdip != NULL || (node_data != NULL &&
	    node_data->node_dip != NULL)) {
		goto end;
	}

	switch (node_type) {

	case IBNEX_IOC_NODE:
		ret = ibnex_ioc_bus_config_one(&parent, *flag,
		    op, devname, child, &need_bus_config);
		if (!need_bus_config) {
			kmem_free(device_name, len);
			return (ret);
		}
		break;

	case IBNEX_PSEUDO_NODE:
		ret = IBNEX_SUCCESS;
		mdi_devi_enter(parent, &circ);
		ibnex_pseudo_initnodes();
		mutex_enter(&ibnex.ibnex_mutex);
		ret = ibnex_pseudo_config_one(NULL,
		    caddr, parent);
		mutex_exit(&ibnex.ibnex_mutex);
		mdi_devi_exit(parent, circ);
		break;

	default:
		if (ibnex_get_pkey_commsvc_index_portnum(devname,
		    &index, &pkey, &port_num) != IBNEX_SUCCESS) {
			IBTF_DPRINTF_L2("ibnex",
			    "\tconfig_port_node: Invalid Service Name");
			kmem_free(device_name, len);
			return (IBNEX_FAILURE);
		}

		if ((pkey != 0) && (port_num != 0)) {
			if (strcmp("ipib",
			    ibnex.ibnex_vppa_comm_svc_names[index]) == 0) {
				IBTF_DPRINTF_L2("ibnex",
				    "Skipping IBD devices... ");
				break;
			}
		}

		ndi_devi_enter(parent, &circ);
		cdip = ibnex_config_port_node(parent, devname);
		if (cdip)
			ret = IBNEX_SUCCESS;
		else
			ret = IBNEX_FAILURE;
		ndi_devi_exit(parent, circ);
		break;
	}
end:
	if (node_type == IBNEX_HCA_CHILD_NODE) {
		/* Allows enumeration under PHCI */
		*flag |= NDI_MDI_FALLBACK;
	}
	kmem_free(device_name, len);
	return (ret);
}

void
ibnex_handle_hca_attach(void *cb_arg)
{
	ib_guid_t hca_guid	= *((ib_guid_t *)cb_arg);
	dev_info_t		*phci;
	int			ii, circ;
	ibdm_hca_list_t		*hca_list;

	IBTF_DPRINTF_L4("ibnex", "handle_hca_attach(%llx)", hca_guid);

	phci = ibtl_ibnex_hcaguid2dip(hca_guid);

	/*
	 * Enumerate children of this HCA, port nodes,
	 * VPPA & HCA_SVC nodes. Use ndi_devi_enter() for
	 * locking. IB Nexus is enumerating the children
	 * of HCA, not MPXIO clients.
	 */
	ndi_devi_enter(phci, &circ);
	ibdm_ibnex_port_settle_wait(hca_guid, ibnex_port_settling_time);
	hca_list = ibdm_ibnex_get_hca_info_by_guid(hca_guid);
	if (hca_list == NULL) {
		ndi_devi_exit(phci, circ);
		kmem_free(cb_arg, sizeof (ib_guid_t));
		return;
	}
	ibnex_create_hcasvc_nodes(phci, hca_list->hl_hca_port_attr);
	for (ii = 0; ii < hca_list->hl_nports; ii++) {
		ibnex_create_port_nodes(phci, &hca_list->hl_port_attr[ii]);
		ibnex_create_vppa_nodes(phci, &hca_list->hl_port_attr[ii]);
	}
	ibdm_ibnex_free_hca_list(hca_list);
	ndi_devi_exit(phci, circ);
	kmem_free(cb_arg, sizeof (ib_guid_t));
}
