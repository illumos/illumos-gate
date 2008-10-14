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


#include "cfga_fp.h"

/* Function prototypes */

static fpcfga_ret_t get_xport_devlink(const char *hba_phys,
    char **hba_logpp, int *l_errnop);
static char ctoi(char c);
static fpcfga_ret_t is_apid_configured(const char *xport_phys,
	const char *dyncomp, struct luninfo_list **lunlistpp, int *l_errnop);
static fpcfga_ret_t insert_lun_to_lunlist(struct luninfo_list **lunlistpp,
	const char *dyncomp, di_node_t devnode, int *l_errnop);
static fpcfga_ret_t update_lunlist(struct luninfo_list **lunlistpp, int lun,
	uint_t	state, char *pathp, int	*l_errnop);


/* Globals */

/* Various conversions routines */

void
cvt_lawwn_to_dyncomp(const la_wwn_t *pwwn, char **dyncomp, int *l_errnop)
{
	*dyncomp = calloc(1, WWN_SIZE*2 + 1);
	if (*dyncomp == NULL) {
		*l_errnop = errno;
	}

	(void) sprintf(*dyncomp, "%016llx",
	(wwnConversion((uchar_t *)pwwn->raw_wwn)));
}


int
cvt_dyncomp_to_lawwn(const char *dyncomp, la_wwn_t *port_wwn)
{
	int	i;
	char	c, c1;
	uchar_t	*wwnp;

	wwnp = port_wwn->raw_wwn;
	for (i = 0; i < WWN_SIZE; i++, wwnp++) {

		c = ctoi(*dyncomp++);
		c1 = ctoi(*dyncomp++);
		if (c == -1 || c1 == -1)
			return (-1);
		*wwnp = ((c << 4) + c1);
	}

	return (0);
}


static char
ctoi(char c)
{
	if ((c >= '0') && (c <= '9'))
		c -= '0';
	else if ((c >= 'A') && (c <= 'F'))
		c = c - 'A' + 10;
	else if ((c >= 'a') && (c <= 'f'))
		c = c - 'a' + 10;
	else
		c = -1;
	return (c);
}


/*
 * Generates the HBA logical ap_id from physical ap_id.
 */
fpcfga_ret_t
make_xport_logid(const char *xport_phys, char **xport_logpp, int *l_errnop)
{
	if (*xport_logpp != NULL) {
		return (FPCFGA_ERR);
	}

	/*
	 * A devlink for the XPORT should exist.  Without the /dev/cfg link
	 * driver name and instance number based based link needs to be
	 * constructed for the minor node type of DDI_NT_FC_ATTACHMENT_POINT.
	 * sunddi.h defines DDI_NT_FC_ATTACHMENT_POINT for
	 * ddi_ctl:attachment_point:fc
	 */
	if (get_xport_devlink(xport_phys, xport_logpp, l_errnop) == FPCFGA_OK) {
		assert(*xport_logpp != NULL);
		return (FPCFGA_OK);
	} else {
		return (FPCFGA_ERR);
	}
}

static fpcfga_ret_t
get_xport_devlink(const char *xport_phys, char **xport_logpp, int *l_errnop)
{
	int match_minor;
	size_t len;
	fpcfga_ret_t ret;

	match_minor = 1;
	ret = physpath_to_devlink(CFGA_DEV_DIR, (char *)xport_phys,
	    xport_logpp, l_errnop, match_minor);
	if (ret != FPCFGA_OK) {
		return (ret);
	}

	assert(*xport_logpp != NULL);

	/* Remove the "/dev/cfg/"  prefix */
	len = strlen(CFGA_DEV_DIR SLASH);

	(void) memmove(*xport_logpp, *xport_logpp + len,
	    strlen(*xport_logpp + len) + 1);

	return (FPCFGA_OK);
}


/*
 * Given a xport path and dynamic ap_id, returns the physical
 * path in pathpp.  If the dynamic ap is not configured pathpp set to NULL
 * and returns FPCFGA_APID_NOCONFIGURE.
 */
fpcfga_ret_t
dyn_apid_to_path(
	const char *xport_phys,
	const char *dyncomp,
	struct luninfo_list **lunlistpp,
	int *l_errnop)
{
	fpcfga_ret_t 	ret;

	/* A device MUST have a dynamic component */
	if (dyncomp == NULL) {
		return (FPCFGA_LIB_ERR);
	}

	ret = is_apid_configured(xport_phys, dyncomp, lunlistpp, l_errnop);

	assert(ret != FPCFGA_OK);

	return (ret);
}

/*
 * When both the transport and dynamic comp are given this function
 * checks to see if the dynamic ap is configured on the dev tree.
 * If it is configured the devfs path will be stored in pathpp.
 * When the dynamic comp is null this function check to see if the transport
 * node has any child.
 *
 * Retrun value: FPCFGA_OK if the apid is configured.
 *		 FPCFGA_APID_NOCONFIGURE if the apid is not configured.
 *		 FPCFGA_LIB_ERR for other errors.
 */
static fpcfga_ret_t
is_apid_configured(
	const char *xport_phys,
	const char *dyncomp,
	struct luninfo_list **lunlistpp,
	int *l_errnop)
{
	char 		*devfs_phys, *devfs_fp_path, *client_path, *cp,
			*pathp = NULL;
	char 		path_name[MAXPATHLEN];
	di_node_t	tree_root, root, fpnode, dev_node, client_node;
	di_path_t 	path = DI_PATH_NIL;
	di_prop_t	prop = DI_PROP_NIL;
	uchar_t		*port_wwn_data = NULL;
	char		*lun_guid = NULL;
	char		port_wwn[WWN_SIZE*2+1];
	int		count, *lunnump, devlen,
			found_fp = 0;
	uint_t		state;
	uint_t		statep;
	fpcfga_ret_t 	ret;

	if (*lunlistpp != NULL) {
		return (FPCFGA_LIB_ERR);
	}

	ret = FPCFGA_APID_NOCONFIGURE;

	if ((devfs_phys = strdup(xport_phys)) == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	if (strncmp(devfs_phys, DEVICES_DIR SLASH, strlen(DEVICES_DIR) +
			strlen(SLASH)) == 0) {
		cp = devfs_phys + strlen(DEVICES_DIR);
		(void) memmove(devfs_phys, cp, strlen(cp) + 1);
	}

	if ((cp = strstr(devfs_phys, MINOR_SEP)) != NULL) {
		*cp = '\0';  /* Terminate string. */
	}

	if ((tree_root = di_init("/", DINFOCPYALL | DINFOPATH))
			== DI_NODE_NIL) {
		*l_errnop = errno;
		S_FREE(devfs_phys);
		return (FPCFGA_LIB_ERR);
	}

	fpnode = di_drv_first_node("fp", tree_root);

	while (fpnode) {
		devfs_fp_path = di_devfs_path(fpnode);
		if ((devfs_fp_path) && !(strncmp(devfs_fp_path,
				devfs_phys, strlen(devfs_phys)))) {
			found_fp = 1;
			di_devfs_path_free(devfs_fp_path);
			break;
		}
		di_devfs_path_free(devfs_fp_path);
		fpnode = di_drv_next_node(fpnode);
	}
	if (!(found_fp)) {
		ret = FPCFGA_LIB_ERR;
		goto out;
	} else {
		root = fpnode;
	}

	/*
	 * when there is no child and path info node the
	 * FPCFGA_APID_NOCONFIGURE is returned
	 * regardless of the dynamic comp.
	 */
	dev_node = di_child_node(root);
	path = di_path_next_client(root, path);
	if ((dev_node == DI_NODE_NIL) && (path == DI_PATH_NIL)) {
		*l_errnop = errno;
		ret = FPCFGA_APID_NOCONFIGURE;
		goto out;
	}

	/*
	 * when dyn comp is null the function just checks if there is any
	 * child under fp transport attachment point.
	 */
	if (dyncomp == NULL) {
		ret = FPCFGA_OK;
		goto out;
	}

	/*
	 * now checks the children node to find
	 * if dynamic ap is configured. if there are multiple luns
	 * store into lunlist.
	 */
	if (dev_node != DI_NODE_NIL) {
		do {
			while ((prop = di_prop_next(dev_node, prop)) !=
					DI_PROP_NIL) {
				/* is property name port-wwn */
				if ((!(strcmp(PORT_WWN_PROP,
					di_prop_name(prop)))) &&
					(di_prop_type(prop) ==
					DI_PROP_TYPE_BYTE)) {
					break;
				}
			}

			if (prop != DI_PROP_NIL) {
				count = di_prop_bytes(prop, &port_wwn_data);
				if (count != WWN_SIZE) {
					ret = FPCFGA_LIB_ERR;
					goto out;
				} else {
					(void) sprintf(port_wwn,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
					port_wwn_data[0], port_wwn_data[1],
					port_wwn_data[2], port_wwn_data[3],
					port_wwn_data[4], port_wwn_data[5],
					port_wwn_data[6], port_wwn_data[7]);
					if (!(strncmp(port_wwn, dyncomp,
							WWN_SIZE*2))) {
						ret = insert_lun_to_lunlist(
							lunlistpp, dyncomp,
							dev_node, l_errnop);
						if (ret != FPCFGA_OK) {
							goto out;
						}
					}
				}
			}
			dev_node = di_sibling_node(dev_node);
			prop = DI_PROP_NIL;
		} while (dev_node != DI_NODE_NIL);
	}

	/*
	 * now checks the path info node to find
	 * if dynamic ap is configured. if there are multiple luns
	 * store into lunlist.
	 */
	if (path != DI_PATH_NIL) {
		/*
		 * now parse the path info node.
		 */
		do {
			count = di_path_prop_lookup_bytes(path, PORT_WWN_PROP,
				&port_wwn_data);
			if (count != WWN_SIZE) {
				ret = FPCFGA_LIB_ERR;
				goto out;
			}

			(void) sprintf(port_wwn,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
				port_wwn_data[0], port_wwn_data[1],
				port_wwn_data[2], port_wwn_data[3],
				port_wwn_data[4], port_wwn_data[5],
				port_wwn_data[6], port_wwn_data[7]);

			/* if matches get the path of scsi_vhci child node. */
			if (!(strncmp(port_wwn, dyncomp, WWN_SIZE*2))) {
				client_node = di_path_client_node(path);
				if (client_node == DI_NODE_NIL) {
					ret = FPCFGA_LIB_ERR;
					*l_errnop = errno;
					goto out;
				}
				count = di_path_prop_lookup_ints(path,
						LUN_PROP, &lunnump);
				client_path = di_devfs_path(client_node);
				strcpy(path_name, client_path);
				di_devfs_path_free(client_path);
				state = di_state(client_node);
				statep = di_path_state(path);

				/*
				 * If the node is
				 * state then check the devfs_path to
				 * see if it has a complete path.
				 * For non scsi_vhci node the path
				 * doesn't contain @w(portwwn) part
				 * consistently.  For scsi_vhci
				 * this behavior may not be there.
				 * To be safe @g(guid) is attempted
				 * to be added here.
				 */
				if ((state & DI_DRIVER_DETACHED) &&
					(strstr(path_name, "@g") == NULL)) {
					prop = DI_PROP_NIL;
					while ((prop = di_prop_next(client_node,
							prop)) != DI_PROP_NIL) {
						/* is property name lun-wwn */
						if ((!(strcmp(LUN_GUID_PROP,
							di_prop_name(prop)))) &&
							(di_prop_type(prop) ==
							DI_PROP_TYPE_STRING)) {
							break;
						}
					}

					if (prop != DI_PROP_NIL) {
						count = di_prop_strings(
							prop, &lun_guid);
						sprintf(&path_name[
							strlen(path_name)],
							"@g%s", lun_guid);
					} else {
						ret = FPCFGA_LIB_ERR;
						goto out;
					}
				}

				devlen = strlen(DEVICES_DIR) +
						strlen(path_name) + 1;
				if ((pathp = calloc(1, devlen))
						== NULL) {
					*l_errnop = errno;
					return (FPCFGA_LIB_ERR);
				} else {
					(void) snprintf(pathp, devlen,
					"%s%s", DEVICES_DIR, path_name);
				}
				if ((ret = (update_lunlist(lunlistpp, *lunnump,
						statep, pathp, l_errnop))) !=
						FPCFGA_OK) {
					S_FREE(pathp);
					goto out;
				}
			}
			path = di_path_next_client(root, path);
		} while (path != DI_PATH_NIL);
	}

out:
	di_fini(tree_root);
	S_FREE(devfs_phys);
	return (ret);
}

static fpcfga_ret_t
insert_lun_to_lunlist(
	struct luninfo_list **lunlistpp,
	const char *dyncomp,
	di_node_t dev_node,
	int *l_errnop)
{
	char		path_name[MAXPATHLEN];
	char 		*pathp, *dev_phys;
	di_prop_t	prop_lun = DI_PROP_NIL;
	uint_t 		state;
	int		count, devlen;
	int		*lunp;

	while ((prop_lun = di_prop_next(dev_node, prop_lun)) != DI_PROP_NIL) {
		if (!(strcmp(LUN_PROP, di_prop_name(prop_lun))) &&
				(di_prop_type(prop_lun) == DI_PROP_TYPE_INT)) {
			count = di_prop_ints(prop_lun, &lunp);
			if (count <= 0) {
				return (FPCFGA_LIB_ERR);
			}
			break;
		}
	}

	if (prop_lun == DI_PROP_NIL) {
		return (FPCFGA_LIB_ERR);
	}

	/*
	 * stores state info in state.
	 * This information is used to get the
	 * validity of path.
	 * if driver_detached don't try to get
	 * the devfs_path since it is not
	 * complete. ex, /pci@1f,2000/pci@1/
	 * SUNW,qlc@5/fp@0,0/ssd
	 * which doesn't contain the port wwn
	 * part.  The attached node looks like
	 * /pci@1f,2000/pci@1/SUNW,qlc@5/fp@0,0/
	 * ssd@w2100002037006b14,0
	 */
	state = di_state(dev_node);

	dev_phys = di_devfs_path(dev_node);
	if (dev_phys == NULL) {
		return (FPCFGA_LIB_ERR);
	}

	strcpy(path_name, dev_phys);

	di_devfs_path_free(dev_phys);

	if ((state & DI_DRIVER_DETACHED) &&
		(strstr(path_name, "@w") == NULL)) {
		sprintf(&path_name[strlen(path_name)], "@w%s,%x", dyncomp,
									*lunp);
	}

	devlen = strlen(DEVICES_DIR) + strlen(path_name) + 1;

	if ((pathp = calloc(1, devlen))
			== NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	} else {
		(void) snprintf(pathp, devlen, "%s%s", DEVICES_DIR, path_name);
	}

	return (update_lunlist(lunlistpp, *lunp, state, pathp, l_errnop));
}

static fpcfga_ret_t
update_lunlist(
	struct luninfo_list **lunlistpp,
	int	lun,
	uint_t	state,
	char 	*pathp,
	int 	*l_errnop)
{
	struct luninfo_list *newlun, *curlun, *prevlun;

	newlun = curlun = prevlun = (struct luninfo_list *)NULL;

	newlun = calloc(1, sizeof (struct luninfo_list));
	if (newlun == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	newlun->lunnum = lun;
	newlun->node_state = state;
	newlun->path = pathp;
	newlun->next = (struct luninfo_list *)NULL;

	/* if lunlist is empty add the new lun info and return. */
	if (*lunlistpp == NULL) {
		*lunlistpp = newlun;
		return (FPCFGA_OK);
	}

	/* if the first lun in the list is the same as the new lun return. */
	if ((*lunlistpp)->lunnum == lun) {
		S_FREE(newlun);
		return (FPCFGA_OK);
	}

	/*
	 * if the first lun in the list is less than the new lun add the
	 * new lun as the first lun and return.
	 */
	if ((*lunlistpp)->lunnum < lun) {
		newlun->next = *lunlistpp;
		*lunlistpp = newlun;
		return (FPCFGA_OK);
	}

	/*
	 * if the first lun in the list is greater than the new lun and
	 * there is a single lun add new lun after the first lun and return.
	 */
	if ((*lunlistpp)->next == NULL) {
		(*lunlistpp)->next = newlun;
		return (FPCFGA_OK);
	}

	/*
	 * now there is more than two luns in the list and the first lun
	 * is greter than the input lun.
	 */
	curlun = (*lunlistpp)->next;
	prevlun = *lunlistpp;

	while (curlun != NULL) {
		if (curlun->lunnum == lun) {
			S_FREE(newlun);
			return (FPCFGA_OK);
		} else if (curlun->lunnum < lun) {
			newlun->next = curlun;
			prevlun->next = newlun;
			return (FPCFGA_OK);
		} else {
			prevlun = curlun;
			curlun = curlun->next;
		}
	}

	/* add the new lun at the end of list. */
	prevlun->next = newlun;
	return (FPCFGA_OK);

}


fpcfga_ret_t
make_dyncomp_from_dinode(
	const di_node_t node,
	char **dyncompp,
	int *l_errnop)
{
	di_prop_t	prop = DI_PROP_NIL;
	uchar_t		*port_wwn_data;
	int		count;

	*l_errnop = 0;
	*dyncompp = calloc(1, WWN_SIZE*2 + 1);
	if (*dyncompp == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	/* now get port-wwn for the input node. */
	while ((prop = di_prop_next(node, prop)) != DI_PROP_NIL) {
		if (!(strcmp(PORT_WWN_PROP, di_prop_name(prop))) &&
			(di_prop_type(prop) == DI_PROP_TYPE_BYTE)) {
			break;
		}
	}

	if (prop != DI_PROP_NIL) {
		count = di_prop_bytes(prop, &port_wwn_data);
		if (count != WWN_SIZE) {
			S_FREE(*dyncompp);
			return (FPCFGA_LIB_ERR);
		}

		(void) sprintf(*dyncompp, "%016llx",
			(wwnConversion(port_wwn_data)));
	} else {
		*l_errnop = errno;
		S_FREE(*dyncompp);
		return (FPCFGA_LIB_ERR);
	}

	return (FPCFGA_OK);
}

fpcfga_ret_t
make_portwwn_luncomp_from_dinode(
	const di_node_t node,
	char **dyncompp,
	int **luncompp,
	int *l_errnop)
{
	uchar_t		*port_wwn_data;
	int		pwwn_ret, lun_ret;

	*l_errnop = 0;

	if ((dyncompp != NULL) &&
			((pwwn_ret = di_prop_lookup_bytes(DDI_DEV_T_ANY,
			node, PORT_WWN_PROP, &port_wwn_data)) <= 0)) {
		*l_errnop = errno;
	}
	if ((luncompp != NULL) &&
			((lun_ret = di_prop_lookup_ints(DDI_DEV_T_ANY,
			node, LUN_PROP, luncompp)) <= 0)) {
		*l_errnop = errno;
	}

	/*
	 * di_prop* returns the number of entries found or 0 if not found
	 * or -1 for othere failure.
	 */
	if ((pwwn_ret <= 0) || (lun_ret <= 0)) {
		return (FPCFGA_LIB_ERR);
	}

	*dyncompp = calloc(1, WWN_SIZE*2+1);
	if (*dyncompp == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	(void) sprintf(*dyncompp, "%016llx", (wwnConversion(port_wwn_data)));

	return (FPCFGA_OK);
}

fpcfga_ret_t
make_portwwn_luncomp_from_pinode(
	const di_path_t pinode,
	char **dyncompp,
	int **luncompp,
	int *l_errnop)
{
	uchar_t		*port_wwn_data;
	int		pwwn_ret, lun_ret;

	*l_errnop = 0;

	if ((dyncompp != NULL) &&
			((pwwn_ret = di_path_prop_lookup_bytes(pinode,
			PORT_WWN_PROP, &port_wwn_data)) <= 0)) {
		*l_errnop = errno;
	}
	if ((luncompp != NULL) &&
			((lun_ret = di_path_prop_lookup_ints(pinode,
			LUN_PROP, luncompp)) <= 0)) {
		*l_errnop = errno;
	}

	/*
	 * di_prop* returns the number of entries found or 0 if not found
	 * or -1 for othere failure.
	 */
	if ((pwwn_ret <= 0) || (lun_ret <= 0)) {
		return (FPCFGA_LIB_ERR);
	}

	*dyncompp = calloc(1, WWN_SIZE*2+1);
	if (*dyncompp == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	}

	(void) sprintf(*dyncompp, "%016llx", (wwnConversion(port_wwn_data)));

	return (FPCFGA_OK);
}

fpcfga_ret_t
construct_nodepath_from_dinode(
	const di_node_t node,
	char **node_pathp,
	int *l_errnop)
{
	char *devfs_path, path_name[MAXPATHLEN], *lun_guid, *port_wwn;
	uchar_t *port_wwn_data;
	int is_scsi_vhci_dev, di_ret, devlen;
	uint_t	state;

	devfs_path = di_devfs_path(node);
	strcpy(path_name, devfs_path);
	di_devfs_path_free(devfs_path);
	state = di_state(node);

	is_scsi_vhci_dev = (strstr(path_name, SCSI_VHCI_DRVR) != NULL) ? 1 : 0;

	/*
	 * If the node is
	 * state then check the devfs_path to
	 * see if it has a complete path.
	 * For non scsi_vhci node the path
	 * doesn't contain @w(portwwn) part
	 * consistently.  For scsi_vhci
	 * this behavior may not be there.
	 * To be safe @g(guid) is attempted
	 * to be added here.
	 */
	if (state & DI_DRIVER_DETACHED) {
		if (is_scsi_vhci_dev &&
			(strstr(path_name, "@g") == NULL)) {
			di_ret = di_prop_lookup_strings(DDI_DEV_T_ANY, node,
				LUN_GUID_PROP, &lun_guid);
			if (di_ret == -1) {
				*l_errnop = errno;
				return (FPCFGA_LIB_ERR);
			} else {
				sprintf(&path_name[strlen(path_name)],
					"@g%s", lun_guid);
			}
		} else if (!is_scsi_vhci_dev &&
			(strstr(path_name, "@w") == NULL)) {
			di_ret = di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
				PORT_WWN_PROP, &port_wwn_data);
			if (di_ret == -1) {
				*l_errnop = errno;
				return (FPCFGA_LIB_ERR);
			} else {
				if ((port_wwn = calloc(1, WWN_SIZE*2 + 1))
						== NULL) {
					*l_errnop = errno;
					return (FPCFGA_LIB_ERR);
				}

				(void) sprintf(port_wwn, "%016llx",
					(wwnConversion(port_wwn_data)));
				(void) sprintf(&path_name[strlen(path_name)],
					"@w%s", port_wwn);
				S_FREE(port_wwn);
			}
		}
	}

	devlen = strlen(DEVICES_DIR) + strlen(path_name) + 1;
	if ((*node_pathp = calloc(1, devlen)) == NULL) {
		*l_errnop = errno;
		return (FPCFGA_LIB_ERR);
	} else {
		(void) snprintf(*node_pathp, devlen,
		"%s%s", DEVICES_DIR, path_name);
	}

	return (FPCFGA_OK);
}

u_longlong_t
wwnConversion(uchar_t *wwn)
{
	u_longlong_t tmp;
	memcpy(&tmp, wwn, sizeof (u_longlong_t));
	return (ntohll(tmp));
}
