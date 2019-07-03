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


#include	"cfga_fp.h"

/* define */
#define	ALL_APID_LUNS_UNUSABLE	0x10

#define	DEFAULT_LUN_COUNT	1024
#define	LUN_SIZE		8
#define	LUN_HEADER_SIZE		8
#define	DEFAULT_LUN_LENGTH	DEFAULT_LUN_COUNT   *	\
				LUN_SIZE	    +	\
				LUN_HEADER_SIZE

/* Some forward declarations */
static fpcfga_ret_t do_devctl_dev_create(apid_t *, char *, int,
							uchar_t, char **);
static fpcfga_ret_t dev_rcm_online(apid_t *, int, cfga_flags_t, char **);
static void dev_rcm_online_nonoperationalpath(apid_t *, cfga_flags_t, char **);
static fpcfga_ret_t dev_rcm_offline(apid_t *, cfga_flags_t, char **);
static fpcfga_ret_t dev_rcm_remove(apid_t *, cfga_flags_t, char **);
static fpcfga_ret_t lun_unconf(char *, int, char *, char *, char **);
static fpcfga_ret_t dev_unconf(apid_t *, char **, uchar_t *);
static fpcfga_ret_t is_xport_phys_in_pathlist(apid_t *, char **);
static void copy_pwwn_data_to_str(char *, const uchar_t *);
static fpcfga_ret_t unconf_vhci_nodes(di_path_t, di_node_t, char *,
			char *, int, int *, int *, char **, cfga_flags_t);
static fpcfga_ret_t unconf_non_vhci_nodes(di_node_t, char *, char *,
			int, int *, int *, char **, cfga_flags_t);
static fpcfga_ret_t unconf_any_devinfo_nodes(apid_t *, cfga_flags_t, char **,
			int *, int *);
static fpcfga_ret_t handle_devs(cfga_cmd_t, apid_t *, cfga_flags_t,
			char **, HBA_HANDLE, int, HBA_PORTATTRIBUTES);


/*
 * This function initiates the creation of the new device node for a given
 * port WWN.
 * So, apidt->dyncomp CANNOT be NULL
 */
static fpcfga_ret_t
do_devctl_dev_create(apid_t *apidt, char *dev_path, int pathlen,
					uchar_t dev_dtype, char **errstring)
{
	devctl_ddef_t	ddef_hdl;
	devctl_hdl_t	bus_hdl, dev_hdl;
	char		*drvr_name = "dummy";
	la_wwn_t	pwwn;

	*dev_path = '\0';
	if ((ddef_hdl = devctl_ddef_alloc(drvr_name, 0)) == NULL) {
		cfga_err(errstring, errno, ERRARG_DC_DDEF_ALLOC, drvr_name, 0);
		return (FPCFGA_LIB_ERR);
	}

	if (cvt_dyncomp_to_lawwn(apidt->dyncomp, &pwwn)) {
		devctl_ddef_free(ddef_hdl);
		cfga_err(errstring, 0, ERR_APID_INVAL, 0);
		return (FPCFGA_LIB_ERR);
	}

	if (devctl_ddef_byte_array(ddef_hdl, PORT_WWN_PROP, FC_WWN_SIZE,
							pwwn.raw_wwn) == -1) {
		devctl_ddef_free(ddef_hdl);
		cfga_err(errstring, errno, ERRARG_DC_BYTE_ARRAY,
							PORT_WWN_PROP, 0);
		return (FPCFGA_LIB_ERR);
	}

	if ((bus_hdl = devctl_bus_acquire(apidt->xport_phys, 0)) == NULL) {
		devctl_ddef_free(ddef_hdl);
		cfga_err(errstring, errno, ERRARG_DC_BUS_ACQUIRE,
							apidt->xport_phys, 0);
		return (FPCFGA_LIB_ERR);
	}

	/* Let driver handle creation of the new path */
	if (devctl_bus_dev_create(bus_hdl, ddef_hdl, 0, &dev_hdl)) {
		devctl_ddef_free(ddef_hdl);
		devctl_release(bus_hdl);
		if (dev_dtype == DTYPE_UNKNOWN) {
			/*
			 * Unknown DTYPES are devices such as another system's
			 * FC HBA port. We have tried to configure it but
			 * have failed. Since devices with no device type
			 * or an unknown dtype cannot be configured, we will
			 * return an appropriate error message.
			 */
			cfga_err(errstring, errno,
			    ERRARG_BUS_DEV_CREATE_UNKNOWN, apidt->dyncomp, 0);
		} else {
			cfga_err(errstring, errno, ERRARG_BUS_DEV_CREATE,
			    apidt->dyncomp, 0);
		}
		return (FPCFGA_LIB_ERR);
	}
	devctl_release(bus_hdl);
	devctl_ddef_free(ddef_hdl);

	devctl_get_pathname(dev_hdl, dev_path, pathlen);
	devctl_release(dev_hdl);

	return (FPCFGA_OK);
}

/*
 * Online, in RCM, all the LUNs for a particular device.
 * Caller can specify the # of luns in the lunlist that have to be onlined
 * by passing a count that is not -ve.
 *
 * INPUT :
 * apidt - this is expected to have the list of luns for the device and so
 *         is assumed to be filled in prior to this call
 * count - # of LUNs in the list that have to be onlined.
 * errstring - If non-NULL, it will hold any error messages
 *
 * RETURNS :
 * 0 on success
 * non-zero otherwise
 */
static fpcfga_ret_t
dev_rcm_online(apid_t *apidt, int count, cfga_flags_t flags, char **errstring)
{
	luninfo_list_t	*lunlistp;
	int		i = 0, ret = 0;
	fpcfga_ret_t	retval = FPCFGA_OK;

	/* This check may be redundant, but safer this way */
	if ((apidt->flags & FLAG_DISABLE_RCM) != 0) {
		/* User has requested not to notify RCM framework */
		return (FPCFGA_OK);
	}

	lunlistp = apidt->lunlist;

	for (lunlistp = apidt->lunlist; lunlistp != NULL;
					i++, lunlistp = lunlistp->next) {
		if ((count >= 0) && (i >= count))
			break;
		if (fp_rcm_online(lunlistp->path, errstring, flags) !=
								FPCFGA_OK) {
			ret++;
		}
	}

	if (ret > 0)
		retval = FPCFGA_LIB_ERR;

	return (retval);
}

/*
 * Online in RCM for devices which only have paths
 * not in ONLINE/STANDBY state
 */
void
dev_rcm_online_nonoperationalpath(apid_t *apidt, cfga_flags_t flags,
    char **errstring)
{
	luninfo_list_t	*lunlistp;

	if ((apidt->flags & FLAG_DISABLE_RCM) != 0) {
		return;
	}

	lunlistp = apidt->lunlist;

	for (lunlistp = apidt->lunlist; lunlistp != NULL;
	    lunlistp = lunlistp->next) {
		if ((lunlistp->lun_flag & FLAG_SKIP_ONLINEOTHERS) != 0) {
			continue;
		}
		(void) fp_rcm_online(lunlistp->path, errstring, flags);
	}
}

/*
 * Offline, in RCM, all the LUNs for a particular device.
 * This function should not be called for the MPXIO case.
 *
 * INPUT :
 * apidt - this is expected to have the list of luns for the device and so
 *         is assumed to be filled in prior to this call
 * errstring - If non-NULL, it will hold any error messages
 *
 * RETURNS :
 * FPCFGA_OK on success
 * error code otherwise
 */
static fpcfga_ret_t
dev_rcm_offline(apid_t *apidt, cfga_flags_t flags, char **errstring)
{
	int		count = 0;
	luninfo_list_t	*lunlistp;

	if ((apidt->flags & FLAG_DISABLE_RCM) != 0) {
		/* User has requested not to notify RCM framework */
		return (FPCFGA_OK);
	}

	for (lunlistp = apidt->lunlist; lunlistp != NULL;
						lunlistp = lunlistp->next) {
		if ((lunlistp->lun_flag & FLAG_SKIP_RCMOFFLINE) != 0) {
			continue;
		}
		if ((apidt->flags & FLAG_REMOVE_UNUSABLE_FCP_DEV) ==
		    FLAG_REMOVE_UNUSABLE_FCP_DEV) {
			int ret = strncmp(lunlistp->path, SCSI_VHCI_ROOT,
				strlen(SCSI_VHCI_ROOT));

			if (((ret == 0) &&
			    (lunlistp->node_state == DI_PATH_STATE_OFFLINE)) ||
			    ((ret != 0) &&
			    ((lunlistp->node_state & DI_DEVICE_OFFLINE) ==
			    DI_DEVICE_OFFLINE))) {
				/* Offline the device through RCM */
				if (fp_rcm_offline(lunlistp->path, errstring,
					    flags) != 0) {
					/*
					 * Bring everything back online in
					 * rcm and return
					 */
					(void) dev_rcm_online(apidt, count,
								flags, NULL);
					return (FPCFGA_LIB_ERR);
				}
				count++;
			}
		} else {
			/* Offline the device through RCM */
			if (fp_rcm_offline(lunlistp->path, errstring,
				    flags) != 0) {
				/*
				 * Bring everything back online in
				 * rcm and return
				 */
				(void) dev_rcm_online(apidt, count, flags,
									NULL);
				return (FPCFGA_LIB_ERR);
			}
			count++;
		}
	}
	return (FPCFGA_OK);
}

/*
 * Remove, in RCM, all the LUNs for a particular device.
 * This function should not be called for the MPXIO case.
 *
 * INPUT :
 * apidt - this is expected to have the list of luns for the device and so
 *         is assumed to be filled in prior to this call
 * errstring - If non-NULL, it will hold any error messages
 *
 * RETURNS :
 * FPCFGA_OK on success
 * error code otherwise
 */
static fpcfga_ret_t
dev_rcm_remove(apid_t *apidt, cfga_flags_t flags, char **errstring)
{
	int		count = 0;
	luninfo_list_t	*lunlistp;

	if ((apidt->flags & FLAG_DISABLE_RCM) != 0) {
		/* User has requested not to notify RCM framework */
		return (FPCFGA_OK);
	}

	for (lunlistp = apidt->lunlist; lunlistp != NULL;
						lunlistp = lunlistp->next) {
		if ((lunlistp->lun_flag & FLAG_SKIP_RCMREMOVE) != 0)
			continue;
		if ((apidt->flags & FLAG_REMOVE_UNUSABLE_FCP_DEV) ==
		    FLAG_REMOVE_UNUSABLE_FCP_DEV) {
			int ret = strncmp(lunlistp->path, SCSI_VHCI_ROOT,
				strlen(SCSI_VHCI_ROOT));

			if (((ret == 0) &&
			    (lunlistp->node_state == DI_PATH_STATE_OFFLINE)) ||
			    ((ret != 0) &&
			    ((lunlistp->node_state & DI_DEVICE_OFFLINE) ==
			    DI_DEVICE_OFFLINE))) {
				/* remove the device through RCM */
				if (fp_rcm_remove(lunlistp->path, errstring,
					    flags) != 0) {
					/*
					 * Bring everything back online in
					 * rcm and return
					 */
					(void) dev_rcm_online(apidt, count,
								flags, NULL);
					return (FPCFGA_LIB_ERR);
				}
				count++;
			}
		} else {
			/* remove the device through RCM */
			if (fp_rcm_remove(lunlistp->path, errstring,
				flags) != 0) {
				/*
				 * Bring everything back online in rcm and
				 * return
				 */
				(void) dev_rcm_online(apidt, count, flags,
									NULL);
				return (FPCFGA_LIB_ERR);
			}
			count++;
		}
	}
	return (FPCFGA_OK);
}

static fpcfga_ret_t
lun_unconf(char *path, int lunnum, char *xport_phys, char *dyncomp,
						char **errstring)
{
	devctl_hdl_t	hdl;
	char		*ptr;		/* To use as scratch/temp pointer */
	char		pathname[MAXPATHLEN];

	if (path == NULL)
		return (FPCFGA_OK);

	if (strncmp(path, SCSI_VHCI_ROOT, strlen(SCSI_VHCI_ROOT)) == 0) {
		/*
		 * We have an MPXIO managed device here.
		 * So, we have to concoct a path for the device.
		 *
		 * xport_phys looks like :
		 * /devices/pci@b,2000/pci@1/SUNW,qlc@5/fp@0,0:fc
		 */
		(void) strlcpy(pathname, xport_phys, MAXPATHLEN);
		if ((ptr = strrchr(pathname, ':')) != NULL) {
			*ptr = '\0';
		}

		/*
		 * Get pointer to driver name from VHCI path
		 * So, if lunlistp->path is
		 * /devices/scsi_vhci/ssd@g220000203707a417,
		 * we need a pointer to the last '/'
		 *
		 * Assumption:
		 * With MPXIO there will be only one entry per lun
		 * So, there will only be one entry in the linked list
		 * apidt->lunlist
		 */
		if ((ptr = strrchr(path, '/')) == NULL) {
			/* This shouldn't happen, but anyways ... */
			cfga_err(errstring, 0, ERRARG_INVALID_PATH, path, 0);
			return (FPCFGA_LIB_ERR);
		}

		/*
		 * Make pathname to look something like :
		 * /devices/pci@x,xxxx/pci@x/SUNW,qlc@x/fp@x,x/ssd@w...
		 */
		strcat(pathname, ptr);

		/*
		 * apidt_create() will make sure that lunlist->path
		 * has a "@<something>" at the end even if the driver
		 * state is "detached"
		 */
		if ((ptr = strrchr(pathname, '@')) == NULL) {
			/* This shouldn't happen, but anyways ... */
			cfga_err(errstring, 0, ERRARG_INVALID_PATH,
						pathname, 0);
			return (FPCFGA_LIB_ERR);
		}
		*ptr = '\0';

		/* Now, concoct the path */
		sprintf(&pathname[strlen(pathname)], "@w%s,%x",
							dyncomp, lunnum);
		ptr = pathname;
	} else {
		/*
		 * non-MPXIO path, use the path that is passed in
		 */
		ptr = path;
	}

	if ((hdl = devctl_device_acquire(ptr,  0)) == NULL) {
		cfga_err(errstring, errno, ERRARG_DEV_ACQUIRE, ptr, 0);
		return (FPCFGA_LIB_ERR);
	}

	if (devctl_device_remove(hdl) != 0) {
		devctl_release(hdl);
		cfga_err(errstring, errno, ERRARG_DEV_REMOVE, ptr, 0);
		return (FPCFGA_LIB_ERR);
	}
	devctl_release(hdl);

	return (FPCFGA_OK);
}

static fpcfga_ret_t
dev_unconf(apid_t *apidt, char **errstring, uchar_t *flag)
{
	luninfo_list_t	*lunlistp;
	fpcfga_ret_t	ret = FPCFGA_OK;
	int lun_cnt = 0, unusable_lun_cnt = 0;

	for (lunlistp = apidt->lunlist; lunlistp != NULL;
	    lunlistp = lunlistp->next) {
		lun_cnt++;
		/*
		 * Unconfigure each LUN.
		 * Note that for MPXIO devices, lunlistp->path will be a
		 * vHCI path
		 */
		if ((apidt->flags & FLAG_REMOVE_UNUSABLE_FCP_DEV) ==
			FLAG_REMOVE_UNUSABLE_FCP_DEV) {
		    if (strncmp(lunlistp->path, SCSI_VHCI_ROOT,
			strlen(SCSI_VHCI_ROOT)) == 0) {
			if (lunlistp->node_state ==
				DI_PATH_STATE_OFFLINE) {
			    unusable_lun_cnt++;
			    if ((ret = lun_unconf(lunlistp->path,
				lunlistp->lunnum, apidt->xport_phys,
				apidt->dyncomp, errstring)) != FPCFGA_OK) {
				return (ret);
			    }
			}
		    } else {
			if ((lunlistp->node_state & DI_DEVICE_OFFLINE) ==
				DI_DEVICE_OFFLINE) {
			    unusable_lun_cnt++;
			    if ((ret = lun_unconf(lunlistp->path,
				lunlistp->lunnum, apidt->xport_phys,
				apidt->dyncomp, errstring)) != FPCFGA_OK) {
				return (ret);
			    }
			}
		    }
		} else {
		/*
		 * Unconfigure each LUN.
		 * Note that for MPXIO devices, lunlistp->path will be a
		 * vHCI path
		 */
		    if ((ret = lun_unconf(lunlistp->path, lunlistp->lunnum,
				apidt->xport_phys, apidt->dyncomp,
				errstring)) != FPCFGA_OK) {
			return (ret);
		    }
		}
	}

	if ((apidt->flags & FLAG_REMOVE_UNUSABLE_FCP_DEV) ==
			FLAG_REMOVE_UNUSABLE_FCP_DEV) {
		/*
		 * when all luns are unconfigured
		 * indicate to remove repository entry.
		 */
		if (lun_cnt == unusable_lun_cnt) {
			*flag = ALL_APID_LUNS_UNUSABLE;
		}
	}

	return (ret);
}

/*
 * Check if the given physical path (the xport_phys) is part of the
 * pHCI list and if the RCM should be done for a particular pHCI.
 * Skip non-MPxIO dev node if any.
 */
static fpcfga_ret_t
is_xport_phys_in_pathlist(apid_t *apidt, char **errstring)
{
	di_node_t	root, vhci, node, phci;
	di_path_t	path = DI_PATH_NIL;
	int		num_active_paths, found = 0;
	char		*vhci_path_ptr, *pathname_ptr, pathname[MAXPATHLEN];
	char		*phci_path, *node_path;
	char		phci_addr[MAXPATHLEN];
	char		*xport_phys, *vhci_path, *dyncomp;
	luninfo_list_t	*lunlistp, *temp;
	int		non_operational_path_count;

	/* a safety check */
	if ((apidt->dyncomp == NULL) || (*apidt->dyncomp == '\0')) {
		return (FPCFGA_LIB_ERR);
	}

	xport_phys = apidt->xport_phys;
	dyncomp = apidt->dyncomp;

	lunlistp = apidt->lunlist;
	for (lunlistp = apidt->lunlist; lunlistp != NULL;
	    lunlistp = lunlistp->next) {

		if (strncmp(lunlistp->path, SCSI_VHCI_ROOT,
		    strlen(SCSI_VHCI_ROOT)) != 0) {
			lunlistp->lun_flag |= FLAG_SKIP_ONLINEOTHERS;
			continue;
		}

		vhci_path = lunlistp->path;

		num_active_paths = 0;	/* # of paths in ONLINE/STANDBY */
		non_operational_path_count = 0;

		if (xport_phys == NULL || vhci_path == NULL) {
		    cfga_err(errstring, 0, ERRARG_XPORT_NOT_IN_PHCI_LIST,
		    xport_phys, 0);
			return (FPCFGA_LIB_ERR);
		}

		(void) strlcpy(pathname, xport_phys, MAXPATHLEN);
		if ((pathname_ptr = strrchr(pathname, ':')) != NULL) {
			*pathname_ptr = '\0';
		}
		/* strip off the /devices/from the path */
		pathname_ptr = pathname + strlen(DEVICES_DIR);

		root = di_init("/", DINFOCPYALL|DINFOPATH);

		if (root == DI_NODE_NIL) {
			return (FPCFGA_LIB_ERR);
		}

		vhci_path_ptr = vhci_path + strlen(DEVICES_DIR);
		if ((vhci = di_drv_first_node(SCSI_VHCI_DRVR, root)) ==
		    DI_NODE_NIL) {
			return (FPCFGA_LIB_ERR);
		}
		found = 0;
		for (node = di_child_node(vhci); node != DI_NODE_NIL;
		    node = di_sibling_node(node)) {
			if ((node_path = di_devfs_path(node)) != NULL) {
				if (strncmp(vhci_path_ptr, node_path,
				    strlen(node_path)) != 0) {
					di_devfs_path_free(node_path);
				} else {
					found = 1;
					break;
				}
			}
		}
		if (found == 0) {
			cfga_err(errstring, 0, ERRARG_XPORT_NOT_IN_PHCI_LIST,
			    xport_phys, 0);
			di_fini(root);
			return (FPCFGA_LIB_ERR);
		}
		/* found vhci_path we are looking for */
		di_devfs_path_free(node_path);
		found = 0;
		for (path = di_path_next_phci(node, DI_PATH_NIL);
		    path != DI_PATH_NIL;
		    path = di_path_next_phci(node, path)) {
			if ((phci = di_path_phci_node(path)) == DI_NODE_NIL) {
				cfga_err(errstring, 0,
				    ERRARG_XPORT_NOT_IN_PHCI_LIST,
				    xport_phys, 0);
				di_fini(root);
				return (FPCFGA_LIB_ERR);
			}
			if ((phci_path = di_devfs_path(phci)) == NULL) {
				cfga_err(errstring, 0,
				    ERRARG_XPORT_NOT_IN_PHCI_LIST,
				    xport_phys, 0);
				di_fini(root);
				return (FPCFGA_LIB_ERR);
			}
			(void) di_path_addr(path, (char *)phci_addr);
			if ((phci_addr == NULL) || (*phci_addr == '\0')) {
				cfga_err(errstring, 0,
				    ERRARG_XPORT_NOT_IN_PHCI_LIST,
				    xport_phys, 0);
				di_devfs_path_free(phci_path);
				di_fini(root);
				return (FPCFGA_LIB_ERR);
			}
			/*
			 * Check if the phci path has the same
			 * xport addr and the target addr with current lun
			 */
			if ((strncmp(phci_path, pathname_ptr,
			    strlen(pathname_ptr)) == 0) &&
			    (strstr(phci_addr, dyncomp) != NULL)) {
				/* SUCCESS Found xport_phys */
				found = 1;
			} else if ((di_path_state(path) ==
			    DI_PATH_STATE_ONLINE) ||
			    (di_path_state(path) == DI_PATH_STATE_STANDBY)) {
				num_active_paths++;
			} else {
				/*
				 * We have another path not in ONLINE/STANDBY
				 * state now, so should do a RCM online after
				 * the unconfiguration of current path.
				 */
				non_operational_path_count++;
			}
			di_devfs_path_free(phci_path);
		}
		di_fini(root);
		if (found == 1) {
			if (num_active_paths != 0) {
				/*
				 * There are other ONLINE/STANDBY paths,
				 * so no need to do the RCM
				 */
				lunlistp->lun_flag |= FLAG_SKIP_RCMREMOVE;
				lunlistp->lun_flag |= FLAG_SKIP_RCMOFFLINE;
			}
			if (non_operational_path_count == 0) {
				lunlistp->lun_flag |= FLAG_SKIP_ONLINEOTHERS;
			}
		} else {
			/*
			 * Fail all operations here
			 */
			cfga_err(errstring, 0, ERRARG_XPORT_NOT_IN_PHCI_LIST,
			    xport_phys, 0);
			return (FPCFGA_APID_NOEXIST);
		}
	}

	/* Mark duplicated paths for same vhci in the list */
	for (lunlistp = apidt->lunlist; lunlistp != NULL;
	    lunlistp = lunlistp->next) {
		if (strncmp(lunlistp->path, SCSI_VHCI_ROOT,
		    strlen(SCSI_VHCI_ROOT)) != 0) {
			continue;
		}
		for (temp = lunlistp->next; temp != NULL;
		    temp = temp->next) {
			if (strcmp(lunlistp->path, temp->path) == 0) {
				/*
				 * don't do RCM for dup
				 */
				lunlistp->lun_flag |= FLAG_SKIP_RCMREMOVE;
				lunlistp->lun_flag |= FLAG_SKIP_RCMOFFLINE;
				lunlistp->lun_flag |= FLAG_SKIP_ONLINEOTHERS;
			}
		}
	}
	return (FPCFGA_OK);
}
/*
 * apidt->dyncomp has to be non-NULL by the time this routine is called
 */
fpcfga_ret_t
dev_change_state(cfga_cmd_t state_change_cmd, apid_t *apidt, la_wwn_t *pwwn,
		cfga_flags_t flags, char **errstring, HBA_HANDLE handle,
		HBA_PORTATTRIBUTES portAttrs)
{
	char			dev_path[MAXPATHLEN];
	char			*update_str, *t_apid;
	int			optflag = apidt->flags;
	int			no_config_attempt = 0;
	fpcfga_ret_t		ret;
	apid_t			my_apidt;
	uchar_t			unconf_flag = 0, peri_qual;
	HBA_STATUS		status;
	HBA_PORTATTRIBUTES	discPortAttrs;
	uint64_t		lun = 0;
	struct scsi_inquiry	inq;
	struct scsi_extended_sense sense;
	HBA_UINT8		scsiStatus;
	uint32_t		inquirySize = sizeof (inq),
				senseSize = sizeof (sense);
	report_lun_resp_t	*resp_buf;
	int			i, l_errno, num_luns = 0;
	uchar_t			*lun_string;

	if ((apidt->dyncomp == NULL) || (*apidt->dyncomp == '\0')) {
		/*
		 * No dynamic component specified. Just return success.
		 * Should not see this case. Just a safety check.
		 */
		return (FPCFGA_OK);
	}

	/* Now construct the string we are going to put in the repository */
	if ((update_str = calloc(1, (strlen(apidt->xport_phys) +
		strlen(DYN_SEP) + strlen(apidt->dyncomp) + 1))) == NULL) {
		cfga_err(errstring, errno, ERR_MEM_ALLOC, 0);
		return (FPCFGA_LIB_ERR);
	}
	strcpy(update_str, apidt->xport_phys);
	strcat(update_str, DYN_SEP);
	strcat(update_str, apidt->dyncomp);

	/* If force update of repository is sought, do it first */
	if (optflag & FLAG_FORCE_UPDATE_REP) {
		/* Ignore any failure in rep update */
		(void) update_fabric_wwn_list(
			((state_change_cmd == CFGA_CMD_CONFIGURE) ?
			ADD_ENTRY : REMOVE_ENTRY),
			update_str, errstring);
	}

	memset(&sense, 0, sizeof (sense));
	if ((ret = get_report_lun_data(apidt->xport_phys, apidt->dyncomp,
		&num_luns, &resp_buf, &sense, &l_errno)) != FPCFGA_OK) {
		/*
		 * Checking the sense key data as well as the additional
		 * sense key.  The SES Node is not required to repond
		 * to Report LUN.  In the case of Minnow, the SES node
		 * returns with KEY_ILLEGAL_REQUEST and the additional
		 * sense key of 0x20.  In this case we will blindly
		 * send the SCSI Inquiry call to lun 0
		 *
		 * if we get any other error we will set the inq_type
		 * appropriately
		 */
		if ((sense.es_key == KEY_ILLEGAL_REQUEST) &&
		    (sense.es_add_code == 0x20)) {
			lun = 0;
		} else {
			if (ret == FPCFGA_FCP_SEND_SCSI_DEV_NOT_TGT) {
				inq.inq_dtype = DTYPE_UNKNOWN;
			} else {
				/*
				 * Failed to get the LUN data for the device
				 * If we find that there is a lunlist for this
				 * device it could mean that there are dangling
				 * devinfo nodes. So, we will go ahead and try
				 * to unconfigure them.
				 */
				if ((apidt->lunlist == NULL) ||
				    (state_change_cmd == CFGA_CMD_CONFIGURE)) {
					S_FREE(update_str);
					status = getPortAttrsByWWN(handle,
					    *((HBA_WWN *)(pwwn)),
					    &discPortAttrs);
					if (status ==
					    HBA_STATUS_ERROR_ILLEGAL_WWN) {
						return (FPCFGA_APID_NOEXIST);
					} else {
						cfga_err(errstring, 0,
						    ERRARG_FC_REP_LUNS,
						    apidt->dyncomp, 0);
						return (FPCFGA_LIB_ERR);
					}
				} else {
					/* unconfig with lunlist not empty */
					no_config_attempt++;
				}
			}
		}
	}
	for (i = 0; i < num_luns; i++) {
		/*
		 * issue the inquiry to the first valid lun found
		 * in the lun_string
		 */
		lun_string = (uchar_t *)&(resp_buf->lun_string[i]);
		memcpy(&lun, lun_string, sizeof (lun));

		memset(&sense, 0, sizeof (sense));
		status = HBA_ScsiInquiryV2(handle, portAttrs.PortWWN,
		    *(HBA_WWN *)(pwwn), lun, 0, 0, &inq, &inquirySize,
		    &scsiStatus, &sense, &senseSize);
		/*
		 * if Inquiry is returned correctly, check the
		 * peripheral qualifier for the lun.  if it is non-zero
		 * then try the SCSI Inquiry on the next lun
		 */
		if (status == HBA_STATUS_OK) {
			peri_qual = inq.inq_dtype & FP_PERI_QUAL_MASK;
			if (peri_qual == DPQ_POSSIBLE) {
				break;
			}
		}
	}

	if (ret == FPCFGA_OK)
		S_FREE(resp_buf);

	/*
	 * If there are no luns on this target, we will attempt to send
	 * the SCSI Inquiry to lun 0
	 */
	if (num_luns == 0) {
		lun = 0;
		status = HBA_ScsiInquiryV2(handle, portAttrs.PortWWN,
		    *(HBA_WWN *)(pwwn), lun, 0, 0, &inq, &inquirySize,
		    &scsiStatus, &sense, &senseSize);
	}

	if (status != HBA_STATUS_OK) {
		if (status ==  HBA_STATUS_ERROR_NOT_A_TARGET) {
			inq.inq_dtype = DTYPE_UNKNOWN;
		} else if (status ==  HBA_STATUS_ERROR_ILLEGAL_WWN) {
			free(update_str);
			return (FPCFGA_APID_NOEXIST);
		} else {
			/*
			 * Failed to get the inq_dtype of device
			 * If we find that there is a lunlist for this
			 * device it could mean that there dangling
			 * devinfo nodes. So, we will go ahead and try
			 * to unconfigure them.  We'll just set the
			 * inq_dtype to some invalid value (0xFF)
			 */
			if ((apidt->lunlist == NULL) ||
			    (state_change_cmd == CFGA_CMD_CONFIGURE)) {
				cfga_err(errstring, 0,
				    ERRARG_FC_INQUIRY,
				    apidt->dyncomp, 0);
				free(update_str);
				return (FPCFGA_LIB_ERR);
			} else {
				/* unconfig with lunlist not empty */
				no_config_attempt++;
			}
		}
	}
	switch (state_change_cmd) {
	case CFGA_CMD_CONFIGURE:
	    if (portAttrs.PortType != HBA_PORTTYPE_NLPORT &&
		portAttrs.PortType != HBA_PORTTYPE_NPORT) {
		free(update_str);
		return (FPCFGA_OK);
	    }

	    if (((inq.inq_dtype & DTYPE_MASK) == DTYPE_UNKNOWN) &&
		((flags & CFGA_FLAG_FORCE) == 0)) {
		/*
		 * We assume all DTYPE_UNKNOWNs are HBAs and we wont
		 * waste time trying to config them. If they are not
		 * HBAs, then there is something wrong since they should
		 * have had a valid dtype.
		 *
		 * However, if the force flag is set (cfgadm -f), we
		 * go ahead and try to configure.
		 *
		 * In this path, however, the force flag is not set.
		 */
		free(update_str);
		return (FPCFGA_OK);
	    }

	    errno = 0;
		/*
		 * We'll issue the devctl_bus_dev_create() call even if the
		 * path exists in the devinfo tree. This is to take care of
		 * the situation where the device may be in a state other
		 * than the online and attached state.
		 */
	    if ((ret = do_devctl_dev_create(apidt, dev_path, MAXPATHLEN,
			inq.inq_dtype, errstring)) != FPCFGA_OK) {
		/*
		 * Could not configure device. To provide a more
		 * meaningful error message, first see if the supplied port
		 * WWN is there on the fabric. Otherwise print the error
		 * message using the information received from the driver
		 */
		status = getPortAttrsByWWN(handle, *((HBA_WWN *)(pwwn)),
		    &discPortAttrs);
		S_FREE(update_str);
		if (status == HBA_STATUS_ERROR_ILLEGAL_WWN) {
			return (FPCFGA_APID_NOEXIST);
		} else {
			return (FPCFGA_LIB_ERR);
		}
	    }

	    if (((optflag & (FLAG_FORCE_UPDATE_REP|FLAG_NO_UPDATE_REP)) == 0) &&
		update_fabric_wwn_list(ADD_ENTRY, update_str, errstring)) {
		    cfga_err(errstring, 0, ERR_CONF_OK_UPD_REP, 0);
	    }

	    S_FREE(update_str);

	    if ((apidt->flags & FLAG_DISABLE_RCM) == 0) {
		/*
		 * There may be multiple LUNs associated with the
		 * WWN we created nodes for. So, we'll call
		 * apidt_create() again and let it build a list of
		 * all the LUNs for this WWN using the devinfo tree.
		 * We will then online all those devices in RCM
		 */
		    if ((t_apid = calloc(1, strlen(apidt->xport_phys) +
					strlen(DYN_SEP) +
					strlen(apidt->dyncomp) + 1)) == NULL) {
			    cfga_err(errstring, errno, ERR_MEM_ALLOC, 0);
			    return (FPCFGA_LIB_ERR);
		    }
		    sprintf(t_apid, "%s%s%s", apidt->xport_phys, DYN_SEP,
			apidt->dyncomp);
		    if ((ret = apidt_create(t_apid, &my_apidt,
					errstring)) != FPCFGA_OK) {
			    free(t_apid);
			    return (ret);
		    }

		    my_apidt.flags = apidt->flags;
		    if ((ret = dev_rcm_online(&my_apidt, -1, flags,
					NULL)) != FPCFGA_OK) {
			    cfga_err(errstring, 0, ERRARG_RCM_ONLINE,
				apidt->lunlist->path, 0);
			    apidt_free(&my_apidt);
			    free(t_apid);
			    return (ret);
		    }
		    S_FREE(t_apid);
		    apidt_free(&my_apidt);
	    }
	    return (FPCFGA_OK);

	case CFGA_CMD_UNCONFIGURE:
		if (portAttrs.PortType != HBA_PORTTYPE_NLPORT &&
		    portAttrs.PortType != HBA_PORTTYPE_NPORT) {
			free(update_str);
			return (FPCFGA_OPNOTSUPP);
		}

		status = getPortAttrsByWWN(handle, *((HBA_WWN *)(pwwn)),
		    &discPortAttrs);
		if (apidt->lunlist == NULL) {
			/*
			 * But first, remove entry from the repository if it is
			 * there ... provided the force update flag is not set
			 * (in which case the update is already done) or if
			 * the no-update flag is not set.
			 */
			if ((optflag &
			(FLAG_FORCE_UPDATE_REP|FLAG_NO_UPDATE_REP)) == 0) {
				if (update_fabric_wwn_list(REMOVE_ENTRY,
						update_str, errstring)) {
					free(update_str);
					cfga_err(errstring, 0,
						ERR_UNCONF_OK_UPD_REP, 0);
					return
					(FPCFGA_UNCONF_OK_UPD_REP_FAILED);
				}
			}
			S_FREE(update_str);
			if (status == HBA_STATUS_ERROR_ILLEGAL_WWN) {
				return (FPCFGA_APID_NOEXIST);
			}
			return (FPCFGA_OK);
		}
		/*
		 * If there are multiple paths to the mpxio
		 * device, we will not check in RCM ONLY when there
		 * is atleast one other ONLINE/STANDBY path
		 */
		if (is_xport_phys_in_pathlist(apidt, errstring) !=
		    FPCFGA_OK) {
			free(update_str);
			return (FPCFGA_XPORT_NOT_IN_PHCI_LIST);
		}

		/*
		 * dev_rcm_offline() updates errstring
		 */
		if ((ret = dev_rcm_offline(apidt, flags, errstring)) !=
		    FPCFGA_OK) {
			free(update_str);
			return (ret);
		}
		if ((ret = dev_unconf(apidt, errstring, &unconf_flag)) !=
		    FPCFGA_OK) {
			/* when inq failed don't attempt to reconfigure */
		    if (!no_config_attempt) {
			(void) do_devctl_dev_create(apidt, dev_path, MAXPATHLEN,
				inq.inq_dtype, NULL);
			(void) dev_rcm_online(apidt, -1, flags, NULL);
		    }
		    free(update_str);
		    return (ret);
		}
		if ((ret = dev_rcm_remove(apidt, flags, errstring)) !=
		    FPCFGA_OK) {
			(void) do_devctl_dev_create(apidt, dev_path, MAXPATHLEN,
				inq.inq_dtype, NULL);
			(void) dev_rcm_online(apidt, -1, flags, NULL);
			free(update_str);
			return (ret);
		}
		/*
		 * If we offlined a lun in RCM when there are multiple paths but
		 * none of them are ONLINE/STANDBY, we have to online it back
		 * in RCM now. This is a try best, will not fail for it.
		 */
		dev_rcm_online_nonoperationalpath(apidt, flags, NULL);

		/* Update the repository if we havent already done it */
		if ((optflag &
			(FLAG_FORCE_UPDATE_REP|FLAG_NO_UPDATE_REP)) == 0) {
			if (((optflag & FLAG_REMOVE_UNUSABLE_FCP_DEV) !=
				    FLAG_REMOVE_UNUSABLE_FCP_DEV) ||
			    (((optflag & FLAG_REMOVE_UNUSABLE_FCP_DEV) ==
				FLAG_REMOVE_UNUSABLE_FCP_DEV) &&
			    (unconf_flag == ALL_APID_LUNS_UNUSABLE))) {
				if (update_fabric_wwn_list(REMOVE_ENTRY,
					    update_str, errstring)) {
				    free(update_str);
				    cfga_err(errstring, errno,
					ERR_UNCONF_OK_UPD_REP, 0);
				    return (FPCFGA_UNCONF_OK_UPD_REP_FAILED);
				}
			}
		}
		free(update_str);
		return (FPCFGA_OK);

	default:
		free(update_str);
		return (FPCFGA_OPNOTSUPP);
	}
}

/*
 * This function copies a port_wwn got by reading the property on a device
 * node (from_ptr in the function below) on to an array (to_ptr) so that it is
 * readable.
 *
 * Caller responsible to allocate enough memory in "to_ptr"
 */
static void
copy_pwwn_data_to_str(char *to_ptr, const uchar_t *from_ptr)
{
	if ((to_ptr == NULL) || (from_ptr == NULL))
		return;

	(void) sprintf(to_ptr, "%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
	from_ptr[0], from_ptr[1], from_ptr[2], from_ptr[3],
	from_ptr[4], from_ptr[5], from_ptr[6], from_ptr[7]);
}

static fpcfga_ret_t
unconf_vhci_nodes(di_path_t pnode, di_node_t fp_node, char *xport_phys,
	char *dyncomp, int unusable_flag,
	int *num_devs, int *failure_count, char **errstring,
	cfga_flags_t flags)
{
	int		iret1, iret2, *lunnump;
	char		*ptr;		/* scratch pad */
	char		*node_path, *vhci_path, *update_str;
	char		port_wwn[WWN_SIZE*2+1], pathname[MAXPATHLEN];
	uchar_t		*port_wwn_data = NULL;
	di_node_t	client_node;

	while (pnode != DI_PATH_NIL) {

		(*num_devs)++;


		if ((node_path = di_devfs_path(fp_node)) == NULL) {
			cfga_err(errstring, 0, ERRARG_DEVINFO,
							xport_phys, 0);
			(*failure_count)++;
			pnode = di_path_next_client(fp_node, pnode);
			continue;
		}

		iret1 = di_path_prop_lookup_bytes(pnode, PORT_WWN_PROP,
			&port_wwn_data);

		iret2 = di_path_prop_lookup_ints(pnode, LUN_PROP, &lunnump);

		if ((iret1 == -1) || (iret2 == -1)) {
			cfga_err(errstring, 0, ERRARG_DI_GET_PROP,
								node_path, 0);
			di_devfs_path_free(node_path);
			node_path = NULL;
			(*failure_count)++;
			pnode = di_path_next_client(fp_node, pnode);
			continue;
		}

		copy_pwwn_data_to_str(port_wwn, port_wwn_data);

		if ((client_node = di_path_client_node(pnode)) ==
								DI_NODE_NIL) {
			(*failure_count)++;
			di_devfs_path_free(node_path);
			node_path = NULL;
			pnode = di_path_next_client(fp_node, pnode);
			continue;
		}

		if ((vhci_path = di_devfs_path(client_node)) == NULL) {
			(*failure_count)++;
			di_devfs_path_free(node_path);
			node_path = NULL;
			pnode = di_path_next_client(fp_node, pnode);
			continue;
		}

		if ((ptr = strrchr(vhci_path, '@')) != NULL) {
			*ptr = '\0';
		}

		if ((ptr = strrchr(vhci_path, '/')) == NULL) {
			(*failure_count)++;
			di_devfs_path_free(node_path);
			node_path = NULL;
			pnode = di_path_next_client(fp_node, pnode);
			continue;
		}

		sprintf(pathname, "%s%s/%s@w%s,%x", DEVICES_DIR, node_path,
					++ptr, port_wwn, *lunnump);

		di_devfs_path_free(node_path);
		di_devfs_path_free(vhci_path);
		node_path = vhci_path = NULL;

		/*
		 * Try to offline in RCM first and if that is successful,
		 * unconfigure the LUN. If offlining in RCM fails, then
		 * update the failure_count which gets passed back to caller
		 *
		 * Here we got to check if unusable_flag is set or not.
		 * If set, then unconfigure only those luns which are in
		 * node_state DI_PATH_STATE_OFFLINE. If not set, unconfigure
		 * all luns.
		 */
		if ((unusable_flag & FLAG_REMOVE_UNUSABLE_FCP_DEV) ==
		    FLAG_REMOVE_UNUSABLE_FCP_DEV) {
			if (pnode->path_state == DI_PATH_STATE_OFFLINE) {
				if (fp_rcm_offline(pathname, errstring,
				    flags) != 0) {
					(*failure_count)++;
					pnode = di_path_next_client(fp_node,
					    pnode);
					continue;
				} else if (lun_unconf(pathname, *lunnump,
				    xport_phys,dyncomp, errstring)
				    != FPCFGA_OK) {
					(void) fp_rcm_online(pathname,
					    NULL, flags);
					(*failure_count)++;
					pnode = di_path_next_client(fp_node,
					    pnode);
					continue;
				} else if (fp_rcm_remove(pathname, errstring,
				    flags) != 0) {
					/*
					 * Bring everything back online
					 * in rcm and continue
					 */
					(void) fp_rcm_online(pathname,
					    NULL, flags);
					(*failure_count)++;
					pnode = di_path_next_client(fp_node,
					    pnode);
					continue;
				}
			} else {
				pnode = di_path_next(fp_node, pnode);
				continue;
			}
		} else {
			if (fp_rcm_offline(pathname, errstring, flags) != 0) {
				(*failure_count)++;
				pnode = di_path_next_client(fp_node, pnode);
				continue;
			} else if (lun_unconf(pathname, *lunnump, xport_phys,
			    dyncomp, errstring) != FPCFGA_OK) {
				(void) fp_rcm_online(pathname, NULL, flags);
				(*failure_count)++;
				pnode = di_path_next_client(fp_node, pnode);
				continue;
			} else if (fp_rcm_remove(pathname, errstring,
			    flags) != 0) {
				/*
				 * Bring everything back online
				 * in rcm and continue
				 */
				(void) fp_rcm_online(pathname, NULL, flags);
				(*failure_count)++;
				pnode = di_path_next_client(fp_node, pnode);
				continue;
			}
		}

		/* Update the repository only on a successful unconfigure */
		if ((update_str = calloc(1, strlen(xport_phys) +
					strlen(DYN_SEP) +
					strlen(port_wwn) + 1)) == NULL) {
			cfga_err(errstring, errno, ERR_UNCONF_OK_UPD_REP, 0);
			(*failure_count)++;
			pnode = di_path_next_client(fp_node, pnode);
			continue;
		}

		/* Init the string to be removed from repository */
		sprintf(update_str, "%s%s%s", xport_phys, DYN_SEP, port_wwn);

		if (update_fabric_wwn_list(REMOVE_ENTRY, update_str,
								errstring)) {
			S_FREE(update_str);
			cfga_err(errstring, errno,
					ERR_UNCONF_OK_UPD_REP, 0);
			(*failure_count)++;
			/* Cleanup and continue from here just for clarity */
			pnode = di_path_next_client(fp_node, pnode);
			continue;
		}

		S_FREE(update_str);
		pnode = di_path_next_client(fp_node, pnode);
	}

	return (FPCFGA_OK);
}

static fpcfga_ret_t
unconf_non_vhci_nodes(di_node_t dnode, char *xport_phys, char *dyncomp,
	int unusable_flag, int *num_devs, int *failure_count,
	char **errstring, cfga_flags_t flags)
{
	int	ret1, ret2, *lunnump;
	char	pathname[MAXPATHLEN];
	char	*node_path, *update_str;
	char	port_wwn[WWN_SIZE*2+1];
	uchar_t	*port_wwn_data = NULL;

	while (dnode != DI_NODE_NIL) {

		(*num_devs)++;

		/* Get the physical path for this node */
		if ((node_path = di_devfs_path(dnode)) == NULL) {
			/*
			 * We don't try to offline in RCM here because we
			 * don't know the path to offline. Just continue to
			 * the next node.
			 */
			cfga_err(errstring, 0, ERRARG_DEVINFO, xport_phys, 0);
			(*failure_count)++;
			dnode = di_sibling_node(dnode);
			continue;
		}

		/* Now get the LUN # of this device thru the property */
		ret1 = di_prop_lookup_ints(DDI_DEV_T_ANY, dnode,
							LUN_PROP, &lunnump);

		/* Next get the port WWN of the device */
		ret2 = di_prop_lookup_bytes(DDI_DEV_T_ANY, dnode,
						PORT_WWN_PROP, &port_wwn_data);

		/* A failure in any of the above is not good */
		if ((ret1 == -1) || (ret2 == -1)) {
			/*
			 * We don't try to offline in RCM here because we
			 * don't know the path to offline. Just continue to
			 * the next node.
			 */
			cfga_err(errstring, 0,
					ERRARG_DI_GET_PROP, node_path, 0);
			di_devfs_path_free(node_path);
			node_path = NULL;
			(*failure_count)++;
			dnode = di_sibling_node(dnode);
			continue;
		}

		/* Prepend the "/devices" prefix to the path and copy it */
		sprintf(pathname, "%s%s", DEVICES_DIR, node_path);
		di_devfs_path_free(node_path);
		node_path = NULL;

		copy_pwwn_data_to_str(port_wwn, port_wwn_data);

		if (strstr(pathname, "@w") == NULL) {
			/*
			 * If the driver is detached, some part of the path
			 * may be missing and so we'll manually construct it
			 */
			sprintf(&pathname[strlen(pathname)], "@w%s,%x",
							port_wwn, *lunnump);
		}

		/*
		 * Try to offline in RCM first and if that is successful,
		 * unconfigure the LUN. If offlining in RCM fails, then
		 * update the failure count
		 *
		 * Here we got to check if unusable_flag is set or not.
		 * If set, then unconfigure only those luns which are in
		 * node_state DI_DEVICE_OFFLINE or DI_DEVICE_DOWN.
		 * If not set, unconfigure all luns.
		 */
		if ((unusable_flag & FLAG_REMOVE_UNUSABLE_FCP_DEV) ==
		    FLAG_REMOVE_UNUSABLE_FCP_DEV) {
			if ((dnode->node_state == DI_DEVICE_OFFLINE) ||
			    (dnode->node_state == DI_DEVICE_DOWN)) {
				if (fp_rcm_offline(pathname, errstring,
				    flags) != 0) {
					(*failure_count)++;
					dnode = di_sibling_node(dnode);
					continue;
				} else if (lun_unconf(pathname, *lunnump,
				    xport_phys,dyncomp, errstring)
				    != FPCFGA_OK) {
					(void) fp_rcm_online(pathname,
					    NULL, flags);
					(*failure_count)++;
					dnode = di_sibling_node(dnode);
					continue;
				} else if (fp_rcm_remove(pathname, errstring,
				    flags) != 0) {
					/*
					 * Bring everything back online
					 * in rcm and continue
					 */
					(void) fp_rcm_online(pathname,
					    NULL, flags);
					(*failure_count)++;
					dnode = di_sibling_node(dnode);
					continue;
				}
			} else {
				dnode = di_sibling_node(dnode);
				continue;
			}
		} else {
			if (fp_rcm_offline(pathname, errstring, flags) != 0) {
				(*failure_count)++;
				dnode = di_sibling_node(dnode);
				continue;
			} else if (lun_unconf(pathname, *lunnump, xport_phys,
			    dyncomp, errstring) != FPCFGA_OK) {
				(void) fp_rcm_online(pathname, NULL, flags);
				(*failure_count)++;
				dnode = di_sibling_node(dnode);
				continue;
			} else if (fp_rcm_remove(pathname, errstring,
			    flags) != 0) {
				/*
				 * Bring everything back online
				 * in rcm and continue
				 */
				(void) fp_rcm_online(pathname, NULL, flags);
				(*failure_count)++;
				dnode = di_sibling_node(dnode);
				continue;
			}
		}

		/* Update the repository only on a successful unconfigure */
		if ((update_str = calloc(1, strlen(xport_phys) +
					strlen(DYN_SEP) +
					strlen(port_wwn) + 1)) == NULL) {
			cfga_err(errstring, errno, ERR_UNCONF_OK_UPD_REP, 0);
			(*failure_count)++;
			dnode = di_sibling_node(dnode);
			continue;
		}

		/* Init the string to be removed from repository */
		sprintf(update_str, "%s%s%s", xport_phys, DYN_SEP, port_wwn);

		if (update_fabric_wwn_list(REMOVE_ENTRY, update_str,
								errstring)) {
			S_FREE(update_str);
			cfga_err(errstring, errno, ERR_UNCONF_OK_UPD_REP, 0);
			(*failure_count)++;
			dnode = di_sibling_node(dnode);
			continue;
		}

		S_FREE(update_str);
		dnode = di_sibling_node(dnode);
	}

	return (FPCFGA_OK);
}

/*
 * INPUT:
 * apidt - Pointer to apid_t structure with data filled in
 * flags - Flags for special handling
 *
 * OUTPUT:
 * errstring - Applicable only on a failure from plugin
 * num_devs  - Incremented per lun
 * failure_count - Incremented on any failed operation on lun
 *
 * RETURNS:
 * non-FPCFGA_OK on any validation check error. If this value is returned, no
 *             devices were handled.  Consequently num_devs and failure_count
 *             will not be incremented.
 * FPCFGA_OK This return value doesn't mean that all devices were successfully
 *             unconfigured, you have to check failure_count.
 */
static fpcfga_ret_t
unconf_any_devinfo_nodes(apid_t *apidt, cfga_flags_t flags, char **errstring,
				int *num_devs, int *failure_count)
{
	char		*node_path = NULL;
	char		pathname[MAXPATHLEN], *ptr;	/* scratch pad */
	di_node_t	root_node, direct_node, fp_node;
	di_path_t	path_node = DI_PATH_NIL;

	/*
	 * apidt->xport_phys is something like :
	 * /devices/pci@.../SUNW,qlc@../fp@0,0:fc
	 * Make sure we copy both the devinfo and pathinfo nodes
	 */
	(void) strlcpy(pathname, apidt->xport_phys, MAXPATHLEN);

	/* Now get rid of the ':' at the end */
	if ((ptr = strstr(pathname, MINOR_SEP)) != NULL)
		*ptr = '\0';

	if (strncmp(pathname, DEVICES_DIR, strlen(DEVICES_DIR))) {
		cfga_err(errstring, 0, ERRARG_INVALID_PATH, pathname, 0);
		return (FPCFGA_INVALID_PATH);
	}

	if ((root_node = di_init("/", DINFOCPYALL | DINFOPATH)) ==
								DI_NODE_NIL) {
		cfga_err(errstring, errno, ERRARG_DEVINFO,
							apidt->xport_phys, 0);
		return (FPCFGA_LIB_ERR);
	}

	if ((fp_node = di_drv_first_node("fp", root_node)) == DI_NODE_NIL) {
		cfga_err(errstring, errno, ERRARG_DEVINFO,
							apidt->xport_phys, 0);
		di_fini(root_node);
		return (FPCFGA_LIB_ERR);
	}

	/*
	 * Search all the fp nodes to see if any match the one we are trying
	 * to unconfigure
	 */

	/* Skip the "/devices" prefix */
	ptr = pathname + strlen(DEVICES_DIR);

	while (fp_node != DI_NODE_NIL) {
		node_path = di_devfs_path(fp_node);
		if (strcmp(node_path, ptr) == 0) {
			/* Found the fp node. 'pathname' has the full path */
			di_devfs_path_free(node_path);
			node_path = NULL;
			break;
		}
		fp_node = di_drv_next_node(fp_node);
		di_devfs_path_free(node_path);
	}

	if (fp_node == DI_NODE_NIL) {
		cfga_err(errstring, 0, ERRARG_NOT_IN_DEVINFO,
							apidt->xport_phys, 0);
		di_fini(root_node);
		return (FPCFGA_LIB_ERR);
	}

	direct_node = di_child_node(fp_node);
	path_node = di_path_next_client(fp_node, path_node);

	if ((direct_node == DI_NODE_NIL) && (path_node == DI_PATH_NIL)) {
		/* No devinfo or pathinfo nodes. Great ! Just return success */
		di_fini(root_node);
		return (FPCFGA_OK);
	}

	/* First unconfigure any non-MPXIO nodes */
	unconf_non_vhci_nodes(direct_node, apidt->xport_phys, apidt->dyncomp,
	    apidt->flags, num_devs, failure_count, errstring, flags);

	/*
	 * Now we will traverse any path info nodes that are there
	 *
	 * Only MPXIO devices have pathinfo nodes
	 */
	unconf_vhci_nodes(path_node, fp_node, apidt->xport_phys, apidt->dyncomp,
	    apidt->flags, num_devs, failure_count, errstring, flags);

	di_fini(root_node);

	/*
	 * We don't want to check the return value of unconf_non_vhci_nodes()
	 * and unconf_vhci_nodes().  But instead, we are interested only in
	 * consistently incrementing num_devs and failure_count so that we can
	 * compare them.
	 */
	return (FPCFGA_OK);
}

/*
 * This function handles configuring/unconfiguring all the devices w.r.t
 * the FCA port specified by apidt.
 *
 * In the unconfigure case, it first unconfigures all the devices that are
 * seen through the given port at that moment and then unconfigures all the
 * devices that still (somehow) have devinfo nodes on the system for that FCA
 * port.
 *
 * INPUT:
 * cmd - CFGA_CMD_CONFIGURE or CFGA_CMD_UNCONFIGURE
 * apidt - Pointer to apid_t structure with data filled in
 * flags - Flags for special handling
 *
 * OUTPUT:
 * errstring - Applicable only on a failure from plugin
 *
 * RETURNS:
 * FPCFGA_OK on success
 * non-FPCFGA_OK otherwise
 */
static fpcfga_ret_t
handle_devs(cfga_cmd_t cmd, apid_t *apidt, cfga_flags_t flags,
	char **errstring, HBA_HANDLE handle, int portIndex,
	HBA_PORTATTRIBUTES portAttrs)
{
	int		num_devs = 0, dev_cs_failed = 0;
	char		port_wwn[WWN_S_LEN];
	la_wwn_t	pwwn;
	apid_t		my_apidt = {NULL};
	char		*my_apid;
	HBA_PORTATTRIBUTES	discPortAttrs;
	int			discIndex;
	fpcfga_ret_t		rval = FPCFGA_OK;

	if ((my_apid = calloc(
		1, strlen(apidt->xport_phys) + strlen(DYN_SEP) +
		(2 * FC_WWN_SIZE) + 1)) == NULL) {
		cfga_err(errstring, errno, ERR_MEM_ALLOC, 0);
		return (FPCFGA_LIB_ERR);
	}

	num_devs = portAttrs.NumberofDiscoveredPorts;
	for (discIndex = 0; discIndex < portAttrs.NumberofDiscoveredPorts;
		discIndex++) {
	    if (getDiscPortAttrs(handle, portIndex,
		discIndex, &discPortAttrs)) {
		dev_cs_failed++;
		/* Move on to the next target */
		continue;
	    }
	    (void) sprintf(port_wwn, "%016llx",
		wwnConversion(discPortAttrs.PortWWN.wwn));
		/*
		 * Construct a fake apid string similar to the one the
		 * plugin gets from the framework and have apidt_create()
		 * fill in the apid_t structure.
		 */
	    strcpy(my_apid, apidt->xport_phys);
	    strcat(my_apid, DYN_SEP);
	    strcat(my_apid, port_wwn);
	    if (apidt_create(my_apid, &my_apidt, errstring) != FPCFGA_OK) {
		dev_cs_failed++;
		continue;
	    }
	    my_apidt.flags = apidt->flags;

	    memcpy(&pwwn, &(discPortAttrs.PortWWN), sizeof (la_wwn_t));
	    if (dev_change_state(cmd, &my_apidt, &pwwn,
		flags, errstring, handle, portAttrs) != FPCFGA_OK) {
		dev_cs_failed++;
	    }
	    apidt_free(&my_apidt);
	}

	S_FREE(my_apid);

	/*
	 * We have now handled all the devices that are currently visible
	 * through the given FCA port. But, it is possible that there are
	 * some devinfo nodes hanging around. For the unconfigure operation,
	 * this has to be looked into too.
	 */
	if (cmd == CFGA_CMD_UNCONFIGURE) {
		/* dev_cs_failed will be updated to indicate any failures */
		rval = unconf_any_devinfo_nodes(apidt, flags, errstring,
		    &num_devs, &dev_cs_failed);
	}

	if (rval == FPCFGA_OK) {
		if (dev_cs_failed == 0)
			return (FPCFGA_OK);

		/*
		 * For the discovered ports, num_devs is counted on target
		 * basis, but for invisible targets, num_devs is counted on
		 * lun basis.
		 *
		 * But if dev_cs_failed and num_devs are incremented
		 * consistently, comparation of these two counters is still
		 * meaningful.
		 */
		if (dev_cs_failed == num_devs) {
			/* Failed on all devices seen through this FCA port */
			cfga_err(errstring, 0,
			((cmd == CFGA_CMD_CONFIGURE) ?
				ERR_FCA_CONFIGURE : ERR_FCA_UNCONFIGURE), 0);
			return (FPCFGA_LIB_ERR);
		} else {
			/* Failed only on some of the devices */
			cfga_err(errstring, 0, ERR_PARTIAL_SUCCESS, 0);
			return (FPCFGA_LIB_ERR);
		}
	} else {
		if (dev_cs_failed == num_devs) {
			/* Failed on all devices seen through this FCA port */
			cfga_err(errstring, 0,
			((cmd == CFGA_CMD_CONFIGURE) ?
				ERR_FCA_CONFIGURE : ERR_FCA_UNCONFIGURE), 0);
			return (FPCFGA_LIB_ERR);
		} else {
			/* Failed only on some of the devices */
			cfga_err(errstring, 0, ERR_PARTIAL_SUCCESS, 0);
			return (FPCFGA_LIB_ERR);
		}
	}

	/*
	 * Should never get here
	 */
}

fpcfga_ret_t
fca_change_state(cfga_cmd_t state_change_cmd, apid_t *apidt,
		cfga_flags_t flags, char **errstring)
{
	fpcfga_ret_t	ret;
	HBA_HANDLE	handle;
	HBA_PORTATTRIBUTES	portAttrs;
	int			portIndex;

	if ((ret = findMatchingAdapterPort(apidt->xport_phys, &handle,
	    &portIndex, &portAttrs, errstring)) != FPCFGA_OK) {
		return (ret);
	}

	/*
	 * Bail out if not fabric/public loop
	 */
	switch (state_change_cmd) {
	case CFGA_CMD_CONFIGURE:
	    if (portAttrs.PortType != HBA_PORTTYPE_NLPORT &&
		portAttrs.PortType != HBA_PORTTYPE_NPORT) {
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (FPCFGA_OK);
	    }
	    break;

	case CFGA_CMD_UNCONFIGURE:
	    if (portAttrs.PortType != HBA_PORTTYPE_NLPORT &&
		portAttrs.PortType != HBA_PORTTYPE_NPORT) {
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (FPCFGA_OPNOTSUPP);
	    }
	    break;
	default:
		HBA_CloseAdapter(handle);
		HBA_FreeLibrary();
		return (FPCFGA_LIB_ERR);
	}
	ret = (handle_devs(state_change_cmd, apidt, flags, errstring,
	    handle, portIndex, portAttrs));
	HBA_CloseAdapter(handle);
	HBA_FreeLibrary();
	return (ret);
}
