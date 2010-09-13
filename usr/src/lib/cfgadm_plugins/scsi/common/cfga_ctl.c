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

#include "cfga_scsi.h"

struct larg {
	int ndevs;
	int nelem;
	char *dev;
	char **dev_list;
};

#define	ETC_VFSTAB	"/etc/vfstab"
#define	SCFGA_LOCK	"/var/run/cfgadm_scsi"

/* Function prototypes */

static scfga_ret_t quiesce_confirm(apid_t *apidp,
    msgid_t cmd_msg, prompt_t *pt, int *okp, int *quiesce, int *l_errnop);
static scfga_ret_t dev_hotplug(apid_t *apidp,
    prompt_t *pt, cfga_flags_t flags, int quiesce, char **errstring);
static int disconnect(struct cfga_confirm *confp);
static int critical_ctrlr(const char *hba_phys);
static cfga_stat_t bus_devctl_to_recep_state(uint_t bus_dc_state);
static int get_hba_children(char *bus_path, char *dev_excl, char ***dev_list);
static char *get_node_path(char *minor_path);
static void free_dev_list_elements(char **dev_list);
static void free_dev_list(char **dev_list);
static int alloc_dev_list(struct larg *largp);

/*
 * Single thread all implicit quiesce operations
 */
static mutex_t	quiesce_mutex = DEFAULTMUTEX;

/*ARGSUSED*/
scfga_ret_t
bus_change_state(
	cfga_cmd_t state_change_cmd,
	apid_t *apidp,
	struct cfga_confirm *confp,
	cfga_flags_t flags,
	char **errstring)
{
	int l_errno = 0, force;
	uint_t state = 0;
	cfga_stat_t bus_state;
	scfga_cmd_t cmd;
	msgid_t errid;
	cfga_stat_t prereq;
	scfga_ret_t ret;
	char **dev_list = NULL;

	assert(apidp->path != NULL);
	assert(apidp->hba_phys != NULL);

	/*
	 * No dynamic components allowed
	 */
	if (apidp->dyncomp != NULL) {
		cfga_err(errstring, 0, ERR_NOT_BUSAPID, 0);
		return (SCFGA_ERR);
	}

	/* Get bus state */
	if (devctl_cmd(apidp->path, SCFGA_BUS_GETSTATE, &state,
	    &l_errno) != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_BUS_GETSTATE, 0);
		return (SCFGA_ERR);
	}

	bus_state = bus_devctl_to_recep_state(state);
	force = ((flags & CFGA_FLAG_FORCE) == CFGA_FLAG_FORCE) ? 1 : 0;
	assert(confp->confirm != NULL);

	switch (state_change_cmd) {
	case CFGA_CMD_DISCONNECT:	/* quiesce bus */
		/*
		 * If force flag not specified, check if controller is
		 * critical.
		 */
		if (!force) {
			/*
			 * This check is not foolproof, get user confirmation
			 * if test passes.
			 */
			if (critical_ctrlr(apidp->path)) {
				cfga_err(errstring, 0, ERR_CTRLR_CRIT, 0);
				ret = SCFGA_ERR;
				break;
			} else if (!disconnect(confp)) {
				ret = SCFGA_NACK;
				break;
			}
		}

		cmd = SCFGA_BUS_QUIESCE;
		errid = ERR_BUS_QUIESCE;
		prereq = CFGA_STAT_CONNECTED;

		goto common;

	case CFGA_CMD_CONNECT:		/* unquiesce bus */
		cmd = SCFGA_BUS_UNQUIESCE;
		errid = ERR_BUS_UNQUIESCE;
		prereq = CFGA_STAT_DISCONNECTED;

		goto common;

	case CFGA_CMD_CONFIGURE:
		cmd = SCFGA_BUS_CONFIGURE;
		errid = ERR_BUS_CONFIGURE;
		prereq = CFGA_STAT_CONNECTED;

		goto common;

	case CFGA_CMD_UNCONFIGURE:
		cmd = SCFGA_BUS_UNCONFIGURE;
		errid = ERR_BUS_UNCONFIGURE;
		prereq = CFGA_STAT_CONNECTED;

		/* FALLTHROUGH */
	common:
		if (bus_state != prereq) {
			cfga_err(errstring, 0,
			    (prereq == CFGA_STAT_CONNECTED)
			    ? ERR_BUS_NOTCONNECTED
			    : ERR_BUS_CONNECTED, 0);
			ret = SCFGA_ERR;
			break;
		}

		/*
		 * When quiescing or unconfiguring a bus, first suspend or
		 * offline it through RCM.
		 * For unquiescing, we simple build the dev_list for
		 * resume notification.
		 */
		if (((apidp->flags & FLAG_DISABLE_RCM) == 0) &&
		    ((cmd == SCFGA_BUS_QUIESCE) ||
		    (cmd == SCFGA_BUS_UNQUIESCE) ||
		    (cmd == SCFGA_BUS_UNCONFIGURE))) {
			ret = get_hba_children(apidp->path, NULL, &dev_list);
			if (ret != SCFGA_OK) {
				break;
			}
			if (cmd == SCFGA_BUS_QUIESCE) {
				if ((ret = scsi_rcm_suspend(dev_list,
				    errstring, flags, 1)) != SCFGA_OK) {
					break;
				}
			} else if (cmd == SCFGA_BUS_UNCONFIGURE) {
				if ((ret = scsi_rcm_offline(dev_list,
				    errstring, flags)) != SCFGA_OK) {
					break;
				}
			}
		}

		ret = devctl_cmd(apidp->path, cmd, NULL, &l_errno);
		if (ret != SCFGA_OK) {
			/*
			 * EIO when child devices are busy may confuse user.
			 * So explain it.
			 */
			if (cmd == SCFGA_BUS_UNCONFIGURE && l_errno == EIO)
				errid = ERR_MAYBE_BUSY;

			cfga_err(errstring, l_errno, errid, 0);

			/*
			 * If the bus was suspended in RCM, then cancel the RCM
			 * operation.  Discard RCM failures here because the
			 * devctl's failure is what is most relevant.
			 */
			if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
				if (cmd == SCFGA_BUS_QUIESCE)
					(void) scsi_rcm_resume(dev_list,
					    errstring,
					    (flags & (~CFGA_FLAG_FORCE)), 1);
				else if (cmd == SCFGA_BUS_UNCONFIGURE) {
					(void) devctl_cmd(apidp->path,
					    SCFGA_BUS_CONFIGURE, NULL,
					    &l_errno);
					(void) scsi_rcm_online(dev_list,
					    errstring,
					    (flags & (~CFGA_FLAG_FORCE)));
				}
			}

			break;
		}

		/*
		 * When unquiescing or configuring a bus, resume or online it
		 * in RCM when the devctl command is complete.
		 * When unconfiguring a bus, notify removal of devices.
		 */
		if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
			if (cmd == SCFGA_BUS_UNQUIESCE) {
				ret = scsi_rcm_resume(dev_list, errstring,
				    (flags & (~CFGA_FLAG_FORCE)), 1);
			} else if (cmd == SCFGA_BUS_UNCONFIGURE) {
				ret = scsi_rcm_remove(dev_list, errstring,
				    (flags & (~CFGA_FLAG_FORCE)));
			}
		}
		break;

	case CFGA_CMD_LOAD:
	case CFGA_CMD_UNLOAD:
		ret = SCFGA_OPNOTSUPP;
		break;

	default:
		cfga_err(errstring, 0, ERR_CMD_INVAL, 0);
		ret = SCFGA_ERR;
		break;
	}

	free_dev_list(dev_list);
	return (ret);
}

scfga_ret_t
dev_change_state(
	cfga_cmd_t state_change_cmd,
	apid_t *apidp,
	cfga_flags_t flags,
	char **errstring)
{
	uint_t state = 0;
	int l_errno = 0;
	cfga_stat_t bus_state;
	scfga_cmd_t cmd;
	msgid_t errid;
	scfga_ret_t ret;
	char *dev_list[2] = {NULL};

	assert(apidp->path != NULL);
	assert(apidp->hba_phys != NULL);

	/*
	 * For a device, dynamic component must be present
	 */
	if (apidp->dyncomp == NULL) {
		cfga_err(errstring, 0, ERR_APID_INVAL, 0);
		return (SCFGA_ERR);
	}

	/* Get bus state */
	if (devctl_cmd(apidp->hba_phys, SCFGA_BUS_GETSTATE, &state,
	    &l_errno) != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_BUS_GETSTATE, 0);
		return (SCFGA_ERR);
	}

	bus_state = bus_devctl_to_recep_state(state);

	switch (state_change_cmd) {
	case CFGA_CMD_CONFIGURE:		/* online device */
		cmd = SCFGA_DEV_CONFIGURE;
		errid = ERR_DEV_CONFIGURE;
		goto common;

	case CFGA_CMD_UNCONFIGURE:		/* offline device */
		cmd = SCFGA_DEV_UNCONFIGURE;
		errid = ERR_DEV_UNCONFIGURE;
		/* FALLTHROUGH */
	common:
		if (bus_state != CFGA_STAT_CONNECTED) {
			cfga_err(errstring, 0, ERR_BUS_NOTCONNECTED, 0);
			ret = SCFGA_ERR;
			break;
		}

		if (apidp->dyntype == PATH_APID) {
			/* call a scsi_vhci ioctl to do online/offline path. */
			ret = path_apid_state_change(apidp, cmd,
			    flags, errstring, &l_errno, errid);
		} else {
			/*
			 * When unconfiguring a device, first offline it
			 * through RCM.
			 */
			if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
				if (cmd == SCFGA_DEV_UNCONFIGURE) {
					dev_list[0] =
					    get_node_path(apidp->path);
					if (dev_list[0] == NULL) {
						ret = SCFGA_ERR;
						break;
					}
					if ((ret = scsi_rcm_offline(dev_list,
					    errstring, flags)) != SCFGA_OK) {
						break;
					}
				}
			}

			ret = devctl_cmd(apidp->path, cmd, NULL, &l_errno);
			if (ret != SCFGA_OK) {
				cfga_err(errstring, l_errno, errid, 0);

			/*
			 * If an unconfigure fails, cancel the RCM offline.
			 * Discard any RCM failures so that the devctl
			 * failure will still be reported.
			 */
				if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
					if (cmd == SCFGA_DEV_UNCONFIGURE)
						(void) scsi_rcm_online(dev_list,
						    errstring, flags);
				}
				break;
			}
			if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
			/*
			 * Unconfigure succeeded, call the RCM notify_remove.
			 */
				if (cmd == SCFGA_DEV_UNCONFIGURE)
					(void) scsi_rcm_remove(dev_list,
					    errstring, flags);
			}
		}
		break;

	/*
	 * Cannot disconnect/connect individual devices without affecting
	 * other devices on the bus. So we don't support these ops.
	 */
	case CFGA_CMD_DISCONNECT:
	case CFGA_CMD_CONNECT:
		cfga_err(errstring, 0, ERR_NOT_DEVOP, 0);
		ret = SCFGA_ERR;
		break;
	case CFGA_CMD_LOAD:
	case CFGA_CMD_UNLOAD:
		ret = SCFGA_OPNOTSUPP;
		break;
	default:
		cfga_err(errstring, 0, ERR_CMD_INVAL, 0);
		ret = SCFGA_ERR;
		break;
	}

	free_dev_list_elements(dev_list);
	return (ret);
}

/*ARGSUSED*/
scfga_ret_t
dev_remove(
	const char *func,
	scfga_cmd_t cmd,
	apid_t *apidp,
	prompt_t *prp,
	cfga_flags_t flags,
	char **errstring)
{
	int proceed, l_errno = 0;
	scfga_ret_t ret;
	int do_quiesce;
	char *dev_list[2] = {NULL};

	assert(apidp->hba_phys != NULL);
	assert(apidp->path != NULL);

	/* device operation only */
	if (apidp->dyncomp == NULL) {
		cfga_err(errstring, 0, ERR_NOT_BUSOP, 0);
		return (SCFGA_ERR);
	}

	proceed = 1;
	ret = quiesce_confirm(apidp, MSG_RMDEV, prp, &proceed, &do_quiesce,
	    &l_errno);
	if (ret != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_DEV_REMOVE, 0);
		return (ret);
	}

	if (!proceed) {
		return (SCFGA_NACK);
	}

	/*
	 * Offline the device in RCM
	 */
	if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
		dev_list[0] = get_node_path(apidp->path);
		if (dev_list[0] == NULL)
			return (SCFGA_ERR);
		if ((ret = scsi_rcm_offline(dev_list, errstring, flags))
		    != SCFGA_OK) {
			free_dev_list_elements(dev_list);
			return (ret);
		}
	}

	/*
	 * Offline the device
	 */
	ret = devctl_cmd(apidp->path, SCFGA_DEV_UNCONFIGURE, NULL, &l_errno);
	if (ret != SCFGA_OK) {

		cfga_err(errstring, l_errno, ERR_DEV_REMOVE, 0);

		/*
		 * Cancel the RCM offline.  Discard the RCM failures so that
		 * the above devctl failure is still reported.
		 */
		if ((apidp->flags & FLAG_DISABLE_RCM) == 0)
			(void) scsi_rcm_online(dev_list, errstring, flags);
		free_dev_list_elements(dev_list);
		return (ret);
	}

	/* Do the physical removal */
	ret = dev_hotplug(apidp, prp, flags, do_quiesce, errstring);

	if (ret == SCFGA_OK) {
		/*
		 * Complete the remove.
		 * Since the device is already offlined, remove shouldn't
		 * fail. Even if remove fails, there is no side effect.
		 */
		(void) devctl_cmd(apidp->path, SCFGA_DEV_REMOVE,
		    NULL, &l_errno);
		if ((apidp->flags & FLAG_DISABLE_RCM) == 0)
			ret = scsi_rcm_remove(dev_list, errstring, flags);
	} else {
		/*
		 * Reconfigure the device and restore the device's RCM state.
		 * If reconfigure succeeds, restore the state to online.
		 * If reconfigure fails (e.g. a typo from user), we treat
		 * the device as removed.
		 */
		if (devctl_cmd(apidp->path, SCFGA_DEV_CONFIGURE, NULL, &l_errno)
		    == SCFGA_OK) {
			if ((apidp->flags & FLAG_DISABLE_RCM) == 0)
				(void) scsi_rcm_online(dev_list, errstring,
				    flags);
		} else {
			char *cp = strrchr(apidp->path, ':');
			if (cp)
				*cp = '\0';
			cfga_err(errstring, l_errno, ERR_DEV_RECONFIGURE,
			    apidp->path, 0);
			if (cp)
				*cp = ':';
			if ((apidp->flags & FLAG_DISABLE_RCM) == 0)
				(void) scsi_rcm_remove(dev_list, errstring,
				    flags);
		}
	}

	free_dev_list_elements(dev_list);
	return (ret);
}

/*ARGSUSED*/
scfga_ret_t
dev_insert(
	const char *func,
	scfga_cmd_t cmd,
	apid_t *apidp,
	prompt_t *prp,
	cfga_flags_t flags,
	char **errstring)
{
	int proceed, l_errno = 0;
	scfga_ret_t ret;
	int do_quiesce;

	assert(apidp->hba_phys != NULL);
	assert(apidp->path != NULL);

	/* Currently, insert operation only allowed for bus */
	if (apidp->dyncomp != NULL) {
		cfga_err(errstring, 0, ERR_NOT_DEVOP, 0);
		return (SCFGA_ERR);
	}

	proceed = 1;
	ret = quiesce_confirm(apidp, MSG_INSDEV, prp, &proceed, &do_quiesce,
	    &l_errno);
	if (ret != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_DEV_INSERT, 0);
		return (ret);
	}

	if (!proceed) {
		return (SCFGA_NACK);
	}

	/* Do the physical addition */
	ret = dev_hotplug(apidp, prp, flags, do_quiesce, errstring);
	if (ret != SCFGA_OK) {
		return (ret);
	}

	/*
	 * Configure bus to online new device(s).
	 * Previously offlined devices will not be onlined.
	 */
	ret = devctl_cmd(apidp->hba_phys, SCFGA_BUS_CONFIGURE, NULL, &l_errno);
	if (ret != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_DEV_INSERT, 0);
		return (SCFGA_ERR);
	}

	return (SCFGA_OK);
}

/*ARGSUSED*/
scfga_ret_t
dev_replace(
	const char *func,
	scfga_cmd_t cmd,
	apid_t *apidp,
	prompt_t *prp,
	cfga_flags_t flags,
	char **errstring)
{
	int proceed, l_errno = 0;
	scfga_ret_t ret, ret2;
	int do_quiesce;
	char *dev_list[2] = {NULL};

	assert(apidp->hba_phys != NULL);
	assert(apidp->path != NULL);

	/* device operation only */
	if (apidp->dyncomp == NULL) {
		cfga_err(errstring, 0, ERR_NOT_BUSOP, 0);
		return (SCFGA_ERR);
	}

	proceed = 1;
	ret = quiesce_confirm(apidp, MSG_REPLDEV, prp, &proceed, &do_quiesce,
	    &l_errno);
	if (ret != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_DEV_REPLACE, 0);
		return (ret);
	}

	if (!proceed) {
		return (SCFGA_NACK);
	}

	/* Offline the device in RCM */
	if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
		dev_list[0] = get_node_path(apidp->path);
		if (dev_list[0] == NULL)
			return (SCFGA_ERR);
		if ((ret = scsi_rcm_offline(dev_list, errstring, flags))
		    != SCFGA_OK) {
			free_dev_list_elements(dev_list);
			return (ret);
		}
	}

	ret = devctl_cmd(apidp->path, SCFGA_DEV_REMOVE, NULL, &l_errno);
	if (ret != SCFGA_OK) {

		/*
		 * Cancel the RCM offline.  Discard any RCM failures so that
		 * the devctl failure can still be reported.
		 */
		if ((apidp->flags & FLAG_DISABLE_RCM) == 0)
			(void) scsi_rcm_online(dev_list, errstring, flags);

		cfga_err(errstring, l_errno, ERR_DEV_REPLACE, 0);
		free_dev_list_elements(dev_list);
		return (ret);
	}

	/* do the physical replace */
	ret = dev_hotplug(apidp, prp, flags, do_quiesce, errstring);

	/* Online the replacement, or restore state on error */
	ret2 = devctl_cmd(apidp->path, SCFGA_DEV_CONFIGURE, NULL, &l_errno);

	if (ret2 != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_DEV_REPLACE, 0);
	}

	/*
	 * Remove the replaced device in RCM, or online the device in RCM
	 * to recover.
	 */
	if ((apidp->flags & FLAG_DISABLE_RCM) == 0) {
		if (ret == SCFGA_OK)
			ret = scsi_rcm_remove(dev_list, errstring, flags);
		else if (ret2 == SCFGA_OK)
			ret2 = scsi_rcm_online(dev_list, errstring, flags);
	}
	free_dev_list_elements(dev_list);

	return (ret == SCFGA_OK ? ret2 : ret);
}

#pragma weak plat_dev_led
/*ARGSUSED*/
scfga_ret_t
dev_led(
	const char *func,
	scfga_cmd_t cmd,
	apid_t *apidp,
	prompt_t *prp,
	cfga_flags_t flags,
	char **errstring)
{

	/*
	 * The implementation of the led command is platform-specific, so
	 * the default behavior is to say that the functionality is not
	 * available for this device.
	 */
	if (plat_dev_led) {
		return (plat_dev_led(func, cmd, apidp, prp, flags, errstring));
	}
	cfga_err(errstring, 0, ERR_UNAVAILABLE, 0);
	return (SCFGA_ERR);
}

/*ARGSUSED*/
scfga_ret_t
reset_common(
	const char *func,
	scfga_cmd_t cmd,
	apid_t *apidp,
	prompt_t *prp,
	cfga_flags_t flags,
	char **errstring)
{
	int l_errno = 0;
	scfga_ret_t ret;


	assert(apidp->path != NULL);
	assert(apidp->hba_phys != NULL);

	switch (cmd) {
	case SCFGA_RESET_DEV:
		if (apidp->dyncomp == NULL) {
			cfga_err(errstring, 0, ERR_NOT_BUSOP, 0);
			return (SCFGA_ERR);
		}
		break;

	case SCFGA_RESET_BUS:
	case SCFGA_RESET_ALL:
		if (apidp->dyncomp != NULL) {
			cfga_err(errstring, 0, ERR_NOT_DEVOP, 0);
			return (SCFGA_ERR);
		}
		break;
	default:
		cfga_err(errstring, 0, ERR_CMD_INVAL, 0);
		return (SCFGA_ERR);
	}

	ret = devctl_cmd(apidp->path, cmd, NULL, &l_errno);
	if (ret != SCFGA_OK) {
		cfga_err(errstring, l_errno, ERR_RESET, 0);
	}

	return (ret);
}

static int
disconnect(struct cfga_confirm *confp)
{
	int ans, append_newline;
	char *cq;

	append_newline = 0;
	cq = cfga_str(append_newline, WARN_DISCONNECT, 0);

	ans = confp->confirm(confp->appdata_ptr, cq);

	S_FREE(cq);

	return (ans == 1);
}

/*
 * Check for "scsi-no-quiesce" property
 * Return code: -1 error, 0 quiesce not required, 1 quiesce required
 */
static int
quiesce_required(apid_t *apidp, int *l_errnop)
{
	di_node_t bus_node, dev_node;
	char *bus_path, *bus_end;
	char *dev_path, *dev_end;
	int *propval;

	/* take libdevinfo snapshot of subtree at hba */
	bus_path = apidp->hba_phys + strlen(DEVICES_DIR);
	bus_end = strrchr(bus_path, ':');
	if (bus_end)
		*bus_end = '\0';

	bus_node = di_init(bus_path, DINFOSUBTREE|DINFOPROP);
	if (bus_end)
		*bus_end = ':';
	if (bus_node == DI_NODE_NIL) {
		*l_errnop = errno;
		return (-1);	/* error */
	}

	/* check bus node for property */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, bus_node, SCSI_NO_QUIESCE,
	    &propval) == 1) {
		di_fini(bus_node);
		return (0);	/* quiesce not required */
	}

	/* if this ap is HBA, return with quiesce required */
	if (apidp->dyncomp == NULL) {
		di_fini(bus_node);
		return (1);
	}

	/* check device node for property */
	dev_path = apidp->path + strlen(DEVICES_DIR);
	dev_end = strrchr(dev_path, ':');
	if (dev_end)
		*dev_end = '\0';

	dev_node = di_child_node(bus_node);
	while (dev_node != DI_NODE_NIL) {
		char *child_path;
		child_path = di_devfs_path(dev_node);
		if (strcmp(child_path, dev_path) == 0) {
			di_devfs_path_free(child_path);
			break;
		}
		di_devfs_path_free(child_path);
		dev_node = di_sibling_node(dev_node);
	}

	if (dev_end)
		*dev_end = ':';
	if (dev_node == DI_NODE_NIL) {
		di_fini(bus_node);
		return (1);	/* dev not found (insert case) */
	}

	/* check child node for property */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, dev_node, "scsi-no-quiesce",
	    &propval) == 1) {
		di_fini(bus_node);
		return (0);	/* quiesce not required */
	}
	return (1);	/* quiesce required */
}

static scfga_ret_t
quiesce_confirm(
	apid_t *apidp,
	msgid_t cmd_msg,
	prompt_t *prp,
	int *okp,
	int *quiesce,
	int *l_errnop)
{
	char *buf = NULL, *hbap = NULL, *cq1 = NULL, *cq2 = NULL;
	char *cp;
	size_t len = 0;
	int i = 0, append_newline;
	scfga_ret_t ret;

	assert(apidp->path != NULL);
	assert(apidp->hba_phys != NULL);

	*quiesce = quiesce_required(apidp, l_errnop);
	if (*quiesce == -1)
		return (SCFGA_ERR);
	else if (*quiesce == 0)
		return (SCFGA_OK);

	/*
	 * Try to create HBA logical ap_id.
	 * If that fails use physical path
	 */
	ret = make_hba_logid(apidp->hba_phys, &hbap, &i);
	if (ret != SCFGA_OK) {
		if ((hbap = get_node_path(apidp->hba_phys)) == NULL) {
			*l_errnop = errno;
			return (SCFGA_LIB_ERR);
		}
	}

	assert(hbap != NULL);

	append_newline = 0;
	cq1 = cfga_str(append_newline, CONF_QUIESCE_1, hbap, 0);
	cq2 = cfga_str(append_newline, CONF_QUIESCE_2, 0);
	len = strlen(cq1) + strlen(cq2) + 1; /* Includes term. NULL */

	if ((buf = calloc(1, len)) == NULL) {
		*l_errnop = errno;
		ret = SCFGA_LIB_ERR;
		S_FREE(cq1);
		S_FREE(cq2);
		goto out;
	}
	(void) strcpy(buf, cq1);
	(void) strcat(buf, cq2);

	S_FREE(cq1);
	S_FREE(cq2);


	/* Remove minor name (if any) from phys path */
	if ((cp = strrchr(apidp->path, ':')) != NULL) {
		*cp = '\0';
	}

	/* describe operation being attempted */
	cfga_msg(prp->msgp, cmd_msg, apidp->path, 0);

	/* Restore minor name */
	if (cp != NULL) {
		*cp = ':';
	}

	/* request permission to quiesce */
	assert(prp->confp != NULL && prp->confp->confirm != NULL);
	*okp = prp->confp->confirm(prp->confp->appdata_ptr, buf);

	ret = SCFGA_OK;
	/*FALLTHRU*/
out:
	S_FREE(buf);
	S_FREE(hbap);
	return (ret);
}

static scfga_ret_t
suspend_in_rcm(
	apid_t		*apidp,
	char		***suspend_list_ptr,
	char		**errstring,
	cfga_flags_t	flags)
{
	scfga_ret_t	ret;
	char		*bus_path = NULL;
	char		*dev_path = NULL;
	char		**suspend_list = NULL;

	*suspend_list_ptr = NULL;

	/* Suspend the bus through RCM */
	if (apidp->flags & FLAG_DISABLE_RCM)
		return (SCFGA_OK);

	/* The bus_path is the HBA path without its minor */
	if ((bus_path = get_node_path(apidp->hba_phys)) == NULL)
		return (SCFGA_ERR);

	/*
	 * The dev_path is already initialized to NULL.  If the AP Id
	 * path differs from the HBA path, then the dev_path should
	 * instead be set to the AP Id path without its minor.
	 */
	if (strcmp(apidp->hba_phys, apidp->path) != 0) {
		if ((dev_path = get_node_path(apidp->path)) == NULL) {
			ret = SCFGA_ERR;
			goto out;
		}
	}

	if ((ret = get_hba_children(bus_path, dev_path, &suspend_list))
	    != SCFGA_OK) {
		free_dev_list(suspend_list);
		goto out;
	}

	if (scsi_rcm_suspend(suspend_list, errstring, flags, 0) != SCFGA_OK) {
		ret = SCFGA_ERR;
		free_dev_list(suspend_list);
	} else {
		ret = SCFGA_OK;
		*suspend_list_ptr = suspend_list;
	}
	/*FALLTHROUGH*/
out:
	S_FREE(bus_path);
	S_FREE(dev_path);
	return (ret);
}

/*
 * Resume the bus through RCM if it successfully
 * unquiesced.
 */
static void
resume_in_rcm(
	apid_t		*apidp,
	char		**suspend_list,
	char		**errstring,
	cfga_flags_t	flags)
{
	if (apidp->flags & FLAG_DISABLE_RCM)
		return;

	(void) scsi_rcm_resume(suspend_list, errstring, flags, 0);

	free_dev_list(suspend_list);
}

static scfga_ret_t
wait_for_hotplug(prompt_t *pt, int msg)
{
	char		*cu = NULL;
	int		append_newline = 0;
	scfga_ret_t	ret;

	cu = cfga_str(append_newline, msg, 0);
	if (pt->confp->confirm(pt->confp->appdata_ptr, cu) != 1) {
		ret = SCFGA_NACK;
	} else {
		ret = SCFGA_OK;
	}
	S_FREE(cu);
	return (ret);
}

static scfga_ret_t
bus_quiesce(apid_t *apidp, prompt_t *pt, char **errstring, cfga_flags_t flags)
{
	int		l_errno;
	scfga_ret_t	ret;
	scfga_ret_t	hpret;
	char		**suspend_list = NULL;

	ret = suspend_in_rcm(apidp, &suspend_list, errstring, flags);
	if (ret != SCFGA_OK) {
		return (ret);
	}

	/*
	 * If the quiesce fails, then cancel the RCM suspend.
	 * Discard any RCM failures so that the devctl failure
	 * can still be reported.
	 */
	l_errno = 0;
	ret = devctl_cmd(apidp->hba_phys, SCFGA_BUS_QUIESCE, NULL, &l_errno);
	if (ret != SCFGA_OK) {
		resume_in_rcm(apidp, suspend_list, errstring, flags);
		cfga_err(errstring, l_errno, ERR_BUS_QUIESCE, 0);
		return (ret);
	}

	/*
	 * Prompt user to proceed with physical hotplug
	 * and wait until they are done.
	 */
	hpret = wait_for_hotplug(pt, CONF_UNQUIESCE);

	/*
	 * The unquiesce may fail with EALREADY (which is ok)
	 * or some other error (which is not ok).
	 */
	l_errno = 0;
	ret = devctl_cmd(apidp->hba_phys, SCFGA_BUS_UNQUIESCE, NULL, &l_errno);
	if (ret != SCFGA_OK && l_errno != EALREADY) {
		free_dev_list(suspend_list);
		cfga_err(errstring, l_errno, ERR_BUS_UNQUIESCE, 0);
		return (SCFGA_ERR);
	}

	resume_in_rcm(apidp, suspend_list, errstring, flags);

	return (hpret);
}

#define	MAX_LOCK_TRIES		20
#define	MAX_UNLINK_TRIES	60
#define	s_getpid		(int)getpid	/* else lint causes problems */

static void
s_unlink(char *file)
{
	int	count = 0;

retry:
	if (unlink(file) == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			CFGA_TRACE1((stdout, "s_unlink[%d]: unlink failed: "
			    "%s: %s\n", s_getpid(), file, strerror(errno)));
			return;
		}

		if (++count < MAX_UNLINK_TRIES) {
			(void) sleep(1);
			goto retry;
		}
		CFGA_TRACE1((stdout, "s_unlink[%d]: retry limit: %s\n",
		    s_getpid(), file));
	} else {
		CFGA_TRACE3((stdout, "s_unlink[%d]: unlinked: %s\n",
		    s_getpid(), file));
	}
}

static scfga_ret_t
create_lock(int *fdp, struct cfga_msg *msgp, char **errstring)
{
	FILE			*fp;
	int			count;
	struct extmnttab	ent;
	int			mnted;


	*fdp = -1;

	/*
	 * Check that /var/run is mounted. In the unlikely event
	 * that the lock file is left behind, we want it
	 * cleared on the next reboot.
	 */
	errno = 0;
	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		cfga_err(errstring, errno, ERRARG_OPEN, MNTTAB, 0);
		return (SCFGA_LIB_ERR);
	}

	resetmnttab(fp);

	mnted = 0;
	while (getextmntent(fp, &ent, sizeof (ent)) == 0) {
		if (strcmp(ent.mnt_mountp, "/var/run") == 0) {
			mnted = 1;
			break;
		}
	}

	(void) fclose(fp);

	if (!mnted) {
		cfga_err(errstring, 0, ERR_VAR_RUN, 0);
		return (SCFGA_LIB_ERR);
	}

	/*
	 * Wait for a short period of time if we cannot O_EXCL create
	 * lock file. If some other cfgadm process is finishing up, we
	 * can get in. If the wait required is long however, just
	 * return SYSTEM_BUSY to the user - a hotplug operation is
	 * probably in progress.
	 */
	count = 0;
retry:
	*fdp = open(SCFGA_LOCK, O_RDWR|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
	if (*fdp == -1 && errno == EEXIST) {
		if (++count < MAX_LOCK_TRIES) {
			if (count == 1)
				cfga_msg(msgp, MSG_WAIT_LOCK, 0);
			(void) sleep(1);
			goto retry;
		}
	}

	if (*fdp == -1 && errno == EEXIST) {
		cfga_err(errstring, 0, ERRARG_QUIESCE_LOCK, SCFGA_LOCK, 0);
		return (SCFGA_SYSTEM_BUSY);
	} else if (*fdp == -1) {
		cfga_err(errstring, errno, ERRARG_QUIESCE_LOCK, SCFGA_LOCK, 0);
		return (SCFGA_LIB_ERR);
	}

	CFGA_TRACE3((stdout, "create_lock[%d]: created lockfile: %s\n",
	    s_getpid(), SCFGA_LOCK));

	return (SCFGA_OK);
}

static scfga_ret_t
syslock(int fd, char **errstring)
{
	struct flock	lock;
	int		count;
	int		rval;

	assert(fd != -1);

	CFGA_TRACE3((stdout, "syslock[%d]: trying lock: %s\n",
	    s_getpid(), SCFGA_LOCK));

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	count = 0;
	while ((rval = fcntl(fd, F_SETLKW, &lock)) == -1 && errno == EINTR) {
		if (++count >= MAX_LOCK_TRIES) {
			CFGA_TRACE1((stdout, "syslock[%d]: retry limit: %s\n",
			    s_getpid(), SCFGA_LOCK));
			goto badlock;
		}
		(void) sleep(1);
	}

	if (rval != -1) {
		CFGA_TRACE3((stdout, "syslock[%d]: locked file: %s\n",
		    s_getpid(), SCFGA_LOCK));
		return (SCFGA_OK);
	}

	/*FALLTHROUGH*/
badlock:
	cfga_err(errstring, errno, ERRARG_LOCK, SCFGA_LOCK, 0);
	/* trace message to display pid */
	CFGA_TRACE1((stdout, "syslock[%d]: cannot lock %s\n",
	    s_getpid(), SCFGA_LOCK));
	return (SCFGA_LIB_ERR);
}

static void
wait_for_child(pid_t cpid)
{
	int	status;
	pid_t	rval;

	CFGA_TRACE2((stdout, "wait_for_child[%d]: child[%d]\n",
	    s_getpid(), (int)cpid));

	for (;;) {
		while ((rval = waitpid(cpid, &status, 0)) != cpid) {
			if (errno == ECHILD) {
				CFGA_TRACE1((stdout, "waitpid[%d]: child[%d] "
				    "doesn't exist\n", s_getpid(), (int)cpid));
				return;
			}

			CFGA_TRACE3((stdout, "waitpid[%d]: returned: %d"
			    ": errno: %s\n", s_getpid(), (int)rval,
			    strerror(errno)));
		}

		if (WIFEXITED(status)) {
			CFGA_TRACE2((stdout, "waitpid[%d]: child[%d]: "
			    "normal exit\n", s_getpid(), (int)cpid));
			return;
		}

		if (WIFSIGNALED(status)) {
			CFGA_TRACE2((stdout, "waitpid[%d]: child[%d]: "
			    "signal exit\n", s_getpid(), (int)cpid));
			return;
		}

		/*
		 * The child has not terminated. We received status
		 * because the child was either stopped or continued.
		 * Wait for child termination by calling waitpid() again.
		 */
	}
}

static void
wait_and_cleanup(int fd, apid_t *apidp)
{
	int		l_errno;
	scfga_ret_t	ret;

	/* This is the child */
	CFGA_TRACE2((stdout, "child[%d]: Entering wait_cleanup\n", s_getpid()));

	if (syslock(fd, NULL) != SCFGA_OK) {
		CFGA_TRACE1((stdout, "child[%d]: lock failure "
		    " - _exit(1)\n", s_getpid()));
		/*
		 * As a last resort, unlink the lock file. This is relatively
		 * safe as the child doesn't unquiesce the bus in this case.
		 */
		s_unlink(SCFGA_LOCK);
		_exit(1);
	}

	l_errno = 0;
	ret = devctl_cmd(apidp->hba_phys, SCFGA_BUS_UNQUIESCE, NULL, &l_errno);
	if (ret != SCFGA_OK) {
		if (l_errno == EALREADY)
			CFGA_TRACE3((stdout, "child[%d]: bus already "
			    "unquiesced: %s\n", s_getpid(), apidp->hba_phys));
		else
			CFGA_TRACE1((stdout, "child[%d]: unquiesce failed: "
			    "%s\n", s_getpid(), strerror(l_errno)));
	} else {
		CFGA_TRACE1((stdout, "child[%d]: unquiesced bus: %s\n",
		    s_getpid(), apidp->hba_phys));
	}

	s_unlink(SCFGA_LOCK);

	CFGA_TRACE2((stdout, "child[%d]: _exit(0)\n", s_getpid()));

	_exit(0);
}

static void
sigblk(sigset_t *osp)
{
	sigset_t set;

	(void) sigemptyset(&set);
	(void) sigemptyset(osp);
	(void) sigaddset(&set, SIGHUP);
	(void) sigaddset(&set, SIGINT);
	(void) sigaddset(&set, SIGQUIT);
	(void) sigaddset(&set, SIGTERM);
	(void) sigaddset(&set, SIGUSR1);
	(void) sigaddset(&set, SIGUSR2);
	(void) sigprocmask(SIG_BLOCK, &set, osp);
}

static void
sigunblk(sigset_t *osp)
{
	(void) sigprocmask(SIG_SETMASK, osp, NULL);
}

/*
 * Here is the algorithm used to ensure that a SCSI bus is not
 * left in the quiesced state:
 *
 *	lock quiesce mutex	// single threads this code
 *	open(O_CREAT|O_EXCL) lock file	// only 1 process at a time
 *	exclusive record lock on lock file
 *	fork1()
 *	quiesce bus
 *	do the physical hotplug operation
 *	unquiesce bus
 *	unlock record lock
 *		-> *child*
 *		-> wait for record lock
 *		-> unconditionally unquiesce bus
 *		-> unlink lock file
 *		-> exit
 *	wait for child to exit
 *	unlock quiesce mutex
 *
 * NOTE1: since record locks are per-process and a close() can
 * release a lock, to keep things MT-safe we need a quiesce mutex.
 *
 * NOTE2: To ensure that the child does not unquiesce a bus quiesced
 * by an unrelated cfgadm_scsi operation, exactly 1 process in the
 * system can be doing an implicit quiesce operation  The exclusive
 * creation of the lock file guarantees this.
 *
 * NOTE3: This works even if the parent process dumps core and/or is
 * abnormally terminated. If the parent dies before the child is
 * forked, the bus is not quiesced. If the parent dies after the
 * bus is quiesced, the child process will ensure that the bus is
 * unquiesced.
 */
static scfga_ret_t
dev_hotplug(
	apid_t *apidp,
	prompt_t *pt,
	cfga_flags_t flags,
	int do_quiesce,
	char **errstring)
{
	scfga_ret_t	ret;
	pid_t		cpid;
	int		fd;
	sigset_t	oset;

	assert(apidp->hba_phys != NULL);
	assert(apidp->path != NULL);

	/* If no quiesce required, prompt the user to do the operation */
	if (!do_quiesce)
		return (wait_for_hotplug(pt, CONF_NO_QUIESCE));

	(void) mutex_lock(&quiesce_mutex);

	ret = create_lock(&fd, pt->msgp, errstring);
	if (ret != SCFGA_OK) {
		(void) mutex_unlock(&quiesce_mutex);
		return (ret);
	}

	ret = syslock(fd, errstring);
	if (ret != SCFGA_OK) {
		goto bad;
	}

	/*
	 * block signals in the child. Parent may
	 * exit, causing signal to be sent to child.
	 */
	sigblk(&oset);

	switch (cpid = fork1()) {
		case 0:
			/* child */
			wait_and_cleanup(fd, apidp);
			_exit(0); /* paranoia */
			/*NOTREACHED*/
		case -1:
			cfga_err(errstring, errno, ERR_FORK, 0);
			sigunblk(&oset);
			ret = SCFGA_LIB_ERR;
			goto bad;
		default:
			/* parent */
			break;
	}

	sigunblk(&oset);

	/* We have forked successfully - this is the parent */
	ret = bus_quiesce(apidp, pt, errstring, flags);

	(void) close(fd);	/* also unlocks */

	wait_for_child(cpid);

	(void) mutex_unlock(&quiesce_mutex);

	return (ret);
bad:
	(void) close(fd);
	s_unlink(SCFGA_LOCK);
	(void) mutex_unlock(&quiesce_mutex);
	return (ret);
}

/*
 * Checks if HBA controls a critical file-system (/, /usr or swap)
 * This routine reads /etc/vfstab and is NOT foolproof.
 * If an error occurs, assumes that controller is NOT critical.
 */
static int
critical_ctrlr(const char *hba_phys)
{
	FILE *fp;
	struct vfstab vfst;
	int vfsret = 1, rv = -1;
	char *bufp;
	const size_t buflen = PATH_MAX;
	char mount[MAXPATHLEN], fstype[MAXPATHLEN], spec[MAXPATHLEN];


	if ((bufp = calloc(1, buflen)) == NULL) {
		return (0);
	}

	fp = NULL;
	if ((fp = fopen(ETC_VFSTAB, "r")) == NULL) {
		rv = 0;
		goto out;
	}

	while ((vfsret = getvfsent(fp, &vfst)) == 0) {

		(void) strcpy(mount, S_STR(vfst.vfs_mountp));
		(void) strcpy(fstype, S_STR(vfst.vfs_fstype));
		(void) strcpy(spec, S_STR(vfst.vfs_special));

		/* Ignore non-critical entries */
		if (strcmp(mount, "/") && strcmp(mount, "/usr") &&
		    strcmp(fstype, "swap")) {
			continue;
		}

		/* get physical path */
		if (realpath(spec, bufp) == NULL) {
			continue;
		}

		/* Check if critical partition is on the HBA */
		if (!(rv = hba_dev_cmp(hba_phys, bufp))) {
			break;
		}
	}

	rv = !vfsret;

	/*FALLTHRU*/
out:
	S_FREE(bufp);
	if (fp != NULL) {
		(void) fclose(fp);
	}
	return (rv);
}

/*
 * Convert bus state to receptacle state
 */
static cfga_stat_t
bus_devctl_to_recep_state(uint_t bus_dc_state)
{
	cfga_stat_t rs;

	switch (bus_dc_state) {
	case BUS_ACTIVE:
		rs = CFGA_STAT_CONNECTED;
		break;
	case BUS_QUIESCED:
	case BUS_SHUTDOWN:
		rs = CFGA_STAT_DISCONNECTED;
		break;
	default:
		rs = CFGA_STAT_NONE;
		break;
	}

	return (rs);
}

static int
add_dev(di_node_t node, void *arg)
{
	int ndevs, len;
	char *path, *p;
	struct larg *largp = (struct larg *)arg;

	/* ignore hba itself and all detached nodes */
	if (di_parent_node(node) == DI_NODE_NIL ||
	    di_node_state(node) < DS_ATTACHED)
		return (DI_WALK_CONTINUE);

	if ((path = di_devfs_path(node)) == NULL) {
		largp->ndevs = -1;
		return (DI_WALK_TERMINATE);
	}

	/* sizeof (DEVICES_DIR) includes the null terminator */
	len = strlen(path) + sizeof (DEVICES_DIR);
	if ((p = malloc(len)) == NULL) {
		di_devfs_path_free(path);
		largp->ndevs = -1;
		return (DI_WALK_TERMINATE);
	}
	(void) snprintf(p, len, "%s%s", DEVICES_DIR, path);
	di_devfs_path_free(path);

	/* ignore device to be excluded */
	if (largp->dev && strcmp(largp->dev, p) == 0) {
		free(p);
		return (DI_WALK_CONTINUE);
	}

	/* grow dev_list to allow room for one more device */
	if (alloc_dev_list(largp) != 0) {
		free(p);
		return (DI_WALK_TERMINATE);
	}
	ndevs = largp->ndevs;
	largp->ndevs++;
	largp->dev_list[ndevs] = p;
	largp->dev_list[ndevs + 1] = NULL;
	return (DI_WALK_CONTINUE);
}

/*
 * Get list of children excluding dev_excl (if not null).
 */
static int
get_hba_children(char *bus_path, char *dev_excl, char ***dev_listp)
{
	int err, ret;
	walkarg_t u;
	struct larg larg;

	*dev_listp = NULL;

	u.node_args.flags = DI_WALK_CLDFIRST;
	u.node_args.fcn = add_dev;

	larg.ndevs = 0;
	larg.nelem = 0;
	larg.dev = dev_excl;
	larg.dev_list = NULL;

	ret = walk_tree(bus_path, &larg, DINFOSUBTREE, &u, SCFGA_WALK_NODE,
	    &err);
	if (larg.ndevs == -1) {
		free_dev_list(larg.dev_list);
		return (SCFGA_ERR);
	}
	*dev_listp = larg.dev_list;
	return (ret);
}

static char *
get_node_path(char *minor_path)
{
	char *path, *cp;

	if ((path = strdup(minor_path)) == NULL)
		return (NULL);
	if ((cp = strrchr(path, ':')) != NULL)
		*cp = '\0';
	return (path);
}

/*
 * Ensure largp->dev_list has room for one more device.
 * Returns 0 on success, -1 on failure.
 */
static int
alloc_dev_list(struct larg *largp)
{
	int nelem;
	char **p;

	if (largp->nelem > largp->ndevs + 2)	/* +1 for NULL termination */
		return (0);

	nelem =  largp->nelem + 16;
	p = realloc(largp->dev_list, nelem * sizeof (char *));
	if (p == NULL)
		return (-1);

	largp->dev_list = p;
	largp->nelem = nelem;
	return (0);
}

static void
free_dev_list_elements(char **dev_list)
{
	while (*dev_list) {
		free(*dev_list);
		dev_list++;
	}
}

static void
free_dev_list(char **dev_list)
{
	if (dev_list == NULL)
		return;

	free_dev_list_elements(dev_list);
	free(dev_list);
}
