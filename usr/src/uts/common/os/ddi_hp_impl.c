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

/*
 * Sun DDI hotplug implementation specific functions
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/avintr.h>
#include <sys/autoconf.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <sys/fs/dv_node.h>

/*
 * Local function prototypes
 */
/* Connector operations */
static int ddihp_cn_pre_change_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t target_state);
static int ddihp_cn_post_change_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t new_state);
static int ddihp_cn_handle_state_change(ddi_hp_cn_handle_t *hdlp);
static int ddihp_cn_change_children_state(ddi_hp_cn_handle_t *hdlp,
    boolean_t online);
/* Port operations */
static int ddihp_port_change_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t target_state);
static int ddihp_port_upgrade_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t target_state);
static int ddihp_port_downgrade_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t target_state);
/* Misc routines */
static void ddihp_update_last_change(ddi_hp_cn_handle_t *hdlp);
static boolean_t ddihp_check_status_prop(dev_info_t *dip);

/*
 * Global functions (called within hotplug framework)
 */

/*
 * Implement modctl() commands for hotplug.
 * Called by modctl_hp() in modctl.c
 */
int
ddihp_modctl(int hp_op, char *path, char *cn_name, uintptr_t arg,
    uintptr_t rval)
{
	dev_info_t		*dip;
	ddi_hp_cn_handle_t	*hdlp;
	ddi_hp_op_t		op = (ddi_hp_op_t)hp_op;
	int			count, rv, error;

	/* Get the dip of nexus node */
	dip = e_ddi_hold_devi_by_path(path, 0);

	if (dip == NULL)
		return (ENXIO);

	DDI_HP_IMPLDBG((CE_CONT, "ddihp_modctl: dip %p op %x path %s "
	    "cn_name %s arg %p rval %p\n", (void *)dip, hp_op, path, cn_name,
	    (void *)arg, (void *)rval));

	if (!NEXUS_HAS_HP_OP(dip)) {
		ddi_release_devi(dip);
		return (ENOTSUP);
	}

	/* Lock before access */
	ndi_devi_enter(dip, &count);

	hdlp = ddihp_cn_name_to_handle(dip, cn_name);

	if (hp_op == DDI_HPOP_CN_CREATE_PORT) {
		if (hdlp != NULL) {
			/* this port already exists. */
			error = EEXIST;

			goto done;
		}
		rv = (*(DEVI(dip)->devi_ops->devo_bus_ops->bus_hp_op))(
		    dip, cn_name, op, NULL, NULL);
	} else {
		if (hdlp == NULL) {
			/* Invalid Connection name */
			error = ENXIO;

			goto done;
		}
		if (hp_op == DDI_HPOP_CN_CHANGE_STATE) {
			ddi_hp_cn_state_t target_state = (ddi_hp_cn_state_t)arg;
			ddi_hp_cn_state_t result_state = 0;

			DDIHP_CN_OPS(hdlp, op, (void *)&target_state,
			    (void *)&result_state, rv);

			DDI_HP_IMPLDBG((CE_CONT, "ddihp_modctl: target_state="
			    "%x, result_state=%x, rv=%x \n",
			    target_state, result_state, rv));
		} else {
			DDIHP_CN_OPS(hdlp, op, (void *)arg, (void *)rval, rv);
		}
	}
	switch (rv) {
	case DDI_SUCCESS:
		error = 0;
		break;
	case DDI_EINVAL:
		error = EINVAL;
		break;
	case DDI_EBUSY:
		error = EBUSY;
		break;
	case DDI_ENOTSUP:
		error = ENOTSUP;
		break;
	case DDI_ENOMEM:
		error = ENOMEM;
		break;
	default:
		error = EIO;
	}

done:
	ndi_devi_exit(dip, count);

	ddi_release_devi(dip);

	return (error);
}

/*
 * Return the state of Hotplug Connection (CN)
 */
int
ddihp_cn_getstate(ddi_hp_cn_handle_t *hdlp)
{
	ddi_hp_cn_state_t	new_state;
	int			ret;

	DDI_HP_IMPLDBG((CE_CONT, "ddihp_cn_getstate: pdip %p hdlp %p\n",
	    (void *)hdlp->cn_dip, (void *)hdlp));

	ASSERT(DEVI_BUSY_OWNED(hdlp->cn_dip));

	DDIHP_CN_OPS(hdlp, DDI_HPOP_CN_GET_STATE,
	    NULL, (void *)&new_state, ret);
	if (ret != DDI_SUCCESS) {
		DDI_HP_IMPLDBG((CE_CONT, "ddihp_cn_getstate: "
		    "CN %p getstate command failed\n", (void *)hdlp));

		return (ret);
	}

	DDI_HP_IMPLDBG((CE_CONT, "ddihp_cn_getstate: hdlp %p "
	    "current Connection state %x new Connection state %x\n",
	    (void *)hdlp, hdlp->cn_info.cn_state, new_state));

	if (new_state != hdlp->cn_info.cn_state) {
		hdlp->cn_info.cn_state = new_state;
		ddihp_update_last_change(hdlp);
	}

	return (ret);
}

/*
 * Implementation function for unregistering the Hotplug Connection (CN)
 */
int
ddihp_cn_unregister(ddi_hp_cn_handle_t *hdlp)
{
	dev_info_t	*dip = hdlp->cn_dip;

	DDI_HP_NEXDBG((CE_CONT, "ddihp_cn_unregister: hdlp %p\n",
	    (void *)hdlp));

	ASSERT(DEVI_BUSY_OWNED(dip));

	(void) ddihp_cn_getstate(hdlp);

	if (hdlp->cn_info.cn_state > DDI_HP_CN_STATE_OFFLINE) {
		DDI_HP_NEXDBG((CE_CONT, "ddihp_cn_unregister: dip %p, hdlp %p "
		    "state %x. Device busy, failed to unregister connection!\n",
		    (void *)dip, (void *)hdlp, hdlp->cn_info.cn_state));

		return (DDI_EBUSY);
	}

	/* unlink the handle */
	DDIHP_LIST_REMOVE(ddi_hp_cn_handle_t, (DEVI(dip)->devi_hp_hdlp), hdlp);

	kmem_free(hdlp->cn_info.cn_name, strlen(hdlp->cn_info.cn_name) + 1);
	kmem_free(hdlp, sizeof (ddi_hp_cn_handle_t));
	return (DDI_SUCCESS);
}

/*
 * For a given Connection name and the dip node where the Connection is
 * supposed to be, find the corresponding hotplug handle.
 */
ddi_hp_cn_handle_t *
ddihp_cn_name_to_handle(dev_info_t *dip, char *cn_name)
{
	ddi_hp_cn_handle_t *hdlp;

	ASSERT(DEVI_BUSY_OWNED(dip));

	DDI_HP_IMPLDBG((CE_CONT, "ddihp_cn_name_to_handle: "
	    "dip %p cn_name to find: %s", (void *)dip, cn_name));
	for (hdlp = DEVI(dip)->devi_hp_hdlp; hdlp; hdlp = hdlp->next) {
		DDI_HP_IMPLDBG((CE_CONT, "ddihp_cn_name_to_handle: "
		    "current cn_name: %s", hdlp->cn_info.cn_name));

		if (strcmp(cn_name, hdlp->cn_info.cn_name) == 0) {
			/* found */
			return (hdlp);
		}
	}
	DDI_HP_IMPLDBG((CE_CONT, "ddihp_cn_name_to_handle: "
	    "failed to find cn_name"));
	return (NULL);
}

/*
 * Process the hotplug operations for Connector and also create Port
 * upon user command.
 */
int
ddihp_connector_ops(ddi_hp_cn_handle_t *hdlp, ddi_hp_op_t op,
    void *arg, void *result)
{
	int			rv = DDI_SUCCESS;
	dev_info_t		*dip = hdlp->cn_dip;

	ASSERT(DEVI_BUSY_OWNED(dip));

	DDI_HP_IMPLDBG((CE_CONT, "ddihp_connector_ops: pdip=%p op=%x "
	    "hdlp=%p arg=%p\n", (void *)dip, op, (void *)hdlp, arg));

	if (op == DDI_HPOP_CN_CHANGE_STATE) {
		ddi_hp_cn_state_t target_state = *(ddi_hp_cn_state_t *)arg;

		rv = ddihp_cn_pre_change_state(hdlp, target_state);
		if (rv != DDI_SUCCESS) {
			/* the state is not changed */
			*((ddi_hp_cn_state_t *)result) =
			    hdlp->cn_info.cn_state;
			return (rv);
		}
	}
	ASSERT(NEXUS_HAS_HP_OP(dip));
	rv = (*(DEVI(dip)->devi_ops->devo_bus_ops->bus_hp_op))(
	    dip, hdlp->cn_info.cn_name, op, arg, result);

	if (rv != DDI_SUCCESS) {
		DDI_HP_IMPLDBG((CE_CONT, "ddihp_connector_ops: "
		    "bus_hp_op failed: pdip=%p cn_name:%s op=%x "
		    "hdlp=%p arg=%p\n", (void *)dip, hdlp->cn_info.cn_name,
		    op, (void *)hdlp, arg));
	}
	if (op == DDI_HPOP_CN_CHANGE_STATE) {
		int rv_post;

		DDI_HP_IMPLDBG((CE_CONT, "ddihp_connector_ops: "
		    "old_state=%x, new_state=%x, rv=%x\n",
		    hdlp->cn_info.cn_state, *(ddi_hp_cn_state_t *)result, rv));

		/*
		 * After state change op is successfully done or
		 * failed at some stages, continue to do some jobs.
		 */
		rv_post = ddihp_cn_post_change_state(hdlp,
		    *(ddi_hp_cn_state_t *)result);

		if (rv_post != DDI_SUCCESS)
			rv = rv_post;
	}

	return (rv);
}

/*
 * Process the hotplug op for Port
 */
int
ddihp_port_ops(ddi_hp_cn_handle_t *hdlp, ddi_hp_op_t op,
    void *arg, void *result)
{
	int		ret = DDI_SUCCESS;

	ASSERT(DEVI_BUSY_OWNED(hdlp->cn_dip));

	DDI_HP_IMPLDBG((CE_CONT, "ddihp_port_ops: pdip=%p op=%x hdlp=%p "
	    "arg=%p\n", (void *)hdlp->cn_dip, op, (void *)hdlp, arg));

	switch (op) {
	case DDI_HPOP_CN_GET_STATE:
	{
		int state;

		state = hdlp->cn_info.cn_state;

		if (hdlp->cn_info.cn_child == NULL) {
			/* No child. Either present or empty. */
			if (state >= DDI_HP_CN_STATE_PORT_PRESENT)
				state = DDI_HP_CN_STATE_PORT_PRESENT;
			else
				state = DDI_HP_CN_STATE_PORT_EMPTY;

		} else { /* There is a child of this Port */

			/* Check DEVI(dip)->devi_node_state */
			switch (i_ddi_node_state(hdlp->cn_info.cn_child)) {
			case	DS_INVAL:
			case	DS_PROTO:
			case	DS_LINKED:
			case	DS_BOUND:
			case	DS_INITIALIZED:
			case	DS_PROBED:
				state = DDI_HP_CN_STATE_OFFLINE;
				break;
			case	DS_ATTACHED:
				state = DDI_HP_CN_STATE_MAINTENANCE;
				break;
			case	DS_READY:
				state = DDI_HP_CN_STATE_ONLINE;
				break;
			default:
				/* should never reach here */
				ASSERT("unknown devinfo state");
			}
			/*
			 * Check DEVI(dip)->devi_state in case the node is
			 * downgraded or quiesced.
			 */
			if (state == DDI_HP_CN_STATE_ONLINE &&
			    ddi_get_devstate(hdlp->cn_info.cn_child) !=
			    DDI_DEVSTATE_UP)
				state = DDI_HP_CN_STATE_MAINTENANCE;
		}

		*((ddi_hp_cn_state_t *)result) = state;

		break;
	}
	case DDI_HPOP_CN_CHANGE_STATE:
	{
		ddi_hp_cn_state_t target_state = *(ddi_hp_cn_state_t *)arg;
		ddi_hp_cn_state_t curr_state = hdlp->cn_info.cn_state;

		ret = ddihp_port_change_state(hdlp, target_state);
		if (curr_state != hdlp->cn_info.cn_state) {
			ddihp_update_last_change(hdlp);
		}
		*((ddi_hp_cn_state_t *)result) = hdlp->cn_info.cn_state;

		break;
	}
	case DDI_HPOP_CN_REMOVE_PORT:
	{
		(void) ddihp_cn_getstate(hdlp);

		if (hdlp->cn_info.cn_state != DDI_HP_CN_STATE_PORT_EMPTY) {
			/* Only empty PORT can be removed by commands */
			ret = DDI_EBUSY;

			break;
		}

		ret = ddihp_cn_unregister(hdlp);
		break;
	}
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

/*
 * Generate the system event with a possible hint
 */
/* ARGSUSED */
void
ddihp_cn_gen_sysevent(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_sysevent_t event_sub_class, int hint, int kmflag)
{
	dev_info_t	*dip = hdlp->cn_dip;
	char		*cn_path, *ap_id;
	char		*ev_subclass = NULL;
	nvlist_t	*ev_attr_list = NULL;
	sysevent_id_t	eid;
	int		ap_id_len, err;

	cn_path = kmem_zalloc(MAXPATHLEN, kmflag);
	if (cn_path == NULL) {
		cmn_err(CE_WARN,
		    "%s%d: Failed to allocate memory for hotplug"
		    " connection: %s\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    hdlp->cn_info.cn_name);

		return;
	}

	/*
	 * Minor device name will be bus path
	 * concatenated with connection name.
	 * One of consumers of the sysevent will pass it
	 * to cfgadm as AP ID.
	 */
	(void) strcpy(cn_path, "/devices");
	(void) ddi_pathname(dip, cn_path + strlen("/devices"));

	ap_id_len = strlen(cn_path) + strlen(":") +
	    strlen(hdlp->cn_info.cn_name) + 1;
	ap_id = kmem_zalloc(ap_id_len, kmflag);
	if (ap_id == NULL) {
		cmn_err(CE_WARN,
		    "%s%d: Failed to allocate memory for AP ID: %s:%s\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    cn_path, hdlp->cn_info.cn_name);
		kmem_free(cn_path, MAXPATHLEN);

		return;
	}

	(void) strcpy(ap_id, cn_path);
	(void) strcat(ap_id, ":");
	(void) strcat(ap_id, hdlp->cn_info.cn_name);
	kmem_free(cn_path, MAXPATHLEN);

	err = nvlist_alloc(&ev_attr_list, NV_UNIQUE_NAME_TYPE, kmflag);

	if (err != 0) {
		cmn_err(CE_WARN,
		    "%s%d: Failed to allocate memory for event subclass %d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    event_sub_class);
		kmem_free(ap_id, ap_id_len);

		return;
	}

	switch (event_sub_class) {
	case DDI_HP_CN_STATE_CHANGE:
		ev_subclass = ESC_DR_AP_STATE_CHANGE;

		switch (hint) {
		case SE_NO_HINT:	/* fall through */
		case SE_HINT_INSERT:	/* fall through */
		case SE_HINT_REMOVE:
			err = nvlist_add_string(ev_attr_list, DR_HINT,
			    SE_HINT2STR(hint));

			if (err != 0) {
				cmn_err(CE_WARN, "%s%d: Failed to add attr [%s]"
				    " for %s event\n", ddi_driver_name(dip),
				    ddi_get_instance(dip), DR_HINT,
				    ESC_DR_AP_STATE_CHANGE);

				goto done;
			}
			break;

		default:
			cmn_err(CE_WARN, "%s%d: Unknown hint on sysevent\n",
			    ddi_driver_name(dip), ddi_get_instance(dip));

			goto done;
		}

		break;

	/* event sub class: DDI_HP_CN_REQ */
	case DDI_HP_CN_REQ:
		ev_subclass = ESC_DR_REQ;

		switch (hint) {
		case SE_INVESTIGATE_RES: /* fall through */
		case SE_INCOMING_RES:	/* fall through */
		case SE_OUTGOING_RES:	/* fall through */
			err = nvlist_add_string(ev_attr_list, DR_REQ_TYPE,
			    SE_REQ2STR(hint));

			if (err != 0) {
				cmn_err(CE_WARN,
				    "%s%d: Failed to add attr [%s] for %s \n"
				    "event", ddi_driver_name(dip),
				    ddi_get_instance(dip),
				    DR_REQ_TYPE, ESC_DR_REQ);

				goto done;
			}
			break;

		default:
			cmn_err(CE_WARN, "%s%d:  Unknown hint on sysevent\n",
			    ddi_driver_name(dip), ddi_get_instance(dip));

			goto done;
		}

		break;

	default:
		cmn_err(CE_WARN, "%s%d:  Unknown Event subclass\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		goto done;
	}

	/*
	 * Add Hotplug Connection (CN) as attribute (common attribute)
	 */
	err = nvlist_add_string(ev_attr_list, DR_AP_ID, ap_id);
	if (err != 0) {
		cmn_err(CE_WARN, "%s%d: Failed to add attr [%s] for %s event\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    DR_AP_ID, EC_DR);

		goto done;
	}

	/*
	 * Log this event with sysevent framework.
	 */
	err = ddi_log_sysevent(dip, DDI_VENDOR_SUNW, EC_DR,
	    ev_subclass, ev_attr_list, &eid,
	    ((kmflag == KM_SLEEP) ? DDI_SLEEP : DDI_NOSLEEP));

	if (err != 0) {
		cmn_err(CE_WARN, "%s%d: Failed to log %s event\n",
		    ddi_driver_name(dip), ddi_get_instance(dip), EC_DR);
	}

done:
	nvlist_free(ev_attr_list);
	kmem_free(ap_id, ap_id_len);
}

/*
 * Local functions (called within this file)
 */

/*
 * Connector operations
 */

/*
 * Prepare to change state for a Connector: offline, unprobe, etc.
 */
static int
ddihp_cn_pre_change_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t	curr_state = hdlp->cn_info.cn_state;
	dev_info_t		*dip = hdlp->cn_dip;
	int			rv = DDI_SUCCESS;

	if (curr_state > target_state &&
	    curr_state == DDI_HP_CN_STATE_ENABLED) {
		/*
		 * If the Connection goes to a lower state from ENABLED,
		 *  then offline all children under it.
		 */
		rv = ddihp_cn_change_children_state(hdlp, B_FALSE);
		if (rv != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "(%s%d): "
			    "failed to unconfigure the device in the"
			    " Connection %s\n", ddi_driver_name(dip),
			    ddi_get_instance(dip),
			    hdlp->cn_info.cn_name);

			return (rv);
		}
		ASSERT(NEXUS_HAS_HP_OP(dip));
		/*
		 * Remove all the children and their ports
		 * after they are offlined.
		 */
		rv = (*(DEVI(dip)->devi_ops->devo_bus_ops->bus_hp_op))(
		    dip, hdlp->cn_info.cn_name, DDI_HPOP_CN_UNPROBE,
		    NULL, NULL);
		if (rv != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "(%s%d): failed"
			    " to unprobe the device in the Connector"
			    " %s\n", ddi_driver_name(dip),
			    ddi_get_instance(dip),
			    hdlp->cn_info.cn_name);

			return (rv);
		}

		DDI_HP_NEXDBG((CE_CONT,
		    "ddihp_connector_ops (%s%d): device"
		    " is unconfigured and unprobed in Connector %s\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    hdlp->cn_info.cn_name));
	}

	return (rv);
}

/*
 * Jobs after change state of a Connector: update last change time,
 * probe, online, sysevent, etc.
 */
static int
ddihp_cn_post_change_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t new_state)
{
	int			rv = DDI_SUCCESS;
	ddi_hp_cn_state_t	curr_state = hdlp->cn_info.cn_state;

	/* Update the state in handle */
	if (new_state != curr_state) {
		hdlp->cn_info.cn_state = new_state;
		ddihp_update_last_change(hdlp);
	}

	if (curr_state < new_state &&
	    new_state == DDI_HP_CN_STATE_ENABLED) {
		/*
		 * Probe and online devices if state is
		 * upgraded to ENABLED.
		 */
		rv = ddihp_cn_handle_state_change(hdlp);
	}
	if (curr_state != hdlp->cn_info.cn_state) {
		/*
		 * For Connector, generate a sysevent on
		 * state change.
		 */
		ddihp_cn_gen_sysevent(hdlp, DDI_HP_CN_STATE_CHANGE,
		    SE_NO_HINT, KM_SLEEP);
	}

	return (rv);
}

/*
 * Handle Connector state change.
 *
 * This function is called after connector is upgraded to ENABLED sate.
 * It probes the device plugged in the connector to setup devinfo nodes
 * and then online the nodes.
 */
static int
ddihp_cn_handle_state_change(ddi_hp_cn_handle_t *hdlp)
{
	dev_info_t		*dip = hdlp->cn_dip;
	int			rv = DDI_SUCCESS;

	ASSERT(DEVI_BUSY_OWNED(dip));
	ASSERT(NEXUS_HAS_HP_OP(dip));
	/*
	 * If the Connection went to state ENABLED from a lower state,
	 * probe it.
	 */
	rv = (*(DEVI(dip)->devi_ops->devo_bus_ops->bus_hp_op))(
	    dip, hdlp->cn_info.cn_name, DDI_HPOP_CN_PROBE, NULL, NULL);

	if (rv != DDI_SUCCESS) {
		ddi_hp_cn_state_t	target_state = DDI_HP_CN_STATE_POWERED;
		ddi_hp_cn_state_t	result_state = 0;

		/*
		 * Probe failed. Disable the connector so that it can
		 * be enabled again by a later try from userland.
		 */
		(void) (*(DEVI(dip)->devi_ops->devo_bus_ops->bus_hp_op))(
		    dip, hdlp->cn_info.cn_name, DDI_HPOP_CN_CHANGE_STATE,
		    (void *)&target_state, (void *)&result_state);

		if (result_state && result_state != hdlp->cn_info.cn_state) {
			hdlp->cn_info.cn_state = result_state;
			ddihp_update_last_change(hdlp);
		}

		cmn_err(CE_WARN,
		    "(%s%d): failed to probe the Connection %s\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    hdlp->cn_info.cn_name);

		return (rv);
	}
	/*
	 * Try to online all the children of CN.
	 */
	(void) ddihp_cn_change_children_state(hdlp, B_TRUE);

	DDI_HP_NEXDBG((CE_CONT, "ddihp_cn_event_handler (%s%d): "
	    "device is configured in the Connection %s\n",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    hdlp->cn_info.cn_name));
	return (rv);
}

/*
 * Online/Offline all the children under the Hotplug Connection (CN)
 *
 * Do online operation when the online parameter is true; otherwise do offline.
 */
static int
ddihp_cn_change_children_state(ddi_hp_cn_handle_t *hdlp, boolean_t online)
{
	dev_info_t		*dip = hdlp->cn_dip;
	dev_info_t		*cdip;
	ddi_hp_cn_handle_t	*h;
	int			rv = DDI_SUCCESS;

	DDI_HP_IMPLDBG((CE_CONT, "ddihp_cn_change_children_state:"
	    " dip %p hdlp %p, online %x\n",
	    (void *)dip, (void *)hdlp, online));

	ASSERT(DEVI_BUSY_OWNED(dip));

	/*
	 * Return invalid if Connection state is < DDI_HP_CN_STATE_ENABLED
	 * when try to online children.
	 */
	if (online && hdlp->cn_info.cn_state < DDI_HP_CN_STATE_ENABLED) {
		DDI_HP_IMPLDBG((CE_CONT, "ddihp_cn_change_children_state: "
		    "Connector %p is not in probed state\n", (void *)hdlp));

		return (DDI_EINVAL);
	}

	/* Now, online/offline all the devices depending on the Connector */

	if (!online) {
		/*
		 * For offline operation we need to firstly clean up devfs
		 * so as not to prevent driver detach.
		 */
		(void) devfs_clean(dip, NULL, DV_CLEAN_FORCE);
	}
	for (h = DEVI(dip)->devi_hp_hdlp; h; h = h->next) {
		if (h->cn_info.cn_type != DDI_HP_CN_TYPE_VIRTUAL_PORT)
			continue;

		if (h->cn_info.cn_num_dpd_on !=
		    hdlp->cn_info.cn_num)
			continue;

		cdip = h->cn_info.cn_child;
		ASSERT(cdip);
		if (online) {
			/* online children */
			if (!ddihp_check_status_prop(dip))
				continue;

			if (ndi_devi_online(cdip,
			    NDI_ONLINE_ATTACH | NDI_CONFIG) != NDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "(%s%d):"
				    " failed to attach driver for a device"
				    " (%s%d) under the Connection %s\n",
				    ddi_driver_name(dip), ddi_get_instance(dip),
				    ddi_driver_name(cdip),
				    ddi_get_instance(cdip),
				    hdlp->cn_info.cn_name);
				/*
				 * One of the devices failed to online, but we
				 * want to continue to online the rest siblings
				 * after mark the failure here.
				 */
				rv = DDI_FAILURE;

				continue;
			}
		} else {
			/* offline children */
			if (ndi_devi_offline(cdip, NDI_UNCONFIG) !=
			    NDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "(%s%d):"
				    " failed to dettach driver for the device"
				    " (%s%d) in the Connection %s\n",
				    ddi_driver_name(dip), ddi_get_instance(dip),
				    ddi_driver_name(cdip),
				    ddi_get_instance(cdip),
				    hdlp->cn_info.cn_name);

				return (DDI_EBUSY);
			}
		}
	}

	return (rv);
}

/*
 * Port operations
 */

/*
 * Change Port state to target_state.
 */
static int
ddihp_port_change_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state = hdlp->cn_info.cn_state;

	if (target_state < DDI_HP_CN_STATE_PORT_EMPTY ||
	    target_state > DDI_HP_CN_STATE_ONLINE) {

		return (DDI_EINVAL);
	}

	if (curr_state < target_state)
		return (ddihp_port_upgrade_state(hdlp, target_state));
	else if (curr_state > target_state)
		return (ddihp_port_downgrade_state(hdlp, target_state));
	else
		return (DDI_SUCCESS);
}

/*
 * Upgrade port state to target_state.
 */
static int
ddihp_port_upgrade_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t	curr_state, new_state, result_state;
	dev_info_t		*cdip;
	int			rv = DDI_SUCCESS;

	curr_state = hdlp->cn_info.cn_state;
	while (curr_state < target_state) {
		switch (curr_state) {
		case DDI_HP_CN_STATE_PORT_EMPTY:
			/* Check the existence of the corresponding hardware */
			new_state = DDI_HP_CN_STATE_PORT_PRESENT;
			rv = ddihp_connector_ops(hdlp,
			    DDI_HPOP_CN_CHANGE_STATE,
			    (void *)&new_state, (void *)&result_state);
			if (rv == DDI_SUCCESS) {
				hdlp->cn_info.cn_state =
				    result_state;
			}
			break;
		case DDI_HP_CN_STATE_PORT_PRESENT:
			/* Read-only probe the corresponding hardware. */
			new_state = DDI_HP_CN_STATE_OFFLINE;
			rv = ddihp_connector_ops(hdlp,
			    DDI_HPOP_CN_CHANGE_STATE,
			    (void *)&new_state, &cdip);
			if (rv == DDI_SUCCESS) {
				hdlp->cn_info.cn_state =
				    DDI_HP_CN_STATE_OFFLINE;

				ASSERT(hdlp->cn_info.cn_child == NULL);
				hdlp->cn_info.cn_child = cdip;
			}
			break;
		case DDI_HP_CN_STATE_OFFLINE:
			/* fall through */
		case DDI_HP_CN_STATE_MAINTENANCE:

			cdip = hdlp->cn_info.cn_child;

			rv = ndi_devi_online(cdip,
			    NDI_ONLINE_ATTACH | NDI_CONFIG);
			if (rv == NDI_SUCCESS) {
				hdlp->cn_info.cn_state =
				    DDI_HP_CN_STATE_ONLINE;
				rv = DDI_SUCCESS;
			} else {
				rv = DDI_FAILURE;
				DDI_HP_IMPLDBG((CE_CONT,
				    "ddihp_port_upgrade_state: "
				    "failed to online device %p at port: %s\n",
				    (void *)cdip, hdlp->cn_info.cn_name));
			}
			break;
		case DDI_HP_CN_STATE_ONLINE:

			break;
		default:
			/* should never reach here */
			ASSERT("unknown devinfo state");
		}
		curr_state = hdlp->cn_info.cn_state;
		if (rv != DDI_SUCCESS) {
			DDI_HP_IMPLDBG((CE_CONT, "ddihp_port_upgrade_state: "
			    "failed curr_state=%x, target_state=%x \n",
			    curr_state, target_state));
			return (rv);
		}
	}

	return (rv);
}

/*
 * Downgrade state to target_state
 */
static int
ddihp_port_downgrade_state(ddi_hp_cn_handle_t *hdlp,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t	curr_state, new_state, result_state;
	dev_info_t		*dip = hdlp->cn_dip;
	dev_info_t		*cdip;
	int			rv = DDI_SUCCESS;

	curr_state = hdlp->cn_info.cn_state;
	while (curr_state > target_state) {

		switch (curr_state) {
		case DDI_HP_CN_STATE_PORT_EMPTY:

			break;
		case DDI_HP_CN_STATE_PORT_PRESENT:
			/* Check the existence of the corresponding hardware */
			new_state = DDI_HP_CN_STATE_PORT_EMPTY;
			rv = ddihp_connector_ops(hdlp,
			    DDI_HPOP_CN_CHANGE_STATE,
			    (void *)&new_state, (void *)&result_state);
			if (rv == DDI_SUCCESS)
				hdlp->cn_info.cn_state =
				    result_state;

			break;
		case DDI_HP_CN_STATE_OFFLINE:
			/*
			 * Read-only unprobe the corresponding hardware:
			 * 1. release the assigned resource;
			 * 2. remove the node pointed by the port's cn_child
			 */
			new_state = DDI_HP_CN_STATE_PORT_PRESENT;
			rv = ddihp_connector_ops(hdlp,
			    DDI_HPOP_CN_CHANGE_STATE,
			    (void *)&new_state, (void *)&result_state);
			if (rv == DDI_SUCCESS)
				hdlp->cn_info.cn_state =
				    DDI_HP_CN_STATE_PORT_PRESENT;
			break;
		case DDI_HP_CN_STATE_MAINTENANCE:
			/* fall through. */
		case DDI_HP_CN_STATE_ONLINE:
			cdip = hdlp->cn_info.cn_child;

			(void) devfs_clean(dip, NULL, DV_CLEAN_FORCE);
			rv = ndi_devi_offline(cdip, NDI_UNCONFIG);
			if (rv == NDI_SUCCESS) {
				hdlp->cn_info.cn_state =
				    DDI_HP_CN_STATE_OFFLINE;
				rv = DDI_SUCCESS;
			} else {
				rv = DDI_EBUSY;
				DDI_HP_IMPLDBG((CE_CONT,
				    "ddihp_port_downgrade_state: failed "
				    "to offline node, rv=%x, cdip=%p \n",
				    rv, (void *)cdip));
			}

			break;
		default:
			/* should never reach here */
			ASSERT("unknown devinfo state");
		}
		curr_state = hdlp->cn_info.cn_state;
		if (rv != DDI_SUCCESS) {
			DDI_HP_IMPLDBG((CE_CONT,
			    "ddihp_port_downgrade_state: failed "
			    "curr_state=%x, target_state=%x \n",
			    curr_state, target_state));
			return (rv);
		}
	}

	return (rv);
}

/*
 * Misc routines
 */

/* Update the last state change time */
static void
ddihp_update_last_change(ddi_hp_cn_handle_t *hdlp)
{
	time_t			time;

	if (drv_getparm(TIME, (void *)&time) != DDI_SUCCESS)
		hdlp->cn_info.cn_last_change = (time_t)-1;
	else
		hdlp->cn_info.cn_last_change = (time32_t)time;
}

/*
 * Check the device for a 'status' property.  A conforming device
 * should have a status of "okay", "disabled", "fail", or "fail-xxx".
 *
 * Return FALSE for a conforming device that is disabled or faulted.
 * Return TRUE in every other case.
 *
 * 'status' property is NOT a bus specific property. It is defined in page 184,
 * IEEE 1275 spec. The full name of the spec is "IEEE Standard for
 * Boot (Initialization Configuration) Firmware: Core Requirements and
 * Practices".
 */
static boolean_t
ddihp_check_status_prop(dev_info_t *dip)
{
	char		*status_prop;
	boolean_t	rv = B_TRUE;

	/* try to get the 'status' property */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "status", &status_prop) == DDI_PROP_SUCCESS) {
		/*
		 * test if the status is "disabled", "fail", or
		 * "fail-xxx".
		 */
		if (strcmp(status_prop, "disabled") == 0) {
			rv = B_FALSE;
			DDI_HP_IMPLDBG((CE_CONT, "ddihp_check_status_prop "
			    "(%s%d): device is in disabled state",
			    ddi_driver_name(dip), ddi_get_instance(dip)));
		} else if (strncmp(status_prop, "fail", 4) == 0) {
			rv = B_FALSE;
			cmn_err(CE_WARN,
			    "hotplug (%s%d): device is in fault state (%s)\n",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    status_prop);
		}

		ddi_prop_free(status_prop);
	}

	return (rv);
}
