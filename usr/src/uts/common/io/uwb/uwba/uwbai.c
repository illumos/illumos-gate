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
 * UWB radio controller driver interfaces
 */
#include <sys/uwb/uwba/uwba.h>
#include <sys/sunndi.h>
#include <sys/ddi.h>


/*
 * The following  is a list of functions which handles the rccb command
 * for uwb model, each rccb command has a related handler. Not all the
 * rccb command is supportted, the below uwb_rccb_handler_tbl lists
 * the supported handler
 */
static int	uwb_do_cmd_rccb(uwb_dev_handle_t, uwb_rccb_cmd_t *);
static int	uwb_do_cmd_scan(uwb_dev_handle_t, uwb_rccb_cmd_t *);
static int	uwb_do_cmd_start_beacon(uwb_dev_handle_t,
		uwb_rccb_cmd_t *);
static int	uwb_do_cmd_dev_addr_mgmt(uwb_dev_handle_t, uwb_rccb_cmd_t *);


static int	uwb_process_rccb_cmd_private(uwb_dev_handle_t,
		uwb_rccb_cmd_t *, uwb_cmd_result_t *);

static int	uwb_send_rccb_cmd(uwb_dev_handle_t, uwb_rccb_cmd_t *);
static int	uwb_check_rccb_cmd(uwb_dev_handle_t, uwb_rccb_cmd_t *);
static int	uwb_check_dev_state(uwba_dev_t *, uwb_rccb_cmd_t *);
static void	uwb_set_dev_state(uwba_dev_t *, uwb_rccb_cmd_t *);

static int 	uwb_wait_cmd_result(uwb_dev_handle_t);
static void 	uwb_free_cmd_result(uwb_dev_handle_t);

static int	uwb_rccb_cmd_enter(uwba_dev_t *);
static void	uwb_rccb_cmd_leave(uwba_dev_t *);

static int	uwb_do_ioctl_rccb_cmd(uwb_dev_handle_t,
		uint16_t, intptr_t, int);

static uwb_notif_wrapper_t *uwb_get_notification(uwb_dev_handle_t,
		intptr_t, int);
static void uwb_free_notification(uwb_notif_wrapper_t *);
/*
 *
 * This is all the rccb command handler supported and not supported in
 * current version. rccb handler table map
 */
static uwb_rccb_handler_t uwb_rccb_handler_tbl [] = {
	UWB_RCCB_NULL_HANDLER, 		/* CHANNEL_CHANGE */
	uwb_do_cmd_dev_addr_mgmt,	/* DEV_ADDR_MGMT */
	uwb_do_cmd_rccb,		/* GET_IE */
	uwb_do_cmd_rccb,		/* RESET */
	uwb_do_cmd_scan,		/* SCAN */
	UWB_RCCB_NULL_HANDLER,		/* SET_BEACON_FILTER */
	UWB_RCCB_NULL_HANDLER,		/* SET_DRP_IE */
	UWB_RCCB_NULL_HANDLER,		/* SET_IE */
	UWB_RCCB_NULL_HANDLER,		/* SET_NOTIFICATION_FILTER */
	UWB_RCCB_NULL_HANDLER,		/* SET_TX_POWER */
	UWB_RCCB_NULL_HANDLER,		/* SLEEP */
	uwb_do_cmd_start_beacon,	/* START_BEACON */
	uwb_do_cmd_rccb,		/* STOP_BEACON */
	UWB_RCCB_NULL_HANDLER,		/* BP_MERGE */
	UWB_RCCB_NULL_HANDLER		/* SEND_COMMAND_FRAME */
};

/*
 * This table recode different size of the rccb command data block
 * For those rccb command not supported, it is zero
 */
static uint8_t uwb_rccb_size_tbl [] = {
	0, 					/* CHANNEL_CHANGE */
	sizeof (uwb_rccb_dev_addr_mgmt_t),	/* DEV_ADDR_MGMT */
	sizeof (uwb_rccb_cmd_t),			/* GET_IE */
	sizeof (uwb_rccb_cmd_t),			/* RESET */
	sizeof (uwb_rccb_scan_t),		/* SCAN */
	0,					/* SET_BEACON_FILTER */
	0,					/* SET_DRP_IE */
	0,					/* SET_IE */
	0,					/* SET_NOTIFICATION_FILTER */
	0,					/* SET_TX_POWER */
	0,					/* SLEEP */
	sizeof (uwb_rccb_start_beacon_t),	/* START_BEACON */
	sizeof (uwb_rccb_cmd_t),			/* STOP_BEACON */
	0,					/* BP_MERGE */
	0					/* SEND_COMMAND_FRAME */
};
_NOTE(SCHEME_PROTECTS_DATA("unique per call", uwba_dev::send_cmd))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", uwb_rceb_get_ie))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", uwb_rceb_result_code))

/*
 * Called by radio controller driver's attach() to register the device to uwba.
 * Including alloc and init the uwb_dev_handle
 */
void
uwb_dev_attach(dev_info_t *dip, uwb_dev_handle_t *uwb_dev_handle,
	uint_t rcd_intr_pri, int (*send_cmd)(uwb_dev_handle_t uwb_dev_hdl,
	mblk_t *data, uint16_t data_len))
{
	uwba_dev_t *uwba_dev;

	uwba_alloc_uwb_dev(dip, &uwba_dev, rcd_intr_pri);

	uwba_init_ctxt_id(uwba_dev);
	uwba_dev->send_cmd = send_cmd;

	uwba_dev_add_to_list(uwba_dev);

	*uwb_dev_handle = (uwb_dev_handle_t)uwba_dev;

}

/*
 * Called by radio controller driver's dettach() to unregister the device from
 * uwba. Including dealloc and fnit the uwb_dev_handle
 */
void
uwb_dev_detach(uwb_dev_handle_t uwb_dev_hdl)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	uwba_dev_rm_from_list(uwba_dev);
	uwba_fini_ctxt_id(uwba_dev);
	uwba_free_uwb_dev(uwba_dev);
}

/*
 * Called by the radio controler to the dip from a uwb_dev_handle
 */
dev_info_t *
uwb_get_dip(uwb_dev_handle_t uwb_dev_hdl)
{
	if (uwb_dev_hdl) {

		return (((uwba_dev_t *)uwb_dev_hdl)->dip);
	}

	return (NULL);
}

/*
 * Called by host controller or radio controller, this function set the
 * ddi_no_autodetach to for the hwarc dip. Radio controller interface
 * should alway be detached after the host controller detachment.
 * So it should be called while the  hwahc is attaching
 *   dip- a hwahc dip or a hwarc dip
 */
int
uwb_dev_online(dev_info_t *dip)
{
	dev_info_t	*pdip, *child_dip;
	int rval = UWB_FAILURE;
	uwba_dev_t *uwba_dev = NULL;
	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	if (uwb_dev_hdl != NULL) {
		(void) ddi_prop_update_int(DDI_DEV_T_NONE, uwba_dev->dip,
		    DDI_NO_AUTODETACH, 1);

		return (UWB_SUCCESS);
	}

	pdip = ddi_get_parent(dip);
	child_dip = ddi_get_child(pdip);
	while (child_dip != NULL) {
		if (child_dip != dip)  {
			/* Force the dip online */
			if (ndi_devi_online(child_dip, NDI_ONLINE_ATTACH) !=
			    NDI_SUCCESS) {
				uwba_log(uwba_dev, UWBA_LOG_LOG,
				    "fail to online dip = %p, node_name = %s",
				    dip, ddi_node_name(child_dip));
			}

			/*
			 * Update the dip properties if it is a radio
			 * controller node
			 */
			if (strcmp(ddi_node_name(child_dip), "hwa-radio") ==
			    0) {
				(void) ddi_prop_update_int(DDI_DEV_T_NONE,
				    child_dip, DDI_NO_AUTODETACH, 1);
				rval = UWB_SUCCESS;
				break;
			}
		}

		child_dip = ddi_get_next_sibling(child_dip);
	}

	return (rval);

}

/*
 * Called by hwahc when detaching.
 * The hwarc should be detached after the hwahc. So it should only be
 * called when hwahc is detaching.
 */
int
uwb_dev_offline(dev_info_t *dip)
{
	uwba_dev_t *uwba_dev = NULL;
	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_dev_offline::no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}
	uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	uwba_log(uwba_dev, UWBA_LOG_LOG,
	    " uwb_dev_offline dip = 0x%p", dip);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, uwba_dev->dip,
	    DDI_NO_AUTODETACH, 0);

	return (UWB_SUCCESS);

}
/*
 * Called by hwarc when disconnect or suspend.
 * Stop beacon. In addition, uwb will save the current channel
 * and dev state.
 */
int
uwb_dev_disconnect(dev_info_t *dip)
{
	uwba_dev_t *uwba_dev = NULL;
	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_dev_offline::no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}
	uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	mutex_enter(&uwba_dev->dev_mutex);
	uint8_t channel = uwba_dev->channel;
	uint8_t state = uwba_dev->dev_state;
	mutex_exit(&uwba_dev->dev_mutex);


	uwba_log(uwba_dev, UWBA_LOG_LOG,
	    " uwb_dev_disconnect dip = 0x%p, channel=%d, state=%d",
	    dip, channel, state);

	if (state == UWB_STATE_BEACON) {
		(void) uwb_stop_beacon(dip);
	}

	mutex_enter(&uwba_dev->dev_mutex);
	uwba_dev->channel = channel;
	uwba_dev->dev_state = state;
	mutex_exit(&uwba_dev->dev_mutex);


	return (UWB_SUCCESS);

}

/*
 * Called by hwarc when reconnect or resume.
 * Start beacon and set the dev address whchi is saved
 * in disconnect or suspend.
 */
int
uwb_dev_reconnect(dev_info_t *dip)
{
	uwba_dev_t *uwba_dev = NULL;
	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_dev_offline::no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}
	uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	mutex_enter(&uwba_dev->dev_mutex);
	uint8_t channel = uwba_dev->channel;
	uint8_t state = uwba_dev->dev_state;
	uwba_dev->dev_state = UWB_STATE_IDLE;
	mutex_exit(&uwba_dev->dev_mutex);

	uwba_log(uwba_dev, UWBA_LOG_LOG,
	    " uwb_dev_reconnect dip = 0x%p, channel= %d, state = %d",
	    dip, channel, state);


	(void) uwb_set_dev_addr(dip, uwba_dev->dev_addr);

	if (state == UWB_STATE_BEACON) {
		(void) uwb_start_beacon(dip, uwba_dev->channel);
	}


	return (UWB_SUCCESS);

}



/*
 * This is a common interface for other models to send a
 * rccb command to the radio controller
 */
int
uwb_process_rccb_cmd(dev_info_t *dip, uwb_rccb_cmd_t *rccb_cmd,
		uwb_cmd_result_t *cmd_result)
{
	int rval = UWB_SUCCESS;
	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_process_rccb_cmd::no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}

	/* check if it is a valid rccb command */
	if (uwb_check_rccb_cmd(uwb_dev_hdl, rccb_cmd) != UWB_SUCCESS) {

		return (UWB_FAILURE);
	}

	rval = uwb_process_rccb_cmd_private(uwb_dev_hdl, rccb_cmd, cmd_result);

	return (rval);
}

/*
 * Find a free chanel by scaning the supported channels
 */
uint8_t
uwb_allocate_channel(dev_info_t *dip)
{
	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	uint8_t channel = 0;
	if (!uwb_dev_hdl) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_send_rccb_cmd: uwba dev not found");
		goto done;
	}
	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_allocate_channel: enter");
	channel = uwba_allocate_channel(uwb_dev_hdl);
done:
	return (channel);
}
/* scan a channel and wait for a while to get beacon info */
int
uwb_scan_channel(uwb_dev_handle_t uwb_dev_hdl, uint8_t channel)
{

	uwb_rccb_scan_t rccb_cmd;

	bzero(&rccb_cmd, sizeof (rccb_cmd));
	rccb_cmd.rccb.bCommandType = UWB_CE_TYPE_GENERAL;

	rccb_cmd.rccb.wCommand	= UWB_CE_SCAN;
	rccb_cmd.bScanState		= UWB_RC_SCAN_ONLY;
	rccb_cmd.wStartTime		= 0;
	rccb_cmd.bChannelNumber	= channel;

	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_scan_channel: channel = %d", channel);
	/* Scan a specific channel */

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, NULL) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_scan_channel: process cmd failed");

		return (UWB_FAILURE);
	}

	/* wait for beacon info */
	delay(drv_usectohz(300000));

	/* stop scan in the channel */
	rccb_cmd.bScanState = UWB_RC_SCAN_DISABLED;

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, (uwb_cmd_result_t *)NULL) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_scan_channel: process cmd failed, channel = %d",
		    channel);

		return (UWB_FAILURE);
	}

	return (UWB_SUCCESS);
}

/* Stop beacon common interface */
int
uwb_stop_beacon(dev_info_t *dip)
{
	uwb_rccb_cmd_t rccb_cmd;
	uwb_rceb_result_code_t ret;

	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_stop_beacon::no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}

	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_stop_beacon: enter");

	bzero(&rccb_cmd, sizeof (rccb_cmd));
	rccb_cmd.rccb.bCommandType = UWB_CE_TYPE_GENERAL;

	rccb_cmd.rccb.wCommand = UWB_CE_STOP_BEACON;

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, (uwb_cmd_result_t *)&ret) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_stop_beacon: process cmd failed");

		return (UWB_FAILURE);
	}

	if (ret.bResultCode != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_stop_beacon: bResultCode =%d", ret.bResultCode);

		return (UWB_FAILURE);
	}

	return (UWB_SUCCESS);
}

/*
 * Start beacon common interface
 * start beaconing on specified channel
 */
int
uwb_start_beacon(dev_info_t *dip, uint8_t channel)
{
	uwb_rccb_start_beacon_t rccb_cmd;
	uwb_rceb_result_code_t ret;
	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);

	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_start_beacon::no dev for dip:0x%p, channel = %d",
		    dip, channel);

		return (UWB_FAILURE);
	}

	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_start_beacon: channel = %d", channel);
	bzero(&rccb_cmd, sizeof (rccb_cmd));
	rccb_cmd.rccb.bCommandType = UWB_CE_TYPE_GENERAL;


	rccb_cmd.rccb.wCommand = UWB_CE_START_BEACON;
	/* todo: this needs to be fixed later */
	rccb_cmd.wBPSTOffset = 0;
	rccb_cmd.bChannelNumber = channel;

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, (uwb_cmd_result_t *)&ret) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_start_beacon: process cmd failed"
		    "channel = %d", channel);

		return (UWB_FAILURE);
	}


	if (ret.bResultCode != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_start_beacon: bResultCode =%d", ret.bResultCode);

		return (UWB_FAILURE);
	}

	return (UWB_SUCCESS);
}

/* Get the mac address of the radion controller */
int
uwb_get_mac_addr(dev_info_t *dip, uint8_t *mac_addr)
{
	uwb_rccb_dev_addr_mgmt_t rccb_cmd;
	uwb_rceb_dev_addr_mgmt_t ret;

	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_get_mac_addr::no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}

	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_get_mac_addr: enter");

	bzero(&rccb_cmd, sizeof (rccb_cmd));
	rccb_cmd.rccb.bCommandType = UWB_CE_TYPE_GENERAL;

	rccb_cmd.rccb.wCommand = UWB_CE_DEV_ADDR_MGMT;
	rccb_cmd.bmOperationType = 2;	/* get MAC. XXX: should use Macro */

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, (uwb_cmd_result_t *)&ret) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_get_mac_addr: process cmd failed");

		return (UWB_FAILURE);
	}


	if (ret.bResultCode != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_get_mac_addr: bResultCode =%d", ret.bResultCode);

		return (UWB_FAILURE);
	}
	(void) memcpy(mac_addr, ret.baAddr, 6);

	return (UWB_SUCCESS);
}

/* Get the device address of the radion controller */
int
uwb_get_dev_addr(dev_info_t *dip, uint16_t *dev_addr)
{
	uwb_rccb_dev_addr_mgmt_t rccb_cmd;
	uwb_rceb_dev_addr_mgmt_t ret;

	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_get_dev_addr::no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}

	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_get_dev_addr: enter");

	bzero(&rccb_cmd, sizeof (rccb_cmd));
	rccb_cmd.rccb.bCommandType = UWB_CE_TYPE_GENERAL;

	rccb_cmd.rccb.wCommand = UWB_CE_DEV_ADDR_MGMT;
	rccb_cmd.bmOperationType = 0;	/* get 16-bit dev addr */

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, (uwb_cmd_result_t *)&ret) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_get_dev_addr: process cmd failed");

		return (UWB_FAILURE);
	}
	if (ret.bResultCode != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_get_dev_addr: bResultCode =%d", ret.bResultCode);

		return (UWB_FAILURE);
	}
	*dev_addr = ret.baAddr[0] | (ret.baAddr[1] << 8);

	return (UWB_SUCCESS);
}

/* Set the device address of the radion controller */
int
uwb_set_dev_addr(dev_info_t *dip, uint16_t dev_addr)
{
	uwb_rccb_dev_addr_mgmt_t rccb_cmd;
	uwb_rceb_dev_addr_mgmt_t ret;

	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_set_dev_addr::no dev for dip:0x%p, dev_addr=%d",
		    dip, dev_addr);

		return (UWB_FAILURE);
	}

	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_set_dev_addr: dev_addr = %d", dev_addr);

	bzero(&rccb_cmd, sizeof (rccb_cmd));
	rccb_cmd.rccb.bCommandType = UWB_CE_TYPE_GENERAL;

	rccb_cmd.rccb.wCommand = UWB_CE_DEV_ADDR_MGMT;
	rccb_cmd.bmOperationType = 1; /* set 16-bit dev addr */
	rccb_cmd.baAddr[0] = dev_addr & 0xff;
	rccb_cmd.baAddr[1] = (dev_addr >> 8) & 0xff;

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, (uwb_cmd_result_t *)&ret) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_set_dev_addr: process cmd failed"
		    "dev_addr=%d", dev_addr);

		return (UWB_FAILURE);
	}


	if (ret.bResultCode != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_set_dev_addr: bResultCode =%d", ret.bResultCode);

		return (UWB_FAILURE);
	}

	return (UWB_SUCCESS);
}

/*
 * Reset the radio controller.
 * This is called when the radio controller is attached.
 * Notice:Radio controller should not be reset when it
 * is beaconing or scaning.
 */
int
uwb_reset_dev(dev_info_t *dip)
{
	uwb_rccb_cmd_t rccb_cmd;
	uwb_rceb_result_code_t ret;

	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_reset_dev:no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}

	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_reset_dev: enter");
	bzero(&rccb_cmd, sizeof (rccb_cmd));
	rccb_cmd.rccb.bCommandType	= UWB_CE_TYPE_GENERAL;
	rccb_cmd.rccb.wCommand	= UWB_CE_RESET;

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, (uwb_cmd_result_t *)&ret) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_reset_dev: process cmd failed");

		return (UWB_FAILURE);
	}
	if (ret.bResultCode != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_reset_dev: bResultCode =%d", ret.bResultCode);

		return (UWB_FAILURE);
	}

	return (UWB_SUCCESS);
}

/*
 * Called while attaching.
 * The physical capabilities is initialized.
 * Only the supported channels is used in current version
 */
int
uwb_init_phy(dev_info_t *dip)
{
	uwb_rccb_cmd_t rccb_cmd;

	uwb_dev_handle_t uwb_dev_hdl = uwba_dev_search(dip);
	if (uwb_dev_hdl == NULL) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwb_init_phy::no dev for dip:0x%p", dip);

		return (UWB_FAILURE);
	}

	uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_DEBUG,
	    "uwb_init_phy: enter");
	bzero(&rccb_cmd, sizeof (rccb_cmd));
	rccb_cmd.rccb.bCommandType = UWB_CE_TYPE_GENERAL;
	rccb_cmd.rccb.wCommand		= UWB_CE_GET_IE;

	if (uwb_process_rccb_cmd_private(uwb_dev_hdl,
	    (uwb_rccb_cmd_t *)&rccb_cmd, (uwb_cmd_result_t *)NULL) != 0) {
		uwba_log((uwba_dev_t *)uwb_dev_hdl, UWBA_LOG_LOG,
		    "uwb_init_phy: process cmd failed");

		return (UWB_FAILURE);
	}
	/* todo: rceb result is handled in event notification */

	return (UWB_SUCCESS);
}


/* Get a notif from the list head. That notif is dis-linked from the list. */
static uwb_notif_wrapper_t *
uwb_get_notif_head(uwb_dev_handle_t uwb_dev_hdl)
{
	uwb_notif_wrapper_t *nw = NULL;
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	mutex_enter(&uwba_dev->dev_mutex);

	if (!list_is_empty(&uwba_dev->notif_list)) {
		nw = list_head(&uwba_dev->notif_list);
		if (nw != NULL) {

			/*
			 * unlink a notification wrapper's structure from the
			 * list
			 */
			list_remove(&(uwba_dev->notif_list), nw);
		}
	}
	mutex_exit(&uwba_dev->dev_mutex);

	return (nw);
}

/*
 * UWB ioctls
 * UWB_COMMAND --- Send a rccb command to the radio controller
 * UWB_GET_NOTIFICATION -- Get the uwb notifications. Not used
 */
int
uwb_do_ioctl(uwb_dev_handle_t uwb_dev_hdl,
	int cmd, intptr_t arg, int mode)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	int	rv = 0;

	switch (cmd) {
	case UWB_COMMAND:	/* Issue commands to UWB Radio Controller */
	{
		uwb_rccb_cmd_t rccb_cmd;
		if (ddi_copyin((caddr_t)arg, &rccb_cmd,
		    sizeof (rccb_cmd), mode)) {
			uwba_log(uwba_dev, UWBA_LOG_LOG,
			    "uwb_do_ioctl: ddi_copyin fail");

			rv = EFAULT;
			break;
		}
		if (uwb_check_rccb_cmd(uwb_dev_hdl, &rccb_cmd) != UWB_SUCCESS) {

			rv = EINVAL;
			break;
		}
		if (uwb_do_ioctl_rccb_cmd(uwb_dev_hdl, rccb_cmd.rccb.wCommand,
		    arg, mode)
		    != UWB_SUCCESS) {

			uwba_log(uwba_dev, UWBA_LOG_LOG,
			    "uwb_do_ioctl: uwb_do_ioctl_rccb_cmd failed");
			rv = EIO;
		}

		break;
	}
	case UWB_GET_NOTIFICATION:
	{
		uwb_notif_wrapper_t *nw;

		nw = uwb_get_notification(uwb_dev_hdl, arg, mode);

		if (nw && nw->notif) {
			/* Copy the notification to userland application */
			if (ddi_copyout(nw->notif,
			    (caddr_t)&(((uwb_notif_get_t *)arg)->notif),
			    nw->length, mode)) { /* todo: 32bit/64bit */

				rv = EFAULT;
			}
			/* release the notif and the wrapper. */
			uwb_free_notification(nw);
		} else {
			rv = EIO;
		}

		break;
	}
	default:
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_ioctl: not a valid cmd value, cmd=%x", cmd);
		rv = EINVAL;
	}

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwb_do_ioctl: exit, rv=%d", rv);

	return (rv);
}


/*
 * Parse all the standard events, including command results and notifications.
 * If a unknown event, return UWB_NOT_SUPPORTED. The specific client radio
 * controllers might has the knowledge to parse the vendor specific
 * events/notifications.
 */
int
uwb_parse_evt_notif(uint8_t *data, int data_len,
	uwb_dev_handle_t uwb_dev_hdl)
{
	uint16_t	evt_code, evt_size;
	void *evt_struct;
	uwb_rceb_head_t	*rceb;
	uwba_dev_t	*uwba_dev;
	uint8_t *spec_data; /* the raw event data excluding rceb. */
	int spec_data_len, offset;
	int rval = UWB_SUCCESS;

	uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	/* Get evt/notif code */
	if ((evt_code = uwba_get_evt_code(data, data_len)) ==
	    UWB_INVALID_EVT_CODE) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_parse_evt_notif: invalid evt_code");

		return (UWB_INVALID_EVT_CODE);
	}

	if ((evt_size = uwba_get_evt_size(data, data_len, evt_code)) ==
	    UWB_INVALID_EVT_SIZE) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_parse_evt_notif: invalid evt_size. evt_code=%d",
		    evt_code);

		return (UWB_INVALID_EVT_SIZE);
	}
	evt_struct = kmem_alloc(evt_size, KM_NOSLEEP);
	if (evt_struct == NULL) {

		return (UWB_NO_RESOURCES);
	}

	/* parse rceb and get the data offset just after the rceb struct. */
	if ((offset = uwba_parse_rceb(data, data_len, evt_struct, evt_size))
	    == UWB_PARSE_ERROR) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_parse_evt_notif: uwba_parse_rceb failed");
		kmem_free(evt_struct, evt_size);

		return (UWB_PARSE_ERROR);
	}
	rceb = (uwb_rceb_head_t *)evt_struct;
	if (rceb->bEventContext > 0 &&
	    rceb->bEventContext != uwba_dev->ctxt_id) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_parse_evt_notif: cmd result's ctxt_id is "
		    "not matching cmd's ctxt_id,"
		    " result ctxt_id=%d, cmd ctxt_id=%d",
		    rceb->bEventContext, uwba_dev->ctxt_id);
	}

	/* the data after rceb head are evt specific data */
	spec_data = data + offset;
	spec_data_len = data_len - offset;

	switch (evt_code) {
	case UWB_CE_CHANNEL_CHANGE:
	case UWB_CE_RESET:
	case UWB_CE_SCAN:
	case UWB_CE_SET_BEACON_FILTER:
	case UWB_CE_SET_NOTIFICATION_FILTER:
	case UWB_CE_SET_TX_POWER:
	case UWB_CE_SLEEP:
	case UWB_CE_START_BEACON:
	case UWB_CE_STOP_BEACON:
	case UWB_CE_BP_MERGE:
	case UWB_CE_SEND_COMMAND_FRAME:
	case UWB_CE_SET_ASIE_NOTIFICATION:
		/* All the above cmd results have only result code. */
		((uwb_rceb_result_code_t *)evt_struct)->bResultCode =
		    *spec_data;
		uwba_log(uwba_dev, UWBA_LOG_DEBUG,
		    "uwb_parse_evt_notif: msg = %s, bResultCode = %d ",
		    uwba_event_msg(evt_code), *spec_data);

		break;
	case UWB_CE_DEV_ADDR_MGMT:
		rval = uwba_parse_dev_addr_mgmt(spec_data, spec_data_len,
		    (uwb_rceb_dev_addr_mgmt_t *)evt_struct);

		break;
	case UWB_CE_GET_IE:
		rval = uwba_parse_get_ie(uwb_dev_hdl, spec_data, spec_data_len,
		    (uwb_rceb_get_ie_t *)evt_struct);

		break;
	case UWB_NOTIF_BEACON_RECEIVED:
		rval = uwba_parse_beacon_rcv(uwb_dev_hdl, spec_data,
		    spec_data_len, (uwb_rceb_beacon_t *)evt_struct);
		break;
	case UWB_NOTIF_BPOIE_CHANGE:
		rval = uwba_parse_bpoie_chg(uwb_dev_hdl, spec_data,
		    spec_data_len, (uwb_rceb_bpoie_change_t *)evt_struct);
		break;

	case UWB_NOTIF_BEACON_SIZE_CHANGE:
	case UWB_CE_SET_DRP_IE:
	case UWB_CE_SET_IE:
	case UWB_NOTIF_IE_RECEIVED:
	case UWB_NOTIF_BP_SLOT_CHANGE:
	case UWB_NOTIF_BP_SWITCH_IE_RECEIVED:
	case UWB_NOTIF_DEV_ADDR_CONFLICT:
	case UWB_NOTIF_DRP_AVAILABILITY_CHANGE:
	case UWB_NOTIF_DRP:
	case UWB_NOTIF_BP_SWITCH_STATUS:
	case UWB_NOTIF_CMD_FRAME_RCV:
	case UWB_NOTIF_CHANNEL_CHANGE_IE_RCV:
		uwba_log(uwba_dev, UWBA_LOG_DEBUG,
		    "uwb_parse_evt_notif: %s not supported",
		    uwba_event_msg(evt_code));
		break;

	default: /* unkonwn events or notifications */
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_parse_evt_notif: unkonwn events or notifications,"
		    " evt_code=%d", evt_code);
		break;
	}

	if (rval != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_parse_evt_notif: fail, rval = %d", rval);

		kmem_free(evt_struct, evt_size);

		return (rval);
	}

	/*
	 * By now, parse complete. Go on notify the waiting cmd thread or add
	 * notification to list
	 */
	if (evt_code > UWB_NOTIF_RESERVED) {
		/* If this event is a cmd result */
		uwba_put_cmd_result(uwba_dev, evt_struct, evt_size);
	} else {

		/* If this event is a notification */
		rval = uwba_add_notif_to_list(uwba_dev, evt_struct, evt_size);
	}

	return (rval);
}


/*
 * Send command to device. This function is shared by those commands whose cmd
 * data have rccb only.
 */
static int
uwb_do_cmd_rccb(uwb_dev_handle_t uwb_dev_hdl, uwb_rccb_cmd_t *rccb_cmd)
{
	/* reset cmd has no extra bytes, just rccb */
	mblk_t *data;
	uint16_t	data_len;
	uwba_dev_t *uwba_dev;
	int rval = UWB_SUCCESS;

	uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	/* size of rccb. Reset cmd has no data other than rccb head */
	data_len = UWB_RAW_RCCB_HEAD_SIZE;

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwb_do_cmd_rccb: wLength=%d", data_len);

	/* Data block */
	if ((data = allocb(data_len, BPRI_HI)) == NULL) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_cmd_rccb: allocb failed");

		return (UWB_FAILURE);
	}

	uwba_fill_rccb_head(uwba_dev, rccb_cmd->rccb.wCommand, data);
	data->b_wptr += data_len;

	/* record the current cmd rccb to the uwb dev handle. */
	uwba_copy_rccb(rccb_cmd, &(uwba_dev->curr_rccb));
	uwba_dev->curr_rccb.rccb.bCommandContext = data->b_rptr[3];

	/*
	 * data will be freed by radio client driver after the cmd is sent to
	 * device
	 */
	rval = uwba_dev->send_cmd(uwb_dev_hdl, data, data_len);
	if (rval != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_cmd_rccb: send cmd fail ");

		return (rval);
	}

	return (rval);
}

/* Dev addr management rccb cmd handler */
static int
uwb_do_cmd_dev_addr_mgmt(uwb_dev_handle_t uwb_dev_hdl,
		uwb_rccb_cmd_t *rccb_cmd)
{
	mblk_t *data;
	uint16_t	data_len;
	uwba_dev_t	*uwba_dev;
	int i, rval = UWB_SUCCESS;
	uwb_rccb_dev_addr_mgmt_t *rccb_dev_addr =
	    (uwb_rccb_dev_addr_mgmt_t *)rccb_cmd;

	uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	/* size of device address mgmt RCCB */
	data_len = UWB_RAW_RCCB_HEAD_SIZE + 7;

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwb_do_cmd_dev_addr_mgmt: wLength=%d, type=%x",
	    data_len, rccb_dev_addr->bmOperationType);

	/* Data block */
	if ((data = allocb(data_len, BPRI_HI)) == NULL) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_cmd_dev_addr_mgmt: allocb failed");

		return (UWB_NO_RESOURCES);
	}

	uwba_fill_rccb_head(uwba_dev, rccb_dev_addr->rccb.wCommand, data);
	data->b_rptr[4] = rccb_dev_addr->bmOperationType;
	for (i = 0; i < 6; i++) {
		data->b_rptr[5 + i] = rccb_dev_addr->baAddr[i];
	}
	data->b_wptr += data_len;

	/* record the current cmd rccb to the uwb dev handle. */
	uwba_copy_rccb((uwb_rccb_cmd_t *)rccb_dev_addr, &(uwba_dev->curr_rccb));
	uwba_dev->curr_rccb.rccb.bCommandContext = data->b_rptr[3];

	if ((rval = uwba_dev->send_cmd(uwb_dev_hdl, data, data_len))
	    != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_cmd_dev_addr_mgmt: fail ");

		return (rval);
	}

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwb_do_cmd_dev_addr_mgmt: success.");

	return (rval);
}

/* Scan rccb cmd handler */
static int
uwb_do_cmd_scan(uwb_dev_handle_t uwb_dev_hdl, uwb_rccb_cmd_t *rccb_cmd)
{
	mblk_t *data;
	uint16_t	data_len;
	uwba_dev_t	*uwba_dev;
	int rval = UWB_SUCCESS;
	uwb_rccb_scan_t *rccb_scan = (uwb_rccb_scan_t *)rccb_cmd;

	uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	data_len = UWB_RAW_RCCB_HEAD_SIZE + 4; /* size of scan RCCB */

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwb_do_cmd_scan: wLength=%d", data_len);

	/* Data block */
	if ((data = allocb(data_len, BPRI_HI)) == NULL) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_cmd_scan: allocb failed");

		return (UWB_NO_RESOURCES);
	}

	uwba_fill_rccb_head(uwba_dev, rccb_scan->rccb.wCommand, data);
	data->b_rptr[4] = rccb_scan->bChannelNumber;
	data->b_rptr[5] = rccb_scan->bScanState;
	UINT16_TO_LE(rccb_scan->wStartTime, 6, data->b_rptr);
	data->b_wptr += data_len;

	/* record the current cmd rccb to the uwb dev handle. */
	uwba_copy_rccb((uwb_rccb_cmd_t *)rccb_scan, &(uwba_dev->curr_rccb));
	uwba_dev->curr_rccb.rccb.bCommandContext = data->b_rptr[3];

	if ((rval = uwba_dev->send_cmd(uwb_dev_hdl, data, data_len))
	    != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_send_rccb_cmd: fail ");

		return (rval);
	}

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwb_do_cmd_scan: success.");

	return (rval);
}

/* Start beacon rccb handler */
static int
uwb_do_cmd_start_beacon(uwb_dev_handle_t uwb_dev_hdl,
		uwb_rccb_cmd_t *rccb_cmd)
{
	mblk_t *data;
	uint16_t	data_len;
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	int rval = UWB_SUCCESS;
	uwba_client_dev_t *client = NULL;
	uwb_rccb_start_beacon_t *rccb_startbc =
	    (uwb_rccb_start_beacon_t *)rccb_cmd;

	if (client = uwba_find_cdev_by_channel(uwba_dev,
	    rccb_startbc->bChannelNumber)) {
		rccb_startbc->wBPSTOffset = client->wBPSTOffset;
	}

	data_len = UWB_RAW_RCCB_HEAD_SIZE + 3; /* size of start beacon RCCB */

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwb_do_cmd_start_beacon: channel= %d , BPSTOffset = %d",
	    rccb_startbc->bChannelNumber, rccb_startbc->wBPSTOffset);
	/* Data block */
	if ((data = allocb(data_len, BPRI_HI)) == NULL) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_cmd_start_beacon: allocb failed");

		return (UWB_FAILURE);
	}

	uwba_fill_rccb_head(uwba_dev, rccb_startbc->rccb.wCommand, data);
	UINT16_TO_LE(rccb_startbc->wBPSTOffset, 4, data->b_rptr);
	data->b_rptr[6] = rccb_startbc->bChannelNumber;
	data->b_wptr += data_len;

	/* record the current cmd rccb to the uwb dev handle. */
	uwba_copy_rccb((uwb_rccb_cmd_t *)rccb_startbc, &(uwba_dev->curr_rccb));
	uwba_dev->curr_rccb.rccb.bCommandContext = data->b_rptr[3];
	if ((rval = uwba_dev->send_cmd(uwb_dev_hdl, data, data_len))
	    != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_cmd_start_beacon: send_cmd failed, channel = %d,"
		    "wBPSTOffset = %d", rccb_startbc->bChannelNumber,
		    rccb_startbc->wBPSTOffset);

		return (rval);
	}

	return (rval);
}

/* Send rccb cmd and get the rceb result */
static int
uwb_process_rccb_cmd_private(uwb_dev_handle_t uwb_dev_hdl,
		uwb_rccb_cmd_t *rccb_cmd, uwb_cmd_result_t *cmd_result)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	int rval = UWB_SUCCESS;

	if (uwb_check_dev_state(uwba_dev, rccb_cmd) != UWB_SUCCESS) {

		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_process_rccb_cmd_private: illegal dev_state:%d",
		    uwba_dev->dev_state);

		return (UWB_FAILURE);
	}



	if (uwb_rccb_cmd_enter(uwba_dev) != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_process_rccb_cmd_private: fail to enter"
		    "wCommand = %d, %s ", rccb_cmd->rccb.wCommand,
		    uwba_event_msg(rccb_cmd->rccb.wCommand));

		return (UWB_FAILURE);
	}

	if ((rval = uwb_send_rccb_cmd(uwb_dev_hdl, rccb_cmd)) != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_process_rccb_cmd_private: fail to send"
		    "wCommand = %d, %s ", rccb_cmd->rccb.wCommand,
		    uwba_event_msg(rccb_cmd->rccb.wCommand));
		goto cleanup;
	}

	mutex_enter(&uwba_dev->dev_mutex);
	/* Copy the command result to application */
	if (cmd_result) {
		bcopy(uwba_dev->cmd_result_wrap.cmd_result, cmd_result,
		    uwba_dev->cmd_result_wrap.length);
	}
	/* release the command result (event) block. */
	uwb_free_cmd_result(uwb_dev_hdl);

	uwb_set_dev_state(uwba_dev, rccb_cmd);

	mutex_exit(&uwba_dev->dev_mutex);

cleanup:
	uwb_rccb_cmd_leave(uwba_dev);

	return (rval);
}

/* Call rccb handler to send a rccb cmd */
static int
uwb_send_rccb_cmd(uwb_dev_handle_t uwb_dev_hdl, uwb_rccb_cmd_t *rccb_cmd)
{
	int rccb_index = rccb_cmd->rccb.wCommand - UWB_CE_CHANNEL_CHANGE;
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	ASSERT(rccb_cmd->rccb.bCommandType == UWB_CE_TYPE_GENERAL);

	mutex_enter(&uwba_dev->dev_mutex);
	if (uwb_rccb_handler_tbl[rccb_index](uwb_dev_hdl, rccb_cmd)
	    != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_send_rccb_cmd: uwb_send_rccb_cmd failed");
		goto failure;

	}
	if (uwb_wait_cmd_result(uwb_dev_hdl) != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_send_rccb_cmd: fail to get cmd result ");
		goto failure;
	}

	mutex_exit(&uwba_dev->dev_mutex);

	return (UWB_SUCCESS);
failure:
	mutex_exit(&uwba_dev->dev_mutex);

	return (UWB_FAILURE);

}
/* Check a rccb cmd */
static int
uwb_check_rccb_cmd(uwb_dev_handle_t uwb_dev_hdl, uwb_rccb_cmd_t *rccb_cmd)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	int rccb_index = rccb_cmd->rccb.wCommand - UWB_CE_CHANNEL_CHANGE;

	if (rccb_cmd->rccb.bCommandType != UWB_CE_TYPE_GENERAL) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_check_rccb_cmd: invalid bCommandType = %d",
		    rccb_cmd->rccb.bCommandType);

		return (UWB_FAILURE);
	}
	if ((rccb_cmd->rccb.wCommand < UWB_CE_CHANNEL_CHANGE) ||
	    (rccb_cmd->rccb.wCommand > UWB_CE_SET_ASIE_NOTIFICATION)) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_check_rccb_cmd: invalid wCommand = %d",
		    rccb_cmd->rccb.wCommand);

		return (UWB_FAILURE);
	}
	if (uwb_rccb_handler_tbl[rccb_index] == UWB_RCCB_NULL_HANDLER) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_send_rccb_cmd: unsupportted wCommand = %d",
		    rccb_cmd->rccb.wCommand);

		return (UWB_FAILURE);
	}

	return (UWB_SUCCESS);
}

/* Check the current dev state */
static int
uwb_check_dev_state(uwba_dev_t *uwba_dev, uwb_rccb_cmd_t *rccb_cmd) {
	uint8_t state = uwba_dev->dev_state;

	switch (rccb_cmd->rccb.wCommand) {
		case	UWB_CE_SCAN:
			if (((uwb_rccb_scan_t *)rccb_cmd)->bScanState
			    == UWB_RC_SCAN_DISABLED) {
				if (state == UWB_STATE_SCAN) {

					return (UWB_SUCCESS);
				}
			} else {

				if (state == UWB_STATE_IDLE) {

					return (UWB_SUCCESS);
				}
			}
			break;

		case	UWB_CE_START_BEACON:
		case	UWB_CE_RESET:
			if (state == UWB_STATE_IDLE) {

				return (UWB_SUCCESS);
			}
			break;

		case	UWB_CE_STOP_BEACON:
			if (state == UWB_STATE_BEACON) {

				return (UWB_SUCCESS);
			}
			break;

		default:
			return (UWB_SUCCESS);
	}

	return (UWB_FAILURE);
}
/* Set the uwb dev state */
static void
uwb_set_dev_state(uwba_dev_t *uwba_dev, uwb_rccb_cmd_t *rccb_cmd) {
	switch (rccb_cmd->rccb.wCommand) {
		case	UWB_CE_SCAN:
			{
				uwb_rccb_scan_t *cmd =
					(uwb_rccb_scan_t *)rccb_cmd;
				if (cmd->bScanState == UWB_RC_SCAN_DISABLED) {

					uwba_dev->dev_state = UWB_STATE_IDLE;
				} else {

					uwba_dev->dev_state = UWB_STATE_SCAN;
					uwba_dev->channel = cmd->bChannelNumber;
				}
			}
			break;

		case	UWB_CE_START_BEACON:
			{
				uwb_rccb_start_beacon_t *cmd =
					(uwb_rccb_start_beacon_t *)rccb_cmd;
				uwba_dev->dev_state = UWB_STATE_BEACON;
				uwba_dev->channel = cmd->bChannelNumber;
			}
			break;

		case	UWB_CE_STOP_BEACON:
		case	UWB_CE_RESET:

			uwba_dev->dev_state = UWB_STATE_IDLE;
			break;
		case UWB_CE_DEV_ADDR_MGMT:
			{
				uwb_rccb_dev_addr_mgmt_t *cmd =
					(uwb_rccb_dev_addr_mgmt_t *)rccb_cmd;
				if (cmd->bmOperationType == 1)
				{
					uwba_dev->dev_addr = cmd->baAddr[1];
					uwba_dev->dev_addr =
					    uwba_dev->dev_addr <<8;
					uwba_dev->dev_addr =
					    uwba_dev->dev_addr | cmd->baAddr[0];
				}
			}
			break;

		default:
			break;
	}

}

/* Handle rccb cmd for ioctl */
static int
uwb_do_ioctl_rccb_cmd(uwb_dev_handle_t uwb_dev_hdl, uint16_t wCommand,
		intptr_t arg, int mode)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	int rv = UWB_FAILURE;

	int rccb_size = uwb_rccb_size_tbl[wCommand - UWB_CE_CHANNEL_CHANGE];
	uwb_rccb_cmd_t *rccb_cmd = NULL;

	if (uwb_rccb_cmd_enter(uwba_dev) != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_ioctl_rccb_cmd: enter cmd fail");

		return (UWB_FAILURE);
	}
	rccb_cmd = kmem_alloc(rccb_size, KM_NOSLEEP);
	if (ddi_copyin((caddr_t)arg, rccb_cmd, rccb_size, mode)) {

		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_ioctl_rccb_cmd: ddi_copyin fail");

		goto cleanup;
	}

	if (uwb_check_dev_state(uwba_dev, rccb_cmd) != UWB_SUCCESS) {

		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_check_dev_state: illegal dev_state:%d",
		    uwba_dev->dev_state);

		goto cleanup;
	}


	if ((uwb_send_rccb_cmd(uwb_dev_hdl, rccb_cmd)) != UWB_SUCCESS) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_ioctl_rccb_cmd: fail to send wCommand = %d ",
		    rccb_cmd->rccb.wCommand);

		goto cleanup;
	}

	/* Copy the command result to application */
	mutex_enter(&uwba_dev->dev_mutex);
	if (ddi_copyout(uwba_dev->cmd_result_wrap.cmd_result, (caddr_t)arg,
	    uwba_dev->cmd_result_wrap.length, mode)) {

		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwb_do_ioctl_rccb_cmd: ddi_copyout fail");
	} else {
		rv = UWB_SUCCESS;
	}

	/* release the command result (event) block. */
	uwb_free_cmd_result(uwb_dev_hdl);

	uwb_set_dev_state(uwba_dev, rccb_cmd);
	mutex_exit(&uwba_dev->dev_mutex);

cleanup:
	uwb_rccb_cmd_leave(uwba_dev);
	kmem_free(rccb_cmd, rccb_size);

	return (rv);
}

/*
 * alloc evt block according to cmd code; alloc context id;
 * link the evt block to uwb_dev_hdl
 */
static int
uwb_wait_cmd_result(uwb_dev_handle_t uwb_dev_hdl)
{
	int rval = UWB_SUCCESS;
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	ASSERT(mutex_owned(&uwba_dev->dev_mutex));

	while (uwba_dev->cmd_result_wrap.cmd_result == NULL) {

		if (cv_timedwait_sig(&uwba_dev->cmd_result_cv,
		    &uwba_dev->dev_mutex, UWB_CMD_TIMEOUT) <= 0) {

			/* no cmd result is received and cv is signaled */
			rval = UWB_FAILURE;

			return (rval);
		}
		uwba_log(uwba_dev, UWBA_LOG_DEBUG,
		    "uwb_wait_cmd_result: wait for cmd complete end, "
		    "cv_signal received.");
	}
	ASSERT(uwba_dev->cmd_result_wrap.cmd_result != NULL);

	return (rval);
}

static void
uwb_free_cmd_result(uwb_dev_handle_t uwb_dev_hdl)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;


	ASSERT(mutex_owned(&uwba_dev->dev_mutex));

	kmem_free(uwba_dev->cmd_result_wrap.cmd_result,
	    uwba_dev->cmd_result_wrap.length);
	uwba_dev->cmd_result_wrap.cmd_result = NULL;
	uwba_dev->cmd_result_wrap.length = 0;
	uwba_free_ctxt_id(uwba_dev, uwba_dev->ctxt_id);
}

/* Get notif for ioctl */
static uwb_notif_wrapper_t *
uwb_get_notification(uwb_dev_handle_t uwb_dev_hdl,
	intptr_t arg, int mode)
{
	uwb_notif_wrapper_t *notif;
	uwb_notif_get_t ng;


	if (ddi_copyin((caddr_t)arg, &ng, sizeof (ng), mode)) {

		return (NULL);
	}
	if (ng.notif.rceb.bEventType != UWB_CE_TYPE_GENERAL) {

		return (NULL);
	}

	notif = uwb_get_notif_head(uwb_dev_hdl);

	return (notif);
}
/* Free a notif from notificatin list */
static void
uwb_free_notification(uwb_notif_wrapper_t *nw)
{
	ASSERT(nw->notif);

	kmem_free(nw->notif, nw->length);
	kmem_free(nw, sizeof (uwb_notif_wrapper_t));
}
/* uwb rccb cmd handler lock */
static int
uwb_rccb_cmd_enter(uwba_dev_t *uwba_dev)
{
	mutex_enter(&uwba_dev->dev_mutex);
	while (uwba_dev->cmd_busy == B_TRUE) {
		if (cv_wait_sig(&uwba_dev->cmd_handler_cv,
		    &uwba_dev->dev_mutex) <= 0) {
			mutex_exit(&uwba_dev->dev_mutex);

			return (UWB_FAILURE);
		}
	}
	uwba_dev->cmd_busy = B_TRUE;
	mutex_exit(&uwba_dev->dev_mutex);

	return (UWB_SUCCESS);
}
/* uwb rccb cmd handler unlock */
static void
uwb_rccb_cmd_leave(uwba_dev_t *uwba_dev)
{
	mutex_enter(&uwba_dev->dev_mutex);
	uwba_dev->cmd_busy = B_FALSE;
	cv_signal(&uwba_dev->cmd_handler_cv);
	mutex_exit(&uwba_dev->dev_mutex);
}
