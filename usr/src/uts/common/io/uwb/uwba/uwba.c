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
 * This file is for uwba private functions
 */

#include <sys/uwb/uwba/uwba.h>

uint_t uwba_errlevel = UWBA_LOG_CONSOLE;

static kmutex_t	uwba_mutex;

/* list for uwba_dev, the radio host devices */
static list_t	uwba_dev_list;

/* modload support */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"UWBA: UWB Architecture"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void	*)&modlmisc, NULL
};

_NOTE(SCHEME_PROTECTS_DATA("unique per call", uwba_client_dev))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", uwb_notif_wrapper))
/* This table is for data decode */
uwba_evt_size_t uwba_evt_size_table[] = {
	[UWB_NOTIF_IE_RECEIVED] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= 6
	},
	[UWB_NOTIF_BEACON_RECEIVED] = {
		.struct_len = sizeof (uwb_rceb_beacon_t),
		.buf_len_offset	= UWB_BEACONINFOLEN_OFFSET
	},
	[UWB_NOTIF_BEACON_SIZE_CHANGE] = {
		.struct_len = sizeof (uwb_rceb_beacon_size_change_t),
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_BPOIE_CHANGE] = {
		.struct_len = sizeof (uwb_rceb_bpoie_change_t),
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_BP_SLOT_CHANGE] = {
		.struct_len = sizeof (uwb_rceb_bp_slot_change_t),
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_BP_SWITCH_IE_RECEIVED] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_DEV_ADDR_CONFLICT] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_DRP_AVAILABILITY_CHANGE] = {
		.struct_len = sizeof (uwb_rceb_drp_availability_t),
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_DRP] = {
		.struct_len = sizeof (uwb_rceb_drp_t),
		.buf_len_offset	= 8
	},
	[UWB_NOTIF_BP_SWITCH_STATUS] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_CMD_FRAME_RCV] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_CHANNEL_CHANGE_IE_RCV] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_RESERVED] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_RESERVED + 1] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_RESERVED + 2] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_NOTIF_RESERVED + 3] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_CHANNEL_CHANGE] = {
		.struct_len = sizeof (uwb_rceb_head_t),
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_DEV_ADDR_MGMT] = {
		.struct_len = sizeof (uwb_rceb_dev_addr_mgmt_t),
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_GET_IE] = {
		.struct_len = sizeof (uwb_rceb_get_ie_t),
		.buf_len_offset	= 4
	},
	[UWB_CE_RESET] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SCAN] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SET_BEACON_FILTER] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SET_DRP_IE] = {
		.struct_len = sizeof (uwb_rceb_set_drp_ie_t),
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SET_IE] = {
		.struct_len = sizeof (uwb_rceb_set_ie_t),
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SET_NOTIFICATION_FILTER] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SET_TX_POWER] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SLEEP] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_START_BEACON] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_STOP_BEACON] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_BP_MERGE] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SEND_COMMAND_FRAME] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
	[UWB_CE_SET_ASIE_NOTIFICATION] = {
		.struct_len = UWB_RESULT_CODE_SIZE,
		.buf_len_offset	= UWB_EVT_NO_BUF_LEN_OFFSET
	},
};
/* This table is used for debug only */
const char *uwba_evt_msg_table[] = {
	[UWB_NOTIF_IE_RECEIVED] 	= "UWB_NOTIF_IE_RECEIVED",
	[UWB_NOTIF_BEACON_RECEIVED] 	= "UWB_NOTIF_BEACON_RECEIVED",
	[UWB_NOTIF_BEACON_SIZE_CHANGE] 	= "UWB_NOTIF_BEACON_SIZE_CHANGE",
	[UWB_NOTIF_BPOIE_CHANGE] 	= "UWB_NOTIF_BPOIE_CHANGE",
	[UWB_NOTIF_BP_SLOT_CHANGE] 	= "UWB_NOTIF_BP_SLOT_CHANGE",
	[UWB_NOTIF_BP_SWITCH_IE_RECEIVED] = "UWB_NOTIF_BP_SWITCH_IE_RECEIVED",
	[UWB_NOTIF_DEV_ADDR_CONFLICT] 	= "UWB_NOTIF_DEV_ADDR_CONFLICT",
	[UWB_NOTIF_DRP_AVAILABILITY_CHANGE] =
					"UWB_NOTIF_DRP_AVAILABILITY_CHANGE",
	[UWB_NOTIF_DRP] 		= "UWB_NOTIF_DRP",
	[UWB_NOTIF_BP_SWITCH_STATUS] 	= "UWB_NOTIF_BP_SWITCH_STATUS",
	[UWB_NOTIF_CMD_FRAME_RCV] 	= "UWB_NOTIF_CMD_FRAME_RCV",
	[UWB_NOTIF_CHANNEL_CHANGE_IE_RCV] = "UWB_NOTIF_CHANNEL_CHANGE_IE_RCV",
	[UWB_NOTIF_RESERVED] 		= "UWB_NOTIF_RESERVED",
	[UWB_NOTIF_RESERVED + 1] 	= "UWB_NOTIF_RESERVED + 1",
	[UWB_NOTIF_RESERVED + 2] 	= "UWB_NOTIF_RESERVED + 2",
	[UWB_NOTIF_RESERVED + 3] 	= "UWB_NOTIF_RESERVED + 2",
	[UWB_CE_CHANNEL_CHANGE] 	= "UWB_CE_CHANNEL_CHANGE",
	[UWB_CE_DEV_ADDR_MGMT] 		= "UWB_CE_DEV_ADDR_MGMT",
	[UWB_CE_GET_IE] 		= "UWB_CE_GET_IE",
	[UWB_CE_RESET] 			= "UWB_CE_RESET",
	[UWB_CE_SCAN] 			= "UWB_CE_SCAN",
	[UWB_CE_SET_BEACON_FILTER] 	= "UWB_CE_SET_BEACON_FILTER",
	[UWB_CE_SET_DRP_IE] 		= "UWB_CE_SET_DRP_IE",
	[UWB_CE_SET_IE] 		= "UWB_CE_SET_IE",
	[UWB_CE_SET_NOTIFICATION_FILTER] = "UWB_CE_SET_NOTIFICATION_FILTER",
	[UWB_CE_SET_TX_POWER] 		= "UWB_CE_SET_TX_POWER",
	[UWB_CE_SLEEP] 			= "UWB_CE_SLEEP",
	[UWB_CE_START_BEACON] 		= "UWB_CE_START_BEACON",
	[UWB_CE_STOP_BEACON] 		= "UWB_CE_STOP_BEACON",
	[UWB_CE_BP_MERGE] 		= "UWB_CE_BP_MERGE",
	[UWB_CE_SEND_COMMAND_FRAME] 	= "UWB_CE_SEND_COMMAND_FRAME",
	[UWB_CE_SET_ASIE_NOTIFICATION] 	= "UWB_CE_SET_ASIE_NOTIFICATION",
};


static void uwba_init_lists(void);
static void uwba_fini_lists(void);
static void uwba_remove_cdev_list(uwba_dev_t *);

static void uwba_list_phy_rates(uwb_dev_handle_t);
static void uwba_list_phy_bandgroups(uwb_dev_handle_t);
static void uwba_get_phy_cap(uwb_dev_handle_t, uint8_t *, uint16_t);
static void uwba_save_phy_cap_bm(uwb_dev_handle_t, uint8_t *);
int
_init(void)
{
	int rval;
	/*
	 * uwba providing uwb device list support needs to be init'ed first
	 * and destroyed last
	 */
	uwba_init_lists();
	mutex_init(&uwba_mutex, NULL, MUTEX_DRIVER, NULL);
	if ((rval = mod_install(&modlinkage)) != 0) {
		uwba_fini_lists();
		mutex_destroy(&uwba_mutex);
	}

	return (rval);
}

int
_fini()
{
	int rval;

	if ((rval = mod_remove(&modlinkage)) == 0) {
		mutex_destroy(&uwba_mutex);
		uwba_fini_lists();
	}

	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* Create the global uwb dev list */
static void
uwba_init_lists(void)
{
	list_create(&(uwba_dev_list), sizeof (uwba_dev_t),
	    offsetof(uwba_dev_t, uwba_dev_node));
}

/* Destroy  the global uwb dev list */
static void
uwba_fini_lists(void)
{
	uwba_dev_t	*dev;

	/* Free all uwb dev node from dev_list */
	while (!list_is_empty(&uwba_dev_list)) {
		dev = list_head(&uwba_dev_list);
		if (dev != NULL) {
			list_remove(&uwba_dev_list, dev);
			kmem_free(dev, sizeof (uwba_dev_t));
		}
	}
}
/* Search the uwb handle with a hwarc/hwahc dip */
uwb_dev_handle_t
uwba_dev_search(dev_info_t *dip)
{
	mutex_enter(&uwba_mutex);
	uwba_dev_t *uwba_dev = list_head(&uwba_dev_list);

	while (uwba_dev != NULL) {
		if (ddi_get_parent(uwba_dev->dip)  == ddi_get_parent(dip)) {

			goto done;
		}
		uwba_dev = list_next(&uwba_dev_list, uwba_dev);
	}
done:
	mutex_exit(&uwba_mutex);

	return (uwb_dev_handle_t)(uwba_dev);
}

/* Add a uwb device (hwarc/whci) to the uwb dev list */
void
uwba_dev_add_to_list(uwba_dev_t *uwba_dev)
{
	mutex_enter(&uwba_mutex);
	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "add uwba_dev = %x", uwba_dev);
	list_insert_tail(&uwba_dev_list, uwba_dev);
	mutex_exit(&uwba_mutex);
}

/* Remove a uwb device (hwarc/whci) from the uwb dev list */
void
uwba_dev_rm_from_list(uwba_dev_t *uwba_dev)
{
	mutex_enter(&uwba_mutex);
	if (list_is_empty(&uwba_dev_list)) {
		mutex_exit(&uwba_mutex);

		return;
	}

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "remove uwba_dev = %x", uwba_dev);

	list_remove(&uwba_dev_list, uwba_dev);
	mutex_exit(&uwba_mutex);
}

/* Init context bitset for a radio device (hwarc/whci) */
void
uwba_init_ctxt_id(uwba_dev_t *uwba_dev)
{
	bitset_init(&uwba_dev->ctxt_bits); /* this bzero sizeof(bitset_t) */
	bitset_resize(&uwba_dev->ctxt_bits, 256); /* alloc mem */
	bitset_add(&uwba_dev->ctxt_bits, 0);
	bitset_add(&uwba_dev->ctxt_bits, 255);
}

/* Free context bitset for a radio device (hwarc/whci) */
void
uwba_fini_ctxt_id(uwba_dev_t *uwba_dev)
{
	/* bitset_fini will free the mem allocated by bitset_resize. */
	bitset_fini(&uwba_dev->ctxt_bits);
}

/* Get a free context id from bitset */
uint8_t
uwba_get_ctxt_id(uwba_dev_t *uwba_dev)
{
	uint8_t	ctxt_id;

	/* if reaches the top, turn around */
	if (uwba_dev->ctxt_id >= UWB_CTXT_ID_TOP) {
		uwba_dev->ctxt_id = UWB_CTXT_ID_BOTTOM -1;
	}
	ctxt_id = uwba_dev->ctxt_id;

	/* Search ctxt_id+1  to UWB_CTXT_ID_UNVALID */
	do {
		ctxt_id++;

		/* test bit and returen if it is not set */
		if (!bitset_in_set(&uwba_dev->ctxt_bits, ctxt_id)) {
			bitset_add(&uwba_dev->ctxt_bits, ctxt_id);
			uwba_dev->ctxt_id = ctxt_id;

			return (ctxt_id);
		}

	} while (ctxt_id < UWB_CTXT_ID_UNVALID);

	/* Search 1  to ctxt_id */
	if (uwba_dev->ctxt_id != 0) {
		ctxt_id = UWB_CTXT_ID_BOTTOM;
		do {
			ctxt_id++;

			/* test bit and returen if it is not set */
			if (!bitset_in_set(&uwba_dev->ctxt_bits, ctxt_id)) {
				bitset_add(&uwba_dev->ctxt_bits, ctxt_id);
				uwba_dev->ctxt_id = ctxt_id;

				return (ctxt_id);
			}
		} while (ctxt_id < uwba_dev->ctxt_id);
	}

	/* All ids are in use, just force to re-use one. */
	uwba_dev->ctxt_id++;

	return (uwba_dev->ctxt_id);
}

/* Reset the bit (offset at ctxt_id) to zero */
void
uwba_free_ctxt_id(uwba_dev_t *dev, uint8_t	ctxt_id)
{
	bitset_del(&dev->ctxt_bits, ctxt_id);

}

/* Fill the rccb to ctrl req's data block */
void
uwba_fill_rccb_head(uwba_dev_t *uwba_dev, uint16_t cmd, mblk_t *data)
{
	data->b_rptr[0] = UWB_CE_TYPE_GENERAL;
	UINT16_TO_LE(cmd, 1, data->b_rptr);
	data->b_rptr[3] = uwba_get_ctxt_id(uwba_dev);
	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "the new ctxt_id is %d", data->b_rptr[3]);
}

/*
 * Allocate uwb_dev_t for a radio controller device. Arg rcd_intr_pri is the
 * interrupt priority of the interrupt handler of the radio controller driver.
 * If there is no interrupt handler in the driver, then pass 0 to this arg.
 */
void
uwba_alloc_uwb_dev(dev_info_t *dip, uwba_dev_t **uwba_dev, uint_t rcd_intr_pri)
{
	char	*devinst;
	int	devinstlen;
	int	instance = ddi_get_instance(dip);

	*uwba_dev = (uwba_dev_t *)kmem_zalloc(sizeof (uwba_dev_t), KM_SLEEP);

	/*
	 * HWA radio controller will not call uwb_* functions in interrupt
	 * level, while WHCI radio controller will.
	 */
	if (rcd_intr_pri == 0) {
		mutex_init(&(*uwba_dev)->dev_mutex, NULL, MUTEX_DRIVER, NULL);
	} else {
		mutex_init(&(*uwba_dev)->dev_mutex, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(rcd_intr_pri));
	}
	mutex_enter(&(*uwba_dev)->dev_mutex);

	(*uwba_dev)->dip = dip;
	(*uwba_dev)->dev_state = UWB_STATE_IDLE;

	/* create a string for driver name and instance number */
	devinst = kmem_zalloc(UWB_MAXSTRINGLEN, KM_SLEEP);
	devinstlen = snprintf(devinst, UWB_MAXSTRINGLEN, "%s%d: ",
	    ddi_driver_name(dip), instance);
	(*uwba_dev)->devinst = kmem_zalloc(devinstlen + 1, KM_SLEEP);
	(void) strncpy((*uwba_dev)->devinst, devinst, devinstlen);
	kmem_free(devinst, UWB_MAXSTRINGLEN);

	/* list to cache the notifications from radio controller device */
	list_create(&(*uwba_dev)->notif_list, sizeof (uwb_notif_wrapper_t),
	    offsetof(uwb_notif_wrapper_t, notif_node));
	(*uwba_dev)->notif_cnt = 0;

	/* list to record the client devices according to beacons received */
	list_create(&(*uwba_dev)->client_dev_list, sizeof (uwba_client_dev_t),
	    offsetof(uwba_client_dev_t, dev_node));
	(*uwba_dev)->client_dev_cnt = 0;

	cv_init(&(*uwba_dev)->cmd_result_cv, NULL, CV_DRIVER, NULL);
	cv_init(&(*uwba_dev)->cmd_handler_cv, NULL, CV_DRIVER, NULL);

	mutex_exit(&(*uwba_dev)->dev_mutex);

}

/* Free a uwb dev for a radio device (hwarc/whci) */
void
uwba_free_uwb_dev(uwba_dev_t *uwba_dev)
{
	uwb_notif_wrapper_t *nw;

	mutex_enter(&(uwba_dev)->dev_mutex);
	cv_destroy(&uwba_dev->cmd_result_cv);
	cv_destroy(&uwba_dev->cmd_handler_cv);

	/*
	 * remove all the notifications in this device's list, and then destroy
	 * the list
	 */
	while (!list_is_empty(&uwba_dev->notif_list)) {

		nw = list_head(&uwba_dev->notif_list);
		if (nw != NULL) {
			list_remove(&(uwba_dev->notif_list), nw);
		} else {
			break;
		}

		/* Free notification struct */
		if (nw->notif) {
			kmem_free(nw->notif, nw->length);
		}
		kmem_free(nw, sizeof (uwb_notif_wrapper_t));
	}
	uwba_dev->notif_cnt = 0;
	list_destroy(&uwba_dev->notif_list);

	uwba_remove_cdev_list(uwba_dev);
	if (uwba_dev->devinst != NULL) {
		kmem_free(uwba_dev->devinst,
		    strlen(uwba_dev->devinst) + 1);
	}
	mutex_exit(&(uwba_dev)->dev_mutex);

	/* Destroy mutex and dev structure */
	mutex_destroy(&uwba_dev->dev_mutex);
	kmem_free(uwba_dev, sizeof (uwba_dev_t));
}


/* Get a event or notification code from the data stream */
uint16_t
uwba_get_evt_code(uint8_t *data, int data_len)
{
	uint16_t	evt_code;

	/*
	 * UWB_RAW_RESULT_CODE_SIZE is the minimum size for any events or
	 * notifications.
	 */
	if (data_len < UWB_RAW_RESULT_CODE_SIZE) {

		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwba_get_evt_code: invalid data_len=%d",
		    data_len);
		return (UWB_INVALID_EVT_CODE);
	}

	LE_TO_UINT16(data, UWB_RAW_WEVENT_OFFSET, evt_code);

	/* if out of range */
	if (evt_code > UWB_CE_SET_ASIE_NOTIFICATION) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwba_get_evt_code: invalid evt_code=%d",
		    evt_code);
		return (UWB_INVALID_EVT_CODE);
	}

	/* if fall into the reserved range */
	if (evt_code >= UWB_NOTIF_RESERVED &&
	    evt_code < UWB_CE_CHANNEL_CHANGE) {
		uwba_log(NULL, UWBA_LOG_LOG,
		    "uwba_get_evt_code: reserved evt_code=%d", evt_code);

		return (UWB_INVALID_EVT_CODE);
	}

	return (evt_code);
}

/* Get the size of notif/evt struct */
uint16_t
uwba_get_evt_size(uint8_t *data, int data_len, uint16_t evt_code)
{
	uint16_t	buf_len_off, buf_len, evt_size;

	evt_size = uwba_evt_size_table[evt_code].struct_len;
	buf_len_off = uwba_evt_size_table[evt_code].buf_len_offset;

	/* If the offset of the variable data length is out of range. */
	if (buf_len_off >= data_len) {

		return (UWB_INVALID_EVT_SIZE);
	}

	/* If this event has variable length data, add up the length. */
	if (buf_len_off) {
		LE_TO_UINT16(data, buf_len_off, buf_len);

		/* in case buf_len is not a reasonable value. */
		if ((buf_len_off + 2 + buf_len) > data_len) {
			uwba_log(NULL, UWBA_LOG_DEBUG,
			    "uwba_get_evt_size: data_len=%d, buf_len_off=%d,"
			    " buf_len=%d", data_len, buf_len_off, buf_len);

			return (UWB_INVALID_EVT_SIZE);
		}

		/*
		 * after add up, the evt size may be a couple of bytes greater
		 * (depends on the structure alignment) than we actually need,
		 * but it does not matter.
		 */
		evt_size += buf_len;
	}

	/*
	 * TODO: check if data_len is less than expected raw event data, for the
	 * fixed length events/notifs.
	 */

	return (evt_size);
}

/*
 * hook the new event to uwb device handle, replace the old one if there is.
 * Signal the cmd thread which is waiting this cmd result.
 */
void
uwba_put_cmd_result(uwba_dev_t *uwba_dev, void *evt_struct,
	uint16_t  evt_size)
{
	uwb_cmd_result_t *cmd_rlt = (uwb_cmd_result_t *)evt_struct;

	mutex_enter(&uwba_dev->dev_mutex);
	if (uwba_dev->cmd_result_wrap.cmd_result) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "previous command result not processed "
		    "bEventType = %d, wEvent = %d, ctxt_id = %d",
		    uwba_dev->cmd_result_wrap.cmd_result->rceb.bEventType,
		    uwba_dev->cmd_result_wrap.cmd_result->rceb.wEvent,
		    uwba_dev->cmd_result_wrap.cmd_result->rceb.bEventContext);

		kmem_free(uwba_dev->cmd_result_wrap.cmd_result,
		    uwba_dev->cmd_result_wrap.length);
	}

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwba_put_cmd_result: wEvent= %d, msg= %s",
	    cmd_rlt->rceb.wEvent, uwba_event_msg(cmd_rlt->rceb.wEvent));
	uwba_dev->cmd_result_wrap.length = evt_size;
	uwba_dev->cmd_result_wrap.cmd_result = cmd_rlt;
	if (cmd_rlt->rceb.bEventContext == uwba_dev->ctxt_id) {
		cv_signal(&uwba_dev->cmd_result_cv);
	} else {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "the cmd result ctxt_id %d is not matching the"
		    "current cmd ctxt_id %d",
		    cmd_rlt->rceb.bEventContext, uwba_dev->ctxt_id);
	}
	mutex_exit(&uwba_dev->dev_mutex);
}

/* add the notification to the tail of uwba_dev->notif_list */
int
uwba_add_notif_to_list(uwba_dev_t *uwba_dev, void *evt_struct,
	uint16_t  evt_size)
{
	uwb_notif_wrapper_t *nw, *ow;

	nw = (uwb_notif_wrapper_t *)kmem_alloc(sizeof (uwb_notif_wrapper_t),
	    KM_NOSLEEP);
	if (nw == NULL) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwba_add_notif_to_list: allocate notif wrapper failed");

		return (UWB_NO_RESOURCES);
	}
	nw->length = evt_size;
	nw->notif = (uwb_rceb_notif_t *)evt_struct;

	mutex_enter(&uwba_dev->dev_mutex);

	list_insert_tail(&uwba_dev->notif_list, nw);
	uwba_dev->notif_cnt++;

	if (uwba_dev->notif_cnt >= UWB_MAX_NOTIF_NUMBER) {
		/* remove oldest one */
		ow = list_head(&uwba_dev->notif_list);
		list_remove(&uwba_dev->notif_list, ow);
		uwba_dev->notif_cnt--;

		/* Free it */
		if (ow->notif) {
			kmem_free(ow->notif, ow->length);
		}
		kmem_free(ow, sizeof (uwb_notif_wrapper_t));
	}

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwba_add_notif_to_list: notification code=%d, notif_cnt=%d",
	    nw->notif->rceb.wEvent, uwba_dev->notif_cnt);

	mutex_exit(&uwba_dev->dev_mutex);

	return (UWB_SUCCESS);
}

/*
 * find the specific client device in the client_dev_list by comparing the MAC
 * address
 */
uwba_client_dev_t *
uwba_find_cdev_by_mac(uwba_dev_t *uwba_dev, uwb_mac_addr_t *mac)
{
	uwba_client_dev_t *cdev = NULL;

	cdev = list_head(&uwba_dev->client_dev_list);
	while (cdev != NULL) {
		if (memcmp(mac, cdev->beacon_frame.Device_Identifier.addr,
		    sizeof (uwb_mac_addr_t)) == 0) {

			return (cdev);
		}
		cdev = list_next(&uwba_dev->client_dev_list, cdev);
	}

	return (cdev);
}
/* find the client device beconing in a specific channel */
uwba_client_dev_t *
uwba_find_cdev_by_channel(uwba_dev_t *uwba_dev, uint8_t channel)
{
	uwba_client_dev_t *cdev = NULL;

	cdev = list_head(&uwba_dev->client_dev_list);
	while (cdev != NULL) {
		if (cdev->bChannelNumber == channel) {

			return (cdev);
		}
		cdev = list_next(&uwba_dev->client_dev_list, cdev);
	}

	return (cdev);
}

/* remove all cdev list for uwb dev */
static void
uwba_remove_cdev_list(uwba_dev_t *uwba_dev)
{
	uwba_client_dev_t *cdev = NULL;

	while (!list_is_empty(&uwba_dev->client_dev_list)) {

		cdev = list_head(&uwba_dev->client_dev_list);
		if (cdev != NULL) {

			list_remove(&(uwba_dev->client_dev_list), cdev);
		} else {

			break;
		}

		kmem_free(cdev, sizeof (uwba_client_dev_t));
	}
}

/* add a client radio device to the tail of uwba_dev->client_dev_list */
int
uwba_add_cdev_to_list(uwba_dev_t *uwba_dev, uwb_beacon_frame_t *bc_frm)
{
	uwb_mac_addr_t	*mac;
	uwba_client_dev_t *cdev;
	int rval = UWB_SUCCESS;

	mutex_enter(&uwba_dev->dev_mutex);

	if (uwba_dev->client_dev_cnt >= UWB_MAX_CDEV_NUMBER) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwba_add_cdev_to_list: can not add this dev,"
		    "client dev number reached max,  client_dev_cnt=%d",
		    uwba_dev->client_dev_cnt);
		rval = UWB_FAILURE;
		goto done;
	}

	mac = &bc_frm->Device_Identifier;
	if (uwba_find_cdev_by_mac(uwba_dev, mac) != NULL) {
		uwba_log(uwba_dev, UWBA_LOG_DEBUG,
		    "uwba_add_cdev_to_list: this client dev is added before");

		rval = UWB_SUCCESS;
		goto done;
	}
	cdev = (uwba_client_dev_t *)kmem_alloc(sizeof (uwba_client_dev_t),
	    KM_NOSLEEP);
	if (cdev == NULL) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwba_add_client_device: allocate "
		    "uwba_client_dev_t failed");

		rval = UWB_NO_RESOURCES;
		goto done;
	}
	(void) memcpy(&cdev->beacon_frame, bc_frm, sizeof (uwb_beacon_frame_t));

	list_insert_tail(&uwba_dev->client_dev_list, cdev);
	uwba_dev->client_dev_cnt++;

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwba_add_cdev_to_list: a new client dev added. MAC: "
	    "%x %x %x %x %x %x, client_dev_cnt=%d",
	    cdev->beacon_frame.Device_Identifier.addr[0],
	    cdev->beacon_frame.Device_Identifier.addr[1],
	    cdev->beacon_frame.Device_Identifier.addr[2],
	    cdev->beacon_frame.Device_Identifier.addr[3],
	    cdev->beacon_frame.Device_Identifier.addr[4],
	    cdev->beacon_frame.Device_Identifier.addr[5],
	    uwba_dev->client_dev_cnt);
done:

	mutex_exit(&uwba_dev->dev_mutex);

	return (rval);
}

/*
 * Return the actual parsed raw data length. Stop parse if datalen or structlen
 * is out of range, and then return UWB_PARSE_ERROR.
 */
int
uwba_parse_data(char	*format,
	uchar_t 	*data,
	size_t		datalen,
	void		*structure,
	size_t		structlen)
{
	int	fmt;
	int	counter = 1;
	int	multiplier = 0;
	uchar_t *datastart = data;
	uchar_t	*dataend = data + datalen;
	void	*structend = (void *)((intptr_t)structure + structlen);

	if ((format == NULL) || (data == NULL) || (structure == NULL)) {

		return (UWB_PARSE_ERROR);
	}

	while ((fmt = *format) != '\0') {

		/*
		 * Could some one pass a "format" that is greater than
		 * the structlen? Conversely, one could pass a ret_buf_len
		 * that is less than the "format" length.
		 * If so, we need to protect against writing over memory.
		 */
		if (counter++ > structlen) {
			return (UWB_PARSE_ERROR);
		}

		if (fmt == 'c') {
			uint8_t	*cp = (uint8_t *)structure;

			cp = (uint8_t *)(((uintptr_t)cp + _CHAR_ALIGNMENT - 1) &
			    ~(_CHAR_ALIGNMENT - 1));

			/*
			 * If data or structure is out of range, stop parse.
			 */
			if (((data + 1) > dataend) ||
			    ((cp + 1) > (uint8_t *)structend))
				return (UWB_PARSE_ERROR);

			*cp++ = *data++;
			structure = (void *)cp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (fmt == 's') {
			uint16_t	*sp = (uint16_t *)structure;

			sp = (uint16_t *)
			    (((uintptr_t)sp + _SHORT_ALIGNMENT - 1) &
			    ~(_SHORT_ALIGNMENT - 1));
			if (((data + 2) > dataend) ||
			    ((sp + 1) > (uint16_t *)structend))
				return (UWB_PARSE_ERROR);

			*sp++ = (data[1] << 8) + data[0];
			data += 2;
			structure = (void *)sp;
			if (multiplier) {
				multiplier--;
			}
			if (multiplier == 0) {
				format++;
			}
		} else if (isdigit(fmt)) {
			multiplier = (multiplier * 10) + (fmt - '0');
			format++;
			counter--;
		} else {
			multiplier = 0;

			return (UWB_PARSE_ERROR);
		}
	}

	return ((intptr_t)data - (intptr_t)datastart);
}


/*
 * parse rceb, check if the context id is in the reasonable range (0x0 - 0xfe).
 * If success, return the offset just after the rceb struct.
 */
int
uwba_parse_rceb(uint8_t *data,
	size_t		datalen,
	void		*structure,
	size_t		structlen)
{
	int parsed_len;
	uwb_rceb_head_t *rceb;

	parsed_len = uwba_parse_data("csc", data, datalen,
	    structure, structlen);
	if (parsed_len  == UWB_PARSE_ERROR) {

		return (UWB_PARSE_ERROR);
	}
	rceb = (uwb_rceb_head_t *)structure;
	if (rceb->bEventContext > UWB_CTXT_ID_TOP) {

		return (UWB_PARSE_ERROR);
	}

	return (parsed_len);
}

int
uwba_parse_dev_addr_mgmt(uint8_t *spec_data, int spec_data_len,
    uwb_rceb_dev_addr_mgmt_t *evt_struct)
{
	/* 6 bytes for address, 1 for result code. */
	if (uwba_parse_data("7c", spec_data,
	    spec_data_len, evt_struct->baAddr, 7) == UWB_PARSE_ERROR) {

		return (UWB_PARSE_ERROR);
	}

	return (UWB_SUCCESS);
}

/* Parse UWB IEs that got by get_ie radio controller command */
int
uwba_parse_get_ie(uwb_dev_handle_t uwb_dev_hdl, uint8_t *spec_data,
	int spec_data_len, uwb_rceb_get_ie_t *evt_struct)
{
	int i;
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	/* At least, it should have wIELength. */
	if (spec_data_len < 2) {

		return (UWB_PARSE_ERROR);
	}
	LE_TO_UINT16(spec_data, 0, evt_struct->wIELength);

	/*
	 * Except wIELength, it should have the number of bytes of indicated by
	 * wIELength.
	 */
	if (spec_data_len < (evt_struct->wIELength + 2)) {

		return (UWB_PARSE_ERROR);
	}

	/*
	 * Proper memory for evt_struct is already allocated for evt_struct in
	 * uwb_parse_evt_notif()
	 */
	bcopy(spec_data + 2, evt_struct->IEData, evt_struct->wIELength);

	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwba_parse_get_ie: wIELength=%d", evt_struct->wIELength);

	for (i = 0; i < evt_struct->wIELength; i++) {
		uwba_log(uwba_dev, UWBA_LOG_DEBUG,
		    "0x%x ", evt_struct->IEData[i]);
	}

	/* Todo: continue to parse other IE Data? */
	uwba_get_phy_cap(uwb_dev_hdl, evt_struct->IEData,
	    evt_struct->wIELength);
	uwba_list_phy_rates(uwb_dev_hdl);
	uwba_list_phy_bandgroups(uwb_dev_hdl);

	return (UWB_SUCCESS);
}


/*
 * Parse the beacon frame and add the client radio device to the dev_list in
 * uwb_dev_handle
 */
void
uwba_parse_beacon_info(uwba_dev_t *uwba_dev, uint8_t *bc_info)
{
	uwb_beacon_frame_t *bc_frm;

	bc_frm = (uwb_beacon_frame_t *)bc_info;

	/*
	 * add the uwb device to list if it is a newly found device according to
	 * its MAC addr in the beacon
	 */
	if (uwba_add_cdev_to_list(uwba_dev, bc_frm) == UWB_SUCCESS) {

		/* TODO: log messages */

		return;
	}
}

int
uwba_parse_bpoie_chg(uwb_dev_handle_t uwb_dev_hdl,
	uint8_t *spec_data, int spec_data_len,
	uwb_rceb_bpoie_change_t *evt_struct) {
	int parsed_len;
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	parsed_len = uwba_parse_data("s", spec_data,
	    spec_data_len, &(evt_struct->wBPOIELength), 2);

	if (parsed_len  == UWB_PARSE_ERROR) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwba_parse_bpoie_chg: parse error, parsed_len=%d",
		    parsed_len);

		return (UWB_PARSE_ERROR);
	}
	/* Todo: not supported now */
	return (UWB_SUCCESS);
}
/* Parse the beacon_receive notif */
int
uwba_parse_beacon_rcv(uwb_dev_handle_t uwb_dev_hdl,
	uint8_t *spec_data, int spec_data_len,
	uwb_rceb_beacon_t *evt_struct)
{
	int parsed_len;
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	uwb_beacon_frame_t *bc_frm = NULL;
	uwba_client_dev_t *client_dev = NULL;

	/* parse the elements except BeaconInfo */
	parsed_len = uwba_parse_data("ccsccs", spec_data,
	    spec_data_len, &(evt_struct->bChannelNumber), 8);
	if (parsed_len  == UWB_PARSE_ERROR) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwba_parse_beacon_rcv: parse error, parsed_len=%d",
		    parsed_len);

		return (UWB_PARSE_ERROR);
	}

	/*
	 * Except the elements before BeaconInfo, it should have the number of
	 * bytes of indicated by wBeaconInfoLength.
	 */
	if ((spec_data_len -UWB_BEACONINFO_OFFSET) <
	    evt_struct->wBeaconInfoLength) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwba_parse_beacon_rcv: parse error: spec_data_len=%d,"
		    "evt_struct->wBeaconInfoLength=%d, bc_info_offset=%d",
		    spec_data_len, evt_struct->wBeaconInfoLength,
		    UWB_BEACONINFO_OFFSET);

		return (UWB_PARSE_ERROR);
	}
	if (evt_struct->wBeaconInfoLength < sizeof (uwb_beacon_frame_t)) {
		uwba_log(uwba_dev, UWBA_LOG_LOG,
		    "uwba_parse_beacon_rcv: too small size, "
		    "wBeaconInfoLength=%d, data[0]=%d, data[1]=%d, data[4]=%d,"
		    " data[5]=%d, data[6]=%d, data[7]=%d, spec_data_len=%d",
		    evt_struct->wBeaconInfoLength, spec_data[0], spec_data[1],
		    spec_data[4], spec_data[5], spec_data[6], spec_data[7],
		    spec_data_len);

		return (UWB_PARSE_ERROR);
	}
	uwba_log(uwba_dev, UWBA_LOG_DEBUG, "uwba_parse_beacon_rcv:"
	    "bChannelNumber = %d bBeaconType = %d "
	    "wBPSTOffset = %d bLQI = %d bRSSI = %d "
	    "wBeaconInfoLength = %d",
	    evt_struct->bChannelNumber, evt_struct->bBeaconType,
	    evt_struct->wBPSTOffset, evt_struct->bLQI, evt_struct->bRSSI,
	    evt_struct->wBeaconInfoLength);

	/*
	 * Proper memory for evt_struct is already allocated for evt_struct in
	 * uwb_parse_evt_notif()
	 */
	bcopy(spec_data + UWB_BEACONINFO_OFFSET,
	    evt_struct->BeaconInfo, evt_struct->wBeaconInfoLength);

	/*
	 * Parse the beacon frame and add the client radio device
	 * to the dev_list in uwb_dev_handle
	 */
	uwba_parse_beacon_info(uwba_dev, evt_struct->BeaconInfo);

	bc_frm = (uwb_beacon_frame_t *)evt_struct->BeaconInfo;

	client_dev = uwba_find_cdev_by_mac(uwba_dev,
	    &(bc_frm->Device_Identifier));

	/* Update the client device's beconing information */
	client_dev->bChannelNumber = evt_struct->bChannelNumber;
	client_dev->bBeaconType = evt_struct->bBeaconType;
	client_dev->wBPSTOffset = evt_struct->wBPSTOffset;
	return (UWB_SUCCESS);
}


/*
 * find the phy capability ie from ie_data, then save the capability bitmap to
 * uwb_dev_hdl
 */
static void
uwba_get_phy_cap(uwb_dev_handle_t uwb_dev_hdl,
    uint8_t *ie_data, uint16_t ie_len)
{
	uint8_t *phy_ie;

	/* traverse ie_data to find PHY Capabilities IE */
	phy_ie = uwba_find_ie(uwb_dev_hdl,
	    UWB_IE_PHY_CAP, ie_data, ie_len);

	if (phy_ie == NULL) {

		return;
	}
	/* copy the phy capabilities bitmap to uwba_dev->phy_cap_bm */
	uwba_save_phy_cap_bm(uwb_dev_hdl, phy_ie);
}

/* Copy the PHY capability bitmap from phy_ie to uwb device handle */
static void
uwba_save_phy_cap_bm(uwb_dev_handle_t uwb_dev_hdl, uint8_t *phy_ie)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	mutex_enter(&uwba_dev->dev_mutex);
	uwba_dev->phy_cap_bm = 0;

	uwba_dev->phy_cap_bm = phy_ie[4];
	uwba_dev->phy_cap_bm = phy_ie[3] | uwba_dev->phy_cap_bm << 8;
	uwba_dev->phy_cap_bm = phy_ie[2] | uwba_dev->phy_cap_bm << 8;
	mutex_exit(&uwba_dev->dev_mutex);
}

/* List all supported PHY data rates by checking the PHY capability bitmap */
static void
uwba_list_phy_rates(uwb_dev_handle_t uwb_dev_hdl)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	int i;
	const char *uwb_phy_rate_table[] = {
		[UWB_RATE_OFFSET_53 - UWB_RATE_OFFSET_BASE] = "53.3",
		[UWB_RATE_OFFSET_80 - UWB_RATE_OFFSET_BASE] = "80",
		[UWB_RATE_OFFSET_106 - UWB_RATE_OFFSET_BASE] = "106.7",
		[UWB_RATE_OFFSET_160 - UWB_RATE_OFFSET_BASE] = "160",
		[UWB_RATE_OFFSET_200 - UWB_RATE_OFFSET_BASE] = "200",
		[UWB_RATE_OFFSET_320 - UWB_RATE_OFFSET_BASE] = "320",
		[UWB_RATE_OFFSET_400 - UWB_RATE_OFFSET_BASE] = "400",
		[UWB_RATE_OFFSET_480 - UWB_RATE_OFFSET_BASE] = "480",
	};

	for (i = UWB_RATE_OFFSET_BASE; i <= UWB_RATE_OFFSET_480; i++) {
		if (BT_TEST(&uwba_dev->phy_cap_bm, i)) {
			uwba_log(uwba_dev, UWBA_LOG_DEBUG,
			    "uwba_list_phy_rates: Rate supported=%s",
			    uwb_phy_rate_table[i - UWB_RATE_OFFSET_BASE]);
		}
	}
	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwba_list_phy_rates: phy_cap_bm=%u",
	    uwba_dev->phy_cap_bm);
}

/* List all supported PHY band groups by checking the PHY capability bitmap */
static void
uwba_list_phy_bandgroups(uwb_dev_handle_t uwb_dev_hdl)
{
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	int i;

	/* group 1 to 4 [ECMA, Table 112] */
	for (i = 0; i <= 7; i++) {
		if (BT_TEST(&uwba_dev->phy_cap_bm, i)) {
			uwba_log(uwba_dev, UWBA_LOG_DEBUG,
			    "uwba_list_phy_bandgroups: band groups "
			    "supported=%d", i);
		}
	}

	/* group 5 [ECMA, Table 112] */
	if (BT_TEST(&uwba_dev->phy_cap_bm, 9)) {
		uwba_log(uwba_dev, UWBA_LOG_DEBUG,
		    "uwba_list_phy_bandgroups: band groups supported=%d", i);
	}
}



/*
 * Allocate a channel for the HC. Scan every channel supported,
 * if beacon information from the channel received, scan the next
 * channel, or else, stop.
 * Return:
 * 	first channel with no beacon recieved
 * 	last channel if every channel is busy
 * 	0 if scan failure
 * uwba_channel_table is used to decode the PHY capability IE.
 * The array index is the bit in the PHY IE. base is the first
 * TFC code.offset is the length from the first TFC code.
 * Refer to:
 * [ECM-368]. CHAP 11.2. Table 25-30.
 * [ECM-368]. CHAP 16.8.16. Table 112
 *
 */
uint8_t
uwba_allocate_channel(uwb_dev_handle_t uwb_dev_hdl) {
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;
	int i, j;
	uwba_channel_range_t uwba_channel_table[] = {
		{ .base =  9, .offset = 4 }, /* Band group 1 TFI */
		{ .base = 13, .offset = 3 }, /* Band group 1 FFI */
		{ .base = 17, .offset = 4 }, /* Band group 2 TFI */
		{ .base = 21, .offset = 3 }, /* Band group 2 FFI */
		{ .base = 25, .offset = 4 }, /* Band group 3 TFI */
		{ .base = 29, .offset = 3 }, /* Band group 3 FFI */
		{ .base = 33, .offset = 4 }, /* Band group 4 TFI */
		{ .base = 37, .offset = 3 }, /* Band group 4 FFI */
		{ .base =  0, .offset = 0 }, /* Bit reserved	 */
		{ .base = 45, .offset = 2 }  /* Band group 5 FFI */
	};
	int tbl_size = sizeof (uwba_channel_table) /
	    sizeof (uwba_channel_range_t);

	uint8_t channel = 0;
	for (i = 0; i < tbl_size; i++) {
		if ((uwba_dev->phy_cap_bm & (0x01<<i)) == 0x0) continue;

		for (j = 0; j < uwba_channel_table[i].offset; j++) {

			channel = uwba_channel_table[i].base + j;
			if (uwb_scan_channel(uwb_dev_hdl, channel)
			    != UWB_SUCCESS) {
				uwba_log(uwba_dev, UWBA_LOG_LOG,
				    "uwba_allocate_channel: scan chanel"
				    " %d failed", channel);

				return (0);
			}
			/* No beacon recevied in this channel, return */
			if (!uwba_find_cdev_by_channel(uwba_dev, channel)) {

				return (channel);
			}
			uwba_log(uwba_dev, UWBA_LOG_DEBUG,
			    "uwba_allocate_channel: exsting device becaoning"
			    "in channel = %d ", channel);
		}

	}

	/*
	 * when we reach here, it means all the channel has beconning device,
	 * return the last channel
	 */
done:
	uwba_log(uwba_dev, UWBA_LOG_DEBUG,
	    "uwba_allocate_channel: return channel = %d",
	    channel);

	return (channel);
}
/*
 * Find a IE with a specific ID in ie_data. Return the pointer to the IE head if
 * found, else return NULL.
 */
uint8_t *
uwba_find_ie(uwb_dev_handle_t uwb_dev_hdl, uint_t ie_id,
	uint8_t *ie_data, uint16_t ie_len)
{
	int i = 0;
	uint8_t curr_ie_len;
	boolean_t matched = B_FALSE;
	uwba_dev_t *uwba_dev = (uwba_dev_t *)uwb_dev_hdl;

	while (i < (ie_len - 1)) {
		if (ie_data[i] == ie_id) {
			matched = B_TRUE;

			break;
		}
		i++; /* move to the length item of the current IE */
		curr_ie_len = ie_data[i];
		i =  i + curr_ie_len + 1; /* move to the next IE's head */
	}
	if (matched) {
		curr_ie_len = ie_data[i + 1];

		/*
		 * if the rest ie data are less than that indicated in the
		 * matched IE's length, then this is not valid IE
		 */
		if ((ie_len - i -1) < curr_ie_len) {
			uwba_log(uwba_dev, UWBA_LOG_LOG,
			    "the matched IE is not valid. "
			    "curr_ie_len=%d, i=%d", curr_ie_len, i);

			return (NULL);
		}

		return (&ie_data[i]);
	}

	return (NULL);
}

void
uwba_copy_rccb(uwb_rccb_cmd_t *src_rccb, uwb_rccb_cmd_t *des_rccb)
{
	bcopy(src_rccb, des_rccb,	sizeof (uwb_rccb_cmd_t));
}

/* uwba_log, log the message output to dmesg according to err level */
void
uwba_log(uwba_dev_t *uwba_dev, uint_t msglevel, char *formatarg, ...)
{
	va_list	ap;
	const char *devinst = NULL;

	if (msglevel <= uwba_errlevel) {
		char *format;
		int formatlen = strlen(formatarg) + 2;	/* '!' and NULL char */
		int devinst_start = 0;
		if (uwba_dev) {
			devinst = uwba_dev->devinst;
		} else {
			devinst = "uwba: ";
		}
		ASSERT(devinst != NULL);

		/* Allocate extra room if driver name and instance is present */
		formatlen += strlen(devinst);

		format = kmem_zalloc(formatlen, KM_SLEEP);

		if (msglevel >= UWBA_LOG_LOG) {
			format[0] = '!';
			devinst_start = 1;
		}

		(void) strcpy(&format[devinst_start], devinst);

		va_start(ap, formatarg);
		(void) strcat(format, formatarg);
		vcmn_err(CE_CONT, format, ap);
		va_end(ap);

		kmem_free(format, formatlen);
	}
}

/* Get a msg string of a event or notfication */
const char *
uwba_event_msg(uint16_t wEvent) {
	if (wEvent > UWB_CE_SET_ASIE_NOTIFICATION) {
		return ("Unknown Message");
	} else {
		return (uwba_evt_msg_table[wEvent]);
	}
}
