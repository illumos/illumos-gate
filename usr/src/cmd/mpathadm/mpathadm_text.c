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
 * mpathadm_text.c : MP API CLI program
 *
 */

#include <libintl.h>

#include <mpapi.h>
#include "mpathadm_text.h"


MP_CHAR * getTextString(int stringVal) {
	switch (stringVal) {
		case TEXT_UNKNOWN:
			return (gettext("unknown"));

		/* load balance types for display and input to cli */
		case TEXT_LBTYPE_FAILOVER_ONLY:
			return ("failover-only");
		case TEXT_LBTYPE_LBAREGION:
			return ("logical-block");
		case TEXT_LBTYPE_DEVICEPROD:
			return ("device-product-specific");
		case TEXT_LBTYPE_LEASTIO:
			return ("least-used");
		case TEXT_LBTYPE_LEASTBLOCKS:
			return ("least-blocks");
		case TEXT_LBTYPE_ROUNDROBIN:
			return ("round-robin");
		case TEXT_LBTYPE_UNKNOWN:
			return ("unknown");
		case TEXT_LBTYPE_NONE:
			return ("none");
		case TEXT_LBTYPE_PROPRIETARY1:
			return ("proprietary1");
		case TEXT_LBTYPE_PROPRIETARY2:
			return ("proprietary2");
		case TEXT_LBTYPE_PROPRIETARY3:
			return ("proprietary3");
		case TEXT_LBTYPE_PROPRIETARY4:
			return ("proprietary4");
		case TEXT_LBTYPE_PROPRIETARY5:
			return ("proprietary5");
		case TEXT_LBTYPE_PROPRIETARY6:
			return ("proprietary6");
		case TEXT_LBTYPE_PROPRIETARY7:
			return ("proprietary7");
		case TEXT_LBTYPE_PROPRIETARY8:
			return ("proprietary8");
		case TEXT_LBTYPE_PROPRIETARY9:
			return ("proprietary9");
		case TEXT_LBTYPE_PROPRIETARY10:
			return ("proprietary10");
		case TEXT_LBTYPE_PROPRIETARY11:
			return ("proprietary11");
		case TEXT_LBTYPE_PROPRIETARY12:
			return ("proprietary12");
		case TEXT_LBTYPE_PROPRIETARY13:
			return ("proprietary13");
		case TEXT_LBTYPE_PROPRIETARY14:
			return ("proprietary14");
		case TEXT_LBTYPE_PROPRIETARY15:
			return ("proprietary15");
		case TEXT_LBTYPE_PROPRIETARY16:
			return ("proprietary16");

		/* used for display */
		case TEXT_NA:
			return (gettext("NA"));

		/* used for displaying of state and comparing input into cli */
		case TEXT_YES:
			return (gettext("yes"));
		case TEXT_NO:
			return (gettext("no"));
		case TEXT_ON:
			return ("on");
		case TEXT_OFF:
			return ("off");

		/* labels for display */
		case TEXT_LB_VENDOR:
			return ("Vendor:");
		case TEXT_LB_DRIVER_NAME:
			return ("Driver Name:");
		case TEXT_LB_DEFAULT_LB:
			return ("Default Load Balance:");
		case TEXT_LB_SUPPORTED_LB:
			return ("Supported Load Balance Types:");
		case TEXT_LB_ALLOWS_ACT_TPG:
			return ("Allows To Activate Target Port Group Access:");
		case TEXT_LB_ALLOWS_PATH_OV:
			return ("Allows Path Override:");
		case TEXT_LB_SUPP_AUTO_FB:
			return ("Supported Auto Failback Config:");
		case TEXT_LB_AUTO_FB:
			return ("Auto Failback:");
		case TEXT_LB_FB_POLLING_RATE:
			return ("Failback Polling Rate (current/max):");
		case TEXT_LB_SUPP_AUTO_P:
			return ("Supported Auto Probing Config:");
		case TEXT_LB_AUTO_PROB:
			return ("Auto Probing:");
		case TEXT_LB_PR_POLLING_RATE:
			return ("Probing Polling Rate (current/max):");
		case TEXT_LB_SUPP_DEVICES:
			return ("Supported Devices:");
		case TEXT_LB_PRODUCT:
			return ("Product:");
		case TEXT_LB_REVISION:
			return ("Revision:");
		case TEXT_LB_LOGICAL_UNIT:
			return ("Logical Unit:");
		case TEXT_LB_INQUIRY_NAME_TYPE:
			return ("Name Type:");
		case TEXT_NAME_TYPE_UNKNOWN:
			return ("unknown type");
		case TEXT_NAME_TYPE_VPD83_TYPE1:
			return ("SCSI Inquiry VPD Page83 Type1");
		case TEXT_NAME_TYPE_VPD83_TYPE2:
			return ("SCSI Inquiry VPD Page83 Type2");
		case TEXT_NAME_TYPE_VPD83_TYPE3:
			return ("SCSI Inquiry VPD Page83 Type3");
		case TEXT_NAME_TYPE_DEVICE_SPECIFIC:
			return ("device specific type");
		case TEXT_LB_INQUIRY_NAME:
			return ("Name:");
		case TEXT_LB_ASYMMETRIC:
			return ("Asymmetric:");
		case TEXT_LB_EXPLICIT_FAILOVER:
			return ("Explicit Failover:");
		case TEXT_LB_CURR_LOAD_BALANCE:
			return ("Current Load Balance:");
		case TEXT_LB_LU_GROUP_ID:
			return ("Logical Unit Group ID:");
		case TEXT_LB_PATH_INFO:
			return ("Paths:");
		case TEXT_LB_INIT_PORT_NAME:
			return ("Initiator Port Name:");
		case TEXT_LB_TARGET_PORT_NAME:
			return ("Target Port Name:");
		case TEXT_LB_OVERRIDE_PATH:
			return ("Override Path:");
		case TEXT_LB_PATH_STATE:
			return ("Path State:");
		case TEXT_LB_TPG_INFO:
			return ("Target Port Groups:");
		case TEXT_LB_ACCESS_STATE:
			return ("Access State:");
		case TEXT_LB_ID:
			return ("ID:");
		case TEXT_TPORT_LIST:
			return ("Target Ports:");
		case TEXT_LB_NAME:
			return ("Name:");
		case TEXT_LB_RELATIVE_ID:
			return ("Relative ID:");
		case TEXT_LB_INITATOR_PORT:
			return ("Initiator Port:");
		case TEXT_LB_TRANSPORT_TYPE:
			return ("Transport Type:");
		case TEXT_LB_OS_DEVICE_FILE:
			return ("OS Device File:");
		case TEXT_LB_MPATH_SUPPORT:
			return ("mpath-support:");
		case TEXT_LB_PATH_COUNT:
			return ("Total Path Count:");
		case TEXT_LB_OP_PATH_COUNT:
			return ("Operational Path Count:");

		case TEXT_LB_ENABLED:
			return ("Enabled:");
		case TEXT_LB_DISABLED:
			return ("Disabled:");

		case TEXT_UNKNOWN_OBJECT:
			return (gettext("unknown object"));

		/* status strings used in error messages */
		case TEXT_MPSTATUS_SUCCESS:
			return (gettext("success"));
		case TEXT_MPSTATUS_INV_PARAMETER:
			return (gettext("invalid parameter"));
		case TEXT_MPSTATUS_UNKNOWN_FN:
			return (gettext("unknown client function"));
		case TEXT_MPSTATUS_FAILED:
			return (gettext("failed"));
		case TEXT_MPSTATUS_INSUFF_MEMORY:
			return (gettext("insufficient memory"));
		case TEXT_MPSTATUS_INV_OBJ_TYPE:
			return (gettext("invalid object type"));
		case TEXT_MPSTATUS_OBJ_NOT_FOUND:
			return (gettext("object not found"));
		case TEXT_MPSTATUS_UNSUPPORTED:
			return (gettext("unsupported"));
		case TEXT_MPSTATUS_FN_REPLACED:
			return (gettext("function replaced"));
		case TEXT_MPSTATUS_ACC_STATE_INVAL:
			return (gettext("invalid access state"));
		case TEXT_MPSTATUS_PATH_NONOP:
			return (gettext("path not operational"));
		case TEXT_MPSTATUS_TRY_AGAIN:
			return (gettext("try again"));
		case TEXT_MPSTATUS_NOT_PERMITTED:
			return (gettext("not permitted"));

		/* error messages */
		case ERR_NO_MPATH_SUPPORT_LIST:
			return (gettext("Error: Unable to get mpath-support "
			    "list."));
		case ERR_CANT_FIND_MPATH_SUPPORT_WITH_NAME:
			return (gettext("Error: Unable to find mpath-support "
			    "%s."));
		case ERR_NO_PROPERTIES:
			return (gettext("Error: Unable to get configuration "
			    "information."));
		case ERR_NO_SUPP_DEVICE_INFO:
			return (gettext("Error: Unable to get supported "
			    "device product information."));
		case ERR_NO_LU_LIST:
			return (gettext("Error: Unable to get the logical "
			    "unit list."));
		case ERR_NO_ASSOCIATED_LU:
			return (gettext("Error: Unable to find an "
			    "associated logical-unit."));
		case ERR_LU_NOT_FOUND_WITH_MISSING_LU_STR:
			return (gettext("Error: Logical-unit %s is not "
			    "found."));
		case ERR_NO_LU_PATH_INFO_WITH_MISSING_LU_STR:
			return (gettext("Error: Failed to get path info for "
			    "logical-unit %s."));
		case ERR_NO_ASSOC_TPGS:
			return (gettext("Error: Unable to get associated "
			    "target port groups ."));
		case ERR_NO_ASSOC_TPORTS:
			return (gettext("Error: Unable to get associated "
			    "target ports."));
		case ERR_NO_INIT_PORTS:
			return (gettext("Error: Unable to get the "
			    "initiator-port list."));
		case ERR_NO_INIT_PORT_LIST_WITH_REASON:
			return (gettext("Error: Unable to get the "
			    "initiator-port list: %s."));
		case ERR_INIT_PORT_NOT_FOUND_WITH_MISSING_LU_STR:
			return (gettext("Error: Initiator port %s is not "
			    "found."));
		case ERR_FAILED_TO_REGISTER_PLUGIN_NAME_WITH_REASON:
			return (gettext("Error: Failed to register %s: %s."));
		case ERR_FAILED_TO_DEREGISTER_PLUGIN_NAME_WITH_REASON:
			return (gettext("Error: Failed to deregister "
			    "%ls: %s."));
		case ERR_FAILED_TO_CHANGE_OPTION_WITH_REASON:
			return (gettext("Error: Failed to change %s: %s."));
		case ERR_FAILED_TO_ENABLE_PATH_WITH_REASON:
			return (gettext("Error: Failed to enable path: %s."));
		case ERR_FAILED_TO_DISABLE_PATH_WITH_REASON:
			return (gettext("Error: Failed to disable path: %s."));
		case ERR_FAILED_TO_OVERRIDE_PATH_WITH_REASON:
			return (gettext("Error: Failed to override path: "
			    "%s."));
		case ERR_LU_NOT_ASYMMETRIC:
			return (gettext("Error: The logical unit is not "
			    "asymmetric."));
		case ERR_NO_FAILOVER_ALLOWED:
			return (gettext("Error: The logical unit doesn't "
			    "support explicit state change."));
		case ERR_FAILED_TO_FAILOVER_WITH_LU_AND_REASON:
			return (gettext("Error: Failover failed %s: %s."));
		case ERR_FAILED_TO_FAILOVER_WITH_REASON:
			return (gettext("Error: Failover failed: %s."));
		case ERR_FAILED_TO_CANCEL_OVERRIDE_PATH_WITH_REASON:
			return (gettext("Error: Failed to cancel the "
			    "overriding setting:  %s."));
		case ERR_FAILED_TO_FIND_PATH:
			return (gettext("Error: Unable to find path."));
		case LU_NOT_FOUND:
			return (gettext("logical-unit not found"));
		case FAILED_TO_FIND_PATH:
			return (gettext("Unable to find path"));
		case MISSING_LU_NAME:
			return (gettext("Missing logical-unit name"));
		case MISSING_INIT_PORT_NAME:
			return (gettext("Missing initiator-port name"));
		case MISSING_TARGET_PORT_NAME:
			return (gettext("Missing target-port name"));
		case TEXT_AUTO_FAILBACK:
			return (gettext("auto failback"));
		case TEXT_AUTO_PROBING:
			return (gettext("auto probing"));
		case TEXT_LOAD_BALANCE:
			return (gettext("load balance"));
		case TEXT_ILLEGAL_ARGUMENT:
			return (gettext("illegal argument"));
		case TEXT_MPATH_SUPPORT_NOT_FOUND:
			return (gettext("unable to find specified "
			    "mpath-support"));
		case ERR_MEMORY_ALLOCATION:
			return (gettext("Error: Memory allocation failure"));
		case TEXT_MORE_INFO:
			return (gettext("For more information, please see"));
		case TEXT_UNABLE_TO_COMPLETE:
			return (gettext("Unable to complete operation"));
		case ERR_FILE_DESCRIPTOR:
			return (gettext("ERROR: Failed getting file "
			    "descriptor"));
		case ERR_DEVID:
			return (gettext("ERROR: Failed attempt to get devid "
			    "information"));
		case ERR_LU_ACCESS_STATE_UNCHANGED:
			return (gettext("ERROR: LU access state unchanged.  "
			    "No standby TPG found."));

		/* strings to display info */
		case TEXT_PATH_STATE_OKAY:
			return ("OK");
		case TEXT_PATH_STATE_PATH_ERR:
			return ("path error");
		case TEXT_PATH_STATE_LU_ERR:
			return ("LU error");
		case TEXT_PATH_STATE_RESERVED:
			return ("reserved");
		case TEXT_PATH_STATE_REMOVED:
			return ("unavailable");
		case TEXT_PATH_STATE_TRANSITIONING:
			return ("transitioning");
		case TEXT_PATH_STATE_OPERATIONAL_CLOSED:
			return ("operational but closed");
		case TEXT_PATH_STATE_INVALID_CLOSED:
			return ("invalid closed");
		case TEXT_PATH_STATE_OFFLINE_CLOSED:
			return ("operational but closed");
		case TEXT_ACCESS_STATE_ACTIVE_OPTIMIZED:
			return ("active optimized");
		case TEXT_ACCESS_STATE_ACTIVE_NONOPTIMIZED:
			return ("active not optimized");
		case TEXT_ACCESS_STATE_STANDBY:
			return ("standby");
		case TEXT_ACCESS_STATE_UNAVAILABLE:
			return ("unavailable");
		case TEXT_ACCESS_STATE_TRANSITIONING:
			return ("transitioning");
		case TEXT_ACCESS_STATE_ACTIVE:
			return ("active");
		case TEXT_ANY_DEVICE:
			return ("any device");

		case TEXT_TRANS_PORT_TYPE_MPNODE:
			return ("Logical Multipath Port");
		case TEXT_TRANS_PORT_TYPE_FC:
			return ("Fibre Channel");
		case TEXT_TRANS_PORT_TYPE_SPI:
			return ("parallel SCSI");
		case TEXT_TRANS_PORT_TYPE_ISCSI:
			return ("iSCSI");
		case TEXT_TRANS_PORT_TYPE_IFB:
			return ("InfiniBand-Fibre Channel");


		default:
			return ("");
	}
}
