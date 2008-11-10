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

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/nvpair.h>

#include "mms_mgmt.h"
#include "mgmt_acsls.h"
#include "mmp_defs.h"
#include "mgmt_sym.h"
#include "mgmt_util.h"

static char *_SrcFile = __FILE__;
#define	HERE _SrcFile, __LINE__

/*
 * This file contains the following functionality:
 * 1. parse MMP responses
 * 2. error handling of MM communication
 */
static int attrs2nvlist(mms_par_node_t *attrs, boolean_t useropt,
    nvlist_t **nvl);
static char *mgmt_cvt_mmp_to_user(char *in);
static char *mgmt_cvt_user_to_mmp(char *in);

typedef struct {
	char	*mmp_opt;
	char	*public_opt;
} map_opt_names;

/* those with NULL equivalents will not be returned to the caller */
static map_opt_names optmap[] = {
	{"CartridgeTypeName",		O_VOLTYPE},
	{"CartridgeTypeNumberSides",	"sides"},
	{"CartridgeTypeMediaLength",	O_SIZE},
	{"CartridgeTypeMediaType",	"purpose"},
	{"CartridgeStatus",		"status"},
	{"CartridgeDriveOccupied",	"loaded-in-drive"},
	{"MaxUseCount",			"max-use-count"},
	{"CartridgeShapeName",		O_MTYPE},
	{"Side1Name",			NULL},
	{"CartridgeTypeSize",		NULL},
	{"CartridgeID",			NULL},
	{"CartridgePCL",		"volid"},
	{"CartridgeState",		"state"},
	{"CartridgeGroupName",		O_MPOOL},
	{"DriveGroupName",		O_DPOOL},
	{"CartridgeTimeCreated",	"created"},
	{"CartridgeTimeMountedLast",	"last-mounted"},
	{"CartridgeTimeMountedTotal",	"total-mount-time"},
	{"CartridgeNumberMounts",	"num-mounts"},
	{"CartridgeWriteProtected",	"write-protected"},
	{"CartridgeNumberVolumes",	NULL},
	{"CartridgeMediaError",		"media-error"},
	{"CartridgeBytesRead",		"bytes-read"},
	{"CartridgeBytesWritten",	"bytes-written"},
	{"CartridgeRecovededReads",	NULL},
	{"CartridgeRecovededWrites",	NULL},
	{"CartridgeUnrecovededReads",	NULL},
	{"CartridgeUnrecovededWrites",	NULL},
	{"LibraryName",			O_MMSLIB},
	{"CartridgeMountPoint",		"mountpt"},
	{"CartridgePath",		"path"},
	{"Administrator",		NULL},
	{"AttendanceMode",		O_ATTENDED},
	{"SystemLogLevel",		O_LOGLEVEL},
	{"SystemAcceptLevel",		NULL},
	{"SystemLogFile",		O_LOGFILE},
	{"SystemMessageLimit",		NULL},
	{"SystemMessageCount",		NULL},
	{"SystemRequestLimit",		NULL},
	{"SystemRequestCount",		"num-oper-requests"},
	{"SystemSyncLimit",		NULL},
	{"SystemDCALimit",		NULL},
	{"SystemDCACount",		NULL},
	{"ClearDriveAtLMConfig",	NULL},
	{"AskClearDriveAtLMConfig",	NULL},
	{"PreemptReservation",		NULL},
	{"MessageLevel",		O_MSGLEVEL},
	{"TraceLevel",			O_TRACELEVEL},
	{"TraceFileSize",		O_TRACESZ},
	{"SocketFdLimit",		O_NUMSOCKET},
	{"SystemLogFileSize",		"log-size"},
	{"SystemName",			O_NAME},
	{"SystemInstance",		NULL},
	{"UnloadDelayTime",		O_UNLOADTM},
	{"DefaultBlocksize",		NULL},
	{"SystemDiskMountTimeout",	O_DKTIMEOUT},
	{"WatcherStartsLimit",		O_NUMRESTART},
	{"DriveRecordRetention",	NULL},
	{"DriveName",			O_NAME},
	{"DriveName",			"drive"},
	{"DriveGroupName",		NULL},
	{"DrivePriority",		NULL},
	{"DriveShapeName",		NULL},
	{"DriveDisabled",		"disabled"},
	{"DriveBroken",			"broken"},
	{"DriveStateSoft",		"DM state"},
	{"DriveStateHard",		"state"},
	{"DriveTimeCreated",		"create-time"},
	{"DriveTimeMountedLast",	"last-mount"},
	{"DriveTimeMountedTotal",	"total-mount-time"},
	{"DriveNumberMounts",		"num-mounts"},
	{"DriveNumberMountsSinceCleaning", "mounts-since-clean"},
	{"DriveLibraryAccessible",	NULL},
	{"DriveLibraryOccupied",	NULL},
	{"DriveNeedsCleaning",		"needs-cleaning"},
	{"MaxMounts",			NULL},
	{"ExclusiveAppName",		NULL},
	{"ReserveDrive",		O_RESERVE},
	{"DefaultBlocksize",		"blocksize"},
	{"DriveSerialNum",		O_SERIALNO},
	{"DriveOnline",			O_ONLINE},
	{"DriveType",			O_TYPE},
	{"LibraryDisabled",		"disabled"},
	{"LibraryBroken",		"broken"},
	{"LibraryStateHard",		"state"},
	{"LibraryStateSoft",		"LM state"},
	{"LibraryOnline",		O_ONLINE},
	{"LibraryType",			O_TYPE},
	{"LibraryIP",			O_ACSHOST},
	{"LibraryACS",			O_ACSNUM},
	{"LibraryLSM",			O_LSMNUM},
	{"LibrarySerialNumber",		O_SERIALNO},
	{"RequestID",			"request-id"},
	{"RequestingTaskID",		NULL},
	{"RequestingClient",		"requestor"},
	{"RequestingInstance",		NULL},
	{"RequestingClientType",	"requestor-type"},
	{"RequestPriority",		"priority"},
	{"RequestState",		O_OBJSTATE},
	{"RequestText",			"description"},
	{"AcceptingSessionID",		NULL},
	{"ResponseText",		O_RESPTXT},
	{"RequestTimeCreated",		"create-time"},
	{"RequestTimeAccepted",		"accept-time"},
	{"RequestTimeResponded",	"response-time"},
	{"ApplicationName",		O_NAME},
	{"ApplicationName",		"application"},
	{"SignatureAlgorithm",		NULL},
	{"AllowRemoteMount",		NULL},
	{"BypassVerify",		NULL},
	{"ReadWriteMode",		NULL},
	{"ValidateFileName",		O_VALIDATEFN},
	{"ValidateVolumeID",		O_VALIDATEVOL},
	{"ValidateExpirationDate",	O_VALIDATEEXP},
	{"SwitchLabel",			NULL},
	{"WriteOverExistingData",	O_OVERWRITEEXT},
	{"Retention",			O_RETENTION},
	{NULL,	NULL}
};

int
mms_client_handle_rsp(void *rsp)
{
	int	rc;
	int	class;
	int	code;
	char	*msg;
	int	rsptype;

	if (!rsp) {
		return (MMS_MGMT_NOARG);
	}

	mms_rsp_ele_t	*lrsp = (mms_rsp_ele_t *)rsp;
	rsptype = mms_rsp_type(rsp);

	switch (rsptype) {
		case MMS_API_RSP_UNACC:
			mms_trace(MMS_ERR, "Command was not accepted");
			rc = MMS_MGMT_REQ_NOT_ACCEPTED;
			break;

		case MMS_API_RSP_ACC:
			mms_trace(MMS_DEBUG, "Command was accepted");
			rc = 0;
			break;

		case MMS_API_RSP_FINAL:
			mms_trace(MMS_INFO, "Command was successful");
			rc = 0;
			break;

		case MMS_API_RSP_FINAL_ERR:
			mms_trace(MMS_ERR,
			    "Command received an error response");

			rc = mms_handle_err_rsp(rsp, &class, &code, &msg);
			if (rc != MMS_API_OK) {
				mms_trace(MMS_ERR, "Error response failed");
				break;
			}

			mms_trace(MMS_ERR, "Error class[%d, %s], code[%d, %s]",
			    class, mms_sym_code_to_str(class),
			    code, mms_sym_code_to_str(code));

			if (msg) {
				mms_trace(MMS_ERR, "Error message[%s]", msg);
			}

			/* TODO:  Translate code/class to something rational */
			if (code == MMS_EDATABASE) {
				if ((strstr(lrsp->mms_rsp_str,
				    "duplicate key"))||
				    (strstr(lrsp->mms_rsp_str,
				    "already exists"))) {
					class = MMS_EXIST;
				} else if (strstr(lrsp->mms_rsp_str,
				    "still referenced")) {
					code = EBUSY;
				}
			}

			if (class == MMS_EXIST) {
				rc = EEXIST;
			} else {
				rc = code;
			}

			break;

		case MMS_API_RSP_FINAL_CANC:
			mms_trace(MMS_INFO,
			    "Command received a cancelled response");
			rc = MMS_MGMT_RSP_CANCELLED;
			break;

		default:
			mms_trace(MMS_ERR, "Unknown response type: %d",
			    rsptype);
			rc = MMS_MGMT_RSP_UNKNOWN;
			break;
	}

	if (lrsp->mms_rsp_str) {
		mms_trace(MMS_DEBUG, "Response: %s", lrsp->mms_rsp_str);
	}

	return (rc);
}


/*
 * Parse the response to a report LIBRARY request and fill the mms_acslib_t
 * structure
 *
 * "LibraryName" "library1" "LibraryDisabled" "false" "LibraryBroken" "false"
 * "LMName" "lm1" "LibraryStateHard" "unknown" "LibraryStateSoft" "ready"
 * "LibraryOnline" "true" "LibraryType" "L180" "LibraryConnection" "network"
 * "LibraryIP" "nws-nsh-54-94.east" "LibraryPath" "" "LibraryACS" "0"
 */
void
mmp_parse_lib_attr(mms_par_node_t *node, mms_acslib_t *lib)
{
	mms_par_node_t	*name;
	mms_par_node_t	*val;
	mms_par_node_t	*lasts = NULL;

	if (!lib) {
		return;
	}

	/* LibraryName */
	name = mms_pn_lookup(node, "LibraryName", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			(void) strlcpy(lib->name, mms_pn_token(val),
			    MAXNAMELEN);
		}
	}

	/* LibraryType */
	name = mms_pn_lookup(node, "LibraryType", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			(void) strlcpy(lib->type, mms_pn_token(val), 32);
		}
	}

	/* LibraryIP */
	name = mms_pn_lookup(node, "LibraryIP", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			(void) strlcpy(lib->acshost,
			    mms_pn_token(val), MAXHOSTNAMELEN);
		}
	}

	/* LibraryACS */
	name = mms_pn_lookup(node, "LibraryACS", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			lib->acs = atoi(mms_pn_token(val));
		}
	}

	name = mms_pn_lookup(node, "LibraryLSM", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			lib->lsm = atoi(mms_pn_token(val));
		}
	}

	/* LibrarySerialNumber */
	name = mms_pn_lookup(node, "LibrarySerialNumber", MMS_PN_STRING,
	    &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			(void) strlcpy(lib->serialnum, mms_pn_token(val),
			    sizeof (lib->serialnum));
		}
	}
}

/*
 * parse the LIBRARY LM response which has a sequence of library objects and
 * the LM(s) for each library
 */
int
mmp_parse_library_rsp(void *rsp, mms_list_t *acslib_list)
{

	mms_acslib_t	*lib;
	mms_lm_t	*lm;
	mms_par_node_t	*root;
	mms_par_node_t	*last = NULL, *alast = NULL;
	mms_par_node_t	*text, *arg;
	boolean_t	first = B_TRUE;

	if (!rsp || !acslib_list) {
		return (-1);
	}

	mms_trace(MMS_DEBUG, "Response: %s",
	    ((mms_rsp_ele_t *)rsp)->mms_rsp_str);

	mms_list_create(acslib_list, sizeof (mms_acslib_t),
	    offsetof(mms_acslib_t, lib_link));

	root = mms_get_tree(rsp);
	if (root == NULL) {
		mms_trace(MMS_ERR, "parse library response failed");
		return (-1);
	}

	for (text = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, &last);
	    text != NULL;
	    text = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, &last)) {


		/*
		 * Multiple attrlist clauses in this text clause:
		 * First attrlist describes the library
		 * Subsequent attrlist describes the LM(s) for the drive
		 */

		lib = (mms_acslib_t *)malloc(sizeof (mms_acslib_t));
		(void) memset(lib, 0, sizeof (mms_acslib_t));

		mms_list_create(&lib->lm_list, sizeof (mms_lm_t),
		    offsetof(mms_lm_t, lm_link));

		for (arg = mms_pn_lookup_arg(text, NULL, NULL, &alast);
		    arg != NULL;
		    arg = mms_pn_lookup_arg(text, NULL, NULL, &alast)) {

			if ((arg->pn_type & MMS_PN_CLAUSE) &&
			    (strcmp(arg->pn_string, "attrlist") == 0)) {

				if (first) {
					mmp_parse_lib_attr(arg, lib);
					first = B_FALSE;
				} else {
					lm = (mms_lm_t *)
					    malloc(sizeof (mms_lm_t));
					(void) memset(lm, 0, sizeof (mms_lm_t));

					mmp_parse_lm_attr(arg, lm);

					mms_list_insert_tail(&lib->lm_list, lm);
				}
			}
		}
		mms_list_insert_tail(acslib_list, lib);
		first = B_TRUE;
		alast = NULL;
	}

	return (0);
}


/*
 * parse the MMP response to a LM report and fill the values in mms_lm_t
 *
 * The response are position dependent.
 * "LibraryName" "virt-library" "LMName" "virt-lm" "LMHost" "10.1.170.163"
 * "LMTargetLibrary" "" "LMTargetPath" "" "LMTargetHost" "muddy-mn"
 * "LMPassword" "" "LMMessageLevel" "error" "LMStateHard" "ready"
 * "LMStateSoft" "ready" "LMDisabled" "false" "TraceLevel" "debug"
 * "TraceFileSize" "10M"
 */
void
mmp_parse_lm_attr(mms_par_node_t *node, mms_lm_t *lm)
{
	mms_par_node_t	*name;
	mms_par_node_t	*pval;
	mms_par_node_t	*lasts = NULL;

	if (!lm || !node) {
		return;
	}

	/* LMName */
	name = mms_pn_lookup(node, "LMName", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		pval = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (pval != NULL) {
			(void) strlcpy(lm->name, mms_pn_token(pval),
			    MAXNAMELEN);
		}
	}

	/* LMTargetHost */
	name = mms_pn_lookup(node, "LMTargetHost", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		pval = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (pval != NULL) {
			(void) strlcpy(lm->hostname,
			    mms_pn_token(pval), MAXHOSTNAMELEN);
		}
	}

	/* Flags - LMStateHard, LMStateSoft, LMDisabled */
}

int
mmp_parse_lm_rsp(void *rsp, mms_list_t *lm_list)
{

	mms_lm_t	*lm;
	mms_par_node_t	*root;
	mms_par_node_t	*last = NULL;
	mms_par_node_t	*text;

	mms_list_create(lm_list, sizeof (mms_lm_t),
	    offsetof(mms_lm_t, lm_link));

	root = mms_get_tree(rsp);
	if (root == NULL) {
		mms_trace(MMS_ERR, "parse LM response failed");
		return (-1);
	}

	for (text = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, &last);
	    text != NULL;
	    text = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, &last)) {

		lm = (mms_lm_t *)malloc(sizeof (mms_lm_t));
		(void) memset(lm, 0, sizeof (mms_lm_t));

		mmp_parse_lm_attr(text, lm);

		mms_list_insert_tail(lm_list, lm);
	}
	return (0);
}


/*
 * parse the MMP response to a DM report and fill the values in mms_dm_t
 *
 * "DMName" "virt-dm1" "DriveName" "virt-drive0" "DMHost" "10.1.170.163"
 * "DMTargetLibrary" "" "DMTargetPath" "/devices/pseudo/dda@0:bn"
 * "DMTargetHost" "muddy-mn" "DMPassword" "" "DMMessageLevel" "error"
 * "DMStateHard" "ready" "DMStateSoft" "ready" "DMDisabled" "false"
 * "TraceLevel" "debug" "TraceFileSize" "10M"
 */
void
mmp_parse_dm_attr(mms_par_node_t *node, mms_dm_t *dm)
{
	mms_par_node_t	*name;
	mms_par_node_t	*pval;
	mms_par_node_t	*lasts = NULL;

	if (!node || !dm) {
		return;
	}

	/* DMName */
	name = mms_pn_lookup(node, "DMName", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		pval = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (pval != NULL) {
			(void) strlcpy(dm->name, mms_pn_token(pval),
			    MAXNAMELEN);
		}
	}

	/* DMTargetHost */
	name = mms_pn_lookup(node, "DMTargetHost", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		pval = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (pval != NULL) {
			(void) strlcpy(dm->hostname,
			    mms_pn_token(pval), MAXHOSTNAMELEN);
		}
	}

	/* Flags - DMStateHard, DMStateSoft, DMDisabled */
}

int
mmp_parse_dm_rsp(void *rsp, mms_list_t *dm_list)
{

	mms_dm_t	*dm;
	mms_par_node_t	*root;
	mms_par_node_t	*lasts = NULL;
	mms_par_node_t	*node;

	mms_list_create(dm_list, sizeof (mms_dm_t),
	    offsetof(mms_dm_t, dm_link));

	root = mms_get_tree(rsp);
	if (root == NULL) {
		mms_trace(MMS_ERR, "parse drive response failed");
		return (-1);
	}

	while (node = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, &lasts)) {
		if (node == NULL) {
			break;
		}

		dm = (mms_dm_t *)malloc(sizeof (mms_dm_t));
		(void) memset(dm, 0, sizeof (mms_dm_t));

		mmp_parse_dm_attr(node, dm);

		mms_list_insert_tail(dm_list, dm);
	}

	return (0);
}


/*
 * Parse drive attributes from the response
 *
 * "DriveName" "drive1" "DriveGroupName" "LTO" "DrivePriority" "1000"
 * "DMName" "" "DriveShapeName" "LTO3" "DriveDisabled" "false"
 * "DriveBroken" "false" "DriveStateSoft" "ready" "DriveStateHard" "unloaded"
 * "DriveTimeCreated" "2007 09 13 12 47 58 328" "DriveTimeMountedLast"
 * "2007 09 20 15 33 54 037" "DriveTimeMountedTotal" "0000 00 00 00 00 00 000"
 * "DriveNumberMounts" "3" "DriveNumberMountsSinceCleaning" "3" "LibraryName"
 * "library1" "BayName" "panel 0" "DriveLibraryAccessible" "true"
 * "DriveLibraryOccupied" "false" "CartridgePCL" "" "DriveNeedsCleaning" "false"
 * "MaxMounts" "0" "ExclusiveAppName" "none" "ReserveDrive" "yes"
 * "DefaultBlocksize" "262144" "DriveGeometry" "0,0,0,1" "DriveSerialNum"
 * "1210013554" "DriveOnline" "true"
 *
 */
void
mmp_parse_drive_attr(mms_par_node_t *node, mms_drive_t *d)
{
	mms_par_node_t	*name;
	mms_par_node_t	*val;
	mms_par_node_t	*lasts = NULL;

	if (!node || !d) {
		return;
	}

	/* DriveName */
	name = mms_pn_lookup(node, "DriveName", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			(void) strlcpy(d->name, mms_pn_token(val), MAXNAMELEN);
		}
	}

	/* DriveGroupName (future) */

	/* DrivePriority */
	name = mms_pn_lookup(node, "DrivePriority", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			d->priority = atoi(mms_pn_token(val));
		}
	}

	/* Flags - DriveDisabled */
	name = mms_pn_lookup(node, "DriveDisabled", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			if (strcmp("true", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_DISABLED;
			}
		}
	}

	/* Flags - DriveBroken */
	name = mms_pn_lookup(node, "DriveBroken", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			if (strcmp("true", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_BROKEN;
			}
		}
	}

	/* Flags - DriveStateSoft */
	name = mms_pn_lookup(node, "DriveStateSoft", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			if (strcmp("ready", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_READY;
			} else if (strcmp("in use", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_INUSE;
			}
		}
	}

	/* Flags - DriveStateHard */
	name = mms_pn_lookup(node, "DriveStateHard", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			if (strcmp("loaded", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_LOADED;
			} else if (strcmp("loading", mms_pn_token(val))
			    == 0) {
				d->flags |= MMS_ST_DRIVE_LOADING;
			} else if (strcmp("unloading", mms_pn_token(val))
			    == 0) {
				d->flags |= MMS_ST_DRIVE_UNLOADING;
			} else if (strcmp("unloaded", mms_pn_token(val))
			    == 0) {
				d->flags |= MMS_ST_DRIVE_UNLOADED;
			}
		}
	}

	/* LibraryName */
	name = mms_pn_lookup(node, "LibraryName", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			(void) strlcpy(d->libname, mms_pn_token(val),
			    MAXNAMELEN);
		}
	}

	/* More Flags - DriveLibraryAccessible, DriveLibraryOccupied */
	name = mms_pn_lookup(node, "DriveLibraryAccessible",
	    MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			if (strcmp("false", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_INACCESSIBLE;
			}
		}
	}


	name = mms_pn_lookup(node, "DriveLibraryOccupied",
	    MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			if (strcmp("true", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_OCCUPIED;
			}
		}
	}


	/* CartridgePCL - Media in Drive */

	/* More Flags - DriveNeedsCleaning */
	name = mms_pn_lookup(node, "DriveNeedsCleaning",
	    MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			if (strcmp("true", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_RCLEANING;
			} else if (strcmp("advisory", mms_pn_token(val))
			    == 0) {
				d->flags |= MMS_ST_DRIVE_ACLEANING;
			} else if (strcmp("mandatory", mms_pn_token(val))
			    == 0) {
				d->flags |= MMS_ST_DRIVE_MCLEANING;
			}
		}
	}


	/* DefaultBlocksize */
	name = mms_pn_lookup(node, "DefaultBlocksize",
	    MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			d->blocksize = atoi(mms_pn_token(val));
		}
	}

	/* DriveSerialNum */
	name = mms_pn_lookup(node, "DriveSerialNum", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			(void) strlcpy(d->serialnum,
			    mms_pn_token(val), MAXSERIALNUMLEN);
		}
	}

	/* More Flags - DriveOnline (not in MM spec ?) */
	name = mms_pn_lookup(node, "DriveOnline", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			if (strcmp("false", mms_pn_token(val)) == 0) {
				d->flags |= MMS_ST_DRIVE_OFFLINE;
			}
		}
	}

	/* DriveType */
	lasts = NULL;
	name = mms_pn_lookup(node, "DriveType", MMS_PN_STRING, &lasts);
	if (name != NULL) {
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &lasts);
		if (val != NULL) {
			(void) strlcpy(d->type, mms_pn_token(val), 32);
		}
	}

}


/*
 * Parse the MMP response consisting of a sequence of drive objects and dm
 * objects for that drive. Convert the response to a list of mms_drive_t
 * This response is in request to a report DRIVE DM
 *
 * The response is made up a series of name value pairs, these name value
 * entries are positional and the parsing function saves a pointer to the
 * following byte, from which the next search for an attribute begins. So the
 * attributes have to be parsed in a predetermined order. The response is
 * given below for attribute order purposes.
 *
 */
int
mmp_parse_drive_rsp(void *rsp, mms_list_t *drive_list)
{

	mms_drive_t	*drive;
	mms_dm_t	*dm;
	mms_par_node_t	*root;
	mms_par_node_t	*last = NULL, *alast = NULL;
	mms_par_node_t	*text, *arg;
	boolean_t	first = B_TRUE;

	if (!rsp || !drive_list) {
		return (-1);
	}

	mms_trace(MMS_ERR,
	    "Response: %s\n", ((mms_rsp_ele_t *)rsp)->mms_rsp_str);

	mms_list_create(drive_list, sizeof (mms_drive_t),
	    offsetof(mms_drive_t, drive_link));

	root = mms_get_tree(rsp);
	if (root == NULL) {
		mms_trace(MMS_ERR, "parse drive response failed");
		return (-1);
	}

	for (text = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, &last);
	    text != NULL;
	    text = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, &last)) {


		/*
		 * Multiple attrlist clauses in this text clause:
		 * First attrlist describes the drive
		 * Subsequent attrlist describes the DM(s) for the drive
		 */

		drive = (mms_drive_t *)malloc(sizeof (mms_drive_t));
		(void) memset(drive, 0, sizeof (mms_drive_t));
		mms_list_create(&drive->dm_list, sizeof (mms_dm_t),
		    offsetof(mms_dm_t, dm_link));

		for (arg = mms_pn_lookup_arg(text, NULL, NULL, &alast);
		    arg != NULL;
		    arg = mms_pn_lookup_arg(text, NULL, NULL, &alast)) {

			if ((arg->pn_type & MMS_PN_CLAUSE) &&
			    (strcmp(arg->pn_string, "attrlist") == 0)) {

				if (first) {
					mmp_parse_drive_attr(arg, drive);
					first = B_FALSE;
				} else {

					dm = (mms_dm_t *)
					    malloc(sizeof (mms_dm_t));
					(void) memset(dm, 0, sizeof (mms_dm_t));

					mmp_parse_dm_attr(arg, dm);

					mms_list_insert_tail(&drive->dm_list,
					    dm);
				}
			}
		}
		mms_list_insert_tail(drive_list, drive);
		first = B_TRUE;
		alast = NULL;
	}

	return (0);
}


/*
 * The function mmp_build() builds the command syntax using the MMP language.
 * All requests to the MM, including access to media, device management
 * functions, routine operational functions and MMS administration are done
 * using the MMP protocol.
 *
 * The MMP is made up of command type, object type and its attributes. MMP
 * supports a rich range of commands which fall into several different
 * categories such as attribute, cancel, create, deallocate, delete, goodbye,
 * locale, privilege, rename, show, accept, begin-end, cpattribute, cpscan,
 * cpshow, cpreset, eject, inject, mount, move, release, respond, shutdown
 * and unmount. The mmp_build() function only supports the attribute, create,
 * delete and show commands at this time.
 *
 * The MMS defines more than 40 types of objects that make up a media
 * environment. This funtion however builds the MMP for the library, lm
 * drive, dm, drivegroup, drivegroupapplication, slottype, cartridge,
 * cartridgegroup, and cartridgegroupapplication only.
 */

/*
 *  Processes a single clause, that may have multiple attr lists
 */
int
mmp_get_nvattrs(char *key, boolean_t useropt, void *response, nvlist_t **nvl)
{
	int		st = 0;
	mms_par_node_t	*lasts = NULL;
	mms_par_node_t	*root;
	mms_par_node_t	*alast;
	mms_par_node_t	*text;
	mms_par_node_t	*attrs;
	nvlist_t	*lst;
	char		*val;
	int		lcnt = 0;
	char		buf[1024];

	if (!key|| !response || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_DEBUG, "Response: %s",
	    ((mms_rsp_ele_t *)response)->mms_rsp_str);

	root = mms_get_tree(response);
	if (root == NULL) {
		mms_trace(MMS_ERR, "parse response failed");
		return (EINVAL);
	}

	if (*nvl == NULL) {
		(void) nvlist_alloc(nvl, NV_UNIQUE_NAME, 0);
	}
	lasts = NULL;

	while ((text = mms_pn_lookup(root, "text", MMS_PN_CLAUSE, &lasts))
	    != NULL) {
		if (*nvl == NULL) {
			(void) nvlist_alloc(nvl, NV_UNIQUE_NAME, 0);
		}

		alast = NULL;

		attrs = mms_pn_lookup_arg(text, NULL, NULL, &alast);
		if (!attrs) {
			break;
		}

		if (strcmp(attrs->pn_string, "attrlist") != 0) {
			/*
			 * Not attrlist - construct nvlist with args.
			 */
			st = attrs2nvlist(text, useropt, &lst);
		} else {
			while (attrs != NULL) {
				st = attrs2nvlist(attrs, useropt, &lst);
				if (st != 0) {
					break;
				}
				attrs = mms_pn_lookup_arg(text, NULL, NULL,
				    &alast);
			}
		}

		if (st == 0) {
			st = nvlist_lookup_string(lst, key, &val);
			if (st != 0) {
				(void) snprintf(buf, sizeof (buf),
				    "unknown_%d", ++lcnt);
				val = buf;
			}
			st = nvlist_add_nvlist(*nvl, val, lst);
		}
		if (st != 0) {
			break;
		}

	}

	return (st);
}

/*
 * Gether attribute values into an array
 */
int
mmp_get_nvattrs_array(char *key, boolean_t useropt,
    void *response, nvlist_t *nvl)
{
	int		st = 0;
	mms_par_node_t	*lasts = NULL;
	mms_par_node_t	*lasta = NULL;
	mms_par_node_t	*root;
	mms_par_node_t	*text;
	mms_par_node_t	*attrs;
	mms_par_node_t	*val;
	uint_t		count = 0;
	char		**arr;
	int		i;
	char		*mmpkey = key;

	if (!key|| !response || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_DEBUG, "Response: %s",
	    ((mms_rsp_ele_t *)response)->mms_rsp_str);

	root = mms_get_tree(response);
	if (root == NULL) {
		mms_trace(MMS_ERR, "parse response failed");
		return (EINVAL);
	}

	lasts = NULL;
	if (useropt) {
		mmpkey = mgmt_cvt_user_to_mmp(key);
		if (mmpkey == NULL) {
			return (EINVAL);
		}
	}

	/* Count how many we have */
	while ((text = mms_pn_lookup_arg(root, "text", MMS_PN_CLAUSE, &lasts))
	    != NULL) {
		attrs = mms_pn_lookup(text, mmpkey, MMS_PN_STRING, NULL);
		if (attrs != NULL) {
			count++;
		}
	}

	arr = (char **)calloc(1, sizeof (uint_t *) * count);
	if (arr == NULL) {
		return (ENOMEM);
	}

	lasts =  NULL;
	for (i = 0; i < count; i++) {
		text = mms_pn_lookup_arg(root, "text", MMS_PN_CLAUSE, &lasts);
		attrs = mms_pn_lookup(text, mmpkey, MMS_PN_STRING, &lasta);
		val = mms_pn_lookup(attrs, NULL, MMS_PN_STRING, &lasta);
		arr[i] = strdup(mms_pn_token(val));
	}

	st = nvlist_add_string_array(nvl, key, arr, count);

	return (st);
}

/*
 *  If useropt = B_TRUE, convert the MMP keys to public keys
 */
static int
attrs2nvlist(mms_par_node_t *attrs, boolean_t useropt, nvlist_t **nvl)
{
	int		st;
	nvlist_t	*lst = NULL;
	mms_par_node_t	*name;
	mms_par_node_t	*val;
	mms_par_node_t	*last = NULL;
	char		*namep;
	char		*valp;

	if (!attrs || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	*nvl = NULL;
	st = nvlist_alloc(&lst, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		return (st);
	}

	for (;;) {
		name = mms_pn_lookup(attrs, "", MMS_PN_STRING, &last);
		if (!name) {
			break;
		}

		namep = mms_pn_token(name);
		val = mms_pn_lookup(name, "", MMS_PN_STRING, &last);
		if (!val) {
			continue;
		}

		valp = mms_pn_token(val);
		if ((valp) && (*valp != '\0')) {
			if (useropt) {
				namep = mgmt_cvt_mmp_to_user(namep);
			}
			if (namep) {
				(void) nvlist_add_string(lst, namep, valp);
			}
		}
	}

	*nvl = lst;

	return (st);
}

static char *
mgmt_cvt_mmp_to_user(char *in)
{
	int	i;
	char	*out = NULL;

	if (!in) {
		return (NULL);
	}

	for (i = 0; optmap[i].mmp_opt != NULL; i++) {
		if (strcmp(optmap[i].mmp_opt, in) == 0) {
			out = optmap[i].public_opt;
			break;
		}
	}

	return (out);
}

static char *
mgmt_cvt_user_to_mmp(char *in)
{
	int	size = sizeof (optmap) / sizeof (map_opt_names);
	int	i;
	char	*out = NULL;

	if (!in) {
		return (NULL);
	}

	for (i = 0; i < size; i++) {
		if (optmap[i].public_opt != NULL) {
			if (strcmp(optmap[i].public_opt, in) == 0) {
				out = optmap[i].mmp_opt;
				break;
			}
		}
	}

	return (out);
}

int
mms_mgmt_mmp_count(void *response, uint32_t *count)
{
	mms_par_node_t	*root;
	mms_par_node_t	*clause;
	mms_par_node_t	*num;

	if (!response || !count) {
		return (MMS_MGMT_NOARG);
	}

	*count = 0;

	mms_trace(MMS_DEBUG, "Response: %s",
	    ((mms_rsp_ele_t *)response)->mms_rsp_str);

	root = mms_get_tree(response);
	if (root == NULL) {
		mms_trace(MMS_ERR, "parse response failed");
		return (EINVAL);
	}

	MMS_PN_LOOKUP(clause, root, "text", MMS_PN_CLAUSE, NULL);
	MMS_PN_LOOKUP(num, clause, NULL, MMS_PN_STRING, NULL);

	*count = atoi(mms_pn_token(num));

	return (0);

not_found:
	/* this label required for the MMS_PN_LOOKUP macro */

	return (1);
}
