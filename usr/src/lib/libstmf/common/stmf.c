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

#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libintl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <libnvpair.h>
#include <pthread.h>
#include <syslog.h>
#include <libstmf.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <store.h>
#include <locale.h>
#include <sys/stmf_ioctl.h>

#define	STMF_PATH    "/devices/pseudo/stmf@0:admin"

#define	EUI "eui."
#define	WWN "wwn."
#define	IQN "iqn."
#define	WWN_ASCII_SIZE 16
#define	IDENT_LENGTH_BYTE 3

#define	MAX_LU		2<<16 - 1
#define	MAX_TARGET_PORT	1024
#define	MAX_PROVIDER	1024
#define	MAX_GROUP	1024
#define	MAX_SESSION	1024
#define	MAX_ISCSI_NAME	223

#define	OPEN_STMF 0
#define	OPEN_EXCL_STMF O_EXCL

#define	LOGICAL_UNIT_TYPE 0
#define	TARGET_TYPE 1
#define	STMF_SERVICE_TYPE 2

static int openStmf(int, int *fd);
static int groupIoctl(int fd, int cmd, stmfGroupName *);
static int loadStore(int fd);
static int initializeConfig();
static int groupMemberIoctl(int fd, int cmd, stmfGroupName *, stmfDevid *);
static int guidCompare(const void *, const void *);
static int addViewEntryIoctl(int fd, stmfGuid *, stmfViewEntry *);
static int loadHostGroups(int fd, stmfGroupList *);
static int loadTargetGroups(int fd, stmfGroupList *);
static int getStmfState(stmf_state_desc_t *);
static int setStmfState(int fd, stmf_state_desc_t *, int);
static int setProviderData(int fd, char *, nvlist_t *, int);

/*
 * Open for stmf module
 *
 * flag - open flag (OPEN_STMF, OPEN_EXCL_STMF)
 * fd - pointer to integer. On success, contains the stmf file descriptor
 */
static int
openStmf(int flag, int *fd)
{
	int ret = STMF_STATUS_ERROR;

	if ((*fd = open(STMF_PATH, O_NDELAY | O_RDONLY | flag)) != -1) {
		ret = STMF_STATUS_SUCCESS;
	} else {
		if (errno == EBUSY) {
			ret = STMF_ERROR_BUSY;
		} else {
			ret = STMF_STATUS_ERROR;
		}
		syslog(LOG_DEBUG, "openStmf:open failure:%s:errno(%d)",
		    STMF_PATH, errno);
	}

	return (ret);
}

/*
 * initializeConfig
 *
 * This routine should be called before any ioctl requiring initialization
 * which is basically everything except stmfGetState(), setStmfState() and
 * stmfLoadConfig().
 */
static int
initializeConfig()
{
	int ret;
	stmfState state;


	ret = stmfGetState(&state);
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/* if we've already initialized or in the process, return success */
	if (state.configState == STMF_CONFIG_STATE_INIT_DONE ||
	    state.configState == STMF_CONFIG_STATE_INIT) {
		return (STMF_STATUS_SUCCESS);
	}

	ret = stmfLoadConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		syslog(LOG_DEBUG,
		    "initializeConfig:stmfLoadConfig:error(%d)", ret);
		return (ret);
	}

	ret = stmfGetState(&state);
	if (ret != STMF_STATUS_SUCCESS) {
		syslog(LOG_DEBUG,
		    "initializeConfig:stmfGetState:error(%d)", ret);
		return (ret);
	}

	if (state.configState != STMF_CONFIG_STATE_INIT_DONE) {
		syslog(LOG_DEBUG, "initializeConfig:state.configState(%d)",
		    state.configState);
		ret = STMF_STATUS_ERROR;
	}

	return (ret);
}


/*
 * groupIoctl
 *
 * Purpose: issue ioctl for create/delete on group
 *
 * cmd - valid STMF ioctl group cmd
 * groupName - groupName to create or delete
 */
static int
groupIoctl(int fd, int cmd, stmfGroupName *groupName)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	stmf_iocdata_t stmfIoctl;
	stmf_group_name_t iGroupName;

	bzero(&iGroupName, sizeof (iGroupName));

	bcopy(groupName, &iGroupName.name, strlen((char *)groupName));

	iGroupName.name_size = strlen((char *)groupName);

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to create the host group
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (iGroupName);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&iGroupName;
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				switch (stmfIoctl.stmf_error) {
					case STMF_IOCERR_TG_EXISTS:
					case STMF_IOCERR_HG_EXISTS:
						ret = STMF_ERROR_EXISTS;
						break;
					case STMF_IOCERR_TG_IN_USE:
					case STMF_IOCERR_HG_IN_USE:
						ret = STMF_ERROR_GROUP_IN_USE;
						break;
					case STMF_IOCERR_INVALID_HG:
					case STMF_IOCERR_INVALID_TG:
						ret = STMF_ERROR_NOT_FOUND;
						break;
					default:
						syslog(LOG_DEBUG,
						    "groupIoctl:error(%d)",
						    stmfIoctl.stmf_error);
						ret = STMF_STATUS_ERROR;
						break;
				}
				break;
		}
	}
done:
	return (ret);
}

/*
 * groupIoctl
 *
 * Purpose: issue ioctl for add/remove member on group
 *
 * cmd - valid STMF ioctl group member cmd
 * groupName - groupName to add to or remove from
 * devid - group member to add or remove
 */
static int
groupMemberIoctl(int fd, int cmd, stmfGroupName *groupName, stmfDevid *devid)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	stmf_iocdata_t stmfIoctl;
	stmf_group_op_data_t stmfGroupData;

	bzero(&stmfGroupData, sizeof (stmfGroupData));

	bcopy(groupName, &stmfGroupData.group.name, strlen((char *)groupName));

	stmfGroupData.group.name_size = strlen((char *)groupName);
	stmfGroupData.ident[IDENT_LENGTH_BYTE] = devid->identLength;
	bcopy(&(devid->ident), &stmfGroupData.ident[IDENT_LENGTH_BYTE + 1],
	    devid->identLength);

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to add to the host group
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (stmfGroupData);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&stmfGroupData;
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				switch (stmfIoctl.stmf_error) {
					case STMF_IOCERR_TG_ENTRY_EXISTS:
					case STMF_IOCERR_HG_ENTRY_EXISTS:
						ret = STMF_ERROR_EXISTS;
						break;
					case STMF_IOCERR_INVALID_TG_ENTRY:
					case STMF_IOCERR_INVALID_HG_ENTRY:
						ret =
						    STMF_ERROR_MEMBER_NOT_FOUND;
						break;
					case STMF_IOCERR_INVALID_TG:
					case STMF_IOCERR_INVALID_HG:
						ret =
						    STMF_ERROR_GROUP_NOT_FOUND;
						break;
					default:
						syslog(LOG_DEBUG,
						    "groupMemberIoctl:error"
						    "(%d)",
						    stmfIoctl.stmf_error);
						ret = STMF_STATUS_ERROR;
						break;
				}
				break;
		}
	}
done:
	return (ret);
}

/*
 * guidCompare
 *
 * qsort function
 * sort on guid
 */
static int
guidCompare(const void *p1, const void *p2)
{

	stmfGuid *g1 = (stmfGuid *)p1, *g2 = (stmfGuid *)p2;
	int i;

	for (i = 0; i < sizeof (stmfGuid); i++) {
		if (g1->guid[i] > g2->guid[i])
			return (1);
		if (g1->guid[i] < g2->guid[i])
			return (-1);
	}

	return (0);
}

/*
 * stmfAddToHostGroup
 *
 * Purpose: Adds an initiator to an existing host group
 *
 * hostGroupName - name of an existing host group
 * hostName - name of initiator to add
 */
int
stmfAddToHostGroup(stmfGroupName *hostGroupName, stmfDevid *hostName)
{
	int ret;
	int fd;

	if (hostGroupName == NULL ||
	    (strnlen((char *)hostGroupName, sizeof (stmfGroupName))
	    == sizeof (stmfGroupName)) || hostName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	if ((ret = groupMemberIoctl(fd, STMF_IOCTL_ADD_HG_ENTRY, hostGroupName,
	    hostName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	ret = psAddHostGroupMember((char *)hostGroupName,
	    (char *)hostName->ident);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_EXISTS:
			ret = STMF_ERROR_EXISTS;
			break;
		case STMF_PS_ERROR_GROUP_NOT_FOUND:
			ret = STMF_ERROR_GROUP_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfAddToHostGroup:psAddHostGroupMember:error(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfAddToTargetGroup
 *
 * Purpose: Adds a local port to an existing target group
 *
 * targetGroupName - name of an existing target group
 * targetName - name of target to add
 */
int
stmfAddToTargetGroup(stmfGroupName *targetGroupName, stmfDevid *targetName)
{
	int ret;
	int fd;
	stmfState state;

	if (targetGroupName == NULL ||
	    (strnlen((char *)targetGroupName, sizeof (stmfGroupName))
	    == sizeof (stmfGroupName)) || targetName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = stmfGetState(&state);
	if (ret == STMF_STATUS_SUCCESS) {
		if (state.operationalState != STMF_SERVICE_STATE_OFFLINE) {
			return (STMF_ERROR_SERVICE_ONLINE);
		}
	} else {
		return (STMF_STATUS_ERROR);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	if ((ret = groupMemberIoctl(fd, STMF_IOCTL_ADD_TG_ENTRY,
	    targetGroupName, targetName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	ret = psAddTargetGroupMember((char *)targetGroupName,
	    (char *)targetName->ident);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_EXISTS:
			ret = STMF_ERROR_EXISTS;
			break;
		case STMF_PS_ERROR_GROUP_NOT_FOUND:
			ret = STMF_ERROR_GROUP_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfAddToTargetGroup:psAddTargetGroupMember:"
			    "error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * addViewEntryIoctl
 *
 * Purpose: Issues ioctl to add a view entry
 *
 * lu - Logical Unit identifier to which the view entry is added
 * viewEntry - view entry to add
 * init - When set to B_TRUE, we are in the init state, i.e. don't call open
 */
static int
addViewEntryIoctl(int fd, stmfGuid *lu, stmfViewEntry *viewEntry)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	stmf_iocdata_t stmfIoctl;
	stmf_view_op_entry_t ioctlViewEntry;

	bzero(&ioctlViewEntry, sizeof (ioctlViewEntry));
	/*
	 * don't set ve_ndx or ve_ndx_valid as ve_ndx_valid should be
	 * false on input
	 */
	ioctlViewEntry.ve_lu_number_valid = viewEntry->luNbrValid;
	ioctlViewEntry.ve_all_hosts = viewEntry->allHosts;
	ioctlViewEntry.ve_all_targets = viewEntry->allTargets;

	if (viewEntry->allHosts == B_FALSE) {
		bcopy(viewEntry->hostGroup, &ioctlViewEntry.ve_host_group.name,
		    sizeof (stmfGroupName));
		ioctlViewEntry.ve_host_group.name_size =
		    strlen((char *)viewEntry->hostGroup);
	}
	if (viewEntry->allTargets == B_FALSE) {
		bcopy(viewEntry->targetGroup,
		    &ioctlViewEntry.ve_target_group.name,
		    sizeof (stmfGroupName));
		ioctlViewEntry.ve_target_group.name_size =
		    strlen((char *)viewEntry->targetGroup);
	}
	if (viewEntry->luNbrValid) {
		bcopy(viewEntry->luNbr, &ioctlViewEntry.ve_lu_nbr,
		    sizeof (ioctlViewEntry.ve_lu_nbr));
	}
	bcopy(lu, &ioctlViewEntry.ve_guid, sizeof (stmfGuid));

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to add to the view entry
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (ioctlViewEntry);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&ioctlViewEntry;
	stmfIoctl.stmf_obuf_size = sizeof (ioctlViewEntry);
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)&ioctlViewEntry;
	ioctlRet = ioctl(fd, STMF_IOCTL_ADD_VIEW_ENTRY, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				switch (stmfIoctl.stmf_error) {
					case STMF_IOCERR_UPDATE_NEED_CFG_INIT:
						ret = STMF_ERROR_CONFIG_NONE;
						break;
					default:
						ret = STMF_ERROR_PERM;
						break;
				}
				break;
			default:
				switch (stmfIoctl.stmf_error) {
					case STMF_IOCERR_LU_NUMBER_IN_USE:
						ret = STMF_ERROR_LUN_IN_USE;
						break;
					case STMF_IOCERR_VIEW_ENTRY_CONFLICT:
						ret = STMF_ERROR_VE_CONFLICT;
						break;
					case STMF_IOCERR_UPDATE_NEED_CFG_INIT:
						ret = STMF_ERROR_CONFIG_NONE;
						break;
					case STMF_IOCERR_INVALID_HG:
						ret = STMF_ERROR_INVALID_HG;
						break;
					case STMF_IOCERR_INVALID_TG:
						ret = STMF_ERROR_INVALID_TG;
						break;
					default:
						syslog(LOG_DEBUG,
						    "addViewEntryIoctl"
						    ":error(%d)",
						    stmfIoctl.stmf_error);
						ret = STMF_STATUS_ERROR;
						break;
				}
				break;
		}
		goto done;
	}

	/* copy lu nbr back to caller's view entry on success */
	viewEntry->veIndex = ioctlViewEntry.ve_ndx;
	if (ioctlViewEntry.ve_lu_number_valid) {
		bcopy(&ioctlViewEntry.ve_lu_nbr, viewEntry->luNbr,
		    sizeof (ioctlViewEntry.ve_lu_nbr));
	}
	viewEntry->luNbrValid = B_TRUE;

done:
	return (ret);
}

/*
 * stmfAddViewEntry
 *
 * Purpose: Adds a view entry to a logical unit
 *
 * lu - guid of the logical unit to which the view entry is added
 * viewEntry - view entry structure to add
 */
int
stmfAddViewEntry(stmfGuid *lu, stmfViewEntry *viewEntry)
{
	int ret;
	int fd;
	stmfViewEntry iViewEntry;

	if (lu == NULL || viewEntry == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* initialize and set internal view entry */
	bzero(&iViewEntry, sizeof (iViewEntry));

	if (!viewEntry->allHosts) {
		bcopy(viewEntry->hostGroup, iViewEntry.hostGroup,
		    sizeof (iViewEntry.hostGroup));
	} else {
		iViewEntry.allHosts = B_TRUE;
	}

	if (!viewEntry->allTargets) {
		bcopy(viewEntry->targetGroup, iViewEntry.targetGroup,
		    sizeof (iViewEntry.targetGroup));
	} else {
		iViewEntry.allTargets = B_TRUE;
	}

	if (viewEntry->luNbrValid) {
		iViewEntry.luNbrValid = B_TRUE;
		bcopy(viewEntry->luNbr, iViewEntry.luNbr,
		    sizeof (iViewEntry.luNbr));
	}

	/*
	 * set users return view entry index valid flag to false
	 * in case of failure
	 */
	viewEntry->veIndexValid = B_FALSE;

	/* Check to ensure service exists */
	if (psCheckService() != STMF_STATUS_SUCCESS) {
		return (STMF_ERROR_SERVICE_NOT_FOUND);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * First add the view entry to the driver
	 */
	ret = addViewEntryIoctl(fd, lu, &iViewEntry);
	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/*
	 * If the add to driver was successful, add it to the persistent
	 * store.
	 */
	ret = psAddViewEntry(lu, &iViewEntry);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfAddViewEntry:psAddViewEntry:error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);

	if (ret == STMF_STATUS_SUCCESS) {
		/* set caller's view entry on success */
		viewEntry->veIndexValid = iViewEntry.veIndexValid;
		viewEntry->veIndex = iViewEntry.veIndex;
		viewEntry->luNbrValid = B_TRUE;
		bcopy(iViewEntry.luNbr, viewEntry->luNbr,
		    sizeof (iViewEntry.luNbr));
	}
	return (ret);
}

/*
 * stmfClearProviderData
 *
 * Purpose: delete all provider data for specified provider
 *
 * providerName - name of provider for which data should be deleted
 */
int
stmfClearProviderData(char *providerName, int providerType)
{
	int ret;
	int fd;
	int ioctlRet;
	int savedErrno;
	stmf_iocdata_t stmfIoctl;
	stmf_ppioctl_data_t ppi;

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	if (providerName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (providerType != STMF_LU_PROVIDER_TYPE &&
	    providerType != STMF_PORT_PROVIDER_TYPE) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	bzero(&ppi, sizeof (ppi));

	(void) strncpy(ppi.ppi_name, providerName, sizeof (ppi.ppi_name));

	switch (providerType) {
		case STMF_LU_PROVIDER_TYPE:
			ppi.ppi_lu_provider = 1;
			break;
		case STMF_PORT_PROVIDER_TYPE:
			ppi.ppi_port_provider = 1;
			break;
		default:
			ret = STMF_ERROR_INVALID_ARG;
			goto done;
	}

	bzero(&stmfIoctl, sizeof (stmfIoctl));

	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (stmf_ppioctl_data_t);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&ppi;

	ioctlRet = ioctl(fd, STMF_IOCTL_CLEAR_PP_DATA, &stmfIoctl);
	if (ioctlRet != 0) {
		savedErrno = errno;
		switch (savedErrno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				syslog(LOG_DEBUG,
				    "stmfClearProviderData:ioctl error(%d)",
				    ioctlRet);
				ret = STMF_STATUS_ERROR;
				break;
		}
		if (savedErrno != ENOENT) {
			goto done;
		}
	}

	ret = psClearProviderData(providerName, providerType);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfClearProviderData:psClearProviderData"
			    ":error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfCreateHostGroup
 *
 * Purpose: Create a new initiator group
 *
 * hostGroupName - name of host group to create
 */
int
stmfCreateHostGroup(stmfGroupName *hostGroupName)
{
	int ret;
	int fd;

	if (hostGroupName == NULL ||
	    (strnlen((char *)hostGroupName, sizeof (stmfGroupName))
	    == sizeof (stmfGroupName))) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* Check to ensure service exists */
	if (psCheckService() != STMF_STATUS_SUCCESS) {
		return (STMF_ERROR_SERVICE_NOT_FOUND);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	if ((ret = groupIoctl(fd, STMF_IOCTL_CREATE_HOST_GROUP,
	    hostGroupName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	ret = psCreateHostGroup((char *)hostGroupName);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_EXISTS:
			ret = STMF_ERROR_EXISTS;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfCreateHostGroup:psCreateHostGroup:error(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfCreateTargetGroup
 *
 * Purpose: Create a local port group
 *
 * targetGroupName - name of local port group to create
 */
int
stmfCreateTargetGroup(stmfGroupName *targetGroupName)
{
	int ret;
	int fd;

	if (targetGroupName == NULL ||
	    (strnlen((char *)targetGroupName, sizeof (stmfGroupName))
	    == sizeof (stmfGroupName))) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* Check to ensure service exists */
	if (psCheckService() != STMF_STATUS_SUCCESS) {
		return (STMF_ERROR_SERVICE_NOT_FOUND);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * Add the group to the driver
	 */
	if ((ret = groupIoctl(fd, STMF_IOCTL_CREATE_TARGET_GROUP,
	    targetGroupName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/*
	 * If the add to the driver was successful, add it to the persistent
	 * store.
	 */
	ret = psCreateTargetGroup((char *)targetGroupName);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_EXISTS:
			ret = STMF_ERROR_EXISTS;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfCreateTargetGroup:psCreateTargetGroup"
			    ":error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfDeleteHostGroup
 *
 * Purpose: Delete an initiator or local port group
 *
 * hostGroupName - group to delete
 */
int
stmfDeleteHostGroup(stmfGroupName *hostGroupName)
{
	int ret;
	int fd;

	if (hostGroupName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* Check to ensure service exists */
	if (psCheckService() != STMF_STATUS_SUCCESS) {
		return (STMF_ERROR_SERVICE_NOT_FOUND);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * Remove the group from the driver
	 */
	if ((ret = groupIoctl(fd, STMF_IOCTL_REMOVE_HOST_GROUP,
	    hostGroupName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/*
	 * If the remove from the driver was successful, remove it from the
	 * persistent store.
	 */
	ret = psDeleteHostGroup((char *)hostGroupName);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfDeleteHostGroup:psDeleteHostGroup:error(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfDeleteTargetGroup
 *
 * Purpose: Delete an initiator or local port group
 *
 * targetGroupName - group to delete
 */
int
stmfDeleteTargetGroup(stmfGroupName *targetGroupName)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;

	if (targetGroupName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* Check to ensure service exists */
	if (psCheckService() != STMF_STATUS_SUCCESS) {
		return (STMF_ERROR_SERVICE_NOT_FOUND);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * Remove the group from the driver
	 */
	if ((ret = groupIoctl(fd, STMF_IOCTL_REMOVE_TARGET_GROUP,
	    targetGroupName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/*
	 * If the remove from the driver was successful, remove it from the
	 * persistent store.
	 */
	ret = psDeleteTargetGroup((char *)targetGroupName);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfDeleteTargetGroup:psDeleteTargetGroup"
			    ":error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfDevidFromIscsiName
 *
 * Purpose: convert an iSCSI name to an stmf devid
 *
 * iscsiName - unicode nul terminated utf-8 encoded iSCSI name
 * devid - on success, contains the converted iscsi name
 */
int
stmfDevidFromIscsiName(char *iscsiName, stmfDevid *devid)
{
	if (devid == NULL || iscsiName == NULL)
		return (STMF_ERROR_INVALID_ARG);

	bzero(devid, sizeof (stmfDevid));

	/* Validate size of target */
	if ((devid->identLength = strlen(iscsiName)) > MAX_ISCSI_NAME ||
	    devid->identLength < strlen(EUI) ||
	    devid->identLength < strlen(IQN)) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if ((strncmp(iscsiName, EUI, strlen(EUI)) != 0) &&
	    strncmp(iscsiName, IQN, strlen(IQN)) != 0) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* copy UTF-8 bytes to ident */
	bcopy(iscsiName, devid->ident, devid->identLength);

	return (STMF_STATUS_SUCCESS);
}

/*
 * stmfDevidFromWwn
 *
 * Purpose: convert a WWN to an stmf devid
 *
 * wwn - 8-byte wwn identifier
 * devid - on success, contains the converted wwn
 */
int
stmfDevidFromWwn(uchar_t *wwn, stmfDevid *devid)
{
	if (wwn == NULL || devid == NULL)
		return (STMF_ERROR_INVALID_ARG);

	bzero(devid, sizeof (stmfDevid));

	/* Copy eui prefix */
	(void) bcopy(WWN, devid->ident, strlen(WWN));

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf((char *)&devid->ident[strlen(WWN)],
	    sizeof (devid->ident), "%02X%02X%02X%02X%02X%02X%02X%02X",
	    wwn[0], wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

	devid->identLength = strlen((char *)devid->ident);

	return (STMF_STATUS_SUCCESS);
}

/*
 * stmfFreeMemory
 *
 * Purpose: Free memory allocated by this library
 *
 * memory - previously allocated pointer of memory managed by library
 */
void
stmfFreeMemory(void *memory)
{
	free(memory);
}

/*
 * stmfGetHostGroupList
 *
 * Purpose: Retrieves the list of initiator group oids
 *
 * hostGroupList - pointer to pointer to hostGroupList structure
 *                 on success, this contains the host group list.
 */
int
stmfGetHostGroupList(stmfGroupList **hostGroupList)
{
	int ret;

	if (hostGroupList == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = psGetHostGroupList(hostGroupList);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfGetHostGroupList:psGetHostGroupList:error(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

	return (ret);
}

/*
 * stmfGetHostGroupMembers
 *
 * Purpose: Retrieves the group properties for a host group
 *
 * groupName - name of group for which to retrieve host group members.
 * groupProp - pointer to pointer to stmfGroupProperties structure
 *             on success, this contains the list of group members.
 */
int
stmfGetHostGroupMembers(stmfGroupName *groupName,
    stmfGroupProperties **groupProp)
{
	int ret;

	if (groupName == NULL || groupProp == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = psGetHostGroupMemberList((char *)groupName, groupProp);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfGetHostGroupMembers:psGetHostGroupMembers"
			    ":error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

	return (ret);
}

/*
 * stmfGetProviderData
 *
 * Purpose: Get provider data list
 *
 * providerName - name of provider for which to retrieve the data
 * nvl - pointer to nvlist_t pointer which will contain the nvlist data
 *       retrieved.
 * providerType - type of provider for which to retrieve data.
 *		    STMF_LU_PROVIDER_TYPE
 *		    STMF_PORT_PROVIDER_TYPE
 */
int
stmfGetProviderData(char *providerName, nvlist_t **nvl, int providerType)
{
	return (stmfGetProviderDataProt(providerName, nvl, providerType,
	    NULL));
}

/*
 * stmfGetProviderDataProt
 *
 * Purpose: Get provider data list with token
 *
 * providerName - name of provider for which to retrieve the data
 * nvl - pointer to nvlist_t pointer which will contain the nvlist data
 *       retrieved.
 * providerType - type of provider for which to retrieve data.
 *		    STMF_LU_PROVIDER_TYPE
 *		    STMF_PORT_PROVIDER_TYPE
 * setToken - Returns the stale data token
 */
int
stmfGetProviderDataProt(char *providerName, nvlist_t **nvl, int providerType,
    uint64_t *setToken)
{
	int ret;

	if (providerName == NULL || nvl == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (providerType != STMF_LU_PROVIDER_TYPE &&
	    providerType != STMF_PORT_PROVIDER_TYPE) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	ret = psGetProviderData(providerName, nvl, providerType, setToken);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfGetProviderData:psGetProviderData:error(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

	return (ret);
}

/*
 * stmfGetProviderDataList
 *
 * Purpose: Get the list of providers currently persisting data
 *
 * providerList - pointer to pointer to an stmfProviderList structure allocated
 *                by the caller. Will contain the list of providers on success.
 */
int
stmfGetProviderDataList(stmfProviderList **providerList)
{
	int ret;

	ret = psGetProviderDataList(providerList);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfGetProviderDataList:psGetProviderDataList"
			    ":error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

	return (ret);
}


/*
 * stmfGetSessionList
 *
 * Purpose: Retrieves the session list for a target (devid)
 *
 * devid - devid of target for which to retrieve session information.
 * sessionList - pointer to pointer to stmfSessionList structure
 *             on success, this contains the list of initiator sessions.
 */
int
stmfGetSessionList(stmfDevid *devid, stmfSessionList **sessionList)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	int ioctlRet;
	int cmd = STMF_IOCTL_SESSION_LIST;
	int i;
	stmf_iocdata_t stmfIoctl;
	slist_scsi_session_t *fSessionList;
	uint8_t ident[260];
	uint32_t fSessionListSize;

	if (sessionList == NULL || devid == NULL) {
		ret = STMF_ERROR_INVALID_ARG;
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * Allocate ioctl input buffer
	 */
	fSessionListSize = MAX_SESSION;
	fSessionListSize = fSessionListSize * (sizeof (slist_scsi_session_t));
	fSessionList = (slist_scsi_session_t *)calloc(1, fSessionListSize);
	if (fSessionList == NULL) {
		return (STMF_ERROR_NOMEM);
	}

	ident[IDENT_LENGTH_BYTE] = devid->identLength;
	bcopy(&(devid->ident), &ident[IDENT_LENGTH_BYTE + 1],
	    devid->identLength);

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to get the session list
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&ident;
	stmfIoctl.stmf_ibuf_size = sizeof (ident);
	stmfIoctl.stmf_obuf_size = fSessionListSize;
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fSessionList;
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				syslog(LOG_DEBUG,
				    "stmfGetSessionList:ioctl errno(%d)",
				    errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}
	/*
	 * Check whether input buffer was large enough
	 */
	if (stmfIoctl.stmf_obuf_max_nentries > MAX_SESSION) {
		fSessionListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (slist_scsi_session_t);
		fSessionList = realloc(fSessionList, fSessionListSize);
		if (fSessionList == NULL) {
			return (STMF_ERROR_NOMEM);
		}
		stmfIoctl.stmf_obuf_size = fSessionListSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fSessionList;
		ioctlRet = ioctl(fd, cmd, &stmfIoctl);
		if (ioctlRet != 0) {
			switch (errno) {
				case EBUSY:
					ret = STMF_ERROR_BUSY;
					break;
				case EACCES:
					ret = STMF_ERROR_PERM;
					break;
				default:
					syslog(LOG_DEBUG,
					    "stmfGetSessionList:ioctl "
					    "errno(%d)", errno);
					ret = STMF_STATUS_ERROR;
					break;
			}
			goto done;
		}
	}

	/*
	 * allocate caller's buffer with the final size
	 */
	*sessionList = (stmfSessionList *)calloc(1, sizeof (stmfSessionList) +
	    stmfIoctl.stmf_obuf_max_nentries * sizeof (stmfSession));
	if (*sessionList == NULL) {
		ret = STMF_ERROR_NOMEM;
		free(sessionList);
		goto done;
	}

	(*sessionList)->cnt = stmfIoctl.stmf_obuf_max_nentries;

	/*
	 * copy session info to caller's buffer
	 */
	for (i = 0; i < (*sessionList)->cnt; i++) {
		(*sessionList)->session[i].initiator.identLength =
		    fSessionList->initiator[IDENT_LENGTH_BYTE];
		bcopy(&(fSessionList->initiator[IDENT_LENGTH_BYTE + 1]),
		    (*sessionList)->session[i].initiator.ident,
		    STMF_IDENT_LENGTH);
		bcopy(&(fSessionList->alias),
		    &((*sessionList)->session[i].alias),
		    sizeof ((*sessionList)->session[i].alias));
		bcopy(&(fSessionList++->creation_time),
		    &((*sessionList)->session[i].creationTime),
		    sizeof (time_t));
	}
done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfGetTargetGroupList
 *
 * Purpose: Retrieves the list of target groups
 *
 * targetGroupList - pointer to a pointer to an stmfGroupList structure. On
 *		     success, it contains the list of target groups.
 */
int
stmfGetTargetGroupList(stmfGroupList **targetGroupList)
{
	int ret;

	if (targetGroupList == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = psGetTargetGroupList(targetGroupList);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfGetTargetGroupList:psGetTargetGroupList:"
			    "error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

	return (ret);
}

/*
 * stmfGetTargetGroupMembers
 *
 * Purpose: Retrieves the group members for a target group
 *
 * groupName - name of target group for which to retrieve members.
 * groupProp - pointer to pointer to stmfGroupProperties structure
 *             on success, this contains the list of group members.
 */
int
stmfGetTargetGroupMembers(stmfGroupName *groupName,
    stmfGroupProperties **groupProp)
{
	int ret;

	if (groupName == NULL || groupProp == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = psGetTargetGroupMemberList((char *)groupName, groupProp);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfGetTargetGroupMembers:psGetTargetGroupMembers:"
			    "error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

	return (ret);
}

/*
 * stmfGetTargetList
 *
 * Purpose: Retrieves the list of target ports
 *
 * targetList - pointer to a pointer to an stmfDevidList structure.
 *		    On success, it contains the list of local ports (target).
 */
int
stmfGetTargetList(stmfDevidList **targetList)
{
	int ret;
	int fd;
	int ioctlRet;
	int i;
	stmf_iocdata_t stmfIoctl;
	/* framework target port list */
	slist_target_port_t *fTargetList, *fTargetListP;
	uint32_t fTargetListSize;

	if (targetList == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * Allocate ioctl input buffer
	 */
	fTargetListSize = MAX_TARGET_PORT * sizeof (slist_target_port_t);
	fTargetListP = fTargetList =
	    (slist_target_port_t *)calloc(1, fTargetListSize);
	if (fTargetList == NULL) {
		goto done;
	}

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to retrieve target list
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_obuf_size = fTargetListSize;
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fTargetList;
	ioctlRet = ioctl(fd, STMF_IOCTL_TARGET_PORT_LIST, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				syslog(LOG_DEBUG,
				    "stmfGetTargetList:ioctl errno(%d)", errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}
	/*
	 * Check whether input buffer was large enough
	 */
	if (stmfIoctl.stmf_obuf_max_nentries > MAX_TARGET_PORT) {
		fTargetListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (slist_target_port_t);
		fTargetListP = fTargetList =
		    realloc(fTargetList, fTargetListSize);
		if (fTargetList == NULL) {
			return (STMF_ERROR_NOMEM);
		}
		stmfIoctl.stmf_obuf_size = fTargetListSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fTargetList;
		ioctlRet = ioctl(fd, STMF_IOCTL_TARGET_PORT_LIST,
		    &stmfIoctl);
		if (ioctlRet != 0) {
			switch (errno) {
				case EBUSY:
					ret = STMF_ERROR_BUSY;
					break;
				case EACCES:
					ret = STMF_ERROR_PERM;
					break;
				default:
					syslog(LOG_DEBUG,
					    "stmfGetTargetList:ioctl errno(%d)",
					    errno);
					ret = STMF_STATUS_ERROR;
					break;
			}
			goto done;
		}
	}

	*targetList = (stmfDevidList *)calloc(1,
	    stmfIoctl.stmf_obuf_max_nentries * sizeof (stmfDevid) +
	    sizeof (stmfDevidList));

	(*targetList)->cnt = stmfIoctl.stmf_obuf_max_nentries;
	for (i = 0; i < stmfIoctl.stmf_obuf_max_nentries; i++, fTargetList++) {
		(*targetList)->devid[i].identLength =
		    fTargetList->target[IDENT_LENGTH_BYTE];
		bcopy(&fTargetList->target[IDENT_LENGTH_BYTE + 1],
		    &(*targetList)->devid[i].ident,
		    fTargetList->target[IDENT_LENGTH_BYTE]);
	}

done:
	(void) close(fd);
	free(fTargetListP);
	return (ret);
}

/*
 * stmfGetTargetProperties
 *
 * Purpose:  Retrieves the properties for a logical unit
 *
 * devid - devid of the target for which to retrieve properties
 * targetProps - pointer to an stmfTargetProperties structure.
 *		On success, it contains the target properties for
 *		the specified devid.
 */
int
stmfGetTargetProperties(stmfDevid *devid, stmfTargetProperties *targetProps)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	int ioctlRet;
	stmf_iocdata_t stmfIoctl;
	sioc_target_port_props_t targetProperties;

	if (devid == NULL || targetProps == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	targetProperties.tgt_id[IDENT_LENGTH_BYTE] = devid->identLength;
	bcopy(&(devid->ident), &targetProperties.tgt_id[IDENT_LENGTH_BYTE + 1],
	    devid->identLength);

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to add to the host group
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (targetProperties.tgt_id);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&targetProperties.tgt_id;
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)&targetProperties;
	stmfIoctl.stmf_obuf_size = sizeof (targetProperties);
	ioctlRet = ioctl(fd, STMF_IOCTL_GET_TARGET_PORT_PROPERTIES,
	    &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			case ENOENT:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			default:
				syslog(LOG_DEBUG,
				    "stmfGetTargetProperties:ioctl errno(%d)",
				    errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}

	bcopy(targetProperties.tgt_provider_name, targetProps->providerName,
	    sizeof (targetProperties.tgt_provider_name));
	if (targetProperties.tgt_state == STMF_STATE_ONLINE) {
		targetProps->status = STMF_TARGET_PORT_ONLINE;
	} else if (targetProperties.tgt_state == STMF_STATE_OFFLINE) {
		targetProps->status = STMF_TARGET_PORT_OFFLINE;
	} else if (targetProperties.tgt_state == STMF_STATE_ONLINING) {
		targetProps->status = STMF_TARGET_PORT_ONLINING;
	} else if (targetProperties.tgt_state == STMF_STATE_OFFLINING) {
		targetProps->status = STMF_TARGET_PORT_OFFLINING;
	}
	bcopy(targetProperties.tgt_alias, targetProps->alias,
	    sizeof (targetProps->alias));
done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfGetLogicalUnitList
 *
 * Purpose: Retrieves list of logical unit Object IDs
 *
 * luList - pointer to a pointer to a stmfGuidList structure. On success,
 *          it contains the list of logical unit guids.
 *
 */
int
stmfGetLogicalUnitList(stmfGuidList **luList)
{
	int ret;
	int fd;
	int ioctlRet;
	int cmd = STMF_IOCTL_LU_LIST;
	int i, k;
	stmf_iocdata_t stmfIoctl;
	/* framework lu list */
	slist_lu_t *fLuList;
	/* persistent store lu list */
	stmfGuidList *sLuList = NULL;
	int finalListSize = 0;
	int newAllocSize;
	uint32_t fLuListSize;
	uint32_t endList;

	if (luList == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * Allocate ioctl input buffer
	 */
	fLuListSize = MAX_LU;
	fLuListSize = fLuListSize * (sizeof (slist_lu_t));
	fLuList = (slist_lu_t *)calloc(1, fLuListSize);
	if (fLuList == NULL) {
		return (STMF_ERROR_NOMEM);
	}

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to get the LU list
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_obuf_size = fLuListSize;
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fLuList;
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				syslog(LOG_DEBUG,
				    "stmfGetLogicalUnitList:ioctl errno(%d)",
				    errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}
	/*
	 * Check whether input buffer was large enough
	 */
	if (stmfIoctl.stmf_obuf_max_nentries > MAX_LU) {
		fLuListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (slist_lu_t);
		fLuList = realloc(fLuList, fLuListSize);
		if (fLuList == NULL) {
			return (STMF_ERROR_NOMEM);
		}
		stmfIoctl.stmf_obuf_size = fLuListSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fLuList;
		ioctlRet = ioctl(fd, cmd, &stmfIoctl);
		if (ioctlRet != 0) {
			switch (errno) {
				case EBUSY:
					ret = STMF_ERROR_BUSY;
					break;
				case EACCES:
					ret = STMF_ERROR_PERM;
					break;
				default:
					syslog(LOG_DEBUG,
					    "stmfGetLogicalUnitList:"
					    "ioctl errno(%d)", errno);
					ret = STMF_STATUS_ERROR;
					break;
			}
			goto done;
		}
	}

	ret = psGetLogicalUnitList(&sLuList);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfGetLogicalUnitList:psGetLogicalUnitList"
			    ":error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}
	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/*
	 * 2 lists must be merged
	 * reallocate the store list to add the list from the
	 * framework
	 */
	newAllocSize = sLuList->cnt * sizeof (stmfGuid) + sizeof (stmfGuidList)
	    + stmfIoctl.stmf_obuf_nentries * sizeof (stmfGuid);

	sLuList = realloc(sLuList, newAllocSize);
	if (sLuList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

	/*
	 * add list from ioctl. Start from end of list retrieved from store.
	 */
	endList = sLuList->cnt + stmfIoctl.stmf_obuf_nentries;
	for (k = 0, i = sLuList->cnt; i < endList; i++, k++) {
		bcopy(&fLuList[k].lu_guid, sLuList->guid[i].guid,
		    sizeof (stmfGuid));
	}
	sLuList->cnt = endList;

	/*
	 * sort the list for merging
	 */
	qsort((void *)&(sLuList->guid[0]), sLuList->cnt,
	    sizeof (stmfGuid), guidCompare);

	/*
	 * get final list count
	 */
	for (i = 0; i < sLuList->cnt; i++) {
		if ((i + 1) <= sLuList->cnt) {
			if (bcmp(sLuList->guid[i].guid, sLuList->guid[i+1].guid,
			    sizeof (stmfGuid)) == 0) {
				continue;
			}
		}
		finalListSize++;
	}

	/*
	 * allocate caller's buffer with the final size
	 */
	*luList = (stmfGuidList *)calloc(1, sizeof (stmfGuidList) +
	    finalListSize * sizeof (stmfGuid));
	if (*luList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

	/*
	 * copy guids to caller's buffer
	 */
	for (k = 0, i = 0; i < sLuList->cnt; i++) {
		if ((i + 1) <= sLuList->cnt) {
			if (bcmp(sLuList->guid[i].guid, sLuList->guid[i+1].guid,
			    sizeof (stmfGuid)) == 0) {
				continue;
			}
		}
		bcopy(&(sLuList->guid[i].guid), (*luList)->guid[k++].guid,
		    sizeof (stmfGuid));
	}

	(*luList)->cnt = finalListSize;

done:
	(void) close(fd);
	/*
	 * free internal buffers
	 */
	free(fLuList);
	free(sLuList);
	return (ret);
}

/*
 * stmfGetLogicalUnitProperties
 *
 * Purpose:  Retrieves the properties for a logical unit
 *
 * lu - guid of the logical unit for which to retrieve properties
 * stmfLuProps - pointer to an stmfLogicalUnitProperties structure. On success,
 *               it contains the logical unit properties for the specified guid.
 */
int
stmfGetLogicalUnitProperties(stmfGuid *lu, stmfLogicalUnitProperties *luProps)
{
	int ret = STMF_STATUS_SUCCESS;
	int stmfRet;
	int fd;
	int ioctlRet;
	int cmd = STMF_IOCTL_GET_LU_PROPERTIES;
	stmfViewEntryList *viewEntryList = NULL;
	stmf_iocdata_t stmfIoctl;
	sioc_lu_props_t fLuProps;

	if (luProps == NULL || luProps == NULL) {
		ret = STMF_ERROR_INVALID_ARG;
	}

	bzero(luProps, sizeof (stmfLogicalUnitProperties));

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to add to the host group
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (stmfGuid);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)lu;
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)&fLuProps;
	stmfIoctl.stmf_obuf_size = sizeof (fLuProps);
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			case ENOENT:
				stmfRet = stmfGetViewEntryList(lu,
				    &viewEntryList);
				if (stmfRet == STMF_STATUS_SUCCESS) {
					luProps->status =
					    STMF_LOGICAL_UNIT_UNREGISTERED;
					if (viewEntryList->cnt > 0) {
						ret = STMF_STATUS_SUCCESS;
					} else {
						ret = STMF_ERROR_NOT_FOUND;
					}
				} else {
					ret = STMF_ERROR_NOT_FOUND;
				}
				stmfFreeMemory(viewEntryList);
				break;
			default:
				syslog(LOG_DEBUG,
				    "stmfGetLogicalUnit:ioctl errno(%d)",
				    errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}

	bcopy(fLuProps.lu_provider_name, luProps->providerName,
	    sizeof (fLuProps.lu_provider_name));
	if (fLuProps.lu_state == STMF_STATE_ONLINE) {
		luProps->status = STMF_LOGICAL_UNIT_ONLINE;
	} else if (fLuProps.lu_state == STMF_STATE_OFFLINE) {
		luProps->status = STMF_LOGICAL_UNIT_OFFLINE;
	} else if (fLuProps.lu_state == STMF_STATE_ONLINING) {
		luProps->status = STMF_LOGICAL_UNIT_ONLINING;
	} else if (fLuProps.lu_state == STMF_STATE_OFFLINING) {
		luProps->status = STMF_LOGICAL_UNIT_OFFLINING;
	}
	bcopy(fLuProps.lu_alias, luProps->alias, sizeof (luProps->alias));
done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfGetState
 *
 * Purpose: retrieve the current state of the stmf module
 *
 * state - pointer to stmfState structure allocated by the caller
 *         On success, contains the state of stmf
 */
int
stmfGetState(stmfState *state)
{
	int ret;
	stmf_state_desc_t iState;

	if (state == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = getStmfState(&iState);
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}
	switch (iState.state) {
		case STMF_STATE_ONLINE:
			state->operationalState =
			    STMF_SERVICE_STATE_ONLINE;
			break;
		case STMF_STATE_OFFLINE:
			state->operationalState =
			    STMF_SERVICE_STATE_OFFLINE;
			break;
		case STMF_STATE_ONLINING:
			state->operationalState =
			    STMF_SERVICE_STATE_ONLINING;
			break;
		case STMF_STATE_OFFLINING:
			state->operationalState =
			    STMF_SERVICE_STATE_OFFLINING;
			break;
		default:
			state->operationalState =
			    STMF_SERVICE_STATE_UNKNOWN;
			break;
	}
	switch (iState.config_state) {
		case STMF_CONFIG_NONE:
			state->configState = STMF_CONFIG_STATE_NONE;
			break;
		case STMF_CONFIG_INIT:
			state->configState = STMF_CONFIG_STATE_INIT;
			break;
		case STMF_CONFIG_INIT_DONE:
			state->configState =
			    STMF_CONFIG_STATE_INIT_DONE;
			break;
		default:
			state->configState =
			    STMF_CONFIG_STATE_UNKNOWN;
			break;
	}
	return (STMF_STATUS_SUCCESS);
}

/*
 * stmfGetViewEntryList
 *
 * Purpose: Retrieves the list of view entries for the specified
 *          logical unit.
 *
 * lu - the guid of the logical unit for which to retrieve the view entry list
 * viewEntryList - a pointer to a pointer to a stmfViewEntryList structure. On
 *                 success, contains the list of view entries.
 */
int
stmfGetViewEntryList(stmfGuid *lu, stmfViewEntryList **viewEntryList)
{
	int ret;

	if (lu == NULL || viewEntryList == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = psGetViewEntryList(lu, viewEntryList);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfGetViewEntryList:error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

	return (ret);
}

/*
 * loadHostGroups
 *
 * Purpose - issues the ioctl to load the host groups into stmf
 *
 * fd - file descriptor for the control node of stmf.
 * groupList - populated host group list
 */
static int
loadHostGroups(int fd, stmfGroupList *groupList)
{
	int i, j;
	int ret = STMF_STATUS_SUCCESS;
	stmfGroupProperties *groupProps = NULL;

	for (i = 0; i < groupList->cnt; i++) {
		if ((ret = groupIoctl(fd, STMF_IOCTL_CREATE_HOST_GROUP,
		    &(groupList->name[i]))) != STMF_STATUS_SUCCESS) {
			goto out;
		}
		ret = stmfGetHostGroupMembers(&(groupList->name[i]),
		    &groupProps);
		for (j = 0; j < groupProps->cnt; j++) {
			if ((ret = groupMemberIoctl(fd, STMF_IOCTL_ADD_HG_ENTRY,
			    &(groupList->name[i]), &(groupProps->name[j])))
			    != STMF_STATUS_SUCCESS) {
				goto out;
			}
		}
	}


out:
	stmfFreeMemory(groupProps);
	return (ret);
}

/*
 * loadTargetGroups
 *
 * Purpose - issues the ioctl to load the target groups into stmf
 *
 * fd - file descriptor for the control node of stmf.
 * groupList - populated target group list.
 */
static int
loadTargetGroups(int fd, stmfGroupList *groupList)
{
	int i, j;
	int ret = STMF_STATUS_SUCCESS;
	stmfGroupProperties *groupProps = NULL;

	for (i = 0; i < groupList->cnt; i++) {
		if ((ret = groupIoctl(fd, STMF_IOCTL_CREATE_TARGET_GROUP,
		    &(groupList->name[i]))) != STMF_STATUS_SUCCESS) {
			goto out;
		}
		ret = stmfGetTargetGroupMembers(&(groupList->name[i]),
		    &groupProps);
		for (j = 0; j < groupProps->cnt; j++) {
			if ((ret = groupMemberIoctl(fd, STMF_IOCTL_ADD_TG_ENTRY,
			    &(groupList->name[i]), &(groupProps->name[j])))
			    != STMF_STATUS_SUCCESS) {
				goto out;
			}
		}
	}


out:
	stmfFreeMemory(groupProps);
	return (ret);
}


/*
 * loadStore
 *
 * Purpose: Load the configuration data from the store
 *
 * First load the host groups and target groups, then the view entries
 * and finally the provider data
 *
 * fd - file descriptor of control node for stmf.
 */
static int
loadStore(int fd)
{
	int ret;
	int i, j;
	stmfGroupList *groupList = NULL;
	stmfGuidList *guidList = NULL;
	stmfViewEntryList *viewEntryList = NULL;
	stmfProviderList *providerList = NULL;
	int providerType;
	nvlist_t *nvl = NULL;



	/* load host groups */
	ret = stmfGetHostGroupList(&groupList);
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}
	ret = loadHostGroups(fd, groupList);
	if (ret != STMF_STATUS_SUCCESS) {
		goto out;
	}

	stmfFreeMemory(groupList);
	groupList = NULL;

	/* load target groups */
	ret = stmfGetTargetGroupList(&groupList);
	if (ret != STMF_STATUS_SUCCESS) {
		goto out;
	}
	ret = loadTargetGroups(fd, groupList);
	if (ret != STMF_STATUS_SUCCESS) {
		goto out;
	}

	stmfFreeMemory(groupList);
	groupList = NULL;

	/* Get the guid list */
	ret = psGetLogicalUnitList(&guidList);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			ret = STMF_STATUS_ERROR;
			break;
	}

	if (ret != STMF_STATUS_SUCCESS) {
		goto out;
	}

	/*
	 * We have the guid list, now get the corresponding
	 * view entries for each guid
	 */
	for (i = 0; i < guidList->cnt; i++) {
		ret = psGetViewEntryList(&guidList->guid[i], &viewEntryList);
		switch (ret) {
			case STMF_PS_SUCCESS:
				ret = STMF_STATUS_SUCCESS;
				break;
			case STMF_PS_ERROR_NOT_FOUND:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			case STMF_PS_ERROR_BUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case STMF_PS_ERROR_SERVICE_NOT_FOUND:
				ret = STMF_ERROR_SERVICE_NOT_FOUND;
				break;
			case STMF_PS_ERROR_VERSION_MISMATCH:
				ret = STMF_ERROR_SERVICE_DATA_VERSION;
				break;
			default:
				ret = STMF_STATUS_ERROR;
				break;
		}
		if (ret != STMF_STATUS_SUCCESS) {
			goto out;
		}
		for (j = 0; j < viewEntryList->cnt; j++) {
			ret = addViewEntryIoctl(fd, &guidList->guid[i],
			    &viewEntryList->ve[j]);
			if (ret != STMF_STATUS_SUCCESS) {
				goto out;
			}
		}
	}

	/* get the list of providers that have data */
	ret = psGetProviderDataList(&providerList);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			ret = STMF_STATUS_ERROR;
			break;
	}
	if (ret != STMF_STATUS_SUCCESS) {
		goto out;
	}

	for (i = 0; i < providerList->cnt; i++) {
		providerType = providerList->provider[i].providerType;
		ret = psGetProviderData(providerList->provider[i].name,
		    &nvl, providerType, NULL);
		switch (ret) {
			case STMF_PS_SUCCESS:
				ret = STMF_STATUS_SUCCESS;
				break;
			case STMF_PS_ERROR_NOT_FOUND:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			case STMF_PS_ERROR_BUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case STMF_PS_ERROR_SERVICE_NOT_FOUND:
				ret = STMF_ERROR_SERVICE_NOT_FOUND;
				break;
			case STMF_PS_ERROR_VERSION_MISMATCH:
				ret = STMF_ERROR_SERVICE_DATA_VERSION;
				break;
			default:
				ret = STMF_STATUS_ERROR;
				break;
		}
		if (ret != STMF_STATUS_SUCCESS) {
			goto out;
		}

		/* call setProviderData */
		ret = setProviderData(fd, providerList->provider[i].name, nvl,
		    providerType);
		switch (ret) {
			case STMF_PS_SUCCESS:
				ret = STMF_STATUS_SUCCESS;
				break;
			case STMF_PS_ERROR_NOT_FOUND:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			case STMF_PS_ERROR_BUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case STMF_PS_ERROR_SERVICE_NOT_FOUND:
				ret = STMF_ERROR_SERVICE_NOT_FOUND;
				break;
			case STMF_PS_ERROR_VERSION_MISMATCH:
				ret = STMF_ERROR_SERVICE_DATA_VERSION;
				break;
			default:
				ret = STMF_STATUS_ERROR;
				break;
		}
		if (ret != STMF_STATUS_SUCCESS) {
			goto out;
		}

		nvlist_free(nvl);
		nvl = NULL;
	}
out:
	if (groupList != NULL) {
		free(groupList);
	}
	if (guidList != NULL) {
		free(guidList);
	}
	if (viewEntryList != NULL) {
		free(viewEntryList);
	}
	if (nvl != NULL) {
		nvlist_free(nvl);
	}
	return (ret);
}

/*
 * stmfLoadConfig
 *
 * Purpose - load the configuration data from smf into stmf
 *
 */
int
stmfLoadConfig(void)
{
	int ret;
	int fd;
	stmf_state_desc_t stmfStateSet;
	stmfState state;


	/* Check to ensure service exists */
	if (psCheckService() != STMF_STATUS_SUCCESS) {
		return (STMF_ERROR_SERVICE_NOT_FOUND);
	}

	ret = stmfGetState(&state);
	if (ret == STMF_STATUS_SUCCESS) {
		if (state.operationalState != STMF_SERVICE_STATE_OFFLINE) {
			return (STMF_ERROR_SERVICE_ONLINE);
		}
	} else {
		return (STMF_STATUS_ERROR);
	}


	stmfStateSet.state = STMF_STATE_OFFLINE;
	stmfStateSet.config_state = STMF_CONFIG_INIT;

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_EXCL_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	ret = setStmfState(fd, &stmfStateSet, STMF_SERVICE_TYPE);
	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/* Load the persistent configuration data */
	ret = loadStore(fd);
	if (ret != 0) {
		goto done;
	}

	stmfStateSet.state = STMF_STATE_OFFLINE;
	stmfStateSet.config_state = STMF_CONFIG_INIT_DONE;

done:
	if (ret == STMF_STATUS_SUCCESS) {
		ret = setStmfState(fd, &stmfStateSet, STMF_SERVICE_TYPE);
	}
	(void) close(fd);
	return (ret);
}

/*
 * getStmfState
 *
 * stmfState - pointer to stmf_state_desc_t structure. Will contain the state
 *             information of the stmf service on success.
 */
static int
getStmfState(stmf_state_desc_t *stmfState)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	int ioctlRet;
	stmf_iocdata_t stmfIoctl;

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to get the stmf state
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (stmf_state_desc_t);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)stmfState;
	stmfIoctl.stmf_obuf_size = sizeof (stmf_state_desc_t);
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)stmfState;
	ioctlRet = ioctl(fd, STMF_IOCTL_GET_STMF_STATE, &stmfIoctl);

	(void) close(fd);

	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				syslog(LOG_DEBUG,
				    "getStmfState:ioctl errno(%d)", errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
	}
	return (ret);
}


/*
 * setStmfState
 *
 * stmfState - pointer to caller set state structure
 * objectType - one of:
 *		LOGICAL_UNIT_TYPE
 *		TARGET_TYPE
 *		STMF_SERVICE_TYPE
 */
static int
setStmfState(int fd, stmf_state_desc_t *stmfState, int objectType)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	int cmd;
	stmf_iocdata_t stmfIoctl;

	switch (objectType) {
		case LOGICAL_UNIT_TYPE:
			cmd = STMF_IOCTL_SET_LU_STATE;
			break;
		case TARGET_TYPE:
			cmd = STMF_IOCTL_SET_TARGET_PORT_STATE;
			break;
		case STMF_SERVICE_TYPE:
			cmd = STMF_IOCTL_SET_STMF_STATE;
			break;
		default:
			ret = STMF_STATUS_ERROR;
			goto done;
	}

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to set the stmf state
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (stmf_state_desc_t);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)stmfState;
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			case ENOENT:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			default:
				syslog(LOG_DEBUG,
				    "setStmfState:ioctl errno(%d)", errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
	}
done:
	return (ret);
}

/*
 * stmfOnline
 *
 * Purpose: Online stmf service
 *
 */
int
stmfOnline(void)
{
	int ret;
	int fd;
	stmfState state;
	stmf_state_desc_t iState;

	ret = stmfGetState(&state);
	if (ret == STMF_STATUS_SUCCESS) {
		if (state.operationalState == STMF_SERVICE_STATE_ONLINE) {
			return (STMF_ERROR_SERVICE_ONLINE);
		}
	} else {
		return (STMF_STATUS_ERROR);
	}
	iState.state = STMF_STATE_ONLINE;
	iState.config_state = STMF_CONFIG_NONE;
	/*
	 * Open control node for stmf
	 * to make call to setStmfState()
	 */
	if ((ret = openStmf(OPEN_EXCL_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);
	ret = setStmfState(fd, &iState, STMF_SERVICE_TYPE);
	(void) close(fd);
	return (ret);
}

/*
 * stmfOffline
 *
 * Purpose: Offline stmf service
 *
 */
int
stmfOffline(void)
{
	int ret;
	int fd;
	stmfState state;
	stmf_state_desc_t iState;

	ret = stmfGetState(&state);
	if (ret == STMF_STATUS_SUCCESS) {
		if (state.operationalState == STMF_SERVICE_STATE_OFFLINE) {
			return (STMF_ERROR_SERVICE_OFFLINE);
		}
	} else {
		return (STMF_STATUS_ERROR);
	}
	iState.state = STMF_STATE_OFFLINE;
	iState.config_state = STMF_CONFIG_NONE;

	/*
	 * Open control node for stmf
	 * to make call to setStmfState()
	 */
	if ((ret = openStmf(OPEN_EXCL_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);
	ret = setStmfState(fd, &iState, STMF_SERVICE_TYPE);
	(void) close(fd);
	return (ret);
}


/*
 * stmfOfflineTarget
 *
 * Purpose: Change state of target to offline
 *
 * devid - devid of the target to offline
 */
int
stmfOfflineTarget(stmfDevid *devid)
{
	stmf_state_desc_t targetState;
	int ret = STMF_STATUS_SUCCESS;
	int fd;

	if (devid == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}
	bzero(&targetState, sizeof (targetState));

	targetState.state = STMF_STATE_OFFLINE;
	targetState.ident[IDENT_LENGTH_BYTE] = devid->identLength;
	bcopy(&(devid->ident), &targetState.ident[IDENT_LENGTH_BYTE + 1],
	    devid->identLength);
	/*
	 * Open control node for stmf
	 * to make call to setStmfState()
	 */
	if ((ret = openStmf(OPEN_EXCL_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);
	ret = setStmfState(fd, &targetState, TARGET_TYPE);
	(void) close(fd);
	return (ret);
}

/*
 * stmfOfflineLogicalUnit
 *
 * Purpose: Change state of logical unit to offline
 *
 * lu - guid of the logical unit to offline
 */
int
stmfOfflineLogicalUnit(stmfGuid *lu)
{
	stmf_state_desc_t luState;
	int ret = STMF_STATUS_SUCCESS;
	int fd;

	if (lu == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	bzero(&luState, sizeof (luState));

	luState.state = STMF_STATE_OFFLINE;
	bcopy(lu, &luState.ident, sizeof (stmfGuid));
	/*
	 * Open control node for stmf
	 * to make call to setStmfState()
	 */
	if ((ret = openStmf(OPEN_EXCL_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);
	ret = setStmfState(fd, &luState, LOGICAL_UNIT_TYPE);
	(void) close(fd);
	return (ret);
}

/*
 * stmfOnlineTarget
 *
 * Purpose: Change state of target to online
 *
 * devid - devid of the target to online
 */
int
stmfOnlineTarget(stmfDevid *devid)
{
	stmf_state_desc_t targetState;
	int ret = STMF_STATUS_SUCCESS;
	int fd;

	if (devid == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}
	bzero(&targetState, sizeof (targetState));

	targetState.state = STMF_STATE_ONLINE;
	targetState.ident[IDENT_LENGTH_BYTE] = devid->identLength;
	bcopy(&(devid->ident), &targetState.ident[IDENT_LENGTH_BYTE + 1],
	    devid->identLength);
	/*
	 * Open control node for stmf
	 * to make call to setStmfState()
	 */
	if ((ret = openStmf(OPEN_EXCL_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);
	ret = setStmfState(fd, &targetState, TARGET_TYPE);
	(void) close(fd);
	return (ret);
}

/*
 * stmfOnlineLogicalUnit
 *
 * Purpose: Change state of logical unit to online
 *
 * lu - guid of the logical unit to online
 */
int
stmfOnlineLogicalUnit(stmfGuid *lu)
{
	stmf_state_desc_t luState;
	int ret = STMF_STATUS_SUCCESS;
	int fd;

	if (lu == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	bzero(&luState, sizeof (luState));

	luState.state = STMF_STATE_ONLINE;
	bcopy(lu, &luState.ident, sizeof (stmfGuid));
	/*
	 * Open control node for stmf
	 * to make call to setStmfState()
	 */
	if ((ret = openStmf(OPEN_EXCL_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);
	ret = setStmfState(fd, &luState, LOGICAL_UNIT_TYPE);
	(void) close(fd);
	return (ret);
}

/*
 * stmfRemoveFromHostGroup
 *
 * Purpose: Removes an initiator from an initiator group
 *
 * hostGroupName - name of an initiator group
 * hostName - name of host group member to remove
 */
int
stmfRemoveFromHostGroup(stmfGroupName *hostGroupName, stmfDevid *hostName)
{
	int ret;
	int fd;

	if (hostGroupName == NULL ||
	    (strnlen((char *)hostGroupName, sizeof (stmfGroupName))
	    == sizeof (stmfGroupName)) || hostName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	if ((ret = groupMemberIoctl(fd, STMF_IOCTL_REMOVE_HG_ENTRY,
	    hostGroupName, hostName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	ret = psRemoveHostGroupMember((char *)hostGroupName,
	    (char *)hostName->ident);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_MEMBER_NOT_FOUND:
			ret = STMF_ERROR_MEMBER_NOT_FOUND;
			break;
		case STMF_PS_ERROR_GROUP_NOT_FOUND:
			ret = STMF_ERROR_GROUP_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfRemoveFromHostGroup"
			    "psRemoveHostGroupMember:error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfRemoveFromTargetGroup
 *
 * Purpose: Removes a local port from a local port group
 *
 * targetGroupName - name of a target group
 * targetName - name of target to remove
 */
int
stmfRemoveFromTargetGroup(stmfGroupName *targetGroupName, stmfDevid *targetName)
{
	int ret;
	int fd;

	if (targetGroupName == NULL ||
	    (strnlen((char *)targetGroupName, sizeof (stmfGroupName))
	    == sizeof (stmfGroupName)) || targetName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	if ((ret = groupMemberIoctl(fd, STMF_IOCTL_REMOVE_TG_ENTRY,
	    targetGroupName, targetName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	ret = psRemoveTargetGroupMember((char *)targetGroupName,
	    (char *)targetName->ident);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_MEMBER_NOT_FOUND:
			ret = STMF_ERROR_MEMBER_NOT_FOUND;
			break;
		case STMF_PS_ERROR_GROUP_NOT_FOUND:
			ret = STMF_ERROR_GROUP_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfRemoveFromTargetGroup"
			    "psRemoveTargetGroupMember:error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfRemoveViewEntry
 *
 * Purpose: Removes a view entry from a logical unit
 *
 * lu - guid of lu for which view entry is being removed
 * viewEntryIndex - index of view entry to remove
 *
 */
int
stmfRemoveViewEntry(stmfGuid *lu, uint32_t viewEntryIndex)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	int ioctlRet;
	stmf_iocdata_t stmfIoctl;
	stmf_view_op_entry_t ioctlViewEntry;

	if (lu == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	bzero(&ioctlViewEntry, sizeof (ioctlViewEntry));
	ioctlViewEntry.ve_ndx_valid = B_TRUE;
	ioctlViewEntry.ve_ndx = viewEntryIndex;
	bcopy(lu, &ioctlViewEntry.ve_guid, sizeof (stmfGuid));

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to add to the view entry
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (ioctlViewEntry);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&ioctlViewEntry;
	ioctlRet = ioctl(fd, STMF_IOCTL_REMOVE_VIEW_ENTRY, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				switch (stmfIoctl.stmf_error) {
					case STMF_IOCERR_UPDATE_NEED_CFG_INIT:
						ret = STMF_ERROR_CONFIG_NONE;
						break;
					default:
						ret = STMF_ERROR_PERM;
						break;
				}
				break;
			case ENODEV:
			case ENOENT:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			default:
				syslog(LOG_DEBUG,
				    "stmfRemoveViewEntry:ioctl errno(%d)",
				    errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}

	ret = psRemoveViewEntry(lu, viewEntryIndex);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_NOT_FOUND:
			ret = STMF_ERROR_NOT_FOUND;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfRemoveViewEntry" "psRemoveViewEntry:error(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfSetProviderData
 *
 * Purpose: set the provider data
 *
 * providerName - unique name of provider
 * nvl - nvlist to set
 * providerType - type of provider for which to set data
 *		STMF_LU_PROVIDER_TYPE
 *		STMF_PORT_PROVIDER_TYPE
 */
int
stmfSetProviderData(char *providerName, nvlist_t *nvl, int providerType)
{
	return (stmfSetProviderDataProt(providerName, nvl, providerType,
	    NULL));
}

/*
 * stmfSetProviderDataProt
 *
 * Purpose: set the provider data
 *
 * providerName - unique name of provider
 * nvl - nvlist to set
 * providerType - type of provider for which to set data
 *		STMF_LU_PROVIDER_TYPE
 *		STMF_PORT_PROVIDER_TYPE
 * setToken - Stale data token returned in the stmfGetProviderDataProt()
 *	      call or NULL.
 */
int
stmfSetProviderDataProt(char *providerName, nvlist_t *nvl, int providerType,
    uint64_t *setToken)
{
	int ret;
	int fd;

	if (providerName == NULL || nvl == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (providerType != STMF_LU_PROVIDER_TYPE &&
	    providerType != STMF_PORT_PROVIDER_TYPE) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* call init */
	ret = initializeConfig();
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	ret = setProviderData(fd, providerName, nvl, providerType);

	(void) close(fd);

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/* setting driver provider data successful. Now persist it */
	ret = psSetProviderData(providerName, nvl, providerType, setToken);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_EXISTS:
			ret = STMF_ERROR_EXISTS;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		case STMF_PS_ERROR_SERVICE_NOT_FOUND:
			ret = STMF_ERROR_SERVICE_NOT_FOUND;
			break;
		case STMF_PS_ERROR_VERSION_MISMATCH:
			ret = STMF_ERROR_SERVICE_DATA_VERSION;
			break;
		case STMF_PS_ERROR_PROV_DATA_STALE:
			ret = STMF_ERROR_PROV_DATA_STALE;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfSetProviderData"
			    "psSetProviderData:error(%d)", ret);
			ret = STMF_STATUS_ERROR;
			break;
	}

done:
	return (ret);
}

/*
 * setProviderData
 *
 * Purpose: set the provider data
 *
 * providerName - unique name of provider
 * nvl - nvlist to set
 * providerType - logical unit or port provider
 */
static int
setProviderData(int fd, char *providerName, nvlist_t *nvl, int providerType)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	size_t nvlistEncodedSize;
	stmf_ppioctl_data_t *ppi = NULL;
	char *allocatedNvBuffer;
	stmf_iocdata_t stmfIoctl;

	if (providerName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* get size of encoded nvlist */
	if (nvlist_size(nvl, &nvlistEncodedSize, NV_ENCODE_XDR) != 0) {
		return (STMF_STATUS_ERROR);
	}

	/* allocate memory for ioctl */
	ppi = (stmf_ppioctl_data_t *)calloc(1, nvlistEncodedSize +
	    sizeof (stmf_ppioctl_data_t));
	if (ppi == NULL) {
		return (STMF_ERROR_NOMEM);
	}

	allocatedNvBuffer = (char *)&ppi->ppi_data;
	if (nvlist_pack(nvl, &allocatedNvBuffer, &nvlistEncodedSize,
	    NV_ENCODE_XDR, 0) != 0) {
		return (STMF_STATUS_ERROR);
	}

	/* set provider name and provider type */
	(void) strncpy(ppi->ppi_name, providerName, sizeof (ppi->ppi_name));
	switch (providerType) {
		case STMF_LU_PROVIDER_TYPE:
			ppi->ppi_lu_provider = 1;
			break;
		case STMF_PORT_PROVIDER_TYPE:
			ppi->ppi_port_provider = 1;
			break;
		default:
			return (STMF_ERROR_INVALID_ARG);
	}

	/* set the size of the ioctl data to packed data size */
	ppi->ppi_data_size = nvlistEncodedSize;

	bzero(&stmfIoctl, sizeof (stmfIoctl));

	stmfIoctl.stmf_version = STMF_VERSION_1;
	/*
	 * Subtracting 8 from the size as that is the size of the last member
	 * of the structure where the packed data resides
	 */
	stmfIoctl.stmf_ibuf_size = nvlistEncodedSize +
	    sizeof (stmf_ppioctl_data_t) - 8;
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)ppi;
	ioctlRet = ioctl(fd, STMF_IOCTL_LOAD_PP_DATA, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				syslog(LOG_DEBUG,
				    "setProviderData:ioctl errno(%d)", errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		if (ret != STMF_STATUS_SUCCESS)
			goto done;
	}

done:
	free(ppi);
	return (ret);
}
