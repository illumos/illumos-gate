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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
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
#include <math.h>
#include <libstmf_impl.h>
#include <sys/stmf_ioctl.h>
#include <sys/stmf_sbd_ioctl.h>
#include <sys/pppt_ioctl.h>
#include <macros.h>

#define	STMF_PATH    "/devices/pseudo/stmf@0:admin"
#define	SBD_PATH    "/devices/pseudo/stmf_sbd@0:admin"
#define	PPPT_PATH    "/devices/pseudo/pppt@0:pppt"

#define	EUI "eui."
#define	WWN "wwn."
#define	IQN "iqn."
#define	LU_ASCII_GUID_SIZE 32
#define	LU_GUID_SIZE 16
#define	OUI_ASCII_SIZE 6
#define	HOST_ID_ASCII_SIZE 8
#define	OUI_SIZE 3
#define	HOST_ID_SIZE 4
#define	IDENT_LENGTH_BYTE 3

/* various initial allocation values */
#define	ALLOC_LU		8192
#define	ALLOC_TARGET_PORT	2048
#define	ALLOC_PROVIDER		64
#define	ALLOC_GROUP		2048
#define	ALLOC_SESSION		2048
#define	ALLOC_VE		256
#define	ALLOC_PP_DATA_SIZE	128*1024
#define	ALLOC_GRP_MEMBER	256

#define	MAX_ISCSI_NAME	223
#define	MAX_SERIAL_SIZE 252 + 1
#define	MAX_LU_ALIAS_SIZE 256
#define	MAX_SBD_PROPS	MAXPATHLEN + MAX_SERIAL_SIZE + MAX_LU_ALIAS_SIZE

#define	OPEN_STMF 0
#define	OPEN_EXCL_STMF O_EXCL

#define	OPEN_SBD 0
#define	OPEN_EXCL_SBD O_EXCL

#define	OPEN_PPPT 0
#define	OPEN_EXCL_PPPT O_EXCL

#define	LOGICAL_UNIT_TYPE 0
#define	TARGET_TYPE 1
#define	STMF_SERVICE_TYPE 2

#define	HOST_GROUP   1
#define	TARGET_GROUP 2

/* set default persistence here */
#define	STMF_DEFAULT_PERSIST	STMF_PERSIST_SMF

#define	MAX_PROVIDER_RETRY 30

static int openStmf(int, int *fd);
static int openSbd(int, int *fd);
static int openPppt(int, int *fd);
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
static int setProviderData(int fd, char *, nvlist_t *, int, uint64_t *);
static int createDiskResource(luResourceImpl *);
static int createDiskLu(diskResource *, stmfGuid *);
static int deleteDiskLu(stmfGuid *luGuid);
static int getDiskProp(luResourceImpl *, uint32_t, char *, size_t *);
static int getDiskAllProps(stmfGuid *luGuid, luResource *hdl);
static int loadDiskPropsFromDriver(luResourceImpl *, sbd_lu_props_t *);
static int removeGuidFromDiskStore(stmfGuid *);
static int addGuidToDiskStore(stmfGuid *, char *);
static int persistDiskGuid(stmfGuid *, char *, boolean_t);
static int setDiskProp(luResourceImpl *, uint32_t, const char *);
static int getDiskGlobalProp(uint32_t prop, char *propVal, size_t *propLen);
static int checkHexUpper(char *);
static int strToShift(const char *);
static int niceStrToNum(const char *, uint64_t *);
static void diskError(uint32_t, int *);
static int importDiskLu(char *fname, stmfGuid *);
static int modifyDiskLu(diskResource *, stmfGuid *, const char *);
static int modifyDiskLuProp(stmfGuid *, const char *, uint32_t, const char *);
static int validateModifyDiskProp(uint32_t);
static uint8_t iGetPersistMethod();
static int groupListIoctl(stmfGroupList **, int);
static int iLoadGroupFromPs(stmfGroupList **, int);
static int groupMemberListIoctl(stmfGroupName *, stmfGroupProperties **, int);
static int getProviderData(char *, nvlist_t **, int, uint64_t *);
static int setDiskStandby(stmfGuid *luGuid);
static int setDiskGlobalProp(uint32_t, const char *);
static int viewEntryCompare(const void *, const void *);
static void deleteNonActiveLus();
static int loadStmfProp(int fd);

static pthread_mutex_t persistenceTypeLock = PTHREAD_MUTEX_INITIALIZER;
static int iPersistType = 0;
/* when B_TRUE, no need to access SMF anymore. Just use iPersistType */
static boolean_t iLibSetPersist = B_FALSE;

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
		} else if (errno == EACCES) {
			ret = STMF_ERROR_PERM;
		} else {
			ret = STMF_STATUS_ERROR;
		}
		syslog(LOG_DEBUG, "openStmf:open failure:%s:errno(%d)",
		    STMF_PATH, errno);
	}

	return (ret);
}

/*
 * Open for sbd module
 *
 * flag - open flag (OPEN_SBD, OPEN_EXCL_SBD)
 * fd - pointer to integer. On success, contains the stmf file descriptor
 */
static int
openSbd(int flag, int *fd)
{
	int ret = STMF_STATUS_ERROR;

	if ((*fd = open(SBD_PATH, O_NDELAY | O_RDONLY | flag)) != -1) {
		ret = STMF_STATUS_SUCCESS;
	} else {
		if (errno == EBUSY) {
			ret = STMF_ERROR_BUSY;
		} else if (errno == EACCES) {
			ret = STMF_ERROR_PERM;
		} else {
			ret = STMF_STATUS_ERROR;
		}
		syslog(LOG_DEBUG, "openSbd:open failure:%s:errno(%d)",
		    SBD_PATH, errno);
	}

	return (ret);
}

/*
 * Open for pppt module
 *
 * flag - open flag (OPEN_PPPT, OPEN_EXCL_PPPT)
 * fd - pointer to integer. On success, contains the stmf file descriptor
 */
static int
openPppt(int flag, int *fd)
{
	int ret = STMF_STATUS_ERROR;

	if ((*fd = open(PPPT_PATH, O_RDONLY | flag)) != -1) {
		ret = STMF_STATUS_SUCCESS;
	} else {
		if (errno == EBUSY) {
			ret = STMF_ERROR_BUSY;
		} else if (errno == EACCES) {
			ret = STMF_ERROR_PERM;
		} else {
			ret = STMF_STATUS_ERROR;
		}
		syslog(LOG_DEBUG, "openPppt:open failure:%s:errno(%d)",
		    PPPT_PATH, errno);
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
			case EPERM:
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
	return (ret);
}

/*
 * groupMemberIoctl
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
				switch (stmfIoctl.stmf_error) {
					case STMF_IOCERR_TG_NEED_TG_OFFLINE:
						ret = STMF_ERROR_TG_ONLINE;
						break;
					default:
						ret = STMF_ERROR_BUSY;
						break;
				}
				break;
			case EPERM:
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
	return (ret);
}

/*
 * qsort function
 * sort on veIndex
 */
static int
viewEntryCompare(const void *p1, const void *p2)
{

	stmfViewEntry *v1 = (stmfViewEntry *)p1, *v2 = (stmfViewEntry *)p2;
	if (v1->veIndex > v2->veIndex)
		return (1);
	if (v1->veIndex < v2->veIndex)
		return (-1);
	return (0);
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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

	if ((ret = groupMemberIoctl(fd, STMF_IOCTL_ADD_TG_ENTRY,
	    targetGroupName, targetName)) != STMF_STATUS_SUCCESS) {
		goto done;
	}

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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
			case EPERM:
				ret = STMF_ERROR_PERM;
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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
			case EPERM:
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
		goto done;
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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
 * stmfCreateLu
 *
 * Purpose: Create a logical unit
 *
 * hdl - handle to logical unit resource created via stmfCreateLuResource
 *
 * luGuid - If non-NULL, on success, contains the guid of the created logical
 *	    unit
 */
int
stmfCreateLu(luResource hdl, stmfGuid *luGuid)
{
	int ret = STMF_STATUS_SUCCESS;
	luResourceImpl *luPropsHdl = hdl;

	if (hdl == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (luPropsHdl->type == STMF_DISK) {
		ret = createDiskLu((diskResource *)luPropsHdl->resource,
		    luGuid);
	} else {
		return (STMF_ERROR_INVALID_ARG);
	}

	return (ret);
}

/*
 * stmfCreateLuResource
 *
 * Purpose: Create resource handle for a logical unit
 *
 * dType - Type of logical unit resource to create
 *	   Can be: STMF_DISK
 *
 * hdl - pointer to luResource
 */
int
stmfCreateLuResource(uint16_t dType, luResource *hdl)
{
	int ret = STMF_STATUS_SUCCESS;

	if (dType != STMF_DISK || hdl == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	*hdl = calloc(1, sizeof (luResourceImpl));
	if (*hdl == NULL) {
		return (STMF_ERROR_NOMEM);
	}

	ret = createDiskResource((luResourceImpl *)*hdl);
	if (ret != STMF_STATUS_SUCCESS) {
		free(*hdl);
		return (ret);
	}

	return (STMF_STATUS_SUCCESS);
}

/*
 * Creates a disk logical unit
 *
 * disk - pointer to diskResource structure that represents the properties
 *        for the disk logical unit to be created.
 */
static int
createDiskLu(diskResource *disk, stmfGuid *createdGuid)
{
	int ret = STMF_STATUS_SUCCESS;
	int dataFileNameLen = 0;
	int metaFileNameLen = 0;
	int serialNumLen = 0;
	int luAliasLen = 0;
	int luMgmtUrlLen = 0;
	int sluBufSize = 0;
	int bufOffset = 0;
	int fd = 0;
	int ioctlRet;
	int savedErrno;
	stmfGuid guid;
	stmf_iocdata_t sbdIoctl = {0};

	sbd_create_and_reg_lu_t *sbdLu = NULL;

	/*
	 * Open control node for sbd
	 */
	if ((ret = openSbd(OPEN_SBD, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/* data file name must be specified */
	if (disk->luDataFileNameValid) {
		dataFileNameLen = strlen(disk->luDataFileName);
	} else {
		(void) close(fd);
		return (STMF_ERROR_MISSING_PROP_VAL);
	}

	sluBufSize += dataFileNameLen + 1;

	if (disk->luMetaFileNameValid) {
		metaFileNameLen = strlen(disk->luMetaFileName);
		sluBufSize += metaFileNameLen + 1;
	}

	serialNumLen = strlen(disk->serialNum);
	sluBufSize += serialNumLen;

	if (disk->luAliasValid) {
		luAliasLen = strlen(disk->luAlias);
		sluBufSize += luAliasLen + 1;
	}

	if (disk->luMgmtUrlValid) {
		luMgmtUrlLen = strlen(disk->luMgmtUrl);
		sluBufSize += luMgmtUrlLen + 1;
	}

	/*
	 * 8 is the size of the buffer set aside for
	 * concatenation of variable length fields
	 */
	sbdLu = (sbd_create_and_reg_lu_t *)calloc(1,
	    sizeof (sbd_create_and_reg_lu_t) + sluBufSize - 8);
	if (sbdLu == NULL) {
		return (STMF_ERROR_NOMEM);
	}

	sbdLu->slu_struct_size = sizeof (sbd_create_and_reg_lu_t) +
	    sluBufSize - 8;

	if (metaFileNameLen) {
		sbdLu->slu_meta_fname_valid = 1;
		sbdLu->slu_meta_fname_off = bufOffset;
		bcopy(disk->luMetaFileName, &(sbdLu->slu_buf[bufOffset]),
		    metaFileNameLen + 1);
		bufOffset += metaFileNameLen + 1;
	}

	bcopy(disk->luDataFileName, &(sbdLu->slu_buf[bufOffset]),
	    dataFileNameLen + 1);
	sbdLu->slu_data_fname_off = bufOffset;
	bufOffset += dataFileNameLen + 1;

	/* currently, serial # is not passed null terminated to the driver */
	if (disk->serialNumValid) {
		sbdLu->slu_serial_valid = 1;
		sbdLu->slu_serial_off = bufOffset;
		sbdLu->slu_serial_size = serialNumLen;
		bcopy(disk->serialNum, &(sbdLu->slu_buf[bufOffset]),
		    serialNumLen);
		bufOffset += serialNumLen;
	}

	if (disk->luAliasValid) {
		sbdLu->slu_alias_valid = 1;
		sbdLu->slu_alias_off = bufOffset;
		bcopy(disk->luAlias, &(sbdLu->slu_buf[bufOffset]),
		    luAliasLen + 1);
		bufOffset += luAliasLen + 1;
	}

	if (disk->luMgmtUrlValid) {
		sbdLu->slu_mgmt_url_valid = 1;
		sbdLu->slu_mgmt_url_off = bufOffset;
		bcopy(disk->luMgmtUrl, &(sbdLu->slu_buf[bufOffset]),
		    luMgmtUrlLen + 1);
		bufOffset += luMgmtUrlLen + 1;
	}

	if (disk->luSizeValid) {
		sbdLu->slu_lu_size_valid = 1;
		sbdLu->slu_lu_size = disk->luSize;
	}

	if (disk->luGuidValid) {
		sbdLu->slu_guid_valid = 1;
		bcopy(disk->luGuid, sbdLu->slu_guid, sizeof (disk->luGuid));
	}

	if (disk->vidValid) {
		sbdLu->slu_vid_valid = 1;
		bcopy(disk->vid, sbdLu->slu_vid, sizeof (disk->vid));
	}

	if (disk->pidValid) {
		sbdLu->slu_pid_valid = 1;
		bcopy(disk->pid, sbdLu->slu_pid, sizeof (disk->pid));
	}

	if (disk->revValid) {
		sbdLu->slu_rev_valid = 1;
		bcopy(disk->rev, sbdLu->slu_rev, sizeof (disk->rev));
	}

	if (disk->companyIdValid) {
		sbdLu->slu_company_id_valid = 1;
		sbdLu->slu_company_id = disk->companyId;
	}

	if (disk->hostIdValid) {
		sbdLu->slu_host_id_valid = 1;
		sbdLu->slu_host_id = disk->hostId;
	}

	if (disk->blkSizeValid) {
		sbdLu->slu_blksize_valid = 1;
		sbdLu->slu_blksize = disk->blkSize;
	}

	if (disk->writeProtectEnableValid) {
		if (disk->writeProtectEnable) {
			sbdLu->slu_write_protected = 1;
		}
	}

	if (disk->writebackCacheDisableValid) {
		sbdLu->slu_writeback_cache_disable_valid = 1;
		if (disk->writebackCacheDisable) {
			sbdLu->slu_writeback_cache_disable = 1;
		}
	}

	sbdIoctl.stmf_version = STMF_VERSION_1;
	sbdIoctl.stmf_ibuf_size = sbdLu->slu_struct_size;
	sbdIoctl.stmf_ibuf = (uint64_t)(unsigned long)sbdLu;
	sbdIoctl.stmf_obuf_size = sbdLu->slu_struct_size;
	sbdIoctl.stmf_obuf = (uint64_t)(unsigned long)sbdLu;

	ioctlRet = ioctl(fd, SBD_IOCTL_CREATE_AND_REGISTER_LU, &sbdIoctl);
	if (ioctlRet != 0) {
		savedErrno = errno;
		switch (savedErrno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				diskError(sbdIoctl.stmf_error, &ret);
				if (ret == STMF_STATUS_ERROR) {
					syslog(LOG_DEBUG,
					"createDiskLu:ioctl "
					"error(%d) (%d) (%d)", ioctlRet,
					    sbdIoctl.stmf_error, savedErrno);
				}
				break;
		}
	}

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/*
	 * on success, copy the resulting guid into the caller's guid if not
	 * NULL
	 */
	if (createdGuid) {
		bcopy(sbdLu->slu_guid, createdGuid->guid,
		    sizeof (sbdLu->slu_guid));
	}

	bcopy(sbdLu->slu_guid, guid.guid, sizeof (sbdLu->slu_guid));
	if (disk->luMetaFileNameValid) {
		ret = addGuidToDiskStore(&guid, disk->luMetaFileName);
	} else {
		ret = addGuidToDiskStore(&guid, disk->luDataFileName);
	}
done:
	free(sbdLu);
	(void) close(fd);
	return (ret);
}


/*
 * stmfImportLu
 *
 * Purpose: Import a previously created logical unit
 *
 * dType - Type of logical unit
 *         Can be: STMF_DISK
 *
 * luGuid - If non-NULL, on success, contains the guid of the imported logical
 *	    unit
 *
 * fname - A file name where the metadata resides
 *
 */
int
stmfImportLu(uint16_t dType, char *fname, stmfGuid *luGuid)
{
	int ret = STMF_STATUS_SUCCESS;

	if (dType == STMF_DISK) {
		ret = importDiskLu(fname, luGuid);
	} else {
		return (STMF_ERROR_INVALID_ARG);
	}

	return (ret);
}

/*
 * importDiskLu
 *
 * filename - filename to import
 * createdGuid - if not NULL, on success contains the imported guid
 *
 */
static int
importDiskLu(char *fname, stmfGuid *createdGuid)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd = 0;
	int ioctlRet;
	int savedErrno;
	int metaFileNameLen;
	stmfGuid iGuid;
	int iluBufSize = 0;
	sbd_import_lu_t *sbdLu = NULL;
	stmf_iocdata_t sbdIoctl = {0};

	if (fname == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/*
	 * Open control node for sbd
	 */
	if ((ret = openSbd(OPEN_SBD, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	metaFileNameLen = strlen(fname);
	iluBufSize += metaFileNameLen + 1;

	/*
	 * 8 is the size of the buffer set aside for
	 * concatenation of variable length fields
	 */
	sbdLu = (sbd_import_lu_t *)calloc(1,
	    sizeof (sbd_import_lu_t) + iluBufSize - 8);
	if (sbdLu == NULL) {
		(void) close(fd);
		return (STMF_ERROR_NOMEM);
	}

	/*
	 * Accept either a data file or meta data file.
	 * sbd will do the right thing here either way.
	 * i.e. if it's a data file, it assumes that the
	 * meta data is shared with the data.
	 */
	(void) strncpy(sbdLu->ilu_meta_fname, fname, metaFileNameLen);

	sbdLu->ilu_struct_size = sizeof (sbd_import_lu_t) + iluBufSize - 8;

	sbdIoctl.stmf_version = STMF_VERSION_1;
	sbdIoctl.stmf_ibuf_size = sbdLu->ilu_struct_size;
	sbdIoctl.stmf_ibuf = (uint64_t)(unsigned long)sbdLu;
	sbdIoctl.stmf_obuf_size = sbdLu->ilu_struct_size;
	sbdIoctl.stmf_obuf = (uint64_t)(unsigned long)sbdLu;

	ioctlRet = ioctl(fd, SBD_IOCTL_IMPORT_LU, &sbdIoctl);
	if (ioctlRet != 0) {

		if (createdGuid && sbdIoctl.stmf_error ==
		    SBD_RET_FILE_ALREADY_REGISTERED) {
			bcopy(sbdLu->ilu_ret_guid, createdGuid->guid,
			    sizeof (sbdLu->ilu_ret_guid));
		}

		savedErrno = errno;
		switch (savedErrno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				diskError(sbdIoctl.stmf_error, &ret);
				if (ret == STMF_STATUS_ERROR) {
					syslog(LOG_DEBUG,
					"importDiskLu:ioctl "
					"error(%d) (%d) (%d)", ioctlRet,
					    sbdIoctl.stmf_error, savedErrno);
				}
				break;
		}
	}


	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	/*
	 * on success, copy the resulting guid into the caller's guid if not
	 * NULL and add it to the persistent store for sbd
	 */
	if (createdGuid) {
		bcopy(sbdLu->ilu_ret_guid, createdGuid->guid,
		    sizeof (sbdLu->ilu_ret_guid));
		ret = addGuidToDiskStore(createdGuid, fname);
	} else {
		bcopy(sbdLu->ilu_ret_guid, iGuid.guid,
		    sizeof (sbdLu->ilu_ret_guid));
		ret = addGuidToDiskStore(&iGuid, fname);
	}
done:
	free(sbdLu);
	(void) close(fd);
	return (ret);
}

/*
 * diskError
 *
 * Purpose: Translate sbd driver error
 */
static void
diskError(uint32_t stmfError, int *ret)
{
	switch (stmfError) {
		case SBD_RET_META_CREATION_FAILED:
		case SBD_RET_ZFS_META_CREATE_FAILED:
			*ret = STMF_ERROR_META_CREATION;
			break;
		case SBD_RET_INVALID_BLKSIZE:
			*ret = STMF_ERROR_INVALID_BLKSIZE;
			break;
		case SBD_RET_FILE_ALREADY_REGISTERED:
			*ret = STMF_ERROR_FILE_IN_USE;
			break;
		case SBD_RET_GUID_ALREADY_REGISTERED:
			*ret = STMF_ERROR_GUID_IN_USE;
			break;
		case SBD_RET_META_PATH_NOT_ABSOLUTE:
		case SBD_RET_META_FILE_LOOKUP_FAILED:
		case SBD_RET_META_FILE_OPEN_FAILED:
		case SBD_RET_META_FILE_GETATTR_FAILED:
		case SBD_RET_NO_META:
			*ret = STMF_ERROR_META_FILE_NAME;
			break;
		case SBD_RET_DATA_PATH_NOT_ABSOLUTE:
		case SBD_RET_DATA_FILE_LOOKUP_FAILED:
		case SBD_RET_DATA_FILE_OPEN_FAILED:
		case SBD_RET_DATA_FILE_GETATTR_FAILED:
			*ret = STMF_ERROR_DATA_FILE_NAME;
			break;
		case SBD_RET_FILE_SIZE_ERROR:
			*ret = STMF_ERROR_FILE_SIZE_INVALID;
			break;
		case SBD_RET_SIZE_OUT_OF_RANGE:
			*ret = STMF_ERROR_SIZE_OUT_OF_RANGE;
			break;
		case SBD_RET_LU_BUSY:
			*ret = STMF_ERROR_LU_BUSY;
			break;
		case SBD_RET_WRITE_CACHE_SET_FAILED:
			*ret = STMF_ERROR_WRITE_CACHE_SET;
			break;
		case SBD_RET_ACCESS_STATE_FAILED:
			*ret = STMF_ERROR_ACCESS_STATE_SET;
			break;
		default:
			*ret = STMF_STATUS_ERROR;
			break;
	}
}

/*
 * Creates a logical unit resource of type STMF_DISK.
 *
 * No defaults should be set here as all defaults are derived from the
 * driver's default settings.
 */
static int
createDiskResource(luResourceImpl *hdl)
{
	hdl->type = STMF_DISK;

	hdl->resource = calloc(1, sizeof (diskResource));
	if (hdl->resource == NULL) {
		return (STMF_ERROR_NOMEM);
	}

	return (STMF_STATUS_SUCCESS);
}

/*
 * stmfDeleteLu
 *
 * Purpose: Delete a logical unit
 *
 * hdl - handle to logical unit resource created via stmfCreateLuResource
 *
 * luGuid - If non-NULL, on success, contains the guid of the created logical
 *	    unit
 */
int
stmfDeleteLu(stmfGuid *luGuid)
{
	int ret = STMF_STATUS_SUCCESS;
	stmfLogicalUnitProperties luProps;

	if (luGuid == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* Check logical unit provider name to call correct dtype function */
	if ((ret = stmfGetLogicalUnitProperties(luGuid, &luProps))
	    != STMF_STATUS_SUCCESS) {
		return (ret);
	} else {
		if (strcmp(luProps.providerName, "sbd") == 0) {
			ret = deleteDiskLu(luGuid);
		} else if (luProps.status == STMF_LOGICAL_UNIT_UNREGISTERED) {
			return (STMF_ERROR_NOT_FOUND);
		} else {
			return (STMF_ERROR_INVALID_ARG);
		}
	}

	return (ret);
}

static int
deleteDiskLu(stmfGuid *luGuid)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	int savedErrno;
	int ioctlRet;
	sbd_delete_lu_t deleteLu = {0};

	stmf_iocdata_t sbdIoctl = {0};

	/*
	 * Open control node for sbd
	 */
	if ((ret = openSbd(OPEN_SBD, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	ret = removeGuidFromDiskStore(luGuid);
	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	bcopy(luGuid, deleteLu.dlu_guid, sizeof (deleteLu.dlu_guid));
	deleteLu.dlu_by_guid = 1;

	sbdIoctl.stmf_version = STMF_VERSION_1;
	sbdIoctl.stmf_ibuf_size = sizeof (deleteLu);
	sbdIoctl.stmf_ibuf = (uint64_t)(unsigned long)&deleteLu;
	ioctlRet = ioctl(fd, SBD_IOCTL_DELETE_LU, &sbdIoctl);
	if (ioctlRet != 0) {
		savedErrno = errno;
		switch (savedErrno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			case ENOENT:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			default:
				syslog(LOG_DEBUG,
				    "deleteDiskLu:ioctl error(%d) (%d) (%d)",
				    ioctlRet, sbdIoctl.stmf_error, savedErrno);
				ret = STMF_STATUS_ERROR;
				break;
		}
	}

done:
	(void) close(fd);
	return (ret);
}

/*
 * stmfLuStandby
 *
 * Purpose: Sets access state to standby
 *
 * luGuid - guid of registered logical unit
 *
 */
int
stmfLuStandby(stmfGuid *luGuid)
{
	int ret = STMF_STATUS_SUCCESS;
	stmfLogicalUnitProperties luProps;

	if (luGuid == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* Check logical unit provider name to call correct dtype function */
	if ((ret = stmfGetLogicalUnitProperties(luGuid, &luProps))
	    != STMF_STATUS_SUCCESS) {
		return (ret);
	} else {
		if (strcmp(luProps.providerName, "sbd") == 0) {
			ret = setDiskStandby(luGuid);
		} else if (luProps.status == STMF_LOGICAL_UNIT_UNREGISTERED) {
			return (STMF_ERROR_NOT_FOUND);
		} else {
			return (STMF_ERROR_INVALID_ARG);
		}
	}

	return (ret);
}

static int
setDiskStandby(stmfGuid *luGuid)
{
	int ret = STMF_STATUS_SUCCESS;
	stmf_iocdata_t sbdIoctl = {0};
	sbd_set_lu_standby_t sbdLu = {0};
	int ioctlRet;
	int savedErrno;
	int fd = 0;

	/*
	 * Open control node for sbd
	 */
	if ((ret = openSbd(OPEN_SBD, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	bcopy(luGuid, &sbdLu.stlu_guid, sizeof (stmfGuid));

	sbdIoctl.stmf_version = STMF_VERSION_1;
	sbdIoctl.stmf_ibuf_size = sizeof (sbd_set_lu_standby_t);
	sbdIoctl.stmf_ibuf = (uint64_t)(unsigned long)&sbdLu;

	ioctlRet = ioctl(fd, SBD_IOCTL_SET_LU_STANDBY, &sbdIoctl);
	if (ioctlRet != 0) {
		savedErrno = errno;
		switch (savedErrno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				diskError(sbdIoctl.stmf_error, &ret);
				if (ret == STMF_STATUS_ERROR) {
					syslog(LOG_DEBUG,
					"setDiskStandby:ioctl "
					"error(%d) (%d) (%d)", ioctlRet,
					    sbdIoctl.stmf_error, savedErrno);
				}
				break;
		}
	}
	(void) close(fd);
	return (ret);
}

/*
 * stmfModifyLu
 *
 * Purpose: Modify properties of a logical unit
 *
 * luGuid - guid of registered logical unit
 * prop - property to modify
 * propVal - property value to set
 *
 */
int
stmfModifyLu(stmfGuid *luGuid, uint32_t prop, const char *propVal)
{
	int ret = STMF_STATUS_SUCCESS;
	stmfLogicalUnitProperties luProps;

	if (luGuid == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* Check logical unit provider name to call correct dtype function */
	if ((ret = stmfGetLogicalUnitProperties(luGuid, &luProps))
	    != STMF_STATUS_SUCCESS) {
		return (ret);
	} else {
		if (strcmp(luProps.providerName, "sbd") == 0) {
			ret = modifyDiskLuProp(luGuid, NULL, prop, propVal);
		} else if (luProps.status == STMF_LOGICAL_UNIT_UNREGISTERED) {
			return (STMF_ERROR_NOT_FOUND);
		} else {
			return (STMF_ERROR_INVALID_ARG);
		}
	}

	return (ret);
}

/*
 * stmfModifyLuByFname
 *
 * Purpose: Modify a device by filename. Device does not need to be registered.
 *
 * dType - type of device to modify
 *         STMF_DISK
 *
 * fname - filename or meta filename
 * prop - valid property identifier
 * propVal - property value
 *
 */
int
stmfModifyLuByFname(uint16_t dType, const char *fname, uint32_t prop,
    const char *propVal)
{
	int ret = STMF_STATUS_SUCCESS;
	if (fname == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (dType == STMF_DISK) {
		ret = modifyDiskLuProp(NULL, fname, prop, propVal);
	} else {
		return (STMF_ERROR_INVALID_ARG);
	}

	return (ret);
}

static int
modifyDiskLuProp(stmfGuid *luGuid, const char *fname, uint32_t prop,
    const char *propVal)
{
	int ret = STMF_STATUS_SUCCESS;
	luResource hdl = NULL;
	luResourceImpl *luPropsHdl;

	ret = stmfCreateLuResource(STMF_DISK, &hdl);
	if (ret != STMF_STATUS_SUCCESS) {
		return (ret);
	}
	ret = validateModifyDiskProp(prop);
	if (ret != STMF_STATUS_SUCCESS) {
		(void) stmfFreeLuResource(hdl);
		return (STMF_ERROR_INVALID_PROP);
	}
	ret = stmfSetLuProp(hdl, prop, propVal);
	if (ret != STMF_STATUS_SUCCESS) {
		(void) stmfFreeLuResource(hdl);
		return (ret);
	}
	luPropsHdl = hdl;
	ret = modifyDiskLu((diskResource *)luPropsHdl->resource, luGuid, fname);
	(void) stmfFreeLuResource(hdl);
	return (ret);
}

static int
validateModifyDiskProp(uint32_t prop)
{
	switch (prop) {
		case STMF_LU_PROP_ALIAS:
		case STMF_LU_PROP_SIZE:
		case STMF_LU_PROP_MGMT_URL:
		case STMF_LU_PROP_WRITE_PROTECT:
		case STMF_LU_PROP_WRITE_CACHE_DISABLE:
			return (STMF_STATUS_SUCCESS);
		default:
			return (STMF_STATUS_ERROR);
	}
}

static int
modifyDiskLu(diskResource *disk, stmfGuid *luGuid, const char *fname)
{
	int ret = STMF_STATUS_SUCCESS;
	int luAliasLen = 0;
	int luMgmtUrlLen = 0;
	int mluBufSize = 0;
	int bufOffset = 0;
	int fd = 0;
	int ioctlRet;
	int savedErrno;
	int fnameSize = 0;
	stmf_iocdata_t sbdIoctl = {0};

	sbd_modify_lu_t *sbdLu = NULL;

	if (luGuid == NULL && fname == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (fname) {
		fnameSize = strlen(fname) + 1;
		mluBufSize += fnameSize;
	}

	/*
	 * Open control node for sbd
	 */
	if ((ret = openSbd(OPEN_SBD, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	if (disk->luAliasValid) {
		luAliasLen = strlen(disk->luAlias);
		mluBufSize += luAliasLen + 1;
	}

	if (disk->luMgmtUrlValid) {
		luMgmtUrlLen = strlen(disk->luMgmtUrl);
		mluBufSize += luMgmtUrlLen + 1;
	}

	/*
	 * 8 is the size of the buffer set aside for
	 * concatenation of variable length fields
	 */
	sbdLu = (sbd_modify_lu_t *)calloc(1,
	    sizeof (sbd_modify_lu_t) + mluBufSize - 8 + fnameSize);
	if (sbdLu == NULL) {
		(void) close(fd);
		return (STMF_ERROR_NOMEM);
	}

	sbdLu->mlu_struct_size = sizeof (sbd_modify_lu_t) +
	    mluBufSize - 8 + fnameSize;

	if (disk->luAliasValid) {
		sbdLu->mlu_alias_valid = 1;
		sbdLu->mlu_alias_off = bufOffset;
		bcopy(disk->luAlias, &(sbdLu->mlu_buf[bufOffset]),
		    luAliasLen + 1);
		bufOffset += luAliasLen + 1;
	}

	if (disk->luMgmtUrlValid) {
		sbdLu->mlu_mgmt_url_valid = 1;
		sbdLu->mlu_mgmt_url_off = bufOffset;
		bcopy(disk->luMgmtUrl, &(sbdLu->mlu_buf[bufOffset]),
		    luMgmtUrlLen + 1);
		bufOffset += luMgmtUrlLen + 1;
	}

	if (disk->luSizeValid) {
		sbdLu->mlu_lu_size_valid = 1;
		sbdLu->mlu_lu_size = disk->luSize;
	}

	if (disk->writeProtectEnableValid) {
		sbdLu->mlu_write_protected_valid = 1;
		if (disk->writeProtectEnable) {
			sbdLu->mlu_write_protected = 1;
		}
	}

	if (disk->writebackCacheDisableValid) {
		sbdLu->mlu_writeback_cache_disable_valid = 1;
		if (disk->writebackCacheDisable) {
			sbdLu->mlu_writeback_cache_disable = 1;
		}
	}

	if (luGuid) {
		bcopy(luGuid, sbdLu->mlu_input_guid, sizeof (stmfGuid));
		sbdLu->mlu_by_guid = 1;
	} else {
		sbdLu->mlu_fname_off = bufOffset;
		bcopy(fname, &(sbdLu->mlu_buf[bufOffset]), fnameSize + 1);
		sbdLu->mlu_by_fname = 1;
	}

	sbdIoctl.stmf_version = STMF_VERSION_1;
	sbdIoctl.stmf_ibuf_size = sbdLu->mlu_struct_size;
	sbdIoctl.stmf_ibuf = (uint64_t)(unsigned long)sbdLu;

	ioctlRet = ioctl(fd, SBD_IOCTL_MODIFY_LU, &sbdIoctl);
	if (ioctlRet != 0) {
		savedErrno = errno;
		switch (savedErrno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				diskError(sbdIoctl.stmf_error, &ret);
				if (ret == STMF_STATUS_ERROR) {
					syslog(LOG_DEBUG,
					"modifyDiskLu:ioctl "
					"error(%d) (%d) (%d)", ioctlRet,
					    sbdIoctl.stmf_error, savedErrno);
				}
				break;
		}
	}

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

done:
	free(sbdLu);
	(void) close(fd);
	return (ret);
}

/*
 * removeGuidFromDiskStore
 *
 * Purpose: delete a logical unit from the sbd provider data
 */
static int
removeGuidFromDiskStore(stmfGuid *guid)
{
	return (persistDiskGuid(guid, NULL, B_FALSE));
}


/*
 * addGuidToDiskStore
 *
 * Purpose: add a logical unit to the sbd provider data
 */
static int
addGuidToDiskStore(stmfGuid *guid, char *filename)
{
	return (persistDiskGuid(guid, filename, B_TRUE));
}


/*
 * persistDiskGuid
 *
 * Purpose: Persist or unpersist a guid for the sbd provider data
 *
 */
static int
persistDiskGuid(stmfGuid *guid, char *filename, boolean_t persist)
{
	char	    guidAsciiBuf[LU_ASCII_GUID_SIZE + 1] = {0};
	nvlist_t    *nvl = NULL;

	uint64_t    setToken;
	boolean_t   retryGetProviderData = B_FALSE;
	boolean_t   newData = B_FALSE;
	int	    ret = STMF_STATUS_SUCCESS;
	int	    retryCnt = 0;
	int	    stmfRet;

	/* if we're persisting a guid, there must be a filename */
	if (persist && !filename) {
		return (1);
	}

	/* guid is stored in lowercase ascii hex */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
	    "%02x%02x%02x%02x%02x%02x",
	    guid->guid[0], guid->guid[1], guid->guid[2], guid->guid[3],
	    guid->guid[4], guid->guid[5], guid->guid[6], guid->guid[7],
	    guid->guid[8], guid->guid[9], guid->guid[10], guid->guid[11],
	    guid->guid[12], guid->guid[13], guid->guid[14], guid->guid[15]);


	do {
		retryGetProviderData = B_FALSE;
		stmfRet = stmfGetProviderDataProt("sbd", &nvl,
		    STMF_LU_PROVIDER_TYPE, &setToken);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			if (persist && stmfRet == STMF_ERROR_NOT_FOUND) {
				ret = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
				if (ret != 0) {
					syslog(LOG_DEBUG,
					    "unpersistGuid:nvlist_alloc(%d)",
					    ret);
					ret = STMF_STATUS_ERROR;
					goto done;
				}
				newData = B_TRUE;
			} else {
				/*
				 * if we're persisting the data, it's
				 * an error. Otherwise, just return
				 */
				if (persist) {
					ret = stmfRet;
				}
				goto done;
			}
		}
		if (persist) {
			ret = nvlist_add_string(nvl, guidAsciiBuf, filename);
		} else {
			ret = nvlist_remove(nvl, guidAsciiBuf,
			    DATA_TYPE_STRING);
			if (ret == ENOENT) {
				ret = 0;
			}
		}
		if (ret == 0) {
			if (newData) {
				stmfRet = stmfSetProviderDataProt("sbd", nvl,
				    STMF_LU_PROVIDER_TYPE, NULL);
			} else {
				stmfRet = stmfSetProviderDataProt("sbd", nvl,
				    STMF_LU_PROVIDER_TYPE, &setToken);
			}
			if (stmfRet != STMF_STATUS_SUCCESS) {
				if (stmfRet == STMF_ERROR_BUSY) {
					/* get/set failed, try again */
					retryGetProviderData = B_TRUE;
					if (retryCnt++ > MAX_PROVIDER_RETRY) {
						ret = stmfRet;
						break;
					}
					continue;
				} else if (stmfRet ==
				    STMF_ERROR_PROV_DATA_STALE) {
					/* update failed, try again */
					nvlist_free(nvl);
					nvl = NULL;
					retryGetProviderData = B_TRUE;
					if (retryCnt++ > MAX_PROVIDER_RETRY) {
						ret = stmfRet;
						break;
					}
					continue;
				} else {
					syslog(LOG_DEBUG,
					    "unpersistGuid:error(%x)", stmfRet);
					ret = stmfRet;
				}
				break;
			}
		} else {
			syslog(LOG_DEBUG,
			    "unpersistGuid:error nvlist_add/remove(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
		}
	} while (retryGetProviderData);

done:
	nvlist_free(nvl);
	return (ret);
}


/*
 * stmfGetLuProp
 *
 * Purpose: Get current value for a resource property
 *
 * hdl - luResource from a previous call to stmfCreateLuResource
 *
 * resourceProp - a valid resource property type
 *
 * propVal - void pointer to a pointer of the value to be retrieved
 */
int
stmfGetLuProp(luResource hdl, uint32_t prop, char *propVal, size_t *propLen)
{
	int ret = STMF_STATUS_SUCCESS;
	luResourceImpl *luPropsHdl = hdl;
	if (hdl == NULL || propLen == NULL || propVal == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (luPropsHdl->type == STMF_DISK) {
		ret = getDiskProp(luPropsHdl, prop, propVal, propLen);
	} else {
		return (STMF_ERROR_INVALID_ARG);
	}

	return (ret);
}

/*
 * stmfGetLuResource
 *
 * Purpose: Get a logical unit resource handle for a given logical unit.
 *
 * hdl - pointer to luResource
 */
int
stmfGetLuResource(stmfGuid *luGuid, luResource *hdl)
{
	int ret = STMF_STATUS_SUCCESS;
	stmfLogicalUnitProperties luProps;

	if (hdl == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/* Check logical unit provider name to call correct dtype function */
	if ((ret = stmfGetLogicalUnitProperties(luGuid, &luProps))
	    != STMF_STATUS_SUCCESS) {
		return (ret);
	} else {
		if (strcmp(luProps.providerName, "sbd") == 0) {
			ret = getDiskAllProps(luGuid, hdl);
		} else if (luProps.status == STMF_LOGICAL_UNIT_UNREGISTERED) {
			return (STMF_ERROR_NOT_FOUND);
		} else {
			return (STMF_ERROR_INVALID_ARG);
		}
	}

	return (ret);
}

/*
 * getDiskAllProps
 *
 * Purpose: load all disk properties from sbd driver
 *
 * luGuid - guid of disk device for which properties are to be retrieved
 * hdl - allocated luResource into which properties are to be copied
 *
 */
static int
getDiskAllProps(stmfGuid *luGuid, luResource *hdl)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	sbd_lu_props_t *sbdProps;
	int ioctlRet;
	int savedErrno;
	int sbdPropsSize = sizeof (*sbdProps) + MAX_SBD_PROPS;
	stmf_iocdata_t sbdIoctl = {0};

	/*
	 * Open control node for sbd
	 */
	if ((ret = openSbd(OPEN_SBD, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);


	*hdl = calloc(1, sizeof (luResourceImpl));
	if (*hdl == NULL) {
		(void) close(fd);
		return (STMF_ERROR_NOMEM);
	}

	sbdProps = calloc(1, sbdPropsSize);
	if (sbdProps == NULL) {
		free(*hdl);
		(void) close(fd);
		return (STMF_ERROR_NOMEM);
	}

	ret = createDiskResource((luResourceImpl *)*hdl);
	if (ret != STMF_STATUS_SUCCESS) {
		free(*hdl);
		free(sbdProps);
		(void) close(fd);
		return (ret);
	}

	sbdProps->slp_input_guid = 1;
	bcopy(luGuid, sbdProps->slp_guid, sizeof (sbdProps->slp_guid));

	sbdIoctl.stmf_version = STMF_VERSION_1;
	sbdIoctl.stmf_ibuf_size = sbdPropsSize;
	sbdIoctl.stmf_ibuf = (uint64_t)(unsigned long)sbdProps;
	sbdIoctl.stmf_obuf_size = sbdPropsSize;
	sbdIoctl.stmf_obuf = (uint64_t)(unsigned long)sbdProps;
	ioctlRet = ioctl(fd, SBD_IOCTL_GET_LU_PROPS, &sbdIoctl);
	if (ioctlRet != 0) {
		savedErrno = errno;
		switch (savedErrno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			case ENOENT:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			default:
				syslog(LOG_DEBUG,
				    "getDiskAllProps:ioctl error(%d) (%d) (%d)",
				    ioctlRet, sbdIoctl.stmf_error, savedErrno);
				ret = STMF_STATUS_ERROR;
				break;
		}
	}

	if (ret == STMF_STATUS_SUCCESS) {
		ret = loadDiskPropsFromDriver((luResourceImpl *)*hdl, sbdProps);
	}

	free(sbdProps);
	(void) close(fd);
	return (ret);
}

/*
 * loadDiskPropsFromDriver
 *
 * Purpose: Retrieve all disk type properties from sbd driver
 *
 * hdl - Allocated luResourceImpl
 * sbdProps - sbd_lu_props_t structure returned from sbd driver
 *
 */
static int
loadDiskPropsFromDriver(luResourceImpl *hdl, sbd_lu_props_t *sbdProps)
{
	int ret = STMF_STATUS_SUCCESS;
	diskResource *diskLu = hdl->resource;
	/* copy guid */
	diskLu->luGuidValid = B_TRUE;
	bcopy(sbdProps->slp_guid, diskLu->luGuid, sizeof (sbdProps->slp_guid));

	if (sbdProps->slp_separate_meta && sbdProps->slp_meta_fname_valid) {
		diskLu->luMetaFileNameValid = B_TRUE;
		if (strlcpy(diskLu->luMetaFileName,
		    (char *)&(sbdProps->slp_buf[sbdProps->slp_meta_fname_off]),
		    sizeof (diskLu->luMetaFileName)) >=
		    sizeof (diskLu->luMetaFileName)) {
			return (STMF_STATUS_ERROR);
		}
	}

	if (sbdProps->slp_data_fname_valid) {
		diskLu->luDataFileNameValid = B_TRUE;
		if (strlcpy(diskLu->luDataFileName,
		    (char *)&(sbdProps->slp_buf[sbdProps->slp_data_fname_off]),
		    sizeof (diskLu->luDataFileName)) >=
		    sizeof (diskLu->luDataFileName)) {
			return (STMF_STATUS_ERROR);
		}
	}

	if (sbdProps->slp_serial_valid) {
		diskLu->serialNumValid = B_TRUE;
		bcopy(&(sbdProps->slp_buf[sbdProps->slp_serial_off]),
		    diskLu->serialNum, sbdProps->slp_serial_size);
	}

	if (sbdProps->slp_mgmt_url_valid) {
		diskLu->luMgmtUrlValid = B_TRUE;
		if (strlcpy(diskLu->luMgmtUrl,
		    (char *)&(sbdProps->slp_buf[sbdProps->slp_mgmt_url_off]),
		    sizeof (diskLu->luMgmtUrl)) >=
		    sizeof (diskLu->luMgmtUrl)) {
			return (STMF_STATUS_ERROR);
		}
	}

	if (sbdProps->slp_alias_valid) {
		diskLu->luAliasValid = B_TRUE;
		if (strlcpy(diskLu->luAlias,
		    (char *)&(sbdProps->slp_buf[sbdProps->slp_alias_off]),
		    sizeof (diskLu->luAlias)) >=
		    sizeof (diskLu->luAlias)) {
			return (STMF_STATUS_ERROR);
		}
	} else { /* set alias to data filename if not set */
		if (sbdProps->slp_data_fname_valid) {
			diskLu->luAliasValid = B_TRUE;
			if (strlcpy(diskLu->luAlias,
			    (char *)&(sbdProps->slp_buf[
			    sbdProps->slp_data_fname_off]),
			    sizeof (diskLu->luAlias)) >=
			    sizeof (diskLu->luAlias)) {
				return (STMF_STATUS_ERROR);
			}
		}
	}

	diskLu->vidValid = B_TRUE;
	bcopy(sbdProps->slp_vid, diskLu->vid, sizeof (diskLu->vid));

	diskLu->pidValid = B_TRUE;
	bcopy(sbdProps->slp_pid, diskLu->pid, sizeof (diskLu->pid));

	diskLu->revValid = B_TRUE;
	bcopy(sbdProps->slp_rev, diskLu->rev, sizeof (diskLu->rev));

	diskLu->writeProtectEnableValid = B_TRUE;
	if (sbdProps->slp_write_protected) {
		diskLu->writeProtectEnable = B_TRUE;
	}

	diskLu->writebackCacheDisableValid = B_TRUE;
	if (sbdProps->slp_writeback_cache_disable_cur) {
		diskLu->writebackCacheDisable = B_TRUE;
	}

	diskLu->blkSizeValid = B_TRUE;
	diskLu->blkSize = sbdProps->slp_blksize;

	diskLu->luSizeValid = B_TRUE;
	diskLu->luSize = sbdProps->slp_lu_size;

	diskLu->accessState = sbdProps->slp_access_state;

	return (ret);
}

/*
 * stmfGetGlobalLuProp
 *
 * Purpose: get a global property for a device type
 *
 */
int
stmfGetGlobalLuProp(uint16_t dType, uint32_t prop, char *propVal,
    size_t *propLen)
{
	int ret = STMF_STATUS_SUCCESS;
	if (dType != STMF_DISK || propVal == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = getDiskGlobalProp(prop, propVal, propLen);

	return (ret);
}

/*
 * getDiskGlobalProp
 *
 * Purpose: get global property from sbd driver
 *
 */
static int
getDiskGlobalProp(uint32_t prop, char *propVal, size_t *propLen)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	sbd_global_props_t *sbdProps;
	void *sbd_realloc;
	int retryCnt = 0;
	boolean_t retry;
	int ioctlRet;
	int savedErrno;
	int sbdPropsSize = sizeof (*sbdProps) + MAX_SBD_PROPS;
	stmf_iocdata_t sbdIoctl = {0};
	size_t reqLen;

	switch (prop) {
		case STMF_LU_PROP_MGMT_URL:
			break;
		default:
			return (STMF_ERROR_INVALID_PROP);
	}

	/*
	 * Open control node for sbd
	 */
	if ((ret = openSbd(OPEN_SBD, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	sbdProps = calloc(1, sbdPropsSize);
	if (sbdProps == NULL) {
		(void) close(fd);
		return (STMF_ERROR_NOMEM);
	}

	do {
		retry = B_FALSE;
		sbdIoctl.stmf_version = STMF_VERSION_1;
		sbdIoctl.stmf_obuf_size = sbdPropsSize;
		sbdIoctl.stmf_obuf = (uint64_t)(unsigned long)sbdProps;
		ioctlRet = ioctl(fd, SBD_IOCTL_GET_GLOBAL_LU, &sbdIoctl);
		if (ioctlRet != 0) {
			savedErrno = errno;
			switch (savedErrno) {
				case EBUSY:
					ret = STMF_ERROR_BUSY;
					break;
				case EPERM:
				case EACCES:
					ret = STMF_ERROR_PERM;
					break;
				case ENOMEM:
					if (sbdIoctl.stmf_error ==
					    SBD_RET_INSUFFICIENT_BUF_SPACE &&
					    retryCnt++ < 3) {
						sbdPropsSize =
						    sizeof (*sbdProps) +
						    sbdProps->
						    mlu_buf_size_needed;

						sbd_realloc = sbdProps;
						sbdProps = realloc(sbdProps,
						    sbdPropsSize);
						if (sbdProps == NULL) {
							free(sbd_realloc);
							ret = STMF_ERROR_NOMEM;
							break;
						}
						retry = B_TRUE;
					} else {
						ret = STMF_ERROR_NOMEM;
					}
					break;
				default:
					syslog(LOG_DEBUG,
					    "getDiskGlobalProp:ioctl error(%d)"
					    "(%d)(%d)", ioctlRet,
					    sbdIoctl.stmf_error, savedErrno);
					ret = STMF_STATUS_ERROR;
					break;
			}

		}
	} while (retry);

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	switch (prop) {
		case STMF_LU_PROP_MGMT_URL:
			if (sbdProps->mlu_mgmt_url_valid == 0) {
				ret = STMF_ERROR_NO_PROP;
				goto done;
			}
			if ((reqLen = strlcpy(propVal, (char *)&(
			    sbdProps->mlu_buf[sbdProps->mlu_mgmt_url_off]),
			    *propLen)) >= *propLen) {
				*propLen = reqLen + 1;
				ret = STMF_ERROR_INVALID_ARG;
				goto done;
			}
			break;
	}

done:
	free(sbdProps);
	(void) close(fd);
	return (ret);
}

/*
 * stmfSetGlobalLuProp
 *
 * Purpose: set a global property for a device type
 *
 */
int
stmfSetGlobalLuProp(uint16_t dType, uint32_t prop, const char *propVal)
{
	int ret = STMF_STATUS_SUCCESS;
	if (dType != STMF_DISK || propVal == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = setDiskGlobalProp(prop, propVal);

	return (ret);
}

/*
 * setDiskGlobalProp
 *
 * Purpose: set properties for resource of type disk
 *
 * resourceProp - valid resource identifier
 * propVal - valid resource value
 */
static int
setDiskGlobalProp(uint32_t resourceProp, const char *propVal)
{
	int ret = STMF_STATUS_SUCCESS;
	sbd_global_props_t *sbdGlobalProps = NULL;
	int sbdGlobalPropsSize = 0;
	int propLen;
	int mluBufSize = 0;
	int fd;
	int savedErrno;
	int ioctlRet;
	stmf_iocdata_t sbdIoctl = {0};

	switch (resourceProp) {
		case STMF_LU_PROP_MGMT_URL:
			break;
		default:
			return (STMF_ERROR_INVALID_PROP);
	}

	/*
	 * Open control node for sbd
	 */
	if ((ret = openSbd(OPEN_SBD, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	propLen = strlen(propVal);
	mluBufSize += propLen + 1;
	sbdGlobalPropsSize += sizeof (sbd_global_props_t) - 8 +
	    max(8, mluBufSize);
	/*
	 * 8 is the size of the buffer set aside for
	 * concatenation of variable length fields
	 */
	sbdGlobalProps = (sbd_global_props_t *)calloc(1, sbdGlobalPropsSize);
	if (sbdGlobalProps == NULL) {
		(void) close(fd);
		return (STMF_ERROR_NOMEM);
	}

	sbdGlobalProps->mlu_struct_size = sbdGlobalPropsSize;

	switch (resourceProp) {
		case STMF_LU_PROP_MGMT_URL:
			sbdGlobalProps->mlu_mgmt_url_valid = 1;
			bcopy(propVal, &(sbdGlobalProps->mlu_buf),
			    propLen + 1);
			break;
		default:
			ret = STMF_ERROR_NO_PROP;
			goto done;
	}

	sbdIoctl.stmf_version = STMF_VERSION_1;
	sbdIoctl.stmf_ibuf_size = sbdGlobalProps->mlu_struct_size;
	sbdIoctl.stmf_ibuf = (uint64_t)(unsigned long)sbdGlobalProps;

	ioctlRet = ioctl(fd, SBD_IOCTL_SET_GLOBAL_LU, &sbdIoctl);
	if (ioctlRet != 0) {
		savedErrno = errno;
		switch (savedErrno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				diskError(sbdIoctl.stmf_error, &ret);
				if (ret == STMF_STATUS_ERROR) {
					syslog(LOG_DEBUG,
					"modifyDiskLu:ioctl "
					"error(%d) (%d) (%d)", ioctlRet,
					    sbdIoctl.stmf_error, savedErrno);
				}
				break;
		}
	}

done:
	free(sbdGlobalProps);
	(void) close(fd);
	return (ret);
}


/*
 * stmfSetLuProp
 *
 * Purpose: set a property on an luResource
 *
 * hdl - allocated luResource
 * prop - property identifier
 * propVal - property value to be set
 */
int
stmfSetLuProp(luResource hdl, uint32_t prop, const char *propVal)
{
	int ret = STMF_STATUS_SUCCESS;
	luResourceImpl *luPropsHdl = hdl;
	if (hdl == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (luPropsHdl->type == STMF_DISK) {
		ret = setDiskProp(luPropsHdl, prop, propVal);
	} else {
		return (STMF_ERROR_INVALID_ARG);
	}

	return (ret);
}

/*
 * getDiskProp
 *
 * Purpose: retrieve a given property from a logical unit resource of type disk
 *
 * hdl - allocated luResourceImpl
 * prop - property identifier
 * propVal - pointer to character to contain the retrieved property value
 * propLen - On input this is the length of propVal. On failure, it contains the
 *           number of bytes required for propVal
 */
static int
getDiskProp(luResourceImpl *hdl, uint32_t prop, char *propVal, size_t *propLen)
{
	int ret = STMF_STATUS_SUCCESS;
	diskResource *diskLu = hdl->resource;
	char accessState[20];
	size_t reqLen;

	if (prop == STMF_LU_PROP_ACCESS_STATE) {
		if (diskLu->accessState == SBD_LU_ACTIVE) {
			(void) strlcpy(accessState, STMF_ACCESS_ACTIVE,
			    sizeof (accessState));
		} else if (diskLu->accessState == SBD_LU_TRANSITION_TO_ACTIVE) {
			(void) strlcpy(accessState,
			    STMF_ACCESS_STANDBY_TO_ACTIVE,
			    sizeof (accessState));
		} else if (diskLu->accessState == SBD_LU_STANDBY) {
			(void) strlcpy(accessState, STMF_ACCESS_STANDBY,
			    sizeof (accessState));
		} else if (diskLu->accessState ==
		    SBD_LU_TRANSITION_TO_STANDBY) {
			(void) strlcpy(accessState,
			    STMF_ACCESS_ACTIVE_TO_STANDBY,
			    sizeof (accessState));
		}
		if ((reqLen = strlcpy(propVal, accessState,
		    *propLen)) >= *propLen) {
			*propLen = reqLen + 1;
			return (STMF_ERROR_INVALID_ARG);
		}
		return (0);
	}

	if (diskLu->accessState != SBD_LU_ACTIVE) {
		return (STMF_ERROR_NO_PROP_STANDBY);
	}

	switch (prop) {
		case STMF_LU_PROP_BLOCK_SIZE:
			if (diskLu->blkSizeValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			reqLen = snprintf(propVal, *propLen, "%llu",
			    (u_longlong_t)diskLu->blkSize);
			if (reqLen >= *propLen) {
				*propLen = reqLen + 1;
				return (STMF_ERROR_INVALID_ARG);
			}
			break;
		case STMF_LU_PROP_FILENAME:
			if (diskLu->luDataFileNameValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if ((reqLen = strlcpy(propVal, diskLu->luDataFileName,
			    *propLen)) >= *propLen) {
				*propLen = reqLen + 1;
				return (STMF_ERROR_INVALID_ARG);
			}
			break;
		case STMF_LU_PROP_META_FILENAME:
			if (diskLu->luMetaFileNameValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if ((reqLen = strlcpy(propVal, diskLu->luMetaFileName,
			    *propLen)) >= *propLen) {
				*propLen = reqLen + 1;
				return (STMF_ERROR_INVALID_ARG);
			}
			break;
		case STMF_LU_PROP_MGMT_URL:
			if (diskLu->luMgmtUrlValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if ((reqLen = strlcpy(propVal, diskLu->luMgmtUrl,
			    *propLen)) >= *propLen) {
				*propLen = reqLen + 1;
				return (STMF_ERROR_INVALID_ARG);
			}
			break;
		case STMF_LU_PROP_GUID:
			if (diskLu->luGuidValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			reqLen = snprintf(propVal, *propLen,
			    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
			    "%02X%02X%02X%02X",
			    diskLu->luGuid[0], diskLu->luGuid[1],
			    diskLu->luGuid[2], diskLu->luGuid[3],
			    diskLu->luGuid[4], diskLu->luGuid[5],
			    diskLu->luGuid[6], diskLu->luGuid[7],
			    diskLu->luGuid[8], diskLu->luGuid[9],
			    diskLu->luGuid[10], diskLu->luGuid[11],
			    diskLu->luGuid[12], diskLu->luGuid[13],
			    diskLu->luGuid[14], diskLu->luGuid[15]);
			if (reqLen >= *propLen) {
				*propLen = reqLen + 1;
				return (STMF_ERROR_INVALID_ARG);
			}
			break;
		case STMF_LU_PROP_SERIAL_NUM:
			if (diskLu->serialNumValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if ((reqLen = strlcpy(propVal, diskLu->serialNum,
			    *propLen)) >= *propLen) {
				*propLen = reqLen + 1;
				return (STMF_ERROR_INVALID_ARG);
			}
			break;
		case STMF_LU_PROP_SIZE:
			if (diskLu->luSizeValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			(void) snprintf(propVal, *propLen, "%llu",
			    (u_longlong_t)diskLu->luSize);
			break;
		case STMF_LU_PROP_ALIAS:
			if (diskLu->luAliasValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if ((reqLen = strlcpy(propVal, diskLu->luAlias,
			    *propLen)) >= *propLen) {
				*propLen = reqLen + 1;
				return (STMF_ERROR_INVALID_ARG);
			}
			break;
		case STMF_LU_PROP_VID:
			if (diskLu->vidValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if (*propLen <= sizeof (diskLu->vid)) {
				return (STMF_ERROR_INVALID_ARG);
			}
			bcopy(diskLu->vid, propVal, sizeof (diskLu->vid));
			propVal[sizeof (diskLu->vid)] = 0;
			break;
		case STMF_LU_PROP_PID:
			if (diskLu->pidValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if (*propLen <= sizeof (diskLu->pid)) {
				return (STMF_ERROR_INVALID_ARG);
			}
			bcopy(diskLu->pid, propVal, sizeof (diskLu->pid));
			propVal[sizeof (diskLu->pid)] = 0;
			break;
		case STMF_LU_PROP_WRITE_PROTECT:
			if (diskLu->writeProtectEnableValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if (diskLu->writeProtectEnable) {
				if ((reqLen = strlcpy(propVal, "true",
				    *propLen)) >= *propLen) {
					*propLen = reqLen + 1;
					return (STMF_ERROR_INVALID_ARG);
				}
			} else {
				if ((reqLen = strlcpy(propVal, "false",
				    *propLen)) >= *propLen) {
					*propLen = reqLen + 1;
					return (STMF_ERROR_INVALID_ARG);
				}
			}
			break;
		case STMF_LU_PROP_WRITE_CACHE_DISABLE:
			if (diskLu->writebackCacheDisableValid == B_FALSE) {
				return (STMF_ERROR_NO_PROP);
			}
			if (diskLu->writebackCacheDisable) {
				if ((reqLen = strlcpy(propVal, "true",
				    *propLen)) >= *propLen) {
					*propLen = reqLen + 1;
					return (STMF_ERROR_INVALID_ARG);
				}
			} else {
				if ((reqLen = strlcpy(propVal, "false",
				    *propLen)) >= *propLen) {
					*propLen = reqLen + 1;
					return (STMF_ERROR_INVALID_ARG);
				}
			}
			break;
		default:
			ret = STMF_ERROR_INVALID_PROP;
			break;
	}

	return (ret);
}

/*
 * setDiskProp
 *
 * Purpose: set properties for resource of type disk
 *
 * hdl - allocated luResourceImpl
 * resourceProp - valid resource identifier
 * propVal - valid resource value
 */
static int
setDiskProp(luResourceImpl *hdl, uint32_t resourceProp, const char *propVal)
{
	int ret = STMF_STATUS_SUCCESS;
	int i;
	diskResource *diskLu = hdl->resource;
	unsigned long long numericProp = 0;
	char guidProp[LU_ASCII_GUID_SIZE + 1];
	char ouiProp[OUI_ASCII_SIZE + 1];
	char hostIdProp[HOST_ID_ASCII_SIZE + 1];
	unsigned int oui[OUI_SIZE];
	unsigned int hostId[HOST_ID_SIZE];
	unsigned int guid[LU_GUID_SIZE];
	int propSize;


	if (propVal == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	switch (resourceProp) {
		case STMF_LU_PROP_ALIAS:
			if (strlcpy(diskLu->luAlias, propVal,
			    sizeof (diskLu->luAlias)) >=
			    sizeof (diskLu->luAlias)) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}
			diskLu->luAliasValid = B_TRUE;
			break;
		case STMF_LU_PROP_BLOCK_SIZE: {
			const char *tmp = propVal;
			while (*tmp) {
				if (!isdigit(*tmp++)) {
					return (STMF_ERROR_INVALID_ARG);
				}
			}
			(void) sscanf(propVal, "%llu", &numericProp);
			if (numericProp > UINT16_MAX) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}
			diskLu->blkSize = numericProp;
			diskLu->blkSizeValid = B_TRUE;
			break;
		}
		case STMF_LU_PROP_COMPANY_ID:
			if ((strlcpy(ouiProp, propVal, sizeof (ouiProp))) >=
			    sizeof (ouiProp)) {
				return (STMF_ERROR_INVALID_ARG);
			}
			if (checkHexUpper(ouiProp) != 0) {
				return (STMF_ERROR_INVALID_ARG);
			}
			(void) sscanf(ouiProp, "%2X%2X%2X",
			    &oui[0], &oui[1], &oui[2]);

			diskLu->companyId = 0;
			diskLu->companyId += oui[0] << 16;
			diskLu->companyId += oui[1] << 8;
			diskLu->companyId += oui[2];
			if (diskLu->companyId == 0) {
				return (STMF_ERROR_INVALID_ARG);
			}
			diskLu->companyIdValid = B_TRUE;
			break;
		case STMF_LU_PROP_HOST_ID:
			if ((strlcpy(hostIdProp, propVal,
			    sizeof (hostIdProp))) >= sizeof (hostIdProp)) {
				return (STMF_ERROR_INVALID_ARG);
			}
			if (checkHexUpper(hostIdProp) != 0) {
				return (STMF_ERROR_INVALID_ARG);
			}
			(void) sscanf(hostIdProp, "%2X%2X%2X%2X",
			    &hostId[0], &hostId[1], &hostId[2], &hostId[3]);

			diskLu->hostId = 0;
			diskLu->hostId += hostId[0] << 24;
			diskLu->hostId += hostId[1] << 16;
			diskLu->hostId += hostId[2] << 8;
			diskLu->hostId += hostId[3];
			if (diskLu->hostId == 0) {
				return (STMF_ERROR_INVALID_ARG);
			}
			diskLu->hostIdValid = B_TRUE;
			break;
		case STMF_LU_PROP_GUID:
			if (strlen(propVal) != LU_ASCII_GUID_SIZE) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}

			if ((strlcpy(guidProp, propVal, sizeof (guidProp))) >=
			    sizeof (guidProp)) {
				return (STMF_ERROR_INVALID_ARG);
			}

			if (checkHexUpper(guidProp) != 0) {
				return (STMF_ERROR_INVALID_ARG);
			}

			(void) sscanf(guidProp,
			    "%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X",
			    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4],
			    &guid[5], &guid[6], &guid[7], &guid[8], &guid[9],
			    &guid[10], &guid[11], &guid[12], &guid[13],
			    &guid[14], &guid[15]);
			for (i = 0; i < sizeof (diskLu->luGuid); i++) {
				diskLu->luGuid[i] = guid[i];
			}
			diskLu->luGuidValid = B_TRUE;
			break;
		case STMF_LU_PROP_FILENAME:
			if ((strlcpy(diskLu->luDataFileName, propVal,
			    sizeof (diskLu->luDataFileName))) >=
			    sizeof (diskLu->luDataFileName)) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}
			diskLu->luDataFileNameValid = B_TRUE;
			break;
		case STMF_LU_PROP_META_FILENAME:
			if ((strlcpy(diskLu->luMetaFileName, propVal,
			    sizeof (diskLu->luMetaFileName))) >=
			    sizeof (diskLu->luMetaFileName)) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}
			diskLu->luMetaFileNameValid = B_TRUE;
			break;
		case STMF_LU_PROP_MGMT_URL:
			if ((strlcpy(diskLu->luMgmtUrl, propVal,
			    sizeof (diskLu->luMgmtUrl))) >=
			    sizeof (diskLu->luMgmtUrl)) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}
			diskLu->luMgmtUrlValid = B_TRUE;
			break;
		case STMF_LU_PROP_PID:
			if ((propSize = strlen(propVal)) >
			    sizeof (diskLu->pid)) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}
			(void) strncpy(diskLu->pid, propVal, propSize);
			diskLu->pidValid = B_TRUE;
			break;
		case STMF_LU_PROP_SERIAL_NUM:
			if ((propSize = strlen(propVal)) >
			    (sizeof (diskLu->serialNum) - 1)) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}
			(void) strncpy(diskLu->serialNum, propVal, propSize);
			diskLu->serialNumValid = B_TRUE;
			break;
		case STMF_LU_PROP_SIZE:
			if ((niceStrToNum(propVal, &diskLu->luSize) != 0)) {
				return (STMF_ERROR_INVALID_ARG);
			}
			diskLu->luSizeValid = B_TRUE;
			break;
		case STMF_LU_PROP_VID:
			if ((propSize = strlen(propVal)) >
			    sizeof (diskLu->vid)) {
				return (STMF_ERROR_INVALID_PROPSIZE);
			}
			(void) strncpy(diskLu->vid, propVal, propSize);
			diskLu->vidValid = B_TRUE;
			break;
		case STMF_LU_PROP_WRITE_PROTECT:
			if (strcasecmp(propVal, "TRUE") == 0) {
				diskLu->writeProtectEnable = B_TRUE;
			} else if (strcasecmp(propVal, "FALSE") == 0) {
				diskLu->writeProtectEnable = B_FALSE;
			} else {
				return (STMF_ERROR_INVALID_ARG);
			}
			diskLu->writeProtectEnableValid = B_TRUE;
			break;
		case STMF_LU_PROP_WRITE_CACHE_DISABLE:
			if (strcasecmp(propVal, "TRUE") == 0) {
				diskLu->writebackCacheDisable = B_TRUE;
			} else if (strcasecmp(propVal, "FALSE") == 0) {
				diskLu->writebackCacheDisable = B_FALSE;
			} else {
				return (STMF_ERROR_INVALID_ARG);
			}
			diskLu->writebackCacheDisableValid = B_TRUE;
			break;
		case STMF_LU_PROP_ACCESS_STATE:
			ret = STMF_ERROR_INVALID_PROP;
			break;
		default:
			ret = STMF_ERROR_INVALID_PROP;
			break;
	}
	return (ret);
}

static int
checkHexUpper(char *buf)
{
	int i;

	for (i = 0; i < strlen(buf); i++) {
		if (isxdigit(buf[i])) {
			buf[i] = toupper(buf[i]);
			continue;
		}
		return (-1);
	}

	return (0);
}

/*
 * Given a numeric suffix, convert the value into a number of bits that the
 * resulting value must be shifted.
 * Code lifted from libzfs_util.c
 */
static int
strToShift(const char *buf)
{
	const char *ends = "BKMGTPE";
	int i;

	if (buf[0] == '\0')
		return (0);

	for (i = 0; i < strlen(ends); i++) {
		if (toupper(buf[0]) == ends[i])
			return (10*i);
	}

	return (-1);
}

int
stmfFreeLuResource(luResource hdl)
{
	int ret = STMF_STATUS_SUCCESS;
	if (hdl == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	luResourceImpl *hdlImpl = hdl;
	free(hdlImpl->resource);
	free(hdlImpl);
	return (ret);
}

/*
 * Convert a string of the form '100G' into a real number. Used when setting
 * the size of a logical unit.
 * Code lifted from libzfs_util.c
 */
static int
niceStrToNum(const char *value, uint64_t *num)
{
	char *end;
	int shift;

	*num = 0;

	/* Check to see if this looks like a number.  */
	if ((value[0] < '0' || value[0] > '9') && value[0] != '.') {
		return (-1);
	}

	/* Rely on stroull() to process the numeric portion.  */
	errno = 0;
	*num = strtoull(value, &end, 10);

	/*
	 * Check for ERANGE, which indicates that the value is too large to fit
	 * in a 64-bit value.
	 */
	if (errno == ERANGE) {
		return (-1);
	}

	/*
	 * If we have a decimal value, then do the computation with floating
	 * point arithmetic.  Otherwise, use standard arithmetic.
	 */
	if (*end == '.') {
		double fval = strtod(value, &end);

		if ((shift = strToShift(end)) == -1) {
			return (-1);
		}

		fval *= pow(2, shift);

		if (fval > UINT64_MAX) {
			return (-1);
		}

		*num = (uint64_t)fval;
	} else {
		if ((shift = strToShift(end)) == -1) {
			return (-1);
		}

		/* Check for overflow */
		if (shift >= 64 || (*num << shift) >> shift != *num) {
			return (-1);
		}

		*num <<= shift;
	}

	return (0);
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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
stmfDevidFromWwn(uchar_t wwn[8], stmfDevid *devid)
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
 * get host group, target group list from stmf
 *
 * groupType - HOST_GROUP, TARGET_GROUP
 */
static int
groupListIoctl(stmfGroupList **groupList, int groupType)
{
	int ret;
	int fd;
	int ioctlRet;
	int i;
	int cmd;
	stmf_iocdata_t stmfIoctl;
	/* framework group list */
	stmf_group_name_t *iGroupList = NULL;
	uint32_t groupListSize;

	if (groupList == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (groupType == HOST_GROUP) {
		cmd = STMF_IOCTL_GET_HG_LIST;
	} else if (groupType == TARGET_GROUP) {
		cmd = STMF_IOCTL_GET_TG_LIST;
	} else {
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
	groupListSize = ALLOC_GROUP;
	groupListSize = groupListSize * (sizeof (stmf_group_name_t));
	iGroupList = (stmf_group_name_t *)calloc(1, groupListSize);
	if (iGroupList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to get the group list
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_obuf_size = groupListSize;
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)iGroupList;
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
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
				    "groupListIoctl:ioctl errno(%d)",
				    errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}
	/*
	 * Check whether input buffer was large enough
	 */
	if (stmfIoctl.stmf_obuf_max_nentries > ALLOC_GROUP) {
		groupListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (stmf_group_name_t);
		iGroupList = realloc(iGroupList, groupListSize);
		if (iGroupList == NULL) {
			ret = STMF_ERROR_NOMEM;
			goto done;
		}
		stmfIoctl.stmf_obuf_size = groupListSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)iGroupList;
		ioctlRet = ioctl(fd, cmd, &stmfIoctl);
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
					    "groupListIoctl:ioctl errno(%d)",
					    errno);
					ret = STMF_STATUS_ERROR;
					break;
			}
			goto done;
		}
	}

	/* allocate and copy to caller's buffer */
	*groupList = (stmfGroupList *)calloc(1, sizeof (stmfGroupList) +
	    sizeof (stmfGroupName) * stmfIoctl.stmf_obuf_nentries);
	if (*groupList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}
	(*groupList)->cnt = stmfIoctl.stmf_obuf_nentries;
	for (i = 0; i < stmfIoctl.stmf_obuf_nentries; i++) {
		bcopy(iGroupList[i].name, (*groupList)->name[i],
		    sizeof (stmfGroupName));
	}

done:
	free(iGroupList);
	(void) close(fd);
	return (ret);
}

/*
 * get host group members, target group members from stmf
 *
 * groupProps - allocated on success
 *
 * groupType - HOST_GROUP, TARGET_GROUP
 */
static int
groupMemberListIoctl(stmfGroupName *groupName, stmfGroupProperties **groupProps,
    int groupType)
{
	int ret;
	int fd;
	int ioctlRet;
	int i;
	int cmd;
	stmf_iocdata_t stmfIoctl;
	/* framework group list */
	stmf_group_name_t iGroupName;
	stmf_ge_ident_t *iGroupMembers;
	uint32_t groupListSize;

	if (groupName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (groupType == HOST_GROUP) {
		cmd = STMF_IOCTL_GET_HG_ENTRIES;
	} else if (groupType == TARGET_GROUP) {
		cmd = STMF_IOCTL_GET_TG_ENTRIES;
	} else {
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

	bzero(&iGroupName, sizeof (iGroupName));

	bcopy(groupName, &iGroupName.name, strlen((char *)groupName));

	iGroupName.name_size = strlen((char *)groupName);

	/*
	 * Allocate ioctl input buffer
	 */
	groupListSize = ALLOC_GRP_MEMBER;
	groupListSize = groupListSize * (sizeof (stmf_ge_ident_t));
	iGroupMembers = (stmf_ge_ident_t *)calloc(1, groupListSize);
	if (iGroupMembers == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to get the group list
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&iGroupName;
	stmfIoctl.stmf_ibuf_size = sizeof (stmf_group_name_t);
	stmfIoctl.stmf_obuf_size = groupListSize;
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)iGroupMembers;
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
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
				    "groupListIoctl:ioctl errno(%d)",
				    errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}
	/*
	 * Check whether input buffer was large enough
	 */
	if (stmfIoctl.stmf_obuf_max_nentries > ALLOC_GRP_MEMBER) {
		groupListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (stmf_ge_ident_t);
		iGroupMembers = realloc(iGroupMembers, groupListSize);
		if (iGroupMembers == NULL) {
			ret = STMF_ERROR_NOMEM;
			goto done;
		}
		stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&iGroupName;
		stmfIoctl.stmf_ibuf_size = sizeof (stmf_group_name_t);
		stmfIoctl.stmf_obuf_size = groupListSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)iGroupMembers;
		ioctlRet = ioctl(fd, cmd, &stmfIoctl);
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
					    "groupListIoctl:ioctl errno(%d)",
					    errno);
					ret = STMF_STATUS_ERROR;
					break;
			}
			goto done;
		}
	}

	/* allocate and copy to caller's buffer */
	*groupProps = (stmfGroupProperties *)calloc(1,
	    sizeof (stmfGroupProperties) +
	    sizeof (stmfDevid) * stmfIoctl.stmf_obuf_nentries);
	if (*groupProps == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}
	(*groupProps)->cnt = stmfIoctl.stmf_obuf_nentries;
	for (i = 0; i < stmfIoctl.stmf_obuf_nentries; i++) {
		(*groupProps)->name[i].identLength =
		    iGroupMembers[i].ident_size;
		bcopy(iGroupMembers[i].ident, (*groupProps)->name[i].ident,
		    iGroupMembers[i].ident_size);
	}

done:
	free(iGroupMembers);
	(void) close(fd);
	return (ret);
}

/*
 * Purpose: access persistent config data for host groups and target groups
 */
static int
iLoadGroupFromPs(stmfGroupList **groupList, int type)
{
	int ret;

	if (groupList == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (type == HOST_GROUP) {
		ret = psGetHostGroupList(groupList);
	} else if (type == TARGET_GROUP) {
		ret = psGetTargetGroupList(groupList);
	} else {
		return (STMF_ERROR_INVALID_ARG);
	}
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
	int ret = STMF_STATUS_ERROR;

	if (hostGroupList == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	ret = groupListIoctl(hostGroupList, HOST_GROUP);
	return (ret);
}


/*
 * Purpose: access persistent config data for host groups and target groups
 */
static int
iLoadGroupMembersFromPs(stmfGroupName *groupName,
    stmfGroupProperties **groupProp, int type)
{
	int ret;

	if (groupName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (type == HOST_GROUP) {
		ret = psGetHostGroupMemberList((char *)groupName, groupProp);
	} else if (type == TARGET_GROUP) {
		ret = psGetTargetGroupMemberList((char *)groupName, groupProp);
	} else {
		return (STMF_ERROR_INVALID_ARG);
	}
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
			    "iLoadGroupMembersFromPs:psGetHostGroupList:"
			    "error(%d)", ret);
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

	ret = groupMemberListIoctl(groupName, groupProp, HOST_GROUP);

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
	return (getProviderData(providerName, nvl, providerType, setToken));
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
	slist_scsi_session_t *fSessionList, *fSessionListP = NULL;
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
	fSessionListSize = ALLOC_SESSION;
	fSessionListSize = fSessionListSize * (sizeof (slist_scsi_session_t));
	fSessionList = (slist_scsi_session_t *)calloc(1, fSessionListSize);
	fSessionListP = fSessionList;
	if (fSessionList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
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
			case EPERM:
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
	if (stmfIoctl.stmf_obuf_max_nentries > ALLOC_SESSION) {
		fSessionListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (slist_scsi_session_t);
		fSessionList = realloc(fSessionList, fSessionListSize);
		if (fSessionList == NULL) {
			ret = STMF_ERROR_NOMEM;
			goto done;
		}
		fSessionListP = fSessionList;
		stmfIoctl.stmf_obuf_size = fSessionListSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fSessionList;
		ioctlRet = ioctl(fd, cmd, &stmfIoctl);
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
	free(fSessionListP);
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

	ret = groupListIoctl(targetGroupList, TARGET_GROUP);
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

	ret = groupMemberListIoctl(groupName, groupProp, TARGET_GROUP);

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
	slist_target_port_t *fTargetList, *fTargetListP = NULL;
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
	fTargetListSize = ALLOC_TARGET_PORT * sizeof (slist_target_port_t);
	fTargetListP = fTargetList =
	    (slist_target_port_t *)calloc(1, fTargetListSize);
	if (fTargetList == NULL) {
		ret = STMF_ERROR_NOMEM;
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
			case EPERM:
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
	if (stmfIoctl.stmf_obuf_max_nentries > ALLOC_TARGET_PORT) {
		fTargetListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (slist_target_port_t);
		fTargetListP = fTargetList =
		    realloc(fTargetList, fTargetListSize);
		if (fTargetList == NULL) {
			ret = STMF_ERROR_NOMEM;
			goto done;
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
				case EPERM:
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
	if (*targetList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

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
	scsi_devid_desc_t *scsiDevid;

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
			case EPERM:
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

	scsiDevid = (scsi_devid_desc_t *)&targetProperties.tgt_id;
	targetProps->protocol = scsiDevid->protocol_id;

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
	int i;
	stmf_iocdata_t stmfIoctl;
	slist_lu_t *fLuList;
	uint32_t fLuListSize;
	uint32_t listCnt;

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
	fLuListSize = ALLOC_LU;
	fLuListSize = fLuListSize * (sizeof (slist_lu_t));
	fLuList = (slist_lu_t *)calloc(1, fLuListSize);
	if (fLuList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
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
			case EPERM:
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
	if (stmfIoctl.stmf_obuf_max_nentries > ALLOC_LU) {
		fLuListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (slist_lu_t);
		free(fLuList);
		fLuList = (slist_lu_t *)calloc(1, fLuListSize);
		if (fLuList == NULL) {
			ret = STMF_ERROR_NOMEM;
			goto done;
		}
		stmfIoctl.stmf_obuf_size = fLuListSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fLuList;
		ioctlRet = ioctl(fd, cmd, &stmfIoctl);
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
					    "stmfGetLogicalUnitList:"
					    "ioctl errno(%d)", errno);
					ret = STMF_STATUS_ERROR;
					break;
			}
			goto done;
		}
	}

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	listCnt = stmfIoctl.stmf_obuf_nentries;

	/*
	 * allocate caller's buffer with the final size
	 */
	*luList = (stmfGuidList *)calloc(1, sizeof (stmfGuidList) +
	    listCnt * sizeof (stmfGuid));
	if (*luList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

	(*luList)->cnt = listCnt;

	/* copy to caller's buffer */
	for (i = 0; i < listCnt; i++) {
		bcopy(&fLuList[i].lu_guid, (*luList)->guid[i].guid,
		    sizeof (stmfGuid));
	}

	/*
	 * sort the list. This gives a consistent view across gets
	 */
	qsort((void *)&((*luList)->guid[0]), (*luList)->cnt,
	    sizeof (stmfGuid), guidCompare);

done:
	(void) close(fd);
	/*
	 * free internal buffers
	 */
	free(fLuList);
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

	if (lu == NULL || luProps == NULL) {
		return (STMF_ERROR_INVALID_ARG);
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
			case EPERM:
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
	int fd;
	int ioctlRet;
	int cmd = STMF_IOCTL_LU_VE_LIST;
	int i;
	stmf_iocdata_t stmfIoctl;
	stmf_view_op_entry_t *fVeList;
	uint32_t fVeListSize;
	uint32_t listCnt;

	if (lu == NULL || viewEntryList == NULL) {
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
	fVeListSize = ALLOC_VE;
	fVeListSize = fVeListSize * (sizeof (stmf_view_op_entry_t));
	fVeList = (stmf_view_op_entry_t *)calloc(1, fVeListSize);
	if (fVeList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to get the LU list
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)lu;
	stmfIoctl.stmf_ibuf_size = sizeof (stmfGuid);
	stmfIoctl.stmf_obuf_size = fVeListSize;
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fVeList;
	ioctlRet = ioctl(fd, cmd, &stmfIoctl);
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
				    "stmfGetViewEntryList:ioctl errno(%d)",
				    errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
		goto done;
	}
	/*
	 * Check whether input buffer was large enough
	 */
	if (stmfIoctl.stmf_obuf_max_nentries > ALLOC_VE) {
		bzero(&stmfIoctl, sizeof (stmfIoctl));
		fVeListSize = stmfIoctl.stmf_obuf_max_nentries *
		    sizeof (stmf_view_op_entry_t);
		free(fVeList);
		fVeList = (stmf_view_op_entry_t *)calloc(1, fVeListSize);
		if (fVeList == NULL) {
			return (STMF_ERROR_NOMEM);
		}
		stmfIoctl.stmf_obuf_size = fVeListSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)fVeList;
		ioctlRet = ioctl(fd, cmd, &stmfIoctl);
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
					    "stmfGetLogicalUnitList:"
					    "ioctl errno(%d)", errno);
					ret = STMF_STATUS_ERROR;
					break;
			}
			goto done;
		}
	}

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	listCnt = stmfIoctl.stmf_obuf_nentries;

	/*
	 * allocate caller's buffer with the final size
	 */
	*viewEntryList = (stmfViewEntryList *)calloc(1,
	    sizeof (stmfViewEntryList) + listCnt * sizeof (stmfViewEntry));
	if (*viewEntryList == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

	(*viewEntryList)->cnt = listCnt;

	/* copy to caller's buffer */
	for (i = 0; i < listCnt; i++) {
		(*viewEntryList)->ve[i].veIndexValid = B_TRUE;
		(*viewEntryList)->ve[i].veIndex = fVeList[i].ve_ndx;
		if (fVeList[i].ve_all_hosts == 1) {
			(*viewEntryList)->ve[i].allHosts = B_TRUE;
		} else {
			bcopy(fVeList[i].ve_host_group.name,
			    (*viewEntryList)->ve[i].hostGroup,
			    fVeList[i].ve_host_group.name_size);
		}
		if (fVeList[i].ve_all_targets == 1) {
			(*viewEntryList)->ve[i].allTargets = B_TRUE;
		} else {
			bcopy(fVeList[i].ve_target_group.name,
			    (*viewEntryList)->ve[i].targetGroup,
			    fVeList[i].ve_target_group.name_size);
		}
		bcopy(fVeList[i].ve_lu_nbr, (*viewEntryList)->ve[i].luNbr,
		    sizeof ((*viewEntryList)->ve[i].luNbr));
		(*viewEntryList)->ve[i].luNbrValid = B_TRUE;
	}

	/*
	 * sort the list. This gives a consistent view across gets
	 */
	qsort((void *)&((*viewEntryList)->ve[0]), (*viewEntryList)->cnt,
	    sizeof (stmfViewEntry), viewEntryCompare);

done:
	(void) close(fd);
	/*
	 * free internal buffers
	 */
	free(fVeList);
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
		ret = iLoadGroupMembersFromPs(&(groupList->name[i]),
		    &groupProps, HOST_GROUP);
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
		ret = iLoadGroupMembersFromPs(&(groupList->name[i]),
		    &groupProps, TARGET_GROUP);
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
	ret = iLoadGroupFromPs(&groupList, HOST_GROUP);
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
	ret = iLoadGroupFromPs(&groupList, TARGET_GROUP);
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
		    providerType, NULL);
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
 * stmfGetAluaState
 *
 * Purpose - Get the alua state
 *
 */
int
stmfGetAluaState(boolean_t *enabled, uint32_t *node)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	stmf_iocdata_t stmfIoctl = {0};
	stmf_alua_state_desc_t alua_state = {0};
	int ioctlRet;

	if (enabled == NULL || node == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * Issue ioctl to get the stmf state
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_obuf_size = sizeof (alua_state);
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)&alua_state;
	ioctlRet = ioctl(fd, STMF_IOCTL_GET_ALUA_STATE, &stmfIoctl);

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
	} else {
		if (alua_state.alua_state == 1) {
			*enabled = B_TRUE;
		} else {
			*enabled = B_FALSE;
		}
		*node = alua_state.alua_node;
	}

	return (ret);
}

/*
 * stmfSetAluaState
 *
 * Purpose - set the alua state to enabled/disabled
 *
 */
int
stmfSetAluaState(boolean_t enabled, uint32_t node)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	stmf_iocdata_t stmfIoctl = {0};
	stmf_alua_state_desc_t alua_state = {0};
	int ioctlRet;

	if ((enabled != B_TRUE && enabled != B_FALSE) || (node > 1)) {
		return (STMF_ERROR_INVALID_ARG);
	}

	if (enabled) {
		alua_state.alua_state = 1;
	}

	alua_state.alua_node = node;

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/*
	 * Issue ioctl to get the stmf state
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (alua_state);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&alua_state;
	ioctlRet = ioctl(fd, STMF_IOCTL_SET_ALUA_STATE, &stmfIoctl);

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
	if (!enabled && ret == STMF_STATUS_SUCCESS) {
		deleteNonActiveLus();
	}

	return (ret);
}

static void
deleteNonActiveLus()
{
	int stmfRet;
	int i;
	stmfGuidList *luList;
	luResource hdl = NULL;
	char propVal[10];
	size_t propValSize = sizeof (propVal);

	stmfRet = stmfGetLogicalUnitList(&luList);
	if (stmfRet != STMF_STATUS_SUCCESS) {
		return;
	}

	for (i = 0; i < luList->cnt; i++) {
		stmfRet = stmfGetLuResource(&luList->guid[i], &hdl);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			goto err;
		}
		stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_ACCESS_STATE, propVal,
		    &propValSize);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			goto err;
		}
		if (propVal[0] == '0') {
			(void) stmfFreeLuResource(hdl);
			hdl = NULL;
			continue;
		}
		(void) stmfDeleteLu(&luList->guid[i]);
		(void) stmfFreeLuResource(hdl);
		hdl = NULL;
	}

err:
	stmfFreeMemory(luList);
	(void) stmfFreeLuResource(hdl);
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
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	stmf_state_desc_t stmfStateSet;
	stmfState state;

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
		stmfStateSet.state = STMF_STATE_OFFLINE;

		if ((ret = openStmf(OPEN_EXCL_STMF, &fd))
		    != STMF_STATUS_SUCCESS) {
			return (ret);
		}
		/*
		 * Configuration not stored persistently; nothing to
		 * initialize so do not set to STMF_CONFIG_INIT.
		 */
		stmfStateSet.config_state = STMF_CONFIG_INIT_DONE;
		goto done;
	}

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
			case EPERM:
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
int
stmfSetStmfProp(uint8_t propType, char *propVal)
{
	int ret = STMF_STATUS_SUCCESS;
	switch (propType) {
		case STMF_DEFAULT_LU_STATE:
			break;
		case STMF_DEFAULT_TARGET_PORT_STATE:
			break;
		default:
			return (STMF_ERROR_INVALID_ARG);
	}
	ret = psSetStmfProp(propType, propVal);
	switch (ret) {
		case STMF_PS_SUCCESS:
			ret = STMF_STATUS_SUCCESS;
			break;
		case STMF_PS_ERROR_BUSY:
			ret = STMF_ERROR_BUSY;
			break;
		default:
			syslog(LOG_DEBUG,
			    "stmfSetStmfProp:psSetStmfProp:error(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
			break;
	}
	return (ret);
}


int
stmfGetStmfProp(uint8_t propType, char *propVal, size_t *propLen)
{
	int ret = STMF_STATUS_SUCCESS;
	char prop[MAXNAMELEN] = {0};
	size_t reqLen;

	if (propVal == NULL || propLen == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}
	switch (propType) {
		case STMF_DEFAULT_LU_STATE:
			break;
		case STMF_DEFAULT_TARGET_PORT_STATE:
			break;
		default:
			return (STMF_ERROR_INVALID_ARG);
	}
	ret = psGetStmfProp(propType, prop);
	if ((reqLen = strlcpy(propVal, prop, *propLen)) >= *propLen) {
		*propLen = reqLen + 1;
		return (STMF_ERROR_INVALID_ARG);
	}

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
		default:
			syslog(LOG_DEBUG,
			    "stmfGetStmfProp:psGetStmfProp:error(%d)",
			    ret);
			ret = STMF_STATUS_ERROR;
			break;
	}
	return (ret);
}

static int
setStmfProp(stmf_set_props_t *stmf_set_props)
{
	char propVal[MAXNAMELEN] = {0};
	int ret;
	if ((ret = psGetStmfProp(STMF_DEFAULT_LU_STATE, propVal)) ==
	    STMF_PS_SUCCESS) {
		if (strncmp(propVal, "offline", strlen(propVal)) == 0) {
			stmf_set_props->default_lu_state_value =
			    STMF_STATE_OFFLINE;
		} else {
			stmf_set_props->default_lu_state_value =
			    STMF_STATE_ONLINE;
		}
	} else {
		syslog(LOG_DEBUG,
		    "DefaultLuState:psSetStmfProp:error(%d)", ret);
		goto done;
	}

	if ((ret = psGetStmfProp(STMF_DEFAULT_TARGET_PORT_STATE, propVal)) ==
	    STMF_PS_SUCCESS) {
		if (strncmp(propVal, "offline", strlen(propVal)) == 0) {
			stmf_set_props->default_target_state_value =
			    STMF_STATE_OFFLINE;
		} else {
			stmf_set_props->default_target_state_value =
			    STMF_STATE_ONLINE;
		}
	} else {
		syslog(LOG_DEBUG,
		    "DefaultTargetPortState:psSetStmfProp:error(%d)", ret);
		goto done;
	}
done:
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
		default:
			ret = STMF_STATUS_ERROR;
			break;
	}
	return (ret);
}

static int
loadStmfProp(int fd)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	stmf_iocdata_t stmfIoctl = {0};
	stmf_set_props_t *stmf_set_props = NULL;

	stmf_set_props = (stmf_set_props_t *)
	    calloc(1, (sizeof (stmf_set_props_t)));
	if (stmf_set_props == NULL) {
		ret = STMF_ERROR_NOMEM;
		goto done;
	}

	/* Loading the default property values from smf */

	if ((ret = setStmfProp(stmf_set_props)) != STMF_STATUS_SUCCESS)
		goto done;

	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (stmf_set_props_t);
	stmfIoctl.stmf_ibuf =
	    (uint64_t)(unsigned long)stmf_set_props;

	ioctlRet = ioctl(fd, STMF_IOCTL_SET_STMF_PROPS,
	    &stmfIoctl);

	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			case ENOENT:
				ret = STMF_ERROR_NOT_FOUND;
				break;
			default:
				syslog(LOG_DEBUG,
				    "setDefaultStmfState:"
				    "ioctl errno(%d)", errno);
				ret = STMF_STATUS_ERROR;
				break;
		}
	}
done:
	if (stmf_set_props != NULL) {
		free(stmf_set_props);
	}
	return (ret);
}

int
stmfLoadStmfProps(void)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	/* open control node for stmf */
	if ((ret = openStmf(OPEN_EXCL_STMF, &fd))
	    != STMF_STATUS_SUCCESS) {
		goto done;
	}
	ret = loadStmfProp(fd);

	(void) close(fd);
done:
	if (ret != STMF_STATUS_SUCCESS) {
		syslog(LOG_DEBUG,
		    "stmfLoadStmfProps:Failed");
	}
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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
			case EPERM:
				ret = STMF_ERROR_PERM;
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

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
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

	ret = setProviderData(fd, providerName, nvl, providerType, setToken);

	(void) close(fd);

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	if (iGetPersistMethod() == STMF_PERSIST_NONE) {
		goto done;
	}

	/* setting driver provider data successful. Now persist it */
	ret = psSetProviderData(providerName, nvl, providerType, NULL);
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
 * getProviderData
 *
 * Purpose: set the provider data from stmf
 *
 * providerName - unique name of provider
 * nvl - nvlist to load/retrieve
 * providerType - logical unit or port provider
 * setToken - returned stale data token
 */
int
getProviderData(char *providerName, nvlist_t **nvl, int providerType,
    uint64_t *setToken)
{
	int ret = STMF_STATUS_SUCCESS;
	int fd;
	int ioctlRet;
	size_t nvlistSize = ALLOC_PP_DATA_SIZE;
	int retryCnt = 0;
	int retryCntMax = MAX_PROVIDER_RETRY;
	stmf_ppioctl_data_t ppi = {0}, *ppi_out = NULL;
	boolean_t retry = B_TRUE;
	stmf_iocdata_t stmfIoctl;

	if (providerName == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/*
	 * Open control node for stmf
	 */
	if ((ret = openStmf(OPEN_STMF, &fd)) != STMF_STATUS_SUCCESS)
		return (ret);

	/* set provider name and provider type */
	if (strlcpy(ppi.ppi_name, providerName,
	    sizeof (ppi.ppi_name)) >=
	    sizeof (ppi.ppi_name)) {
		ret = STMF_ERROR_INVALID_ARG;
		goto done;
	}
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

	do {
		/* allocate memory for ioctl */
		ppi_out = (stmf_ppioctl_data_t *)calloc(1, nvlistSize +
		    sizeof (stmf_ppioctl_data_t));
		if (ppi_out == NULL) {
			ret = STMF_ERROR_NOMEM;
			goto done;

		}

		/* set the size of the ioctl data to allocated buffer */
		ppi.ppi_data_size = nvlistSize;

		bzero(&stmfIoctl, sizeof (stmfIoctl));

		stmfIoctl.stmf_version = STMF_VERSION_1;
		stmfIoctl.stmf_ibuf_size = sizeof (stmf_ppioctl_data_t);
		stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&ppi;
		stmfIoctl.stmf_obuf_size = sizeof (stmf_ppioctl_data_t) +
		    nvlistSize;
		stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)ppi_out;
		ioctlRet = ioctl(fd, STMF_IOCTL_GET_PP_DATA, &stmfIoctl);
		if (ioctlRet != 0) {
			switch (errno) {
				case EBUSY:
					ret = STMF_ERROR_BUSY;
					break;
				case EPERM:
				case EACCES:
					ret = STMF_ERROR_PERM;
					break;
				case EINVAL:
					if (stmfIoctl.stmf_error ==
					    STMF_IOCERR_INSUFFICIENT_BUF) {
						nvlistSize =
						    ppi_out->ppi_data_size;
						free(ppi_out);
						ppi_out = NULL;
						if (retryCnt++ > retryCntMax) {
							retry = B_FALSE;
							ret = STMF_ERROR_BUSY;
						} else {
							ret =
							    STMF_STATUS_SUCCESS;
						}
					} else {
						syslog(LOG_DEBUG,
						    "getProviderData:ioctl"
						    "unable to retrieve "
						    "nvlist");
						ret = STMF_STATUS_ERROR;
					}
					break;
				case ENOENT:
					ret = STMF_ERROR_NOT_FOUND;
					break;
				default:
					syslog(LOG_DEBUG,
					    "getProviderData:ioctl errno(%d)",
					    errno);
					ret = STMF_STATUS_ERROR;
					break;
			}
			if (ret != STMF_STATUS_SUCCESS)
				goto done;
		}
	} while (retry && stmfIoctl.stmf_error == STMF_IOCERR_INSUFFICIENT_BUF);

	if ((ret = nvlist_unpack((char *)ppi_out->ppi_data,
	    ppi_out->ppi_data_size, nvl, 0)) != 0) {
		ret = STMF_STATUS_ERROR;
		goto done;
	}

	/* caller has asked for new token */
	if (setToken) {
		*setToken = ppi_out->ppi_token;
	}
done:
	free(ppi_out);
	(void) close(fd);
	return (ret);
}

/*
 * setProviderData
 *
 * Purpose: set the provider data in stmf
 *
 * providerName - unique name of provider
 * nvl - nvlist to set
 * providerType - logical unit or port provider
 * setToken - stale data token to check if not NULL
 */
static int
setProviderData(int fd, char *providerName, nvlist_t *nvl, int providerType,
    uint64_t *setToken)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	size_t nvlistEncodedSize;
	stmf_ppioctl_data_t *ppi = NULL;
	uint64_t outToken;
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

	if (setToken) {
		ppi->ppi_token_valid = 1;
		ppi->ppi_token = *setToken;
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
	stmfIoctl.stmf_obuf_size = sizeof (uint64_t);
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)&outToken;
	ioctlRet = ioctl(fd, STMF_IOCTL_LOAD_PP_DATA, &stmfIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			case EINVAL:
				if (stmfIoctl.stmf_error ==
				    STMF_IOCERR_PPD_UPDATED) {
					ret = STMF_ERROR_PROV_DATA_STALE;
				} else {
					ret = STMF_STATUS_ERROR;
				}
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

	/* caller has asked for new token */
	if (setToken) {
		*setToken = outToken;
	}
done:
	free(ppi);
	return (ret);
}

/*
 * set the persistence method in the library only or library and service
 */
int
stmfSetPersistMethod(uint8_t persistType, boolean_t serviceSet)
{
	int ret = STMF_STATUS_SUCCESS;
	int oldPersist;

	(void) pthread_mutex_lock(&persistenceTypeLock);
	oldPersist = iPersistType;
	if (persistType == STMF_PERSIST_NONE ||
	    persistType == STMF_PERSIST_SMF) {
		iLibSetPersist = B_TRUE;
		iPersistType = persistType;
	} else {
		(void) pthread_mutex_unlock(&persistenceTypeLock);
		return (STMF_ERROR_INVALID_ARG);
	}
	/* Is this for this library open or in SMF */
	if (serviceSet == B_TRUE) {
		ret = psSetServicePersist(persistType);
		if (ret != STMF_PS_SUCCESS) {
			ret = STMF_ERROR_PERSIST_TYPE;
			/* Set to old value */
			iPersistType = oldPersist;
		}
	}
	(void) pthread_mutex_unlock(&persistenceTypeLock);

	return (ret);
}

/*
 * Only returns internal state for persist. If unset, goes to ps. If that
 * fails, returns default setting
 */
static uint8_t
iGetPersistMethod()
{

	uint8_t persistType = 0;

	(void) pthread_mutex_lock(&persistenceTypeLock);
	if (iLibSetPersist) {
		persistType = iPersistType;
	} else {
		int ret;
		ret = psGetServicePersist(&persistType);
		if (ret != STMF_PS_SUCCESS) {
			/* set to default */
			persistType = STMF_DEFAULT_PERSIST;
		}
	}
	(void) pthread_mutex_unlock(&persistenceTypeLock);
	return (persistType);
}

/*
 * Returns either library state or persistent config state depending on
 * serviceState
 */
int
stmfGetPersistMethod(uint8_t *persistType, boolean_t serviceState)
{
	int ret = STMF_STATUS_SUCCESS;

	if (persistType == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}
	if (serviceState) {
		ret = psGetServicePersist(persistType);
		if (ret != STMF_PS_SUCCESS) {
			ret = STMF_ERROR_PERSIST_TYPE;
		}
	} else {
		(void) pthread_mutex_lock(&persistenceTypeLock);
		if (iLibSetPersist) {
			*persistType = iPersistType;
		} else {
			*persistType = STMF_DEFAULT_PERSIST;
		}
		(void) pthread_mutex_unlock(&persistenceTypeLock);
	}

	return (ret);
}

/*
 * stmfPostProxyMsg
 *
 * Purpose: Post a message to the proxy port provider
 *
 * buf - buffer containing message to post
 * buflen - buffer length
 */
int
stmfPostProxyMsg(int hdl, void *buf, uint32_t buflen)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	pppt_iocdata_t ppptIoctl = {0};

	if (buf == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/*
	 * Issue ioctl to post the message
	 */
	ppptIoctl.pppt_version = PPPT_VERSION_1;
	ppptIoctl.pppt_buf_size = buflen;
	ppptIoctl.pppt_buf = (uint64_t)(unsigned long)buf;
	ioctlRet = ioctl(hdl, PPPT_MESSAGE, &ppptIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			default:
				ret = STMF_ERROR_POST_MSG_FAILED;
				break;
		}
	}

	return (ret);
}

/*
 * stmfInitProxyDoor
 *
 * Purpose: Install door in proxy
 *
 * hdl - pointer to returned handle
 * fd - door from door_create()
 */
int
stmfInitProxyDoor(int *hdl, int door)
{
	int ret = STMF_STATUS_SUCCESS;
	int ioctlRet;
	int fd;
	pppt_iocdata_t ppptIoctl = {0};

	if (hdl == NULL) {
		return (STMF_ERROR_INVALID_ARG);
	}

	/*
	 * Open control node for pppt
	 */
	if ((ret = openPppt(OPEN_PPPT, &fd)) != STMF_STATUS_SUCCESS) {
		return (ret);
	}

	/*
	 * Issue ioctl to install the door
	 */
	ppptIoctl.pppt_version = PPPT_VERSION_1;
	ppptIoctl.pppt_door_fd = (uint32_t)door;
	ioctlRet = ioctl(fd, PPPT_INSTALL_DOOR, &ppptIoctl);
	if (ioctlRet != 0) {
		switch (errno) {
			case EPERM:
			case EACCES:
				ret = STMF_ERROR_PERM;
				break;
			case EINVAL:
				ret = STMF_ERROR_INVALID_ARG;
				break;
			case EBUSY:
				ret = STMF_ERROR_DOOR_INSTALLED;
				break;
			default:
				ret = STMF_STATUS_ERROR;
				break;
		}
	}

	/* return driver fd to caller */
	*hdl = fd;
	return (ret);
}

void
stmfDestroyProxyDoor(int hdl)
{
	(void) close(hdl);
}

/*
 * validateLunNumIoctl
 *
 * Purpose: Issues ioctl to check and get available lun# in view entry
 *
 * viewEntry - view entry to use
 */
static int
validateLunNumIoctl(int fd, stmfViewEntry *viewEntry)
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
	/* Validating the lun number */
	if (viewEntry->luNbrValid) {
		bcopy(viewEntry->luNbr, &ioctlViewEntry.ve_lu_nbr,
		    sizeof (ioctlViewEntry.ve_lu_nbr));
	}

	bzero(&stmfIoctl, sizeof (stmfIoctl));
	/*
	 * Issue ioctl to validate lun# in the view entry
	 */
	stmfIoctl.stmf_version = STMF_VERSION_1;
	stmfIoctl.stmf_ibuf_size = sizeof (ioctlViewEntry);
	stmfIoctl.stmf_ibuf = (uint64_t)(unsigned long)&ioctlViewEntry;
	stmfIoctl.stmf_obuf_size = sizeof (ioctlViewEntry);
	stmfIoctl.stmf_obuf = (uint64_t)(unsigned long)&ioctlViewEntry;
	ioctlRet = ioctl(fd, STMF_IOCTL_VALIDATE_VIEW, &stmfIoctl);

	/* save available lun number */
	if (!viewEntry->luNbrValid) {
		bcopy(ioctlViewEntry.ve_lu_nbr, viewEntry->luNbr,
		    sizeof (ioctlViewEntry.ve_lu_nbr));
	}
	if (ioctlRet != 0) {
		switch (errno) {
			case EBUSY:
				ret = STMF_ERROR_BUSY;
				break;
			case EPERM:
				ret = STMF_ERROR_PERM;
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
	}
	return (ret);
}

/*
 * stmfValidateView
 *
 * Purpose: Validate or get lun # base on TG, HG of view entry
 *
 * viewEntry - view entry structure to use
 */
int
stmfValidateView(stmfViewEntry *viewEntry)
{
	int ret;
	int fd;
	stmfViewEntry iViewEntry;

	if (viewEntry == NULL) {
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
	 * Validate lun# in the view entry from the driver
	 */
	ret = validateLunNumIoctl(fd, &iViewEntry);
	(void) close(fd);

	/* save available lun number */
	if (!viewEntry->luNbrValid) {
		bcopy(iViewEntry.luNbr, viewEntry->luNbr,
		    sizeof (iViewEntry.luNbr));
	}

	return (ret);
}
