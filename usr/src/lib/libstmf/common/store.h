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
#ifndef	_STORE_H
#define	_STORE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libnvpair.h>

/*
 * Error defines
 */
#define	STMF_PS_SUCCESS			0
#define	STMF_PS_ERROR			1
#define	STMF_PS_ERROR_MEMBER_NOT_FOUND	2
#define	STMF_PS_ERROR_GROUP_NOT_FOUND	3
#define	STMF_PS_ERROR_NOT_FOUND		4
#define	STMF_PS_ERROR_EXISTS		5
#define	STMF_PS_ERROR_NOMEM		6
#define	STMF_PS_ERROR_RETRY		7
#define	STMF_PS_ERROR_BUSY		8
#define	STMF_PS_ERROR_SERVICE_NOT_FOUND 9
#define	STMF_PS_ERROR_INVALID_ARG	10
#define	STMF_PS_ERROR_VERSION_MISMATCH	11
#define	STMF_PS_ERROR_PROV_DATA_STALE	12

int psAddHostGroupMember(char *groupName, char *memberName);
int psAddTargetGroupMember(char *groupName, char *memberName);
int psAddViewEntry(stmfGuid *lu, stmfViewEntry *viewEntry);
int psCreateHostGroup(char *groupName);
int psDeleteHostGroup(char *groupName);
int psCreateTargetGroup(char *groupName);
int psDeleteTargetGroup(char *groupName);
int psGetViewEntry(stmfGuid *lu, uint32_t viewEntryIndex, stmfViewEntry *ve);
int psGetLogicalUnitList(stmfGuidList **guidList);
int psRemoveHostGroupMember(char *groupName, char *memberName);
int psRemoveTargetGroupMember(char *groupName, char *memberName);
int psRemoveViewEntry(stmfGuid *lu, uint32_t viewEntryIndex);
int psGetHostGroupList(stmfGroupList **groupList);
int psGetTargetGroupList(stmfGroupList **groupList);
int psGetHostGroupMemberList(char *groupName, stmfGroupProperties **groupList);
int psGetTargetGroupMemberList(char *groupName,
    stmfGroupProperties **groupList);
int psGetViewEntryList(stmfGuid *lu, stmfViewEntryList **viewEntryList);
int psCheckService();
int psSetProviderData(char *providerName, nvlist_t *nvl, int providerType,
    uint64_t *setHandle);
int psGetProviderData(char *providerName, nvlist_t **nvl, int providerType,
    uint64_t *setHandle);
int psGetProviderDataList(stmfProviderList **providerList);
int psClearProviderData(char *providerName, int providerType);

#ifdef	__cplusplus
}
#endif

#endif	/* _STORE_H */
