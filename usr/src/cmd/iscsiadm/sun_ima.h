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

#ifndef	_SUN_IMA_H
#define	_SUN_IMA_H

#include <iscsiadm.h>

#ifdef	__cplusplus
extern "C" {
#endif

IMA_API	IMA_STATUS SUN_IMA_GetDiscoveryAddressPropertiesList(
    SUN_IMA_DISC_ADDR_PROP_LIST	**ppList);
IMA_API IMA_STATUS SUN_IMA_GetStaticTargetProperties(
	IMA_OID	staticTargetOid,
	SUN_IMA_STATIC_TARGET_PROPERTIES *pProps);
IMA_API IMA_STATUS SUN_IMA_AddStaticTarget(
	IMA_OID lhbaOid,
	const SUN_IMA_STATIC_DISCOVERY_TARGET staticConfig,
	IMA_OID *pTargetOid);
IMA_API	IMA_STATUS SUN_IMA_GetTargetProperties(
	IMA_OID targetId,
	SUN_IMA_TARGET_PROPERTIES *pProps);
IMA_STATUS SUN_IMA_SetTargetAuthParams(
	IMA_OID targetOid,
	IMA_AUTHMETHOD method,
	const IMA_INITIATOR_AUTHPARMS *pParms);
IMA_STATUS SUN_IMA_GetTargetAuthMethods(
	IMA_OID		lhbaOid,
	IMA_OID		targetOid,
	IMA_UINT	*pMethodCount,
	IMA_AUTHMETHOD *pMethodList);
IMA_STATUS SUN_IMA_SetInitiatorRadiusConfig(
	IMA_OID	lhbaOid,
	SUN_IMA_RADIUS_CONFIG *config);
IMA_STATUS SUN_IMA_GetInitiatorRadiusConfig(
	IMA_OID	lhbaOid,
	SUN_IMA_RADIUS_CONFIG *config);
IMA_STATUS SUN_IMA_SetInitiatorRadiusAccess(
	IMA_OID lhbaOid,
	IMA_BOOL radiusAccess);
IMA_STATUS SUN_IMA_GetInitiatorRadiusAccess(
	IMA_OID lhbaOid,
	IMA_BOOL *radiusAccess);
IMA_STATUS SUN_IMA_SendTargets(
	IMA_NODE_NAME nodeName,
	IMA_TARGET_ADDRESS address,
	SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES **ppList);
IMA_STATUS SUN_IMA_SetTargetBidirAuthFlag(
	IMA_OID targetOid,
	IMA_BOOL *bidirAuthFlag);
IMA_STATUS SUN_IMA_GetTargetBidirAuthFlag(
	IMA_OID targetOid,
	IMA_BOOL *bidirAuthFlag);
IMA_STATUS SUN_IMA_CreateTargetOid(
	IMA_NODE_NAME targetName,
	IMA_OID *targetOid);
IMA_STATUS SUN_IMA_RemoveTargetParam(
	IMA_OID targetOid);
IMA_API IMA_STATUS SUN_IMA_SetHeaderDigest(
	IMA_OID oid,
	IMA_UINT algorithmCount,
	const SUN_IMA_DIGEST_ALGORITHM *algorithmList);
IMA_API IMA_STATUS SUN_IMA_SetDataDigest(
	IMA_OID oid,
	IMA_UINT algorithmCount,
	const SUN_IMA_DIGEST_ALGORITHM *algorithmList);
IMA_API IMA_STATUS SUN_IMA_GetHeaderDigest(
	IMA_OID oid,
	SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm);
IMA_API IMA_STATUS SUN_IMA_GetDataDigest(
	IMA_OID oid,
	SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm);
IMA_STATUS SUN_IMA_GetLuProperties(
	IMA_OID luId,
	SUN_IMA_LU_PROPERTIES *pProps);
IMA_API	IMA_STATUS SUN_IMA_GetConnOidList(
	IMA_OID	*oid,
	IMA_OID_LIST **ppList);
IMA_API	IMA_STATUS SUN_IMA_GetConnProperties(
	IMA_OID	*connOid,
	SUN_IMA_CONN_PROPERTIES	**pProps);
IMA_API IMA_STATUS SUN_IMA_GetConfigSessions(
	IMA_OID targetOid,
	SUN_IMA_CONFIG_SESSIONS **pConfigSessions);
IMA_API IMA_STATUS SUN_IMA_SetConfigSessions(
	IMA_OID targetOid,
	SUN_IMA_CONFIG_SESSIONS *pConfigSessions);
IMA_API	IMA_STATUS SUN_IMA_RemoveDiscoveryAddress(
	SUN_IMA_TARGET_ADDRESS discoveryAddress);
IMA_STATUS SUN_IMA_SetTargetAuthMethods(
	IMA_OID targetOid,
	IMA_UINT *methodCount,
	const IMA_AUTHMETHOD *pMethodList);
IMA_STATUS getNegotiatedDigest(
	int digestType,
	SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm,
	SUN_IMA_CONN_PROPERTIES *connProps);
IMA_API	IMA_STATUS SUN_IMA_GetISNSServerAddressPropertiesList(
	SUN_IMA_DISC_ADDR_PROP_LIST **ppList);
IMA_API	IMA_STATUS SUN_IMA_RemoveISNSServerAddress(
	SUN_IMA_TARGET_ADDRESS isnsServerAddress);
IMA_API IMA_STATUS SUN_IMA_AddISNSServerAddress(
	const SUN_IMA_TARGET_ADDRESS isnsServerAddress);
IMA_STATUS SUN_IMA_RetrieveISNSServerTargets(
    IMA_TARGET_ADDRESS serverAddress,
    SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES **ppList);
IMA_STATUS SUN_IMA_GetSessionOidList(
	IMA_OID initiatorOid,
	IMA_OID_LIST **ppList);
IMA_API	IMA_STATUS SUN_IMA_GetTargetAuthParms(
	IMA_OID oid,
	IMA_AUTHMETHOD method,
	IMA_INITIATOR_AUTHPARMS *pParms);
IMA_STATUS SUN_IMA_GetBootTargetName(
	IMA_NODE_NAME tgtName);
IMA_STATUS SUN_IMA_GetBootTargetAuthParams(
	IMA_INITIATOR_AUTHPARMS *pTgtCHAP);
IMA_STATUS SUN_IMA_GetBootMpxio(
	IMA_BOOL *pMpxioEnabled);
IMA_STATUS SUN_IMA_GetBootIscsi(
	IMA_BOOL *pIscsiBoot);

#ifdef	__cplusplus
}
#endif

#endif	/* _SUN_IMA_H */
