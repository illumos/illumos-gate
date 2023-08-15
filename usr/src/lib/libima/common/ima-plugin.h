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
 *
 * Description
 * imaPlugin.h: interface for the iScsiPlugin class.
 *
 * License:
 *	The contents of this file are subject to the SNIA Public License
 *	Version 1.0 (the "License"); you may not use this file except in
 *	compliance with the License. You may obtain a copy of the License at
 *
 *	/http://www.snia.org/English/Resources/Code/OpenSource.html
 *
 *	Software distributed under the License is distributed on an "AS IS"
 *	basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *	the License for the specific language governing rights and limitations
 *	under the License.
 *
 * The Original Code is  SNIA HBA API and IMA general header file
 *
 * The Initial Developer of the Original Code is:
 *		Benjamin F. Kuo, Troika Networks, Inc. (benk@troikanetworks.com)
 *		David Dillard		VERITAS Software		david.dillard@veritas.com
 *
 * Contributor(s):
 *	Jeff Ding, Adaptec, Inc. (jding@corp.adaptec.com)
 *
 *******************************************************************************
 *
 *   Changes:
 *	09/24/2003 Initial Draft
 *	(for other changes... see the CVS logs)
 *  12/15/2003 corrected the defined parameter in IMA_SetPhbaIsnsDiscovery().
 *  lower case the computer name as iscsi name in IMA_GenerateNodeName().
 ******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IMAPLUGIN_H
#define IMAPLUGIN_H

typedef IMA_STATUS (* Initialize)(
		IMA_UINT32 pluginOid
	);

typedef void (* TerminateFn)();


typedef IMA_STATUS (* IMA_GetPluginPropertiesFn)(
	IMA_OID pluginOid,
	IMA_PLUGIN_PROPERTIES *pProps
);


typedef IMA_STATUS (* IMA_GetSharedNodeOidFn)(
	IMA_OID *pSharedNodeId
);


typedef IMA_STATUS (* IMA_GetNodePropertiesFn)(
	IMA_OID nodeOid,
	IMA_NODE_PROPERTIES *pProps
);


typedef IMA_STATUS (* IMA_SetNodeNameFn)(
	IMA_OID nodeOid,
	const IMA_NODE_NAME newName
);


typedef IMA_STATUS (* IMA_GenerateNodeNameFn)(
	IMA_NODE_NAME generatedname
);


typedef IMA_STATUS (* IMA_SetNodeAliasFn)(
	IMA_OID nodeOid,
	const IMA_NODE_ALIAS newAlias
);


typedef IMA_STATUS (* IMA_GetLhbaOidListFn)(
	IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_GetLhbaPropertiesFn)(
	IMA_OID lhbaId,
	IMA_LHBA_PROPERTIES *pProps
);


typedef IMA_STATUS (* IMA_GetPhbaOidListFn)(
	IMA_OID_LIST **ppList
);


typedef IMA_STATUS (* IMA_GetPhbaPropertiesFn)(
	IMA_OID phbaId,
	IMA_PHBA_PROPERTIES *pProps
);


typedef IMA_STATUS (* IMA_GetNonSharedNodeOidListFn)(
		IMA_OID_LIST **ppList
	);


typedef IMA_STATUS (* IMA_GetFirstBurstLengthPropertiesFn)(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
	);


typedef IMA_STATUS (* IMA_GetMaxBurstLengthPropertiesFn)(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
	);


typedef IMA_STATUS (* IMA_GetMaxRecvDataSegmentLengthPropertiesFn)(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
	);


/*---------------------------------------------*/
typedef IMA_STATUS (* IMA_PluginIOCtlFn)(
		IMA_OID pluginOid,
		IMA_UINT command,
		const void *pInputBuffer,
		IMA_UINT inputBufferLength,
		void *pOutputBuffer,
		IMA_UINT *pOutputBufferLength
);


typedef IMA_STATUS (* IMA_GetNetworkPortalOidListFn)(
		IMA_OID lhbaId,
		IMA_OID_LIST **ppList
);


typedef IMA_STATUS (* IMA_SetFirstBurstLengthFn)(
		IMA_OID lhbaId,
		IMA_UINT firstBurstLength
);

typedef IMA_STATUS (* IMA_SetMaxBurstLengthFn)(
		IMA_OID lhbaId,
		IMA_UINT maxBurstLength
);

typedef IMA_STATUS (* IMA_SetMaxRecvDataSegmentLengthFn)(
		IMA_OID lhbaId,
		IMA_UINT maxRecvDataSegmentLength
);

typedef IMA_STATUS (* IMA_GetMaxConnectionsPropertiesFn)(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetMaxConnectionsFn)(
		IMA_OID lhbaId,
		IMA_UINT maxConnections
);

typedef IMA_STATUS (* IMA_GetDefaultTime2RetainPropertiesFn)(
		IMA_OID lhbaId,
		IMA_MIN_MAX_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetDefaultTime2RetainFn)(
		IMA_OID lhbaId,
		IMA_UINT defaultTime2Retain
);

typedef IMA_STATUS (* IMA_GetDefaultTime2WaitPropertiesFn)(
		IMA_OID lhbaId,
		IMA_MIN_MAX_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetDefaultTime2WaitFn)(
		IMA_OID lhbaId,
		IMA_UINT defaultTime2Wait
);

typedef IMA_STATUS (* IMA_GetMaxOutstandingR2TPropertiesFn)(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetMaxOutstandingR2TFn)(
		IMA_OID lhbaId,
		IMA_UINT maxOutstandingR2T
);

typedef IMA_STATUS (* IMA_GetErrorRecoveryLevelPropertiesFn)(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetErrorRecoveryLevelFn)(
		IMA_OID Oid,
		IMA_UINT errorRecoveryLevel
);

typedef IMA_STATUS (* IMA_GetInitialR2TPropertiesFn)(
		IMA_OID Oid,
		IMA_BOOL_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetInitialR2TFn)(
		IMA_OID Oid,
		IMA_BOOL initialR2T
);

typedef IMA_STATUS (* IMA_GetImmediateDataPropertiesFn)(
		IMA_OID Oid,
		IMA_BOOL_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetImmediateDataFn)(
		IMA_OID Oid,
		IMA_BOOL immediateData
);

typedef IMA_STATUS (* IMA_GetDataPduInOrderPropertiesFn)(
		IMA_OID Oid,
		IMA_BOOL_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetDataPduInOrderFn)(
		IMA_OID Oid,
		IMA_BOOL dataPduInOrder
);

typedef IMA_STATUS (* IMA_GetDataSequenceInOrderPropertiesFn)(
		IMA_OID Oid,
		IMA_BOOL_VALUE *pProps
);

typedef IMA_STATUS (* IMA_SetDataSequenceInOrderFn)(
		IMA_OID Oid,
		IMA_BOOL dataSequenceInOrder
);

typedef IMA_STATUS (* IMA_SetStatisticsCollectionFn)(
		IMA_OID Oid,
		IMA_BOOL enableStatisticsCollection
);

typedef IMA_STATUS (* IMA_GetNetworkPortStatusFn)(
		IMA_OID portOid,
		IMA_NETWORK_PORT_STATUS *pStatus
);

typedef IMA_STATUS (* IMA_GetTargetOidListFn)(
		IMA_OID Oid,
		IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_RemoveStaleDataFn)(
		IMA_OID lhbaId
);

typedef IMA_STATUS (* IMA_SetIsnsDiscoveryFn)(
		IMA_OID phbaId,
		IMA_BOOL enableIsnsDiscovery,
		IMA_ISNS_DISCOVERY_METHOD discoveryMethod,
		const IMA_HOST_ID *iSnsHost
);

typedef IMA_STATUS (* IMA_SetSlpDiscoveryFn)(
		IMA_OID phbaId,
		IMA_BOOL enableSlpDiscovery
);

typedef IMA_STATUS (* IMA_SetStaticDiscoveryFn)(
		IMA_OID phbaId,
		IMA_BOOL enableStaticDiscovery
);

typedef IMA_STATUS (* IMA_SetSendTargetsDiscoveryFn)(
		IMA_OID phbaId,
		IMA_BOOL enableSendTargetsDiscovery
);

typedef IMA_STATUS (* IMA_AddPhbaStaticDiscoveryTargetFn)(
		IMA_OID phbaOid,
		const IMA_TARGET_ADDRESS targetAddress,
		IMA_OID_LIST **pTargetOidList
);

typedef IMA_STATUS (* IMA_RemovePhbaStaticDiscoveryTargetFn)(
		IMA_OID phbaOid,
		IMA_OID targetOid
);

typedef IMA_STATUS (* IMA_GetPnpOidListFn)(
		IMA_OID Oid,
		IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_GetPhbaDownloadPropertiesFn)(
		IMA_OID phbaId,
		IMA_PHBA_DOWNLOAD_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_IsPhbaDownloadFileFn)(
		IMA_OID phbaId,
		const IMA_WCHAR *pFileName,
		IMA_PHBA_DOWNLOAD_IMAGE_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_PhbaDownloadFn)(
		IMA_OID phbaId,
		IMA_PHBA_DOWNLOAD_IMAGE_TYPE imageType,
		const IMA_WCHAR *pFileName
);

typedef IMA_STATUS (* IMA_GetNetworkPortalPropertiesFn)(
		IMA_OID networkPortalId,
		IMA_NETWORK_PORTAL_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_SetNetworkPortalIpAddressFn)(
		IMA_OID networkPortalId,
		const IMA_IP_ADDRESS NewIpAddress
);

typedef IMA_STATUS (* IMA_GetLnpOidListFn)(
		IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_GetLnpPropertiesFn)(
		IMA_OID lnpId,
		IMA_LNP_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetPnpPropertiesFn)(
		IMA_OID pnpId,
		IMA_PNP_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetPnpStatisticsFn)(
		IMA_OID pnpId,
		IMA_PNP_STATISTICS *pStats
);

typedef	IMA_STATUS (* IMA_GetConnectionPropertiesFn)(
		IMA_OID connectionId,
		IMA_CONNECTION_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetTargetPropertiesFn)(
		IMA_OID targetId,
		IMA_TARGET_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetSessionPropertiesFn)(
		IMA_OID sessionId,
		IMA_SESSION_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetTargetErrorStatisticsFn)(
		IMA_OID targetId,
		IMA_TARGET_ERROR_STATISTICS *pStats
);

typedef IMA_STATUS (* IMA_GetLuOidListFn)(
		IMA_OID Oid,
		IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_GetLuOidFn)(
		IMA_OID targetId,
		IMA_UINT64 lun,
		IMA_OID *pluId
);

typedef IMA_STATUS (* IMA_GetLuPropertiesFn)(
		IMA_OID luId,
		IMA_LU_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetStatisticsPropertiesFn)(
		IMA_OID oid,
		IMA_STATISTICS_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetDeviceStatisticsFn)(
		IMA_OID luId,
		IMA_DEVICE_STATISTICS *pStats
);

typedef IMA_STATUS (* IMA_LuInquiryFn)(
		IMA_OID deviceId,
		IMA_BOOL evpd,
		IMA_BOOL cmddt,
		IMA_BYTE pageCode,

		IMA_BYTE *pOutputBuffer,
		IMA_UINT *pOutputBufferLength,

		IMA_BYTE *pSenseBuffer,
		IMA_UINT *pSenseBufferLength
);

typedef IMA_STATUS (* IMA_LuReadCapacityFn)(
		IMA_OID deviceId,
		IMA_UINT cdbLength,
		IMA_BYTE *pOutputBuffer,
		IMA_UINT *pOutputBufferLength,

		IMA_BYTE *pSenseBuffer,
		IMA_UINT *pSenseBufferLength
);

typedef IMA_STATUS (* IMA_LuReportLunsFn)(
		IMA_OID deviceId,
		IMA_BOOL sendToWellKnownLun,
		IMA_BYTE selectReport,

		IMA_BYTE *pOutputBuffer,
		IMA_UINT *pOutputBufferLength,

		IMA_BYTE *pSenseBuffer,
		IMA_UINT *pSenseBufferLength
);

typedef IMA_STATUS (* IMA_ExposeLuFn)(
		IMA_OID luId
);

typedef IMA_STATUS (* IMA_UnexposeLuFn)(
		IMA_OID luId
);

typedef IMA_STATUS (* IMA_GetPhbaStatusFn)(
		IMA_OID hbaId,
		IMA_PHBA_STATUS *pStatus
);

typedef IMA_STATUS (* IMA_RegisterForObjectVisibilityChangesFn) (
		IMA_OBJECT_VISIBILITY_FN pClientFn
);

typedef IMA_STATUS (* IMA_DeregisterForObjectVisibilityChangesFn) (
		IMA_OBJECT_VISIBILITY_FN pClientFn
);

typedef IMA_STATUS (* IMA_RegisterForObjectPropertyChangesFn) (
		IMA_OBJECT_PROPERTY_FN pClientFn
);

typedef IMA_STATUS (* IMA_DeregisterForObjectPropertyChangesFn) (
		IMA_OBJECT_PROPERTY_FN pClientFn
);


typedef IMA_STATUS (* IMA_GetAddressKeyPropertiesFn)(
		IMA_OID targetOid,
		IMA_ADDRESS_KEY_PROPERTIES **ppProps
);

typedef IMA_STATUS (* IMA_GetIpPropertiesFn)(
		IMA_OID oid,
		IMA_IP_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_SetIpConfigMethodFn)(
		IMA_OID oid,
		IMA_BOOL enableDhcpIpConfiguration
);

typedef IMA_STATUS (* IMA_SetSubnetMaskFn)(
		IMA_OID oid,
		IMA_IP_ADDRESS subnetMask
);

typedef IMA_STATUS (* IMA_SetDnsServerAddressFn)(
		IMA_OID oid,
		const IMA_IP_ADDRESS *primaryDnsServerAddress,
		const IMA_IP_ADDRESS *alternateDnsServerAddress
);

typedef IMA_STATUS (* IMA_SetDefaultGatewayFn)(
		IMA_OID oid,
		IMA_IP_ADDRESS defaultGateway
);

typedef IMA_STATUS (* IMA_GetSupportedAuthMethodsFn)(
		IMA_OID lhbaOid,
		IMA_BOOL getSettableMethods,
		IMA_UINT *pMethodCount,
		IMA_AUTHMETHOD *pMethodList
);

typedef IMA_STATUS (* IMA_GetInUseInitiatorAuthMethodsFn)(
		IMA_OID	lhbaOid,
		IMA_UINT	*pMethodCount,
		IMA_AUTHMETHOD *pMethodList
);

typedef IMA_STATUS (* IMA_GetInitiatorAuthParmsFn)(
		IMA_OID lhbaOid,
		IMA_AUTHMETHOD method,
		IMA_INITIATOR_AUTHPARMS *pParms
);

typedef IMA_STATUS (* IMA_SetInitiatorAuthMethodsFn)(
		IMA_OID lhbaOid,
		IMA_UINT methodCount,
		const IMA_AUTHMETHOD *pMethodList
);

typedef IMA_STATUS (* IMA_SetInitiatorAuthParmsFn)(
		IMA_OID lhbaOid,
		IMA_AUTHMETHOD method,
		const IMA_INITIATOR_AUTHPARMS *pParms
);

typedef IMA_STATUS (* IMA_FreeMemoryFn)(
	void *pMemory
);

typedef IMA_STATUS (* IMA_GetStaticDiscoveryTargetOidListFn)(
                IMA_OID oid,
                IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_GetDiscoveryPropertiesFn)(
				IMA_OID oid,
				IMA_DISCOVERY_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_AddDiscoveryAddressFn)(
				IMA_OID oid,
				const IMA_TARGET_ADDRESS discoveryAddress,
				IMA_OID *pDiscoveryAddressOid
);

typedef IMA_STATUS (* IMA_AddStaticDiscoveryTargetFn)(
				IMA_OID oid,
				const IMA_STATIC_DISCOVERY_TARGET staticDiscoveryTarget,
				IMA_OID *pStaticDiscoveryTargetOid
);

typedef IMA_STATUS (* IMA_RemoveStaticDiscoveryTargetFn)(
				IMA_OID oid
);

typedef IMA_STATUS (* IMA_GetStaticDiscoveryTargetPropertiesFn)(
				IMA_OID staticDiscoveryTargetOid,
				IMA_STATIC_DISCOVERY_TARGET_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetDiscoveryAddressOidListFn) (
				IMA_OID Oid,
				IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_GetSessionOidListFn) (
				IMA_OID Oid,
				IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_GetConnectionOidListFn) (
				IMA_OID Oid,
				IMA_OID_LIST **ppList
);

typedef IMA_STATUS (* IMA_GetDiscoveryAddressPropertiesFn) (
		 IMA_OID discoveryAddressOid,
		 IMA_DISCOVERY_ADDRESS_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_RemoveDiscoveryAddressFn) (
		IMA_OID	discoveryAddressOid
);

typedef IMA_STATUS (* IMA_GetIpsecPropertiesFn) (
		IMA_OID oid,
		IMA_IPSEC_PROPERTIES *pProps
);

typedef IMA_STATUS (* IMA_GetAddressKeysFn) (
		IMA_OID targetOid,
		IMA_ADDRESS_KEYS **ppKeys
);

typedef IMA_STATUS (* QIMA_SetUpdateIntervalFn)(
        IMA_OID pluginOid,
        time_t interval
);

typedef IMA_STATUS (* IMA_CommitHbaParametersFn)(
				IMA_OID oid, IMA_COMMIT_LEVEL commitLevel
);

typedef IMA_STATUS (* SUN_IMA_GetTunablePropertiesFn) (
		IMA_OID oid,
       		ISCSI_TUNABLE_PARAM *param
);

typedef IMA_STATUS (* SUN_IMA_SetTunablePropertiesFn) (
		IMA_OID oid,
       		ISCSI_TUNABLE_PARAM *param
);

#endif

#ifdef __cplusplus
}
#endif

