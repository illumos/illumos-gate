/******************************************************************************
 *
 * Description
 *  mpapi-plugin.h - interfaces for the MP API Version 1.0 plugin library.
 *  A compliant plugin library should implement interfaces with name without Fn
 *  suffix from function definitions below.
 *
 * License:
 *  The contents of this file are subject to the SNIA Public License
 *  Version 1.1 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *
 *  TBD
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *  the License for the specific language governing rights and limitations
 *  under the License.
 *
 * The Original Code is iSCSI Management API and Multipath Management API
 * 	plugin header file
 *
 * The Initial Developer of the Original Code is:
 *	Benjamin F. Kuo Troika Networks, Inc. (benk@troikanetworks.com)
 *	David Dillard	VERITAS Software(david.dillard@veritas.com)
 *	Jeff Ding	Adaptec, Inc. (jding@corp.adaptec.com)
 *      Hyon Kim       	Sun Microsystems(hyon.kim@sun.com)
 *
 * Contributor(s):
 *	Paul von Behren	Sun Microsystems(paul.vonbehren@sun.com)
 *
 ******************************************************************************
 *
 *   Changes:
 *  1/15/2005 Implemented SNIA MP API specification 1.0
 *****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


#ifndef MPPLUGIN_H
#define MPPLUGIN_H

/*
 * MP API common library calls InitaizeFn as part of dynamically loading
 * the plugins.  For this version of implementation the common library
 * passes the sequence number of the plugin oid through InitializeFn.  The
 * sequnece number will be used as the ownerId for the plugin generated OIDs.
 */
typedef MP_STATUS (* InitializeFn)  (
        MP_UINT32   pluginOwnerID
    );

/*
 * MP API common library calls TerminateFn as part of dynamically unloading
 * the plugins.
 */
typedef MP_STATUS (* TerminateFn) (void);

/**
 ******************************************************************************
 *
 * Function table for OID and properties discovery API
 *
 ******************************************************************************
 */

typedef MP_STATUS (* MP_GetPluginPropertiesPluginFn)(
        MP_PLUGIN_PROPERTIES *pProps
);

typedef MP_STATUS (* MP_GetDeviceProductOidListPluginFn)(
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetDeviceProductPropertiesFn)(
	MP_OID 				oid,
        MP_DEVICE_PRODUCT_PROPERTIES *pProps
);

typedef MP_STATUS (* MP_GetInitiatorPortOidListPluginFn)(
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetInitiatorPortPropertiesFn)(
        MP_OID                        oid,
        MP_INITIATOR_PORT_PROPERTIES *pProps
);

typedef MP_STATUS (* MP_GetMultipathLusPluginFn)(
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetMultipathLusDevProdFn)(
	MP_OID	oid,
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetMPLogicalUnitPropertiesFn)(
        MP_OID                                oid,
        MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES *pProps
);

typedef MP_STATUS (* MP_GetAssociatedPathOidListFn)(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetPathLogicalUnitPropertiesFn)(
        MP_OID                           oid,
        MP_PATH_LOGICAL_UNIT_PROPERTIES *pProps
);

typedef MP_STATUS (* MP_GetAssociatedTPGOidListFn)(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetTargetPortGroupPropertiesFn)(
        MP_OID                           oid,
        MP_TARGET_PORT_GROUP_PROPERTIES *pProps
);

typedef MP_STATUS (* MP_GetMPLuOidListFromTPGFn)(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetProprietaryLoadBalanceOidListPluginFn)(
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetProprietaryLoadBalancePropertiesFn)(
        MP_OID        oid,
	MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES *pProps
);

typedef MP_STATUS (* MP_GetTargetPortOidListFn)(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

typedef MP_STATUS (* MP_GetTargetPortPropertiesFn)(
        MP_OID                     oid,
        MP_TARGET_PORT_PROPERTIES *pProps
);

/**
 ******************************************************************************
 *
 * Function table for path management API
 *
 ******************************************************************************
 */

typedef MP_STATUS (* MP_AssignLogicalUnitToTPGFn)(
        MP_OID tpgOid,
        MP_OID luOid
);

typedef MP_STATUS (* MP_SetOverridePathFn)(
    MP_OID logicalUnitOid,
    MP_OID pathOid
);

typedef MP_STATUS (* MP_CancelOverridePathFn)(
        MP_OID luOid
);

typedef MP_STATUS (* MP_EnableAutoFailbackPluginFn)(
);

typedef MP_STATUS (* MP_EnableAutoFailbackLuFn)(
    MP_OID oid
);

typedef MP_STATUS (* MP_EnableAutoProbingPluginFn)(
);

typedef MP_STATUS (* MP_EnableAutoProbingLuFn)(
    MP_OID oid
);

typedef MP_STATUS (* MP_DisableAutoFailbackPluginFn)(
);

typedef MP_STATUS (* MP_DisableAutoFailbackLuFn)(
    MP_OID oid
);

typedef MP_STATUS (* MP_DisableAutoProbingPluginFn)(
);

typedef MP_STATUS (* MP_DisableAutoProbingLuFn)(
    MP_OID oid
);

typedef MP_STATUS (* MP_EnablePathFn)(
    MP_OID oid
);

typedef MP_STATUS (* MP_DisablePathFn)(
    MP_OID oid
);

typedef MP_STATUS (* MP_SetLogicalUnitLoadBalanceTypeFn)(
    MP_OID               logicalUnitoid,
    MP_LOAD_BALANCE_TYPE loadBalance
);

typedef MP_STATUS (* MP_SetPathWeightFn)(
    MP_OID    pathOid,
    MP_UINT32 weight
);

typedef MP_STATUS (* MP_SetPluginLoadBalanceTypePluginFn)(
    MP_LOAD_BALANCE_TYPE loadBalance
);

typedef MP_STATUS (* MP_SetFailbackPollingRatePluginFn)(
    MP_UINT32 pollingRate
);

typedef MP_STATUS (* MP_SetFailbackPollingRateLuFn)(
    MP_OID	oid,
    MP_UINT32	pollingRate
);

typedef MP_STATUS (* MP_SetProbingPollingRatePluginFn)(
    MP_UINT32 pollingRate
);

typedef MP_STATUS (* MP_SetProbingPollingRateLuFn)(
    MP_OID	oid,
    MP_UINT32	pollingRate
);

typedef MP_STATUS (* MP_SetProprietaryPropertiesFn)(
    MP_OID             oid,
    MP_UINT32          count,
    MP_PROPRIETARY_PROPERTY *pPropertyList
);

typedef MP_STATUS (* MP_SetTPGAccessFn)(
    MP_OID             luOid,
    MP_UINT32          count,
    MP_TPG_STATE_PAIR *pTpgStateList
);

/**
 ******************************************************************************
 *
 * Function table for event support API
 *
 ******************************************************************************
 */

typedef MP_STATUS (* MP_RegisterForObjectPropertyChangesPluginFn)(
    MP_OBJECT_PROPERTY_FN   pClientFn,
    MP_OBJECT_TYPE	    objectType,
    void		    *pCallerData
);

typedef MP_STATUS (* MP_DeregisterForObjectPropertyChangesPluginFn)(
    MP_OBJECT_PROPERTY_FN   pClientFn,
    MP_OBJECT_TYPE	    objectType
);

typedef MP_STATUS (* MP_RegisterForObjectVisibilityChangesPluginFn)(
    MP_OBJECT_VISIBILITY_FN pClientFn,
    MP_OBJECT_TYPE	    objectType,
    void		    *pCallerData
);

typedef MP_STATUS (* MP_DeregisterForObjectVisibilityChangesPluginFn)(
    MP_OBJECT_VISIBILITY_FN pClientFn,
    MP_OBJECT_TYPE          objectType
);

typedef MP_STATUS (* Sun_MP_SendScsiCmdFn)(
    MP_OID oid, struct uscsi_cmd *cmd
);

#endif

#ifdef __cplusplus
};
#endif

