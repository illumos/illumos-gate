/******************************************************************************
 *
 * Description
 *  mpapi.h - general header file for Multipath Management API Version 1.0
 *  client
 *
 * License:
 *  The contents of this file are subject to the SNIA Public License
 *  Version 1.1 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *
 *  http://mp-mgmt-api.sourceforge.net
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *  the License for the specific language governing rights and limitations
 *  under the License.
 *
 * The Original Code is  SNIA iSCSI Management API and Multipath Management API
 *	general header file
 *
 * The Initial Developer of the Original Code is:
 *	Benjamin F. Kuo Troika Networks, Inc. (benk@troikanetworks.com)
 *	David Dillard	VERITAS Software(david.dillard@veritas.com)
 *	Jeff Ding	Adaptec, Inc. (jding@corp.adaptec.com)
 *	Dave Wysochanski Network Appliance, Inc. (davidw@netapp.com)
 *      Hyon Kim       	Sun Microsystems(hyon.kim@sun.com)
 *
 * Contributor(s):
 *	Paul von Behren Sun Microsystems(paul.vonbehren@sun.com)
 *
 ******************************************************************************
 *
 *   Changes:
 *  1/15/2005   Implemented SNIA MP API specification 1.0
 *  10/11/2005
 *		- Added the license location in the header comment.
 *	  	- Added an implementation note in constants and macros
 *		  declarations section.
 *		- Fixed field name value in struct _MP_PROPRIETARY_PROPERTY.
 *		- Fixed typo in logicalUnitGroupID in
 *		  _MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES
 *		- Fixed typo in desiredState in struct _MP_TPG_STATE_PAIR.
 *		- Fixed typo in API name MP_GetTargetPortGroupProperties.
 *		- Clarified description of MP_STATUS_INVALID_PARAMETER error
 *		  in MP_GetObjectType().
 *		- Fixed typo in API name
 *		  MP_GetProprietaryLoadBalanceProperties().
 *  3/6/2006
 *		- mpapi.h header file is updated for
 *		  MP_LOAD_BALANCE_TYPE change in the spec.
 *****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


#ifndef MPAPI_H
#define MPAPI_H

#include <time.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>


/* Library version string */
#define MP_LIBVERSION 1

/**
 *******************************************************************************
 *
 * Generic MP Constant Definitions
 *
 *******************************************************************************
 */
#define RL_LIBRARY_SEQNUM           0

/**
* Value which can be assigned to an MP_BOOL and or an MP_XBOOL.
*/
#define MP_TRUE        1

/**
* Value which can be assigned to an MP_BOOL and or an MP_XBOOL.
*/
#define MP_FALSE       0

/**
* Value which can be assigned to an MP_XBOOL.
*/
#define MP_UNKNOWN     0xFFFFFFFF

#define MP_MAX_NUM_PLUGINS	64
#define MP_OBJECT_TYPE_MATCH	1
#define MP_OBJECT_TYPE_ANY	2
#define MAX_NAME_SIZE		256
#define MAX_LINE_SIZE		515


/**
 ******************************************************************************
 *
 * Base MP API Type Definitions
 *
 ******************************************************************************
 */

typedef unsigned char   MP_UINT8;  /* unsigned  8 bits */
typedef char            MP_INT8;   /* signed    8 bits */
typedef unsigned short  MP_UINT16; /* unsigned 16 bits */
typedef short           MP_INT16;  /* signed   16 bits */
typedef unsigned int    MP_UINT32; /* unsigned 32 bits */
typedef int             MP_INT32;  /* signed   32 bits */
typedef void*           MP_PVOID;  /* pointer  to void */
typedef MP_UINT32       MP_VOID32; /* opaque   32 bits */
typedef long long	MP_INT64;  /* signed   64 bits */
typedef unsigned long long	 MP_UINT64; /* unsigned 64 bits */

/**
 * A character.
 */
typedef char MP_CHAR;

/**
 * A wide character.
 */
typedef wchar_t MP_WCHAR;

/**
 * An unsigned character.
 */
typedef unsigned char MP_BYTE;

/**
 * A boolean.
 */
typedef MP_UINT32 MP_BOOL;

/**
 * An extended boolean: can have the values @ref MP_TRUE, @ref MP_FALSE, and
 * @ref MP_UNKNOWN.
 */
typedef MP_UINT32 MP_XBOOL;

/**
 ******************************************************************************
 *
 * Constants and macros declarations related to MP_STATUS
 * Implementation Notes:  This library does validation for OID argument and
 *			  returns the following errors.
 *
 *		1. MP_STATUS_INVALID_OBJECT_TYPE when input OID type is not
 *		   one of legitimate types defined SNIA Multipath Management
 *		   Spec.
 *		2. MP_STATUS_INVALID_PARAMETER when input OID type is
 *		   legitimate but not a proper type for API.
 *		3. MP_STATUS_OBJECT_NOT_FOUND when the ownerId of input OID is
 *		   not found or no object instance with matching
 *		   sequenceNumber is found.
 *		   The ownerId is validated by the common library and the
 *		   sequence number is validated by the plugin library.
 *
 ******************************************************************************
 */
typedef enum {
    MP_STATUS_SUCCESS               = 0,
    MP_STATUS_INVALID_PARAMETER     = 1,
    MP_STATUS_UNKNOWN_FN	    = 2,
    MP_STATUS_FAILED                = 3,
    MP_STATUS_INSUFFICIENT_MEMORY   = 4,
    MP_STATUS_INVALID_OBJECT_TYPE   = 5,
    MP_STATUS_OBJECT_NOT_FOUND      = 6,
    MP_STATUS_UNSUPPORTED           = 7,
    MP_STATUS_FN_REPLACED           = 8,
    MP_STATUS_ACCESS_STATE_INVALID  = 9,
    MP_STATUS_INVALID_WEIGHT        = 10,
    MP_STATUS_PATH_NONOPERATIONAL   = 11,
    MP_STATUS_TRY_AGAIN		    = 12,
    MP_STATUS_NOT_PERMITTED	    = 13

} MP_STATUS;

/**
 ******************************************************************************
 *
 * Declaration of the MP_PATH_STATE constants
 *
 ******************************************************************************
 */
#define MP_PATH_STATE_OKAY	    0
#define MP_PATH_STATE_PATH_ERR      1
#define MP_PATH_STATE_LU_ERR        2
#define MP_PATH_STATE_RESERVED      3
#define MP_PATH_STATE_REMOVED       4
#define MP_PATH_STATE_TRANSITIONING 5
#define MP_PATH_STATE_OPERATIONAL_CLOSED    6
#define MP_PATH_STATE_INVALID_CLOSED	    7
#define MP_PATH_STATE_OFFLINE_CLOSED	    8
#define MP_PATH_STATE_UNKNOWN       	    9

typedef MP_UINT32 MP_PATH_STATE;

/**
 *******************************************************************************
 *
 * Declaration of the MP_OBJECT_TYPE constants
 *
 *******************************************************************************
 */
#define MP_OBJECT_TYPE_UNKNOWN              0
#define MP_OBJECT_TYPE_PLUGIN               1
#define MP_OBJECT_TYPE_INITIATOR_PORT       2
#define MP_OBJECT_TYPE_TARGET_PORT          3
#define MP_OBJECT_TYPE_MULTIPATH_LU         4
#define MP_OBJECT_TYPE_PATH_LU              5
#define MP_OBJECT_TYPE_DEVICE_PRODUCT       6
#define MP_OBJECT_TYPE_TARGET_PORT_GROUP    7
#define MP_OBJECT_TYPE_PROPRIETARY_LOAD_BALANCE	8

/* set to the highest constant of object type. */
#define MP_OBJECT_TYPE_MAX          8

typedef MP_UINT32 MP_OBJECT_TYPE;

/**
 *******************************************************************************
 *
 * Declaration of the MP_PORT_TRANSPORT_TYPE
 *
 *******************************************************************************
 */
#define MP_PORT_TRANSPORT_TYPE_UNKNOWN  0
#define MP_PORT_TRANSPORT_TYPE_MPNODE   1
#define MP_PORT_TRANSPORT_TYPE_FC       2
#define MP_PORT_TRANSPORT_TYPE_SPI      3
#define MP_PORT_TRANSPORT_TYPE_ISCSI    4
#define MP_PORT_TRANSPORT_TYPE_IFB      5

typedef MP_UINT32 MP_PORT_TRANSPORT_TYPE;

/**
 *******************************************************************************
 *
 * Declaration of the MP_ACCESS_STATE_TYPE constants
 *
 *******************************************************************************
 */
#define MP_ACCESS_STATE_ACTIVE_OPTIMIZED    (0x0)
#define MP_ACCESS_STATE_ACTIVE_NONOPTIMIZED (0x1)
#define MP_ACCESS_STATE_STANDBY             (0x2)
#define MP_ACCESS_STATE_UNAVAILABLE         (0x3)
#define MP_ACCESS_STATE_TRANSITIONING       (0xF)
#define MP_ACCESS_STATE_ACTIVE              (0x10)

typedef MP_UINT32 MP_ACCESS_STATE_TYPE;

/**
 *******************************************************************************
 *
 * Declaration of the MP_LOAD_BALANCE_TYPE constants
 *
 *******************************************************************************
 */
#define MP_LOAD_BALANCE_TYPE_UNKNOWN        (1<<0)
#define MP_LOAD_BALANCE_TYPE_ROUNDROBIN     (1<<1)
#define MP_LOAD_BALANCE_TYPE_LEASTBLOCKS    (1<<2)
#define MP_LOAD_BALANCE_TYPE_LEASTIO        (1<<3)
#define MP_LOAD_BALANCE_TYPE_DEVICE_PRODUCT (1<<4)
#define MP_LOAD_BALANCE_TYPE_LBA_REGION     (1<<5)
#define MP_LOAD_BALANCE_TYPE_FAILOVER_ONLY  (1<<6)
/**
 * Proprietary load balance type should start from 0x10000(1<<16) or greater.
 * It is exposed through API MP_GetProprietaryLoadBalanceProperties if exists.
 */

typedef MP_UINT32 MP_LOAD_BALANCE_TYPE;

typedef struct mpPluginInfo {
      MP_WCHAR        pluginName[MAX_NAME_SIZE];
      MP_CHAR         pluginPath[MAX_NAME_SIZE];
      void*           hdlPlugin;
      MP_UINT32       ownerId;
} MPPLUGININFO_T;


/**
 *******************************************************************************
 *
 * Declaration of the MP_PROPRIETARY_PROPERTY
 *
 *******************************************************************************
 */
typedef struct _MP_PROPRIETARY_PROPERTY
{
    MP_WCHAR                name[16];
    MP_WCHAR                value[48];

} MP_PROPRIETARY_PROPERTY;

/**
 *******************************************************************************
 *
 * Declaration of the MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES
 *
 *******************************************************************************
 */
typedef struct _MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES
{
    MP_LOAD_BALANCE_TYPE    typeIndex;
    MP_WCHAR                name[256];
    MP_WCHAR                vendorName[256];
    MP_UINT32		    proprietaryPropertyCount;
    MP_PROPRIETARY_PROPERTY proprietaryProperties[8];

} MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_UINT32 MP_LOGICAL_UNIT_NAME_TYPE constants
 *
 *******************************************************************************
 */
#define MP_LU_NAME_TYPE_UNKNOWN         0
#define MP_LU_NAME_TYPE_VPD83_TYPE1     1
#define MP_LU_NAME_TYPE_VPD83_TYPE2     2
#define MP_LU_NAME_TYPE_VPD83_TYPE3     3
#define MP_LU_NAME_TYPE_DEVICE_SPECIFIC 4

typedef MP_UINT32 MP_LOGICAL_UNIT_NAME_TYPE;

/**
 *******************************************************************************
 *
 * Declaration of the MP_UINT32 MP_AUTOFAILBACK_SUPPORT constants
 *
 *******************************************************************************
 */
#define MP_AUTOFAILBACK_SUPPORT_NONE	0
#define MP_AUTOFAILBACK_SUPPORT_PLUGIN	1
#define MP_AUTOFAILBACK_SUPPORT_MPLU	2
#define MP_AUTOFAILBACK_SUPPORT_PLUGINANDMPLU	3

typedef MP_UINT32 MP_AUTOFAILBACK_SUPPORT;

/**
 *******************************************************************************
 *
 * Declaration of the MP_UINT32 MP_AUTOPROBING_SUPPORT constants
 *
 *******************************************************************************
 */
#define MP_AUTOPROBING_SUPPORT_NONE	0
#define MP_AUTOPROBING_SUPPORT_PLUGIN	1
#define MP_AUTORPOBING_SUPPORT_MPLU	2
#define MP_AUTORPOBING_SUPPORT_PLUGINANDMPLU	3

typedef MP_UINT32 MP_AUTOPROBING_SUPPORT;

/**
 *******************************************************************************
 *
 * Declaration of the MP_OID structure
 *
 * This structure should be treated as opaque by clients of the API.
 * Appropriate APIs should be used to extract information from the structure.
 *
 * Also ZERO_OID is defined for APIs that may handle multiple plugin OIDs.
 *
 *******************************************************************************
 */
typedef struct _MP_OID
{
    /**
     * The type of the object.  When an object ID is supplied as a parameter
     * to an API the library uses this value to insure that the supplied
     * object ID's type is appropriate for the API.
     */
    MP_OBJECT_TYPE objectType;

    /**
     * A value determined by the library which it uses to uniquely identify the
     * owner of an object.  The owner of an object is either the library itself
     * or a plugin.  When an object ID is supplied as a parameter to an API the
     * library uses this value to determine if it should handle the call itself
     * or direct the call to one or more plugins.
     */
    MP_UINT32      ownerId;

    /**
     * A value determined by a plugin which a plugin uses, perhaps in
     * combination with the object type, to uniquely identify one of its
     * objects.
     */
    MP_UINT64      objectSequenceNumber;

} MP_OID;

#define ZERO_OID ((const MP_OID){MP_OBJECT_TYPE_UNKNOWN,0,0})

/**
 *******************************************************************************
 *
 * Declaration of the MP_OID_LIST structure
 *
 * This structure is used by a number of APIs to return lists of objects.  Any
 * instance of this structure returned by an API must be freed by a client
 * using the MP_FreeOidList API.  Although oids is declared to be an
 * array of one
 * @ref MP_OID structure it can in fact contain any number of
 * @ref MP_OID structures.  The oidCount indicates the number of @ref MP_OID
 * structures in the oids array.
 *
 * @note The @a oids array is a variable length array, despite its declaration
 *       below it can be of any length.
 *
 *******************************************************************************
 */
typedef struct _MP_OID_LIST
{
    /**
     * The number of object IDs in the @a oids array.
     */
    MP_UINT32       oidCount;

    /**
     * A variable length array of zero or more object IDs.  There are
     * 'oidCount' object IDs in this array.
     */
    MP_OID         oids[1];

} MP_OID_LIST;

/**
 *******************************************************************************
 *
 * Declaration of the MP_LIBRARY_PROPERTIES structure
 *
 * This structure is returned by the MP_GetLibraryProperties() API.
 *
 *******************************************************************************
 */
typedef struct _MP_LIBRARY_PROPERTIES
{
    /**
     * The version of the Multipath Management API implemented by the library.
     */
    MP_UINT32       supportedMpVersion;

    /**
     * A null terminated ASCII string containing the name of the vendor that
     * created the binary version of the library.
     */
    MP_WCHAR        vendor[256];

    /**
     * A null terminated ASCII string containing the implementation version
     * of the library from the vendor specified in the 'vendor' field.
     */
    MP_WCHAR        implementationVersion[256];

    /**
     * A null terminated ASCII string ideally containing the path and file
     * name of the library that is being used by the currently executing
     * process can be found. If the path cannot be determined then it is
     * acceptable to fill this field with only the name (and extension if
     * applicable) of the file of the library.  If this cannot be determined
     * then this field should be an empty string.
     */
    MP_CHAR        fileName[256];

    /**
     * The time and date that the library that is executing was built.
     */
    MP_WCHAR        buildTime[256];

} MP_LIBRARY_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_PLUGIN_PROPERTIES structure
 *
 * This structure is returned by the MP_GetPluginProperties() API.
 *
 *******************************************************************************
 */
typedef struct _MP_PLUGIN_PROPERTIES
{
    /**
     * The version of the Multipath Management API implemented by a plugin.
     */
    MP_UINT32 supportedMpVersion;

    /**
     * A null terminated Unicode string containing the name of the vendor that
     * created the binary version of the plugin.
     */
    MP_WCHAR vendor[256];

    /**
     * A null terminated Unicode string containing the implementation version
     * of the plugin from the vendor specified in vendor.
     */
    MP_WCHAR implementationVersion[256];

    /**
     * A null terminated ASCII string ideally containing the path and file
     * name of the plugin that is filling in this structure.
     */
    MP_CHAR fileName[256];

    /**
     * The time and date that the plugin that is executing was built.
     */
    MP_WCHAR buildTime[256];

    /**
     * A null terminated Unicode string containing the name of the multipath
     * driver vendor associated with this plugin.
     */
    MP_WCHAR driverVendor[256];

    /**
     * A null terminated Unicode string ideally containing the path and file
     * name of the plugin that is filling in this structure.
     */
    MP_CHAR driverName[256];

    /**
     * A null terminated Unicode string containing the version number of
     * the multipath driver.
     */
    MP_WCHAR driverVersion[256];

    /**
     * A set of flags representing the load balance types
     * (MP_LOAD_BALANCE_TYPES) supported by the plugin/driver as a plugin-wide
     * property.
     */
    MP_UINT32 supportedLoadBalanceTypes;

    /**
     * boolean indicating whether the implementation supports activating target
     * port groups.
     */
    MP_BOOL canSetTPGAccess;

    /**
     * A Boolean indicating whether the implementations supports overriding
     * paths. Setting this to true indicates MP_SetOverridePath and
     * MP_CancelOverridePath are supported.
     */
    MP_BOOL canOverridePaths;

    /**
     * A boolean indicating whether the implementation exposes (or leaves
     * exposed) device files for the individual paths encapsulated by the
     * multipath device file. This is typically true for MP drivers that sit
     * near the top of the driver stack..
     */
    MP_BOOL exposesPathDeviceFiles;

    /**
     * A string representing the primary file names the driver uses for
     * multipath logical units.
     */
    MP_CHAR deviceFileNamespace[256];

    /**
     * A boolean indicating whether the driver limits multipath capabilities
     * to certain device types. If true, then the driver only provides multipath
     * support to devices exposed through MP_DEVICE_PRODUCT_PROPERTIES
     * instances. If false, then the driver supports any device that provides
     * standard SCSI logical unit identifiers.
     */
    MP_BOOL onlySupportsSpecifiedProducts;

    /**
     * Describes the range of administer settable path weights supported by the
     * driver. A driver with no path preference capabilities should set
     * this property to zero. A driver with the ability to enable/disable
     * paths should set this property to 1. Drivers with more weight settings
     * can set the property appropriately.
     */
    MP_UINT32 maximumWeight;

    /**
     * The autofailback support indicates whether the implementation supports
     * auto-failback (to reenable paths that revert to a good state) at the
     * plugin level, the multipath logical unit level, both levels or whether
     * auto-failback is unsupported.
     */
    MP_AUTOFAILBACK_SUPPORT autoFailbackSupport;

    /**
     * A Boolean indicating whether plugin-wide autofailback is currently
     * enabled. This parameter is undefined if autoFailbackSupport is
     * MP_AUTOFAILBACK_SUPPORT_NONE or MP_AUTOFAILBACK_SUPPORT_MPLU.
     */
    MP_BOOL pluginAutoFailbackEnabled;

    /**
     * The maximum plugin-wide polling rate (in seconds) for auto-failback
     * supported by the driver. A value of zero indicates the driver/plugin
     * does not support polling. Undefined if autoFailbackSupport is
     * MP_AUTOFAILBACK_SUPPORT_NONE or MP_AUTOFAILBACK_SUPPORT_MPLU. If the
     * plugin/driver supports auto-failback without polling or does not provide
     * a way to set the polling rate, then this must be set to zero (0).
     * This value is set by the plugin and cannot be modified by users.
     */
    MP_UINT32 failbackPollingRateMax;

    /**
     * The current plugin-wide auto-failback polling rate (in seconds).
     * Undefined if autofailbackSupport is MP_AUTOFAILBACK_SUPPORT_NONE or
     * MP_AUTOFAILBACK_SUPPORT_MPLU. Cannot be more that plooingRateMax.
     */
    MP_UINT32 currentFailbackPollingRate;

    /**
     * An enumerated type indicating whether the implementation supports
     * auto-probing at the plugin level, the multipath logical unit level, both
     * levels or whether auto-probing is unsupported.
     */
    MP_AUTOPROBING_SUPPORT autoProbingSupport;

    /**
     * A boolean indicating that plugin-wide auto-probing is enabled. This
     * property is undefined if autoProbingSupport is
     * MP_AUTOPROBING_SUPPORT_NONE or MP_AUTOPROBING_SUPPORT_MPLU.
     */
    MP_BOOL pluginAutoProbingEnabled;

    /**
     * The maximum plugin-wide polling rate (in seconds) for auto-probing
     * supported by the driver. Undefined if autoProbingSupport is
     * MP_AUTOPROBING_SUPPORT_NONE or MP_AUTOPROBING_SUPPORT_MPLU. If the
     * plugin/driver supports auto-probing without polling or does not provide a
     * way to set the probing polling rate, then this must be set to zero (0).
     * This value is set by the plugin and cannot be modified by users.
     */
    MP_UINT32 probingPollingRateMax;

    /**
     * The current plugin-wide auto-probing polling rate (in seconds).
     * Undefined if autoProbingSupport is MP_AUTOPROBING_SUPPORT_NONE or
     * MP_AUTOPROBING_SUPPORT_MPLU. Cannot be more that probingPollingRateMax.
     */
    MP_UINT32 currentProbingPollingRate;

    /**
     * The load balance type that will be used by the driver for devices
     * (without a corresponding MP_DEVICE_PRODUCT_PROPERTIES instance) unless
     * overridden by the administrator. Any logical unit with vendor, product,
     * and revision properties matching a MP_DEVICE_PRODUCT_PROPERTIES instance
     * will default to a device-specific load balance type.
     */
    MP_LOAD_BALANCE_TYPE defaultloadBalanceType;

    /**
     * The count of proprietary properties (less that or equal to eight)
     * supported.
     */
    MP_UINT32	proprietaryPropertyCount;

    /**
     * A list of proprietary property name/value pairs.
     */
    MP_PROPRIETARY_PROPERTY proprietaryProperties[8];

} MP_PLUGIN_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_DEVICE_PRODUCT_PROPERTIES structure.
 *
 * This structure is returned by the MP_GetDeviceProductProperties() API.
 *
 *******************************************************************************
 */
typedef struct _MP_DEVICE_PRODUCT_PROPERTIES
{
    MP_CHAR	    vendor[8];
    MP_CHAR	    product[16];
    MP_CHAR	    revision[4];
    MP_UINT32	    supportedLoadBalanceTypes;

} MP_DEVICE_PRODUCT_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES structure.
 *
 * This structure is returned by the MP_GetMPLogicalUnitProperties() API.
 *
 *******************************************************************************
 */
typedef struct _MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES
{
    MP_CHAR			vendor[8];
    MP_CHAR			product[16];
    MP_CHAR			revision[4];
    MP_CHAR			name[256];
    MP_LOGICAL_UNIT_NAME_TYPE   nameType;
    MP_CHAR			deviceFileName[256];
    MP_BOOL			asymmetric;
    MP_OID			overridePath;
    MP_LOAD_BALANCE_TYPE	currentLoadBalanceType;
    MP_UINT32			logicalUnitGroupID;
    MP_XBOOL			autoFailbackEnabled;
    MP_UINT32			failbackPollingRateMax;
    MP_UINT32			currentFailbackPollingRate;
    MP_XBOOL 			autoProbingEnabled;
    MP_UINT32 			probingPollingRateMax;
    MP_UINT32 			currentProbingPollingRate;
    MP_UINT32 			proprietaryPropertyCount;
    MP_PROPRIETARY_PROPERTY 	proprietaryProperties[8];

} MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_PATH_LOGICAL_UNIT_PROPERTIES structure.
 *
 * This structure is returned by the MP_GetPathLogicalUnitProperties() API.
 *
 *******************************************************************************
 */
typedef struct _MP_PATH_LOGICAL_UNIT_PROPERTIES
{
    MP_UINT32	    weight;
    MP_PATH_STATE   pathState;
    MP_BOOL	    disabled;
    MP_OID	    initiatorPortOid;
    MP_OID	    targetPortOid;
    MP_OID	    logicalUnitOid;
    MP_UINT64	    logicalUnitNumber;
    MP_CHAR	    deviceFileName[256];
    MP_UINT32	    busNumber;
    MP_UINT32	    portNumber;

} MP_PATH_LOGICAL_UNIT_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_INITIATOR_PORT_PROPERTIES structure.
 *
 * This structure is returned by the MP_GetInitiatorPortProperties() API.
 *
 *******************************************************************************
 */
typedef struct _MP_INITIATOR_PORT_PROPERTIES
{
    MP_CHAR		    portID[256];
    MP_PORT_TRANSPORT_TYPE  portType;
    MP_CHAR		    osDeviceFile[256];
    MP_WCHAR		    osFriendlyName[256];

} MP_INITIATOR_PORT_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_TARGET_PORT_PROPERTIES structure.
 *
 * This structure is returned by the MP_GetTargetPortProperties() API.
 *
 *******************************************************************************
 */
typedef struct _MP_TARGET_PORT_PROPERTIES
{
    MP_CHAR	portID[256];
    MP_UINT32	relativePortID;

} MP_TARGET_PORT_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_TARGET_PORT_GROUP_PROPERTIES structure.
 *
 * This structure is returned by the MP_GetTargetPortGroupProperties() API.
 *
 *******************************************************************************
 */
typedef struct _MP_TARGET_PORT_GROUP_PROPERTIES
{
    MP_ACCESS_STATE_TYPE    accessState;
    MP_BOOL                 explicitFailover;
    MP_BOOL                 supportsLuAssignment;
    MP_BOOL		    preferredLuPath;
    MP_UINT32		    tpgID;

} MP_TARGET_PORT_GROUP_PROPERTIES;

/**
 *******************************************************************************
 *
 * Declaration of the MP_TPG_STATE_PAIR structure.
 *
 * This structure is used as an argument for the MP_SetTPGAcess() API.
 *
 *******************************************************************************
 */
typedef struct _MP_TPG_STATE_PAIR
{
    MP_OID                  tpgOid;
    MP_ACCESS_STATE_TYPE    desiredState;

} MP_TPG_STATE_PAIR;

/**
 *******************************************************************************
 *
 * Declaration of call back function type for event support
 *
 *******************************************************************************
 */
typedef void (* MP_OBJECT_PROPERTY_FN) (
    MP_OID_LIST *pOidList, void *pCallerData
);

typedef void (* MP_OBJECT_VISIBILITY_FN) (
    MP_BOOL becomingVisible, MP_OID_LIST *pOidList, void *pCallerData
);

void InitLibrary();
void ExitLibrary();

/**
 ******************************************************************************
 *
 * The APIs for property and object related discovery.
 *
 * - MP_GetLibraryProperties
 * - MP_GetPluginOidList
 * - MP_GetPluginProperties
 * - MP_GetAssociatedPluginOid
 * - MP_GetObjectType
 * - MP_GetDeviceProductOidList
 * - MP_GetDeviceProductProperties
 * - MP_GetInitiatorPortOidList
 * - MP_GetInitiatorPortProperties
 * - MP_GetMultipathLus
 * - MP_GetMPLogicalUnitProperties
 * - MP_GetAssociatedPathOidList
 * - MP_GetPathLogicalUnitProperties
 * - MP_GetAssociatedTPGOidList
 * - MP_GetTargetPortGroupProperties
 * - MP_GetMPLuOidListFromTPG
 * - MP_GetProprietaryLoadBalanceOidList
 * - MP_GetProprietaryLoadBalanceProperties
 * - MP_GetTargetPortOidList
 * - MP_GetTargetPortProperties
 *
 ******************************************************************************
 */

/**
 *******************************************************************************
 *
 * Gets the properties of the MP API library that is being used.
 *
 * @param  pProps
 *         A pointer to an MP_LIBRARY_PROPERTIES structure allocated by
 *         the caller.  On successful return this structure will contain the
 *         properties of the MP API library.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *          Returned if the library properties were successfully returned.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding the
 *      library properties is found to be invalid.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API.
 *
 ******************************************************************************
 */
MP_STATUS MP_GetLibraryProperties(
        MP_LIBRARY_PROPERTIES *pProps
);

/**
 ******************************************************************************
 *
 * Gets a list of the object IDs of all currently loaded plugins.
 *
 * @param ppList
 *        A pointer to a pointer to an MP_OID_LIST.  On successful
 *        return this will contain a pointer to an @ref MP_OID_LIST
 *        which contains the object IDs of all of the plugins currently
 *        loaded by the library.
 *
 * @return MP_STATUS indicating if the operation was successful or
 *          if an error occurred.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *      Returned if oid does not specify any valid object type. This is
 *      most likely to happen if an uninitialized object ID is passed to
 *      the API.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList is NULL or specifies a memory area to which data
 *      cannot be written. MP_STATUS_SUCCESS Returned when the operation is
 *      successful.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs*
 *
 * @retval MP_STATUS_SUCCESS
 *          Returned if the plugin ID list was successfully returned.
 *
 ******************************************************************************
 */
MP_STATUS MP_GetPluginOidList(
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets the properties of the specified vendor plugin.
 *
 * @param  oid
 *         The ID of the plugin whose properties are being retrieved.
 *
 * @param  pProps
 *         A pointer to an @ref MP_PLUGIN_PROPERTIES structure allocated by
 *         the caller.  On successful return this will contain the properties
 *         of the plugin specified by pluginOid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if an
 *         error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned if the plugin properties were successfully returned.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *         Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *         Returned if oid has an owner that is not currently known to
 *     the system.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *         Returned if 'pProps' is NULL or specifies a memory area to
 *         which data cannot be written.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetPluginProperties(
        MP_OID                oid,
        MP_PLUGIN_PROPERTIES *pProps
);


/**
 *******************************************************************************
 *
 * Gets the object ID for the plugin associated with the specified object ID.
 *
 * @param  oid
 *         The object ID of an object that has been received from a previous
 *         library call.
 *
 * @param  pPluginOid
 *         A pointer to an MP_OID structure allocated by the caller.  On
 *         successful return this will contain the object ID of the plugin
 *         associated with the object specified by @a objectId.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *          Returned if the associated plugin ID was successfully returned.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid does not specify a plugin that is currently known to
 *     the system.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *          Returned if 'oid' specifies an object not owned by a plugin or
 *     	    if pPluginOid is NULL or specifies a memory area to which data
 *          cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if 'oid' specifies an object with an invalid type.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetAssociatedPluginOid(
        MP_OID  oid,
        MP_OID *pPluginOid
);


/**
 *******************************************************************************
 *
 * Gets the object type of an initialized object ID.
 *
 * @param  oid
 *         The object ID of an object that has been received from a previous
 *         library call.
 *
 * @param  pObjectType
 *         A pointer to an MP_OBJECT_TYPE variable allocated by the caller.
 *         On successful return this will contain the object type of oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or
 *         if an error occurred.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned if oid has an owner that is not currently known to
 *      the system.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetObjectType(
        MP_OID          oid,
        MP_OBJECT_TYPE *pObjectType
);


/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the device product properties
 *       associated with this plugin.
 *
 * @param  oid
 *         The object ID of plugin.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the device
 *      product descriptors associated with the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the device product list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *         Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *         Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetDeviceProductOidList(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets the device product properties of the specified plugin oid.
 *
 * @param  oid
 *         The object ID of the plugin.
 *
 * @param  ppProps
 *      A pointer to an MP_DEVICE_PRODUCT_PROPERTIES structure
 *      allocated by the caller. On successful return it will contain
 *      a pointer to an MP_DEVICE_PRODUCT_PROPERTIES structure allocated
 *      by the library.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppProps pointer passed as placeholder for holding
 *      the device product properties is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *         Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *         Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetDeviceProductProperties(
        MP_OID                         oid,
        MP_DEVICE_PRODUCT_PROPERTIES *pProps
);

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the initiator ports associated
 * with this plugin.
 *
 * @param  oid
 *         The object ID of plugin.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the initiator
 *      ports associated with the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the initiator port list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetInitiatorPortOidList(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets the properties of the specified initiator port.
 *
 * @param  oid
 *         The object ID of the initiator port.
 *
 * @param  pProps
 *      A pointer to an MP_INITIATOR_PORT_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetInitiatorPortProperties(
        MP_OID                        oid,
        MP_INITIATOR_PORT_PROPERTIES *pProps
);

/**
 *******************************************************************************
 *
 * Gets a list of multipath logical units associated to a plugin.
 *
 * @param  oid
 *         The object ID of plugin.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the multipath
 *      logical units associated with the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the multipath logical unit list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetMultipathLus(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets the properties of the specified logical unit.
 *
 * @param  oid
 *         The object ID of the multipath logical unit.
 *
 * @param  pProps
 *      A pointer to an MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetMPLogicalUnitProperties(
        MP_OID                                oid,
        MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES *pProps
);

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the path logical units associated
 * with the specified multipath logical unit, initiator port, or target port.
 *
 * @param  oid
 *         The object ID of multipath logical unit, initiator port, or
 *     target port.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the mp path
 *      logical units associated with the specified OID.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the device product list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetAssociatedPathOidList(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets the properties of the specified path logical unit.
 *
 * @param  oid
 *         The object ID of the path logical unit.
 *
 * @param  pProps
 *      A pointer to an MP_PATH_LOGICAL_UNIT_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetPathLogicalUnitProperties(
        MP_OID                           oid,
        MP_PATH_LOGICAL_UNIT_PROPERTIES *pProps
);

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the target port group associated
 * with the specified multipath logical unit.
 *
 * @param  oid
 *         The object ID of the multiple logical unit.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the target
 *      port group associated with the specified multipath logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the target port group list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 *
 *******************************************************************************
 */
MP_STATUS MP_GetAssociatedTPGOidList(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets the properties of the specified target port group.
 *
 * @param  oid
 *         The object ID of the target port group.
 *
 * @param  pProps
 *      A pointer to an MP_TARGET_PORT_GROUP_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetTargetPortGroupProperties(
        MP_OID                           oid,
        MP_TARGET_PORT_GROUP_PROPERTIES *pProps
);

/**
 *******************************************************************************
 *
 * Gets a list of multipath logical units associated with the specific target
 *  port group.
 *
 * @param  oid
 *         The object ID of the target port group.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the multipath
 *      logical units associated with the specified target port group.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the multipath logical unit list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 *******************************************************************************
 */
MP_STATUS MP_GetMPLuOidListFromTPG(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the proprietary load balance
 * algorithms associated with this plugin.
 *
 * @param  oid
 *         The object ID of the plugin.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the proprietary
 *      load balance algorithms associated with the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the proprietary load balance oid list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetProprietaryLoadBalanceOidList(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets the properties of the specified load balance properties structure.
 *
 * @param  oid
 *         The object ID of the proprietary load balance structure.
 *
 * @param  pProps
 *      A pointer to an MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *      Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetProprietaryLoadBalanceProperties(
        MP_OID                     oid,
        MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES *pProps
);

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of the target ports in the specified target
 * port group.
 *
 * @param  oid
 *         The object ID of the target port group.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the target ports
 *      associated with the specified target port group.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the multipath logical unit list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 *******************************************************************************
 */
MP_STATUS MP_GetTargetPortOidList(
        MP_OID        oid,
        MP_OID_LIST **ppList
);

/**
 *******************************************************************************
 *
 * Gets the properties of the specified target port.
 *
 * @param  oid
 *         The object ID of the target port.
 *
 * @param  pProps
 *      A pointer to an MP_TARGET_PORT_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetTargetPortProperties(
        MP_OID                     oid,
        MP_TARGET_PORT_PROPERTIES *pProps
);

/**
 ******************************************************************************
 *
 * The APIs for path management.
 *
 * - MP_AssignLogicalUnitToTPG
 * - MP_SetOverridePath
 * - MP_CancelOverridePath
 * - MP_EnableAutoFailback
 * - MP_DisableAutoFailback
 * - MP_EnableAutoProbing
 * - MP_DisableAutoProbing
 * - MP_EnablePath
 * - MP_DisablePath
 * - MP_SetLogicalUnitLoadBalanceType
 * - MP_SetPluginLoadBalanceType
 * - MP_SetPathWeight
 * - MP_SetFailbackPollingRates
 * - MP_SetProbingPollingRates
 * - MP_SetProprietaryProperties
 * - MP_SetTPGAccess
 *
 ******************************************************************************
 */

/**
 *******************************************************************************
 *
 * Assign a multipath logical unit to a target port group.
 *
 * @param  tpgOid
 *      An MP_TARGET_PORT_GROUP oid. The target port group currently in
 *      active access state that the administrator would like the LU
 *      assigned to.
 *
 * @param  luOid
 *      An MP_MULTIPATH_LOGICAL_UNIT oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned when luOid is not associated with tpgOid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_AssignLogicalUnitToTPG(
        MP_OID tpgOid,
        MP_OID luOid
);

/**
 *******************************************************************************
 *
 * Manually override the path for a logical unit. The path exclusively used to
 * access the logical unit until cleared.
 *
 * @param  logicalUnitOid
 *      The object ID of the multipath logical unit.
 *
 * @param  pathOid
 *      The object ID of the path logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if the oid of the object is not valid
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_PATH_NONOPERATIONAL
 *          Returned when the driver cannot communicate through selected path.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetOverridePath(
    MP_OID logicalUnitOid,
    MP_OID pathOid
);

/**
 *******************************************************************************
 *
 * Cancel a path override and re-enable load balancing.
 *
 * @param  luOid
 *         An MP_MULTIPATH_LOGICAL_UNIT oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if MP_MULTIPATH_LOGICAL_UNIT with the luOid is not found.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_CancelOverridePath(
        MP_OID logicalUnitOid
);

/**
 *******************************************************************************
 *
 * Enables Auto-failback.
 *
 * @param  oid
 *      The oid of the plugin or the multipath logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid plugin oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_EnableAutoFailback(
    MP_OID oid
);

/**
 *******************************************************************************
 *
 * Disables Auto-failback.
 *
 * @param  oid
 *      The oid of the plugin or the multipath logical unit..
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid plugin oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_DisableAutoFailback(
    MP_OID oid
);

/**
 *******************************************************************************
 *
 * Enables Auto-probing.
 *
 * @param  oid
 *      The oid of the plugin or the multipath logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid plugin oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_EnableAutoProbing(
    MP_OID oid
);

/**
 *******************************************************************************
 *
 * Disables Auto-probing.
 *
 * @param  oid
 *      The oid of the plugin or the multipath logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid plugin oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_DisableAutoProbing(
    MP_OID oid
);

/**
 *******************************************************************************
 *
 * Enables a path. This API may cause failover in a logical unit with
 * asymmetric access.
 *
 * @param  oid
 *      The oid of the path.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid path oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_EnablePath(
    MP_OID oid
);

/**
 *******************************************************************************
 *
 * Disables a path. This API may cause failover in a logical unit with
 * asymmetric access. This API may cause a logical unit to become unavailable.
 *
 * @param  oid
 *      The oid of the path.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid path oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *          Returned when the API is not supported.
 *
 * @retval MP_STATUS_TRY_AGAIN
 *          Returned when path cannot be disabled at this time.
 *
 * @retval MP_STATUS_NOT_PERMITTED
 *          Returned when disabling thsi path would cause the login unit to
 * 	    become unavailable.
 *
 *******************************************************************************
 */
MP_STATUS MP_DisablePath(
    MP_OID oid
);

/**
 *******************************************************************************
 *
 * Set the multipath logical unit s load balancing policy.
 *
 * @param  logicalUnitoid
 *      The object ID of the multipath logical unit.
 *
 * @param  loadBanlance
 *      The desired load balance policy for the specified logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if no MP_MULTIPATH_LOGICAL_UNIT associated with
 *      @ref ligicalUnitrOid is found or invalid MP_LOAD_BALANCE_TYPE is
 *      specified.
 *
 * @retval MP_STATUS_FAILED
 *      Returned when the specified loadBalance type cannot be handled
 *      by the plugin.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetLogicalUnitLoadBalanceType(
    MP_OID               logicalUnitOid,
    MP_LOAD_BALANCE_TYPE loadBalance
);

/**
 *******************************************************************************
 *
 * Set the weight to be assigned to a particular path.
 *
 * @param  pathOid
 *      The object ID of the path logical unit.
 *
 * @param  weight
 *      weight that will be assigned to the path logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the MP Path specified by the PathOid could not be
 *      found.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the operation failed.
 *
 * @retval MP_STATUS_INVALID_WEIGHT
 *          Returned when the weight parameter is greater than the plugin's
 *      maxWeight property.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetPathWeight(
    MP_OID    pathOid,
    MP_UINT32 weight
);

/**
 *******************************************************************************
 *
 * Set the default load balance policy for the plugin.
 *
 * @param  oid
 *      The object ID of the plugin
 *
 * @param  loadBalance
 *      The desired default load balance policy for the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the the plugin specified by @ref oid could not be
 *      found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if the oid of the object is not valid.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the specified loadBalance type cannot be handled
 *      by the plugin.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetPluginLoadBalanceType(
    MP_OID               oid,
    MP_LOAD_BALANCE_TYPE loadBalance
);

/**
 *******************************************************************************
 *
 * Set the failback polling rates. Setting both rates to zero disables polling.
 *
 * @param  pluginOid
 *      The object ID of either the plugin or a multipath logical unit.
 *
 * @param  pollingRate
 *      The value to be set in MP_PLUGIN_PROPERTIES current pollingRate or
 *	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES pollingRate.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the the plugin specified by @ref oid could not be
 *      found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if one of the polling values is outside the range
 *      supported by the driver.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetFailbackPollingRate(
    MP_OID    oid,
    MP_UINT32 pollingRate
);

/**
 *******************************************************************************
 *
 * Set the probing polling rates. Setting both rates to zero disables polling.
 *
 * @param  pluginOid
 *      The object ID of either the plugin or a multipath logical unit.
 *
 * @param  pollingRate
 *      The value to be set in MP_PLUGIN_PROPERTIES current pollingRate or
 *	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES pollingRate.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the the plugin specified by @ref oid could not be
 *      found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if one of the polling values is outside the range
 *      supported by the driver.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetProbingPollingRate(
    MP_OID    oid,
    MP_UINT32 pollingRate
);

/**
 *******************************************************************************
 *
 * Set proprietary properties in supported object instances.
 *
 * @param  pluginOid
 *      The object ID of MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES,
 *	MP_PLUGIN_PROPERTIES or MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES.
 *
 * @param  count
 *	   The number of valid items in pPropertyList.
 *
 * @param  pPropertyList
 *	   A pointer to an array of property name/value pairs. This array must
 *	   contain the same number of elements as count.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the the plugin specified by @ref oid could not be
 *      found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if one of the polling values is outside the range
 *      supported by the driver.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetProprietaryProperties(
    MP_OID    oid,
    MP_UINT32 count,
    MP_PROPRIETARY_PROPERTY *pPropertyList
);

/**
 *******************************************************************************
 *
 * Set the access state for a list of target port groups. This allows
 * a client to force a failover or failback to a desired set of target port
 * groups.
 *
 * @param  luOid
 *      The object ID of the logical unit where the command is sent.
 *
 * @param  count
 *      The number of valid items in the pTpgStateList.
 *
 * @param  pTpgStateList
 *      A pointer to an array of TPG/access-state values. This array must
 *      contain the same number of elements as @ref count.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the MP_MULTIPATH_LOGICAL_UNIT associated with @ref
 *      oid could not be found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pTpgStateList is null or if one of the TPGs referenced
 *      in the list is not associated with the specified MP logical unit.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_ACCESS_STATE_INVALID
 *         Returned if the target device returns a status indicating the caller
 *     is attempting to establish an illegal combination of access states.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if the underlying interface failed the commend for some
 *      reason other than MP_STATUS_ACCESS_STATE_INVALID
 *
 *******************************************************************************
 */
MP_STATUS MP_SetTPGAccess(
    MP_OID             luOid,
    MP_UINT32          count,
    MP_TPG_STATE_PAIR *pTpgStateList
);

/**
 ******************************************************************************
 *
 * The APIs that are associated with event support.
 *
 * - MP_RegisterForObjectPropertyChanges
 * - MP_DeregisterForObjectPropertyChanges
 * - MP_RegisterForObjectVisibilityChanges
 * - MP_DeregisterForObjectVisibilityChanges
 *
 ******************************************************************************
 */

/**
 *******************************************************************************
 *
 * Registers a client function that is to be called
 * whenever the property of an an object changes.
 *
 * @param  pClientFn,
 *      A pointer to an MP_OBJECT_PROPERTY_FN function defined by the
 *      client. On successful return this function will be called to
 *      inform the client of objects that have had one or more properties
 *      change.
 *
 * @param  objectType
 *      The type of object the client wishes to deregister for
 *      property change callbacks. If null, then all objects types are
 *      deregistered.
 *
 * @param  pCallerData
 *      A pointer that is passed to the callback routine with each event.
 *      This may be used by the caller to correlate the event to source of
 *      the registration.
 *
 * @param  pluginOid
 *      A plugin oid that the client wishes to deregister for property change.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pClientFn is NULL or specifies a memory area
 *      that is not executable.
 *
 * @retval MP_STATUS_FN_REPLACED
 *      Returned when an existing client function is replaced with the one
 *      specified in pClientFn.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if objectType does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_RegisterForObjectPropertyChanges(
    MP_OBJECT_PROPERTY_FN   pClientFn,
    MP_OBJECT_TYPE	    objectType,
    void		    *pCallerData,
    MP_OID		    pluginOid
);

/**
 *******************************************************************************
 *
 * Deregisters a previously registered client function that is to be invoked
 * whenever an object's property changes.
 *
 * @param  pClientFn,
 *      A pointer to an MP_OBJECT_PROPERTY_FN function defined by the
 *      client that was previously registered using
 *      the MP_RegisterForObjectPropertyChanges API. On successful return
 *      this function will no longer be called to inform the client of
 *      object property changes.
 *
 * @param  objectType
 *      The type of object the client wishes to deregister for
 *      property change callbacks. If null, then all objects types are
 *      deregistered.
 *
 * @param  pluginOid
 *      A plugin oid that the client wishes to deregister for property change.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pClientFn is NULL or specifies a memory area
 *      that is not executable.
 *
 * @retval MP_STATUS_UNKNOWN_FN
 *      Returned if pClientFn is not the same as the previously registered
 *      function.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if objectType does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if pClientFn deregistration is not possible at this time.
 *
 *******************************************************************************
 */
MP_STATUS MP_DeregisterForObjectPropertyChanges(
    MP_OBJECT_PROPERTY_FN   pClientFn,
    MP_OBJECT_TYPE	    objectType,
    MP_OID		    pluginOid
);

/**
 *******************************************************************************
 *
 * Registers a client function that is to be called
 * whenever a high level object appears or disappears.
 *
 * @param  pClientFn,
 *      A pointer to an MP_OBJECT_VISIBILITY_FN function defined by the
 *      client. On successful return this function will be called to
 *      inform the client of objects whose visibility has changed.
 *
 * @param  objectType
 *      The type of object the client wishes to deregister for
 *      property change callbacks. If null, then all objects types are
 *      deregistered.
 *
 * @param  pCallerData
 *      A pointer that is passed to the callback routine with each event.
 *      This may be used by the caller to correlate the event to source of
 *      the registration.
 *
 * @param  pluginOid
 *      A plugin oid that the client wishes to deregister for property change.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pClientFn is NULL or specifies a memory area
 *      that is not executable.
 *
 * @retval MP_STATUS_FN_REPLACED
 *      Returned when an existing client function is replaced with the one
 *      specified in pClientFn.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if objectType does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_RegisterForObjectVisibilityChanges(
    MP_OBJECT_VISIBILITY_FN pClientFn,
    MP_OBJECT_TYPE	    objectType,
    void		    *pCallerData,
    MP_OID		    pluginOid
);

/**
 *******************************************************************************
 *
 * Deregisters a previously registered client function that is to be invoked
 * whenever a high level object appears or disappears.
 *
 * @param  pClientFn,
 *      A pointer to an MP_OBJECT_VISIBILITY_FN function defined by the
 *      client that was previously registered using
 *      the MP_RegisterForObjectVisibilityChanges API. On successful return
 *      this function will no longer be called to inform the client of
 *      object property changes.
 *
 * @param  objectType
 *      The type of object the client wishes to deregister for visibility
 *      change callbacks. If null, then all objects types are
 *      deregistered.
 *
 * @param  pluginOid
 *      A plugin oid that the client wishes to deregister for property change.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pClientFn is NULL or specifies a memory area
 *      that is not executable.
 *
 * @retval MP_STATUS_UNKNOWN_FN
 *      Returned if pClientFn is not the same as the previously registered
 *      function.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if objectType does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if pClientFn deregistration is not possible at this time.
 *
 *******************************************************************************
 */
MP_STATUS MP_DeregisterForObjectVisibilityChanges(
    MP_OBJECT_VISIBILITY_FN pClientFn,
    MP_OBJECT_TYPE          objectType,
    MP_OID		    pluginOid
);

/**
 ******************************************************************************
 *
 * The utility APIs
 *
 * - MP_CompareOIDs
 * - MP_FreeOidList
 * - MP_RegisterPlugin
 * - MP_DeregisterPlugin
 *
 ******************************************************************************
 */

/**
 *******************************************************************************
 *
 * Compare two Oids for equality to see whether they refer to the same object.
 *
 * @param  oid1
 *          Oid to compare.
 *
 * @param  oid2
 *          Oid to compare.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the two Oids do refer to the same object.
 *
 * @retval MP_STATUS_FAILED
 *      Returned if the Oids don't compare.
 *
 *******************************************************************************
 */
MP_STATUS MP_CompareOIDs(
    MP_OID oid1,
    MP_OID oid2
);

/**
 *******************************************************************************
 *
 * Frees memory returned by an MP API.
 *
 * @param  pMemory
 *      A pointer to the memory returned by an MP API. On successful
        return, the allocated memory is freed.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when pPluginId is deregistered successfully.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pMemory is NULL or specifies a memory area to which
 *      data cannot be written.
 *
 *******************************************************************************
 */
MP_STATUS MP_FreeOidList(
    MP_OID_LIST *pOidList
);

/**
 *******************************************************************************
 *
 * Registers a plugin with common library.  The implementation of this routine
 * is based on configuration file /etc/mpapi.conf that contains a list of
 * plugin libraries.
 *
 * @param  pPluginId
 *      A pointer to the key name shall be the reversed domain name of
 *      the vendor followed by followed by the vendor specific name for
 *      the plugin that uniquely identifies the plugin.
 *
 * @param  pFileName
 *      The full path to the plugin library.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when pPluginId is deregistered successfully.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pPluginId is NULL or specifies a memory area that
 *      is not executable.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if pClientFn deregistration is not possible at this time.
 *
 *******************************************************************************
 */
MP_STATUS MP_RegisterPlugin(
    MP_WCHAR *pPluginId,
    MP_CHAR *pFileName
);

/**
 *******************************************************************************
 *
 * Deregisters a plugin from the common library.
 *
 * @param  pPluginId
 *      A pointer to a Plugin ID previously registered using
 *      the MP_RegisterPlugin API..
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when pPluginId is deregistered successfully.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pPluginId is NULL or specifies a memory area that
 *      is not executable.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if pClientFn deregistration is not possible at this time.
 *
 *******************************************************************************
 */
MP_STATUS MP_DeregisterPlugin(
    MP_WCHAR *pPluginId
);

#endif

#ifdef __cplusplus
};
#endif

