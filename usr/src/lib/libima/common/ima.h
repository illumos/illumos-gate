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

/******************************************************************************
 *
 * Description
 *  Ima.h - general header file for client
 *       and library developers
 *
 * License:
 *  The contents of this file are subject to the SNIA Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *
 *  /http://www.snia.org/English/Resources/Code/OpenSource.html
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *  the License for the specific language governing rights and limitations
 *  under the License.
 *
 * The Original Code is  SNIA HBA API and IMA general header file
 *
 * The Initial Developer of the Original Code is:
 *      Benjamin F. Kuo, Troika Networks, Inc. (benk@troikanetworks.com)
 *      David Dillard       VERITAS Software        david.dillard@veritas.com
 *
 * Contributor(s):
 *  Jeff Ding, Adaptec, Inc. (jding@corp.adaptec.com)
 *  Dave Wysochanski, Network Appliance, Inc. (davidw@netapp.com)
 *
 ******************************************************************************
 *
 *   Changes:
 *  09/24/2003 Initial Draft
 *  (for other changes... see the CVS logs)
 *  12/15/2003 corrected the defined parameter in IMA_SetPhbaIsnsDiscovery().
 *             lower case the computer name as iscsi name in
 *             IMA_GenerateNodeName().
 *  03/01/2004 Brought up to date with respect to IMA v1.0.1; made formatting
 *             changes - lines to 80 cols - for readability.
 *
 *  01/21/2005 Updated to support IMA 1.1.3.
 *****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

#ifndef IMA_H
#define IMA_H

#include <time.h>
#include <wchar.h>


/* Library version string */
#define HBA_LIBVERSION 2

#define	IMA_MAX_CALLBACK_PER_PLUGIN	64
#define IMA_MAX_NUM_PLUGINS		32

/* DLL imports for WIN32 operation */
#ifdef WIN32
#ifdef IMA_EXPORTS
#define IMA_API __declspec(dllexport)
#else
#define IMA_API __declspec(dllimport)
#endif
#else
#define IMA_API
#endif

/* OS specific definitions */

#ifdef WIN32
typedef unsigned char   IMA_UINT8;  // Unsigned  8 bits
typedef char            IMA_INT8;   // Signed    8 bits
typedef unsigned short  IMA_UINT16; // Unsigned 16 bits
typedef short           IMA_INT16;  // Signed   16 bits
typedef unsigned int    IMA_UINT32; // Unsigned 32 bits
typedef int             IMA_INT32;  // Signed   32 bits
typedef void*           IMA_PVOID;  // Pointer  to void
typedef IMA_UINT32      IMA_VOID32; // Opaque   32 bits


/* Don't confuse, _WIN32 with WIN32... OK, how do you accompish that */
#ifdef _WIN32
typedef __int64             IMA_INT64;
typedef unsigned __int64    IMA_UINT64;
#else
typedef struct {
    TN_UINT32   lo_val;
    TN_UINT32   hi_val;
} IMA_INT64;

typedef struct {
    TN_UINT32   lo_val;
    TN_UINT32   hi_val;
} IMA_UINT64;
#endif  /*  #ifdef _WIN32   */


#else

/* Note this section needs to be cleaned up for various Unix platforms */
typedef unsigned char   IMA_UINT8;  /* Unsigned  8 bits */
typedef char            IMA_INT8;   /* Signed    8 bits */
typedef unsigned short  IMA_UINT16; /* Unsigned 16 bits */
typedef short           IMA_INT16;  /* Signed   16 bits */
typedef unsigned int    IMA_UINT32; /* Unsigned 32 bits */
typedef int             IMA_INT32;  /* Signed   32 bits */
typedef void*           IMA_PVOID;  /* Pointer  to void */
typedef IMA_UINT32      IMA_VOID32; /* Opaque   32 bits */
typedef long long       IMA_INT64;
typedef long long       IMA_UINT64;

#endif  /*  #ifdef WIN32 */



/**
*******************************************************************************
*
* Generic IMA Constant Definitions
*
*******************************************************************************
*/
#define RL_LIBRARY_SEQNUM           0
#define RL_SHARED_NODE_SEQNUM       0

/**
* Value which can be assigned to an IMA_BOOL and or an IMA_XBOOL.
*/
#define IMA_TRUE        1

/**
* Value which can be assigned to an IMA_BOOL and or an IMA_XBOOL.
*/
#define IMA_FALSE       0

/**
* Value which can be assigned to an IMA_XBOOL.
*/
#define IMA_UNKNOWN     0xFFFFFFFF



/**
*******************************************************************************
*
* Base IMA Type Definitions
*
* @note Types that have a specific size must be defined ImaOsTypes.h which is
*       an OS specific include file which is included by this file.
*
*******************************************************************************
*/

/**
* A character.
*/
typedef char IMA_CHAR;

/**
* A wide character.
*/
typedef wchar_t IMA_WCHAR;

/**
* An integer.  Spec states this is 32 bits on 32-bit systems, and 64-bit
* on 64-bit systems.
*/
typedef unsigned long IMA_UINT;

/**
* A boolean.
*/
typedef IMA_UINT32 IMA_BOOL;

/**
* An extended boolean: can have the values @ref IMA_TRUE, @ref IMA_FALSE, and
* @ref IMA_UNKNOWN.
*/
typedef IMA_UINT32 IMA_XBOOL;

/**
* A date and time.
*/
typedef struct tm IMA_DATETIME;

typedef unsigned char IMA_BYTE;

/**
*******************************************************************************
*
* Constants and macros declarations related to IMA_STATUS
*
*******************************************************************************
*/
#ifdef SOLARIS
typedef IMA_UINT IMA_STATUS;

#define	IMA_STATUS_SUCCESS		0x00000000
#define	IMA_STATUS_ERROR		0x80000000

#define	IMA_SUCCESS(status) (((IMA_STATUS)(status) & \
	    (IMA_STATUS)IMA_STATUS_ERROR) == 0 ? IMA_TRUE : IMA_FALSE)
#define	IMA_ERROR(status)   (((IMA_STATUS)(status) & \
	    (IMA_STATUS)IMA_STATUS_ERROR) == 0x8000000 ? IMA_TRUE : IMA_FALSE)

#define	MAKE_IMA_STATUS(x)	((IMA_STATUS)(x))
#define	MAKE_IMA_ERROR(x)	((IMA_STATUS)(IMA_STATUS_ERROR | (x)))
#define	GET_SYSTEM_ERROR(x)	(((IMA_STATUS)(x) & 0x0000FFFF))

#define	IMA_STATUS_REBOOT_NECESSARY		MAKE_IMA_STATUS(0x01)
#define	IMA_STATUS_INCONSISTENT_NODE_PROPERTIES	MAKE_IMA_STATUS(0x02)
#define	IMA_STATUS_SCSI_STATUS_CONDITION_MET	MAKE_IMA_STATUS(0x100)

#define	IMA_ERROR_NOT_SUPPORTED			MAKE_IMA_ERROR(0x01)
#define	IMA_ERROR_INSUFFICIENT_MEMORY		MAKE_IMA_ERROR(0x02)
#define	IMA_ERROR_LAST_PRIMARY_DISCOVERY_METHOD	MAKE_IMA_ERROR(0x03)
#define	IMA_ERROR_UNEXPECTED_OS_ERROR		MAKE_IMA_ERROR(0x04)
#define	IMA_ERROR_SYNC_TIMEOUT			MAKE_IMA_ERROR(0x05)
#define	IMA_ERROR_LU_EXPOSED			MAKE_IMA_ERROR(0x06)
#define	IMA_ERROR_LU_NOT_EXPOSED		MAKE_IMA_ERROR(0x07)
#define	IMA_ERROR_LU_IN_USE			MAKE_IMA_ERROR(0x08)
#define	IMA_ERROR_TARGET_TIMEOUT		MAKE_IMA_ERROR(0x09)
#define	IMA_ERROR_LOGIN_REJECTED		MAKE_IMA_ERROR(0x0A)
#define	IMA_ERROR_STATS_COLLECTION_NOT_ENABLED	MAKE_IMA_ERROR(0x0B)
#define	IMA_ERROR_SCSI_STATUS_CHECK_CONDITION	MAKE_IMA_ERROR(0x100)
#define	IMA_ERROR_SCSI_STATUS_BUSY		MAKE_IMA_ERROR(0x101)
#define	IMA_ERROR_SCSI_STATUS_RESERVATION_CONFLICT  	MAKE_IMA_ERROR(0x102)
#define	IMA_ERROR_SCSI_STATUS_TASK_SET_FULL	MAKE_IMA_ERROR(0x103)
#define	IMA_ERROR_SCSI_STATUS_ACA_ACTIVE	MAKE_IMA_ERROR(0x104)
#define	IMA_ERROR_SCSI_STATUS_TASK_ABORTED	MAKE_IMA_ERROR(0x105)
#define	IMA_ERROR_INVALID_PARAMETER		MAKE_IMA_ERROR(0x40000000)
#define	IMA_ERROR_INVALID_OBJECT_TYPE		MAKE_IMA_ERROR(0x40000001)
#define	IMA_ERROR_INCORRECT_OBJECT_TYPE		MAKE_IMA_ERROR(0x40000002)
#define	IMA_ERROR_OBJECT_NOT_FOUND		MAKE_IMA_ERROR(0x40000003)
#define	IMA_ERROR_NAME_TOO_LONG			MAKE_IMA_ERROR(0x40000004)
#define	IMA_ERROR_UNKNOWN_ERROR			MAKE_IMA_ERROR(0x0fffffff)

#else

typedef enum {
    IMA_STATUS_SUCCESS                      = 0x00000000,
    IMA_STATUS_REBOOT_NECESSARY             = 0x00000001,
    IMA_STATUS_INCONSISTENT_NODE_PROPERTIES = 0x00000002,
    IMA_STATUS_SCSI_STATUS_CONDITION_MET    = 0x00000100,

    IMA_STATUS_ERROR                        = 0x80000000,
    IMA_ERROR_NOT_SUPPORTED                 = 0x80000001,
    IMA_ERROR_INSUFFICIENT_MEMORY           = 0x80000002,
    IMA_ERROR_LAST_PRIMARY_DISCOVERY_METHOD = 0x80000003,
    IMA_ERROR_UNEXPECTED_OS_ERROR           = 0x80000004,
    IMA_ERROR_SYNC_TIMEOUT                  = 0x80000005,
    IMA_ERROR_LU_EXPOSED                    = 0x80000006,
    IMA_ERROR_LU_NOT_EXPOSED                = 0x80000007,
    IMA_ERROR_LU_IN_USE                     = 0x80000008,
    IMA_ERROR_TARGET_TIMEOUT                = 0x80000009,
    IMA_ERROR_LOGIN_REJECTED                = 0x8000000A,
    IMA_ERROR_STATS_COLLECTION_NOT_ENABLED  = 0x8000000B,
    IMA_ERROR_SCSI_STATUS_CHECK_CONDITION      = 0x80000100,
    IMA_ERROR_SCSI_STATUS_BUSY                 = 0x80000101,
    IMA_ERROR_SCSI_STATUS_RESERVATION_CONFLICT = 0x80000102,
    IMA_ERROR_SCSI_STATUS_TASK_SET_FULL        = 0x80000103,
    IMA_ERROR_SCSI_STATUS_ACA_ACTIVE           = 0x80000104,
    IMA_ERROR_SCSI_STATUS_TASK_ABORTED         = 0x80000105,
    IMA_ERROR_INVALID_PARAMETER             = 0xC0000000,
    IMA_ERROR_INVALID_OBJECT_TYPE           = 0xC0000001,
    IMA_ERROR_INCORRECT_OBJECT_TYPE         = 0xC0000002,
    IMA_ERROR_OBJECT_NOT_FOUND              = 0xC0000003,
    IMA_ERROR_NAME_TOO_LONG                 = 0xC0000004,
    IMA_ERROR_UNKNOWN_ERROR                 = 0x8FFFFFFF
} IMA_STATUS;

/*
#define IMA_SUCCESS(status)     ( (IMA_UINT32)(status) & \
                                  (IMA_UINT32)IMA_STATUS_ERROR == 0 ? \
                                  IMA_TRUE : IMA_FALSE )
#define IMA_ERROR(status)       ( (IMA_UINT32)(status) & \
                                  (IMA_UINT32)IMA_STATUS_ERROR == 0x8000000 ? \
                                  IMA_TRUE : IMA_FALSE )
*/

#define IMA_SUCCESS(status)							!((status) & IMA_STATUS_ERROR)
#define IMA_ERROR(status)							((status) & IMA_STATUS_ERROR)

#endif

/**
*******************************************************************************
*
* Declaration of the IMA_OBJECT_TYPE enumeration
*
*******************************************************************************
*/
typedef enum
{
    IMA_OBJECT_TYPE_UNKNOWN =   0,
    IMA_OBJECT_TYPE_PLUGIN  =   1,
    IMA_OBJECT_TYPE_NODE    =   2,
    IMA_OBJECT_TYPE_LHBA    =   3,
    IMA_OBJECT_TYPE_PHBA    =   4,
    IMA_OBJECT_TYPE_NETWORK_PORTAL  =   5,
    IMA_OBJECT_TYPE_PORTAL_GROUP    =   6,
    IMA_OBJECT_TYPE_LNP =   7,
    IMA_OBJECT_TYPE_PNP =   8,
    IMA_OBJECT_TYPE_TARGET  =   9,
    IMA_OBJECT_TYPE_LU  =   10,
	IMA_OBJECT_TYPE_DISCOVERY_ADDRESS = 11,
	IMA_OBJECT_TYPE_STATIC_DISCOVERY_TARGET = 12,
    IMA_OBJECT_TYPE_CONNECTION	=	13,
	IMA_OBJECT_TYPE_SESSION	=	14
} IMA_OBJECT_TYPE;

typedef enum
{
    IMA_ISNS_DISCOVERY_METHOD_STATIC    =   0,
    IMA_ISNS_DISCOVERY_METHOD_DHCP  =   1,
    IMA_ISNS_DISCOVERY_METHOD_SLP   =   2
} IMA_ISNS_DISCOVERY_METHOD;

typedef enum
{
    IMA_DOWNLOAD_IMAGE_TYPE_FIRMWARE    =   0,
    IMA_DOWNLOAD_IMAGE_TYPE_OPTION_ROM  =   1,
    IMA_DOWNLOAD_IMAGE_TYPE_ALL =   2,
	IMA_DOWNLOAD_IMAGE_TYPE_BOOTCODE = 3
} IMA_PHBA_DOWNLOAD_IMAGE_TYPE;

typedef enum
{
    IMA_PHBA_STATUS_WORKING =   0,
    IMA_PHBA_STATUS_FAILED  =   1
} IMA_PHBA_STATUS;

typedef enum
{
    IMA_NETWORK_PORT_STATUS_WORKING =   0,
    IMA_NETWORK_PORT_STATUS_DEGRADED    =   1,
    IMA_NETWORK_PORT_STATUS_CRITICAL    =   2,
    IMA_NETWORK_PORT_STATUS_FAILED  =   3,
    IMA_NETWORK_PORT_STATUS_DISCONNECTED    =   4
} IMA_NETWORK_PORT_STATUS;

typedef enum
{
    IMA_TARGET_DISCOVERY_METHOD_STATIC      =   1,
    IMA_TARGET_DISCOVERY_METHOD_SLP     =   2,
    IMA_TARGET_DISCOVERY_METHOD_ISNS        =   4,
    IMA_TARGET_DISCOVERY_METHOD_SENDTARGETS =   8
} IMA_TARGET_DISCOVERY_METHOD;

typedef enum
{
    IMA_AUTHMETHOD_NONE =   0,
    IMA_AUTHMETHOD_CHAP =   1,
    IMA_AUTHMETHOD_SRP  =   2,
    IMA_AUTHMETHOD_KRB5 =   3,
    IMA_AUTHMETHOD_SPKM1    =   4,
    IMA_AUTHMETHOD_SPKM2    =   5
} IMA_AUTHMETHOD;

typedef enum
{
	IMA_COMMIT_TYPE_AUTO	= 0,
	IMA_COMMIT_TYPE_ACTIVE,
	IMA_COMMIT_TYPE_PERSISTENT,
	IMA_COMMIT_TYPE_ACTIVE_AND_PERSISTENT,
	IMA_COMMIT_TYPE_ALL_WITH_RESET
} IMA_COMMIT_LEVEL;

typedef enum
{
	IMA_DIGEST_NONE		= 0,
	IMA_DIGEST_CRC32C		= 1
} IMA_DIGEST_TYPE;


/**
*******************************************************************************
*
* Declaration of the IMA_OID structure
*
* This structure should be treated as opaque by clients of the API.
* Appropriate APIs should be used to extract information from the structure.
*
*******************************************************************************
*/
typedef struct _IMA_OID
{
    /**
    * The type of the object.  When an object ID is supplied as a parameter
    * to an API the library uses this value to insure that the supplied
    * object's type is appropriate for the API.
    */
    IMA_OBJECT_TYPE objectType;

    /**
    * A value determined by the library which it uses to uniquely identify the
    * owner of an object.  The owner of an object is either the library itself
    * or a plugin.  When an object ID is supplied as a parameter to an API the
    * library uses this value to determine if it should handle the call itself
    * or direct the call to one or more plugins.
    */
    IMA_UINT32      ownerId;

    /**
    * A value determined by a plugin which a plugin uses, perhaps in
    * combination with the object type, to uniquely identify one of its
    * objects.
    */
    IMA_UINT64      objectSequenceNumber;

} IMA_OID;



/**
*******************************************************************************
*
* Declaration of the IMA_OID_LIST structure
*
* This structure is used by a number of APIs to return lists of objects.  Any
* instance of this structure returned by an API must be freed by a client
* using the IMA_FreeObjectIdList API.  Although oids is declared to be an
* array of one
* @ref IMA_OID structure it can in fact contain any number of
* @ref IMA_OID structures.
*
* @note The @a oids array is a variable length array, despite its declaration
*       below it can be of any length.
*
*******************************************************************************
*/
typedef struct _IMA_OID_LIST
{
    /**
    * The number of object IDs in the @a oids array.
    */
    IMA_UINT        oidCount;

    /**
    * A variable length array of zero or more object IDs.  There are
    * 'oidCount' object IDs in this array.
    */
    IMA_OID         oids[1];

} IMA_OID_LIST;

#define IMA_HOST_NAME_LEN 256
typedef IMA_WCHAR IMA_HOST_NAME[IMA_HOST_NAME_LEN];
typedef IMA_BYTE IMA_MAC_ADDRESS[6];

/**
*******************************************************************************
*
* Declaration of the IMA_LIBRARY_PROPERTIES structure
*
*******************************************************************************
*/
typedef struct _IMA_LIBRARY_PROPERTIES
{
    /**
    * The version of the iSCSI Management API implemented by the library.
    * The value returned by a library for the API as described in this
    * document is one.
    */
    IMA_UINT        supportedImaVersion;

    /**
    * A nul terminated ASCII string containing the name of the vendor that
    * created the binary version of the library.
    */
    IMA_WCHAR       vendor[256];

    /**
    * A nul terminated ASCII string containing the implementation version
    * of the library from the vendor specified in the 'vendor' field.
    */
    IMA_WCHAR       implementationVersion[256];

    /**
    * A nul terminated ASCII string ideally containing the path and file
    * name of the library that is being used by the currently executing
    * process can be found. If the path cannot be determined then it is
    * acceptable to fill this field with only the name (and extension if
    * applicable) of the file of the library.  If this cannot be determined
    * then this field should be an empty string.
    */
    IMA_WCHAR       fileName[256];

    /**
    * The time and date that the library that is executing was built.
    */
    IMA_DATETIME    buildTime;

    IMA_BYTE    reserved[64];
} IMA_LIBRARY_PROPERTIES;



/**
*******************************************************************************
*
* Declaration of the IMA_PLUGIN_PROPERTIES structure
*
*******************************************************************************
*/
typedef struct _IMA_PLUGIN_PROPERTIES
{
        IMA_UINT        supportedImaVersion;
        IMA_WCHAR       vendor[256];
        IMA_WCHAR       implementationVersion[256];
        IMA_WCHAR       fileName[256];
        IMA_DATETIME    buildTime;

        IMA_BOOL        lhbasCanBeCreatedAndDestroyed;

        IMA_BYTE        reserved[64];

} IMA_PLUGIN_PROPERTIES;


typedef struct _IMA_IP_ADDRESS
{
        IMA_BOOL        ipv4Address;
        IMA_BYTE        ipAddress[16];

} IMA_IP_ADDRESS;

typedef struct _IMA_ADDRESS_KEY
{
        IMA_IP_ADDRESS  ipAddress;
        IMA_UINT16      portNumber;

} IMA_ADDRESS_KEY;

typedef struct _IMA_ADDRESS_KEYS
{
        IMA_UINT		addressKeyCount;
        IMA_ADDRESS_KEY addressKeys[1];

} IMA_ADDRESS_KEYS;

typedef struct _IMA_ADDRESS_KEY_PROPERTIES
{
        IMA_UINT        addressKeyCount;
        IMA_ADDRESS_KEY addressKeys[1];

} IMA_ADDRESS_KEY_PROPERTIES;

typedef struct _IMA_IP_PROPERTIES
{
        IMA_BOOL        ipConfigurationMethodSettable;
        IMA_BOOL        dhcpConfigurationEnabled;

        IMA_BOOL        subnetMaskSettable;
        IMA_BOOL        subnetMaskValid;
        IMA_IP_ADDRESS  subnetMask;

        IMA_BOOL        defaultGatewaySettable;
        IMA_BOOL        defaultGatewayValid;
        IMA_IP_ADDRESS  defaultGateway;

        IMA_BOOL        primaryDnsServerAddressSettable;
        IMA_BOOL        primaryDnsServerAddressValid;
        IMA_IP_ADDRESS  primaryDnsServerAddress;

        IMA_BOOL        alternateDnsServerAddressSettable;
        IMA_BOOL        alternateDnsServerAddressValid;
        IMA_IP_ADDRESS  alternateDnsServerAddress;

        IMA_BYTE        reserved[64];

} IMA_IP_PROPERTIES;

typedef struct _IMA_HOST_ID
{
		IMA_BOOL hostnameInUse;
		union {

			IMA_HOST_NAME 	hostname;
			IMA_IP_ADDRESS 	ipAddress;

		} id;

} IMA_HOST_ID;

typedef struct _IMA_TARGET_ADDRESS
{
		IMA_HOST_ID hostnameIpAddress;
		IMA_UINT16 	portNumber;

} IMA_TARGET_ADDRESS;

/**
*******************************************************************************
*
* Declaration of the IMA_NODE_NAME type
*
*******************************************************************************
*/
#define	IMA_NODE_NAME_LEN   224
typedef IMA_WCHAR IMA_NODE_NAME[IMA_NODE_NAME_LEN];



/**
*******************************************************************************
*
* Declaration of the IMA_NODE_ALIAS type
*
*******************************************************************************
*/
#define	IMA_NODE_ALIAS_LEN	256
typedef IMA_WCHAR IMA_NODE_ALIAS[IMA_NODE_ALIAS_LEN];



/**
*******************************************************************************
*
* Declaration of the IMA_DOMAIN_NAME type
*
* A variable of this type may be formatted in any of the following four ways:
*       1.  An empty string, which indicates that no host or IP address is
*           specified
*       2.  A DNS host name
*       3.  A dotted-decimal IPv4 address
*       4.  A bracketed IPv6 address as specified in RFC 2732
*
* In all cases a domain name is terminated by a nul character.
* This type is used by several APIs: IMA_SetPhbaSnsDiscovery(),
* IMA_SetNetworkPortalIpAddress(), and indirectly by
* IMA_GetPhbaDiscoveryProperties().
*
*******************************************************************************
*/
typedef wchar_t IMA_DOMAIN_NAME[256];

typedef struct _IMA_PHBA_DOWNLOAD_IMAGE_PROPERTIES
{
        IMA_PHBA_DOWNLOAD_IMAGE_TYPE    imageType;
        IMA_WCHAR               version[32];
        IMA_WCHAR               description[512];
        IMA_XBOOL               upgrade;
} IMA_PHBA_DOWNLOAD_IMAGE_PROPERTIES;


/**
*******************************************************************************
*
* Declaration of the IMA_NODE_PROPERTIES structure
*
* This structure is returned by the IMA_GetNodeProperties() API.
*
* NOTE: It is possible for both 'runningInInitiatorMode' and
*       'runningInTargetMode' to be set to @c IMA_TRUE.  This means that
*       the node is operating both as an initiator and as a target.
*
*******************************************************************************
*/
typedef struct _IMA_NODE_PROPERTIES
{
    /**
    * A boolean indicating if the node is running as initiator or not.
    */
    IMA_BOOL        runningInInitiatorMode;

    /**
    * A boolean indicating if the node is running as a target or not.
    */
    IMA_BOOL        runningInTargetMode;

    /**
    * A boolean which indicates if the node's name is set or not.
    */
    IMA_BOOL        nameValid;

    /**
    * A nul terminated Unicode string which contains the name of the node.
    * The value in this field is only valid if 'nameValid' is set to
    * IMA_TRUE, in which case it will be Unicode NULL terminated.  If
    * 'nameValid' is set to IMA_FALSE then this field will contain an
    * empty string.
    */
    IMA_NODE_NAME   name;

    /**
    * A boolean which indicates if the node's alias is set or not.
    */
    IMA_BOOL        aliasValid;

    /**
    * A nul terminated Unicode string which contains the alias of the node.
    * This field is only valid if 'aliasValid' is set to IMA_TRUE, in which
    * case it will be Unicode NULL terminated.  If 'aliasValid' is set to
    * IMA_FALSE then this field will contain an empty string.
    */
    IMA_NODE_ALIAS  alias;

    /*
     * Boolean indicating if both the name and alias are settable using
     * IMA_SetNodeName() and IMA_SetNodeAlias().
     */
    IMA_BOOL    nameAndAliasSettable;

    IMA_BYTE    reserved[64];

} IMA_NODE_PROPERTIES;



/**
*******************************************************************************
*
* Declaration of the IMA_LHBA_PROPERTIES structure
*
* This structure is returned by the IMA_GetLhbaProperties()  API.
*
*******************************************************************************
*/
typedef struct _IMA_LHBA_PROPERTIES
{
    IMA_WCHAR   osDeviceName[256];
    IMA_BOOL    luExposingSupported;
    IMA_BOOL    isDestroyable;

    IMA_BOOL    staleDataRemovable;
    IMA_UINT    staleDataSize;

    IMA_BOOL    initiatorAuthMethodsSettable;
    IMA_BOOL    targetAuthMethodsSettable;

    IMA_BYTE    reserved[128];
} IMA_LHBA_PROPERTIES;



/**
*******************************************************************************
*
* Declaration of the IMA_ULP_xxx constants
*
*******************************************************************************
*/
#define IMA_ULP_TCP             0x01
#define IMA_ULP_SCTP            0x02
#define IMA_ULP_UDP             0x04



/**
*******************************************************************************
*
* Declaration of the IMA_MIN_MAX_VALUE structure
*
* Note: If the 'currentValueValid' field is IMA_FALSE then the value of
*       'settable' must also be set to IMA_FALSE.
*
* Note: The fields in this structure contain values which are defined by the
*       implementation and not by the iSCSI specification.  It is possible
*       that an implementation may be more or less restrictive in the values
*       that it can accept than the iSCSI specification allows.
*
* Note: An example of how to use 'incrementValue': Suppose that a structure is
*       obtained where 'currentValueValid' is IMA_TRUE, 'settable' is
*       IMA_TRUE, 'currentValue' is 50, 'defaultValue' is 50, 'minimumValue'
*       is 30, 'maximumValue' is 70 and 'incrementValue' is 10.  In this case,
*       the possible values that the property can be set to are 30, 40, 50,
*       60, and 70.  The new value must be the current value plus or minus
*       some multiple of 'incrementValue'.
*
*******************************************************************************
*/
typedef struct _IMA_MIN_MAX_VALUE
{
    /**
    * A boolean indicating if the @a currentValue field contains a valid value.
    */
    IMA_BOOL        currentValueValid;

    /**
    * Indicates if the corresponding property is settable.  If this field
    * has the value IMA_TRUE then the 'defaultValue', 'minimumValue',
    * 'maximumValue', and 'incrementValue' fields shall contain valid
    * values.  If this field has the value IMA_FALSE then these fields
    * have undefined values.
    */
    IMA_BOOL        settable;

    /**
    * If currentValueValid has the value IMA_TRUE then this field contains
    * the current value of the associated property.  If 'currentValueValid' has
    * the value IMA_FALSE then the value of this field is undefined.
    */
    IMA_UINT32      currentValue;

    /**
    * If 'settable' has the value IMA_TRUE then this field contains the
    * implementation's default value of the associated property.  If 'settable'
    * has the value IMA_FALSE then the value of this field is undefined.
    */
    IMA_UINT32      defaultValue;

    /**
    * If 'settable' has the value IMA_TRUE then this field contains the
    * implementation's minimum value of the associated property.  If 'settable'
    * has the value IMA_FALSE then the value of this field is undefined.
    */
    IMA_UINT32      minimumValue;

    /**
    * If 'settable' has the value IMA_TRUE then this field contains the
    * implementation's maximum value of the associated property.  If 'settable'
    * has the value IMA_FALSE then the value of this field is undefined.
    */
    IMA_UINT32      maximumValue;

    /**
    * If 'settable' has the value IMA_TRUE then this field contains a value
    * which can be added to or subtracted from 'currentValue' to obtain other
    * possible values of the associated property. If 'settable' has the value
    * IMA_FALSE then the value of this field is undefined.
    */
    IMA_UINT32      incrementValue;

} IMA_MIN_MAX_VALUE;

typedef struct _IMA_BOOL_VALUE
{
    IMA_BOOL    currentValueValid;
    IMA_BOOL    settable;
    IMA_BOOL    currentValue;
    IMA_BOOL    defaultValue;
} IMA_BOOL_VALUE;

/**
*******************************************************************************
*
* Declaration of the IMA_PHBA_PROPERTIES structure
*
* This structure is returned by the IMA_GetPhbaProperties() API.
*
* Note: Both 'isInitiator' and 'isTarget' cannot be set to IMA_FALSE as this
*       would mean that the PHBA was not functioning as either an initiator or
*       target, which means that its not functioning at all.
*
*******************************************************************************
*/
typedef struct _IMA_PHBA_PROPERTIES
{
    /**
    * A nul terminated ASCII string which contains the name of the vendor
    * of a PHBA. If the first character in this field is nul then the
    * vendor is unknown.
    */
    IMA_WCHAR       vendor[64];

    /**
    * A nul terminated ASCII string which contains the name of the model of
    * a PHBA. If the first character in this field is nul then the model is
    * unknown.
    */
    IMA_WCHAR       model[256];

    /**
    * A nul terminated ASCII string which contains a description of a PHBA.
    * This is a user friendly description of the PHBA.  If the first character
    * in this field is nul then there is no description.
    */
    IMA_WCHAR       description[256];

    /**
    * A nul terminated ASCII string which contains the serial number of a
    * PHBA.  If the first character in this field is nul then the serial
    * number is unknown.
    */
    IMA_WCHAR       serialNumber[64];

    /**
    * A nul terminated ASCII string which contains the hardware version of
    * a PHBA. If the first character in this field is nul then the hardware
    * version is unknown.
    */
    IMA_WCHAR       hardwareVersion[256];

    /**
    * A nul terminated ASCII string which contains the ASIC version of a
    * PHBA.  If the first character in this field is nul then the ASIC
    * version is unknown or is not applicable.
    */
    IMA_WCHAR       asicVersion[256];

    /**
    * A nul terminated ASCII string which contains the firmware version of
    * a PHBA.  If the first character in this field is nul then the firmware
    * version is unknown or is not applicable.
    */
    IMA_WCHAR       firmwareVersion[256];

    /**
    * A nul terminated ASCII string which contains the option ROM version
    * of a PHBA. If the first character in this field is nul then the option
    * ROM version is unknown or is not applicable.
    */
    IMA_WCHAR       optionRomVersion[256];

    /**
    * A nul terminated ASCII string which contains the name of the driver
    * controlling a PHBA.  If the first character in this field is nul then
    * the name of the driver is unknown.
    */
    IMA_WCHAR       driverName[256];

    /**
    * A nul terminated ASCII string which contains the version of the driver
    * specified in 'driverName'.  If the first character in this field is nul
    * then the version of the driver is unknown.
    *
    * This field can have a known value only if @a driverName has a known
    * value as well.
    */
    IMA_WCHAR       driverVersion[256];

    /**
    * A field containing flags which indicate what upper level protocols
    * are supported by a PHBA.  Examples of upper level protocols include:
    *
    *       - TCP, represented by IMA_ULP_TCP
    *       - SCTP, represented by IMA_ULP_SCTP
    *       - UDP, represented by IMA_ULP_UDP
    */
    IMA_UINT        supportedUlps;

    /**
    * A extended boolean which indicates if a PHBA supports executing SCSI
    * commands which cause bidirectional transfers.
    *
    * Note: The value of this field applies to the entire stack:
    * the hardware, ASIC, firmware, driver, etc.  All must support SCSI
    * commands which cause bidirectional transfers for this field to be
    * set to IMA_TRUE.
    */
    IMA_XBOOL       bidirectionalTransfersSupported;

    /**
    * The maximum length, in bytes, of a CDB that can be transferred by
    * this PHBA.  If this field has a value of zero that indicates that
    * this value is unknown.
    *
    * Note: The value of this field applies to the entire stack:
    * the hardware, ASIC, firmware, driver, etc.  All must support the
    * maximum CDB length returned in this field.
    */
    IMA_UINT        maximumCdbLength;

    /**
    * An extended boolean which indicates if a PHBA can also function as
    * a standard NIC concurrently with functioning as an iSCSI PHBA.
    */
    IMA_XBOOL       canBeNic;

    /**
    * A extended boolean which indicates if a PHBA is functioning as a
    * standard NIC concurrently with functioning as an iSCSI PHBA.
    */
    IMA_XBOOL       isNic;

    /**
    * An extended boolean indicating if the PHBA is functioning as an
    * initiator.
    */
    IMA_XBOOL       isInitiator;

    /**
    * An extended boolean indicating if the PHBA is functioning as a target.
    */
    IMA_XBOOL       isTarget;

    /**
    * An extended boolean indicating if the PHBA is using a TCP offload engine.
    *
    * Note: This value should only be set to @c IMA_TRUE if a TCP offload
    * engine is present and is being used.  If it can be determined that a
    * TCP offload engine is present, but it cannot be determined if that
    * offload engine is being used then this value should be set to
    * IMA_UNKNOWN.
    */
    IMA_XBOOL       usingTcpOffloadEngine;

    /**
    * An extended boolean indicating if the PHBA is using a iSCSI offload
    * engine.
    *
    * Note: This value should only be set to @c IMA_TRUE if a iSCSI offload
    * engine is present and is being used.  If it can be determined that an
    * iSCSI offload engine is present, but it cannot be determined if that
    * offload engine is being used then this value should be set to
    * IMA_UNKNOWN.
    */
    IMA_XBOOL       usingIscsiOffloadEngine;

    IMA_BYTE        reserved[128];

} IMA_PHBA_PROPERTIES;

/**
*******************************************************************************
*
* Declaration of the IMA_DISCOVERY_PROPERTIES structure
*
*******************************************************************************
*/
typedef struct _IMA_DISCOVERY_PROPERTIES
{
		IMA_BOOL			iSnsDiscoverySettable;
		IMA_XBOOL			iSnsDiscoveryEnabled;
		IMA_ISNS_DISCOVERY_METHOD   	iSnsDiscoveryMethod;
		IMA_HOST_ID			iSnsHost;

		IMA_BOOL    			slpDiscoverySettable;
		IMA_XBOOL   			slpDiscoveryEnabled;

		IMA_BOOL    			staticDiscoverySettable;
		IMA_XBOOL   			staticDiscoveryEnabled;

		IMA_BOOL    			sendTargetsDiscoverySettable;
		IMA_XBOOL   			sendTargetsDiscoveryEnabled;

		IMA_BYTE    			reserved[128];
} IMA_DISCOVERY_PROPERTIES;


typedef struct _IMA_PHBA_DOWNLOAD_PROPERTIES
{
        IMA_BOOL        isPhbaDownloadFileSupported;
        IMA_BOOL        optionRomDownloadSupported;
        IMA_BOOL        firmwareDownloadSupported;

        IMA_BYTE        reserved[32];
} IMA_PHBA_DOWNLOAD_PROPERTIES;

typedef struct _IMA_IPSEC_PROPERTIES
{
        IMA_BOOL        ipsecSupported;
        IMA_BOOL        implementedInHardware;
        IMA_BOOL        implementedInSoftware;

        IMA_BYTE        reserved[32];

} IMA_IPSEC_PROPERTIES;

typedef struct _IMA_LNP_PROPERTIES
{
        IMA_MAC_ADDRESS macAddress;
        IMA_BOOL        macAddressSettable;
        IMA_BYTE        reserved[32];

} IMA_LNP_PROPERTIES;

typedef struct _IMA_PNP_PROPERTIES
{
        IMA_OID         associatedPhbaOid;

        IMA_MAC_ADDRESS macAddress;
        IMA_BOOL        macAddressSettable;

        IMA_UINT        maximumTransferRate;
        IMA_UINT        currentTransferRate;

        IMA_UINT        maximumFrameSize;

        IMA_BYTE        reserved[64];
} IMA_PNP_PROPERTIES;

typedef struct _IMA_PNP_STATISTICS
{
        IMA_UINT64      bytesSent;
        IMA_UINT32      pdusSent;
        IMA_UINT64      bytesReceived;
        IMA_UINT32      pdusReceived;

} IMA_PNP_STATISTICS;

typedef struct _IMA_TARGET_PROPERTIES
{
        IMA_OID associatedNodeOid;
        IMA_OID associatedLhbaOid;

        IMA_NODE_NAME   name;
        IMA_NODE_ALIAS  alias;
        IMA_UINT32      discoveryMethodFlags;

        IMA_BOOL        sendTargetsDiscoverySettable;
        IMA_BOOL        sendTargetsDiscoveryEnabled;

        IMA_BYTE        reserved[128];

} IMA_TARGET_PROPERTIES;

typedef struct _IMA_CONNECTION_PROPERTIES
{
	IMA_OID	associatedSessionOid;
	IMA_UINT16	connectionId;
	IMA_DIGEST_TYPE	dataDigest;
	IMA_DIGEST_TYPE	headerDigest;
	IMA_BOOL	ifMarker;
	IMA_UINT32	ifMarkInt;
	IMA_UINT32	maxRecvDataSegmentLength;
	IMA_UINT32	maxTransmitDataSegmentLength;
	IMA_BOOL	ofMarker;
	IMA_UINT32	ofMarkInt;
} IMA_CONNECTION_PROPERTIES;


typedef struct _IMA_SESSION_PROPERTIES
{
	IMA_OID	associatedLhbaOid;
	IMA_AUTHMETHOD	authMethod;
	IMA_BOOL	dataPduInOrder;
	IMA_BOOL	dataSequenceInOrder;
	IMA_UINT16	defaultTime2Retain;
	IMA_UINT16	defaultTime2Wait;
	IMA_UINT16	errorRecoveryLevel;
	IMA_UINT32	firstBurstLength;
	IMA_BOOL	immediateData;
	IMA_BOOL	initialR2T;
	IMA_BYTE	isid[6];
	IMA_UINT32	maxBurstLength;
	IMA_UINT16	maxConnections;
	IMA_UINT16	maxOutstandingR2T;
	IMA_UINT16	targetPortalGroupTag;
	IMA_UINT16	tsih;
} IMA_SESSION_PROPERTIES;


typedef struct _IMA_TARGET_ERROR_STATISTICS
{
        IMA_BOOL        loginFailedCountValid;
        IMA_UINT32      loginFailedCount;

        IMA_BOOL        sessionFailedCountValid;
        IMA_UINT32      sessionFailedCount;

        IMA_BOOL        headerOrDigestSessionFailedCountValid;
        IMA_UINT32      headerOrDigestSessionFailedCount;

        IMA_BOOL        timeLimitExceededSessionFailedCountValid;
        IMA_UINT32      timeLimitExceededSessionFailedCount;

        IMA_BOOL        formatErrorSessionFailedCountValid;
        IMA_UINT32      formatErrorSessionFailedCount;

        IMA_BOOL        closedConnectionDueToTimeoutCountValid;
        IMA_UINT32      closedConnectionDueToTimeoutCount;

        IMA_BOOL        lastLoginFailureTimeValid;
        IMA_DATETIME    lastLoginFailureTime;

        IMA_BYTE        reserved[64];

} IMA_TARGET_ERROR_STATISTICS;

typedef struct _IMA_LU_PROPERTIES
{
        IMA_OID         associatedTargetOid;
        IMA_UINT64      targetLun;

        IMA_BOOL        exposedToOs;
        IMA_DATETIME    timeExposedToOs;

        IMA_BOOL        osDeviceNameValid;
        IMA_WCHAR       osDeviceName[64];

        IMA_BOOL        osParallelIdsValid;
        IMA_UINT32      osBusNumber;
        IMA_UINT32      osTargetId;
        IMA_UINT32      osLun;

        IMA_BYTE        reserved[128];

} IMA_LU_PROPERTIES;

typedef struct _IMA_STATISTICS_PROPERTIES
{
        IMA_BOOL        statisticsCollectionSettable;
        IMA_BOOL        statisticsCollectionEnabled;

} IMA_STATISTICS_PROPERTIES;

typedef struct _IMA_DEVICE_STATISTICS
{
        IMA_UINT64      scsiPayloadBytesSent;
        IMA_UINT64      scsiPayloadBytesReceived;

        IMA_UINT64      iScsiPduBytesSent;
        IMA_UINT64      iScsiPduBytesReceived;

        IMA_UINT64      iScsiPdusSent;
        IMA_UINT64      iScsiPdusReceived;

        IMA_UINT64      millisecondsSpentSending;
        IMA_UINT64      millisecondsSpentReceiving;

} IMA_DEVICE_STATISTICS;

typedef struct _IMA_NETWORK_PORTAL_PROPERTIES
{
        IMA_IP_ADDRESS  ipAddress;
        IMA_OID         associatedLnp;

        IMA_BYTE        reserved[32];
} IMA_NETWORK_PORTAL_PROPERTIES;

typedef void (* IMA_OBJECT_VISIBILITY_FN)(
        IMA_BOOL        becomingVisible,
        IMA_OID         oid
);

typedef void (* IMA_OBJECT_PROPERTY_FN)(
        IMA_OID         oid
);

typedef struct _IMA_CHAP_INITIATOR_AUTHPARMS
{

        IMA_UINT        retries;

        IMA_BYTE        name[512];
        IMA_UINT        nameLength;

        IMA_UINT        minValueLength;
        IMA_UINT        maxValueLength;

        IMA_BYTE        challengeSecret[256];
        IMA_UINT        challengeSecretLength;

        IMA_BYTE        reserved[512];

} IMA_CHAP_INITIATOR_AUTHPARMS;

typedef struct _IMA_SRP_INITIATOR_AUTHPARMS
{

        IMA_BYTE        userName[512];
        IMA_UINT        userNameLength;

        IMA_BYTE        reserved[512];

} IMA_SRP_INITIATOR_AUTHPARMS;

typedef struct _IMA_KRB5_INITIATOR_AUTHPARMS
{

        IMA_BYTE        clientKey[1024];
        IMA_UINT        clientKeyLength;

        IMA_BYTE        reserved[2048];

} IMA_KRB5_INITIATOR_AUTHPARMS;

typedef struct _IMA_SPKM_INITIATOR_AUTHPARMS
{

        IMA_BYTE        privateKey[4096];
        IMA_UINT        privateKeyLength;

        IMA_BYTE        publicKey[4096];
        IMA_UINT        publicKeyLength;

        IMA_BYTE        reserved[4096];

} IMA_SPKM_INITIATOR_AUTHPARMS;

typedef union _IMA_INITIATOR_AUTHPARMS
{

        IMA_CHAP_INITIATOR_AUTHPARMS    chapParms;
        IMA_SRP_INITIATOR_AUTHPARMS     srpParms;
        IMA_KRB5_INITIATOR_AUTHPARMS    kerberosParms;
        IMA_SPKM_INITIATOR_AUTHPARMS    spkmParms;

} IMA_INITIATOR_AUTHPARMS;


typedef struct _IMA_STATIC_DISCOVERY_TARGET
{
		IMA_NODE_NAME 		targetName;
		IMA_TARGET_ADDRESS 	targetAddress;

} IMA_STATIC_DISCOVERY_TARGET;

typedef struct _IMA_DISCOVERY_ADDRESS_PROPERTIES
{
		IMA_OID			associatedNodeOid;
		IMA_OID			associatedLhbaOid;
		IMA_TARGET_ADDRESS	discoveryAddress;

} IMA_DISCOVERY_ADDRESS_PROPERTIES;

typedef struct _IMA_STATIC_TGT_PROPERTIES
{
		IMA_OID				associatedNodeOid;
		IMA_OID				associatedLhbaOid;
		IMA_STATIC_DISCOVERY_TARGET	staticTarget;

} IMA_STATIC_DISCOVERY_TARGET_PROPERTIES;

typedef struct ima_plugin_info {
	char PluginName[64];
        char PluginPath[256];
#ifdef WIN32
	HINSTANCE hPlugin; /* Handle to a loaded DLL */
#else
	void* hPlugin; /* Handle to a loaded DLL */
#endif
	IMA_UINT32 ownerId;
#ifdef WIN32
	HANDLE pluginMutex;
#else
	int pluginMutex;
#endif
	IMA_UINT number_of_vbcallbacks;
        IMA_OBJECT_VISIBILITY_FN vbcallback[IMA_MAX_CALLBACK_PER_PLUGIN];
        IMA_UINT number_of_pccallbacks;
        IMA_OBJECT_PROPERTY_FN pccallback[IMA_MAX_CALLBACK_PER_PLUGIN];
} IMA_PLUGIN_INFO, *PIMA_PLUGIN_INFO;


/**
*******************************************************************************
*
* The individual APIs of the IMA are declared below.
*
*******************************************************************************
*/

/**
*******************************************************************************
*
* Gets the properties of the IMA library that is being used.
*
* @param  pProps
*         A pointer to an IMA_LIBRARY_PROPERTIES structure allocated by
*         the caller.  On successful return this structure will contain the
*         properties of the IMA library.
*
* @return An IMA_STATUS indicating if the operation was successful or if
*         an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the library properties were successfully returned.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'pProps' is NULL or specifies a memory area to which
*         data cannot be written.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetLibraryProperties(
        IMA_LIBRARY_PROPERTIES *pProps
);



/**
*******************************************************************************
*
* Gets a list of the object IDs of all currently loaded plugins.
*
* @param ppList
*        A pointer to a pointer to an IMA_OID_LIST.  On successful
*        return this will contain a pointer to an @ref IMA_OID_LIST
*        which contains the object IDs of all of the plugins currently
*        loaded by the library.
*
* @return An IMA_STATUS indicating if the operation was successful or
*         if an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the plugin ID list was successfully returned.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'ppList' is NULL or specifies a memory area to
*         which data cannot be written.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetPluginOidList(
        IMA_OID_LIST **ppList
);



/**
*******************************************************************************
*
* Gets the properties of the specified vendor plugin.
*
* @param  pluginOid
*         The ID of the plugin whose properties are being retrieved.
*
* @param  pProps
*         A pointer to an @ref IMA_PLUGIN_PROPERTIES structure allocated by
*         the caller.  On successful return this will contain the properties
*         of the plugin specified by pluginOid.
*
* @return An IMA_STATUS indicating if the operation was successful or if an
*         error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the plugin properties were successfully returned.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'pluginOid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'pluginOid' does not specify a plugin object.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'pluginOid' refers to a plugin, but not one that
*         is currently loaded.
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'pProps' is NULL or specifies a memory area to
*         which data cannot be written.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetPluginProperties(
        IMA_OID pluginOid,
        IMA_PLUGIN_PROPERTIES *pProps
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
*         A pointer to an IMA_OID structure allocated by the caller.  On
*         successful return this will contain the object ID of the plugin
*         associated with the object specified by @a objectId.  This
*         can then be used to work with the plugin, e.g., to get the
*         properties of the plugin or the send the plugin an IOCtl.
*
* @return An IMA_STATUS indicating if the operation was successful or if
*         an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the associated plugin ID was successfully returned.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'pPluginOid' is NULL or specifies a memory area to
*         which data cannot be written.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'oid' specifies an object not owned by a plugin, but
*         instead one that is owned by the library.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'oid' specifies an object with an invalid type.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetAssociatedPluginOid(
        IMA_OID oid,
        IMA_OID *pPluginOid
);



/**
*******************************************************************************
*
* Gets the object ID of the shared node.
*
* @param  pSharedNodeOid
*         A pointer to an IMA_OID structure allocated by the caller.  On
*         successful return it will contain the object ID of the
*         shared node of the currently executing system is placed.
*
* @return An IMA_STATUS indicating if the operation was successful or
*         if an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the shared node ID has been successfully retrieved.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'pSharedNodeOid' is NULL or specifies a memory area
*         to which data cannot be written.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetSharedNodeOid(
        IMA_OID *pSharedNodeOid
);

IMA_API IMA_STATUS IMA_GetObjectType(
        IMA_OID oid,
        IMA_OBJECT_TYPE *pObjectType
);


/**
*******************************************************************************
*
* Gets the properties of the specified iSCSI node.
*
* @param  nodeOid
*         The ID of the node to get the properties of.
*
* @param  pProps
*         A pointer to an @ref IMA_NODE_PROPERTIES structure which on
*         successful return will contain the properties of the specified node.
*
* @return An IMA_STATUS indicating if the operation was successful or if
*         an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the node properties have been successfully retrieved.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'pProps' is NULL or specifies a memory area to which
*         data cannot be written.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'nodeOid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'nodeOid' does not specify a node object.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'nodeOid' does not specify a node which is currently
*         known to the system.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetNodeProperties(
        IMA_OID nodeOid,
        IMA_NODE_PROPERTIES *pProps
);



/**
*******************************************************************************
*
* Sets the name of the specified node.
*
* @param  nodeOid
*         The object ID of the node whose name is being set.
*
* @param  newName
*         The new name of the node.
*
* @return An IMA_STATUS indicating if the operation was successful or
*         if an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the node name was successfully changed.
*
* @retval IMA_STATUS_REBOOT_NECESSARY
*         Returned if a reboot is necessary before the setting of the
*         name actually takes affect.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'newName' is NULL, or specifies a memory area
*         to which data cannot be written, or has a length of 0.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'nodeOid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'nodeOid' does not specify a node object.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'nodeOid' does not specify a node which is
*         currently known to the system.
*
* @retval IMA_ERROR_NAME_TOO_LONG
*         Returned if 'newName' contains too many characters.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_SetNodeName(
        IMA_OID nodeOid,
        const IMA_NODE_NAME newName
);



/**
*******************************************************************************
*
* Generates a unique node name for the currently running system.
*
* @param  generatedName
*         On successful return contains the generated node name.
*
* @return  An IMA_STATUS indicating if the operation was successful or if an
*          error occurred.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'generatedname is NULL or
*               specifies a memory area to which data cannot be written.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GenerateNodeName(
        IMA_NODE_NAME generatedName
);



/**
*******************************************************************************
*
* Sets the alias of the specified node.
*
* @param  nodeOid
*         The object ID of the node whose alias is being set.
*
* @param  newAlias
*         A pointer to a Unicode string which contains the new node alias.
*         If this parameter is NULL then the current alias is deleted, in which
*         case the specified node no longer has an alias.
*
* @return An IMA_STATUS indicating if the operation was successful or
*         if an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the node's alias has been successfully set.
*
* @retval IMA_STATUS_REBOOT_NECESSARY
*         A reboot is necessary before the setting of the alias actually
*         takes effect.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'nodeOid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'nodeOid' does not specify a node object.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'nodeOid' does not specify a node which is currently
*         known to the system.
*
* @retval IMA_ERROR_NAME_TOO_LONG
*         Returned if 'newAlias' contains too many characters.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_SetNodeAlias(
        IMA_OID nodeOid,
        const IMA_NODE_ALIAS newAlias
);



/**
*******************************************************************************
*
* Gets a list of the object IDs of all the logical HBAs in the system.
*
* @param  ppList
*         A pointer to a pointer to an @ref IMA_OID_LIST structure.  On
*         successful return this will contain a pointer to an
*         IMA_OID_LIST which contains the object IDs of all of the
*         LHBAs currently in the system.
*
* @return An IMA_STATUS indicating if the operation was successful or if
*         an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the LHBA ID list has been successfully returned.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'ppList' is NULL or specifies a memory area to which
*         data cannot be written.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetLhbaOidList(
        IMA_OID_LIST **ppList
);



/**
*******************************************************************************
*
* Gets the properties of the specified logical HBA.
*
* @param  lhbaOid
*         The object ID of the LHBA whose properties are being retrieved.
*
* @param  pProps
*         A pointer to an IMA_LHBA_PROPERTIES structure.  On successful
*         return this will contain the properties of the LHBA specified by
*         'lhbaOid'.
*
* @return An IMA_STATUS indicating if the operation was successful or if
*         an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the properties of the specified LHBA have been
*         successfully retrieved.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'pProps' is NULL or specifies a memory area to which
*         data cannot be written.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'lhbaOid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'lhbaOid' does not specify a LHBA.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'lhbaOid' does not specify a LHBA which is currently
*         known to the system.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetLhbaProperties(
        IMA_OID lhbaOid,
        IMA_LHBA_PROPERTIES *pProps
);



/**
*******************************************************************************
*
* Gets a list of the object IDs of all the physical HBAs in the system.
*
* @param  ppList
*         A pointer to a pointer to an IMA_OID_LIST structure.  On successful
*         return this will contain a pointer to an IMA_OID_LIST which
*         contains the object IDs of all of the PHBAs currently in the system.
*
* @return An IMA_STATUS indicating if the operation was successful or if
*         an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the PHBA OID list has been successfully returned.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'ppList' is NULL or specifies a memory area to which
*         data cannot be written.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetPhbaOidList(
        IMA_OID_LIST **ppList
);



/**
*******************************************************************************
*
* Gets the general properties of a physical HBA.
*
* @param  phbaOid
*         The object ID of the PHBA whose properties are being queried.
*
* @param  pProps
*         A pointer to an @ref IMA_PHBA_PROPERTIES structure.  On successful
*         return this will contain the properties of the PHBA specified by
*         'phbaOid'.
#
* @return An IMA_STATUS indicating if the operation was successful or
*         if an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the properties of the specified PHBA have been
*         successfully retrieved.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'pProps' is NULL or specifies a memory area to which
*         data cannot be written.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'phbaOid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'phbaOid' does not specify a PHBA.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'phbaOid' does not specify a PHBA which is currently
*         known to the system.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetPhbaProperties(
        IMA_OID phbaOid,
        IMA_PHBA_PROPERTIES *pProps
);

/**
*******************************************************************************
*
* Frees a previously allocated IMA_OID_LIST structure.
*
* @param pMemory  A pointer to an IMA_OID_LIST structure allocated by the
*                 library.  On successful return the memory allocated by the
*                 list is freed.
* @return  An IMA_STATUS indicating if the operation was successful or if an
*          error occurred.
* @retval IMA_SUCCESS
*         Returned if the specified object ID list was successfully
*         freed.
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if pMemory is NULL or specifies a memory area from which
*         data cannot be read.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_FreeMemory(
        void *pMemory
);



IMA_API IMA_STATUS IMA_GetNonSharedNodeOidList(
                IMA_OID_LIST **ppList
);




/**
*******************************************************************************
*
* Gets the first burst length properties of the specified logical HBA.
*
* @param  oid
*         The object ID of the logical HBA to get the first burst length
*         properties of.
*
* @param  pProps
*         A pointer to a min/max values structure.
*
* @return An IMA_STATUS indicating if the operation was successful or if an
*         error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the first burst length properties have been
*         successfully retrieved.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if pProps is NULL or specifies a memory area to which
*         data cannot be written.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'oid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'oid' does not specify a LHBA.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'oid' does not specify a LHBA which is currently
*         known to the system.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetFirstBurstLengthProperties(
                IMA_OID oid,
                IMA_MIN_MAX_VALUE *pProps
);


/**
*******************************************************************************
*
* Gets the max burst length properties of the specified logical HBA.
*
* @param  oid
*         The object ID of the logical HBA to get the max burst length
*         properties of.
*
* @param  pProps
*         A pointer to an IMA_MIN_MAX_VALUE structure allocated by the
*         caller.  On successful return this structure will contain the max
*         burst length properties of this LHBA.
*
* @return An IMA_STATUS indicating if the operation was successful or if
*         an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the max burst length properties have been successfully
*         retrieved.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if pProps is NULL or specifies a memory area to which
*         data cannot be written.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'oid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'oid' does not specify a LHBA.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'oid' does not specify a LHBA which is currently
*         known to the system.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetMaxBurstLengthProperties(
                IMA_OID Oid,
                IMA_MIN_MAX_VALUE *pProps
);

/**
*******************************************************************************
*
* Gets the maximum receive data segment length properties of the specified
* logical HBA.
*
* @param  oid
*         The object ID of the logical HBA to get the max receive data
*         segment length properties of.
*
* @param  pProps
*         A pointer to an @ref IMA_MIN_MAX_VALUE structure allocated by the
*         caller.  On successful return this structure will contain the max
*         receive data segment length properties of this LHBA.
*
* @return An IMA_STATUS indicating if the operation was successful or if
*         an error occurred.
*
* @retval IMA_SUCCESS
*         Returned if the max receive data segment length properties
*         have been successfully retrieved.
*
* @retval IMA_ERROR_INVALID_PARAMETER
*         Returned if 'pProps' is NULL or specifies a memory area to which
*         data cannot be written.
*
* @retval IMA_ERROR_INVALID_OBJECT_TYPE
*         Returned if 'oid' does not specify any valid object type.
*
* @retval IMA_ERROR_INCORRECT_OBJECT_TYPE
*         Returned if 'oid' does not specify a LHBA.
*
* @retval IMA_ERROR_OBJECT_NOT_FOUND
*         Returned if 'oid' does not specify a LHBA which is currently
*         known to the system.
*
*******************************************************************************
*/
IMA_API IMA_STATUS IMA_GetMaxRecvDataSegmentLengthProperties(
                IMA_OID oid,
                IMA_MIN_MAX_VALUE *pProps
);


/*---------------------------------------------*/
IMA_API IMA_STATUS IMA_PluginIOCtl(
                IMA_OID pluginOid,
                IMA_UINT command,
                const void *pInputBuffer,
                IMA_UINT inputBufferLength,
                void *pOutputBuffer,
                IMA_UINT *pOutputBufferLength
);



IMA_API IMA_STATUS IMA_GetNetworkPortalOidList(
                IMA_OID oid,
                IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_SetFirstBurstLength(
                IMA_OID oid,
                IMA_UINT firstBurstLength
);

IMA_API IMA_STATUS IMA_SetMaxBurstLength(
                IMA_OID oid,
                IMA_UINT maxBurstLength
);

IMA_API IMA_STATUS IMA_SetMaxRecvDataSegmentLength(
                IMA_OID oid,
                IMA_UINT maxRecvDataSegmentLength
);

IMA_API IMA_STATUS IMA_GetMaxConnectionsProperties(
                IMA_OID oid,
                IMA_MIN_MAX_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetMaxConnections(
                IMA_OID oid,
                IMA_UINT maxConnections
);

IMA_API IMA_STATUS IMA_GetDefaultTime2RetainProperties(
                IMA_OID oid,
                IMA_MIN_MAX_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetDefaultTime2Retain(
                IMA_OID oid,
                IMA_UINT defaultTime2Retain
);

IMA_API IMA_STATUS IMA_GetDefaultTime2WaitProperties(
                IMA_OID oid,
                IMA_MIN_MAX_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetDefaultTime2Wait(
                IMA_OID oid,
                IMA_UINT defaultTime2Wait
);

IMA_API IMA_STATUS IMA_GetMaxOutstandingR2TProperties(
                IMA_OID oid,
                IMA_MIN_MAX_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetMaxOutstandingR2T(
                IMA_OID oid,
                IMA_UINT maxOutstandingR2T
);

IMA_API IMA_STATUS IMA_GetErrorRecoveryLevelProperties(
                IMA_OID oid,
                IMA_MIN_MAX_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetErrorRecoveryLevel(
                IMA_OID oid,
                IMA_UINT errorRecoveryLevel
);

IMA_API IMA_STATUS IMA_GetInitialR2TProperties(
                IMA_OID oid,
                IMA_BOOL_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetInitialR2T(
                IMA_OID oid,
                IMA_BOOL initialR2T
);

IMA_API IMA_STATUS IMA_GetImmediateDataProperties(
                IMA_OID oid,
                IMA_BOOL_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetImmediateData(
                IMA_OID oid,
                IMA_BOOL immediateData
);

IMA_API IMA_STATUS IMA_GetDataPduInOrderProperties(
                IMA_OID oid,
                IMA_BOOL_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetDataPduInOrder(
                IMA_OID oid,
                IMA_BOOL dataPduInOrder
);

IMA_API IMA_STATUS IMA_GetDataSequenceInOrderProperties(
                IMA_OID oid,
                IMA_BOOL_VALUE *pProps
);

IMA_API IMA_STATUS IMA_SetDataSequenceInOrder(
                IMA_OID oid,
                IMA_BOOL dataSequenceInOrder
);

IMA_API IMA_STATUS IMA_SetStatisticsCollection(
                IMA_OID oid,
                IMA_BOOL enableStatisticsCollection
);

IMA_API IMA_STATUS IMA_GetNetworkPortStatus(
                IMA_OID portOid,
                IMA_NETWORK_PORT_STATUS *pStatus
);

IMA_API IMA_STATUS IMA_GetTargetOidList(
                IMA_OID oid,
                IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_RemoveStaleData(
                IMA_OID lhbaOid
);

IMA_API	IMA_STATUS IMA_SetIsnsDiscovery(
		IMA_OID phbaId,
		IMA_BOOL enableIsnsDiscovery,
		IMA_ISNS_DISCOVERY_METHOD discoveryMethod,
		const IMA_HOST_ID *iSnsHost
);

IMA_API IMA_STATUS IMA_SetSlpDiscovery(
                IMA_OID phbaOid,
                IMA_BOOL enableSlpDiscovery
);

IMA_API IMA_STATUS IMA_SetStaticDiscovery(
                IMA_OID phbaOid,
                IMA_BOOL enableStaticDiscovery
);

IMA_API IMA_STATUS IMA_SetSendTargetsDiscovery(
                IMA_OID oid,
                IMA_BOOL enableSendTargetsDiscovery
);

IMA_API IMA_STATUS IMA_RemoveStaticDiscoveryTarget(
                IMA_OID targetOid
);

IMA_API IMA_STATUS IMA_GetIpsecProperties(
                IMA_OID phbaOid,
                IMA_IPSEC_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_GetPnpOidList(
                IMA_OID oid,
                IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_GetPhbaDownloadProperties(
                IMA_OID phbaOid,
                IMA_PHBA_DOWNLOAD_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_IsPhbaDownloadFile(
                IMA_OID phbaOid,
                const IMA_WCHAR *pFileName,
                IMA_PHBA_DOWNLOAD_IMAGE_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_PhbaDownload(
                IMA_OID phbaOid,
                IMA_PHBA_DOWNLOAD_IMAGE_TYPE imageType,
                const IMA_WCHAR *pFileName
);

IMA_API IMA_STATUS IMA_GetNetworkPortalProperties(
                IMA_OID networkPortalOid,
                IMA_NETWORK_PORTAL_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_SetNetworkPortalIpAddress(
                IMA_OID networkPortalOid,
                const IMA_IP_ADDRESS NewIpAddress
);

IMA_API IMA_STATUS IMA_GetLnpOidList(
                IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_GetLnpProperties(
                IMA_OID lnpOid,
                IMA_LNP_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_GetPnpProperties(
                IMA_OID pnpOid,
                IMA_PNP_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_GetPnpStatistics(
                IMA_OID pnpOid,
                IMA_PNP_STATISTICS *pStats
);

IMA_API IMA_STATUS IMA_GetTargetProperties(
                IMA_OID targetOid,
                IMA_TARGET_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_GetTargetErrorStatistics(
                IMA_OID targetOid,
                IMA_TARGET_ERROR_STATISTICS *pStats
);

IMA_API IMA_STATUS IMA_GetLuOidList(
                IMA_OID oid,
                IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_GetLuOid(
                IMA_OID targetOid,
                IMA_UINT64 lun,
                IMA_OID *pluOid
);

IMA_API IMA_STATUS IMA_GetLuProperties(
                IMA_OID luOid,
                IMA_LU_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_GetStatisticsProperties(
                IMA_OID oid,
                IMA_STATISTICS_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_GetDeviceStatistics(
                IMA_OID oid,
                IMA_DEVICE_STATISTICS *pStats
);

IMA_API IMA_STATUS IMA_LuInquiry(
                IMA_OID deviceOid,
                IMA_BOOL evpd,
                IMA_BOOL cmddt,
                IMA_BYTE pageCode,

                IMA_BYTE *pOutputBuffer,
                IMA_UINT *pOutputBufferLength,

                IMA_BYTE *pSenseBuffer,
                IMA_UINT *pSenseBufferLength
);

IMA_API IMA_STATUS IMA_LuReadCapacity(
                IMA_OID deviceOid,
                IMA_UINT cdbLength,
                IMA_BYTE *pOutputBuffer,
                IMA_UINT *pOutputBufferLength,

                IMA_BYTE *pSenseBuffer,
                IMA_UINT *pSenseBufferLength
);

IMA_API IMA_STATUS IMA_LuReportLuns(
                IMA_OID deviceOid,
                IMA_BOOL sendToWellKnownLun,
                IMA_BYTE selectReport,

                IMA_BYTE *pOutputBuffer,
                IMA_UINT *pOutputBufferLength,

                IMA_BYTE *pSenseBuffer,
                IMA_UINT *pSenseBufferLength
);

IMA_API IMA_STATUS IMA_ExposeLu(
                IMA_OID luOid
);

IMA_API IMA_STATUS IMA_UnexposeLu(
                IMA_OID luOid
);

IMA_API IMA_STATUS IMA_GetPhbaStatus(
                IMA_OID hbaOid,
                IMA_PHBA_STATUS *pStatus
);

IMA_API IMA_STATUS IMA_RegisterForObjectVisibilityChanges (
                IMA_OBJECT_VISIBILITY_FN pClientFn
);

IMA_API IMA_STATUS IMA_DeregisterForObjectVisibilityChanges (
                IMA_OBJECT_VISIBILITY_FN pClientFn
);

IMA_API IMA_STATUS IMA_RegisterForObjectPropertyChanges (
                IMA_OBJECT_PROPERTY_FN pClientFn
);

IMA_API IMA_STATUS IMA_DeregisterForObjectPropertyChanges (
                IMA_OBJECT_PROPERTY_FN pClientFn
);


IMA_API IMA_STATUS IMA_GetAddressKeyProperties(
                IMA_OID targetOid,
                IMA_ADDRESS_KEY_PROPERTIES **ppProps
);

IMA_API IMA_STATUS IMA_GetIpProperties(
                IMA_OID oid,
                IMA_IP_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_SetIpConfigMethod(
                IMA_OID oid,
                IMA_BOOL enableDhcpIpConfiguration
);

IMA_API	IMA_STATUS IMA_SetIsnsDiscovery(
		IMA_OID oid,
		IMA_BOOL enableIsnsDiscovery,
		IMA_ISNS_DISCOVERY_METHOD discoveryMethod,
		const IMA_HOST_ID *iSnsHost
);


IMA_API IMA_STATUS IMA_SetSubnetMask(
                IMA_OID oid,
                IMA_IP_ADDRESS subnetMask
);

IMA_API IMA_STATUS IMA_SetDnsServerAddress(
                IMA_OID oid,
                const IMA_IP_ADDRESS *pPrimaryDnsServerAddress,
                const IMA_IP_ADDRESS *pAlternateDnsServerAddress
);

IMA_API IMA_STATUS IMA_SetDefaultGateway(
                IMA_OID oid,
                IMA_IP_ADDRESS defaultGateway
);

IMA_API IMA_STATUS IMA_GetSupportedAuthMethods(
                IMA_OID lhbaOid,
                IMA_BOOL getSettableMethods,
                IMA_UINT *pMethodCount,
                IMA_AUTHMETHOD *pMethodList
);

IMA_API IMA_STATUS IMA_GetInUseInitiatorAuthMethods(
                IMA_OID lhbaOid,
                IMA_UINT        *pMethodCount,
                IMA_AUTHMETHOD  *pMethodList
);

IMA_API IMA_STATUS IMA_GetInitiatorAuthParms(
                IMA_OID lhbaOid,
                IMA_AUTHMETHOD method,
                IMA_INITIATOR_AUTHPARMS *pParms
);

IMA_API IMA_STATUS IMA_SetInitiatorAuthMethods(
                IMA_OID lhbaOid,
                IMA_UINT methodCount,
                const IMA_AUTHMETHOD *pMethodList
);

IMA_API IMA_STATUS IMA_SetInitiatorAuthParms(
                IMA_OID lhbaOid,
                IMA_AUTHMETHOD method,
                const IMA_INITIATOR_AUTHPARMS *pParms
);


IMA_API IMA_STATUS IMA_GetStaticDiscoveryTargetOidList (
                IMA_OID oid,
                IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_GetStaticDiscoveryTargetProperties(
		IMA_OID staticDiscoveryTargetOid,
		IMA_STATIC_DISCOVERY_TARGET_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_SetStaticDiscovery(
		IMA_OID oid,
		IMA_BOOL enableStaticDiscovery
);

IMA_API IMA_STATUS IMA_GetDiscoveryProperties(
		IMA_OID oid,
		IMA_DISCOVERY_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_AddDiscoveryAddress(
		IMA_OID oid,
		const IMA_TARGET_ADDRESS discoveryAddress,
		IMA_OID *pDiscoveryAddressOid
);

IMA_API IMA_STATUS IMA_AddStaticDiscoveryTarget(
		IMA_OID oid,
		const IMA_STATIC_DISCOVERY_TARGET staticDiscoveryTarget,
		IMA_OID *pStaticDiscoveryTargetOid
);

IMA_API IMA_STATUS IMA_GetAddressKeys(
		IMA_OID targetOid,
		IMA_ADDRESS_KEYS **ppKeys
);

IMA_API IMA_STATUS IMA_GetSessionOidList (
		IMA_OID oid,
		IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_GetConnectionOidList (
		IMA_OID oid,
		IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_GetDiscoveryAddressOidList (
		IMA_OID oid,
		IMA_OID_LIST **ppList
);

IMA_API IMA_STATUS IMA_GetDiscoveryAddressProperties (
		IMA_OID discoveryAddressOid,
		IMA_DISCOVERY_ADDRESS_PROPERTIES *pProps
);

IMA_API IMA_STATUS IMA_RemoveDiscoveryAddress (
		IMA_OID oid
);

IMA_API IMA_STATUS QIMA_SetUpdateInterval(IMA_OID pluginOid, time_t interval);

IMA_API IMA_STATUS IMA_CommitHbaParameters (IMA_OID lhba, IMA_COMMIT_LEVEL commitLevel);

#endif

#ifdef __cplusplus
};
#endif


