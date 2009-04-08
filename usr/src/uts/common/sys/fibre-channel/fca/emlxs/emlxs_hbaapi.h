/*
 * *****************************************************************************
 *
 * Description
 *	hbaapi.h - general header file for client
 * 		 and library developers
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
 * The Original Code is  SNIA HBA API general header file
 *
 * The Initial Developer of the Original Code is:
 *	Benjamin F. Kuo, Troika Networks, Inc. (benk@troikanetworks.com)
 *
 * Contributor(s):
 *	Tuan Lam, QLogic Corp. (t_lam@qlc.com)
 *	Dan Willie, Emulex Corp. (Dan.Willie@emulex.com)
 *	Dixon Hutchinson, Legato Systems, Inc. (dhutchin@legato.com)
 *	David Dillard, VERITAS Software Corp. (david.dillard@veritas.com)
 *
 *******************************************************************************
 *
 *   Changes:
 *	03/09/2000 Initial Draft
 *	(for other changes... see the CVS logs)
 *******************************************************************************
 */

#ifndef _EMLXS_HBAAPI_H
#define _EMLXS_HBAAPI_H

#ifdef __cplusplus
extern "C" {
#endif

/* Library version string */
#define HBA_LIBVERSION 2

/* DLL imports for WIN32 operation */
#ifdef WIN32
#ifdef HBAAPI_EXPORTS
#define HBA_API __declspec(dllexport)
#else
#define HBA_API __declspec(dllimport)
#endif
#else
#define HBA_API
#endif

/* OS specific definitions */

#ifdef WIN32
typedef unsigned char	HBA_UINT8;	// Unsigned  8 bits
typedef		 char	HBA_INT8;	// Signed    8 bits
typedef unsigned short	HBA_UINT16;	// Unsigned 16 bits
typedef		 short	HBA_INT16;	// Signed   16 bits
typedef unsigned int	HBA_UINT32;	// Unsigned 32 bits
typedef		 int	HBA_INT32;	// Signed   32 bits
typedef void*		HBA_PVOID;	// Pointer  to void
typedef HBA_UINT32	HBA_VOID32;	// Opaque   32 bits


/* Don't confuse, _WIN32 with WIN32... OK, how do you accompish that */
#ifdef _WIN32
typedef			_int64		HBA_INT64;
typedef			unsigned _int64	HBA_UINT64;
#else
typedef struct {
	TN_UINT32	lo_val;
	TN_UINT32	hi_val;
} HBA_INT64;

typedef struct {
	TN_UINT32	lo_val;
	TN_UINT32	hi_val;
} HBA_UINT64;
#endif	/*	#ifdef _WIN32	*/


#else
#ifndef	_KERNEL
#include <time.h> /* Needed for struct tm */
#endif /* ifndef _KERNEL */

/* Note this section needs to be cleaned up for various Unix platforms */
typedef unsigned char	HBA_UINT8;	/* Unsigned  8 bits */
typedef		 char	HBA_INT8;	/* Signed    8 bits */
typedef unsigned short	HBA_UINT16;	/* Unsigned 16 bits */
typedef		 short	HBA_INT16;	/* Signed   16 bits */
typedef unsigned int	HBA_UINT32;	/* Unsigned 32 bits */
typedef		 int	HBA_INT32;	/* Signed   32 bits */
typedef void*		HBA_PVOID;	/* Pointer  to void */
typedef HBA_UINT32	HBA_VOID32;	/* Opaque   32 bits */
typedef long long	HBA_INT64;
typedef long long	HBA_UINT64;

#endif  /*  #ifdef WIN32 */


/* 4.2.1	Handle to Device */
typedef HBA_UINT32	HBA_HANDLE;

#define HBA_HANDLE_INVALID		0

/* 4.2.2	Status Return Values */
typedef HBA_UINT32	HBA_STATUS;

#define HBA_STATUS_OK			0
#define HBA_STATUS_ERROR		1   /* Error */
#define HBA_STATUS_ERROR_NOT_SUPPORTED	2   /* Function not supported.*/
#define HBA_STATUS_ERROR_INVALID_HANDLE	3   /* invalid handle */
#define HBA_STATUS_ERROR_ARG		4   /* Bad argument */
#define HBA_STATUS_ERROR_ILLEGAL_WWN	5   /* WWN not recognized */
#define HBA_STATUS_ERROR_ILLEGAL_INDEX	6   /* Index not recognized */
#define HBA_STATUS_ERROR_MORE_DATA	7   /* Larger buffer required */
#define HBA_STATUS_ERROR_STALE_DATA	8   /* Information has changed since
					     * last call to
					     * HBA_Refreshinformation */
#define HBA_STATUS_SCSI_CHECK_CONDITION	9   /* Obvious */
#define HBA_STATUS_ERROR_BUSY		10  /* Adapter busy or reserved,
					     * retry may be effective */
#define HBA_STATUS_ERROR_TRY_AGAIN	11  /* Request timedout,
					     * retry may be effective */
#define HBA_STATUS_ERROR_UNAVAILABLE	12  /* Referenced HBA has been removed
					     * or deactivated */
#define HBA_STATUS_ERROR_ELS_REJECT	13  /* The requested ELS was rejected by
					     * the local adapter */
#define HBA_STATUS_ERROR_INVALID_LUN	14  /* The specified LUN is not provided 
					     *  the specified adapter */
#define HBA_STATUS_ERROR_INCOMPATIBLE	15  /* An incompatibility has been
				* detected among the library and driver modules 
				* invoked which will cause one or more functions 
				* in the highest version that all support to 
				* operate incorrectly.  The differing function 
				* sets of software modules implementing different
				* versions of the HBA API specification does not 
				* in itself constitute an incompatibility.  Known 
				* interoperability bugs among supposedly 
				* compatible versions should be reported as 
				* incompatibilities, but not all such 
				* interoperability bugs may be known.  This value
				* may be returned by any function that calls a 
				* Vendor Specific Library and returns an 
				* HBA_STATUS, and by HBA_LoadLibrary and 
				* HBA_GetAdapterName. */

#define HBA_STATUS_ERROR_AMBIGUOUS_WWN	16  /* Multiple adapters have a matching
					     * WWN. This could occur if the
					     * NodeWWN of multiple adapters is 
					     * identical */
#define HBA_STATUS_ERROR_LOCAL_BUS	17  /* A persistent binding request
					     * included a bad local SCSI bus
					     * number */
#define HBA_STATUS_ERROR_LOCAL_TARGET	18  /* A persistent binding request
					     * included a bad local SCSI target
					     * number */
#define HBA_STATUS_ERROR_LOCAL_LUN	19  /* A persistent binding request
					     * included a bad local SCSI logical
					     * unit number */
#define HBA_STATUS_ERROR_LOCAL_SCSIID_BOUND 20
					    /* A persistent binding set request
					     * included a local SCSI ID that was
					     * already bound */
#define HBA_STATUS_ERROR_TARGET_FCID	21  /* A persistent binding request
					     * included a bad or unlocatable FCP
					     * Target FCID */
#define HBA_STATUS_ERROR_TARGET_NODE_WWN 22 /* A persistent binding request 
					     * included a bad FCP Target Node
					     * WWN */
#define HBA_STATUS_ERROR_TARGET_PORT_WWN 23 /* A persistent binding request
					     * included a bad FCP Target Port
					     * WWN */
#define HBA_STATUS_ERROR_TARGET_LUN	24  /* A persistent binding request
					     * included an FCP Logical Unit Number
					     * not defined by the identified 
					     * Target*/
#define HBA_STATUS_ERROR_TARGET_LUID	25  /* A persistent binding request
					     * included an undefined or otherwise
					     * inaccessible Logical Unit Unique
					     * Identifier */
#define HBA_STATUS_ERROR_NO_SUCH_BINDING 26 /* A persistent binding remove request
					     * included a binding which did not
					     * match a binding established by the
					     * specified port */
#define HBA_STATUS_ERROR_NOT_A_TARGET	27  /* A SCSI command was requested to an
					     * Nx_Port that was not a SCSI
					     * Target Port */
#define HBA_STATUS_ERROR_UNSUPPORTED_FC4 28 /* A request was made concerning an 
					     * unsupported FC-4 protocol */


#define HBA_STATUS_ERROR_INCAPABLE	29  /* A request was made to enable 
					     * unimplemented capabilities for a 
					     * port */ 

/* 4.2.3	Port Operational Modes Values */
typedef HBA_UINT32 HBA_PORTTYPE;

#define HBA_PORTTYPE_UNKNOWN		1   /* Unknown */
#define HBA_PORTTYPE_OTHER		2   /* Other */
#define HBA_PORTTYPE_NOTPRESENT		3   /* Not present */
#define HBA_PORTTYPE_NPORT		5   /* Fabric  */
#define HBA_PORTTYPE_NLPORT		6   /* Public Loop */
#define HBA_PORTTYPE_FLPORT		7
#define HBA_PORTTYPE_FPORT		8   /* Fabric Port */
#define HBA_PORTTYPE_EPORT		9   /* Fabric expansion port */
#define HBA_PORTTYPE_GPORT		10  /* Generic Fabric Port */
#define HBA_PORTTYPE_LPORT		20  /* Private Loop */
#define HBA_PORTTYPE_PTP		21  /* Point to Point */


typedef HBA_UINT32 HBA_PORTSTATE;
#define HBA_PORTSTATE_UNKNOWN		1   /* Unknown */
#define HBA_PORTSTATE_ONLINE		2   /* Operational */
#define HBA_PORTSTATE_OFFLINE		3   /* User Offline */
#define HBA_PORTSTATE_BYPASSED		4   /* Bypassed */
#define HBA_PORTSTATE_DIAGNOSTICS	5   /* In diagnostics mode */
#define HBA_PORTSTATE_LINKDOWN		6   /* Link Down */
#define HBA_PORTSTATE_ERROR		7   /* Port Error */
#define HBA_PORTSTATE_LOOPBACK		8   /* Loopback */


typedef HBA_UINT32 HBA_PORTSPEED;
#define HBA_PORTSPEED_UNKNOWN		0   /* Unknown - transceiver incable
					     * of reporting */
#define HBA_PORTSPEED_1GBIT		1   /* 1 GBit/sec */
#define HBA_PORTSPEED_2GBIT		2   /* 2 GBit/sec */
#define HBA_PORTSPEED_10GBIT		4   /* 10 GBit/sec */
#define HBA_PORTSPEED_4GBIT		8   /* 4 GBit/sec */
#define HBA_PORTSPEED_8GBIT		16  /* 8 GBit/sec */
#define HBA_PORTSPEED_16GBIT		32  /* 16 GBit/sec */
#define HBA_PORTSPEED_NOT_NEGOTIATED	(1<<15)   /* Speed not established */



/* 4.2.4	Class of Service Values - See GS-2 Spec.*/

typedef HBA_UINT32 HBA_COS;


/* 4.2.5	Fc4Types Values */

typedef struct HBA_fc4types {
    HBA_UINT8 bits[32];		/* 32 bytes of FC-4 per GS-2 */
} HBA_FC4TYPES, *PHBA_FC4TYPES;

/* 4.2.6	Basic Types */

typedef struct HBA_wwn {
    HBA_UINT8 wwn[8];
} HBA_WWN, *PHBA_WWN;

typedef struct HBA_ipaddress {
    int	ipversion;		/* see enumerations in RNID */
    union
    {
	unsigned char ipv4address[4];
	unsigned char ipv6address[16];
    } ipaddress;
} HBA_IPADDRESS, *PHBA_IPADDRESS;

typedef HBA_INT8	HBA_BOOLEAN;

/* 4.2.7	Adapter Attributes */
typedef struct hba_AdapterAttributes {
    char	Manufacturer[64];	/*Emulex */
    char	SerialNumber[64];	/* A12345 */
    char	Model[256];		/* QLA2200 */
    char	ModelDescription[256];	/* Agilent TachLite */
    HBA_WWN	NodeWWN;
    char	NodeSymbolicName[256];	/* From GS-3 */
    char	HardwareVersion[256];	/* Vendor use */
    char	DriverVersion[256];	/* Vendor use */
    char	OptionROMVersion[256];	/* Vendor use  - i.e. hardware boot ROM*/
    char	FirmwareVersion[256];	/* Vendor use */
    HBA_UINT32	VendorSpecificID;	/* Vendor specific */
    HBA_UINT32	NumberOfPorts;
    char	DriverName[256];	/* Binary path and/or name of driver
					 *file */
} HBA_ADAPTERATTRIBUTES, *PHBA_ADAPTERATTRIBUTES;

/* 4.2.8	Port Attributes */
typedef struct HBA_PortAttributes {
    HBA_WWN		NodeWWN;
    HBA_WWN		PortWWN;
    HBA_UINT32		PortFcId;
    HBA_PORTTYPE	PortType;		/*PTP, Fabric, etc. */
    HBA_PORTSTATE	PortState;
    HBA_COS		PortSupportedClassofService;
    HBA_FC4TYPES	PortSupportedFc4Types;
    HBA_FC4TYPES	PortActiveFc4Types;
    char		PortSymbolicName[256];
    char		OSDeviceName[256];	/* \device\ScsiPort3  */
    HBA_PORTSPEED	PortSupportedSpeed;
    HBA_PORTSPEED	PortSpeed;
    HBA_UINT32		PortMaxFrameSize;
    HBA_WWN		FabricName;
    HBA_UINT32		NumberofDiscoveredPorts;
} HBA_PORTATTRIBUTES, *PHBA_PORTATTRIBUTES;



/* 4.2.9	Port Statistics */

typedef struct HBA_PortStatistics {
    HBA_INT64		SecondsSinceLastReset;
    HBA_INT64		TxFrames;
    HBA_INT64		TxWords;
    HBA_INT64		RxFrames;
    HBA_INT64		RxWords;
    HBA_INT64		LIPCount;
    HBA_INT64		NOSCount;
    HBA_INT64		ErrorFrames;
    HBA_INT64		DumpedFrames;
    HBA_INT64		LinkFailureCount;
    HBA_INT64		LossOfSyncCount;
    HBA_INT64		LossOfSignalCount;
    HBA_INT64		PrimitiveSeqProtocolErrCount;
    HBA_INT64		InvalidTxWordCount;
    HBA_INT64		InvalidCRCCount;
} HBA_PORTSTATISTICS, *PHBA_PORTSTATISTICS;



/* 4.2.10		FCP Attributes */

typedef enum HBA_fcpbindingtype { TO_D_ID, TO_WWN, TO_OTHER } HBA_FCPBINDINGTYPE;

typedef struct HBA_ScsiId {
    char		OSDeviceName[256];	/* \device\ScsiPort3  */
    HBA_UINT32		ScsiBusNumber;		/* Bus on the HBA */
    HBA_UINT32		ScsiTargetNumber;	/* SCSI Target ID to OS */
    HBA_UINT32		ScsiOSLun;
} HBA_SCSIID, *PHBA_SCSIID;

typedef struct HBA_FcpId {
    HBA_UINT32		FcId;
    HBA_WWN		NodeWWN;
    HBA_WWN		PortWWN;
    HBA_UINT64		FcpLun;
} HBA_FCPID, *PHBA_FCPID;

typedef struct HBA_LUID {
    char		buffer[256];	/* Unique Device Identifier */
} HBA_LUID, *PHBA_LUID;

typedef struct HBA_FcpScsiEntry {
    HBA_SCSIID		ScsiId;
    HBA_FCPID		FcpId;
} HBA_FCPSCSIENTRY, *PHBA_FCPSCSIENTRY;

typedef struct HBA_FcpScsiEntryV2 {
    HBA_SCSIID		ScsiId;
    HBA_FCPID		FcpId;
    HBA_LUID		LUID;
} HBA_FCPSCSIENTRYV2, *PHBA_FCPSCSIENTRYV2;

typedef struct HBA_FCPTargetMapping {
    HBA_UINT32		NumberOfEntries;
    HBA_FCPSCSIENTRY	entry[1];		/* Variable length array
						 * containing mappings */
} HBA_FCPTARGETMAPPING, *PHBA_FCPTARGETMAPPING;

typedef struct HBA_FCPTargetMappingV2 {
    HBA_UINT32		NumberOfEntries;
    HBA_FCPSCSIENTRYV2	entry[1];		/* Variable length array
						 * containing mappings */
} HBA_FCPTARGETMAPPINGV2, *PHBA_FCPTARGETMAPPINGV2;

typedef struct HBA_FCPBindingEntry {
    HBA_FCPBINDINGTYPE	type;
    HBA_SCSIID		ScsiId;
    HBA_FCPID		FcpId;			/* WWN valid only if type is
						 * to WWN, FcpLun always valid */
    HBA_UINT32		FcId;
} HBA_FCPBINDINGENTRY, *PHBA_FCPBINDINGENTRY;

typedef struct HBA_FCPBinding {
    HBA_UINT32		NumberOfEntries;
    HBA_FCPBINDINGENTRY	entry[1];		/* Variable length array */
} HBA_FCPBINDING, *PHBA_FCPBINDING;

/* 4.2.11	FC-3 Management Atrributes */

typedef enum HBA_wwntype { NODE_WWN, PORT_WWN } HBA_WWNTYPE;

typedef struct HBA_MgmtInfo {
    HBA_WWN		wwn;
    HBA_UINT32		unittype;
    HBA_UINT32		PortId;
    HBA_UINT32		NumberOfAttachedNodes;
    HBA_UINT16		IPVersion;
    HBA_UINT16		UDPPort;
    HBA_UINT8		IPAddress[16];
    HBA_UINT16		reserved;
    HBA_UINT16		TopologyDiscoveryFlags;
} HBA_MGMTINFO, *PHBA_MGMTINFO;

/* Event Codes */
#define HBA_EVENT_LIP_OCCURRED		1
#define HBA_EVENT_LINK_UP		2
#define HBA_EVENT_LINK_DOWN		3
#define HBA_EVENT_LIP_RESET_OCCURRED	4
#define HBA_EVENT_RSCN			5
#define HBA_EVENT_PROPRIETARY		0xFFFF

typedef struct HBA_Link_EventInfo {
    HBA_UINT32		PortFcId;		/* Port where event occurred */
    HBA_UINT32		Reserved[3];
} HBA_LINK_EVENTINFO, *PHBA_LINK_EVENTINFO;

typedef struct HBA_RSCN_EventInfo {
    HBA_UINT32		PortFcId;		/* Port where event occurred */
    HBA_UINT32		NPortPage;		/* Reference FC-FS for RSCN ELS
						 * "Affected N-Port Pages"*/
    HBA_UINT32		Reserved[2];
} HBA_RSCN_EVENTINFO, *PHBA_RSCN_EVENTINFO;

typedef struct HBA_Pty_EventInfo {
    HBA_UINT32 PtyData[4];			/* Proprietary data */
} HBA_PTY_EVENTINFO, *PHBA_PTY_EVENTINFO;

typedef struct HBA_EventInfo {
    HBA_UINT32		EventCode;
    union {
	HBA_LINK_EVENTINFO	Link_EventInfo;
	HBA_RSCN_EVENTINFO	RSCN_EventInfo;
	HBA_PTY_EVENTINFO	Pty_EventInfo;
    }			Event;
} HBA_EVENTINFO, *PHBA_EVENTINFO;

#ifndef	_KERNEL
typedef struct HBA_LibraryAttributes {
    HBA_BOOLEAN		final;
    char		LibPath[256];
    char		VName[256];
    char		VVersion[256];
    struct tm		build_date;
} HBA_LIBRARYATTRIBUTES, *PHBA_LIBRARYATTRIBUTES;
#endif /* ifndef _KERNEL */

/* Persistant Binding... */
typedef HBA_UINT32 HBA_BIND_TYPE;
#define HBA_BIND_TO_D_ID		0x0001
#define HBA_BIND_TO_WWPN		0x0002
#define HBA_BIND_TO_WWNN		0x0004
#define HBA_BIND_TO_LUID		0x0008
#define HBA_BIND_TARGETS		0x0800

/* A bit mask of Rev 2.0 persistent binding capabilities */
typedef HBA_UINT32 HBA_BIND_CAPABILITY;
/* The following are bit flags indicating persistent binding capabilities */
#define HBA_CAN_BIND_TO_D_ID		0x0001
#define HBA_CAN_BIND_TO_WWPN		0x0002
#define HBA_CAN_BIND_TO_WWNN		0x0004
#define HBA_CAN_BIND_TO_LUID		0x0008
#define HBA_CAN_BIND_ANY_LUNS		0x0400
#define HBA_CAN_BIND_TARGETS		0x0800
#define HBA_CAN_BIND_AUTOMAP		0x1000
#define HBA_CAN_BIND_CONFIGURED		0x2000

#define HBA_BIND_STATUS_DISABLED	0x00
#define HBA_BIND_STATUS_ENABLED		0x01

typedef HBA_UINT32 HBA_BIND_STATUS;

#define HBA_BIND_EFFECTIVE_AT_REBOOT	0x00
#define HBA_BIND_EFFECTIVE_IMMEDIATE	0x01

typedef HBA_UINT32 HBA_BIND_EFFECTIVE;

typedef struct HBA_FCPBindingEntry2 {
    HBA_BIND_TYPE	type;
    HBA_SCSIID		ScsiId;
    HBA_FCPID		FcpId;
    HBA_LUID		LUID;
    HBA_STATUS		status;
} HBA_FCPBINDINGENTRY2, *PHBA_FCPBINDINGENTRY2;

typedef struct HBA_FcpBinding2 {
    HBA_UINT32		NumberOfEntries;
    HBA_FCPBINDINGENTRY2
			entry[1];	/* Variable length array */
} HBA_FCPBINDING2, *PHBA_FCPBINDING2;

/* FC-4 Instrumentation */
typedef struct HBA_FC4Statistics {
    HBA_INT64		InputRequests;
    HBA_INT64		OutputRequests;
    HBA_INT64		ControlRequests;
    HBA_INT64		InputMegabytes;
    HBA_INT64		OutputMegabytes;
} HBA_FC4STATISTICS, *PHBA_FC4STATISTICS;


typedef void *	HBA_CALLBACKHANDLE;
/* Adapter Level Events */
#define HBA_EVENT_ADAPTER_UNKNOWN	0x100
#define HBA_EVENT_ADAPTER_ADD		0x101
#define HBA_EVENT_ADAPTER_REMOVE	0x102
#define HBA_EVENT_ADAPTER_CHANGE	0x103

/* Port Level Events */
#define HBA_EVENT_PORT_UNKNOWN		0x200
#define HBA_EVENT_PORT_OFFLINE		0x201
#define HBA_EVENT_PORT_ONLINE		0x202
#define HBA_EVENT_PORT_NEW_TARGETS	0x203
#define HBA_EVENT_PORT_FABRIC		0x204

/* Port Statistics Events */
#define HBA_EVENT_PORT_STAT_THRESHOLD	0x301
#define HBA_EVENT_PORT_STAT_GROWTH	0x302

/* Target Level Events */
#define HBA_EVENT_TARGET_UNKNOWN	0x400
#define HBA_EVENT_TARGET_OFFLINE	0x401
#define HBA_EVENT_TARGET_ONLINE		0x402
#define HBA_EVENT_TARGET_REMOVED	0x403

/* Fabric Link  Events */
#define HBA_EVENT_LINK_UNKNOWN		0x500
#define HBA_EVENT_LINK_INCIDENT		0x501

HBA_API HBA_UINT32 HBA_GetVersion();

/*
 * Make sure HBA_LoadLibrary returns before any other threads
 * make calls to the library
 */
HBA_API HBA_STATUS HBA_LoadLibrary();

HBA_API HBA_STATUS HBA_FreeLibrary();

HBA_API HBA_UINT32 HBA_GetNumberOfAdapters();

HBA_API HBA_STATUS HBA_GetAdapterName(
    HBA_UINT32		adapterindex,
    char		*adaptername
    );

HBA_API HBA_HANDLE HBA_OpenAdapter(
    char*		adaptername
    );

HBA_API HBA_STATUS HBA_OpenAdapterByWWN(
    HBA_HANDLE		*handle,
    HBA_WWN		wwn
    );

HBA_API void HBA_CloseAdapter(
    HBA_HANDLE		handle
    );

HBA_API HBA_STATUS HBA_GetAdapterAttributes(
    HBA_HANDLE		handle,
    HBA_ADAPTERATTRIBUTES
			*hbaattributes
    );

HBA_API HBA_STATUS HBA_GetAdapterPortAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_PORTATTRIBUTES	*portattributes
    );

HBA_API HBA_STATUS HBA_GetPortStatistics(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_PORTSTATISTICS	*portstatistics
    );

HBA_API HBA_STATUS HBA_GetDiscoveredPortAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		discoveredportindex,
    HBA_PORTATTRIBUTES	*portattributes
    );

HBA_API HBA_STATUS HBA_GetPortAttributesByWWN(
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_PORTATTRIBUTES	*portattributes
    );

HBA_API HBA_STATUS HBA_SendCTPassThruV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    void		*pReqBuffer,
    HBA_UINT32		ReqBufferSize,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize
    );

/* Depricated, but supported */
HBA_API HBA_STATUS HBA_SendCTPassThru(
    HBA_HANDLE		handle,
    void		*pReqBuffer,
    HBA_UINT32		ReqBufferSize,
    void		*pRspBuffer,
    HBA_UINT32		RspBufferSize
    );

HBA_API void HBA_RefreshAdapterConfiguration();

HBA_API HBA_STATUS HBA_GetEventBuffer(
    HBA_HANDLE		handle,
    HBA_EVENTINFO	*EventBuffer,
    HBA_UINT32		*EventBufferCount
    );

HBA_API HBA_STATUS HBA_SetRNIDMgmtInfo(
    HBA_HANDLE		handle,
    HBA_MGMTINFO	Info
    );

HBA_API HBA_STATUS HBA_GetRNIDMgmtInfo(
    HBA_HANDLE		handle,
    HBA_MGMTINFO	*pInfo
    );

HBA_API HBA_STATUS HBA_SendRNIDV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		destWWN,
    HBA_UINT32		destFCID,
    HBA_UINT32		NodeIdDataFormat,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize
    );

/* Depricated, but supported */
HBA_API HBA_STATUS HBA_SendRNID(
    HBA_HANDLE		handle,
    HBA_WWN		wwn,
    HBA_WWNTYPE		wwntype,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize
    );

HBA_API HBA_STATUS HBA_SendRLS (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		destWWN,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize
    );

HBA_API HBA_STATUS HBA_SendRPL (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		agent_wwn,
    HBA_UINT32		agent_domain,
    HBA_UINT32		portindex,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize
    );

HBA_API HBA_STATUS HBA_SendRPS (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		agent_wwn,
    HBA_UINT32		agent_domain,
    HBA_WWN		object_wwn,
    HBA_UINT32		object_port_number,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize
    );

HBA_API HBA_STATUS HBA_SendSRL (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		wwn,
    HBA_UINT32		domain,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize
    );

HBA_API HBA_STATUS HBA_SendLIRR (
    HBA_HANDLE		handle,
    HBA_WWN		sourceWWN,
    HBA_WWN		destWWN,
    HBA_UINT8		function,
    HBA_UINT8		type,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize
    );


HBA_API HBA_STATUS HBA_GetFC4Statistics (
    HBA_HANDLE		handle,
    HBA_WWN		portWWN,
    HBA_UINT8		FC4type,
    HBA_FC4STATISTICS	*pstatistics
    );

HBA_API HBA_STATUS HBA_GetFCPStatistics (
    HBA_HANDLE		handle,
    const HBA_SCSIID	*lunit,
    HBA_FC4STATISTICS	*pstatistics);

HBA_API void HBA_RefreshInformation(
    HBA_HANDLE		handle
    );

HBA_API void HBA_ResetStatistics(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex
    );

HBA_API HBA_STATUS HBA_GetFcpTargetMapping(
    HBA_HANDLE		handle,
    HBA_FCPTARGETMAPPING
			*pmapping
    );

HBA_API HBA_STATUS HBA_GetFcpTargetMappingV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_FCPTARGETMAPPINGV2
			*pmapping
    );

HBA_API HBA_STATUS HBA_GetBindingCapability(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_BIND_CAPABILITY *pcapability
    );

HBA_API HBA_STATUS HBA_GetBindingSupport(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_BIND_CAPABILITY *pcapability
    );

HBA_API HBA_STATUS HBA_SetBindingSupport(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_BIND_CAPABILITY capability
    );

HBA_API HBA_STATUS HBA_SetPersistentBindingV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    const HBA_FCPBINDING2
			*pbinding
    );

HBA_API HBA_STATUS HBA_GetPersistentBindingV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_FCPBINDING2	*binding
    );

HBA_API HBA_STATUS HBA_RemovePersistentBinding(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    const HBA_FCPBINDING2
			*pbinding
    );

/* Depricated, but supported */
HBA_API HBA_STATUS HBA_GetFcpPersistentBinding(
    HBA_HANDLE		handle,
    HBA_FCPBINDING	*binding
    );

HBA_API HBA_STATUS HBA_RemoveAllPersistentBindings(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN
    );

HBA_STATUS HBA_ScsiInquiryV2 (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		discoveredPortWWN,
    HBA_UINT64		fcLUN,
    HBA_UINT8		CDB_Byte1,
    HBA_UINT8		CDB_BYte2,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize,
    HBA_UINT8		*pScsiStatus,
    void		*pSenseBuffer,
    HBA_UINT32		*pSenseBufferSize
    );

/* Depricated, but supported */
HBA_API HBA_STATUS HBA_SendScsiInquiry (
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_UINT64		fcLUN,
    HBA_UINT8		EVPD,
    HBA_UINT32		PageCode,
    void		*pRspBuffer,
    HBA_UINT32		RspBufferSize,
    void		*pSenseBuffer,
    HBA_UINT32		SenseBufferSize
    );

HBA_API HBA_STATUS HBA_ScsiReportLUNsV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		discoveredPortWWN,
    void		*pRespBuffer,
    HBA_UINT32		*pRespBufferSize,
    HBA_UINT8		*pScsiStatus,
    void		*pSenseBuffer,
    HBA_UINT32		*pSenseBufferSize
    );

/* Depricated, but supported */
HBA_API HBA_STATUS HBA_SendReportLUNs (
    HBA_HANDLE		handle,
    HBA_WWN		portWWN,
    void		*pRspBuffer,
    HBA_UINT32		RspBufferSize,
    void		*pSenseBuffer,
    HBA_UINT32		SenseBufferSize
    );

HBA_API HBA_STATUS HBA_ScsiReadCapacityV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		discoveredPortWWN,
    HBA_UINT64		fcLUN,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize,
    HBA_UINT8		*pScsiStatus,
    void		*pSenseBuffer,
    HBA_UINT32		*SenseBufferSize
    );

/* Depricated, but supported */
HBA_API HBA_STATUS HBA_SendReadCapacity (
    HBA_HANDLE		handle,
    HBA_WWN		portWWN,
    HBA_UINT64		fcLUN,
    void		*pRspBuffer,
    HBA_UINT32		RspBufferSize,
    void		*pSenseBuffer,
    HBA_UINT32		SenseBufferSize
    );

#ifndef	_KERNEL
HBA_API HBA_UINT32 HBA_GetVendorLibraryAttributes (
    HBA_UINT32		adapter_index,
    HBA_LIBRARYATTRIBUTES
			*attributes
    );
#endif /* ifndef _KERNEL */

HBA_API HBA_STATUS HBA_RemoveCallback(
    HBA_CALLBACKHANDLE	callbackHandle
    );

HBA_API HBA_STATUS HBA_RegisterForAdapterAddEvents(
    void		(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType
	),
    void		*userData,
    HBA_CALLBACKHANDLE *callbackHandle
    );

HBA_API HBA_STATUS HBA_RegisterForAdapterEvents(
    void		(*callback)(
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType
	),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_CALLBACKHANDLE	*callbackHandle
    );

HBA_API HBA_STATUS HBA_RegisterForAdapterPortEvents(
    void		(*callback)(
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType,
	HBA_UINT32	fabricPortID
	),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_CALLBACKHANDLE *callbackHandle
    );

HBA_API HBA_STATUS HBA_RegisterForAdapterPortStatEvents(
    void		(*callback)(
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType
	),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_PORTSTATISTICS	stats,
    HBA_UINT32		statType,
    HBA_CALLBACKHANDLE	*callbackHandle
    );


HBA_API HBA_STATUS HBA_RegisterForTargetEvents(
    void		(*callback)(
	void		*data,
	HBA_WWN		hbaPortWWN,
	HBA_WWN		discoveredPortWWN,
	HBA_UINT32	eventType
	),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		discoveredPortWWN,
    HBA_CALLBACKHANDLE	*callbackHandle,
    HBA_UINT32		allTargets
    );

HBA_API HBA_STATUS HBA_RegisterForLinkEvents(
    void		(*callback)
    (
	void		*data,
	HBA_WWN		adapterWWN,
	HBA_UINT32	eventType,
	void		*pRLIRBuffer,
	HBA_UINT32	RLIRBufferSize
	),
    void		*userData,
    void		*pRLIRBuffer,
    HBA_UINT32		RLIRBufferSize,
    HBA_HANDLE		handle,
    HBA_CALLBACKHANDLE	*callbackHandle
);

/* Wrapper library specific entry points */

#ifndef	_KERNEL
HBA_API HBA_UINT32 HBA_GetWrapperLibraryAttributes (
    HBA_LIBRARYATTRIBUTES
			*attributes
);
#endif /* ifndef _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _EMLXS_HBAAPI_H */
