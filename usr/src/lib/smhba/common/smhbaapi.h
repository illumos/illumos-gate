/*
 * ****************************************************************************
 *
 * Description
 *	smhbaapi.h - general header file for client
 *	and library developers
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
 * The Original Code for  SM-HBA API general header file
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
 * ****************************************************************************
 *
 * Adding on SM-HBA related definitions.
 *
 * - Includes the original HBA API header.
 * - SMHBA_* interfaces and structures are defined.
 *
 * ****************************************************************************
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMHBAAPI_H_
#define	_SMHBAAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <hbaapi.h>

/* Library version string */
#define	SMHBA_LIBVERSION 1

/*
 * A SCSI function was requested at a time when issuing the requested command
 * would cause a SCSI overlapped command condition (see SAM-3)
 */
#define	HBA_STATUS_ERROR_TARGET_BUSY	30
/* SM-HBA 6.2	Status Return Values */
/* A call was made to HBA_FreeLibrary when no library was loaded */
#define	HBA_STATUS_ERROR_NOT_LOADED	31
/* A call was made to HBA_LoadLibrary when a library was already loaded */
#define	HBA_STATUS_ERROR_ALREADY_LOADED 32
/*
 * The Address Identifier specified in a call to HBA_SendRNIDV2
 * violates access control rules * for that call.
 */
#define	HBA_STATUS_ERROR_ILLEGAL_FCID	33
#define	HBA_STATUS_ERROR_NOT_ASCSIDEVICE    34
#define	HBA_STATUS_ERROR_INVALID_PROTOCOL_TYPE	35
#define	HBA_STATUS_ERROR_BAD_EVENT_TYPE	36


/* SM-HBA 6.4.1.1 Port Type */
#define	HBA_PORTTYPE_SASDEVICE   30 /* SAS (SSP or STP) */
#define	HBA_PORTTYPE_SATADEVICE  31 /* SATA Device, i.e. Direct Attach SATA */
#define	HBA_PORTTYPE_SASEXPANDER 32 /* SAS Expander */

/* SM-HBA 6.4.1.2 Port State */
#define	HBA_PORTSTATE_DEGRADED	9 /* Degraded, but Operational mode */

/* SM-HBA 6.11.1.3 Port Speed */
#define	HBA_PORTSPEED_4GBIT	8  /*  4 GBit / sec */

/* SM-HBA 6.1	Basic Attributes Types */
typedef struct SMHBA_scsilun {HBA_UINT8 lun[8]; }
    SMHBA_SCSILUN, *PSMHBA_SCSILUN;
			/* A byte array representation of a SCSI */
			/* LUN (see SAM-4). The first byte of the */
			/* LUN shall be in the first byte of the */
			/* array, and successive bytes of the SCSI */
			/* LUN shall be in successive bytes of the */
			/* array. */
typedef unsigned long HBA_SCSILUN;
			/* A 64 bit unsigned integer representation */
			/* of a SCSI LUN (see SAM-4); */
			/* may use OS-specific typedef. */
			/* Byte zero of a SCSI LUN shall be stored */
			/* in the lowest memory address */
			/* of the unsigned 64-bit integer value, */
			/* and successive bytes of the SCSI LUN */
			/* shall be stored in successively higher memory */
			/* addresses of the unsigned 64-bit intege value. */
			/* Note that computers often do not store */
			/* a byte array in memory in the same order */
			/* as they store an integer. */
			/* This standard requires storage as a byte array */


/* SM-HBA 6.3.1 Generic Adapter Attribute */
typedef struct SMHBA_AdapterAttributes {
	char			Manufacturer[64];
	char			SerialNumber[64];
	char			Model[256];
	char			ModelDescription[256];
	char			HardwareVersion[256];
	char			DriverVersion[256];
	char			OptionROMVersion[256];
	char			FirmwareVersion[256];
	HBA_UINT32		VendorSpecificID;
	char			DriverName[256];
	char			HBASymbolicName[256];
	char			RedundantOptionROMVersion[256];
	char			RedundantFirmwareVersion[256];
} SMHBA_ADAPTERATTRIBUTES, *PSMHBA_ADAPTERATTRIBUTES;

/* SM-HBA 6.4.6 SMHBA FC Port Attributes */
typedef struct SMHBA_FC_Port {
	HBA_WWN			NodeWWN;
	HBA_WWN			PortWWN;
	HBA_UINT32		FcId;
	HBA_COS			PortSupportedClassofService;
	HBA_FC4TYPES		PortSupportedFc4Types;
	HBA_FC4TYPES		PortActiveFc4Types;
	HBA_WWN			FabricName;
	char			PortSymbolicName[256];
	HBA_UINT32		NumberofDiscoveredPorts;
	HBA_UINT8		NumberofPhys;
}SMHBA_FC_PORT, *PSMHBA_FC_PORT;

/* SM-HBA 6.4.7.1 HBA_SASPortProtocol */
typedef HBA_UINT32	HBA_SASPORTPROTOCOL;
#define	HBA_SASPORTPROTOCOL_SSP	    1 /* Serial SCSI Protocol Port */
#define	HBA_SASPORTPROTOCOL_STP	    2 /* Serial ATA Tunneling Protocol Port */
#define	HBA_SASPORTPROTOCOL_SMP	    4 /* Serial Management Protocol Port */
/* SATA Device, Direct Attached or anywhere in the domain. */
#define	HBA_SASPORTPROTOCOL_SATA    8

/* SM-HBA 6.4.8 SMHBA SAS Port Attributes */
typedef struct SMHBA_SAS_Port {
	HBA_SASPORTPROTOCOL	PortProtocol;
	HBA_WWN			LocalSASAddress;
	HBA_WWN			AttachedSASAddress;
	HBA_UINT32		NumberofDiscoveredPorts;
	HBA_UINT32		NumberofPhys;
} SMHBA_SAS_PORT, *PSMHBA_SAS_PORT;

/* SM-HBA 6.4.2 Generic Port Attributes */
typedef union SMHBA_Port {
	SMHBA_FC_PORT		*FCPort;
	SMHBA_SAS_PORT		*SASPort;
} SMHBA_PORT, *PSMHBA_PORT;

typedef struct SMHBA_PortAttributes {
	HBA_PORTTYPE		PortType;
	HBA_PORTSTATE		PortState;
	char			OSDeviceName[256];
	SMHBA_PORT		PortSpecificAttribute;
} SMHBA_PORTATTRIBUTES, *PSMHBA_PORTATTRIBUTES;

/* SM-HBA 6.5.1.1 FC Phy Speed */
typedef HBA_UINT32 HBA_FCPHYSPEED;
/* Unknown transceiver incapable of reporting */
#define	HBA_FCSPEED_UNKNOWN		0
/*
 * The following are redundantly defined in SM-HBA 6.11.1.3 Port Speed.
 * #define  HBA_PORTSPEED_1GBIT            1       1 GBit/sec
 * #define  HBA_PORTSPEED_2GBIT            2          2 GBit/sec
 * #define  HBA_PORTSPEED_10GBIT           4          10 GBit/sec
 * #define  HBA_PORTSPEED_4GBIT            8          4 GBit/sec
 */
#define	HBA_FCPHYSPEED_8GBIT		16  /* 8 GBit/sec */
#define	HBA_FCPHYSPEED_16GBIT		32  /* 16 GBit/sec */
/*
 * The following conflicts with HBA API
 * #define  HBA_PORTSPEED_NOT_NEGOTIATED   (1<<15)  Speed not established
 */

/* SM-HBA 6.6.1.2 SM-HBA FC Phy Type */
typedef HBA_UINT8 HBA_FCPHYTYPE;
#define	HBA_FCPHYTYPE_UNKNOWN		    1 /* Unknown Phy type */
#define	HBA_FCPHYTYPE_OPTICAL		    2 /* Optical Phy */
#define	HBA_FCPHYTYPE_COPPER		    4 /* Copper Phy */

/* SM-HBA 6.5.2 SM-HBA FC Phy Attributes */
typedef struct SMHBA_FC_Phy {
	HBA_FCPHYSPEED	    PhySupportedSpeed;	/* PhySupportedSpeed */
	HBA_FCPHYSPEED	    PhySpeed;		/* PhySpeed */
	HBA_FCPHYTYPE	    PhyType;
	HBA_UINT32	    MaxFrameSize;	/* MaxFrameSize */
} SMHBA_FC_PHY, *PSMHBA_FC_PHY;

/* SM-HBA 6.5.4 SAS PHY Attribute Data Declaration */
typedef HBA_UINT32 HBA_SASPHYSPEED;

#define	HBA_SASSTATE_UNKNOWN	0x00 /* Phy is enabled. Speed is unknown */
#define	HBA_SASSTATE_DISABLED	0x01 /* Phy is disabled. */
/* Phy is enabled. But failed speed negotiation. */
#define	HBA_SASSTATE_FAILED	0x02
/*
 * Phy is enabled. Detected a SATA device and entered the SATA Spinup hold
 * state.
 */
#define	HBA_SASSTATE_SATASPINUP    0x03
/* The phy is attached to a Port Selector (see SATA-2.6). */
#define	HBA_SASSTATE_SATAPORTSEL    0x04
#define	HBA_SASSPEED_1_5GBIT	    0x08 /*  1.5 GBit/sec */
#define	HBA_SASSPEED_3GBIT	    0x09 /*  3 GBit/sec */
#define	HBA_SASSPEED_6GBIT	    0x0a /*  6 GBit/sec */
#define	HBA_SASSPEED_12GBIT	    0x0b /* 12 GBit/sec */

/* SM-HBA  6.5.5 SAS Phy Attribute */
typedef struct SMHBA_SAS_Phy {
	HBA_UINT8	    PhyIdentifier;
	HBA_SASPHYSPEED	    NegotiatedLinkRate;
	HBA_SASPHYSPEED	    ProgrammedMinLinkRate;
	HBA_SASPHYSPEED	    HardwareMinLinkRate;
	HBA_SASPHYSPEED	    ProgrammedMaxLinkRate;
	HBA_SASPHYSPEED	    HardwareMaxLinkRate;
	HBA_WWN		    domainPortWWN;
} SMHBA_SAS_PHY, *PSMHBA_SAS_PHY;

/* SM-HBA 6.6.1.1 Protocol Statistics Data Declarations */
/* Statistical counters for FC-4, SSP, STP, SMP protocols */
typedef struct SMHBA_ProtocolStatistics {
	HBA_INT64	    SecondsSinceLastReset;
	HBA_INT64	    InputRequests;
	HBA_INT64	    OutputRequests;
	HBA_INT64	    ControlRequests;
	HBA_INT64	    InputMegabytes;
	HBA_INT64	    OutputMegabytes;
} SMHBA_PROTOCOLSTATISTICS, *PSMHBA_PROTOCOLSTATISTICS;

/* SM-HBA 6.6.2.1 Port Statistics Data Declarations */
typedef struct SMHBA_PortStatistics {
	HBA_INT64	    SecondsSinceLastReset;
	HBA_INT64	    TxFrames;
	HBA_INT64	    TxWords;
	HBA_INT64	    RxFrames;
	HBA_INT64	    RxWords;
}SMHBA_PORTSTATISTICS, *PSMHBA_PORTSTATISTICS;

/* SM-HBA 6.6.2.2 SAS Phy Statistics Data Declaration */
typedef struct SMHBA_SASPhyStatistics {
	HBA_INT64	    SecondsSinceLastReset;
	HBA_INT64	    TxFrames;
	HBA_INT64	    TxWords;
	HBA_INT64	    RxFrames;
	HBA_INT64	    RxWords;
	HBA_INT64	    InvalidDwordCount;
	HBA_INT64	    RunningDisparityErrorCount;
	HBA_INT64	    LossofDwordSyncCount;
	HBA_INT64	    PhyResetProblemCount;
} SMHBA_SASPHYSTATISTICS, *PSMHBA_SASPHYSTATISTICS;

/* SM-HBA 6.6.2.4 FC Phy Statistics Data Declaration */
/* Statistical counters for FC-0, FC-1, and FC-2 */
typedef struct SMHBA_FCPhyStatistics {
	HBA_INT64	    SecondsSinceLastReset;
	HBA_INT64	    TxFrames;
	HBA_INT64	    TxWords;
	HBA_INT64	    RxFrames;
	HBA_INT64	    RxWords;
	HBA_INT64	    LIPCount;
	HBA_INT64	    NOSCount;
	HBA_INT64	    ErrorFrames;
	HBA_INT64	    DumpedFrames;
	HBA_INT64	    LinkFailureCount;
	HBA_INT64	    LossOfSyncCount;
	HBA_INT64	    LossOfSignalCount;
	HBA_INT64	    PrimitiveSeqProtocolErrCount;
	HBA_INT64	    InvalidTxWordCount;
	HBA_INT64	    InvalidCRCCount;
}SMHBA_FCPHYSTATISTICS, *PSMHBA_FCPHYSTATISTICS;

/* SM-HBA 6.6.2.1 Phy Statistics Data Declaration */
typedef union SMHBA_PhyStatistics {
	SMHBA_SASPHYSTATISTICS	*SASPhyStatistics;
	SMHBA_FCPHYSTATISTICS	*FCPhyStatistics;
} SMHBA_PHYSTATISTICS, *PSMHBA_PHYSTATISTICS;

/* SM-HBA 6.7.1.1 SMHBA_BIND_CAPABILITY */
typedef HBA_UINT32 SMHBA_BIND_CAPABILITY;
#define	SMHBA_CAN_BIND_TO_WWPN 0x0001
#define	SMHBA_CAN_BIND_TO_LUID 0x0002
#define	SMHBA_CAN_BIND_ANY_LUNS 0x0400
#define	SMHBA_CAN_BIND_AUTOMAP 0x0800

/* SM-HBA 6.7.1.2 SMHBA_BIND_TYPE */
typedef HBA_UINT32 SMHBA_BIND_TYPE;
#define	SMHBA_BIND_TO_WWPN 0x0001
#define	SMHBA_BIND_TO_LUID 0x0002

/* SM-HBA 6.7.1.3 SMHBA_ScsiId */
typedef struct SMHBA_ScsiId {
	char	    OSDeviceName[256];
	HBA_UINT32  ScsiBusNumber;
	HBA_UINT32  ScsiTargetNumber;
	HBA_UINT32  ScsiOSLun;
} SMHBA_SCSIID, *PSMHBA_SCSIID;

/* SM-HBA 6.7.1.4 SMHBA_LUID */
typedef struct SMHBA_LUID {
	char	    buffer[256];
} SMHBA_LUID, *PSMHBA_LUID;

/* SM-HBA 6.7.1.5 SMHBA_PORTLUN */
typedef struct SMHBA_PORTLUN {
	HBA_WWN		    PortWWN;
	HBA_WWN		    domainPortWWN;
	SMHBA_SCSILUN	    TargetLun;
} SMHBA_PORTLUN, *PSMHBA_PORTLUN;

/* SM-HBA 6.7.1.6 Composite types */
typedef struct SMHBA_ScsiEntry {
	SMHBA_SCSIID ScsiId;
	SMHBA_PORTLUN PortLun;
	SMHBA_LUID LUID;
} SMHBA_SCSIENTRY, *PSMHBA_SCSIENTRY;

typedef struct SMHBA_TargetMapping {
	HBA_UINT32 NumberOfEntries;
	SMHBA_SCSIENTRY entry[1]; /* Variable length array */
} SMHBA_TARGETMAPPING, *PSMHBA_TARGETMAPPING;

typedef struct SMHBA_BindingEntry {
	SMHBA_BIND_TYPE	type;
	SMHBA_SCSIID	ScsiId;
	SMHBA_PORTLUN	PortLun;
	SMHBA_LUID	LUID;
	HBA_STATUS	Status;
} SMHBA_BINDINGENTRY, *PSMHBA_BINDINGENTRY;

typedef struct SMHBA_Binding {
	HBA_UINT32	    NumberOfEntries;
	SMHBA_BINDINGENTRY  entry[1]; /* Variable length array */
} SMHBA_BINDING, *PSMHBA_BINDING;

/* SM-HBA 6.9.5 Library Attribute Data Declarations */
typedef struct SMHBA_LibraryAttributes {
	char	    LibPath[256];
	char	    VName[256];
	char	    VVersion[256];
	struct {
		int	tm_mday;    /* day of the month - [1 - 31] */
		int	tm_mon;	    /* months since January - [0 - 11] */
		int	tm_year;    /* years since 1900 */
	} build_date;
} SMHBA_LIBRARYATTRIBUTES, *PSMHBA_LIBRARYATTRIBUTES;

/* SM-HBA 6.8.1 Asynchronous Event Data Declarations */
#define	HBA_EVENT_PORT_BROADCAST_CHANGE 0x205
#define	HBA_EVENT_PORT_BROADCAST_SES	0x208
#define	HBA_EVENT_PORT_BROADCAST_D24_0  0x206
#define	HBA_EVENT_PORT_BROADCAST_D27_4  0x207
#define	HBA_EVENT_PORT_BROADCAST_D01_4  0x209
#define	HBA_EVENT_PORT_BROADCAST_D04_7  0x20A
#define	HBA_EVENT_PORT_BROADCAST_D16_7  0x20B
#define	HBA_EVENT_PORT_BROADCAST_D29_7  0x20C
#define	HBA_EVENT_PORT_ALL		0x2FF

/* SM-HBA specific entry points. */

HBA_UINT32 SMHBA_GetVersion();

HBA_UINT32 SMHBA_GetWrapperLibraryAttributes(
	SMHBA_LIBRARYATTRIBUTES *attributes
);

HBA_UINT32 SMHBA_GetVendorLibraryAttributes(
	HBA_UINT32		adapter_index,
	SMHBA_LIBRARYATTRIBUTES *attributes
);

HBA_STATUS SMHBA_GetAdapterAttributes(
	HBA_HANDLE handle,
	SMHBA_ADAPTERATTRIBUTES *pAdapterAttributes
);

HBA_STATUS SMHBA_GetNumberOfPorts(
	HBA_HANDLE handle,
	HBA_UINT32 *numberofports
);

HBA_STATUS SMHBA_GetPortType(
	HBA_HANDLE handle,
	HBA_UINT32 portindex,
	HBA_PORTTYPE *porttype
);

HBA_STATUS SMHBA_GetAdapterPortAttributes(
	HBA_HANDLE handle,
	HBA_UINT32 portindex,
	SMHBA_PORTATTRIBUTES *portattributes
);

HBA_STATUS SMHBA_GetDiscoveredPortAttributes(
	HBA_HANDLE handle,
	HBA_UINT32 portindex,
	HBA_UINT32 discoveredportindex,
	SMHBA_PORTATTRIBUTES *porattributes
);

HBA_STATUS SMHBA_GetPortAttributesByWWN(
	HBA_HANDLE handle,
	HBA_WWN portWWN,
	HBA_WWN domainPortWWN,
	SMHBA_PORTATTRIBUTES *portattributes
);

HBA_STATUS SMHBA_GetPortAttributesByWWN(
	HBA_HANDLE handle,
	HBA_WWN portWWN,
	HBA_WWN domainPortWWN,
	SMHBA_PORTATTRIBUTES *portattributes
);

HBA_STATUS SMHBA_GetFCPhyAttributes(
	HBA_HANDLE handle,
	HBA_UINT32 portindex,
	HBA_UINT32 phyindex,
	SMHBA_FC_PHY *phytype
);

HBA_STATUS SMHBA_GetSASPhyAttributes(
	HBA_HANDLE handle,
	HBA_UINT32 portindex,
	HBA_UINT32 phyindex,
	SMHBA_SAS_PHY *phytype
);

HBA_STATUS SMHBA_GetProtocolStatistics(
	HBA_HANDLE handle,
	HBA_UINT32 portindex,
	HBA_UINT32 protocoltype,
	SMHBA_PROTOCOLSTATISTICS *pProtocolStatistics
);

HBA_STATUS SMHBA_GetPhyStatistics(
	HBA_HANDLE handle,
	HBA_UINT32 portindex,
	HBA_UINT32 phyindex,
	SMHBA_PHYSTATISTICS *pPhyStatistics
);

HBA_STATUS SMHBA_SendTEST(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN destWWN,
	HBA_UINT32 destFCID,
	void *pReqBuffer,
	HBA_UINT32 ReqBufferSize
);

HBA_STATUS SMHBA_SendECHO(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN destWWN,
	HBA_UINT32 destFCID,
	void *pReqBuffer,
	HBA_UINT32 ReqBufferSize,
	void *pRspBuffer,
	HBA_UINT32 *pRspBufferSize
);

HBA_UINT32 SMHBA_SendSMPPassThru(
	HBA_HANDLE handle,
	HBA_WWN hbaportWWN,
	HBA_WWN destportWWN,
	HBA_WWN domainPortWWN,
	void *pReqBuffer,
	HBA_UINT32 ReqBufferSize,
	void *pRspBuffer,
	HBA_UINT32 *pRspBufferSize
);

HBA_STATUS SMHBA_GetBindingCapability(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN domainPortWWN,
	SMHBA_BIND_CAPABILITY *pFlags
);

HBA_STATUS SMHBA_GetBindingSupport(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN domainPortWWN,
	SMHBA_BIND_CAPABILITY *pFlags
);

HBA_STATUS SMHBA_SetBindingSupport(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN domainPortWWN,
	SMHBA_BIND_CAPABILITY flags
);

HBA_STATUS SMHBA_GetTargetMapping(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN domainPortWWN,
	SMHBA_TARGETMAPPING *pMapping
);

HBA_STATUS SMHBA_GetPersistentBinding(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN domainPortWWN,
	SMHBA_BINDING *binding
);

HBA_STATUS SMHBA_SetPersistentBinding(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN domainPortWWN,
	const SMHBA_BINDING *binding
);

HBA_STATUS SMHBA_RemovePersistentBinding(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN domainPortWWN,
	const SMHBA_BINDING *binding
);

HBA_STATUS SMHBA_RemoveAllPersistentBindings(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN domainPortWWN
);

HBA_STATUS SMHBA_GetLUNStatistics(
	HBA_HANDLE handle,
	const HBA_SCSIID *lunit,
	SMHBA_PROTOCOLSTATISTICS *statistics
);

HBA_STATUS SMHBA_ScsiInquiry(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN discoveredPortWWN,
	HBA_WWN domainPortWWN,
	SMHBA_SCSILUN smhbaLUN,
	HBA_UINT8 CDB_Byte1,
	HBA_UINT8 CDB_Byte2,
	void *pRspBuffer,
	HBA_UINT32 *pRspBufferSize,
	HBA_UINT8 *pScsiStatus,
	void *pSenseBuffer,
	HBA_UINT32 *pSenseBufferSize
);

HBA_STATUS SMHBA_ScsiReportLUNs(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN discoveredPortWWN,
	HBA_WWN domainPortWWN,
	void *pRspBuffer,
	HBA_UINT32 *pRspBufferSize,
	HBA_UINT8 *pScsiStatus,
	void *pSenseBuffer,
	HBA_UINT32 *pSenseBufferSize
);

HBA_STATUS SMHBA_ScsiReadCapacity(
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN discoveredPortWWN,
	HBA_WWN domainPortWWN,
	SMHBA_SCSILUN smhbaLUN,
	void *pRspBuffer,
	HBA_UINT32 *pRspBufferSize,
	HBA_UINT8 *pScsiStatus,
	void *pSenseBuffer,
	HBA_UINT32 *pSenseBufferSize
);

HBA_STATUS SMHBA_RegisterForAdapterAddEvents(
	void (*pCallback) (
		void *pData,
		HBA_WWN portWWN,
		HBA_UINT32 eventType),
	void *pUserData,
	HBA_CALLBACKHANDLE *pCallbackHandle
);

HBA_STATUS SMHBA_RegisterForAdapterEvents(
	void (*pCallback) (
		void *pData,
		HBA_WWN portWWN,
		HBA_UINT32 eventType),
	void *pUserData,
	HBA_HANDLE handle,
	HBA_CALLBACKHANDLE *pCallbackHandle
);

HBA_STATUS SMHBA_RegisterForAdapterPortEvents(
	void (*pCallback) (
		void *pData,
		HBA_WWN portWWN,
		HBA_UINT32 eventType,
		HBA_UINT32 fabricPortID),
	void *pUserData,
	HBA_HANDLE handle,
	HBA_WWN portWWN,
	HBA_UINT32 specificEventType,
	HBA_CALLBACKHANDLE *pCallbackHandle
);

HBA_STATUS SMHBA_RegisterForAdapterPortStatEvents(
	void (*pCallback) (
		void *pData,
		HBA_WWN portWWN,
		HBA_UINT32 protocolType,
		HBA_UINT32 eventType),
	void *pUserData,
	HBA_HANDLE handle,
	HBA_WWN portWWN,
	HBA_UINT32 protocolType,
	SMHBA_PROTOCOLSTATISTICS stats,
	HBA_UINT32 statType,
	HBA_CALLBACKHANDLE *pCallbackHandle
);

HBA_STATUS SMHBA_RegisterForAdapterPhyStatEvents(
	void (*pCallback) (
		void *pData,
		HBA_WWN portWWN,
		HBA_UINT32 phyIndex,
		HBA_UINT32 eventType),
	void *pUserData,
	HBA_HANDLE handle,
	HBA_WWN portWWN,
	HBA_UINT32 phyIndex,
	SMHBA_PHYSTATISTICS stats,
	HBA_UINT32 statType,
	HBA_CALLBACKHANDLE *pCallbackHandle
);

HBA_STATUS SMHBA_RegisterForTargetEvents(
	void (*pCallback) (
		void *pData,
		HBA_WWN hbaPortWWN,
		HBA_WWN discoveredPortWWN,
		HBA_WWN domainPortWWN,
		HBA_UINT32 eventType),
	void *pUserData,
	HBA_HANDLE handle,
	HBA_WWN hbaPortWWN,
	HBA_WWN discoveredPortWWN,
	HBA_WWN domainPortWWN,
	HBA_CALLBACKHANDLE *pCallbackHandle,
	HBA_UINT32 allTargets
);

#ifdef __cplusplus
}
#endif

#endif /* _SMHBAAPI_H_ */
