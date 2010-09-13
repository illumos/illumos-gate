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

#ifndef	_FCIO_H
#define	_FCIO_H


#include <sys/note.h>
#include <sys/fibre-channel/fc_types.h>
#include <sys/fibre-channel/fc_appif.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ioctl definitions
 */
#define	FCTIO				('F'<< 8)

/*
 * New ioctl definitions
 */
#define	FCIO_CMD			(FCTIO | 1998)
#define	FCIO_SUB_CMD			('Z' << 8)
#define	FCIO_GET_NUM_DEVS		(FCIO_SUB_CMD + 0x01)
#define	FCIO_GET_DEV_LIST		(FCIO_SUB_CMD + 0x02)
#define	FCIO_GET_SYM_PNAME		(FCIO_SUB_CMD + 0x03)
#define	FCIO_GET_SYM_NNAME		(FCIO_SUB_CMD + 0x04)
#define	FCIO_SET_SYM_PNAME		(FCIO_SUB_CMD + 0x05)
#define	FCIO_SET_SYM_NNAME		(FCIO_SUB_CMD + 0x06)
#define	FCIO_GET_LOGI_PARAMS		(FCIO_SUB_CMD + 0x07)
#define	FCIO_DEV_LOGIN			(FCIO_SUB_CMD + 0x08)
#define	FCIO_DEV_LOGOUT			(FCIO_SUB_CMD + 0x09)
#define	FCIO_GET_STATE			(FCIO_SUB_CMD + 0x0A)
#define	FCIO_DEV_REMOVE			(FCIO_SUB_CMD + 0x0B)
#define	FCIO_GET_FCODE_REV		(FCIO_SUB_CMD + 0x0C)
#define	FCIO_GET_FW_REV			(FCIO_SUB_CMD + 0x0D)
#define	FCIO_GET_DUMP_SIZE		(FCIO_SUB_CMD + 0x0E)
#define	FCIO_FORCE_DUMP			(FCIO_SUB_CMD + 0x0F)
#define	FCIO_GET_DUMP			(FCIO_SUB_CMD + 0x10)
#define	FCIO_GET_TOPOLOGY		(FCIO_SUB_CMD + 0x11)
#define	FCIO_RESET_LINK			(FCIO_SUB_CMD + 0x12)
#define	FCIO_RESET_HARD			(FCIO_SUB_CMD + 0x13)
#define	FCIO_RESET_HARD_CORE		(FCIO_SUB_CMD + 0x14)
#define	FCIO_DIAG			(FCIO_SUB_CMD + 0x15)
#define	FCIO_NS				(FCIO_SUB_CMD + 0x16)
#define	FCIO_DOWNLOAD_FW		(FCIO_SUB_CMD + 0x17)
#define	FCIO_GET_HOST_PARAMS		(FCIO_SUB_CMD + 0x18)
#define	FCIO_LINK_STATUS		(FCIO_SUB_CMD + 0x19)
#define	FCIO_DOWNLOAD_FCODE		(FCIO_SUB_CMD + 0x1A)
#define	FCIO_GET_NODE_ID		(FCIO_SUB_CMD + 0x1B)
#define	FCIO_SET_NODE_ID		(FCIO_SUB_CMD + 0x1C)
#define	FCIO_SEND_NODE_ID		(FCIO_SUB_CMD + 0x1D)

/*
 * IOCTLs to handle T11's FC-HBA library
 */
#define	FCIO_GET_ADAPTER_ATTRIBUTES	(FCIO_SUB_CMD + 0x1E)
#define	FCIO_GET_OTHER_ADAPTER_PORTS	(FCIO_SUB_CMD + 0x1F)
#define	FCIO_GET_ADAPTER_PORT_ATTRIBUTES    (FCIO_SUB_CMD + 0x20)
#define	FCIO_GET_DISCOVERED_PORT_ATTRIBUTES (FCIO_SUB_CMD + 0x21)
#define	FCIO_GET_PORT_ATTRIBUTES	(FCIO_SUB_CMD + 0x22)
#define	FCIO_GET_ADAPTER_PORT_STATS	(FCIO_SUB_CMD + 0x23)
#define	FCIO_GET_ADAPTER_PORT_NPIV_ATTRIBUTES   (FCIO_SUB_CMD + 0x24)
#define	FCIO_CREATE_NPIV_PORT		(FCIO_SUB_CMD + 0x25)
#define	FCIO_GET_NPIV_ATTRIBUTES	(FCIO_SUB_CMD + 0x26)
#define	FCIO_GET_DISCOVERED_NPIV_ATTRIBUTES	(FCIO_SUB_CMD + 0x27)
#define	FCIO_GET_NPIV_PORT_LIST		(FCIO_SUB_CMD + 0x28)
#define	FCIO_DELETE_NPIV_PORT		(FCIO_SUB_CMD + 0x29)
#define	FCIO_NPIV_GET_ADAPTER_ATTRIBUTES	(FCIO_SUB_CMD + 0x2a)


/*
 * Fixed diag_codes for FCIO_DIAG. These is supported by all FCAs.
 * No FCA should define ioctls in this range.
 */
#define	FCIO_DIAG_PORT_DISABLE		(FCIO_SUB_CMD + 0x80)
#define	FCIO_DIAG_PORT_ENABLE		(FCIO_SUB_CMD + 0x81)

/* cmd_flags for FCIO_LINK_STATUS ioctl */
#define	FCIO_CFLAGS_RLS_DEST_NPORT	0x0000
#define	FCIO_CFLAGS_RLS_DEST_FPORT	0x0001

/*
 * Note about fc_port_dev_t structure : The dev_did.priv_lilp_posit field will
 * return the lilp map position of the port for diagnostics to use.
 * It is important to note that dev_did.priv_lilp_posit field will only have
 * valid loop position for Private Loop devices ONLY and the value
 * contained in this field for other topologies will be undetermined.
 */
typedef struct fc_port_dev {
	uchar_t		dev_dtype;		/* SCSI device type */
	uint32_t	dev_type[8];		/* protocol specific */
	uint32_t	dev_state;		/* port state */
	fc_portid_t	dev_did;		/* Destination Identifier */
	fc_hardaddr_t	dev_hard_addr;		/* Hard address */
	la_wwn_t	dev_pwwn;		/* port WWN */
	la_wwn_t	dev_nwwn;		/* node WWN */
} fc_port_dev_t;

#if defined(_SYSCALL32)

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct fc_port_dev32 {
	uchar_t		dev_dtype;		/* SCSI device type */
	uint32_t	dev_type[8];		/* protocol specific */
	uint32_t	dev_state;		/* port state */
	fc_portid_t	dev_did;		/* Destination Identifier */
	fc_hardaddr_t	dev_hard_addr;		/* Hard address */
	la_wwn_t	dev_pwwn;		/* port WWN */
	la_wwn_t	dev_nwwn;		/* node WWN */
} fc_port_dev32_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif	/* _SYSCALL32 */

typedef struct fc_port_dev fc_ns_map_entry_t;

/*
 * fcio_xfer definitions
 */
#define	FCIO_XFER_NONE		0x00
#define	FCIO_XFER_READ		0x01
#define	FCIO_XFER_WRITE		0x02
#define	FCIO_XFER_RW		(FCIO_XFER_READ | FCIO_XFER_WRITE)

typedef struct fcio {
	uint16_t	fcio_xfer;	/* direction */
	uint16_t	fcio_cmd;	/* sub command */
	uint16_t	fcio_flags;	/* flags */
	uint16_t	fcio_cmd_flags;	/* command specific flags */
	size_t		fcio_ilen;	/* Input buffer length */
	caddr_t		fcio_ibuf;	/* Input buffer */
	size_t		fcio_olen;	/* Output buffer length */
	caddr_t		fcio_obuf;	/* Output buffer */
	size_t		fcio_alen;	/* Auxillary buffer length */
	caddr_t		fcio_abuf;	/* Auxillary buffer */
	int		fcio_errno;	/* FC internal error code */
} fcio_t;

/*
 * T11 FC-HBA exchange structures
 */
#define	FC_HBA_LIST_VERSION		    1
typedef struct fc_hba_list {
	uint32_t		version;    /* Set to FC_HBA_LIST_VERSION */
	uint32_t		numAdapters;
	uint64_t		reserved;
	char			hbaPaths[1][MAXPATHLEN]; /* numAdapters long */
} fc_hba_list_t;

#define	FC_HBA_NPIV_PORT_LIST_VERSION	1
typedef struct fc_hba_npiv_port_list {
	uint32_t		version;
	uint32_t		numAdapters;
	uint64_t		reserved;
	char			hbaPaths[1][MAXPATHLEN];
} fc_hba_npiv_port_list_t;

#define	FC_HBA_NPIV_ATTRIBUTES_VERSION	1
typedef struct fc_hba_npiv_attributes {
	uint32_t		version;
	la_wwn_t		NodeWWN;
	la_wwn_t		PortWWN;
	fc_hba_state_change_t	lastChange;
} fc_hba_npiv_attributes_t;

#define	FC_HBA_PORT_NPIV_ATTRIBUTES_VERSION	1
typedef struct fc_hba_port_npiv_attributes {
	uint32_t		version;
	int			npivflag;
	fc_hba_state_change_t	lastChange;
	la_wwn_t		NodeWWN;
	la_wwn_t		PortWWN;
	uint32_t		MaxNumberOfNPIVPorts;
	uint32_t		NumberOfNPIVPorts;
} fc_hba_port_npiv_attributes_t;

#define	FC_HBA_SINGLE_VERSION		    1
typedef struct fc_hba_single {
	uint32_t		version;    /* Set to FC_HBA_SINGLE_VERSION */
	uint64_t		reserved;
	char			hbaPath[MAXPATHLEN];
} fc_hba_single_t;

#define	FC_HBA_ADAPTER_ATTRIBUTES_VERSION   1
typedef struct fc_hba_adapter_attributes {
	uint32_t    version;	/* Set to FC_HBA_ADAPTER_ATTRIBUTES_VERSION */
	char	    Manufacturer[64];
	char	    SerialNumber[64];
	char	    Model[256];
	char	    ModelDescription[256];
	la_wwn_t    NodeWWN;
	char	    NodeSymbolicName[256];
	char	    HardwareVersion[256];
	char	    DriverVersion[256];
	char	    OptionROMVersion[256];
	char	    FirmwareVersion[256];
	uint32_t    VendorSpecificID;
	uint32_t    NumberOfPorts;
	char	    DriverName[256];
	uint64_t    reserved;
} fc_hba_adapter_attributes_t;

#if defined(_SYSCALL32)

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct fc_hba_adapter_attributes32 {
	uint32_t    version;	/* Set to FC_HBA_ADAPTER_ATTRIBUTES_VERSION */
	char	    Manufacturer[64];
	char	    SerialNumber[64];
	char	    Model[256];
	char	    ModelDescription[256];
	la_wwn_t    NodeWWN;
	char	    NodeSymbolicName[256];
	char	    HardwareVersion[256];
	char	    DriverVersion[256];
	char	    OptionROMVersion[256];
	char	    FirmwareVersion[256];
	uint32_t    VendorSpecificID;
	uint32_t    NumberOfPorts;
	char	    DriverName[256];
	uint64_t    reserved;
} fc_hba_adapter_attributes32_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif	/* defined(_SYSCALL32) */

#define	FC_HBA_PORT_ATTRIBUTES_VERSION	    1
typedef struct fc_hba_port_attributes {
	uint32_t		version; /* FC_HBA_PORT_ATTRIBUTES_VERSION */
	fc_hba_state_change_t	lastChange;
	minor_t			fp_minor;
	la_wwn_t		NodeWWN;
	la_wwn_t		PortWWN;
	uint32_t		PortFcId;
	uint32_t		PortType;
	uint32_t		PortState;
	uint32_t		PortSupportedClassofService;
	uint8_t			PortSupportedFc4Types[32];
	uint8_t			PortActiveFc4Types[32];
	char			PortSymbolicName[256];
	uint32_t		PortSupportedSpeed;
	uint32_t		PortSpeed;
	uint32_t		PortMaxFrameSize;
	la_wwn_t		FabricName;
	uint32_t		NumberofDiscoveredPorts;
	uint64_t		reserved;
} fc_hba_port_attributes_t;

#if defined(_SYSCALL32)

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct fc_hba_port_attributes32 {
	uint32_t		version; /* FC_HBA_PORT_ATTRIBUTES_VERSION */
	fc_hba_state_change_t	lastChange;
	minor_t			fp_minor;
	la_wwn_t		NodeWWN;
	la_wwn_t		PortWWN;
	uint32_t		PortFcId;
	uint32_t		PortType;
	uint32_t		PortState;
	uint32_t		PortSupportedClassofService;
	uint8_t			PortSupportedFc4Types[32];
	uint8_t			PortActiveFc4Types[32];
	char			PortSymbolicName[256];
	uint32_t		PortSupportedSpeed;
	uint32_t		PortSpeed;
	uint32_t		PortMaxFrameSize;
	la_wwn_t		FabricName;
	uint32_t		NumberofDiscoveredPorts;
	uint64_t		reserved;
} fc_hba_port_attributes32_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif	/* defined(_SYSCALL32) */

#define	FC_HBA_ADAPTER_PORT_STATS_VERSION   1
typedef struct fc_hba_adapter_port_stats {
	uint32_t	    version; /* FC_HBA_ADAPTER_PORT_STATS_VERSION */
	uint64_t	    SecondsSinceLastReset;
	uint64_t	    TxFrames;
	uint64_t	    TxWords;
	uint64_t	    RxFrames;
	uint64_t	    RxWords;
	uint64_t	    LIPCount;
	uint64_t	    NOSCount;
	uint64_t	    ErrorFrames;
	uint64_t	    DumpedFrames;
	uint64_t	    LinkFailureCount;
	uint64_t	    LossOfSyncCount;
	uint64_t	    LossOfSignalCount;
	uint64_t	    PrimitiveSeqProtocolErrCount;
	uint64_t	    InvalidTxWordCount;
	uint64_t	    InvalidCRCCount;
	uint64_t	    reserved;
} fc_hba_adapter_port_stats_t;


/*
 * Constant values derived from T11 FC-HBA
 */
#define	FC_HBA_PORTTYPE_UNKNOWN		1   /* Unknown */
#define	FC_HBA_PORTTYPE_OTHER		2   /* Other */
#define	FC_HBA_PORTTYPE_NOTPRESENT	3   /* Not present */
#define	FC_HBA_PORTTYPE_NPORT		5   /* Fabric  */
#define	FC_HBA_PORTTYPE_NLPORT		6   /* Public Loop */
#define	FC_HBA_PORTTYPE_FLPORT		7
#define	FC_HBA_PORTTYPE_FPORT		8   /* Fabric Port */
#define	FC_HBA_PORTTYPE_EPORT		9   /* Fabric expansion port */
#define	FC_HBA_PORTTYPE_GPORT		10  /* Generic Fabric Port */
#define	FC_HBA_PORTTYPE_LPORT		20  /* Private Loop */
#define	FC_HBA_PORTTYPE_PTP		21  /* Point to Point */

#define	FC_HBA_PORTSTATE_UNKNOWN	1   /* Unknown */
#define	FC_HBA_PORTSTATE_ONLINE		2   /* Operational */
#define	FC_HBA_PORTSTATE_OFFLINE	3   /* User Offline */
#define	FC_HBA_PORTSTATE_BYPASSED	4   /* Bypassed */
#define	FC_HBA_PORTSTATE_DIAGNOSTICS	5   /* In diagnostics mode */
#define	FC_HBA_PORTSTATE_LINKDOWN	6   /* Link Down */
#define	FC_HBA_PORTSTATE_ERROR		7   /* Port Error */
#define	FC_HBA_PORTSTATE_LOOPBACK	8   /* Loopback */



#if defined(_SYSCALL32)
/*
 * 32 bit varient of fcio_t; to be used
 * only in the driver and NOT applications
 */
struct fcio32 {
	uint16_t	fcio_xfer;	/* direction */
	uint16_t	fcio_cmd;	/* sub command */
	uint16_t	fcio_flags;	/* flags */
	uint16_t	fcio_cmd_flags;	/* command specific flags */
	size32_t	fcio_ilen;	/* Input buffer length */
	caddr32_t	fcio_ibuf;	/* Input buffer */
	size32_t	fcio_olen;	/* Output buffer length */
	caddr32_t	fcio_obuf;	/* Output buffer */
	size32_t	fcio_alen;	/* Auxillary buffer length */
	caddr32_t	fcio_abuf;	/* Auxillary buffer */
	int		fcio_errno;	/* FC internal error code */
};

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", fcio32))
#endif /* __lint */

#endif /* _SYSCALL32 */

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", fcio fc_port_dev))
#endif /* __lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _FCIO_H */
