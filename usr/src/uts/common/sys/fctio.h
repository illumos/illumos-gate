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
#ifndef	_FCTIO_H
#define	_FCTIO_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	FCT_IOCTL			(((uint32_t)'F') << 24)
#define	FCTIO_CMD			(FCT_IOCTL | 2007)
#define	FCTIO_SUB_CMD			('Z' << 8)
#define	FCTIO_ADAPTER_LIST			(FCTIO_SUB_CMD + 0x01)
#define	FCTIO_GET_ADAPTER_ATTRIBUTES		(FCTIO_SUB_CMD + 0x02)
#define	FCTIO_GET_ADAPTER_PORT_ATTRIBUTES	(FCTIO_SUB_CMD + 0x03)
#define	FCTIO_GET_DISCOVERED_PORT_ATTRIBUTES	(FCTIO_SUB_CMD + 0x04)
#define	FCTIO_GET_PORT_ATTRIBUTES		(FCTIO_SUB_CMD + 0x05)
#define	FCTIO_GET_ADAPTER_PORT_STATS		(FCTIO_SUB_CMD + 0x06)
#define	FCTIO_GET_LINK_STATUS			(FCTIO_SUB_CMD + 0x07)
#define	FCTIO_FORCE_LIP				(FCTIO_SUB_CMD + 0x08)

/*
 * fcio_xfer definitions
 */
#define	FCTIO_XFER_NONE		0x00
#define	FCTIO_XFER_READ		0x01
#define	FCTIO_XFER_WRITE	0x02
#define	FCTIO_XFER_RW		(FCTIO_XFER_READ | FCTIO_XFER_WRITE)

typedef struct fctio {
	uint16_t	fctio_xfer;		/* direction */
	uint16_t	fctio_cmd;		/* sub command */
	uint16_t	fctio_flags;		/* flags */
	uint16_t	fctio_cmd_flags;	/* command specific flags */
	uint32_t	fctio_ilen;		/* Input buffer length */
	uint32_t	fctio_olen;		/* Output buffer length */
	uint32_t	fctio_alen;		/* Auxillary buffer length */
	uint32_t	fctio_errno;		/* FC internal error code */
	uint64_t	fctio_ibuf;		/* Input buffer */
	uint64_t	fctio_obuf;		/* Output buffer */
	uint64_t	fctio_abuf;		/* Auxillary buffer */
} fctio_t;

#define	FCT_HBA_LIST_VERSION	1
typedef struct fc_tgt_hba_list {
	uint32_t	version;
	uint32_t	numPorts;
	uint8_t		port_wwn[1][8];
} fc_tgt_hba_list_t;

#define	FCT_HBA_ADAPTER_ATTRIBUTES_VERSION   1
typedef struct fc_tgt_hba_adapter_attributes {
	uint32_t    version;	/* Set to FC_HBA_ADAPTER_ATTRIBUTES_VERSION */
	uint32_t    reserved_1;
	char	    Manufacturer[64];
	char	    SerialNumber[64];
	char	    Model[256];
	char	    ModelDescription[256];
	uint8_t	    NodeWWN[8];
	char	    NodeSymbolicName[256];
	char	    HardwareVersion[256];
	char	    DriverVersion[256];
	char	    OptionROMVersion[256];
	char	    FirmwareVersion[256];
	uint32_t    VendorSpecificID;
	uint32_t    NumberOfPorts;
	char	    DriverName[256];
	uint64_t    reserved_2;
} fc_tgt_hba_adapter_attributes_t;

#define	FCT_HBA_PORT_ATTRIBUTES_VERSION	1
typedef struct fc_tgt_hba_port_attributes {
	uint32_t		version; /* FC_HBA_PORT_ATTRIBUTES_VERSION */
	uint32_t    		reserved_1;
	uint64_t		lastChange;
	uint8_t			NodeWWN[8];
	uint8_t			PortWWN[8];
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
	uint32_t		NumberofDiscoveredPorts;
	uint8_t			FabricName[8];
	uint64_t		reserved_2;
} fc_tgt_hba_port_attributes_t;

#define	FCT_HBA_ADAPTER_PORT_STATS_VERSION   1
typedef struct fc_tgt_hba_adapter_port_stats {
	uint32_t		version; /* FC_HBA_ADAPTER_PORT_STATS_VERSION */
	uint32_t    		reserved_1;
	uint64_t		SecondsSinceLastReset;
	uint64_t		TxFrames;
	uint64_t		TxWords;
	uint64_t		RxFrames;
	uint64_t		RxWords;
	uint64_t		LIPCount;
	uint64_t		NOSCount;
	uint64_t		ErrorFrames;
	uint64_t		DumpedFrames;
	uint64_t		LinkFailureCount;
	uint64_t		LossOfSyncCount;
	uint64_t		LossOfSignalCount;
	uint64_t		PrimitiveSeqProtocolErrCount;
	uint64_t		InvalidTxWordCount;
	uint64_t		InvalidCRCCount;
	uint64_t		reserved_2;
} fc_tgt_hba_adapter_port_stats_t;

/*
 * Constant values derived from T11 FC-HBA
 */
#define	FC_HBA_PORTTYPE_UNKNOWN		1	/* Unknown */
#define	FC_HBA_PORTTYPE_OTHER		2	/* Other */
#define	FC_HBA_PORTTYPE_NOTPRESENT	3	/* Not present */
#define	FC_HBA_PORTTYPE_NPORT		5	/* Fabric  */
#define	FC_HBA_PORTTYPE_NLPORT		6	/* Public Loop */
#define	FC_HBA_PORTTYPE_FLPORT		7
#define	FC_HBA_PORTTYPE_FPORT		8	/* Fabric Port */
#define	FC_HBA_PORTTYPE_EPORT		9	/* Fabric expansion port */
#define	FC_HBA_PORTTYPE_GPORT		10	/* Generic Fabric Port */
#define	FC_HBA_PORTTYPE_LPORT		20	/* Private Loop */
#define	FC_HBA_PORTTYPE_PTP		21	/* Point to Point */

#define	FC_HBA_PORTSTATE_UNKNOWN	1	/* Unknown */
#define	FC_HBA_PORTSTATE_ONLINE		2	/* Operational */
#define	FC_HBA_PORTSTATE_OFFLINE	3	/* User Offline */
#define	FC_HBA_PORTSTATE_BYPASSED	4	/* Bypassed */
#define	FC_HBA_PORTSTATE_DIAGNOSTICS	5	/* In diagnostics mode */
#define	FC_HBA_PORTSTATE_LINKDOWN	6	/* Link Down */
#define	FC_HBA_PORTSTATE_ERROR		7	/* Port Error */
#define	FC_HBA_PORTSTATE_LOOPBACK	8	/* Loopback */

/*
 * HBA/Port attributes tracked for the T11 FC-HBA specification
 */
#define	FC_HBA_PORTSPEED_UNKNOWN	0	/* Unknown - transceiver */
						/* incable of reporting */
#define	FC_HBA_PORTSPEED_1GBIT		1	/* 1 GBit/sec */
#define	FC_HBA_PORTSPEED_2GBIT		2	/* 2 GBit/sec */
#define	FC_HBA_PORTSPEED_10GBIT		4	/* 10 GBit/sec */
#define	FC_HBA_PORTSPEED_4GBIT		8	/* 4 GBit/sec */
#define	FC_HBA_PORTSPEED_8GBIT		16	/* 8 GBit/sec */
#define	FC_HBA_PORTSPEED_16GBIT		32	/* 16 GBit/sec */
#define	FC_HBA_PORTSPEED_NOT_NEGOTIATED	(1<<15)   /* Speed not established */

#define	FCTIO_SUCCESS			0
#define	FCTIO_FAILURE			1
#define	FCTIO_BADWWN			2
#define	FCTIO_MOREDATA			3
#define	FCTIO_OUTOFBOUNDS		4

/* Sysevent defs */
#define	EC_SUNFC		"EC_sunfc"
#define	ESC_SUNFC_PORT_ATTACH	"ESC_sunfc_port_attach"
#define	ESC_SUNFC_PORT_DETACH	"ESC_sunfc_port_detach"
#define	ESC_SUNFC_PORT_ONLINE	"ESC_sunfc_port_online"
#define	ESC_SUNFC_PORT_OFFLINE	"ESC_sunfc_port_offline"
#define	ESC_SUNFC_PORT_RSCN	"ESC_sunfc_port_rscn"
#define	ESC_SUNFC_TARGET_ADD	"ESC_sunfc_target_add"
#define	ESC_SUNFC_TARGET_REMOVE	"ESC_sunfc_target_remove"

#ifdef	__cplusplus
}
#endif

#endif /* _FCTIO_H */
