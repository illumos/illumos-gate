/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_DFC_H
#define	_EMLXS_DFC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/fibre-channel/fcio.h>
#include <emlxs_fcio.h>

#define	DFC_REV		1

#ifdef DHCHAP_SUPPORT
#undef	DFC_REV
#define	DFC_REV		2  /* DHCHAP_SUPPORT */
#endif /* DHCHAP_SUPPORT */

#undef	DFC_REV
#define	DFC_REV		3  /* NPIV_SUPPORT */


typedef struct dfc
{
	uint32_t	cmd;
	uint32_t	flag;

	void		*buf1;
	uint32_t	buf1_size;
	uint32_t	data1;

	void		*buf2;
	uint32_t	buf2_size;
	uint32_t	data2;

	void		*buf3;
	uint32_t	buf3_size;
	uint32_t	data3;

	void		*buf4;
	uint32_t	buf4_size;
	uint32_t	data4;
} dfc_t;


/*
 * 32 bit varient of dfc_t to be used only in the driver and NOT applications
 */
typedef struct dfc32
{
	uint32_t	cmd;
	uint32_t	flag;

	uint32_t	buf1;
	uint32_t	buf1_size;
	uint32_t	data1;

	uint32_t	buf2;
	uint32_t	buf2_size;
	uint32_t	data2;

	uint32_t	buf3;
	uint32_t	buf3_size;
	uint32_t	data3;

	uint32_t	buf4;
	uint32_t	buf4_size;
	uint32_t	data4;

} dfc32_t;


#ifdef SAN_DIAG_SUPPORT
typedef struct sd_bucket_info
{
	uint16_t	type;
	uint16_t	search_type;
	uint32_t	base;
	uint32_t	step;
	uint16_t	state;
	uint64_t	values[SD_IO_LATENCY_MAX_BUCKETS];
} sd_bucket_info_t;
#endif

/* Valid dfc.dfc_cmd codes  (DFC_REV=1) */
#define	EMLXS_GET_HBAINFO		1
#define	EMLXS_GET_IOINFO		2
#define	EMLXS_GET_LINKINFO		3
#define	EMLXS_GET_NODEINFO		4
#define	EMLXS_GET_EVENTINFO		5
#define	EMLXS_GET_REV			6
#define	EMLXS_GET_DUMPREGION		7
#define	EMLXS_GET_HBASTATS		8
#define	EMLXS_GET_DRVSTATS		9

/* FCIO_SUPPORT */
#define	EMLXS_FCIO_CMD			10

#define	EMLXS_GET_CFG			15
#define	EMLXS_SET_CFG			16
#define	EMLXS_GET_EVENT			17
#define	EMLXS_SET_EVENT			18

#define	EMLXS_SEND_MBOX			20
#define	EMLXS_SEND_ELS			21
#define	EMLXS_SEND_CT			22
#define	EMLXS_SEND_CT_RSP		23
#define	EMLXS_SEND_MENLO		24
#define	EMLXS_SEND_SCSI			25

#define	EMLXS_SET_DIAG			30
#define	EMLXS_LOOPBACK_MODE		31
#define	EMLXS_LOOPBACK_TEST		32
#define	EMLXS_RESET_PORT		33

#define	EMLXS_READ_PCI			40
#define	EMLXS_WRITE_PCI			41
#define	EMLXS_WRITE_FLASH		42
#define	EMLXS_READ_FLASH		43
#define	EMLXS_READ_MEM			44
#define	EMLXS_WRITE_MEM			45
#define	EMLXS_WRITE_CTLREG		46
#define	EMLXS_READ_CTLREG		47


/* NPIV_SUPPORT */
#define	EMLXS_CREATE_VPORT		50
#define	EMLXS_DESTROY_VPORT		51
#define	EMLXS_GET_VPORTINFO		52
#define	EMLXS_NPIV_RESOURCE		53
#define	EMLXS_NPIV_TEST			54

/* DHCHAP_SUPPORT */
#define	EMLXS_INIT_AUTH			60
#define	EMLXS_GET_AUTH_CFG		61
#define	EMLXS_SET_AUTH_CFG		62
#define	EMLXS_GET_AUTH_PASSWORD 	63
#define	EMLXS_SET_AUTH_PASSWORD 	64
#define	EMLXS_GET_AUTH_STATUS		65
#define	EMLXS_GET_AUTH_CFG_TABLE  	66
#define	EMLXS_GET_AUTH_KEY_TABLE  	67

/* SFCT_SUPPORT */
#define	EMLXS_GET_FCTSTAT		70

#define	EMLXS_GET_PERSIST_LINKDOWN	71
#define	EMLXS_SET_PERSIST_LINKDOWN	72

/* FCOE_SUPPORT */
#define	EMLXS_GET_FCOE_FCFLIST		80
#define	EMLXS_SEND_MBOX4		81
#define	EMLXS_RD_BE_FCF			82
#define	EMLXS_SET_BE_DCBX		83
#define	EMLXS_GET_BE_DCBX		84
#define	EMLXS_GET_QOS			85

/* SAN DIAG SUPPORT */
#define	EMLXS_SD_SET_BUCKET		100
#define	EMLXS_SD_START_DATA_COLLECTION  101
#define	EMLXS_SD_STOP_DATA_COLLECTION   102
#define	EMLXS_SD_RESET_DATA_COLLECTION  103
#define	EMLXS_SD_GET_DATA		104
#define	EMLXS_SD_DESTROY_BUCKET		105
#define	EMLXS_SD_GET_BUCKET		106
#define	EMLXS_SD_SET_EVENT		107
#define	EMLXS_SD_GET_EVENT		108



/* EMLXS_SET_AUTH_CFG - flags */
#define	EMLXS_AUTH_CFG_ADD		0
#define	EMLXS_AUTH_CFG_DELETE		1

/* ERROR Codes */
#define	DFC_ERRNO_START			0x200

#define	DFC_SUCCESS		0
#define	DFC_SYS_ERROR		(DFC_ERRNO_START + 1)  /* General system err */
#define	DFC_DRV_ERROR		(DFC_ERRNO_START + 2)  /* General driver err */
#define	DFC_HBA_ERROR		(DFC_ERRNO_START + 3)  /* General HBA err */
#define	DFC_IO_ERROR		(DFC_ERRNO_START + 4)  /* General IO err */

#define	DFC_ARG_INVALID		(DFC_ERRNO_START + 5)  /* Invalid Argument */
#define	DFC_ARG_MISALIGNED	(DFC_ERRNO_START + 6)  /* Misaligned Argument */
#define	DFC_ARG_NULL		(DFC_ERRNO_START + 7)  /* NULL Argument */
#define	DFC_ARG_TOOSMALL	(DFC_ERRNO_START + 8)  /* Argument too small */
#define	DFC_ARG_TOOBIG		(DFC_ERRNO_START + 9)  /* Argument too big */

#define	DFC_COPYIN_ERROR	(DFC_ERRNO_START + 10) /* DDI copyin err */
#define	DFC_COPYOUT_ERROR	(DFC_ERRNO_START + 11) /* DDI copyout err */

#define	DFC_TIMEOUT		(DFC_ERRNO_START + 12) /* Resource timeout */
#define	DFC_SYSRES_ERROR	(DFC_ERRNO_START + 13) /* Out of sys resource */
#define	DFC_DRVRES_ERROR	(DFC_ERRNO_START + 14) /* Out of drv resource */
#define	DFC_HBARES_ERROR	(DFC_ERRNO_START + 15) /* Out of HBA resource */

#define	DFC_OFFLINE_ERROR	(DFC_ERRNO_START + 16) /* Driver offline */
#define	DFC_ONLINE_ERROR	(DFC_ERRNO_START + 17) /* Driver offline */

/* NPIV_SUPPORT */
#define	DFC_NPIV_DISABLED	(DFC_ERRNO_START + 18) /* NPIV disabled */
#define	DFC_NPIV_UNSUPPORTED	(DFC_ERRNO_START + 19) /* NPIV not supported */
#define	DFC_NPIV_ACTIVE		(DFC_ERRNO_START + 20) /* NPIV active */

#define	DFC_NOT_SUPPORTED	(DFC_ERRNO_START + 21) /* Not supported */
#define	DFC_NO_DATA		(DFC_ERRNO_START + 22) /* No Data to return */

/* DHCHAP_SUPPORT */
#define	DFC_AUTH_NOT_CONFIGURED			(DFC_ERRNO_START + 30)
#define	DFC_AUTH_FAILED_NO_SA_FOUND		(DFC_ERRNO_START + 31)
#define	DFC_AUTH_INIT_OK_AUTH_FAILED		(DFC_ERRNO_START + 32)
#define	DFC_AUTH_COMPARE_FAILED			(DFC_ERRNO_START + 33)
#define	DFC_AUTH_WWN_NOT_FOUND			(DFC_ERRNO_START + 34)
#define	DFC_AUTH_PASSWORD_INVALID		(DFC_ERRNO_START + 35)
#define	DFC_AUTH_INVALID_ENTITY			(DFC_ERRNO_START + 36)
#define	DFC_AUTH_ENTITY_NOT_ACTIVE		(DFC_ERRNO_START + 37)
#define	DFC_AUTH_INVALID_OPERATION		(DFC_ERRNO_START + 38)
#define	DFC_AUTH_AUTHENTICATION_GOINGON		(DFC_ERRNO_START + 39)
#define	DFC_AUTH_CREATE_STORKEY_ERROR		(DFC_ERRNO_START + 40)
#define	DFC_AUTH_CREATE_PARMKEY_ERROR		(DFC_ERRNO_START + 41)
#define	DFC_AUTH_CREATE_AUTHKEY_ERROR		(DFC_ERRNO_START + 42)
#define	DFC_AUTH_CREATE_BORDKEY_ERROR		(DFC_ERRNO_START + 43)
#define	DFC_AUTH_AUTHENTICATION_NOT_SUPPORTED	(DFC_ERRNO_START + 44)
#define	DFC_AUTH_AUTHENTICATION_DISABLED	(DFC_ERRNO_START + 45)
#define	DFC_AUTH_CONFIG_NOT_FOUND		(DFC_ERRNO_START + 47)
#define	DFC_AUTH_LOCAL_REMOTE_PWD_EQUAL		(DFC_ERRNO_START + 48)

/* MENLO_SUPPORT */
#define	DFC_INVALID_ADAPTER			(DFC_ERRNO_START + 50)
#define	DFC_RSP_BUF_OVERRUN			(DFC_ERRNO_START + 51)
#define	DFC_LINKDOWN_ERROR			(DFC_ERRNO_START + 52)

/* SAN_DIAG_SUPPORT */
#define	DFC_SD_STAT_START			(DFC_ERRNO_START + 60)

#define	DFC_SD_OK				(DFC_ERRNO_START + 60)
#define	DFC_SD_ERROR_GENERIC			(DFC_ERRNO_START + 61)
#define	DFC_SD_ERROR_INVALID_ARG		(DFC_ERRNO_START + 62)
#define	DFC_SD_ERROR_INVALID_BOARD_ID		(DFC_ERRNO_START + 63)
#define	DFC_SD_ERROR_INVALID_PORT		(DFC_ERRNO_START + 64)
#define	DFC_SD_ERROR_NOT_SUPPORTED		(DFC_ERRNO_START + 65)
#define	DFC_SD_ERROR_CATEGORY_NOT_SUPPORTED	(DFC_ERRNO_START + 66)
#define	DFC_SD_ERROR_SUBCAT_NOT_SUPPORTED	(DFC_ERRNO_START + 67)
#define	DFC_SD_ERROR_MORE_DATA_AVAIL		(DFC_ERRNO_START + 68)
#define	DFC_SD_ERROR_EVENT_ALREADY_REG		(DFC_ERRNO_START + 69)
#define	DFC_SD_ERROR_NO_ACTIVE_REG		(DFC_ERRNO_START + 70)
#define	DFC_SD_ERROR_ARG_MISSING		(DFC_ERRNO_START + 71)
#define	DFC_SD_ERROR_NO_MEM			(DFC_ERRNO_START + 72)
#define	DFC_SD_ERROR_BUCKET_NOT_SET		(DFC_ERRNO_START + 73)
#define	DFC_SD_ERROR_REG_HANDLE			(DFC_ERRNO_START + 74)
#define	DFC_SD_ERROR_INVALID_SEARCH_TYPE	(DFC_ERRNO_START + 75)
#define	DFC_SD_ERROR_FUNCTION_NOT_SUPPORTED	(DFC_ERRNO_START + 76)
#define	DFC_SD_ERROR_OUT_OF_HANDLES		(DFC_ERRNO_START + 77)
#define	DFC_SD_ERROR_LIB_NOT_INIT		(DFC_ERRNO_START + 78)
#define	DFC_SD_ERROR_DATA_COLLECTION_ACTIVE	(DFC_ERRNO_START + 79)
#define	DFC_SD_ERROR_DATA_COLLECTION_NOT_ACTIVE	(DFC_ERRNO_START + 80)


#define	DFC_ERRNO_END				(DFC_ERRNO_START + 128)

typedef struct dfc_hbainfo
{
	char		vpd_serial_num[32];
	char		vpd_part_num[32];
	char		vpd_port_num[20];
	char		vpd_eng_change[32];
	char		vpd_manufacturer[80];
	char		vpd_model[80];
	char		vpd_model_desc[256];
	char		vpd_prog_types[256];
	char		vpd_id[80];

	uint32_t	flags;
#define	HBA_FLAG_SBUS			0x00000001
#define	HBA_FLAG_OFFLINE		0x00000002
#define	HBA_FLAG_NPIV			0x00000004 /* Supports NPIV */
#define	HBA_FLAG_DHCHAP			0x00000008 /* Supports DHCHAP */
#define	HBA_FLAG_DYN_WWN		0x00000010 /* Supports Dynamic WWN */
#define	HBA_FLAG_E2E_AUTH		0x00000020 /* Supports E2E Auth */
#define	HBA_FLAG_TARGET_MODE		0x00000040 /* Supports Target Mode */
#define	HBA_FLAG_TARGET_MODE_ENA	0x00000080 /* Target Mode is enabled */
#define	HBA_FLAG_SAN_DIAG		0x00000100 /* Supports SAN Diags */
#define	HBA_FLAG_FCOE			0x00000200 /* Supports FCoE */
#define	HBA_FLAG_PERSISTLINK		0x00000400 /* Supports Persist Link */
						    /* Up/Down */
#define	HBA_FLAG_EXT_MBOX		0x00000800 /* Supports Ext MBOX cmds */

	uint32_t	device_id;
	uint32_t	vendor_id;
	uint32_t	ports;
	uint32_t	port_index;

	uint32_t	vpi_max;
	uint32_t	vpi_high;

	char		wwnn[8];
	char		snn[256];

	char		wwpn[8];
	char		spn[256];

	char		fw_version[256];
	char		fcode_version[256];
	char		boot_version[256];

	uint32_t	biuRev;
	uint32_t	smRev;
	uint32_t	smFwRev;
	uint32_t	endecRev;
	uint32_t	rBit;
	uint32_t	fcphHigh;
	uint32_t	fcphLow;
	uint32_t	feaLevelHigh;
	uint32_t	feaLevelLow;

	uint32_t	kern_rev;
	char		kern_name[32];
	uint32_t	stub_rev;
	char		stub_name[32];
	uint32_t	sli1_rev;
	char		sli1_name[32];
	uint32_t	sli2_rev;
	char		sli2_name[32];
	uint32_t	sli3_rev;
	char		sli3_name[32];
	uint32_t	sli4_rev;
	char		sli4_name[32];
	uint32_t	sli_mode;

	uint32_t	drv_instance;
	char		drv_label[64];
	char		drv_module[64];
	char		drv_name[32];
	char		drv_version[64];
	char		drv_revision[64];

	char		hostname[32];
	char		os_devname[256];

	uint32_t	port_id;
	uint32_t	port_type;
	uint32_t	port_state;
	uint32_t	topology;
	uint32_t	hard_alpa;
	uint8_t		alpa_count;
	uint8_t		alpa_map[128];

	uint32_t	supported_cos;
	uint32_t	supported_types[8];
	uint32_t	active_types[8];

	uint32_t	supported_speeds;
	uint32_t	port_speed;
	uint32_t	max_frame_size;

	uint8_t		fabric_wwpn[8];
	uint8_t		fabric_wwnn[8];
	uint32_t	node_count;

	uint8_t		pci_function_number;
	uint8_t		pci_device_number;
	uint8_t		pci_bus_number;
} dfc_hbainfo_t;



typedef struct fc_class
{
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		classValid:1;		/* FC Word 0, bit 31 */
	uint8_t		intermix:1;		/* FC Word 0, bit 30 */
	uint8_t		stackedXparent:1;	/* FC Word 0, bit 29 */
	uint8_t		stackedLockDown:1;	/* FC Word 0, bit 28 */
	uint8_t		seqDelivery:1;		/* FC Word 0, bit 27 */
	uint8_t		word0Reserved1:3;	/* FC Word 0, bit 24:26 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		word0Reserved1:3;	/* FC Word 0, bit 24:26 */
	uint8_t		seqDelivery:1;		/* FC Word 0, bit 27 */
	uint8_t		stackedLockDown:1;	/* FC Word 0, bit 28 */
	uint8_t		stackedXparent:1;	/* FC Word 0, bit 29 */
	uint8_t		intermix:1;		/* FC Word 0, bit 30 */
	uint8_t		classValid:1;		/* FC Word 0, bit 31 */
#endif
	uint8_t		word0Reserved2;		/* FC Word 0, bit 16:23 */
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		iCtlXidReAssgn:2;	/* FC Word 0, Bit 14:15 */
	uint8_t		iCtlInitialPa:2;	/* FC Word 0, bit 12:13 */
	uint8_t		iCtlAck0capable:1;	/* FC Word 0, bit 11 */
	uint8_t		iCtlAckNcapable:1;	/* FC Word 0, bit 10 */
	uint8_t		word0Reserved3:2;	/* FC Word 0, bit  8: 9 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		word0Reserved3:2;	/* FC Word 0, bit  8: 9 */
	uint8_t		iCtlAckNcapable:1;	/* FC Word 0, bit 10 */
	uint8_t		iCtlAck0capable:1;	/* FC Word 0, bit 11 */
	uint8_t		iCtlInitialPa:2;	/* FC Word 0, bit 12:13 */
	uint8_t		iCtlXidReAssgn:2;	/* FC Word 0, Bit 14:15 */
#endif
	uint8_t		word0Reserved4;		/* FC Word 0, bit  0: 7 */
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		rCtlAck0capable:1;	/* FC Word 1, bit 31 */
	uint8_t		rCtlAckNcapable:1;	/* FC Word 1, bit 30 */
	uint8_t		rCtlXidInterlck:1;	/* FC Word 1, bit 29 */
	uint8_t		rCtlErrorPolicy:2;	/* FC Word 1, bit 27:28 */
	uint8_t		word1Reserved1:1;	/* FC Word 1, bit 26 */
	uint8_t		rCtlCatPerSeq:2;	/* FC Word 1, bit 24:25 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		rCtlCatPerSeq:2;	/* FC Word 1, bit 24:25 */
	uint8_t		word1Reserved1:1;	/* FC Word 1, bit 26 */
	uint8_t		rCtlErrorPolicy:2;	/* FC Word 1, bit 27:28 */
	uint8_t		rCtlXidInterlck:1;	/* FC Word 1, bit 29 */
	uint8_t		rCtlAckNcapable:1;	/* FC Word 1, bit 30 */
	uint8_t		rCtlAck0capable:1;	/* FC Word 1, bit 31 */
#endif
	uint8_t		word1Reserved2;		/* FC Word 1, bit 16:23 */
	uint8_t		rcvDataSizeMsb;		/* FC Word 1, bit  8:15 */
	uint8_t		rcvDataSizeLsb;		/* FC Word 1, bit  0: 7 */

	uint8_t		concurrentSeqMsb;	/* FC Word 2, bit 24:31 */
	uint8_t		concurrentSeqLsb;	/* FC Word 2, bit 16:23 */
	uint8_t		EeCreditSeqMsb;		/* FC Word 2, bit  8:15 */
	uint8_t		EeCreditSeqLsb;		/* FC Word 2, bit  0: 7 */

	uint8_t		openSeqPerXchgMsb;	/* FC Word 3, bit 24:31 */
	uint8_t		openSeqPerXchgLsb;	/* FC Word 3, bit 16:23 */
	uint8_t		word3Reserved1;		/* Fc Word 3, bit  8:15 */
	uint8_t		word3Reserved2;		/* Fc Word 3, bit  0: 7 */
} fc_class_t;

typedef struct fc_csp
{
	uint8_t  fcphHigh;		/* FC Word 0, byte 0 */
	uint8_t  fcphLow;		/* FC Word 0, byte 1 */
	uint8_t  bbCreditMsb;		/* FC Word 0, byte 2 */
	uint8_t  bbCreditlsb;		/* FC Word 0, byte 3 */

#ifdef EMLXS_BIG_ENDIAN
	uint16_t increasingOffset:1;	/* FC Word 1, bit 31 */
	uint16_t randomOffset:1;	/* FC Word 1, bit 30 */
	uint16_t word1Reserved2:1;	/* FC Word 1, bit 29 */
	uint16_t fPort:1;		/* FC Word 1, bit 28 */
	uint16_t altBbCredit:1;		/* FC Word 1, bit 27 */
	uint16_t edtovResolution:1;	/* FC Word 1, bit 26 */
	uint16_t multicast:1;		/* FC Word 1, bit 25 */
	uint16_t broadcast:1;		/* FC Word 1, bit 24 */

	uint16_t huntgroup:1;		/* FC Word 1, bit 23 */
	uint16_t simplex:1;		/* FC Word 1, bit 22 */
	uint16_t word1Reserved1:3;	/* FC Word 1, bit 21:19 */
	uint16_t dhd:1;	/* FC Word 1, bit 18 */
	uint16_t contIncSeqCnt:1;	/* FC Word 1, bit 17 */
	uint16_t payloadlength:1;	/* FC Word 1, bit 16 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t broadcast:1;		/* FC Word 1, bit 24 */
	uint16_t multicast:1;		/* FC Word 1, bit 25 */
	uint16_t edtovResolution:1;	/* FC Word 1, bit 26 */
	uint16_t altBbCredit:1;		/* FC Word 1, bit 27 */
	uint16_t fPort:1;		/* FC Word 1, bit 28 */
	uint16_t word1Reserved2:1;	/* FC Word 1, bit 29 */
	uint16_t randomOffset:1;	/* FC Word 1, bit 30 */
	uint16_t increasingOffset:1;	/* FC Word 1, bit 31 */

	uint16_t payloadlength:1;	/* FC Word 1, bit 16 */
	uint16_t contIncSeqCnt:1;	/* FC Word 1, bit 17 */
	uint16_t dhd:1;			/* FC Word 1, bit 18 */
	uint16_t word1Reserved1:3;	/* FC Word 1, bit 21:19 */
	uint16_t simplex:1;		/* FC Word 1, bit 22 */
	uint16_t huntgroup:1;		/* FC Word 1, bit 23 */
#endif

	uint8_t  bbRcvSizeMsb;		/* FC Word 1, byte 2 */
	uint8_t  bbRcvSizeLsb;		/* FC Word 1, byte 3 */

	union
	{
		struct
		{
			uint8_t word2Reserved1;		/* FC Word 2 byte 0 */
			uint8_t totalConcurrSeq;	/* FC Word 2 byte 1 */
			uint8_t roByCategoryMsb;	/* FC Word 2 byte 2 */
			uint8_t roByCategoryLsb;	/* FC Word 2 byte 3 */
		} nPort;

		uint32_t r_a_tov;			/* RATOV (Big Endian) */
	} w2;

	uint32_t e_d_tov;	/* E_D_TOV must be in B.E. format */
} fc_csp_t;


typedef struct fc_sparm
{
	fc_csp_t	csp;

	uint8_t		wwpn[8];
	uint8_t		wwnn[8];

	fc_class_t	cls1;
	fc_class_t	cls2;
	fc_class_t	cls3;
	fc_class_t	cls4;

	uint8_t		vendorVersion[16];
} fc_sparm_t;


typedef struct dfc_node
{
	uint32_t	port_id;
	uint32_t	rpi;
	uint32_t	xri;
	uint32_t	flags;

#define	PORT_FLAG_FCP_TARGET	0x00000001
#define	PORT_FLAG_FCP_INI	0x00000002
#define	PORT_FLAG_FCP2		0x00000004
#define	PORT_FLAG_IP		0x00000008
#define	PORT_FLAG_VPORT		0x00000010

#define	PORT_FLAG_DFC_STATE_VALID	0x00000020
#define	PORT_FLAG_DFC_STATE		0xF0000000

	fc_sparm_t	sparm;

} dfc_node_t;


typedef struct dfc_hbastats
{
	uint32_t	tx_frame_cnt;
	uint32_t	rx_frame_cnt;
	uint32_t	tx_kbyte_cnt;
	uint32_t	rx_kbyte_cnt;
	uint32_t	tx_seq_cnt;
	uint32_t	rx_seq_cnt;
	uint32_t	orig_exch_cnt;
	uint32_t	resp_exch_cnt;
	uint32_t	pbsy_cnt;
	uint32_t	fbsy_cnt;
	uint32_t	link_failure_cnt;
	uint32_t	loss_sync_cnt;
	uint32_t	loss_signal_cnt;
	uint32_t	seq_error_cnt;
	uint32_t	inval_tx_word_cnt;
	uint32_t	crc_error_cnt;
	uint32_t	seq_timeout_cnt;
	uint32_t	elastic_overrun_cnt;
	uint32_t	arb_timeout_cnt;
	uint32_t	rx_buf_credit;
	uint32_t	rx_buf_cnt;
	uint32_t	tx_buf_credit;
	uint32_t	tx_buf_cnt;
	uint32_t	EOFa_cnt;
	uint32_t	EOFdti_cnt;
	uint32_t	EOFni_cnt;
	uint32_t	SOFf_cnt;
	uint32_t	link_event_tag;
	uint32_t	last_reset_time;
	uint32_t	topology;
	uint32_t	port_type;
	uint32_t	link_speed;
} dfc_hbastats_t;


typedef struct dfc_drvstats
{
	uint32_t	LinkUp;
	uint32_t	LinkDown;
	uint32_t	LinkEvent;
	uint32_t	LinkMultiEvent;

	uint32_t	MboxIssued;
	uint32_t	MboxCompleted; /* = MboxError + MbxGood */
	uint32_t	MboxGood;
	uint32_t	MboxError;
	uint32_t	MboxBusy;
	uint32_t	MboxInvalid;

	uint32_t	IocbIssued[4];
	uint32_t	IocbReceived[4];
	uint32_t	IocbTxPut[4];
	uint32_t	IocbTxGet[4];
	uint32_t	IocbRingFull[4];

	uint32_t	IntrEvent[8];
#define	RESV_INTR	7
#define	ERATT_INTR	6
#define	MBATT_INTR	5
#define	LKATT_INTR	4
#define	R3ATT_INTR	3
#define	R2ATT_INTR	2
#define	R1ATT_INTR	1
#define	R0ATT_INTR	0

	uint32_t	FcpIssued;
	uint32_t	FcpCompleted; /* FcpGood + FcpError */
	uint32_t	FcpGood;
	uint32_t	FcpError;

	uint32_t	FcpEvent; /* FcpStray + FcpComplete */
	uint32_t	FcpStray;

	uint32_t	ElsEvent; /* ElsStray + ElsComplete (cmd + rsp) */
	uint32_t	ElsStray;

	uint32_t	ElsCmdIssued;
	uint32_t	ElsCmdCompleted; /* ElsCmdGood + ElsCmdError */
	uint32_t	ElsCmdGood;
	uint32_t	ElsCmdError;

	uint32_t	ElsRspIssued;
	uint32_t	ElsRspCompleted;

	uint32_t	ElsRcvEvent; /* ElsRcvError + ElsRcvDrop + ElsCmdRcv */
	uint32_t	ElsRcvError;
	uint32_t	ElsRcvDropped;
	uint32_t	ElsCmdReceived; /* ElsRscnRcv + ElsPlogiRcv + ... */
	uint32_t	ElsRscnReceived;
	uint32_t	ElsPlogiReceived;
	uint32_t	ElsPrliReceived;
	uint32_t	ElsPrloReceived;
	uint32_t	ElsLogoReceived;
	uint32_t	ElsAdiscReceived;
	uint32_t	ElsGenReceived;

	uint32_t	CtEvent; /* CtStray + CtCmdComplete + CtRspComplete */
	uint32_t	CtStray;

	uint32_t	CtCmdIssued;
	uint32_t	CtCmdCompleted; /* CtCmdGood + CtCmdError */
	uint32_t	CtCmdGood;
	uint32_t	CtCmdError;

	uint32_t	CtRspIssued;
	uint32_t	CtRspCompleted;

	uint32_t	CtRcvEvent; /* CtRcvError + CtRcvDropp + CtCmdRcv */
	uint32_t	CtRcvError;
	uint32_t	CtRcvDropped;
	uint32_t	CtCmdReceived;

	uint32_t	IpEvent; /* IpStray + IpSeqComplete + IpBcastComplete */
	uint32_t	IpStray;

	uint32_t	IpSeqIssued;
	uint32_t	IpSeqCompleted; /* IpSeqGood + IpSeqError */
	uint32_t	IpSeqGood;
	uint32_t	IpSeqError;

	uint32_t	IpBcastIssued;
	uint32_t	IpBcastCompleted; /* IpBcastGood + IpBcastError */
	uint32_t	IpBcastGood;
	uint32_t	IpBcastError;

	uint32_t	IpRcvEvent; /* IpDrop + IpSeqRcv + IpBcastRcv */
	uint32_t	IpDropped;
	uint32_t	IpSeqReceived;
	uint32_t	IpBcastReceived;

	uint32_t	IpUbPosted;
	uint32_t	ElsUbPosted;
	uint32_t	CtUbPosted;

#if (DFC_REV >= 2)
	uint32_t	IocbThrottled;
	uint32_t	ElsAuthReceived;
#endif
} dfc_drvstats_t;

#ifdef SFCT_SUPPORT
/*
 * FctP2IOXcnt will count IOs by their fcpDL. Counters
 * are for buckets of various power of 2 sizes.
 * Bucket 0  <  512  > 0
 * Bucket 1  >= 512  < 1024
 * Bucket 2  >= 1024 < 2048
 * Bucket 3  >= 2048 < 4096
 * Bucket 4  >= 4096 < 8192
 * Bucket 5  >= 8192 < 16K
 * Bucket 6  >= 16K  < 32K
 * Bucket 7  >= 32K  < 64K
 * Bucket 8  >= 64K  < 128K
 * Bucket 9  >= 128K < 256K
 * Bucket 10 >= 256K < 512K
 * Bucket 11 >= 512K < 1MB
 * Bucket 12 >= 1MB  < 2MB
 * Bucket 13 >= 2MB  < 4MB
 * Bucket 14 >= 4MB  < 8MB
 * Bucket 15 >= 8MB
 */
#define	DFC_TGTPORT_STAT_VERSION	1
#define	MAX_TGTPORT_IOCNT		16
typedef struct dfc_tgtport_stat
{
	uint8_t		Version;
	uint8_t		Reserved[7];

	/* IO counters */
	uint64_t	FctP2IOWcnt[MAX_TGTPORT_IOCNT]; /* Writes */
	uint64_t	FctP2IORcnt[MAX_TGTPORT_IOCNT]; /* Reads  */
	uint64_t	FctIOCmdCnt;			/* Other, ie TUR */
	uint64_t	FctCmdReceived;			/* total I/O */
	uint64_t	FctReadBytes;			/* total read bytes */
	uint64_t	FctWriteBytes;			/* total write bytes */

	/* IOCB handling counters */
	uint64_t	FctEvent;			/* FctStray + FctCmpl */
	uint64_t	FctCompleted;			/* FctCmpl (Good+Err) */
	uint64_t 	FctCmplGood;

	uint32_t	FctCmplError;
	uint32_t	FctStray;

	/* Fct event counters */
	uint32_t	FctRcvDropped;
	uint32_t	FctOverQDepth;
	uint32_t	FctOutstandingIO;
	uint32_t	FctFailedPortRegister;
	uint32_t	FctPortRegister;
	uint32_t	FctPortDeregister;

	uint32_t	FctAbortSent;
	uint32_t	FctNoBuffer;
	uint32_t	FctScsiStatusErr;
	uint32_t	FctScsiQfullErr;
	uint32_t	FctScsiResidOver;
	uint32_t	FctScsiResidUnder;
	uint32_t	FctScsiSenseErr;

	/* Additional info */
	uint32_t	FctLinkState;
} dfc_tgtport_stat_t;
#endif /* SFCT_SUPPORT */

/* DFC_REV >= 3 */
typedef struct dfc_vportinfo
{
	uint32_t	flags;
#define	VPORT_CONFIG		0x00000001
#define	VPORT_ENABLED		0x00000002
#define	VPORT_BOUND		0x00000004
#define	VPORT_IP		0x00000008
#define	VPORT_RESTRICTED	0x00000010	/* login restricted */

	uint32_t	vpi;
	uint32_t	port_id;
	uint8_t		wwpn[8];
	uint8_t		wwnn[8];

	char		snn[256];
	char		spn[256];

	uint32_t	ulp_statec;
} dfc_vportinfo_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_DFC_H */
