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

#ifndef _EMLXS_DFCLIB_H
#define	_EMLXS_DFCLIB_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_DFC_EVENTS			16
#define	MAX_EMLXS_BRDS			128
#define	MAX_CFG_PARAM 			64
#define	MAX_NODES 				4096

#ifndef MAX_VPORTS
#define	MAX_VPORTS			256
#endif  /* MAX_VPORTS */

#ifdef EMLXS_SPARC
#define	EMLXS_BIG_ENDIAN
#endif	/* EMLXS_SPARC */

#ifdef EMLXS_I386
#define	EMLXS_LITTLE_ENDIAN
#endif	/* EMLXS_I386 */


typedef struct brdinfo
{
	uint32_t a_mem_hi;	/* memory identifier for adapter access */
	uint32_t a_mem_low;	/* memory identifier for adapter access */
	uint32_t a_flash_hi;	/* memory identifier for adapter access */
	uint32_t a_flash_low;	/* memory identifier for adapter access */
	uint32_t a_ctlreg_hi;	/* memory identifier for adapter access */
	uint32_t a_ctlreg_low;	/* memory identifier for adapter access */
	uint32_t a_intrlvl;	/* interrupt level for adapter */
	uint32_t a_pci;		/* PCI identifier (device / vendor id) */
	uint32_t a_busid;	/* identifier of PCI bus adapter is on */
	uint32_t a_devid;	/* identifier of PCI device number */
	uint8_t  a_rsvd1;	/* reserved for future use */
	uint8_t  a_rsvd2;	/* reserved for future use */
	uint8_t  a_siglvl;	/* signal handler used by library */
	uint8_t  a_ddi;		/* identifier device driver instance number */
	uint32_t a_onmask;	/* mask of ONDI primatives supported */
	uint32_t a_offmask;	/* mask of OFFDI primatives supported */
	uint8_t  a_drvrid[16];	/* driver version */
	uint8_t  a_fwname[32];	/* firmware version */
} brdinfo_t;


typedef struct dfc_brdinfo
{
	uint32_t a_mem_hi;	/* memory identifier for adapter access */
	uint32_t a_mem_low;	/* memory identifier for adapter access */
	uint32_t a_flash_hi;	/* memory identifier for adapter access */
	uint32_t a_flash_low;	/* memory identifier for adapter access */
	uint32_t a_ctlreg_hi;	/* memory identifier for adapter access */
	uint32_t a_ctlreg_low;	/* memory identifier for adapter access */
	uint32_t a_intrlvl;	/* interrupt level for adapter */
	uint32_t a_pci;		/* PCI identifier (device / vendor id) */
	uint32_t a_busid;	/* identifier of PCI bus adapter is on */
	uint32_t a_devid;	/* identifier of PCI device number */
	uint8_t  a_pciFunc;	/* identifier of PCI function number */
	uint8_t  a_siglvl;	/* signal handler used by library */
	uint16_t a_ddi;		/* identifier device driver instance number */
	uint32_t a_onmask;	/* mask of ONDI primatives supported */
	uint32_t a_offmask;	/* mask of OFFDI primatives supported */
	uint8_t  a_drvrid[16];	/* driver version */
	uint8_t  a_fwname[32];	/* firmware version */
	uint8_t  a_wwpn[8];	/* worldwide portname */
} dfc_brdinfo_t;


#define	PADDR_LO(addr)	((uint32_t)(((uint64_t)(addr)) & 0xffffffff))
#define	PADDR_HI(addr)	((uint32_t)(((uint64_t)(addr)) >> 32))
#define	PADDR(high, low)	((uint64_t)((((uint64_t)(high)) << 32) \
					| (((uint64_t)(low)) & 0xffffffff)))

typedef struct ulp_bde
{
	uint32_t	bdeAddress;

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	bdeReserved:4;
	uint32_t	bdeAddrHigh:4;
	uint32_t	bdeSize:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	bdeSize:24;
	uint32_t	bdeAddrHigh:4;
	uint32_t	bdeReserved:4;
#endif
} ulp_bde_t;

typedef struct ulp_bde64
{
	union
	{
		uint32_t	w;
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	bdeFlags:8;
			uint32_t	bdeSize:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	bdeSize:24;
			uint32_t	bdeFlags:8;
#endif

#define	BUFF_USE_RSVD		0x01 /* bdeFlags */
#define	BUFF_USE_INTRPT		0x02 /* Not Implemented with LP6000 */
#define	BUFF_USE_CMND		0x04 /* Optional, 1=cmd/rsp 0=data buffer */
#define	BUFF_USE_RCV		0x08 /* ""  "",  1=rcv buffer, 0=xmit buffer */
#define	BUFF_TYPE_32BIT		0x10 /* ""  "",  1=32 bit addr 0=64 bit addr */
#define	BUFF_TYPE_SPECIAL	0x20 /* Not Implemented with LP6000  */
#define	BUFF_TYPE_BDL		0x40 /* Optional,  may be set in BDL */
#define	BUFF_TYPE_INVALID	0x80 /* ""  "" */
		} f;
	} tus;

	uint32_t	addrLow;
	uint32_t	addrHigh;
} ulp_bde64_t;


/* ==== Mailbox Commands ==== */
#define	MBX_SHUTDOWN		0x00
#define	MBX_LOAD_SM		0x01
#define	MBX_READ_NV		0x02
#define	MBX_WRITE_NV		0x03
#define	MBX_RUN_BIU_DIAG	0x04
#define	MBX_INIT_LINK		0x05
#define	MBX_DOWN_LINK		0x06
#define	MBX_CONFIG_LINK		0x07
#define	MBX_PART_SLIM		0x08
#define	MBX_CONFIG_RING		0x09
#define	MBX_RESET_RING		0x0A
#define	MBX_READ_CONFIG		0x0B
#define	MBX_READ_RCONFIG	0x0C
#define	MBX_READ_SPARM		0x0D
#define	MBX_READ_STATUS		0x0E
#define	MBX_READ_RPI		0x0F
#define	MBX_READ_XRI		0x10
#define	MBX_READ_REV		0x11
#define	MBX_READ_LNK_STAT	0x12
#define	MBX_REG_LOGIN		0x13
#define	MBX_UNREG_LOGIN		0x14
#define	MBX_READ_LA		0x15
#define	MBX_CLEAR_LA		0x16
#define	MBX_DUMP_MEMORY		0x17
#define	MBX_DUMP_CONTEXT	0x18
#define	MBX_RUN_DIAGS		0x19
#define	MBX_RESTART		0x1A
#define	MBX_UPDATE_CFG		0x1B
#define	MBX_DOWN_LOAD		0x1C
#define	MBX_DEL_LD_ENTRY	0x1D
#define	MBX_RUN_PROGRAM		0x1E
#define	MBX_SET_MASK		0x20
#define	MBX_SET_SLIM		0x21
#define	MBX_UNREG_D_ID		0x23
#define	MBX_KILL_BOARD		0x24
#define	MBX_CONFIG_FARP		0x25
#define	MBX_WRITE_VPARMS	0x32
#define	MBX_LOAD_AREA		0x81
#define	MBX_RUN_BIU_DIAG64	0x84
#define	MBX_CONFIG_PORT		0x88
#define	MBX_READ_SPARM64	0x8D
#define	MBX_READ_RPI64		0x8F
#define	MBX_CONFIG_MSI		0x90
#define	MBX_REG_LOGIN64		0x93
#define	MBX_READ_LA64		0x95
#define	MBX_FLASH_WR_ULA	0x98
#define	MBX_SET_DEBUG		0x99
#define	MBX_SLI_CONFIG		0x9B
#define	MBX_LOAD_EXP_ROM	0x9C
#define	MBX_REQUEST_FEATURES	0x9D
#define	MBX_RESUME_RPI		0x9E
#define	MBX_REG_VFI		0x9F
#define	MBX_REG_FCFI		0xA0
#define	MBX_UNREG_VFI		0xA1
#define	MBX_UNREG_FCFI		0xA2
#define	MBX_INIT_VFI		0xA3
#define	MBX_INIT_VPI		0xA4
#define	MBX_ACCESS_VDATA	0xA5
#define	MBX_MAX_CMDS		0xA6
#define	MBX_SLI2_CMD_MASK	0x80


typedef struct read_sparm_var
{
	uint32_t	rsvd1;
	uint32_t	rsvd2;
	union
	{
		ulp_bde_t	sp;
		ulp_bde64_t	sp64;
	} un;
} read_sparm_var_t;


typedef struct read_rev_var
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	cv:1;
	uint32_t	rr:1;
	uint32_t	rsvd1:29;
	uint32_t	rv:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rv:1;
	uint32_t	rsvd1:29;
	uint32_t	rr:1;
	uint32_t	cv:1;
#endif
	uint32_t	biuRev;
	uint32_t	smRev;
	union
	{
		uint32_t	smFwRev;
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint8_t		ProgType;
			uint8_t		ProgId;
			uint16_t	ProgVer:4;
			uint16_t	ProgRev:4;
			uint16_t	ProgFixLvl:2;
			uint16_t	ProgDistType:2;
			uint16_t	DistCnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	DistCnt:4;
			uint16_t	ProgDistType:2;
			uint16_t	ProgFixLvl:2;
			uint16_t	ProgRev:4;
			uint16_t	ProgVer:4;
			uint8_t		ProgId;
			uint8_t		ProgType;
#endif
		} b;
	} un;
	uint32_t	endecRev;

#ifdef EMLXS_BIG_ENDIAN
	uint8_t		feaLevelHigh;
	uint8_t		feaLevelLow;
	uint8_t		fcphHigh;
	uint8_t		fcphLow;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		fcphLow;
	uint8_t		fcphHigh;
	uint8_t		feaLevelLow;
	uint8_t		feaLevelHigh;
#endif
	uint32_t	postKernRev;
	uint32_t	opFwRev;
	uint8_t		opFwName[16];
	uint32_t	sli1FwRev;
	uint8_t		sli1FwName[16];
	uint32_t	sli2FwRev;
	uint8_t		sli2FwName[16];
} read_rev_var_t;


typedef struct dump_var
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd:25;
	uint32_t	ra:1;
	uint32_t	co:1;
	uint32_t	cv:1;
	uint32_t	type:4;

	uint32_t	entry_index:16;
	uint32_t	region_id:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	type:4;
	uint32_t	cv:1;
	uint32_t	co:1;
	uint32_t	ra:1;
	uint32_t	rsvd:25;

	uint32_t	region_id:16;
	uint32_t	entry_index:16;
#endif
	uint32_t	base_adr;
	uint32_t	word_cnt;
	uint32_t	resp_offset;
} dump_var_t;


typedef struct dump4_var
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	link:8;
	uint32_t	rsvd:20;
	uint32_t	type:4;

	uint32_t	entry_index:16;
	uint32_t	region_id:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	type:4;
	uint32_t	rsvd:20;
	uint32_t	link:8;

	uint32_t	region_id:16;
	uint32_t	entry_index:16;
#endif
	uint32_t	available_cnt;
	uint32_t	addrLow;
	uint32_t	addrHigh;
	uint32_t	rsp_cnt;
} dump4_var_t;


typedef struct update_cfg
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd2:16;
	uint32_t	proc_type:8;
	uint32_t	rsvd1:1;
	uint32_t	Abit:1;
	uint32_t	DIbit:1;
	uint32_t	Vbit:1;
	uint32_t	req_type:4;
#define	INIT_REGION	1
#define	UPDATE_DATA	2
#define	CLEAN_UP_CFG	3
	uint32_t	entry_len:16;
	uint32_t	region_id:16;
#endif

#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	req_type:4;
#define	INIT_REGION	1
#define	UPDATE_DATA	2
#define	CLEAN_UP_CFG	3
	uint32_t	Vbit:1;
	uint32_t	DIbit:1;
	uint32_t	Abit:1;
	uint32_t	rsvd1:1;
	uint32_t	proc_type:8;
	uint32_t	rsvd2:16;

	uint32_t	region_id:16;
	uint32_t	entry_len:16;
#endif

	uint32_t	rsp_info;
	uint32_t	byte_len;
	uint32_t	cfg_data;
} update_cfg_var_t;



typedef struct
{
	union {
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint8_t domain;
			uint8_t port_number;
			uint8_t subsystem;
			uint8_t opcode;
#else
			uint8_t opcode;
			uint8_t subsystem;
			uint8_t port_number;
			uint8_t domain;
#endif
			uint32_t timeout;
			uint32_t request_length;
			uint32_t rsvd0;
		}req;

		struct {
#ifdef EMLXS_BIG_ENDIAN
			/* dw 0 */
			uint8_t domain;
			uint8_t rsvd0;
			uint8_t subsystem;
			uint8_t opcode;

			/* dw 1 */
			uint16_t rsvd1;
			uint8_t additional_status;
			uint8_t status;
#else
			/* dw 0 */
			uint8_t opcode;
			uint8_t subsystem;
			uint8_t rsvd0;
			uint8_t domain;

			/* dw 1 */
			uint8_t status;
			uint8_t additional_status;
			uint16_t rsvd1;
#endif

			uint32_t rsp_length;
			uint32_t actual_rsp_length;
		}rsp;
		uint32_t dw[4];
	}u0;
} common_hdr_t;

typedef struct get_oem_attrs
{
	common_hdr_t hdr;
	union {
		struct {
			uint32_t rsvd0;
		}req;

		struct {
			uint8_t emulex_serial_number[12];
			uint8_t oem_serial_number[24];
			uint32_t oem_personality_mgmt_word;
#ifdef EMLXS_BIG_ENDIAN
			uint8_t rsvd[3];
			uint8_t oem_current_personality;
#else
			uint8_t oem_current_personality;
			uint8_t rsvd[3];
#endif

		}rsp;
	}params;

} get_oem_attrs_t;


typedef struct read_write_flashrom {
	common_hdr_t hdr;
	uint32_t	flash_op_code;
	uint32_t	flash_op_type;
	uint32_t	data_buffer_size;
	uint32_t	data_offset;
	uint8_t		data_buffer[4];
} read_write_flashrom_t;


typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	special:8;		/* word 1 */
	uint32_t	reserved2:16;		/* word 1 */
	uint32_t	sge_cnt:5;		/* word 1 */
	uint32_t	reserved1:2;		/* word 1 */
	uint32_t	embedded:1;		/* word 1 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	embedded:1;		/* word 1 */
	uint32_t	reserved1:2;		/* word 1 */
	uint32_t	sge_cnt:5;		/* word 1 */
	uint32_t	reserved2:16;		/* word 1 */
	uint32_t	special:8;		/* word 1 */
#endif
	uint32_t	payload_length;		/* word 2 */
	uint32_t	tag_low;		/* word 3 */
	uint32_t	tag_hi;			/* word 4 */
	uint32_t	reserved3;		/* word 5 */

} be_req_header_t;

typedef struct
{
	be_req_header_t	be;

	union
	{
		get_oem_attrs_t		varOemAttrs;
		read_write_flashrom_t	varFlashRom;
	} un;

} sli_config_var_t;


typedef struct read_cfg_var
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	cr:1;
	uint32_t	ci:1;
	uint32_t	cr_delay:6;
	uint32_t	cr_count:8;
	uint32_t	InitBBC:8;
	uint32_t	MaxBBC:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	MaxBBC:8;
	uint32_t	InitBBC:8;
	uint32_t	cr_count:8;
	uint32_t	cr_delay:6;
	uint32_t	ci:1;
	uint32_t	cr:1;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	topology:8;
	uint32_t	myDid:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	myDid:24;
	uint32_t	topology:8;
#endif
	/* Defines for topology (defined previously) */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	AR:1;
	uint32_t	IR:1;
	uint32_t	rsvd1:29;
	uint32_t	ack0:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	ack0:1;
	uint32_t	rsvd1:29;
	uint32_t	IR:1;
	uint32_t	AR:1;
#endif
	uint32_t	edtov;
	uint32_t	arbtov;
	uint32_t	ratov;
	uint32_t	rttov;
	uint32_t	altov;
	uint32_t	lmt;

#define	LMT_1GB_CAPABLE  0x0004
#define	LMT_2GB_CAPABLE	 0x0008
#define	LMT_4GB_CAPABLE	 0x0040
#define	LMT_8GB_CAPABLE	 0x0080
#define	LMT_10GB_CAPABLE 0x0100

	uint32_t	rsvd2;
	uint32_t	rsvd3;
	uint32_t	max_xri;
	uint32_t	max_iocb;
	uint32_t	max_rpi;
	uint32_t	avail_xri;
	uint32_t	avail_iocb;
	uint32_t	avail_rpi;
	uint32_t	default_rpi;
} read_cfg_var_t;


typedef struct read_log_var
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	type:8;
	uint32_t	byte_count:8;
	uint32_t	write:1;
	uint32_t	resv:3;
	uint32_t	offset:12;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	offset:12;
	uint32_t	resv:3;
	uint32_t	write:1;
	uint32_t	byte_count:8;
	uint32_t	type:8;
#endif

	uint32_t	data;
} read_log_var_t;


typedef struct log_status_var
{

#ifdef EMLXS_BIG_ENDIAN
	uint16_t	split_log_next;
	uint16_t	log_next;

	uint32_t	size;

	uint32_t	format:8;
	uint32_t	resv2:22;
	uint32_t	log_level:1;
	uint32_t	split_log:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	log_next;
	uint16_t	split_log_next;

	uint32_t	size;

	uint32_t	split_log:1;
	uint32_t	log_level:1;
	uint32_t	resv2:22;
	uint32_t	format:8;
#endif

	uint32_t	offset;
} log_status_var_t;


typedef struct read_evt_log_var
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	read_log:1;
	uint32_t	clear_log:1;
	uint32_t	mbox_rsp:1;
	uint32_t	resv:28;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	resv:28;
	uint32_t	mbox_rsp:1;
	uint32_t	clear_log:1;
	uint32_t	read_log:1;
#endif

	uint32_t	offset;

	union
	{
		ulp_bde_t	sp;
		ulp_bde64_t	sp64;
	} un;
} read_evt_log_var_t;


typedef struct dfc_mailbox
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	mbxStatus;
	uint8_t		mbxCommand;
	uint8_t		mbxReserved:6;
	uint8_t		mbxHc:1;
	uint8_t		mbxOwner:1;	/* Low order bit first word */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		mbxOwner:1;	/* Low order bit first word */
	uint8_t		mbxHc:1;
	uint8_t		mbxReserved:6;
	uint8_t		mbxCommand;
	uint16_t	mbxStatus;
#endif

	union
	{
		uint32_t		varWords[31];
		read_sparm_var_t	varRdSparm;
		read_rev_var_t		varRdRev;
		read_cfg_var_t		varRdCfg;
		dump_var_t		varDmp;
		read_log_var_t		varRdLog;
		log_status_var_t	varLogStat;
		read_evt_log_var_t	varRdEvtLog;

	} un;
} dfc_mailbox_t;


typedef struct dfc_mailbox4
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	mbxStatus;
	uint8_t		mbxCommand;
	uint8_t		mbxReserved:6;
	uint8_t		mbxHc:1;
	uint8_t		mbxOwner:1;	/* Low order bit first word */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		mbxOwner:1;	/* Low order bit first word */
	uint8_t		mbxHc:1;
	uint8_t		mbxReserved:6;
	uint8_t		mbxCommand;
	uint16_t	mbxStatus;
#endif

	union
	{
		uint32_t		varWords[63];
		dump4_var_t		varDmp;
		update_cfg_var_t	varUpdateCfg;
		sli_config_var_t	varSLIConfig;
	} un;
} dfc_mailbox4_t;




/* Config Region 23 Records */

typedef struct tlv_fcoe {
	uint8_t		type;
	uint8_t		length;
	uint8_t		version;
#define	TLV_FCOE_VER	1

	uint8_t		fip_flags;
#define	TLV_FCOE_FIP	0x40
#define	TLV_FCOE_VLAN	0x01

	uint8_t		FCMap[3];
	uint8_t		reserved;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd:20;
	uint32_t	VLanId:12;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	VLanId:12;
	uint32_t	rsvd:20;
#endif
} tlv_fcoe_t;


typedef struct tlv_fcfconnectentry {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd1:4;
	uint32_t	VLanId:12;
	uint32_t	rsvd2:7;
	uint32_t	AddrMode:1;
	uint32_t	AddrModePreferred:1;
	uint32_t	AddrModeValid:1;
	uint32_t	VLanValid:1;
	uint32_t	SwitchNameValid:1;
	uint32_t	FabricNameValid:1;
	uint32_t	Primary:1;
	uint32_t	Boot:1;
	uint32_t	Valid:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	Valid:1;
	uint32_t	Boot:1;
	uint32_t	Primary:1;
	uint32_t	FabricNameValid:1;
	uint32_t	SwitchNameValid:1;
	uint32_t	VLanValid:1;
	uint32_t	AddrModeValid:1;
	uint32_t	AddrModePreferred:1;
	uint32_t	AddrMode:1;
	uint32_t	rsvd2:7;
	uint32_t	VLanId:12;
	uint32_t	rsvd1:4;
#endif
	uint8_t		FabricName[8];
	uint8_t		SwitchName[8];
} tlv_fcfconnectentry_t;


#define	MAX_FCFCONNECTLIST_ENTRIES	16
typedef struct tlv_fcfconnectlist {
	uint8_t			type;
	uint8_t			length;
	uint16_t		rsvd;
	tlv_fcfconnectentry_t	entry[MAX_FCFCONNECTLIST_ENTRIES];
} tlv_fcfconnectlist_t;


typedef struct dfc_ioinfo
{
	uint32_t a_mboxCmd;	/* mailbox commands issued */
	uint32_t a_mboxCmpl;	/* mailbox commands completed */
	uint32_t a_mboxErr;	/* mailbox commands completed, error status */
	uint32_t a_iocbCmd;	/* iocb command ring issued */
	uint32_t a_iocbRsp;	/* iocb rsp ring received */
	uint32_t a_adapterIntr;	/* adapter interrupt events */
	uint32_t a_fcpCmd;	/* FCP commands issued */
	uint32_t a_fcpCmpl;	/* FCP command completions received */
	uint32_t a_fcpErr;	/* FCP command completions errors */
	uint32_t a_seqXmit;	/* IP xmit sequences sent */
	uint32_t a_seqRcv;	/* IP sequences received */
	uint32_t a_bcastXmit;	/* cnt of successful xmit bcast cmds issued */
	uint32_t a_bcastRcv;	/* cnt of receive bcast cmds received */
	uint32_t a_elsXmit;	/* cnt of successful ELS req cmds issued */
	uint32_t a_elsRcv;	/* cnt of ELS request commands received */
	uint32_t a_RSCNRcv;	/* cnt of RSCN commands received */
	uint32_t a_seqXmitErr;	/* cnt of unsuccessful xmit bcast cmds issued */
	uint32_t a_elsXmitErr;	/* cnt of unsuccessful ELS req cmds issued  */
	uint32_t a_elsBufPost;	/* cnt of ELS buffers posted to adapter */
	uint32_t a_ipBufPost;	/* cnt of IP buffers posted to adapter */
	uint32_t a_cnt1;	/* generic counter */
	uint32_t a_cnt2;	/* generic counter */
	uint32_t a_cnt3;	/* generic counter */
	uint32_t a_cnt4;	/* generic counter */

} dfc_ioinfo_t;


typedef struct dfc_linkinfo
{
	uint32_t	a_linkEventTag;
	uint32_t	a_linkUp;
	uint32_t	a_linkDown;
	uint32_t	a_linkMulti;
	uint32_t	a_DID;
	uint8_t		a_topology;
	uint8_t		a_linkState;
	uint8_t		a_alpa;
	uint8_t		a_alpaCnt;
	uint8_t		a_alpaMap[128];
	uint8_t		a_wwpName[8];
	uint8_t		a_wwnName[8];
} dfc_linkinfo_t;

/* values for a_topology */
#define	LNK_LOOP		0x1
#define	LNK_PUBLIC_LOOP		0x2
#define	LNK_FABRIC		0x3
#define	LNK_PT2PT		0x4
#define	LNK_MENLO_MAINTENANCE	0x5

/* values for a_linkState */
#define	LNK_DOWN		0x1
#define	LNK_UP			0x2
#define	LNK_FLOGI		0x3
#define	LNK_DISCOVERY		0x4
#define	LNK_REDISCOVERY		0x5
#define	LNK_READY		0x6
#define	LNK_DOWN_PERSIST	0x7


typedef struct dfc_traceinfo
{
	uint8_t		a_event;
	uint8_t		a_cmd;
	uint16_t	a_status;
	uint32_t	a_information;
} dfc_traceinfo_t;


typedef struct dfc_cfgparam
{
	char		a_string[32];
	uint32_t	a_low;
	uint32_t	a_hi;
	uint32_t	a_default;
	uint32_t	a_current;
	uint16_t	a_flag;
#define	CFG_EXPORT		0x1	/* Export this parameter to end user */
#define	CFG_IGNORE		0x2	/* Ignore this parameter */
#define	CFG_APPLICABLE		0x4	/* Applicable to this HBA */
#define	CFG_COMMON		0x8	/* Common to all HBAs */

	uint16_t	a_changestate;
#define	CFG_REBOOT		0x0	/* Changes effective after system */
					/* reboot */
#define	CFG_DYMANIC		0x1	/* Changes effective immediately */
#define	CFG_RESTART		0x2	/* Changes effective after adapter */
					/* restart */
#define	CFG_LINKRESET		0x3	/* Changes effective after link reset */

	char		a_help[80];
} dfc_cfgparam_t;



typedef struct dfc_nodeinfo
{
	uint16_t	a_flag;
	uint16_t	a_state;
	uint32_t	a_did;
	uint8_t		a_wwpn[8];
	uint8_t		a_wwnn[8];
	uint32_t	a_targetid;
} dfc_nodeinfo_t;

/* Defines for a_state */
#define	NODE_UNUSED	0	/* unused NL_PORT entry */
#define	NODE_LIMBO	0x1	/* entry needs to hang around for wwpn / sid */
#define	NODE_LOGOUT	0x2	/* NL_PORT is not logged in - entry is cached */
#define	NODE_PLOGI	0x3	/* PLOGI was sent to NL_PORT */
#define	NODE_LOGIN	0x4	/* NL_PORT is logged in / login REG_LOGINed */
#define	NODE_PRLI	0x5	/* PRLI was sent to NL_PORT */
#define	NODE_ALLOC	0x6	/* NL_PORT is  ready to initiate adapter I/O */
#define	NODE_SEED	0x7	/* seed scsi id bind in table */

/* Defines for a_flag */
#define	NODE_RPI_XRI	0x1	/* creating xri for entry */
#define	NODE_REQ_SND	0x2	/* sent ELS request for this entry */
#define	NODE_ADDR_AUTH	0x4	/* Authenticating addr for this entry */
#define	NODE_RM_ENTRY	0x8	/* Remove this entry */
#define	NODE_FARP_SND	0x10	/* sent FARP request for this entry */
#define	NODE_FABRIC	0x20	/* this entry represents the Fabric */
#define	NODE_FCP_TARGET	0x40	/* this entry is an FCP target */
#define	NODE_IP_NODE	0x80	/* this entry is an IP node */
#define	NODE_DISC_START	0x100	/* start discovery on this entry */
#define	NODE_SEED_WWPN	0x200	/* Entry scsi id is seeded for WWPN */
#define	NODE_SEED_WWNN	0x400	/* Entry scsi id is seeded for WWNN */
#define	NODE_SEED_DID	0x800	/* Entry scsi id is seeded for DID */
#define	NODE_SEED_MASK	0xe00	/* mask for seeded flags */
#define	NODE_AUTOMAP	0x1000	/* This entry was automap'ed */
#define	NODE_NS_REMOVED	0x2000	/* This entry removed from NameServer */


typedef struct dfc_vpd
{
	uint32_t	version;
#define	DFC_VPD_VERSION		1

	char		ModelDescription[256];	/* VPD field V1 */
	char		Model[80];		/* VPD field V2 */
	char		ProgramType[256];	/* VPD field V3 */
	char		PortNum[20];		/* VPD field V4 */
} dfc_vpd_t;

typedef struct dfc_destid
{
	uint32_t	idType;	/* 0 - wwpn, 1 - d_id */
	uint32_t	d_id;
	uint8_t		wwpn[8];
} dfc_destid_t;


typedef struct dfc_loopback
{
	uint32_t	bufSize;
	uint8_t		*XmitBuffer;
	uint8_t		*RcvBuffer;
} dfc_loopback_t;


typedef struct dfc_drvinfo
{
	uint8_t		drvInfoVer;	/* Version of this structure */
#define	DFC_DRVINFO_VERSION2		0x02
#define	DFC_DRVINFO_VERSION3		0x03 /* NPIV    */
#define	DFC_DRVINFO_VERSION4		0x04 /* DHCHAP */
#define	DFC_DRVINFO_VERSION		DFC_DRVINFO_VERSION3

#ifdef DHCHAP_SUPPORT
#undef  DFC_DRVINFO_VERSION
#define	DFC_DRVINFO_VERSION		DFC_DRVINFO_VERSION4
#endif /* DHCHAP_SUPPORT */

	uint8_t		drvType;
#define	DFC_DRVINFO_SOLARIS	0x11	/* Solaris */
#define	DFC_DRVINFO_LEADVILLE	0x14	/* Solaris Leadville ULP */
#define	DFC_DRVINFO_COMSTAR	0x16	/* Solaris Comstar ULP */

	uint16_t	reserved;
	uint8_t		rmLevel;	/* Remote Management (HBAnyware) */
					/* Support Level */
#define	DFC_DRVINFO_RMLEVEL		0x02	/* HBAnyware v2.3 */

	uint8_t		mpLevel;	/* MultiPulse support Level */
	uint8_t		hbaapiLevel;	/* HBAAPI support level */
#define	DFC_DRVINFO_HBAAPI	0x01	/* HBAAPI v1.0 */

	uint8_t		reserved1;
	char		drvVer[16];	/* Driver Version string */
	char		drvName[8];	/* Driver Name */
	char		ftrDrvVer[16];	/* Filter/IOCtl Driver Version string */
	char		ftrDrvName[8];	/* Filter/IOCtl Driver Name */
	char		ipDrvVer[16];	/* IP Driver/component Version string */
	char		ipDrvName[8];	/* IP Driver/component Name */
	uint32_t	d_id;
	uint8_t		wwpn[8];
	uint8_t		wwnn[8];
	uint8_t		hostname[32];	/* IP node hostname from uname -n */

#if (DFC_DRVINFO_VERSION >= DFC_DRVINFO_VERSION3)
	uint32_t	NPIVsupport;
#define	DFC_DRVINFO_NPIV_DRV	0x00000001
#define	DFC_DRVINFO_NPIV_MODS	0x00000002
#define	DFC_DRVINFO_NPIV_PARMS	0x00000004
#define	DFC_DRVINFO_NPIV_FW	0x00000008

#endif	/* >= DFC_DRVINFO_VERSION3 */

#if (DFC_DRVINFO_VERSION >= DFC_DRVINFO_VERSION4)
	uint32_t	sliMode;
	uint64_t	featureList;
#define	DFC_DRVINFO_FEATURE_DIAG		0x00000001
#define	DFC_DRVINFO_FEATURE_MAPPING		0x00000002
#define	DFC_DRVINFO_FEATURE_DHCHAP		0x00000004
#define	DFC_DRVINFO_FEATURE_IKE			0x00000008
#define	DFC_DRVINFO_FEATURE_NPIV		0x00000010
#define	DFC_DRVINFO_FEATURE_RESET_WWN		0x00000020
#define	DFC_DRVINFO_FEATURE_VOLATILE_WWN	0x00000040
#define	DFC_DRVINFO_FEATURE_E2E_AUTH		0x00000080
#define	DFC_DRVINFO_FEATURE_SAN_DIAG		0x00000100
#define	DFC_DRVINFO_FEATURE_FCOE		0x00000200
#define	DFC_DRVINFO_FEATURE_PERSISTLINK		0x00000400
#define	DFC_DRVINFO_FEATURE_TARGET_MODE		0x00000800
#define	DFC_DRVINFO_FEATURE_EXT_MBOX		0x00001000

#endif /* >= DFC_DRVINFO_VERSION4 */
} dfc_drvinfo_t;



typedef struct dfc_regevent
{
	uint32_t	ppid;
	uint32_t	cpid;

	uint32_t	event;
	uint32_t	type;
	uint32_t	outsz;
	void		*ctx;
	void		(*func) ();

	uint32_t	cindex;	/* Set only by child */
	uint32_t	state;	/* Set only by child */

	/* state */
#define	CHILD_UNKNOWN		0
#define	CHILD_UNBORN		1
#define	CHILD_ALIVE		2
#define	CHILD_REGISTERED	3
#define	CHILD_ASLEEP		4
#define	CHILD_AWAKE		5
#define	CHILD_DIED		6

	uint32_t	pindex;	/* Set only by parent */
	uint32_t	flags;	/* Set only by parent */

	/* flags */
#define	EVENT_REGISTERED	0x01
#define	EVENT_SERVICE_ACTIVE	0x02

#ifdef SAN_DIAG_SUPPORT
	HBA_WWN		portname;
#endif /* SAN_DIAG_SUPPORT */

	pthread_t ptid;
	uint32_t board;

} dfc_regevent_t;


/* Defines for RegisterForEvent mask */
#define	FC_REG_LINK_EVENT	0x01		/* Register for link up/down */
						/* events */
#define	FC_REG_RSCN_EVENT	0x02		/* Register for RSCN events */
#define	FC_REG_CT_EVENT		0x04		/* Register for CT request */
						/* events */
#define	FC_REG_MULTIPULSE_EVENT	0x08		/* Register for MultiPulse */
						/* events */
#define	FC_REG_DUMP_EVENT	0x10		/* Register for Diagnostic */
						/* Dump events */
#define	FC_REG_TEMP_EVENT	0x20		/* Register for Temperature */
						/* events */
#define	FC_REG_VPORTRSCN_EVENT	0x40		/* Register for VPort RSCN */
						/* events */
#ifdef SAN_DIAG_SUPPORT
#define	FC_REG_SD_ELS_EVENT	0x1000		/* Register for SANDiag ELS */
						/* events */
#define	FC_REG_SD_FABRIC_EVENT  0x2000		/* Register for SANDiag */
						/* Fabric events */
#define	FC_REG_SD_SCSI_EVENT    0x4000		/* Register for SANDiag SCSI */
						/* events */
#define	FC_REG_SD_BOARD_EVENT   0x8000		/* Register for SANDiag Board */
						/* events */
#endif /* SAN_DIAG_SUPPORT */
#define	FC_REG_FCOE_EVENT	0x80000000	/* (Unofficial) Register for */
						/* FCOE events */

#define	MAX_RSCN_PAYLOAD	1024
#define	MAX_CT_PAYLOAD		(1024*320)

/* Temperature event types */
#define	DFC_TEMP_CRITICAL	1
#define	DFC_TEMP_WARNING	2
#define	DFC_TEMP_SAFE		3

/* bits in a_onmask */
#define	ONDI_MBOX		0x1	/* allows non-destructive mailbox */
					/* commands */
#define	ONDI_IOINFO		0x2	/* supports retrieval of I/O info */
#define	ONDI_LNKINFO		0x4	/* supports retrieval of link info */
#define	ONDI_NODEINFO		0x8	/* supports retrieval of node info */
#define	ONDI_TRACEINFO		0x10	/* supports retrieval of trace info */
#define	ONDI_SETTRACE		0x20	/* supports configuration of trace */
					/* info */
#define	ONDI_SLI1		0x40	/* hardware supports SLI-1 interface */
#define	ONDI_SLI2		0x80	/* hardware supports SLI-2 interface */
#define	ONDI_BIG_ENDIAN		0x100	/* DDI interface is BIG Endian */
#define	ONDI_LTL_ENDIAN		0x200	/* DDI interface is LITTLE Endian */
#define	ONDI_RMEM		0x400	/* allows reading of adapter shared */
					/* memory */
#define	ONDI_RFLASH		0x800	/* allows reading of adapter flash */
#define	ONDI_RPCI		0x1000	/* allows reading of adapter pci */
					/* registers */
#define	ONDI_RCTLREG		0x2000	/* allows reading of adapter cntrol */
					/* registers */
#define	ONDI_CFGPARAM		0x4000	/* supports get/set configuration */
					/* parameters */
#define	ONDI_CT			0x8000	/* supports passthru CT interface */
#define	ONDI_HBAAPI		0x10000	/* supports HBA API interface */
#define	ONDI_SBUS		0x20000	/* supports SBUS adapter interface */

/* bits in a_offmask */
#define	OFFDI_MBOX	0x1		/* allows all mailbox commands */
#define	OFFDI_RMEM	0x2		/* allows reading of adapter shared */
					/* memory */
#define	OFFDI_WMEM	0x4		/* allows writing of adapter shared */
					/* memory */
#define	OFFDI_RFLASH	0x8		/* allows reading of adapter flash */
#define	OFFDI_WFLASH	0x10		/* allows writing of adapter flash */
#define	OFFDI_RPCI	0x20		/* allows reading of adapter pci */
					/* registers */
#define	OFFDI_WPCI	0x40		/* allows writing of adapter pci */
					/* registers */
#define	OFFDI_RCTLREG	0x80		/* allows reading of adapter cntrol */
					/* registers */
#define	OFFDI_WCTLREG	0x100		/* allows writing of adapter cntrol */
					/* registers */
#define	OFFDI_OFFLINE	0x80000000	/* if set, adapter is in offline */
					/* state */


#define	DDI_SHOW	0x0
#define	DDI_ONDI	0x1
#define	DDI_OFFDI	0x2
#define	DDI_WARMDI	0x3
#define	DDI_DIAGDI	0x4

/* mbxStatus */
#define	DFC_MBX_SUCCESS			0x00
#define	DFC_MBXERR_NUM_RINGS		0x01
#define	DFC_MBXERR_NUM_IOCBS		0x02
#define	DFC_MBXERR_IOCBS_EXCEEDED	0x03
#define	DFC_MBXERR_BAD_RING_NUMBER	0x04
#define	DFC_MBXERR_MASK_ENTRIES_RANGE	0x05
#define	DFC_MBXERR_MASKS_EXCEEDED	0x06
#define	DFC_MBXERR_BAD_PROFILE		0x07
#define	DFC_MBXERR_BAD_DEF_CLASS	0x08
#define	DFC_MBXERR_BAD_MAX_RESPONDER	0x09
#define	DFC_MBXERR_BAD_MAX_ORIGINATOR	0x0A
#define	DFC_MBXERR_RPI_REGISTERED	0x0B
#define	DFC_MBXERR_RPI_FULL		0x0C
#define	DFC_MBXERR_NO_RESOURCES		0x0D
#define	DFC_MBXERR_BAD_RCV_LENGTH	0x0E
#define	DFC_MBXERR_DMA_ERROR		0x0F
#define	DFC_MBXERR_ERROR		0x10

#define	DFC_MBXERR_OVERTEMP_ERROR	0xFA
#define	DFC_MBXERR_HARDWARE_ERROR	0xFB
#define	DFC_MBXERR_DRVR_ERROR		0xFC
#define	DFC_MBXERR_BUSY			0xFD
#define	DFC_MBXERR_TIMEOUT		0xFE
#define	DFC_MBX_NOT_FINISHED		0xFF



/* Error codes for library calls */
#define	DFC_ERR_GENERAL_ERROR		0x1

#define	DFC_ERR_MBOX_ERROR		0x2
#define	DFC_ERR_LINK_DOWN		0x2
#define	DFC_ERR_INCORRECT_VER		0x2
#define	DFC_ERR_INVALID_ID		0x2
#define	DFC_ERR_TIMEOUT			0x2
#define	DFC_ERR_NOT_SUPPORTED		0x2
#define	DFC_ERR_NPIV_ACTIVE		0x2

#define	DFC_ERR_NO_RPI			0x3
#define	DFC_ERR_BUFFER_OVERFLOW		0x3
#define	DFC_ERR_INVALID_LOOPBACK_TYPE	0x3
#define	DFC_ERR_OVERTEMP		0x3

#define	DFC_ERR_LOOPBACK_BUSY		0x4
#define	DFC_ERR_INVALID_RESET_TYPE	0x4
#define	DFC_ERR_MENLO_LINKDOWN		0x4

#define	DFC_ERR_SEQ_TIMEOUT		0x5

#define	DFC_ERR_NO_XMIT			0x6
#define	DFC_ERR_INVALID_NUMBER		0x6

#define	DFC_ERR_RESET_RECV		0x7




/* type definitions for GetBindList function */
typedef enum dfc_bindtype
{
	BIND_NONE,
	BIND_WWNN,
	BIND_WWPN,
	BIND_DID,
	BIND_ALPA
} dfc_bindtype_t;


typedef struct dfc_bind_entry
{
	dfc_bindtype_t  bind_type;
	uint32_t	scsi_id;
	uint32_t	did;
	uint8_t		wwnn[8];
	uint8_t		wwpn[8];
	uint32_t	flags;

	/* Bind Entry flags */
#define	DFC_BIND_AUTOMAP	0x1	/* Node is automapped */
#define	DFC_BIND_BINDLIST	0x2	/* entry in bind list not mapped */
#define	DFC_BIND_MAPPED		0x4	/* Node is mapped to a scsiid */
#define	DFC_BIND_UNMAPPED	0x8	/* Node is unmapped */
#define	DFC_BIND_NODEVTMO	0x10	/* NODEVTMO flag of the node */
#define	DFC_BIND_NOSCSIID	0x20	/* No scsi id is assigned yet */
#define	DFC_BIND_RPTLUNST	0x40	/* Node is in report lun cmpl st */
} dfc_bind_entry_t;

typedef struct dfc_bind_list
{
	uint32_t		NumberOfEntries;
	dfc_bind_entry_t	entry[1];	/* Variable length array */
} dfc_bind_list_t;



/* Defines for error codes -OLD- */
#define	FC_ERROR_BUFFER_OVERFLOW	0xff
#define	FC_ERROR_RESPONSE_TIMEOUT	0xfe
#define	FC_ERROR_LINK_UNAVAILABLE	0xfd
#define	FC_ERROR_INSUFFICIENT_RESOURCES	0xfc
#define	FC_ERROR_EXISTING_REGISTRATION	0xfb
#define	FC_ERROR_INVALID_TAG		0xfa
#define	FC_ERROR_INVALID_WWN		0xf9
#define	FC_ERROR_CREATEVENT_FAILED	0xf8



typedef union dfc_ct_rev
{
	/* Structure is in Big Endian format */
	struct
	{
		uint32_t	Revision:8;
		uint32_t	InId:24;
	} bits;
	uint32_t	word;
} dfc_ct_rev_t;

typedef union dfc_ct_resp
{
	/* Structure is in Big Endian format */
	struct
	{
		uint32_t	CmdRsp:16;
		uint32_t	Size:16;
	} bits;
	uint32_t	word;
} dfc_ct_resp_t;

typedef struct dfc_ct_request
{
	/* Structure is in Big Endian format */
	dfc_ct_rev_t	RevisionId;
	uint8_t		FsType;
	uint8_t		FsSubType;
	uint8_t		Options;
	uint8_t		Rsrvd1;
	dfc_ct_resp_t	CommandResponse;
	uint8_t		Rsrvd2;
	uint8_t		ReasonCode;
	uint8_t		Explanation;
	uint8_t		VendorUnique;
} dfc_ct_request_t;

#define	SLI_CT_REVISION	1

#define	FC_FSTYPE_ALL 0xffff	/* match on all fsTypes */

/* Emulex Vendor-Unique CT Request Command Codes */
#define	CT_OP_GSAT	0x0101	/* Get Server Attributes */
#define	CT_OP_GHAT	0x0102	/* Get HBA Attributes */
#define	CT_OP_GPAT	0x0103	/* Get Port Attributes */
#define	CT_OP_GDAT	0x0104	/* Get Driver Attributes */
#define	CT_OP_GPST	0x0105	/* Get Port Statistics */
/* 0x0106 is reserved */
#define	CT_OP_GDP	0x0107	/* Get Driver Parameters */
#define	CT_OP_GDPG	0x0108	/* Get Driver Parameters Global */
#define	CT_OP_GEPS	0x0109	/* Get Extended Port Statistics */
#define	CT_OP_GLAT	0x010A	/* Get Lun Attributes */

#define	CT_OP_SSAT	0x0111	/* Set Server Attributes */
#define	CT_OP_SHAT	0x0112	/* Set HBA Attributes */
#define	CT_OP_SPAT	0x0113	/* Set Port Attributes */
#define	CT_OP_SDAT	0x0114	/* Set Driver Attributes */
/* 0x0115 is reserved */
/* 0x0116 is reserved */
#define	CT_OP_SDP	0x0117	/* Set Driver Parameter */
#define	CT_OP_SBBS	0x0118	/* Set Boot Bios State */

#define	CT_OP_RPST	0x0121	/* Reset Port Statistics */
#define	CT_OP_VFW	0x0122	/* Verify Firmware */
#define	CT_OP_DFW	0x0123	/* Download Firmware */
#define	CT_OP_RES	0x0124	/* Reset HBA */
#define	CT_OP_RHD	0x0125	/* Run HBA Diagnostic */
#define	CT_OP_UFW	0x0126	/* Upgrade Firmware */
#define	CT_OP_RDP	0x0127	/* Reset Driver Parameters */
#define	CT_OP_GHDR	0x0128	/* Get HBA Diagnotic Results */
#define	CT_OP_CHD	0x0129	/* Cancel HBA Diagnostic */

/* 0x0131 is reserved */
/* 0x0132 is reserved */
#define	CT_OP_SSR 0x0133	/* Send Software Resource */

#define	CT_OP_RSAT	0x0141	/* Read  SA Table */
#define	CT_OP_WSAT	0x0142	/* Write SA Table */
#define	CT_OP_RSAH	0x0143	/* Read  SA Table Header */
#define	CT_OP_WSAH	0x0144	/* Write SA Table Header */
#define	CT_OP_RACT	0x0145	/* Read  Access Control Table */
#define	CT_OP_WACT	0x0146	/* Write Access Control Table */
#define	CT_OP_RKT	0x0147	/* Read  Key Table Table */
#define	CT_OP_WKT	0x0148	/* Write Key Table Table */
#define	CT_OP_SSC	0x0149	/* Cause SA Table re-read;sync */

#define	CT_OP_QHBA	0x0151	/* Query HBA */
#define	CT_OP_GST	0x0152	/* Get Status */

#define	CT_OP_GFTM	0x0161	/* Get FCP Target Mapping */
#define	CT_OP_SRL	0x0162	/* SCSI Report Luns */
#define	CT_OP_SI	0x0163	/* SCSI Inquiry */
#define	CT_OP_SRC	0x0164	/* SCSI Read Capacity */

#define	CT_OP_GPB	0x0171	/* Get FCP Persistent Binding */
#define	CT_OP_SPB	0x0172	/* Set FCP Persistent Binding */
#define	CT_OP_RPB	0x0173	/* Remove FCP Persistent Binding */
#define	CT_OP_RAPB	0x0174	/* Remove All FCP Persistent Bindings */
#define	CT_OP_GBC	0x0175	/* Get Binding Capability */
#define	CT_OP_GBS	0x0176	/* Get Binding Support */
#define	CT_OP_SBS	0x0177	/* Set Binding Support */
#define	CT_OP_GANI	0x0178	/* Get All Nodes Info */
#define	CT_OP_GRV	0x0179	/* Get Range Value for Bus#, Target#, Lun# */
#define	CT_OP_GAPBS	0x017A	/* Get AutoPB service state */
				/* (AutoPilotManager) */
#define	CT_OP_APBC	0x017B	/* Configure AutoPB service */
				/* (AutoPilotManager) */

#define	CT_OP_GDT	0x0180	/* Get Driver Type */
#define	CT_OP_GDLMI	0x0181	/* Get Drive Letter Mapping */
				/* Information [GDLM] */
#define	CT_OP_GANA	0x0182	/* Get All Node Addresses */
#define	CT_OP_GDLV	0x0183	/* Get Driver Library Version */
#define	CT_OP_GWUP	0x0184	/* Get Adapter Wakeup Parameters */
#define	CT_OP_GLM	0x0185	/* Get Adapter Loopmap */
#define	CT_OP_GABS	0x0186	/* Get Adapter Beacon State */
#define	CT_OP_SABS	0x0187	/* Set Adapter Beacon State */
#define	CT_OP_RPR	0x0188	/* Read Adapter PCI Registers */

/* NPIV return codes */
#define	DFC_NPIV_SUCCESS			0
#define	DFC_NPIV_GENERAL_ERROR			1
#define	DFC_NPIV_NOT_SUPPORTED			2
#define	DFC_NPIV_NO_RESOURCES			3
#define	DFC_NPIV_INVALID_HANDLE			3
#define	DFC_NPIV_ILLEGAL_WWPN			4
#define	DFC_NPIV_TOO_MANY_VPORTS		4
#define	DFC_NPIV_ILLEGAL_WWN			5
#define	DFC_NPIV_BUSY				5
#define	DFC_NPIV_INVALID_WWN			6
#define	DFC_NPIV_LINK_DOWN			7
#define	DFC_NPIV_MORE_DATA			7
#define	DFC_NPIV_FABRIC_NOT_SUPPORTED		8
#define	DFC_NPIV_FABRIC_OUT_OF_RESOURCE		9
#define	DFC_NPIV_INVALID_ACCESS_KEY		10
#define	DFC_NPIV_INVALID_HANDLE_AT_CREATE	11
#define	DFC_NPIV_UNSUPPORTED_OPTION		12

typedef struct dfc_vport_QoS
{
	uint32_t	resv;
} dfc_vport_QoS_t;


/* VPORT type */
#define	VPORT_TYPE_PHYSICAL	0
#define	VPORT_TYPE_VIRTUAL	1

/* VPORT States */
#define	VPORT_STATE_UNKNOWN		0
#define	VPORT_STATE_LINKDOWN		1
#define	VPORT_STATE_INIT		2
#define	VPORT_STATE_NO_FABRIC_SUPPORT	3
#define	VPORT_STATE_NO_FABRIC_RESOURCE	4
#define	VPORT_STATE_FABRIC_LOGOUT	5
#define	VPORT_STATE_FABRIC_REJECT_WWN	6
#define	VPORT_STATE_FABRIC_LOGIN_FAIL	7
#define	VPORT_STATE_ACTIVE		8
#define	VPORT_STATE_AUTH_FAILED		9

/* VPORT Options */
#define	 VPORT_OPT_AUTORETRY		0x00000001
#define	 VPORT_OPT_AUTOWWN		0x00000002
#define	 VPORT_OPT_ACTIVATE		0x00000004

#define	 VPORT_OPT_SAVE_CREATE_ONLY	0x00000000
#define	 VPORT_OPT_SAVE_CREATE_UPDATE	0x00000010
#define	 VPORT_OPT_SAVE_UPDATE_ONLY	0x00000018
#define	 VPORT_OPT_SAVE_MASK		0x00000018

#define	 VPORT_OPT_RESTRICT		0x00000020
#define	 VPORT_OPT_UNRESTRICT		0x00000040
#define	 VPORT_OPT_RESTRICT_MASK	0x00000060

#define	 VPORT_OPT_FAILOVER		0x00000080

/* Check list bit-mapped value */
#define	 CL_NPIV_PARM_ENABLE		0x00000001
#define	 CL_SLI3_ENABLE			0x00000002
#define	 CL_HBA_SUPPORT_NPIV		0x00000004
#define	 CL_HBA_HAS_RESOURCES		0x00000008
#define	 CL_HBA_LINKUP			0x00000010
#define	 CL_P2P_TOPOLOGY		0x00000020
#define	 CL_FABRIC_SUPPORTS_NPIV	0x00000040
#define	 CL_FABRIC_HAS_RESOURCES	0x00000080
#define	 CL_NPIV_READY			0x000000FF




#define	DFC_VPORT_ATTR_VERSION	2
typedef struct dfc_vport_attrs
{
	uint8_t		version;	/* 2 = version of this structure, */
					/* for compatibility check */
	uint8_t		reserved1[3];

	uint8_t		wwpn[8];	/* virtual port WWPN */
	uint8_t		wwnn[8];	/* virtual port WWNN */
	char		name[256];	/* name to be register with the */
					/* fabric */

	uint32_t	options;

	uint32_t	portFcId;	/* D-ID; set when the N-port is */
					/* created successfully */

	uint8_t		state;		/* VPORT state */
	uint8_t		restrictLogin;
	uint8_t		flags;
	uint8_t		reserved2;
	uint64_t	buf;		/* Used for VPI */

	uint8_t		fabric_wwn[8];	/* Fabric WWN (WWNN) */
	uint32_t	checklist;
	uint8_t		accessKey[32];
} dfc_vport_attrs_t;


typedef struct dfc_vport_entry
{
	uint8_t		wwpn[8];	/* wwpn of the virtual port */
	uint8_t		wwnn[8];	/* wwnn of the virtual port */
	uint32_t	PortFcId;	/* FC port ID assigned to this */
					/* virtual port */
} dfc_vport_entry_t;


typedef struct dfc_vport_entry_list
{
	uint32_t		NumberOfEntries;
	dfc_vport_entry_t	entry[MAX_VPORTS];
} dfc_vport_entry_list_t;


typedef struct dfc_vport_nodeinfo_entry
{
	uint32_t	bind_type;
#define	VPORT_NODE_BINDDID		0x0000
#define	VPORT_NODE_BINDWWNN		0x0001
#define	VPORT_NODE_BINDWWPN		0x0002
#define	VPORT_NODE_AUTOMAP		0x0004
#define	VPORT_NODE_UNMASK_ALL_LUN 	0x0008
#define	VPORT_NODE_DISABLE_LUN_AUTOMAP	0x0010
#define	VPORT_NODE_ALPA			0x0020

	HBA_SCSIID	scsiId;
	HBA_FCPID	fcpId;

	uint32_t	nodeState;
#define	VPORT_NODESTATE_EXIST		0x0001
#define	VPORT_NODESTATE_READY		0x0002
#define	VPORT_NODESTATE_LINKDOWN	0x0004
#define	VPORT_NODESTATE_UNMAPPED	0x0008
#define	VPORT_NODESTATE_BOUND		0x0010

	uint32_t	reserved;
} dfc_vport_nodeinfo_entry_t;

typedef struct dfc_vport_get_nodeinfo
{
	uint32_t			NumberOfEntries;  /* number of nodes */
	dfc_vport_nodeinfo_entry_t	entry[MAX_NODES]; /* start of array */
} dfc_vport_get_nodeinfo_t;


typedef struct dfc_vport_resource
{
	uint32_t	vpi_max;
	uint32_t	vpi_inuse;
	uint32_t	rpi_max;
	uint32_t	rpi_inuse;
} dfc_vport_resource_t;


typedef struct dfc_vlinkinfo
{
	uint32_t	api_versions;

	uint8_t		linktype;
	uint8_t		state;
	uint8_t		fail_reason;
	uint8_t		prev_fail_reason;
#define	VPORT_FAIL_UNKNOWN			0
#define	VPORT_FAIL_LINKDOWN			1
#define	VPORT_FAIL_FAB_UNSUPPORTED		2
#define	VPORT_FAIL_FAB_NORESOURCES		3
#define	VPORT_FAIL_FAB_LOGOUT			4
#define	VPORT_FAIL_HBA_NORESOURCES		5

	uint8_t		wwnn[8];
	uint8_t		wwpn[8];

	void		*vlink;

	uint32_t	vpi_max;
	uint32_t	vpi_inuse;
	uint32_t	rpi_max;
	uint32_t	rpi_inuse;
} dfc_vlinkinfo_t;


#ifdef DHCHAP_SUPPORT

/* DHCHAP return code */
#define	DFC_AUTH_STATUS_NOT_CONFIGURED			0x8001
#define	DFC_AUTH_STATUS_AUTH_FAILED_NO_SA_FOUND		0x8002
#define	DFC_AUTH_STATUS_AUTH_INIT_OK_AUTH_FAILED	0x8003
#define	DFC_AUTH_STATUS_COMPARE_FAILED			0x8004
#define	DFC_AUTH_STATUS_WWN_NOT_FOUND			0x8005
#define	DFC_AUTH_STATUS_PASSWORD_INVALID		0x8006
#define	DFC_AUTH_STATUS_INVALID_ENTITY			0x8007
#define	DFC_AUTH_STATUS_ENTITY_NOT_ACTIVE		0x8008
#define	DFC_AUTH_STATUS_INVALID_OPERATION		0x8009
#define	DFC_AUTH_STATUS_OUT_OF_RESOURCES		0x800a
#define	DFC_AUTH_STATUS_AUTHENTICATION_GOINGON		0x800b
#define	DFC_AUTH_STATUS_INVALID_BOARD_NO		0x800c
#define	DFC_AUTH_STATUS_IO_ERROR			0x800d
#define	DFC_AUTH_STATUS_CREATE_STORKEY_ERROR		0x800e
#define	DFC_AUTH_STATUS_CREATE_PARMKEY_ERROR		0x800f
#define	DFC_AUTH_STATUS_CREATE_AUTHKEY_ERROR		0x8010
#define	DFC_AUTH_STATUS_LOCAL_REMOTE_PASSWORD_SAME	0x8011
#define	DFC_AUTH_STATUS_CREATE_BORDKEY_ERROR		0x8020
#define	DFC_AUTH_STATUS_DRVTYPE_NOT_SUPPORTED		0x8030
#define	DFC_AUTH_STATUS_AUTHENTICATION_NOT_SUPPORTED	0x8031
#define	DFC_AUTH_STATUS_GENERAL_ERROR			0x8032
#define	DFC_AUTH_STATUS_CONFIG_NOT_FOUND		0x8034
#define	DFC_AUTH_STATUS_NOT_PRIVILEGE_USER		0x8040


typedef struct dfc_fcsp_config
{
	HBA_WWN		lwwpn;
	HBA_WWN		rwwpn;

	uint16_t	auth_tov;	/* seconds */
#define	DFC_AUTH_TOV_MIN	20
#define	DFC_AUTH_TOV_MAX	1000
#define	DFC_AUTH_TOV_DEFAULT	45

	uint8_t		auth_mode;
#define	DFC_AUTH_MODE_DISABLED	1
#define	DFC_AUTH_MODE_ACTIVE	2
#define	DFC_AUTH_MODE_PASSIVE	3
#define	DFC_AUTH_MODE_DEFAULT	DFC_AUTH_MODE_DISABLED

	uint8_t		auth_bidir:1;
#define	DFC_AUTH_BIDIR_DISABLED	0
#define	DFC_AUTH_BIDIR_ENABLED	1
#define	DFC_AUTH_BIDIR_DEFAULT	DFC_AUTH_BIDIR_DISABLED
	uint8_t		reserved:7;

	uint8_t		type_priority[4];
#define	DFC_AUTH_TYPE_DHCHAP	1	/* Only one currently supported */
#define	DFC_AUTH_TYPE_FCAP	2
#define	DFC_AUTH_TYPE_FCPAP	3
#define	DFC_AUTH_TYPE_KERBEROS	4
#define	DFC_AUTH_TYPE_MAX	4
#define	DFC_AUTH_TYPE_DEFAULT0	DFC_AUTH_TYPE_DHCHAP
#define	DFC_AUTH_TYPE_DEFAULT1	0
#define	DFC_AUTH_TYPE_DEFAULT2	0
#define	DFC_AUTH_TYPE_DEFAULT3	0

	uint8_t		hash_priority[4];
#define	DFC_AUTH_HASH_MD5	1
#define	DFC_AUTH_HASH_SHA1	2
#define	DFC_AUTH_HASH_MAX	2
#define	DFC_AUTH_HASH_DEFAULT0	DFC_AUTH_HASH_MD5
#define	DFC_AUTH_HASH_DEFAULT1	DFC_AUTH_HASH_SHA1
#define	DFC_AUTH_HASH_DEFAULT2	0
#define	DFC_AUTH_HASH_DEFAULT3	0

	uint8_t		group_priority[8];
#define	DFC_AUTH_GROUP_NULL	1
#define	DFC_AUTH_GROUP_1024	2
#define	DFC_AUTH_GROUP_1280	3
#define	DFC_AUTH_GROUP_1536	4
#define	DFC_AUTH_GROUP_2048	5
#define	DFC_AUTH_GROUP_MAX	5

#define	DFC_AUTH_GROUP_DEFAULT0	DFC_AUTH_GROUP_NULL
#define	DFC_AUTH_GROUP_DEFAULT1	DFC_AUTH_GROUP_1024
#define	DFC_AUTH_GROUP_DEFAULT2	DFC_AUTH_GROUP_1280
#define	DFC_AUTH_GROUP_DEFAULT3	DFC_AUTH_GROUP_1536
#define	DFC_AUTH_GROUP_DEFAULT4	DFC_AUTH_GROUP_2048
#define	DFC_AUTH_GROUP_DEFAULT5	0
#define	DFC_AUTH_GROUP_DEFAULT6	0
#define	DFC_AUTH_GROUP_DEFAULT7	0

	uint32_t	reauth_tov;	/* minutes */
#define	DFC_REAUTH_TOV_MIN	0
#define	DFC_REAUTH_TOV_MAX	7200
#define	DFC_REAUTH_TOV_DEFAULT	1440
} dfc_fcsp_config_t;


typedef struct dfc_password
{
	uint16_t	length;
#define	DFC_PASSWORD_LENGTH_MIN		8
#define	DFC_PASSWORD_LENGTH_MAX		128

	uint16_t	type;
#define	DFC_PASSWORD_TYPE_ASCII		1
#define	DFC_PASSWORD_TYPE_BINARY	2
#define	DFC_PASSWORD_TYPE_IGNORE	3

	uint8_t		password[DFC_PASSWORD_LENGTH_MAX];
} dfc_password_t;

typedef struct dfc_auth_password
{
	HBA_WWN		lwwpn;
	HBA_WWN		rwwpn;

	dfc_password_t	lpw;
	dfc_password_t	rpw;

	dfc_password_t	lpw_new;
	dfc_password_t	rpw_new;
} dfc_auth_password_t;


typedef struct dfc_auth_cfglist
{
	uint32_t	cnt;
	HBA_WWN  rwwpn[1];
} dfc_auth_cfglist_t;


typedef struct dfc_auth_status
{
	HBA_WWN		lwwpn;
	HBA_WWN		rwwpn;

	uint8_t		auth_state;
#define	DFC_AUTH_STATE_OFF		1
#define	DFC_AUTH_STATE_INP		2
#define	DFC_AUTH_STATE_ON		3
#define	DFC_AUTH_STATE_FAILED		4

	uint8_t		auth_failReason;
#define	DFC_AUTH_FAIL_GENERIC		1
#define	DFC_AUTH_FAIL_ELS_TMO		2
#define	DFC_AUTH_FAIL_XACT_TMO		3
#define	DFC_AUTH_FAIL_LS_RJT		4
#define	DFC_AUTH_FAIL_BSY_LS_RJT	5
#define	DFC_AUTH_FAIL_REJECTED		6

	uint8_t		type_priority;
	uint8_t		group_priority;

	uint8_t		hash_priority;
	uint8_t		localAuth :1;
	uint8_t		remoteAuth :1;
	uint8_t		pad :6;
	uint16_t	reserved0;

	uint32_t	time_from_last_auth; /* seconds */
	uint32_t	time_until_next_auth; /* seconds */

	uint32_t	reserved1;
	uint32_t	reserved2;
} dfc_auth_status_t;

#endif	/* DHCHAP_SUPPORT */

/*
 * Start of FCP specific structures
 */

#ifndef MAX_FCP_SNS
typedef struct emlxs_fcp_rsp
{
	uint32_t	rspRsvd1;	/* FC Word 0, byte 0:3 */
	uint32_t	rspRsvd2;	/* FC Word 1, byte 0:3 */

	uint8_t		rspStatus0;	/* FCP_STATUS byte 0 (reserved) */
	uint8_t		rspStatus1;	/* FCP_STATUS byte 1 (reserved) */
	uint8_t		rspStatus2;	/* FCP_STATUS byte 2 field validity */
#define	RSP_LEN_VALID	0x01		/* bit 0 */
#define	SNS_LEN_VALID	0x02		/* bit 1 */
#define	RESID_OVER	0x04		/* bit 2 */
#define	RESID_UNDER	0x08		/* bit 3 */
	uint8_t		rspStatus3;	/* FCP_STATUS byte 3 SCSI status byte */
#define	SCSI_STAT_GOOD		0x00
#define	SCSI_STAT_CHECK_COND	0x02
#define	SCSI_STAT_COND_MET	0x04
#define	SCSI_STAT_BUSY		0x08
#define	SCSI_STAT_INTERMED	0x10
#define	SCSI_STAT_INTERMED_CM	0x14
#define	SCSI_STAT_RES_CNFLCT	0x18
#define	SCSI_STAT_CMD_TERM	0x22
#define	SCSI_STAT_QUE_FULL	0x28
#define	SCSI_STAT_ACA_ACTIVE	0x30
#define	SCSI_STAT_TASK_ABORT	0x40

	uint32_t	rspResId;	/* Residual xfer if RESID_xxxx set in */
					/* fcpStatus2 */
					/* Received in Big Endian format */
	uint32_t	rspSnsLen;	/* Length of sense data in fcpSnsInfo */
					/* received in Big Endian format */
	uint32_t	rspRspLen;	/* Length of FCP response data in */
					/* fcpRspInfo */
					/* Received In Big Endian format */

	uint8_t		rspInfo0;	/* FCP_RSP_INFO byte 0 (reserved) */
	uint8_t		rspInfo1;	/* FCP_RSP_INFO byte 1 (reserved) */
	uint8_t		rspInfo2;	/* FCP_RSP_INFO byte 2 (reserved) */
	uint8_t		rspInfo3;	/* FCP_RSP_INFO RSP_CODE byte 3 */

#define	RSP_NO_FAILURE		0x00
#define	RSP_DATA_BURST_ERR	0x01
#define	RSP_CMD_FIELD_ERR	0x02
#define	RSP_RO_MISMATCH_ERR	0x03
#define	RSP_TM_NOT_SUPPORTED	0x04	/* Task mgmt function not supported */
#define	RSP_TM_NOT_COMPLETED	0x05	/* Task mgmt function not performed */

	uint32_t	rspInfoRsvd;	/* FCP_RSP_INFO bytes 4-7 (reserved) */

	/*
	 * Define maximum size of SCSI Sense buffer.
	 * Seagate never issues more than 18 bytes of Sense data.
	 */
#define	MAX_FCP_SNS		128
	uint8_t		rspSnsInfo[MAX_FCP_SNS];
} emlxs_fcp_rsp;
typedef emlxs_fcp_rsp FCP_RSP;
#endif /* MAX_FCP_SNS */


#ifndef FC_LUN_SHIFT
typedef struct emlxs_fcp_cmd
{
	uint32_t	fcpLunMsl;	/* most significant word (32 bits) */
	uint32_t	fcpLunLsl;	/* least significant word (32 bits) */

	/*
	 * # of bits to shift lun id to end up in right payload word,
	 * little endian = 8, big = 16.
	 */
#ifdef EMLXS_LITTLE_ENDIAN
#define	FC_LUN_SHIFT		8
#define	FC_ADDR_MODE_SHIFT	0
#endif
#ifdef EMLXS_BIG_ENDIAN
#define	FC_LUN_SHIFT		16
#define	FC_ADDR_MODE_SHIFT	24
#endif

	uint8_t		fcpCntl0;	/* FCP_CNTL byte 0 (reserved) */
	uint8_t		fcpCntl1;	/* FCP_CNTL byte 1 task codes */
#define	SIMPLE_Q	0x00
#define	HEAD_OF_Q	0x01
#define	ORDERED_Q	0x02
#define	ACA_Q		0x04
#define	UNTAGGED	0x05

	uint8_t		fcpCntl2;	/* FCP_CTL byte 2 task management */
					/* codes */
#define	 ABORT_TASK_SET	0x02		/* Bit 1 */
#define	 CLEAR_TASK_SET	0x04		/* bit 2 */
#define	 LUN_RESET	0x10		/* bit 4 */
#define	 TARGET_RESET	0x20		/* bit 5 */
#define	 CLEAR_ACA	0x40		/* bit 6 */
#define	 TERMINATE_TASK	0x80		/* bit 7 */

	uint8_t		fcpCntl3;
#define	 WRITE_DATA	0x01		/* Bit 0 */
#define	 READ_DATA	0x02		/* Bit 1 */

	uint8_t		fcpCdb[16];	/* SRB cdb field is copied here */
	uint32_t	fcpDl;		/* Total transfer length */
} emlxs_fcp_cmd_t;
typedef emlxs_fcp_cmd_t FCP_CMND;
#endif /* FC_LUN_SHIFT */


/*
 * Used by libdfc (SendScsiCmd, SendFcpCmd, DFC_SendScsiCmdV2, DFC_SendFcpCmdV2
 * and emlxs_dfc_send_scsi_fcp functions
 */
typedef struct dfc_send_scsi_fcp_cmd_info
{
	HBA_WWN		src_wwn;
	HBA_WWN		dst_wwn;
	uint32_t	cnt1;
	uint32_t	cnt2;
	uint32_t	ver;
} dfc_send_scsi_fcp_cmd_info_t;

#define	SCSI_RSP_CNT(x)		x->cnt1
#define	SCSI_SNS_CNT(x)		x->cnt2
#define	FC_DATA_CNT(x)		x->cnt1
#define	FC_RSP_CNT(x)		x->cnt2

#define	DFC_SEND_SCSI_FCP_V1	1
#define	DFC_SEND_SCSI_FCP_V2	2

typedef struct DFC_FCoEParam
{
	uint8_t		version;
#define	DFC_FCoE_PARAM_VERSION	1

	uint8_t		Reserved[3];
	uint8_t		FCMap[3];
	uint8_t		VLanValid;
#define	VLAN_ID_INVALID	0x0
#define	VLAN_ID_VALID	0x1

	uint16_t	VLanId;
} DFC_FCoEParam_t;

typedef struct DFC_FCoEFCFConnectEntry
{
	uint16_t	flags;
#define	FCFCNCT_RSVD		0x00000001
#define	FCFCNCT_BOOT		0x00000002
#define	FCFCNCT_PRIMARY		0x00000004
#define	FCFCNCT_FBNM_VALID	0x00000008
#define	FCFCNCT_SWNM_VALID	0x00000010
#define	FCFCNCT_VLAN_VALID	0x00000020
#define	FCFCNCT_MASK		0xFFFFFF00

	uint16_t	vlan_id;
	uint8_t		fabric_name[8];
	uint8_t		switch_name[8];
	uint8_t		reserved[2];
} DFC_FCoEFCFConnectEntry_t;

typedef struct DFC_FCoEFCFConnectList
{
	uint8_t				version;
#define	DFC_FCoE_FCFCONNECTLIST_VERSION	1

	uint8_t				reserved;
	uint8_t				numberOfEntries;
	uint8_t				maxNumOfEntries;
	DFC_FCoEFCFConnectEntry_t	entries[1];
} DFC_FCoEFCFConnectList_t;

typedef struct DFC_FCoEFCFInfo
{
	uint8_t		FabricName[8];
	uint8_t		SwitchName[8];
	uint8_t		Mac[6];
	uint16_t	State;
#define	FCF_AVAILABLE_STATE	0x1

	uint8_t		VLanBitMap[512];
	uint8_t		FC_Map[3];
	uint8_t		reserved1;
	uint32_t	LKA_Period;
	uint32_t	reserved2;
	uint32_t	Priority;
} DFC_FCoEFCFInfo_t;

typedef struct DFC_FCoEFCFList
{
	uint8_t		version;
#define	DFC_FCoE_FCFLIST_VERSION	1

	uint8_t			reserved[3];
	uint16_t		numberOfEntries;
	uint16_t		nActiveFCFs;
	DFC_FCoEFCFInfo_t	entries[1];
} DFC_FCoEFCFList_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_DFCLIB_H */
