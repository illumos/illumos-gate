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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_MBOX_H
#define	_EMLXS_MBOX_H

#ifdef	__cplusplus
extern "C" {
#endif

/* SLI 2/3 Mailbox defines */

#define	MBOX_SIZE			256
#define	MBOX_EXTENSION_OFFSET		MBOX_SIZE

#ifdef MBOX_EXT_SUPPORT
#define	MBOX_EXTENSION_SIZE		1024
#else
#define	MBOX_EXTENSION_SIZE		0
#endif /* MBOX_EXT_SUPPORT */



/* ==== Mailbox Commands ==== */
#define	MBX_SHUTDOWN			0x00	/* terminate testing */
#define	MBX_LOAD_SM			0x01
#define	MBX_READ_NV			0x02
#define	MBX_WRITE_NV			0x03
#define	MBX_RUN_BIU_DIAG		0x04
#define	MBX_INIT_LINK			0x05
#define	MBX_DOWN_LINK			0x06
#define	MBX_CONFIG_LINK			0x07
#define	MBX_PART_SLIM			0x08
#define	MBX_CONFIG_RING			0x09
#define	MBX_RESET_RING			0x0A
#define	MBX_READ_CONFIG			0x0B
#define	MBX_READ_RCONFIG		0x0C
#define	MBX_READ_SPARM			0x0D
#define	MBX_READ_STATUS			0x0E
#define	MBX_READ_RPI			0x0F
#define	MBX_READ_XRI			0x10
#define	MBX_READ_REV			0x11
#define	MBX_READ_LNK_STAT		0x12
#define	MBX_REG_LOGIN			0x13
#define	MBX_UNREG_LOGIN			0x14  /* SLI2/3 */
#define	MBX_UNREG_RPI			0x14  /* SLI4 */
#define	MBX_READ_LA			0x15
#define	MBX_CLEAR_LA			0x16
#define	MBX_DUMP_MEMORY			0x17
#define	MBX_DUMP_CONTEXT		0x18
#define	MBX_RUN_DIAGS			0x19
#define	MBX_RESTART			0x1A
#define	MBX_UPDATE_CFG			0x1B
#define	MBX_DOWN_LOAD			0x1C
#define	MBX_DEL_LD_ENTRY		0x1D
#define	MBX_RUN_PROGRAM			0x1E
#define	MBX_SET_MASK			0x20
#define	MBX_SET_VARIABLE		0x21
#define	MBX_UNREG_D_ID			0x23
#define	MBX_KILL_BOARD			0x24
#define	MBX_CONFIG_FARP			0x25
#define	MBX_BEACON			0x2A
#define	MBX_READ_VPI			0x2B
#define	MBX_CONFIG_MSIX			0x30
#define	MBX_HEARTBEAT			0x31
#define	MBX_WRITE_VPARMS		0x32
#define	MBX_ASYNC_EVENT			0x33

#define	MBX_READ_EVENT_LOG_STATUS	0x37
#define	MBX_READ_EVENT_LOG		0x38
#define	MBX_WRITE_EVENT_LOG		0x39
#define	MBX_NV_LOG			0x3A
#define	MBX_PORT_CAPABILITIES		0x3B
#define	MBX_IOV_CONTROL			0x3C
#define	MBX_IOV_MBX			0x3D


#define	MBX_CONFIG_HBQ			0x7C  /* SLI3 */
#define	MBX_LOAD_AREA			0x81
#define	MBX_RUN_BIU_DIAG64		0x84
#define	MBX_GET_DEBUG			0x86
#define	MBX_CONFIG_PORT			0x88
#define	MBX_READ_SPARM64		0x8D
#define	MBX_READ_RPI64			0x8F
#define	MBX_CONFIG_MSI			0x90
#define	MBX_REG_LOGIN64			0x93 /* SLI2/3 */
#define	MBX_REG_RPI			0x93 /* SLI4 */
#define	MBX_READ_LA64			0x95 /* SLI2/3 */
#define	MBX_READ_TOPOLOGY		0x95 /* SLI4 */
#define	MBX_REG_VPI			0x96 /* NPIV */
#define	MBX_UNREG_VPI			0x97 /* NPIV */
#define	MBX_FLASH_WR_ULA		0x98
#define	MBX_SET_DEBUG			0x99
#define	MBX_SLI_CONFIG			0x9B
#define	MBX_LOAD_EXP_ROM		0x9C
#define	MBX_REQUEST_FEATURES		0x9D
#define	MBX_RESUME_RPI			0x9E
#define	MBX_REG_VFI			0x9F
#define	MBX_REG_FCFI			0xA0
#define	MBX_UNREG_VFI			0xA1
#define	MBX_UNREG_FCFI			0xA2
#define	MBX_INIT_VFI			0xA3
#define	MBX_INIT_VPI			0xA4
#define	MBX_ACCESS_VDATA		0xA5
#define	MBX_MAX_CMDS			0xA6


/*
 * Define Status
 */
#define	MBX_SUCCESS			0x0
#define	MBX_FAILURE			0x1
#define	MBXERR_NUM_IOCBS		0x2
#define	MBXERR_IOCBS_EXCEEDED		0x3
#define	MBXERR_BAD_RING_NUMBER		0x4
#define	MBXERR_MASK_ENTRIES_RANGE	0x5
#define	MBXERR_MASKS_EXCEEDED		0x6
#define	MBXERR_BAD_PROFILE		0x7
#define	MBXERR_BAD_DEF_CLASS		0x8
#define	MBXERR_BAD_MAX_RESPONDER	0x9
#define	MBXERR_BAD_MAX_ORIGINATOR	0xA
#define	MBXERR_RPI_REGISTERED		0xB
#define	MBXERR_RPI_FULL			0xC
#define	MBXERR_NO_RESOURCES		0xD
#define	MBXERR_BAD_RCV_LENGTH		0xE
#define	MBXERR_DMA_ERROR		0xF
#define	MBXERR_NOT_SUPPORTED		0x10
#define	MBXERR_UNSUPPORTED_FEATURE	0x11
#define	MBXERR_UNKNOWN_COMMAND		0x12
#define	MBXERR_BAD_IP_BIT		0x13
#define	MBXERR_BAD_PCB_ALIGN		0x14
#define	MBXERR_BAD_HBQ_ID		0x15
#define	MBXERR_BAD_HBQ_STATE		0x16
#define	MBXERR_BAD_HBQ_MASK_NUM		0x17
#define	MBXERR_BAD_HBQ_MASK_SUBSET	0x18
#define	MBXERR_HBQ_CREATE_FAIL		0x19
#define	MBXERR_HBQ_EXISTING		0x1A
#define	MBXERR_HBQ_RSPRING_FULL		0x1B
#define	MBXERR_HBQ_DUP_MASK		0x1C
#define	MBXERR_HBQ_INVAL_GET_PTR	0x1D
#define	MBXERR_BAD_HBQ_SIZE		0x1E
#define	MBXERR_BAD_HBQ_ORDER		0x1F
#define	MBXERR_INVALID_ID		0x20

#define	MBXERR_INVALID_VFI		0x30

#define	MBXERR_FLASH_WRITE_FAILED	0x100

#define	MBXERR_INVALID_LINKSPEED	0x500

#define	MBXERR_BAD_REDIRECT		0x900
#define	MBXERR_RING_ALREADY_CONFIG	0x901

#define	MBXERR_RING_INACTIVE		0xA00

#define	MBXERR_RPI_INACTIVE		0xF00

#define	MBXERR_NO_ACTIVE_XRI		0x1100
#define	MBXERR_XRI_NOT_ACTIVE		0x1101

#define	MBXERR_RPI_INUSE		0x1400

#define	MBXERR_NO_LINK_ATTENTION	0x1500

#define	MBXERR_INVALID_SLI_MODE		0x8800
#define	MBXERR_INVALID_HOST_PTR		0x8801
#define	MBXERR_CANT_CFG_SLI_MODE	0x8802
#define	MBXERR_BAD_OVERLAY		0x8803
#define	MBXERR_INVALID_FEAT_REQ		0x8804

#define	MBXERR_CONFIG_CANT_COMPLETE	0x88FF

#define	MBXERR_DID_ALREADY_REGISTERED	0x9600
#define	MBXERR_DID_INCONSISTENT		0x9601
#define	MBXERR_VPI_TOO_LARGE		0x9603

#define	MBXERR_STILL_ASSOCIATED		0x9700

#define	MBXERR_INVALID_VF_STATE		0x9F00
#define	MBXERR_VFI_ALREADY_REGISTERED	0x9F02
#define	MBXERR_VFI_TOO_LARGE		0x9F03

#define	MBXERR_LOAD_FW_FAILED		0xFFFE
#define	MBXERR_FIND_FW_FAILED		0xFFFF

/* Driver special codes */
#define	MBX_DRIVER_RESERVED		0xF9 /* Set to lowest drv status */
#define	MBX_NONEMBED_ERROR		0xF9
#define	MBX_OVERTEMP_ERROR		0xFA
#define	MBX_HARDWARE_ERROR		0xFB
#define	MBX_DRVR_ERROR			0xFC
#define	MBX_BUSY			0xFD
#define	MBX_TIMEOUT			0xFE
#define	MBX_NOT_FINISHED		0xFF

/*
 * flags for EMLXS_SLI_ISSUE_MBOX_CMD()
 */
#define	MBX_POLL	0x01	/* poll mailbox till command done, */
				/* then return */
#define	MBX_SLEEP	0x02	/* sleep till mailbox intr cmpl */
				/* wakes thread up */
#define	MBX_WAIT	0x03	/* wait for comand done, then return */
#define	MBX_NOWAIT	0x04	/* issue command then return immediately */
#define	MBX_BOOTSTRAP	0x80	/* issue a command on the bootstrap mbox */



/*
 * Begin Structure Definitions for Mailbox Commands
 */

typedef struct revcompat
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	ldflag:1;	/* Set in SRAM descriptor */
	uint32_t	ldcount:7;	/* For use by program load */
	uint32_t	kernel:4;	/* Kernel ID */
	uint32_t	kver:4;	/* Kernel compatibility version */
	uint32_t	SMver:4;	/* Sequence Manager version */
					/* 0 if none */
	uint32_t	ENDECver:4;	/* ENDEC+ version, 0 if none */
	uint32_t	BIUtype:4;	/* PCI = 0 */
	uint32_t	BIUver:4;	/* BIU version, 0 if none */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	BIUver:4;	/* BIU version, 0 if none */
	uint32_t	BIUtype:4;	/* PCI = 0 */
	uint32_t	ENDECver:4;	/* ENDEC+ version, 0 if none */
	uint32_t	SMver:4;	/* Sequence Manager version */
					/* 0 if none */
	uint32_t	kver:4;	/* Kernel compatibility version */
	uint32_t	kernel:4;	/* Kernel ID */
	uint32_t	ldcount:7;	/* For use by program load */
	uint32_t	ldflag:1;	/* Set in SRAM descriptor */
#endif
} REVCOMPAT;

typedef struct id_word
{
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		Type;
	uint8_t		Id;
	uint8_t		Ver;
	uint8_t		Rev;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		Rev;
	uint8_t		Ver;
	uint8_t		Id;
	uint8_t		Type;
#endif
	union
	{
		REVCOMPAT	cp;
		uint32_t	revcomp;
	} un;
} PROG_ID;

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		tval;
	uint8_t		tmask;
	uint8_t		rval;
	uint8_t		rmask;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		rmask;
	uint8_t		rval;
	uint8_t		tmask;
	uint8_t		tval;
#endif
} RR_REG;


/* Structure used for a HBQ entry */
typedef struct
{
	ULP_BDE64	bde;
	union UN_TAG
	{
		uint32_t	w;
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	HBQ_tag:4;
			uint32_t	HBQE_tag:28;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	HBQE_tag:28;
			uint32_t	HBQ_tag:4;
#endif
		} ext;
	} unt;
} HBQE_t;

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		tmatch;
	uint8_t		tmask;
	uint8_t		rctlmatch;
	uint8_t		rctlmask;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		rctlmask;
	uint8_t		rctlmatch;
	uint8_t		tmask;
	uint8_t		tmatch;
#endif
} HBQ_MASK;

#define	EMLXS_MAX_HBQ_BUFFERS	4096

typedef struct
{
	uint32_t	HBQ_num_mask;		/* number of mask entries in */
						/* port array */
	uint32_t	HBQ_recvNotify;		/* Rcv buffer notification */
	uint32_t	HBQ_numEntries;		/* # of entries in HBQ */
	uint32_t	HBQ_headerLen;		/* 0 if not profile 4 or 5 */
	uint32_t	HBQ_logEntry;		/* Set to 1 if this HBQ used */
						/* for LogEntry */
	uint32_t	HBQ_profile;		/* Selection profile 0=all, */
						/* 7=logentry */
	uint32_t	HBQ_ringMask;		/* Binds HBQ to a ring e.g. */
						/* Ring0=b0001, ring2=b0100 */
	uint32_t	HBQ_id;			/* index of this hbq in ring */
						/* of HBQs[] */
	uint32_t	HBQ_PutIdx_next;	/* Index to next HBQ slot to */
						/* use */
	uint32_t	HBQ_PutIdx;		/* HBQ slot to use */
	uint32_t	HBQ_GetIdx;		/* Local copy of Get index */
						/* from Port */
	uint16_t	HBQ_PostBufCnt;		/* Current number of entries */
						/* in list */
	MATCHMAP	*HBQ_PostBufs[EMLXS_MAX_HBQ_BUFFERS];
	MATCHMAP	HBQ_host_buf;		/* HBQ host buffer for HBQEs */
	HBQ_MASK	HBQ_Masks[6];

	union
	{
		uint32_t	allprofiles[12];

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	seqlenoff:16;
			uint32_t	maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	maxlen:16;
			uint32_t	seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	rsvd1:28;
			uint32_t	seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	seqlenbcnt:4;
			uint32_t	rsvd1:28;
#endif
			uint32_t	rsvd[10];
		} profile2;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	seqlenoff:16;
			uint32_t	maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	maxlen:16;
			uint32_t	seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	cmdcodeoff:28;
			uint32_t	rsvd1:12;
			uint32_t	seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	seqlenbcnt:4;
			uint32_t	rsvd1:12;
			uint32_t	cmdcodeoff:28;
#endif
			uint32_t	cmdmatch[8];

			uint32_t	rsvd[2];
		} profile3;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	seqlenoff:16;
			uint32_t	maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	maxlen:16;
			uint32_t	seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	cmdcodeoff:28;
			uint32_t	rsvd1:12;
			uint32_t	seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	seqlenbcnt:4;
			uint32_t	rsvd1:12;
			uint32_t	cmdcodeoff:28;
#endif
			uint32_t	cmdmatch[8];

			uint32_t	rsvd[2];
		} profile5;
	} profiles;
} HBQ_INIT_t;



/* Structure for MB Command LOAD_SM and DOWN_LOAD */


typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd2:24;
	uint32_t	keep:1;
	uint32_t	acknowledgment:1;
	uint32_t	version:1;
	uint32_t	erase_or_prog:1;
	uint32_t	update_flash:1;
	uint32_t	update_ram:1;
	uint32_t	method:1;
	uint32_t	load_cmplt:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	load_cmplt:1;
	uint32_t	method:1;
	uint32_t	update_ram:1;
	uint32_t	update_flash:1;
	uint32_t	erase_or_prog:1;
	uint32_t	version:1;
	uint32_t	acknowledgment:1;
	uint32_t	keep:1;
	uint32_t	rsvd2:24;
#endif

#define	DL_FROM_BDE	0	/* method */
#define	DL_FROM_SLIM	1

#define	PROGRAM_FLASH	0	/* erase_or_prog */
#define	ERASE_FLASH	1

	uint32_t	dl_to_adr;
	uint32_t	dl_len;
	union
	{
		uint32_t	dl_from_slim_offset;
		ULP_BDE		dl_from_bde;
		ULP_BDE64	dl_from_bde64;
		PROG_ID		prog_id;
	} un;
} LOAD_SM_VAR;


/* Structure for MB Command READ_NVPARM (02) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
	uint32_t	rsvd1[3];	/* Read as all one's */
	uint32_t	rsvd2;		/* Read as all zero's */
	uint32_t	portname[2];	/* N_PORT name */
	uint32_t	nodename[2];	/* NODE name */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	pref_DID:24;
	uint32_t	hardAL_PA:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	hardAL_PA:8;
	uint32_t	pref_DID:24;
#endif
	uint32_t	rsvd3[21];	/* Read as all one's */
} READ_NV_VAR;


/* Structure for MB Command WRITE_NVPARMS (03) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
	uint32_t	rsvd1[3];	/* Must be all one's */
	uint32_t	rsvd2;		/* Must be all zero's */
	uint32_t	portname[2];	/* N_PORT name */
	uint32_t	nodename[2];	/* NODE name */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	pref_DID:24;
	uint32_t	hardAL_PA:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	hardAL_PA:8;
	uint32_t	pref_DID:24;
#endif
	uint32_t	rsvd3[21];	/* Must be all one's */
} WRITE_NV_VAR;


/* Structure for MB Command RUN_BIU_DIAG64 (0x84) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
	uint32_t	rsvd1;
	union
	{
		struct
		{
			ULP_BDE64	xmit_bde64;
			ULP_BDE64	rcv_bde64;
		} s2;
	} un;
} BIU_DIAG_VAR;


/* Structure for MB Command INIT_LINK (05) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd1:24;
	uint32_t	lipsr_AL_PA:8;	/* AL_PA to issue Lip Selective */
					/* Reset to */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	lipsr_AL_PA:8;	/* AL_PA to issue Lip Selective */
					/* Reset to */
	uint32_t	rsvd1:24;
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint8_t		fabric_AL_PA;	/* If using a Fabric Assigned AL_PA */
	uint8_t		rsvd2;
	uint16_t	link_flags;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	link_flags;
	uint8_t		rsvd2;
	uint8_t		fabric_AL_PA;	/* If using a Fabric Assigned AL_PA */
#endif
#define	FLAGS_LOCAL_LB			0x01	/* link_flags (=1) */
						/* ENDEC loopback */
#define	FLAGS_TOPOLOGY_MODE_LOOP_PT	0x00	/* Attempt loop then pt-pt */
#define	FLAGS_TOPOLOGY_MODE_PT_PT	0x02	/* Attempt pt-pt only */
#define	FLAGS_TOPOLOGY_MODE_LOOP	0x04	/* Attempt loop only */
#define	FLAGS_TOPOLOGY_MODE_PT_LOOP	0x06	/* Attempt pt-pt then loop */
#define	FLAGS_LIRP_LILP			0x80	/* LIRP / LILP is disabled */

#define	FLAGS_TOPOLOGY_FAILOVER		0x0400	/* Bit 10 */
#define	FLAGS_LINK_SPEED		0x0800	/* Bit 11 */
#define	FLAGS_PREABORT_RETURN		0x4000	/* Bit 14 */

	uint32_t	link_speed;	/* NEW_FEATURE */
#define	LINK_SPEED_AUTO			0	/* Auto selection */
#define	LINK_SPEED_1G			1	/* 1 Gigabaud */
#define	LINK_SPEED_2G			2	/* 2 Gigabaud */
} INIT_LINK_VAR;


/* Structure for MB Command DOWN_LINK (06) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
	uint32_t	rsvd1;
} DOWN_LINK_VAR;


/* Structure for MB Command CONFIG_LINK (07) */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	cr:1;
	uint32_t	ci:1;
	uint32_t	cr_delay:6;
	uint32_t	cr_count:8;
	uint32_t	rsvd1:8;
	uint32_t	MaxBBC:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	MaxBBC:8;
	uint32_t	rsvd1:8;
	uint32_t	cr_count:8;
	uint32_t	cr_delay:6;
	uint32_t	ci:1;
	uint32_t	cr:1;
#endif
	uint32_t	myId;
	uint32_t	rsvd2;
	uint32_t	edtov;
	uint32_t	arbtov;
	uint32_t	ratov;
	uint32_t	rttov;
	uint32_t	altov;
	uint32_t	crtov;
	uint32_t	citov;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rrq_enable:1;
	uint32_t	rrq_immed:1;
	uint32_t	rsvd4:29;
	uint32_t	ack0_enable:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	ack0_enable:1;
	uint32_t	rsvd4:29;
	uint32_t	rrq_immed:1;
	uint32_t	rrq_enable:1;
#endif
} CONFIG_LINK;


/* Structure for MB Command PART_SLIM (08) */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t		unused1:24;
	uint32_t		numRing:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t		numRing:8;
	uint32_t		unused1:24;
#endif
	emlxs_ring_def_t	ringdef[4];
	uint32_t		hbainit;
} PART_SLIM_VAR;


/* Structure for MB Command CONFIG_RING (09) */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	unused2:6;
	uint32_t	recvSeq:1;
	uint32_t	recvNotify:1;
	uint32_t	numMask:8;
	uint32_t	profile:8;
	uint32_t	unused1:4;
	uint32_t	ring:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	ring:4;
	uint32_t	unused1:4;
	uint32_t	profile:8;
	uint32_t	numMask:8;
	uint32_t	recvNotify:1;
	uint32_t	recvSeq:1;
	uint32_t	unused2:6;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	maxRespXchg;
	uint16_t	maxOrigXchg;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	maxOrigXchg;
	uint16_t	maxRespXchg;
#endif
	RR_REG		rrRegs[6];
} CONFIG_RING_VAR;


/* Structure for MB Command RESET_RING (10) */

typedef struct
{
	uint32_t	ring_no;
} RESET_RING_VAR;


/* Structure for MB Command READ_CONFIG (11) */
/* Good for SLI2/3 only */

typedef struct
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

#define	LMT_1GB_CAPABLE		0x0004
#define	LMT_2GB_CAPABLE		0x0008
#define	LMT_4GB_CAPABLE		0x0040
#define	LMT_8GB_CAPABLE		0x0080
#define	LMT_10GB_CAPABLE	0x0100
#define	LMT_16GB_CAPABLE	0x0200
/* E2E supported on adapters >= 8GB */
#define	LMT_E2E_CAPABLE		(LMT_8GB_CAPABLE|LMT_10GB_CAPABLE)

	uint32_t	rsvd2;
	uint32_t	rsvd3;
	uint32_t	max_xri;
	uint32_t	max_iocb;
	uint32_t	max_rpi;
	uint32_t	avail_xri;
	uint32_t	avail_iocb;
	uint32_t	avail_rpi;
	uint32_t	max_vpi;
	uint32_t	max_alpa;
	uint32_t	rsvd4;
	uint32_t	avail_vpi;

} READ_CONFIG_VAR;


/* Structure for MB Command READ_CONFIG(0x11) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	extents:1;	/* Word 1 */
	uint32_t	rsvd1:31;

	uint32_t	topology:8;	/* Word 2 */
	uint32_t	rsvd2:15;
	uint32_t	ldv:1;
	uint32_t	link_type:2;
	uint32_t	link_number:6;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rsvd1:31;	/* Word 1 */
	uint32_t	extents:1;

	uint32_t	link_number:6;	/* Word 2 */
	uint32_t	link_type:2;
	uint32_t	ldv:1;
	uint32_t	rsvd2:15;
	uint32_t	topology:8;
#endif
	uint32_t	rsvd3;		/* Word 3 */
	uint32_t	edtov;		/* Word 4 */
	uint32_t	rsvd4;		/* Word 5 */
	uint32_t	ratov;		/* Word 6 */
	uint32_t	rsvd5;		/* Word 7 */
	uint32_t	rsvd6;		/* Word 8 */
	uint32_t	lmt;		/* Word 9 */
	uint32_t	rsvd8;		/* Word 10 */
	uint32_t	rsvd9;		/* Word 11 */

#ifdef EMLXS_BIG_ENDIAN
	uint16_t	XRICount;	/* Word 12 */
	uint16_t	XRIBase;	/* Word 12 */

	uint16_t	RPICount;	/* Word 13 */
	uint16_t	RPIBase;	/* Word 13 */

	uint16_t	VPICount;	/* Word 14 */
	uint16_t	VPIBase;	/* Word 14 */

	uint16_t	VFICount;	/* Word 15 */
	uint16_t	VFIBase;	/* Word 15 */

	uint16_t	FCFICount;	/* Word 16 */
	uint16_t	rsvd10;		/* Word 16 */

	uint16_t	EQCount;	/* Word 17 */
	uint16_t	RQCount;	/* Word 17 */

	uint16_t	CQCount;	/* Word 18 */
	uint16_t	WQCount;	/* Word 18 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	XRIBase;	/* Word 12 */
	uint16_t	XRICount;	/* Word 12 */

	uint16_t	RPIBase;	/* Word 13 */
	uint16_t	RPICount;	/* Word 13 */

	uint16_t	VPIBase;	/* Word 14 */
	uint16_t	VPICount;	/* Word 14 */

	uint16_t	VFIBase;	/* Word 15 */
	uint16_t	VFICount;	/* Word 15 */

	uint16_t	rsvd10;		/* Word 16 */
	uint16_t	FCFICount;	/* Word 16 */

	uint16_t	RQCount;	/* Word 17 */
	uint16_t	EQCount;	/* Word 17 */

	uint16_t	WQCount;	/* Word 18 */
	uint16_t	CQCount;	/* Word 18 */
#endif

} READ_CONFIG4_VAR;

/* Structure for MB Command READ_RCONFIG (12) */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd2:7;
	uint32_t	recvNotify:1;
	uint32_t	numMask:8;
	uint32_t	profile:8;
	uint32_t	rsvd1:4;
	uint32_t	ring:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	ring:4;
	uint32_t	rsvd1:4;
	uint32_t	profile:8;
	uint32_t	numMask:8;
	uint32_t	recvNotify:1;
	uint32_t	rsvd2:7;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	maxResp;
	uint16_t	maxOrig;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	maxOrig;
	uint16_t	maxResp;
#endif
	RR_REG		rrRegs[6];
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	cmdRingOffset;
	uint16_t	cmdEntryCnt;
	uint16_t	rspRingOffset;
	uint16_t	rspEntryCnt;
	uint16_t	nextCmdOffset;
	uint16_t	rsvd3;
	uint16_t	nextRspOffset;
	uint16_t	rsvd4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	cmdEntryCnt;
	uint16_t	cmdRingOffset;
	uint16_t	rspEntryCnt;
	uint16_t	rspRingOffset;
	uint16_t	rsvd3;
	uint16_t	nextCmdOffset;
	uint16_t	rsvd4;
	uint16_t	nextRspOffset;
#endif
} READ_RCONF_VAR;


/* Structure for MB Command READ_SPARM (13) */
/* Structure for MB Command READ_SPARM64 (0x8D) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
	uint32_t	rsvd1;
	uint32_t	rsvd2;
	union
	{
		ULP_BDE		sp;	/* This BDE points to SERV_PARM */
					/* structure */
		ULP_BDE64	sp64;
	} un;
	uint32_t	rsvd3;

#ifdef EMLXS_BIG_ENDIAN
	uint16_t	portNameCnt;
	uint16_t	portNameOffset;

	uint16_t	fabricNameCnt;
	uint16_t	fabricNameOffset;

	uint16_t	lportNameCnt;
	uint16_t	lportNameOffset;

	uint16_t	lfabricNameCnt;
	uint16_t	lfabricNameOffset;

#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	portNameOffset;
	uint16_t	portNameCnt;

	uint16_t	fabricNameOffset;
	uint16_t	fabricNameCnt;

	uint16_t	lportNameOffset;
	uint16_t	lportNameCnt;

	uint16_t	lfabricNameOffset;
	uint16_t	lfabricNameCnt;

#endif

} READ_SPARM_VAR;


/* Structure for MB Command READ_STATUS (14) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd1:31;
	uint32_t	clrCounters:1;

	uint16_t	activeXriCnt;
	uint16_t	activeRpiCnt;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	clrCounters:1;
	uint32_t	rsvd1:31;

	uint16_t	activeRpiCnt;
	uint16_t	activeXriCnt;
#endif
	uint32_t	xmitByteCnt;
	uint32_t	rcvByteCnt;
	uint32_t	xmitFrameCnt;
	uint32_t	rcvFrameCnt;
	uint32_t	xmitSeqCnt;
	uint32_t	rcvSeqCnt;
	uint32_t	totalOrigExchanges;
	uint32_t	totalRespExchanges;
	uint32_t	rcvPbsyCnt;
	uint32_t	rcvFbsyCnt;
} READ_STATUS_VAR;


/* Structure for MB Command READ_RPI (15) */
/* Structure for MB Command READ_RPI64 (0x8F) */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	nextRpi;
	uint16_t	reqRpi;
	uint32_t	rsvd2:8;
	uint32_t	DID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	reqRpi;
	uint16_t	nextRpi;
	uint32_t	DID:24;
	uint32_t	rsvd2:8;
#endif
	union
	{
		ULP_BDE		sp;
		ULP_BDE64	sp64;
	} un;
} READ_RPI_VAR;


/* Structure for MB Command READ_XRI (16) */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	nextXri;
	uint16_t	reqXri;
	uint16_t	rsvd1;
	uint16_t	rpi;
	uint32_t	rsvd2:8;
	uint32_t	DID:24;
	uint32_t	rsvd3:8;
	uint32_t	SID:24;
	uint32_t	rsvd4;
	uint8_t		seqId;
	uint8_t		rsvd5;
	uint16_t	seqCount;
	uint16_t	oxId;
	uint16_t	rxId;
	uint32_t	rsvd6:30;
	uint32_t	si:1;
	uint32_t	exchOrig:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	reqXri;
	uint16_t	nextXri;
	uint16_t	rpi;
	uint16_t	rsvd1;
	uint32_t	DID:24;
	uint32_t	rsvd2:8;
	uint32_t	SID:24;
	uint32_t	rsvd3:8;
	uint32_t	rsvd4;
	uint16_t	seqCount;
	uint8_t		rsvd5;
	uint8_t		seqId;
	uint16_t	rxId;
	uint16_t	oxId;
	uint32_t	exchOrig:1;
	uint32_t	si:1;
	uint32_t	rsvd6:30;
#endif
} READ_XRI_VAR;


/* Structure for MB Command READ_REV (17) */
/* Good for SLI2/3 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	cv:1;
	uint32_t	rr:1;
	uint32_t	co:1;
	uint32_t	rp:1;
	uint32_t	cv3:1;
	uint32_t	rf3:1;
	uint32_t	rsvd1:10;
	uint32_t	offset:14;
	uint32_t	rv:2;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rv:2;
	uint32_t	offset:14;
	uint32_t	rsvd1:10;
	uint32_t	rf3:1;
	uint32_t	cv3:1;
	uint32_t	rp:1;
	uint32_t	co:1;
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

	uint32_t	sliFwRev1;
	uint8_t		sliFwName1[16];
	uint32_t	sliFwRev2;
	uint8_t		sliFwName2[16];
} READ_REV_VAR;

/* Structure for MB Command READ_REV (17) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	Rsvd3:2;
	uint32_t	VPD:1;
	uint32_t	rsvd2:6;
	uint32_t	dcbxMode:2;
	uint32_t	FCoE:1;
	uint32_t	sliLevel:4;
	uint32_t	rsvd1:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rsvd1:16;
	uint32_t	sliLevel:4;
	uint32_t	FCoE:1;
	uint32_t	dcbxMode:2;
	uint32_t	rsvd2:6;
	uint32_t	VPD:1;
	uint32_t	Rsvd3:2;
#endif

	uint32_t	HwRev1;
	uint32_t	HwRev2;
	uint32_t	Rsvd4;
	uint32_t	HwRev3;

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

	uint32_t	Redboot;

	uint32_t	ARMFwId;
	uint8_t		ARMFwName[16];

	uint32_t	ULPFwId;
	uint8_t		ULPFwName[16];

	uint32_t	Rsvd6[30];

	ULP_BDE64	VPDBde;

	uint32_t	ReturnedVPDLength;

} READ_REV4_VAR;

#define	EMLXS_DCBX_MODE_CIN	0	/* Mapped to nonFIP mode */
#define	EMLXS_DCBX_MODE_CEE	1	/* Mapped to FIP mode */

/* Structure for MB Command READ_LINK_STAT (18) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
	uint32_t	rsvd1;
	uint32_t	linkFailureCnt;
	uint32_t	lossSyncCnt;

	uint32_t	lossSignalCnt;
	uint32_t	primSeqErrCnt;
	uint32_t	invalidXmitWord;
	uint32_t	crcCnt;
	uint32_t	primSeqTimeout;
	uint32_t	elasticOverrun;
	uint32_t	arbTimeout;

	uint32_t	rxBufCredit;
	uint32_t	rxBufCreditCur;

	uint32_t	txBufCredit;
	uint32_t	txBufCreditCur;

	uint32_t	EOFaCnt;
	uint32_t	EOFdtiCnt;
	uint32_t	EOFniCnt;
	uint32_t	SOFfCnt;
	uint32_t	DropAERCnt;
	uint32_t	DropRcv;
} READ_LNK_VAR;


/* Structure for MB Command REG_LOGIN (19) */
/* Structure for MB Command REG_LOGIN64 (0x93) */
/* Structure for MB Command REG_RPI (0x93) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	rsvd1;
	uint16_t	rpi;
	uint32_t	CI:1;
	uint32_t	rsvd2:1;
	uint32_t	TERP:1;
	uint32_t	rsvd3:4;
	uint32_t	update:1;
	uint32_t	did:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	rpi;
	uint16_t	rsvd1;
	uint32_t	did:24;
	uint32_t	update:1;
	uint32_t	rsvd3:4;
	uint32_t	TERP:1;
	uint32_t	rsvd2:1;
	uint32_t	CI:1;
#endif
	union
	{
		ULP_BDE		sp;
		ULP_BDE64	sp64;
	} un;

#ifdef EMLXS_BIG_ENDIAN
	uint16_t	rsvd6;
	uint16_t	vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	vpi;
	uint16_t	rsvd6;
#endif
} REG_LOGIN_VAR;

/* Word 30 contents for REG_LOGIN */
typedef union
{
	struct
	{
#ifdef EMLXS_BIG_ENDIAN
		uint16_t	rsvd1:12;
		uint16_t	class:4;
		uint16_t	xri;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
		uint16_t	xri;
		uint16_t	class:4;
		uint16_t	rsvd1:12;
#endif
	} f;
	uint32_t	word;
} REG_WD30;


/* Structure for MB Command UNREG_LOGIN (0x14) - SLI2/3 */
/* Structure for MB Command UNREG_RPI (0x14) - SLI4 */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	ll:2;		/* SLI4 only */
	uint16_t	rsvd1:14;
	uint16_t	rpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	rpi;
	uint16_t	rsvd1:14;
	uint16_t	ll:2;		/* SLI4 only */
#endif

	uint32_t	rsvd2;
	uint32_t	rsvd3;
	uint32_t	rsvd4;
	uint32_t	rsvd5;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	rsvd6;
	uint16_t	vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	vpi;
	uint16_t	rsvd6;
#endif
} UNREG_LOGIN_VAR;

/* Structure for MB Command REG_FCFI (0xA0) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	FCFI;
	uint16_t	InfoIndex;

	uint16_t	RQId0;
	uint16_t	RQId1;
	uint16_t	RQId2;
	uint16_t	RQId3;

	uint8_t		Id0_type;
	uint8_t		Id0_type_mask;
	uint8_t		Id0_rctl;
	uint8_t		Id0_rctl_mask;

	uint8_t		Id1_type;
	uint8_t		Id1_type_mask;
	uint8_t		Id1_rctl;
	uint8_t		Id1_rctl_mask;

	uint8_t		Id2_type;
	uint8_t		Id2_type_mask;
	uint8_t		Id2_rctl;
	uint8_t		Id2_rctl_mask;

	uint8_t		Id3_type;
	uint8_t		Id3_type_mask;
	uint8_t		Id3_rctl;
	uint8_t		Id3_rctl_mask;

	uint32_t	Rsvd1: 17;
	uint32_t	mam: 2;
	uint32_t	vv: 1;
	uint32_t	vlanTag: 12;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	InfoIndex;
	uint16_t	FCFI;

	uint16_t	RQId1;
	uint16_t	RQId0;
	uint16_t	RQId3;
	uint16_t	RQId2;

	uint8_t		Id0_rctl_mask;
	uint8_t		Id0_rctl;
	uint8_t		Id0_type_mask;
	uint8_t		Id0_type;

	uint8_t		Id1_rctl_mask;
	uint8_t		Id1_rctl;
	uint8_t		Id1_type_mask;
	uint8_t		Id1_type;

	uint8_t		Id2_rctl_mask;
	uint8_t		Id2_rctl;
	uint8_t		Id2_type_mask;
	uint8_t		Id2_type;

	uint8_t		Id3_rctl_mask;
	uint8_t		Id3_rctl;
	uint8_t		Id3_type_mask;
	uint8_t		Id3_type;

	uint32_t	vlanTag: 12;
	uint32_t	vv: 1;
	uint32_t	mam: 2;
	uint32_t	Rsvd1: 17;
#endif

}  REG_FCFI_VAR;

/* Defines for mam */
#define	EMLXS_REG_FCFI_MAM_SPMA	1	/* Server Provided MAC Address */
#define	EMLXS_REG_FCFI_MAM_FPMA	2	/* Fabric Provided MAC Address */

/* Structure for MB Command UNREG_FCFI (0xA2) */
/* Good for SLI4 only */

typedef struct
{
	uint32_t	Rsvd1;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	Rsvd2;
	uint16_t	FCFI;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	FCFI;
	uint16_t	Rsvd2;
#endif
}  UNREG_FCFI_VAR;

/* Structure for MB Command RESUME_RPI (0x9E) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	Rsvd1;
	uint16_t	RPI;

	uint32_t	EventTag;
	uint32_t	rsvd2[3];

	uint16_t	VFI;
	uint16_t	VPI;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	RPI;
	uint16_t	Rsvd1;

	uint32_t	EventTag;
	uint32_t	rsvd2[3];

	uint16_t	VPI;
	uint16_t	VFI;
#endif

}  RESUME_RPI_VAR;


/* Structure for MB Command UNREG_D_ID (0x23) */

typedef struct
{
	uint32_t	did;

	uint32_t	rsvd2;
	uint32_t	rsvd3;
	uint32_t	rsvd4;
	uint32_t	rsvd5;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	rsvd6;
	uint16_t	vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	vpi;
	uint16_t	rsvd6;
#endif
} UNREG_D_ID_VAR;


/* Structure for MB Command READ_LA (21) */
/* Structure for MB Command READ_LA64 (0x95) */

typedef struct
{
	uint32_t	eventTag;	/* Event tag */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd2:19;
	uint32_t	fa:1;
	uint32_t	mm:1;
	uint32_t	tc:1;
	uint32_t	pb:1;
	uint32_t	il:1;
	uint32_t	attType:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	attType:8;
	uint32_t	il:1;
	uint32_t	pb:1;
	uint32_t	tc:1;
	uint32_t	mm:1;
	uint32_t	fa:1;
	uint32_t	rsvd2:19;
#endif
#define	AT_RESERVED	0x00	/* Reserved - attType */
#define	AT_LINK_UP	0x01	/* Link is up */
#define	AT_LINK_DOWN	0x02	/* Link is down */
#define	AT_NO_HARD_ALPA	0x03	/* SLI4 */

#ifdef EMLXS_BIG_ENDIAN
	uint8_t		granted_AL_PA;
	uint8_t		lipAlPs;
	uint8_t		lipType;
	uint8_t		topology;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		topology;
	uint8_t		lipType;
	uint8_t		lipAlPs;
	uint8_t		granted_AL_PA;
#endif

	/* lipType */
#define	LT_PORT_INIT	0x00	/* An L_PORT initing (F7, AL_PS) - lipType */
#define	LT_PORT_ERR	0x01	/* Err @L_PORT rcv'er (F8, AL_PS) */
#define	LT_RESET_APORT	0x02	/* Lip Reset of some other port */
#define	LT_RESET_MYPORT	0x03	/* Lip Reset of my port */

	/* topology */
#define	TOPOLOGY_PT_PT	0x01	/* Topology is pt-pt / pt-fabric */
#define	TOPOLOGY_LOOP	0x02	/* Topology is FC-AL (private) */

	union
	{
		ULP_BDE		lilpBde;	/* This BDE points to a */
						/* 128 byte buffer to store */
						/* the LILP AL_PA position */
						/* map into */
		ULP_BDE64	lilpBde64;
	} un;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	Dlu:1;
	uint32_t	Dtf:1;
	uint32_t	Drsvd2:14;
	uint32_t	DlnkSpeed:8;
	uint32_t	DnlPort:4;
	uint32_t	Dtx:2;
	uint32_t	Drx:2;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	Drx:2;
	uint32_t	Dtx:2;
	uint32_t	DnlPort:4;
	uint32_t	DlnkSpeed:8;
	uint32_t	Drsvd2:14;
	uint32_t	Dtf:1;
	uint32_t	Dlu:1;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	Ulu:1;
	uint32_t	Utf:1;
	uint32_t	Ursvd2:14;
	uint32_t	UlnkSpeed:8;
	uint32_t	UnlPort:4;
	uint32_t	Utx:2;
	uint32_t	Urx:2;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	Urx:2;
	uint32_t	Utx:2;
	uint32_t	UnlPort:4;
	uint32_t	UlnkSpeed:8;
	uint32_t	Ursvd2:14;
	uint32_t	Utf:1;
	uint32_t	Ulu:1;
#endif
#define	LA_1GHZ_LINK   0x04	/* lnkSpeed */
#define	LA_2GHZ_LINK   0x08	/* lnkSpeed */
#define	LA_4GHZ_LINK   0x10	/* lnkSpeed */
#define	LA_8GHZ_LINK   0x20	/* lnkSpeed */
#define	LA_10GHZ_LINK  0x40	/* lnkSpeed */
#define	LA_16GHZ_LINK  0x80	/* lnkSpeed */
} READ_LA_VAR;


/* Structure for MB Command CLEAR_LA (22) */

typedef struct
{
	uint32_t	eventTag;	/* Event tag */
	uint32_t	rsvd1;
} CLEAR_LA_VAR;

/* Structure for MB Command DUMP */
/* Good for SLI2/3 only */

typedef struct
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
} DUMP_VAR;

/* Structure for MB Command DUMP */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	ppi:4;
	uint32_t	phy_index:4;
	uint32_t	rsvd:20;
	uint32_t	type:4;

	uint32_t	entry_index:16;
	uint32_t	region_id:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	type:4;
	uint32_t	rsvd:20;
	uint32_t	phy_index:4;
	uint32_t	ppi:4;

	uint32_t	region_id:16;
	uint32_t	entry_index:16;
#endif
	uint32_t	available_cnt;
	uint32_t	addrLow;
	uint32_t	addrHigh;
	uint32_t	rsp_cnt;
} DUMP4_VAR;

/*
 * Dump type
 */
#define	DMP_MEM_REG	0x1
#define	DMP_NV_PARAMS	0x2

/*
 * Dump region ID
 */
#define	NODE_CFG_A_REGION_ID	0
#define	NODE_CFG_B_REGION_ID	1
#define	NODE_CFG_C_REGION_ID	2
#define	NODE_CFG_D_REGION_ID	3
#define	WAKE_UP_PARMS_REGION_ID	4
#define	DEF_PCI_CFG_REGION_ID	5
#define	PCI_CFG_1_REGION_ID	6
#define	PCI_CFG_2_REGION_ID	7
#define	RSVD1_REGION_ID		8
#define	RSVD2_REGION_ID		9
#define	RSVD3_REGION_ID		10
#define	RSVD4_REGION_ID		11
#define	RSVD5_REGION_ID		12
#define	RSVD6_REGION_ID		13
#define	RSVD7_REGION_ID		14
#define	DIAG_TRACE_REGION_ID	15
#define	WWN_REGION_ID		16

#define	DMP_VPD_REGION		14
#define	DMP_VPD_SIZE		1024
#define	DMP_VPD_DUMP_WCOUNT	24

#define	DMP_FCOE_REGION		23
#define	DMP_FCOE_DUMP_WCOUNT	256


/* Structure for MB Command UPDATE_CFG */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd2:16;
	uint32_t	proc_type:8;
	uint32_t	rsvd1:1;
	uint32_t	Abit:1;
	uint32_t	Obit:1;
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
	uint32_t	Obit:1;
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
} UPDATE_CFG_VAR;

/* Structure for MB Command DEL_LD_ENTRY (29) */

typedef struct
{
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	list_req:2;
	uint32_t	list_rsp:2;
	uint32_t	rsvd:28;
#else
	uint32_t	rsvd:28;
	uint32_t	list_rsp:2;
	uint32_t	list_req:2;
#endif

#define	FLASH_LOAD_LIST	1
#define	RAM_LOAD_LIST	2
#define	BOTH_LISTS	3

	PROG_ID		prog_id;
} DEL_LD_ENTRY_VAR;

/* Structure for MB Command LOAD_AREA (81) */
typedef struct
{
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	load_cmplt:1;
	uint32_t	method:1;
	uint32_t	rsvd1:1;
	uint32_t	update_flash:1;
	uint32_t	erase_or_prog:1;
	uint32_t	version:1;
	uint32_t	rsvd2:2;
	uint32_t	progress:8;
	uint32_t	step:8;
	uint32_t	area_id:8;
#else
	uint32_t	area_id:8;
	uint32_t	step:8;
	uint32_t	progress:8;
	uint32_t	rsvd2:2;
	uint32_t	version:1;
	uint32_t	erase_or_prog:1;
	uint32_t	update_flash:1;
	uint32_t	rsvd1:1;
	uint32_t	method:1;
	uint32_t	load_cmplt:1;
#endif
	uint32_t	dl_to_adr;
	uint32_t	dl_len;
	union
	{
		uint32_t	dl_from_slim_offset;
		ULP_BDE		dl_from_bde;
		ULP_BDE64	dl_from_bde64;
		PROG_ID		prog_id;
	} un;
} LOAD_AREA_VAR;

/* Structure for MB Command LOAD_EXP_ROM (9C) */
typedef struct
{
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rsvd1:8;
	uint32_t	progress:8;
	uint32_t	step:8;
	uint32_t	rsvd2:8;
#else
	uint32_t	rsvd2:8;
	uint32_t	step:8;
	uint32_t	progress:8;
	uint32_t	rsvd1:8;
#endif
	uint32_t	dl_to_adr;
	uint32_t	rsvd3;
	union
	{
		uint32_t	word[2];
		PROG_ID		prog_id;
	} un;
} LOAD_EXP_ROM_VAR;


/* Structure for MB Command CONFIG_HBQ (7C) */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd1:7;
	uint32_t	recvNotify:1;	/* Receive Notification */
	uint32_t	numMask:8;	/* # Mask Entries */
	uint32_t	profile:8;	/* Selection Profile */
	uint32_t	rsvd2:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rsvd2:8;
	uint32_t	profile:8;	/* Selection Profile */
	uint32_t	numMask:8;	/* # Mask Entries */
	uint32_t	recvNotify:1;	/* Receive Notification */
	uint32_t	rsvd1:7;
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	hbqId:16;
	uint32_t	rsvd3:12;
	uint32_t	ringMask:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	ringMask:4;
	uint32_t	rsvd3:12;
	uint32_t	hbqId:16;
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	numEntries:16;
	uint32_t	rsvd4:8;
	uint32_t	headerLen:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	headerLen:8;
	uint32_t	rsvd4:8;
	uint32_t	numEntries:16;
#endif

	uint32_t	hbqaddrLow;
	uint32_t	hbqaddrHigh;

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd5:31;
	uint32_t	logEntry:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	logEntry:1;
	uint32_t	rsvd5:31;
#endif

	uint32_t	rsvd6;	/* w7 */
	uint32_t	rsvd7;	/* w8 */
	uint32_t	rsvd8;	/* w9 */

	HBQ_MASK	hbqMasks[6];

	union
	{
		uint32_t	allprofiles[12];

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	seqlenoff:16;
			uint32_t	maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	maxlen:16;
			uint32_t	seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	rsvd1:28;
			uint32_t	seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	seqlenbcnt:4;
			uint32_t	rsvd1:28;
#endif
			uint32_t	rsvd[10];
		} profile2;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	seqlenoff:16;
			uint32_t	maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	maxlen:16;
			uint32_t	seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	cmdcodeoff:28;
			uint32_t	rsvd1:12;
			uint32_t	seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	seqlenbcnt:4;
			uint32_t	rsvd1:12;
			uint32_t	cmdcodeoff:28;
#endif
			uint32_t	cmdmatch[8];

			uint32_t	rsvd[2];
		} profile3;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	seqlenoff:16;
			uint32_t	maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	maxlen:16;
			uint32_t	seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	cmdcodeoff:28;
			uint32_t	rsvd1:12;
			uint32_t	seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	seqlenbcnt:4;
			uint32_t	rsvd1:12;
			uint32_t	cmdcodeoff:28;
#endif
			uint32_t	cmdmatch[8];

			uint32_t	rsvd[2];
		} profile5;
	} profiles;
} CONFIG_HBQ_VAR;


/* Structure for MB Command REG_VPI(0x96) */
/* Good for SLI2/3 and SLI4 */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd1;
	uint32_t	rsvd2:7;
	uint32_t	upd:1;
	uint32_t	sid:24;
	uint32_t	portname[2];    /* N_PORT name */
	uint32_t	rsvd5;
	uint16_t	vfi;
	uint16_t	vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rsvd1;
	uint32_t	sid:24;
	uint32_t	upd:1;
	uint32_t	rsvd2:7;
	uint32_t	portname[2];    /* N_PORT name */
	uint32_t	rsvd5;
	uint16_t	vpi;
	uint16_t	vfi;
#endif
} REG_VPI_VAR;

/* Structure for MB Command INIT_VPI(0xA3) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	vfi;
	uint16_t	vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	vpi;
	uint16_t	vfi;
#endif
} INIT_VPI_VAR;

/* Structure for MB Command UNREG_VPI (0x97) */
/* Good for SLI2/3 */

typedef struct
{
	uint32_t	rsvd1;
	uint32_t	rsvd2;
	uint32_t	rsvd3;
	uint32_t	rsvd4;
	uint32_t	rsvd5;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	rsvd6;
	uint16_t	vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	vpi;
	uint16_t	rsvd6;
#endif
} UNREG_VPI_VAR;

/* Structure for MB Command UNREG_VPI (0x97) */
/* Good for SLI4 */

typedef struct
{
	uint32_t	rsvd1;
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		ii:2;
	uint16_t	rsvd2:14;
	uint16_t	index;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	index;
	uint16_t	rsvd2:14;
	uint8_t		ii:2;
#endif
} UNREG_VPI_VAR4;

/* Structure for MB Command REG_VFI(0x9F) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	rsvd1:2;
	uint16_t	upd:1;
	uint16_t	vp:1;
	uint16_t	rsvd2:12;
	uint16_t	vfi;

	uint16_t	vpi;
	uint16_t	fcfi;

	uint32_t	portname[2];    /* N_PORT name */

	ULP_BDE64	bde;

/* CHANGE with next firmware drop */
	uint32_t	edtov;
	uint32_t	ratov;

	uint32_t	rsvd5:8;
	uint32_t	sid:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	vfi;
	uint16_t	rsvd2:12;
	uint16_t	vp:1;
	uint16_t	upd:1;
	uint16_t	rsvd1:2;

	uint16_t	fcfi;
	uint16_t	vpi;

	uint32_t	portname[2];    /* N_PORT name */

	ULP_BDE64	bde;

/* CHANGE with next firmware drop */
	uint32_t	edtov;
	uint32_t	ratov;

	uint32_t	sid:24;
	uint32_t	rsvd5:8;
#endif
} REG_VFI_VAR;

/* Structure for MB Command INIT_VFI(0xA4) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	vr:1;
	uint32_t	vt:1;
	uint32_t	vf:1;
	uint32_t	rsvd1:13;
	uint32_t	vfi:16;

	uint16_t	rsvd2;
	uint16_t	fcfi;

	uint32_t	rsvd3:16;
	uint32_t	pri:3;
	uint32_t	vf_id:12;
	uint32_t	rsvd4:1;

	uint32_t	hop_count:8;
	uint32_t	rsvd5:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	vfi:16;
	uint32_t	rsvd1:13;
	uint32_t	vf:1;
	uint32_t	vt:1;
	uint32_t	vr:1;

	uint16_t	fcfi;
	uint16_t	rsvd2;

	uint32_t	rsvd4:1;
	uint32_t	vf_id:12;
	uint32_t	pri:3;
	uint32_t	rsvd3:16;

	uint32_t	rsvd5:24;
	uint32_t	hop_count:8;
#endif
} INIT_VFI_VAR;

/* Structure for MB Command UNREG_VFI (0xA1) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd1:3;
	uint32_t	vp:1;
	uint32_t	rsvd2:28;

	uint16_t	vpi;
	uint16_t	vfi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rsvd2:28;
	uint32_t	vp:1;
	uint32_t	rsvd1:3;

	uint16_t	vfi;
	uint16_t	vpi;
#endif
} UNREG_VFI_VAR;



typedef struct
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
		ULP_BDE		sp;
		ULP_BDE64	sp64;
	} un;
} READ_EVT_LOG_VAR;

typedef struct
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
} LOG_STATUS_VAR;


/* Structure for MB Command CONFIG_PORT (0x88) */
typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	cBE:1;
	uint32_t	cET:1;
	uint32_t	cHpcb:1;
	uint32_t	rMA:1;
	uint32_t	sli_mode:4;
	uint32_t	pcbLen:24;	/* bit 23:0 of memory based port */
					/* config block */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	pcbLen:24;	/* bit 23:0 of memory based port */
					/* config block */
	uint32_t	sli_mode:4;
	uint32_t	rMA:1;
	uint32_t	cHpcb:1;
	uint32_t	cET:1;
	uint32_t	cBE:1;
#endif

	uint32_t	pcbLow;		/* bit 31:0 of memory based port */
					/* config block */
	uint32_t	pcbHigh; 	/* bit 63:32 of memory based port */
					/* config block */
	uint32_t	hbainit[5];

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	hps:1; /* Host pointers in SLIM */
	uint32_t	rsvd:31;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rsvd:31;
	uint32_t	hps:1; /* Host pointers in SLIM */
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd1:24;
	uint32_t	cmv:1;		/* Configure Max VPIs */
	uint32_t	ccrp:1;		/* Config Command Ring Polling */
	uint32_t	csah:1;		/* Configure Synchronous Abort */
					/* Handling */
	uint32_t	chbs:1;		/* Cofigure Host Backing store */
	uint32_t	cinb:1;		/* Enable Interrupt Notification */
					/* Block */
	uint32_t	cerbm:1;	/* Configure Enhanced Receive */
					/* Buffer Management */
	uint32_t	cmx:1;		/* Configure Max XRIs */
	uint32_t	cmr:1;		/* Configure Max RPIs */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	cmr:1;		/* Configure Max RPIs */
	uint32_t	cmx:1;		/* Configure Max XRIs */
	uint32_t	cerbm:1;	/* Configure Enhanced Receive */
					/* Buffer Management */
	uint32_t	cinb:1;		/* Enable Interrupt Notification */
					/* Block */
	uint32_t	chbs:1;		/* Cofigure Host Backing store */
	uint32_t	csah:1;		/* Configure Synchronous Abort */
					/* Handling */
	uint32_t	ccrp:1;		/* Config Command Ring Polling */
	uint32_t	cmv:1;		/* Configure Max VPIs */
	uint32_t	rsvd1:24;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd2:19;	/* Reserved */
	uint32_t	gdss:1;		/* Configure Data Security SLI */
	uint32_t	rsvd3:3;	/* Reserved */
	uint32_t	gbg:1;		/* Grant BlockGuard */
	uint32_t	gmv:1;		/* Grant Max VPIs */
	uint32_t	gcrp:1;		/* Grant Command Ring Polling */
	uint32_t	gsah:1;		/* Grant Synchronous Abort Handling */
	uint32_t	ghbs:1;		/* Grant Host Backing Store */
	uint32_t	ginb:1;		/* Grant Interrupt Notification Block */
	uint32_t	gerbm:1;	/* Grant ERBM Request */
	uint32_t	gmx:1;		/* Grant Max XRIs */
	uint32_t	gmr:1;		/* Grant Max RPIs */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	gmr:1;		/* Grant Max RPIs */
	uint32_t	gmx:1;		/* Grant Max XRIs */
	uint32_t	gerbm:1;	/* Grant ERBM Request */
	uint32_t	ginb:1;		/* Grant Interrupt Notification Block */
	uint32_t	ghbs:1;		/* Grant Host Backing Store */
	uint32_t	gsah:1;		/* Grant Synchronous Abort Handling */
	uint32_t	gcrp:1;		/* Grant Command Ring Polling */
	uint32_t	gmv:1;		/* Grant Max VPIs */
	uint32_t	gbg:1;		/* Grant BlockGuard */
	uint32_t	rsvd3:3;	/* Reserved */
	uint32_t	gdss:1;		/* Configure Data Security SLI */
	uint32_t	rsvd2:19;	/* Reserved */
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	max_rpi:16;	/* Max RPIs Port should configure */
	uint32_t	max_xri:16;	/* Max XRIs Port should configure */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	max_xri:16;	/* Max XRIs Port should configure */
	uint32_t	max_rpi:16;	/* Max RPIs Port should configure */
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	max_hbq:16;	/* Max HBQs Host expect to configure */
	uint32_t	rsvd4:16;	/* Max HBQs Host expect to configure */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	rsvd4:16;	/* Max HBQs Host expect to configure */
	uint32_t	max_hbq:16;	/* Max HBQs Host expect to configure */
#endif

	uint32_t	rsvd5;		/* Reserved */

#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd6:16;	/* Reserved */
	uint32_t	vpi_max:16;	/* Max number of virt N-Ports */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	vpi_max:16;	/* Max number of virt N-Ports */
	uint32_t	rsvd6:16;	/* Reserved */
#endif
} CONFIG_PORT_VAR;

/* Structure for MB Command REQUEST_FEATURES (0x9D) */
/* Good for SLI4 only */

typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd1:31;
	uint32_t	QueryMode:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	QueryMode:1;
	uint32_t	rsvd1:31;
#endif

	uint32_t	featuresRequested;
	uint32_t	featuresEnabled;

} REQUEST_FEATURES_VAR;

#define	SLI4_FEATURE_INHIBIT_AUTO_ABTS		0x0001
#define	SLI4_FEATURE_NPIV			0x0002
#define	SLI4_FEATURE_DIF			0x0004
#define	SLI4_FEATURE_VIRTUAL_FABRICS		0x0008
#define	SLI4_FEATURE_FCP_INITIATOR		0x0010
#define	SLI4_FEATURE_FCP_TARGET			0x0020
#define	SLI4_FEATURE_FCP_COMBO			0x0040
#define	SLI4_FEATURE_RSVD1			0x0080
#define	SLI4_FEATURE_RQD			0x0100
#define	SLI4_FEATURE_INHIBIT_AUTO_ABTS_R	0x0200
#define	SLI4_FEATURE_HIGH_LOGIN_MODE		0x0400
#define	SLI4_FEATURE_PERF_HINT			0x0800


/* SLI-2 Port Control Block */

/* SLIM POINTER */
#define	SLIMOFF	0x30	/* WORD */

typedef struct _SLI2_RDSC
{
	uint32_t	cmdEntries;
	uint32_t	cmdAddrLow;
	uint32_t	cmdAddrHigh;

	uint32_t	rspEntries;
	uint32_t	rspAddrLow;
	uint32_t	rspAddrHigh;
} SLI2_RDSC;

typedef struct _PCB
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	type:8;
#define	TYPE_NATIVE_SLI2	0x01;
	uint32_t	feature:8;
#define	FEATURE_INITIAL_SLI2	0x01;
	uint32_t	rsvd:12;
	uint32_t	maxRing:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	maxRing:4;
	uint32_t	rsvd:12;
	uint32_t	feature:8;
#define	FEATURE_INITIAL_SLI2	0x01;
	uint32_t	type:8;
#define	TYPE_NATIVE_SLI2	0x01;
#endif

	uint32_t	mailBoxSize;
	uint32_t	mbAddrLow;
	uint32_t	mbAddrHigh;

	uint32_t	hgpAddrLow;
	uint32_t	hgpAddrHigh;

	uint32_t	pgpAddrLow;
	uint32_t	pgpAddrHigh;
	SLI2_RDSC	rdsc[MAX_RINGS_AVAILABLE];
} PCB;

/* NEW_FEATURE */
typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	rsvd0:27;
	uint32_t	discardFarp:1;
	uint32_t	IPEnable:1;
	uint32_t	nodeName:1;
	uint32_t	portName:1;
	uint32_t	filterEnable:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	filterEnable:1;
	uint32_t	portName:1;
	uint32_t	nodeName:1;
	uint32_t	IPEnable:1;
	uint32_t	discardFarp:1;
	uint32_t	rsvd:27;
#endif
	NAME_TYPE	portname;
	NAME_TYPE	nodename;
	uint32_t	rsvd1;
	uint32_t	rsvd2;
	uint32_t	rsvd3;
	uint32_t	IPAddress;
} CONFIG_FARP_VAR;


/* NEW_FEATURE */
typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	defaultMessageNumber:16;
	uint32_t	rsvd1:3;
	uint32_t	nid:5;
	uint32_t	rsvd2:5;
	uint32_t	defaultPresent:1;
	uint32_t	addAssociations:1;
	uint32_t	reportAssociations:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	reportAssociations:1;
	uint32_t	addAssociations:1;
	uint32_t	defaultPresent:1;
	uint32_t	rsvd2:5;
	uint32_t	nid:5;
	uint32_t	rsvd1:3;
	uint32_t	defaultMessageNumber:16;
#endif
	uint32_t	attConditions;
	uint8_t		attentionId[16];
	uint16_t	messageNumberByHA[32];
	uint16_t	messageNumberByID[16];
	uint32_t	rsvd3;
} CONFIG_MSI_VAR;


/* NEW_FEATURE */
typedef struct
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	defaultMessageNumber:8;
	uint32_t	rsvd1:11;
	uint32_t	nid:5;
	uint32_t	rsvd2:5;
	uint32_t	defaultPresent:1;
	uint32_t	addAssociations:1;
	uint32_t	reportAssociations:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	reportAssociations:1;
	uint32_t	addAssociations:1;
	uint32_t	defaultPresent:1;
	uint32_t	rsvd2:5;
	uint32_t	nid:5;
	uint32_t	rsvd1:11;
	uint32_t	defaultMessageNumber:8;
#endif
	uint32_t	attConditions1;
	uint32_t	attConditions2;
	uint8_t		attentionId[16];
	uint8_t		messageNumberByHA[64];
	uint8_t		messageNumberByID[16];
	uint32_t	autoClearByHA1;
	uint32_t	autoClearByHA2;
	uint32_t	autoClearByID;
	uint32_t	resv3;
} CONFIG_MSIX_VAR;


/* Union of all Mailbox Command types */

typedef union
{
	uint32_t		varWords[31];
	LOAD_SM_VAR		varLdSM;	/* cmd =  1 (LOAD_SM) */
	READ_NV_VAR		varRDnvp;	/* cmd =  2 (READ_NVPARMS) */
	WRITE_NV_VAR		varWTnvp;	/* cmd =  3 (WRITE_NVPARMS) */
	BIU_DIAG_VAR		varBIUdiag;	/* cmd =  4 (RUN_BIU_DIAG) */
	INIT_LINK_VAR		varInitLnk;	/* cmd =  5 (INIT_LINK) */
	DOWN_LINK_VAR		varDwnLnk;	/* cmd =  6 (DOWN_LINK) */
	CONFIG_LINK		varCfgLnk;	/* cmd =  7 (CONFIG_LINK) */
	PART_SLIM_VAR		varSlim;	/* cmd =  8 (PART_SLIM) */
	CONFIG_RING_VAR		varCfgRing;	/* cmd =  9 (CONFIG_RING) */
	RESET_RING_VAR		varRstRing;	/* cmd = 10 (RESET_RING) */
	READ_CONFIG_VAR		varRdConfig;	/* cmd = 11 (READ_CONFIG) */
	READ_RCONF_VAR		varRdRConfig;	/* cmd = 12 (READ_RCONFIG) */
	READ_SPARM_VAR		varRdSparm;	/* cmd = 13 (READ_SPARM(64)) */
	READ_STATUS_VAR		varRdStatus;	/* cmd = 14 (READ_STATUS) */
	READ_RPI_VAR		varRdRPI;	/* cmd = 15 (READ_RPI(64)) */
	READ_XRI_VAR		varRdXRI;	/* cmd = 16 (READ_XRI) */
	READ_REV_VAR		varRdRev;	/* cmd = 17 (READ_REV) */
	READ_LNK_VAR		varRdLnk;	/* cmd = 18 (READ_LNK_STAT) */
	REG_LOGIN_VAR		varRegLogin;	/* cmd = 19 (REG_LOGIN(64)) */
	UNREG_LOGIN_VAR		varUnregLogin;	/* cmd = 20 (UNREG_LOGIN) */
	READ_LA_VAR		varReadLA;	/* cmd = 21 (READ_LA(64)) */
	CLEAR_LA_VAR		varClearLA;	/* cmd = 22 (CLEAR_LA) */
	DUMP_VAR		varDmp;		/* Warm Start DUMP mbx cmd */
	UPDATE_CFG_VAR		varUpdateCfg;	/* cmd = 0x1b Warm Start */
						/* UPDATE_CFG cmd */
	DEL_LD_ENTRY_VAR	varDelLdEntry;	/* cmd = 0x1d (DEL_LD_ENTRY) */
	UNREG_D_ID_VAR		varUnregDID;	/* cmd = 0x23 (UNREG_D_ID) */
	CONFIG_FARP_VAR		varCfgFarp;	/* cmd = 0x25 (CONFIG_FARP) */
	CONFIG_MSI_VAR		varCfgMSI;	/* cmd = 0x90 (CONFIG_MSI) */
	CONFIG_MSIX_VAR		varCfgMSIX;	/* cmd = 0x30 (CONFIG_MSIX) */
	CONFIG_HBQ_VAR		varCfgHbq;	/* cmd = 0x7C (CONFIG_HBQ) */
	LOAD_AREA_VAR		varLdArea;	/* cmd = 0x81 (LOAD_AREA) */
	CONFIG_PORT_VAR		varCfgPort;	/* cmd = 0x88 (CONFIG_PORT) */
	LOAD_EXP_ROM_VAR	varLdExpRom;	/* cmd = 0x9C (LOAD_XP_ROM) */
	REG_VPI_VAR		varRegVpi;	/* cmd = 0x96 (REG_VPI) */
	UNREG_VPI_VAR		varUnregVpi;	/* cmd = 0x97 (UNREG_VPI) */
	READ_EVT_LOG_VAR	varRdEvtLog;	/* cmd = 0x38 (READ_EVT_LOG) */
	LOG_STATUS_VAR		varLogStat;	/* cmd = 0x37 */

} MAILVARIANTS;

#define	MAILBOX_CMD_BSIZE	128
#define	MAILBOX_CMD_WSIZE	32

/*
 * SLI-2 specific structures
 */

typedef struct _SLI1_DESC
{
	emlxs_rings_t	mbxCring[4];
	uint32_t	mbxUnused[24];
} SLI1_DESC; /* 128 bytes */

typedef struct
{
	uint32_t	cmdPutInx;
	uint32_t	rspGetInx;
} HGP;

typedef struct
{
	uint32_t	cmdGetInx;
	uint32_t	rspPutInx;
} PGP;

typedef struct _SLI2_DESC
{
	HGP		host[4];
	PGP		port[4];
	uint32_t	HBQ_PortGetIdx[16];
} SLI2_DESC; /* 128 bytes */

typedef union
{
	SLI1_DESC	s1;	/* 32 words, 128 bytes */
	SLI2_DESC	s2;	/* 32 words, 128 bytes */
} SLI_VAR;

typedef volatile struct
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
	MAILVARIANTS	un;		/* 124 bytes */
	SLI_VAR		us;		/* 128 bytes */
} MAILBOX;				/* 256 bytes */



/* SLI4 IOCTL Mailbox */
/* ALL SLI4 specific mbox commands have a standard request /response header */
/* Word 0 is just like SLI 3 */

typedef struct mbox_req_hdr
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	domain:8;		/* word 6 */
	uint32_t	port:8;
	uint32_t	subsystem:8;
	uint32_t	opcode:8;

	uint32_t	timeout;		/* word 7 */

	uint32_t	req_length;		/* word 8 */

	uint32_t	reserved1:24;		/* word 9 */
	uint32_t	version:8;		/* word 9 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	opcode:8;
	uint32_t	subsystem:8;
	uint32_t	port:8;
	uint32_t	domain:8;		/* word 6 */

	uint32_t	timeout;		/* word 7 */

	uint32_t	req_length;		/* word 8 */

	uint32_t	version:8;		/* word 9 */
	uint32_t	reserved1:24;		/* word 9 */
#endif

} mbox_req_hdr_t;


typedef struct mbox_req_hdr2
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	vf_number:16;		/* word 6 */
	uint32_t	subsystem:8;
	uint32_t	opcode:8;

	uint32_t	timeout;		/* word 7 */

	uint32_t	req_length;		/* word 8 */

	uint32_t	vh_number:6;		/* word 9 */
	uint32_t	pf_number:10;
	uint32_t	reserved1:8;
	uint32_t	version:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	opcode:8;
	uint32_t	subsystem:8;
	uint32_t	vf_number:16;		/* word 6 */

	uint32_t	timeout;		/* word 7 */

	uint32_t	req_length;		/* word 8 */

	uint32_t	version:8;
	uint32_t	reserved1:8;
	uint32_t	pf_number:10;
	uint32_t	vh_number:6;		/* word 9 */
#endif

} mbox_req_hdr2_t;

typedef struct mbox_rsp_hdr
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	domain:8;		/* word 6 */
	uint32_t	reserved1:8;
	uint32_t	subsystem:8;
	uint32_t	opcode:8;

	uint32_t	reserved2:16;		/* word 7 */
	uint32_t	extra_status:8;
	uint32_t	status:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	opcode:8;
	uint32_t	subsystem:8;
	uint32_t	reserved1:8;
	uint32_t	domain:8;		/* word 6 */

	uint32_t	status:8;
	uint32_t	extra_status:8;
	uint32_t	reserved2:16;		/* word 7 */
#endif
	uint32_t	rsp_length;		/* word 8 */
	uint32_t	allocated_length;	/* word 9 */
} mbox_rsp_hdr_t;

#define	MBX_RSP_STATUS_SUCCESS		0x00
#define	MBX_RSP_STATUS_FAILED		0x01
#define	MBX_RSP_STATUS_ILLEGAL_REQ	0x02
#define	MBX_RSP_STATUS_ILLEGAL_FIELD	0x03
#define	MBX_RSP_STATUS_FCF_IN_USE	0x3A
#define	MBX_RSP_STATUS_NO_FCF		0x43

#define	MGMT_ADDI_STATUS_INCOMPATIBLE	0xA2

typedef struct be_req_hdr
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
	union
	{
		mbox_req_hdr_t	hdr_req;
		mbox_req_hdr2_t hdr_req2;
		mbox_rsp_hdr_t	hdr_rsp;
	} un_hdr;
} be_req_hdr_t;

#define	EMLXS_MAX_NONEMBED_SIZE		(1024 * 64)

/* SLI_CONFIG Mailbox commands */

#define	IOCTL_SUBSYSTEM_COMMON			0x01
#define	IOCTL_SUBSYSTEM_FCOE			0x0C
#define	IOCTL_SUBSYSTEM_DCBX			0x10

#define	COMMON_OPCODE_READ_FLASHROM		0x06
#define	COMMON_OPCODE_WRITE_FLASHROM		0x07
#define	COMMON_OPCODE_CQ_CREATE			0x0C
#define	COMMON_OPCODE_EQ_CREATE			0x0D
#define	COMMON_OPCODE_MQ_CREATE 		0x15
#define	COMMON_OPCODE_GET_CNTL_ATTRIB		0x20
#define	COMMON_OPCODE_NOP			0x21
#define	COMMON_OPCODE_QUERY_FIRMWARE_CONFIG	0x3A
#define	COMMON_OPCODE_RESET			0x3D
#define	COMMON_OPCODE_SET_PHYSICAL_LINK_CFG_V1	0x3E

#define	COMMON_OPCODE_GET_BOOT_CFG		0x42
#define	COMMON_OPCODE_SET_BOOT_CFG		0x43
#define	COMMON_OPCODE_MANAGE_FAT		0x44
#define	COMMON_OPCODE_GET_PHYSICAL_LINK_CFG_V1	0x47
#define	COMMON_OPCODE_GET_PORT_NAME		0x4D

#define	COMMON_OPCODE_MQ_CREATE_EXT		0x5A
#define	COMMON_OPCODE_GET_VPD_DATA		0x5B
#define	COMMON_OPCODE_GET_PHY_DETAILS		0x66
#define	COMMON_OPCODE_SEND_ACTIVATION		0x73
#define	COMMON_OPCODE_RESET_LICENSES		0x74
#define	COMMON_OPCODE_GET_CNTL_ADDL_ATTRIB	0x79

#define	COMMON_OPCODE_GET_EXTENTS_INFO		0x9A
#define	COMMON_OPCODE_GET_EXTENTS		0x9B
#define	COMMON_OPCODE_ALLOC_EXTENTS		0x9C
#define	COMMON_OPCODE_DEALLOC_EXTENTS		0x9D

#define	COMMON_OPCODE_GET_PROFILE_CAPS		0xA1
#define	COMMON_OPCODE_GET_MR_PROFILE_CAPS	0xA2
#define	COMMON_OPCODE_SET_MR_PROFILE_CAPS	0xA3
#define	COMMON_OPCODE_GET_PROFILE_CFG		0xA4
#define	COMMON_OPCODE_SET_PROFILE_CFG		0xA5
#define	COMMON_OPCODE_GET_PROFILE_LIST		0xA6
#define	COMMON_OPCODE_GET_ACTIVE_PROFILE	0xA7
#define	COMMON_OPCODE_SET_ACTIVE_PROFILE	0xA8
#define	COMMON_OPCODE_SET_FACTORY_PROFILE_CFG	0xA9

#define	COMMON_OPCODE_READ_OBJ			0xAB
#define	COMMON_OPCODE_WRITE_OBJ			0xAC
#define	COMMON_OPCODE_READ_OBJ_LIST		0xAD
#define	COMMON_OPCODE_DELETE_OBJ		0xAE
#define	COMMON_OPCODE_GET_SLI4_PARAMS		0xB5

#define	FCOE_OPCODE_WQ_CREATE			0x01
#define	FCOE_OPCODE_CFG_POST_SGL_PAGES		0x03
#define	FCOE_OPCODE_RQ_CREATE			0x05
#define	FCOE_OPCODE_READ_FCF_TABLE		0x08
#define	FCOE_OPCODE_ADD_FCF_TABLE		0x09
#define	FCOE_OPCODE_DELETE_FCF_TABLE		0x0A
#define	FCOE_OPCODE_POST_HDR_TEMPLATES		0x0B
#define	FCOE_OPCODE_REDISCOVER_FCF_TABLE	0x10
#define	FCOE_OPCODE_SET_FCLINK_SETTINGS		0x21

#define	DCBX_OPCODE_GET_DCBX_MODE		0x04
#define	DCBX_OPCODE_SET_DCBX_MODE		0x05

typedef	struct
{
	struct
	{
		uint32_t opcode;
#define	MGMT_FLASHROM_OPCODE_FLASH		1
#define	MGMT_FLASHROM_OPCODE_SAVE		2
#define	MGMT_FLASHROM_OPCODE_CLEAR		3
#define	MGMT_FLASHROM_OPCODE_REPORT		4
#define	MGMT_FLASHROM_OPCODE_INFO		5
#define	MGMT_FLASHROM_OPCODE_CRC		6
#define	MGMT_FLASHROM_OPCODE_OFFSET_FLASH	7
#define	MGMT_FLASHROM_OPCODE_OFFSET_SAVE	8
#define	MGMT_PHY_FLASHROM_OPCODE_FLASH		9
#define	MGMT_PHY_FLASHROM_OPCODE_SAVE		10

		uint32_t optype;
#define	MGMT_FLASHROM_OPTYPE_ISCSI_FIRMWARE	0
#define	MGMT_FLASHROM_OPTYPE_REDBOOT		1
#define	MGMT_FLASHROM_OPTYPE_ISCSI_BIOS		2
#define	MGMT_FLASHROM_OPTYPE_PXE_BIOS		3
#define	MGMT_FLASHROM_OPTYPE_CTRLS		4
#define	MGMT_FLASHROM_OPTYPE_CFG_IPSEC		5
#define	MGMT_FLASHROM_OPTYPE_CFG_INI		6
#define	MGMT_FLASHROM_OPTYPE_ROM_OFFSET		7
#define	MGMT_FLASHROM_OPTYPE_FCOE_BIOS		8
#define	MGMT_FLASHROM_OPTYPE_ISCSI_BACKUP	9
#define	MGMT_FLASHROM_OPTYPE_FCOE_FIRMWARE	10
#define	MGMT_FLASHROM_OPTYPE_FCOE_BACKUP	11
#define	MGMT_FLASHROM_OPTYPE_CTRLP		12
#define	MGMT_FLASHROM_OPTYPE_NCSI_FIRMWARE	13
#define	MGMT_FLASHROM_OPTYPE_CFG_NIC		14
#define	MGMT_FLASHROM_OPTYPE_CFG_DCBX		15
#define	MGMT_FLASHROM_OPTYPE_CFG_PXE_BIOS	16
#define	MGMT_FLASHROM_OPTYPE_CFG_ALL		17
#define	MGMT_FLASHROM_OPTYPE_PHY_FIRMWARE	0xff /* Driver defined */

		uint32_t data_buffer_size; /* Align to 4KB */
		uint32_t offset;
		uint32_t data_buffer; /* image starts here */

	} params;

} IOCTL_COMMON_FLASHROM;


typedef	struct
{
	union
	{
		struct
		{
			uint32_t rsvd;
		} request;


		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t interface_type;
			uint16_t phy_type;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t phy_type;
			uint16_t interface_type;
#endif

/* phy_type */
#define	PHY_XAUI		0x0
#define	PHY_AEL_2020		0x1 /* eluris/Netlogic */
#define	PHY_LSI_BRCM1		0x2 /* Peak pre-production board */
#define	PHY_LSI_BRCM2		0x3 /* Peak production board */
#define	PHY_SOLARFLARE		0x4 /* Dell recommended */
#define	PHY_AMCC_QT2025		0x5 /* AMCC PHY */
#define	PHY_AMCC_QT2225		0x6 /* AMCC PHY */
#define	PHY_BRCM_5931		0x7 /* Broadcom Phy used by HP LOM */
#define	PHY_BE3_INTERNAL_10GB	0x8 /* Internal 10GbPHY in BE3 */
#define	PHY_BE3_INTERNAL_1GB	0x9 /* Internal 1Gb PHY in BE3 */
#define	PHY_TN_2022		0xa /* Teranetics dual port 65nm PHY */
#define	PHY_MARVELL_88E1340	0xb /* Marvel 1G PHY */
#define	PHY_MARVELL_88E1322	0xc /* Marvel 1G PHY */
#define	PHY_TN_8022		0xd /* Teranetics dual port 40nm PHY */
#define	PHY_TYPE_NOT_SUPPORTED

/* interface_type */
#define	CX4_10GB_TYPE		0x0
#define	XFP_10GB_TYPE		0x1
#define	SFP_1GB_TYPE		0x2
#define	SFP_PLUS_10GB_TYPE	0x3
#define	KR_10GB_TYPE		0x4
#define	KX4_10GB_TYPE		0x5
#define	BASET_10GB_TYPE		0x6 /* 10G BaseT */
#define	BASET_1000_TYPE		0x7 /* 1000 BaseT */
#define	BASEX_1000_TYPE		0x8 /* 1000 BaseX */
#define	SGMII_TYPE		0x9
#define	INTERFACE_10GB_DISABLED	0xff /* Interface type not supported */

			uint32_t misc_params;
			uint32_t rsvd[4];
		} response;

	} params;

} IOCTL_COMMON_GET_PHY_DETAILS;


typedef	struct
{
	union
	{
		struct
		{
			uint32_t rsvd;
		} request;


		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint8_t port3_name;
			uint8_t port2_name;
			uint8_t port1_name;
			uint8_t port0_name;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint8_t port0_name;
			uint8_t port1_name;
			uint8_t port2_name;
			uint8_t port3_name;
#endif
		} response;

	} params;

} IOCTL_COMMON_GET_PORT_NAME;


typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd:30;
			uint32_t pt:2;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t pt:2;
			uint32_t rsvd:30;
#endif
#define	PORT_TYPE_GIGE		0
#define	PORT_TYPE_FC		1
		} request;


		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint8_t port3_name;
			uint8_t port2_name;
			uint8_t port1_name;
			uint8_t port0_name;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint8_t port0_name;
			uint8_t port1_name;
			uint8_t port2_name;
			uint8_t port3_name;
#endif
		} response;

	} params;

} IOCTL_COMMON_GET_PORT_NAME_V1;


typedef	struct
{
	union
	{
		struct
		{
			uint32_t fat_operation;
#define	RETRIEVE_FAT		0
#define	QUERY_FAT		1
#define	CLEAR_FAT		2

			uint32_t read_log_offset;
			uint32_t read_log_length;
			uint32_t data_buffer_size;
			uint32_t data_buffer;
		} request;

		struct
		{
			uint32_t log_size;
			uint32_t read_log_length;
			uint32_t rsvd0;
			uint32_t rsvd1;
			uint32_t data_buffer;
		} response;

	} params;

} IOCTL_COMMON_MANAGE_FAT;


typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t EOF:1; /* word 4 */
			uint32_t rsvd0:7;
			uint32_t desired_write_length:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t desired_write_length:24;
			uint32_t rsvd0:7;
			uint32_t EOF:1;  /* word 4 */
#endif
			uint32_t write_offset;  /* word 5 */
			char object_name[(4 * 26)];   /* word 6 - 31 */
			uint32_t buffer_desc_count; /* word 32 */

#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd:8; /* word 33 */
			uint32_t buffer_length:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t buffer_length:24;
			uint32_t rsvd:8; /* word 33 */
#endif
			uint32_t buffer_addrlo; /* word 34 */
			uint32_t buffer_addrhi; /* word 35 */
		} request;

		struct
		{
			uint32_t actual_write_length;

#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd:24;
			uint32_t change_status:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t change_status:8;
			uint32_t rsvd:24;
#endif
#define	CS_NO_RESET		0
#define	CS_REBOOT_RQD		1
#define	CS_FW_RESET_RQD		2
#define	CS_PROTO_RESET_RQD	3
		} response;

	} params;

} IOCTL_COMMON_WRITE_OBJECT;


typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t descriptor_offset:16; /* word 4 */
			uint32_t descriptor_count:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t descriptor_count:16;
			uint32_t descriptor_offset:16; /* word 4 */
#endif
			uint32_t reserved;  /* word 5 */
			char object_name[(4 * 26)];   /* word 6 - 31 */
			uint32_t buffer_desc_count; /* word 32 */

#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd:8; /* word 33 */
			uint32_t buffer_length:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t buffer_length:24;
			uint32_t rsvd:8; /* word 33 */
#endif
			uint32_t buffer_addrlo; /* word 34 */
			uint32_t buffer_addrhi; /* word 35 */
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t reserved:16;
			uint32_t actual_descriptor_count:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t actual_descriptor_count:16;
			uint32_t reserved:16;
#endif
		} response;

	} params;

} IOCTL_COMMON_READ_OBJECT_LIST;


typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t reserved:16; /* word 4 */
			uint32_t boot_instance:8;
			uint32_t boot_status:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t boot_status:8;
			uint32_t boot_instance:8;
			uint32_t reserved:16; /* word 4 */
#endif
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t reserved:16; /* word 4 */
			uint32_t boot_instance:8;
			uint32_t boot_status:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t boot_status:8;
			uint32_t boot_instance:8;
			uint32_t reserved:16; /* word 4 */
#endif
		} response;

	} params;

} IOCTL_COMMON_BOOT_CFG;


/* IOCTL_COMMON_QUERY_FIRMWARE_CONFIG */
typedef struct _BE_FW_CFG
{
	uint32_t	BEConfigNumber;
	uint32_t	ASICRevision;
	uint32_t	PhysicalPort;
	uint32_t	FunctionMode;
	uint32_t	ULPMode;

} BE_FW_CFG;

typedef	struct _IOCTL_COMMON_QUERY_FIRMWARE_CONFIG
{
	union
	{
		struct
		{
			uint32_t	rsvd0;
		} request;

		BE_FW_CFG	response;

	}	params;

} IOCTL_COMMON_QUERY_FIRMWARE_CONFIG;



/* IOCTL_FCOE_READ_FCF_TABLE */
typedef struct
{
	uint32_t	max_recv_size;
	uint32_t	fka_adv_period;
	uint32_t	fip_priority;

#ifdef EMLXS_BIG_ENDIAN
	uint8_t		fcf_mac_address_hi[4];

	uint8_t		mac_address_provider;
	uint8_t		fcf_available;
	uint8_t		fcf_mac_address_low[2];

	uint8_t		fabric_name_identifier[8];

	uint8_t		fcf_sol:1;
	uint8_t		rsvd0:5;
	uint8_t		fcf_fc:1;
	uint8_t		fcf_valid:1;
	uint8_t		fc_map[3];

	uint16_t	fcf_state;
	uint16_t	fcf_index;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		fcf_mac_address_hi[4];

	uint8_t		fcf_mac_address_low[2];
	uint8_t		fcf_available;
	uint8_t		mac_address_provider;

	uint8_t		fabric_name_identifier[8];

	uint8_t		fc_map[3];
	uint8_t		fcf_valid:1;
	uint8_t		fcf_fc:1;
	uint8_t		rsvd0:5;
	uint8_t		fcf_sol:1;

	uint16_t	fcf_index;
	uint16_t	fcf_state;
#endif

	uint8_t		vlan_bitmap[512];
	uint8_t		switch_name_identifier[8];

} FCF_RECORD_t;

#define	EMLXS_FCOE_MAX_RCV_SZ	0x800

/* defines for mac_address_provider */
#define	EMLXS_MAM_BOTH	0	/* Both SPMA and FPMA */
#define	EMLXS_MAM_FPMA	1	/* Fabric Provided MAC Address */
#define	EMLXS_MAM_SPMA	2	/* Server Provided MAC Address */

typedef struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	rsvd0;
			uint16_t	fcf_index;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	fcf_index;
			uint16_t	rsvd0;
#endif

		} request;

		struct
		{
			uint32_t	event_tag;
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	rsvd0;
			uint16_t	next_valid_fcf_index;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	next_valid_fcf_index;
			uint16_t	rsvd0;
#endif
			FCF_RECORD_t fcf_entry[1];

		} response;

	} params;

} IOCTL_FCOE_READ_FCF_TABLE;


/* IOCTL_FCOE_ADD_FCF_TABLE */
typedef struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	rsvd0;
			uint16_t	fcf_index;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	fcf_index;
			uint16_t	rsvd0;
#endif
			FCF_RECORD_t fcf_entry;

		} request;
	} params;

} IOCTL_FCOE_ADD_FCF_TABLE;


/* IOCTL_FCOE_DELETE_FCF_TABLE */
typedef struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	fcf_indexes[1];
			uint16_t	fcf_count;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	fcf_count;
			uint16_t	fcf_indexes[1];
#endif

		} request;
	} params;

} IOCTL_FCOE_DELETE_FCF_TABLE;


/* IOCTL_FCOE_REDISCOVER_FCF_TABLE */
typedef struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	rsvd0;
			uint16_t	fcf_count;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	fcf_count;
			uint16_t	rsvd0;
#endif
			uint32_t	rsvd1;
			uint16_t	fcf_index[1];

		} request;
	} params;

} IOCTL_FCOE_REDISCOVER_FCF_TABLE;


#define	FCOE_FCF_MAC0	0x0E
#define	FCOE_FCF_MAC1	0xFC
#define	FCOE_FCF_MAC2	0x00
#define	FCOE_FCF_MAC3	0xFF
#define	FCOE_FCF_MAC4	0xFF
#define	FCOE_FCF_MAC5	0xFE

#define	FCOE_FCF_MAP0	0x0E
#define	FCOE_FCF_MAP1	0xFC
#define	FCOE_FCF_MAP2	0x00

#define	MGMT_STATUS_FCF_IN_USE	0x3a

/* IOCTL_COMMON_NOP */
typedef	struct _IOCTL_COMMON_NOP
{
	union
	{
		struct
		{
			uint64_t	context;
		} request;

		struct
		{
			uint64_t	context;
		} response;

	} params;

} IOCTL_COMMON_NOP;


/*	Context for EQ create	*/
typedef	struct _EQ_CONTEXT
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	Size:1;
	uint32_t	Rsvd2:1;
	uint32_t	Valid:1;
	uint32_t	Rsvd1:29;

	uint32_t	Armed:1;
	uint32_t	Rsvd4:2;
	uint32_t	Count:3;
	uint32_t	Rsvd3:26;

	uint32_t	Rsvd6:9;
	uint32_t	DelayMult:10;
	uint32_t	Rsvd5:13;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	Rsvd1:29;
	uint32_t	Valid:1;
	uint32_t	Rsvd2:1;
	uint32_t	Size:1;

	uint32_t	Rsvd3:26;
	uint32_t	Count:3;
	uint32_t	Rsvd4:2;
	uint32_t	Armed:1;

	uint32_t	Rsvd5:13;
	uint32_t	DelayMult:10;
	uint32_t	Rsvd6:9;
#endif

	uint32_t	Rsvd7;

} EQ_CONTEXT;


/* define for Count field */
#define	EQ_ELEMENT_COUNT_1024	2
#define	EQ_ELEMENT_COUNT_2048	3
#define	EQ_ELEMENT_COUNT_4096	4

/* define for Size field */
#define	EQ_ELEMENT_SIZE_4	0

/* define for DelayMullt - used for interrupt coalescing */
#define	EQ_DELAY_MULT		64

/*	Context for CQ create	*/
typedef	struct _CQ_CONTEXT
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	Eventable:1;
	uint32_t	Rsvd3:1;
	uint32_t	Valid:1;
	uint32_t	Count:2;
	uint32_t	Rsvd2:12;
	uint32_t	NoDelay:1;
	uint32_t	CoalesceWM:2;
	uint32_t	Rsvd1:12;

	uint32_t	Armed:1;
	uint32_t	Rsvd5:1;
	uint32_t	EQId:8;
	uint32_t	Rsvd4:22;

	uint32_t	Rsvd6;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	Rsvd1:12;
	uint32_t	CoalesceWM:2;
	uint32_t	NoDelay:1;
	uint32_t	Rsvd2:12;
	uint32_t	Count:2;
	uint32_t	Valid:1;
	uint32_t	Rsvd3:1;
	uint32_t	Eventable:1;

	uint32_t	Rsvd4:22;
	uint32_t	EQId:8;
	uint32_t	Rsvd5:1;
	uint32_t	Armed:1;

	uint32_t	Rsvd6;
#endif

	uint32_t	Rsvd7;

} CQ_CONTEXT;

typedef	struct _CQ_CONTEXT_V2
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	Eventable:1;
	uint32_t	Rsvd3:1;
	uint32_t	Valid:1;
	uint32_t	CqeCnt:2;
	uint32_t	CqeSize:2;
	uint32_t	Rsvd2:9;
	uint32_t	AutoValid:1;
	uint32_t	NoDelay:1;
	uint32_t	CoalesceWM:2;
	uint32_t	Rsvd1:12;

	uint32_t	Armed:1;
	uint32_t	Rsvd4:15;
	uint32_t	EQId:16;

	uint32_t	Rsvd5:16;
	uint32_t	Count1:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	Rsvd1:12;
	uint32_t	CoalesceWM:2;
	uint32_t	NoDelay:1;
	uint32_t	AutoValid:1;
	uint32_t	Rsvd2:9;
	uint32_t	CqeSize:2;
	uint32_t	CqeCnt:2;
	uint32_t	Valid:1;
	uint32_t	Rsvd3:1;
	uint32_t	Eventable:1;

	uint32_t	EQId:16;
	uint32_t	Rsvd4:15;
	uint32_t	Armed:1;

	uint32_t	Count1:16;
	uint32_t	Rsvd5:16;
#endif

	uint32_t	Rsvd7;

} CQ_CONTEXT_V2;

/* CqeSize */
#define	CQE_SIZE_16_BYTES	0
#define	CQE_SIZE_32_BYTES	1

/* define for Count field */
#define	CQ_ELEMENT_COUNT_256	0
#define	CQ_ELEMENT_COUNT_512	1
#define	CQ_ELEMENT_COUNT_1024	2
#define	CQ_ELEMENT_COUNT_SPECIFIED	3

/*	Context for MQ create	*/
typedef	struct _MQ_CONTEXT
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	CQId:10;
	uint32_t	Rsvd2:2;
	uint32_t	Size:4;
	uint32_t	Rsvd1:16;

	uint32_t	Valid:1;
	uint32_t	Rsvd3:31;

	uint32_t	Rsvd4:21;
	uint32_t	ACQId:10;
	uint32_t	ACQV:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	Rsvd1:16;
	uint32_t	Size:4;
	uint32_t	Rsvd2:2;
	uint32_t	CQId:10;

	uint32_t	Rsvd3:31;
	uint32_t	Valid:1;

	uint32_t	ACQV:1;
	uint32_t	ACQId:10;
	uint32_t	Rsvd4:21;
#endif

	uint32_t	Rsvd5;

} MQ_CONTEXT;


typedef	struct _MQ_CONTEXT_V1
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	Rsvd2:12;
	uint32_t	Size:4;
	uint32_t	ACQId:16;

	uint32_t	Valid:1;
	uint32_t	Rsvd3:31;

	uint32_t	Rsvd4:31;
	uint32_t	ACQV:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	ACQId:16;
	uint32_t	Size:4;
	uint32_t	Rsvd2:12;

	uint32_t	Rsvd3:31;
	uint32_t	Valid:1;

	uint32_t	ACQV:1;
	uint32_t	Rsvd4:31;
#endif

	uint32_t	Rsvd5;

} MQ_CONTEXT_V1;


/* define for Size field */
#define	MQ_ELEMENT_COUNT_16 0x05

/*	Context for RQ create	*/
typedef	struct _RQ_CONTEXT
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	Rsvd2:12;
	uint32_t	RqeCnt:4;
	uint32_t	Rsvd1:16;

	uint32_t	Rsvd3;

	uint32_t	CQId:16;
	uint32_t	BufferSize:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	Rsvd1:16;
	uint32_t	RqeCnt:4;
	uint32_t	Rsvd2:12;

	uint32_t	Rsvd3;

	uint32_t	BufferSize:16;
	uint32_t	CQId:16;
#endif

	uint32_t  Rsvd5;

} RQ_CONTEXT;

typedef	struct _RQ_CONTEXT_V1
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	RqeCnt:16;
	uint32_t	Rsvd1:4;
	uint32_t	RqeSize:4;
	uint32_t	PageSize:8;

	uint32_t	Rsvd2;

	uint32_t	CQId:16;
	uint32_t	Rsvd:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	PageSize:8;
	uint32_t	RqeSize:4;
	uint32_t	Rsvd1:4;
	uint32_t	RqeCnt:16;

	uint32_t	Rsvd2;

	uint32_t	Rsvd:16;
	uint32_t	CQId:16;
#endif

	uint32_t	BufferSize;

} RQ_CONTEXT_V1;

/* RqeSize */
#define	RQE_SIZE_8_BYTES	0x02
#define	RQE_SIZE_16_BYTES	0x03
#define	RQE_SIZE_32_BYTES	0x04
#define	RQE_SIZE_64_BYTES	0x05
#define	RQE_SIZE_128_BYTES	0x06

/* RQ PageSize */
#define	RQ_PAGE_SIZE_4K		0x01
#define	RQ_PAGE_SIZE_8K		0x02
#define	RQ_PAGE_SIZE_16K	0x04
#define	RQ_PAGE_SIZE_32K	0x08
#define	RQ_PAGE_SIZE_64K	0x10


/* IOCTL_COMMON_EQ_CREATE */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd1;
			uint16_t	NumPages;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	NumPages;
			uint16_t	Rsvd1;
#endif
			EQ_CONTEXT	EQContext;
			BE_PHYS_ADDR	Pages[8];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	MsiIndex; /* V1 only */
			uint16_t	EQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	EQId;
			uint16_t	MsiIndex; /* V1 only */
#endif
		} response;
	} params;

} IOCTL_COMMON_EQ_CREATE;


typedef	struct
{
#ifdef EMLXS_BIG_ENDIAN
		uint32_t	Rsvd1:24;		/* Word 0 */
		uint32_t	ProtocolType:8;

		uint32_t	Rsvd3:3;		/* Word 1 */
		uint32_t	SliHint2:5;
		uint32_t	SliHint1:8;
		uint32_t	IfType:4;
		uint32_t	SliFamily:4;
		uint32_t	Revision:4;
		uint32_t	Rsvd2:3;
		uint32_t	FT:1;

		uint32_t	EqRsvd3:4;		/* Word 2 */
		uint32_t	EqeCntMethod:4;
		uint32_t	EqPageSize:8;
		uint32_t	EqRsvd2:4;
		uint32_t	EqeSize:4;
		uint32_t	EqRsvd1:4;
		uint32_t	EqPageCnt:4;

		uint32_t	EqRsvd4:16;		/* Word 3 */
		uint32_t	EqeCntMask:16;

		uint32_t	CqRsvd3:4;		/* Word 4 */
		uint32_t	CqeCntMethod:4;
		uint32_t	CqPageSize:8;
		uint32_t	CQV:2;
		uint32_t	CqRsvd2:2;
		uint32_t	CqeSize:4;
		uint32_t	CqRsvd1:4;
		uint32_t	CqPageCnt:4;

		uint32_t	CqRsvd4:16;		/* Word 5 */
		uint32_t	CqeCntMask:16;

		uint32_t	MqRsvd2:4;		/* Word 6 */
		uint32_t	MqeCntMethod:4;
		uint32_t	MqPageSize:8;
		uint32_t	MQV:2;
		uint32_t	MqRsvd1:10;
		uint32_t	MqPageCnt:4;

		uint32_t	MqRsvd3:16;		/* Word 7 */
		uint32_t	MqeCntMask:16;

		uint32_t	WqRsvd3:4;		/* Word 8 */
		uint32_t	WqeCntMethod:4;
		uint32_t	WqPageSize:8;
		uint32_t	WQV:2;
		uint32_t	WqeRsvd2:2;
		uint32_t	WqeSize:4;
		uint32_t	WqRsvd1:4;
		uint32_t	WqPageCnt:4;

		uint32_t	WqRsvd4:16;		/* Word 9 */
		uint32_t	WqeCntMask:16;

		uint32_t	RqRsvd3:4;		/* Word 10 */
		uint32_t	RqeCntMethod:4;
		uint32_t	RqPageSize:8;
		uint32_t	RQV:2;
		uint32_t	RqeRsvd2:2;
		uint32_t	RqeSize:4;
		uint32_t	RqRsvd1:4;
		uint32_t	RqPageCnt:4;

		uint32_t	RqDbWin:4;		/* Word 11 */
		uint32_t	RqRsvd4:12;
		uint32_t	RqeCntMask:16;

		uint32_t	Loopback:4;		/* Word 12 */
		uint32_t	Rsvd4:12;
		uint32_t	PHWQ:1;
		uint32_t	PHON:1;
		uint32_t	PHOFF:1;
		uint32_t	TRIR:1;
		uint32_t	TRTY:1;
		uint32_t	TCCA:1;
		uint32_t	MWQE:1;
		uint32_t	ASSI:1;
		uint32_t	TERP:1;
		uint32_t	TGT:1;
		uint32_t	AREG:1;
		uint32_t	FBRR:1;
		uint32_t	SGLR:1;
		uint32_t	HDRR:1;
		uint32_t	EXT:1;
		uint32_t	FCOE:1;

		uint32_t	SgeLength;		/* Word 13 */

		uint32_t	SglRsvd2:8;		/* Word 14 */
		uint32_t	SglAlign:8;
		uint32_t	SglPageSize:8;
		uint32_t	SglRsvd1:4;
		uint32_t	SglPageCnt:4;

		uint32_t	Rsvd5:16;		/* Word 15 */
		uint32_t	MinRqSize:16;

		uint32_t	MaxRqSize;		/* Word 16 */

		uint32_t	RPIMax:16;
		uint32_t	XRIMax:16;		/* Word 17 */

		uint32_t	VFIMax:16;
		uint32_t	VPIMax:16;		/* Word 18 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
		uint32_t	ProtocolType:8;		/* Word 0 */
		uint32_t	Rsvd1:24;

		uint32_t	FT:1;			/* Word 1 */
		uint32_t	Rsvd2:3;
		uint32_t	Revision:4;
		uint32_t	SliFamily:4;
		uint32_t	IfType:4;
		uint32_t	SliHint1:8;
		uint32_t	SliHint2:5;
		uint32_t	Rsvd3:3;

		uint32_t	EqPageCnt:4;		/* Word 2 */
		uint32_t	EqRsvd1:4;
		uint32_t	EqeSize:4;
		uint32_t	EqRsvd2:4;
		uint32_t	EqPageSize:8;
		uint32_t	EqeCntMethod:4;
		uint32_t	EqRsvd3:4;

		uint32_t	EqeCntMask:16;		/* Word 3 */
		uint32_t	EqRsvd4:16;

		uint32_t	CqPageCnt:4;		/* Word 4 */
		uint32_t	CqRsvd1:4;
		uint32_t	CqeSize:4;
		uint32_t	CqRsvd2:2;
		uint32_t	CQV:2;
		uint32_t	CqPageSize:8;
		uint32_t	CqeCntMethod:4;
		uint32_t	CqRsvd3:4;

		uint32_t	CqeCntMask:16;		/* Word 5 */
		uint32_t	CqRsvd4:16;

		uint32_t	MqPageCnt:4;		/* Word 6 */
		uint32_t	MqRsvd1:10;
		uint32_t	MQV:2;
		uint32_t	MqPageSize:8;
		uint32_t	MqeCntMethod:4;
		uint32_t	MqRsvd2:4;

		uint32_t	MqeCntMask:16;		/* Word 7 */
		uint32_t	MqRsvd3:16;

		uint32_t	WqPageCnt:4;		/* Word 8 */
		uint32_t	WqRsvd1:4;
		uint32_t	WqeSize:4;
		uint32_t	WqeRsvd2:2;
		uint32_t	WQV:2;
		uint32_t	WqPageSize:8;
		uint32_t	WqeCntMethod:4;
		uint32_t	WqRsvd3:4;

		uint32_t	WqeCntMask:16;		/* Word 9 */
		uint32_t	WqRsvd4:16;

		uint32_t	RqPageCnt:4;		/* Word 10 */
		uint32_t	RqRsvd1:4;
		uint32_t	RqeSize:4;
		uint32_t	RqeRsvd2:2;
		uint32_t	RQV:2;
		uint32_t	RqPageSize:8;
		uint32_t	RqeCntMethod:4;
		uint32_t	RqRsvd3:4;

		uint32_t	RqeCntMask:16;		/* Word 11 */
		uint32_t	RqRsvd4:12;
		uint32_t	RqDbWin:4;

		uint32_t	FCOE:1;			/* Word 12 */
		uint32_t	EXT:1;
		uint32_t	HDRR:1;
		uint32_t	SGLR:1;
		uint32_t	FBRR:1;
		uint32_t	AREG:1;
		uint32_t	TGT:1;
		uint32_t	TERP:1;
		uint32_t	ASSI:1;
		uint32_t	MWQE:1;
		uint32_t	TCCA:1;
		uint32_t	TRTY:1;
		uint32_t	TRIR:1;
		uint32_t	PHOFF:1;
		uint32_t	PHON:1;
		uint32_t	PHWQ:1;
		uint32_t	Rsvd4:12;
		uint32_t	Loopback:4;

		uint32_t	SgeLength;		/* Word 13 */

		uint32_t	SglPageCnt:4;		/* Word 14 */
		uint32_t	SglRsvd1:4;
		uint32_t	SglPageSize:8;
		uint32_t	SglAlign:8;
		uint32_t	SglRsvd2:8;

		uint32_t	MinRqSize:16;		/* Word 15 */
		uint32_t	Rsvd5:16;

		uint32_t	MaxRqSize;		/* Word 16 */

		uint32_t	XRIMax:16;		/* Word 17 */
		uint32_t	RPIMax:16;

		uint32_t	VPIMax:16;		/* Word 18 */
		uint32_t	VFIMax:16;
#endif

		uint32_t	Rsvd6;			/* Word 19 */

} sli_params_t;

/* SliFamily values */
#define	SLI_FAMILY_BE2		0x0
#define	SLI_FAMILY_BE3		0x1
#define	SLI_FAMILY_LANCER_A	0xA
#define	SLI_FAMILY_LANCER_B	0xB



/* IOCTL_COMMON_SLI4_PARAMS */
typedef	struct
{
	union
	{
		struct
		{
			uint32_t	Rsvd1;
		} request;

		struct
		{
			sli_params_t param;
		} response;
	} params;

} IOCTL_COMMON_SLI4_PARAMS;


#define	MAX_EXTENTS		16 /* 1 to 104 */

/* IOCTL_COMMON_EXTENTS */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	RscCnt;
			uint16_t	RscType;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	RscType;
			uint16_t	RscCnt;
#endif
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	ExtentSize;
			uint16_t	ExtentCnt;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	ExtentCnt;
			uint16_t	ExtentSize;
#endif

			uint16_t	RscId[MAX_EXTENTS];

		} response;
	} params;

} IOCTL_COMMON_EXTENTS;

/* RscType */
#define	RSC_TYPE_FCOE_VFI	0x20
#define	RSC_TYPE_FCOE_VPI	0x21
#define	RSC_TYPE_FCOE_RPI	0x22
#define	RSC_TYPE_FCOE_XRI	0x23



/* IOCTL_COMMON_CQ_CREATE */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd1;
			uint16_t	NumPages;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	NumPages;
			uint16_t	Rsvd1;
#endif
			CQ_CONTEXT	CQContext;
			BE_PHYS_ADDR	Pages[4];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd1;
			uint16_t	CQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	CQId;
			uint16_t	Rsvd1;
#endif
		} response;
	} params;

} IOCTL_COMMON_CQ_CREATE;


/* IOCTL_COMMON_CQ_CREATE_V2 */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint8_t		Rsvd1;
			uint8_t		PageSize;
			uint16_t	NumPages;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	NumPages;
			uint8_t		PageSize;
			uint8_t		Rsvd1;
#endif
			CQ_CONTEXT_V2	CQContext;
			BE_PHYS_ADDR	Pages[8];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd1;
			uint16_t	CQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	CQId;
			uint16_t	Rsvd1;
#endif
		} response;
	} params;

} IOCTL_COMMON_CQ_CREATE_V2;

#define	CQ_PAGE_SIZE_4K		0x01
#define	CQ_PAGE_SIZE_8K		0x02
#define	CQ_PAGE_SIZE_16K	0x04
#define	CQ_PAGE_SIZE_32K	0x08
#define	CQ_PAGE_SIZE_64K	0x10



/* IOCTL_COMMON_MQ_CREATE */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd1;
			uint16_t	NumPages;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	NumPages;
			uint16_t	Rsvd1;
#endif
			MQ_CONTEXT	MQContext;
			BE_PHYS_ADDR	Pages[8];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd1;
			uint16_t	MQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	MQId;
			uint16_t	Rsvd1;
#endif
		} response;
	} params;

} IOCTL_COMMON_MQ_CREATE;


/* IOCTL_COMMON_MQ_CREATE_EXT */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	rsvd0;
			uint16_t	num_pages;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	num_pages;
			uint16_t	rsvd0;
#endif
			uint32_t	async_event_bitmap;

#define	ASYNC_LINK_EVENT	0x00000002
#define	ASYNC_FCF_EVENT		0x00000004
#define	ASYNC_DCBX_EVENT	0x00000008
#define	ASYNC_iSCSI_EVENT	0x00000010
#define	ASYNC_GROUP5_EVENT	0x00000020
#define	ASYNC_FC_EVENT		0x00010000
#define	ASYNC_PORT_EVENT	0x00020000
#define	ASYNC_VF_EVENT		0x00040000
#define	ASYNC_MR_EVENT		0x00080000

			MQ_CONTEXT	context;
			BE_PHYS_ADDR	pages[8];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	rsvd0;
			uint16_t	MQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	MQId;
			uint16_t	rsvd0;
#endif
		} response;

	} params;

} IOCTL_COMMON_MQ_CREATE_EXT;


/* IOCTL_COMMON_MQ_CREATE_EXT_V1 */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	CQId;
			uint16_t	num_pages;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	num_pages;
			uint16_t	CQId;
#endif
			uint32_t	async_event_bitmap;

			MQ_CONTEXT_V1	context;
			BE_PHYS_ADDR	pages[8];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	rsvd0;
			uint16_t	MQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	MQId;
			uint16_t	rsvd0;
#endif
		} response;

	} params;

} IOCTL_COMMON_MQ_CREATE_EXT_V1;


/* IOCTL_FCOE_RQ_CREATE */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd0;
			uint16_t	NumPages;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	NumPages;
			uint16_t	Rsvd0;
#endif
			RQ_CONTEXT	RQContext;
			BE_PHYS_ADDR	Pages[8];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd1;
			uint16_t	RQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	RQId;
			uint16_t	Rsvd1;
#endif
		} response;

	} params;

} IOCTL_FCOE_RQ_CREATE;


/* IOCTL_FCOE_RQ_CREATE_V1 */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t 	DNB:1;
			uint32_t 	DFD:1;
			uint32_t 	DIM:1;
			uint32_t	Rsvd0:13;
			uint32_t	NumPages:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	NumPages:16;
			uint32_t	Rsvd0:13;
			uint32_t 	DIM:1;
			uint32_t 	DFD:1;
			uint32_t 	DNB:1;
#endif
			RQ_CONTEXT_V1	RQContext;
			BE_PHYS_ADDR	Pages[8];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd1;
			uint16_t	RQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	RQId;
			uint16_t	Rsvd1;
#endif
		} response;

	} params;

} IOCTL_FCOE_RQ_CREATE_V1;


/* IOCTL_FCOE_WQ_CREATE */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	CQId;
			uint16_t	NumPages;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	NumPages;
			uint16_t	CQId;
#endif
			BE_PHYS_ADDR	Pages[4];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd0;
			uint16_t	WQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	WQId;
			uint16_t	Rsvd0;
#endif
		} response;

	} params;

} IOCTL_FCOE_WQ_CREATE;


/* IOCTL_FCOE_WQ_CREATE_V1 */
typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	CQId;
			uint16_t	NumPages;

			uint32_t	WqeCnt:16;
			uint32_t	Rsvd1:4;
			uint32_t	WqeSize:4;
			uint32_t	PageSize:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	NumPages;
			uint16_t	CQId;

			uint32_t	PageSize:8;
			uint32_t	WqeSize:4;
			uint32_t	Rsvd1:4;
			uint32_t	WqeCnt:16;
#endif
			uint32_t	Rsvd:2;
			BE_PHYS_ADDR	Pages[4];
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	Rsvd0;
			uint16_t	WQId;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	WQId;
			uint16_t	Rsvd0;
#endif
		} response;

	} params;

} IOCTL_FCOE_WQ_CREATE_V1;

/* WqeSize */
#define	WQE_SIZE_64_BYTES	0x05
#define	WQE_SIZE_128_BYTES	0x06

/* PageSize */
#define	WQ_PAGE_SIZE_4K		0x01
#define	WQ_PAGE_SIZE_8K		0x02
#define	WQ_PAGE_SIZE_16K	0x04
#define	WQ_PAGE_SIZE_32K	0x08
#define	WQ_PAGE_SIZE_64K	0x10



/* IOCTL_FCOE_CFG_POST_SGL_PAGES */
typedef	struct _FCOE_SGL_PAGES
{
	BE_PHYS_ADDR	sgl_page0;	/* 1st page per XRI */
	BE_PHYS_ADDR	sgl_page1;	/* 2nd page per XRI */

} FCOE_SGL_PAGES;

typedef	struct
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	xri_count;
			uint16_t	xri_start;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	xri_start;
			uint16_t	xri_count;
#endif
			FCOE_SGL_PAGES	pages[1];
		} request;

		struct
		{
			uint32_t	rsvd0;
		} response;

	} params;

	uint32_t	rsvd0[2];

} IOCTL_FCOE_CFG_POST_SGL_PAGES;


/* IOCTL_FCOE_POST_HDR_TEMPLATES */
typedef struct _IOCTL_FCOE_POST_HDR_TEMPLATES
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint16_t	num_pages;
			uint16_t	rpi_offset;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t	rpi_offset;
			uint16_t	num_pages;
#endif
			BE_PHYS_ADDR	pages[32];

		}request;

	}params;

} IOCTL_FCOE_POST_HDR_TEMPLATES;



#define	EMLXS_IOCTL_DCBX_MODE_CEE	0	/* Mapped to FIP mode */
#define	EMLXS_IOCTL_DCBX_MODE_CIN	1	/* Mapped to nonFIP mode */

/* IOCTL_DCBX_GET_DCBX_MODE */
typedef struct _IOCTL_DCBX_GET_DCBX_MODE
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint8_t		rsvd0[3];
			uint8_t		port_num;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint8_t		port_num;
			uint8_t		rsvd0[3];
#endif
		} request;

		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint8_t		rsvd1[3];
			uint8_t		dcbx_mode;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint8_t		dcbx_mode;
			uint8_t		rsvd1[3];
#endif
		} response;

	} params;

} IOCTL_DCBX_GET_DCBX_MODE;


/* IOCTL_DCBX_SET_DCBX_MODE */
typedef struct _IOCTL_DCBX_SET_DCBX_MODE
{
	union
	{
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint8_t		rsvd0[2];
			uint8_t		dcbx_mode;
			uint8_t		port_num;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint8_t		port_num;
			uint8_t		dcbx_mode;
			uint8_t		rsvd0[2];
#endif
		} request;

		struct
		{
			uint32_t	rsvd1;
		} response;

	} params;

} IOCTL_DCBX_SET_DCBX_MODE;


/* IOCTL_COMMON_GET_CNTL_ATTRIB */
typedef	struct
{
	char		flashrom_version_string[32];
	char		manufacturer_name[32];
	char		rsvd0[28];
	uint32_t	default_extended_timeout;
	char		controller_model_number[32];
	char		controller_description[64];
	char		controller_serial_number[32];
	char		ip_version_string[32];
	char		firmware_version_string[32];
	char		bios_version_string[32];
	char		redboot_version_string[32];
	char		driver_version_string[32];
	char		fw_on_flash_version_string[32];
	uint32_t	functionalities_supported;
	uint16_t	max_cdblength;
	uint8_t		asic_revision;
	uint8_t		generational_guid[16];
	uint8_t		hba_port_count;
	uint16_t	default_link_down_timeout;
	uint8_t		iscsi_ver_min_max;
	uint8_t		multifunction_device;
	uint8_t		cache_valid;
	uint8_t		hba_status;
	uint8_t		max_domains_supported;
	uint8_t		phy_port;
	uint32_t	firmware_post_status;
	uint32_t	hba_mtu[2];

} MGMT_HBA_ATTRIB;

typedef	struct
{
	MGMT_HBA_ATTRIB		hba_attribs;
	uint16_t		pci_vendor_id;
	uint16_t		pci_device_id;
	uint16_t		pci_sub_vendor_id;
	uint16_t		pci_sub_system_id;
	uint8_t			pci_bus_number;
	uint8_t			pci_device_number;
	uint8_t			pci_function_number;
	uint8_t			interface_type;
	uint64_t		unique_identifier;

} MGMT_CONTROLLER_ATTRIB;

typedef	struct
{
	union
	{
		struct
		{
			uint32_t rsvd0;
		} request;

		struct
		{
			MGMT_CONTROLLER_ATTRIB cntl_attributes_info;
		} response;

	} params;

} IOCTL_COMMON_GET_CNTL_ATTRIB;


typedef	union
{
	IOCTL_COMMON_NOP		NOPVar;
	IOCTL_FCOE_WQ_CREATE		WQCreateVar;
	IOCTL_FCOE_WQ_CREATE_V1		WQCreateVar1;
	IOCTL_FCOE_RQ_CREATE		RQCreateVar;
	IOCTL_FCOE_RQ_CREATE_V1		RQCreateVar1;
	IOCTL_COMMON_EQ_CREATE		EQCreateVar;
	IOCTL_COMMON_CQ_CREATE		CQCreateVar;
	IOCTL_COMMON_CQ_CREATE_V2	CQCreateVar2;
	IOCTL_COMMON_MQ_CREATE		MQCreateVar;
	IOCTL_COMMON_MQ_CREATE_EXT	MQCreateExtVar;
	IOCTL_COMMON_MQ_CREATE_EXT_V1	MQCreateExtVar1;
	IOCTL_FCOE_CFG_POST_SGL_PAGES	PostSGLVar;
	IOCTL_COMMON_GET_CNTL_ATTRIB	GetCntlAttributesVar;
	IOCTL_FCOE_READ_FCF_TABLE	ReadFCFTableVar;
	IOCTL_FCOE_ADD_FCF_TABLE	AddFCFTableVar;
	IOCTL_FCOE_REDISCOVER_FCF_TABLE	RediscoverFCFTableVar;
	IOCTL_COMMON_FLASHROM		FlashRomVar;
	IOCTL_COMMON_MANAGE_FAT		FATVar;
	IOCTL_DCBX_GET_DCBX_MODE	GetDCBX;
	IOCTL_DCBX_SET_DCBX_MODE	SetDCBX;
	IOCTL_COMMON_SLI4_PARAMS	Sli4ParamVar;
	IOCTL_COMMON_EXTENTS		ExtentsVar;
	IOCTL_COMMON_GET_PHY_DETAILS	PHYDetailsVar;
	IOCTL_COMMON_GET_PORT_NAME	PortNameVar;
	IOCTL_COMMON_GET_PORT_NAME_V1	PortNameVar1;
	IOCTL_COMMON_WRITE_OBJECT	WriteObjVar;
	IOCTL_COMMON_BOOT_CFG		BootCfgVar;

} IOCTL_VARIANTS;

/* Structure for MB Command SLI_CONFIG(0x9b) */
/* Good for SLI4 only */

typedef struct
{
	be_req_hdr_t	be;
	BE_PHYS_ADDR	payload;
} SLI_CONFIG_VAR;

#define	IOCTL_HEADER_SZ	(4 * sizeof (uint32_t))


typedef union
{
	uint32_t		varWords[63];
	READ_NV_VAR		varRDnvp;	/* cmd = x02 (READ_NVPARMS) */
	INIT_LINK_VAR		varInitLnk;	/* cmd = x05 (INIT_LINK) */
	CONFIG_LINK		varCfgLnk;	/* cmd = x07 (CONFIG_LINK) */
	READ_REV4_VAR		varRdRev4;	/* cmd = x11 (READ_REV) */
	READ_LNK_VAR		varRdLnk;	/* cmd = x12 (READ_LNK_STAT) */
	DUMP4_VAR		varDmp4;	/* cmd = x17 (DUMP) */
	UPDATE_CFG_VAR		varUpdateCfg;	/* cmd = x1b (update Cfg) */
	BIU_DIAG_VAR		varBIUdiag;	/* cmd = x84 (RUN_BIU_DIAG64) */
	READ_SPARM_VAR		varRdSparm;	/* cmd = x8D (READ_SPARM64) */
	REG_FCFI_VAR		varRegFCFI;	/* cmd = xA0 (REG_FCFI) */
	UNREG_FCFI_VAR		varUnRegFCFI;	/* cmd = xA2 (UNREG_FCFI) */
	READ_LA_VAR		varReadLA;	/* cmd = x95 (READ_LA64) */
	READ_CONFIG4_VAR	varRdConfig4;	/* cmd = x0B (READ_CONFIG) */
	RESUME_RPI_VAR		varResumeRPI;	/* cmd = x9E (RESUME_RPI) */
	REG_LOGIN_VAR		varRegLogin;	/* cmd = x93 (REG_RPI) */
	UNREG_LOGIN_VAR		varUnregLogin;	/* cmd = x14 (UNREG_RPI) */
	REG_VPI_VAR		varRegVPI4;	/* cmd = x96 (REG_VPI) */
	UNREG_VPI_VAR4		varUnRegVPI4;	/* cmd = x97 (UNREG_VPI) */
	REG_VFI_VAR		varRegVFI4;	/* cmd = x9F (REG_VFI) */
	UNREG_VFI_VAR		varUnRegVFI4;	/* cmd = xA1 (UNREG_VFI) */
	REQUEST_FEATURES_VAR	varReqFeatures;	/* cmd = x9D (REQ_FEATURES) */
	SLI_CONFIG_VAR		varSLIConfig;	/* cmd = x9B (SLI_CONFIG) */
	INIT_VPI_VAR		varInitVPI4;	/* cmd = xA3 (INIT_VPI) */
	INIT_VFI_VAR		varInitVFI4;	/* cmd = xA4 (INIT_VFI) */

} MAILVARIANTS4;		/* Used for SLI-4 */

#define	MAILBOX_CMD_SLI4_BSIZE	256
#define	MAILBOX_CMD_SLI4_WSIZE	64

#define	MAILBOX_CMD_MAX_BSIZE	256
#define	MAILBOX_CMD_MAX_WSIZE	64


typedef volatile struct
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
	MAILVARIANTS4	un;		/* 252 bytes */
} MAILBOX4;				/* Used for SLI-4 */

/*
 * End Structure Definitions for Mailbox Commands
 */


typedef struct emlxs_mbq
{
	volatile uint32_t	mbox[MAILBOX_CMD_MAX_WSIZE];
	struct emlxs_mbq	*next;

	/* Defferred handling pointers */
	void			*nonembed;	/* ptr to data buffer */
						/* structure */
	void			*bp;		/* ptr to data buffer */
						/* structure */
	void			*sbp;		/* ptr to emlxs_buf_t */
						/* structure */
	void			*ubp;		/* ptr to fc_unsol_buf_t */
						/* structure */
	void			*iocbq;		/* ptr to IOCBQ structure */
	void			*context;	/* ptr to mbox context data */
	void			*port;		/* Sending port */
	uint32_t		flag;

#define	MBQ_POOL_ALLOCATED	0x00000001
#define	MBQ_PASSTHRU		0x00000002
#define	MBQ_EMBEDDED		0x00000004
#define	MBQ_BOOTSTRAP		0x00000008
#define	MBQ_COMPLETED		0x00010000	/* Used for MBX_SLEEP */
#define	MBQ_INIT_MASK		0x0000ffff

#ifdef MBOX_EXT_SUPPORT
	uint8_t			*extbuf;	/* ptr to mailbox ext buffer */
	uint32_t		extsize;	/* size of mailbox ext buffer */
#endif /* MBOX_EXT_SUPPORT */
	uint32_t		(*mbox_cmpl)();
} emlxs_mbq_t;
typedef emlxs_mbq_t MAILBOXQ;


/* We currently do not support IOCBs in SLI1 mode */
typedef struct
{
	MAILBOX		mbx;
#ifdef MBOX_EXT_SUPPORT
	uint8_t		mbxExt[MBOX_EXTENSION_SIZE];
#endif /* MBOX_EXT_SUPPORT */
	uint8_t		pad[(SLI_SLIM1_SIZE -
				(sizeof (MAILBOX) + MBOX_EXTENSION_SIZE))];
} SLIM1;


typedef struct
{
	MAILBOX		mbx;
#ifdef MBOX_EXT_SUPPORT
	uint8_t		mbxExt[MBOX_EXTENSION_SIZE];
#endif /* MBOX_EXT_SUPPORT */
	PCB		pcb;
	uint8_t		IOCBs[SLI_IOCB_MAX_SIZE];
} SLIM2;


/* def for new 2MB Flash (Pegasus ...) */
#define	MBX_LOAD_AREA		0x81
#define	MBX_LOAD_EXP_ROM	0x9C

#define	FILE_TYPE_AWC		0xE1A01001
#define	FILE_TYPE_DWC		0xE1A02002
#define	FILE_TYPE_BWC		0xE1A03003

#define	AREA_ID_MASK		0xFFFFFF0F
#define	AREA_ID_AWC		0x00000001
#define	AREA_ID_DWC		0x00000002
#define	AREA_ID_BWC		0x00000003

#define	CMD_START_ERASE		1
#define	CMD_CONTINUE_ERASE	2
#define	CMD_DOWNLOAD		3
#define	CMD_END_DOWNLOAD	4

#define	RSP_ERASE_STARTED	1
#define	RSP_ERASE_COMPLETE	2
#define	RSP_DOWNLOAD_MORE	3
#define	RSP_DOWNLOAD_DONE	4

#define	EROM_CMD_FIND_IMAGE	8
#define	EROM_CMD_CONTINUE_ERASE	9
#define	EROM_CMD_COPY		10

#define	EROM_RSP_ERASE_STARTED	8
#define	EROM_RSP_ERASE_COMPLETE	9
#define	EROM_RSP_COPY_MORE	10
#define	EROM_RSP_COPY_DONE	11

#define	ALLext			1
#define	DWCext			2
#define	BWCext			3

#define	NO_ALL			0
#define	ALL_WITHOUT_BWC		1
#define	ALL_WITH_BWC		2

#define	KERNEL_START_ADDRESS	0x000000
#define	DOWNLOAD_START_ADDRESS	0x040000
#define	EXP_ROM_START_ADDRESS	0x180000
#define	SCRATCH_START_ADDRESS	0x1C0000
#define	CONFIG_START_ADDRESS	0x1E0000


typedef struct SliAifHdr
{
	uint32_t	CompressBr;
	uint32_t	RelocBr;
	uint32_t	ZinitBr;
	uint32_t	EntryBr;
	uint32_t	Area_ID;
	uint32_t	RoSize;
	uint32_t	RwSize;
	uint32_t	DbgSize;
	uint32_t	ZinitSize;
	uint32_t	DbgType;
	uint32_t	ImageBase;
	uint32_t	Area_Size;
	uint32_t	AddressMode;
	uint32_t	DataBase;
	uint32_t	AVersion;
	uint32_t	Spare2;
	uint32_t	DebugSwi;
	uint32_t	ZinitCode[15];
} AIF_HDR, *PAIF_HDR;

typedef struct ImageHdr
{
	uint32_t	BlockSize;
	PROG_ID		Id;
	uint32_t	Flags;
	uint32_t	EntryAdr;
	uint32_t	InitAdr;
	uint32_t	ExitAdr;
	uint32_t	ImageBase;
	uint32_t	ImageSize;
	uint32_t	ZinitSize;
	uint32_t	RelocSize;
	uint32_t	HdrCks;
} IMAGE_HDR, *PIMAGE_HDR;



typedef struct
{
	PROG_ID		prog_id;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	pci_cfg_rsvd:27;
	uint32_t	use_hdw_def:1;
	uint32_t	pci_cfg_sel:3;
	uint32_t	pci_cfg_lookup_sel:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	pci_cfg_lookup_sel:1;
	uint32_t	pci_cfg_sel:3;
	uint32_t	use_hdw_def:1;
	uint32_t	pci_cfg_rsvd:27;
#endif
	union
	{
		PROG_ID		boot_bios_id;
		uint32_t	boot_bios_wd[2];
	} u0;
	PROG_ID		sli1_prog_id;
	PROG_ID		sli2_prog_id;
	PROG_ID		sli3_prog_id;
	PROG_ID		sli4_prog_id;
	union
	{
		PROG_ID		EROM_prog_id;
		uint32_t	EROM_prog_wd[2];
	} u1;
} WAKE_UP_PARMS, *PWAKE_UP_PARMS;


#define	PROG_DESCR_STR_LEN	24
#define	MAX_LOAD_ENTRY		32

typedef struct
{
	uint32_t	next;
	uint32_t	prev;
	uint32_t	start_adr;
	uint32_t	len;
	union
	{
		PROG_ID		id;
		uint32_t	wd[2];
	} un;
	uint8_t		prog_descr[PROG_DESCR_STR_LEN];
} LOAD_ENTRY;

typedef struct
{
	uint32_t	head;
	uint32_t	tail;
	uint32_t	entry_cnt;
	LOAD_ENTRY	load_entry[MAX_LOAD_ENTRY];
} LOAD_LIST;

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_MBOX_H */
