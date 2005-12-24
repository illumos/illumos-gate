/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PLAT_ECC_NUM_H
#define	_SYS_PLAT_ECC_NUM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/int_types.h>
#include <sys/cheetahregs.h>
#include <sys/cpuvar.h>
#include <sys/dditypes.h>
#include <sys/ddipropdefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/platform_module.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>

/*
 * This file contains the common definitions used by the platform
 * unum ecc logging.
 */

typedef enum {
	PLAT_ECC_ERROR_MESSAGE,
	PLAT_ECC_INDICTMENT_MESSAGE,
	PLAT_ECC_ERROR2_MESSAGE,
	PLAT_ECC_INDICTMENT2_MESSAGE,
	PLAT_ECC_CAPABILITY_MESSAGE,
	PLAT_ECC_DIMM_SID_MESSAGE
} plat_ecc_message_type_t;

/* Platform-specific function for sending mailbox message */
extern int plat_send_ecc_mailbox_msg(plat_ecc_message_type_t, void *);

/* For figuring out unique CPU id */
extern int plat_make_fru_cpuid(int, int, int);

/* For figuring out board number for given CPU id */
extern int plat_make_fru_boardnum(int);

/* For initializing the taskqs */
extern void plat_ecc_init(void);

/* For setting the capability value */
extern void plat_ecc_capability_sc_set(uint32_t cap);

/* For sending a capability message to the SC */
extern int plat_ecc_capability_send(void);

/* For determining the maximum cpumem boards possible */
extern int plat_max_cpumem_boards(void);

/* For parsing the values from a memory unum */
extern int parse_unum_memory(char *, int *, int *, int *, int *, int *);

/*
 * The following variables enable and disable the fruid message logging on SC.
 * ecc_log_fruid_enable can be set in /etc/system or via mdb.  A value
 * of 1 is default, and indicates the messages are sent.  A value of 0
 * indicates that the messages are not sent.
 */
extern int ecc_log_fruid_enable;

#define	ECC_FRUID_ENABLE_DEFAULT	1

#define	PLAT_ECC_JNUMBER_LENGTH	60
typedef struct plat_ecc_error_data {
	uint8_t		version;	/* Starting with 1 */
	uint8_t		error_code;	/* Error Code */
	uint16_t	proc_num;	/* Processor Number of */
					/* CPU in error */
	uint8_t		bank_no;	/* 0 or 1 */
	uint8_t		ecache_dimm_no;	/* 0 to 3 */
	uint8_t		error_type;	/* single, two, three, quad */
					/* or multiple bit error status */
	uint8_t		databit_type;	/* Identify the databit type: */
					/* MTAG, ECC, MTAGECC or Data */
	uint8_t		databit_no;	/* Failed Databit number */
	uint8_t		node_no;	/* Wildcat node number */
	uint16_t	detecting_proc;	/* Processor detecting the ECC error */
	char		Jnumber[60];	/* Jnumber of the Dimm or Ecache */
} plat_ecc_error_data_t;

#define	PLAT_ECC_VERSION	3
#define	PLAT_ERROR_CODE_UNK	0x0	/* Unknown */
#define	PLAT_ERROR_CODE_CE	0x1	/* Correctable ECC error */
#define	PLAT_ERROR_CODE_UE	0x2	/* Uncorrectable ECC error */
#define	PLAT_ERROR_CODE_EDC	0x3	/* Correctable ECC error from E$ */
#define	PLAT_ERROR_CODE_EDU	0x4	/* Uncorrectable ECC error from E$ */
#define	PLAT_ERROR_CODE_WDC	0x5	/* Correctable E$ write-back ECC */
#define	PLAT_ERROR_CODE_WDU	0x6	/* Uncorrectable E$ write-back ECC */
#define	PLAT_ERROR_CODE_CPC	0x7	/* Copy-out correctable ECC error */
#define	PLAT_ERROR_CODE_CPU	0x8	/* Copy-out uncorrectable ECC error */
#define	PLAT_ERROR_CODE_UCC	0x9	/* SW handled correctable ECC */
#define	PLAT_ERROR_CODE_UCU	0xa	/* SW handled uncorrectable ECC */
#define	PLAT_ERROR_CODE_EMC	0xb	/* Correctable MTAG ECC error */
#define	PLAT_ERROR_CODE_EMU	0xc	/* Uncorrectable MTAG ECC error */

#define	PLAT_ERROR_TYPE_UNK	0x0	/* Unknown */
#define	PLAT_ERROR_TYPE_SINGLE	0x1	/* Single bit error */
#define	PLAT_ERROR_TYPE_M2	0x2	/* Double bit error */
#define	PLAT_ERROR_TYPE_M3	0x3	/* Triple bit error */
#define	PLAT_ERROR_TYPE_M4	0x4	/* Quad bit error */
#define	PLAT_ERROR_TYPE_M	0x5	/* Multiple bit error */

#define	PLAT_BIT_TYPE_MULTI	0x0	/* Error is 2 or more bits */
#define	PLAT_BIT_TYPE_MTAG_D	0x1	/* MTAG data error */
#define	PLAT_BIT_TYPE_MTAG_E	0x2	/* MTAG ECC error */
#define	PLAT_BIT_TYPE_ECC	0x3	/* ECC error */
#define	PLAT_BIT_TYPE_DATA	0x4	/* Data error */

/*
 * Based on "UltraSPARC-III Programmer's Reference Manual", these values are
 * obtained when you use the syndrome bits from the AFSR to index into the
 * ECC syndrome table.  See us3_common.c for more details on the definitions
 * of C0, C1, C2, ... C8, MT0, MT1, ... M3, M4 ... etc.
 */

#define	ECC_SYND_DATA_BEGIN	0
#define	ECC_SYND_DATA_LENGTH	128	/* data bits 0-127 */
#define	ECC_SYND_ECC_BEGIN	(ECC_SYND_DATA_BEGIN + ECC_SYND_DATA_LENGTH)
#define	ECC_SYND_ECC_LENGTH	9	/* ECC bits C0 - C* */
#define	ECC_SYND_MTAG_BEGIN	(ECC_SYND_ECC_BEGIN + ECC_SYND_ECC_LENGTH)
#define	ECC_SYND_MTAG_LENGTH	3	/* MTAG DATA bits MT0, MT1, MT3 */
#define	ECC_SYND_MECC_BEGIN	(ECC_SYND_MTAG_BEGIN + ECC_SYND_MTAG_LENGTH)
#define	ECC_SYND_MECC_LENGTH	4	/* MTAG ECC bits MTC0 - MTC3 */
#define	ECC_SYND_M2	144
#define	ECC_SYND_M3	145
#define	ECC_SYND_M4	146
#define	ECC_SYND_M	147

enum plat_ecc_type {PLAT_ECC_UNKNOWN, PLAT_ECC_MEMORY, PLAT_ECC_ECACHE };

typedef struct plat_ecc_msg_hdr {
	uint8_t		emh_major_ver;
	uint8_t		emh_minor_ver;
	uint16_t	emh_msg_type;
	uint16_t	emh_msg_length;
	uint16_t	emh_future0;	/* pad */
} plat_ecc_msg_hdr_t;

extern uint16_t ecc_error2_mailbox_flags;

#define	PLAT_ECC_ERROR2_SEND_L2_XXC		0x0001
#define	PLAT_ECC_ERROR2_SEND_L2_XXU		0x0002
#define	PLAT_ECC_ERROR2_SEND_L3_XXC		0x0004
#define	PLAT_ECC_ERROR2_SEND_L3_XXU		0x0008
#define	PLAT_ECC_ERROR2_SEND_MEM_ERRS		0x0010
#define	PLAT_ECC_ERROR2_SEND_BUS_ERRS		0x0020
#define	PLAT_ECC_ERROR2_SEND_L2_TAG_ERRS	0x0040
#define	PLAT_ECC_ERROR2_SEND_L3_TAG_ERRS	0x0080
#define	PLAT_ECC_ERROR2_SEND_L1_PARITY		0x0100
#define	PLAT_ECC_ERROR2_SEND_TLB_PARITY		0x0200
#define	PLAT_ECC_ERROR2_SEND_IV_ERRS		0x0400
#define	PLAT_ECC_ERROR2_SEND_MTAG_XXC		0x0800
#define	PLAT_ECC_ERROR2_SEND_IV_MTAG_XXC	0x1000
#define	PLAT_ECC_ERROR2_SEND_PCACHE		0x2000

/* default value for ecc_error2_mailbox_flags */
#define	PLAT_ECC_ERROR2_SEND_DEFAULT		0x3fff

typedef struct plat_ecc_error2_data {
	plat_ecc_msg_hdr_t	ee2d_header;	/* Header info */
	uint8_t		ee2d_type;		/* PLAT_ECC_ERROR2_* */
	uint8_t		ee2d_afar_status;	/* AFLT_STAT_* (see async.h) */
	uint8_t		ee2d_synd_status;	/* AFLT_STAT_* (see async.h) */
	uint8_t		ee2d_bank_number;	/* 0 or 1 */
	uint16_t	ee2d_detecting_proc;	/* Proc that detected error */
	uint16_t	ee2d_jnumber;		/* J# of the part in error */
	uint16_t	ee2d_owning_proc;	/* Proc that controls memory */
	uint16_t	ee2d_future1;		/* pad */
	uint32_t	ee2d_cpu_impl;		/* Proc type */
	uint64_t	ee2d_afsr;		/* AFSR */
	uint64_t	ee2d_sdw_afsr;		/* Shadow AFSR */
	uint64_t	ee2d_afsr_ext;		/* Extended AFSR */
	uint64_t	ee2d_sdw_afsr_ext;	/* Shadow extended AFSR */
	uint64_t	ee2d_afar;		/* AFAR */
	uint64_t	ee2d_sdw_afar;		/* Shadow AFAR */
	uint64_t	ee2d_timestamp;		/* Time stamp */
} plat_ecc_error2_data_t;

#define	ee2d_major_version	ee2d_header.emh_major_ver
#define	ee2d_minor_version	ee2d_header.emh_minor_ver
#define	ee2d_msg_type		ee2d_header.emh_msg_type
#define	ee2d_msg_length		ee2d_header.emh_msg_length

#define	PLAT_ECC_ERROR2_VERSION_MAJOR		1
#define	PLAT_ECC_ERROR2_VERSION_MINOR		1

/* Values for ee2d_type */
#define	PLAT_ECC_ERROR2_NONE			0x00
#define	PLAT_ECC_ERROR2_L2_CE			0x01
#define	PLAT_ECC_ERROR2_L2_UE			0x02
#define	PLAT_ECC_ERROR2_L3_CE			0x03
#define	PLAT_ECC_ERROR2_L3_UE			0x04
#define	PLAT_ECC_ERROR2_CE			0x05
#define	PLAT_ECC_ERROR2_UE			0x06
#define	PLAT_ECC_ERROR2_DUE			0x07
#define	PLAT_ECC_ERROR2_TO			0x08
#define	PLAT_ECC_ERROR2_BERR			0x09
#define	PLAT_ECC_ERROR2_DTO			0x0a
#define	PLAT_ECC_ERROR2_DBERR			0x0b
#define	PLAT_ECC_ERROR2_L2_TSCE			0x0c
#define	PLAT_ECC_ERROR2_L2_THCE			0x0d
#define	PLAT_ECC_ERROR2_L3_TSCE			0x0e /* Unused */
#define	PLAT_ECC_ERROR2_L3_THCE			0x0f
#define	PLAT_ECC_ERROR2_DPE			0x10
#define	PLAT_ECC_ERROR2_IPE			0x11
#define	PLAT_ECC_ERROR2_ITLB			0x12
#define	PLAT_ECC_ERROR2_DTLB			0x13
#define	PLAT_ECC_ERROR2_IVU			0x14
#define	PLAT_ECC_ERROR2_IVC			0x15
#define	PLAT_ECC_ERROR2_EMC			0x16
#define	PLAT_ECC_ERROR2_IMC			0x17
#define	PLAT_ECC_ERROR2_L3_MECC			0x18
#define	PLAT_ECC_ERROR2_PCACHE			0x19

#define	PLAT_ECC_ERROR2_NUMVALS			0x1a

typedef struct plat_ecc_ch_async_flt {
	int		ecaf_synd_status; /* AFLT_STAT_* (see async.h) */
	int		ecaf_afar_status; /* AFLT_STAT_* (see async.h) */
	uint64_t	ecaf_sdw_afar;
	uint64_t	ecaf_sdw_afsr;
	uint64_t	ecaf_afsr_ext;
	uint64_t	ecaf_sdw_afsr_ext;
} plat_ecc_ch_async_flt_t;

/*
 * The following structures/#defines are used to notify the SC
 * of DIMMs that fail the leaky bucket algorithm, E$ that experience
 * multiple correctable errors and fail the serd algorithm, and
 * E$ that experience any non-fatal uncorrectable error.
 */

extern uint8_t ecc_indictment_mailbox_disable;

/* The message is OK */
#define	PLAT_ECC_INDICTMENT_OK		0x00

/* Send the message, but don't trust it */
#define	PLAT_ECC_INDICTMENT_SUSPECT	0x01

/* Don't send message */
#define	PLAT_ECC_INDICTMENT_NO_SEND	0x02

extern uint8_t ecc_indictment_mailbox_flags;

/* DIMM indictments for CEs */
#define	PLAT_ECC_SEND_DIMM_INDICT		0x01

/* E$ indictments for UCC, WDC, CPC, EDC */
#define	PLAT_ECC_SEND_ECACHE_XXC_INDICT		0x02

/* E$ indictments for UCU, WDU, CPU, EDU */
#define	PLAT_ECC_SEND_ECACHE_XXU_INDICT		0x04

/* Default value for ecc_indictment_mailbox_flags */
#define	PLAT_ECC_SEND_DEFAULT_INDICT	(PLAT_ECC_SEND_ECACHE_XXC_INDICT |\
					PLAT_ECC_SEND_ECACHE_XXU_INDICT)

/*
 * WARNING: The plat_ecc_indictment_data_t struct size can be no bigger than
 * 128 bytes.  The union will fill out the structure to the correct size -
 * the string space used in solaris_version will fill out the rest of the
 * structure.
 *
 * Any changes made to this structure in the future should ensure that the
 * structure does not go over 128 bytes.
 */

#define	PLAT_ECC_INDICT_SIZE	128

typedef struct {
	uint8_t 	version;		/* Starting with 1 */
	uint8_t 	indictment_type;	/* see below for values */
	uint8_t 	indictment_uncertain;
				/* Value of ecc_indictment_mailbox_disable */
	uint8_t 	board_num;		/* board number of dimm/E$ */
	uint16_t	detecting_proc;		/* Processor Number of CPU */
						/* reporting error */
	uint16_t	syndrome;		/* syndrome of last error */
	uint16_t	jnumber;		/* Jnumber of dimm/E$ */
	uint16_t	future[7];		/* For future use */
	uint64_t	afsr;			/* AFSR of last error */
	uint64_t	afar;			/* AFAR of last error */
	char    	solaris_version[1];
						/* Solaris version string */
} plat_ecc_indict_msg_contents_t;

typedef union {
	plat_ecc_indict_msg_contents_t	msg_contents;
	uint8_t				filler[PLAT_ECC_INDICT_SIZE];
} plat_ecc_indictment_data_t;

#define	PLAT_ECC_VERSION_LENGTH		(PLAT_ECC_INDICT_SIZE - \
		offsetof(plat_ecc_indict_msg_contents_t, solaris_version))

#define	PLAT_ECC_INDICTMENT_VERSION	1

/*
 * Values for indictment_type.  For Panther, E$ refers to
 * the L3$.  For previous procs, E$ refers to the L2$.
 */
#define	PLAT_ECC_INDICT_NONE			0x00
#define	PLAT_ECC_INDICT_DIMM			0x01
#define	PLAT_ECC_INDICT_ECACHE_CORRECTABLES	0x02
#define	PLAT_ECC_INDICT_ECACHE_UNCORRECTABLE	0x03


/*
 * These values are used to set the state of msg_status
 *
 * 0 - No message in transit
 * 1 - taskq thread dispatched, dispatching thread waiting for signal
 * 2 - dispatched thread completed sending message
 * 3 - dispatching thread received interrupt, not waiting for signal
 */
#define	PLAT_ECC_NO_MSG_ACTIVE		0
#define	PLAT_ECC_TASK_DISPATCHED	1
#define	PLAT_ECC_MSG_SENT		2
#define	PLAT_ECC_INTERRUPT_RECEIVED	3

/*
 * Min and max sizes of plat_ecc_taskq
 */
#define	PLAT_ECC_TASKQ_MIN	2
#define	PLAT_ECC_TASKQ_MAX	8

extern uint16_t ecc_indictment2_mailbox_flags;


#define	PLAT_ECC_SEND_INDICT2_L2_XXU		0x0001
#define	PLAT_ECC_SEND_INDICT2_L2_XXC_SERD	0x0002
#define	PLAT_ECC_SEND_INDICT2_L2_TAG_SERD	0x0004
#define	PLAT_ECC_SEND_INDICT2_L3_XXU		0x0008
#define	PLAT_ECC_SEND_INDICT2_L3_XXC_SERD	0x0010
#define	PLAT_ECC_SEND_INDICT2_L3_TAG_SERD	0x0020
#define	PLAT_ECC_SEND_INDICT2_L1_SERD		0x0040
#define	PLAT_ECC_SEND_INDICT2_TLB_SERD		0x0080
#define	PLAT_ECC_SEND_INDICT2_FPU		0x0100
#define	PLAT_ECC_SEND_INDICT2_PCACHE_SERD	0x0200

#define	PLAT_ECC_SEND_INDICT2_DEFAULT		0x03ff

typedef struct plat_ecc_indictment2_data {
	plat_ecc_msg_hdr_t	ei2d_header;	/* Header info */
	uint8_t		ei2d_type;		/* PLAT_ECC_INDICT2_* */
	uint8_t		ei2d_uncertain;		/* See indictment_uncertain */
	uint8_t		ei2d_board_num;		/* Board number of dimm */
	uint8_t		ei2d_future1;		/* pad */
	uint16_t	ei2d_arraigned_proc;	/* Proc number */
	uint16_t	ei2d_jnumber;		/* Jnumber */
	uint32_t	ei2d_cpu_impl;		/* Proc type */
	uint32_t	ei2d_future2;		/* pad */
	uint64_t	ei2d_timestamp;		/* Time stamp */
} plat_ecc_indictment2_data_t;

#define	ei2d_major_version	ei2d_header.emh_major_ver
#define	ei2d_minor_version	ei2d_header.emh_minor_ver
#define	ei2d_msg_type		ei2d_header.emh_msg_type
#define	ei2d_msg_length		ei2d_header.emh_msg_length

#define	PLAT_ECC_INDICT2_MAJOR_VERSION	1
#define	PLAT_ECC_INDICT2_MINOR_VERSION	1

/*
 * Values for ei2d_type
 */

#define	PLAT_ECC_INDICT2_NONE			0x00
#define	PLAT_ECC_INDICT2_L2_UE			0x01
#define	PLAT_ECC_INDICT2_L2_SERD		0x02
#define	PLAT_ECC_INDICT2_L2_TAG_SERD		0x03
#define	PLAT_ECC_INDICT2_L3_UE			0x04
#define	PLAT_ECC_INDICT2_L3_SERD		0x05
#define	PLAT_ECC_INDICT2_L3_TAG_SERD		0x06
#define	PLAT_ECC_INDICT2_DCACHE_SERD		0x07
#define	PLAT_ECC_INDICT2_ICACHE_SERD		0x08
#define	PLAT_ECC_INDICT2_ITLB_SERD		0x09
#define	PLAT_ECC_INDICT2_DTLB_SERD		0x0a
#define	PLAT_ECC_INDICT2_FPU			0x0b
#define	PLAT_ECC_INDICT2_PCACHE_SERD		0x0c

#define	PLAT_ECC_INDICT2_NUMVALS		0x0d

/*
 * The following structure maps the indictment reason to its
 * corresponding type.
 */
typedef struct plat_ecc_bl_map {
	char	*ebm_reason;	/* Indictment reason */
	int	ebm_type;	/* Indictment type */
} plat_ecc_bl_map_t;

/*
 * This message is used to exchange the capability of the SC and Domain
 * so that both entities can adjust their behavior as appropriate.
 * Also the Solaris version is sent from the Domain along with the
 * capability bitmap.
 */
typedef struct plat_capability_data {
	plat_ecc_msg_hdr_t	capd_header;	/* Header info */
	uint32_t	capd_capability;	/* Capability bitmap */
	uint32_t	capd_future1;		/* pad */
	uint64_t	capd_future2;		/* pad */
	char		capd_solaris_version[1];
						/* Solaris version string ptr */
} plat_capability_data_t;

#define	capd_major_version	capd_header.emh_major_ver
#define	capd_minor_version	capd_header.emh_minor_ver
#define	capd_msg_type		capd_header.emh_msg_type
#define	capd_msg_length		capd_header.emh_msg_length

#define	PLAT_ECC_CAP_VERSION_MAJOR	1
#define	PLAT_ECC_CAP_VERSION_MINOR	1

#define	PLAT_ECC_CAPABILITY_ERROR		0x001
#define	PLAT_ECC_CAPABILITY_INDICT		0x002
#define	PLAT_ECC_CAPABILITY_ERROR2		0x004
#define	PLAT_ECC_CAPABILITY_INDICT2		0x008
#define	PLAT_ECC_CAPABILITY_FMA			0x010
#define	PLAT_ECC_CAPABILITY_EREPORTS		0x020	/* unused */
#define	PLAT_ECC_CAPABILITY_DIMM_SID		0x040
#define	PLAT_ECC_CAPABILITY_DP_ERROR		0x080
#define	PLAT_ECC_CAPABILITY_DP_FAULT		0x100

#define	PLAT_ECC_CAPABILITY_DOMAIN_DEFAULT	0x1df
#define	PLAT_ECC_CAPABILITY_SC_DEFAULT		0x003

extern uint32_t plat_ecc_capability_map_domain;
extern uint32_t plat_ecc_capability_map_sc;

/*
 * The following structure is a wrapper around the all messages. The
 * extra members are used for communicating between two threads.
 */
typedef struct plat_ecc_message {
	plat_ecc_message_type_t		ecc_msg_type;
	uint32_t			ecc_msg_status;
	uint32_t			ecc_msg_ret;
	uint32_t			ecc_msg_len;
	void *				ecc_msg_data;
} plat_ecc_message_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PLAT_ECC_NUM_H */
