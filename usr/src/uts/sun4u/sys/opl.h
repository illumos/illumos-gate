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

#ifndef	_OPL_H
#define	_OPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	OPL_MAX_CPU_PER_CMP		8
#define	OPL_MAX_CORES_PER_CMP		4
#define	OPL_MAX_STRANDS_PER_CORE	2
#define	OPL_MAX_CMP_UNITS_PER_BOARD	4
#define	OPL_MAX_BOARDS			16
#define	OPL_MAX_CPU_PER_BOARD		\
	(OPL_MAX_CPU_PER_CMP * OPL_MAX_CMP_UNITS_PER_BOARD)
#define	OPL_MAX_MEM_UNITS_PER_BOARD	1
#define	OPL_MAX_IO_UNITS_PER_BOARD	16
#define	OPL_MAX_PCICH_UNITS_PER_BOARD	4
#define	OPL_MAX_TSBS_PER_PCICH		2
#define	OPL_MAX_CORE_UNITS_PER_BOARD	\
	(OPL_MAX_CORES_PER_CMP * OPL_MAX_CMP_UNITS_PER_BOARD)

#define	OPL_MAX_COREID_PER_CMP		4
#define	OPL_MAX_STRANDID_PER_CORE	2
#define	OPL_MAX_CPUID_PER_CMP		(OPL_MAX_COREID_PER_CMP * \
	OPL_MAX_STRANDID_PER_CORE)
#define	OPL_MAX_CMPID_PER_BOARD		4
#define	OPL_MAX_CPUID_PER_BOARD		\
	(OPL_MAX_CPUID_PER_CMP * OPL_MAX_CMPID_PER_BOARD)
#define	OPL_MAX_COREID_PER_BOARD	\
	(OPL_MAX_COREID_PER_CMP * OPL_MAX_CMPID_PER_BOARD)
/*
 * Macros to extract LSB_ID, CHIP_ID, CORE_ID, and STRAND_ID
 * from the given cpuid.
 */
#define	LSB_ID(x)	(((uint_t)(x)/OPL_MAX_CPUID_PER_BOARD) & \
	(OPL_MAX_BOARDS - 1))
#define	CHIP_ID(x)	(((uint_t)(x)/OPL_MAX_CPUID_PER_CMP) & \
	(OPL_MAX_CMPID_PER_BOARD - 1))
#define	CORE_ID(x)	(((uint_t)(x)/OPL_MAX_STRANDID_PER_CORE) & \
	(OPL_MAX_COREID_PER_CMP - 1))
#define	STRAND_ID(x)	((uint_t)(x) & (OPL_MAX_STRANDID_PER_CORE - 1))

/*
 * Max. boards supported in a domain per model.
 */
#define	OPL_MAX_BOARDS_IKKAKU	1
#define	OPL_MAX_BOARDS_FF1	1
#define	OPL_MAX_BOARDS_FF2	2
#define	OPL_MAX_BOARDS_DC1	4
#define	OPL_MAX_BOARDS_DC2	8
#define	OPL_MAX_BOARDS_DC3	16

/* OPL model type */
typedef enum {
	FF1,
	FF2,
	DC1,
	DC2,
	DC3,
	IKKAKU
} opl_type_t;

/* OPL model specific cmds selection  */
#define	STD_DISPATCH_TABLE	0x0
#define	EXT_DISPATCH_TABLE	0x1

/*
 * Structure to gather model-specific information at boot.
 */
typedef struct opl_model_info {
	char		model_name[MAXSYSNAME];	/* OPL model name */
	int		model_max_boards;	/* Maximum boards per model */
	opl_type_t 	model_type;		/* Model type */
	int		model_cmds;		/* Model specific cmds */
} opl_model_info_t;

extern int	plat_max_boards(void);
extern int	plat_max_cpu_units_per_board(void);
extern int	plat_max_mem_units_per_board(void);
extern int	plat_max_io_units_per_board(void);
extern int	plat_max_cmp_units_per_board(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _OPL_H */
