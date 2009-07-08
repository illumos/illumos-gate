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

#ifndef	_PCITOOL_UI_H
#define	_PCITOOL_UI_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This defines the interface between the pcitool_ui.c module which parses the
 * commandline options, and the other pcitool modules which process them.
 */
#define	SUCCESS	0	/* This does not conflict with errno values. */
#define	FAILURE	-1	/* General failure. */

/*
 * Flags which get set in the flags field of pcitool_uiargs_t. There is a flag
 * for each option specified on the commandline.
 */
#define	NEXUS_FLAG	0x1
#define	LEAF_FLAG	0x2
#define	INTR_FLAG	0x4		/* Either -i or -m specified */
#define	PROBEDEV_FLAG	0x8		/* Probe a specific device */
#define	PROBETREE_FLAG	0x10		/* Probe all devs on a tree */
#define	PROBEALL_FLAG	0x20		/* Probe devs on all trees */
#define	PROBERNG_FLAG	0x40		/* Probe devs within bus ranges */
					/* - mod to PROBEALL and PROBETREE */
#define	PROBE_FLAGS	(PROBEDEV_FLAG | PROBETREE_FLAG | PROBEALL_FLAG | \
				PROBERNG_FLAG)
#define	ALL_COMMANDS	(NEXUS_FLAG | LEAF_FLAG | INTR_FLAG | PROBE_FLAGS)
#define	READ_FLAG	0x80
#define	WRITE_FLAG	0x100
#define	OFFSET_FLAG	0x200
#define	SIZE_FLAG	0x400
#define	ENDIAN_FLAG	0x800
#define	BYTEDUMP_FLAG	0x1000
#define	CHARDUMP_FLAG	0x2000
#define	ERRCONT_FLAG	0x4000
#define	VERBOSE_FLAG	0x8000
#define	QUIET_FLAG	0x10000
#define	LOOP_FLAG	0x20000
#define	SHOWCTLR_FLAG	0x40000
#define	SETGRP_FLAG	0x80000

/* Values specified by suboption parser. */
#define	BANK_SPEC_FLAG	(0x10000ULL << 32)
#define	BASE_SPEC_FLAG	(0x20000ULL << 32)
#define	BUS_SPEC_FLAG	(0x40000ULL << 32)
#define	DEV_SPEC_FLAG	(0x80000ULL << 32)
#define	FUNC_SPEC_FLAG	(0x100000ULL << 32)
#define	CPU_SPEC_FLAG	(0x200000ULL << 32)	/* -w <cpu#> */
#define	INO_ALL_FLAG	(0x400000ULL << 32)	/* -i all */
#define	INO_SPEC_FLAG	(0x800000ULL << 32)	/* -i <#ino> */
#define	MSI_ALL_FLAG	(0x1000000ULL << 32)	/* -m all */
#define	MSI_SPEC_FLAG	(0x2000000ULL << 32)	/* -m <#msi> */

/* Macros for a few heavily-used flags. */
#define	IS_VERBOSE(flags)	(flags & VERBOSE_FLAG)
#define	IS_QUIET(flags)		(flags & QUIET_FLAG)
#define	IS_LOOP(flags)		(flags & LOOP_FLAG)

/*
 * This is the structure of flags and parsed values returned from pcitool_ui.c
 */
typedef struct uiargs {
	uint64_t	write_value;
	uint64_t	base_address;
	uint64_t	flags;
	uint32_t	offset;
	uint32_t	bytedump_amt;
	uint32_t	intr_cpu;
	uint8_t		bus;
	uint8_t		device;
	uint8_t		function;
	uint8_t		size;
	uint8_t		bank;
	uint8_t		intr_ino;
	uint16_t	intr_msi;
	boolean_t	big_endian;
} pcitool_uiargs_t;

/* Exported functions. */

int get_commandline_args(int argc, char *argv[], pcitool_uiargs_t *parsed_args);
void usage(char *name);

#ifdef	__cplusplus
}
#endif

#endif	/* _PCITOOL_UI_H */
