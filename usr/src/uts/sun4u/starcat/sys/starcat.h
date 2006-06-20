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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_STARCAT_H
#define	_SYS_STARCAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Manifest constants of Starcat configuration
 */

#define	STARCAT_BDSET_MAX	18	/* maximum number of boardsets	*/

#define	STARCAT_BDSET_MIN	1	/* minimum number of boardsets	*/

#define	STARCAT_BDSET_SLOT_MAX	2	/* maximum slots per boardset	*/

#define	STARCAT_SLOT0_CPU_MAX	8	/* max CPUs per slot 0 board	*/

#define	STARCAT_SLOT1_CPU_MAX	4	/* max CPUs per slot 1 board	*/

#define	STARCAT_BDSET_CPU_MAX	12	/* maximum CPUs per boardset	*/

#define	STARCAT_SLOT0_MEM_MAX	4	/* max mem units per slot 0 bd	*/

#define	STARCAT_SLOT1_MEM_MAX	0	/* max mem units per slot 1 bd	*/

#define	STARCAT_BDSET_MEM_MAX	4	/* max mem units per boardset	*/

#define	STARCAT_SLOT0_IO_MAX	0	/* max I/O ctrlrs per slot 0 bd	*/

#define	STARCAT_SLOT1_IO_MAX	2	/* max I/O ctrlrs per slot 1 bd	*/

#define	STARCAT_BDSET_IO_MAX	2	/* max I/O ctrlrs per boardset	*/

#define	STARCAT_TSB_PER_IO	2	/* each IO has two leaves */

					/* max prealloc spare tsb's	*/
#define	STARCAT_SPARE_TSB_MAX	\
	(STARCAT_BDSET_MAX * STARCAT_BDSET_IO_MAX * STARCAT_TSB_PER_IO)

/*
 * Data bearing mondo vector (DMV) support
 *
 * For Starcat, we need to add a few extra "hardware" dmv interrupts.
 * These actually do not correspond to physical hardware but are used
 * by Starcat IDN.
 */
#define	STARCAT_DMV_EXTRA	4
#define	STARCAT_DMV_HWINT	(MAX_UPA + STARCAT_DMV_EXTRA)
#define	STARCAT_DMV_IDN_BASE	(MAX_UPA)

/*
 * The CPU ID on starcat looks like this:
 *
 *     9        5  4     3     2    1    0
 *    --------------------------------------
 *    | Expander |   | Slot | Core | LPORT |
 *    --------------------------------------
 *
 * Expander   Starcat has STARCAT_BDSET_MAX (18) expanders.
 * Slot       Starcat has STARCAT_BDSET_SLOT_MAX (2) slots per expander.
 *            Slot 0 carries a CPU-MEM board which has 4 processor chips.
 *            Slot 1 carries an I/O board typically. But it can be
 *            configured to carry a MAXCAT board which has 2 processor
 *            chips on board.
 * LPORT      Port number within the slot for a chip. This is also the
 *            chip number within the slot. Note that Slot 1 can have only
 *            2 chips, but this representation allows for 4. This is just
 *            the theoretical max.
 * Core       Core number within the chip.
 *
 * Currently, the maximum number of cores supported is 2 per chip (on
 * Panther and Jaguar).
 *
 */
/*
 * Macros for manipulating CPU IDs
 */
#define	STARCAT_CPUID_TO_EXPANDER(p)	(((p) >> 5) & 0x1f)
#define	STARCAT_CPUID_TO_BOARDSLOT(p)	(((p) >> 3) & 0x1)
#define	STARCAT_CPUID_TO_PORTID(p)	((p) & ~0x4)
#define	STARCAT_CPUID_TO_COREID(p)	(((p) >> 2) & 0x1)
#define	STARCAT_CPUID_TO_CORE_BIT(p)	((p) & (0x1 << 2))
#define	STARCAT_CPUID_TO_AGENT(p)	((p) & 0x7)
#define	STARCAT_CPUID_TO_LPORT(p)	((p) & 0x3)

#define	MAKE_CPUID(e, s, a)	\
		((((e) & 0x1f) << 5) | (((s) & 0x1) << 3) | ((a) & 0x7))

/*
 * Definitions for decoding memory controller registers.  These values
 * are taken from Chapter 9 of the SPARCV9 JSP-1 US-III implementation
 * supplement.
 */

/* Starcat has four banks of memory per MC */
#define	MAX_BANKS_PER_MC	(4)

/* Use only low bits for local CPU MC ASI */
#define	MC_OFFSET_MASK		(0xffu)

/* Shifts to access specific fields of the memdecode register */
#define	MC_VALID_SHIFT		(63)	/* Shift for valid bit */
#define	MC_UK_SHIFT		(41)	/* Shift for upper mask field */
#define	MC_UM_SHIFT		(20)	/* Shift for upper match field */
#define	PHYS2UM_SHIFT		(26)	/* UM field matches bits 42-26 of PA */

/* Extract upper mask field from the decode register */
#define	MC_UK(memdec)		(((memdec) >> MC_UK_SHIFT) & 0xfffu)

/* Extract upper match field from memdecode register */
#define	MC_UM(memdec)		(((memdec) >> MC_UM_SHIFT) & 0x1fffffu)

/* Size of the range covered by the address mask field */
#define	MC_UK2SPAN(memdec)	((MC_UK(memdec) + 1) << PHYS2UM_SHIFT)

/* The base PA the memdecode register will respond to */
#define	MC_BASE(memdec)		(MC_UM(memdec) & ~(MC_UK(memdec)))


/*
 * Prototypes for functions
 */

extern int set_platform_max_ncpus(void);
extern int plat_max_boards(void);
extern int plat_max_cpu_units_per_board(void);
extern int plat_max_mem_units_per_board(void);
extern int plat_max_io_units_per_board(void);
extern uint64_t lddmcdecode(uint64_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STARCAT_H */
