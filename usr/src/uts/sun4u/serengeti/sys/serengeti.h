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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SERENGETI_H
#define	_SYS_SERENGETI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * serengeti.h - Serengeti/WildCat common header file
 *
 * This header file contains the common definitions and macros for the
 * Serengeti and WildCat platforms. We define them all here to avoid them
 * being redefined in numerous different drivers.
 */

#include <sys/dditypes.h>

/*
 * Definitions
 * ===========
 */

#ifndef	TRUE
#define	TRUE	1
#endif

#ifndef	FALSE
#define	FALSE	0
#endif


#define	SG_MAX_IO_PER_BD		5	/* 4 pci buses + cpci */
#define	SG_MAX_CMPS_PER_BD		4
#define	SG_MAX_CPUS_PER_BD		8
#define	SG_MAX_MEM_PER_BD		1
#define	SG_MAX_CPU_BDS			6
#define	SG_MAX_IO_BDS			4
#define	SG_MAX_POWER_SUPPLIES		6
#define	SG_MAX_FAN_TRAYS		6
#define	SG_MAX_REPEATER_BDS		4
#define	SG_MAX_BDS			(SG_MAX_CPU_BDS + SG_MAX_IO_BDS)
#define	SG_MAX_CPUS			(SG_MAX_CPUS_PER_BD * SG_MAX_CPU_BDS)

#define	SG_MAX_SLOTS_PER_IO_BD		8
#define	SG_SCHIZO_PER_IO_BD		2

#define	SSM_MAX_INSTANCES		16
#define	SSM_MAX_BDS			(SSM_MAX_INSTANCES * SG_MAX_BDS)

#define	SG_MIN_CPU_SAFARI_ID		0	/* 0x00 */
#define	SG_MAX_CPU_SAFARI_ID		23	/* 0x17 */
#define	SG_MIN_IO_SAFARI_ID		24	/* 0x18 */
#define	SG_MAX_IO_SAFARI_ID		31	/* 0x1F */


/*
 * possible states for the Keyswitch Position.
 */
#define	SG_KEYSWITCH_POSN_UNKNOWN	(-1)
#define	SG_KEYSWITCH_POSN_ON		2
#define	SG_KEYSWITCH_POSN_DIAG		3
#define	SG_KEYSWITCH_POSN_SECURE	4



/*
 * Macros
 * ======
 */

/* we only need the 5 LSB of the portid to calculate the board number */
#define	SG_SAFARI_ID_MASK		0x1F	/* 5 bits */
#define	SG_CPU_ID_MASK			0x21F	/* bit 9 and bits 0-4 */
#define	SG_CORE_ID_MASK			0x200	/* bit 9 */
#define	SG_NODE_MASK			0x0F	/* 4 bits */
#define	SG_PORTID_NODE_SHIFT		5

/*
 * For Serengeti and WildCat the portid consists of 10 bits.
 *
 * [9] [8 -------- 5][4 --------- 0]
 *  ^      NodeID        AgentID
 *  |___ Used in CMP to identify core 1.  Unused with non-CMP.
 *
 * For CPU boards:
 *	Aid <4:2>			: Board ID/Number
 *	Aid <1:0>			: CPU ID
 * For IO boards:
 *	(Aid <4:0> - 24) / 2 + 6	: Board ID/Number
 * 	(Aid <4:0> - 24) % 2		: Schizo ID
 */

/*
 * For Jaguar there are two CPU IDs the can be derived from portid
 * and coreid.  On Serengeti, bit 9 is set for core 1, resulting in
 * the cpuid for core 1 being 512 off from the one for core 0.
 */
#define	SG_JG_CORE1_SHIFT		9
#define	SG_JG_CORE1_OFFSET		(1 << SG_JG_CORE1_SHIFT)
#define	SG_PORTID_TO_CPUID(p, c)	((p) + ((c) << SG_JG_CORE1_SHIFT))
#define	SG_PORTID_TO_CPU_UNIT(p, c)	((p % SG_MAX_CMPS_PER_BD) | \
					    ((c) * SG_MAX_CMPS_PER_BD))
#define	SG_CPUID_TO_PORTID(c)		((c) & SG_SAFARI_ID_MASK)
#define	SG_CPUID_TO_COREID(c)		(((c) & SG_CORE_ID_MASK) >> \
					    SG_JG_CORE1_SHIFT)
#define	SG_CPUID_TO_CPU_UNIT(c)		SG_PORTID_TO_CPU_UNIT( \
					    SG_CPUID_TO_PORTID(c), \
					    SG_CPUID_TO_COREID(c))

/*
 * SG_PORTID_TO_NODEID
 *
 * Calculates the SSM NodeID from the portid
 */
#define	SG_PORTID_TO_NODEID(portid)	(((portid) >> SG_PORTID_NODE_SHIFT) & \
						SG_NODE_MASK)

/*
 * SG_PORTID_TO_SAFARI_ID
 *
 * Calculates the Safari Agent ID from the portid.
 */
#define	SG_PORTID_TO_SAFARI_ID(portid)	((portid) & SG_SAFARI_ID_MASK)


/*
 * SG_PORTID_TO_BOARD_NUM
 *
 * If a valid portid is passed in, this macro returns the board number
 * associated with it, otherwise it returns -1.
 */
#define	SG_PORTID_TO_BOARD_NUM(portid) \
	((SG_PORTID_IS_CPU_TYPE(portid)) ? \
		(SG_CPU_BD_PORTID_TO_BD_NUM(portid)) : \
	((SG_PORTID_IS_IO_TYPE(portid)) ? \
		SG_IO_BD_PORTID_TO_BD_NUM(portid) : (-1)))

/*
 * SG_BOARD_IS_CPU_TYPE
 *
 * If the board number of a board of CPU type is passed in, TRUE is returned,
 * otherwise FALSE.
 */
#define	SG_BOARD_IS_CPU_TYPE(board_num) \
	((((board_num) >= 0) && ((board_num) < SG_MAX_CPU_BDS)) ? TRUE: FALSE)

/*
 * SG_BOARD_IS_IO_TYPE
 *
 * If the board number of a board of IO type is passed in, TRUE is returned,
 * otherwise FALSE.
 */
#define	SG_BOARD_IS_IO_TYPE(board_num) \
	((((board_num) >= SG_MAX_CPU_BDS) && \
		((board_num) < SG_MAX_BDS)) ? TRUE: FALSE)

/*
 * SG_PORTID_IS_CPU_TYPE
 *
 * If the portid associated with a CPU board is passed in, TRUE is returned,
 * otherwise FALSE.
 */
#define	SG_PORTID_IS_CPU_TYPE(portid) \
	(((((portid) & SG_SAFARI_ID_MASK) >= SG_MIN_CPU_SAFARI_ID) && \
	(((portid) & SG_SAFARI_ID_MASK) <= SG_MAX_CPU_SAFARI_ID)) ? TRUE: FALSE)

/*
 * SG_PORTID_IS_IO_TYPE
 *
 * If the portid associated with an IO board is passed in, TRUE is returned,
 * otherwise FALSE.
 */
#define	SG_PORTID_IS_IO_TYPE(portid) \
	(((((portid) & SG_SAFARI_ID_MASK) >= SG_MIN_IO_SAFARI_ID) && \
	(((portid) & SG_SAFARI_ID_MASK) <= SG_MAX_IO_SAFARI_ID)) ? TRUE: FALSE)

/*
 * SG_CPU_BD_PORTID_TO_BD_NUM
 *
 * If the portid associated with a CPU board is passed in, the board number
 * associated with this portid is returned, otherwise -1.
 */
#define	SG_CPU_BD_PORTID_TO_BD_NUM(portid) \
	((SG_PORTID_IS_CPU_TYPE(portid)) ? \
		(((portid) & SG_SAFARI_ID_MASK) / 4) : (-1))

/*
 * SG_IO_BD_PORTID_TO_BD_NUM
 *
 * If the portid associated with an IO board is passed in, the board number
 * associated with this portid is returned, otherwise -1.
 */
#define	SG_IO_BD_PORTID_TO_BD_NUM(portid) \
	(SG_PORTID_IS_IO_TYPE(portid) ? \
		(((((portid) & SG_SAFARI_ID_MASK) - 24) / 2) + 6) : (-1))

/*
 * SG_PORTID_TO_CPU_POSN
 *
 * If the portid associated with a CPU board is passed in, the position
 * of the CPU module for this portid is returned, otherwise -1.
 */
#define	SG_PORTID_TO_CPU_POSN(portid) \
	((SG_PORTID_IS_CPU_TYPE(portid)) ? \
		(((portid) & SG_SAFARI_ID_MASK) % 4) : (-1))

/*
 * Serengeti slices are defined by bits 34..41 of the physical address
 * space, and can contain Safari agent ID bits depending upon the SC
 * firmware being used.
 */

#define	PA_SLICE_SHIFT		(34)
#define	PFN_SLICE_SHIFT		(PA_SLICE_SHIFT - MMU_PAGESHIFT)
#define	PA_2_SLICE(pa)		(((pa) >> PA_SLICE_SHIFT) & SG_SLICE_MASK)
#define	PFN_2_SLICE(pfn)	(((pfn) >> PFN_SLICE_SHIFT) & SG_SLICE_MASK)

/* Define the max memory banks per CPU board */
#define	SG_MAX_BANKS_PER_MC	(4)

/* Define the number of possible slices for the span of slice bits */
#define	SG_SLICE_MASK		(0xff)
#define	SG_MAX_SLICE		(SG_SLICE_MASK + 1)

/*
 * b represents the SB and c represents the processor (P)
 * in relation to the SB.
 */
#define	MAKE_CPUID(b, c)	((b*4) + c)

/* Each physical CPU has 2 ecache DIMMs */
#define	SG_NUM_ECACHE_DIMMS_PER_CPU	2

/* Bit 4 of the physical address indicates ecache dimm 0 or 1 */
#define	SG_ECACHE_DIMM_SHIFT	4
#define	SG_ECACHE_DIMM_MASK	0x10

extern	dev_info_t	*find_chosen_dip(void);

extern int sg_get_prom_version(int *sysp, int *intfp, int *bldp);
extern int sg_prom_sb_dr_check(void);
extern int sg_prom_cpci_dr_check(void);
extern int sg_get_ecacheunum(int cpuid, uint64_t physaddr, char *buf,
    uint_t buflen, int *lenp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SERENGETI_H */
