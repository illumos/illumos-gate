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

#ifndef _SBDP_MEM_H
#define	_SBDP_MEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sbd.h>
#include <sys/sbdp_priv.h>

#define	SBDP_MAX_MCS_PER_NODE		4
#define	SBDP_MAX_MEM_NODES_PER_BOARD	4
#define	SBDP_MAX_CORES_PER_CMP		2

typedef uint64_t mc_dc_regs_t[SBDP_MAX_MCS_PER_NODE];

typedef struct {
	int	board;
	pnode_t	*nodes;
	int	nmem;
} mem_op_t;

typedef struct {
	uint_t	regspec_addr_hi;
	uint_t	regspec_addr_lo;
	uint_t	regspec_size_hi;
	uint_t	regspec_size_lo;
} mc_regspace;

typedef struct {
	uint64_t	mc_decode[SBDP_MAX_MCS_PER_NODE];
	uint64_t	mc_memctl;
} mc_regs_t;

/*
 * Memory controller register offsets
 */
#define	SG_MEM_TIMING1_CTL	0x400000
#define	SG_MEM_TIMING2_CTL	0x400008
#define	SG_MEM_TIMING3_CTL	0x400038
#define	SG_MEM_TIMING4_CTL	0x400040
#define	SG_MEM_DECODE0_ADR	0x400028
#define	SG_MEM_DECODE1_ADR	0x400010
#define	SG_MEM_DECODE2_ADR	0x400018
#define	SG_MEM_DECODE3_ADR	0x400020
#define	SG_MEM_CONTROL_ADR	0x400030
#define	SG_EMU_ACTIVITY_STATUS	0x400050

/*
 * Bit fields for the decode registers
 */
#define	SG_DECODE_VALID		0x8000000000000000ull
#define	SG_DECODE_UK		0x001ffe0000000000ull
#define	SG_DECODE_UM		0x000001fffff00000ull
#define	SG_DECODE_LK		0x00000000000fc000ull
#define	SG_DECODE_LM		0x0000000000003f00ull
#define	SG_INVAL_UM		0x0000000ffff00000ull
#define	SG_SLICE_INFO		0x000001fc00000000ull
#define	SG_ALIGNMENT		0x800000000ULL


/*
 * Memory Macros
 */
#define	MC_MEMDEC0(mc_addr) \
	(mc_addr) | SG_MEM_DECODE0_ADR
#define	MC_MEMDEC1(mc_addr) \
	(mc_addr) | SG_MEM_DECODE1_ADR
#define	MC_MEMDEC2(mc_addr) \
	(mc_addr) | SG_MEM_DECODE2_ADR
#define	MC_MEMDEC3(mc_addr) \
	(mc_addr) | SG_MEM_DECODE3_ADR
#define	MC_ACTIVITY_STATUS(mc_addr) \
	(mc_addr) | SG_EMU_ACTIVITY_STATUS


/*
 * Mappings to the array for the decode registers only
 */
#define	SG_MC_DECODE_I		0
#define	SG_MC_DECODE_II		1
#define	SG_MC_DECODE_III	2
#define	SG_MC_DECODE_IV		3
/*
 * Memory Macros
 */
#define	SG_REG_2_OFFSET(num) \
	    ((num) == SG_MC_DECODE_I ? (uint64_t)SG_MEM_DECODE0_ADR : \
	    (num) == SG_MC_DECODE_II ? (uint64_t)SG_MEM_DECODE1_ADR : \
	    (num) == SG_MC_DECODE_III ? (uint64_t)SG_MEM_DECODE2_ADR : \
	    (num) == SG_MC_DECODE_IV ? (uint64_t)SG_MEM_DECODE3_ADR : \
	    (uint64_t)-1)

#define	MC_VALID_SHIFT		63
#define	MC_UK_SHIFT		41
#define	MC_UM_SHIFT		20
#define	MC_LK_SHIFT		14
#define	MC_LM_SHIFT		8
#define	PHYS2UM_SHIFT		26
#define	MC_UK(memdec)		(((memdec) >> MC_UK_SHIFT) & 0xfffu)
#define	MC_LK(memdec)		(((memdec) >> MC_LK_SHIFT)& 0x3fu)
#define	MC_INTLV(memdec)	((~(MC_LK(memdec)) & 0xfu) + 1)
#define	MC_UK2SPAN(memdec)	((MC_UK(memdec) + 1) << PHYS2UM_SHIFT)
#define	MC_SPANMB(memdec)	(MC_UK2SPAN(memdec) >> 20)
#define	MC_UM(memdec)		(((memdec) >> MC_UM_SHIFT) & 0x1fffffu)
#define	MC_LM(memdec)		(((memdec) >> MC_LM_SHIFT) & 0x3f)
#define	MC_BASE(memdec)		(MC_UM(memdec) & ~(MC_UK(memdec)))
#define	MC_BASE2UM(base)	(((base) & 0x1fffffu) << MC_UM_SHIFT)
#define	SAF_MASK		0x000007ffff800000ull
#define	MC_OFFSET_MASK		0xffu

/*
 * Memory Slice information
 */
#define	SG_SLICE_16G_SIZE	0x400000000ULL
#define	SG_SLICE_32G_SIZE	0x800000000ULL
#define	SG_SLICE_64G_SIZE	0x1000000000ULL

/*
 * Copy-rename info
 */

#define	SBDP_RENAME_MAXOP	(PAGESIZE / sizeof (sbdp_rename_script_t))

/*
 * Must be same size as sbdp_rename_script_t.
 */
typedef struct {
	uint64_t	addr;
	uint_t		bd_id;
	pnode_t		node;
	uint_t		asi;
	uint_t		_filler;
} sbdp_mc_idle_script_t;

typedef struct {
	uint64_t	masr_addr;
	uint64_t	masr;
	uint_t		asi;
	uint_t		_filler;
} sbdp_rename_script_t;

typedef struct {
	sbdp_bd_t	*s_bdp;	/* pointer to src bd info */
	sbdp_bd_t	*t_bdp;	/* pointer to tgt bd info */
	sbdp_rename_script_t *script; 	/* points to the actual script */
	uint64_t	ret;
	sbdp_mc_idle_script_t *busy_mc;
} sbdp_cr_handle_t;


extern uint64_t lddsafaddr(uint64_t physaddr);
extern uint64_t lddmcdecode(uint64_t physaddr);
extern void stdmcdecode(uint64_t, uint64_t);

int sbdp_is_mem(pnode_t node, void *arg);
#ifdef DEBUG
int sbdp_passthru_readmem(sbdp_handle_t *hp, void *);
int sbdp_passthru_prep_script(sbdp_handle_t *hp, void *);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SBDP_MEM_H */
