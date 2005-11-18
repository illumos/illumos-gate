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

#ifndef _SYS_UPA64S_VAR_H
#define	_SYS_UPA64S_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	HI32(x) ((uint32_t)(((uint64_t)(x)) >> 32))
#define	LO32(x) ((uint32_t)(uintptr_t)(x))
#define	UPA64S_PORTS	2	/* number of UPA ports per device */

/*
 * the following typedef is used to describe the state
 * of a UPA port interrupt.
 */
typedef enum { INO_FREE = 0, INO_INUSE } ino_state_t;

/*
 * INO related macros:
 */
#define	UPA64S_MAKE_MONDO(id, ino)	((id) << 6 | (ino))
#define	UPA64S_MONDO_TO_INO(mondo) 	((mondo) & 0x3f)

/*
 * Interrupt Mapping Registers
 */
#define	IMR_MONDO			0x7ff
#define	IMR_TID_BIT			26
#define	IMR_TID				(0x1f << IMR_TID_BIT)
#define	IMR_VALID			(1u << 31)
#define	UPA64S_IMR_TO_CPUID(imr)	(((imr) & IMR_TID) >> IMR_TID_BIT)
#define	UPA64S_IMR_TO_MONDO(imr)	((imr) & IMR_MONDO)
#define	UPA64S_CPUID_TO_IMR(cpuid)	((cpuid) << IMR_TID_BIT)
#define	UPA64S_GET_MAP_REG(mondo, imr)	((mondo) | (imr) | IMR_VALID)

/*
 * The following structure defines the format of UPA64S addresses.
 * This structure is used to hold UPA64S "reg" property entries.
 */
typedef struct upa64s_regspec {
	uint64_t upa64s_phys;
	uint64_t upa64s_size;
} upa64s_regspec_t;

/*
 * The following structure defines the format of a "ranges"
 * property entry for UPA64S bus node.
 */
typedef struct upa64s_ranges {
	uint64_t upa64s_child;
	uint64_t upa64s_parent;
	uint64_t upa64s_size;
} upa64s_ranges_t;

/*
 * per-upa64s soft state structure:
 */
typedef struct upa64s_devstate {
	dev_info_t *dip;			/* devinfo structure */
	uint_t safari_id;			/* safari device id */

	ino_state_t ino_state[UPA64S_PORTS];	/* INO state */
	uint64_t *imr[UPA64S_PORTS];		/* Intr mapping reg; treat */
						/* as two element array */
	ddi_acc_handle_t imr_ah[UPA64S_PORTS];	/* Mapping handle */
	uint64_t imr_data[UPA64S_PORTS];	/* imr save/restore area */

	caddr_t config_base;			/* conf base address */
	uint64_t *upa0_config;			/* UPA 0 config */
	uint64_t *upa1_config;			/* UPA 1 config */
	uint64_t *if_config;			/* UPA inteface config */
	uint64_t *estar;			/* UPA estar control */
	ddi_acc_handle_t config_base_ah;	/* config acc handle */

	int power_level;			/* upa64s' power level */
	int saved_power_level;			/* power level during suspend */
} upa64s_devstate_t;

/*
 * UPA64S Register Offsets
 */
#define	UPA64S_UPA0_CONFIG_OFFSET	0x00
#define	UPA64S_UPA1_CONFIG_OFFSET	0x08
#define	UPA64S_IF_CONFIG_OFFSET		0x10
#define	UPA64S_ESTAR_OFFSET		0x18

/*
 * UPA64S Interface Configurations
 */
#define	UPA64S_NOT_POK_RST_L	0x0
#define	UPA64S_POK_RST_L	0x2
#define	UPA64S_POK_NOT_RST_L	0x3

/*
 * UPA64S Energy Star Control Register
 */
#define	UPA64S_FULL_SPEED	0x01
#define	UPA64S_1_2_SPEED	0x02
#define	UPA64S_1_64_SPEED	0x40

/*
 * Power Management definitions
 */
#define	UPA64S_PM_COMP		0		/* power management component */
#define	UPA64S_PM_UNKNOWN	-1		/* power unknown */
#define	UPA64S_PM_RESET		0		/* power off */
#define	UPA64S_PM_NORMOP	1		/* power on */

/*
 * upa64s soft state macros:
 */
#define	get_upa64s_soft_state(i)	\
	((upa64s_devstate_t *)ddi_get_soft_state(per_upa64s_state, (i)))
#define	alloc_upa64s_soft_state(i)	\
	ddi_soft_state_zalloc(per_upa64s_state, (i))
#define	free_upa64s_soft_state(i)	\
	ddi_soft_state_free(per_upa64s_state, (i))

/*
 * debugging definitions:
 */
#if defined(DEBUG)
#define	D_ATTACH	0x00000001
#define	D_DETACH	0x00000002
#define	D_POWER		0x00000004
#define	D_MAP		0x00000008
#define	D_CTLOPS	0x00000010
#define	D_G_ISPEC	0x00000020
#define	D_A_ISPEC	0x00000040
#define	D_R_ISPEC	0x00000080
#define	D_INIT_CLD	0x00400000
#define	D_RM_CLD	0x00800000
#define	D_GET_REG	0x01000000
#define	D_XLATE_REG	0x02000000
#define	D_INTRDIST	0x04000000

#define	D_CONT		0x80000000

#define	DBG(flag, psp, fmt) \
	upa64s_debug(flag, psp, fmt, 0, 0, 0, 0, 0);
#define	DBG1(flag, psp, fmt, a1) \
	upa64s_debug(flag, psp, fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	DBG2(flag, psp, fmt, a1, a2) \
	upa64s_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	DBG3(flag, psp, fmt, a1, a2, a3) \
	upa64s_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), 0, 0);
#define	DBG4(flag, psp, fmt, a1, a2, a3, a4) \
	upa64s_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), (uintptr_t)(a4), 0);
#define	DBG5(flag, psp, fmt, a1, a2, a3, a4, a5) \
	upa64s_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), (uintptr_t)(a4), (uintptr_t)(a5));

static void upa64s_debug(uint_t, dev_info_t *, char *, uintptr_t, uintptr_t, \
	uintptr_t, uintptr_t, uintptr_t);
#else
#define	DBG(flag, psp, fmt)
#define	DBG1(flag, psp, fmt, a1)
#define	DBG2(flag, psp, fmt, a1, a2)
#define	DBG3(flag, psp, fmt, a1, a2, a3)
#define	DBG4(flag, psp, fmt, a1, a2, a3, a4)
#define	DBG5(flag, psp, fmt, a1, a2, a3, a4, a5)
#define	dump_dma_handle(flag, psp, h)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_UPA64S_VAR_H */
