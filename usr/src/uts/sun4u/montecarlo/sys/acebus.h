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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ACEBUS_H
#define	_SYS_ACEBUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * driver state type:
 */
typedef enum { NEW = 0, ATTACHED, RESUMED, DETACHED,
		SUSPENDED, PM_SUSPENDED } driver_state_t;

/*
 * The i86pc specific code fragments are to support the debug of "honeynut"
 * and "multigrain" prototypes on i86pc platform.  Most of the fragments
 * deal with differences in the interrupt dispatching between the prototypes
 * and the cheerio ebus.  On the prototype boards, all interrupt lines are
 * tied together.  For this case, the nexus driver uses a common interrupt
 * handler to poll all of its children.
 */
#if defined(i86pc)
#define	MAX_EBUS_DEVS	6

/*
 * ebus device interrupt info;
 */
typedef struct {
	char *name;
	uint_t inuse;
	uint_t (*handler)();
	caddr_t arg;
} ebus_intr_slot_t;
#endif

struct ebus_intr_map {
	uint32_t ebus_phys_hi;
	uint32_t ebus_phys_low;
	uint32_t ebus_intr;
	uint32_t intr_ctlr_nodeid;
	uint32_t ino;
};

struct ebus_intr_map_mask {
	uint32_t ebus_phys_hi;
	uint32_t ebus_phys_low;
	uint32_t ebus_intr;
};

/*
 * driver soft state structure:
 */
typedef struct {
	dev_info_t *dip;
	driver_state_t state;
	pci_regspec_t *reg;
	int nreg;
	struct ebus_pci_rangespec *rangep;
	int range_cnt;

#if defined(i86pc)
	ddi_iblock_cookie_t iblock;
	ddi_idevice_cookie_t idevice;
	ebus_intr_slot_t intr_slot[MAX_EBUS_DEVS];
#endif
#if defined(__sparc)
	/* Interrupt support */
	int intr_map_size;
	struct ebus_intr_map *intr_map;
	struct ebus_intr_map_mask *intr_map_mask;
#endif
} ebus_devstate_t;

/*
 * definition of ebus reg spec entry:
 */
typedef struct {
	uint32_t addr_hi;
	uint32_t addr_low;
	uint32_t size;
} ebus_regspec_t;

/* EBUS range entry */
struct ebus_pci_rangespec {
	uint32_t ebus_phys_hi;			/* Child hi range address */
	uint32_t ebus_phys_low;			/* Child low range address */
	uint32_t pci_phys_hi;			/* Parent hi rng addr */
	uint32_t pci_phys_mid;			/* Parent mid rng addr */
	uint32_t pci_phys_low;			/* Parent low rng addr */
	uint32_t rng_size;			/* Range size */
};

/*
 * use macros for soft state and driver properties:
 */
#define	get_acebus_soft_state(i)	\
	((ebus_devstate_t *)ddi_get_soft_state(per_acebus_state, (i)))

#define	alloc_acebus_soft_state(i)	\
	ddi_soft_state_zalloc(per_acebus_state, (i))

#define	free_acebus_soft_state(i)	\
	ddi_soft_state_free(per_acebus_state, (i))


#define	getprop(dip, name, addr, intp)		\
		ddi_getlongprop(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS, \
				(name), (caddr_t)(addr), (intp))

/*
 * register offsets and lengths:
 */
#define	TCR_OFFSET	0x710000
#define	TCR_LENGTH	12

#define	CSR_IO_RINDEX		2
#define	CSR_SIZE		0x00800000
#define	TCR1_OFF		0x00710000
#define	TCR2_OFF		0x00710004
#define	TCR3_OFF		0x00710008
#define	PMD_AUX_OFF		0x00728000
#define	FREQ_AUX_OFF		0x0072a000
#define	DCSR1_OFF		0x00700000
#define	DACR1_OFF		0x00700004
#define	DBCR1_OFF		0x00700008
#define	DCSR2_OFF		0x00702000
#define	DACR2_OFF		0x00702004
#define	DBCR2_OFF		0x00702008
#define	DCSR3_OFF		0x00704000
#define	DACR3_OFF		0x00704004
#define	DBCR3_OFF		0x00704008
#define	DCSR4_OFF		0x00706000
#define	DACR4_OFF		0x00706004
#define	DBCR4_OFF		0x00706008

/*
 * timing control register settings:
 */
#define	TCR1		0x08101008
#define	TCR2		0x08100020
#define	TCR3		0x00000020
#define	TCR1_REGVAL	0xe3080808
#define	TCR2_REGVAL	0x0808ff20
#define	TCR3_REGVAL	0x91f3c420



#if defined(DEBUG)
#define	D_IDENTIFY	0x00000001
#define	D_ATTACH	0x00000002
#define	D_DETACH	0x00000004
#define	D_MAP		0x00000008
#define	D_CTLOPS	0x00000010
#define	D_INTR		0x00000100

#define	DBG(flag, psp, fmt)	\
	acebus_debug(flag, psp, fmt, 0, 0, 0, 0, 0);
#define	DBG1(flag, psp, fmt, a1)	\
	acebus_debug(flag, psp, fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	DBG2(flag, psp, fmt, a1, a2)	\
	acebus_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	DBG3(flag, psp, fmt, a1, a2, a3)	\
	acebus_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
	    (uintptr_t)(a3), 0, 0);
#define	DBG4(flag, psp, fmt, a1, a2, a3, a4)	\
	acebus_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
	    (uintptr_t)(a3), \
		(uintptr_t)(a4), 0);
#define	DBG5(flag, psp, fmt, a1, a2, a3, a4, a5)	\
	acebus_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
	    (uintptr_t)(a3), \
		(uintptr_t)(a4), (uintptr_t)(a5));
static void
acebus_debug(uint_t, ebus_devstate_t *, char *, uintptr_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t);
#else
#define	DBG(flag, psp, fmt)
#define	DBG1(flag, psp, fmt, a1)
#define	DBG2(flag, psp, fmt, a1, a2)
#define	DBG3(flag, psp, fmt, a1, a2, a3)
#define	DBG4(flag, psp, fmt, a1, a2, a3, a4)
#define	DBG5(flag, psp, fmt, a1, a2, a3, a4, a5)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ACEBUS_H */
