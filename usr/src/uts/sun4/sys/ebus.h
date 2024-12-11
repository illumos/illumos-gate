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

#ifndef _SYS_EBUS_H
#define	_SYS_EBUS_H

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
 * definition of ebus reg spec entry:
 */
typedef struct {
	uint32_t addr_hi;
	uint32_t addr_low;
	uint32_t size;
} ebus_regspec_t;

/* Range entry for 3-cell parent address */
struct ebus_pci_rangespec {
	uint32_t phys_hi;			/* Child hi range address */
	uint32_t phys_low;			/* Child low range address */
	uint32_t par_phys_hi;			/* Parent hi rng addr */
	uint32_t par_phys_mid;			/* Parent mid rng addr */
	uint32_t par_phys_low;			/* Parent low rng addr */
	uint32_t rng_size;			/* Range size */
};

/* Range entry for 2-cell parent address */
struct ebus_jbus_rangespec {
	uint32_t phys_hi;			/* Child hi range address */
	uint32_t phys_low;			/* Child low range address */
	uint32_t par_phys_hi;			/* Parent hi rng addr */
	uint32_t par_phys_low;			/* Parent low rng addr */
	uint32_t rng_size;			/* Range size */
};

typedef union vrangespec {
	struct ebus_pci_rangespec	pci_rangespec;
	struct ebus_jbus_rangespec	jbus_rangespec;
} vrangespec_t;

typedef union vregspec {
	struct pci_phys_spec	pci_regspec;
	struct regspec		jbus_regspec;
} vregspec_t;

/*
 * driver soft state structure:
 */
typedef struct {
	dev_info_t *dip;
	driver_state_t state;
	pci_regspec_t *reg;
	int nreg;

	vrangespec_t *vrangep;
	int vrange_len;
	int vrange_cnt;

	kmutex_t ebus_mutex;
	uint_t ebus_soft_state;
#define	EBUS_SOFT_STATE_CLOSED		0x00
#define	EBUS_SOFT_STATE_OPEN		0x01
#define	EBUS_SOFT_STATE_OPEN_EXCL	0x02

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
	int ebus_addr_cells;
	int ebus_paddr_cells;
	int ebus_psz_cells;
	int ebus_sz_cells;
} ebus_devstate_t;


/*
 * use macros for soft state and driver properties:
 */
#define	get_ebus_soft_state(i)	\
	((ebus_devstate_t *)ddi_get_soft_state(per_ebus_state, (i)))

#define	alloc_ebus_soft_state(i)	\
	ddi_soft_state_zalloc(per_ebus_state, (i))

#define	free_ebus_soft_state(i)	\
	ddi_soft_state_free(per_ebus_state, (i))


#define	getprop(dip, name, addr, intp)		\
		ddi_getlongprop(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS, \
				(name), (caddr_t)(addr), (intp))

#define	IS_RIO(dip) \
		((ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, \
		"device-id", -1) == 0x1100) && \
		(ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, \
		"vendor-id", -1) == 0x108e))

#define	EBUS_4MHZ	4000

/*
 * register offsets and lengths:
 */
#define	TCR_OFFSET	0x710000
#define	TCR_LENGTH	12

/*
 * timing control register settings:
 */
#define	TCR1		0x08101008
#define	TCR2		0x08100020
#define	TCR3		0x00000020

#if defined(DEBUG)
#define	D_IDENTIFY	0x00000001
#define	D_ATTACH	0x00000002
#define	D_DETACH	0x00000004
#define	D_MAP		0x00000008
#define	D_CTLOPS	0x00000010
#define	D_INTR		0x00000100

#define	DBG(flag, psp, fmt)	\
	ebus_debug(flag, psp, fmt, 0, 0, 0, 0, 0);
#define	DBG1(flag, psp, fmt, a1)	\
	ebus_debug(flag, psp, fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	DBG2(flag, psp, fmt, a1, a2)	\
	ebus_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	DBG3(flag, psp, fmt, a1, a2, a3)	\
	ebus_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
	    (uintptr_t)(a3), 0, 0);
#define	DBG4(flag, psp, fmt, a1, a2, a3, a4)	\
	ebus_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
	    (uintptr_t)(a3), \
		(uintptr_t)(a4), 0);
#define	DBG5(flag, psp, fmt, a1, a2, a3, a4, a5)	\
	ebus_debug(flag, psp, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
	    (uintptr_t)(a3), \
		(uintptr_t)(a4), (uintptr_t)(a5));
static void
ebus_debug(uint_t, ebus_devstate_t *, char *, uintptr_t, uintptr_t, uintptr_t,
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

#endif	/* _SYS_EBUS_H */
