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

#ifndef	_SYS_SBBCVAR_H
#define	_SYS_SBBCVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct sbbc_intr_map {
	uint32_t sbbc_phys_hi;
	uint32_t sbbc_phys_mid;
	uint32_t sbbc_phys_low;
	uint32_t sbbc_intr;
	uint32_t intr_ctlr_nodeid;
	uint32_t ino;
}sbbc_intr_map_t;

struct sbbc_intr_map_mask {
	uint32_t sbbc_phys_hi;
	uint32_t sbbc_phys_mid;
	uint32_t sbbc_phys_low;
	uint32_t sbbc_intr;
};

/* sbbc intrspec for initializing its children. */
struct sbbc_intrspec {
	struct intrspec intr_spec;
	dev_info_t *dip;		/* Interrupt parent dip */
	uint32_t intr;			/* for lookup */
};

/*
 * definition of sbbc child reg spec entry:
 */
typedef struct {
	uint32_t addr_hi;
	uint32_t addr_low;
	uint32_t size;
} sbbc_child_regspec_t;

/* SBBC range entry */
typedef struct sbbc_pci_rangespec {
	uint32_t sbbc_phys_hi;		/* Child hi range address */
	uint32_t sbbc_phys_low;		/* Child low range address */
	uint32_t pci_phys_hi;		/* Parent hi rng addr */
	uint32_t pci_phys_mid;		/* Parent mid rng addr */
	uint32_t pci_phys_low;		/* Parent low rng addr */
	uint32_t rng_size;		/* Range size */
} sbbc_pci_rangespec_t;

typedef int procid_t;

/* Max. SBBC devices/children */
#define	MAX_SBBC_DEVICES	3

/* Only used for fixed or legacy interrupts */
#define	SBBC_INTR_STATE_DISABLE	0	/* disabled */
#define	SBBC_INTR_STATE_ENABLE	1	/* enabled */

typedef struct sbbc_child_intr {
	char *name;
	uint_t inum;
	uint_t status;
	uint_t (*intr_handler)();
	caddr_t arg1;
	caddr_t	arg2;
} sbbc_child_intr_t;

typedef struct sbbcsoft {
	int instance;
	int oflag;
	uint_t myinumber;
	dev_info_t *dip;			/* device information */
	pci_regspec_t *reg;
	int nreg;
	sbbc_pci_rangespec_t *rangep;
	int range_cnt;
	int range_len;
	struct sbbc_regs_map *pci_sbbc_map;	/* SBBC Internal Registers */
	ddi_acc_handle_t pci_sbbc_map_handle;
	ddi_iblock_cookie_t sbbc_iblock_cookie; /* interrupt block cookie */
	kmutex_t sbbc_intr_mutex;		/* lock for interrupts */
	sbbc_child_intr_t *child_intr[MAX_SBBC_DEVICES]; /* intr per device */
	boolean_t suspended;			/* TRUE if driver suspended */
	kmutex_t umutex;			/* lock for this structure */
} sbbcsoft_t;

#define	TRUE		1
#define	FALSE		0


#if defined(DEBUG)

#define	SBBC_DBG_ATTACH		0x1
#define	SBBC_DBG_DETACH		0x2
#define	SBBC_DBG_CTLOPS		0x4
#define	SBBC_DBG_INITCHILD	0x8
#define	SBBC_DBG_UNINITCHILD	0x10
#define	SBBC_DBG_BUSMAP		0x20
#define	SBBC_DBG_INTR		0x40
#define	SBBC_DBG_PCICONF	0x80
#define	SBBC_DBG_MAPRANGES	0x100
#define	SBBC_DBG_PROPERTIES	0x200
#define	SBBC_DBG_OPEN		0x400
#define	SBBC_DBG_CLOSE		0x800
#define	SBBC_DBG_IOCTL		0x1000
#define	SBBC_DBG_INTROPS	0x2000


#define	SBBC_DBG0(flag, dip, fmt) \
	sbbc_dbg(flag, dip, fmt, 0, 0, 0, 0, 0);
#define	SBBC_DBG1(flag, dip, fmt, a1) \
	sbbc_dbg(flag, dip, fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	SBBC_DBG2(flag, dip, fmt, a1, a2) \
	sbbc_dbg(flag, dip, fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	SBBC_DBG3(flag, dip, fmt, a1, a2, a3) \
	sbbc_dbg(flag, dip, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), 0, 0);
#define	SBBC_DBG4(flag, dip, fmt, a1, a2, a3, a4) \
	sbbc_dbg(flag, dip, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), (uintptr_t)(a4), 0);
#define	SBBC_DBG5(flag, dip, fmt, a1, a2, a3, a4, a5) \
	sbbc_dbg(flag, dip, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), (uintptr_t)(a4), (uintptr_t)(a5));

#else /* DEBUG */

#define	SBBC_DBG0(flag, dip, fmt)
#define	SBBC_DBG1(flag, dip, fmt, a1)
#define	SBBC_DBG2(flag, dip, fmt, a1, a2)
#define	SBBC_DBG3(flag, dip, fmt, a1, a2, a3)
#define	SBBC_DBG4(flag, dip, fmt, a1, a2, a3, a4)
#define	SBBC_DBG5(flag, dip, fmt, a1, a2, a3, a4, a5)

#endif /* DEBUG */

/* debugging flags */
/*
 * To enable tracing, uncomment this line:
 * #define	SBBC_TRACE	1
 */

#if defined(SBBC_TRACE)

#ifndef NSBBCTRACE
#define	NSBBCTRACE	1024
#endif

struct sbbctrace {
	int count;
	int function;		/* address of function */
	int trace_action;	/* descriptive 4 characters */
	int object;		/* object operated on */
};

/*
 * For debugging, allocate space for the trace buffer
 */

extern struct sbbctrace sbbctrace_buffer[];
extern struct sbbctrace *sbbctrace_ptr;
extern int sbbctrace_count;

#define	SBBCTRACEINIT() {				\
	if (sbbctrace_ptr == NULL)		\
		sbbctrace_ptr = sbbctrace_buffer; \
	}

#define	LOCK_TRACE()	(uint_t)ddi_enter_critical()
#define	UNLOCK_TRACE(x)	ddi_exit_critical((uint_t)x)

#define	SBBCTRACE(func, act, obj) {		\
	int __s = LOCK_TRACE();			\
	int *_p = &sbbctrace_ptr->count;	\
	*_p++ = ++sbbctrace_count;		\
	*_p++ = (int)(func);			\
	*_p++ = (int)(act);			\
	*_p++ = (int)(obj);			\
	if ((struct sbbctrace *)(void *)_p >= &sbbctrace_buffer[NSBBCTRACE])\
		sbbctrace_ptr = sbbctrace_buffer; \
	else					\
		sbbctrace_ptr = (struct sbbctrace *)(void *)_p; \
	UNLOCK_TRACE(__s);			\
	}

#else	/* !SBBC_TRACE */

/* If no tracing, define no-ops */
#define	SBBCTRACEINIT()
#define	SBBCTRACE(a, b, c)

#endif	/* !SBBC_TRACE */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBBCVAR_H */
