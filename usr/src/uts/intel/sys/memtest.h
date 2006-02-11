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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MEMTEST_H
#define	_MEMTEST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interfaces for the memory error injection driver (memtest).  This driver is
 * intended for use only by mtst.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MEMTEST_DEVICE		"/devices/pseudo/memtest@0:memtest"

#define	MEMTEST_VERSION		1

#define	MEMTESTIOC		('M' << 8)
#define	MEMTESTIOC_INQUIRE	(MEMTESTIOC | 0)
#define	MEMTESTIOC_CONFIG	(MEMTESTIOC | 1)
#define	MEMTESTIOC_INJECT	(MEMTESTIOC | 2)
#define	MEMTESTIOC_MEMREQ	(MEMTESTIOC | 3)
#define	MEMTESTIOC_MEMREL	(MEMTESTIOC | 4)

#define	MEMTEST_F_DEBUG		0x1

typedef struct memtest_inq {
	uint_t minq_version;		/* [out] driver version */
} memtest_inq_t;

/*
 * Used by the userland injector to request a memory region from the driver.
 * This region (or a portion thereof) will be used for the error.  The caller
 * is expected to fill in the restrictions, if any, that are to be applied to
 * the region.  If the driver cannot allocate a region that meets the supplied
 * restrictions, the ioctl will fail.  Upon success, all members will be filled
 * in with values that reflect the allocated area.
 */

#define	MEMTEST_MEMREQ_MAXNUM	5	/* maximum number of open allocations */
#define	MEMTEST_MEMREQ_MAXSIZE	8192	/* maximum size of each allocation */

#define	MEMTEST_MEMREQ_UNSPEC	((uint64_t)-1)

typedef struct memtest_memreq {
	int mreq_cpuid;			/* cpu restriction (opt, -1 if unset) */
	uint32_t mreq_size;		/* size of allocation */
	uint64_t mreq_vaddr;		/* [out] VA of allocation */
	uint64_t mreq_paddr;		/* [out] PA of allocation */
} memtest_memreq_t;

/*
 * Arrays of statements are passed to the memtest driver for error injection.
 */
#define	MEMTEST_INJECT_MAXNUM	20	/* Max # of stmts per INJECT ioctl */

#define	MEMTEST_INJ_STMT_MSR	0x1	/* an MSR to be written */
#define	MEMTEST_INJ_STMT_PCICFG	0x2	/* address in PCI config space */
#define	MEMTEST_INJ_STMT_INT	0x3	/* a specific interrupt to be raised */
#define	MEMTEST_INJ_STMT_POLL	0x4	/* tell CPU module to poll for CEs */

/* Must be kept in sync with mtst_inj_statement in mtst_cpumod_api.h */
typedef struct memtest_inj_stmt {
	int mis_cpuid;			/* target CPU for statement */
	uint_t mis_type;		/* MEMTEST_INJ_STMT_* */
	union {
		struct {		/* MEMTEST_INJ_STMT_MSR */
			uint32_t _mis_msrnum;	/* MSR number */
			uint32_t _mis_pad;	/* reserved */
			uint64_t _mis_msrval;	/* value for MSR */
		} _mis_msr;
		struct {		/* MEMTEST_INJ_STMT_PCICFG */
			uint32_t _mis_pciaddr;	/* address in config space */
			uint32_t _mis_pcival;	/* value for PCI config reg */
		} _mis_pci;
		uint8_t _mis_int;	/* MEMTEST_INJ_STMT_INT; int num */
	} _mis_data;
} memtest_inj_stmt_t;

#define	mis_msrnum	_mis_data._mis_msr._mis_msrnum
#define	mis_msrval	_mis_data._mis_msr._mis_msrval
#define	mis_pciaddr	_mis_data._mis_pci._mis_pciaddr
#define	mis_pcival	_mis_data._mis_pci._mis_pcival
#define	mis_int		_mis_data._mis_int

typedef struct memtest_inject {
	int mi_nstmts;
	uint32_t mi_pad;
	memtest_inj_stmt_t mi_stmts[1];
} memtest_inject_t;

#ifdef __cplusplus
}
#endif

#endif /* _MEMTEST_H */
