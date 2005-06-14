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

#ifndef	_MDB_PARAM_H
#define	_MDB_PARAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * mdb_param.h
 *
 * Support header file for mdb_ks module for module developers wishing
 * to access macros in <sys/param.h> which expand to the current value
 * of kernel global variables.  Developers should include <mdb/mdb_param.h>
 * rather than <sys/param.h>.  This will arrange for the inclusion of
 * <sys/param.h>, plus redefinition of all the macros therein to expand
 * to the value of globals defined in mdb_ks.  The following cpp goop
 * is necessary to get <sys/param.h> to *not* define those macros.
 */

#ifdef	_SYS_PARAM_H
#error "You should not include <sys/param.h> prior to <mdb/mdb_param.h>"
#endif

#ifndef _MACHDEP
#define	_MACHDEP

#ifndef _SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

/*
 * Case 1: We defined both _MACHDEP and _SYS_MACHPARAM_H.  Undef both
 * after we include <sys/param.h>.
 */
#include <sys/param.h>
#undef _SYS_MACHPARAM_H
#undef _MACHDEP

#else	/* _SYS_MACHPARAM_H */

/*
 * Case 2: We defined _MACHDEP only.
 */
#include <sys/param.h>
#undef _MACHDEP

#endif	/* _SYS_MACHPARAM_H */
#else	/* _MACHDEP */

#ifndef _SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

/*
 * Case 3: We defined _SYS_MACHPARAM_H.
 */
#include <sys/param.h>
#undef _SYS_MACHPARAM_H

#else	/* _SYS_MACHPARAM_H */

/*
 * Case 4: _MACHDEP and _SYS_MACHPARAM_H are both already defined.
 */
#include <sys/param.h>

#endif	/* _SYS_MACHPARAM_H */
#endif	/* _MACHDEP */

/*
 * Extern declarations for global variables defined in the mdb_ks module.
 * All of these will be filled in during ks's _mdb_init routine.
 */
extern unsigned long _mdb_ks_pagesize;
extern unsigned int _mdb_ks_pageshift;
extern unsigned long _mdb_ks_pageoffset;
extern unsigned long long _mdb_ks_pagemask;
extern unsigned long _mdb_ks_mmu_pagesize;
extern unsigned int _mdb_ks_mmu_pageshift;
extern unsigned long _mdb_ks_mmu_pageoffset;
extern unsigned long _mdb_ks_mmu_pagemask;
extern uintptr_t _mdb_ks_kernelbase;
extern uintptr_t _mdb_ks_userlimit;
extern uintptr_t _mdb_ks_userlimit32;
extern uintptr_t _mdb_ks_argsbase;
extern unsigned long _mdb_ks_msg_bsize;
extern unsigned long _mdb_ks_defaultstksz;
extern int _mdb_ks_ncpu;

/*
 * Now derive all the macros using the global variables defined in
 * the support library.  These macros will in turn be referenced in
 * other kernel macros.
 */
#define	PAGESIZE	_mdb_ks_pagesize
#define	PAGESHIFT	_mdb_ks_pageshift
#define	PAGEOFFSET	_mdb_ks_pageoffset
#define	PAGEMASK	_mdb_ks_pagemask
#define	MMU_PAGESIZE	_mdb_ks_mmu_pagesize
#define	MMU_PAGESHIFT	_mdb_ks_mmu_pageshift
#define	MMU_PAGEOFFSET	_mdb_ks_mmu_pageoffset
#define	MMU_PAGEMASK	_mdb_ks_mmu_pagemask

#define	KERNELBASE	_mdb_ks_kernelbase
#define	USERLIMIT	_mdb_ks_userlimit
#define	USERLIMIT32	_mdb_ks_userlimit32
#define	ARGSBASE	_mdb_ks_argsbase
#define	MSG_BSIZE	_mdb_ks_msg_bsize
#define	DEFAULTSTKSZ	_mdb_ks_defaultstksz
#define	NCPU		_mdb_ks_ncpu

#define	_STRING_H	/* Do not re-include <string.h> */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_PARAM_H */
