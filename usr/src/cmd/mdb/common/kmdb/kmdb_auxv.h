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

#ifndef _KMDB_AUXV_H
#define	_KMDB_AUXV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The kmdb_auxv is the interface between the driver and the debugger portions
 * of kmdb.  It is used for three purposes:
 *
 *  1) To pass system-specific configuration information to the debugger.  This
 *     information is used by the debugger to tailor itself to the running
 *     system.
 *
 *  2) To pass debugger state information to the driver.
 *
 *  3) To configure the DPI.
 *
 * We use this somewhat torturous method to initialize and configure kmdb due to
 * the somewhat unique requirements of kmdb as a pseudo-standalone debugger.
 * The debugger portion of kmdb is compiled as a standalone, without any
 * external dependencies.  As a result, it cannot communicate directly to the
 * outside world.  Any such communications must be through functions passed to
 * it by the driver.  The auxv provides a means by which these pointers and
 * other parameters may be passed to the debugger.
 */

#include <gelf.h>
#include <sys/machelf.h>
#include <sys/kdi.h>
#ifdef sun4v
#include <sys/obpdefs.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kmdb_auxv_nv {
	char kanv_name[25];
	char kanv_val[50];
} kmdb_auxv_nv_t;

#define	KMDB_AUXV_FL_NOUNLOAD	0x1	/* don't allow debugger unload */
#define	KMDB_AUXV_FL_NOTRPSWTCH	0x2	/* don't switch to kmdb's TBA/IDT */

typedef struct kmdb_auxv {
	caddr_t		kav_dseg;		/* Base of segdebug */
	size_t		kav_dseg_size;		/* Size of segdebug */
	size_t		kav_pagesize;		/* Base page size */
	int		kav_ncpu;		/* Maximum number of CPUs */
	kdi_t		*kav_kdi;		/* Ops vector for KDI */
	void		*kav_romp;		/* Opaque PROM handle */

#ifdef __sparc
	int		*kav_promexitarmp;	/* PROM exit kmdb entry armer */

	caddr_t		kav_tba_active;		/* Trap table to be used */
	caddr_t		kav_tba_obp;		/* OBP's trap table */
#ifdef	sun4v
	caddr_t		kav_tba_kernel;		/* Kernel's trap table */
#endif
	caddr_t		kav_tba_native;		/* kmdb's trap table */
	size_t		kav_tba_native_sz;	/* kmdb's trap table size */
#endif

#if defined(__i386) || defined(__amd64)
	kmdb_auxv_nv_t	*kav_pcache;		/* Copies of common props */
	int		kav_nprops;		/* Size of prop cache */
#endif

	uintptr_t (*kav_lookup_by_name)(char *, char *); /* Live kernel only */

	void (*kav_wrintr_fire)(void);		/* Send softint to driver */

	const char	*kav_config;		/* State string from MDB */
	const char	**kav_argv;		/* Args from boot line */
	uint_t		kav_flags;		/* KMDB_AUXV_FL_* */

	const char	*kav_modpath;		/* kernel module_path */

#ifdef __sparc
	void (*kav_ktrap_install)(int, void (*)(void)); /* Add to krnl trptbl */
	void (*kav_ktrap_restore)(void);	/* Restore krnl trap hdlrs */
#ifdef sun4v
	uint_t		kav_domaining;		/* Domaining status */
	caddr_t		kav_promif_root;	/* PROM shadow tree root */
	ihandle_t	kav_promif_in;		/* PROM input dev instance */
	ihandle_t	kav_promif_out;		/* PROM output dev instance */
	phandle_t	kav_promif_pin;		/* PROM input dev package */
	phandle_t	kav_promif_pout;	/* PROM output dev package */
	pnode_t		kav_promif_chosennode;	/* PROM "/chosen" node */
	pnode_t		kav_promif_optionsnode;	/* PROM "/options" node */
#endif
#endif

} kmdb_auxv_t;

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_AUXV_H */
