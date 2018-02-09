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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_BOOTSYMS_H
#define	_SYS_BOOTSYMS_H

/*
 * This header file should not exist.
 *
 * Whether it be due to laziness, machismo, or just plain cluelessness, most
 * of the symbols over in psm/stand are not properly prototyped anywhere.
 *
 * To workaround this, developers have adopted the horrendous practice of
 * "externing" the symbols they need, leading to dozens of declarations of
 * the same symbol which have to be kept in sync.  Unfortunately, no similar
 * workaround exists for lint's pass2, which requires definitions for all
 * symbols in order to properly perform cross-checks.
 *
 * Thus, this header file was created to address two problems:
 *
 *	1. The "extern" problem.  All files beneath stand/lib should #include
 *	   this file rather than "extern" the symbol. Additionally, existing
 *	   externs should be removed as convenient.
 *
 *	   Of course, eventually some brave soul needs to venture over to the
 *	   slums of psm/stand and add all the proper header files, at which
 *	   point this file can be disposed of.
 *
 *	2. The lint pass2 problem.  Specifically, this file is used to build
 *	   llib-lfakeboot.ln, which is then used to properly lint the
 *	   binaries under stand/lib.  See stand/lib/llib-lfakeboot for more
 *	   details.
 *
 * Note that the set of symbols shared between stand/lib and psm/stand is
 * itself a moving target.  As such, this file should be updated as needed
 * so that it always contains the *minimum* set of shared symbols needed to
 * avoid externs and placate lint.
 */

#include <sys/saio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * From psm/stand/boot/$(MACH)/common/fsconf.c:
 */
extern int nfs_readsize;
extern int boot_nfsw;
extern struct boot_fs_ops *boot_fsw[];
extern struct boot_fs_ops *extendfs_ops;
extern struct boot_fs_ops *origfs_ops;

/*
 * From psm/stand/boot/common/boot.c:
 */
extern int boothowto;
extern int verbosemode;
extern char *systype;
extern struct memlist *pfreelistp;
extern struct memlist *vfreelistp;
extern void set_default_filename(char *);

/*
 * From psm/stand/boot/common/heap_kmem.c:
 */
extern void *bkmem_alloc(size_t);
extern void *bkmem_zalloc(size_t);
extern void bkmem_free(void *, size_t);

/*
 * From psm/stand/boot/$(MACH)/common/$(MACH)_standalloc.c:
 */
extern caddr_t resalloc(enum RESOURCES, size_t, caddr_t, int);
extern void resfree(enum RESOURCES, caddr_t, size_t);
extern void reset_alloc(void);

/*
 * From psm/stand/lib/names/$(MACH)/common/mfgname.c: (libnames)
 */
extern char *get_mfg_name(void);

/*
 * From psm/stand/boot/i386/common/boot_plat.c or
 *      psm/stand/boot/sparcv9/sun4u/machdep.c:
 */
extern int pagesize;
extern int global_pages;

#ifdef __sparc
/*
 * From psm/stand/boot/sparc/common/fsconf.c:
 */
extern char *bootp_response;
#endif /* __sparc */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BOOTSYMS_H */
