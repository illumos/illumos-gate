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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Kernel Run-Time Linker/Loader private interfaces.
 */

#ifndef	_SYS_KOBJ_IMPL_H
#define	_SYS_KOBJ_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/kdi.h>
#include <sys/kobj.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Boot/aux vector attributes.
 */

#define	BA_DYNAMIC	0
#define	BA_PHDR		1
#define	BA_PHNUM	2
#define	BA_PHENT	3
#define	BA_ENTRY	4
#define	BA_PAGESZ	5
#define	BA_LPAGESZ	6
#define	BA_LDELF	7
#define	BA_LDSHDR	8
#define	BA_LDNAME	9
#define	BA_BSS		10
#define	BA_IFLUSH	11
#define	BA_CPU		12
#define	BA_MMU		13
#define	BA_GOTADDR	14
#define	BA_NEXTGOT	15
#define	BA_NUM		16

typedef union {
	unsigned long ba_val;
	void *ba_ptr;
} val_t;

/*
 * Segment info.
 */
struct proginfo {
	uint_t size;
	uint_t align;
};

/*
 * Implementation-specific flags.
 */
#define	KOBJ_EXEC	0x0004	/* executable (unix module) */
#define	KOBJ_INTERP	0x0008	/* the interpreter module */
#define	KOBJ_PRIM	0x0010	/* a primary kernel module */
#define	KOBJ_RESOLVED	0x0020	/* fully resolved */
#define	KOBJ_TNF_PROBE	0x0040	/* Contains TNF probe(s) */
#define	KOBJ_RELOCATED	0x0080	/* relocation completed */
#define	KOBJ_NOPARENTS	0x0200	/* nothing can depend on this module */
#define	KOBJ_IGNMULDEF	0x0400	/* ignore dups during sym resolution */
#define	KOBJ_NOKSYMS	0x0800	/* module's symbols don't go into ksyms */
#define	KOBJ_EXPORTED	0x1000	/* ctf, syms copied to vmem */

/*
 * kobj_notify_add() data notification structure
 */
typedef void kobj_notify_f(uint_t, struct modctl *);

typedef struct kobj_notify_list {
	kobj_notify_f		*kn_func;	/* notification func */
	uint_t			kn_type;	/* notification type */
	struct kobj_notify_list	*kn_prev;
	struct kobj_notify_list	*kn_next;
} kobj_notify_list_t;

/*
 * krtld can provide notification to external clients on the
 * following events.
 */
#define	KOBJ_NOTIFY_MODLOADING		1	/* very early in module load */
#define	KOBJ_NOTIFY_MODUNLOADING	2	/* before module unload */
#define	KOBJ_NOTIFY_MODLOADED		3	/* after module load */
#define	KOBJ_NOTIFY_MODUNLOADED		4	/* after module unload */
#define	KOBJ_NOTIFY_MAX			4

#define	ALIGN(x, a)	((a) == 0 ? (uintptr_t)(x) : \
	(((uintptr_t)(x) + (uintptr_t)(a) - 1l) & ~((uintptr_t)(a) - 1l)))

#ifdef	DEBUG
#define	KOBJ_DEBUG
#endif

#ifdef KOBJ_DEBUG
/*
 * Debugging flags.
 */
#define	D_DEBUG			0x001	/* general debugging */
#define	D_SYMBOLS		0x002	/* debug symbols */
#define	D_RELOCATIONS		0x004	/* debug relocations */
#define	D_LOADING		0x008	/* section loading */

extern int kobj_debug;		/* different than moddebug */
#endif

/*
 * Flags for kobj memory allocation.
 */
#define	KM_WAIT			0x0	/* wait for it */
#define	KM_NOWAIT		0x1	/* return immediately */

#define	KM_TMP			0x1000	/* freed before kobj_init returns */
#define	KM_SCRATCH		0x2000	/* not freed until kobj_sync */

#ifdef	KOBJ_OVERRIDES
/*
 * Until the kernel is fully linked, all code running in the
 * context of krtld/kobj using bcopy or bzero must be directed
 * to the kobj equivalents.  All (ok, most) references to bcopy
 * or bzero are thus so vectored.
 */
#define	bcopy(s, d, n)		kobj_bcopy((s), (d), (n))
#define	bzero(p, n)		kobj_bzero((p), (n))
#define	strlcat(s, d, n)	kobj_strlcat((s), (d), (n))
#endif

extern kdi_t kobj_kdi;

struct bootops;

extern struct modctl_list *kobj_linkmaps[];

extern char *kobj_kmdb_argv[];

extern int kobj_mmu_pagesize;

extern void kobj_init(void *romvec, void *dvec,
	struct bootops *bootvec, val_t *bootaux);
extern int kobj_notify_add(kobj_notify_list_t *);
extern int kobj_notify_remove(kobj_notify_list_t *);
extern int do_relocations(struct module *);
extern int do_relocate(struct module *, char *, Word, int, int, Addr);
extern struct bootops *ops;
extern void exitto(caddr_t);
extern void kobj_sync_instruction_memory(caddr_t, size_t);
extern uint_t kobj_gethashsize(uint_t);
extern void * kobj_mod_alloc(struct module *, size_t, int, reloc_dest_t *);
extern void mach_alloc_funcdesc(struct module *);
extern uint_t kobj_hash_name(const char *);
extern caddr_t kobj_segbrk(caddr_t *, size_t, size_t, caddr_t);
extern int get_progbits_size(struct module *, struct proginfo *,
	struct proginfo *, struct proginfo *);
extern Sym *kobj_lookup_kernel(const char *);
extern struct modctl *kobj_boot_mod_lookup(const char *);
extern void kobj_export_module(struct module *);
extern int kobj_load_primary_module(struct modctl *);
extern int boot_compinfo(int, struct compinfo *);
extern void mach_modpath(char *, const char *);

extern void kobj_setup_standalone_vectors(void);
extern void kobj_restore_vectors(void);
extern void (*_kobj_printf)(void *, const char *fmt, ...);
extern void (*kobj_bcopy)(const void *, void *, size_t);
extern void (*kobj_bzero)(void *, size_t);
extern size_t (*kobj_strlcat)(char *, const char *, size_t);

#define	KOBJ_LM_PRIMARY		0x0
#define	KOBJ_LM_DEBUGGER	0x1

extern void kobj_lm_append(int, struct modctl *modp);
extern struct modctl_list *kobj_lm_lookup(int);
extern void kobj_lm_dump(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KOBJ_IMPL_H */
