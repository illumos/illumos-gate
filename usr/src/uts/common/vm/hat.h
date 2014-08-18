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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_VM_HAT_H
#define	_VM_HAT_H

#include <sys/types.h>
#include <sys/t_lock.h>
#include <vm/faultcode.h>
#include <sys/kstat.h>
#include <sys/siginfo.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * VM - Hardware Address Translation management.
 *
 * This file describes the machine independent interfaces to
 * the hardware address translation management routines.  Other
 * machine specific interfaces and structures are defined
 * in <vm/hat_xxx.h>.  The hat layer manages the address
 * translation hardware as a cache driven by calls from the
 * higher levels of the VM system.
 */

struct hat;
struct kpme;
struct memseg;

#include <vm/page.h>

/*
 * a callback used with hat_unload_callback()
 * start and end mark are set to a range of unloaded addresses
 * and the function is invoked with a pointer to this data structure
 */
typedef struct hat_callback {
	caddr_t	hcb_start_addr;
	caddr_t hcb_end_addr;
	void	(*hcb_function)(struct hat_callback *);
	void	*hcb_data;
} hat_callback_t;

typedef void *hat_region_cookie_t;

#ifdef	_KERNEL

/*
 * One time hat initialization
 */
void	hat_init(void);

/*
 * Notify hat of a system dump
 */
void	hat_dump(void);

/*
 * Operations on an address space:
 *
 * struct hat *hat_alloc(as)
 *	allocated a hat structure for as.
 *
 * void hat_free_start(hat)
 *	informs hat layer process has finished executing but as has not
 *	been cleaned up yet.
 *
 * void hat_free_end(hat)
 *	informs hat layer as is being destroyed.  hat layer cannot use as
 *	pointer after this call.
 *
 * void hat_swapin(hat)
 *	allocate any hat resources required for process being swapped in.
 *
 * void hat_swapout(hat)
 *	deallocate hat resources for process being swapped out.
 *
 * size_t hat_get_mapped_size(hat)
 *	returns number of bytes that have valid mappings in hat.
 *
 * void hat_stats_enable(hat)
 * void hat_stats_disable(hat)
 *	enables/disables collection of stats for hat.
 *
 * int hat_dup(parenthat, childhat, addr, len, flags)
 *	Duplicate address translations of the parent to the child.  Supports
 *	the entire address range or a range depending on flag,
 *	zero returned on success, non-zero on error
 *
 * void hat_thread_exit(thread)
 *	Notifies the HAT that a thread is exiting, called after it has been
 *	reassigned to the kernel AS.
 */

struct hat *hat_alloc(struct as *);
void	hat_free_start(struct hat *);
void	hat_free_end(struct hat *);
int	hat_dup(struct hat *, struct hat *, caddr_t, size_t, uint_t);
void	hat_swapin(struct hat *);
void	hat_swapout(struct hat *);
size_t	hat_get_mapped_size(struct hat *);
int	hat_stats_enable(struct hat *);
void	hat_stats_disable(struct hat *);
void	hat_thread_exit(kthread_t *);

/*
 * Operations on a named address within a segment:
 *
 * void hat_memload(hat, addr, pp, attr, flags)
 *	load/lock the given page struct
 *
 * void hat_memload_array(hat, addr, len, ppa, attr, flags)
 *	load/lock the given array of page structs
 *
 * void hat_devload(hat, addr, len, pf, attr, flags)
 *	load/lock the given page frame number
 *
 * void hat_unlock(hat, addr, len)
 *	unlock a given range of addresses
 *
 * void hat_unload(hat, addr, len, flags)
 * void hat_unload_callback(hat, addr, len, flags, callback)
 *	unload a given range of addresses (has optional callback)
 *
 * void hat_sync(hat, addr, len, flags)
 *	synchronize mapping with software data structures
 *
 * void	hat_map(hat, addr, len, flags)
 *
 * void hat_setattr(hat, addr, len, attr)
 * void hat_clrattr(hat, addr, len, attr)
 * void hat_chgattr(hat, addr, len, attr)
 *	modify attributes for a range of addresses. skips any invalid mappings
 *
 * uint_t hat_getattr(hat, addr, *attr)
 *	returns attr for <hat,addr> in *attr.  returns 0 if there was a
 *	mapping and *attr is valid, nonzero if there was no mapping and
 *	*attr is not valid.
 *
 * size_t hat_getpagesize(hat, addr)
 *	returns pagesize in bytes for <hat, addr>. returns -1 if there is
 *	no mapping. This is an advisory call.
 *
 * pfn_t hat_getpfnum(hat, addr)
 *	returns pfn for <hat, addr> or PFN_INVALID if mapping is invalid.
 *
 * int hat_probe(hat, addr)
 *	return 0 if no valid mapping is present.  Faster version
 *	of hat_getattr in certain architectures.
 *
 * int hat_share(dhat, daddr, shat, saddr, len, szc)
 *
 * void hat_unshare(hat, addr, len, szc)
 *
 * void hat_chgprot(hat, addr, len, vprot)
 *	This is a deprecated call.  New segment drivers should store
 *	all attributes and use hat_*attr calls.
 *	Change the protections in the virtual address range
 *	given to the specified virtual protection.  If vprot is ~PROT_WRITE,
 *	then remove write permission, leaving the other permissions
 *	unchanged.  If vprot is ~PROT_USER, remove user permissions.
 *
 * void hat_flush_range(hat, addr, size)
 *	Invalidate a virtual address translation for the local CPU.
 */

void	hat_memload(struct hat *, caddr_t, struct page *, uint_t, uint_t);
void	hat_memload_array(struct hat *, caddr_t, size_t, struct page **,
		uint_t, uint_t);
void	hat_memload_region(struct hat *, caddr_t, struct page *, uint_t,
		uint_t, hat_region_cookie_t);
void	hat_memload_array_region(struct hat *, caddr_t, size_t, struct page **,
		uint_t, uint_t, hat_region_cookie_t);

void	hat_devload(struct hat *, caddr_t, size_t, pfn_t, uint_t, int);

void	hat_unlock(struct hat *, caddr_t, size_t);
void	hat_unlock_region(struct hat *, caddr_t, size_t, hat_region_cookie_t);

void	hat_unload(struct hat *, caddr_t, size_t, uint_t);
void	hat_unload_callback(struct hat *, caddr_t, size_t, uint_t,
		hat_callback_t *);
void	hat_flush_range(struct hat *, caddr_t, size_t);
void	hat_sync(struct hat *, caddr_t, size_t, uint_t);
void	hat_map(struct hat *, caddr_t, size_t, uint_t);
void	hat_setattr(struct hat *, caddr_t, size_t, uint_t);
void	hat_clrattr(struct hat *, caddr_t, size_t, uint_t);
void	hat_chgattr(struct hat *, caddr_t, size_t, uint_t);
uint_t	hat_getattr(struct hat *, caddr_t, uint_t *);
ssize_t	hat_getpagesize(struct hat *, caddr_t);
pfn_t	hat_getpfnum(struct hat *, caddr_t);
int	hat_probe(struct hat *, caddr_t);
int	hat_share(struct hat *, caddr_t, struct hat *, caddr_t, size_t, uint_t);
void	hat_unshare(struct hat *, caddr_t, size_t, uint_t);
void	hat_chgprot(struct hat *, caddr_t, size_t, uint_t);
void	hat_reserve(struct as *, caddr_t, size_t);
pfn_t	va_to_pfn(void *);
uint64_t va_to_pa(void *);

/*
 * Kernel Physical Mapping (segkpm) hat interface routines.
 */
caddr_t	hat_kpm_mapin(struct page *, struct kpme *);
void	hat_kpm_mapout(struct page *, struct kpme *, caddr_t);
caddr_t hat_kpm_mapin_pfn(pfn_t);
void    hat_kpm_mapout_pfn(pfn_t);
caddr_t	hat_kpm_page2va(struct page *, int);
struct page *hat_kpm_vaddr2page(caddr_t);
int	hat_kpm_fault(struct hat *, caddr_t);
void	hat_kpm_mseghash_clear(int);
void	hat_kpm_mseghash_update(pgcnt_t, struct memseg *);
void	hat_kpm_addmem_mseg_update(struct memseg *, pgcnt_t, offset_t);
void	hat_kpm_addmem_mseg_insert(struct memseg *);
void	hat_kpm_addmem_memsegs_update(struct memseg *);
caddr_t hat_kpm_mseg_reuse(struct memseg *);
void	hat_kpm_delmem_mseg_update(struct memseg *, struct memseg **);
void	hat_kpm_split_mseg_update(struct memseg *, struct memseg **,
			struct memseg *, struct memseg *, struct memseg *);
void	hat_kpm_walk(void (*)(void *, void *, size_t), void *);

/*
 * Operations on all translations for a given page(s)
 *
 * void hat_page_setattr(pp, flag)
 * void hat_page_clrattr(pp, flag)
 *	used to set/clr red/mod bits.
 *
 * uint hat_page_getattr(pp, flag)
 *	If flag is specified, returns 0 if attribute is disabled
 *	and non zero if enabled.  If flag specifes multiple attributs
 *	then returns 0 if ALL atriibutes are disabled.  This is an advisory
 *	call.
 *
 * int hat_pageunload(pp, forceflag)
 *	Unload all translations attached to pp. On x86 the bulk of the work is
 *	done by hat_page_inval.
 *
 * void	hat_page_inval(pp, pgsz, curhat)
 *	Unload translations attached to pp. If curhat is provided, only the
 *	translation for that process is unloaded, otherwise all are unloaded.
 *
 * uint_t hat_pagesync(pp, flags)
 *	get hw stats from hardware into page struct and reset hw stats
 *	returns attributes of page
 *
 * ulong_t hat_page_getshare(pp)
 *	returns approx number of mappings to this pp.  A return of 0 implies
 *	there are no mappings to the page.
 *
 * faultcode_t hat_softlock(hat, addr, lenp, ppp, flags);
 *	called to softlock pages for zero copy tcp
 *
 * void hat_page_demote(pp);
 *	unload all large mappings to pp and decrease p_szc of all
 *	constituent pages according to the remaining mappings.
 */

void	hat_page_setattr(struct page *, uint_t);
void	hat_page_clrattr(struct page *, uint_t);
uint_t	hat_page_getattr(struct page *, uint_t);
int	hat_pageunload(struct page *, uint_t);
void	hat_page_inval(struct page *, uint_t, struct hat *);
uint_t	hat_pagesync(struct page *, uint_t);
ulong_t	hat_page_getshare(struct page *);
int	hat_page_checkshare(struct page *, ulong_t);
faultcode_t hat_softlock(struct hat *, caddr_t, size_t *,
			struct page **, uint_t);
void	hat_page_demote(struct page *);

/*
 * Rountine to expose supported HAT features to PIM.
 */
enum hat_features {
	HAT_SHARED_PT,		/* Shared page tables */
	HAT_DYNAMIC_ISM_UNMAP,	/* hat_pageunload() handles ISM pages */
	HAT_VMODSORT,		/* support for VMODSORT flag of vnode */
	HAT_SHARED_REGIONS	/* shared regions support */
};

int hat_supported(enum hat_features, void *);

/*
 * Services provided to the hat:
 *
 * void as_signal_proc(as, siginfo)
 *	deliver signal to all processes that have this as.
 *
 * int hat_setstat(as, addr, len, rmbits)
 *	informs hatstat layer that ref/mod bits need to be updated for
 *	address range. Returns 0 on success, 1 for failure.
 */
void	as_signal_proc(struct as *, k_siginfo_t *siginfo);
void	hat_setstat(struct as *, caddr_t, size_t, uint_t);

/*
 * Flags to pass to hat routines.
 *
 * Certain flags only apply to some interfaces:
 *
 * 	HAT_LOAD	Default flags to load a translation to the page.
 * 	HAT_LOAD_LOCK	Lock down mapping resources; hat_map(), hat_memload(),
 *			and hat_devload().
 *	HAT_LOAD_ADV	Advisory load - Load translation if and only if
 *			sufficient MMU resources exist (i.e., do not steal).
 *	HAT_LOAD_SHARE	A flag to hat_memload() to indicate h/w page tables
 *			that map some user pages (not kas) is shared by more
 *			than one process (eg. ISM).
 *	HAT_LOAD_CONTIG	Pages are contigous
 *	HAT_LOAD_NOCONSIST Do not add mapping to mapping list.
 *	HAT_LOAD_REMAP	Reload a valid pte with a different page frame.
 *	HAT_RELOAD_SHARE Reload a shared page table entry. Some platforms
 *			 may require different actions than on the first
 *			 load of a shared mapping.
 *	HAT_NO_KALLOC	Do not kmem_alloc while creating the mapping; at this
 *			point, it's setting up mapping to allocate internal
 *			hat layer data structures.  This flag forces hat layer
 *			to tap its reserves in order to prevent infinite
 *			recursion.
 *	HAT_LOAD_TEXT	A flag to hat_memload() to indicate loading text pages.
 */

/*
 * Flags for hat_memload/hat_devload
 */
#define	HAT_FLAGS_RESV		0xFF000000	/* resv for hat impl */
#define	HAT_LOAD		0x00
#define	HAT_LOAD_LOCK		0x01
#define	HAT_LOAD_ADV		0x04
#define	HAT_LOAD_CONTIG		0x10
#define	HAT_LOAD_NOCONSIST	0x20
#define	HAT_LOAD_SHARE		0x40
#define	HAT_LOAD_REMAP		0x80
#define	HAT_RELOAD_SHARE	0x100
#define	HAT_NO_KALLOC		0x200
#define	HAT_LOAD_TEXT		0x400

/*
 * Flags for initializing disable_*large_pages.
 *
 *	HAT_AUTO_TEXT	Get MMU specific disable_auto_text_large_pages
 *	HAT_AUTO_DATA	Get MMU specific disable_auto_data_large_pages
 */
#define	HAT_AUTO_TEXT		0x800
#define	HAT_AUTO_DATA		0x1000

/*
 * Attributes for hat_memload/hat_devload/hat_*attr
 * are a superset of prot flags defined in mman.h.
 */
#define	HAT_PLAT_ATTR_MASK	0xF00000
#define	HAT_PROT_MASK		0x0F

#define	HAT_NOFAULT		0x10
#define	HAT_NOSYNC		0x20

/*
 * Advisory ordering attributes. Apply only to device mappings.
 *
 * HAT_STRICTORDER: the CPU must issue the references in order, as the
 *	programmer specified.  This is the default.
 * HAT_UNORDERED_OK: the CPU may reorder the references (this is all kinds
 *	of reordering; store or load with store or load).
 * HAT_MERGING_OK: merging and batching: the CPU may merge individual stores
 *	to consecutive locations (for example, turn two consecutive byte
 *	stores into one halfword store), and it may batch individual loads
 *	(for example, turn two consecutive byte loads into one halfword load).
 *	This also implies re-ordering.
 * HAT_LOADCACHING_OK: the CPU may cache the data it fetches and reuse it
 *	until another store occurs.  The default is to fetch new data
 *	on every load.  This also implies merging.
 * HAT_STORECACHING_OK: the CPU may keep the data in the cache and push it to
 *	the device (perhaps with other data) at a later time.  The default is
 *	to push the data right away.  This also implies load caching.
 */
#define	HAT_STRICTORDER		0x0000
#define	HAT_UNORDERED_OK	0x0100
#define	HAT_MERGING_OK		0x0200
#define	HAT_LOADCACHING_OK	0x0300
#define	HAT_STORECACHING_OK	0x0400
#define	HAT_ORDER_MASK		0x0700

/* endian attributes */
#define	HAT_NEVERSWAP		0x0000
#define	HAT_STRUCTURE_BE	0x1000
#define	HAT_STRUCTURE_LE	0x2000
#define	HAT_ENDIAN_MASK		0x3000

/* flags for hat_softlock */
#define	HAT_COW			0x0001

/*
 * Flags for hat_unload
 */
#define	HAT_UNLOAD		0x00
#define	HAT_UNLOAD_NOSYNC	0x02
#define	HAT_UNLOAD_UNLOCK	0x04
#define	HAT_UNLOAD_OTHER	0x08
#define	HAT_UNLOAD_UNMAP	0x10

/*
 * Flags for hat_pagesync, hat_getstat, hat_sync
 */
#define	HAT_SYNC_DONTZERO	0x00
#define	HAT_SYNC_ZERORM		0x01
/* Additional flags for hat_pagesync */
#define	HAT_SYNC_STOPON_REF	0x02
#define	HAT_SYNC_STOPON_MOD	0x04
#define	HAT_SYNC_STOPON_RM	(HAT_SYNC_STOPON_REF | HAT_SYNC_STOPON_MOD)
#define	HAT_SYNC_STOPON_SHARED	0x08

/*
 * Flags for hat_dup
 *
 * HAT_DUP_ALL dup entire address space
 * HAT_DUP_COW dup plus hat_clrattr(..PROT_WRITE) on newas
 */
#define	HAT_DUP_ALL		1
#define	HAT_DUP_COW		2
#define	HAT_DUP_SRD		3


/*
 * Flags for hat_map
 */
#define	HAT_MAP			0x00

/*
 * Flag for hat_pageunload
 */
#define	HAT_ADV_PGUNLOAD	0x00
#define	HAT_FORCE_PGUNLOAD	0x01
#define	HAT_CURPROC_PGUNLOAD	0x02

/*
 * Attributes for hat_page_*attr, hat_setstats and
 * returned by hat_pagesync.
 */
#define	P_MOD	0x1		/* the modified bit */
#define	P_REF	0x2		/* the referenced bit */
#define	P_RO	0x4		/* Read only page */
#define	P_NSH	0x8		/* Not to shuffle v_pages */

#define	hat_ismod(pp)		(hat_page_getattr(pp, P_MOD))
#define	hat_isref(pp)		(hat_page_getattr(pp, P_REF))
#define	hat_isro(pp)		(hat_page_getattr(pp, P_RO))

#define	hat_setmod(pp)		(hat_page_setattr(pp, P_MOD))
#define	hat_setmod_only(pp)	(hat_page_setattr(pp, P_MOD|P_NSH))
#define	hat_setref(pp)		(hat_page_setattr(pp, P_REF))
#define	hat_setrefmod(pp)	(hat_page_setattr(pp, P_REF|P_MOD))

#define	hat_clrmod(pp)		(hat_page_clrattr(pp, P_MOD))
#define	hat_clrref(pp)		(hat_page_clrattr(pp, P_REF))
#define	hat_clrrefmod(pp)	(hat_page_clrattr(pp, P_REF|P_MOD))

#define	hat_page_is_mapped(pp)	(hat_page_getshare(pp))

/*
 * hat_setup is being used in sparc/os/sundep.c
 */
void	hat_setup(struct hat *, int);

/*
 * Flags for hat_setup
 */
#define	HAT_DONTALLOC		0
#define	HAT_ALLOC		1
#define	HAT_INIT		2

/*
 * Other routines, for statistics
 */
int	hat_startstat(struct as *);
void	hat_getstat(struct as *, caddr_t, size_t, uint_t, char *, int);
void	hat_freestat(struct as *, int);
void	hat_resvstat(size_t, struct as *, caddr_t);

/*
 * Relocation callback routines. Currently only sfmmu HAT supports
 * these.
 */
extern int	hat_add_callback(id_t, caddr_t, uint_t, uint_t, void *,
	pfn_t *, void **);
extern id_t	hat_register_callback(int,
	int (*prehandler)(caddr_t, uint_t, uint_t, void *),
	int (*posthandler)(caddr_t, uint_t, uint_t, void *, pfn_t),
	int (*errhandler)(caddr_t, uint_t, uint_t, void *), int);
extern void	hat_delete_callback(caddr_t, uint_t, void *, uint_t, void *);

/*
 * hat_add_callback()/hat_delete_callback() flags.
 */
#define	HAC_NOSLEEP	0x0
#define	HAC_SLEEP	0x1
#define	HAC_PAGELOCK	0x2

/*
 * Suspend/unsuspend handler callback arguments.
 */
#define	HAT_SUSPEND		0x0010
#define	HAT_UNSUSPEND		0x0010
#define	HAT_PRESUSPEND		0x0020
#define	HAT_POSTUNSUSPEND	0x0020

/*
 * Error handler callback arguments. See the block comments
 * before the implementation of hat_add_callback() for an
 * explanation of what these mean.
 */
#define	HAT_CB_ERR_LEAKED	0x1

#endif /* _KERNEL */

/*
 * The size of the bit array for ref and mod bit storage must be a power of 2.
 * 2 bits are collected for each page.  Below the power used is 4,
 * which is 16 8-bit characters = 128 bits, ref and mod bit information
 * for 64 pages.
 */
#define	HRM_SHIFT		4
#define	HRM_BYTES		(1 << HRM_SHIFT)
#define	HRM_PAGES		((HRM_BYTES * NBBY) / 2)
#define	HRM_PGPERBYTE		(NBBY/2)
#define	HRM_PGBYTEMASK		(HRM_PGPERBYTE-1)

#define	HRM_PGOFFMASK		((HRM_PGPERBYTE-1) << MMU_PAGESHIFT)
#define	HRM_BASEOFFSET		(((MMU_PAGESIZE * HRM_PAGES) - 1))
#define	HRM_BASEMASK		(~(HRM_BASEOFFSET))

#define	HRM_BASESHIFT		(MMU_PAGESHIFT + (HRM_SHIFT + 2))
#define	HRM_PAGEMASK		(MMU_PAGEMASK ^ HRM_BASEMASK)

#define	HRM_HASHSIZE		0x200
#define	HRM_HASHMASK		(HRM_HASHSIZE - 1)

#define	HRM_BLIST_INCR		0x200

/*
 * The structure for maintaining referenced and modified information
 */
struct hrmstat {
	struct as	*hrm_as;	/* stat block belongs to this as */
	uintptr_t	hrm_base;	/* base of block */
	ushort_t	hrm_id;		/* opaque identifier, one of a_vbits */
	struct hrmstat	*hrm_anext;	/* as statistics block list */
	struct hrmstat	*hrm_hnext;	/* list for hashed blocks */
	uchar_t		hrm_bits[HRM_BYTES]; /* the ref and mod bits */
};

extern struct hrmstat **hrm_hashtab;

/*
 * For global monitoring of the reference and modified bits
 * of all address spaces we reserve one id bit.
 */
#define	HRM_SWSMONID	1


#ifdef _KERNEL

/*
 * Hat locking functions
 * XXX - these two functions are currently being used by hatstats
 * 	they can be removed by using a per-as mutex for hatstats.
 */
void	hat_enter(struct hat *);
void	hat_exit(struct hat *);

typedef void (*hat_rgn_cb_func_t)(caddr_t, caddr_t, caddr_t,
    size_t, void *, u_offset_t);

void			hat_join_srd(struct hat *, vnode_t *);

hat_region_cookie_t	hat_join_region(struct hat *, caddr_t, size_t, void *,
			    u_offset_t, uchar_t, uchar_t, hat_rgn_cb_func_t,
			    uint_t);
void			hat_leave_region(struct hat *, hat_region_cookie_t,
			    uint_t);
void			hat_dup_region(struct hat *, hat_region_cookie_t);

#define	HAT_INVALID_REGION_COOKIE	((hat_region_cookie_t)-1)
#define	HAT_IS_REGION_COOKIE_VALID(c)	((c) != HAT_INVALID_REGION_COOKIE)

/* hat_join_region() flags */

#define	HAT_REGION_TEXT	0x1	/* passed by segvn */
#define	HAT_REGION_ISM	0x2	/* for hat_share()/hat_unshare() */

#define	HAT_REGION_TYPE_MASK	(0x7)

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HAT_H */
