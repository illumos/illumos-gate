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

#ifndef	_VM_SEG_KP_H
#define	_VM_SEG_KP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * segkp (as in kernel pageable) is a segment driver that supports allocation
 * of page-aligned variable size of vm resources.
 *
 * Each vm resource represents a page-aligned range of virtual addresses.
 * The caller may specify whether the resource should include a redzone,
 * be locked down, or be zero initialized.
 */

#include <vm/seg.h>
#include <sys/vmem.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * Private information per overall segkp segment (as opposed
 * to per resource within segment). There are as many anon slots
 * allocated as there there are pages in the segment.
 */
struct segkp_segdata {
	struct anon_hdr	*kpsd_anon;	/* anon structs */
	vmem_t		*kpsd_arena; 	/* virtual memory descriptor */
	struct segkp_data **kpsd_hash;	/* Hash table for lookups */
};

#define	SEGKP_VMEM(seg)	(((struct segkp_segdata *)(seg)->s_data)->kpsd_arena)

/*
 * A hash table is used to aid in the lookup of a kpd's based on vaddr.
 * Since the heaviest use of segkp occurs from segkp_*get and segkp_*release,
 * the hashing is based on the vaddr used by these routines.
 */
#define	SEGKP_HASHSZ		256	/* power of two */
#define	SEGKP_HASHMASK		(SEGKP_HASHSZ - 1)
#define	SEGKP_HASH(vaddr)	\
	((int)(((uintptr_t)vaddr >> PAGESHIFT) & SEGKP_HASHMASK))

struct segkp_data {
	kmutex_t	kp_lock;	/* per resource lock */
	caddr_t		kp_base;	/* starting addr of chunk */
	size_t		kp_len;		/* # of bytes */
	uint_t		kp_flags;	/* state info */
	int		kp_cookie;	/* index into cache array */
	ulong_t		kp_anon_idx;	/* index into main anon array */
					/* in segkp_segdata */
	struct anon_hdr	*kp_anon;	/* anon structs */
	struct segkp_data *kp_next;	/* ptr to next in hash chain */
};

/*
 * Flag bits
 *
 */
#define	KPD_ZERO	0x01		/* initialize resource with 0 */
#define	KPD_LOCKED	0x02		/* resources locked */
#define	KPD_NO_ANON	0x04		/* no swap resources required */
#define	KPD_HASREDZONE	0x08		/* include a redzone */
#define	KPD_NOWAIT	0x10		/* do not wait for res. if unavail. */
#define	KPD_WRITEDIRTY	0x20		/* dirty pages should be flushed */
#define	KPD_HASAMP	0x40		/* anon_hdr managed by caller */

/*
 * A cache of segkp elements may be created via segkp_cache_init().
 * The elements on the freelist all have the same len and flags value.
 * The cookie passed to the client is an index into the freelist array.
 */
struct segkp_cache  {
	int		kpf_max;		/* max # of elements allowed */
	int		kpf_count;		/* current no. of elments */
	int		kpf_inuse;		/* list inuse */
	uint_t		kpf_flags;		/* seg_kp flag value */
	size_t		kpf_len;		/* len of resource */
	struct seg	*kpf_seg;		/* segment */
	struct segkp_data *kpf_list;		/* list of kpd's */
};
#define	SEGKP_MAX_CACHE		4	/* Number of caches maintained */

/*
 * Define redzone, and stack_to_memory macros.
 * The redzone is PAGESIZE bytes.
 */
#ifdef	STACK_GROWTH_DOWN
#define	KPD_REDZONE(kpd)	(0)
#define	stom(v, flags)	(((flags) & KPD_HASREDZONE) ? (v) + PAGESIZE : (v))

#else	/* STACK_GROWTH_DOWN */

#define	KPD_REDZONE(kpd) (btop(kpd->kp_len) - 1)
#define	stom(v)	(v)
#endif	/* STACK_GROWTH_DOWN */

#define	SEGKP_MAPLEN(len, flags) \
	(((flags) & KPD_HASREDZONE) ? (len) - PAGESIZE : (len))

extern	struct seg *segkp;
/* If segkp becomes more than one seg this test will need changing. */
#define	SEG_IS_SEGKP(SEG)	((SEG) == segkp)

/*
 * Public routine declarations not part of the segment ops vector go here.
 */
int	segkp_create(struct seg *seg);
caddr_t	segkp_get(struct seg *seg, size_t len, uint_t flags);
void	segkp_release(struct seg *seg, caddr_t vaddr);
void *  segkp_cache_init(struct seg *seg, int maxsize, size_t len,
		uint_t flags);
void	segkp_cache_free();
caddr_t segkp_cache_get(void *cookie);
int	segkp_map_red(void);
void	segkp_unmap_red(void);
size_t	swapsize(caddr_t v);

/* Special currently only used by schedctl. */
struct anon_map;	/* Make the compiler happy about the next line. */
caddr_t segkp_get_withanonmap(struct seg *, size_t, uint_t, struct anon_map *);

/*
 * We allow explicit calls to segkp_fault, even though it's part
 * of the segkp ops vector.
 */
faultcode_t segkp_fault(struct hat *hat, struct seg *seg, caddr_t addr,
	size_t len, enum fault_type type, enum seg_rw rw);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_KP_H */
