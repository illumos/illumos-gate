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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Inter-Domain Network - SMR support.
 */

#ifndef	_SYS_IDN_SMR_H
#define	_SYS_IDN_SMR_H

#include <sys/sysmacros.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint_t	smr_offset_t;

#define	IDN_NIL_SMROFFSET		((smr_offset_t)-1)

/*
 * ---------------------------------------------------------------------
 * Data in the SMR is automatically aligned on 64 byte boundaries due
 * to the large IDN_SMR_BUFSIZE, however the streams buffers may not be
 * so we bump them in order to allow us to align appropriately and thus
 * maximize bcopy performance.
 * ---------------------------------------------------------------------
 */
#define	IDN_ALIGNSIZE		64
/*
 * Align the pointer "p" to the same relative offset as the reference
 * pointer "r" within IDN_ALIGNSIZE bytes.
 */
#define	IDN_ALIGNPTR(p, r)	((uintptr_t)(p) + (((uintptr_t)(r) - \
					(uintptr_t)(p)) & \
					(uintptr_t)(IDN_ALIGNSIZE - 1)))

#define	IDN_OFFSET2ADDR(off)	((caddr_t)((uintptr_t)(off) + \
					(uintptr_t)idn.smr.vaddr))
#define	IDN_ADDR2OFFSET(va)	((smr_offset_t)((caddr_t)(va) - idn.smr.vaddr))
#define	IDN_BUF2DATA(b, o)	((caddr_t)((uintptr_t)(b) + (uintptr_t)(o)))
#define	IDN_BUF2HDR(b)		((smr_pkthdr_t *)(b))

#define	IDN_CKSUM_PKT_COUNT	(offsetof(smr_pkthdr_t, b_cksum) / 2)

#define	IDN_CKSUM_PKT(h)	\
		(IDN_CHECKSUM ? \
		idn_cksum((ushort_t *)(h), IDN_CKSUM_PKT_COUNT) : 0)

typedef struct smr_pkthdr {
	uint_t		b_netaddr;
	uint_t		b_netports;
	smr_offset_t	b_offset;
	int		b_length;

	ushort_t	b_rawio;
	ushort_t	b_cksum;
	smr_offset_t	b_next;		/* used during reclamation */
} smr_pkthdr_t;

/*
 * ---------------------------------------------------------------------
 * IDN Slab related definitions.
 *
 * Domains are allocated SMR buffers in slabs.  Slaves keep track of
 * their own slabs in their respective idn_domain entry.  The Master
 * keeps track of slave slabs via their respective idn_domain entry.
 * The global slab pools representing all of the SMR and managed by
 * the master are maintained in the idn_global structure.
 *
 * The minimum number of slabs is chosen so that there is at least
 * one slab available for every possible domain that might be attached.
 *
 * NOTE: idn_slab_bufcount * idn_smr_bufsize should be on a 64-byte
 *	 (IDN_ALIGNSIZE) boundary for maximum bcopy performance.
 * ---------------------------------------------------------------------
 */
#define	IDN_SLAB_BUFCOUNT	idn_slab_bufcount
#define	IDN_SLAB_SIZE		(IDN_SLAB_BUFCOUNT * IDN_SMR_BUFSIZE)
#define	IDN_SLAB_MAXNUM		(idn.slabpool->ntotslabs)
#define	IDN_SLAB_MINPERPOOL	3
#define	IDN_SLAB_MINTOTAL	idn_slab_mintotal
#define	IDN_SLAB_PREALLOC	idn_slab_prealloc

/*
 * ---------------------------------------------------------------------
 * Maximum number of slabs per domain the master will
 * allow to be allocated.  Further requests simply result
 * in a failed allocation.
 * Nominal value is 1/6 of the total available (~10).
 * Maximum number of bufs a domain can expect based on
 * IDN_SLAB_MAXPERDOMAIN.
 * ---------------------------------------------------------------------
 */
#define	IDN_SLAB_MAXPERDOMAIN	idn_slab_maxperdomain
#define	IDN_BUF_MAXPERDOMAIN	(IDN_SLAB_MAXPERDOMAIN * IDN_SLAB_BUFCOUNT)
/*
 * ---------------------------------------------------------------------
 * If the total number of available slabs managed by the master
 * goes below this minimum total threshold, then the master kicks
 * off a reap request to all domains to check for free slabs and
 * to give them up.  For performance reasons, domains do not
 * automatically flush out free slabs.  They rely on the master
 * to tell them to look for some.
 * ---------------------------------------------------------------------
 */
#define	IDN_SLAB_THRESHOLD	MIN(MAX_DOMAINS, \
					(IDN_SLAB_MINTOTAL + \
					(IDN_SLAB_MINTOTAL / 5)))
#define	IDN_REAP_INTERVAL	(2 * hz)

#define	SMR_SLABPOOL_HASH(d)		((d) % idn.slabpool->npools)
#define	SMR_SLABPOOL_HASHSTEP(p)	(((p)+4) % idn.slabpool->npools)
#define	SMR_SLAB_HASH(p, d) \
				((d) % idn.slabpool->pool[p].nslabs)
#define	SMR_SLAB_HASHSTEP(p, s) \
				(((s)+1) % idn.slabpool->pool[p].nslabs)

/*
 * ---------------------------------------------------------------------
 * There is one smr_slabbuf for each buffer in the respective slab.
 *
 * sb_domid	Domainid currently owning respective buffer.
 *		Local domains use this field to determine what buffers
 *		are outstanding at which domains.  The master uses this
 *		field to know which domain owns given slab.
 * sb_bufp	Actual pointer to (VA) buffer.
 * sb_next	Used to manage free and in-use lists.
 * ---------------------------------------------------------------------
 */
typedef struct smr_slabbuf {
	int		sb_domid;
	caddr_t		sb_bufp;
	struct smr_slabbuf	*sb_next;
} smr_slabbuf_t;

/*
 * ---------------------------------------------------------------------
 * There is one smr_slab per slab of buffers.
 *
 * sl_next	List of slabs allocated to same requester.
 * sl_start	Base virtual address (SMR) of slab.
 * sl_end	Points to byte immediately following end of slab.
 * sl_lock	Atomic lock used to manage free/inuse lists.
 * sl_domid	Used by Master to indicate which slave owns
 *		respective slab.
 * sl_free	Freelist of available buffers.
 * sl_inuse	List of buffers currently allocated and in-use.
 * sl_head	Pointer to memory allocated to hold smr_slabbuf_t's.
 * ---------------------------------------------------------------------
 */
typedef struct smr_slab {
	struct smr_slab	*sl_next;
	caddr_t		sl_start,
			sl_end;
	lock_t		sl_lock;

	union {
		int	_sl_domid;
		struct {
			smr_slabbuf_t	*_sl_free;
			smr_slabbuf_t	*_sl_inuse;
			smr_slabbuf_t	*_sl_head;
		} _s;
	} _u;
} smr_slab_t;

#define	sl_domid	_u._sl_domid
#define	sl_free		_u._s._sl_free
#define	sl_inuse	_u._s._sl_inuse
#define	sl_head		_u._s._sl_head

/*
 * ---------------------------------------------------------------------
 * io/idn_smr.c
 * ---------------------------------------------------------------------
 */
extern void	smr_slab_reap(int domid, int *nslabs);
extern int	smr_slab_alloc(int domid, smr_slab_t **spp);
extern void 	smr_slab_free(int domid, smr_slab_t *sp);
extern void	smr_slab_garbage_collection(smr_slab_t *sp);
extern int	smr_slab_busy(smr_slab_t *sp);
extern int 	smr_buf_alloc(int domid, uint_t len, caddr_t *bufpp);
extern int 	smr_buf_free(int domid, caddr_t bufp, uint_t len);
extern int	smr_buf_free_locked(int domid, caddr_t bufp, uint_t len);
extern int 	smr_buf_free_all(int domid);
extern int 	smr_buf_reclaim(int domid, int nbufs);
extern int 	smr_slaballoc_put(int domid, smr_slab_t *sp, int forceflag,
					int serrno);
extern void	smr_alloc_buflist(smr_slab_t *sp);
extern void	smr_free_buflist(smr_slab_t *sp);
extern int	smr_slabwaiter_init();
extern void	smr_slabwaiter_deinit();
extern int	smr_slabwaiter_abort(int domid, int serrno);
extern smr_slab_t *smr_slaballoc_get(int domid, caddr_t bufp,
					caddr_t ebufp);
extern int	smr_slabpool_init(size_t reserved_size,
					caddr_t *reserved_area);
extern void 	smr_slabpool_deinit();
extern void	smr_remap(struct as *as, register caddr_t vaddr,
					register pfn_t new_pfn, uint_t mblen);

extern int	idn_slab_prealloc;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IDN_SMR_H */
