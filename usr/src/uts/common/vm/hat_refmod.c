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

/*
 * The following routines implement the hat layer's
 * recording of the referenced and modified bits.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/kmem.h>

/*
 * Note, usage of cmn_err requires you not hold any hat layer locks.
 */
#include <sys/cmn_err.h>

#include <vm/as.h>
#include <vm/hat.h>

kmutex_t hat_statlock;		/* protects all hat statistics data */
struct hrmstat *hrm_memlist;	/* tracks memory alloced for hrm_blist blocks */
struct hrmstat **hrm_hashtab;	/* hash table for finding blocks quickly */
struct hrmstat *hrm_blist;
int hrm_blist_incr = HRM_BLIST_INCR;
int hrm_blist_lowater = HRM_BLIST_INCR/2;
int hrm_blist_num = 0;
int hrm_blist_total = 0;
int hrm_mlockinited = 0;
int hrm_allocfailmsg = 0;	/* print a message when allocations fail */
int hrm_allocfail = 0;

static struct hrmstat	*hrm_balloc(void);
static void	hrm_link(struct hrmstat *);
static void	hrm_setbits(struct hrmstat *, caddr_t, uint_t);
static void	hrm_hashout(struct hrmstat *);
static void	hrm_getblk(int);

#define	hrm_hash(as, addr) \
	(HRM_HASHMASK & \
	(((uintptr_t)(addr) >> HRM_BASESHIFT) ^ ((uintptr_t)(as) >> 2)))

#define	hrm_match(hrm, as, addr) \
	(((hrm)->hrm_as == (as) && \
	((hrm)->hrm_base == ((uintptr_t)(addr) & HRM_BASEMASK))) ? 1 : 0)

/*
 * Called when an address space maps in more pages while stats are being
 * collected.
 */
/* ARGSUSED */
void
hat_resvstat(size_t chunk, struct as *as, caddr_t addr)
{
}

/*
 * Start the statistics gathering for an address space.
 * Return -1 if we can't do it, otherwise return an opaque
 * identifier to be used when querying for the gathered statistics.
 * The identifier is an unused bit in a_vbits.
 * Bit 0 is reserved for swsmon.
 */
int
hat_startstat(struct as *as)
{
	uint_t nbits;		/* number of bits */
	uint_t bn;		/* bit number */
	uint_t id;		/* new vbit, identifier */
	uint_t vbits;		/* used vbits of address space */
	size_t chunk;		/* mapped size for stats */

	/*
	 * If the refmod saving memory allocator runs out, print
	 * a warning message about how to fix it, see comment at
	 * the beginning of hat_setstat.
	 */
	if (hrm_allocfailmsg) {
		cmn_err(CE_WARN,
		    "hrm_balloc failures occured, increase hrm_blist_incr");
		hrm_allocfailmsg = 0;
	}

	/*
	 * Verify that a buffer of statistics blocks exists
	 * and allocate more, if needed.
	 */

	chunk = hat_get_mapped_size(as->a_hat);
	chunk = (btop(chunk)/HRM_PAGES);
	if (chunk < HRM_BLIST_INCR)
		chunk = 0;

	hrm_getblk((int)chunk);

	/*
	 * Find a unused id in the given address space.
	 */
	hat_enter(as->a_hat);
	vbits = as->a_vbits;
	nbits = sizeof (as->a_vbits) * NBBY;
	for (bn = 1, id = 2; bn < (nbits - 1); bn++, id <<= 1)
		if ((id & vbits) == 0)
			break;
	if (bn >= (nbits - 1)) {
		hat_exit(as->a_hat);
		return (-1);
	}
	as->a_vbits |= id;
	hat_exit(as->a_hat);
	(void) hat_stats_enable(as->a_hat);
	return (id);
}

/*
 * Record referenced and modified information for an address space.
 * Rmbits is a word containing the referenced bit in bit position 1
 * and the modified bit in bit position 0.
 *
 * For current informational uses, one can rerun any program using
 * this facility after modifying the hrm_blist_incr to be a larger
 * amount so that a larger buffer of blocks will be maintained.
 */
void
hat_setstat(struct as *as, caddr_t addr, size_t len, uint_t rmbits)
{
	struct hrmstat	*hrm;
	uint_t		vbits, newbits, nb;
	int		h;

	ASSERT(len == PAGESIZE);
	ASSERT((rmbits & ~(P_MOD|P_REF)) == 0);

	if (rmbits == 0)
		return;

	mutex_enter(&hat_statlock);

	/*
	 * Search the hash list for the as and addr we are looking for
	 * and set the ref and mod bits in every block that matches.
	 */
	vbits = 0;
	h = hrm_hash(as, addr);
	for (hrm = hrm_hashtab[h]; hrm; hrm = hrm->hrm_hnext) {
		if (hrm_match(hrm, as, addr)) {
			hrm_setbits(hrm, addr, rmbits);
			vbits |= hrm->hrm_id;
		}
	}

	/*
	 * If we didn't find a block for all of the enabled
	 * vpages bits, then allocate and initialize a block
	 * for each bit that was not found.
	 */
	if (vbits != as->a_vbits) {
		newbits = (vbits ^ as->a_vbits) & as->a_vbits;
		while (newbits) {
			if (ffs(newbits))
				nb = 1 << (ffs(newbits)-1);
			hrm = (struct hrmstat *)hrm_balloc();
			if (hrm == NULL) {
				hrm_allocfailmsg = 1;
				hrm_allocfail++;
				mutex_exit(&hat_statlock);
				return;
			}
			hrm->hrm_as = as;
			hrm->hrm_base = (uintptr_t)addr & HRM_BASEMASK;
			hrm->hrm_id = nb;
			hrm_link(hrm);
			hrm_setbits(hrm, addr, rmbits);
			newbits &= ~nb;
		}
	}
	mutex_exit(&hat_statlock);
}

/*
 * Free the resources used to maintain the referenced and modified
 * statistics for the virtual page view of an address space
 * identified by id.
 */
void
hat_freestat(struct as *as, int id)
{
	struct hrmstat *hrm;
	struct hrmstat *prev_ahrm;
	struct hrmstat *hrm_tmplist;
	struct hrmstat *hrm_next;

	hat_stats_disable(as->a_hat);	/* tell the hat layer to stop */
	hat_enter(as->a_hat);
	if (id == 0)
		as->a_vbits = 0;
	else
		as->a_vbits &= ~id;

	if ((hrm = as->a_hrm) == NULL) {
		hat_exit(as->a_hat);
		return;
	}
	hat_exit(as->a_hat);

	mutex_enter(&hat_statlock);

	for (prev_ahrm = NULL; hrm; hrm = hrm->hrm_anext) {
		if ((id == hrm->hrm_id) || (id == NULL)) {

			hrm_hashout(hrm);
			hrm->hrm_hnext = hrm_blist;
			hrm_blist = hrm;
			hrm_blist_num++;

			if (prev_ahrm == NULL)
				as->a_hrm = hrm->hrm_anext;
			else
				prev_ahrm->hrm_anext = hrm->hrm_anext;

		} else
			prev_ahrm = hrm;
	}

	/*
	 * If all statistics blocks are free,
	 * return the memory to the system.
	 */
	if (hrm_blist_num == hrm_blist_total) {
		/* zero the block list since we are giving back its memory */
		hrm_blist = NULL;
		hrm_blist_num = 0;
		hrm_blist_total = 0;
		hrm_tmplist = hrm_memlist;
		hrm_memlist = NULL;
	} else {
		hrm_tmplist = NULL;
	}

	mutex_exit(&hat_statlock);

	/*
	 * If there are any hrmstat structures to be freed, this must only
	 * be done after we've released hat_statlock.
	 */
	while (hrm_tmplist != NULL) {
		hrm_next = hrm_tmplist->hrm_hnext;
		kmem_free(hrm_tmplist, hrm_tmplist->hrm_base);
		hrm_tmplist = hrm_next;
	}
}

/*
 * Grab memory for statistics gathering of the hat layer.
 */
static void
hrm_getblk(int chunk)
{
	struct hrmstat *hrm, *l;
	int i;
	int hrm_incr;

	mutex_enter(&hat_statlock);
	/*
	 * XXX The whole private freelist management here really should be
	 * overhauled.
	 *
	 * The freelist should have some knowledge of how much memory is
	 * needed by a process and thus when hat_resvstat get's called, we can
	 * increment the freelist needs for that process within this subsystem.
	 * Thus there will be reservations for all processes which are being
	 * watched which should be accurate, and consume less memory overall.
	 *
	 * For now, just make sure there's enough entries on the freelist to
	 * handle the current chunk.
	 */
	if ((hrm_blist == NULL) ||
	    (hrm_blist_num <= hrm_blist_lowater) ||
	    (chunk && (hrm_blist_num < chunk + hrm_blist_incr))) {
		mutex_exit(&hat_statlock);

		hrm_incr = chunk  + hrm_blist_incr;
		hrm = kmem_zalloc(sizeof (struct hrmstat) * hrm_incr, KM_SLEEP);
		hrm->hrm_base = sizeof (struct hrmstat) * hrm_incr;

		/*
		 * thread the allocated blocks onto a freelist
		 * using the first block to hold information for
		 * freeing them all later
		 */
		mutex_enter(&hat_statlock);
		hrm->hrm_hnext = hrm_memlist;
		hrm_memlist = hrm;

		hrm_blist_total += (hrm_incr - 1);
		for (i = 1; i < hrm_incr; i++) {
			l = &hrm[i];
			l->hrm_hnext = hrm_blist;
			hrm_blist = l;
			hrm_blist_num++;
		}
	}
	mutex_exit(&hat_statlock);
}

static void
hrm_hashin(struct hrmstat *hrm)
{
	int 		h;

	ASSERT(MUTEX_HELD(&hat_statlock));
	h = hrm_hash(hrm->hrm_as, hrm->hrm_base);

	hrm->hrm_hnext = hrm_hashtab[h];
	hrm_hashtab[h] = hrm;
}

static void
hrm_hashout(struct hrmstat *hrm)
{
	struct hrmstat	*list, **prev_hrm;
	int		h;

	ASSERT(MUTEX_HELD(&hat_statlock));
	h = hrm_hash(hrm->hrm_as, hrm->hrm_base);
	list = hrm_hashtab[h];
	prev_hrm = &hrm_hashtab[h];

	while (list) {
		if (list == hrm) {
			*prev_hrm = list->hrm_hnext;
			return;
		}
		prev_hrm = &list->hrm_hnext;
		list = list->hrm_hnext;
	}
}


/*
 * Link a statistic block into an address space and also put it
 * on the hash list for future references.
 */
static void
hrm_link(struct hrmstat *hrm)
{
	struct as *as = hrm->hrm_as;

	ASSERT(MUTEX_HELD(&hat_statlock));
	hrm->hrm_anext = as->a_hrm;
	as->a_hrm = hrm;
	hrm_hashin(hrm);
}

/*
 * Allocate a block for statistics keeping.
 * Returns NULL if blocks are unavailable.
 */
static struct hrmstat *
hrm_balloc(void)
{
	struct hrmstat *hrm;

	ASSERT(MUTEX_HELD(&hat_statlock));

	hrm = hrm_blist;
	if (hrm != NULL) {
		hrm_blist = hrm->hrm_hnext;
		hrm_blist_num--;
		hrm->hrm_hnext = NULL;
	}
	return (hrm);
}

/*
 * Set the ref and mod bits for addr within statistics block hrm.
 */
static void
hrm_setbits(struct hrmstat *hrm, caddr_t addr, uint_t bits)
{
	uint_t po, bo, spb;
	uint_t nbits;

	po = ((uintptr_t)addr & HRM_BASEOFFSET) >> MMU_PAGESHIFT; /* pg off */
	bo = po / (NBBY / 2);			/* which byte in bit array */
	spb = (3 - (po & 3)) * 2;		/* shift position within byte */
	nbits = bits << spb;			/* bit mask */
	hrm->hrm_bits[bo] |= nbits;
}

/*
 * Return collected statistics about an address space.
 * If clearflag is set, atomically read and zero the bits.
 *
 * Fill in the data array supplied with the referenced and
 * modified bits collected for address range [addr ... addr + len]
 * in address space, as, uniquely identified by id.
 * The destination is a byte array.  We fill in three bits per byte:
 * referenced, modified, and hwmapped bits.
 * Kernel only interface, can't fault on destination data array.
 *
 */
void
hat_getstat(struct as *as, caddr_t addr, size_t len, uint_t id,
    caddr_t datap, int clearflag)
{
	size_t	np;		/* number of pages */
	caddr_t	a;
	char 	*dp;

	np = btop(len);
	bzero(datap, np);

	/* allocate enough statistics blocks to cover the len passed in */
	hrm_getblk(np / HRM_PAGES);

	hat_sync(as->a_hat, addr, len, clearflag);

	/* allocate more statistics blocks if needed */
	hrm_getblk(0);

	mutex_enter(&hat_statlock);
	if (hrm_hashtab == NULL) {
		/* can happen when victim process exits */
		mutex_exit(&hat_statlock);
		return;
	}
	dp = datap;
	a = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	while (a < addr + len) {
		struct hrmstat	*hrm;
		size_t	n;		/* number of pages, temp */
		int	h;		/* hash index */
		uint_t	po;

		h = hrm_hash(as, a);
		n = (HRM_PAGES -
		    (((uintptr_t)a & HRM_PAGEMASK) >> MMU_PAGESHIFT));
		if (n > np)
			n = np;
		po = ((uintptr_t)a & HRM_BASEOFFSET) >> MMU_PAGESHIFT;

		for (hrm = hrm_hashtab[h]; hrm; hrm = hrm->hrm_hnext) {
			if (hrm->hrm_as == as &&
			    hrm->hrm_base == ((uintptr_t)a & HRM_BASEMASK) &&
			    id == hrm->hrm_id) {
				int i, nr;
				uint_t bo, spb;

				/*
				 * Extract leading unaligned bits.
				 */
				i = 0;
				while (i < n && (po & 3)) {
					bo = po / (NBBY / 2);
					spb = (3 - (po & 3)) * 2;
					*dp++ |= (hrm->hrm_bits[bo] >> spb) & 3;
					if (clearflag)
						hrm->hrm_bits[bo] &= ~(3<<spb);
					po++;
					i++;
				}
				/*
				 * Extract aligned bits.
				 */
				nr = n/4*4;
				bo = po / (NBBY / 2);
				while (i < nr) {
					int bits = hrm->hrm_bits[bo];
					*dp++ |= (bits >> 6) & 3;
					*dp++ |= (bits >> 4) & 3;
					*dp++ |= (bits >> 2) & 3;
					*dp++ |= (bits >> 0) & 3;
					if (clearflag)
						hrm->hrm_bits[bo] = 0;
					bo++;
					po += 4;
					i += 4;
				}
				/*
				 * Extract trailing unaligned bits.
				 */
				while (i < n) {
					bo = po / (NBBY / 2);
					spb = (3 - (po & 3)) * 2;
					*dp++ |= (hrm->hrm_bits[bo] >> spb) & 3;
					if (clearflag)
						hrm->hrm_bits[bo] &= ~(3<<spb);
					po++;
					i++;
				}

				break;
			}
		}
		if (hrm == NULL)
			dp += n;
		np -= n;
		a += n * MMU_PAGESIZE;
	}
	mutex_exit(&hat_statlock);
}
