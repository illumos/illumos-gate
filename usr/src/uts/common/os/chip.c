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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/processor.h>
#include <sys/disp.h>
#include <sys/chip.h>

/*
 * CMT aware scheduler/dispatcher support
 *
 * With the introduction of Chip Multi-Threaded (CMT) processor architectures,
 * it is no longer necessarily true that a given physical processor
 * module (chip) will present itself as a single schedulable entity (cpu_t).
 * Rather, each chip may present itself as one or more "logical" CPUs.
 *
 * The logical CPUs presented may share physical components on the chip
 * such as caches, data pipes, FPUs, etc. It is advantageous to have the
 * kernel know which logical CPUs are presented by a given chip,
 * and what facilities on the chip are shared, since the kernel can then use
 * this information to employ scheduling policies that help improve the
 * availability of per chip resources, and increase utilization of a thread's
 * cache investment.
 *
 * The "chip_t" structure represents a physical processor.
 * It is used to keep track of which logical CPUs are presented by a given
 * chip, and to provide a parameterized representation of a chip's
 * properties. A count of the number of running threads is also
 * maintained, and is used by the dispatcher to balance load across the
 * system's chips to improve performance through increased chip resource
 * availability.
 *
 * Locking:
 *
 * Safely traversing the per lgroup lists requires the same protections
 * as traversing the cpu lists. One must either:
 *	- hold cpu_lock
 *	- have disabled kernel preemption
 *	- be at high SPL
 *	- have cpu's paused
 *
 * Safely traversing the global "chip_list" requires holding cpu_lock.
 *
 * A chip's nrunning count should only be modified using the
 * CHIP_NRUNNING() macro, through which updates of the count are done
 * atomically.
 */

chip_t			cpu0_chip;	/* chip structure for first CPU */

/*
 * chip_bootstrap is used on platforms where it is possible to enter the
 * dispatcher before a new CPU's chip initialization has happened.
 */
static chip_t		chip_bootstrap;

#define	CPU_HAS_NO_CHIP(cp)	\
	((cp)->cpu_chip == NULL || (cp)->cpu_chip == &chip_bootstrap)

static chip_t		*chip_list;	/* protected by CPU lock */
static chip_set_t	chip_set;	/* bitmap of chips in existence */
					/* indexed by chip_seqid */
static chipid_t		chip_seqid_next = 0;	/* next sequential chip id */
static int		nchips = 0;	/* num chips in existence */

static chip_t	*chip_find(chipid_t);
static int	chip_kstat_extract(kstat_t *, int);

/*
 * Declare static kstat names (defined in chip.h)
 */
CHIP_KSTAT_NAMES;

/*
 * Find the chip_t with the given chip_id.
 */
static chip_t *
chip_find(chipid_t chipid)
{
	chip_t	*chp, *chip_start;

	ASSERT(chip_list == NULL || chip_list->chip_next == chip_list ||
	    MUTEX_HELD(&cpu_lock));

	if ((chp = chip_start = chip_list) != NULL) {
		do {
			if (chp->chip_id == chipid) {
				return (chp);
			}
		} while ((chp = chp->chip_next) != chip_start);
	}
	return (NULL);
}

#ifndef sun4v
/*
 * Setup the kstats for this chip, if needed
 */
void
chip_kstat_create(chip_t *chp)
{
	chip_stat_t	stat;
	kstat_t		*chip_kstat;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (chp->chip_kstat != NULL)
		return;		/* already initialized */

	chip_kstat = kstat_create("chip", chp->chip_id, NULL, "misc",
	    KSTAT_TYPE_NAMED, CHIP_NUM_STATS,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);

	if (chip_kstat != NULL) {
		chip_kstat->ks_lock = &chp->chip_kstat_mutex;
		mutex_init(chip_kstat->ks_lock, NULL, MUTEX_DEFAULT, NULL);
		chip_kstat->ks_private = chp;
		chip_kstat->ks_data = chp->chip_kstat_data;
		for (stat = 0; stat < CHIP_NUM_STATS; stat++)
			kstat_named_init(&chp->chip_kstat_data[stat],
			    chip_kstat_names[stat], KSTAT_DATA_INT64);
		chip_kstat->ks_update = chip_kstat_extract;
		chp->chip_kstat = chip_kstat;
		kstat_install(chip_kstat);
	}
}
#else
/*
 * Note: On sun4v systems, chip kstats don't currently
 * exist, since "chip" structures and policies are being
 * leveraged to implement core level balancing, and exporting
 * chip kstats in light of this would be both misleading
 * and confusing.
 */
/* ARGSUSED */
void
chip_kstat_create(chip_t *chp)
{
}
#endif	/* !sun4v */

static int
chip_kstat_extract(kstat_t *ksp, int rw)
{
	struct kstat_named	*ksd;
	chip_t			*chp;

	chp = (chip_t *)ksp->ks_private;

	ksd = (struct kstat_named *)ksp->ks_data;
	ASSERT(ksd == chp->chip_kstat_data);

	/*
	 * The chip kstats are read only
	 */
	if (rw == KSTAT_WRITE)
		return (EACCES);

	ksd[CHIP_ID].value.i64 = chp->chip_id;
	ksd[CHIP_NCPUS].value.i64 = chp->chip_ncpu;
	ksd[CHIP_NRUNNING].value.i64 = chp->chip_nrunning;
	ksd[CHIP_RECHOOSE].value.i64 =
	    rechoose_interval + chp->chip_rechoose_adj;

	return (0);
}

/*
 * If necessary, instantiate a chip_t for this CPU.
 * Called when a CPU is being added to the system either in startup,
 * or because of DR. The cpu will be assigned to the chip's active
 * CPU list later in chip_cpu_assign()
 */
void
chip_cpu_init(cpu_t *cp)
{
	chipid_t	cid;
	int		rechoose;
	chip_t		*chp;
	chip_def_t	chp_def;

	ASSERT((chip_list == NULL) || (MUTEX_HELD(&cpu_lock)));

	/*
	 * Call into the platform to fetch this cpu's chipid
	 * On sun4v platforms, the chip infrastructure is currently being
	 * leveraged to implement core level load balancing.
	 */
#ifdef	sun4v
	cid = chip_plat_get_pipeid(cp);
#else
	cid = chip_plat_get_chipid(cp);
#endif /* sun4v */

	chp = chip_find(cid);
	if (chp == NULL) {

		/*
		 * Create a new chip
		 */
		if (chip_list == NULL)
			chp = &cpu0_chip;
		else
			chp = kmem_zalloc(sizeof (*chp), KM_SLEEP);

		chp->chip_id = cid;
		chp->chip_nrunning = 0;

		/*
		 * If we're booting, take this moment to perform
		 * some additional initialization
		 */
		if (chip_list == NULL) {
			CHIP_SET_ZERO(chip_set);
			CHIP_SET_ZERO(cp->cpu_part->cp_chipset);
			chp->chip_nrunning++;	/* for t0 */
		}

		/*
		 * Find the next free sequential chip id.
		 * A chip's sequential id exists in the range
		 * 0 .. CHIP_MAX_CHIPS, and is suitable for use with
		 * chip sets.
		 */
		while (CHIP_SET_TEST(chip_set, chip_seqid_next))
			chip_seqid_next++;
		chp->chip_seqid = chip_seqid_next++;
		CHIP_SET_ADD(chip_set, chp->chip_seqid);

		ASSERT(chip_seqid_next <= CHIP_MAX_CHIPS);


		/*
		 * Query the platform specific parameters
		 * for this chip
		 */
		chip_plat_define_chip(cp, &chp_def);
		chp->chip_rechoose_adj = chp_def.chipd_rechoose_adj;
		chp->chip_type = chp_def.chipd_type;

		ASSERT((chp->chip_type < CHIP_NUM_TYPES) &&
		    (chp->chip_type >= CHIP_DEFAULT));

		/*
		 * Insert this chip in chip_list
		 */
		if (chip_list == NULL) {
			chip_list = chp;
			chp->chip_next = chp->chip_prev = chp;
		} else {
			chip_t	*chptr;

			chptr = chip_list;
			chp->chip_next = chptr;
			chp->chip_prev = chptr->chip_prev;
			chptr->chip_prev->chip_next = chp;
			chptr->chip_prev = chp;
		}

		nchips++;
		ASSERT(nchips <= CHIP_MAX_CHIPS);

		/*
		 * The boot cpu will create the first chip's kstats
		 * later in cpu_kstat_init()
		 */
		if (chp != &cpu0_chip)
			chip_kstat_create(chp);
	}

	/*
	 * Initialize the effective rechoose interval cached
	 * in this cpu structure.
	 */
	rechoose = rechoose_interval + chp->chip_rechoose_adj;
	cp->cpu_rechoose = (rechoose < 0) ? 0 : rechoose;

	cp->cpu_chip = chp;
	chp->chip_ref++;
}

/*
 * This cpu is being deleted. It has already been removed from
 * the chip's active cpu list back in chip_cpu_unassign(). Here
 * we remove the cpu's reference to the chip, and cleanup/destroy
 * the chip if needed.
 */
void
chip_cpu_fini(cpu_t *cp)
{
	chip_t	*chp;
	chip_t	*prev, *next;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * This can happen if the CPU failed to power on
	 */
	if (CPU_HAS_NO_CHIP(cp))
		return;

	chp = cp->cpu_chip;
	cp->cpu_chip = NULL;

	if (--chp->chip_ref == 0) {
		/*
		 * make sure the chip is really empty
		 */
		ASSERT(chp->chip_ncpu == 0);
		ASSERT(chp->chip_cpus == NULL);
		ASSERT(chp->chip_nrunning == 0);
		ASSERT(chp->chip_lgrp == NULL);
		ASSERT((chp->chip_next_lgrp == NULL) &&
		    (chp->chip_prev_lgrp == NULL));

		if (chip_seqid_next > chp->chip_seqid)
			chip_seqid_next = chp->chip_seqid;
		CHIP_SET_REMOVE(chip_set, chp->chip_seqid);

		chp->chip_id = -1;
		chp->chip_seqid = -1;

		/*
		 * remove the chip from the system's chip list
		 */
		if (chip_list == chp)
			chip_list = chp->chip_next;

		prev = chp->chip_prev;
		next = chp->chip_next;

		prev->chip_next = next;
		next->chip_prev = prev;

		chp->chip_next = chp->chip_prev = NULL;

		nchips--;

		/*
		 * clean up any chip kstats
		 */
		if (chp->chip_kstat) {
			kstat_delete(chp->chip_kstat);
			chp->chip_kstat = NULL;
		}
		/*
		 * If the chip_t structure was dynamically
		 * allocated, free it.
		 */
		if (chp != &cpu0_chip)
			kmem_free(chp, sizeof (*chp));
	}
}

/*
 * This cpu is becoming active (online).
 * Perform all the necessary bookkeeping in it's chip_t
 */
void
chip_cpu_assign(cpu_t *cp)
{
	chip_t		*chp;
	cpu_t		*cptr;

	ASSERT(chip_list == NULL || chip_list->chip_next == chip_list ||
	    MUTEX_HELD(&cpu_lock));

	chp = cp->cpu_chip;

	/*
	 * Add this cpu to the chip's cpu list
	 */
	if (chp->chip_ncpu == 0) {
		chp->chip_cpus = cp;
		cp->cpu_next_chip = cp->cpu_prev_chip = cp;
	} else {
		cptr = chp->chip_cpus;
		cp->cpu_next_chip = cptr;
		cp->cpu_prev_chip = cptr->cpu_prev_chip;
		cp->cpu_prev_chip->cpu_next_chip = cp;
		cptr->cpu_prev_chip = cp;
	}

	chp->chip_ncpu++;

	/*
	 * Notate this chip's seqid in the cpu partition's chipset
	 */
	chip_cpu_move_part(cp, NULL, cp->cpu_part);
}

/*
 * This cpu is being offlined, so do the reverse
 * of cpu_chip_assign()
 */
void
chip_cpu_unassign(cpu_t *cp)
{
	chip_t		*chp;
	struct cpu	*prev;
	struct cpu	*next;

	ASSERT(MUTEX_HELD(&cpu_lock));

	chp = cp->cpu_chip;

	chip_cpu_move_part(cp, cp->cpu_part, NULL);

	/*
	 * remove this cpu from the chip's cpu list
	 */
	prev = cp->cpu_prev_chip;
	next = cp->cpu_next_chip;

	prev->cpu_next_chip = next;
	next->cpu_prev_chip = prev;

	cp->cpu_next_chip = cp->cpu_prev_chip = NULL;

	chp->chip_ncpu--;

	if (chp->chip_ncpu == 0) {
		chp->chip_cpus = NULL;
	} else if (chp->chip_cpus == cp) {
		chp->chip_cpus = next;
	}
}

/*
 * A cpu on the chip is moving into and/or out of a cpu partition.
 * Maintain the cpuparts' chip membership set.
 * oldpp is NULL when a cpu is being offlined.
 * newpp is NULL when a cpu is being onlined.
 */
void
chip_cpu_move_part(cpu_t *cp, cpupart_t *oldpp, cpupart_t *newpp)
{
	cpu_t	*cpp;
	chip_t	*chp;

	ASSERT(chip_list->chip_next == chip_list || MUTEX_HELD(&cpu_lock));

	chp = cp->cpu_chip;

	if (newpp != NULL) {
		/*
		 * Add the chip's seqid to the cpupart's chip set
		 */
		CHIP_SET_ADD(newpp->cp_chipset, chp->chip_seqid);
	}

	if (oldpp != NULL) {
		cpp = cp;
		while ((cpp = cpp->cpu_next_chip) != cp) {
			if (cpp->cpu_part->cp_id == oldpp->cp_id) {
				/*
				 * Another cpu on the chip is in the old
				 * cpu partition, so we're done
				 */
				return;
			}
		}

		/*
		 * No other cpu on the chip is in the old partition
		 * so remove the chip's seqid from it's set
		 */
		CHIP_SET_REMOVE(oldpp->cp_chipset, chp->chip_seqid);
	}
}

/*
 * Called to indicate a slave CPU has started up.
 */
void
chip_cpu_startup(cpu_t *cp)
{
	/*
	 * Indicate that the chip has a new running thread
	 * (slave startup)
	 */
	CHIP_NRUNNING(cp->cpu_chip, 1);
}

/*
 * Provide the specified CPU a bootstrap chip
 */
void
chip_bootstrap_cpu(cpu_t *cp)
{
	cp->cpu_chip = &chip_bootstrap;
}

/*
 * Given a chip set, return 1 if it is empty.
 */
int
chip_set_isnull(chip_set_t *set)
{
	int	i;

	for (i = 0; i < CHIP_SET_WORDS; i++) {
		if (set->csb[i] != 0)
			return (0);
	}
	return (1);
}
