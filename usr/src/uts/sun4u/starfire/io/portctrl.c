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
 * Copyright 1990-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/machsystm.h>
#include <sys/starfire.h>

/*
 * Interrupt target translation data for
 * Starfire's Port controller asics
 */
struct pc_ittrans_data {
	kmutex_t ittrans_lock;			 /* lock for ITTR array */
	volatile uint64_t *ittrans_mondovec[32]; /* mondovecreg addr array */
	uint64_t ittransreg_physaddr[32];	 /* ITTREG physaddr array */
};

/*
 * Setup and initialize the soft table that
 * represent the Starfire interrupt target translation
 * registers in the Port controller asics. There is one
 * for each sysio/pci instance.
 */
void
pc_ittrans_init(int upa_id, caddr_t *ittptr_cookie)
{
	int i;
	uint64_t physaddr;
	struct pc_ittrans_data *tmpptr;

	ASSERT(ittptr_cookie != NULL);

	/*
	 * Allocate the data structure to support starfire's
	 * interrupt target translations
	 */
	tmpptr = (struct pc_ittrans_data *)
			kmem_zalloc(sizeof (struct pc_ittrans_data),
				KM_SLEEP);

	/* Initialize the ittrans lock */
	mutex_init(&tmpptr->ittrans_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Construct the base physical address of the
	 * ITTR registers associated with this PC asics
	 */
	physaddr = STARFIRE_UPAID2UPS(upa_id);
	physaddr |= (STARFIRE_PSI_BASE | STARFIRE_PSI_PCREG_OFF |
			STARFIRE_PC_INT_MAP);

	/*
	 * Initialize the ITTR table
	 * This soft table is used to represent the interrupt
	 * target translation hardware registers in the Starfire's
	 * PC asics. There are 32 slots and each slot consists of
	 * a mondovec regaddr entry and the physical address of
	 * the that ITT register. A empty slot is one whose
	 * mondovec entry is null. To reserve/use a slot for a
	 * particular intr mapping reg, we simply find
	 * a empty slot and write in the mondovec mapping
	 * regaddr into the mondovec field.
	 */
	for (i = 0; i < 32; i++) {
		tmpptr->ittrans_mondovec[i] = NULL;
		tmpptr->ittransreg_physaddr[i] = physaddr + i*16;
	}

	*ittptr_cookie = (caddr_t)tmpptr;
}

void
pc_ittrans_uninit(caddr_t ittr_cookie)
{
	struct pc_ittrans_data *tmpptr;

	ASSERT(ittr_cookie != NULL);

	tmpptr = (struct pc_ittrans_data *)ittr_cookie;

	mutex_destroy(&tmpptr->ittrans_lock);
	kmem_free((int *)ittr_cookie, sizeof (struct pc_ittrans_data));
}

/*
 * This routine searches for a slot in the soft ITTR table
 * that was reserved earlier by matching the mondovec
 * mapping regaddr argument with the corresponding field in
 * the table. Note that the soft ITTR table mirrors the
 * corresponding hw table in the starfire port controller(PC)
 * asics. A new slot will be obtained if the slot cannot
 * be found. (not reserved previously). The routine then programs
 * in the target cpu id into the PC ITTR hardware, updates the
 * soft table  and return the index to this slot as the target
 * id cookie.
 */
int
pc_translate_tgtid(caddr_t ittr_cookie, int cpu_id,
		volatile uint64_t *mondovec_addr)
{
	struct pc_ittrans_data *ittptr;
	int i;
	int foundslot = -1;

	ASSERT(ittr_cookie != NULL);

	ittptr = (struct pc_ittrans_data *)ittr_cookie;

	mutex_enter(&ittptr->ittrans_lock);

	/*
	 * Search the mondovec addrlist to see if we
	 * already reserved/used a slot for this particular
	 * mondovec mapping regaddr.
	 */
	for (i = 0; i < 32; i++) {
		if (mondovec_addr == ittptr->ittrans_mondovec[i]) {
			/*
			 * found the slot that matches the
			 * mondo vec in question
			 */
			foundslot = i;
			break;
		}
		if (foundslot == -1 && ittptr->ittrans_mondovec[i] == NULL)
			/* keep track of a empty slot */
			foundslot = i;
	}

	if (foundslot != -1) {
		/* We found a slot for this mondo vec, let's use it */
		stphysio(ittptr->ittransreg_physaddr[foundslot],
			STARFIRE_UPAID2HWMID(cpu_id));
		ittptr->ittrans_mondovec[foundslot] = mondovec_addr;
	} else {
		cmn_err(CE_PANIC, "No more ITTR slots!!");
	}

	mutex_exit(&ittptr->ittrans_lock);
	return (foundslot);
}

/*
 * This routine searches the interrupt target translation table
 * (if exists) for a slot that was reserved/used earlier by
 * matching the mondovec_addr input argument with the mondovec
 * field in the table. The routine then free the found slot by
 * resetting it to zero.
 */
void
pc_ittrans_cleanup(caddr_t ittr_cookie,
		volatile uint64_t *mondovec_addr)
{

	struct pc_ittrans_data *ittptr;
	int i;
	int foundslot = -1;

	ASSERT(ittr_cookie != NULL);

	ittptr = (struct pc_ittrans_data *)ittr_cookie;

	mutex_enter(&ittptr->ittrans_lock);

	/*
	 * Search the mondovec addrlist for the reserved/used
	 * slot associated with this particular mondo vector.
	 */
	for (i = 0; i < 32; i++) {
		if (mondovec_addr == ittptr->ittrans_mondovec[i]) {
			/*
			 * found the slot that matches the
			 * mondo vec in question
			 */
			foundslot = i;
			break;
		}
	}

	if (foundslot != -1) {
		/* We found a slot for this mondo vec, clear it */
		ittptr->ittrans_mondovec[foundslot] = 0;
	}

	mutex_exit(&ittptr->ittrans_lock);
}

int
pc_madr_add(int lboard, int rboard, int proc, uint_t madr)
{
	register int	i;
	uint_t		madr_rd, madr_off;
	uint64_t	pc_madr_addr;

	pc_madr_addr = STARFIRE_PC_MADR_ADDR(lboard, rboard, proc);

	/*
	 * First write with Presence bit disabled
	 * and then with it enabled.
	 */
	madr_off = madr & ~STARFIRE_MC_MEM_PRESENT_MASK;
	stphysio(pc_madr_addr, madr_off);

	for (i = 0; i < 20; i++) {
		madr_rd = ldphysio(pc_madr_addr);
		if (madr_off == madr_rd)
			break;
	}
	if (madr_off != madr_rd) {
		cmn_err(CE_WARN,
			"pc_madr_add: (1) failed to update "
			"PC MADR (%d, %d, %d, 0x%x)\n",
			lboard, rboard, proc, madr);
		return (-1);
	}
	if (madr == madr_off) {
		/*
		 * Caller wanted to write value out there
		 * with presence bit turned off, which is
		 * what we just completed.  So, we're finished.
		 */
		return (0);
	}
	/*
	 * Now write with Presence bit enabled.
	 */
	stphysio(pc_madr_addr, madr);

	for (i = 0; i < 20; i++) {
		madr_rd = ldphysio(pc_madr_addr);
		if (madr == madr_rd)
			break;
	}
	if (madr != madr_rd) {
		cmn_err(CE_WARN,
			"pc_madr_add: (2) failed to update "
			"PC MADR (%d, %d, %d, 0x%x)\n",
			lboard, rboard, proc, madr);
		return (-1);
	}

	return (0);
}
