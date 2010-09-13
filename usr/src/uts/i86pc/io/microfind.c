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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/dl.h>
#include <sys/param.h>
#include <sys/pit.h>
#include <sys/inline.h>
#include <sys/machlock.h>
#include <sys/avintr.h>
#include <sys/smp_impldefs.h>
#include <sys/archsystm.h>
#include <sys/systm.h>
#include <sys/machsystm.h>

#define	PIT_COUNTDOWN	(PIT_READMODE | PIT_NDIVMODE)
#define	MICROCOUNT	0x2000

/*
 * Loop count for 10 microsecond wait.  MUST be initialized for those who
 * insist on calling "tenmicrosec" before the clock has been initialized.
 */
unsigned int microdata = 50;

void
microfind(void)
{
	uint64_t max, count = MICROCOUNT;

	/*
	 * The algorithm tries to guess a loop count for tenmicrosec such
	 * that found will be 0xf000 PIT counts, but because it is only a
	 * rough guess there is no guarantee that tenmicrosec will take
	 * exactly 0xf000 PIT counts. min is set initially to 0xe000 and
	 * represents the number of PIT counts that must elapse in
	 * tenmicrosec for microfind to calculate the correct loop count for
	 * tenmicrosec. The algorith will successively set count to better
	 * approximations until the number of PIT counts elapsed are greater
	 * than min. Ideally the first guess should be correct, but as cpu's
	 * become faster MICROCOUNT may have to be increased to ensure
	 * that the first guess for count is correct. There is no harm
	 * leaving MICRCOUNT at 0x2000, the results will be correct, it just
	 * may take longer to calculate the correct value for the loop
	 * count used by tenmicrosec. In some cases min may be reset as the
	 * algorithm progresses in order to facilitate faster cpu's.
	 */
	unsigned long found, min = 0xe000;
	ulong_t s;
	unsigned char status;

	s = clear_int_flag();		/* disable interrupts */

	/*CONSTCOND*/
	while (1) {

		/*
		 * microdata is the loop count used in tenmicrosec. The first
		 * time around microdata is set to 1 to make tenmicrosec
		 * return quickly. The purpose of this while loop is to
		 * warm the cache for the next time around when the number
		 * of PIT counts are measured.
		 */
		microdata = 1;

		/*CONSTCOND*/
		while (1) {
			/* Put counter 0 in mode 0 */
			outb(PITCTL_PORT, PIT_LOADMODE);
			/* output a count of -1 to counter 0 */
			outb(PITCTR0_PORT, 0xff);
			outb(PITCTR0_PORT, 0xff);
			tenmicrosec();

			/* READ BACK counter 0 to latch status and count */
			outb(PITCTL_PORT, PIT_READBACK|PIT_READBACKC0);

			/* Read status of counter 0 */
			status = inb(PITCTR0_PORT);

			/* Read the value left in the counter */
			found = inb(PITCTR0_PORT) | (inb(PITCTR0_PORT) << 8);

			if (microdata != 1)
				break;

			microdata = count;
		}

		/* verify that the counter began the count-down */
		if (status & (1 << PITSTAT_NULLCNT)) {
			/* microdata is too small */
			count = count << 1;

			/*
			 * If the cpu is so fast that it cannot load the
			 * counting element of the PIT with a very large
			 * value for the loop used in tenmicrosec, then
			 * the algorithm will not work for this cpu.
			 * It is very unlikely there will ever be such
			 * an x86.
			 */
			if (count > 0x100000000)
				panic("microfind: cpu is too fast");

			continue;
		}

		/* verify that the counter did not wrap around */
		if (status & (1 << PITSTAT_OUTPUT)) {
			/*
			 * microdata is too large. Since there are counts
			 * that would have been appropriate for the PIT
			 * not to wrap on even a lowly AT, count will never
			 * decrease to 1.
			 */
			count = count >> 1;
			continue;
		}

		/* mode 0 is an n + 1 counter */
		found = 0x10000 - found;
		if (found > min)
			break;

		/* verify that the cpu is slow enough to count to 0xf000 */
		count *= 0xf000;
		max = 0x100000001 * found;

		/*
		 * It is possible that at some point cpu's will become
		 * sufficiently fast such that the PIT will not be able to
		 * count to 0xf000 within the maximum loop count used in
		 * tenmicrosec. In that case the loop count in tenmicrosec
		 * may be set to the maximum value because it is unlikely
		 * that the cpu will be so fast that tenmicrosec with the
		 * maximum loop count will take more than ten microseconds.
		 * If the cpu is indeed too fast for the current
		 * implementation of tenmicrosec, then there is code below
		 * intended to catch that situation.
		 */
		if (count >= max) {
			/* cpu is fast, just make it count as high it can */
			count = 0x100000000;
			min = 0;
			continue;
		}

		/*
		 * Count in the neighborhood of 0xf000 next time around
		 * There is no risk of dividing by zero since found is in the
		 * range of 0x1 to 0x1000.
		 */
		count = count / found;
	}

	/*
	 * Formula for delaycount is :
	 *  (loopcount * timer clock speed) / (counter ticks * 1000)
	 *  Note also that 1000 is for figuring out milliseconds
	 */
	count *= PIT_HZ;
	max = ((uint64_t)found) * 100000;
	count = count / max;	/* max is never zero */

	if (count >= 0x100000001)
		/*
		 * This cpu is too fast for the current implementation of
		 * tenmicrosec. It is unlikely such a fast x86 will exist.
		 */
		panic("microfind: cpu is too fast");

	if (count != 0)
		microdata = count;
	else
		microdata = 1;

	/* Restore timer channel 0 for BIOS use */

	/* write mode to 3, square-wave */
	outb(PITCTL_PORT, PIT_C0 | PIT_LOADMODE | PIT_SQUAREMODE);

	/* write 16 bits of 0 for initial count */
	outb(PITCTR0_PORT, 0);
	outb(PITCTR0_PORT, 0);

	restore_int_flag(s);		/* restore interrupt state */
}
