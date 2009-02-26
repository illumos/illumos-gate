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
 */

#include <sys/sunddi.h>
#include <sys/cpupm.h>

/*
 * Initialize the field that will be used for reporting
 * the supported_frequencies_Hz cpu_info kstat.
 */
void
cpupm_set_supp_freqs(cpu_t *cp, int *speeds, uint_t nspeeds)
{
	char		*supp_freqs = NULL;
	char		*sfptr;
	uint64_t	*hzspeeds;
	int		i;
	int		j;
#define	UINT64_MAX_STRING (sizeof ("18446744073709551615"))

	if (speeds == NULL) {
		cpu_set_supp_freqs(cp, supp_freqs);
		return;
	}

	hzspeeds = kmem_zalloc(nspeeds * sizeof (uint64_t), KM_SLEEP);
	for (i = nspeeds - 1, j = 0; i >= 0; i--, j++) {
		hzspeeds[i] = CPUPM_SPEED_HZ(cp->cpu_type_info.pi_clock,
		    speeds[j]);
	}

	supp_freqs = kmem_zalloc((UINT64_MAX_STRING * nspeeds), KM_SLEEP);
	sfptr = supp_freqs;
	for (i = 0; i < nspeeds; i++) {
		if (i == nspeeds - 1) {
			(void) sprintf(sfptr, "%"PRIu64, hzspeeds[i]);
		} else {
			(void) sprintf(sfptr, "%"PRIu64":", hzspeeds[i]);
			sfptr = supp_freqs + strlen(supp_freqs);
		}
	}
	cpu_set_supp_freqs(cp, supp_freqs);
	kmem_free(supp_freqs, (UINT64_MAX_STRING * nspeeds));
	kmem_free(hzspeeds, nspeeds * sizeof (uint64_t));
}
