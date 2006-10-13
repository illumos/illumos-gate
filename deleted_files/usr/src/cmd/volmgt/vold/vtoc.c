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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * VTOC class implementation file.
 */

#include "vtoc.h"

static const int DEFAULT_SOLARIS_BASE_PARTITION = 2;

/*
 * Declarations of private methods
 */

static boolean_t
duplicates(struct vtoc *	vtocp,
	int			partition_number_1,
	int			partition_number_2);

/*
 * Definitions of public methods
 */

int
vtoc_base_partition(struct vtoc *	vtocp)
{
	/*
	 * Return the partition number of the largest partition
	 * that starts at byte 0 of the medium.
	 */

	int	base_partition;
	int	test_partition;

	/*
	 * Find the first partition that starts at byte 0 of the medium.
	 */

	test_partition = 0;
	while ((test_partition < V_NUMPAR) &&
		(vtocp->v_part[test_partition].p_start != 0)) {
		test_partition++;
	}
	base_partition = test_partition;

	/*
	 * Look for higher-numbered partitions that also start at
	 * byte 0 of the medium and are larger than the first
	 * partition that starts at byte 0.
	 */
 
	test_partition++;
	while (test_partition < V_NUMPAR) {
		if ((vtocp->v_part[test_partition].p_start == 0) &&
			(vtocp->v_part[test_partition].p_size >
			 vtocp->v_part[base_partition].p_size)) {
			base_partition = test_partition;
		}
		test_partition++;
	}

	/*
	 * If unable to find a partition starting at byte 0 of the
	 * medium, set the base partition number to -1.  Otherwise,
	 * if the default Solaris base partition is identical to
	 * the base partition found using the algorithm above, set
	 * the base partition number to the default Solaris base
	 * partition number.
	 */

	if (base_partition == V_NUMPAR) {
		base_partition = -1;
	} else if (duplicates(vtocp,
			base_partition,
			DEFAULT_SOLARIS_BASE_PARTITION) == B_TRUE) {
		base_partition = DEFAULT_SOLARIS_BASE_PARTITION;
	}
	return (base_partition);
}

u_char
vtoc_number_of_partitions(struct vtoc *	vtocp)
{
	u_char	number_of_partitions;
	int	partition_number;
	int	possible_duplicate;

	number_of_partitions = 0;
	partition_number = 0;
	while (partition_number < V_NUMPAR) {
		if (vtocp->v_part[partition_number].p_size > 0) {
			number_of_partitions++;
		}
		partition_number++;
	}
	/*
	 * Subtract duplicates
	 */
	partition_number = 0;
	while (partition_number < V_NUMPAR) {
		if (vtocp->v_part[partition_number].p_size > 0) {
			possible_duplicate = partition_number + 1;
			while (possible_duplicate < V_NUMPAR) {
				if (duplicates(vtocp,
					partition_number,
					possible_duplicate) == B_TRUE) {

					number_of_partitions--;
				}
				possible_duplicate++;
			}
		}
		partition_number++;
	}
	return (number_of_partitions);
}

u_long
vtoc_partition_mask(struct vtoc *	vtocp)
{
	u_long	partition_mask;
	int	partition_number;
	int	possible_duplicate;

	partition_mask = (u_long)0;
	partition_number = 0;
	while (partition_number < V_NUMPAR) {
		if (vtocp->v_part[partition_number].p_size > 0) {
			partition_mask |= (u_long) 1 << partition_number;
		}
		partition_number++;
	}
	/*
	 * Remove duplicates
	 */
	partition_number = 0;
	while (partition_number < V_NUMPAR) {
		if (vtocp->v_part[partition_number].p_size > 0) {
			possible_duplicate = partition_number + 1;
			while (possible_duplicate < V_NUMPAR) {
				if (duplicates(vtocp,
					partition_number,
					possible_duplicate) == B_TRUE) {

					partition_mask &= ~((u_long) 1 <<
						possible_duplicate);
				}
				possible_duplicate++;
			}
		}
		partition_number++;
	}
	return (partition_mask);
}

off_t
vtoc_partition_offset(struct vtoc *	vtocp,
			int		partition_number)
{
	return ((off_t) (vtocp->v_sectorsz *
		vtocp->v_part[partition_number].p_start));

}

boolean_t
vtoc_valid(struct vtoc *	vtocp)
{
	if (vtocp->v_sanity == VTOC_SANE) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

/*
 * Definitions of private methods
 */

static boolean_t
duplicates(struct vtoc *	vtocp,
	int			partition_1,
	int			partition_2)
{
	if ((vtocp->v_part[partition_1].p_start ==
		vtocp->v_part[partition_2].p_start) &&

		(vtocp->v_part[partition_1].p_size ==
			vtocp->v_part[partition_2].p_size)) {

		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}
