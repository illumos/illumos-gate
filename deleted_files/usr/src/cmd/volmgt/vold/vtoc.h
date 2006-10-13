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
 */

#ifndef __VTOC_H
#define	__VTOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * VTOC class interface file.
 */

/*
 * System include files
 */

#include <sys/types.h>
#include <sys/vtoc.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int
vtoc_base_partition(struct vtoc *	vtocp);

extern u_char
vtoc_number_of_partitions(struct vtoc *	vtocp);

extern u_long
vtoc_partition_mask(struct vtoc *	vtocp);
/*
 * Returns a bit mask with a one in each bit position that
 * corresponds to a slice or partition that occupies actual
 * space on the medium.  Bit 0 is the least significant bit
 * of the mask and represents slice or partition 0.
 */

extern off_t
vtoc_partition_offset(struct vtoc *	vtocp,
			int		partition_number);
/*
 * Returns the byte offset of the start of partition
 * "partition_number" from the start of the medium.
 */

extern boolean_t
vtoc_valid(struct vtoc *	vtocp);

#ifdef __cplusplus
}
#endif

#endif /* __VTOC_H */
