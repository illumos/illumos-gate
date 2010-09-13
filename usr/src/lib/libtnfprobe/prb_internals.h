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
 *      Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _PRB_INTERNALS_H
#define	_PRB_INTERNALS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Notes:
 *
 * There is a memseg statically allocated in libtnfprobe.  This memory is
 * consumed by the internal and external probe control fucntions for
 * initial_final blocks, and compositions.
 *
 * There is no mechanism for freeing this memory; it is leaked.  This is
 * because the overhead involved to protect uses of old memory is too
 * high for probes.
 *
 * The target program internally allocates memory from the bottom edge of
 * the segment, and the external program allocates from the high edge of
 * the segment.
 *
 * The i_reqsz field is set by the internal memory allocation routine
 * while it is allocating.  If the external process happens to freeze the
 * target process while it is in the middle of an internal allocation the
 * i_reqsz field allows the external process to be extra conservative in
 * avoiding a memory collision.
 */

/*
 * Typedefs
 */

typedef struct tnf_memseg
{
    char *	min_p;		/* points to min free byte */
    char *	max_p;		/* points past max free byte */

    mutex_t	i_lock;		/* internal sync lock */
    size_t	i_reqsz;	/* internal request size */

} tnf_memseg_t;


/*
 * Declarations
 */

char *		__tnf_probe_alloc(size_t size);

#ifdef __cplusplus
}
#endif

#endif /* _PRB_INTERNALS_H */
