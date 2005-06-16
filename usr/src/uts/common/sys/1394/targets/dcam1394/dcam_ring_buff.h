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

#ifndef _SYS_1394_TARGETS_DCAM1394_RINGBUFF_H
#define	_SYS_1394_TARGETS_DCAM1394_RINGBUFF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/modctl.h>
#include <sys/ksynch.h>
#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/1394/ixl1394.h>
#include <sys/1394/t1394.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_NUM_READ_PTRS	1

ring_buff_t	*ring_buff_create(dcam_state_t *softc_p, size_t num_buffs,
		    size_t buff_num_bytes);
int	ring_buff_free(dcam_state_t *softc_p, ring_buff_t *ring_buff_p);
int	ring_buff_read_ptr_add(ring_buff_t *ring_buff_p);
int	ring_buff_read_ptr_remove(ring_buff_t *ring_buff_p, int read_ptr_id);
buff_info_t	*ring_buff_read_ptr_get(ring_buff_t *ring_buff_p,
		    int read_ptr_id);
void	ring_buff_read_ptr_incr(ring_buff_t *ring_buff_p, int read_ptr_id);
int	ring_buff_read_ptr_pos_get(ring_buff_t *ring_buff_p, int read_ptr_id);
int	ring_buff_write_ptr_pos_get(ring_buff_t *ring_buff_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_DCAM1394_RINGBUFF_H */
