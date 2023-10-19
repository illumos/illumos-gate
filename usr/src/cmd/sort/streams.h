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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SORT_STREAMS_H
#define	_SORT_STREAMS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fields.h"
#include "types.h"
#include "streams_array.h"
#include "streams_common.h"
#include "streams_mmap.h"
#include "streams_stdio.h"
#include "streams_wide.h"
#include "utility.h"

#define	ST_MEM_FILLED	0x0	/* no memory left; proceed to internal sort */
#define	ST_MEM_AVAIL	0x1	/* memory left for sort; take add'l input */

#define	ST_NOCACHE	0x0	/* write sorted array to temporary file */
#define	ST_CACHE	0x1	/* keep sorted array in memory */
#define	ST_OPEN		0x2	/* create open temporary file */
#define	ST_WIDE		0x4	/* write multibyte chars to temporary file */

extern void stream_add_file_to_chain(stream_t **, char *);
extern void stream_clear(stream_t *);
extern void stream_close_all_previous(stream_t *);
extern uint_t stream_count_chain(stream_t *);
extern int stream_insert(sort_t *, stream_t *, stream_t *);
extern stream_t *stream_new(int);
extern int stream_open_for_read(sort_t *, stream_t *);
extern void stream_push_to_chain(stream_t **, stream_t *);
extern stream_t *stream_push_to_temporary(stream_t **, stream_t *, int);
extern void stream_set_size(stream_t *, size_t);
extern void stream_stat_chain(stream_t *);
extern void stream_swap_buffer(stream_t *, char **, size_t *);
extern void stream_unlink_temporary(stream_t *streamp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SORT_STREAMS_H */
