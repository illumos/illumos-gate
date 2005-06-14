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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RSMLIB_IN_H
#define	_RSMLIB_IN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#define	LOOPBACK "loopback"
#define	DEVRSM "/dev/rsm"
#define	RSMSEGIDFILE	"/etc/rsm/rsm.segmentid"
#define	RSMSEG_RESERVED	"reserved"

#define	RSM_IMPORT_SEG	1
#define	RSM_EXPORT_SEG	2

#define	RSM_MAX_HANDLE_DVMA	0x2000

/* This is the default barrier implementation structure */
typedef struct {
	rsmseg_handle_t	*rsmgenbar_seg;
	uint16_t	rsmgenbar_gen;
	rsm_barrier_t	*rsmgenbar_data;
}rsmgenbar_handle_t;

#define	RSM_MAX_BUCKETS		128 /* # buckets in the hash table */
#define	RSM_POLLFD_PER_CHUNK	16  /* # pollfd in each chunk */

/* least significant 3 bytes of the fd should be unique enough */
#define	RSM_POLLFD_HASH(fd)	(((fd) ^ ((fd) >> 8) ^ ((fd) >> 16)) % \
		RSM_MAX_BUCKETS)

/*
 * pollfd_table maintains a mapping from fd to resource number. It also
 * provides a mechanism to check if a given fd corresponds to an rsmapi
 * segment. Entries get added to this table as a result of
 * rsm_memseg_get_pollfd and removed as a result of rsm_memseg_release_pollfd.
 */
typedef struct {
	int		fd;
	minor_t		segrnum;
}rsm_pollfd_element_t;

typedef struct rsm_pollfd_chunk {
	struct rsm_pollfd_chunk	*next;
	int			nfree;
	rsm_pollfd_element_t	fdarray[RSM_POLLFD_PER_CHUNK];
} rsm_pollfd_chunk_t;

typedef struct {
	mutex_t			lock;
	rsm_pollfd_chunk_t	*buckets[RSM_MAX_BUCKETS];
} rsm_pollfd_table_t;

/*
 * The following macros are defined only if the DEBUG flag is enabled
 * The macro makes use of category and level values defined in rsm.h
 * and the dbg_printf function defined in rsmlib.c (defined as an
 * extern below)
 */
#ifdef	DEBUG
#define	TRACELOG "/tmp/librsm.log"
#define	DBPRINTF(msg) dbg_printf msg
#else
#define	TRACELOG
#define	DBPRINTF(msg)
#endif

extern void dbg_printf(int category, int level, char *fmt, ...);

typedef int (*rsm_attach_entry_t)(int, rsm_segops_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _RSMLIB_IN_H */
