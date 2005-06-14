/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * infblock.h -- header to use infblock.c
 * Copyright (C) 1995-1998 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h 
 */

#ifndef	_INFBLOCK_H
#define	_INFBLOCK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct inflate_blocks_state;
typedef struct inflate_blocks_state inflate_blocks_statef;

extern inflate_blocks_statef *inflate_blocks_new(z_streamp, check_func, uInt);
extern int inflate_blocks(inflate_blocks_statef *, z_streamp, int);
extern void inflate_blocks_reset(inflate_blocks_statef *, z_streamp, uLongf *);
extern int inflate_blocks_free(inflate_blocks_statef *, z_streamp);
extern void inflate_set_dictionary(inflate_blocks_statef *, const Bytef *,
	uInt);
extern int inflate_blocks_sync_point(inflate_blocks_statef *);

#ifdef	__cplusplus
}
#endif

#endif	/* _INFBLOCK_H */
