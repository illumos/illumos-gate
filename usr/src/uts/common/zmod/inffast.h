/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * inffast.h -- header to use inffast.c
 * Copyright (C) 1995-1998 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h 
 */

#ifndef	_INFFAST_H
#define	_INFFAST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int inflate_fast(uInt, uInt, inflate_huft *, inflate_huft *,
    inflate_blocks_statef *, z_streamp);

#ifdef	__cplusplus
}
#endif

#endif	/* _INFFAST_H */
