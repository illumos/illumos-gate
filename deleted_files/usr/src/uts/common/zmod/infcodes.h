/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * infcodes.h -- header to use infcodes.c
 * Copyright (C) 1995-1998 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h 
 */

#ifndef	_INFCODES_H
#define	_INFCODES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct inflate_codes_state;
typedef struct inflate_codes_state inflate_codes_statef;

extern inflate_codes_statef *inflate_codes_new(uInt, uInt, inflate_huft *,
	inflate_huft *, z_streamp);

extern int inflate_codes(inflate_blocks_statef *, z_streamp, int);
extern void inflate_codes_free(inflate_codes_statef *, z_streamp);

#ifdef	__cplusplus
}
#endif

#endif	/* _INFCODES_H */
