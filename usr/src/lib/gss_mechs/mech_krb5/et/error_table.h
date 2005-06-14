
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#ifndef _ET_H

#include <errno.h>

#if defined(macintosh)
#define ET_EBUFSIZ 256
#else
#define ET_EBUFSIZ 64
#endif

struct et_list {
    struct et_list *next;
    const struct error_table FAR *table;
};

#if !defined(_MSDOS) && !defined(_WIN32) && !defined(macintosh)
extern struct et_list * _et_list;
#endif

#define	ERRCODE_RANGE	8	/* # of bits to shift table number */
#define	BITS_PER_CHAR	6	/* # bits to shift per character in name */
#define ERRCODE_MAX   0xFFFFFFFF      /* Mask for maximum error table */

extern const char FAR *error_table_name ET_P((unsigned long));
extern const char FAR *error_table_name_r ET_P((unsigned long, char FAR *));

#define _ET_H
#endif
