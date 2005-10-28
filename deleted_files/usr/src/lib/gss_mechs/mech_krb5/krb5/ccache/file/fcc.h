#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains constant and function declarations used in the
 * file-based credential cache routines.
 */

#ifndef __KRB5_FILE_CCACHE__
#define __KRB5_FILE_CCACHE__

#define NEED_LOWLEVEL_IO
#include "k5-int.h"
#include "fcc-proto.h"
#include <stdio.h>

#define KRB5_OK 0

#define KRB5_FCC_MAXLEN 100

/*
 * FCC version 2 contains type information for principals.  FCC
 * version 1 does not.
 *  
 * FCC version 3 contains keyblock encryption type information, and is
 * architecture independent.  Previous versions are not.
 *
 * The code will accept version 1, 2, and 3 ccaches, and depending 
 * what KRB5_FCC_DEFAULT_FVNO is set to, it will create version 1, 2,
 * or 3 FCC caches.
 *
 * The default credentials cache should be type 3 for now (see
 * init_ctx.c).
 */

#define KRB5_FCC_FVNO_1 0x0501		/* krb5 v5, fcc v1 */
#define KRB5_FCC_FVNO_2 0x0502		/* krb5 v5, fcc v2 */
#define KRB5_FCC_FVNO_3 0x0503		/* krb5 v5, fcc v3 */
#define KRB5_FCC_FVNO_4 0x0504		/* krb5 v5, fcc v4 */

#define	FCC_OPEN_AND_ERASE	1
#define	FCC_OPEN_RDWR		2
#define	FCC_OPEN_RDONLY		3
#define	FCC_OPEN_AND_ERASE_NOUNLINK	255	/* SUNW */

/* Credential file header tags.
 * The header tags are constructed as:
 *	krb5_ui_2	tag
 *	krb5_ui_2	len
 *	krb5_octet	data[len]
 * This format allows for older versions of the fcc processing code to skip
 * past unrecognized tag formats.
 */
#define FCC_TAG_DELTATIME	1

#ifndef TKT_ROOT
#ifdef MSDOS_FILESYSTEM
#define TKT_ROOT "\\tkt"
#else
#define TKT_ROOT "/tmp/tkt"
#endif
#endif

/* macros to make checking flags easier */
#define OPENCLOSE(id) (((krb5_fcc_data *)id->data)->flags & KRB5_TC_OPENCLOSE)

typedef struct _krb5_fcc_data {
     char *filename;
     int fd;
     krb5_flags flags;
     int mode;				/* needed for locking code */
     int version;	      		/* version number of the file */
} krb5_fcc_data;

/* An off_t can be arbitrarily complex */
typedef struct _krb5_fcc_cursor {
     off_t pos;
} krb5_fcc_cursor;

#define MAYBE_OPEN(CONTEXT, ID, MODE) \
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_open_ret = krb5_fcc_open_file (CONTEXT,ID,MODE);	\
	if (maybe_open_ret) return maybe_open_ret; } }

#define MAYBE_CLOSE(CONTEXT, ID, RET) \
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_close_ret = krb5_fcc_close_file (CONTEXT,ID);	\
	if (!(RET)) RET = maybe_close_ret; } }

#define MAYBE_CLOSE_IGNORE(CONTEXT, ID) \
{									\
    if (OPENCLOSE (ID)) {						\
	(void) krb5_fcc_close_file (CONTEXT,ID); } }

/* DO NOT ADD ANYTHING AFTER THIS #endif */
#endif /* __KRB5_FILE_CCACHE__ */
