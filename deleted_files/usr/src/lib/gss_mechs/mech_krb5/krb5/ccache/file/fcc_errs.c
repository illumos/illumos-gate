#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_errs.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * error code interpretation routine
 */



#include "fcc.h"

/*ARGSUSED*/
krb5_error_code
krb5_fcc_interpret(context, errnum)
   krb5_context context;
int errnum;
{
    register krb5_error_code retval;
    switch (errnum) {
    case ENOENT:
	retval = KRB5_FCC_NOFILE;
	break;
    case EPERM:
    case EACCES:
    case EISDIR:
    case ENOTDIR:
#ifdef ELOOP
    case ELOOP:				/* XXX */
#endif
#ifdef ETXTBSY
    case ETXTBSY:
#endif
    case EBUSY:
    case EROFS:
	retval = KRB5_FCC_PERM;
	break;
    case EINVAL:
    case EEXIST:			/* XXX */
    case EFAULT:
    case EBADF:
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
#endif
#ifdef EWOULDBLOCK
    case EWOULDBLOCK:
#endif
	retval = KRB5_FCC_INTERNAL;
	break;
#ifdef EDQUOT
    case EDQUOT:
#endif
    case ENOSPC:
    case EIO:
    case ENFILE:
    case EMFILE:
    case ENXIO:
    default:
	retval = KRB5_CC_IO;		/* XXX */
    }
    return retval;
}
