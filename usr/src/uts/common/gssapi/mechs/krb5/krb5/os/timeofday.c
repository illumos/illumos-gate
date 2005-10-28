/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/os/timeofday.c
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * libos: krb5_timeofday function for BSD 4.3 
 */


#include <k5-int.h>

#ifdef	_KERNEL
#include <sys/time.h>
#else
#include <time.h>
#include <errno.h>
#endif

#ifdef POSIX_TYPES
#define timetype time_t
#else
#define timetype long
#endif

#ifndef HAVE_ERRNO
extern int errno;
#endif

krb5_error_code KRB5_CALLCONV 
krb5_timeofday(krb5_context context, register krb5_int32 *timeret)
{
    krb5_os_context os_ctx = context->os_context;
    krb5_int32 tval;

    if (os_ctx->os_flags & KRB5_OS_TOFFSET_TIME) {
	    *timeret = os_ctx->time_offset;
	    return 0;
    }
    {
	krb5_int32 usecs;
	krb5_error_code	kret;

	if (kret = krb5_crypto_us_timeofday(&tval,
			 &usecs))
		return kret;
    }
    if (tval == (timetype) -1)
#ifdef _KERNEL
	return 1;
#else
	return (krb5_error_code) errno;
#endif
    if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)
	    tval += os_ctx->time_offset;
    *timeret = tval;
  	
    return 0;
}
