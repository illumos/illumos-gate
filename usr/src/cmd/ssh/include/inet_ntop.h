/* $Id: inet_ntop.h,v 1.4 2001/08/09 00:56:53 mouring Exp $ */

#ifndef	_INET_NTOP_H
#define	_INET_NTOP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#ifndef HAVE_INET_NTOP
const char *                 
inet_ntop(int af, const void *src, char *dst, size_t size);
#endif /* !HAVE_INET_NTOP */

#ifdef __cplusplus
}
#endif

#endif /* _INET_NTOP_H */
