/* $Id: fake-getnameinfo.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_FAKE_GETNAMEINFO_H
#define	_FAKE_GETNAMEINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa, size_t salen, char *host, 
                size_t hostlen, char *serv, size_t servlen, int flags);
#endif /* !HAVE_GETNAMEINFO */

#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif /* !NI_MAXSERV */
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif /* !NI_MAXHOST */

#ifdef __cplusplus
}
#endif

#endif /* _FAKE_GETNAMEINFO_H */
