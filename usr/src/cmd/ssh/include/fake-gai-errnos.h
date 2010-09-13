/*
 * fake library for ssh
 *
 * This file is included in getaddrinfo.c and getnameinfo.c.
 * See getaddrinfo.c and getnameinfo.c.
 */

#ifndef	_FAKE_GAI_ERRNOS_H
#define	_FAKE_GAI_ERRNOS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


/* $Id: fake-gai-errnos.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

/* for old netdb.h */
#ifndef EAI_NODATA
#define EAI_NODATA	1
#define EAI_MEMORY	2
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FAKE_GAI_ERRNOS_H */
