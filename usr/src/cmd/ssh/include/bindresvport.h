/* $Id: bindresvport.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_BINDRESVPORT_H
#define	_BINDRESVPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#ifndef HAVE_BINDRESVPORT_SA
int bindresvport_sa(int sd, struct sockaddr *sa);
#endif /* !HAVE_BINDRESVPORT_SA */

#ifdef __cplusplus
}
#endif

#endif /* _BINDRESVPORT_H */
