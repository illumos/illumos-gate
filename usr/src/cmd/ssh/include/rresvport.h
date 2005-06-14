/* $Id: rresvport.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_RRESVPORT_H
#define	_RRESVPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#ifndef HAVE_RRESVPORT_AF
int rresvport_af(int *alport, sa_family_t af);
#endif /* !HAVE_RRESVPORT_AF */

#ifdef __cplusplus
}
#endif

#endif /* _RRESVPORT_H */
