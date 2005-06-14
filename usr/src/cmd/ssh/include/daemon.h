/* $Id: daemon.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_DAEMON_H
#define	_DAEMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif /* !HAVE_DAEMON */

#ifdef __cplusplus
}
#endif

#endif /* _DAEMON_H */
