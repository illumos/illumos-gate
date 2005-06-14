/* $Id: getopt.h,v 1.4 2001/09/18 05:05:21 djm Exp $ */

#ifndef	_GETOPT_H
#define	_GETOPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#if !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

int BSDgetopt(int argc, char * const *argv, const char *opts);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _GETOPT_H */
