/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SUNW_PORT_BEFORE_H
#define	_SUNW_PORT_BEFORE_H

#ifdef SUNW_OPTIONS
#include <conf/sunoptions.h>
#endif

/* version-specific defines */
#include <os_version.h>
#if (OS_MAJOR == 5 && OS_MINOR < 6)
#ifndef SOLARIS_BITTYPES
#define	NEED_SOLARIS_BITTYPES 1
#endif
#endif

#if (OS_MAJOR == 5 && OS_MINOR < 5)
#undef HAS_PTHREADS
#else
#define	HAS_PTHREADS
#endif

#if defined(HAS_PTHREADS) && defined(_REENTRANT)
#define DO_PTHREADS
#endif

/*
 * need these if we are using public versions of nameser.h, resolv.h, and
 * inet.h
 */
#include <sys/param.h>
#if (!defined(BSD)) || (BSD < 199306)
#include <sys/bitypes.h>
#else
#include <sys/types.h>
#endif
#include <sys/cdefs.h>

#endif	/* _SUNW_PORT_BEFORE_H */
