/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014-2016 PALO, Richard.
 */

#ifndef _SYS_NULL_H
#define	_SYS_NULL_H

#ifndef	NULL

#if defined(_LP64)
#define	NULL	0L
#else
#define	NULL	0
#endif

#endif	/* NULL */

#endif	/* _SYS_NULL_H */
