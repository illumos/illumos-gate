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
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * Common definitions
 */

#ifndef _MAN_H_
#define	_MAN_H_

#define	CONFIG		"man.cf"
#define	DEFMANDIR	"/usr/share/man"
#define	INDENT		24
#define	PAGER		"less -ins"
#define	WHATIS		"whatis"
#define	PRECONV		"/usr/lib/mandoc_preconv"

#define	LINE_ALLOC	4096
#define	MAXDIRS		128
#define	MAXTOKENS	64

#define	DPRINTF		if (debug) \
				(void) printf

void	mwpath(char *path);

#endif	/* _MAN_H_ */
