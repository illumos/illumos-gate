/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_WINLOCKIO_H
#define	_SYS_WINLOCKIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ioccom.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Structure for allocating lock contexts.
 * The page number portion of sy_ident is the offset for mmap(2).
 * The page offset portion of sy_ident is the byte-offset relative to
 * the start of the page returned by mmap(2) and should added to it.
 */

struct	winlockalloc {
	uint_t	sy_key;		/* user-provided key, if any */
	uint_t	sy_ident;	/* system-provided identification */
};

/*
 * Structure for getting and setting lock timeouts or NOTIMEOUT flag
 */

struct	winlocktimeout {
	uint_t	sy_ident;	/* system-provided identification */
	uint_t	sy_timeout;	/* timeout value in seconds */
	int	sy_flags;	/* Flags for lock context - see defs below */
};

#define	WIOC	('L'<<8)


#define	WINLOCKALLOC		(WIOC|0)
#define	WINLOCKFREE		(WIOC|1)
#define	WINLOCKSETTIMEOUT	(WIOC|2)
#define	WINLOCKGETTIMEOUT	(WIOC|3)
#define	WINLOCKDUMP		(WIOC|4)

#ifndef GRABPAGEALLOC
#include <sys/fbio.h>		/* defines GRAB* ioctls */
#endif

/* flag bits */
#define	SY_NOTIMEOUT	0x1	/* This client never times out */

#ifdef	_KERNEL

#define	UFLAGS		0x00ff	/* flags usable by users */
#define	KFLAGS		0xff00	/* flags used by driver implementation */
#define	TRASHPAGE	0x0400	/* process has unlock mapping to trashpage */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_WINLOCKIO_H */
