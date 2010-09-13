/*
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	__sys_types_h
#define	__sys_types_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Basic system types.
 */

#include <sys/stdtypes.h>		/* ANSI & POSIX types */

#ifndef	_POSIX_SOURCE
#include <sys/sysmacros.h>

#define	physadr		physadr_t
#define	quad		quad_t

typedef	unsigned char	u_char;
typedef	unsigned short	u_short;
typedef	unsigned int	u_int;
typedef	unsigned long	u_long;
typedef	unsigned short	ushort;		/* System V compatibility */
typedef	unsigned int	uint;		/* System V compatibility */
#endif	/* !_POSIX_SOURCE */

typedef	struct  _physadr_t { int r[1]; } *physadr_t;
typedef	struct label_t {
	int	val[2];
} label_t;
typedef	struct	_quad_t { long val[2]; } quad_t;
typedef	long	daddr_t;
typedef	char *	caddr_t;
typedef	unsigned long	ino_t;
typedef	short	dev_t;
typedef	long	off_t;
typedef	unsigned short	uid_t;
typedef	unsigned short	gid_t;
typedef	long	key_t;
typedef	char *	addr_t;

#ifndef	_POSIX_SOURCE

#define	NBBY	8		/* number of bits in a byte */
/*
 * Select uses bit masks of file descriptors in longs.
 * These macros manipulate such bit fields (the filesystem macros use chars).
 * FD_SETSIZE may be defined by the user, but the default here
 * should be >= NOFILE (param.h).
 */
#ifndef	FD_SETSIZE
#define	FD_SETSIZE	256
#endif

typedef	long	fd_mask;
#define	NFDBITS	(sizeof (fd_mask) * NBBY)	/* bits per mask */
#ifndef	howmany
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#endif

typedef	struct fd_set {
	fd_mask	fds_bits[howmany(FD_SETSIZE, NFDBITS)];
} fd_set;


#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define	FD_ZERO(p)	bzero((char *)(p), sizeof (*(p)))

#endif	/* !_POSIX_SOURCE */
#endif	/* !__sys_types_h */
