/*
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_sys_uio_h
#define	_sys_uio_h

struct	iovec {
	caddr_t	iov_base;
	int	iov_len;
};

/*
 * The uio_seg define below is obsolete and is included only
 * for compatibility with previous releases.  New code should
 * use the uio_segflg field.
 */
struct	uio {
	struct	iovec *uio_iov;
	int	uio_iovcnt;
	off_t	uio_offset;
	short	uio_segflg;
#define	uio_seg	uio_segflg		/* obsolete */
	short	uio_fmode;		/* careful what you put here, the file
					 * bits that fill this are an int. */
	int	uio_resid;
};

enum	uio_rw { UIO_READ, UIO_WRITE };

/*
 * Segment flag values (should be enum).
 *
 * The UIOSEG_* defines are obsolete and are included only
 * for compatibility with previous releases.  New code should
 * use the UIO_* definitions.
 */
#define	UIO_USERSPACE	0		/* from user data space */
#define	UIO_SYSSPACE	1		/* from system space */
#define	UIO_USERISPACE	2		/* from user I space */

#define	UIOSEG_USER	0		/* obsolete */
#define	UIOSEG_KERNEL	1		/* obsolete */

#endif	/*!_sys_uio_h*/
