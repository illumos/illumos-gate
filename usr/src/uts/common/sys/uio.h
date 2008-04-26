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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_UIO_H
#define	_SYS_UIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * I/O parameter information.  A uio structure describes the I/O which
 * is to be performed by an operation.  Typically the data movement will
 * be performed by a routine such as uiomove(), which updates the uio
 * structure to reflect what was done.
 */

#if	defined(_XPG4_2)
typedef struct iovec {
	void	*iov_base;
	size_t	iov_len;
} iovec_t;
#else
typedef struct iovec {
	caddr_t	iov_base;
#if defined(_LP64)
	size_t	iov_len;
#else
	long	iov_len;
#endif
} iovec_t;
#endif	/* defined(_XPG4_2) */

#if defined(_SYSCALL32)

/* Kernel's view of user ILP32 iovec struct */

typedef	struct iovec32 {
	caddr32_t	iov_base;
	int32_t		iov_len;
} iovec32_t;

#endif	/* _SYSCALL32 */

#if 	!defined(_XPG4_2) || defined(__EXTENSIONS__)
/*
 * Segment flag values.
 */
typedef enum uio_seg { UIO_USERSPACE, UIO_SYSSPACE, UIO_USERISPACE } uio_seg_t;

typedef struct uio {
	iovec_t		*uio_iov;	/* pointer to array of iovecs */
	int		uio_iovcnt;	/* number of iovecs */
	lloff_t		_uio_offset;	/* file offset */
	uio_seg_t	uio_segflg;	/* address space (kernel or user) */
	uint16_t	uio_fmode;	/* file mode flags */
	uint16_t	uio_extflg;	/* extended flags */
	lloff_t		_uio_limit;	/* u-limit (maximum byte offset) */
	ssize_t		uio_resid;	/* residual count */
} uio_t;

#define	uio_loffset	_uio_offset._f
#if !defined(_LP64)
#define	uio_offset	_uio_offset._p._l
#else
#define	uio_offset	uio_loffset
#endif

#define	uio_llimit	_uio_limit._f
#if !defined(_LP64)
#define	uio_limit	_uio_limit._p._l
#else
#define	uio_limit	uio_llimit
#endif

/*
 * I/O direction.
 */
typedef enum uio_rw { UIO_READ, UIO_WRITE } uio_rw_t;

/*
 * uio_extflg: extended flags
 *
 * NOTE: This flag will be used in uiomove to determine if non-temporal
 * access, ie, access bypassing caches, should be used.  Filesystems that
 * don't initialize this field could experience suboptimal performance due to
 * the random data the field contains.
 */
#define	UIO_COPY_DEFAULT	0x0000	/* no special options to copy */
#define	UIO_COPY_CACHED		0x0001	/* copy should not bypass caches */

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#if	defined(_KERNEL)

int	uiomove(void *, size_t, enum uio_rw, uio_t *);
int	ureadc(int, uio_t *);	/* should be errno_t in future */
int	uwritec(struct uio *);
void	uioskip(uio_t *, size_t);
int	uiodup(uio_t *, uio_t *, iovec_t *, int);

#else	/* defined(_KERNEL) */

#if 	defined(__STDC__)

extern ssize_t readv(int, const struct iovec *, int);
extern ssize_t writev(int, const struct iovec *, int);

#else	/* defined(__STDC__) */

extern ssize_t readv();
extern ssize_t writev();

#endif	/* defined(__STDC__) */

#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_UIO_H */
