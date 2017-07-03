/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

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

/*
 * Extended uio_t uioa_t used for asynchronous uio.
 *
 * Note: UIOA_IOV_MAX is defined and used as it is in "fs/vncalls.c"
 *	 as there isn't a formal definition of IOV_MAX for the kernel.
 */
#define	UIOA_IOV_MAX	16

typedef struct uioa_page_s {		/* locked uio_iov state */
	int	uioa_pfncnt;		/* count of pfn_t(s) in *uioa_ppp */
	void	**uioa_ppp;		/* page_t or pfn_t arrary */
	caddr_t	uioa_base;		/* address base */
	size_t	uioa_len;		/* span length */
} uioa_page_t;

typedef struct uioa_s {
	iovec_t		*uio_iov;	/* pointer to array of iovecs */
	int		uio_iovcnt;	/* number of iovecs */
	lloff_t		_uio_offset;	/* file offset */
	uio_seg_t	uio_segflg;	/* address space (kernel or user) */
	uint16_t	uio_fmode;	/* file mode flags */
	uint16_t	uio_extflg;	/* extended flags */
	lloff_t		_uio_limit;	/* u-limit (maximum byte offset) */
	ssize_t		uio_resid;	/* residual count */
	/*
	 * uioa extended members.
	 */
	uint32_t	uioa_state;	/* state of asynch i/o */
	ssize_t		uioa_mbytes;	/* bytes that have been uioamove()ed */
	uioa_page_t	*uioa_lcur;	/* pointer into uioa_locked[] */
	void		**uioa_lppp;	/* pointer into lcur->uioa_ppp[] */
	void		*uioa_hwst[4];	/* opaque hardware state */
	uioa_page_t	uioa_locked[UIOA_IOV_MAX]; /* Per iov locked pages */
} uioa_t;

/*
 * uio extensions
 *
 * PSARC 2009/478: Copy Reduction Interfaces
 */
typedef enum xuio_type {
	UIOTYPE_ASYNCIO,
	UIOTYPE_ZEROCOPY
} xuio_type_t;

typedef struct xuio {
	uio_t xu_uio;		/* Embedded UIO structure */

	/* Extended uio fields */
	enum xuio_type xu_type;	/* What kind of uio structure? */
	union {
		/* Async I/O Support, intend to replace uioa_t. */
		struct {
			uint32_t xu_a_state;	/* state of async i/o */
			/* bytes that have been uioamove()ed */
			ssize_t xu_a_mbytes;
			uioa_page_t *xu_a_lcur;	/* pointer into uioa_locked[] */
			/* pointer into lcur->uioa_ppp[] */
			void **xu_a_lppp;
			void *xu_a_hwst[4];	/* opaque hardware state */
			/* Per iov locked pages */
			uioa_page_t xu_a_locked[UIOA_IOV_MAX];
		} xu_aio;

		/*
		 * Copy Reduction Support -- facilate loaning / returning of
		 * filesystem cache buffers.
		 */
		struct {
			int xu_zc_rw;	/* read or write buffer */
			void *xu_zc_priv;	/* fs specific */
		} xu_zc;
	} xu_ext;
} xuio_t;

#define	XUIO_XUZC_PRIV(xuio)    xuio->xu_ext.xu_zc.xu_zc_priv
#define	XUIO_XUZC_RW(xuio)	xuio->xu_ext.xu_zc.xu_zc_rw

#define	UIOA_ALLOC	0x0001		/* allocated but not yet initialized */
#define	UIOA_INIT	0x0002		/* initialized but not yet enabled */
#define	UIOA_ENABLED	0x0004		/* enabled, asynch i/o active */
#define	UIOA_FINI	0x0008		/* finished waiting for uioafini() */

#define	UIOA_CLR	(~0x000F)	/* clear mutually exclusive bits */

#define	UIOA_POLL	0x0010		/* need dcopy_poll() */

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
 *
 * NOTE: This flag is also used by uioasync callers to pass an extended
 * uio_t (uioa_t), to uioasync enabled consumers. Unlike above all
 * consumers of a uioa_t require the uio_extflg to be initialized.
 */
#define	UIO_COPY_DEFAULT	0x0000	/* no special options to copy */
#define	UIO_COPY_CACHED		0x0001	/* copy should not bypass caches */

#define	UIO_ASYNC		0x0002	/* uio_t is really a uioa_t */
#define	UIO_XUIO		0x0004	/* Structure is xuio_t */

/*
 * Global uioasync capability shadow state.
 */
typedef struct uioasync_s {
	boolean_t	enabled;	/* Is uioasync enabled? */
	size_t		mincnt;		/* Minimum byte count for use of */
} uioasync_t;

#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

int	uiomove(void *, size_t, enum uio_rw, uio_t *);
void	uio_prefaultpages(ssize_t, uio_t *);
int	uiocopy(void *, size_t, enum uio_rw, uio_t *, size_t *);
int	ureadc(int, uio_t *);	/* should be errno_t in future */
int	uwritec(struct uio *);
void	uioskip(uio_t *, size_t);
int	uiodup(uio_t *, uio_t *, iovec_t *, int);

int	uioamove(void *, size_t, enum uio_rw, uioa_t *);
int	uioainit(uio_t *, uioa_t *);
int	uioafini(uio_t *, uioa_t *);
extern	uioasync_t uioasync;

#else	/* defined(_KERNEL) */

extern ssize_t readv(int, const struct iovec *, int);
extern ssize_t writev(int, const struct iovec *, int);

/*
 * When in the large file compilation environment,
 * map preadv/pwritev to their 64 bit offset versions
 */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	preadv	preadv64
#pragma	redefine_extname	pwritev	pwritev64
#else /* __PRAGMA_REDEFINE_EXTNAME */
#define	preadv	preadv64
#define	pwritev	pwritev64
#endif /* __PRAGMA_REDEFINE_EXTNAME */
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */

/* In the LP64 compilation environment, the APIs are already large file */
#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef  __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	preadv64	preadv
#pragma	redefine_extname	pwritev64	pwritev
#else   /* __PRAGMA_REDEFINE_EXTNAME */
#define	preadv64	preadv
#define	pwritev64	pwritev
#endif  /* __PRAGMA_REDEFINE_EXTNAME */
#endif  /* _LP64 && _LARGEFILE64_SOURCE */

extern ssize_t preadv(int, const struct iovec *, int, off_t);
extern ssize_t pwritev(int, const struct iovec *, int, off_t);

/*
 * preadv64 and pwritev64 should be defined when:
 * - Using the transitional compilation environment, and not
 *     the large file compilation environment.
 */
#if defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	!defined(__PRAGMA_REDEFINE_EXTNAME))
extern ssize_t preadv64(int, const struct iovec *, int, off64_t);
extern ssize_t pwritev64(int, const struct iovec *, int, off64_t);
#endif /* _LARGEFILE64_SOURCE */

#endif	/* defined(_KERNEL) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_UIO_H */
