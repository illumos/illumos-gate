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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NSC_DEV_H
#define	_NSC_DEV_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __NSC_GEN__
Error: Illegal #include - private file.
#endif


#include <sys/nsctl/nsc_gen.h>
#include <sys/nsc_ddi.h>

/*
 * Interface to I/O module.
 */

typedef struct nsc_io_s {
	struct nsc_io_s *next;		/* Link to next I/O module */
	kcondvar_t	cv;		/* Blocking variable */
	int	id;			/* Module id */
	int	flag;			/* Flags */
	char	*name;			/* Module name */
	int	refcnt;			/* Reference count */
	int	abufcnt;		/* # of allocated anonymous buffers */
	int	pend;			/* Unregister pending */
	int	(*open)();		/* Open device */
	int	(*close)();		/* Close device */
	int	(*attach)();		/* Attach device */
	int	(*detach)();		/* Detach device */
	int	(*flush)();		/* Flush device */
	int	(*alloc_buf)();		/* Allocate buffer */
	int	(*free_buf)();		/* Free buffer */
	int	(*read)();		/* Read buffer */
	int	(*write)();		/* Write buffer */
	int	(*zero)();		/* Zero buffer */
	int	(*copy)();		/* Copy buffer between handles */
	int	(*copy_direct)();	/* Copy buffer between handle & disk */
	int	(*uncommit)();		/* Uncommit buffer */
	struct nsc_buf_s *(*alloc_h)();	/* Allocate handle */
	int	(*free_h)();		/* Free handle */
	int	(*uread)();		/* User read */
	int	(*uwrite)();		/* User write */
	int	(*trksize)();		/* Set track size */
	int	(*discard)();		/* Discard pinned data */
	int	(*sizes)();		/* Return size of cache */
	int	(*getpin)();		/* Get pinned info */
	int	(*nodehints)();		/* Return current node hints */
	int	(*partsize)();		/* Partition size */
	int	(*maxfbas)();		/* Maximum I/O size */
	int	(*control)();		/* Module control function */
	long	provide;		/* Interface provided */
} nsc_io_t;


typedef struct nsc_path_s {
	struct nsc_path_s *sp_next;	/* Link to next path */
	char	*sp_path;		/* Pathname */
	int	sp_type;		/* Open type */
	nsc_io_t	*sp_io;			/* I/O module */
	int	sp_pend;		/* Unregister pending */
} nsc_path_t;


/*
 * Note: NSC_MAXPATH currently defined here and in nsctl.h
 */
#if !defined(NSC_MAXPATH)
#define	NSC_MAXPATH	64
#endif


#define	NSC_SETVAL_MAX	32

typedef struct nsc_val_s {
	struct nsc_val_s *sv_next;	/* Link to next value */
	char	sv_name[NSC_SETVAL_MAX]; /* Name of value */
	int	sv_value;		/* Value of name */
} nsc_val_t;


typedef struct nsc_devval_s {
	struct nsc_devval_s *dv_next;		/* Next dev/val header */
	nsc_val_t 	*dv_values;		/* The values */
	char		dv_path[NSC_MAXPATH];	/* Path name of device */
	uint64_t	dv_phash;		/* Hash of pathname */
} nsc_devval_t;


/* used for ncall */
typedef struct nsc_rval_s {
	char	path[NSC_MAXPATH];	/* Path name of dev */
	char	name[NSC_SETVAL_MAX];	/* Name of value */
	int	value;			/* Value of name */
} nsc_rval_t;


extern int _nsc_maxdev;

#define	_NSC_OPEN	0x0004		/* Open in progress */
#define	_NSC_CLOSE	0x0008		/* Close in progress */
#define	_NSC_PINNED	0x0010		/* Pinned data reported */
#define	_NSC_ATTACH	0x0020		/* Available for I/O */
#define	_NSC_DETACH	0x0040		/* Detach in progress */
#define	_NSC_OWNER	0x0080		/* Owner detach in progress */


typedef struct nsc_iodev_s {
	struct nsc_iodev_s *si_next;	/* Link to next I/O device */
	struct nsc_fd_s *si_open;	/* Open file descriptors */
	kmutex_t	si_lock;	/* Lock to protect I/O chain */
	kcondvar_t	si_cv;		/* Blocking variable */
	int	si_refcnt;		/* Reference count */
	int	si_busy;		/* Callback in progress */
	int	si_pend;		/* Operation is pending */
	int	si_rpend;		/* Reserve is pending */
	int	si_avail;		/* Available for I/O */
	nsc_io_t *si_io;			/* Interface to I/O module */
	void	*si_active;		/* Active I/O chain */
	struct nsc_dev_s *si_dev;	/* Device structure */
} nsc_iodev_t;


typedef struct nsc_dev_s {
	struct nsc_dev_s *nsc_next;	/* Link to next device */
	struct nsc_fd_s *nsc_close;	/* Closed file descriptors */
	nsc_iodev_t *nsc_list;		/* Active I/O modules */
	char	*nsc_path;		/* Pathname */
	uint64_t	nsc_phash;	/* Pathname hash */
	kmutex_t	nsc_lock;	/* Lock to protect state */
	int	nsc_refcnt;		/* Reference count */
	kcondvar_t	nsc_cv;		/* Blocking variable */
	int	nsc_wait;		/* Count of waiters */
	int	nsc_pend;		/* Operation is pending */
	int	nsc_rpend;		/* Reserve is pending */
	int	nsc_drop;		/* Detach on release */
	int	nsc_reopen;		/* Doing reopen */
	nsc_devval_t *nsc_values;	/* Values - see nsc_setval() */
} nsc_dev_t;


/*
 * Storage file descriptor.
 */

typedef struct nsc_fd_s {
	struct nsc_fd_s *sf_next;	/* Link to next descriptor */
	nsc_iodev_t *sf_iodev;		/* I/O device structure */
	nsc_iodev_t *sf_owner;		/* Parent I/O device */
	nsc_dev_t *sf_dev;		/* Device structure */
	nsc_io_t *sf_aio;		/* Active I/O module */
	int	sf_avail;		/* Availability for I/O */
	int	sf_pend;		/* Operation is pending */
	int	sf_type;		/* Open type */
	int	sf_flag;		/* Open flags */
	clock_t sf_lbolt;		/* Open timestamp */
	int	sf_reopen;		/* Re-open required */
	blind_t	sf_cd;			/* Underlying I/O descriptor */
	blind_t	sf_arg;			/* Argument for callbacks */
	int	sf_reserve;		/* Device is reserved */
	int	sf_mode;		/* Type of reserve */
	void	(*sf_pinned)();		/* Callback - Data pinned */
	void	(*sf_unpinned)();	/* Callback - Data unpinned */
	int	(*sf_attach)();		/* Callback - Attach */
	int	(*sf_detach)();		/* Callback - Detach */
	int	(*sf_flush)();		/* Callback - Flush */
} nsc_fd_t;


/*
 * External definitions.
 */

extern nsc_io_t *_nsc_null_io;

#ifdef _KERNEL
extern int _nsc_open_fd(nsc_fd_t *, int);
extern int _nsc_close_fd(nsc_fd_t *, int);
extern int _nsc_detach_fd(nsc_fd_t *, int);
extern int _nsc_detach_iodev(nsc_iodev_t *, nsc_fd_t *, int);
extern int _nsc_detach_dev(nsc_dev_t *, nsc_iodev_t *, int);
extern int _nsc_call_io(long, blind_t, blind_t, blind_t);
extern int _nsc_wait_dev(nsc_dev_t *, int);
extern void _nsc_wake_dev(nsc_dev_t *, int *);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _NSC_DEV_H */
