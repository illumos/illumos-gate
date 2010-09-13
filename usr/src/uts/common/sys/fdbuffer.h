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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_FDBUFFER_H
#define	_SYS_FDBUFFER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <vm/page.h>
#include <sys/buf.h>

typedef enum {
	FDB_PAGEIO,		/* fdbuffer is a page buffer */
	FDB_VADDR		/* fdbuffer is a address buffer */
} fdb_type_t;

#define	FDB_READ	0x01		/* fdbuffer is readable */
#define	FDB_WRITE	0x02		/* fdbuffer is asked for write */
#define	FDB_DONE	0x04		/* fdbuffer buffer io done */
#define	FDB_ERROR	0x08		/* fdbuffer in error state */
#define	FDB_ASYNC	0x10		/* fdbuffer using async i/o requests */
#define	FDB_SYNC	0x20		/* fdbuffer using direct i/o requests */
#define	FDB_ICALLBACK	0x40		/* fdbuffer immediate call back */
#define	FDB_ZEROHOLE	0x80		/* fdbuffer auto-zero holes */

typedef struct fdb_holes {
	struct fdb_holes *next_hole;
	u_offset_t off;		/* start offset for this hole */
	size_t len;		/* length of this hole */
} fdb_holes_t;

struct fdbuffer;

typedef void (*fdb_iodone_t)(struct fdbuffer *fdbuf, void *kargp, buf_t *bp);


/*
 * Implementation notes in the fdbuffer structure members:
 *
 * fd_state: The state variable carries four distinct types of information
 *           it could probably be a bit field as such.
 *
 *	READ/WRITE:
 *		This information is stored in fdbuffer at the time the
 *		The buffer is created and is used for sanity check in
 *		subsequent calls to fdb_iosetup(). This information
 *		persists for the entire life of the buffer.
 *
 *	[A]SYNC:
 *		The buffer can be either in sync or async mode. In
 *		async mode all calls are to be async and the i/o
 *		must take place for the entire range or the fdbuf
 *		i/o must be ended with a call to fdb_ioerrdone()
 *		In the async case the call back is made either
 *		for every i/o completed or only once at the end
 *		of i/o. This depends on how the call back function
 *		is registered. See fdb_set_iofunc(). The fdbuf has
 *		to be freed by the call back function.
 *
 *	ZEROHOLE:
 *		This is the case the holes are to be zeroed. Note
 *		that we do not zero the holes when fdb_add_hole() is
 *		getting called. We leave the zeroing of the holes to
 *		when a list is requested or the buffer is freed. This
 *		so that we can avoid zeroing pages while holding ufs
 *		locks.
 */


typedef struct fdbuffer {
	fdb_type_t fd_type;	/* type of buffer */
	int	fd_state;	/* state of the fdbfer */
	size_t	fd_len;		/* length of this fdbuffer */
	size_t	fd_iocount;	/* total io acked, includes errors and holes */
	int	fd_iodispatch;	/* # of io's dispatched */
	int	fd_err;		/* last i/o error due from buf_t */
	ssize_t	fd_resid;	/* total len in error */

	buf_t *fd_parentbp;	/* buf associated with parent buf */

	union {
		page_t *pages;	/* page list for FDPAGE_BUF */
		caddr_t	addr;	/* address for FDADDR_BUF */
	} fd_un;

	fdb_holes_t *fd_holes;	/* holes list if this fdbuffer has holes */

	page_t **fd_shadow;	/* shadow pages used for direct i/o to uspace */
	struct proc *fd_procp;	/* procp used in bp for direct i/o to uspace */

	/*
	 * Call this function when the I/O on the full range of fdbuffer
	 * is completed. The call is made only if the i/o requests
	 * are asynchronous.
	 */

	fdb_iodone_t fd_iofunc;
	void *fd_iargp;		/* iodone function argument to be passed */

	/*
	 * The mutex protects iodispatch, iocount, state, and resid
	 * flags and variables since they are examined and updated by
	 * async call backs. All other structure members are modified
	 * in a single threaded fashion and do not require a lock.
	 */
	kmutex_t fd_mutex;

} fdbuffer_t;

#define	fd_pages	fd_un.pages
#define	fd_addr		fd_un.addr

extern fdbuffer_t *fdb_page_create(page_t *pp, size_t len, int flag);
extern fdbuffer_t *fdb_addr_create(caddr_t addr, size_t len, int flag,
    page_t **pplist, struct proc *procp);

extern void fdb_set_iofunc(fdbuffer_t *fdbuf, fdb_iodone_t iofunc, void *ioarg,
    int flags);
extern fdb_holes_t *fdb_get_holes(fdbuffer_t *fdbuf);
extern int fdb_get_error(fdbuffer_t *fdbuf);
extern void fdb_free(fdbuffer_t *fdbuf);
/*
 * Need to add:
 * fdb_get_iolen
 */
extern void fdb_add_hole(fdbuffer_t *fdbuf, u_offset_t off, size_t len);
extern buf_t *fdb_iosetup(fdbuffer_t *fdbuf, u_offset_t off, size_t len,
    struct vnode *vn, int flags);
extern void fdb_iodone(buf_t *bufp);
extern void fdb_ioerrdone(fdbuffer_t *fdbuf, int error);
extern void fdb_init(void);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_FDBUFFER_H */
