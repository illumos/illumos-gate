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

#ifndef _NSC_DISK_H
#define	_NSC_DISK_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __NSC_GEN__
Error: Illegal #include - private file.
#endif

#include <sys/types.h>
#include <sys/file.h>
#include <sys/uio.h>

#include <sys/nsctl/nsc_dev.h>
#include <sys/nsctl/nsctl.h>

#define	_NSC_DBUF_NVEC	5

/*
 * Buffer structure for disk I/O.
 */

typedef struct nsc_dbuf_s {
	nsc_buf_t db_buf;		/* Generic buffer header */
	void	(*db_disc)();		/* Disconnect callback */
	uio_t	db_uio;			/* Scatter/gather list */
	iovec_t	db_iov[_NSC_DBUF_NVEC];	/* Data transfer address */
	char	*db_addr;		/* Address of data buffer */
	nsc_vec_t db_bvec[2];		/* Pointers to data */
	struct nsc_dbuf_s *db_next;	/* Link to next buffer */
	nsc_size_t db_maxfbas;		/* Maxfbas value for the device */
} nsc_dbuf_t;


#define	db_fd		db_buf.sb_fd
#define	db_pos		db_buf.sb_pos
#define	db_len		db_buf.sb_len
#define	db_flag		db_buf.sb_flag
#define	db_error	db_buf.sb_error
#define	db_vec		db_buf.sb_vec


/*
 * Sector Mode definitions.
 */

#define	FPOS_TO_FBA(u)	((nsc_off_t)(FBA_NUM((u)->uio_loffset)))
#define	FPOS_TO_OFF(u)	((nsc_off_t)(FBA_OFF((u)->uio_loffset)))
#define	SET_FPOS(u, f)	((u)->uio_loffset = (offset_t)FBA_SIZE((offset_t)f))


#ifdef __cplusplus
}
#endif

#endif /* _NSC_DISK_H */
