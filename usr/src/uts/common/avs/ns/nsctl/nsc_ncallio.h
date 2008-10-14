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

#ifndef _NSC_NCALLIO_H
#define	_NSC_NCALLIO_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __NSC_GEN__
Error: Illegal #include - private file.
#endif

#include <sys/types.h>
#include <sys/nsctl/nsc_dev.h>
#include <sys/nsctl/nsctl.h>

/*
 * ncall-io structures
 */

/*
 * local per-device info structure
 */
typedef struct nsc_ncio_dev {
	struct nsc_ncio_dev	*next;			/* linkage */
	char			path[NSC_MAXPATH];	/* pathname */
	uint64_t		phash;			/* path hash */
	uint64_t		partsize;		/* size (FBAs) */
	int			snode;			/* server node */
	int			ref;			/* ref count */
} nsc_ncio_dev_t;


/*
 * on the wire partsize request structure (reply is inline).
 */
typedef struct nsc_ncio_size {
	char	path[NSC_MAXPATH];
} nsc_ncio_size_t;


/*
 * buffer handle and one the wire representation.
 */

#define	NSC_NCIO_MAXDATA	(NCALL_DATA_SZ - FBA_SIZE(1))


typedef struct nsc_ncio_rw {
	union {
		struct {
			int	snode;			/* server node */
			uint64_t pos;			/* offset of i/o */
			uint64_t len;			/* length of i/o */
			char	path[NSC_MAXPATH];	/* path of device */
		} rw;
		char pad[FBA_SIZE(1)];			/* pad to FBA */
	} rw_u;
	char	rw_data[NSC_NCIO_MAXDATA];		/* data */
} nsc_ncio_rw_t;

#define	rw_snode	rw_u.rw.snode
#define	rw_path		rw_u.rw.path
#define	rw_pos		rw_u.rw.pos
#define	rw_len		rw_u.rw.len


typedef struct nsc_ncio_bufh {
	nsc_buf_t	bufh;
	nsc_vec_t	vec[2];
	void		(*disc)();
	struct nsc_ncio_bufh *next;
	struct nsc_ncio_rw rw;
} nsc_ncio_buf_t;


#ifdef __cplusplus
}
#endif

#endif /* _NSC_NCALLIO_H */
