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

/*
 * Copyright 2018 Nexenta Systems, Inc.
 */

#ifndef _NFS4_DRC_H
#define	_NFS4_DRC_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NFSv4 Duplicate Request cache.
 */
typedef struct rfs4_drc {
	kmutex_t	lock;
	uint32_t	dr_hash;
	uint32_t	max_size;
	uint32_t	in_use;
	list_t		dr_cache;
	list_t		*dr_buckets;
} rfs4_drc_t;

/*
 * NFSv4 Duplicate request cache entry.
 */
typedef struct rfs4_dupreq {
	list_node_t	dr_bkt_next;
	list_node_t	dr_next;
	list_t		*dr_bkt;
	rfs4_drc_t	*drc;
	int		dr_state;
	uint32_t	dr_xid;
	struct netbuf	dr_addr;
	COMPOUND4res	dr_res;
} rfs4_dupreq_t;

/*
 *  State of rfs4_dupreq.
 */
#define	NFS4_DUP_ERROR		-1
#define	NFS4_NOT_DUP		0
#define	NFS4_DUP_NEW		1
#define	NFS4_DUP_PENDING	2
#define	NFS4_DUP_FREE		3

#define	NFS4_DUP_REPLAY		4
#define	NFS4_DUP_INUSE		5

extern uint32_t nfs4_drc_max;
extern uint32_t nfs4_drc_hash;

rfs4_drc_t *rfs4_init_drc(uint32_t, uint32_t);
void rfs4_fini_drc(void);
void rfs4_dr_chstate(rfs4_dupreq_t *, int);
rfs4_dupreq_t *rfs4_alloc_dr(rfs4_drc_t *);
int rfs4_find_dr(struct svc_req *, rfs4_drc_t *, rfs4_dupreq_t **);

#ifdef	__cplusplus
}
#endif

#endif /* _NFS4_DRC_H */
