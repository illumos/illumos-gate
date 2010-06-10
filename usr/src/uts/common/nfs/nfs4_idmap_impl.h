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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NFS4_IDMAP_IMPL_H
#define	_NFS4_IDMAP_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/list.h>
#include <sys/door.h>

/*
 * This is a private header file.  Applications should not directly include
 * this file.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Cache Entry Definitions
 */
#define	NFSID_CACHE_ANCHORS	256

typedef struct nfsidmap {
	struct nfsidmap *id_chain[2];	/* must be first */
	time_t		 id_time;	/* time stamp */
	uid_t		 id_no;		/* uid/gid */
	utf8string	 id_str;	/* user@domain string */
} nfsidmap_t;

#define	id_forw			id_chain[0]
#define	id_back			id_chain[1]
#define	id_len			id_str.utf8string_len
#define	id_val			id_str.utf8string_val

typedef struct nfsidhq {
	union {
		struct nfsidhq	*hq_head[2];	/* for empty queue */
		struct nfsidmap *hq_chain[2];	/* for LRU list */
	} hq_link;
	kmutex_t	hq_lock;		/* protects hash queue */
} nfsidhq_t;

#define	hq_que_forw		hq_link.hq_head[0]
#define	hq_que_back		hq_link.hq_head[1]
#define	hq_lru_forw		hq_link.hq_chain[0]
#define	hq_lru_back		hq_link.hq_chain[1]

typedef struct {
	const char	*name;		/* cache name */
	nfsidhq_t	*table;		/* hash table */
	/*
	 * Since we need to know the status of nfsmapid from random functions
	 * that deal with idmap caches, we keep a pointer to the relevant fields
	 * in the zone's globals so we don't have to keep passing them around.
	 */
	door_handle_t		*nfsidmap_daemon_dh;
} idmap_cache_info_t;

typedef enum hash_stat { HQ_HASH_HINT, HQ_HASH_FIND } hash_stat;

/*
 * Per-zone modular globals
 */
struct nfsidmap_globals {
	list_node_t		nig_link; /* linkage into global list */
	enum clnt_stat		nig_last_stat;	/* status of last RPC call */
	int			nig_msg_done;	/* have we printed a message? */
	idmap_cache_info_t	u2s_ci;	/* table mapping uid-to-string */
	idmap_cache_info_t	s2u_ci;	/* table mapping string-to-uid */
	idmap_cache_info_t	g2s_ci;	/* table mapping groupid-to-string */
	idmap_cache_info_t	s2g_ci;	/* table mapping string-to-groupid */
	pid_t			nfsidmap_pid;
	kmutex_t		nfsidmap_daemon_lock;
	/*
	 * nfsidmap_daemon_lock protects the following:
	 * 	nfsidmap_daemon_dh
	 */
	door_handle_t		nfsidmap_daemon_dh;
};

#ifdef	__cplusplus
}
#endif

#endif /* _NFS4_IDMAP_IMPL_H */
