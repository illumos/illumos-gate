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

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/nsctl/nsctl.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/unistat/spcs_s_k.h>
#include "dsw.h"
#include "dsw_dev.h"

#ifdef DS_DDICT
#include "../contract.h"
#endif

#include <sys/sdt.h>		/* dtrace is S10 or later */

/*
 * Instant Image.
 *
 * This file contains the chunk map lookup functions of II.
 *
 */
#define	CHUNK_FBA(chunk) DSW_CHK2FBA(chunk)

extern int ii_debug;	/* debug level switch */
int ii_map_debug = 0;

#ifdef II_MULTIMULTI_TERABYTE
typedef	int64_t	nodeid_t;
typedef	int32_t	nodeid32_t;
#else
typedef	int32_t	nodeid_t;
#endif

typedef struct	ii_node {
	chunkid_t	vchunk_id;		/* virtual chunk id */
} NODE;

typedef struct ii_nodelink_s {
	chunkid_t	next_chunk;
} ii_nodelink_t;

static	int	nodes_per_fba = FBA_SIZE(1) / sizeof (NODE);

ii_header_t *_ii_bm_header_get(_ii_info_t *ip, nsc_buf_t **tmp);
int _ii_bm_header_put(ii_header_t *hdr, _ii_info_t *ip,
    nsc_buf_t *tmp);
void _ii_rlse_devs(_ii_info_t *, int);
int _ii_rsrv_devs(_ii_info_t *, int, int);
void _ii_error(_ii_info_t *, int);
/*
 * Private functions for use in this file.
 */
static void free_node(_ii_info_t *ip, NODE *np, nodeid_t ni);
static chunkid_t ii_alloc_overflow(_ii_info_t *ip);
void ii_free_overflow(_ii_info_t *, chunkid_t);
extern int _ii_nsc_io(_ii_info_t *, int, nsc_fd_t *, int, nsc_off_t,
    unsigned char *, nsc_size_t);

static int
update_tree_header(_ii_info_t *ip)
{
	ii_header_t *header;
	nsc_buf_t	*tmp = NULL;

	mutex_enter(&ip->bi_mutex);
	header = _ii_bm_header_get(ip, &tmp);
	if (header == NULL) {
		/* bitmap is probably offline */
		mutex_exit(&ip->bi_mutex);
		DTRACE_PROBE(_iit_update_tree_header_end);
		return (1);
	}
	header->ii_mstchks = ip->bi_mstchks;
	header->ii_shdchks = ip->bi_shdchks;
	header->ii_shdchkused = ip->bi_shdchkused;
	header->ii_shdfchk = ip->bi_shdfchk;
	(void) _ii_bm_header_put(header, ip, tmp);
	mutex_exit(&ip->bi_mutex);

	return (0);
}

static int
update_overflow_header(_ii_info_t *ip, _ii_overflow_t *op)
{
	(void) _ii_nsc_io(ip, KS_OVR, op->ii_dev->bi_fd, NSC_WRBUF,
	    II_OHEADER_FBA, (unsigned char *)&(op->ii_do),
	    sizeof (_ii_doverflow_t));

	return (0);
}

static int
node_io(_ii_info_t *ip, NODE *np, nodeid_t node, int flag)
{
	int	rc;
	int	node_fba;
	int	tree_fba = ip->bi_copyfba + (ip->bi_copyfba-ip->bi_shdfba);
	int	offset;
	nsc_buf_t *tmp = NULL;

	/*
	 * Don't use _ii_nsc_io() as _ii_nsc_io() requires io to start at
	 * an fba boundary.
	 */

	/* calculate location of node on bitmap file */
	offset = (node % nodes_per_fba) * sizeof (NODE);
	node_fba = tree_fba + node / nodes_per_fba;

	/* read disk block containing node */
	rc = nsc_alloc_buf(ip->bi_bmpfd, node_fba, 1, NSC_RDBUF|flag, &tmp);
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_BMPOFFLINE);
		if (tmp)
			(void) nsc_free_buf(tmp);

		DTRACE_PROBE(_iit_node_io_end);
		return (1);
	}

	/* copy node and update bitmap file if needed */
	rc = 0;
	if (flag == NSC_RDBUF)
		bcopy(tmp->sb_vec->sv_addr+offset, np, sizeof (NODE));
	else {
		bcopy(np, tmp->sb_vec->sv_addr+offset, sizeof (NODE));
		II_NSC_WRITE(ip, bitmap, rc, tmp, node_fba, 1, 0);
		if (!II_SUCCESS(rc)) {
			_ii_error(ip, DSW_BMPOFFLINE);
			rc = EIO;
		}
	}
	if (tmp)
		(void) nsc_free_buf(tmp);

	return (0);
}

static int
node_fba_fill(_ii_info_t *ip, nsc_size_t nchunks, chunkid_t vchunk_id)
{
	int	rc;
	nsc_off_t	fba;
	nsc_size_t	fbas;
	nsc_size_t	maxfbas;
	nsc_buf_t *bp;
	nsc_vec_t *vp;

	/* Determine maximum number of FBAs to allocate */
	rc =  nsc_maxfbas(ip->bi_bmpfd, 0, &maxfbas);
	if (!II_SUCCESS(rc))
		maxfbas = DSW_CBLK_FBA;

	/* Write out blocks of initialied NODEs */
	fba = ip->bi_copyfba + (ip->bi_copyfba-ip->bi_shdfba);
	fbas = FBA_LEN(nchunks * sizeof (NODE));
	while (fbas > 0) {

		/* Determine number of FBA to allocate this time */
		if (fbas < maxfbas) maxfbas = fbas;

		/* Allocate buffer which map to FBAs containing NODEs */
		bp = NULL;
		rc = nsc_alloc_buf(ip->bi_bmpfd, fba, maxfbas, NSC_WRBUF, &bp);
		if (!II_SUCCESS(rc)) {
			_ii_error(ip, DSW_BMPOFFLINE);
			DTRACE_PROBE(alloc_buf_failed);
			return (EIO);
		}

		/* traverse vector list, filling wth initialized NODEs */
		for (vp = bp->sb_vec; vp->sv_addr && vp->sv_len; vp++) {
			NODE *pnode = (NODE *)vp->sv_addr;
			NODE *enode = (NODE *)(vp->sv_addr +  vp->sv_len);
			while (pnode < enode) {
				pnode->vchunk_id = vchunk_id;
				pnode++;
			}
		}

		/* write FBAs containing initialized NODEs */
		II_NSC_WRITE(ip, bitmap, rc, bp, fba, maxfbas, 0);
		if (!II_SUCCESS(rc)) {
			_ii_error(ip, DSW_BMPOFFLINE);
			(void) nsc_free_buf(bp);
			DTRACE_PROBE(write_failed);
			return (EIO);
		}

		/* free the buffer */
		(void) nsc_free_buf(bp);

		/* Adjust nsc buffer values */
		fba += maxfbas;
		fbas -= maxfbas;
	}

	return (0);
}

/*
 * Reads the node into core and returns a pointer to it.
 */

static NODE *
read_node(_ii_info_t *ip, nodeid_t node)
{
	NODE *new;

	new = (NODE *)kmem_alloc(sizeof (NODE), KM_SLEEP);

	if (node_io(ip, new, node, NSC_RDBUF)) {
		kmem_free(new, sizeof (NODE));
		new = NULL;
	}

	return (new);
}


static chunkid_t
alloc_chunk(_ii_info_t *ip)
{
	ii_nodelink_t nl;
	int fba;
	chunkid_t rc = II_NULLCHUNK;

	mutex_enter(&ip->bi_chksmutex);
	if (ip->bi_shdchkused < ip->bi_shdchks) {
		rc = ip->bi_shdchkused++;
	} else if (ip->bi_shdfchk != II_NULLCHUNK) {
		ASSERT(ip->bi_shdfchk >= 0 && ip->bi_shdfchk < ip->bi_shdchks);
		rc = ip->bi_shdfchk;
		fba = CHUNK_FBA(rc);
		(void) _ii_rsrv_devs(ip, SHDR, II_INTERNAL);
		(void) _ii_nsc_io(ip, KS_SHD, SHDFD(ip), NSC_RDBUF, fba,
		    (unsigned char *)&nl, sizeof (nl));
		_ii_rlse_devs(ip, SHDR);
		ip->bi_shdfchk = nl.next_chunk;
		ASSERT(ip->bi_shdfchk == II_NULLCHUNK ||
		    (ip->bi_shdfchk >= 0 && ip->bi_shdfchk < ip->bi_shdchks));
	} else {

		/* into overflow */
		rc = ii_alloc_overflow(ip);
	}
	mutex_exit(&ip->bi_chksmutex);
	(void) update_tree_header(ip);

	return (rc);
}

/*
 * releases memory for node
 */
static void	/*ARGSUSED*/
release_node(_ii_info_t *ip, NODE *np, nodeid_t ni)
{
	kmem_free(np, sizeof (NODE));

}

static void
write_node(_ii_info_t *ip, NODE *np, nodeid_t ni)
{
	(void) node_io(ip, np, ni, NSC_WRBUF);
	release_node(ip, np, ni);

}

static void
free_node(_ii_info_t *ip, NODE *np, nodeid_t ni)
{
	ii_nodelink_t nl;
	int	fba;

	if (np == NULL) {
		DTRACE_PROBE(_iit_free_node_end);
		return;
	}

	mutex_enter(&ip->bi_chksmutex);
	if (II_ISOVERFLOW(np->vchunk_id)) {
		/* link chunk onto overflow free list */
		ii_free_overflow(ip, np->vchunk_id);
	} else {
		/* write old free list head into chunk */
		nl.next_chunk = ip->bi_shdfchk;
		ip->bi_shdfchk = np->vchunk_id;
		ASSERT(ip->bi_shdfchk == II_NULLCHUNK ||
		    (ip->bi_shdfchk >= 0 && ip->bi_shdfchk < ip->bi_shdchks));
		fba = CHUNK_FBA(np->vchunk_id);
		(void) _ii_rsrv_devs(ip, SHDR, II_INTERNAL);
		(void) _ii_nsc_io(ip, KS_SHD, SHDFD(ip), NSC_WRBUF, fba,
		    (unsigned char *)&nl, sizeof (nl));
		_ii_rlse_devs(ip, SHDR);
		/* update free counts */
		/* ip->bi_unused++; */
	}
	np->vchunk_id = II_NULLCHUNK;
	(void) node_io(ip, np, ni, NSC_WRBUF);
	(void) update_tree_header(ip);
	mutex_exit(&ip->bi_chksmutex);

}

/*
 * Public functions for dsw_dev to use.
 */

/*
 * Overflow volume functions.
 */

/* put overflow chunk on the overflow volume free list */
void
ii_free_overflow(_ii_info_t *ip, chunkid_t chunk)
{
	ii_nodelink_t nl;
	_ii_overflow_t *op;
	int fba;

	if (!II_ISOVERFLOW(chunk)) {
		DTRACE_PROBE(_iit_free_overflow_end_1);
		return;
	}
	chunk = II_2OVERFLOW(chunk);

	op = ip->bi_overflow;
	if (op == NULL) {
#ifdef DEBUG
		cmn_err(CE_PANIC, "overflow used, but not attached ip %p",
		    (void *) ip);
#endif
		DTRACE_PROBE(_iit_free_overflow_end_2);
		return;
	}
	mutex_enter(&(op->ii_mutex));

	DTRACE_PROBE(_iit_free_overflow);

	/* write old free list head into chunk */
	nl.next_chunk = op->ii_freehead;
	fba = CHUNK_FBA(chunk);
	(void) nsc_reserve(op->ii_dev->bi_fd, NSC_MULTI);
	(void) _ii_nsc_io(ip, KS_OVR, op->ii_dev->bi_fd, NSC_WRBUF, fba,
	    (unsigned char *)&nl, sizeof (nl));
	/* update free counts */
	op->ii_unused++;
	ASSERT(op->ii_used > 0);		/* always use 1 for header */

	/* write chunk id into header freelist start */
	op->ii_freehead =  chunk;

	(void) update_overflow_header(ip, op);
	nsc_release(op->ii_dev->bi_fd);
	mutex_exit(&(op->ii_mutex));

}

/* reclaim any overflow storage used by the volume */
void
ii_reclaim_overflow(_ii_info_t *ip)
{
	NODE	*node;
	nodeid_t node_id;
	_ii_overflow_t *op;

	if ((ip->bi_flags & (DSW_VOVERFLOW | DSW_FRECLAIM)) == 0) {
		DTRACE_PROBE(_iit_reclaim_overflow_end);
		return;
	}

	/*
	 * Determine whether overflow should be reclaimed:
	 * 1/ If we're not doing a group volume update
	 * OR
	 * 2/ If the number of detaches != number of attached vols
	 */
	op = ip->bi_overflow;
	if (op && (((op->ii_flags & IIO_VOL_UPDATE) == 0) ||
	    (op->ii_detachcnt != op->ii_drefcnt))) {
#ifndef II_MULTIMULTI_TERABYTE
		/* assert volume size fits into node_id */
		ASSERT(ip->bi_mstchks <= INT32_MAX);
#endif
		for (node_id = 0; node_id < ip->bi_mstchks; node_id++) {
			if ((node = read_node(ip, node_id)) == NULL) {
				DTRACE_PROBE(_iit_reclaim_overflow_end);
				/* hum.... */ return;
			}
			ii_free_overflow(ip, node->vchunk_id);
			release_node(ip, node, node_id);
		}
	} else {
		/* need to reset the overflow volume header */
		op->ii_freehead = II_NULLNODE;
		op->ii_used = 1;		/* we have used the header */
		op->ii_unused = op->ii_nchunks - op->ii_used;
		(void) update_overflow_header(ip, op);
	}

	DTRACE_PROBE(_iit_reclaim_overflow);

	if ((ip->bi_flags & DSW_VOVERFLOW) == DSW_VOVERFLOW) {
		mutex_enter(&ip->bi_mutex);
		II_FLAG_CLR(DSW_VOVERFLOW, ip);
		mutex_exit(&ip->bi_mutex);
	}
	--iigkstat.spilled_over.value.ul;

}

static chunkid_t
ii_alloc_overflow(_ii_info_t *ip)
{
	chunkid_t chunk;
	ii_nodelink_t nl;
	_ii_overflow_t *op;
	int fba;

	if ((op = ip->bi_overflow) == NULL) {
		DTRACE_PROBE(_iit_alloc_overflow_end);
		return (II_NULLCHUNK);	/* no overflow volume attached */
	}

	mutex_enter(&(op->ii_mutex));

	DTRACE_PROBE(_iit_alloc_overflow);

	if (op->ii_unused < 1) {
		mutex_exit(&(op->ii_mutex));
		DTRACE_PROBE(_iit_alloc_overflow_end);
		return (II_NULLCHUNK);
	}
	(void) nsc_reserve(op->ii_dev->bi_fd, NSC_MULTI);
	if (op->ii_freehead != II_NULLCHUNK) {
		/* pick first from free list */
		chunk = op->ii_freehead;
		fba = CHUNK_FBA(chunk);
		(void) _ii_nsc_io(ip, KS_OVR, op->ii_dev->bi_fd, NSC_RDBUF, fba,
		    (unsigned char *)&nl, sizeof (nl));
		op->ii_freehead = nl.next_chunk;
		/* decrease unused count, fix bug 4419956 */
		op->ii_unused--;
	} else {
		/* otherwise pick first unused */
		if (op->ii_used > op->ii_nchunks)
			chunk = II_NULLCHUNK;
		else {
			chunk = op->ii_used++;
			op->ii_unused--;
		}
	}
	if (chunk != II_NULLCHUNK) {
		chunk = II_2OVERFLOW(chunk);
		if ((ip->bi_flags&DSW_VOVERFLOW) == 0) {
			mutex_enter(&ip->bi_mutex);
			II_FLAG_SET(DSW_VOVERFLOW, ip);
			mutex_exit(&ip->bi_mutex);
			++iigkstat.spilled_over.value.ul;
		}
	}
	(void) update_overflow_header(ip, op);
	nsc_release(op->ii_dev->bi_fd);
	mutex_exit(&(op->ii_mutex));

	return (chunk);
}
/*
 * Find or insert key into search tree.
 */

chunkid_t
ii_tsearch(_ii_info_t *ip, chunkid_t chunk_id)
			/* Address of the root of the tree */
{
	NODE	*rootp = NULL;
	chunkid_t n;	/* New node id if key not found */

	if ((rootp = read_node(ip, chunk_id)) == NULL) {
		DTRACE_PROBE(_iit_tsearch_end);
		return (II_NULLNODE);
	}
	n = rootp->vchunk_id;
	if (n != II_NULLCHUNK) { /* chunk allocated, return location */
		release_node(ip, rootp, 0);
		DTRACE_PROBE(_iit_tsearch_end);
		return (n);
	}
	n = alloc_chunk(ip);
	if (n != II_NULLCHUNK) {
		rootp->vchunk_id = n;
		write_node(ip, rootp, chunk_id);
	} else
		release_node(ip, rootp, 0);

	return (n);
}

/* Delete node with key chunkid */
void
ii_tdelete(_ii_info_t *ip,
	chunkid_t chunkid)	/* Key to be deleted */
{
	NODE *np = NULL;

	if ((np = read_node(ip, chunkid)) == NULL) {
		DTRACE_PROBE(_iit_tdelete_end);
		return;
	}

	ASSERT(np->vchunk_id != II_NULLCHUNK);
	free_node(ip, np, chunkid);
	np->vchunk_id = II_NULLCHUNK;
	write_node(ip, np, chunkid);

}

/*
 * initialise an empty map for ip
 */

int
ii_tinit(_ii_info_t *ip)
{
	int rc = 0;

	/* overflow can't be attached before first call to this function */
	if (ip->bi_overflow)
		ii_reclaim_overflow(ip);

	mutex_enter(&ip->bi_chksmutex);
	ip->bi_shdfchk = II_NULLCHUNK;	/* set freelist to empty chain */
	ip->bi_shdchkused = 0;

	/* fill index (bi_mstchks size) with II_NULLCHUNK */
	rc = node_fba_fill(ip, ip->bi_mstchks, II_NULLCHUNK);
	if (rc == 0)
		rc = update_tree_header(ip);
	mutex_exit(&ip->bi_chksmutex);

	return (rc);
}

/*
 * Calculate the size of map space provided by a bitmap volume with
 * tree_len fba's spare for the tree.
 */

nsc_size_t
ii_btsize(nsc_size_t tree_len)
{
	nsc_size_t nchunks;

	nchunks = tree_len * nodes_per_fba;

	if (ii_debug > 1)
		cmn_err(CE_NOTE,
		    "ii_btsize: bitmap with %" NSC_SZFMT
		    " spare fba's will map %" NSC_SZFMT " chunks",
			tree_len, nchunks);

	return (nchunks);
}
