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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_VIO_UTIL_H
#define	_VIO_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stream.h>
#include <sys/vio_mailbox.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Helper routines for the Logical Domains (LDoms) drivers
 *
 * Note: The contents of this file are private to the implementation of the
 * LDoms drivers and are subject to change at any time without notice.
 */

/*
 * A message is composed of three structures. A message block (mblk_t), a
 * data block to which it points and a data buffer. desballoc(9F) allows
 * the caller to specify the data buffer and a free function which will
 * be invoked when freeb(9F) is called to free the message. This allows
 * the user to reclaim and reuse the data buffer, as opposed to using
 * allocb(9F) where the message block, data block and data buffer are
 * all destroyed by freeb().
 *
 * Note that even with desballoc the message and data blocks are destroyed
 * by freeb() and must be recreated. It is only the data buffer which is
 * preserved.
 *
 * The caller first creates a pool of vio_mblk_t's by invoking
 * vio_create_mblks() and specifying the number of mblks and the size of the
 * associated data buffers. Each vio_mblk_t contains a pointer to the
 * mblk_t, a pointer to the data buffer and a function pointer to the
 * reclaim function. The caller is returned a pointer to the pool which is
 * used in subsequent allocation/destroy requests.
 *
 * The pool is managed as a circular queue with a head and tail pointer.
 * Allocation requests result in the head index being incremented, mblks
 * being returned to the pool result in the tail pointer being incremented.
 *
 * The pool can only be destroyed when all the mblks have been returned. It
 * is the responsibility of the caller to ensure that all vio_allocb()
 * requests have been completed before the pool is destroyed.
 *
 *
 * vio_mblk_pool_t
 * +-------------+
 * |    tail     |--------------------------------+
 * +-------------+                                |
 * |    head     |--------+                       |
 * +-------------+        |                       |
 * ...............        V                       V
 * +-------------+     +-------+-------+-------+-------+
 * |    quep     |---->| vmp_t | vmp_t | vmp_t | vmp_t |
 * +-------------+     +-------+-------+-------+-------+
 * |             |         |       |       |       |
 * ...                     |       |       |       |   +------------+
 *                         |       |       |       +-->| data block |
 *                         |       |       |           +------------+
 *                         |       |       |   +------------+
 *                         |       |       +-->| data block |
 *                         |       |           +------------+
 *                         |       |   +------------+
 *                         |       +-->| data block |
 *                         |           +------------+
 *                         |   +------------+
 *                         +-->| data block |
 *                             +------------+
 *
 */

/* mblk pool flags */
#define	VMPL_FLAG_DESTROYING	0x1	/* pool is being destroyed */

struct vio_mblk_pool;

typedef struct vio_mblk {
	uint8_t			*datap;		/* data buffer */
	mblk_t			*mp;		/* mblk using datap */
	frtn_t			reclaim;	/* mblk reclaim routine */
	struct vio_mblk_pool 	*vmplp;		/* pointer to parent pool */
} vio_mblk_t;

typedef struct vio_mblk_pool {
	struct vio_mblk_pool	*nextp;	/* next in a list */
	kmutex_t		hlock;	/* sync access to head */
	kmutex_t		tlock;	/* sync access to tail */
	vio_mblk_t		*basep;	/* base pointer to pool of vio_mblks */
	vio_mblk_t		**quep; /* queue of free vio_mblks */
	uint8_t			*datap; /* rx data buffer area */
	uint32_t		head;	/* queue head */
	uint32_t		tail;	/* queue tail */
	uint64_t		quelen;	/* queue len (# mblks) */
	uint64_t		quemask; /* quelen - 1 */
	size_t			mblk_size; /* data buf size of each mblk */
	uint32_t		flag;	/* pool-related flags */
} vio_mblk_pool_t;

typedef struct vio_multi_pool {
	uint32_t		num_pools;	/* no. of vio mblk pools */
	uint32_t		tbsz;		/* allocated buffer size */
	uint32_t		*bufsz_tbl;	/* buffer sizes table */
	uint32_t		*nbuf_tbl;	/* no. of buffers table */
	vio_mblk_pool_t		**vmpp;		/* vio mblk pools */
} vio_multi_pool_t;

int vio_create_mblks(uint64_t num_mblks,
			size_t mblk_size, vio_mblk_pool_t **);
int vio_destroy_mblks(vio_mblk_pool_t *);
mblk_t *vio_allocb(vio_mblk_pool_t *);
void vio_freeb(void *arg);
int vio_init_multipools(vio_multi_pool_t *vmultip, int num_pools, ...);
void vio_destroy_multipools(vio_multi_pool_t *vmultip, vio_mblk_pool_t **fvmp);
mblk_t *vio_multipool_allocb(vio_multi_pool_t *vmultip, size_t size);

/* VIO versioning helpers */
#define	VIO_VER_IS_NEGOTIATED(ver, maj, min)		\
	((ver.major == (maj)) && (ver.minor == (min)))

boolean_t	vio_ver_is_supported(vio_ver_t ver, uint16_t maj, uint16_t min);

#ifdef	__cplusplus
}
#endif

#endif	/* _VIO_UTIL_H */
