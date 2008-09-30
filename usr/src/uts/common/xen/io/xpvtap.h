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

#ifndef _SYS_XPVTAP_H
#define	_SYS_XPVTAP_H


#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/* Notification from user app that it has pushed responses */
#define	XPVTAP_IOCTL_RESP_PUSH		1

/* Number of bytes the user app should mmap for the gref pages */
#define	XPVTAP_GREF_BUFSIZE	\
	(BLKIF_RING_SIZE * BLKIF_MAX_SEGMENTS_PER_REQUEST * PAGESIZE)


#ifdef	_KERNEL

#include <xen/io/blk_common.h>


#define	XPVTAP_GREF_REQADDR(base, id) (caddr_t) \
	((uintptr_t)base + (id * BLKIF_MAX_SEGMENTS_PER_REQUEST * PAGESIZE))

/* structure used to keep track of resources */
typedef struct xpvtap_rs_s {
	/*
	 * Bounds of resource allocation. We will start allocating at rs_min
	 * and rollover at rs_max+1 (rs_max is included). e.g. for rs_min=0
	 * and rs_max=7, we will have 8 total resources which can be alloced.
	 */
	uint_t rs_min;
	uint_t rs_max;

	/*
	 * rs_free points to an array of 64-bit values used to track resource
	 * allocation. rs_free_size is the free buffer size in bytes.
	 */
	uint64_t *rs_free;
	uint_t rs_free_size;

	/*
	 * last tracks the last alloc'd resource. This allows us to do a round
	 * robin allocation.
	 */
	uint_t rs_last;

	/*
	 * set when flushing all allocated resources. We'll know the lock
	 * is held.
	 */
	boolean_t rs_flushing;

	kmutex_t rs_mutex;
} xpvtap_rs_t;
typedef struct xpvtap_rs_s *xpvtap_rs_hdl_t;

/* track if user app has the device open, and sleep waiting for close */
typedef struct xpvtap_open_s {
	kmutex_t	bo_mutex;
	boolean_t	bo_opened;
	kcondvar_t	bo_exit_cv;
} xpvtap_open_t;

/*
 * ring between driver and user app. requests are forwared from the
 * guest to the user app on this ring. reponses from the user app come in
 * on this ring are then are forwarded to the guest.
 */
typedef struct xpvtap_user_ring_s {
	/* ring state */
	blkif_front_ring_t	ur_ring;

	/*
	 * pointer to allocated memory for the ring which is shared between
	 * the driver and the app.
	 */
	blkif_sring_t		*ur_sring;

	/* umem cookie for free'ing up the umem */
	ddi_umem_cookie_t	ur_cookie;

	RING_IDX		ur_prod_polled;
} xpvtap_user_ring_t;

/*
 * track the requests that come in from the guest. we need to track the
 * requests for two reasons. first, we need to know how many grefs we need
 * to unmap when the app sends the response. second, since we use the ID in
 * the request to index into um_guest_pages (tells the app where the segments
 * are mapped), we need to have a mapping between the the ID we sent in the
 * request to the app and the ID we got from the guest request. The response
 * to the guest needs to have the later.
 */
typedef struct xpvtap_user_map_s {
	/* address space of the user app. grab this in open */
	struct as		*um_as;

	/* state to track request IDs we can send to the user app */
	xpvtap_rs_hdl_t		um_rs;

	/*
	 * base user app VA of the mapped grefs. this VA space is large enough
	 * to map the max pages per request * max outstanding requests.
	 */
	caddr_t			um_guest_pages;
	size_t			um_guest_size;

	/*
	 * have we locked down the gref buffer's ptes and registered
	 * them with segmf. This needs to happen after the user app
	 * has mmaped the gref buf.
	 */
	boolean_t		um_registered;

	/*
	 * array of outstanding requests to the user app. Index into this
	 * array using the ID in the user app request.
	 */
	blkif_request_t		*um_outstanding_reqs;
} xpvtap_user_map_t;

/* thread start, wake, exit state */
typedef struct xpvtap_user_thread_s {
	kmutex_t		ut_mutex;
	kcondvar_t		ut_wake_cv;
	volatile boolean_t	ut_wake;
	volatile boolean_t	ut_exit;
	kcondvar_t		ut_exit_done_cv;
	volatile boolean_t	ut_exit_done;
	ddi_taskq_t		*ut_taskq;
} xpvtap_user_thread_t;

/* driver state */
typedef struct xpvtap_state_s {
	dev_info_t		*bt_dip;
	int			bt_instance;

	/* ring between the guest and xpvtap */
	blk_ring_t		bt_guest_ring;

	/* ring between xpvtap and the user app */
	xpvtap_user_ring_t	bt_user_ring;

	xpvtap_user_map_t	bt_map;
	xpvtap_user_thread_t	bt_thread;
	struct pollhead		bt_pollhead;
	xpvtap_open_t		bt_open;
} xpvtap_state_t;

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_XPVTAP_H */
