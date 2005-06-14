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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _LIBRSMWRSM_H
#define	_LIBRSMWRSM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Private Header file for librsmwrsm.c */

#define	WRSMLIB_CACHELINE_SIZE	64
#define	WRSMLIB_ALIGN 64
#define	WRSMLIB_CACHELINE_SHIFT	6
#define	WRSMLIB_CACHELINE_MASK	(WRSMLIB_CACHELINE_SIZE - 1)
/*
 * number of controllers is set by the wrsm.conf file. as there is no
 * way to dynamically relay this information to the plugin library,
 * maxcontrollers is set here to the maximum number of controllers a system
 * could ever have.
 */
#define	MAXCONTROLLERS 64
#define	STRIPE_STRIDE 128
#define	SAFARI_OFFSET 64
#define	MAXWCISTRIPING 4
#define	STRIPE_MASK 1


typedef unsigned char wrsm_barrier_state_t;
#define	BARRIER_CLOSED	((wrsm_barrier_state_t)0xff)
#define	BARRIER_OPENED	((wrsm_barrier_state_t)0xfe)
#define	BARRIER_FAILED	((wrsm_barrier_state_t)0xfd)

/*
 * The following type may be allocated on the stack, then using the function
 * wrsmlib_align a properly aligned message buffer is extracted.
 * once wrsmlib_blkcopy is fixed - alignment here won't be needed
 */
typedef uint8_t wrsmlib_raw_message_t[WRSMLIB_CACHELINE_SIZE + WRSMLIB_ALIGN];

/* plugin specific structures */
typedef struct {
	mutex_t segmutex;
	boolean_t isloopback; /* when export cnode - local cnode */
	rsm_barrier_mode_t barrier_mode;  /* implicit or explicit barrier */
	rsm_barrier_type_t barrier_type;
	rsm_memseg_id_t segment_id;
	caddr_t barrier_scratch_addr; /* barrier scratch page */
	caddr_t barrier_ncslice_addr; /* page 0 of ncslice */
	caddr_t  route_info_addr; /* start of route change data  */
	uint32_t init_route_counter; /* set on open = *reconfig_ctr_addr */
	uint32_t *route_counterp; /* route counter pointer - read only */
	uint32_t *reroutingp; /* in process of ncslice rerouting - read only */
	uint32_t *stripingp;
	rsm_addr_t export_cnodeid;
} plugin_importseg_t;


/*
 * this struct is a static array in the plugin. for each controller,
 * it maintains the related opened (> 0) file descriptors and the count
 * for the number of open request on that controller. the library will
 * request the driver to close the controller on the last close request for
 * that particular controller.
 */
typedef struct {
	rsm_addr_t local_cnode;
	int open_controller_count;
	int fd;
} opened_controllers_t;

typedef struct {
	wrsm_barrier_state_t state; /* whether opened or closed */
	uint32_t route_counter; /* init in open and checked in close */
	uint64_t wci_cluster_error_count_initial;
	plugin_importseg_t *importsegp;
} plugin_barrier_t;


/*
 * Performs a 64-byte block copy, used for remote read/write/interrupts.
 * Assumes both addresses are 64-byte aligned, and does no checking.
 */
void
wrsmlib_blkcopy(void *src, void *dst, uint_t num_blocks);

/*
 * Performs a 64-byte block store, used for remote writes.
 * Assumes that the dst addr is 64-byte aligned, and does no checking.
 */
void
wrsmlib_blkwrite(void *src, void *dst, uint_t num_blocks);

#ifdef __cplusplus
}
#endif

#endif /* _LIBRSMWRSM_H */
