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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * this library is the plugin module used by RSMAPI to communicate
 * with the Wildcat RSM driver. The library offers functions to
 * setup a connection with the driver, to enable users of RSMAPI to perform
 * put, get and barrier operations.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <synch.h>
#include <assert.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <sys/rsm/rsmapi_common.h>
#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsmndi.h>
#include <sys/wrsm.h>
#include <sys/wrsm_plugin.h>
#include "librsmwrsm.h"

#ifdef DEBUG

#define	PLUGIN_DEBUG	0x0001
#define	PLUGIN_WARN	0x0002
#define	PLUGIN_PUT	0x0004
#define	PLUGIN_GET	0x0008
#define	PLUGIN_BARRIER	0x0010

/*
 * for debuging:
 * - compile with DEBUG and set environment variable PLUGIN_VERBOSITY.
 *  PLUGIN_VERBOSITY  = 0x1F to turn all ALL debug options
 * or an OR'ed combination of:
 * PLUGIN_DEBUG 0x0001 -This option is  used for messages in all
 *                      initialization functions and local functions
 *                        (errors/failures use PLUGIN_WARN)
 * PLUGIN_WARN	0x0002 - This option spans all areas, when ever error,
 *                      or failure of any sort occurs. Minimally Set THIS ONE!
 * PLUGIN_PUT	0x0004 - This option for all put related request.
 *                           (errors/failures use PLUGIN_WARN)
 * PLUGIN_GET	0x0008 - This option for all get related request
 *                            (errors/failures use PLUGIN_WARN)
 * PLUGIN_BARRIER 0x0010- This option for ALL barrier operations (close, open
 *                             init, destroy, etc)
 * Note, not all possible errors have a corresponding message printed.
 */
static void
plugin_debug_print(char *format, ...)
{
	va_list	arglist;

	va_start(arglist, format);
	(void) vfprintf(stderr, format, arglist);
	va_end(arglist);
}
static int plugin_debug = 0; /* initialize to 0 */

#define	DEBUGP(a, b) if (plugin_debug & (a)) plugin_debug_print b
#else
#define	DEBUGP(a, b) { }
#endif
/*
 * the following is based on wci_cluster_error_status_array_u defined
 * in wci_regs.h. The plugin is unable to include wci_regs.h. Not
 * only is wci_regs.h for use by Kernel modules, wci_regs.h can not
 * be used with 32 bit applications.
 */

typedef union {
	struct wci_CESR {
		uint32_t rsvd_z				:	32;
		uint32_t rsvd_x				:	26;
		uint32_t disable_fail_fast		:	1;    /* 5 */
		uint32_t not_valid			:	1;    /* 4 */
		uint32_t value				:	4;    /* 3:0 */
	} bit;
	uint64_t val;
} wci_CESR_u;



#define	ASSERT	assert
#define	STRIPE_BIT(stripe, i)	(((stripe) >> (i)) & (STRIPE_MASK))

/* Internal functions */
static int wrsm_memseg_import_connect(rsmapi_controller_handle_t controller,
    rsm_node_id_t node_id, rsm_memseg_id_t segment_id,
    rsm_permission_t perm, rsm_memseg_import_handle_t *im_memseg);
static int wrsm_memseg_import_disconnect(rsm_memseg_import_handle_t im_memseg);
static int wrsm_memseg_import_get8(rsm_memseg_import_handle_t im_memseg,
    off_t offset, uint8_t *datap, ulong_t rep_cnt, boolean_t swap);
static int wrsm_memseg_import_get16(rsm_memseg_import_handle_t im_memseg,
    off_t offset, uint16_t *datap, ulong_t rep_cnt, boolean_t swap);
static int wrsm_memseg_import_get32(rsm_memseg_import_handle_t im_memseg,
    off_t offset, uint32_t *datap, ulong_t rep_cnt, boolean_t swap);
static int wrsm_memseg_import_get64(rsm_memseg_import_handle_t im_memseg,
    off_t offset, uint64_t *datap, ulong_t rep_cnt, boolean_t swap);
static int wrsm_memseg_import_get(rsm_memseg_import_handle_t im_memseg,
    off_t offset, void *dst_addr, size_t length);
static int wrsm_memseg_import_put8(rsm_memseg_import_handle_t im_memseg,
    off_t offset, uint8_t *data, ulong_t rep_cnt, boolean_t swap);
static int wrsm_memseg_import_put16(rsm_memseg_import_handle_t im_memseg,
    off_t offset, uint16_t *data, ulong_t rep_cnt, boolean_t swap);
static int wrsm_memseg_import_put32(rsm_memseg_import_handle_t im_memseg,
    off_t offset, uint32_t *data, ulong_t rep_cnt, boolean_t swap);
static int wrsm_memseg_import_put64(rsm_memseg_import_handle_t im_memseg,
    off_t offset, uint64_t *data, ulong_t rep_cnt, boolean_t swap);
static int wrsm_memseg_import_put(rsm_memseg_import_handle_t im_memseg,
    off_t offset, void *src_addr, size_t length);
static int wrsm_memseg_import_init_barrier(rsm_memseg_import_handle_t
    im_memseg, rsm_barrier_type_t type, rsm_barrier_handle_t barrier);
static int wrsm_memseg_import_open_barrier(rsm_barrier_handle_t barrier);
static int wrsm_memseg_import_order_barrier(rsm_barrier_handle_t barrier);
static int wrsm_memseg_import_close_barrier(rsm_barrier_handle_t barrier);
static int wrsm_memseg_import_destroy_barrier(rsm_barrier_handle_t barrier);
static int wrsm_memseg_import_get_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t *mode);
static int wrsm_memseg_import_set_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t mode);
static int wrsm_memseg_import_putv(rsm_scat_gath_t *sg_io);
static int wrsm_memseg_import_getv(rsm_scat_gath_t *sg_io);
static int wrsm_create_localmemory_handle(rsmapi_controller_handle_t controller,
    rsm_localmemory_handle_t *local_handle_p, caddr_t local_vaddr, size_t len);
static int wrsm_free_localmemory_handle(rsm_localmemory_handle_t local_handle);
static int wrsm_register_lib_funcs(rsm_lib_funcs_t *libfuncs);
static int wrsm_get_lib_attr(rsm_ndlib_attr_t **libattr);
static int wrsm_closedevice(rsmapi_controller_handle_t controller);

static rsm_ndlib_attr_t wrsm_rsm_ndlib_attr = {
	B_TRUE,
	B_TRUE
};
static rsm_segops_t wrsm_ops = {
	RSM_LIB_VERSION,
	wrsm_memseg_import_connect,
	wrsm_memseg_import_disconnect,
	wrsm_memseg_import_get8,
	wrsm_memseg_import_get16,
	wrsm_memseg_import_get32,
	wrsm_memseg_import_get64,
	wrsm_memseg_import_get,
	wrsm_memseg_import_put8,
	wrsm_memseg_import_put16,
	wrsm_memseg_import_put32,
	wrsm_memseg_import_put64,
	wrsm_memseg_import_put,
	wrsm_memseg_import_init_barrier,
	wrsm_memseg_import_open_barrier,
	wrsm_memseg_import_order_barrier,
	wrsm_memseg_import_close_barrier,
	wrsm_memseg_import_destroy_barrier,
	wrsm_memseg_import_get_mode,
	wrsm_memseg_import_set_mode,
	wrsm_memseg_import_putv,
	wrsm_memseg_import_getv,
	wrsm_create_localmemory_handle,
	wrsm_free_localmemory_handle,
	wrsm_register_lib_funcs,
	wrsm_get_lib_attr,
	wrsm_closedevice
};

static rsm_lib_funcs_t *rsm_lib_funcs;

/* list of file descriptors */
static opened_controllers_t opened_ctrls_fd[MAXCONTROLLERS] =
{{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1},
{0, -1, -1}, {0, -1, -1}, {0, -1, -1}, {0, -1, -1}};

static wrsmlib_raw_message_t cachelinebufscratch; /* write/read barrier use */


/*
 * local function used to return a page aligned aligned structure
 */
static void *
wrsmlib_align(wrsmlib_raw_message_t *raw_msg)
{
	void *addr;

	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: wrsmlib_align\n"));

	addr = (void *)(((uint64_t)raw_msg + WRSMLIB_ALIGN) &
	    ~WRSMLIB_CACHELINE_MASK);

	return (addr);

}


/*
 * writes and then reads to barrier scractchpage up to two way link striping
 * and 4 way wci striping during the  close_barrier that is called for
 * a put routine. It is needed to flush out the buffer
 * to assure that the transaction has made it to the remote node.
 */
static void
write_read_scratchpage(plugin_barrier_t *bar)
{
	int i;
	caddr_t scratch_addr;
	caddr_t aligned_cacheline;

	/*
	 * wrsmlib_blkcopy does a membar sync before, during and after
	 * writes/reads.
	 */
	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: write_read_scratchpage\n "));
	ASSERT(bar);

	/* No need to check data, since we check wci_error_cluster_count */

	aligned_cacheline = (caddr_t)wrsmlib_align(&cachelinebufscratch);

	/* write all request */
	for (i = 0; i < (MAXWCISTRIPING * 2); i++) {
		if (STRIPE_BIT(*bar->importsegp->stripingp, i)) {
			scratch_addr = bar->importsegp->barrier_scratch_addr +
			    STRIPE_STRIDE * i;
			DEBUGP(PLUGIN_BARRIER, (" librsmwrsm: "
			    "write_read_scratchpage write for %dth stripe "
			    "offset,addr is 0x%lx  \n", i, scratch_addr));
			wrsmlib_blkcopy(aligned_cacheline,  scratch_addr, 1);
		}
	}

	/* read all request */
	for (i = 0; i < (MAXWCISTRIPING * 2); i++) {
		if (STRIPE_BIT(*bar->importsegp->stripingp, i)) {
			scratch_addr = bar->importsegp->barrier_scratch_addr +
			    STRIPE_STRIDE * i;
			DEBUGP(PLUGIN_BARRIER, (" librsmwrsm: "
			    "write_read_scratchpag read for %dth stripe "
			    "offset, addr is 0x%lx  \n", i, scratch_addr));
			wrsmlib_blkcopy(scratch_addr, aligned_cacheline, 1);
		}
	}
}

/*
 * sum's up all the wci_cluster_error_count at the first four
 * offsets in barrier_ncslice page (mapped in, in the connect call)
 * if the striping bit is set for that offset
 * The relation between which bit is set and at what offset to read is as
 * follows:
 * starting at  barriermap->ncslice_addr
 *	If Bit 0 is set, stripe offset 0
 *	If Bit 1 is set, stripe offset 128
 *	IF Bit 2 is set, stripe offset 256 (+ 128 from the previous)
 *	If Bit 3 is set, stripe offset 384 (128 chunks)
 */
static void
sum_cluster_error_count(plugin_barrier_t *bar, uint64_t *total)
{
	int i;

	/*
	 * the location of the wci_cluster_error_count in ncslice page 0
	 * is (based on wci -2 prm) byte offset 64.
	 */
	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: sum_cluster_error_count"
	    " barrier_ncslice addr start is %p  \n",
	    bar->importsegp->barrier_ncslice_addr));

	*total = 0;
	for (i = 0; i < MAXWCISTRIPING; i++) {
		/*
		 * STRIPE_STRIDE * i - is the start pointer between
		 * striping, and SAFARI_OFFSET is the offset into the
		 * location that the wci_cluster_error_count can be found
		 */
		if (STRIPE_BIT(*bar->importsegp->stripingp, i)) {
			/* LINTED */
			*total += *((uint64_t *)
			    (bar->importsegp->barrier_ncslice_addr
				+ (STRIPE_STRIDE * i) + SAFARI_OFFSET));
		}
	}
	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: sum_cluster_error_count"
	    " total is %ld\n", *total));
}

/* gets at most 64 bytes of len from a single cacheline */
static int
small_get(rsm_memseg_import_handle_t im_memseg, off_t offset, uint_t len,
    caddr_t buf)
{
	wrsmlib_raw_message_t cachelinebuf;
	caddr_t aligned_cacheline = (caddr_t)wrsmlib_align(&cachelinebuf);
	off_t read_offset;
	off_t cacheline_offset;
	caddr_t seg;
	plugin_importseg_t *importsegp;

	importsegp = RSMNDI_SEG_GETPRIV(im_memseg);
	ASSERT(importsegp);
	DEBUGP(PLUGIN_GET, ("librsmwrsm: small_get controller num %d,"
	    " segment_id %d\n", RSMNDI_SEG_GETUNIT(im_memseg),
	    importsegp->segment_id));

	if (!importsegp->isloopback) {
		/* offset into aligned cacheline */
		cacheline_offset = offset & WRSMLIB_CACHELINE_MASK;
		ASSERT((cacheline_offset + len) <= WRSMLIB_CACHELINE_SIZE);

		/*
		 * aligned offset relevant to which cacheline to copy from
		 * segment so mask out the lower 14 bits
		 */
		read_offset = offset & ~WRSMLIB_CACHELINE_MASK;

		seg = RSMNDI_GET_MAPADDR(im_memseg, read_offset);
		ASSERT(seg);

		/* get entire cacheline starting at seg */
		wrsmlib_blkcopy(seg, aligned_cacheline, 1);

		/*
		 * copy requested len of  bytes at cacheline_offset
		 * into buf
		 */
		bcopy(aligned_cacheline + cacheline_offset, buf, len);
	} else {
		/* If we're in loopback, just copy */
		seg =  RSMNDI_GET_MAPADDR(im_memseg, offset);
		bcopy(seg, buf, len);
	}

	return (RSM_SUCCESS);
}

/*
 * local function that performs the meat of the close_barrier routine
 * using the plugin's barrier structure. the use of this function is
 * needed because when the IMPLICIT barriers are done, there is
 * no way to pass the RSMAPI defined barrier structure of which is
 * considered to be an opaque type according to the plugin.
 * When flag is set to TRUE, close_barrier request is due to a put
 * request, hence write_read_scratchpage is required, or the call request
 * is due to an EXPLICIT barrier and we do not know wether or not the
 * data request was a read or a write.
 */
static int
close_barrier(plugin_barrier_t *bar, boolean_t flag)
{
	uint64_t wci_cluster_error_count_final;

	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: close_barrier\n"));

	ASSERT(bar && bar->importsegp);

	if (bar->importsegp->isloopback) {
		/* export_cnode = local cnode, loopback mode */
		return (RSM_SUCCESS);
	}
	/*
	 * If set to FAILED, return RSMERR_BARRIER_FAILURE
	 * rerouting occured on open_barrier
	 */
	if (bar->state == BARRIER_FAILED) {
		return (RSMERR_BARRIER_FAILURE);
	}
	/* If set to OPENED, then open_barrier was not previously called */
	if (bar->state != BARRIER_OPENED) {
		return (RSMERR_BARRIER_NOT_OPENED);
	}

	bar->state = BARRIER_CLOSED;

	/* only write/read scratch page on puts done with implicit barriers */
	if (flag) {
		write_read_scratchpage(bar);
	}
	sum_cluster_error_count(bar, &wci_cluster_error_count_final);
	if (bar->wci_cluster_error_count_initial !=
	    wci_cluster_error_count_final) {
		/* span of time errors occured - fail */
		DEBUGP(PLUGIN_WARN, ("librsmwrsm: WARNING close barrier "
		    "cluster errors detected (initial != final) FAIL\n"));
		return (RSMERR_BARRIER_FAILURE);

	}

	if (*bar->importsegp->reroutingp || (bar->route_counter !=
	    *bar->importsegp->route_counterp)) {
		DEBUGP(PLUGIN_WARN, ("librsmwrsm: WARNING close barrier"
		    "failure: either routing is changing %d (should be 0)\n"
		    "\t or route has changed: initial route = %d and should "
		    " be equal to final route = %d\n",
		    *bar->importsegp->reroutingp, bar->route_counter,
		    *bar->importsegp->route_counterp));
		return (RSMERR_BARRIER_FAILURE);
	}

	return (RSM_SUCCESS);


}

/*
 * local function that performs the meat of the open_barrier routine
 * using the plugin's barrier structure. the use of this function is
 * needed because when the IMPLICIT barriers are done, there is
 * no way to pass the RSMAPI defined barrier structure of which is
 * considered to be an opaque type according to the plugin.
 */
static int
open_barrier(plugin_barrier_t *bar)
{
	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: open_barrier \n"));
	ASSERT(bar && bar->importsegp);

	if (bar->importsegp->isloopback) {
		/* export_cnode = local cnode, loopback mode */
		DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: open_barrier - "
		    "LOOPBACK\n"));
		return (RSM_SUCCESS);
	}

	/* if reroutingp is set, driver is in process of route change */
	ASSERT(bar->importsegp->reroutingp);
	if (*bar->importsegp->reroutingp) {
		DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: open_barrier - "
		    "FAILURE occuring - rerouting in progress"
		    "this will cause close barriers to FAIL\n"));
		bar->state = BARRIER_FAILED;
		return (RSM_SUCCESS);
	}

	bar->state = BARRIER_OPENED;
	bar->route_counter = bar->importsegp->init_route_counter;

	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: open_barrier\n"));

	/*
	 * by using the bar->importsegp->init_route_counter initialzied
	 * in the connect call, we avoid taking the lock for every
	 * call to open_barrier. instead, we only take the barrier lock
	 * when there is a route change.
	 */
	if (bar->route_counter != *bar->importsegp->route_counterp) {
		/*
		 * if these don't match then there has been a route change
		 * we must now update the importseg->init_route_counter
		 * and the local bar->route_counter (used for comparison in
		 * close) recall importseg->route_counterp, is actually the
		 * read only pointer to the drivers address space.
		 */
		(void) mutex_lock(&bar->importsegp->segmutex);

		/*
		 * bar->route_counter will be used later for comparison
		 * in close_barrier which will check it against the drivers
		 * counter -  *bar->importseg->route_counterp.
		 */

		bar->route_counter = bar->importsegp->init_route_counter =
		    *bar->importsegp->route_counterp;
		(void) mutex_unlock(&bar->importsegp->segmutex);
	}

	sum_cluster_error_count(bar, &bar->wci_cluster_error_count_initial);
	return (RSM_SUCCESS);
}

/*
 * Initialization routine called from rsm library framework
 */
int
wrsm_opendevice(int unit, rsm_segops_t **ops)
{
	int tmpfd;
	char devicename[12];
	rsm_addr_t args;

#ifdef DEBUG
	char *env;

	/* set debug variables */
	if (env = getenv("PLUGIN_VERBOSITY")) {
		/* LINTED cast from 64-bit integer to 32-bit integer */
		plugin_debug = (int)
		    strtol(env, (char **)NULL, 0);
	} else {
		plugin_debug = 0;
	}
	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: plugin_debug is 0x%x \n",
	    plugin_debug));
#endif
	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: wrsm_opendevice controller "
	    "%d\n", unit));

	(void) sprintf(devicename, "/dev/wrsm%d", unit);

	if (opened_ctrls_fd[unit].fd == -1) {
		/* first opendevice called, initialize count */
		opened_ctrls_fd[unit].open_controller_count = 1;
		tmpfd = open(devicename, O_RDWR);
	} else {
		/*
		 * device already opened - keep count of number of times
		 * requested so that we only call the device's close
		 * routine once. This will save us the hassle of keeping
		 * track of additional fd's.
		 */
		ASSERT(opened_ctrls_fd[unit].fd >= 0);
		opened_ctrls_fd[unit].open_controller_count++;
		return (RSM_SUCCESS);
	}

	if (tmpfd == -1) {
		if (errno == ENOENT) {
			/* no config exist for this controller */
			return (RSMERR_BAD_CTLR_HNDL);
		} else {
			return (RSMERR_CTLR_NOT_PRESENT);
		}
	}

	/*
	 * libc can only handle fd < 256
	 * because of this, other libraries need to request fd >= 256
	 */
	if ((opened_ctrls_fd[unit].fd = fcntl(tmpfd, F_DUPFD, 256)) == -1) {
		/* than keep tmpfd */
		opened_ctrls_fd[unit].fd = tmpfd;
	} else {
		/* close tmpfd since new fd was assigned */
		(void) close(tmpfd);
	}

	/* get local cnode - for use with loopback */
	if (ioctl(opened_ctrls_fd[unit].fd,
	    WRSM_CTLR_PLUGIN_GETLOCALNODE, &args) == 0) {
		opened_ctrls_fd[unit].local_cnode = args;
		DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: local cnode is %d \n",
		    opened_ctrls_fd[unit].local_cnode));
	} else {
		/*
		 * If a local cnode is not returned, that is because
		 * the controller is not part of network.
		 */
		DEBUGP(PLUGIN_WARN, ("librsmwrsm: wrsm_opendevice -"
		    "controller %d not part of network \n", unit));
		return (RSMERR_CTLR_NOT_PRESENT);
	}
	*ops = &wrsm_ops;

	/* initialize for use in read_write_barrier_scratch routine */
	(void)
	    memset(cachelinebufscratch, 0xFF, sizeof (wrsmlib_raw_message_t));

	return (RSM_SUCCESS);
}

/* set RSMAPI approved error based on errno coming from the driver/mmap call */
static int
seterr()
{
	int retval;
	switch (errno) {
	case ENXIO:
	case EINVAL:
		retval = RSMERR_BAD_CTLR_HNDL;
		break;
	case ENODEV:
		retval = RSMERR_CTLR_NOT_PRESENT;
		break;
	case EACCES:
		retval = RSMERR_PERM_DENIED;
		break;
	case ENOMEM:
		retval = RSMERR_INSUFFICIENT_MEM;
		break;
	case EPROTO:
		retval = RSMERR_SEG_NOT_PUBLISHED;
		break;
	case EHOSTUNREACH:
		retval = RSMERR_REMOTE_NODE_UNREACHABLE;
		break;
	case ENOTSUP:
	case EOVERFLOW:
	case EAGAIN:
	case EBADF:
		retval = RSMERR_INTERRUPTED;
		break;
	default:
		/* unknown return value from mmap */
		DEBUGP(PLUGIN_WARN, ("librsmwrsm: ERROR: mmap returned %d\n",
		    errno));
		retval = RSMERR_INTERRUPTED;
	}

	return (retval);
}

/* ARGSUSED */
static int
wrsm_memseg_import_connect(rsmapi_controller_handle_t controller,
    rsm_node_id_t node_id, rsm_memseg_id_t segment_id, rsm_permission_t perm,
    rsm_memseg_import_handle_t *im_memseg)
{
	int prot;
	int ctrl_num;
	wrsm_plugin_offset_t pseudo_offset;
	rsm_addr_t export_cnodeid;
	plugin_importseg_t *importsegp;
	int err = 0;

	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: wrsm_memseg_import_connect \n"));

	ctrl_num = (int)RSMNDI_CNTRLR_GETUNIT(controller);

	if ((err = rsm_lib_funcs->rsm_get_hwaddr(controller, node_id,
	    &export_cnodeid)) != RSM_SUCCESS) {
		return (err);
	}
	importsegp = (plugin_importseg_t *)malloc(sizeof (plugin_importseg_t));

	if (importsegp == NULL) {
		return (RSMERR_INSUFFICIENT_MEM);
	}

	/* iniitialize plugin specific importseg */
	importsegp->segment_id = segment_id;
	importsegp->export_cnodeid = export_cnodeid;
	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: wrsm_memseg_import_connect"
	    " controller number is %d, segid is %d  cnodeid %lld\n",
	    ctrl_num, segment_id, export_cnodeid));

	ASSERT(ctrl_num >= 0 && ctrl_num <= MAXCONTROLLERS);

	/* determine if we should be doing loopback ie, export_cnode = local */
	if (opened_ctrls_fd[ctrl_num].local_cnode == export_cnodeid) {
		importsegp->isloopback = B_TRUE;
		DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: connect - LOOPBACK mode"
		    "\n"));
	} else {
		importsegp->isloopback = B_FALSE;
		DEBUGP(PLUGIN_DEBUG, ("librsmwrsm:*** connect NOT in Loopback "
		    "  mode \n"));
	}

	/* if not loopback test, set up driver mappings */
	if (!importsegp->isloopback) {
		/* prepare generic part of pseudo offset */
		pseudo_offset.bit.segment_id = segment_id;
		/* cnodeids are never > 255 that is why we can cast this */
		pseudo_offset.bit.export_cnodeid = (unsigned char)
		    export_cnodeid;

		/*
		 * Remote memory scratch page used by close barrier to ensure
		 * completion of previous writes
		 */
		pseudo_offset.bit.page_type = WRSM_MMAP_BARRIER_SCRATCH;
		prot = PROT_READ | PROT_WRITE;
		if ((importsegp->barrier_scratch_addr =
		    mmap64(NULL, WRSM_PAGESIZE, prot, MAP_SHARED,
			opened_ctrls_fd[ctrl_num].fd, pseudo_offset.val))
		    == MAP_FAILED) {
			DEBUGP(PLUGIN_WARN, ("librsmwrsm: mmap Barrier"
			    " scratch failed on controller number %d export"
			    " cnode %d errno %d.\n", ctrl_num,
			    pseudo_offset.bit.export_cnodeid, errno));
			return (seterr());
		}
		DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: mmap of  BARRIER Scratch "
		    " successfull addr = %p for importsegp %p \n",
		    importsegp->barrier_scratch_addr, importsegp));

		/*
		 * Local WCI error registers to check during barrier close, in
		 * particular, the plugin is currently only interested in
		 * wci_cluster_error_count that is assesible via ncslice page 0
		 */
		pseudo_offset.bit.page_type = WRSM_MMAP_BARRIER_REGS;
		prot = PROT_READ | PROT_WRITE;

		if ((importsegp->barrier_ncslice_addr =
		    mmap64(NULL, WRSM_PAGESIZE, prot, MAP_SHARED,
			opened_ctrls_fd[ctrl_num].fd, pseudo_offset.val))
		    == MAP_FAILED) {
			DEBUGP(PLUGIN_WARN, ("librsmwrsm: mmap Barrier"
			    " REGS failed on controller number %d export"
			    " cnode %ld.\n", ctrl_num, export_cnodeid));
			return (seterr());
		}

		DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: mmap of  BARRIER_REGS "
		    "succesfull addr = %p for importsegp %p\n",
		    importsegp->barrier_ncslice_addr, importsegp));
		/*
		 * the wci wrsm driver maps the rerouting and the route_counter
		 * and striping (refered to by the driver as link_stripesp)
		 * into one address space. the plugin mmaps that address space
		 * route_info_addr, and then, for clarity, reads them with more
		 * meaningful names.
		 */
		pseudo_offset.bit.page_type = WRSM_MMAP_RECONFIG;
		prot = PROT_READ;

		if ((importsegp->route_info_addr =
		    mmap64(NULL, WRSM_PAGESIZE, prot, MAP_SHARED,
			opened_ctrls_fd[ctrl_num].fd, pseudo_offset.val))
		    == MAP_FAILED) {
			DEBUGP(PLUGIN_WARN, ("LIBRSMWRSM: mmap reconfig cntr"
			    " failed on controller number %d export "
			    " cnode %ld.\n", ctrl_num, export_cnodeid));
			return (seterr());
		}
		/*
		 * a counter of the number of times the route have changed
		 * plugin needs to confirm that the number hasn't changed
		 * between a barrier open and a barrier close
		 */
		ASSERT(importsegp->route_info_addr);

		/* LINTED */
		importsegp->route_counterp = (uint32_t *)
		    importsegp->route_info_addr;
		/*
		 * if reroutingp is > 0, then  a rerouting in progress,
		 * barier_open and barrier_close need to check this.
		 */
		/* LINTED */
		importsegp->reroutingp = (uint32_t *)
		    (importsegp->route_info_addr + sizeof (uint32_t));

		/* needed to determine which stripe offsets to read */
		/* LINTED */
		importsegp->stripingp = (uint32_t *)
		    (importsegp->route_info_addr + (2 * sizeof (uint32_t)));

		DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: Mapped ROUTE info initial "
		    "addr is %p *route_counterp %d\n\t and rerouting %d "
		    "(should be 0) and striping DATA 0x%x for importsegp %p\n",
		    importsegp->route_info_addr, *importsegp->route_counterp,
		    *importsegp->reroutingp, *importsegp->stripingp,
		    importsegp));

		/*
		 * initialize init_route_counter. if init_route_counter doesn't
		 * ever differ from the drivers route_counter
		 * (*importsegp->route_counterp) we know that routing has
		 * not changed.
		 */

		importsegp->init_route_counter = *importsegp->route_counterp;
	}
	importsegp->barrier_mode = RSM_BARRIER_MODE_IMPLICIT; /* default */

	if (mutex_init(&importsegp->segmutex, USYNC_THREAD, NULL) != 0) {
		DEBUGP(PLUGIN_WARN, ("librsmwrsm: ERROR unable to allocate "
		    "space for mutex\n"));
		(void) munmap(importsegp->route_info_addr, WRSM_PAGESIZE);
		(void) munmap(importsegp->barrier_scratch_addr, WRSM_PAGESIZE);
		(void) munmap(importsegp->barrier_ncslice_addr, WRSM_PAGESIZE);
		return (RSMERR_INSUFFICIENT_MEM);
	}

	RSMNDI_SEG_SETPRIV(*im_memseg, importsegp);
	return (RSM_SUCCESS);
}


static int
wrsm_memseg_import_disconnect(rsm_memseg_import_handle_t im_memseg)
{
	plugin_importseg_t *importsegp;
	int error = RSM_SUCCESS;

	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: wrsm_memseg_import_disconnect\n"));
	importsegp  = (plugin_importseg_t *)RSMNDI_SEG_GETPRIV(im_memseg);
	ASSERT(importsegp);

	(void) mutex_destroy(&importsegp->segmutex);
	if (!importsegp->isloopback) {
		if (importsegp->route_info_addr == NULL) {
			DEBUGP(PLUGIN_WARN, ("librsmwrsm: WARNING:"
			    "route_info_addr is NULL\n"));
			error = RSMERR_BAD_SEG_HNDL;
		} else {
			(void) munmap(importsegp->route_info_addr,
			    WRSM_PAGESIZE);
		}
		if (importsegp->barrier_scratch_addr == NULL) {
			DEBUGP(PLUGIN_WARN, ("librsmwrsm: WARNING:"
			    "barrier_scratch_addr is NULL\n"));
			error = RSMERR_BAD_SEG_HNDL;
		} else {
			(void) munmap(importsegp->barrier_scratch_addr,
			    WRSM_PAGESIZE);
		}
		if (importsegp->barrier_ncslice_addr == NULL) {
			DEBUGP(PLUGIN_WARN, ("librsmwrsm: WARNING: "
			    "barrier_ncslice_addr is NULL\n"));
			error = RSMERR_BAD_SEG_HNDL;
		} else {
			(void) munmap(importsegp->barrier_ncslice_addr,
			    WRSM_PAGESIZE);
		}
	}
	free(importsegp);

	return (error);
}

/* ARGSUSED */
static int
wrsm_memseg_import_get8(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint8_t *datap, ulong_t rep_cnt, boolean_t swap)
{
	size_t len = (size_t)(sizeof (uint8_t) * rep_cnt);

	return (wrsm_memseg_import_get(im_memseg, offset, (void *)datap, len));
}

/* ARGSUSED */
static int
wrsm_memseg_import_get16(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint16_t *datap, ulong_t rep_cnt, boolean_t swap)
{
	size_t len = (size_t)(sizeof (uint16_t) * rep_cnt);

	/* Check for valid alignment */
	if ((((uint64_t)datap & 0x1) != 0) ||
	    (((uint64_t)offset & 0x1) != 0)) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}
	return (wrsm_memseg_import_get(im_memseg, offset, (void *)datap, len));
}

/* ARGSUSED */
static int
wrsm_memseg_import_get32(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint32_t *datap, ulong_t rep_cnt, boolean_t swap)
{
	size_t len = (size_t)(sizeof (uint32_t) * rep_cnt);

	/* Check for valid alignment */
	if ((((uint64_t)datap & 0x3) != 0) ||
	    (((uint64_t)offset & 0x3) != 0)) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}
	return (wrsm_memseg_import_get(im_memseg, offset, (void *)datap, len));
}

/* ARGSUSED */
static int
wrsm_memseg_import_get64(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint64_t *datap, ulong_t rep_cnt, boolean_t swap)
{
	size_t len = (size_t)(sizeof (uint64_t) * rep_cnt);

	/* Check for valid alignment */
	if ((((uint64_t)datap & 0x7) != 0) ||
	    (((uint64_t)offset & 0x7) != 0)) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}
	return (wrsm_memseg_import_get(im_memseg, offset, (void *)datap, len));
}

/*
 * from segment addr, get len bytes starting at offset returned in dst_addr
 * caller must gauruntee that the offset + len doesn't exceed segment size.
 */
static int
wrsm_memseg_import_get(rsm_memseg_import_handle_t im_memseg, off_t offset,
    void *dst_addr, size_t len)
{
	wrsmlib_raw_message_t cachelinebuf;
	caddr_t aligned_cacheline = (caddr_t)wrsmlib_align(&cachelinebuf);

	uint_t partial_cacheline;
	uint_t num_cachelines;
	int err = 0;
	caddr_t dp = dst_addr;
	plugin_importseg_t *importsegp;
	caddr_t seg;
	plugin_barrier_t bar_implicit;

#ifdef DEBUG
	int ctrl_num = RSMNDI_SEG_GETUNIT(im_memseg);
#endif /* DEBUG */

	DEBUGP(PLUGIN_GET, ("librsmwrsm: wrsm_memseg_import_get\n"));
	ASSERT(dst_addr);

	if (len == 0) {
		return (RSM_SUCCESS);
	}

	importsegp = (plugin_importseg_t *)RSMNDI_SEG_GETPRIV(im_memseg);
	ASSERT(importsegp);

#ifdef DEBUG
	DEBUGP(PLUGIN_GET, ("librsmwrsm: wrsm_memseg_import_get controller"
	    " num %d, segment_id %d\n", ctrl_num, importsegp->segment_id));
#endif

	if (importsegp->barrier_mode == RSM_BARRIER_MODE_IMPLICIT) {
		bar_implicit.importsegp = importsegp;
		DEBUGP(PLUGIN_GET, ("librsmwrsm: wrsm_get BARRIER IMPLICIT "
		    " mode \n"));
		if ((err = open_barrier(&bar_implicit)) != RSM_SUCCESS) {
			return (err);
		}
	}

	/* handle partial cacheline read at start of buffer */

	if (offset & WRSMLIB_CACHELINE_MASK) {
		DEBUGP(PLUGIN_GET, ("librsmwrsm: wrsm_memseg_import_get "
		    "partial, start of buf  at offset 0x%lx "
		    "length %ld \n", offset, len));
		/* get length within given cacheline */
		partial_cacheline = WRSMLIB_CACHELINE_SIZE - ((uint_t)offset &
		    WRSMLIB_CACHELINE_MASK);
		if (partial_cacheline > (uint_t)len)
			partial_cacheline = (uint_t)len;

		if ((err = small_get(im_memseg, offset, partial_cacheline, dp))
		    != RSM_SUCCESS) {
			if (importsegp->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				(void) close_barrier(&bar_implicit, B_FALSE);
				return (err);
			}
		}

		if (len == 0) {
			if (importsegp->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				return (close_barrier(&bar_implicit, B_FALSE));

			} else {
				return (RSM_SUCCESS);
			}
		}
		/* increment to next unread part in buffer */
		len -= partial_cacheline;
		dp += partial_cacheline;
		offset += partial_cacheline;
	}


	/* handle cacheline size reads */
	num_cachelines = (uint_t)(len >> WRSMLIB_CACHELINE_SHIFT);
	if (num_cachelines) {
		uint_t total_cachelines_size;
		total_cachelines_size = num_cachelines * WRSMLIB_CACHELINE_SIZE;
		DEBUGP(PLUGIN_GET, ("librsmwrsm: wrsm_memseg_import_get "
		    "for %d num_cachelines at  offset 0x%lx length %ld\n",
		    num_cachelines, offset, len));

		/* get virtual address of offset in mapped segment */
		seg = RSMNDI_GET_MAPADDR(im_memseg, offset);
		ASSERT(seg);

		if (((uint64_t)dp & (uint64_t)WRSMLIB_CACHELINE_MASK)
		    == 0) {
			/* aligned cacheline - this is to be fixed */
			if (!importsegp->isloopback) {
				wrsmlib_blkcopy(seg, dp, num_cachelines);
			} else {
				bcopy(seg, dp, total_cachelines_size);
			}
			dp += total_cachelines_size;
		} else {
			while (num_cachelines) {
				if (!importsegp->isloopback) {
					wrsmlib_blkcopy(seg, aligned_cacheline,
					    1);
					bcopy(aligned_cacheline, dp,
						WRSMLIB_CACHELINE_SIZE);
				} else {
					bcopy(seg, dp, WRSMLIB_CACHELINE_SIZE);
				}
				dp += WRSMLIB_CACHELINE_SIZE;
				seg += WRSMLIB_CACHELINE_SIZE;
				num_cachelines--;
			}
		}
		len -= total_cachelines_size;
		offset += total_cachelines_size;
	}

	/* get partial cacheline at end of buffer */
	if (len) {
		DEBUGP(PLUGIN_GET, ("librsmwrsm: wrsm_memseg_import_get "
		    "end of buf at  offset 0x%lx length %ld\n",
		    offset, len));
		if ((err = small_get(im_memseg, offset, (uint_t)len, dp))
		    != RSM_SUCCESS) {
			if (importsegp->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				(void) close_barrier(&bar_implicit, B_FALSE);
			}
			return (err);
		}
	}
	if (importsegp->barrier_mode == RSM_BARRIER_MODE_IMPLICIT) {
		err = close_barrier(&bar_implicit, B_FALSE);
	}
	return (err);
}

/* ARGSUSED */
static int
wrsm_memseg_import_put8(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint8_t *datap, ulong_t rep_cnt, boolean_t swap)
{
	size_t len = (size_t)(sizeof (uint8_t) * rep_cnt);

	return (wrsm_memseg_import_put(im_memseg, offset, (void *)datap, len));
}

/* ARGSUSED */
static int
wrsm_memseg_import_put16(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint16_t *datap, ulong_t rep_cnt, boolean_t swap)
{
	size_t len = (size_t)(sizeof (uint16_t) * rep_cnt);

	/* Check for valid alignment */
	if ((((uint64_t)datap & 0x1) != 0) ||
	    (((uint64_t)offset & 0x1) != 0)) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}
	return (wrsm_memseg_import_put(im_memseg, offset, (void *)datap, len));
}

/* ARGSUSED */
static int
wrsm_memseg_import_put32(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint32_t *datap, ulong_t rep_cnt, boolean_t swap)
{
	size_t len = (size_t)(sizeof (uint32_t) * rep_cnt);

	/* Check for valid alignment */
	if ((((uint64_t)datap & 0x3) != 0) ||
	    (((uint64_t)offset & 0x3) != 0)) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}
	return (wrsm_memseg_import_put(im_memseg, offset, (void *)datap, len));
}

/* ARGSUSED */
static int
wrsm_memseg_import_put64(rsm_memseg_import_handle_t im_memseg, off_t offset,
    uint64_t *datap, ulong_t rep_cnt, boolean_t swap)
{
	size_t len = (size_t)(sizeof (uint64_t) * rep_cnt);

	/* Check for valid alignment */
	if ((((uint64_t)datap & 0x7) != 0) ||
	    (((uint64_t)offset & 0x7) != 0)) {
		return (RSMERR_BAD_MEM_ALIGNMENT);
	}
	return (wrsm_memseg_import_put(im_memseg, offset, (void *)datap, len));
}

static int
wrsm_memseg_import_put(rsm_memseg_import_handle_t im_memseg, off_t offset,
    void *src_addr, size_t length)
{
	uint_t partial_cacheline;
	uint_t num_cachelines;
	int err = 0;
	plugin_importseg_t *importsegp;
	caddr_t seg;
	msg_pluginput_args_t args; /* to pass args to driver via ioctl */
	int ctrl_num;
	plugin_barrier_t bar_implicit;

	DEBUGP(PLUGIN_PUT, ("librsmwrsm: wrsm_memseg_import_put \n"));

	importsegp = RSMNDI_SEG_GETPRIV(im_memseg);
	ASSERT(importsegp);
	ASSERT(src_addr);

	ctrl_num = RSMNDI_SEG_GETUNIT(im_memseg);

	if (length == 0) {
		return (RSM_SUCCESS);
	}

	/* set unchanging fields in msgargs */
	args.remote_cnodeid = importsegp->export_cnodeid;
	args.segment_id = importsegp->segment_id;

	/* set msgargs.buf to src_addr - increment/decrement  using buf */
	args.buf = src_addr;

	if (importsegp->barrier_mode == RSM_BARRIER_MODE_IMPLICIT) {
		bar_implicit.importsegp  = importsegp;
		DEBUGP(PLUGIN_PUT, ("librsmwrsm: wrsm...put Implicit"
		    " Barriers\n"));
		if ((err = open_barrier(&bar_implicit)) !=
		    RSM_SUCCESS) {
			return (err);
		}
	}

	/*
	 * WARNING - if  thread-barriers are supported, small put errors must
	 * be recorded because these errors are currently recorded in the CESR
	 * register but they are cleared by the driver prior to return from
	 * the ioctl.
	 */

	/* handle partial line write at start of buff */
	if (offset & WRSMLIB_CACHELINE_MASK) {
		DEBUGP(PLUGIN_PUT, ("librsmwrsm: partial write, start "
		    " of buf for controller %d, and segid %d offset 0x%lx"
		    " length %ld buf addr %p export_cnode %d\n",
		    ctrl_num, args.segment_id, offset, length,
		    (void *)args.buf, importsegp->export_cnodeid));
		partial_cacheline = WRSMLIB_CACHELINE_SIZE - ((uint_t)offset &
		    WRSMLIB_CACHELINE_MASK);
		if (partial_cacheline > (uint_t)length)
			partial_cacheline = (uint_t)length;

		args.offset = offset;
		args.len = partial_cacheline;

		if (!importsegp->isloopback) {
			if ((err = ioctl(opened_ctrls_fd[ctrl_num].fd,
			    WRSM_CTLR_PLUGIN_SMALLPUT, &args)) != 0) {
				if (importsegp->barrier_mode ==
				    RSM_BARRIER_MODE_IMPLICIT) {
					(void) close_barrier(&bar_implicit,
								B_TRUE);
				}
				DEBUGP(PLUGIN_PUT, ("librsmwrsm: partial "
				    "write, start of buf for controller %d, "
				    "and segid %d IOCTL failed with err %d "
				    "errno is %d\n",
				    ctrl_num, args.segment_id, err, errno));
			return (RSMERR_BARRIER_FAILURE);
			}
		} else {
			seg = RSMNDI_GET_MAPADDR(im_memseg, offset);
			bcopy(args.buf, seg, partial_cacheline);
		}
		length -= partial_cacheline;
		args.buf += partial_cacheline;
		offset += partial_cacheline;

		if (length == 0) {
			if (importsegp->barrier_mode ==
			    RSM_BARRIER_MODE_IMPLICIT) {
				return (close_barrier(&bar_implicit, B_TRUE));
			} else {
				return (RSM_SUCCESS);
			}
		}
	}


	/* handle cacheline size writes */
	num_cachelines = (uint_t)(length >> WRSMLIB_CACHELINE_SHIFT);

	if (num_cachelines) {
		uint_t total_cachelines_size;
		total_cachelines_size = num_cachelines * WRSMLIB_CACHELINE_SIZE;

		seg = RSMNDI_GET_MAPADDR(im_memseg, offset);
		ASSERT(seg);
		DEBUGP(PLUGIN_PUT, ("librsmwrsm: full cachelines ctrl_num "
		    " %d offset 0x%lx length %ld \n", ctrl_num, offset,
		    length));
		if (importsegp->isloopback) {
			bcopy(args.buf, seg,
			    num_cachelines *  WRSMLIB_CACHELINE_SIZE);
		} else {
			/*
			 * args.buf (ie. src_addr) can be any alignment
			 * and dst is cacheline aligned so we can
			 * wrsmlib_blkwrite once to send all cachelines
			 */
			wrsmlib_blkwrite(args.buf, seg, num_cachelines);
		}
		args.buf += total_cachelines_size;
		length -= total_cachelines_size;
		offset += total_cachelines_size;
	}

	/* handle partial cacheline write at end of buffer */

	if (length) {
		DEBUGP(PLUGIN_PUT, ("librsmwrsm: writes at end of buffer "
		    "for ctrl_num %d segment id %d offset 0x%lx length "
		    "%d export cnode %d\n", ctrl_num, args.segment_id,
		    offset, length, importsegp->export_cnodeid));
		args.offset = offset;
		args.len = length;
		if (!importsegp->isloopback) {
			if ((err = ioctl(opened_ctrls_fd[ctrl_num].fd,
			    WRSM_CTLR_PLUGIN_SMALLPUT, &args)) != 0) {
				if (importsegp->barrier_mode ==
				    RSM_BARRIER_MODE_IMPLICIT) {
					(void) close_barrier(&bar_implicit,
								B_TRUE);
				}
				DEBUGP(PLUGIN_PUT, ("librsmwrsm: partial "
				    "write, end of buf for controller %d, "
				    "and segid %d IOCTL FAILED WITH ERR %d "
				    "errno is %d\n",
				ctrl_num, args.segment_id, err, errno));
				return (RSMERR_BARRIER_FAILURE);
			}
		} else {
			seg = RSMNDI_GET_MAPADDR(im_memseg, offset);
			bcopy(args.buf, seg, length);
		}
	}

	if (importsegp->barrier_mode == RSM_BARRIER_MODE_IMPLICIT) {
		return (close_barrier(&bar_implicit, B_TRUE));
	} else {
		return (RSM_SUCCESS);
	}

}

static int
wrsm_memseg_import_init_barrier(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_type_t type, rsm_barrier_handle_t barrier)
{
	plugin_barrier_t *bar;
	plugin_importseg_t *importsegp;

	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: wrsm...init_barrier \n"));

	importsegp = RSMNDI_SEG_GETPRIV(im_memseg);
	ASSERT(importsegp);

	bar = (plugin_barrier_t *)malloc(sizeof (plugin_barrier_t));
	if (bar == NULL) {
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}
	bar->importsegp = importsegp;
	bar->importsegp->barrier_type = type;
	bar->state = BARRIER_CLOSED;
	RSMNDI_BARRIER_SETPRIV(barrier, bar);
	return (RSM_SUCCESS);
}


static int
wrsm_memseg_import_open_barrier(rsm_barrier_handle_t barrier)
{
	plugin_barrier_t *bar;
	int err = 0;

	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: "
	    "wrsm_memseg_import_open_barrier\n"));
	bar = (plugin_barrier_t *)RSMNDI_BARRIER_GETPRIV(barrier);

	err = open_barrier(bar);

	return (err);
}

static int
wrsm_memseg_import_order_barrier(rsm_barrier_handle_t barrier)
{

	plugin_barrier_t *bar;
	int err = 0;

	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: "
	    "wrsm_memseg_import_order_barrier\n"));
	bar = (plugin_barrier_t *)RSMNDI_BARRIER_GETPRIV(barrier);
	err = close_barrier(bar, B_TRUE);
	/*
	 * to allow code reuse, we call close_barrier here since order_barrier
	 * and close barrier perform the same function expect that
	 * order_barrier does not change the barrier_state to CLOSED. We set
	 * it back to opened here so that close_barrier doesn't need to
	 * perform and additional check
	 */
	bar->state = BARRIER_OPENED;
	return (err);
}

static int
wrsm_memseg_import_close_barrier(rsm_barrier_handle_t barrier)
{
	plugin_barrier_t *bar;
	int err = 0;

	bar = (plugin_barrier_t *)RSMNDI_BARRIER_GETPRIV(barrier);

	err = close_barrier(bar, B_TRUE);

	return (err);


}

static int
wrsm_memseg_import_destroy_barrier(rsm_barrier_handle_t barrier)
{
	plugin_barrier_t *bar;

	DEBUGP(PLUGIN_BARRIER, ("librsmwrsm: "
	    "wrsm_memseg_import_destroy_barrier\n"));
	bar = (plugin_barrier_t *)RSMNDI_BARRIER_GETPRIV(barrier);
	if (bar)
		free(bar);
	return (RSM_SUCCESS);
}

static int
wrsm_memseg_import_get_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t *mode)
{
	plugin_importseg_t *importsegp;

	importsegp = (plugin_importseg_t *)RSMNDI_SEG_GETPRIV(im_memseg);
	ASSERT(importsegp);

	(void) mutex_lock(&importsegp->segmutex);
	*mode = importsegp->barrier_mode;
	(void) mutex_unlock(&importsegp->segmutex);

	return (RSM_SUCCESS);
}

static int
wrsm_memseg_import_set_mode(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_mode_t mode)
{
	plugin_importseg_t *importsegp;
	importsegp  = (plugin_importseg_t *)RSMNDI_SEG_GETPRIV(im_memseg);
	ASSERT(importsegp);

	(void) mutex_lock(&importsegp->segmutex);
	importsegp->barrier_mode = mode;
	(void) mutex_unlock(&importsegp->segmutex);

	return (RSM_SUCCESS);
}

static int
wrsm_memseg_import_putv(rsm_scat_gath_t *sg_io)
{
	rsm_iovec_t *iovec;
	int64_t i;
	int err = 0;

	DEBUGP(PLUGIN_PUT, ("librsmwrsm: wrsm_memseg_import_putv \n"));

	/*
	 * iovec for Wildcat always just uses local.vaddr
	 */
	iovec = sg_io->iovec;
	for (i = 0; i < sg_io->io_request_count; i++) {
		DEBUGP(PLUGIN_PUT, ("librsmwrsm: wrsm_memseg_import_putv "
		    "offset %d, length %d \n", iovec->local_offset,
		    iovec->transfer_length));
		err = wrsm_memseg_import_put(sg_io->remote_handle,
		    iovec->remote_offset,
		    iovec->local.vaddr + iovec->local_offset,
		    iovec->transfer_length);
		if (err != RSM_SUCCESS) {
			DEBUGP(PLUGIN_WARN, ("librsmwrsm: WARNING"
			    " wrsm_memseg_import_putv err detected\n"));
			/*
			 * set io_residual_count to the number of putv's that
			 * failed including this one.
			 */
			sg_io->io_residual_count =
			    sg_io->io_request_count - i + 1;
			return (err);
		}
		iovec++;
	}
	sg_io->io_residual_count = 0;
	return (err);
}

static int
wrsm_memseg_import_getv(rsm_scat_gath_t *sg_io)
{
	rsm_iovec_t *iovec;
	int64_t i;
	int err = 0;

	DEBUGP(PLUGIN_GET, ("librsmwrsm: wrsm_memseg_import_getv \n"));

	/*
	 * iovec for Wildcat always just uses local.vaddr
	 */
	iovec = sg_io->iovec;
	for (i = 0; i < sg_io->io_request_count; i++) {
		DEBUGP(PLUGIN_GET, ("librsmwrsm: wrsm_memseg_import_getv "
		    "offset %d, length %d \n", iovec->local_offset,
		    iovec->transfer_length));
		err = wrsm_memseg_import_get(sg_io->remote_handle,
		    iovec->remote_offset,
		    iovec->local.vaddr + iovec->local_offset,
		    iovec->transfer_length);
		if (err != RSM_SUCCESS) {
			DEBUGP(PLUGIN_WARN, ("librsmwrsm: WARNING"
			    " wrsm_memseg_import_getv err detected\n"));
			/*
			 * set io_residual_count to the number of getv's that
			 * failed including this one.
			 */
			sg_io->io_residual_count =
			    sg_io->io_request_count - i + 1;
			return (err);
		}
		iovec++;
	}
	sg_io->io_residual_count = 0;
	return (err);
}


/* ARGSUSED */
static int
wrsm_create_localmemory_handle(rsmapi_controller_handle_t controller,
    rsm_localmemory_handle_t *local_handle_p,
    caddr_t local_vaddr, size_t len)
{
	*local_handle_p = (rsm_localmemory_handle_t)local_vaddr;
	return (RSM_SUCCESS);
}

/* ARGSUSED */
static int
wrsm_free_localmemory_handle(rsm_localmemory_handle_t local_handle)
{
	return (RSM_SUCCESS);
}


static int
wrsm_register_lib_funcs(rsm_lib_funcs_t *libfuncs)
{
	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: wrsm_register_lib_funcs \n"));
	rsm_lib_funcs = libfuncs;
	return (RSM_SUCCESS);
}


static int
wrsm_get_lib_attr(rsm_ndlib_attr_t **libattr)
{
	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: wrsm_get_lib_attr\n"));
	*libattr = &wrsm_rsm_ndlib_attr;
	return (RSM_SUCCESS);
}



/*
 * the kernel will call the drivers close only on the last close of
 * for all open instances. Hence, this close routines spares the kernel
 * the added work, and only request a close on the last  close. By doing
 * this, we save ourselves the hassle of keeping track of additional
 * fd.
 */
static int
wrsm_closedevice(rsmapi_controller_handle_t controller)
{
	int ctrl_num;

	ctrl_num = (int)RSMNDI_CNTRLR_GETUNIT(controller);
	DEBUGP(PLUGIN_DEBUG, ("librsmwrsm: wrsm_closedevice controller "
	    "%d\n", ctrl_num));

	if (opened_ctrls_fd[ctrl_num].open_controller_count > 0) {
		if ((--opened_ctrls_fd[ctrl_num].open_controller_count) == 0) {
			(void) close(opened_ctrls_fd[ctrl_num].fd);
			opened_ctrls_fd[ctrl_num].fd = -1;
		}
	}
	return (RSM_SUCCESS);

}
