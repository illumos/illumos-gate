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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/mdb_modapi.h>
#include <sys/scsi/scsi.h>
#include <sys/dkio.h>
#include <sys/taskq.h>
#include <sys/scsi/targets/sddef.h>

/* Represents global soft state data in walk_step, walk_init */
#define	SD_DATA(param)	((sd_str_p)wsp->walk_data)->param

/* Represents global soft state data in callback and related routines */
#define	SD_DATA_IN_CBACK(param)	((sd_str_p)walk_data)->param

#define	SUCCESS			WALK_NEXT
#define	FAIL			WALK_ERR

/*
 * Primary attribute struct for buf extensions.
 */
struct __ddi_xbuf_attr {
	kmutex_t	xa_mutex;
	size_t		xa_allocsize;
	uint32_t	xa_pending;	/* call to xbuf_iostart() is iminent */
	uint32_t	xa_active_limit;
	uint32_t	xa_active_count;
	uint32_t	xa_active_lowater;
	struct buf	*xa_headp;	/* FIFO buf queue head ptr */
	struct buf	*xa_tailp;	/* FIFO buf queue tail ptr */
	kmutex_t	xa_reserve_mutex;
	uint32_t	xa_reserve_limit;
	uint32_t	xa_reserve_count;
	void		*xa_reserve_headp;
	void		(*xa_strategy)(struct buf *, void *, void *);
	void		*xa_attr_arg;
	timeout_id_t	xa_timeid;
	taskq_t		*xa_tq;
};

/*
 * Provides soft state information like the number of elements, pointer
 * to soft state elements etc
 */
typedef struct i_ddi_soft_state sd_state_str_t, *sd_state_str_ptr;

/* structure to store soft state statistics */
typedef struct sd_str {
	void		*sd_state;
	uintptr_t	current_root;
	int		current_list_count;
	int		valid_root_count;
	int		silent;
	sd_state_str_t	sd_state_data;
} sd_str_t, *sd_str_p;


/*
 *    Function: buf_avforw_walk_init
 *
 * Description: MDB calls the init function to initiate the walk,
 *		in response to mdb_walk() function called by the
 *		dcmd 'buf_avforw' or when the user executes the
 *		walk dcmd 'address::walk buf_avforw'.
 *
 *   Arguments: new mdb_walk_state_t structure. A new structure is
 *		created for each walk, so that multiple instances of
 *		the walker can be active simultaneously.
 */
static int
buf_avforw_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("buffer address required with the command\n");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (buf_t), UM_SLEEP);
	return (WALK_NEXT);
}


/*
 *    Function: buf_avforw_walk_step
 *
 * Description: The step function is invoked by the walker during each
 *		iteration. Its primary job is to determine the address
 *		of the next 'buf_avforw' object, read in the local copy
 *		of this object, call the callback 'buf_callback' function,
 *		and return its status. The iteration is terminated when
 *		the walker encounters a null queue pointer which signifies
 *		end of queue.
 *
 *   Arguments: mdb_walk_state_t structure
 */
static int
buf_avforw_walk_step(mdb_walk_state_t *wsp)
{
	int		status;

	/*
	 * if walk_addr is null then it effectively means an end of all
	 * buf structures, hence end the iterations.
	 */
	if (wsp->walk_addr == 0) {
		return (WALK_DONE);
	}

	/*
	 * Read the contents of the current object, invoke the callback
	 * and assign the next objects address to mdb_walk_state_t structure.
	 */
	if (mdb_vread(wsp->walk_data, sizeof (buf_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read buf at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
							    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)(((buf_t *)wsp->walk_data)->av_forw);

	return (status);
}

/*
 *    Function: buf_callback
 *
 * Description: This is the callback function called by the 'buf_avforw'
 *		walker when 'buf_avforw' dcmd is invoked.
 *		It is called during each walk step. It displays the contents
 *		of the current object (addr) passed to it by the step
 *		function. It also prints the header and footer during the
 *		first and the last iteration of the walker.
 *
 *   Arguments: addr -> current buf_avforw objects address.
 *		walk_data -> private storage for the walker.
 *		buf_entries -> private data for the callback. It represents
 *		the count of objects processed so far.
 */
static int
buf_callback(uintptr_t addr, const void *walk_data, void *buf_entries)
{
	int	*count = (int *)buf_entries;

	/*
	 * If this is the first invocation of the command, print a
	 * header line for the output that will follow.
	 */
	if (*count == 0) {
		mdb_printf("============================\n");
		mdb_printf("Walking buf list via av_forw\n");
		mdb_printf("============================\n");
	}

	/*
	 * read the object and print the contents.
	 */
	mdb_set_dot(addr);
	mdb_eval("$<buf");

	mdb_printf("---\n");
	(*count)++;

	/* if this is the last entry and print the footer */
	if (((buf_t *)walk_data)->av_forw == NULL) {
		mdb_printf("---------------------------\n");
		mdb_printf("Processed %d Buf entries\n", *count);
		mdb_printf("---------------------------\n");
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

/*
 *    Function: buf_avforw_walk_fini
 *
 * Description: The buf_avforw_walk_fini is called when the walk is terminated
 *		in response to WALK_DONE in buf_avforw_walk_step. It frees
 *		the walk_data structure.
 *
 *   Arguments: mdb_walk_state_t structure
 */
static void
buf_avforw_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (buf_t));
}

/*
 *    Function: dump_xbuf_attr
 *
 * Description: Prints the contents of Xbuf queue.
 *
 *   Arguments: object contents pointer and address.
 */
static void
dump_xbuf_attr(struct __ddi_xbuf_attr *xba_ptr, uintptr_t mem_addr)
{
	mdb_printf("0x%8lx:\tmutex\t\tallocsize\tpending\n",
		mem_addr + offsetof(struct __ddi_xbuf_attr, xa_mutex));

	mdb_printf("           \t%lx\t\t%d\t\t%d\n",
		xba_ptr->xa_mutex._opaque[0], xba_ptr->xa_allocsize,
							xba_ptr->xa_pending);
	mdb_printf("0x%8lx:\tactive_limit\tactive_count\tactive_lowater\n",
		mem_addr + offsetof(struct __ddi_xbuf_attr, xa_active_limit));

	mdb_printf("           \t%lx\t\t%lx\t\t%lx\n",
		xba_ptr->xa_active_limit, xba_ptr->xa_active_count,
						xba_ptr->xa_active_lowater);
	mdb_printf("0x%8lx:\theadp\t\ttailp\n",
		mem_addr + offsetof(struct __ddi_xbuf_attr, xa_headp));

	mdb_printf("           \t%lx%c\t%lx\n",
		xba_ptr->xa_headp, (xba_ptr->xa_headp == 0?'\t':' '),
							xba_ptr->xa_tailp);
	mdb_printf(
	"0x%8lx:\treserve_mutex\treserve_limit\treserve_count\treserve_headp\n",
		mem_addr + offsetof(struct __ddi_xbuf_attr, xa_reserve_mutex));

	mdb_printf("           \t%lx\t\t%lx\t\t%lx\t\t%lx\n",
		xba_ptr->xa_reserve_mutex._opaque[0], xba_ptr->xa_reserve_limit,
		xba_ptr->xa_reserve_count, xba_ptr->xa_reserve_headp);

	mdb_printf("0x%8lx:\ttimeid\t\ttq\n",
		mem_addr + offsetof(struct __ddi_xbuf_attr, xa_timeid));

	mdb_printf("           \t%lx%c\t%lx\n",
		xba_ptr->xa_timeid, (xba_ptr->xa_timeid == 0?'\t':' '),
								xba_ptr->xa_tq);
}

/*
 *    Function: init_softstate_members
 *
 * Description: Initialize mdb_walk_state_t structure with either 'sd' or
 *		'ssd' related information.
 *
 *   Arguments: new mdb_walk_state_t structure
 */
static int
init_softstate_members(mdb_walk_state_t *wsp)
{
	wsp->walk_data = mdb_alloc(sizeof (sd_str_t), UM_SLEEP);

	/*
	 * store the soft state statistics variables like non-zero
	 * soft state entries, base address, actual count of soft state
	 * processed etc.
	 */
	SD_DATA(sd_state) = (sd_state_str_ptr)wsp->walk_addr;

	SD_DATA(current_list_count) = 0;
	SD_DATA(valid_root_count) = 0;

	if (mdb_vread((void *)&SD_DATA(sd_state_data),
			sizeof (sd_state_str_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to sd_state at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(SD_DATA(sd_state_data.array));

	SD_DATA(current_root) = wsp->walk_addr;
	return (WALK_NEXT);
}

#if (!defined(__fibre))
/*
 *    Function: sd_state_walk_init
 *
 * Description: MDB calls the init function to initiate the walk,
 *		in response to mdb_walk() function called by the
 *		dcmd 'sd_state' or when the user executes the
 *		walk dcmd '::walk sd_state'.
 *		The init function initializes the walker to either
 *		the user specified address or the default kernel
 *		'sd_state' pointer.
 *
 *   Arguments: new mdb_walk_state_t structure
 */
static int
sd_state_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0 &&
	    mdb_readvar(&wsp->walk_addr, "sd_state") == -1) {
		mdb_warn("failed to read 'sd_state'");
		return (WALK_ERR);
	}

	return (init_softstate_members(wsp));
}

#else

/*
 *    Function: ssd_state_walk_init
 *
 * Description: MDB calls the init function to initiate the walk,
 *		in response to mdb_walk() function called by the
 *		dcmd 'ssd_state' or when the user executes the
 *		walk dcmd '::walk ssd_state'.
 *		The init function initializes the walker to either
 *		the user specified address or the default kernel
 *		'ssd_state' pointer.
 *
 *   Arguments: new mdb_walk_state_t structure
 */
static int
ssd_state_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "ssd_state") == -1) {
		mdb_warn("failed to read 'ssd_state'");
		return (WALK_ERR);
	}

	return (init_softstate_members(wsp));
}
#endif


/*
 *    Function: sd_state_walk_step
 *
 * Description: The step function is invoked by the walker during each
 *		iteration. Its primary job is to determine the address
 *		of the next 'soft state' object, read in the local copy
 *		of this object, call the callback 'sd_callback' function,
 *		and return its status. The iteration is terminated when
 *		the soft state counter equals the total soft state count
 *		obtained initially.
 *
 *   Arguments: mdb_walk_state_t structure
 */
static int
sd_state_walk_step(mdb_walk_state_t *wsp)
{
	int		status;
	void		*tp;

	/*
	 * If all the soft state entries have been processed then stop
	 * future iterations.
	 */
	if (SD_DATA(current_list_count) >= SD_DATA(sd_state_data.n_items)) {
		return (WALK_DONE);
	}

	/*
	 * read the object contents, invoke the callback and set the
	 * mdb_walk_state_t structure to the next object.
	 */
	if (mdb_vread(&tp, sizeof (void *), wsp->walk_addr) == -1) {
		mdb_warn("failed to read at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback((uintptr_t)tp, wsp->walk_data,
							wsp->walk_cbdata);
	if (tp != 0) {
		/* Count the number of non-zero un entries. */
		SD_DATA(valid_root_count++);
	}

	wsp->walk_addr += sizeof (void *);
	SD_DATA(current_list_count++);
	return (status);
}


/*
 *    Function: sd_state_walk_fini
 *
 * Description: The sd_state_walk_fini is called when the walk is terminated
 *		in response to WALK_DONE in sd_state_walk_step. It frees
 *		the walk_data structure.
 *
 *   Arguments: mdb_walk_state_t structure
 */
static void
sd_state_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (sd_str_t));
}

/*
 *    Function: process_semo_sleepq
 *
 * Description: Iterate over the semoclose wait Q members of the soft state.
 *		Print the contents of each member. In case of silent mode
 *		the contents are avoided and only the address is printed.
 *
 *   Arguments: starting queue address, print mode.
 */
static int
process_semo_sleepq(uintptr_t	walk_addr, int silent)
{
	uintptr_t	rootBuf;
	buf_t		currentBuf;
	int		semo_sleepq_count = 0;

	/* Set up to process the device's semoclose wait Q */
	rootBuf = walk_addr;

	if (!silent) {
		mdb_printf("\nSEMOCLOSE SLEEP Q:\n");
		mdb_printf("----------\n");
	}

	mdb_printf("SEMOCLOSE sleep Q head: %lx\n", rootBuf);

	while (rootBuf) {
		/* Process the device's cmd. wait Q */
		if (!silent) {
			mdb_printf("SEMOCLOSE SLEEP Q list entry:\n");
			mdb_printf("------------------\n");
		}

		if (mdb_vread((void *)&currentBuf, sizeof (buf_t),
							rootBuf) == -1) {
			mdb_warn("failed to read buf at %p", rootBuf);
			return (FAIL);
		}

		if (!silent) {
			mdb_set_dot(rootBuf);
			mdb_eval("$<buf");
			mdb_printf("---\n");
		}
		++semo_sleepq_count;
		rootBuf = (uintptr_t)currentBuf.av_forw;
	}

	if (rootBuf == 0) {
		mdb_printf("------------------------------\n");
		mdb_printf("Processed %d SEMOCLOSE SLEEP Q entries\n",
							semo_sleepq_count);
		mdb_printf("------------------------------\n");

	}
	return (SUCCESS);
}

/*
 *    Function: process_sdlun_waitq
 *
 * Description: Iterate over the wait Q members of the soft state.
 *		Print the contents of each member. In case of silent mode
 *		the contents are avoided and only the address is printed.
 *
 *   Arguments: starting queue address, print mode.
 */
static int
process_sdlun_waitq(uintptr_t walk_addr, int silent)
{
	uintptr_t	rootBuf;
	buf_t		currentBuf;
	int		sdLunQ_count = 0;

	rootBuf = walk_addr;

	if (!silent) {
		mdb_printf("\nUN WAIT Q:\n");
		mdb_printf("----------\n");
	}
	mdb_printf("UN wait Q head: %lx\n", rootBuf);

	while (rootBuf) {
		/* Process the device's cmd. wait Q */
		if (!silent) {
			mdb_printf("UN WAIT Q list entry:\n");
			mdb_printf("------------------\n");
		}

		if (mdb_vread(&currentBuf, sizeof (buf_t),
						(uintptr_t)rootBuf) == -1) {
			mdb_warn("failed to read buf at %p",
							(uintptr_t)rootBuf);
			return (FAIL);
		}

		if (!silent) {
			mdb_set_dot(rootBuf);
			mdb_eval("$<buf");
			mdb_printf("---\n");
		}

		rootBuf = (uintptr_t)currentBuf.av_forw;
		++sdLunQ_count;
	}

	if (rootBuf == 0) {
		mdb_printf("------------------------------\n");
		mdb_printf("Processed %d UN WAIT Q entries\n", sdLunQ_count);
		mdb_printf("------------------------------\n");
	}

	return (SUCCESS);
}

/*
 *    Function: process_xbuf
 *
 * Description: Iterate over the Xbuf Attr and Xbuf Attr wait Q of the soft
 *		state.
 *		Print the contents of each member. In case of silent mode
 *		the contents are avoided and only the address is printed.
 *
 *   Arguments: starting xbuf address, print mode.
 */
static int
process_xbuf(uintptr_t xbuf_attr, int silent)
{
	struct __ddi_xbuf_attr	xba;
	buf_t			xba_current;
	void			*xba_root;
	int			xbuf_q_count = 0;

	if (xbuf_attr == 0) {
		mdb_printf("---------------------------\n");
		mdb_printf("No XBUF ATTR entry\n");
		mdb_printf("---------------------------\n");
		return (SUCCESS);
	}

	/* Process the Xbuf Attr struct for a device. */
	if (mdb_vread((void *)&xba, sizeof (struct __ddi_xbuf_attr),
							xbuf_attr) == -1) {
		mdb_warn("failed to read xbuf_attr at %p", xbuf_attr);
		return (FAIL);
	}

	if (!silent) {
		mdb_printf("\nXBUF ATTR:\n");
		mdb_printf("----------\n");

		dump_xbuf_attr(&xba, xbuf_attr);
		mdb_printf("---\n");

		mdb_printf("\nXBUF Q:\n");
		mdb_printf("-------\n");
	}

	mdb_printf("xbuf Q head: %lx\n", xba.xa_headp);

	xba_root = (void *) xba.xa_headp;

	/* Process the Xbuf Attr wait Q, if there are any entries. */
	while ((uintptr_t)xba_root) {
		if (!silent) {
			mdb_printf("XBUF_Q list entry:\n");
			mdb_printf("------------------\n");
		}

		if (mdb_vread((void *)&xba_current, sizeof (buf_t),
						(uintptr_t)xba_root) == -1) {
			mdb_warn("failed to read buf at %p",
							(uintptr_t)xba_root);
			return (FAIL);
		}
		if (!silent) {
			mdb_set_dot((uintptr_t)xba_root);
			mdb_eval("$<buf");
			mdb_printf("---\n");
		}
		++xbuf_q_count;

		xba_root = (void *)xba_current.av_forw;
	}

	if (xba_root == NULL) {
		mdb_printf("---------------------------\n");
		mdb_printf("Processed %d XBUF Q entries\n", xbuf_q_count);
		mdb_printf("---------------------------\n");
	}
	return (SUCCESS);
}

/*
 *    Function: print_footer
 *
 * Description: Prints the footer if all the soft state entries are processed.
 *
 *   Arguments: private storage of the walker.
 */
static void
print_footer(const void *walk_data)
{
	if (SD_DATA_IN_CBACK(current_list_count) >=
			(SD_DATA_IN_CBACK(sd_state_data.n_items) - 1)) {
		mdb_printf("---------------------------\n");
		mdb_printf("Processed %d UN softstate entries\n",
					SD_DATA_IN_CBACK(valid_root_count));
		mdb_printf("---------------------------\n");
	}
}

/*
 *    Function: sd_callback
 *
 * Description: This is the callback function called by the
 *		'sd_state/ssd_state' walker when 'sd_state/ssd_state' dcmd
 *		invokes the walker.
 *		It is called during each walk step. It displays the contents
 *		of the current soft state object (addr) passed to it by the
 *		step function. It also prints the header and footer during the
 *		first and the last step of the walker.
 *		The contents of the soft state also includes various queues
 *		it includes like Xbuf, semo_close, sdlun_waitq.
 *
 *   Arguments: addr -> current soft state objects address.
 *		walk_data -> private storage for the walker.
 *		flg_silent -> private data for the callback. It represents
 *		the silent mode of operation.
 */
static int
sd_callback(uintptr_t addr, const void *walk_data, void *flg_silent)
{
	struct sd_lun	sdLun;
	int		silent = *(int *)flg_silent;

	/*
	 * If this is the first invocation of the command, print a
	 * header line for the output that will follow.
	 */
	if (SD_DATA_IN_CBACK(current_list_count) == 0) {
		mdb_printf("walk_addr = %lx\n", SD_DATA_IN_CBACK(sd_state));
		mdb_printf("walking sd_state units via ptr: %lx\n",
					SD_DATA_IN_CBACK(current_root));
		mdb_printf("%d entries in sd_state table\n",
				SD_DATA_IN_CBACK(sd_state_data.n_items));
	}

	mdb_printf("\nun %d: %lx\n", SD_DATA_IN_CBACK(current_list_count),
									addr);

	mdb_printf("--------------\n");

	/* if null soft state iterate over to next one */
	if (addr == 0) {
		print_footer(walk_data);
		return (SUCCESS);
	}
	/*
	 * For each buf, we need to read the sd_lun struct,
	 * and then print out its contents, and get the next.
	 */
	else if (mdb_vread(&sdLun, sizeof (struct sd_lun), (uintptr_t)addr) ==
	    sizeof (sdLun)) {
		if (!silent) {
			mdb_set_dot(addr);
			mdb_eval("$<sd_lun");
			mdb_printf("---\n");
		}
	} else {
		mdb_warn("failed to read softstate at %p", addr);
		return (FAIL);
	}

	/* process device Xbuf Attr struct and wait Q */
	process_xbuf((uintptr_t)sdLun.un_xbuf_attr, silent);

	/* process device cmd wait Q */
	process_sdlun_waitq((uintptr_t)sdLun.un_waitq_headp, silent);

	/* process device semoclose wait Q */
	if (sdLun.un_semoclose._opaque[1] == 0) {
		process_semo_sleepq((uintptr_t)sdLun.un_semoclose._opaque[0],
									silent);
	}

	/* print the actual number of soft state processed */
	print_footer(walk_data);
	return (SUCCESS);
}

#if (!defined(__fibre))
/*
 *    Function: dcmd_sd_state
 *
 * Description: Scans through the sd soft state entries and prints their
 *		contents including of various queues it contains. It uses
 *		'sd_state' walker to perform a global walk. If a particular
 *		soft state address is specified than it performs the above job
 *		itself (local walk).
 *
 *   Arguments: addr -> user specified address or NULL if no address is
 *			specified.
 *		flags -> integer reflecting whether an address was specified,
 *			 or if it was invoked by the walker in a loop etc.
 *		argc -> the number of arguments supplied to the dcmd.
 *		argv -> the actual arguments supplied by the user.
 */
/*ARGSUSED*/
static int
dcmd_sd_state(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct sd_lun	sdLun;
	uint_t		silent = 0;

	/* Enable the silent mode if '-s' option specified the user */
	if (mdb_getopts(argc, argv, 's', MDB_OPT_SETBITS, TRUE, &silent, NULL)
							!= argc) {
		return (DCMD_USAGE);
	}

	/*
	 * If no address is specified on the command line, perform
	 * a global walk invoking 'sd_state' walker. If a particular address
	 * is specified then print the soft state and its queues.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_walk("sd_state", sd_callback, (void *)&silent);
		return (DCMD_OK);
	} else {
		mdb_printf("\nun: %lx\n", addr);
		mdb_printf("--------------\n");

		/* read the sd_lun struct and print the contents */
		if (mdb_vread(&sdLun, sizeof (struct sd_lun),
		    (uintptr_t)addr) == sizeof (sdLun)) {

			if (!silent) {
				mdb_set_dot(addr);
				mdb_eval("$<sd_lun");
				mdb_printf("---\n");
			}
		} else {
			mdb_warn("failed to read softstate at %p", addr);
			return (DCMD_OK);
		}

		/* process Xbuf Attr struct and wait Q for the soft state */
		process_xbuf((uintptr_t)sdLun.un_xbuf_attr, silent);

		/* process device' cmd wait Q */
		process_sdlun_waitq((uintptr_t)sdLun.un_waitq_headp, silent);

		/* process device's semoclose wait Q */
		if (sdLun.un_semoclose._opaque[1] == 0) {
			process_semo_sleepq(
			(uintptr_t)sdLun.un_semoclose._opaque[0], silent);
		}
	}
	return (DCMD_OK);
}

#else

/*
 *    Function: dcmd_ssd_state
 *
 * Description: Scans through the ssd soft state entries and prints their
 *		contents including of various queues it contains. It uses
 *		'ssd_state' walker to perform a global walk. If a particular
 *		soft state address is specified than it performs the above job
 *		itself (local walk).
 *
 *   Arguments: addr -> user specified address or NULL if no address is
 *			specified.
 *		flags -> integer reflecting whether an address was specified,
 *			 or if it was invoked by the walker in a loop etc.
 *		argc -> the number of arguments supplied to the dcmd.
 *		argv -> the actual arguments supplied by the user.
 */
/*ARGSUSED*/
static int
dcmd_ssd_state(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct sd_lun	sdLun;
	uint_t		silent = 0;

	/* Enable the silent mode if '-s' option specified the user */
	if (mdb_getopts(argc, argv, 's', MDB_OPT_SETBITS, TRUE, &silent, NULL)
							!= argc) {
		return (DCMD_USAGE);
	}

	/*
	 * If no address is specified on the command line, perform
	 * a global walk invoking 'sd_state' walker. If a particular address
	 * is specified then print the soft state and its queues.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_walk("ssd_state", sd_callback, (void *)&silent);
		return (DCMD_OK);
	} else {
		mdb_printf("\nun: %lx\n", addr);
		mdb_printf("--------------\n");

		/* read the sd_lun struct and print the contents */
		if (mdb_vread(&sdLun, sizeof (struct sd_lun),
		    (uintptr_t)addr) == sizeof (sdLun)) {
			if (!silent) {
				mdb_set_dot(addr);
				mdb_eval("$<sd_lun");
				mdb_printf("---\n");
			}
		} else {
			mdb_warn("failed to read softstate at %p", addr);
			return (DCMD_OK);
		}

		/* process Xbuf Attr struct and wait Q for the soft state */
		process_xbuf((uintptr_t)sdLun.un_xbuf_attr, silent);

		/* process device' cmd wait Q */
		process_sdlun_waitq((uintptr_t)sdLun.un_waitq_headp, silent);

		/* process device's semoclose wait Q */
		if (sdLun.un_semoclose._opaque[1] == 0) {
			process_semo_sleepq(
			(uintptr_t)sdLun.un_semoclose._opaque[0], silent);
		}
	}
	return (DCMD_OK);
}
#endif

/*
 *    Function: dcmd_buf_avforw
 *
 * Description: Scans through the buf list via av_forw and prints
 *		their contents.
 *		It uses the 'buf_avforw' walker to perform the walk.
 *
 *   Arguments: addr -> user specified address.
 *		flags -> integer reflecting whether an address was specified,
 *			 or if it was invoked by the walker in a loop etc.
 *		argc -> the number of arguments supplied to the dcmd.
 *		argv -> the actual arguments supplied by the user.
 */
/*ARGSUSED*/
static int
dcmd_buf_avforw(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int	buf_entries = 0;

	/* it does not take any arguments */
	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * If no address was specified on the command line, print the
	 * error msg, else scan and
	 * print out all the buffers available by invoking buf_avforw walker.
	 */
	if ((flags & DCMD_ADDRSPEC)) {
		mdb_pwalk("buf_avforw", buf_callback, (void *)&buf_entries,
									addr);
		return (DCMD_OK);
	} else {
		mdb_printf("buffer address required with the command\n");
	}

	return (DCMD_USAGE);
}

/*
 * MDB module linkage information:
 *
 * List of structures describing our dcmds, a list of structures
 * describing our walkers, and a function named _mdb_init to return a pointer
 * to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "buf_avforw", ":", "buf_t list via av_forw", dcmd_buf_avforw},
#if (!defined(__fibre))
	{ "sd_state", "[-s]", "sd soft state list", dcmd_sd_state},
#else
	{ "ssd_state", "[-s]", "ssd soft state list", dcmd_ssd_state},
#endif
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "buf_avforw", "walk list of buf_t structures via av_forw",
	buf_avforw_walk_init, buf_avforw_walk_step, buf_avforw_walk_fini },
#if (!defined(__fibre))
	{ "sd_state", "walk all sd soft state queues",
		sd_state_walk_init, sd_state_walk_step, sd_state_walk_fini },
#else
	{ "ssd_state", "walk all ssd soft state queues",
		ssd_state_walk_init, sd_state_walk_step, sd_state_walk_fini },
#endif
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

/*
 *    Function: _mdb_init
 *
 * Description: Returns mdb_modinfo_t structure which provides linkage and
 *		module identification information to the debugger.
 *
 *   Arguments: void
 */
const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
