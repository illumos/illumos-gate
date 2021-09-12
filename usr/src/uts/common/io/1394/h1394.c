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

/*
 * h1394.c
 *    1394 Services Layer HAL Interface
 *    Contains all of the routines that define the HAL to Services Layer
 *    interface
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sunndi.h>
#include <sys/cmn_err.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/time.h>
#include <sys/devctl.h>
#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>


extern struct bus_ops nx1394_busops;
extern int nx1394_define_events(s1394_hal_t *hal);
extern void nx1394_undefine_events(s1394_hal_t *hal);
extern int s1394_ignore_invalid_gap_cnt;

/*
 * Function:    h1394_init()
 * Input(s):    modlp			The structure containing all of the
 *					    HAL's relevant information
 *
 * Output(s):
 *
 * Description:	h1394_init() is called by the HAL's _init function and is
 *		used to set up the nexus bus ops.
 */
int
h1394_init(struct modlinkage *modlp)
{
	struct dev_ops	*devops;

	devops = ((struct modldrv *)(modlp->ml_linkage[0]))->drv_dev_ops;
	devops->devo_bus_ops = &nx1394_busops;

	return (0);
}

/*
 * Function:    h1394_fini()
 * Input(s):    modlp			The structure containing all of the
 *					    HAL's relevant information
 *
 * Output(s):
 *
 * Description:	h1394_fini() is called by the HAL's _fini function and is
 *		used to NULL out the nexus bus ops.
 */
void
h1394_fini(struct modlinkage *modlp)
{
	struct dev_ops	*devops;

	devops = ((struct modldrv *)(modlp->ml_linkage[0]))->drv_dev_ops;
	devops->devo_bus_ops = NULL;
}

/*
 * Function:    h1394_attach()
 * Input(s):    halinfo			The structure containing all of the
 *					    HAL's relevant information
 *		cmd			The ddi_attach_cmd_t that tells us
 *					    if this is a RESUME or a regular
 *					    attach() call
 *
 * Output(s):	sl_private		The HAL "handle" to be used for
 *					    all subsequent calls into the
 *					    1394 Software Framework
 *
 * Description:	h1394_attach() registers the HAL with the 1394 Software
 *		Framework.  It returns a HAL "handle" to be used for
 *		all subsequent calls into the 1394 Software Framework.
 */
int
h1394_attach(h1394_halinfo_t *halinfo, ddi_attach_cmd_t cmd, void **sl_private)
{
	s1394_hal_t	*hal;
	int		ret;
	char		buf[32];
	uint_t		cmd_size;

	ASSERT(sl_private != NULL);

	/* If this is a DDI_RESUME, return success */
	if (cmd == DDI_RESUME) {
		hal = (s1394_hal_t *)(*sl_private);
		/* If we have a 1394A PHY, then reset the "contender bit" */
		if (hal->halinfo.phy == H1394_PHY_1394A)
			(void) HAL_CALL(hal).set_contender_bit(
			    hal->halinfo.hal_private);
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/* Allocate space for s1394_hal_t */
	hal = kmem_zalloc(sizeof (s1394_hal_t), KM_SLEEP);

	/* Setup HAL state */
	hal->hal_state = S1394_HAL_INIT;

	/* Copy in the halinfo struct */
	hal->halinfo = *halinfo;

	/* Create the topology tree mutex */
	mutex_init(&hal->topology_tree_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Create the Cycle Mater timer mutex */
	mutex_init(&hal->cm_timer_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Initialize the Isoch CEC list */
	hal->isoch_cec_list_head = NULL;
	hal->isoch_cec_list_tail = NULL;
	mutex_init(&hal->isoch_cec_list_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Initialize the Bus Manager node ID mutex and cv */
	mutex_init(&hal->bus_mgr_node_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);
	cv_init(&hal->bus_mgr_node_cv, NULL, CV_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Initialize the Bus Manager node ID - "-1" means undetermined */
	hal->bus_mgr_node	= -1;
	hal->incumbent_bus_mgr	= B_FALSE;

	/* Initialize the Target list */
	hal->target_head = NULL;
	hal->target_tail = NULL;
	rw_init(&hal->target_list_rwlock, NULL, RW_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Setup Request Q's */
	hal->outstanding_q_head	= NULL;
	hal->outstanding_q_tail	= NULL;
	mutex_init(&hal->outstanding_q_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);
	hal->pending_q_head	= NULL;
	hal->pending_q_tail	= NULL;
	mutex_init(&hal->pending_q_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Create the kmem_cache for command allocations */
	(void) sprintf(buf, "hal%d_cache", ddi_get_instance(hal->halinfo.dip));
	cmd_size = sizeof (cmd1394_cmd_t) + sizeof (s1394_cmd_priv_t) +
	    hal->halinfo.hal_overhead;

	hal->hal_kmem_cachep = kmem_cache_create(buf, cmd_size, 8, NULL, NULL,
	    NULL, NULL, NULL, 0);

	/* Setup the event stuff */
	ret = nx1394_define_events(hal);
	if (ret != DDI_SUCCESS) {
		/* Clean up before leaving */
		s1394_cleanup_for_detach(hal, H1394_CLEANUP_LEVEL0);

		return (DDI_FAILURE);
	}

	/* Initialize the mutexes and cv's used by the bus reset thread */
	mutex_init(&hal->br_thread_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);
	cv_init(&hal->br_thread_cv, NULL, CV_DRIVER, hal->halinfo.hw_interrupt);
	mutex_init(&hal->br_cmplq_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);
	cv_init(&hal->br_cmplq_cv, NULL, CV_DRIVER, hal->halinfo.hw_interrupt);

	/*
	 * Create a bus reset thread to handle the device discovery.
	 *    It should take the default stack sizes, it should run
	 *    the s1394_br_thread() routine at the start, passing the
	 *    HAL pointer as its argument.  The thread should be put
	 *    on processor p0, its state should be set to runnable,
	 *    but not yet on a processor, and its scheduling priority
	 *    should be the minimum level of any system class.
	 */
	hal->br_thread = thread_create((caddr_t)NULL, 0, s1394_br_thread,
	    hal, 0, &p0, TS_RUN, minclsyspri);

	/* Until we see a bus reset this HAL has no nodes */
	hal->number_of_nodes = 0;
	hal->num_bus_reset_till_fail = NUM_BR_FAIL;

	/* Initialize the SelfID Info */
	hal->current_buffer = 0;
	hal->selfid_buf0 = kmem_zalloc(S1394_SELFID_BUF_SIZE, KM_SLEEP);
	hal->selfid_buf1 = kmem_zalloc(S1394_SELFID_BUF_SIZE, KM_SLEEP);

	/* Initialize kstat structures */
	ret = s1394_kstat_init(hal);
	if (ret != DDI_SUCCESS) {
		/* Clean up before leaving */
		s1394_cleanup_for_detach(hal, H1394_CLEANUP_LEVEL3);

		return (DDI_FAILURE);
	}
	hal->hal_kstats->guid = hal->halinfo.guid;

	/* Setup the node tree pointers */
	hal->old_tree	   = &hal->last_valid_tree[0];
	hal->topology_tree = &hal->current_tree[0];

	/* Initialize the local Config ROM entry */
	ret = s1394_init_local_config_rom(hal);
	if (ret != DDI_SUCCESS) {
		/* Clean up before leaving */
		s1394_cleanup_for_detach(hal, H1394_CLEANUP_LEVEL4);

		return (DDI_FAILURE);
	}

	/* Initialize 1394 Address Space */
	ret = s1394_init_addr_space(hal);
	if (ret != DDI_SUCCESS) {
		/* Clean up before leaving */
		s1394_cleanup_for_detach(hal, H1394_CLEANUP_LEVEL5);

		return (DDI_FAILURE);
	}

	/* Initialize FCP subsystem */
	ret = s1394_fcp_hal_init(hal);
	if (ret != DDI_SUCCESS) {
		/* Clean up before leaving */
		s1394_cleanup_for_detach(hal, H1394_CLEANUP_LEVEL6);

		return (DDI_FAILURE);
	}

	/* Initialize the IRM node ID - "-1" means invalid, undetermined */
	hal->IRM_node = -1;

	/* If we have a 1394A PHY, then set the "contender bit" */
	if (hal->halinfo.phy == H1394_PHY_1394A)
		(void) HAL_CALL(hal).set_contender_bit(
		    hal->halinfo.hal_private);

	/* Add into linked list */
	mutex_enter(&s1394_statep->hal_list_mutex);
	if ((s1394_statep->hal_head == NULL) &&
	    (s1394_statep->hal_tail == NULL)) {
		s1394_statep->hal_head = hal;
		s1394_statep->hal_tail = hal;
	} else {
		s1394_statep->hal_tail->hal_next = hal;
		hal->hal_prev = s1394_statep->hal_tail;
		s1394_statep->hal_tail = hal;
	}
	mutex_exit(&s1394_statep->hal_list_mutex);

	/* Fill in services layer private info */
	*sl_private = (void *)hal;

	return (DDI_SUCCESS);
}

/*
 * Function:    h1394_detach()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		cmd			The ddi_detach_cmd_t that tells us
 *					    if this is a SUSPEND or a regular
 *					    detach() call
 *
 * Output(s):	DDI_SUCCESS		HAL successfully detached
 *		DDI_FAILURE		HAL failed to detach
 *
 * Description:	h1394_detach() unregisters the HAL from the 1394 Software
 *		Framework.  It can be called during a SUSPEND operation or
 *		for a real detach() event.
 */
int
h1394_detach(void **sl_private, ddi_detach_cmd_t cmd)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)(*sl_private);

	switch (cmd) {
	case DDI_DETACH:
		/* Clean up before leaving */
		s1394_cleanup_for_detach(hal, H1394_CLEANUP_LEVEL7);
		/* NULL out the HAL "handle" */
		*sl_private = NULL;
		break;

	case DDI_SUSPEND:
		/* Turn off any timers that might be set */
		s1394_destroy_timers(hal);
		/* Set the hal_was_suspended bit */
		hal->hal_was_suspended = B_TRUE;
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Function:    h1394_alloc_cmd()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		flags			The flags parameter is described below
 *
 * Output(s):	cmdp			Pointer to the newly allocated command
 *		hal_priv_ptr		Offset into the command, points to
 *					    the HAL's private area
 *
 * Description:	h1394_alloc_cmd() allocates a command for use with the
 *		h1394_read_request(), h1394_write_request(), or
 *		h1394_lock_request() interfaces of the 1394 Software Framework.
 *		By default, h1394_alloc_cmd() may sleep while allocating
 *		memory for the command structure.  If this is undesirable,
 *		the HAL may set the H1394_ALLOC_CMD_NOSLEEP bit in the flags
 *		parameter.
 */
int
h1394_alloc_cmd(void *sl_private, uint_t flags, cmd1394_cmd_t **cmdp,
    h1394_cmd_priv_t **hal_priv_ptr)
{
	s1394_hal_t	 *hal;
	s1394_cmd_priv_t *s_priv;

	hal = (s1394_hal_t *)sl_private;

	if (s1394_alloc_cmd(hal, flags, cmdp) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(*cmdp);

	*hal_priv_ptr = &s_priv->hal_cmd_private;

	return (DDI_SUCCESS);
}

/*
 * Function:    h1394_free_cmd()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		cmdp			Pointer to the command to be freed
 *
 * Output(s):	DDI_SUCCESS		HAL successfully freed command
 *		DDI_FAILURE		HAL failed to free command
 *
 * Description:	h1394_free_cmd() attempts to free a command that has previously
 *		been allocated by the HAL.  It is possible for h1394_free_cmd()
 *		to fail because the command is currently in-use by the 1394
 *		Software Framework.
 */
int
h1394_free_cmd(void *sl_private, cmd1394_cmd_t **cmdp)
{
	s1394_hal_t	 *hal;
	s1394_cmd_priv_t *s_priv;

	hal = (s1394_hal_t *)sl_private;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(*cmdp);

	/* Check that command isn't in use */
	if (s_priv->cmd_in_use == B_TRUE) {
		ASSERT(s_priv->cmd_in_use == B_FALSE);
		return (DDI_FAILURE);
	}

	kmem_cache_free(hal->hal_kmem_cachep, *cmdp);

	/* Command pointer is set to NULL before returning */
	*cmdp = NULL;

	/* kstats - number of cmds freed */
	hal->hal_kstats->cmd_free++;

	return (DDI_SUCCESS);
}

/*
 * Function:    h1394_cmd_is_complete()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		command_id		Pointer to the command that has
 *					    just completed
 *		cmd_type		AT_RESP => AT response or ATREQ =
 *					    AT request
 *		status			Command's completion status
 *
 * Output(s):	None
 *
 * Description:	h1394_cmd_is_complete() is called by the HAL whenever an
 *		outstanding command has completed (successfully or otherwise).
 *		After determining whether it was an AT request or and AT
 *		response that we are handling, the command is dispatched to
 *		the appropriate handler in the 1394 Software Framework.
 */
void
h1394_cmd_is_complete(void *sl_private, cmd1394_cmd_t *command_id,
    uint32_t cmd_type, int status)
{
	s1394_hal_t	*hal;
	dev_info_t	*dip;

	hal = (s1394_hal_t *)sl_private;

	/* Is it AT_RESP or AT_REQ? */
	switch (cmd_type) {
	case H1394_AT_REQ:
		s1394_atreq_cmd_complete(hal, command_id, status);
		break;

	case H1394_AT_RESP:
		s1394_atresp_cmd_complete(hal, command_id, status);
		break;

	default:
		dip = hal->halinfo.dip;

		/* An unexpected error in the HAL */
		cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
		    ddi_node_name(dip), ddi_get_instance(dip));

		/* Disable the HAL */
		s1394_hal_shutdown(hal, B_TRUE);

		break;
	}
}

/*
 * Function:    h1394_bus_reset()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *
 * Output(s):	selfid_buf_addr		The pointer to a buffer into which
 *					    any Self ID packets should be put
 *
 * Description:	h1394_bus_reset() is called whenever a 1394 bus reset event
 *		is detected by the HAL.  This routine simply prepares for
 *		the subsequent Self ID packets.
 */
void
h1394_bus_reset(void *sl_private, void **selfid_buf_addr)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)sl_private;

	mutex_enter(&hal->topology_tree_mutex);

	/* Update the HAL's state */
	if (hal->hal_state != S1394_HAL_SHUTDOWN) {
		hal->hal_state = S1394_HAL_RESET;
	} else {
		mutex_exit(&hal->topology_tree_mutex);
		return;
	}

	if (hal->initiated_bus_reset == B_TRUE) {
		hal->initiated_bus_reset = B_FALSE;
		if (hal->num_bus_reset_till_fail > 0) {
			hal->num_bus_reset_till_fail--;
		}
	} else {
		hal->num_bus_reset_till_fail = NUM_BR_FAIL;
	}

	/* Reset the IRM node ID */
	hal->IRM_node = -1;

	/* Slowest node defaults to IEEE1394_S400 */
	hal->slowest_node_speed = IEEE1394_S400;

	/* Pick a SelfID buffer to give */
	if (hal->current_buffer == 0) {
		*selfid_buf_addr = (void *)hal->selfid_buf1;
		hal->current_buffer = 1;
	} else {
		*selfid_buf_addr = (void *)hal->selfid_buf0;
		hal->current_buffer = 0;
	}

	/* Disable the CSR topology_map (temporarily) */
	s1394_CSR_topology_map_disable(hal);

	mutex_exit(&hal->topology_tree_mutex);

	/* Reset the Bus Manager node ID */
	mutex_enter(&hal->bus_mgr_node_mutex);
	hal->bus_mgr_node = -1;
	mutex_exit(&hal->bus_mgr_node_mutex);
}

/*
 * Function:    h1394_self_ids()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		selfid_buf_addr		Pointer to the Self ID buffer
 *		selfid_size		The size of the filled part of the
 *					    Self ID buffer
 *		node_id			The local (host) node ID for the
 *					    current generation
 *		generation_count	The current generation number
 *
 * Output(s):	None
 *
 * Description:	h1394_self_ids() does alot of the work at bus reset.  It
 *		takes the Self ID packets and parses them, builds a topology
 *		tree representation of them, calculates gap count, IRM, speed
 *		map, does any node matching that's possible, and then wakes
 *		up the br_thread.
 */
void
h1394_self_ids(void *sl_private, void *selfid_buf_addr, uint32_t selfid_size,
    uint32_t node_id, uint32_t generation_count)
{
	s1394_hal_t	*hal;
	int		diameter;
	uint_t		gen_diff, gen_rollover;
	boolean_t	tree_copied = B_FALSE;
	ushort_t	saved_number_of_nodes;

	/*
	 * NOTE: current topology tree is referred to as topology_tree
	 * and the old topology tree is referred to as old_tree.
	 * tree_valid indicates selfID buffer checked out OK and we were
	 * able to build the topology tree.
	 * tree_processed indicates we read the config ROMs as needed.
	 */
	hal = (s1394_hal_t *)sl_private;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);
	if (hal->hal_state == S1394_HAL_SHUTDOWN) {
		mutex_exit(&hal->topology_tree_mutex);
		return;
	}

	/* kstats - number of selfid completes */
	hal->hal_kstats->selfid_complete++;

	if (generation_count > hal->generation_count) {
		gen_diff = generation_count - hal->generation_count;
		hal->hal_kstats->bus_reset += gen_diff;
	} else {
		gen_diff = hal->generation_count - generation_count;
		/* Use max_generation to determine how many bus resets */
		hal->hal_kstats->bus_reset +=
		    (hal->halinfo.max_generation - gen_diff);
	}

	/*
	 * If the current tree has a valid topology tree (selfids
	 * checked out OK etc) and config roms read as needed,
	 * then make it the old tree before building a new one.
	 */
	if ((hal->topology_tree_valid == B_TRUE) &&
	    (hal->topology_tree_processed == B_TRUE)) {
		/* Trees are switched after the copy completes */
		s1394_copy_old_tree(hal);
		tree_copied = B_TRUE;
	}

	/* Set the new generation and node id */
	hal->node_id = node_id;
	hal->generation_count = generation_count;

	/* Invalidate the current topology tree */
	hal->topology_tree_valid = B_FALSE;
	hal->topology_tree_processed = B_FALSE;
	hal->cfgroms_being_read = 0;

	/*
	 * Save the number of nodes prior to parsing the self id buffer.
	 * We need this saved value while initializing the topology tree
	 * (for non-copy case).
	 */
	saved_number_of_nodes = hal->number_of_nodes;

	/* Parse the SelfID buffer */
	if (s1394_parse_selfid_buffer(hal, selfid_buf_addr, selfid_size) !=
	    DDI_SUCCESS) {
		/* Unlock the topology tree */
		mutex_exit(&hal->topology_tree_mutex);

		/* kstats - SelfID buffer error */
		hal->hal_kstats->selfid_buffer_error++;
		return;		/* Error parsing SelfIDs */
	}

	/* Sort the SelfID packets by node number (if it's a 1995 PHY) */
	if (hal->halinfo.phy == H1394_PHY_1995) {
		s1394_sort_selfids(hal);
	}

	/*
	 * Update the cycle master timer - if the timer is set and
	 * we were the root but we are not anymore, then disable it.
	 */
	mutex_enter(&hal->cm_timer_mutex);
	if ((hal->cm_timer_set == B_TRUE) &&
	    ((hal->old_number_of_nodes - 1) ==
		IEEE1394_NODE_NUM(hal->old_node_id)) &&
	    ((hal->number_of_nodes - 1) !=
		IEEE1394_NODE_NUM(hal->node_id))) {
		mutex_exit(&hal->cm_timer_mutex);
		(void) untimeout(hal->cm_timer);
	} else {
		mutex_exit(&hal->cm_timer_mutex);
	}

	s1394_init_topology_tree(hal, tree_copied, saved_number_of_nodes);

	/* Determine the 1394 bus gap count */
	hal->gap_count = s1394_get_current_gap_count(hal);
	/* If gap counts are inconsistent, reset */
	if (hal->gap_count == -1) {
		/* Unlock the topology tree */
		mutex_exit(&hal->topology_tree_mutex);

		/* kstats - SelfID buffer error (invalid gap counts) */
		hal->hal_kstats->selfid_buffer_error++;

		if (s1394_ignore_invalid_gap_cnt == 1) {
			/* Lock the topology tree again */
			mutex_enter(&hal->topology_tree_mutex);
			hal->gap_count = 0x3F;
		} else {
			return;	/* Invalid gap counts in SelfID buffer */
		}
	}

	/* Determine the Isoch Resource Manager */
	hal->IRM_node = s1394_get_isoch_rsrc_mgr(hal);

	/* Build the topology tree */
	if (s1394_topology_tree_build(hal) != DDI_SUCCESS) {
		/* Unlock the topology tree */
		mutex_exit(&hal->topology_tree_mutex);

		/* kstats - SelfID buffer error (Invalid topology tree) */
		hal->hal_kstats->selfid_buffer_error++;
		return;		/* Error building topology tree from SelfIDs */
	}

	/* Update the CSR topology_map */
	s1394_CSR_topology_map_update(hal);

	/* Calculate the diameter */
	diameter = s1394_topology_tree_calculate_diameter(hal);

	/* Determine the optimum gap count */
	hal->optimum_gap_count = s1394_gap_count_optimize(diameter);

	/* Fill in the speed map */
	s1394_speed_map_fill(hal);

	/* Initialize the two trees (for tree walking) */
	s1394_topology_tree_mark_all_unvisited(hal);
	s1394_old_tree_mark_all_unvisited(hal);
	s1394_old_tree_mark_all_unmatched(hal);

	/* Are both trees (old and new) valid? */
	if ((hal->old_tree_valid == B_TRUE) &&
	    (hal->topology_tree_valid == B_TRUE)) {
		/* If HAL was in a suspended state, then do no matching */
		if (hal->hal_was_suspended == B_TRUE) {
		    hal->hal_was_suspended = B_FALSE;
		} else {
			gen_rollover = hal->halinfo.max_generation + 1;
			/* If only one bus reset occurred, match the trees */
			if (((hal->old_generation_count + 1) % gen_rollover) ==
			    generation_count) {
				s1394_match_tree_nodes(hal);
			}
		}
	}

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);

	/* Wake up the bus reset processing thread */
	s1394_tickle_bus_reset_thread(hal);
}

/*
 * Function:    h1394_read_request()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		req			The incoming AR request
 *
 * Output(s):	None
 *
 * Description:	h1394_read_request() receives incoming AR requests.  These
 *		asynchronous read requests are dispatched to the appropriate
 *		target (if one has registered) or are handled by the 1394
 *		Software Framework, which will send out an appropriate
 *		response.
 */
void
h1394_read_request(void *sl_private, cmd1394_cmd_t *req)
{
	s1394_hal_t		*hal;
	s1394_cmd_priv_t	*s_priv;
	s1394_addr_space_blk_t  *addr_blk;
	dev_info_t		*dip;
	uint64_t		end_of_request;
	uint32_t		offset;
	size_t			cmd_length;
	uchar_t			*bufp_addr;
	uchar_t			*begin_ptr;
	uchar_t			*end_ptr;
	uchar_t			*tmp_ptr;
	void (*recv_read_req)(cmd1394_cmd_t *);

	hal = (s1394_hal_t *)sl_private;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(req);

	s_priv->cmd_priv_xfer_type = S1394_CMD_READ;

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
		cmd_length = IEEE1394_QUADLET;
		hal->hal_kstats->arreq_quad_rd++;
		break;

	case CMD1394_ASYNCH_RD_BLOCK:
		cmd_length = req->cmd_u.b.blk_length;
		hal->hal_kstats->arreq_blk_rd++;
		break;

	default:
		dip = hal->halinfo.dip;

		/* An unexpected error in the HAL */
		cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
		    ddi_node_name(dip), ddi_get_instance(dip));

		/* Disable the HAL */
		s1394_hal_shutdown(hal, B_TRUE);

		return;
	}

	/* Lock the "used" tree */
	mutex_enter(&hal->addr_space_used_mutex);

	/* Has the 1394 address been allocated? */
	addr_blk = s1394_used_tree_search(hal, req->cmd_addr);

	/* If it wasn't found, it isn't owned... */
	if (addr_blk == NULL) {
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);
		req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Does the WHOLE request fit in the allocated block? */
	end_of_request = (req->cmd_addr + cmd_length) - 1;
	if (end_of_request > addr_blk->addr_hi) {
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);
		req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Is a read request valid for this address space? */
	if (!(addr_blk->addr_enable & T1394_ADDR_RDENBL)) {
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Make sure quadlet requests are quadlet-aligned */
	offset = req->cmd_addr - addr_blk->addr_lo;
	if ((req->cmd_type == CMD1394_ASYNCH_RD_QUAD) &&
	    ((offset & 0x3) != 0)) {
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Fill in the backing store if necessary */
	if (addr_blk->kmem_bufp != NULL) {
		offset = req->cmd_addr - addr_blk->addr_lo;
		bufp_addr = (uchar_t *)addr_blk->kmem_bufp + offset;

		switch (req->cmd_type) {
		case CMD1394_ASYNCH_RD_QUAD:
			bcopy((void *)bufp_addr,
			    (void *)&(req->cmd_u.q.quadlet_data), cmd_length);
			break;

		case CMD1394_ASYNCH_RD_BLOCK:
			begin_ptr = req->cmd_u.b.data_block->b_wptr;
			end_ptr	  = begin_ptr + cmd_length;
			tmp_ptr	  = req->cmd_u.b.data_block->b_datap->db_lim;
			if (end_ptr <= tmp_ptr) {
				bcopy((void *)bufp_addr, (void *)begin_ptr,
				    cmd_length);
				/* Update b_wptr to refelect the new data */
				req->cmd_u.b.data_block->b_wptr = end_ptr;
			} else {
				dip = hal->halinfo.dip;

				/* An unexpected error in the HAL */
				cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
				    ddi_node_name(dip), ddi_get_instance(dip));

				/* Unlock the "used" tree */
				mutex_exit(&hal->addr_space_used_mutex);

				/* Disable the HAL */
				s1394_hal_shutdown(hal, B_TRUE);

				return;
			}
			break;

		default:
			dip = hal->halinfo.dip;

			/* An unexpected error in the HAL */
			cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
			    ddi_node_name(dip), ddi_get_instance(dip));

			/* Unlock the "used" tree */
			mutex_exit(&hal->addr_space_used_mutex);

			/* Disable the HAL */
			s1394_hal_shutdown(hal, B_TRUE);

			return;
		}
	}

	/* Fill in the rest of the info in the request */
	s_priv->arreq_valid_addr = B_TRUE;
	req->cmd_callback_arg	 = addr_blk->addr_arg;
	recv_read_req		 = addr_blk->addr_events.recv_read_request;

	/* Unlock the "used" tree */
	mutex_exit(&hal->addr_space_used_mutex);

	/*
	 * Add no code that modifies the command after the target
	 * callback is called or after the response is sent to the
	 * HAL.
	 */
	if (recv_read_req != NULL) {
		recv_read_req(req);
	} else {
		req->cmd_result = IEEE1394_RESP_COMPLETE;
		(void) s1394_send_response(hal, req);
		return;
	}
}

/*
 * Function:    h1394_write_request()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		req			The incoming AR request
 *
 * Output(s):	None
 *
 * Description:	h1394_write_request() receives incoming AR requests.  These
 *		asynchronous write requests are dispatched to the appropriate
 *		target (if one has registered) or are handled by the 1394
 *		Software Framework, which will send out an appropriate
 *		response.
 */
void
h1394_write_request(void *sl_private, cmd1394_cmd_t *req)
{
	s1394_hal_t		*hal;
	s1394_cmd_priv_t	*s_priv;
	h1394_cmd_priv_t	*h_priv;
	s1394_addr_space_blk_t	*addr_blk;
	dev_info_t		*dip;
	uint32_t		offset;
	size_t			cmd_length;
	uchar_t			*bufp_addr;
	uchar_t			*begin_ptr;
	uchar_t			*end_ptr;
	uchar_t			*tmp_ptr;
	uint64_t		end_of_request;
	boolean_t		posted_write = B_FALSE;
	boolean_t		write_error = B_FALSE;
	void (*recv_write_req)(cmd1394_cmd_t *);

	hal = (s1394_hal_t *)sl_private;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(req);

	s_priv->cmd_priv_xfer_type = S1394_CMD_WRITE;

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_WR_QUAD:
		cmd_length = IEEE1394_QUADLET;
		hal->hal_kstats->arreq_quad_wr++;
		break;

	case CMD1394_ASYNCH_WR_BLOCK:
		cmd_length = req->cmd_u.b.blk_length;
		hal->hal_kstats->arreq_blk_wr++;
		hal->hal_kstats->arreq_blk_wr_size += cmd_length;
		break;

	default:
		dip = hal->halinfo.dip;

		/* An unexpected error in the HAL */
		cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
		    ddi_node_name(dip), ddi_get_instance(dip));

		/* Disable the HAL */
		s1394_hal_shutdown(hal, B_TRUE);

		return;
	}

	/* Lock the "used" tree */
	mutex_enter(&hal->addr_space_used_mutex);

	/* Has the 1394 address been allocated? */
	addr_blk = s1394_used_tree_search(hal, req->cmd_addr);

	/* Is this a posted write request? */
	posted_write = s1394_is_posted_write(hal, req->cmd_addr);

	/* If it wasn't found, it isn't owned... */
	if (addr_blk == NULL) {
		req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		write_error	= B_TRUE;
		goto write_error_check;
	}

	/* Does the WHOLE request fit in the allocated block? */
	end_of_request = (req->cmd_addr + cmd_length) - 1;
	if (end_of_request > addr_blk->addr_hi) {
		req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		write_error	= B_TRUE;
		goto write_error_check;
	}

	/* Is a write request valid for this address space? */
	if (!(addr_blk->addr_enable & T1394_ADDR_WRENBL)) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		write_error	= B_TRUE;
		goto write_error_check;
	}

	/* Make sure quadlet request is quadlet aligned */
	offset = req->cmd_addr - addr_blk->addr_lo;
	if ((req->cmd_type == CMD1394_ASYNCH_WR_QUAD) &&
	    ((offset & 0x3) != 0)) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		write_error	= B_TRUE;
		goto write_error_check;
	}

write_error_check:
	/* Check if posted-write when sending error responses */
	if (write_error == B_TRUE) {
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);

		if (posted_write == B_TRUE) {
			/* Get a pointer to the HAL private struct */
			h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;
			hal->hal_kstats->arreq_posted_write_error++;
			/* Free the command - Pass it back to the HAL */
			HAL_CALL(hal).response_complete(
			    hal->halinfo.hal_private, req, h_priv);
			return;
		} else {
			(void) s1394_send_response(hal, req);
			return;
		}
	}

	/* Fill in the backing store if necessary */
	if (addr_blk->kmem_bufp != NULL) {
		offset = req->cmd_addr - addr_blk->addr_lo;
		bufp_addr = (uchar_t *)addr_blk->kmem_bufp + offset;
		switch (req->cmd_type) {
		case CMD1394_ASYNCH_WR_QUAD:
			bcopy((void *)&(req->cmd_u.q.quadlet_data),
			    (void *)bufp_addr, cmd_length);
			break;

		case CMD1394_ASYNCH_WR_BLOCK:
			begin_ptr = req->cmd_u.b.data_block->b_rptr;
			end_ptr = begin_ptr + cmd_length;
			tmp_ptr = req->cmd_u.b.data_block->b_wptr;
			if (end_ptr <= tmp_ptr) {
				bcopy((void *)begin_ptr, (void *)bufp_addr,
				    cmd_length);
			} else {
				dip = hal->halinfo.dip;

				/* An unexpected error in the HAL */
				cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
				    ddi_node_name(dip), ddi_get_instance(dip));

				/* Unlock the "used" tree */
				mutex_exit(&hal->addr_space_used_mutex);

				/* Disable the HAL */
				s1394_hal_shutdown(hal, B_TRUE);

				return;
			}
			break;

		default:
			dip = hal->halinfo.dip;

			/* An unexpected error in the HAL */
			cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
			    ddi_node_name(dip), ddi_get_instance(dip));

			/* Unlock the "used" tree */
			mutex_exit(&hal->addr_space_used_mutex);

			/* Disable the HAL */
			s1394_hal_shutdown(hal, B_TRUE);

			return;
		}
	}

	/* Fill in the rest of the info in the request */
	if (addr_blk->addr_type == T1394_ADDR_POSTED_WRITE)
		s_priv->posted_write = B_TRUE;

	s_priv->arreq_valid_addr = B_TRUE;
	req->cmd_callback_arg	 = addr_blk->addr_arg;
	recv_write_req		 = addr_blk->addr_events.recv_write_request;

	/* Unlock the "used" tree */
	mutex_exit(&hal->addr_space_used_mutex);

	/*
	 * Add no code that modifies the command after the target
	 * callback is called or after the response is sent to the
	 * HAL.
	 */
	if (recv_write_req != NULL) {
		recv_write_req(req);
	} else {
		req->cmd_result = IEEE1394_RESP_COMPLETE;
		(void) s1394_send_response(hal, req);
		return;
	}
}

/*
 * Function:    h1394_lock_request()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		req			The incoming AR request
 *
 * Output(s):	None
 *
 * Description:	h1394_lock_request() receives incoming AR requests.  These
 *		asynchronous lock requests are dispatched to the appropriate
 *		target (if one has registered) or are handled by the 1394
 *		Software Framework, which will send out an appropriate
 *		response.
 */
void
h1394_lock_request(void *sl_private, cmd1394_cmd_t *req)
{
	s1394_hal_t		*hal;
	s1394_cmd_priv_t	*s_priv;
	s1394_addr_space_blk_t	*addr_blk;
	dev_info_t		*dip;
	uint64_t		end_of_request;
	uint32_t		offset;
	uchar_t			*bufp_addr;
	cmd1394_lock_type_t	lock_type;
	void (*recv_lock_req)(cmd1394_cmd_t *);

	hal = (s1394_hal_t *)sl_private;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(req);

	s_priv->cmd_priv_xfer_type = S1394_CMD_LOCK;

	/* Lock the "used" tree */
	mutex_enter(&hal->addr_space_used_mutex);

	/* Has the 1394 address been allocated? */
	addr_blk = s1394_used_tree_search(hal, req->cmd_addr);

	/* If it wasn't found, it isn't owned... */
	if (addr_blk == NULL) {
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);
		req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Does the WHOLE request fit in the allocated block? */
	switch (req->cmd_type) {
	case CMD1394_ASYNCH_LOCK_32:
		end_of_request = (req->cmd_addr + IEEE1394_QUADLET) - 1;
		/* kstats - 32-bit lock request */
		hal->hal_kstats->arreq_lock32++;
		break;

	case CMD1394_ASYNCH_LOCK_64:
		end_of_request = (req->cmd_addr + IEEE1394_OCTLET) - 1;
		/* kstats - 64-bit lock request */
		hal->hal_kstats->arreq_lock64++;
		break;

	default:
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);

		dip = hal->halinfo.dip;

		/* An unexpected error in the HAL */
		cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
		    ddi_node_name(dip), ddi_get_instance(dip));

		/* Disable the HAL */
		s1394_hal_shutdown(hal, B_TRUE);

		return;
	}

	if (end_of_request > addr_blk->addr_hi) {
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);
		req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Is a lock request valid for this address space? */
	if (!(addr_blk->addr_enable & T1394_ADDR_LKENBL)) {
		/* Unlock the "used" tree */
		mutex_exit(&hal->addr_space_used_mutex);
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Fill in the backing store if necessary */
	if (addr_blk->kmem_bufp != NULL) {
		offset = req->cmd_addr - addr_blk->addr_lo;
		bufp_addr = (uchar_t *)addr_blk->kmem_bufp + offset;

		if (req->cmd_type == CMD1394_ASYNCH_LOCK_32) {
			uint32_t	old_value;
			uint32_t	arg_value;
			uint32_t	data_value;
			uint32_t	new_value;

			arg_value	= req->cmd_u.l32.arg_value;
			data_value	= req->cmd_u.l32.data_value;
			lock_type	= req->cmd_u.l32.lock_type;
			bcopy((void *)bufp_addr, (void *)&old_value,
			    IEEE1394_QUADLET);

			switch (lock_type) {
			case CMD1394_LOCK_MASK_SWAP:
				/* Mask-Swap (see P1394A - Table 1.7) */
				new_value = (data_value & arg_value) |
				    (old_value & ~arg_value);
				/* Copy new_value into backing store */
				bcopy((void *)&new_value, (void *)bufp_addr,
				    IEEE1394_QUADLET);
				req->cmd_u.l32.old_value = old_value;
				break;

			case CMD1394_LOCK_COMPARE_SWAP:
				/* Compare-Swap */
				if (old_value == arg_value) {
					new_value = data_value;
					/* Copy new_value into backing store */
					bcopy((void *)&new_value,
					    (void *)bufp_addr,
					    IEEE1394_QUADLET);
				}
				req->cmd_u.l32.old_value = old_value;
				break;

			case CMD1394_LOCK_FETCH_ADD:
				/* Fetch-Add (see P1394A - Table 1.7) */
				old_value = T1394_DATA32(old_value);
				new_value = old_value + data_value;
				new_value = T1394_DATA32(new_value);
				/* Copy new_value into backing store */
				bcopy((void *)&new_value, (void *)bufp_addr,
				    IEEE1394_QUADLET);
				req->cmd_u.l32.old_value = old_value;
				break;

			case CMD1394_LOCK_LITTLE_ADD:
				/* Little-Add (see P1394A - Table 1.7) */
				old_value = T1394_DATA32(old_value);
				new_value = old_value + data_value;
				new_value = T1394_DATA32(new_value);
				/* Copy new_value into backing store */
				bcopy((void *)&new_value, (void *)bufp_addr,
				    IEEE1394_QUADLET);
				req->cmd_u.l32.old_value = old_value;
				break;

			case CMD1394_LOCK_BOUNDED_ADD:
				/* Bounded-Add (see P1394A - Table 1.7) */
				old_value = T1394_DATA32(old_value);
				if (old_value != arg_value) {
					new_value = old_value + data_value;
					new_value = T1394_DATA32(new_value);
					/* Copy new_value into backing store */
					bcopy((void *)&new_value,
					    (void *)bufp_addr,
					    IEEE1394_QUADLET);
				}
				req->cmd_u.l32.old_value = old_value;
				break;

			case CMD1394_LOCK_WRAP_ADD:
				/* Wrap-Add (see P1394A - Table 1.7) */
				old_value = T1394_DATA32(old_value);
				if (old_value != arg_value) {
					new_value = old_value + data_value;
				} else {
					new_value = data_value;
				}
				new_value = T1394_DATA32(new_value);
				/* Copy new_value into backing store */
				bcopy((void *)&new_value, (void *)bufp_addr,
				    IEEE1394_QUADLET);
				req->cmd_u.l32.old_value = old_value;
				break;

			default:
				/* Unlock the "used" tree */
				mutex_exit(&hal->addr_space_used_mutex);
				req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
				(void) s1394_send_response(hal, req);
				return;
			}
		} else {
			/* Handling for the 8-byte (64-bit) lock requests */
			uint64_t	old_value;
			uint64_t	arg_value;
			uint64_t	data_value;
			uint64_t	new_value;

			arg_value	= req->cmd_u.l64.arg_value;
			data_value	= req->cmd_u.l64.data_value;
			lock_type	= req->cmd_u.l64.lock_type;
			bcopy((void *)bufp_addr, (void *)&old_value,
			    IEEE1394_OCTLET);

			switch (lock_type) {
			case CMD1394_LOCK_MASK_SWAP:
				/* Mask-Swap (see P1394A - Table 1.7) */
				new_value = (data_value & arg_value) |
				    (old_value & ~arg_value);
				/* Copy new_value into backing store */
				bcopy((void *)&new_value, (void *)bufp_addr,
				    IEEE1394_OCTLET);
				req->cmd_u.l64.old_value = old_value;
				break;

			case CMD1394_LOCK_COMPARE_SWAP:
				/* Compare-Swap */
				if (old_value == arg_value) {
					new_value = data_value;
					/* Copy new_value into backing store */
					bcopy((void *)&new_value,
					    (void *)bufp_addr,
					    IEEE1394_OCTLET);
				}
				req->cmd_u.l64.old_value = old_value;
				break;

			case CMD1394_LOCK_FETCH_ADD:
				/* Fetch-Add (see P1394A - Table 1.7) */
				old_value = T1394_DATA64(old_value);
				new_value = old_value + data_value;
				new_value = T1394_DATA64(new_value);
				/* Copy new_value into backing store */
				bcopy((void *)&new_value, (void *)bufp_addr,
				    IEEE1394_OCTLET);
				req->cmd_u.l64.old_value = old_value;
				break;

			case CMD1394_LOCK_LITTLE_ADD:
				/* Little-Add (see P1394A - Table 1.7) */
				old_value = T1394_DATA64(old_value);
				new_value = old_value + data_value;
				new_value = T1394_DATA64(new_value);
				/* Copy new_value into backing store */
				bcopy((void *)&new_value, (void *)bufp_addr,
				    IEEE1394_OCTLET);
				req->cmd_u.l64.old_value = old_value;
				break;

			case CMD1394_LOCK_BOUNDED_ADD:
				/* Bounded-Add (see P1394A - Table 1.7) */
				old_value = T1394_DATA64(old_value);
				if (old_value != arg_value) {
					new_value = old_value + data_value;
					new_value = T1394_DATA64(new_value);
					/* Copy new_value into backing store */
					bcopy((void *)&new_value,
					    (void *)bufp_addr,
					    IEEE1394_OCTLET);
				}
				req->cmd_u.l64.old_value = old_value;
				break;

			case CMD1394_LOCK_WRAP_ADD:
				/* Wrap-Add (see P1394A - Table 1.7) */
				old_value = T1394_DATA64(old_value);
				if (old_value != arg_value) {
					new_value = old_value + data_value;
				} else {
					new_value = data_value;
				}
				new_value = T1394_DATA64(new_value);
				/* Copy new_value into backing store */
				bcopy((void *)&new_value, (void *)bufp_addr,
				    IEEE1394_OCTLET);
				req->cmd_u.l64.old_value = old_value;
				break;

			default:
				/* Unlock the "used" tree */
				mutex_exit(&hal->addr_space_used_mutex);
				req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
				(void) s1394_send_response(hal, req);
				return;
			}
		}
	}

	/* Fill in the rest of the info in the request */
	s_priv->arreq_valid_addr = B_TRUE;
	req->cmd_callback_arg	 = addr_blk->addr_arg;
	recv_lock_req		 = addr_blk->addr_events.recv_lock_request;

	/* Unlock the "used" tree */
	mutex_exit(&hal->addr_space_used_mutex);

	/*
	 * Add no code that modifies the command after the target
	 * callback is called or after the response is sent to the
	 * HAL.
	 */
	if (recv_lock_req != NULL) {
		recv_lock_req(req);
	} else {
		req->cmd_result = IEEE1394_RESP_COMPLETE;
		(void) s1394_send_response(hal, req);
		return;
	}
}

/*
 * Function:    h1394_ioctl()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		cmd			ioctl cmd
 *		arg			argument for the ioctl cmd
 *		mode			mode bits (see ioctl(9e))
 *		cred_p			cred structure pointer
 *		rval_p			pointer to return value (see ioctl(9e))
 *
 * Output(s):	EINVAL if not a DEVCTL ioctl, else return value from s1394_ioctl
 *
 * Description:	h1394_ioctl() implements non-HAL specific ioctls. Currently,
 *		DEVCTL ioctls are the only generic ioctls supported.
 */
int
h1394_ioctl(void *sl_private, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	int	status;

	if ((cmd & DEVCTL_IOC) != DEVCTL_IOC)
		return (EINVAL);

	status = s1394_ioctl((s1394_hal_t *)sl_private, cmd, arg, mode,
	    cred_p, rval_p);

	return (status);
}

/*
 * Function:    h1394_phy_packet()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		packet_data		Pointer to a buffer of packet data
 *		quadlet_count		Length of the buffer
 *		timestamp		Timestamp indicating time of arrival
 *
 * Output(s):	None
 *
 * Description:	h1394_phy_packet() is not implemented currently, but would
 *		be used to process the responses to PHY ping packets in P1394A
 *		When one is sent out, a timestamp is given indicating its time
 *		of departure. Comparing that old timestamp with this new
 *		timestamp, we can determine the time of flight and can use
 *		those times to optimize the gap count.
 */
/* ARGSUSED */
void
h1394_phy_packet(void *sl_private, uint32_t *packet_data, uint_t quadlet_count,
	uint_t timestamp)
{
	/* This interface is not yet implemented */
}

/*
 * Function:    h1394_error_detected()
 * Input(s):    sl_private		The HAL "handle" returned by
 *					    h1394_attach()
 *		type			The type of error the HAL detected
 *		arg			Pointer to any extra information
 *
 * Output(s):	None
 *
 * Description:	h1394_error_detected() is used by the HAL to report errors
 *		to the 1394 Software Framework.
 */
void
h1394_error_detected(void *sl_private, h1394_error_t type, void *arg)
{
	s1394_hal_t	*hal;
	uint_t		hal_node_num;
	uint_t		IRM_node_num;

	hal = (s1394_hal_t *)sl_private;

	switch (type) {
	case H1394_LOCK_RESP_ERR:
		/* If we are the IRM, then initiate a bus reset */
		mutex_enter(&hal->topology_tree_mutex);
		hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
		IRM_node_num = hal->IRM_node;
		mutex_exit(&hal->topology_tree_mutex);
		if (IRM_node_num == hal_node_num)
			s1394_initiate_hal_reset(hal, NON_CRITICAL);
		break;

	case H1394_POSTED_WR_ERR:
		break;

	case H1394_SELF_INITIATED_SHUTDOWN:
		s1394_hal_shutdown(hal, B_FALSE);
		break;

	case H1394_CYCLE_TOO_LONG:
		/* Set a timer to become cycle master after 1 second */
		mutex_enter(&hal->cm_timer_mutex);
		hal->cm_timer_set = B_TRUE;
		mutex_exit(&hal->cm_timer_mutex);
		hal->cm_timer = timeout(s1394_cycle_too_long_callback, hal,
		    drv_usectohz(CYCLE_MASTER_TIMER * 1000));

		break;

	default:
		break;
	}
}
