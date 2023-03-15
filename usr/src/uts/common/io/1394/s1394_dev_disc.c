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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

/*
 * s1394_dev_disc.c
 *    1394 Services Layer Device Discovery Routines
 *    This file contains the bus reset thread code, bus manager routines and
 *    various routines that are used to implement remote Config ROM reading.
 *
 *    FUTURE:
 *    Rescan the bus if invalid nodes are seen.
 *    Investigate taskq for reading phase2 config rom reads.
 *    If we are reading the entire bus info blk, we should attempt
 *    a block read and fallback to quad reads if this fails.
 */

#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/varargs.h>

#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>
#include <sys/1394/ieee1212.h>

/* hcmd_ret_t */
typedef enum {
	S1394_HCMD_INVALID,
	S1394_HCMD_NODE_DONE,
	S1394_HCMD_NODE_EXPECT_MORE,
	S1394_HCMD_LOCK_FAILED
} hcmd_ret_t;

#define	QUAD_TO_CFGROM_ADDR(b, n, q, addr) {			\
	uint64_t bl = (b);					\
	uint64_t nl = (n);					\
	addr = ((bl) << IEEE1394_ADDR_BUS_ID_SHIFT) |		\
		((nl) << IEEE1394_ADDR_PHY_ID_SHIFT);		\
	addr += IEEE1394_CONFIG_ROM_ADDR + ((q) << 2);		\
}

#define	CFGROM_READ_PAUSE(d)						\
	((s1394_cfgrom_read_delay_ms == 0) ? (void) 0 :			\
	delay(drv_usectohz((d) * 1000)))

#define	BUMP_CFGROM_READ_DELAY(n)					\
	(n)->cfgrom_read_delay += s1394_cfgrom_read_delay_incr

#define	CFGROM_GET_READ_DELAY(n, d)					\
	((d) = (n)->cfgrom_read_delay)

#define	SETUP_QUAD_READ(n, reset_fails, quadlet, cnt)			\
{									\
	int i = (reset_fails);						\
	if (i != 0) {							\
		(n)->cfgrom_read_fails = 0;				\
		(n)->cfgrom_read_delay = (uchar_t)s1394_cfgrom_read_delay_ms; \
	}								\
	(n)->cfgrom_quad_to_read = (quadlet);				\
	(n)->cfgrom_quad_read_cnt = (cnt);				\
}

static void s1394_wait_for_events(s1394_hal_t *hal, int firsttime);

static int s1394_wait_for_cfgrom_callbacks(s1394_hal_t *hal, uint_t wait_gen,
    hcmd_ret_t(*handle_cmd_fn)(s1394_hal_t *hal, cmd1394_cmd_t *cmd));

static void s1394_flush_cmplq(s1394_hal_t *hal);

static void s1394_br_thread_exit(s1394_hal_t *hal);

static void s1394_target_bus_reset_notifies(s1394_hal_t *hal,
    t1394_localinfo_t *localinfo);

static int s1394_alloc_cfgrom(s1394_hal_t *hal, s1394_node_t *node,
    s1394_status_t *status);

static int s1394_cfgrom_scan_phase1(s1394_hal_t *hal);

static hcmd_ret_t s1394_br_thread_handle_cmd_phase1(s1394_hal_t *hal,
    cmd1394_cmd_t *cmd);

static int s1394_cfgrom_scan_phase2(s1394_hal_t *hal);

static hcmd_ret_t s1394_br_thread_handle_cmd_phase2(s1394_hal_t *hal,
    cmd1394_cmd_t *cmd);

static int s1394_read_config_quadlet(s1394_hal_t *hal, cmd1394_cmd_t *cmd,
    s1394_status_t *status);

static void s1394_cfgrom_read_callback(cmd1394_cmd_t *cmd);

static void s1394_get_quad_info(cmd1394_cmd_t *cmd, uint32_t *node_num,
    uint32_t *quadlet, uint32_t *data);

static int s1394_match_GUID(s1394_hal_t *hal, s1394_node_t *nnode);

static int s1394_match_all_GUIDs(s1394_hal_t *hal);

static void s1394_become_bus_mgr(void *arg);

static void s1394_become_bus_mgr_callback(cmd1394_cmd_t *cmd);

static int s1394_bus_mgr_processing(s1394_hal_t *hal);

static int s1394_do_bus_mgr_processing(s1394_hal_t *hal);

static void s1394_bus_mgr_timers_stop(s1394_hal_t *hal,
    timeout_id_t *bus_mgr_query_tid, timeout_id_t *bus_mgr_tid);

static void s1394_bus_mgr_timers_start(s1394_hal_t *hal,
    timeout_id_t *bus_mgr_query_tid, timeout_id_t *bus_mgr_tid);

static int s1394_cycle_master_capable(s1394_hal_t *hal);

static int s1394_do_phy_config_pkt(s1394_hal_t *hal, int new_root,
    int new_gap_cnt, uint32_t IRM_flags);

static void s1394_phy_config_callback(cmd1394_cmd_t *cmd);

static int s1394_calc_next_quad(s1394_hal_t *hal, s1394_node_t *node,
    uint32_t quadlet, uint32_t *nextquadp);

static int s1394_cfgrom_read_retry_cnt = 3;	/* 1 + 3 retries */
static int s1394_cfgrom_read_delay_ms = 20;	/* start with 20ms */
static int s1394_cfgrom_read_delay_incr = 10;	/* 10ms increments */
static int s1394_enable_crc_validation = 0;
static int s1394_turn_off_dir_stack = 0;
static int s1394_crcsz_is_cfgsz = 0;
static int s1394_enable_rio_pass1_workarounds = 0;

/*
 * s1394_br_thread()
 *    is the bus reset thread. Its sole purpose is to read/reread config roms
 *    as appropriate and do bus reset time things (bus manager processing,
 *    isoch resource reallocation etc.).
 */
void
s1394_br_thread(s1394_hal_t *hal)
{
	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	/* Initialize the Bus Mgr timers */
	hal->bus_mgr_timeout_id = 0;
	hal->bus_mgr_query_timeout_id = 0;

	/* Initialize the cmpletion Q */
	mutex_enter(&hal->br_cmplq_mutex);
	hal->br_cmplq_head = hal->br_cmplq_tail = NULL;
	mutex_exit(&hal->br_cmplq_mutex);

	s1394_wait_for_events(hal, 1);

	for (;;) {
		ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

		s1394_wait_for_events(hal, 0);

		ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

		/* stop bus manager timeouts, if needed */
		s1394_bus_mgr_timers_stop(hal, &hal->bus_mgr_query_timeout_id,
		    &hal->bus_mgr_timeout_id);

		s1394_flush_cmplq(hal);

		/* start timers for checking bus manager, if needed */
		s1394_bus_mgr_timers_start(hal, &hal->bus_mgr_query_timeout_id,
		    &hal->bus_mgr_timeout_id);

		/* Try to reallocate all isoch resources */
		s1394_isoch_rsrc_realloc(hal);

		if (s1394_cfgrom_scan_phase1(hal) != DDI_SUCCESS) {
			continue;
		}

		if (s1394_bus_mgr_processing(hal) != DDI_SUCCESS) {
			continue;
		}

		ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

		if (s1394_cfgrom_scan_phase2(hal) != DDI_SUCCESS) {
			continue;
		}

		ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
	}
}

/*
 * s1394_wait_for_events()
 *    blocks waiting for a cv_signal on the bus reset condition variable.
 *    Used by the bus reset thread for synchronizing with the bus reset/
 *    self id interrupt callback from the hal. Does CPR initialization
 *    first time it is called. If services layer sees a valid self id
 *    buffer, it builds the topology tree and signals the bus reset thread
 *    to read the config roms as appropriate (indicated by BR_THR_CFGROM_SCAN).
 *    If the services layer wishes to kill the bus reset thread, it signals
 *    this by signaling a BR_THR_GO_AWAY event.
 */
static void
s1394_wait_for_events(s1394_hal_t *hal, int firsttime)
{
	uint_t event;

	ASSERT(MUTEX_NOT_HELD(&hal->br_thread_mutex));
	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	if (firsttime)
		CALLB_CPR_INIT(&hal->hal_cprinfo, &hal->br_thread_mutex,
		    callb_generic_cpr, "s1394_br_thread");

	/* Check and wait for a BUS RESET */
	mutex_enter(&hal->br_thread_mutex);
	while ((event = hal->br_thread_ev_type) == 0) {
		CALLB_CPR_SAFE_BEGIN(&hal->hal_cprinfo);
		cv_wait(&hal->br_thread_cv, &hal->br_thread_mutex);
		CALLB_CPR_SAFE_END(&hal->hal_cprinfo, &hal->br_thread_mutex);
	}

	if (event & BR_THR_GO_AWAY) {
		s1394_br_thread_exit(hal);
		/*NOTREACHED*/
		return;
	}

	if (firsttime) {
		mutex_exit(&hal->br_thread_mutex);
		return;
	}

	mutex_enter(&hal->topology_tree_mutex);
	hal->br_cfgrom_read_gen = hal->generation_count;

	hal->br_thread_ev_type &= ~BR_THR_CFGROM_SCAN;
	mutex_exit(&hal->topology_tree_mutex);
	mutex_exit(&hal->br_thread_mutex);
}

/*
 * s1394_wait_for_cfgrom_callbacks()
 *    Waits for completed config rom reads. Takes each completion off the
 *    completion queue and passes it to the "completion handler" function
 *    that was passed in as an argument. Further processing of the completion
 *    queue depends on the return status of the completion handler. If there
 *    is a bus reset while waiting for completions or if the services layer
 *    signals BR_THR_GO_AWAY, quits waiting for completions and returns
 *    non-zero. Also returns non-zero if completion handler returns
 *    S1394_HCMD_LOCK_FAILED.  Returns 0 if config roms for all nodes have
 *    been dealt with.
 */
static int
s1394_wait_for_cfgrom_callbacks(s1394_hal_t *hal, uint_t wait_gen,
    hcmd_ret_t(*handle_cmd_fn)(s1394_hal_t *hal, cmd1394_cmd_t *cmd))
{
	cmd1394_cmd_t *cmd;
	s1394_cmd_priv_t *s_priv;
	int ret, done = 0;
	hcmd_ret_t cmdret;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	ret = DDI_SUCCESS;

	while (!done) {
		mutex_enter(&hal->br_cmplq_mutex);
		mutex_enter(&hal->topology_tree_mutex);
		while (wait_gen == hal->generation_count &&
		    (hal->br_thread_ev_type & BR_THR_GO_AWAY) == 0 &&
		    hal->br_cmplq_head == NULL) {
			mutex_exit(&hal->topology_tree_mutex);
			cv_wait(&hal->br_cmplq_cv, &hal->br_cmplq_mutex);
			mutex_enter(&hal->topology_tree_mutex);
		}
		ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
		if (wait_gen != hal->generation_count ||
		    (hal->br_thread_ev_type & BR_THR_GO_AWAY) != 0) {
			mutex_exit(&hal->topology_tree_mutex);
			mutex_exit(&hal->br_cmplq_mutex);
			s1394_flush_cmplq(hal);
			return (DDI_FAILURE);
		}
		mutex_exit(&hal->topology_tree_mutex);

		if ((cmd = hal->br_cmplq_head) != NULL) {
			s_priv = S1394_GET_CMD_PRIV(cmd);

			hal->br_cmplq_head = s_priv->cmd_priv_next;
		}
		if (cmd == hal->br_cmplq_tail)
			hal->br_cmplq_tail = NULL;
		mutex_exit(&hal->br_cmplq_mutex);

		if (cmd != NULL) {
			if (cmd->bus_generation != wait_gen) {
				(void) s1394_free_cmd(hal, &cmd);
				continue;
			}
			cmdret = (*handle_cmd_fn)(hal, cmd);
			ASSERT(cmdret != S1394_HCMD_INVALID);
			if (cmdret == S1394_HCMD_LOCK_FAILED) {
				/* flush completion queue */
				ret = DDI_FAILURE;
				s1394_flush_cmplq(hal);
				break;
			} else if (cmdret == S1394_HCMD_NODE_DONE) {
				if (--hal->cfgroms_being_read == 0) {
					/* All done */
					break;
				}
			} else {
				ASSERT(cmdret == S1394_HCMD_NODE_EXPECT_MORE);
				done = 0;
			}
		}
	}

	return (ret);
}

/*
 * s1394_flush_cmplq()
 *    Frees all cmds on the completion queue.
 */
static void
s1394_flush_cmplq(s1394_hal_t *hal)
{
	s1394_cmd_priv_t *s_priv;
	cmd1394_cmd_t *cmd, *tcmd;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	cmd = NULL;

	do {
		mutex_enter(&hal->br_cmplq_mutex);
		cmd = hal->br_cmplq_head;
		hal->br_cmplq_head = hal->br_cmplq_tail = NULL;
		mutex_exit(&hal->br_cmplq_mutex);

		while (cmd != NULL) {
			s_priv = S1394_GET_CMD_PRIV(cmd);

			tcmd = s_priv->cmd_priv_next;
			(void) s1394_free_cmd(hal, &cmd);
			cmd = tcmd;
		}

		mutex_enter(&hal->br_cmplq_mutex);
		cmd = hal->br_cmplq_head;
		mutex_exit(&hal->br_cmplq_mutex);

	} while (cmd != NULL);
}

/*
 * s1394_br_thread_exit()
 *    Flushes the completion queue and calls thread_exit() (which effectively
 *    kills the bus reset thread).
 */
static void
s1394_br_thread_exit(s1394_hal_t *hal)
{
	ASSERT(MUTEX_HELD(&hal->br_thread_mutex));
	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
	s1394_flush_cmplq(hal);
#ifndef	__lock_lint
	CALLB_CPR_EXIT(&hal->hal_cprinfo);
#endif
	hal->br_thread_ev_type &= ~BR_THR_GO_AWAY;
	thread_exit();
	/*NOTREACHED*/
}

/*
 * s1394_target_bus_reset_notifies()
 *    tells the ndi event framework to invoke any callbacks registered for
 *    "bus reset event".
 */
static void
s1394_target_bus_reset_notifies(s1394_hal_t *hal, t1394_localinfo_t *localinfo)
{
	ddi_eventcookie_t cookie;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	if (ndi_event_retrieve_cookie(hal->hal_ndi_event_hdl, NULL,
	    DDI_DEVI_BUS_RESET_EVENT, &cookie, NDI_EVENT_NOPASS) ==
	    NDI_SUCCESS) {
		(void) ndi_event_run_callbacks(hal->hal_ndi_event_hdl, NULL,
		    cookie, localinfo);
	}
}

/*
 * s1394_alloc_cfgrom()
 *    Allocates config rom for the node. Sets CFGROM_NEW_ALLOC bit in the
 *    node cfgrom state. Drops topology_tree_mutex around the calls to
 *    kmem_zalloc(). If re-locking fails, returns DDI_FAILURE, else returns
 *    DDI_SUCCESS.
 */
static int
s1394_alloc_cfgrom(s1394_hal_t *hal, s1394_node_t *node, s1394_status_t *status)
{
	uint32_t *cfgrom;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	*status = S1394_NOSTATUS;

	/*
	 * if cfgrom is non-NULL, this has to be generation changed
	 * case (where we allocate cfgrom again to reread the cfgrom)
	 */
	ASSERT(node->cfgrom == NULL || (node->cfgrom != NULL &&
	    CFGROM_GEN_CHANGED(node) == B_TRUE));

	/*
	 * if node matched, either cfgrom has to be NULL or link should be
	 * off in the last matched node or config rom generations changed.
	 */
	ASSERT(NODE_MATCHED(node) == B_FALSE || (NODE_MATCHED(node) == B_TRUE &&
	    (node->cfgrom == NULL || LINK_ACTIVE(node->old_node) == B_FALSE) ||
	    CFGROM_GEN_CHANGED(node) == B_TRUE));

	s1394_unlock_tree(hal);
	cfgrom = (uint32_t *)kmem_zalloc(IEEE1394_CONFIG_ROM_SZ, KM_SLEEP);
	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		kmem_free(cfgrom, IEEE1394_CONFIG_ROM_SZ);
		*status |= S1394_LOCK_FAILED;
		return (DDI_FAILURE);
	}
	node->cfgrom = cfgrom;
	node->cfgrom_size = IEEE1394_CONFIG_ROM_QUAD_SZ;
	SET_CFGROM_NEW_ALLOC(node);
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	return (DDI_SUCCESS);
}

/*
 * s1394_free_cfgrom()
 *    Marks the config rom invalid and frees up the config based on otpions.
 */
void
s1394_free_cfgrom(s1394_hal_t *hal, s1394_node_t *node,
    s1394_free_cfgrom_t options)
{
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	ASSERT(node->cfgrom != NULL);

	if (options == S1394_FREE_CFGROM_BOTH) {
		/*
		 * free in both old and new trees; will be called with
		 * new node.
		 */
		s1394_node_t *onode = node->old_node;

		if (NODE_MATCHED(node) == B_TRUE && onode->cfgrom != NULL)
			ASSERT(onode->cfgrom == node->cfgrom);

		if (onode != NULL && onode->cfgrom != NULL && onode->cfgrom !=
		    node->cfgrom)
			kmem_free(onode->cfgrom, IEEE1394_CONFIG_ROM_SZ);

		kmem_free(node->cfgrom, IEEE1394_CONFIG_ROM_SZ);
		onode->cfgrom = NULL;
		node->cfgrom = NULL;

		CLEAR_CFGROM_STATE(onode);
		CLEAR_CFGROM_STATE(node);

	} else if (options == S1394_FREE_CFGROM_NEW) {

		ASSERT(CFGROM_NEW_ALLOC(node) == B_TRUE);
		kmem_free(node->cfgrom, IEEE1394_CONFIG_ROM_SZ);
		CLEAR_CFGROM_NEW_ALLOC(node);
		node->cfgrom = NULL;
		CLEAR_CFGROM_STATE(node);

	} else if (options == S1394_FREE_CFGROM_OLD) {

		/* freeing in old tree */
		kmem_free(node->cfgrom, IEEE1394_CONFIG_ROM_SZ);
		node->cfgrom = NULL;
		CLEAR_CFGROM_STATE(node);
	}
}

/*
 * s1394_copy_cfgrom()
 *    Copies config rom info from "from" node to "to" node. Clears
 *    CFGROM_NEW_ALLOC bit in cfgrom state in bothe nodes. (CFGROM_NEW_ALLOC
 *    acts as a reference count. If set, only the node in the current tree
 *    has a pointer to it; if clear, both the node in the current tree as
 *    well as the corresponding node in the old tree point to the same memory).
 */
void
s1394_copy_cfgrom(s1394_node_t *to, s1394_node_t *from)
{
	ASSERT(to->cfgrom == NULL);

	to->cfgrom = from->cfgrom;
	to->cfgrom_state = from->cfgrom_state;
	to->cfgrom_valid_size = from->cfgrom_valid_size;
	to->cfgrom_size = from->cfgrom_size;
	to->node_state = from->node_state;

	bcopy(from->dir_stack, to->dir_stack,
	    offsetof(s1394_node_t, cfgrom_quad_to_read) -
	    offsetof(s1394_node_t, dir_stack));

	to->cfgrom_quad_to_read = from->cfgrom_quad_to_read;

	CLEAR_CFGROM_NEW_ALLOC(to);
	CLEAR_CFGROM_NEW_ALLOC(from);

	/*
	 * old link off, new link on => handled in s1394_cfgrom_scan_phase1
	 * old link on, new link off => handled in s1394_process_old_tree
	 */
	if (LINK_ACTIVE(from) == B_FALSE) {
		/*
		 * if last time around, link was off, there wouldn't
		 * have been config rom allocated.
		 */
		ASSERT(from->cfgrom == NULL);
		return;
	} else {
		s1394_selfid_pkt_t *selfid_pkt = to->selfid_packet;

		if (IEEE1394_SELFID_ISLINKON(selfid_pkt))
			SET_LINK_ACTIVE(to);
	}
}

/*
 * s1394_read_bus_info_blk()
 *    Attempts to kick off reading IEEE1212_NODE_CAP_QUAD quad or quad 0.
 *    Increments cfgroms_being_read by 1. Returns DDI_SUCCESS command was
 *    issued, else sets status to the failure reason and returns DDI_FAILURE.
 */
static int
s1394_read_bus_info_blk(s1394_hal_t *hal, s1394_node_t *node,
    s1394_status_t *status)
{
	uint32_t quadlet;
	cmd1394_cmd_t *cmd;
	uchar_t node_num;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	ASSERT(LINK_ACTIVE(node) == B_TRUE);

	node_num = node->node_num;

	/*
	 * drop the topology lock around command allocation. Return failure
	 * if either command allocation fails or cannot reacquire the lock
	 */
	s1394_unlock_tree(hal);
	*status = S1394_NOSTATUS;

	if (s1394_alloc_cmd(hal, 0, &cmd) != DDI_SUCCESS) {
		*status |= S1394_CMD_ALLOC_FAILED;
	}
	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		*status |= S1394_LOCK_FAILED;
		/* free the cmd allocated above */
		if (((*status) & S1394_CMD_ALLOC_FAILED) != 0)
			(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
	}
	if (((*status) & (S1394_CMD_ALLOC_FAILED | S1394_LOCK_FAILED)) != 0) {
		return (DDI_FAILURE);
	}

	/* allocate cfgrom if needed */
	if (node->cfgrom == NULL && s1394_alloc_cfgrom(hal, node, status) !=
	    DDI_SUCCESS) {
		ASSERT(((*status) & S1394_LOCK_FAILED) != 0);
		(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
		ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
		return (DDI_FAILURE);
	}

	/*
	 * if this is a matched node, read quad 2 (node capabilities) to
	 * see if the generation count changed.
	 */
	quadlet = CFGROM_BIB_READ(node) ? IEEE1212_NODE_CAP_QUAD : 0;

	/*
	 * read bus info block at 100Mbit. This will help us with the cases
	 * where LINK is slower than PHY; s1394 uses PHY speed till speed map
	 * is updated.
	 */
	cmd->completion_callback = s1394_cfgrom_read_callback;
	cmd->bus_generation = hal->generation_count;
	cmd->cmd_options = (CMD1394_CANCEL_ON_BUS_RESET |
	    CMD1394_OVERRIDE_ADDR | CMD1394_OVERRIDE_SPEED);
	cmd->cmd_speed = IEEE1394_S100;
	cmd->cmd_type = CMD1394_ASYNCH_RD_QUAD;

	QUAD_TO_CFGROM_ADDR(IEEE1394_LOCAL_BUS, node_num,
	    quadlet, cmd->cmd_addr);

	SETUP_QUAD_READ(node, 1, quadlet, 1);
	if (s1394_read_config_quadlet(hal, cmd, status) != DDI_SUCCESS) {
		/* free the command if it wasn't handed over to the HAL */
		if (((*status) & S1394_CMD_INFLIGHT) == 0) {
			(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
		}
		if (((*status) & S1394_LOCK_FAILED) != 0) {
			ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
		}
		return (DDI_FAILURE);
	}

	hal->cfgroms_being_read++;
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	return (DDI_SUCCESS);
}

/*
 * s1394_read_rest_of_cfgrom()
 *    Attempts to start reading node->cfgrom_quad_to_read quadlet. Increments
 *    cfgroms_being_read by 1 and returns DDI_SUCCESS if command was issued,
 *    else sets status to the failure reason and returns DDI_FAILURE.
 */
int
s1394_read_rest_of_cfgrom(s1394_hal_t *hal, s1394_node_t *node,
    s1394_status_t *status)
{
	cmd1394_cmd_t *cmd;
	uchar_t node_num = node->node_num;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	ASSERT(LINK_ACTIVE(node) == B_TRUE);

	/*
	 * drop the topology lock around command allocation. Return failure
	 * if either command allocation fails or cannot reacquire the lock
	 */
	s1394_unlock_tree(hal);
	*status = S1394_NOSTATUS;

	if (s1394_alloc_cmd(hal, 0, &cmd) != DDI_SUCCESS) {
		*status |= S1394_CMD_ALLOC_FAILED;
	}
	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		*status |= S1394_LOCK_FAILED;
		/* free if we allocated a cmd above */
		if (((*status) & S1394_CMD_ALLOC_FAILED) == 0)
			(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
	}
	if (((*status) & (S1394_CMD_ALLOC_FAILED | S1394_LOCK_FAILED)) != 0) {
		return (DDI_FAILURE);
	}

	cmd->completion_callback = s1394_cfgrom_read_callback;
	cmd->bus_generation = hal->generation_count;
	cmd->cmd_options = (CMD1394_CANCEL_ON_BUS_RESET |
	    CMD1394_OVERRIDE_ADDR);
	cmd->cmd_type = CMD1394_ASYNCH_RD_QUAD;

	QUAD_TO_CFGROM_ADDR(IEEE1394_LOCAL_BUS, node_num,
	    node->cfgrom_quad_to_read, cmd->cmd_addr);
	SETUP_QUAD_READ(node, 1, node->cfgrom_quad_to_read, 1);
	if (s1394_read_config_quadlet(hal, cmd, status) != DDI_SUCCESS) {
		/* free the command if it wasn't handed over to the HAL */
		if (((*status) & S1394_CMD_INFLIGHT) == 0) {
			(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
		}
		if (((*status) & S1394_LOCK_FAILED) != 0) {
			ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
		}
		return (DDI_FAILURE);
	}

	hal->cfgroms_being_read++;
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	return (DDI_SUCCESS);
}

/*
 * s1394_cfgrom_scan_phase1()
 *    Attempts to read bus info blocks for nodes as needed. Returns DDI_FAILURE
 *    if bus reset generations changed (as indicated by s1394_lock_tree()
 *    return status) or if any of the callees return failure, else returns
 *    DDI_SUCCESS.
 */
static int
s1394_cfgrom_scan_phase1(s1394_hal_t *hal)
{
	uint32_t number_of_nodes;
	int ret;
	int node;
	int wait_in_gen;
	int wait_for_cbs;
	uint_t hal_node_num;
	uint_t hal_node_num_old;
	s1394_node_t *nnode, *onode;
	s1394_selfid_pkt_t *selfid_pkt;
	s1394_status_t status;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	wait_for_cbs = 0;
	number_of_nodes = hal->number_of_nodes;
	hal->cfgroms_being_read = 0;
	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	hal_node_num_old = IEEE1394_NODE_NUM(hal->old_node_id);
	s1394_unlock_tree(hal);

	ret = DDI_SUCCESS;

	/* Send requests for all new node config ROM 0 */
	for (node = 0; node < number_of_nodes; node++) {

		status = S1394_UNKNOWN;

		if (s1394_lock_tree(hal) != DDI_SUCCESS) {
			status = S1394_LOCK_FAILED;
			break;
		}

		nnode = &hal->topology_tree[node];
		onode = nnode->old_node;
		/* if node matched, onode should be non NULL */
		ASSERT(NODE_MATCHED(nnode) == B_FALSE || (NODE_MATCHED(nnode) ==
		    B_TRUE && onode != NULL));

		/*
		 * Read bus info block if it is a brand new node (MATCHED is 0)
		 * or if matched but link was off in previous generations or
		 * or if matched but had invalid cfgrom in last generation
		 * or if matched but config rom generation > 1 (this is to
		 * check if config rom generation changed between bus resets).
		 */
		if ((node != hal_node_num) &&
		    ((NODE_MATCHED(nnode) == B_FALSE) ||
		    (NODE_MATCHED(nnode) == B_TRUE && LINK_ACTIVE(onode) ==
		    B_FALSE) || (NODE_MATCHED(nnode) == B_TRUE &&
		    (onode->cfgrom == NULL || CFGROM_VALID(onode) ==
		    B_FALSE)) || (NODE_MATCHED(nnode) == B_TRUE &&
		    nnode->cfgrom != NULL && CONFIG_ROM_GEN(nnode->cfgrom) >
		    1))) {

			SET_NODE_VISITED(nnode);
			selfid_pkt = nnode->selfid_packet;
			if (IEEE1394_SELFID_ISLINKON(selfid_pkt)) {

				SET_LINK_ACTIVE(nnode);

				status = S1394_UNKNOWN;

				if (s1394_read_bus_info_blk(hal, nnode,
				    &status) != DDI_SUCCESS) {
					if ((status & S1394_LOCK_FAILED) != 0)
						break;
				} else {
					wait_for_cbs++;
					wait_in_gen = hal->br_cfgrom_read_gen;
				}
			} else {
				/*
				 * Special case: if link was active last
				 * time around, this should be treated as
				 * node going away.
				 */
				CLEAR_LINK_ACTIVE(nnode);
				if (NODE_MATCHED(nnode) == B_TRUE &&
				    LINK_ACTIVE(onode) == B_TRUE) {
					CLEAR_CFGROM_STATE(nnode);
				}
			}
		} else {
			if (node == hal_node_num) {
				onode = &hal->old_tree[hal_node_num_old];
				/* Set up the local matched nodes */
				if (onode) {
					nnode->old_node = onode;
					SET_NODE_MATCHED(nnode);
					SET_NODE_MATCHED(onode);
					s1394_copy_cfgrom(nnode, onode);
				}
			}
		}
		s1394_unlock_tree(hal);
	}

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	if ((status & S1394_LOCK_FAILED) != 0) {
		return (DDI_FAILURE);
	}

	/*
	 * If we started any reads, wait for completion callbacks
	 */
	if (wait_for_cbs != 0) {
		ret = s1394_wait_for_cfgrom_callbacks(hal, wait_in_gen,
		    s1394_br_thread_handle_cmd_phase1);
	}

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	return (ret);
}

/*
 * s1394_br_thread_handle_cmd_phase1()
 *    Process the cmd completion for phase 1 config rom reads. If we
 *    successfully read IEEE1212_NODE_CAP_QUAD quadlet and config rom gen
 *    did not change, move targets hanging off the old node to the current
 *    node. If config rom generations change, alloc new config rom and start
 *    re-reading the new config rom. If all of bus info block is read (as
 *    required), mark the node as CFGROM_BIB_READ. If config rom read fails
 *    retry if not too many failures. Topology tree mutex is dropped and
 *    reacquired in this routine. If reacquiring fails, returns
 *    S1394_HCMD_LOCK_FAILED. If the entire bus info block is read, returns
 *    S1394_HCMD_NODE_DONE, else returns S1394_HCMD_NODE_EXPECT_MORE (to
 *    indicate not done with the node yet).
 *
 *    If we cannot read any of the quadlets in the bus info block, cfgrom
 *    is marked invalid in this generation (a side effect of calling
 *    s1394_free_cfgrom()). We free cfgrom in this routine only if the failure
 *    is not due to bus generations changing.
 */
static hcmd_ret_t
s1394_br_thread_handle_cmd_phase1(s1394_hal_t *hal, cmd1394_cmd_t *cmd)
{
	s1394_target_t *t;
	s1394_node_t *node, *onode;
	uint32_t node_num, quadlet, data;
	int freecmd, done, locked;
	hcmd_ret_t cmdret;
	uchar_t readdelay;
	s1394_status_t status;

	s1394_get_quad_info(cmd, &node_num, &quadlet, &data);
	ASSERT(quadlet == 0 || quadlet < IEEE1394_BIB_QUAD_SZ);

	cmdret = S1394_HCMD_NODE_EXPECT_MORE;

	locked = 1;
	freecmd = 1;

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		locked = 0;
		goto bail;
	}

	node = &hal->topology_tree[node_num];

	if (cmd->cmd_result == CMD1394_CMDSUCCESS) {

		int reread = 0;

		done = 0;

		if (quadlet == IEEE1212_NODE_CAP_QUAD &&
		    CFGROM_BIB_READ(node)) {

			int cur_gen = ((data & IEEE1394_BIB_GEN_MASK) >>
			    IEEE1394_BIB_GEN_SHIFT);

			/*
			 * node->old_node can be NULL if this is a new node &
			 * we are doing a rescan
			 */
			onode = node->old_node;
			if (CONFIG_ROM_GEN(node->cfgrom) == cur_gen) {

				if (CFGROM_PARSED(node) == B_TRUE) {
					rw_enter(&hal->target_list_rwlock,
					    RW_WRITER);
					/* Update the target list, if any */
					if (onode != NULL &&
					    (t = onode->target_list) != NULL) {
						node->target_list = t;
						while (t != NULL) {
							t->on_node = node;
							t = t->target_sibling;
						}
					}
					rw_exit(&hal->target_list_rwlock);
				}
				SET_NODE_MATCHED(node);
				if (onode)
					SET_NODE_MATCHED(onode);
				node->cfgrom_quad_to_read =
				    IEEE1394_BIB_QUAD_SZ;
				done++;
			} else {

				SET_CFGROM_GEN_CHANGED(node);
				if (onode != NULL)
					SET_CFGROM_GEN_CHANGED(onode);
				/*
				 * Reset BIB_READ flag and start reading entire
				 * config rom.
				 */
				CLEAR_CFGROM_BIB_READ(node);
				reread = 1;

				/*
				 * if generations changed, allocate cfgrom for
				 * the new generation. s1394_match_GUID() will
				 * free up the cfgrom from the old generation.
				 */
				if (s1394_alloc_cfgrom(hal, node, &status) !=
				    DDI_SUCCESS) {
					ASSERT((status & S1394_LOCK_FAILED) !=
					    0);
					ASSERT(MUTEX_NOT_HELD(&hal->
					    topology_tree_mutex));
					locked = 0;
					/* we failed to relock the tree */
					goto bail;
				}
			}
		}

		/*
		 * we end up here if we don't have bus_info_blk for this
		 * node or if config rom generation changed.
		 */

		/*
		 * Pass1 Rio bug workaround. Due to this bug, if we read
		 * past quadlet 5 of the config rom, the PCI bus gets wedged.
		 * Avoid the hang by not reading past quadlet 5.
		 * We identify a remote Rio by the node vendor id part of
		 * quad 3 (which is == SUNW == S1394_SUNW_OUI (0x80020)).
		 */
		if (s1394_enable_rio_pass1_workarounds != 0) {
			if ((quadlet == 3) && ((data >> 8) == S1394_SUNW_OUI)) {
				node->cfgrom_size = IEEE1394_BIB_QUAD_SZ;
				node->cfgrom_valid_size = IEEE1394_BIB_QUAD_SZ;
			}
		}

		if (!done) {

			if (reread)
				quadlet = 0;
			else
				node->cfgrom[quadlet++] = data;

			/* if we don't have the entire bus_info_blk... */
			if (quadlet < IEEE1394_BIB_QUAD_SZ) {

				CFGROM_GET_READ_DELAY(node, readdelay);
				SETUP_QUAD_READ(node, 1, quadlet, 1);
				s1394_unlock_tree(hal);
				CFGROM_READ_PAUSE(readdelay);
				/* get next quadlet */
				if (s1394_lock_tree(hal) != DDI_SUCCESS) {
					locked = 0;
				} else if (s1394_read_config_quadlet(hal, cmd,
				    &status) != DDI_SUCCESS) {
					/*
					 * Failed to get going. If command was
					 * successfully handed over to the HAL,
					 * don't free it (it will get freed
					 * later in the callback).
					 */
					if ((status & S1394_CMD_INFLIGHT) !=
					    0) {
						freecmd = 0;
					}
					if ((status & S1394_LOCK_FAILED) != 0) {
						locked = 0;
					} else {
						if (CFGROM_NEW_ALLOC(node) ==
						    B_TRUE) {
							s1394_free_cfgrom(hal,
							    node,
							S1394_FREE_CFGROM_NEW);
						} else {
							CLEAR_CFGROM_STATE(
							    node);
						}
					}
					done++;
				} else {
					freecmd = 0;
				}
			} else {
				/* got all of bus_info_blk */
				SET_CFGROM_BIB_READ(node);
				if (node->cfgrom_size == IEEE1394_BIB_QUAD_SZ)
				    SET_CFGROM_ALL_READ(node);
				node->cfgrom_quad_to_read = quadlet;
				done++;
			}
		}
	} else {
		done = 1;
		node->cfgrom_read_fails++;
		BUMP_CFGROM_READ_DELAY(node);

		/* retry if not too many failures */
		if (node->cfgrom_read_fails < s1394_cfgrom_read_retry_cnt) {
			CFGROM_GET_READ_DELAY(node, readdelay);
			SETUP_QUAD_READ(node, 0, quadlet, 1);
			s1394_unlock_tree(hal);
			CFGROM_READ_PAUSE(readdelay);
			if (s1394_lock_tree(hal) != DDI_SUCCESS) {
				locked = 0;
			} else if (s1394_read_config_quadlet(hal, cmd,
			    &status) != DDI_SUCCESS) {
				/*
				 * Failed to get going. If command was
				 * successfully handed over to the HAL,
				 * don't free it (it will get freed
				 * later in the callback).
				 */
				if ((status & S1394_CMD_INFLIGHT) != 0) {
					freecmd = 0;
				}
				if ((status & S1394_LOCK_FAILED) != 0) {
					locked = 0;
				} else {
					if (CFGROM_NEW_ALLOC(node) == B_TRUE) {
						s1394_free_cfgrom(hal, node,
						    S1394_FREE_CFGROM_NEW);
					} else {
						CLEAR_CFGROM_STATE(node);
					}
				}
			} else {
				done = 0;
				freecmd = 0;
			}
		} else {
			if (CFGROM_NEW_ALLOC(node) == B_TRUE) {
				s1394_free_cfgrom(hal, node,
				    S1394_FREE_CFGROM_NEW);
			} else {
				CLEAR_CFGROM_STATE(node);
			}
		}
	}
bail:
	if (freecmd) {
		(void) s1394_free_cmd(hal, &cmd);
	}

	if (done) {
		cmdret = S1394_HCMD_NODE_DONE;
	}

	/* if we are bailing out because locking failed, locked == 0 */
	if (locked == 0)
		cmdret = S1394_HCMD_LOCK_FAILED;
	else
		s1394_unlock_tree(hal);

	return (cmdret);
}

/*
 * s1394_cfgrom_scan_phase2()
 *    Handles phase 2 of bus reset processing. Matches GUIDs between old
 *    and new topology trees to identify which node moved where. Processes
 *    the old topology tree (involves offlining any nodes that got unplugged
 *    between the last generation and the current generation). Updates speed
 *    map, sets up physical AR request filer and does isoch resource
 *    realloc failure notification and bus reset notifications. Then resends
 *    any commands that were issued by targets while the reset was being
 *    processed. Finally, the current topology tree is processed. This involves
 *    reading config rom past the bus info block for new nodes and parsing
 *    the config rom, creating a devinfo for each unit directory found in the
 *    config rom.
 *    Returns DDI_FAILURE if there was bus reset during any of the function
 *    calls (as indicated by lock failures) or if any of the routines callees
 *    return failure, else returns DDI_SUCCESS.
 */
static int
s1394_cfgrom_scan_phase2(s1394_hal_t *hal)
{
	int ret;
	uint_t wait_gen;
	int wait_for_cbs = 0;
	t1394_localinfo_t localinfo;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (s1394_match_all_GUIDs(hal) == DDI_SUCCESS) {
		s1394_unlock_tree(hal);
	}

	if (s1394_process_old_tree(hal) != DDI_SUCCESS) {
		ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
		return (DDI_FAILURE);
	}

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	s1394_update_speed_map_link_speeds(hal);
	s1394_unlock_tree(hal);

	/* Setup physical AR request filters */
	s1394_physical_arreq_setup_all(hal);

	/* Notify targets of isoch resource realloc failures */
	s1394_isoch_rsrc_realloc_notify(hal);

	/* Notify targets of the end of bus reset processing */
	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	localinfo.bus_generation = hal->generation_count;
	localinfo.local_nodeID = hal->node_id;

	s1394_unlock_tree(hal);
	s1394_target_bus_reset_notifies(hal, &localinfo);
	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Set HAL state to normal */
	if (hal->disable_requests_bit == 0)
		hal->hal_state = S1394_HAL_NORMAL;
	else
		hal->hal_state = S1394_HAL_DREQ;

	s1394_unlock_tree(hal);

	/* Flush the pending Q */
	s1394_resend_pending_cmds(hal);

	if (s1394_process_topology_tree(hal, &wait_for_cbs, &wait_gen)) {
		ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
		return (DDI_FAILURE);
	}

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	s1394_print_node_info(hal);

	s1394_unlock_tree(hal);

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	ret = DDI_SUCCESS;

	/*
	 * If we started any reads, wait for completion callbacks
	 */
	if (wait_for_cbs != 0) {
		ret = s1394_wait_for_cfgrom_callbacks(hal, wait_gen,
		    s1394_br_thread_handle_cmd_phase2);
	}

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	return (ret);
}

/*
 * s1394_br_thread_handle_cmd_phase2()
 *    Process the cmd completion for phase 2 config rom reads. If all the
 *    needed quads are read, validates the config rom; if config rom is
 *    invalid (crc failures), frees the config rom, else marks the config rom
 *    valid and calls s1394_update_devinfo_tree() to parse the config rom.
 *    If need to get more quadlets, attempts to kick off the read and returns
 *    S1394_HCMD_NODE_EXPECT_MORE if successfully started the read. If a bus
 *    reset is seen while in this routine, returns S1394_HCMD_LOCK_FAILED. If
 *    done with the node (with or withoug crc errors), returns
 *    S1394_HCMD_NODE_DONE, else returns S1394_HCMD_NODE_EXPECT_MORE (to
 *    indicate not done with the node yet).
 */
static hcmd_ret_t
s1394_br_thread_handle_cmd_phase2(s1394_hal_t *hal, cmd1394_cmd_t *cmd)
{
	s1394_node_t *node;
	uint32_t node_num, quadlet, data;
	int update_devinfo, locked, freecmd, done;
	hcmd_ret_t cmdret;
	uchar_t readdelay;
	s1394_status_t status;

	/*
	 * we end up here if this is a brand new node or if it is a known node
	 * but the config ROM changed (and triggered a re-read).
	 */
	s1394_get_quad_info(cmd, &node_num, &quadlet, &data);
	ASSERT(quadlet == IEEE1394_BIB_QUAD_SZ || quadlet <
	    IEEE1394_CONFIG_ROM_QUAD_SZ);

	locked = freecmd = done = 1;
	cmdret = S1394_HCMD_NODE_EXPECT_MORE;

	update_devinfo = 0;

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		locked = 0;
		goto bail;
	}

	node = &hal->topology_tree[node_num];

	if (cmd->cmd_result == CMD1394_CMDSUCCESS) {

		ASSERT(CFGROM_BIB_READ(node) == B_TRUE);

		node->cfgrom[quadlet] = data;

		if (s1394_calc_next_quad(hal, node, quadlet, &quadlet) != 0) {
			/*
			 * Done with this node. Mark config rom valid and
			 * update the devinfo tree for this node.
			 */
			node->cfgrom_valid_size = quadlet + 1;
			if (s1394_valid_cfgrom(hal, node) == B_TRUE) {
				SET_CFGROM_ALL_READ(node);
				update_devinfo++;
			} else {
				s1394_free_cfgrom(hal, node,
				    S1394_FREE_CFGROM_BOTH);
			}
		} else {
			CFGROM_GET_READ_DELAY(node, readdelay);
			SETUP_QUAD_READ(node, 1, quadlet, 1);
			s1394_unlock_tree(hal);
			CFGROM_READ_PAUSE(readdelay);
			if (s1394_lock_tree(hal) != DDI_SUCCESS) {
				locked = 0;
			} else if (s1394_read_config_quadlet(hal, cmd,
			    &status) != DDI_SUCCESS) {
				/* give up on this guy */
				if ((status & S1394_CMD_INFLIGHT) != 0) {
					freecmd = 0;
				}
				if ((status & S1394_LOCK_FAILED) != 0) {
					locked = 0;
				} else {
					node->cfgrom_valid_size = quadlet;
					if (s1394_valid_cfgrom(hal, node) ==
					    B_TRUE) {
						SET_CFGROM_ALL_READ(node);
						update_devinfo++;
					} else {
						s1394_free_cfgrom(hal, node,
						    S1394_FREE_CFGROM_BOTH);
					}
				}
			} else {
				/* successfully started next read */
				done = 0;
				freecmd = 0;
			}
		}
	} else {
		node->cfgrom_read_fails++;
		BUMP_CFGROM_READ_DELAY(node);

		/* retry if not too many failures */
		if (node->cfgrom_read_fails < s1394_cfgrom_read_retry_cnt) {
			CFGROM_GET_READ_DELAY(node, readdelay);
			s1394_unlock_tree(hal);
			SETUP_QUAD_READ(node, 0, quadlet, 1);
			CFGROM_READ_PAUSE(readdelay);
			if (s1394_lock_tree(hal) != DDI_SUCCESS) {
				locked = 0;
			} else if (s1394_read_config_quadlet(hal, cmd,
			    &status) != DDI_SUCCESS) {
				if ((status & S1394_CMD_INFLIGHT) != 0) {
					freecmd = 0;
				}
				if ((status & S1394_LOCK_FAILED) != 0) {
					locked = 0;
				} else {
					/* stop further reads */
					node->cfgrom_valid_size = quadlet + 1;
					if (s1394_valid_cfgrom(hal, node) ==
					    B_TRUE) {
						SET_CFGROM_ALL_READ(node);
						update_devinfo++;
					} else {
						s1394_free_cfgrom(hal, node,
						    S1394_FREE_CFGROM_BOTH);
					}
				}
			} else {
				/* successfully started next read */
				done = 0;
				freecmd = 0;
			}
		} else {
			node->cfgrom_valid_size = quadlet + 1;
			if (s1394_valid_cfgrom(hal, node) == B_TRUE) {
				SET_CFGROM_ALL_READ(node);
				update_devinfo++;
			} else {
				s1394_free_cfgrom(hal, node,
				    S1394_FREE_CFGROM_BOTH);
			}
		}
	}
bail:
	if (freecmd) {
		(void) s1394_free_cmd(hal, &cmd);
	}

	if (done) {
		cmdret = S1394_HCMD_NODE_DONE;
	}

	if (update_devinfo) {
		ASSERT(locked);
		/*
		 * s1394_update_devinfo_tree() drops and reacquires the
		 * topology_tree_mutex. If tree lock fails, it returns
		 * a DDI_FAILURE. Set locked to 0 so in this case so that
		 * we will return S1394_HCMD_LOCK_FAILED below
		 */
		if (s1394_update_devinfo_tree(hal, node) != DDI_SUCCESS) {
			ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
			locked = 0;
		}
	}

	/* if we are bailing out because locking failed, locked == 0 */
	if (locked == 0)
		cmdret = S1394_HCMD_LOCK_FAILED;
	else
		s1394_unlock_tree(hal);

	return (cmdret);
}

/*
 * s1394_read_config_quadlet()
 *    Starts the reads of a config quadlet (deduced cmd_addr).  Returns
 *    DDI_SUCCESS if the read was started with no errors, else DDI_FAILURE
 *    is returned, with status indicating the reason for the failure(s).
 */
static int
s1394_read_config_quadlet(s1394_hal_t *hal, cmd1394_cmd_t *cmd,
    s1394_status_t *status)
{
	s1394_node_t *node;
	int ret, err, node_num, quadlet;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	node_num = IEEE1394_ADDR_PHY_ID(cmd->cmd_addr);
	node = &hal->topology_tree[node_num];
	quadlet = node->cfgrom_quad_to_read;

	/* Calculate the 64-bit address */
	QUAD_TO_CFGROM_ADDR(IEEE1394_LOCAL_BUS, node_num, quadlet,
	    cmd->cmd_addr);

	*status = S1394_NOSTATUS;

	ret = s1394_setup_asynch_command(hal, NULL, cmd, S1394_CMD_READ, &err);

	if (ret != DDI_SUCCESS) {
		*status |= S1394_UNKNOWN;
		ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
		return (DDI_FAILURE);
	}

	s1394_unlock_tree(hal);
	ret = DDI_SUCCESS;
	/* Send the command out */
	if (s1394_xfer_asynch_command(hal, cmd, &err) == DDI_SUCCESS) {
		/* Callers can expect a callback now */
		*status |= S1394_CMD_INFLIGHT;
	} else {

		s1394_cmd_priv_t *s_priv;

		/* Remove from queue */
		s1394_remove_q_asynch_cmd(hal, cmd);
		s_priv = S1394_GET_CMD_PRIV(cmd);

		s_priv->cmd_in_use = B_FALSE;

		*status |= S1394_XFER_FAILED;
		ret = DDI_FAILURE;
	}

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		*status |= S1394_LOCK_FAILED;
		ret = DDI_FAILURE;
	}

	return (ret);
}

/*
 * s1394_cfgrom_read_callback()
 *    callback routine for config rom reads. Frees the command if it failed
 *    due to bus reset else appends the command to the completion queue
 *    and signals the completion queue cv.
 */
static void
s1394_cfgrom_read_callback(cmd1394_cmd_t *cmd)
{
	cmd1394_cmd_t *tcmd;
	s1394_cmd_priv_t *s_priv;
	s1394_hal_t *hal;

#if defined(DEBUG)
	uint32_t node_num, quadlet, data;
#endif

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	hal = (s1394_hal_t *)s_priv->sent_on_hal;

#if defined(DEBUG)

	s1394_get_quad_info(cmd, &node_num, &quadlet, &data);

#endif

	if (cmd->cmd_result == CMD1394_EBUSRESET) {
		(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
	} else {
		mutex_enter(&hal->br_cmplq_mutex);

		/* Put the command on completion queue */
		s_priv->cmd_priv_next = NULL;
		if ((tcmd = hal->br_cmplq_tail) != NULL) {
			s_priv = S1394_GET_CMD_PRIV(tcmd);

			s_priv->cmd_priv_next = cmd;
		}

		hal->br_cmplq_tail = cmd;

		if (hal->br_cmplq_head == NULL)
			hal->br_cmplq_head = cmd;

		cv_signal(&hal->br_cmplq_cv);
		mutex_exit(&hal->br_cmplq_mutex);
	}
}

/*
 * s1394_cfgrom_parse_unit_dir()
 *    Parses the unit directory passed in and returns reg[2...5] of reg
 *    property (see 1275 binding for reg property defintion). Currently,
 *    returns 0 for all the values since none of the existing devices implement
 *    this and future devices, per P1212r, need a binding change.
 */
/* ARGSUSED */
void
s1394_cfgrom_parse_unit_dir(uint32_t *unit_dir, uint32_t *addr_hi,
    uint32_t *addr_lo, uint32_t *size_hi, uint32_t *size_lo)
{
	*addr_hi = *addr_lo = *size_hi = *size_lo = 0;
}

/*
 * s1394_get_quad_info()
 *    Helper routine that picks apart the various fields of a 1394 address
 */
static void
s1394_get_quad_info(cmd1394_cmd_t *cmd, uint32_t *node_num, uint32_t *quadlet,
    uint32_t *data)
{
	uint64_t addr;

	addr = cmd->cmd_addr;
	*node_num = IEEE1394_ADDR_PHY_ID(addr);
	*quadlet = ((addr & IEEE1394_ADDR_OFFSET_MASK) -
	    IEEE1394_CONFIG_ROM_ADDR);
	*quadlet = (*quadlet >> 2);
	*data = T1394_DATA32(cmd->cmd_u.q.quadlet_data);
}

/*
 * s1394_match_GUID()
 *    attempts to match nnode (which is in the current topology tree) with
 *    a node in the old topology tree by comparing GUIDs. If a match is found
 *    the old_node field of the current node and cur_node field of the old
 *    are set point to each other. Also, this routine makes both the nodes
 *    point at the same config rom.  If unable to relock the tree, returns
 *    DDI_FAILURE, else returns DDI_SUCCESS.
 */
static int
s1394_match_GUID(s1394_hal_t *hal, s1394_node_t *nnode)
{
	int old_node;
	int gen_changed;
	uint32_t old_a, old_b;
	uint32_t new_a, new_b;
	s1394_node_t *onode;
	s1394_target_t *t;
	int	ret = DDI_SUCCESS;

	ASSERT(nnode->cfgrom != NULL);
	ASSERT(CFGROM_BIB_READ(nnode));

	new_a = nnode->node_guid_hi;
	new_b = nnode->node_guid_lo;

	for (old_node = 0; old_node < hal->old_number_of_nodes; old_node++) {

		onode = &hal->old_tree[old_node];
		if (onode->cfgrom == NULL || CFGROM_BIB_READ(onode) == B_FALSE)
			continue;

		old_a = onode->node_guid_hi;
		old_b = onode->node_guid_lo;

		if ((old_a == new_a) && (old_b == new_b)) {

			if (NODE_MATCHED(onode) == B_TRUE) {
				cmn_err(CE_NOTE, "!Duplicate GUIDs: %08x%08x",
				    old_a, old_b);
				/* offline the new node that last matched */
				ret = s1394_offline_node(hal, onode->cur_node);
				/* and make the current new node invalid */
				ASSERT(CFGROM_NEW_ALLOC(nnode) == B_TRUE);
				s1394_free_cfgrom(hal, nnode,
				    S1394_FREE_CFGROM_NEW);
				break;
			}

			/*
			 * If there is indeed a cfgrom gen change,
			 * CFGROM_GEN_CHANGED() will be set iff we are matching
			 * tree nodes. Otherwise, CONFIG_ROM_GEN(old) !=
			 * CONFIG_ROM_GEN(new).
			 */
			if (CFGROM_GEN_CHANGED(nnode) == B_TRUE ||
			    (CONFIG_ROM_GEN(onode->cfgrom) !=
			    CONFIG_ROM_GEN(nnode->cfgrom))) {
				gen_changed = 1;
			} else {
				gen_changed = 0;
			}

			onode->cur_node = nnode;
			nnode->old_node = onode;
			nnode->node_state = onode->node_state;
			SET_NODE_VISITED(onode);
			SET_NODE_MATCHED(onode);
			SET_NODE_MATCHED(nnode);
			/*
			 * If generations changed, need to offline any targets
			 * hanging off the old node, prior to freeing up old
			 * cfgrom. If the generations didn't change, we can
			 * free up the new config rom and copy all info from
			 * the old node (this helps in picking up further
			 * reads from where the last generation left off).
			 */
			if (gen_changed == 1) {
				if (s1394_offline_node(hal, onode)) {
					ret = DDI_FAILURE;
					break;
				}
				s1394_free_cfgrom(hal, onode,
				    S1394_FREE_CFGROM_OLD);
				CLEAR_CFGROM_PARSED(nnode);
				CLEAR_CFGROM_NEW_ALLOC(nnode);
				CLEAR_CFGROM_NEW_ALLOC(onode);
				onode->cfgrom = nnode->cfgrom;
				/* done */
				break;
			}

			/*
			 * Free up cfgrom memory in the new_node and
			 * point it at the same config rom as the old one.
			 */
			if (onode->cfgrom != nnode->cfgrom) {
				ASSERT(CFGROM_NEW_ALLOC(nnode) == B_TRUE);
				s1394_free_cfgrom(hal, nnode,
				    S1394_FREE_CFGROM_NEW);
			}
			nnode->cfgrom = onode->cfgrom;
			nnode->cfgrom_state = onode->cfgrom_state;
			nnode->cfgrom_valid_size = onode->cfgrom_valid_size;
			nnode->cfgrom_size = onode->cfgrom_size;
			nnode->cfgrom_quad_to_read = onode->cfgrom_quad_to_read;
			bcopy(onode->dir_stack, nnode->dir_stack,
			    offsetof(s1394_node_t, cfgrom_quad_to_read) -
			    offsetof(s1394_node_t, dir_stack));
			CLEAR_CFGROM_NEW_ALLOC(nnode);
			CLEAR_CFGROM_NEW_ALLOC(onode);

			if (CFGROM_PARSED(nnode) == B_TRUE) {
				rw_enter(&hal->target_list_rwlock, RW_WRITER);
				/* Update the target list */
				if ((t = onode->target_list) != NULL) {
					nnode->target_list = t;
					while (t != NULL) {
						t->on_node = nnode;
						t = t->target_sibling;
					}
				}
				rw_exit(&hal->target_list_rwlock);
			}
			break;
		}
	}

	return (ret);
}

/*
 * s1394_match_all_GUIDs()
 *    attempt to match each node in the current topology tree with the a
 *    node in the old topology tree.  If unable to relock the tree, returns
 *    DDI_FAILURE, else returns DDI_SUCCESS.
 */
static int
s1394_match_all_GUIDs(s1394_hal_t *hal)
{
	int node;
	int ret = DDI_SUCCESS;
	s1394_node_t *nnode;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	for (node = 0; node < hal->number_of_nodes; node++) {
		nnode = &hal->topology_tree[node];
		if (LINK_ACTIVE(nnode) == B_FALSE || CFGROM_BIB_READ(nnode) ==
		    B_FALSE)
			continue;
		if (NODE_MATCHED(nnode)) {
			/*
			 * Skip if node matched. If config rom generations
			 * changed, we want to call s1394_match_GUID() even
			 * if the nodes matched.
			 */
			int gen_changed;
			s1394_node_t *onode = nnode->old_node;

			gen_changed = (onode && onode->cfgrom &&
			    CONFIG_ROM_GEN(onode->cfgrom) != CONFIG_ROM_GEN(
			    nnode->cfgrom)) ? 1 : 0;

			if (CFGROM_GEN_CHANGED(nnode) == 0 && gen_changed == 0)
				continue;
		}

		if (s1394_match_GUID(hal, nnode) == DDI_FAILURE) {
			ret = DDI_FAILURE;
		}
	}

	return (ret);
}

/*
 * s1394_valid_cfgrom()
 *    Performs crc check on the config rom. Returns B_TRUE if config rom has
 *    good CRC else returns B_FALSE.
 */
/* ARGSUSED */
boolean_t
s1394_valid_cfgrom(s1394_hal_t *hal, s1394_node_t *node)
{
	uint32_t crc_len, crc_value, CRC, CRC_old, quad0;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	ASSERT(node->cfgrom);

	if (s1394_enable_crc_validation == 0) {
		return (B_TRUE);
	}

	quad0 = node->cfgrom[0];
	crc_len = (quad0 >> IEEE1394_CFG_ROM_CRC_LEN_SHIFT) &
	    IEEE1394_CFG_ROM_CRC_LEN_MASK;
	crc_value = quad0 & IEEE1394_CFG_ROM_CRC_VALUE_MASK;

	if (node->cfgrom_valid_size < crc_len + 1) {
		return (B_FALSE);
	}

	CRC = s1394_CRC16(&node->cfgrom[1], crc_len);

	if (CRC != crc_value) {
		CRC_old = s1394_CRC16_old(&node->cfgrom[1], crc_len);
		if (CRC_old == crc_value) {
			return (B_TRUE);
		}

		cmn_err(CE_NOTE,
		    "!Bad CRC in config rom (node's GUID %08x%08x)",
		    node->node_guid_hi, node->node_guid_lo);

		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * s1394_valid_dir()
 *    Performs crc check on a directory.  Returns B_TRUE if dir has good CRC
 *    else returns B_FALSE.
 */
/*ARGSUSED*/
boolean_t
s1394_valid_dir(s1394_hal_t *hal, s1394_node_t *node,
    uint32_t key, uint32_t *dir)
{
	uint32_t dir_len, crc_value, CRC, CRC_old, quad0;

	/*
	 * Ideally, we would like to do crc validations for the entire cfgrom
	 * as well as the individual directories. However, we have seen devices
	 * that have valid directories but busted cfgrom crc and devices that
	 * have bad crcs in directories as well as for the entire cfgrom. This
	 * is sad, but unfortunately, real world!
	 */
	if (s1394_enable_crc_validation == 0) {
		return (B_TRUE);
	}

	quad0 = dir[0];

	dir_len = IEEE1212_DIR_LEN(quad0);
	crc_value = IEEE1212_DIR_CRC(quad0);

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	CRC = s1394_CRC16(&dir[1], dir_len);

	if (CRC != crc_value) {
		CRC_old = s1394_CRC16_old(&dir[1], dir_len);
		if (CRC_old == crc_value) {
			return (B_TRUE);
		}

		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * s1394_become_bus_mgr()
 *    is a callback from a timeout() setup by the main br_thread.  After
 *    a bus reset, depending on the Bus Manager's incumbancy and the state
 *    of its abdicate bit, a timer of a certain length is set.  After this
 *    time expires, the local host may attempt to become the Bus Manager.
 *    This is done by sending a request to the current IRM on the bus.  The
 *    IRM holds the BUS_MANAGER_ID register.  Depending on whether or not
 *    the local host is already the IRM, we will send a request onto the
 *    1394 bus or call into the HAL.
 */
static void
s1394_become_bus_mgr(void *arg)
{
	s1394_hal_t	 *hal;
	s1394_cmd_priv_t *s_priv;
	cmd1394_cmd_t	 *cmd;
	uint64_t	 Bus_Mgr_ID_addr;
	uint32_t	 hal_node_num;
	uint32_t	 old_value;
	uint32_t	 generation;
	uint_t		 curr_bus_mgr;
	uint_t		 bm_node;
	uint_t		 IRM_node;
	int		 err;
	int		 ret;

	hal = (s1394_hal_t *)arg;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	generation   = hal->generation_count;
	IRM_node = hal->IRM_node;

	mutex_enter(&hal->bus_mgr_node_mutex);
	bm_node = hal->bus_mgr_node;
	mutex_exit(&hal->bus_mgr_node_mutex);

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);

	/* Make sure we aren't already the Bus Manager */
	if (bm_node != -1) {
		return;
	}

	/* Send compare-swap to BUS_MANAGER_ID */
	/* register on the Isoch Rsrc Mgr */
	if (IRM_node == hal_node_num) {
		/* Local */
		ret = HAL_CALL(hal).csr_cswap32(hal->halinfo.hal_private,
		    generation, (IEEE1394_SCSR_BUSMGR_ID &
		    IEEE1394_CSR_OFFSET_MASK), S1394_INVALID_NODE_NUM,
		    hal_node_num, &old_value);
		if (ret != DDI_SUCCESS) {
			return;
		}
		curr_bus_mgr = IEEE1394_NODE_NUM(old_value);

		mutex_enter(&hal->bus_mgr_node_mutex);
		if ((curr_bus_mgr == S1394_INVALID_NODE_NUM) ||
		    (curr_bus_mgr == hal_node_num)) {
			hal->bus_mgr_node = hal_node_num;
			hal->incumbent_bus_mgr = B_TRUE;
		} else {
			hal->bus_mgr_node = curr_bus_mgr;
			hal->incumbent_bus_mgr = B_FALSE;
		}
		cv_signal(&hal->bus_mgr_node_cv);
		mutex_exit(&hal->bus_mgr_node_mutex);

	} else {
		/* Remote */
		if (s1394_alloc_cmd(hal, T1394_ALLOC_CMD_NOSLEEP, &cmd) !=
		    DDI_SUCCESS) {
			return;
		}

		cmd->cmd_options	   = (CMD1394_CANCEL_ON_BUS_RESET |
		    CMD1394_OVERRIDE_ADDR);
		cmd->cmd_type		   = CMD1394_ASYNCH_LOCK_32;
		cmd->completion_callback   = s1394_become_bus_mgr_callback;
		Bus_Mgr_ID_addr		   = (IEEE1394_ADDR_BUS_ID_MASK |
		    IEEE1394_SCSR_BUSMGR_ID) |
		    (((uint64_t)hal->IRM_node) << IEEE1394_ADDR_PHY_ID_SHIFT);
		cmd->cmd_addr		   = Bus_Mgr_ID_addr;
		cmd->bus_generation	   = generation;
		cmd->cmd_u.l32.arg_value   = T1394_DATA32(
		    S1394_INVALID_NODE_NUM);
		cmd->cmd_u.l32.data_value  = T1394_DATA32(hal_node_num);
		cmd->cmd_u.l32.num_retries = 0;
		cmd->cmd_u.l32.lock_type   = CMD1394_LOCK_COMPARE_SWAP;

		/* Get the Services Layer private area */
		s_priv = S1394_GET_CMD_PRIV(cmd);

		/* Lock the topology tree */
		mutex_enter(&hal->topology_tree_mutex);

		ret = s1394_setup_asynch_command(hal, NULL, cmd,
		    S1394_CMD_LOCK, &err);

		/* Unlock the topology tree */
		mutex_exit(&hal->topology_tree_mutex);

		/* Command has now been put onto the queue! */
		if (ret != DDI_SUCCESS) {
			/* Need to free the command */
			(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
			return;
		}

		/* Send the command out */
		ret = s1394_xfer_asynch_command(hal, cmd, &err);

		if (ret != DDI_SUCCESS) {
			/* Remove cmd outstanding request Q */
			s1394_remove_q_asynch_cmd(hal, cmd);

			s_priv->cmd_in_use = B_FALSE;

			mutex_enter(&hal->bus_mgr_node_mutex);

			/* Don't know who the bus_mgr is */
			hal->bus_mgr_node = S1394_INVALID_NODE_NUM;
			hal->incumbent_bus_mgr = B_FALSE;

			cv_signal(&hal->bus_mgr_node_cv);
			mutex_exit(&hal->bus_mgr_node_mutex);

			/* Need to free the command */
			(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
		}
	}
}

/*
 * s1394_become_bus_mgr_callback()
 *    is the callback used by s1394_become_bus_mgr() when it is necessary
 *    to send the Bus Manager request to a remote IRM.  After the completion
 *    of the compare-swap request, this routine looks at the "old_value"
 *    in the request to determine whether or not it has become the Bus
 *    Manager for the current generation.  It sets the bus_mgr_node and
 *    incumbent_bus_mgr fields to their appropriate values.
 */
static void
s1394_become_bus_mgr_callback(cmd1394_cmd_t *cmd)
{
	s1394_cmd_priv_t *s_priv;
	s1394_hal_t *hal;
	uint32_t hal_node_num;
	uint32_t temp;
	uint_t curr_bus_mgr;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	hal = (s1394_hal_t *)s_priv->sent_on_hal;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);

	/* Was the command successful? */
	if (cmd->cmd_result == CMD1394_CMDSUCCESS) {
		temp = T1394_DATA32(cmd->cmd_u.l32.old_value);
		curr_bus_mgr = IEEE1394_NODE_NUM(temp);
		mutex_enter(&hal->bus_mgr_node_mutex);
		if ((curr_bus_mgr == S1394_INVALID_NODE_NUM) ||
		    (curr_bus_mgr == hal_node_num)) {

			hal->bus_mgr_node = hal_node_num;
			hal->incumbent_bus_mgr = B_TRUE;

		} else {
			hal->bus_mgr_node = curr_bus_mgr;
			hal->incumbent_bus_mgr = B_FALSE;
		}
		cv_signal(&hal->bus_mgr_node_cv);
		mutex_exit(&hal->bus_mgr_node_mutex);

	} else {
		mutex_enter(&hal->bus_mgr_node_mutex);

		/* Don't know who the bus_mgr is */
		hal->bus_mgr_node = S1394_INVALID_NODE_NUM;
		hal->incumbent_bus_mgr = B_FALSE;

		cv_signal(&hal->bus_mgr_node_cv);
		mutex_exit(&hal->bus_mgr_node_mutex);
	}

	/* Need to free the command */
	(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);
}

/*
 * s1394_bus_mgr_processing()
 *    is called following "phase1" completion of reading Bus_Info_Blocks.
 *    Its purpose is to determine whether the local node is capable of
 *    becoming the Bus Manager (has the IRMC bit set) and if so to call
 *    the s1394_do_bus_mgr_processing() routine.
 *    NOTE: we overload DDI_FAILURE return value to mean jump back to
 *    the start of bus reset processing.
 */
static int
s1394_bus_mgr_processing(s1394_hal_t *hal)
{
	int ret;
	int IRM_node_num;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	IRM_node_num = hal->IRM_node;
	s1394_unlock_tree(hal);

	ret = DDI_SUCCESS;

	/* If we are IRM capable, then do bus_mgr stuff... */
	if (hal->halinfo.bus_capabilities & IEEE1394_BIB_IRMC_MASK) {
		/* If there is an IRM, then do bus_mgr stuff */
		if (IRM_node_num != -1) {
			if (s1394_do_bus_mgr_processing(hal))
				ret = DDI_FAILURE;
		}
	}

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	return (ret);
}

/*
 * s1394_do_bus_mgr_processing()
 *    is used to perform those operations expected of the Bus Manager.
 *    After being called, s1394_do_bus_mgr_processing() looks at the value
 *    in bus_mgr_node and waits if it is -1 (Bus Manager has not been
 *    chosen yet).  Then, if there is more than one node on the 1394 bus,
 *    and we are either the Bus Manager or (if there is no Bus Manager)
 *    the IRM, it optimizes the gap_count and/or sets the cycle master's
 *    root holdoff bit (to ensure that the cycle master is/stays root).
 *
 *    NOTE: we overload DDI_FAILURE return value to mean jump back to
 *    the start of bus reset processing.
 */
static int
s1394_do_bus_mgr_processing(s1394_hal_t *hal)
{
	int	ret;
	int	IRM_flags, hal_bus_mgr_node;
	int	IRM_node_num;
	uint_t	hal_node_num, number_of_nodes;
	int	new_root, new_gap_cnt;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	/* Wait for Bus Manager to be determined */
	/* or a Bus Reset to happen */
	mutex_enter(&hal->bus_mgr_node_mutex);
	if (hal->bus_mgr_node == -1)
		cv_wait(&hal->bus_mgr_node_cv, &hal->bus_mgr_node_mutex);

	/* Check if a BUS RESET has come while we've been waiting */
	mutex_enter(&hal->br_thread_mutex);
	if (hal->br_thread_ev_type & (BR_THR_CFGROM_SCAN | BR_THR_GO_AWAY)) {

		mutex_exit(&hal->br_thread_mutex);
		mutex_exit(&hal->bus_mgr_node_mutex);

		return (1);
	}
	mutex_exit(&hal->br_thread_mutex);

	hal_bus_mgr_node = hal->bus_mgr_node;
	mutex_exit(&hal->bus_mgr_node_mutex);

	if (s1394_lock_tree(hal) != DDI_SUCCESS) {
		return (1);
	}
	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	IRM_node_num = hal->IRM_node;
	number_of_nodes = hal->number_of_nodes;

	ret = 0;

	/* If we are the bus_mgr or if there is no bus_mgr */
	/* the IRM and there is > 1 nodes on the bus */
	if ((number_of_nodes > 1) &&
	    ((hal_bus_mgr_node == (int)hal_node_num) ||
		((hal_bus_mgr_node == S1394_INVALID_NODE_NUM) &&
		    (IRM_node_num == (int)hal_node_num)))) {

		IRM_flags = 0;

		/* Make sure the root node is cycle master capable */
		if (!s1394_cycle_master_capable(hal)) {
			/* Make the local node root */
			new_root = hal_node_num;
			IRM_flags = IRM_flags | ROOT_HOLDOFF;

			/* If setting root, then optimize gap_count */
			new_gap_cnt = hal->optimum_gap_count;
			IRM_flags = IRM_flags | GAP_COUNT;

		} else {
			/* Make sure root's ROOT_HOLDOFF bit is set */
			new_root = (number_of_nodes - 1);
			IRM_flags = IRM_flags | ROOT_HOLDOFF;
		}
		if (hal->gap_count > hal->optimum_gap_count) {
			/* Set the gap_count to optimum */
			new_gap_cnt = hal->optimum_gap_count;
			IRM_flags = IRM_flags | GAP_COUNT;

		}

		s1394_unlock_tree(hal);

		if (IRM_flags) {
			ret = s1394_do_phy_config_pkt(hal, new_root,
			    new_gap_cnt, IRM_flags);
		}
		return (ret);
	}

	s1394_unlock_tree(hal);

	return (ret);
}

/*
 * s1394_bus_mgr_timers_stop()
 *    Cancels bus manager timeouts
 */
/*ARGSUSED*/
static void
s1394_bus_mgr_timers_stop(s1394_hal_t *hal, timeout_id_t *bus_mgr_query_tid,
    timeout_id_t *bus_mgr_tid)
{
	/* Cancel the Bus Mgr timeouts (if necessary) */
	if (*bus_mgr_tid != 0) {
		(void) untimeout(*bus_mgr_tid);
		*bus_mgr_tid = 0;
	}
	if (*bus_mgr_query_tid != 0) {
		(void) untimeout(*bus_mgr_query_tid);
		*bus_mgr_query_tid = 0;
	}
}

/*
 * s1394_bus_mgr_timers_start()
 *    Starts bus manager timeouts if the hal is IRM capable.
 */
static void
s1394_bus_mgr_timers_start(s1394_hal_t *hal, timeout_id_t *bus_mgr_query_tid,
    timeout_id_t *bus_mgr_tid)
{
	boolean_t incumbant;
	uint_t	  hal_node_num;
	int	  IRM_node_num;

	mutex_enter(&hal->topology_tree_mutex);

	IRM_node_num = hal->IRM_node;
	hal_node_num = hal->node_id;

	mutex_enter(&hal->bus_mgr_node_mutex);
	incumbant = hal->incumbent_bus_mgr;
	mutex_exit(&hal->bus_mgr_node_mutex);

	/* If we are IRM capable, then do bus_mgr stuff... */
	if (hal->halinfo.bus_capabilities & IEEE1394_BIB_IRMC_MASK) {
		/*
		 * If we are the IRM, then wait 625ms
		 * before checking BUS_MANAGER_ID register
		 */
		if (IRM_node_num == IEEE1394_NODE_NUM(hal_node_num)) {

			mutex_exit(&hal->topology_tree_mutex);

			/* Wait 625ms, then check bus manager */
			*bus_mgr_query_tid = timeout(s1394_become_bus_mgr,
			    hal, drv_usectohz(IEEE1394_BM_IRM_TIMEOUT));

			mutex_enter(&hal->topology_tree_mutex);
		}

		/* If there is an IRM on the bus */
		if (IRM_node_num != -1) {
			if ((incumbant == B_TRUE) &&
			    (hal->abdicate_bus_mgr_bit == 0)) {
				mutex_exit(&hal->topology_tree_mutex);

				/* Try to become bus manager */
				s1394_become_bus_mgr(hal);

				mutex_enter(&hal->topology_tree_mutex);
			} else {
				hal->abdicate_bus_mgr_bit = 0;

				mutex_exit(&hal->topology_tree_mutex);

				/* Wait 125ms, then try to become bus manager */
				*bus_mgr_tid = timeout(s1394_become_bus_mgr,
				    hal, drv_usectohz(
					IEEE1394_BM_INCUMBENT_TIMEOUT));

				mutex_enter(&hal->topology_tree_mutex);
			}
		} else {
			mutex_enter(&hal->bus_mgr_node_mutex);
			hal->incumbent_bus_mgr = B_FALSE;
			mutex_exit(&hal->bus_mgr_node_mutex);
		}
	}

	mutex_exit(&hal->topology_tree_mutex);
}

/*
 * s1394_get_maxpayload()
 *    is used to determine a device's maximum payload size.  That is to
 *    say, the largest packet that can be transmitted or received by the
 *    the target device given the current topological (speed) constraints
 *    and the constraints specified in the local host's and remote device's
 *    Config ROM (max_rec).  Caller must hold the topology_tree_mutex and
 *    the target_list_rwlock as an RW_READER (at least).
 */
/*ARGSUSED*/
void
s1394_get_maxpayload(s1394_target_t *target, uint_t *dev_max_payload,
    uint_t *current_max_payload)
{
	s1394_hal_t *hal;
	uint32_t bus_capabilities;
	uint32_t from_node;
	uint32_t to_node;
	uint_t local_max_rec;
	uint_t local_max_blk;
	uint_t max_rec;
	uint_t max_blk;
	uint_t curr_speed;
	uint_t speed_max_blk;
	uint_t temp;

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	/* Make sure we're holding the topology_tree_mutex */
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	/* Set dev_max_payload to local (HAL's) size */
	bus_capabilities = target->on_hal->halinfo.bus_capabilities;
	local_max_rec = (bus_capabilities & IEEE1394_BIB_MAXREC_MASK) >>
	    IEEE1394_BIB_MAXREC_SHIFT;
	if ((local_max_rec > 0) && (local_max_rec < 14)) {
		local_max_blk = 1 << (local_max_rec + 1);
	} else {
		/* These are either unspecified or reserved */
		local_max_blk = 4;
	}

	/* Is this target on a node? */
	if ((target->target_state & S1394_TARG_GONE) == 0 &&
	    (target->on_node != NULL)) {
		ASSERT(target->on_node->cfgrom != NULL);

		bus_capabilities =
		    target->on_node->cfgrom[IEEE1212_NODE_CAP_QUAD];
		max_rec = (bus_capabilities & IEEE1394_BIB_MAXREC_MASK) >>
		    IEEE1394_BIB_MAXREC_SHIFT;

		if ((max_rec > 0) && (max_rec < 14)) {
			max_blk = 1 << (max_rec + 1);
		} else {
			/* These are either unspecified or reserved */
			max_blk = 4;
		}
		(*dev_max_payload) = max_blk;

		from_node = IEEE1394_NODE_NUM(target->on_hal->node_id);
		to_node = (target->on_node->node_num);

		/* Speed is to be filled in from speed map */
		curr_speed = (uint_t)s1394_speed_map_get(target->on_hal,
		    from_node, to_node);
		speed_max_blk = 512 << curr_speed;
		temp = (local_max_blk < max_blk) ? local_max_blk : max_blk;
		(*current_max_payload) = (temp < speed_max_blk) ? temp :
		    speed_max_blk;
	} else {
		/* Set dev_max_payload to local (HAL's) size */
		(*dev_max_payload) = local_max_blk;
		(*current_max_payload) = local_max_blk;
	}
}

/*
 * s1394_cycle_master_capable()
 *    is used to determine whether or not the current root node on the
 *    1394 bus has its CMC-bit set in it Config ROM.  If not, then it
 *    is not capable of being cycle master and a new root node must be
 *    selected.
 */
static int
s1394_cycle_master_capable(s1394_hal_t *hal)
{
	s1394_node_t	*root;
	int		cycle_master_capable;
	uint_t		hal_node_num;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);

	/* Get a pointer to the root node */
	root = s1394_topology_tree_get_root_node(hal);

	/* Ignore, if we are already root */
	if (root == &hal->topology_tree[hal_node_num]) {
		return (1);
	}

	/*
	 * We want to pick a new root if link is off or we don't have
	 * valid config rom
	 */
	if (LINK_ACTIVE(root) == B_FALSE || root->cfgrom == NULL ||
	    CFGROM_BIB_READ(root) == 0) {

		return (0);
	}

	/* Check the Cycle Master bit in the Bus Info Block */
	cycle_master_capable = root->cfgrom[IEEE1212_NODE_CAP_QUAD] &
	    IEEE1394_BIB_CMC_MASK;

	if (cycle_master_capable) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * s1394_do_phy_config_pkt()
 *    is called by s1394_do_bus_mgr_processing() to setup and send out
 *    a PHY configuration packet onto the 1394 bus.  Depending on the
 *    values in IRM_flags, the gap_count and root_holdoff bits on the
 *    bus will be affected by this packet.
 *
 *    NOTE: we overload DDI_FAILURE return value to mean jump back to
 *    the start of bus reset processing.
 */
static int
s1394_do_phy_config_pkt(s1394_hal_t *hal, int new_root, int new_gap_cnt,
    uint32_t IRM_flags)
{
	cmd1394_cmd_t	 *cmd;
	s1394_cmd_priv_t *s_priv;
	h1394_cmd_priv_t *h_priv;
	uint32_t	 pkt_data = 0;
	uint32_t	 gap_cnt = 0;
	uint32_t	 root = 0;
	int		 ret, result;
	uint_t		 flags = 0;

	/* Gap count needs to be optimized */
	if (IRM_flags & GAP_COUNT) {

		pkt_data = pkt_data | IEEE1394_PHY_CONFIG_T_BIT_MASK;
		gap_cnt = ((uint32_t)new_gap_cnt) <<
		    IEEE1394_PHY_CONFIG_GAP_CNT_SHIFT;
		gap_cnt = gap_cnt & IEEE1394_PHY_CONFIG_GAP_CNT_MASK;
		pkt_data = pkt_data | gap_cnt;

		(void) HAL_CALL(hal).set_gap_count(hal->halinfo.hal_private,
		    (uint_t)new_gap_cnt);
	}

	/* Root node needs to be changed */
	if (IRM_flags & ROOT_HOLDOFF) {

		pkt_data = pkt_data | IEEE1394_PHY_CONFIG_R_BIT_MASK;
		root = ((uint32_t)new_root) <<
		    IEEE1394_PHY_CONFIG_ROOT_HOLD_SHIFT;
		root = root & IEEE1394_PHY_CONFIG_ROOT_HOLD_MASK;
		pkt_data = pkt_data | root;

		(void) HAL_CALL(hal).set_root_holdoff_bit(
		    hal->halinfo.hal_private);
	}


	if (IRM_flags) {
		if (s1394_alloc_cmd(hal, flags, &cmd) != DDI_SUCCESS) {
			return (0);
		}

		if (s1394_lock_tree(hal) != DDI_SUCCESS) {
			/* lock tree failure indicates a bus gen change */
			(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);
			return (1);
		}

		/* Setup the callback routine */
		cmd->completion_callback  = s1394_phy_config_callback;
		cmd->cmd_callback_arg	  = (void *)(uintptr_t)IRM_flags;
		cmd->bus_generation	  = hal->generation_count;
		cmd->cmd_options	  = CMD1394_OVERRIDE_ADDR;
		cmd->cmd_type		  = CMD1394_ASYNCH_WR_QUAD;
		cmd->cmd_u.q.quadlet_data = pkt_data;

		/* Get the Services Layer private area */
		s_priv = S1394_GET_CMD_PRIV(cmd);

		/* Get a pointer to the HAL private struct */
		h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;

		s_priv->sent_by_target	= (s1394_target_t *)NULL;
		s_priv->sent_on_hal	= (s1394_hal_t *)hal;

		h_priv->bus_generation	= cmd->bus_generation;

		/* Speed must be IEEE1394_S100 on PHY config packets */
		s_priv->hal_cmd_private.speed = IEEE1394_S100;

		/* Mark command as being used */
		s_priv->cmd_in_use = B_TRUE;

		s1394_unlock_tree(hal);

		/* Put command on the HAL's outstanding request Q */
		s1394_insert_q_asynch_cmd(hal, cmd);

		ret = HAL_CALL(hal).send_phy_configuration_packet(
		    hal->halinfo.hal_private, (cmd1394_cmd_t *)cmd,
		    (h1394_cmd_priv_t *)&s_priv->hal_cmd_private, &result);

		if (ret != DDI_SUCCESS) {
			(void) s1394_free_cmd(hal, (cmd1394_cmd_t **)&cmd);

			return (0);

		} else {
			/*
			 * There will be a bus reset only if GAP_COUNT changed
			 */
			if (IRM_flags & GAP_COUNT) {
				return (1);
			}
		}
	}

	return (0);
}

/*
 * s1394_phy_config_callback()
 *    is the callback called after the PHY configuration packet has been
 *    sent out onto the 1394 bus.  Depending on the values in IRM_flags,
 *    (specifically if the gap_count has been changed) this routine may
 *    initiate a bus reset.
 */
static void
s1394_phy_config_callback(cmd1394_cmd_t *cmd)
{
	s1394_cmd_priv_t *s_priv;
	s1394_hal_t *hal;
	uint32_t IRM_flags;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	hal = (s1394_hal_t *)s_priv->sent_on_hal;

	IRM_flags = (uint32_t)(uintptr_t)cmd->cmd_callback_arg;

	if (cmd->cmd_result != CMD1394_CMDSUCCESS) {
		(void) s1394_free_cmd(hal, &cmd);
	} else {
		(void) s1394_free_cmd(hal, &cmd);

		/* Only need a bus reset if we changed GAP_COUNT */
		if (IRM_flags & GAP_COUNT) {
			s1394_initiate_hal_reset(hal, NON_CRITICAL);
		}
	}
}

/*
 * s1394_lock_tree()
 *    Attempts to lock the topology tree. Returns DDI_FAILURE if generations
 *    changed or if the services layer signals the bus reset thread to go
 *    away. Otherwise, returns DDI_SUCCESS.
 */
int
s1394_lock_tree(s1394_hal_t *hal)
{
	ASSERT(MUTEX_NOT_HELD(&hal->br_thread_mutex));
	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	mutex_enter(&hal->br_thread_mutex);
	ndi_devi_enter(hal->halinfo.dip);
	mutex_enter(&hal->topology_tree_mutex);

	if ((hal->br_thread_ev_type & BR_THR_GO_AWAY) != 0) {
		mutex_exit(&hal->br_thread_mutex);
		mutex_exit(&hal->topology_tree_mutex);
		ndi_devi_exit(hal->halinfo.dip);
		return (DDI_FAILURE);
	} else if (hal->br_cfgrom_read_gen != hal->generation_count) {
		mutex_exit(&hal->br_thread_mutex);
		mutex_exit(&hal->topology_tree_mutex);
		ndi_devi_exit(hal->halinfo.dip);
		return (DDI_FAILURE);
	}

	mutex_exit(&hal->br_thread_mutex);

	return (DDI_SUCCESS);
}

/*
 * s1394_unlock_tree()
 *    Unlocks the topology tree
 */
void
s1394_unlock_tree(s1394_hal_t *hal)
{
	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));
	mutex_exit(&hal->topology_tree_mutex);
	ndi_devi_exit(hal->halinfo.dip);
}

/*
 * s1394_calc_next_quad()
 *    figures out the next quadlet to read. This maintains a stack of
 *    directories in the node. When the first quad of a directory (the
 *    first directory would be the root directory) is read, it is pushed on
 *    the this stack. When the directory is all read, it scans the directory
 *    looking for indirect entries. If any indirect directory entry is found,
 *    it is pushed on stack and that directory is read. If we are done dealing
 *    with all entries in the current dir, the directory is popped off the
 *    stack. If the stack is empty, we are back at the root directory level
 *    and essentially read the entire directory hierarchy.
 *    Returns 0 is more quads to read, else returns non-zero.
 */
static int
s1394_calc_next_quad(s1394_hal_t *hal, s1394_node_t *node, uint32_t quadlet,
    uint32_t *nextquadp)
{
	uint32_t data, type, key, value, *ptr;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	if (((quadlet + 1) >= node->cfgrom_size) ||
	    (CFGROM_SIZE_IS_CRCSIZE(node) == B_TRUE && (quadlet + 1) >=
		node->cfgrom_valid_size)) {
		return (1);
	}

	if (s1394_turn_off_dir_stack != 0 || CFGROM_DIR_STACK_OFF(node) ==
	    B_TRUE) {
		quadlet++;
		*nextquadp = quadlet;
		return (0);
	}

	data = node->cfgrom[quadlet];

	if (quadlet == IEEE1212_ROOT_DIR_QUAD) {
		node->dir_stack_top = -1;
		node->expected_dir_quad = quadlet;
		node->expected_type = IEEE1212_IMMEDIATE_TYPE;
	}

	CFGROM_TYPE_KEY_VALUE(data, type, key, value);

	/*
	 * check to make sure we are looking at a dir. If the config rom
	 * is broken, then revert to normal scanning of the config rom
	 */
	if (node->expected_dir_quad == quadlet) {
		if (type != 0 || key != 0) {
			SET_CFGROM_DIR_STACK_OFF(node);
			quadlet = IEEE1212_ROOT_DIR_QUAD;
		} else {
			node->cur_dir_start = quadlet;
			node->cur_dir_size = IEEE1212_DIR_LEN(data);
			node->expected_dir_quad = 0;
			/* get the next quad */
			quadlet++;
		}
	} else {
		/*
		 * If we read all quads in cur dir and the cur dir is not
		 * a leaf, scan for offsets (if the directory's CRC checks
		 * out OK). If we have a directory or a leaf, we save the
		 * current location on the stack and start reading that
		 * directory. So, we will end up with a depth first read of
		 * the entire config rom. If we are done with the current
		 * directory, pop it off the stack and continue the scanning
		 * as appropriate.
		 */
		if (quadlet == node->cur_dir_start + node->cur_dir_size) {

			int i, top;
			boolean_t done_with_cur_dir = B_FALSE;

			if (node->expected_type == IEEE1212_LEAF_TYPE) {
				node->expected_type = IEEE1212_IMMEDIATE_TYPE;
				done_with_cur_dir = B_TRUE;
				goto donewithcurdir;
			}

			ptr = &node->cfgrom[node->cur_dir_start];
			CFGROM_TYPE_KEY_VALUE(*ptr, type, key, value);

			/*
			 * If CRC for this directory is invalid, turn off
			 * dir stack and start re-reading from root dir.
			 * This wastes the work done thus far, but CRC
			 * errors in directories should be rather rare.
			 * if s1394_crcsz_is_cfgsz is set, then set
			 * cfgrom_valid_size to the len specfied as crc len
			 * in quadlet 0.
			 */
			if (s1394_valid_dir(hal, node, key, ptr) == B_FALSE) {
				SET_CFGROM_DIR_STACK_OFF(node);
				if (s1394_crcsz_is_cfgsz != 0) {
					SET_CFGROM_SIZE_IS_CRCSIZE(node);
					node->cfgrom_valid_size =
					    ((node->cfgrom[0] >>
					    IEEE1394_CFG_ROM_CRC_LEN_SHIFT) &
					    IEEE1394_CFG_ROM_CRC_LEN_MASK);
				}
				*nextquadp = IEEE1212_ROOT_DIR_QUAD;
				return (0);
			}
			i = node->cur_dir_start + 1;
		rescan:
			for (done_with_cur_dir = B_FALSE; i <=
			    node->cur_dir_start + node->cur_dir_size; i++) {
				data = node->cfgrom[i];
				CFGROM_TYPE_KEY_VALUE(data, type, key, value);
				/* read leaf type and directory types only */
				if (type == IEEE1212_LEAF_TYPE || type ==
				    IEEE1212_DIRECTORY_TYPE) {

					/*
					 * push current dir on stack; if the
					 * stack is overflowing, ie, too many
					 * directory level nestings, turn off
					 * dir stack and fall back to serial
					 * scanning, starting at root dir. This
					 * wastes all the work we have done
					 * thus far, but more than 16 levels
					 * of directories is rather odd...
					 */
					top = ++node->dir_stack_top;
					if (top == S1394_DIR_STACK_SIZE) {
						SET_CFGROM_DIR_STACK_OFF(node);
						*nextquadp =
						    IEEE1212_ROOT_DIR_QUAD;
						return (0);
					}

					node->dir_stack[top].dir_start =
					    node->cur_dir_start;
					node->dir_stack[top].dir_size =
					    node->cur_dir_size;
					node->dir_stack[top].dir_next_quad =
					    i + 1;
					/* and set the next quadlet to read */
					quadlet = i + value;
					node->expected_dir_quad = quadlet;
					node->expected_type = type;
					break;
				}
			}

		donewithcurdir:

			if ((i > node->cur_dir_start + node->cur_dir_size) ||
				done_with_cur_dir == B_TRUE) {

				/*
				 * all done with cur dir; pop it off the stack
				 */
				if (node->dir_stack_top >= 0) {
					top = node->dir_stack_top--;
					node->cur_dir_start =
					    node->dir_stack[top].dir_start;
					node->cur_dir_size =
					    node->dir_stack[top].dir_size;
					i = node->dir_stack[top].dir_next_quad;
					goto rescan;
				} else {
					/*
					 * if empty stack, we are at the top
					 * level; declare done.
					 */
					return (1);
				}
			}
		} else {
			/* get the next quadlet */
			quadlet++;
		}
	}
	*nextquadp = quadlet;

	return (0);
}
