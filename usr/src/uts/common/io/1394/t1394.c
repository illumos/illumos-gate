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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * t1394.c
 *    1394 Target Driver Interface
 *    This file contains all of the 1394 Software Framework routines called
 *    by target drivers
 */

#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/tnf_probe.h>

#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>

static int s1394_allow_detach = 0;

/*
 * Function:    t1394_attach()
 * Input(s):    dip			The dip given to the target driver
 *					    in it's attach() routine
 *		version			The version of the target driver -
 *					    T1394_VERSION_V1
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	attachinfo		Used to pass info back to target,
 *					    including bus generation, local
 *					    node ID, dma attribute, etc.
 *		t1394_hdl		The target "handle" to be used for
 *					    all subsequent calls into the
 *					    1394 Software Framework
 *
 * Description:	t1394_attach() registers the target (based on its dip) with
 *		the 1394 Software Framework.  It returns the bus_generation,
 *		local_nodeID, iblock_cookie and other useful information to
 *		the target, as well as a handle (t1394_hdl) that will be used
 *		in all subsequent calls into this framework.
 */
/* ARGSUSED */
int
t1394_attach(dev_info_t *dip, int version, uint_t flags,
    t1394_attachinfo_t *attachinfo, t1394_handle_t *t1394_hdl)
{
	s1394_hal_t	*hal;
	s1394_target_t	*target;
	uint_t		dev;
	uint_t		curr;
	uint_t		unit_dir;
	int		hp_node = 0;

	ASSERT(t1394_hdl != NULL);
	ASSERT(attachinfo != NULL);

	TNF_PROBE_0_DEBUG(t1394_attach_enter, S1394_TNF_SL_HOTPLUG_STACK, "");

	*t1394_hdl = NULL;

	if (version != T1394_VERSION_V1) {
		TNF_PROBE_1(t1394_attach_error, S1394_TNF_SL_HOTPLUG_ERROR, "",
		    tnf_string, msg, "Invalid version");
		TNF_PROBE_0_DEBUG(t1394_attach_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (DDI_FAILURE);
	}

	hal = s1394_dip_to_hal(ddi_get_parent(dip));
	if (hal == NULL) {
		TNF_PROBE_1(t1394_attach_error, S1394_TNF_SL_HOTPLUG_ERROR, "",
		    tnf_string, msg, "No parent dip found for target");
		TNF_PROBE_0_DEBUG(t1394_attach_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (DDI_FAILURE);
	}

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	hp_node = ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "hp-node");

	/* Allocate space for s1394_target_t */
	target = kmem_zalloc(sizeof (s1394_target_t), KM_SLEEP);

	mutex_enter(&hal->topology_tree_mutex);

	target->target_version = version;

	/* Copy in the params */
	target->target_dip = dip;
	target->on_hal	   = hal;

	/* Place the target on the appropriate node */
	target->on_node	= NULL;

	rw_enter(&target->on_hal->target_list_rwlock, RW_WRITER);
	if (hp_node != 0) {
		s1394_add_target_to_node(target);
		/*
		 * on_node can be NULL if the node got unplugged
		 * while the target driver is in its attach routine.
		 */
		if (target->on_node == NULL) {
			s1394_remove_target_from_node(target);
			rw_exit(&target->on_hal->target_list_rwlock);
			mutex_exit(&hal->topology_tree_mutex);
			kmem_free(target, sizeof (s1394_target_t));
			TNF_PROBE_1(t1394_attach_error,
			    S1394_TNF_SL_HOTPLUG_ERROR, "", tnf_string, msg,
			    "on_node == NULL");
			TNF_PROBE_0_DEBUG(t1394_attach_exit,
			    S1394_TNF_SL_HOTPLUG_STACK, "");
			return (DDI_FAILURE);
		}

		target->target_state = S1394_TARG_HP_NODE;
		if (S1394_NODE_BUS_PWR_CONSUMER(target->on_node) == B_TRUE)
			target->target_state |= S1394_TARG_BUS_PWR_CONSUMER;
	}

	/* Return the current generation */
	attachinfo->localinfo.bus_generation = target->on_hal->generation_count;

	/* Fill in hal node id */
	attachinfo->localinfo.local_nodeID = target->on_hal->node_id;

	/* Give the target driver the iblock_cookie */
	attachinfo->iblock_cookie = target->on_hal->halinfo.hw_interrupt;

	/* Give the target driver the attributes */
	attachinfo->acc_attr	= target->on_hal->halinfo.acc_attr;
	attachinfo->dma_attr	= target->on_hal->halinfo.dma_attr;

	unit_dir = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "unit-dir-offset", 0);
	target->unit_dir = unit_dir;

	/* By default, disable all physical AR requests */
	target->physical_arreq_enabled = 0;


	/* Get dev_max_payload & current_max_payload */
	s1394_get_maxpayload(target, &dev, &curr);
	target->dev_max_payload		= dev;
	target->current_max_payload	= curr;

	/* Add into linked list */
	if ((target->on_hal->target_head == NULL) &&
	    (target->on_hal->target_tail == NULL)) {
		target->on_hal->target_head = target;
		target->on_hal->target_tail = target;
	} else {
		target->on_hal->target_tail->target_next = target;
		target->target_prev = target->on_hal->target_tail;
		target->on_hal->target_tail = target;
	}
	rw_exit(&target->on_hal->target_list_rwlock);

	/* Fill in services layer private info */
	*t1394_hdl = (t1394_handle_t)target;

	mutex_exit(&hal->topology_tree_mutex);

	TNF_PROBE_0_DEBUG(t1394_attach_exit, S1394_TNF_SL_HOTPLUG_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_detach()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		Target successfully detached
 *		DDI_FAILURE		Target failed to detach
 *
 * Description:	t1394_detach() unregisters the target from the 1394 Software
 *		Framework.  t1394_detach() can fail if the target has any
 *		allocated commands that haven't been freed.
 */
/* ARGSUSED */
int
t1394_detach(t1394_handle_t *t1394_hdl, uint_t flags)
{
	s1394_target_t	*target;
	uint_t		num_cmds;

	TNF_PROBE_0_DEBUG(t1394_detach_enter, S1394_TNF_SL_HOTPLUG_STACK, "");

	ASSERT(t1394_hdl != NULL);

	target = (s1394_target_t *)(*t1394_hdl);

	ASSERT(target->on_hal);

	mutex_enter(&target->on_hal->topology_tree_mutex);
	rw_enter(&target->on_hal->target_list_rwlock, RW_WRITER);

	/* How many cmds has this target allocated? */
	num_cmds = target->target_num_cmds;

	if (num_cmds != 0) {
		rw_exit(&target->on_hal->target_list_rwlock);
		mutex_exit(&target->on_hal->topology_tree_mutex);
		TNF_PROBE_1(t1394_detach_error, S1394_TNF_SL_HOTPLUG_ERROR, "",
		    tnf_string, msg, "Must free all commands before detach()");
		TNF_PROBE_0_DEBUG(t1394_detach_exit,
		    S1394_TNF_SL_HOTPLUG_STACK, "");
		return (DDI_FAILURE);
	}

	/*
	 * Remove from linked lists. Topology tree is already locked
	 * so that the node won't go away while we are looking at it.
	 */
	if ((target->on_hal->target_head == target) &&
	    (target->on_hal->target_tail == target)) {
		target->on_hal->target_head = NULL;
		target->on_hal->target_tail = NULL;
	} else {
		if (target->target_prev)
			target->target_prev->target_next = target->target_next;
		if (target->target_next)
			target->target_next->target_prev = target->target_prev;
		if (target->on_hal->target_head == target)
			target->on_hal->target_head = target->target_next;
		if (target->on_hal->target_tail == target)
			target->on_hal->target_tail = target->target_prev;
	}

	s1394_remove_target_from_node(target);
	rw_exit(&target->on_hal->target_list_rwlock);

	mutex_exit(&target->on_hal->topology_tree_mutex);

	/* Free memory */
	kmem_free(target, sizeof (s1394_target_t));

	*t1394_hdl = NULL;

	TNF_PROBE_0_DEBUG(t1394_detach_exit, S1394_TNF_SL_HOTPLUG_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_alloc_cmd()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		flags			The flags parameter is described below
 *
 * Output(s):	cmdp			Pointer to the newly allocated command
 *
 * Description:	t1394_alloc_cmd() allocates a command for use with the
 *		t1394_read(), t1394_write(), or t1394_lock() interfaces
 *		of the 1394 Software Framework.  By default, t1394_alloc_cmd()
 *		may sleep while allocating memory for the command structure.
 *		If this is undesirable, the target may set the
 *		T1394_ALLOC_CMD_NOSLEEP bit in the flags parameter.  Also,
 *		this call may fail because a target driver has already
 *		allocated MAX_NUMBER_ALLOC_CMDS commands.
 */
int
t1394_alloc_cmd(t1394_handle_t t1394_hdl, uint_t flags, cmd1394_cmd_t **cmdp)
{
	s1394_hal_t	 *hal;
	s1394_target_t	 *target;
	s1394_cmd_priv_t *s_priv;
	uint_t		 num_cmds;

	TNF_PROBE_0_DEBUG(t1394_alloc_cmd_enter, S1394_TNF_SL_ATREQ_STACK, "");

	ASSERT(t1394_hdl != NULL);

	target = (s1394_target_t *)t1394_hdl;

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	rw_enter(&hal->target_list_rwlock, RW_WRITER);

	/* How many cmds has this target allocated? */
	num_cmds = target->target_num_cmds;

	if (num_cmds >= MAX_NUMBER_ALLOC_CMDS) {
		rw_exit(&hal->target_list_rwlock);
		TNF_PROBE_1(t1394_alloc_cmd_error, S1394_TNF_SL_ATREQ_ERROR,
		    "", tnf_string, msg, "Attempted to alloc > "
		    "MAX_NUMBER_ALLOC_CMDS");
		TNF_PROBE_0_DEBUG(t1394_alloc_cmd_exit,
		    S1394_TNF_SL_ATREQ_STACK, "");
		/* kstats - cmd alloc failures */
		hal->hal_kstats->cmd_alloc_fail++;
		return (DDI_FAILURE);
	}

	/* Increment the number of cmds this target has allocated? */
	target->target_num_cmds = num_cmds + 1;

	if (s1394_alloc_cmd(hal, flags, cmdp) != DDI_SUCCESS) {
		target->target_num_cmds = num_cmds;	/* Undo increment */
		rw_exit(&hal->target_list_rwlock);
		TNF_PROBE_1(t1394_alloc_cmd_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Failed to allocate command structure");
		TNF_PROBE_0_DEBUG(t1394_alloc_cmd_exit,
		    S1394_TNF_SL_ATREQ_STACK, "");
		/* kstats - cmd alloc failures */
		hal->hal_kstats->cmd_alloc_fail++;
		return (DDI_FAILURE);
	}

	rw_exit(&hal->target_list_rwlock);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(*cmdp);

	/* Initialize the command's blocking mutex */
	mutex_init(&s_priv->blocking_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Initialize the command's blocking condition variable */
	cv_init(&s_priv->blocking_cv, NULL, CV_DRIVER, NULL);

	TNF_PROBE_0_DEBUG(t1394_alloc_cmd_exit, S1394_TNF_SL_ATREQ_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_free_cmd()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		flags			The flags parameter is unused (for now)
 *		cmdp			Pointer to the command to be freed
 *
 * Output(s):	DDI_SUCCESS		Target successfully freed command
 *		DDI_FAILURE		Target failed to free command
 *
 * Description:	t1394_free_cmd() attempts to free a command that has previously
 *		been allocated by the target driver.  It is possible for
 *		t1394_free_cmd() to fail because the command is currently
 *		in-use by the 1394 Software Framework.
 */
/* ARGSUSED */
int
t1394_free_cmd(t1394_handle_t t1394_hdl, uint_t flags, cmd1394_cmd_t **cmdp)
{
	s1394_hal_t	 *hal;
	s1394_target_t	 *target;
	s1394_cmd_priv_t *s_priv;
	uint_t		 num_cmds;

	TNF_PROBE_0_DEBUG(t1394_free_cmd_enter, S1394_TNF_SL_ATREQ_STACK, "");

	ASSERT(t1394_hdl != NULL);

	target = (s1394_target_t *)t1394_hdl;

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	rw_enter(&hal->target_list_rwlock, RW_WRITER);

	/* How many cmds has this target allocated? */
	num_cmds = target->target_num_cmds;

	if (num_cmds == 0) {
		rw_exit(&hal->target_list_rwlock);
		TNF_PROBE_2(t1394_free_cmd_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "No commands left to be freed "
		    "(num_cmds <= 0)", tnf_uint, num_cmds, num_cmds);
		TNF_PROBE_0_DEBUG(t1394_free_cmd_exit,
		    S1394_TNF_SL_ATREQ_STACK, "");
		ASSERT(num_cmds != 0);
		return (DDI_FAILURE);
	}

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(*cmdp);

	/* Check that command isn't in use */
	if (s_priv->cmd_in_use == B_TRUE) {
		rw_exit(&hal->target_list_rwlock);
		TNF_PROBE_1(t1394_free_cmd_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Attempted to free an in-use command");
		TNF_PROBE_0_DEBUG(t1394_free_cmd_exit,
		    S1394_TNF_SL_ATREQ_STACK, "");
		ASSERT(s_priv->cmd_in_use == B_FALSE);
		return (DDI_FAILURE);
	}

	/* Decrement the number of cmds this target has allocated */
	target->target_num_cmds--;

	rw_exit(&hal->target_list_rwlock);

	/* Destroy the command's blocking condition variable */
	cv_destroy(&s_priv->blocking_cv);

	/* Destroy the command's blocking mutex */
	mutex_destroy(&s_priv->blocking_mutex);

	kmem_cache_free(hal->hal_kmem_cachep, *cmdp);

	/* Command pointer is set to NULL before returning */
	*cmdp = NULL;

	/* kstats - number of cmd frees */
	hal->hal_kstats->cmd_free++;

	TNF_PROBE_0_DEBUG(t1394_free_cmd_exit, S1394_TNF_SL_ATREQ_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_read()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		cmd			Pointer to the command to send
 *
 * Output(s):	DDI_SUCCESS		Target successful sent the command
 *		DDI_FAILURE		Target failed to send command
 *
 * Description:	t1394_read() attempts to send an asynchronous read request
 *		onto the 1394 bus.
 */
int
t1394_read(t1394_handle_t t1394_hdl, cmd1394_cmd_t *cmd)
{
	s1394_hal_t	  *to_hal;
	s1394_target_t	  *target;
	s1394_cmd_priv_t  *s_priv;
	s1394_hal_state_t state;
	int		  ret;
	int		  err;

	TNF_PROBE_0_DEBUG(t1394_read_enter, S1394_TNF_SL_ATREQ_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(cmd != NULL);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Is this command currently in use? */
	if (s_priv->cmd_in_use == B_TRUE) {
		TNF_PROBE_1(t1394_read_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Attempted to resend an in-use command");
		TNF_PROBE_0_DEBUG(t1394_read_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		ASSERT(s_priv->cmd_in_use == B_FALSE);
		return (DDI_FAILURE);
	}

	target = (s1394_target_t *)t1394_hdl;

	/* Set-up the destination of the command */
	to_hal = target->on_hal;

	/* No status (default) */
	cmd->cmd_result = CMD1394_NOSTATUS;

	/* Check for proper command type */
	if ((cmd->cmd_type != CMD1394_ASYNCH_RD_QUAD) &&
	    (cmd->cmd_type != CMD1394_ASYNCH_RD_BLOCK)) {
		cmd->cmd_result = CMD1394_EINVALID_COMMAND;
		TNF_PROBE_1(t1394_read_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Invalid command type specified");
		TNF_PROBE_0_DEBUG(t1394_read_exit,
		    S1394_TNF_SL_ATREQ_STACK, "");
		return (DDI_FAILURE);
	}

	/* Is this a blocking command on interrupt stack? */
	if ((cmd->cmd_options & CMD1394_BLOCKING) &&
	    (servicing_interrupt())) {
		cmd->cmd_result = CMD1394_EINVALID_CONTEXT;
		TNF_PROBE_1(t1394_read_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Tried to use CMD1394_BLOCKING in "
		    "intr context");
		TNF_PROBE_0_DEBUG(t1394_read_exit,
		    S1394_TNF_SL_ATREQ_STACK, "");
		return (DDI_FAILURE);
	}

	mutex_enter(&to_hal->topology_tree_mutex);
	state = to_hal->hal_state;
	if (state != S1394_HAL_NORMAL) {
		ret = s1394_HAL_asynch_error(to_hal, cmd, state);
		if (ret != CMD1394_CMDSUCCESS) {
			cmd->cmd_result = ret;
			mutex_exit(&to_hal->topology_tree_mutex);
			return (DDI_FAILURE);
		}
	}

	ret = s1394_setup_asynch_command(to_hal, target, cmd,
	    S1394_CMD_READ, &err);

	/* Command has now been put onto the queue! */
	if (ret != DDI_SUCCESS) {
		/* Copy error code into result */
		cmd->cmd_result = err;
		mutex_exit(&to_hal->topology_tree_mutex);
		TNF_PROBE_1(t1394_read_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Failed in s1394_setup_asynch_command()");
		TNF_PROBE_0_DEBUG(t1394_read_exit,
		    S1394_TNF_SL_ATREQ_STACK, "");
		return (DDI_FAILURE);
	}

	/*
	 * If this command was sent during a bus reset,
	 * then put it onto the pending Q.
	 */
	if (state == S1394_HAL_RESET) {
		/* Remove cmd from outstanding request Q */
		s1394_remove_q_asynch_cmd(to_hal, cmd);
		/* Are we on the bus reset event stack? */
		if (s1394_on_br_thread(to_hal) == B_TRUE) {
			/* Blocking commands are not allowed */
			if (cmd->cmd_options & CMD1394_BLOCKING) {
				mutex_exit(&to_hal->topology_tree_mutex);
				s_priv->cmd_in_use = B_FALSE;
				cmd->cmd_result	   = CMD1394_EINVALID_CONTEXT;
				TNF_PROBE_1(t1394_read_error,
				    S1394_TNF_SL_ATREQ_ERROR, "", tnf_string,
				    msg, "CMD1394_BLOCKING in bus reset "
				    "context");
				TNF_PROBE_0_DEBUG(t1394_read_exit,
				    S1394_TNF_SL_ATREQ_STACK, "");
				return (DDI_FAILURE);
			}
		}

		s1394_pending_q_insert(to_hal, cmd, S1394_PENDING_Q_FRONT);
		mutex_exit(&to_hal->topology_tree_mutex);

		/* Block (if necessary) */
		goto block_on_asynch_cmd;
	}
	mutex_exit(&to_hal->topology_tree_mutex);

	/* Send the command out */
	ret = s1394_xfer_asynch_command(to_hal, cmd, &err);

	if (ret != DDI_SUCCESS) {
		if (err == CMD1394_ESTALE_GENERATION) {
			/* Remove cmd from outstanding request Q */
			s1394_remove_q_asynch_cmd(to_hal, cmd);
			s1394_pending_q_insert(to_hal, cmd,
			    S1394_PENDING_Q_FRONT);

			/* Block (if necessary) */
			goto block_on_asynch_cmd;

		} else {
			/* Remove cmd from outstanding request Q */
			s1394_remove_q_asynch_cmd(to_hal, cmd);

			s_priv->cmd_in_use = B_FALSE;

			/* Copy error code into result */
			cmd->cmd_result    = err;

			TNF_PROBE_1(t1394_read_error, S1394_TNF_SL_ATREQ_ERROR,
			    "", tnf_string, msg, "Failed in "
			    "s1394_xfer_asynch_command()");
			TNF_PROBE_0_DEBUG(t1394_read_exit,
			    S1394_TNF_SL_ATREQ_STACK, "");
			return (DDI_FAILURE);
		}
	} else {
		/* Block (if necessary) */
		goto block_on_asynch_cmd;
	}

block_on_asynch_cmd:
	s1394_block_on_asynch_cmd(cmd);

	TNF_PROBE_0_DEBUG(t1394_read_exit,
	    S1394_TNF_SL_ATREQ_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_write()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		cmd			Pointer to the command to send
 *
 * Output(s):	DDI_SUCCESS		Target successful sent the command
 *		DDI_FAILURE		Target failed to send command
 *
 * Description:	t1394_write() attempts to send an asynchronous write request
 *		onto the 1394 bus.
 */
int
t1394_write(t1394_handle_t t1394_hdl, cmd1394_cmd_t *cmd)
{
	s1394_hal_t	  *to_hal;
	s1394_target_t	  *target;
	s1394_cmd_priv_t  *s_priv;
	s1394_hal_state_t state;
	int		  ret;
	int		  err;

	TNF_PROBE_0_DEBUG(t1394_write_enter, S1394_TNF_SL_ATREQ_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(cmd != NULL);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Is this command currently in use? */
	if (s_priv->cmd_in_use == B_TRUE) {
		TNF_PROBE_1(t1394_write_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Attempted to resend an in-use command");
		TNF_PROBE_0_DEBUG(t1394_write_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		ASSERT(s_priv->cmd_in_use == B_FALSE);
		return (DDI_FAILURE);
	}

	target = (s1394_target_t *)t1394_hdl;

	/* Set-up the destination of the command */
	to_hal = target->on_hal;

	/* Is this an FA request? */
	if (s_priv->cmd_ext_type == S1394_CMD_EXT_FA) {
		if (S1394_IS_CMD_FCP(s_priv) &&
		    (s1394_fcp_write_check_cmd(cmd) != DDI_SUCCESS)) {
			TNF_PROBE_0_DEBUG(t1394_write_exit,
			    S1394_TNF_SL_ATREQ_STACK, "");
			return (DDI_FAILURE);
		}
		s1394_fa_convert_cmd(to_hal, cmd);
	}

	/* No status (default) */
	cmd->cmd_result = CMD1394_NOSTATUS;

	/* Check for proper command type */
	if ((cmd->cmd_type != CMD1394_ASYNCH_WR_QUAD) &&
	    (cmd->cmd_type != CMD1394_ASYNCH_WR_BLOCK)) {
		cmd->cmd_result = CMD1394_EINVALID_COMMAND;
		s1394_fa_check_restore_cmd(to_hal, cmd);
		TNF_PROBE_1(t1394_write_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Invalid command type specified");
		TNF_PROBE_0_DEBUG(t1394_write_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		return (DDI_FAILURE);
	}

	/* Is this a blocking command on interrupt stack? */
	if ((cmd->cmd_options & CMD1394_BLOCKING) &&
	    (servicing_interrupt())) {
		cmd->cmd_result = CMD1394_EINVALID_CONTEXT;
		s1394_fa_check_restore_cmd(to_hal, cmd);
		TNF_PROBE_1(t1394_write_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Tried to use CMD1394_BLOCKING in intr "
		    "context");
		TNF_PROBE_0_DEBUG(t1394_write_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		return (DDI_FAILURE);
	}

	mutex_enter(&to_hal->topology_tree_mutex);
	state = to_hal->hal_state;
	if (state != S1394_HAL_NORMAL) {
		ret = s1394_HAL_asynch_error(to_hal, cmd, state);
		if (ret != CMD1394_CMDSUCCESS) {
			cmd->cmd_result = ret;
			mutex_exit(&to_hal->topology_tree_mutex);
			s1394_fa_check_restore_cmd(to_hal, cmd);
			return (DDI_FAILURE);
		}
	}

	ret = s1394_setup_asynch_command(to_hal, target, cmd,
	    S1394_CMD_WRITE, &err);

	/* Command has now been put onto the queue! */
	if (ret != DDI_SUCCESS) {
		/* Copy error code into result */
		cmd->cmd_result = err;
		mutex_exit(&to_hal->topology_tree_mutex);
		s1394_fa_check_restore_cmd(to_hal, cmd);
		TNF_PROBE_1(t1394_write_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Failed in s1394_setup_asynch_command()");
		TNF_PROBE_0_DEBUG(t1394_write_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		return (DDI_FAILURE);
	}

	/*
	 * If this command was sent during a bus reset,
	 * then put it onto the pending Q.
	 */
	if (state == S1394_HAL_RESET) {
		/* Remove cmd from outstanding request Q */
		s1394_remove_q_asynch_cmd(to_hal, cmd);
		/* Are we on the bus reset event stack? */
		if (s1394_on_br_thread(to_hal) == B_TRUE) {
			/* Blocking commands are not allowed */
			if (cmd->cmd_options & CMD1394_BLOCKING) {
				mutex_exit(&to_hal->topology_tree_mutex);
				s_priv->cmd_in_use = B_FALSE;
				cmd->cmd_result    = CMD1394_EINVALID_CONTEXT;
				s1394_fa_check_restore_cmd(to_hal, cmd);
				TNF_PROBE_1(t1394_write_error,
				    S1394_TNF_SL_ATREQ_ERROR, "", tnf_string,
				    msg, "CMD1394_BLOCKING in bus reset cntxt");
				TNF_PROBE_0_DEBUG(t1394_write_exit,
				    S1394_TNF_SL_ATREQ_STACK, "");
				return (DDI_FAILURE);
			}
		}

		s1394_pending_q_insert(to_hal, cmd, S1394_PENDING_Q_FRONT);
		mutex_exit(&to_hal->topology_tree_mutex);

		/* Block (if necessary) */
		s1394_block_on_asynch_cmd(cmd);

		TNF_PROBE_0_DEBUG(t1394_write_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		return (DDI_SUCCESS);
	}
	mutex_exit(&to_hal->topology_tree_mutex);

	/* Send the command out */
	ret = s1394_xfer_asynch_command(to_hal, cmd, &err);

	if (ret != DDI_SUCCESS) {
		if (err == CMD1394_ESTALE_GENERATION) {
			/* Remove cmd from outstanding request Q */
			s1394_remove_q_asynch_cmd(to_hal, cmd);
			s1394_pending_q_insert(to_hal, cmd,
			    S1394_PENDING_Q_FRONT);

			/* Block (if necessary) */
			s1394_block_on_asynch_cmd(cmd);

			TNF_PROBE_0_DEBUG(t1394_write_exit,
			    S1394_TNF_SL_ATREQ_STACK, "");
			return (DDI_SUCCESS);
		} else {
			/* Remove cmd from outstanding request Q */
			s1394_remove_q_asynch_cmd(to_hal, cmd);

			s_priv->cmd_in_use = B_FALSE;

			/* Copy error code into result */
			cmd->cmd_result = err;

			s1394_fa_check_restore_cmd(to_hal, cmd);
			TNF_PROBE_1(t1394_write_error,
			    S1394_TNF_SL_ATREQ_ERROR, "", tnf_string, msg,
			    "Failed in s1394_xfer_asynch_command()");
			TNF_PROBE_0_DEBUG(t1394_write_exit,
			    S1394_TNF_SL_ATREQ_STACK, "");
			return (DDI_FAILURE);
		}
	} else {
		/* Block (if necessary) */
		s1394_block_on_asynch_cmd(cmd);

		TNF_PROBE_0_DEBUG(t1394_write_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		return (DDI_SUCCESS);
	}
}

/*
 * Function:    t1394_lock()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		cmd			Pointer to the command to send
 *
 * Output(s):	DDI_SUCCESS		Target successful sent the command
 *		DDI_FAILURE		Target failed to send command
 *
 * Description:	t1394_lock() attempts to send an asynchronous lock request
 *		onto the 1394 bus.
 */
int
t1394_lock(t1394_handle_t t1394_hdl, cmd1394_cmd_t *cmd)
{
	s1394_hal_t	    *to_hal;
	s1394_target_t	    *target;
	s1394_cmd_priv_t    *s_priv;
	s1394_hal_state_t   state;
	cmd1394_lock_type_t lock_type;
	uint_t		    num_retries;
	int		    ret;

	TNF_PROBE_0_DEBUG(t1394_lock_enter, S1394_TNF_SL_ATREQ_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(cmd != NULL);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Is this command currently in use? */
	if (s_priv->cmd_in_use == B_TRUE) {
		TNF_PROBE_1(t1394_lock_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Attempted to resend an in-use command");
		TNF_PROBE_0_DEBUG(t1394_lock_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		ASSERT(s_priv->cmd_in_use == B_FALSE);
		return (DDI_FAILURE);
	}

	target = (s1394_target_t *)t1394_hdl;

	/* Set-up the destination of the command */
	to_hal = target->on_hal;

	mutex_enter(&to_hal->topology_tree_mutex);
	state = to_hal->hal_state;
	if (state != S1394_HAL_NORMAL) {
		ret = s1394_HAL_asynch_error(to_hal, cmd, state);
		if (ret != CMD1394_CMDSUCCESS) {
			cmd->cmd_result = ret;
			mutex_exit(&to_hal->topology_tree_mutex);
			return (DDI_FAILURE);
		}
	}
	mutex_exit(&to_hal->topology_tree_mutex);

	/* Check for proper command type */
	if ((cmd->cmd_type != CMD1394_ASYNCH_LOCK_32) &&
	    (cmd->cmd_type != CMD1394_ASYNCH_LOCK_64)) {
		cmd->cmd_result = CMD1394_EINVALID_COMMAND;
		TNF_PROBE_1(t1394_lock_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Invalid command type sent to "
		    "t1394_lock()");
		TNF_PROBE_0_DEBUG(t1394_lock_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		return (DDI_FAILURE);
	}

	/* No status (default) */
	cmd->cmd_result = CMD1394_NOSTATUS;

	/* Is this a blocking command on interrupt stack? */
	if ((cmd->cmd_options & CMD1394_BLOCKING) &&
	    (servicing_interrupt())) {
		cmd->cmd_result = CMD1394_EINVALID_CONTEXT;
		TNF_PROBE_1(t1394_lock_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Tried to use CMD1394_BLOCKING in intr "
		    "context");
		TNF_PROBE_0_DEBUG(t1394_lock_exit, S1394_TNF_SL_ATREQ_STACK,
		    "");
		return (DDI_FAILURE);
	}

	if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
		lock_type	= cmd->cmd_u.l32.lock_type;
		num_retries	= cmd->cmd_u.l32.num_retries;
	} else {	/* (cmd->cmd_type == CMD1394_ASYNCH_LOCK_64) */
		lock_type	= cmd->cmd_u.l64.lock_type;
		num_retries	= cmd->cmd_u.l64.num_retries;
	}

	/* Make sure num_retries is reasonable */
	ASSERT(num_retries <= MAX_NUMBER_OF_LOCK_RETRIES);

	switch (lock_type) {
	case CMD1394_LOCK_MASK_SWAP:
	case CMD1394_LOCK_FETCH_ADD:
	case CMD1394_LOCK_LITTLE_ADD:
	case CMD1394_LOCK_BOUNDED_ADD:
	case CMD1394_LOCK_WRAP_ADD:
	case CMD1394_LOCK_COMPARE_SWAP:
		ret = s1394_compare_swap(to_hal, target, cmd);
		break;

	case CMD1394_LOCK_BIT_AND:
	case CMD1394_LOCK_BIT_OR:
	case CMD1394_LOCK_BIT_XOR:
	case CMD1394_LOCK_INCREMENT:
	case CMD1394_LOCK_DECREMENT:
	case CMD1394_LOCK_ADD:
	case CMD1394_LOCK_SUBTRACT:
	case CMD1394_LOCK_THRESH_ADD:
	case CMD1394_LOCK_THRESH_SUBTRACT:
	case CMD1394_LOCK_CLIP_ADD:
	case CMD1394_LOCK_CLIP_SUBTRACT:
		ret = s1394_split_lock_req(to_hal, target, cmd);
		break;

	default:
		TNF_PROBE_1(t1394_lock_error, S1394_TNF_SL_ATREQ_ERROR, "",
		    tnf_string, msg, "Invalid lock_type in command");
		cmd->cmd_result = CMD1394_EINVALID_COMMAND;
		ret = DDI_FAILURE;
		break;
	}

	TNF_PROBE_0_DEBUG(t1394_lock_exit, S1394_TNF_SL_ATREQ_STACK, "");
	return (ret);
}

/*
 * Function:    t1394_alloc_addr()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		addr_allocp		The structure used to specify the type,
 *					    size, permissions, and callbacks
 *					    (if any) for the requested block
 *					    of 1394 address space
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	result			Used to pass more specific info back
 *					    to target
 *
 * Description:	t1394_alloc_addr() requests that part of the 1394 Address Space
 *		on the local node be set aside for this target driver, and
 *		associated with this address space should be some permissions
 *		and callbacks.  If the request is unable to be fulfilled,
 *		t1394_alloc_addr() will return DDI_FAILURE and result will
 *		indicate the reason.  T1394_EINVALID_PARAM indicates that the
 *		combination of flags given is invalid, and T1394_EALLOC_ADDR
 *		indicates that the requested type of address space is
 *		unavailable.
 */
/* ARGSUSED */
int
t1394_alloc_addr(t1394_handle_t t1394_hdl, t1394_alloc_addr_t *addr_allocp,
    uint_t flags, int *result)
{
	s1394_hal_t	*hal;
	s1394_target_t	*target;
	uint64_t	addr_lo;
	uint64_t	addr_hi;
	int		err;

	TNF_PROBE_0_DEBUG(t1394_alloc_addr_enter, S1394_TNF_SL_ARREQ_STACK,
	    "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(addr_allocp != NULL);

	target = (s1394_target_t *)t1394_hdl;

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	/* Get the bounds of the request */
	addr_lo = addr_allocp->aa_address;
	addr_hi = addr_lo + addr_allocp->aa_length;

	/* Check combination of flags */
	if ((addr_allocp->aa_enable & T1394_ADDR_RDENBL) &&
	    (addr_allocp->aa_evts.recv_read_request == NULL) &&
	    (addr_allocp->aa_kmem_bufp == NULL)) {
		if ((addr_allocp->aa_type != T1394_ADDR_FIXED)	||
		    (addr_lo < hal->physical_addr_lo)		||
		    (addr_hi > hal->physical_addr_hi)) {

			/*
			 * Reads are enabled, but target doesn't want to
			 * be notified and hasn't given backing store
			 */
			*result = T1394_EINVALID_PARAM;

			TNF_PROBE_1(t1394_alloc_addr_error,
			    S1394_TNF_SL_ARREQ_ERROR, "", tnf_string, msg,
			    "Invalid flags "
			    "(RDs on, notify off, no backing store)");
			TNF_PROBE_0_DEBUG(t1394_alloc_addr_exit,
			    S1394_TNF_SL_ARREQ_STACK, "");

			/* kstats - addr alloc failures */
			hal->hal_kstats->addr_alloc_fail++;
			return (DDI_FAILURE);
		} else {
			addr_allocp->aa_enable &= ~T1394_ADDR_RDENBL;
		}
	}

	if ((addr_allocp->aa_enable & T1394_ADDR_WRENBL) &&
	    (addr_allocp->aa_evts.recv_write_request == NULL) &&
	    (addr_allocp->aa_kmem_bufp == NULL)) {
		if ((addr_allocp->aa_type != T1394_ADDR_FIXED)	||
		    (addr_lo < hal->physical_addr_lo)		||
		    (addr_hi > hal->physical_addr_hi)) {

			/*
			 * Writes are enabled, but target doesn't want to
			 * be notified and hasn't given backing store
			 */
			*result = T1394_EINVALID_PARAM;

			TNF_PROBE_1(t1394_alloc_addr_error,
			    S1394_TNF_SL_ARREQ_ERROR, "", tnf_string, msg,
			    "Invalid flags "
			    "(WRs on, notify off, no backing store)");
			TNF_PROBE_0_DEBUG(t1394_alloc_addr_exit,
			    S1394_TNF_SL_ARREQ_STACK, "");

			/* kstats - addr alloc failures */
			hal->hal_kstats->addr_alloc_fail++;
			return (DDI_FAILURE);
		} else {
			addr_allocp->aa_enable &= ~T1394_ADDR_WRENBL;
		}
	}

	if ((addr_allocp->aa_enable & T1394_ADDR_LKENBL) &&
	    (addr_allocp->aa_evts.recv_lock_request == NULL) &&
	    (addr_allocp->aa_kmem_bufp == NULL)) {
		if ((addr_allocp->aa_type != T1394_ADDR_FIXED)	||
		    (addr_lo < hal->physical_addr_lo)		||
		    (addr_hi > hal->physical_addr_hi)) {

			/*
			 * Locks are enabled, but target doesn't want to
			 * be notified and hasn't given backing store
			 */
			*result = T1394_EINVALID_PARAM;

			TNF_PROBE_1(t1394_alloc_addr_error,
			    S1394_TNF_SL_ARREQ_ERROR, "", tnf_string, msg,
			    "Invalid flags "
			    "(LKs on, notify off, no backing store)");
			TNF_PROBE_0_DEBUG(t1394_alloc_addr_exit,
			    S1394_TNF_SL_ARREQ_STACK, "");

			/* kstats - addr alloc failures */
			hal->hal_kstats->addr_alloc_fail++;
			return (DDI_FAILURE);
		} else {
			addr_allocp->aa_enable &= ~T1394_ADDR_LKENBL;
		}
	}

	/* If not T1394_ADDR_FIXED, then allocate a block */
	if (addr_allocp->aa_type != T1394_ADDR_FIXED) {
		err = s1394_request_addr_blk((s1394_hal_t *)target->on_hal,
					addr_allocp);
		if (err != DDI_SUCCESS) {
			*result = T1394_EALLOC_ADDR;
			/* kstats - addr alloc failures */
			hal->hal_kstats->addr_alloc_fail++;
		} else {
			*result = T1394_NOERROR;
		}
		TNF_PROBE_0_DEBUG(t1394_alloc_addr_exit,
		    S1394_TNF_SL_ARREQ_STACK, "");
		return (err);
	} else {
		err = s1394_claim_addr_blk((s1394_hal_t *)target->on_hal,
					addr_allocp);
		if (err != DDI_SUCCESS) {
			*result = T1394_EALLOC_ADDR;
			/* kstats - addr alloc failures */
			hal->hal_kstats->addr_alloc_fail++;
		} else {
			*result = T1394_NOERROR;
			/* If physical, update the AR request counter */
			if ((addr_lo >= hal->physical_addr_lo) &&
			    (addr_hi <= hal->physical_addr_hi)) {
				rw_enter(&hal->target_list_rwlock, RW_WRITER);
				target->physical_arreq_enabled++;
				rw_exit(&hal->target_list_rwlock);

				s1394_physical_arreq_set_one(target);
			}
		}
		TNF_PROBE_0_DEBUG(t1394_alloc_addr_exit,
		    S1394_TNF_SL_ARREQ_STACK, "");
		return (err);
	}
}

/*
 * Function:    t1394_free_addr()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		addr_hdl		The address "handle" returned by the
 *					   the t1394_alloc_addr() routine
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		Target successfully freed memory
 *		DDI_FAILURE		Target failed to free the memory block
 *
 * Description:	t1394_free_addr() attempts to free up memory that has been
 *		allocated by the target using t1394_alloc_addr().
 */
/* ARGSUSED */
int
t1394_free_addr(t1394_handle_t t1394_hdl, t1394_addr_handle_t *addr_hdl,
    uint_t flags)
{
	s1394_addr_space_blk_t	*curr_blk;
	s1394_hal_t		*hal;
	s1394_target_t		*target;

	TNF_PROBE_0_DEBUG(t1394_free_addr_enter, S1394_TNF_SL_ARREQ_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(addr_hdl != NULL);

	target = (s1394_target_t *)t1394_hdl;

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	curr_blk = (s1394_addr_space_blk_t *)(*addr_hdl);

	if (s1394_free_addr_blk(hal, curr_blk) != DDI_SUCCESS) {
		TNF_PROBE_0_DEBUG(t1394_free_addr_exit,
		    S1394_TNF_SL_ARREQ_STACK, "");
		return (DDI_FAILURE);
	}

	/* If physical, update the AR request counter */
	if (curr_blk->addr_type == T1394_ADDR_FIXED) {
		target->physical_arreq_enabled--;
		s1394_physical_arreq_clear_one(target);
	}

	*addr_hdl = NULL;

	/* kstats - number of addr frees */
	hal->hal_kstats->addr_space_free++;

	TNF_PROBE_0_DEBUG(t1394_free_addr_exit, S1394_TNF_SL_ARREQ_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_recv_request_done()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		resp			Pointer to the command which the
 *					    target received in it's callback
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		Target successfully returned command
 *					    to the 1394 Software Framework,
 *					    and, if necessary, sent response
 *		DDI_FAILURE		Target failed to return the command to
 *					    the 1394 Software Framework
 *
 * Description:	t1394_recv_request_done() takes the command that is given and
 *		determines whether that command requires a response to be
 *		sent on the 1394 bus.  If it is necessary and it's response
 *		code (cmd_result) has been set appropriately, then a response
 *		will be sent.  If no response is necessary (broadcast or
 *		posted write), then the command resources are reclaimed.
 */
/* ARGSUSED */
int
t1394_recv_request_done(t1394_handle_t t1394_hdl, cmd1394_cmd_t *resp,
    uint_t flags)
{
	s1394_hal_t	 *hal;
	s1394_cmd_priv_t *s_priv;
	h1394_cmd_priv_t *h_priv;
	mblk_t		 *curr_blk;
	size_t		 msgb_len;
	size_t		 size;
	int		 ret;
	boolean_t	 response = B_TRUE;
	boolean_t	 posted_write = B_FALSE;
	boolean_t	 write_cmd = B_FALSE;
	boolean_t	 mblk_too_small;

	TNF_PROBE_0_DEBUG(t1394_recv_request_done_enter,
	    S1394_TNF_SL_ARREQ_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(resp != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(resp);

	/* Get a pointer to the HAL private struct */
	h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;

	/* Is this an FA request? */
	if (s_priv->cmd_ext_type == S1394_CMD_EXT_FA) {
		s1394_fa_convert_cmd(hal, resp);
	}

	/* Is this a write request? */
	if ((resp->cmd_type == CMD1394_ASYNCH_WR_QUAD) ||
	    (resp->cmd_type == CMD1394_ASYNCH_WR_BLOCK)) {
		write_cmd = B_TRUE;
		/* Is this a posted write request? */
		posted_write = s_priv->posted_write;
	}

	/* If broadcast or posted write cmd, don't send response */
	if ((resp->broadcast == 1) ||
	    ((write_cmd == B_TRUE) && (posted_write == B_TRUE)))
		response = B_FALSE;

	if (response == B_FALSE) {
		if ((write_cmd == B_TRUE) && (posted_write == B_TRUE)) {
			/* kstats - Posted Write error */
			hal->hal_kstats->arreq_posted_write_error++;
		}

		/* Free the command - Pass it back to the HAL */
		HAL_CALL(hal).response_complete(hal->halinfo.hal_private, resp,
		    h_priv);
		TNF_PROBE_0_DEBUG(t1394_recv_request_done_exit,
		    S1394_TNF_SL_ARREQ_STACK, "");
		return (DDI_SUCCESS);
	}

	ASSERT(response == B_TRUE);

	/* Verify valid response code */
	switch (resp->cmd_result) {
	case IEEE1394_RESP_COMPLETE:
		/* Is the mblk_t too small? */
		if (resp->cmd_type == CMD1394_ASYNCH_RD_BLOCK) {
			curr_blk = resp->cmd_u.b.data_block;
			size	 = resp->cmd_u.b.blk_length;
			msgb_len = 0;
			mblk_too_small = B_TRUE;

			if (curr_blk == NULL) {
				TNF_PROBE_1(t1394_recv_request_done_error,
				    S1394_TNF_SL_ARREQ_ERROR, "", tnf_string,
				    msg, "mblk_t is NULL in response");
				TNF_PROBE_0_DEBUG(t1394_recv_request_done_exit,
				    S1394_TNF_SL_ARREQ_STACK, "");
				/*
				 * Free the command - Pass it back
				 * to the HAL
				 */
				HAL_CALL(hal).response_complete(
				    hal->halinfo.hal_private, resp, h_priv);
				ASSERT(curr_blk != NULL);
				return (DDI_FAILURE);
			}

			while (curr_blk != NULL) {
				msgb_len +=
				    (curr_blk->b_wptr - curr_blk->b_rptr);

				if (msgb_len >= size) {
					mblk_too_small = B_FALSE;
					break;
				}
				curr_blk = curr_blk->b_cont;
			}

			if (mblk_too_small == B_TRUE) {
				TNF_PROBE_1(t1394_recv_request_done_error,
				    S1394_TNF_SL_ARREQ_ERROR, "", tnf_string,
				    msg, "mblk_t too small in response");
				TNF_PROBE_0_DEBUG(t1394_recv_request_done_exit,
				    S1394_TNF_SL_ARREQ_STACK, "");
				/*
				 * Free the command - Pass it back
				 * to the HAL
				 */
				HAL_CALL(hal).response_complete(
				    hal->halinfo.hal_private, resp, h_priv);
				ASSERT(mblk_too_small != B_TRUE);
				return (DDI_FAILURE);
			}
		}
		/* FALLTHROUGH */
	case IEEE1394_RESP_CONFLICT_ERROR:
	case IEEE1394_RESP_DATA_ERROR:
	case IEEE1394_RESP_TYPE_ERROR:
	case IEEE1394_RESP_ADDRESS_ERROR:
		ret = s1394_send_response(hal, resp);
		TNF_PROBE_0_DEBUG(t1394_recv_request_done_exit,
		    S1394_TNF_SL_ARREQ_STACK, "");
		return (ret);

	default:
		TNF_PROBE_1(t1394_recv_request_done_error,
		    S1394_TNF_SL_ARREQ_ERROR, "", tnf_string, msg,
		    "Invalid response code");
		TNF_PROBE_0_DEBUG(t1394_recv_request_done_exit,
		    S1394_TNF_SL_ARREQ_STACK, "");
		return (DDI_FAILURE);
	}
}


/*
 * Function:    t1394_fcp_register_controller()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		evts			The structure in which the target
 *					    specifies its callback routines
 *
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		Successfully registered.
 *
 *		DDI_FAILURE		Not registered due to failure.
 *
 * Description:	Used to register the target within the Framework as an FCP
 *		controller.
 */
/* ARGSUSED */
int
t1394_fcp_register_controller(t1394_handle_t t1394_hdl, t1394_fcp_evts_t *evts,
    uint_t flags)
{
	int		result;

	TNF_PROBE_0_DEBUG(t1394_fcp_register_controller_enter,
	    S1394_TNF_SL_FCP_STACK, "");

	ASSERT(t1394_hdl != NULL);

	result = s1394_fcp_register_ctl((s1394_target_t *)t1394_hdl, evts);

	TNF_PROBE_0_DEBUG(t1394_fcp_register_controller_exit,
	    S1394_TNF_SL_FCP_STACK, "");
	return (result);
}

/*
 * Function:    t1394_fcp_unregister_controller()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *
 * Output(s):	DDI_SUCCESS		Successfully unregistered.
 *
 *		DDI_FAILURE		Not unregistered due to failure.
 *
 * Description:	Used to unregister the target within the Framework as an FCP
 *		controller.
 */
int
t1394_fcp_unregister_controller(t1394_handle_t t1394_hdl)
{
	int		result;

	TNF_PROBE_0_DEBUG(t1394_fcp_unregister_controller_enter,
	    S1394_TNF_SL_FCP_STACK, "");

	ASSERT(t1394_hdl != NULL);

	result = s1394_fcp_unregister_ctl((s1394_target_t *)t1394_hdl);

	TNF_PROBE_0_DEBUG(t1394_fcp_unregister_controller_exit,
	    S1394_TNF_SL_FCP_STACK, "");
	return (result);
}

/*
 * Function:    t1394_fcp_register_target()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		evts			The structure in which the target
 *					    specifies its callback routines
 *
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		Successfully registered.
 *
 *		DDI_FAILURE		Not registered due to failure.
 *
 * Description:	Used to register the target within the Framework as an FCP
 *		target.
 */
/* ARGSUSED */
int
t1394_fcp_register_target(t1394_handle_t t1394_hdl, t1394_fcp_evts_t *evts,
    uint_t flags)
{
	int		result;

	TNF_PROBE_0_DEBUG(t1394_fcp_register_target_enter,
	    S1394_TNF_SL_FCP_STACK, "");

	ASSERT(t1394_hdl != NULL);

	result = s1394_fcp_register_tgt((s1394_target_t *)t1394_hdl, evts);

	TNF_PROBE_0_DEBUG(t1394_fcp_register_target_exit,
	    S1394_TNF_SL_FCP_STACK, "");
	return (result);
}

/*
 * Function:    t1394_fcp_unregister_target()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *
 * Output(s):	DDI_SUCCESS		Successfully unregistered.
 *
 *		DDI_FAILURE		Not unregistered due to failure.
 *
 * Description:	Used to unregister the target within the Framework as an FCP
 *		target.
 */
int
t1394_fcp_unregister_target(t1394_handle_t t1394_hdl)
{
	int		result;

	TNF_PROBE_0_DEBUG(t1394_fcp_unregister_target_enter,
	    S1394_TNF_SL_FCP_STACK, "");

	ASSERT(t1394_hdl != NULL);

	result = s1394_fcp_unregister_tgt((s1394_target_t *)t1394_hdl);

	TNF_PROBE_0_DEBUG(t1394_fcp_unregister_target_exit,
	    S1394_TNF_SL_FCP_STACK, "");
	return (result);
}

/*
 * Function:    t1394_cmp_register()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		evts			The structure in which the target
 *					    specifies its callback routines
 *
 * Output(s):	DDI_SUCCESS		Successfully registered.
 *
 *		DDI_FAILURE		Not registered due to failure.
 *
 * Description:	Used to register the target within the Framework as a CMP
 *		device.
 */
/* ARGSUSED */
int
t1394_cmp_register(t1394_handle_t t1394_hdl, t1394_cmp_evts_t *evts,
    uint_t flags)
{
	int		result;

	TNF_PROBE_0_DEBUG(t1394_cmp_register_enter, S1394_TNF_SL_CMP_STACK, "");

	ASSERT(t1394_hdl != NULL);

	result = s1394_cmp_register((s1394_target_t *)t1394_hdl, evts);

	TNF_PROBE_0_DEBUG(t1394_cmp_register_exit, S1394_TNF_SL_CMP_STACK, "");
	return (result);
}

/*
 * Function:    t1394_cmp_unregister()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		evts			The structure in which the target
 *					    specifies its callback routines
 *
 * Output(s):	DDI_SUCCESS		Successfully registered.
 *
 *		DDI_FAILURE		Not registered due to failure.
 *
 * Description:	Used to unregister the target within the Framework as a CMP
 *		device.
 */
int
t1394_cmp_unregister(t1394_handle_t t1394_hdl)
{
	int		result;

	TNF_PROBE_0_DEBUG(t1394_cmp_unregister_enter, S1394_TNF_SL_CMP_STACK,
	    "");

	ASSERT(t1394_hdl != NULL);

	result = s1394_cmp_unregister((s1394_target_t *)t1394_hdl);

	TNF_PROBE_0_DEBUG(t1394_cmp_unregister_exit, S1394_TNF_SL_CMP_STACK,
	    "");
	return (result);
}

/*
 * Function:    t1394_cmp_read()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		reg			Register type.
 *		valp			Returned register value.
 *
 * Output(s):	DDI_SUCCESS		Successfully registered.
 *
 *		DDI_FAILURE		Not registered due to failure.
 *
 * Description:	Used to read a CMP register value.
 */
int
t1394_cmp_read(t1394_handle_t t1394_hdl, t1394_cmp_reg_t reg, uint32_t *valp)
{
	int		result;

	TNF_PROBE_0_DEBUG(t1394_cmp_read_enter, S1394_TNF_SL_CMP_STACK, "");

	ASSERT(t1394_hdl != NULL);

	result = s1394_cmp_read((s1394_target_t *)t1394_hdl, reg, valp);

	TNF_PROBE_0_DEBUG(t1394_cmp_read_exit, S1394_TNF_SL_CMP_STACK, "");
	return (result);
}

/*
 * Function:    t1394_cmp_cas()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		reg			Register type.
 *		arg_val			Compare argument.
 *		new_val			New register value.
 *		old_valp		Returned original register value.
 *
 * Output(s):	DDI_SUCCESS		Successfully registered.
 *
 *		DDI_FAILURE		Not registered due to failure.
 *
 * Description:	Used to compare-swap a CMP register value.
 */
int
t1394_cmp_cas(t1394_handle_t t1394_hdl, t1394_cmp_reg_t reg, uint32_t arg_val,
    uint32_t new_val, uint32_t *old_valp)
{
	int		result;

	TNF_PROBE_0_DEBUG(t1394_cmp_read_enter, S1394_TNF_SL_CMP_STACK, "");

	ASSERT(t1394_hdl != NULL);

	result = s1394_cmp_cas((s1394_target_t *)t1394_hdl, reg, arg_val,
				new_val, old_valp);

	TNF_PROBE_0_DEBUG(t1394_cmp_read_exit, S1394_TNF_SL_CMP_STACK, "");
	return (result);
}

/*
 * Function:    t1394_alloc_isoch_single()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		sii			The structure used to set up the
 *					    overall characteristics of the
 *					    isochronous stream
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	setup_args		Contains the channel number that was
 *					    allocated
 *		t1394_single_hdl	This in the isoch "handle" used in
 *					    t1394_free_isoch_single()
 *		result			Used to pass more specific info back
 *					    to target
 *
 * Description:	t1394_alloc_isoch_single() is used to direct the 1394 Software
 *		Framework to allocate an isochronous channel and bandwidth
 *		from the Isochronous Resource Manager (IRM).  If a bus reset
 *		occurs, the 1394 Software Framework attempts to reallocate the
 *		same resources, calling the rsrc_fail_target() callback if
 *		it is unsuccessful.
 */
/* ARGSUSED */
int
t1394_alloc_isoch_single(t1394_handle_t t1394_hdl,
    t1394_isoch_singleinfo_t *sii, uint_t flags,
    t1394_isoch_single_out_t *output_args,
    t1394_isoch_single_handle_t	*t1394_single_hdl, int *result)
{
	s1394_hal_t		*hal;
	s1394_isoch_cec_t	*cec_new;
	t1394_join_isochinfo_t	jii;
	int			ret;
	int			err;

	TNF_PROBE_0_DEBUG(t1394_alloc_isoch_single_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_single_hdl != NULL);
	ASSERT(sii != NULL);

	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Check for invalid channel_mask */
	if (sii->si_channel_mask == 0) {
		TNF_PROBE_1(t1394_alloc_isoch_single_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Invalid channel mask");
		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_single_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Check for invalid bandwidth */
	if ((sii->si_bandwidth <= IEEE1394_BANDWIDTH_MIN) ||
	    (sii->si_bandwidth > IEEE1394_BANDWIDTH_MAX)) {
		TNF_PROBE_1(t1394_alloc_isoch_single_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Invalid bandwidth requirements");
		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_single_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Verify that rsrc_fail_target() callback is non-NULL */
	if (sii->rsrc_fail_target == NULL) {
		TNF_PROBE_1(t1394_alloc_isoch_single_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Invalid callback specified");
		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_single_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/*
	 * Allocate an Isoch CEC of type S1394_SINGLE
	 */

	/* Allocate the Isoch CEC structure */
	cec_new = kmem_zalloc(sizeof (s1394_isoch_cec_t), KM_SLEEP);

	/* Initialize the structure type */
	cec_new->cec_type = S1394_SINGLE;

	/* Create the mutex and "in_callbacks" cv */
	mutex_init(&cec_new->isoch_cec_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);
	cv_init(&cec_new->in_callbacks_cv, NULL, CV_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Initialize the Isoch CEC's member list */
	cec_new->cec_member_list_head = NULL;
	cec_new->cec_member_list_tail = NULL;

	/* Initialize the filters */
	cec_new->filter_min_speed	= sii->si_speed;
	cec_new->filter_max_speed	= sii->si_speed;
	cec_new->filter_current_speed	= cec_new->filter_max_speed;
	cec_new->filter_channel_mask	= sii->si_channel_mask;
	cec_new->bandwidth		= sii->si_bandwidth;
	cec_new->state_transitions	= ISOCH_CEC_FREE | ISOCH_CEC_JOIN |
					    ISOCH_CEC_SETUP;

	mutex_enter(&hal->isoch_cec_list_mutex);

	/* Insert Isoch CEC into the HAL's list */
	s1394_isoch_cec_list_insert(hal, cec_new);

	mutex_exit(&hal->isoch_cec_list_mutex);

	/*
	 * Join the newly created Isoch CEC
	 */
	jii.req_channel_mask	= sii->si_channel_mask;
	jii.req_max_speed	= sii->si_speed;
	jii.jii_options		= T1394_TALKER;
	jii.isoch_cec_evts_arg	= sii->single_evt_arg;

	/* All events are NULL except rsrc_fail_target() */
	jii.isoch_cec_evts.setup_target	    = NULL;
	jii.isoch_cec_evts.start_target	    = NULL;
	jii.isoch_cec_evts.stop_target	    = NULL;
	jii.isoch_cec_evts.stop_target	    = NULL;
	jii.isoch_cec_evts.teardown_target  = NULL;
	jii.isoch_cec_evts.rsrc_fail_target = sii->rsrc_fail_target;

	ret = t1394_join_isoch_cec(t1394_hdl,
	    (t1394_isoch_cec_handle_t)cec_new, 0, &jii);

	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(t1394_alloc_isoch_single_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Unexpected error from t1394_join_isoch_cec()");

		ret = t1394_free_isoch_cec(t1394_hdl, flags,
		    (t1394_isoch_cec_handle_t *)&cec_new);
		if (ret != DDI_SUCCESS) {
			/* Unable to free the Isoch CEC */
			TNF_PROBE_1(t1394_alloc_isoch_single_error,
			    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
			    "Unexpected error from t1394_free_isoch_cec()");
			ASSERT(0);
		}

		/* Handle is nulled out before returning */
		*t1394_single_hdl = NULL;

		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_single_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/*
	 * Setup the isoch resources, etc.
	 */
	ret = t1394_setup_isoch_cec(t1394_hdl,
	    (t1394_isoch_cec_handle_t)cec_new, 0, &err);

	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(t1394_alloc_isoch_single_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Unexpected error from t1394_setup_isoch_cec()");

		*result = err;

		/* Leave the Isoch CEC */
		ret = t1394_leave_isoch_cec(t1394_hdl,
		    (t1394_isoch_cec_handle_t)cec_new, 0);
		if (ret != DDI_SUCCESS) {
			/* Unable to leave the Isoch CEC */
			TNF_PROBE_1(t1394_alloc_isoch_single_error,
			    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
			    "Unexpected error from t1394_leave_isoch_cec()");
			ASSERT(0);
		}

		/* Free up the Isoch CEC */
		ret = t1394_free_isoch_cec(t1394_hdl, flags,
		    (t1394_isoch_cec_handle_t *)&cec_new);
		if (ret != DDI_SUCCESS) {
			/* Unable to free the Isoch CEC */
			TNF_PROBE_1(t1394_alloc_isoch_single_error,
			    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
			    "Unexpected error from t1394_free_isoch_cec()");
			ASSERT(0);
		}

		/* Handle is nulled out before returning */
		*t1394_single_hdl = NULL;

		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_single_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Return the setup_args - channel num and speed */
	mutex_enter(&cec_new->isoch_cec_mutex);
	output_args->channel_num  = cec_new->realloc_chnl_num;
	mutex_exit(&cec_new->isoch_cec_mutex);

	/* Update the handle */
	*t1394_single_hdl = (t1394_isoch_single_handle_t)cec_new;

	TNF_PROBE_0_DEBUG(t1394_alloc_isoch_single_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_free_isoch_single()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_single_hdl	The isoch "handle" return by
 *					    t1394_alloc_isoch_single()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	None
 *
 * Description:	t1394_free_isoch_single() frees the isochronous resources
 *		and the handle that were allocated during the call to
 *		t1394_alloc_isoch_single().
 */
/* ARGSUSED */
void
t1394_free_isoch_single(t1394_handle_t t1394_hdl,
    t1394_isoch_single_handle_t *t1394_single_hdl, uint_t flags)
{
	s1394_isoch_cec_t *cec_curr;
	int		  ret;

	TNF_PROBE_0_DEBUG(t1394_free_isoch_single_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_single_hdl != NULL);

	/* Convert the handle to an Isoch CEC pointer */
	cec_curr = (s1394_isoch_cec_t *)(*t1394_single_hdl);

	/*
	 * Teardown the isoch resources, etc.
	 */
	ret = t1394_teardown_isoch_cec(t1394_hdl,
	    (t1394_isoch_cec_handle_t)cec_curr, 0);
	if (ret != DDI_SUCCESS) {
		/* Unable to teardown the Isoch CEC */
		TNF_PROBE_1(t1394_free_isoch_single_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Unexpected error from t1394_teardown_isoch_cec()");
		ASSERT(0);
	}

	/*
	 * Leave the Isoch CEC
	 */
	ret = t1394_leave_isoch_cec(t1394_hdl,
	    (t1394_isoch_cec_handle_t)cec_curr, 0);
	if (ret != DDI_SUCCESS) {
		/* Unable to leave the Isoch CEC */
		TNF_PROBE_1(t1394_free_isoch_single_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Unexpected error from t1394_leave_isoch_cec()");
		ASSERT(0);
	}

	/*
	 * Free the Isoch CEC
	 */
	ret = t1394_free_isoch_cec(t1394_hdl, flags,
	    (t1394_isoch_cec_handle_t *)&cec_curr);
	if (ret != DDI_SUCCESS) {
		/* Unable to free the Isoch CEC */
		TNF_PROBE_1(t1394_free_isoch_single_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Unexpected error from t1394_free_isoch_cec()");
		ASSERT(0);
	}

	/* Handle is nulled out before returning */
	*t1394_single_hdl = NULL;

	TNF_PROBE_0_DEBUG(t1394_free_isoch_single_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
}

/*
 * Function:    t1394_alloc_isoch_cec()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		props			The structure used to set up the
 *					    overall characteristics of for
 *					    the Isoch CEC.
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	t1394_isoch_cec_hdl	The Isoch CEC "handle" used in all
 *					    subsequent isoch_cec() calls
 *
 * Description:	t1394_alloc_isoch_cec() allocates and initializes an
 *		isochronous channel event coordinator (Isoch CEC) for use
 *		in managing and coordinating activity for an isoch channel
 */
/* ARGSUSED */
int
t1394_alloc_isoch_cec(t1394_handle_t t1394_hdl, t1394_isoch_cec_props_t *props,
    uint_t flags, t1394_isoch_cec_handle_t *t1394_isoch_cec_hdl)
{
	s1394_hal_t	  *hal;
	s1394_isoch_cec_t *cec_new;
	uint64_t	  temp;

	TNF_PROBE_0_DEBUG(t1394_alloc_isoch_cec_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_isoch_cec_hdl != NULL);
	ASSERT(props != NULL);

	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Check for invalid channel_mask */
	if (props->cec_channel_mask == 0) {
		TNF_PROBE_1(t1394_alloc_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Invalid channel mask");
		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Test conditions specific to T1394_NO_IRM_ALLOC */
	temp = props->cec_channel_mask;
	if (props->cec_options & T1394_NO_IRM_ALLOC) {
		/* If T1394_NO_IRM_ALLOC, then only one bit should be set */
		if (!ISP2(temp)) {
			TNF_PROBE_1(t1394_alloc_isoch_cec_error,
			    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
			    "Invalid channel mask");
			TNF_PROBE_0_DEBUG(t1394_alloc_isoch_cec_exit,
			    S1394_TNF_SL_ISOCH_STACK, "");
			return (DDI_FAILURE);
		}

		/* If T1394_NO_IRM_ALLOC, then speeds should be equal */
		if (props->cec_min_speed != props->cec_max_speed) {
			TNF_PROBE_1(t1394_alloc_isoch_cec_error,
			    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
			    "Invalid speeds (min != max)");
			TNF_PROBE_0_DEBUG(t1394_alloc_isoch_cec_exit,
			    S1394_TNF_SL_ISOCH_STACK, "");
			return (DDI_FAILURE);
		}
	}

	/* Check for invalid bandwidth */
	if ((props->cec_bandwidth <= IEEE1394_BANDWIDTH_MIN) ||
	    (props->cec_bandwidth > IEEE1394_BANDWIDTH_MAX)) {
		TNF_PROBE_1(t1394_alloc_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Invalid bandwidth requirements");
		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Allocate the Isoch CEC structure */
	cec_new = kmem_zalloc(sizeof (s1394_isoch_cec_t), KM_SLEEP);

	/* Initialize the structure type */
	cec_new->cec_type = S1394_PEER_TO_PEER;

	/* Create the mutex and "in_callbacks" cv */
	mutex_init(&cec_new->isoch_cec_mutex, NULL, MUTEX_DRIVER,
	    hal->halinfo.hw_interrupt);
	cv_init(&cec_new->in_callbacks_cv, NULL, CV_DRIVER,
	    hal->halinfo.hw_interrupt);

	/* Initialize the Isoch CEC's member list */
	cec_new->cec_member_list_head	= NULL;
	cec_new->cec_member_list_tail	= NULL;

	/* Initialize the filters */
	cec_new->filter_min_speed	= props->cec_min_speed;
	cec_new->filter_max_speed	= props->cec_max_speed;
	cec_new->filter_current_speed	= cec_new->filter_max_speed;
	cec_new->filter_channel_mask	= props->cec_channel_mask;
	cec_new->bandwidth		= props->cec_bandwidth;
	cec_new->cec_options		= props->cec_options;
	cec_new->state_transitions	= ISOCH_CEC_FREE | ISOCH_CEC_JOIN |
					    ISOCH_CEC_SETUP;

	mutex_enter(&hal->isoch_cec_list_mutex);

	/* Insert Isoch CEC into the HAL's list */
	s1394_isoch_cec_list_insert(hal, cec_new);

	mutex_exit(&hal->isoch_cec_list_mutex);

	/* Update the handle and return */
	*t1394_isoch_cec_hdl = (t1394_isoch_cec_handle_t)cec_new;

	TNF_PROBE_0_DEBUG(t1394_alloc_isoch_cec_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_free_isoch_cec()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		flags			The flags parameter is unused (for now)
 *		t1394_isoch_cec_hdl	The Isoch CEC "handle" returned by
 *					    t1394_alloc_isoch_cec()
 *
 * Output(s):	DDI_SUCCESS		Target successfully freed the Isoch CEC
 *		DDI_FAILURE		Target failed to free the Isoch CEC
 *
 * Description:	t1394_free_isoch_cec() attempts to free the Isoch CEC
 *		structure.  It will fail (DDI_FAILURE) if there are any
 *		remaining members who have not yet left.
 */
/* ARGSUSED */
int
t1394_free_isoch_cec(t1394_handle_t t1394_hdl, uint_t flags,
    t1394_isoch_cec_handle_t *t1394_isoch_cec_hdl)
{
	s1394_hal_t	  *hal;
	s1394_isoch_cec_t *cec_curr;

	TNF_PROBE_0_DEBUG(t1394_free_isoch_cec_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_isoch_cec_hdl != NULL);

	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Convert the handle to an Isoch CEC pointer */
	cec_curr = (s1394_isoch_cec_t *)(*t1394_isoch_cec_hdl);

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* Are we in any callbacks? */
	if (CEC_IN_ANY_CALLBACKS(cec_curr)) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_free_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to free Isoch CEC (in callbacks)");
		TNF_PROBE_0_DEBUG(t1394_free_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Is "free" a legal state transition? */
	if (CEC_TRANSITION_LEGAL(cec_curr, ISOCH_CEC_FREE) == 0) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_free_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to free Isoch CEC");
		TNF_PROBE_0_DEBUG(t1394_free_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}
	mutex_exit(&cec_curr->isoch_cec_mutex);

	mutex_enter(&hal->isoch_cec_list_mutex);

	/* Remove Isoch CEC from HAL's list */
	s1394_isoch_cec_list_remove(hal, cec_curr);

	mutex_exit(&hal->isoch_cec_list_mutex);

	/* Destroy the Isoch CEC's mutex and cv */
	cv_destroy(&cec_curr->in_callbacks_cv);
	mutex_destroy(&cec_curr->isoch_cec_mutex);

	/* Free up the memory for the Isoch CEC struct */
	kmem_free(cec_curr, sizeof (s1394_isoch_cec_t));

	/* Update the handle and return */
	*t1394_isoch_cec_hdl = NULL;

	TNF_PROBE_0_DEBUG(t1394_free_isoch_cec_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_join_isoch_cec()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_isoch_cec_hdl	The Isoch CEC "handle" returned by
 *					    t1394_alloc_isoch_cec()
 *		flags			The flags parameter is unused (for now)
 *		join_isoch_info		This structure provides infomation
 *					    about a target that wishes to join
 *					    the given Isoch CEC.  It gives
 *					    max_speed, channel_mask, etc.
 *
 * Output(s):	DDI_SUCCESS		Target successfully joined the
 *					    Isoch CEC
 *		DDI_FAILURE		Target failed to join the Isoch CEC
 *
 * Description:	t1394_join_isoch_cec() determines, based on the information
 *		given in the join_isoch_info structure, if the target may
 *		join the Isoch CEC.  If it is determined that the target may
 *		join, the specified callback routines are stored away for
 *		later use in the coordination tasks.
 */
/* ARGSUSED */
int
t1394_join_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags,
    t1394_join_isochinfo_t *join_isoch_info)
{
	s1394_hal_t		 *hal;
	s1394_isoch_cec_t	 *cec_curr;
	s1394_isoch_cec_member_t *member_new;
	uint64_t		 check_mask;
	uint_t			 curr_max_speed;

	TNF_PROBE_0_DEBUG(t1394_join_isoch_cec_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_isoch_cec_hdl != NULL);

	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Convert the handle to an Isoch CEC pointer */
	cec_curr = (s1394_isoch_cec_t *)t1394_isoch_cec_hdl;

	/* Allocate a new Isoch CEC member structure */
	member_new = kmem_zalloc(sizeof (s1394_isoch_cec_member_t), KM_SLEEP);

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* Are we in any callbacks? (Wait for them to finish) */
	while (CEC_IN_ANY_CALLBACKS(cec_curr)) {
		cec_curr->cec_want_wakeup = B_TRUE;
		cv_wait(&cec_curr->in_callbacks_cv,
		    &cec_curr->isoch_cec_mutex);
	}

	/* Is "join" a legal state transition? */
	if (CEC_TRANSITION_LEGAL(cec_curr, ISOCH_CEC_JOIN) == 0) {
		kmem_free(member_new, sizeof (s1394_isoch_cec_member_t));
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_join_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to join Isoch CEC");
		TNF_PROBE_0_DEBUG(t1394_join_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Check the channel mask for consistency */
	check_mask = join_isoch_info->req_channel_mask &
	    cec_curr->filter_channel_mask;
	if (check_mask == 0) {
		kmem_free(member_new, sizeof (s1394_isoch_cec_member_t));
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_join_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Inconsistent channel mask specified");
		TNF_PROBE_0_DEBUG(t1394_join_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Check for consistent speeds */
	if (join_isoch_info->req_max_speed < cec_curr->filter_min_speed) {
		kmem_free(member_new, sizeof (s1394_isoch_cec_member_t));
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_join_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Inconsistent speed specified");
		TNF_PROBE_0_DEBUG(t1394_join_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	} else if (join_isoch_info->req_max_speed <
	    cec_curr->filter_current_speed) {
		curr_max_speed = join_isoch_info->req_max_speed;
	} else {
		curr_max_speed = cec_curr->filter_current_speed;
	}

	/* Check for no more than one talker */
	if ((join_isoch_info->jii_options & T1394_TALKER) &&
	    (cec_curr->cec_member_talker != NULL)) {
		kmem_free(member_new, sizeof (s1394_isoch_cec_member_t));
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_join_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Multiple talkers specified");
		TNF_PROBE_0_DEBUG(t1394_join_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Verify that all callbacks are non-NULL (for PEER_TO_PEER) */
	if ((cec_curr->cec_type == S1394_PEER_TO_PEER) &&
	    ((join_isoch_info->isoch_cec_evts.setup_target	== NULL) ||
	    (join_isoch_info->isoch_cec_evts.start_target	== NULL) ||
	    (join_isoch_info->isoch_cec_evts.stop_target	== NULL) ||
	    (join_isoch_info->isoch_cec_evts.rsrc_fail_target	== NULL) ||
	    (join_isoch_info->isoch_cec_evts.teardown_target	== NULL))) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_join_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Invalid callbacks specified");
		TNF_PROBE_0_DEBUG(t1394_join_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Copy the events information into the struct */
	member_new->isoch_cec_evts	= join_isoch_info->isoch_cec_evts;
	member_new->isoch_cec_evts_arg	= join_isoch_info->isoch_cec_evts_arg;
	member_new->cec_mem_options	= join_isoch_info->jii_options;
	member_new->cec_mem_target	= (s1394_target_t *)t1394_hdl;

	/* Insert new member into Isoch CEC's member list */
	s1394_isoch_cec_member_list_insert(hal, cec_curr, member_new);

	/* Update the channel mask filter */
	cec_curr->filter_channel_mask	= check_mask;

	/* Update the speed filter */
	cec_curr->filter_current_speed	= curr_max_speed;

	/* Update the talker pointer (if necessary) */
	if (join_isoch_info->jii_options & T1394_TALKER)
		cec_curr->cec_member_talker = cec_curr->cec_member_list_head;

	/*
	 * Now "leave" is a legal state transition
	 * and "free" is an illegal state transition
	 */
	CEC_SET_LEGAL(cec_curr, ISOCH_CEC_LEAVE);
	CEC_SET_ILLEGAL(cec_curr, ISOCH_CEC_FREE);

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	TNF_PROBE_0_DEBUG(t1394_join_isoch_cec_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_leave_isoch_cec()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_isoch_cec_hdl	The Isoch CEC "handle" returned by
 *					    t1394_alloc_isoch_cec()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		Target successfully left the
 *					    Isoch CEC
 *		DDI_FAILURE		Target failed to leave the Isoch CEC
 *
 * Description:	t1394_leave_isoch_cec() is used by a target driver to remove
 *		itself from the Isoch CEC's member list.  It is possible
 *		for this call to fail because the target is not found in
 *		the current member list, or because it is not an appropriate
 *		time for a target to leave.
 */
/* ARGSUSED */
int
t1394_leave_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags)
{
	s1394_hal_t		 *hal;
	s1394_isoch_cec_t	 *cec_curr;
	s1394_isoch_cec_member_t *member_curr;
	s1394_isoch_cec_member_t *member_temp;
	boolean_t		 found;
	uint64_t		 temp_channel_mask;
	uint_t			 temp_max_speed;

	TNF_PROBE_0_DEBUG(t1394_leave_isoch_cec_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_isoch_cec_hdl != NULL);

	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Convert the handle to an Isoch CEC pointer */
	cec_curr = (s1394_isoch_cec_t *)t1394_isoch_cec_hdl;

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* Are we in any callbacks? (Wait for them to finish) */
	while (CEC_IN_ANY_CALLBACKS(cec_curr)) {
		cec_curr->cec_want_wakeup = B_TRUE;
		cv_wait(&cec_curr->in_callbacks_cv,
		    &cec_curr->isoch_cec_mutex);
	}

	/* Is "leave" a legal state transition? */
	if (CEC_TRANSITION_LEGAL(cec_curr, ISOCH_CEC_LEAVE) == 0) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_leave_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to leave Isoch CEC");
		TNF_PROBE_0_DEBUG(t1394_leave_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Find the Target on the CEC's member list */
	found = B_FALSE;
	temp_channel_mask = cec_curr->cec_alloc_props.cec_channel_mask;
	temp_max_speed	  = cec_curr->cec_alloc_props.cec_max_speed;
	member_curr	  = cec_curr->cec_member_list_head;
	while (member_curr != NULL) {
		if (member_curr->cec_mem_target ==
		    (s1394_target_t *)t1394_hdl) {
			member_temp = member_curr;
			found	    = B_TRUE;
		} else {
			/* Keep track of channel mask and max speed info */
			temp_channel_mask &= member_curr->req_channel_mask;
			if (member_curr->req_max_speed < temp_max_speed)
				temp_max_speed = member_curr->req_max_speed;
		}
		member_curr = member_curr->cec_mem_next;
	}

	/* Target not found on this Isoch CEC */
	if (found == B_FALSE) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_leave_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Target not found in Isoch CEC member list");
		TNF_PROBE_0_DEBUG(t1394_leave_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	} else {
		/* This member's departure may change filter constraints */
		cec_curr->filter_current_speed  = temp_max_speed;
		cec_curr->filter_channel_mask   = temp_channel_mask;
	}

	/* Remove member from Isoch CEC's member list */
	s1394_isoch_cec_member_list_remove(hal, cec_curr, member_temp);

	/* If we are removing the talker, then update the pointer */
	if (cec_curr->cec_member_talker == member_temp)
		cec_curr->cec_member_talker = NULL;

	/* Is the Isoch CEC's member list empty? */
	if ((cec_curr->cec_member_list_head == NULL) &&
	    (cec_curr->cec_member_list_tail == NULL)) {
		/*
		 * Now "free" _might_ be a legal state transition
		 * if we aren't in setup or start phases and "leave"
		 * is definitely an illegal state transition
		 */
		if (CEC_TRANSITION_LEGAL(cec_curr, ISOCH_CEC_JOIN) != 0)
			CEC_SET_LEGAL(cec_curr, ISOCH_CEC_FREE);
		CEC_SET_ILLEGAL(cec_curr, ISOCH_CEC_LEAVE);
	}

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	/* Free the Isoch CEC member structure */
	kmem_free(member_temp, sizeof (s1394_isoch_cec_member_t));

	TNF_PROBE_0_DEBUG(t1394_leave_isoch_cec_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_setup_isoch_cec()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_isoch_cec_hdl	The Isoch CEC "handle" returned by
 *					    t1394_alloc_isoch_cec()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	result			Used to pass more specific info back
 *					    to target
 *
 * Description:	t1394_setup_isoch_cec() directs the 1394 Software Framework
 *		to allocate isochronous resources and invoke the setup_target()
 *		callback for each member of the Isoch CEC.  This call may
 *		fail because bandwidth was unavailable (T1394_ENO_BANDWIDTH),
 *		channels were unavailable (T1394_ENO_CHANNEL), or one of the
 *		member targets returned failure from its setup_target()
 *		callback.
 */
/* ARGSUSED */
int
t1394_setup_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags, int *result)
{
	s1394_hal_t			*hal;
	s1394_isoch_cec_t		*cec_curr;
	s1394_isoch_cec_member_t	*member_curr;
	t1394_setup_target_args_t	target_args;
	uint64_t			temp_chnl_mask;
	uint32_t			old_chnl;
	uint32_t			try_chnl;
	uint_t				bw_alloc_units;
	uint_t				generation;
	int				chnl_num;
	int				err;
	int				ret;
	int				j;
	int	(*setup_callback)(t1394_isoch_cec_handle_t, opaque_t,
			    t1394_setup_target_args_t *);

	TNF_PROBE_0_DEBUG(t1394_setup_isoch_cec_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_isoch_cec_hdl != NULL);

	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Convert the handle to an Isoch CEC pointer */
	cec_curr = (s1394_isoch_cec_t *)t1394_isoch_cec_hdl;

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* Are we in any callbacks? */
	if (CEC_IN_ANY_CALLBACKS(cec_curr)) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_setup_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to setup Isoch CEC (in callbacks)");
		TNF_PROBE_0_DEBUG(t1394_setup_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Is "setup" a legal state transition? */
	if (CEC_TRANSITION_LEGAL(cec_curr, ISOCH_CEC_SETUP) == 0) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_setup_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to setup Isoch CEC");
		TNF_PROBE_0_DEBUG(t1394_setup_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* If T1394_NO_IRM_ALLOC is set then don't allocate... do callbacks */
	if (cec_curr->cec_options & T1394_NO_IRM_ALLOC) {
		goto setup_do_callbacks;
	}

	/* Allocate bandwidth and channels */
	for (j = 0; j < S1394_ISOCH_ALLOC_RETRIES; j++) {
		/*
		 * Get the current generation number - don't
		 * need the lock because we are read only here
		 */
		generation = hal->generation_count;

		/* Compute how much bandwidth is needed */
		bw_alloc_units = s1394_compute_bw_alloc_units(hal,
		    cec_curr->bandwidth, cec_curr->filter_current_speed);

		/* Check that the generation has not changed - */
		/* don't need the lock (read only) */
		if (generation != hal->generation_count)
			continue;

		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);

		/* Try to allocate the bandwidth */
		ret = s1394_bandwidth_alloc(hal, bw_alloc_units, generation,
		    &err);

		/* Lock the Isoch CEC member list */
		mutex_enter(&cec_curr->isoch_cec_mutex);

		/* If there was a bus reset, start over */
		if (ret == DDI_FAILURE) {
			if (err == CMD1394_EBUSRESET) {
				continue; /* start over and try again */
			} else {
				*result = T1394_ENO_BANDWIDTH;
				/* Unlock the Isoch CEC member list */
				mutex_exit(&cec_curr->isoch_cec_mutex);
				TNF_PROBE_1(t1394_setup_isoch_cec_error,
				    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string,
				    msg, "Unable to allocate isoch bandwidth");
				TNF_PROBE_0_DEBUG(t1394_setup_isoch_cec_exit,
				    S1394_TNF_SL_ISOCH_STACK, "");
				return (DDI_FAILURE);
			}
		}

		/* Check that the generation has not changed - */
		/* don't need the lock (read only) */
		if (generation != hal->generation_count)
			continue;

		/*
		 * Allocate a channel
		 *    From IEEE 1394-1995, Section 8.3.2.3.8: "Bits
		 *    allocated in the CHANNELS_AVAILABLE_HI field of
		 *    this register shall start at bit zero (channel
		 *    number zero), and additional channel numbers shall
		 *    be represented in a monotonically increasing sequence
		 *    of bit numbers up to a maximum of bit 31 (channel
		 *    number 31).  Bits allocated in the CHANNELS_AVAILABLE_LO
		 *    field of this register shall start at bit zero
		 *    (channel number 32), and additional channel numbers
		 *    shall be represented in a monotonically increasing
		 *    sequence of bit numbers up to a maximum of bit 31
		 *    (channel number 63).
		 */
		temp_chnl_mask = cec_curr->filter_channel_mask;
		for (chnl_num = 63; chnl_num >= 0; chnl_num--) {
			if ((temp_chnl_mask & 1) == 1) {
				try_chnl = (1 << ((63 - chnl_num) % 32));

				/* Unlock the Isoch CEC member list */
				mutex_exit(&cec_curr->isoch_cec_mutex);
				if (chnl_num < 32) {
					ret = s1394_channel_alloc(hal,
					    try_chnl, generation,
					    S1394_CHANNEL_ALLOC_HI, &old_chnl,
					    &err);
				} else {
					ret = s1394_channel_alloc(hal,
					    try_chnl, generation,
					    S1394_CHANNEL_ALLOC_LO, &old_chnl,
					    &err);
				}
				/* Lock the Isoch CEC member list */
				mutex_enter(&cec_curr->isoch_cec_mutex);

				/* Did we get a channel? (or a bus reset) */
				if ((ret == DDI_SUCCESS) ||
				    (err == CMD1394_EBUSRESET))
					break;
			}
			temp_chnl_mask = temp_chnl_mask >> 1;
		}

		/* If we've tried all the possible channels, then fail */
		if (chnl_num == 0) {
			*result = T1394_ENO_CHANNEL;
			/*
			 * If we successfully allocate bandwidth, and
			 * then fail getting a channel, we need to
			 * free up the bandwidth
			 */

			/* Check that the generation has not changed */
			/* lock not needed here (read only) */
			if (generation != hal->generation_count)
				continue;

			/* Unlock the Isoch CEC member list */
			mutex_exit(&cec_curr->isoch_cec_mutex);

			/* Try to free up the bandwidth */
			ret = s1394_bandwidth_free(hal, bw_alloc_units,
			    generation, &err);

			/* Lock the Isoch CEC member list */
			mutex_enter(&cec_curr->isoch_cec_mutex);

			if (ret == DDI_FAILURE) {
				if (err == CMD1394_EBUSRESET) {
					continue;
				} else {
					TNF_PROBE_1(t1394_setup_isoch_cec_error,
					    S1394_TNF_SL_ISOCH_ERROR, "",
					    tnf_string, msg,
					    "Unable to free isoch bandwidth");
				}
			}

			/* Unlock the Isoch CEC member list */
			mutex_exit(&cec_curr->isoch_cec_mutex);
			TNF_PROBE_1(t1394_setup_isoch_cec_error,
			    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
			    "Unable to allocate isoch channel");
			TNF_PROBE_0_DEBUG(t1394_setup_isoch_cec_exit,
			    S1394_TNF_SL_ISOCH_STACK, "");
			return (DDI_FAILURE);
		}

		/* If we got a channel, we're done (else start over) */
		if (ret == DDI_SUCCESS)
			break;
		else if (err == CMD1394_EBUSRESET)
			continue;
	}

	/* Have we gotten too many bus resets? */
	if (j == S1394_ISOCH_ALLOC_RETRIES) {
		*result = T1394_ENO_BANDWIDTH;
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_setup_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Unable to allocate isoch channel");
		TNF_PROBE_0_DEBUG(t1394_setup_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	cec_curr->realloc_valid	    = B_TRUE;
	cec_curr->realloc_chnl_num  = chnl_num;
	cec_curr->realloc_bandwidth = cec_curr->bandwidth;
	cec_curr->realloc_speed	    = cec_curr->filter_current_speed;

setup_do_callbacks:
	/* Call all of the setup_target() callbacks */
	target_args.channel_num	    = chnl_num;
	target_args.channel_speed   = cec_curr->filter_current_speed;

	/* Now we are going into the callbacks */
	cec_curr->in_callbacks	    = B_TRUE;

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	member_curr = cec_curr->cec_member_list_head;
	*result = 0;
	while (member_curr != NULL) {
		if (member_curr->isoch_cec_evts.setup_target != NULL) {
			setup_callback =
			    member_curr->isoch_cec_evts.setup_target;
			ret = setup_callback(t1394_isoch_cec_hdl,
			    member_curr->isoch_cec_evts_arg, &target_args);
			if (ret != DDI_SUCCESS)
				*result = T1394_ETARGET;
		}
		member_curr = member_curr->cec_mem_next;
	}

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* We are finished with the callbacks */
	cec_curr->in_callbacks = B_FALSE;
	if (cec_curr->cec_want_wakeup == B_TRUE) {
		cec_curr->cec_want_wakeup = B_FALSE;
		cv_broadcast(&cec_curr->in_callbacks_cv);
	}

	/*
	 * Now "start" and "teardown" are legal state transitions
	 * and "join", "free", and "setup" are illegal state transitions
	 */
	CEC_SET_LEGAL(cec_curr, (ISOCH_CEC_START | ISOCH_CEC_TEARDOWN));
	CEC_SET_ILLEGAL(cec_curr, (ISOCH_CEC_JOIN | ISOCH_CEC_FREE |
	    ISOCH_CEC_SETUP));

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	/* Return DDI_FAILURE if any targets failed setup */
	if (*result != 0) {
		TNF_PROBE_1(t1394_setup_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Target returned error in setup_target()");
		TNF_PROBE_0_DEBUG(t1394_setup_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(t1394_setup_isoch_cec_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_start_isoch_cec()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_isoch_cec_hdl	The Isoch CEC "handle" returned by
 *					    t1394_alloc_isoch_cec()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		All start_target() callbacks returned
 *					    successfully
 *		DDI_FAILURE		One or more start_target() callbacks
 *					    returned failure
 *
 * Description:	t1394_start_isoch_cec() directs the 1394 Software Framework
 *		to invoke each of the start_target() callbacks, first for
 *		each listener, then for the talker.
 */
/* ARGSUSED */
int
t1394_start_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags)
{
	s1394_isoch_cec_t	 *cec_curr;
	s1394_isoch_cec_member_t *member_curr;
	int			 ret;
	boolean_t		 err;
	int	(*start_callback)(t1394_isoch_cec_handle_t, opaque_t);

	TNF_PROBE_0_DEBUG(t1394_start_isoch_cec_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_isoch_cec_hdl != NULL);

	/* Convert the handle to an Isoch CEC pointer */
	cec_curr = (s1394_isoch_cec_t *)t1394_isoch_cec_hdl;

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* Are we in any callbacks? */
	if (CEC_IN_ANY_CALLBACKS(cec_curr)) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_start_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to start Isoch CEC (in callbacks)");
		TNF_PROBE_0_DEBUG(t1394_start_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Is "start" a legal state transition? */
	if (CEC_TRANSITION_LEGAL(cec_curr, ISOCH_CEC_START) == 0) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_start_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to start Isoch CEC");
		TNF_PROBE_0_DEBUG(t1394_start_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Now we are going into the callbacks */
	cec_curr->in_callbacks = B_TRUE;

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	/*
	 * Call all of the start_target() callbacks
	 * Start at the tail (listeners first) and
	 * go toward the head (talker last)
	 */
	member_curr = cec_curr->cec_member_list_tail;
	err = B_FALSE;
	while (member_curr != NULL) {
		if (member_curr->isoch_cec_evts.start_target != NULL) {
			start_callback =
			    member_curr->isoch_cec_evts.start_target;
			ret = start_callback(t1394_isoch_cec_hdl,
			    member_curr->isoch_cec_evts_arg);
		if (ret != DDI_SUCCESS)
			err = B_TRUE;
		}
		member_curr = member_curr->cec_mem_prev;
	}

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* We are finished with the callbacks */
	cec_curr->in_callbacks = B_FALSE;
	if (cec_curr->cec_want_wakeup == B_TRUE) {
		cec_curr->cec_want_wakeup = B_FALSE;
		cv_broadcast(&cec_curr->in_callbacks_cv);
	}

	/*
	 * Now "stop" is a legal state transitions
	 * and "start" and "teardown" are illegal state transitions
	 */
	CEC_SET_LEGAL(cec_curr, ISOCH_CEC_STOP);
	CEC_SET_ILLEGAL(cec_curr, (ISOCH_CEC_START | ISOCH_CEC_TEARDOWN));

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	/* Return DDI_FAILURE if any targets failed start */
	if (err == B_TRUE) {
		TNF_PROBE_1(t1394_start_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Target returned error in start_target()");
		TNF_PROBE_0_DEBUG(t1394_start_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	TNF_PROBE_0_DEBUG(t1394_start_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_stop_isoch_cec()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_isoch_cec_hdl	The Isoch CEC "handle" returned by
 *					    t1394_alloc_isoch_cec()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		Target successfully stopped the
 *					    Isoch CEC
 *		DDI_FAILURE		Target failed to stop the Isoch CEC
 *
 * Description:	t1394_stop_isoch_cec() directs the 1394 Software Framework
 *		to invoke each of the stop_target() callbacks, first for
 *		the talker, then for each listener.
 *		(This call will fail if it is called at an
 *		inappropriate time, i.e. before the t1394_start_isoch_cec()
 *		call, etc.)
 */
/* ARGSUSED */
int
t1394_stop_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags)
{
	s1394_isoch_cec_t	 *cec_curr;
	s1394_isoch_cec_member_t *member_curr;
	void	(*stop_callback)(t1394_isoch_cec_handle_t, opaque_t);

	TNF_PROBE_0_DEBUG(t1394_stop_isoch_cec_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_isoch_cec_hdl != NULL);

	/* Convert the handle to an Isoch CEC pointer */
	cec_curr = (s1394_isoch_cec_t *)t1394_isoch_cec_hdl;

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* Are we in any callbacks? */
	if (CEC_IN_ANY_CALLBACKS(cec_curr)) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_stop_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to stop Isoch CEC (in callbacks)");
		TNF_PROBE_0_DEBUG(t1394_stop_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Is "stop" a legal state transition? */
	if (CEC_TRANSITION_LEGAL(cec_curr, ISOCH_CEC_STOP) == 0) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_stop_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to stop Isoch CEC");
		TNF_PROBE_0_DEBUG(t1394_stop_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Now we are going into the callbacks */
	cec_curr->in_callbacks = B_TRUE;

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	/*
	 * Call all of the stop_target() callbacks
	 * Start at the head (talker first) and
	 * go toward the tail (listeners last)
	 */
	member_curr = cec_curr->cec_member_list_head;
	while (member_curr != NULL) {
		if (member_curr->isoch_cec_evts.stop_target != NULL) {
			stop_callback =
			    member_curr->isoch_cec_evts.stop_target;
			stop_callback(t1394_isoch_cec_hdl,
			    member_curr->isoch_cec_evts_arg);
		}
		member_curr = member_curr->cec_mem_next;
	}

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* We are finished with the callbacks */
	cec_curr->in_callbacks = B_FALSE;
	if (cec_curr->cec_want_wakeup == B_TRUE) {
		cec_curr->cec_want_wakeup = B_FALSE;
		cv_broadcast(&cec_curr->in_callbacks_cv);
	}

	/*
	 * Now "start" and "teardown" are legal state transitions
	 * and "stop" is an illegal state transitions
	 */
	CEC_SET_LEGAL(cec_curr, (ISOCH_CEC_START | ISOCH_CEC_TEARDOWN));
	CEC_SET_ILLEGAL(cec_curr, ISOCH_CEC_STOP);

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	TNF_PROBE_0_DEBUG(t1394_stop_isoch_cec_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_teardown_isoch_cec()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_isoch_cec_hdl	The Isoch CEC "handle" returned by
 *					    t1394_alloc_isoch_cec()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	DDI_SUCCESS		Target successfully tore down the
 *					    Isoch CEC
 *		DDI_FAILURE		Target failed to tear down the
 *					    Isoch CEC
 *
 * Description:	t1394_teardown_isoch_cec() directs the 1394 Software Framework
 *		to free up any isochronous resources we might be holding and
 *		call all of the teardown_target() callbacks.
 *		(This call will fail if it is called at an
 *		inappropriate time, i.e. before the t1394_start_isoch_cec()
 *		call, before the t1394_stop_isoch_cec, etc.
 */
/* ARGSUSED */
int
t1394_teardown_isoch_cec(t1394_handle_t t1394_hdl,
    t1394_isoch_cec_handle_t t1394_isoch_cec_hdl, uint_t flags)
{
	s1394_hal_t		 *hal;
	s1394_isoch_cec_t	 *cec_curr;
	s1394_isoch_cec_member_t *member_curr;
	uint32_t		 chnl_mask;
	uint32_t		 old_chnl_mask;
	uint_t			 bw_alloc_units;
	uint_t			 generation;
	int			 ret;
	int			 err;
	void	(*teardown_callback)(t1394_isoch_cec_handle_t, opaque_t);

	TNF_PROBE_0_DEBUG(t1394_teardown_isoch_cec_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_isoch_cec_hdl != NULL);

	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Convert the handle to an Isoch CEC pointer */
	cec_curr = (s1394_isoch_cec_t *)t1394_isoch_cec_hdl;

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* Are we in any callbacks? */
	if (CEC_IN_ANY_CALLBACKS(cec_curr)) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_teardown_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to teardown Isoch CEC (in callbacks)");
		TNF_PROBE_0_DEBUG(t1394_teardown_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* Is "teardown" a legal state transition? */
	if (CEC_TRANSITION_LEGAL(cec_curr, ISOCH_CEC_TEARDOWN) == 0) {
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		TNF_PROBE_1(t1394_teardown_isoch_cec_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "Not allowed to teardown Isoch CEC");
		TNF_PROBE_0_DEBUG(t1394_teardown_isoch_cec_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");
		return (DDI_FAILURE);
	}

	/* If T1394_NO_IRM_ALLOC is set then don't free... do callbacks */
	if (cec_curr->cec_options & T1394_NO_IRM_ALLOC) {
		goto teardown_do_callbacks;
	}

	/* If nothing has been allocated or we failed to */
	/* reallocate, then we are done... call the callbacks */
	if ((cec_curr->realloc_valid == B_FALSE) ||
	    (cec_curr->realloc_failed == B_TRUE)) {
		goto teardown_do_callbacks;
	}

	/*
	 * Get the current generation number - don't need the
	 * topology tree mutex here because it is read-only, and
	 * there is a race condition with or without it.
	 */
	generation = hal->generation_count;

	/* Compute the amount bandwidth to free */
	bw_alloc_units = s1394_compute_bw_alloc_units(hal,
	    cec_curr->bandwidth, cec_curr->realloc_speed);

	/* Check that the generation has not changed - */
	/* don't need the lock (read only) */
	if (generation != hal->generation_count)
		goto teardown_do_callbacks;

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	/* Try to free up the bandwidth */
	ret = s1394_bandwidth_free(hal, bw_alloc_units, generation, &err);

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	if (ret == DDI_FAILURE) {
		if (err == CMD1394_EBUSRESET) {
			goto teardown_do_callbacks;
		} else {
			TNF_PROBE_1(t1394_teardown_isoch_cec_error,
			    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
			    "Unable to free allocated bandwidth");
		}
	}

	/* Free the allocated channel */
	chnl_mask = (1 << ((63 - cec_curr->realloc_chnl_num) % 32));

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);
	if (cec_curr->realloc_chnl_num < 32) {
		ret = s1394_channel_free(hal, chnl_mask, generation,
		    S1394_CHANNEL_ALLOC_HI, &old_chnl_mask, &err);
	} else {
		ret = s1394_channel_free(hal, chnl_mask, generation,
		    S1394_CHANNEL_ALLOC_LO, &old_chnl_mask, &err);
	}
	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	if (ret == DDI_FAILURE) {
		if (err == CMD1394_EBUSRESET) {
			goto teardown_do_callbacks;
		} else {
			TNF_PROBE_1(t1394_teardown_isoch_cec_error,
			    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
			    "Unable to free allocated bandwidth");
		}
	}

teardown_do_callbacks:
	/* From here on reallocation is unnecessary */
	cec_curr->realloc_valid	    = B_FALSE;
	cec_curr->realloc_chnl_num  = 0;
	cec_curr->realloc_bandwidth = 0;

	/* Now we are going into the callbacks */
	cec_curr->in_callbacks	    = B_TRUE;

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);

	/* Call all of the teardown_target() callbacks */
	member_curr = cec_curr->cec_member_list_head;
	while (member_curr != NULL) {
		if (member_curr->isoch_cec_evts.teardown_target != NULL) {
			teardown_callback =
			    member_curr->isoch_cec_evts.teardown_target;
			teardown_callback(t1394_isoch_cec_hdl,
			    member_curr->isoch_cec_evts_arg);
		}
		member_curr = member_curr->cec_mem_next;
	}

	/* Lock the Isoch CEC member list */
	mutex_enter(&cec_curr->isoch_cec_mutex);

	/* We are finished with the callbacks */
	cec_curr->in_callbacks = B_FALSE;
	if (cec_curr->cec_want_wakeup == B_TRUE) {
		cec_curr->cec_want_wakeup = B_FALSE;
		cv_broadcast(&cec_curr->in_callbacks_cv);
	}

	/*
	 * Now "join" and "setup" are legal state transitions
	 * and "start" and "teardown" are illegal state transitions
	 */
	CEC_SET_LEGAL(cec_curr, (ISOCH_CEC_JOIN | ISOCH_CEC_SETUP));
	CEC_SET_ILLEGAL(cec_curr, (ISOCH_CEC_START | ISOCH_CEC_TEARDOWN));

	/* And if the member list is empty, then "free" is legal too */
	if ((cec_curr->cec_member_list_head == NULL) &&
	    (cec_curr->cec_member_list_tail == NULL)) {
		CEC_SET_LEGAL(cec_curr, ISOCH_CEC_FREE);
	}

	/* Unlock the Isoch CEC member list */
	mutex_exit(&cec_curr->isoch_cec_mutex);
	TNF_PROBE_0_DEBUG(t1394_teardown_isoch_cec_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_alloc_isoch_dma()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		idi			This structure contains information
 *					    for configuring the data flow for
 *					    isochronous DMA
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	t1394_idma_hdl		The IDMA "handle" used in all
 *					    subsequent isoch_dma() calls
 *		result			Used to pass more specific info back
 *					    to target
 *
 * Description:	t1394_alloc_isoch_dma() allocates and initializes an
 *		isochronous DMA resource for transmitting or receiving
 *		isochronous data.  If it fails, result may hold
 *		T1394_EIDMA_NO_RESRCS, indicating that no isoch DMA resource
 *		are available.
 */
/* ARGSUSED */
int
t1394_alloc_isoch_dma(t1394_handle_t t1394_hdl,
    id1394_isoch_dmainfo_t *idi, uint_t flags,
    t1394_isoch_dma_handle_t *t1394_idma_hdl, int *result)
{
	s1394_hal_t	*hal;
	int		ret;

	TNF_PROBE_0_DEBUG(t1394_alloc_isoch_dma_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(idi != NULL);
	ASSERT(t1394_idma_hdl != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Sanity check dma options.  If talk enabled, listen should be off */
	if ((idi->idma_options & ID1394_TALK) &&
	    (idi->idma_options != ID1394_TALK)) {
		TNF_PROBE_1(t1394_alloc_isoch_dma_talk_conflict_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "conflicting idma options; talker and listener");
		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_dma_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");

		*result = T1394_EIDMA_CONFLICT;
		return (DDI_FAILURE);
	}

	/* Only one listen mode allowed */
	if ((idi->idma_options & ID1394_LISTEN_PKT_MODE) &&
	    (idi->idma_options & ID1394_LISTEN_BUF_MODE)) {
		TNF_PROBE_1(t1394_alloc_isoch_dma_listen_conflict_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "conflicting idma options; both listener modes set");
		TNF_PROBE_0_DEBUG(t1394_alloc_isoch_dma_exit,
		    S1394_TNF_SL_ISOCH_STACK, "");

		*result = T1394_EIDMA_CONFLICT;
		return (DDI_FAILURE);
	}

	/* Have HAL alloc a resource and compile ixl */
	ret = HAL_CALL(hal).alloc_isoch_dma(hal->halinfo.hal_private, idi,
	    (void **)t1394_idma_hdl, result);

	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(t1394_alloc_isoch_dma_hal_error,
		    S1394_TNF_SL_ISOCH_ERROR, "", tnf_string, msg,
		    "HAL alloc_isoch_dma error, maybe IXL compilation");
		if (*result == IXL1394_ENO_DMA_RESRCS) {
			*result = T1394_EIDMA_NO_RESRCS;
		}
	}

	TNF_PROBE_0_DEBUG(t1394_alloc_isoch_dma_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (ret);
}

/*
 * Function:    t1394_free_isoch_dma()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		flags			The flags parameter is unused (for now)
 *		t1394_idma_hdl		The IDMA "handle" returned by
 *					    t1394_alloc_isoch_dma()
 *
 * Output(s):	None
 *
 * Description:	t1394_free_isoch_dma() is used to free all DMA resources
 *		allocated for the isoch stream associated with t1394_idma_hdl.
 */
/* ARGSUSED */
void
t1394_free_isoch_dma(t1394_handle_t t1394_hdl, uint_t flags,
    t1394_isoch_dma_handle_t *t1394_idma_hdl)
{
	s1394_hal_t	*hal;

	TNF_PROBE_0_DEBUG(t1394_free_isoch_dma_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(*t1394_idma_hdl != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Tell HAL to release local isoch dma resources */
	HAL_CALL(hal).free_isoch_dma(hal->halinfo.hal_private, *t1394_idma_hdl);

	/* Null out isoch handle */
	*t1394_idma_hdl = NULL;

	TNF_PROBE_0_DEBUG(t1394_free_isoch_dma_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
}

/*
 * Function:    t1394_start_isoch_dma()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_idma_hdl		The IDMA "handle" returned by
 *					    t1394_alloc_isoch_dma()
 *		idma_ctrlinfo		This structure contains control args
 *					    used when starting isoch DMA for
 *					    the allocated resource
 *		flags			One flag defined - ID1394_START_ON_CYCLE
 *
 * Output(s):	result			Used to pass more specific info back
 *					    to target
 *
 * Description:	t1394_start_isoch_dma() is used to start DMA for the isoch
 *		stream associated with t1394_idma_hdl.
 */
/* ARGSUSED */
int
t1394_start_isoch_dma(t1394_handle_t t1394_hdl,
    t1394_isoch_dma_handle_t t1394_idma_hdl,
    id1394_isoch_dma_ctrlinfo_t *idma_ctrlinfo, uint_t flags,
    int *result)
{
	s1394_hal_t	*hal;
	int		ret;

	TNF_PROBE_0_DEBUG(t1394_start_isoch_dma_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_idma_hdl != NULL);
	ASSERT(idma_ctrlinfo != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	ret = HAL_CALL(hal).start_isoch_dma(hal->halinfo.hal_private,
	    (void *)t1394_idma_hdl, idma_ctrlinfo, flags, result);

	TNF_PROBE_0_DEBUG(t1394_start_isoch_dma_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (ret);
}

/*
 * Function:    t1394_stop_isoch_dma()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_idma_hdl		The IDMA "handle" returned by
 *					    t1394_alloc_isoch_dma()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	None
 *
 * Description:	t1394_stop_isoch_dma() is used to stop DMA for the isoch
 *		stream associated with t1394_idma_hdl.
 */
/* ARGSUSED */
void
t1394_stop_isoch_dma(t1394_handle_t t1394_hdl,
    t1394_isoch_dma_handle_t t1394_idma_hdl, uint_t flags)
{
	s1394_hal_t	*hal;
	int		result;

	TNF_PROBE_0_DEBUG(t1394_stop_isoch_dma_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_idma_hdl != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	HAL_CALL(hal).stop_isoch_dma(hal->halinfo.hal_private,
	    (void *)t1394_idma_hdl, &result);

	TNF_PROBE_0_DEBUG(t1394_stop_isoch_dma_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
}

/*
 * Function:    t1394_update_isoch_dma()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		t1394_idma_hdl		The IDMA "handle" returned by
 *					    t1394_alloc_isoch_dma()
 *		idma_updateinfo		This structure contains ixl command args
 *					    used when updating args in an
 *					    existing list of ixl commands with
 *					    args in a new list of ixl commands.
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	result			Used to pass more specific info back
 *					    to target
 *
 * Description:	t1394_update_isoch_dma() is used to alter an IXL program that
 *		has already been built (compiled) by t1394_alloc_isoch_dma().
 */
/* ARGSUSED */
int
t1394_update_isoch_dma(t1394_handle_t t1394_hdl,
    t1394_isoch_dma_handle_t t1394_idma_hdl,
    id1394_isoch_dma_updateinfo_t *idma_updateinfo, uint_t flags,
    int *result)
{
	s1394_hal_t	*hal;
	int		ret;

	TNF_PROBE_0_DEBUG(t1394_update_isoch_dma_enter,
	    S1394_TNF_SL_ISOCH_STACK, "");

	ASSERT(t1394_hdl != NULL);
	ASSERT(t1394_idma_hdl != NULL);
	ASSERT(idma_updateinfo != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	ret = HAL_CALL(hal).update_isoch_dma(hal->halinfo.hal_private,
	    (void *)t1394_idma_hdl, idma_updateinfo, flags, result);

	TNF_PROBE_0_DEBUG(t1394_update_isoch_dma_exit,
	    S1394_TNF_SL_ISOCH_STACK, "");
	return (ret);
}

/*
 * Function:    t1394_initiate_bus_reset()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	None
 *
 * Description:	t1394_initiate_bus_reset() determines whether the local
 *		device has a P1394A PHY and will support the arbitrated
 *		short bus reset. If not, it will initiate a normal bus reset.
 */
/* ARGSUSED */
void
t1394_initiate_bus_reset(t1394_handle_t t1394_hdl, uint_t flags)
{
	s1394_hal_t	*hal;
	int		ret;

	TNF_PROBE_0_DEBUG(t1394_initiate_bus_reset_enter,
	    S1394_TNF_SL_BR_STACK, "");

	ASSERT(t1394_hdl != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Reset the bus */
	if (hal->halinfo.phy == H1394_PHY_1394A) {
		ret = HAL_CALL(hal).short_bus_reset(hal->halinfo.hal_private);
		if (ret != DDI_SUCCESS) {
			TNF_PROBE_1(t1394_initiate_bus_reset_error,
			    S1394_TNF_SL_ERROR, "", tnf_string, msg,
			    "Error initiating short bus reset");
		}
	} else {
		ret = HAL_CALL(hal).bus_reset(hal->halinfo.hal_private);
		if (ret != DDI_SUCCESS) {
			TNF_PROBE_1(t1394_initiate_bus_reset_error,
			    S1394_TNF_SL_ERROR, "", tnf_string, msg,
			    "Error initiating bus reset");
		}
	}

	TNF_PROBE_0_DEBUG(t1394_initiate_bus_reset_exit,
	    S1394_TNF_SL_BR_STACK, "");
}

/*
 * Function:    t1394_get_topology_map()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		bus_generation		The current generation
 *		tm_length		The size of the tm_buffer given
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	tm_buffer		Filled in by the 1394 Software Framework
 *					    with the contents of the local
 *					    TOPOLOGY_MAP
 *
 * Description:	t1394_get_topology_map() returns the 1394 TOPLOGY_MAP.  See
 *		IEEE 1394-1995 Section 8.2.3.4.1 for format information.  This
 *		call can fail if there is a generation mismatch or the
 *		tm_buffer is too small to hold the TOPOLOGY_MAP.
 */
/* ARGSUSED */
int
t1394_get_topology_map(t1394_handle_t t1394_hdl, uint_t bus_generation,
    size_t tm_length, uint_t flags, uint32_t *tm_buffer)
{
	s1394_hal_t	*hal;
	uint32_t	*tm_ptr;
	uint_t		length;

	TNF_PROBE_0_DEBUG(t1394_get_topology_map_enter, S1394_TNF_SL_CSR_STACK,
	    "");

	ASSERT(t1394_hdl != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	/* Check the bus_generation for the Topology Map */
	if (bus_generation != hal->generation_count) {
		/* Unlock the topology tree */
		mutex_exit(&hal->topology_tree_mutex);
		TNF_PROBE_1(t1394_get_topology_map_error,
		    S1394_TNF_SL_CSR_ERROR, "", tnf_string, msg,
		    "Generation mismatch");
		TNF_PROBE_0_DEBUG(t1394_get_topology_map_exit,
		    S1394_TNF_SL_CSR_STACK, "");
		return (DDI_FAILURE);
	}

	tm_ptr	= (uint32_t *)hal->CSR_topology_map;
	length	= tm_ptr[0] >> 16;
	length  = length * 4;	/* Bytes instead of quadlets   */
	length  = length + 4;   /* don't forget the first quad */

	/* Check that the buffer is big enough */
	if (length > (uint_t)tm_length) {
		/* Unlock the topology tree */
		mutex_exit(&hal->topology_tree_mutex);
		TNF_PROBE_1(t1394_get_topology_map_error,
		    S1394_TNF_SL_CSR_ERROR, "", tnf_string, msg,
		    "Buffer size too small");
		TNF_PROBE_0_DEBUG(t1394_get_topology_map_exit,
		    S1394_TNF_SL_CSR_STACK, "");
		return (DDI_FAILURE);
	}

	/* Do the copy */
	bcopy(tm_ptr, tm_buffer, length);

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);
	TNF_PROBE_0_DEBUG(t1394_get_topology_map_exit, S1394_TNF_SL_CSR_STACK,
	    "");
	return (DDI_SUCCESS);
}

/*
 * Function:    t1394_CRC16()
 * Input(s):    d			The data to compute the CRC-16 for
 *		crc_length		The length into the data to compute for
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	CRC			The CRC-16 computed for the length
 *					    of data specified
 *
 * Description:	t1394_CRC16() implements ISO/IEC 13213:1994, ANSI/IEEE Std
 *		1212, 1994 - 8.1.5.
 */
/* ARGSUSED */
uint_t
t1394_CRC16(uint32_t *d, size_t crc_length, uint_t flags)
{
	/* Implements ISO/IEC 13213:1994,	*/
	/* ANSI/IEEE Std 1212, 1994 - 8.1.5	*/
	uint_t	ret;

	TNF_PROBE_0_DEBUG(t1394_CRC16_enter, S1394_TNF_SL_STACK, "");

	ret = s1394_CRC16((uint_t *)d, (uint_t)crc_length);

	TNF_PROBE_0_DEBUG(t1394_CRC16_exit, S1394_TNF_SL_STACK, "");
	return (ret);
}

/*
 * Function:    t1394_add_cfgrom_entry()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		cfgrom_entryinfo	This structure holds the cfgrom key,
 *					    buffer, and size
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	t1394_cfgrom_hdl	The ConfigROM "handle" used in
 *					    t1394_rem_cfgrom_entry()
 *		result			Used to pass more specific info back
 *					    to target
 *
 * Description:	t1394_add_cfgrom_entry() adds an entry to the local Config ROM,
 *		updating the directory entries as necessary.  This call could
 *		fail because there is no room for the new entry in Config ROM
 *		(T1394_ECFGROM_FULL), the key is invalid (T1394_EINVALID_PARAM),
 *		or it was called in interrupt context (T1394_EINVALID_CONTEXT).
 */
/* ARGSUSED */
int
t1394_add_cfgrom_entry(t1394_handle_t t1394_hdl,
    t1394_cfgrom_entryinfo_t *cfgrom_entryinfo, uint_t flags,
    t1394_cfgrom_handle_t *t1394_cfgrom_hdl, int *result)
{
	s1394_hal_t	*hal;
	s1394_target_t	*target;
	int		ret;
	uint_t		key;
	uint_t		size;
	uint32_t	*buffer;

	TNF_PROBE_0_DEBUG(t1394_add_cfgrom_entry_enter,
	    S1394_TNF_SL_CFGROM_STACK, "");

	ASSERT(t1394_hdl != NULL);

	target = (s1394_target_t *)t1394_hdl;

	key = cfgrom_entryinfo->ce_key;
	buffer = cfgrom_entryinfo->ce_buffer;
	size = (uint_t)cfgrom_entryinfo->ce_size;

	/* Check for a valid size */
	if (size == 0) {
		*result = T1394_EINVALID_PARAM;
		TNF_PROBE_1_DEBUG(t1394_add_cfgrom_entry_error,
		    S1394_TNF_SL_CFGROM_ERROR, "", tnf_string, msg,
		    "Invalid size of Config ROM buffer (== 0)");
		TNF_PROBE_0_DEBUG(t1394_add_cfgrom_entry_exit,
		    S1394_TNF_SL_CFGROM_STACK, "");
		return (DDI_FAILURE);
	}

	/* Check for a valid key type */
	if (((key << IEEE1212_KEY_VALUE_SHIFT) & IEEE1212_KEY_TYPE_MASK) == 0) {
		*result = T1394_EINVALID_PARAM;
		TNF_PROBE_1_DEBUG(t1394_add_cfgrom_entry_error,
		    S1394_TNF_SL_CFGROM_ERROR, "", tnf_string, msg,
		    "Invalid key_type in Config ROM key");
		TNF_PROBE_0_DEBUG(t1394_add_cfgrom_entry_exit,
		    S1394_TNF_SL_CFGROM_STACK, "");
		return (DDI_FAILURE);
	}

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	/* Is this on the interrupt stack? */
	if (servicing_interrupt()) {
		*result = T1394_EINVALID_CONTEXT;
		TNF_PROBE_0_DEBUG(t1394_add_cfgrom_entry_exit,
		    S1394_TNF_SL_CFGROM_STACK, "");
		return (DDI_FAILURE);
	}

	/* Lock the Config ROM buffer */
	mutex_enter(&hal->local_config_rom_mutex);

	ret = s1394_add_config_rom_entry(hal, key, buffer, size,
	    (void **)t1394_cfgrom_hdl, result);
	if (ret != DDI_SUCCESS) {
		if (*result == CMD1394_ERSRC_CONFLICT)
			*result = T1394_ECFGROM_FULL;
		mutex_exit(&hal->local_config_rom_mutex);

		TNF_PROBE_1(t1394_add_cfgrom_entry_error,
		    S1394_TNF_SL_CFGROM_ERROR, "", tnf_string, msg,
		    "Failed in s1394_add_cfgrom_entry()");
		TNF_PROBE_0_DEBUG(t1394_add_cfgrom_entry_exit,
		    "stacktrace 1394 s1394", "");
		return (ret);
	}

	/* Setup the timeout function */
	if (hal->config_rom_timer_set == B_FALSE) {
		hal->config_rom_timer_set = B_TRUE;
		mutex_exit(&hal->local_config_rom_mutex);
		hal->config_rom_timer =
		    timeout(s1394_update_config_rom_callback, hal,
			drv_usectohz(CONFIG_ROM_UPDATE_DELAY * 1000));
	} else {
		mutex_exit(&hal->local_config_rom_mutex);
	}

	TNF_PROBE_0_DEBUG(t1394_add_cfgrom_entry_exit,
	    S1394_TNF_SL_CFGROM_STACK, "");
	return (ret);
}

/*
 * Function:    t1394_rem_cfgrom_entry()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		flags			The flags parameter is unused (for now)
 *		t1394_cfgrom_hdl	The ConfigROM "handle" returned by
 *					    t1394_add_cfgrom_entry()
 *
 * Output(s):	result			Used to pass more specific info back
 *					    to target
 *
 * Description:	t1394_rem_cfgrom_entry() is used to remove a previously added
 *		Config ROM entry (indicated by t1394_cfgrom_hdl).
 */
/* ARGSUSED */
int
t1394_rem_cfgrom_entry(t1394_handle_t t1394_hdl, uint_t flags,
    t1394_cfgrom_handle_t *t1394_cfgrom_hdl, int *result)
{
	s1394_hal_t	*hal;
	s1394_target_t	*target;
	int		ret;

	TNF_PROBE_0_DEBUG(t1394_rem_cfgrom_entry_enter,
	    S1394_TNF_SL_CFGROM_STACK, "");

	ASSERT(t1394_hdl != NULL);

	target = (s1394_target_t *)t1394_hdl;

	/* Find the HAL this target resides on */
	hal = target->on_hal;

	/* Is this on the interrupt stack? */
	if (servicing_interrupt()) {
		*result = T1394_EINVALID_CONTEXT;
		TNF_PROBE_0_DEBUG(t1394_rem_cfgrom_entry_exit,
		    S1394_TNF_SL_CFGROM_STACK, "");
		return (DDI_FAILURE);
	}

	/* Lock the Config ROM buffer */
	mutex_enter(&hal->local_config_rom_mutex);

	ret = s1394_remove_config_rom_entry(hal, (void **)t1394_cfgrom_hdl,
	    result);
	if (ret != DDI_SUCCESS) {
		mutex_exit(&hal->local_config_rom_mutex);
		TNF_PROBE_1(t1394_rem_cfgrom_entry_error,
		    S1394_TNF_SL_CFGROM_ERROR, "", tnf_string, msg,
		    "Failed in s1394_remove_cfgrom_entry()");
		TNF_PROBE_0_DEBUG(t1394_rem_cfgrom_entry_exit,
		    "stacktrace 1394 s1394", "");
		return (ret);
	}

	/* Setup the timeout function */
	if (hal->config_rom_timer_set == B_FALSE) {
		hal->config_rom_timer_set = B_TRUE;
		mutex_exit(&hal->local_config_rom_mutex);
		hal->config_rom_timer =
		    timeout(s1394_update_config_rom_callback, hal,
			drv_usectohz(CONFIG_ROM_UPDATE_DELAY * 1000));
	} else {
		mutex_exit(&hal->local_config_rom_mutex);
	}

	TNF_PROBE_0_DEBUG(t1394_rem_cfgrom_entry_exit,
	    S1394_TNF_SL_CFGROM_STACK, "");
	return (ret);
}

/*
 * Function:    t1394_get_targetinfo()
 * Input(s):    t1394_hdl		The target "handle" returned by
 *					    t1394_attach()
 *		bus_generation		The current generation
 *		flags			The flags parameter is unused (for now)
 *
 * Output(s):	targetinfo		Structure containing max_payload,
 *					    max_speed, and target node ID.
 *
 * Description:	t1394_get_targetinfo() is used to retrieve information specific
 *		to a target device.  It will fail if the generation given
 *		does not match the current generation.
 */
/* ARGSUSED */
int
t1394_get_targetinfo(t1394_handle_t t1394_hdl, uint_t bus_generation,
    uint_t flags, t1394_targetinfo_t *targetinfo)
{
	s1394_hal_t	*hal;
	s1394_target_t	*target;
	uint_t		dev;
	uint_t		curr;
	uint_t		from_node;
	uint_t		to_node;

	TNF_PROBE_0_DEBUG(t1394_get_targetinfo_enter, S1394_TNF_SL_STACK, "");

	ASSERT(t1394_hdl != NULL);

	/* Find the HAL this target resides on */
	hal = ((s1394_target_t *)t1394_hdl)->on_hal;

	target = (s1394_target_t *)t1394_hdl;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	/* Check the bus_generation */
	if (bus_generation != hal->generation_count) {
		/* Unlock the topology tree */
		mutex_exit(&hal->topology_tree_mutex);
		TNF_PROBE_3(t1394_get_targetinfo_error, S1394_TNF_SL_STACK, "",
		    tnf_string, msg, "Generation mismatch",
		    tnf_uint, gen, bus_generation,
		    tnf_uint, current_gen, hal->generation_count);
		return (DDI_FAILURE);
	}

	rw_enter(&hal->target_list_rwlock, RW_READER);
	/*
	 * If there is no node, report T1394_INVALID_NODEID for target_nodeID;
	 * current_max_speed and current_max_payload are undefined for this
	 * case.
	 */
	if (((target->target_state & S1394_TARG_GONE) != 0) ||
	    (target->on_node == NULL)) {
		targetinfo->target_nodeID = T1394_INVALID_NODEID;
		TNF_PROBE_1_DEBUG(t1394_get_targetinfo_exit,
		    S1394_TNF_SL_STACK, "", tnf_string, msg, "No device");
	} else {
		targetinfo->target_nodeID =
		    (target->on_hal->node_id & IEEE1394_BUS_NUM_MASK) |
		    target->on_node->node_num;

		from_node = (target->on_hal->node_id) & IEEE1394_NODE_NUM_MASK;
		to_node = target->on_node->node_num;

		targetinfo->current_max_speed = (uint_t)s1394_speed_map_get(
		    hal, from_node, to_node);

		/* Get current_max_payload */
		s1394_get_maxpayload(target, &dev, &curr);
		targetinfo->current_max_payload	= curr;

		TNF_PROBE_3_DEBUG(t1394_get_targetinfo_exit,
		    S1394_TNF_SL_STACK, "",
		    tnf_uint, payload, targetinfo->current_max_payload,
		    tnf_uint, speed, targetinfo->current_max_speed,
		    tnf_uint, nodeid, targetinfo->target_nodeID);
	}

	rw_exit(&hal->target_list_rwlock);
	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);
	return (DDI_SUCCESS);
}
