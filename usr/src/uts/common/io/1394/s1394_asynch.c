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
 * s1394_asynch.c
 *    1394 Services Layer Asynchronous Communications Routines
 *    These routines handle all of the tasks relating to asynch commands
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>
#include <sys/1394/ieee1212.h>

static void s1394_handle_lock(cmd1394_cmd_t *cmd);

static cmd1394_cmd_t *s1394_pending_q_remove(s1394_hal_t *hal);

static boolean_t s1394_process_pending_q(s1394_hal_t *hal);

static boolean_t s1394_pending_q_helper(s1394_hal_t *hal, cmd1394_cmd_t *cmd);

static int s1394_process_split_lock(cmd1394_cmd_t *cmd,
    cmd1394_cmd_t *target_cmd);

static int s1394_finish_split_lock(cmd1394_cmd_t *cmd,
    cmd1394_cmd_t *target_cmd);

/*
 * s1394_alloc_cmd()
 *    is used to allocate a command for a target or for a HAL.
 */
int
s1394_alloc_cmd(s1394_hal_t *hal, uint_t flags, cmd1394_cmd_t **cmdp)
{
	s1394_cmd_priv_t *s_priv;
	void		 *hal_overhead;
	uint_t		 cmd_size;
	int		 alloc_sleep;

	alloc_sleep = (flags & T1394_ALLOC_CMD_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	if ((alloc_sleep == KM_SLEEP) &&
	    (servicing_interrupt())) {
		ASSERT(alloc_sleep != KM_SLEEP);	/* fail */
		return (DDI_FAILURE);
	}

	/* either FCP command or response, but not both */
	if ((flags &
	    (T1394_ALLOC_CMD_FCP_COMMAND | T1394_ALLOC_CMD_FCP_RESPONSE)) ==
	    (T1394_ALLOC_CMD_FCP_COMMAND | T1394_ALLOC_CMD_FCP_RESPONSE)) {
		return (DDI_FAILURE);
	}

	*cmdp = kmem_cache_alloc(hal->hal_kmem_cachep, alloc_sleep);
	if (*cmdp == NULL) {
		return (DDI_FAILURE);
	}
	cmd_size = sizeof (cmd1394_cmd_t) +
	    sizeof (s1394_cmd_priv_t) + hal->halinfo.hal_overhead;
	bzero((void *)*cmdp, cmd_size);

	(*cmdp)->cmd_version = T1394_VERSION_V1;
	(*cmdp)->cmd_result = CMD1394_NOSTATUS;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(*cmdp);

	/* Set extension type */
	if (flags & T1394_ALLOC_CMD_FCP_COMMAND) {
		s1394_fa_init_cmd(s_priv, S1394_FA_TYPE_FCP_CTL);
	} else if (flags & T1394_ALLOC_CMD_FCP_RESPONSE) {
		s1394_fa_init_cmd(s_priv, S1394_FA_TYPE_FCP_TGT);
	}

	/* Set up the hal_overhead ptr in the hal_cmd_private */
	hal_overhead = (uchar_t *)s_priv + sizeof (s1394_cmd_priv_t);
	s_priv->hal_cmd_private.hal_overhead = (void *)hal_overhead;

	/* kstats - number of cmd allocs */
	hal->hal_kstats->cmd_alloc++;

	return (DDI_SUCCESS);
}

/*
 * s1394_free_cmd()
 *    is used to free a command that had been previously allocated by
 *    s1394_alloc_cmd().
 */
int
s1394_free_cmd(s1394_hal_t *hal, cmd1394_cmd_t **cmdp)
{
	s1394_cmd_priv_t *s_priv;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(*cmdp);

	/* Check that command isn't in use */
	if (s_priv->cmd_in_use == B_TRUE) {
		ASSERT(s_priv->cmd_in_use == B_FALSE);
		return (DDI_FAILURE);
	}

	/* kstats - number of cmd allocs */
	kmem_cache_free(hal->hal_kmem_cachep, *cmdp);

	/* Command pointer is set to NULL before returning */
	*cmdp = NULL;

	/* kstats - number of cmd frees */
	hal->hal_kstats->cmd_free++;

	return (DDI_SUCCESS);
}

/*
 * s1394_xfer_asynch_command()
 *    is used to send an asynch command down to the HAL.  Based upon the type
 *    of command that is being sent, the appropriate HAL function is called.
 *    Command failures are handled be returning an error and/or shutting down
 *    the HAL, depending on the severity of the error.
 */
int
s1394_xfer_asynch_command(s1394_hal_t *hal, cmd1394_cmd_t *cmd, int *err)
{
	s1394_cmd_priv_t  *s_priv;
	h1394_cmd_priv_t  *h_priv;
	s1394_hal_state_t state;
	dev_info_t	  *dip;
	int		  result_from_hal;
	int		  ret;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	mutex_enter(&hal->topology_tree_mutex);
	state = hal->hal_state;
	if (((state != S1394_HAL_NORMAL) && (state != S1394_HAL_RESET)) ||
	    (hal->disable_requests_bit == 1)) {
		*err = s1394_HAL_asynch_error(hal, cmd, state);
		mutex_exit(&hal->topology_tree_mutex);
		return (DDI_FAILURE);
	}
	mutex_exit(&hal->topology_tree_mutex);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Get a pointer to the HAL private struct */
	h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;

	/* kstats - number of AT requests sent */
	switch (cmd->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
		hal->hal_kstats->atreq_quad_rd++;
		break;

	case CMD1394_ASYNCH_RD_BLOCK:
		hal->hal_kstats->atreq_blk_rd++;
		break;

	case CMD1394_ASYNCH_WR_QUAD:
		hal->hal_kstats->atreq_quad_wr++;
		break;

	case CMD1394_ASYNCH_WR_BLOCK:
		hal->hal_kstats->atreq_blk_wr++;
		hal->hal_kstats->atreq_blk_wr_size += h_priv->mblk.length;
		break;

	case CMD1394_ASYNCH_LOCK_32:
		hal->hal_kstats->atreq_lock32++;
		break;

	case CMD1394_ASYNCH_LOCK_64:
		hal->hal_kstats->atreq_lock64++;
		break;
	}

	switch (s_priv->cmd_priv_xfer_type) {
	/* Call the HAL's read entry point */
	case S1394_CMD_READ:
		ret = HAL_CALL(hal).read(hal->halinfo.hal_private,
		    (cmd1394_cmd_t *)cmd,
		    (h1394_cmd_priv_t *)&s_priv->hal_cmd_private,
		    &result_from_hal);
		break;

	/* Call the HAL's write entry point */
	case S1394_CMD_WRITE:
		ret = HAL_CALL(hal).write(hal->halinfo.hal_private,
		    (cmd1394_cmd_t *)cmd,
		    (h1394_cmd_priv_t *)&s_priv->hal_cmd_private,
		    &result_from_hal);
		break;

	/* Call the HAL's lock entry point */
	case S1394_CMD_LOCK:
		ret = HAL_CALL(hal).lock(hal->halinfo.hal_private,
		    (cmd1394_cmd_t *)cmd,
		    (h1394_cmd_priv_t *)&s_priv->hal_cmd_private,
		    &result_from_hal);
		break;

	default:
		*err = CMD1394_EUNKNOWN_ERROR;

		return (DDI_FAILURE);
	}

	if (ret == DDI_FAILURE) {
		switch (result_from_hal) {
		case H1394_STATUS_EMPTY_TLABEL:
			/* Out of TLABELs - Unable to send AT req */
			*err = CMD1394_ENO_ATREQ;
			break;

		case H1394_STATUS_INVALID_BUSGEN:
			/* Out of TLABELs - Unable to send AT req */
			*err = CMD1394_ESTALE_GENERATION;
			break;

		case H1394_STATUS_NOMORE_SPACE:
			/* No more space on HAL's HW queue */
			*err = CMD1394_ENO_ATREQ;
			break;

		case H1394_STATUS_INTERNAL_ERROR:
			dip = hal->halinfo.dip;

			/* An unexpected error in the HAL */
			cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
			    ddi_node_name(dip), ddi_get_instance(dip));

			/* Disable the HAL */
			s1394_hal_shutdown(hal, B_TRUE);

			*err = CMD1394_EFATAL_ERROR;
			break;

		default:
			dip = hal->halinfo.dip;

			/* An unexpected error in the HAL */
			cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
			    ddi_node_name(dip), ddi_get_instance(dip));

			/* Disable the HAL */
			s1394_hal_shutdown(hal, B_TRUE);

			*err = CMD1394_EFATAL_ERROR;
			break;
		}

		return (DDI_FAILURE);
	}

	/* No errors, return success */
	*err = CMD1394_NOSTATUS;

	return (DDI_SUCCESS);
}

/*
 * s1394_setup_asynch_command()
 *    is used to setup an asynch command to be sent down to the HAL and out
 *    onto the bus.  This function handles setting up the destination address
 *    (if necessary), speed, max_payload, putting the command onto the
 *    outstanding Q list, and any other things that must be done prior to
 *    calling the HAL.
 */
int
s1394_setup_asynch_command(s1394_hal_t *hal, s1394_target_t *target,
    cmd1394_cmd_t *cmd, uint32_t xfer_type, int *err)
{
	s1394_cmd_priv_t  *s_priv;
	h1394_cmd_priv_t  *h_priv;
	uint64_t	  node;
	uint32_t	  from_node;
	uint32_t	  to_node;
	uint32_t	  bus_capabilities;
	uint_t		  current_max_payload;
	uint_t		  max_rec;
	uint_t		  max_blk;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	switch (cmd->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
	case CMD1394_ASYNCH_WR_QUAD:
	case CMD1394_ASYNCH_RD_BLOCK:
	case CMD1394_ASYNCH_WR_BLOCK:
	case CMD1394_ASYNCH_LOCK_32:
	case CMD1394_ASYNCH_LOCK_64:
		break;

	default:
		*err = CMD1394_EINVALID_COMMAND;
		return (DDI_FAILURE);
	}

	/* Check for potential address roll-over */
	if (s1394_address_rollover(cmd) != B_FALSE) {
		*err = CMD1394_EADDRESS_ERROR;
		return (DDI_FAILURE);
	}

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Set up who sent command on which hal */
	s_priv->sent_by_target	= (s1394_target_t *)target;
	s_priv->sent_on_hal	= (s1394_hal_t *)hal;

	/* Set up command transfer type */
	s_priv->cmd_priv_xfer_type = xfer_type;

	if (cmd->cmd_options & CMD1394_OVERRIDE_ADDR) {
		/* Compare the current generation from the HAL struct */
		/* to the one given by the target */

		/* Speed is to be filled in from speed map */
		from_node = IEEE1394_NODE_NUM(hal->node_id);
		to_node	  = IEEE1394_ADDR_PHY_ID(cmd->cmd_addr);

		if (cmd->bus_generation != hal->generation_count) {
			*err = CMD1394_ESTALE_GENERATION;
			return (DDI_FAILURE);
		}

	} else {
		/* Set the generation */
		cmd->bus_generation = hal->generation_count;

		/* If not OVERRIDE_ADDR, then target may not be NULL */
		ASSERT(target != NULL);

		rw_enter(&hal->target_list_rwlock, RW_READER);

		if ((target->target_state & S1394_TARG_GONE) != 0 ||
		    target->on_node == NULL) {
			rw_exit(&hal->target_list_rwlock);
			*err = CMD1394_EDEVICE_REMOVED;
			return (DDI_FAILURE);
		}

		ASSERT((target->target_state & S1394_TARG_GONE) == 0);
		node = target->on_node->node_num;
		rw_exit(&hal->target_list_rwlock);

		/* Mask in the top 16-bits */
		cmd->cmd_addr = (cmd->cmd_addr & IEEE1394_ADDR_OFFSET_MASK);
		cmd->cmd_addr = (cmd->cmd_addr |
		    (node << IEEE1394_ADDR_PHY_ID_SHIFT));
		cmd->cmd_addr = (cmd->cmd_addr | IEEE1394_ADDR_BUS_ID_MASK);

		/* Speed is to be filled in from speed map */
		from_node = IEEE1394_NODE_NUM(hal->node_id);
		to_node = (uint32_t)node;
	}

	/* Get a pointer to the HAL private struct */
	h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;

	/* Copy the generation into the HAL's private field */
	h_priv->bus_generation = cmd->bus_generation;

	/* Fill in the nodeID */
	cmd->nodeID = (cmd->cmd_addr & IEEE1394_ADDR_NODE_ID_MASK) >>
	    IEEE1394_ADDR_NODE_ID_SHIFT;

	if (cmd->cmd_options & CMD1394_OVERRIDE_SPEED) {
		if (cmd->cmd_speed > IEEE1394_S400) {
			*err = CMD1394_EINVALID_COMMAND;
			return (DDI_FAILURE);

		} else {
			s_priv->hal_cmd_private.speed = (int)cmd->cmd_speed;
		}

	} else {
		/* Speed is to be filled in from speed map */
		s_priv->hal_cmd_private.speed = (int)s1394_speed_map_get(hal,
		    from_node, to_node);
	}

	/* Is it a block request? */
	if ((cmd->cmd_type == CMD1394_ASYNCH_RD_BLOCK) ||
	    (cmd->cmd_type == CMD1394_ASYNCH_WR_BLOCK)) {

		if (cmd->cmd_u.b.data_block == NULL) {
			*err = CMD1394_ENULL_MBLK;
			return (DDI_FAILURE);
		}

		/* Also need to check for MBLK_TOO_SMALL */
		if (s1394_mblk_too_small(cmd) != B_FALSE) {
			*err = CMD1394_EMBLK_TOO_SMALL;
			return (DDI_FAILURE);
		}

		/* Initialize bytes_transferred to zero */
		cmd->cmd_u.b.bytes_transferred = 0;

		/* Handle the MAX_PAYLOAD size */
		if (cmd->cmd_options & CMD1394_OVERRIDE_ADDR) {

			current_max_payload = 512 <<
			    (s_priv->hal_cmd_private.speed);
			if (hal->topology_tree[to_node].cfgrom) {
				bus_capabilities =
				    hal->topology_tree[to_node].cfgrom[
					IEEE1212_NODE_CAP_QUAD];
				max_rec = (bus_capabilities &
				    IEEE1394_BIB_MAXREC_MASK) >>
				    IEEE1394_BIB_MAXREC_SHIFT;
			} else {
				max_rec = 0;
			}

			if ((max_rec > 0) && (max_rec < 14)) {
				max_blk = 1 << (max_rec + 1);

			} else {
				/* These are either unspecified or reserved */
				max_blk = 4;
			}
			if (max_blk < current_max_payload)
				current_max_payload = max_blk;

		} else {
			rw_enter(&hal->target_list_rwlock, RW_READER);
			current_max_payload = target->current_max_payload;
			rw_exit(&hal->target_list_rwlock);
		}

		if (cmd->cmd_options & CMD1394_OVERRIDE_MAX_PAYLOAD) {
			if (current_max_payload > cmd->cmd_u.b.max_payload)
				current_max_payload = cmd->cmd_u.b.max_payload;
		}

		h_priv->mblk.curr_mblk = cmd->cmd_u.b.data_block;

		if (cmd->cmd_type == CMD1394_ASYNCH_WR_BLOCK) {
			h_priv->mblk.curr_offset =
			    cmd->cmd_u.b.data_block->b_rptr;
		} else {
			h_priv->mblk.curr_offset =
			    cmd->cmd_u.b.data_block->b_wptr;
		}

		if (cmd->cmd_u.b.blk_length > current_max_payload) {
			h_priv->mblk.length = current_max_payload;
			s_priv->data_remaining = cmd->cmd_u.b.blk_length;

		} else {
			h_priv->mblk.length = cmd->cmd_u.b.blk_length;
			s_priv->data_remaining = cmd->cmd_u.b.blk_length;
		}
	}

	/* Mark command as being used */
	s_priv->cmd_in_use = B_TRUE;

	/* Put command on the HAL's outstanding request Q */
	s1394_insert_q_asynch_cmd(hal, cmd);

	return (DDI_SUCCESS);
}

/*
 * s1394_insert_q_asynch_cmd()
 *    is used to insert a given command structure onto a HAL's outstanding
 *    asynch queue.
 */
void
s1394_insert_q_asynch_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd)
{
	s1394_cmd_priv_t *s_priv;
	s1394_cmd_priv_t *c_priv;
	cmd1394_cmd_t	 *temp_cmd;

	mutex_enter(&hal->outstanding_q_mutex);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Is the outstanding request queue empty? */
	if ((hal->outstanding_q_head == NULL) &&
	    (hal->outstanding_q_tail == NULL)) {

		hal->outstanding_q_head = (cmd1394_cmd_t *)cmd;
		hal->outstanding_q_tail = (cmd1394_cmd_t *)cmd;
		s_priv->cmd_priv_next = (cmd1394_cmd_t *)NULL;
		s_priv->cmd_priv_prev = (cmd1394_cmd_t *)NULL;

	} else {
		s_priv->cmd_priv_next = hal->outstanding_q_head;
		s_priv->cmd_priv_prev = (cmd1394_cmd_t *)NULL;

		temp_cmd = (cmd1394_cmd_t *)hal->outstanding_q_head;
		c_priv = (s1394_cmd_priv_t *)((uchar_t *)temp_cmd +
		    sizeof (cmd1394_cmd_t));
		c_priv->cmd_priv_prev = (cmd1394_cmd_t *)cmd;

		hal->outstanding_q_head = (cmd1394_cmd_t *)cmd;
	}

	mutex_exit(&hal->outstanding_q_mutex);
}

/*
 * s1394_remove_q_asynch_cmd()
 *    is used to remove a given command structure from a HAL's outstanding
 *    asynch queue.
 */
void
s1394_remove_q_asynch_cmd(s1394_hal_t *hal, cmd1394_cmd_t *cmd)
{
	s1394_cmd_priv_t *s_priv;
	s1394_cmd_priv_t *c_priv;
	cmd1394_cmd_t	 *prev_cmd;
	cmd1394_cmd_t	 *next_cmd;

	mutex_enter(&hal->outstanding_q_mutex);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	prev_cmd = (cmd1394_cmd_t *)s_priv->cmd_priv_prev;
	next_cmd = (cmd1394_cmd_t *)s_priv->cmd_priv_next;

	s_priv->cmd_priv_prev = (cmd1394_cmd_t *)NULL;
	s_priv->cmd_priv_next = (cmd1394_cmd_t *)NULL;

	if (prev_cmd != NULL) {
		c_priv = (s1394_cmd_priv_t *)((uchar_t *)prev_cmd +
		    sizeof (cmd1394_cmd_t));
		c_priv->cmd_priv_next = (cmd1394_cmd_t *)next_cmd;

	} else {
		if (hal->outstanding_q_head == (cmd1394_cmd_t *)cmd)
			hal->outstanding_q_head = (cmd1394_cmd_t *)next_cmd;
	}

	if (next_cmd != NULL) {
		c_priv = (s1394_cmd_priv_t *)((uchar_t *)next_cmd +
		    sizeof (cmd1394_cmd_t));
		c_priv->cmd_priv_prev = (cmd1394_cmd_t *)prev_cmd;

	} else {
		if (hal->outstanding_q_tail == (cmd1394_cmd_t *)cmd)
			hal->outstanding_q_tail = (cmd1394_cmd_t *)prev_cmd;
	}

	mutex_exit(&hal->outstanding_q_mutex);
}

/*
 * s1394_atreq_cmd_complete()
 *    is called by h1394_cmd_is_complete() when an AT request has completed.
 *    Based upon a command's completion status, s1394_atreq_cmd_complete()
 *    determines whether to call the target (or unblock), put the command onto
 *    the pending Q to be sent out later, or to resend the command
 *    (multi-part command).
 */
void
s1394_atreq_cmd_complete(s1394_hal_t *hal, cmd1394_cmd_t *req, int status)
{
	s1394_cmd_priv_t *s_priv;
	h1394_cmd_priv_t *h_priv;
	dev_info_t	 *dip;
	int		 ret;
	int		 cmd_result;
	int		 err;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(req);

	/* If not an ack_complete... */
	if (status != H1394_CMD_SUCCESS) {
		/* kstats - number of failure AT responses */
		switch (req->cmd_type) {
		case CMD1394_ASYNCH_RD_QUAD:
			hal->hal_kstats->atresp_quad_rd_fail++;
			break;

		case CMD1394_ASYNCH_RD_BLOCK:
			hal->hal_kstats->atresp_blk_rd_fail++;
			break;

		case CMD1394_ASYNCH_WR_QUAD:
			hal->hal_kstats->atresp_quad_wr_fail++;
			break;

		case CMD1394_ASYNCH_WR_BLOCK:
			hal->hal_kstats->atresp_blk_wr_fail++;
			break;

		case CMD1394_ASYNCH_LOCK_32:
			hal->hal_kstats->atresp_lock32_fail++;
			break;

		case CMD1394_ASYNCH_LOCK_64:
			hal->hal_kstats->atresp_lock64_fail++;
			break;
		}


		switch (status) {
		/* evt_missing_ack */
		case H1394_CMD_ETIMEOUT:
			cmd_result = CMD1394_ETIMEOUT;
			break;

		/* evt_flushed */
		case H1394_CMD_EBUSRESET:
			/* Move request to pending Q if cancel on */
			/* reset is not set */
			if (req->cmd_options & CMD1394_CANCEL_ON_BUS_RESET) {
				cmd_result = CMD1394_EBUSRESET;
				break;
			}
			s1394_remove_q_asynch_cmd(hal, req);
			s1394_pending_q_insert(hal, req, S1394_PENDING_Q_REAR);
			return;

		/* ack_busy_X */
		/* ack_busy_A */
		/* ack_busy_B */
		case H1394_CMD_EDEVICE_BUSY:
			cmd_result = CMD1394_EDEVICE_BUSY;
			break;

		/* ack_data_error */
		case H1394_CMD_EDATA_ERROR:
			cmd_result = CMD1394_EDATA_ERROR;
			break;

		/* ack_type_error */
		case H1394_CMD_ETYPE_ERROR:
			cmd_result = CMD1394_ETYPE_ERROR;
			break;

		/* resp_address_error */
		/* ack_address_error */
		case H1394_CMD_EADDR_ERROR:
			cmd_result = CMD1394_EADDRESS_ERROR;
			break;

		/* resp_conflict_error */
		/* ack_conflict_error */
		case H1394_CMD_ERSRC_CONFLICT:
			cmd_result = CMD1394_ERSRC_CONFLICT;
			break;

		/* ack_tardy */
		case H1394_CMD_EDEVICE_POWERUP:
			cmd_result = CMD1394_EDEVICE_BUSY;
			break;

		/* device errors (bad tcodes, ACKs, etc...) */
		case H1394_CMD_EDEVICE_ERROR:
			cmd_result = CMD1394_EDEVICE_ERROR;
			break;

		/* Unknown error type */
		case H1394_CMD_EUNKNOWN_ERROR:
			cmd_result = CMD1394_EUNKNOWN_ERROR;
			break;

		/* Unrecognized error */
		default:
			dip = hal->halinfo.dip;

			/* An unexpected error in the HAL */
			cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
			    ddi_node_name(dip), ddi_get_instance(dip));

			/* Disable the HAL */
			s1394_hal_shutdown(hal, B_TRUE);

			return;
		}

		/* Remove command from the HAL's outstanding request Q */
		s1394_remove_q_asynch_cmd(hal, req);

		s_priv->cmd_in_use = B_FALSE;

		req->cmd_result = cmd_result;

		/* Is this a blocking command? */
		if (req->cmd_options & CMD1394_BLOCKING) {
			/* Unblock the waiting command */
			mutex_enter(&s_priv->blocking_mutex);
			s_priv->blocking_flag = B_TRUE;
			cv_signal(&s_priv->blocking_cv);
			mutex_exit(&s_priv->blocking_mutex);

			return;
		}

		/* Call the target's completion_callback() */
		if (req->completion_callback != NULL) {
			req->completion_callback(req);
		}

		return;
	}

	/* Successful unless otherwise modified */
	err = CMD1394_CMDSUCCESS;

	if ((req->cmd_type == CMD1394_ASYNCH_RD_BLOCK) ||
	    (req->cmd_type == CMD1394_ASYNCH_WR_BLOCK)) {

		/* Get a pointer to the HAL private struct */
		h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;

		/* Update data_remaining */
		s_priv->data_remaining -= h_priv->mblk.length;

		/* Increment bytes_transferred */
		req->cmd_u.b.bytes_transferred += h_priv->mblk.length;

		if (req->cmd_type == CMD1394_ASYNCH_RD_BLOCK)
			hal->hal_kstats->atreq_blk_rd_size +=
			    h_priv->mblk.length;

		/* Is there still more to send? */
		if (s_priv->data_remaining > 0) {

			/* Setup the new mblk and offset */
			h_priv->mblk.curr_mblk = h_priv->mblk.next_mblk;
			h_priv->mblk.curr_offset = h_priv->mblk.next_offset;

			/* Update destination address */
			if (!(req->cmd_options &
			    CMD1394_DISABLE_ADDR_INCREMENT)) {
				req->cmd_addr += h_priv->mblk.length;
			}

			/*
			 * Use the current MAX_PAYLOAD size.  This value
			 * doesn't need to be recalculated because we must
			 * be in the same generation on the bus, else we
			 * would have seen a bus reset error.
			 */
			if (s_priv->data_remaining < h_priv->mblk.length) {
				h_priv->mblk.length = s_priv->data_remaining;
			}

			/* Send command out again */
			ret = s1394_xfer_asynch_command(hal, req, &err);

			if (ret == DDI_SUCCESS) {
				return;

			} else if (err == CMD1394_ESTALE_GENERATION) {
				/* Remove cmd from outstanding request Q */
				s1394_remove_q_asynch_cmd(hal, req);
				s1394_pending_q_insert(hal, req,
				    S1394_PENDING_Q_REAR);

				return;
			}
		}
	}

	/* Remove command from the HAL's outstanding request Q */
	s1394_remove_q_asynch_cmd(hal, req);

	s_priv->cmd_in_use = B_FALSE;

	/* Set status */
	req->cmd_result = err;

	/* Is this a blocking command? */
	if (req->cmd_options & CMD1394_BLOCKING) {
		/* Unblock the waiting command */
		mutex_enter(&s_priv->blocking_mutex);
		s_priv->blocking_flag = B_TRUE;
		cv_signal(&s_priv->blocking_cv);
		mutex_exit(&s_priv->blocking_mutex);

		return;
	}

	/* Set status and call completion_callback() */
	if (req->completion_callback != NULL) {

		req->completion_callback(req);

		return;
	}
}

/*
 * s1394_atresp_cmd_complete()
 *    is similar to s1394_atreq_cmd_complete(). It is also called by
 *    h1394_cmd_is_complete(), but when an AT response has completed.
 *    Again, based upon the command's completion status,
 *    s1394_atresp_cmd_complete() determines whether to call the target or
 *    to simply cleanup the command and return.
 */
void
s1394_atresp_cmd_complete(s1394_hal_t *hal, cmd1394_cmd_t *resp, int status)
{
	s1394_cmd_priv_t *s_priv;
	h1394_cmd_priv_t *h_priv;
	dev_info_t	 *dip;
	boolean_t	 valid_addr_blk;
	int		 target_status;

	target_status = CMD1394_CMDSUCCESS;

	/* If not an ack_complete */
	if (status != H1394_CMD_SUCCESS) {
		switch (status) {
		/* evt_missing_ack */
		case H1394_CMD_ETIMEOUT:
			target_status = CMD1394_ETIMEOUT;
			break;

		/* evt_flushed */
		case H1394_CMD_EBUSRESET:
			target_status = CMD1394_EBUSRESET;
			break;

		/* ack_busy_X */
		/* ack_busy_A */
		/* ack_busy_B */
		case H1394_CMD_EDEVICE_BUSY:
			target_status = CMD1394_EDEVICE_BUSY;
			break;

		/* ack_data_error */
		case H1394_CMD_EDATA_ERROR:
			target_status = CMD1394_EDATA_ERROR;
			break;

		/* ack_type_error */
		case H1394_CMD_ETYPE_ERROR:
			target_status = CMD1394_ETYPE_ERROR;
			break;

		/* ack_address_error */
		case H1394_CMD_EADDR_ERROR:
			target_status = CMD1394_EADDRESS_ERROR;
			break;

		/* ack_conflict_error */
		case H1394_CMD_ERSRC_CONFLICT:
			target_status = CMD1394_ERSRC_CONFLICT;
			break;

		/* ack_tardy */
		case H1394_CMD_EDEVICE_POWERUP:
			target_status = CMD1394_EDEVICE_BUSY;
			break;

		/* device errors (bad tcodes, ACKs, etc...) */
		case H1394_CMD_EDEVICE_ERROR:
			target_status = CMD1394_EDEVICE_ERROR;
			break;

		/* Unknown error type */
		case H1394_CMD_EUNKNOWN_ERROR:
			target_status = CMD1394_EUNKNOWN_ERROR;
			break;

		/* Unrecognized error */
		default:
			dip = hal->halinfo.dip;

			/* An unexpected error in the HAL */
			cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
			    ddi_node_name(dip), ddi_get_instance(dip));

			/* Disable the HAL */
			s1394_hal_shutdown(hal, B_TRUE);

			return;
		}
	}

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(resp);

	/* Get a pointer to the HAL private struct */
	h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;

	valid_addr_blk = s_priv->arreq_valid_addr;

	if (valid_addr_blk == B_TRUE) {
		/* Set the command status */
		resp->cmd_result = target_status;

		switch (s_priv->cmd_priv_xfer_type) {
		case S1394_CMD_READ:
		case S1394_CMD_WRITE:
		case S1394_CMD_LOCK:
			if (resp->completion_callback != NULL) {
				resp->completion_callback(resp);
			}
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
	}

	/* Free the command - Pass it back to the HAL */
	HAL_CALL(hal).response_complete(hal->halinfo.hal_private, resp, h_priv);
}

/*
 * s1394_send_response()
 *    is used to send a response to an AR request.  Depending on whether the
 *    request was a broadcast request, a write to posted write address space,
 *    or some other request, either a response packet is sent, or the command
 *    is returned to the HAL.  A return value of DDI_SUCCESS means that the
 *    command has been handled correctly.  It was either successfully sent to
 *    the HAL, or, if it was posted_write of broadcast, it was freed up.  A
 *    return value of DDI_FAILURE indicates either a serious error, in which
 *    case the HAL is shutdown, or a failure returned by the HAL, in which
 *    case the command is freed up and notice of the failure is returned.
 */
int
s1394_send_response(s1394_hal_t *hal, cmd1394_cmd_t *resp)
{
	s1394_cmd_priv_t *s_priv;
	h1394_cmd_priv_t *h_priv;
	dev_info_t	 *dip;
	int		 ret;
	int		 result;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(resp);

	/* Get a pointer to the HAL private struct */
	h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;

	/*
	 * If request was broadcast or a write request to a posted write
	 * address, don't send a response
	 */
	if ((resp->broadcast == 1) || ((s_priv->posted_write == B_TRUE) &&
	    ((resp->cmd_result == CMD1394_ASYNCH_WR_QUAD) ||
	    (resp->cmd_result == CMD1394_ASYNCH_WR_BLOCK)))) {

		/* Free the command - Pass it back to the HAL */
		HAL_CALL(hal).response_complete(hal->halinfo.hal_private,
		    resp, h_priv);

		return (DDI_SUCCESS);
	}

	/* kstats - number of failure responses sent */
	if (resp->cmd_result != IEEE1394_RESP_COMPLETE) {
		switch (resp->cmd_type) {
		case CMD1394_ASYNCH_RD_QUAD:
			hal->hal_kstats->arresp_quad_rd_fail++;
			break;

		case CMD1394_ASYNCH_RD_BLOCK:
			hal->hal_kstats->arresp_blk_rd_fail++;
			break;

		case CMD1394_ASYNCH_WR_QUAD:
			hal->hal_kstats->arresp_quad_wr_fail++;
			break;

		case CMD1394_ASYNCH_WR_BLOCK:
			hal->hal_kstats->arresp_blk_wr_fail++;
			break;

		case CMD1394_ASYNCH_LOCK_32:
			hal->hal_kstats->arresp_lock32_fail++;
			break;

		case CMD1394_ASYNCH_LOCK_64:
			hal->hal_kstats->arresp_lock64_fail++;
			break;
		}
	} else {
		if (resp->cmd_type == CMD1394_ASYNCH_RD_BLOCK)
			hal->hal_kstats->arreq_blk_rd_size +=
			    resp->cmd_u.b.blk_length;
	}

	if (resp->cmd_type == CMD1394_ASYNCH_RD_BLOCK) {
		h_priv->mblk.curr_mblk = resp->cmd_u.b.data_block;
		h_priv->mblk.curr_offset = resp->cmd_u.b.data_block->b_rptr;
		h_priv->mblk.length = resp->cmd_u.b.blk_length;
	}

	switch (s_priv->cmd_priv_xfer_type) {
	case S1394_CMD_READ:
		ret = HAL_CALL(hal).read_response(hal->halinfo.hal_private,
		    resp, h_priv, &result);
		break;

	case S1394_CMD_WRITE:
		ret = HAL_CALL(hal).write_response(hal->halinfo.hal_private,
		    resp, h_priv, &result);
		break;

	case S1394_CMD_LOCK:
		ret = HAL_CALL(hal).lock_response(hal->halinfo.hal_private,
		    resp, h_priv, &result);
		break;

	default:
		dip = hal->halinfo.dip;

		/* An unexpected error in the HAL */
		cmn_err(CE_WARN, HALT_ERROR_MESSAGE,
		    ddi_node_name(dip), ddi_get_instance(dip));

		/* Disable the HAL */
		s1394_hal_shutdown(hal, B_TRUE);

		return (DDI_FAILURE);
	}

	/* Unable to send a response */
	if (ret != DDI_SUCCESS) {
		/* Free the command - Pass it back to the HAL */
		HAL_CALL(hal).response_complete(hal->halinfo.hal_private,
		    resp, h_priv);

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * s1394_compare_swap()
 *    is used by t1394_lock() to send a lock request.  Any of the lock
 *    requests specified explicitly by the 1394 spec will pass thru here,
 *    i.e compare-swap, mask-swap, etc.
 */
int
s1394_compare_swap(s1394_hal_t *hal, s1394_target_t *target, cmd1394_cmd_t *cmd)
{
	s1394_cmd_priv_t	*s_priv;
	s1394_hal_state_t	state;
	int			err;
	int			ret;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	/* Lock the topology tree - protect from bus reset */
	mutex_enter(&hal->topology_tree_mutex);

	ret = s1394_setup_asynch_command(hal, target, cmd, S1394_CMD_LOCK,
	    &err);

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Command has now been put onto the queue! */
	if (ret != DDI_SUCCESS) {
		/* Copy error code into result */
		cmd->cmd_result = err;

		return (DDI_FAILURE);
	}

	mutex_enter(&hal->topology_tree_mutex);
	state = hal->hal_state;
	/* If this command was sent during a bus reset, */
	/* then put it onto the pending Q. */
	if (state == S1394_HAL_RESET) {
		/* Remove cmd from outstanding request Q */
		s1394_remove_q_asynch_cmd(hal, cmd);

		/* Are we on the bus reset event stack? */
		if (s1394_on_br_thread(hal) == B_TRUE) {
			/* Blocking commands are not allowed */
			if (cmd->cmd_options & CMD1394_BLOCKING) {
				mutex_exit(&hal->topology_tree_mutex);

				s_priv->cmd_in_use = B_FALSE;

				cmd->cmd_result = CMD1394_EINVALID_CONTEXT;

				return (DDI_FAILURE);
			}
		}

		s1394_pending_q_insert(hal, cmd, S1394_PENDING_Q_FRONT);
		mutex_exit(&hal->topology_tree_mutex);

		/* Block (if necessary) */
		s1394_block_on_asynch_cmd(cmd);

		return (DDI_SUCCESS);
	}
	mutex_exit(&hal->topology_tree_mutex);

	/* Send the command out */
	ret = s1394_xfer_asynch_command(hal, cmd, &err);

	if (ret != DDI_SUCCESS) {
		if (err == CMD1394_ESTALE_GENERATION) {
			/* Remove cmd from outstanding request Q */
			s1394_remove_q_asynch_cmd(hal, cmd);
			s1394_pending_q_insert(hal, cmd, S1394_PENDING_Q_FRONT);

			/* Block (if necessary) */
			s1394_block_on_asynch_cmd(cmd);

			return (DDI_SUCCESS);

		} else {
			/* Remove cmd from outstanding request Q */
			s1394_remove_q_asynch_cmd(hal, cmd);

			s_priv->cmd_in_use = B_FALSE;

			/* Copy error code into result */
			cmd->cmd_result = err;

			return (DDI_FAILURE);
		}
	} else {
		/* Block (if necessary) */
		s1394_block_on_asynch_cmd(cmd);

		return (DDI_SUCCESS);
	}
}

/*
 * s1394_split_lock_req()
 *    is also used by t1394_lock() to send a lock request.  The difference
 *    is that s1394_split_lock_req() is used to send the software supported
 *    lock types, i.e. bit_and, bit_or, etc.  These lock requests require
 *    more than one transaction, typically compare-swap's.
 */
int
s1394_split_lock_req(s1394_hal_t *hal, s1394_target_t *target,
    cmd1394_cmd_t *cmd)
{
	s1394_cmd_priv_t *s_priv;
	cmd1394_cmd_t	 *tmp_cmd;

	/* Allocate a temporary command */
	if (s1394_alloc_cmd(hal, T1394_ALLOC_CMD_NOSLEEP, &tmp_cmd) !=
	    DDI_SUCCESS) {
		cmd->cmd_result = CMD1394_EUNKNOWN_ERROR;

		return (DDI_FAILURE);
	}

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(tmp_cmd);

	tmp_cmd->completion_callback	= s1394_handle_lock;
	tmp_cmd->cmd_callback_arg	= (opaque_t)cmd;
	tmp_cmd->cmd_type		= cmd->cmd_type;
	tmp_cmd->cmd_addr		= cmd->cmd_addr;
	tmp_cmd->cmd_options		= cmd->cmd_options;
	tmp_cmd->bus_generation		= cmd->bus_generation;

	/* The temporary command can not block */
	tmp_cmd->cmd_options = tmp_cmd->cmd_options & ~CMD1394_BLOCKING;

	/* Setup compare-swap with data_value == arg_value (read) */
	if (tmp_cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
		tmp_cmd->cmd_u.l32.data_value	= 0;
		tmp_cmd->cmd_u.l32.arg_value	= 0;
		tmp_cmd->cmd_u.l32.lock_type	= CMD1394_LOCK_COMPARE_SWAP;
		s_priv->temp_num_retries	= cmd->cmd_u.l32.num_retries;
	} else {
		tmp_cmd->cmd_u.l64.data_value	= 0;
		tmp_cmd->cmd_u.l64.arg_value	= 0;
		tmp_cmd->cmd_u.l64.lock_type	= CMD1394_LOCK_COMPARE_SWAP;
		s_priv->temp_num_retries	= cmd->cmd_u.l64.num_retries;
	}

	/* Initialize lock_req_step */
	s_priv->lock_req_step = 0;

	/* Get the Services Layer private area for the target cmd */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	s_priv->cmd_in_use = B_TRUE;

	/* Send the request */
	if (s1394_compare_swap(hal, target, tmp_cmd) != DDI_SUCCESS) {
		s_priv->cmd_in_use = B_FALSE;

		/* Free the temporary command */
		if (s1394_free_cmd(hal, &tmp_cmd) != DDI_SUCCESS)
			cmd->cmd_result = CMD1394_EUNKNOWN_ERROR;

		return (DDI_FAILURE);
	}

	/* Block (if necessary) */
	s1394_block_on_asynch_cmd(cmd);

	return (DDI_SUCCESS);
}

/*
 * s1394_handle_lock()
 *    is the callback for s1394_split_lock_req().  It does all of the real
 *    work.  Based on the specific lock type all necessary manipulation is
 *    performed and another compare swap is sent out.  If the transaction
 *    is unsuccessful, it is retried.
 */
static void
s1394_handle_lock(cmd1394_cmd_t *cmd)
{
	s1394_hal_t	 *to_hal;
	s1394_target_t	 *target;
	s1394_cmd_priv_t *s_priv;
	cmd1394_cmd_t	 *target_cmd;
	uint32_t	 lock_req_step;
	int		 tcmd_result;
	int		 ret;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	lock_req_step = s_priv->lock_req_step;

	/* Get the target's command */
	target_cmd = (cmd1394_cmd_t *)cmd->cmd_callback_arg;

	/* Get the destination of the command */
	to_hal = s_priv->sent_on_hal;

lock_req_step_0:
	/* Is this step 0 completing? */
	if (lock_req_step == 0) {
		/* Was the request successful? */
		if (cmd->cmd_result == CMD1394_CMDSUCCESS) {
			/* Do any math, bit ops, or byte-swapping necessary */
			ret = s1394_process_split_lock(cmd, target_cmd);

			if (ret != DDI_SUCCESS) {
				tcmd_result = target_cmd->cmd_result;
				goto lock_req_done;
			}

			s_priv->lock_req_step = 1;

			target = s_priv->sent_by_target;

			if (s1394_compare_swap(to_hal, target, cmd) !=
			    DDI_SUCCESS) {
				tcmd_result = cmd->cmd_result;
				goto lock_req_done;
			} else {
				return;
			}
		} else {
			/* Command failed for some reason */
			tcmd_result = cmd->cmd_result;
			goto lock_req_done;
		}
	} else {	/* lock_req_step == 1 */
		/* Was the request successful? */
		if (cmd->cmd_result == CMD1394_CMDSUCCESS) {
			/* Do whatever's necessary to finish up the lock */
			ret = s1394_finish_split_lock(cmd, target_cmd);

			if (ret != DDI_SUCCESS) {
				lock_req_step = 0;
				goto lock_req_step_0;
			} else {
				tcmd_result = cmd->cmd_result;
				goto lock_req_done;
			}
		} else {
			/* Command failed for some reason */
			tcmd_result = cmd->cmd_result;
			goto lock_req_done;
		}
	}

lock_req_done:
	(void) s1394_free_cmd(to_hal, &cmd);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(target_cmd);

	s_priv->cmd_in_use = B_FALSE;

	target_cmd->cmd_result = tcmd_result;

	/* Is this a blocking command? */
	if (target_cmd->cmd_options & CMD1394_BLOCKING) {
		/* Unblock the waiting command */
		mutex_enter(&s_priv->blocking_mutex);
		s_priv->blocking_flag = B_TRUE;
		cv_signal(&s_priv->blocking_cv);
		mutex_exit(&s_priv->blocking_mutex);

		return;
	}

	/* Call the target's completion_callback() */
	if (target_cmd->completion_callback != NULL)
		target_cmd->completion_callback(target_cmd);
}

/*
 * s1394_pending_q_insert()
 *    is used to insert a given command structure onto a HAL's pending queue
 *    for later processing (after the bus reset).  All commands returned by
 *    the HAL, are inserted onto the rear of the list (first priority), and
 *    all other commands (from targets during bus reset) are put onto the front.
 */
void
s1394_pending_q_insert(s1394_hal_t *hal, cmd1394_cmd_t *cmd, uint_t flags)
{
	cmd1394_cmd_t *temp_cmd;
	s1394_cmd_priv_t *s_priv;
	s1394_cmd_priv_t *c_priv;

	mutex_enter(&hal->pending_q_mutex);

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Is the outstanding request queue empty? */
	if ((hal->pending_q_head == NULL) && (hal->pending_q_tail == NULL)) {

		hal->pending_q_head = (cmd1394_cmd_t *)cmd;
		hal->pending_q_tail = (cmd1394_cmd_t *)cmd;
		s_priv->cmd_priv_next = (cmd1394_cmd_t *)NULL;
		s_priv->cmd_priv_prev = (cmd1394_cmd_t *)NULL;

	} else if (flags == S1394_PENDING_Q_FRONT) {
		s_priv->cmd_priv_next = hal->pending_q_head;
		s_priv->cmd_priv_prev = (cmd1394_cmd_t *)NULL;

		temp_cmd = (cmd1394_cmd_t *)hal->pending_q_head;
		c_priv = (s1394_cmd_priv_t *)((uchar_t *)temp_cmd +
		    sizeof (cmd1394_cmd_t));
		c_priv->cmd_priv_prev = (cmd1394_cmd_t *)cmd;

		hal->pending_q_head = (cmd1394_cmd_t *)cmd;

	} else {
		s_priv->cmd_priv_prev = hal->pending_q_tail;
		s_priv->cmd_priv_next = (cmd1394_cmd_t *)NULL;

		temp_cmd = (cmd1394_cmd_t *)hal->pending_q_tail;
		c_priv = (s1394_cmd_priv_t *)((uchar_t *)temp_cmd +
		    sizeof (cmd1394_cmd_t));
		c_priv->cmd_priv_next = (cmd1394_cmd_t *)cmd;

		hal->pending_q_tail = (cmd1394_cmd_t *)cmd;
	}

	mutex_exit(&hal->pending_q_mutex);

	/* kstats - number of pending Q insertions */
	hal->hal_kstats->pending_q_insert++;
}

/*
 * s1394_pending_q_remove()
 *    is used to remove a command structure from a HAL's pending queue for
 *    processing.
 */
static cmd1394_cmd_t *
s1394_pending_q_remove(s1394_hal_t *hal)
{
	s1394_cmd_priv_t *s_priv;
	s1394_cmd_priv_t *c_priv;
	cmd1394_cmd_t	 *cmd;
	cmd1394_cmd_t	 *prev_cmd;

	mutex_enter(&hal->pending_q_mutex);

	cmd = (cmd1394_cmd_t *)hal->pending_q_tail;
	if (cmd == NULL) {
		mutex_exit(&hal->pending_q_mutex);
		return (NULL);
	}

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	prev_cmd = (cmd1394_cmd_t *)s_priv->cmd_priv_prev;

	s_priv->cmd_priv_prev = (cmd1394_cmd_t *)NULL;
	s_priv->cmd_priv_next = (cmd1394_cmd_t *)NULL;

	if (prev_cmd != NULL) {
		c_priv = (s1394_cmd_priv_t *)((uchar_t *)prev_cmd +
		    sizeof (cmd1394_cmd_t));
		c_priv->cmd_priv_next = (cmd1394_cmd_t *)NULL;

	} else {
		hal->pending_q_head = (cmd1394_cmd_t *)NULL;
	}
	hal->pending_q_tail = (cmd1394_cmd_t *)prev_cmd;

	mutex_exit(&hal->pending_q_mutex);

	return (cmd);
}

/*
 * s1394_resend_pending_cmds()
 *    is called when the pending queue is to be flushed.  After most of the
 *    bus reset processing is completed, the pending commands are sent/resent.
 */
void
s1394_resend_pending_cmds(s1394_hal_t *hal)
{
	int done;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	do {
		done = s1394_process_pending_q(hal);
	} while (done == B_FALSE);

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));
}

/*
 * s1394_process_pending_q()
 *    is called to send/resend the commands on the pending queue.  All command
 *    handling can be done here, including notifying the target of failed
 *    commands, etc.  If it is necessary to recompute the address, speed,
 *    or max_payload for a command, that can be done here too.  And if there
 *    is no reason not to continue sending commands from the pending queue,
 *    then a B_FALSE is returned, else B_TRUE is returned.
 */
static boolean_t
s1394_process_pending_q(s1394_hal_t *hal)
{
	s1394_cmd_priv_t *s_priv;
	h1394_cmd_priv_t *h_priv;
	s1394_target_t	 *target;
	cmd1394_cmd_t	 *cmd;
	uint64_t	 node;
	uint32_t	 from_node;
	uint32_t	 to_node;
	uint_t		 current_max_payload;
	int		 ret;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	/* Pull a command from the Pending Q */
	cmd = s1394_pending_q_remove(hal);

	if (cmd == NULL) {
		return (B_TRUE);
	}

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Get a pointer to the HAL private struct */
	h_priv = (h1394_cmd_priv_t *)&s_priv->hal_cmd_private;

	if ((cmd->cmd_options & CMD1394_OVERRIDE_ADDR) ||
	    (cmd->cmd_options & CMD1394_CANCEL_ON_BUS_RESET)) {
		if (h_priv->bus_generation == hal->generation_count) {
			ret = s1394_pending_q_helper(hal, cmd);
			return (ret);
		} else {

			s_priv->cmd_in_use = B_FALSE;

			cmd->cmd_result = CMD1394_EBUSRESET;

			/* Is this a blocking command? */
			if (cmd->cmd_options & CMD1394_BLOCKING) {
				/* Unblock the waiting command */
				mutex_enter(&s_priv->blocking_mutex);
				s_priv->blocking_flag = B_TRUE;
				cv_signal(&s_priv->blocking_cv);
				mutex_exit(&s_priv->blocking_mutex);

				return (B_FALSE);
			}

			/* Call the target's completion_callback() */
			if (cmd->completion_callback != NULL) {
				cmd->completion_callback(cmd);
			}

			return (B_FALSE);
		}
	} else {
		if (h_priv->bus_generation == hal->generation_count) {
			ret = s1394_pending_q_helper(hal, cmd);
			return (ret);
		} else {
			/* Make sure we can get the topology_tree_mutex */
			if (s1394_lock_tree(hal) != DDI_SUCCESS)
				return (B_TRUE);

			/* Set the generation */
			cmd->bus_generation = hal->generation_count;

			/* Copy the generation into the HAL's private field */
			h_priv->bus_generation = cmd->bus_generation;

			target = s_priv->sent_by_target;

			/* If not OVERRIDE_ADDR, then target may not be NULL */
			ASSERT(target != NULL);

			rw_enter(&hal->target_list_rwlock, RW_READER);

			if (((target->target_state & S1394_TARG_GONE) == 0) &&
			    (target->on_node != NULL)) {
				node = target->on_node->node_num;
				rw_exit(&hal->target_list_rwlock);
			} else {
				rw_exit(&hal->target_list_rwlock);

				s_priv->cmd_in_use = B_FALSE;

				cmd->cmd_result = CMD1394_EDEVICE_REMOVED;

				/* Is this a blocking command? */
				if (cmd->cmd_options & CMD1394_BLOCKING) {
					s1394_unlock_tree(hal);

					/* Unblock the waiting command */
					mutex_enter(&s_priv->blocking_mutex);
					s_priv->blocking_flag = B_TRUE;
					cv_signal(&s_priv->blocking_cv);
					mutex_exit(&s_priv->blocking_mutex);

					return (B_FALSE);
				}

				/* Call the target's completion_callback() */
				if (cmd->completion_callback != NULL) {
					s1394_unlock_tree(hal);
					cmd->completion_callback(cmd);
					return (B_FALSE);
				} else {
					s1394_unlock_tree(hal);
					return (B_FALSE);
				}
			}

			/* Mask in the top 16-bits */
			cmd->cmd_addr = cmd->cmd_addr &
			    IEEE1394_ADDR_OFFSET_MASK;
			cmd->cmd_addr = cmd->cmd_addr |
			    (node << IEEE1394_ADDR_PHY_ID_SHIFT);
			cmd->cmd_addr = cmd->cmd_addr |
			    IEEE1394_ADDR_BUS_ID_MASK;

			/* Speed is to be filled in from speed map */
			from_node = IEEE1394_NODE_NUM(hal->node_id);
			to_node	  = (uint32_t)node;

			/* Fill in the nodeID */
			cmd->nodeID =
			    (cmd->cmd_addr & IEEE1394_ADDR_NODE_ID_MASK) >>
				IEEE1394_ADDR_NODE_ID_SHIFT;

			if (cmd->cmd_options & CMD1394_OVERRIDE_SPEED) {
				s_priv->hal_cmd_private.speed =
				    (int)cmd->cmd_speed;
			} else {
				/* Speed is to be filled in from speed map */
				s_priv->hal_cmd_private.speed =
				    (int)s1394_speed_map_get(hal, from_node,
				    to_node);
			}

			/* Is it a block request? */
			if ((cmd->cmd_type == CMD1394_ASYNCH_RD_BLOCK) ||
			    (cmd->cmd_type == CMD1394_ASYNCH_WR_BLOCK)) {

				/* Get a pointer to the HAL private struct */
				h_priv = (h1394_cmd_priv_t *)&s_priv->
				    hal_cmd_private;

				/* Handle the MAX_PAYLOAD size */
				if (s_priv->sent_by_target != NULL) {
					current_max_payload =
					    s_priv->sent_by_target->
					    current_max_payload;
				} else {
					current_max_payload = 4;
				}
				if (cmd->cmd_options &
				    CMD1394_OVERRIDE_MAX_PAYLOAD) {
					if (current_max_payload >
					    cmd->cmd_u.b.max_payload)
					    current_max_payload =
						    cmd->cmd_u.b.max_payload;
				}
				if (s_priv->data_remaining <
				    current_max_payload) {
					h_priv->mblk.length =
					    s_priv->data_remaining;
				} else {
					h_priv->mblk.length =
					    current_max_payload;
				}
			}
			s1394_unlock_tree(hal);
			ret = s1394_pending_q_helper(hal, cmd);
			return (ret);
		}
	}
}

/*
 * s1394_pending_q_helper()
 *    is a "helper" function for s1394_process_pending_q().  It attempts to
 *    resend commands, handling error conditions whenever necessary.
 */
static boolean_t
s1394_pending_q_helper(s1394_hal_t *hal, cmd1394_cmd_t *cmd)
{
	s1394_cmd_priv_t *s_priv;
	int		 err;
	int		 ret;

	ASSERT(MUTEX_NOT_HELD(&hal->topology_tree_mutex));

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Put cmd on outstanding request Q */
	s1394_insert_q_asynch_cmd(hal, cmd);

	/* Send command out again */
	ret = s1394_xfer_asynch_command(hal, cmd, &err);

	if (ret != DDI_SUCCESS) {
		if (err == CMD1394_ESTALE_GENERATION) {
			/* Remove cmd outstanding req Q */
			s1394_remove_q_asynch_cmd(hal, cmd);
			s1394_pending_q_insert(hal, cmd, S1394_PENDING_Q_FRONT);

			return (B_TRUE);
		} else {
			/* Remove cmd from outstanding request Q */
			s1394_remove_q_asynch_cmd(hal, cmd);

			s_priv->cmd_in_use = B_FALSE;

			cmd->cmd_result = err;

			/* Is this a blocking command? */
			if (cmd->cmd_options & CMD1394_BLOCKING) {
				/* Unblock waiting command */
				mutex_enter(&s_priv->blocking_mutex);
				s_priv->blocking_flag = B_TRUE;
				cv_signal(&s_priv->blocking_cv);
				mutex_exit(&s_priv->blocking_mutex);

				return (B_FALSE);
			}

			/* Call target completion_callback() */
			if (cmd->completion_callback != NULL) {
				cmd->completion_callback(cmd);
				return (B_FALSE);
			} else {
				return (B_FALSE);
			}
		}
	}

	return (B_FALSE);
}

/*
 * s1394_process_split_lock()
 *    is a "helper" function for the s1394_handle_lock() callback.  Its
 *    job is to perform whatever manipulation is required for the given
 *    request.
 */
static int
s1394_process_split_lock(cmd1394_cmd_t *cmd, cmd1394_cmd_t *target_cmd)
{
	uint64_t	 new_value64;
	uint64_t	 data_value64;
	uint64_t	 arg_value64;
	uint64_t	 old_value64;
	uint64_t	 temp_value64;
	uint32_t	 new_value32;
	uint32_t	 data_value32;
	uint32_t	 arg_value32;
	uint32_t	 old_value32;
	uint32_t	 temp_value32;

	if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
		old_value32  = cmd->cmd_u.l32.old_value;
		data_value32 = target_cmd->cmd_u.l32.data_value;
		arg_value32  = target_cmd->cmd_u.l32.arg_value;

		/* Lock type specific */
		switch (target_cmd->cmd_u.l32.lock_type) {
		case CMD1394_LOCK_BIT_AND:
			new_value32 = old_value32 & data_value32;
			break;

		case CMD1394_LOCK_BIT_OR:
			new_value32 = old_value32 | data_value32;
			break;

		case CMD1394_LOCK_BIT_XOR:
			new_value32 = old_value32 ^ data_value32;
			break;

		case CMD1394_LOCK_INCREMENT:
			old_value32 = T1394_DATA32(old_value32);
			new_value32 = old_value32 + 1;
			new_value32 = T1394_DATA32(new_value32);
			old_value32 = T1394_DATA32(old_value32);
			break;

		case CMD1394_LOCK_DECREMENT:
			old_value32 = T1394_DATA32(old_value32);
			new_value32 = old_value32 - 1;
			new_value32 = T1394_DATA32(new_value32);
			old_value32 = T1394_DATA32(old_value32);
			break;

		case CMD1394_LOCK_ADD:
			old_value32 = T1394_DATA32(old_value32);
			new_value32 = old_value32 + data_value32;
			new_value32 = T1394_DATA32(new_value32);
			old_value32 = T1394_DATA32(old_value32);
			break;

		case CMD1394_LOCK_SUBTRACT:
			old_value32 = T1394_DATA32(old_value32);
			new_value32 = old_value32 - data_value32;
			new_value32 = T1394_DATA32(new_value32);
			old_value32 = T1394_DATA32(old_value32);
			break;

		case CMD1394_LOCK_THRESH_ADD:
			old_value32 = T1394_DATA32(old_value32);
			temp_value32 = (old_value32 + data_value32);
			if ((temp_value32 >= old_value32) &&
			    (temp_value32 <= arg_value32)) {
				new_value32 = T1394_DATA32(temp_value32);
				old_value32 = T1394_DATA32(old_value32);
			} else {
				/* Failed threshold add */
				target_cmd->cmd_u.l32.old_value =
				    T1394_DATA32(cmd->cmd_u.l32.old_value);
				target_cmd->cmd_result = CMD1394_CMDSUCCESS;
				return (DDI_FAILURE);
			}
			break;

		case CMD1394_LOCK_THRESH_SUBTRACT:
			old_value32 = T1394_DATA32(old_value32);
			temp_value32 = (old_value32 - data_value32);
			if ((old_value32 >= data_value32) &&
			    (temp_value32 >= arg_value32)) {
				new_value32 = T1394_DATA32(temp_value32);
				old_value32 = T1394_DATA32(old_value32);
			} else {
				/* Failed threshold subtract */
				target_cmd->cmd_u.l32.old_value =
				    T1394_DATA32(cmd->cmd_u.l32.old_value);
				target_cmd->cmd_result = CMD1394_CMDSUCCESS;
				return (DDI_FAILURE);
			}
			break;

		case CMD1394_LOCK_CLIP_ADD:
			old_value32 = T1394_DATA32(old_value32);
			temp_value32 = (old_value32 + data_value32);
			if ((temp_value32 < old_value32) ||
			    (temp_value32 > arg_value32))
				new_value32 = T1394_DATA32(arg_value32);
			else
				new_value32 = T1394_DATA32(temp_value32);
			old_value32 = T1394_DATA32(old_value32);
			break;

		case CMD1394_LOCK_CLIP_SUBTRACT:
			old_value32 = T1394_DATA32(old_value32);
			temp_value32 = (old_value32 - data_value32);
			if ((data_value32 > old_value32) ||
			    (temp_value32 < arg_value32))
				new_value32 = T1394_DATA32(arg_value32);
			else
				new_value32 = T1394_DATA32(temp_value32);
			old_value32 = T1394_DATA32(old_value32);
			break;
		}

		/* Send compare-swap lock request */
		cmd->cmd_u.l32.arg_value  = old_value32;
		cmd->cmd_u.l32.data_value = new_value32;
	} else {
		old_value64  = cmd->cmd_u.l64.old_value;
		data_value64 = target_cmd->cmd_u.l64.data_value;
		arg_value64  = target_cmd->cmd_u.l64.arg_value;

		/* Lock type specific */
		switch (target_cmd->cmd_u.l64.lock_type) {
		case CMD1394_LOCK_BIT_AND:
			new_value64 = old_value64 & data_value64;
			break;

		case CMD1394_LOCK_BIT_OR:
			new_value64 = old_value64 | data_value64;
			break;

		case CMD1394_LOCK_BIT_XOR:
			new_value64 = old_value64 ^ data_value64;
			break;

		case CMD1394_LOCK_INCREMENT:
			old_value64 = T1394_DATA64(old_value64);
			new_value64 = old_value64 + 1;
			new_value64 = T1394_DATA64(new_value64);
			old_value64 = T1394_DATA64(old_value64);
			break;

		case CMD1394_LOCK_DECREMENT:
			old_value64 = T1394_DATA64(old_value64);
			new_value64 = old_value64 - 1;
			new_value64 = T1394_DATA64(new_value64);
			old_value64 = T1394_DATA64(old_value64);
			break;

		case CMD1394_LOCK_ADD:
			old_value64 = T1394_DATA64(old_value64);
			new_value64 = old_value64 + data_value64;
			new_value64 = T1394_DATA64(new_value64);
			old_value64 = T1394_DATA64(old_value64);
			break;

		case CMD1394_LOCK_SUBTRACT:
			old_value64 = T1394_DATA64(old_value64);
			new_value64 = old_value64 - data_value64;
			new_value64 = T1394_DATA64(new_value64);
			old_value64 = T1394_DATA64(old_value64);
			break;

		case CMD1394_LOCK_THRESH_ADD:
			old_value64 = T1394_DATA64(old_value64);
			temp_value64 = (old_value64 + data_value64);
			if ((temp_value64 >= old_value64) &&
			    (temp_value64 <= arg_value64)) {
				new_value64 = T1394_DATA64(temp_value64);
				old_value64 = T1394_DATA64(old_value64);
			} else {
				/* Failed threshold add */
				target_cmd->cmd_u.l64.old_value =
				    T1394_DATA64(cmd->cmd_u.l64.old_value);
				target_cmd->cmd_result = CMD1394_CMDSUCCESS;
				return (DDI_FAILURE);
			}
			break;

		case CMD1394_LOCK_THRESH_SUBTRACT:
			old_value64 = T1394_DATA64(old_value64);
			temp_value64 = (old_value64 - data_value64);
			if ((old_value64 >= data_value64) &&
			    (temp_value64 >= arg_value64)) {
				new_value64 = T1394_DATA64(temp_value64);
				old_value64 = T1394_DATA64(old_value64);
			} else {
				/* Failed threshold subtract */
				target_cmd->cmd_u.l64.old_value =
				    T1394_DATA64(cmd->cmd_u.l64.old_value);
				target_cmd->cmd_result = CMD1394_CMDSUCCESS;
				return (DDI_FAILURE);
			}
			break;

		case CMD1394_LOCK_CLIP_ADD:
			old_value64 = T1394_DATA64(old_value64);
			temp_value64 = (old_value64 + data_value64);
			if ((temp_value64 < old_value64) ||
			    (temp_value64 > arg_value64))
				new_value64 = T1394_DATA64(arg_value64);
			else
				new_value64 = T1394_DATA64(temp_value64);
			old_value64 = T1394_DATA64(old_value64);
			break;

		case CMD1394_LOCK_CLIP_SUBTRACT:
			old_value64 = T1394_DATA64(old_value64);
			temp_value64 = (old_value64 - data_value64);
			if ((data_value64 > old_value64) ||
			    (temp_value64 < arg_value64))
				new_value64 = T1394_DATA64(arg_value64);
			else
				new_value64 = T1394_DATA64(temp_value64);
			old_value64 = T1394_DATA64(old_value64);
			break;
		}

		/* Send compare-swap lock request */
		cmd->cmd_u.l64.arg_value  = old_value64;
		cmd->cmd_u.l64.data_value = new_value64;
	}

	return (DDI_SUCCESS);
}

/*
 * s1394_finish_split_lock()
 *    is another "helper" function for the s1394_handle_lock() callback.
 *    Its job is to finish up whatever lock request procesing is necessary.
 */
static int
s1394_finish_split_lock(cmd1394_cmd_t *cmd, cmd1394_cmd_t *target_cmd)
{
	s1394_cmd_priv_t *s_priv;
	uint64_t	 tmp_value64;
	uint32_t	 tmp_value32;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	if (((cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) &&
	    (cmd->cmd_u.l32.old_value == cmd->cmd_u.l32.arg_value)) ||
	    ((cmd->cmd_type == CMD1394_ASYNCH_LOCK_64) &&
	    (cmd->cmd_u.l64.old_value == cmd->cmd_u.l64.arg_value))) {

		if (cmd->cmd_type == CMD1394_ASYNCH_LOCK_32) {
			switch (cmd->cmd_u.l32.lock_type) {
			case CMD1394_LOCK_INCREMENT:
			case CMD1394_LOCK_DECREMENT:
			case CMD1394_LOCK_ADD:
			case CMD1394_LOCK_SUBTRACT:
			case CMD1394_LOCK_THRESH_ADD:
			case CMD1394_LOCK_THRESH_SUBTRACT:
			case CMD1394_LOCK_CLIP_ADD:
			case CMD1394_LOCK_CLIP_SUBTRACT:
				tmp_value32 = cmd->cmd_u.l32.old_value;
				tmp_value32 = T1394_DATA32(tmp_value32);
				target_cmd->cmd_u.l32.old_value = tmp_value32;
				break;
			default:
				tmp_value32 = cmd->cmd_u.l32.old_value;
				target_cmd->cmd_u.l32.old_value = tmp_value32;
				break;
			}
		} else {
			switch (cmd->cmd_u.l64.lock_type) {
			case CMD1394_LOCK_INCREMENT:
			case CMD1394_LOCK_DECREMENT:
			case CMD1394_LOCK_ADD:
			case CMD1394_LOCK_SUBTRACT:
			case CMD1394_LOCK_THRESH_ADD:
			case CMD1394_LOCK_THRESH_SUBTRACT:
			case CMD1394_LOCK_CLIP_ADD:
			case CMD1394_LOCK_CLIP_SUBTRACT:
				tmp_value64 = cmd->cmd_u.l64.old_value;
				tmp_value64 = T1394_DATA64(tmp_value64);
				target_cmd->cmd_u.l64.old_value = tmp_value64;
				break;
			default:
				tmp_value64 = cmd->cmd_u.l64.old_value;
				target_cmd->cmd_u.l64.old_value = tmp_value64;
				break;
			}
		}
		/* Set status */
		target_cmd->cmd_result = CMD1394_CMDSUCCESS;
		return (DDI_SUCCESS);
	} else {
		if (s_priv->temp_num_retries > 0) {
			/* Decrement retry count */
			s_priv->temp_num_retries--;

			/* Reset lock_req_step */
			s_priv->lock_req_step = 0;

			/* Resend... start at step 0 again */
			return (DDI_FAILURE);
		} else {
			/* Failed... RETRIES_EXCEEDED */
			target_cmd->cmd_result = CMD1394_ERETRIES_EXCEEDED;
			return (DDI_SUCCESS);
		}
	}
}
