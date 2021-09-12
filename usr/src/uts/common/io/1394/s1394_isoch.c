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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * s1394_isoch.c
 *    1394 Services Layer Isochronous Communication Routines
 *    This file contains routines for managing isochronous bandwidth
 *    and channel needs for registered targets (through the target
 *    isoch interfaces).
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>

/*
 * s1394_isoch_rsrc_realloc()
 *    is called during bus reset processing to reallocate any isochronous
 *    resources that were previously allocated.
 */
void
s1394_isoch_rsrc_realloc(s1394_hal_t *hal)
{
	s1394_isoch_cec_t *cec_curr;
	uint32_t	  chnl_mask;
	uint32_t	  old_chnl_mask;
	uint_t		  bw_alloc_units;
	uint_t		  generation;
	uint_t		  chnl_num;
	int		  err;
	int		  ret;

	/*
	 * Get the current generation number - don't need the
	 * topology tree mutex here because it is read-only, and
	 * there is a race condition with or without it.
	 */
	generation = hal->generation_count;

	/* Lock the Isoch CEC list */
	mutex_enter(&hal->isoch_cec_list_mutex);

	cec_curr = hal->isoch_cec_list_head;
	while (cec_curr != NULL) {
		/* Lock the Isoch CEC member list */
		mutex_enter(&cec_curr->isoch_cec_mutex);

		/* Are we supposed to reallocate resources? */
		if (!(cec_curr->cec_options & T1394_NO_IRM_ALLOC) &&
		    (cec_curr->realloc_valid == B_TRUE) &&
		    (cec_curr->realloc_failed == B_FALSE)) {

			/* Reallocate some bandwidth */
			bw_alloc_units = s1394_compute_bw_alloc_units(hal,
			    cec_curr->bandwidth, cec_curr->realloc_speed);

			/* Check that the generation has not changed */
			if (generation != hal->generation_count) {
				/* Try the next Isoch CEC */
				goto next_isoch_cec;
			}

			/* Unlock the Isoch CEC member list */
			mutex_exit(&cec_curr->isoch_cec_mutex);
			/*
			 * We can unlock the Isoch CEC list here
			 * because we know this Isoch CEC can not
			 * go away (we are trying to realloc its
			 * resources so it can't be in a state that
			 * will allow a free).
			 */
			mutex_exit(&hal->isoch_cec_list_mutex);

			/* Try to reallocate bandwidth */
			ret = s1394_bandwidth_alloc(hal, bw_alloc_units,
			    generation, &err);

			/* Lock the Isoch CEC list */
			mutex_enter(&hal->isoch_cec_list_mutex);
			/* Lock the Isoch CEC member list */
			mutex_enter(&cec_curr->isoch_cec_mutex);

			/* If we failed because we couldn't get bandwidth */
			if (ret == DDI_FAILURE) {
				cec_curr->realloc_failed = B_TRUE;
				cec_curr->realloc_fail_reason =
				    T1394_RSRC_BANDWIDTH;
			}
		}

		/* Are we supposed to reallocate resources? */
		if (!(cec_curr->cec_options & T1394_NO_IRM_ALLOC) &&
		    (cec_curr->realloc_valid == B_TRUE) &&
		    (cec_curr->realloc_failed == B_FALSE)) {

			/* Reallocate the channel */
			chnl_num  = cec_curr->realloc_chnl_num;
			chnl_mask = (1 << ((63 - chnl_num) % 32));

			/* Unlock the Isoch CEC member list */
			mutex_exit(&cec_curr->isoch_cec_mutex);
			/*
			 * We can unlock the Isoch CEC list here
			 * because we know this Isoch CEC can not
			 * go away (we are trying to realloc its
			 * resources so it can't be in a state that
			 * will allow a free).
			 */
			mutex_exit(&hal->isoch_cec_list_mutex);

			if (chnl_num < 32) {
				ret = s1394_channel_alloc(hal, chnl_mask,
				    generation, S1394_CHANNEL_ALLOC_HI,
				    &old_chnl_mask, &err);
			} else {
				ret = s1394_channel_alloc(hal, chnl_mask,
				    generation, S1394_CHANNEL_ALLOC_LO,
				    &old_chnl_mask, &err);
			}

			/* Lock the Isoch CEC list */
			mutex_enter(&hal->isoch_cec_list_mutex);
			/* Lock the Isoch CEC member list */
			mutex_enter(&cec_curr->isoch_cec_mutex);

			if (ret == DDI_FAILURE) {
				if (err != CMD1394_EBUSRESET) {
					/*
					 * If we successfully reallocate
					 * bandwidth, and then fail getting
					 * the channel, we need to free up
					 * the bandwidth
					 */

					/* Try to free up the bandwidth */
					ret = s1394_bandwidth_free(hal,
					    bw_alloc_units, generation, &err);
					/* Try the next Isoch CEC */
					goto next_isoch_cec;
				}
				cec_curr->realloc_failed = B_TRUE;
				cec_curr->realloc_fail_reason =
				    T1394_RSRC_CHANNEL;
			}
		}
next_isoch_cec:
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		cec_curr = cec_curr->cec_next;
	}

	/* Unlock the Isoch CEC list */
	mutex_exit(&hal->isoch_cec_list_mutex);
}

/*
 * s1394_isoch_rsrc_realloc_notify()
 *    is called during bus reset processing to notify all targets for
 *    which isochronous resources were not able to be reallocated.
 */
void
s1394_isoch_rsrc_realloc_notify(s1394_hal_t *hal)
{
	s1394_isoch_cec_t	 *cec_curr;
	s1394_isoch_cec_member_t *member_curr;
	t1394_isoch_rsrc_error_t fail_arg;
	opaque_t		 evts_arg;
	s1394_isoch_cec_type_t	 type;
	void (*rsrc_fail_callback)(t1394_isoch_cec_handle_t, opaque_t,
				t1394_isoch_rsrc_error_t);

	/* Lock the Isoch CEC list */
	mutex_enter(&hal->isoch_cec_list_mutex);

	/* Notify all targets that failed realloc */
	cec_curr = hal->isoch_cec_list_head;
	while (cec_curr != NULL) {
		/* Lock the Isoch CEC member list */
		mutex_enter(&cec_curr->isoch_cec_mutex);

		/* Do we notify of realloc failure? */
		if (!(cec_curr->cec_options & T1394_NO_IRM_ALLOC) &&
		    (cec_curr->realloc_valid == B_TRUE) &&
		    (cec_curr->realloc_failed == B_TRUE)) {

			/* Reason for realloc failure */
			fail_arg = cec_curr->realloc_fail_reason;

			/* Now we are going into the callbacks */
			cec_curr->in_fail_callbacks = B_TRUE;

			type = cec_curr->cec_type;

			/* Unlock the Isoch CEC member list */
			mutex_exit(&cec_curr->isoch_cec_mutex);
			/*
			 * We can unlock the Isoch CEC list here
			 * because we have the in_fail_callbacks
			 * field set to B_TRUE.  And free will fail
			 * if we are in fail callbacks.
			 */
			mutex_exit(&hal->isoch_cec_list_mutex);

			/* Call all of the rsrc_fail_target() callbacks */
			/* Start at the head (talker first) and */
			/* go toward the tail (listeners last) */
			member_curr = cec_curr->cec_member_list_head;
			while (member_curr != NULL) {
				rsrc_fail_callback = member_curr->
				    isoch_cec_evts.rsrc_fail_target;
				evts_arg = member_curr->isoch_cec_evts_arg;
				if (rsrc_fail_callback != NULL) {

					if (type == S1394_PEER_TO_PEER) {
						rsrc_fail_callback(
						    (t1394_isoch_cec_handle_t)
						    cec_curr, evts_arg,
						    fail_arg);
					} else {
						rsrc_fail_callback(
						    (t1394_isoch_cec_handle_t)
						    cec_curr, evts_arg,
						    fail_arg);
					}
				}
				member_curr = member_curr->cec_mem_next;
			}

			/* Lock the Isoch CEC list */
			mutex_enter(&hal->isoch_cec_list_mutex);
			/* Lock the Isoch CEC member list */
			mutex_enter(&cec_curr->isoch_cec_mutex);

			/* We are finished with the callbacks */
			cec_curr->in_fail_callbacks = B_FALSE;
			if (cec_curr->cec_want_wakeup == B_TRUE) {
				cec_curr->cec_want_wakeup = B_FALSE;
				cv_broadcast(&cec_curr->in_callbacks_cv);
			}

			/* Set flags back to original state */
			cec_curr->realloc_valid	 = B_FALSE;
			cec_curr->realloc_failed = B_FALSE;
		}
		/* Unlock the Isoch CEC member list */
		mutex_exit(&cec_curr->isoch_cec_mutex);
		cec_curr = cec_curr->cec_next;
	}

	/* Unlock the Isoch CEC list */
	mutex_exit(&hal->isoch_cec_list_mutex);
}

/*
 * s1394_channel_alloc()
 *    is used to allocate an isochronous channel.  A channel mask and
 *    generation are passed.  A request is sent to whichever node is the
 *    IRM for the appropriate channels.  If it fails because of a bus
 *    reset it can be retried.  If it fails for another reason the
 *    channel(s) may not be availble or there may be no IRM.
 */
int
s1394_channel_alloc(s1394_hal_t *hal, uint32_t channel_mask, uint_t generation,
    uint_t flags, uint32_t *old_channels, int *result)
{
	cmd1394_cmd_t	*cmd;
	uint64_t	IRM_ID_addr;
	uint32_t	compare;
	uint32_t	swap;
	uint32_t	old_value;
	uint_t		hal_node_num;
	uint_t		IRM_node;
	uint_t		offset;
	int		ret;
	int		i;
	int		num_retries = S1394_ISOCH_ALLOC_RETRIES;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	IRM_node = hal->IRM_node;

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);

	/* Make sure there is a valid IRM on the bus */
	if (IRM_node == -1) {
		*result = CMD1394_ERETRIES_EXCEEDED;
		return (DDI_FAILURE);
	}

	if (flags & S1394_CHANNEL_ALLOC_HI) {
		offset =
		    (IEEE1394_SCSR_CHANS_AVAIL_HI & IEEE1394_CSR_OFFSET_MASK);
	} else {
		offset =
		    (IEEE1394_SCSR_CHANS_AVAIL_LO & IEEE1394_CSR_OFFSET_MASK);
	}

	/* Send compare-swap to CHANNELS_AVAILABLE */
	/* register on the Isoch Rsrc Mgr */
	if (IRM_node == hal_node_num) {
		/* Local */
		i = num_retries;
		do {
			(void) HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
			    offset, &old_value);

			/* Check that the generation has not changed */
			if (generation != hal->generation_count) {
				*result = CMD1394_EBUSRESET;
				return (DDI_FAILURE);
			}

			compare = old_value;
			swap	= old_value & (~channel_mask);

			ret = HAL_CALL(hal).csr_cswap32(
			    hal->halinfo.hal_private, generation,
			    offset, compare, swap, &old_value);
			if (ret != DDI_SUCCESS) {
				*result = CMD1394_EBUSRESET;
				return (DDI_FAILURE);
			}

			if ((~old_value & channel_mask) != 0) {
				*result = CMD1394_ERETRIES_EXCEEDED;
				return (DDI_FAILURE);
			}

			if (old_value == compare) {
				*result = CMD1394_CMDSUCCESS;
				*old_channels = old_value;

				return (DDI_SUCCESS);
			}
		} while (i--);

		*result = CMD1394_ERETRIES_EXCEEDED;
		return (DDI_FAILURE);

	} else {
		/* Remote */
		if (s1394_alloc_cmd(hal, 0, &cmd) != DDI_SUCCESS) {
			*result = CMD1394_EUNKNOWN_ERROR;
			return (DDI_FAILURE);
		}

		cmd->cmd_options = (CMD1394_CANCEL_ON_BUS_RESET |
		    CMD1394_OVERRIDE_ADDR | CMD1394_BLOCKING);
		cmd->cmd_type = CMD1394_ASYNCH_LOCK_32;

		if (flags & S1394_CHANNEL_ALLOC_HI) {
			IRM_ID_addr = (IEEE1394_ADDR_BUS_ID_MASK |
			    IEEE1394_SCSR_CHANS_AVAIL_HI) |
			    (((uint64_t)IRM_node) <<
			    IEEE1394_ADDR_PHY_ID_SHIFT);
		} else {
			IRM_ID_addr = (IEEE1394_ADDR_BUS_ID_MASK |
			    IEEE1394_SCSR_CHANS_AVAIL_LO) |
			    (((uint64_t)IRM_node) <<
			    IEEE1394_ADDR_PHY_ID_SHIFT);
		}

		cmd->cmd_addr		   = IRM_ID_addr;
		cmd->bus_generation	   = generation;
		cmd->cmd_u.l32.data_value  = T1394_DATA32(~channel_mask);
		cmd->cmd_u.l32.num_retries = num_retries;
		cmd->cmd_u.l32.lock_type   = CMD1394_LOCK_BIT_AND;

		ret = s1394_split_lock_req(hal, NULL, cmd);

		if (ret == DDI_SUCCESS) {
			if (cmd->cmd_result == CMD1394_CMDSUCCESS) {
				*old_channels = T1394_DATA32(
				    cmd->cmd_u.l32.old_value);

				if ((~(*old_channels) & channel_mask) != 0) {
					*result = CMD1394_ERETRIES_EXCEEDED;
					ret = DDI_FAILURE;
				} else {
					*result = cmd->cmd_result;
				}

				/* Need to free the command */
				(void) s1394_free_cmd(hal, &cmd);

				return (ret);

			} else {
				*result = cmd->cmd_result;
				/* Need to free the command */
				(void) s1394_free_cmd(hal, &cmd);

				return (DDI_FAILURE);
			}
		} else {
			*result = cmd->cmd_result;

			/* Need to free the command */
			(void) s1394_free_cmd(hal, &cmd);

			return (DDI_FAILURE);
		}
	}
}

/*
 * s1394_channel_free()
 *    is used to free up an isochronous channel.  A channel mask and
 *    generation are passed.  A request is sent to whichever node is the
 *    IRM for the appropriate channels.  If it fails because of a bus
 *    reset it can be retried.  If it fails for another reason the
 *    channel(s) may already be free or there may be no IRM.
 */
int
s1394_channel_free(s1394_hal_t *hal, uint32_t channel_mask, uint_t generation,
    uint_t flags, uint32_t *old_channels, int *result)
{
	cmd1394_cmd_t	*cmd;
	uint64_t	IRM_ID_addr;
	uint32_t	compare;
	uint32_t	swap;
	uint32_t	old_value;
	uint_t		hal_node_num;
	uint_t		IRM_node;
	uint_t		offset;
	int		ret;
	int		i;
	int		num_retries = S1394_ISOCH_ALLOC_RETRIES;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	IRM_node = hal->IRM_node;

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);

	/* Make sure there is a valid IRM on the bus */
	if (IRM_node == -1) {
		*result = CMD1394_ERETRIES_EXCEEDED;
		return (DDI_FAILURE);
	}

	if (flags & S1394_CHANNEL_ALLOC_HI) {
		offset =
		    (IEEE1394_SCSR_CHANS_AVAIL_HI & IEEE1394_CSR_OFFSET_MASK);
	} else {
		offset =
		    (IEEE1394_SCSR_CHANS_AVAIL_LO & IEEE1394_CSR_OFFSET_MASK);
	}

	/* Send compare-swap to CHANNELS_AVAILABLE */
	/* register on the Isoch Rsrc Mgr */
	if (hal->IRM_node == hal_node_num) {
		/* Local */
		i = num_retries;
		do {
			(void) HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
			    offset, &old_value);

			/* Check that the generation has not changed */
			if (generation != hal->generation_count) {
				*result = CMD1394_EBUSRESET;
				return (DDI_FAILURE);
			}

			compare = old_value;
			swap	= old_value | channel_mask;

			ret = HAL_CALL(hal).csr_cswap32(
			    hal->halinfo.hal_private, hal->generation_count,
			    offset, compare, swap, &old_value);
			if (ret != DDI_SUCCESS) {
				*result = CMD1394_EBUSRESET;
				return (DDI_FAILURE);
			}

			if (old_value == compare) {
				*result = CMD1394_CMDSUCCESS;
				*old_channels = old_value;
				return (DDI_SUCCESS);
			}
		} while (i--);

		*result = CMD1394_ERETRIES_EXCEEDED;
		return (DDI_FAILURE);

	} else {
		/* Remote */
		if (s1394_alloc_cmd(hal, 0, &cmd) != DDI_SUCCESS) {
			*result = CMD1394_EUNKNOWN_ERROR;
			return (DDI_FAILURE);
		}

		cmd->cmd_options = (CMD1394_CANCEL_ON_BUS_RESET |
		    CMD1394_OVERRIDE_ADDR | CMD1394_BLOCKING);
		cmd->cmd_type = CMD1394_ASYNCH_LOCK_32;

		if (flags & S1394_CHANNEL_ALLOC_HI) {
			IRM_ID_addr = (IEEE1394_ADDR_BUS_ID_MASK |
			    IEEE1394_SCSR_CHANS_AVAIL_HI) |
			    (((uint64_t)IRM_node) <<
			    IEEE1394_ADDR_PHY_ID_SHIFT);
		} else {
			IRM_ID_addr = (IEEE1394_ADDR_BUS_ID_MASK |
			    IEEE1394_SCSR_CHANS_AVAIL_LO) |
			    (((uint64_t)IRM_node) <<
			    IEEE1394_ADDR_PHY_ID_SHIFT);
		}

		cmd->cmd_addr		   = IRM_ID_addr;
		cmd->bus_generation	   = generation;
		cmd->cmd_u.l32.data_value  = T1394_DATA32(channel_mask);
		cmd->cmd_u.l32.num_retries = num_retries;
		cmd->cmd_u.l32.lock_type   = CMD1394_LOCK_BIT_OR;

		ret = s1394_split_lock_req(hal, NULL, cmd);

		if (ret == DDI_SUCCESS) {
			if (cmd->cmd_result == CMD1394_CMDSUCCESS) {

				*old_channels = T1394_DATA32(
				    cmd->cmd_u.l32.old_value);
				*result = cmd->cmd_result;

				/* Need to free the command */
				(void) s1394_free_cmd(hal, &cmd);

				return (DDI_SUCCESS);

			} else {
				*result = cmd->cmd_result;

				/* Need to free the command */
				(void) s1394_free_cmd(hal, &cmd);

				return (DDI_FAILURE);
			}
		} else {
			*result = cmd->cmd_result;
			/* Need to free the command */
			(void) s1394_free_cmd(hal, &cmd);

			return (DDI_FAILURE);
		}
	}
}

/*
 * s1394_bandwidth_alloc()
 *    is used to allocate isochronous bandwidth.  A number of bandwidth
 *    allocation units and a generation are passed.  The request is sent
 *    to whichever node is the IRM for this amount of bandwidth.  If it
 *    fails because of a bus reset it can be retried.  If it fails for
 *    another reason the bandwidth may not be available or there may be
 *    no IRM.
 */
int
s1394_bandwidth_alloc(s1394_hal_t *hal, uint32_t bw_alloc_units,
    uint_t generation, int *result)
{
	cmd1394_cmd_t	*cmd;
	uint64_t	IRM_ID_addr;
	uint32_t	compare;
	uint32_t	swap;
	uint32_t	old_value;
	uint_t		hal_node_num;
	uint_t		IRM_node;
	int		temp_value;
	int		ret;
	int		i;
	int		num_retries = S1394_ISOCH_ALLOC_RETRIES;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	IRM_node = hal->IRM_node;

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);

	/* Make sure there is a valid IRM on the bus */
	if (IRM_node == -1) {
		*result = CMD1394_ERETRIES_EXCEEDED;
		return (DDI_FAILURE);
	}

	/* Send compare-swap to BANDWIDTH_AVAILABLE */
	/* register on the Isoch Rsrc Mgr */
	if (IRM_node == hal_node_num) {
		/* Local */
		i = num_retries;
		do {
			(void) HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
			    (IEEE1394_SCSR_BANDWIDTH_AVAIL &
			    IEEE1394_CSR_OFFSET_MASK), &old_value);
			/*
			 * Check that the generation has not changed -
			 * don't need the lock (read-only)
			 */
			if (generation != hal->generation_count) {
				*result = CMD1394_EBUSRESET;
				return (DDI_FAILURE);
			}

			temp_value = (old_value - bw_alloc_units);
			if ((old_value >= bw_alloc_units) &&
			    (temp_value >= IEEE1394_BANDWIDTH_MIN)) {
				compare = old_value;
				swap	= (uint32_t)temp_value;
			} else {
				*result = CMD1394_ERETRIES_EXCEEDED;
				return (DDI_FAILURE);
			}

			ret = HAL_CALL(hal).csr_cswap32(
			    hal->halinfo.hal_private, generation,
			    (IEEE1394_SCSR_BANDWIDTH_AVAIL &
			    IEEE1394_CSR_OFFSET_MASK), compare, swap,
			    &old_value);
			if (ret != DDI_SUCCESS) {
				*result = CMD1394_EBUSRESET;
				return (DDI_FAILURE);
			}

			if (old_value == compare) {
				*result = CMD1394_CMDSUCCESS;
				return (DDI_SUCCESS);
			}
		} while (i--);

		*result = CMD1394_ERETRIES_EXCEEDED;
		return (DDI_FAILURE);

	} else {
		/* Remote */
		if (s1394_alloc_cmd(hal, 0, &cmd) != DDI_SUCCESS) {
			*result = CMD1394_EUNKNOWN_ERROR;
			return (DDI_FAILURE);
		}

		cmd->cmd_options = (CMD1394_CANCEL_ON_BUS_RESET |
		    CMD1394_OVERRIDE_ADDR | CMD1394_BLOCKING);
		cmd->cmd_type = CMD1394_ASYNCH_LOCK_32;
		IRM_ID_addr = (IEEE1394_ADDR_BUS_ID_MASK |
		    IEEE1394_SCSR_BANDWIDTH_AVAIL) | (((uint64_t)IRM_node) <<
		    IEEE1394_ADDR_PHY_ID_SHIFT);
		cmd->cmd_addr		   = IRM_ID_addr;
		cmd->bus_generation	   = generation;
		cmd->cmd_u.l32.arg_value   = 0;
		cmd->cmd_u.l32.data_value  = bw_alloc_units;
		cmd->cmd_u.l32.num_retries = num_retries;
		cmd->cmd_u.l32.lock_type   = CMD1394_LOCK_THRESH_SUBTRACT;

		ret = s1394_split_lock_req(hal, NULL, cmd);

		if (ret == DDI_SUCCESS) {
			if (cmd->cmd_result == CMD1394_CMDSUCCESS) {
				*result = cmd->cmd_result;
				/* Need to free the command */
				(void) s1394_free_cmd(hal, &cmd);

				return (DDI_SUCCESS);

			} else {
				*result = cmd->cmd_result;
				/* Need to free the command */
				(void) s1394_free_cmd(hal, &cmd);

				return (DDI_FAILURE);
			}
		} else {
			*result = cmd->cmd_result;
			/* Need to free the command */
			(void) s1394_free_cmd(hal, &cmd);

			return (DDI_FAILURE);
		}
	}
}

/*
 * s1394_compute_bw_alloc_units()
 *    is used to compute the number of "bandwidth allocation units" that
 *    are necessary for a given bit rate.  It calculates the overhead
 *    necessary for isoch packet headers, bus arbitration, etc.  (See
 *    IEEE 1394-1995 Section 8.3.2.3.7 for an explanation of what a
 *    "bandwidth allocation unit" is.
 */
uint_t
s1394_compute_bw_alloc_units(s1394_hal_t *hal, uint_t bandwidth, uint_t speed)
{
	uint_t	total_quads;
	uint_t	speed_factor;
	uint_t	bau;
	int	max_hops;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	/* Calculate the 1394 bus diameter */
	max_hops = s1394_topology_tree_calculate_diameter(hal);

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);

	/* Calculate the total bandwidth (including overhead) */
	total_quads = (bandwidth >> 2) + IEEE1394_ISOCH_HDR_QUAD_SZ;
	switch (speed) {
	case IEEE1394_S400:
		speed_factor = ISOCH_SPEED_FACTOR_S400;
		break;
	case IEEE1394_S200:
		speed_factor = ISOCH_SPEED_FACTOR_S200;
		break;
	case IEEE1394_S100:
		speed_factor = ISOCH_SPEED_FACTOR_S100;
		break;
	}
	/* See IEC 61883-1 pp. 26-29 for this formula */
	bau = (32 * max_hops) + (total_quads * speed_factor);

	return (bau);
}

/*
 * s1394_bandwidth_free()
 *    is used to free up isochronous bandwidth.  A number of bandwidth
 *    allocation units and a generation are passed. The request is sent
 *    to whichever node is the IRM for this amount of bandwidth.  If it
 *    fails because of a bus reset it can be retried. If it fails for
 *    another reason the bandwidth may already be freed or there may
 *    be no IRM.
 */
int
s1394_bandwidth_free(s1394_hal_t *hal, uint32_t bw_alloc_units,
    uint_t generation, int *result)
{
	cmd1394_cmd_t	*cmd;
	uint64_t	IRM_ID_addr;
	uint32_t	compare;
	uint32_t	swap;
	uint32_t	old_value;
	uint32_t	temp_value;
	uint_t		hal_node_num;
	uint_t		IRM_node;
	int		ret;
	int		i;
	int		num_retries = S1394_ISOCH_ALLOC_RETRIES;

	/* Lock the topology tree */
	mutex_enter(&hal->topology_tree_mutex);

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	IRM_node = hal->IRM_node;

	/* Unlock the topology tree */
	mutex_exit(&hal->topology_tree_mutex);

	/* Make sure there is a valid IRM on the bus */
	if (IRM_node == -1) {
		*result = CMD1394_ERETRIES_EXCEEDED;
		return (DDI_FAILURE);
	}

	/* Send compare-swap to BANDWIDTH_AVAILABLE */
	/* register on the Isoch Rsrc Mgr */
	if (IRM_node == hal_node_num) {
		i = num_retries;
		do {
			(void) HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
			    (IEEE1394_SCSR_BANDWIDTH_AVAIL &
			    IEEE1394_CSR_OFFSET_MASK), &old_value);

			/* Check that the generation has not changed */
			if (generation != hal->generation_count) {
				*result = CMD1394_EBUSRESET;
				return (DDI_FAILURE);
			}

			temp_value = (old_value + bw_alloc_units);
			if ((temp_value >= old_value) &&
			    (temp_value <= IEEE1394_BANDWIDTH_MAX)) {
				compare = old_value;
				swap	= temp_value;
			} else {
				*result = CMD1394_ERETRIES_EXCEEDED;
				return (DDI_FAILURE);
			}

			ret = HAL_CALL(hal).csr_cswap32(
			    hal->halinfo.hal_private, generation,
			    (IEEE1394_SCSR_BANDWIDTH_AVAIL &
			    IEEE1394_CSR_OFFSET_MASK), compare, swap,
			    &old_value);
			if (ret != DDI_SUCCESS) {
				*result = CMD1394_EBUSRESET;
				return (DDI_FAILURE);
			}

			if (old_value == compare) {
				*result = CMD1394_CMDSUCCESS;
				return (DDI_SUCCESS);
			}
		} while (i--);

		*result = CMD1394_ERETRIES_EXCEEDED;
		return (DDI_FAILURE);

	} else {
		/* Remote */
		if (s1394_alloc_cmd(hal, 0, &cmd) != DDI_SUCCESS) {
			*result = CMD1394_EUNKNOWN_ERROR;
			return (DDI_FAILURE);
		}

		cmd->cmd_options = (CMD1394_CANCEL_ON_BUS_RESET |
		    CMD1394_OVERRIDE_ADDR | CMD1394_BLOCKING);
		cmd->cmd_type = CMD1394_ASYNCH_LOCK_32;
		IRM_ID_addr = (IEEE1394_ADDR_BUS_ID_MASK |
		    IEEE1394_SCSR_BANDWIDTH_AVAIL) |
		    (((uint64_t)hal->IRM_node) << IEEE1394_ADDR_PHY_ID_SHIFT);
		cmd->cmd_addr		   = IRM_ID_addr;
		cmd->bus_generation	   = generation;
		cmd->cmd_u.l32.arg_value   = IEEE1394_BANDWIDTH_MAX;
		cmd->cmd_u.l32.data_value  = bw_alloc_units;
		cmd->cmd_u.l32.num_retries = num_retries;
		cmd->cmd_u.l32.lock_type   = CMD1394_LOCK_THRESH_ADD;

		ret = s1394_split_lock_req(hal, NULL, cmd);

		if (ret == DDI_SUCCESS) {
			if (cmd->cmd_result == CMD1394_CMDSUCCESS) {
				*result = cmd->cmd_result;

				/* Need to free the command */
				(void) s1394_free_cmd(hal, &cmd);

				return (DDI_SUCCESS);

			} else {
				*result = cmd->cmd_result;
				/* Need to free the command */
				(void) s1394_free_cmd(hal, &cmd);

				return (DDI_FAILURE);
			}
		} else {
			*result = cmd->cmd_result;
			/* Need to free the command */
			(void) s1394_free_cmd(hal, &cmd);

			return (DDI_FAILURE);
		}
	}
}

/*
 * s1394_isoch_cec_list_insert()
 *    is used to insert an Isoch CEC into a given HAL's list of Isoch CECs.
 */
void
s1394_isoch_cec_list_insert(s1394_hal_t *hal, s1394_isoch_cec_t *cec)
{
	s1394_isoch_cec_t *cec_temp;

	ASSERT(MUTEX_HELD(&hal->isoch_cec_list_mutex));

	/* Is the Isoch CEC list empty? */
	if ((hal->isoch_cec_list_head == NULL) &&
	    (hal->isoch_cec_list_tail == NULL)) {

		hal->isoch_cec_list_head = cec;
		hal->isoch_cec_list_tail = cec;

		cec->cec_next = NULL;
		cec->cec_prev = NULL;

	} else {
		cec->cec_next = hal->isoch_cec_list_head;
		cec->cec_prev = NULL;
		cec_temp = hal->isoch_cec_list_head;
		cec_temp->cec_prev = cec;

		hal->isoch_cec_list_head = cec;
	}
}

/*
 * s1394_isoch_cec_list_remove()
 *    is used to remove an Isoch CEC from a given HAL's list of Isoch CECs.
 */
void
s1394_isoch_cec_list_remove(s1394_hal_t *hal, s1394_isoch_cec_t *cec)
{
	s1394_isoch_cec_t *prev_cec;
	s1394_isoch_cec_t *next_cec;

	ASSERT(MUTEX_HELD(&hal->isoch_cec_list_mutex));

	prev_cec = cec->cec_prev;
	next_cec = cec->cec_next;
	cec->cec_prev = NULL;
	cec->cec_next = NULL;

	if (prev_cec != NULL) {
		prev_cec->cec_next = next_cec;

	} else {
		if (hal->isoch_cec_list_head == cec)
			hal->isoch_cec_list_head = next_cec;
	}

	if (next_cec != NULL) {
		next_cec->cec_prev = prev_cec;

	} else {
		if (hal->isoch_cec_list_tail == cec)
			hal->isoch_cec_list_tail = prev_cec;
	}
}

/*
 * s1394_isoch_cec_member_list_insert()
 *    is used to insert a new member (target) into the list of members for
 *    a given Isoch CEC.
 */
/* ARGSUSED */
void
s1394_isoch_cec_member_list_insert(s1394_hal_t *hal, s1394_isoch_cec_t *cec,
    s1394_isoch_cec_member_t *member)
{
	s1394_isoch_cec_member_t *member_temp;

	ASSERT(MUTEX_HELD(&cec->isoch_cec_mutex));

	/* Is the Isoch CEC member list empty? */
	if ((cec->cec_member_list_head == NULL) &&
	    (cec->cec_member_list_tail == NULL)) {

		cec->cec_member_list_head = member;
		cec->cec_member_list_tail = member;
		member->cec_mem_next = NULL;
		member->cec_mem_prev = NULL;

	} else if (member->cec_mem_options & T1394_TALKER) {
		/* Put talker at the head of the list */
		member->cec_mem_next = cec->cec_member_list_head;
		member->cec_mem_prev = NULL;
		member_temp = cec->cec_member_list_head;
		member_temp->cec_mem_prev = member;
		cec->cec_member_list_head = member;

	} else {
		/* Put listeners at the tail of the list */
		member->cec_mem_prev = cec->cec_member_list_tail;
		member->cec_mem_next = NULL;
		member_temp = cec->cec_member_list_tail;
		member_temp->cec_mem_next = member;
		cec->cec_member_list_tail = member;
	}
}

/*
 * s1394_isoch_cec_member_list_remove()
 *    is used to remove a member (target) from the list of members for
 *    a given Isoch CEC.
 */
/* ARGSUSED */
void
s1394_isoch_cec_member_list_remove(s1394_hal_t *hal, s1394_isoch_cec_t *cec,
    s1394_isoch_cec_member_t *member)
{
	s1394_isoch_cec_member_t *prev_member;
	s1394_isoch_cec_member_t *next_member;

	ASSERT(MUTEX_HELD(&cec->isoch_cec_mutex));

	prev_member = member->cec_mem_prev;
	next_member = member->cec_mem_next;

	member->cec_mem_prev = NULL;
	member->cec_mem_next = NULL;

	if (prev_member != NULL) {
		prev_member->cec_mem_next = next_member;

	} else {
		if (cec->cec_member_list_head == member)
			cec->cec_member_list_head = next_member;
	}

	if (next_member != NULL) {
		next_member->cec_mem_prev = prev_member;

	} else {
		if (cec->cec_member_list_tail == member)
			cec->cec_member_list_tail = prev_member;
	}
}
