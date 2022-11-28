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
 * s1394_csr.c
 *    1394 Services Layer CSR and Config ROM Routines
 *    Contains all of the CSR callback routines for various required
 *    CSR registers.  Also contains routines for their initialization
 *    and destruction, as well as routines to handle the processing
 *    of Config ROM update requests.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>
#include <sys/1394/ieee1212.h>

static void s1394_CSR_state_clear(cmd1394_cmd_t *req);

static void s1394_CSR_state_set(cmd1394_cmd_t *req);

static void s1394_CSR_node_ids(cmd1394_cmd_t *req);

static void s1394_CSR_reset_start(cmd1394_cmd_t *req);

static void s1394_CSR_split_timeout(cmd1394_cmd_t *req);

static void s1394_CSR_argument_regs(cmd1394_cmd_t *req);

static void s1394_CSR_test_regs(cmd1394_cmd_t *req);

static void s1394_CSR_interrupt_regs(cmd1394_cmd_t *req);

static void s1394_CSR_clock_regs(cmd1394_cmd_t *req);

static void s1394_CSR_message_regs(cmd1394_cmd_t *req);

static void s1394_CSR_cycle_time(cmd1394_cmd_t *req);

static void s1394_CSR_bus_time(cmd1394_cmd_t *req);

static void s1394_CSR_busy_timeout(cmd1394_cmd_t *req);

static void s1394_CSR_IRM_regs(cmd1394_cmd_t *req);

static void s1394_CSR_topology_map(cmd1394_cmd_t *req);

static void s1394_common_CSR_routine(s1394_hal_t *hal, cmd1394_cmd_t *req);

static int s1394_init_config_rom_structures(s1394_hal_t *hal);

static int s1394_destroy_config_rom_structures(s1394_hal_t *hal);

/*
 * s1394_setup_CSR_space()
 *    setups up the local host's CSR registers and callback routines.
 */
int
s1394_setup_CSR_space(s1394_hal_t *hal)
{
	s1394_addr_space_blk_t	*curr_blk;
	t1394_alloc_addr_t	addr;
	t1394_addr_enable_t	rw_flags;
	int			result;

	/*
	 * Although they are not freed up in this routine, if
	 * one of the s1394_claim_addr_blk() routines fails,
	 * all of the previously successful claims will be
	 * freed up in s1394_destroy_addr_space() upon returning
	 * DDI_FAILURE from this routine.
	 */

	rw_flags = T1394_ADDR_RDENBL | T1394_ADDR_WRENBL;

	/*
	 * STATE_CLEAR
	 *    see IEEE 1394-1995, Section 8.3.2.2.1 or
	 *    IEEE 1212-1994, Section 7.4.1
	 */
	addr.aa_address	= IEEE1394_CSR_STATE_CLEAR;
	addr.aa_length	= IEEE1394_QUADLET;
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_state_clear;
	addr.aa_evts.recv_write_request	= s1394_CSR_state_clear;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * STATE_SET
	 *    see IEEE 1394-1995, Section 8.3.2.2.2 or
	 *    IEEE 1212-1994, Section 7.4.2
	 */
	addr.aa_address	= IEEE1394_CSR_STATE_SET;
	addr.aa_length	= IEEE1394_QUADLET;
	addr.aa_enable	= T1394_ADDR_WRENBL;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= NULL;
	addr.aa_evts.recv_write_request	= s1394_CSR_state_set;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * NODE_IDS
	 *    see IEEE 1394-1995, Section 8.3.2.2.3 or
	 *    IEEE 1212-1994, Section 7.4.3
	 */
	addr.aa_address	= IEEE1394_CSR_NODE_IDS;
	addr.aa_length	= IEEE1394_QUADLET;
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_node_ids;
	addr.aa_evts.recv_write_request = s1394_CSR_node_ids;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * RESET_START
	 *    see IEEE 1394-1995, Section 8.3.2.2.4 or
	 *    IEEE 1212-1994, Section 7.4.4
	 */
	addr.aa_address	= IEEE1394_CSR_RESET_START;
	addr.aa_length	= IEEE1394_QUADLET;
	addr.aa_enable	= T1394_ADDR_WRENBL;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= NULL;
	addr.aa_evts.recv_write_request	= s1394_CSR_reset_start;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * SPLIT_TIMEOUT
	 *    see IEEE 1394-1995, Section 8.3.2.2.6 or
	 *    IEEE 1212-1994, Section 7.4.7
	 */
	addr.aa_address	= IEEE1394_CSR_SPLIT_TIMEOUT_HI;
	addr.aa_length	= IEEE1394_OCTLET;
	addr.aa_enable	= rw_flags;
	addr.aa_type = T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_split_timeout;
	addr.aa_evts.recv_write_request	= s1394_CSR_split_timeout;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * ARGUMENT_HI and ARGUMENT_LO
	 *    see IEEE 1394-1995, Section 8.3.2.2.7 or
	 *    IEEE 1212-1994, Section 7.4.8
	 */
	addr.aa_address	= IEEE1394_CSR_ARG_HI;
	addr.aa_length	= 2 * (IEEE1394_QUADLET);
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_argument_regs;
	addr.aa_evts.recv_write_request	= s1394_CSR_argument_regs;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * TEST_START and TEST_STATUS
	 *    see IEEE 1394-1995, Section 8.3.2.2.7 or
	 *    IEEE 1212-1994, Section 7.4.9 - 7.4.10
	 */
	addr.aa_address	= IEEE1394_CSR_TEST_START;
	addr.aa_length	= 2 * (IEEE1394_QUADLET);
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_test_regs;
	addr.aa_evts.recv_write_request	= s1394_CSR_test_regs;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * INTERRUPT_TARGET and INTERRUPT_MASK
	 *    see IEEE 1394-1995, Section 8.3.2.2.9 or
	 *    IEEE 1212-1994, Section 7.4.15 - 7.4.16
	 */
	addr.aa_address	= IEEE1394_CSR_INTERRUPT_TARGET;
	addr.aa_length	= 2 * (IEEE1394_QUADLET);
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_interrupt_regs;
	addr.aa_evts.recv_write_request	= s1394_CSR_interrupt_regs;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * CLOCK_VALUE, CLOCK_TICK_PERIOD, CLOCK_INFO, etc.
	 *    see IEEE 1394-1995, Section 8.3.2.2.10 or
	 *    IEEE 1212-1994, Section 7.4.17 - 7.4.20
	 */
	addr.aa_address	= IEEE1394_CSR_CLOCK_VALUE;
	addr.aa_length	= IEEE1394_CSR_CLOCK_VALUE_SZ;
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_clock_regs;
	addr.aa_evts.recv_write_request	= s1394_CSR_clock_regs;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * MESSAGE_REQUEST and MESSAGE_RESPONSE
	 *    see IEEE 1394-1995, Section 8.3.2.2.11 or
	 *    IEEE 1212-1994, Section 7.4.21
	 */
	addr.aa_address	= IEEE1394_CSR_MESSAGE_REQUEST;
	addr.aa_length	= IEEE1394_CSR_MESSAGE_REQUEST_SZ;
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_message_regs;
	addr.aa_evts.recv_write_request	= s1394_CSR_message_regs;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * CYCLE_TIME
	 *    see IEEE 1394-1995, Section 8.3.2.3.1
	 */
	addr.aa_address	= IEEE1394_SCSR_CYCLE_TIME;
	addr.aa_length	= IEEE1394_QUADLET;
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_cycle_time;
	addr.aa_evts.recv_write_request	= s1394_CSR_cycle_time;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * BUS_TIME
	 *    see IEEE 1394-1995, Section 8.3.2.3.2
	 */
	addr.aa_address = IEEE1394_SCSR_BUS_TIME;
	addr.aa_length	= IEEE1394_QUADLET;
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_bus_time;
	addr.aa_evts.recv_write_request	= s1394_CSR_bus_time;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * BUSY_TIMEOUT
	 *    see IEEE 1394-1995, Section 8.3.2.3.5
	 */
	addr.aa_address	= IEEE1394_SCSR_BUSY_TIMEOUT;
	addr.aa_length	= IEEE1394_QUADLET;
	addr.aa_enable	= rw_flags;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_busy_timeout;
	addr.aa_evts.recv_write_request	= s1394_CSR_busy_timeout;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * BUS_MANAGER_ID
	 * BANDWIDTH_AVAILABLE
	 * CHANNELS_AVAILABLE
	 *    see IEEE 1394-1995, Section 8.3.2.3.6 - 8.3.2.3.8
	 */
	addr.aa_address	= IEEE1394_SCSR_BUSMGR_ID;
	addr.aa_length	= 3 * (IEEE1394_QUADLET);
	addr.aa_enable	= T1394_ADDR_RDENBL | T1394_ADDR_LKENBL;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_IRM_regs;
	addr.aa_evts.recv_write_request	= NULL;
	addr.aa_evts.recv_lock_request	= s1394_CSR_IRM_regs;
	addr.aa_kmem_bufp = NULL;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Reserved for Configuration ROM
	 *    see IEEE 1394-1995, Section 8.3.2.5.3
	 */
	addr.aa_address	= IEEE1394_CONFIG_ROM_ADDR;
	addr.aa_length	= IEEE1394_CONFIG_ROM_SZ;
	result = s1394_reserve_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * TOPOLOGY_MAP
	 *    see IEEE 1394-1995, Section 8.3.2.4.1
	 */
	hal->CSR_topology_map = kmem_zalloc(IEEE1394_UCSR_TOPOLOGY_MAP_SZ,
	    KM_SLEEP);
	addr.aa_address	= IEEE1394_UCSR_TOPOLOGY_MAP;
	addr.aa_length	= IEEE1394_UCSR_TOPOLOGY_MAP_SZ;
	addr.aa_enable	= T1394_ADDR_RDENBL;
	addr.aa_type	= T1394_ADDR_FIXED;
	addr.aa_evts.recv_read_request	= s1394_CSR_topology_map;
	addr.aa_evts.recv_write_request	= NULL;
	addr.aa_evts.recv_lock_request	= NULL;
	addr.aa_kmem_bufp = (caddr_t)hal->CSR_topology_map;
	addr.aa_arg	  = hal;
	result = s1394_claim_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		kmem_free((void *)hal->CSR_topology_map,
		    IEEE1394_UCSR_TOPOLOGY_MAP_SZ);
		return (DDI_FAILURE);
	}
	curr_blk = (s1394_addr_space_blk_t *)(addr.aa_hdl);
	/* Set up the block so that we free kmem_bufp at detach */
	curr_blk->free_kmem_bufp = B_TRUE;

	/*
	 * Reserve the SPEED_MAP
	 *    see IEEE 1394-1995, Section 8.3.2.4.1
	 *    (obsoleted in P1394A)
	 */
	addr.aa_address	= IEEE1394_UCSR_SPEED_MAP;
	addr.aa_length	= IEEE1394_UCSR_SPEED_MAP_SZ;
	result = s1394_reserve_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Reserved - Boundary between reserved Serial Bus
	 * dependent registers and other CSR register space.
	 * See IEEE 1394-1995, Table 8-4 for this address.
	 *
	 * This quadlet is reserved as a way of preventing
	 * the inadvertant allocation of a part of CSR space
	 * that will likely be used by future specifications
	 */
	addr.aa_address	= IEEE1394_UCSR_RESERVED_BOUNDARY;
	addr.aa_length	= IEEE1394_QUADLET;
	result = s1394_reserve_addr_blk(hal, &addr);
	if (result != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * s1394_CSR_state_clear()
 *    handles all requests to the STATE_CLEAR CSR register.  It enforces
 *    that certain bits that can be twiddled only by a given node (IRM or
 *    Bus Manager).
 */
static void
s1394_CSR_state_clear(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;
	uint32_t	data;
	uint_t		offset;
	uint_t		is_from;
	uint_t		should_be_from;
	int		result;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	/* Register offset */
	offset = req->cmd_addr & IEEE1394_CSR_OFFSET_MASK;

	/* Verify that request is quadlet aligned */
	if ((offset & 0x3) != 0) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Only writes from IRM or Bus Mgr allowed (in some cases) */
	mutex_enter(&hal->topology_tree_mutex);
	is_from = IEEE1394_NODE_NUM(req->nodeID);
	if (hal->bus_mgr_node != -1)
		should_be_from = IEEE1394_NODE_NUM(hal->bus_mgr_node);
	else if (hal->IRM_node != -1)
		should_be_from = IEEE1394_NODE_NUM(hal->IRM_node);
	else
		should_be_from = S1394_INVALID_NODE_NUM;
	mutex_exit(&hal->topology_tree_mutex);

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
		/*
		 * The csr_read() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented. But although the STATE_CLEAR register
		 * is required to be implemented and readable, we will
		 * return IEEE1394_RESP_ADDRESS_ERROR in the response if
		 * we ever see this error.
		 */
		result = HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
		    offset, &data);
		if (result == DDI_SUCCESS) {
			req->cmd_u.q.quadlet_data = data;
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	case CMD1394_ASYNCH_WR_QUAD:
		data = req->cmd_u.q.quadlet_data;

		/* CMSTR bit - request must be from bus_mgr/IRM */
		if (is_from != should_be_from) {
			data = data & ~IEEE1394_CSR_STATE_CMSTR;
		}

		mutex_enter(&hal->topology_tree_mutex);
		/* DREQ bit - disabling DREQ can come from anyone */
		if (data & IEEE1394_CSR_STATE_DREQ) {
			hal->disable_requests_bit = 0;
			if (hal->hal_state == S1394_HAL_DREQ)
				hal->hal_state = S1394_HAL_NORMAL;
		}

		/* ABDICATE bit */
		if (data & IEEE1394_CSR_STATE_ABDICATE) {
			hal->abdicate_bus_mgr_bit = 0;
		}
		mutex_exit(&hal->topology_tree_mutex);
		/*
		 * The csr_write() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented. But although the STATE_CLEAR register
		 * is required to be implemented and writeable, we will
		 * return IEEE1394_RESP_ADDRESS_ERROR in the response if
		 * we ever see this error.
		 */
		result = HAL_CALL(hal).csr_write(hal->halinfo.hal_private,
		    offset, data);
		if (result == DDI_SUCCESS) {
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	default:
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	}

	(void) s1394_send_response(hal, req);
}

/*
 * s1394_CSR_state_set()
 *    handles all requests to the STATE_SET CSR register. It enforces that
 *    certain bits that can be twiddled only by a given node (IRM or Bus
 *    Manager).
 */
static void
s1394_CSR_state_set(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;
	uint32_t	data;
	uint_t		offset;
	uint_t		is_from;
	uint_t		should_be_from;
	uint_t		hal_node_num;
	uint_t		hal_number_of_nodes;
	int		result;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	/* Register offset */
	offset = req->cmd_addr & IEEE1394_CSR_OFFSET_MASK;

	/* Verify that request is quadlet aligned */
	if ((offset & 0x3) != 0) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	/* Only writes from IRM or Bus Mgr allowed (in some cases) */
	mutex_enter(&hal->topology_tree_mutex);
	is_from = IEEE1394_NODE_NUM(req->nodeID);
	if (hal->bus_mgr_node != -1)
		should_be_from = IEEE1394_NODE_NUM(hal->bus_mgr_node);
	else if (hal->IRM_node != -1)
		should_be_from = IEEE1394_NODE_NUM(hal->IRM_node);
	else
		should_be_from = S1394_INVALID_NODE_NUM;
	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);
	hal_number_of_nodes = hal->number_of_nodes;
	mutex_exit(&hal->topology_tree_mutex);

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_WR_QUAD:
		data = req->cmd_u.q.quadlet_data;

		/* CMSTR bit - request must be from bus_mgr/IRM */
		/*		& must be root to have bit set */
		if ((is_from != should_be_from) ||
		    (hal_node_num != (hal_number_of_nodes - 1))) {
			data = data & ~IEEE1394_CSR_STATE_CMSTR;
		}

		mutex_enter(&hal->topology_tree_mutex);
		/* DREQ bit - only bus_mgr/IRM can set this bit */
		if (is_from != should_be_from) {
			data = data & ~IEEE1394_CSR_STATE_DREQ;

		} else if (data & IEEE1394_CSR_STATE_DREQ) {
			hal->disable_requests_bit = 1;
			if (hal->hal_state == S1394_HAL_NORMAL)
				hal->hal_state = S1394_HAL_DREQ;
		}
		/* ABDICATE bit */
		if (data & IEEE1394_CSR_STATE_ABDICATE) {
			hal->abdicate_bus_mgr_bit = 1;
		}
		mutex_exit(&hal->topology_tree_mutex);
		/*
		 * The csr_write() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented. But although the STATE_SET register
		 * is required to be implemented and writeable, we will
		 * return IEEE1394_RESP_ADDRESS_ERROR in the response if
		 * we ever see this error.
		 */
		result = HAL_CALL(hal).csr_write(hal->halinfo.hal_private,
		    offset, data);
		if (result == DDI_SUCCESS) {
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	default:
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	}

	(void) s1394_send_response(hal, req);
}

/*
 * s1394_CSR_node_ids()
 *    handles all requests to the NODE_IDS CSR register.  It passes all
 *    requests to the common routine - s1394_common_CSR_routine().
 */
static void
s1394_CSR_node_ids(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	s1394_common_CSR_routine(hal, req);
}

/*
 * s1394_CSR_reset_start()
 *    handles all requests to the RESET_START CSR register. Only write
 *    requests are legal, everything else gets a type_error response.
 */
static void
s1394_CSR_reset_start(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;
	uint32_t	data;
	uint_t		offset;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	/* RESET_START register offset */
	offset = req->cmd_addr & IEEE1394_CSR_OFFSET_MASK;

	/* Verify that request is quadlet aligned */
	if ((offset & 0x3) != 0) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_WR_QUAD:
		data = req->cmd_u.q.quadlet_data;
		/*
		 * The csr_write() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented. Because we don't do any thing with
		 * the RESET_START register we will ignore failures and
		 * return IEEE1394_RESP_COMPLETE regardless.
		 */
		(void) HAL_CALL(hal).csr_write(hal->halinfo.hal_private,
		    offset, data);
		req->cmd_result = IEEE1394_RESP_COMPLETE;
		break;

	default:
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	}

	(void) s1394_send_response(hal, req);
}

/*
 * s1394_CSR_split_timeout()
 *    handles all requests to the SPLIT_TIMEOUT CSR register.  It passes all
 *    requests to the common routine - s1394_common_CSR_routine().
 */
static void
s1394_CSR_split_timeout(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	s1394_common_CSR_routine(hal, req);
}

/*
 * s1394_CSR_argument_regs()
 *    handles all requests to the ARGUMENT CSR registers.  It passes all
 *    requests to the common routine - s1394_common_CSR_routine().
 */
static void
s1394_CSR_argument_regs(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	s1394_common_CSR_routine(hal, req);
}

/*
 * s1394_CSR_test_regs()
 *    handles all requests to the TEST CSR registers. It passes all requests
 *    to the common routine - s1394_common_CSR_routine().
 */
static void
s1394_CSR_test_regs(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;
	uint_t		offset;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	/* TEST register offset */
	offset = req->cmd_addr & IEEE1394_CSR_OFFSET_MASK;

	/* TEST_STATUS is Read-Only */
	if ((offset == (IEEE1394_CSR_TEST_STATUS & IEEE1394_CSR_OFFSET_MASK)) &&
	    (req->cmd_type == CMD1394_ASYNCH_WR_QUAD)) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
	} else {
		s1394_common_CSR_routine(hal, req);
	}
}

/*
 * s1394_CSR_interrupt_regs()
 *    handles all requests to the INTERRUPT CSR registers.  It passes all
 *    requests to the common routine - s1394_common_CSR_routine().
 */
static void
s1394_CSR_interrupt_regs(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	s1394_common_CSR_routine(hal, req);
}

/*
 * s1394_CSR_clock_regs()
 *    handles all requests to the CLOCK CSR registers.  It passes all
 *    requests to the common routine - s1394_common_CSR_routine().
 */
static void
s1394_CSR_clock_regs(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	s1394_common_CSR_routine(hal, req);
}

/*
 * s1394_CSR_message_regs()
 *    handles all requests to the MESSAGE CSR registers.  It passes all
 *    requests to the common routine - s1394_common_CSR_routine().
 */
static void
s1394_CSR_message_regs(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	s1394_common_CSR_routine(hal, req);
}

/*
 * s1394_CSR_cycle_time()
 *    handles all requests to the CYCLE_TIME CSR register.
 */
static void
s1394_CSR_cycle_time(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;
	uint32_t	data;
	uint_t		offset;
	int		result;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	/* CYCLE_TIME register offset */
	offset = req->cmd_addr & IEEE1394_CSR_OFFSET_MASK;

	/* Verify that request is quadlet aligned */
	if ((offset & 0x3) != 0) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
		/*
		 * The csr_read() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented. But although the CYCLE_TIME register
		 * is required to be implemented on devices capable of
		 * providing isochronous services (like us), we will
		 * return IEEE1394_RESP_ADDRESS_ERROR in the response
		 * if we ever see this error.
		 */
		result = HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
		    offset, &data);
		if (result == DDI_SUCCESS) {
			req->cmd_u.q.quadlet_data = data;
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	case CMD1394_ASYNCH_WR_QUAD:
		data = req->cmd_u.q.quadlet_data;
		/*
		 * The csr_write() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented. But although the CYCLE_TIME register
		 * is required to be implemented on devices capable of
		 * providing isochronous services (like us), the effects
		 * of a write are "node-dependent" so we will return
		 * IEEE1394_RESP_ADDRESS_ERROR in the response if we
		 * ever see this error.
		 */
		result = HAL_CALL(hal).csr_write(hal->halinfo.hal_private,
		    offset, data);
		if (result == DDI_SUCCESS) {
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	default:
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	}

	(void) s1394_send_response(hal, req);
}

/*
 * s1394_CSR_bus_time()
 *    handles all requests to the BUS_TIME CSR register.  It enforces that
 *    only a broadcast write request from the IRM or Bus Manager can change
 *    its value.
 */
static void
s1394_CSR_bus_time(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;
	uint32_t	data;
	uint_t		offset;
	uint_t		is_from;
	uint_t		should_be_from;
	int		result;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	/* BUS_TIME register offset */
	offset = req->cmd_addr & IEEE1394_CSR_OFFSET_MASK;

	/* Verify that request is quadlet aligned */
	if ((offset & 0x3) != 0) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
		/*
		 * The csr_read() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented. But although the BUS_TIME register
		 * is required to be implemented by devices capable of
		 * being cycle master (like us), we will return
		 * IEEE1394_RESP_ADDRESS_ERROR in the response if we
		 * ever see this error.
		 */
		result = HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
		    offset, &data);
		if (result == DDI_SUCCESS) {
			req->cmd_u.q.quadlet_data = data;
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	case CMD1394_ASYNCH_WR_QUAD:
		/* Only broadcast writes from IRM or Bus Mgr allowed */
		mutex_enter(&hal->topology_tree_mutex);
		is_from = IEEE1394_NODE_NUM(req->nodeID);
		if (hal->bus_mgr_node != -1)
			should_be_from = IEEE1394_NODE_NUM(hal->bus_mgr_node);
		else if (hal->IRM_node != -1)
			should_be_from = IEEE1394_NODE_NUM(hal->IRM_node);
		else
			should_be_from = S1394_INVALID_NODE_NUM;
		mutex_exit(&hal->topology_tree_mutex);

		if ((req->broadcast != 1) || (is_from != should_be_from)) {
			req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
			break;
		}

		data = req->cmd_u.q.quadlet_data;
		/*
		 * The csr_write() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented. But although the BUS_TIME register
		 * is required to be implemented on devices capable of
		 * being cycle master (like us), we will return
		 * IEEE1394_RESP_ADDRESS_ERROR in the response if we
		 * ever see this error.
		 */
		result = HAL_CALL(hal).csr_write(hal->halinfo.hal_private,
		    offset, data);
		if (result == DDI_SUCCESS) {
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	default:
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	}

	(void) s1394_send_response(hal, req);
}

/*
 * s1394_CSR_busy_timeout()
 *    handles all requests to the BUSY_TIMEOUT CSR register.  It passes all
 *    requests to the common routine - s1394_common_CSR_routine().
 */
static void
s1394_CSR_busy_timeout(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	s1394_common_CSR_routine(hal, req);
}

/*
 * s1394_CSR_IRM_regs()
 *    handles all requests to the IRM registers, including BANDWIDTH_AVAILABLE,
 *    CHANNELS_AVAILABLE, and the BUS_MANAGER_ID.  Only quadlet read and lock
 *    requests are allowed.
 */
static void
s1394_CSR_IRM_regs(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;
	uint32_t	generation;
	uint32_t	data;
	uint32_t	compare;
	uint32_t	swap;
	uint32_t	old;
	uint_t		offset;
	int		result;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	/* IRM register offset */
	offset = (req->cmd_addr & IEEE1394_CSR_OFFSET_MASK);

	/* Verify that request is quadlet aligned */
	if ((offset & 0x3) != 0) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
		return;
	}

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
		/*
		 * The csr_read() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented.  In many cases these registers will
		 * have been implemented in HW.  We are not likely to ever
		 * receive this callback.  If we do, though, we will
		 * return IEEE1394_RESP_ADDRESS_ERROR when we get an error
		 * and IEEE1394_RESP_COMPLETE for success.
		 */
		result = HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
		    offset, &data);
		if (result == DDI_SUCCESS) {
			req->cmd_u.q.quadlet_data = data;
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	case CMD1394_ASYNCH_LOCK_32:
		mutex_enter(&hal->topology_tree_mutex);
		generation = hal->generation_count;
		mutex_exit(&hal->topology_tree_mutex);
		if (req->cmd_u.l32.lock_type == CMD1394_LOCK_COMPARE_SWAP) {
			compare = req->cmd_u.l32.arg_value;
			swap = req->cmd_u.l32.data_value;
			/*
			 * The csr_cswap32() call can return DDI_FAILURE if
			 * the HAL is shutdown, if the register at "offset"
			 * is unimplemented, or if the generation has changed.
			 * In the last case, it shouldn't matter because the
			 * call to s1394_send_response will fail on a bad
			 * generation and the command will be freed.
			 */
			result = HAL_CALL(hal).csr_cswap32(
			    hal->halinfo.hal_private, generation,
			    offset, compare, swap, &old);
			if (result == DDI_SUCCESS) {
				req->cmd_u.l32.old_value = old;
				req->cmd_result = IEEE1394_RESP_COMPLETE;
			} else {
				req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
			}
			break;
		} else {
			req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		}

		break;

	default:
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	}

	(void) s1394_send_response(hal, req);
}

/*
 * s1394_CSR_topology_map()
 *    handles all request for the TOPOLOGY_MAP[].  Since it is implemented
 *    with backing store, there isn't much to do besides return success or
 *    failure.
 */
static void
s1394_CSR_topology_map(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal;

	hal = (s1394_hal_t *)req->cmd_callback_arg;

	/* Make sure it's a quadlet read request */
	if (req->cmd_type == CMD1394_ASYNCH_RD_QUAD)
		req->cmd_result = IEEE1394_RESP_COMPLETE;
	else
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;

	(void) s1394_send_response(hal, req);
}

/*
 * s1394_CSR_topology_map_update()
 *    is used to update the local host's TOPOLOGY_MAP[] buffer.  It copies in
 *    the SelfID packets, updates the generation and other fields, and
 *    computes the necessary CRC values before returning.
 *    Callers must be holding the topology_tree_mutex.
 */
void
s1394_CSR_topology_map_update(s1394_hal_t *hal)
{
	s1394_selfid_pkt_t *selfid_packet;
	uint32_t	   *tm_ptr;
	uint32_t	   *data_ptr;
	uint32_t	   node_count;
	uint32_t	   self_id_count;
	uint_t		   CRC;
	uint32_t	   length;
	int		   i, j, c;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	tm_ptr = (uint32_t *)hal->CSR_topology_map;
	data_ptr = (uint32_t *)&(tm_ptr[3]);

	c = 0;
	for (i = 0; i < hal->number_of_nodes; i++) {
		j = -1;
		selfid_packet = hal->selfid_ptrs[i];

		do {
			j++;
			data_ptr[c++] = selfid_packet[j].spkt_data;
		}
		while (IEEE1394_SELFID_ISMORE(&selfid_packet[j]));
	}

	/* Update Topology Map Generation */
	tm_ptr[1] = tm_ptr[1] + 1;

	/* Update Node_Count and Self_Id_Count */
	node_count = (i & IEEE1394_TOP_MAP_LEN_MASK);
	self_id_count = (c & IEEE1394_TOP_MAP_LEN_MASK);
	tm_ptr[2] = (node_count << IEEE1394_TOP_MAP_LEN_SHIFT) |
	    (self_id_count);

	/* Calculate CRC-16 */
	length = self_id_count + 2;
	CRC = s1394_CRC16(&(tm_ptr[1]), length);
	tm_ptr[0] = (length << IEEE1394_TOP_MAP_LEN_SHIFT) | CRC;
}

/*
 * s1394_CSR_topology_map_disable()
 *    is used to disable the local host's TOPOLOGY_MAP[] buffer (during bus
 *    reset processing).  It sets the topology map's length to zero to
 *    indicate that it is invalid.
 */
void
s1394_CSR_topology_map_disable(s1394_hal_t *hal)
{
	uint32_t *tm_ptr;

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	tm_ptr = (uint32_t *)hal->CSR_topology_map;

	/* Set length = 0 */
	tm_ptr[0] = tm_ptr[0] & IEEE1394_TOP_MAP_LEN_MASK;
}

/*
 * s1394_common_CSR_routine()
 *    is used to handle most of the CSR register requests.  They are passed
 *    to the appropriate HAL entry point for further processing.  Then they
 *    are filled in with an appropriate response code, and the response is sent.
 */
static void
s1394_common_CSR_routine(s1394_hal_t *hal, cmd1394_cmd_t *req)
{
	uint32_t data;
	uint_t	 offset;
	int	 result;

	/* Register offset */
	offset = (req->cmd_addr & IEEE1394_CSR_OFFSET_MASK);

	/* Verify that request is quadlet aligned */
	if ((offset & 0x3) != 0) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		(void) s1394_send_response(hal, req);
	}

	switch (req->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
		/*
		 * The csr_read() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented.  We will return IEEE1394_RESP_ADDRESS_ERROR
		 * in the response if we see this error.
		 */
		result = HAL_CALL(hal).csr_read(hal->halinfo.hal_private,
		    offset, &data);
		if (result == DDI_SUCCESS) {
			req->cmd_u.q.quadlet_data = data;
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	case CMD1394_ASYNCH_WR_QUAD:
		data = req->cmd_u.q.quadlet_data;
		/*
		 * The csr_read() call can return DDI_FAILURE if the HAL
		 * is shutdown or if the register at "offset" is
		 * unimplemented.  We will return IEEE1394_RESP_ADDRESS_ERROR
		 * in the response if we see this error.
		 */
		result = HAL_CALL(hal).csr_write(hal->halinfo.hal_private,
		    offset, data);
		if (result == DDI_SUCCESS) {
			req->cmd_result = IEEE1394_RESP_COMPLETE;
		} else {
			req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
		}
		break;

	default:
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	}

	(void) s1394_send_response(hal, req);
}

/*
 * s1394_init_local_config_rom()
 *    is called in the HAL attach routine - h1394_attach() - to setup the
 *    initial Config ROM entries on the local host, including the
 *    bus_info_block and the root and unit directories.
 */
int
s1394_init_local_config_rom(s1394_hal_t *hal)
{
	uint32_t *config_rom;
	uint32_t *node_unique_id_leaf;
	uint32_t *unit_dir;
	uint32_t *text_leaf;
	void	 *n_handle;
	uint64_t guid;
	uint32_t guid_hi, guid_lo;
	uint32_t bus_capabilities;
	uint32_t irmc, g;
	uint32_t module_vendor_id;
	uint32_t node_capabilities;
	uint32_t root_dir_len;
	uint32_t CRC;
	int	 status, i, ret;

	/* Setup Config ROM mutex */
	mutex_init(&hal->local_config_rom_mutex,
	    NULL, MUTEX_DRIVER, hal->halinfo.hw_interrupt);

	/* Allocate 1K for the Config ROM buffer */
	hal->local_config_rom = (uint32_t *)kmem_zalloc(IEEE1394_CONFIG_ROM_SZ,
	    KM_SLEEP);

	/* Allocate 1K for the temporary buffer */
	hal->temp_config_rom_buf = (uint32_t *)kmem_zalloc(
	    IEEE1394_CONFIG_ROM_SZ, KM_SLEEP);

	config_rom = hal->local_config_rom;

	/* Lock the Config ROM buffer */
	mutex_enter(&hal->local_config_rom_mutex);

	/* Build the config ROM structures */
	ret = s1394_init_config_rom_structures(hal);
	if (ret != DDI_SUCCESS) {
		/* Unlock the Config ROM buffer */
		mutex_exit(&hal->local_config_rom_mutex);
		kmem_free((void *)hal->temp_config_rom_buf,
		    IEEE1394_CONFIG_ROM_SZ);
		kmem_free((void *)hal->local_config_rom,
		    IEEE1394_CONFIG_ROM_SZ);
		mutex_destroy(&hal->local_config_rom_mutex);
		return (DDI_FAILURE);
	}
	/* Build the Bus_Info_Block - see IEEE 1394-1995, Section 8.3.2.5.4 */
	bus_capabilities = hal->halinfo.bus_capabilities;

	/*
	 * If we are Isoch Resource Manager capable then we are
	 * Bus Manager capable too.
	 */
	irmc = (bus_capabilities & IEEE1394_BIB_IRMC_MASK) >>
	    IEEE1394_BIB_IRMC_SHIFT;
	if (irmc)
		bus_capabilities = bus_capabilities | IEEE1394_BIB_BMC_MASK;

	/*
	 * Set generation to P1394a valid (but changeable)
	 * Even if we have a 1995 PHY, we will still provide
	 * certain P1394A functionality (especially with respect
	 * to Config ROM updates).  So we must publish this
	 * information.
	 */
	g = 2 << IEEE1394_BIB_GEN_SHIFT;
	bus_capabilities = bus_capabilities | g;

	/* Get the GUID */
	guid = hal->halinfo.guid;
	guid_hi = (uint32_t)(guid >> 32);
	guid_lo = (uint32_t)(guid & 0x00000000FFFFFFFF);

	config_rom[1] = 0x31333934;	/* "1394" */
	config_rom[2] = bus_capabilities;
	config_rom[3] = guid_hi;
	config_rom[4] = guid_lo;

	/* The CRC covers only our Bus_Info_Block */
	CRC = s1394_CRC16(&config_rom[1], 4);
	config_rom[0] = (0x04040000) | CRC;

	/* Do byte-swapping if necessary (x86) */
	for (i = 0; i < IEEE1394_BIB_QUAD_SZ; i++)
		config_rom[i] = T1394_DATA32(config_rom[i]);

	/* Build the Root_Directory - see IEEE 1394-1995, Section 8.3.2.5.5 */

	/* MODULE_VENDOR_ID - see IEEE 1394-1995, Section 8.3.2.5.5.1 */
	module_vendor_id = S1394_SUNW_OUI;

	/* NODE_CAPABILITIES - see IEEE 1394-1995, Section 8.3.2.5.5.2 */
	node_capabilities = hal->halinfo.node_capabilities &
	    IEEE1212_NODE_CAPABILITIES_MASK;
	root_dir_len = 2;

	config_rom[6] = (IEEE1212_MODULE_VENDOR_ID <<
	    IEEE1212_KEY_VALUE_SHIFT) | module_vendor_id;
	config_rom[7] = (IEEE1212_NODE_CAPABILITIES <<
	    IEEE1212_KEY_VALUE_SHIFT) | node_capabilities;

	CRC = s1394_CRC16(&config_rom[6], root_dir_len);
	config_rom[IEEE1394_BIB_QUAD_SZ] =
	    (root_dir_len << IEEE1394_CFG_ROM_LEN_SHIFT) | CRC;

	/* Do byte-swapping if necessary (x86) */
	for (i = IEEE1394_BIB_QUAD_SZ; i < 8; i++)
		config_rom[i] = T1394_DATA32(config_rom[i]);

	/* Build the Root Text leaf - see IEEE 1394-1995, Section 8.3.2.5.7 */
	text_leaf = (uint32_t *)kmem_zalloc(S1394_ROOT_TEXT_LEAF_SZ, KM_SLEEP);
	text_leaf[1] = 0x00000000;
	text_leaf[2] = 0x00000000;
	text_leaf[3] = 0x53756e20;	/* "Sun " */
	text_leaf[4] = 0x4d696372;	/* "Micr" */
	text_leaf[5] = 0x6f737973;	/* "osys" */
	text_leaf[6] = 0x74656d73;	/* "tems" */
	text_leaf[7] = 0x2c20496e;	/* ", In" */
	text_leaf[8] = 0x632e0000;	/* "c."   */
	CRC = s1394_CRC16(&text_leaf[1], S1394_ROOT_TEXT_LEAF_QUAD_SZ - 1);
	text_leaf[0] = (0x00080000) | CRC;

	/* Do byte-swapping if necessary (x86) */
	for (i = 0; i < 9; i++)
		text_leaf[i] = T1394_DATA32(text_leaf[i]);

	ret = s1394_add_config_rom_entry(hal, S1394_ROOT_TEXT_KEY, text_leaf,
	    S1394_ROOT_TEXT_LEAF_QUAD_SZ, &n_handle, &status);
	if (ret != DDI_SUCCESS) {
		kmem_free((void *)text_leaf, S1394_ROOT_TEXT_LEAF_SZ);
		/* Destroy the config_rom structures */
		(void) s1394_destroy_config_rom_structures(hal);
		/* Unlock the Config ROM buffer */
		mutex_exit(&hal->local_config_rom_mutex);
		kmem_free((void *)hal->temp_config_rom_buf,
		    IEEE1394_CONFIG_ROM_SZ);
		kmem_free((void *)hal->local_config_rom,
		    IEEE1394_CONFIG_ROM_SZ);
		mutex_destroy(&hal->local_config_rom_mutex);
		return (DDI_FAILURE);
	}
	kmem_free((void *)text_leaf, S1394_ROOT_TEXT_LEAF_SZ);

	/* Build the Node_Unique_Id leaf - IEEE 1394-1995, Sect. 8.3.2.5.7.1 */
	node_unique_id_leaf = (uint32_t *)kmem_zalloc(S1394_NODE_UNIQUE_ID_SZ,
	    KM_SLEEP);
	node_unique_id_leaf[1] = guid_hi;
	node_unique_id_leaf[2] = guid_lo;
	CRC = s1394_CRC16(&node_unique_id_leaf[1],
	    S1394_NODE_UNIQUE_ID_QUAD_SZ - 1);
	node_unique_id_leaf[0] = (0x00020000) | CRC;

	/* Do byte-swapping if necessary (x86) */
	for (i = 0; i < S1394_NODE_UNIQUE_ID_QUAD_SZ; i++)
		node_unique_id_leaf[i] = T1394_DATA32(node_unique_id_leaf[i]);

	ret = s1394_add_config_rom_entry(hal, S1394_NODE_UNIQUE_ID_KEY,
	    node_unique_id_leaf, S1394_NODE_UNIQUE_ID_QUAD_SZ, &n_handle,
	    &status);
	if (ret != DDI_SUCCESS) {
		kmem_free((void *)node_unique_id_leaf,
		    S1394_NODE_UNIQUE_ID_SZ);
		/* Destroy the config_rom structures */
		(void) s1394_destroy_config_rom_structures(hal);
		/* Unlock the Config ROM buffer */
		mutex_exit(&hal->local_config_rom_mutex);
		kmem_free((void *)hal->temp_config_rom_buf,
		    IEEE1394_CONFIG_ROM_SZ);
		kmem_free((void *)hal->local_config_rom,
		    IEEE1394_CONFIG_ROM_SZ);
		mutex_destroy(&hal->local_config_rom_mutex);
		return (DDI_FAILURE);
	}
	kmem_free((void *)node_unique_id_leaf, S1394_NODE_UNIQUE_ID_SZ);

	/* Build the Unit_Directory for 1394 Framework */
	unit_dir = (uint32_t *)kmem_zalloc(S1394_UNIT_DIR_SZ, KM_SLEEP);
	unit_dir[1] = 0x12080020;	/* Sun Microsystems */
	unit_dir[2] = 0x13000001;	/* Version 1 */
	unit_dir[3] = 0x81000001;	/* offset to the text leaf */
	CRC = s1394_CRC16(&unit_dir[1], 3);
	unit_dir[0] = (0x00030000) | CRC;

	/* Do byte-swapping if necessary (x86) */
	for (i = 0; i < 4; i++)
		unit_dir[i] = T1394_DATA32(unit_dir[i]);

	/* Build the Unit Directory text leaf */
	unit_dir[5] = 0x00000000;
	unit_dir[6] = 0x00000000;
	unit_dir[7] = 0x536f6c61;	/* "Sola" */
	unit_dir[8] = 0x72697320;	/* "ris " */
	unit_dir[9] = 0x31333934;	/* "1394" */
	unit_dir[10] = 0x20535720;	/* " SW " */
	unit_dir[11] = 0x4672616d;	/* "Fram" */
	unit_dir[12] = 0x65576f72;	/* "ewor" */
	unit_dir[13] = 0x6b000000;	/* "k"    */
	CRC = s1394_CRC16(&unit_dir[5], 9);
	unit_dir[4] = (0x00090000) | CRC;

	/* Do byte-swapping if necessary (x86) */
	for (i = 4; i < S1394_UNIT_DIR_QUAD_SZ; i++)
		unit_dir[i] = T1394_DATA32(unit_dir[i]);

	ret = s1394_add_config_rom_entry(hal, S1394_UNIT_DIR_KEY, unit_dir,
	    S1394_UNIT_DIR_QUAD_SZ, &n_handle, &status);
	if (ret != DDI_SUCCESS) {
		kmem_free((void *)unit_dir, S1394_UNIT_DIR_SZ);
		/* Destroy the config_rom structures */
		(void) s1394_destroy_config_rom_structures(hal);
		/* Unlock the Config ROM buffer */
		mutex_exit(&hal->local_config_rom_mutex);
		kmem_free((void *)hal->temp_config_rom_buf,
		    IEEE1394_CONFIG_ROM_SZ);
		/* Free the 1K for the Config ROM buffer */
		kmem_free((void *)hal->local_config_rom,
		    IEEE1394_CONFIG_ROM_SZ);
		mutex_destroy(&hal->local_config_rom_mutex);
		return (DDI_FAILURE);
	}
	kmem_free((void *)unit_dir, S1394_UNIT_DIR_SZ);

	hal->config_rom_update_amount = (IEEE1394_CONFIG_ROM_QUAD_SZ -
	    hal->free_space);

	/* Unlock the Config ROM buffer */
	mutex_exit(&hal->local_config_rom_mutex);

	/*
	 * The update_config_rom() call can return DDI_FAILURE if the
	 * HAL is shutdown.
	 */
	(void) HAL_CALL(hal).update_config_rom(hal->halinfo.hal_private,
	    config_rom, IEEE1394_CONFIG_ROM_QUAD_SZ);

	return (DDI_SUCCESS);
}

/*
 * s1394_destroy_local_config_rom()
 *    is necessary for h1394_detach().  It undoes all the work that
 *    s1394_init_local_config_rom() had setup and more.  By pulling
 *    everything out of the conig rom structures and freeing them and their
 *    associated mutexes, the Config ROM is completely cleaned up.
 */
void
s1394_destroy_local_config_rom(s1394_hal_t *hal)
{
	/* Lock the Config ROM buffer */
	mutex_enter(&hal->local_config_rom_mutex);

	/* Destroy the config_rom structures */
	(void) s1394_destroy_config_rom_structures(hal);

	/* Unlock the Config ROM buffer */
	mutex_exit(&hal->local_config_rom_mutex);

	/* Free the 1K for the temporary buffer */
	kmem_free((void *)hal->temp_config_rom_buf, IEEE1394_CONFIG_ROM_SZ);
	/* Free the 1K for the Config ROM buffer */
	kmem_free((void *)hal->local_config_rom, IEEE1394_CONFIG_ROM_SZ);

	/* Setup Config ROM mutex */
	mutex_destroy(&hal->local_config_rom_mutex);
}

/*
 * s1394_init_config_rom_structures()
 *    initializes the structures that are used to maintain the local Config ROM.
 *    Callers must be holding the local_config_rom_mutex.
 */
static int
s1394_init_config_rom_structures(s1394_hal_t *hal)
{
	s1394_config_rom_t *root_directory;
	s1394_config_rom_t *rest_of_config_rom;

	ASSERT(MUTEX_HELD(&hal->local_config_rom_mutex));

	root_directory = (s1394_config_rom_t *)kmem_zalloc(
	    sizeof (s1394_config_rom_t), KM_SLEEP);

	root_directory->cfgrom_used = B_TRUE;
	root_directory->cfgrom_addr_lo = IEEE1394_BIB_QUAD_SZ;
	root_directory->cfgrom_addr_hi = IEEE1394_BIB_QUAD_SZ + 2;

	rest_of_config_rom = (s1394_config_rom_t *)kmem_zalloc(
	    sizeof (s1394_config_rom_t), KM_SLEEP);

	rest_of_config_rom->cfgrom_used = B_FALSE;
	rest_of_config_rom->cfgrom_addr_lo = root_directory->cfgrom_addr_hi + 1;
	rest_of_config_rom->cfgrom_addr_hi = IEEE1394_CONFIG_ROM_QUAD_SZ - 1;

	root_directory->cfgrom_next = rest_of_config_rom;
	root_directory->cfgrom_prev = NULL;
	rest_of_config_rom->cfgrom_next = NULL;
	rest_of_config_rom->cfgrom_prev = root_directory;

	hal->root_directory = root_directory;
	hal->free_space = IEEE1394_CONFIG_ROM_QUAD_SZ -
	    (rest_of_config_rom->cfgrom_addr_lo);

	return (DDI_SUCCESS);
}

/*
 * s1394_destroy_config_rom_structures()
 *    is used to destroy the structures that maintain the local Config ROM.
 *    Callers must be holding the local_config_rom_mutex.
 */
static int
s1394_destroy_config_rom_structures(s1394_hal_t *hal)
{
	s1394_config_rom_t *curr_blk;
	s1394_config_rom_t *next_blk;

	ASSERT(MUTEX_HELD(&hal->local_config_rom_mutex));

	curr_blk = hal->root_directory;

	while (curr_blk != NULL) {
		next_blk = curr_blk->cfgrom_next;
		kmem_free(curr_blk, sizeof (s1394_config_rom_t));
		curr_blk = next_blk;
	}

	return (DDI_SUCCESS);
}

/*
 * s1394_add_config_rom_entry()
 *    is used to add a new entry to the local host's config ROM.  By
 *    specifying a key and a buffer, it is possible to update the Root
 *    Directory to point to the new entry (in buffer).  Additionally, all
 *    of the relevant CRCs, lengths, and generations are updated as well.
 *    By returning a Config ROM "handle", we can allow targets to remove
 *    the corresponding entry.
 *    Callers must be holding the local_config_rom_mutex.
 */
int
s1394_add_config_rom_entry(s1394_hal_t *hal, uint8_t key, uint32_t *buffer,
    uint_t size, void **handle, int *status)
{
	s1394_config_rom_t *curr_blk;
	s1394_config_rom_t *new_blk;
	uint32_t	   *config_rom;
	uint32_t	   *temp_buf;
	uint32_t	   CRC;
	uint_t		   tmp_offset;
	uint_t		   tmp_size, temp;
	uint_t		   last_entry_offset;
	int		   i;

	ASSERT(MUTEX_HELD(&hal->local_config_rom_mutex));

	if (size > hal->free_space) {
		/* Out of space */
		*status = CMD1394_ERSRC_CONFLICT;
		return (DDI_FAILURE);
	}

	config_rom = hal->local_config_rom;
	temp_buf = hal->temp_config_rom_buf;

	/* Copy the Bus_Info_Block */
	bcopy(&config_rom[0], &temp_buf[0], IEEE1394_BIB_SZ);

	/* Copy and add to the Root_Directory */
	tmp_offset = hal->root_directory->cfgrom_addr_lo;
	tmp_size = (hal->root_directory->cfgrom_addr_hi - tmp_offset) + 1;
	tmp_size = tmp_size + 1;	/* For the new entry */
	bcopy(&config_rom[tmp_offset], &temp_buf[tmp_offset], tmp_size << 2);
	last_entry_offset = hal->root_directory->cfgrom_addr_hi + 1;

	curr_blk = hal->root_directory;
	curr_blk->cfgrom_addr_hi = curr_blk->cfgrom_addr_hi + 1;
	while (curr_blk->cfgrom_next != NULL) {
		if (curr_blk->cfgrom_next->cfgrom_used == B_TRUE) {
			tmp_offset = curr_blk->cfgrom_next->cfgrom_addr_lo;
			tmp_size = (curr_blk->cfgrom_next->cfgrom_addr_hi -
			    tmp_offset) + 1;

			bcopy(&config_rom[tmp_offset],
			    &temp_buf[tmp_offset + 1], tmp_size << 2);
			curr_blk->cfgrom_next->cfgrom_addr_lo++;
			curr_blk->cfgrom_next->cfgrom_addr_hi++;
			last_entry_offset =
			    curr_blk->cfgrom_next->cfgrom_addr_hi;

			tmp_offset = curr_blk->cfgrom_next->root_dir_offset;

			/* Swap... add one... then unswap */
			temp = T1394_DATA32(temp_buf[tmp_offset]);
			temp++;
			temp_buf[tmp_offset] = T1394_DATA32(temp);
		} else {
			curr_blk->cfgrom_next->cfgrom_addr_lo++;
			hal->free_space--;
			break;
		}

		curr_blk = curr_blk->cfgrom_next;
	}

	/* Get the pointer to the "free" space */
	curr_blk = curr_blk->cfgrom_next;

	/* Is it an exact fit? */
	if (hal->free_space == size) {
		curr_blk->cfgrom_used = B_TRUE;

	} else {		/* Must break this piece */
		new_blk = (s1394_config_rom_t *)kmem_zalloc(
		    sizeof (s1394_config_rom_t), KM_SLEEP);
		if (new_blk == NULL) {
			return (DDI_FAILURE);
		}

		new_blk->cfgrom_addr_hi = curr_blk->cfgrom_addr_hi;
		new_blk->cfgrom_addr_lo = curr_blk->cfgrom_addr_lo + size;
		curr_blk->cfgrom_addr_hi = new_blk->cfgrom_addr_lo - 1;
		new_blk->cfgrom_next = curr_blk->cfgrom_next;
		curr_blk->cfgrom_next = new_blk;
		new_blk->cfgrom_prev = curr_blk;
		curr_blk->cfgrom_used = B_TRUE;
		last_entry_offset = curr_blk->cfgrom_addr_hi;
	}
	hal->free_space = hal->free_space - size;

	/* Copy in the new entry */
	tmp_offset = curr_blk->cfgrom_addr_lo;
	bcopy(buffer, &temp_buf[tmp_offset], size << 2);

	/* Update root directory */
	tmp_offset = hal->root_directory->cfgrom_addr_hi;
	tmp_size = tmp_offset - hal->root_directory->cfgrom_addr_lo;
	curr_blk->root_dir_offset = tmp_offset;
	tmp_offset = curr_blk->cfgrom_addr_lo - tmp_offset;

	temp_buf[hal->root_directory->cfgrom_addr_hi] =
	    T1394_DATA32((((uint32_t)key) << IEEE1212_KEY_VALUE_SHIFT) |
	    tmp_offset);
	tmp_offset = hal->root_directory->cfgrom_addr_lo;

	/* Do byte-swapping if necessary (x86) */
	for (i = (tmp_offset + 1); i <= hal->root_directory->cfgrom_addr_hi;
	    i++)
		temp_buf[i] = T1394_DATA32(temp_buf[i]);

	CRC = s1394_CRC16(&temp_buf[tmp_offset + 1], tmp_size);
	temp_buf[tmp_offset] = (tmp_size << IEEE1394_CFG_ROM_LEN_SHIFT) | CRC;

	/* Redo byte-swapping if necessary (x86) */
	for (i = tmp_offset; i <= hal->root_directory->cfgrom_addr_hi; i++)
		temp_buf[i] = T1394_DATA32(temp_buf[i]);

	/* Copy it back to config_rom buffer */
	last_entry_offset++;
	bcopy(&temp_buf[0], &config_rom[0], last_entry_offset << 2);

	/* Return a handle to this block */
	*handle = curr_blk;

	*status = T1394_NOERROR;

	return (DDI_SUCCESS);
}

/*
 * s1394_remove_config_rom_entry()
 *    is used to remove an entry from the local host's config ROM.  By
 *    specifying the Config ROM "handle" that was given in the allocation,
 *    it is possible to remove the entry.  Subsequently, the Config ROM is
 *    updated again.
 *    Callers must be holding the local_config_rom_mutex.
 */
int
s1394_remove_config_rom_entry(s1394_hal_t *hal, void **handle, int *status)
{
	s1394_config_rom_t *del_blk;
	s1394_config_rom_t *curr_blk;
	s1394_config_rom_t *last_blk;
	s1394_config_rom_t *free_blk;
	uint32_t	   *config_rom;
	uint32_t	   *temp_buf;
	uint32_t	   entry;
	uint_t		   CRC;
	uint_t		   root_offset;
	uint_t		   del_offset;
	uint_t		   tmp_offset;
	uint_t		   tmp_size;
	int		   i;

	ASSERT(MUTEX_HELD(&hal->local_config_rom_mutex));

	del_blk = (s1394_config_rom_t *)(*handle);

	config_rom = hal->local_config_rom;
	temp_buf = hal->temp_config_rom_buf;

	/* Copy the Bus_Info_Block */
	bcopy(&config_rom[0], &temp_buf[0], IEEE1394_BIB_SZ);

	root_offset = hal->root_directory->cfgrom_addr_lo;
	del_offset = del_blk->root_dir_offset;

	/* Update Root_Directory entries before the deleted one */
	for (i = root_offset; i < del_offset; i++) {
		entry = T1394_DATA32(config_rom[i]);

		/* If entry is an offset address - update it */
		if (entry & 0x80000000)
			temp_buf[i] = T1394_DATA32(entry - 1);
		else
			temp_buf[i] = T1394_DATA32(entry);
	}

	/* Move all Unit_Directories prior to the deleted one */
	curr_blk = hal->root_directory->cfgrom_next;

	while (curr_blk != del_blk) {
		tmp_offset = curr_blk->cfgrom_addr_lo;
		tmp_size = (curr_blk->cfgrom_addr_hi - tmp_offset) + 1;

		bcopy(&config_rom[tmp_offset], &temp_buf[tmp_offset - 1],
		    tmp_size << 2);
		curr_blk->cfgrom_addr_lo--;
		curr_blk->cfgrom_addr_hi--;
		curr_blk = curr_blk->cfgrom_next;
	}

	/* Move all Unit_Directories after the deleted one */
	curr_blk = del_blk->cfgrom_next;
	last_blk = del_blk->cfgrom_prev;

	del_offset = (del_blk->cfgrom_addr_hi - del_blk->cfgrom_addr_lo) + 1;

	while ((curr_blk != NULL) && (curr_blk->cfgrom_used == B_TRUE)) {
		tmp_offset = curr_blk->cfgrom_addr_lo;
		tmp_size = (curr_blk->cfgrom_addr_hi - tmp_offset) + 1;

		bcopy(&config_rom[tmp_offset],
		    &temp_buf[tmp_offset - (del_offset + 1)], tmp_size << 2);

		root_offset = curr_blk->root_dir_offset;
		temp_buf[root_offset - 1] =
		    config_rom[root_offset] - del_offset;
		curr_blk->root_dir_offset--;
		curr_blk->cfgrom_addr_lo = curr_blk->cfgrom_addr_lo -
		    (del_offset + 1);
		curr_blk->cfgrom_addr_hi = curr_blk->cfgrom_addr_hi -
		    (del_offset + 1);

		last_blk = curr_blk;
		curr_blk = curr_blk->cfgrom_next;
	}

	/* Remove del_blk from the list */
	if (del_blk->cfgrom_prev != NULL)
		del_blk->cfgrom_prev->cfgrom_next = del_blk->cfgrom_next;

	if (del_blk->cfgrom_next != NULL)
		del_blk->cfgrom_next->cfgrom_prev = del_blk->cfgrom_prev;

	del_blk->cfgrom_prev = NULL;
	del_blk->cfgrom_next = NULL;
	kmem_free((void *)del_blk, sizeof (s1394_config_rom_t));

	/* Update and zero out the "free" block */
	if (curr_blk != NULL) {
		curr_blk->cfgrom_addr_lo = curr_blk->cfgrom_addr_lo -
		    (del_offset + 1);

	} else {
		free_blk = (s1394_config_rom_t *)kmem_zalloc(
		    sizeof (s1394_config_rom_t), KM_SLEEP);
		if (free_blk == NULL) {
			return (DDI_FAILURE);
		}

		free_blk->cfgrom_used = B_FALSE;
		free_blk->cfgrom_addr_lo = (IEEE1394_CONFIG_ROM_QUAD_SZ - 1) -
		    (del_offset + 1);
		free_blk->cfgrom_addr_hi = (IEEE1394_CONFIG_ROM_QUAD_SZ - 1);

		free_blk->cfgrom_prev = last_blk;
		free_blk->cfgrom_next = NULL;
		curr_blk = free_blk;
	}
	hal->free_space = hal->free_space + (del_offset + 1);
	tmp_offset = curr_blk->cfgrom_addr_lo;
	tmp_size = (curr_blk->cfgrom_addr_hi - tmp_offset) + 1;
	bzero(&temp_buf[tmp_offset], tmp_size << 2);


	/* Update root directory */
	hal->root_directory->cfgrom_addr_hi--;
	tmp_offset = hal->root_directory->cfgrom_addr_lo;
	tmp_size = hal->root_directory->cfgrom_addr_hi - tmp_offset;

	/* Do byte-swapping if necessary (x86) */
	for (i = (tmp_offset + 1); i <= hal->root_directory->cfgrom_addr_hi;
	    i++)
		temp_buf[i] = T1394_DATA32(temp_buf[i]);

	CRC = s1394_CRC16(&temp_buf[tmp_offset + 1], tmp_size);
	temp_buf[tmp_offset] = (tmp_size << IEEE1394_CFG_ROM_LEN_SHIFT) | CRC;

	/* Do byte-swapping if necessary (x86) */
	for (i = (tmp_offset + 1); i <= hal->root_directory->cfgrom_addr_hi;
	    i++)
		temp_buf[i] = T1394_DATA32(temp_buf[i]);

	/* Copy it back to config_rom buffer */
	tmp_size = IEEE1394_CONFIG_ROM_SZ - (hal->free_space << 2);
	bcopy(&temp_buf[0], &config_rom[0], tmp_size);

	/* Return a handle to this block */
	*handle = NULL;

	*status = T1394_NOERROR;

	return (DDI_SUCCESS);
}

/*
 * s1394_update_config_rom_callback()
 *    is the callback used by t1394_add_cfgrom_entry() and
 *    t1394_rem_cfgrom_entry().  After a target updates the Config ROM, a
 *    timer is set with this as its callback function.  This is to reduce
 *    the number of bus resets that would be necessary if many targets
 *    wished to update the Config ROM simultaneously.
 */
void
s1394_update_config_rom_callback(void *arg)
{
	s1394_hal_t	*hal;
	uint32_t	*config_rom;
	uint32_t	bus_capabilities;
	uint32_t	g;
	uint_t		CRC;
	uint_t		last_entry_offset;
	int		i;

	hal = (s1394_hal_t *)arg;

	/* Lock the Config ROM buffer */
	mutex_enter(&hal->local_config_rom_mutex);

	config_rom = hal->local_config_rom;

	/* Update Generation and CRC for Bus_Info_Block */

	/* Do byte-swapping if necessary (x86) */
	for (i = 0; i < IEEE1394_BIB_QUAD_SZ; i++)
		config_rom[i] = T1394_DATA32(config_rom[i]);

	bus_capabilities = config_rom[IEEE1212_NODE_CAP_QUAD];
	g = ((bus_capabilities & IEEE1394_BIB_GEN_MASK) >>
	    IEEE1394_BIB_GEN_SHIFT) + 1;
	if (g > 15)
		g = 2;
	g = g << IEEE1394_BIB_GEN_SHIFT;

	bus_capabilities = (bus_capabilities & (~IEEE1394_BIB_GEN_MASK)) | g;
	config_rom[IEEE1212_NODE_CAP_QUAD] = bus_capabilities;

	CRC = s1394_CRC16(&config_rom[1], IEEE1394_BIB_QUAD_SZ - 1);
	config_rom[0] = (0x04040000) | CRC;

	/* Do byte-swapping if necessary (x86) */
	for (i = 0; i < IEEE1394_BIB_QUAD_SZ; i++)
		config_rom[i] = T1394_DATA32(config_rom[i]);

	/* Make sure we update only what is necessary */
	last_entry_offset = (IEEE1394_CONFIG_ROM_QUAD_SZ - hal->free_space);
	if (last_entry_offset < hal->config_rom_update_amount)
		last_entry_offset = hal->config_rom_update_amount;

	hal->config_rom_update_amount = (IEEE1394_CONFIG_ROM_QUAD_SZ -
	    hal->free_space);

	/* Clear the timer flag */
	hal->config_rom_timer_set = B_FALSE;

	/* Unlock the Config ROM buffer */
	mutex_exit(&hal->local_config_rom_mutex);

	/*
	 * The update_config_rom() call can return DDI_FAILURE if the
	 * HAL is shutdown.
	 */
	(void) HAL_CALL(hal).update_config_rom(hal->halinfo.hal_private,\
	    config_rom, last_entry_offset);

	/* Initiate a bus reset */
	(void) HAL_CALL(hal).bus_reset(hal->halinfo.hal_private);
}
