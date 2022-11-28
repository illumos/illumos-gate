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
 * hci1394_s1394if.c
 *    The interface into the HAL from the services layer.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>

#include <sys/1394/h1394.h>
#include <sys/1394/ixl1394.h>
#include <sys/1394/adapters/hci1394.h>


static void hci1394_s1394if_shutdown(void *hal_private);
static int hci1394_s1394if_phy(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result);
static int hci1394_s1394if_write(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result);
static int hci1394_s1394if_read(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result);
static int hci1394_s1394if_lock(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result);
static int hci1394_s1394if_write_response(void *hal_private,
    cmd1394_cmd_t *cmd_id, h1394_cmd_priv_t *cmd_private, int *result);
static int hci1394_s1394if_read_response(void *hal_private,
    cmd1394_cmd_t *cmd_id, h1394_cmd_priv_t *cmd_private, int *result);
static int hci1394_s1394if_lock_response(void *hal_private,
    cmd1394_cmd_t *cmd_id, h1394_cmd_priv_t *cmd_private, int *result);
static void hci1394_s1394if_response_complete(void *hal_private,
    cmd1394_cmd_t *cmd_id, h1394_cmd_priv_t *cmd_private);
static int hci1394_s1394if_reset_bus(void *hal_private);
static int hci1394_s1394if_set_contender_bit(void *hal_private);
static int hci1394_s1394if_set_root_holdoff_bit(void *hal_private);
static int hci1394_s1394if_set_gap_count(void *hal_private, uint_t gap_count);
static int hci1394_s1394if_update_config_rom(void *hal_private,
    void *local_buf, uint_t quadlet_count);
static int hci1394_s1394if_phy_filter_set(void *hal_private,
    uint64_t mask, uint_t generation);
static int hci1394_s1394if_phy_filter_clr(void *hal_private,
    uint64_t mask, uint_t generation);
static int hci1394_s1394if_short_bus_reset(void *hal_private);
static int hci1394_s1394if_csr_read(void *hal_private,
    uint_t offset, uint32_t *data);
static int hci1394_s1394if_csr_write(void *hal_private,
    uint_t offset, uint32_t data);
static int hci1394_s1394if_csr_cswap32(void *hal_private, uint_t generation,
    uint_t offset, uint32_t compare, uint32_t swap, uint32_t *old);
static void hci1394_s1394if_power_state_change(void *hal_private,
    h1394_node_pwr_flags_t nodeflags);


/* entry points into HAL from Services Layer */
h1394_evts_t hci1394_evts = {
	H1394_EVTS_V1,				/* hal_version */
	0,					/* reserved */
	hci1394_s1394if_shutdown,		/* shutdown */
	hci1394_s1394if_phy,			/* send_phy_config_pkt */
	hci1394_s1394if_read,			/* read */
	hci1394_s1394if_read_response,		/* read_response */
	hci1394_s1394if_write,			/* write */
	hci1394_s1394if_write_response,		/* write_response */
	hci1394_s1394if_response_complete,	/* response_complete */
	hci1394_s1394if_lock,			/* lock */
	hci1394_s1394if_lock_response,		/* lock_response */
	hci1394_alloc_isoch_dma,		/* allocate_isoch_dma */
	hci1394_free_isoch_dma,			/* free_isoch_dma */
	hci1394_start_isoch_dma,		/* start_isoch_dma */
	hci1394_stop_isoch_dma,			/* stop_isoch_dma */
	hci1394_update_isoch_dma,		/* update_isoch_dma */
	hci1394_s1394if_update_config_rom,	/* update_config_rom */
	hci1394_s1394if_reset_bus,		/* bus_reset */
	hci1394_s1394if_short_bus_reset,	/* short_bus_reset */
	hci1394_s1394if_set_contender_bit,	/* set_contender_bit */
	hci1394_s1394if_set_root_holdoff_bit,	/* set_root_holdoff_bit */
	hci1394_s1394if_set_gap_count,		/* set_gap_count */
	hci1394_s1394if_csr_read,		/* csr_read */
	hci1394_s1394if_csr_write,		/* csr_write */
	hci1394_s1394if_csr_cswap32,		/* csr_cswap32 */
	hci1394_s1394if_phy_filter_set,		/* phys_arreq_enable_set */
	hci1394_s1394if_phy_filter_clr,		/* phys_arreq_enable_clr */
	hci1394_s1394if_power_state_change	/* node_power_state_change */
};


/*
 * hci1394_s1394if_shutdown()
 *    Shutdown the HAL. This is called when a critical error has been detected.
 *    This routine should shutdown the HAL so that it will no longer send or
 *    receive information to/from the 1394 bus. The purpose of this function is
 *    to try and keep the machine from crashing.
 */
static void
hci1394_s1394if_shutdown(void *hal_private)
{
	hci1394_state_t *soft_state;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;
	hci1394_shutdown(soft_state->drvinfo.di_dip);
}


/*
 * hci1394_s1394if_phy()
 *    write a phy packet out to the 1394 bus.  A phy packet consists of one
 *    quadlet of data.
 */
static int
hci1394_s1394if_phy(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not in a bus reset or shutdown */
	if (hci1394_state(&soft_state->drvinfo) != HCI1394_NORMAL) {
		if (hci1394_state(&soft_state->drvinfo) == HCI1394_BUS_RESET) {
			*result = H1394_STATUS_INVALID_BUSGEN;
		} else {
			*result = H1394_STATUS_INTERNAL_ERROR;
		}
		return (DDI_FAILURE);
	}

	status = hci1394_async_phy(soft_state->async, cmd_id, cmd_private,
	    result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_write()
 *    Perform a 1394 write operation.  This can be either a quadlet or block
 *    write.
 */
static int
hci1394_s1394if_write(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not in a bus reset or shutdown */
	if (hci1394_state(&soft_state->drvinfo) != HCI1394_NORMAL) {
		if (hci1394_state(&soft_state->drvinfo) == HCI1394_BUS_RESET) {
			*result = H1394_STATUS_INVALID_BUSGEN;
		} else {
			*result = H1394_STATUS_INTERNAL_ERROR;
		}
		return (DDI_FAILURE);
	}

	status = hci1394_async_write(soft_state->async, cmd_id, cmd_private,
	    result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_read()
 *    Perform a 1394 read operation.  This can be either a quadlet or block
 *    read.
 */
static int
hci1394_s1394if_read(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not in a bus reset or shutdown */
	if (hci1394_state(&soft_state->drvinfo) != HCI1394_NORMAL) {
		if (hci1394_state(&soft_state->drvinfo) == HCI1394_BUS_RESET) {
			*result = H1394_STATUS_INVALID_BUSGEN;
		} else {
			*result = H1394_STATUS_INTERNAL_ERROR;
		}
		return (DDI_FAILURE);
	}

	status = hci1394_async_read(soft_state->async, cmd_id, cmd_private,
	    result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_lock()
 *    Perform a 1394/1212 lock operation.  This can be one of the following lock
 *    operations: (CMD1394_LOCK_MASK_SWAP, CMD1394_LOCK_COMPARE_SWAP
 *    CMD1394_LOCK_FETCH_ADD, CMD1394_LOCK_LITTLE_ADD, CMD1394_LOCK_BOUNDED_ADD
 *    CMD1394_LOCK_WRAP_ADD)
 */
static int
hci1394_s1394if_lock(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not in a bus reset or shutdown */
	if (hci1394_state(&soft_state->drvinfo) != HCI1394_NORMAL) {
		if (hci1394_state(&soft_state->drvinfo) == HCI1394_BUS_RESET) {
			*result = H1394_STATUS_INVALID_BUSGEN;
		} else {
			*result = H1394_STATUS_INTERNAL_ERROR;
		}
		return (DDI_FAILURE);
	}

	status = hci1394_async_lock(soft_state->async, cmd_id, cmd_private,
	    result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_write_response()
 *    Send a response to a write request received off of the 1394 bus.  This
 *    could have been with a quadlet or block write request.
 */
static int
hci1394_s1394if_write_response(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not in a bus reset or shutdown */
	if (hci1394_state(&soft_state->drvinfo) != HCI1394_NORMAL) {
		if (hci1394_state(&soft_state->drvinfo) == HCI1394_BUS_RESET) {
			*result = H1394_STATUS_INVALID_BUSGEN;
		} else {
			*result = H1394_STATUS_INTERNAL_ERROR;
		}
		return (DDI_FAILURE);
	}

	status = hci1394_async_write_response(soft_state->async, cmd_id,
	    cmd_private, result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_read_response()
 *    Send a response to a read request received off of the 1394 bus.  This
 *    could have been with a quadlet or block read request.
 */
static int
hci1394_s1394if_read_response(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not in a bus reset or shutdown */
	if (hci1394_state(&soft_state->drvinfo) != HCI1394_NORMAL) {
		if (hci1394_state(&soft_state->drvinfo) == HCI1394_BUS_RESET) {
			*result = H1394_STATUS_INVALID_BUSGEN;
		} else {
			*result = H1394_STATUS_INTERNAL_ERROR;
		}
		return (DDI_FAILURE);
	}

	status = hci1394_async_read_response(soft_state->async, cmd_id,
	    cmd_private, result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_lock_response()
 *    Send a response to a lock request received off of the 1394 bus.  This
 *    could have been one of the following lock operations:
 *    (CMD1394_LOCK_MASK_SWAP, CMD1394_LOCK_COMPARE_SWAP CMD1394_LOCK_FETCH_ADD,
 *    CMD1394_LOCK_LITTLE_ADD, CMD1394_LOCK_BOUNDED_ADD, CMD1394_LOCK_WRAP_ADD)
 */
static int
hci1394_s1394if_lock_response(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private, int *result)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not in a bus reset or shutdown */
	if (hci1394_state(&soft_state->drvinfo) != HCI1394_NORMAL) {
		if (hci1394_state(&soft_state->drvinfo) == HCI1394_BUS_RESET) {
			*result = H1394_STATUS_INVALID_BUSGEN;
		} else {
			*result = H1394_STATUS_INTERNAL_ERROR;
		}
		return (DDI_FAILURE);
	}

	status = hci1394_async_lock_response(soft_state->async, cmd_id,
	    cmd_private, result);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_response_complete()
 *    This notifies the HAL that the services layer and target driver are done
 *    with a command that was received off of the 1394 bus.  This will usually
 *    be called after the response to the command has been command_complete'd.
 *    The HAL is free to re-use the command or free up the memory from this
 *    command after this call has returned.  This should only be called for
 *    ARREQ's.
 */
static void
hci1394_s1394if_response_complete(void *hal_private, cmd1394_cmd_t *cmd_id,
    h1394_cmd_priv_t *cmd_private)
{
	hci1394_state_t *soft_state;

	ASSERT(hal_private != NULL);
	soft_state = (hci1394_state_t *)hal_private;
	hci1394_async_response_complete(soft_state->async, cmd_id, cmd_private);
}


/*
 * hci1394_s1394if_reset_bus()
 *    This routine resets the 1394 bus. It performs a "long" bus reset.  It
 *    should work on all OpenHCI adapters.
 */
static int
hci1394_s1394if_reset_bus(void *hal_private)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	status = hci1394_ohci_bus_reset(soft_state->ohci);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_set_contender_bit()
 *    This routine sets up the PHY so that the selfid contender bit will be set
 *    on subsequent bus resets.  This routine will fail when we have a 1394-1995
 *    PHY since this PHY does not have a SW controllable contender bit.
 */
static int
hci1394_s1394if_set_contender_bit(void *hal_private)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	if (soft_state->halinfo.phy == H1394_PHY_1995) {
		return (DDI_FAILURE);
	}

	status = hci1394_ohci_contender_enable(soft_state->ohci);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_set_root_holdoff_bit()
 *    This routine will set the root holdoff bit in the PHY. The Services Layer
 *    should send out a PHY configuration packet first to tell everyone which
 *    node to set the root holdoff bit on.  If it is our root holdoff bit we
 *    are setting, the PHY will automatically set it unless we have an old
 *    (1394-1995) PHY.  If we have a 1394-1995 PHY, the SL needs to call this
 *    routine after sending the PHY configuration packet.  The SL also needs to
 *    call this if they want to perform a long bus reset and have the root
 *    holdoff bit set.  We do this so that we do not have to do a read before
 *    the write.  A PHY register write has less of a chance of failing.
 */
static int
hci1394_s1394if_set_root_holdoff_bit(void *hal_private)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	status = hci1394_ohci_root_holdoff_enable(soft_state->ohci);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_set_gap_count()
 *    This routine will set the gap count bit in the PHY. The Services Layer
 *    should send out a PHY configuration packet first to tell everyone what
 *    gap count to use. Our PHY will automatically set the gap count unless we
 *    have an old (1394-1995) PHY.  If we have a 1394-1995 PHY, the SL needs to
 *    call this routine after sending the PHY configuration packet and before
 *    generating a bus reset. The SL also needs to call before the they call to
 *    perform a long bus reset. We do this so that we do not have to do a PHY
 *    read before the write. A PHY register write has less of a chance of
 *    failing.
 */
static int
hci1394_s1394if_set_gap_count(void *hal_private, uint_t gap_count)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	status = hci1394_ohci_gap_count_set(soft_state->ohci, gap_count);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_phy_filter_set()
 *    reads/writes to physically mapped memory from devices on the bus are
 *    disabled by default. They can be enabled on a node by node basis. All
 *    physical accesses are disabled every bus reset so they must be re-enabled
 *    every bus reset (This is due to the fact the the node ids change every bus
 *    reset). A 64-bit mask is passed in to enable nodes to be able to rd/wr
 *    physically mapped memory over the 1394 bus. A bit = to 1 enables that
 *    node's physical accesses, a bit = to 0 does nothing (i.e. a bitwise or is
 *    performed). The LSB of the mask (bit 0), maps to node #0, bit #62, maps to
 *    node 62.  The MSB (#63) is not used since the can only be 63 nodes
 *    (0 - 62) on the bus.
 *
 *    hci1394_s1394if_phy_filter_clr() is used to disable access to physical
 *    memory.  This is only required if the node had previously been enabled.
 *
 *    generation is used to verify that we are have not gotten a bus reset since
 *    the mask was built.
 */
static int
hci1394_s1394if_phy_filter_set(void *hal_private,
    uint64_t mask, uint_t generation)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	status = hci1394_ohci_phy_filter_set(soft_state->ohci, mask,
	    generation);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_phy_filter_clr()
 *    reads/writes to physically mapped memory from devices on the bus are
 *    disabled by default. They can be enabled/disabled on a node by node basis.
 *    All physical accesses are disabled every bus reset so they must be
 *    re-enabled every bus reset (This is due to the fact the the node ids
 *    change every bus reset).  Only nodes which have been enabled and no longer
 *    need access to physical memory need to be disabled.
 *
 *    A 64-bit mask is passed in to disable nodes from being able to rd/wr
 *    physically mapped memory over the 1394 bus. A bit = to 1 disables that
 *    node's physical accesses, a bit = to 0 does nothing (i.e. a bitwise or is
 *    performed). The LSB of the mask (bit 0), maps to node #0, bit #62, maps to
 *    node 62.  The MSB (#63) is not used since there can only be 63 nodes
 *    (0 - 62) on the bus.
 *
 *    hci1394_s1394if_phy_filter_set() is used to enable access to physical
 *    memory.
 *
 *    generation is used to verify that we are have not gotten a bus reset since
 *    the mask was build.
 */
static int
hci1394_s1394if_phy_filter_clr(void *hal_private,
    uint64_t mask, uint_t generation)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	status = hci1394_ohci_phy_filter_clr(soft_state->ohci, mask,
	    generation);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_short_bus_reset()
 *    This routine resets the 1394 bus.  It performs a "short" bus reset.  It
 *    will only work on adapters with a 1394A or later PHY. Calling this routine
 *    when we have a 1394-1995 PHY is an error.
 */
static int
hci1394_s1394if_short_bus_reset(void *hal_private)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	if (soft_state->halinfo.phy == H1394_PHY_1995) {
		return (DDI_FAILURE);
	}

	status = hci1394_ohci_bus_reset_short(soft_state->ohci);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_update_config_rom()
 *    This routine updates the configuration ROM.  It copies "quadlet_count"
 *    32-bit words from "local_buf" to the config ROM starting at the first
 *    location in config ROM. This routine is meant to update the entire config
 *    ROM and not meant for a partial update.
 */
static int
hci1394_s1394if_update_config_rom(void *hal_private,
    void *local_buf, uint_t quadlet_count)
{
	hci1394_state_t *soft_state;


	ASSERT(hal_private != NULL);
	ASSERT(local_buf != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	hci1394_ohci_cfgrom_update(soft_state->ohci, local_buf, quadlet_count);

	return (DDI_SUCCESS);
}


/*
 * hci1394_s1394if_csr_read()
 *    CSR register read interface
 *    For more information on CSR registers, see
 *	IEEE 1212
 *	IEEE 1394-1995
 *		section 8.3.2
 *	IEEE P1394A Draft 3.0
 *		sections 10.32,10.33
 */
static int
hci1394_s1394if_csr_read(void *hal_private, uint_t offset, uint32_t *data)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);
	ASSERT(data != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	switch (offset) {
	case CSR_STATE_CLEAR:
		hci1394_csr_state_get(soft_state->csr, data);
		status = DDI_SUCCESS;
		break;
	case CSR_STATE_SET:
		/* Write Only Register */
		status = DDI_FAILURE;
		break;
	case CSR_NODE_IDS:
		hci1394_ohci_nodeid_get(soft_state->ohci, data);
		status = DDI_SUCCESS;
		break;
	case CSR_RESET_START:
		/* Not supported */
		status = DDI_FAILURE;
		break;
	case CSR_SPLIT_TIMEOUT_HI:
		hci1394_csr_split_timeout_hi_get(soft_state->csr, data);
		status = DDI_SUCCESS;
		break;
	case CSR_SPLIT_TIMEOUT_LO:
		hci1394_csr_split_timeout_lo_get(soft_state->csr, data);
		status = DDI_SUCCESS;
		break;
	case CSR_CYCLE_TIME:
		/* CYCLE_TIME is implemented in HW */
		hci1394_ohci_cycletime_get(soft_state->ohci, data);
		status = DDI_SUCCESS;
		break;
	case CSR_BUS_TIME:
		/* BUS_TIME is implemented in the hci1394_ohci_* SW */
		hci1394_ohci_bustime_get(soft_state->ohci, data);
		status = DDI_SUCCESS;
		break;
	case CSR_BUSY_TIMEOUT:
		hci1394_ohci_atreq_retries_get(soft_state->ohci, data);
		status = DDI_SUCCESS;
		break;
	case CSR_BUS_MANAGER_ID:
		/* BUS_MANAGER_ID is implemented in HW */
		status = hci1394_ohci_csr_read(soft_state->ohci, 0, data);
		break;
	case CSR_BANDWIDTH_AVAILABLE:
		/* BANDWIDTH_AVAILABLE is implemented in HW */
		status = hci1394_ohci_csr_read(soft_state->ohci, 1, data);
		break;
	case CSR_CHANNELS_AVAILABLE_HI:
		/* CHANNELS_AVAILABLE_HI is implemented in HW */
		status = hci1394_ohci_csr_read(soft_state->ohci, 2, data);
		break;
	case CSR_CHANNELS_AVAILABLE_LO:
		/* CHANNELS_AVAILABLE_LO is implemented in HW */
		status = hci1394_ohci_csr_read(soft_state->ohci, 3, data);
		break;
	default:
		status = DDI_FAILURE;
		break;
	}

	return (status);
}


/*
 * hci1394_s1394if_csr_write()
 *    CSR register write interface
 *    For more information on CSR registers, see
 *	IEEE 1212
 *	IEEE 1394-1995
 *		section 8.3.2
 *	IEEE P1394A Draft 3.0
 *		sections 10.32,10.33
 */
static int
hci1394_s1394if_csr_write(void *hal_private, uint_t offset, uint32_t data)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	switch (offset) {
	case CSR_STATE_CLEAR:
		hci1394_csr_state_bclr(soft_state->csr, data);
		status = DDI_SUCCESS;
		break;
	case CSR_STATE_SET:
		hci1394_csr_state_bset(soft_state->csr, data);
		status = DDI_SUCCESS;
		break;
	case CSR_NODE_IDS:
		hci1394_ohci_nodeid_set(soft_state->ohci, data);
		status = DDI_SUCCESS;
		break;
	case CSR_RESET_START:
		/* Not supported */
		status = DDI_FAILURE;
		break;

		/*
		 * there is a race condition when updating the split timeout
		 * due to the nature of the interface. (i.e. having a separate
		 * hi an lo register)
		 */
	case CSR_SPLIT_TIMEOUT_HI:
		hci1394_csr_split_timeout_hi_set(soft_state->csr, data);
		/*
		 * update the pending list timeout value. The split timeout
		 * is stored in 1394 bus cycles and the timeout is specified in
		 * nS.  Therefore, we need to convert the split timeout into nS.
		 */
		hci1394_async_pending_timeout_update(soft_state->async,
		    OHCI_BUS_CYCLE_TO_nS(hci1394_csr_split_timeout_get(
			soft_state->csr)));
		status = DDI_SUCCESS;
		break;
	case CSR_SPLIT_TIMEOUT_LO:
		hci1394_csr_split_timeout_lo_set(soft_state->csr, data);
		/*
		 * update the pending list timeout value. The split timeout
		 * is stored in 1394 bus cycles and the timeout is specified in
		 * nS.  Therefore, we need to convert the split timeout into nS.
		 */
		hci1394_async_pending_timeout_update(soft_state->async,
		    OHCI_BUS_CYCLE_TO_nS(hci1394_csr_split_timeout_get(
			soft_state->csr)));
		status = DDI_SUCCESS;
		break;

	case CSR_CYCLE_TIME:
		hci1394_ohci_cycletime_set(soft_state->ohci, data);
		status = DDI_SUCCESS;
		break;
	case CSR_BUS_TIME:
		hci1394_ohci_bustime_set(soft_state->ohci, data);
		status = DDI_SUCCESS;
		break;
	case CSR_BUSY_TIMEOUT:
		hci1394_ohci_atreq_retries_set(soft_state->ohci, data);
		status = DDI_SUCCESS;
		break;
	case CSR_BUS_MANAGER_ID:
		/* Invalid access, only read/cswap32 allowed */
		status = DDI_FAILURE;
		break;
	case CSR_BANDWIDTH_AVAILABLE:
		/* Invalid access, only read/cswap32 allowed */
		status = DDI_FAILURE;
		break;
	case CSR_CHANNELS_AVAILABLE_HI:
		/* Invalid access, only read/cswap32 allowed */
		status = DDI_FAILURE;
		break;
	case CSR_CHANNELS_AVAILABLE_LO:
		/* Invalid access, only read/cswap32 allowed */
		status = DDI_FAILURE;
		break;
	default:
		status = DDI_FAILURE;
		break;
	}

	return (status);
}


/*
 * hci1394_s1394if_csr_cswap32()
 *    CSR register cswap32 interface
 *    For more information on CSR registers, see
 *	IEEE 1212
 *	IEEE 1394-1995
 *		section 8.3.2
 *	IEEE P1394A Draft 3.0
 *		sections 10.32,10.33
 */
static int
hci1394_s1394if_csr_cswap32(void *hal_private, uint_t generation, uint_t offset,
    uint32_t compare, uint32_t swap, uint32_t *old)
{
	hci1394_state_t *soft_state;
	int status;


	ASSERT(hal_private != NULL);
	ASSERT(old != NULL);

	soft_state = (hci1394_state_t *)hal_private;

	/* make sure we are not shutdown */
	if (hci1394_state(&soft_state->drvinfo) == HCI1394_SHUTDOWN) {
		return (DDI_FAILURE);
	}

	switch (offset) {
	case CSR_STATE_CLEAR:
		/* Invalid access, only read/write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_STATE_SET:
		/* Invalid access, only write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_NODE_IDS:
		/* Invalid access, only read/write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_RESET_START:
		/* Invalid access, only read/write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_SPLIT_TIMEOUT_HI:
		/* Invalid access, only read/write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_SPLIT_TIMEOUT_LO:
		/* Invalid access, only read/write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_CYCLE_TIME:
		/* Invalid access, only read/write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_BUS_TIME:
		/* Invalid access, only read/write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_BUSY_TIMEOUT:
		/* Invalid access, only read/write allowed */
		status = DDI_FAILURE;
		break;
	case CSR_BUS_MANAGER_ID:
		/* BUS_MANAGER_ID is implemented in HW */
		status = hci1394_ohci_csr_cswap(soft_state->ohci, generation,
		    OHCI_CSR_SEL_BUS_MGR_ID, compare, swap, old);
		break;
	case CSR_BANDWIDTH_AVAILABLE:
		/* BANDWIDTH_AVAILABLE is implemented in HW */
		status = hci1394_ohci_csr_cswap(soft_state->ohci, generation,
		    OHCI_CSR_SEL_BANDWIDTH_AVAIL, compare, swap, old);
		break;
	case CSR_CHANNELS_AVAILABLE_HI:
		/* CHANNELS_AVAILABLE_HI is implemented in HW */
		status = hci1394_ohci_csr_cswap(soft_state->ohci, generation,
		    OHCI_CSR_SEL_CHANS_AVAIL_HI, compare, swap, old);
		break;
	case CSR_CHANNELS_AVAILABLE_LO:
		/* CHANNELS_AVAILABLE_LO is implemented in HW */
		status = hci1394_ohci_csr_cswap(soft_state->ohci, generation,
		    OHCI_CSR_SEL_CHANS_AVAIL_LO, compare, swap, old);
		break;
	default:
		status = DDI_FAILURE;
		break;
	}

	return (status);
}


/*
 * hci1394_s1394if_power_state_change()
 *    Signals that a change in the bus topology has taken place which may affect
 *    power management.
 */
/*ARGSUSED*/
static void
hci1394_s1394if_power_state_change(void *hal_private,
    h1394_node_pwr_flags_t nodeflags)
{
	/* not implemented */
}
