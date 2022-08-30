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
 * hci1394_csr.c
 *    This code contains the code for the CSR registers handled by the HAL in
 *    SW.  The HW implemented CSR registers are in hci1394_ohci.c
 *
 *   For more information on CSR registers, see
 *	IEEE 1212
 *	IEEE 1394-1995
 *		section 8.3.2
 *	IEEE P1394A Draft 3.0
 *		sections 10.32,10.33
 *
 * NOTE: A read/write to a CSR SW based register will first go to the Services
 *    Layer which will do some filtering and then come through the s1394if. Look
 *    in hci1394_s1394if.c to see which registers are implemented in HW and
 *    which are implemented in SW.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/types.h>

#include <sys/1394/adapters/hci1394.h>
#include <sys/1394/adapters/hci1394_extern.h>


/*
 * The split_timeout_lo register cannot be set below 800 and above 7999.  The
 * split_timeout_hi register cannot be set above 7.
 */
#define	CSR_MIN_SPLIT_TIMEOUT_LO	800
#define	CSR_MAX_SPLIT_TIMEOUT_LO	7999
#define	CSR_MAX_SPLIT_TIMEOUT_HI	7

/*
 * We will convert the split_timeout_lo to return the data in most significant
 * 13 bits on the fly.
 */
#define	CSR_SPLIT_TIMEOUT_LO_SHIFT	19

/*
 * This is what we report to the services layer as our node capabilities.
 * See IEEE 1212_1994, section 8.4.11
 *
 * Split Timeout Registers are implemented (bit 15)
 * This node uses 64-bit addressing (bit 9)
 * This node uses fixed addressing scheme (bit 8)
 * STATE_BITS.lost is implemented
 * STATE_BITS.dreq is implemented
 */
#define	CSR_INITIAL_NODE_CAPABILITIES	0x000083C0

/*
 * macro to calculate split_timeout based on split_timeout_lo and
 * split_timeout_hi
 */
#define	CSR_SPLIT_TIMEOUT(split_hi, split_lo) \
	((split_hi * IEEE1394_BUS_CYCLES_PER_SEC) + split_lo)


static void hci1394_csr_state_init(hci1394_csr_t *csr);


/*
 * hci1394_csr_init()
 *    Initialize CSR state and CSR SW based registers.
 */
void
hci1394_csr_init(hci1394_drvinfo_t *drvinfo, hci1394_ohci_handle_t ohci,
    hci1394_csr_handle_t *csr_handle)
{
	hci1394_csr_t *csr;


	ASSERT(drvinfo != NULL);
	ASSERT(ohci != NULL);
	ASSERT(csr_handle != NULL);

	/* alloc the space to keep track of the csr registers */
	csr = kmem_alloc(sizeof (hci1394_csr_t), KM_SLEEP);

	/* setup the return parameter */
	*csr_handle = csr;

	/* Initialize the csr structure */
	csr->csr_drvinfo = drvinfo;
	csr->csr_ohci = ohci;
	mutex_init(&csr->csr_mutex, NULL, MUTEX_DRIVER,
	    drvinfo->di_iblock_cookie);
	hci1394_csr_state_init(csr);
}


/*
 * hci1394_csr_fini()
 *    Free up any space allocated and any mutexes used.
 */
void
hci1394_csr_fini(hci1394_csr_handle_t *csr_handle)
{
	hci1394_csr_t *csr;


	ASSERT(csr_handle != NULL);

	csr = (hci1394_csr_t *)*csr_handle;
	mutex_destroy(&csr->csr_mutex);
	kmem_free(csr, sizeof (hci1394_csr_t));
	*csr_handle = NULL;
}


/*
 * hci1394_csr_resume()
 *    When resuming power on a workstation, re-setup our CSR registers.
 */
void
hci1394_csr_resume(hci1394_csr_handle_t csr_handle)
{
	ASSERT(csr_handle != NULL);
	hci1394_csr_state_init(csr_handle);
}


/*
 * hci1394_csr_node_capabilities()
 *    Return the CSR node capabilities.
 */
void
hci1394_csr_node_capabilities(hci1394_csr_handle_t csr_handle,
    uint32_t *capabilities)
{
	ASSERT(csr_handle != NULL);
	ASSERT(capabilities != NULL);

	mutex_enter(&csr_handle->csr_mutex);
	*capabilities = csr_handle->csr_capabilities;
	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_state_get()
 *    Read the CSR state register. Currently we only support the dreq, cmstr,
 *    and abdicate bits in the CSR state register.  See the specs mentioned
 *    above for the behavior of these bits.
 */
void
hci1394_csr_state_get(hci1394_csr_handle_t csr_handle, uint32_t *state)
{
	ASSERT(csr_handle != NULL);
	ASSERT(state != NULL);

	mutex_enter(&csr_handle->csr_mutex);
	*state = csr_handle->csr_state;
	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_state_bset()
 *    Perform a bit set on the CSR state register.  The value of state will be
 *    or'd with the CSR state register. Currently we only support the dreq,
 *    cmstr, and abdicate bits in the CSR state register.  See the specs
 *    mentioned above for the behavior of these bits.
 */
void
hci1394_csr_state_bset(hci1394_csr_handle_t csr_handle, uint32_t state)
{
	uint32_t supported_state;


	ASSERT(csr_handle != NULL);

	mutex_enter(&csr_handle->csr_mutex);

	/* only support dreq, cmstr, and abdicate bits */
	supported_state = state & (IEEE1394_CSR_STATE_ABDICATE |
	    IEEE1394_CSR_STATE_CMSTR | IEEE1394_CSR_STATE_DREQ);

	/*
	 * If we are setting the Cycle Master bit and we are the root node,
	 * enable Cycle Start Packets.
	 */
	if ((supported_state & IEEE1394_CSR_STATE_CMSTR) &&
	    (hci1394_ohci_root_check(csr_handle->csr_ohci))) {
		hci1394_ohci_cycle_master_enable(csr_handle->csr_ohci);
	}

	/* set the supported bits in csr_state */
	csr_handle->csr_state |= supported_state;

	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_state_bclr()
 *     Perform a bit clear on the CSR state register. The inverted value of
 *     state will be and'd with CSR state register. Currently we only support
 *     the dreq, cmstr, and abdicate bits in the CSR state register.  See the
 *     specs mentioned above for the behavior of these bits.
 */
void
hci1394_csr_state_bclr(hci1394_csr_handle_t csr_handle, uint32_t state)
{
	uint32_t supported_state;


	ASSERT(csr_handle != NULL);

	mutex_enter(&csr_handle->csr_mutex);

	/* only support dreq, cmstr, and abdicate bits */
	supported_state = state & (IEEE1394_CSR_STATE_ABDICATE |
	    IEEE1394_CSR_STATE_CMSTR | IEEE1394_CSR_STATE_DREQ);

	/*
	 * If we are clearing the Cycle Master bit and we are the root node,
	 * disable Cycle Start Packets.
	 */
	if ((supported_state & IEEE1394_CSR_STATE_CMSTR) &&
	    (hci1394_ohci_root_check(csr_handle->csr_ohci))) {
		hci1394_ohci_cycle_master_disable(csr_handle->csr_ohci);
	}

	/* Clear the supported bits in csr_state */
	csr_handle->csr_state &= ~state;

	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_split_timeout_hi_get()
 *    Read the CSR split_timeout_hi register.
 */
void
hci1394_csr_split_timeout_hi_get(hci1394_csr_handle_t csr_handle,
    uint32_t *split_timeout_hi)
{
	ASSERT(csr_handle != NULL);
	ASSERT(split_timeout_hi != NULL);

	mutex_enter(&csr_handle->csr_mutex);
	*split_timeout_hi = csr_handle->csr_split_timeout_hi;
	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_split_timeout_lo_get()
 *    Read the CSR split_timeout_lo register.
 */
void
hci1394_csr_split_timeout_lo_get(hci1394_csr_handle_t csr_handle,
    uint32_t *split_timeout_lo)
{
	ASSERT(csr_handle != NULL);
	ASSERT(split_timeout_lo != NULL);

	mutex_enter(&csr_handle->csr_mutex);

	/*
	 * Read the split_timeout_lo CSR register. Convert split_timeout_lo to
	 * use the data in most significant 13 bits on the fly.
	 */
	*split_timeout_lo = csr_handle->csr_split_timeout_lo <<
	    CSR_SPLIT_TIMEOUT_LO_SHIFT;

	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_split_timeout_hi_set()
 *    Write the CSR split_timeout_hi register. This routine will also
 *    re-calculate the "split_timeout" which is used internally in the HAL
 *    driver. The only accesses to split_timeout_hi and split_timeout_lo
 *    should be over the 1394 bus. Only the least significant 3 bits are
 *    relevant in the split_timeout_hi register.
 */
void
hci1394_csr_split_timeout_hi_set(hci1394_csr_handle_t csr_handle,
    uint32_t split_timeout_hi)
{
	ASSERT(csr_handle != NULL);

	mutex_enter(&csr_handle->csr_mutex);

	/*
	 * update the split_timeout_hi CSR register. Only look at the 3 LSBits.
	 * Update our internal split_timeout value.
	 */
	csr_handle->csr_split_timeout_hi = split_timeout_hi &
	    CSR_MAX_SPLIT_TIMEOUT_HI;
	csr_handle->csr_split_timeout = CSR_SPLIT_TIMEOUT(
	    csr_handle->csr_split_timeout_hi, csr_handle->csr_split_timeout_lo);

	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_split_timeout_lo_set()
 *    Write the CSR split_timeout_lo register. This routine will also
 *    re-calculate the "split_timeout" which is used internally in the HAL
 *    driver. The only accesses to split_timeout_hi and split_timeout_lo
 *    should be over the 1394 bus. Only the most significant 13 bits are
 *    relevant in the split_timeout_lo register.
 */
void
hci1394_csr_split_timeout_lo_set(hci1394_csr_handle_t csr_handle,
    uint32_t split_timeout_lo)
{
	ASSERT(csr_handle != NULL);

	mutex_enter(&csr_handle->csr_mutex);

	/*
	 * Update the split_timeout_lo CSR register.  Only look at the 3 LSBits.
	 * Convert the split_timeout_lo to use the data in most significant 13
	 * bits on the fly.
	 */
	csr_handle->csr_split_timeout_lo = split_timeout_lo >>
	    CSR_SPLIT_TIMEOUT_LO_SHIFT;

	/* threshold the split_timeout_lo value */
	if (csr_handle->csr_split_timeout_lo < CSR_MIN_SPLIT_TIMEOUT_LO) {
		csr_handle->csr_split_timeout_lo = CSR_MIN_SPLIT_TIMEOUT_LO;
	} else if (csr_handle->csr_split_timeout_lo >
	    CSR_MAX_SPLIT_TIMEOUT_LO) {
		csr_handle->csr_split_timeout_lo = CSR_MAX_SPLIT_TIMEOUT_LO;
	}

	/* Update our internal split_timeout value */
	csr_handle->csr_split_timeout = CSR_SPLIT_TIMEOUT(
	    csr_handle->csr_split_timeout_hi, csr_handle->csr_split_timeout_lo);

	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_split_timeout_get()
 *    Return the current value of split_timeout.  This is the  only routine
 *    which should be used to get the split timeout for use in a calculation
 *    (e.g. for calculating ACK pending timeout).
 */
uint_t
hci1394_csr_split_timeout_get(hci1394_csr_handle_t csr_handle)
{
	uint_t split_timeout;


	ASSERT(csr_handle != NULL);

	mutex_enter(&csr_handle->csr_mutex);

	/* read our internal split_timeout value */
	split_timeout = csr_handle->csr_split_timeout;

	mutex_exit(&csr_handle->csr_mutex);

	return (split_timeout);
}


/*
 * hci1394_csr_bus_reset()
 *    Perform required bus reset processing on CSR registers. This includes
 *    clearing the abdicate bit, and setting/clearing the Cycle Master bit.
 *    See sections 10.32 and 10.33 in the IEEE P1394A Draft 3.0 spec.  See
 *    section 8.3.2.2.1 in the IEEE 1394-1995 spec. This routine should be
 *    called every bus reset.
 */
void
hci1394_csr_bus_reset(hci1394_csr_handle_t csr_handle)
{
	ASSERT(csr_handle != NULL);

	mutex_enter(&csr_handle->csr_mutex);

	/* Clear the abdicate bit.  Always do this. */
	csr_handle->csr_state &= ~IEEE1394_CSR_STATE_ABDICATE;

	/* if we are NOT currently the root node on the bus */
	if (hci1394_ohci_root_check(csr_handle->csr_ohci) == B_FALSE) {
		/*
		 * Set the was_root state.  This is needed for the Cycle Master
		 * state machine below.
		 */
		csr_handle->csr_was_root = B_FALSE;

		/*
		 * Clear the Cycle Master bit.  We do not have to shut off cycle
		 * master in OpenHCI.  The HW will automatically stop generating
		 * Cycle Start packets when it is not the root node.
		 */
		csr_handle->csr_state &= ~IEEE1394_CSR_STATE_CMSTR;

	/*
	 * if we are currently the root node on the bus and we were NOT
	 * the root before the reset.
	 */
	} else if (csr_handle->csr_was_root == B_FALSE) {

		/* set the was_root state to TRUE */
		csr_handle->csr_was_root = B_TRUE;

		/*
		 * if we are cycle master capable, set the Cycle Master bit and
		 * start Cycle Start packets. We should always be Cycle Master
		 * capable.
		 */
		if (hci1394_ohci_cmc_check(csr_handle->csr_ohci)) {
			csr_handle->csr_state |= IEEE1394_CSR_STATE_CMSTR;
			hci1394_ohci_cycle_master_enable(csr_handle->csr_ohci);

		/*
		 * if we are NOT cycle master capable, clear the Cycle Master
		 * bit and stop Cycle Start packets. We should never see this
		 * in OpenHCI. I think? :-)
		 */
		} else {
			csr_handle->csr_state &= ~IEEE1394_CSR_STATE_CMSTR;
			hci1394_ohci_cycle_master_disable(csr_handle->csr_ohci);
		}
	}
	/*
	 * else {}
	 * else we are root now. We were root before, keep cmstr the same.
	 * Nothing to do.
	 */

	mutex_exit(&csr_handle->csr_mutex);
}


/*
 * hci1394_csr_state_init()
 *    set the CSR SW registers and state variables to their initial settings.
 */
static void hci1394_csr_state_init(hci1394_csr_t *csr)
{
	ASSERT(csr != NULL);

	mutex_enter(&csr->csr_mutex);

	/*
	 * Initialize the split timeout to be 0 seconds (split_timeout_hi) and
	 * use a patchable variable for the initial split_timeout_lo. This
	 * variable must be patched before the driver attaches.  It is never
	 * looked at again after this code is run.
	 *
	 * Calculate the split_timeout which we will use in the driver based on
	 * split_timeout_lo and split_timeout_hi.
	 */
	csr->csr_split_timeout_hi = 0;
	csr->csr_split_timeout_lo = hci1394_split_timeout;
	csr->csr_split_timeout = CSR_SPLIT_TIMEOUT(
	    csr->csr_split_timeout_hi, csr->csr_split_timeout_lo);

	/* Set the initial CSR State register to 0 */
	csr->csr_state = 0;

	/*
	 * was_root is an internal state variable which tracks if we were root
	 * last bus reset.  This is needed for the required state register bus
	 * reset processing.
	 */
	csr->csr_was_root = B_FALSE;

	/* setup our initial capabilities setting */
	csr->csr_capabilities = CSR_INITIAL_NODE_CAPABILITIES;

	mutex_exit(&csr->csr_mutex);
}
