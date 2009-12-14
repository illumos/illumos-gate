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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/ddi.h>
#include <sys/plat_ecc_dimm.h>

extern int plat_max_mc_units_per_board(void);
extern int plat_ecc_dispatch_task(plat_ecc_message_t *);

/* Platform specific function to get DIMM offset information */
int (*p2get_mem_offset)(uint64_t, uint64_t *);

/* Platform specific function to get dimm serial id information */
int (*p2get_mem_sid)(int, int, char *, int, int *);

/*
 * Platform specific function to convert a DIMM location/serial id and
 * offset into a physical address.
 */
int (*p2get_mem_addr)(int, char *, uint64_t, uint64_t *);

/*
 * Timeouts variable for determining when to give up waiting for a
 * response from the SC.  The value is in seconds and the default is
 * based on the current default mailbox timeout used for Serengeti
 * mailbox requests which is 30 seconds (Starcat uses a smaller value).
 */
int plat_dimm_req_timeout = 30;
int plat_dimm_req_min_timeout = 6;

/* Number of times to retries DIMM serial id requests */
int plat_dimm_req_max_retries = 1;

static void  plat_request_all_mem_sids(uint32_t);

int
plat_get_mem_sid(char *unum, char *buf, int buflen, int *lenp)
{
	int	board, pos, bank, dimm, jnumber;
	int	mcid;

	if (p2get_mem_sid == NULL ||
	    (plat_ecc_capability_sc_get(PLAT_ECC_DIMM_SID_MESSAGE) == 0))
		return (ENOTSUP);

	if (parse_unum_memory(unum, &board, &pos, &bank, &dimm,
	    &jnumber) != 0)
		return (EINVAL);

	if (dimm < 0)
		return (EINVAL);

	mcid = plat_make_fru_cpuid(board, 0, pos);
	dimm += (bank * 4);	/* convert dimm from 0-3 to 0-7 value */

	return (p2get_mem_sid(mcid, dimm, buf, buflen, lenp));
}

int
plat_get_mem_offset(uint64_t paddr, uint64_t *offp)
{
	if (p2get_mem_offset != NULL) {
		return (p2get_mem_offset(paddr, offp));
	} else
		return (ENOTSUP);
}

int
plat_get_mem_addr(char *unum, char *sid, uint64_t offset, uint64_t *addrp)
{
	int	board, pos, bank, dimm, jnumber;
	int	mcid;

	if (p2get_mem_addr == NULL ||
	    (plat_ecc_capability_sc_get(PLAT_ECC_DIMM_SID_MESSAGE) == 0))
		return (ENOTSUP);

	if (parse_unum_memory(unum, &board, &pos, &bank, &dimm,
	    &jnumber) != 0)
		return (EINVAL);

	mcid = plat_make_fru_cpuid(board, 0, pos);

	return (p2get_mem_addr(mcid, sid, offset, addrp));
}

dimm_sid_cache_t *
plat_alloc_sid_cache(int *max_entries)
{
	dimm_sid_cache_t *cache;
	int i, bd, p;
	int max_mc_per_bd = plat_max_mc_units_per_board();

	*max_entries = plat_max_cpumem_boards() * max_mc_per_bd;

	cache = (dimm_sid_cache_t *)kmem_zalloc(sizeof (dimm_sid_cache_t) *
	    *max_entries, KM_SLEEP);

	for (i = 0; i < *max_entries; i++) {
		bd = i / max_mc_per_bd;
		p = i % max_mc_per_bd;
		cache[i].mcid = plat_make_fru_cpuid(bd, 0, p);
	}

	return (cache);
}

static void
plat_populate_sid_cache_one(dimm_sid_cache_t *cache, int bd)
{
	int		i, j;
	uint8_t		valid;
	dimm_sid_t	*dimmsidsp;
	int		max_mc_per_bd = plat_max_mc_units_per_board();


	/*
	 * There must be at least one dimm on the board for this
	 * code to be called.
	 */
	ASSERT(domain_dimm_sids[bd].pdsb_valid_bitmap);

	for (i = 0; i < max_mc_per_bd; i++) {
		int index = bd * max_mc_per_bd + i;

		/*
		 * Each entry in the cache represents one mc.
		 * If state is not MC_DIMM_SIDS_REQUESTED, then that mc
		 * either has no DIMMs, is not present, or already has
		 * DIMM serial ids available from a previous call to this
		 * function.
		 */
		if (cache[index].state != MC_DIMM_SIDS_REQUESTED)
			continue;

		valid = domain_dimm_sids[bd].pdsb_valid_bitmap >> (i * 8) &
		    0xff;

		dimmsidsp = cache[index].sids;

		/*
		 * Copy the valid DIMM serial ids.  Each mc can have up to
		 * eight DIMMs.
		 */
		for (j = 0; j < 8; j++) {
			if (((1 << j) & valid) == 0)
				continue;

			(void) strncpy(dimmsidsp[j],
			    domain_dimm_sids[bd].pdsb_dimm_sids[(i * 8) + j],
			    PLAT_MAX_DIMM_SID_LEN);
		}

		cache[index].state = MC_DIMM_SIDS_AVAILABLE;
	}
}

int
plat_populate_sid_cache(dimm_sid_cache_t *cache, int max_entries)
{
	int		i;
	int		bd;
	uint32_t	bds = 0, retry_bds = 0;
	int		max_mc_per_bd = plat_max_mc_units_per_board();
	clock_t		start_lbolt, current_lbolt;
	ulong_t		elapsed_sec;
	int		max_retries = plat_dimm_req_max_retries;

	for (i = 0; i < max_entries; i++) {
		if (cache[i].state == MC_DIMM_SIDS_REQUESTED) {
			bd = i / max_mc_per_bd;
			bds |= (1 << bd);
		}
	}

retry:
	plat_request_all_mem_sids(bds);

	/*
	 * Wait for mailbox messages from SC.
	 * Keep track of elapsed time in order to avoid getting
	 * stuck here if something is wrong with the SC.
	 */
	if (plat_dimm_req_timeout < plat_dimm_req_min_timeout) {
		cmn_err(CE_WARN, "plat_dimm_req_timeout (%d secs) is less "
		    "than the minimum value (%d secs).  Resetting to "
		    "minimum.", plat_dimm_req_timeout,
		    plat_dimm_req_min_timeout);
		plat_dimm_req_timeout = plat_dimm_req_min_timeout;
	}

	start_lbolt = ddi_get_lbolt();

	while (bds) {
		for (bd = 0; bd < plat_max_cpumem_boards(); bd++) {
			if (((1 << bd) & bds) == 0)
				continue;

			switch (domain_dimm_sids[bd].pdsb_state) {
			case PDSB_STATE_STORE_IN_PROGRESS:
				/* Check elapsed time for possible timeout. */
				current_lbolt = ddi_get_lbolt();
				elapsed_sec = TICK_TO_SEC(current_lbolt -
				    start_lbolt);
				if (elapsed_sec > plat_dimm_req_timeout) {
					mutex_enter(&domain_dimm_sids[bd].
					    pdsb_lock);
					domain_dimm_sids[bd].pdsb_state =
					    PDSB_STATE_FAILED_TO_STORE;
					mutex_exit(&domain_dimm_sids[bd].
					    pdsb_lock);
				}
				continue;

			case PDSB_STATE_FAILED_TO_STORE:
				/* Record board# for possible retry */
				retry_bds |= (1 << bd);
				break;

			case PDSB_STATE_STORED:
				/* Success! */
				plat_populate_sid_cache_one(cache, bd);
				break;

			default:
				cmn_err(CE_PANIC, "Unknown state (0x%x) for "
				    "domain_dimm_sids[%d]",
				    domain_dimm_sids[bd].pdsb_state, bd);
			}

			bds &= ~(1 << bd);
		}
		/*
		 * If there are still outstanding requests, delay for one half
		 * second to avoid excessive busy waiting.
		 */
		if (bds != 0)
			delay(drv_usectohz(500000));
	}

	if (max_retries-- && retry_bds) {
		bds = retry_bds;
		retry_bds = 0;
		goto retry;
	} else if (!max_retries && retry_bds) {
		cmn_err(CE_WARN, "!Unable to retrieve DIMM serial ids for "
		    "boards 0x%x", retry_bds);
		return (ETIMEDOUT);
	}

	return (0);
}

/*
 * Functions for requesting DIMM serial id information from the SC and
 * updating and storing it on the domain for use by the Memory Controller
 * driver.
 */

/*
 * Adds DIMM serial id data received from the SC to the domain_dimm_sids[]
 * array. Called by the Serengeti and Starcat mailbox code that handles the
 * reply message from the SC containing a plat_dimm_sid_board_data_t.
 */
int
plat_store_mem_sids(plat_dimm_sid_board_data_t *data)
{
	int	bd;
	int	i;

	bd = data->pdsbd_board_num;

	mutex_enter(&domain_dimm_sids[bd].pdsb_lock);

	if (data->pdsbd_errno) {
		domain_dimm_sids[bd].pdsb_state = PDSB_STATE_FAILED_TO_STORE;
		mutex_exit(&domain_dimm_sids[bd].pdsb_lock);
		cmn_err(CE_WARN, "!plat_store_mem_sids: bd %d  errno %d", bd,
		    data->pdsbd_errno);
		return (data->pdsbd_errno);
	}

	domain_dimm_sids[bd].pdsb_valid_bitmap = data->pdsbd_valid_bitmap;
	for (i = 0; i < PLAT_MAX_DIMMS_PER_BOARD; i++) {
		if ((1 << i) & domain_dimm_sids[bd].pdsb_valid_bitmap) {
			(void) strncpy(domain_dimm_sids[bd].pdsb_dimm_sids[i],
			    data->pdsbd_dimm_sids[i], PLAT_MAX_DIMM_SID_LEN);
		}
	}
	domain_dimm_sids[bd].pdsb_state = PDSB_STATE_STORED;

	mutex_exit(&domain_dimm_sids[bd].pdsb_lock);

	return (0);
}

/*
 * Calls plat_request_mem_sids(bd) for each board number present in the domain.
 * Called the first time the capability exchange is successful and the SC
 * capability indicates support for providing DIMM serial ids.
 *
 * The input argument is a bitmask of cpu/mem boards that are present and
 * have at least one memory controller configured.
 */
static void
plat_request_all_mem_sids(uint32_t bds)
{
	int	bd;
	int	ret;

	for (bd = 0; bd < plat_max_cpumem_boards(); bd++) {
		if (!((1 << bd) & bds))
			continue;

		ret = plat_request_mem_sids(bd);
		if (ret) {
			mutex_enter(&domain_dimm_sids[bd].pdsb_lock);
			domain_dimm_sids[bd].pdsb_state =
			    PDSB_STATE_FAILED_TO_STORE;
			mutex_exit(&domain_dimm_sids[bd].pdsb_lock);
		}
	}
}

/*
 * Initiates a mailbox request to SC for DIMM serial ids for the specified
 * board number.  Called by DR when a CPU/Mem board is connected.  Also
 * called by plat_request_all_mem_sids().
 */
int
plat_request_mem_sids(int boardnum)
{
	plat_ecc_message_t		*wrapperp;
	plat_dimm_sid_request_data_t	*dreqp;

	if (domain_dimm_sids[boardnum].pdsb_state == PDSB_STATE_STORED)
		return (0);

	mutex_enter(&domain_dimm_sids[boardnum].pdsb_lock);
	domain_dimm_sids[boardnum].pdsb_state = PDSB_STATE_STORE_IN_PROGRESS;
	mutex_exit(&domain_dimm_sids[boardnum].pdsb_lock);

	wrapperp = kmem_zalloc(sizeof (plat_ecc_message_t), KM_SLEEP);

	/* Initialize the wrapper */
	wrapperp->ecc_msg_status = PLAT_ECC_NO_MSG_ACTIVE;
	wrapperp->ecc_msg_type = PLAT_ECC_DIMM_SID_MESSAGE;
	wrapperp->ecc_msg_len = sizeof (plat_dimm_sid_request_data_t);
	wrapperp->ecc_msg_data = kmem_zalloc(wrapperp->ecc_msg_len, KM_SLEEP);

	dreqp = (plat_dimm_sid_request_data_t *)wrapperp->ecc_msg_data;

	/* Fill the header */
	dreqp->pdsrd_major_version = PLAT_ECC_DIMM_SID_VERSION_MAJOR;
	dreqp->pdsrd_minor_version = PLAT_ECC_DIMM_SID_VERSION_MINOR;
	dreqp->pdsrd_msg_type = PLAT_ECC_DIMM_SID_MESSAGE;
	dreqp->pdsrd_msg_length = wrapperp->ecc_msg_len;

	/* Set board number DIMM serial ids are requested for */
	dreqp->pdsrd_board_num = boardnum;

	/*
	 * Send the data on to the queuing function
	 */
	return (plat_ecc_dispatch_task(wrapperp));
}

/*
 * Discards DIMM serial id information from domain_dimm_sids[]
 * for a particular board.
 * Called by DR when a CPU/Mem board is disconnected.
 */
int
plat_discard_mem_sids(int boardnum)
{
	mutex_enter(&domain_dimm_sids[boardnum].pdsb_lock);
	domain_dimm_sids[boardnum].pdsb_state = PDSB_STATE_INVALID;
	mutex_exit(&domain_dimm_sids[boardnum].pdsb_lock);

	return (0);
}
