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
 * s1394_misc.c
 *    1394 Services Layer Miscellaneous Routines
 *    This file contains miscellaneous routines used as "helper" functions
 *    by various other files in the Services Layer.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>

int s1394_print_guids = 0;		/* patch to print GUIDs */

extern void nx1394_undefine_events(s1394_hal_t *hal);
static void s1394_cleanup_node_cfgrom(s1394_hal_t *hal);

/*
 * s1394_cleanup_for_detach()
 *    is used to do all of the necessary cleanup to handle a detach or a
 *    failure in h1394_attach().  The cleanup_level specifies how far we
 *    got in h1394_attach() before failure.
 */
void
s1394_cleanup_for_detach(s1394_hal_t *hal, uint_t cleanup_level)
{

	switch (cleanup_level) {
	case H1394_CLEANUP_LEVEL7:
		/* remove HAL from the global HAL list */
		mutex_enter(&s1394_statep->hal_list_mutex);
		if ((s1394_statep->hal_head == hal) &&
		    (s1394_statep->hal_tail == hal)) {
			s1394_statep->hal_head = NULL;
			s1394_statep->hal_tail = NULL;
		} else {
			if (hal->hal_prev)
				hal->hal_prev->hal_next = hal->hal_next;
			if (hal->hal_next)
				hal->hal_next->hal_prev = hal->hal_prev;
			if (s1394_statep->hal_head == hal)
				s1394_statep->hal_head = hal->hal_next;
			if (s1394_statep->hal_tail == hal)
				s1394_statep->hal_tail = hal->hal_prev;
		}
		mutex_exit(&s1394_statep->hal_list_mutex);
		/*
		 * No FCP cleanup needed at this time -- the following call
		 * to s1394_destroy_addr_space() takes care of everything.
		 */
		/* FALLTHROUGH */

	case H1394_CLEANUP_LEVEL6:
		s1394_destroy_addr_space(hal);
		/* FALLTHROUGH */

	case H1394_CLEANUP_LEVEL5:
		s1394_destroy_local_config_rom(hal);
		/* FALLTHROUGH */

	case H1394_CLEANUP_LEVEL4:
		/* Undo all the kstat stuff */
		(void) s1394_kstat_delete(hal);
		/* FALLTHROUGH */

	case H1394_CLEANUP_LEVEL3:
		/* Free up the memory for selfID buffer #1 */
		kmem_free(hal->selfid_buf1, S1394_SELFID_BUF_SIZE);
		/* Free up the memory for selfID buffer #0 */
		kmem_free(hal->selfid_buf0, S1394_SELFID_BUF_SIZE);
		/* Turn off any timers that might be set */
		s1394_destroy_timers(hal);
		/* Destroy the bus_reset thread */
		s1394_destroy_br_thread(hal);
		/* Cleanup the Config ROM buffers in the topology_tree */
		s1394_cleanup_node_cfgrom(hal);
		/* FALLTHROUGH */

	case H1394_CLEANUP_LEVEL2:
		/* Destroy the br_cmplq_cv and br_cmplq_mutex */
		cv_destroy(&hal->br_cmplq_cv);
		mutex_destroy(&hal->br_cmplq_mutex);
		/* Destroy the br_thread_cv and br_thread_mutex */
		cv_destroy(&hal->br_thread_cv);
		mutex_destroy(&hal->br_thread_mutex);
		/* FALLTHROUGH */

	case H1394_CLEANUP_LEVEL1:
		(void) ddi_prop_remove_all(hal->halinfo.dip);
		nx1394_undefine_events(hal);
		/* FALLTHROUGH */

	case H1394_CLEANUP_LEVEL0:
		kmem_cache_destroy(hal->hal_kmem_cachep);
		/* Destroy pending_q_mutex and outstanding_q_mutex */
		mutex_destroy(&hal->pending_q_mutex);
		mutex_destroy(&hal->outstanding_q_mutex);
		/* Destroy target_list_rwlock */
		rw_destroy(&hal->target_list_rwlock);
		/* Destroy bus_mgr_node_mutex and bus_mgr_node_cv */
		cv_destroy(&hal->bus_mgr_node_cv);
		mutex_destroy(&hal->bus_mgr_node_mutex);
		/* Destroy isoch_cec_list_mutex */
		mutex_destroy(&hal->isoch_cec_list_mutex);
		/* Destroy the Cycle Master timer mutex */
		mutex_destroy(&hal->cm_timer_mutex);
		/* Destroy topology_tree_mutex */
		mutex_destroy(&hal->topology_tree_mutex);
		/* Free the hal structure */
		kmem_free(hal, sizeof (s1394_hal_t));
		break;

	default:
		/* Error */
		break;
	}
}

/*
 * s1394_hal_shutdown()
 *    is used to shutdown the HAL.  If the HAL indicates that an error
 *    condition (hardware or software) has occurred, it is shutdown. This
 *    routine is also called when HAL informs the services layer of a shutdown
 *    (due an internal shutdown, for eg). disable_hal indicates whether the
 *    caller intends to inform the hal of the (services layer) shutdown or not.
 */
void
s1394_hal_shutdown(s1394_hal_t *hal, boolean_t disable_hal)
{
	ddi_eventcookie_t cookie;
	t1394_localinfo_t localinfo;

	mutex_enter(&hal->topology_tree_mutex);

	if (hal->hal_state == S1394_HAL_SHUTDOWN) {
		mutex_exit(&hal->topology_tree_mutex);
		if (disable_hal == B_TRUE)
			HAL_CALL(hal).shutdown(hal->halinfo.hal_private);

		return;
	}

	hal->hal_state = S1394_HAL_SHUTDOWN;
	mutex_exit(&hal->topology_tree_mutex);
	/* Disable the HAL */
	if (disable_hal == B_TRUE)
		HAL_CALL(hal).shutdown(hal->halinfo.hal_private);

	/*
	 * Send a remove event to all interested parties
	 */
	mutex_enter(&hal->topology_tree_mutex);
	localinfo.bus_generation = hal->generation_count;
	localinfo.local_nodeID	 = hal->node_id;
	mutex_exit(&hal->topology_tree_mutex);

	if (ndi_event_retrieve_cookie(hal->hal_ndi_event_hdl, NULL,
	    DDI_DEVI_REMOVE_EVENT, &cookie, NDI_EVENT_NOPASS) ==
	    NDI_SUCCESS)
		(void) ndi_event_run_callbacks(hal->hal_ndi_event_hdl, NULL,
		    cookie, &localinfo);
}

/*
 * s1394_initiate_hal_reset()
 *    sets up the HAL structure to indicate a self-initiated bus reset and
 *    calls the appropriate HAL entry point.  If too many bus resets have
 *    happened, a message is printed out and the call is ignored.
 */
void
s1394_initiate_hal_reset(s1394_hal_t *hal, int reason)
{
	if (hal->num_bus_reset_till_fail > 0) {
		hal->initiated_bus_reset = B_TRUE;
		hal->initiated_br_reason = reason;

		/* Reset the bus */
		(void) HAL_CALL(hal).bus_reset(hal->halinfo.hal_private);
	} else {
		cmn_err(CE_NOTE, "Unable to reenumerate the 1394 bus - If new"
		    " devices have recently been added, remove them.");
	}
}

/*
 * s1394_on_br_thread()
 *    is used to determine if the current thread of execution is the same
 *    as the bus reset thread.  This is useful during bus reset callbacks
 *    to determine whether or not a target may block.
 */
boolean_t
s1394_on_br_thread(s1394_hal_t *hal)
{
	if (hal->br_thread == curthread)
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * s1394_destroy_br_thread()
 *    is used in h1394_detach() to signal the bus reset thread to go away.
 */
void
s1394_destroy_br_thread(s1394_hal_t *hal)
{
	/* Send the signal to the reset thread to go away */
	mutex_enter(&hal->br_thread_mutex);
	hal->br_thread_ev_type |= BR_THR_GO_AWAY;
	cv_signal(&hal->br_thread_cv);
	mutex_exit(&hal->br_thread_mutex);

	/* Wakeup the bus_reset thread if waiting for bus_mgr timer */
	mutex_enter(&hal->bus_mgr_node_mutex);
	hal->bus_mgr_node = S1394_INVALID_NODE_NUM;
	cv_signal(&hal->bus_mgr_node_cv);
	mutex_exit(&hal->bus_mgr_node_mutex);

	mutex_enter(&hal->br_cmplq_mutex);
	cv_signal(&hal->br_cmplq_cv);
	mutex_exit(&hal->br_cmplq_mutex);

	/* Wait for the br_thread to be done */
	while (hal->br_thread_ev_type & BR_THR_GO_AWAY)
		delay(drv_usectohz(10));
}

/*
 * s1394_tickle_bus_reset_thread()
 *    is used to wakeup the bus reset thread after the interrupt routine
 *    has completed its bus reset processing.
 */
void
s1394_tickle_bus_reset_thread(s1394_hal_t *hal)
{
	if (hal->topology_tree_processed != B_TRUE) {
		/* Send the signal to the reset thread */
		mutex_enter(&hal->br_thread_mutex);
		hal->br_thread_ev_type |= BR_THR_CFGROM_SCAN;
		cv_signal(&hal->br_thread_cv);
		mutex_exit(&hal->br_thread_mutex);

		/* Signal the msgq wait, too (just in case) */
		mutex_enter(&hal->br_cmplq_mutex);
		cv_signal(&hal->br_cmplq_cv);
		mutex_exit(&hal->br_cmplq_mutex);

		/* Signal the bus_mgr wait, too (just in case) */
		mutex_enter(&hal->bus_mgr_node_mutex);
		cv_signal(&hal->bus_mgr_node_cv);
		mutex_exit(&hal->bus_mgr_node_mutex);
	}
}

/*
 * s1394_block_on_asynch_cmd()
 *    is used by many of the asynch routines to block (if necessary)
 *    while waiting for command completion.
 */
void
s1394_block_on_asynch_cmd(cmd1394_cmd_t	*cmd)
{
	s1394_cmd_priv_t  *s_priv;

	/* Get the Services Layer private area */
	s_priv = S1394_GET_CMD_PRIV(cmd);

	/* Is this a blocking command? */
	if (cmd->cmd_options & CMD1394_BLOCKING) {
		/* Block until command completes */
		mutex_enter(&s_priv->blocking_mutex);
		while (s_priv->blocking_flag != B_TRUE)
			cv_wait(&s_priv->blocking_cv, &s_priv->blocking_mutex);
		s_priv->blocking_flag = B_FALSE;
		mutex_exit(&s_priv->blocking_mutex);
	}
}

/*
 * s1394_HAL_asynch_error()
 *    is used by many of the asynch routines to determine what error
 *    code is expected in a given situation (based on HAL state).
 */
/* ARGSUSED */
int
s1394_HAL_asynch_error(s1394_hal_t *hal, cmd1394_cmd_t *cmd,
    s1394_hal_state_t state)
{

	ASSERT(MUTEX_HELD(&hal->topology_tree_mutex));

	switch (state) {
	case S1394_HAL_RESET:
		/* "dreq" bit is set (CSR) */
		if (hal->disable_requests_bit == 1)
			return (CMD1394_ENO_ATREQ);
		else
			return (CMD1394_CMDSUCCESS);

	case S1394_HAL_DREQ:
		/* "dreq" bit is set (CSR) */
		return (CMD1394_ENO_ATREQ);

	case S1394_HAL_SHUTDOWN:
		return (CMD1394_EFATAL_ERROR);

	default:
		return (CMD1394_CMDSUCCESS);
	}
}

/*
 * s1394_mblk_too_small()
 *    is used to determine if the mlbk_t structure(s) given in an asynch
 *    block request are sufficient to hold the amount of data requested.
 */
boolean_t
s1394_mblk_too_small(cmd1394_cmd_t *cmd)
{
	mblk_t	  *curr_blk;
	boolean_t flag;
	size_t	  msgb_len;
	size_t	  size;

	curr_blk = cmd->cmd_u.b.data_block;
	msgb_len = 0;
	flag = B_TRUE;
	size = cmd->cmd_u.b.blk_length;

	while (curr_blk != NULL) {
		if (cmd->cmd_type == CMD1394_ASYNCH_WR_BLOCK) {
			msgb_len += (curr_blk->b_wptr - curr_blk->b_rptr);
		} else {
			msgb_len +=
			    (curr_blk->b_datap->db_lim - curr_blk->b_wptr);
		}

		if (msgb_len >= size) {
			flag = B_FALSE;
			break;
		}

		curr_blk = curr_blk->b_cont;
	}

	return (flag);
}

/*
 * s1394_address_rollover()
 *    is used to determine if the address given will rollover the 48-bit
 *    address space.
 */
boolean_t
s1394_address_rollover(cmd1394_cmd_t *cmd)
{
	uint64_t addr_before;
	uint64_t addr_after;
	size_t	 length;

	switch (cmd->cmd_type) {
	case CMD1394_ASYNCH_RD_QUAD:
	case CMD1394_ASYNCH_WR_QUAD:
	case CMD1394_ASYNCH_LOCK_32:
		length = IEEE1394_QUADLET;
		break;

	case CMD1394_ASYNCH_LOCK_64:
		length = IEEE1394_OCTLET;
		break;

	case CMD1394_ASYNCH_RD_BLOCK:
	case CMD1394_ASYNCH_WR_BLOCK:
		length = cmd->cmd_u.b.blk_length;
		break;
	}

	addr_before = cmd->cmd_addr & IEEE1394_ADDR_OFFSET_MASK;
	addr_after = (addr_before + length) & IEEE1394_ADDR_OFFSET_MASK;

	if (addr_after < addr_before) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * s1394_stoi()
 *    returns the integer value of the string of hex/dec/oct numeric characters
 *    beginning at *p. Does no overflow checking.
 */
uint_t
s1394_stoi(char *p, int len, int base)
{
	int	n;
	int	c;

	if (len == 0)
		return (0);

	for (n = 0; len && (c = *p); p++, len--) {
		if (c >= '0' && c <= '9')
			c = c - '0';
		else if (c >= 'a' && c <= 'f')
			c = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			c = c - 'F' + 10;
		n = (n * base) + c;
	}

	return (n);
}

/*
 * s1394_CRC16()
 *    implements ISO/IEC 13213:1994, ANSI/IEEE Std 1212, 1994 - 8.1.5
 */
uint_t
s1394_CRC16(uint_t *d, uint_t crc_length)
{
	uint_t	CRC = 0;
	uint_t	data;
	uint_t	next;
	uint_t	sum;
	int	shift;
	int	i;

	for (i = 0; i < crc_length; i++) {
		data = d[i];

		/* Another check should be made with "shift > 0" in  */
		/* order to support any devices that coded it wrong. */
		for (next = CRC, shift = 28; shift >= 0; shift -= 4) {
			sum = ((next >> 12) ^ (data >> shift)) & 0xF;
			next = (next << 4) ^ (sum << 12) ^ (sum << 5) ^ (sum);
		}
		CRC = next & IEEE1394_CRC16_MASK;
	}

	return (CRC);
}

/*
 * s1394_CRC16_old()
 *    implements a slightly modified version of ISO/IEC 13213:1994,
 *    ANSI/IEEE Std 1212, 1994 - 8.1.5.  In the original IEEE 1212-1994
 *    specification the C code example was incorrect and some devices
 *    were manufactured using this incorrect CRC.  On CRC16 failures
 *    this CRC is tried in case it is a legacy device.
 */
uint_t
s1394_CRC16_old(uint_t *d, uint_t crc_length)
{
	uint_t	CRC = 0;
	uint_t	data;
	uint_t	next;
	uint_t	sum;
	int	shift;
	int	i;

	for (i = 0; i < crc_length; i++) {
		data = d[i];
		for (next = CRC, shift = 28; shift > 0; shift -= 4) {
			sum = ((next >> 12) ^ (data >> shift)) & 0xF;
			next = (next << 4) ^ (sum << 12) ^ (sum << 5) ^ (sum);
		}
		CRC = next & IEEE1394_CRC16_MASK;
	}

	return (CRC);
}

/*
 * s1394_ioctl()
 *    implements generic ioctls (eg. devctl support) and any non-HAL ioctls.
 *    Only ioctls required for devctl support are implemented at present.
 */
/* ARGSUSED */
int
s1394_ioctl(s1394_hal_t *hal, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	struct devctl_iocdata	*dcp;
	dev_info_t		*self;
	int			rv = 0;

	self = hal->halinfo.dip;

	/*
	 * We can use the generic implementation for these ioctls
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(self, cmd, arg, mode, 0));
	}

	/* Read devctl ioctl data */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS) {
		return (EFAULT);
	}

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
	case DEVCTL_DEVICE_REMOVE:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_CONFIGURE:
	case DEVCTL_BUS_UNCONFIGURE:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_QUIESCE:
	case DEVCTL_BUS_UNQUIESCE:
		rv = ENOTSUP;	/* Or call up the tree? */
		break;

	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
		if (hal->halinfo.phy == H1394_PHY_1394A) {
			(void) HAL_CALL(hal).short_bus_reset(
			    hal->halinfo.hal_private);
		} else {
			(void)
			    HAL_CALL(hal).bus_reset(hal->halinfo.hal_private);
		}
		break;

	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);

	return (rv);
}

/*
 * s1394_kstat_init()
 *    is used to initialize and the Services Layer's kernel statistics.
 */
int
s1394_kstat_init(s1394_hal_t *hal)
{
	int instance;

	hal->hal_kstats = (s1394_kstat_t *)kmem_zalloc(sizeof (s1394_kstat_t),
	    KM_SLEEP);

	instance = ddi_get_instance(hal->halinfo.dip);

	hal->hal_ksp = kstat_create("s1394", instance, "stats", "misc",
	    KSTAT_TYPE_RAW, sizeof (s1394_kstat_t), KSTAT_FLAG_VIRTUAL);
	if (hal->hal_ksp != NULL) {
		hal->hal_ksp->ks_private = (void *)hal;
		hal->hal_ksp->ks_update = s1394_kstat_update;
		kstat_install(hal->hal_ksp);

		return (DDI_SUCCESS);
	} else {
		kmem_free((void *)hal->hal_kstats, sizeof (s1394_kstat_t));
		return (DDI_FAILURE);
	}
}

/*
 * s1394_kstat_delete()
 *    is used (in h1394_detach()) to cleanup/free and the Services Layer's
 *    kernel statistics.
 */
int
s1394_kstat_delete(s1394_hal_t *hal)
{
	kstat_delete(hal->hal_ksp);
	kmem_free((void *)hal->hal_kstats, sizeof (s1394_kstat_t));

	return (DDI_SUCCESS);
}

/*
 * s1394_kstat_update()
 *    is a callback that is called whenever a request to read the kernel
 *    statistics is made.
 */
int
s1394_kstat_update(kstat_t *ksp, int rw)
{
	s1394_hal_t	*hal;

	hal = ksp->ks_private;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		ksp->ks_data = hal->hal_kstats;
	}

	return (0);
}

/*
 * s1394_addr_alloc_kstat()
 *    is used by the kernel statistics to update the count for each type of
 *    address allocation.
 */
void
s1394_addr_alloc_kstat(s1394_hal_t *hal, uint64_t addr)
{
	/* kstats - number of addr allocs */
	if (s1394_is_posted_write(hal, addr) == B_TRUE)
		hal->hal_kstats->addr_posted_alloc++;
	else if (s1394_is_normal_addr(hal, addr) == B_TRUE)
		hal->hal_kstats->addr_normal_alloc++;
	else if (s1394_is_csr_addr(hal, addr) == B_TRUE)
		hal->hal_kstats->addr_csr_alloc++;
	else if (s1394_is_physical_addr(hal, addr) == B_TRUE)
		hal->hal_kstats->addr_phys_alloc++;
}

/*
 * s1394_print_node_info()
 *    is used to print speed map and GUID information on the console.
 */
void
s1394_print_node_info(s1394_hal_t *hal)
{
	int	i, j;
	uint_t	hal_node_num;
	char	str[200], tmp[200];

	/* These are in common/os/logsubr.c */
	extern void log_enter(void);
	extern void log_exit(void);

	if (s1394_print_guids == 0)
		return;

	hal_node_num = IEEE1394_NODE_NUM(hal->node_id);

	log_enter();

	cmn_err(CE_CONT, "Speed Map (%d):\n",
	    ddi_get_instance(hal->halinfo.dip));

	(void) strcpy(str, "    |");
	for (i = 0; i < hal->number_of_nodes; i++) {
	    (void) sprintf(tmp, " %2d ", i);
	    (void) strcat(str, tmp);
	}
	(void) strcat(str, "  |       GUID\n");
	cmn_err(CE_CONT, str);

	(void) strcpy(str, "----|");
	for (i = 0; i < hal->number_of_nodes; i++) {
	    (void) sprintf(tmp, "----");
	    (void) strcat(str, tmp);
	}
	(void) strcat(str, "--|------------------\n");
	cmn_err(CE_CONT, str);

	for (i = 0; i < hal->number_of_nodes; i++) {

	    (void) sprintf(str, " %2d |", i);

	    for (j = 0; j < hal->number_of_nodes; j++) {
		(void) sprintf(tmp, " %3d", hal->speed_map[i][j]);
		(void) strcat(str, tmp);
	    }

	    if (i == hal_node_num) {

		(void) strcat(str, "  | Local OHCI Card\n");

	    } else if (CFGROM_BIB_READ(&hal->topology_tree[i])) {

		(void) sprintf(tmp, "  | %08x%08x\n",
				    hal->topology_tree[i].node_guid_hi,
				    hal->topology_tree[i].node_guid_lo);
		(void) strcat(str, tmp);

	    } else if (hal->topology_tree[i].link_active == 0) {

		(void) strcat(str, "  | Link off\n");

	    } else {

		(void) strcat(str, "  | ????????????????\n");
	    }
	    cmn_err(CE_CONT, str);
	}
	cmn_err(CE_CONT, "\n");

	log_exit();
}

/*
 * s1394_dip_to_hal()
 *    is used to lookup a HAL's structure pointer by its dip.
 */
s1394_hal_t *
s1394_dip_to_hal(dev_info_t *hal_dip)
{
	s1394_hal_t	*current_hal = NULL;

	mutex_enter(&s1394_statep->hal_list_mutex);

	/* Search the HAL list for this dip */
	current_hal = s1394_statep->hal_head;
	while (current_hal != NULL) {
		if (current_hal->halinfo.dip == hal_dip) {
			break;
		}
		current_hal = current_hal->hal_next;
	}

	mutex_exit(&s1394_statep->hal_list_mutex);

	return (current_hal);
}

/*
 * s1394_target_from_dip_locked()
 *    searches target_list on the HAL for target corresponding to tdip;
 *    if found, target is returned, else returns NULL. This routine assumes
 *    target_list_rwlock is locked.
 *    NOTE: the callers may have the list locked in either write mode or read
 *    mode. Currently, there is no ddi-compliant way we can assert on the lock
 *    being held in write mode.
 */
s1394_target_t *
s1394_target_from_dip_locked(s1394_hal_t *hal, dev_info_t *tdip)
{
	s1394_target_t	*temp;

	temp = hal->target_head;
	while (temp != NULL) {
	    if (temp->target_dip == tdip) {
		return (temp);
	    }
	    temp = temp->target_next;
	}

	return (NULL);
}
/*
 * s1394_target_from_dip()
 *    searches target_list on the HAL for target corresponding to tdip;
 *    if found, target is returned locked.
 */
s1394_target_t *
s1394_target_from_dip(s1394_hal_t *hal, dev_info_t *tdip)
{
	s1394_target_t	*target;

	rw_enter(&hal->target_list_rwlock, RW_READER);
	target = s1394_target_from_dip_locked(hal, tdip);
	rw_exit(&hal->target_list_rwlock);

	return (target);
}

/*
 * s1394_destroy_timers()
 *    turns off any outstanding timers in preparation for detach or suspend.
 */
void
s1394_destroy_timers(s1394_hal_t *hal)
{
	/* Destroy both of the Bus Mgr timers */
	(void) untimeout(hal->bus_mgr_timeout_id);
	(void) untimeout(hal->bus_mgr_query_timeout_id);

	/* Destroy the Cycle Master timer */
	(void) untimeout(hal->cm_timer);

	/* Wait for the Config ROM timer (if necessary) */
	while (hal->config_rom_timer_set == B_TRUE) {
		delay(drv_usectohz(10));
	}
}


/*
 * s1394_cleanup_node_cfgrom()
 *    frees up all of the Config ROM in use by nodes in the topology_tree
 */
static void
s1394_cleanup_node_cfgrom(s1394_hal_t *hal)
{
	uint32_t *cfgrom;
	int	 i;

	for (i = 0; i < IEEE1394_MAX_NODES; i++) {
		if ((cfgrom = hal->topology_tree[i].cfgrom) != NULL)
			kmem_free(cfgrom, IEEE1394_CONFIG_ROM_SZ);
	}
}

/*
 * s1394_cycle_too_long_callback()
 *    turns on the cycle master bit of the root node (current Cycle Master)
 */
void
s1394_cycle_too_long_callback(void *arg)
{
	s1394_hal_t	*hal;
	ushort_t	root_node_num;
	ushort_t	hal_node_num;
	uint32_t	data;
	uint_t		offset;

	hal = (s1394_hal_t *)arg;

	/* Clear the cm_timer_cet bit */
	mutex_enter(&hal->topology_tree_mutex);
	mutex_enter(&hal->cm_timer_mutex);
	hal->cm_timer_set = B_FALSE;
	mutex_exit(&hal->cm_timer_mutex);

	/* Get the root node and host node numbers */
	root_node_num = hal->number_of_nodes - 1;
	hal_node_num  = IEEE1394_NODE_NUM(hal->node_id);
	mutex_exit(&hal->topology_tree_mutex);

	/* If we are the root node, set the cycle master bit */
	if (hal_node_num == root_node_num) {
		data	= IEEE1394_CSR_STATE_CMSTR;
		offset  = (IEEE1394_CSR_STATE_SET & IEEE1394_CSR_OFFSET_MASK);
		(void) HAL_CALL(hal).csr_write(hal->halinfo.hal_private,
		    offset, data);
	}
}
