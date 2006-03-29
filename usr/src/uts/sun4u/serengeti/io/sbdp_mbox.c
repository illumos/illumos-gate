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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpuvar.h>
#include <sys/cpu_module.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/param.h>
#include <sys/obpdefs.h>
#include <sys/prom_plat.h>
#include <sys/sgsbbc_mailbox.h>
#include <sys/sbd_ioctl.h>
#include <sys/sbdp_priv.h>
#include <sys/sbdp_mbox.h>
#include <sys/promif.h>
#include <sys/plat_ecc_dimm.h>

#define	UNKNOWN "unknown"
#define	INITL_STATUS	0xdead

int sbdp_mbox_wait = 86400;	/* in seconds */
int sbdp_shw_bd_wait = 5;	/* in seconds */

int sbdp_sc_err_translation(int);
int sbdp_poweroff_wkaround = 1;

/*
 * By default, DR of non-Panther procs is not allowed into a Panther
 * domain with large page sizes enabled.  Setting this to 0 will remove
 * the restriction.
 */
static int sbdp_large_page_restriction = 1;

/*
 * Initialize the data structs for the common part of the pkts
 */
void
sbdp_init_msg_pkt(sbbc_msg_t *msg, uint16_t sub_type, int len, caddr_t buf)
{
	msg->msg_type.type = DR_MBOX;
	msg->msg_type.sub_type = sub_type;
	msg->msg_status = INITL_STATUS;
	msg->msg_len = len;
	msg->msg_buf = buf;
	msg->msg_data[0] = 0;
	msg->msg_data[1] = 0;

}

/*
 * Convert a showboard data structure to the board structure shared
 * between sbd and sbdp
 */
void
sbdp_showbd_2_sbd_stat(show_board_t *shbp, sbd_stat_t *stp, int board)
{
	static fn_t	f = "sbdp_showbd_2_sbd_stat";

	SBDP_DBG_FUNC("%s\n", f);

	stp->s_board = board;
	(void) strcpy(stp->s_info, shbp->s_info);
	stp->s_power = shbp->s_power;

	(void) strcpy(stp->s_type, shbp->s_type);

	if (shbp->s_present == 0) {
		/*
		 * This should go away since the SC should put the unknown
		 * We leave this here so Symon and other scripts don't have
		 * a problem
		 */
		(void) strcpy(stp->s_type, UNKNOWN);
		stp->s_rstate = SBD_STAT_EMPTY;
	} else if (shbp->s_claimed == 0)
		stp->s_rstate = SBD_STAT_DISCONNECTED;
	else
		stp->s_rstate = SBD_STAT_CONNECTED;


	stp->s_assigned = shbp->s_assigned;
	stp->s_cond = shbp->s_cond;
}

/*
 * Entry point from sbd.  Get the status from the SC and then convert
 * the info returned into something that sbd understands
 * If the request times out or fails other than an illegal transaction
 * copy the info from our inventory
 */
int
sbdp_get_board_status(sbdp_handle_t *hp, sbd_stat_t *stp)
{
	int		board = hp->h_board;
	int		node = hp->h_wnode;
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	info_t		inform, *informp = &inform;
	show_board_t	show_bd, *shbp = &show_bd;
	int		rv = 0;
	sbd_error_t	*sep = hp->h_err;
	int		len;
	sbdp_bd_t	*bdp;
	static fn_t	f = "sbdp_get_board_status";

	SBDP_DBG_FUNC("%s\n", f);

	/*
	 * Check for options.  If there are any, fail the operation
	 */
	if (hp->h_opts != NULL && hp->h_opts->copts != NULL) {
		sbdp_set_err(sep, ESBD_INVAL_OPT, hp->h_opts->copts);
		return (-1);
	}

	bdp = sbdp_get_bd_info(node, board);

	informp->board = board;
	informp->node = node;
	informp->revision = 0xdead;
	len = sizeof (info_t);

	sbdp_init_msg_pkt(reqp, DR_MBOX_SHOW_BOARD, len, (caddr_t)informp);

	bzero(shbp, sizeof (show_board_t));
	shbp->s_cond = -1;
	shbp->s_power = -1;
	shbp->s_assigned = -1;
	shbp->s_claimed = -1;
	shbp->s_present = -1;
	len = sizeof (show_board_t);

	sbdp_init_msg_pkt(resp, DR_MBOX_SHOW_BOARD, len, (caddr_t)shbp);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_shw_bd_wait);

	SBDP_DBG_MISC("show board completed: rv = %d\n", rv);

	/*
	 * This domain has no access to this board. Return failure
	 */
	if ((resp->msg_status == SG_MBOX_STATUS_BOARD_ACCESS_DENIED) ||
		(resp->msg_status == SG_MBOX_STATUS_ILLEGAL_SLOT) ||
		(resp->msg_status == SG_MBOX_STATUS_ILLEGAL_NODE)) {

		/*
		 * invalidate cached copy.
		 */
		bdp->valid_cp = -1;

		sbdp_set_err(sep, ESGT_GET_BOARD_STAT, NULL);
		return (EIO);
	}

	/*
	 * If we get any error see if we can return a cached copy of the
	 * board info.  If one exists turn the busy flag on
	 */
	if (rv != 0) {
		mutex_enter(&bdp->bd_mutex);
		if (bdp->valid_cp == -1) {
			sbdp_set_err(sep, ESGT_GET_BOARD_STAT,
			    NULL);
			mutex_exit(&bdp->bd_mutex);
			return (EIO);
		}

		/*
		 * we have a valid copy.  Return it and set the
		 * busy flag on so the user know this is not the most
		 * recent copy
		 */
		bcopy(bdp->bd_sc, shbp, sizeof (show_board_t));
		mutex_exit(&bdp->bd_mutex);
		stp->s_busy = 1;
		/*
		 * The sbbc returns the error in both parts (i.e rv and status)
		 * so since we just took care of it reset rv
		 */
		rv = 0;
	} else {
		/*
		 * revalidate our copy of the returned data
		 */
		if (bdp == NULL) {
			SBDP_DBG_MBOX("HUGE ERROR\n");
		} else {
			mutex_enter(&bdp->bd_mutex);
			bcopy(shbp, bdp->bd_sc, sizeof (show_board_t));
			bdp->valid_cp = 1;
			mutex_exit(&bdp->bd_mutex);
		}
	}


	SBDP_DBG_MBOX("Showboard: board\t%d\n\trevision\t%d\n\ts_cond\t%d\n\t"
		"s_power\t%d\n\ts_assigned\t%d\n\ts_claimed\t%d\n\t"
		"s_present\t%d\n\ts_ledstatus\t%d\n\ts_type\t%s\n\t"
		"s_info\t%s\n",
			board, shbp->revision, shbp->s_cond, shbp->s_power,
			shbp->s_assigned, shbp->s_claimed, shbp->s_present,
			shbp->s_ledstatus, shbp->s_type, shbp->s_info);

	/*
	 * Now that we got the info run through the sbd-sbdp translator
	 */
	sbdp_showbd_2_sbd_stat(shbp, stp, board);

	/*
	 * Last add the platform options
	 */
	SBDP_PLATFORM_OPTS(stp->s_platopts);

	return (rv);
}

/*
 * Entry point from sbd.  Call down to the SC to assign the board
 * We simply return the status the SC told us
 */
int
sbdp_assign_board(sbdp_handle_t *hp)
{
	int		board = hp->h_board;
	int		node = hp->h_wnode;
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		cmd_rev = -1;
	info2_t		inform, *informp = &inform;
	int		rv = 0;
	sbd_error_t	*sep;
	int		len;
	static fn_t	f = "sbdp_assign_board";

	SBDP_DBG_FUNC("%s\n", f);

	sep = hp->h_err;
	/*
	 * Check for options.  If there are any, fail the operation
	 */
	if (hp->h_opts != NULL && hp->h_opts->copts != NULL) {
		sbdp_set_err(sep, ESBD_INVAL_OPT, hp->h_opts->copts);
		return (-1);
	}

	informp->board = board;
	informp->node = node;
	informp->extra = SBDP_ASSIGN;
	len =	sizeof (info2_t);

	sbdp_init_msg_pkt(reqp, DR_MBOX_ASSIGN, len, (caddr_t)informp);

	len =  sizeof (cmd_rev);

	sbdp_init_msg_pkt(resp, DR_MBOX_ASSIGN, len, (caddr_t)&cmd_rev);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to assign board: rv = %d\n", rv);
		sbdp_set_err(sep, sbdp_sc_err_translation(resp->msg_status),
		    NULL);
	}

	return (rv);
}

/*
 * Entry point from sbd.  Call down to the SC to unassign the board
 * We simply return the status the SC told us
 */
int
sbdp_unassign_board(sbdp_handle_t *hp)
{
	int		board = hp->h_board;
	int		node = hp->h_wnode;
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		cmd_rev = -1;
	info2_t		inform, *informp = &inform;
	int		rv = 0;
	sbd_error_t	*sep;
	int		len;
	static fn_t	f = "sbdp_unassign_board";

	SBDP_DBG_FUNC("%s\n", f);

	sep = hp->h_err;
	/*
	 * Check for options.  If there are any, fail the operation
	 */
	if (hp->h_opts != NULL && hp->h_opts->copts != NULL) {
		sbdp_set_err(sep, ESBD_INVAL_OPT, hp->h_opts->copts);
		return (-1);
	}

	informp->board = board;
	informp->node = node;
	informp->extra = SBDP_UNASSIGN;
	len =	sizeof (info2_t);

	sbdp_init_msg_pkt(reqp, DR_MBOX_ASSIGN, len, (caddr_t)informp);

	len =  sizeof (cmd_rev);

	sbdp_init_msg_pkt(resp, DR_MBOX_ASSIGN, len, (caddr_t)&cmd_rev);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to unassign board: rv = %d\n", rv);
		sbdp_set_err(sep, sbdp_sc_err_translation(resp->msg_status),
		    NULL);
	}

	return (rv);
}

static int
sg_attach_board(void *arg)
{
	sbdp_handle_t	*hp;
	cpuset_t	cset;
	int		rv;
	static fn_t	f = "sg_attach_board";

	SBDP_DBG_FUNC("%s\n", f);

	hp = (sbdp_handle_t *)arg;

	cset = cpu_ready_set;
	promsafe_xc_attention(cset);
	rv = prom_serengeti_attach_board(hp->h_wnode, hp->h_board);
	xc_dismissed(cset);

	return (rv);
}

static int
sg_detach_board(void *arg)
{
	sbdp_handle_t	*hp;
	cpuset_t	cset;
	int		rv;
	static fn_t	f = "sg_detach_board";

	SBDP_DBG_FUNC("%s\n", f);

	hp = (sbdp_handle_t *)arg;

	cset = cpu_ready_set;
	promsafe_xc_attention(cset);
	rv = prom_serengeti_detach_board(hp->h_wnode, hp->h_board);
	xc_dismissed(cset);

	return (rv);
}

/*
 * Entry point from sbd.  First we call down to the SC to "attach/claim" this
 * board.  As a side effect the SC updates the pda info so obp can create the
 * device tree.  If we are successful, we ask OBP to probe the board.  OBP
 * creates new nodes on its own obp tree
 * As an added bonus, since we don't use the inkernel prober, we need to create
 * the dev_info nodes but just to a point where they are created but
 * Solaris can't use them (i.e BIND)
 */
int
sbdp_connect_board(sbdp_handle_t *hp)
{
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		rv = 0;
	int		board, node;
	sbd_error_t	*sep;
	static fn_t	f = "sbdp_connect_board";
	int		panther_pages_enabled;

	SBDP_DBG_FUNC("%s\n", f);

	board = hp->h_board;
	node = hp->h_wnode;
	sep = hp->h_err;

	/*
	 * Check for options.  If there are any, fail the operation
	 */
	if (hp->h_opts != NULL && hp->h_opts->copts != NULL) {
		sbdp_set_err(sep, ESBD_INVAL_OPT, hp->h_opts->copts);
		return (-1);
	}

	/*
	 * Currently, we pass the info in the extra data fields.
	 * This may change in the SC.  We need to change it then
	 */
	sbdp_init_msg_pkt(reqp, DR_MBOX_CLAIM, 0, (caddr_t)NULL);
	reqp->msg_data[0] = node;
	reqp->msg_data[1] = board;

	sbdp_init_msg_pkt(resp, DR_MBOX_CLAIM, 0, (caddr_t)NULL);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to claim board: rv = %d\n", rv);
		sbdp_set_err(sep, sbdp_sc_err_translation(resp->msg_status),
		    NULL);
		return (rv);
	}

	rv = prom_tree_update(sg_attach_board, hp);
	if (rv != 0) {
		SBDP_DBG_MISC("failed to prom attach board: rv = %d\n", rv);
		sbdp_set_err(sep, ESGT_PROM_ATTACH, NULL);
		/*
		 * Clean up
		 */
		sbdp_init_msg_pkt(reqp, DR_MBOX_UNCLAIM, 0, (caddr_t)NULL);
		reqp->msg_data[0] = node;
		reqp->msg_data[1] = board;

		sbdp_init_msg_pkt(resp, DR_MBOX_UNCLAIM, 0, (caddr_t)NULL);

		(void) sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

		return (rv);
	}

	SBDP_DBG_MISC("prom attach worked\n");
	sbdp_attach_bd(node, board);

	/*
	 * XXX Until the Solaris large pages support heterogeneous cpu
	 * domains, DR needs to prevent the addition of non-Panther cpus
	 * to an all-Panther domain with large pages enabled.
	 */
	panther_pages_enabled = (page_num_pagesizes() > DEFAULT_MMU_PAGE_SIZES);
	if (sbdp_board_non_panther_cpus(node, board) > 0 &&
	    panther_pages_enabled && sbdp_large_page_restriction) {
		cmn_err(CE_WARN, "Domain shutdown is required to add a non-"
		    "UltraSPARC-IV+ board into an all UltraSPARC-IV+ domain");
		(void) sbdp_disconnect_board(hp);
		sbdp_set_err(sep, ESGT_NOT_SUPP, NULL);
		return (-1);
	}

	/*
	 * Now that the board has been successfully attached, obtain
	 * platform-specific DIMM serial id information for the board.
	 */
	if (SG_BOARD_IS_CPU_TYPE(board) &&
	    plat_ecc_capability_sc_get(PLAT_ECC_DIMM_SID_MESSAGE)) {
		(void) plat_request_mem_sids(board);
	}

	return (rv);
}

/*
 * Entry point from sbd.  Undo the connect call. We first need to remove
 * the "dummy (i.e unusable)" nodes from solaris.  We then call down to OBP
 * to prune its tree.  After all has been cleaned up from OBP and Solaris
 * We call the SC to "detach/unclain" the board. A side effect is that the
 * SC will clear the pda entries for this board
 */
int
sbdp_disconnect_board(sbdp_handle_t *hp)
{
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		rv = 0;
	int		board, node;
	sbd_error_t	*sep;
	static fn_t	f = "sbdp_disconnect_board";

	SBDP_DBG_FUNC("%s\n", f);

	board = hp->h_board;
	node = hp->h_wnode;
	sep = hp->h_err;

	SBDP_DBG_MISC("sbdp_disconnect_board: board = %d node = %d\n",
	    board, node);

	/*
	 * Check for options.  If there are any, fail the operation
	 */
	if (hp->h_opts != NULL && hp->h_opts->copts != NULL) {
		sbdp_set_err(sep, ESBD_INVAL_OPT, hp->h_opts->copts);
		return (-1);
	}

	if (sbdp_detach_bd(node, board, sep)) {
		sbdp_attach_bd(node, board);
		SBDP_DBG_ALL("failed to detach board %d\n", board);
		return (-1);
	}

	rv = prom_tree_update(sg_detach_board, hp);
	if (rv == -1) {
		/*
		 * Clean up
		 */
		sbdp_attach_bd(node, board);
		SBDP_DBG_MISC("failed to prom detach board: rv = %d\n", rv);
		sbdp_set_err(sep, ESGT_PROM_DETACH, NULL);
		return (rv);
	}

	SBDP_DBG_MISC("prom detach worked\n");
	/*
	 * Currently, we pass the info in the extra data fields.
	 * This may change in the SC.  We need to change it then
	 */
	sbdp_init_msg_pkt(reqp, DR_MBOX_UNCLAIM, 0, (caddr_t)NULL);
	reqp->msg_data[0] = node;
	reqp->msg_data[1] = board;

	sbdp_init_msg_pkt(resp, DR_MBOX_UNCLAIM, 0, (caddr_t)NULL);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to unclaim board: rv = %d\n", rv);
		sbdp_set_err(sep, sbdp_sc_err_translation(resp->msg_status),
		    NULL);
		/* bring back the obp tree to what it was */
		(void) prom_tree_update(sg_attach_board, hp);
	}

	/*
	 * Now that the board has been successfully detached, discard
	 * platform-specific DIMM serial id information for the board.
	 */
	if (!rv && SG_BOARD_IS_CPU_TYPE(board) &&
	    plat_ecc_capability_sc_get(PLAT_ECC_DIMM_SID_MESSAGE)) {
		(void) plat_discard_mem_sids(board);
	}

	return (rv);
}

/*
 * Entry point from sbd.  Very simple.  Just ask the SC to poweoff the board
 * Return the status from the SC
 */
int
sbdp_poweroff_board(sbdp_handle_t *hp)
{
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		cmd_rev = -1;
	info2_t		inform, *informp;
	int		rv = 0;
	sbd_error_t	*sep;
	int		len;
	static fn_t	f = "sbdp_poweroff_board";

	SBDP_DBG_FUNC("%s\n", f);

	sep = hp->h_err;
	/*
	 * Check for options.  If there are any, fail the operation
	 */
	if (hp->h_opts != NULL && hp->h_opts->copts != NULL) {
		sbdp_set_err(sep, ESBD_INVAL_OPT, hp->h_opts->copts);
		return (-1);
	}

	/*
	 * Can't check for bad options here since we use this for workaround
	 * on poweron.
	 */

	informp = &inform;
	informp->board = hp->h_board;
	informp->node = hp->h_wnode;
	informp->extra = SBDP_POWER_OFF;

	len = sizeof (info2_t);
	sbdp_init_msg_pkt(reqp, DR_MBOX_POWER, len, (caddr_t)informp);

	len = sizeof (cmd_rev);
	sbdp_init_msg_pkt(resp, DR_MBOX_POWER, len, (caddr_t)&cmd_rev);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to poweroff board: rv = %d\n", rv);
		sbdp_set_err(sep, sbdp_sc_err_translation(resp->msg_status),
		    NULL);
	}

	return (rv);
}

/*
 * Entry point from sbd.  Ask the SC to poweron the board
 * Return the status from the SC
 */
int
sbdp_poweron_board(sbdp_handle_t *hp)
{
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		cmd_rev = -1;
	info2_t		inform, *informp;
	int		rv = 0;
	sbd_error_t	*sep;
	int		len;
	int		board = hp->h_board;
	static fn_t	f = "sbdp_poweron_board";

	SBDP_DBG_FUNC("%s\n", f);

	sep = hp->h_err;
	/*
	 * Check for options.  If there are any, fail the operation
	 */
	if (hp->h_opts != NULL && hp->h_opts->copts != NULL) {
		sbdp_set_err(sep, ESBD_INVAL_OPT, hp->h_opts->copts);
		return (-1);
	}

	if (sbdp_poweroff_wkaround)
		if (SG_BOARD_IS_CPU_TYPE(board)) {

			if ((rv = sbdp_poweroff_board(hp)) != 0)
				return (rv);
		}

	informp = &inform;
	informp->board = hp->h_board;
	informp->node = hp->h_wnode;
	informp->extra = SBDP_POWER_ON;

	len = sizeof (info2_t);
	sbdp_init_msg_pkt(reqp, DR_MBOX_POWER, len, (caddr_t)informp);

	len = sizeof (cmd_rev);
	sbdp_init_msg_pkt(resp, DR_MBOX_POWER, len, (caddr_t)&cmd_rev);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to poweron board: rv = %d\n", rv);
		sbdp_set_err(sep, sbdp_sc_err_translation(resp->msg_status),
		    NULL);
	}

	return (rv);
}

int
sbdp_get_diag(sbdp_opts_t *opts)
{
	char		*cptr;
	static fn_t	f = "sbdp_get_diag";

	SBDP_DBG_FUNC("%s\n", f);

	if ((opts == NULL) || (opts->copts == NULL))
		return (SBDP_DIAG_NVCI);

	if ((cptr = strstr(opts->copts, "diag=")) != NULL) {
		/*
		 * We have args and need to process them
		 */
		cptr += strlen("diag=");

		if (strncmp(cptr, "off", sizeof ("off")) == 0) {
			return (SBDP_DIAG_OFF);
		} else if (strncmp(cptr, "init", sizeof ("init")) == 0) {
			return (SBDP_DIAG_INIT);
		} else if (strncmp(cptr, "quick", sizeof ("quick")) == 0) {
			return (SBDP_DIAG_QUICK);
		} else if (strncmp(cptr, "min", sizeof ("min")) == 0) {
			return (SBDP_DIAG_MIN);
		} else if (strncmp(cptr, "default", sizeof ("default")) == 0 ||
			strncmp(cptr, "max", sizeof ("max")) == 0) {
			return (SBDP_DIAG_DEFAULT);
		} else if (strncmp(cptr, "mem1", sizeof ("mem1")) == 0) {
			return (SBDP_DIAG_MEM1);
		} else if (strncmp(cptr, "mem2", sizeof ("mem2")) == 0) {
			return (SBDP_DIAG_MEM2);
		}
	}
	SBDP_DBG_MISC("error: unrecognized arg\n");
	return (-1);
}


/*
 * Entry point from sbd.  Ask the SC to test the board.  We still need to
 * worry about the diag level.  The user may have changed it
 *
 * NOTE: The flag field has 2 different meanings whether we are dealing
 * with a cpu/mem board or an io board.  In the case of a cpu/mem board it
 * means retest the board to the diag level specified. In the case of an IO
 * board, it means: Perform the necessary steps to prepare the board
 * for the claim without running POST at the diag level specified.
 */
int
sbdp_test_board(sbdp_handle_t *hp, sbdp_opts_t *opts)
{
	int		board = hp->h_board;
	int		node = hp->h_wnode;
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		cmd_rev = -1;
	testb_t		inform, *informp = &inform;
	int		rv = 0;
	sbd_error_t	*sep;
	int		diag;
	int		len;
	static fn_t	f = "sbdp_test_board";

	SBDP_DBG_FUNC("%s\n", f);

	sep = hp->h_err;

	diag = sbdp_get_diag(opts);

	if (diag == -1) {
		sbdp_set_err(sep, ESBD_INVAL_OPT, opts != NULL ?
		    opts->copts : NULL);
		return (-1);
	}

	SBDP_DBG_MISC("Diag level is 0x%x\n", diag);

	informp->info.board = board;
	informp->info.node = node;

	informp->info.extra = diag;

	/*
	 * Only force retest on CPU boards
	 */
	if (SG_BOARD_IS_CPU_TYPE(board))
		informp->flag = 1;
	else {
		/*
		 * For CPULESS IO pass the force to the SC
		 */
		if (hp->h_flags & SBDP_IOCTL_FLAG_FORCE)
			informp->flag = 1;
		else
			informp->flag = 0;

	}

	len = sizeof (testb_t);
	sbdp_init_msg_pkt(reqp, DR_MBOX_TEST_BD, len, (caddr_t)informp);


	len = sizeof (cmd_rev);
	sbdp_init_msg_pkt(resp, DR_MBOX_TEST_BD, len, (caddr_t)&cmd_rev);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to test board: rv = %d status = %d\n",
		    rv, resp->msg_status);
		rv = resp->msg_status;
		sbdp_set_err(sep, sbdp_sc_err_translation(resp->msg_status),
		    NULL);
	}

	return (rv);
}

/*
 * Request the SC to update POST's memory slice table by swapping
 * the entries for the two board numbers given
 * This is used when performing a copy-rename operation.
 */
int
sbdp_swap_slices(int bd1, int bd2)
{
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		cmd_rev = -1;
	swap_slices_t	inform, *informp = &inform;
	int		rv;
	int		len;
	static fn_t	f = "sbdp_swap_slices";

	SBDP_DBG_FUNC("%s\n", f);

	informp->board1 = bd1;
	informp->board2 = bd2;

	len = sizeof (swap_slices_t);
	sbdp_init_msg_pkt(reqp, DR_MBOX_SWAP_SLICES, len, (caddr_t)informp);

	len = sizeof (cmd_rev);
	sbdp_init_msg_pkt(resp, DR_MBOX_SWAP_SLICES, len, (caddr_t)&cmd_rev);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to swap slices %d<->%d: rv = %d "
		    "status = %d\n", bd1, bd2, rv, resp->msg_status);
		rv = sbdp_sc_err_translation(resp->msg_status);
	}

	return (rv);
}

int
sbdp_sc_err_translation(int error)
{
	int err;
	static fn_t	f = "sbdp_sc_err_translation";

	SBDP_DBG_FUNC("%s\n", f);

	switch (error) {
	case SG_MBOX_STATUS_HARDWARE_FAILURE:
		err = ESGT_HW_FAIL;
		break;
	case SG_MBOX_STATUS_ILLEGAL_PARAMETER:
	case SG_MBOX_STATUS_ILLEGAL_NODE:
	case SG_MBOX_STATUS_ILLEGAL_SLOT:
		err = ESGT_INVAL;
		break;
	case SG_MBOX_STATUS_BOARD_ACCESS_DENIED:
		err = ESGT_BD_ACCESS;
		break;
	case SG_MBOX_STATUS_STALE_CONTENTS:
		err = ESGT_STALE_CMP;
		break;
	case SG_MBOX_STATUS_STALE_OBJECT:
		err = ESGT_STALE_OBJ;
		break;
	case SG_MBOX_STATUS_NO_SEPROM_SPACE:
		err = ESGT_NO_SEPROM_SPACE;
		break;
	case SG_MBOX_STATUS_NO_MEMORY:
		err = ESGT_NO_MEM;
		break;
	case SG_MBOX_STATUS_NOT_SUPPORTED:
		err = ESGT_NOT_SUPP;
		break;
	case SG_MBOX_STATUS_COMMAND_FAILURE:
	default:
		err = ESGT_INTERNAL;
		break;
	}

	return (err);
}

int
sbdp_stop_cpu(processorid_t cpu)
{
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		rv = 0;
	int		len;
	static fn_t	f = "sbdp_stop_cpu";

	SBDP_DBG_FUNC("%s\n", f);

	len = sizeof (processorid_t);
	sbdp_init_msg_pkt(reqp, DR_MBOX_STOP_CPU, len, (caddr_t)&cpu);

	sbdp_init_msg_pkt(resp, DR_MBOX_STOP_CPU, 0, (caddr_t)NULL);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to stop cpu: rv = %d\n", rv);
	}

	return (rv);
}

int
sbdp_start_cpu(processorid_t cpu)
{
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		rv = 0;
	int		len;
	static fn_t	f = "sbdp_start_cpu";

	SBDP_DBG_FUNC("%s\n", f);

	len = sizeof (cpu);
	sbdp_init_msg_pkt(reqp, DR_MBOX_START_CPU, len, (caddr_t)&cpu);

	sbdp_init_msg_pkt(resp, DR_MBOX_START_CPU, 0, (caddr_t)NULL);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to start cpu: rv = %d\n", rv);
	}

	return (rv);
}

/*
 * With the SIR implementation for CPU unconfigure, this mailbox
 * call is obsolete.
 */
int
sbdp_start_cpu_pairs(processorid_t cpu)
{
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;
	int		rv = 0;
	int		len;
	static fn_t	f = "sbdp_start_cpu_pairs";

	SBDP_DBG_FUNC("%s\n", f);

	len = sizeof (cpu);
	sbdp_init_msg_pkt(reqp, DR_MBOX_START_CPU_PAIRS, len, (caddr_t)&cpu);

	sbdp_init_msg_pkt(resp, DR_MBOX_START_CPU_PAIRS, 0, (caddr_t)NULL);

	rv = sbbc_mbox_request_response(reqp, resp, sbdp_mbox_wait);

	if (rv != 0 || (rv = resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		SBDP_DBG_MISC("failed to start cpu pair: rv = %d\n", rv);
	}

	return (rv);
}
