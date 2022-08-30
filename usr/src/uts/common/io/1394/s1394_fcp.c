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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * s1394_fcp.c
 *    1394 Services Layer FCP Support Routines
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/types.h>
#include <sys/kmem.h>

#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>

static int s1394_fcp_register_common(s1394_target_t *target,
    t1394_fcp_evts_t *evts, s1394_fa_type_t type, s1394_fa_descr_t *descr);
static int s1394_fcp_unregister_common(s1394_target_t *target,
    s1394_fa_type_t type);
static void s1394_fcp_resp_recv_write_request(cmd1394_cmd_t *req);
static void s1394_fcp_cmd_recv_write_request(cmd1394_cmd_t *req);
static void s1394_fcp_recv_write_request(cmd1394_cmd_t *req,
    s1394_fa_type_t type);
static void s1394_fcp_recv_write_unclaimed(s1394_hal_t *hal,
    cmd1394_cmd_t *req);


/*
 * number of retries to notify registered targets in case target list
 * changes while the list rwlock is dropped for the time of callback
 */
uint_t s1394_fcp_notify_retry_cnt = 3;

s1394_fa_descr_t s1394_fcp_ctl_descr = {
	IEC61883_FCP_RESP_ADDR,
	IEC61883_FCP_RESP_SIZE,
	T1394_ADDR_WRENBL,
	{ NULL, s1394_fcp_resp_recv_write_request, NULL },
	IEC61883_FCP_CMD_ADDR
};

s1394_fa_descr_t s1394_fcp_tgt_descr = {
	IEC61883_FCP_CMD_ADDR,
	IEC61883_FCP_CMD_SIZE,
	T1394_ADDR_WRENBL,
	{ NULL, s1394_fcp_cmd_recv_write_request, NULL },
	IEC61883_FCP_RESP_ADDR
};


int
s1394_fcp_hal_init(s1394_hal_t *hal)
{
	int	ret = DDI_SUCCESS;

	if ((ddi_prop_exists(DDI_DEV_T_ANY, hal->halinfo.dip, DDI_PROP_DONTPASS,
	    "h1394-fcp-claim-on-demand")) == 0) {
		/* if not on-demand, claim addresses now */
		ret = s1394_fa_claim_addr(hal, S1394_FA_TYPE_FCP_CTL,
					&s1394_fcp_ctl_descr);
		if (ret == DDI_SUCCESS) {
			ret = s1394_fa_claim_addr(hal, S1394_FA_TYPE_FCP_TGT,
						&s1394_fcp_tgt_descr);
			if (ret != DDI_SUCCESS) {
				s1394_fa_free_addr(hal, S1394_FA_TYPE_FCP_CTL);
			}
		}
	}

	return (ret);
}

int
s1394_fcp_register_ctl(s1394_target_t *target, t1394_fcp_evts_t *evts)
{
	return (s1394_fcp_register_common(target, evts, S1394_FA_TYPE_FCP_CTL,
			&s1394_fcp_ctl_descr));
}

int
s1394_fcp_register_tgt(s1394_target_t *target, t1394_fcp_evts_t *evts)
{
	return (s1394_fcp_register_common(target, evts, S1394_FA_TYPE_FCP_TGT,
			&s1394_fcp_tgt_descr));
}

int
s1394_fcp_unregister_ctl(s1394_target_t *target)
{
	return (s1394_fcp_unregister_common(target, S1394_FA_TYPE_FCP_CTL));
}

int
s1394_fcp_unregister_tgt(s1394_target_t *target)
{
	return (s1394_fcp_unregister_common(target, S1394_FA_TYPE_FCP_TGT));
}


static int
s1394_fcp_register_common(s1394_target_t *target, t1394_fcp_evts_t *evts,
    s1394_fa_type_t type, s1394_fa_descr_t *descr)
{
	s1394_hal_t	*hal = target->on_hal;
	s1394_fcp_target_t *fcp;

	rw_enter(&hal->target_list_rwlock, RW_WRITER);

	if (s1394_fa_list_is_empty(hal, type)) {
		if (s1394_fa_claim_addr(hal, type, descr) != DDI_SUCCESS) {
			rw_exit(&hal->target_list_rwlock);
			return (DDI_FAILURE);
		}
	}

	/* Add on the target list */
	s1394_fa_list_add(hal, target, type);

	fcp = &target->target_fa[type].fat_u.fcp;
	fcp->fc_evts = *evts;

	rw_exit(&hal->target_list_rwlock);

	return (DDI_SUCCESS);
}

static int
s1394_fcp_unregister_common(s1394_target_t *target, s1394_fa_type_t type)
{
	s1394_hal_t	*hal = target->on_hal;
	int		result;

	rw_enter(&hal->target_list_rwlock, RW_WRITER);

	result = s1394_fa_list_remove(hal, target, type);
	if (result == DDI_SUCCESS) {
		if (s1394_fa_list_is_empty(hal, type)) {
			s1394_fa_free_addr(hal, type);
		}
	}

	rw_exit(&hal->target_list_rwlock);

	return (result);
}

/*
 * s1394_fcp_write_check_cmd()
 *    Check if an FCP command is formed correctly;
 *    set cmd_result and return DDI_FAILURE if not.
 */
int
s1394_fcp_write_check_cmd(cmd1394_cmd_t *cmd)
{
	int	len;

	/* 4-byte writes must be quadlet writes */
	if (cmd->cmd_type == CMD1394_ASYNCH_WR_BLOCK) {
		len = cmd->cmd_u.b.blk_length;
		if (len == 4) {
			cmd->cmd_result = CMD1394_ETYPE_ERROR;
			return (DDI_FAILURE);
		}
	} else {
		len = 4;
	}

	/*
	 * request must be within FCP range. we avoid extra checks by
	 * using the fact that command and response are of the same size
	 */
	if ((cmd->cmd_addr & IEEE1394_ADDR_OFFSET_MASK) + len >
	    IEC61883_FCP_CMD_SIZE) {
		cmd->cmd_result = CMD1394_EADDRESS_ERROR;
		return (DDI_FAILURE);
	}

	/* some options don't make sense for FCP commands */
	if (cmd->cmd_options & CMD1394_OVERRIDE_ADDR) {
		cmd->cmd_result = CMD1394_EINVALID_COMMAND;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
s1394_fcp_resp_recv_write_request(cmd1394_cmd_t *req)
{
	s1394_fcp_recv_write_request(req, S1394_FA_TYPE_FCP_CTL);
}

static void
s1394_fcp_cmd_recv_write_request(cmd1394_cmd_t *req)
{
	s1394_fcp_recv_write_request(req, S1394_FA_TYPE_FCP_TGT);
}

/*
 * s1394_fcp_recv_write_request()
 *    Common write request handler
 */
static void
s1394_fcp_recv_write_request(cmd1394_cmd_t *req, s1394_fa_type_t type)
{
	s1394_hal_t	*hal = (s1394_hal_t *)req->cmd_callback_arg;
	s1394_target_t	*target;
	s1394_fa_target_t *fat;
	uint_t		saved_gen;
	int		num_retries = 0;
	int		(*cb)(cmd1394_cmd_t *req);
	boolean_t	restored = B_FALSE;
	int		ret = T1394_REQ_UNCLAIMED;

	rw_enter(&hal->target_list_rwlock, RW_READER);

start:
	target = hal->hal_fa[type].fal_head;

	if (target) {
		s1394_fa_restore_cmd(hal, req);
		restored = B_TRUE;

		/* Find a target that claims the request */
		do {
			fat = &target->target_fa[type];

			cb = fat->fat_u.fcp.fc_evts.fcp_write_request;
			if (cb == NULL) {
				continue;
			}
			req->cmd_callback_arg = fat->fat_u.fcp.fc_evts.fcp_arg;

			saved_gen = s1394_fa_list_gen(hal, type);

			rw_exit(&hal->target_list_rwlock);
			ret = cb(req);
			rw_enter(&hal->target_list_rwlock, RW_READER);

			if (ret == T1394_REQ_CLAIMED) {
				break;
			}

			/*
			 * List could change while we dropped the lock. In such
			 * case, start all over again, because missing a write
			 * request can have more serious consequences for a
			 * target than receiving same request more than once
			 */
			if (saved_gen != s1394_fa_list_gen(hal, type)) {
				num_retries++;
				if (num_retries <= s1394_fcp_notify_retry_cnt) {
					goto start;
				} else {
					break;
				}
			}

			target = fat->fat_next;
		} while (target != NULL);
	}

	rw_exit(&hal->target_list_rwlock);

	if (ret != T1394_REQ_CLAIMED) {
		if (restored) {
			s1394_fa_convert_cmd(hal, req);
		}
		s1394_fcp_recv_write_unclaimed(hal, req);
	}
}

/*
 * none of the targets claimed the request - send an appropriate response
 */
static void
s1394_fcp_recv_write_unclaimed(s1394_hal_t *hal, cmd1394_cmd_t *req)
{
	req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
	(void) s1394_send_response(hal, req);
}
