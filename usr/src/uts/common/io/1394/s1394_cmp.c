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
 * s1394_cmp.c
 *    1394 Services Layer Connection Management Procedures Support Routines
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

static void s1394_cmp_init(s1394_hal_t *hal);
static void s1394_cmp_fini(s1394_hal_t *hal);
static void s1394_cmp_ompr_recv_read_request(cmd1394_cmd_t *req);
static void s1394_cmp_impr_recv_read_request(cmd1394_cmd_t *req);
static void s1394_cmp_ompr_recv_lock_request(cmd1394_cmd_t *req);
static void s1394_cmp_impr_recv_lock_request(cmd1394_cmd_t *req);
static void s1394_cmp_notify_reg_change(s1394_hal_t *hal, t1394_cmp_reg_t reg,
    s1394_target_t *self);


/*
 * number of retries to notify registered targets in case target list
 * changes while the list rwlock is dropped for the time of callback
 */
uint_t s1394_cmp_notify_retry_cnt = 3;

s1394_fa_descr_t s1394_cmp_ompr_descr = {
	IEC61883_CMP_OMPR_ADDR,
	4,
	T1394_ADDR_RDENBL | T1394_ADDR_LKENBL,
	{
		s1394_cmp_ompr_recv_read_request,
		NULL,
		s1394_cmp_ompr_recv_lock_request
	},
	0
};

s1394_fa_descr_t s1394_cmp_impr_descr = {
	IEC61883_CMP_IMPR_ADDR,
	4,
	T1394_ADDR_RDENBL | T1394_ADDR_LKENBL,
	{
		s1394_cmp_impr_recv_read_request,
		NULL,
		s1394_cmp_impr_recv_lock_request
	},
	0
};


int
s1394_cmp_register(s1394_target_t *target, t1394_cmp_evts_t *evts)
{
	s1394_hal_t	*hal = target->on_hal;
	static t1394_cmp_evts_t default_evts = { NULL, NULL };

	rw_enter(&hal->target_list_rwlock, RW_WRITER);
	/*
	 * if registering the first target, claim and initialize addresses
	 */
	if (s1394_fa_list_is_empty(hal, S1394_FA_TYPE_CMP)) {
		if (s1394_fa_claim_addr(hal, S1394_FA_TYPE_CMP_OMPR,
		    &s1394_cmp_ompr_descr) != DDI_SUCCESS) {
			rw_exit(&hal->target_list_rwlock);
			return (DDI_FAILURE);
		}

		if (s1394_fa_claim_addr(hal, S1394_FA_TYPE_CMP_IMPR,
		    &s1394_cmp_impr_descr) != DDI_SUCCESS) {
			s1394_fa_free_addr(hal, S1394_FA_TYPE_CMP_OMPR);
			rw_exit(&hal->target_list_rwlock);
			return (DDI_FAILURE);
		}

		s1394_cmp_init(hal);
	}

	/* Add on the target list (we only use one list) */
	s1394_fa_list_add(hal, target, S1394_FA_TYPE_CMP);

	if (evts == NULL) {
		evts = &default_evts;
	}
	target->target_fa[S1394_FA_TYPE_CMP].fat_u.cmp.cm_evts = *evts;

	rw_exit(&hal->target_list_rwlock);

	return (DDI_SUCCESS);
}

int
s1394_cmp_unregister(s1394_target_t *target)
{
	s1394_hal_t	*hal = target->on_hal;

	rw_enter(&hal->target_list_rwlock, RW_WRITER);

	if (s1394_fa_list_remove(hal, target,
	    S1394_FA_TYPE_CMP) == DDI_SUCCESS) {
		if (s1394_fa_list_is_empty(hal, S1394_FA_TYPE_CMP)) {
			s1394_fa_free_addr(hal, S1394_FA_TYPE_CMP_OMPR);
			s1394_fa_free_addr(hal, S1394_FA_TYPE_CMP_IMPR);
			s1394_cmp_fini(hal);
		}
	}

	rw_exit(&hal->target_list_rwlock);

	return (DDI_SUCCESS);
}

int
s1394_cmp_read(s1394_target_t *target, t1394_cmp_reg_t reg, uint32_t *valp)
{
	s1394_hal_t	*hal = target->on_hal;
	s1394_cmp_hal_t *cmp = &hal->hal_cmp;
	int		ret = DDI_FAILURE;

	if (reg == T1394_CMP_OMPR) {
		rw_enter(&cmp->cmp_ompr_rwlock, RW_READER);
		*valp = cmp->cmp_ompr_val;
		rw_exit(&cmp->cmp_ompr_rwlock);
		ret = DDI_SUCCESS;
	} else if (reg == T1394_CMP_IMPR) {
		rw_enter(&cmp->cmp_impr_rwlock, RW_READER);
		*valp = cmp->cmp_impr_val;
		rw_exit(&cmp->cmp_impr_rwlock);
		ret = DDI_SUCCESS;
	}

	return (ret);
}

int
s1394_cmp_cas(s1394_target_t *target, t1394_cmp_reg_t reg, uint32_t arg_val,
		uint32_t new_val, uint32_t *old_valp)
{
	s1394_hal_t	*hal = target->on_hal;
	s1394_cmp_hal_t *cmp = &hal->hal_cmp;
	int		ret = DDI_SUCCESS;

	if (reg == T1394_CMP_OMPR) {
		rw_enter(&cmp->cmp_ompr_rwlock, RW_WRITER);
		*old_valp = cmp->cmp_ompr_val;
		if (cmp->cmp_ompr_val == arg_val) {
			cmp->cmp_ompr_val = new_val;
		}
		rw_exit(&cmp->cmp_ompr_rwlock);
	} else if (reg == T1394_CMP_IMPR) {
		rw_enter(&cmp->cmp_impr_rwlock, RW_WRITER);
		*old_valp = cmp->cmp_impr_val;
		if (cmp->cmp_impr_val == arg_val) {
			cmp->cmp_impr_val = new_val;
		}
		rw_exit(&cmp->cmp_impr_rwlock);
	} else {
		ret = DDI_FAILURE;
	}

	/* notify other targets */
	if (ret == DDI_SUCCESS) {
		s1394_cmp_notify_reg_change(hal, reg, target);
	}

	return (ret);
}

static void
s1394_cmp_init(s1394_hal_t *hal)
{
	s1394_cmp_hal_t *cmp = &hal->hal_cmp;

	rw_init(&cmp->cmp_ompr_rwlock, NULL, RW_DRIVER, NULL);
	rw_init(&cmp->cmp_impr_rwlock, NULL, RW_DRIVER, NULL);

	cmp->cmp_ompr_val = IEC61883_CMP_OMPR_INIT_VAL;
	cmp->cmp_impr_val = IEC61883_CMP_IMPR_INIT_VAL;
}

static void
s1394_cmp_fini(s1394_hal_t *hal)
{
	s1394_cmp_hal_t *cmp = &hal->hal_cmp;

	rw_destroy(&cmp->cmp_ompr_rwlock);
	rw_destroy(&cmp->cmp_impr_rwlock);
}

/*
 * iMPR/oMPR read/lock requests
 */
static void
s1394_cmp_ompr_recv_read_request(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal = req->cmd_callback_arg;
	s1394_cmp_hal_t *cmp = &hal->hal_cmp;

	if (req->cmd_type != CMD1394_ASYNCH_RD_QUAD) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	} else {
		rw_enter(&cmp->cmp_ompr_rwlock, RW_READER);
		req->cmd_u.q.quadlet_data = cmp->cmp_ompr_val;
		rw_exit(&cmp->cmp_ompr_rwlock);
		req->cmd_result = IEEE1394_RESP_COMPLETE;
	}

	(void) s1394_send_response(hal, req);
}

static void
s1394_cmp_impr_recv_read_request(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal = req->cmd_callback_arg;
	s1394_cmp_hal_t *cmp = &hal->hal_cmp;

	if (req->cmd_type != CMD1394_ASYNCH_RD_QUAD) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	} else {
		rw_enter(&cmp->cmp_impr_rwlock, RW_READER);
		req->cmd_u.q.quadlet_data = cmp->cmp_impr_val;
		rw_exit(&cmp->cmp_impr_rwlock);
		req->cmd_result = IEEE1394_RESP_COMPLETE;
	}

	(void) s1394_send_response(hal, req);
}

static void
s1394_cmp_ompr_recv_lock_request(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal = req->cmd_callback_arg;
	s1394_cmp_hal_t *cmp = &hal->hal_cmp;
	boolean_t	notify = B_TRUE;

	if ((req->cmd_type != CMD1394_ASYNCH_LOCK_32) ||
	    (req->cmd_u.l32.lock_type != CMD1394_LOCK_COMPARE_SWAP)) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		notify = B_FALSE;
	} else {
		rw_enter(&cmp->cmp_ompr_rwlock, RW_WRITER);
		req->cmd_u.l32.old_value = cmp->cmp_ompr_val;
		if (cmp->cmp_ompr_val == req->cmd_u.l32.arg_value) {
			/* write only allowed bits */
			cmp->cmp_ompr_val = (req->cmd_u.l32.data_value &
			    IEC61883_CMP_OMPR_LOCK_MASK) |
			    (cmp->cmp_ompr_val & ~IEC61883_CMP_OMPR_LOCK_MASK);
		}
		rw_exit(&cmp->cmp_ompr_rwlock);
		req->cmd_result = IEEE1394_RESP_COMPLETE;
	}

	(void) s1394_send_response(hal, req);

	/* notify all targets */
	if (notify) {
		s1394_cmp_notify_reg_change(hal, T1394_CMP_OMPR, NULL);
	}
}

static void
s1394_cmp_impr_recv_lock_request(cmd1394_cmd_t *req)
{
	s1394_hal_t	*hal = req->cmd_callback_arg;
	s1394_cmp_hal_t *cmp = &hal->hal_cmp;
	boolean_t	notify = B_TRUE;

	if ((req->cmd_type != CMD1394_ASYNCH_LOCK_32) ||
	    (req->cmd_u.l32.lock_type != CMD1394_LOCK_COMPARE_SWAP)) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
		notify = B_FALSE;
	} else {
		rw_enter(&cmp->cmp_impr_rwlock, RW_WRITER);
		req->cmd_u.l32.old_value = cmp->cmp_impr_val;
		if (cmp->cmp_impr_val == req->cmd_u.l32.arg_value) {
			/* write only allowed bits */
			cmp->cmp_impr_val = (req->cmd_u.l32.data_value &
			    IEC61883_CMP_IMPR_LOCK_MASK) |
			    (cmp->cmp_impr_val & ~IEC61883_CMP_IMPR_LOCK_MASK);
		}
		rw_exit(&cmp->cmp_impr_rwlock);
		req->cmd_result = IEEE1394_RESP_COMPLETE;
	}

	(void) s1394_send_response(hal, req);

	/* notify all targets */
	if (notify) {
		s1394_cmp_notify_reg_change(hal, T1394_CMP_IMPR, NULL);
	}
}

/*
 * Notify registered targets except 'self' about register value change
 */
static void
s1394_cmp_notify_reg_change(s1394_hal_t *hal, t1394_cmp_reg_t reg,
    s1394_target_t *self)
{
	s1394_target_t	*target;
	s1394_fa_target_t *fat;
	uint_t		saved_gen;
	int		num_retries = 0;
	void		(*cb)(opaque_t, t1394_cmp_reg_t);
	opaque_t	arg;

	rw_enter(&hal->target_list_rwlock, RW_READER);

start:
	target = hal->hal_fa[S1394_FA_TYPE_CMP].fal_head;

	for (; target; target = fat->fat_next) {
		fat = &target->target_fa[S1394_FA_TYPE_CMP];

		/*
		 * even if the target list changes when the lock is dropped,
		 * comparing with self is safe because the target should
		 * not unregister until all CMP operations are completed
		 */
		if (target == self) {
			continue;
		}

		cb = fat->fat_u.cmp.cm_evts.cmp_reg_change;
		if (cb == NULL) {
			continue;
		}
		arg = fat->fat_u.cmp.cm_evts.cmp_arg;

		saved_gen = s1394_fa_list_gen(hal, S1394_FA_TYPE_CMP);

		rw_exit(&hal->target_list_rwlock);
		cb(arg, reg);
		rw_enter(&hal->target_list_rwlock, RW_READER);

		/*
		 * List could change while we dropped the lock. In such
		 * case, start all over again, because missing a register
		 * change can have more serious consequences for a
		 * target than receiving same notification more than once
		 */
		if (saved_gen != s1394_fa_list_gen(hal, S1394_FA_TYPE_CMP)) {
			if (++num_retries <= s1394_cmp_notify_retry_cnt) {
				goto start;
			} else {
				break;
			}
		}
	}

	rw_exit(&hal->target_list_rwlock);
}
