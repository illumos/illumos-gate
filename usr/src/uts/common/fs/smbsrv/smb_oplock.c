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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * smb1 oplock support
 */

#include <smbsrv/smb_kproto.h>

#define	BATCH_OR_EXCL	(OPLOCK_LEVEL_BATCH | OPLOCK_LEVEL_ONE)

/*
 * Client has an open handle and requests an oplock.
 * Convert SMB1 oplock request info in to internal form,
 * call common oplock code, convert result to SMB1.
 */
void
smb1_oplock_acquire(smb_request_t *sr, boolean_t level2ok)
{
	smb_arg_open_t *op = &sr->arg.open;
	smb_ofile_t *ofile = sr->fid_ofile;
	uint32_t status;

	/* Only disk trees get oplocks. */
	if ((sr->tid_tree->t_res_type & STYPE_MASK) != STYPE_DISKTREE) {
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	if (!smb_tree_has_feature(sr->tid_tree, SMB_TREE_OPLOCKS)) {
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	if (!smb_session_levelII_oplocks(sr->session))
		level2ok = B_FALSE;

	/* Common code checks file type. */

	/*
	 * SMB1: Convert to internal form.
	 */
	switch (op->op_oplock_level) {
	case SMB_OPLOCK_BATCH:
		op->op_oplock_state = OPLOCK_LEVEL_BATCH;
		break;
	case SMB_OPLOCK_EXCLUSIVE:
		op->op_oplock_state = OPLOCK_LEVEL_ONE;
		break;
	case SMB_OPLOCK_LEVEL_II:
		op->op_oplock_state = OPLOCK_LEVEL_TWO;
		break;
	case SMB_OPLOCK_NONE:
	default:
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	/*
	 * Tree options may force shared oplocks
	 */
	if (smb_tree_has_feature(sr->tid_tree, SMB_TREE_FORCE_L2_OPLOCK)) {
		op->op_oplock_state = OPLOCK_LEVEL_TWO;
	}

	/*
	 * Try exclusive first, if requested
	 */
	if ((op->op_oplock_state & BATCH_OR_EXCL) != 0) {
		status = smb_oplock_request(sr, ofile,
		    &op->op_oplock_state);
	} else {
		status = NT_STATUS_OPLOCK_NOT_GRANTED;
	}

	/*
	 * If exclusive failed (or tree forced shared oplocks)
	 * and if the caller supports Level II, try shared.
	 */
	if (status == NT_STATUS_OPLOCK_NOT_GRANTED && level2ok) {
		op->op_oplock_state = OPLOCK_LEVEL_TWO;
		status = smb_oplock_request(sr, ofile,
		    &op->op_oplock_state);
	}

	/*
	 * Either of the above may have returned the
	 * status code that says we should wait.
	 */
	if (status == NT_STATUS_OPLOCK_BREAK_IN_PROGRESS) {
		(void) smb_oplock_wait_break(ofile->f_node, 0);
		status = 0;
	}

	/*
	 * Keep track of what we got (in ofile->f_oplock.og_state)
	 * so we'll know what we had when sending a break later.
	 * The og_dialect here is the oplock dialect, which may be
	 * different than SMB dialect.  Pre-NT clients did not
	 * support "Level II" oplocks.  If we're talking to a
	 * client that didn't set the CAP_LEVEL_II_OPLOCKS in
	 * its capabilities, let og_dialect = LANMAN2_1.
	 */
	ofile->f_oplock.og_dialect = (level2ok) ?
	    NT_LM_0_12 : LANMAN2_1;
	switch (status) {
	case NT_STATUS_SUCCESS:
		ofile->f_oplock.og_state = op->op_oplock_state;
		break;
	case NT_STATUS_OPLOCK_NOT_GRANTED:
		ofile->f_oplock.og_state = 0;
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	default:
		/* Caller did not check args sufficiently? */
		cmn_err(CE_NOTE, "clnt %s oplock req. err 0x%x",
		    sr->session->ip_addr_str, status);
		ofile->f_oplock.og_state = 0;
		op->op_oplock_level = SMB_OPLOCK_NONE;
		return;
	}

	/*
	 * Have STATUS_SUCCESS
	 * Convert internal oplock state to SMB1
	 */
	if (op->op_oplock_state & OPLOCK_LEVEL_BATCH) {
		op->op_oplock_level = SMB_OPLOCK_BATCH;
	} else if (op->op_oplock_state & OPLOCK_LEVEL_ONE) {
		op->op_oplock_level = SMB_OPLOCK_EXCLUSIVE;
	} else if (op->op_oplock_state & OPLOCK_LEVEL_TWO) {
		op->op_oplock_level = SMB_OPLOCK_LEVEL_II;
	} else {
		op->op_oplock_level = SMB_OPLOCK_NONE;
	}
}
