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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility routines to manage debugger frames and commands.  A debugger frame
 * is used by each invocation of mdb_run() (the main parsing loop) to manage
 * its state.  Refer to the comments in mdb.c for more information on frames.
 * Each frame has a list of commands (that is, a dcmd, argument list, and
 * optional address list) that represent a pipeline after it has been parsed.
 */

#include <mdb/mdb_debug.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb.h>

mdb_cmd_t *
mdb_cmd_create(mdb_idcmd_t *idcp, mdb_argvec_t *argv)
{
	mdb_cmd_t *cp = mdb_zalloc(sizeof (mdb_cmd_t), UM_NOSLEEP);

	if (cp == NULL) {
		warn("failed to allocate memory for command");
		longjmp(mdb.m_frame->f_pcb, MDB_ERR_NOMEM);
	}

	mdb_list_append(&mdb.m_frame->f_cmds, cp);
	mdb_argvec_copy(&cp->c_argv, argv);
	mdb_argvec_zero(argv);
	cp->c_dcmd = idcp;

	return (cp);
}

void
mdb_cmd_destroy(mdb_cmd_t *cp)
{
	mdb_addrvec_destroy(&cp->c_addrv);
	mdb_argvec_destroy(&cp->c_argv);
	mdb_vcb_purge(cp->c_vcbs);
	mdb_free(cp, sizeof (mdb_cmd_t));
}

void
mdb_cmd_reset(mdb_cmd_t *cp)
{
	mdb_addrvec_destroy(&cp->c_addrv);
	mdb_vcb_purge(cp->c_vcbs);
	cp->c_vcbs = NULL;
}

void
mdb_frame_reset(mdb_frame_t *fp)
{
	mdb_cmd_t *cp;

	while ((cp = mdb_list_next(&fp->f_cmds)) != NULL) {
		mdb_list_delete(&fp->f_cmds, cp);
		mdb_cmd_destroy(cp);
	}
	fp->f_cp = NULL;
	fp->f_pcmd = NULL;

	while (mdb_iob_stack_size(&fp->f_ostk) != 0) {
		mdb_iob_destroy(mdb.m_out);
		mdb.m_out = mdb_iob_stack_pop(&fp->f_ostk);
	}

	mdb_wcb_purge(&fp->f_wcbs);
	mdb_recycle(&fp->f_mblks);
}

void
mdb_frame_push(mdb_frame_t *fp)
{
	mdb_intr_disable();

	if (mdb.m_fmark == NULL)
		mdb.m_fmark = fp;

	mdb_lex_state_save(mdb.m_frame->f_lstate);

	bzero(fp, sizeof (mdb_frame_t));
	mdb_lex_state_create(fp);
	mdb_list_append(&mdb.m_flist, fp);

	fp->f_flags = mdb.m_flags & MDB_FL_VOLATILE;
	fp->f_pcmd = mdb.m_frame->f_pcmd;
	fp->f_id = mdb.m_fid++;
	mdb.m_frame->f_dot = mdb_nv_get_value(mdb.m_dot);

	mdb.m_frame = fp;
	mdb.m_depth++;

	mdb_dprintf(MDB_DBG_DSTK, "push frame <%u> mark=%p in=%s out=%s\n",
	    fp->f_id, (void *)mdb.m_fmark,
	    mdb_iob_name(mdb.m_in), mdb_iob_name(mdb.m_out));

	mdb_intr_enable();
}

void
mdb_frame_pop(mdb_frame_t *fp, int err)
{
	mdb_intr_disable();

	ASSERT(mdb_iob_stack_size(&fp->f_istk) == 0);
	ASSERT(mdb_iob_stack_size(&fp->f_ostk) == 0);
	ASSERT(mdb_list_next(&fp->f_cmds) == NULL);
	ASSERT(fp->f_mblks == NULL);
	ASSERT(fp->f_wcbs == NULL);

	mdb_dprintf(MDB_DBG_DSTK, "pop frame <%u> status=%s\n",
	    fp->f_id, mdb_err2str(err));

	if (mdb.m_frame == fp) {
		mdb.m_flags &= ~MDB_FL_VOLATILE;
		mdb.m_flags |= fp->f_flags;
		mdb_frame_switch(mdb_list_prev(fp));
	}

	if (mdb.m_fmark == fp)
		mdb.m_fmark = NULL;

	mdb_lex_state_destroy(fp);

	mdb_list_delete(&mdb.m_flist, fp);
	ASSERT(mdb.m_depth != 0);
	mdb.m_depth--;

	mdb_intr_enable();
}

void
mdb_frame_switch(mdb_frame_t *frame)
{
	mdb_lex_state_save(mdb.m_frame->f_lstate);
	mdb.m_frame->f_dot = mdb_nv_get_value(mdb.m_dot);
	mdb.m_frame = frame;
	mdb_lex_state_restore(mdb.m_frame->f_lstate);
	mdb_dprintf(MDB_DBG_DSTK, "switch to frame <%u>\n", mdb.m_frame->f_id);

	mdb_nv_set_value(mdb.m_dot, frame->f_dot);
}

void
mdb_frame_set_pipe(mdb_frame_t *frame)
{
	frame->pipe = TRUE;
}

void
mdb_frame_clear_pipe(mdb_frame_t *frame)
{
	frame->pipe = FALSE;
}

mdb_frame_t *
mdb_frame_pipe(void)
{
	mdb_frame_t *frame = mdb_list_prev(mdb.m_frame);

	while (frame && frame->pipe == FALSE)
		frame = mdb_list_prev(frame);

	return (frame);
}
