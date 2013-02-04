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

#ifndef	_MDB_FRAME_H
#define	_MDB_FRAME_H

#include <mdb/mdb_module.h>
#include <mdb/mdb_addrvec.h>
#include <mdb/mdb_list.h>
#include <mdb/mdb_umem.h>
#include <mdb/mdb_vcb.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb_wcb.h>
#include <mdb/mdb.h>
#include <setjmp.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mdb_cmd {
	mdb_list_t c_list;		/* List forward/back pointers */
	mdb_idcmd_t *c_dcmd;		/* Dcmd to invoke */
	mdb_argvec_t c_argv;		/* Arguments for this command */
	mdb_addrvec_t c_addrv;		/* Addresses for this command */
	mdb_vcb_t *c_vcbs;		/* Variable control block list */
} mdb_cmd_t;

typedef struct mdb_frame {
	mdb_list_t f_list;		/* Frame stack forward/back pointers */
	mdb_list_t f_cmds;		/* List of commands to execute */
	mdb_wcb_t *f_wcbs;		/* Walk control blocks for GC */
	mdb_mblk_t *f_mblks;		/* Memory blocks for GC */
	mdb_cmd_t *f_pcmd;		/* Next cmd in pipe (if pipe active) */
	mdb_cmd_t *f_cp;		/* Pointer to executing command */
	mdb_iob_stack_t f_istk;		/* Stack of input i/o buffers */
	mdb_iob_stack_t f_ostk;		/* Stack of output i/o buffers */
	jmp_buf f_pcb;			/* Control block for longjmp */
	uint_t f_flags;			/* Volatile flags to save/restore */
	uint_t f_id;			/* ID for debugging purposes */
	mdb_argvec_t f_argvec;		/* Command arguments */
	int f_oldstate;			/* Last lex state */
	struct mdb_lex_state *f_lstate;	/* Current lex state */
	uintmax_t f_dot;		/* Value of '.' */
	mdb_bool_t pipe;		/* frame has pipe context */
	uint_t f_cbactive;		/* true iff a callback is active */
} mdb_frame_t;

#ifdef _MDB

extern mdb_cmd_t *mdb_cmd_create(mdb_idcmd_t *, mdb_argvec_t *);
extern void mdb_cmd_destroy(mdb_cmd_t *);
extern void mdb_cmd_reset(mdb_cmd_t *);

extern void mdb_frame_reset(mdb_frame_t *);
extern void mdb_frame_push(mdb_frame_t *);
extern void mdb_frame_pop(mdb_frame_t *, int);

extern void mdb_frame_switch(mdb_frame_t *);

extern void mdb_frame_set_pipe(mdb_frame_t *);
extern void mdb_frame_clear_pipe(mdb_frame_t *);
extern mdb_frame_t *mdb_frame_pipe(void);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_FRAME_H */
