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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MM_TASK_H
#define	_MM_TASK_H


#ifdef	__cplusplus
extern "C" {
#endif


int		mm_get_tm_cmd(mm_data_t *mm_data);
mm_db_rval_t mm_set_tm_task(mm_db_t *db, mm_command_t *cmd);
mm_db_rval_t mm_new_tm_task(mm_db_t *db, mm_command_t *command, char *state);
mm_db_rval_t mm_set_tm_cartridge(mm_db_t *db, char *taskid, char *cartridge_id);
mm_db_rval_t mm_set_tm_drive(mm_db_t *db, char *taskid, char *drive);
mm_db_rval_t mm_set_tm_library(mm_db_t *db, char *taskid, char *library);
mm_db_rval_t mm_set_tm_cmd_dispatched(mm_db_t *db, char *taskid);
mm_db_rval_t mm_del_tm_cmd(mm_db_t *db, char *taskid);
mm_db_rval_t mm_chg_tm_cmd_priority(mm_db_t *db, char *taskid, int priority);
void tm_be_add_mounts(mm_command_t *cmd);

#ifdef	__cplusplus
}
#endif

#endif	/* _MM_TASK_H */
