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

#ifndef	_MM_SQL_IMPL_H_
#define	_MM_SQL_IMPL_H_


#ifdef	__cplusplus
extern "C" {
#endif

typedef struct sql_ops_tab sql_ops_tab_t;
struct sql_ops_tab {
	char		*sql_mmp_ops;
	char		*sql_ops;
};

/*
 * Common SQL
 */
int	mm_sql_chk_len(char **line, int off, int *bufsize, int len);
void	mm_sql_db_err_rsp_new(mm_command_t *command, mm_db_t *db);
int	mm_sql_trans_match_new(mm_command_t *command, int *offset);
int	mm_sql_trans_order_new(mm_command_t *cmd, int *offset);
int	mm_sql_trans_number_new(mm_command_t *cmd, int *offset);
int	mm_sql_report_clause_new(mm_command_t *command, char *objname);
int	mm_sql_notify_inst_new(mm_db_t *db, mm_command_t *cmd, char *objname,
		int match_off, char **objinst);
void	mm_sql_order(mm_command_t *cmd);
void	mm_sql_number(mm_command_t *cmd);
int	mm_notify_delete(mm_db_t *db, mm_command_t *cmd, char *objname,
		int match_off);
int	mm_get_dest(mm_wka_t *mm_wka, mm_command_t *cmd);
int	mm_get_const(mm_wka_t *mm_wka, mm_command_t *cmd);
int	mm_add_char(char *str, mms_list_t *list);

#ifdef	__cplusplus
}
#endif

#endif	/* _MM_SQL_IMPL_H_ */
