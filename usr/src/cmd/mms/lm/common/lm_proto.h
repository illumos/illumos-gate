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

#ifndef __LM_PROTO_H
#define	__LM_PROTO_H


#ifdef	__cplusplus
extern "C" {
#endif

int lm_queue_init(lm_queue_t *, int, void (*)());
int lm_queue_add(lm_queue_t *, void *, char **, int);
void lm_queue_clean();

void lm_remove_lmpl_cmd(int, lmpl_rsp_ele_t *);
int lm_obtain_task_id(int *, lmpl_rsp_ele_t **);
int lm_gen_lmpl_cmd(char *, lmpl_rsp_ele_t *, int);
int lm_handle_event(mms_par_node_t *);
int lm_handle_response(mms_par_node_t *);
int lm_handle_parser_error(mms_par_node_t *, mms_list_t *);
int lm_write_msg(char *, mms_t *, pthread_mutex_t);
void lm_connect_failure(mms_t *);

int lm_common_ready(int, char *, char *);
int lm_common_activate(mms_par_node_t *, char *, char *);
int lm_common_private(mms_par_node_t *, char *, char *);
int lm_common_event(mms_par_node_t *, char *, char *);
int lm_common_internal(mms_par_node_t *, char *, char *);
int lm_common_exit(mms_par_node_t *, char *, char *);
int lm_common_reset(mms_par_node_t *, char *, char *);
extern void lm_message(char *, char *, char *);

lm_cmdHandle_t lm_load_cmds(char *, int, lm_cmdData_t *);
void lm_unload_cmds(lm_cmdHandle_t);
void lm_serr(mms_trace_sev_t, char *, int, char *, ...);
void lm_log(int, char *, ...);
void handle_lmpl_cmd_error(int, char *, char *, char *, char *);
void lm_send_cancel(int);

#ifdef	__cplusplus
}
#endif

#endif /* __LM_PROTO_H */
