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

#ifndef __MMS_MGMT_H
#define	__MMS_MGMT_H


#ifdef	__cplusplus
extern "C" {
#endif

typedef enum mms_cmd_name mms_cmd_name_t;
enum mms_cmd_name {
	MMS_CMD_OTHER = 0,
	MMS_CMD_BEGIN = 1,
	MMS_CMD_END = 2
};

void mms_acc_insert(mms_session_t *, mms_rsp_ele_t *);
void mms_acc_wakeup(mms_session_t *);
void mms_be_wait(mms_session_t *, boolean_t);
void mms_be_wakeup(mms_session_t *);
void mms_cmd_create(mms_session_t *, char *, char *, int,
    void (*callbk)(void *arg, void *arg1), void *);
void mms_cmd_free(mms_cmd_ele_t *);
void mms_cmd_flush(mms_session_t *, char *);
void mms_cmd_insert(mms_session_t *, mms_cmd_ele_t *);
void mms_ev_insert(mms_session_t *, mms_rsp_ele_t *);
void mms_rsp_insert(mms_session_t *, mms_rsp_ele_t *);
void mms_rsp_wakeup(mms_session_t *);
void mms_start_notify(mms_session_t *);
void mms_thread_exit(mms_session_t *);
void mms_thread_start(mms_session_t *);

char *mms_cmd_get_task(mms_par_node_t *);

int  mms_cmd_extract(char *, char **, mms_cmd_name_t *);
int  mms_obtain_accept(mms_session_t *, char *, mms_rsp_ele_t **);
int  mms_obtain_final(mms_session_t *, char *, mms_rsp_ele_t **);
int  mms_send(mms_session_t *, char *, mms_cmd_name_t, char *,
    mms_rsp_ele_t **);
int  mms_sync_reader(mms_session_t *, int, char *, mms_rsp_ele_t **);

mms_cmd_name_t  mms_be_extract(mms_session_t *, char *);
mms_cmd_ele_t *mms_cmd_remove(mms_session_t *, char *);
mms_rsp_ele_t *mms_rsp_create(char *, mms_par_node_t *, int, char *);
mms_rsp_ele_t *mms_rsp_find(mms_session_t *, char *);

#ifdef	__cplusplus
}
#endif


#endif /* __MMS_MGMT_H */
