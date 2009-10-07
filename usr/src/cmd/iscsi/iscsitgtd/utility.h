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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TARGET_UTILITY_H
#define	_TARGET_UTILITY_H

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "iscsi_conn.h"
#include <sys/iscsi_protocol.h>
#include "errcode.h"

#define	SNA32_CHECK 2147483648UL

/*
 * Generates a lot more information on each transfer. Disabling this reduces
 * one possible performance impact in the data path. Event with logging turned
 * off the messages are still queued which requires malloc's and possible lock
 * contention on the management queue. This is a gut feeling, rather than
 * actual tests to confirm.
 */
#undef	FULL_DEBUG

typedef struct thick_provo {
	struct thick_provo	*next,
				*prev;
	char			*targ_name;
	int			lun;
	target_queue_t		*q;
} thick_provo_t;

/*
 * in_mark presents the state in validate_xml()
 * in_lt means it enters a '<' and wants a '>' to return normal
 * in_amp means it meets a '&' and wants a ';' to return normal
 */
typedef enum {
	in_none,
	in_lt,
	in_amp
} in_mark_t;

void util_init();
int read_retry(int fd, char *buf, int count);
Boolean_t parse_text(iscsi_conn_t *c, int dlen, char **text,
    int *text_length, int *errcode);
Boolean_t add_text(char **text, int *current_length, char *name, char *val);
char *task_to_str(int func);
void create_geom(diskaddr_t size, int *cylinders, int *heads, int *spt);
void connection_parameters_default(iscsi_conn_t *c);
int sna_lt(uint32_t n1, uint32_t n2);
int sna_lte(uint32_t n1, uint32_t n2);
void xml_rtn_msg(char **buf, err_code_t code);
Boolean_t add_target_alias(iscsi_conn_t *c, char **text, int *test_length);
Boolean_t validate_version(tgt_node_t *node, int *maj, int *min);
char *create_tpgt_list(char *tname);
Boolean_t check_access(tgt_node_t *targ, char *initiator_name,
    Boolean_t req_chap);
tgt_node_t *find_target_node(char *targ_name);
void util_title(target_queue_t *q, int type, int num, char *title);
Boolean_t util_create_guid(char **guid, uchar_t id_type);
Boolean_t strtoll_multiplier(char *str, uint64_t *sp);
void thick_provo_stop(char *targ, int lun);
void *thick_provo_start(void *v);
Boolean_t thick_provo_chk_thr(char *targ, int lun);
void remove_target_common(char *name, int lun, char **msg);
char *get_local_name(char *iname);
Boolean_t validate_xml(char *req);


#ifdef __cplusplus
}
#endif

#endif /* _TARGET_UTILITY_H */
