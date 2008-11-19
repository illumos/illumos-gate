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

#ifndef	__DM_MSG_H
#define	__DM_MSG_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <mms_sym.h>
#include <mms_list.h>
#include <mms_dm_msg.h>

extern	mms_list_t	dm_msg_hdr_list;

#define	DM_MSG_DM	"dm"
#define	DM_MSG_ERROR	"error"

/*
 * There is a dm_msghdr_t for every pthread.
 */
typedef	struct	dm_msg_hdr {
	mms_list_node_t	msg_next;
	mms_list_t	msg_msglist;
	pthread_t	msg_tid;		/* pthread id */
}	dm_msg_hdr_t;

typedef	struct	dm_msg {
	mms_list_node_t	msg_next;
	char		*msg_text;		/* could be NULL */
	int		msg_class;		/* error class */
	int		msg_code;		/* error code */
}	dm_msg_t;

#define	DM_MSG_ADD(x)		TRACE((MMS_ERR, dm_msg_add x))
#define	DM_MSG_ADD_HEAD(x)	TRACE((MMS_ERR, dm_msg_add_head x))
#define	DM_MSG_PREPEND(x)	TRACE((MMS_ERR, dm_msg_prepend x))
#define	DM_ADM_ERR		"administrator", "error"
#define	DM_MSG_SEND(x)		dm_send_message x
#define	DM_MSG_REASON		"dm", DMNAME, "error", dm_msg_text(), NULL

#ifdef	__cplusplus
}
#endif

#endif	/* __DM_MSG_H */
