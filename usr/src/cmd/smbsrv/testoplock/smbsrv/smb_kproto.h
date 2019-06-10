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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Function prototypes needed by the "testoplock" program
 * (a small subset of what the SMB server uses)
 */

#ifndef _SMB_KPROTO_H_
#define	_SMB_KPROTO_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/varargs.h>
#include <sys/cmn_err.h>
#include <smbsrv/smb.h>
#include <smbsrv/smb_ktypes.h>

boolean_t smb_ofile_is_open(smb_ofile_t *);
boolean_t smb_node_is_file(smb_node_t *);

/*
 * SMB locked list function prototypes
 */
void	smb_llist_init(void);
void	smb_llist_fini(void);
void	smb_llist_constructor(smb_llist_t *, size_t, size_t);
void	smb_llist_destructor(smb_llist_t *);
void	smb_llist_enter(smb_llist_t *ll, krw_t);
void	smb_llist_exit(smb_llist_t *);
void	smb_llist_post(smb_llist_t *, void *, smb_dtorproc_t);
void	smb_llist_flush(smb_llist_t *);
void	smb_llist_insert_head(smb_llist_t *ll, void *obj);
void	smb_llist_insert_tail(smb_llist_t *ll, void *obj);
void	smb_llist_remove(smb_llist_t *ll, void *obj);
int	smb_llist_upgrade(smb_llist_t *ll);
uint32_t smb_llist_get_count(smb_llist_t *ll);
#define	smb_llist_head(ll)		list_head(&(ll)->ll_list)
#define	smb_llist_next(ll, obj)		list_next(&(ll)->ll_list, obj)
int	smb_account_connected(smb_user_t *user);

/*
 * Common oplock functions
 */
uint32_t smb_oplock_request(smb_request_t *, smb_ofile_t *, uint32_t *);
uint32_t smb_oplock_ack_break(smb_request_t *, smb_ofile_t *, uint32_t *);
uint32_t smb_oplock_break_PARENT(smb_node_t *, smb_ofile_t *);
uint32_t smb_oplock_break_OPEN(smb_node_t *, smb_ofile_t *,
    uint32_t DesiredAccess, uint32_t CreateDisposition);
uint32_t smb_oplock_break_BATCH(smb_node_t *, smb_ofile_t *,
    uint32_t DesiredAccess, uint32_t CreateDisposition);
uint32_t smb_oplock_break_HANDLE(smb_node_t *, smb_ofile_t *);
void smb_oplock_break_CLOSE(smb_node_t *, smb_ofile_t *);
uint32_t smb_oplock_break_READ(smb_node_t *, smb_ofile_t *);
uint32_t smb_oplock_break_WRITE(smb_node_t *, smb_ofile_t *);
uint32_t smb_oplock_break_SETINFO(smb_node_t *,
    smb_ofile_t *ofile, uint32_t InfoClass);
uint32_t smb_oplock_break_DELETE(smb_node_t *, smb_ofile_t *);

void smb_oplock_move(smb_node_t *, smb_ofile_t *, smb_ofile_t *);

/*
 * Protocol-specific oplock functions
 * (and "server-level" functions)
 */
void smb1_oplock_acquire(smb_request_t *, boolean_t);
void smb1_oplock_break_notification(smb_request_t *, uint32_t);
void smb2_oplock_break_notification(smb_request_t *, uint32_t);
void smb2_lease_break_notification(smb_request_t *, uint32_t, boolean_t);
void smb_oplock_ind_break(smb_ofile_t *, uint32_t, boolean_t, uint32_t);
void smb_oplock_ind_break_in_ack(smb_request_t *, smb_ofile_t *,
    uint32_t, boolean_t);
void smb_oplock_send_brk(smb_request_t *);
uint32_t smb_oplock_wait_break(smb_node_t *, int);

int smb_lock_range_access(smb_request_t *, smb_node_t *,
    uint64_t, uint64_t, boolean_t);


#ifdef	__cplusplus
}
#endif

#endif /* _SMB_KPROTO_H_ */
