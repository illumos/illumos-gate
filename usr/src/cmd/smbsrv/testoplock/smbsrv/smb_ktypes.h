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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Structures and type definitions needed by the "testoplock" program
 * (a small subset of what the SMB server uses)
 */

#ifndef _SMB_KTYPES_H
#define	_SMB_KTYPES_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/list.h>
#include <sys/sdt.h>

typedef struct smb_session smb_session_t;
typedef struct smb_user smb_user_t;
typedef struct smb_tree smb_tree_t;


/*
 * Destructor object used in the locked-list delete queue.
 */
#define	SMB_DTOR_MAGIC		0x44544F52	/* DTOR */
#define	SMB_DTOR_VALID(d)	\
    ASSERT(((d) != NULL) && ((d)->dt_magic == SMB_DTOR_MAGIC))

typedef void (*smb_dtorproc_t)(void *);

typedef struct smb_dtor {
	list_node_t	dt_lnd;
	uint32_t	dt_magic;
	void		*dt_object;
	smb_dtorproc_t	dt_proc;
} smb_dtor_t;

typedef struct smb_llist {
	krwlock_t	ll_lock;
	list_t		ll_list;
	uint32_t	ll_count;
	uint64_t	ll_wrop;
	kmutex_t	ll_mutex;
	list_t		ll_deleteq;
	uint32_t	ll_deleteq_count;
	boolean_t	ll_flushing;
} smb_llist_t;

/*
 * Per smb_node oplock state
 */
typedef struct smb_oplock {
	kmutex_t		ol_mutex;
	boolean_t		ol_fem;		/* fem monitor installed? */
	struct smb_ofile	*excl_open;
	uint32_t		ol_state;
	int32_t			cnt_II;
	int32_t			cnt_R;
	int32_t			cnt_RH;
	int32_t			cnt_RHBQ;
	int32_t			waiters;
	kcondvar_t		WaitingOpenCV;
} smb_oplock_t;

/*
 * Per smb_ofile oplock state
 */
typedef struct smb_oplock_grant {
	/* smb protocol-level state */
	uint32_t		og_state;	/* latest sent to client */
	uint32_t		og_breaking;	/* BREAK_TO... flags */
	uint16_t		og_dialect;	/* how to send breaks */
	/* File-system level state */
	uint8_t			onlist_II;
	uint8_t			onlist_R;
	uint8_t			onlist_RH;
	uint8_t			onlist_RHBQ;
	uint8_t			BreakingToRead;
} smb_oplock_grant_t;

#define	SMB_LEASE_KEY_SZ	16

#define	SMB_NODE_MAGIC		0x4E4F4445	/* 'NODE' */
#define	SMB_NODE_VALID(p)	ASSERT((p)->n_magic == SMB_NODE_MAGIC)

typedef enum {
	SMB_NODE_STATE_AVAILABLE = 0,
	SMB_NODE_STATE_DESTROYING
} smb_node_state_t;

/*
 * waiting_event        # of clients requesting FCN
 * n_timestamps         cached timestamps
 * n_allocsz            cached file allocation size
 * n_dnode              directory node
 * n_unode              unnamed stream node
 * delete_on_close_cred credentials for delayed delete
 */
typedef struct smb_node {
	list_node_t		n_lnd;
	uint32_t		n_magic;
	krwlock_t		n_lock;
	kmutex_t		n_mutex;
	smb_node_state_t	n_state;
	uint32_t		n_refcnt;
	uint32_t		n_open_count;
	volatile int		flags;

	smb_llist_t		n_ofile_list;
	smb_oplock_t		n_oplock;
} smb_node_t;

#define	NODE_FLAGS_WRITE_THROUGH	0x00100000
#define	NODE_FLAGS_DELETE_COMMITTED	0x20000000
#define	NODE_FLAGS_DELETE_ON_CLOSE	0x40000000

/*
 * Some flags for ofile structure
 *
 *	SMB_OFLAGS_SET_DELETE_ON_CLOSE
 *   Set this flag when the corresponding open operation whose
 *   DELETE_ON_CLOSE bit of the CreateOptions is set. If any
 *   open file instance has this bit set, the NODE_FLAGS_DELETE_ON_CLOSE
 *   will be set for the file node upon close.
 */

/*	SMB_OFLAGS_READONLY		0x0001 (obsolete) */
#define	SMB_OFLAGS_EXECONLY		0x0002
#define	SMB_OFLAGS_SET_DELETE_ON_CLOSE	0x0004
#define	SMB_OFLAGS_LLF_POS_VALID	0x0008

#define	SMB_OFILE_MAGIC		0x4F464C45	/* 'OFLE' */
#define	SMB_OFILE_VALID(p)	\
    ASSERT((p != NULL) && ((p)->f_magic == SMB_OFILE_MAGIC))

/*
 * This is the size of the per-handle "Lock Sequence" array.
 * See LockSequenceIndex in [MS-SMB2] 2.2.26, and smb2_lock.c
 */
#define	SMB_OFILE_LSEQ_MAX		64

/* {arg_open,ofile}->dh_vers values */
typedef enum {
	SMB2_NOT_DURABLE = 0,
	SMB2_DURABLE_V1,
	SMB2_DURABLE_V2,
	SMB2_RESILIENT,
} smb_dh_vers_t;

/*
 * See the long "Ofile State Machine" comment in smb_ofile.c
 */
typedef enum {
	SMB_OFILE_STATE_ALLOC = 0,
	SMB_OFILE_STATE_OPEN,
	SMB_OFILE_STATE_SAVE_DH,
	SMB_OFILE_STATE_SAVING,
	SMB_OFILE_STATE_CLOSING,
	SMB_OFILE_STATE_CLOSED,
	SMB_OFILE_STATE_ORPHANED,
	SMB_OFILE_STATE_RECONNECT,
	SMB_OFILE_STATE_EXPIRED,
	SMB_OFILE_STATE_SENTINEL
} smb_ofile_state_t;

typedef struct smb_ofile {
	list_node_t		f_tree_lnd;	/* t_ofile_list */
	list_node_t		f_node_lnd;	/* n_ofile_list */
	list_node_t		f_dh_lnd;	/* sv_persistid_ht */
	uint32_t		f_magic;
	kmutex_t		f_mutex;
	smb_ofile_state_t	f_state;

	uint16_t		f_fid;
	uint16_t		f_ftype;
	uint32_t		f_refcnt;
	uint32_t		f_granted_access;
	uint32_t		f_share_access;

	smb_node_t		*f_node;

	smb_oplock_grant_t	f_oplock;
	uint8_t			TargetOplockKey[SMB_LEASE_KEY_SZ];
	uint8_t			ParentOplockKey[SMB_LEASE_KEY_SZ];
	struct smb_lease	*f_lease;

} smb_ofile_t;

typedef struct smb_request {
	list_node_t		sr_session_lnd;
	uint32_t		sr_magic;
	kmutex_t		sr_mutex;
} smb_request_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SMB_KTYPES_H */
