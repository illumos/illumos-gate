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
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/thread.h>
#include <sys/taskq_impl.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb.h>
#include <smbsrv/smb_ktypes.h>

#define	SMB_DCMD_INDENT		2
#define	ACE_TYPE_TABLEN		(ACE_ALL_TYPES + 1)
#define	ACE_TYPE_ENTRY(_v_)	{_v_, #_v_}
#define	SMB_COM_ENTRY(_v_, _x_)	{#_v_, _x_}

#define	SMB_MDB_MAX_OPTS	9

#define	SMB_OPT_SERVER		0x00000001
#define	SMB_OPT_SESSION		0x00000002
#define	SMB_OPT_REQUEST		0x00000004
#define	SMB_OPT_USER		0x00000008
#define	SMB_OPT_TREE		0x00000010
#define	SMB_OPT_OFILE		0x00000020
#define	SMB_OPT_ODIR		0x00000040
#define	SMB_OPT_WALK		0x00000100
#define	SMB_OPT_VERBOSE		0x00000200
#define	SMB_OPT_ALL_OBJ		0x000000FF

/*
 * Structure associating an ACE type to a string.
 */
typedef struct {
	uint8_t		ace_type_value;
	const char	*ace_type_sting;
} ace_type_entry_t;

/*
 * Structure containing strings describing an SMB command.
 */
typedef struct {
	const char	*smb_com;
	const char	*smb_andx;
} smb_com_entry_t;

/*
 * Structure describing an object to be expanded (displayed).
 */
typedef struct {
	uint_t		ex_mask;
	size_t		ex_offset;
	const char	*ex_dcmd;
	const char	*ex_name;
} smb_exp_t;

/*
 * List of supported options. Ther order has the match the bits SMB_OPT_xxx.
 */
typedef struct smb_mdb_opts {
	char		*o_name;
	uint32_t	o_value;
} smb_mdb_opts_t;

static smb_mdb_opts_t smb_opts[SMB_MDB_MAX_OPTS] =
{
	{ "-s", SMB_OPT_SERVER	},
	{ "-e", SMB_OPT_SESSION	},
	{ "-r", SMB_OPT_REQUEST	},
	{ "-u", SMB_OPT_USER	},
	{ "-t", SMB_OPT_TREE	},
	{ "-f", SMB_OPT_OFILE	},
	{ "-d", SMB_OPT_ODIR	},
	{ "-w", SMB_OPT_WALK	},
	{ "-v", SMB_OPT_VERBOSE	}
};

static smb_com_entry_t	smb_com[256] =
{
	SMB_COM_ENTRY(SMB_COM_CREATE_DIRECTORY, "No"),
	SMB_COM_ENTRY(SMB_COM_DELETE_DIRECTORY, "No"),
	SMB_COM_ENTRY(SMB_COM_OPEN, "No"),
	SMB_COM_ENTRY(SMB_COM_CREATE, "No"),
	SMB_COM_ENTRY(SMB_COM_CLOSE, "No"),
	SMB_COM_ENTRY(SMB_COM_FLUSH, "No"),
	SMB_COM_ENTRY(SMB_COM_DELETE, "No"),
	SMB_COM_ENTRY(SMB_COM_RENAME, "No"),
	SMB_COM_ENTRY(SMB_COM_QUERY_INFORMATION, "No"),
	SMB_COM_ENTRY(SMB_COM_SET_INFORMATION, "No"),
	SMB_COM_ENTRY(SMB_COM_READ, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE, "No"),
	SMB_COM_ENTRY(SMB_COM_LOCK_BYTE_RANGE, "No"),
	SMB_COM_ENTRY(SMB_COM_UNLOCK_BYTE_RANGE, "No"),
	SMB_COM_ENTRY(SMB_COM_CREATE_TEMPORARY, "No"),
	SMB_COM_ENTRY(SMB_COM_CREATE_NEW, "No"),
	SMB_COM_ENTRY(SMB_COM_CHECK_DIRECTORY, "No"),
	SMB_COM_ENTRY(SMB_COM_PROCESS_EXIT, "No"),
	SMB_COM_ENTRY(SMB_COM_SEEK, "No"),
	SMB_COM_ENTRY(SMB_COM_LOCK_AND_READ, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_AND_UNLOCK, "No"),
	SMB_COM_ENTRY(0x15, "?"),
	SMB_COM_ENTRY(0x16, "?"),
	SMB_COM_ENTRY(0x17, "?"),
	SMB_COM_ENTRY(0x18, "?"),
	SMB_COM_ENTRY(0x19, "?"),
	SMB_COM_ENTRY(SMB_COM_READ_RAW, "No"),
	SMB_COM_ENTRY(SMB_COM_READ_MPX, "No"),
	SMB_COM_ENTRY(SMB_COM_READ_MPX_SECONDARY, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_RAW, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_MPX, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_MPX_SECONDARY, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_COMPLETE, "No"),
	SMB_COM_ENTRY(SMB_COM_QUERY_SERVER, "No"),
	SMB_COM_ENTRY(SMB_COM_SET_INFORMATION2, "No"),
	SMB_COM_ENTRY(SMB_COM_QUERY_INFORMATION2, "No"),
	SMB_COM_ENTRY(SMB_COM_LOCKING_ANDX, "No"),
	SMB_COM_ENTRY(SMB_COM_TRANSACTION, "No"),
	SMB_COM_ENTRY(SMB_COM_TRANSACTION_SECONDARY, "No"),
	SMB_COM_ENTRY(SMB_COM_IOCTL, "No"),
	SMB_COM_ENTRY(SMB_COM_IOCTL_SECONDARY, "No"),
	SMB_COM_ENTRY(SMB_COM_COPY, "No"),
	SMB_COM_ENTRY(SMB_COM_MOVE, "No"),
	SMB_COM_ENTRY(SMB_COM_ECHO, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_AND_CLOSE, "No"),
	SMB_COM_ENTRY(SMB_COM_OPEN_ANDX, "No"),
	SMB_COM_ENTRY(SMB_COM_READ_ANDX, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_ANDX, "No"),
	SMB_COM_ENTRY(SMB_COM_NEW_FILE_SIZE, "No"),
	SMB_COM_ENTRY(SMB_COM_CLOSE_AND_TREE_DISC, "No"),
	SMB_COM_ENTRY(SMB_COM_TRANSACTION2, "No"),
	SMB_COM_ENTRY(SMB_COM_TRANSACTION2_SECONDARY, "No"),
	SMB_COM_ENTRY(SMB_COM_FIND_CLOSE2, "No"),
	SMB_COM_ENTRY(SMB_COM_FIND_NOTIFY_CLOSE, "No"),
	SMB_COM_ENTRY(0x36, "?"),
	SMB_COM_ENTRY(0x37, "?"),
	SMB_COM_ENTRY(0x38, "?"),
	SMB_COM_ENTRY(0x39, "?"),
	SMB_COM_ENTRY(0x3A, "?"),
	SMB_COM_ENTRY(0x3B, "?"),
	SMB_COM_ENTRY(0x3C, "?"),
	SMB_COM_ENTRY(0x3D, "?"),
	SMB_COM_ENTRY(0x3E, "?"),
	SMB_COM_ENTRY(0x3F, "?"),
	SMB_COM_ENTRY(0x40, "?"),
	SMB_COM_ENTRY(0x41, "?"),
	SMB_COM_ENTRY(0x42, "?"),
	SMB_COM_ENTRY(0x43, "?"),
	SMB_COM_ENTRY(0x44, "?"),
	SMB_COM_ENTRY(0x45, "?"),
	SMB_COM_ENTRY(0x46, "?"),
	SMB_COM_ENTRY(0x47, "?"),
	SMB_COM_ENTRY(0x48, "?"),
	SMB_COM_ENTRY(0x49, "?"),
	SMB_COM_ENTRY(0x4A, "?"),
	SMB_COM_ENTRY(0x4B, "?"),
	SMB_COM_ENTRY(0x4C, "?"),
	SMB_COM_ENTRY(0x4D, "?"),
	SMB_COM_ENTRY(0x4E, "?"),
	SMB_COM_ENTRY(0x4F, "?"),
	SMB_COM_ENTRY(0x50, "?"),
	SMB_COM_ENTRY(0x51, "?"),
	SMB_COM_ENTRY(0x52, "?"),
	SMB_COM_ENTRY(0x53, "?"),
	SMB_COM_ENTRY(0x54, "?"),
	SMB_COM_ENTRY(0x55, "?"),
	SMB_COM_ENTRY(0x56, "?"),
	SMB_COM_ENTRY(0x57, "?"),
	SMB_COM_ENTRY(0x58, "?"),
	SMB_COM_ENTRY(0x59, "?"),
	SMB_COM_ENTRY(0x5A, "?"),
	SMB_COM_ENTRY(0x5B, "?"),
	SMB_COM_ENTRY(0x5C, "?"),
	SMB_COM_ENTRY(0x5D, "?"),
	SMB_COM_ENTRY(0x5E, "?"),
	SMB_COM_ENTRY(0x5F, "?"),
	SMB_COM_ENTRY(0x60, "?"),
	SMB_COM_ENTRY(0x61, "?"),
	SMB_COM_ENTRY(0x62, "?"),
	SMB_COM_ENTRY(0x63, "?"),
	SMB_COM_ENTRY(0x64, "?"),
	SMB_COM_ENTRY(0x65, "?"),
	SMB_COM_ENTRY(0x66, "?"),
	SMB_COM_ENTRY(0x67, "?"),
	SMB_COM_ENTRY(0x68, "?"),
	SMB_COM_ENTRY(0x69, "?"),
	SMB_COM_ENTRY(0x6A, "?"),
	SMB_COM_ENTRY(0x6B, "?"),
	SMB_COM_ENTRY(0x6C, "?"),
	SMB_COM_ENTRY(0x6D, "?"),
	SMB_COM_ENTRY(0x6E, "?"),
	SMB_COM_ENTRY(0x6F, "?"),
	SMB_COM_ENTRY(SMB_COM_TREE_CONNECT, "No"),
	SMB_COM_ENTRY(SMB_COM_TREE_DISCONNECT, "No"),
	SMB_COM_ENTRY(SMB_COM_NEGOTIATE, "No"),
	SMB_COM_ENTRY(SMB_COM_SESSION_SETUP_ANDX, "No"),
	SMB_COM_ENTRY(SMB_COM_LOGOFF_ANDX, "No"),
	SMB_COM_ENTRY(SMB_COM_TREE_CONNECT_ANDX, "No"),
	SMB_COM_ENTRY(0x76, "?"),
	SMB_COM_ENTRY(0x77, "?"),
	SMB_COM_ENTRY(0x78, "?"),
	SMB_COM_ENTRY(0x79, "?"),
	SMB_COM_ENTRY(0x7A, "?"),
	SMB_COM_ENTRY(0x7B, "?"),
	SMB_COM_ENTRY(0x7C, "?"),
	SMB_COM_ENTRY(0x7D, "?"),
	SMB_COM_ENTRY(0x7E, "?"),
	SMB_COM_ENTRY(0x7F, "?"),
	SMB_COM_ENTRY(SMB_COM_QUERY_INFORMATION_DISK, "No"),
	SMB_COM_ENTRY(SMB_COM_SEARCH, "No"),
	SMB_COM_ENTRY(SMB_COM_FIND, "No"),
	SMB_COM_ENTRY(SMB_COM_FIND_UNIQUE, "No"),
	SMB_COM_ENTRY(SMB_COM_FIND_CLOSE, "No"),
	SMB_COM_ENTRY(0x85, "?"),
	SMB_COM_ENTRY(0x86, "?"),
	SMB_COM_ENTRY(0x87, "?"),
	SMB_COM_ENTRY(0x88, "?"),
	SMB_COM_ENTRY(0x89, "?"),
	SMB_COM_ENTRY(0x8A, "?"),
	SMB_COM_ENTRY(0x8B, "?"),
	SMB_COM_ENTRY(0x8C, "?"),
	SMB_COM_ENTRY(0x8D, "?"),
	SMB_COM_ENTRY(0x8E, "?"),
	SMB_COM_ENTRY(0x8F, "?"),
	SMB_COM_ENTRY(0x90, "?"),
	SMB_COM_ENTRY(0x91, "?"),
	SMB_COM_ENTRY(0x92, "?"),
	SMB_COM_ENTRY(0x93, "?"),
	SMB_COM_ENTRY(0x94, "?"),
	SMB_COM_ENTRY(0x95, "?"),
	SMB_COM_ENTRY(0x96, "?"),
	SMB_COM_ENTRY(0x97, "?"),
	SMB_COM_ENTRY(0x98, "?"),
	SMB_COM_ENTRY(0x99, "?"),
	SMB_COM_ENTRY(0x9A, "?"),
	SMB_COM_ENTRY(0x9B, "?"),
	SMB_COM_ENTRY(0x9C, "?"),
	SMB_COM_ENTRY(0x9D, "?"),
	SMB_COM_ENTRY(0x9E, "?"),
	SMB_COM_ENTRY(0x9F, "?"),
	SMB_COM_ENTRY(SMB_COM_NT_TRANSACT, "No"),
	SMB_COM_ENTRY(SMB_COM_NT_TRANSACT_SECONDARY, "No"),
	SMB_COM_ENTRY(SMB_COM_NT_CREATE_ANDX, "No"),
	SMB_COM_ENTRY(0xA3, "?"),
	SMB_COM_ENTRY(SMB_COM_NT_CANCEL, "No"),
	SMB_COM_ENTRY(SMB_COM_NT_RENAME, "No"),
	SMB_COM_ENTRY(0xA6, "?"),
	SMB_COM_ENTRY(0xA7, "?"),
	SMB_COM_ENTRY(0xA8, "?"),
	SMB_COM_ENTRY(0xA9, "?"),
	SMB_COM_ENTRY(0xAA, "?"),
	SMB_COM_ENTRY(0xAB, "?"),
	SMB_COM_ENTRY(0xAC, "?"),
	SMB_COM_ENTRY(0xAD, "?"),
	SMB_COM_ENTRY(0xAE, "?"),
	SMB_COM_ENTRY(0xAF, "?"),
	SMB_COM_ENTRY(0xB0, "?"),
	SMB_COM_ENTRY(0xB1, "?"),
	SMB_COM_ENTRY(0xB2, "?"),
	SMB_COM_ENTRY(0xB3, "?"),
	SMB_COM_ENTRY(0xB4, "?"),
	SMB_COM_ENTRY(0xB5, "?"),
	SMB_COM_ENTRY(0xB6, "?"),
	SMB_COM_ENTRY(0xB7, "?"),
	SMB_COM_ENTRY(0xB8, "?"),
	SMB_COM_ENTRY(0xB9, "?"),
	SMB_COM_ENTRY(0xBA, "?"),
	SMB_COM_ENTRY(0xBB, "?"),
	SMB_COM_ENTRY(0xBC, "?"),
	SMB_COM_ENTRY(0xBD, "?"),
	SMB_COM_ENTRY(0xBE, "?"),
	SMB_COM_ENTRY(0xBF, "?"),
	SMB_COM_ENTRY(SMB_COM_OPEN_PRINT_FILE, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_PRINT_FILE, "No"),
	SMB_COM_ENTRY(SMB_COM_CLOSE_PRINT_FILE, "No"),
	SMB_COM_ENTRY(SMB_COM_GET_PRINT_QUEUE, "No"),
	SMB_COM_ENTRY(0xC4, "?"),
	SMB_COM_ENTRY(0xC5, "?"),
	SMB_COM_ENTRY(0xC6, "?"),
	SMB_COM_ENTRY(0xC7, "?"),
	SMB_COM_ENTRY(0xC8, "?"),
	SMB_COM_ENTRY(0xC9, "?"),
	SMB_COM_ENTRY(0xCA, "?"),
	SMB_COM_ENTRY(0xCB, "?"),
	SMB_COM_ENTRY(0xCC, "?"),
	SMB_COM_ENTRY(0xCD, "?"),
	SMB_COM_ENTRY(0xCE, "?"),
	SMB_COM_ENTRY(0xCF, "?"),
	SMB_COM_ENTRY(0xD0, "?"),
	SMB_COM_ENTRY(0xD1, "?"),
	SMB_COM_ENTRY(0xD2, "?"),
	SMB_COM_ENTRY(0xD3, "?"),
	SMB_COM_ENTRY(0xD4, "?"),
	SMB_COM_ENTRY(0xD5, "?"),
	SMB_COM_ENTRY(0xD6, "?"),
	SMB_COM_ENTRY(0xD7, "?"),
	SMB_COM_ENTRY(SMB_COM_READ_BULK, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_BULK, "No"),
	SMB_COM_ENTRY(SMB_COM_WRITE_BULK_DATA, "No"),
	SMB_COM_ENTRY(0xDB, "?"),
	SMB_COM_ENTRY(0xDC, "?"),
	SMB_COM_ENTRY(0xDD, "?"),
	SMB_COM_ENTRY(0xDE, "?"),
	SMB_COM_ENTRY(0xDF, "?"),
	SMB_COM_ENTRY(0xE0, "?"),
	SMB_COM_ENTRY(0xE1, "?"),
	SMB_COM_ENTRY(0xE2, "?"),
	SMB_COM_ENTRY(0xE3, "?"),
	SMB_COM_ENTRY(0xE4, "?"),
	SMB_COM_ENTRY(0xE5, "?"),
	SMB_COM_ENTRY(0xE6, "?"),
	SMB_COM_ENTRY(0xE7, "?"),
	SMB_COM_ENTRY(0xE8, "?"),
	SMB_COM_ENTRY(0xE9, "?"),
	SMB_COM_ENTRY(0xEA, "?"),
	SMB_COM_ENTRY(0xEB, "?"),
	SMB_COM_ENTRY(0xEC, "?"),
	SMB_COM_ENTRY(0xED, "?"),
	SMB_COM_ENTRY(0xEE, "?"),
	SMB_COM_ENTRY(0xEF, "?"),
	SMB_COM_ENTRY(0xF0, "?"),
	SMB_COM_ENTRY(0xF1, "?"),
	SMB_COM_ENTRY(0xF2, "?"),
	SMB_COM_ENTRY(0xF3, "?"),
	SMB_COM_ENTRY(0xF4, "?"),
	SMB_COM_ENTRY(0xF5, "?"),
	SMB_COM_ENTRY(0xF6, "?"),
	SMB_COM_ENTRY(0xF7, "?"),
	SMB_COM_ENTRY(0xF8, "?"),
	SMB_COM_ENTRY(0xF9, "?"),
	SMB_COM_ENTRY(0xFA, "?"),
	SMB_COM_ENTRY(0xFB, "?"),
	SMB_COM_ENTRY(0xFC, "?"),
	SMB_COM_ENTRY(0xFD, "?"),
	SMB_COM_ENTRY(0xFE, "?"),
	SMB_COM_ENTRY(0xFF, "?")
};

static int smb_dcmd_list(uintptr_t, uint_t, int, const mdb_arg_t *);
static void smb_dcmd_list_help(void);
static int smb_dcmd_server(uintptr_t, uint_t, int, const mdb_arg_t *);
static void smb_dcmd_session_help(void);
static int smb_dcmd_session(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_dcmd_request(uintptr_t, uint_t, int, const mdb_arg_t *);
static void smb_dcmd_user_help(void);
static int smb_dcmd_user(uintptr_t, uint_t, int, const mdb_arg_t *);
static void smb_dcmd_tree_help(void);
static int smb_dcmd_tree(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_dcmd_odir(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_dcmd_ofile(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_dcmd_kshare(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_dcmd_vfs(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_vfs_walk_init(mdb_walk_state_t *);
static int smb_vfs_walk_step(mdb_walk_state_t *);
static void smb_node_help(void);
static int smb_dcmd_node(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_node_walk_init(mdb_walk_state_t *);
static int smb_node_walk_step(mdb_walk_state_t *);
static int smb_lock(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_oplock(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_oplock_grant(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_ace(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_ace_walk_init(mdb_walk_state_t *);
static int smb_ace_walk_step(mdb_walk_state_t *);
static int smb_acl(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_sd(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_sid(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_sid_print(uintptr_t);
static int smb_fssd(uintptr_t, uint_t, int, const mdb_arg_t *);
static int smb_dcmd_getopt(uint_t *, int, const mdb_arg_t *);
static int smb_dcmd_setopt(uint_t, int, mdb_arg_t *);
static int smb_obj_expand(uintptr_t, uint_t, const smb_exp_t *, ulong_t);
static int smb_obj_list(const char *, uint_t, uint_t);
static int smb_worker_findstack(uintptr_t);
static int smb_stats(uintptr_t, uint_t, int, const mdb_arg_t *);

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers and a function named _mdb_init to return a pointer
 * to our module information.
 */
static const mdb_dcmd_t dcmds[] = {
	{   "smblist",
	    "[-seutfdwv]",
	    "print tree of SMB objects",
	    smb_dcmd_list,
	    smb_dcmd_list_help },
	{   "smbsrv",
	    "[-seutfdwv]",
	    "print smb_server information",
	    smb_dcmd_server },
	{   "smbshares",
	    "[-v]",
	    "print smb_kshare_t information",
	    smb_dcmd_kshare },
	{   "smbvfs",
	    "[-v]",
	    "print smb_vfs information",
	    smb_dcmd_vfs },
	{   "smbnode",
	    "?[-vps]",
	    "print smb_node_t information",
	    smb_dcmd_node,
	    smb_node_help },
	{   "smbsess",
	    "[-utfdwv]",
	    "print smb_session_t information",
	    smb_dcmd_session,
	    smb_dcmd_session_help},
	{   "smbreq",
	    ":[-v]",
	    "print smb_request_t information",
	    smb_dcmd_request },
	{   "smblock", ":[-v]",
	    "print smb_lock_t information", smb_lock },
	{   "smbuser",
	    ":[-vdftq]",
	    "print smb_user_t information",
	    smb_dcmd_user,
	    smb_dcmd_user_help },
	{   "smbtree",
	    ":[-vdf]",
	    "print smb_tree_t information",
	    smb_dcmd_tree,
	    smb_dcmd_tree_help },
	{   "smbodir",
	    ":[-v]",
	    "print smb_odir_t information",
	    smb_dcmd_odir },
	{   "smbofile",
	    "[-v]",
	    "print smb_file_t information",
	    smb_dcmd_ofile },
	{   "smboplock", NULL,
	    "print smb_oplock_t information", smb_oplock },
	{   "smboplockgrant", NULL,
	    "print smb_oplock_grant_t information", smb_oplock_grant },
	{   "smbstat", NULL,
	    "print all smb dispatched requests statistics",
	    smb_stats },
	{   "smbace", "[-v]",
	    "print smb_ace_t information", smb_ace },
	{   "smbacl", "[-v]",
	    "print smb_acl_t information", smb_acl },
	{   "smbsid", "[-v]",
	    "print smb_sid_t information", smb_sid },
	{   "smbsd", "[-v]",
	    "print smb_sd_t information", smb_sd },
	{   "smbfssd", "[-v]",
	    "print smb_fssd_t information", smb_fssd },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{   "smbnode_walker",
	    "walk list of smb_node_t structures",
	    smb_node_walk_init,
	    smb_node_walk_step,
	    NULL,
	    NULL },
	{   "smbvfs_walker",
	    "walk list of smb_vfs_t structures",
	    smb_vfs_walk_init,
	    smb_vfs_walk_step,
	    NULL,
	    NULL },
	{   "smbace_walker",
	    "walk list of smb_ace_t structures",
	    smb_ace_walk_init,
	    smb_ace_walk_step,
	    NULL,
	    NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

/*
 * *****************************************************************************
 * ****************************** Top level DCMD *******************************
 * *****************************************************************************
 */

static void
smb_dcmd_list_help(void)
{
	mdb_printf(
	    "Displays the list of objects using an indented tree format.\n"
	    "If no option is specified the entire tree is displayed\n\n");
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose information\n"
	    "-s\tDisplay the list of servers\n"
	    "-e\tDisplay the list of sessions\n"
	    "-r\tDisplay the list of smb requests\n"
	    "-u\tDisplay the list of users\n"
	    "-t\tDisplay the list of trees\n"
	    "-f\tDisplay the list of open files\n"
	    "-d\tDisplay the list of open searches\n");
}

/*
 * ::smblist
 *
 * This function lists the objects specified on the command line. If no object
 * is specified the entire tree (server through ofile and odir) is displayed.
 *
 */
/*ARGSUSED*/
static int
smb_dcmd_list(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	GElf_Sym	sym;
	uint_t		opts = 0;
	int		new_argc;
	mdb_arg_t	new_argv[SMB_MDB_MAX_OPTS];

	if (smb_dcmd_getopt(&opts, argc, argv))
		return (DCMD_USAGE);

	if (!(opts & ~(SMB_OPT_WALK | SMB_OPT_VERBOSE)))
		opts |= SMB_OPT_ALL_OBJ;

	opts |= SMB_OPT_WALK;

	new_argc = smb_dcmd_setopt(opts, SMB_MDB_MAX_OPTS, new_argv);

	if (mdb_lookup_by_name("smb_servers", &sym) == -1) {
		mdb_warn("failed to find symbol smb_servers");
		return (DCMD_ERR);
	}

	addr = (uintptr_t)sym.st_value + offsetof(smb_llist_t, ll_list);

	if (mdb_pwalk_dcmd("list", "smbsrv", new_argc, new_argv, addr))
		return (DCMD_ERR);
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ***************************** smb_server_t **********************************
 * *****************************************************************************
 */

static const char *smb_server_state[SMB_SERVER_STATE_SENTINEL] =
{
	"CREATED",
	"CONFIGURED",
	"RUNNING",
	"STOPPING",
	"DELETING"
};

/*
 * List of objects that can be expanded under a server structure.
 */
static const smb_exp_t smb_server_exp[] =
{
	{ SMB_OPT_ALL_OBJ,
	    offsetof(smb_server_t, sv_nbt_daemon.ld_session_list.ll_list),
	    "smbsess", "smb_session"},
	{ SMB_OPT_ALL_OBJ,
	    offsetof(smb_server_t, sv_tcp_daemon.ld_session_list.ll_list),
	    "smbsess", "smb_session"},
	{ 0, 0, NULL, NULL }
};

/*
 * ::smbsrv
 *
 * smbsrv dcmd - Print out smb_server structures.
 */
/*ARGSUSED*/
static int
smb_dcmd_server(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		opts;
	ulong_t		indent = 0;

	if (smb_dcmd_getopt(&opts, argc, argv))
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		return (smb_obj_list("smb_server", opts | SMB_OPT_SERVER,
		    flags));

	if (((opts & SMB_OPT_WALK) && (opts & SMB_OPT_SERVER)) ||
	    !(opts & SMB_OPT_WALK)) {
		smb_server_t	*sv;
		const char	*state;

		sv = mdb_alloc(sizeof (smb_server_t), UM_SLEEP | UM_GC);
		if (mdb_vread(sv, sizeof (smb_server_t), addr) == -1) {
			mdb_warn("failed to read smb_server at %p", addr);
			return (DCMD_ERR);
		}

		indent = SMB_DCMD_INDENT;

		if (opts & SMB_OPT_VERBOSE) {
			mdb_arg_t	argv;

			argv.a_type = MDB_TYPE_STRING;
			argv.a_un.a_str = "smb_server_t";
			if (mdb_call_dcmd("print", addr, flags, 1, &argv))
				return (DCMD_ERR);
		} else {
			if (DCMD_HDRSPEC(flags))
				mdb_printf(
				    "%<b>%<u>%-?s% "
				    "%-4s% "
				    "%-32s% "
				    "%</u>%</b>\n",
				    "SERVER", "ZONE", "STATE");

			if (sv->sv_state >= SMB_SERVER_STATE_SENTINEL)
				state = "UNKNOWN";
			else
				state = smb_server_state[sv->sv_state];

			mdb_printf("%-?p %-4d %-32s \n",
			    addr, sv->sv_zid, state);
		}
	}
	if (smb_obj_expand(addr, opts, smb_server_exp, indent))
		return (DCMD_ERR);
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ***************************** smb_session_t *********************************
 * *****************************************************************************
 */

static const char *smb_session_state[SMB_SESSION_STATE_SENTINEL] =
{
	"INITIALIZED",
	"DISCONNECTED",
	"CONNECTED",
	"ESTABLISHED",
	"NEGOTIATED",
	"OPLOCK_BREAKING",
	"WRITE_RAW_ACTIVE",
	"READ_RAW_ACTIVE",
	"TERMINATED"
};

/*
 * List of objects that can be expanded under a session structure.
 */
static const smb_exp_t smb_session_exp[] =
{
	{ SMB_OPT_REQUEST,
	    offsetof(smb_session_t, s_req_list.sl_list),
	    "smbreq", "smb_request"},
	{ SMB_OPT_USER,
	    offsetof(smb_session_t, s_user_list.ll_list),
	    "smbuser", "smb_user"},
	{ SMB_OPT_TREE | SMB_OPT_OFILE | SMB_OPT_ODIR,
	    offsetof(smb_session_t, s_tree_list.ll_list),
	    "smbtree", "smb_tree"},
	{ 0, 0, NULL, NULL}
};

static void
smb_dcmd_session_help(void)
{
	mdb_printf(
	    "Display the contents of smb_session_t, with optional"
	    " filtering.\n\n");
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose smb_session information\n"
	    "-r\tDisplay the list of smb requests attached\n"
	    "-u\tDisplay the list of users attached\n");
}

/*
 * ::smbsess
 *
 * smbsess dcmd - Print out the smb_session structure.
 */
static int
smb_dcmd_session(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		opts;
	ulong_t		indent = 0;

	if (smb_dcmd_getopt(&opts, argc, argv))
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		opts |= SMB_OPT_SESSION;
		opts &= ~SMB_OPT_SERVER;
		return (smb_obj_list("smb_session", opts, flags));
	}

	if (((opts & SMB_OPT_WALK) && (opts & SMB_OPT_SESSION)) ||
	    !(opts & SMB_OPT_WALK)) {
		smb_session_t	*se;
		const char	*state;

		indent = SMB_DCMD_INDENT;

		se = mdb_alloc(sizeof (*se), UM_SLEEP | UM_GC);
		if (mdb_vread(se, sizeof (*se), addr) == -1) {
			mdb_warn("failed to read smb_session at %p", addr);
			return (DCMD_ERR);
		}
		if (se->s_state >= SMB_SESSION_STATE_SENTINEL)
			state = "INVALID";
		else
			state = smb_session_state[se->s_state];

		if (opts & SMB_OPT_VERBOSE) {
			mdb_printf("%<b>%<u>SMB session information "
			    "(%p): %</u>%</b>\n", addr);
			switch (se->ipaddr.a_family) {
			case AF_INET:
				mdb_printf("Client IP address: %I\n",
				    se->ipaddr.a_ipv4);
				mdb_printf("Local IP Address: %I\n",
				    se->local_ipaddr.a_ipv4);
				break;
			case AF_INET6:
				mdb_printf("Client IP address: %N\n",
				    &(se->ipaddr.a_ipv6));
				mdb_printf("Local IP Address: %N\n",
				    &(se->local_ipaddr.a_ipv6));
				break;
			default:
				mdb_printf("Client IP address: unknown\n");
				mdb_printf("Local IP Address: unknown\n");
			}
			mdb_printf("Session KID: %u\n", se->s_kid);
			mdb_printf("Workstation Name: %s\n",
			    se->workstation);
			mdb_printf("Session state: %u (%s)\n", se->s_state,
			    state);
			mdb_printf("Number of Users: %u\n",
			    se->s_user_list.ll_count);
			mdb_printf("Number of Trees: %u\n", se->s_tree_cnt);
			mdb_printf("Number of Files: %u\n", se->s_file_cnt);
			mdb_printf("Number of Shares: %u\n", se->s_dir_cnt);
			mdb_printf("Number of active Transact.: %u\n\n",
			    se->s_xa_list.ll_count);
		} else {
			char	cipaddr[INET6_ADDRSTRLEN];
			char	lipaddr[INET6_ADDRSTRLEN];
			int	ipaddrstrlen;

			switch (se->ipaddr.a_family) {
			case AF_INET:
				ipaddrstrlen = INET_ADDRSTRLEN;
				(void) mdb_snprintf(cipaddr, sizeof (cipaddr),
				    "%I", se->ipaddr.a_ipv4);
				(void) mdb_snprintf(lipaddr, sizeof (lipaddr),
				    "%I", se->local_ipaddr.a_ipv4);
				break;
			case AF_INET6:
				ipaddrstrlen = INET6_ADDRSTRLEN;
				(void) mdb_snprintf(cipaddr, sizeof (cipaddr),
				    "%N", &(se->ipaddr.a_ipv6));
				(void) mdb_snprintf(lipaddr, sizeof (lipaddr),
				    "%N", &(se->local_ipaddr.a_ipv6));
				break;
			default:
				ipaddrstrlen = INET_ADDRSTRLEN;
				(void) mdb_snprintf(cipaddr, sizeof (cipaddr),
				    "unknown");
				(void) mdb_snprintf(lipaddr, sizeof (lipaddr),
				    "unknown");
			}

			if (DCMD_HDRSPEC(flags)) {
				mdb_printf(
				    "%<b>%<u>%-?s %-*s %-*s %-16s%</u>%</b>\n",
				    "SESSION", ipaddrstrlen, "CLIENT_IP_ADDR",
				    ipaddrstrlen, "LOCAL_IP_ADDR", "STATE");
			}
			mdb_printf("%-?p %-*s %-*s %s\n", addr, ipaddrstrlen,
			    cipaddr, ipaddrstrlen, lipaddr, state);
		}
	}
	if (smb_obj_expand(addr, opts, smb_session_exp, indent))
		return (DCMD_ERR);
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * **************************** smb_request_t **********************************
 * *****************************************************************************
 */

static const char *smb_request_state[SMB_REQ_STATE_SENTINEL] =
{
	"FREE",
	"INITIALIZING",
	"SUBMITTED",
	"ACTIVE",
	"WAITING_EVENT",
	"EVENT_OCCURRED",
	"WAITING_LOCK",
	"COMPLETED",
	"CANCELED",
	"CLEANED_UP"
};

#define	SMB_REQUEST_BANNER	\
	"%<b>%<u>%-?s %-?s %-14s %-14s %-16s %-32s%</u>%</b>\n"
#define	SMB_REQUEST_FORMAT	\
	"%-?p %-?p %-14lld %-14lld %-16s %s\n"

static int
smb_dcmd_request(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		opts;

	if (smb_dcmd_getopt(&opts, argc, argv))
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		opts |= SMB_OPT_REQUEST;
		opts &= ~(SMB_OPT_SERVER | SMB_OPT_SESSION | SMB_OPT_USER);
		return (smb_obj_list("smb_request", opts, flags));
	}

	if (((opts & SMB_OPT_WALK) && (opts & SMB_OPT_REQUEST)) ||
	    !(opts & SMB_OPT_WALK)) {
		smb_request_t	*sr;
		const char	*state;
		uint64_t	waiting;
		uint64_t	running;

		sr = mdb_alloc(sizeof (*sr), UM_SLEEP | UM_GC);
		if (mdb_vread(sr, sizeof (*sr), addr) == -1) {
			mdb_warn("failed to read smb_request at %p", addr);
			return (DCMD_ERR);
		}
		if (sr->sr_magic != SMB_REQ_MAGIC) {
			mdb_warn("not an smb_request_t (%p)>", addr);
			return (DCMD_ERR);
		}
		waiting = 0;
		running = 0;
		if (sr->sr_time_submitted != 0) {
			if (sr->sr_time_active != 0) {
				waiting = sr->sr_time_active -
				    sr->sr_time_submitted;
				running = mdb_gethrtime() -
				    sr->sr_time_active;
			} else {
				waiting = mdb_gethrtime() -
				    sr->sr_time_submitted;
			}
		}
		waiting /= NANOSEC;
		running /= NANOSEC;

		if (sr->sr_state >= SMB_REQ_STATE_SENTINEL)
			state = "INVALID";
		else
			state = smb_request_state[sr->sr_state];

		if (opts & SMB_OPT_VERBOSE) {
			mdb_printf(
			    "%</b>%</u>SMB request information (%p):"
			    "%</u>%</b>\n\n", addr);

			mdb_printf(
			    "first SMB COM: %u (%s)\n"
			    "current SMB COM: %u (%s)\n"
			    "state: %u (%s)\n"
			    "TID(tree): %u (%p)\n"
			    "UID(user): %u (%p)\n"
			    "FID(file): %u (%p)\n"
			    "PID: %u\n"
			    "MID: %u\n\n"
			    "waiting time: %lld\n"
			    "running time: %lld\n",
			    sr->first_smb_com,
			    smb_com[sr->first_smb_com].smb_com,
			    sr->smb_com,
			    smb_com[sr->smb_com].smb_com,
			    sr->sr_state, state,
			    sr->smb_tid, sr->tid_tree,
			    sr->smb_uid, sr->uid_user,
			    sr->smb_fid, sr->fid_ofile,
			    sr->smb_pid,
			    sr->smb_mid,
			    waiting,
			    running);

			smb_worker_findstack((uintptr_t)sr->sr_worker);
		} else {
			if (DCMD_HDRSPEC(flags))
				mdb_printf(
				    SMB_REQUEST_BANNER,
				    "ADDR",
				    "WORKER",
				    "WAITING(s)",
				    "RUNNING(s)",
				    "STATE",
				    "COMMAND");

			mdb_printf(SMB_REQUEST_FORMAT,
			    addr,
			    sr->sr_worker,
			    waiting,
			    running,
			    state,
			    smb_com[sr->smb_com].smb_com);
		}
	}
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ****************************** smb_user_t ***********************************
 * *****************************************************************************
 */

static const char *smb_user_state[SMB_USER_STATE_SENTINEL] =
{
	"LOGGED_IN",
	"LOGGING_OFF",
	"LOGGED_OFF"
};

static void
smb_dcmd_user_help(void)
{
	mdb_printf(
	    "Display the contents of smb_user_t, with optional filtering.\n\n");
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose smb_user information\n");
}

static int
smb_dcmd_user(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		opts;

	if (smb_dcmd_getopt(&opts, argc, argv))
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		opts |= SMB_OPT_USER;
		opts &= ~(SMB_OPT_SERVER | SMB_OPT_SESSION | SMB_OPT_REQUEST);
		return (smb_obj_list("smb_user", opts, flags));
	}

	if (((opts & SMB_OPT_WALK) && (opts & SMB_OPT_USER)) ||
	    !(opts & SMB_OPT_WALK)) {
		smb_user_t	*user;
		char		*account;

		user = mdb_alloc(sizeof (*user), UM_SLEEP | UM_GC);
		if (mdb_vread(user, sizeof (*user), addr) == -1) {
			mdb_warn("failed to read smb_user at %p", addr);
			return (DCMD_ERR);
		}
		account = mdb_zalloc(user->u_domain_len + user->u_name_len + 2,
		    UM_SLEEP | UM_GC);

		if (user->u_domain_len)
			(void) mdb_vread(account, user->u_domain_len,
			    (uintptr_t)user->u_domain);

		strcat(account, "\\");

		if (user->u_name_len)
			(void) mdb_vread(account + strlen(account),
			    user->u_name_len, (uintptr_t)user->u_name);

		if (opts & SMB_OPT_VERBOSE) {
			const char	*state;

			if (user->u_state >= SMB_USER_STATE_SENTINEL)
				state = "INVALID";
			else
				state = smb_user_state[user->u_state];

			mdb_printf("%<b>%<u>SMB user information (%p):"
			    "%</u>%</b>\n", addr);
			mdb_printf("UID: %u\n", user->u_uid);
			mdb_printf("State: %d (%s)\n", user->u_state, state);
			mdb_printf("Flags: 0x%08x\n", user->u_flags);
			mdb_printf("Privileges: 0x%08x\n", user->u_privileges);
			mdb_printf("Credential: %p\n", user->u_cred);
			mdb_printf("Reference Count: %d\n", user->u_refcnt);
			mdb_printf("User Account: %s\n\n", account);
		} else {
			if (DCMD_HDRSPEC(flags))
				mdb_printf(
				    "%<b>%<u>%?-s "
				    "%-5s "
				    "%-32s%</u>%</b>\n",
				    "USER", "UID", "ACCOUNT");

			mdb_printf("%-?p %-5u %-32s\n", addr, user->u_uid,
			    account);
		}
	}
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ****************************** smb_tree_t ***********************************
 * *****************************************************************************
 */

static const char *smb_tree_state[SMB_TREE_STATE_SENTINEL] =
{
	"CONNECTED",
	"DISCONNECTING",
	"DISCONNECTED"
};

/*
 * List of objects that can be expanded under a tree structure.
 */
static const smb_exp_t smb_tree_exp[] =
{
	{ SMB_OPT_OFILE,
	    offsetof(smb_tree_t, t_ofile_list.ll_list),
	    "smbofile", "smb_ofile"},
	{ SMB_OPT_ODIR,
	    offsetof(smb_tree_t, t_odir_list.ll_list),
	    "smbodir", "smb_odir"},
	{ 0, 0, NULL, NULL}
};

static void
smb_dcmd_tree_help(void)
{
	mdb_printf(
	    "Display the contents of smb_tree_t, with optional filtering.\n\n");
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose smb_tree information\n"
	    "-d\tDisplay the list of smb_odirs attached\n"
	    "-f\tDisplay the list of smb_ofiles attached\n");
}

static int
smb_dcmd_tree(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		opts;
	ulong_t		indent = 0;

	if (smb_dcmd_getopt(&opts, argc, argv))
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		opts |= SMB_OPT_TREE;
		opts &= ~(SMB_OPT_SERVER | SMB_OPT_SESSION | SMB_OPT_REQUEST |
		    SMB_OPT_USER);
		return (smb_obj_list("smb_tree", opts, flags));
	}

	if (((opts & SMB_OPT_WALK) && (opts & SMB_OPT_TREE)) ||
	    !(opts & SMB_OPT_WALK)) {
		smb_tree_t	*tree;

		indent = SMB_DCMD_INDENT;

		tree = mdb_alloc(sizeof (*tree), UM_SLEEP | UM_GC);
		if (mdb_vread(tree, sizeof (*tree), addr) == -1) {
			mdb_warn("failed to read smb_tree at %p", addr);
			return (DCMD_ERR);
		}
		if (opts & SMB_OPT_VERBOSE) {
			const char	*state;

			if (tree->t_state >= SMB_TREE_STATE_SENTINEL)
				state = "INVALID";
			else
				state = smb_tree_state[tree->t_state];

			mdb_printf("%<b>%<u>SMB tree information (%p):"
			    "%</u>%</b>\n\n", addr);
			mdb_printf("TID: %04x\n", tree->t_tid);
			mdb_printf("State: %d (%s)\n", tree->t_state, state);
			mdb_printf("Share: %s\n", tree->t_sharename);
			mdb_printf("Resource: %s\n", tree->t_resource);
			mdb_printf("Type: %s\n", tree->t_typename);
			mdb_printf("Volume: %s\n", tree->t_volume);
			mdb_printf("Umask: %04x\n", tree->t_umask);
			mdb_printf("Flags: %08x\n", tree->t_flags);
			mdb_printf("SMB Node: %llx\n", tree->t_snode);
			mdb_printf("Reference Count: %d\n\n", tree->t_refcnt);
		} else {
			if (DCMD_HDRSPEC(flags))
				mdb_printf(
				    "%<b>%<u>%-?s %-5s %-16s %-32s%</u>%</b>\n",
				    "TREE", "TID", "SHARE NAME", "RESOURCE");

			mdb_printf("%-?p %-5u %-16s %-32s\n", addr,
			    tree->t_tid, tree->t_sharename, tree->t_resource);
		}
	}
	if (smb_obj_expand(addr, opts, smb_tree_exp, indent))
		return (DCMD_ERR);
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ****************************** smb_odir_t ***********************************
 * *****************************************************************************
 */

static const char *smb_odir_state[SMB_ODIR_STATE_SENTINEL] =
{
	"OPEN",
	"IN_USE",
	"CLOSING",
	"CLOSED"
};

static int
smb_dcmd_odir(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		opts;

	if (smb_dcmd_getopt(&opts, argc, argv))
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		opts |= SMB_OPT_ODIR;
		opts &= ~(SMB_OPT_SERVER | SMB_OPT_SESSION | SMB_OPT_REQUEST |
		    SMB_OPT_USER | SMB_OPT_TREE | SMB_OPT_OFILE);
		return (smb_obj_list("smb_odir", opts, flags));
	}

	if (((opts & SMB_OPT_WALK) && (opts & SMB_OPT_ODIR)) ||
	    !(opts & SMB_OPT_WALK)) {
		smb_odir_t	*od;

		od = mdb_alloc(sizeof (*od), UM_SLEEP | UM_GC);
		if (mdb_vread(od, sizeof (*od), addr) == -1) {
			mdb_warn("failed to read smb_odir at %p", addr);
			return (DCMD_ERR);
		}
		if (opts & SMB_OPT_VERBOSE) {
			const char	*state;

			if (od->d_state >= SMB_ODIR_STATE_SENTINEL)
				state = "INVALID";
			else
				state = smb_odir_state[od->d_state];

			mdb_printf(
			    "%<b>%<u>SMB odir information (%p):%</u>%</b>\n\n",
			    addr);
			mdb_printf("State: %d (%s)\n", od->d_state, state);
			mdb_printf("SID: %u\n", od->d_odid);
			mdb_printf("User: %p\n", od->d_user);
			mdb_printf("Tree: %p\n", od->d_tree);
			mdb_printf("Reference Count: %d\n", od->d_refcnt);
			mdb_printf("Pattern: %s\n", od->d_pattern);
			mdb_printf("SMB Node: %p\n\n", od->d_dnode);
		} else {
			if (DCMD_HDRSPEC(flags))
				mdb_printf(
				    "%<b>%<u>%-?s "
				    "%-5s "
				    "%-?s "
				    "%-16s%</u>%</b>\n",
				    "ODIR", "SID", "VNODE", "PATTERN");

			mdb_printf("%?p %-5u %-16p %s\n",
			    addr, od->d_odid, od->d_dnode, od->d_pattern);
		}
	}
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ****************************** smb_ofile_t **********************************
 * *****************************************************************************
 */

static const char *smb_ofile_state[SMB_OFILE_STATE_SENTINEL] =
{
	"OPEN",
	"CLOSING",
	"CLOSED"
};

static int
smb_dcmd_ofile(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		opts;

	if (smb_dcmd_getopt(&opts, argc, argv))
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		opts |= SMB_OPT_OFILE;
		opts &= ~(SMB_OPT_SERVER | SMB_OPT_SESSION | SMB_OPT_REQUEST |
		    SMB_OPT_USER | SMB_OPT_TREE | SMB_OPT_ODIR);
		return (smb_obj_list("smb_ofile", opts, flags));
	}

	if (((opts & SMB_OPT_WALK) && (opts & SMB_OPT_OFILE)) ||
	    !(opts & SMB_OPT_WALK)) {
		smb_ofile_t	*of;

		of = mdb_alloc(sizeof (*of), UM_SLEEP | UM_GC);
		if (mdb_vread(of, sizeof (*of), addr) == -1) {
			mdb_warn("failed to read smb_ofile at %p", addr);
			return (DCMD_ERR);
		}
		if (opts & SMB_OPT_VERBOSE) {
			const char	*state;

			if (of->f_state >= SMB_OFILE_STATE_SENTINEL)
				state = "INVALID";
			else
				state = smb_ofile_state[of->f_state];

			mdb_printf(
			    "%<b>%<u>SMB ofile information (%p):%</u>%</b>\n\n",
			    addr);
			mdb_printf("FID: %u\n", of->f_fid);
			mdb_printf("State: %d (%s)\n", of->f_state, state);
			mdb_printf("SMB Node: %p\n", of->f_node);
			mdb_printf("LLF Offset: 0x%llx (%s)\n",
			    of->f_llf_pos,
			    ((of->f_flags & SMB_OFLAGS_LLF_POS_VALID) ?
			    "Valid" : "Invalid"));
			mdb_printf("Flags: 0x%08x\n", of->f_flags);
			mdb_printf("User: %p\n", of->f_user);
			mdb_printf("Tree: %p\n", of->f_tree);
			mdb_printf("Credential: %p\n\n", of->f_cr);
		} else {
			if (DCMD_HDRSPEC(flags))
				mdb_printf(
				    "%<b>%<u>%-?s "
				    "%-5s "
				    "%-?s "
				    "%-?s%</u>%</b>\n",
				    "OFILE", "FID", "SMB NODE", "CRED");

			mdb_printf("%?p %-5u %-p %p\n", addr,
			    of->f_fid, of->f_node, of->f_cr);
		}
	}
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ******************************** smb_kshare_t *******************************
 * *****************************************************************************
 */

static int
smb_kshare_cb(uintptr_t addr, const void *data, void *arg)
{
	uint_t *opts = arg;
	uintptr_t ta, sa;
	char name[32];
	char path[64];
	_NOTE(ARGUNUSED(data));

	if (*opts & SMB_OPT_VERBOSE) {
		mdb_arg_t	argv;

		argv.a_type = MDB_TYPE_STRING;
		argv.a_un.a_str = "smb_kshare_t";
		/* Don't fail the walk if this fails. */
		mdb_call_dcmd("print", addr, 0, 1, &argv);
	} else {
		/*
		 * Summary line for a kshare
		 * Don't fail the walk if any of these fail.
		 */
		ta = addr + OFFSETOF(smb_kshare_t, shr_name);
		if (mdb_vread(&sa, sizeof (sa), ta) < 0 ||
		    mdb_readstr(name, sizeof (name), sa) <= 0)
			strcpy(name, "?");

		ta = addr + OFFSETOF(smb_kshare_t, shr_path);
		if (mdb_vread(&sa, sizeof (sa), ta) < 0 ||
		    mdb_readstr(path, sizeof (path), sa) <= 0)
			strcpy(path, "?");

		mdb_printf("%-?p ", addr);	/* smb_kshare_t */
		mdb_printf("%-16s ", name);
		mdb_printf("%-s", path);
		mdb_printf("\n");
	}

	return (WALK_NEXT);
}

/*
 * ::smbshares
 *
 * dcmd - Print out smb_kshare structures.
 *	requires addr of an smb_server_t
 */
/*ARGSUSED*/
static int
smb_dcmd_kshare(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		opts = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, SMB_OPT_VERBOSE, &opts,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);
	addr += OFFSETOF(smb_server_t, sv_export.e_share_avl.avl_tree);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf(
		    "%<b>%<u>"
		    "%-?s "
		    "%-16s "
		    "%-s"
		    "%</u>%</b>\n",
		    "smb_kshare_t", "name", "path");
	}

	if (mdb_pwalk("genunix`avl", smb_kshare_cb, &opts, addr) == -1) {
		mdb_warn("cannot walk smb_kshare avl");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ******************************** smb_vfs_t **********************************
 * *****************************************************************************
 */

/*
 * ::smbvfs
 *
 * smbvfs dcmd - Prints out smb_vfs structures.
 */
/*ARGSUSED*/
static int
smb_dcmd_vfs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int		verbose = FALSE;
	smb_vfs_t	*sf;
	vnode_t		*vn;
	char		*path;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If no smb_vfs address was specified on the command line, we can
	 * print out all smb_vfs by invoking the smb_vfs walker, using
	 * this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("smbvfs_walker", "smbvfs",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'smb_vfs'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf(
		    "%<b>%<u>"
		    "%-?s "
		    "%-10s "
		    "%-16s "
		    "%-16s"
		    "%-s"
		    "%</u>%</b>\n",
		    "SMB_VFS", "REFCNT", "VFS", "VNODE", "ROOT");
	}

	sf = mdb_alloc(sizeof (*sf), UM_SLEEP | UM_GC);
	if (mdb_vread(sf, sizeof (*sf), addr) == -1) {
		mdb_warn("failed to read smb_vfs at %p", addr);
		return (DCMD_ERR);
	}

	vn = mdb_alloc(sizeof (*vn), UM_SLEEP | UM_GC);
	if (mdb_vread(vn, sizeof (*vn),
	    (uintptr_t)sf->sv_rootvp) == -1) {
		mdb_warn("failed to read vnode at %p", sf->sv_rootvp);
		return (DCMD_ERR);
	}

	path = mdb_zalloc(MAXPATHLEN, UM_SLEEP | UM_GC);
	(void) mdb_vread(path, MAXPATHLEN, (uintptr_t)vn->v_path);

	mdb_printf(
	    "%-?p %-10d %-?p %-?p %-s\n", addr, sf->sv_refcnt,
	    sf->sv_vfsp, sf->sv_rootvp, path);

	return (DCMD_OK);
}

/*
 * Initialize the smb_vfs_t walker to point to the smb_export
 * in the specified smb_server_t instance.  (no global walks)
 */
static int
smb_vfs_walk_init(mdb_walk_state_t *wsp)
{

	if (wsp->walk_addr == NULL) {
		mdb_printf("require address of an smb_server_t\n");
		return (WALK_ERR);
	}

	wsp->walk_addr +=
	    OFFSETOF(smb_server_t, sv_export.e_vfs_list.ll_list);

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("failed to walk list of VFS");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
smb_vfs_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * *****************************************************************************
 * ******************************* smb_node_t **********************************
 * *****************************************************************************
 */

static void
smb_node_help(void)
{
	mdb_printf(
	    "Display the contents of smb_node_t, with optional filtering.\n\n");
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf(
	    "-v\tDisplay verbose smb_node information\n"
	    "-p\tDisplay the full path of the vnode associated\n"
	    "-s\tDisplay the stack of the last 16 calls that modified the "
	    "reference\n\tcount\n");
}

/*
 * ::smbnode
 *
 * smb_node dcmd - Print out smb_node structure.
 */
static int
smb_dcmd_node(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_node_t	node;
	int		rc;
	int		verbose = FALSE;
	int		print_full_path = FALSE;
	int		stack_trace = FALSE;
	vnode_t		vnode;
	char		od_name[MAXNAMELEN];
	char		path_name[1024];
	uintptr_t	list_addr, oplock_addr;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'p', MDB_OPT_SETBITS, TRUE, &print_full_path,
	    's', MDB_OPT_SETBITS, TRUE, &stack_trace,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If no smb_node address was specified on the command line, we can
	 * print out all smb nodes by invoking the smb_node walker, using
	 * this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("smbnode_walker", "smbnode",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'smb_node'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose) {
			mdb_printf("%<b>%<u>SMB node information:%</u>%</b>\n");
		} else {
			mdb_printf(
			    "%<b>%<u>%-?s "
			    "%-?s "
			    "%-18s "
			    "%-6s "
			    "%-6s "
			    "%-8s "
			    "%-6s%</u>%</b>\n",
			    "ADDR", "VP", "NODE-NAME", "OFILES", "LOCKS",
			    "OPLOCK", "REF");
		}
	}

	/*
	 * For each smb_node, we just need to read the smb_node_t struct, read
	 * and then print out the following fields.
	 */
	if (mdb_vread(&node, sizeof (node), addr) == sizeof (node)) {
		(void) mdb_snprintf(od_name, sizeof (od_name), "%s",
		    node.od_name);
		if (print_full_path) {
			if (mdb_vread(&vnode, sizeof (vnode_t),
			    (uintptr_t)node.vp) == sizeof (vnode_t)) {
				if (mdb_readstr(path_name, sizeof (path_name),
				    (uintptr_t)vnode.v_path) != 0) {
					(void) mdb_snprintf(od_name,
					    sizeof (od_name), "N/A");
				}
			}
		}
		if (verbose) {
			mdb_printf("VP: %p\n", node.vp);
			mdb_printf("Name: %s\n", od_name);
			if (print_full_path)
				mdb_printf("V-node Path: %s\n", path_name);
			mdb_printf("Ofiles: %u\n", node.n_ofile_list.ll_count);
			mdb_printf("Range Locks: %u\n",
			    node.n_lock_list.ll_count);
			if (node.n_lock_list.ll_count != 0) {
				(void) mdb_inc_indent(SMB_DCMD_INDENT);
				list_addr = addr +
				    offsetof(smb_node_t, n_lock_list) +
				    offsetof(smb_llist_t, ll_list);
				if (mdb_pwalk_dcmd("list", "smblock", 0,
				    NULL, list_addr)) {
					mdb_warn("failed to walk node's active"
					    " locks");
				}
				(void) mdb_dec_indent(SMB_DCMD_INDENT);
			}
			if (node.n_oplock.ol_count == 0) {
				mdb_printf("Opportunistic Locks: 0\n");
			} else {
				oplock_addr =
				    addr + offsetof(smb_node_t, n_oplock);
				mdb_printf("Opportunistic Lock: %p\n",
				    oplock_addr);
				rc = mdb_call_dcmd("smboplock", oplock_addr,
				    flags, argc, argv);
				if (rc != DCMD_OK)
					return (rc);
			}
			mdb_printf("Reference Count: %u\n\n", node.n_refcnt);
		} else {
			mdb_printf("%-?p %-?p %-18s %-6d %-6d %-8d %-6d ",
			    addr, node.vp, od_name, node.n_ofile_list.ll_count,
			    node.n_lock_list.ll_count,
			    node.n_oplock.ol_count, node.n_refcnt);

			if (print_full_path)
				mdb_printf("\t%s\n", path_name);
		}
		if (stack_trace && node.n_audit_buf) {
			int ctr;
			smb_audit_buf_node_t *anb;

			anb = mdb_alloc(sizeof (smb_audit_buf_node_t),
			    UM_SLEEP | UM_GC);

			if (mdb_vread(anb, sizeof (*anb),
			    (uintptr_t)node.n_audit_buf) != sizeof (*anb)) {
				mdb_warn("failed to read audit buffer");
				return (DCMD_ERR);
			}
			ctr = anb->anb_max_index + 1;
			anb->anb_index--;
			anb->anb_index &= anb->anb_max_index;

			while (ctr) {
				smb_audit_record_node_t	*anr;

				anr = anb->anb_records + anb->anb_index;

				if (anr->anr_depth) {
					char c[MDB_SYM_NAMLEN];
					GElf_Sym sym;
					int i;

					mdb_printf("\nRefCnt: %u\t",
					    anr->anr_refcnt);

					for (i = 0;
					    i < anr->anr_depth;
					    i++) {
						if (mdb_lookup_by_addr(
						    anr->anr_stack[i],
						    MDB_SYM_FUZZY,
						    c, sizeof (c),
						    &sym) == -1) {
							continue;
						}
						mdb_printf("%s+0x%1x",
						    c,
						    anr->anr_stack[i] -
						    (uintptr_t)sym.st_value);
						++i;
						break;
					}

					while (i < anr->anr_depth) {
						if (mdb_lookup_by_addr(
						    anr->anr_stack[i],
						    MDB_SYM_FUZZY,
						    c, sizeof (c),
						    &sym) == -1) {
							++i;
							continue;
						}
						mdb_printf("\n\t\t%s+0x%1x",
						    c,
						    anr->anr_stack[i] -
						    (uintptr_t)sym.st_value);
						++i;
					}
					mdb_printf("\n");
				}
				anb->anb_index--;
				anb->anb_index &= anb->anb_max_index;
				ctr--;
			}
		}
	} else {
		mdb_warn("failed to read struct smb_node at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * Initialize the smb_node_t walker by reading the value of smb_node_hash_table
 * in the kernel's symbol table. Only global walk supported.
 */
static int
smb_node_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym	sym;
	int		i;
	uintptr_t	node_hash_table_addr;

	if (wsp->walk_addr == NULL) {
		if (mdb_lookup_by_name("smb_node_hash_table", &sym) == -1) {
			mdb_warn("failed to find 'smb_node_hash_table'");
			return (WALK_ERR);
		}
		node_hash_table_addr = (uintptr_t)sym.st_value;
	} else {
		mdb_printf("smb_node walk only supports global walks\n");
		return (WALK_ERR);
	}

	for (i = 0; i < SMBND_HASH_MASK + 1; i++) {
		wsp->walk_addr = node_hash_table_addr +
		    (i * sizeof (smb_llist_t)) + offsetof(smb_llist_t, ll_list);
		if (mdb_layered_walk("list", wsp) == -1) {
			mdb_warn("failed to walk 'list'");
			return (WALK_ERR);
		}
	}

	return (WALK_NEXT);
}

static int
smb_node_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * *****************************************************************************
 * ****************************** smb_lock_t ***********************************
 * *****************************************************************************
 */

static int
smb_lock(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_lock_t	lock;
	int		verbose = FALSE;
	uintptr_t	list_addr;
	char		*lock_type;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * An smb_lock_t address must be specified.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		if (verbose)
			mdb_printf("SMB lock information:\n\n");
		else
			mdb_printf("%<u>%-?s %4s %16s %8s %9s%</u>\n",
			    "Locks: ", "TYPE", "START", "LENGTH",
			    "CONFLICTS");
	}

	if (mdb_vread(&lock, sizeof (lock), addr) == sizeof (lock)) {
		switch (lock.l_type) {
		case SMB_LOCK_TYPE_READWRITE:
			lock_type = "RW";
			break;
		case SMB_LOCK_TYPE_READONLY:
			lock_type = "RO";
			break;
		default:
			lock_type = "N/A";
			break;
		}
		if (verbose) {
			mdb_printf("Type             :\t%s (%u)\n",
			    lock_type, lock.l_type);
			mdb_printf("Start            :\t%llx\n",
			    lock.l_start);
			mdb_printf("Length           :\t%lx\n",
			    lock.l_length);
			mdb_printf("Session          :\t%p\n",
			    lock.l_session);
			mdb_printf("File             :\t%p\n",
			    lock.l_file);
			mdb_printf("User ID          :\t%u\n",
			    lock.l_uid);
			mdb_printf("Process ID       :\t%u\n",
			    lock.l_pid);
			mdb_printf("Conflicts        :\t%u\n",
			    lock.l_conflict_list.sl_count);
			if (lock.l_conflict_list.sl_count != 0) {
				(void) mdb_inc_indent(SMB_DCMD_INDENT);
				list_addr = addr +
				    offsetof(smb_lock_t, l_conflict_list) +
				    offsetof(smb_slist_t, sl_list);
				if (mdb_pwalk_dcmd("list", "smb_lock",
				    0, NULL, list_addr)) {
					mdb_warn("failed to walk conflict "
					    "locks ");
				}
				(void) mdb_dec_indent(SMB_DCMD_INDENT);
			}
			mdb_printf("Blocked by       :\t%p\n",
			    lock.l_blocked_by);
			mdb_printf("Flags            :\t0x%x\n",
			    lock.l_flags);
			mdb_printf("\n");
		} else {
			mdb_printf("%?p %4s %16llx %08lx %9x", addr,
			    lock_type, lock.l_start, lock.l_length,
			    lock.l_conflict_list.sl_count);
		}
	} else {
		mdb_warn("failed to read struct smb_request at %p", addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ************************** smb_oplock_grant_t *******************************
 * *****************************************************************************
 */
/*ARGSUSED*/
static int
smb_oplock_grant(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_oplock_grant_t	grant;
	char			 *level;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-16s %-10s %-16s%</u>\n",
		    "Grants:", "LEVEL", "OFILE");
	}

	if (mdb_vread(&grant, sizeof (grant), addr) == sizeof (grant)) {
		switch (grant.og_level) {
		case SMB_OPLOCK_EXCLUSIVE:
			level = "EXCLUSIVE";
			break;
		case SMB_OPLOCK_BATCH:
			level = "BATCH";
			break;
		case SMB_OPLOCK_LEVEL_II:
			level = "LEVEL_II";
			break;
		default:
			level = "UNKNOWN";
			break;
		}

		mdb_printf("%-16p %-10s %-16p", addr, level, grant.og_ofile);
	}
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ***************************** smb_oplock_t **********************************
 * *****************************************************************************
 */
/*ARGSUSED*/
static int
smb_oplock(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_oplock_t	oplock;
	uintptr_t	list_addr;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&oplock, sizeof (oplock), addr) != sizeof (oplock)) {
		mdb_warn("failed to read struct smb_oplock at %p", addr);
		return (DCMD_ERR);
	}

	if (oplock.ol_count == 0)
		return (DCMD_OK);

	(void) mdb_inc_indent(SMB_DCMD_INDENT);
	switch (oplock.ol_break) {
	case SMB_OPLOCK_BREAK_TO_NONE:
		mdb_printf("Break Pending: BREAK_TO_NONE\n");
		break;
	case SMB_OPLOCK_BREAK_TO_LEVEL_II:
		mdb_printf(
		    "Break Pending: BREAK_TO_LEVEL_II\n");
		break;
	default:
		break;
	}

	list_addr = addr + offsetof(smb_oplock_t, ol_grants);

	if (mdb_pwalk_dcmd("list", "smboplockgrant",
	    argc, argv, list_addr)) {
		mdb_warn("failed to walk oplock grants");
	}

	(void) mdb_dec_indent(SMB_DCMD_INDENT);

	return (DCMD_OK);
}

/*
 * ::smbstat
 *
 * Prints SMB requests statistics.
 */
/*ARGSUSED*/
static int
smb_stats(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_server_t	*sv;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	sv = mdb_alloc(sizeof (*sv), UM_SLEEP | UM_GC);
	if (mdb_vread(sv, sizeof (*sv), addr) == -1) {
		mdb_warn("failed to read server object at %p", addr);
		return (DCMD_ERR);
	}
	if (sv->sv_magic != SMB_SERVER_MAGIC) {
		mdb_warn("not an smb_server_t (%p)>", addr);
		return (DCMD_ERR);
	}
	mdb_printf(
	    "\n%<b>  nbt   tcp users trees files pipes%</b>\n"
	    "%5d %5d %5d %5d %5d %5d\n",
	    sv->sv_nbt_sess,
	    sv->sv_tcp_sess,
	    sv->sv_users,
	    sv->sv_trees,
	    sv->sv_files,
	    sv->sv_pipes);

	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ******************************** smb_ace_t **********************************
 * *****************************************************************************
 */
static const ace_type_entry_t	ace_types[ACE_TYPE_TABLEN] =
{
	ACE_TYPE_ENTRY(ACE_ACCESS_ALLOWED_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_ACCESS_DENIED_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_SYSTEM_AUDIT_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_SYSTEM_ALARM_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_ACCESS_ALLOWED_COMPOUND_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_ACCESS_ALLOWED_OBJECT_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_ACCESS_DENIED_OBJECT_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_SYSTEM_AUDIT_OBJECT_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_SYSTEM_ALARM_OBJECT_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_ACCESS_ALLOWED_CALLBACK_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_ACCESS_DENIED_CALLBACK_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_SYSTEM_AUDIT_CALLBACK_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_SYSTEM_ALARM_CALLBACK_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE),
	ACE_TYPE_ENTRY(ACE_SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE),
	ACE_TYPE_ENTRY(0x11),
	ACE_TYPE_ENTRY(0x12),
	ACE_TYPE_ENTRY(0x13),
	ACE_TYPE_ENTRY(0x14),
	ACE_TYPE_ENTRY(0x15),
	ACE_TYPE_ENTRY(0x16),
	ACE_TYPE_ENTRY(0x17),
	ACE_TYPE_ENTRY(0x18),
	ACE_TYPE_ENTRY(0x19),
	ACE_TYPE_ENTRY(0x1A),
	ACE_TYPE_ENTRY(0x1B),
	ACE_TYPE_ENTRY(0x1C),
	ACE_TYPE_ENTRY(0x1D),
	ACE_TYPE_ENTRY(0x1E),
	ACE_TYPE_ENTRY(0x1F)
};

static const mdb_bitmask_t ace_flag_bits[] = {
	{ "OBJECT_INHERIT_ACE", OBJECT_INHERIT_ACE, OBJECT_INHERIT_ACE },
	{ "CONTAINER_INHERIT_ACE", CONTAINER_INHERIT_ACE,
	    CONTAINER_INHERIT_ACE },
	{ "NO_PROPOGATE_INHERIT_ACE", NO_PROPOGATE_INHERIT_ACE,
	    NO_PROPOGATE_INHERIT_ACE },
	{ "INHERIT_ONLY_ACE", INHERIT_ONLY_ACE, INHERIT_ONLY_ACE },
	{ "INHERITED_ACE", INHERITED_ACE, INHERITED_ACE },
	{ "SUCCESSFUL_ACCESS_ACE_FLAG", SUCCESSFUL_ACCESS_ACE_FLAG,
	    SUCCESSFUL_ACCESS_ACE_FLAG },
	{ "FAILED_ACCESS_ACE_FLAG", FAILED_ACCESS_ACE_FLAG,
	    FAILED_ACCESS_ACE_FLAG },
	{ NULL, 0, 0 }
};

/*
 * ::smbace
 */
static int
smb_ace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_ace_t	ace;
	int		verbose = FALSE;
	const char	*ptr;
	int		rc;

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * An smb_ace address is required.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&ace, sizeof (ace), addr) != sizeof (ace)) {
		mdb_warn("failed to read struct smb_ace at %p", addr);
		return (DCMD_ERR);
	}

	if (verbose) {
		if (ace.se_hdr.se_type < ACE_TYPE_TABLEN)
			ptr = ace_types[ace.se_hdr.se_type].ace_type_sting;
		else
			ptr = "Unknown";

		mdb_printf("ACE Type: 0x%02x (%s)\n", ace.se_hdr.se_type, ptr);
		mdb_printf("ACE Flags: %b\n", (int)ace.se_hdr.se_flags,
		    ace_flag_bits);
		mdb_printf("ACE Wire Size: 0x%04x\n", ace.se_hdr.se_bsize);
		mdb_printf("ACE Mask: 0x%08x\n", ace.se_mask);
		mdb_printf("ACE SID: ");
	} else {
		if (DCMD_HDRSPEC(flags))
			mdb_printf(
			    "%<b>%<u>%?-s %-4s %-4s %-8s %s%</u>%</b>\n",
			    "ACE", "TYPE", "FLAGS", "MASK", "SID");
		mdb_printf("%?p 0x%02x 0x%02x 0x%08x ", addr,
		    ace.se_hdr.se_type, ace.se_hdr.se_flags, ace.se_mask);
	}
	rc = smb_sid_print((uintptr_t)ace.se_sid);
	mdb_printf("\n");
	return (rc);
}

static int
smb_ace_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_printf("smb_ace walk only supports local walks\n");
		return (WALK_ERR);
	}

	wsp->walk_addr += offsetof(smb_acl_t, sl_sorted);

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("failed to walk list of ACEs");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
smb_ace_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * *****************************************************************************
 * ******************************** smb_acl_t **********************************
 * *****************************************************************************
 */

/*
 * ::smbacl
 */
static int
smb_acl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_acl_t	acl;

	/* An smb_acl address is required. */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&acl, sizeof (acl), addr) != sizeof (acl)) {
		mdb_warn("failed to read struct smb_acl at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("ACL Revision: %d\n", acl.sl_revision);
	mdb_printf("ACL Size on Wire: %d\n", acl.sl_bsize);
	mdb_printf("ACL Number of ACEs: %d\n", acl.sl_acecnt);

	(void) mdb_inc_indent(SMB_DCMD_INDENT);
	if (mdb_pwalk_dcmd("smbace_walker", "smbace", argc, argv, addr)) {
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
		mdb_warn("failed to walk list of ACEs for ACL %p", addr);
		return (DCMD_ERR);
	}
	(void) mdb_dec_indent(SMB_DCMD_INDENT);
	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ********************************* smb_sd_t **********************************
 * *****************************************************************************
 */

/*
 * ::smbsd
 */
static int
smb_sd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_sd_t	sd;
	int		rc;

	/*
	 * An smb_sid address is required.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&sd, sizeof (sd), addr) != sizeof (sd)) {
		mdb_warn("failed to read struct smb_sd at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("SD Revision: %d\n", sd.sd_revision);
	mdb_printf("SD Control: %04x\n", sd.sd_control);
	if (sd.sd_control & SE_OWNER_DEFAULTED)
		mdb_printf("\t    SE_OWNER_DEFAULTED\n");
	if (sd.sd_control & SE_GROUP_DEFAULTED)
		mdb_printf("\t    SE_GROUP_DEFAULTED\n");
	if (sd.sd_control & SE_DACL_PRESENT)
		mdb_printf("\t    SE_DACL_PRESENT\n");
	if (sd.sd_control & SE_DACL_DEFAULTED)
		mdb_printf("\t    SE_DACL_DEFAULTED\n");
	if (sd.sd_control & SE_SACL_PRESENT)
		mdb_printf("\t    SE_SACL_PRESENT\n");
	if (sd.sd_control & SE_SACL_DEFAULTED)
		mdb_printf("\t    SE_SACL_DEFAULTED\n");
	if (sd.sd_control & SE_DACL_AUTO_INHERIT_REQ)
		mdb_printf("\t    SE_DACL_AUTO_INHERIT_REQ\n");
	if (sd.sd_control & SE_SACL_AUTO_INHERIT_REQ)
		mdb_printf("\t    SE_SACL_AUTO_INHERIT_REQ\n");
	if (sd.sd_control & SE_DACL_AUTO_INHERITED)
		mdb_printf("\t    SE_DACL_AUTO_INHERITED\n");
	if (sd.sd_control & SE_SACL_AUTO_INHERITED)
		mdb_printf("\t    SE_SACL_AUTO_INHERITED\n");
	if (sd.sd_control & SE_DACL_PROTECTED)
		mdb_printf("\t    SE_DACL_PROTECTED\n");
	if (sd.sd_control & SE_SACL_PROTECTED)
		mdb_printf("\t    SE_SACL_PROTECTED\n");
	if (sd.sd_control & SE_SELF_RELATIVE)
		mdb_printf("\t    SE_SELF_RELATIVE\n");

	mdb_printf("SID of Owner: ");
	rc = smb_sid_print((uintptr_t)sd.sd_owner);
	if (rc != DCMD_OK)
		return (rc);
	mdb_printf("\nSID of Group: ");
	rc = smb_sid_print((uintptr_t)sd.sd_group);
	if (rc != DCMD_OK)
		return (rc);
	mdb_printf("\n");

	if (sd.sd_control & SE_SACL_PRESENT && sd.sd_sacl) {
		mdb_printf("%<b>%<u>System ACL%</u>%</b>\n");
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		rc = mdb_call_dcmd("smbacl", (uintptr_t)sd.sd_sacl, flags,
		    argc, argv);
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
		if (rc != DCMD_OK)
			return (rc);
	}
	if (sd.sd_control & SE_DACL_PRESENT && sd.sd_dacl) {
		mdb_printf("%<b>%<u>Discretionary ACL%</u>%</b>\n");
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		rc = mdb_call_dcmd("smbacl", (uintptr_t)sd.sd_dacl, flags,
		    argc, argv);
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
		if (rc != DCMD_OK)
			return (rc);
	}

	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ********************************* smb_sid_t *********************************
 * *****************************************************************************
 */

/*
 * ::smbsid
 */
/*ARGSUSED*/
static int
smb_sid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	/*
	 * An smb_sid address is required.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	return (smb_sid_print(addr));
}

/*
 * smb_sid_print
 */
static int
smb_sid_print(uintptr_t addr)
{
	smb_sid_t	sid;
	smb_sid_t	*psid;
	size_t		sid_size;
	int		i;
	uint64_t	authority;

	sid_size = offsetof(smb_sid_t, sid_subauth);

	if (mdb_vread(&sid, sid_size, addr) != sid_size) {
		mdb_warn("failed to read struct smb_sid at %p", addr);
		return (DCMD_ERR);
	}

	sid_size += sid.sid_subauthcnt * sizeof (sid.sid_subauth[0]);

	psid = mdb_zalloc(sid_size, UM_SLEEP | UM_GC);
	if (mdb_vread(psid, sid_size, addr) != sid_size) {
		mdb_warn("failed to read struct smb_sid at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("S-%d", psid->sid_revision);
	authority = 0;
	for (i = 0; i < NT_SID_AUTH_MAX; i++) {
		authority += ((uint64_t)psid->sid_authority[i]) <<
		    (8 * (NT_SID_AUTH_MAX - 1) - i);
	}
	mdb_printf("-%ll", authority);

	for (i = 0; i < psid->sid_subauthcnt; i++)
		mdb_printf("-%d", psid->sid_subauth[i]);

	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * ********************************* smb_fssd_t ********************************
 * *****************************************************************************
 */

/*
 * ::smbfssd
 */
static int
smb_fssd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	smb_fssd_t	fssd;
	int		rc;

	/*
	 * An smb_fssd address is required.
	 */
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&fssd, sizeof (fssd), addr) != sizeof (fssd)) {
		mdb_warn("failed to read struct smb_fssd at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("FSSD secinfo: 0x%x\n", fssd.sd_secinfo);
	if (fssd.sd_secinfo & SMB_OWNER_SECINFO)
		mdb_printf("FSSD uid: %d\n", fssd.sd_uid);
	if (fssd.sd_secinfo & SMB_GROUP_SECINFO)
		mdb_printf("FSSD gid: %d\n", fssd.sd_gid);
	if (fssd.sd_secinfo & SMB_SACL_SECINFO && fssd.sd_zsacl) {
		mdb_printf("%<b>%<u>System ACL%</u>%</b>\n");
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		rc = mdb_call_dcmd("smbacl", (uintptr_t)fssd.sd_zsacl, flags,
		    argc, argv);
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
		if (rc != DCMD_OK)
			return (rc);
	}
	if (fssd.sd_secinfo & SMB_DACL_SECINFO && fssd.sd_zdacl) {
		mdb_printf("%<b>%<u>Discretionary ACL%</u>%</b>\n");
		(void) mdb_inc_indent(SMB_DCMD_INDENT);
		rc = mdb_call_dcmd("smbacl", (uintptr_t)fssd.sd_zdacl, flags,
		    argc, argv);
		(void) mdb_dec_indent(SMB_DCMD_INDENT);
		if (rc != DCMD_OK)
			return (rc);
	}

	return (DCMD_OK);
}

/*
 * *****************************************************************************
 * **************************** Utility Funcions *******************************
 * *****************************************************************************
 */

/*
 * smb_dcmd_getopt
 *
 * This function analyzes the arguments passed in and sets the bit corresponding
 * to the options found in the opts variable.
 *
 * Return Value
 *
 *	-1	An error occured during the decoding
 *	0	The decoding was successful
 */
static int
smb_dcmd_getopt(uint_t *opts, int argc, const mdb_arg_t *argv)
{
	*opts = 0;

	if (mdb_getopts(argc, argv,
	    's', MDB_OPT_SETBITS, SMB_OPT_SERVER, opts,
	    'e', MDB_OPT_SETBITS, SMB_OPT_SESSION, opts,
	    'r', MDB_OPT_SETBITS, SMB_OPT_REQUEST, opts,
	    'u', MDB_OPT_SETBITS, SMB_OPT_USER, opts,
	    't', MDB_OPT_SETBITS, SMB_OPT_TREE, opts,
	    'f', MDB_OPT_SETBITS, SMB_OPT_OFILE, opts,
	    'd', MDB_OPT_SETBITS, SMB_OPT_ODIR, opts,
	    'w', MDB_OPT_SETBITS, SMB_OPT_WALK, opts,
	    'v', MDB_OPT_SETBITS, SMB_OPT_VERBOSE, opts,
	    NULL) != argc)
		return (-1);

	return (0);
}

/*
 * smb_dcmd_setopt
 *
 * This function set the arguments corresponding to the bits set in opts.
 *
 * Return Value
 *
 *	Number of arguments set.
 */
static int
smb_dcmd_setopt(uint_t opts, int max_argc, mdb_arg_t *argv)
{
	int	i;
	int	argc = 0;

	for (i = 0; i < SMB_MDB_MAX_OPTS; i++) {
		if ((opts & smb_opts[i].o_value) && (argc < max_argc)) {
			argv->a_type = MDB_TYPE_STRING;
			argv->a_un.a_str = smb_opts[i].o_name;
			argc++;
			argv++;
		}
	}
	return (argc);
}

/*
 * smb_obj_expand
 */
static int
smb_obj_expand(uintptr_t addr, uint_t opts, const smb_exp_t *x, ulong_t indent)
{
	int		rc = 0;
	int		argc;
	mdb_arg_t	argv[SMB_MDB_MAX_OPTS];

	argc = smb_dcmd_setopt(opts | SMB_OPT_WALK, SMB_MDB_MAX_OPTS, argv);

	(void) mdb_inc_indent(indent);
	while (x->ex_dcmd) {
		if (x->ex_mask & opts) {
			rc = mdb_pwalk_dcmd("list", x->ex_dcmd, argc, argv,
			    addr + x->ex_offset);

			if (rc) {
				mdb_warn("failed to walk the list of %s in %p",
				    x->ex_name, addr + x->ex_offset);
				break;
			}
		}
		x++;
	}
	(void) mdb_dec_indent(indent);
	return (rc);
}

/*
 * smb_obj_list
 *
 * Function called by the DCMDs when no address is provided. It expands the
 * tree under the object type associated with the calling DCMD (based on the
 * flags passed in).
 *
 * Return Value
 *
 *	DCMD_OK
 *	DCMD_ERR
 */
static int
smb_obj_list(const char *name, uint_t opts, uint_t flags)
{
	int		argc;
	mdb_arg_t	argv[SMB_MDB_MAX_OPTS];

	argc = smb_dcmd_setopt(opts, SMB_MDB_MAX_OPTS, argv);

	if (mdb_call_dcmd("smblist", 0, flags, argc, argv)) {
		mdb_warn("failed to list %s", name);
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

static int
smb_worker_findstack(uintptr_t addr)
{
	kthread_t	t;
	taskq_t		tq;
	char		cmd[80];
	mdb_arg_t	cmdarg;

	if (mdb_vread(&t, sizeof (kthread_t), addr) == -1) {
		mdb_warn("failed to read kthread_t at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&tq, sizeof (taskq_t), (uintptr_t)t.t_taskq) == -1)
		tq.tq_name[0] = '\0';

	mdb_inc_indent(2);

	mdb_printf("PC: %a", t.t_pc);
	if (t.t_tid == 0) {
		if (tq.tq_name[0] != '\0')
			mdb_printf("    TASKQ: %s\n", tq.tq_name);
		else
			mdb_printf("    THREAD: %a()\n", t.t_startpc);
	}

	mdb_snprintf(cmd, sizeof (cmd), "<.$c%d", 16);
	cmdarg.a_type = MDB_TYPE_STRING;
	cmdarg.a_un.a_str = cmd;
	(void) mdb_call_dcmd("findstack", addr, DCMD_ADDRSPEC, 1, &cmdarg);
	mdb_dec_indent(2);
	mdb_printf("\n");
	return (DCMD_OK);
}
