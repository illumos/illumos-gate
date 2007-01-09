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
%/*
% * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% */
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
%#include <sys/vfs.h>
%#include <sys/dirent.h>
%#include <sys/types.h>
%#include <sys/types32.h>
%
%#define	xdr_dev_t xdr_u_int
%#define	xdr_bool_t xdr_bool
%
/*
 * Autofs/automountd communication protocol.
 */

const AUTOFS_MAXPATHLEN		= 1024;
const AUTOFS_MAXCOMPONENTLEN	= 255;
const AUTOFS_MAXOPTSLEN		= 1024;
const AUTOFS_DAEMONCOOKIE	= 100000;

/*
 * Action Status
 * Automountd replies to autofs indicating whether the operation is done,
 * or further action needs to be taken by autofs.
 */
enum autofs_stat {
	AUTOFS_ACTION=0,	/* list of actions included */
	AUTOFS_DONE=1		/* no further action required by kernel */
};

/*
 * Used by autofs to either create a link, or mount a new filesystem.
 */
enum autofs_action {
	AUTOFS_MOUNT_RQ=0,	/* mount request */
	AUTOFS_LINK_RQ=1,	/* link create */
	AUTOFS_NONE=2		/* no action */
};

enum autofs_res {
	AUTOFS_OK=0,
	AUTOFS_NOENT=2,
	AUTOFS_ECOMM=5,
	AUTOFS_NOMEM=12,
	AUTOFS_NOTDIR=20,
	AUTOFS_SHUTDOWN=1000
};

/*
 * Lookup/Mount request.
 * Argument structure passed to both autofs_lookup() and autofs_mount().
 * autofs_lookup():
 *	Query automountd if 'path/subdir/name' exists in 'map'
 * autofs_mount():
 *	Request automountd to mount the map entry associated with
 *	'path/subdir/name' in 'map' given 'opts' options.
 */
struct autofs_lookupargs {
	string	map<AUTOFS_MAXPATHLEN>;		/* context or map name */
	string	path<AUTOFS_MAXPATHLEN>;	/* mountpoint */
	string	name<AUTOFS_MAXCOMPONENTLEN>;	/* entry we're looking for */
	string	subdir<AUTOFS_MAXPATHLEN>;	/* subdir within map */
	string	opts<AUTOFS_MAXOPTSLEN>;
	bool_t	isdirect;			/* direct mountpoint? */
	uid_t	uid;				/* uid of caller */
};

/*
 * Symbolic link information.
 */
struct linka {
	string	dir<AUTOFS_MAXPATHLEN>;		/* original name */
	string	link<AUTOFS_MAXPATHLEN>;	/* link (new) name */
};

/*
 * We don't define netbuf in RPCL, we include the header file that
 * includes it, and implement the xdr function ourselves.
 */

/*
 * Autofs Mount specific information - used to mount a new
 * autofs filesystem.
 */
struct autofs_args {
	struct netbuf	addr;		/* daemon address */
	string path<AUTOFS_MAXPATHLEN>;	/* autofs mountpoint */
	string opts<AUTOFS_MAXOPTSLEN>;	/* default mount options */
	string map<AUTOFS_MAXPATHLEN>;	/* name of map */
	string subdir<AUTOFS_MAXPATHLEN>; /* subdir within map */
	string key<AUTOFS_MAXCOMPONENTLEN>; /* used in direct mounts only */
	int		mount_to;	/* time in sec the fs is to remain */
					/* mounted after last reference */
	int		rpc_to;		/* timeout for rpc calls */
	int		direct;		/* 1 = direct mount */
};

%#ifdef _SYSCALL32
%/*
% * This is an LP64 representation of the ILP32 autofs_args data structure
% * for use by autofs_mount which may receive the data structure "raw"
% * from a 32-bit program without being processed by XDR.  rpcgen doesn't
% * need to see this structure since RPC/XDR only deals with the "native"
% * version of autofs_args.  If this isn't hidden from rpcgen then it will
% * insist on generating unnecessary code to deal with it.
% */
%struct autofs_args32 {
%	struct netbuf32	addr;		/* daemon address */
%	caddr32_t	path;		/* autofs mountpoint */
%	caddr32_t	opts;		/* default mount options */
%	caddr32_t	map;		/* name of map */
%	caddr32_t	subdir;		/* subdir within map */
%	caddr32_t	key;		/* used in direct mounts */
%	int32_t		mount_to;	/* time in sec the fs is to remain */
%					/* mounted after last reference */
%	int32_t		rpc_to;		/* timeout for rpc calls */
%	int32_t		direct;		/* 1 = direct mount */
%};
%#endif	/* _SYSCALL32 */

/*
 * Contains the necessary information to notify autofs to
 * perfom either a new mount or create a symbolic link.
 */
union action_list_entry switch (autofs_action action) {
case AUTOFS_MOUNT_RQ:
	struct mounta mounta;
case AUTOFS_LINK_RQ:
	struct linka linka;
default:
	void;
};

/*
 * List of actions that need to be performed by autofs to
 * finish the requested operation.
 */
struct action_list {
	action_list_entry action;
	action_list *next;
};

union mount_result_type switch (autofs_stat status) {
case AUTOFS_ACTION:
	action_list *list;
case AUTOFS_DONE:
	int error;
default:
	void;
};

/*
 * Result from mount operation.
 */
struct autofs_mountres {
	mount_result_type mr_type;
	int mr_verbose;
};

union lookup_result_type switch (autofs_action action) {
case AUTOFS_LINK_RQ:
	struct linka lt_linka;
case AUTOFS_MOUNT_RQ:
	void;
default:
	void;
};

/*
 * Result from lookup operation.
 */
struct autofs_lookupres {
	enum autofs_res lu_res;
	lookup_result_type lu_type;
	int lu_verbose;
};

/*
 * Unmount operation request
 * Automountd will issue unmount system call for the
 * given fstype on the given mntpnt.
 */

struct umntrequest {
	bool_t isdirect;			/* direct mount? */
	string mntresource<AUTOFS_MAXPATHLEN>;	/* mntpnt source */
	string mntpnt<AUTOFS_MAXPATHLEN>;	/* mntpnt to unmount */
	string fstype<AUTOFS_MAXCOMPONENTLEN>;	/* filesystem type to umount */
	string mntopts<AUTOFS_MAXOPTSLEN>;	/* mntpnt options */
	struct umntrequest *next;		/* next unmount */
};

/*
 * Unmount operation result
 * status = 0 if unmount was successful,
 * otherwise status = errno.
 */
struct umntres {
	int status;
};

/*
 * AUTOFS readdir request
 * Request list of entries in 'rda_map' map starting at the given
 * offset 'rda_offset', for 'rda_count' bytes.
 */
struct autofs_rddirargs {
	string	rda_map<AUTOFS_MAXPATHLEN>;
	u_int	rda_offset;		/* starting offset */
	u_int	rda_count;		/* total size requested */
	uid_t	uid;			/* uid of caller */
};

struct autofsrddir {
	u_int	rddir_offset;		/* last offset in list */
	u_int	rddir_size;		/* size in bytes of entries */
	bool_t	rddir_eof;		/* TRUE if last entry in result */
	struct dirent64 *rddir_entries;	/* variable number of entries */
};

/*
 * AUTOFS readdir result.
 */
struct autofs_rddirres {
	enum autofs_res rd_status;
	u_int rd_bufsize;		/* autofs request size (not xdr'ed) */
	struct autofsrddir rd_rddir;
};
