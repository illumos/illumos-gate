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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AUTH_H
#define	_AUTH_H

/*
 * nfsauth_prot.x (The NFSAUTH Protocol)
 *
 * This protocol is used by the kernel to authorize NFS clients. This svc
 * lives in the mount daemon and checks the client's access for an export
 * with a given authentication flavor.
 *
 * The status result determines what kind of access the client is permitted.
 *
 * The result is cached in the kernel, so the authorization call will be
 * made only the first time the client mounts the filesystem.
 *
 * const A_MAXPATH	= 1024;
 *
 * struct auth_req {
 * 	netobj 	req_client;		# client's address
 * 	string	req_netid<>;		# Netid of address
 * 	string	req_path<A_MAXPATH>;	# export path
 * 	int	req_flavor;		# auth flavor
 *	uid_t	req_clnt_uid;		# client's uid
 *	gid_t	req_clnt_gid;		# client's gid
 *	gid_t	req_clnt_gids<>;	# client's supplemental groups
 * };
 *
 * const NFSAUTH_DENIED	  = 0x01;	# Access denied
 * const NFSAUTH_RO	  = 0x02;	# Read-only
 * const NFSAUTH_RW	  = 0x04;	# Read-write
 * const NFSAUTH_ROOT	  = 0x08;	# Root access
 * const NFSAUTH_WRONGSEC = 0x10;	# Advise NFS v4 clients to
 * 					# try a different flavor
 * const NFSAUTH_UIDMAP   = 0x100;	# uid mapped
 * const NFSAUTH_GIDMAP   = 0x200;	# gid mapped
 * const NFSAUTH_GROUPS   = 0x400;	# translated supplemental groups
 * #
 * # The following are not part of the protocol.
 * #
 * const NFSAUTH_DROP	 = 0x20;	# Drop request
 * const NFSAUTH_MAPNONE = 0x40;	# Mapped flavor to AUTH_NONE
 * const NFSAUTH_LIMITED = 0x80;	# Access limited to visible nodes
 *
 * struct auth_res {
 * 	int	auth_perm;
 *	uid_t	auth_srv_uid;		# translated uid
 *	gid_t	auth_srv_gid;		# translated gid
 *	gid_t	auth_srv_gids<>;	# translated supplemental groups
 * };
 *
 * program NFSAUTH_PROG {
 * 	version NFSAUTH_VERS {
 *		#
 *		# Authorization Request
 *		#
 * 		auth_res
 * 		NFSAUTH_ACCESS(auth_req) = 1;
 *
 * 	} = 1;
 * } = 100231;
 */

#ifndef _KERNEL
#include <stddef.h>
#endif
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <rpc/xdr.h>

#ifdef	__cplusplus
extern "C" {
#endif


/* --8<-- Start: nfsauth_prot.x definitions --8<-- */

#define	A_MAXPATH		1024

#define	NFSAUTH_ACCESS		1

#define	NFSAUTH_DENIED		0x01
#define	NFSAUTH_RO		0x02
#define	NFSAUTH_RW		0x04
#define	NFSAUTH_ROOT		0x08
#define	NFSAUTH_WRONGSEC	0x10
#define	NFSAUTH_DROP		0x20
#define	NFSAUTH_MAPNONE		0x40
#define	NFSAUTH_LIMITED		0x80
#define	NFSAUTH_UIDMAP		0x100
#define	NFSAUTH_GIDMAP		0x200
#define	NFSAUTH_GROUPS		0x400

struct auth_req {
	netobj	 req_client;
	char	*req_netid;
	char	*req_path;
	int	 req_flavor;
	uid_t	 req_clnt_uid;
	gid_t	 req_clnt_gid;
	struct {
		uint_t	len;
		gid_t	*val;
	} req_clnt_gids;
};
typedef struct auth_req auth_req;

struct auth_res {
	int	auth_perm;
	uid_t	auth_srv_uid;
	gid_t	auth_srv_gid;
	struct {
		uint_t	len;
		gid_t	*val;
	} auth_srv_gids;
};
typedef struct auth_res auth_res;

/* --8<-- End: nfsauth_prot.x definitions --8<-- */


#define	NFSAUTH_DR_OKAY		0x0	/* success */
#define	NFSAUTH_DR_BADCMD	0x100	/* NFSAUTH_ACCESS is only cmd allowed */
#define	NFSAUTH_DR_DECERR	0x200	/* mountd could not decode arguments */
#define	NFSAUTH_DR_EFAIL	0x400	/* mountd could not encode results */
#define	NFSAUTH_DR_TRYCNT	5	/* door handle acquisition retry cnt */

#if defined(DEBUG) && !defined(_KERNEL)
#define	MOUNTD_DOOR		"/var/run/mountd_door"
#endif

/*
 * Only cmd is added to the args. We need to know "what" we want
 * the daemon to do for us. Also, 'stat' returns the status from
 * the daemon down to the kernel in addition to perms.
 */
struct nfsauth_arg {
	uint_t		cmd;
	auth_req	areq;
};
typedef struct nfsauth_arg nfsauth_arg_t;

struct nfsauth_res {
	uint_t		stat;
	auth_res	ares;
};
typedef struct nfsauth_res nfsauth_res_t;

/*
 * For future extensibility, we version the data structures so
 * future incantations of mountd(1m) will know how to XDR decode
 * the arguments.
 */
enum vtypes {
	V_ERROR = 0,
	V_PROTO = 1
};
typedef enum vtypes vtypes;

typedef struct varg {
	uint_t	vers;
	union {
		nfsauth_arg_t	arg;
		/* additional args versions go here */
	} arg_u;
} varg_t;

extern bool_t	xdr_varg(XDR *, varg_t *);
extern bool_t	xdr_nfsauth_arg(XDR *, nfsauth_arg_t *);
extern bool_t	xdr_nfsauth_res(XDR *, nfsauth_res_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _AUTH_H */
