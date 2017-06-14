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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_NFS_NFSSYS_H
#define	_NFS_NFSSYS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Private definitions for the nfssys system call.
 * Note: <nfs/export.h> and <nfs/nfs.h> must be included before
 * this file.
 */

/*
 * Flavors of nfssys call.  Note that OLD_mumble commands are no longer
 * implemented, but the entries are kept as placeholders for binary
 * compatibility.
 */
enum nfssys_op	{ OLD_NFS_SVC, OLD_ASYNC_DAEMON, EXPORTFS, OLD_NFS_GETFH,
    OLD_NFS_CNVT, NFS_REVAUTH, OLD_NFS_FH_TO_FID, OLD_LM_SVC, KILL_LOCKMGR,
    LOG_FLUSH, SVCPOOL_CREATE, NFS_SVC, LM_SVC, SVCPOOL_WAIT, SVCPOOL_RUN,
    NFS4_SVC, RDMA_SVC_INIT, NFS4_CLR_STATE, NFS_IDMAP,
    NFS4_SVC_REQUEST_QUIESCE, NFS_GETFH, NFS4_DSS_SETPATHS,
    NFS4_DSS_SETPATHS_SIZE, NFS4_EPHEMERAL_MOUNT_TO, MOUNTD_ARGS,
    NFSCMD_ARGS };

struct nfs_svc_args {
	int		fd;		/* Connection endpoint */
	char		*netid;		/* Identify transport */
	struct netbuf	addrmask;	/* Address mask for host */
	int		versmin;	/* Min protocol version to offer */
	int		versmax;	/* Max protocol version to offer */
	int		delegation;	/* NFSv4 delegation on/off? */
};

#ifdef _SYSCALL32
struct nfs_svc_args32 {
	int32_t		fd;		/* Connection endpoint */
	caddr32_t	netid;		/* Identify transport */
	struct netbuf32	addrmask;	/* Address mask for host */
	int32_t		versmin;	/* Min protocol version to offer */
	int32_t		versmax;	/* Max protocol version to offer */
	int32_t		delegation;	/* NFSv4 delegation on/off? */
};
#endif

struct exportfs_args {
	char		*dname;
	struct exportdata *uex;
};

#ifdef _SYSCALL32
struct exportfs_args32 {
	caddr32_t	dname;
	caddr32_t	uex;
};
#endif

struct nfs_getfh_args {
	char		*fname;
	int		vers;
	int		*lenp;
	char		*fhp;
};

#ifdef _SYSCALL32
struct nfs_getfh_args32 {
	caddr32_t	fname;
	int32_t		vers;
	caddr32_t	lenp;
	caddr32_t	fhp;
};
#endif

struct nfs_revauth_args {
	int		authtype;
	uid_t		uid;
};

#ifdef _SYSCALL32
struct nfs_revauth_args32 {
	int32_t		authtype;
	uid32_t		uid;
};
#endif

/*
 * Arguments for establishing lock manager service.  If you change
 * lm_svc_args, you should increment the version number.  Try to keep
 * supporting one or more old versions of the args, so that old lockd's
 * will work with new kernels.
 */

enum lm_fmly  { LM_INET, LM_INET6, LM_LOOPBACK };
enum lm_proto { LM_TCP, LM_UDP };

struct lm_svc_args {
	int		version;	/* keep this first */
	int		fd;
	enum lm_fmly	n_fmly;		/* protocol family */
	enum lm_proto	n_proto;	/* protocol */
	dev_t		n_rdev;		/* device ID */
	int		debug;		/* debugging level */
	time_t		timout;		/* client handle life (asynch RPCs) */
	int		grace;		/* secs in grace period */
	time_t	retransmittimeout;	/* retransmission interval */
};

#ifdef _SYSCALL32
struct lm_svc_args32 {
	int32_t		version;	/* keep this first */
	int32_t		fd;
	enum lm_fmly	n_fmly;		/* protocol family */
	enum lm_proto	n_proto;	/* protocol */
	dev32_t		n_rdev;		/* device ID */
	int32_t		debug;		/* debugging level */
	time32_t	timout;		/* client handle life (asynch RPCs) */
	int32_t		grace;		/* secs in grace period */
	time32_t	retransmittimeout;	/* retransmission interval */
};
#endif

#define	LM_SVC_CUR_VERS	30		/* current lm_svc_args vers num */

/*
 * Arguments for nfslog flush service.
 */
struct nfsl_flush_args {
	int		version;
	int		directive;
	char		*buff;		/* buffer to flush/rename */
	int		buff_len;	/* includes terminating '\0' */
};

#define	NFSL_FLUSH_ARGS_VERS 1		/* current nfsl_flush_args vers num */

#ifdef _SYSCALL32
struct nfsl_flush_args32 {
	int32_t		version;
	int32_t		directive;
	caddr32_t	buff;		/* buffer to flush/rename */
	int32_t		buff_len;	/* includes terminating '\0' */
};
#endif

/*
 * Arguments for initialising RDMA service.
 */
struct rdma_svc_args {
	uint32_t	poolid;		/* Thread Pool ID */
	char		*netid;		/* Network Identifier */
	int		nfs_versmin;	/* Min NFS version to offer */
	int		nfs_versmax;	/* Max NFS version to offer */
	int		delegation;	/* NFSv4 delegation on/off? */
};

#ifdef _SYSCALL32
struct rdma_svc_args32 {
	uint32_t	poolid;		/* Thread Pool ID */
	caddr32_t	netid;		/* Network Identifier */
	int32_t		nfs_versmin;	/* Min NFS version to offer */
	int32_t		nfs_versmax;	/* Max NFS version to offer */
	int32_t		delegation;	/* NFSv4 delegation on/off? */
};
#endif


#define	NFS4_CLRST_VERSION	1
struct nfs4clrst_args {
	int		vers;
	int		addr_type;
	void		*ap;
};

#ifdef _SYSCALL32
struct nfs4clrst_args32 {
	int32_t		vers;
	int32_t		addr_type;
	caddr32_t	ap;
};
#endif

struct nfsidmap_args {
	uint_t		state;	/* Flushes caches, set state up 1 or down 0 */
	uint_t		did;	/* Door id to upcall */
};

#define	NFSL_ALL	0x01		/* Flush all buffers */
#define	NFSL_RENAME	0x02		/* Rename buffer(s) */
#define	NFSL_SYNC	0x04		/* Perform operation synchronously? */

#ifdef _KERNEL
union nfssysargs {
	struct exportfs_args	*exportfs_args_u;	/* exportfs args */
	struct nfs_getfh_args	*nfs_getfh_args_u;	/* nfs_getfh args */
	struct nfs_svc_args	*nfs_svc_args_u;	/* nfs_svc args */
	struct rdma_svc_args	*rdma_svc_args_u;	/* rdma_svc args */
	struct nfs_revauth_args	*nfs_revauth_args_u;	/* nfs_revauth args */
	struct lm_svc_args	*lm_svc_args_u;		/* lm_svc args */
	/* kill_lockmgr args: none */
	struct nfsl_flush_args	*nfsl_flush_args_u;	/* nfsl_flush args */
	struct svcpool_args	*svcpool_args_u;	/* svcpool args */
	struct nfs4clrst_args   *nfs4clrst_u;		/* nfs4 clear state */
	struct nfsidmap_args	*nfsidmap_u;		/* nfsidmap */
};

struct nfssysa {
	enum nfssys_op		opcode;	/* operation discriminator */
	union nfssysargs	arg;	/* syscall-specific arg pointer */
};
#define	nfssysarg_exportfs	arg.exportfs_args_u
#define	nfssysarg_getfh		arg.nfs_getfh_args_u
#define	nfssysarg_svc		arg.nfs_svc_args_u
#define	nfssysarg_rdmastart	arg.rdma_svc_args_u
#define	nfssysarg_revauth	arg.nfs_revauth_args_u
#define	nfssysarg_lmsvc		arg.lm_svc_args_u
#define	nfssysarg_nfslflush	arg.nfsl_flush_args_u
#define	nfssysarg_svcpool	arg.svcpool_args_u
#define	nfssysarg_nfs4clrst	arg.nfs4clrst_u
#define	nfssysarg_nfsidmap	arg.nfsidmap_u

#ifdef _SYSCALL32
union nfssysargs32 {
	caddr32_t exportfs_args_u;	/* exportfs args */
	caddr32_t nfs_getfh_args_u;	/* nfs_getfh args */
	caddr32_t nfs_svc_args_u;	/* nfs_svc args */
	caddr32_t rdma_svc_args_u;	/* rdma_start args */
	caddr32_t nfs_revauth_args_u;	/* nfs_revauth args */
	caddr32_t lm_svc_args_u;	/* lm_svc args */
	/* kill_lockmgr args: none */
	caddr32_t nfsl_flush_args_u;	/* nfsl_flush args */
	caddr32_t svcpool_args_u;
	caddr32_t nfs4clrst_u;
};
struct nfssysa32 {
	enum nfssys_op		opcode;	/* operation discriminator */
	union nfssysargs32	arg;	/* syscall-specific arg pointer */
};
#endif /* _SYSCALL32 */

#endif	/* _KERNEL */

struct nfs4_svc_args {
	int		fd;		/* Connection endpoint */
	int		cmd;
	char		*netid;		/* Transport Identifier */
	char		*addr;		/* Universal Address */
	char		*protofmly;	/* Protocol Family */
	char		*proto;		/* Protocol, eg. "tcp" */
	struct netbuf	addrmask;	/* Address mask for host */
};

#ifdef _SYSCALL32
struct nfs4_svc_args32 {
	int32_t		fd;
	int32_t		cmd;
	caddr32_t	netid;
	caddr32_t	addr;
	caddr32_t	protofmly;
	caddr32_t	proto;
	struct netbuf32	addrmask;
};
#endif

#define	NFS4_KRPC_START	1
#define	NFS4_SETPORT	2
#define	NFS4_DQUERY	4

/* DSS: distributed stable storage */
#define	NFS4_DSS_STATE_LEAF	"v4_state"
#define	NFS4_DSS_OLDSTATE_LEAF	"v4_oldstate"
#define	NFS4_DSS_DIR_MODE	0755
#define	NFS4_DSS_NVPAIR_NAME	"dss_pathname_array"
/* default storage dir */
#define	NFS4_DSS_VAR_DIR	"/var/nfs"

#ifdef _KERNEL

#include <sys/systm.h>		/* for rval_t typedef */

extern int	nfssys(enum nfssys_op opcode, void *arg);
extern int	exportfs(struct exportfs_args *, model_t, cred_t *);
extern int	nfs_getfh(struct nfs_getfh_args *, model_t, cred_t *);
extern int	nfs_svc(struct nfs_svc_args *, model_t);
extern int	lm_svc(struct lm_svc_args *uap);
extern int	lm_shutdown(void);
extern int	nfsl_flush(struct nfsl_flush_args *, model_t);
extern int	nfs4_svc(struct nfs4_svc_args *, model_t);
extern int 	rdma_start(struct rdma_svc_args *);
extern void	rfs4_clear_client_state(struct nfs4clrst_args *);
extern void	nfs_idmap_args(struct nfsidmap_args *);
extern void	nfs4_ephemeral_set_mount_to(uint_t);
extern void	mountd_args(uint_t);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_NFSSYS_H */
