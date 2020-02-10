/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2018 Nexenta Systems, Inc.
 */

#ifndef	_NFS_LOG_H
#define	_NFS_LOG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <rpc/rpc.h>

#define	LOG_MODE		0600	/* open log with these permissions */
#define	LOG_INPROG_STRING	"_log_in_process"

/*
 * Definition of dummy program for logging special non-nfs reqs
 */
#define	NFSLOG_PROGRAM		((rpcprog_t)42)
#define	NFSLOG_VERSION		((rpcvers_t)1)

#define	NFSLOG_VERSMIN		((rpcvers_t)1)
#define	NFSLOG_VERSMAX		((rpcvers_t)1)

#define	NFSLOG_NULL		((rpcproc_t)0)
#define	NFSLOG_SHARE		((rpcproc_t)1)
#define	NFSLOG_UNSHARE		((rpcproc_t)2)
#define	NFSLOG_LOOKUP		((rpcproc_t)3)
#define	NFSLOG_GETFH		((rpcproc_t)4)

/*
 * Version of the on disk log file
 */
#define	NFSLOG_BUF_VERSION	((rpcvers_t)2)

#define	NFSLOG_BUF_VERSMIN	((rpcvers_t)1)
#define	NFSLOG_BUF_VERSMAX	((rpcvers_t)2)
/*
 * Contents of the on disk log file header
 *
 * Note: This is the structure for older version 1 buffers, and does not
 * adequately support large buffer files, as the offset is 32 bit. Newer
 * buffer files are written using version 2 buffer header (below) which
 * has a 64 bit offset. However, because existing buffers continue to use
 * the old header format, the daemon xdr code can read and write either format.
 * This definition below is not explicitely used anywhere in the code,
 * but is implicitely used by the daemon xdr code. For that reason, it
 * is kept here for information purpose only.
 */
struct nfslog_buffer_header_1 {
	uint32_t bh_length;		/* Length of this header */
	uint32_t bh_version;		/* Version of buffer contents */
	uint32_t bh_flags;		/* Optional flags field */
	uint32_t bh_offset;		/* offset within file to begin */
	timestruc32_t bh_timestamp;	/* When the buffer was created */
};
typedef struct nfslog_buffer_header_1 nfslog_buffer_header_1;

/*
 * For the current version 2, which supports largefiles
 */
struct nfslog_buffer_header_2 {
	uint32_t bh_length;		/* Length of this header */
	rpcvers_t bh_version;		/* Version of buffer contents */
	u_offset_t bh_offset;		/* offset within file to begin */
	uint32_t bh_flags;		/* Optional flags field */
	timestruc32_t bh_timestamp;	/* When the buffer was created */
};
typedef struct nfslog_buffer_header_2 nfslog_buffer_header_2;

typedef struct nfslog_buffer_header_2 nfslog_buffer_header;

/* bh_flags values */
#define	NFSLOG_BH_OFFSET_OVERFLOW	1	/* version 1 bh_offset */

/*
 * For each record written to the log file, this struct is used
 * as the logical header; it will be XDR encoded to be written to the file.
 *
 * Note: if the buffer file becomes large enough, the rh_rec_id may
 * wrap around. This situation is appropriately handled by the daemon however.
 */
struct nfslog_record_header {
	uint32_t rh_reclen;		/* Length of entire record */
	uint32_t rh_rec_id;		/* unique id for this log */
	rpcprog_t rh_prognum;		/* Program number */
	rpcproc_t rh_procnum;		/* Procedure number */
	rpcvers_t rh_version;		/* Version number */
	uint32_t rh_auth_flavor;	/* Auth flavor of RPC request */
	timestruc32_t rh_timestamp;	/* time stamp of the request */
	uid_t rh_uid;			/* uid of requestor as per RPC */
	gid_t rh_gid;			/* gid of requestor as per RPC */
};
typedef struct nfslog_record_header nfslog_record_header;

/*
 * For each record written to the log file, this is the logical
 * structure of the record; it will be XDR encoded and written to
 * the file.
 */
struct nfslog_request_record {
	nfslog_record_header re_header;	/* Header as defined above */
	char *re_principal_name;	/* Principal name of caller */
	char *re_netid;			/* Netid used for request */
	char *re_tag;			/* Log buffer tag for file system */
	struct netbuf re_ipaddr;	/* Requestors ip address */
	caddr_t re_rpc_arg;		/* RPC arguments and response */
	caddr_t re_rpc_res;
};
typedef struct nfslog_request_record nfslog_request_record;

/*
 * From this point forward, the definitions represent the arguments
 * and results of each possible RPC that can be logged.  These
 * may have been trimmed in content from the real RPC arguments
 * and results to save space.
 */
typedef fhandle_t fhandle;

struct nfslog_sharefsargs {
	int sh_flags;
	uint32_t sh_anon;
	char *sh_path;
	fhandle sh_fh_buf;
};
typedef struct nfslog_sharefsargs nfslog_sharefsargs;

typedef nfsstat nfslog_sharefsres;

struct nfslog_getfhargs {
	fhandle gfh_fh_buf;
	char *gfh_path;
};
typedef struct nfslog_getfhargs nfslog_getfhargs;

struct nfslog_diropargs {
	fhandle da_fhandle;
	char *da_name;
};
typedef struct nfslog_diropargs nfslog_diropargs;

struct nfslog_drok {
	fhandle drok_fhandle;
};
typedef struct nfslog_drok nfslog_drok;

struct nfslog_diropres {
	nfsstat dr_status;
	union {
		nfslog_drok dr_ok;
	} nfslog_diropres_u;
};
typedef struct nfslog_diropres nfslog_diropres;

typedef struct nfsreadargs nfslog_nfsreadargs;

struct nfslog_rrok {
	uint32_t filesize;
	uint32_t rrok_count;
};
typedef struct nfslog_rrok nfslog_rrok;

struct nfslog_rdresult {
	nfsstat r_status;
	union {
		nfslog_rrok r_ok;
	} nfslog_rdresult_u;
};
typedef struct nfslog_rdresult nfslog_rdresult;

struct nfslog_writeargs {
	fhandle waargs_fhandle;
	uint32_t waargs_begoff;
	uint32_t waargs_offset;
	uint32_t waargs_totcount;
	uint32_t waargs_count;
};
typedef struct nfslog_writeargs nfslog_writeargs;

struct nfslog_writeresult {
	nfsstat wr_status;
	union {
		uint32_t wr_size;
	} nfslog_writeresult_u;
};
typedef struct nfslog_writeresult nfslog_writeresult;

struct nfslog_sattr {
	uint32_t sa_mode;
	uint32_t sa_uid;
	uint32_t sa_gid;
	uint32_t sa_size;
	nfs2_timeval sa_atime;
	nfs2_timeval sa_mtime;
};
typedef struct nfslog_sattr nfslog_sattr;

struct nfslog_createargs {
	nfslog_sattr ca_sa;
	nfslog_diropargs ca_da;
};
typedef struct nfslog_createargs nfslog_createargs;

struct nfslog_setattrargs {
	fhandle saa_fh;
	nfslog_sattr saa_sa;
};
typedef struct nfslog_setattrargs nfslog_setattrargs;

struct nfslog_rdlnres {
	nfsstat rl_status;
	union {
		char *rl_ok;
	} nfslog_rdlnres_u;
};
typedef struct nfslog_rdlnres nfslog_rdlnres;

struct nfslog_rnmargs {
	nfslog_diropargs rna_from;
	nfslog_diropargs rna_to;
};
typedef struct nfslog_rnmargs nfslog_rnmargs;

struct nfslog_linkargs {
	fhandle la_from;
	nfslog_diropargs la_to;
};
typedef struct nfslog_linkargs nfslog_linkargs;

struct nfslog_symlinkargs {
	nfslog_diropargs sla_from;
	char *sla_tnm;
	nfslog_sattr sla_sa;
};
typedef struct nfslog_symlinkargs nfslog_symlinkargs;

struct nfslog_rddirargs {
	fhandle rda_fh;
	uint32_t rda_offset;
	uint32_t rda_count;
};
typedef struct nfslog_rddirargs nfslog_rddirargs;

struct nfslog_rdok {
	uint32_t rdok_offset;
	uint32_t rdok_size;
	bool_t rdok_eof;
};
typedef struct nfslog_rdok nfslog_rdok;

struct nfslog_rddirres {
	nfsstat rd_status;
	union {
		nfslog_rdok rd_ok;
	} nfslog_rddirres_u;
};
typedef struct nfslog_rddirres nfslog_rddirres;

struct nfslog_diropargs3 {
	nfs_fh3 dir;
	char *name;
};
typedef struct nfslog_diropargs3 nfslog_diropargs3;

struct nfslog_LOOKUP3res {
	nfsstat3 status;
	union {
		nfs_fh3 object;
	} nfslog_LOOKUP3res_u;
};
typedef struct nfslog_LOOKUP3res nfslog_LOOKUP3res;

struct nfslog_createhow3 {
	createmode3 mode;
	union {
		set_size3 size;
	} nfslog_createhow3_u;
};
typedef struct nfslog_createhow3 nfslog_createhow3;

struct nfslog_CREATE3args {
	nfslog_diropargs3 where;
	nfslog_createhow3 how;
};
typedef struct nfslog_CREATE3args nfslog_CREATE3args;

struct nfslog_CREATE3resok {
	post_op_fh3 obj;
};
typedef struct nfslog_CREATE3resok nfslog_CREATE3resok;

struct nfslog_CREATE3res {
	nfsstat3 status;
	union {
		nfslog_CREATE3resok ok;
	} nfslog_CREATE3res_u;
};
typedef struct nfslog_CREATE3res nfslog_CREATE3res;

struct nfslog_SETATTR3args {
	nfs_fh3 object;
	set_size3 size;
};
typedef struct nfslog_SETATTR3args nfslog_SETATTR3args;

struct nfslog_READLINK3res {
	nfsstat3 status;
	union {
		char *data;
	} nfslog_READLINK3res_u;
};
typedef struct nfslog_READLINK3res nfslog_READLINK3res;

struct nfslog_READ3args {
	nfs_fh3 file;
	offset3 offset;
	count3 count;
};
typedef struct nfslog_READ3args nfslog_READ3args;

struct nfslog_READ3resok {
	size3 filesize;
	count3 count;
	bool_t eof;
	uint32_t size;
};
typedef struct nfslog_READ3resok nfslog_READ3resok;

struct nfslog_READ3res {
	nfsstat3 status;
	union {
		nfslog_READ3resok ok;
	} nfslog_READ3res_u;
};
typedef struct nfslog_READ3res nfslog_READ3res;

struct nfslog_WRITE3args {
	nfs_fh3 file;
	offset3 offset;
	count3 count;
	stable_how stable;
};
typedef struct nfslog_WRITE3args nfslog_WRITE3args;

struct nfslog_WRITE3resok {
	size3 filesize;
	count3 count;
	stable_how committed;
};
typedef struct nfslog_WRITE3resok nfslog_WRITE3resok;

struct nfslog_WRITE3res {
	nfsstat3 status;
	union {
		nfslog_WRITE3resok ok;
	} nfslog_WRITE3res_u;
};
typedef struct nfslog_WRITE3res nfslog_WRITE3res;

struct nfslog_MKDIR3args {
	nfslog_diropargs3 where;
};
typedef struct nfslog_MKDIR3args nfslog_MKDIR3args;

struct nfslog_MKDIR3res {
	nfsstat3 status;
	union {
		post_op_fh3 obj;
	} nfslog_MKDIR3res_u;
};
typedef struct nfslog_MKDIR3res nfslog_MKDIR3res;

struct nfslog_SYMLINK3args {
	nfslog_diropargs3 where;
	char *symlink_data;
};
typedef struct nfslog_SYMLINK3args nfslog_SYMLINK3args;

struct nfslog_SYMLINK3res {
	nfsstat3 status;
	union {
		post_op_fh3 obj;
	} nfslog_SYMLINK3res_u;
};
typedef struct nfslog_SYMLINK3res nfslog_SYMLINK3res;

struct nfslog_MKNOD3args {
	nfslog_diropargs3 where;
	ftype3 type;
};
typedef struct nfslog_MKNOD3args nfslog_MKNOD3args;

struct nfslog_MKNOD3res {
	nfsstat3 status;
	union {
		post_op_fh3 obj;
	} nfslog_MKNOD3res_u;
};
typedef struct nfslog_MKNOD3res nfslog_MKNOD3res;

struct nfslog_REMOVE3args {
	nfslog_diropargs3 object;
};
typedef struct nfslog_REMOVE3args nfslog_REMOVE3args;

struct nfslog_RMDIR3args {
	nfslog_diropargs3 object;
};
typedef struct nfslog_RMDIR3args nfslog_RMDIR3args;

struct nfslog_RENAME3args {
	nfslog_diropargs3 from;
	nfslog_diropargs3 to;
};
typedef struct nfslog_RENAME3args nfslog_RENAME3args;

struct nfslog_LINK3args {
	nfs_fh3 file;
	nfslog_diropargs3 link;
};
typedef struct nfslog_LINK3args nfslog_LINK3args;

struct nfslog_READDIRPLUS3args {
	nfs_fh3 dir;
	count3 dircount;
	count3 maxcount;
};
typedef struct nfslog_READDIRPLUS3args nfslog_READDIRPLUS3args;

struct nfslog_entryplus3 {
	post_op_fh3 name_handle;
	char *name;
	struct nfslog_entryplus3 *nextentry;
};
typedef struct nfslog_entryplus3 nfslog_entryplus3;

struct nfslog_dirlistplus3 {
	nfslog_entryplus3 *entries;
	bool_t eof;
};
typedef struct nfslog_dirlistplus3 nfslog_dirlistplus3;

struct nfslog_READDIRPLUS3resok {
	nfslog_dirlistplus3 reply;
};
typedef struct nfslog_READDIRPLUS3resok nfslog_READDIRPLUS3resok;

struct nfslog_READDIRPLUS3res {
	nfsstat3 status;
	union {
		nfslog_READDIRPLUS3resok ok;
	} nfslog_READDIRPLUS3res_u;
};
typedef struct nfslog_READDIRPLUS3res nfslog_READDIRPLUS3res;

struct nfslog_COMMIT3args {
	nfs_fh3 file;
	offset3 offset;
	count3 count;
};
typedef struct nfslog_COMMIT3args nfslog_COMMIT3args;

/* the xdr functions */
#ifndef _KERNEL

extern bool_t xdr_nfsstat(XDR *, nfsstat *);
extern bool_t xdr_uint64(XDR *, uint64 *);
extern bool_t xdr_uint32(XDR *, uint32 *);
extern bool_t xdr_fhandle(XDR *, fhandle_t *);
extern bool_t xdr_nfs_fh3(XDR *, nfs_fh3 *);
extern bool_t xdr_nfsstat3(XDR *, nfsstat3 *);
extern bool_t xdr_nfslog_buffer_header(XDR *, nfslog_buffer_header *);
extern bool_t xdr_nfslog_request_record(XDR *, nfslog_request_record *);
extern bool_t xdr_nfslog_sharefsargs(XDR *, nfslog_sharefsargs *);
extern bool_t xdr_nfslog_sharefsres(XDR *, nfslog_sharefsres *);
extern bool_t xdr_nfslog_getfhargs(XDR *, nfslog_getfhargs *);
extern bool_t xdr_nfslog_diropargs(XDR *, nfslog_diropargs *);
extern bool_t xdr_nfslog_diropres(XDR *, nfslog_diropres *);
extern bool_t xdr_nfslog_nfsreadargs(XDR *, nfslog_nfsreadargs *);
extern bool_t xdr_nfslog_rdresult(XDR *, nfslog_rdresult *);
extern bool_t xdr_nfslog_writeargs(XDR *, nfslog_writeargs *);
extern bool_t xdr_nfslog_writeresult(XDR *, nfslog_writeresult *);
extern bool_t xdr_nfslog_createargs(XDR *, nfslog_createargs *);
extern bool_t xdr_nfslog_setattrargs(XDR *, nfslog_setattrargs *);
extern bool_t xdr_nfslog_rdlnres(XDR *, nfslog_rdlnres *);
extern bool_t xdr_nfslog_rnmargs(XDR *, nfslog_rnmargs *);
extern bool_t xdr_nfslog_linkargs(XDR *, nfslog_linkargs *);
extern bool_t xdr_nfslog_symlinkargs(XDR *, nfslog_symlinkargs *);
extern bool_t xdr_nfslog_rddirargs(XDR *, nfslog_rddirargs *);
extern bool_t xdr_nfslog_rddirres(XDR *, nfslog_rddirres *);
extern bool_t xdr_nfslog_diropargs3(XDR *, nfslog_diropargs3 *);
extern bool_t xdr_nfslog_LOOKUP3res(XDR *, nfslog_LOOKUP3res *);
extern bool_t xdr_nfslog_CREATE3args(XDR *, nfslog_CREATE3args *);
extern bool_t xdr_nfslog_CREATE3res(XDR *, nfslog_CREATE3res *);
extern bool_t xdr_nfslog_SETATTR3args(XDR *, nfslog_SETATTR3args *);
extern bool_t xdr_nfslog_READLINK3res(XDR *, nfslog_READLINK3res *);
extern bool_t xdr_nfslog_READ3args(XDR *, nfslog_READ3args *);
extern bool_t xdr_nfslog_READ3res(XDR *, nfslog_READ3res *);
extern bool_t xdr_nfslog_WRITE3args(XDR *, nfslog_WRITE3args *);
extern bool_t xdr_nfslog_WRITE3res(XDR *, nfslog_WRITE3res *);
extern bool_t xdr_nfslog_MKDIR3args(XDR *, nfslog_MKDIR3args *);
extern bool_t xdr_nfslog_MKDIR3res(XDR *, nfslog_MKDIR3res *);
extern bool_t xdr_nfslog_SYMLINK3args(XDR *, nfslog_SYMLINK3args *);
extern bool_t xdr_nfslog_SYMLINK3res(XDR *, nfslog_SYMLINK3res *);
extern bool_t xdr_nfslog_MKNOD3args(XDR *, nfslog_MKNOD3args *);
extern bool_t xdr_nfslog_MKNOD3res(XDR *, nfslog_MKNOD3res *);
extern bool_t xdr_nfslog_REMOVE3args(XDR *, nfslog_REMOVE3args *);
extern bool_t xdr_nfslog_RMDIR3args(XDR *, nfslog_RMDIR3args *);
extern bool_t xdr_nfslog_RENAME3args(XDR *, nfslog_RENAME3args *);
extern bool_t xdr_nfslog_LINK3args(XDR *, nfslog_LINK3args *);
extern bool_t xdr_nfslog_READDIRPLUS3args(XDR *, nfslog_READDIRPLUS3args *);
extern bool_t xdr_nfslog_READDIRPLUS3res(XDR *, nfslog_READDIRPLUS3res *);
extern bool_t xdr_nfslog_COMMIT3args(XDR *, nfslog_COMMIT3args *);

#else /* !_KERNEL */

extern bool_t xdr_nfsstat(XDR *, nfsstat *);
extern bool_t xdr_nfslog_nfsreadargs(XDR *, nfslog_nfsreadargs *);
extern bool_t xdr_nfslog_sharefsres(XDR *, nfslog_sharefsres *);
extern bool_t xdr_nfslog_sharefsargs(XDR *, struct exportinfo *);
extern bool_t xdr_nfslog_getfhargs(XDR *, nfslog_getfhargs *);
extern bool_t xdr_nfslog_diropargs(XDR *, struct nfsdiropargs *);
extern bool_t xdr_nfslog_drok(XDR *, struct nfsdrok *);
extern bool_t xdr_nfslog_diropres(XDR *, struct nfsdiropres *);
extern bool_t xdr_nfslog_getattrres(XDR *, struct nfsattrstat *);
extern bool_t xdr_nfslog_rrok(XDR *, struct nfsrrok *);
extern bool_t xdr_nfslog_rdresult(XDR *, struct nfsrdresult *);
extern bool_t xdr_nfslog_writeargs(XDR *, struct nfswriteargs *);
extern bool_t xdr_nfslog_writeresult(XDR *, struct nfsattrstat *);
extern bool_t xdr_nfslog_createargs(XDR *, struct nfscreatargs *);
extern bool_t xdr_nfslog_sattr(XDR *, struct nfssattr *);
extern bool_t xdr_nfslog_setattrargs(XDR *, struct nfssaargs *);
extern bool_t xdr_nfslog_rdlnres(XDR *, struct nfsrdlnres *);
extern bool_t xdr_nfslog_rnmargs(XDR *, struct nfsrnmargs *);
extern bool_t xdr_nfslog_symlinkargs(XDR *, struct nfsslargs *);
extern bool_t xdr_nfslog_statfs(XDR *, struct nfsstatfs *);
extern bool_t xdr_nfslog_linkargs(XDR *, struct nfslinkargs *);
extern bool_t xdr_nfslog_rddirargs(XDR *, struct nfsrddirargs *);
extern bool_t xdr_nfslog_rdok(XDR *, struct nfsrdok *);
extern bool_t xdr_nfslog_rddirres(XDR *, struct nfsrddirres *);
extern bool_t xdr_nfslog_diropargs3(XDR *, diropargs3 *);
extern bool_t xdr_nfslog_LOOKUP3res(XDR *, LOOKUP3res *);
extern bool_t xdr_nfslog_createhow3(XDR *, createhow3 *);
extern bool_t xdr_nfslog_CREATE3args(XDR *, CREATE3args *);
extern bool_t xdr_nfslog_CREATE3resok(XDR *, CREATE3resok *);
extern bool_t xdr_nfslog_CREATE3res(XDR *, CREATE3res *);
extern bool_t xdr_nfslog_GETATTR3res(XDR *, GETATTR3res *);
extern bool_t xdr_nfslog_ACCESS3args(XDR *, ACCESS3args *);
extern bool_t xdr_nfslog_ACCESS3res(XDR *, ACCESS3res *);
extern bool_t xdr_nfslog_SETATTR3args(XDR *, SETATTR3args *);
extern bool_t xdr_nfslog_SETATTR3res(XDR *, SETATTR3res *);
extern bool_t xdr_nfslog_READLINK3res(XDR *, READLINK3res *);
extern bool_t xdr_nfslog_READ3args(XDR *, READ3args *);
extern bool_t xdr_nfslog_READ3resok(XDR *, READ3resok *);
extern bool_t xdr_nfslog_READ3res(XDR *, READ3res *);
extern bool_t xdr_nfslog_READ3resok(XDR *, READ3resok *);
extern bool_t xdr_nfslog_READ3res(XDR *, READ3res *);
extern bool_t xdr_nfslog_WRITE3args(XDR *, WRITE3args *);
extern bool_t xdr_nfslog_WRITE3resok(XDR *, WRITE3resok *);
extern bool_t xdr_nfslog_WRITE3res(XDR *, WRITE3res *);
extern bool_t xdr_nfslog_MKDIR3args(XDR *, MKDIR3args *);
extern bool_t xdr_nfslog_MKDIR3res(XDR *, MKDIR3res *);
extern bool_t xdr_nfslog_SYMLINK3args(XDR *, SYMLINK3args *);
extern bool_t xdr_nfslog_SYMLINK3res(XDR *, SYMLINK3res *);
extern bool_t xdr_nfslog_MKNOD3args(XDR *, MKNOD3args *);
extern bool_t xdr_nfslog_MKNOD3res(XDR *, MKNOD3res *);
extern bool_t xdr_nfslog_REMOVE3args(XDR *, REMOVE3args *);
extern bool_t xdr_nfslog_REMOVE3res(XDR *, REMOVE3res *);
extern bool_t xdr_nfslog_RMDIR3args(XDR *, RMDIR3args *);
extern bool_t xdr_nfslog_RMDIR3res(XDR *, RMDIR3res *);
extern bool_t xdr_nfslog_RENAME3args(XDR *, RENAME3args *);
extern bool_t xdr_nfslog_RENAME3res(XDR *, RENAME3res *);
extern bool_t xdr_nfslog_LINK3args(XDR *, LINK3args *);
extern bool_t xdr_nfslog_LINK3res(XDR *, LINK3res *);
extern bool_t xdr_nfslog_READDIR3args(XDR *, READDIR3args *);
extern bool_t xdr_nfslog_READDIR3res(XDR *, READDIR3res *);
extern bool_t xdr_nfslog_FSSTAT3args(XDR *, FSSTAT3args *);
extern bool_t xdr_nfslog_FSSTAT3res(XDR *, FSSTAT3res *);
extern bool_t xdr_nfslog_FSINFO3args(XDR *, FSINFO3args *);
extern bool_t xdr_nfslog_FSINFO3res(XDR *, FSINFO3res *);
extern bool_t xdr_nfslog_PATHCONF3args(XDR *, PATHCONF3args *);
extern bool_t xdr_nfslog_PATHCONF3res(XDR *, PATHCONF3res *);
extern bool_t xdr_nfslog_COMMIT3args(XDR *, COMMIT3args *);
extern bool_t xdr_nfslog_COMMIT3res(XDR *, COMMIT3res *);
extern bool_t xdr_nfslog_READDIRPLUS3args(XDR *, READDIRPLUS3args *);
extern bool_t xdr_nfslog_READDIRPLUS3res(XDR *, READDIRPLUS3res *);
extern bool_t xdr_nfslog_request_record(XDR *,	struct exportinfo *,
			struct svc_req *, cred_t *, struct netbuf *,
			unsigned int, unsigned int);


#endif /* !_KERNEL */

#ifdef _KERNEL

/*
 * Used to direct nfslog_write_record() on its behavior of
 * writing log entries
 */
#define	NFSLOG_ALL_BUFFERS	1
#define	NFSLOG_ONE_BUFFER	2

/* Sizes of the various memory allocations for encoding records */
#define	NFSLOG_SMALL_RECORD_SIZE 512
#define	NFSLOG_SMALL_REC_NAME	"nfslog_small_rec"
#define	NFSLOG_MEDIUM_RECORD_SIZE 8192
#define	NFSLOG_MEDIUM_REC_NAME	"nfslog_medium_rec"
#define	NFSLOG_LARGE_RECORD_SIZE 32768
#define	NFSLOG_LARGE_REC_NAME	"nfslog_large_rec"

/*
 * Functions used for interaction with nfs logging
 */
extern bool_t	xdr_nfslog_buffer_header(XDR *, nfslog_buffer_header *);

extern void	nfslog_share_record(struct exportinfo *exi, cred_t *cr);
extern void	nfslog_unshare_record(struct exportinfo *exi, cred_t *cr);
extern void	nfslog_getfh(struct exportinfo *, fhandle *, char *,
		enum uio_seg, cred_t *);

extern void	nfslog_init();
extern int	nfslog_setup(struct exportinfo *);
extern void	nfslog_disable(struct exportinfo *);
/*PRINTFLIKE2*/
extern void	nfslog_dprint(const int, const char *fmt, ...)
	__KPRINTFLIKE(2);
extern void	*nfslog_record_alloc(struct exportinfo *, int,
		void **, int);
extern void	nfslog_record_free(void *, void *, size_t);
extern struct	exportinfo *nfslog_get_exi(nfs_export_t *, struct exportinfo *,
		struct svc_req *, caddr_t, unsigned int *);
extern void	nfslog_write_record(struct exportinfo *, struct svc_req *,
		caddr_t, caddr_t, cred_t *, struct netbuf *, unsigned int,
		unsigned int);

extern struct log_buffer *nfslog_buffer_list;

/*
 * Logging debug macro; expands to nothing for non-debug kernels.
 */
#ifndef DEBUG
#define	LOGGING_DPRINT(x)
#else
#define	LOGGING_DPRINT(x)	nfslog_dprint x
#endif

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_LOG_H */
