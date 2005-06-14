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
 *
 * nfs_inet.h contains definitions specific to inetboot's nfs implementation.
 */

#ifndef _NFS_INET_H
#define	_NFS_INET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/saio.h>
#include <rpcsvc/nfs_prot.h>
#include <rpcsvc/nfs4_prot.h>
#include "clnt.h"
#include <sys/vfs.h>
#include <sys/dirent.h>

#define	NFSBUF_SIZE	(READ_SIZE+1024)
#define	READ_SIZE	(8192)	/* NFS readsize */
#define	NFS_READ_DECR	(1024)	/* NFS readsize decrement */
#define	NFS3BUF_SIZE	(READ3_SIZE+1024)
#define	READ3_SIZE	(32 * 1024)	/* NFS3 readsize */
#define	NFS4BUF_SIZE	(READ4_SIZE+1024)
#define	READ4_SIZE	(32 * 1024)	/* NFS4 readsize */
#define	NFS4_MAX_UTF8STRING	(8 * 1024)
#define	NFS4_MAX_BITWORDS	(2)
#define	NFS_MAX_FERRS	(3)	/* MAX frame errors before decr read size */
#define	NFS_REXMIT_MIN	(3)	/* NFS retry min in secs */
#define	NFS_REXMIT_MAX	(15)	/* NFS retry max in secs */

extern int nfs_readsize;
extern struct nfs_file roothandle;
extern CLIENT *root_CLIENT;

/*
 * Boot specific V4 fh with maximum allowed data statically allocated
 */
struct nfs_bfh4 {
	uint_t len;
	char data[NFS4_FHSIZE];
};

/*
 * Boot specific V3 fh with maximum allowed data statically allocated
 */
struct nfs_bfh3 {
	uint_t len;
	char data[NFS3_FHSIZE];
};

union _nfs_fh {
	nfs_fh fh2;
	struct nfs_bfh3 fh3;
	struct nfs_bfh4 fh4;
};

union _nfs_cookie {
	nfscookie cookie2;
	cookie3 cookie3;
	nfs_cookie4 cookie4;
};

union _nfs_ftype {
	ftype type2;
	ftype3 type3;
	nfs_ftype4 type4;
};

/*
 * NFS: This structure represents the current open file.
 */
struct nfs_file {
	int version;
	ulong_t offset;
	union _nfs_ftype ftype;
	union _nfs_fh fh;
	union _nfs_cookie cookie;
};

struct nfs_fid {
	ushort_t nf_len;
	ushort_t nf_pad;
	struct nfs_fh fh;
};

#define	cfile_is_dir(cf)    (((cf)->version == NFS_VERSION) ?	\
				((cf)->ftype.type2 == NFDIR) :	\
				(((cf)->version == NFS_V3) ?	\
				((cf)->ftype.type3 == NF3DIR) : \
				(((cf)->version == NFS_V4) ?	\
				((cf)->ftype.type4 == NF4DIR) : 0)))

#define	cfile_is_lnk(cf)    (((cf)->version == NFS_VERSION) ?	\
				((cf)->ftype.type2 == NFLNK) :	\
				(((cf)->version == NFS_V3) ?	\
				((cf)->ftype.type3 == NF3LNK) : \
				(((cf)->version == NFS_V4) ?	\
				((cf)->ftype.type4 == NF4LNK) : 0)))

/*
 * Predefine an attribute bitmap that inetboot will most likely be
 * interested in.
 */
typedef union attr4_bitmap1_u {
	struct {
		unsigned int
#ifdef _BIT_FIELDS_HTOL
		b_pad4:			11,
		b_fattr4_fileid:	1,
		b_fattr4_filehandle:	1,
		b_pad3:			10,
		b_fattr4_fsid:		1,
		b_pad2:			3,
		b_fattr4_size:		1,
		b_pad1:			2,
		b_fattr4_type:		1,
		b_supported_attrs:	1;
#endif
#ifdef _BIT_FIELDS_LTOH
		b_supported_attrs:	1,
		b_fattr4_type:		1,
		b_pad1:			2,
		b_fattr4_size:		1,
		b_pad2:			3,
		b_fattr4_fsid:		1,
		b_pad3:			10,
		b_fattr4_filehandle:	1,
		b_fattr4_fileid:	1,
		b_pad4:			11;
#endif
	} bitmap_s;
	uint_t word;
} attr4_bitmap1_t;

#define	bm_supported_attrs	bitmap_s.b_supported_attrs
#define	bm_fattr4_type		bitmap_s.b_fattr4_type
#define	bm_fattr4_size		bitmap_s.b_fattr4_size
#define	bm_fattr4_fsid		bitmap_s.b_fattr4_fsid
#define	bm_fattr4_fileid	bitmap_s.b_fattr4_fileid
#define	bm_fattr4_filehandle	bitmap_s.b_fattr4_filehandle

typedef	union attr4_bitmap2_u {
	struct {
		unsigned int
#ifdef _BIT_FIELDS_HTOL
		b_pad4:			10,
		b_fattr4_time_modify:	1,
		b_fattr4_time_metadata:	1,
		b_pad3:			4,
		b_fattr4_time_access:	1,
		b_pad2:			13,
		b_fattr4_mode:		1,
		b_pad1:			1;
#endif
#ifdef _BIT_FIELDS_LTOH
		b_pad1:			1,
		b_fattr4_mode:		1,
		b_pad2:			13,
		b_fattr4_time_access:	1,
		b_pad3:			4,
		b_fattr4_time_metadata:	1,
		b_fattr4_time_modify:	1,
		b_pad4:			10;
#endif
	} bitmap_s;
	uint_t word;
} attr4_bitmap2_t;

#define	bm_fattr4_mode		bitmap_s.b_fattr4_mode
#define	bm_fattr4_time_access	bitmap_s.b_fattr4_time_access
#define	bm_fattr4_time_metadata	bitmap_s.b_fattr4_time_metadata
#define	bm_fattr4_time_modify	bitmap_s.b_fattr4_time_modify

typedef struct b_bitmap4 {
	uint_t b_bitmap_len;
	uint_t b_bitmap_val[NFS4_MAX_BITWORDS];
} b_bitmap4_t;

/*
 * Define a usable set of v4 atttributes for inetboot.
 */
typedef struct b_fattr4_s {
	b_bitmap4_t	b_supported_attrs;
	nfs_ftype4	b_fattr4_type;
	uint64_t	b_fattr4_size;
	fsid4		b_fattr4_fsid;
	struct nfs_bfh4	b_fattr4_filehandle;
	uint64_t	b_fattr4_fileid;
	mode4		b_fattr4_mode;
	nfstime4	b_fattr4_time_access;
	nfstime4	b_fattr4_time_metadata;
	nfstime4	b_fattr4_time_modify;
} b_fattr4_t;

/*
 * common to putfh and putfhroot.
 */
typedef struct putfh4arg_s {
	uint_t		pf_opnum;	/* can either be putfh or putrootfh */
	struct nfs_bfh4	pf_filehandle;	/* only used by putfh */
} putfh4arg_t;

/*
 * Use this struct to construct our OTW compound procedures.  Layout makes for
 * easy XDR'ing. Include putfh.
 */
typedef union compound_u {
	struct {
		utf8string	tag;
		uint_t		minorversion;	/* 0 */
		uint_t		argarray_len;	/* 1 + n for putfh */
		bool_t		isputrootfh;	/* flag */
		putfh4arg_t	opputfh;	/* putfh args */
	} compound_ua_s;
	struct {
		nfsstat4	status;		/* status of last op */
		utf8string	tag;
		uint_t		resarray_len;	/* 1 + n for putfh */
		uint_t		opputfh;	/* putfh opnum */
		nfsstat4	putfh_status;	/* putfh status */
	} compound_ur_s;
} b_compound_t;

/*
 * Define some macros for easy access into the compound structrue
 */
#define	ca_tag compound_ua_s.tag
#define	ca_minorversion compound_ua_s.minorversion
#define	ca_argarray_len compound_ua_s.argarray_len
#define	ca_isputrootfh compound_ua_s.isputrootfh
#define	ca_opputfh compound_ua_s.opputfh

#define	cr_status compound_ur_s.status
#define	cr_tag compound_ur_s.tag
#define	cr_resarray_len compound_ur_s.resarray_len
#define	cr_opputfh compound_ur_s.opputfh
#define	cr_putfh_status compound_ur_s.putfh_status
/*
 * Define simple compound structs that include op specific data
 */
typedef struct getattrres_cmn {
	uint_t		gc_opgetattr;		/* getattr opnum */
	nfsstat4	gc_attr_status;		/* getattr result */
	b_bitmap4_t	gc_retattr;		/* getattr result */
	uint_t		gc_attrlist_len;	/* getattr result */
	b_fattr4_t	gc_attrs;		/* getattr result */
} getattrres_cmn_t;

/*
 * getattr: putfh/getattr
 */
typedef struct getattr4arg_s {
	b_compound_t	ga_arg;		/* compound + putfh */
	uint_t		ga_opgetattr;	/* getattr opnum */
	b_bitmap4_t	ga_attr_req;	/* getattr arg */
} getattr4arg_t;

typedef struct getattr4res_s {
	b_compound_t		gr_res;	/* compound + putfh */
	getattrres_cmn_t	gr_cmn;
} getattr4res_t;

#define	gr_opgetattr gr_cmn.gc_opgetattr
#define	gr_attr_status gr_cmn.gc_attr_status
#define	gr_retattr gr_cmn.gc_retattr
#define	gr_attrs gr_cmn.gc_attrs

/*
 * lookup: putfh/lookup/getattr
 */
typedef struct lookup4arg_s {
	b_compound_t	la_arg;		/* compound + putfh */
	uint_t		la_oplookup;	/* lookup opnum */
	component4	la_pathname;	/* lookup arg */
	uint_t		la_opgetattr;	/* getattr opnum */
	b_bitmap4_t	la_attr_req;	/* getattr arg */
} lookup4arg_t;

typedef struct lookup4res_s {
	b_compound_t		lr_res;		/* compound + putfh */
	uint_t			lr_oplookup;	/* lookup opnum */
	nfsstat4		lr_lookup_status;	/* lookup result */
	getattrres_cmn_t	lr_gcmn;	/* getattr result */
} lookup4res_t;

#define	lr_opgetattr lr_gcmn.gc_opgetattr
#define	lr_attr_status lr_gcmn.gc_attr_status
#define	lr_retattr lr_gcmn.gc_retattr
#define	lr_attrs lr_gcmn.gc_attrs

/*
 * lookupp: putfh/lookupp/getattr
 *
 * For results: use the lookup4res_t
 */
typedef struct lookupp4arg_s {
	b_compound_t	la_arg;		/* compound + putfh */
	uint_t		la_oplookupp;	/* lookupp opnum */
	uint_t		la_opgetattr;	/* lookupp arg */
	b_bitmap4_t	la_attr_req;	/* lookupp arg */
} lookupp4arg_t;

/*
 * read: putfh/read
 */
typedef struct read4arg_s {
	b_compound_t	r_arg;		/* compound + putfh */
	uint_t		r_opread;	/* read opnum */
	stateid4	r_stateid;	/* read arg */
	offset4		r_offset;	/* read arg */
	count4		r_count;	/* read arg */
} read4arg_t;

typedef struct read4res_s {
	b_compound_t	r_res;		/* compound + putfh */
	uint_t		r_opread;	/* read opnum */
	nfsstat4	r_status;	/* read result */
	bool_t		r_eof;		/* read result */
	uint_t		r_data_len;	/* read result */
	char		*r_data_val;	/* read result */
} read4res_t;

typedef struct b_entry4_s {
	nfs_cookie4		b_cookie;
	utf8string		b_name;
	uint64_t		b_fileid;
	struct b_entry4_s	*b_nextentry;
} b_entry4_t;

/*
 * readdir: putfh/readdir/getattr
 */
typedef struct readdir4arg_s {
	b_compound_t	rd_arg;		/* compoud + putfh */
	uint_t		rd_opreaddir;	/* readdir opnum */
	nfs_cookie4	rd_cookie;	/* readdir arg */
	verifier4	rd_cookieverf;	/* readdir arg */
	count4		rd_dircount;	/* readdir arg */
	count4		rd_maxcount;	/* readdir arg */
	b_bitmap4_t	rd_attr_req;	/* readdir arg */
} readdir4arg_t;

typedef struct readdir4res_s {
	b_compound_t	rd_res;		/* compound + putfh */
	uint_t		rd_opreaddir;	/* readdir opnum */
	nfsstat4	rd_status;	/* readdir result */
	verifier4	rd_cookieverf;	/* readdir result */
	b_entry4_t	*rd_entries;	/* readdir result */
	bool_t		rd_eof;		/* readdir result */
} readdir4res_t;

/*
 * readlink: putfh/readlink
 */
typedef struct readlink4arg_s {
	b_compound_t	rl_arg;		/* compound + putfh */
	uint_t		rl_opreadlink;	/* readlink opnum */
} readlink4arg_t;

typedef struct readlink4res_s {
	b_compound_t	rl_res;		/* compound + putfh */
	uint_t		rl_opreadlink;	/* readlink opnum */
	nfsstat4	rl_status;	/* readlink result */
	utf8string	rl_link;	/* readlink result */
} readlink4res_t;

/*
 * Generic NFS functions
 */
extern int	boot_nfs_mountroot(char *);
extern int	boot_nfs_unmountroot(void);
extern int	lookup(char *pathname, struct nfs_file *, bool_t);
extern bool_t	whoami(void);
extern bool_t	getfile(char *, char *, struct in_addr *, char *);

/*
 * NFS Version 2 specific functions
 */
extern void	nfs_error(enum nfsstat);
extern ssize_t	nfsread(struct nfs_file *, char *, size_t);
extern int	nfsgetattr(struct nfs_file *, struct vattr *);
extern int	nfsgetdents(struct nfs_file *, struct dirent *, unsigned);
extern struct nfs_file *nfslookup(struct nfs_file *, char *, int *);
extern int nfsgetsymlink(struct nfs_file *cfile, char **path);

/*
 * NFS Version 3 specific functions
 */
extern void	nfs3_error(enum nfsstat3);
extern ssize_t	nfs3read(struct nfs_file *, char *, size_t);
extern int	nfs3getattr(struct nfs_file *, struct vattr *);
extern int	nfs3getdents(struct nfs_file *, struct dirent *, unsigned);
extern struct nfs_file *nfs3lookup(struct nfs_file *, char *, int *);
extern int	nfs3getsymlink(struct nfs_file *, char **);

/*
 * NFS Version 4 specific functions
 */
extern void	nfs4_error(enum nfsstat4);
extern ssize_t	nfs4read(struct nfs_file *, char *, size_t);
extern int	nfs4getattr(struct nfs_file *, struct vattr *);
extern int	nfs4_getdents(struct nfs_file *, struct dirent *, unsigned);
extern struct nfs_file *nfs4lookup(struct nfs_file *, char *, int *);
extern struct nfs_file *nfs4lookupp(struct nfs_file *, int *, uint64_t *);
extern int	nfs4getsymlink(struct nfs_file *, char **);
extern void	compound_init(b_compound_t *, utf8string *, uint_t, uint_t,
				struct nfs_bfh4 *);

/*
 * NFSv4 xdr ops
 */
extern bool_t	xdr_getattr4_args(XDR *, getattr4arg_t *);
extern bool_t	xdr_getattr4_res(XDR *, getattr4res_t *);
extern bool_t	xdr_lookup4_args(XDR *, lookup4arg_t *);
extern bool_t	xdr_lookup4_res(XDR *, lookup4res_t *);
extern bool_t	xdr_lookupp4_args(XDR *, lookupp4arg_t *);
extern bool_t	xdr_read4_args(XDR *, read4arg_t *);
extern bool_t	xdr_read4_res(XDR *, read4res_t *);
extern bool_t	xdr_readdir4_args(XDR *, readdir4arg_t *);
extern bool_t	xdr_readdir4_res(XDR *, readdir4res_t *);
extern bool_t	xdr_readlink4_args(XDR *, readlink4arg_t *);
extern bool_t	xdr_readlink4_res(XDR *, readlink4res_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _NFS_INET_H */
