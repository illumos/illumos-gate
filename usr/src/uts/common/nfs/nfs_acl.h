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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 *	Copyright 2006 Sun Microsystems, Inc.
 *	All rights reserved.
 *	Use is subject to license terms.
 */

#ifndef _NFS_NFS_ACL_H
#define	_NFS_NFS_ACL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	NFS_ACL_MAX_ENTRIES	1024

typedef ushort_t o_mode;

struct aclent {
	int type;
	uid32_t id;
	o_mode perm;
};
typedef struct aclent aclent;

#define	NA_USER_OBJ	0x1
#define	NA_USER		0x2
#define	NA_GROUP_OBJ	0x4
#define	NA_GROUP	0x8
#define	NA_CLASS_OBJ	0x10
#define	NA_OTHER_OBJ	0x20
#define	NA_ACL_DEFAULT	0x1000

#define	NA_READ		0x4
#define	NA_WRITE	0x2
#define	NA_EXEC		0x1

struct secattr {
	uint32 mask;
	int aclcnt;
	struct {
		uint_t aclent_len;
		aclent *aclent_val;
	} aclent;
	int dfaclcnt;
	struct {
		uint_t dfaclent_len;
		aclent *dfaclent_val;
	} dfaclent;
};
typedef struct secattr secattr;

#define	NA_ACL		0x1
#define	NA_ACLCNT	0x2
#define	NA_DFACL	0x4
#define	NA_DFACLCNT	0x8

struct GETACL2args {
	fhandle_t fh;
	uint32 mask;
};
typedef struct GETACL2args GETACL2args;

struct GETACL2resok {
	struct nfsfattr attr;
	vsecattr_t acl;
};
typedef struct GETACL2resok GETACL2resok;

struct GETACL2res {
	enum nfsstat status;
	union {
		GETACL2resok ok;
	} res_u;
};
typedef struct GETACL2res GETACL2res;

struct SETACL2args {
	fhandle_t fh;
	vsecattr_t acl;
};
typedef struct SETACL2args SETACL2args;

struct SETACL2resok {
	struct nfsfattr attr;
};
typedef struct SETACL2resok SETACL2resok;

struct SETACL2res {
	enum nfsstat status;
	union {
		SETACL2resok ok;
	} res_u;
};
typedef struct SETACL2res SETACL2res;

struct GETATTR2args {
	fhandle_t fh;
};
typedef struct GETATTR2args GETATTR2args;

struct GETATTR2resok {
	struct nfsfattr attr;
};
typedef struct GETATTR2resok GETATTR2resok;

struct GETATTR2res {
	enum nfsstat status;
	union {
		GETATTR2resok ok;
	} res_u;
};
typedef struct GETATTR2res GETATTR2res;

struct ACCESS2args {
	fhandle_t fh;
	uint32 access;
};
typedef struct ACCESS2args ACCESS2args;

#define	ACCESS2_READ	0x1
#define	ACCESS2_LOOKUP	0x2
#define	ACCESS2_MODIFY	0x4
#define	ACCESS2_EXTEND	0x8
#define	ACCESS2_DELETE	0x10
#define	ACCESS2_EXECUTE	0x20

struct ACCESS2resok {
	struct nfsfattr attr;
	uint32 access;
};
typedef struct ACCESS2resok ACCESS2resok;

struct ACCESS2res {
	enum nfsstat status;
	union {
		ACCESS2resok ok;
	} res_u;
};
typedef struct ACCESS2res ACCESS2res;

struct GETXATTRDIR2args {
	fhandle_t fh;
	bool_t create;
};
typedef struct GETXATTRDIR2args GETXATTRDIR2args;

struct GETXATTRDIR2resok {
	fhandle_t fh;
	struct nfsfattr attr;
};
typedef struct GETXATTRDIR2resok GETXATTRDIR2resok;

struct GETXATTRDIR2res {
	enum nfsstat status;
	union {
		GETXATTRDIR2resok ok;
	} res_u;
};
typedef struct GETXATTRDIR2res GETXATTRDIR2res;

struct GETACL3args {
	nfs_fh3 fh;
	uint32 mask;
};
typedef struct GETACL3args GETACL3args;

struct GETACL3resok {
	post_op_attr attr;
	vsecattr_t acl;
};
typedef struct GETACL3resok GETACL3resok;

struct GETACL3resfail {
	post_op_attr attr;
};
typedef struct GETACL3resfail GETACL3resfail;

struct GETACL3res {
	nfsstat3 status;
	union {
		GETACL3resok ok;
		GETACL3resfail fail;
	} res_u;
};
typedef struct GETACL3res GETACL3res;

struct SETACL3args {
	nfs_fh3 fh;
	vsecattr_t acl;
};
typedef struct SETACL3args SETACL3args;

struct SETACL3resok {
	post_op_attr attr;
};
typedef struct SETACL3resok SETACL3resok;

struct SETACL3resfail {
	post_op_attr attr;
};
typedef struct SETACL3resfail SETACL3resfail;

struct SETACL3res {
	nfsstat3 status;
	union {
		SETACL3resok ok;
		SETACL3resfail fail;
	} res_u;
};
typedef struct SETACL3res SETACL3res;

struct GETXATTRDIR3args {
	nfs_fh3 fh;
	bool_t create;
};
typedef struct GETXATTRDIR3args GETXATTRDIR3args;

struct GETXATTRDIR3resok {
	nfs_fh3 fh;
	post_op_attr attr;
};
typedef struct GETXATTRDIR3resok GETXATTRDIR3resok;

struct GETXATTRDIR3res {
	nfsstat3 status;
	union {
		GETXATTRDIR3resok ok;
	} res_u;
};
typedef struct GETXATTRDIR3res GETXATTRDIR3res;

#define	NFS_ACL_PROGRAM	((rpcprog_t)(100227))
#define	NFS_ACL_VERSMIN	((rpcvers_t)(2))
#define	NFS_ACL_VERSMAX	((rpcvers_t)(3))

#define	NFS_ACL_V2		((rpcvers_t)(2))
#define	ACLPROC2_NULL		((rpcproc_t)(0))
#define	ACLPROC2_GETACL		((rpcproc_t)(1))
#define	ACLPROC2_SETACL		((rpcproc_t)(2))
#define	ACLPROC2_GETATTR	((rpcproc_t)(3))
#define	ACLPROC2_ACCESS		((rpcproc_t)(4))
#define	ACLPROC2_GETXATTRDIR	((rpcproc_t)(5))

#define	NFS_ACL_V3		((rpcvers_t)(3))
#define	ACLPROC3_NULL		((rpcproc_t)(0))
#define	ACLPROC3_GETACL		((rpcproc_t)(1))
#define	ACLPROC3_SETACL		((rpcproc_t)(2))
#define	ACLPROC3_GETXATTRDIR	((rpcproc_t)(3))

#ifdef _KERNEL
/* the xdr functions */
extern bool_t xdr_uid(XDR *, uid32_t *);
extern bool_t xdr_o_mode(XDR *, o_mode *);
extern bool_t xdr_aclent(XDR *, aclent_t *);
extern bool_t xdr_secattr(XDR *, vsecattr_t *);

extern bool_t xdr_GETACL2args(XDR *, GETACL2args *);
extern bool_t xdr_fastGETACL2args(XDR *, GETACL2args **);
extern bool_t xdr_GETACL2resok(XDR *, GETACL2resok *);
extern bool_t xdr_GETACL2res(XDR *, GETACL2res *);
extern bool_t xdr_SETACL2args(XDR *, SETACL2args *);
extern bool_t xdr_SETACL2resok(XDR *, SETACL2resok *);
#ifdef _LITTLE_ENDIAN
extern bool_t xdr_fastSETACL2resok(XDR *, SETACL2resok *);
#endif
extern bool_t xdr_SETACL2res(XDR *, SETACL2res *);
#ifdef _LITTLE_ENDIAN
extern bool_t xdr_fastSETACL2res(XDR *, SETACL2res *);
#endif
extern bool_t xdr_GETATTR2args(XDR *, GETATTR2args *);
extern bool_t xdr_fastGETATTR2args(XDR *, GETATTR2args **);
extern bool_t xdr_GETATTR2resok(XDR *, GETATTR2resok *);
#ifdef _LITTLE_ENDIAN
extern bool_t xdr_fastGETATTR2resok(XDR *, GETATTR2resok *);
#endif
extern bool_t xdr_GETATTR2res(XDR *, GETATTR2res *);
#ifdef _LITTLE_ENDIAN
extern bool_t xdr_fastGETATTR2res(XDR *, GETATTR2res *);
#endif
extern bool_t xdr_ACCESS2args(XDR *, ACCESS2args *);
extern bool_t xdr_fastACCESS2args(XDR *, ACCESS2args **);
extern bool_t xdr_ACCESS2resok(XDR *, ACCESS2resok *);
#ifdef _LITTLE_ENDIAN
extern bool_t xdr_fastACCESS2resok(XDR *, ACCESS2resok *);
#endif
extern bool_t xdr_ACCESS2res(XDR *, ACCESS2res *);
#ifdef _LITTLE_ENDIAN
extern bool_t xdr_fastACCESS2res(XDR *, ACCESS2res *);
#endif
extern bool_t xdr_GETXATTRDIR2args(XDR *, GETXATTRDIR2args *);
extern bool_t xdr_GETXATTRDIR2res(XDR *, GETXATTRDIR2res *);

extern bool_t xdr_GETACL3args(XDR *, GETACL3args *);
extern bool_t xdr_GETACL3resok(XDR *, GETACL3resok *);
extern bool_t xdr_GETACL3resfail(XDR *, GETACL3resfail *);
extern bool_t xdr_GETACL3res(XDR *, GETACL3res *);
extern bool_t xdr_SETACL3args(XDR *, SETACL3args *);
extern bool_t xdr_SETACL3resok(XDR *, SETACL3resok *);
extern bool_t xdr_SETACL3resfail(XDR *, SETACL3resfail *);
extern bool_t xdr_SETACL3res(XDR *, SETACL3res *);
extern bool_t xdr_GETXATTRDIR3args(XDR *, GETXATTRDIR3args *);
extern bool_t xdr_GETXATTRDIR3res(XDR *, GETXATTRDIR3res *);

#endif

#ifdef _KERNEL
/* the service procedures */
extern void acl2_getacl(GETACL2args *, GETACL2res *,
    struct exportinfo *, struct svc_req *, cred_t *, bool_t);
extern void *acl2_getacl_getfh(GETACL2args *);
extern void acl2_getacl_free(GETACL2res *);
extern void acl2_setacl(SETACL2args *, SETACL2res *,
    struct exportinfo *, struct svc_req *, cred_t *, bool_t);
extern void *acl2_setacl_getfh(SETACL2args *);
extern void acl2_getattr(GETATTR2args *, GETATTR2res *,
    struct exportinfo *, struct svc_req *, cred_t *, bool_t);
extern void *acl2_getattr_getfh(GETATTR2args *);
extern void acl2_access(ACCESS2args *, ACCESS2res *,
    struct exportinfo *, struct svc_req *, cred_t *, bool_t);
extern void *acl2_access_getfh(ACCESS2args *);
extern void acl2_getxattrdir(GETXATTRDIR2args *, GETXATTRDIR2res *,
    struct exportinfo *, struct svc_req *, cred_t *, bool_t);
extern void *acl2_getxattrdir_getfh(GETXATTRDIR2args *);

extern void acl3_getacl(GETACL3args *, GETACL3res *,
    struct exportinfo *, struct svc_req *, cred_t *, bool_t);
extern void *acl3_getacl_getfh(GETACL3args *);
extern void acl3_getacl_free(GETACL3res *);
extern void acl3_setacl(SETACL3args *, SETACL3res *,
    struct exportinfo *, struct svc_req *, cred_t *, bool_t);
extern void *acl3_setacl_getfh(SETACL3args *);
extern void acl3_getxattrdir(GETXATTRDIR3args *, GETXATTRDIR3res *,
    struct exportinfo *, struct svc_req *, cred_t *, bool_t);
extern void *acl3_getxattrdir_getfh(GETXATTRDIR3args *);

#endif

#ifdef _KERNEL
/* the client side procedures */
extern int acl_getacl2(vnode_t *, vsecattr_t *, int, cred_t *);
extern int acl_setacl2(vnode_t *, vsecattr_t *, int, cred_t *);
extern int acl_getattr2_otw(vnode_t *, vattr_t *, cred_t *);
extern int acl_access2(vnode_t *, int, int, cred_t *);
extern int acl_getxattrdir2(vnode_t *, vnode_t **, bool_t, cred_t *, int);
extern int acl_getacl3(vnode_t *, vsecattr_t *, int, cred_t *);
extern int acl_setacl3(vnode_t *, vsecattr_t *, int, cred_t *);
extern int acl_getxattrdir3(vnode_t *, vnode_t **, bool_t, cred_t *, int);
extern int acl2call(mntinfo_t *, rpcproc_t, xdrproc_t, caddr_t, xdrproc_t,
			caddr_t, cred_t *, int *, enum nfsstat *, int,
			failinfo_t *);
extern int acl3call(mntinfo_t *, rpcproc_t, xdrproc_t, caddr_t, xdrproc_t,
			caddr_t, cred_t *, int *, nfsstat3 *, int,
			failinfo_t *);
extern void nfs_acl_free(vsecattr_t *);
#endif

#ifdef _KERNEL
/* server and client data structures */
extern kstat_named_t	*aclproccnt_v2_ptr;
extern kstat_t		**aclprocio_v2_ptr;
extern kstat_named_t	*aclproccnt_v3_ptr;
extern kstat_t		**aclprocio_v3_ptr;

extern char		*aclnames_v2[];
extern uchar_t		acl_call_type_v2[];
extern uchar_t		acl_ss_call_type_v2[];
extern uchar_t		acl_timer_type_v2[];

extern char		*aclnames_v3[];
extern uchar_t		acl_call_type_v3[];
extern uchar_t		acl_ss_call_type_v3[];
extern uchar_t		acl_timer_type_v3[];
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_NFS_ACL_H */
