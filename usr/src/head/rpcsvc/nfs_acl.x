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
 *	Copyright 1994,2001-2003 Sun Microsystems, Inc.
 *	All rights reserved.
 *	Use is subject to license terms.
 */

/*
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

const NFS_ACL_MAX_ENTRIES = 1024;

typedef int uid;
typedef unsigned short o_mode;

/*
 * This is the format of an ACL which is passed over the network.
 */
struct aclent {
	int type;
	uid id;
	o_mode perm;
};

/*
 * The values for the type element of the aclent structure.
 */
const NA_USER_OBJ = 0x1;	/* object owner */
const NA_USER = 0x2;		/* additional users */
const NA_GROUP_OBJ = 0x4;	/* owning group of the object */
const NA_GROUP = 0x8;		/* additional groups */
const NA_CLASS_OBJ = 0x10;	/* file group class and mask entry */
const NA_OTHER_OBJ = 0x20;	/* other entry for the object */
const NA_ACL_DEFAULT = 0x1000;	/* default flag */

/*
 * The bit field values for the perm element of the aclent
 * structure.  The three values can be combined to form any
 * of the 8 combinations.
 */
const NA_READ = 0x4;		/* read permission */
const NA_WRITE = 0x2;		/* write permission */
const NA_EXEC = 0x1;		/* exec permission */

/*
 * This is the structure which contains the ACL entries for a
 * particular entity.  It contains the ACL entries which apply
 * to this object plus any default ACL entries which are
 * inherited by its children.
 *
 * The values for the mask field are defined below.
 */
struct secattr {
	u_int mask;
	int aclcnt;
	aclent aclent<NFS_ACL_MAX_ENTRIES>;
	int dfaclcnt;
	aclent dfaclent<NFS_ACL_MAX_ENTRIES>;
};

/*
 * The values for the mask element of the secattr struct as well
 * as for the mask element in the arguments in the GETACL2 and
 * GETACL3 procedures.
 */
const NA_ACL = 0x1;		/* aclent contains a valid list */
const NA_ACLCNT = 0x2;		/* the number of entries in the aclent list */
const NA_DFACL = 0x4;		/* dfaclent contains a valid list */
const NA_DFACLCNT = 0x8;	/* the number of entries in the dfaclent list */

/*
 * This the definition for the GETACL procedure which applies to
 * NFS Version 2.
 */
struct GETACL2args {
	fhandle_t fh;
	u_int mask;
};

struct GETACL2resok {
	struct nfsfattr attr;
	secattr acl;
};

union GETACL2res switch (enum nfsstat status) {
case ACL2_OK:
	GETACL2resok resok;
default:
	void;
};

/*
 * This is the definition for the SETACL procedure which applies
 * NFS Version 2.
 */
struct SETACL2args {
	fhandle_t fh;
	secattr acl;
};

struct SETACL2resok {
	struct nfsfattr attr;
};

union SETACL2res switch (enum nfsstat status) {
case ACL2_OK:
	SETACL2resok resok;
default:
	void;
};

/*
 * This is the definition for the GETATTR procedure which can be
 * used as an alternative to the GETATTR in NFS Version 2.  The
 * main difference between this GETATTR and the NFS GETATTR is
 * that this GETATTR returns the mode of the file without it being
 * changed to match the min/max permissions mapping that the NFS
 * Version 2 server does.
 */
struct GETATTR2args {
	fhandle_t fh;
};

struct GETATTR2resok {
	struct nfsfattr attr;
};

union GETATTR2res switch (enum nfsstat status) {
case ACL2_OK:
	GETATTR2resok resok;
default:
	void;
};

/*
 * This is the definition for the ACCESS procedure which applies
 * to NFS Version 2.
 */
struct ACCESS2args {
	fhandle_t fh;
	uint32 access;
};

/*
 * The following access permissions may be requested:
 */
const ACCESS2_READ = 0x1;	/* read data or readdir a directory */
const ACCESS2_LOOKUP = 0x2;	/* lookup a name in a directory */
const ACCESS2_MODIFY = 0x4;	/* rewrite existing file data or */
				/* modify existing directory entries */
const ACCESS2_EXTEND = 0x8;	/* write new data or add directory entries */
const ACCESS2_DELETE = 0x10;	/* delete existing directory entry */
const ACCESS2_EXECUTE = 0x20;	/* execute file (no meaning for a directory) */

struct ACCESS2resok {
	struct nfsfattr attr;
	uint32 access;
};

union ACCESS2res switch (enum nfsstat status) {
case ACL2_OK:
	ACCESS2resok resok;
default:
	void;
};

/*
 * This is the definition for the GETXATTRDIR procedure which applies
 * to NFS Version 2 files.
 */
struct GETXATTRDIR2args {
	fhandle_t fh;
	bool create;
};

struct GETXATTRDIR2resok {
	fhandle_t fh;
	struct nfsfattr attr;
};

union GETXATTRDIR2res switch (enum nfsstat status) {
case ACL2_OK:
	GETXATTRDIR2resok resok;
default:
	void;
};

/*
 * This is the definition for the GETACL procedure which applies
 * to NFS Version 3 files.
 */
struct GETACL3args {
	nfs_fh3 fh;
	u_int mask;
};

struct GETACL3resok {
	post_op_attr attr;
	secattr acl;
};

struct GETACL3resfail {
	post_op_attr attr;
};

union GETACL3res switch (nfsstat3 status) {
case ACL3_OK:
	GETACL3resok resok;
default:
	GETACL3resfail resfail;
};

/*
 * This is the definition for the SETACL procedure which applies
 * to NFS Version 3 files.
 */
struct SETACL3args {
	nfs_fh3 fh;
	secattr acl;
};

struct SETACL3resok {
	post_op_attr attr;
};

struct SETACL3resfail {
	post_op_attr attr;
};

union SETACL3res switch (nfsstat3 status) {
case ACL3_OK:
	SETACL3resok resok;
default:
	SETACL3resfail resfail;
};

/*
 * This is the definition for the GETXATTRDIR procedure which applies
 * to NFS Version 3 files.
 */
struct GETXATTRDIR3args {
	nfs_fh3 fh;
	bool create;
};

struct GETXATTRDIR3resok {
	nfs_fh3 fh;
	post_op_attr attr;
};

union GETXATTRDIR3res switch (nfsstat3 status) {
case ACL3_OK:
	GETXATTRDIR3resok resok;
default:
	void;
};

/*
 * XXX {
 * This is a transitional interface to enable Solaris NFSv4
 * clients to manipulate ACLs on Solaris servers until the
 * spec is complete enough to implement this inside the
 * NFSv4 protocol itself.  NFSv4 does handle extended
 * attributes in-band.
 */

/*
 * This is the definition for the GETACL procedure which applies
 * to NFS Version 4 files.
 */
struct GETACL4args {
	nfs_fh4 fh;
	u_int mask;
};

struct GETACL4resok {
	post_op_attr attr;
	secattr acl;
};

struct GETACL4resfail {
	post_op_attr attr;
};

union GETACL4res switch (nfsstat3 status) {
case ACL4_OK:
	GETACL4resok resok;
default:
	GETACL4resfail resfail;
};

/*
 * This is the definition for the SETACL procedure which applies
 * to NFS Version 4 files.
 */
struct SETACL4args {
	nfs_fh4 fh;
	secattr acl;
};

struct SETACL4resok {
	post_op_attr attr;
};

struct SETACL4resfail {
	post_op_attr attr;
};

union SETACL4res switch (nfsstat3 status) {
case ACL4_OK:
	SETACL4resok resok;
default:
	SETACL4resfail resfail;
};

/* XXX } */

/*
 * Share the port with the NFS service.  NFS has to be running
 * in order for this service to be useful anyway.
 */
const NFS_ACL_PORT = 2049;

/*
 * This is the definition for the ACL network protocol which is used
 * to provide support for Solaris ACLs for files which are accessed
 * via NFS Version 2 and NFS Version 3.
 */
program NFS_ACL_PROGRAM {
	version NFS_ACL_V2 {
		void
		 ACLPROC2_NULL(void) = 0;
		GETACL2res
		 ACLPROC2_GETACL(GETACL2args) = 1;
		SETACL2res
		 ACLPROC2_SETACL(SETACL2args) = 2;
		GETATTR2res
		 ACLPROC2_GETATTR(GETATTR2args) = 3;
		ACCESS2res
		 ACLPROC2_ACCESS(ACCESS2args) = 4;
		GETXATTRDIR2res
		 ACLPROC2_GETXATTRDIR(GETXATTRDIR2args) = 5;
	} = 2;
	version NFS_ACL_V3 {
		void
		 ACLPROC3_NULL(void) = 0;
		GETACL3res
		 ACLPROC3_GETACL(GETACL3args) = 1;
		SETACL3res
		 ACLPROC3_SETACL(SETACL3args) = 2;
		GETXATTRDIR3res
		 ACLPROC3_GETXATTRDIR(GETXATTRDIR3args) = 3;
	} = 3;
	version NFS_ACL_V4 {
		void
		 ACLPROC4_NULL(void) = 0;
		GETACL4res
		 ACLPROC4_GETACL(GETACL4args) = 1;
		SETACL4res
		 ACLPROC4_SETACL(SETACL4args) = 2;
	} = 4;
} = 100227;
