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
 * Copyright 1996-1999, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

const WNL_PORT          = 2049;
const WNL_MAXDATA       = 8192;
const WNL_MAXNAMLEN	= 255;
const WNL_FHSIZE	= 32;
const WNL_FIFO_DEV	= -1;	/* size kludge for named pipes */

/*
 * Indicator for native path semantics.
 */
const WNL_NATIVEPATH	= 0x80;

/*
 * Indicator for security negotiation.
 */
const WNL_SEC_NEGO	= 0x81;

/*
 * File types
 */
const WNLMODE_FMT  = 0170000;	/* type of file */
const WNLMODE_DIR  = 0040000;	/* directory */
const WNLMODE_CHR  = 0020000;	/* character special */
const WNLMODE_BLK  = 0060000;	/* block special */
const WNLMODE_REG  = 0100000;	/* regular */
const WNLMODE_LNK  = 0120000;	/* symbolic link */
const WNLMODE_SOCK = 0140000;	/* socket */
const WNLMODE_FIFO = 0010000;	/* fifo */

/*
 * Error status
 */
enum wnl_stat {
	WNL_OK= 0,		/* no error */
	WNLERR_PERM=1,		/* Not owner */
	WNLERR_NOENT=2,		/* No such file or directory */
	WNLERR_IO=5,		/* I/O error */
	WNLERR_NXIO=6,		/* No such device or address */
	WNLERR_ACCES=13,	/* Permission denied */
	WNLERR_EXIST=17,	/* File exists */
	WNLERR_XDEV=18,		/* Cross-device link */
	WNLERR_NODEV=19,	/* No such device */
	WNLERR_NOTDIR=20,	/* Not a directory*/
	WNLERR_ISDIR=21,	/* Is a directory */
	WNLERR_INVAL=22,	/* Invalid argument */
	WNLERR_FBIG=27,		/* File too large */
	WNLERR_NOSPC=28,	/* No space left on device */
	WNLERR_ROFS=30,		/* Read-only file system */
	WNLERR_OPNOTSUPP=45,	/* Operation not supported */
	WNLERR_NAMETOOLONG=63,	/* File name too long */
	WNLERR_NOTEMPTY=66,	/* Directory not empty */
	WNLERR_DQUOT=69,	/* Disc quota exceeded */
	WNLERR_STALE=70,	/* Stale WNL file handle */
	WNLERR_REMOTE=71,	/* Object is remote */
	WNLERR_WFLUSH=72	/* write cache flushed */
};

/*
 * File types
 */
enum wnl_ftype {
	WNL_NON = 0,	/* non-file */
	WNL_REG = 1,	/* regular file */
	WNL_DIR = 2,	/* directory */
	WNL_BLK = 3,	/* block special */
	WNL_CHR = 4,	/* character special */
	WNL_LNK = 5,	/* symbolic link */
	WNL_SOCK = 6,	/* unix domain sockets */
	WNL_BAD = 7,	/* unused */
	WNL_FIFO = 8 	/* named pipe */
};

/*
 * File access handle
 */
struct wnl_fh {
	opaque data[WNL_FHSIZE];
};

/* 
 * Timeval
 */
struct wnl_time {
	unsigned seconds;
	unsigned useconds;
};


/*
 * File attributes
 */
struct wnl_fattr {
	wnl_ftype type;		/* file type */
	unsigned mode;		/* protection mode bits */
	unsigned nlink;		/* # hard links */
	unsigned uid;		/* owner user id */
	unsigned gid;		/* owner group id */
	unsigned size;		/* file size in bytes */
	unsigned blocksize;	/* prefered block size */
	unsigned rdev;		/* special device # */
	unsigned blocks;	/* Kb of disk used by file */
	unsigned fsid;		/* device # */
	unsigned fileid;	/* inode # */
	wnl_time	atime;		/* time of last access */
	wnl_time	mtime;		/* time of last modification */
	wnl_time	ctime;		/* time of last change */
};

typedef string wnl_filename<WNL_MAXNAMLEN>; 

/*
 * Arguments for directory operations
 */
struct wnl_diropargs {
	wnl_fh	dir;	/* directory file handle */
	wnl_filename name;		/* name (up to WNL_MAXNAMLEN bytes) */
};

struct wnl_diropokres {
	wnl_fh file;
	wnl_fattr attributes;
};

/*
 * Results from directory operation
 */
union wnl_diropres switch (wnl_stat status) {
case WNL_OK:
	wnl_diropokres wnl_diropres;
default:
	void;
};

/*
 * Version 3 declarations and definitions.
 */

/*
 * Sizes
 */
const WNL3_FHSIZE         = 64;

/*
 * Basic data types
 */
typedef unsigned hyper	wnl_uint64;
typedef hyper		wnl_int64;
typedef unsigned int	wnl_uint32;
typedef string		wnl_filename3<>;
typedef wnl_uint64	wnl_fileid3;
typedef wnl_uint32	wnl_uid3;
typedef wnl_uint32	wnl_gid3;
typedef wnl_uint64	wnl_size3;
typedef wnl_uint32	wnl_mode3;

/*
 * Error status
 */
enum wnl_stat3 {
	WNL3_OK = 0,
	WNL3ERR_PERM = 1,
	WNL3ERR_NOENT = 2,
	WNL3ERR_IO = 5,
	WNL3ERR_NXIO = 6,
	WNL3ERR_ACCES = 13,
	WNL3ERR_EXIST = 17,
	WNL3ERR_XDEV = 18,
	WNL3ERR_NODEV = 19,
	WNL3ERR_NOTDIR = 20,
	WNL3ERR_ISDIR = 21,
	WNL3ERR_INVAL = 22,
	WNL3ERR_FBIG = 27,
	WNL3ERR_NOSPC = 28,
	WNL3ERR_ROFS = 30,
	WNL3ERR_MLINK = 31,
	WNL3ERR_NAMETOOLONG = 63,
	WNL3ERR_NOTEMPTY = 66,
	WNL3ERR_DQUOT = 69,
	WNL3ERR_STALE = 70,
	WNL3ERR_REMOTE = 71,
	WNL3ERR_BADHANDLE = 10001,
	WNL3ERR_NOT_SYNC = 10002,
	WNL3ERR_BAD_COOKIE = 10003,
	WNL3ERR_NOTSUPP = 10004,
	WNL3ERR_TOOSMALL = 10005,
	WNL3ERR_SERVERFAULT = 10006,
	WNL3ERR_BADTYPE = 10007,
	WNL3ERR_JUKEBOX = 10008
};

/*
 * File types
 */
enum wnl_ftype3 {
	WNL_3REG = 1,
	WNL_3DIR = 2,
	WNL_3BLK = 3,
	WNL_3CHR = 4,
	WNL_3LNK = 5,
	WNL_3SOCK = 6,
	WNL_3FIFO = 7
};

struct wnl_specdata3 {
	wnl_uint32	specdata1;
	wnl_uint32	specdata2;
};

/*
 * File access handle
 */
struct wnl_fh3 {
	opaque data<WNL3_FHSIZE>;
};

/* 
 * Timeval
 */
struct wnl_time3 {
	wnl_uint32 seconds;
	wnl_uint32 nseconds;
};

/*
 * File attributes
 */
struct wnl_fattr3 {
	wnl_ftype3	  type;
	wnl_mode3	  mode;
	wnl_uint32	  nlink;
	wnl_uid3	  uid;
	wnl_gid3	  gid;
	wnl_size3	  size;
	wnl_size3	  used;
	wnl_specdata3 rdev;
	wnl_uint64	  fsid;
	wnl_fileid3	  fileid;
	wnl_time3  atime;
	wnl_time3  mtime;
	wnl_time3  ctime;
};

/*
 * File attributes
 */
union wnl_post_op_attr switch (bool attributes_follow) {
case TRUE:
	wnl_fattr3 attributes;
case FALSE:
	void;
};	

union wln_post_op_fh3 switch (bool handle_follows) {
case TRUE:
	wnl_fh3 handle;
case FALSE:
	void;
};

struct wnl_diropargs3 {
	wnl_fh3   dir;
	wnl_filename3 name;
};

/*
 * LOOKUP: Lookup wnl_filename
 */
struct WNL_LOOKUP3args {
	wnl_diropargs3 what;
};

struct WNL_LOOKUP3resok {
	wnl_fh3		object;
	wnl_post_op_attr	obj_attributes;
	wnl_post_op_attr	dir_attributes;
};

struct WNL_LOOKUP3resfail {
	wnl_post_op_attr	dir_attributes;
};

union WNL_LOOKUP3res switch (wnl_stat3 status) {
case WNL3_OK:
	WNL_LOOKUP3resok	res_ok;
default:
	WNL_LOOKUP3resfail	res_fail;
};

const MAX_FLAVORS	= 128;

struct snego_t {
	int cnt;
	int array[MAX_FLAVORS];
};

enum snego_stat {
	/* default flavor invalid and a flavor has been negotiated */
	SNEGO_SUCCESS = 0,

	/* default flavor valid, no need to negotiate flavors */
	SNEGO_DEF_VALID = 1,

	/* array size too small */
	SNEGO_ARRAY_TOO_SMALL = 2,

	SNEGO_FAILURE = 3
};

/*
 * Remote file service routines
 */
program WNL_PROGRAM {
	version WNL_V2 {
		void 
		WNLPROC_NULL(void) = 0;

		wnl_diropres 
		WNLPROC_LOOKUP(wnl_diropargs) = 4;
	} = 2;

	version WNL_V3 {
		void 
		WNLPROC3_NULL(void) = 0;

		WNL_LOOKUP3res 
		WNLPROC3_LOOKUP(WNL_LOOKUP3args) = 3;
	} = 3;

	version WNL_V4 {
		void
		WNLPROC4_NULL(void) = 0;
	} = 4;

} = 100003;
