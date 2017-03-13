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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PKGLIBMSGS_H
#define	_PKGLIBMSGS_H


#ifdef __cplusplus
extern "C" {
#endif

/* srchcfile messages */
#define	ERR_MISSING_NEWLINE	"missing newline at end of entry"
#define	ERR_ILLEGAL_SEARCH_PATH	"illegal search path specified"
#define	ERR_CANNOT_READ_MM_NUMS	"unable to read major/minor device numbers"
#define	ERR_INCOMPLETE_ENTRY	"incomplete entry"
#define	ERR_VOLUMENO_UNEXPECTED	"volume number not expected"
#define	ERR_FTYPE_I_UNEXPECTED	"ftype <i> not expected"
#define	ERR_CANNOT_READ_CLASS_TOKEN	"unable to read class token"
#define	ERR_CANNOT_READ_PATHNAME_FLD	"unable to read pathname field"
#define	ERR_UNKNOWN_FTYPE	"unknown ftype"
#define	ERR_CANNOT_READ_LL_PATH	"unable to read local/link path"
#define	ERR_INCOMPLETE_ENTRY	"incomplete entry"
#define	ERR_NO_LINK_SOURCE_SPECIFIED	"no link source specified"
#define	ERR_CANNOT_READ_MOG	"unable to read mode/owner/group"
#define	ERR_CANNOT_READ_CONTENT_INFO	"unable to read content info"
#define	ERR_PACKAGE_NAME_TOO_LONG	"package name too long"
#define	ERR_NO_MEMORY	"no memory for package information"
#define	ERR_BAD_ENTRY_END	"bad end of entry"
#define	ERR_EXTRA_TOKENS	"extra token(s) on input line"

/* pkgtrans messages */
#define	MSG_TRANSFER	"Transferring <%s> package instance\n"
#define	MSG_RENAME 	"\t... instance renamed <%s> on destination\n"

#define	ERR_TRANSFER	"unable to complete package transfer"
#define	MSG_SEQUENCE	"- volume is out of sequence"
#define	MSG_MEM		"- no memory"
#define	MSG_CMDFAIL	"- process <%s> failed, exit code %d"
#define	MSG_POPEN	"- popen of <%s> failed, errno=%d"
#define	MSG_PCLOSE	"- pclose of <%s> failed, errno=%d"
#define	MSG_BADDEV	"- invalid or unknown device <%s>"
#define	MSG_GETVOL	"- unable to obtain package volume"
#define	MSG_NOSIZE 	"- unable to obtain maximum part size from pkgmap"
#define	MSG_CHDIR	"- unable to change directory to <%s>"
#define	MSG_SYMLINK	"- unable to create symbolic link to <%s> from <%s>"
#define	MSG_STATDIR	"- unable to stat <%s>"
#define	MSG_CHOWNDIR	"- unable to chown <%s>"
#define	MSG_CHMODDIR	"- unable to chmod <%s>"
#define	MSG_FSTYP	"- unable to determine filesystem type for <%s>"
#define	MSG_NOTEMP	"- unable to create or use temporary directory <%s>"
#define	MSG_SAMEDEV	"- source and destination represent the same device"
#define	MSG_NOTMPFIL	"- unable to create or use temporary file <%s>"
#define	MSG_NOPKGMAP	"- unable to open pkgmap for <%s>"
#define	MSG_BADPKGINFO	"- unable to determine contents of pkginfo file"
#define	MSG_NOPKGS	"- no packages were selected from <%s>"
#define	MSG_MKDIR	"- unable to make directory <%s>"
#define	MSG_NOEXISTS	"- package instance <%s> does not exist on source " \
			"device"
#define	MSG_EXISTS	"- no permission to overwrite existing path <%s>"
#define	MSG_DUPVERS	"- identical version of <%s> already exists on " \
			"destination device"
#define	MSG_TWODSTREAM	"- both source and destination devices cannot be a " \
			"datastream"
#define	MSG_OPEN	"- open of <%s> failed, errno=%d"
#define	MSG_STATVFS	"- statvfs(%s) failed, errno=%d"

/* parameter errors */
#define	ERR_LEN		"length of parameter <%s> value exceeds limit"
#define	ERR_ASCII	"parameter <%s> must be ascii"
#define	ERR_ALNUM	"parameter <%s> must be alphanumeric"
#define	ERR_CHAR	"parameter <%s> has incorrect first character"
#define	ERR_UNDEF	"parameter <%s> cannot be null"

/* volume sequence errors */
#define	MSG_SEQ		"Volume is out of sequence."
#define	MSG_CORRUPT	"Volume is corrupt or is not part of the appropriate " \
			"package."
#define	ERR_NOPKGMAP	"ERROR: unable to process <%s>"
#define	ERR_BADPKGINFO	"ERROR: unable to process <%s>"

/* datastream processing errors */
#define	ERR_UNPACK	"attempt to process datastream failed"
#define	ERR_DSTREAMSEQ	"datastream sequence corruption"
#define	ERR_TRANSFER    "unable to complete package transfer"
#define	MSG_CMDFAIL	"- process <%s> failed, exit code %d"
#define	MSG_TOC		"- bad format in datastream table-of-contents"
#define	MSG_EMPTY	"- datastream table-of-contents appears to be empty"
#define	MSG_POPEN	"- popen of <%s> failed, errno=%d"
#define	MSG_OPEN	"- open of <%s> failed, errno=%d"
#define	MSG_PCLOSE	"- pclose of <%s> failed, errno=%d"
#define	MSG_PKGNAME	"- invalid package name in datastream table-of-contents"
#define	MSG_NOPKG	"- package <%s> not in datastream"
#define	MSG_STATFS	"- unable to stat filesystem, errno=%d"
#define	MSG_NOSPACE	"- not enough space, %ld blocks required, "\
			"%lld available"

/* pkglist errors */
#define	ERR_MEMORY	"memory allocation failure, errno=%d"
#define	ERR_NOPKG	"no package associated with <%s>"
#define	HEADER		"The following packages are available:"
#define	HELP		"Please enter the package instances you wish to " \
			"process from the list provided (or 'all' to process " \
			"all packages.)"

#define	PROMPT		"Select package(s) you wish to process (or 'all' to " \
			"process all packages)."
/* pkgmap errors */
#define	ERR_READLINK	"unable to read link specification."
#define	ERR_NOVAR	"no value defined for%s variable <%s>."
#define	ERR_OWNTOOLONG	"owner string is too long."
#define	ERR_GRPTOOLONG	"group string is too long."
#define	ERR_IMODE	"mode must not be parametric at install time."
#define	ERR_BASEINVAL	"invalid base for mode."
#define	ERR_MODELONG	"mode string is too long."
#define	ERR_MODEALPHA	"mode is not numeric."
#define	ERR_MODEBITS	"invalid bits set in mode."

/* package mount errors and msgs */
#define	ERR_FSTYP	"unable to determine fstype for <%s>"
#define	ERR_NOTROOT	"You must be \"root\" when using mountable media."
#define	MOUNT		"/sbin/mount"
#define	UMOUNT		"/sbin/umount"
#define	FSTYP		"/usr/sbin/fstyp"

#define	LABEL0	"Insert %%v %d of %d for <%s> package into %%p."
#define	LABEL1	"Insert %%v %d of %d into %%p."
#define	LABEL2	"Insert %%v for <%s> package into %%p."
#define	LABEL3	"Insert %%v into %%p."

/* package verify errors */
#define	MSG_WLDDEVNO	"NOTE: <%s> created as device (%ld, %ld)."

#define	WRN_QV_SIZE	"WARNING: quick verify of <%s>; wrong size."
#define	WRN_QV_MTIME	"WARNING: quick verify of <%s>; wrong mod time."

#define	ERR_PKG_INTERNAL "Internal package library failure file %s line %d"
#define	ERR_UNKNOWN	"unable to determine object type"
#define	ERR_EXIST	"pathname does not exist"
#define	ERR_FTYPE	"file type <%c> expected <%c> actual"
#define	ERR_FTYPED	"<%s> is a door and is not being modified"
#define	ERR_LINK	"pathname not properly linked to <%s>"
#define	ERR_SLINK	"pathname not symbolically linked to <%s>"
#define	ERR_MTIME	"modtime <%s> expected <%s> actual"
#define	ERR_SIZE	"file size <%llu> expected <%llu> actual"
#define	ERR_CKSUM	"file cksum <%ld> expected <%ld> actual"
#define	ERR_NO_CKSUM	"unable to checksum, may need to re-run command as " \
			"user \"root\""
#define	ERR_MAJMIN	"major/minor device <%ld, %ld> " \
			"expected <%ld, %ld> actual"
#define	ERR_PERM	"permissions <%04lo> expected <%04lo> actual"
#define	ERR_GROUP	"group name <%s> expected <%s> actual"
#define	ERR_OWNER	"owner name <%s> expected <%s> actual"
#define	ERR_MODFAIL	"unable to fix modification time"
#define	ERR_LINKFAIL	"unable to create link to <%s>"
#define	ERR_LINKISDIR	"<%s> is a directory, link() not performed"
#define	ERR_SLINKFAIL	"unable to create symbolic link to <%s>"
#define	ERR_DIRFAIL	"unable to create directory"
#define	ERR_CDEVFAIL	"unable to create character-special device"
#define	ERR_BDEVFAIL	"unable to create block-special device"
#define	ERR_PIPEFAIL	"unable to create named pipe"
#define	ERR_ATTRFAIL	"unable to fix attributes"
#define	ERR_BADGRPID	"unable to determine group name for gid <%d>"
#define	ERR_BADUSRID	"unable to determine owner name for uid <%d>"
#define	ERR_BADGRPNM	"group name <%s> not found in group table(s)"
#define	ERR_BADUSRNM	"owner name <%s> not found in passwd table(s)"
#define	ERR_GETWD	"unable to determine current working directory"
#define	ERR_CHDIR	"unable to change current working directory to <%s>"
#define	ERR_RMDIR	"unable to remove existing directory at <%s>"

/* others */
#define	ERR_ISCPIO_OPEN		"iscpio(): open(%s) failed!"
#define	ERR_ISCPIO_FSTAT	"iscpio(): fstat(%s) failed!"
#define	ERR_ISCPIO_READ		"iscpio(): read(%s) failed!"
#define	ERR_ISCPIO_NOCPIO	"iscpio(): <%s> is not a cpio archive!"

#define	ERR_DUPFAIL	"%s: strdup(%s) failed.\n"
#define	ERR_ADDFAIL	"%s: add_cache() failed.\n"
#define	ERR_BADMEMB	"%s: %s in \"%s\" %s structure is invalid.\n"
#define	ERR_NOGRP	"dup_gr_ent(): no group entry provided.\n"
#define	ERR_NOPWD	"dup_pw_ent(): no passwd entry provided.\n"
#define	ERR_NOINIT	"%s: init_cache() failed.\n"
#define	ERR_MALLOC	"%s: malloc(%d) failed for %s.\n"

#define	ERR_TOO_MANY_ARGS	"too many arguments passed to pkgexecl " \
				"for command <%s>"
#define	ERR_WAIT_FAILED	"wait for process %ld failed, status " \
			"<0x%08x> errno <%d> (%s)"
#define	ERR_FORK_FAILED	"fork() failed errno=%d (%s)"
#define	ERR_FREOPEN	"freopen(%s, \"%s\", %s) failed, errno=%d (%s)"
#define	ERR_FDOPEN	"fdopen(%d, \"%s\") failed, errno=%d (%s)"
#define	ERR_CLOSE	"close(%d) failed, errno=%d"
#define	ERR_SETGID	"setgid(%d) failed."
#define	ERR_SETUID	"setuid(%d) failed."
#define	ERR_EX_FAIL	"exec of %s failed, errno=%d"

#define	ERR_MEM "unable to allocate memory."

#define	MSG_BASE_USED   "Using <%s> as the package base directory."

#ifdef __cplusplus
}
#endif

#endif /* _PKGLIBMSGS_H */
