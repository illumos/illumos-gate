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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MSGDEFS_H
#define	_MSGDEFS_H


#ifdef __cplusplus
extern "C" {
#endif

#define	ERR_USAGE   "usage:\n" \
	"\tpkginstall [-o] [-n] [-d device] " \
	"[-m mountpt [-f fstype]] [-v] " \
	"[[-M] -R host_path] [-V fs_file] [-b bindir] [-a admin_file] " \
	"[-r resp_file] [-N calling_prog] directory pkginst\n"

#define	ERR_STREAMDIR	"unable to make temporary directory to unpack " \
		"datastream: %s"
#define	ERR_CANNOT_USE_DIR	"cannot use directory <%s>: %s"
#define	ERR_PATH "the path <%s> is invalid!"

#define	ERR_CHDIR	"unable to change current working directory to <%s>"
#define	MSG_MANMOUNT	"Assuming mounts have been provided."
#define	ERR_DB		"unable to query or modify database"
#define	ERR_DB_TBL	"unable to remove database entries for package <%s> " \
			"in table <%s>."
#define	ERR_DSARCH	"unable to find archive for <%s> in datastream"
#define	ERR_CREAT_CONT  "unable to create contents file <%s>"
#define	ERR_LIVE_CONTINUE_NOT_SUPPORTED	"live continue mode is not supported"
#define	ERR_ROOT_SET	"Could not set install root from the environment."
#define	ERR_ROOT_CMD	"Command line install root contends with environment."
#define	ERR_MEMORY	  "memory allocation failure, errno=%d"
#define	ERR_SNPRINTF "Not enough memory to format, %s"
#define	ERR_INTONLY	 "unable to install <%s> without user interaction"
#define	ERR_NOREQUEST   "package does not contain an interactive request script"
#define	ERR_LOCKFILE	"unable to create lockfile <%s>"
#define	ERR_PKGINFO	"unable to open pkginfo file <%s>"
#define	ERR_PKGBINCP	"unable to copy <%s>\n\tto <%s>"
#define	ERR_PKGBINREN   "unable to rename <%s>\n\tto <%s>"
#define	ERR_RESPONSE	"unable to open response file <%s>"
#define	ERR_PKGMAP	"unable to open pkgmap file <%s>"
#define	ERR_MKDIR	"unable to make temporary directory <%s>"
#define	ERR_ADMBD	"%s is already installed at %s. Admin file will " \
			"force a duplicate installation at %s."
#define	ERR_NEWBD	"%s is already installed at %s. Duplicate " \
			"installation attempted at %s."
#define	ERR_DSTREAM	"unable to unpack datastream"
#define	ERR_DSTREAMCNT  "datastream early termination problem"
#define	ERR_RDONLY	"read-only parameter <%s> cannot be assigned a value"
#define	ERR_REQUEST	"request script did not complete successfully"
#define	WRN_CHKINSTALL  "checkinstall script suspends"
#define	ERR_CHKINSTALL  "checkinstall script did not complete successfully"
#define	ERR_PREINSTALL  "preinstall script did not complete successfully"
#define	ERR_POSTINSTALL "postinstall script did not complete successfully"
#define	ERR_OPRESVR4	"unable to unlink options file <%s>"
#define	ERR_SYSINFO	"unable to process installed package information, " \
			"errno=%d"
#define	ERR_BADULIMIT   "cannot process invalid ULIMIT value of <%s>."
#define	MSG_INST_ONE	"   %d package pathname is already properly installed."
#define	MSG_INST_MANY   "   %d package pathnames are already properly " \
			"installed."
#define	ERR_PATCHPKG	"unable to update patch_table with patches that " \
			"have been pre installed"
#define	SPECIAL_MALLOC	"unable to maintain package contents text due to "\
			"insufficient memory: %s"
#define	SPECIAL_ACCESS	"unable to maintain package contents text due to "\
			"an access failure: %s"
#define	SPECIAL_MAP	"unable to maintain package contents text due to "\
			"a failure to map the database into memory: %S"
#define	SPECIAL_INPUT	"unable to maintain package contents text: alternate "\
			"root path too long"

#ifdef __cplusplus
}
#endif

#endif	/* _MSGDEFS_H */
