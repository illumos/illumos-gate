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

#ifndef	_SYSEVENTADM_MSG_H
#define	_SYSEVENTADM_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Gettext strings for internationalization
 */
#define	MSG_NOT_ROOT	\
	gettext("%s: must be root\n")

#define	MSG_NOT_GLOBAL	\
	gettext("%s: must be in global zone\n")

#define	MSG_CANNOT_CREATE	\
	gettext("%s: cannot create %s - %s\n")

#define	MSG_CANNOT_OPEN	\
	gettext("%s: cannot open %s - %s\n")

#define	MSG_CLOSE_ERROR	\
	gettext("%s: close of %s failed - %s\n")

#define	MSG_CHMOD_ERROR	\
	gettext("%s: cannot chmod %s to 0444 - %s\n")

#define	MSG_CANNOT_OPEN_DIR	\
	gettext("%s: cannot open directory %s - %s\n")

#define	MSG_CLOSE_DIR_ERROR	\
	gettext("%s: close of directory %s failed - %s\n")

#define	MSG_TMP_FILE	\
	gettext("%s: unable to make tmp file name\n")

#define	MSG_CANNOT_UNLINK	\
	gettext("%s: cannot unlink %s - %s\n")

#define	MSG_CANNOT_RENAME	\
	gettext("%s: cannot rename %s to %s - %s\n")

#define	MSG_RESTART_FAILED	\
	gettext("%s: restart failed - %s\n")

#define	MSG_NO_MEM	\
	gettext("%s: out of memory\n")

#define	MSG_USAGE_INTRO	\
	gettext("usage: syseventadm <cmd> ...\n")

#define	MSG_USAGE_OPTIONS	\
	gettext("where the possible commands and options for each are:\n")

#define	MSG_LOCK_CREATE_ERR	\
	gettext("%s: error creating lock %s - %s\n")

#define	MSG_LOCK_PATH_ERR	\
	gettext("%s: error creating lock %s - file path invalid\n")

#define	MSG_LOCK_SET_ERR	\
	gettext("%s: error setting lock in %s - %s\n")

#define	MSG_LOCK_CLR_ERR	\
	gettext("%s: error clearing lock in %s - %s\n")

#define	MSG_LOCK_CLOSE_ERR	\
	gettext("%s: error closing lock %s - %s\n")

#ifdef	__cplusplus
}
#endif

#endif	/* _SYSEVENTADM_MSG_H */
