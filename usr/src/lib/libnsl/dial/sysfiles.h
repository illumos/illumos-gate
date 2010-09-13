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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _DIAL_SYSFILES_H
#define	_DIAL_SYSFILES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	SYSDIR		(const char *)"/etc/uucp"
#define	SYSFILES	(const char *)"/etc/uucp/Sysfiles"
#define	SYSTEMS		(const char *)"/etc/uucp/Systems"
#define	DEVICES		(const char *)"/etc/uucp/Devices"
#define	DIALERS		(const char *)"/etc/uucp/Dialers"
#define	DEVCONFIG	(const char *)"/etc/uucp/Devconfig"
#define	CONFIG		(const char *)"/etc/uucp/Config"

#define	SAME	0
#define	TRUE	1
#define	FALSE	0
#define	FAIL	-1

/* flags to check file access for REAL user id */
#define	ACCESS_SYSTEMS	1
#define	ACCESS_DEVICES	2
#define	ACCESS_DIALERS	3

/* flags to check file access for EFFECTIVE user id */
#define	EACCESS_SYSTEMS	4
#define	EACCESS_DEVICES	5
#define	EACCESS_DIALERS	6

#ifdef __cplusplus
}
#endif

#endif /* _DIAL_SYSFILES_H */
