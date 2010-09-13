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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IPP_IPPCTL_H
#define	_IPP_IPPCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Header file for the IPP Policy Framework Configuration Driver
 *
 * WARNING: Everything in this file is private, belonging to the IPP
 * subsystem.  The interfaces and declarations made here are subject
 * to change.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * nvpair keys
 */

#define	IPPCTL_OP		"ippctl.op"
#define	IPPCTL_MODNAME		"ippctl.modname"
#define	IPPCTL_MODNAME_ARRAY	"ippctl.modname_array"
#define	IPPCTL_ANAME		"ippctl.aname"
#define	IPPCTL_ANAME_ARRAY	"ippctl.aname_array"
#define	IPPCTL_FLAGS		"ippctl.flags"
#define	IPPCTL_RC		"ippctl.rc"

/*
 * ioctl values
 */

#define	IPPCTL_BASE	('I' << 24 | 'P' << 16 | 'P' << 8)

#define	IPPCTL_CMD	(IPPCTL_BASE | 0x01)
#define	IPPCTL_DATA	(IPPCTL_BASE | 0x02)

/*
 * op values
 */

#define	IPPCTL_OP_ACTION_CREATE		0x00
#define	IPPCTL_OP_ACTION_MODIFY		0x01
#define	IPPCTL_OP_ACTION_DESTROY	0x02
#define	IPPCTL_OP_ACTION_INFO		0x03
#define	IPPCTL_OP_ACTION_MOD		0x04
#define	IPPCTL_OP_LIST_MODS		0x05
#define	IPPCTL_OP_MOD_LIST_ACTIONS	0x06

/*
 * ioctl structure
 */

typedef	struct ippctl_ioctl {
	caddr_t		ii_buf;
	size_t		ii_buflen;
} ippctl_ioctl_t;

#ifdef	_SYSCALL32
typedef	struct ippctl_ioctl32 {
	caddr32_t	ii32_buf;
	size32_t	ii32_buflen;
} ippctl_ioctl32_t;
#endif /* _SYSCALL32 */

#ifdef __cplusplus
}
#endif

#endif /* _IPP_IPPCTL_H */
