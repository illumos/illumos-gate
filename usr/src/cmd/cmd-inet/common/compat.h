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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _COMPAT_H
#define	_COMPAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for IPv4 compat defaults file reader.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	INET_DEFAULT_FILE	"/etc/default/inet_type"
#define	DEFAULT_IP		"DEFAULT_IP"

#define	DEFAULT_PROT_V4_ONLY	(1)
#define	DEFAULT_PROT_BOTH	(0)
#define	DEFAULT_PROT_BAD_VALUE	(-1)

extern int get_compat_flag(char **);

#ifdef __cplusplus
}
#endif

#endif /* _COMPAT_H */
