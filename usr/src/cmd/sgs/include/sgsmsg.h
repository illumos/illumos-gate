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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SGSMSG_DOT_H
#define	_SGSMSG_DOT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	__lint

/*
 * In normal operation, sgsmsg generates an ELF-format string table
 * for strings, and Msg is an integer offset into that table.
 */
typedef int	Msg;

#else	/* __lint */

/*
 * When __lint is defined, Msg is a char *.  This allows lint to
 * check our format strings against its arguments.
 */
typedef char	*Msg;

#endif	/* __lint */


#ifdef __cplusplus
}
#endif

#endif /* _SGSMSG_DOT_H */
