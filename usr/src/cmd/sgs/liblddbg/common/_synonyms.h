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
 *	Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

#ifndef	_SYNONYMS_DOT_H
#define	_SYNONYMS_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Some synonyms definitions - ld.so.1 exports sufficient functions from its
 * libc contents for liblddbg to bind.  The intention is insure that liblddbg
 * doesn't require a dependency on libc itself, and thus debugging with the
 * runtime linker is as optimal as possible.
 */
#define	close	_close
#define	open	_open
#define	write	_write

#ifdef	__cplusplus
}
#endif

#endif /* _SYNONYMS_DOT_H */
