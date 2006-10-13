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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_VOLMGT_PRIVATE_H
#define	_VOLMGT_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interfaces that are private to the volmgt library.
 */
char 	*volmgt_getfullblkname(char *n);
char 	*volmgt_getfullrawname(char *n);

#ifndef	TRUE
#define	TRUE		1
#define	FALSE		0
#endif

#ifndef	NULLC
#define	NULLC		'\0'
#endif

#ifdef	DEBUG
/* for debugging */
void	denter(char *, ...);
void	dexit(char *, ...);
void	dprintf(char *, ...);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _VOLMGT_PRIVATE_H */
