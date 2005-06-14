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
 * Copyright (c) 1995-1996, by Sun Microsystems, Inc.
 * All rights reserved.
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
char 	*getrawpart0(char *path);
char 	*volmgt_getfullblkname(char *n);
char 	*volmgt_getfullrawname(char *n);
char 	*volmgt_completename(char *name);
char	*concat_paths(char *s, char *head, char *tail, char *opt_tail2);

#define	DEFAULT_ROOT	"/vol"
#define	DEFAULT_CONFIG	"/etc/vold.conf"
#define	MAXARGC		100

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
