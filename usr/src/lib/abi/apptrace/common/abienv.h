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
 * Copyright (c) 1996-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _ABIENV_H
#define	_ABIENV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

typedef	struct liblist {
	char 		*l_libname;
	void		*l_handle;
	struct liblist	*l_next;
} Liblist;

typedef struct intlist {
	char		*i_name;
	struct intlist	*i_next;
} Intlist;

extern void		appendlist(Liblist **, Liblist **,
    char const *, int);
extern void		build_env_list(Liblist **, char const *);
extern void		build_env_list1(Liblist **, Liblist **, char const *);
extern Liblist		*check_list(Liblist *, char const *);
extern char		*checkenv(char const *);
extern int		build_interceptor_path(char *, size_t, char const *);
extern char		*abibasename(char const *);

extern void		env_to_intlist(Intlist **, char const *);
extern int		check_intlist(Intlist *, char const *);

#endif /* _ABIENV_H */
