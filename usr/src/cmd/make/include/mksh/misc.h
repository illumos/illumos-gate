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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2019 RackTop Systems.
 */

#ifndef _MKSH_MISC_H
#define	_MKSH_MISC_H

#include <mksh/defs.h>

extern void	append_char(wchar_t, String);
extern Property	append_prop(Name, Property_id);
extern void	append_string(wchar_t *, String, int);
extern void	enable_interrupt(void (*) (int));
extern char	*errmsg(int);
extern void	fatal_mksh(const char *, ...) __NORETURN;
extern void	fatal_reader_mksh(const char *, ...) __NORETURN;
extern char	*get_current_path_mksh(void);
extern Property	get_prop(Property, Property_id);
extern char	*getmem(size_t);
extern Name	getname_fn(wchar_t *name, int len, Boolean dont_enter,
		    Boolean *foundp = NULL);
extern void	store_name(Name);
extern void	free_name(Name);
extern void	handle_interrupt_mksh(int);
extern Property	maybe_append_prop(Name, Property_id);
extern void	retmem(wchar_t *);
extern void	retmem_mb(caddr_t);
extern void	setup_char_semantics(void);
extern void	setup_interrupt(void (*) (int));
extern void	warning_mksh(char *, ...);

extern void	append_string(char *, String, int);
extern wchar_t	*get_wstring(char *);


#endif /* _MKSH_MISC_H */
