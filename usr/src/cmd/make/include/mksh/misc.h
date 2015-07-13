#ifndef _MKSH_MISC_H
#define _MKSH_MISC_H
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
 */

#include <mksh/defs.h>

extern void	append_char(wchar_t from, register String to);
extern Property	append_prop(register Name target, register Property_id type);
extern void	append_string(register wchar_t *from, register String to, register int length);
extern void	enable_interrupt(register void (*handler) (int));
extern char	*errmsg(int errnum);
extern void	fatal_mksh(const char *message, ...);
extern void	fatal_reader_mksh(const char *pattern, ...);
extern char	*get_current_path_mksh(void);
extern Property	get_prop(register Property start, register Property_id type);
extern char	*getmem(register int size);
extern Name	getname_fn(wchar_t *name, register int len, register Boolean dont_enter, register Boolean * foundp = NULL);
extern void	store_name(Name name);
extern void	free_name(Name name);
extern void	handle_interrupt_mksh(int);
extern Property	maybe_append_prop(register Name target, register Property_id type);
extern void	retmem(wchar_t *p);
extern void	retmem_mb(caddr_t p);
extern void	setup_char_semantics(void);
extern void	setup_interrupt(register void (*handler) (int));
extern void	warning_mksh(char * message, ...);

extern void	append_string(register char *from, register String to, register int length);
extern wchar_t	*get_wstring(char * from);


#endif
