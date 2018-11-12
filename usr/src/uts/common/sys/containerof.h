/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Toomas Soome <tsoome@me.com>
 */

#ifndef _SYS_CONTAINEROF_H
#define	_SYS_CONTAINEROF_H

/*
 * __containerof macro for private use in illumos.
 *
 * __containerof(ptr, type, member) will return pointer to the data
 * structure of given type, calculated based on the offset of 'member'
 * in the structure 'type'.
 *
 * For this macro to work, we should be certain of the pointer type.
 */

#include <sys/stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__containerof)

/*
 * The extension to support statements and declarations in expressions,
 * https://gcc.gnu.org/onlinedocs/gcc/Statement-Exprs.html, is available
 * in gcc >= 3.1.
 * We perform the assignment below to try and provide additional type safety.
 */
#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
#define	__containerof(m, s, name) (					\
{									\
	const volatile __typeof(((s *)0)->name) *__m = (m);		\
	(void *)((uintptr_t)__m - (uintptr_t)offsetof(s, name));	\
})
#else
#define	__containerof(m, s, name)			\
	(void *)((uintptr_t)(m) - (uintptr_t)offsetof(s, name))
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CONTAINEROF_H */
