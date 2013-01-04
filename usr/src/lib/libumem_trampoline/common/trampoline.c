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
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 */

/*
 * This is a local link auditing library for libumem(3LIB). It provides a means
 * for us to implement the per-thread caching component of libumem. When any
 * binary or library attempts to bind to libumem's malloc and free symbols we
 * instead point them to a private buffer in our own BSS. Our mapfile ensures
 * that this BSS is readable, writeable, and executable. By default these
 * private buffers contain a jmp instruction to the original libumem malloc and
 * free.
 *
 * When libumem tries to generate its assembly, we key off of private symbol
 * names and replace their values with pointers to our values. For more
 * information on this process, see section 8 of the big theory statement for
 * libumem in lib/libumem/common/umem.c.
 *
 * Note that this is very x86 specific currently. This includes x86 instructions
 * and making assumptions about alignment of variables, see the lint warnings.
 * By the current construction, SPARC is basically a no-op.
 */
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <libelf.h>
#include <link.h>

#if defined(__i386) || defined(__amd64)
#define	LIBUMEM_TRAMPOLINE_JMP32	0xe9
#endif	/* defined(__i386) || defined(__amd64) */

/*
 * This is our malloc trampoline.  We give it the name "malloc" to make it
 * appear somewhat like malloc.
 */
static uint8_t malloc[4096];
static uint8_t free[4096];
static size_t msize = sizeof (malloc);
static size_t fsize = sizeof (free);

/*
 * We don't want to link against libc, so we define our own versions of the
 * string functions as necessary.
 */
static int
la_strcmp(const char *s1, const char *s2)
{
	if (s1 == s2)
		return (0);
	while (*s1 == *s2++)
		if (*s1++ == '\0')
			return (0);

	return (*(unsigned char *)s1 - *(unsigned char *)--s2);
}

static char *
la_strrchr(char *str, char c)
{
	char *r;

	r = NULL;
	do {
		if (*str == c)
			r = str;
	} while (*str++);
	return (r);
}

/*ARGSUSED*/
uint_t
la_version(uint_t version)
{
	return (LAV_CURRENT);
}

/*ARGSUSED*/
uint_t
la_objopen(Link_map *lmp, Lmid_t lmid, uintptr_t *cookie)
{
#if defined(__i386) || defined(__amd64)
	char *objname;

	if ((objname = la_strrchr(lmp->l_name, '/')) == NULL ||
	    *(++objname) == '\0')
		objname = lmp->l_name;

	if (la_strcmp(objname, "libumem.so.1") == 0 ||
	    la_strcmp(objname, "libumem.so") == 0)
		return (LA_FLG_BINDFROM | LA_FLG_BINDTO);
#endif	/* defined(__i386) || defined(__amd64) */

	return (0);
}

#if defined(_LP64)
/*ARGSUSED*/
uintptr_t
la_symbind64(Elf64_Sym *symp, uint_t symndx, uintptr_t *refcook,
    uintptr_t *defcook, uint_t *sb_flags, char const *sym_name)
#else
/*ARGSUSED*/
uintptr_t
la_symbind32(Elf32_Sym *symp, uint_t symndx, uintptr_t *refcook,
    uintptr_t *defcook, uint_t *sb_flags)
#endif
{
#if defined(__i386) || defined(__amd64)
	int i = 0;

#if !defined(_LP64)
	char const *sym_name = (char const *) symp->st_name;
#endif

	if (la_strcmp(sym_name, "malloc") == 0) {
		if (malloc[i] == '\0') {
			malloc[i++] = LIBUMEM_TRAMPOLINE_JMP32;
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			*(uint32_t *)&malloc[i] = (uint32_t)(symp->st_value -
			    (uintptr_t)&malloc[i + sizeof (uint32_t)]);
		}

		return ((uintptr_t)malloc);
	} else if (la_strcmp(sym_name, "free") == 0) {
		if (free[i] == '\0') {
			free[i++] = LIBUMEM_TRAMPOLINE_JMP32;
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			*(uint32_t *)&free[i] = (uint32_t)(symp->st_value -
			    (uintptr_t)&free[i + sizeof (uint32_t)]);
		}

		return ((uintptr_t)free);
	} else if (la_strcmp(sym_name, "umem_genasm_mptr") == 0) {
		return ((uintptr_t)malloc);
	} else if (la_strcmp(sym_name, "umem_genasm_msize") == 0) {
		return ((uintptr_t)&msize);
	} else if (la_strcmp(sym_name, "umem_genasm_fptr") == 0) {
		return ((uintptr_t)free);
	} else if (la_strcmp(sym_name, "umem_genasm_fsize") == 0) {
		return ((uintptr_t)&fsize);
	} else {
		return (symp->st_value);
	}
#endif	/* defined(__i386) || defined(__amd64) */
}
