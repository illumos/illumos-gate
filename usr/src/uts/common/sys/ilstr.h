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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _SYS_ILSTR_H
#define	_SYS_ILSTR_H

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/stdbool.h>
#else
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ilstr_errno {
	ILSTR_ERROR_OK = 0,
	ILSTR_ERROR_NOMEM,
	ILSTR_ERROR_OVERFLOW,
	ILSTR_ERROR_PRINTF,
} ilstr_errno_t;

typedef enum ilstr_flag {
	ILSTR_FLAG_PREALLOC = (1 << 0),
} ilstr_flag_t;

typedef struct ilstr {
	char *ils_data;
	size_t ils_datalen;
	size_t ils_strlen;
	ilstr_errno_t ils_errno;
	int ils_kmflag;
	ilstr_flag_t ils_flag;
} ilstr_t;

extern void ilstr_init(ilstr_t *, int);
extern void ilstr_init_prealloc(ilstr_t *, char *, size_t);
extern void ilstr_reset(ilstr_t *);
extern void ilstr_fini(ilstr_t *);
extern void ilstr_append_str(ilstr_t *, const char *);
extern void ilstr_prepend_str(ilstr_t *, const char *);
extern void ilstr_append_char(ilstr_t *, char);
extern void ilstr_prepend_char(ilstr_t *, char);
extern ilstr_errno_t ilstr_errno(ilstr_t *);
extern const char *ilstr_cstr(ilstr_t *);
extern size_t ilstr_len(ilstr_t *);
extern bool ilstr_is_empty(ilstr_t *);
extern const char *ilstr_errstr(ilstr_t *);
void ilstr_aprintf(ilstr_t *, const char *, ...);
void ilstr_vaprintf(ilstr_t *, const char *, va_list);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ILSTR_H */
