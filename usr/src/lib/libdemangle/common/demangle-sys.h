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
 * Copyright 2017 Jason King
 * Copyright 2018, Joyent, Inc.
 */

#ifndef _DEMANGLE_SYS_H
#define	_DEMANGLE_SYS_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sysdem_lang_e {
	SYSDEM_LANG_AUTO,
	SYSDEM_LANG_CPP,
	SYSDEM_LANG_RUST
} sysdem_lang_t;

typedef struct sysdem_alloc_s {
	void *(*alloc)(size_t);
	void (*free)(void *, size_t);
} sysdem_ops_t;

char *sysdemangle(const char *, sysdem_lang_t, sysdem_ops_t *);

#ifdef __cplusplus
}
#endif

#endif /* _DEMANGLE_SYS_H */
