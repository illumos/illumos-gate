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
 */

#ifndef _STR_H
#define	_STR_H

#include <sys/types.h>
#include "demangle-sys.h"
#include "demangle_int.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sysdem_alloc_s;

typedef struct str_s {
	char		*str_s;
	sysdem_ops_t	*str_ops;
	size_t		str_len;
	size_t		str_size;
} str_t;

typedef struct str_pair_s {
	str_t	strp_l;
	str_t	strp_r;
} str_pair_t;

void str_init(str_t *restrict, sysdem_ops_t *);
void str_fini(str_t *);
size_t str_length(const str_t *);
boolean_t str_copy(const str_t *, str_t *);
void str_set(str_t *, const char *, size_t);
boolean_t str_append(str_t *, const char *, size_t);
boolean_t str_append_str(str_t *, const str_t *);
boolean_t str_append_c(str_t *, char);
boolean_t str_insert(str_t *, size_t, const char *, size_t);
boolean_t str_insert_str(str_t *, size_t, const str_t *);
boolean_t str_erase(str_t *, size_t, size_t);

str_pair_t *str_pair_init(str_pair_t *, sysdem_ops_t *);
void str_pair_fini(str_pair_t *);
boolean_t str_pair_merge(str_pair_t *);
boolean_t str_pair_copy(const str_pair_t *, str_pair_t *);
size_t str_pair_len(const str_pair_t *);

#ifdef __cplusplus
}
#endif

#endif /* _STR_H */
