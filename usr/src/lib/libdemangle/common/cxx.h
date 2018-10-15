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

#ifndef _CPP_H
#define	_CPP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "demangle-sys.h"
#include "str.h"

typedef struct name_s {
	str_pair_t	*nm_items;
	sysdem_ops_t	*nm_ops;
	size_t		nm_len;
	size_t		nm_size;
} name_t;

extern size_t cpp_name_max_depth;

void name_clear(name_t *);
void name_init(name_t *, sysdem_ops_t *);
void name_fini(name_t *);
size_t name_len(const name_t *);
boolean_t name_empty(const name_t *);
boolean_t name_add(name_t *, const char *, size_t, const char *, size_t);
boolean_t name_add_str(name_t *, str_t *, str_t *);
boolean_t name_join(name_t *, size_t, const char *);
boolean_t name_fmt(name_t *, const char *, const char *);
str_pair_t *name_at(const name_t *, size_t);
str_pair_t *name_top(name_t *);
void name_pop(name_t *, str_pair_t *);

typedef struct sub_s {
	name_t		*sub_items;
	sysdem_ops_t	*sub_ops;
	size_t		sub_len;
	size_t		sub_size;
} sub_t;

void sub_clear(sub_t *);
void sub_init(sub_t *, sysdem_ops_t *);
void sub_fini(sub_t *);
void sub_pop(sub_t *);
boolean_t sub_save(sub_t *, const name_t *, size_t);
boolean_t sub_substitute(const sub_t *, size_t, name_t *);
boolean_t sub_empty(const sub_t *);
size_t sub_len(const sub_t *);

typedef struct templ_s {
	sub_t		*tpl_items;
	sysdem_ops_t	*tpl_ops;
	size_t		tpl_len;
	size_t		tpl_size;
} templ_t;

void templ_init(templ_t *, sysdem_ops_t *);
void templ_fini(templ_t *);
boolean_t templ_empty(const templ_t *);
size_t templ_top_len(const templ_t *);
boolean_t templ_sub(const templ_t *, size_t, name_t *);
boolean_t templ_save(const name_t *, size_t, templ_t *);

boolean_t templ_push(templ_t *);
void templ_pop(templ_t *);
sub_t *templ_top(templ_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CPP_H */
