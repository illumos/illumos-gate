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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef _HASH_H
#define	_HASH_H

typedef struct hash_entry {
	struct hash_entry	*next_entry;
	struct hash_entry	*right_entry;
	struct hash_entry	*left_entry;
	char			*key;
	char			*data;
} hash_entry;

typedef struct hash {
	size_t			size;
	hash_entry		**table;
	hash_entry		*start;
	enum hash_type {
		String_Key = 0,
		Integer_Key = 1
	} hash_type;
} hash;

extern hash	*make_hash(size_t);
extern hash	*make_ihash(size_t);
extern char	**get_hash(hash *, char *);
extern char	**find_hash(hash *, const char *);
extern char	*del_hash(hash *, const char *);
extern size_t 	operate_hash(hash *, void (*)(), const char *);
extern void 	destroy_hash(hash *, int (*)(), const char *);

#endif /* _HASH_H */
