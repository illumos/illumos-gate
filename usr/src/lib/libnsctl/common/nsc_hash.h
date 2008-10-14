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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NSC_HASH_H
#define	_NSC_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hash_node_s {
	struct hash_node_s *next;
	char *key;
	void *data;
} hash_node_t;

hash_node_t **nsc_create_hash();
int nsc_insert_node(hash_node_t **, void *, const char *);
void *nsc_lookup(hash_node_t **, const char *);
void *nsc_remove_node(hash_node_t **, char *);
void nsc_remove_all(hash_node_t **, void (*)(void *));

#ifdef __cplusplus
}
#endif

#endif	/* _NSC_HASH_H */
