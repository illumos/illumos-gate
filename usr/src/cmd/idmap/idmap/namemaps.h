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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Additional API for Identity Mapping Service
 */

#ifndef NAMEMAPS_H
#define	NAMEMAPS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Directory based name map API
 */

typedef struct idmap_nm_handle idmap_nm_handle_t;

/* Set namemap */
extern idmap_stat idmap_set_namemap(idmap_nm_handle_t *, char *, char *,
    int, int, int);

/* Unset namemap */
extern idmap_stat idmap_unset_namemap(idmap_nm_handle_t *, char *, char *,
    int, int, int);

extern idmap_stat idmap_get_namemap(idmap_nm_handle_t *p, int *, char **,
    char **, int *, char **,  char **);

extern void idmap_fini_namemaps(idmap_nm_handle_t *);

extern idmap_stat idmap_init_namemaps(idmap_handle_t *, idmap_nm_handle_t **,
    char *, char *, char *, char *, int);

#ifdef __cplusplus
}
#endif

#endif /* NAMEMAPS_H */
