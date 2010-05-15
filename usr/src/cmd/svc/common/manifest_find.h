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

#ifndef _MANIFEST_FIND_H
#define	_MANIFEST_FIND_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include "manifest_hash.h"

#define	CHECKHASH	0x1
#define	CHECKEXT	0x2
#define	BUNDLE_PROF	0x4
#define	BUNDLE_MFST	0x8

typedef struct manifest_info {
	const char	*mi_path;	/* Path of manifest file */
	const char	*mi_prop;	/* Property that holds manifest hash */
	uchar_t		mi_hash[MHASH_SIZE]; /* Manifest hash */
} manifest_info_t;

/*
 * Declare functions that are used for finding service bundle files in a
 * directory.
 */


int find_manifests(const char *, manifest_info_t ***, int);
void free_manifest_array(manifest_info_t **);

#ifdef __cplusplus
}
#endif

#endif /* _MANIFEST_FIND_H */
