/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NAME_FACTORY_H
#define	_NAME_FACTORY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Indexed name factory; creates unique indexed names from base name strings
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef void *	name_factory_handle_t;

typedef enum {
	NAME_FACTORY_BAD_BASE_NAME,
	NAME_FACTORY_BASE_NAME_NOT_FOUND,
	NAME_FACTORY_OUT_OF_MEMORY,
	NAME_FACTORY_SUCCESS
} name_factory_result_t;

extern void destroy_name_factory(void);
extern name_factory_result_t name_factory_make_name(char *, char *, char **);
/*
 * Add a unique index number to base_namep and return the indexed
 * name string in *indexed_namepp; if *name_factorypp is NULL, create
 * a new name factory and return a pointer to it in *name_factorypp.
 *
 */

#ifdef __cplusplus
}
#endif

#endif /* _NAME_FACTORY_H */
