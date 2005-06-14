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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _SPEC_H
#define	_SPEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <stdio.h>
#include <libgen.h>
#include <sys/types.h>

#include "queue.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Typedefs
 */

typedef enum spec_type {
	SPEC_EXACT,
	SPEC_REGEXP


}			   spec_type_t;


typedef struct spec {
	queue_node_t	qn;
	char		   *str;
	spec_type_t	 type;
	char		   *regexp_p;

}			   spec_t;

typedef void
(*spec_attr_fun_t) (spec_t * spec, char *attr, char *value, void *calldatap);
typedef void
(*spec_val_fun_t) (spec_t * spec, char *value, void *calldatap);


/*
 * Globals
 */


/*
 * Declarations
 */

spec_t * spec(char *str_p, spec_type_t type);
void spec_destroy(spec_t * list_p);
void spec_print(FILE * stream, spec_t * list_p);
spec_t * spec_list(spec_t * list_p, spec_t * item_p);
void spec_attrtrav(spec_t * spec_p, char *attrs,
	spec_attr_fun_t fun, void *calldata_p);
void spec_valtrav(spec_t * spec_p, char *valstr,
	spec_val_fun_t fun, void *calldata_p);
spec_t *spec_dup(spec_t * spec_p);

#ifdef __cplusplus
}
#endif

#endif /* _SPEC_H */
