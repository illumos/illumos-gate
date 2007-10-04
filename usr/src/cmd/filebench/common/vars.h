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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FB_VARS_H
#define	_FB_VARS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint64_t vinteger_t;
typedef vinteger_t *var_integer_t;
typedef char **var_string_t;

typedef struct var {
	char		*var_name;
	int		var_type;
	struct var	*var_next;
	char		*var_string;
	vinteger_t	var_integer;
} var_t;

#define	VAR_TYPE_DYNAMIC 1

vinteger_t *integer_alloc(vinteger_t integer);
char **string_alloc(char *string);
int var_assign_integer(char *name, vinteger_t integer);
vinteger_t *var_ref_integer(char *name);
int var_assign_string(char *name, char *string);
int var_assign_var(char *name, char *string);
char **var_ref_string(char *name);
char *var_to_string(char *name);
vinteger_t var_to_integer(char *name);
int integer_isset(var_integer_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_VARS_H */
