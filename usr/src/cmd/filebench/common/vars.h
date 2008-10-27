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

#ifndef _FB_VARS_H
#define	_FB_VARS_H

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/* Attribute Value Descriptor types */
typedef enum avd_type {
	AVD_INVALID = 0,	/* avd is empty */
	AVD_VAL_BOOL,		/* avd contains a boolean_t */
	AVD_VARVAL_BOOL,	/* avd points to the boolean_t in a var_t */
	AVD_VAL_INT,		/* avd contains an fbint_t */
	AVD_VARVAL_INT,		/* avd points to the fbint_t in a var_t */
	AVD_VAL_STR,		/* avd contains a sting (*char) */
	AVD_VARVAL_STR,		/* avd points to a string in a var_t */
	AVD_VAL_DBL,		/* avd contains a double float */
	AVD_VARVAL_DBL,		/* avd points to the double in a var_t */
	AVD_IND_VAR,		/* avd points a var_t */
	AVD_IND_RANDVAR		/* avd points to the randdist_t associated */
				/* with a random type var_t */
} avd_type_t;

typedef uint64_t fbint_t;

/* Attribute Value Descriptor */
typedef struct avd {
	avd_type_t  avd_type;
	union {
		boolean_t	boolval;
		boolean_t	*boolptr;
		fbint_t		intval;
		fbint_t		*intptr;
		double		dblval;
		double		*dblptr;
		char		*strval;
		char		**strptr;
		struct randdist *randptr;
		struct var	*varptr;
	} avd_val;
} *avd_t;

#define	AVD_IS_RANDOM(vp)	((vp) && ((vp)->avd_type == AVD_IND_RANDVAR))
#define	AVD_IS_STRING(vp)	((vp) && (((vp)->avd_type == AVD_VAL_STR) || \
				((vp)->avd_type == AVD_VARVAL_STR)))
#define	AVD_IS_VAR(vp)		((vp) && (((vp)->avd_type == AVD_IND_VAR) || \
				((vp)->avd_type == AVD_VARVAL_INT) || \
				((vp)->avd_type == AVD_VARVAL_DBL)))

typedef struct var {
	char		*var_name;
	int		var_type;
	struct var	*var_next;
	union {
		boolean_t	boolean;
		fbint_t		integer;
		double		dbl_flt;
		char		*string;
		struct randdist *randptr;
		struct var	*varptr;
	} var_val;
} var_t;

#define	VAR_TYPE_GLOBAL		0x00	/* global variable */
#define	VAR_TYPE_DYNAMIC	0x01	/* Dynamic variable */
#define	VAR_TYPE_RANDOM		0x02	/* random variable */
#define	VAR_TYPE_LOCAL		0x03	/* Local variable */
#define	VAR_TYPE_MASK		0x0f
#define	VAR_TYPE_BOOL_SET	0x10	/* var contains a boolean */
#define	VAR_TYPE_INT_SET	0x20	/* var contains an integer */
#define	VAR_TYPE_STR_SET	0x30	/* var contains a string */
#define	VAR_TYPE_DBL_SET	0x40	/* var contains a double */
#define	VAR_TYPE_RAND_SET	0x50	/* var contains a randdist pointer */
#define	VAR_TYPE_INDVAR_SET	0x60    /* var points to another local var */
#define	VAR_TYPE_SET_MASK	0xf0

#define	VAR_HAS_BOOLEAN(vp) \
	(((vp)->var_type & VAR_TYPE_SET_MASK) == VAR_TYPE_BOOL_SET)

#define	VAR_HAS_INTEGER(vp) \
	(((vp)->var_type & VAR_TYPE_SET_MASK) == VAR_TYPE_INT_SET)

#define	VAR_HAS_DOUBLE(vp) \
	(((vp)->var_type & VAR_TYPE_SET_MASK) == VAR_TYPE_DBL_SET)

#define	VAR_HAS_STRING(vp) \
	(((vp)->var_type & VAR_TYPE_SET_MASK) == VAR_TYPE_STR_SET)

#define	VAR_HAS_RANDDIST(vp) \
	(((vp)->var_type & VAR_TYPE_SET_MASK) == VAR_TYPE_RAND_SET)

#define	VAR_HAS_INDVAR(vp) \
	(((vp)->var_type & VAR_TYPE_SET_MASK) == VAR_TYPE_INDVAR_SET)

#define	VAR_SET_BOOL(vp, val)	\
	{			\
		(vp)->var_val.boolean = (val); \
		(vp)->var_type = \
		(((vp)->var_type & (~VAR_TYPE_SET_MASK)) | VAR_TYPE_BOOL_SET);\
	}

#define	VAR_SET_INT(vp, val)	\
	{			\
		(vp)->var_val.integer = (val); \
		(vp)->var_type = \
		(((vp)->var_type & (~VAR_TYPE_SET_MASK)) | VAR_TYPE_INT_SET); \
	}

#define	VAR_SET_DBL(vp, val)	\
	{			\
		(vp)->var_val.dbl_flt = (val); \
		(vp)->var_type = \
		    (((vp)->var_type & (~VAR_TYPE_SET_MASK)) | \
		    VAR_TYPE_DBL_SET); \
	}

#define	VAR_SET_STR(vp, val)	\
	{			\
		(vp)->var_val.string = (val); \
		(vp)->var_type = \
		    (((vp)->var_type & (~VAR_TYPE_SET_MASK)) | \
		    VAR_TYPE_STR_SET); \
	}

#define	VAR_SET_RAND(vp, val)	\
	{			\
		(vp)->var_val.randptr = (val); \
		(vp)->var_type = \
		    (((vp)->var_type & (~VAR_TYPE_SET_MASK)) | \
		    VAR_TYPE_RAND_SET); \
	}

#define	VAR_SET_INDVAR(vp, val)	\
	{			\
		(vp)->var_val.varptr = (val); \
		(vp)->var_type = \
		    (((vp)->var_type & (~VAR_TYPE_SET_MASK)) | \
		    VAR_TYPE_INDVAR_SET); \
	}

avd_t avd_bool_alloc(boolean_t bool);
avd_t avd_int_alloc(fbint_t integer);
avd_t avd_str_alloc(char *string);
boolean_t avd_get_bool(avd_t);
fbint_t avd_get_int(avd_t);
double avd_get_dbl(avd_t);
char *avd_get_str(avd_t);
void avd_update(avd_t *avdp, var_t *lvar_list);
avd_t var_ref_attr(char *name);
int var_assign_boolean(char *name, boolean_t bool);
int var_assign_integer(char *name, fbint_t integer);
int var_assign_double(char *name, double dbl);
int var_assign_string(char *name, char *string);
int var_assign_var(char *name, char *string);
void var_update_comp_lvars(var_t *newlvar, var_t *proto_comp_vars,
    var_t *mstr_lvars);
var_t *var_define_randvar(char *name);
var_t *var_find_randvar(char *name);
boolean_t var_to_boolean(char *name);
fbint_t var_to_integer(char *name);
var_t *var_lvar_alloc_local(char *name);
var_t *var_lvar_assign_boolean(char *name, boolean_t);
var_t *var_lvar_assign_integer(char *name, fbint_t);
var_t *var_lvar_assign_double(char *name, double);
var_t *var_lvar_assign_string(char *name, char *string);
var_t *var_lvar_assign_var(char *name, char *src_name);
char *var_to_string(char *name);
char *var_randvar_to_string(char *name, int param);
int var_is_set4_randvar(char *name);

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_VARS_H */
