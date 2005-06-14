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
 *	Copyright 1993 by Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/***************************************************************** 

  Copyright  1993 Sun Microsystems 
  All Rights Reserved.

  %W% %G% %U%

  Revisions
     06/10/93 - Raymond Lai  Created

******************************************************************/

#ifndef _CAFE_DEM_H
#define _CAFE_DEM_H

#include "dem.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Note: NDEM_type starts with 1000 so that dbx can tell a NDEM_name
   structure from a DEM (cfront) one.
*/

enum NDEM_type {
	NDEM_other = 1000,	/* default */
	NDEM_constructor, NDEM_destructor, NDEM_operator, NDEM_conversion,
	NDEM_unnamed_arg, NDEM_static_constructor, NDEM_static_destructor
};

typedef struct NDEM_modifier {
	char			 is_signed : 1;
	char			 is_volatile : 1;
	char			 is_unsigned : 1;
	char			 is_const : 1;
	char			 is_static : 1;
} NDEM_modifier;

struct NDEM_class;
struct NDEM_arg;

/* A cafe name.  This can be either a (static) data member, a function member,
   or a global function.
*/

typedef struct NDEM_name {
	enum NDEM_type		 type;
	struct NDEM_class	*qual_class;
	char 			*raw_name;
	struct NDEM_arg		*conv_t;	/* for conversion function */
	struct NDEM_arg		*f_args;	/* for function */
	struct NDEM_modifier	 f_modifier;	/* for member function */
} NDEM_name;

/* A class. */

typedef struct NDEM_class {
	struct NDEM_class	*qual_class;
	char			*raw_class_name;
	struct NDEM_arg		*t_args;	/* for template class */
} NDEM_class;

/* A function pointer (as an argument). */

typedef struct NDEM_fptr {
	struct NDEM_class	*qual_class;
	struct NDEM_arg		*f_args;
	struct NDEM_arg		*return_t;
	struct NDEM_arg		*decls;		/* function declarator list */
} NDEM_fptr;

/* A member data pointer (as an argument). */

typedef struct NDEM_mdptr {
	struct NDEM_class	*qual_class;
	struct NDEM_arg		*mem_data_t;
} NDEM_mdptr;

/* An abbreviation record (for arguments like "NDC", "TB"). */

typedef struct NDEM_abbrev_rec {
	int			 repetition_number;
	int			 param_number;
} NDEM_abbrev_rec;

/* A pointer, reference, or array introduces a type of its own... */

enum NDEM_decl_type {
	NDEM_pointer = 1, NDEM_reference, NDEM_array
};

typedef struct NDEM_declarator {
	enum NDEM_decl_type	 decl_type;
	struct NDEM_arg		*real_arg;
	char			*array_size;	/* if an array */
} NDEM_declarator;

enum NDEM_arg_type {
	NDEM_basic_type, NDEM_user_defined_type, NDEM_function_ptr, NDEM_decl,
	NDEM_mem_data_ptr,
	NDEM_abbrev_N, NDEM_abbrev_T,
	NDEM_i_const, /* template integral constant argument */
	NDEM_p_const  /* template pointer constant argument */
};

/* A type. */

typedef struct NDEM_arg {
	enum NDEM_arg_type		 arg_type;
	union {
		char			 basic_t;
		struct NDEM_class	*user_defined_t;
		struct NDEM_fptr	*function_ptr;
		struct NDEM_mdptr	*mem_data_ptr;
		struct NDEM_abbrev_rec	 abbrev_rec;
		struct NDEM_declarator	 decl;
		char			*pt_constant;
		struct NDEM_name	*temp_p_arg;
	} arg_data;
	struct NDEM_modifier		 modifier;
	struct NDEM_arg			*next;
} NDEM_arg;

#ifdef DBX_SUPPORT

extern int		cafe_dem		(char *, NDEM_name *, char *);
extern enum DEM_TYPE	cafe_getfieldtype	(NDEM_name *);
extern char		*cafe_getclass		(NDEM_name *, char *);
extern char		*cafe_getname		(NDEM_name *, char *);
extern char		**cafe_getparentclass	(NDEM_name *, char **);
extern char		*cafe_gettemplatename	(NDEM_name *);

#endif

#ifdef __cplusplus
}
#endif

#endif
