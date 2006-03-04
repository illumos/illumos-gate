%{
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
 *
 *	Copyright 1993-2000 by Sun Microsystems, Inc.
 *	All Rights Reserved
 */
/***************************************************************** 

  %W% %G% %U%

  Revisions
     06/10/93 - Raymond Lai  Created

******************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "cafe_dem.h"

#define		 DEM_VERSION	0
#define		 CHECK_OLD_PREFIX(s) (s[0] == '$')
#define		 CHECK_PREFIX(s) (s[0] == '_' && s[1] == '_' && \
				isdigit(s[2]) && DEM_VERSION >= s[2] - '0')

static char	 ll_cur_char;
static int	 ll_id_size = 0;	/* the default token is of size 1 */
static char	*yytext;

#define		 BUFSIZE	8192
static char	 name_buffer[BUFSIZE];
static char	*mem_reservoir;

#define 	 ALIGN_MASK	03

static void *allocate(size_t size)
{
	char *pos;

	while ((unsigned long)mem_reservoir & ALIGN_MASK)
		++mem_reservoir;
	pos = mem_reservoir;
	mem_reservoir += size;
	return pos;
}

/* Will only be called by print_template_args() and print_function_args()
   to deallocate the excess memory allocated for argument array.
*/

static void deallocate(size_t size)
{
	mem_reservoir -= size;
}

static char *convert_number(int n)
{
	int i, len = 0;
	static char tmp[1024];
	char *s;

	if (n == 0) return NULL;

	do {
		tmp[len++] = n % 10 + '0';
	} while ((n /= 10) > 0);

	s = allocate(len+1);
	i = 0;
	while (--len >= 0)
		s[i++] = tmp[len];
	s[i] = '\0';

	return s;
}

static NDEM_name *result;
static NDEM_arg *conv_type;
static NDEM_modifier save_modifier, current_modifier = { 0, 0, 0, 0, 0 };

static void reset_current_modifier()
{
	current_modifier.is_signed = current_modifier.is_volatile =
	current_modifier.is_unsigned = current_modifier.is_const =
	current_modifier.is_static = 0;
}

enum Boolean { TRUE = 1, FALSE = 0 };

/* Don't build function argument structures when yyparse() is called by
   cafe_dem()...
*/
static enum Boolean from_cafe_dem = FALSE;
static enum Boolean build_args = TRUE;

/* Function arguments of embedded functions still need to be handled.  For
   example:

   $fDfoo7$FBfPvi44D_Dbarv == foo<&f(void*, int), 3>::bar( <IGNORE> )
          ^^^^^^^                 ^^^^^^^^^^^^^^

   The following stack is used for this purpose.  When the parser is called
   by cafe_dem() to parse a function, it first pushes a TRUE onto the stack.
   All subsequent values pushed into the stack are FALSE.

   Note the stack doesn't need to be large.
*/
static enum Boolean stack[10];
static int sk_top = 0;

#define push(f) stack[sk_top++] = f
#define pop() stack[--sk_top]

/*________________________________________________________________________*/

%}

%union {
	int		 i_val;
	char		 c_val;
	char		*s_val;
	NDEM_name	*n_val;
	NDEM_class	*class_val;
	NDEM_arg	*arg_val;
	NDEM_fptr	*fptr_val;
}

%token IDENTIFIER NUMBER

%type <i_val> big_number uname_size

%type <s_val> uname_spec uname_specN op_name optimize_number

%type <n_val> function_name global_data_name

/* namespace_spec is used solely for qualifying class(es) for now... */
%type <class_val> class_spec class_specN namespace_spec

%type <arg_val> template_spec template_arg_spec t_arg_spec arg_spec
		arg_type formal_arg_spec arg_abbrev type_declarator
		modifier_n_declarator

%type <fptr_val> function_arg_spec

%% 


mangled_name :
	function_name
	    {	 result = $1; }
|	global_data_name
	    {	 result = $1; }
|	internal_name
|	external_linkage_name
|	error
	    {	 return 1;   }
;

PREFIX :
	'_' '_' VERSION
	    {	if (DEM_VERSION < ll_cur_char - '0') YYERROR;   }
|	'$'
;

VERSION :
	'0'|'1'|'2'|'3'|'4'|'5'|'6'|'7'|'8'|'9'
;

UPPER_LETTER :
	'A'|'B'|'C'|'D'|'E'|'F'|'G'|'H'|'I'|'J'|'K'|'L'|'M'|'N'|'O'|
	'P'|'Q'|'R'|'S'|'T'|'U'|'V'|'W'|'X'|'Y'|'Z'
;

LOWER_LETTER :
	'a'|'b'|'c'|'d'|'e'|'f'|'g'|'h'|'i'|'j'|'k'|'l'|'m'|'n'|'o'|
	'p'|'q'|'r'|'s'|'t'|'u'|'v'|'w'|'x'|'y'|'z'
;

/* Upper case letter represent the numbers 0 thru 25.  Lower case are the 
*  numbers  26 thru 51.  A prefix of '0' adds 52 to the value. e.g.:
*
*      C = 2
*      c = 28
*      y = 50
*     0y = 102
*
*
* The key features are that:
*      -numbers less than or equal to 51 are only one character
*      -the end of a big_number can be found when embedded in a
*       string: e.g.
*
*		 Dfoo = big_number 3, string "foo"
*		 OCB  = big_number 54, string "B"
*/

big_number :  
	UPPER_LETTER 
	    {	$$ = ll_cur_char - 'A';   }
|	LOWER_LETTER 
	    {	$$ = ll_cur_char - 'a' + 26;   }
|	'0' big_number 
	    {	$$ = 52 + $2;   }
;

/*"identifier" is defined the the ANSI committee */

uname : 
	IDENTIFIER      
;
				       

uname_spec : 
	uname_size
	    {	ll_id_size = $1;   }
	uname
	    {
		if (build_args)
		{
		    $$ = allocate($1+1);
		    (void) strncpy($$, yytext, $1);
		    *($$+$1) = '\0';
		}
		else
		    $$ = NULL;
	    }
;

uname_size : 
	big_number
;

class_specN : 
	namespace_spec class_spec
	    {
		if (build_args)
		{
		    $2->qual_class = $1;
		    $$ = $2;
		}
		else
		    $$ = NULL;
	    }
;

class_spec : 
	fun_local_spec uname_spec template_spec
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_class));
		    $$->raw_class_name = $2;
		    $$->t_args = $3;
		}
		else
		    $$ = NULL;
	    }
;

uname_specN : 
	namespace_spec uname_spec
	    {
		$$ = $2;
	    }
;

namespace_spec : 
	/* nil */
	    {	$$ = NULL;   }
|	namespace_spec '1' uname_spec
|	namespace_spec '5' class_specN
	    {
		if (build_args)
		{
		    $3->qual_class = $1;
		    $$ = $3;
		}
		else
		    $$ = NULL;
	    }
;

template_spec :
	/* nil */
	    {	$$ = NULL;   }
|	'7' template_arg_spec '_'
	    {	$$ = $2;   }
;

template_arg_spec :
	t_arg_spec
|	template_arg_spec t_arg_spec
	    {
		if (build_args)
		{
		    NDEM_arg *tmp = $1;
		    while (tmp->next) tmp = tmp->next;
		    tmp->next = $2;
		}
		$$ = $1;
	    }
;

t_arg_spec :
	arg_spec
|	'4' optimize_number
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_i_const;
		    $$->arg_data.pt_constant = $2;
		}
		else
		    $$ = NULL;
	    }
|	'4' optimize_number 'n'
	    {
		if (build_args)
		{
		    char *s = allocate(strlen($2)+2);
		    s[0] = '-';
		    (void) strcpy(s+1, $2);
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_i_const;
		    $$->arg_data.pt_constant = s;
		}
		else
		    $$ = NULL;
	    }
|	'4' function_name '_'
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_p_const;
		    $$->arg_data.temp_p_arg = $2;
		}
		else
		    $$ = NULL;
	    }
|	'4' global_data_name '_'
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_p_const;
		    $$->arg_data.temp_p_arg = $2;
		}
		else
		    $$ = NULL;
	    }
;

optimize_number :
	big_number
	    {
		if (build_args)
		    $$ = convert_number($1);
		else
		    $$ = NULL;
	    }
|	'8' big_number
	    {	ll_id_size = $2;   }
	uname
	    {
		if (build_args)
		{
		    $$ = allocate($2+1);
		    (void) strncpy($$, yytext, $2);
		    *($$+$2) = '\0';
		}
		else
		    $$ = NULL;
	    }
;

/*
* ".F" signifies a standard function
* ".f" is a member function
* ".O" is a global operator function
* ".o" is a member operator function
*/

function_name : 
	PREFIX 'F'
	    {
		push(from_cafe_dem);
		from_cafe_dem = FALSE;
	    }
	uname_specN
	    {
		if (pop())
		    build_args = FALSE;
	    }
	formal_arg_spec 
	    {
		$$ = allocate(sizeof(NDEM_name));
		if ($4[0] == 'O')
		    $$->type = NDEM_conversion;
		else
		    $$->type = NDEM_other;
		$$->raw_name = $4;
		$$->f_args = $6;
	    }
|	PREFIX 'C'
	    {
		push(from_cafe_dem);
		from_cafe_dem = FALSE;
	    }
	uname_specN
	    {
		if (pop())
		    build_args = FALSE;
	    }
	formal_arg_spec 
	    {
		$$ = allocate(sizeof(NDEM_name));
		$$->type = NDEM_static_constructor;
		$$->raw_name = "__STATIC_CONSTRUCTOR";
		$$->f_args = $6;
	    }
|	PREFIX 'D'
	    {
		push(from_cafe_dem);
		from_cafe_dem = FALSE;
	    }
	uname_specN
	    {
		if (pop())
		    build_args = FALSE;
	    }
	formal_arg_spec 
	    {
		$$ = allocate(sizeof(NDEM_name));
		$$->type = NDEM_static_destructor;
		$$->raw_name = "__STATIC_DESTRUCTOR";
		$$->f_args = $6;
	    }
|	PREFIX 'f'
	    {
		push(from_cafe_dem);
		from_cafe_dem = FALSE;
	    }
	class_specN uname_spec
	    {
		if (pop())
		    build_args = FALSE;
	    }
	formal_arg_spec f_modifier
	    {
		$$ = allocate(sizeof(NDEM_name));
		$$->type = NDEM_other;
		$$->qual_class = $4;
		$$->raw_name = $5;
		$$->f_args = $7;
		$$->f_modifier = current_modifier;
		reset_current_modifier();
	    }
|	PREFIX 'O'
	    {
		push(from_cafe_dem);
		from_cafe_dem = FALSE;
	    }
	op_name namespace_spec
	    {
		if (pop())
		    build_args = FALSE;
	    }
	formal_arg_spec 
	    {
		$$ = allocate(sizeof(NDEM_name));
		if ($4[0] == 'O')
		{
		    $$->type = NDEM_conversion;
		    $$->conv_t = conv_type;
		}
		else if ($4[0] == 'C')
		    $$->type = NDEM_constructor;
		else if ($4[0] == 'D')
		    $$->type = NDEM_destructor;
		else
		    $$->type = NDEM_operator;
		$$->raw_name = $4;
		$$->f_args = $7;
	    }
|	PREFIX 'o'
	    {
		push(from_cafe_dem);
		from_cafe_dem = FALSE;
	    }
	class_specN op_name
	    {
		if (pop())
		    build_args = FALSE;
	    }
	formal_arg_spec f_modifier
	    {
		$$ = allocate(sizeof(NDEM_name));
		if ($5[0] == 'O')
		{
		    $$->type = NDEM_conversion;
		    $$->conv_t = conv_type;
		}
		else if ($5[0] == 'C')
		    $$->type = NDEM_constructor;
		else if ($5[0] == 'D')
		    $$->type = NDEM_destructor;
		else
		    $$->type = NDEM_operator;
		$$->qual_class = $4;
		$$->raw_name = $5;
		$$->f_args = $7;
		$$->f_modifier = current_modifier;
		reset_current_modifier();
	    }
;

f_modifier:
	/* nil */
|	'K'
	    { current_modifier.is_const = 1; }
|	'W'
	    { current_modifier.is_volatile = 1; }
|	'T'
	    { current_modifier.is_static = 1; }
;

/* Note: "adv" and "add" have been changed to "gav" and "gad" to avoid
*  grammar conflicts.
*
* See p. 125 of the ARM.  Note that operator T() is now "op" class_specN.
*/

op_name : 
	'm' 'l'
	    { $$ = "*"; }
|	'm' 'd'
	    { $$ = "%"; }
|	'm' 'i'
	    { $$ = "-"; }
|	'r' 's'
	    { $$ = ">>"; }
|	'n' 'e'
	    { $$ = "!="; }
|	'g' 't'
	    { $$ = ">"; }
|	'g' 'e'
	    { $$ = ">="; }
|	'o' 'r'
	    { $$ = "|"; }
|	'a' 'a'
	    { $$ = "&&"; }
|	'n' 't'
	    { $$ = "!"; }
|       'p' 'p'
	    { $$ = "++"; }
|	'a' 's'
	    { $$ = "="; }
|	'a' 'p' 'l'
	    { $$ = "+="; }
|	'a' 'm' 'u'
	    { $$ = "*="; }
|	'a' 'm' 'd'
	    { $$ = "%="; }
|	'a' 'r' 's'
	    { $$ = ">>="; }
|	'a' 'o' 'r'
	    { $$ = "|="; }
|	'c' 'm'
	    { $$ = ","; }
|	'd' 'v'
	    { $$ = "/"; }
|       'p' 'l'
	    { $$ = "+"; }
|	'l' 's'
	    { $$ = "<<"; }
|	'e' 'q'
	    { $$ = "=="; }
|	'l' 't'
	    { $$ = "<"; }
|	'l' 'e'
	    { $$ = "<="; }
|	'a' 'd'
	    { $$ = "&"; }
|	'e' 'r'
	    { $$ = "^"; }
|	'o' 'o'
	    { $$ = "||"; }
|	'c' 'o'
	    { $$ = "~"; }
|	'm' 'm'
	    { $$ = "--"; }
|       'r' 'f'
	    { $$ = "->"; }
|	'a' 'm' 'i'
	    { $$ = "-="; }
|	'g' 'd' 'v'
/*	'a' 'd' 'v'	*/
	    { $$ = "/="; }
|	'a' 'l' 's'
	    { $$ = "<<="; }
|	'g' 'a' 'd'
/*	'a' 'a' 'd'	*/
	    { $$ = "&="; }
|	'a' 'e' 'r'
	    { $$ = "^="; }
|	'r' 'm'
	    { $$ = "->*"; }
|	'c' 'l'
	    { $$ = "()"; }
|	'v' 'c'
	    { $$ = "[]"; }
|       'c' 't'
	    { $$ = "C"; }
|	'd' 't'
	    { $$ = "D"; }
|	'n' 'w'
	    { $$ = "new"; }
|	'd' 'l'
	    { $$ = "delete"; }
|	'o' 'p' arg_spec
	    {
		conv_type = $3;
		$$ = "O";
	    }
;

/* "$N" is for global data (they are mangled when their addresses are
	passed as template arguments).
*  "$d" is for static data members
*/

global_data_name : 
	PREFIX 'N' namespace_spec uname_spec
	    {
		$$ = allocate(sizeof(NDEM_name));
		$$->type = NDEM_other;
		$$->raw_name = $4;
	    }
|	PREFIX 'd' class_specN uname_spec
	    {
		$$ = allocate(sizeof(NDEM_name));
		$$->type = NDEM_other;
		$$->qual_class = $3;
		$$->raw_name = $4;
	    }
;

/*
*  "$P" is for compiler private data and must be file local or block local.
*  "$X" is for extensions and can be global.  The big_number should be used
*     to serialize the extensions since collisions between different compilers
*     can occur. (Note that "P" is file local and doesn't have this problem.)
*  "$V" is for virtual tables.  It is to be global.
*/ 

internal_name : 
 	 PREFIX 'P' private_id 
|	 PREFIX 'X' big_number private_id 
| 	 PREFIX 'V' class_specN
;

private_id : 
	/* FIXUP: This is implementation specific */
;

external_linkage_name : 
	/* defined by other languages ABI */
;

/* This is used to add info for function local classes.  The big_number is a
*  compiler dependent scope identifier and can be omitted if not needed.
*/

/* Note that function local classes only need to be mangled when the linker
*  will see them, such as when a member function will be instantiated.
*/

fun_local_spec : 
 	/* nil */ 
|	'2' fun_local_scope
; 

fun_local_scope :
	big_number
|	'8' big_number
	    {   ll_id_size = $2;   }
	uname
;

arg_spec : 
	modifier_n_declarator arg_type
	    {
		if (build_args)
		{
		    $2->modifier = current_modifier;
		    reset_current_modifier();
		    if ($1) {
		        if ($2->arg_type == NDEM_function_ptr) {
			    $2->arg_data.function_ptr->decls = $1;
			    $$ = $2;
		        }
		        else {
			    NDEM_arg *tmp = $1;
			    while (tmp->arg_data.decl.real_arg)
			        tmp = tmp->arg_data.decl.real_arg;
			    tmp->arg_data.decl.real_arg = $2;
			    $$ = $1;
		        }
		    }
		    else
		        $$ = $2;
		}
		else
		    $$ = NULL;
	    }
|	arg_abbrev
;

function_arg_spec :
	'F' formal_arg_spec '_' arg_spec
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_fptr));
		    $$->f_args = $2;
		    $$->return_t = $4;
		}
		else
		    $$ = NULL;
	    }
|	'M' class_specN 'F' formal_arg_spec f_modifier
	    {
		if (build_args)
		{
		    save_modifier = current_modifier;
		    reset_current_modifier();
		}
	    }
	'_' arg_spec
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_fptr));
		    $$->qual_class = $2;
		    $$->f_args = $4;
		    $$->return_t = $8;
		    current_modifier = save_modifier;
		}
		else
		    $$ = NULL;
	    }
;

formal_arg_spec :
	formal_arg_spec arg_spec
	    {
		if (build_args)
		{
		    NDEM_arg *tmp = $1;
		    while (tmp->next) tmp = tmp->next;
		    tmp->next = $2;
		    $$ = $1;
		}
		else
		    $$ = NULL;
	    }
|	arg_spec
;

modifier_n_declarator :
	/* nil */
	    {	 $$ = NULL;   }
|	modifier_n_declarator modifier
|	modifier_n_declarator type_declarator
	    {
		if (build_args)
		{
		    if ($1) {
		        NDEM_arg *tmp = $1;
		        while (tmp->arg_data.decl.real_arg)
			    tmp = tmp->arg_data.decl.real_arg;
		        tmp->arg_data.decl.real_arg = $2;
		        $$ = $1;
		    }
		    else
		        $$ = $2;
		}
		else
		    $$ = NULL;
	    }
;

modifier : 
	'C'
	    {
		if (build_args)
		    current_modifier.is_const = 1;
	    }
|	'S'
	    {
		if (build_args)
		    current_modifier.is_signed = 1;
	    }
|	'U'
	    {
		if (build_args)
		    current_modifier.is_unsigned = 1;
	    }
|	'V'
	    {
		if (build_args)
		    current_modifier.is_volatile = 1;
	    }
;

type_declarator : 
	'P' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_decl;
		    $$->arg_data.decl.decl_type = NDEM_pointer;
		    $$->modifier = current_modifier;
		    reset_current_modifier();
		}
		else
		    $$ = NULL;
	    }
|	'R' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_decl;
		    $$->arg_data.decl.decl_type = NDEM_reference;
		    $$->modifier = current_modifier;
		    reset_current_modifier();
		}
		else
		    $$ = NULL;
	    }
|	'A' big_number 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_decl;
		    $$->arg_data.decl.decl_type = NDEM_array;
		    $$->arg_data.decl.array_size = convert_number($2);
		    $$->modifier = current_modifier;
		    reset_current_modifier();
		}
		else
		    $$ = NULL;
	    }
|	'A' '8' big_number
	    {	ll_id_size = $3;   }
	uname
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_decl;
		    $$->arg_data.decl.decl_type = NDEM_array;
		    $$->arg_data.decl.array_size = allocate($3+1);
		    (void) strncpy($$->arg_data.decl.array_size, yytext, $3);
		    *($$->arg_data.decl.array_size+$3) = '\0';
		    $$->modifier = current_modifier;
		    reset_current_modifier();
		}
		else
		    $$ = NULL;
	    }
;

arg_type : 
	'v' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'v';
		}
		else
		    $$ = NULL;
	    }
|	'c' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'c';
		}
		else
		    $$ = NULL;
	    }
|	's' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 's';
		}
		else
		    $$ = NULL;
	    }
|	'i' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'i';
		}
		else
		    $$ = NULL;
	    }
|	'l' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'l';
		}
		else
		    $$ = NULL;
	    }
|	'f' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'f';
		}
		else
		    $$ = NULL;
	    }
|	'd' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'd';
		}
		else
		    $$ = NULL;
	    }
|	'D' 
/*	'r'	*/
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'D';
		}
		else
		    $$ = NULL;
	    }
|	'L'
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'L';
		}
		else
		    $$ = NULL;
	    }
| 	'e' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'e';
		}
		else
		    $$ = NULL;
	    }
| 	'G' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'G';
		}
		else
		    $$ = NULL;
	    }
| 	'w' 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_basic_type;
		    $$->arg_data.basic_t = 'w';
		}
		else
		    $$ = NULL;
	    }
|	'6' class_specN
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_user_defined_type;
		    $$->arg_data.user_defined_t = $2;
		}
		else
		    $$ = NULL;
	    }
|	function_arg_spec
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_function_ptr;
		    $$->arg_data.function_ptr = $1;
		}
		else
		    $$ = NULL;
	    }
|	'M' class_specN 'D' arg_spec
	    {
		if (build_args)
		{
		    NDEM_mdptr *t = allocate(sizeof(NDEM_mdptr));
		    t->qual_class = $2;
		    t->mem_data_t = $4;
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_mem_data_ptr;
		    $$->arg_data.mem_data_ptr = t;
		}
		else
		    $$ = NULL;
	    }
;

arg_abbrev : 
	'N' big_number big_number 
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_abbrev_N;
		    $$->arg_data.abbrev_rec.repetition_number = $2;
		    $$->arg_data.abbrev_rec.param_number = $3;
		}
		else
		    $$ = NULL;
	    }
|	'T' big_number   
	    {
		if (build_args)
		{
		    $$ = allocate(sizeof(NDEM_arg));
		    $$->arg_type = NDEM_abbrev_T;
		    $$->arg_data.abbrev_rec.param_number = $2;
		}
		else
		    $$ = NULL;
	    }
;


/* EXAMPLES:

    ***  THIS SECTION NEEDS TO BE UPDATED !! ***

  C++ constuct               New                  Cfront
  ------------              -----                --------

   P(int);                  .FAPi                 P__fi

   class a
   {
      Q (double);           .fAaAQd               Q__1aFd
      class b
      {
         R(...);            .f5AaAbARe            R__Q21a|bFe
      }
      S(a);                 .fAaAS5Aa             S__1aFa 
   }

   namespace n
   {
      T(void);              .F1AnATv
      class c
      {
         U(void);           .f1AnAcAUv
         namespace m
         {
            W(void)         .F1An5Ac1AmAWv
         }
      }
      namespace p
      {
         X(void);           .F1An1ApAXv
      }
   }            


 NOTES
           
The dot (.), can be replaced by any character that is not valid in the 
first position of the linker symbols of languages that C++ will be
linked with.


Numeric switches:


     Number           Rule              Preceeds
-------------------------------------------------------          
       0         big_number          more numbers
       1         namespace_spec      a namespace
       2         fun_local_spec      a class local to a function 
       3         template_spec       a template spec
       4         fun_local_spec      a scope id
       5         namespace_spec      a class
       6         arg_spec            a class object as an argument

Type Letters

  
     Letter           Rule              Type
-------------------------------------------------------
      .F         function_name       function
      .f         function_name       member function
      .s         function_name       static member function
      .O         function_name       operator
      .o         function_name       operator member
      .D         global_data_name    global data
      .d         global_data_name    static member data
      .P         internal_name       name, private to compiler
      .X         internal_name       a compiler extension 
      .V         internal_name       virtual table

Naming convention frequently, but not always, followed:

     (anything)_size        a big_number giving size of the next item

     (anything)_spec        an item, including its size, e.g.: class_spec

     (anything)_specN       same as (anything)_spec but with optional 
                            name space

*/    

%%

static char *out_buffer;
static int obx = 0;		/* out_buffer index */

static void put_characters(char *s, size_t len)
{
    size_t i;
    for (i = 0;  i < len; ++i)
	out_buffer[obx++] = s[i];
}

#define put_string(s)						\
{								\
    put_characters(s, strlen(s));				\
}

static void print_simple_type(char t)
{
    switch(t) {

	case 'v':
	    put_characters("void", 4);
	    break;

	case 'c':
	    put_characters("char", 4);
	    break;

	case 's':
	    put_characters("short", 5);
	    break;

	case 'i':
	    put_characters("int", 3);
	    break;

	case 'l':
	    put_characters("long", 4);
	    break;

	case 'f':
	    put_characters("float", 5);
	    break;

	case 'd':
	    put_characters("double", 6);
	    break;

	case 'D':
	    put_characters("long double", 11);
	    break;

	case 'L':
	    put_characters("long long", 9);
	    break;

	case 'e':
	    put_characters("...", 3);
	    break;

	case 'w':
	    put_characters("wchar_t", 7);
	    break;

	case 'G':
	    put_characters("T", 1);
	    break;
    }
}

static void print_class(NDEM_class *, int);
static void print_function_args(NDEM_arg *);
static void print_name(NDEM_name *);

static void print_modifier(NDEM_modifier mod)
{
    if (mod.is_const) put_characters("const ", 6);
    if (mod.is_signed) put_characters("signed ", 7);
    if (mod.is_unsigned) put_characters("unsigned ", 9);
    if (mod.is_volatile) put_characters("volatile ", 9);
}

/* print modifier(s) of pointers */
static void print_p_modifier(NDEM_modifier mod)
{
    if (mod.is_const) put_characters(" const", 6);
    if (mod.is_volatile) put_characters(" volatile", 9);
}

static void print_arg(NDEM_arg *arg)
{
    if (! arg) return;

    switch(arg->arg_type) {

        case NDEM_basic_type:
	    print_modifier(arg->modifier);
	    print_simple_type(arg->arg_data.basic_t);
	    break;

	case NDEM_user_defined_type:
	    print_modifier(arg->modifier);
	    print_class(arg->arg_data.user_defined_t, 1);
	    break;

	case NDEM_function_ptr:
	    print_arg(arg->arg_data.function_ptr->return_t);
	    put_characters(" (", 2);
	    if (arg->arg_data.function_ptr->qual_class)
	    {
		print_class(arg->arg_data.function_ptr->qual_class, 1);
		put_characters("::", 2);
	    }
	    print_arg(arg->arg_data.function_ptr->decls);
	    put_characters(")", 1);
	    print_function_args(arg->arg_data.function_ptr->f_args);
	    print_p_modifier(arg->modifier);
	    break;

	case NDEM_mem_data_ptr:
	    print_arg(arg->arg_data.mem_data_ptr->mem_data_t);
	    put_characters(" ", 1);
	    print_class(arg->arg_data.mem_data_ptr->qual_class, 1);
	    put_characters("::", 2);
	    break;

	case NDEM_decl:
	    /* The last node in function pointer declarator list is NULL.
	    */
	    if (arg->arg_data.decl.real_arg)
	    	print_arg(arg->arg_data.decl.real_arg);
	    switch(arg->arg_data.decl.decl_type) {

		case NDEM_pointer:
		    put_characters("*", 1);
		    break;

		case NDEM_reference:
		    put_characters("&", 1);
		    break;

		case NDEM_array:
		    put_characters("[", 1);
		    if (arg->arg_data.decl.array_size)
			put_string(arg->arg_data.decl.array_size)
		    put_characters("]", 1);
		    break;
	    }
	    print_p_modifier(arg->modifier);
	    break;

	case NDEM_i_const:
	    if (arg->arg_data.pt_constant)
		put_string(arg->arg_data.pt_constant)
	    else
		put_characters("0", 1);
	    break;

	case NDEM_p_const:
	    put_characters("&", 1);
	    print_name(arg->arg_data.temp_p_arg);
	    break;

	case NDEM_abbrev_N:
	case NDEM_abbrev_T:
	   /* should never come to here! */
	default:
	    break;
    }
}

static void flat_args(NDEM_arg *in, NDEM_arg **arg_arr, int *n_ptr)
{
    int i, n = 0;

    while (in)
    {
	if (in->arg_type == NDEM_abbrev_T || in->arg_type == NDEM_abbrev_N)
	{
	    /* first align with arg_arr index... */
	    in->arg_data.abbrev_rec.param_number -= 1;

	    if (in->arg_data.abbrev_rec.param_number >= n)
	    {
		/* something's wrong.  skip the argument */
		in = in->next;
		break;
	    }
	    if (in->arg_type == NDEM_abbrev_T)
		arg_arr[n++] = arg_arr[in->arg_data.abbrev_rec.param_number];
	    else
		for (i = 0;  i < in->arg_data.abbrev_rec.repetition_number;  i++)
		    arg_arr[n++] = arg_arr[in->arg_data.abbrev_rec.param_number];
	}
	else
	    arg_arr[n++] = in;
	in = in->next;
    }
    *n_ptr = n;
}

#define MAX_ARG 300
static const int arg_array_size = sizeof(NDEM_arg *) * MAX_ARG;

static void print_template_args(NDEM_arg *arg)
{
    NDEM_arg **new_arg_list;
    int no_of_args, i;

    if (! arg)
    {
	put_characters("<?>", 3);
	return;
    }

    put_characters("<", 1);
    new_arg_list = allocate(arg_array_size);
    flat_args(arg, new_arg_list, &no_of_args);

    /* deallocate the excess memory...
    */
    deallocate(arg_array_size - sizeof(NDEM_arg *) * no_of_args);

    for(i = 0;  i < no_of_args;  ++i)
    {
	print_arg(new_arg_list[i]);
	if (i < no_of_args - 1)
	    put_characters(", ", 2);
    }
    put_characters(">", 1);
}

static void print_function_args(NDEM_arg *arg)
{
    NDEM_arg **new_arg_list;
    int no_of_args, i;

    if (! arg)
    {
		put_characters("(?)", 3);
		return;
    }

    put_characters("(", 1);
    new_arg_list = allocate(arg_array_size);
    flat_args(arg, new_arg_list, &no_of_args);

    /* deallocate the excess memory...
    */
    deallocate(arg_array_size - sizeof(NDEM_arg *) * no_of_args);

    for(i = 0;  i < no_of_args;  ++i)
    {
	print_arg(new_arg_list[i]);
	if (i < no_of_args - 1)
	    put_characters(", ", 2);
    }
    put_characters(")", 1);
}

static void print_class(NDEM_class *cl, int full_qual_name)
{
    if (! cl) return;
    if (cl->qual_class && full_qual_name)
    {
	print_class(cl->qual_class, full_qual_name);
	put_characters("::", 2);
    }
    put_string(cl->raw_class_name)
    if (cl->t_args)
	print_template_args(cl->t_args);
}

static void print_name(NDEM_name *name)
{
    if (! name) return;

    switch (name->type) {

	case NDEM_constructor:
	    print_class(name->qual_class, 1);
	    put_characters("::", 2);
	    print_class(name->qual_class, 0);
	    print_function_args(name->f_args);
	    print_p_modifier(name->f_modifier);
	    break;

	case NDEM_destructor:
	    print_class(name->qual_class, 1);
	    put_characters("::~", 3);
	    print_class(name->qual_class, 0);
	    print_function_args(name->f_args);
	    print_p_modifier(name->f_modifier);
	    break;

	case NDEM_operator:
	case NDEM_conversion:
	    if (name->qual_class)
	    {
		if (name->f_modifier.is_static)
		    put_characters("static ", 7);
		print_class(name->qual_class, 1);
		put_characters("::", 2);
	    }
	    put_characters("operator ", 9);
	    if (name->type != NDEM_conversion)
		put_string(name->raw_name)
	    else
		print_arg(name->conv_t);
	    print_function_args(name->f_args);
	    if (name->qual_class)
		print_p_modifier(name->f_modifier);
	    break;

	case NDEM_static_constructor:
	case NDEM_static_destructor:
	case NDEM_other:
	    if (name->qual_class)
	    {
		if (name->f_modifier.is_static)
		    put_characters("static ", 7);
		print_class(name->qual_class, 1);
		put_characters("::", 2);
	    }
	    put_string(name->raw_name)
	    if (name->f_args)
	    {
		print_function_args(name->f_args);
		if (name->qual_class)
		    print_p_modifier(name->f_modifier);
	    }
	    break;

	case NDEM_unnamed_arg:
	default:
	    break;
    }
}

static void print_global_name(NDEM_name *name)
{
    print_name(name);
    put_characters("\0", 1);	/* insert the ending '\0' */
}

static char *in_buffer;
static int ibx;			/* in_buffer index */
static size_t in_len = 0;	/* symbol length */

static void startup(char *in, char *mem, size_t mem_size)
{
    if (in) {
	in_buffer = in;
	ibx = ll_id_size = sk_top = 0;
	in_len = strlen(in);
    }
    mem_reservoir = mem;
    (void) memset(mem_reservoir, 0, mem_size);
}

int yylex(void)
{

    if (ibx + (ll_id_size? ll_id_size - 1 : 0) >= in_len)
	return 0;

    if (! ll_id_size)
	return (ll_cur_char = in_buffer[ibx++]);
    else
    {
	yytext = in_buffer + ibx;
	ibx += ll_id_size;
	ll_id_size = 0;
	return IDENTIFIER;
    }
}


int demangle(char *in, char *out)
{
    if (in == NULL || !*in || out == NULL) return -1;

    if (CHECK_PREFIX(in))
    {
	startup(in, name_buffer, BUFSIZE);
	if (yyparse() == 0)
	{
	    out_buffer = out;
	    obx = 0;	/* reset out_buffer index */
	    print_global_name(result);
	    return 0;
	}
	else
	{
	    /* definitely not a cfront name! */
	    (void) strcpy(out, in);
	    return -1;
	}
    }

    /* Not a cafe symbol, try cfront demangler... */
    return cfront_demangle(in, out);
}

static void yyerror(char *msg)
{
	(void) msg;
}


/* The code below is provided for tools nm, prof, and gprof.
*/

char *cafe_demangle(char *in, char *out)
{
    if (in == NULL || !*in || out == NULL) return in;

    if (CHECK_PREFIX(in))
    {
	startup(in, name_buffer, BUFSIZE);
	if (yyparse() == 0)
	{
	    out_buffer = out;
	    obx = 0;
	    print_global_name(result);
	    return out;
	}
    }

    /* not a cafe symbol... */
    return in;
}
