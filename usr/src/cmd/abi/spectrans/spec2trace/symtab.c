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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <malloc.h>
#include "parser.h"
#include "trace.h"
#include "util.h"
#include "symtab.h"
#include "errlog.h"

/* Types */
enum kind_t { PRIMITIVE = 0, COMPOSITE, VARARG };

struct entry_t {
	char	*e_name;
	int	e_valid;
	int	e_line;
	char	*e_file;
	int	e_kind;		/* PRIMITIVE, COMPOSITE... */
	char	*e_type;	/* where kind == PRIMITIVE */
	/* base type, ie. char if e_type is char */
	char	*e_basetype;
	int	e_levels;	/* levels of indirection */
	char	*e_attribute;	/* kind == COMPOSITE or VARARG. */
	char	*e_assertion;	/* reserved for kind == VARARG. */
	char	*e_comment;	/* reserved for per-element comments. */
	int	e_pre_uses;
	int	e_post_uses;
};

typedef struct entry_head_t {
	int	used;
	int	n_entries;
	ENTRY	entry[1]; /* Actually entry[n_entries]. */
} EHEAD;

static struct symtab_t {
	ENTRY	*Function;
	EHEAD	*Args;
	EHEAD	*Varargs;
	EHEAD	*Globals;
	ENTRY	*Errval;

	/* Includes */
	table_t	*Includes;

	/* Bindings */
	ENTRY	*Exception;

	/* Types */
	table_t	*Print_Types;

	/* Error-message information. */
	int	Line;
	char	Filename[MAXLINE];

	/* Trace additions */
	char	Prototype[MAXLINE];
	char	Formals[MAXLINE];
	char	Actuals[MAXLINE];
	char	Cast[MAXLINE];
	int	Nonreturn;
	int	Skip;

	/* Adl additions */
	/* various assertions, one hopes */
} Symtab;

/* File Globals. */
static EHEAD *create_entry_table(int);
static EHEAD *add_entry_table(EHEAD *,
	char *, int, char *, int, char *, char *, int, char *, int, int);
static ENTRY *get_entry_table(EHEAD *, int);
static EHEAD *free_entry_table(EHEAD *);
static void clear_entries(EHEAD *, int, int);
static ENTRY *allocate_entry(ENTRY *, char *, int, char *, int,
    char *, char *, int, char *, int, int);
static ENTRY *set_entry(ENTRY *,
	char *, int, char *, int, char *, char *, int, char *, int, int);
static ENTRY *free_entry(ENTRY *);
static void symtab_clear_varargs(void);
static void symtab_clear_globals(void);
static void symtab_clear_print_types(void);
static void symtab_set_nonreturn(int);
static table_t *symtab_free_print_types(table_t *);

/*
 * symtab_new_function -- clear counts, variables for a new function.
 */
void
symtab_new_function(const int line, const char *file)
{
	errlog(BEGIN, "symtab_new_function() {");
	Symtab.Line = line;	/* Set, don't clear. */
	symtab_set_filename(file);

	symtab_clear_function();
	symtab_clear_varargs();
	symtab_clear_globals();
	symtab_clear_errval();
	symtab_clear_exception();
	symtab_clear_print_types();

	symtab_set_nonreturn(NO);
	symtab_set_skip(NO);
	errlog(END, "}");
}


/*
 * symtab_clear_function -- clear function-prototype-derived
 *	values. Called on each prototype line and at beginning
 *	of interface.
 */
void
symtab_clear_function(void)
{

	errlog(BEGIN, "symtab_clear_function() {");
	Symtab.Function = free_entry(Symtab.Function);
	Symtab.Args = free_entry_table(Symtab.Args);
	Symtab.Prototype[0] = '\0';
	Symtab.Formals[0] = '\0';
	Symtab.Actuals[0] = '\0';
	Symtab.Cast[0] = '\0';
	errlog(END, "}");
}


/*
 * symtab_clear_varargs -- called only at end
 */
static void
symtab_clear_varargs(void)
{

	errlog(BEGIN, "symtab_clear_varargs() {");
	Symtab.Varargs = free_entry_table(Symtab.Varargs);
	errlog(END, "}");
}

/*
 * symtab_clear_includes -- clear only at end of file (union++)
 */
void
symtab_clear_includes(void)
{

	errlog(BEGIN, "symtab_clear_includes() {");
	Symtab.Includes = free_string_table(Symtab.Includes);
	errlog(END, "}");
}

static void
symtab_clear_globals(void)
{

	errlog(BEGIN, "symtab_clear_globals() {");
	Symtab.Globals = free_entry_table(Symtab.Globals);
	errlog(END, "}");
}

void
symtab_clear_errval(void)
{

	errlog(BEGIN, "symtab_clear_errval() {");
	Symtab.Errval = free_entry(Symtab.Errval);
	errlog(END, "}");
}

void
symtab_clear_exception(void)
{

	errlog(BEGIN, "symtab_clear_exception() {");
	Symtab.Exception = free_entry(Symtab.Exception);
	errlog(END, "}");
}

static void
symtab_clear_print_types(void)
{

	errlog(BEGIN, "symtab_clear_print_types() {");
	Symtab.Print_Types = symtab_free_print_types(Symtab.Print_Types);
	errlog(END, "}");
}


/* Generated by m4 -- character string values */

void
symtab_set_prototype(char *p)
{

	errlog(BEGIN, "symtab_set_prototype(void) {");
	(void) strncpy(Symtab.Prototype, p, sizeof (Symtab.Prototype));
	Symtab.Prototype[sizeof (Symtab.Prototype)-1] = '\0';
	errlog(END, "}");
}

char *
symtab_get_prototype(void)
{
	errlog(BEGIN, "symtab_get_prototype() {"); errlog(END, "}");
	return (Symtab.Prototype);
}

void
symtab_set_formals(char *p)
{
	errlog(BEGIN, "symtab_set_formals() {");
	errlog(VERBOSE, "p = %s", p);
	(void) strncpy(Symtab.Formals, p, sizeof (Symtab.Formals));
	Symtab.Formals[sizeof (Symtab.Formals)-1] = '\0';
	errlog(END, "}");
}

char *
symtab_get_formals(void)
{
	errlog(BEGIN, "symtab_get_formals() {"); errlog(END, "}");
	return (Symtab.Formals);
}

void
symtab_set_actuals(char *p)
{
	errlog(BEGIN, "symtab_set_actuals() {"); errlog(END, "}");
	errlog(VERBOSE, "p = %s", p);
	(void) strncpy(Symtab.Actuals, p, sizeof (Symtab.Actuals));
	Symtab.Actuals[sizeof (Symtab.Actuals)-1] = '\0';
}

char *
symtab_get_actuals(void)
{
	errlog(BEGIN, "symtab_get_actuals() {"); errlog(END, "}");
	return (Symtab.Actuals);
}

void
symtab_set_cast(char *p)
{
	errlog(BEGIN, "symtab_set_cast() {"); errlog(END, "}");
	(void) strncpy(Symtab.Cast, p, sizeof (Symtab.Cast));
	Symtab.Cast[sizeof (Symtab.Cast)-1] = '\0';
}

char *
symtab_get_cast(void)
{
	errlog(BEGIN, "symtab_get_cast() {"); errlog(END, "}");
	return (Symtab.Cast);
}


void
symtab_set_filename(const char *p)
{
	errlog(BEGIN, "symtab_set_filename() {"); errlog(END, "}");
	(void) strncpy(Symtab.Filename, p, sizeof (Symtab.Filename));
	Symtab.Filename[sizeof (Symtab.Filename)-1] = '\0';
}

char *
symtab_get_filename(void)
{
	errlog(BEGIN, "symtab_get_filename() {"); errlog(END, "}");
	return (Symtab.Filename);
}


/* Generated by m4 -- int values */

static void
symtab_set_nonreturn(int val)
{
	errlog(BEGIN, "symtab_set_nonreturn() {"); errlog(END, "}");
	Symtab.Nonreturn = val;
}

int
symtab_get_nonreturn(void)
{
	errlog(BEGIN, "symtab_get_nonreturn() {"); errlog(END, "}");
	return (Symtab.Nonreturn);
}

void
symtab_set_line(int val)
{
	errlog(BEGIN, "symtab_set_line() {"); errlog(END, "}");
	Symtab.Line = val;
}

int
symtab_get_line(void)
{
	errlog(BEGIN, "symtab_get_line() {"); errlog(END, "}");
	return (Symtab.Line);
}


void
symtab_set_skip(int value)
{
	errlog(BEGIN, "symtab_set_skip() {"); errlog(END, "}");
	Symtab.Skip = value;
}

int
symtab_get_skip(void)
{
	errlog(BEGIN, "symtab_get_skip() {"); errlog(END, "}");
	return (Symtab.Skip);
}

/*
 * Manually written access functions for ENTRY * variables.
 */

void
symtab_set_function(char *name, int line, char *file,
    char *type, char *basetype, int levels)
{

	errlog(BEGIN, "symtab_set_function() {");
	Symtab.Function = allocate_entry(Symtab.Function,
	    name, line, file, PRIMITIVE, type, basetype, levels, "", -1, -1);
	errlog(END, "}");
}

ENTRY *
symtab_get_function(void)
{
	errlog(BEGIN, "symtab_get_function() {"); errlog(END, "}");
	if (Symtab.Function == NULL)
		return (NULL);
	else
		return ((Symtab.Function->e_valid)? Symtab.Function: NULL);
}

void
symtab_set_exception(char *value, int line, char *file)
{

	errlog(BEGIN, "symtab_set_exception() {");
	Symtab.Exception = allocate_entry(Symtab.Exception,
		value, line, file, COMPOSITE, "", "", 0, "", -1, -1);
	errlog(END, "}");
}

ENTRY *
symtab_get_exception(void)
{

	errlog(BEGIN, "symtab_get_exception() {"); errlog(END, "}");
	if (Symtab.Exception == NULL)
		return (NULL);
	else
		return ((Symtab.Exception->e_valid)? Symtab.Exception: NULL);
}

void
symtab_set_errval(char *name, int line, char *file, char *type, char *basetype,
    int levels)
{

	errlog(BEGIN, "symtab_set_errval() {");
	Symtab.Errval = allocate_entry(Symtab.Errval,
	    name, line, file, PRIMITIVE, type, basetype, levels,
	    "", -1, -1);
	errlog(END, "}");
}

ENTRY *
symtab_get_errval(void)
{

	errlog(BEGIN, "symtab_get_errval() {"); errlog(END, "}");
	if (Symtab.Errval == NULL)
		return (NULL);
	else
		return ((Symtab.Errval->e_valid)? Symtab.Errval: NULL);
}

/*
 * Manually written  access function for tables of ENTRYs
 */
void
symtab_add_args(char *name, int line, char *file,
    char *type, char *basetype, int levels)
{

	errlog(BEGIN, "symtab_add_args() {");
	if (Symtab.Args == NULL) {
		Symtab.Args = create_entry_table(10);
	}
	Symtab.Args = add_entry_table(Symtab.Args,
	    name, line, file, PRIMITIVE, type, basetype, levels, "", -1, -1);
	errlog(END, "}");
}

static int curr_arg;

ENTRY *
symtab_get_first_arg(void)
{

	errlog(BEGIN, "symtab_get_first_arg() {"); errlog(END, "}");
	curr_arg = 1;
	return (get_entry_table(Symtab.Args, 0));
}

ENTRY *
symtab_get_next_arg(void)
{

	errlog(BEGIN, "symtab_get_next_arg() {"); errlog(END, "}");
	return (get_entry_table(Symtab.Args, curr_arg++));
}

ENTRY *
symtab_get_last_arg(void)
{

	errlog(BEGIN, "symtab_get_last_arg() {"); errlog(END, "}");
	return (get_entry_table(Symtab.Args, Symtab.Args->used));
}

void
symtab_add_varargs(char *name, int line, char *file, char *type, char *print)
{

	errlog(BEGIN, "symtab_add_varargs() {");
	if (Symtab.Varargs == NULL) {
		Symtab.Varargs = create_entry_table(10);
	}
	Symtab.Varargs = add_entry_table(Symtab.Varargs,
		name, line, file, PRIMITIVE, type, print, 0, "", -1, -1);
	errlog(END, "}");
}

static int curr_vararg;

ENTRY *
symtab_get_first_vararg(void)
{

	errlog(BEGIN, "symtab_get_first_vararg() {"); errlog(END, "}");
	curr_vararg = 1;
	return (get_entry_table(Symtab.Varargs, 0));
}

ENTRY *
symtab_get_next_vararg(void)
{

	errlog(BEGIN, "symtab_get_next_vararg() {"); errlog(END, "}");
	return (get_entry_table(Symtab.Varargs, curr_vararg++));
}

void
symtab_add_globals(char *name, int line, char *file, char *type,
    char *basetype, int levels)
{

	errlog(BEGIN, "symtab_add_globals() {");
	if (Symtab.Globals == NULL) {
		Symtab.Globals = create_entry_table(10);
	}
	Symtab.Globals = add_entry_table(Symtab.Globals,
	    name, line, file, PRIMITIVE, type, basetype, levels, "", -1, -1);
	errlog(END, "}");
}


static int curr_global;

ENTRY *
symtab_get_first_global(void)
{

	errlog(BEGIN, "symtab_get_first_global() {"); errlog(END, "}");
	curr_global = 1;
	return (get_entry_table(Symtab.Globals, 0));
}

ENTRY *
symtab_get_next_global(void)
{

	errlog(BEGIN, "symtab_get_next_global() {"); errlog(END, "}");
	return (get_entry_table(Symtab.Globals, curr_global++));
}

/*
 * manually written functions for accessing tables of strings
 */

/*
 * symtab_add_print_types -- add only non-void print types (due to
 *	parser errors in collect.c, yuck). Also note trick compare...
 *	TBD : common code in db, symtab needs to be
 *	pulled out, as they're getting out of sync.
 */
void
symtab_add_print_types(char *print_type, char *c_type)
{
	char	buffer[MAXLINE];

	errlog(BEGIN, "symtab_add_print_types() {");
#ifdef notdef
	if (strcmp(print_type, "void") == 0 || *print_type == NULL) {
		errlog(END, "}");
		return;
	}
#endif
	(void) snprintf(buffer, sizeof (buffer), "%s, %s", print_type, c_type);
	if (Symtab.Print_Types == NULL) {
	Symtab.Print_Types = create_string_table(50);
	}
	if (in_string_table(Symtab.Print_Types, print_type) == NO) {
		Symtab.Print_Types = add_string_table(Symtab.Print_Types,
					&buffer[0]);
	}
	errlog(END, "}");
}

static table_t *
symtab_free_print_types(table_t *t)
{
	errlog(BEGIN, "symtab_free_print_types() {"); errlog(END, "}");
	return (free_string_table(t));
}


static int curr_print_type;

char *
symtab_get_first_print_type(void)
{

	errlog(BEGIN, "symtab_get_first_print_type() {"); errlog(END, "}");
	curr_print_type = 1;
	return (get_string_table(Symtab.Print_Types, 0));
}

char *
symtab_get_next_print_type(void)
{

	errlog(BEGIN, "symtab_get_next_print_type() {"); errlog(END, "}");
	return (get_string_table(Symtab.Print_Types, curr_print_type++));
}

void
symtab_add_includes(char *value)
{

	errlog(BEGIN, "symtab_add_includes() {");
	if (Symtab.Includes == NULL) {
		Symtab.Includes = create_string_table(50);
	}
	if (in_string_table(Symtab.Includes, value) == NO) {
		Symtab.Includes = add_string_table(Symtab.Includes, value);
	}
	errlog(END, "}");
}

static int curr_include;

char *
symtab_get_first_include(void)
{

	errlog(BEGIN, "symtab_get_first_include() {"); errlog(END, "}");
	curr_include = 1;
	return (get_string_table(Symtab.Includes, 0));
}

char *
symtab_get_next_include(void)
{

	errlog(BEGIN, "symtab_get_next_include() {"); errlog(END, "}");
	return (get_string_table(Symtab.Includes, curr_include++));
}


void
symtab_sort_includes(void)
{
	errlog(BEGIN, "symtab_sort_includes() {");
	sort_string_table(Symtab.Includes);
	errlog(END, "}");
}

/*
 * ENTRYs  -- access functions to contents of an entry.
 */

char *
name_of(ENTRY *e)
{
	return (e->e_name);
}

int
validity_of(ENTRY *e)
{

	if (e == NULL)
		return (NO);
	else
		return (e->e_valid);
}

int
line_of(ENTRY *e)
{
	return (e->e_line);
}


char *
file_of(ENTRY *e)
{
	return (e->e_file);
}

/*
 * x_type_of -- return (type with an extension: an embedded %s where
 *	the name goes.
 */
char *
x_type_of(ENTRY *e)
{
	if (e != NULL && (e->e_kind == PRIMITIVE || e->e_kind == VARARG))
		return (e->e_type);
	else
		return (NULL);
}


/*
 * type_of -- return (just the type, with the %s removed. This is the common
 *	case, and its also the slowest... TBD.
 */
char *
type_of(ENTRY *e)
{
	static char buffer[MAXLINE];
	char	*p, *q;

	if (e != NULL && (e->e_kind == PRIMITIVE || e->e_kind == VARARG)) {
		p = e->e_type;
		q = &buffer[0];
		while (*p != '\0') {
			if (*p == '%') {
				p += 2;
			} else {
				*q++ = *p++;
			}
		}
		*q = '\0';
		return (strtrim(&buffer[0]));
	}
	else
		return (NULL);
}

char *
basetype_of(ENTRY *e)
{
	if (e != NULL && (e->e_kind == PRIMITIVE || e->e_kind == VARARG))
		return (e->e_basetype);
	else
		return (NULL);
}

int
levels_of(ENTRY *e)
{
	if (e != NULL && (e->e_kind == PRIMITIVE || e->e_kind == VARARG))
		return (e->e_levels);
	else
		return (0);
}

char *
inverse_of(ENTRY *e)
{

	if (e != NULL && e->e_kind == COMPOSITE)
		return (e->e_attribute);
	else
		return (NULL);
}

char *
selector_of(ENTRY *e)
{

	if (e != NULL && e->e_kind == VARARG)
		return (e->e_attribute);
	else
		return (NULL);
}

int
preuses_of(ENTRY *e)
{

	if (e)
		return (e->e_pre_uses);
	else
		return (-1);
}

int
postuses_of(ENTRY *e)
{

	if (e)
		return (e->e_post_uses);
	else
		return (-1);
}


/*
 * allocate_entry -- make a parameter list into a complete
 *	ENTRY struct, allocated dynamically.
 */
	/* ARGSUSED -- lint bug */
static ENTRY *
allocate_entry(ENTRY *e,
    char *name, int line, char *file,
    int kind, char *type, char *basetype, int levels, char *attribute,
    int npre, int npost)
{

	errlog(BEGIN, "allocate_entry() {");
	if (e == NULL) {
		if ((e = (ENTRY *)calloc(1, sizeof (ENTRY))) == NULL) {
			errlog(FATAL, "can't allocate space for an ENTRY");
		}
	}
	errlog(END, "}");
	return (set_entry(e, name, line, file, kind, type, basetype, levels,
			attribute, npre, npost));
}

/*
 * set_entry -- set a passed-in entry, using
 *	passed parameters, to values suitable for a
 *	symtab entry
 */
static ENTRY *
set_entry(ENTRY *e,
    char *name, int line, char *file,
    int kind, char *type, char *basetype, int levels, char *attribute,
    int npre, int npost)
{

	errlog(BEGIN, "set_entry() {");
	if (e == NULL) {
		errlog(FATAL, "programmer error: passed a NULL ENTRY");
	}
	e->e_name = strset(e->e_name, name);
	e->e_valid = YES;
	e->e_line = line,
	e->e_file = strset(e->e_file, file);
	e->e_kind = kind;
	switch (kind) {
	case PRIMITIVE:
		e->e_type = strset(e->e_type, type);
		e->e_basetype = strset(e->e_basetype, basetype);
		e->e_levels = levels;
		break;
	case COMPOSITE:
		e->e_attribute = strset(e->e_attribute, attribute);
		break;
	case VARARG:
		e->e_attribute = strset(e->e_attribute, attribute);
		break;
	default:
		errlog(FATAL, "programmer error: impossible kind of ENTRY");
	}

	e->e_pre_uses = npre;
	e->e_post_uses = npost;
	errlog(END, "}");
	return (e);
}


/*
 * free_entry -- really just mark an entry as invalid
 */
static ENTRY *
free_entry(ENTRY *e)
{
	if (e != NULL)
		e->e_valid = NO;
	return (e);
}


/*
 * ENTRY tables.
 */
#define	ENTRY_INCREMENT 10

static EHEAD *
create_entry_table(int n)
{
	EHEAD	*p;

	errlog(BEGIN, "create_entry_table() {");
	if ((p = (EHEAD *)calloc(1,
	    sizeof (EHEAD)+(n*sizeof (ENTRY)))) == NULL) {
		errlog(FATAL, "can't allocate space for an ENTRY table");
	}
	p->used = -1;
	p->n_entries = n;
	errlog(END, "}");
	return (p);
}

static EHEAD *
add_entry_table(EHEAD *t, char *name, int line, char *file,
    int kind, char *type, char *basetype, int levels, char *attribute,
    int npre, int npost)
{
	EHEAD	*t2;

	errlog(BEGIN, "add_entry_table() {");
	if (t == NULL) {
		errlog(FATAL, "programmer error: tried to add to NULL EHEAD");
	}
	t->used++;
	if (t->used >= t->n_entries) {
		if ((t2 = (EHEAD *)realloc(t,
			sizeof (EHEAD)+(sizeof (ENTRY)*
				(t->n_entries+ENTRY_INCREMENT)))) == NULL) {
			errlog(FATAL, "out of memory extending an EHEAD");
		}
		t = t2;
		clear_entries(t, t->n_entries, (t->n_entries+ENTRY_INCREMENT));
		t->n_entries += ENTRY_INCREMENT;
	}
	(void) set_entry(&t->entry[t->used],
	    name, line, file, kind, type, basetype, levels,
	    attribute, npre, npost);
	errlog(END, "}");
	return (t);
}

static ENTRY *
get_entry_table(EHEAD *t, int index)
{
	if (t == NULL)  {
		return (NULL);
	} else if (index > t->used) {
		return (NULL);
	} else {
		return (&(t->entry[index]));
	}
}

static EHEAD *
free_entry_table(EHEAD *t)
{
	if (t != NULL)
		t->used = -1;
	return (t);
}

static void
clear_entries(EHEAD *t, int start, int end)
{
	int	i;

	for (i = start; i < end; i++) {
		(void) memset(&t->entry[i], 0, sizeof (ENTRY));
	}
}
