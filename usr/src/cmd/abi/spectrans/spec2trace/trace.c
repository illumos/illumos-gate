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
 * Copyright (c) 1997-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *
 * trace.c -- a  simple translator from spec source to c source for
 *	a apptrace interposer library.  This file implements the
 *	(interface to) the front end. Other files implement the middle
 *	and databases, and generate.c implements the back end.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>

#include "parser.h"
#include "trace.h"

#include "util.h"
#include "db.h"
#include "symtab.h"
#include "io.h"
#include "printfuncs.h"
#include "errlog.h"
#include "parseproto.h"

static int  Verbose;

/* File globals. This would be better as a class. */
/* The first four (commented out) of these enums are defined in parser.h */
enum {
	/* XLATOR_KW_NOTFOUND = 0, */
	/* XLATOR_KW_FUNC, */
	/* XLATOR_KW_DATA */
	/* XLATOR_KW_END */
	XLATOR_KW_EXCP = 4,
	XLATOR_KW_DECL,
	XLATOR_KW_INCL,
	XLATOR_KW_ERRNO,
	XLATOR_KW_ERRVAL,
	XLATOR_KW_ARCH,
	XLATOR_KW_WEAK
};
#define	FIRST_TOKEN 4	/* Must match the first token in the above enum */

static xlator_keyword_t Keywords[] = {
	{ "exception", XLATOR_KW_EXCP },
	{ "declaration", XLATOR_KW_DECL },
	{ "include", XLATOR_KW_INCL },
	{ "errno", XLATOR_KW_ERRNO },
	{ "errval", XLATOR_KW_ERRVAL},
	{ "arch", XLATOR_KW_ARCH},
	{ "weak", XLATOR_KW_WEAK},
	{ "weakfor", XLATOR_KW_WEAK},
	{ "alias", XLATOR_KW_WEAK},
	{ NULL, XLATOR_KW_NOTFOUND }
};

static struct stats_t {
	int	libraries,
		files,
		interfaces,
		lines;
	int	errors,
		warnings,
		skips;
	time_t	start,
		end;
} Statistics;

#define	LINE	(m.mi_line_number-(m.mi_nlines-1))

static void stats_init(void);
static void stats_report(void);

static int collect_binding(int const, char *, int);
static int collect_prototype(char *, int, int);
static int collect_include(char *, int);
static int collect_errval(char *, int);
static int collect_arch(char *);

static void generate_includes(void);
static void generate_init(void);
static void generate_interface(void);
static void generate_closedown(void);
static int generate_aux_file();

/* Local (static) parsing functions. */
static char *to_actual();
static int to_basetype(char *);
static char *de_const(char *);
static char *strpqcpy(char *, char *, char *);

/*
 * xlator_init -- initialize translator, called at startup-time
 *	with a struct translator_info of information the translator
 *	might need, returning a list of ``interesting'' spec keywords
 *	for the front end to select and pass to the back end translator.
 *
 */
xlator_keyword_t *
xlator_init(const Translator_info *t_info)
{
	int	i;

	errlog(BEGIN, "xlator_init() {");

	/* Save interesting parameters. */
	stats_init();
	db_set_source_directory(".");
	db_set_target_directory(".");
	Verbose = t_info->ti_verbosity;
	seterrseverity(Verbose); /* Ditto. */
	db_set_output_file(t_info->ti_output_file);
	db_set_arch(t_info->ti_arch);

	/* Display passed argument and return value. */
	errlog(VERBOSE, "Keywords[] = {");
	for (i = 0; Keywords[i].key != NULL; i++) {
		errlog(VERBOSE, "    \"%s\", ", Keywords[i].key);
	}
	errlog(VERBOSE, "    (char *) NULL");
	errlog(VERBOSE, "};");

	errlog(END, "}");
	return (Keywords);
}

/*
 * xlator_startlib -- called on starting a new library, so back end
 *	translator can decide to change output file/directory if desired.
 */
int
xlator_startlib(char const *libname)
{
	errlog(BEGIN, "xlator_startlib() ");

	Statistics.libraries++;
	db_set_current_library(libname);
	errlog(VERBOSE, "now in library \"%s\"", libname);
	errlog(END, "}");
	return (SUCCESS_RC);
}

/*
 * xlator_startfile -- ditto, called on starting each new spec file in the
 *	specified library.
 */
int
xlator_startfile(char const *filename)
{
	int	rc = SUCCESS_RC;
	char	infile[MAXLINE],
		outfile[MAXLINE],
		*lib = db_get_current_library();

	seterrline(0, filename, "", "");
	errlog(BEGIN, "xlator_startfile() {");
	Statistics.files++;
	db_set_current_file(filename);
	errlog(TRACING, "now in file \"%s\" in lib \"%s\"",
		filename, lib);

	/* Generate filenames. */
	(void) snprintf(infile, sizeof (infile), "%s", filename);
	(void) snprintf(outfile, sizeof (outfile), "%s.c",
		db_get_output_file());

	/* Open .c file. */
	if (open_code_file() == NO) {
		rc = ERROR_RC;
	}

	generate_init(); /* Write stuff to the c file. */
	symtab_clear_includes(); /* Clear out the per-file data. */
	errlog(END, "}");
	return (rc);
}

/*
 * xlator_start_if -- tritto, called on starting each new
 *	interface in the spec file.
 */
int
xlator_start_if(const Meta_info m, int const token, char *value)
{
	char ifname[BUFSIZ];
	char *kw;

	switch (token) {
	case XLATOR_KW_FUNC:
		kw = "Function";
		break;
	case XLATOR_KW_DATA:
		kw = "Data";
		break;
	default:
		/* This should never happen */
		errlog(ERROR,
		    "\"%s\", line %d: Implementation error! "
		    "Please file a bug\n", __FILE__, __LINE__);
		return (XLATOR_FATAL);
	}

	seterrline(LINE, m.mi_filename, kw, value);
	errlog(BEGIN, "xlator_start_if() {");

/*
 * XXX Note whether interface is function or data in some state data item.
 * We'll need it later when writing interceptors.
 */

	Statistics.interfaces++;
	(void) strpqcpy(ifname, value, nextsep2(value));
	if (*ifname == '\0') {
		errlog(INPUT|ERROR|FATAL,
		    "missing argument in \"%s\" line", kw);
	}
	db_set_current_interface(ifname);
	errlog(VERBOSE, "interface='%s'", value);
	if (token == XLATOR_KW_DATA) {
		Statistics.skips++;
		errlog(VERBOSE, "telling front end to skip '%s'", value);
		errlog(END, "}");
		return (SKIP_RC); /* Tell front end to skip it for us. */
	}

	errlog(TRACING, "now in interface \"%s\"", value);

	symtab_new_function(m.mi_line_number, m.mi_filename);
		/* Also cleans junk out of symbol table. */
	errlog(END, "}");
	return (SUCCESS_RC);
}

/*
 * xlator_take_kvpair -- the primary call: collect a datum provide by the
 *	front-end wrapper.
 */
int
xlator_take_kvpair(Meta_info m, int const token, char *value)
{
	int retval;
	char *key = Keywords[token-FIRST_TOKEN].key;

	int line = LINE; /* TBD */
	symtab_set_filename(m.mi_filename);

	value = strnormalize(value);

	seterrline(line, m.mi_filename, key, value);
	errlog(BEGIN, "xlator_take_kvpair() {");
	Statistics.lines++;
	errlog(VERBOSE, "key='%s', value='%s'",
	    (key) ? key : "<nil>",
	    (value) ? value : "<nil>");
	switch (token) {
	case XLATOR_KW_DECL:

	/*
	 * XXX Check state item to see that it is a function,
	 * else do not emit interceptor
	 */
		symtab_clear_function(); /* Always use last one. */
		errlog(END, "}");
		retval = collect_prototype(value, line, m.mi_ext_cnt);
		break;

	case XLATOR_KW_INCL:
		errlog(END, "}"); /* Use union of all includes. */
		retval = collect_include(value, line);
		if (retval == ERROR_RC) {
			errlog(FATAL|INPUT, "Bad include line in spec file");
		}
		break;

	case XLATOR_KW_EXCP:
		symtab_clear_exception(); /* Always use last. */
		retval = collect_binding(token, value, line);
		break;

	case XLATOR_KW_ERRNO:
		symtab_clear_errval(); /* Always use last. */
		retval = collect_errval("errno", line);
		break;

	case XLATOR_KW_ERRVAL:
		symtab_clear_errval(); /* Always use last. */
		retval =  collect_errval(value, line);
		break;

	case XLATOR_KW_ARCH:
		retval = collect_arch(value);
		break;

	case XLATOR_KW_WEAK:
		if (m.mi_extended == 1) {
			errlog(ERROR, "\"%s\", line %d: "
			    "Warning: Cannot use extends with a weak "
			    "interface",
			    m.mi_filename,
			    m.mi_line_number);
		}
		retval = SUCCESS_RC;
		break;
	default:
		retval = ERROR_RC;
	}

	errlog(END, "}");

	return (retval);
}

/*
 * xlator_end_if -- called at the end of the interface, to trigger
 *	per-interface processing now entire thing has been seen.
 */
/*ARGSUSED*/
int
xlator_end_if(const Meta_info m, char const *value)
{
	seterrline(LINE, m.mi_filename, "end", value);
	errlog(BEGIN, "xlator_end_if() {");
	if (symtab_get_skip() == YES) {
		symtab_set_skip(NO);
		Statistics.skips++;
	} else {
		generate_interface();
	}
	errlog(END, "}");
	return (SUCCESS_RC);
}

/*
 * xlator_endfile -- called at the end of the file, to trigger per-file
 * processing.
 */
int
xlator_endfile(void)
{
	errlog(BEGIN, "xlator_endfile() {");

	generate_closedown();
	errlog(END, "}");
	return ((commit_code_file() == YES)? SUCCESS_RC: ERROR_RC);
}

/*
 * xlator_endlib -- ditto, at the end of the library.
 */
int
xlator_endlib(void)
{
	errlog(BEGIN, "xlator_endlib() {");
	errlog(END, "}");
	return (SUCCESS_RC);
}

/*
 * xlator_end -- the end of the processing, called so translator
 *	can do cleanup, write makefiles, etc.
 */
int
xlator_end(void)
{
	int	rc = SUCCESS_RC;

	errlog(BEGIN, "xlator_end() {");
	rc += !generate_aux_file();
	stats_report();
	errlog(END, "}");
	return (rc);
}


/*
** utilities for this layer/phase only.
*/

/*
 * stats_init -- note what time it is...
 */
static void
stats_init(void)
{
	Statistics.start = time(NULL);
}

/*
 * stats_report -- say how much we just did
 */
#define	max(a, b) (a > b)? a: b

static void
stats_report(void)
{
	double	seconds;

	Statistics.end = time(NULL);
	seconds = difftime(Statistics.end, Statistics.start);

	switch (Verbose) {
	default:
		/*FALLTHROUGH*/
	case 1:
		(void) fprintf(stderr, "Statistics:\n"
		    "    %d libraries\n    %d files\n"
		    "    %d interfaces\n    %d lines\n"
		    "    %d errors\n    %d warnings\n"
		    "    %d skips\n"
		    "in %.0f seconds, at %.1f lines/minute.\n",
		    Statistics.libraries, Statistics.files,
		    Statistics.interfaces, Statistics.lines,
		    Statistics.errors, Statistics.warnings,
		    Statistics.skips,
		    seconds, Statistics.lines*60.0/seconds);
		break;
	case 0:
		if (Statistics.errors != 0 || Statistics.warnings != 0) {
			(void) fprintf(stderr,
			    "spec2trace: %d errors %d warnings.\n",
			    Statistics.errors, Statistics.warnings);
		}
		break;
	}
}


/*
 * Tiny stats class...
 */
void
stats_add_warning(void)
{
	Statistics.warnings++;
}

void
stats_add_error(void)
{
	Statistics.errors++;
}

/*
 * collect_includes -- collect a global list of include files,
 *	converting the comma- or space-separated input list into a
 *	structure for the database to store.
 *	As this can cause problems will ill-structured
 *	files, there is a mechanism to allow exclusion of
 *	certain files, (or certain combinations).  At
 *	the moment, the mechanism is TBD, as is the second arg.
 */
/*ARGSUSED1*/
int
collect_include(char *p, int line)
{
	char	*include;
	int	len;

	errlog(BEGIN, "collect_include() {");
	if ((include = strtok(p, ", ")) != NULL) {
		for (; include != NULL; include = strtok(NULL, ", ")) {
			include  = skipb(include);

			/*
			 * Make sure the include file's name
			 * has legitimate C syntax - i.e. it's in double
			 * quotes or angle brackets.
			 */
			if (*include != '"' && *include != '<')
				return (ERROR_RC);

			len = strlen(include);

			if (include[len-1] != '"' && include[len-1] != '>')
				return (ERROR_RC);

			/*
			 * If include filename syntax is OK, add it to
			 * the list
			 */
			symtab_add_includes(include);
		}
	}
	errlog(END, "}");
	return (SUCCESS_RC);
}

/*
 * collect_binding -- take a binding and stuff it into the database
 *	in canonical form (with the word return in it).
 */
int
collect_binding(int const token, char *value, int line)
{
	char	*file = db_get_current_file();

	errlog(BEGIN, "collect_binding() {");
	errlog(VERBOSE, "name=\"%s\", value=\"%s\", line=%d\n",
	    Keywords[token-FIRST_TOKEN].key, value, line);

	if (token == XLATOR_KW_EXCP) {
		symtab_set_exception(value, line, file);
	} else {
		errlog(FATAL|INPUT, "programmer error: impossible binding.");
	}
	errlog(END, "}");
	return (SUCCESS_RC);
}

/*
 * collect_errval -- collect the error variable name (only)
 *	from the line.  This is expected to be the first
 *	or only thing in a space- or comma-separated list.
 *	Collecting errno/errval possible value is left TBD.
 */
int
collect_errval(char *p, int line)
{
	char	*name;

	errlog(BEGIN, "collect_errval() {");
	name = strtok(p, " \t\n\r");
	symtab_set_errval(name, line, db_get_current_file(), "int", "int", 0);
	errlog(END, "}");
	return (SUCCESS_RC);
}

/*
 * collect_arch -- collect architecture.
 */
int
collect_arch(char *value)
{
	char const	*arch = db_get_arch();
	char	*buf, *p;
	char	*t;

	errlog(BEGIN, "collect_arch() {");
	if (value == 0 || *value == '\0')
		errlog(FATAL|INPUT, "No architectures defined in ARCH line");

	if ((buf = strdup(value)) == NULL)
		errlog(FATAL, "Could not allocate memory in ARCH directive");

	t = buf;
	while ((p = strtok(t, " \r\t\n")) != NULL) {
		if (strcmp(p, arch) == 0 || strcmp(p, "all") == 0)
			goto cleanup;
		t = NULL;
	}
	symtab_set_skip(YES);

cleanup:
	free(buf);
	return (SUCCESS_RC);
}

/*
 * de_const -- get rid of const meta-types. This is actually a
 *	dodge to avoid writing a base-type function early in the
 *	process. This may turn into to_basetype() or to_primitivetype().
 */
static char *
de_const(char *type)
{
	char *p, *q;
	int i;

	p = skipb(type);

	q = strstr(type, "const");
	if (q > p) {
		for (i = 0; i < 5; i++) {
			*q++ = '\0';
		}
		(void) sprintf(type, "%s%s", strnormalize(p), q);
		return (type);
	} else if (p == q) {
		return (skipb(nextsep(p)));
	} else {
		return (type);
	}

}

/*
 * to_basetype -- convert a C type declaration into its base type and return
 * 	the number of levels of indirection.
 *	Destructive and eats ``const''.
 */
static int
to_basetype(char *str)
{
	char	*p = str,
		buffer[MAXLINE+1],
		*q = &buffer[0];
	int	levels = 0;

	assert(strlen(str) < MAXLINE, "string exceeded MAXLINE");
	buffer[0] = '\0';
	for (; *p != '\0'; p++) {
		switch (*p) {
		case ' ': /* Convert spaces to single ' '. */
			if (*(q-1) != ' ')
				*q++ = ' ';
			break;
		case '*': /* Convert * to _P. */
			if (*(q-1) != ' ')
				*q++ = ' ';
			levels++;
			break;
		case 'c': /* This might be a const */
			if (strncmp(p, "const", 5) == 0) {
				p += 4;
			} else {
				*q++ = *p;
			}
			break;
		default:
			/* Otherwise just copy. */
			*q++ = *p;
			break;
		}
		*q = '\0';
	}
	assert(q < &buffer[MAXLINE], "q fell off end of buffer");
	q--;
	while (*q == ' ') {
		*q-- = '\0';
	}
	assert(strlen(buffer) < MAXLINE, "buffer length exceeded MAXLINE");
	(void) strcpy(str, buffer);
	return (levels);
}

/*
 * to_actual -- create an actual-argument list for use
 *	when calling the function.
 */
static char *
to_actual(void)
{
	ENTRY	*p;
	static char buffer[MAXLINE+1];
	int	n;

	*buffer = '\0';
	if ((p = symtab_get_first_arg()) != NULL) {
		n = MAXLINE - snprintf(buffer, MAXLINE, "%s", name_of(p));
		for (p = symtab_get_next_arg(); p != NULL;
						p = symtab_get_next_arg()) {
			if (*name_of(p) != '\0')
				n -= snprintf(strend(buffer), n,
					", %s", name_of(p));
		}
	}
	return (buffer);
}

/*
 * strpqcpy -- string copy that takes whatever begins with p and ends
 *	just before q.
 */
static char *
strpqcpy(char *target, char *p, char *q)
{
	char	saved;

	saved = *q;
	*q = '\0';
	(void) strcpy(target, p);
	*q = saved;
	return (target);
}

#ifndef lint
int
breakpoint(void)
{
	return (0);
}
#endif


int
collect_prototype(char *p, int line, int extcnt)
{
	char	f_type[BUFSIZ];	/* The function. */
	char	f_basetype[BUFSIZ];
	char	f_name[BUFSIZ];
	char	a_name[BUFSIZ];	/* The arguments. */
	char	a_basetype[BUFSIZ];
	char	a_type[BUFSIZ];
	char	*file = db_get_current_file();
	char	*interface = db_get_current_interface();
	char	*q;
	char const *parse_err;
	char	tmp_proto[BUFSIZ], buf[BUFSIZ];
	decl_t	*pp, *funargs;
	type_t	*tp;
	int	levels, a_levels;

	tmp_proto[BUFSIZ-1] = 0;
	errlog(BEGIN, "collect_prototype() {");
	if (p[strlen(p)-1] != ';')
		(void) snprintf(tmp_proto, BUFSIZ, "%s;", p);
	else
		(void) snprintf(tmp_proto, BUFSIZ, "%s", p);

	/* save prototype in symbol table */
	symtab_set_prototype(p);

	errlog(VERBOSE, "parsing prototype: %s\n", tmp_proto);

	/* Parse Prototype */
	if ((parse_err = decl_Parse(tmp_proto, &pp)) != NULL) {
		errlog(FATAL|INPUT, "bad prototype: %s\n\t%s\n", parse_err, p);
	}

	if (extcnt == 0) {
		char *dname = decl_GetName(pp);
		if (strcmp(interface, dname) != 0)
			errlog(FATAL|INPUT, "function and declaration"
			    " name mismatch\nfunction name = %s,"
			    " declaration name = %s\n", interface,
			    dname);
	}

	tp = decl_GetType(pp);

	if (type_IsPtrFun(tp)) {
		errlog(FATAL|INPUT, "function %s is declared as a data item"
		    " (pointer to function)\n", interface);
	} else if (!type_IsFunction(tp)) {
		errlog(FATAL|INPUT, "function %s is declared as a data item",
		    interface);
	}

	if (type_IsVarargs(tp)) {
		symtab_set_skip(YES);
		decl_Destroy(pp);
		return (SUCCESS_RC);
	}

	decl_GetTraceInfo(pp, f_type, f_basetype, &funargs);
	(void) sprintf(buf, "%s", strnormalize(f_type));
	(void) strcpy(f_type, buf);
	(void) sprintf(buf, "%s", strnormalize(f_basetype));
	(void) strcpy(f_basetype, buf);
	levels = to_basetype(f_basetype);

	/* get interface name from 'Begin' line */
	(void) strpqcpy(f_name, interface, nextsep(interface));
	(void) decl_SetName(pp, f_name);

	errlog(VERBOSE, "f_name=%s, f_basetype=%s, f_type=%s\n",
		f_name, f_basetype, f_type);

	symtab_set_function(f_name, line, file, f_type, f_basetype, levels);

	db_add_print_types(f_basetype,
	    (q = de_const(type_of(symtab_get_function()))));

	symtab_add_print_types(f_basetype, q);

	/* args list */
	while (funargs) {
		(void) snprintf(a_type, BUFSIZ, "%s ",
			strnormalize(declspec_ToString(buf, funargs->d_ds)));
		(void) snprintf(a_basetype, BUFSIZ, "%s",
			strnormalize(de_const(declspec_ToString(buf,
			funargs->d_ds))));

		tp = funargs->d_type;

		for (a_levels = 0; tp; ) {
			if (tp->t_dt == DD_PTR || tp->t_dt == DD_ARY) {
				(void) strcat(a_type, "*");
				a_levels++;
			}
			tp = tp->t_next;
		}

		/*
		 * XXX: This is a hack to work around bug in yacc parser
		 *  "int foo(void)" prototypes get interpreted as having 1
		 *  argument with the d_name of the argument being NULL.
		 */
		if (funargs->d_name) {
			(void) snprintf(a_name, 20, "%s", funargs->d_name);

			errlog(VERBOSE,
			    "a_name = %s, a_basetype = %s, a_type = %s\n",
			    a_name, a_basetype, a_type);

			symtab_add_args(a_name, line, file,
			    a_type, a_basetype, a_levels);
			db_add_print_types(a_basetype,
			    q = de_const(type_of(symtab_get_last_arg())));
			symtab_add_print_types(a_basetype, q);
		}

		funargs = funargs->d_next;
	}
	symtab_set_formals(decl_ToFormal(pp));
	symtab_set_actuals(to_actual());

	symtab_set_cast(decl_ToString(buf, DTS_CAST, pp, NULL));

	decl_Destroy(pp);

	errlog(END, "}");
	return (SUCCESS_RC);
}


/*
 * generators
 */

/*
 * generate_init -- prime the code generator as required.
 */
static void
generate_init(void)
{
	errlog(BEGIN, "generate_init() {");

	(void) fprintf(Headfp,
	    "/*\n"
	    " * Generated by spec2trace %s: do not edit this file.\n */\n\n",
	    TRACE_VERSION);

	(void) fprintf(Headfp,
	    "#ifndef true\n"
	    "#define\ttrue 1\n"
	    "#define\tfalse 0\n"
	    "#endif\n\n"
	    "static char const *oparen = \"(\";\n"
	    "static char const *retstr = \"  return = \";\n"
	    "static char const *errnostr = \" errno = \";\n"
	    "static char const *nilstr = \"<nil>\";\n"
	    "\n");

	errlog(END, "}");
}


/*
 * generate_interface -- call the two main parts of the per-interface
 *	code generation.
 */
static void
generate_interface(void)
{
	ENTRY	*function = symtab_get_function();

	errlog(BEGIN, "generate_interface() {");
	/* Check for required information. */
	if (validity_of(function) == NO) {
		symtab_set_skip(YES);
		errlog(WARNING|INPUT, "no prototype for interface "
			"it will be skipped");
		errlog(END, "}");
		return;
	}

	/* Generate the current interface 's print-functions declarations. */
	generate_print_declarations(Bodyfp);

	/* Generate the linkage part (a function and a struct */
	generate_linkage(function);

	/* Generate the actual interceptor. */
	generate_interceptor(function);
	errlog(END, "}");
}


/*
 * generate_closedown -- produce includes.
 */
static void
generate_closedown(void)
{
	errlog(BEGIN, "generate_closedown() {");

	/* Print includes to primary file. */
	generate_includes();
	(void) putc('\n', Headfp);
	errlog(END, "}");
}

/*
 * generate_aux_file -- generate one additional .pf file with
 *	print-function pointers.
 */
static int
generate_aux_file(void)
{
	FILE	*fp;
	char	pathname[MAXLINE];

	errlog(BEGIN, "generate_aux_file() {");
	/* Open file */
	(void) snprintf(pathname, sizeof (pathname), "%s.pf",
		db_get_output_file());
	errlog(TRACING,  "output file = '%s'", pathname);
	if ((fp = fopen(pathname, "w")) == NULL) {
		errlog(FATAL, "%s: %s", pathname, strerror(errno));
	}

	/*
	 * Declare and initialize all print function pointers to null.
	 * Some spec files result in nothing being put into the .pf
	 * file.  We must create the file since make(1) does not cope
	 * well with absent files that it expects to have built.  So
	 * now the build gets empty compilation unit warnings...  So
	 * we unconditionally create a static pointer.
	 */
	(void) fprintf(fp,
	    "/* Do not edit this file: it is a generated one. */\n\n"
	    "static char const *__abi_place_holder;\n\n");

	generate_print_definitions(fp);

	/* Close file */
	if (fclose(fp) != 0) {
		errlog(FATAL, "fclose %s: %s", pathname, strerror(errno));
	}
	errlog(END, "}");
	return (YES);
}



/*
 * generate_includes -- generate #includes to Headfp
 */
static void
generate_includes(void)
{
	char	*include;

	errlog(BEGIN, "generate_includes() {");
	errlog(TRACING,  "includes=");
	for (include = symtab_get_first_include(); include != NULL;
	    include = symtab_get_next_include())
		(void) fprintf(Headfp, "#include %s\n", include);

	(void) fprintf(Headfp, "\n#include <stdio.h>\n"
	    "#include <dlfcn.h>\n"
	    "#include <apptrace.h>\n\n");

	errlog(TRACING,  "\n");
	errlog(END, "}");
}
