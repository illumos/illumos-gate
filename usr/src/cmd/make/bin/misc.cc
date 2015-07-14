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
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	misc.cc
 *
 *	This file contains various unclassified routines. Some main groups:
 *		getname
 *		Memory allocation
 *		String handling
 *		Property handling
 *		Error message handling
 *		Make internal state dumping
 *		main routine support
 */

/*
 * Included files
 */
#include <errno.h>
#include <mk/defs.h>
#include <mksh/macro.h>		/* SETVAR() */
#include <mksh/misc.h>		/* enable_interrupt() */
#include <stdarg.h>		/* va_list, va_start(), va_end() */
#include <vroot/report.h>	/* SUNPRO_DEPENDENCIES */
#include <libintl.h>

extern void job_adjust_fini();

/*
 * Defined macros
 */

/*
 * typedefs & structs
 */

/*
 * Static variables
 */

/*
 * File table of contents
 */
static	void		print_rule(register Name target);
static	void		print_target_n_deps(register Name target);

/*****************************************
 *
 *	getname
 */

/*****************************************
 *
 *	Memory allocation
 */

/*
 *	free_chain()
 *
 *	frees a chain of Name_vector's
 *
 *	Parameters:
 *		ptr		Pointer to the first element in the chain
 *				to be freed.
 *
 *	Global variables used:
 */
void 
free_chain(Name_vector ptr)
{
	if (ptr != NULL) {
		if (ptr->next != NULL) {
			free_chain(ptr->next);
		}
		free((char *) ptr);
	}
}

/*****************************************
 *
 *	String manipulation
 */

/*****************************************
 *
 *	Nameblock property handling
 */

/*****************************************
 *
 *	Error message handling
 */

/*
 *	fatal(format, args...)
 *
 *	Print a message and die
 *
 *	Parameters:
 *		format		printf type format string
 *		args		Arguments to match the format
 *
 *	Global variables used:
 *		fatal_in_progress Indicates if this is a recursive call
 *		parallel_process_cnt Do we need to wait for anything?
 *		report_pwd	Should we report the current path?
 */
/*VARARGS*/
void
fatal(const char *message, ...)
{
	va_list args;

	va_start(args, message);
	(void) fflush(stdout);
	(void) fprintf(stderr, gettext("%s: Fatal error: "), getprogname());
	(void) vfprintf(stderr, message, args);
	(void) fprintf(stderr, "\n");
	va_end(args);
	if (report_pwd) {
		(void) fprintf(stderr,
			       gettext("Current working directory %s\n"),
			       get_current_path());
	}
	(void) fflush(stderr);
	if (fatal_in_progress) {
		exit_status = 1;
		exit(1);
	}
	fatal_in_progress = true;
	/* Let all parallel children finish */
	if ((dmake_mode_type == parallel_mode) &&
	    (parallel_process_cnt > 0)) {
		(void) fprintf(stderr,
			       gettext("Waiting for %d %s to finish\n"),
			       parallel_process_cnt,
			       parallel_process_cnt == 1 ?
			       gettext("job") : gettext("jobs"));
		(void) fflush(stderr);
	}

	while (parallel_process_cnt > 0) {
		await_parallel(true);
		finish_children(false);
	}

	job_adjust_fini();

	exit_status = 1;
	exit(1);
}

/*
 *	warning(format, args...)
 *
 *	Print a message and continue.
 *
 *	Parameters:
 *		format		printf type format string
 *		args		Arguments to match the format
 *
 *	Global variables used:
 *		report_pwd	Should we report the current path?
 */
/*VARARGS*/
void
warning(char * message, ...)
{
	va_list args;

	va_start(args, message);
	(void) fflush(stdout);
	(void) fprintf(stderr, gettext("%s: Warning: "), getprogname());
	(void) vfprintf(stderr, message, args);
	(void) fprintf(stderr, "\n");
	va_end(args);
	if (report_pwd) {
		(void) fprintf(stderr,
			       gettext("Current working directory %s\n"),
			       get_current_path());
	}
	(void) fflush(stderr);
}

/*
 *	time_to_string(time)
 *
 *	Take a numeric time value and produce
 *	a proper string representation.
 *
 *	Return value:
 *				The string representation of the time
 *
 *	Parameters:
 *		time		The time we need to translate
 *
 *	Global variables used:
 */
char *
time_to_string(const timestruc_t &time)
{
	struct tm		*tm;
	char			buf[128];

        if (time == file_doesnt_exist) {
                return gettext("File does not exist");
        }
        if (time == file_max_time) {
                return gettext("Younger than any file");
        }
	tm = localtime(&time.tv_sec);
	strftime(buf, sizeof (buf), "%c %Z", tm);
        buf[127] = (int) nul_char;
        return strdup(buf);
}

/*
 *	get_current_path()
 *
 *	Stuff current_path with the current path if it isnt there already.
 *
 *	Parameters:
 *
 *	Global variables used:
 */
char *
get_current_path(void)
{
	char			pwd[(MAXPATHLEN * MB_LEN_MAX)];
	static char		*current_path;

	if (current_path == NULL) {
		getcwd(pwd, sizeof(pwd));
		if (pwd[0] == (int) nul_char) {
			pwd[0] = (int) slash_char;
			pwd[1] = (int) nul_char;
		}
		current_path = strdup(pwd);
	}
	return current_path;
}

/*****************************************
 *
 *	Make internal state dumping
 *
 *	This is a set  of routines for dumping the internal make state
 *	Used for the -p option
 */

/*
 *	dump_make_state()
 *
 *	Dump make's internal state to stdout
 *
 *	Parameters:
 *
 *	Global variables used:
 *		svr4 			Was ".SVR4" seen in makefile?
 *		svr4_name		The Name ".SVR4", printed
 *		posix			Was ".POSIX" seen in makefile?
 *		posix_name		The Name ".POSIX", printed
 *		default_rule		Points to the .DEFAULT rule
 *		default_rule_name	The Name ".DEFAULT", printed
 *		default_target_to_build	The first target to print
 *		dot_keep_state		The Name ".KEEP_STATE", printed
 *		dot_keep_state_file	The Name ".KEEP_STATE_FILE", printed
 *		hashtab			The make hash table for Name blocks
 *		ignore_errors		Was ".IGNORE" seen in makefile?
 *		ignore_name		The Name ".IGNORE", printed
 *		keep_state		Was ".KEEP_STATE" seen in makefile?
 *		percent_list		The list of % rules
 *		precious		The Name ".PRECIOUS", printed
 *		sccs_get_name		The Name ".SCCS_GET", printed
 *		sccs_get_posix_name	The Name ".SCCS_GET_POSIX", printed
 *		get_name		The Name ".GET", printed
 *		get_posix_name		The Name ".GET_POSIX", printed
 *		sccs_get_rule		Points to the ".SCCS_GET" rule
 *		silent			Was ".SILENT" seen in makefile?
 *		silent_name		The Name ".SILENT", printed
 *		suffixes		The suffix list from ".SUFFIXES"
 *		suffixes_name		The Name ".SUFFIX", printed
 */
void
dump_make_state(void)
{
	Name_set::iterator	p, e;
	register Property	prop;
	register Dependency	dep;
	register Cmd_line	rule;
	Percent			percent, percent_depe;

	/* Default target */
	if (default_target_to_build != NULL) {
		print_rule(default_target_to_build);
	}
	(void) printf("\n");

	/* .POSIX */
	if (posix) {
		(void) printf("%s:\n", posix_name->string_mb);
	}

	/* .DEFAULT */
	if (default_rule != NULL) {
		(void) printf("%s:\n", default_rule_name->string_mb);
		for (rule = default_rule; rule != NULL; rule = rule->next) {
			(void) printf("\t%s\n", rule->command_line->string_mb);
		}
	}

	/* .IGNORE */
	if (ignore_errors) {
		(void) printf("%s:\n", ignore_name->string_mb);
	}

	/* .KEEP_STATE: */
	if (keep_state) {
		(void) printf("%s:\n\n", dot_keep_state->string_mb);
	}

	/* .PRECIOUS */
	(void) printf("%s:", precious->string_mb);
	for (p = hashtab.begin(), e = hashtab.end(); p != e; p++) {
			if ((p->stat.is_precious) || (all_precious)) {
				(void) printf(" %s", p->string_mb);
			}
	}
	(void) printf("\n");

	/* .SCCS_GET */
	if (sccs_get_rule != NULL) {
		(void) printf("%s:\n", sccs_get_name->string_mb);
		for (rule = sccs_get_rule; rule != NULL; rule = rule->next) {
			(void) printf("\t%s\n", rule->command_line->string_mb);
		}
	}

	/* .SILENT */
	if (silent) {
		(void) printf("%s:\n", silent_name->string_mb);
	}

	/* .SUFFIXES: */
	(void) printf("%s:", suffixes_name->string_mb);
	for (dep = suffixes; dep != NULL; dep = dep->next) {
		(void) printf(" %s", dep->name->string_mb);
		build_suffix_list(dep->name);
	}
	(void) printf("\n\n");

	/* % rules */
	for (percent = percent_list;
	     percent != NULL;
	     percent = percent->next) {
		(void) printf("%s:",
			      percent->name->string_mb);
		
		for (percent_depe = percent->dependencies;
		     percent_depe != NULL;
		     percent_depe = percent_depe->next) {
			(void) printf(" %s", percent_depe->name->string_mb);
		}
		
		(void) printf("\n");

		for (rule = percent->command_template;
		     rule != NULL;
		     rule = rule->next) {
			(void) printf("\t%s\n", rule->command_line->string_mb);
		}
	}

	/* Suffix rules */
	for (p = hashtab.begin(), e = hashtab.end(); p != e; p++) {
			Wstring wcb(p);
			if (wcb.get_string()[0] == (int) period_char) {
				print_rule(p);
			}
	}

	/* Macro assignments */
	for (p = hashtab.begin(), e = hashtab.end(); p != e; p++) {
			if (((prop = get_prop(p->prop, macro_prop)) != NULL) &&
			    (prop->body.macro.value != NULL)) {
				(void) printf("%s", p->string_mb);
				print_value(prop->body.macro.value,
					    (Daemon) prop->body.macro.daemon);
			}
	}
	(void) printf("\n");

	/* Conditional macro assignments */
	for (p = hashtab.begin(), e = hashtab.end(); p != e; p++) {
			for (prop = get_prop(p->prop, conditional_prop);
			     prop != NULL;
			     prop = get_prop(prop->next, conditional_prop)) {
				(void) printf("%s := %s",
					      p->string_mb,
					      prop->body.conditional.name->
					      string_mb);
				if (prop->body.conditional.append) {
					printf(" +");
				}
				else {
					printf(" ");
				}
				print_value(prop->body.conditional.value,
					    no_daemon);
			}
	}
	(void) printf("\n");

	/* All other dependencies */
	for (p = hashtab.begin(), e = hashtab.end(); p != e; p++) {
			if (p->colons != no_colon) {
				print_rule(p);
			}
	}
	(void) printf("\n");
}

/*
 *	print_rule(target)
 *
 *	Print the rule for one target
 *
 *	Parameters:
 *		target		Target we print rule for
 *
 *	Global variables used:
 */
static void
print_rule(register Name target)
{
	register Cmd_line	rule;
	register Property	line;
	register Dependency	dependency;

	if (target->dependency_printed ||
	    ((line = get_prop(target->prop, line_prop)) == NULL) ||
	    ((line->body.line.command_template == NULL) &&
	     (line->body.line.dependencies == NULL))) {
		return;
	}
	target->dependency_printed = true;

	(void) printf("%s:", target->string_mb);

	for (dependency = line->body.line.dependencies;
	     dependency != NULL;
	     dependency = dependency->next) {
		(void) printf(" %s", dependency->name->string_mb);
	}

	(void) printf("\n");

	for (rule = line->body.line.command_template;
	     rule != NULL;
	     rule = rule->next) {
		(void) printf("\t%s\n", rule->command_line->string_mb);
	}
}

void
dump_target_list(void)
{
	Name_set::iterator	p, e;
	Wstring	str;

	for (p = hashtab.begin(), e = hashtab.end(); p != e; p++) {
			str.init(p);
			wchar_t * wcb = str.get_string();
			if ((p->colons != no_colon) &&
			    ((wcb[0] != (int) period_char) ||
			     ((wcb[0] == (int) period_char) &&
			      (wcschr(wcb, (int) slash_char))))) {
				print_target_n_deps(p);
			}
	}
}

static void
print_target_n_deps(register Name target)
{
	register Cmd_line	rule;
	register Property	line;
	register Dependency	dependency;

	if (target->dependency_printed) {
		return;
	}
	target->dependency_printed = true;

	(void) printf("%s\n", target->string_mb);

	if ((line = get_prop(target->prop, line_prop)) == NULL) {
		return;
	}
	for (dependency = line->body.line.dependencies;
	     dependency != NULL;
	     dependency = dependency->next) {
		if (!dependency->automatic) {
			print_target_n_deps(dependency->name);
		}
	}
}

/*****************************************
 *
 *	main() support
 */

/*
 *	load_cached_names()
 *
 *	Load the vector of cached names
 *
 *	Parameters:
 *
 *	Global variables used:
 *		Many many pointers to Name blocks.
 */
void
load_cached_names(void)
{
	char		*cp;
	Name		dollar;

	/* Load the cached_names struct */
	MBSTOWCS(wcs_buffer, ".BUILT_LAST_MAKE_RUN");
	built_last_make_run = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "@");
	c_at = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, " *conditionals* ");
	conditionals = GETNAME(wcs_buffer, FIND_LENGTH);
	/*
	 * A version of make was released with NSE 1.0 that used
	 * VERSION-1.1 but this version is identical to VERSION-1.0.
	 * The version mismatch code makes a special case for this
	 * situation.  If the version number is changed from 1.0
	 * it should go to 1.2.
	 */
	MBSTOWCS(wcs_buffer, "VERSION-1.0");
	current_make_version = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".SVR4");
	svr4_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".POSIX");
	posix_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".DEFAULT");
	default_rule_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "$");
	dollar = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".DONE");
	done = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".");
	dot = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".KEEP_STATE");
	dot_keep_state = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".KEEP_STATE_FILE");
	dot_keep_state_file = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "");
	empty_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, " FORCE");
	force = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "HOST_ARCH");
	host_arch = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "HOST_MACH");
	host_mach = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".IGNORE");
	ignore_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".INIT");
	init = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".LOCAL");
	localhost_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".make.state");
	make_state = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "MAKEFLAGS");
	makeflags = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".MAKE_VERSION");
	make_version = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".NO_PARALLEL");
	no_parallel_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".NOT_AUTO");
	not_auto = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".PARALLEL");
	parallel_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "PATH");
	path_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "+");
	plus = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".PRECIOUS");
	precious = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "?");
	query = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "^");
	hat = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".RECURSIVE");
	recursive_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".SCCS_GET");
	sccs_get_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".SCCS_GET_POSIX");
	sccs_get_posix_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".GET");
	get_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".GET_POSIX");
	get_posix_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "SHELL");
	shell_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".SILENT");
	silent_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".SUFFIXES");
	suffixes_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, SUNPRO_DEPENDENCIES);
	sunpro_dependencies = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "TARGET_ARCH");
	target_arch = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "TARGET_MACH");
	target_mach = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "VIRTUAL_ROOT");
	virtual_root = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "VPATH");
	vpath_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, ".WAIT");
	wait_name = GETNAME(wcs_buffer, FIND_LENGTH);

	wait_name->state = build_ok;

	/* Mark special targets so that the reader treats them properly */
	svr4_name->special_reader = svr4_special;
	posix_name->special_reader = posix_special;
	built_last_make_run->special_reader = built_last_make_run_special;
	default_rule_name->special_reader = default_special;
	dot_keep_state->special_reader = keep_state_special;
	dot_keep_state_file->special_reader = keep_state_file_special;
	ignore_name->special_reader = ignore_special;
	make_version->special_reader = make_version_special;
	no_parallel_name->special_reader = no_parallel_special;
	parallel_name->special_reader = parallel_special;
	localhost_name->special_reader = localhost_special;
	precious->special_reader = precious_special;
	sccs_get_name->special_reader = sccs_get_special;
	sccs_get_posix_name->special_reader = sccs_get_posix_special;
	get_name->special_reader = get_special;
	get_posix_name->special_reader = get_posix_special;
	silent_name->special_reader = silent_special;
	suffixes_name->special_reader = suffixes_special;

	/* The value of $$ is $ */
	(void) SETVAR(dollar, dollar, false);
	dollar->dollar = false;

	/* Set the value of $(SHELL) */
	if (posix) {
	  MBSTOWCS(wcs_buffer, "/usr/xpg4/bin/sh");
	} else {
	  MBSTOWCS(wcs_buffer, "/bin/sh");
	}
	(void) SETVAR(shell_name, GETNAME(wcs_buffer, FIND_LENGTH), false);

	/*
	 * Use " FORCE" to simulate a FRC dependency for :: type
	 * targets with no dependencies.
	 */
	(void) append_prop(force, line_prop);
	force->stat.time = file_max_time;

	/* Make sure VPATH is defined before current dir is read */
	if ((cp = getenv(vpath_name->string_mb)) != NULL) {
		MBSTOWCS(wcs_buffer, cp);
		(void) SETVAR(vpath_name,
			      GETNAME(wcs_buffer, FIND_LENGTH),
			      false);
	}

	/* Check if there is NO PATH variable. If not we construct one. */
	if (getenv(path_name->string_mb) == NULL) {
		vroot_path = NULL;
		add_dir_to_path(".", &vroot_path, -1);
		add_dir_to_path("/bin", &vroot_path, -1);
		add_dir_to_path("/usr/bin", &vroot_path, -1);
	}
}

/* 
 * iterate on list of conditional macros in np, and place them in 
 * a String_rec starting with, and separated by the '$' character.
 */
void
cond_macros_into_string(Name np, String_rec *buffer)
{
	Macro_list	macro_list;

	/* 
	 * Put the version number at the start of the string
	 */
	MBSTOWCS(wcs_buffer, DEPINFO_FMT_VERSION);
	append_string(wcs_buffer, buffer, FIND_LENGTH);
	/* 
	 * Add the rest of the conditional macros to the buffer
	 */
	if (np->depends_on_conditional){
		for (macro_list = np->conditional_macro_list; 
		     macro_list != NULL; macro_list = macro_list->next){
			append_string(macro_list->macro_name, buffer, 
				FIND_LENGTH);
			append_char((int) equal_char, buffer);
			append_string(macro_list->value, buffer, FIND_LENGTH);
			append_char((int) dollar_char, buffer);
		}
	}
}

