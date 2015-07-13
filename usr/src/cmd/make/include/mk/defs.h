#ifndef _MK_DEFS_H
#define _MK_DEFS_H
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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Included files
 */

#include <mksh/defs.h>



/*
 * Defined macros
 */

#define SKIPSPACE(x)	while (*x &&				\
			       ((*x == (int) space_char) ||	\
			        (*x == (int) tab_char) ||	\
			        (*x == (int) comma_char))) {	\
					x++;			\
			}

#define SKIPWORD(x)	while (*x &&				\
			       (*x != (int) space_char) &&	\
			       (*x != (int) tab_char) &&	\
			       (*x != (int) newline_char) &&	\
			       (*x != (int) comma_char) &&	\
			       (*x != (int) equal_char)) {	\
					x++;			\
			}

#define SKIPTOEND(x)	while (*x &&				\
			       (*x != (int) newline_char)) {	\
					x++;			\
			}

#define PMAKE_DEF_MAX_JOBS	2	/* Default number of parallel jobs. */

#define OUT_OF_DATE(a,b) \
	(((a) < (b)) || (((a) == file_doesnt_exist) && ((b) == file_doesnt_exist)))

#define OUT_OF_DATE_SEC(a,b) \
	(((a).tv_sec < (b).tv_sec) || (((a).tv_sec == file_doesnt_exist.tv_sec) && ((b).tv_sec == file_doesnt_exist.tv_sec)))

#define SETVAR(name, value, append) \
				setvar_daemon(name, value, append, no_daemon, \
					      true, debug_level)
#define MAX(a,b)		(((a)>(b))?(a):(b))
/*
 * New feature added to SUN5_0 make,  invoke the vanilla svr4 make when
 * the USE_SVR4_MAKE environment variable is set.
 */
#define SVR4_MAKE		"/usr/ccs/lib/svr4.make"
#define USE_SVR4_MAKE		"USE_SVR4_MAKE"
/*
 * The standard MAXHOSTNAMELEN is 64. We want 32.
 */
#define	MAX_HOSTNAMELEN		32


/*
 * typedefs & structs
 */
typedef enum {
	no_state,
	scan_name_state,
	scan_command_state,
	enter_dependencies_state,
	enter_conditional_state,
	enter_equal_state,
	illegal_bytes_state,
	illegal_eoln_state,
	poorly_formed_macro_state,
	exit_state
}                       Reader_state;

struct _Name_vector {
	struct _Name		*names[64];
	struct _Chain		*target_group[64];
	short                   used;
	struct _Name_vector	*next;
};

struct _Running {
	struct _Running		*next;
	Doname			state;
	struct _Name		*target;
	struct _Name		*true_target;
	struct _Property	*command;
	struct _Name		*sprodep_value;
	char			*sprodep_env;
	int			recursion_level;
	Boolean			do_get;
	Boolean			implicit;
	Boolean			redo;
	int			auto_count;
	struct _Name		**automatics;
	pid_t			pid;
	int			job_msg_id;
	char			*stdout_file;
	char			*stderr_file;
	struct _Name		*temp_file;
	int			conditional_cnt;
	struct _Name		**conditional_targets;
	Boolean			make_refd;
};

typedef enum {
	serial_mode,
	parallel_mode
} DMake_mode;

typedef enum {
	txt1_mode,
	txt2_mode,
	html1_mode
} DMake_output_mode;

struct _Recursive_make {
	struct _Recursive_make	*next;	/* Linked list */
	wchar_t			*target;/* Name of target */
	wchar_t			*oldline;/* Original line in .nse_depinfo */
	wchar_t			*newline;/* New line in .nse_depinfo */
	wchar_t			*cond_macrostring;
					/* string built from value of
					 * conditional macros used by
					 * this target
					 */
	Boolean			removed;/* This target is no longer recursive*/
};

struct _Dyntarget {
	struct _Dyntarget	*next;
	struct _Name		*name;
};


/*
 * Typedefs for all structs
 */
typedef struct _Cmd_line	*Cmd_line, Cmd_line_rec;
typedef struct _Dependency	*Dependency, Dependency_rec;
typedef struct _Macro		*Macro, Macro_rec;
typedef struct _Name_vector	*Name_vector, Name_vector_rec;
typedef struct _Percent		*Percent, Percent_rec;
typedef struct _Dyntarget	*Dyntarget;
typedef struct _Recursive_make	*Recursive_make, Recursive_make_rec;
typedef struct _Running		*Running, Running_rec;


/*
 *	extern declarations for all global variables.
 *	The actual declarations are in globals.cc
 */
extern	Boolean		allrules_read;
extern	Name		posix_name;
extern	Name		svr4_name;
extern	Boolean		sdot_target;
extern	Boolean		all_parallel;
extern	Boolean		assign_done;
extern	Boolean		build_failed_seen;
extern	Name		built_last_make_run;
extern	Name		c_at;
extern	Boolean		command_changed;
extern	Boolean		commands_done;
extern	Chain		conditional_targets;
extern	Name		conditionals;
extern	Boolean		continue_after_error;
extern	Property	current_line;
extern	Name		current_make_version;
extern	Name		current_target;
extern	short		debug_level;
extern	Cmd_line	default_rule;
extern	Name		default_rule_name;
extern	Name		default_target_to_build;
extern	Boolean		depinfo_already_read;
extern	Name		dmake_group;
extern	Name		dmake_max_jobs;
extern	Name		dmake_mode;
extern	DMake_mode	dmake_mode_type;
extern	Name		dmake_output_mode;
extern	DMake_output_mode	output_mode;
extern	Name		dmake_odir;
extern	Name		dmake_rcfile;
extern	Name		done;
extern	Name		dot;
extern	Name		dot_keep_state;
extern	Name		dot_keep_state_file;
extern	Name		empty_name;
extern	Boolean		fatal_in_progress;
extern	int		file_number;
extern	Name		force;
extern	Name		ignore_name;
extern	Boolean		ignore_errors;
extern	Boolean		ignore_errors_all;
extern	Name		init;
extern	int		job_msg_id;
extern	Boolean		keep_state;
extern	Name		make_state;
extern	timestruc_t	make_state_before;
extern	Boolean		make_state_locked;
extern	Dependency	makefiles_used;
extern	Name		makeflags;
extern	Name		make_version;
extern	char		mbs_buffer2[];
extern	char		*mbs_ptr;
extern	char		*mbs_ptr2;
extern	Boolean		no_action_was_taken;
extern	Boolean		no_parallel;
extern	Name		no_parallel_name;
extern	Name		not_auto;
extern	Boolean		only_parallel;
extern	Boolean		parallel;
extern	Name		parallel_name;
extern	Name		localhost_name;
extern	int		parallel_process_cnt;
extern	Percent		percent_list;
extern	Dyntarget	dyntarget_list;
extern	Name		plus;
extern	Name		pmake_machinesfile;
extern	Name		precious;
extern	Name		primary_makefile;
extern	Boolean		quest;
extern	short		read_trace_level;
extern	Boolean		reading_dependencies;
extern	int		recursion_level;
extern	Name		recursive_name;
extern	short		report_dependencies_level;
extern	Boolean		report_pwd;
extern	Boolean		rewrite_statefile;
extern	Running		running_list;
extern	char		*sccs_dir_path;
extern	Name		sccs_get_name;
extern	Name		sccs_get_posix_name;
extern	Cmd_line	sccs_get_rule;
extern	Cmd_line	sccs_get_org_rule;
extern	Cmd_line	sccs_get_posix_rule;
extern	Name		get_name;
extern	Name		get_posix_name;
extern	Cmd_line	get_rule;
extern	Cmd_line	get_posix_rule;
extern	Boolean		all_precious;
extern	Boolean		report_cwd;
extern	Boolean		silent_all;
extern	Boolean		silent;
extern	Name		silent_name;
extern	char		*stderr_file;
extern	char		*stdout_file;
extern	Boolean		stdout_stderr_same;
extern	Dependency	suffixes;
extern	Name		suffixes_name;
extern	Name		sunpro_dependencies;
extern	Boolean		target_variants;
extern	const char	*tmpdir;
extern	const char	*temp_file_directory;
extern	Name		temp_file_name;
extern	short		temp_file_number;
extern  wchar_t		*top_level_target;
extern	Boolean		touch;
extern	Boolean		trace_reader;
extern	Boolean		build_unconditional;
extern	pathpt		vroot_path;
extern	Name		wait_name;
extern	wchar_t		wcs_buffer2[];
extern	wchar_t		*wcs_ptr;
extern	wchar_t		*wcs_ptr2;
extern	long int	hostid;

/*
 * Declarations of system defined variables
 */
/* On linux this variable is defined in 'signal.h' */
extern	char		*sys_siglist[];

/*
 * Declarations of system supplied functions
 */
extern	int		file_lock(char *, char *, int *, int);

/*
 * Declarations of functions declared and used by make
 */
extern	void		add_pending(Name target, int recursion_level, Boolean do_get, Boolean implicit, Boolean redo);
extern	void		add_running(Name target, Name true_target, Property command, int recursion_level, int auto_count, Name *automatics, Boolean do_get, Boolean implicit);
extern	void		add_serial(Name target, int recursion_level, Boolean do_get, Boolean implicit);
extern	void		add_subtree(Name target, int recursion_level, Boolean do_get, Boolean implicit);
extern  void 		append_or_replace_macro_in_dyn_array(ASCII_Dyn_Array *Ar, char *macro);
extern	void		await_parallel(Boolean waitflg);
extern	void		build_suffix_list(Name target_suffix);
extern	Boolean		check_auto_dependencies(Name target, int auto_count, Name *automatics);
extern	void		check_state(Name temp_file_name);
extern	void		cond_macros_into_string(Name np, String_rec *buffer);
extern	void		construct_target_string();
extern	void		create_xdrs_ptr(void);
extern	void		depvar_add_to_list (Name name, Boolean cmdline);
extern	Doname		doname(register Name target, register Boolean do_get, register Boolean implicit, register Boolean automatic = false);
extern	Doname		doname_check(register Name target, register Boolean do_get, register Boolean implicit, register Boolean automatic);
extern	Doname		doname_parallel(Name target, Boolean do_get, Boolean implicit);
extern	Doname		dosys(register Name command, register Boolean ignore_error, register Boolean call_make, Boolean silent_error, Boolean always_exec, Name target);
extern	void		dump_make_state(void);
extern	void		dump_target_list(void);
extern	void		enter_conditional(register Name target, Name name, Name value, register Boolean append);
extern	void		enter_dependencies(register Name target, Chain target_group, register Name_vector depes, register Cmd_line command, register Separator separator);
extern	void		enter_dependency(Property line, register Name depe, Boolean automatic);
extern	void		enter_equal(Name name, Name value, register Boolean append);
extern  Percent		enter_percent(register Name target, Chain target_group, register Name_vector depes, Cmd_line command);
extern	Dyntarget	enter_dyntarget(register Name target);
extern	Name_vector	enter_name(String string, Boolean tail_present, register wchar_t *string_start, register wchar_t *string_end, Name_vector current_names, Name_vector *extra_names, Boolean *target_group_seen);
extern	Boolean		exec_vp(register char *name, register char **argv, char **envp, register Boolean ignore_error);
extern	Doname		execute_parallel(Property line, Boolean waitflg, Boolean local = false);
extern	Doname		execute_serial(Property line);
extern	timestruc_t&  	exists(register Name target);
extern	void		fatal(const char *, ...);
extern	void		fatal_reader(char *, ...);
extern	Doname		find_ar_suffix_rule(register Name target, Name true_target, Property *command, Boolean rechecking);
extern	Doname		find_double_suffix_rule(register Name target, Property *command, Boolean rechecking);
extern	Doname		find_percent_rule(register Name target, Property *command, Boolean rechecking);
extern	int		find_run_directory (char *cmd, char *cwd, char *dir, char **pgm, char **run, char *path);
extern	Doname		find_suffix_rule(Name target, Name target_body, Name target_suffix, Property *command, Boolean rechecking);
extern	Chain		find_target_groups(register Name_vector target_list, register int i, Boolean reset);
extern	void		finish_children(Boolean docheck);
extern	void		finish_running(void);
extern	void		free_chain(Name_vector ptr);
extern  void		gather_recursive_deps(void);
extern	char		*get_current_path(void);
extern	int		get_job_msg_id(void);
extern	wchar_t		*getmem_wc(register int size);
/* On linux getwd(char *) is defined in 'unistd.h' */
#ifdef __cplusplus
extern "C" {
#endif
extern	char		*getwd(char *);
#ifdef __cplusplus
}
#endif
extern	void		handle_interrupt(int);
extern	Boolean		is_running(Name target);
extern	void		load_cached_names(void);
extern	Boolean		parallel_ok(Name target, Boolean line_prop_must_exists);
extern	void		print_dependencies(register Name target, register Property line);
extern	void		send_job_start_msg(Property line);
extern	void		send_rsrc_info_msg(int max_jobs, char *hostname, char *username);
extern	void		print_value(register Name value, Daemon daemon);
extern	timestruc_t&	read_archive(register Name target);
extern	int		read_dir(Name dir, wchar_t *pattern, Property line, wchar_t *library);
extern	void		read_directory_of_file(register Name file);
extern	int		read_make_machines(Name make_machines_name);
extern	Boolean		read_simple_file(register Name makefile_name, register Boolean chase_path, register Boolean doname_it, Boolean complain, Boolean must_exist, Boolean report_file, Boolean lock_makefile);
extern	void		remove_recursive_dep(Name target);
extern	void		report_recursive_dep(Name target, char *line);
extern	void		report_recursive_done(void);
extern	void		report_recursive_init(void);
extern	Recursive_make	find_recursive_target(Name target);
extern	void		reset_locals(register Name target, register Property old_locals, register Property conditional, register int index);
extern	void		set_locals(register Name target, register Property old_locals);
extern	void		setvar_append(register Name name, register Name value);
extern	void		setvar_envvar(void);
extern	void		special_reader(Name target, register Name_vector depes, Cmd_line command);
extern	void		startup_rxm();
extern	Doname		target_can_be_built(register Name target);
extern	char		*time_to_string(const timestruc_t &time);
extern	void		update_target(Property line, Doname result);
extern	void		warning(char *, ...);
extern	void		write_state_file(int report_recursive, Boolean exiting);
extern	Name		vpath_translation(register Name cmd);
extern	char 		*make_install_prefix(void);

#define DEPINFO_FMT_VERSION "VERS2$"
#define VER_LEN strlen(DEPINFO_FMT_VERSION)


#endif
