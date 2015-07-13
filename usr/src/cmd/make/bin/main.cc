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
 * Copyright 2006 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	main.cc
 *
 *	make program main routine plus some helper routines
 */
 
/*
 * Included files
 */
#include <bsd/bsd.h>		/* bsd_signal() */


#include <locale.h>		/* setlocale() */
#include <libgen.h>
#include <mk/defs.h>
#include <mksh/macro.h>		/* getvar() */
#include <mksh/misc.h>		/* getmem(), setup_char_semantics() */

#include <pwd.h>		/* getpwnam() */
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/errno.h>		/* ENOENT */
#include <sys/stat.h>		/* fstat() */
#include <fcntl.h>		/* open() */

#	include <sys/systeminfo.h>	/* sysinfo() */

#include <sys/types.h>		/* stat() */
#include <sys/wait.h>		/* wait() */
#include <unistd.h>		/* execv(), unlink(), access() */
#include <vroot/report.h>	/* report_dependency(), get_report_file() */

// From read2.cc
extern	Name		normalize_name(register wchar_t *name_string, register int length);

extern void job_adjust_fini();


/*
 * Defined macros
 */
#define	LD_SUPPORT_ENV_VAR	"SGS_SUPPORT_32"
#define	LD_SUPPORT_ENV_VAR_32	"SGS_SUPPORT_32"
#define	LD_SUPPORT_ENV_VAR_64	"SGS_SUPPORT_64"
#define	LD_SUPPORT_MAKE_LIB	"libmakestate.so.1"
#ifdef __i386
#define	LD_SUPPORT_MAKE_ARCH	"i386"
#elif __sparc
#define	LD_SUPPORT_MAKE_ARCH	"sparc"
#else
#error "Unsupported architecture"
#endif

/*
 * typedefs & structs
 */

/*
 * Static variables
 */
static	char		*argv_zero_string;
static	Boolean		build_failed_ever_seen;
static	Boolean		continue_after_error_ever_seen;	/* `-k' */
static	Boolean		dmake_group_specified;		/* `-g' */
static	Boolean		dmake_max_jobs_specified;	/* `-j' */
static	Boolean		dmake_mode_specified;		/* `-m' */
static	Boolean		dmake_add_mode_specified;	/* `-x' */
static	Boolean		dmake_output_mode_specified;	/* `-x DMAKE_OUTPUT_MODE=' */
static	Boolean		dmake_compat_mode_specified;	/* `-x SUN_MAKE_COMPAT_MODE=' */
static	Boolean		dmake_odir_specified;		/* `-o' */
static	Boolean		dmake_rcfile_specified;		/* `-c' */
static	Boolean		env_wins;			/* `-e' */
static	Boolean		ignore_default_mk;		/* `-r' */
static	Boolean		list_all_targets;		/* `-T' */
static	int		mf_argc;
static	char		**mf_argv;
static	Dependency_rec  not_auto_depen_struct;
static	Dependency 	not_auto_depen = &not_auto_depen_struct;
static	Boolean		pmake_cap_r_specified;		/* `-R' */
static	Boolean		pmake_machinesfile_specified;	/* `-M' */
static	Boolean		stop_after_error_ever_seen;	/* `-S' */
static	Boolean		trace_status;			/* `-p' */

#ifdef DMAKE_STATISTICS
static	Boolean		getname_stat = false;
#endif

	static	time_t		start_time;
	static	int		g_argc;
	static	char		**g_argv;

/*
 * File table of contents
 */
	extern "C" void		cleanup_after_exit(void);

extern "C" {
	extern	void		dmake_exit_callback(void);
	extern	void		dmake_message_callback(char *);
}

extern	Name		normalize_name(register wchar_t *name_string, register int length);

extern	int		main(int, char * []);

static	void		append_makeflags_string(Name, String);
static	void		doalarm(int);
static	void		enter_argv_values(int , char **, ASCII_Dyn_Array *);
static	void		make_targets(int, char **, Boolean);
static	int		parse_command_option(char);
static	void		read_command_options(int, char **);
static	void		read_environment(Boolean);
static	void		read_files_and_state(int, char **);
static	Boolean		read_makefile(Name, Boolean, Boolean, Boolean);
static	void		report_recursion(Name);
static	void		set_sgs_support(void);
static	void		setup_for_projectdir(void);
static	void		setup_makeflags_argv(void);
static	void		report_dir_enter_leave(Boolean entering);

extern void expand_value(Name, register String , Boolean);

static const char	verstring[] = "illumos make";

jmp_buf jmpbuffer;

/*
 *	main(argc, argv)
 *
 *	Parameters:
 *		argc			You know what this is
 *		argv			You know what this is
 *
 *	Static variables used:
 *		list_all_targets	make -T seen
 *		trace_status		make -p seen
 *
 *	Global variables used:
 *		debug_level		Should we trace make actions?
 *		keep_state		Set if .KEEP_STATE seen
 *		makeflags		The Name "MAKEFLAGS", used to get macro
 *		remote_command_name	Name of remote invocation cmd ("on")
 *		running_list		List of parallel running processes
 *		stdout_stderr_same	true if stdout and stderr are the same
 *		auto_dependencies	The Name "SUNPRO_DEPENDENCIES"
 *		temp_file_directory	Set to the dir where we create tmp file
 *		trace_reader		Set to reflect tracing status
 *		working_on_targets	Set when building user targets
 */
int
main(int argc, char *argv[])
{
	/*
	 * cp is a -> to the value of the MAKEFLAGS env var,
	 * which has to be regular chars.
	 */
	register char		*cp;
	char 			make_state_dir[MAXPATHLEN];
	Boolean			parallel_flag = false;
	char			*prognameptr;
	char 			*slash_ptr;
	mode_t			um;
	int			i;
	struct itimerval	value;
	char			def_dmakerc_path[MAXPATHLEN];
	Name			dmake_name, dmake_name2;
	Name			dmake_value, dmake_value2;
	Property		prop, prop2;
	struct stat		statbuf;
	int			statval;

	struct stat		out_stat, err_stat;
	hostid = gethostid();
	bsd_signals();

	(void) setlocale(LC_ALL, "");


#ifdef DMAKE_STATISTICS
	if (getenv("DMAKE_STATISTICS")) {
		getname_stat = true;
	}
#endif

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"	
#endif
	textdomain(TEXT_DOMAIN);

	g_argc = argc;
	g_argv = (char **) malloc((g_argc + 1) * sizeof(char *));
	for (i = 0; i < argc; i++) {
		g_argv[i] = argv[i];
	}
	g_argv[i] = NULL;

	/*
	 * Set argv_zero_string to some form of argv[0] for
	 * recursive MAKE builds.
	 */

	if (*argv[0] == (int) slash_char) {
		/* argv[0] starts with a slash */
		argv_zero_string = strdup(argv[0]);
	} else if (strchr(argv[0], (int) slash_char) == NULL) {
		/* argv[0] contains no slashes */
		argv_zero_string = strdup(argv[0]);
	} else {
		/*
		 * argv[0] contains at least one slash,
		 * but doesn't start with a slash
		 */
		char	*tmp_current_path;
		char	*tmp_string;

		tmp_current_path = get_current_path();
		tmp_string = getmem(strlen(tmp_current_path) + 1 +
		                    strlen(argv[0]) + 1);
		(void) sprintf(tmp_string,
		               "%s/%s",
		               tmp_current_path,
		               argv[0]);
		argv_zero_string = strdup(tmp_string);
		retmem_mb(tmp_string);
	}

	/* 
	 * The following flags are reset if we don't have the 
	 * (.nse_depinfo or .make.state) files locked and only set 
	 * AFTER the file has been locked. This ensures that if the user
	 * interrupts the program while file_lock() is waiting to lock
	 * the file, the interrupt handler doesn't remove a lock 
	 * that doesn't belong to us.
	 */
	make_state_lockfile = NULL;
	make_state_locked = false;


	/*
	 * look for last slash char in the path to look at the binary 
	 * name. This is to resolve the hard link and invoke make
	 * in svr4 mode.
	 */

	/* Sun OS make standart */
	svr4 = false;  
	posix = false;
	if(!strcmp(argv_zero_string, "/usr/xpg4/bin/make")) {
		svr4 = false;
		posix = true;
	} else {
		prognameptr = strrchr(argv[0], '/');
		if(prognameptr) {
			prognameptr++;
		} else {
			prognameptr = argv[0];
		}
		if(!strcmp(prognameptr, "svr4.make")) {
			svr4 = true;
			posix = false;
		}
	}
	if (getenv(USE_SVR4_MAKE) || getenv("USE_SVID")){
	   svr4 = true;
	   posix = false;
	}

	/*
	 * Find the dmake_compat_mode: posix, sun, svr4, or gnu_style, .
	 */
	char * dmake_compat_mode_var = getenv("SUN_MAKE_COMPAT_MODE");
	if (dmake_compat_mode_var != NULL) {
		if (0 == strcasecmp(dmake_compat_mode_var, "GNU")) {
			gnu_style = true;
		}
		//svr4 = false;
		//posix = false;
	}

	/*
	 * Temporary directory set up.
	 */
	char * tmpdir_var = getenv("TMPDIR");
	if (tmpdir_var != NULL && *tmpdir_var == '/' && strlen(tmpdir_var) < MAXPATHLEN) {
		strcpy(mbs_buffer, tmpdir_var);
		for (tmpdir_var = mbs_buffer+strlen(mbs_buffer);
			*(--tmpdir_var) == '/' && tmpdir_var > mbs_buffer;
			*tmpdir_var = '\0');
		if (strlen(mbs_buffer) + 32 < MAXPATHLEN) { /* 32 = strlen("/dmake.stdout.%d.%d.XXXXXX") */
			sprintf(mbs_buffer2, "%s/dmake.tst.%d.XXXXXX",
				mbs_buffer, getpid());
			int fd = mkstemp(mbs_buffer2);
			if (fd >= 0) {
				close(fd);
				unlink(mbs_buffer2);
				tmpdir = strdup(mbs_buffer);
			}
		}
	}

	/* find out if stdout and stderr point to the same place */
	if (fstat(1, &out_stat) < 0) {
		fatal(gettext("fstat of standard out failed: %s"), errmsg(errno));
	}
	if (fstat(2, &err_stat) < 0) {
		fatal(gettext("fstat of standard error failed: %s"), errmsg(errno));
	}
	if ((out_stat.st_dev == err_stat.st_dev) &&
	    (out_stat.st_ino == err_stat.st_ino)) {
		stdout_stderr_same = true;
	} else {
		stdout_stderr_same = false;
	}
	/* Make the vroot package scan the path using shell semantics */
	set_path_style(0);

	setup_char_semantics();

	setup_for_projectdir();

	/*
	 * If running with .KEEP_STATE, curdir will be set with
	 * the connected directory.
	 */
	(void) atexit(cleanup_after_exit);

	load_cached_names();

/*
 *	Set command line flags
 */
	setup_makeflags_argv();
	read_command_options(mf_argc, mf_argv);
	read_command_options(argc, argv);
	if (debug_level > 0) {
		cp = getenv(makeflags->string_mb);
		(void) printf(gettext("MAKEFLAGS value: %s\n"), cp == NULL ? "" : cp);
	}

	setup_interrupt(handle_interrupt);

	read_files_and_state(argc, argv);

	/*
	 * Find the dmake_output_mode: TXT1, TXT2 or HTML1.
	 */
	MBSTOWCS(wcs_buffer, "DMAKE_OUTPUT_MODE");
	dmake_name2 = GETNAME(wcs_buffer, FIND_LENGTH);
	prop2 = get_prop(dmake_name2->prop, macro_prop);
	if (prop2 == NULL) {
		/* DMAKE_OUTPUT_MODE not defined, default to TXT1 mode */
		output_mode = txt1_mode;
	} else {
		dmake_value2 = prop2->body.macro.value;
		if ((dmake_value2 == NULL) ||
		    (IS_EQUAL(dmake_value2->string_mb, "TXT1"))) {
			output_mode = txt1_mode;
		} else if (IS_EQUAL(dmake_value2->string_mb, "TXT2")) {
			output_mode = txt2_mode;
		} else if (IS_EQUAL(dmake_value2->string_mb, "HTML1")) {
			output_mode = html1_mode;
		} else {
			warning(gettext("Unsupported value `%s' for DMAKE_OUTPUT_MODE after -x flag (ignored)"),
			      dmake_value2->string_mb);
		}
	}
	/*
	 * Find the dmake_mode: parallel, or serial.
	 */
    if ((!pmake_cap_r_specified) &&
        (!pmake_machinesfile_specified)) {
	char *s, *b;

	if ((s = strdup(argv[0])) == NULL)
		fatal(gettext("Out of memory"));

	b = basename(s);

	MBSTOWCS(wcs_buffer, "DMAKE_MODE");
	dmake_name2 = GETNAME(wcs_buffer, FIND_LENGTH);
	prop2 = get_prop(dmake_name2->prop, macro_prop);
	// If we're invoked as 'make' run serially, regardless of DMAKE_MODE
	// If we're invoked as 'make' but passed -j, run parallel
	// If we're invoked as 'dmake', without DMAKE_MODE, default parallel
	// If we're invoked as 'dmake' and DMAKE_MODE is set, honour it.
	if ((strcmp(b, "make") == 0) &&
	    !dmake_max_jobs_specified) {
		dmake_mode_type = serial_mode;
		no_parallel = true;
	} else if (prop2 == NULL) {
		/* DMAKE_MODE not defined, default based on our name */
		if (strcmp(b, "dmake") == 0) {
			dmake_mode_type = parallel_mode;
			no_parallel = false;
		}
	} else {
		dmake_value2 = prop2->body.macro.value;
		if (IS_EQUAL(dmake_value2->string_mb, "parallel")) {
			dmake_mode_type = parallel_mode;
			no_parallel = false;
		} else if (IS_EQUAL(dmake_value2->string_mb, "serial")) {
			dmake_mode_type = serial_mode;
			no_parallel = true;
		} else {
			fatal(gettext("Unknown dmake mode argument `%s' after -m flag"), dmake_value2->string_mb);
		}
	}
	free(s);
    }

	parallel_flag = true;
	putenv(strdup("DMAKE_CHILD=TRUE"));

//
// If dmake is running with -t option, set dmake_mode_type to serial.
// This is done because doname() calls touch_command() that runs serially.
// If we do not do that, maketool will have problems. 
//
	if(touch) {
		dmake_mode_type = serial_mode;
		no_parallel = true;
	}

	/*
	 * Check whether stdout and stderr are physically same.
	 * This is in order to decide whether we need to redirect
	 * stderr separately from stdout.
	 * This check is performed only if __DMAKE_SEPARATE_STDERR
	 * is not set. This variable may be used in order to preserve
	 * the 'old' behaviour.
	 */
	out_err_same = true;
	char * dmake_sep_var = getenv("__DMAKE_SEPARATE_STDERR");
	if (dmake_sep_var == NULL || (0 != strcasecmp(dmake_sep_var, "NO"))) {
		struct stat stdout_stat;
		struct stat stderr_stat;
		if( (fstat(1, &stdout_stat) == 0)
		 && (fstat(2, &stderr_stat) == 0) )
		{
			if( (stdout_stat.st_dev != stderr_stat.st_dev)
			 || (stdout_stat.st_ino != stderr_stat.st_ino) )
			{
				out_err_same = false;
			}
		}
	}

		
/*
 *	Enable interrupt handler for alarms
 */
        (void) bsd_signal(SIGALRM, (SIG_PF)doalarm);

/*
 *	Check if make should report
 */
	if (getenv(sunpro_dependencies->string_mb) != NULL) {
		FILE	*report_file;

		report_dependency("");
		report_file = get_report_file();
		if ((report_file != NULL) && (report_file != (FILE*)-1)) {
			(void) fprintf(report_file, "\n");
		}
	}

/*
 *	Make sure SUNPRO_DEPENDENCIES is exported (or not) properly.
 */
	if (keep_state) {
		maybe_append_prop(sunpro_dependencies, macro_prop)->
		  body.macro.exported = true;
	} else {
		maybe_append_prop(sunpro_dependencies, macro_prop)->
		  body.macro.exported = false;
	}

	working_on_targets = true;
	if (trace_status) {
		dump_make_state();
		fclose(stdout);
		fclose(stderr);
		exit_status = 0;
		exit(0);
	}
	if (list_all_targets) {
		dump_target_list();
		fclose(stdout);
		fclose(stderr);
		exit_status = 0;
		exit(0);
	}
	trace_reader = false;

 	/*
 	 * Set temp_file_directory to the directory the .make.state
 	 * file is written to.
 	 */
 	if ((slash_ptr = strrchr(make_state->string_mb, (int) slash_char)) == NULL) {
 		temp_file_directory = strdup(get_current_path());
 	} else {
 		*slash_ptr = (int) nul_char;
 		(void) strcpy(make_state_dir, make_state->string_mb);
 		*slash_ptr = (int) slash_char;
		   /* when there is only one slash and it's the first
		   ** character, make_state_dir should point to '/'.
		   */
		if(make_state_dir[0] == '\0') {
		   make_state_dir[0] = '/';
		   make_state_dir[1] = '\0';
		}
 		if (make_state_dir[0] == (int) slash_char) {
 			temp_file_directory = strdup(make_state_dir);
 		} else {
 			char	tmp_current_path2[MAXPATHLEN];
 
 			(void) sprintf(tmp_current_path2,
 			               "%s/%s",
 			               get_current_path(),
 			               make_state_dir);
 			temp_file_directory = strdup(tmp_current_path2);
 		}
 	}


	report_dir_enter_leave(true);

	make_targets(argc, argv, parallel_flag);

	report_dir_enter_leave(false);

	if (build_failed_ever_seen) {
		if (posix) {
			exit_status = 1;
		}
		exit(1);
	}
	exit_status = 0;
	exit(0);
	/* NOTREACHED */
}

/*
 *	cleanup_after_exit()
 *
 *	Called from exit(), performs cleanup actions.
 *
 *	Parameters:
 *		status		The argument exit() was called with
 *		arg		Address of an argument vector to
 *				cleanup_after_exit()
 *
 *	Global variables used:
 *		command_changed	Set if we think .make.state should be rewritten
 *		current_line	Is set we set commands_changed
 *		do_not_exec_rule
 *				True if -n flag on
 *		done		The Name ".DONE", rule we run
 *		keep_state	Set if .KEEP_STATE seen
 *		parallel	True if building in parallel
 *		quest		If -q is on we do not run .DONE
 *		report_dependencies
 *				True if -P flag on
 *		running_list	List of parallel running processes
 *		temp_file_name	The temp file is removed, if any
 */
extern "C" void
cleanup_after_exit(void)
{
	Running		rp;

extern long	getname_bytes_count;
extern long	getname_names_count;
extern long	getname_struct_count;
extern long	freename_bytes_count;
extern long	freename_names_count;
extern long	freename_struct_count;
extern long	other_alloc;

extern long	env_alloc_num;
extern long	env_alloc_bytes;


#ifdef DMAKE_STATISTICS
if(getname_stat) {
	printf(">>> Getname statistics:\n");
	printf("  Allocated:\n");
	printf("        Names: %ld\n", getname_names_count);
	printf("      Strings: %ld Kb (%ld bytes)\n", getname_bytes_count/1000, getname_bytes_count);
	printf("      Structs: %ld Kb (%ld bytes)\n", getname_struct_count/1000, getname_struct_count);
	printf("  Total bytes: %ld Kb (%ld bytes)\n", getname_struct_count/1000 + getname_bytes_count/1000, getname_struct_count + getname_bytes_count);

	printf("\n  Unallocated: %ld\n", freename_names_count);
	printf("        Names: %ld\n", freename_names_count);
	printf("      Strings: %ld Kb (%ld bytes)\n", freename_bytes_count/1000, freename_bytes_count);
	printf("      Structs: %ld Kb (%ld bytes)\n", freename_struct_count/1000, freename_struct_count);
	printf("  Total bytes: %ld Kb (%ld bytes)\n", freename_struct_count/1000 + freename_bytes_count/1000, freename_struct_count + freename_bytes_count);

	printf("\n  Total used: %ld Kb (%ld bytes)\n", (getname_struct_count/1000 + getname_bytes_count/1000) - (freename_struct_count/1000 + freename_bytes_count/1000), (getname_struct_count + getname_bytes_count) - (freename_struct_count + freename_bytes_count));

	printf("\n>>> Other:\n");
	printf(
		"       Env (%ld): %ld Kb (%ld bytes)\n",
		env_alloc_num,
		env_alloc_bytes/1000,
		env_alloc_bytes
	);

}
#endif

	parallel = false;
	/* If we used the SVR4_MAKE, don't build .DONE or .FAILED */
	if (!getenv(USE_SVR4_MAKE)){
	    /* Build the target .DONE or .FAILED if we caught an error */
	    if (!quest && !list_all_targets) {
		Name		failed_name;

		MBSTOWCS(wcs_buffer, ".FAILED");
		failed_name = GETNAME(wcs_buffer, FIND_LENGTH);
		if ((exit_status != 0) && (failed_name->prop != NULL)) {
			/*
			 * [tolik] switch DMake to serial mode
			 */
			dmake_mode_type = serial_mode;
			no_parallel = true;
			(void) doname(failed_name, false, true);
		} else {
		    if (!trace_status) {
			/*
			 * Switch DMake to serial mode
			 */
			dmake_mode_type = serial_mode;
			no_parallel = true;
			(void) doname(done, false, true);
		    }
		}
	    }
	}
	/*
	 * Remove the temp file utilities report dependencies thru if it
	 * is still around
	 */
	if (temp_file_name != NULL) {
		(void) unlink(temp_file_name->string_mb);
	}
	/*
	 * Do not save the current command in .make.state if make
	 * was interrupted.
	 */
	if (current_line != NULL) {
		command_changed = true;
		current_line->body.line.command_used = NULL;
	}
	/*
	 * For each parallel build process running, remove the temp files
	 * and zap the command line so it won't be put in .make.state
	 */
	for (rp = running_list; rp != NULL; rp = rp->next) {
		if (rp->temp_file != NULL) {
			(void) unlink(rp->temp_file->string_mb);
		}
		if (rp->stdout_file != NULL) {
			(void) unlink(rp->stdout_file);
			retmem_mb(rp->stdout_file);
			rp->stdout_file = NULL;
		}
		if (rp->stderr_file != NULL) {
			(void) unlink(rp->stderr_file);
			retmem_mb(rp->stderr_file);
			rp->stderr_file = NULL;
		}
		command_changed = true;
/*
		line = get_prop(rp->target->prop, line_prop);
		if (line != NULL) {
			line->body.line.command_used = NULL;
		}
 */
	}
	/* Remove the statefile lock file if the file has been locked */
	if ((make_state_lockfile != NULL) && (make_state_locked)) {
		(void) unlink(make_state_lockfile);
		make_state_lockfile = NULL;
		make_state_locked = false;
	}
	/* Write .make.state */
	write_state_file(1, (Boolean) 1);

	job_adjust_fini();
}

/*
 *	handle_interrupt()
 *
 *	This is where C-C traps are caught.
 *
 *	Parameters:
 *
 *	Global variables used (except DMake 1.0):
 *		current_target		Sometimes the current target is removed
 *		do_not_exec_rule	But not if -n is on
 *		quest			or -q
 *		running_list		List of parallel running processes
 *		touch			Current target is not removed if -t on
 */
void
handle_interrupt(int)
{
	Property		member;
	Running			rp;

	(void) fflush(stdout);
	if (childPid > 0) {
		kill(childPid, SIGTERM);
		childPid = -1;
	}
	for (rp = running_list; rp != NULL; rp = rp->next) {
		if (rp->state != build_running) {
			continue;
		}
		if (rp->pid > 0) {
			kill(rp->pid, SIGTERM);
			rp->pid = -1;
		}
	}
	if (getpid() == getpgrp()) {
		bsd_signal(SIGTERM, SIG_IGN);
		kill (-getpid(), SIGTERM);
	}
	/* Clean up all parallel children already finished */
        finish_children(false);

	/* Make sure the processes running under us terminate first */

	while (wait((int *) NULL) != -1);
	/* Delete the current targets unless they are precious */
	if ((current_target != NULL) &&
	    current_target->is_member &&
	    ((member = get_prop(current_target->prop, member_prop)) != NULL)) {
		current_target = member->body.member.library;
	}
	if (!do_not_exec_rule &&
	    !touch &&
	    !quest &&
	    (current_target != NULL) &&
	    !(current_target->stat.is_precious || all_precious)) {

/* BID_1030811 */
/* azv 16 Oct 95 */
		current_target->stat.time = file_no_time; 

		if (exists(current_target) != file_doesnt_exist) {
			(void) fprintf(stderr,
				       "\n*** %s ",
				       current_target->string_mb);
			if (current_target->stat.is_dir) {
				(void) fprintf(stderr,
					       gettext("not removed.\n"),
					       current_target->string_mb);
			} else if (unlink(current_target->string_mb) == 0) {
				(void) fprintf(stderr,
					       gettext("removed.\n"),
					       current_target->string_mb);
			} else {
				(void) fprintf(stderr,
					       gettext("could not be removed: %s.\n"),
					       current_target->string_mb,
					       errmsg(errno));
			}
		}
	}
	for (rp = running_list; rp != NULL; rp = rp->next) {
		if (rp->state != build_running) {
			continue;
		}
		if (rp->target->is_member &&
		    ((member = get_prop(rp->target->prop, member_prop)) !=
		     NULL)) {
			rp->target = member->body.member.library;
		}
		if (!do_not_exec_rule &&
		    !touch &&
		    !quest &&
		    !(rp->target->stat.is_precious || all_precious)) {

			rp->target->stat.time = file_no_time; 
			if (exists(rp->target) != file_doesnt_exist) {
				(void) fprintf(stderr,
					       "\n*** %s ",
					       rp->target->string_mb);
				if (rp->target->stat.is_dir) {
					(void) fprintf(stderr,
						       gettext("not removed.\n"),
						       rp->target->string_mb);
				} else if (unlink(rp->target->string_mb) == 0) {
					(void) fprintf(stderr,
						       gettext("removed.\n"),
						       rp->target->string_mb);
				} else {
					(void) fprintf(stderr,
						       gettext("could not be removed: %s.\n"),
						       rp->target->string_mb,
						       errmsg(errno));
				}
			}
		}
	}


	/* Have we locked .make.state or .nse_depinfo? */
	if ((make_state_lockfile != NULL) && (make_state_locked)) {
		unlink(make_state_lockfile);
		make_state_lockfile = NULL;
		make_state_locked = false;
	}
	/*
	 * Re-read .make.state file (it might be changed by recursive make)
	 */
	check_state(NULL);

	report_dir_enter_leave(false);

	exit_status = 2;
	exit(2);
}

/*
 *	doalarm(sig, ...)
 *
 *	Handle the alarm interrupt but do nothing.  Side effect is to
 *	cause return from wait3.
 *
 *	Parameters:
 *		sig
 *
 *	Global variables used:
 */
/*ARGSUSED*/
static void
doalarm(int)
{
	return;
}


/*
 *	read_command_options(argc, argv)
 *
 *	Scan the cmd line options and process the ones that start with "-"
 *
 *	Return value:
 *				-M argument, if any
 *
 *	Parameters:
 *		argc		You know what this is
 *		argv		You know what this is
 *
 *	Global variables used:
 */
static void
read_command_options(register int argc, register char **argv)
{
	register int		ch;
	int			current_optind = 1;
	int			last_optind_with_double_hyphen = 0;
	int			last_optind;
	int			last_current_optind;
	register int		i;
	register int		j;
	register int		k;
	register int		makefile_next = 0; /*
						    * flag to note options:
						    * -c, f, g, j, m, o
						    */
	const char		*tptr;
	const char		*CMD_OPTS;

	extern char		*optarg;
	extern int		optind, opterr, optopt;

#define SUNPRO_CMD_OPTS	"-~Bbc:Ddef:g:ij:K:kM:m:NnO:o:PpqRrSsTtuVvwx:"

#	define SVR4_CMD_OPTS   "-c:ef:g:ij:km:nO:o:pqrsTtVv"

	/*
	 * Added V in SVR4_CMD_OPTS also, which is going to be a hidden
	 * option, just to make sure that the getopt doesn't fail when some
	 * users leave their USE_SVR4_MAKE set and try to use the makefiles
	 * that are designed to issue commands like $(MAKE) -V. Anyway it
	 * sets the same flag but ensures that getopt doesn't fail.
	 */

	opterr = 0;
	optind = 1;
	while (1) {
		last_optind=optind;			/* Save optind and current_optind values */
		last_current_optind=current_optind;	/* in case we have to repeat this round. */
		if (svr4) {
			CMD_OPTS=SVR4_CMD_OPTS;
			ch = getopt(argc, argv, SVR4_CMD_OPTS);
		} else {
			CMD_OPTS=SUNPRO_CMD_OPTS;
			ch = getopt(argc, argv, SUNPRO_CMD_OPTS);
		}
		if (ch == EOF) {
			if(optind < argc) {
				/*
				 * Fixing bug 4102537:
				 *    Strange behaviour of command make using -- option.
				 * Not all argv have been processed
				 * Skip non-flag argv and continue processing.
				 */
				optind++;
				current_optind++;
				continue;
			} else {
				break;
			}

		}
		if (ch == '?') {
		 	if (optopt == '-') {
				/* Bug 5060758: getopt() changed behavior (s10_60),
				 * and now we have to deal with cases when options
				 * with double hyphen appear here, from -$(MAKEFLAGS)
				 */
				i = current_optind;
				if (argv[i][0] == '-') {
				  if (argv[i][1] == '-') {
				    if (argv[i][2] != '\0') {
				      /* Check if this option is allowed */
				      tptr = strchr(CMD_OPTS, argv[i][2]);
				      if (tptr) {
				        if (last_optind_with_double_hyphen != current_optind) {
				          /* This is first time we are trying to fix "--"
				           * problem with this option. If we come here second 
				           * time, we will go to fatal error.
				           */
				          last_optind_with_double_hyphen = current_optind;
				          
				          /* Eliminate first hyphen character */
				          for (j=0; argv[i][j] != '\0'; j++) {
				            argv[i][j] = argv[i][j+1];
				          }
				          
				          /* Repeat the processing of this argument */
				          optind=last_optind;
				          current_optind=last_current_optind;
				          continue;
				        }
				      }
				    }
				  }
				}
			}
		}

		if (ch == '?') {
			if (svr4) {
				fprintf(stderr,
					gettext("Usage : dmake [ -f makefile ][ -c dmake_rcfile ][ -g dmake_group ]\n"));
				fprintf(stderr,
					gettext("              [ -j dmake_max_jobs ][ -m dmake_mode ][ -o dmake_odir ]...\n"));
				fprintf(stderr,
					gettext("              [ -e ][ -i ][ -k ][ -n ][ -p ][ -q ][ -r ][ -s ][ -t ][ -v ]\n"));
				tptr = strchr(SVR4_CMD_OPTS, optopt);
			} else {
				fprintf(stderr,
					gettext("Usage : dmake [ -f makefile ][ -c dmake_rcfile ][ -g dmake_group ]\n"));
				fprintf(stderr,
					gettext("              [ -j dmake_max_jobs ][ -K statefile ][ -m dmake_mode ][ -x MODE_NAME=VALUE ][ -o dmake_odir ]...\n"));
				fprintf(stderr,
					gettext("              [ -d ][ -dd ][ -D ][ -DD ][ -e ][ -i ][ -k ][ -n ][ -p ][ -P ][ -u ][ -w ]\n"));
				fprintf(stderr,
					gettext("              [ -q ][ -r ][ -s ][ -S ][ -t ][ -v ][ -V ][ target... ][ macro=value... ][ \"macro +=value\"... ]\n"));
				tptr = strchr(SUNPRO_CMD_OPTS, optopt);
			}
			if (!tptr) {
				fatal(gettext("Unknown option `-%c'"), optopt);
			} else {
				fatal(gettext("Missing argument after `-%c'"), optopt);
			}
		}



		makefile_next |= parse_command_option(ch);
		/*
		 * If we're done processing all of the options of
		 * ONE argument string...
		 */
		if (current_optind < optind) {
			i = current_optind;
			k = 0;
			/* If there's an argument for an option... */
			if ((optind - current_optind) > 1) {
				k = i + 1;
			}
			switch (makefile_next) {
			case 0:
				argv[i] = NULL;
				/* This shouldn't happen */
				if (k) {
					argv[k] = NULL;
				}
				break;
			case 1:	/* -f seen */
				argv[i] = (char *)"-f";
				break;
			case 2:	/* -c seen */
				argv[i] = (char *)"-c";
				break;
			case 4:	/* -g seen */
				argv[i] = (char *)"-g";
				break;
			case 8:	/* -j seen */
				argv[i] = (char *)"-j";
				break;
			case 16: /* -M seen */
				argv[i] = (char *)"-M";
				break;
			case 32: /* -m seen */
				argv[i] = (char *)"-m";
				break;
			case 128: /* -O seen */
				argv[i] = (char *)"-O";
				break;
			case 256: /* -K seen */
				argv[i] = (char *)"-K";
			        break;
			case 512:	/* -o seen */
				argv[i] = (char *)"-o";
				break;
			case 1024: /* -x seen */
				argv[i] = (char *)"-x";
				break;
			default: /* > 1 of -c, f, g, j, K, M, m, O, o, x seen */
				fatal(gettext("Illegal command line. More than one option requiring\nan argument given in the same argument group"));
			}

			makefile_next = 0;
			current_optind = optind;
		}
	}
}

static void
quote_str(char *str, char *qstr)
{
	char		*to;
	char		*from;

	to = qstr;
	for (from = str; *from; from++) {
		switch (*from) {
		case ';':	/* End of command */
		case '(':	/* Start group */
		case ')':	/* End group */
		case '{':	/* Start group */
		case '}':	/* End group */
		case '[':	/* Reg expr - any of a set of chars */
		case ']':	/* End of set of chars */
		case '|':	/* Pipe or logical-or */
		case '^':	/* Old-fashioned pipe */
		case '&':	/* Background or logical-and */
		case '<':	/* Redirect stdin */
		case '>':	/* Redirect stdout */
		case '*':	/* Reg expr - any sequence of chars */
		case '?':	/* Reg expr - any single char */
		case '$':	/* Variable substitution */
		case '\'':	/* Singe quote - turn off all magic */
		case '"':	/* Double quote - span whitespace */
		case '`':	/* Backquote - run a command */
		case '#':	/* Comment */
		case ' ':	/* Space (for MACRO=value1 value2  */
		case '\\':	/* Escape char - turn off magic of next char */
			*to++ = '\\';
			break;

		default:
			break;
		}
		*to++ = *from;
	}
	*to = '\0';
}

static void
unquote_str(char *str, char *qstr)
{
	char		*to;
	char		*from;

	to = qstr;
	for (from = str; *from; from++) {
		if (*from == '\\') {
			from++;
		}
		*to++ = *from;
	}
	*to = '\0';
}

/*
 * Convert the MAKEFLAGS string value into a vector of char *, similar
 * to argv.
 */
static void
setup_makeflags_argv()
{
	char		*cp;
	char		*cp1;
	char		*cp2;
	char		*cp3;
	char		*cp_orig;
	Boolean		add_hyphen;
	int		i;
	char		tmp_char;

	mf_argc = 1;
	cp = getenv(makeflags->string_mb);
	cp_orig = cp;

	if (cp) {
		/*
		 * If new MAKEFLAGS format, no need to add hyphen.
		 * If old MAKEFLAGS format, add hyphen before flags.
		 */

		if ((strchr(cp, (int) hyphen_char) != NULL) ||
		    (strchr(cp, (int) equal_char) != NULL)) {

			/* New MAKEFLAGS format */

			add_hyphen = false;

			/* Check if MAKEFLAGS value begins with multiple
			 * hyphen characters, and remove all duplicates.
			 * Usually it happens when the next command is
			 * used: $(MAKE) -$(MAKEFLAGS)
			 * 
			 * This was a workaround for BugID 5060758, but
			 * appears to have survived as a fix in make.
			 */
			while (*cp) {
				if (*cp != (int) hyphen_char) {
					break;
				}
				cp++;
				if (*cp == (int) hyphen_char) {
					/* There are two hyphens. Skip one */
					cp_orig = cp;
					cp++;
				}
				if (!(*cp)) {
					/* There are hyphens only. Skip all */
					cp_orig = cp;
					break;
				}
			}
		} else {

			/* Old MAKEFLAGS format */

			add_hyphen = true;
		}
	}

	/* Find the number of arguments in MAKEFLAGS */
	while (cp && *cp) {
		/* Skip white spaces */
		while (cp && *cp && isspace(*cp)) {
			cp++;
		}
		if (cp && *cp) {
			/* Increment arg count */
			mf_argc++;
			/* Go to next white space */
			while (cp && *cp && !isspace(*cp)) {
				if(*cp == (int) backslash_char) {
					cp++;
				}
				cp++;
			}
		}
	}
	/* Allocate memory for the new MAKEFLAGS argv */
	mf_argv = (char **) malloc((mf_argc + 1) * sizeof(char *));
	mf_argv[0] = (char *)"MAKEFLAGS";
	/*
	 * Convert the MAKEFLAGS string value into a vector of char *,
	 * similar to argv.
	 */
	cp = cp_orig;
	for (i = 1; i < mf_argc; i++) {
		/* Skip white spaces */
		while (cp && *cp && isspace(*cp)) {
			cp++;
		}
		if (cp && *cp) {
			cp_orig = cp;
			/* Go to next white space */
			while (cp && *cp && !isspace(*cp)) {
				if(*cp == (int) backslash_char) {
					cp++;
				}
				cp++;
			}
			tmp_char = *cp;
			*cp = (int) nul_char;
			if (add_hyphen) {
				mf_argv[i] = getmem(2 + strlen(cp_orig));
				mf_argv[i][0] = '\0';
				(void) strcat(mf_argv[i], "-");
				// (void) strcat(mf_argv[i], cp_orig);
				unquote_str(cp_orig, mf_argv[i]+1);
			} else {
				mf_argv[i] = getmem(2 + strlen(cp_orig));
				//mf_argv[i] = strdup(cp_orig);
				unquote_str(cp_orig, mf_argv[i]);
			}
			*cp = tmp_char;
		}
	}
	mf_argv[i] = NULL;
}

/*
 *	parse_command_option(ch)
 *
 *	Parse make command line options.
 *
 *	Return value:
 *				Indicates if any -f -c or -M were seen
 *
 *	Parameters:
 *		ch		The character to parse
 *
 *	Static variables used:
 *		dmake_group_specified	Set for make -g
 *		dmake_max_jobs_specified	Set for make -j
 *		dmake_mode_specified	Set for make -m
 *		dmake_add_mode_specified	Set for make -x
 *		dmake_compat_mode_specified	Set for make -x SUN_MAKE_COMPAT_MODE=
 *		dmake_output_mode_specified	Set for make -x DMAKE_OUTPUT_MODE=
 *		dmake_odir_specified	Set for make -o
 *		dmake_rcfile_specified	Set for make -c
 *		env_wins		Set for make -e
 *		ignore_default_mk	Set for make -r
 *		trace_status		Set for make -p
 *
 *	Global variables used:
 *		.make.state path & name set for make -K
 *		continue_after_error	Set for make -k
 *		debug_level		Set for make -d
 *		do_not_exec_rule	Set for make -n
 *		filter_stderr		Set for make -X
 *		ignore_errors_all	Set for make -i
 *		no_parallel		Set for make -R
 *		quest			Set for make -q
 *		read_trace_level	Set for make -D
 *		report_dependencies	Set for make -P
 *		silent_all		Set for make -s
 *		touch			Set for make -t
 */
static int
parse_command_option(register char ch)
{
	static int		invert_next = 0;
	int			invert_this = invert_next;

	invert_next = 0;
	switch (ch) {
	case '-':			 /* Ignore "--" */
		return 0;
	case '~':			 /* Invert next option */
		invert_next = 1;
		return 0;
	case 'B':			 /* Obsolete */
		return 0;
	case 'b':			 /* Obsolete */
		return 0;
	case 'c':			 /* Read alternative dmakerc file */
		if (invert_this) {
			dmake_rcfile_specified = false;
		} else {
			dmake_rcfile_specified = true;
		}
		return 2;
	case 'D':			 /* Show lines read */
		if (invert_this) {
			read_trace_level--;
		} else {
			read_trace_level++;
		}
		return 0;
	case 'd':			 /* Debug flag */
		if (invert_this) {
			debug_level--;
		} else {
			debug_level++;
		}
		return 0;
	case 'e':			 /* Environment override flag */
		if (invert_this) {
			env_wins = false;
		} else {
			env_wins = true;
		}
		return 0;
	case 'f':			 /* Read alternative makefile(s) */
		return 1;
	case 'g':			 /* Use alternative DMake group */
		if (invert_this) {
			dmake_group_specified = false;
		} else {
			dmake_group_specified = true;
		}
		return 4;
	case 'i':			 /* Ignore errors */
		if (invert_this) {
			ignore_errors_all = false;
		} else {
			ignore_errors_all = true;
		}
		return 0;
	case 'j':			 /* Use alternative DMake max jobs */
		if (invert_this) {
			dmake_max_jobs_specified = false;
		} else {
			dmake_mode_type = parallel_mode;
			no_parallel = false;
			dmake_max_jobs_specified = true;
		}
		return 8;
	case 'K':			 /* Read alternative .make.state */
		return 256;
	case 'k':			 /* Keep making even after errors */
		if (invert_this) {
			continue_after_error = false;
		} else {
			continue_after_error = true;
			continue_after_error_ever_seen = true;
		}
		return 0;
	case 'M':			 /* Read alternative make.machines file */
		if (invert_this) {
			pmake_machinesfile_specified = false;
		} else {
			pmake_machinesfile_specified = true;
			dmake_mode_type = parallel_mode;
			no_parallel = false;
		}
		return 16;
	case 'm':			 /* Use alternative DMake build mode */
		if (invert_this) {
			dmake_mode_specified = false;
		} else {
			dmake_mode_specified = true;
		}
		return 32;
	case 'x':			 /* Use alternative DMake mode */
		if (invert_this) {
			dmake_add_mode_specified = false;
		} else {
			dmake_add_mode_specified = true;
		}
		return 1024;
	case 'N':			 /* Reverse -n */
		if (invert_this) {
			do_not_exec_rule = true;
		} else {
			do_not_exec_rule = false;
		}
		return 0;
	case 'n':			 /* Print, not exec commands */
		if (invert_this) {
			do_not_exec_rule = false;
		} else {
			do_not_exec_rule = true;
		}
		return 0;
	case 'O':			 /* Integrate with maketool, obsolete */
		return 0;
	case 'o':			 /* Use alternative dmake output dir */
		if (invert_this) {
			dmake_odir_specified = false;
		} else {
			dmake_odir_specified = true;
		}
		return 512;
	case 'P':			 /* Print for selected targets */
		if (invert_this) {
			report_dependencies_level--;
		} else {
			report_dependencies_level++;
		}
		return 0;
	case 'p':			 /* Print description */
		if (invert_this) {
			trace_status = false;
			do_not_exec_rule = false;
		} else {
			trace_status = true;
			do_not_exec_rule = true;
		}
		return 0;
	case 'q':			 /* Question flag */
		if (invert_this) {
			quest = false;
		} else {
			quest = true;
		}
		return 0;
	case 'R':			 /* Don't run in parallel */
		if (invert_this) {
			pmake_cap_r_specified = false;
			no_parallel = false;
		} else {
			pmake_cap_r_specified = true;
			dmake_mode_type = serial_mode;
			no_parallel = true;
		}
		return 0;
	case 'r':			 /* Turn off internal rules */
		if (invert_this) {
			ignore_default_mk = false;
		} else {
			ignore_default_mk = true;
		}
		return 0;
	case 'S':			 /* Reverse -k */
		if (invert_this) {
			continue_after_error = true;
		} else {
			continue_after_error = false;
			stop_after_error_ever_seen = true;
		}
		return 0;
	case 's':			 /* Silent flag */
		if (invert_this) {
			silent_all = false;
		} else {
			silent_all = true;
		}
		return 0;
	case 'T':			 /* Print target list */
		if (invert_this) {
			list_all_targets = false;
			do_not_exec_rule = false;
		} else {
			list_all_targets = true;
			do_not_exec_rule = true;
		}
		return 0;
	case 't':			 /* Touch flag */
		if (invert_this) {
			touch = false;
		} else {
			touch = true;
		}
		return 0;
	case 'u':			 /* Unconditional flag */
		if (invert_this) {
			build_unconditional = false;
		} else {
			build_unconditional = true;
		}
		return 0;
	case 'V':			/* SVR4 mode */
		svr4 = true;
		return 0;
	case 'v':			/* Version flag */
		if (invert_this) {
		} else {
			fprintf(stdout, "%s: %s\n", getprogname(), verstring);
			exit_status = 0;
			exit(0);
		}
		return 0;
	case 'w':			 /* Unconditional flag */
		if (invert_this) {
			report_cwd = false;
		} else {
			report_cwd = true;
		}
		return 0;
#if 0
	case 'X':			/* Filter stdout */
		if (invert_this) {
			filter_stderr = false;
		} else {
			filter_stderr = true;
		}
		return 0;
#endif
	default:
		break;
	}
	return 0;
}

/*
 *	setup_for_projectdir()
 *
 *	Read the PROJECTDIR variable, if defined, and set the sccs path
 *
 *	Parameters:
 *
 *	Global variables used:
 *		sccs_dir_path	Set to point to SCCS dir to use
 */
static void
setup_for_projectdir(void)
{
static char	path[MAXPATHLEN];
char		cwdpath[MAXPATHLEN];
uid_t uid;
int   done=0;

	/* Check if we should use PROJECTDIR when reading the SCCS dir. */
	sccs_dir_path = getenv("PROJECTDIR");
	if ((sccs_dir_path != NULL) &&
	    (sccs_dir_path[0] != (int) slash_char)) {
		struct passwd *pwent;

	     {
		uid = getuid();
		pwent = getpwuid(uid);
		if (pwent == NULL) {
		   fatal(gettext("Bogus USERID "));
		}
		if ((pwent = getpwnam(sccs_dir_path)) == NULL) {
			/*empty block : it'll go & check cwd  */
		}
		else {
		  (void) sprintf(path, "%s/src", pwent->pw_dir);
		  if (access(path, F_OK) == 0) {
			sccs_dir_path = path;
			done = 1;
		  } else {
			(void) sprintf(path, "%s/source", pwent->pw_dir);
			if (access(path, F_OK) == 0) {
				sccs_dir_path = path;
				done = 1;
			}
		     }
		}
		if (!done) {
		    if (getcwd(cwdpath, MAXPATHLEN - 1 )) {

		       (void) sprintf(path, "%s/%s", cwdpath,sccs_dir_path);
		       if (access(path, F_OK) == 0) {
		        	sccs_dir_path = path;
				done = 1;
		        } else {
		  	       	fatal(gettext("Bogus PROJECTDIR '%s'"), sccs_dir_path);
		        }
		    }
		}
	   }
	}
}

char *
make_install_prefix(void)
{
	int ret;
	char origin[PATH_MAX];
	char *dir;

	if ((ret = readlink("/proc/self/path/a.out", origin,
	    PATH_MAX - 1)) < 0)
		fatal("failed to read origin from /proc\n");

	
	origin[ret] = '\0';
	return strdup(dirname(origin));
}

static char *
add_to_env(const char *var, const char *value, const char *fallback)
{
	const char *oldpath;
	char *newpath;

	oldpath = getenv(var);
	if (oldpath == NULL) {
		if (value != NULL) {
			asprintf(&newpath, "%s=%s",
			    var, value);
		} else {
			asprintf(&newpath, "%s=%s",
			    var, fallback);
		}
	} else {
		if (value != NULL) {
			asprintf(&newpath, "%s=%s:%s",
			    var, oldpath, value);
		} else {
			asprintf(&newpath, "%s=%s:%s",
			    var, oldpath, fallback);			
		}
	}

	return (newpath);
}

/*
 *	set_sgs_support()
 *
 *	Add the libmakestate.so.1 lib to the env var SGS_SUPPORT
 *	  if it's not already in there.
 *	The SGS_SUPPORT env var and libmakestate.so.1 is used by
 *	  the linker ld to report .make.state info back to make.
 *
 * In the new world we always will set the 32-bit and 64-bit versions of this
 * variable explicitly so that we can take into account the correct isa and our
 * prefix. So say that the prefix was /opt/local. Then we would want to search
 * /opt/local/lib/libmakestate.so.1:libmakestate.so.1. We still want to search
 * the original location just as a safety measure.
 */
static void
set_sgs_support()
{
	int		len;
	char		*newpath, *newpath64;
	char 		*lib32, *lib64;
	static char	*prev_path, *prev_path64;
	char		*origin = make_install_prefix();
	struct stat st;

	asprintf(&lib32, "%s/%s/%s", origin, "../lib",
	    LD_SUPPORT_MAKE_LIB);

	if (stat(lib32, &st) != 0) {
		free(lib32);
		// Try the tools path
		asprintf(&lib32, "%s/%s/%s/%s", origin, "../../lib/",
		    LD_SUPPORT_MAKE_ARCH, LD_SUPPORT_MAKE_LIB);

		if (stat(lib32, &st) != 0) {
			free(lib32);
			lib32 = NULL;
		}
	}

	asprintf(&lib64, "%s/%s/64/%s", origin, "../lib",
	    LD_SUPPORT_MAKE_LIB);

	if (stat(lib64, &st) != 0) {
		free(lib64);
		// Try the tools path
		asprintf(&lib64, "%s/%s/%s/64/%s", origin, "../../lib/",
		    LD_SUPPORT_MAKE_ARCH, LD_SUPPORT_MAKE_LIB);

		if (stat(lib64, &st) != 0) {
			free(lib64);
			lib64 = NULL;
		}
	}

	newpath = add_to_env(LD_SUPPORT_ENV_VAR_32, lib32, LD_SUPPORT_MAKE_LIB);
	newpath64 = add_to_env(LD_SUPPORT_ENV_VAR_64, lib64, LD_SUPPORT_MAKE_LIB);

	putenv(newpath);
	if (prev_path) {
		free(prev_path);
	}
	prev_path = newpath;

	putenv(newpath64);
	if (prev_path64) {
		free(prev_path64);
	}
	prev_path64 = newpath64;
	free(lib32);
	free(lib64);
	free(origin);
}

/*
 *	read_files_and_state(argc, argv)
 *
 *	Read the makefiles we care about and the environment
 *	Also read the = style command line options
 *
 *	Parameters:
 *		argc		You know what this is
 *		argv		You know what this is
 *
 *	Static variables used:
 *		env_wins	make -e, determines if env vars are RO
 *		ignore_default_mk make -r, determines if make.rules is read
 *		not_auto_depen	dwight
 *
 *	Global variables used:
 *		default_target_to_build	Set to first proper target from file
 *		do_not_exec_rule Set to false when makfile is made
 *		dot		The Name ".", used to read current dir
 *		empty_name	The Name "", use as macro value
 *		keep_state	Set if KEEP_STATE is in environment
 *		make_state	The Name ".make.state", used to read file
 *		makefile_type	Set to type of file being read
 *		makeflags	The Name "MAKEFLAGS", used to set macro value
 *		not_auto	dwight
 *		read_trace_level Checked to se if the reader should trace
 *		report_dependencies If -P is on we do not read .make.state
 *		trace_reader	Set if reader should trace
 *		virtual_root	The Name "VIRTUAL_ROOT", used to check value
 */
static void
read_files_and_state(int argc, char **argv)
{
	wchar_t			buffer[1000];
	wchar_t			buffer_posix[1000];
	register char		ch;
	register char		*cp;
	Property		def_make_macro = NULL;
	Name			def_make_name;
	Name			default_makefile;
	String_rec		dest;
	wchar_t			destbuffer[STRING_BUFFER_LENGTH];
	register int		i;
	register int		j;
	Name			keep_state_name;
	int			length;
	Name			Makefile;
	register Property	macro;
	struct stat		make_state_stat;
	Name			makefile_name;
        register int		makefile_next = 0;
	register Boolean	makefile_read = false;
	String_rec		makeflags_string;
	String_rec		makeflags_string_posix;
	String_rec *		makeflags_string_current;
	Name			makeflags_value_saved;
	register Name		name;
	Name			new_make_value;
	Boolean			save_do_not_exec_rule;
	Name			sdotMakefile;
	Name			sdotmakefile_name;
	static wchar_t		state_file_str;
	static char		state_file_str_mb[MAXPATHLEN];
	static struct _Name	state_filename;
	Boolean			temp;
	char			tmp_char;
	wchar_t			*tmp_wcs_buffer;
	register Name		value;
	ASCII_Dyn_Array		makeflags_and_macro;
	Boolean			is_xpg4;

/*
 *	Remember current mode. It may be changed after reading makefile
 *	and we will have to correct MAKEFLAGS variable.
 */
	is_xpg4 = posix;

	MBSTOWCS(wcs_buffer, "KEEP_STATE");
	keep_state_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "Makefile");
	Makefile = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "makefile");
	makefile_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "s.makefile");
	sdotmakefile_name = GETNAME(wcs_buffer, FIND_LENGTH);
	MBSTOWCS(wcs_buffer, "s.Makefile");
	sdotMakefile = GETNAME(wcs_buffer, FIND_LENGTH);

/*
 *	initialize global dependency entry for .NOT_AUTO
 */
	not_auto_depen->next = NULL;
	not_auto_depen->name = not_auto;
	not_auto_depen->automatic = not_auto_depen->stale = false;

/*
 *	Read internal definitions and rules.
 */
	if (read_trace_level > 1) {
		trace_reader = true;
	}
	if (!ignore_default_mk) {
		if (svr4) {
			MBSTOWCS(wcs_buffer, "svr4.make.rules");
			default_makefile = GETNAME(wcs_buffer, FIND_LENGTH);
		} else {
			MBSTOWCS(wcs_buffer, "make.rules");
			default_makefile = GETNAME(wcs_buffer, FIND_LENGTH);
		}
		default_makefile->stat.is_file = true;

		(void) read_makefile(default_makefile,
				     true,
				     false,
				     true);
	}

	/*
	 * If the user did not redefine the MAKE macro in the
	 * default makefile (make.rules), then we'd like to
	 * change the macro value of MAKE to be some form
	 * of argv[0] for recursive MAKE builds.
	 */
	MBSTOWCS(wcs_buffer, "MAKE");
	def_make_name = GETNAME(wcs_buffer, wcslen(wcs_buffer));
	def_make_macro = get_prop(def_make_name->prop, macro_prop);
	if ((def_make_macro != NULL) &&
	    (IS_EQUAL(def_make_macro->body.macro.value->string_mb,
	              "make"))) {
		MBSTOWCS(wcs_buffer, argv_zero_string);
		new_make_value = GETNAME(wcs_buffer, wcslen(wcs_buffer));
		(void) SETVAR(def_make_name,
		              new_make_value,
		              false);
	}

	default_target_to_build = NULL;
	trace_reader = false;

/*
 *	Read environment args. Let file args which follow override unless
 *	-e option seen. If -e option is not mentioned.
 */
	read_environment(env_wins);
	if (getvar(virtual_root)->hash.length == 0) {
		maybe_append_prop(virtual_root, macro_prop)
		  ->body.macro.exported = true;
		MBSTOWCS(wcs_buffer, "/");
		(void) SETVAR(virtual_root,
			      GETNAME(wcs_buffer, FIND_LENGTH),
			      false);
	}

/*
 * We now scan mf_argv and argv to see if we need to set
 * any of the DMake-added options/variables in MAKEFLAGS.
 */

	makeflags_and_macro.start = 0;
	makeflags_and_macro.size = 0;
	enter_argv_values(mf_argc, mf_argv, &makeflags_and_macro);
	enter_argv_values(argc, argv, &makeflags_and_macro);

/*
 *	Set MFLAGS and MAKEFLAGS
 *	
 *	Before reading makefile we do not know exactly which mode
 *	(posix or not) is used. So prepare two MAKEFLAGS strings
 *	for both posix and solaris modes because they are different.
 */
	INIT_STRING_FROM_STACK(makeflags_string, buffer);
	INIT_STRING_FROM_STACK(makeflags_string_posix, buffer_posix);
	append_char((int) hyphen_char, &makeflags_string);
	append_char((int) hyphen_char, &makeflags_string_posix);

	switch (read_trace_level) {
	case 2:
		append_char('D', &makeflags_string);
		append_char('D', &makeflags_string_posix);
	case 1:
		append_char('D', &makeflags_string);
		append_char('D', &makeflags_string_posix);
	}
	switch (debug_level) {
	case 2:
		append_char('d', &makeflags_string);
		append_char('d', &makeflags_string_posix);
	case 1:
		append_char('d', &makeflags_string);
		append_char('d', &makeflags_string_posix);
	}
	if (env_wins) {
		append_char('e', &makeflags_string);
		append_char('e', &makeflags_string_posix);
	}
	if (ignore_errors_all) {
		append_char('i', &makeflags_string);
		append_char('i', &makeflags_string_posix);
	}
	if (continue_after_error) {
		if (stop_after_error_ever_seen) {
			append_char('S', &makeflags_string_posix);
			append_char((int) space_char, &makeflags_string_posix);
			append_char((int) hyphen_char, &makeflags_string_posix);
		}
		append_char('k', &makeflags_string);
		append_char('k', &makeflags_string_posix);
	} else {
		if (stop_after_error_ever_seen 
		    && continue_after_error_ever_seen) {
			append_char('k', &makeflags_string_posix);
			append_char((int) space_char, &makeflags_string_posix);
			append_char((int) hyphen_char, &makeflags_string_posix);
			append_char('S', &makeflags_string_posix);
		}
	}
	if (do_not_exec_rule) {
		append_char('n', &makeflags_string);
		append_char('n', &makeflags_string_posix);
	}
	switch (report_dependencies_level) {
	case 4:
		append_char('P', &makeflags_string);
		append_char('P', &makeflags_string_posix);
	case 3:
		append_char('P', &makeflags_string);
		append_char('P', &makeflags_string_posix);
	case 2:
		append_char('P', &makeflags_string);
		append_char('P', &makeflags_string_posix);
	case 1:
		append_char('P', &makeflags_string);
		append_char('P', &makeflags_string_posix);
	}
	if (trace_status) {
		append_char('p', &makeflags_string);
		append_char('p', &makeflags_string_posix);
	}
	if (quest) {
		append_char('q', &makeflags_string);
		append_char('q', &makeflags_string_posix);
	}
	if (silent_all) {
		append_char('s', &makeflags_string);
		append_char('s', &makeflags_string_posix);
	}
	if (touch) {
		append_char('t', &makeflags_string);
		append_char('t', &makeflags_string_posix);
	}
	if (build_unconditional) {
		append_char('u', &makeflags_string);
		append_char('u', &makeflags_string_posix);
	}
	if (report_cwd) {
		append_char('w', &makeflags_string);
		append_char('w', &makeflags_string_posix);
	}
	/* -c dmake_rcfile */
	if (dmake_rcfile_specified) {
		MBSTOWCS(wcs_buffer, "DMAKE_RCFILE");
		dmake_rcfile = GETNAME(wcs_buffer, FIND_LENGTH);
		append_makeflags_string(dmake_rcfile, &makeflags_string);
		append_makeflags_string(dmake_rcfile, &makeflags_string_posix);
	}
	/* -g dmake_group */
	if (dmake_group_specified) {
		MBSTOWCS(wcs_buffer, "DMAKE_GROUP");
		dmake_group = GETNAME(wcs_buffer, FIND_LENGTH);
		append_makeflags_string(dmake_group, &makeflags_string);
		append_makeflags_string(dmake_group, &makeflags_string_posix);
	}
	/* -j dmake_max_jobs */
	if (dmake_max_jobs_specified) {
		MBSTOWCS(wcs_buffer, "DMAKE_MAX_JOBS");
		dmake_max_jobs = GETNAME(wcs_buffer, FIND_LENGTH);
		append_makeflags_string(dmake_max_jobs, &makeflags_string);
		append_makeflags_string(dmake_max_jobs, &makeflags_string_posix);
	}
	/* -m dmake_mode */
	if (dmake_mode_specified) {
		MBSTOWCS(wcs_buffer, "DMAKE_MODE");
		dmake_mode = GETNAME(wcs_buffer, FIND_LENGTH);
		append_makeflags_string(dmake_mode, &makeflags_string);
		append_makeflags_string(dmake_mode, &makeflags_string_posix);
	}
	/* -x dmake_compat_mode */
//	if (dmake_compat_mode_specified) {
//		MBSTOWCS(wcs_buffer, "SUN_MAKE_COMPAT_MODE");
//		dmake_compat_mode = GETNAME(wcs_buffer, FIND_LENGTH);
//		append_makeflags_string(dmake_compat_mode, &makeflags_string);
//		append_makeflags_string(dmake_compat_mode, &makeflags_string_posix);
//	}
	/* -x dmake_output_mode */
	if (dmake_output_mode_specified) {
		MBSTOWCS(wcs_buffer, "DMAKE_OUTPUT_MODE");
		dmake_output_mode = GETNAME(wcs_buffer, FIND_LENGTH);
		append_makeflags_string(dmake_output_mode, &makeflags_string);
		append_makeflags_string(dmake_output_mode, &makeflags_string_posix);
	}
	/* -o dmake_odir */
	if (dmake_odir_specified) {
		MBSTOWCS(wcs_buffer, "DMAKE_ODIR");
		dmake_odir = GETNAME(wcs_buffer, FIND_LENGTH);
		append_makeflags_string(dmake_odir, &makeflags_string);
		append_makeflags_string(dmake_odir, &makeflags_string_posix);
	}
	/* -M pmake_machinesfile */
	if (pmake_machinesfile_specified) {
		MBSTOWCS(wcs_buffer, "PMAKE_MACHINESFILE");
		pmake_machinesfile = GETNAME(wcs_buffer, FIND_LENGTH);
		append_makeflags_string(pmake_machinesfile, &makeflags_string);
		append_makeflags_string(pmake_machinesfile, &makeflags_string_posix);
	}
	/* -R */
	if (pmake_cap_r_specified) {
		append_char((int) space_char, &makeflags_string);
		append_char((int) hyphen_char, &makeflags_string);
		append_char('R', &makeflags_string);
		append_char((int) space_char, &makeflags_string_posix);
		append_char((int) hyphen_char, &makeflags_string_posix);
		append_char('R', &makeflags_string_posix);
	}

/*
 *	Make sure MAKEFLAGS is exported
 */
	maybe_append_prop(makeflags, macro_prop)->
	  body.macro.exported = true;

	if (makeflags_string.buffer.start[1] != (int) nul_char) {
		if (makeflags_string.buffer.start[1] != (int) space_char) {
			MBSTOWCS(wcs_buffer, "MFLAGS");
			(void) SETVAR(GETNAME(wcs_buffer, FIND_LENGTH),
				      GETNAME(makeflags_string.buffer.start,
					      FIND_LENGTH),
				      false);
		} else {
			MBSTOWCS(wcs_buffer, "MFLAGS");
			(void) SETVAR(GETNAME(wcs_buffer, FIND_LENGTH),
				      GETNAME(makeflags_string.buffer.start + 2,
					      FIND_LENGTH),
				      false);
		}
	}

/* 
 *	Add command line macro to POSIX makeflags_string  
 */
	if (makeflags_and_macro.start) {
		tmp_char = (char) space_char;
		cp = makeflags_and_macro.start;
		do {
			append_char(tmp_char, &makeflags_string_posix);
		} while ( tmp_char = *cp++ ); 
		retmem_mb(makeflags_and_macro.start);
	}

/*
 *	Now set the value of MAKEFLAGS macro in accordance
 *	with current mode.
 */
	macro = maybe_append_prop(makeflags, macro_prop);
	temp = (Boolean) macro->body.macro.read_only;
	macro->body.macro.read_only = false;
	if(posix || gnu_style) {
		makeflags_string_current = &makeflags_string_posix;
	} else {
		makeflags_string_current = &makeflags_string;
	}
	if (makeflags_string_current->buffer.start[1] == (int) nul_char) {
		makeflags_value_saved =
			GETNAME( makeflags_string_current->buffer.start + 1
			       , FIND_LENGTH
			       );
	} else {
		if (makeflags_string_current->buffer.start[1] != (int) space_char) {
			makeflags_value_saved =
				GETNAME( makeflags_string_current->buffer.start
				       , FIND_LENGTH
				       );
		} else {
			makeflags_value_saved =
				GETNAME( makeflags_string_current->buffer.start + 2
				       , FIND_LENGTH
				       );
		}
	}
	(void) SETVAR( makeflags
	             , makeflags_value_saved
	             , false
	             );
	macro->body.macro.read_only = temp;

/*
 *	Read command line "-f" arguments and ignore -c, g, j, K, M, m, O and o args.
 */
	save_do_not_exec_rule = do_not_exec_rule;
	do_not_exec_rule = false;
	if (read_trace_level > 0) {
		trace_reader = true;
	}

	for (i = 1; i < argc; i++) {
		if (argv[i] &&
		    (argv[i][0] == (int) hyphen_char) &&
		    (argv[i][1] == 'f') &&
		    (argv[i][2] == (int) nul_char)) {
			argv[i] = NULL;		/* Remove -f */
			if (i >= argc - 1) {
				fatal(gettext("No filename argument after -f flag"));
			}
			MBSTOWCS(wcs_buffer, argv[++i]);
			primary_makefile = GETNAME(wcs_buffer, FIND_LENGTH);
			(void) read_makefile(primary_makefile, true, true, true);
			argv[i] = NULL;		/* Remove filename */
			makefile_read = true;
		} else if (argv[i] &&
			   (argv[i][0] == (int) hyphen_char) &&
			   (argv[i][1] == 'c' ||
			    argv[i][1] == 'g' ||
			    argv[i][1] == 'j' ||
			    argv[i][1] == 'K' ||
			    argv[i][1] == 'M' ||
			    argv[i][1] == 'm' ||
			    argv[i][1] == 'O' ||
			    argv[i][1] == 'o') &&
			   (argv[i][2] == (int) nul_char)) {
			argv[i] = NULL;
			argv[++i] = NULL;
		}
	}

/*
 *	If no command line "-f" args then look for "makefile", and then for
 *	"Makefile" if "makefile" isn't found.
 */
	if (!makefile_read) {
		(void) read_dir(dot,
				(wchar_t *) NULL,
				(Property) NULL,
				(wchar_t *) NULL);
	    if (!posix) {
		if (makefile_name->stat.is_file) {
			if (Makefile->stat.is_file) {
				warning(gettext("Both `makefile' and `Makefile' exist"));
			}
			primary_makefile = makefile_name;
			makefile_read = read_makefile(makefile_name,
						      false,
						      false,
						      true);
		}
		if (!makefile_read &&
		    Makefile->stat.is_file) {
			primary_makefile = Makefile;
			makefile_read = read_makefile(Makefile,
						      false,
						      false,
						      true);
		}
	    } else {

		enum sccs_stat save_m_has_sccs = NO_SCCS;
		enum sccs_stat save_M_has_sccs = NO_SCCS;

		if (makefile_name->stat.is_file) {
			if (Makefile->stat.is_file) {
				warning(gettext("Both `makefile' and `Makefile' exist"));
			}
		}
		if (makefile_name->stat.is_file) {
			if (makefile_name->stat.has_sccs == NO_SCCS) {
			   primary_makefile = makefile_name;
			   makefile_read = read_makefile(makefile_name,
						      false,
						      false,
						      true);
			} else {
			  save_m_has_sccs = makefile_name->stat.has_sccs;
			  makefile_name->stat.has_sccs = NO_SCCS;
			  primary_makefile = makefile_name;
			  makefile_read = read_makefile(makefile_name,
						      false,
						      false,
						      true);
			}
		}
		if (!makefile_read &&
		    Makefile->stat.is_file) {
			if (Makefile->stat.has_sccs == NO_SCCS) {
			   primary_makefile = Makefile;
			   makefile_read = read_makefile(Makefile,
						      false,
						      false,
						      true);
			} else {
			  save_M_has_sccs = Makefile->stat.has_sccs;
			  Makefile->stat.has_sccs = NO_SCCS;
			  primary_makefile = Makefile;
			  makefile_read = read_makefile(Makefile,
						      false,
						      false,
						      true);
			}
		}
		if (!makefile_read &&
		        makefile_name->stat.is_file) {
			   makefile_name->stat.has_sccs = save_m_has_sccs;
			   primary_makefile = makefile_name;
			   makefile_read = read_makefile(makefile_name,
						      false,
						      false,
						      true);
		}
		if (!makefile_read &&
		    Makefile->stat.is_file) {
			   Makefile->stat.has_sccs = save_M_has_sccs;
			   primary_makefile = Makefile;
			   makefile_read = read_makefile(Makefile,
						      false,
						      false,
						      true);
		}
	    }
	}
	do_not_exec_rule = save_do_not_exec_rule;
	allrules_read = makefile_read;
	trace_reader = false;

/*
 *	Now get current value of MAKEFLAGS and compare it with
 *	the saved value we set before reading makefile.
 *	If they are different then MAKEFLAGS is subsequently set by
 *	makefile, just leave it there. Otherwise, if make mode
 *	is changed by using .POSIX target in makefile we need
 *	to correct MAKEFLAGS value.
 */
	Name mf_val = getvar(makeflags);
	if( (posix != is_xpg4)
	 && (!strcmp(mf_val->string_mb, makeflags_value_saved->string_mb)))
	{
		if (makeflags_string_posix.buffer.start[1] == (int) nul_char) {
			(void) SETVAR(makeflags,
				      GETNAME(makeflags_string_posix.buffer.start + 1,
					      FIND_LENGTH),
				      false);
		} else {
			if (makeflags_string_posix.buffer.start[1] != (int) space_char) {
				(void) SETVAR(makeflags,
					      GETNAME(makeflags_string_posix.buffer.start,
						      FIND_LENGTH),
					      false);
			} else {
				(void) SETVAR(makeflags,
					      GETNAME(makeflags_string_posix.buffer.start + 2,
						      FIND_LENGTH),
					      false);
			}
		}
	}

	if (makeflags_string.free_after_use) {
		retmem(makeflags_string.buffer.start);
	}
	if (makeflags_string_posix.free_after_use) {
		retmem(makeflags_string_posix.buffer.start);
	}
	makeflags_string.buffer.start = NULL;
	makeflags_string_posix.buffer.start = NULL;

	if (posix) {
		/*
		 * If the user did not redefine the ARFLAGS macro in the
		 * default makefile (make.rules), then we'd like to
		 * change the macro value of ARFLAGS to be in accordance
		 * with "POSIX" requirements.
		 */
		MBSTOWCS(wcs_buffer, "ARFLAGS");
		name = GETNAME(wcs_buffer, wcslen(wcs_buffer));
		macro = get_prop(name->prop, macro_prop);
		if ((macro != NULL) && /* Maybe (macro == NULL) || ? */
		    (IS_EQUAL(macro->body.macro.value->string_mb,
		              "rv"))) {
			MBSTOWCS(wcs_buffer, "-rv");
			value = GETNAME(wcs_buffer, wcslen(wcs_buffer));
			(void) SETVAR(name,
			              value,
			              false);
		}
	}

	if (!posix && !svr4) {
		set_sgs_support();
	}


/*
 *	Make sure KEEP_STATE is in the environment if KEEP_STATE is on.
 */
	macro = get_prop(keep_state_name->prop, macro_prop);
	if ((macro != NULL) &&
	    macro->body.macro.exported) {
		keep_state = true;
	}
	if (keep_state) {
		if (macro == NULL) {
			macro = maybe_append_prop(keep_state_name,
						  macro_prop);
		}
		macro->body.macro.exported = true;
		(void) SETVAR(keep_state_name,
			      empty_name,
			      false);

		/*
		 *	Read state file
		 */

		/* Before we read state, let's make sure we have
		** right state file.
		*/
		/* just in case macro references are used in make_state file
		** name, we better expand them at this stage using expand_value.
		*/
		INIT_STRING_FROM_STACK(dest, destbuffer);
		expand_value(make_state, &dest, false);

		make_state = GETNAME(dest.buffer.start, FIND_LENGTH);

		if(!stat(make_state->string_mb, &make_state_stat)) {
		   if(!(make_state_stat.st_mode & S_IFREG) ) {
			/* copy the make_state structure to the other
			** and then let make_state point to the new
			** one.
			*/
		      memcpy(&state_filename, make_state,sizeof(state_filename));
		      state_filename.string_mb = state_file_str_mb;
		/* Just a kludge to avoid two slashes back to back */			
		      if((make_state->hash.length == 1)&&
			        (make_state->string_mb[0] == '/')) {
			 make_state->hash.length = 0;
			 make_state->string_mb[0] = '\0';
		      }
	   	      sprintf(state_file_str_mb,"%s%s",
		       make_state->string_mb,"/.make.state");
		      make_state = &state_filename;
			/* adjust the length to reflect the appended string */
		      make_state->hash.length += 12;
		   }
		} else { /* the file doesn't exist or no permission */
		   char tmp_path[MAXPATHLEN];
		   char *slashp;

		   if (slashp = strrchr(make_state->string_mb, '/')) {
		      strncpy(tmp_path, make_state->string_mb, 
				(slashp - make_state->string_mb));
			tmp_path[slashp - make_state->string_mb]=0;
		      if(strlen(tmp_path)) {
		        if(stat(tmp_path, &make_state_stat)) {
			  warning(gettext("directory %s for .KEEP_STATE_FILE does not exist"),tmp_path);
		        }
		        if (access(tmp_path, F_OK) != 0) {
			  warning(gettext("can't access dir %s"),tmp_path);
		        }
		      }
		   }
		}
		if (report_dependencies_level != 1) {
			Makefile_type	makefile_type_temp = makefile_type;
			makefile_type = reading_statefile;
			if (read_trace_level > 1) {
				trace_reader = true;
			}
			(void) read_simple_file(make_state,
						false,
						false,
						false,
						false,
						false,
						true);
			trace_reader = false;
			makefile_type = makefile_type_temp;
		}
	}
}

/*
 * Scan the argv for options and "=" type args and make them readonly.
 */
static void
enter_argv_values(int argc, char *argv[], ASCII_Dyn_Array *makeflags_and_macro)
{
	register char		*cp;
	register int		i;
	int			length;
	register Name		name;
	int			opt_separator = argc; 
	char			tmp_char;
	wchar_t			*tmp_wcs_buffer;
	register Name		value;
	Boolean			append = false;
	Property		macro;
	struct stat		statbuf;


	/* Read argv options and "=" type args and make them readonly. */
	makefile_type = reading_nothing;
	for (i = 1; i < argc; ++i) {
		append = false;
		if (argv[i] == NULL) {
			continue;
		} else if (((argv[i][0] == '-') && (argv[i][1] == '-')) ||
			   ((argv[i][0] == (int) ' ') &&
			    (argv[i][1] == (int) '-') &&
			    (argv[i][2] == (int) ' ') &&
			    (argv[i][3] == (int) '-'))) {
			argv[i] = NULL;
			opt_separator = i;
			continue;
		} else if ((i < opt_separator) && (argv[i][0] == (int) hyphen_char)) {
			switch (parse_command_option(argv[i][1])) {
			case 1:	/* -f seen */
				++i;
				continue;
			case 2:	/* -c seen */
				if (argv[i+1] == NULL) {
					fatal(gettext("No dmake rcfile argument after -c flag"));
				}
				MBSTOWCS(wcs_buffer, "DMAKE_RCFILE");
				name = GETNAME(wcs_buffer, FIND_LENGTH);
				break;
			case 4:	/* -g seen */
				if (argv[i+1] == NULL) {
					fatal(gettext("No dmake group argument after -g flag"));
				}
				MBSTOWCS(wcs_buffer, "DMAKE_GROUP");
				name = GETNAME(wcs_buffer, FIND_LENGTH);
				break;
			case 8:	/* -j seen */
				if (argv[i+1] == NULL) {
					fatal(gettext("No dmake max jobs argument after -j flag"));
				}
				MBSTOWCS(wcs_buffer, "DMAKE_MAX_JOBS");
				name = GETNAME(wcs_buffer, FIND_LENGTH);
				break;
			case 16: /* -M seen */
				if (argv[i+1] == NULL) {
					fatal(gettext("No pmake machinesfile argument after -M flag"));
				}
				MBSTOWCS(wcs_buffer, "PMAKE_MACHINESFILE");
				name = GETNAME(wcs_buffer, FIND_LENGTH);
				break;
			case 32: /* -m seen */
				if (argv[i+1] == NULL) {
					fatal(gettext("No dmake mode argument after -m flag"));
				}
				MBSTOWCS(wcs_buffer, "DMAKE_MODE");
				name = GETNAME(wcs_buffer, FIND_LENGTH);
				break;
			case 256: /* -K seen */
				if (argv[i+1] == NULL) {
					fatal(gettext("No makestate filename argument after -K flag"));
				}
				MBSTOWCS(wcs_buffer, argv[i+1]);
				make_state = GETNAME(wcs_buffer, FIND_LENGTH);
				keep_state = true;
				argv[i] = NULL;
				argv[i+1] = NULL;
				continue;
			case 512:	/* -o seen */
				if (argv[i+1] == NULL) {
					fatal(gettext("No dmake output dir argument after -o flag"));
				}
				MBSTOWCS(wcs_buffer, "DMAKE_ODIR");
				name = GETNAME(wcs_buffer, FIND_LENGTH);
				break;
			case 1024: /* -x seen */
				if (argv[i+1] == NULL) {
					fatal(gettext("No argument after -x flag"));
				}
				length = strlen( "SUN_MAKE_COMPAT_MODE=");
				if (strncmp(argv[i+1], "SUN_MAKE_COMPAT_MODE=", length) == 0) {
					argv[i+1] = &argv[i+1][length];
					MBSTOWCS(wcs_buffer, "SUN_MAKE_COMPAT_MODE");
					name = GETNAME(wcs_buffer, FIND_LENGTH);
					dmake_compat_mode_specified = dmake_add_mode_specified;
					break;
				}
				length = strlen( "DMAKE_OUTPUT_MODE=");
				if (strncmp(argv[i+1], "DMAKE_OUTPUT_MODE=", length) == 0) {
					argv[i+1] = &argv[i+1][length];
					MBSTOWCS(wcs_buffer, "DMAKE_OUTPUT_MODE");
					name = GETNAME(wcs_buffer, FIND_LENGTH);
					dmake_output_mode_specified = dmake_add_mode_specified;
				} else {
					warning(gettext("Unknown argument `%s' after -x flag (ignored)"),
					      argv[i+1]);
					argv[i] = argv[i + 1] = NULL;
					continue;
				}
				break;
			default: /* Shouldn't reach here */
				argv[i] = NULL;
				continue;
			}
			argv[i] = NULL;
			if (i == (argc - 1)) {
				break;
			}
			if ((length = strlen(argv[i+1])) >= MAXPATHLEN) {
				tmp_wcs_buffer = ALLOC_WC(length + 1);
				(void) mbstowcs(tmp_wcs_buffer, argv[i+1], length + 1);
				value = GETNAME(tmp_wcs_buffer, FIND_LENGTH);
				retmem(tmp_wcs_buffer);
			} else {
				MBSTOWCS(wcs_buffer, argv[i+1]);
				value = GETNAME(wcs_buffer, FIND_LENGTH);
			}
			argv[i+1] = NULL;
		} else if ((cp = strchr(argv[i], (int) equal_char)) != NULL) {
/* 
 * Combine all macro in dynamic array
 */
			if(*(cp-1) == (int) plus_char)
			{
				if(isspace(*(cp-2))) {
					append = true;
					cp--;
				}
			}
			if(!append)
				append_or_replace_macro_in_dyn_array(makeflags_and_macro, argv[i]);

			while (isspace(*(cp-1))) {
				cp--;
			}
			tmp_char = *cp;
			*cp = (int) nul_char;
			MBSTOWCS(wcs_buffer, argv[i]);
			*cp = tmp_char;
			name = GETNAME(wcs_buffer, wcslen(wcs_buffer));
			while (*cp != (int) equal_char) {
				cp++;
			}
			cp++;
			while (isspace(*cp) && (*cp != (int) nul_char)) {
				cp++;
			}
			if ((length = strlen(cp)) >= MAXPATHLEN) {
				tmp_wcs_buffer = ALLOC_WC(length + 1);
				(void) mbstowcs(tmp_wcs_buffer, cp, length + 1);
				value = GETNAME(tmp_wcs_buffer, FIND_LENGTH);
				retmem(tmp_wcs_buffer);
			} else {
				MBSTOWCS(wcs_buffer, cp);
				value = GETNAME(wcs_buffer, FIND_LENGTH);
			}
			argv[i] = NULL;
		} else {
			/* Illegal MAKEFLAGS argument */
			continue;
		}
		if(append) {
			setvar_append(name, value);
			append = false;
		} else {
			macro = maybe_append_prop(name, macro_prop);
			macro->body.macro.exported = true;
			SETVAR(name, value, false)->body.macro.read_only = true;
		}
	}
}

/*
 * Append the DMake option and value to the MAKEFLAGS string.
 */
static void
append_makeflags_string(Name name, register String makeflags_string)
{
	const char	*option;

	if (strcmp(name->string_mb, "DMAKE_GROUP") == 0) {
		option = " -g ";
	} else if (strcmp(name->string_mb, "DMAKE_MAX_JOBS") == 0) {
		option = " -j ";
	} else if (strcmp(name->string_mb, "DMAKE_MODE") == 0) {
		option = " -m ";
	} else if (strcmp(name->string_mb, "DMAKE_ODIR") == 0) {
		option = " -o ";
	} else if (strcmp(name->string_mb, "DMAKE_RCFILE") == 0) {
		option = " -c ";
	} else if (strcmp(name->string_mb, "PMAKE_MACHINESFILE") == 0) {
		option = " -M ";
	} else if (strcmp(name->string_mb, "DMAKE_OUTPUT_MODE") == 0) {
		option = " -x DMAKE_OUTPUT_MODE=";
	} else if (strcmp(name->string_mb, "SUN_MAKE_COMPAT_MODE") == 0) {
		option = " -x SUN_MAKE_COMPAT_MODE=";
	} else {
		fatal(gettext("Internal error: name not recognized in append_makeflags_string()"));
	}
	Property prop = maybe_append_prop(name, macro_prop);
	if( prop == 0 || prop->body.macro.value == 0 ||
	    prop->body.macro.value->string_mb == 0 ) {
		return;
	}
	char mbs_value[MAXPATHLEN + 100];
	strcpy(mbs_value, option);
	strcat(mbs_value, prop->body.macro.value->string_mb);
	MBSTOWCS(wcs_buffer, mbs_value);
	append_string(wcs_buffer, makeflags_string, FIND_LENGTH);
}

/*
 *	read_environment(read_only)
 *
 *	This routine reads the process environment when make starts and enters
 *	it as make macros. The environment variable SHELL is ignored.
 *
 *	Parameters:
 *		read_only	Should we make env vars read only?
 *
 *	Global variables used:
 *		report_pwd	Set if this make was started by other make
 */
static void
read_environment(Boolean read_only)
{
	register char		**environment;
	int			length;
	wchar_t			*tmp_wcs_buffer;
	Boolean			alloced_tmp_wcs_buffer = false;
	register wchar_t	*name;
	register wchar_t	*value;
	register Name		macro;
	Property		val;
	Boolean			read_only_saved;

	reading_environment = true;
	environment = environ;
	for (; *environment; environment++) {
		read_only_saved = read_only;
		if ((length = strlen(*environment)) >= MAXPATHLEN) {
			tmp_wcs_buffer = ALLOC_WC(length + 1);
			alloced_tmp_wcs_buffer = true;
			(void) mbstowcs(tmp_wcs_buffer, *environment, length + 1);
			name = tmp_wcs_buffer;
		} else {
			MBSTOWCS(wcs_buffer, *environment);
			name = wcs_buffer;
		}
		value = (wchar_t *) wcschr(name, (int) equal_char);

		/*
		 * Looks like there's a bug in the system, but sometimes
		 * you can get blank lines in *environment.
		 */
		if (!value) {
			continue;
		}
		MBSTOWCS(wcs_buffer2, "SHELL=");
		if (IS_WEQUALN(name, wcs_buffer2, wcslen(wcs_buffer2))) {
			continue;
		}
		MBSTOWCS(wcs_buffer2, "MAKEFLAGS=");
		if (IS_WEQUALN(name, wcs_buffer2, wcslen(wcs_buffer2))) {
			report_pwd = true;
			/*
			 * In POSIX mode we do not want MAKEFLAGS to be readonly.
			 * If the MAKEFLAGS macro is subsequently set by the makefile,
			 * it replaces the MAKEFLAGS variable currently found in the
			 * environment.
			 * See Assertion 50 in section 6.2.5.3 of standard P1003.3.2/D8.
			 */
			if(posix) {
				read_only_saved = false;
			}
		}

		/*
		 * We ignore SUNPRO_DEPENDENCIES. This environment variable is
		 * set by make and read by cpp which then writes info to
		 * .make.dependency.xxx.  When make is invoked by another make
		 * (recursive make), we don't want to read this because then
		 * the child make will end up writing to the parent
		 * directory's .make.state and clobbering them.
		 */
		MBSTOWCS(wcs_buffer2, "SUNPRO_DEPENDENCIES");
		if (IS_WEQUALN(name, wcs_buffer2, wcslen(wcs_buffer2))) {
			continue;
		}

		macro = GETNAME(name, value - name);
		maybe_append_prop(macro, macro_prop)->body.macro.exported =
		  true;
		if ((value == NULL) || ((value + 1)[0] == (int) nul_char)) {
			val = setvar_daemon(macro,
					    (Name) NULL,
					    false, no_daemon, false, debug_level);
		} else {
			val = setvar_daemon(macro,
					    GETNAME(value + 1, FIND_LENGTH),
					    false, no_daemon, false, debug_level);
		}
		val->body.macro.read_only = read_only_saved;
		if (alloced_tmp_wcs_buffer) {
			retmem(tmp_wcs_buffer);
			alloced_tmp_wcs_buffer = false;
		}
	}
	reading_environment = false;
}

/*
 *	read_makefile(makefile, complain, must_exist, report_file)
 *
 *	Read one makefile and check the result
 *
 *	Return value:
 *				false is the read failed
 *
 *	Parameters:
 *		makefile	The file to read
 *		complain	Passed thru to read_simple_file()
 *		must_exist	Passed thru to read_simple_file()
 *		report_file	Passed thru to read_simple_file()
 *
 *	Global variables used:
 *		makefile_type	Set to indicate we are reading main file
 *		recursion_level	Initialized
 */
static Boolean
read_makefile(register Name makefile, Boolean complain, Boolean must_exist, Boolean report_file)
{
	Boolean			b;
	
	makefile_type = reading_makefile;
	recursion_level = 0;
	reading_dependencies = true;
	b = read_simple_file(makefile, true, true, complain,
			     must_exist, report_file, false);
	reading_dependencies = false;
	return b;
}

/*
 *	make_targets(argc, argv, parallel_flag)
 *
 *	Call doname on the specified targets
 *
 *	Parameters:
 *		argc		You know what this is
 *		argv		You know what this is
 *		parallel_flag	True if building in parallel
 *
 *	Global variables used:
 *		build_failed_seen Used to generated message after failed -k
 *		commands_done	Used to generate message "Up to date"
 *		default_target_to_build	First proper target in makefile
 *		init		The Name ".INIT", use to run command
 *		parallel	Global parallel building flag
 *		quest		make -q, suppresses messages
 *		recursion_level	Initialized, used for tracing
 *		report_dependencies make -P, regroves whole process
 */
static void
make_targets(int argc, char **argv, Boolean parallel_flag)
{
	int			i;
	char			*cp;
	Doname			result;
	register Boolean	target_to_make_found = false;

	(void) doname(init, true, true);
	recursion_level = 1;
	parallel = parallel_flag;
/*
 *	make remaining args
 */
/*
	if ((report_dependencies_level == 0) && parallel) {
 */
	if (parallel) {
		/*
		 * If building targets in parallel, start all of the
		 * remaining args to build in parallel.
		 */
		for (i = 1; i < argc; i++) {
			if ((cp = argv[i]) != NULL) {
				commands_done = false;
				if ((cp[0] == (int) period_char) &&
				    (cp[1] == (int) slash_char)) {
					cp += 2;
				}
				 if((cp[0] == (int) ' ') &&
				    (cp[1] == (int) '-') &&
				    (cp[2] == (int) ' ') &&
				    (cp[3] == (int) '-')) {
			            argv[i] = NULL;
					continue;
				}
				MBSTOWCS(wcs_buffer, cp);
				//default_target_to_build = GETNAME(wcs_buffer,
				//				  FIND_LENGTH);
				default_target_to_build = normalize_name(wcs_buffer,
								  wcslen(wcs_buffer));
				if (default_target_to_build == wait_name) {
					if (parallel_process_cnt > 0) {
						finish_running();
					}
					continue;
				}
				top_level_target = get_wstring(default_target_to_build->string_mb);
				/*
				 * If we can't execute the current target in
				 * parallel, hold off the target processing
				 * to preserve the order of the targets as they appeared
				 * in command line.
				 */
				if (!parallel_ok(default_target_to_build, false)
						&& parallel_process_cnt > 0) {
					finish_running();
				}
				result = doname_check(default_target_to_build,
						      true,
						      false,
						      false);
				gather_recursive_deps();
				if (/* !commands_done && */
				    (result == build_ok) &&
				    !quest &&
				    (report_dependencies_level == 0) /*  &&
				    (exists(default_target_to_build) > file_doesnt_exist)  */) {
					if (posix) {
						if (!commands_done) {
							(void) printf(gettext("`%s' is updated.\n"),
						 		      default_target_to_build->string_mb);
						} else {
							if (no_action_was_taken) {
								(void) printf(gettext("`%s': no action was taken.\n"),
						 			      default_target_to_build->string_mb);
							}
						}
					} else {
						default_target_to_build->stat.time = file_no_time;
						if (!commands_done &&
						    (exists(default_target_to_build) > file_doesnt_exist)) {
							(void) printf(gettext("`%s' is up to date.\n"),
								      default_target_to_build->string_mb);
						}
					}
				}
			}
		}
		/* Now wait for all of the targets to finish running */
		finish_running();
		//		setjmp(jmpbuffer);
		
	}
	for (i = 1; i < argc; i++) {
		if ((cp = argv[i]) != NULL) {
			target_to_make_found = true;
			if ((cp[0] == (int) period_char) &&
			    (cp[1] == (int) slash_char)) {
				cp += 2;
			}
				 if((cp[0] == (int) ' ') &&
				    (cp[1] == (int) '-') &&
				    (cp[2] == (int) ' ') &&
				    (cp[3] == (int) '-')) {
			            argv[i] = NULL;
					continue;
				}
			MBSTOWCS(wcs_buffer, cp);
			default_target_to_build = normalize_name(wcs_buffer, wcslen(wcs_buffer));
			top_level_target = get_wstring(default_target_to_build->string_mb);
			report_recursion(default_target_to_build);
			commands_done = false;
			if (parallel) {
				result = (Doname) default_target_to_build->state;
			} else {
				result = doname_check(default_target_to_build,
						      true,
						      false,
						      false);
			}
			gather_recursive_deps();
			if (build_failed_seen) {
				build_failed_ever_seen = true;
				warning(gettext("Target `%s' not remade because of errors"),
					default_target_to_build->string_mb);
			}
			build_failed_seen = false;
			if (report_dependencies_level > 0) {
				print_dependencies(default_target_to_build,
						   get_prop(default_target_to_build->prop,
							    line_prop));
			}
			default_target_to_build->stat.time =
			  file_no_time;
			if (default_target_to_build->colon_splits > 0) {
				default_target_to_build->state =
				  build_dont_know;
			}
			if (!parallel &&
			    /* !commands_done && */
			    (result == build_ok) &&
			    !quest &&
			    (report_dependencies_level == 0) /*  &&
			    (exists(default_target_to_build) > file_doesnt_exist)  */) {
				if (posix) {
					if (!commands_done) {
						(void) printf(gettext("`%s' is updated.\n"),
					 		      default_target_to_build->string_mb);
					} else {
						if (no_action_was_taken) {
							(void) printf(gettext("`%s': no action was taken.\n"),
					 			      default_target_to_build->string_mb);
						}
					}
				} else {
					if (!commands_done &&
					    (exists(default_target_to_build) > file_doesnt_exist)) {
						(void) printf(gettext("`%s' is up to date.\n"),
							      default_target_to_build->string_mb);
					}
				}
			}
		}
	}

/*
 *	If no file arguments have been encountered,
 *	make the first name encountered that doesnt start with a dot
 */
	if (!target_to_make_found) {
		if (default_target_to_build == NULL) {
			fatal(gettext("No arguments to build"));
		}
		commands_done = false;
		top_level_target = get_wstring(default_target_to_build->string_mb);
		report_recursion(default_target_to_build);


		if (getenv("SPRO_EXPAND_ERRORS")){
			(void) printf("::(%s)\n",
				      default_target_to_build->string_mb);
		}


		result = doname_parallel(default_target_to_build, true, false);
		gather_recursive_deps();
		if (build_failed_seen) {
			build_failed_ever_seen = true;
			warning(gettext("Target `%s' not remade because of errors"),
				default_target_to_build->string_mb);
		}
		build_failed_seen = false;
		if (report_dependencies_level > 0) {
			print_dependencies(default_target_to_build,
					   get_prop(default_target_to_build->
						    prop,
						    line_prop));
		}
		default_target_to_build->stat.time = file_no_time;
		if (default_target_to_build->colon_splits > 0) {
			default_target_to_build->state = build_dont_know;
		}
		if (/* !commands_done && */
		    (result == build_ok) &&
		    !quest &&
		    (report_dependencies_level == 0) /*  &&
		    (exists(default_target_to_build) > file_doesnt_exist)  */) {
			if (posix) {
				if (!commands_done) {
					(void) printf(gettext("`%s' is updated.\n"),
				 		      default_target_to_build->string_mb);
				} else {
					if (no_action_was_taken) {
						(void) printf(gettext("`%s': no action was taken.\n"),
							      default_target_to_build->string_mb);
					}
				}
			} else {
				if (!commands_done &&
				    (exists(default_target_to_build) > file_doesnt_exist)) {
					(void) printf(gettext("`%s' is up to date.\n"),
						      default_target_to_build->string_mb);
				}
			}
		}
	}
}

/*
 *	report_recursion(target)
 *
 *	If this is a recursive make and the parent make has KEEP_STATE on
 *	this routine reports the dependency to the parent make
 *
 *	Parameters:
 *		target		Target to report
 *
 *	Global variables used:
 *		makefiles_used		List of makefiles read
 *		recursive_name		The Name ".RECURSIVE", printed
 *		report_dependency	dwight
 */
static void
report_recursion(register Name target)
{
	register FILE		*report_file = get_report_file();

	if ((report_file == NULL) || (report_file == (FILE*)-1)) {
		return;
	}
	if (primary_makefile == NULL) {
		/*
		 * This can happen when there is no makefile and
		 * only implicit rules are being used.
		 */
		return;
	}
	(void) fprintf(report_file,
		       "%s: %s ",
		       get_target_being_reported_for(),
		       recursive_name->string_mb);
	report_dependency(get_current_path());
	report_dependency(target->string_mb);
	report_dependency(primary_makefile->string_mb);
	(void) fprintf(report_file, "\n");
}

/* Next function "append_or_replace_macro_in_dyn_array" must be in "misc.cc". */
/* NIKMOL */
extern void
append_or_replace_macro_in_dyn_array(ASCII_Dyn_Array *Ar, char *macro)
{
	register char	*cp0;	/* work pointer in macro */
	register char	*cp1;	/* work pointer in array */
	register char	*cp2;	/* work pointer in array */
	register char	*cp3;	/* work pointer in array */
	register char	*name;	/* macro name */
	register char	*value;	/* macro value */
	register int 	len_array;
	register int 	len_macro;

	char * esc_value = NULL;
	int esc_len;

	if (!(len_macro = strlen(macro))) return;
	name = macro;
	while (isspace(*(name))) {
		name++;
	}
	if (!(value = strchr(name, (int) equal_char))) {
		/* no '=' in macro */
		goto ERROR_MACRO;
	}
	cp0 = value;
	value++;
	while (isspace(*(value))) {
		value++;
	}
	while (isspace(*(cp0-1))) {
		cp0--;
	}
	if (cp0 <= name) goto ERROR_MACRO; /* no name */
	if (!(Ar->size)) goto ALLOC_ARRAY;
	cp1 = Ar->start;

LOOK_FOR_NAME:
	if (!(cp1 = strchr(cp1, name[0]))) goto APPEND_MACRO;
	if (!(cp2 = strchr(cp1, (int) equal_char))) goto APPEND_MACRO;
	if (strncmp(cp1, name, (size_t)(cp0-name))) {
		/* another name */
		cp1++;
		goto LOOK_FOR_NAME;
	}
	if (cp1 != Ar->start) {
		if (!isspace(*(cp1-1))) {
			/* another name */
			cp1++;
			goto LOOK_FOR_NAME;
		}
	}
	for (cp3 = cp1 + (cp0-name); cp3 < cp2; cp3++) {
		if (isspace(*cp3)) continue;
		/* else: another name */
		cp1++;
		goto LOOK_FOR_NAME;
	}
	/* Look for the next macro name in array */
	cp3 = cp2+1;
	if (*cp3 != (int) doublequote_char) {
		/* internal error */
		goto ERROR_MACRO;
	}
	if (!(cp3 = strchr(cp3+1, (int) doublequote_char))) {
		/* internal error */
		goto ERROR_MACRO;
	}
	cp3++;
	while (isspace(*cp3)) {
		cp3++;
	}
	
	cp2 = cp1;  /* remove old macro */
	if ((*cp3) && (cp3 < Ar->start + Ar->size)) {
		for (; cp3 < Ar->start + Ar->size; cp3++) {
			*cp2++ = *cp3;
		}
	} 
	for (; cp2 < Ar->start + Ar->size; cp2++) {
		*cp2 = 0;
	}
	if (*cp1) {
		/* check next name */
		goto LOOK_FOR_NAME;
	}
	goto APPEND_MACRO;

ALLOC_ARRAY:
	if (Ar->size) {
		cp1 = Ar->start;
	} else {
		cp1 = 0;
	}
	Ar->size += 128;
	Ar->start = getmem(Ar->size);
	for (len_array=0; len_array < Ar->size; len_array++) {
		Ar->start[len_array] = 0;
	}
	if (cp1) {
		strcpy(Ar->start, cp1);
		retmem((wchar_t *) cp1);
	}

APPEND_MACRO:
	len_array = strlen(Ar->start);
	esc_value = (char*)malloc(strlen(value)*2 + 1);
	quote_str(value, esc_value);
	esc_len = strlen(esc_value) - strlen(value);
	if (len_array + len_macro + esc_len + 5 >= Ar->size) goto  ALLOC_ARRAY;
	strcat(Ar->start, " ");
	strncat(Ar->start, name, cp0-name);
	strcat(Ar->start, "=");
	strncat(Ar->start, esc_value, strlen(esc_value));
	free(esc_value);
	return;
ERROR_MACRO:	
	/* Macro without '=' or with invalid left/right part */
	return;
}

static void
report_dir_enter_leave(Boolean entering)
{
	char	rcwd[MAXPATHLEN];
static	char *	mlev = NULL;
	char *	make_level_str = NULL;
	int	make_level_val = 0;

	make_level_str = getenv("MAKELEVEL");
	if(make_level_str) {
		make_level_val = atoi(make_level_str);
	}
	if(mlev == NULL) {
		mlev = (char*) malloc(MAXPATHLEN);
	}
	if(entering) {
		sprintf(mlev, "MAKELEVEL=%d", make_level_val + 1);
	} else {
		make_level_val--;
		sprintf(mlev, "MAKELEVEL=%d", make_level_val);
	}
	putenv(mlev);

	if(report_cwd) {
		if(make_level_val <= 0) {
			if(entering) {
				sprintf(rcwd,
				    gettext("%s: Entering directory `%s'\n"),
				    getprogname(),
				    get_current_path());
			} else {
				sprintf(rcwd,
				    gettext("%s: Leaving directory `%s'\n"),
				    getprogname(),
				    get_current_path());
			}
		} else {
			if(entering) {
				sprintf(rcwd,
				    gettext("%s[%d]: Entering directory `%s'\n"),
				    getprogname(),
				    make_level_val, get_current_path());
			} else {
				sprintf(rcwd,
				    gettext("%s[%d]: Leaving directory `%s'\n"),
				    getprogname(),
				    make_level_val, get_current_path());
			}
		}
		printf("%s", rcwd);
	}
}
