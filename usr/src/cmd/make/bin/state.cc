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
 *	state.c
 *
 *	This file contains the routines that write the .make.state file
 */

/*
 * Included files
 */
#include <mk/defs.h>
#include <mksh/misc.h>		/* errmsg() */
#include <setjmp.h>		/* setjmp() */
#include <unistd.h>		/* getpid() */
#include <errno.h>		/* errno    */
#include <locale.h>		/* MB_CUR_MAX    */

/*
 * Defined macros
 */
#define LONGJUMP_VALUE 17
#define XFWRITE(string, length, fd) {if (fwrite(string, 1, length, fd) == 0) \
					longjmp(long_jump, LONGJUMP_VALUE);}
#define XPUTC(ch, fd) { \
	if (putc((int) ch, fd) == EOF) \
		longjmp(long_jump, LONGJUMP_VALUE); \
	}
#define XFPUTS(string, fd) fputs(string, fd)

/*
 * typedefs & structs
 */

/*
 * Static variables
 */

/*
 * File table of contents
 */
static char * escape_target_name(Name np)
{
	if(np->dollar) {
		int len = strlen(np->string_mb);
		char * buff = (char*)malloc(2 * len);
		int pos = 0;
		wchar_t wc;
		int pp = 0;
		while(pos < len) {
			int n = mbtowc(&wc, np->string_mb + pos, MB_CUR_MAX);
			if(n < 0) { // error - this shouldn't happen
				(void)free(buff);
				return strdup(np->string_mb);
			}
			if(wc == dollar_char) {
				buff[pp] = '\\'; pp++;
				buff[pp] = '$'; pp++;
			} else {
				for(int j=0;j<n;j++) {
					buff[pp] = np->string_mb[pos+j]; pp++;
				}
			}
			pos += n;
		}
		buff[pp] = '\0';
		return buff;
	} else {
		return strdup(np->string_mb);
	}
}

static	void		print_auto_depes(register Dependency dependency, register FILE *fd, register Boolean built_this_run, register int *line_length, register char *target_name, jmp_buf long_jump);

/*
 *	write_state_file(report_recursive, exiting)
 *
 *	Write a new version of .make.state
 *
 *	Parameters:
 *		report_recursive	Should only be done at end of run
 *		exiting			true if called from the exit handler
 *
 *	Global variables used:
 *		built_last_make_run The Name ".BUILT_LAST_MAKE_RUN", written
 *		command_changed	If no command changed we do not need to write
 *		current_make_version The Name "<current version>", written
 *		do_not_exec_rule If -n is on we do not write statefile
 *		hashtab		The hashtable that contains all names
 *		keep_state	If .KEEP_STATE is no on we do not write file
 *		make_state	The Name ".make.state", used for opening file
 *		make_version	The Name ".MAKE_VERSION", written
 *		recursive_name	The Name ".RECURSIVE", written
 *		rewrite_statefile Indicates that something changed
 */

void
write_state_file(int, Boolean exiting)
{
	register FILE		*fd;
	int			lock_err;
	char			buffer[MAXPATHLEN];
	char			make_state_tempfile[MAXPATHLEN];
	jmp_buf			long_jump;
	register int		attempts = 0;
	Name_set::iterator	np, e;
	register Property	lines;
	register int		m;
	Dependency		dependency;
	register Boolean	name_printed;
	Boolean			built_this_run = false;
	char			*target_name;
	int			line_length;
	register Cmd_line	cp;


	if (!rewrite_statefile ||
	    !command_changed ||
	    !keep_state ||
	    do_not_exec_rule ||
	    (report_dependencies_level > 0)) {
		return;
	}
	/* Lock the file for writing. */
 	make_state_lockfile = getmem(strlen(make_state->string_mb) + strlen(".lock") + 1);
 	(void) sprintf(make_state_lockfile,
 	               "%s.lock",
 	               make_state->string_mb);
	if (lock_err = file_lock(make_state->string_mb, 
				 make_state_lockfile, 
				 (int *) &make_state_locked, 0)) {
 		retmem_mb(make_state_lockfile);
		make_state_lockfile = NULL;
		
		/*
		 * We need to make sure that we are not being
		 * called by the exit handler so we don't call
		 * it again.
		 */
		
		if (exiting) {
			(void) sprintf(buffer, "%s/.make.state.%d.XXXXXX", tmpdir, getpid());
			report_pwd = true;
			warning(gettext("Writing to %s"), buffer);
			int fdes = mkstemp(buffer);
			if ((fdes < 0) || (fd = fdopen(fdes, "w")) == NULL) {
				fprintf(stderr,
					gettext("Could not open statefile `%s': %s"),
					buffer,
					errmsg(errno));
				return;
			}
		} else {
			report_pwd = true;
			fatal(gettext("Can't lock .make.state"));
		}
	}

	(void) sprintf(make_state_tempfile,
	               "%s.tmp",
	               make_state->string_mb);
	/* Delete old temporary statefile (in case it exists) */
	(void) unlink(make_state_tempfile);
	if ((fd = fopen(make_state_tempfile, "w")) == NULL) {
		lock_err = errno; /* Save it! unlink() can change errno */
		(void) unlink(make_state_lockfile);
 		retmem_mb(make_state_lockfile);
		make_state_lockfile = NULL;
		make_state_locked = false;
		fatal(gettext("Could not open temporary statefile `%s': %s"),
		      make_state_tempfile,
		      errmsg(lock_err));
	}
	/*
	 * Set a trap for failed writes. If a write fails, the routine
	 * will try saving the .make.state file under another name in /tmp.
	 */
	if (setjmp(long_jump)) {
		(void) fclose(fd);
		if (attempts++ > 5) {
			if ((make_state_lockfile != NULL) &&
			    make_state_locked) {
				(void) unlink(make_state_lockfile);
 				retmem_mb(make_state_lockfile);
				make_state_lockfile = NULL;
				make_state_locked = false;
			}
			fatal(gettext("Giving up on writing statefile"));
		}
		sleep(10);
		(void) sprintf(buffer, "%s/.make.state.%d.XXXXXX", tmpdir, getpid());
		int fdes = mkstemp(buffer);
		if ((fdes < 0) || (fd = fdopen(fdes, "w")) == NULL) {
			fatal(gettext("Could not open statefile `%s': %s"),
			      buffer,
			      errmsg(errno));
		}
		warning(gettext("Initial write of statefile failed. Trying again on %s"),
			buffer);
	}

	/* Write the version stamp. */
	XFWRITE(make_version->string_mb,
		strlen(make_version->string_mb),
		fd);
	XPUTC(colon_char, fd);
	XPUTC(tab_char, fd);
	XFWRITE(current_make_version->string_mb,
		strlen(current_make_version->string_mb),
		fd);
	XPUTC(newline_char, fd);

	/*
	 * Go through all the targets, dump their dependencies and
	 * command used.
	 */
	for (np = hashtab.begin(), e = hashtab.end(); np != e; np++) {
		/*
		 * If the target has no command used nor dependencies,
		 * we can go to the next one.
		 */
		if ((lines = get_prop(np->prop, line_prop)) == NULL) {
			continue;
		}
		/* If this target is a special target, don't print. */
		if (np->special_reader != no_special) {
			continue;
		}
		/*
		 * Find out if any of the targets dependencies should
		 * be written to .make.state.
		 */
		for (m = 0, dependency = lines->body.line.dependencies;
		     dependency != NULL;
		     dependency = dependency->next) {
			if (m = !dependency->stale
			    && (dependency->name != force)
#ifndef PRINT_EXPLICIT_DEPEN
			    && dependency->automatic
#endif
			    ) {
				break;
			}
		}
		/* Only print if dependencies listed. */
		if (m || (lines->body.line.command_used != NULL)) {
			name_printed = false;
			/*
			 * If this target was built during this make run,
			 * we mark it.
			 */
			built_this_run = false;
			if (np->has_built) {
				built_this_run = true;
				XFWRITE(built_last_make_run->string_mb,
					strlen(built_last_make_run->string_mb),
					fd);
				XPUTC(colon_char, fd);
				XPUTC(newline_char, fd);
			}
			/* If the target has dependencies, we dump them. */
			target_name = escape_target_name(np);
			if (np->has_long_member_name) {
				target_name =
				  get_prop(np->prop, long_member_name_prop)
				    ->body.long_member_name.member_name->
				      string_mb;
			}
			if (m) {
				XFPUTS(target_name, fd);
				XPUTC(colon_char, fd);
				XFPUTS("\t", fd);
				name_printed = true;
				line_length = 0;
				for (dependency =
				     lines->body.line.dependencies;
				     dependency != NULL;
				     dependency = dependency->next) {
					print_auto_depes(dependency,
							 fd,
							 built_this_run,
							 &line_length,
							 target_name,
							 long_jump);
				}
				XFPUTS("\n", fd);
			}
			/* If there is a command used, we dump it. */
			if (lines->body.line.command_used != NULL) {
				/*
				 * Only write the target name if it
				 * wasn't done for the dependencies.
				 */
				if (!name_printed) {
					XFPUTS(target_name, fd);
					XPUTC(colon_char, fd);
					XPUTC(newline_char, fd);
				}
				/*
				 * Write the command lines.
				 * Prefix each textual line with a tab.
				 */
				for (cp = lines->body.line.command_used;
				     cp != NULL;
				     cp = cp->next) {
					char		*csp;
					int		n;

					XPUTC(tab_char, fd);
					if (cp->command_line != NULL) {
						for (csp = cp->
						           command_line->
						           string_mb,
						     n = strlen(cp->
						                command_line->
						                string_mb);
						     n > 0;
						     n--, csp++) {
							XPUTC(*csp, fd);
							if (*csp ==
							    (int) newline_char) {
								XPUTC(tab_char,
								      fd);
							}
						}
					}
					XPUTC(newline_char, fd);
				}
			}
			(void)free(target_name);
		}
	}
	if (fclose(fd) == EOF) {
		longjmp(long_jump, LONGJUMP_VALUE);
	}
	if (attempts == 0) {
		if (unlink(make_state->string_mb) != 0 && errno != ENOENT) {
			lock_err = errno; /* Save it! unlink() can change errno */
			/* Delete temporary statefile */
			(void) unlink(make_state_tempfile);
			(void) unlink(make_state_lockfile);
	 		retmem_mb(make_state_lockfile);
			make_state_lockfile = NULL;
			make_state_locked = false;
			fatal(gettext("Could not delete old statefile `%s': %s"),
			      make_state->string_mb,
			      errmsg(lock_err));
		}
		if (rename(make_state_tempfile, make_state->string_mb) != 0) {
			lock_err = errno; /* Save it! unlink() can change errno */
			/* Delete temporary statefile */
			(void) unlink(make_state_tempfile);
			(void) unlink(make_state_lockfile);
	 		retmem_mb(make_state_lockfile);
			make_state_lockfile = NULL;
			make_state_locked = false;
			fatal(gettext("Could not rename `%s' to `%s': %s"),
			      make_state_tempfile,
			      make_state->string_mb,
			      errmsg(lock_err));
		}
	}
	if ((make_state_lockfile != NULL) && make_state_locked) {
		(void) unlink(make_state_lockfile);
 		retmem_mb(make_state_lockfile);
		make_state_lockfile = NULL;
		make_state_locked = false;
	}
}

/*
 *	print_auto_depes(dependency, fd, built_this_run,
 *			 line_length, target_name, long_jump)
 *
 *	Will print a dependency list for automatic entries.
 *
 *	Parameters:
 *		dependency	The dependency to print
 *		fd		The file to print it to
 *		built_this_run	If on we prefix each line with .BUILT_THIS...
 *		line_length	Pointer to line length var that we update
 *		target_name	We need this when we restart line
 *		long_jump	setjmp/longjmp buffer used for IO error action
 *
 *	Global variables used:
 *		built_last_make_run The Name ".BUILT_LAST_MAKE_RUN", written
 *		force		The Name " FORCE", compared against
 */
static void
print_auto_depes(register Dependency dependency, register FILE *fd, register Boolean built_this_run, register int *line_length, register char *target_name, jmp_buf long_jump)
{
	if (!dependency->automatic ||
	    dependency->stale ||
	    (dependency->name == force)) {
		return;
	}
	XFWRITE(dependency->name->string_mb, 
		strlen(dependency->name->string_mb),
		fd);
	/*
	 * Check if the dependency line is too long.
	 * If so, break it and start a new one.
	 */
	if ((*line_length += (int) strlen(dependency->name->string_mb) + 1) > 450) {
		*line_length = 0;
		XPUTC(newline_char, fd);
		if (built_this_run) {
			XFPUTS(built_last_make_run->string_mb, fd);
			XPUTC(colon_char, fd);
			XPUTC(newline_char, fd);
		}
		XFPUTS(target_name, fd);
		XPUTC(colon_char, fd);
		XPUTC(tab_char, fd);
	} else {
		XFPUTS(" ", fd);
	}
	return;
}


