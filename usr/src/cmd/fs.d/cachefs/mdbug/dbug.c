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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 *
 *			dbug.c
 *
 * Purpose:
 *    Implements the dbug_routine class.
 *    This code is derived from the public domain DBUG
 *    package written by Fred Fish.
 *
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef DBUG_OFF

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <thread.h>
#include <sys/types.h>
#include <signal.h>
#include "flist.h"
#include "mdbug.h"
#include "priv.h"

/* forward references */
static int listparse(register char *ctlp, flist_object_t *head);
static boolean inlist(flist_object_t *flist_object_p, const char *cp);
static boolean dotrace(dbug_state_object_t *dbug_state_object_p,
    const char *func, const char *process);
static void indent(register dbug_state_object_t *dbug_state_object_p,
    int indent);
static void doprefix(dbug_state_object_t *dbug_state_object_p, int line,
    long lineno, const char *file, const char *process);
static FILE *openfile(char *name);
static boolean writable(char *pathname);
static void changeowner(char *pathname);
static int delayarg(int value);
static void delay(uint_t xx);
static ulong_t getclock();
static char *mystrtok(char *s1, char *s2);
void doabort();

/* initialize static members of class */
int	sd_on = 0;
char	sd_process[128];
long	sd_lineno = 0;
dbug_state_object_t *sd_push = NULL;

/* this structure defines thread specific data */
typedef struct thread_data {
#ifdef STACKINIT
	unsigned long	 td_stackinit;		/* Begining of stack. */
#endif
	int		 td_line;		/* Current line number. */
	char		 td_keyword[64];	/* Current keyword. */
	dbug_object_t	*td_first;		/* Current routine. */
} thread_data_t;
#ifdef _REENTRANT
mutex_t		mdt_lock;
int		mdt_once = 0;
thread_key_t	mdt_key;
#else
thread_data_t	mdt_data;
#endif
/*
 * format of control string
 *   command[:command:...]
 *
 *   commands
 *   debugging on	'd'  d[,<keyword>[,...]]
 *   delay value	'D'  D[,<delay value>]
 *   function list	'f'  f[,<function name>[,...]]
 *   print filename	'F'  F
 *   print pid		'i'  i
 *   print line number	'L'  L
 *   print call depth	'n'  n
 *   number each line	'N'  N
 *   output file	'o'  o[,<filename>
 *   process name list	'p'  p[,<process name>[,...]]
 *   print proc name	'P'  P
 *   reset indentation	'r'  r
 *   print runtime	'R'  R
 *   print thread info	'T'  T
 *   print trace	't'  t
 *   print stack depth	's'  s
 */

/*
 *
 *		dbug_object_create
 *
 * Description:
 *	Constructor for the dbug_routine class.
 * Arguments:
 *	line	- line number where object was created.
 *	file	- file name object was created in.
 *	function- routine name object was created in.
 * Returns:
 * Errors:
 * Preconditions:
 */
void
dbug_object_create(int line, const char *file, const char *function)
{
	dbug_object_t  *dbug_object_p;
	dbug_state_object_t *dbug_state_object_p;
	ulong_t stacksize;
	int created = 0;
	char *cptr;

	thread_data_t *tdp = NULL;
#ifdef _REENTRANT
	LOCK_THREAD_DATA();
	if (!mdt_once) {
		if (thr_keycreate(&mdt_key, dbug_thread_exit) != 0)
			doabort();
		mdt_once++;
	}
	GET_THREAD_DATA_PTR(&tdp);
	if (tdp == NULL) {
		tdp = (thread_data_t *)calloc(sizeof (*tdp), 1);
		if (tdp == NULL)
			doabort();
		thr_setspecific(mdt_key, tdp);
		created = 1;
		tdp->td_keyword[0] = '\0';
		tdp->td_first = NULL;
	}
#else
	GET_THREAD_DATA_PTR(&tdp);
#endif

	dbug_object_p = (dbug_object_t *)calloc(sizeof (dbug_object_t), 1);

	if (dbug_object_p == NULL)
		doabort();

	/* save the function name */
	if (function)
		strcpy(dbug_object_p->d_func, function);
	else
		strcpy(dbug_object_p->d_func, "unknown");

	/* save the base of the file name */
	if (file) {
		cptr = strrchr(file, '/');
		if (cptr == NULL)
			strcpy(dbug_object_p->d_file, file);
		else
			strcpy(dbug_object_p->d_file, cptr++);
	} else
		strcpy(dbug_object_p->d_file, "unknown");

	/* Chain this onto our list of them */
	dbug_object_p->d_prev = tdp->td_first;
	tdp->td_first = dbug_object_p;

	/* set the default routine exit point line number to zero */
	dbug_object_p->d_leaveline = 0;

	/* If debugging is off, then all done */
	if (NOT db_debugon())
		goto out;

	/* if the active state is null initialize it */
	if (sd_push == NULL)
		db_push("d,:f,:F:i:L:n:N:o,cfsd_debug.out:p,:P:r:R:T:t:s");

	/* get a pointer to the active state */
	dbug_state_object_p = sd_push;

#ifdef STACKINIT
	/*
	 * Get the new stack depth.
	 * There a two problems associated with this.
	 * One is because c++ allows declarations anywhere inside of
	 * a routine.  So it is difficult to position the dbug_enter()
	 * macro after all declarations and still be useful.
	 * Two is that the dbug_enter() macro should be before all
	 * other automatic objects so that its destructor gets called
	 * last as the routine is returning.
	 * The solution is to advise placing the dbug_enter() macro at
	 * the start of the routine and specifying that that stack
	 * values apply upto but not including the current routine.
	 */
	stacksize = (ulong_t)this;
	if (GROWDOWN)
		stacksize = tdp->td_stackinit - stacksize;
	else
		stacksize = stacksize - tdp->td_stackinit;
#endif

	/* record the new nesting level */
	dbug_state_object_p->s_level++;

	/* if producing a trace of function calls */
	if (dotrace(dbug_state_object_p, dbug_object_p->d_func, sd_process)) {
		doprefix(dbug_state_object_p, line, sd_lineno++,
		    dbug_object_p->d_file, sd_process);
		indent(dbug_state_object_p, dbug_state_object_p->s_level);
		if (dbug_state_object_p->sf_stack)
			fprintf(dbug_state_object_p->s_out_file, ">%s   %ld\n",
			    dbug_object_p->d_func, stacksize);
		else
			fprintf(dbug_state_object_p->s_out_file, ">%s\n",
			    dbug_object_p->d_func);
		fflush(dbug_state_object_p->s_out_file);
		delay(dbug_state_object_p->s_delay);
	}

	/* if a new thread */
	if (created && dbug_state_object_p->sf_thread) {
		doprefix(dbug_state_object_p, line, sd_lineno++,
		    dbug_object_p->d_file, sd_process);
		indent(dbug_state_object_p, dbug_state_object_p->s_level);
		fprintf(dbug_state_object_p->s_out_file, "thread created\n");
		fflush(dbug_state_object_p->s_out_file);
		delay(dbug_state_object_p->s_delay);
	}

out:;
	UNLOCK_THREAD_DATA();
}

/*
 *
 *		dbug_object_destroy
 *
 * Description:
 *	Destructor for the dbug_routine class.
 *	Unchains this object from the list.
 * Arguments:
 * Returns:
 * Errors:
 * Preconditions:
 */
void
dbug_object_destroy(char *function_name, int line)
{
	dbug_object_t *dbug_object_p;
	dbug_state_object_t *dbug_state_object_p;
	thread_data_t *tdp;

	LOCK_THREAD_DATA();
	GET_THREAD_DATA_PTR(&tdp);

	/* unchain from the list of objects */
	dbug_object_p = tdp->td_first;
	tdp->td_first = dbug_object_p->d_prev;

	/* If debugging is off, then nothing else to do */
	if (NOT db_debugon())
		goto out;

	dbug_object_p->d_leaveline = line;

	/* get a pointer to the active state */
	dbug_state_object_p = sd_push;

	/*
	 * Make sure the last one created is being deleted.
	 * This will not be the case if there are multiple dbug_routine
	 * objects per routine or if one is created outside of a routine.
	 */
	if (strcmp(function_name, dbug_object_p->d_func)) {
		doprefix(dbug_state_object_p, dbug_object_p->d_leaveline,
		    sd_lineno++, dbug_object_p->d_file, sd_process);
		indent(dbug_state_object_p, dbug_state_object_p->s_level);
		fprintf(dbug_state_object_p->s_out_file,
		    "<expected %s, actual %s, ERROR: "
		    "dbug_enter/dbug_leave out of sequence.\n",
		    dbug_object_p->d_func, function_name);
		fflush(dbug_state_object_p->s_out_file);
		/* delay(dbug_state_object_p->s_delay); */
	}

	/* if producing a trace of function calls */
	if (dotrace(dbug_state_object_p, dbug_object_p->d_func, sd_process)) {
		doprefix(dbug_state_object_p, dbug_object_p->d_leaveline,
		    sd_lineno++, dbug_object_p->d_file, sd_process);
		indent(dbug_state_object_p, dbug_state_object_p->s_level);
		fprintf(dbug_state_object_p->s_out_file, "<%s\n",
		    dbug_object_p->d_func);
		fflush(dbug_state_object_p->s_out_file);
#if 0
		delay(dbug_state_object_p->s_delay);
#endif
	}


	/* record the new nesting level */
	dbug_state_object_p->s_level--;

out:;
	free(dbug_object_p);
	UNLOCK_THREAD_DATA();
}

/*
 *
 *		db_keyword
 *
 * Description:
 *	Test a keyword to determine if it is in the currently active
 *	keyword list.  As with the function list, a keyword is accepted
 *	if the list is null, otherwise it must match one of the list
 *	members.  When debugging is not on, no keywords are accepted.
 *	After the maximum trace level is exceeded, no keywords are
 *	accepted (this behavior subject to change).  Additionally,
 *	the current function and process must be accepted based on
 *	their respective lists.
 * Arguments:
 *	keyword - the keyword to test
 * Returns:
 *	Returns 1 if keyword accepted, 0 otherwise.
 * Errors:
 * Preconditions:
 *	precond(keyword)
 */
int
db_keyword(dbug_object_t *dbug_object_p, const char *keyword)
{
	dbug_state_object_t *dbug_state_object_p;
	int ret = 0;

	/* return FALSE if not debugging */
	if (NOT db_debugon())
		return (0);

	LOCK_THREAD_DATA();

	/* return FALSE if not debugging */
	if (NOT db_debugon())
		goto out;

	/* get a pointer to the active state */
	dbug_state_object_p = sd_push;

	if (dbug_state_object_p->sf_debug) {  /* is this test necessary ? */
		if (inlist(dbug_state_object_p->s_functions,
		    dbug_object_p->d_func)) {
			if (inlist(dbug_state_object_p->s_processes,
			    sd_process)) {
				if (inlist(dbug_state_object_p->s_keywords,
				    keyword)) {
					ret = 1;
					goto out;
				}
			}
		}
	}

out:
	UNLOCK_THREAD_DATA();
	return (ret);
}

/*
 *
 *		db_pargs
 *
 * Description:
 *	Saves arguments for subsequent usage by db_printf.
 * Arguments:
 *	line    - the line number the db_print occurs on
 *	keyword - determines whether or not to really print anything
 * Returns:
 * Errors:
 * Preconditions:
 *	precond(keyword)
 */
void
db_pargs(dbug_object_t *dbug_object_p, int line, char *keyword)
{
	thread_data_t *tdp;

	/* return if no debugging yet */
	if (NOT db_debugon())
		return;

	GET_THREAD_DATA_PTR(&tdp);

	tdp->td_line = line;
	if (keyword)
		strcpy(tdp->td_keyword, keyword);
	else
		tdp->td_keyword[0] = '\0';
}

int
db_getfd()
{
	return (fileno(sd_push->s_out_file));
}

/*
 *
 *		db_printf
 *
 * Description:
 *	Outputs the specified message if the keyword specified
 *	by db_pargs() has been selected.  The line number specified
 *	by db_pargs() is also used as the line number the db_printf()
 *	occurs on.  The format string should NOT include a terminating
 *	newline as one is supplied automatically.
 * Arguments:
 *	format - printf style printing control string
 *	...    - additional arguments required by the control string
 * Returns:
 * Errors:
 * Preconditions:
 *	precond(format)
 */
void
db_printf(char *keyword, char *format, ...)
{
	dbug_object_t *dbug_object_p;
	thread_data_t *tdp;
	dbug_state_object_t *dbug_state_object_p = sd_push;
	va_list args;

	dbug_object_p = db_get_dbug_object_p();
	/* return if no debugging yet */
	if (NOT db_debugon())
		return;

	GET_THREAD_DATA_PTR(&tdp);

	/* return if keyword not selected */
	if (NOT db_keyword(dbug_object_p, tdp->td_keyword))
		return;

	LOCK_THREAD_DATA();

	/* get a pointer to the active state */

	va_start(args, format);

	doprefix(dbug_state_object_p, tdp->td_line, sd_lineno++,
		dbug_object_p->d_file, sd_process);
	if (dbug_state_object_p->sf_trace)
		indent(dbug_state_object_p, dbug_state_object_p->s_level +1);
	else
		fprintf(dbug_state_object_p->s_out_file, "%s: ",
		    dbug_object_p->d_func);
	if (tdp->td_keyword[0])
		fprintf(dbug_state_object_p->s_out_file, "%s: ",
		    tdp->td_keyword);
	vfprintf(dbug_state_object_p->s_out_file, format, args);
	fprintf(dbug_state_object_p->s_out_file, "\n");
	fflush(dbug_state_object_p->s_out_file);
	delay(dbug_state_object_p->s_delay);

	va_end(args);

	UNLOCK_THREAD_DATA();
}

/*
 *
 *		db_traceprint
 *
 * Description:
 *	Prints out a trace of the call stack.
 * Arguments:
 *	line    - the line number where this call was made
 *	keyword - keyword to test against
 * Returns:
 * Errors:
 * Preconditions:
 */
void
db_traceprint(int line, const char *keyword)
{
	dbug_object_t *dbug_object_p;
	dbug_object_t *pdr;
	/* return if no debugging yet */
	if (NOT db_debugon())
		return;

	if ((dbug_object_p = db_get_dbug_object_p()) == NULL)
		doabort();

	/* If the specified keyword is enabled */
	if (db_keyword(dbug_object_p, keyword)) {
		/* perform setup for using db_printf */
		db_pargs(dbug_object_p, line, NULL);

		/* Output a header message */
		db_printf(NULL, "Stack Trace");

		/* walk the stack of dbug_routine objects */
		for (pdr = dbug_object_p; pdr != NULL; pdr = pdr->d_prev) {
			/* output the routine name */
			db_printf(NULL, "  %s() (%s)", pdr->d_func,
			    pdr->d_file);
		}
	}
}

/*
 *
 *			db_assert
 *
 * Description:
 *	Called when an assert fails.
 *	Prints out a stack trace and aborts.
 * Arguments:
 *	line	line number assert occurred at
 *	msgp	string form of assert code that failed
 * Returns:
 * Preconditions:
 *	precond(msgp)
 */
void
db_assert(dbug_object_t *dbug_object_p, int line, const char *msgp)
{
	if (NOT db_debugon())
		db_push("-#:d");
	db_pargs(dbug_object_p, line, NULL);
	db_printf(NULL, "Assertion Failed %s:%s():%d \"%s\"",
	    dbug_object_p->d_file, dbug_object_p->d_func, line, msgp);
	db_traceprint(line, NULL);
	doabort();
}

/*
 *
 *			db_precond
 *
 * Description:
 *	Called when an precond fails.
 *	Prints out a stack trace and aborts.
 * Arguments:
 *	line	line number precond occurred at
 *	msgp	string form of precond code that failed
 * Returns:
 * Preconditions:
 *	precond(msgp)
 */
void
db_precond(dbug_object_t *dbug_object_p, int line, const char *msgp)
{
	if (NOT db_debugon())
		db_push("-#:d");
	db_pargs(dbug_object_p, line, NULL);
	db_printf(NULL, "Precondition Failed %s:%s():%d \"%s\"",
	    dbug_object_p->d_file, dbug_object_p->d_func, line, msgp);
	db_traceprint(line, NULL);
	doabort();
}

/*
 *
 *		db_push
 *
 * Description:
 *	Push current debugger state and set up a new one.
 *	Returns NULL if no errors, an error string if there
 *	is an error.
 *
 * format of control string
 *   command[:command:...]
 *
 *   commands
 *   debugging on	'd'  d[,<keyword>[,...]]
 *   delay value	'D'  D[,<delay value>]
 *   function list	'f'  f[,<function name>[,...]]
 *   print filename	'F'  F
 *   print pid		'i'  i
 *   print line number	'L'  L
 *   print call depth	'n'  n
 *   number each line	'N'  N
 *   output file	'o'  o[,<filename>
 *   process name list	'p'  p[,<process name>[,...]]
 *   print proc name	'P'  P
 *   reset indentation	'r'  r
 *   print runtime	'R'  R
 *   print thread info	'T'  T
 *   print trace	't'  t
 *   print stack depth	's'  s
 */
char *
db_push(const char *control)
{
	char *dupcontrol = NULL;
	dbug_state_object_t *dbug_state_object_p;
	flist_object_t *flist_object_p;
	register char *scan;
	int retval;
	char res[100];
	int level;

	LOCK_THREAD_DATA();

	/* error if the control string is NULL */
	if (control == NULL) {
		strcpy(res, "mdbug: control string is NULL");
		goto out;
	}

	/* turn debugging flag off */
	sd_on = FALSE;

	/* get the level from the old state if it exists */
	if (sd_push == NULL)
		level = 0;
	else
		level = sd_push->s_level;

	/* Create a new state */
	dbug_state_object_p = dbug_state_create(level);
	if (dbug_state_object_p == NULL) {
		strcpy(res, "mdbug: out of memory, dbug_state_create");
		goto out;
	}

	/* add it to our list of states and make it the current one */
	dbug_state_object_p->s_next = sd_push;
	sd_push = dbug_state_object_p;

	/* Strip off -# if in the control string */
	if ((*control == '-') && (*(control+1) == '#'))
		control += 2;

	/* make a copy of the control string so we can modify it with strtok */
	dupcontrol = strdup(control);
	if (dupcontrol == NULL) {
		strcpy(res, "mdbug: out of memory, strdup");
		goto out;
	}

	/* parse the control string */
	for (scan = mystrtok(dupcontrol, ":");
	    scan != NULL;
	    scan = mystrtok(NULL, ":")) {
		switch (*scan++) {
		case 'd':			/* debugging on */
			sd_on = TRUE;
			dbug_state_object_p->sf_debug = TRUE;
			if (*scan++ == ',') {
				retval = listparse(scan,
				    dbug_state_object_p->s_keywords);
				if (retval < 0) {
					strcpy(res,
					    "mdbug: -d too many keywords");
					goto out;
				}
			}
			break;

		case 'D': 			/* specify delay value */
			dbug_state_object_p->s_delay = 0;
			if (*scan++ == ',') {
				flist_object_p = flist_create();
				retval = listparse(scan, flist_object_p);
				if (retval < 0) {
					strcpy(res,
					    "mdbug: -D too many delays");
					goto out;
				}
				if (flist_object_p->f_count > 0) {
					dbug_state_object_p->s_delay =
					    delayarg(atoi(
					    (char *)fl_top(flist_object_p)));
				}
				flist_destroy(flist_object_p);
			}
			break;

		case 'f': 			/* list of functions to watch */
			if (*scan++ == ',') {
				retval = listparse(scan,
				    dbug_state_object_p->s_functions);
				if (retval < 0) {
					strcpy(res,
					    "mdbug: -f too many functions");
					goto out;
				}
			}
			break;

		case 'F': 		/* print file name with dbug output */
			dbug_state_object_p->sf_file = TRUE;
			break;

		case 'i': 		/* print pid with dbug output */
			dbug_state_object_p->sf_pid = TRUE;
			break;

		case 'L':		/* print line nums with dbug output */
			dbug_state_object_p->sf_line = TRUE;
			break;

		case 'n': 		/* print function call depth */
			dbug_state_object_p->sf_depth = TRUE;
			break;

		case 'N': 		/* number each line of dbug output */
			dbug_state_object_p->sf_number = TRUE;
			break;

		case 'o': 		/* specifies output file for dbug */
			if (*scan++ == ',') {
				flist_object_p = flist_create();
				retval = listparse(scan, flist_object_p);
				if (retval < 0) {
					strcpy(res,
					    "mdbug: -o too many output files");
					goto out;
				}

				if (flist_object_p->f_count > 0) {
					dbug_state_object_p->s_out_file =
					    openfile((char *)
					    fl_top(flist_object_p));
					if (dbug_state_object_p->s_out_file !=
					    NULL)
						dbug_state_object_p->sf_didopen
						    = 1;
				} else
					dbug_state_object_p->s_out_file =
					    openfile(NULL);
				flist_destroy(flist_object_p);
			} else
				dbug_state_object_p->s_out_file =
				    openfile(NULL);
			if (dbug_state_object_p->s_out_file == NULL) {
				strcpy(res,
				    "mdbug: -o cannot open output file");
				goto out;
			}
			break;

		case 'p':			/* debug specified processes */
			if (*scan++ == ',') {
				retval = listparse(scan,
				    dbug_state_object_p->s_processes);
				if (retval < 0) {
					strcpy(res,
					    "mdbug: -p too many processes");
					goto out;
				}
			}
			break;

		case 'P': 		/* print process name on dbug output */
			dbug_state_object_p->sf_process = TRUE;
			break;

		case 'r': 			/* reset indentation to zero */
			dbug_state_object_p->s_level = 0;
			break;

		case 's': 			/* print stack depth on enter */
			dbug_state_object_p->sf_stack = TRUE;
			break;

		case 'R':		/* print time prog has been running */
			dbug_state_object_p->sf_time = TRUE;
			time(&dbug_state_object_p->s_starttime);
			break;

		case 'T':		/* print thread information */
			dbug_state_object_p->sf_thread = TRUE;
			break;

		case 't': 		/* print trace of functions called */
			dbug_state_object_p->sf_trace = TRUE;
			dbug_state_object_p->s_maxdepth = MAXDEPTH;
			if (*scan++ == ',') {
				flist_object_p = flist_create();
				retval = listparse(scan, flist_object_p);
				if (retval < 0) {
					strcpy(res,
					    "mdbug: -t too many traces");
					goto out;
				}
				if (flist_object_p->f_count > 0) {
					dbug_state_object_p->s_maxdepth =
					    atoi((char *)
					    fl_top(flist_object_p));
				}
				flist_destroy(flist_object_p);
			}
			break;
		}
	}

out:
	/* free up the dupped control string */
	free(dupcontrol);

	UNLOCK_THREAD_DATA();

	/* return result */
	return (NULL);
}

/*
 *
 *		db_pop
 *
 * Description:
 *	Pop the debug stack.
 */
void
db_pop()
{
	dbug_state_object_t *dbug_state_object_p;

	LOCK_THREAD_DATA();

	/* return if no debugging yet */
	if (sd_push == NULL)
		goto out;

	/* get and remove the top item from the list */
	dbug_state_object_p = sd_push;
	sd_push = dbug_state_object_p->s_next;

	/* Delete the item. */
	dbug_state_destroy(dbug_state_object_p);

	/* get the current top of the stack */
	dbug_state_object_p = sd_push;
	if (dbug_state_object_p) {
		/* See if debugging is turned on */
		if (dbug_state_object_p->sf_debug)
			sd_on = TRUE;
		else
			sd_on = FALSE;
	}

out:;
	UNLOCK_THREAD_DATA();
}

/*
 *
 *			db_process
 *
 * Description:
 *	Specifies the name of the process.
 *	Only the pointer is saved, the string is not copied.
 * Arguments:
 *	namep
 * Returns:
 * Preconditions:
 */
void
db_process(const char *namep)
{
	thread_data_t *tdp;

	strcpy(sd_process, namep);

#ifdef STACKINIT
	GET_THREAD_DATA_PTR(&tdp);
	tdp->td_stackinit = (ulong_t)this;
#endif
}

/*
 *
 *			listparse
 *
 * Description:
 *	parse list of modifiers in debug control string
 *
 *	Given pointer to a comma separated list of strings in "cltp",
 *	parses the list, building a list and returning a pointer to it.
 *	The original comma separated list is destroyed in the process of
 *	building the linked list, thus it had better be a duplicate
 *	if it is important.
 *
 *	This routine is only called from db_push.
 *	Returns 0 for success, -1 for failure.
 */
static int
listparse(register char *ctlp, flist_object_t *head)
{
	char *start;
	char *item;

	/* scan the string until end */
	while (*ctlp != '\0') {
		/* See if no more room on the list */
		if (fl_space(head) == 0)
			return (-1);

		/* save the begining of this section */
		start = ctlp;

		/* loop until the end of the token is found */
		while ((*ctlp != '\0') && (*ctlp != ','))
			ctlp++;

		/* add a string terminator if necessary, for strdup */
		if (*ctlp == ',')
			*ctlp++ = '\0';

		/* make a copy of the string */
		item = strdup(start);
		if (item == NULL)
			return (-1);

		/* add it to the list */
		fl_push(head, item);
	}

	return (0);
}

/*
 *
 *			inlist
 *
 * Description:
 *	Tests the string pointed to by "cp" to determine if it is in
 *	the list pointed to by "flist_object_p".  Linkp points to the first
 *	link in the list.  If flist_object_p is empty then the string is treated
 *	as if it is in the list (I.E all strings are in the null list).
 *	This may seem rather strange at first but leads to the desired
 *	operation if no list is given.  The net effect is that all
 *	strings will be accepted when there is no list, and when there
 *	is a list, only those strings in the list will be accepted.
 */
static boolean
inlist(flist_object_t *flist_object_p, const char *cp)
{
	register boolean accept;
	register char *item;

	if ((flist_object_p == NULL) || (flist_object_p->f_count == 0) ||
		(cp == NULL))
		accept = TRUE;
	else {
		accept = FALSE;

		/* walk the list of items */
		for (item = (char *)fl_top(flist_object_p);
		    item != NULL;
		    item = (char *)fl_next(flist_object_p)) {
			/* see if a match */
			if (strcmp(item, cp) == 0) {
				accept = TRUE;
				break;
			}
		}
	}

	return (accept);
}

/*
 *
 *			dotrace
 *
 * Description:
 *	Checks to see if tracing is enabled based on whether the
 *	user has specified tracing, the maximum trace depth has
 *	not yet been reached, the current function is selected,
 *	and the current process is selected.  Returns TRUE if
 *	tracing is enabled, FALSE otherwise.
 */
static boolean
dotrace(dbug_state_object_t *dbug_state_object_p, const char *func,
    const char *process)
{
	boolean trace;

	trace = FALSE;
	if (dbug_state_object_p->sf_trace) {
		if (dbug_state_object_p->s_level <=
		    dbug_state_object_p->s_maxdepth) {
			if (inlist(dbug_state_object_p->s_functions, func)) {
				if (inlist(dbug_state_object_p->s_processes,
				    process)) {
					trace = TRUE;
				}
			}
		}
	}

	return (trace);
}

/*
 *
 *			indent
 *
 * Description:
 *	Indent a line to the given level.  Note that this is
 *	a simple minded but portable implementation.
 *	There are better ways.
 *
 *	Also, the indent must be scaled by the compile time option
 *	of character positions per nesting level.
 */
static void
indent(register dbug_state_object_t *dbug_state_object_p, int indent)
{
	register int count;
	char buffer[PRINTBUF];

	indent *= INDENT;
	for (count = 0;
	    (count < (indent - INDENT)) && (count < (PRINTBUF - 1));
	    count++) {
		if ((count % INDENT) == 0)
			buffer[count] = '|';
		else
			buffer[count] = ' ';
	}

	buffer[count] = '\0';
	fprintf(dbug_state_object_p->s_out_file, buffer);
	fflush(dbug_state_object_p->s_out_file);
}

/*
 *
 *			doprefix
 *
 * Description:
 *	Print prefix common to all debugger output lines, prior to
 *	doing indentation if necessary.  Print such information as
 *	current process name, current source file name and line number,
 *	and current function nesting depth.
 */
static void
doprefix(dbug_state_object_t *dbug_state_object_p, int line, long lineno,
	const char *file, const char *process)
{
#if DBUG_UNIX
	if (dbug_state_object_p->sf_pid)
		fprintf(dbug_state_object_p->s_out_file, "%5d: ",
		    (int)getpid());
#endif

	if (dbug_state_object_p->sf_thread)
		fprintf(dbug_state_object_p->s_out_file, "%5ld: ",
		    (long)thr_self());

	if (dbug_state_object_p->sf_number)
		fprintf(dbug_state_object_p->s_out_file, "%5ld: ", lineno);

	if (dbug_state_object_p->sf_process && process)
		fprintf(dbug_state_object_p->s_out_file, "%s: ", process);

	if (dbug_state_object_p->sf_file)
		fprintf(dbug_state_object_p->s_out_file, "%14s: ", file);

	if (dbug_state_object_p->sf_line)
		fprintf(dbug_state_object_p->s_out_file, "%5d: ", line);

	if (dbug_state_object_p->sf_depth)
		fprintf(dbug_state_object_p->s_out_file, "%4d: ",
		dbug_state_object_p->s_level);

	fflush(dbug_state_object_p->s_out_file);
}

/*
 *
 *			openfile
 *
 * Description:
 *	Given name of a new file (or NULL for stdout) opens the file
 *	and sets the output stream to the new file.
 */
static FILE *
openfile(char *name)
{
	FILE *fp;
	boolean newfile;

	if (name == NULL)
		return (stdout);

	if (NOT writable(name))
		return (NULL);

	/* see if the file already exists */
	if (file_exists(name))
		newfile = FALSE;
	else
		newfile = TRUE;

	/* open the file */
	fp = fopen(name, "a+");
	if (fp == NULL)
		return (NULL);

	/*
	 * If the file is newly created, give it away to the user
	 * that started the program.
	 */
	if (newfile) {
		changeowner(name);
	}
	return (fp);
}

/*
 *
 *			writable
 *
 * Description:
 *	Because the debugger might be linked in with a program that
 *	runs with the set-uid-bit (suid) set, we have to be careful
 *	about opening a user named file for debug output.  This consists
 *	of checking the file for write access with the real user id,
 *	or checking the directory where the file will be created.
 *
 *	Returns TRUE if the user would normally be allowed write or
 *	create access to the named file.  Returns FALSE otherwise.
 */
static boolean
writable(char *pathname)
{
#if DBUG_UNIX

	char *lastslash;

	boolean granted = FALSE;
	if (file_exists(pathname)) {
		if (file_writable(pathname)) {
			granted = TRUE;
		}
	} else {
		lastslash = strrchr(pathname, '/');
		if (lastslash != NULL) {
			*lastslash = '\0';
		} else {
			pathname = ".";
		}
		if (file_writable(pathname)) {
			granted = TRUE;
		}
		if (lastslash != NULL) {
			*lastslash = '/';
		}
	}
	return (granted);
#else
	return (TRUE);
#endif
}

/*
 *
 *			changeowner
 *
 * Description:
 *	For unix systems, change the owner of the newly created debug
 *	file to the real owner.  This is strictly for the benefit of
 *	programs that are running with the set-user-id bit set.
 *
 *	Note that at this point, the fact that pathname represents
 *	a newly created file has already been established.  If the
 *	program that the debugger is linked to is not running with
 *	the suid bit set, then this operation is redundant (but
 *	harmless).
 */
static void
changeowner(char *pathname)
{
#if DBUG_UNIX
	chown(pathname, getuid(), getgid());
#endif
}

/*
 *
 *			delayarg
 *
 * Description:
 *	Converts delay argument, given in tenths of a second, to the
 *	appropriate numerical argument used by the system to delay
 *	that that many tenths of a second.  For example, on the
 *	amiga, there is a system call "Delay()" which takes an
 *	argument in ticks (50 per second).  On unix, the sleep
 *	command takes seconds.  Thus a value of "10", for one
 *	second of delay, gets converted to 50 on the amiga, and 1
 *	on unix.  Other systems will need to use a timing loop.
 */
static int
delayarg(int value)
{
	unsigned int delayarg = 0;

#if (unix || xenix)
	delayarg = value / 10;		/* Delay is in seconds for sleep () */
#endif
	return (delayarg);
}

/*
 *
 *			delay
 *
 * Description:
 *	Implements the delay function.
 *
 *	A dummy delay stub for systems that do not support delays.
 *	With a little work, this can be turned into a timing loop.
 */

static void
delay(uint_t xx)
{
#if (unix || xenix)
	sleep(xx);
#endif
#if amiga
	Delay(xx);
#endif
#ifdef __ZTC__
	msleep((ulong_t)xx);
#endif
}

/*
 *
 *			getclock
 *
 * Description:
 *	Returns the time in milliseconds used by this process
 *	so far.
 */
#if (unix || xenix)

#include <sys/param.h>
#if BSD4_3 || sun

#include <sys/time.h>
#include <sys/resource.h>

static ulong_t
getclock()
{
#if 0
	struct rusage ru;

	getrusage(RUSAGE_SELF, &ru);
	return ((ru.ru_utime.tv_sec * 1000) + (ru.ru_utime.tv_usec / 1000));
#else
	return (0);
#endif
}

#else

static ulong_t
getclock()
{
	return (0);
}

#endif
#endif	/* unix */

#ifdef MSDOS
static ulong_t
getclock()
{
	return (clock() * 10);
}
#endif

/*
 *
 *			mystrtok
 *
 * Description:
 *	A version of strtok for those systems without it
 */
static char *
mystrtok(char *s1, char *s2)
{
	static char *end = NULL;
	register char *rtnval;

	rtnval = NULL;
	if (s2 != NULL) {
		if (s1 != NULL) {
			end = s1;
			rtnval = mystrtok((char *)NULL, s2);
		} else if (end != NULL) {
			if (*end != '\0') {
				rtnval = end;
				while ((*end != *s2) && (*end != '\0')) {
					end++;
				}
				if (*end != '\0') {
					*end++ = '\0';
				}
			}
		}
	}

	return (rtnval);
}

/*
 *
 *			dbug_thread_exit
 *
 * Description:
 *	Called when a thread exits.
 * Arguments:
 *	data	pointer to thread specific data
 * Returns:
 * Preconditions:
 */
void
dbug_thread_exit(void *data)
{
	dbug_state_object_t *dbug_state_object_p;

	LOCK_THREAD_DATA();

	/* If debugging is off, then nothing else to do */
	if (NOT db_debugon())
		goto out;

	/* get a pointer to the active state */
	dbug_state_object_p = sd_push;

	if (dbug_state_object_p->sf_thread) {
		doprefix(dbug_state_object_p, 0, sd_lineno++, "unknown",
		    sd_process);
		indent(dbug_state_object_p, dbug_state_object_p->s_level);
		fprintf(dbug_state_object_p->s_out_file, "thread destroyed\n");
		fflush(dbug_state_object_p->s_out_file);
		delay(dbug_state_object_p->s_delay);
	}

out:;
	FREE_THREAD_DATA(data);
	UNLOCK_THREAD_DATA();
}

/*
 *
 *			doabort
 *
 * Description:
 *	Causes the process to exit immediatly with a core dump.
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
doabort()
{
	dbug_state_object_t *dbug_state_object_p = sd_push;
	fflush(dbug_state_object_p->s_out_file);
	for (;;) {
		kill(getpid(), SIGABRT);
		(void) signal(SIGABRT, SIG_DFL);
		(void) sigrelse(SIGABRT);
	}
}

/*
 *
 *			dbug_state_create
 *
 * Description:
 *	Constructor for the dbug_state class.
 * Arguments:
 *	The current level in the call stack.
 * Returns:
 * Preconditions:
 */
dbug_state_object_t *
dbug_state_create(int level)
{
	dbug_state_object_t *dbug_state_object_p;

	dbug_state_object_p =
	    (dbug_state_object_t *)calloc(sizeof (dbug_state_object_t), 1);

	if (dbug_state_object_p == NULL)
		doabort();

	dbug_state_object_p->sf_trace = 0;
	dbug_state_object_p->sf_debug = 0;
	dbug_state_object_p->sf_file = 0;
	dbug_state_object_p->sf_line = 0;
	dbug_state_object_p->sf_depth = 0;
	dbug_state_object_p->sf_process = 0;
	dbug_state_object_p->sf_number = 0;
	dbug_state_object_p->sf_pid = 0;
	dbug_state_object_p->sf_stack = 0;
	dbug_state_object_p->sf_time = 0;
	dbug_state_object_p->sf_didopen = 0;
	dbug_state_object_p->sf_thread = 0;
	dbug_state_object_p->s_maxdepth = MAXDEPTH;
	dbug_state_object_p->s_delay = 0;
	dbug_state_object_p->s_level = level;
	dbug_state_object_p->s_starttime = 0;
	dbug_state_object_p->s_out_file = stderr;
	dbug_state_object_p->s_next = NULL;
	return (dbug_state_object_p);
}

/*
 *
 *			dbug_state_destroy
 *
 * Description:
 *	Destructor for the dbug_state class.
 * Arguments:
 * Returns:
 * Preconditions:
 */
void
dbug_state_destroy(dbug_state_object_t *dbug_state_object_p)
{
	if (dbug_state_object_p->sf_didopen)
		fclose(dbug_state_object_p->s_out_file);
	free(dbug_state_object_p);
}

/*
 *
 *		db_debugon
 *
 * Description:
 *   Returns 1 if debugging is currently enabled, 0 otherwise.
 * Arguments:
 * Returns:
 * Errors:
 * Preconditions:
 */

int
db_debugon(dbug_object_p)
dbug_object_t *dbug_object_p;
{
	return (sd_on);
}
boolean
file_exists(const char *pathname)
{
	return (access(pathname, F_OK) == 0);
}
boolean
file_writable(const char *pathname)
{
	return (access(pathname, W_OK) == 0);
}
dbug_object_t *
db_get_dbug_object_p()
{
	thread_data_t *tdp;

	GET_THREAD_DATA_PTR(&tdp);
	return (tdp->td_first);
}
#endif /* DBUG_OFF */
