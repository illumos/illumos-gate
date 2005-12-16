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
// ------------------------------------------------------------
//
//			dbug.cc
//
// Purpose:
//    Implements the dbug_routine class.
//    This code is derived from the public domain DBUG
//    package written by Fred Fish.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#ifndef DBUG_OFF

#include <stdio.h>
#include <stdlib.h>
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

// forward references
static int listparse(register char *ctlp, flist *head);
static boolean inlist(flist *linkp, const char *cp);
static boolean dotrace(dbug_state *pst, const char *func, const char *process);
static void indent(register dbug_state *pst, int indent);
static void doprefix(dbug_state *pst, int line, long lineno,
    const char *file, const char *process);
static FILE *openfile(char *name);
static boolean writable(char *pathname);
static void changeowner(char *pathname);
static int delayarg(int value);
static void delay(u_int xx);
static u_long getclock();
static char *mystrtok(char *s1, char *s2);
static void doabort();

// initialize static members of class
int			 dbug_routine::sd_on = 0;
const char		*dbug_routine::sd_process = NULL;
long			 dbug_routine::sd_lineno = 0;
class dbug_state	*dbug_routine::sd_push = NULL;

// this structure defines thread specific data
struct thread_data {
	unsigned long	 td_stackinit;	// Begining of stack.
	int		 td_line;	// Current line number.
	const char	*td_keyword;	// Current keyword.
	dbug_routine	*td_first;	// Current routine.
};

#ifdef _REENTRANT
mutex_t		mdt_lock;
int		mdt_once = 0;
thread_key_t	mdt_key;
#else
thread_data	mdt_data;
#endif

// ------------------------------------------------------------
//
//		dbug_routine
//
// Description:
//	Constructor for the dbug_routine class.
// Arguments:
//	line	- line number where object was created.
//	file	- file name object was created in.
//	function- routine name object was created in.
// Returns:
// Errors:
// Preconditions:

dbug_routine::dbug_routine(int line, const char *file, const char *function)
{
	dbug_state *pst;
	u_long stacksize;
	int created = 0;

	thread_data *tdp;
#ifdef _REENTRANT
	mutex_lock(&mdt_lock);
	if (!mdt_once) {
		if (thr_keycreate(&mdt_key, dbug_thread_exit) != 0)
			doabort();
		mdt_once++;
	}
	thr_getspecific(mdt_key, (void **)&tdp);
	if (tdp == NULL) {
		tdp = (thread_data *)calloc(sizeof (*tdp), 1);
		if (tdp == NULL)
			doabort();
		thr_setspecific(mdt_key, tdp);
		created = 1;
	}
#else
	tdp = &mdt_data;
#endif

	// save the function name
	if (function)
		d_func = function;
	else
		d_func = "unknown";

	// save the base of the file name
	if (file) {
		d_file = strrchr(file, '/');
		if (d_file == NULL)
			d_file = file;
		else
			d_file++;
	} else
		d_file = "unknown";

	// Chain this onto our list of them
	d_prev = tdp->td_first;
	tdp->td_first = this;

	// set the default routine exit point line number to zero
	d_leaveline = 0;

	// If debugging is off, then all done
	if (NOT db_debugon())
		goto out;

	// get a pointer to the active state
	pst = sd_push;

	// Get the new stack depth.
	// There a two problems associated with this.
	// One is because c++ allows declarations anywhere inside of
	// a routine.  So it is difficult to position the dbug_enter()
	// macro after all declarations and still be useful.
	// Two is that the dbug_enter() macro should be before all
	// other automatic objects so that its destructor gets called
	// last as the routine is returning.
	// The solution is to advise placing the dbug_enter() macro at
	// the start of the routine and specifying that that stack
	// values apply upto but not including the current routine.
	stacksize = (u_long)this;
	if (GROWDOWN)
		stacksize = tdp->td_stackinit - stacksize;
	else
		stacksize = stacksize - tdp->td_stackinit;

	// record the new nesting level
	pst->s_level++;

	// if producing a trace of function calls
	if (dotrace(pst, d_func, sd_process)) {
		doprefix(pst, line, sd_lineno++, d_file, sd_process);
		indent(pst, pst->s_level);
		if (pst->sf_stack)
			fprintf(pst->s_out_file, ">%s   %ld\n",
				d_func, stacksize);
		else
			fprintf(pst->s_out_file, ">%s\n", d_func);
		fflush(pst->s_out_file);
		delay(pst->s_delay);
	}

	// if a new thread
	if (created && pst->sf_thread) {
		doprefix(pst, line, sd_lineno++, d_file, sd_process);
		indent(pst, pst->s_level);
		fprintf(pst->s_out_file, "thread created\n");
		fflush(pst->s_out_file);
		delay(pst->s_delay);
	}

out:;
#ifdef _REENTRANT
	mutex_unlock(&mdt_lock);
#endif
}

// ------------------------------------------------------------
//
//		~dbug_routine
//
// Description:
//	Destructor for the dbug_routine class.
//	Unchains this object from the list.
// Arguments:
// Returns:
// Errors:
// Preconditions:

dbug_routine::~dbug_routine()
{
	dbug_state *pst;
	thread_data *tdp;
#ifdef _REENTRANT
	mutex_lock(&mdt_lock);
	thr_getspecific(mdt_key, (void **)&tdp);
#else
	tdp = &mdt_data;
#endif

	// unchain from the list of objects
	dbug_routine *cur = tdp->td_first;
	tdp->td_first = d_prev;

	// If debugging is off, then nothing else to do
	if (NOT db_debugon())
		goto out;

	// get a pointer to the active state
	pst = sd_push;

	// Make sure the last one created is being deleted.
	// This will not be the case if there are multiple dbug_routine
	// objects per routine or if one is created outside of a routine.
	if (this != cur) {
		doprefix(pst, d_leaveline, sd_lineno++, d_file, sd_process);
		indent(pst, pst->s_level);
		fprintf(pst->s_out_file,
			"<%s, ERROR: dbug_enter/dbug_leave out of sequence.\n",
			d_func);
		fflush(pst->s_out_file);
		delay(pst->s_delay);
	}

	// if producing a trace of function calls
	if (dotrace(pst, d_func, sd_process)) {
		doprefix(pst, d_leaveline, sd_lineno++, d_file, sd_process);
		indent(pst, pst->s_level);
		fprintf(pst->s_out_file, "<%s\n", d_func);
		fflush(pst->s_out_file);
		delay(pst->s_delay);
	}

	// record the new nesting level
	pst->s_level--;

out:;
#ifdef _REENTRANT
	mutex_unlock(&mdt_lock);
#endif
}

// ------------------------------------------------------------
//
//		db_leave
//
// Description:
//	Indicates the line number that the routine exits at.
// Arguments:
//	line - the line number on or one before the return
//		statement is executed at.
// Returns:
// Errors:
// Preconditions:

void
dbug_routine::db_leave(int line)
{
	d_leaveline = line;
}

// ------------------------------------------------------------
//
//		db_keyword
//
// Description:
//	Test a keyword to determine if it is in the currently active
//	keyword list.  As with the function list, a keyword is accepted
//	if the list is null, otherwise it must match one of the list
//	members.  When debugging is not on, no keywords are accepted.
//	After the maximum trace level is exceeded, no keywords are
//	accepted (this behavior subject to change).  Additionally,
//	the current function and process must be accepted based on
//	their respective lists.
// Arguments:
//	keyword - the keyword to test
// Returns:
//	Returns 1 if keyword accepted, 0 otherwise.
// Errors:
// Preconditions:
//	precond(keyword)

int
dbug_routine::db_keyword(const char *keyword)
{
	dbug_state *pst;

	// return FALSE if not debugging
	if (NOT db_debugon())
		return (0);

#ifdef _REENTRANT
	mutex_lock(&mdt_lock);
#endif
	int ret = 0;

	// return FALSE if not debugging
	if (NOT db_debugon())
		goto out;

	// get a pointer to the active state
	pst = sd_push;

	if (pst->sf_debug) {  // is this test necessary ?????????
		if (inlist(&pst->s_functions, d_func)) {
			if (inlist(&pst->s_processes, sd_process)) {
				if (inlist(&pst->s_keywords, keyword)) {
					ret = 1;
					goto out;
				}
			}
		}
	}

out:
#ifdef _REENTRANT
	mutex_unlock(&mdt_lock);
#endif
	return (ret);
}

// ------------------------------------------------------------
//
//		db_pargs
//
// Description:
//	Saves arguments for subsequent usage by db_printf.
// Arguments:
//	line    - the line number the db_print occurs on
//	keyword - determines whether or not to really print anything
// Returns:
// Errors:
// Preconditions:
//	precond(keyword)

void
dbug_routine::db_pargs(int line, const char *keyword)
{
	// return if no debugging yet
	if (NOT db_debugon())
		return;

	thread_data *tdp;
#ifdef _REENTRANT
	thr_getspecific(mdt_key, (void **)&tdp);
#else
	tdp = &mdt_data;
#endif

	tdp->td_line = line;
	tdp->td_keyword = keyword;
}

// ------------------------------------------------------------
//
//		db_printf
//
// Description:
//	Outputs the specified message if the keyword specified
//	by db_pargs() has been selected.  The line number specified
//	by db_pargs() is also used as the line number the db_printf()
//	occurs on.  The format string should NOT include a terminating
//	newline as one is supplied automatically.
// Arguments:
//	format - printf style printing control string
//	...    - additional arguments required by the control string
// Returns:
// Errors:
// Preconditions:
//	precond(format)

void
dbug_routine::db_printf(const char *format, ...)
{
	// return if no debugging yet
	if (NOT db_debugon())
		return;

	thread_data *tdp;
#ifdef _REENTRANT
	thr_getspecific(mdt_key, (void **)&tdp);
#else
	tdp = &mdt_data;
#endif

	// return if keyword not selected
	if (NOT db_keyword(tdp->td_keyword))
		return;

#ifdef _REENTRANT
	mutex_lock(&mdt_lock);
#endif

	// get a pointer to the active state
	dbug_state *pst = sd_push;

	va_list args;
	va_start(args, format);

	doprefix(pst, tdp->td_line, sd_lineno++, d_file, sd_process);
	if (pst->sf_trace)
		indent(pst, pst->s_level +1);
	else
		fprintf(pst->s_out_file, "%s: ", d_func);
	if (tdp->td_keyword)
		fprintf(pst->s_out_file, "%s: ", tdp->td_keyword);
	vfprintf(pst->s_out_file, format, args);
	fprintf(pst->s_out_file, "\n");
	fflush(pst->s_out_file);
	delay(pst->s_delay);

	va_end(args);

#ifdef _REENTRANT
	mutex_unlock(&mdt_lock);
#endif
}

// ------------------------------------------------------------
//
//		db_traceprint
//
// Description:
//	Prints out a trace of the call stack.
// Arguments:
//	line    - the line number where this call was made
//	keyword - keyword to test against
// Returns:
// Errors:
// Preconditions:

void
dbug_routine::db_traceprint(int line, const char *keyword)
{
	// return if no debugging yet
	if (NOT db_debugon())
		return;

	// If the specified keyword is enabled
	if (db_keyword(keyword)) {
		// perform setup for using db_printf
		db_pargs(line, NULL);

		// Output a header message
		db_printf("Stack Trace");

		// walk the stack of dbug_routine objects
		for (dbug_routine *pdr = this;
		    pdr != NULL;
		    pdr = pdr->d_prev) {
			// output the routine name
			db_printf("  %s() (%s)",
				pdr->d_func, pdr->d_file);
		}
	}
}

// -----------------------------------------------------------------
//
//			db_assert
//
// Description:
//	Called when an assert fails.
//	Prints out a stack trace and aborts.
// Arguments:
//	line	line number assert occurred at
//	msgp	string form of assert code that failed
// Returns:
// Preconditions:
//	precond(msgp)

void
dbug_routine::db_assert(int line, const char *msgp)
{
	if (NOT db_debugon())
		db_push("-#:d");
	db_pargs(line, NULL);
	db_printf("Assertion Failed %s:%s():%d \"%s\"",
		d_file, d_func, line, msgp);
	db_traceprint(line, NULL);
	doabort();
}

// -----------------------------------------------------------------
//
//			db_precond
//
// Description:
//	Called when an precond fails.
//	Prints out a stack trace and aborts.
// Arguments:
//	line	line number precond occurred at
//	msgp	string form of precond code that failed
// Returns:
// Preconditions:
//	precond(msgp)

void
dbug_routine::db_precond(int line, const char *msgp)
{
	if (NOT db_debugon())
		db_push("-#:d");
	db_pargs(line, NULL);
	db_printf("Precondition Failed %s:%s():%d \"%s\"",
		d_file, d_func, line, msgp);
	db_traceprint(line, NULL);
	doabort();
}

// ------------------------------------------------------------
//
//		dbug_routine::db_push
//
// Description:
//	Push current debugger state and set up a new one.
//	Returns NULL if no errors, an error string if there
//	is an error.

const char *
dbug_routine::db_push(const char *control)
{
	char *dupcontrol = NULL;
	dbug_state *pst;

#ifdef _REENTRANT
	mutex_lock(&mdt_lock);
#endif
	char *res = NULL;

	// error if the control string is NULL
	if (control == NULL) {
		res = "mdbug: control string is NULL";
		goto out;
	}

	// turn debugging flag off
	sd_on = FALSE;

	// get the level from the old state if it exists
	int level;
	if (sd_push == NULL)
		level = 0;
	else
		level = sd_push->s_level;

	// Create a new state
	pst = new dbug_state(level);
	if (pst == NULL) {
		res = "mdbug: out of memory, dbug_state";
		goto out;
	}

	// add it to our list of states and make it the current one
	pst->s_next = sd_push;
	sd_push = pst;

	// Strip off -# if in the control string
	if ((*control == '-') && (*(control+1) == '#'))
		control += 2;

	// make a copy of the control string so we can modify it with strtok
	dupcontrol = strdup(control);
	if (dupcontrol == NULL) {
		res = "mdbug: out of memory, strdup";
		goto out;
	}

	// parse the control string
	register char *scan;
	int retval;
	for (scan = mystrtok(dupcontrol, ":");
	    scan != NULL;
	    scan = mystrtok(NULL, ":")) {
		switch (*scan++) {
		case 'd':			// debugging on
			sd_on = TRUE;
			pst->sf_debug = TRUE;
			if (*scan++ == ',') {
				retval = listparse(scan, &pst->s_keywords);
				if (retval < 0) {
					res = "mdbug: -d too many keywords";
					goto out;
				}
			}
			break;

		case 'D': 			// specify delay value
			pst->s_delay = 0;
			if (*scan++ == ',') {
				flist temp;
				retval = listparse(scan, &temp);
				if (retval < 0) {
					res = "mdbug: -D too many delays";
					goto out;
				}
				if (temp.fl_count() > 0) {
					pst->s_delay = delayarg(
					    atoi((char *)temp.fl_top()));
				}
				temp.fl_clear();
			}
			break;

		case 'f': 			// list of functions to watch
			if (*scan++ == ',') {
				retval = listparse(scan, &pst->s_functions);
				if (retval < 0) {
					res = "mdbug: -f too many functions";
					goto out;
				}
			}
			break;

		case 'F': 		// print file name with dbug output
			pst->sf_file = TRUE;
			break;

		case 'i': 			// print pid with dbug output
			pst->sf_pid = TRUE;
			break;

		case 'L':		// print line numbers with dbug output
			pst->sf_line = TRUE;
			break;

		case 'n': 			// print function call depth
			pst->sf_depth = TRUE;
			break;

		case 'N': 		// number each line of dbug output
			pst->sf_number = TRUE;
			break;

		case 'o': 		// specifies output file for dbug
			if (*scan++ == ',') {
				flist temp;
				retval = listparse(scan, &temp);
				if (retval < 0) {
					res = "mdbug: -o too many"
					    " output files";
					goto out;
				}

				if (temp.fl_count() > 0) {
					pst->s_out_file =
					    openfile((char *)temp.fl_top());
					if (pst->s_out_file != NULL)
						pst->sf_didopen = 1;
				} else
					pst->s_out_file = openfile(NULL);
				temp.fl_clear();
			} else
				pst->s_out_file = openfile(NULL);
			if (pst->s_out_file == NULL) {
				res = "mdbug: -o cannot open output file";
				goto out;
			}
			break;

		case 'p':			// debug specified processes
			if (*scan++ == ',') {
				retval = listparse(scan, &pst->s_processes);
				if (retval < 0) {
					res = "mdbug: -p too many processes";
					goto out;
				}
			}
			break;

		case 'P': 		// print process name on dbug output
			pst->sf_process = TRUE;
			break;

		case 'r': 			// reset indentation to zero
			pst->s_level = 0;
			break;

		case 's': 			// print stack depth on enter
			pst->sf_stack = TRUE;
			break;

		case 'R':		// print time program has been running
			pst->sf_time = TRUE;
			time(&pst->s_starttime);
			break;

		case 'T':		// print thread information
			pst->sf_thread = TRUE;
			break;

		case 't': 		// print trace of functions called
			pst->sf_trace = TRUE;
			pst->s_maxdepth = MAXDEPTH;
			if (*scan++ == ',') {
				flist temp;
				retval = listparse(scan, &temp);
				if (retval < 0) {
					res = "mdbug: -t too many traces";
					goto out;
				}
				if (temp.fl_count() > 0) {
					pst->s_maxdepth =
					    atoi((char *)temp.fl_top());
				}
				temp.fl_clear();
			}
			break;
		}
	}

out:
	// free up the dupped control string
	free(dupcontrol);

#ifdef _REENTRANT
	mutex_unlock(&mdt_lock);
#endif

	// return result
	return (res);
}

// ------------------------------------------------------------
//
//		dbug_routine::db_pop
//
// Description:
//	Pop the debug stack.

void
dbug_routine::db_pop()
{
	dbug_state *pst;

#ifdef _REENTRANT
	mutex_lock(&mdt_lock);
#endif

	// return if no debugging yet
	if (sd_push == NULL)
		goto out;

	// get and remove the top item from the list
	pst = sd_push;
	sd_push = pst->s_next;

	// Delete the item.
	delete pst;

	// get the current top of the stack
	pst = sd_push;
	if (pst) {
		// See if debugging is turned on
		if (pst->sf_debug)
			sd_on = TRUE;
		else
			sd_on = FALSE;
	}

out:;
#ifdef _REENTRANT
	mutex_unlock(&mdt_lock);
#endif
}

// -----------------------------------------------------------------
//
//			db_process
//
// Description:
//	Specifies the name of the process.
//	Only the pointer is saved, the string is not copied.
// Arguments:
//	namep
// Returns:
// Preconditions:

void
dbug_routine::db_process(const char *namep)
{
	sd_process = namep;

	thread_data *tdp;
#ifdef _REENTRANT
	thr_getspecific(mdt_key, (void **)&tdp);
#else
	tdp = &mdt_data;
#endif
	tdp->td_stackinit = (u_long)this;
}

// ------------------------------------------------------------
//
//			listparse
//
// Description:
//	parse list of modifiers in debug control string
//
//	Given pointer to a comma separated list of strings in "cltp",
//	parses the list, building a list and returning a pointer to it.
//	The original comma separated list is destroyed in the process of
//	building the linked list, thus it had better be a duplicate
//	if it is important.
//
//	This routine is only called from db_push.
//	Returns 0 for success, -1 for failure.

static int
listparse(register char *ctlp, flist *head)
{
	// scan the string until end
	while (*ctlp != '\0') {
		// See if no more room on the list
		if (head->fl_space() == 0)
			return (-1);

		// save the begining of this section
		char *start = ctlp;

		// loop until the end of the token is found
		while ((*ctlp != '\0') && (*ctlp != ','))
			ctlp++;

		// add a string terminator if necessary, for strdup
		if (*ctlp == ',')
			*ctlp++ = '\0';

		// make a copy of the string
		char *item = strdup(start);
		if (item == NULL)
			return (-1);

		// add it to the list
		head->fl_push(item);
	}

	return (0);
}

// ------------------------------------------------------------
//
//			inlist
//
// Description:
//	Tests the string pointed to by "cp" to determine if it is in
//	the list pointed to by "linkp".  Linkp points to the first
//	link in the list.  If linkp is empty then the string is treated
//	as if it is in the list (I.E all strings are in the null list).
//	This may seem rather strange at first but leads to the desired
//	operation if no list is given.  The net effect is that all
//	strings will be accepted when there is no list, and when there
//	is a list, only those strings in the list will be accepted.

static boolean
inlist(flist *linkp, const char *cp)
{
	register boolean accept;

	if ((linkp == NULL) || (linkp->fl_count() == 0) || (cp == NULL))
		accept = TRUE;
	else {
		accept = FALSE;

		// walk the list of items
		for (register char *item = (char *)linkp->fl_top();
		    item != NULL;
		    item = (char *)linkp->fl_next()) {
			// see if a match
			if (strcmp(item, cp) == 0) {
				accept = TRUE;
				break;
			}
		}
	}

	return (accept);
}

// ------------------------------------------------------------
//
//			dotrace
//
// Description:
//	Checks to see if tracing is enabled based on whether the
//	user has specified tracing, the maximum trace depth has
//	not yet been reached, the current function is selected,
//	and the current process is selected.  Returns TRUE if
//	tracing is enabled, FALSE otherwise.

static boolean
dotrace(dbug_state *pst, const char *func, const char *process)
{
	boolean trace;

	trace = FALSE;
	if (pst->sf_trace) {
		if (pst->s_level <= pst->s_maxdepth) {
			if (inlist(&pst->s_functions, func)) {
				if (inlist(&pst->s_processes, process)) {
					trace = TRUE;
				}
			}
		}
	}

	return (trace);
}

// ------------------------------------------------------------
//
//			indent
//
// Description:
//	Indent a line to the given level.  Note that this is
//	a simple minded but portable implementation.
//	There are better ways.
//
//	Also, the indent must be scaled by the compile time option
//	of character positions per nesting level.

static void
indent(register dbug_state *pst, int indent)
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
	fprintf(pst->s_out_file, buffer);
	fflush(pst->s_out_file);
}

// ------------------------------------------------------------
//
//			doprefix
//
// Description:
//	Print prefix common to all debugger output lines, prior to
//	doing indentation if necessary.  Print such information as
//	current process name, current source file name and line number,
//	and current function nesting depth.

static void
doprefix(dbug_state *pst, int line, long lineno,
    const char *file, const char *process)
{
#if DBUG_UNIX
	if (pst->sf_pid)
		fprintf(pst->s_out_file, "%5d: ", getpid());
#endif

	if (pst->sf_thread)
		fprintf(pst->s_out_file, "%5ld: ", thr_self());

	if (pst->sf_number)
		fprintf(pst->s_out_file, "%5ld: ", lineno);

	if (pst->sf_process && process)
		fprintf(pst->s_out_file, "%s: ", process);

	if (pst->sf_file)
		fprintf(pst->s_out_file, "%14s: ", file);

	if (pst->sf_line)
		fprintf(pst->s_out_file, "%5d: ", line);

	if (pst->sf_depth)
		fprintf(pst->s_out_file, "%4d: ", pst->s_level);

	fflush(pst->s_out_file);
}

// ------------------------------------------------------------
//
//			openfile
//
// Description:
//	Given name of a new file (or NULL for stdout) opens the file
//	and sets the output stream to the new file.

static FILE *
openfile(char *name)
{
	FILE *fp;
	boolean newfile;

	if (name == NULL)
		return (stdout);

	if (NOT writable(name))
		return (NULL);

	// see if the file already exists
	if (file_exists(name))
		newfile = FALSE;
	else
		newfile = TRUE;

	// open the file
	fp = fopen(name, "a+");
	if (fp == NULL)
		return (NULL);

	// If the file is newly created, give it away to the user
	// that started the program.
	if (newfile) {
		changeowner(name);
	}
	return (fp);
}

// ------------------------------------------------------------
//
//			writable
//
// Description:
//	Because the debugger might be linked in with a program that
//	runs with the set-uid-bit (suid) set, we have to be careful
//	about opening a user named file for debug output.  This consists
//	of checking the file for write access with the real user id,
//	or checking the directory where the file will be created.
//
//	Returns TRUE if the user would normally be allowed write or
//	create access to the named file.  Returns FALSE otherwise.

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

// ------------------------------------------------------------
//
//			changeowner
//
// Description:
//	For unix systems, change the owner of the newly created debug
//	file to the real owner.  This is strictly for the benefit of
//	programs that are running with the set-user-id bit set.
//
//	Note that at this point, the fact that pathname represents
//	a newly created file has already been established.  If the
//	program that the debugger is linked to is not running with
//	the suid bit set, then this operation is redundant (but
//	harmless).

static void
changeowner(char *pathname)
{
#if DBUG_UNIX
	chown(pathname, getuid(), getgid());
#endif
}

// ------------------------------------------------------------
//
//			delayarg
//
// Description:
//	Converts delay argument, given in tenths of a second, to the
//	appropriate numerical argument used by the system to delay
//	that that many tenths of a second.  For example, on the
//	amiga, there is a system call "Delay()" which takes an
//	argument in ticks (50 per second).  On unix, the sleep
//	command takes seconds.  Thus a value of "10", for one
//	second of delay, gets converted to 50 on the amiga, and 1
//	on unix.  Other systems will need to use a timing loop.

static int
delayarg(int value)
{
	unsigned int delayarg = 0;

#if (unix || xenix)
	delayarg = value / 10;		/* Delay is in seconds for sleep () */
#endif
	return (delayarg);
}

// ------------------------------------------------------------
//
//			delay
//
// Description:
//	Implements the delay function.
/*
 *	A dummy delay stub for systems that do not support delays.
 *	With a little work, this can be turned into a timing loop.
 */

static void
delay(u_int xx)
{
#if (unix || xenix)
	sleep(xx);
#endif
#if amiga
	Delay(xx);
#endif
#ifdef __ZTC__
	msleep((u_long)xx);
#endif
}

// ------------------------------------------------------------
//
//			getclock
//
// Description:
//	Returns the time in milliseconds used by this process
//	so far.

#if (unix || xenix)

#include <sys/param.h>
#if BSD4_3 || sun

#include <sys/time.h>
#include <sys/resource.h>

static u_long
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

static u_long
getclock()
{
	return (0);
}

#endif
#endif	/* unix */

#ifdef MSDOS
static u_long
getclock()
{
	return (clock() * 10);
}
#endif

// ------------------------------------------------------------
//
//			mystrtok
//
// Description:
//	A version of strtok for those systems without it

static char *
mystrtok(char *s1, char *s2)
{
	static char *end = NULL;
	register char *rtnval;

	rtnval = NULL;
	if (s2 != NULL) {
		if (s1 != NULL) {
			end = s1;
			rtnval = mystrtok((char *) NULL, s2);
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

// -----------------------------------------------------------------
//
//			dbug_thread_exit
//
// Description:
//	Called when a thread exits.
// Arguments:
//	data	pointer to thread specific data
// Returns:
// Preconditions:

void
dbug_routine::dbug_thread_exit(void *data)
{
	dbug_state *pst;

#ifdef _REENTRANT
	mutex_lock(&mdt_lock);
#endif

	// If debugging is off, then nothing else to do
	if (NOT db_debugon())
		goto out;

	// get a pointer to the active state
	pst = sd_push;

	if (pst->sf_thread) {
		doprefix(pst, 0, sd_lineno++, "unknown", sd_process);
		indent(pst, pst->s_level);
		fprintf(pst->s_out_file, "thread destroyed\n");
		fflush(pst->s_out_file);
		delay(pst->s_delay);
	}

out:;
#ifdef _REENTRANT
	free(data);
	mutex_unlock(&mdt_lock);
#endif
}

// -----------------------------------------------------------------
//
//			doabort
//
// Description:
//	Causes the process to exit immediatly with a core dump.
// Arguments:
// Returns:
// Preconditions:

static void
doabort()
{
	for (;;) {
		kill(getpid(), SIGABRT);
		(void) signal(SIGABRT, SIG_DFL);
		(void) sigrelse(SIGABRT);
	}
}

// -----------------------------------------------------------------
//
//			dbug_state::dbug_state
//
// Description:
//	Constructor for the dbug_state class.
// Arguments:
//	The current level in the call stack.
// Returns:
// Preconditions:

dbug_state::dbug_state(int level)
{
	sf_trace = 0;
	sf_debug = 0;
	sf_file = 0;
	sf_line = 0;
	sf_depth = 0;
	sf_process = 0;
	sf_number = 0;
	sf_pid = 0;
	sf_stack = 0;
	sf_time = 0;
	sf_didopen = 0;
	sf_thread = 0;
	s_maxdepth = MAXDEPTH;
	s_delay = 0;
	s_level = level;
	s_starttime = 0;
	s_out_file = stderr;
	s_next = NULL;
}

// -----------------------------------------------------------------
//
//			dbug_state::~dbug_state
//
// Description:
//	Destructor for the dbug_state class.
// Arguments:
// Returns:
// Preconditions:

dbug_state::~dbug_state()
{
	if (sf_didopen)
		fclose(s_out_file);
}

#endif /* DBUG_OFF */
