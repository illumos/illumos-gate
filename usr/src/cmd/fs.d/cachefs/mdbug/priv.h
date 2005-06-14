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
 *
 *			priv.h
 *
 *    Internal header file for the mdbug package.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* Copyright (c) 1994 by Sun Microsystems, Inc. */

/*
 * .LIBRARY base
 * .NAME dbug_state - used by dbug_routine to maintain state
 *
 * .SECTION Description
 * The dbug_state class is used by the dbug_routine class to maintain
 * state established by the dbug_push() macro.
 * The priv.h include file is also used to store constructs used internally
 * by the mdbug package.
 */

#ifndef PRIV_H
#define	PRIV_H

/* DBUG_DOS or DBUG_UNIX should be defined in the makefile to 1 */

/* Define various shorthand notations. */
#define	boolean int
#define	TRUE 1
#define	FALSE 0
#define	NOT !
#define	XOR ^
#define	MAX(x, y) (((x) > (y)) ? (x) : (y))
#define	MIN(x, y) (((x) > (y)) ? (y) : (x))

/* Determine which way the stack grows */
#if DBUG_DOS || DBUG_UNIX
const int GROWDOWN = TRUE;
#else
const int GROWDOWN = FALSE;
#endif

/* Manifest constants which may be "tuned" if desired. */
#define	PRINTBUF	1024	/* Print buffer size */
#define	INDENT		4	/* Indentation per trace level */
#define	MAXDEPTH	200	/* Maximum trace depth default */

boolean file_exists(const char *pathname);
boolean file_writable(const char *pathname);

/*
 * This class is used to maintain the state established by the
 * push call.
 */
typedef struct dbug_state_object {

	boolean	 sf_trace:1;	/* TRUE if tracing is on */
	boolean	 sf_debug:1;	/* TRUE if debugging is on */
	boolean	 sf_file:1;	/* TRUE if file name print enabled */
	boolean	 sf_line:1;	/* TRUE if line number print enabled */
	boolean	 sf_depth:1;	/* TRUE if function nest level print enabled */
	boolean	 sf_process:1;	/* TRUE if process name print enabled */
	boolean	 sf_number:1;	/* TRUE if number each line */
	boolean	 sf_pid:1;	/* TRUE if identify each line with pid */
	boolean	 sf_stack:1;	/* TRUE if should print stack depth */
	boolean	 sf_time:1;	/* TRUE if should print time information */
	boolean	 sf_didopen:1;	/* TRUE if opened the log file */
	boolean	 sf_thread:1;	/* TRUE if should print thread information */
	int	 s_maxdepth;	/* Current maximum trace depth */
	int	 s_delay;	/* Delay amount after each output line */
	u_int	 s_level;	/* Current function nesting level */
	time_t	 s_starttime;	/* Time push was done */
	FILE	*s_out_file;	/* Current output stream */
	flist_object_t	*s_functions;	/* List of functions */
	flist_object_t	*s_pfunctions;	/* List of profiled functions */
	flist_object_t	*s_keywords;	/* List of debug keywords */
	flist_object_t	*s_processes;	/* List of process names */

	struct dbug_state_object *s_next; /* pointer to next pushed state */
}dbug_state_object_t;

dbug_state_object_t *dbug_state_create(int);
void dbug_state_destroy(dbug_state_object_t *);

#ifdef _REENTRANT
#define	LOCK_THREAD_DATA()		mutex_lock(&mdt_lock)
#define	ALLOC_THREAD_DATA_PTR(TDP)	db_alloc_thread_data(TDP)
#define	GET_THREAD_DATA_PTR(TDP)	thr_getspecific(mdt_key, (void **)TDP)
#define	UNLOCK_THREAD_DATA()		mutex_unlock(&mdt_lock)
#define	FREE_THREAD_DATA(PTR)		free(PTR)
#else
#define	LOCK_THREAD_DATA()
#define	ALLOC_THREAD_DATA_PTR(TDP)	*TDP = &mdt_data
#define	GET_THREAD_DATA_PTR(TDP)	*TDP = &mdt_data
#define	UNLOCK_THREAD_DATA()
#define	FREE_THREAD_DATA(PTR)
#endif
#endif /* PRIV_H */
