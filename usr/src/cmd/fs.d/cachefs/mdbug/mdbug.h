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
 *			mdbug.h
 *
 *	Include file for the mdbug class.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* Copyright (c) 1994 by Sun Microsystems, Inc. */

/*
 * .LIBRARY base
 * .NAME mdbug - macros for debugging C++ programs.
 * .FILE dbug.cc
 * .FILE mdbug.h
 */

/*
 * .SECTION Description
 * The mdbug package provides a set of macros for debugging C++ programs.
 * Features include tracing function entry and exit points, printing
 * of debug messages, and heap corruption detection.  All features can
 * be selectively enabled at run time using command line options.  Also
 * defining the macro DBUG_OFF removes all mdbug code from the compilation.
 */

#ifndef MDBUG_H
#define	MDBUG_H

#define	DBUG_STMT(A) do { A } while (0)

#ifndef DBUG_OFF
#define	DBUG_LENGTH 64
typedef struct dbug_object {
	char	d_func[DBUG_LENGTH];		/* Name of current function. */
	char	d_file[DBUG_LENGTH];		/* Name of current file. */
	struct dbug_object	*d_prev;	/* dbug_routine object */
	int	 d_leaveline;			/* Exit line from routine. */
} dbug_object_t;

void dbug_object_create();
void dbug_object_destroy(char *function_name, int line);
int db_keyword(dbug_object_t *dbug_object_p, const char *keyword);
void db_pargs(dbug_object_t *dbug_object_p, int line, char *keyword);
void db_printf(char *keyword, char *format, ...);
void db_traceprint(int line, const char *keyword);
void db_assert(dbug_object_t *dbug_object_p, int line, const char *msgp);
void db_precond(dbug_object_t *dbug_object_p, int line, const char *msgp);
char *db_push(const char *control);
void db_pop();
void db_process(const char *namep);
void dbug_thread_exit(void *data);
dbug_object_t *db_get_dbug_object_p();
void doabort();


#define	dbug_enter(A)		dbug_object_create(__LINE__, __FILE__, A)
#define	dbug_leave(A)		dbug_object_destroy(A, __LINE__)
#define	dbug_traceprint(KEY)	db_traceprint(__LINE__, KEY)
#define	dbug_push(A)		db_push(A)
void	dbug_pop();
#define	dbug_process(A)		db_process(A)
void	dbug_assert();
#define	dbug_assert(A)\
	if (!(A)) { db_assert(db_get_dbug_object_p(), __LINE__, ""); }
#define	dbug_precond(A)\
	if (!(A)) { db_precond(db_get_dbug_object_p(), __LINE__, ""); }
void	dbug_execute();
#define	dbug_print(A)		db_printf A
int	db_debugon();

#else /* if DBUG_OFF */

#define	dbug_enter(A)			0
#define	dbug_leave(A)			0
#define	dbug_traceprint(KEY)		0
#define	dbug_push(A)			0
#define	dbug_pop()			0
#define	dbug_process(A)			0
#define	dbug_execute(KEY, CODE)		0
#define	dbug_print(A)
#define	dbug_assert(A)			0
#define	dbug_precond(A)			0
#define	db_debugon()			0

#endif /* DBUG_OFF */
#endif /* MDBUG_H */
