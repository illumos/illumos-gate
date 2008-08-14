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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _ML_PUB_
#define	_ML_PUB_
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ERROR_H
#include <errno.h>
#endif

#ifndef _DB_DEFS_API_
#include "db_defs.h"
#endif


#define	MNOMSG		MMSG(0, "")
#if defined(_lint)

#define	MMSG(num, fmt)		num, fmt
#define	MLOG(args)		ml_lint_event args
#define	MLOGDB(args)		ml_lint_db args
#define	MLOGU(args)		ml_lint_unexpected args
#define	MLOGERRNO(args)		ml_lint_errno args
#define	MLOGSIGNAL(args)		ml_lint_signal args
#define	MLOGCSI(args)  	ml_lint_csi args
#define	MLOGDEBUG(debug_lvl, args)		ml_lint_event args;

#else

#define	MMSG(num, fmt) fmt

#define	MLOG(args)		do {     \
	ml_file_name = __FILE__; ml_line_num  = __LINE__; \
	ml_file_id = SccsId; ml_log_event args; } while (0)

#define	MLOGDB(args)		do {     \
	ml_file_name = __FILE__; ml_line_num  = __LINE__; \
	ml_file_id = SccsId; ml_log_db args; } while (0)

#define	MLOGU(args)		do {     \
	ml_file_name = __FILE__; ml_line_num  = __LINE__; \
	ml_file_id = SccsId; ml_log_unexpected args; } while (0)

#define	MLOGERRNO(args)		do {     \
	ml_file_name = __FILE__; ml_line_num  = __LINE__; \
	ml_file_id = SccsId; ml_log_errno args; } while (0)

#define	MLOGSIGNAL(args)		do {     \
	ml_file_name = __FILE__; ml_line_num  = __LINE__; \
	ml_file_id = SccsId; ml_log_signal args; } while (0)

#define	MLOGCSI(args)		do {     \
	ml_file_name = __FILE__; ml_line_num  = __LINE__; \
	ml_file_id = SccsId; ml_log_csi args; } while (0)

#ifdef DEBUG
#define	MLOGDEBUG(debug_lvl, print_str) do { \
	if TRACE(debug_lvl) {            \
	MLOG(print_str);	   \
	}                                \
	} while (0)
#else
#define	MLOGDEBUG(debug_lvl, print_str) \
	;
#endif

#endif


#define	CL_ASSERT(n, x)	{  \
	if (!(x))	{                                                  \
	MLOG((MMSG(1190, ("%s: Assertion %s failed, file %s, line %d.")),   \
	n, #x, __FILE__, __LINE__));			                    \
	return (STATUS_PROCESS_FAILURE);                                    \
	}                                                                   \
}


extern char		*ml_file_name;
extern char		*ml_file_id;
extern int 	ml_line_num;


void ml_lint_db(char *, int, char *, ...);
void ml_lint_event(int, char *, ...);
void ml_lint_errno(int, char *, ...);
void ml_lint_signal(int, int, char *, ...);
void ml_lint_unexpected(char *, char *, STATUS, int, char *, ...);
void ml_lint_csi(STATUS, char *, char *, int, char *, ...);

#ifdef NOT_CSC
void		ml_log_db(char *caller, int msgno, ...);
void		ml_log_event(int msgno, ...);
void		ml_log_errno(int msgno, ...);
void		ml_log_signal(int i_signal, int i_msgno, ...);
void		ml_log_unexpected(char *caller, char *callee,
			STATUS status, int msgno, ...);
void		ml_log_csi(STATUS status, char *caller, char *callee,
				int msgno, ...);
STATUS ml_msg_initialize(char *);
void		ml_output(const char *cp_message);
void		ml_output_register(void (*funcptr)(const char *));
void		ml_start_message(char *);


void		ml_log_db(char *caller, int msgno, ...);
void		ml_log_event(char *cp_fmt, ...);
void		ml_log_errno(int msgno, ...);
void		ml_log_signal(int i_signal, int i_msgno, ...);
void		ml_log_unexpected(char *caller, char *callee,
			STATUS status, char *cp_fmt, ...);
void		ml_log_csi(STATUS status, char *caller, char *callee,
			char *cp_fmt, ...);
STATUS ml_msg_initialize(char *);
void		ml_output(const char *cp_message);
void		ml_output_register(void (*funcptr)(const char *));
void		ml_start_message(char *);
#endif


#ifdef __cplusplus
}
#endif
#endif /* _ML_PUB_ */
