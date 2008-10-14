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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TRACE_H
#define	_TRACE_H



#include <cstdarg>
#include <string>
#include <vector>
#include <stack>
#include <pthread.h>

#ifndef	MAX_MSG_LEN
#define	MAX_MSG_LEN 2048
#endif

/*
 * @memo	    Tracing, Logging, and debugging facility
 * @field	    ONE_FIELD_DESCRIPTION
 *
 * @doc		    The Trace class provides stack tracing, and basic
 *		    logging/debugging facilities.
 */
class Trace {
public:
	Trace(std::string myRoutine);

	~Trace();

	std::string label() {
	    return (routine);
	}

	void noMemory() {
	    message(1, "Out of memory");
	}

	void debug(const char *fmt, ...) {
	    char msg[MAX_MSG_LEN];
	    va_list ap;
	    va_start(ap, fmt);
	    vsnprintf(msg, sizeof (msg), fmt, ap);
	    message(LOG_DEBUG, msg);
	    va_end(ap);
	}

	void genericIOError(const char *fmt, ...) {
	    char msg[MAX_MSG_LEN];
	    va_list ap;
	    va_start(ap, fmt);
	    vsnprintf(msg, sizeof (msg), fmt, ap);
	    message(IO_ERROR, msg);
	    va_end(ap);
	}

	void internalError(const char *fmt, ...) {
	    char msg[MAX_MSG_LEN];
	    va_list ap;
	    va_start(ap, fmt);
	    vsnprintf(msg, sizeof (msg), fmt, ap);
	    message(INTERNAL_ERROR, msg);
	    va_end(ap);
	}

	void userError(const char *fmt, ...) {
	    char msg[MAX_MSG_LEN];
	    va_list ap;
	    va_start(ap, fmt);
	    vsnprintf(msg, sizeof (msg), fmt, ap);
	    message(USER_ERROR, msg);
	    va_end(ap);
	}

	void stackTrace();

private:
	std::string routine;
	pthread_t	tid;
	static const int INTERNAL_ERROR = 3;
	static const int STACK_TRACE = 4;
	static const int IO_ERROR = 5;
	static const int USER_ERROR = 6;
	static const int LOG_DEBUG = 7;
	void message(int priority, const char *msg);
	static std::vector<std::vector<Trace *> > stacks;
	static std::vector<std::string> indent;
};

#endif /* _TRACE_H */
