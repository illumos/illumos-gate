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



#include "Trace.h"
#include <cstdarg>
#include <string>
#include <cstdio>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

using namespace std;

/**
 * Tracking for the stacks
 */
vector<vector<Trace *> > Trace::stacks;

/**
 * The indentation string for output
 */
vector<string> Trace::indent;

#define MAX_MSG_PREFIX_LEN 128
#define	CTIME_LEN	26
#define	DEBUG_FILE	"/var/adm/sun_fc.debug"
#define	LOG_FILE	"/var/adm/sun_fc"

/**
 * @memo	    Log a message
 * @param	    priority The priority of the message (see syslog man page)
 * @param	    msg The message string
 * 
 * @doc		    If the debug file is present, we will log everything to
 *		    that file.  Otherwise, if the normal log file is present,
 *		    we'll log all non-debug messages to that file.  Lastly,
 *		    if neither file is present, the message will be
 *		    silently discarded.
 */
void Trace::message(int priority, const char *msg) {
	char prefix[MAX_MSG_PREFIX_LEN];
	char message[MAX_MSG_PREFIX_LEN + MAX_MSG_LEN + 2];
	int fd;
	// char time[CTIME_LEN+1];
	std::string priString;


	/* If we can open the log file, write there, else use the cim log */
	fd = open(DEBUG_FILE, O_WRONLY|O_APPEND); /* will only open if exists */
	if (fd == -1) {
	    /* No debug file, how about the log file? */
	    if (priority == LOG_DEBUG) {
		return; /* Ignore debug */
	    }
	    fd = open(LOG_FILE, O_WRONLY|O_APPEND);
	    /* We catch open failures later */
	}

	// now(time);
	/* First interpret the priority value */
	switch (priority) {
	case INTERNAL_ERROR:
	    priString = "INTERNAL";
	    break;
	case STACK_TRACE:
	    priString = "STACK";
	    break;
	case IO_ERROR:
	    priString = "IO";
	    break;
	case USER_ERROR:
	    priString = "USER";
	    break;
	case LOG_DEBUG:
	    priString = "DEBUG";
	    break;
	default:
	    priString = "UNKNOWN";
	    break;
	}

	if (fd != -1) {
	    /* Format the prefix string for the log file */
	    snprintf(prefix, MAX_MSG_PREFIX_LEN, "%d:%d:%s%s:%s",
		time(NULL),
		tid,
		indent[tid].c_str(),
		routine.c_str(),
		priString.c_str());

	    /* Format the message string for the log file */
	    snprintf(message, strlen(prefix) + MAX_MSG_LEN + 2, "%s:%s\n",
		prefix,
		msg);
	    write(fd, message, strlen(message));
	    close(fd);
	} /* Else discard the log message */
}

/**
 * @memo	    Create a new Trace instance and update stack.
 * @param	    myRoutine The name of the routine 
 * 
 * @doc		    This class was developed to provide a Java
 *		    like stack trace capability, as C++ does not provide
 *		    a run-time stack lookup feature.  Instances of the
 *		    Trace class should be created on the stack so they
 *		    will be automatically freed when the stack is popped
 *		    when the function returns.
 */
Trace::Trace(std::string myRoutine) : routine(myRoutine) {
	tid = pthread_self();
	if (stacks.size() < tid+1) {
	    stacks.resize(tid+1);
	    indent.resize(tid+1);
	    indent[tid] = "";
	}
	message(LOG_DEBUG, "entered");
	stacks[tid].push_back(this);
	indent[tid] += " ";
}

/**
 * @memo	    Delete a trace instances and update the stack
 */
Trace::~Trace() {
	string::size_type len = indent[tid].size();
	if (len > 0) {
	    indent[tid].resize(len - 1);
	}
	message(LOG_DEBUG, "exited");
	stacks[tid].pop_back();
}

/**
 * @memo	    Print out the current stack trace information
 */
void Trace::stackTrace() {
	message(STACK_TRACE, "Stack trace follows");
	for (vector<Trace *>::size_type i = stacks[tid].size() - 1; ; i--) {
	    string msg = "	    ";
	    msg += (stacks[tid])[i]->label();
	    message(STACK_TRACE, msg.c_str());
	    if (i == 0) {
		break;
	    }
	}
}
