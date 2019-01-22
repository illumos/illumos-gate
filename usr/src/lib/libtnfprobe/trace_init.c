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

/*
 * Includes
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <assert.h>
#include <limits.h>
#include <values.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/param.h>

#include <thread.h>
#include <sys/lwp.h>
#include <errno.h>

#include "tnf_trace.h"


/*
 * Defines
 */
#define	TNF_FILE_MODE	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/*
 * Declarations
 */

extern void thr_probe_setup(void *);
#pragma weak thr_probe_setup

/*
 * Globals
 */

static TNFW_B_CONTROL __tnfw_b_control_local = {
	TNFW_B_NOBUFFER,
	NULL,
	_tnf_trace_initialize,
	_tnf_fork_thread_setup,
	0
};

TNFW_B_CONTROL *_tnfw_b_control = &__tnfw_b_control_local;

static char    *file_start;

/*
 * Two Project Private Interfaces between prex and libtnfprobe -
 * tnf_trace_file_name and tnf_trace_file_size (three now ...)
 */
char		tnf_trace_file_name[MAXPATHLEN] = "";
uint_t		tnf_trace_file_size = 4194304;	/* 4 Meg */
uint_t		tnf_trace_file_min = (128 * 1024);

tnf_ops_t	tnf_trace_initial_tpd = {
	TNF_ALLOC_REUSABLE,	/* mode			 */
	tnfw_b_alloc,		/* alloc		 */
	tnfw_b_xcommit,		/* commit		 */
	tnfw_b_xabort,		/* rollback		 */
	{
		B_FALSE		/* tnfw_w_initialized	 */
		/* rest of struct is null */
	},
	0			/* busy			 */
};

/*
 * tnf_process_enable: exported API to turn on tracing for the process
 *			(on by default).
 */
void
tnf_process_enable(void)
{
	TNFW_B_UNSET_STOPPED(_tnfw_b_control->tnf_state);
}

/*
 * tnf_process_disable: exported API to turn off tracing for the process.
 */
void
tnf_process_disable(void)
{
	TNFW_B_SET_STOPPED(_tnfw_b_control->tnf_state);
}

/*
 * _tnf_trace_initialize
 *	prex is responsible for creating and zeroing the trace file.  So,
 *	this routine expects the file to be there.  It does try to handle
 *	the case where prex (run as root) for probing a setuid root program
 *	created the trace file as root.  But, by the time the first probe is
 *	hit (and this function is called), the program has reduced it's
 *	privilege to its real user id - so the open fails.  In this case,
 *	this function unlinks the trace file and creates it again with its
 *	current user id.  The unlink can fail if the user does not have
 *	write permission in the directory where the trace file is - if so,
 *	tracing is set to broken.
 */
int
_tnf_trace_initialize(void)
{
	int		fd;
	int		created_file = 0;
	static mutex_t	init_mutex = DEFAULTMUTEX;

	/*
	 * if this is a MT program and the primordial thread hasn't been
	 * setup yet, can't start tracing yet - THREAD_REG hasn't been
	 * initialized, so we can't call open() in libthread.
	 */

	/*
	 * Use dlsym to check for the present of thr_probe_setup.
	 */

	if ((((int(*)())dlsym(RTLD_DEFAULT, "thr_probe_setup")) != NULL) &&
	    (thr_main() == -1)) {
		return (0);
	}

	/*
	 * lock is needed to to prevent multiple threads from
	 * mmapping the file.
	 */
	mutex_lock(&init_mutex);
	if (_tnfw_b_control->tnf_state != TNFW_B_NOBUFFER) {
		mutex_unlock(&init_mutex);
		return (1);
	}

	_tnfw_b_control->tnf_pid = getpid();
	assert(tnf_trace_file_name[0] != '\0');
	fd = open(tnf_trace_file_name, O_RDWR, TNF_FILE_MODE);
	if (fd < 0) {
		if (errno == EACCES) {
			/*
			 * fix for bug 1197494: permission denied when
			 * trying to open the file - happens for setuid root
			 * programs - prex creates the file with root ownership
			 */
			if (unlink(tnf_trace_file_name) == -1) {
				goto SetBroken;
			}
			/* try creating it rather than opening it */
			fd = open(tnf_trace_file_name,
			    O_CREAT | O_RDWR | O_TRUNC, TNF_FILE_MODE);
			if (fd < 0) {
				goto SetBroken;
			}
			/*
			 * expand file to needed size - ftruncate is not
			 * portable, hence using lseek + write.
			 */
			if (lseek(fd, tnf_trace_file_size-1, SEEK_SET) == -1) {
				goto SetBroken;
			}
			if (write(fd, "", 1) != 1) {
				goto SetBroken;
			}
			created_file = 1;
		} else {
			goto SetBroken;
		}
	}

	/* mmap the file */
	if ((file_start = mmap(0, tnf_trace_file_size,
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == (caddr_t)-1) {
		goto SetBroken;
	}
	if (created_file == 1) {
		/* explicitly zero the file XXX - performance problem */
		(void) memset(file_start, 0, tnf_trace_file_size);
	}
	_tnfw_b_control->tnf_buffer = file_start;

	if (tnfw_b_init_buffer(file_start, tnf_trace_file_size / TNF_BLOCK_SIZE,
	    TNF_BLOCK_SIZE, B_TRUE) != TNFW_B_OK) {
		goto SetBroken;
	}

	/* successful return */
	_tnfw_b_control->tnf_state = TNFW_B_RUNNING;
	mutex_unlock(&init_mutex);
	return (1);

SetBroken:
	_tnfw_b_control->tnf_state = TNFW_B_BROKEN;
	mutex_unlock(&init_mutex);
	return (0);

}

/*
 * _tnf_sched_init
 */

void
_tnf_sched_init(tnf_schedule_t *sched, hrtime_t t)
{
	thread_t tid = 0;

	sched->time_base = t;
	/* thr_self() is stubbed out by libc for a non-threaded pgm */
	tid = thr_self();
	sched->tid = tid;
	sched->lwpid = _lwp_self();
	sched->pid = getpid();
}
