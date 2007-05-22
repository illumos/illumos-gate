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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <thread.h>
#include <pthread.h>
#include <sys/lwp.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#ifdef sparc
#include <setjmp.h>
#endif /* sparc */

#include "tnf_trace.h"

/*
 * Typedefs
 */

typedef tnf_ops_t *(*tnf_context_t)(void);

typedef void * (*start_func_t)(void *arg);

typedef int (*tnf_thr_create_func_t)(void		*stk,
				size_t			stksize,
				start_func_t		startfunc,
				void			*arg,
				long			flags,
				thread_t		*newthread);

typedef int (*tnf_pthread_create_func_t)(pthread_t	*thr,
				const pthread_attr_t	*attr,
				start_func_t		startfunc,
				void *			arg);

typedef void (*tnf_thr_exit_func_t)(void *) __NORETURN;

typedef void (*tnf_pthread_exit_func_t)(void *) __NORETURN;

typedef pid_t (*fork_t)(void);

typedef int (*tnf_thr_stksegment_func_t)(stack_t *s);

typedef struct args {
	start_func_t		real_func;
	void 			*real_arg;
} args_t;

/*
 * Local Declarations
 */

static void * tnf_threaded_test(void 			*dummy,
				tnf_probe_control_t 	*probe_p,
				tnf_probe_setup_t 	*set_p);
static void * tnf_non_threaded_test(void 			*dummy,
					tnf_probe_control_t	*probe_p,
					tnf_probe_setup_t	*set_p);
static tnf_ops_t *tnf_probe_getfunc(void);
static void *probestart(void *arg);
static pid_t common_fork(fork_t real_fork);
static void probe_setup(void *data);
static tnf_ops_t *tnf_get_ops();

/*
 * Static Globals
 */

extern tnf_ops_t 	tnf_trace_initial_tpd;
static void 		*tpd = &tnf_trace_initial_tpd;
#ifdef sparc
static size_t		tnf_probe_dsize = 0;
#endif /* sparc */

/*
 * Project Private interfaces:
 * 	These are interfaces between prex and libtnfw, or
 * 	between libtnfw and libtthread.
 */

/* variable indicates if libtnfw has sync'ed up with libthread or not */
long			__tnf_probe_thr_sync		= 0;

/* head of the list that is used to chain all probes */
tnf_probe_control_t	*__tnf_probe_list_head		= NULL;
int			__tnf_probe_list_valid		= 0;

/* notify function that libthread calls after primordial thread is created */
void __tnf_probe_notify(void);

tnf_probe_test_func_t tnf_threaded_test_addr = tnf_threaded_test;
tnf_probe_test_func_t tnf_non_threaded_test_addr = tnf_non_threaded_test;


/*
 * Externs
 */
#pragma weak thr_probe_getfunc_addr
extern tnf_context_t	thr_probe_getfunc_addr;

#pragma weak thr_probe_setup
extern void thr_probe_setup(void *);

/* ---------------------------------------------------------------- */
/* ----------------------- Public Functions ----------------------- */
/* ---------------------------------------------------------------- */

/*
 * probe_setup() - the thread probe setup function for the non-threaded
 * case.
 */
static void
probe_setup(void *data)
{
#ifdef DEBUG
	/* #### - TEMPORARY */
	fprintf(stderr, "probe_setup: \n");
#endif
	tpd = data;

}   /* end probe_setup */

/*
 * __tnf_probe_notify() - libthread calls this function to notify us
 * that the primordial thread has been created.
 */

void
__tnf_probe_notify(void)
{
	tnf_probe_control_t		*prbctl_p;
	tnf_probe_test_func_t		test_func;

	/* paranoia: thr_probe_setup should be defined */
	assert(thr_probe_setup != 0);
	if (thr_probe_setup != 0) thr_probe_setup(tpd);

	/*
	 * no race with prex if we set flag first
	 *		- this is an idempotent operation
	 */
	__tnf_probe_thr_sync = 1;

#ifdef DEBUG
	{
		char tmp_buf[512];
		(void) sprintf(tmp_buf, "__tnf_probe_notify: \n");
		(void) write(2, tmp_buf, strlen(tmp_buf));
	}
#endif
	/*
	 * Use dlsym to test for the present of "thr_probe_getfunc_addr" .
	 */

	test_func = (((int(*)())dlsym(RTLD_DEFAULT,
		"thr_probe_getfunc_addr")) != NULL) ? tnf_threaded_test : 0;

	assert(test_func);

	/*
	 * I think in this case that we do not need to check the
	 * __tnf_probe_list_valid flag since __tnf_probe_notify is
	 * called very early.
	 */

	/* replace all existing test functions with libthread's test func */
	for (prbctl_p = __tnf_probe_list_head; prbctl_p;
					prbctl_p = prbctl_p->next)
		if (prbctl_p->test_func)
			prbctl_p->test_func = test_func;

	return;

}   /* end __tnf_probe_notify */

/*
 * _tnf_fork_thread_setup - function called by buffering layer
 * whenever it finds a thread in the newly forked process that
 * hasn't been re-initialized in this process.
 */
void
_tnf_fork_thread_setup(void)
{
	tnf_ops_t	*ops;

#ifdef DEBUGFUNCS
	{
		char tmp_buf[512];
		(void) sprintf(tmp_buf, "in _tnf_fork_thread_setup: \n");
		(void) write(2, tmp_buf, strlen(tmp_buf));
	}
#endif
	/* get the tpd */
	ops = tnf_get_ops();
	if (!ops)
		return;
	/* null out tag_index, so that a new one is initialized and written */
	ops->schedule.record_p = 0;
	return;

}

/* ---------------------------------------------------------------- */
/* ---------------------- Interposed Functions -------------------- */
/* ---------------------------------------------------------------- */

/*
 * thr_create() - this function is interposed in front of the
 * actual thread create function in libthread.
 */

int
thr_create(void 		*stk,
	size_t		stksize,
	void *		(*real_func)(void *),
	void		*real_arg,
	long		flags,
	thread_t	*new_thread)
{
	static tnf_thr_create_func_t real_thr_create = NULL;
	args_t *arg_p;

#ifdef VERYVERBOSE
	fprintf(stderr, "hello from the interposed thr_create parent\n");
#endif

	/* use dlsym to find the address of the "real" thr_create function */
	if (real_thr_create == NULL) {
		real_thr_create = (tnf_thr_create_func_t)
					dlsym(RTLD_NEXT, "thr_create");
	}
	assert(real_thr_create);

	/* set up the interposed argument block */
	arg_p = (args_t *)malloc(sizeof (args_t));
	assert(arg_p);
	arg_p->real_func = real_func;
	arg_p->real_arg  = real_arg;

	return ((*real_thr_create)(stk, stksize, probestart, (void *) arg_p,
					flags, new_thread));

}   /* end thr_create */


int
pthread_create(pthread_t *new_thread_id,
	const pthread_attr_t *attr,
	void *		(*real_func)(void *),
	void		*real_arg)
{
	static tnf_pthread_create_func_t real_pthread_create = NULL;
	args_t *arg_p;

#ifdef VERYVERBOSE
	fprintf(stderr, "hello from the interposed pthread_create parent\n");
#endif

	/* use dlsym to find the address of the "real" pthread_create func */
	if (real_pthread_create == NULL) {
		real_pthread_create = (tnf_pthread_create_func_t)
					dlsym(RTLD_NEXT, "pthread_create");
	}
	assert(real_pthread_create);

	/* set up the interposed argument block */
	arg_p = (args_t *)malloc(sizeof (args_t));
	assert(arg_p);
	arg_p->real_func = real_func;
	arg_p->real_arg  = real_arg;

	return ((*real_pthread_create)(new_thread_id, attr, probestart,
			(void *) arg_p));

}   /* end pthread_create */

void
thr_exit(void * status)
{
	static tnf_thr_exit_func_t real_thr_exit = NULL;
	/* use dlsym to find the address of the "real" pthread_create func */
	if (real_thr_exit == NULL) {
		real_thr_exit = (tnf_thr_exit_func_t)
		dlsym(RTLD_NEXT, "thr_exit");
	}
	assert(real_thr_exit);


	/*
	 * Calling tnf_thread_disable() whenever a thread exits...
	 * This has the side-effect of unlocking our currently
	 * locked block in the trace buffer.  This keeps a dying
	 * thread from taking a block with it when it dies, but
	 * it means that we won't be able to trace events from
	 * the thread-specific data destructors.  We will lose
	 * out on any events a thread spits out AFTER is calls thr_exit().
	 * This code was added to fix a bug where tracing breaks when trying
	 * to trace a program with large numbers of thread-ids.
	 *
	 * Addendum:
	 * Now you can't get events for thr_exit using an interposition library.
	 * Since thr_exit is a really helpful event, this is a problem.
	 * Also, breaking this interposition will probably break
	 * BAT, the DevPro TNF perf tool.
	 *
	 * Addendum:
	 * Correction:  You can get interposition events if the interposition
	 * library comes BEFORE libtnfprobe.so.  But not, if the interp.
	 * library comes AFTER libtnfprobe.so.  This is a more difficult
	 * constraint that it might sound like because of the following:
	 * The tnfctl functional interface and the prex command line
	 * interface provide convenience features where you can supply
	 * a character string argument which will be put into LD_PRELOAD
	 * for you.  Unfortunately, this string gets appended AFTER
	 * libtnfprobe.so by the tnfctl library(and also hence by the
	 * prex -l option).
	 * Luckily, when libtnfprobe is added by the tnfctl library, it is
	 * added AFTER an existing contents of the LD_PRELOAD variable.
	 *
	 * Therefore, if you are using an interposition library to collect
	 * thr_exit and pthread_exit events, THEN you should NOT use 'prex -l'
	 * or the 'ld_preload' argument to tnfctl_exec_open(), instead, you
	 * should be sure to put the interposition library into the LD_PRELOAD
	 * variable yourself.
	 *
	 */

	tnf_thread_disable();

	((*real_thr_exit)(status));
}

void
pthread_exit(void * status)
{
	static tnf_pthread_exit_func_t real_pthread_exit = NULL;
	/* use dlsym to find the address of the "real" pthread_create func */
	if (real_pthread_exit == NULL) {
		real_pthread_exit = (tnf_pthread_exit_func_t)
		dlsym(RTLD_NEXT, "pthread_exit");
	}
	assert(real_pthread_exit);
	/* see the comment in thr_exit about tnf_thread_disable() */
	tnf_thread_disable();
	((*real_pthread_exit)(status));
}

/*
 * function to be interposed in front of _resume.  We invalidate the
 * schedule record in case the lwpid changes the next time this
 * thread is scheduled.
 */

#pragma weak _resume_ret = _tnf_resume_ret
void
_tnf_resume_ret(void *arg1)
{
	static void (*real_resume_ret)(void *) = NULL;
	tnf_ops_t	*ops;

	if (real_resume_ret == NULL) {
		real_resume_ret = (void (*)(void *)) dlsym(RTLD_NEXT,
					"_resume_ret");
	}
	assert(real_resume_ret);

	ops = tnf_get_ops();
	if (ops) {
		/*
		 * invalidate the schedule record.  This forces it
		 * to get re-initialized with the new lwpid the next
		 * time this thread gets scheduled
		 */
		if (ops->schedule.lwpid != _lwp_self())
			ops->schedule.record_p = 0;
	}

	real_resume_ret(arg1);
}

/*
 * Functions to be interposed in front of fork and fork1.
 *
 * NOTE: we can't handle vfork, because the child would ruin the parent's
 * data structures.  We therefore don't interpose, letting the child's
 * events appear as though they were the parent's.  A slightly cleaner
 * way to handle vfork would be to interpose on vfork separately to
 * change the pid and anything else needed to show any events caused
 * by the child as its events, and then interpose on the exec's as
 * well to set things back to the way they should be for the parent.
 * But this is a lot of work, and it makes almost no difference, since the
 * child typically exec's very quickly after a vfork.
 */

#pragma weak fork = _tnf_fork
pid_t
_tnf_fork(void)
{
	static fork_t real_fork = NULL;

	if (real_fork == NULL) {
		real_fork = (fork_t)dlsym(RTLD_NEXT, "fork");
	}
	assert(real_fork);
	return (common_fork(real_fork));
}

#pragma weak fork1 = _tnf_fork1
pid_t
_tnf_fork1(void)
{
	static fork_t real_fork = NULL;

	if (real_fork == NULL) {
		real_fork = (fork_t)dlsym(RTLD_NEXT, "fork1");
	}
	assert(real_fork);
	return (common_fork(real_fork));
}

#ifdef sparc
/*
 * Function to be interposed in front of thr_stksegment
 * _tnf_thr_stksegment() - used to hide the probestart() allocated data
 * on the thread stack, ensuring that the caller receives a pointer to the
 * true bottom (ie, usable) portion of the stack, and the size thereof.
 *
 * NOTE:  On sparc systems, failure to allow for the presense of tnf data
 * on the stack would cause TNF probes to fail across doorfs calls.  The
 * i386 version of door_return decides to "skip over some slop", so no
 * interpose function is required for x86;  if the 512 byte 'slop skip'
 * is ever removed from the i386 door_return, then it will also need
 * interpose function intervention.
 *
 * Note: Instead of making this function static, we reduce it to local
 * scope in the mapfile. That allows the linker to prevent it from
 * appearing in the .SUNW_dynsymsort section.
 */
#pragma weak thr_stksegment = _tnf_thr_stksegment
int
_tnf_thr_stksegment(stack_t *s)
{
	static tnf_thr_stksegment_func_t real_thr_stksegment = NULL;
	int	err;

#ifdef VERYVERBOSE
	fprintf(stderr, "hello from the interposed thr_stksegment\n");
#endif

	if (real_thr_stksegment == NULL) {
		real_thr_stksegment = (tnf_thr_stksegment_func_t)
		    dlsym(RTLD_NEXT, "thr_stksegment");
	}
	assert(real_thr_stksegment);

	err = ((*real_thr_stksegment)(s));
	if (err == 0) {
		s->ss_sp = (void *)((caddr_t)s->ss_sp - tnf_probe_dsize);
		s->ss_size -= tnf_probe_dsize;
	}
	return (err);
}
#endif /* sparc */

/* ---------------------------------------------------------------- */
/* ----------------------- Private Functions ---------------------- */
/* ---------------------------------------------------------------- */

/*
 * tnf_probe_getfunc() - default test function if libthread is not
 * present
 */
static tnf_ops_t *
tnf_probe_getfunc(void)
{
	/* test function to be used if libthread is not linked in */
#ifdef DEBUGFUNCS
	{
		char tmp_buf[512];
		(void) sprintf(tmp_buf, "tnf_probe_getfunc: \n");
		(void) write(2, tmp_buf, strlen(tmp_buf));
	}
#endif
	return (tpd);
}   /* end tnf_probe_getfunc */


/*
 * probestart() - this function is called as the start_func by the
 * interposed thr_create() and pthread_create().  It calls the real start
 * function.
 */

static void *
probestart(void * arg)
{
	args_t 		*args_p = (args_t *)arg;
	start_func_t	real_func;
	void		*real_arg;
	tnf_ops_t	ops;		/* allocated on stack */
	void		*real_retval;

#ifdef VERYVERBOSE
	fprintf(stderr, "hello from the interposed thr_create child\n");
#endif
#ifdef sparc
	/*
	 * if the size of the probe data has not yet been calculated,
	 * initialize a jmpbuffer and calculate the amount of stack space
	 * used by probestart:  %fp - %sp from jmp_buf
	 * Not expecting anything to actually longjmp here, so that is
	 * handled as an error condition.
	 */
	if (tnf_probe_dsize == 0) {
		jmp_buf tnf_jmpbuf;
		if (setjmp(tnf_jmpbuf) != 0) {
			(void) write(2,
			    "probestart:  unexpected longjmp\n", 32);
			assert(0);
		}
		tnf_probe_dsize = (size_t)(tnf_jmpbuf[3] - tnf_jmpbuf[1]);
	}
#endif /* sparc */

	/* initialize ops */
	(void) memset(&ops, 0, sizeof (ops));	/* zero ops */
	ops.mode = TNF_ALLOC_REUSABLE;
	ops.alloc = tnfw_b_alloc;
	ops.commit = tnfw_b_xcommit;
	ops.rollback = tnfw_b_xabort;

	/* copy (and free) the allocated arg block */
	real_func = args_p->real_func;
	real_arg  = args_p->real_arg;
	free(args_p);

	/* paranoia: thr_probe_setup should be defined */
	assert(thr_probe_setup != 0);
	if (thr_probe_setup != 0) thr_probe_setup(&ops);

#ifdef VERYVERBOSE
	fprintf(stderr, "in middle of interposed start procedure\n");
#endif

	real_retval = (*real_func)(real_arg);

	/*
	 * we need to write a NULL into the tpd pointer to disable
	 * tracing for this thread.
	 * CAUTION: never make this function tail recursive because
	 * tpd is allocated on stack.
	 */

	/* This should be handled by the call to tnf_thread_disable() */
	/* if (thr_probe_setup != 0) */
	/* thr_probe_setup(NULL); */

	/* see the comment in thr_exit about tnf_thread_disable */
	tnf_thread_disable();

	return (real_retval);

}   /* end probestart */


static thread_key_t tpd_key = THR_ONCE_KEY;
static tnf_ops_t *stashed_tpd = NULL;

/*
 * tnf_thread_disable: API to disable a thread
 */
void
tnf_thread_disable(void)
{
	tnf_ops_t		*ops;

	if (thr_probe_setup != 0) {
		/* threaded client */

		/* REMIND: destructor function ? */
		(void) thr_keycreate_once(&tpd_key, NULL);
		/* get the tpd */
		ops = thr_probe_getfunc_addr();
		/* check ops to ensure function is idempotent */
		if (ops != NULL) {
			/* unlock currently held blocks */
			tnfw_b_release_block(&ops->wcb);
			/* disable the thread */
			thr_probe_setup(NULL);
			/* stash the tpd */
			(void) thr_setspecific(tpd_key, ops);
		}
	} else {
		/* non-threaded client */

		/* get the tpd */
		ops = tnf_probe_getfunc();
		if (ops != NULL) {
			/* disable the process */
			probe_setup(NULL);
			/* stash the tpd */
			stashed_tpd = ops;
		}
	}
}

/*
 * tnf_thread_enable: API to enable a thread
 */
void
tnf_thread_enable(void)
{
	tnf_ops_t *ops;

	if (thr_probe_setup != 0) {
		/* threaded client */

		ops = pthread_getspecific(tpd_key);
		if (ops)
			thr_probe_setup(ops);
	} else {
		/* non-threaded client */

		ops = stashed_tpd;
		if (ops)
			probe_setup(ops);
	}
}

/*
 * common_fork - code that is common among the interpositions of
 * fork, fork1, and vfork
 */
static pid_t
common_fork(fork_t real_fork)
{
	pid_t		 retval;
	tnf_ops_t	*ops;
	tnf_tag_data_t	*metatag_data;

#ifdef DEBUGFUNCS
	{
		char tmp_buf[512];
		(void) sprintf(tmp_buf, "in interposed fork: \n");
		(void) write(2, tmp_buf, strlen(tmp_buf));
	}
#endif
	if ((_tnfw_b_control->tnf_state == TNFW_B_NOBUFFER) &&
				(tnf_trace_file_name[0] != '\0')) {
		/*
		 * if no buffer has been allocated yet, and prex plugged in
		 * name...
		 */
		ops = tnf_get_ops();
		if (ops == NULL) {
			/*
			 * get it from stashed location
			 * don't enable thread though
			 */
			if (thr_probe_setup != 0) {
				/* threaded client */
				ops = pthread_getspecific(tpd_key);
			} else {
				/* non-threaded client */
				ops = stashed_tpd;
			}
		}

		/*
		 * ops shouldn't be NULL.  But, if it is, then we don't
		 * initialize tracing.  In the child, tracing will be
		 * set to broken.
		 */
		if (ops) {
			/* initialize tracing */
			ops->busy = 1;
			metatag_data = TAG_DATA(tnf_struct_type);
			metatag_data->tag_desc(ops, metatag_data);
			/* commit the data */
			(void) ops->commit(&(ops->wcb));
			ops->busy = 0;
		}
	}

	retval = real_fork();
	if (retval == 0) {
		/* child process */
		_tnfw_b_control->tnf_pid = getpid();
		if ((_tnfw_b_control->tnf_state == TNFW_B_NOBUFFER) &&
				(tnf_trace_file_name[0] != '\0')) {
			/*
			 * race condition, prex attached after condition was
			 * checked in parent, so both parent and child point at
			 * the same file name and will overwrite each other.
			 * So, we set tracing to broken in child.  We could
			 * invent a new state called RACE and use prex to
			 * reset it, if needed...
			 */
			tnf_trace_file_name[0] = '\0';
			_tnfw_b_control->tnf_state = TNFW_B_BROKEN;
		} else if (_tnfw_b_control->tnf_state == TNFW_B_RUNNING) {
			/* normal expected condition */
			_tnfw_b_control->tnf_state = TNFW_B_FORKED;
		}
	}
	return (retval);
}

/*
 * tnf_threaded_test
 */
/*ARGSUSED0*/
static void *
tnf_threaded_test(void *dummy, tnf_probe_control_t *probe_p,
			tnf_probe_setup_t *set_p)
{
	tnf_ops_t *tpd_p;

	tpd_p = thr_probe_getfunc_addr();
	if (tpd_p) {
		return (probe_p->alloc_func(tpd_p, probe_p, set_p));
	}
	return (NULL);
}


/*
 * tnf_non_threaded_test
 */
/*ARGSUSED0*/
static void *
tnf_non_threaded_test(void *dummy, tnf_probe_control_t *probe_p,
				tnf_probe_setup_t *set_p)
{
	tnf_ops_t *tpd_p;

	tpd_p = tnf_probe_getfunc();
	if (tpd_p) {
		return (probe_p->alloc_func(tpd_p, probe_p, set_p));
	}
	return (NULL);
}

/*
 * tnf_get_ops() returns the ops pointer (thread-private data), or NULL
 * if tracing is disabled for this thread.
 */
static tnf_ops_t *
tnf_get_ops()
{
	tnf_context_t	*test_func_p = &thr_probe_getfunc_addr;
	tnf_context_t	 test_func;

	/*
	 * IMPORTANT: this test to see whether thr_probe_getfunc_addr
	 * is bound is tricky.  The compiler currently has a bug
	 * (1263684) that causes the test to be optimized away unless
	 * coded with an intermediate pointer (test_func_p).  This
	 * causes the process to SEGV when the variable is not bound.
	 */

	test_func = test_func_p ? *test_func_p : tnf_probe_getfunc;
	return ((*test_func)());
}
