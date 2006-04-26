#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libc/spec/threads.spec

function	pthread_atfork
include		<unistd.h>, <sys/types.h>
declaration	int pthread_atfork(void (*prepare)(void), \
			void (*parent)(void), void (*child)(void))
version		SUNW_1.1
errno		ENOMEM
exception	$return != 0
end

function	pthread_attr_destroy
include		<pthread.h>
declaration	int pthread_attr_destroy(pthread_attr_t *attr)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_getdetachstate
include		<pthread.h>
declaration	int pthread_attr_getdetachstate(const pthread_attr_t *attr, \
			int *detachstate)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_getinheritsched
include		<pthread.h>
declaration	int pthread_attr_getinheritsched( \
			const pthread_attr_t *_RESTRICT_KYWD attr, \
			int *_RESTRICT_KYWD inheritsched)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_getschedparam
include		<pthread.h>
declaration	int pthread_attr_getschedparam( \
			const pthread_attr_t *_RESTRICT_KYWD attr, \
			struct sched_param *_RESTRICT_KYWD param)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_getschedpolicy
include		<pthread.h>
declaration	int pthread_attr_getschedpolicy( \
			const pthread_attr_t *_RESTRICT_KYWD attr, \
			int *_RESTRICT_KYWD policy)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_getscope
include		<pthread.h>
declaration	int pthread_attr_getscope( \
			const pthread_attr_t *_RESTRICT_KYWD attr, \
			int *_RESTRICT_KYWD contentionscope)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_getstack
include		<pthread.h>
declaration	int pthread_attr_getstack( \
			const pthread_attr_t *_RESTRICT_KYWD attr, \
			void **_RESTRICT_KYWD stackaddr, \
			size_t *_RESTRICT_KYWD stacksize)
version		SUNW_1.22
errno		EINVAL
end

function	pthread_attr_getstackaddr
include		<pthread.h>
declaration	int pthread_attr_getstackaddr( \
			const pthread_attr_t *_RESTRICT_KYWD attr, \
			void **_RESTRICT_KYWD stackaddr)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_getstacksize
include		<pthread.h>
declaration	int pthread_attr_getstacksize( \
			const pthread_attr_t *_RESTRICT_KYWD attr, \
			size_t *_RESTRICT_KYWD stacksize)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_init
include		<pthread.h>
declaration	int pthread_attr_init(pthread_attr_t *attr)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_setdetachstate
include		<pthread.h>
declaration	int pthread_attr_setdetachstate(pthread_attr_t *attr, \
			int detachstate)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_setinheritsched
include		<pthread.h>
declaration	int pthread_attr_setinheritsched(pthread_attr_t *attr, \
			int inheritsched)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_setschedparam
include		<pthread.h>
declaration	int pthread_attr_setschedparam( \
			pthread_attr_t *_RESTRICT_KYWD attr, \
			const struct sched_param *_RESTRICT_KYWD param)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_setschedpolicy
include		<pthread.h>
declaration	int pthread_attr_setschedpolicy(pthread_attr_t *attr, \
			int policy)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_setscope
include		<pthread.h>
declaration	int pthread_attr_setscope(pthread_attr_t *attr, \
			int contentionscope)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_setstack
include		<pthread.h>
declaration	int pthread_attr_setstack(pthread_attr_t *attr, \
			void *stackaddr, size_t stacksize)
version		SUNW_1.22
errno		EINVAL
end

function	pthread_attr_setstackaddr
include		<pthread.h>
declaration	int pthread_attr_setstackaddr(pthread_attr_t *attr, \
			void *stackaddr)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_attr_setstacksize
include		<pthread.h>
declaration	int pthread_attr_setstacksize(pthread_attr_t *attr, \
			size_t stacksize)
version		SUNW_1.1
errno		ENOMEM EINVAL ENOTSUP
end

function	pthread_barrierattr_init
include		<pthread.h>
declaration	int pthread_barrierattr_init(pthread_barrierattr_t *attr)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_barrierattr_destroy
include		<pthread.h>
declaration	int pthread_barrierattr_destroy(pthread_barrierattr_t *attr)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_barrierattr_setpshared
include		<pthread.h>
declaration	int pthread_barrierattr_setpshared( \
			pthread_barrierattr_t *attr, int pshared)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_barrierattr_getpshared
include		<pthread.h>
declaration	int pthread_barrierattr_getpshared( \
			const pthread_barrierattr_t *attr, int *pshared)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_barrier_init
include		<pthread.h>
declaration	int pthread_barrier_init(pthread_barrier_t *barrier, \
			const pthread_barrierattr_t *attr, uint_t count)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_barrier_destroy
include		<pthread.h>
declaration	int pthread_barrier_destroy(pthread_barrier_t *barrier)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_barrier_wait
include		<pthread.h>
declaration	int pthread_barrier_wait(pthread_barrier_t *barrier)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_cancel
include		<pthread.h>
declaration	int pthread_cancel(pthread_t target_thread)
version		SUNW_1.1
errno		ESRCH
end

function	pthread_cond_broadcast
include		<pthread.h>
declaration	int pthread_cond_broadcast(pthread_cond_t *cond)
version		SUNW_0.9
errno		EINVAL
end

function	pthread_cond_destroy
include		<pthread.h>
declaration	int pthread_cond_destroy(pthread_cond_t *cond)
version		SUNW_0.9
errno		EBUSY, EINVAL
end

function	pthread_cond_init
include		<pthread.h>
declaration	int pthread_cond_init(pthread_cond_t *_RESTRICT_KYWD cond, \
			const pthread_condattr_t *_RESTRICT_KYWD attr)
version		SUNW_0.9
errno		EAGAIN, ENOMEM, EBUSY, EINVAL
end

function	pthread_cond_signal
include		<pthread.h>
declaration	int pthread_cond_signal(pthread_cond_t *cond)
version		SUNW_0.9
errno		EINVAL
end

function	pthread_cond_timedwait
include		<pthread.h>
declaration	int pthread_cond_timedwait( \
			pthread_cond_t *_RESTRICT_KYWD cond, \
			pthread_mutex_t *_RESTRICT_KYWD mutex, \
			const struct timespec *_RESTRICT_KYWD abstime)
version		SUNW_0.9
errno		ETIMEDOUT, EINVAL
end

function	pthread_cond_reltimedwait_np
include		<pthread.h>
declaration	int pthread_cond_reltimedwait_np(pthread_cond_t *cond, \
			pthread_mutex_t *mutex, const struct timespec *abstime)
version		SUNW_1.21
errno		ETIMEDOUT, EINVAL
end

function	pthread_cond_wait
include		<pthread.h>
declaration	int pthread_cond_wait(pthread_cond_t *_RESTRICT_KYWD cond, \
			pthread_mutex_t *_RESTRICT_KYWD mutex)
version		SUNW_0.9
errno		EINVAL
end

function	pthread_condattr_destroy
include		<pthread.h>
declaration	int pthread_condattr_destroy(pthread_condattr_t *attr)
version		SUNW_0.9
errno		ENOMEM EINVAL
end

function	pthread_condattr_getclock
include		<pthread.h>
declaration	int pthread_condattr_getclock( \
			const pthread_condattr_t *attr, clockid_t *clock_id)
version		SUNW_1.22
errno		EINVAL
end

function	pthread_condattr_getpshared
include		<pthread.h>
declaration	int pthread_condattr_getpshared( \
			const pthread_condattr_t *_RESTRICT_KYWD attr, \
			int *_RESTRICT_KYWD process_shared)
version		SUNW_0.9
errno		ENOMEM EINVAL
end

function	pthread_condattr_init
include		<pthread.h>
declaration	int pthread_condattr_init(pthread_condattr_t *attr)
version		SUNW_0.9
errno		ENOMEM EINVAL
end

function	pthread_condattr_setclock
include		<pthread.h>
declaration	int pthread_condattr_setclock( \
			pthread_condattr_t *attr, clockid_t clock_id)
version		SUNW_1.22
errno		EINVAL
end

function	pthread_condattr_setpshared
include		<pthread.h>
declaration	int pthread_condattr_setpshared(pthread_condattr_t *attr, \
			int process_shared)
version		SUNW_0.9
errno		ENOMEM EINVAL
end

function	pthread_create
include		<pthread.h>
declaration	int pthread_create(pthread_t *_RESTRICT_KYWD thread, \
			const pthread_attr_t *_RESTRICT_KYWD attr, \
			void *(*start_routine)(void*), \
			void *_RESTRICT_KYWD arg)
version		SUNW_1.1
errno		EAGAIN EINVAL ENOMEM
end

function	pthread_detach
include		<pthread.h>
declaration	int pthread_detach(pthread_t tid)
version		SUNW_1.1
errno		EINVAL ESRCH
end

function	pthread_equal
include		<pthread.h>
declaration	int pthread_equal(pthread_t t1, pthread_t t2)
version		SUNW_1.1
end

function	pthread_exit
include		<pthread.h>
declaration	void pthread_exit(void *status)
version		SUNW_1.1
end

function	pthread_getschedparam
include		<pthread.h>, <sched.h>
declaration	int pthread_getschedparam(pthread_t tid, \
			int *_RESTRICT_KYWD policy, \
			struct sched_param *_RESTRICT_KYWD param)
version		SUNW_1.1
errno		ESRCH ENOTSUP EINVAL
end

function	pthread_getspecific
include		<pthread.h>
declaration	void *pthread_getspecific(pthread_key_t key)
version		SUNW_1.1
end

function	pthread_join
include		<pthread.h>
declaration	int pthread_join(pthread_t tid, void **status)
version		SUNW_1.1
errno		ESRCH EDEADLK
end

function	pthread_key_create
include		<pthread.h>
declaration	int pthread_key_create(pthread_key_t *keyp, \
			void (*destructor)(void *))
version		SUNW_1.1
errno		EAGAIN ENOMEM EINVAL
end

function	pthread_key_delete
include		<pthread.h>
declaration	int pthread_key_delete(pthread_key_t key)
version		SUNW_1.1
errno		EAGAIN ENOMEM EINVAL
end

function	pthread_kill
include		<pthread.h>, <signal.h>
declaration	int pthread_kill(pthread_t tid, int signo)
version		SUNW_1.1
errno		ESRCH EINVAL
end

function	pthread_mutex_destroy
include		<pthread.h>
declaration	int pthread_mutex_destroy(pthread_mutex_t *mutex)
version		SUNW_0.9
errno		EBUSY, EINVAL
end

function	pthread_mutex_getprioceiling
include		<pthread.h>
declaration	int pthread_mutex_getprioceiling( \
			const pthread_mutex_t *_RESTRICT_KYWD mutex, \
			int *_RESTRICT_KYWD prioceiling)
version		SUNW_0.9
end

function	pthread_mutex_init
include		<pthread.h>
declaration	int pthread_mutex_init(pthread_mutex_t *_RESTRICT_KYWD mutex, \
			const pthread_mutexattr_t *_RESTRICT_KYWD attr)
version		SUNW_0.9
errno		EAGAIN, ENOMEM, EBUSY, EPERM, EINVAL
end

function	pthread_mutex_lock
include		<pthread.h>
declaration	int pthread_mutex_lock(pthread_mutex_t *mutex)
version		SUNW_0.9
errno		EINVAL, EDEADLK
end

function	pthread_mutex_setprioceiling
include		<pthread.h>
declaration	int pthread_mutex_setprioceiling( \
			pthread_mutex_t *_RESTRICT_KYWD mutex, \
			int prioceiling, int *_RESTRICT_KYWD old_ceiling)
version		SUNW_0.9
end

function	pthread_mutex_trylock
include		<pthread.h>
declaration	int pthread_mutex_trylock(pthread_mutex_t *mutex)
version		SUNW_0.9
errno		EINVAL, EBUSY
end

function	pthread_mutex_unlock
include		<pthread.h>
declaration	int pthread_mutex_unlock(pthread_mutex_t *mutex)
version		SUNW_0.9
errno		EINVAL, EPERM
end

function	pthread_mutexattr_destroy
include		<pthread.h>
declaration	int pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
version		SUNW_0.9
errno		ENOMEM EINVAL ENOSYS
end

function	pthread_mutexattr_getprioceiling
include		<pthread.h>
declaration	int pthread_mutexattr_getprioceiling( \
			const pthread_mutexattr_t *_RESTRICT_KYWD attr, \
			int *_RESTRICT_KYWD prioceiling)
version		SUNW_0.9
end

function	pthread_mutexattr_getprotocol
include		<pthread.h>, <sched.h>
declaration	int pthread_mutexattr_getprotocol( \
			const pthread_mutexattr_t *_RESTRICT_KYWD attr, \
			int *_RESTRICT_KYWD protocol)
version		SUNW_0.9
end

function	pthread_mutexattr_getpshared
include		<pthread.h>
declaration	int pthread_mutexattr_getpshared( \
			const pthread_mutexattr_t *_RESTRICT_KYWD attr, \
			int *_RESTRICT_KYWD process_shared)
version		SUNW_0.9
errno		ENOMEM EINVAL ENOSYS
end

function	pthread_mutexattr_init
include		<pthread.h>
declaration	int pthread_mutexattr_init(pthread_mutexattr_t *attr)
version		SUNW_0.9
errno		ENOMEM EINVAL ENOSYS
end

function	pthread_mutexattr_setprotocol
include		<pthread.h>, <sched.h>
declaration	int pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, \
			int protocol)
version		SUNW_0.9
end

function	pthread_mutexattr_setpshared
include		<pthread.h>
declaration	int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, \
			int process_shared)
version		SUNW_0.9
errno		ENOMEM EINVAL ENOSYS
end

function	pthread_once
include		<pthread.h>
declaration	int pthread_once(pthread_once_t *once_control, \
			void (*init_routine)(void))
version		SUNW_1.1
errno		EINVAL
end

function	pthread_self
include		<pthread.h>
declaration	pthread_t pthread_self(void)
version		SUNW_1.1
end

function	pthread_setcancelstate
include		<pthread.h>
declaration	int pthread_setcancelstate(int state, int *oldstate)
version		SUNW_1.1
errno		EINVAL
end

function	pthread_setcanceltype
include		<pthread.h>
declaration	int pthread_setcanceltype(int type, int *oldtype)
version		SUNW_1.1
errno		EINVAL
end

function	pthread_setschedparam
include		<pthread.h>, <sched.h>
declaration	int pthread_setschedparam(pthread_t tid, int policy, \
			const struct sched_param *param)
version		SUNW_1.1
errno		ESRCH ENOTSUP EINVAL EPERM
end

function	pthread_setschedprio
include		<pthread.h>
declaration	int pthread_setschedprio(pthread_t tid, int prio)
version		SUNW_1.22
errno		ESRCH ENOTSUP EINVAL EPERM
end

function	pthread_setspecific
include		<pthread.h>
declaration	int pthread_setspecific(pthread_key_t key, const void *value)
version		SUNW_1.1
errno		ENOMEM EINVAL
end

function	pthread_sigmask
include		<pthread.h>, <signal.h>
declaration	int pthread_sigmask(int how, \
			const sigset_t *_RESTRICT_KYWD newmask, \
			sigset_t *_RESTRICT_KYWD oldmask)
version		SUNW_1.1
errno		EINVAL EFAULT
end

function	pthread_testcancel
include		<pthread.h>
declaration	void pthread_testcancel(void)
version		SUNW_1.1
end

function	pthread_mutex_timedlock
include		<pthread.h>, <time.h>
declaration	int pthread_mutex_timedlock(pthread_mutex_t *mutex, \
			const timespec_t *abstime)
version		SUNW_1.22
errno		EINVAL, ETIMEDOUT
end

function	pthread_mutex_reltimedlock_np
include		<pthread.h>, <time.h>
declaration	int pthread_mutex_reltimedlock_np(pthread_mutex_t *mutex, \
			const timespec_t *reltime)
version		SUNW_1.22
errno		EINVAL, ETIMEDOUT
end

function	pthread_mutexattr_setrobust_np
include		<pthread.h>
declaration	int pthread_mutexattr_setrobust_np(pthread_mutexattr_t *attr, \
			int robustness)
version		SUNW_1.22
errno		ENOTSUP EINVAL ENOSYS
exception	$return != 0
end

function	pthread_mutexattr_getrobust_np 
include		<pthread.h>
declaration	int pthread_mutexattr_getrobust_np( \
			const pthread_mutexattr_t *attr, int *robustness)
version		SUNW_1.22
errno		ENOTSUP EINVAL ENOSYS
exception	$return != 0
end

function	pthread_mutex_consistent_np
include		<pthread.h>
declaration	int pthread_mutex_consistent_np(pthread_mutex_t *mp)
version		SUNW_1.22
errno		EINVAL ENOSYS
exception	$return != 0
end

function	pthread_spin_init
include		<pthread.h>
declaration	int pthread_spin_init(pthread_spinlock_t *lock, int pshared)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_spin_destroy
include		<pthread.h>
declaration	int pthread_spin_destroy(pthread_spinlock_t *lock)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_spin_trylock
include		<pthread.h>
declaration	int pthread_spin_trylock(pthread_spinlock_t *lock)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_spin_lock
include		<pthread.h>
declaration	int pthread_spin_lock(pthread_spinlock_t *lock)
version		SUNW_1.22
exception	$return != 0
end

function	pthread_spin_unlock
include		<pthread.h>
declaration	int pthread_spin_unlock(pthread_spinlock_t *lock)
version		SUNW_1.22
exception	$return != 0
end

function	schedctl_init
include		<schedctl.h>
declaration	schedctl_t *schedctl_init(void)
version		SUNW_1.22
end

function	_schedctl_init
weak		schedctl_init
version		SUNWprivate_1.1
end

function	schedctl_lookup
include		<schedctl.h>
declaration	schedctl_t *schedctl_lookup(void)
version		SUNW_1.22
end

function	_schedctl_lookup
weak		schedctl_lookup
version		SUNWprivate_1.1
end

function	schedctl_exit
include		<schedctl.h>
declaration	void schedctl_exit(void)
version		SUNW_1.22
end

function	_schedctl_exit
weak		schedctl_exit
version		SUNWprivate_1.1
end

function	thr_continue
include		<thread.h>
declaration	int thr_continue(thread_t tid)
version		SUNW_0.8
end

function	thr_create
include		<thread.h>
declaration	int thr_create(void *stack_base, size_t stack_size, \
			void *(*start_func)(void *), void *arg, long flags, \
			thread_t *new_thread_ID)
version		SUNW_0.8
end

function	thr_exit
include		<thread.h>
declaration	void thr_exit(void *status)
version		SUNW_0.8
end

function	thr_getconcurrency
include		<thread.h>
declaration	int thr_getconcurrency(void)
version		SUNW_0.8
end

function	thr_getprio
include		<thread.h>
declaration	int thr_getprio(thread_t tid, int *priop)
version		SUNW_0.8
end

function	thr_getspecific
include		<thread.h>
declaration	int thr_getspecific(thread_key_t key, void **valuep)
version		SUNW_0.8
end

function	thr_join
include		<thread.h>
declaration	int thr_join(thread_t tid, thread_t *dtidp, void **statusp)
version		SUNW_0.8
end

function	thr_keycreate
include		<thread.h>
declaration	int thr_keycreate(thread_key_t *keyp, \
			void (*destructor)(void *value))
version		SUNW_0.8
end

function	thr_kill
include		<thread.h>, <signal.h>
declaration	int thr_kill(thread_t tid, int signo)
version		SUNW_0.8
end

function	thr_main
include		<thread.h>
declaration	int thr_main(void)
version		SUNW_1.1
errno
end

function	thr_min_stack
include		<thread.h>
declaration	size_t thr_min_stack(void)
version		SUNW_0.9
end

function	thr_self
include		<thread.h>
declaration	thread_t thr_self(void)
version		SUNW_0.8
end

function	thr_setconcurrency
include		<thread.h>
declaration	int thr_setconcurrency(int level)
version		SUNW_0.8
end

function	thr_setprio
include		<thread.h>
declaration	int thr_setprio(thread_t tid, int prio)
version		SUNW_0.8
end

function	thr_setspecific
include		<thread.h>
declaration	int thr_setspecific(thread_key_t key, void *value)
version		SUNW_0.8
end

function	thr_sigsetmask
include		<thread.h>, <signal.h>
declaration	int thr_sigsetmask(int how, const sigset_t *newp, \
			sigset_t *oldp)
version		SUNW_0.8
end

function	thr_stksegment
include		<thread.h>, <sys/signal.h>
declaration	int thr_stksegment(stack_t *sp)
version		SUNW_0.9
errno		EFAULT EAGAIN
end

function	thr_suspend
include		<thread.h>
declaration	int thr_suspend(thread_t tid)
version		SUNW_0.8
end

function	thr_yield
include		<thread.h>
declaration	void thr_yield(void)
version		SUNW_0.8
end

data		thr_probe_getfunc_addr
version		SUNWprivate_1.1
end

function	thr_probe_setup
version		SUNWprivate_1.1
end		

function	_pthread_mutexattr_setrobust_np
weak		pthread_mutexattr_setrobust_np
version		SUNWprivate_1.1
end

function	_pthread_mutexattr_getrobust_np
weak		pthread_mutexattr_getrobust_np
version		SUNWprivate_1.1
end

function	_pthread_mutex_consistent_np
weak		pthread_mutex_consistent_np
version		SUNWprivate_1.1
end

function	_pthread_setcleanupinit
version		SUNWprivate_1.1
end

function	__pthread_min_stack
version		SUNWprivate_1.1
end

function	lwp_self
version		SUNWprivate_1.1
end		

function	_thr_continue_allmutators
version		SUNWprivate_1.1
end		

function	_thr_continue_mutator
version		SUNWprivate_1.1
end		

function	_thr_getstate
version		SUNWprivate_1.1
end		

function	_thr_mutators_barrier
version		SUNWprivate_1.1
end		

function	_thr_setmutator
version		SUNWprivate_1.1
end		

function	_thr_setstate
version		SUNWprivate_1.1
end		

function	_thr_sighndlrinfo
version		SUNWprivate_1.1
end		

function	_thr_suspend_allmutators
version		SUNWprivate_1.1
end		

function	_thr_suspend_mutator
version		SUNWprivate_1.1
end		

function	_thr_wait_mutator
version		SUNWprivate_1.1
end		

function	thr_continue_allmutators
version		SUNWprivate_1.1
end		

function	thr_continue_mutator
version		SUNWprivate_1.1
end		

function	thr_getstate
version		SUNWprivate_1.1
end		

function	thr_mutators_barrier
version		SUNWprivate_1.1
end		

function	thr_setmutator
version		SUNWprivate_1.1
end		

function	thr_setstate
version		SUNWprivate_1.1
end		

function	thr_sighndlrinfo
version		SUNWprivate_1.1
end		

function	thr_suspend_allmutators
version		SUNWprivate_1.1
end		

function	thr_suspend_mutator
version		SUNWprivate_1.1
end		

function	thr_wait_mutator
version		SUNWprivate_1.1
end		

function	__gettsp
version		SUNWprivate_1.1
end		

function	_assfail
version		SUNWprivate_1.1
end		

function	__tls_get_addr
version		SUNWprivate_1.1
end		

function	___tls_get_addr
arch		i386
version		i386=SUNWprivate_1.1
end		

function	_cancel_prologue
version		SUNWprivate_1.1
end

function	_cancel_epilogue
version		SUNWprivate_1.1
end

function	_sigoff
version		SUNWprivate_1.1
end

function	_sigon
version		SUNWprivate_1.1
end

function	_sigdeferred
version		SUNWprivate_1.1
end

function	_thr_detach
version		SUNWprivate_1.1
end		

function	_thr_key_delete
version		SUNWprivate_1.1
end		

function	_thr_schedctl
version		SUNWprivate_1.1
end		

function	_thr_slot_offset
version		SUNWprivate_1.1
end		

function	_resume
version		SUNWprivate_1.1
end

function	_resume_ret
version		SUNWprivate_1.1
end

function	posix_spawn
include		<spawn.h>
declaration	int posix_spawn( \
			pid_t *, \
			const char *, \
			const posix_spawn_file_actions_t *, \
			const posix_spawnattr_t *, \
			char *const [], \
			char *const [])
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnp
include		<spawn.h>
declaration	int posix_spawnp( \
			pid_t *, \
			const char *, \
			const posix_spawn_file_actions_t *, \
			const posix_spawnattr_t *attrp, \
			char *const [], \
			char *const [])
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawn_file_actions_init
include		<spawn.h>
declaration	int posix_spawn_file_actions_init( \
			posix_spawn_file_actions_t *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawn_file_actions_destroy
include		<spawn.h>
declaration	int posix_spawn_file_actions_destroy( \
			posix_spawn_file_actions_t *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawn_file_actions_addopen
include		<spawn.h>
declaration	int posix_spawn_file_actions_addopen( \
			posix_spawn_file_actions_t *, \
			int, \
			const char *, \
			int, \
			mode_t)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawn_file_actions_addclose
include		<spawn.h>
declaration	int posix_spawn_file_actions_addclose( \
			posix_spawn_file_actions_t *, \
			int)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawn_file_actions_adddup2
include		<spawn.h>
declaration	int posix_spawn_file_actions_adddup2( \
			posix_spawn_file_actions_t *, \
			int, \
			int)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_init
include		<spawn.h>
declaration	int posix_spawnattr_init( \
			posix_spawnattr_t *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_destroy
include		<spawn.h>
declaration	int posix_spawnattr_destroy( \
			posix_spawnattr_t *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_setflags
include		<spawn.h>
declaration	int posix_spawnattr_setflags( \
			posix_spawnattr_t *, \
			short)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_getflags
include		<spawn.h>
declaration	int posix_spawnattr_getflags( \
			const posix_spawnattr_t *, \
			short *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_setpgroup
include		<spawn.h>
declaration	int posix_spawnattr_setpgroup( \
			posix_spawnattr_t *, \
			pid_t)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_getpgroup
include		<spawn.h>
declaration	int posix_spawnattr_getpgroup( \
			const posix_spawnattr_t *, \
			pid_t *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_setschedparam
include		<spawn.h>
declaration	int posix_spawnattr_setschedparam( \
			posix_spawnattr_t *, \
			const struct sched_param *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_getschedparam
include		<spawn.h>
declaration	int posix_spawnattr_getschedparam( \
			const posix_spawnattr_t *, \
			struct sched_param *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_setschedpolicy
include		<spawn.h>
declaration	int posix_spawnattr_setschedpolicy( \
			posix_spawnattr_t *, \
			int)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_getschedpolicy
include		<spawn.h>
declaration	int posix_spawnattr_getschedpolicy( \
			const posix_spawnattr_t *, \
			int *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_setsigdefault
include		<spawn.h>
declaration	int posix_spawnattr_setsigdefault( \
			posix_spawnattr_t *, \
			const sigset_t *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_getsigdefault
include		<spawn.h>
declaration	int posix_spawnattr_getsigdefault( \
			const posix_spawnattr_t *, \
			sigset_t *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_setsigmask
include		<spawn.h>
declaration	int posix_spawnattr_setsigmask( \
			posix_spawnattr_t *, \
			const sigset_t *)
version		SUNW_1.22
exception	$return != 0
end

function	posix_spawnattr_getsigmask
include		<spawn.h>
declaration	int posix_spawnattr_getsigmask( \
			const posix_spawnattr_t *, \
			sigset_t *)
version		SUNW_1.22
exception	$return != 0
end

function	_posix_spawn
weak		posix_spawn
version		SUNWprivate_1.1
end

function	_posix_spawnp
weak		posix_spawnp
version		SUNWprivate_1.1
end

function	_posix_spawn_file_actions_init
weak		posix_spawn_file_actions_init
version		SUNWprivate_1.1
end

function	_posix_spawn_file_actions_destroy
weak		posix_spawn_file_actions_destroy
version		SUNWprivate_1.1
end

function	_posix_spawn_file_actions_addopen
weak		posix_spawn_file_actions_addopen
version		SUNWprivate_1.1
end

function	_posix_spawn_file_actions_addclose
weak		posix_spawn_file_actions_addclose
version		SUNWprivate_1.1
end

function	_posix_spawn_file_actions_adddup2
weak		posix_spawn_file_actions_adddup2
version		SUNWprivate_1.1
end

function	_posix_spawnattr_init
weak		posix_spawnattr_init
version		SUNWprivate_1.1
end

function	_posix_spawnattr_destroy
weak		posix_spawnattr_destroy
version		SUNWprivate_1.1
end

function	_posix_spawnattr_setflags
weak		posix_spawnattr_setflags
version		SUNWprivate_1.1
end

function	_posix_spawnattr_getflags
weak		posix_spawnattr_getflags
version		SUNWprivate_1.1
end

function	_posix_spawnattr_setpgroup
weak		posix_spawnattr_setpgroup
version		SUNWprivate_1.1
end

function	_posix_spawnattr_getpgroup
weak		posix_spawnattr_getpgroup
version		SUNWprivate_1.1
end

function	_posix_spawnattr_setschedparam
weak		posix_spawnattr_setschedparam
version		SUNWprivate_1.1
end

function	_posix_spawnattr_getschedparam
weak		posix_spawnattr_getschedparam
version		SUNWprivate_1.1
end

function	_posix_spawnattr_setschedpolicy
weak		posix_spawnattr_setschedpolicy
version		SUNWprivate_1.1
end

function	_posix_spawnattr_getschedpolicy
weak		posix_spawnattr_getschedpolicy
version		SUNWprivate_1.1
end

function	_posix_spawnattr_setsigdefault
weak		posix_spawnattr_setsigdefault
version		SUNWprivate_1.1
end

function	_posix_spawnattr_getsigdefault
weak		posix_spawnattr_getsigdefault
version		SUNWprivate_1.1
end

function	_posix_spawnattr_setsigmask
weak		posix_spawnattr_setsigmask
version		SUNWprivate_1.1
end

function	_posix_spawnattr_getsigmask
weak		posix_spawnattr_getsigmask
version		SUNWprivate_1.1
end
