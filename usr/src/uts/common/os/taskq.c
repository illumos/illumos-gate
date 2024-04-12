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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 * Copyright 2018, Joyent, Inc.
 * Copyright 2023-2024 RackTop Systems, Inc.
 */

/*
 * Kernel task queues: general-purpose asynchronous task scheduling.
 *
 * A common problem in kernel programming is the need to schedule tasks
 * to be performed later, by another thread. There are several reasons
 * you may want or need to do this:
 *
 * (1) The task isn't time-critical, but your current code path is.
 *
 * (2) The task may require grabbing locks that you already hold.
 *
 * (3) The task may need to block (e.g. to wait for memory), but you
 *     cannot block in your current context.
 *
 * (4) Your code path can't complete because of some condition, but you can't
 *     sleep or fail, so you queue the task for later execution when condition
 *     disappears.
 *
 * (5) You just want a simple way to launch multiple tasks in parallel.
 *
 * Task queues provide such a facility. In its simplest form (used when
 * performance is not a critical consideration) a task queue consists of a
 * single list of tasks, together with one or more threads to service the
 * list. There are some cases when this simple queue is not sufficient:
 *
 * (1) The task queues are very hot and there is a need to avoid data and lock
 *	contention over global resources.
 *
 * (2) Some tasks may depend on other tasks to complete, so they can't be put in
 *	the same list managed by the same thread.
 *
 * (3) Some tasks may block for a long time, and this should not block other
 *	tasks in the queue.
 *
 * To provide useful service in such cases we define a "dynamic task queue"
 * which has an individual thread for each of the tasks. These threads are
 * dynamically created as they are needed and destroyed when they are not in
 * use. The API for managing task pools is the same as for managing task queues
 * with the exception of a taskq creation flag TASKQ_DYNAMIC which tells that
 * dynamic task pool behavior is desired.
 *
 * Dynamic task queues may also place tasks in a "backlog" when a taskq is
 * resource constrained.  Users of task queues may prevent tasks from being
 * enqueued in the backlog by passing TQ_NOQUEUE in the dispatch call.
 *
 * See "Dynamic Task Queues" below for more details.
 *
 * INTERFACES ==================================================================
 *
 * taskq_t *taskq_create(name, nthreads, pri, minalloc, maxalloc, flags);
 *
 *	Create a taskq with specified properties.
 *	Possible 'flags':
 *
 *	  TASKQ_DYNAMIC: Create task pool for task management. If this flag is
 *		specified, 'nthreads' specifies the maximum number of threads in
 *		the task queue. Task execution order for dynamic task queues is
 *		not predictable.
 *
 *		If this flag is not specified (default case) a
 *		single-list task queue is created with 'nthreads' threads
 *		servicing it. Entries in this queue are managed by
 *		taskq_ent_alloc() and taskq_ent_free() which try to keep the
 *		task population between 'minalloc' and 'maxalloc', but the
 *		latter limit is only advisory for TQ_SLEEP dispatches and the
 *		former limit is only advisory for TQ_NOALLOC dispatches. If
 *		TASKQ_PREPOPULATE is set in 'flags', the taskq will be
 *		prepopulated with 'minalloc' task structures.
 *
 *		Since non-DYNAMIC taskqs are queues, tasks are guaranteed to be
 *		executed in the order they are scheduled if nthreads == 1.
 *		If nthreads > 1, task execution order is not predictable.
 *
 *	  TASKQ_PREPOPULATE: Prepopulate task queue with threads.
 *		Also prepopulate the task queue with 'minalloc' task structures.
 *
 *	  TASKQ_THREADS_CPU_PCT: This flag specifies that 'nthreads' should be
 *		interpreted as a percentage of the # of online CPUs on the
 *		system.  The taskq subsystem will automatically adjust the
 *		number of threads in the taskq in response to CPU online
 *		and offline events, to keep the ratio.  nthreads must be in
 *		the range [0,100].
 *
 *		The calculation used is:
 *
 *			MAX((ncpus_online * percentage)/100, 1)
 *
 *		This flag is not supported for DYNAMIC task queues.
 *		This flag is not compatible with TASKQ_CPR_SAFE.
 *
 *	  TASKQ_CPR_SAFE: This flag specifies that users of the task queue will
 *		use their own protocol for handling CPR issues. This flag is not
 *		supported for DYNAMIC task queues.  This flag is not compatible
 *		with TASKQ_THREADS_CPU_PCT.
 *
 *	The 'pri' field specifies the default priority for the threads that
 *	service all scheduled tasks.
 *
 * taskq_t *taskq_create_instance(name, instance, nthreads, pri, minalloc,
 *    maxalloc, flags);
 *
 *	Like taskq_create(), but takes an instance number (or -1 to indicate
 *	no instance).
 *
 * taskq_t *taskq_create_proc(name, nthreads, pri, minalloc, maxalloc, proc,
 *    flags);
 *
 *	Like taskq_create(), but creates the taskq threads in the specified
 *	system process.  If proc != &p0, this must be called from a thread
 *	in that process.
 *
 * taskq_t *taskq_create_sysdc(name, nthreads, minalloc, maxalloc, proc,
 *    dc, flags);
 *
 *	Like taskq_create_proc(), but the taskq threads will use the
 *	System Duty Cycle (SDC) scheduling class with a duty cycle of dc.
 *
 * void taskq_destroy(tap):
 *
 *	Waits for any scheduled tasks to complete, then destroys the taskq.
 *	Caller should guarantee that no new tasks are scheduled in the closing
 *	taskq.
 *
 * taskqid_t taskq_dispatch(tq, func, arg, flags):
 *
 *	Dispatches the task "func(arg)" to taskq. The 'flags' indicates whether
 *	the caller is willing to block for memory.  The function returns an
 *	opaque value which is zero iff dispatch fails.  If flags is TQ_NOSLEEP
 *	or TQ_NOALLOC and the task can't be dispatched, taskq_dispatch() fails
 *	and returns TASKQID_INVALID.
 *
 *	ASSUMES: func != NULL.
 *
 *	Possible flags:
 *	  TQ_NOSLEEP: Do not wait for resources; may fail.
 *
 *	  TQ_NOALLOC: Do not allocate memory; may fail.  May only be used with
 *		non-dynamic task queues.
 *
 *	  TQ_NOQUEUE: Do not enqueue a task if it can't dispatch it due to
 *		lack of available resources and fail. If this flag is not
 *		set, and the task pool is exhausted, the task may be scheduled
 *		in the backing queue. This flag may ONLY be used with dynamic
 *		task queues.
 *
 *		NOTE: This flag should always be used when a task queue is used
 *		for tasks that may depend on each other for completion.
 *		Enqueueing dependent tasks may create deadlocks.
 *
 *	  TQ_SLEEP:   May block waiting for resources. May still fail for
 *		dynamic task queues if TQ_NOQUEUE is also specified, otherwise
 *		always succeed.
 *
 *	  TQ_FRONT:   Puts the new task at the front of the queue.  Be careful.
 *
 *	NOTE: Dynamic task queues are much more likely to fail in
 *		taskq_dispatch() (especially if TQ_NOQUEUE was specified), so it
 *		is important to have backup strategies handling such failures.
 *
 * void taskq_dispatch_ent(tq, func, arg, flags, tqent)
 *
 *	This is a light-weight form of taskq_dispatch(), that uses a
 *	preallocated taskq_ent_t structure for scheduling.  As a
 *	result, it does not perform allocations and cannot ever fail.
 *	Note especially that it cannot be used with TASKQ_DYNAMIC
 *	taskqs.  The memory for the tqent must not be modified or used
 *	until the function (func) is called.  (However, func itself
 *	may safely modify or free this memory, once it is called.)
 *	Note that the taskq framework will NOT free this memory.
 *
 * boolean_t taskq_empty(tq)
 *
 *	Queries if there are tasks pending on the queue.
 *
 * void taskq_wait(tq):
 *
 *	Waits for all previously scheduled tasks to complete.
 *
 *	NOTE: It does not stop any new task dispatches.
 *	      Do NOT call taskq_wait() from a task: it will cause deadlock.
 *
 * void taskq_suspend(tq)
 *
 *	Suspend all task execution. Tasks already scheduled for a dynamic task
 *	queue will still be executed, but all new scheduled tasks will be
 *	suspended until taskq_resume() is called.
 *
 * int  taskq_suspended(tq)
 *
 *	Returns 1 if taskq is suspended and 0 otherwise. It is intended to
 *	ASSERT that the task queue is suspended.
 *
 * void taskq_resume(tq)
 *
 *	Resume task queue execution.
 *
 * int  taskq_member(tq, thread)
 *
 *	Returns 1 if 'thread' belongs to taskq 'tq' and 0 otherwise. The
 *	intended use is to ASSERT that a given function is called in taskq
 *	context only.
 *
 * system_taskq
 *
 *	Global system-wide dynamic task queue for common uses. It may be used by
 *	any subsystem that needs to schedule tasks and does not need to manage
 *	its own task queues. It is initialized quite early during system boot.
 *
 * IMPLEMENTATION ==============================================================
 *
 * This is schematic representation of the task queue structures.
 *
 *   taskq:
 *   +-------------+
 *   | tq_lock     | +---< taskq_ent_free()
 *   +-------------+ |
 *   |...          | | tqent:                  tqent:
 *   +-------------+ | +------------+          +------------+
 *   | tq_freelist |-->| tqent_next |--> ... ->| tqent_next |
 *   +-------------+   +------------+          +------------+
 *   |...          |   | ...        |          | ...        |
 *   +-------------+   +------------+          +------------+
 *   | tq_task     |    |
 *   |             |    +-------------->taskq_ent_alloc()
 * +--------------------------------------------------------------------------+
 * | |                     |            tqent                   tqent         |
 * | +---------------------+     +--> +------------+     +--> +------------+  |
 * | | ...		   |     |    | func, arg  |     |    | func, arg  |  |
 * +>+---------------------+ <---|-+  +------------+ <---|-+  +------------+  |
 *   | tq_task.tqent_next  | ----+ |  | tqent_next | --->+ |  | tqent_next |--+
 *   +---------------------+	   |  +------------+     ^ |  +------------+
 * +-| tq_task.tqent_prev  |	   +--| tqent_prev |     | +--| tqent_prev |  ^
 * | +---------------------+	      +------------+     |    +------------+  |
 * | |...		   |	      | ...        |     |    | ...        |  |
 * | +---------------------+	      +------------+     |    +------------+  |
 * |                                      ^              |                    |
 * |                                      |              |                    |
 * +--------------------------------------+--------------+       TQ_APPEND() -+
 *   |             |                      |
 *   |...          |   taskq_thread()-----+
 *   +-------------+
 *   | tq_buckets  |--+-------> [ NULL ] (for regular task queues)
 *   +-------------+  |
 *                    |   DYNAMIC TASK QUEUES:
 *                    |
 *                    +-> taskq_idlebucket	    taskq_idlebucket_dispatch()
 *                    +-> taskq_bucket[nCPU]		taskq_bucket_dispatch()
 *                        +-------------------+                    ^
 *                   +--->| tqbucket_lock     |                    |
 *                   |    +-------------------+   +--------+      +--------+
 *                   |    | tqbucket_freelist |-->| tqent  |-->...| tqent  |
 *                   |    +-------------------+<--+--------+<--...+--------+
 *                   |    |                   |   | thread |      | thread |
 *                   |    | ...               |   +--------+      +--------+
 *                   |    |                   |
 *                   |    +-------------------+   +--------+      +--------+
 *                   |    | tqbucket_backlog  |-->| tqent  |-->...| tqent  |
 *                   |    +-------------------+<--+--------+<--...+--------+
 *                   |    | ...               |   (no thread)
 *                   |    +-------------------+
 *		     |
 *                   |    +-------------------+
 * taskq_dispatch()--+--->| tqbucket_lock     |
 *      TQ_HASH()    |    +-------------------+   +--------+      +--------+
 *                   |    | tqbucket_freelist |-->| tqent  |-->...| tqent  |
 *                   |    +-------------------+<--+--------+<--...+--------+
 *                   |    |                   |   | thread |      | thread |
 *                   |    | ...               |   +--------+      +--------+
 *                   |    |                   |
 *                   |    +-------------------+   +--------+      +--------+
 *                   |    | tqbucket_backlog  |-->| tqent  |-->...| tqent  |
 *                   |    +-------------------+<--+--------+<--...+--------+
 *                   |    | ...               |   (no thread)
 *                   |    +-------------------+
 *		     |
 *		     +--->	...
 *
 *
 * Task queues use tq_task field to link new entry in the queue. The queue is a
 * circular doubly-linked list. Entries are put in the end of the list with
 * TQ_APPEND() and processed from the front of the list by taskq_thread() in
 * FIFO order. Task queue entries are cached in the free list managed by
 * taskq_ent_alloc() and taskq_ent_free() functions.
 *
 *	All threads used by task queues mark t_taskq field of the thread to
 *	point to the task queue.
 *
 * Taskq Thread Management -----------------------------------------------------
 *
 * Taskq's non-dynamic threads are managed with several variables and flags:
 *
 *	* tq_nthreads	- The number of threads in taskq_thread() for the
 *			  taskq.
 *
 *	* tq_active	- The number of threads not waiting on a CV in
 *			  taskq_thread(); includes newly created threads
 *			  not yet counted in tq_nthreads.
 *
 *	* tq_nthreads_target
 *			- The number of threads desired for the taskq.
 *
 *	* tq_flags & TASKQ_CHANGING
 *			- Indicates that tq_nthreads != tq_nthreads_target.
 *
 *	* tq_flags & TASKQ_THREAD_CREATED
 *			- Indicates that a thread is being created in the taskq.
 *
 * During creation, tq_nthreads and tq_active are set to 0, and
 * tq_nthreads_target is set to the number of threads desired.  The
 * TASKQ_CHANGING flag is set, and taskq_thread_create() is called to
 * create the first thread. taskq_thread_create() increments tq_active,
 * sets TASKQ_THREAD_CREATED, and creates the new thread.
 *
 * Each thread starts in taskq_thread(), clears the TASKQ_THREAD_CREATED
 * flag, and increments tq_nthreads.  It stores the new value of
 * tq_nthreads as its "thread_id", and stores its thread pointer in the
 * tq_threadlist at the (thread_id - 1).  We keep the thread_id space
 * densely packed by requiring that only the largest thread_id can exit during
 * normal adjustment.   The exception is during the destruction of the
 * taskq; once tq_nthreads_target is set to zero, no new threads will be created
 * for the taskq queue, so every thread can exit without any ordering being
 * necessary.
 *
 * Threads will only process work if their thread id is <= tq_nthreads_target.
 *
 * When TASKQ_CHANGING is set, threads will check the current thread target
 * whenever they wake up, and do whatever they can to apply its effects.
 *
 * TASKQ_THREAD_CPU_PCT --------------------------------------------------------
 *
 * When a taskq is created with TASKQ_THREAD_CPU_PCT, we store their requested
 * percentage in tq_threads_ncpus_pct, start them off with the correct thread
 * target, and add them to the taskq_cpupct_list for later adjustment.
 *
 * We register taskq_cpu_setup() to be called whenever a CPU changes state.  It
 * walks the list of TASKQ_THREAD_CPU_PCT taskqs, adjusts their nthreads_target
 * if need be, and wakes up all of the threads to process the change.
 *
 * Dynamic Task Queues Implementation ------------------------------------------
 *
 * For a dynamic task queue, the set of worker threads expands and contracts
 * based on the workload presented via taskq_dispatch calls. The work of a
 * dynamic task queue is distributed across an array of "buckets" to reduce
 * lock contention, with distribution determined via a hash (See TQ_HASH).
 * The array of buckets is sized based on the number of CPUs in the system.
 * The tunable 'taskq_maxbuckets' limits the maximum number of buckets.
 * One additional bucket is used as the "idle bucket" (details below).
 *
 * Each bucket also has a "backlog" list, used to store pending jobs,
 * which are taskq_ent_t objects with no associated thread.  The total of
 * backlogged work is distributed through the array of buckets, so that as
 * threads become available in each bucket, they begin work on the backlog
 * in parallel.  In order to ensure progress on the backlog, some care is
 * taken to avoid buckets with a backlog with no threads.
 *
 * Each bucket usually has some worker threads ready to accept new work,
 * represented by a taskq_ent_t on the tqbucket_freelist. In addition to
 * that array of buckets there is one more bucket called the "idle bucket",
 * used as a place to put idle threads that might be moved to a regular
 * bucket when that bucket needs another worker thread.  When a dispatch
 * call (one willing to sleep) finds no free thread in either the hashed
 * bucket free list nor in the idle bucket, it will attempt to create a
 * new thread in the hashed bucket (see taskq_bucket_extend).
 *
 * Dispatch first tries a bucket chosen by hash, then the idle bucket.
 * If the dispatch call allows sleeping, it then attempts to extend the
 * bucket chosen by hash, and makes a dispatch attempt on that bucket.
 * If that all fails, and if the dispatch call allows a queued task,
 * an entry is placed on a per-bucket backlog queue.  The backlog is
 * serviced as soon as other bucket threads become available.
 *
 * Worker threads wait a "short" time (taskq_thread_bucket_wait) on the
 * free list for the bucket in which they were dispatched, and if no new
 * work takes them off the free list before the expiration of the "short"
 * wait, the thread takes itself off that bucket free list and moves to
 * the "idle bucket", where waits longer (taskq_thread_timeout), before
 * giving up waiting for work and exiting.
 *
 * New threads normally start life in one of the buckets (chosen by hash)
 * and stay there while there's work for that bucket.  After a thread
 * waits in a bucket for a short time (taskq_d_svc_tmo) without having
 * any task assigned, it migrates to the idle bucket.  An exception
 * is made for TASKQ_PREPOPULATE, in which case threads start out in
 * the idle bucket.
 *
 * Running taskq_ent_t entries are not on any list. The dispatch function
 * sets their "func" and "arg" fields and signals the corresponding thread to
 * execute the task. Once the thread executes the task it clears the "func"
 * field and places an entry on the per-bucket "tqbucket_freelist" which is
 * used as a short-term cache of threads available for that bucket.  All
 * entries on the free list should have the "func" field equal to NULL.
 * The free list is a circular doubly-linked list identical in structure to
 * the tq_task list above, but entries are taken from it in LIFO order so
 * that threads seeing no work for a while can move to the idle bucket.
 *
 * The taskq_bucket_dispatch() function gets the most recently used entry
 * from the free list, sets its "func" and "arg" fields and signals a worker
 * thread.  Dispatch first tries a bucket selected via hash, then the idle
 * bucket.  If both of those fail (and depending on options) an attempt to
 * add threads to the bucket is made.
 *
 * After executing each task a per-entry thread taskq_d_thread() places its
 * entry on the bucket free list and goes to a (short) timed sleep. If it
 * wakes up without getting a new task it, it removes the entry from the
 * free list and "migrates" to the "idle bucket" for a longer wait.
 * If that longer wait expires without work arriving, the thread exits.
 * The thread sleep time is controlled by a tunable `taskq_thread_timeout'.
 * A thread may be dispatched work from the idle bucket (eg. when dispatch
 * fails to find a free entry in the hashed buckets).  When a thread is
 * dispatched from the idle bucket, it moves to the bucket that the hash
 * initially selected.
 *
 * Dynamic task queues make limited use of the "backing queue", which is
 * the same taskq->tq_task list used by orginary (non-dynamic) task queues.
 * The only taskq entries places on this list are for taskq_bucket_overflow
 * calls, used to request thread creation for some bucket after a dispatch
 * call fails to find a ready thread in some bucket.  There is only one
 * thread servicing this backing queue, so these jobs should only sleep
 * for memory allocation, and shoud not run jobs that block indefinitely.
 *
 * There are various statistics kept in the bucket which allows for later
 * analysis of taskq usage patterns. Also, a global copy of taskq creation and
 * death statistics is kept in the global taskq data structure. Since thread
 * creation and death happen rarely, updating such global data does not present
 * a performance problem.
 *
 * NOTE: Threads are not bound to any CPU and there is absolutely no association
 *       between the bucket and actual thread CPU, so buckets are used only to
 *	 split resources and reduce resource contention. Having threads attached
 *	 to the CPU denoted by a bucket may reduce number of times the job
 *	 switches between CPUs.
 *
 *	 Current algorithm creates a thread whenever a bucket has no free
 *	 entries. It would be nice to know how many threads are in the running
 *	 state and don't create threads if all CPUs are busy with existing
 *	 tasks, but it is unclear how such strategy can be implemented.
 *
 *	 Currently buckets are created statically as an array attached to task
 *	 queue. On some system with nCPUs < max_ncpus it may waste system
 *	 memory. One solution may be allocation of buckets when they are first
 *	 touched, but it is not clear how useful it is.
 *
 * SUSPEND/RESUME implementation -----------------------------------------------
 *
 *	Before executing a task taskq_thread() (executing non-dynamic task
 *	queues) obtains taskq's thread lock as a reader. The taskq_suspend()
 *	function gets the same lock as a writer blocking all non-dynamic task
 *	execution. The taskq_resume() function releases the lock allowing
 *	taskq_thread to continue execution.
 *
 *	For dynamic task queues, each bucket is marked as TQBUCKET_SUSPEND by
 *	taskq_suspend() function. After that taskq_bucket_dispatch() always
 *	fails, so that taskq_dispatch() will either enqueue tasks for a
 *	suspended backing queue or fail if TQ_NOQUEUE is specified in dispatch
 *	flags.
 *
 *	NOTE: taskq_suspend() does not immediately block any tasks already
 *	      scheduled for dynamic task queues. It only suspends new tasks
 *	      scheduled after taskq_suspend() was called.
 *
 *	taskq_member() function works by comparing a thread t_taskq pointer with
 *	the passed thread pointer.
 *
 * LOCKS and LOCK Order -------------------------------------------------------
 *
 *   There are four locks used in task queues:
 *
 *   1a) The idle bucket lock for bucket management.
 *   1b) The hashed bucket locks for bucket management.
 *
 *   2) The global taskq_cpupct_lock, which protects the list of
 *      TASKQ_THREADS_CPU_PCT taskqs.
 *
 *   3) The taskq_t's tq_lock, protecting global task queue state.
 *
 *   There are a few cases where two of these are entered, and when that
 *   happens the lock entries are in the order they are listed here.
 *
 * DEBUG FACILITIES ------------------------------------------------------------
 *
 * For DEBUG kernels it is possible to induce random failures to
 * taskq_dispatch() function when it is given TQ_NOSLEEP argument. The value of
 * taskq_dmtbf and taskq_smtbf tunables control the mean time between induced
 * failures for dynamic and static task queues respectively.
 *
 * Setting TASKQ_STATISTIC to 0 will disable per-bucket statistics.
 *
 * TUNABLES --------------------------------------------------------------------
 *
 *	system_taskq_size	- Size of the global system_taskq.
 *				  This value is multiplied by nCPUs to determine
 *				  actual size.
 *				  Default value: 64
 *
 *	taskq_minimum_nthreads_max
 *				- Minimum size of the thread list for a taskq.
 *				  Useful for testing different thread pool
 *				  sizes by overwriting tq_nthreads_target.
 *
 *	taskq_thread_timeout	- Maximum idle time for taskq_d_thread()
 *				  Default value: 5 minutes
 *
 *	taskq_maxbuckets	- Maximum number of buckets in any task queue
 *				  Default value: 128
 *
 *	taskq_dmtbf		- Mean time between induced dispatch failures
 *				  for dynamic task queues.
 *				  Default value: UINT_MAX (no induced failures)
 *
 *	taskq_smtbf		- Mean time between induced dispatch failures
 *				  for static task queues.
 *				  Default value: UINT_MAX (no induced failures)
 *
 * CONDITIONAL compilation -----------------------------------------------------
 *
 *    TASKQ_STATISTIC	- If set will enable bucket statistic (default).
 *
 */

#include <sys/taskq_impl.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/callb.h>
#include <sys/class.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>	/* For throttlefree */
#include <sys/sysmacros.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/sdt.h>
#include <sys/sysdc.h>
#include <sys/note.h>

static kmem_cache_t *taskq_ent_cache, *taskq_cache;

/*
 * Pseudo instance numbers for taskqs without explicitly provided instance.
 */
static vmem_t *taskq_id_arena;

/* Global system task queue for common use */
taskq_t	*system_taskq;

/*
 * Maximum number of entries in global system taskq is
 *	system_taskq_size * max_ncpus
 */
#define	SYSTEM_TASKQ_SIZE 64
int system_taskq_size = SYSTEM_TASKQ_SIZE;

/*
 * Minimum size for tq_nthreads_max; useful for those who want to play around
 * with increasing a taskq's tq_nthreads_target.
 */
int taskq_minimum_nthreads_max = 1;

/*
 * We want to ensure that when taskq_create() returns, there is at least
 * one thread ready to handle requests.  To guarantee this, we have to wait
 * for the second thread, since the first one cannot process requests until
 * the second thread has been created.
 */
#define	TASKQ_CREATE_ACTIVE_THREADS	2

/* Maximum percentage allowed for TASKQ_THREADS_CPU_PCT */
#define	TASKQ_CPUPCT_MAX_PERCENT	1000
int taskq_cpupct_max_percent = TASKQ_CPUPCT_MAX_PERCENT;

/*
 * Dynamic task queue threads that don't get any work within
 * taskq_thread_timeout destroy themselves
 */
#define	TASKQ_THREAD_TIMEOUT (60 * 5)
int taskq_thread_timeout = TASKQ_THREAD_TIMEOUT;

/*
 * Dynamic taskq queue threads stay in an empty bucket for only a
 * relatively short time before moving to the "idle bucket".
 */
int taskq_thread_bucket_wait = 500;	/* mSec. */

/*
 * A counter for debug and testing.  See the increment site below.
 */
uint64_t taskq_disptcreates_lost = 0;

/*
 * Upper and lower limits on number of buckets for dyanmic taskq.
 * Must be a power of two.  Dynamic should have more than one bucket.
 * The floor of four is chosen somewhat arbitrarily, based on the
 * smallest number of CPUs found in modern systems.
 */
#define	TASKQ_MINBUCKETS 4
int taskq_minbuckets = TASKQ_MINBUCKETS;
#define	TASKQ_MAXBUCKETS 128
int taskq_maxbuckets = TASKQ_MAXBUCKETS;

/*
 * Hashing function: mix various bits of x and CPUHINT
 *
 * This hash is applied to the "arg" address supplied to taskq_dispatch.
 * The distribution of objects in memory for that address are generally
 * whatever the memory allocation system provides. We know only that they
 * will be aligned to whatever minimum alignment is provided, and that the
 * sizes of these objects will vary. Due to the known aligment, this hash
 * function puts the CPU index in the lowest signigicant bits. Other bits
 * are simply combined via XOR using a (low-cost) byte-access-compatible
 * set of shifts. Emperical results show that this hash produces fairly
 * even distribution for the consumers in this system.
 */
#define	TQ_HASH(x, c)	((c) ^ (x) ^ ((x) >> 8) ^ ((x) >> 16) ^ ((x) >> 24))

/*
 * Get an index for the current CPU, used in the hash to spread
 * work among buckets based on what CPU is running this.
 */
#define	CPUHINT()		((uintptr_t)(CPU->cpu_seqid))

/*
 * We do not create any new threads when the system is low on memory and start
 * throttling memory allocations. The following macro tries to estimate such
 * condition.
 */
#define	ENOUGH_MEMORY() (freemem > throttlefree)

/*
 * Static functions.
 */
static taskq_t	*taskq_create_common(const char *, int, int, pri_t, int,
    int, proc_t *, uint_t, uint_t);
static void taskq_thread(void *);
static void taskq_d_thread(taskq_ent_t *);
static void taskq_d_migrate(void *);
static void taskq_d_redirect(void *);
static void taskq_bucket_overflow(void *);
static taskq_ent_t *taskq_bucket_extend(taskq_bucket_t *);
static void taskq_bucket_redist(taskq_bucket_t *);
static int  taskq_constructor(void *, void *, int);
static void taskq_destructor(void *, void *);
static int  taskq_ent_constructor(void *, void *, int);
static void taskq_ent_destructor(void *, void *);
static taskq_ent_t *taskq_ent_alloc(taskq_t *, int);
static void taskq_ent_free(taskq_t *, taskq_ent_t *);
static int taskq_ent_exists(taskq_t *, task_func_t, void *);
static taskq_ent_t *taskq_bucket_dispatch(taskq_bucket_t *, task_func_t,
    void *);
static void taskq_backlog_enqueue(taskq_bucket_t *,
    taskq_ent_t *tqe, int flags);

/*
 * Task queues kstats.
 */
struct taskq_kstat {
	kstat_named_t	tq_pid;
	kstat_named_t	tq_tasks;
	kstat_named_t	tq_executed;
	kstat_named_t	tq_maxtasks;
	kstat_named_t	tq_totaltime;
	kstat_named_t	tq_nalloc;
	kstat_named_t	tq_nactive;
	kstat_named_t	tq_pri;
	kstat_named_t	tq_nthreads;
	kstat_named_t	tq_nomem;
} taskq_kstat = {
	{ "pid",		KSTAT_DATA_UINT64 },
	{ "tasks",		KSTAT_DATA_UINT64 },
	{ "executed",		KSTAT_DATA_UINT64 },
	{ "maxtasks",		KSTAT_DATA_UINT64 },
	{ "totaltime",		KSTAT_DATA_UINT64 },
	{ "nalloc",		KSTAT_DATA_UINT64 },
	{ "nactive",		KSTAT_DATA_UINT64 },
	{ "priority",		KSTAT_DATA_UINT64 },
	{ "threads",		KSTAT_DATA_UINT64 },
	{ "nomem",		KSTAT_DATA_UINT64 },
};

struct taskq_d_kstat {
	kstat_named_t	tqd_pri;
	kstat_named_t	tqd_hits;
	kstat_named_t	tqd_misses;
	kstat_named_t	tqd_ihits;	/* idle bucket hits */
	kstat_named_t	tqd_imisses;	/* idle bucket misses */
	kstat_named_t	tqd_overflows;
	kstat_named_t	tqd_tcreates;
	kstat_named_t	tqd_tdeaths;
	kstat_named_t	tqd_maxthreads;
	kstat_named_t	tqd_nomem;
	kstat_named_t	tqd_disptcreates;
	kstat_named_t	tqd_totaltime;
	kstat_named_t	tqd_nalloc;
	kstat_named_t	tqd_nfree;
	kstat_named_t	tqd_nbacklog;
	kstat_named_t	tqd_maxbacklog;
} taskq_d_kstat = {
	{ "priority",		KSTAT_DATA_UINT64 },
	{ "hits",		KSTAT_DATA_UINT64 },
	{ "misses",		KSTAT_DATA_UINT64 },
	{ "ihits",		KSTAT_DATA_UINT64 },
	{ "imisses",		KSTAT_DATA_UINT64 },
	{ "overflows",		KSTAT_DATA_UINT64 },
	{ "tcreates",		KSTAT_DATA_UINT64 },
	{ "tdeaths",		KSTAT_DATA_UINT64 },
	{ "maxthreads",		KSTAT_DATA_UINT64 },
	{ "nomem",		KSTAT_DATA_UINT64 },
	{ "disptcreates",	KSTAT_DATA_UINT64 },
	{ "totaltime",		KSTAT_DATA_UINT64 },
	{ "nalloc",		KSTAT_DATA_UINT64 },
	{ "nfree",		KSTAT_DATA_UINT64 },
	{ "nbacklog",		KSTAT_DATA_UINT64 },
	{ "maxbacklog",		KSTAT_DATA_UINT64 },
};

static kmutex_t taskq_kstat_lock;
static kmutex_t taskq_d_kstat_lock;
static int taskq_kstat_update(kstat_t *, int);
static int taskq_d_kstat_update(kstat_t *, int);

/*
 * List of all TASKQ_THREADS_CPU_PCT taskqs.
 */
static list_t taskq_cpupct_list;	/* protected by cpu_lock */

/*
 * Collect per-bucket statistic when TASKQ_STATISTIC is defined.
 */
#define	TASKQ_STATISTIC 1

#if TASKQ_STATISTIC
#define	TQ_STAT(b, x)	b->tqbucket_stat.x++
#else
#define	TQ_STAT(b, x)
#endif

/*
 * Random fault injection.
 */
uint_t taskq_random;
uint_t taskq_dmtbf = UINT_MAX;    /* mean time between injected failures */
uint_t taskq_smtbf = UINT_MAX;    /* mean time between injected failures */

/*
 * TQ_NOSLEEP dispatches on dynamic task queues are always allowed to fail.
 *
 * TQ_NOSLEEP dispatches on static task queues can't arbitrarily fail because
 * they could prepopulate the cache and make sure that they do not use more
 * then minalloc entries.  So, fault injection in this case insures that
 * either TASKQ_PREPOPULATE is not set or there are more entries allocated
 * than is specified by minalloc.  TQ_NOALLOC dispatches are always allowed
 * to fail, but for simplicity we treat them identically to TQ_NOSLEEP
 * dispatches.
 */
#ifdef DEBUG
#define	TASKQ_D_RANDOM_DISPATCH_FAILURE(tq, flag)		\
	taskq_random = (taskq_random * 2416 + 374441) % 1771875;\
	if ((flag & TQ_NOSLEEP) &&				\
	    taskq_random < 1771875 / taskq_dmtbf) {		\
		return (TASKQID_INVALID);			\
	}

#define	TASKQ_S_RANDOM_DISPATCH_FAILURE(tq, flag)		\
	taskq_random = (taskq_random * 2416 + 374441) % 1771875;\
	if ((flag & (TQ_NOSLEEP | TQ_NOALLOC)) &&		\
	    (!(tq->tq_flags & TASKQ_PREPOPULATE) ||		\
	    (tq->tq_nalloc > tq->tq_minalloc)) &&		\
	    (taskq_random < (1771875 / taskq_smtbf))) {		\
		mutex_exit(&tq->tq_lock);			\
		return (TASKQID_INVALID);			\
	}
#else
#define	TASKQ_S_RANDOM_DISPATCH_FAILURE(tq, flag)
#define	TASKQ_D_RANDOM_DISPATCH_FAILURE(tq, flag)
#endif

#define	IS_EMPTY(l) (((l).tqent_prev == (l).tqent_next) &&	\
	((l).tqent_prev == &(l)))

/*
 * Initialize 'tqe' list head
 */
#define	TQ_LIST_INIT(l) {					\
	l.tqent_next = &l;					\
	l.tqent_prev = &l;					\
}
/*
 * Append `tqe' in the end of the doubly-linked list denoted by l.
 */
#define	TQ_APPEND(l, tqe) {					\
	tqe->tqent_next = &l;					\
	tqe->tqent_prev = l.tqent_prev;				\
	tqe->tqent_next->tqent_prev = tqe;			\
	tqe->tqent_prev->tqent_next = tqe;			\
}
/*
 * Prepend 'tqe' to the beginning of l
 */
#define	TQ_PREPEND(l, tqe) {					\
	tqe->tqent_next = l.tqent_next;				\
	tqe->tqent_prev = &l;					\
	tqe->tqent_next->tqent_prev = tqe;			\
	tqe->tqent_prev->tqent_next = tqe;			\
}
/*
 * Remove 'tqe' from some list
 */
#define	TQ_REMOVE(tqe) {					\
	tqe->tqent_prev->tqent_next = tqe->tqent_next;		\
	tqe->tqent_next->tqent_prev = tqe->tqent_prev;		\
	tqe->tqent_next = NULL;					\
	tqe->tqent_prev = NULL;					\
}

/*
 * Schedule a task specified by func and arg into the task queue entry tqe.
 */
#define	TQ_DO_ENQUEUE(tq, tqe, func, arg, front) {			\
	ASSERT(MUTEX_HELD(&tq->tq_lock));				\
	_NOTE(CONSTCOND)						\
	if (front) {							\
		TQ_PREPEND(tq->tq_task, tqe);				\
	} else {							\
		TQ_APPEND(tq->tq_task, tqe);				\
	}								\
	tqe->tqent_func = (func);					\
	tqe->tqent_arg = (arg);						\
	tq->tq_tasks++;							\
	if (tq->tq_tasks - tq->tq_executed > tq->tq_maxtasks)		\
		tq->tq_maxtasks = tq->tq_tasks - tq->tq_executed;	\
	cv_signal(&tq->tq_dispatch_cv);					\
	DTRACE_PROBE2(taskq__enqueue, taskq_t *, tq, taskq_ent_t *, tqe); \
}

#define	TQ_ENQUEUE(tq, tqe, func, arg)					\
	TQ_DO_ENQUEUE(tq, tqe, func, arg, 0)

#define	TQ_ENQUEUE_FRONT(tq, tqe, func, arg)				\
	TQ_DO_ENQUEUE(tq, tqe, func, arg, 1)

/*
 * Do-nothing task which may be used to prepopulate thread caches.
 */
/*ARGSUSED*/
void
nulltask(void *unused)
{
}

/*ARGSUSED*/
static int
taskq_constructor(void *buf, void *cdrarg, int kmflags)
{
	taskq_t *tq = buf;

	bzero(tq, sizeof (taskq_t));

	mutex_init(&tq->tq_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&tq->tq_threadlock, NULL, RW_DEFAULT, NULL);
	cv_init(&tq->tq_dispatch_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&tq->tq_exit_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&tq->tq_wait_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&tq->tq_maxalloc_cv, NULL, CV_DEFAULT, NULL);

	tq->tq_task.tqent_next = &tq->tq_task;
	tq->tq_task.tqent_prev = &tq->tq_task;

	return (0);
}

/*ARGSUSED*/
static void
taskq_destructor(void *buf, void *cdrarg)
{
	taskq_t *tq = buf;

	ASSERT(tq->tq_nthreads == 0);
	ASSERT(tq->tq_buckets == NULL);
	ASSERT(tq->tq_dnthreads == 0);

	mutex_destroy(&tq->tq_lock);
	rw_destroy(&tq->tq_threadlock);
	cv_destroy(&tq->tq_dispatch_cv);
	cv_destroy(&tq->tq_exit_cv);
	cv_destroy(&tq->tq_wait_cv);
	cv_destroy(&tq->tq_maxalloc_cv);
}

/*ARGSUSED*/
static int
taskq_ent_constructor(void *buf, void *cdrarg, int kmflags)
{
	taskq_ent_t *tqe = buf;

	tqe->tqent_thread = NULL;
	cv_init(&tqe->tqent_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
taskq_ent_destructor(void *buf, void *cdrarg)
{
	taskq_ent_t *tqe = buf;

	ASSERT(tqe->tqent_thread == NULL);
	cv_destroy(&tqe->tqent_cv);
}

void
taskq_init(void)
{
	taskq_ent_cache = kmem_cache_create("taskq_ent_cache",
	    sizeof (taskq_ent_t), 0, taskq_ent_constructor,
	    taskq_ent_destructor, NULL, NULL, NULL, 0);
	taskq_cache = kmem_cache_create("taskq_cache", sizeof (taskq_t),
	    0, taskq_constructor, taskq_destructor, NULL, NULL, NULL, 0);
	taskq_id_arena = vmem_create("taskq_id_arena",
	    (void *)1, INT32_MAX, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);

	list_create(&taskq_cpupct_list, sizeof (taskq_t),
	    offsetof(taskq_t, tq_cpupct_link));
}

static void
taskq_update_nthreads(taskq_t *tq, uint_t ncpus)
{
	uint_t newtarget = TASKQ_THREADS_PCT(ncpus, tq->tq_threads_ncpus_pct);

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&tq->tq_lock));

	/* We must be going from non-zero to non-zero; no exiting. */
	ASSERT3U(tq->tq_nthreads_target, !=, 0);
	ASSERT3U(newtarget, !=, 0);

	ASSERT3U(newtarget, <=, tq->tq_nthreads_max);
	if (newtarget != tq->tq_nthreads_target) {
		tq->tq_flags |= TASKQ_CHANGING;
		tq->tq_nthreads_target = newtarget;
		cv_broadcast(&tq->tq_dispatch_cv);
		cv_broadcast(&tq->tq_exit_cv);
	}
}

/* called during task queue creation */
static void
taskq_cpupct_install(taskq_t *tq, cpupart_t *cpup)
{
	ASSERT(tq->tq_flags & TASKQ_THREADS_CPU_PCT);

	mutex_enter(&cpu_lock);
	mutex_enter(&tq->tq_lock);
	tq->tq_cpupart = cpup->cp_id;
	taskq_update_nthreads(tq, cpup->cp_ncpus);
	mutex_exit(&tq->tq_lock);

	list_insert_tail(&taskq_cpupct_list, tq);
	mutex_exit(&cpu_lock);
}

static void
taskq_cpupct_remove(taskq_t *tq)
{
	ASSERT(tq->tq_flags & TASKQ_THREADS_CPU_PCT);

	mutex_enter(&cpu_lock);
	list_remove(&taskq_cpupct_list, tq);
	mutex_exit(&cpu_lock);
}

/*ARGSUSED*/
static int
taskq_cpu_setup(cpu_setup_t what, int id, void *arg)
{
	taskq_t *tq;
	cpupart_t *cp = cpu[id]->cpu_part;
	uint_t ncpus = cp->cp_ncpus;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(ncpus > 0);

	switch (what) {
	case CPU_OFF:
	case CPU_CPUPART_OUT:
		/* offlines are called *before* the cpu is offlined. */
		if (ncpus > 1)
			ncpus--;
		break;

	case CPU_ON:
	case CPU_CPUPART_IN:
		break;

	default:
		return (0);		/* doesn't affect cpu count */
	}

	for (tq = list_head(&taskq_cpupct_list); tq != NULL;
	    tq = list_next(&taskq_cpupct_list, tq)) {

		mutex_enter(&tq->tq_lock);
		/*
		 * If the taskq is part of the cpuset which is changing,
		 * update its nthreads_target.
		 */
		if (tq->tq_cpupart == cp->cp_id) {
			taskq_update_nthreads(tq, ncpus);
		}
		mutex_exit(&tq->tq_lock);
	}
	return (0);
}

void
taskq_mp_init(void)
{
	mutex_enter(&cpu_lock);
	register_cpu_setup_func(taskq_cpu_setup, NULL);
	/*
	 * Make sure we're up to date.  At this point in boot, there is only
	 * one processor set, so we only have to update the current CPU.
	 */
	(void) taskq_cpu_setup(CPU_ON, CPU->cpu_id, NULL);
	mutex_exit(&cpu_lock);
}

/*
 * Create global system dynamic task queue.
 */
void
system_taskq_init(void)
{
	system_taskq = taskq_create_common("system_taskq", 0,
	    system_taskq_size * max_ncpus, minclsyspri, 4, 512, &p0, 0,
	    TASKQ_DYNAMIC | TASKQ_PREPOPULATE);
}

/*
 * taskq_ent_alloc()
 *
 * Allocates a new taskq_ent_t structure either from the free list or from the
 * cache. Returns NULL if it can't be allocated.
 *
 * Assumes: tq->tq_lock is held.
 */
static taskq_ent_t *
taskq_ent_alloc(taskq_t *tq, int flags)
{
	int kmflags = (flags & TQ_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;
	taskq_ent_t *tqe;
	clock_t wait_time;
	clock_t	wait_rv;

	ASSERT(MUTEX_HELD(&tq->tq_lock));

	/*
	 * TQ_NOALLOC allocations are allowed to use the freelist, even if
	 * we are below tq_minalloc.
	 */
again:	if ((tqe = tq->tq_freelist) != NULL &&
	    ((flags & TQ_NOALLOC) || tq->tq_nalloc >= tq->tq_minalloc)) {
		tq->tq_freelist = tqe->tqent_next;
	} else {
		if (flags & TQ_NOALLOC)
			return (NULL);

		if (tq->tq_nalloc >= tq->tq_maxalloc) {
			if (kmflags & KM_NOSLEEP)
				return (NULL);

			/*
			 * We don't want to exceed tq_maxalloc, but we can't
			 * wait for other tasks to complete (and thus free up
			 * task structures) without risking deadlock with
			 * the caller.  So, we just delay for one second
			 * to throttle the allocation rate. If we have tasks
			 * complete before one second timeout expires then
			 * taskq_ent_free will signal us and we will
			 * immediately retry the allocation (reap free).
			 */
			wait_time = ddi_get_lbolt() + hz;
			while (tq->tq_freelist == NULL) {
				tq->tq_maxalloc_wait++;
				wait_rv = cv_timedwait(&tq->tq_maxalloc_cv,
				    &tq->tq_lock, wait_time);
				tq->tq_maxalloc_wait--;
				if (wait_rv == -1)
					break;
			}
			if (tq->tq_freelist)
				goto again;		/* reap freelist */

		}
		mutex_exit(&tq->tq_lock);

		tqe = kmem_cache_alloc(taskq_ent_cache, kmflags);

		mutex_enter(&tq->tq_lock);
		if (tqe != NULL)
			tq->tq_nalloc++;
	}
	return (tqe);
}

/*
 * taskq_ent_free()
 *
 * Free taskq_ent_t structure by either putting it on the free list or freeing
 * it to the cache.
 *
 * Assumes: tq->tq_lock is held.
 */
static void
taskq_ent_free(taskq_t *tq, taskq_ent_t *tqe)
{
	ASSERT(MUTEX_HELD(&tq->tq_lock));

	if (tq->tq_nalloc <= tq->tq_minalloc) {
		tqe->tqent_next = tq->tq_freelist;
		tq->tq_freelist = tqe;
	} else {
		tq->tq_nalloc--;
		mutex_exit(&tq->tq_lock);
		kmem_cache_free(taskq_ent_cache, tqe);
		mutex_enter(&tq->tq_lock);
	}

	if (tq->tq_maxalloc_wait)
		cv_signal(&tq->tq_maxalloc_cv);
}

/*
 * taskq_ent_exists()
 *
 * Return 1 if taskq already has entry for calling 'func(arg)'.
 *
 * Assumes: tq->tq_lock is held.
 */
static int
taskq_ent_exists(taskq_t *tq, task_func_t func, void *arg)
{
	taskq_ent_t	*tqe;

	ASSERT(MUTEX_HELD(&tq->tq_lock));

	for (tqe = tq->tq_task.tqent_next; tqe != &tq->tq_task;
	    tqe = tqe->tqent_next)
		if ((tqe->tqent_func == func) && (tqe->tqent_arg == arg))
			return (1);
	return (0);
}

/*
 * Dispatch a task "func(arg)" to a free entry of bucket b.
 *
 * Assumes: no bucket locks is held.
 *
 * Returns: a pointer to an entry if dispatch was successful.
 *	    NULL if there are no free entries or if the bucket is suspended.
 */
static taskq_ent_t *
taskq_bucket_dispatch(taskq_bucket_t *b, task_func_t func, void *arg)
{
	taskq_ent_t *tqe;
	taskq_t *tq = b->tqbucket_taskq;
	taskq_bucket_t *idleb = &tq->tq_buckets[tq->tq_nbuckets];

	ASSERT(MUTEX_NOT_HELD(&b->tqbucket_lock));
	ASSERT(func != NULL);
	VERIFY(b >= tq->tq_buckets && b < idleb);

	mutex_enter(&b->tqbucket_lock);

	ASSERT(b->tqbucket_nfree != 0 || IS_EMPTY(b->tqbucket_freelist));
	ASSERT(b->tqbucket_nfree == 0 || !IS_EMPTY(b->tqbucket_freelist));

	/*
	 * Get en entry from the freelist if there is one.
	 * Schedule task into the entry.
	 */
	if ((b->tqbucket_nfree != 0) &&
	    !(b->tqbucket_flags & TQBUCKET_SUSPEND)) {
		tqe = b->tqbucket_freelist.tqent_prev;

		ASSERT(tqe != &b->tqbucket_freelist);
		ASSERT(tqe->tqent_thread != NULL);

		TQ_REMOVE(tqe);
		b->tqbucket_nfree--;
		tqe->tqent_func = func;
		tqe->tqent_arg = arg;
		b->tqbucket_nalloc++;
		DTRACE_PROBE2(taskq__d__enqueue, taskq_bucket_t *, b,
		    taskq_ent_t *, tqe);
		cv_signal(&tqe->tqent_cv);
		TQ_STAT(b, tqs_hits);
	} else {
		tqe = NULL;
		TQ_STAT(b, tqs_misses);
	}
	mutex_exit(&b->tqbucket_lock);
	return (tqe);
}

/*
 * Dispatch a task "func(arg)" using a free entry from the "idle" bucket.
 * If we succeed finding a free entry, migrate that thread from the "idle"
 * bucket to the bucket passed (b).
 *
 * Assumes: no bucket locks is held.
 *
 * Returns: a pointer to an entry if dispatch was successful.
 *	    NULL if there are no free entries or if the bucket is suspended.
 */
static taskq_ent_t *
taskq_idlebucket_dispatch(taskq_bucket_t *b, task_func_t func, void *arg)
{
	taskq_ent_t	*tqe;
	taskq_t		*tq = b->tqbucket_taskq;
	taskq_bucket_t	*idleb = &tq->tq_buckets[tq->tq_nbuckets];

	ASSERT(func != NULL);
	ASSERT(b != idleb);
	ASSERT(MUTEX_NOT_HELD(&b->tqbucket_lock));
	ASSERT(MUTEX_NOT_HELD(&idleb->tqbucket_lock));

	/*
	 * Get out quickly (without locks) if unlikely to succeed.
	 */
	if (idleb->tqbucket_nfree == 0) {
		TQ_STAT(idleb, tqs_misses);
		return (NULL);
	}

	/*
	 * Need the mutex on both the idle bucket (idleb) and bucket (b)
	 * entered below. See Locks and Lock Order in the top comments.
	 */
	mutex_enter(&idleb->tqbucket_lock);

	IMPLY(idleb->tqbucket_nfree == 0, IS_EMPTY(idleb->tqbucket_freelist));
	IMPLY(idleb->tqbucket_nfree != 0, !IS_EMPTY(idleb->tqbucket_freelist));

	/*
	 * Get an entry from the idle bucket freelist if there is one.
	 * Schedule task into the entry.
	 */
	if ((idleb->tqbucket_nfree != 0) &&
	    !(idleb->tqbucket_flags & TQBUCKET_SUSPEND)) {
		tqe = idleb->tqbucket_freelist.tqent_prev;

		ASSERT(tqe != &idleb->tqbucket_freelist);
		ASSERT(tqe->tqent_thread != NULL);

		TQ_REMOVE(tqe);
		idleb->tqbucket_nfree--;

		tqe->tqent_func = func;
		tqe->tqent_arg = arg;

		/*
		 * Note move TQE to new bucket here!
		 * See reaction in taskq_d_thread
		 */
		tqe->tqent_un.tqent_bucket = b;

		/*
		 * Track the "alloc" on the bucket moved to,
		 * as if this tqe were dispatched from there.
		 */
		mutex_enter(&b->tqbucket_lock);
		b->tqbucket_nalloc++;
		mutex_exit(&b->tqbucket_lock);

		DTRACE_PROBE2(taskq__d__enqueue, taskq_bucket_t *, b,
		    taskq_ent_t *, tqe);

		/* Let the tqe thread run. */
		cv_signal(&tqe->tqent_cv);

		/* Count this as a "hit" on the idle bucket. */
		TQ_STAT(idleb, tqs_hits);
	} else {
		tqe = NULL;
		TQ_STAT(idleb, tqs_misses);
	}

	mutex_exit(&idleb->tqbucket_lock);

	return (tqe);
}

/*
 * Enqueue a taskq job on the per-bucket backlog.
 */
static taskq_ent_t *
taskq_backlog_dispatch(taskq_bucket_t *bucket, task_func_t func, void *arg,
    int flags)
{
	taskq_ent_t *tqe;
	int kmflags = (flags & TQ_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	tqe = kmem_cache_alloc(taskq_ent_cache, kmflags);
	if (tqe == NULL)
		return (tqe);

	tqe->tqent_func = func;
	tqe->tqent_arg = arg;

	mutex_enter(&bucket->tqbucket_lock);
	taskq_backlog_enqueue(bucket, tqe, flags);
	mutex_exit(&bucket->tqbucket_lock);

	return (tqe);
}

static void
taskq_backlog_enqueue(taskq_bucket_t *bucket, taskq_ent_t *tqe, int flags)
{

	ASSERT(MUTEX_HELD(&bucket->tqbucket_lock));

	tqe->tqent_un.tqent_bucket = bucket;
	if ((flags & TQ_FRONT) != 0) {
		TQ_PREPEND(bucket->tqbucket_backlog, tqe);
	} else {
		TQ_APPEND(bucket->tqbucket_backlog, tqe);
	}
	bucket->tqbucket_nbacklog++;
	/* See membar_consumer in taskq_d_thread(). */
	membar_producer();
	DTRACE_PROBE2(taskq__d__enqueue,
	    taskq_bucket_t *, bucket,
	    taskq_ent_t *, tqe);
	TQ_STAT(bucket, tqs_overflow);
#if TASKQ_STATISTIC
	if (bucket->tqbucket_stat.tqs_maxbacklog <
	    bucket->tqbucket_nbacklog) {
		bucket->tqbucket_stat.tqs_maxbacklog =
		    bucket->tqbucket_nbacklog;
	}
#endif
	/*
	 * Before this function is called, the caller has tried
	 * taskq_bucket_dispatch, taskq_idlebucket_dispatch, and
	 * not found any idle TQE. The bucket lock is dropped
	 * between those calls and this, so it's possible that a
	 * TQE worker became idle before we entered the mutex.
	 * Check for that here and wake an idle thread so it
	 * will re-check the backlog.
	 */
	if (bucket->tqbucket_nfree != 0) {
		taskq_ent_t *itqe;
		itqe = bucket->tqbucket_freelist.tqent_prev;
		cv_signal(&itqe->tqent_cv);
	}
}

/*
 * Dispatch a task.
 *
 * Assumes: func != NULL
 *
 * Returns: NULL if dispatch failed.
 *	    non-NULL if task dispatched successfully.
 *	    Actual return value is the pointer to taskq entry that was used to
 *	    dispatch a task. This is useful for debugging.
 */
taskqid_t
taskq_dispatch(taskq_t *tq, task_func_t func, void *arg, uint_t flags)
{
	taskq_bucket_t *bucket = NULL;	/* Which bucket needs extension */
	taskq_ent_t *tqe = NULL;
	uint_t bsize;

	ASSERT(tq != NULL);
	ASSERT(func != NULL);

	if ((tq->tq_flags & TASKQ_DYNAMIC) == 0) {
		/*
		 * TQ_NOQUEUE flag can't be used with non-dynamic task queues.
		 */
		ASSERT(!(flags & TQ_NOQUEUE));
		/*
		 * Enqueue the task to the underlying queue.
		 */
		mutex_enter(&tq->tq_lock);

		TASKQ_S_RANDOM_DISPATCH_FAILURE(tq, flags);

		if ((tqe = taskq_ent_alloc(tq, flags)) == NULL) {
			tq->tq_nomem++;
			mutex_exit(&tq->tq_lock);
			return ((taskqid_t)tqe);
		}
		/* Make sure we start without any flags */
		tqe->tqent_un.tqent_flags = 0;

		if (flags & TQ_FRONT) {
			TQ_ENQUEUE_FRONT(tq, tqe, func, arg);
		} else {
			TQ_ENQUEUE(tq, tqe, func, arg);
		}
		mutex_exit(&tq->tq_lock);
		return ((taskqid_t)tqe);
	}

	/*
	 * Dynamic taskq dispatching.
	 */
	ASSERT(!(flags & (TQ_NOALLOC | TQ_FRONT)));
	TASKQ_D_RANDOM_DISPATCH_FAILURE(tq, flags);

	ASSERT(func != taskq_d_migrate);
	ASSERT(func != taskq_d_redirect);

	bsize = tq->tq_nbuckets;

	if (bsize == 1) {
		/*
		 * In a single-CPU case there is only one bucket, so get
		 * entry directly from there.
		 */
		tqe = taskq_bucket_dispatch(tq->tq_buckets, func, arg);
		if (tqe != NULL)
			return ((taskqid_t)tqe);	/* Fastpath */
		bucket = tq->tq_buckets;
	} else {
		uintptr_t h = TQ_HASH((uintptr_t)arg, CPUHINT());

		bucket = &tq->tq_buckets[h & (bsize - 1)];
		ASSERT(bucket->tqbucket_taskq == tq);	/* Sanity check */

		/*
		 * Do a quick check before grabbing the lock. If the bucket does
		 * not have free entries now, chances are very small that it
		 * will after we take the lock, so we just skip it.
		 */
		if (bucket->tqbucket_nfree != 0) {
			tqe = taskq_bucket_dispatch(bucket, func, arg);
			if (tqe != NULL)
				return ((taskqid_t)tqe);	/* Fastpath */
		} else {
			TQ_STAT(bucket, tqs_misses);
		}
	}

	/*
	 * Try the "idle" bucket, which if successful, will
	 * migrate an idle thread into this bucket.
	 */
	tqe = taskq_idlebucket_dispatch(bucket, func, arg);
	if (tqe != NULL)
		return ((taskqid_t)tqe);

	/*
	 * At this point we have failed to dispatch (tqe == NULL).
	 * Try more expensive measures, if appropriate.
	 */
	ASSERT(tqe == NULL);

	/*
	 * For KM_SLEEP dispatches, try to extend the bucket and retry dispatch.
	 *
	 * taskq_bucket_extend() may fail to do anything, but this is
	 * fine - we deal with it later. If the bucket was successfully
	 * extended, there is a good chance that taskq_bucket_dispatch()
	 * will get this new entry, unless another dispatch is racing with
	 * this one and steals the new entry from under us.  In that (rare)
	 * case, repeat the taskq_bucket_extend() call.  Keep a count of
	 * the "lost the race" events just for debug and testing.
	 */
	if ((flags & TQ_NOSLEEP) == 0) {
		while (taskq_bucket_extend(bucket) != NULL) {
			TQ_STAT(bucket, tqs_disptcreates);
			tqe = taskq_bucket_dispatch(bucket, func, arg);
			if (tqe != NULL) {
				return ((taskqid_t)tqe);
			}
			taskq_disptcreates_lost++;
		}
	}

	/*
	 * Dispatch failed and we can't find an entry to schedule a task.
	 * Use the per-bucket backlog queue unless TQ_NOQUEUE was asked.
	 * Whether or not this succeeds, we'll schedule an asynchornous
	 * task to try to extend (add a thread to) this bucket.
	 */
	if ((flags & TQ_NOQUEUE) == 0) {
		tqe = taskq_backlog_dispatch(bucket, func, arg, flags);
	}

	/*
	 * Since there are not enough free entries in the bucket, add a
	 * taskq entry to the backing queue to extend it in the background
	 * (unless we already have a taskq entry to perform that work).
	 *
	 * Note that this is the ONLY case where dynamic taskq's use the
	 * (single threaded) tq->tq_tasks dispatch mechanism.
	 */
	mutex_enter(&tq->tq_lock);
	if (!taskq_ent_exists(tq, taskq_bucket_overflow, bucket)) {
		taskq_ent_t *tqe1;
		if ((tqe1 = taskq_ent_alloc(tq, flags)) != NULL) {
			TQ_ENQUEUE(tq, tqe1, taskq_bucket_overflow, bucket);
		} else {
			tq->tq_nomem++;
		}
	}
	mutex_exit(&tq->tq_lock);

	return ((taskqid_t)tqe);
}

void
taskq_dispatch_ent(taskq_t *tq, task_func_t func, void *arg, uint_t flags,
    taskq_ent_t *tqe)
{
	ASSERT(func != NULL);
	ASSERT(!(tq->tq_flags & TASKQ_DYNAMIC));

	/*
	 * Mark it as a prealloc'd task.  This is important
	 * to ensure that we don't free it later.
	 */
	tqe->tqent_un.tqent_flags |= TQENT_FLAG_PREALLOC;
	/*
	 * Enqueue the task to the underlying queue.
	 */
	mutex_enter(&tq->tq_lock);

	if (flags & TQ_FRONT) {
		TQ_ENQUEUE_FRONT(tq, tqe, func, arg);
	} else {
		TQ_ENQUEUE(tq, tqe, func, arg);
	}
	mutex_exit(&tq->tq_lock);
}

/*
 * Allow our caller to ask if there are tasks pending on the queue.
 */
boolean_t
taskq_empty(taskq_t *tq)
{
	boolean_t rv;

	ASSERT3P(tq, !=, curthread->t_taskq);
	mutex_enter(&tq->tq_lock);
	rv = (tq->tq_task.tqent_next == &tq->tq_task) && (tq->tq_active == 0);
	mutex_exit(&tq->tq_lock);

	return (rv);
}

/*
 * Wait for all pending tasks to complete.
 * Calling taskq_wait from a task will cause deadlock.
 */
void
taskq_wait(taskq_t *tq)
{
	ASSERT(tq != curthread->t_taskq);

	mutex_enter(&tq->tq_lock);
	while (tq->tq_task.tqent_next != &tq->tq_task || tq->tq_active != 0)
		cv_wait(&tq->tq_wait_cv, &tq->tq_lock);
	mutex_exit(&tq->tq_lock);

	if (tq->tq_flags & TASKQ_DYNAMIC) {
		taskq_bucket_t *b = tq->tq_buckets;
		int bid = 0;
		for (; (b != NULL) && (bid <= tq->tq_nbuckets); b++, bid++) {
			mutex_enter(&b->tqbucket_lock);
			while (b->tqbucket_nalloc > 0 ||
			    b->tqbucket_nbacklog > 0)
				cv_wait(&b->tqbucket_cv, &b->tqbucket_lock);
			mutex_exit(&b->tqbucket_lock);
		}
	}
}

void
taskq_wait_id(taskq_t *tq, taskqid_t id __unused)
{
	taskq_wait(tq);
}

/*
 * Suspend execution of tasks.
 *
 * Tasks in the queue part will be suspended immediately upon return from this
 * function. Pending tasks in the dynamic part will continue to execute, but all
 * new tasks will  be suspended.
 */
void
taskq_suspend(taskq_t *tq)
{
	rw_enter(&tq->tq_threadlock, RW_WRITER);

	if (tq->tq_flags & TASKQ_DYNAMIC) {
		taskq_bucket_t *b = tq->tq_buckets;
		int bid = 0;
		for (; (b != NULL) && (bid <= tq->tq_nbuckets); b++, bid++) {
			mutex_enter(&b->tqbucket_lock);
			b->tqbucket_flags |= TQBUCKET_SUSPEND;
			mutex_exit(&b->tqbucket_lock);
		}
	}
	/*
	 * Mark task queue as being suspended. Needed for taskq_suspended().
	 */
	mutex_enter(&tq->tq_lock);
	ASSERT(!(tq->tq_flags & TASKQ_SUSPENDED));
	tq->tq_flags |= TASKQ_SUSPENDED;
	mutex_exit(&tq->tq_lock);
}

/*
 * returns: 1 if tq is suspended, 0 otherwise.
 */
int
taskq_suspended(taskq_t *tq)
{
	return ((tq->tq_flags & TASKQ_SUSPENDED) != 0);
}

/*
 * Resume taskq execution.
 */
void
taskq_resume(taskq_t *tq)
{
	ASSERT(RW_WRITE_HELD(&tq->tq_threadlock));

	if (tq->tq_flags & TASKQ_DYNAMIC) {
		taskq_bucket_t *b = tq->tq_buckets;
		int bid = 0;
		for (; (b != NULL) && (bid <= tq->tq_nbuckets); b++, bid++) {
			mutex_enter(&b->tqbucket_lock);
			b->tqbucket_flags &= ~TQBUCKET_SUSPEND;
			mutex_exit(&b->tqbucket_lock);
		}
	}
	mutex_enter(&tq->tq_lock);
	ASSERT(tq->tq_flags & TASKQ_SUSPENDED);
	tq->tq_flags &= ~TASKQ_SUSPENDED;
	mutex_exit(&tq->tq_lock);

	rw_exit(&tq->tq_threadlock);
}

int
taskq_member(taskq_t *tq, kthread_t *thread)
{
	return (thread->t_taskq == tq);
}

/*
 * Creates a thread in the taskq.  We only allow one outstanding create at
 * a time.  We drop and reacquire the tq_lock in order to avoid blocking other
 * taskq activity while thread_create() or lwp_kernel_create() run.
 *
 * The first time we're called, we do some additional setup, and do not
 * return until there are enough threads to start servicing requests.
 */
static void
taskq_thread_create(taskq_t *tq)
{
	kthread_t	*t;
	const boolean_t	first = (tq->tq_nthreads == 0);

	ASSERT(MUTEX_HELD(&tq->tq_lock));
	ASSERT(tq->tq_flags & TASKQ_CHANGING);
	ASSERT(tq->tq_nthreads < tq->tq_nthreads_target);
	ASSERT(!(tq->tq_flags & TASKQ_THREAD_CREATED));


	tq->tq_flags |= TASKQ_THREAD_CREATED;
	tq->tq_active++;
	mutex_exit(&tq->tq_lock);

	/*
	 * With TASKQ_DUTY_CYCLE the new thread must have an LWP
	 * as explained in ../disp/sysdc.c (for the msacct data).
	 * Normally simple kthreads are preferred, unless the
	 * caller has asked for LWPs for other reasons.
	 */
	if ((tq->tq_flags & (TASKQ_DUTY_CYCLE | TASKQ_THREADS_LWP)) != 0) {
		/* Enforced in taskq_create_common */
		ASSERT3P(tq->tq_proc, !=, &p0);
		t = lwp_kernel_create(tq->tq_proc, taskq_thread, tq, TS_RUN,
		    tq->tq_pri);
	} else {
		t = thread_create(NULL, 0, taskq_thread, tq, 0, tq->tq_proc,
		    TS_RUN, tq->tq_pri);
	}

	if (!first) {
		mutex_enter(&tq->tq_lock);
		return;
	}

	/*
	 * We know the thread cannot go away, since tq cannot be
	 * destroyed until creation has completed.  We can therefore
	 * safely dereference t.
	 */
	if (tq->tq_flags & TASKQ_THREADS_CPU_PCT) {
		taskq_cpupct_install(tq, t->t_cpupart);
	}
	mutex_enter(&tq->tq_lock);

	/* Wait until we can service requests. */
	while (tq->tq_nthreads != tq->tq_nthreads_target &&
	    tq->tq_nthreads < TASKQ_CREATE_ACTIVE_THREADS) {
		cv_wait(&tq->tq_wait_cv, &tq->tq_lock);
	}
}

/*
 * Common "sleep taskq thread" function, which handles CPR stuff, as well
 * as giving a nice common point for debuggers to find inactive threads.
 */
static clock_t
taskq_thread_wait(taskq_t *tq, kmutex_t *mx, kcondvar_t *cv,
    callb_cpr_t *cprinfo, clock_t timeout)
{
	clock_t ret = 0;

	ASSERT(MUTEX_HELD(mx));
	if (!(tq->tq_flags & TASKQ_CPR_SAFE)) {
		CALLB_CPR_SAFE_BEGIN(cprinfo);
	}
	if (timeout < 0)
		cv_wait(cv, mx);
	else
		ret = cv_reltimedwait(cv, mx, timeout, TR_CLOCK_TICK);

	if (!(tq->tq_flags & TASKQ_CPR_SAFE)) {
		CALLB_CPR_SAFE_END(cprinfo, mx);
	}

	return (ret);
}

/*
 * Worker thread for processing task queue.
 */
static void
taskq_thread(void *arg)
{
	int thread_id;

	taskq_t *tq = arg;
	taskq_ent_t *tqe;
	callb_cpr_t cprinfo;
	hrtime_t start, end;
	boolean_t freeit;

	curthread->t_taskq = tq;	/* mark ourselves for taskq_member() */

	if (curproc != &p0 && (tq->tq_flags & TASKQ_DUTY_CYCLE)) {
		sysdc_thread_enter(curthread, tq->tq_DC,
		    (tq->tq_flags & TASKQ_DC_BATCH) ? SYSDC_THREAD_BATCH : 0);
	}

	if (tq->tq_flags & TASKQ_CPR_SAFE) {
		CALLB_CPR_INIT_SAFE(curthread, tq->tq_name);
	} else {
		CALLB_CPR_INIT(&cprinfo, &tq->tq_lock, callb_generic_cpr,
		    tq->tq_name);
	}
	mutex_enter(&tq->tq_lock);
	thread_id = ++tq->tq_nthreads;
	ASSERT(tq->tq_flags & TASKQ_THREAD_CREATED);
	ASSERT(tq->tq_flags & TASKQ_CHANGING);
	tq->tq_flags &= ~TASKQ_THREAD_CREATED;

	VERIFY3S(thread_id, <=, tq->tq_nthreads_max);

	if (tq->tq_nthreads_max == 1)
		tq->tq_thread = curthread;
	else
		tq->tq_threadlist[thread_id - 1] = curthread;

	/* Allow taskq_create_common()'s taskq_thread_create() to return. */
	if (tq->tq_nthreads == TASKQ_CREATE_ACTIVE_THREADS)
		cv_broadcast(&tq->tq_wait_cv);

	for (;;) {
		if (tq->tq_flags & TASKQ_CHANGING) {
			/* See if we're no longer needed */
			if (thread_id > tq->tq_nthreads_target) {
				/*
				 * To preserve the one-to-one mapping between
				 * thread_id and thread, we must exit from
				 * highest thread ID to least.
				 *
				 * However, if everyone is exiting, the order
				 * doesn't matter, so just exit immediately.
				 * (this is safe, since you must wait for
				 * nthreads to reach 0 after setting
				 * tq_nthreads_target to 0)
				 */
				if (thread_id == tq->tq_nthreads ||
				    tq->tq_nthreads_target == 0)
					break;

				/* Wait for higher thread_ids to exit */
				(void) taskq_thread_wait(tq, &tq->tq_lock,
				    &tq->tq_exit_cv, &cprinfo, -1);
				continue;
			}

			/*
			 * If no thread is starting taskq_thread(), we can
			 * do some bookkeeping.
			 */
			if (!(tq->tq_flags & TASKQ_THREAD_CREATED)) {
				/* Check if we've reached our target */
				if (tq->tq_nthreads == tq->tq_nthreads_target) {
					tq->tq_flags &= ~TASKQ_CHANGING;
					cv_broadcast(&tq->tq_wait_cv);
				}
				/* Check if we need to create a thread */
				if (tq->tq_nthreads < tq->tq_nthreads_target) {
					taskq_thread_create(tq);
					continue; /* tq_lock was dropped */
				}
			}
		}
		if ((tqe = tq->tq_task.tqent_next) == &tq->tq_task) {
			if (--tq->tq_active == 0)
				cv_broadcast(&tq->tq_wait_cv);
			(void) taskq_thread_wait(tq, &tq->tq_lock,
			    &tq->tq_dispatch_cv, &cprinfo, -1);
			tq->tq_active++;
			continue;
		}

		TQ_REMOVE(tqe);
		mutex_exit(&tq->tq_lock);

		/*
		 * For prealloc'd tasks, we don't free anything.  We
		 * have to check this now, because once we call the
		 * function for a prealloc'd taskq, we can't touch the
		 * tqent any longer (calling the function returns the
		 * ownershp of the tqent back to caller of
		 * taskq_dispatch.)
		 */
		if ((!(tq->tq_flags & TASKQ_DYNAMIC)) &&
		    (tqe->tqent_un.tqent_flags & TQENT_FLAG_PREALLOC)) {
			/* clear pointers to assist assertion checks */
			tqe->tqent_next = tqe->tqent_prev = NULL;
			freeit = B_FALSE;
		} else {
			freeit = B_TRUE;
		}

		rw_enter(&tq->tq_threadlock, RW_READER);
		start = gethrtime();
		DTRACE_PROBE2(taskq__exec__start, taskq_t *, tq,
		    taskq_ent_t *, tqe);
		tqe->tqent_func(tqe->tqent_arg);
		DTRACE_PROBE2(taskq__exec__end, taskq_t *, tq,
		    taskq_ent_t *, tqe);
		end = gethrtime();
		rw_exit(&tq->tq_threadlock);

		mutex_enter(&tq->tq_lock);
		tq->tq_totaltime += end - start;
		tq->tq_executed++;

		if (freeit)
			taskq_ent_free(tq, tqe);
	}

	if (tq->tq_nthreads_max == 1)
		tq->tq_thread = NULL;
	else
		tq->tq_threadlist[thread_id - 1] = NULL;

	/* We're exiting, and therefore no longer active */
	ASSERT(tq->tq_active > 0);
	tq->tq_active--;

	ASSERT(tq->tq_nthreads > 0);
	tq->tq_nthreads--;

	/* Wake up anyone waiting for us to exit */
	cv_broadcast(&tq->tq_exit_cv);
	if (tq->tq_nthreads == tq->tq_nthreads_target) {
		if (!(tq->tq_flags & TASKQ_THREAD_CREATED))
			tq->tq_flags &= ~TASKQ_CHANGING;

		cv_broadcast(&tq->tq_wait_cv);
	}

	ASSERT(!(tq->tq_flags & TASKQ_CPR_SAFE));
	CALLB_CPR_EXIT(&cprinfo);		/* drops tq->tq_lock */
	if (curthread->t_lwp != NULL) {
		mutex_enter(&curproc->p_lock);
		lwp_exit();
	} else {
		thread_exit();
	}
}

/*
 * Sentinel function to help with thread migration.
 * We never actualy run this function.
 *
 * When a thread becomes idle in one bucket and goes in search of another
 * bucket to service, it's not on any free list. For consistency with the
 * various assertions, we want the tqent_func to be non-NULL, so in such
 * cases it points to this function.
 */
static void
taskq_d_migrate(void *arg __unused)
{
	ASSERT(0);
}

/*
 * Sentinel function to help with thread redistribution (forced migration).
 * We never actualy run this function.
 *
 * When taskq_bucket_redist needs to direct a thread from one bucket
 * to another, this function is dispatched into the bucket that will
 * donate the thread, with the arg pointing to the bucket that will
 * receive the thread.  See checks for this sentinel in the functions
 * taskq_d_svc_bucket, taskq_d_thread.
 */
static void
taskq_d_redirect(void *arg __unused)
{
	ASSERT(0);
}

/*
 * Helper for taskq_d_thread() -- service a bucket
 */
static void
taskq_d_svc_bucket(taskq_ent_t *tqe,
    taskq_bucket_t *bucket, taskq_t *tq)
{
	kmutex_t	*lock = &bucket->tqbucket_lock;
	clock_t		w = 0;
	clock_t		tmo = MSEC_TO_TICK(taskq_thread_bucket_wait);

	mutex_enter(lock);

	/*
	 * After this thread is started by taskq_bucket_extend(),
	 * we may be on the free list (func == NULL) or we may have
	 * been given a task to run.  If we have a task, start at
	 * the top of the for loop, otherwise start in "the middle",
	 * where we would be after finishing some task.
	 */
	if (tqe->tqent_func == NULL) {
		/* We started on the bucket free list. */
		ASSERT(tqe->tqent_prev != NULL);
		ASSERT(bucket->tqbucket_nfree > 0);

		/*
		 * If we have a backlog, take off free list and
		 * start working on the backlog.
		 */
		if (bucket->tqbucket_nbacklog > 0) {
			TQ_REMOVE(tqe);
			bucket->tqbucket_nfree--;
			tqe->tqent_func = taskq_d_migrate;
			bucket->tqbucket_nalloc++;
			goto entry_backlog;
		}
		/*
		 * We're already on the free list, so start where
		 * we'd wait just after going onto the free list.
		 */
		goto entry_freelist;
	}

	/*
	 * After a forced migration, clear the REDIRECT flag,
	 * then continue as if voluntary migration.
	 */
	if (tqe->tqent_func == taskq_d_redirect) {
		bucket->tqbucket_flags &= ~TQBUCKET_REDIRECT;
		tqe->tqent_func = taskq_d_migrate;
	}

	/*
	 * Migration to a new bucket (forced or voluntary).
	 * We're not on any free list.  Enter middle of loop,
	 * but first adjust nalloc as if we were dispatched.
	 * Adjustment of nfree-- happened during return from
	 * this function after servicing another bucket.
	 */
	if (tqe->tqent_func == taskq_d_migrate) {
		bucket->tqbucket_nalloc++;
		goto entry_backlog;
	}

	for (;;) {
		/*
		 * If a task is scheduled (func != NULL), execute it.
		 */
		if (tqe->tqent_func != NULL) {
			hrtime_t	start;
			hrtime_t	end;

			/* Should not be on free list. */
			ASSERT(tqe->tqent_prev == NULL);
			ASSERT(bucket->tqbucket_nalloc > 0);

			/*
			 * Check for redirect (forced migration)
			 * Skip going on free list. Just return.
			 */
			if (tqe->tqent_func == taskq_d_redirect) {
				bucket->tqbucket_nalloc--;
				goto unlock_out;
			}

			/*
			 * Run the job.
			 */
			mutex_exit(lock);
			start = gethrtime();
			DTRACE_PROBE3(taskq__d__exec__start, taskq_t *, tq,
			    taskq_bucket_t *, bucket, taskq_ent_t *, tqe);
			tqe->tqent_func(tqe->tqent_arg);
			DTRACE_PROBE3(taskq__d__exec__end, taskq_t *, tq,
			    taskq_bucket_t *, bucket, taskq_ent_t *, tqe);
			end = gethrtime();
			mutex_enter(lock);
			bucket->tqbucket_totaltime += end - start;
		}

	entry_backlog:
		/*
		 * If there's a backlog, consume the head of the
		 * backlog like taskq_bucket_dispatch, then let the
		 * normal execution code path run it.
		 */
		if (bucket->tqbucket_nbacklog > 0) {
			taskq_ent_t	*bltqe;

			/*
			 * Should not be on free list.
			 * May enter here from the top.
			 */
			ASSERT(tqe->tqent_prev == NULL);
			ASSERT(bucket->tqbucket_nalloc > 0);

			ASSERT(!IS_EMPTY(bucket->tqbucket_backlog));
			bltqe = bucket->tqbucket_backlog.tqent_next;
			TQ_REMOVE(bltqe);
			bucket->tqbucket_nbacklog--;

			DTRACE_PROBE2(taskq__x__backlog,
			    taskq_bucket_t *, bucket,
			    taskq_ent_t *, bltqe);

			/*
			 * Copy the backlog entry to the tqe
			 * and free the backlog entry.
			 */
			tqe->tqent_func = bltqe->tqent_func;
			tqe->tqent_arg  = bltqe->tqent_arg;
			kmem_cache_free(taskq_ent_cache, bltqe);

			/* Run as usual. */
			continue;
		}

		DTRACE_PROBE2(taskq__d__wait1,
		    taskq_t *, tq, taskq_ent_t *, tqe);

		/*
		 * We've run out of work in this bucket.
		 * Put our TQE on the free list and wait.
		 */
		ASSERT(tqe->tqent_prev == NULL);
		ASSERT(bucket->tqbucket_nalloc > 0);
		bucket->tqbucket_nalloc--;
		tqe->tqent_func = NULL;
		TQ_APPEND(bucket->tqbucket_freelist, tqe);
		bucket->tqbucket_nfree++;

		/*
		 * taskq_wait() waits for nalloc to drop to zero on
		 * tqbucket_cv.
		 */
		cv_signal(&bucket->tqbucket_cv);

	entry_freelist:
		/*
		 * Note: may enter here from the top.
		 * We're on the free list.  Wait for work.
		 */
		ASSERT(tqe->tqent_func == NULL);
		ASSERT(tqe->tqent_prev != NULL);
		ASSERT(MUTEX_HELD(lock));

		/*
		 * If we're closing, finish.
		 */
		if ((bucket->tqbucket_flags & TQBUCKET_CLOSE) != 0)
			break;

		/*
		 * Go to sleep waiting for work to arrive.
		 * Sleep only briefly here on the bucket.
		 * If no work lands in the bucket, return and
		 * the caller will put this TQE on the common
		 * list of idle threads and do the long wait.
		 */
		w = cv_reltimedwait(&tqe->tqent_cv, lock, tmo, TR_CLOCK_TICK);

		/*
		 * At this point we may be in two different states:
		 *
		 * (1) tqent_func is set which means that a new task is
		 *	dispatched and we need to execute it.
		 *	The dispatch took us off the free list.
		 *
		 * (2) Thread is sleeping for too long, or closing.
		 *	We're done servicing this bucket.
		 *
		 * Some consistency checks:
		 * func == NULL implies on free list
		 * func != NULL implies not on free list
		 */
		if (tqe->tqent_func == NULL) {
			/* Should be on the free list. */
			ASSERT(tqe->tqent_prev != NULL);
			ASSERT(bucket->tqbucket_nfree > 0);
			if (w < 0) {
				/* slept too long */
				break;
			}

			/*
			 * We may have been signaled if we finished a job
			 * and got on the free list just before a call to
			 * taskq_backlog_dispatch took the lock.  In that
			 * case resume working on the backlog.
			 */
			if (bucket->tqbucket_nbacklog > 0) {
				TQ_REMOVE(tqe);
				bucket->tqbucket_nfree--;
				tqe->tqent_func = taskq_d_migrate;
				bucket->tqbucket_nalloc++;
				goto entry_backlog;
			}

			/*
			 * Woken for some other reason.
			 * Still on the free list, lock held.
			 * Just wait again.
			 */
			goto entry_freelist;
		}

		/*
		 * taskq_bucket_dispatch has set tqent_func
		 * and taken us off the free list.
		 */
		ASSERT(tqe->tqent_func != NULL);
		ASSERT(tqe->tqent_prev == NULL);
		/* Back to the top (continue) */
	}

	/*
	 * Remove the entry from the free list.
	 * Will migrate to another bucket.
	 * See taskq_d_migrate above.
	 *
	 * Note: nalloc++ happens after we return to taskq_d_thread
	 * and enter the mutex for the next bucket we serve.
	 */
	TQ_REMOVE(tqe);
	tqe->tqent_func = taskq_d_migrate;
	ASSERT(bucket->tqbucket_nfree > 0);
	bucket->tqbucket_nfree--;
	cv_signal(&bucket->tqbucket_cv);

unlock_out:
	mutex_exit(lock);
}

/*
 * Worker thread for dynamic taskq's
 */
static void
taskq_d_thread(taskq_ent_t *tqe)
{
	callb_cpr_t	cprinfo;
	taskq_bucket_t	*b;
	taskq_bucket_t	*bucket = tqe->tqent_un.tqent_bucket;
	taskq_t		*tq = bucket->tqbucket_taskq;
	taskq_bucket_t	*idle_bucket = &tq->tq_buckets[tq->tq_nbuckets];
	kmutex_t	*idle_lock = &idle_bucket->tqbucket_lock;
	clock_t		tmo, w = 0;

	CALLB_CPR_INIT(&cprinfo, idle_lock, callb_generic_cpr, tq->tq_name);

	/*
	 * Note that taskq_idlebucket_dispatch can change
	 * tqent_bucket when we're on the free list.  Hold
	 * idle_lock to synchronize with those changes.
	 */
	mutex_enter(idle_lock);
	bucket = tqe->tqent_un.tqent_bucket;

	/*
	 * If we were started for TASKQ_PREPOPULATE,
	 * we'll be on the idle bucket free list.
	 * In that case start in the middle.
	 */
	if (bucket == idle_bucket) {
		ASSERT(tqe->tqent_func == NULL);
		ASSERT(tqe->tqent_prev != NULL);
		goto entry_freelist;
	}

	/* Not on the idle_bucket free list. */
	mutex_exit(idle_lock);

	for (;;) {
	continue_2:

		/*
		 * Service the bucket pointed to by the TQE.
		 * We are NOT on the idle_bucket free list.
		 * We may or may not be on the bucket free list.
		 */
		ASSERT(MUTEX_NOT_HELD(idle_lock));
		bucket = tqe->tqent_un.tqent_bucket;
		VERIFY3P(bucket, >=, tq->tq_buckets);
		VERIFY3P(bucket, <, idle_bucket);

		/* Enters/exits bucket->tqbucket_lock */
		taskq_d_svc_bucket(tqe, bucket, tq);

		/*
		 * Finished servicing a bucket where we became idle.
		 * Not on any free list.  Migrate to another bucket.
		 * With "redirect" (forced migration) we move to the
		 * bucket indicated by the arg.
		 */
		ASSERT(tqe->tqent_prev == NULL);
		if (tqe->tqent_func == taskq_d_redirect) {
			/*
			 * Migrate to this bucket.
			 * See: taskq_d_redirect()
			 */
			tqe->tqent_un.tqent_bucket = tqe->tqent_arg;
			DTRACE_PROBE2(taskq__d__redirect,
			    taskq_t *, tq, taskq_ent_t *, tqe);
			continue;
		}

		/*
		 * Look for buckets with backlog and if found, migrate
		 * to that bucket.  Search starting at the next bucket
		 * after the current one so the search starting points
		 * will be distributed.
		 *
		 * Unlocked access is OK here.  A bucket may be missed
		 * due to a stale (cached) nbacklog value, but another
		 * idle thread will see the updated value soon.  If we
		 * visit a bucket needlessly, the visit will be short.
		 * There's a membar_producer after tqbucket_nbacklog is
		 * updated, which should ensure visibility of updates
		 * soon enough so buckets needing attention will get a
		 * visit by threads passing through here.
		 */
	check_backlog:
		ASSERT(tqe->tqent_func == taskq_d_migrate);
		VERIFY3P(bucket, >=, tq->tq_buckets);
		VERIFY3P(bucket, <, idle_bucket);
		membar_consumer();
		b = bucket;
		do {
			/* Next bucket */
			if (++b == idle_bucket)
				b = tq->tq_buckets;

			if (b->tqbucket_nbacklog > 0) {
				/*
				 * Migrate to this bucket.
				 * See: taskq_d_migrate()
				 */
				tqe->tqent_un.tqent_bucket = b;
				DTRACE_PROBE2(taskq__d__migration,
				    taskq_t *, tq, taskq_ent_t *, tqe);
				goto continue_2;
			}
		} while (b != bucket);

		DTRACE_PROBE2(taskq__d__wait2,
		    taskq_t *, tq, taskq_ent_t *, tqe);

		/*
		 * Migrate to the idle bucket, put this TQE on
		 * the free list for that bucket, then wait.
		 */
		ASSERT(tqe->tqent_prev == NULL);
		tqe->tqent_un.tqent_bucket = idle_bucket;
		mutex_enter(idle_lock);
		tqe->tqent_func = NULL;
		TQ_APPEND(idle_bucket->tqbucket_freelist, tqe);
		idle_bucket->tqbucket_nfree++;

	entry_freelist:
		/*
		 * Note: may enter here from the top.
		 * We're on the free list.  Wait for work.
		 */
		ASSERT(tqe->tqent_func == NULL);
		ASSERT(tqe->tqent_prev != NULL);
		ASSERT(idle_bucket->tqbucket_nfree > 0);
		ASSERT(MUTEX_HELD(idle_lock));
		ASSERT3P(tqe->tqent_un.tqent_bucket, ==, idle_bucket);

		/*
		 * If we're closing, finish.
		 */
		if ((idle_bucket->tqbucket_flags & TQBUCKET_CLOSE) != 0)
			break;

		/*
		 * Go to sleep waiting for work to arrive.
		 * If a thread is sleeping too long, it dies.
		 * If this is the last thread, no timeout.
		 */
		if (idle_bucket->tqbucket_nfree == 1) {
			tmo = -1;
		} else {
			tmo = SEC_TO_TICK(taskq_thread_timeout);
		}
		w = taskq_thread_wait(tq, idle_lock,
		    &tqe->tqent_cv, &cprinfo, tmo);

		/*
		 * At this point we may be in two different states:
		 *
		 * (1) tqent_func is set which means that a new task is
		 *	dispatched and we need to execute it.
		 *	The dispatch took us off the free list.
		 *	Migrate to the new bucket.
		 *
		 * (2) Thread is sleeping for too long -- return
		 *
		 * Some consistency checks:
		 * func == NULL implies on free list
		 * func != NULL implies not on free list
		 */
		if (tqe->tqent_func == NULL) {
			/* Should be on the free list. */
			ASSERT(tqe->tqent_prev != NULL);
			if (w < 0 && idle_bucket->tqbucket_nfree > 1) {
				/*
				 * taskq_thread_wait timed out.
				 * If not last thread, exit.
				 */
				break;
			}

			/*
			 * Woken for some other reason, one of:
			 *	Last thread - stick around longer
			 *	Destroying, out via CLOSE above
			 *	taskq_bucket_redist signaled
			 *
			 * Still on the free list, lock held. Continue
			 * back at the re-check for backlog work,
			 * which means coming off the free list.
			 *
			 * Note that tqent_bucket is the idle bucket
			 * at this point, which is not valid above,
			 * so pretend we just finished servicing the
			 * first bucket.  This happens rarely.
			 */
			bucket = tq->tq_buckets;
			TQ_REMOVE(tqe);
			idle_bucket->tqbucket_nfree--;
			tqe->tqent_func = taskq_d_migrate;
			tqe->tqent_un.tqent_bucket = bucket;
			mutex_exit(idle_lock);
			goto check_backlog;
		}

		/*
		 * taskq_idlebucket_dispatch will have moved this
		 * taskq_ent_t from the idle bucket (idleb) to a
		 * new bucket (newb).  In detail, it has:
		 *	Removed this TQE from idlb->tqbucket_freelist
		 *	deccremented idleb->tqbucket_nfree
		 *	Set tqent_bucket = new_bucket
		 *	Set tqent_func, tqent_argarg
		 *	incremented newb->tqbucket_nalloc
		 */
		ASSERT(tqe->tqent_func != NULL);
		ASSERT(tqe->tqent_prev == NULL);
		ASSERT(tqe->tqent_un.tqent_bucket != idle_bucket);
		DTRACE_PROBE2(taskq__d__idledisp,
		    taskq_t *, tq, taskq_ent_t *, tqe);
		mutex_exit(idle_lock);
		/* Back to the top (continue) */
	}
	ASSERT(MUTEX_HELD(idle_lock));
	ASSERT(tqe->tqent_prev != NULL);

	/*
	 * Thread creation/destruction happens rarely,
	 * so grabbing the lock is not a big performance issue.
	 * The bucket lock is dropped by CALLB_CPR_EXIT().
	 */

	/* Remove the entry from the free list. */
	TQ_REMOVE(tqe);
	ASSERT(idle_bucket->tqbucket_nfree > 0);
	idle_bucket->tqbucket_nfree--;

	/* Note: Creates and deaths are on the idle bucket. */
	TQ_STAT(idle_bucket, tqs_tdeaths);
	cv_signal(&idle_bucket->tqbucket_cv);

	/*
	 * When destroying, wake the next thread, if any.
	 * See thundering herd comment in taskq_destroy.
	 */
	if ((idle_bucket->tqbucket_flags & TQBUCKET_CLOSE) != 0 &&
	    (idle_bucket->tqbucket_nfree > 0)) {
		taskq_ent_t *ntqe;
		ASSERT(!IS_EMPTY(idle_bucket->tqbucket_freelist));
		ntqe = idle_bucket->tqbucket_freelist.tqent_next;
		cv_signal(&ntqe->tqent_cv);
	}

	tqe->tqent_thread = NULL;
	mutex_enter(&tq->tq_lock);
	tq->tq_dnthreads--;
	cv_broadcast(&tq->tq_exit_cv);
	mutex_exit(&tq->tq_lock);

	CALLB_CPR_EXIT(&cprinfo);	/* mutex_exit(idle_lock) */

	kmem_cache_free(taskq_ent_cache, tqe);

	if (curthread->t_lwp != NULL) {
		mutex_enter(&curproc->p_lock);
		lwp_exit(); /* noreturn. drops p_lock */
	} else {
		thread_exit();
	}
}


/*
 * Taskq creation. May sleep for memory.
 * Always use automatically generated instances to avoid kstat name space
 * collisions.
 */

taskq_t *
taskq_create(const char *name, int nthreads, pri_t pri, int minalloc,
    int maxalloc, uint_t flags)
{
	ASSERT((flags & ~TASKQ_INTERFACE_FLAGS) == 0);

	return (taskq_create_common(name, 0, nthreads, pri, minalloc,
	    maxalloc, &p0, 0, flags | TASKQ_NOINSTANCE));
}

/*
 * Create an instance of task queue. It is legal to create task queues with the
 * same name and different instances.
 *
 * taskq_create_instance is used by ddi_taskq_create() where it gets the
 * instance from ddi_get_instance(). In some cases the instance is not
 * initialized and is set to -1. This case is handled as if no instance was
 * passed at all.
 */
taskq_t *
taskq_create_instance(const char *name, int instance, int nthreads, pri_t pri,
    int minalloc, int maxalloc, uint_t flags)
{
	ASSERT((flags & ~TASKQ_INTERFACE_FLAGS) == 0);
	ASSERT((instance >= 0) || (instance == -1));

	if (instance < 0) {
		flags |= TASKQ_NOINSTANCE;
	}

	return (taskq_create_common(name, instance, nthreads,
	    pri, minalloc, maxalloc, &p0, 0, flags));
}

taskq_t *
taskq_create_proc(const char *name, int nthreads, pri_t pri, int minalloc,
    int maxalloc, proc_t *proc, uint_t flags)
{
	ASSERT((flags & ~TASKQ_INTERFACE_FLAGS) == 0);
	ASSERT(proc->p_flag & SSYS);

	return (taskq_create_common(name, 0, nthreads, pri, minalloc,
	    maxalloc, proc, 0, flags | TASKQ_NOINSTANCE));
}

taskq_t *
taskq_create_sysdc(const char *name, int nthreads, int minalloc,
    int maxalloc, proc_t *proc, uint_t dc, uint_t flags)
{
	ASSERT((flags & ~TASKQ_INTERFACE_FLAGS) == 0);
	ASSERT(proc->p_flag & SSYS);

	return (taskq_create_common(name, 0, nthreads, minclsyspri, minalloc,
	    maxalloc, proc, dc, flags | TASKQ_NOINSTANCE | TASKQ_DUTY_CYCLE));
}

static taskq_t *
taskq_create_common(const char *name, int instance, int nthreads, pri_t pri,
    int minalloc, int maxalloc, proc_t *proc, uint_t dc, uint_t flags)
{
	taskq_t *tq = kmem_cache_alloc(taskq_cache, KM_SLEEP);
	uint_t ncpus = ((boot_max_ncpus == -1) ? max_ncpus : boot_max_ncpus);
	uint_t bsize;	/* # of buckets - always power of 2 */
	int max_nthreads;

	/*
	 * TASKQ_DYNAMIC, TASKQ_CPR_SAFE and TASKQ_THREADS_CPU_PCT are all
	 * mutually incompatible.
	 */
	IMPLY((flags & TASKQ_DYNAMIC), !(flags & TASKQ_CPR_SAFE));
	IMPLY((flags & TASKQ_DYNAMIC), !(flags & TASKQ_THREADS_CPU_PCT));
	IMPLY((flags & TASKQ_CPR_SAFE), !(flags & TASKQ_THREADS_CPU_PCT));

	/* Cannot have DYNAMIC with DUTY_CYCLE */
	IMPLY((flags & TASKQ_DYNAMIC), !(flags & TASKQ_DUTY_CYCLE));

	/* Cannot have DUTY_CYCLE with a p0 kernel process */
	IMPLY((flags & TASKQ_DUTY_CYCLE), proc != &p0);

	/* Cannot have THREADS_LWP with a p0 kernel process */
	IMPLY((flags & TASKQ_THREADS_LWP), proc != &p0);

	/* Cannot have DC_BATCH without DUTY_CYCLE */
	ASSERT((flags & (TASKQ_DUTY_CYCLE|TASKQ_DC_BATCH)) != TASKQ_DC_BATCH);

	ASSERT(proc != NULL);

	bsize = 1 << (highbit(ncpus) - 1);
	ASSERT(bsize >= 1);
	bsize = MAX(bsize, taskq_minbuckets);
	bsize = MIN(bsize, taskq_maxbuckets);

	if (flags & TASKQ_DYNAMIC) {
		ASSERT3S(nthreads, >=, 1);
		/* Need at least (bsize + 1) threads */
		tq->tq_maxsize = MAX(nthreads, bsize + 1);
		/* See taskq_bucket_redist(). */
		tq->tq_atpb = tq->tq_maxsize / bsize;
		ASSERT(tq->tq_atpb != 0);

		/* For dynamic task queues use just one backing thread */
		nthreads = max_nthreads = 1;

	} else if (flags & TASKQ_THREADS_CPU_PCT) {
		uint_t pct;
		ASSERT3S(nthreads, >=, 0);
		pct = nthreads;

		if (pct > taskq_cpupct_max_percent)
			pct = taskq_cpupct_max_percent;

		/*
		 * If you're using THREADS_CPU_PCT, the process for the
		 * taskq threads must be curproc.  This allows any pset
		 * binding to be inherited correctly.  If proc is &p0,
		 * we won't be creating LWPs, so new threads will be assigned
		 * to the default processor set.
		 */
		ASSERT(curproc == proc || proc == &p0);
		tq->tq_threads_ncpus_pct = pct;
		nthreads = 1;		/* corrected in taskq_thread_create() */
		max_nthreads = TASKQ_THREADS_PCT(max_ncpus, pct);

	} else {
		ASSERT3S(nthreads, >=, 1);
		max_nthreads = nthreads;
	}

	if (max_nthreads < taskq_minimum_nthreads_max)
		max_nthreads = taskq_minimum_nthreads_max;

	/*
	 * Make sure the name is 0-terminated, and conforms to the rules for
	 * C indentifiers
	 */
	(void) strncpy(tq->tq_name, name, TASKQ_NAMELEN + 1);
	strident_canon(tq->tq_name, TASKQ_NAMELEN + 1);

	tq->tq_flags = flags | TASKQ_CHANGING;
	tq->tq_active = 0;
	tq->tq_instance = instance;
	tq->tq_nthreads_target = nthreads;
	tq->tq_nthreads_max = max_nthreads;
	tq->tq_minalloc = minalloc;
	tq->tq_maxalloc = maxalloc;
	tq->tq_nbuckets = bsize;
	tq->tq_proc = proc;
	tq->tq_pri = pri;
	tq->tq_DC = dc;
	list_link_init(&tq->tq_cpupct_link);

	if (max_nthreads > 1)
		tq->tq_threadlist = kmem_alloc(
		    sizeof (kthread_t *) * max_nthreads, KM_SLEEP);

	mutex_enter(&tq->tq_lock);
	if (flags & TASKQ_PREPOPULATE) {
		while (minalloc-- > 0)
			taskq_ent_free(tq, taskq_ent_alloc(tq, TQ_SLEEP));
	}

	/*
	 * Before we start creating threads for this taskq, take a
	 * zone hold so the zone can't go away before taskq_destroy
	 * makes sure all the taskq threads are gone.  This hold is
	 * similar in purpose to those taken by zthread_create().
	 */
	zone_hold(tq->tq_proc->p_zone);

	/*
	 * Create the first thread, which will create any other threads
	 * necessary.  taskq_thread_create will not return until we have
	 * enough threads to be able to process requests.
	 */
	taskq_thread_create(tq);
	mutex_exit(&tq->tq_lock);

	/*
	 * For dynamic taskq, create the array of buckets, PLUS ONE
	 * for the bucket used as the "idle bucket".
	 */
	if (flags & TASKQ_DYNAMIC) {
		taskq_bucket_t *bucket = kmem_zalloc(sizeof (taskq_bucket_t) *
		    (bsize + 1), KM_SLEEP);
		taskq_bucket_t *idle_bucket = &bucket[bsize];
		int b_id;

		tq->tq_buckets = bucket;

		/* Initialize each bucket */
		for (b_id = 0; b_id < (bsize + 1); b_id++, bucket++) {
			mutex_init(&bucket->tqbucket_lock, NULL, MUTEX_DEFAULT,
			    NULL);
			cv_init(&bucket->tqbucket_cv, NULL, CV_DEFAULT, NULL);
			bucket->tqbucket_taskq = tq;
			TQ_LIST_INIT(bucket->tqbucket_freelist);
			TQ_LIST_INIT(bucket->tqbucket_backlog);
		}
		/*
		 * Always create at least one idle bucket thread.
		 * That can't fail because we're at nthreads=0.
		 * If pre-populating, create more (nbuckets) threads.
		 * That can fail, in which case we'll just try later.
		 */
		(void) taskq_bucket_extend(idle_bucket);
		if (flags & TASKQ_PREPOPULATE) {
			int i;
			for (i = 1; i < bsize; i++) {
				(void) taskq_bucket_extend(idle_bucket);
			}
		}
	}

	/*
	 * Install kstats.
	 * We have two cases:
	 *   1) Instance is provided to taskq_create_instance(). In this case it
	 *	should be >= 0 and we use it.
	 *
	 *   2) Instance is not provided and is automatically generated
	 */
	if (flags & TASKQ_NOINSTANCE) {
		instance = tq->tq_instance =
		    (int)(uintptr_t)vmem_alloc(taskq_id_arena, 1, VM_SLEEP);
	}

	if (flags & TASKQ_DYNAMIC) {
		if ((tq->tq_kstat = kstat_create("unix", instance,
		    tq->tq_name, "taskq_d", KSTAT_TYPE_NAMED,
		    sizeof (taskq_d_kstat) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL)) != NULL) {
			tq->tq_kstat->ks_lock = &taskq_d_kstat_lock;
			tq->tq_kstat->ks_data = &taskq_d_kstat;
			tq->tq_kstat->ks_update = taskq_d_kstat_update;
			tq->tq_kstat->ks_private = tq;
			kstat_install(tq->tq_kstat);
		}
	} else {
		if ((tq->tq_kstat = kstat_create("unix", instance, tq->tq_name,
		    "taskq", KSTAT_TYPE_NAMED,
		    sizeof (taskq_kstat) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL)) != NULL) {
			tq->tq_kstat->ks_lock = &taskq_kstat_lock;
			tq->tq_kstat->ks_data = &taskq_kstat;
			tq->tq_kstat->ks_update = taskq_kstat_update;
			tq->tq_kstat->ks_private = tq;
			kstat_install(tq->tq_kstat);
		}
	}

	return (tq);
}

/*
 * taskq_destroy().
 *
 * Assumes: by the time taskq_destroy is called no one will use this task queue
 * in any way and no one will try to dispatch entries in it.
 */
void
taskq_destroy(taskq_t *tq)
{

	ASSERT(! (tq->tq_flags & TASKQ_CPR_SAFE));

	/*
	 * Destroy kstats.
	 */
	if (tq->tq_kstat != NULL) {
		kstat_delete(tq->tq_kstat);
		tq->tq_kstat = NULL;
	}

	/*
	 * Destroy instance if needed.
	 */
	if (tq->tq_flags & TASKQ_NOINSTANCE) {
		vmem_free(taskq_id_arena, (void *)(uintptr_t)(tq->tq_instance),
		    1);
		tq->tq_instance = 0;
	}

	/*
	 * Unregister from the cpupct list.
	 */
	if (tq->tq_flags & TASKQ_THREADS_CPU_PCT) {
		taskq_cpupct_remove(tq);
	}

	/*
	 * Wait for any pending entries to complete.
	 */
	taskq_wait(tq);

	mutex_enter(&tq->tq_lock);
	ASSERT((tq->tq_task.tqent_next == &tq->tq_task) &&
	    (tq->tq_active == 0));

	/* notify all the threads that they need to exit */
	tq->tq_nthreads_target = 0;

	tq->tq_flags |= TASKQ_CHANGING;
	cv_broadcast(&tq->tq_dispatch_cv);
	cv_broadcast(&tq->tq_exit_cv);

	while (tq->tq_nthreads != 0)
		cv_wait(&tq->tq_wait_cv, &tq->tq_lock);

	if (tq->tq_nthreads_max != 1)
		kmem_free(tq->tq_threadlist, sizeof (kthread_t *) *
		    tq->tq_nthreads_max);

	tq->tq_minalloc = 0;
	while (tq->tq_nalloc != 0)
		taskq_ent_free(tq, taskq_ent_alloc(tq, TQ_SLEEP));

	mutex_exit(&tq->tq_lock);

	/*
	 * For dynamic taskq:
	 * Mark each bucket as closing and wakeup all sleeping threads.
	 * Two passes: 1st mark & wake all; 2nd wait for thread exits.
	 * Include the idle bucket here.
	 */
	if (tq->tq_buckets != NULL) {
		taskq_bucket_t *b;
		uint_t bid = 0;

		ASSERT((tq->tq_flags & TASKQ_DYNAMIC) != 0);

		for (bid = 0, b = tq->tq_buckets;
		    bid <= tq->tq_nbuckets;
		    b++, bid++) {

			taskq_ent_t *tqe;

			mutex_enter(&b->tqbucket_lock);

			/* We called taskq_wait() above. */
			ASSERT(b->tqbucket_nalloc == 0);

			/*
			 * Wakeup all sleeping threads.
			 *
			 * The idle bucket may have many threads.
			 * Avoid a "thundering herd" of calls into
			 * taskq_thread_wait() / cv_reltimedwait()
			 * thrashing mutexes in callout teardown,
			 * and just wake the first idle thread,
			 * letting it wake the next.
			 * See cv_signal near end of taskq_d_thread
			 * In other buckets, wake all threads.
			 */
			b->tqbucket_flags |= TQBUCKET_CLOSE;
			for (tqe = b->tqbucket_freelist.tqent_next;
			    tqe != &b->tqbucket_freelist;
			    tqe = tqe->tqent_next) {

				cv_signal(&tqe->tqent_cv);

				if (bid == tq->tq_nbuckets) {
					/* idle bucket; just wake one. */
					break;
				}
			}
			mutex_exit(&b->tqbucket_lock);
		}

		for (bid = 0, b = tq->tq_buckets;
		    bid <= tq->tq_nbuckets;
		    b++, bid++) {
			/*
			 * Wait for tqbucket_freelist threads to exit.
			 */
			mutex_enter(&b->tqbucket_lock);
			while (b->tqbucket_nfree > 0)
				cv_wait(&b->tqbucket_cv, &b->tqbucket_lock);
			mutex_exit(&b->tqbucket_lock);
		}

		/*
		 * Threads that are migrating between buckets could be
		 * missed by the waits on tqbucket_nfree, so also wait
		 * for the total thread count to go to zero.
		 */
		mutex_enter(&tq->tq_lock);
		while (tq->tq_dnthreads > 0) {
			cv_wait(&tq->tq_exit_cv, &tq->tq_lock);
		}
		mutex_exit(&tq->tq_lock);

		/*
		 * Destroy all buckets
		 */
		for (bid = 0, b = tq->tq_buckets;
		    bid <= tq->tq_nbuckets;
		    b++, bid++) {
			mutex_destroy(&b->tqbucket_lock);
			cv_destroy(&b->tqbucket_cv);
		}

		kmem_free(tq->tq_buckets,
		    sizeof (taskq_bucket_t) * (tq->tq_nbuckets + 1));

		/* Cleanup fields before returning tq to the cache */
		tq->tq_buckets = NULL;
		tq->tq_dnthreads = 0;
	} else {
		ASSERT((tq->tq_flags & TASKQ_DYNAMIC) == 0);
	}

	/*
	 * Now that all the taskq threads are gone, we can
	 * drop the zone hold taken in taskq_create_common
	 */
	zone_rele(tq->tq_proc->p_zone);

	tq->tq_threads_ncpus_pct = 0;
	tq->tq_totaltime = 0;
	tq->tq_tasks = 0;
	tq->tq_maxtasks = 0;
	tq->tq_executed = 0;
	kmem_cache_free(taskq_cache, tq);
}

/*
 * This is called asynchronously after taskq_dispatch has failed to
 * find a free thread.  Try to create a thread (taskq_bucket_extend)
 * and if that fails, make sure the bucket has at least one thread,
 * redirecting a thread from another bucket if necessary.
 */
static void
taskq_bucket_overflow(void *arg)
{
	taskq_bucket_t *b = arg;

	if (taskq_bucket_extend(b) == NULL) {
		taskq_bucket_redist(b);
	}
}

/*
 * Extend a bucket with a new entry on the free list and attach a worker
 * thread to it.  This is called from a context where sleep is allowed.
 * This function may quietly fail. Callers deal with the possibility
 * that this might not have created a thread for some reason, eg.
 * lack of resources or limits on the number of threads.
 *
 * Argument: pointer to the bucket.
 * Return: pointer to new taskq_ent_t if we created a thread, else NULL
 */
static taskq_ent_t *
taskq_bucket_extend(taskq_bucket_t *b)
{
	taskq_ent_t *tqe;
	taskq_t *tq = b->tqbucket_taskq;
	taskq_bucket_t *idleb = &tq->tq_buckets[tq->tq_nbuckets];
	kthread_t *t;
	int nthreads;

	/* How many threads currently in this bucket? */
	mutex_enter(&b->tqbucket_lock);
	nthreads = b->tqbucket_nalloc + b->tqbucket_nfree;
	mutex_exit(&b->tqbucket_lock);

	mutex_enter(&tq->tq_lock);

	/*
	 * When there are no threads in this bucket, this call should
	 * "try harder", so continue even if short on memory.
	 */
	if (! ENOUGH_MEMORY() && (nthreads > 0)) {
		tq->tq_nomem++;
		mutex_exit(&tq->tq_lock);
		return (NULL);
	}

	/*
	 * Observe global taskq limits on the number of threads.
	 */
	if ((tq->tq_dnthreads + 1) > tq->tq_maxsize) {
		mutex_exit(&tq->tq_lock);
		return (NULL);
	}
	tq->tq_dnthreads++;
	mutex_exit(&tq->tq_lock);

	tqe = kmem_cache_alloc(taskq_ent_cache, KM_SLEEP);

	ASSERT(tqe->tqent_thread == NULL);

	tqe->tqent_un.tqent_bucket = b;

	/*
	 * Create a thread in a TS_STOPPED state first. If it is successfully
	 * created, place the entry on the free list and start the thread.
	 */
	if ((tq->tq_flags & TASKQ_THREADS_LWP) != 0) {
		/* Enforced in taskq_create_common */
		ASSERT3P(tq->tq_proc, !=, &p0);
		t = lwp_kernel_create(tq->tq_proc, taskq_d_thread,
		    tqe, TS_STOPPED, tq->tq_pri);
	} else {
		t = thread_create(NULL, 0, taskq_d_thread, tqe,
		    0, tq->tq_proc, TS_STOPPED, tq->tq_pri);
	}
	tqe->tqent_thread = t;
	t->t_taskq = tq;	/* mark thread as a taskq_member() */

	/*
	 * Once the entry is ready, link it to the the bucket free list.
	 */
	mutex_enter(&b->tqbucket_lock);
	tqe->tqent_func = NULL;
	TQ_APPEND(b->tqbucket_freelist, tqe);
	b->tqbucket_nfree++;
	mutex_exit(&b->tqbucket_lock);

	/*
	 * Account for creates in the idle bucket, because
	 * the deaths will be accounted there.
	 */
	mutex_enter(&idleb->tqbucket_lock);
	TQ_STAT(idleb, tqs_tcreates);
#if TASKQ_STATISTIC
	nthreads = idleb->tqbucket_stat.tqs_tcreates -
	    idleb->tqbucket_stat.tqs_tdeaths;
	idleb->tqbucket_stat.tqs_maxthreads = MAX(nthreads,
	    idleb->tqbucket_stat.tqs_maxthreads);
#endif
	mutex_exit(&idleb->tqbucket_lock);

	/*
	 * Start the stopped thread.
	 */
	if (t->t_lwp != NULL) {
		proc_t *p = tq->tq_proc;
		mutex_enter(&p->p_lock);
		t->t_proc_flag &= ~TP_HOLDLWP;
		lwp_create_done(t);	/* Sets TS_ALLSTART etc. */
		mutex_exit(&p->p_lock);
	} else {
		thread_lock(t);
		t->t_schedflag |= TS_ALLSTART;
		setrun_locked(t);
		thread_unlock(t);
	}

	return (tqe);
}

/*
 * This is called after taskq_dispatch failed to find a free thread and
 * also failed to create a new thread.  This usually means the taskq has
 * as many threads are we're allowed to create, but can also happen when
 * dispatch has TQ_NOQUEUE, or (rarely) we created a thread but lost the
 * new thread to another racing dispatch call.  If this bucket has a
 * backlog and no threads, then redistribute threads by moving one
 * from another bucket (the donor bucket) into this one.  A thread in
 * the donor bucket is redirected by dispatching the special function
 * taskq_d_redirect in the donor bucket. As soon as some thread in the
 * donor bucket completes, it will find taskq_d_redirect in the backlog
 * and move to the recipient bucket (the bucket arg here).
 */
static void
taskq_bucket_redist(taskq_bucket_t *bucket)
{
	taskq_t *tq = bucket->tqbucket_taskq;
	taskq_bucket_t *idle_bucket = &tq->tq_buckets[tq->tq_nbuckets];
	taskq_bucket_t *db;	/* donor bucket candidate */
	taskq_ent_t *tqe = NULL;
	uint_t nthreads;

	VERIFY3P(bucket, >=, tq->tq_buckets);
	VERIFY3P(bucket, <, idle_bucket);

	/*
	 * This makes no sense with a single bucket.
	 * Someone patched taskq_minbuckets?
	 */
	if (tq->tq_nbuckets == 1)
		goto out;

	/*
	 * Only redirect when there's a backlog and no threads,
	 * and we have not already redirected a thread.
	 */
	mutex_enter(&bucket->tqbucket_lock);
	nthreads = bucket->tqbucket_nalloc + bucket->tqbucket_nfree;
	if (nthreads > 0 || bucket->tqbucket_nbacklog == 0 ||
	    (bucket->tqbucket_flags & TQBUCKET_REDIRECT) != 0) {
		mutex_exit(&bucket->tqbucket_lock);
		goto out;
	}
	/* Clear this later if we fail to redirect a thread. */
	bucket->tqbucket_flags |= TQBUCKET_REDIRECT;
	mutex_exit(&bucket->tqbucket_lock);

	/*
	 * Need a tqe for taskq_backlog_enqueue
	 */
	tqe = kmem_cache_alloc(taskq_ent_cache, KM_SLEEP);
	ASSERT(tqe->tqent_thread == NULL);
	tqe->tqent_func = taskq_d_redirect;
	tqe->tqent_arg = bucket; /* redirected to */

	/*
	 * Find a "donor bucket" (db) that can afford to lose a thread.
	 * Search starting at the next bucket after the passed in one.
	 * There should be some buckets with more threads than average
	 * because the recipient bucket has no threads.
	 */
	db = bucket;
	for (;;) {
		/* Next bucket */
		if (++db == idle_bucket)
			db = tq->tq_buckets;
		if (db == bucket)
			break;

		mutex_enter(&db->tqbucket_lock);
		nthreads = db->tqbucket_nalloc + db->tqbucket_nfree;
		if (nthreads > tq->tq_atpb) {
			taskq_backlog_enqueue(db, tqe, TQ_FRONT);
			mutex_exit(&db->tqbucket_lock);
			goto out;
		}
		mutex_exit(&db->tqbucket_lock);
	}
	/*
	 * No bucket with more than an average number of threads.
	 * Free the tqe; undo the redirect flag.
	 */
	DTRACE_PROBE2(taskq__redist__fails, taskq_t *, tq,
	    taskq_bucket_t *, bucket);
	kmem_cache_free(taskq_ent_cache, tqe);
	tqe = NULL;
	mutex_enter(&bucket->tqbucket_lock);
	bucket->tqbucket_flags &= ~TQBUCKET_REDIRECT;
	mutex_exit(&bucket->tqbucket_lock);

out:
	/*
	 * We're usually here because some backlog work exists.
	 * In case a thread became idle just before a backlog
	 * was added to some bucket, wake an idle thread.
	 */
	mutex_enter(&idle_bucket->tqbucket_lock);
	if (idle_bucket->tqbucket_nfree != 0) {
		taskq_ent_t *itqe;
		itqe = bucket->tqbucket_freelist.tqent_prev;
		cv_signal(&itqe->tqent_cv);
	}
	mutex_exit(&idle_bucket->tqbucket_lock);

	DTRACE_PROBE3(taskq__bucket__redist__ret, taskq_t *, tq,
	    taskq_bucket_t *, bucket, taskq_ent_t *, tqe);
}

static int
taskq_kstat_update(kstat_t *ksp, int rw)
{
	struct taskq_kstat *tqsp = &taskq_kstat;
	taskq_t *tq = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	tqsp->tq_pid.value.ui64 = tq->tq_proc->p_pid;
	tqsp->tq_tasks.value.ui64 = tq->tq_tasks;
	tqsp->tq_executed.value.ui64 = tq->tq_executed;
	tqsp->tq_maxtasks.value.ui64 = tq->tq_maxtasks;
	tqsp->tq_totaltime.value.ui64 = tq->tq_totaltime;
	tqsp->tq_nactive.value.ui64 = tq->tq_active;
	tqsp->tq_nalloc.value.ui64 = tq->tq_nalloc;
	tqsp->tq_pri.value.ui64 = tq->tq_pri;
	tqsp->tq_nthreads.value.ui64 = tq->tq_nthreads;
	tqsp->tq_nomem.value.ui64 = tq->tq_nomem;
	return (0);
}

static int
taskq_d_kstat_update(kstat_t *ksp, int rw)
{
	struct taskq_d_kstat *tqsp = &taskq_d_kstat;
	taskq_t *tq = ksp->ks_private;
	taskq_bucket_t *b;
	int bid;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ASSERT(tq->tq_flags & TASKQ_DYNAMIC);

	tqsp->tqd_pri.value.ui64 = tq->tq_pri;
	tqsp->tqd_nomem.value.ui64 = tq->tq_nomem;

	/*
	 * Accumulate tqbucket_nalloc etc, tqbucket_stats
	 */
	tqsp->tqd_nalloc.value.ui64 = 0;
	tqsp->tqd_nbacklog.value.ui64 = 0;
	tqsp->tqd_nfree.value.ui64 = 0;
	tqsp->tqd_totaltime.value.ui64 = 0;

	tqsp->tqd_hits.value.ui64 = 0;
	tqsp->tqd_misses.value.ui64 = 0;
	tqsp->tqd_ihits.value.ui64 = 0;
	tqsp->tqd_imisses.value.ui64 = 0;
	tqsp->tqd_overflows.value.ui64 = 0;
	tqsp->tqd_maxbacklog.value.ui64 = 0;
	tqsp->tqd_tcreates.value.ui64 = 0;
	tqsp->tqd_tdeaths.value.ui64 = 0;
	tqsp->tqd_maxthreads.value.ui64 = 0;
	tqsp->tqd_disptcreates.value.ui64 = 0;

	/* Apparently this can be called when... */
	if ((b = tq->tq_buckets) == NULL)
		return (0);

	for (bid = 0; bid <= tq->tq_nbuckets; b++, bid++) {

		tqsp->tqd_nalloc.value.ui64 += b->tqbucket_nalloc;
		tqsp->tqd_nbacklog.value.ui64 += b->tqbucket_nbacklog;
		tqsp->tqd_nfree.value.ui64 += b->tqbucket_nfree;
		tqsp->tqd_totaltime.value.ui64 += b->tqbucket_totaltime;

		/*
		 * For regular buckets, update hits, misses.
		 * For the idle bucket, update ihits, imisses
		 */
		if (bid < tq->tq_nbuckets) {
			tqsp->tqd_hits.value.ui64 +=
			    b->tqbucket_stat.tqs_hits;
			tqsp->tqd_misses.value.ui64 +=
			    b->tqbucket_stat.tqs_misses;
		} else {
			tqsp->tqd_ihits.value.ui64 +=
			    b->tqbucket_stat.tqs_hits;
			tqsp->tqd_imisses.value.ui64 +=
			    b->tqbucket_stat.tqs_misses;
		}

		tqsp->tqd_overflows.value.ui64 +=
		    b->tqbucket_stat.tqs_overflow;
		tqsp->tqd_maxbacklog.value.ui64 +=
		    b->tqbucket_stat.tqs_maxbacklog;
		tqsp->tqd_tcreates.value.ui64 +=
		    b->tqbucket_stat.tqs_tcreates;
		tqsp->tqd_tdeaths.value.ui64 +=
		    b->tqbucket_stat.tqs_tdeaths;
		tqsp->tqd_maxthreads.value.ui64 +=
		    b->tqbucket_stat.tqs_maxthreads;
		tqsp->tqd_disptcreates.value.ui64 +=
		    b->tqbucket_stat.tqs_disptcreates;
	}

	return (0);
}
