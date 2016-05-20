/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Manage the native/emulation stack for LX-branded LWPs.
 */

#include <assert.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>

#include <thread.h>
#include <sys/mman.h>
#include <sys/brand.h>
#include <sys/syscall.h>
#include <sys/debug.h>

#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_thread.h>


typedef struct lx_stack_list_ent {
	thread_t sle_tid;
	void *sle_stack;
	size_t sle_stack_size;
	lx_tsd_t *sle_tsd;
} lx_stack_list_ent_t;

static mutex_t lx_stack_list_lock = ERRORCHECKMUTEX;
lx_stack_list_ent_t *lx_stack_list = NULL;
unsigned int lx_stack_list_elems = 0;

/*
 * Usermode emulation alternate stack size, expressed as a page count:
 */
int lx_native_stack_page_count = LX_NATIVE_STACK_PAGE_COUNT;

/*
 * We use these private functions from libc to suspend signal delivery in
 * critical sections:
 */
extern void _sigon(void);
extern void _sigoff(void);

void
lx_stack_prefork(void)
{
	lx_tsd_t *lx_tsd = lx_get_tsd();

	/*
	 * The "lx_stack_list_lock" mutex is used to protect access to the list
	 * of per-thread native stacks.  Management of native stacks is
	 * generally performed while servicing an emulated fork(2), vfork(2) or
	 * clone(2) system call.
	 *
	 * Multiple threads may be attempting to create new threads or
	 * processes concurrently, but in the case of fork(2) only the
	 * currently executing thread is duplicated in the child process.  We
	 * require that the stack list lock be taken before the native fork1()
	 * or forkx(), and released in both the parent and the child once the
	 * operation is complete. For vfork() the lock must only be released in
	 * the parent (once it resumes execution) since the child is borrowing
	 * the parent's thread. The _sigoff/_sigon dance will also only take
	 * place in the parent.
	 *
	 * Holding this mutex prevents the forked child from containing a
	 * copy-on-write copy of a locked mutex without the thread that would
	 * later unlock it.  We also suspend signal delivery while entering
	 * this critical section to ensure async signal safety.
	 *
	 * Unfortunately some Linux applications (e.g. busybox) will call vfork
	 * and then call fork (without the expected intervening exec). We
	 * avoid the mutex deadlock by skipping the call since we know this
	 * thread has borrowed the parent's address space and the parent cannot
	 * execute until we exit/exec.
	 */
	_sigoff();
	if (lx_tsd->lxtsd_is_vforked == 0)
		VERIFY0(mutex_lock(&lx_stack_list_lock));
}

void
lx_stack_postfork(void)
{
	lx_tsd_t *lx_tsd = lx_get_tsd();

	if (lx_tsd->lxtsd_is_vforked == 0)
		VERIFY0(mutex_unlock(&lx_stack_list_lock));
	_sigon();
}

/*
 * Free the alternate stack for this thread.
 */
void
lx_free_stack(void)
{
	thread_t me = thr_self();
	int i;

	_sigoff();
	VERIFY0(mutex_lock(&lx_stack_list_lock));

	/*
	 * Find this thread's stack in the list of stacks.
	 */
	for (i = 0; i < lx_stack_list_elems; i++) {
		if (lx_stack_list[i].sle_tid != me) {
			continue;
		}

		(void) munmap(lx_stack_list[i].sle_stack,
		    lx_stack_list[i].sle_stack_size);

		/*
		 * Free the thread-specific data structure for this thread.
		 */
		if (lx_stack_list[i].sle_tsd != NULL) {
			free(lx_stack_list[i].sle_tsd->lxtsd_clone_state);
			free(lx_stack_list[i].sle_tsd);
		}

		/*
		 * Free up this stack list entry:
		 */
		bzero(&lx_stack_list[i], sizeof (lx_stack_list[i]));

		VERIFY0(mutex_unlock(&lx_stack_list_lock));
		_sigon();
		return;
	}

	/*
	 * Did not find the stack in the list.
	 */
	assert(0);
}

/*
 * After fork1(), we must unmap the stack of every thread other than the
 * one copied into the child process.
 */
void
lx_free_other_stacks(void)
{
	int i, this_stack = -1;
	thread_t me = thr_self();
	lx_tsd_t *lx_tsd = lx_get_tsd();

	_sigoff();

	/*
	 * We don't need to check or take the lx_stack_list_lock here because
	 * we are the only thread in this process, but if we got here via an
	 * evil vfork->fork path then we must drop the lock for the new child
	 * and reset our "is_vforked" counter.
	 */
	if (lx_tsd->lxtsd_is_vforked != 0) {
		VERIFY0(mutex_unlock(&lx_stack_list_lock));
		lx_tsd->lxtsd_is_vforked = 0;
	}

	for (i = 0; i < lx_stack_list_elems; i++) {
		if (lx_stack_list[i].sle_tid == me) {
			/*
			 * Do not unmap the stack for this LWP.
			 */
			this_stack = i;
			continue;
		} else if (lx_stack_list[i].sle_tid == 0) {
			/*
			 * Skip any holes in the list.
			 */
			continue;
		}

		/*
		 * Free the thread-specific data structure for this thread.
		 */
		if (lx_stack_list[i].sle_tsd != NULL) {
			free(lx_stack_list[i].sle_tsd->lxtsd_clone_state);
			free(lx_stack_list[i].sle_tsd);
		}

		/*
		 * Unmap the stack of every other LWP.
		 */
		(void) munmap(lx_stack_list[i].sle_stack,
		    lx_stack_list[i].sle_stack_size);
	}
	/*
	 * Did not find the stack for this LWP in the list.
	 */
	assert(this_stack != -1);

	/*
	 * Ensure the stack data for this LWP is in the first slot and shrink
	 * the list.
	 */
	if (this_stack != 0) {
		lx_stack_list[0] = lx_stack_list[this_stack];
	}
	lx_stack_list_elems = 1;
	lx_stack_list = realloc(lx_stack_list, lx_stack_list_elems *
	    sizeof (lx_stack_list[0]));
	if (lx_stack_list == NULL) {
		lx_err_fatal("failed to shrink stack list: %s",
		    strerror(errno));
	}

	_sigon();
}

/*
 * Allocate an alternate stack for the execution of native emulation routines.
 * This routine is based, in part, on find_stack() from libc.
 */
int
lx_alloc_stack(void **nstack, size_t *nstack_size)
{
	static int pagesize = 0;
	static int stackprot = 0;
	int stacksize = 0;
	void *stack;

	/*
	 * Fetch configuration once:
	 */
	if (pagesize == 0) {
		pagesize = _sysconf(_SC_PAGESIZE);
		assert(pagesize > 0);
	}
	if (stackprot == 0) {
		long lprot = _sysconf(_SC_STACK_PROT);

		stackprot = lprot > 0 ? lprot : (PROT_READ | PROT_WRITE);
	}

	stacksize = lx_native_stack_page_count * pagesize;

	if ((stack = mmap(NULL, stacksize, stackprot, MAP_PRIVATE |
	    MAP_NORESERVE | MAP_ANON, -1, (off_t)0)) == MAP_FAILED) {
		int en = errno;
		lx_debug("lx_alloc_stack: failed to allocate stack: %s",
		    strerror(errno));
		errno = en;
		return (-1);
	}

#if DEBUG
	/*
	 * Write a recognisable pattern into the allocated stack pages.
	 */
	for (pos = 0; pos < ((stacksize - 1) / 4); pos++) {
		((uint32_t *)stack)[pos] = 0x0facade0;
	}
#endif

	*nstack = stack;
	*nstack_size = stacksize;

	return (0);
}

/*
 * Configure the in-kernel brand-specific LWP data with the native stack
 * pointer for this thread.  If a stack is not passed, allocate one first.
 */
void
lx_install_stack(void *stack, size_t stacksize, lx_tsd_t *tsd)
{
	thread_t me = thr_self();
	int i;
	uintptr_t stack_top;

	if (stack == NULL) {
		/*
		 * If we were not passed a stack, then allocate one:
		 */
		if (lx_alloc_stack(&stack, &stacksize) == -1) {
			lx_err_fatal("failed to allocate stack for thread "
			    "%d: %s", me, strerror(errno));
		}
	}

	/*
	 * Install the stack in the global list of thread stacks.
	 */
	_sigoff();
	VERIFY0(mutex_lock(&lx_stack_list_lock));

	for (i = 0; i < lx_stack_list_elems; i++) {
		assert(lx_stack_list[i].sle_tid != me);
		if (lx_stack_list[i].sle_tid == 0)
			break;
	}
	if (i >= lx_stack_list_elems) {
		lx_stack_list_elems++;
		lx_stack_list = realloc(lx_stack_list, lx_stack_list_elems *
		    sizeof (lx_stack_list[0]));
		if (lx_stack_list == NULL) {
			lx_err_fatal("failed to extend stack list: %s",
			    strerror(errno));
		}
	}
	lx_stack_list[i].sle_tid = me;
	lx_stack_list[i].sle_stack = stack;
	lx_stack_list[i].sle_stack_size = stacksize;
	lx_stack_list[i].sle_tsd = tsd;

	VERIFY0(mutex_unlock(&lx_stack_list_lock));
	_sigon();

	/*
	 * Inform the kernel of the location of the brand emulation
	 * stack for this LWP:
	 */
	stack_top = (uintptr_t)stack + stacksize;
	lx_debug("stack %p stack_top %p\n", stack, stack_top);
	if (syscall(SYS_brand, B_SET_NATIVE_STACK, stack_top) != 0) {
		lx_err_fatal("unable to set native stack: %s", strerror(errno));
	}
}
