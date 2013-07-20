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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma weak _atexit = atexit

#include "lint.h"
#include "thr_uberdata.h"
#include "libc_int.h"
#include "atexit.h"
#include "stdiom.h"

/*
 * Note that memory is managed by lmalloc()/lfree().
 *
 * Among other reasons, this is occasioned by the insistence of our
 * brothers sh(1) and csh(1) that they can do malloc, etc., better than
 * libc can.  Those programs define their own malloc routines, and
 * initialize the underlying mechanism in main().  This means that calls
 * to malloc occuring before main will crash.  The loader calls atexit(3C)
 * before calling main, so we'd better avoid malloc() when it does.
 *
 * Another reason for using lmalloc()/lfree() is that the atexit()
 * list must transcend all link maps.  See the Linker and Libraries
 * Guide for information on alternate link maps.
 *
 * See "thr_uberdata.h" for the definitions of structures used here.
 */

static int in_range(void *, Lc_addr_range_t[], uint_t count);

extern	caddr_t	_getfp(void);

/*
 * exitfns_lock is declared to be a recursive mutex so that we
 * can hold it while calling out to the registered functions.
 * If they call back to us, we are self-consistent and everything
 * works, even the case of calling exit() from functions called
 * by _exithandle() (recursive exit()).  All that is required is
 * that the registered functions actually return (no longjmp()s).
 *
 * Because exitfns_lock is declared to be a recursive mutex, we
 * cannot use it with lmutex_lock()/lmutex_unlock() and we must
 * use mutex_lock()/mutex_unlock().  This means that atexit()
 * and exit() are not async-signal-safe.  We make them fork1-safe
 * via the atexit_locks()/atexit_unlocks() functions, called from
 * libc_prepare_atfork()/libc_child_atfork()/libc_parent_atfork()
 */

/*
 * atexit_locks() and atexit_unlocks() are called on every link map.
 * Do not use curthread->ul_uberdata->atexit_root for these.
 */
void
atexit_locks()
{
	(void) mutex_lock(&__uberdata.atexit_root.exitfns_lock);
}

void
atexit_unlocks()
{
	(void) mutex_unlock(&__uberdata.atexit_root.exitfns_lock);
}


/*
 * This is called via atexit() before the primordial thread is fully set up.
 * Be careful about dereferencing self->ul_uberdata->atexit_root.
 */
int
__cxa_atexit(void (*hdlr)(void *), void *arg, void *dso)
{
	ulwp_t *self;
	atexit_root_t *arp;
	_exthdlr_t *p;

	if ((p = lmalloc(sizeof (_exthdlr_t))) == NULL)
		return (-1);

	if ((self = __curthread()) == NULL)
		arp = &__uberdata.atexit_root;
	else {
		arp = &self->ul_uberdata->atexit_root;
		(void) mutex_lock(&arp->exitfns_lock);
	}
	p->hdlr = hdlr;
	p->arg = arg;
	p->dso = dso;
	p->next = arp->head;
	arp->head = p;

	if (self != NULL)
		(void) mutex_unlock(&arp->exitfns_lock);
	return (0);
}

int
atexit(void (*func)(void))
{
	return (__cxa_atexit((_exithdlr_func_t)func, NULL, NULL));
}

/*
 * Note that we may be entered recursively, as we'll call __cxa_finalize(0) at
 * exit, one of our handlers is ld.so.1`atexit_fini, and libraries may call
 * __cxa_finalize(__dso_handle) from their _fini.
 */
void
__cxa_finalize(void *dso)
{
	atexit_root_t *arp = &curthread->ul_uberdata->atexit_root;
	_exthdlr_t *p, *o;
	int cancel_state;

	/* disable cancellation while running atexit handlers */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	(void) mutex_lock(&arp->exitfns_lock);

	o = NULL;
	p = arp->head;
	while (p != NULL) {
		if ((dso == NULL) || (p->dso == dso)) {
			if (o != NULL)
				o->next = p->next;
			else
				arp->head = p->next;

			p->hdlr(p->arg);
			lfree(p, sizeof (_exthdlr_t));
			o = NULL;
			p = arp->head;
		} else {
			o = p;
			p = p->next;
		}
	}

	(void) mutex_unlock(&arp->exitfns_lock);
	(void) pthread_setcancelstate(cancel_state, NULL);
}

void
_exithandle(void)
{
	atexit_root_t *arp = &curthread->ul_uberdata->atexit_root;

	arp->exit_frame_monitor = _getfp() + STACK_BIAS;
	__cxa_finalize(NULL);
}

/*
 * _get_exit_frame_monitor is called by the C++ runtimes.
 */
void *
_get_exit_frame_monitor(void)
{
	atexit_root_t *arp = &curthread->ul_uberdata->atexit_root;
	return (&arp->exit_frame_monitor);
}

/*
 * The following is a routine which the loader (ld.so.1) calls when it
 * processes a dlclose call on an object.  It resets all signal handlers
 * which fall within the union of the ranges specified by the elements
 * of the array range to SIG_DFL.
 */
static void
_preexec_sig_unload(Lc_addr_range_t range[], uint_t count)
{
	uberdata_t *udp = curthread->ul_uberdata;
	int sig;
	rwlock_t *rwlp;
	struct sigaction *sap;
	struct sigaction oact;
	void (*handler)();

	for (sig = 1; sig < NSIG; sig++) {
		sap = (struct sigaction *)&udp->siguaction[sig].sig_uaction;
again:
		handler = sap->sa_handler;
		if (handler != SIG_DFL && handler != SIG_IGN &&
		    in_range((void *)handler, range, count)) {
			rwlp = &udp->siguaction[sig].sig_lock;
			lrw_wrlock(rwlp);
			if (handler != sap->sa_handler) {
				lrw_unlock(rwlp);
				goto again;
			}
			sap->sa_handler = SIG_DFL;
			sap->sa_flags = SA_SIGINFO;
			(void) sigemptyset(&sap->sa_mask);
			if (__sigaction(sig, NULL, &oact) == 0 &&
			    oact.sa_handler != SIG_DFL &&
			    oact.sa_handler != SIG_IGN)
				(void) __sigaction(sig, sap, NULL);
			lrw_unlock(rwlp);
		}
	}
}

/*
 * The following is a routine which the loader (ld.so.1) calls when it
 * processes a dlclose call on an object.  It cancels all atfork() entries
 * whose prefork, parent postfork, or child postfork functions fall within
 * the union of the ranges specified by the elements of the array range.
 */
static void
_preexec_atfork_unload(Lc_addr_range_t range[], uint_t count)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	atfork_t *atfork_q;
	atfork_t *atfp;
	atfork_t *next;
	void (*func)(void);
	int start_again;

	(void) mutex_lock(&udp->atfork_lock);
	if ((atfork_q = udp->atforklist) != NULL) {
		atfp = atfork_q;
		do {
			next = atfp->forw;
			start_again = 0;

			if (((func = atfp->prepare) != NULL &&
			    in_range((void *)func, range, count)) ||
			    ((func = atfp->parent) != NULL &&
			    in_range((void *)func, range, count)) ||
			    ((func = atfp->child) != NULL &&
			    in_range((void *)func, range, count))) {
				if (self->ul_fork) {
					/*
					 * dlclose() called from a fork handler.
					 * Deleting the entry would wreak havoc.
					 * Just null out the function pointers
					 * and leave the entry in place.
					 */
					atfp->prepare = NULL;
					atfp->parent = NULL;
					atfp->child = NULL;
					continue;
				}
				if (atfp == atfork_q) {
					/* deleting the list head member */
					udp->atforklist = atfork_q = next;
					start_again = 1;
				}
				atfp->forw->back = atfp->back;
				atfp->back->forw = atfp->forw;
				lfree(atfp, sizeof (atfork_t));
				if (atfp == atfork_q) {
					/* we deleted the whole list */
					udp->atforklist = NULL;
					break;
				}
			}
		} while ((atfp = next) != atfork_q || start_again);
	}
	(void) mutex_unlock(&udp->atfork_lock);
}

/*
 * The following is a routine which the loader (ld.so.1) calls when it
 * processes a dlclose call on an object.  It sets the destructor
 * function pointer to NULL for all keys whose destructors fall within
 * the union of the ranges specified by the elements of the array range.
 * We don't assign TSD_UNALLOCATED (the equivalent of pthread_key_destroy())
 * because the thread may use the key's TSD further on in fini processing.
 */
static void
_preexec_tsd_unload(Lc_addr_range_t range[], uint_t count)
{
	tsd_metadata_t *tsdm = &curthread->ul_uberdata->tsd_metadata;
	void (*func)(void *);
	int key;

	lmutex_lock(&tsdm->tsdm_lock);
	for (key = 1; key < tsdm->tsdm_nused; key++) {
		if ((func = tsdm->tsdm_destro[key]) != NULL &&
		    func != TSD_UNALLOCATED &&
		    in_range((void *)func, range, count))
			tsdm->tsdm_destro[key] = NULL;
	}
	lmutex_unlock(&tsdm->tsdm_lock);
}

/*
 * The following is a routine which the loader (ld.so.1) calls when it
 * processes dlclose calls on objects with atexit registrations.  It
 * executes the exit handlers that fall within the union of the ranges
 * specified by the elements of the array range in the REVERSE ORDER of
 * their registration.  Do not change this characteristic; it is REQUIRED
 * BEHAVIOR.
 */
int
_preexec_exit_handlers(Lc_addr_range_t range[], uint_t count)
{
	atexit_root_t *arp = &curthread->ul_uberdata->atexit_root;
	_exthdlr_t *o;		/* previous node */
	_exthdlr_t *p;		/* this node */
	int cancel_state;

	/* disable cancellation while running atexit handlers */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	(void) mutex_lock(&arp->exitfns_lock);
	o = NULL;
	p = arp->head;
	while (p != NULL) {
		/*
		 * We call even CXA handlers of functions present in the
		 * library being unloaded.  The specification isn't
		 * particularly clear on this, and this seems the most sane.
		 * This is the behaviour of FreeBSD 9.1 (GNU libc leaves the
		 * handler on the exit list, and crashes at exit time).
		 *
		 * This won't cause handlers to be called twice, because
		 * anything called from a __cxa_finalize call from the
		 * language runtime will have been removed from the list.
		 */
		if (in_range((void *)p->hdlr, range, count)) {
			/* We need to execute this one */
			if (o != NULL)
				o->next = p->next;
			else
				arp->head = p->next;
			p->hdlr(p->arg);
			lfree(p, sizeof (_exthdlr_t));
			o = NULL;
			p = arp->head;
		} else {
			o = p;
			p = p->next;
		}
	}
	(void) mutex_unlock(&arp->exitfns_lock);
	(void) pthread_setcancelstate(cancel_state, NULL);

	_preexec_tsd_unload(range, count);
	_preexec_atfork_unload(range, count);
	_preexec_sig_unload(range, count);

	return (0);
}

static int
in_range(void *addr, Lc_addr_range_t ranges[], uint_t count)
{
	uint_t idx;

	for (idx = 0; idx < count; idx++) {
		if (addr >= ranges[idx].lb &&
		    addr < ranges[idx].ub) {
			return (1);
		}
	}

	return (0);
}
