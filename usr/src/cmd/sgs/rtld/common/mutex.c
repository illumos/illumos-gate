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
 *	Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation of all threads interfaces between ld.so.1 and libthread.
 *
 * In a non-threaded environment all thread interfaces are vectored to noops.
 * When called via _ld_concurrency() from libthread these vectors are reassigned
 * to real threads interfaces.  Two models are supported:
 *
 * TI_VERSION == 1
 *	Under this model libthread provides rw_rwlock/rw_unlock, through which
 *	we vector all rt_mutex_lock/rt_mutex_unlock calls.
 *	Under lib/libthread these interfaces provided _sigon/_sigoff (unlike
 *	lwp/libthread that provided signal blocking via bind_guard/bind_clear.
 *
 * TI_VERSION == 2
 *	Under this model only libthreads bind_guard/bind_clear and thr_self
 *	interfaces are used.  Both libthreads block signals under the
 *	bind_guard/bind_clear interfaces.   Lower level locking is derived
 *	from internally bound _lwp_ interfaces.  This removes recursive
 *	problems encountered when obtaining locking interfaces from libthread.
 *	The use of mutexes over reader/writer locks also enables the use of
 *	condition variables for controlling thread concurrency (allows access to
 *	objects only after their .init has completed).
 *
 * CI_VERSION == 1
 *	introduced with CI_VERSION & CI_ATEXIT
 *
 * CI_VERSION == 2
 *	add support for CI_LCMESSAGES
 *
 * CI_VERSION == 3
 *	Add the following versions to the CI table:
 *
 *		CI_BIND_GUARD, CI_BIND_CLEAR, CI_THR_SELF
 *		CI_TLS_MODADD, CI_TLS_MOD_REMOVE, CI_TLS_STATMOD
 *
 *	It was also at this level that the DT_SUNW_RTLDINFO structure
 *	was introduced as a mechanism to handshake with ld.so.1
 *
 * CI_VERSION == 4
 *	  Added the CI_THRINIT handshake as part of the libc/libthread
 *	  merge project.  libc now initializes the current thread pointer
 *	  (%g7 for sparc) as part of this and no longer relies on the
 *	  INITFIRST flag (which others have started to camp out on).
 */
#include	"_synonyms.h"

#include	<synch.h>
#include	<signal.h>
#include	<thread.h>
#include	<synch.h>
#include	<strings.h>
#include	<stdio.h>
#include	"thr_int.h"
#include	"_elf.h"
#include	"_rtld.h"

/*
 * Define our own local mutex functions.
 */
static int	bindmask = THR_FLG_RTLD;

static int
_rt_bind_guard(int bit)
{
	if ((bit & bindmask) == 0) {
		bindmask |= bit;
		return (1);
	}
	return (0);
}

static int
_rt_bind_clear(int bit)
{
	if (bit == 0)
		return (bindmask);
	else {
		bindmask &= ~bit;
		return (0);
	}
}

static int
_rt_thr_self()
{
	return (1);
}

static int
_rt_null()
{
	return (0);
}

#if	(defined(DEBUG) || defined(SGS_PRE_UNIFIED_PROCESS))
/*
 * These three routines are used to protect the locks that ld.so.1 has.
 * They are passed to pthread_atfork() and used during a fork1() to make
 * sure we do not do a fork while a lock is being held.
 */
static void
prepare_atfork(void)
{
	(void) rt_bind_guard(THR_FLG_MASK);
	(void) rt_mutex_lock(&rtldlock);
}

static void
child_atfork(void)
{
	(void) rt_mutex_unlock(&rtldlock);
	(void) rt_bind_clear(THR_FLG_MASK);
}

static void
parent_atfork(void)
{
	(void) rt_mutex_unlock(&rtldlock);
	(void) rt_bind_clear(THR_FLG_MASK);
}
#endif

/*
 * Define the maximum number of thread interfaces ld.so.1 is interested in,
 * this is a subset of the total number of interfaces communicated between
 * libthread and libc.
 */
#define	STI_MAX			11

/*
 * Define our own thread jump table.
 */
#define	RT_BIND_GUARD		0
#define	RT_BIND_CLEAR		1
#define	RT_THR_SELF		2
#define	RT_MUTEX_LOCK		3
#define	RT_MUTEX_UNLOCK		4
#define	RT_COND_WAIT		5
#define	RT_COND_BROAD		6

#define	SRT_MAX			7

static int (*	thr_jmp_table[SRT_MAX])() = {
	_rt_bind_guard,				/* RT_BIND_GUARD */
	_rt_bind_clear,				/* RT_BIND_CLEAR */
	_rt_thr_self,				/* RT_THR_SELF */
	_rt_null,				/* RT_MUTEX_LOCK */
	_rt_null,				/* RT_MUTEX_UNLOCK */
	_rt_null,				/* RT_COND_WAIT */
	_rt_null				/* RT_COND_BROAD */
};

#if	(defined(DEBUG) || defined(SGS_PRE_UNIFIED_PROCESS))
static int (*	thr_def_table[SRT_MAX])() = {
	_rt_bind_guard,				/* RT_BIND_GUARD */
	_rt_bind_clear,				/* RT_BIND_CLEAR */
	_rt_thr_self,				/* RT_THR_SELF */
	_rt_null,				/* RT_MUTEX_LOCK */
	_rt_null,				/* RT_MUTEX_UNLOCK */
	_rt_null,				/* RT_COND_WAIT */
	_rt_null				/* RT_COND_BROAD */
};
#endif

/*
 * The interface with the threads library which is supplied through libdl.so.1.
 * A non-null argument allows a function pointer array to be passed to us which
 * is used to re-initialize the linker concurrency table.  A null argument
 * causes the table to be reset to the defaults.
 */
void
/* ARGSUSED */
_ld_concurrency(void * ptr)
{
#if	(defined(DEBUG) || defined(SGS_PRE_UNIFIED_PROCESS))
	int		tag;
	Thr_interface *	funcs = ptr;

	if (funcs) {
		int (*	table[STI_MAX])();

		/*
		 * Collect all the threads interfaces we're interested in.
		 */
		table[TI_LATFORK] = NULL;
		for (tag = funcs->ti_tag; tag; tag = (++funcs)->ti_tag) {
			if (tag < STI_MAX)
				table[tag] = funcs->ti_un.ti_func;
		}

		/*
		 * At this point we've re-entered ld.so.1 from libthreads .init.
		 * All locks are down.  Exercise any common thread interfaces
		 * before we remap ld.so.1 to use them, this allows us to be
		 * re-entered to resolve .plt's without exercising locks.
		 */
		(void) (*table[TI_BIND_GUARD])(THR_FLG_RTLD);
		(void) (*table[TI_BIND_CLEAR])(THR_FLG_RTLD);
		(void) (*table[TI_THRSELF])();

		/*
		 * Prepare atfork, if necessary.
		 */
		if (table[TI_LATFORK])
			(void) (*table[TI_LATFORK])(prepare_atfork,
			    parent_atfork, child_atfork);

		/*
		 * Establish what interfaces are available for this version of
		 * libthread and make them live.
		 */
		if (table[TI_VERSION] == (int (*)())1) {
			/*
			 * Restrict ourselves to the readers/writers locks.
			 */
			(void) (*table[TI_LRW_WRLOCK])(&rtldlock);
			(void) (*table[TI_LRW_UNLOCK])(&rtldlock);

			thr_jmp_table[RT_MUTEX_LOCK] = table[TI_LRW_WRLOCK];
			thr_jmp_table[RT_MUTEX_UNLOCK] = table[TI_LRW_UNLOCK];
		} else {
			/*
			 * Go directly to our internal interfaces.
			 */
			thr_jmp_table[RT_MUTEX_LOCK] = _lwp_mutex_lock;
			thr_jmp_table[RT_MUTEX_UNLOCK] = _lwp_mutex_unlock;
			thr_jmp_table[RT_COND_WAIT] = _lwp_cond_wait;
			thr_jmp_table[RT_COND_BROAD] = _lwp_cond_broadcast;

			/*
			 * If concurrency is requested inable it now.
			 */
			if ((rtld_flags & RT_FL_NOCONCUR) == 0)
				rtld_flags |= RT_FL_CONCUR;
		}

		/*
		 * Make all common interfaces go live.
		 */
		thr_jmp_table[RT_BIND_CLEAR] = table[TI_BIND_CLEAR];
		thr_jmp_table[RT_BIND_GUARD] = table[TI_BIND_GUARD];
		thr_jmp_table[RT_THR_SELF] = table[TI_THRSELF];

		rtld_flags |= RT_FL_THREADS;

	} else {
		/*
		 * If libthread were to be dlclosed() we'd get here to reset
		 * our interfaces back to the internal noops (as libthread
		 * typically can't be dlclosed() it's unlikely we'll ever
		 * exercise this.  If a bindlock is currently in place clear it.
		 */
		if (rt_bind_clear(0x0) & THR_FLG_RTLD) {
			(void) rt_mutex_unlock(&rtldlock);
			(void) rt_bind_clear(THR_FLG_RTLD);
		}
		rtld_flags &= ~RT_FL_THREADS;
		for (tag = 0; tag < SRT_MAX; tag++)
			thr_jmp_table[tag] = thr_def_table[tag];
	}
#endif
}

void
get_lcinterface(Rt_map *lmp, Lc_interface *funcs)
{
	int		tag;
	char		*nlocale;
	void		*tlsmodadd = 0;
	void		*tlsmodrem = 0;
	void		*tlsstatmod = 0;
	Lm_list		*lml, *lml2;
	Listnode	*lnp;

	if (!funcs || !lmp)
		return;

	lml = LIST(lmp);

	for (tag = funcs->ci_tag; tag; tag = (++funcs)->ci_tag) {
		switch (tag) {
		case CI_ATEXIT:
			/*
			 * If we obtained a _preexec_exit_handlers()
			 * call back (typically supplied via libc's
			 * .init) then register it for use in dlclose().
			 */
			if (lml->lm_peh == 0) {
				lml->lm_peh = funcs->ci_un.ci_func;
				lml->lm_peh_lmp = lmp;
			}
			break;
		case CI_LCMESSAGES:
			/*
			 * If we've obtained a message locale (typically
			 * supplied via libc's setlocale()) then
			 * register it for use in dgettext() to
			 * reestablish a locale for ld.so.1's messages.
			 */
			if (lml->lm_flags & LML_FLG_BASELM) {
				nlocale = funcs->ci_un.ci_ptr;
				if ((locale == 0) ||
				    strcmp(locale, nlocale)) {
					if (locale) {
						free((void *)locale);
						rtld_flags |= RT_FL_NEWLOCALE;
					}
					locale = strdup(nlocale);

					/*
					 * Clear any cached messages.
					 */
					err_strs[ERR_NONE] = 0;
					err_strs[ERR_WARNING] = 0;
					err_strs[ERR_FATAL] = 0;
					err_strs[ERR_ELF] = 0;

					nosym_str = 0;
				}
			}
			break;
		case CI_BIND_GUARD:
			thr_jmp_table[RT_BIND_GUARD] =
				(int(*)())funcs->ci_un.ci_ptr;
			/*
			 * Go directly to our internal interfaces.
			 */
			thr_jmp_table[RT_MUTEX_LOCK] = _lwp_mutex_lock;
			thr_jmp_table[RT_MUTEX_UNLOCK] = _lwp_mutex_unlock;
			thr_jmp_table[RT_COND_WAIT] = _lwp_cond_wait;
			thr_jmp_table[RT_COND_BROAD] = _lwp_cond_broadcast;

			/*
			 * If concurrency is requested inable it now.
			 */
			if ((rtld_flags & RT_FL_NOCONCUR) == 0)
				rtld_flags |= RT_FL_CONCUR;
			rtld_flags |= RT_FL_THREADS;
			break;
		case CI_BIND_CLEAR:
			thr_jmp_table[RT_BIND_CLEAR] =
				(int(*)()) funcs->ci_un.ci_ptr;
			break;
		case CI_THR_SELF:
			thr_jmp_table[RT_THR_SELF] =
				(int(*)()) funcs->ci_un.ci_ptr;
			break;
		case CI_TLS_MODADD:
			tlsmodadd = funcs->ci_un.ci_ptr;
			break;
		case CI_TLS_MODREM:
			tlsmodrem = funcs->ci_un.ci_ptr;
			break;
		case CI_TLS_STATMOD:
			tlsstatmod = funcs->ci_un.ci_ptr;
			break;
#ifdef	CI_THRINIT
		case CI_THRINIT:
			thrinit = (void(*)())funcs->ci_un.ci_ptr;
			break;
#endif
#ifdef	CI_V_FOUR
		case CI_VERSION:
			if ((rtld_flags2 & RT_FL2_RTLDSEEN) == 0) {
			    rtld_flags2 |= RT_FL2_RTLDSEEN;
			    if (funcs->ci_un.ci_val >= CI_V_FOUR) {
				rtld_flags2 |= RT_FL2_UNIFPROC;

				/*
				 * We might have seen auditor which
				 * is not dependent on libc. Such auditor's
				 * link map list has LML_FLG_HOLDLOCK on.
				 * It needs to be dropped. Refer to:
				 *	audit_setup() in audit.c.
				 */
				if ((rtld_flags2 & RT_FL2_HASAUDIT) == 0)
					break;

				/*
				 * Yes, we did. Take care of them.
				 */
				for (LIST_TRAVERSE(&dynlm_list, lnp, lml2)) {
					Rt_map *map = (Rt_map *)lml2->lm_head;

					if (FLAGS(map) & FLG_RT_AUDIT) {
						lml2->lm_flags &=
							~LML_FLG_HOLDLOCK;
					}
				}
			    }
			}
			break;
#endif
		default:
			break;
		}
	}
	if (tlsmodadd && tlsmodrem && tlsstatmod)
		tls_setroutines(lml, tlsmodadd, tlsmodrem, tlsstatmod);
}

/*
 * Define the local interface for each of the threads interfaces.
 */
thread_t
rt_thr_self()
{
	return ((* thr_jmp_table[RT_THR_SELF])());
}

int
rt_mutex_lock(Rt_lock * mp)
{
	return ((* thr_jmp_table[RT_MUTEX_LOCK])(mp));
}

int
rt_mutex_unlock(Rt_lock * mp)
{
	return ((* thr_jmp_table[RT_MUTEX_UNLOCK])(mp));
}

int
rt_bind_guard(int bindflag)
{
	return ((* thr_jmp_table[RT_BIND_GUARD])(bindflag));
}

int
rt_bind_clear(int bindflag)
{
	return ((* thr_jmp_table[RT_BIND_CLEAR])(bindflag));
}

Rt_cond *
rt_cond_create()
{
	return (calloc(1, sizeof (Rt_cond)));
}

int
rt_cond_wait(Rt_cond * cvp, Rt_lock * mp)
{
	return ((* thr_jmp_table[RT_COND_WAIT])(cvp, mp));
}

int
rt_cond_broadcast(Rt_cond * cvp)
{
	return ((* thr_jmp_table[RT_COND_BROAD])(cvp));
}

#ifdef	EXPAND_RELATIVE

/*
 * Mutex interfaces to resolve references from any objects extracted from
 * libc_pic.a.  Note, as ld.so.1 is essentially single threaded these can be
 * noops.
 */

#pragma weak lmutex_lock = __mutex_lock
#pragma weak _private_mutex_lock = __mutex_lock
#pragma weak mutex_lock = __mutex_lock
#pragma weak _mutex_lock = __mutex_lock
/* ARGSUSED */
int
__mutex_lock(mutex_t *mp)
{
	return (0);
}

#pragma weak lmutex_unlock = __mutex_unlock
#pragma weak _private_mutex_unlock = __mutex_unlock
#pragma weak mutex_unlock = __mutex_unlock
#pragma weak _mutex_unlock = __mutex_unlock
/* ARGSUSED */
int
__mutex_unlock(mutex_t *mp)
{
	return (0);
}

/*
 * This is needed to satisfy sysconf() (case _SC_THREAD_STACK_MIN)
 */
#pragma weak thr_min_stack = _thr_min_stack
size_t
_thr_min_stack()
{
#ifdef _LP64
	return (8 * 1024);
#else
	return (4 * 1024);
#endif
}

#endif	/* EXPAND_RELATIVE */
