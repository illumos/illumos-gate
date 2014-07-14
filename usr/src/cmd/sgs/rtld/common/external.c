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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * Implementation of all external interfaces between ld.so.1 and libc.
 *
 * This file started as a set of routines that provided synchronization and
 * locking operations using calls to libthread.  libthread has merged with libc
 * under the Unified Process Model (UPM), and things have gotten a lot simpler.
 * This file continues to establish and redirect various events within ld.so.1
 * to interfaces within libc.
 *
 * Until libc is loaded and relocated, any external interfaces are captured
 * locally.  Each link-map list maintains its own set of external vectors, as
 * each link-map list typically provides its own libc.  Although this per-link-
 * map list vectoring provides a degree of flexibility, there is a protocol
 * expected when calling various libc interfaces.
 *
 * i.	Any new alternative link-map list should call CI_THRINIT, and then call
 *	CI_TLS_MODADD to register any TLS for each object of that link-map list
 *	(this item is labeled i. as auditors can be the first objects loaded,
 *	and they exist on their own lik-map list).
 *
 * ii.	For the primary link-map list, CI_TLS_STATMOD must be called first to
 *	register any static TLS.  This routine is called regardless of there
 *	being any TLS, as this routine also establishes the link-map list as the
 *	primary list and fixes the association of uberdata).  CI_THRINIT should
 *	then be called.
 *
 * iii.	Any objects added to an existing link-map list (primary or alternative)
 *	should call CI_TLS_MODADD to register any additional TLS.
 *
 * These events are established by:
 *
 * i.	Typically, libc is loaded as part of the primary dependencies of any
 *	link-map list (since the Unified Process Model (UPM), libc can't be
 *	lazily loaded).  To minimize the possibility of loading and registering
 *	objects, and then tearing them down (because of a relocation error),
 *	external vectors are established as part of load_completion().  This
 *	routine is called on completion of any operation that can cause objects
 *	to be loaded.  This point of control insures the objects have been fully
 *	analyzed and relocated, and moved to their controlling link-map list.
 *	The external vectors are established prior to any .inits being fired.
 *
 * ii.	Calls to CI_THRINIT, and CI_TLS_MODADD also occur as part of
 *	load_completion().  CI_THRINIT is only called once for each link-map
 *	control list.
 *
 * iii.	Calls to CI_TLS_STATMOD, and CI_THRINIT occur for the primary link-map
 *	list in the final stages of setup().
 *
 * The interfaces provide by libc can be divided into two families.  The first
 * family consists of those interfaces that should be called from the link-map
 * list.  It's possible that these interfaces convey state concerning the
 * link-map list they are part of:
 *
 *	CI_ATEXIT
 *	CI TLS_MODADD
 *	CI_TLS_MODREM
 *	CI_TLS_STATMOD
 *	CI_THRINIT
 *
 * The second family are global in nature, that is, the link-map list from
 * which they are called provides no state information.  In fact, for
 * CI_BIND_GUARD, the calling link-map isn't even known.  The link-map can only
 * be deduced after ld.so.1's global lock has been obtained.  Therefore, the
 * following interfaces are also maintained as global:
 *
 *	CI_LCMESSAGES
 *	CI_BIND_GUARD
 *	CI_BIND_CLEAR
 *	CI_THR_SELF
 *
 * Note, it is possible that these global interfaces are obtained from an
 * alternative link-map list that gets torn down because of a processing
 * failure (unlikely, because the link-map list components must be analyzed
 * and relocated prior to load_completion(), but perhaps the tear down is still
 * a possibility).  Thus the global interfaces may have to be replaced.  Once
 * the interfaces have been obtained from the primary link-map, they can
 * remain fixed, as the primary link-map isn't going to go anywhere.
 *
 * The last wrinkle in the puzzle is what happens if an alternative link-map
 * is loaded with no libc dependency?  In this case, the alternative objects
 * can not call CI_THRINIT, can not be allowed to use TLS, and will not receive
 * any atexit processing.
 *
 * The history of these external interfaces is defined by their version:
 *
 * TI_VERSION == 1
 *	Under this model libthread provided rw_rwlock/rw_unlock, through which
 *	all rt_mutex_lock/rt_mutex_unlock calls were vectored.
 *	Under libc/libthread these interfaces provided _sigon/_sigoff (unlike
 *	lwp/libthread that provided signal blocking via bind_guard/bind_clear).
 *
 * TI_VERSION == 2
 *	Under this model only libthreads bind_guard/bind_clear and thr_self
 *	interfaces were used.  Both libthreads blocked signals under the
 *	bind_guard/bind_clear interfaces.   Lower level locking is derived
 *	from internally bound _lwp_ interfaces.  This removes recursive
 *	problems encountered when obtaining locking interfaces from libthread.
 *	The use of mutexes over reader/writer locks also enables the use of
 *	condition variables for controlling thread concurrency (allows access
 *	to objects only after their .init has completed).
 *
 * NOTE, the TI_VERSION indicated the ti_interface version number, where the
 * ti_interface was a large vector of functions passed to both libc (to override
 * the thread stub interfaces) and ld.so.1.  ld.so.1 used only a small subset of
 * these interfaces.
 *
 * CI_VERSION == 1
 *	Introduced with CI_VERSION & CI_ATEXIT
 *
 * CI_VERSION == 2 (Solaris 8 update 2).
 *	Added support for CI_LCMESSAGES
 *
 * CI_VERSION == 3 (Solaris 9).
 *	Added the following versions to the CI table:
 *
 *		CI_BIND_GUARD, CI_BIND_CLEAR, CI_THR_SELF
 *		CI_TLS_MODADD, CI_TLS_MOD_REMOVE, CI_TLS_STATMOD
 *
 *	This version introduced the DT_SUNW_RTLDINFO structure as a mechanism
 *	to handshake with ld.so.1.
 *
 * CI_VERSION == 4 (Solaris 10).
 *	Added the CI_THRINIT handshake as part of the libc/libthread unified
 *	process model.  libc now initializes the current thread pointer from
 *	this interface (and no longer relies on the INITFIRST flag - which
 *	others have started to camp out on).
 *
 * CI_VERSION == 5 (Solaris 11).
 *	Use of "protected" references within libc, so that symbols are
 *	pre-bound, and don't require ld.so.1 binding.  This implementation
 *	protects libc's critical regions from being vectored to auditors.
 *
 * CI_VERSION == 6 (Solaris 11).
 *	Added the CI_CRITICAL handshake, to allow "mem*" family to be reexposed
 *	as "global", and thus be redirected to auxiliary filters.
 *
 * Release summary:
 *
 *	Solaris 8	CI_ATEXIT via _ld_libc()
 *			TI_* via _ld_concurrency()
 *
 *	Solaris 9	CI_ATEXIT and CI_LCMESSAGES via _ld_libc()
 *			CI_* via RTLDINFO and _ld_libc()  - new libthread
 *			TI_* via _ld_concurrency()  - old libthread
 *
 *	Solaris 10	CI_ATEXIT and CI_LCMESSAGES via _ld_libc()
 *			CI_* via RTLDINFO and _ld_libc()  - new libthread
 */

#include <sys/debug.h>
#include <synch.h>
#include <signal.h>
#include <thread.h>
#include <synch.h>
#include <strings.h>
#include <stdio.h>
#include <debug.h>
#include <libc_int.h>
#include "_elf.h"
#include "_rtld.h"

/*
 * This interface provides the unified process model communication between
 * ld.so.1 and libc.  This interface can be called a number of times:
 *
 *   -	Initially, this interface is called to process RTLDINFO.  This data
 *	structure is typically provided by libc, and contains the address of
 *	libc interfaces that must be called to initialize threads information.
 *
 *   -	_ld_libc(), this interface can also be called by libc at process
 *	initialization, after libc has been loaded and relocated, but before
 *	control has been passed to any user code (.init's or main()).  This
 *	call provides additional libc interface information that ld.so.1 must
 *	call during process execution.
 *
 *   -	_ld_libc() can also be called by libc during process execution to
 * 	re-establish interfaces such as the locale.
 */
static void
get_lcinterface(Rt_map *lmp, Lc_interface *funcs)
{
	int		threaded = 0, entry = 0, tag;
	Lm_list		*lml;
	Lc_desc		*lcp;

	if ((lmp == NULL) || (funcs == NULL))
		return;

	/*
	 * Once the process is active, ensure we grab a lock.
	 */
	if (rtld_flags & RT_FL_APPLIC)
		entry = enter(0);

	lml = LIST(lmp);
	lcp = &lml->lm_lcs[0];

	DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));

	for (tag = funcs->ci_tag; tag; tag = (++funcs)->ci_tag) {
		char	*gptr;
		char	*lptr = funcs->ci_un.ci_ptr;

		DBG_CALL(Dbg_util_lcinterface(lmp, tag, lptr));

		if (tag >= CI_MAX)
			continue;

		/*
		 * Maintain all interfaces on a per-link-map basis.  Note, for
		 * most interfaces, only the first interface is used for any
		 * link-map list.  This prevents accidents with developers who
		 * manage to load two different versions of libc.
		 */
		if ((lcp[tag].lc_lmp) &&
		    (tag != CI_LCMESSAGES) && (tag != CI_VERSION)) {
			DBG_CALL(Dbg_unused_lcinterface(lmp,
			    lcp[tag].lc_lmp, tag));
			continue;
		}

		lcp[tag].lc_un.lc_ptr = lptr;
		lcp[tag].lc_lmp = lmp;

		gptr = glcs[tag].lc_un.lc_ptr;

		/*
		 * Process any interfaces that must be maintained on a global
		 * basis.
		 */
		switch (tag) {
		case CI_ATEXIT:
			break;

		case CI_LCMESSAGES:
			/*
			 * At startup, ld.so.1 can establish a locale from one
			 * of the locale family of environment variables (see
			 * ld_str_env() and readenv_user()).  During process
			 * execution the locale can also be changed by the user.
			 * This interface is called from libc should the locale
			 * be modified.  Presently, only one global locale is
			 * maintained for all link-map lists, and only objects
			 * on the primrary link-map may change this locale.
			 */
			if ((lml->lm_flags & LML_FLG_BASELM) &&
			    ((gptr == NULL) || (strcmp(gptr, lptr) != 0))) {
				/*
				 * If we've obtained a message locale (typically
				 * supplied via libc's setlocale()), then
				 * register the locale for use in dgettext() so
				 * as to reestablish the locale for ld.so.1's
				 * messages.
				 */
				if (gptr) {
					free((void *)gptr);
					rtld_flags |= RT_FL_NEWLOCALE;
				}
				glcs[tag].lc_un.lc_ptr = strdup(lptr);

				/*
				 * Clear any cached messages.
				 */
				bzero(err_strs, sizeof (err_strs));
				nosym_str = NULL;
			}
			break;

		case CI_BIND_GUARD:
		case CI_BIND_CLEAR:
		case CI_THR_SELF:
		case CI_CRITICAL:
			/*
			 * If the global vector is unset, or this is the primary
			 * link-map, set the global vector.
			 */
			if ((gptr == NULL) || (lml->lm_flags & LML_FLG_BASELM))
				glcs[tag].lc_un.lc_ptr = lptr;

			/* FALLTHROUGH */

		case CI_TLS_MODADD:
		case CI_TLS_MODREM:
		case CI_TLS_STATMOD:
		case CI_THRINIT:
			threaded++;
			break;

		case CI_VERSION:
			if ((rtld_flags2 & RT_FL2_RTLDSEEN) == 0) {
				Aliste	idx;
				Lm_list	*lml2;
				int	version;

				rtld_flags2 |= RT_FL2_RTLDSEEN;

				version = funcs->ci_un.ci_val;
#if defined(CI_V_FIVE)
				if (version >= CI_V_FIVE) {
					thr_flg_nolock = THR_FLG_NOLOCK;
					thr_flg_reenter = THR_FLG_REENTER;
				}
#endif
				if (version < CI_V_FOUR)
					break;

				rtld_flags2 |= RT_FL2_UNIFPROC;

				/*
				 * We might have seen an auditor which is not
				 * dependent on libc.  Such an auditor's link
				 * map list has LML_FLG_HOLDLOCK set.  This
				 * lock needs to be dropped.  Refer to
				 * audit_setup() in audit.c.
				 */
				if ((rtld_flags2 & RT_FL2_HASAUDIT) == 0)
					break;

				/*
				 * Yes, we did.  Take care of them.
				 */
				for (APLIST_TRAVERSE(dynlm_list, idx, lml2)) {
					Rt_map *map = (Rt_map *)lml2->lm_head;

					if (FLAGS(map) & FLG_RT_AUDIT) {
						lml2->lm_flags &=
						    ~LML_FLG_HOLDLOCK;
					}
				}
			}
			break;

		default:
			break;
		}
	}

	if (threaded) {
		/*
		 * If a version of libc gives us only a subset of the TLS
		 * interfaces, it's confused and we discard the whole lot.
		 */
		if ((lcp[CI_TLS_MODADD].lc_un.lc_func &&
		    lcp[CI_TLS_MODREM].lc_un.lc_func &&
		    lcp[CI_TLS_STATMOD].lc_un.lc_func) == NULL) {
			lcp[CI_TLS_MODADD].lc_un.lc_func = NULL;
			lcp[CI_TLS_MODREM].lc_un.lc_func = NULL;
			lcp[CI_TLS_STATMOD].lc_un.lc_func = NULL;
		}

		/*
		 * Indicate that we're now thread capable.
		 */
		if ((lml->lm_flags & LML_FLG_RTLDLM) == 0)
			rtld_flags |= RT_FL_THREADS;
	}

	if (entry)
		leave(lml, 0);
}

/*
 * At this point we know we have a set of objects that have been fully analyzed
 * and relocated.  Prior to the next major step of running .init sections (ie.
 * running user code), retrieve any RTLDINFO interfaces.
 */
int
rt_get_extern(Lm_list *lml, Rt_map *lmp)
{
	if (lml->lm_rti) {
		Aliste		idx;
		Rti_desc	*rti;

		for (ALIST_TRAVERSE(lml->lm_rti, idx, rti))
			get_lcinterface(rti->rti_lmp, rti->rti_info);

		free(lml->lm_rti);
		lml->lm_rti = 0;
	}

	/*
	 * Perform some sanity checks.  If we have TLS requirements we better
	 * have the associated external interfaces.
	 */
	if (lml->lm_tls &&
	    (lml->lm_lcs[CI_TLS_STATMOD].lc_un.lc_func == NULL)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_TLS_NOSUPPORT),
		    NAME(lmp));
		return (0);
	}
	return (1);
}

/*
 * Provide an interface for libc to communicate additional interface
 * information.
 */
void
_ld_libc(void *ptr)
{
	get_lcinterface(_caller(caller(), CL_EXECDEF), (Lc_interface *)ptr);
}

static int	bindmask = 0;

int
rt_bind_guard(int flags)
{
	int	(*fptr)(int);
	int	bindflag;

	if ((fptr = glcs[CI_BIND_GUARD].lc_un.lc_func) != NULL) {
		return ((*fptr)(flags));
	} else {
		bindflag = (flags & THR_FLG_RTLD);
		if ((bindflag & bindmask) == 0) {
			bindmask |= bindflag;
			return (1);
		}
		return (0);
	}
}

int
rt_bind_clear(int flags)
{
	int	(*fptr)(int);
	int	bindflag;

	if ((fptr = glcs[CI_BIND_CLEAR].lc_un.lc_func) != NULL) {
		return ((*fptr)(flags));
	} else {
		bindflag = (flags & THR_FLG_RTLD);
		if (bindflag == 0)
			return (bindmask);
		else {
			bindmask &= ~bindflag;
			return (0);
		}
	}
}

/*
 * Make sure threads have been initialized.  This interface is called once for
 * each link-map list.
 */
void
rt_thr_init(Lm_list *lml)
{
	void	(*fptr)(void);

	if ((fptr =
	    (void (*)())lml->lm_lcs[CI_THRINIT].lc_un.lc_func) != NULL) {
		lml->lm_lcs[CI_THRINIT].lc_un.lc_func = NULL;

		leave(lml, thr_flg_reenter);
		(*fptr)();
		(void) enter(thr_flg_reenter);

		/*
		 * If this is an alternative link-map list, and this is the
		 * first call to initialize threads, don't let the destination
		 * libc be deleted.  It is possible that an auditors complete
		 * initialization fails, but there is presently no main link-map
		 * list.  As this libc has established the thread pointer, don't
		 * delete this libc, otherwise the initialization of libc on the
		 * main link-map can be compromised during its threads
		 * initialization.
		 */
		if (((lml->lm_flags & LML_FLG_BASELM) == 0) &&
		    ((rtld_flags2 & RT_FL2_PLMSETUP) == 0))
			MODE(lml->lm_lcs[CI_THRINIT].lc_lmp) |= RTLD_NODELETE;
	}
}

thread_t
rt_thr_self()
{
	thread_t	(*fptr)(void);

	if ((fptr = (thread_t (*)())glcs[CI_THR_SELF].lc_un.lc_func) != NULL)
		return ((*fptr)());

	return (1);
}

int
rt_mutex_lock(Rt_lock *mp)
{
	return (_lwp_mutex_lock((lwp_mutex_t *)mp));
}

int
rt_mutex_unlock(Rt_lock *mp)
{
	return (_lwp_mutex_unlock((lwp_mutex_t *)mp));
}

/*
 * Test whether we're in a libc critical region.  Certain function references,
 * like the "mem*" family, might require binding.  Although these functions can
 * safely bind to auxiliary filtees, they should not be captured by auditors.
 */
int
rt_critical()
{
	int	(*fptr)(void);

	if ((fptr = glcs[CI_CRITICAL].lc_un.lc_func) != NULL)
		return ((*fptr)());

	return (0);
}

/*
 * Mutex interfaces to resolve references from any objects extracted from
 * libc_pic.a.  Note, as ld.so.1 is essentially single threaded these can be
 * noops.
 */
#pragma weak lmutex_lock = mutex_lock
/* ARGSUSED */
int
mutex_lock(mutex_t *mp)
{
	return (0);
}

#pragma weak lmutex_unlock = mutex_unlock
/* ARGSUSED */
int
mutex_unlock(mutex_t *mp)
{
	return (0);
}

/* ARGSUSED */
int
mutex_init(mutex_t *mp, int type, void *arg)
{
	return (0);
}

/* ARGSUSED */
int
mutex_destroy(mutex_t *mp)
{
	return (0);
}

/*
 * This is needed to satisfy sysconf() (case _SC_THREAD_STACK_MIN)
 */
size_t
thr_min_stack()
{
	return (sizeof (uintptr_t) * 1024);
}

/*
 * Local str[n]casecmp() interfaces for the dynamic linker,
 * to avoid problems when linking with libc_pic.a
 */
int
strcasecmp(const char *s1, const char *s2)
{
	extern int ascii_strcasecmp(const char *, const char *);

	return (ascii_strcasecmp(s1, s2));
}

int
strncasecmp(const char *s1, const char *s2, size_t n)
{
	extern int ascii_strncasecmp(const char *, const char *, size_t);

	return (ascii_strncasecmp(s1, s2, n));
}

/*
 * The following functions are cancellation points in libc.
 * They are called from other functions in libc that we extract
 * and use directly.  We don't do cancellation while we are in
 * the dynamic linker, so we redefine these to call the primitive,
 * non-cancellation interfaces.
 */
int
close(int fildes)
{
	extern int __close(int);

	return (__close(fildes));
}

int
fcntl(int fildes, int cmd, ...)
{
	extern int __fcntl(int, int, ...);
	intptr_t arg;
	va_list ap;

	va_start(ap, cmd);
	arg = va_arg(ap, intptr_t);
	va_end(ap);
	return (__fcntl(fildes, cmd, arg));
}

int
open(const char *path, int oflag, ...)
{
	extern int __open(const char *, int, mode_t);
	mode_t mode;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	return (__open(path, oflag, mode));
}

int
openat(int fd, const char *path, int oflag, ...)
{
	extern int __openat(int, const char *, int, mode_t);
	mode_t mode;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	return (__openat(fd, path, oflag, mode));
}

ssize_t
read(int fd, void *buf, size_t size)
{
	extern ssize_t __read(int, void *, size_t);
	return (__read(fd, buf, size));
}

ssize_t
write(int fd, const void *buf, size_t size)
{
	extern ssize_t __write(int, const void *, size_t);
	return (__write(fd, buf, size));
}

/*
 * ASCII versions of ctype character classification functions.  This avoids
 * pulling in the entire locale framework that is in libc.
 */

int
isdigit(int c)
{
	return ((c >= '0' && c <= '9') ? 1 : 0);
}

int
isupper(int c)
{
	return ((c >= 'A' && c <= 'Z') ? 1 : 0);
}

int
islower(int c)
{
	return ((c >= 'a' && c <= 'z') ? 1 : 0);
}

int
isspace(int c)
{
	return (((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n') ||
	    (c == '\v') || (c == '\f')) ? 1 : 0);
}

int
isxdigit(int c)
{
	return ((isdigit(c) || (c >= 'A' && c <= 'F') ||
	    (c >= 'a' && c <= 'f')) ? 1 : 0);
}

int
isalpha(int c)
{
	return ((isupper(c) || islower(c)) ? 1 : 0);
}

int
isalnum(int c)
{
	return ((isalpha(c) || isdigit(c)) ? 1 : 0);
}
