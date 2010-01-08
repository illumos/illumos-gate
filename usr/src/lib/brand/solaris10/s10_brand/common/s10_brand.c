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

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <thread.h>
#include <sys/auxv.h>
#include <sys/brand.h>
#include <sys/inttypes.h>
#include <sys/lwp.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/zone.h>
#include <sys/stat.h>
#include <sys/mntent.h>
#include <sys/ctfs.h>
#include <sys/priv.h>
#include <sys/acctctl.h>
#include <libgen.h>
#include <bsm/audit.h>
#include <sys/crypto/ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/ucontext.h>
#include <sys/mntio.h>
#include <sys/mnttab.h>
#include <sys/attr.h>
#include <atomic.h>

#include <s10_brand.h>
#include <s10_misc.h>

/*
 * Principles of emulation 101.
 *
 *
 * *** Setting errno
 *
 * Just don't do it.  This emulation library is loaded onto a
 * seperate link map from the application who's address space we're
 * running in.  We have our own private copy of libc, so there for,
 * the errno value accessible from here is is also private and changing
 * it will not affect any errno value that the processes who's address
 * space we are running in will see.  To return an error condition we
 * should return the negated errno value we'd like the system to return.
 * For more information about this see the comment in s10_handler().
 * Basically, when we return to the caller that initiated the system
 * call it's their responsibility to set errno.
 *
 *
 * *** Recursion Considerations
 *
 * When emulating system calls we need to be very careful about what
 * library calls we invoke.  Library calls should be kept to a minimum.
 * One issue is that library calls can invoke system calls, so if we're
 * emulating a system call and we invoke a library call that depends on
 * that system call we will probably enter a recursive loop, which would
 * be bad.
 *
 *
 * *** Return Values.
 *
 * When declaring new syscall emulation functions, it is very important
 * to to set the proper RV_* flags in the s10_sysent_table.  Upon failure,
 * syscall emulation fuctions should return an errno value.  Upon success
 * syscall emulation functions should return 0 and set the sysret_t return
 * value parameters accordingly.
 *
 * There are five possible syscall macro wrappers used in the kernel's system
 * call sysent table.  These turn into the following return values:
 *	SYSENT_CL	-> SYSENT_C or SYSENT_CI
 *	SYSENT_C	SE_64RVAL		RV_DEFAULT
 *	SYSENT_CI	SE_32RVAL1		RV_DEFAULT
 *	SYSENT_2CI	SE_32RVAL1|SE_32RVAL2	RV_32RVAL2
 *	SYSENT_AP	SE_64RVAL		RV_64RVAL
 *
 *
 * *** Agent lwp considerations
 *
 * It is currently impossible to do any emulation for these system call
 * when they are being invoked on behalf of an agent lwp.  To understand why
 * it's impossible you have to understand how agent lwp syscalls work.
 *
 * The agent lwp syscall process works as follows:
 *   1  The controlling process stops the target.
 *   2  The controlling process injects an agent lwp which is also stopped.
 *      This agent lwp assumes the userland stack and register values
 *      of another stopped lwp in the current process.
 *   3  The controlling process configures the agent lwp to start
 *      executing the requested system call.
 *   4  The controlling process configure /proc to stop the agent lwp when
 *      it enters the requested system call.
 *   5  The controlling processes allows the agent lwp to start executing.
 *   6  The agent lwp traps into the kernel to perform the requested system
 *      call and immediately stop.
 *   7  The controlling process copies all the arguments for the requested
 *      system call onto the agent lwp's stack.
 *   8  The controlling process configures /proc to stop the agent lwp
 *      when it completes the requested system call.
 *   9  The controlling processes allows the agent lwp to start executing.
 *  10  The agent lwp executes the system call and then stop before returning
 *      to userland.
 *  11  The controlling process copies the return value and return arguments
 *      back from the agent lwps stack.
 *  12  The controlling process destroys the agent lwp and restarts
 *      the target process.
 *
 * The fundamental problem is that when the agent executes the request
 * system call in step 5, if we're emulating that system call then the
 * lwp is redirected back to our emulation layer without blocking
 * in the kernel.  But our emulation layer can't access the arguments
 * for the system call because they haven't been copied to the stack
 * yet and they still only exist in the controlling processes address
 * space.  This prevents us from being able to do any emulation of
 * agent lwp system calls.  Hence, currently our brand trap interposition
 * callback (s10_brand_syscall_callback_common) will detect if a system
 * call is being made by an agent lwp, and if this is the case it will
 * never redirect the system call to this emulation library.
 *
 * In the future, if this proves to be a problem the the easiest solution
 * would probably be to replace the branded versions of these application
 * with their native counterparts.  Ie,  truss, plimit, and pfiles could be
 * replace with wrapper scripts that execute the native versions of these
 * applications.  In the case of plimit and pfiles this should be pretty
 * strait forward.  Truss would probably be more tricky since it can
 * execute applications which would be branded applications, so in that
 * case it might be necessary to create a loadable library which could
 * be LD_PRELOADed into truss and this library would interpose on the
 * exec() system call to allow truss to correctly execute branded
 * processes.  It should be pointed out that this solution could work
 * because "native agent lwps" (ie, agent lwps created by native
 * processes) can be treated differently from "branded aged lwps" (ie,
 * agent lwps created by branded processes), since native agent lwps
 * would presumably be making native system calls and hence not need
 * any interposition.
 *
 */

static zoneid_t zoneid;
static boolean_t emul_global_zone = B_FALSE;
static s10_emul_bitmap_t emul_bitmap;
pid_t zone_init_pid;

/*
 * S10_FEATURE_IS_PRESENT is a macro that helps facilitate conditional
 * emulation.  For each constant N defined in the s10_emulated_features
 * enumeration in usr/src/uts/common/brand/solaris10/s10_brand.h,
 * S10_FEATURE_IS_PRESENT(N) is true iff the feature/backport represented by N
 * is present in the Solaris 10 image hosted within the zone.  In other words,
 * S10_FEATURE_IS_PRESENT(N) is true iff the file /usr/lib/brand/solaris10/M,
 * where M is the enum value of N, was present in the zone when the zone booted.
 *
 *
 * *** Sample Usage
 *
 * Suppose that you need to backport a fix to Solaris 10 and there is
 * emulation in place for the fix.  Suppose further that the emulation won't be
 * needed if the fix is backported (i.e., if the fix is present in the hosted
 * Solaris 10 environment, then the brand won't need the emulation).  Then if
 * you add a constant named "S10_FEATURE_X" to the end of the
 * s10_emulated_features enumeration that represents the backported fix and
 * S10_FEATURE_X evaluates to four, then you should create a file named
 * /usr/lib/brand/solaris10/4 as part of your backport.  Additionally, you
 * should retain the aforementioned emulation but modify it so that it's
 * performed only when S10_FEATURE_IS_PRESENT(S10_FEATURE_X) is false.  Thus the
 * emulation function should look something like the following:
 *
 *	static int
 *	my_emul_function(sysret_t *rv, ...)
 *	{
 *		if (S10_FEATURE_IS_PRESENT(S10_FEATURE_X)) {
 *			// Don't emulate
 *			return (__systemcall(rv, ...));
 *		} else {
 *			// Emulate whatever needs to be emulated when the
 *			// backport isn't present in the Solaris 10 image.
 *		}
 *	}
 */
#define	S10_FEATURE_IS_PRESENT(s10_emulated_features_constant)	\
	((emul_bitmap[(s10_emulated_features_constant) >> 3] &	\
	(1 << ((s10_emulated_features_constant) & 0x7))) != 0)

#define	EMULATE(cb, args)	{ (sysent_cb_t)(cb), (args) }
#define	NOSYS			EMULATE(s10_unimpl, (0 | RV_DEFAULT))

typedef long (*sysent_cb_t)();
typedef struct s10_sysent_table {
	sysent_cb_t	st_callc;
	uintptr_t	st_args;
} s10_sysent_table_t;
s10_sysent_table_t s10_sysent_table[];

#define	S10_UTS_RELEASE	"5.10"
#define	S10_UTS_VERSION	"Generic_Virtual"

/*LINTED: static unused*/
static volatile int		s10_abort_err;
/*LINTED: static unused*/
static volatile const char	*s10_abort_msg;
/*LINTED: static unused*/
static volatile const char	*s10_abort_file;
/*LINTED: static unused*/
static volatile int		s10_abort_line;

extern int errno;

/*ARGSUSED*/
void
_s10_abort(int err, const char *msg, const char *file, int line)
{
	sysret_t rval;

	/* Save the error message into convenient globals */
	s10_abort_err = err;
	s10_abort_msg = msg;
	s10_abort_file = file;
	s10_abort_line = line;

	/* kill ourselves */
	abort();

	/* If abort() didn't work, try something stronger. */
	(void) __systemcall(&rval, SYS_lwp_kill + 1024, _lwp_self(), SIGKILL);
}

static int
s10_uucopy(const void *from, void *to, size_t size)
{
	sysret_t rval;

	if (__systemcall(&rval, SYS_uucopy + 1024, from, to, size) != 0)
		return (EFAULT);
	return (0);
}

/*
 * ATTENTION: uucopystr() does NOT ensure that string are null terminated!
 */
static int
s10_uucopystr(const void *from, void *to, size_t size)
{
	sysret_t rval;

	if (__systemcall(&rval, SYS_uucopystr + 1024, from, to, size) != 0)
		return (EFAULT);
	return (0);
}

/*
 * Figures out the PID of init for the zone.  Also returns a boolean
 * indicating whether this process currently has that pid: if so,
 * then at this moment, we are init.
 */
static boolean_t
get_initpid_info(void)
{
	pid_t pid;
	sysret_t rval;
	int err;

	/*
	 * Determine the current process PID and the PID of the zone's init.
	 * We use care not to call getpid() here, because we're not supposed
	 * to call getpid() until after the program is fully linked-- the
	 * first call to getpid() is a signal from the linker to debuggers
	 * that linking has been completed.
	 */
	if ((err = __systemcall(&rval, SYS_brand,
	    B_S10_PIDINFO, &pid, &zone_init_pid)) != 0) {
		s10_abort(err, "Failed to get init's pid");
	}

	/*
	 * Note that we need to be cautious with the pid we get back--
	 * it should not be stashed and used in place of getpid(), since
	 * we might fork(2).  So we keep zone_init_pid and toss the pid
	 * we otherwise got.
	 */
	if (pid == zone_init_pid)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * This function is defined to be NOSYS but it won't be called from the
 * the kernel since the NOSYS system calls are not enabled in the kernel.
 * Thus, the only time this function is called is directly from within the
 * indirect system call path.
 */
/*ARGSUSED*/
static long
s10_unimpl(sysret_t *rv, uintptr_t p1)
{
	sysret_t rval;

	/*
	 * We'd like to print out some kind of error message here like
	 * "unsupported syscall", but we can't because it's not safe to
	 * assume that stderr or STDERR_FILENO actually points to something
	 * that is a terminal, and if we wrote to those files we could
	 * inadvertantly write to some applications open files, which would
	 * be bad.
	 *
	 * Normally, if an application calls an invalid system call
	 * it get a SIGSYS sent to it.  So we'll just go ahead and send
	 * ourselves a signal here.  Note that this is far from ideal since
	 * if the application has registered a signal handler, that signal
	 * handler may recieve a ucontext_t as the third parameter to
	 * indicate the context of the process when the signal was
	 * generated, and in this case that context will not be what the
	 * application is expecting.  Hence, we should probably create a
	 * brandsys() kernel function that can deliver the signal to us
	 * with the correct ucontext_t.
	 */
	(void) __systemcall(&rval, SYS_lwp_kill + 1024, _lwp_self(), SIGSYS);
	return (ENOSYS);
}

#if defined(__sparc) && !defined(__sparcv9)
/*
 * Yuck.  For 32-bit sparc applications, handle indirect system calls.
 * Note that we declare this interface to use the maximum number of
 * system call arguments.  If we recieve a system call that uses less
 * arguments, then the additional arguments will be garbage, but they
 * will also be ignored so that should be ok.
 */
static long
s10_indir(sysret_t *rv, int code,
    uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
    uintptr_t a5, uintptr_t a6, uintptr_t a7)
{
	s10_sysent_table_t *sst = &(s10_sysent_table[code]);

	s10_assert(code < NSYSCALL);
	switch (sst->st_args & NARGS_MASK) {
	case 0:
		return ((sst->st_callc)(rv));
	case 1:
		return ((sst->st_callc)(rv, a0));
	case 2:
		return ((sst->st_callc)(rv, a0, a1));
	case 3:
		return ((sst->st_callc)(rv, a0, a1, a2));
	case 4:
		return ((sst->st_callc)(rv, a0, a1, a2, a3));
	case 5:
		return ((sst->st_callc)(rv, a0, a1, a2, a3, a4));
	case 6:
		return ((sst->st_callc)(rv, rv, a0, a1, a2, a3, a4, a5));
	case 7:
		return ((sst->st_callc)(rv, a0, a1, a2, a3, a4, a5, a6));
	case 8:
		return ((sst->st_callc)(rv, a0, a1, a2, a3, a4, a5, a6, a7));
	}
	s10_abort(0, "invalid entry in s10_sysent_table");
	return (EINVAL);
}
#endif /* __sparc && !__sparcv9 */

/* Free the thread-local storage provided by mntfs_get_mntentbuf(). */
static void
mntfs_free_mntentbuf(void *arg)
{
	struct mntentbuf *embufp = arg;

	if (embufp == NULL)
		return;
	if (embufp->mbuf_emp)
		free(embufp->mbuf_emp);
	if (embufp->mbuf_buf)
		free(embufp->mbuf_buf);
	bzero(embufp, sizeof (struct mntentbuf));
	free(embufp);
}

/* Provide the thread-local storage required by mntfs_ioctl(). */
static struct mntentbuf *
mntfs_get_mntentbuf(size_t size)
{
	static mutex_t keylock;
	static thread_key_t key;
	static int once_per_keyname = 0;
	void *tsd = NULL;
	struct mntentbuf *embufp;

	/* Create the key. */
	if (!once_per_keyname) {
		(void) mutex_lock(&keylock);
		if (!once_per_keyname) {
			if (thr_keycreate(&key, mntfs_free_mntentbuf)) {
				(void) mutex_unlock(&keylock);
				return (NULL);
			} else {
				once_per_keyname++;
			}
		}
		(void) mutex_unlock(&keylock);
	}

	/*
	 * The thread-specific datum for this key is the address of a struct
	 * mntentbuf. If this is the first time here then we allocate the struct
	 * and its contents, and associate its address with the thread; if there
	 * are any problems then we abort.
	 */
	if (thr_getspecific(key, &tsd))
		return (NULL);
	if (tsd == NULL) {
		if (!(embufp = calloc(1, sizeof (struct mntentbuf))) ||
		    !(embufp->mbuf_emp = malloc(sizeof (struct extmnttab))) ||
		    thr_setspecific(key, embufp)) {
			mntfs_free_mntentbuf(embufp);
			return (NULL);
		}
	} else {
		embufp = tsd;
	}

	/* Return the buffer, resizing it if necessary. */
	if (size > embufp->mbuf_bufsize) {
		if (embufp->mbuf_buf)
			free(embufp->mbuf_buf);
		if ((embufp->mbuf_buf = malloc(size)) == NULL) {
			embufp->mbuf_bufsize = 0;
			return (NULL);
		} else {
			embufp->mbuf_bufsize = size;
		}
	}
	return (embufp);
}

/*
 * The MNTIOC_GETMNTENT command in this release differs from that in early
 * versions of Solaris 10.
 *
 * Previously, the command would copy a pointer to a struct extmnttab to an
 * address provided as an argument. The pointer would be somewhere within a
 * mapping already present within the user's address space. In addition, the
 * text to which the struct's members pointed would also be within a
 * pre-existing mapping. Now, the user is required to allocate memory for both
 * the struct and the text buffer, and to pass the address of each within a
 * struct mntentbuf. In order to conceal these details from a Solaris 10 client
 * we allocate some thread-local storage in which to create the necessary data
 * structures; this is static, thread-safe memory that will be cleaned up
 * without the caller's intervention.
 *
 * MNTIOC_GETEXTMNTENT and MNTIOC_GETMNTANY are new in this release; they should
 * not work for older clients.
 */
int
mntfs_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	int err;
	struct stat statbuf;
	struct mntentbuf *embufp;
	static size_t bufsize = MNT_LINE_MAX;


	/* Do not emulate mntfs commands from up-to-date clients. */
	if (S10_FEATURE_IS_PRESENT(S10_FEATURE_ALTERED_MNTFS_IOCTL))
		return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));

	/* Do not emulate mntfs commands directed at other file systems. */
	if ((err = __systemcall(rval, SYS_fstat + 1024, fdes, &statbuf)) != 0)
		return (err);
	if (strcmp(statbuf.st_fstype, MNTTYPE_MNTFS) != 0)
		return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));

	if (cmd == MNTIOC_GETEXTMNTENT || cmd == MNTIOC_GETMNTANY)
		return (EINVAL);

	if ((embufp = mntfs_get_mntentbuf(bufsize)) == NULL)
		return (ENOMEM);

	/*
	 * MNTIOC_GETEXTMNTENT advances the file pointer once it has
	 * successfully copied out the result to the address provided. We
	 * therefore need to check the user-supplied address now since the
	 * one we'll be providing is guaranteed to work.
	 */
	if (s10_uucopy(&embufp->mbuf_emp, (void *)arg, sizeof (void *)) != 0)
		return (EFAULT);

	/*
	 * Keep retrying for as long as we fail for want of a large enough
	 * buffer.
	 */
	for (;;) {
		if ((err = __systemcall(rval, SYS_ioctl + 1024, fdes,
		    MNTIOC_GETEXTMNTENT, embufp)) != 0)
			return (err);

		if (rval->sys_rval1 == MNTFS_TOOLONG) {
			/* The buffer wasn't large enough. */
			(void) atomic_swap_ulong((unsigned long *)&bufsize,
			    2 * embufp->mbuf_bufsize);
			if ((embufp = mntfs_get_mntentbuf(bufsize)) == NULL)
				return (ENOMEM);
		} else {
			break;
		}
	}

	if (s10_uucopy(&embufp->mbuf_emp, (void *)arg, sizeof (void *)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Assign the structure member value from the s (source) structure to the
 * d (dest) structure.
 */
#define	struct_assign(d, s, val)	(((d).val) = ((s).val))

/*
 * The CRYPTO_GET_FUNCTION_LIST parameter structure crypto_function_list_t
 * changed between S10 and Nevada, so we have to emulate the old S10
 * crypto_function_list_t structure when interposing on the ioctl syscall.
 */
typedef struct s10_crypto_function_list {
	boolean_t fl_digest_init;
	boolean_t fl_digest;
	boolean_t fl_digest_update;
	boolean_t fl_digest_key;
	boolean_t fl_digest_final;

	boolean_t fl_encrypt_init;
	boolean_t fl_encrypt;
	boolean_t fl_encrypt_update;
	boolean_t fl_encrypt_final;

	boolean_t fl_decrypt_init;
	boolean_t fl_decrypt;
	boolean_t fl_decrypt_update;
	boolean_t fl_decrypt_final;

	boolean_t fl_mac_init;
	boolean_t fl_mac;
	boolean_t fl_mac_update;
	boolean_t fl_mac_final;

	boolean_t fl_sign_init;
	boolean_t fl_sign;
	boolean_t fl_sign_update;
	boolean_t fl_sign_final;
	boolean_t fl_sign_recover_init;
	boolean_t fl_sign_recover;

	boolean_t fl_verify_init;
	boolean_t fl_verify;
	boolean_t fl_verify_update;
	boolean_t fl_verify_final;
	boolean_t fl_verify_recover_init;
	boolean_t fl_verify_recover;

	boolean_t fl_digest_encrypt_update;
	boolean_t fl_decrypt_digest_update;
	boolean_t fl_sign_encrypt_update;
	boolean_t fl_decrypt_verify_update;

	boolean_t fl_seed_random;
	boolean_t fl_generate_random;

	boolean_t fl_session_open;
	boolean_t fl_session_close;
	boolean_t fl_session_login;
	boolean_t fl_session_logout;

	boolean_t fl_object_create;
	boolean_t fl_object_copy;
	boolean_t fl_object_destroy;
	boolean_t fl_object_get_size;
	boolean_t fl_object_get_attribute_value;
	boolean_t fl_object_set_attribute_value;
	boolean_t fl_object_find_init;
	boolean_t fl_object_find;
	boolean_t fl_object_find_final;

	boolean_t fl_key_generate;
	boolean_t fl_key_generate_pair;
	boolean_t fl_key_wrap;
	boolean_t fl_key_unwrap;
	boolean_t fl_key_derive;

	boolean_t fl_init_token;
	boolean_t fl_init_pin;
	boolean_t fl_set_pin;

	boolean_t prov_is_hash_limited;
	uint32_t prov_hash_threshold;
	uint32_t prov_hash_limit;
} s10_crypto_function_list_t;

typedef struct s10_crypto_get_function_list {
	uint_t				fl_return_value;
	crypto_provider_id_t		fl_provider_id;
	s10_crypto_function_list_t	fl_list;
} s10_crypto_get_function_list_t;

/*
 * The structure returned by the CRYPTO_GET_FUNCTION_LIST ioctl on /dev/crypto
 * increased in size due to:
 *	6482533 Threshold for HW offload via PKCS11 interface
 * between S10 and Nevada.  This is a relatively simple process of filling
 * in the S10 structure fields with the Nevada data.
 *
 * We stat the device to make sure that the ioctl is meant for /dev/crypto.
 *
 */
static int
crypto_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	int				err;
	s10_crypto_get_function_list_t	s10_param;
	crypto_get_function_list_t	native_param;
	static dev_t			crypto_dev = (dev_t)-1;
	struct stat			sbuf;

	if (crypto_dev == (dev_t)-1) {
		if ((err = __systemcall(rval, SYS_stat + 1024, "/dev/crypto",
		    &sbuf)) != 0)
			goto nonemuioctl;
		crypto_dev = major(sbuf.st_rdev);
	}
	if ((err = __systemcall(rval, SYS_fstat + 1024, fdes, &sbuf)) != 0)
		return (err);
	/* Each open fd of /dev/crypto gets a new minor device. */
	if (major(sbuf.st_rdev) != crypto_dev)
		goto nonemuioctl;

	if (s10_uucopy((const void *)arg, &s10_param, sizeof (s10_param)) != 0)
		return (EFAULT);
	struct_assign(native_param, s10_param, fl_provider_id);
	if ((err = __systemcall(rval, SYS_ioctl + 1024, fdes, cmd,
	    &native_param)) != 0)
		return (err);

	struct_assign(s10_param, native_param, fl_return_value);
	struct_assign(s10_param, native_param, fl_provider_id);

	struct_assign(s10_param, native_param, fl_list.fl_digest_init);
	struct_assign(s10_param, native_param, fl_list.fl_digest);
	struct_assign(s10_param, native_param, fl_list.fl_digest_update);
	struct_assign(s10_param, native_param, fl_list.fl_digest_key);
	struct_assign(s10_param, native_param, fl_list.fl_digest_final);

	struct_assign(s10_param, native_param, fl_list.fl_encrypt_init);
	struct_assign(s10_param, native_param, fl_list.fl_encrypt);
	struct_assign(s10_param, native_param, fl_list.fl_encrypt_update);
	struct_assign(s10_param, native_param, fl_list.fl_encrypt_final);

	struct_assign(s10_param, native_param, fl_list.fl_decrypt_init);
	struct_assign(s10_param, native_param, fl_list.fl_decrypt);
	struct_assign(s10_param, native_param, fl_list.fl_decrypt_update);
	struct_assign(s10_param, native_param, fl_list.fl_decrypt_final);

	struct_assign(s10_param, native_param, fl_list.fl_mac_init);
	struct_assign(s10_param, native_param, fl_list.fl_mac);
	struct_assign(s10_param, native_param, fl_list.fl_mac_update);
	struct_assign(s10_param, native_param, fl_list.fl_mac_final);

	struct_assign(s10_param, native_param, fl_list.fl_sign_init);
	struct_assign(s10_param, native_param, fl_list.fl_sign);
	struct_assign(s10_param, native_param, fl_list.fl_sign_update);
	struct_assign(s10_param, native_param, fl_list.fl_sign_final);
	struct_assign(s10_param, native_param, fl_list.fl_sign_recover_init);
	struct_assign(s10_param, native_param, fl_list.fl_sign_recover);

	struct_assign(s10_param, native_param, fl_list.fl_verify_init);
	struct_assign(s10_param, native_param, fl_list.fl_verify);
	struct_assign(s10_param, native_param, fl_list.fl_verify_update);
	struct_assign(s10_param, native_param, fl_list.fl_verify_final);
	struct_assign(s10_param, native_param, fl_list.fl_verify_recover_init);
	struct_assign(s10_param, native_param, fl_list.fl_verify_recover);

	struct_assign(s10_param, native_param,
	    fl_list.fl_digest_encrypt_update);
	struct_assign(s10_param, native_param,
	    fl_list.fl_decrypt_digest_update);
	struct_assign(s10_param, native_param, fl_list.fl_sign_encrypt_update);
	struct_assign(s10_param, native_param,
	    fl_list.fl_decrypt_verify_update);

	struct_assign(s10_param, native_param, fl_list.fl_seed_random);
	struct_assign(s10_param, native_param, fl_list.fl_generate_random);

	struct_assign(s10_param, native_param, fl_list.fl_session_open);
	struct_assign(s10_param, native_param, fl_list.fl_session_close);
	struct_assign(s10_param, native_param, fl_list.fl_session_login);
	struct_assign(s10_param, native_param, fl_list.fl_session_logout);

	struct_assign(s10_param, native_param, fl_list.fl_object_create);
	struct_assign(s10_param, native_param, fl_list.fl_object_copy);
	struct_assign(s10_param, native_param, fl_list.fl_object_destroy);
	struct_assign(s10_param, native_param, fl_list.fl_object_get_size);
	struct_assign(s10_param, native_param,
	    fl_list.fl_object_get_attribute_value);
	struct_assign(s10_param, native_param,
	    fl_list.fl_object_set_attribute_value);
	struct_assign(s10_param, native_param, fl_list.fl_object_find_init);
	struct_assign(s10_param, native_param, fl_list.fl_object_find);
	struct_assign(s10_param, native_param, fl_list.fl_object_find_final);

	struct_assign(s10_param, native_param, fl_list.fl_key_generate);
	struct_assign(s10_param, native_param, fl_list.fl_key_generate_pair);
	struct_assign(s10_param, native_param, fl_list.fl_key_wrap);
	struct_assign(s10_param, native_param, fl_list.fl_key_unwrap);
	struct_assign(s10_param, native_param, fl_list.fl_key_derive);

	struct_assign(s10_param, native_param, fl_list.fl_init_token);
	struct_assign(s10_param, native_param, fl_list.fl_init_pin);
	struct_assign(s10_param, native_param, fl_list.fl_set_pin);

	struct_assign(s10_param, native_param, fl_list.prov_is_hash_limited);
	struct_assign(s10_param, native_param, fl_list.prov_hash_threshold);
	struct_assign(s10_param, native_param, fl_list.prov_hash_limit);

	return (s10_uucopy(&s10_param, (void *)arg, sizeof (s10_param)));

nonemuioctl:
	return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));
}

/*
 * The process contract CT_TGET and CT_TSET parameter structure ct_param_t
 * changed between S10 and Nevada, so we have to emulate the old S10
 * ct_param_t structure when interposing on the ioctl syscall.
 */
typedef struct s10_ct_param {
	uint32_t ctpm_id;
	uint32_t ctpm_pad;
	uint64_t ctpm_value;
} s10_ct_param_t;

/*
 * We have to emulate process contract ioctls for init(1M) because the
 * ioctl parameter structure changed between S10 and Nevada.  This is
 * a relatively simple process of filling Nevada structure fields,
 * shuffling values, and initiating a native system call.
 *
 * For now, we'll assume that all consumers of CT_TGET and CT_TSET will
 * need emulation.  We'll issue a stat to make sure that the ioctl
 * is meant for the contract file system.
 *
 */
static int
ctfs_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	int err;
	s10_ct_param_t s10param;
	ct_param_t param;
	struct stat statbuf;

	if ((err = __systemcall(rval, SYS_fstat + 1024, fdes, &statbuf)) != 0)
		return (err);
	if (strcmp(statbuf.st_fstype, MNTTYPE_CTFS) != 0)
		return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));

	if (s10_uucopy((const void *)arg, &s10param, sizeof (s10param)) != 0)
		return (EFAULT);
	param.ctpm_id = s10param.ctpm_id;
	param.ctpm_size = sizeof (uint64_t);
	param.ctpm_value = &s10param.ctpm_value;
	if ((err = __systemcall(rval, SYS_ioctl + 1024, fdes, cmd, &param))
	    != 0)
		return (err);

	if (cmd == CT_TGET)
		return (s10_uucopy(&s10param, (void *)arg, sizeof (s10param)));

	return (0);
}

typedef struct s10_zfs_cmd {
	char		zc_name[MAXPATHLEN];
	char		zc_value[MAXPATHLEN * 2];
	char		zc_string[MAXNAMELEN];
	uint64_t	zc_guid;
	uint64_t	zc_nvlist_conf;		/* really (char *) */
	uint64_t	zc_nvlist_conf_size;
	uint64_t	zc_nvlist_src;		/* really (char *) */
	uint64_t	zc_nvlist_src_size;
	uint64_t	zc_nvlist_dst;		/* really (char *) */
	uint64_t	zc_nvlist_dst_size;
	uint64_t	zc_cookie;
	uint64_t	zc_objset_type;
	uint64_t	zc_perm_action;
	uint64_t 	zc_history;		/* really (char *) */
	uint64_t 	zc_history_len;
	uint64_t	zc_history_offset;
	uint64_t	zc_obj;
	/* Solaris Next added zc_iflags member here */
	zfs_share_t	zc_share;
	dmu_objset_stats_t zc_objset_stats;
	struct drr_begin zc_begin_record;
	zinject_record_t zc_inject_record;
} s10_zfs_cmd_t;

/*
 * There is a difference in the zfs_cmd_t ioctl parameter between S10 and
 * Solaris Next so we need to translate between the two structures when
 * making ZFS ioctls.
 */
static int
zfs_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	int				err;
	s10_zfs_cmd_t			s10_param;
	zfs_cmd_t			native_param;
	static dev_t			zfs_dev = (dev_t)-1;
	struct stat			sbuf;

	if (zfs_dev == (dev_t)-1) {
		if ((err = __systemcall(rval, SYS_stat + 1024, "/dev/zfs",
		    &sbuf)) != 0)
			goto nonemuioctl;
		zfs_dev = major(sbuf.st_rdev);
	}
	if ((err = __systemcall(rval, SYS_fstat + 1024, fdes, &sbuf)) != 0)
		return (err);
	if (major(sbuf.st_rdev) != zfs_dev)
		goto nonemuioctl;

	if (s10_uucopy((const void *)arg, &s10_param, sizeof (s10_param)) != 0)
		return (EFAULT);

	bcopy((const void *)s10_param.zc_name, (void *)native_param.zc_name,
	    sizeof (s10_param.zc_name));
	bcopy((const void *)s10_param.zc_value, (void *)native_param.zc_value,
	    sizeof (s10_param.zc_value));
	bcopy((const void *)s10_param.zc_string, (void *)native_param.zc_string,
	    sizeof (s10_param.zc_string));
	struct_assign(native_param, s10_param, zc_guid);
	struct_assign(native_param, s10_param, zc_nvlist_conf);
	struct_assign(native_param, s10_param, zc_nvlist_conf_size);
	struct_assign(native_param, s10_param, zc_nvlist_src);
	struct_assign(native_param, s10_param, zc_nvlist_src_size);
	struct_assign(native_param, s10_param, zc_nvlist_dst);
	struct_assign(native_param, s10_param, zc_nvlist_dst_size);
	struct_assign(native_param, s10_param, zc_cookie);
	struct_assign(native_param, s10_param, zc_objset_type);
	struct_assign(native_param, s10_param, zc_perm_action);
	struct_assign(native_param, s10_param, zc_history);
	struct_assign(native_param, s10_param, zc_history_len);
	struct_assign(native_param, s10_param, zc_history_offset);
	struct_assign(native_param, s10_param, zc_obj);
	native_param.zc_iflags = 0;
	struct_assign(native_param, s10_param, zc_share);
	struct_assign(native_param, s10_param, zc_objset_stats);
	struct_assign(native_param, s10_param, zc_begin_record);
	struct_assign(native_param, s10_param, zc_inject_record);

	err = __systemcall(rval, SYS_ioctl + 1024, fdes, cmd, &native_param);

	bcopy((const void *)native_param.zc_name, (void *)s10_param.zc_name,
	    sizeof (s10_param.zc_name));
	bcopy((const void *)native_param.zc_value, (void *)s10_param.zc_value,
	    sizeof (s10_param.zc_value));
	bcopy((const void *)native_param.zc_string, (void *)s10_param.zc_string,
	    sizeof (s10_param.zc_string));
	struct_assign(s10_param, native_param, zc_guid);
	struct_assign(s10_param, native_param, zc_nvlist_conf);
	struct_assign(s10_param, native_param, zc_nvlist_conf_size);
	struct_assign(s10_param, native_param, zc_nvlist_src);
	struct_assign(s10_param, native_param, zc_nvlist_src_size);
	struct_assign(s10_param, native_param, zc_nvlist_dst);
	struct_assign(s10_param, native_param, zc_nvlist_dst_size);
	struct_assign(s10_param, native_param, zc_cookie);
	struct_assign(s10_param, native_param, zc_objset_type);
	struct_assign(s10_param, native_param, zc_perm_action);
	struct_assign(s10_param, native_param, zc_history);
	struct_assign(s10_param, native_param, zc_history_len);
	struct_assign(s10_param, native_param, zc_history_offset);
	struct_assign(s10_param, native_param, zc_obj);
	struct_assign(s10_param, native_param, zc_share);
	struct_assign(s10_param, native_param, zc_objset_stats);
	struct_assign(s10_param, native_param, zc_begin_record);
	struct_assign(s10_param, native_param, zc_inject_record);

	(void) s10_uucopy(&s10_param, (void *)arg, sizeof (s10_param));
	return (err);

nonemuioctl:
	return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));
}

int
s10_ioctl(sysret_t *rval, int fdes, int cmd, intptr_t arg)
{
	switch (cmd) {
	case CRYPTO_GET_FUNCTION_LIST:
		return (crypto_ioctl(rval, fdes, cmd, arg));
	case CT_TGET:
		/*FALLTHRU*/
	case CT_TSET:
		return (ctfs_ioctl(rval, fdes, cmd, arg));
	case MNTIOC_GETMNTENT:
		/*FALLTHRU*/
	case MNTIOC_GETEXTMNTENT:
		/*FALLTHRU*/
	case MNTIOC_GETMNTANY:
		return (mntfs_ioctl(rval, fdes, cmd, arg));
	}

	if ((cmd & 0xff00) == ZFS_IOC)
		return (zfs_ioctl(rval, fdes, cmd, arg));

	return (__systemcall(rval, SYS_ioctl + 1024, fdes, cmd, arg));
}

/*
 * Unfortunately, pwrite()'s behavior differs between S10 and Nevada when
 * applied to files opened with O_APPEND.  The offset argument is ignored and
 * the buffer is appended to the target file in S10, whereas the current file
 * position is ignored in Nevada (i.e., pwrite() acts as though the target file
 * wasn't opened with O_APPEND).  This is a result of the fix for CR 6655660
 * (pwrite() must ignore the O_APPEND/FAPPEND flag).
 *
 * We emulate the old S10 pwrite() behavior by checking whether the target file
 * was opened with O_APPEND.  If it was, then invoke the write() system call
 * instead of pwrite(); otherwise, invoke the pwrite() system call as usual.
 */
static int
s10_pwrite(sysret_t *rval, int fd, const void *bufferp, size_t num_bytes,
    off_t offset)
{
	int err;

	if ((err = __systemcall(rval, SYS_fcntl + 1024, fd, F_GETFL)) != 0)
		return (err);
	if (rval->sys_rval1 & O_APPEND)
		return (__systemcall(rval, SYS_write + 1024, fd, bufferp,
		    num_bytes));
	return (__systemcall(rval, SYS_pwrite + 1024, fd, bufferp, num_bytes,
	    offset));
}

#ifndef	_LP64
/*
 * This is the large file version of the pwrite() system call for 32-bit
 * processes.  This exists for the same reason that s10_pwrite() exists; see
 * the comment above s10_pwrite().
 */
static int
s10_pwrite64(sysret_t *rval, int fd, const void *bufferp, size32_t num_bytes,
    uint32_t offset_1, uint32_t offset_2)
{
	int err;

	if ((err = __systemcall(rval, SYS_fcntl + 1024, fd, F_GETFL)) != 0)
		return (err);
	if (rval->sys_rval1 & O_APPEND)
		return (__systemcall(rval, SYS_write + 1024, fd, bufferp,
		    num_bytes));
	return (__systemcall(rval, SYS_pwrite64 + 1024, fd, bufferp,
	    num_bytes, offset_1, offset_2));
}
#endif	/* !_LP64 */

/*
 * These are convenience macros that s10_getdents_common() uses.  Both treat
 * their arguments, which should be character pointers, as dirent pointers or
 * dirent64 pointers and yield their d_name and d_reclen fields.  These
 * macros shouldn't be used outside of s10_getdents_common().
 */
#define	dirent_name(charptr)	((charptr) + name_offset)
#define	dirent_reclen(charptr)	\
	(*(unsigned short *)(uintptr_t)((charptr) + reclen_offset))

/*
 * This function contains code that is common to both s10_getdents() and
 * s10_getdents64().  See the comment above s10_getdents() for details.
 *
 * rval, fd, buf, and nbyte should be passed unmodified from s10_getdents()
 * and s10_getdents64().  getdents_syscall_id should be either SYS_getdents
 * or SYS_getdents64.  name_offset should be the the byte offset of
 * the d_name field in the dirent structures passed to the kernel via the
 * syscall represented by getdents_syscall_id.  reclen_offset should be
 * the byte offset of the d_reclen field in the aforementioned dirent
 * structures.
 */
static int
s10_getdents_common(sysret_t *rval, int fd, char *buf, size_t nbyte,
    int getdents_syscall_id, size_t name_offset, size_t reclen_offset)
{
	int err;
	size_t buf_size;
	char *local_buf;
	char *buf_current;

	/*
	 * Use a special brand operation, B_S10_ISFDXATTRDIR, to determine
	 * whether the specified file descriptor refers to an extended file
	 * attribute directory.  If it doesn't, then SYS_getdents won't
	 * reveal extended file attributes, in which case we can simply
	 * hand the syscall to the native kernel.
	 */
	if ((err = __systemcall(rval, SYS_brand + 1024, B_S10_ISFDXATTRDIR,
	    fd)) != 0)
		return (err);
	if (rval->sys_rval1 == 0)
		return (__systemcall(rval, getdents_syscall_id + 1024, fd, buf,
		    nbyte));

	/*
	 * The file descriptor refers to an extended file attributes directory.
	 * We need to create a dirent buffer that's as large as buf into which
	 * the native SYS_getdents will store the special extended file
	 * attribute directory's entries.  We can't dereference buf because
	 * it might be an invalid pointer!
	 */
	if (nbyte > MAXGETDENTS_SIZE)
		nbyte = MAXGETDENTS_SIZE;
	local_buf = (char *)malloc(nbyte);
	if (local_buf == NULL) {
		/*
		 * getdents(2) doesn't return an error code indicating a memory
		 * allocation error and it doesn't make sense to return any of
		 * its documented error codes for a malloc(3C) failure.  We'll
		 * use ENOMEM even though getdents(2) doesn't use it because it
		 * best describes the failure.
		 */
		(void) S10_TRUSS_POINT_3(rval, getdents_syscall_id, ENOMEM, fd,
		    buf, nbyte);
		rval->sys_rval1 = -1;
		rval->sys_rval2 = 0;
		return (EIO);
	}

	/*
	 * Issue a native SYS_getdents syscall but use our local dirent buffer
	 * instead of buf.  This will allow us to examine the returned dirent
	 * structures immediately and copy them to buf later.  That way the
	 * calling process won't be able to see the dirent structures until
	 * we finish examining them.
	 */
	if ((err = __systemcall(rval, getdents_syscall_id + 1024, fd, local_buf,
	    nbyte)) != 0) {
		free(local_buf);
		return (err);
	}
	buf_size = rval->sys_rval1;
	if (buf_size == 0) {
		free(local_buf);
		return (0);
	}

	/*
	 * Look for SUNWattr_ro (VIEW_READONLY) and SUNWattr_rw
	 * (VIEW_READWRITE) in the directory entries and remove them
	 * from the dirent buffer.
	 */
	for (buf_current = local_buf;
	    (size_t)(buf_current - local_buf) < buf_size; /* cstyle */) {
		if (strcmp(dirent_name(buf_current), VIEW_READONLY) != 0 &&
		    strcmp(dirent_name(buf_current), VIEW_READWRITE) != 0) {
			/*
			 * The dirent refers to an attribute that should
			 * be visible to Solaris 10 processes.  Keep it
			 * and examine the next entry in the buffer.
			 */
			buf_current += dirent_reclen(buf_current);
		} else {
			/*
			 * We found either SUNWattr_ro (VIEW_READONLY)
			 * or SUNWattr_rw (VIEW_READWRITE).  Remove it
			 * from the dirent buffer by decrementing
			 * buf_size by the size of the entry and
			 * overwriting the entry with the remaining
			 * entries.
			 */
			buf_size -= dirent_reclen(buf_current);
			(void) memmove(buf_current, buf_current +
			    dirent_reclen(buf_current), buf_size -
			    (size_t)(buf_current - local_buf));
		}
	}

	/*
	 * Copy local_buf into buf so that the calling process can see
	 * the results.
	 */
	if ((err = s10_uucopy(local_buf, buf, buf_size)) != 0) {
		free(local_buf);
		rval->sys_rval1 = -1;
		rval->sys_rval2 = 0;
		return (err);
	}
	rval->sys_rval1 = buf_size;
	free(local_buf);
	return (0);
}

/*
 * Solaris Next added two special extended file attributes, SUNWattr_ro and
 * SUNWattr_rw, which are called "extended system attributes".  They have
 * special semantics (e.g., a process cannot unlink SUNWattr_ro) and should
 * not appear in solaris10-branded zones because no Solaris 10 applications,
 * including system commands such as tar(1), are coded to correctly handle these
 * special attributes.
 *
 * This emulation function solves the aforementioned problem by emulating
 * the getdents(2) syscall and filtering both system attributes out of resulting
 * directory entry lists.  The emulation function only filters results when
 * the given file descriptor refers to an extended file attribute directory.
 * Filtering getdents(2) results is expensive because it requires dynamic
 * memory allocation; however, the performance cost is tolerable because
 * we don't expect Solaris 10 processes to frequently examine extended file
 * attribute directories.
 *
 * The brand's emulation library needs two getdents(2) emulation functions
 * because getdents(2) comes in two flavors: non-largefile-aware getdents(2)
 * and largefile-aware getdents64(2).  s10_getdents() handles the non-largefile-
 * aware case for 32-bit processes and all getdents(2) syscalls for 64-bit
 * processes (64-bit processes use largefile-aware interfaces by default).
 * See s10_getdents64() below for the largefile-aware getdents64(2) emulation
 * function for 32-bit processes.
 */
static int
s10_getdents(sysret_t *rval, int fd, struct dirent *buf, size_t nbyte)
{
	return (s10_getdents_common(rval, fd, (char *)buf, nbyte, SYS_getdents,
	    offsetof(struct dirent, d_name),
	    offsetof(struct dirent, d_reclen)));
}

#ifndef	_LP64
/*
 * This is the largefile-aware version of getdents(2) for 32-bit processes.
 * This exists for the same reason that s10_getdents() exists.  See the comment
 * above s10_getdents().
 */
static int
s10_getdents64(sysret_t *rval, int fd, struct dirent64 *buf, size_t nbyte)
{
	return (s10_getdents_common(rval, fd, (char *)buf, nbyte,
	    SYS_getdents64, offsetof(struct dirent64, d_name),
	    offsetof(struct dirent64, d_reclen)));
}
#endif	/* !_LP64 */

#define	S10_AC_PROC		(0x1 << 28)
#define	S10_AC_TASK		(0x2 << 28)
#define	S10_AC_FLOW		(0x4 << 28)
#define	S10_AC_MODE(x)		((x) & 0xf0000000)
#define	S10_AC_OPTION(x)	((x) & 0x0fffffff)

/*
 * The mode shift, mode mask and option mask for acctctl have changed.  The
 * mode is currently the top full byte and the option is the lower 3 full bytes.
 */
int
s10_acctctl(sysret_t *rval, int cmd, void *buf, size_t bufsz)
{
	int mode = S10_AC_MODE(cmd);
	int option = S10_AC_OPTION(cmd);

	switch (mode) {
	case S10_AC_PROC:
		mode = AC_PROC;
		break;
	case S10_AC_TASK:
		mode = AC_TASK;
		break;
	case S10_AC_FLOW:
		mode = AC_FLOW;
		break;
	default:
		return (S10_TRUSS_POINT_3(rval, SYS_acctctl, EINVAL, cmd, buf,
		    bufsz));
	}

	return (__systemcall(rval, SYS_acctctl + 1024, mode | option, buf,
	    bufsz));
}

/*
 * The Audit Policy parameters have changed due to:
 *    6466722 audituser and AUDIT_USER are defined, unused, undocumented and
 *            should be removed.
 *
 * In S10 we had the following flag:
 *	#define AUDIT_USER 0x0040
 * which doesn't exist in Solaris Next where the subsequent flags are shifted
 * down.  For example, in S10 we had:
 *	#define AUDIT_GROUP     0x0080
 * but on Solaris Next we have:
 *	#define AUDIT_GROUP     0x0040
 * AUDIT_GROUP has the value AUDIT_USER had in S10 and all of the subsequent
 * bits are also shifted one place.
 *
 * When we're getting or setting the Audit Policy parameters we need to
 * shift the outgoing or incoming bits into their proper positions.  Since
 * S10_AUDIT_USER was always unused, we always clear that bit on A_GETPOLICY.
 *
 * The command we care about, BSM_AUDITCTL, passes the most parameters (3),
 * so declare this function to take up to 4 args and just pass them on.
 * The number of parameters for s10_auditsys needs to be equal to the BSM_*
 * subcommand that has the most parameters, since we want to pass all
 * parameters through, regardless of which subcommands we interpose on.
 *
 * Note that the auditsys system call uses the SYSENT_AP macro wrapper instead
 * of the more common SYSENT_CI macro.  This means the return value is a
 * SE_64RVAL so the syscall table uses RV_64RVAL.
 */

#define	S10_AUDIT_HMASK	0xffffffc0
#define	S10_AUDIT_LMASK	0x3f

int
s10_auditsys(sysret_t *rval, int bsmcmd, intptr_t a0, intptr_t a1, intptr_t a2)
{
	int	err;
	uint_t	m;

	if (bsmcmd != BSM_AUDITCTL)
		return (__systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0, a1,
		    a2));

	if ((int)a0 == A_GETPOLICY) {
		if ((err = __systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0,
		    &m, a2)) != 0)
			return (err);
		m = ((m & S10_AUDIT_HMASK) << 1) | (m & S10_AUDIT_LMASK);
		if (s10_uucopy(&m, (void *)a1, sizeof (m)) != 0)
			return (EFAULT);
		return (0);

	} else if ((int)a0 == A_SETPOLICY) {
		if (s10_uucopy((const void *)a1, &m, sizeof (m)) != 0)
			return (EFAULT);
		m = ((m >> 1) & S10_AUDIT_HMASK) | (m & S10_AUDIT_LMASK);
		return (__systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0, &m,
		    a2));
	}

	return (__systemcall(rval, SYS_auditsys + 1024, bsmcmd, a0, a1, a2));
}

/*
 * Determine whether the executable passed to SYS_exec or SYS_execve is a
 * native executable.  The s10_npreload.so invokes the B_S10_NATIVE brand
 * operation which patches up the processes exec info to eliminate any trace
 * of the wrapper.  That will make pgrep and other commands that examine
 * process' executable names and command-line parameters work properly.
 */
static int
s10_exec_native(sysret_t *rval, const char *fname, const char **argp,
    const char **envp)
{
	const char *filename = fname;
	char path[64];
	int err;

	/* Get a copy of the executable we're trying to run */
	path[0] = '\0';
	(void) s10_uucopystr(filename, path, sizeof (path));

	/* Check if we're trying to run a native binary */
	if (strncmp(path, "/.SUNWnative/usr/lib/brand/solaris10/s10_native",
	    sizeof (path)) != 0)
		return (0);

	/* Skip the first element in the argv array */
	argp++;

	/*
	 * The the path of the dynamic linker is the second parameter
	 * of s10_native_exec().
	 */
	if (s10_uucopy(argp, &filename, sizeof (char *)) != 0)
		return (EFAULT);

	/* If an exec call succeeds, it never returns */
	err = __systemcall(rval, SYS_brand + 1024, B_EXEC_NATIVE, filename,
	    argp, envp, NULL, NULL, NULL);
	s10_assert(err != 0);
	return (err);
}

/*
 * Interpose on the SYS_exec syscall to detect native wrappers.
 */
int
s10_exec(sysret_t *rval, const char *fname, const char **argp)
{
	int err;

	if ((err = s10_exec_native(rval, fname, argp, NULL)) != 0)
		return (err);

	/* If an exec call succeeds, it never returns */
	err = __systemcall(rval, SYS_exec + 1024, fname, argp);
	s10_assert(err != 0);
	return (err);
}

/*
 * Interpose on the SYS_execve syscall to detect native wrappers.
 */
int
s10_execve(sysret_t *rval, const char *fname, const char **argp,
    const char **envp)
{
	int err;

	if ((err = s10_exec_native(rval, fname, argp, envp)) != 0)
		return (err);

	/* If an exec call succeeds, it never returns */
	err = __systemcall(rval, SYS_execve + 1024, fname, argp, envp);
	s10_assert(err != 0);
	return (err);
}

/*
 * S10's issetugid() syscall is now a subcode to privsys().
 */
static int
s10_issetugid(sysret_t *rval)
{
	return (__systemcall(rval, SYS_privsys + 1024, PRIVSYS_ISSETUGID,
	    0, 0, 0, 0, 0));
}

/*
 * New last arg "block" flag should be zero.  The block flag is used by
 * the Opensolaris AIO implementation, which is now part of libc.
 */
static int
s10_sigqueue(sysret_t *rval, pid_t pid, int signo, void *value, int si_code)
{
	return (__systemcall(rval, SYS_sigqueue + 1024, pid, signo, value,
	    si_code, 0));
}

static long
s10_uname(sysret_t *rv, uintptr_t p1)
{
	struct utsname un, *unp = (struct utsname *)p1;
	int rev, err;

	if ((err = __systemcall(rv, SYS_uname + 1024, &un)) != 0)
		return (err);

	rev = atoi(&un.release[2]);
	s10_assert(rev >= 11);
	bzero(un.release, _SYS_NMLN);
	(void) strlcpy(un.release, S10_UTS_RELEASE, _SYS_NMLN);
	bzero(un.version, _SYS_NMLN);
	(void) strlcpy(un.version, S10_UTS_VERSION, _SYS_NMLN);

	/* copy out the modified uname info */
	return (s10_uucopy(&un, unp, sizeof (un)));
}

int
s10_sysinfo(sysret_t *rv, int command, char *buf, long count)
{
	char *value;
	int len;

	/*
	 * We must interpose on the sysinfo(2) commands SI_RELEASE and
	 * SI_VERSION; all others get passed to the native sysinfo(2)
	 * command.
	 */
	switch (command) {
		case SI_RELEASE:
			value = S10_UTS_RELEASE;
			break;

		case SI_VERSION:
			value = S10_UTS_VERSION;
			break;

		default:
			/*
			 * The default action is to pass the command to the
			 * native sysinfo(2) syscall.
			 */
			return (__systemcall(rv, SYS_systeminfo + 1024,
			    command, buf, count));
	}

	len = strlen(value) + 1;
	if (count > 0) {
		if (s10_uucopystr(value, buf, count) != 0)
			return (EFAULT);

		/* Assure NULL termination of buf as s10_uucopystr() doesn't. */
		if (len > count && s10_uucopy("\0", buf + (count - 1), 1) != 0)
			return (EFAULT);
	}

	/*
	 * On success, sysinfo(2) returns the size of buffer required to hold
	 * the complete value plus its terminating NULL byte.
	 */
	(void) S10_TRUSS_POINT_3(rv, SYS_systeminfo, 0, command, buf, count);
	rv->sys_rval1 = len;
	rv->sys_rval2 = 0;
	return (0);
}

#ifdef	__x86
#ifdef	__amd64
/*
 * 64-bit x86 LWPs created by SYS_lwp_create start here if they need to set
 * their %fs registers to the legacy Solaris 10 selector value.
 *
 * This function does three things:
 *
 *	1.  Trap to the kernel so that it can set %fs to the legacy Solaris 10
 *	    selector value.
 *	2.  Read the LWP's true entry point (the entry point supplied by libc
 *	    when SYS_lwp_create was invoked) from %r14.
 *	3.  Eliminate this function's stack frame and pass control to the LWP's
 *	    true entry point.
 *
 * See the comment above s10_lwp_create_correct_fs() (see below) for the reason
 * why this function exists.
 */
/*ARGSUSED*/
static void
s10_lwp_create_entry_point(void *ulwp_structp)
{
	sysret_t rval;

	/*
	 * The new LWP's %fs register is initially zero, but libc won't
	 * function correctly when %fs is zero.  Change the LWP's %fs register
	 * via SYS_brand.
	 */
	(void) __systemcall(&rval, SYS_brand + 1024, B_S10_FSREGCORRECTION);

	/*
	 * Jump to the true entry point, which is stored in %r14.
	 * Remove our stack frame before jumping so that
	 * s10_lwp_create_entry_point() won't be seen in stack traces.
	 *
	 * NOTE: s10_lwp_create_entry_point() pushes %r12 onto its stack frame
	 * so that it can use it as a temporary register.  We don't restore %r12
	 * in this assembly block because we don't care about its value (and
	 * neither does _lwp_start()).  Besides, the System V ABI AMD64
	 * Actirecture Processor Supplement doesn't specify that %r12 should
	 * have a special value when LWPs start, so we can ignore its value when
	 * we jump to the true entry point.  Furthermore, %r12 is a callee-saved
	 * register, so the true entry point should push %r12 onto its stack
	 * before using the register.  We ignore %r14 after we read it for
	 * similar reasons.
	 *
	 * NOTE: The compiler will generate a function epilogue for this
	 * function despite the fact that the LWP will never execute it.
	 * We could hand-code this entire function in assembly to eliminate
	 * the epilogue, but the epilogue is only three or four instructions,
	 * so we wouldn't save much space.  Besides, why would we want
	 * to create yet another ugly, hard-to-maintain assembly function when
	 * we could write most of it in C?
	 */
	__asm__ __volatile__(
	    "movq %0, %%rdi\n\t"	/* pass ulwp_structp as arg1 */
	    "movq %%rbp, %%rsp\n\t"	/* eliminate the stack frame */
	    "popq %%rbp\n\t"
	    "jmp *%%r14\n\t"		/* jump to the true entry point */
	    : : "r" (ulwp_structp));
	/*NOTREACHED*/
}

/*
 * The S10 libc expects that %fs will be nonzero for new 64-bit x86 LWPs but the
 * Nevada kernel clears %fs for such LWPs.  Unforunately, new LWPs do not issue
 * SYS_lwp_private (see s10_lwp_private() below) after they are created, so
 * we must ensure that new LWPs invoke a brand operation that sets %fs to a
 * nonzero value immediately after their creation.
 *
 * The easiest way to do this is to make new LWPs start at a special function,
 * s10_lwp_create_entry_point() (see its definition above), that invokes the
 * brand operation that corrects %fs.  We'll store the entry points of new LWPs
 * in their %r14 registers so that s10_lwp_create_entry_point() can find and
 * call them after invoking the special brand operation.  %r14 is a callee-saved
 * register; therefore, any functions invoked by s10_lwp_create_entry_point()
 * and all functions dealing with signals (e.g., sigacthandler()) will preserve
 * %r14 for s10_lwp_create_entry_point().
 *
 * The Nevada kernel can safely work with nonzero %fs values because the kernel
 * configures per-thread %fs segment descriptors so that the legacy %fs selector
 * value will still work.  See the comment in lwp_load() regarding %fs and
 * %fsbase in 64-bit x86 processes.
 *
 * This emulation exists thanks to CRs 6467491 and 6501650.
 */
static int
s10_lwp_create_correct_fs(sysret_t *rval, ucontext_t *ucp, int flags,
    id_t *new_lwp)
{
	ucontext_t s10_uc;

	/*
	 * Copy the supplied ucontext_t structure to the local stack
	 * frame and store the new LWP's entry point (the value of %rip
	 * stored in the ucontext_t) in the new LWP's %r14 register.
	 * Then make s10_lwp_create_entry_point() the new LWP's entry
	 * point.
	 */
	if (s10_uucopy(ucp, &s10_uc, sizeof (s10_uc)) != 0)
		return (EFAULT);
	s10_uc.uc_mcontext.gregs[REG_R14] = s10_uc.uc_mcontext.gregs[REG_RIP];
	s10_uc.uc_mcontext.gregs[REG_RIP] = (greg_t)s10_lwp_create_entry_point;

	/*
	 * Issue SYS_lwp_create to create the new LWP.  We pass the
	 * modified ucontext_t to make sure that the new LWP starts at
	 * s10_lwp_create_entry_point().
	 */
	return (__systemcall(rval, SYS_lwp_create + 1024, &s10_uc,
	    flags, new_lwp));
}
#endif	/* __amd64 */

/*
 * This function is invoked on x86 systems when SYS_lwp_create is issued but no
 * %fs register correction is necessary.
 *
 * See the comment above s10_lwp_create_correct_fs() above for more details.
 */
static int
s10_lwp_create(sysret_t *rval, ucontext_t *ucp, int flags, id_t *new_lwp)
{
	return (__systemcall(rval, SYS_lwp_create + 1024, ucp, flags, new_lwp));
}

/*
 * SYS_lwp_private is issued by libc_init() to set %fsbase in 64-bit x86
 * processes.  The Nevada kernel sets %fs to zero but the S10 libc expects
 * %fs to be nonzero.  We'll pass the issued system call to the kernel untouched
 * and invoke a brand operation to set %fs to the legacy S10 selector value.
 *
 * This emulation exists thanks to CRs 6467491 and 6501650.
 */
static int
s10_lwp_private(sysret_t *rval, int cmd, int which, uintptr_t base)
{
#ifdef	__amd64
	int err;

	/*
	 * The current LWP's %fs register should be zero.  Determine whether the
	 * Solaris 10 libc with which we're working functions correctly when %fs
	 * is zero by calling thr_main() after issuing the SYS_lwp_private
	 * syscall.  If thr_main() barfs (returns -1), then change the LWP's %fs
	 * register via SYS_brand and patch s10_sysent_table so that issuing
	 * SYS_lwp_create executes s10_lwp_create_correct_fs() rather than the
	 * default s10_lwp_create().  s10_lwp_create_correct_fs() will
	 * guarantee that new LWPs will have correct %fs values.
	 */
	if ((err = __systemcall(rval, SYS_lwp_private + 1024, cmd, which,
	    base)) != 0)
		return (err);
	if (thr_main() == -1) {
		/*
		 * SYS_lwp_private is only issued by libc_init(), which is
		 * executed when libc is first loaded by ld.so.1.  Thus we
		 * are guaranteed to be single-threaded at this point.  Even
		 * if we were multithreaded at this point, writing a 64-bit
		 * value to the st_callc field of a s10_sysent_table
		 * entry is guaranteed to be atomic on 64-bit x86 chips
		 * as long as the field is not split across cache lines
		 * (It shouldn't be.).  See chapter 8, section 1.1 of
		 * "The Intel 64 and IA32 Architectures Software Developer's
		 * Manual," Volume 3A for more details.
		 */
		s10_sysent_table[SYS_lwp_create].st_callc =
		    (sysent_cb_t)s10_lwp_create_correct_fs;
		return (__systemcall(rval, SYS_brand + 1024,
		    B_S10_FSREGCORRECTION));
	}
	return (0);
#else	/* !__amd64 */
	return (__systemcall(rval, SYS_lwp_private + 1024, cmd, which, base));
#endif	/* !__amd64 */
}
#endif	/* __x86 */

/*
 * The Opensolaris versions of lwp_mutex_timedlock() and lwp_mutex_trylock()
 * add an extra argument to the interfaces, a uintptr_t value for the mutex's
 * mutex_owner field.  The Solaris 10 libc assigns the mutex_owner field at
 * user-level, so we just make the extra argument be zero in both syscalls.
 */

static int
s10_lwp_mutex_timedlock(sysret_t *rval, lwp_mutex_t *lp, timespec_t *tsp)
{
	return (__systemcall(rval, SYS_lwp_mutex_timedlock + 1024, lp, tsp, 0));
}

static int
s10_lwp_mutex_trylock(sysret_t *rval, lwp_mutex_t *lp)
{
	return (__systemcall(rval, SYS_lwp_mutex_trylock + 1024, lp, 0));
}

/*
 * If the emul_global_zone flag is set then emulate some aspects of the
 * zone system call.  In particular, emulate the global zone ID on the
 * ZONE_LOOKUP subcommand and emulate some of the global zone attributes
 * on the ZONE_GETATTR subcommand.  If the flag is not set or we're performing
 * some other operation, simply pass the calls through.
 */
int
s10_zone(sysret_t *rval, int cmd, void *arg1, void *arg2, void *arg3,
    void *arg4)
{
	char		*aval;
	int		len;
	zoneid_t	zid;
	int		attr;
	char		*buf;
	size_t		bufsize;

	/*
	 * We only emulate the zone syscall for a subset of specific commands,
	 * otherwise we just pass the call through.
	 */
	if (!emul_global_zone)
		return (__systemcall(rval, SYS_zone + 1024, cmd, arg1, arg2,
		    arg3, arg4));

	switch (cmd) {
	case ZONE_LOOKUP:
		(void) S10_TRUSS_POINT_1(rval, SYS_zone, 0, cmd);
		rval->sys_rval1 = GLOBAL_ZONEID;
		rval->sys_rval2 = 0;
		return (0);

	case ZONE_GETATTR:
		zid = (zoneid_t)(uintptr_t)arg1;
		attr = (int)(uintptr_t)arg2;
		buf = (char *)arg3;
		bufsize = (size_t)arg4;

		/*
		 * If the request is for the global zone then we're emulating
		 * that, otherwise pass this thru.
		 */
		if (zid != GLOBAL_ZONEID)
			goto passthru;

		switch (attr) {
		case ZONE_ATTR_NAME:
			aval = GLOBAL_ZONENAME;
			break;

		case ZONE_ATTR_BRAND:
			aval = NATIVE_BRAND_NAME;
			break;
		default:
			/*
			 * We only emulate a subset of the attrs, use the
			 * real zone id to pass thru the rest.
			 */
			arg1 = (void *)(uintptr_t)zoneid;
			goto passthru;
		}

		(void) S10_TRUSS_POINT_5(rval, SYS_zone, 0, cmd, zid, attr,
		    buf, bufsize);

		len = strlen(aval) + 1;
		if (len > bufsize)
			return (ENAMETOOLONG);

		if (buf != NULL) {
			if (len == 1) {
				if (s10_uucopy("\0", buf, 1) != 0)
					return (EFAULT);
			} else {
				if (s10_uucopystr(aval, buf, len) != 0)
					return (EFAULT);

				/*
				 * Assure NULL termination of "buf" as
				 * s10_uucopystr() does NOT.
				 */
				if (s10_uucopy("\0", buf + (len - 1), 1) != 0)
					return (EFAULT);
			}
		}

		rval->sys_rval1 = len;
		rval->sys_rval2 = 0;
		return (0);

	default:
		break;
	}

passthru:
	return (__systemcall(rval, SYS_zone + 1024, cmd, arg1, arg2, arg3,
	    arg4));
}

/*
 * Close a libc file handle, but don't actually close the underlying
 * file descriptor.
 */
static void
s10_close_fh(FILE *file)
{
	int fd, fd_new;

	if (file == NULL)
		return;

	if ((fd = fileno(file)) < 0)
		return;

	fd_new = dup(fd);
	if (fd_new == -1)
		return;

	(void) fclose(file);
	(void) dup2(fd_new, fd);
	(void) close(fd_new);
}

/*ARGSUSED*/
int
s10_init(int argc, char *argv[], char *envp[])
{
	sysret_t		rval;
	s10_brand_reg_t		reg;
	s10_elf_data_t		sed;
	auxv_t			*ap;
	uintptr_t		*p;
	int			i, err;
	char			*bname;

	/* Sanity check our translation table return value codes */
	for (i = 0; i < NSYSCALL; i++) {
		s10_sysent_table_t *est = &(s10_sysent_table[i]);
		s10_assert(BIT_ONLYONESET(est->st_args & RV_MASK));
	}

	/*
	 * We need to shutdown all libc stdio.  libc stdio normally goes to
	 * file descriptors, but since we're actually part of a another
	 * process we don't own these file descriptors and we can't make
	 * any assumptions about their state.
	 */
	s10_close_fh(stdin);
	s10_close_fh(stdout);
	s10_close_fh(stderr);

	/*
	 * Cache the pid of the zone's init process and determine if
	 * we're init(1m) for the zone.  Remember: we might be init
	 * now, but as soon as we fork(2) we won't be.
	 */
	(void) get_initpid_info();

	/* get the current zoneid */
	err = __systemcall(&rval, SYS_zone, ZONE_LOOKUP, NULL);
	s10_assert(err == 0);
	zoneid = (zoneid_t)rval.sys_rval1;

	/* Get the zone's emulation bitmap. */
	if ((err = __systemcall(&rval, SYS_zone, ZONE_GETATTR, zoneid,
	    S10_EMUL_BITMAP, emul_bitmap, sizeof (emul_bitmap))) != 0) {
		s10_abort(err, "The zone's patch level is unsupported");
		/*NOTREACHED*/
	}

	bname = basename(argv[0]);

	/*
	 * In general we want the S10 commands that are zone-aware to continue
	 * to behave as they normally do within a zone.  Since these commands
	 * are zone-aware, they should continue to "do the right thing".
	 * However, some zone-aware commands aren't going to work the way
	 * we expect them to inside the branded zone.  In particular, the pkg
	 * and patch commands will not properly manage all pkgs/patches
	 * unless the commands think they are running in the global zone.  For
	 * these commands we want to emulate the global zone.
	 *
	 * We don't do any emulation for pkgcond since it is typically used
	 * in pkg/patch postinstall scripts and we want those scripts to do
	 * the right thing inside a zone.
	 *
	 * One issue is the handling of hollow pkgs.  Since the pkgs are
	 * hollow, they won't use pkgcond in their postinstall scripts.  These
	 * pkgs typically are installing drivers so we handle that by
	 * replacing add_drv and rem_drv in the s10_boot script.
	 */
	if (strcmp("pkgadd", bname) == 0 || strcmp("pkgrm", bname) == 0 ||
	    strcmp("patchadd", bname) == 0 || strcmp("patchrm", bname) == 0)
		emul_global_zone = B_TRUE;

	/*
	 * Register our syscall emulation table with the kernel.
	 * Note that we don't have to do invoke (syscall_number + 1024)
	 * until we've actually establised a syscall emulation callback
	 * handler address, which is what we're doing with this brand
	 * syscall.
	 */
	reg.sbr_version = S10_VERSION;
#ifdef	__x86
	reg.sbr_handler = (caddr_t)s10_handler_table;
#else	/* !__x86 */
	reg.sbr_handler = (caddr_t)s10_handler;
#endif	/* !__x86 */

	if ((err = __systemcall(&rval, SYS_brand, B_REGISTER, &reg)) != 0) {
		s10_abort(err, "Failed to brand current process");
		/*NOTREACHED*/
	}

	/* Get data about the executable we're running from the kernel. */
	if ((err = __systemcall(&rval, SYS_brand + 1024,
	    B_ELFDATA, (void *)&sed)) != 0) {
		s10_abort(err,
		    "Failed to get required brand ELF data from the kernel");
		/*NOTREACHED*/
	}

	/*
	 * Find the aux vector on the stack.
	 */
	p = (uintptr_t *)envp;
	while (*p != NULL)
		p++;

	/*
	 * p is now pointing at the 0 word after the environ pointers.
	 * After that is the aux vectors.
	 *
	 * The aux vectors are currently pointing to the brand emulation
	 * library and associated linker.  We're going to change them to
	 * point to the brand executable and associated linker (or to no
	 * linker for static binaries).  This matches the process data
	 * stored within the kernel and visible from /proc, which was
	 * all setup in s10_elfexec().  We do this so that when a debugger
	 * attaches to the process it sees the process as a normal solaris
	 * process, this brand emulation library and everything on it's
	 * link map will not be visible, unless our librtld_db plugin
	 * is used.  Note that this is very different from how Linux
	 * branded processes are implemented within lx branded zones.
	 * In that situation, the primary linkmap of the process is the
	 * brand emulation libraries linkmap, not the Linux applications
	 * linkmap.
	 *
	 * We also need to clear the AF_SUN_NOPLM flag from the AT_SUN_AUXFLAGS
	 * aux vector.  This flag told our linker that we don't have a
	 * primary link map.  Now that our linker is done initializing, we
	 * want to clear this flag before we transfer control to the
	 * applications copy of the linker, since we want that linker to have
	 * a primary link map which will be the link map for the application
	 * we're running.
	 */
	p++;
	for (ap = (auxv_t *)p; ap->a_type != AT_NULL; ap++) {
		switch (ap->a_type) {
			case AT_BASE:
				/* Hide AT_BASE if static binary */
				if (sed.sed_base == NULL) {
					ap->a_type = AT_IGNORE;
					ap->a_un.a_val = NULL;
				} else {
					ap->a_un.a_val = sed.sed_base;
				}
				break;
			case AT_ENTRY:
				ap->a_un.a_val = sed.sed_entry;
				break;
			case AT_PHDR:
				ap->a_un.a_val = sed.sed_phdr;
				break;
			case AT_PHENT:
				ap->a_un.a_val = sed.sed_phent;
				break;
			case AT_PHNUM:
				ap->a_un.a_val = sed.sed_phnum;
				break;
			case AT_SUN_AUXFLAGS:
				ap->a_un.a_val &= ~AF_SUN_NOPLM;
				break;
			case AT_SUN_EMULATOR:
				/*
				 * ld.so.1 inspects AT_SUN_EMULATOR to see if
				 * if it is the linker for the brand emulation
				 * library.  Hide AT_SUN_EMULATOR, as the
				 * linker we are about to jump to is the linker
				 * for the binary.
				 */
				ap->a_type = AT_IGNORE;
				ap->a_un.a_val = NULL;
				break;
			case AT_SUN_LDDATA:
				/* Hide AT_SUN_LDDATA if static binary */
				if (sed.sed_lddata == NULL) {
					ap->a_type = AT_IGNORE;
					ap->a_un.a_val = NULL;
				} else {
					ap->a_un.a_val = sed.sed_lddata;
				}
				break;
			default:
				break;
		}
	}

	s10_runexe(argv, sed.sed_ldentry);
	/*NOTREACHED*/
	s10_abort(0, "s10_runexe() returned");
	return (-1);
}

/*
 * This table must have at least NSYSCALL entries in it.
 *
 * The second parameter of each entry in the s10_sysent_table
 * contains the number of parameters and flags that describe the
 * syscall return value encoding.  See the block comments at the
 * top of this file for more information about the syscall return
 * value flags and when they should be used.
 */
s10_sysent_table_t s10_sysent_table[] = {
#if defined(__sparc) && !defined(__sparcv9)
	EMULATE(s10_indir, 9 | RV_64RVAL),	/*  0 */
#else /* !__sparc || __sparcv9 */
	NOSYS,					/*  0 */
#endif /* !__sparc || __sparcv9 */
	NOSYS,					/*   1 */
	NOSYS,					/*   2 */
	NOSYS,					/*   3 */
	NOSYS,					/*   4 */
	NOSYS,					/*   5 */
	NOSYS,					/*   6 */
	NOSYS,					/*   7 */
	NOSYS,					/*   8 */
	NOSYS,					/*   9 */
	NOSYS,					/*  10 */
	EMULATE(s10_exec, 2 | RV_DEFAULT),	/*  11 */
	NOSYS,					/*  12 */
	NOSYS,					/*  13 */
	NOSYS,					/*  14 */
	NOSYS,					/*  15 */
	NOSYS,					/*  16 */
	NOSYS,					/*  17 */
	NOSYS,					/*  18 */
	NOSYS,					/*  19 */
	NOSYS,					/*  20 */
	NOSYS,					/*  21 */
	NOSYS,					/*  22 */
	NOSYS,					/*  23 */
	NOSYS,					/*  24 */
	NOSYS,					/*  25 */
	NOSYS,					/*  26 */
	NOSYS,					/*  27 */
	NOSYS,					/*  28 */
	NOSYS,					/*  29 */
	NOSYS,					/*  30 */
	NOSYS,					/*  31 */
	NOSYS,					/*  32 */
	NOSYS,					/*  33 */
	NOSYS,					/*  34 */
	NOSYS,					/*  35 */
	NOSYS,					/*  36 */
	NOSYS,					/*  37 */
	NOSYS,					/*  38 */
	NOSYS,					/*  39 */
	NOSYS,					/*  40 */
	NOSYS,					/*  41 */
	NOSYS,					/*  42 */
	NOSYS,					/*  43 */
	NOSYS,					/*  44 */
	NOSYS,					/*  45 */
	NOSYS,					/*  46 */
	NOSYS,					/*  47 */
	NOSYS,					/*  48 */
	NOSYS,					/*  49 */
	NOSYS,					/*  50 */
	NOSYS,					/*  51 */
	NOSYS,					/*  52 */
	NOSYS,					/*  53 */
	EMULATE(s10_ioctl, 3 | RV_DEFAULT),	/*  54 */
	NOSYS,					/*  55 */
	NOSYS,					/*  56 */
	NOSYS,					/*  57 */
	NOSYS,					/*  58 */
	EMULATE(s10_execve, 3 | RV_DEFAULT),	/*  59 */
	NOSYS,					/*  60 */
	NOSYS,					/*  61 */
	NOSYS,					/*  62 */
	NOSYS,					/*  63 */
	NOSYS,					/*  64 */
	NOSYS,					/*  65 */
	NOSYS,					/*  66 */
	NOSYS,					/*  67 */
	NOSYS,					/*  68 */
	NOSYS,					/*  69 */
	NOSYS,					/*  70 */
	EMULATE(s10_acctctl, 3 | RV_DEFAULT),	/*  71 */
	NOSYS,					/*  72 */
	NOSYS,					/*  73 */
	NOSYS,					/*  74 */
	EMULATE(s10_issetugid, 0 | RV_DEFAULT),	/*  75 */
	NOSYS,					/*  76 */
	NOSYS,					/*  77 */
	NOSYS,					/*  78 */
	NOSYS,					/*  79 */
	NOSYS,					/*  80 */
	EMULATE(s10_getdents, 3 | RV_DEFAULT),	/*  81 */
	NOSYS,					/*  82 */
	NOSYS,					/*  83 */
	NOSYS,					/*  84 */
	NOSYS,					/*  85 */
	NOSYS,					/*  86 */
	NOSYS,					/*  87 */
	NOSYS,					/*  88 */
	NOSYS,					/*  89 */
	NOSYS,					/*  90 */
	NOSYS,					/*  91 */
	NOSYS,					/*  92 */
	NOSYS,					/*  93 */
	NOSYS,					/*  94 */
	NOSYS,					/*  95 */
	NOSYS,					/*  96 */
	NOSYS,					/*  97 */
	NOSYS,					/*  98 */
	NOSYS,					/*  99 */
	NOSYS,					/* 100 */
	NOSYS,					/* 101 */
	NOSYS,					/* 102 */
	NOSYS,					/* 103 */
	NOSYS,					/* 104 */
	NOSYS,					/* 105 */
	NOSYS,					/* 106 */
	NOSYS,					/* 107 */
	NOSYS,					/* 108 */
	NOSYS,					/* 109 */
	NOSYS,					/* 110 */
	NOSYS,					/* 111 */
	NOSYS,					/* 112 */
	NOSYS,					/* 113 */
	NOSYS,					/* 114 */
	NOSYS,					/* 115 */
	NOSYS,					/* 116 */
	NOSYS,					/* 117 */
	NOSYS,					/* 118 */
	NOSYS,					/* 119 */
	NOSYS,					/* 120 */
	NOSYS,					/* 121 */
	NOSYS,					/* 122 */
	NOSYS,					/* 123 */
	NOSYS,					/* 124 */
	NOSYS,					/* 125 */
	NOSYS,					/* 126 */
	NOSYS,					/* 127 */
	NOSYS,					/* 128 */
	NOSYS,					/* 129 */
	NOSYS,					/* 130 */
	NOSYS,					/* 131 */
	NOSYS,					/* 132 */
	NOSYS,					/* 133 */
	NOSYS,					/* 134 */
	EMULATE(s10_uname, 1 | RV_DEFAULT),	/* 135 */
	NOSYS,					/* 136 */
	NOSYS,					/* 137 */
	NOSYS,					/* 138 */
	EMULATE(s10_sysinfo, 3 | RV_DEFAULT),	/* 139 */
	NOSYS,					/* 140 */
	NOSYS,					/* 141 */
	NOSYS,					/* 142 */
	NOSYS,					/* 143 */
	NOSYS,					/* 144 */
	NOSYS,					/* 145 */
	NOSYS,					/* 146 */
	NOSYS,					/* 147 */
	NOSYS,					/* 148 */
	NOSYS,					/* 149 */
	NOSYS,					/* 150 */
	NOSYS,					/* 151 */
	NOSYS,					/* 152 */
	NOSYS,					/* 153 */
	NOSYS,					/* 154 */
	NOSYS,					/* 155 */
	NOSYS,					/* 156 */
	NOSYS,					/* 157 */
	NOSYS,					/* 158 */
#ifdef	__x86
	EMULATE(s10_lwp_create, 3 | RV_DEFAULT), /* 159 */
#else	/* !__x86 */
	NOSYS,					/* 159 */
#endif	/* !__x86 */
	NOSYS,					/* 160 */
	NOSYS,					/* 161 */
	NOSYS,					/* 162 */
	NOSYS,					/* 163 */
	NOSYS,					/* 164 */
	NOSYS,					/* 165 */
#ifdef	__x86
	EMULATE(s10_lwp_private, 3 | RV_DEFAULT), /* 166 */
#else	/* !__x86 */
	NOSYS,					/* 166 */
#endif	/* !__x86 */
	NOSYS,					/* 167 */
	NOSYS,					/* 168 */
	NOSYS,					/* 169 */
	NOSYS,					/* 170 */
	NOSYS,					/* 171 */
	NOSYS,					/* 172 */
	NOSYS,					/* 173 */
	EMULATE(s10_pwrite, 4 | RV_DEFAULT),	/* 174 */
	NOSYS,					/* 175 */
	NOSYS,					/* 176 */
	NOSYS,					/* 177 */
	NOSYS,					/* 178 */
	NOSYS,					/* 179 */
	NOSYS,					/* 180 */
	NOSYS,					/* 181 */
	NOSYS,					/* 182 */
	NOSYS,					/* 183 */
	NOSYS,					/* 184 */
	NOSYS,					/* 185 */
	EMULATE(s10_auditsys, 4 | RV_64RVAL),	/* 186 */
	NOSYS,					/* 187 */
	NOSYS,					/* 188 */
	NOSYS,					/* 189 */
	EMULATE(s10_sigqueue, 4 | RV_DEFAULT),	/* 190 */
	NOSYS,					/* 191 */
	NOSYS,					/* 192 */
	NOSYS,					/* 193 */
	NOSYS,					/* 194 */
	NOSYS,					/* 195 */
	NOSYS,					/* 196 */
	NOSYS,					/* 197 */
	NOSYS,					/* 198 */
	NOSYS,					/* 199 */
	NOSYS,					/* 200 */
	NOSYS,					/* 201 */
	NOSYS,					/* 202 */
	NOSYS,					/* 203 */
	NOSYS,					/* 204 */
	NOSYS,					/* 205 */
	NOSYS,					/* 206 */
	NOSYS,					/* 207 */
	NOSYS,					/* 208 */
	NOSYS,					/* 209 */
	EMULATE(s10_lwp_mutex_timedlock, 2 | RV_DEFAULT),	/* 210 */
	NOSYS,					/* 211 */
	NOSYS,					/* 212 */
#ifdef	_LP64
	NOSYS,					/* 213 */
#else	/* !_LP64 */
	EMULATE(s10_getdents64, 3 | RV_DEFAULT), /* 213 */
#endif	/* !_LP64 */
	NOSYS,					/* 214 */
	NOSYS,					/* 215 */
	NOSYS,					/* 216 */
	NOSYS,					/* 217 */
	NOSYS,					/* 218 */
	NOSYS,					/* 219 */
	NOSYS,					/* 220 */
	NOSYS,					/* 221 */
	NOSYS,					/* 222 */
#ifdef	_LP64
	NOSYS,					/* 223 */
#else	/* !_LP64 */
	EMULATE(s10_pwrite64, 5 | RV_DEFAULT),	/* 223 */
#endif	/* !_LP64 */
	NOSYS,					/* 224 */
	NOSYS,					/* 225 */
	NOSYS,					/* 226 */
	EMULATE(s10_zone, 5 | RV_DEFAULT),	/* 227 */
	NOSYS,					/* 228 */
	NOSYS,					/* 229 */
	NOSYS,					/* 230 */
	NOSYS,					/* 231 */
	NOSYS,					/* 232 */
	NOSYS,					/* 233 */
	NOSYS,					/* 234 */
	NOSYS,					/* 235 */
	NOSYS,					/* 236 */
	NOSYS,					/* 237 */
	NOSYS,					/* 238 */
	NOSYS,					/* 239 */
	NOSYS,					/* 240 */
	NOSYS,					/* 241 */
	NOSYS,					/* 242 */
	NOSYS,					/* 243 */
	NOSYS,					/* 244 */
	NOSYS,					/* 245 */
	NOSYS,					/* 246 */
	NOSYS,					/* 247 */
	NOSYS,					/* 248 */
	NOSYS,					/* 249 */
	NOSYS,					/* 250 */
	EMULATE(s10_lwp_mutex_trylock, 1 | RV_DEFAULT),		/* 251 */
	NOSYS,					/* 252 */
	NOSYS,					/* 253 */
	NOSYS,					/* 254 */
	NOSYS					/* 255 */
};
