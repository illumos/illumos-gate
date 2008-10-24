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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/bitmap.h>
#include <sys/brand.h>
#include <sys/inttypes.h>
#include <sys/lwp.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/utsname.h>

#include <sn1_brand.h>
#include <sn1_misc.h>

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
 * For more information about this see the comment in sn1_handler().
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
 * to to set the proper RV_* flags in the sn1_sysent_table.  Upon failure,
 * syscall emulation fuctions should return an errno value.  Upon success
 * syscall emulation functions should return 0 and set the sysret_t return
 * value parameters accordingly.
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
 * callback (sn1_brand_syscall_callback_common) will detect if a system
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
 *
 * *** sn1 brand emulation scope considerations
 *
 * One of the differences between the lx brand and the s8 and s9
 * brands, is that the s8 and s9 brands only interpose on syscalls
 * that need some kind of emulation, where as the lx brand interposes
 * on _all_ system calls.  Lx branded system calls that don't need
 * any emulation are then redirected back to the kernel from the
 * userland library via the IN_KERNEL_SYSCALL macro.  The lx-syscall
 * dtrace provider depends on this behavior.
 *
 * Given that the sn1 brand exists for testing purposes, it should
 * eventually be enhanced to redirect all system calls through the
 * brand emulation library.  This will ensure the maximum testing
 * exposure for the brandz infrastructure.  Some other options to
 * consider for improving brandz test exposure are:
 * - Folding the sn1 brand into the native brand and only enabling
 *   it on DEBUG builds.
 * - Modifying the zones test suite to use sn1 branded zones by default,
 *   any adapting functional test harnesses to use sn1 branded zones
 *   by default instead of native zones.
 */

#define	EMULATE(cb, args)	{ (sysent_cb_t)(cb), (args) }
#define	NOSYS			EMULATE(sn1_unimpl, (0 | RV_DEFAULT))

typedef long (*sysent_cb_t)();
typedef struct sn1_sysent_table {
	sysent_cb_t	st_callc;
	uintptr_t	st_args;
} sn1_sysent_table_t;
sn1_sysent_table_t sn1_sysent_table[];

/*LINTED: static unused*/
static volatile int		sn1_abort_err;
/*LINTED: static unused*/
static volatile const char	*sn1_abort_msg;
/*LINTED: static unused*/
static volatile const char	*sn1_abort_file;
/*LINTED: static unused*/
static volatile int		sn1_abort_line;

extern int errno;

/*ARGSUSED*/
void
_sn1_abort(int err, const char *msg, const char *file, int line)
{
	sysret_t rval;

	/* Save the error message into convenient globals */
	sn1_abort_err = err;
	sn1_abort_msg = msg;
	sn1_abort_file = file;
	sn1_abort_line = line;

	/* kill ourselves */
	abort();

	/* If abort() didn't work, try something stronger. */
	(void) __systemcall(&rval, SYS_lwp_kill + 1024, _lwp_self(), SIGKILL);
}

/*
 * This function is defined to be NOSYS but it won't be called from the
 * the kernel since the NOSYS system calls are not enabled in the kernel.
 * Thus, the only time this function is called is directly from within the
 * indirect system call path.
 */
/*ARGSUSED*/
static long
sn1_unimpl(sysret_t *rv, uintptr_t p1)
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
sn1_indir(sysret_t *rv, int code,
    uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
    uintptr_t a5, uintptr_t a6, uintptr_t a7)
{
	sn1_sysent_table_t *sst = &(sn1_sysent_table[code]);

	sn1_assert(code < NSYSCALL);
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
	sn1_abort(0, "invalid entry in sn1_sysent_table");
	return (EINVAL);
}
#endif /* __sparc && !__sparcv9 */

static long
sn1_uname(sysret_t *rv, uintptr_t p1)
{
	struct utsname	un, *unp = (struct utsname *)p1;
	int		rev, err;

	if ((err = __systemcall(rv, SYS_uname + 1024, &un)) != 0)
		return (err);

	rev = atoi(&un.release[2]);
	sn1_assert(rev >= 10);
	(void) sprintf(un.release, "5.%d", rev - 1);

	if (uucopy(&un, unp, sizeof (un)) != 0)
		return (EFAULT);
	return (0);
}

/*
 * Close a libc file handle, but don't actually close the underlying
 * file descriptor.
 */
static void
sn1_close_fh(FILE *file)
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
sn1_init(int argc, char *argv[], char *envp[])
{
	sysret_t		rval;
	sn1_brand_reg_t		reg;
	sn1_elf_data_t		sed;
	auxv_t			*ap;
	uintptr_t		*p;
	int			i, err;

	/* Sanity check our translation table return value codes */
	for (i = 0; i < NSYSCALL; i++) {
		sn1_sysent_table_t *est = &(sn1_sysent_table[i]);
		sn1_assert(BIT_ONLYONESET(est->st_args & RV_MASK));
	}

	/*
	 * We need to shutdown all libc stdio.  libc stdio normally goes to
	 * file descriptors, but since we're actually part of a another
	 * process we don't own these file descriptors and we can't make
	 * any assumptions about their state.
	 */
	sn1_close_fh(stdin);
	sn1_close_fh(stdout);
	sn1_close_fh(stderr);

	/*
	 * Register our syscall emulation table with the kernel.
	 * Note that we don't have to do invoke (syscall_number + 1024)
	 * until we've actually establised a syscall emulation callback
	 * handler address, which is what we're doing with this brand
	 * syscall.
	 */
	reg.sbr_version = SN1_VERSION;
	reg.sbr_handler = (caddr_t)sn1_handler;
	if ((err = __systemcall(&rval, SYS_brand, B_REGISTER, &reg)) != 0) {
		sn1_abort(err, "Failed to brand current process");
		/*NOTREACHED*/
	}

	/* Get data about the executable we're running from the kernel. */
	if ((err = __systemcall(&rval, SYS_brand + 1024,
	    B_ELFDATA, (void *)&sed)) != 0) {
		sn1_abort(err,
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
	 * all setup in sn1_elfexec().  We do this so that when a debugger
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

	sn1_runexe(argv, sed.sed_ldentry);
	/*NOTREACHED*/
	sn1_abort(0, "sn1_runexe() returned");
	return (-1);
}

#define	IN_KERNEL_SYSCALL(name, num)					\
static long								\
sn1_##name(sysret_t *rv,						\
    uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3,		\
    uintptr_t a4, uintptr_t a5, uintptr_t a6, uintptr_t a7)		\
{									\
	return (__systemcall(rv, num + 1024,				\
	    a0, a1, a2, a3, a4, a5, a6, a7));				\
}

/*
 * These are branded system calls, which have been redirected to this
 * userland emulation library, and are emulated by passing them strait
 * on to the kernel as native system calls.
 */
IN_KERNEL_SYSCALL(read,		SYS_read)		/*   3 */
IN_KERNEL_SYSCALL(write,	SYS_write)		/*   4 */
IN_KERNEL_SYSCALL(wait,		SYS_wait)		/*   7 */
IN_KERNEL_SYSCALL(time,		SYS_time)		/*  13 */
IN_KERNEL_SYSCALL(getpid,	SYS_getpid)		/*  20 */
IN_KERNEL_SYSCALL(mount,	SYS_mount)		/*  21 */
IN_KERNEL_SYSCALL(getuid,	SYS_getuid)		/*  24 */
IN_KERNEL_SYSCALL(times,	SYS_times)		/*  43 */
IN_KERNEL_SYSCALL(getgid,	SYS_getgid)		/*  47 */
IN_KERNEL_SYSCALL(utssys,	SYS_utssys)		/*  57 */
IN_KERNEL_SYSCALL(readlink,	SYS_readlink)		/*  90 */

/*
 * This table must have at least NSYSCALL entries in it.
 *
 * The second parameter of each entry in the sn1_sysent_table
 * contains the number of parameters and flags that describe the
 * syscall return value encoding.  See the block comments at the
 * top of this file for more information about the syscall return
 * value flags and when they should be used.
 */
sn1_sysent_table_t sn1_sysent_table[] = {
#if defined(__sparc) && !defined(__sparcv9)
	EMULATE(sn1_indir, 9 | RV_64RVAL),	/*  0 */
#else /* !__sparc || __sparcv9 */
	NOSYS,					/*  0 */
#endif /* !__sparc || __sparcv9 */
	NOSYS,					/*   1 */
	NOSYS,					/*   2 */
	EMULATE(sn1_read, 3 | RV_DEFAULT),	/*   3 */
	EMULATE(sn1_write, 3 | RV_DEFAULT),	/*   4 */
	NOSYS,					/*   5 */
	NOSYS,					/*   6 */
	EMULATE(sn1_wait, 0 | RV_32RVAL2),	/*   7 */
	NOSYS,					/*   8 */
	NOSYS,					/*   9 */
	NOSYS,					/*  10 */
	NOSYS,					/*  11 */
	NOSYS,					/*  12 */
	EMULATE(sn1_time, 0 | RV_DEFAULT),	/*  13 */
	NOSYS,					/*  14 */
	NOSYS,					/*  15 */
	NOSYS,					/*  16 */
	NOSYS,					/*  17 */
	NOSYS,					/*  18 */
	NOSYS,					/*  19 */
	EMULATE(sn1_getpid, 0 | RV_32RVAL2),	/*  20 */
	EMULATE(sn1_mount, 8 | RV_DEFAULT),	/*  21 */
	NOSYS,					/*  22 */
	NOSYS,					/*  23 */
	EMULATE(sn1_getuid, 0 | RV_32RVAL2),	/*  24 */
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
	EMULATE(sn1_times, 1 | RV_DEFAULT),	/*  43 */
	NOSYS,					/*  44 */
	NOSYS,					/*  45 */
	NOSYS,					/*  46 */
	EMULATE(sn1_getgid, 0 | RV_32RVAL2),	/*  47 */
	NOSYS,					/*  48 */
	NOSYS,					/*  49 */
	NOSYS,					/*  50 */
	NOSYS,					/*  51 */
	NOSYS,					/*  52 */
	NOSYS,					/*  53 */
	NOSYS,					/*  54 */
	NOSYS,					/*  55 */
	NOSYS,					/*  56 */
	EMULATE(sn1_utssys, 4 | RV_32RVAL2),	/*  57 */
	NOSYS,					/*  58 */
	NOSYS,					/*  59 */
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
	NOSYS,					/*  71 */
	NOSYS,					/*  72 */
	NOSYS,					/*  73 */
	NOSYS,					/*  74 */
	NOSYS,					/*  75 */
	NOSYS,					/*  76 */
	NOSYS,					/*  77 */
	NOSYS,					/*  78 */
	NOSYS,					/*  79 */
	NOSYS,					/*  80 */
	NOSYS,					/*  81 */
	NOSYS,					/*  82 */
	NOSYS,					/*  83 */
	NOSYS,					/*  84 */
	NOSYS,					/*  85 */
	NOSYS,					/*  86 */
	NOSYS,					/*  87 */
	NOSYS,					/*  88 */
	NOSYS,					/*  89 */
	EMULATE(sn1_readlink, 3 | RV_DEFAULT),	/*  90 */
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
	EMULATE(sn1_uname, 1 | RV_DEFAULT),	/* 135 */
	NOSYS,					/* 136 */
	NOSYS,					/* 137 */
	NOSYS,					/* 138 */
	NOSYS,					/* 139 */
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
	NOSYS,					/* 159 */
	NOSYS,					/* 160 */
	NOSYS,					/* 161 */
	NOSYS,					/* 162 */
	NOSYS,					/* 163 */
	NOSYS,					/* 164 */
	NOSYS,					/* 165 */
	NOSYS,					/* 166 */
	NOSYS,					/* 167 */
	NOSYS,					/* 168 */
	NOSYS,					/* 169 */
	NOSYS,					/* 170 */
	NOSYS,					/* 171 */
	NOSYS,					/* 172 */
	NOSYS,					/* 173 */
	NOSYS,					/* 174 */
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
	NOSYS,					/* 186 */
	NOSYS,					/* 187 */
	NOSYS,					/* 188 */
	NOSYS,					/* 189 */
	NOSYS,					/* 190 */
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
	NOSYS,					/* 210 */
	NOSYS,					/* 211 */
	NOSYS,					/* 212 */
	NOSYS,					/* 213 */
	NOSYS,					/* 214 */
	NOSYS,					/* 215 */
	NOSYS,					/* 216 */
	NOSYS,					/* 217 */
	NOSYS,					/* 218 */
	NOSYS,					/* 219 */
	NOSYS,					/* 220 */
	NOSYS,					/* 221 */
	NOSYS,					/* 222 */
	NOSYS,					/* 223 */
	NOSYS,					/* 224 */
	NOSYS,					/* 225 */
	NOSYS,					/* 226 */
	NOSYS,					/* 227 */
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
	NOSYS,					/* 251 */
	NOSYS,					/* 252 */
	NOSYS,					/* 253 */
	NOSYS,					/* 254 */
	NOSYS					/* 255 */
};
