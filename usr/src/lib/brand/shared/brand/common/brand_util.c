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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <fcntl.h>
#include <brand_misc.h>
#include <sys/brand.h>

extern brand_sysent_table_t brand_sysent_table[];

/*LINTED: static unused*/
static volatile int		brand_abort_err;
/*LINTED: static unused*/
static volatile const char	*brand_abort_msg;
/*LINTED: static unused*/
static volatile const char	*brand_abort_file;
/*LINTED: static unused*/
static volatile int		brand_abort_line;

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
 * should return the errno value we'd like the system to return.
 * For more information about this see the comments in brand_misc.h.
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
 * See brand_misc.h.
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
 * callback (XXX_brand_syscall_callback_common) will detect if a system
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
 * *** General considerations
 *
 * One of the differences between the lx brand and the s10
 * brand, is that the s10 brand only interposes on syscalls
 * that need some kind of emulation, whereas the lx brand interposes
 * on _all_ system calls.  Lx branded system calls that don't need
 * any emulation are then redirected back to the kernel from the
 * userland library via the IN_KERNEL_SYSCALL macro.  The lx-syscall
 * dtrace provider depends on this behavior.
 *
 */

/*ARGSUSED*/
void
_brand_abort(int err, const char *msg, const char *file, int line)
{
	sysret_t rval;

	/* Save the error message into convenient globals */
	brand_abort_err = err;
	brand_abort_msg = msg;
	brand_abort_file = file;
	brand_abort_line = line;

	/* kill ourselves */
	abort();

	/* If abort() didn't work, try something stronger. */
	(void) __systemcall(&rval, SYS_lwp_kill + 1024, _lwp_self(), SIGKILL);
}

int
brand_uucopy(const void *from, void *to, size_t size)
{
	sysret_t rval;

	if (__systemcall(&rval, SYS_uucopy + 1024, from, to, size) != 0)
		return (EFAULT);
	return (0);
}

/*
 * ATTENTION: uucopystr() does NOT ensure that string are null terminated!
 */
int
brand_uucopystr(const void *from, void *to, size_t size)
{
	sysret_t rval;

	if (__systemcall(&rval, SYS_uucopystr + 1024, from, to, size) != 0)
		return (EFAULT);
	return (0);
}

/*
 * This function is defined to be NOSYS but it won't be called from the
 * the kernel since the NOSYS system calls are not enabled in the kernel.
 * Thus, the only time this function is called is directly from within the
 * indirect system call path.
 */
/*ARGSUSED*/
long
brand_unimpl(sysret_t *rv, uintptr_t p1)
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
long
brand_indir(sysret_t *rv, int code,
    uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
    uintptr_t a5, uintptr_t a6, uintptr_t a7)
{
	brand_sysent_table_t *sst = &(brand_sysent_table[code]);

	brand_assert(code < NSYSCALL);
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
		return ((sst->st_callc)(rv, a0, a1, a2, a3, a4, a5));
	case 7:
		return ((sst->st_callc)(rv, a0, a1, a2, a3, a4, a5, a6));
	case 8:
		return ((sst->st_callc)(rv, a0, a1, a2, a3, a4, a5, a6, a7));
	}
	brand_abort(0, "invalid entry in brand_sysent_table");
	return (EINVAL);
}
#endif /* __sparc && !__sparcv9 */

/*
 * Close a libc file handle, but don't actually close the underlying
 * file descriptor.
 */
static void
brand_close_fh(FILE *file)
{
	int fd, fd_new;

	if (file == NULL)
		return;

	if ((fd = fileno(file)) < 0)
		return;

	/*
	 * We're a branded process but our handler isn't installed yet.  We
	 * can't use the dup() syscall since it no longer exists.
	 */
	fd_new = fcntl(fd, F_DUPFD, 0);
	if (fd_new == -1)
		return;

	(void) fclose(file);
	(void) dup2(fd_new, fd);
	(void) close(fd_new);
}

/*ARGSUSED*/
void
brand_pre_init()
{
	int			i;

	/* Sanity check our translation table return value codes */
	for (i = 0; i < NSYSCALL; i++) {
		brand_sysent_table_t *est = &(brand_sysent_table[i]);
		brand_assert(BIT_ONLYONESET(est->st_args & RV_MASK));
	}

	/*
	 * We need to shutdown all libc stdio.  libc stdio normally goes to
	 * file descriptors, but since we're actually part of a another
	 * process we don't own these file descriptors and we can't make
	 * any assumptions about their state.
	 */
	brand_close_fh(stdin);
	brand_close_fh(stdout);
	brand_close_fh(stderr);
}

/*ARGSUSED*/
ulong_t
brand_post_init(int version, int argc, char *argv[], char *envp[])
{
	sysret_t		rval;
	brand_proc_reg_t	reg;
	brand_elf_data_t	sed;
	auxv_t			*ap;
	uintptr_t		*p;
	int			err;

	/*
	 * Register our syscall emulation table with the kernel.
	 * Note that we don't have to do invoke (syscall_number + 1024)
	 * until we've actually establised a syscall emulation callback
	 * handler address, which is what we're doing with this brand
	 * syscall.
	 */
	reg.sbr_version = version;
#ifdef	__x86
	reg.sbr_handler = (caddr_t)brand_handler_table;
#else	/* !__x86 */
	reg.sbr_handler = (caddr_t)brand_handler;
#endif	/* !__x86 */

	if ((err = __systemcall(&rval, SYS_brand, B_REGISTER, &reg)) != 0) {
		brand_abort(err, "Failed to brand current process");

		/*NOTREACHED*/
	}

	/* Get data about the executable we're running from the kernel. */
	if ((err = __systemcall(&rval, SYS_brand + 1024,
	    B_ELFDATA, (void *)&sed)) != 0) {
		brand_abort(err,
		    "Failed to get required brand ELF data from the kernel");
		/*NOTREACHED*/
	}

	/*
	 * Find the aux vector on the stack.
	 */
	p = (uintptr_t *)envp;
	while (*p != 0)
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
				if (sed.sed_base == 0) {
					ap->a_type = AT_IGNORE;
					ap->a_un.a_val = 0;
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
				ap->a_un.a_val = 0;
				break;
			case AT_SUN_LDDATA:
				/* Hide AT_SUN_LDDATA if static binary */
				if (sed.sed_lddata == 0) {
					ap->a_type = AT_IGNORE;
					ap->a_un.a_val = 0;
				} else {
					ap->a_un.a_val = sed.sed_lddata;
				}
				break;
			default:
				break;
		}
	}

	return (sed.sed_ldentry);
}
