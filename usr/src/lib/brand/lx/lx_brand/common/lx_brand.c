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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2014 Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fstyp.h>
#include <sys/fsid.h>
#include <sys/systm.h>
#include <sys/auxv.h>
#include <sys/frame.h>
#include <zone.h>
#include <sys/brand.h>
#include <sys/epoll.h>

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <synch.h>
#include <libelf.h>
#include <libgen.h>
#include <pthread.h>
#include <utime.h>
#include <dirent.h>
#include <ucontext.h>
#include <libintl.h>
#include <locale.h>

#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>
#include <sys/lx_stat.h>
#include <sys/lx_statfs.h>
#include <sys/lx_ioctl.h>
#include <sys/lx_signal.h>
#include <sys/lx_syscall.h>
#include <sys/lx_thread.h>
#include <sys/lx_thunk_server.h>

/*
 * General emulation guidelines.
 *
 * Once the emulation handler has been installed onto the process, we need to
 * be concerned about system calls made by the emulation, as well as any
 * library calls which in turn make system calls. This is actually only an
 * issue for the 64-bit case, since the kernel sycall entry point is common for
 * both Illumos and Linux. The trampoline code in the kernel needs some way to
 * distinguish when it should bounce out for emulation (Linux system call) vs.
 * stay in the kernel (emulation system call). For the 32-bit case Linux uses
 * int80 for system calls which is orthogonal to all of the Illumos system call
 * entry points and thus there is no issue.
 *
 * To cope with this for the 64-bit case, we maintain a mode flag on each
 * LWP so we can tell when a system call comes from Linux. We then set the mode
 * flag to Illumos so that all future system calls from the emulation are
 * handled correctly. The emulation must reset the mode when it is ready to
 * return control to Linux. This is done via the B_CLR_NTV_SYSC_FLAG brand
 * call. There is additional complexity with this mode switching in the
 * case of a user-defined signal handler. This is described in the signal
 * emulation code comments.
 *
 * *** Setting errno
 *
 * This emulation library is loaded onto a seperate link map from the
 * application whose address space we're running in. The Linux libc errno is
 * independent of our native libc errno. To pass back an error the emulation
 * function should return -errno back to the Linux caller.
 *
 * *** General considerations
 *
 * The lx brand interposes on _all_ system calls. Linux system calls that need
 * special handling in the kernel are redirected back to the kernel via the
 * IN_KERNEL_EMULATION macro which uses a range of the brand system call
 * command number to determine which in-kernel lx function to invoke.
 *
 * *** DTrace
 *
 * The lx-syscall DTrace provider (see lx_systrace_attach in
 * uts/common/brand/lx/dtrace/lx_systrace.c) works as follows:
 *
 * When probes are enabled:
 *    lx_systrace_enable -> lx_brand_systrace_enable
 *
 * This enables the trace jump table in the kernel (see
 * uts/intel/brand/lx/lx_brand_asm.s which has the functions
 * lx_brand_int80_enable and lx_brand_syscall_enable, and the corresponding
 * patch points lx_brand_int80_patch_point and lx_brand_syscall_patch_point).
 *
 * The library code defines lx_handler_table and lx_handler_trace_table
 * in the i386 and amd64 lx_handler.s code.
 *
 * The trace jump table enables lx_traceflag which is used in the lx_emulate
 * function to make the B_SYSENTRY/B_SYSRETURN brandsys syscalls. These in turn
 * will call lx_systrace_entry_ptr/lx_systrace_return_ptr so that we can DTrace
 * the Linux syscalls via the provider.
 *
 * When probes are disbaled, we undo the patch points via:
 *    lx_systrace_disable -> lx_brand_systrace_disable
 */


/*
 * Map Illumos errno to the Linux equivalent.
 */
static int stol_errno[] = {
	0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
	10,  11,  12,  13,  14,  15,  16,  17,  18,  19,
	20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
	30,  31,  32,  33,  34,  42,  43,  44,  45,  46,
	47,  48,  49,  50,  51,  35,  47,  22,  38,  22, /* 49 */
	52,  53,  54,  55,  56,  57,  58,  59,  22,  22,
	61,  61,  62,  63,  64,  65,  66,  67,  68,  69,
	70,  71,  22,  22,  72,  22,  22,  74,  36,  75,
	76,  77,  78,  79,  80,  81,  82,  83,  84,  38,
	40,  85,  86,  39,  87,  88,  89,  90,  91,  92, /* 99 */
	22,  22,  22,  22,  22,  22,  22,  22,  22,  22,
	22,  22,  22,  22,  22,  22,  22,  22,  22,  22,
	93,  94,  95,  96,  97,  98,  99, 100, 101, 102,
	103, 104, 105, 106, 107,  22,  22,  22,  22,  22,
	22,  22,  22, 108, 109, 110, 111, 112, 113, 114, /* 149 */
	115, 116
};

char lx_release[LX_VERS_MAX];
char lx_cmd_name[MAXNAMLEN];

/*
 * Map a linux locale ending string to the solaris equivalent.
 */
struct lx_locale_ending {
	const char	*linux_end;	/* linux ending string */
	const char	*solaris_end;	/* to transform with this string */
	int		le_size;	/* linux ending string length */
	int		se_size;	/* solaris ending string length */
};

#define	l2s_locale(lname, sname) \
	{(lname), (sname), sizeof ((lname)) - 1, sizeof ((sname)) - 1}

#define	MAXLOCALENAMELEN	30
#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

/*
 * This flag is part of the registration with the in-kernel brand module. It's
 * used in lx_handler() to determine if we should go back into the kernel after
 * a system call in case the kernel needs to perform some post-syscall work
 * like tracing for example.
 */
int lx_traceflag;

/* Offsets for nosys_msgs */
#define	NOSYS_NULL		0
#define	NOSYS_NONE		1
#define	NOSYS_NO_EQUIV		2
#define	NOSYS_KERNEL		3
#define	NOSYS_UNDOC		4
#define	NOSYS_OBSOLETE		5

#if defined(_ILP32)
#define	EBP_HAS_ARG6		0x01
#endif

static char *nosys_msgs[] = {
	"Not done yet",
	"No such Linux system call",
	"No equivalent Solaris functionality",
	"Reads/modifies Linux kernel state",
	"Undocumented and/or rarely used system call",
	"Unsupported, obsolete system call"
};

/*
 * Most syscalls return an int but some return something else, typically a
 * ssize_t. This can be either an int or a long, depending on if we're compiled
 * for 32-bit or 64-bit. To correctly propagate the -errno return code in the
 * 64-bit case, we declare all emulation wrappers will return a long. Thus,
 * when we save the return value into the %eax or %rax register and return to
 * Linux, we will have the right size value in both the 32 and 64 bit cases.
 */

struct lx_sysent {
	char    *sy_name;
	long	(*sy_callc)();
	char	sy_flags;
	char	sy_narg;
};

static struct lx_sysent sysents[LX_NSYSCALLS + 1];

static uintptr_t stack_bottom;

#if defined(_LP64)
long lx_fsb;
long lx_fs;
#endif
int lx_install = 0;		/* install mode enabled if non-zero */
boolean_t lx_is_rpm = B_FALSE;
int lx_rpm_delay = 1;
int lx_strict = 0;		/* "strict" mode enabled if non-zero */
int lx_verbose = 0;		/* verbose mode enabled if non-zero */
int lx_debug_enabled = 0;	/* debugging output enabled if non-zero */

pid_t zoneinit_pid;		/* zone init PID */
long max_pid;			/* native maximum PID */

thread_key_t lx_tsd_key;

int
lx_errno(int err)
{
	if (err >= sizeof (stol_errno) / sizeof (stol_errno[0])) {
		lx_debug("invalid errno %d\n", err);
		assert(0);
	}

	return (stol_errno[err]);
}

int
uucopy_unsafe(const void *src, void *dst, size_t n)
{
	bcopy(src, dst, n);
	return (0);
}

int
uucopystr_unsafe(const void *src, void *dst, size_t n)
{
	(void) strncpy((char *)src, dst, n);
	return (0);
}

static void
i_lx_msg(int fd, char *msg, va_list ap)
{
	int	i;
	char	buf[LX_MSG_MAXLEN];

	/* LINTED [possible expansion issues] */
	i = vsnprintf(buf, sizeof (buf), msg, ap);
	buf[LX_MSG_MAXLEN - 1] = '\0';
	if (i == -1)
		return;

	/* if debugging is enabled, send this message to debug output */
	if (lx_debug_enabled != 0)
		lx_debug(buf);

	if (fd == 2) {
		/*
		 * We let the user choose whether or not to see these
		 * messages on the console.
		 */
		if (lx_verbose == 0)
			return;
	}

	/* we retry in case of EINTR */
	do {
		i = write(fd, buf, strlen(buf));
	} while ((i == -1) && (errno == EINTR));
}

/*PRINTFLIKE1*/
void
lx_err(char *msg, ...)
{
	va_list	ap;

	assert(msg != NULL);

	va_start(ap, msg);
	i_lx_msg(STDERR_FILENO, msg, ap);
	va_end(ap);
}

/*
 * This is just a non-zero exit value which also isn't one that would allow
 * us to easily detect if a branded process exited because of a recursive
 * fatal error.
 */
#define	LX_ERR_FATAL	42

/*
 * Our own custom version of abort(), this routine will be used in place
 * of the one located in libc.  The primary difference is that this version
 * will first reset the signal handler for SIGABRT to SIG_DFL, ensuring the
 * SIGABRT sent causes us to dump core and is not caught by a user program.
 */
void
abort(void)
{
	static int aborting = 0;

	struct sigaction sa;
	sigset_t sigmask;

	/* watch out for recursive calls to this function */
	if (aborting != 0)
		exit(LX_ERR_FATAL);

	aborting = 1;

	/*
	 * Block all signals here to avoid taking any signals while exiting
	 * in an effort to avoid any strange user interaction with our death.
	 */
	(void) sigfillset(&sigmask);
	(void) sigprocmask(SIG_BLOCK, &sigmask, NULL);

	/*
	 * Our own version of abort(3C) that we know will never call
	 * a user-installed SIGABRT handler first.  We WANT to die.
	 *
	 * Do this by resetting the handler to SIG_DFL, and releasing any
	 * held SIGABRTs.
	 *
	 * If no SIGABRTs are pending, send ourselves one.
	 *
	 * The while loop is a bit of overkill, but abort(3C) does it to
	 * assure it never returns so we will as well.
	 */
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = SIG_DFL;
	sa.sa_flags = 0;

	for (;;) {
		(void) sigaction(SIGABRT, &sa, NULL);
		(void) sigrelse(SIGABRT);
		(void) thr_kill(thr_self(), SIGABRT);
	}

	/*NOTREACHED*/
}

/*PRINTFLIKE1*/
void
lx_msg(char *msg, ...)
{
	va_list	ap;

	assert(msg != NULL);
	va_start(ap, msg);
	i_lx_msg(STDOUT_FILENO, msg, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
lx_err_fatal(char *msg, ...)
{
	va_list	ap;

	assert(msg != NULL);

	va_start(ap, msg);
	i_lx_msg(STDERR_FILENO, msg, ap);
	va_end(ap);
	abort();
}

/*
 * See if it is safe to alloca() sz bytes.  Return 1 for yes, 0 for no.
 */
int
lx_check_alloca(size_t sz)
{
	uintptr_t sp = (uintptr_t)&sz;
	uintptr_t end = sp - sz;

	return ((end < sp) && (end >= stack_bottom));
}

/*PRINTFLIKE1*/
void
lx_unsupported(char *msg, ...)
{
	va_list	ap;
	char dmsg[256];
	int lastc;

	assert(msg != NULL);

	/* make a brand call so we can easily dtrace unsupported actions */
	va_start(ap, msg);
	/* LINTED [possible expansion issues] */
	(void) vsnprintf(dmsg, sizeof (dmsg), msg, ap);
	dmsg[255] = '\0';
	lastc = strlen(dmsg) - 1;
	if (dmsg[lastc] == '\n')
		dmsg[lastc] = '\0';
	(void) syscall(SYS_brand, B_UNSUPPORTED, dmsg);
	va_end(ap);

	/* send the msg to the error stream */
	va_start(ap, msg);
	i_lx_msg(STDERR_FILENO, msg, ap);
	va_end(ap);

	/*
	 * If the user doesn't trust the application to responsibly
	 * handle ENOTSUP, we kill the application.
	 */
	if (lx_strict)
		(void) kill(getpid(), SIGSYS);
}

extern void lx_runexe(void *argv, void *entry);
int lx_init(int argc, char *argv[], char *envp[]);

static int
lx_emulate_args(lx_regs_t *rp, struct lx_sysent *s, uintptr_t *args)
{
#if defined(_LP64)
	/*
	 * Note: Syscall argument passing is different from function call
	 * argument passing on amd64.  For function calls, the fourth arg is
	 * passed via %rcx, but for system calls the 4th arg is passed via %r10.
	 * This is because in amd64, the syscall instruction puts the lower
	 * 32 bits of %rflags in %r11 and puts the %rip value to %rcx.
	 *
	 * Appendix A of the amd64 ABI (Linux conventions) states that syscalls
	 * are limited to 6 args and no arg is passed on the stack.
	 */
	args[0] = rp->lxr_rdi;
	args[1] = rp->lxr_rsi;
	args[2] = rp->lxr_rdx;
	args[3] = rp->lxr_r10;
	args[4] = rp->lxr_r8;
	args[5] = rp->lxr_r9;
#else
	/*
	 * If the system call takes 6 args, then libc has stashed them in
	 * memory at the address contained in %ebx. Except for some syscalls
	 * which store the 6th argument in %ebp.
	 */
	if (s->sy_narg == 6 && !(s->sy_flags & EBP_HAS_ARG6)) {
		if (uucopy((void *)rp->lxr_ebx, args,
		    sizeof (args[0]) * 6) != 0)
			return (-stol_errno[errno]);
	} else {
		args[0] = rp->lxr_ebx;
		args[1] = rp->lxr_ecx;
		args[2] = rp->lxr_edx;
		args[3] = rp->lxr_esi;
		args[4] = rp->lxr_edi;
		args[5] = rp->lxr_ebp;
	}
#endif

	return (0);
}

void
lx_emulate(lx_regs_t *rp)
{
	struct lx_sysent *s;
	uintptr_t args[6];
#if defined(_ILP32)
	uintptr_t gs = rp->lxr_gs & 0xffff;	/* %gs is only 16 bits */
#endif
	int syscall_num;
	long ret;

#if defined(_LP64)
	syscall_num = rp->lxr_rax;
#else
	syscall_num = rp->lxr_eax;
#endif

	/*
	 * lx_brand_int80_callback() or lx_brand_syscall_callback() ensures
	 * that the syscall_num is sane; Use it as is.
	 */
	assert(syscall_num >= 0);
	assert(syscall_num < (sizeof (sysents) / sizeof (sysents[0])));
	s = &sysents[syscall_num];

	if ((ret = lx_emulate_args(rp, s, args)) != 0)
		goto out;

	/*
	 * If the tracing flag is enabled we call into the brand-specific
	 * kernel module to handle the tracing activity (DTrace or ptrace).
	 * It would be tempting to perform DTrace activity in the brand
	 * module's syscall trap callback, rather than having to return
	 * to the kernel here, but -- since argument encoding can vary
	 * according to the specific system call -- that would require
	 * replicating the knowledge of argument decoding in the kernel
	 * module as well as here in the brand library.
	 */
	if (lx_traceflag != 0) {
		/*
		 * Part of the ptrace "interface" is that on syscall entry
		 * %rax / %eax should be reported as -ENOSYS while the
		 * orig_rax /  orig_eax field of the user structure needs to
		 * contain the actual system call number. If we end up stopping
		 * here, the controlling process will dig the lx_regs_t
		 * structure out of our stack.
		 */
#if defined(_LP64)
		rp->lxr_orig_rax = syscall_num;
		rp->lxr_rax = -stol_errno[ENOSYS];
#else
		rp->lxr_orig_eax = syscall_num;
		rp->lxr_eax = -stol_errno[ENOSYS];
#endif

		(void) syscall(SYS_brand, B_SYSENTRY, syscall_num, args);

		/*
		 * The external tracer may have modified the arguments to this
		 * system call. Refresh the argument cache to account for this.
		 */
		if ((ret = lx_emulate_args(rp, s, args)) != 0)
			goto out;
	}

	if (s->sy_callc == NULL) {
		lx_unsupported("unimplemented syscall #%d (%s): %s\n",
		    syscall_num, s->sy_name, nosys_msgs[(int)s->sy_flags]);
		ret = -stol_errno[ENOTSUP];
		goto out;
	}

	if (lx_debug_enabled != 0) {
		const char *fmt = NULL;

		switch (s->sy_narg) {
		case 0:
			fmt = "calling %s()";
			break;
		case 1:
			fmt = "calling %s(0x%p)";
			break;
		case 2:
			fmt = "calling %s(0x%p, 0x%p)";
			break;
		case 3:
			fmt = "calling %s(0x%p, 0x%p, 0x%p)";
			break;
		case 4:
			fmt = "calling %s(0x%p, 0x%p, 0x%p, 0x%p)";
			break;
		case 5:
			fmt = "calling %s(0x%p, 0x%p, 0x%p, 0x%p, 0x%p)";
			break;
		case 6:
			fmt = "calling %s(0x%p, 0x%p, 0x%p, 0x%p, 0x%p, 0x%p)";
			break;
		}

		lx_debug(fmt, s->sy_name, args[0], args[1], args[2], args[3],
		    args[4], args[5]);
	}

	/*
	 * On 64-bit code, the %gs will be 0 in both native and Linux code.
	 */
#if defined(_ILP32)
	if (gs != LWPGS_SEL) {
		lx_tsd_t *lx_tsd;

		/*
		 * While a %gs of 0 is technically legal (as long as the
		 * application never dereferences memory using %gs), Solaris
		 * has its own ideas as to how a zero %gs should be handled in
		 * _update_sregs(), such that any 32-bit user process with a
		 * %gs of zero running on a system with a 64-bit kernel will
		 * have its %gs hidden base register stomped on on return from
		 * a system call, leaving an incorrect base address in place
		 * until the next time %gs is actually reloaded (forcing a
		 * reload of the base address from the appropriate descriptor
		 * table.)
		 *
		 * Of course the kernel will once again stomp on THAT base
		 * address when returning from a system call, resulting in an
		 * an application segmentation fault.
		 *
		 * To avoid this situation, disallow a save of a zero %gs
		 * here in order to try and capture any Linux process that
		 * attempts to make a syscall with a zero %gs installed.
		 */
		assert(gs != 0);

		if ((ret = thr_getspecific(lx_tsd_key,
		    (void **)&lx_tsd)) != 0)
			lx_err_fatal("lx_emulate: unable to read "
			    "thread-specific data: %s", strerror(ret));

		assert(lx_tsd != 0);

		lx_tsd->lxtsd_gs = gs;

		lx_debug("lx_emulate(): gsp 0x%p, saved gs: 0x%x", lx_tsd, gs);
	}
#endif /* _ILP32 */

	ret = s->sy_callc(args[0], args[1], args[2], args[3], args[4],
	    args[5]);

	if (ret > -65536 && ret < 65536)
		lx_debug("\t= %d", ret);
	else
		lx_debug("\t= 0x%x", ret);

	/*
	 * If the return value is between -1 and -4095 then it's an errno, so
	 * we translate the Illumos error number into the Linux equivalent.
	 */
	if (ret < 0 && ret > -4096) {
		if (-ret >= sizeof (stol_errno) / sizeof (stol_errno[0])) {
			lx_debug("Invalid return value from emulated "
			    "syscall %d (%s): %d\n",
			    syscall_num, s->sy_name, ret);
			assert(0);
		}

		ret = -stol_errno[-ret];
	}

out:
	/*
	 * For 32-bit, %eax holds the return code from the system call. For
	 * 64-bit, %rax holds the return code.
	 */
#if defined(_LP64)
	rp->lxr_rax = ret;
#else
	rp->lxr_eax = ret;
#endif

	/*
	 * If the trace flag is set, bounce into the kernel to let it do
	 * any necessary tracing (DTrace or ptrace).
	 */
	if (lx_traceflag != 0) {
#if defined(_LP64)
		rp->lxr_orig_rax = syscall_num;
#else
		rp->lxr_orig_eax = syscall_num;
#endif
		(void) syscall(SYS_brand, B_SYSRETURN, syscall_num, ret);
	}

#if defined(_LP64)
	/*
	 * For 64-bit code this must be the last thing we do in the emulation
	 * code path before we return back to the Linux program. This will
	 * disable native syscalls so the next time a syscall happens on this
	 * thread, it will come back into the emulation. We can omit the extra
	 * syscall overhead in the 32-bit case.
	 */
	(void) syscall(SYS_brand, B_CLR_NTV_SYSC_FLAG);
#endif
}

static void
lx_close_fh(FILE *file)
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


extern int set_l10n_alternate_root(char *path);

#if defined(_LP64)
static void *
map_vdso()
{
	int fd;
	mmapobj_result_t	mpp[10]; /* we know the size of our lib */
	mmapobj_result_t	*smpp = mpp;
	uint_t			mapnum = 10;

	if ((fd = open("/native/usr/lib/brand/lx/amd64/lx_vdso.so.1",
	    O_RDONLY)) == -1)
		lx_err_fatal("couldn't open lx_vdso.so.1");

	if (mmapobj(fd, MMOBJ_INTERPRET, smpp, &mapnum, NULL) == -1)
		lx_err_fatal("couldn't mmapobj lx_vdso.so.1");

	(void) close(fd);

	/* assume first segment is the base of the mapping */
	return (smpp->mr_addr);
}
#endif

/*ARGSUSED*/
int
lx_init(int argc, char *argv[], char *envp[])
{
	char		*r;
	auxv_t		*ap;
	long		*p;
	int		err;
	lx_elf_data_t	edp;
	lx_brand_registration_t reg;
	static lx_tsd_t lx_tsd;
#if defined(_LP64)
	void		*vdso_hdr;
#endif

	stack_bottom = 2 * sysconf(_SC_PAGESIZE);

	/*
	 * We need to shutdown all libc stdio.  libc stdio normally goes to
	 * file descriptors, but since we're actually part of a linux
	 * process we don't own these file descriptors and we can't make
	 * any assumptions about their state.
	 */
	lx_close_fh(stdin);
	lx_close_fh(stdout);
	lx_close_fh(stderr);

	lx_debug_init();

	r = getenv("LX_RELEASE");
	if (r == NULL) {
		if (zone_getattr(getzoneid(), LX_KERN_VERSION_NUM, lx_release,
		    sizeof (lx_release)) != sizeof (lx_release))
			(void) strlcpy(lx_release, "2.4.21", LX_VERS_MAX);
	} else {
		(void) strlcpy(lx_release, r, 128);
	}

	lx_debug("lx_release: %s\n", lx_release);

	/*
	 * Should we kill an application that attempts an unimplemented
	 * system call?
	 */
	if (getenv("LX_STRICT") != NULL) {
		lx_strict = 1;
		lx_debug("STRICT mode enabled.\n");
	}

	/*
	 * Are we in install mode?
	 */
	if (getenv("LX_INSTALL") != NULL) {
		lx_install = 1;
		lx_debug("INSTALL mode enabled.\n");
	}

	/*
	 * Should we attempt to send messages to the screen?
	 */
	if (getenv("LX_VERBOSE") != NULL) {
		lx_verbose = 1;
		lx_debug("VERBOSE mode enabled.\n");
	}

	/* needed in wait4(), get it once since it never changes */
	max_pid = sysconf(_SC_MAXPID);

	(void) strlcpy(lx_cmd_name, basename(argv[0]), sizeof (lx_cmd_name));
	lx_debug("executing linux process: %s", argv[0]);
	lx_debug("branding myself and setting handler to 0x%p",
	    (void *)lx_handler_table);

	/*
	 * The version of rpm that ships with CentOS/RHEL 3.x has a race
	 * condition in it.  If it creates a child process to run a
	 * post-install script, and that child process completes too
	 * quickly, it will disappear before the parent notices.  This
	 * causes the parent to hang forever waiting for the already dead
	 * child to die.  I'm sure there's a Lazarus joke buried in here
	 * somewhere.
	 *
	 * Anyway, as a workaround, we make every child of an 'rpm' process
	 * sleep for 1 second, giving the parent a chance to enter its
	 * wait-for-the-child-to-die loop.  Thay may be the hackiest trick
	 * in all of our Linux emulation code - and that's saying
	 * something.
	 */
	if (strcmp("rpm", basename(argv[0])) == NULL)
		lx_is_rpm = B_TRUE;

	reg.lxbr_version = LX_VERSION;
	reg.lxbr_handler = (void *)&lx_handler_table;
	reg.lxbr_tracehandler = (void *)&lx_handler_trace_table;
	reg.lxbr_traceflag = (void *)&lx_traceflag;

	/*
	 * Register the address of the user-space handler with the lx brand
	 * module. As a side-effect this leaves the thread in native syscall
	 * mode so that it's ok to continue to make syscalls during setup. We
	 * need to switch to Linux mode at the end of initialization.
	 */
	if (syscall(SYS_brand, B_REGISTER, &reg))
		lx_err_fatal("failed to brand the process");

	/* Look up the PID that serves as init for this zone */
	if ((err = lx_lpid_to_spid(1, &zoneinit_pid)) < 0)
		lx_err_fatal("Unable to find PID for zone init process: %s",
		    strerror(err));

	/*
	 * Ubuntu init will fail if its TERM environment variable is not set
	 * so if we are running init, and TERM is not set, we set term and
	 * reexec so that the new environment variable is propagated to the
	 * linux application stack.
	 */
	if ((getpid() == zoneinit_pid) && (getenv("TERM") == NULL)) {
		if (setenv("TERM", "vt100", 1) < 0 || execv(argv[0], argv) < 0)
			lx_err_fatal("failed to set TERM");
	}

	/*
	 * Upload data about the lx executable from the kernel.
	 */
	if (syscall(SYS_brand, B_ELFDATA, (void *)&edp))
		lx_err_fatal("failed to get required ELF data from the kernel");

	if (lx_ioctl_init() != 0)
		lx_err_fatal("failed to setup the ioctl translator");

	if (lx_stat_init() != 0)
		lx_err_fatal("failed to setup the stat translator");

	if (lx_statfs_init() != 0)
		lx_err_fatal("failed to setup the statfs translator");

#if defined(_LP64)
	vdso_hdr = map_vdso();
#endif

	/*
	 * Find the aux vector on the stack.
	 */
	p = (long *)envp;
	while (*p != NULL)
		p++;
	/*
	 * p is now pointing at the 0 word after the environ pointers. After
	 * that is the aux vectors.
	 */
	p++;
	for (ap = (auxv_t *)p; ap->a_type != 0; ap++) {
		switch (ap->a_type) {
			case AT_BASE:
				ap->a_un.a_val = edp.ed_base;
				break;
			case AT_ENTRY:
				ap->a_un.a_val = edp.ed_entry;
				break;
			case AT_PHDR:
				ap->a_un.a_val = edp.ed_phdr;
				break;
			case AT_PHENT:
				ap->a_un.a_val = edp.ed_phent;
				break;
			case AT_PHNUM:
				ap->a_un.a_val = edp.ed_phnum;
				break;
#if defined(_LP64)
			case AT_SUN_BRAND_LX_SYSINFO_EHDR:
				ap->a_type = AT_SYSINFO_EHDR;
				ap->a_un.a_val = (long)vdso_hdr;
				break;
#endif
			default:
				break;
		}
	}

	/* Do any thunk server initalization. */
	lxt_server_init(argc, argv);

	/* Setup signal handler information. */
	if (lx_siginit())
		lx_err_fatal("failed to initialize lx signals for the "
		    "branded process");

	/* Setup thread-specific data area for managing linux threads. */
	if ((err = thr_keycreate(&lx_tsd_key, NULL)) != 0)
		lx_err_fatal("thr_keycreate(lx_tsd_key) failed: %s",
		    strerror(err));

	lx_debug("thr_keycreate created lx_tsd_key (%d)", lx_tsd_key);

	/* Initialize the thread specific data for this thread. */
	bzero(&lx_tsd, sizeof (lx_tsd));
#if defined(_ILP32)
	/* start with %gs having the native libc value */
	lx_tsd.lxtsd_gs = LWPGS_SEL;
#endif

	if ((err = thr_setspecific(lx_tsd_key, &lx_tsd)) != 0)
		lx_err_fatal("Unable to initialize thread-specific data: %s",
		    strerror(err));

	/*
	 * Save the current context of this thread.
	 * We'll restore this context when this thread attempts to exit.
	 */
	if (getcontext(&lx_tsd.lxtsd_exit_context) != 0)
		lx_err_fatal("Unable to initialize thread-specific exit "
		    "context: %s", strerror(errno));

	if (lx_tsd.lxtsd_exit == 0) {
#if defined(_LP64)
		/* Switch to Linux syscall mode */
		(void) syscall(SYS_brand, B_CLR_NTV_SYSC_FLAG);
#endif

		lx_runexe(argv, (void *)edp.ed_ldentry);
		/* lx_runexe() never returns. */
		assert(0);
	}

	/*
	 * We are here because the Linux application called the exit() or
	 * exit_group() system call.  In turn the brand library did a
	 * setcontext() to jump to the thread context state we saved above.
	 */
	if (lx_tsd.lxtsd_exit == 1)
		thr_exit((void *)(long)lx_tsd.lxtsd_exit_status);
	else
		exit(lx_tsd.lxtsd_exit_status);

	assert(0);

	/*NOTREACHED*/
	return (0);
}

/*
 * Walk back through the stack until we find the lx_emulate() frame.
 */
lx_regs_t *
lx_syscall_regs(void)
{
	/* LINTED - alignment */
	struct frame *fr = (struct frame *)_getfp();

	while (fr->fr_savpc != (uintptr_t)&lx_emulate_done) {
		fr = (struct frame *)fr->fr_savfp;
		assert(fr->fr_savpc != NULL);
	}

#if defined(_LP64)
	/*
	 * This is %rbp, update to be at the end of the frame for correct
	 * struct offsets. lx_emulate only takes one parameter, a pointer to
	 * lx_regs_t.
	 */
	return ((lx_regs_t *)(fr->fr_savfp - sizeof (lx_regs_t)));
#else
	return ((lx_regs_t *)((uintptr_t *)fr)[2]);
#endif
}

int
lx_lpid_to_spair(pid_t lpid, pid_t *spid, lwpid_t *slwp)
{
	pid_t pid;
	lwpid_t tid;

	if (lpid == 0) {
		pid = getpid();
		tid = thr_self();
	} else {
		if (syscall(SYS_brand, B_LPID_TO_SPAIR, lpid, &pid, &tid) < 0)
			return (-errno);

		/*
		 * If the returned pid is -1, that indicates we tried to
		 * look up the PID for init, but that process no longer
		 * exists.
		 */
		if (pid == -1)
			return (-ESRCH);
	}

	if (uucopy(&pid, spid, sizeof (pid_t)) != 0)
		return (-errno);

	if (uucopy(&tid, slwp, sizeof (lwpid_t)) != 0)
		return (-errno);

	return (0);
}

int
lx_lpid_to_spid(pid_t lpid, pid_t *spid)
{
	lwpid_t slwp;

	return (lx_lpid_to_spair(lpid, spid, &slwp));
}

char *
lx_fd_to_path(int fd, char *buf, int buf_size)
{
	char	path_proc[MAXPATHLEN];
	pid_t	pid;
	int	n;

	assert((buf != NULL) && (buf_size >= 0));

	if (fd < 0)
		return (NULL);

	if ((pid = getpid()) == -1)
		return (NULL);

	(void) snprintf(path_proc, MAXPATHLEN,
	    "/native/proc/%d/path/%d", pid, fd);

	if ((n = readlink(path_proc, buf, buf_size - 1)) == -1)
		return (NULL);
	buf[n] = '\0';

	return (buf);
}

/*
 * Create a translation function that calls an in-kernel emulation function
 * vectored through the brand's in-kernel translation table.
 */
#define	IN_KERNEL_EMULATION(name, num)					\
long									\
lx_##name(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,	\
	uintptr_t p5, uintptr_t p6)					\
{									\
	long r;								\
	lx_debug("\tsyscall %d re-vectoring to lx kernel module "	\
	    "for " #name "()", num);					\
	r = syscall(SYS_brand, B_IKE_SYSCALL + num,			\
	    p1, p2, p3, p4, p5, p6);					\
	return ((r == -1) ? -errno : r);				\
}

IN_KERNEL_EMULATION(kill, LX_EMUL_kill)
IN_KERNEL_EMULATION(pipe, LX_EMUL_pipe)
IN_KERNEL_EMULATION(brk, LX_EMUL_brk)
IN_KERNEL_EMULATION(getppid, LX_EMUL_getppid)
IN_KERNEL_EMULATION(sysinfo, LX_EMUL_sysinfo)
IN_KERNEL_EMULATION(modify_ldt, LX_EMUL_modify_ldt)
IN_KERNEL_EMULATION(setresuid16, LX_EMUL_setresuid16)
IN_KERNEL_EMULATION(setresgid16, LX_EMUL_setresgid16)
IN_KERNEL_EMULATION(setresuid, LX_EMUL_setresuid)
IN_KERNEL_EMULATION(setresgid, LX_EMUL_setresgid)
IN_KERNEL_EMULATION(gettid, LX_EMUL_gettid)
IN_KERNEL_EMULATION(tkill, LX_EMUL_tkill)
IN_KERNEL_EMULATION(futex, LX_EMUL_futex)
IN_KERNEL_EMULATION(set_thread_area, LX_EMUL_set_thread_area)
IN_KERNEL_EMULATION(get_thread_area, LX_EMUL_get_thread_area)
IN_KERNEL_EMULATION(set_tid_address, LX_EMUL_set_tid_address)
IN_KERNEL_EMULATION(arch_prctl, LX_EMUL_arch_prctl)
IN_KERNEL_EMULATION(tgkill, LX_EMUL_tgkill)
IN_KERNEL_EMULATION(read, LX_EMUL_read)

#if defined(_LP64)
/* The following is the 64-bit syscall table */

static struct lx_sysent sysents[] = {
	{"read",	lx_read,		0,		3}, /* 0 */
	{"write",	lx_write,		0,		3}, /* 1 */
	{"open",	lx_open,		0,		3}, /* 2 */
	{"close",	lx_close,		0,		1}, /* 3 */
	{"stat",	lx_stat64,		0,		2}, /* 4 */
	{"fstat",	lx_fstat64,		0,		2}, /* 5 */
	{"lstat",	lx_lstat64,		0,		2}, /* 6 */
	{"poll",	lx_poll,		0,		3}, /* 7 */
	{"lseek",	lx_lseek,		0,		3}, /* 8 */
	{"mmap",	lx_mmap,		0,		6}, /* 9 */
	{"mprotect",	lx_mprotect,		0,		3}, /* 10 */
	{"munmap",	lx_munmap,		0,		2}, /* 11 */
	{"brk",		lx_brk,			0,		1}, /* 12 */
	{"rt_sigaction", lx_rt_sigaction,	0,		4}, /* 13 */
	{"rt_sigprocmask", lx_rt_sigprocmask,	0,		4}, /* 14 */
	{"rt_sigreturn", lx_rt_sigreturn,	0,		0}, /* 15 */
	{"ioctl",	lx_ioctl,		0,		3}, /* 16 */
	{"pread64",	lx_pread,		0,		4}, /* 17 */
	{"pwrite64",	lx_pwrite,		0,		4}, /* 18 */
	{"readv",	lx_readv,		0,		3}, /* 19 */
	{"writev",	lx_writev,		0,		3}, /* 20 */
	{"access",	lx_access,		0,		2}, /* 21 */
	{"pipe",	lx_pipe,		0,		1}, /* 22 */
	{"select",	lx_select,		0,		5}, /* 23 */
	{"sched_yield",	lx_yield,		0,		0}, /* 24 */
	{"mremap",	lx_remap,		0,		5}, /* 25 */
	{"msync",	lx_msync,		0,		3}, /* 26 */
	{"mincore",	lx_mincore,		0,		3}, /* 27 */
	{"madvise",	lx_madvise,		0,		3}, /* 28 */
	{"shmget",	lx_shmget,		0,		3}, /* 29 */
	{"shmat",	lx_shmat,		0,		4}, /* 30 */
	{"shmctl",	lx_shmctl,		0,		3}, /* 31 */
	{"dup",		lx_dup,			0,		1}, /* 32 */
	{"dup2",	lx_dup2,		0,		2}, /* 33 */
	{"pause",	lx_pause,		0,		0}, /* 34 */
	{"nanosleep",	lx_nanosleep,		0,		2}, /* 35 */
	{"getitimer",	lx_getitimer,		0,		2}, /* 36 */
	{"alarm",	lx_alarm,		0,		1}, /* 37 */
	{"setitimer",	lx_setitimer,		0,		3}, /* 38 */
	{"getpid",	lx_getpid,		0,		0}, /* 39 */
	{"sendfile",	lx_sendfile64,		0,		4}, /* 40 */
	{"socket",	lx_socket,		0,		3}, /* 41 */
	{"connect",	lx_connect,		0,		3}, /* 42 */
	{"accept",	lx_accept,		0,		3}, /* 43 */
	{"sendto",	lx_sendto,		0,		6}, /* 44 */
	{"recvfrom",	lx_recvfrom,		0,		6}, /* 45 */
	{"sendmsg",	lx_sendmsg,		0,		3}, /* 46 */
	{"recvmsg",	lx_recvmsg,		0,		3}, /* 47 */
	{"shutdown",	lx_shutdown,		0,		2}, /* 48 */
	{"bind",	lx_bind,		0,		3}, /* 49 */
	{"listen",	lx_listen,		0,		2}, /* 50 */
	{"getsockname",	lx_getsockname,		0,		3}, /* 51 */
	{"getpeername",	lx_getpeername,		0,		3}, /* 52 */
	{"socketpair",	lx_socketpair,		0,		4}, /* 53 */
	{"setsockopt",	lx_setsockopt,		0,		5}, /* 54 */
	{"getsockopt",	lx_getsockopt,		0,		5}, /* 55 */
	{"clone",	lx_clone,		0,		5}, /* 56 */
	{"fork",	lx_fork,		0,		0}, /* 57 */
	{"vfork",	lx_vfork,		0,		0}, /* 58 */
	{"execve",	lx_execve,		0,		3}, /* 59 */
	{"exit",	lx_exit,		0,		1}, /* 60 */
	{"wait4",	lx_wait4,		0,		4}, /* 61 */
	{"kill",	lx_kill,		0,		2}, /* 62 */
	{"uname",	lx_uname,		0,		1}, /* 63 */
	{"semget",	lx_semget,		0,		3}, /* 64 */
	{"semop",	lx_semop,		0,		3}, /* 65 */
	{"semctl",	lx_semctl,		0,		4}, /* 66 */
	{"shmdt",	lx_shmdt,		0,		1}, /* 67 */
	{"msgget",	lx_msgget,		0,		2}, /* 68 */
	{"msgsnd",	lx_msgsnd,		0,		4}, /* 69 */
	{"msgrcv",	lx_msgrcv,		0,		5}, /* 70 */
	{"msgctl",	lx_msgctl,		0,		3}, /* 71 */
	{"fcntl",	lx_fcntl64,		0,		3}, /* 72 */
	{"flock",	lx_flock,		0,		2}, /* 73 */
	{"fsync",	lx_fsync,		0,		1}, /* 74 */
	{"fdatasync",	lx_fdatasync,		0,		1}, /* 75 */
	{"truncate",	lx_truncate,		0,		2}, /* 76 */
	{"ftruncate",	lx_ftruncate,		0,		2}, /* 77 */
	{"getdents",	lx_getdents,		0,		3}, /* 78 */
	{"getcwd",	lx_getcwd,		0,		2}, /* 79 */
	{"chdir",	lx_chdir,		0,		1}, /* 80 */
	{"fchdir",	lx_fchdir,		0,		1}, /* 81 */
	{"rename",	lx_rename,		0,		2}, /* 82 */
	{"mkdir",	lx_mkdir,		0,		2}, /* 83 */
	{"rmdir",	lx_rmdir,		0,		1}, /* 84 */
	{"creat",	lx_creat,		0,		2}, /* 85 */
	{"link",	lx_link,		0,		2}, /* 86 */
	{"unlink",	lx_unlink,		0,		1}, /* 87 */
	{"symlink",	lx_symlink,		0,		2}, /* 88 */
	{"readlink",	lx_readlink,		0,		3}, /* 89 */
	{"chmod",	lx_chmod,		0,		2}, /* 90 */
	{"fchmod",	lx_fchmod,		0,		2}, /* 91 */
	{"chown",	lx_chown,		0,		3}, /* 92 */
	{"fchown",	lx_fchown,		0,		3}, /* 93 */
	{"lchown",	lx_lchown,		0,		3}, /* 94 */
	{"umask",	lx_umask,		0,		1}, /* 95 */
	{"gettimeofday", lx_gettimeofday,	0,		2}, /* 96 */
	{"getrlimit",	lx_getrlimit,		0,		2}, /* 97 */
	{"getrusage",	lx_getrusage,		0,		2}, /* 98 */
	{"sysinfo",	lx_sysinfo,		0,		1}, /* 99 */
	{"times",	lx_times,		0,		1}, /* 100 */
	{"ptrace",	lx_ptrace,		0,		4}, /* 101 */
	{"getuid",	lx_getuid,		0,		0}, /* 102 */
	{"syslog",	lx_syslog,		0,		3}, /* 103 */
	{"getgid",	lx_getgid,		0,		0}, /* 104 */
	{"setuid",	lx_setuid,		0,		1}, /* 105 */
	{"setgid",	lx_setgid,		0,		1}, /* 106 */
	{"geteuid",	lx_geteuid,		0,		0}, /* 107 */
	{"getegid",	lx_getegid,		0,		0}, /* 108 */
	{"setpgid",	lx_setpgid,		0,		2}, /* 109 */
	{"getppid",	lx_getppid,		0,		0}, /* 110 */
	{"getpgrp",	lx_getpgrp,		0,		0}, /* 111 */
	{"setsid",	lx_setsid,		0,		0}, /* 112 */
	{"setreuid",	lx_setreuid,		0,		0}, /* 113 */
	{"setregid",	lx_setregid,		0,		0}, /* 114 */
	{"getgroups",	lx_getgroups,		0,		2}, /* 115 */
	{"setgroups",	lx_setgroups,		0,		2}, /* 116 */
	{"setresuid",	lx_setresuid,		0,		3}, /* 117 */
	{"getresuid",	lx_getresuid,		0,		3}, /* 118 */
	{"setresgid",	lx_setresgid,		0,		3}, /* 119 */
	{"getresgid",	lx_getresgid,		0,		3}, /* 120 */
	{"getpgid",	lx_getpgid,		0,		1}, /* 121 */
	{"setfsuid",	lx_setfsuid,		0,		1}, /* 122 */
	{"setfsgid",	lx_setfsgid,		0,		1}, /* 123 */
	{"getsid",	lx_getsid,		0,		1}, /* 124 */
	{"capget",	lx_capget,		0,		2}, /* 125 */
	{"capset",	lx_capset,		0,		2}, /* 126 */
	{"rt_sigpending", lx_rt_sigpending,	0,		2}, /* 127 */
	{"rt_sigtimedwait", lx_rt_sigtimedwait,	0,		4}, /* 128 */
	{"rt_sigqueueinfo", lx_rt_sigqueueinfo,	0,		3}, /* 129 */
	{"rt_sigsuspend", lx_rt_sigsuspend,	0,		2}, /* 130 */
	{"sigaltstack",	lx_sigaltstack,		0,		2}, /* 131 */
	{"utime",	lx_utime,		0,		2}, /* 132 */
	{"mknod",	lx_mknod,		0,		3}, /* 133 */
	{"uselib",	NULL,			NOSYS_KERNEL,	0}, /* 134 */
	{"personality",	lx_personality,		0,		1}, /* 135 */
	{"ustat",	NULL,			NOSYS_OBSOLETE,	2}, /* 136 */
	{"statfs",	lx_statfs,		0,		2}, /* 137 */
	{"fstatfs",	lx_fstatfs,		0,		2}, /* 138 */
	{"sysfs",	lx_sysfs, 		0,		3}, /* 139 */
	{"getpriority",	lx_getpriority,		0,		2}, /* 140 */
	{"setpriority",	lx_setpriority,		0,		3}, /* 141 */
	{"sched_setparam", lx_sched_setparam,	0,		2}, /* 142 */
	{"sched_getparam", lx_sched_getparam,	0,		2}, /* 143 */
	{"sched_setscheduler", lx_sched_setscheduler, 0,	3}, /* 144 */
	{"sched_getscheduler", lx_sched_getscheduler, 0,	1}, /* 145 */
	{"sched_get_priority_max", lx_sched_get_priority_max, 0, 1}, /* 146 */
	{"sched_get_priority_min", lx_sched_get_priority_min, 0, 1}, /* 147 */
	{"sched_rr_get_interval", lx_sched_rr_get_interval, 0, 2},  /* 148 */
	{"mlock",	lx_mlock,		0,		2}, /* 149 */
	{"munlock",	lx_munlock,		0,		2}, /* 150 */
	{"mlockall",	lx_mlockall,		0,		1}, /* 151 */
	{"munlockall",	lx_munlockall,		0,		0}, /* 152 */
	{"vhangup",	lx_vhangup,		0,		0}, /* 153 */
	{"modify_ldt",	lx_modify_ldt,		0,		3}, /* 154 */
	{"pivot_root",	NULL,			NOSYS_KERNEL,	0}, /* 155 */
	{"sysctl",	lx_sysctl,		0,		1}, /* 156 */
	{"prctl",	lx_prctl,		0,		5}, /* 157 */
	{"arch_prctl",	lx_arch_prctl,		0,		2}, /* 158 */
	{"adjtimex",	lx_adjtimex,		0,		1}, /* 159 */
	{"setrlimit",	lx_setrlimit,		0,		2}, /* 160 */
	{"chroot",	lx_chroot,		0,		1}, /* 161 */
	{"sync",	lx_sync,		0,		0}, /* 162 */
	{"acct",	NULL,			NOSYS_NO_EQUIV,	0}, /* 163 */
	{"settimeofday", lx_settimeofday,	0,		2}, /* 164 */
	{"mount",	lx_mount,		0,		5}, /* 165 */
	{"umount2",	lx_umount2,		0,		2}, /* 166 */
	{"swapon",	NULL,			NOSYS_KERNEL,	0}, /* 167 */
	{"swapoff",	NULL,			NOSYS_KERNEL,	0}, /* 168 */
	{"reboot",	lx_reboot,		0,		4}, /* 169 */
	{"sethostname",	lx_sethostname,		0,		2}, /* 170 */
	{"setdomainname", lx_setdomainname,	0,		2}, /* 171 */
	{"iopl",	NULL,			NOSYS_NO_EQUIV,	0}, /* 172 */
	{"ioperm",	NULL,			NOSYS_NO_EQUIV,	0}, /* 173 */
	{"create_module", NULL,			NOSYS_KERNEL,	0}, /* 174 */
	{"init_module",	NULL,			NOSYS_KERNEL,	0}, /* 175 */
	{"delete_module", NULL,			NOSYS_KERNEL,	0}, /* 176 */
	{"get_kernel_syms", NULL,		NOSYS_KERNEL,	0}, /* 177 */
	{"query_module", lx_query_module,	NOSYS_KERNEL,	5}, /* 178 */
	{"quotactl",	NULL,			NOSYS_KERNEL,	0}, /* 179 */
	{"nfsservctl",	NULL,			NOSYS_KERNEL,	0}, /* 180 */
	{"getpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 181 */
	{"putpmsg",	NULL,			NOSYS_OBSOLETE,	0}, /* 182 */
	{"afs_syscall",	NULL,			NOSYS_KERNEL,	0}, /* 183 */
	{"tux",		NULL,			NOSYS_NO_EQUIV,	0}, /* 184 */
	{"security",	NULL,			NOSYS_NO_EQUIV,	0}, /* 185 */
	{"gettid",	lx_gettid,		0,		0}, /* 186 */
	{"readahead",	NULL,			NOSYS_NO_EQUIV,	0}, /* 187 */
	{"setxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 188 */
	{"lsetxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 189 */
	{"fsetxattr",	NULL,			NOSYS_NO_EQUIV,	0}, /* 190 */
	{"getxattr",	lx_xattr4,		0,		4}, /* 191 */
	{"lgetxattr",	lx_xattr4,		0,		4}, /* 192 */
	{"fgetxattr",	lx_xattr4,		0,		4}, /* 193 */
	{"listxattr",	lx_xattr3,		0,		3}, /* 194 */
	{"llistxattr",	lx_xattr3,		0,		3}, /* 195 */
	{"flistxattr",	lx_xattr3,		0,		3}, /* 196 */
	{"removexattr",	lx_xattr2,		0,		2}, /* 197 */
	{"lremovexattr", lx_xattr2,		0,		2}, /* 198 */
	{"fremovexattr", lx_xattr2,		0,		2}, /* 199 */
	{"tkill",	lx_tkill,		0,		2}, /* 200 */
	{"time",	lx_time,		0,		1}, /* 201 */
	{"futex",	lx_futex,		0,		6}, /* 202 */
	{"sched_setaffinity", lx_sched_setaffinity, 0,		3}, /* 203 */
	{"sched_getaffinity", lx_sched_getaffinity, 0,		3}, /* 204 */
	{"set_thread_area", lx_set_thread_area,	0,		1}, /* 205 */
	{"io_setup",	NULL,			NOSYS_NO_EQUIV,	0}, /* 206 */
	{"io_destroy",	NULL,			NOSYS_NO_EQUIV,	0}, /* 207 */
	{"io_getevents", NULL,			NOSYS_NO_EQUIV,	0}, /* 208 */
	{"io_submit",	NULL,			NOSYS_NO_EQUIV,	0}, /* 209 */
	{"io_cancel",	NULL,			NOSYS_NO_EQUIV,	0}, /* 210 */
	{"get_thread_area", lx_get_thread_area,	0,		1}, /* 211 */
	{"lookup_dcookie", NULL,		NOSYS_NO_EQUIV,	0}, /* 212 */
	{"epoll_create", lx_epoll_create,	0,		1}, /* 213 */
	{"epoll_ctl_old", NULL,			NOSYS_NULL,	0}, /* 214 */
	{"epoll_wait_old", NULL,		NOSYS_NULL,	0}, /* 215 */
	{"remap_file_pages", NULL,		NOSYS_NO_EQUIV,	0}, /* 216 */
	{"getdents64",	lx_getdents64,		0,		3}, /* 217 */
	{"set_tid_address", lx_set_tid_address, 0,		1}, /* 218 */
	{"restart_syscall", NULL,		NOSYS_NULL,	0}, /* 219 */
	{"semtimedop",	lx_semtimedop,		0,		4}, /* 220 */
	{"fadvise64",	lx_fadvise64_64,	0,		4}, /* 221 */
	{"timer_create", NULL,			NOSYS_UNDOC,	0}, /* 222 */
	{"timer_settime", NULL,			NOSYS_UNDOC,	0}, /* 223 */
	{"timer_gettime", NULL,			NOSYS_UNDOC,	0}, /* 224 */
	{"timer_getoverrun", NULL,		NOSYS_UNDOC,	0}, /* 225 */
	{"timer_delete", NULL,			NOSYS_UNDOC,	0}, /* 226 */
	{"clock_settime", lx_clock_settime,	0,		2}, /* 227 */
	{"clock_gettime", lx_clock_gettime,	0,		2}, /* 228 */
	{"clock_getres", lx_clock_getres,	0,		2}, /* 229 */
	{"clock_nanosleep", lx_clock_nanosleep,	0,		4}, /* 230 */
	{"exit_group",	lx_group_exit,		0,		1}, /* 231 */
	{"epoll_wait",	lx_epoll_wait,		0,		4}, /* 232 */
	{"epoll_ctl",	lx_epoll_ctl,		0,		4}, /* 233 */
	{"tgkill",	lx_tgkill,		0,		3}, /* 234 */
	{"utimes",	lx_utimes,		0,		2}, /* 235 */
	{"vserver",	NULL,			NOSYS_NULL,	0}, /* 236 */
	{"mbind",	NULL,			NOSYS_NULL,	0}, /* 237 */
	{"set_mempolicy", NULL,			NOSYS_NULL,	0}, /* 238 */
	{"get_mempolicy", NULL,			NOSYS_NULL,	0}, /* 239 */
	{"mq_open",	NULL,			NOSYS_NULL,	0}, /* 240 */
	{"mq_unlink",	NULL,			NOSYS_NULL,	0}, /* 241 */
	{"mq_timedsend", NULL,			NOSYS_NULL,	0}, /* 242 */
	{"mq_timedreceive", NULL,		NOSYS_NULL,	0}, /* 243 */
	{"mq_notify",	NULL,			NOSYS_NULL,	0}, /* 244 */
	{"mq_getsetattr", NULL,			NOSYS_NULL,	0}, /* 245 */
	{"kexec_load",	NULL,			NOSYS_NULL,	0}, /* 246 */
	{"waitid",	lx_waitid,		0,		4}, /* 247 */
	{"add_key",	NULL,			NOSYS_NULL,	0}, /* 248 */
	{"request_key",	NULL,			NOSYS_NULL,	0}, /* 249 */
	{"keyctl",	NULL,			NOSYS_NULL,	0}, /* 250 */
	{"ioprio_set",	NULL,			NOSYS_NULL,	0}, /* 251 */
	{"ioprio_get",	NULL,			NOSYS_NULL,	0}, /* 252 */
	{"inotify_init", lx_inotify_init,	0,		0}, /* 253 */
	{"inotify_add_watch", lx_inotify_add_watch, 0,		3}, /* 254 */
	{"inotify_rm_watch", lx_inotify_rm_watch, 0,		2}, /* 255 */
	{"migrate_pages", NULL,			NOSYS_NULL,	0}, /* 256 */
	{"openat",	lx_openat,		0,		4}, /* 257 */
	{"mkdirat",	lx_mkdirat,		0,		3}, /* 258 */
	{"mknodat",	lx_mknodat,		0,		4}, /* 259 */
	{"fchownat",	lx_fchownat,		0,		5}, /* 260 */
	{"futimesat",	lx_futimesat,		0,		3}, /* 261 */
	{"fstatat64",	lx_fstatat64,		0,		4}, /* 262 */
	{"unlinkat",	lx_unlinkat,		0,		3}, /* 263 */
	{"renameat",	lx_renameat,		0,		4}, /* 264 */
	{"linkat",	lx_linkat,		0,		5}, /* 265 */
	{"symlinkat",	lx_symlinkat,		0,		3}, /* 266 */
	{"readlinkat",	lx_readlinkat,		0,		4}, /* 267 */
	{"fchmodat",	lx_fchmodat,		0,		4}, /* 268 */
	{"faccessat",	lx_faccessat,		0,		4}, /* 269 */
	{"pselect6",	lx_pselect6,		0,		6}, /* 270 */
	{"ppoll",	NULL,			NOSYS_NULL,	0}, /* 271 */
	{"unshare",	NULL,			NOSYS_NULL,	0}, /* 272 */
	{"set_robust_list", NULL,		NOSYS_NULL,	0}, /* 273 */
	{"get_robust_list", NULL,		NOSYS_NULL,	0}, /* 274 */
	{"splice",	NULL,			NOSYS_NULL,	0}, /* 275 */
	{"tee",		NULL,			NOSYS_NULL,	0}, /* 276 */
	{"sync_file_range", NULL,		NOSYS_NULL,	0}, /* 277 */
	{"vmsplice",	NULL,			NOSYS_NULL,	0}, /* 278 */
	{"move_pages",	NULL,			NOSYS_NULL,	0}, /* 279 */
	{"utimensat",	lx_utimensat,		0,		4}, /* 280 */
	{"epoll_pwait",	lx_epoll_pwait,		0,		5}, /* 281 */
	{"signalfd",	NULL,			NOSYS_NULL,	0}, /* 282 */
	{"timerfd_create", NULL,		NOSYS_NULL,	0}, /* 283 */
	{"eventfd",	NULL,			NOSYS_NULL,	0}, /* 284 */
	{"fallocate",	NULL,			NOSYS_NULL,	0}, /* 285 */
	{"timerfd_settime", NULL,		NOSYS_NULL,	0}, /* 286 */
	{"timerfd_gettime", NULL,		NOSYS_NULL,	0}, /* 287 */
	{"accept4",	lx_accept4,		0,		4}, /* 288 */
	{"signalfd4",	NULL,			NOSYS_NULL,	0}, /* 289 */
	{"eventfd2",	NULL,			NOSYS_NULL,	0}, /* 290 */
	{"epoll_create1", lx_epoll_create1,	0,		1}, /* 291 */
	{"dup3",	lx_dup3,		0,		3}, /* 292 */
	{"pipe2",	lx_pipe2,		0,		2}, /* 293 */
	{"inotify_init1", lx_inotify_init1,	0,		1}, /* 294 */
	{"preadv",	NULL,			NOSYS_NULL,	0}, /* 295 */
	{"pwritev",	NULL,			NOSYS_NULL,	0}, /* 296 */
	{"rt_tgsigqueueinfo", lx_rt_tgsigqueueinfo, 0,		4}, /* 297 */
	{"perf_event_open", NULL,		NOSYS_NULL,	0}, /* 298 */
	{"recvmmsg",	NULL,			NOSYS_NULL,	0}, /* 299 */
	{"fanotify_init", NULL,			NOSYS_NULL,	0}, /* 300 */
	{"fanotify_mark", NULL,			NOSYS_NULL,	0}, /* 301 */
	{"prlimit64",	lx_prlimit64,		0,		4}, /* 302 */
	{"name_to_handle_at", NULL,		NOSYS_NULL,	0}, /* 303 */
	{"open_by_handle_at", NULL,		NOSYS_NULL,	0}, /* 304 */
	{"clock_adjtime", NULL,			NOSYS_NULL,	0}, /* 305 */
	{"syncfs",	NULL,			NOSYS_NULL,	0}, /* 306 */
	{"sendmmsg",	NULL,			NOSYS_NULL,	0}, /* 307 */
	{"setns",	NULL,			NOSYS_NULL,	0}, /* 309 */
	{"getcpu",	lx_getcpu,		0,		3}, /* 309 */
	{"process_vm_readv", NULL,		NOSYS_NULL,	0}, /* 310 */
	{"process_vm_writev", NULL,		NOSYS_NULL,	0}, /* 311 */
	{"kcmp",	NULL,			NOSYS_NULL,	0}, /* 312 */
	{"finit_module", NULL,			NOSYS_NULL,	0}, /* 313 */
	{"sched_setattr", NULL,			NOSYS_NULL,	0}, /* 314 */
	{"sched_getattr", NULL,			NOSYS_NULL,	0}, /* 315 */
	{"renameat2", NULL,			NOSYS_NULL,	0}, /* 316 */

	/* XXX TBD gap then x32 syscalls from 512 - 544 */
};

#else
/* The following is the 32-bit syscall table */

static struct lx_sysent sysents[] = {
	{"nosys",	NULL,		NOSYS_NONE,	0},	/*  0 */
	{"exit",	lx_exit,	0,		1},	/*  1 */
	{"fork",	lx_fork,	0,		0},	/*  2 */
	{"read",	lx_read,	0,		3},	/*  3 */
	{"write",	lx_write,	0,		3},	/*  4 */
	{"open",	lx_open,	0,		3},	/*  5 */
	{"close",	lx_close,	0,		1},	/*  6 */
	{"waitpid",	lx_waitpid,	0,		3},	/*  7 */
	{"creat",	lx_creat,	0,		2},	/*  8 */
	{"link",	lx_link,	0,		2},	/*  9 */
	{"unlink",	lx_unlink,	0,		1},	/* 10 */
	{"execve",	lx_execve,	0,		3},	/* 11 */
	{"chdir",	lx_chdir,	0,		1},	/* 12 */
	{"time",	lx_time,	0,		1},	/* 13 */
	{"mknod",	lx_mknod,	0,		3},	/* 14 */
	{"chmod",	lx_chmod,	0,		2},	/* 15 */
	{"lchown16",	lx_lchown16,	0,		3},	/* 16 */
	{"break",	NULL,		NOSYS_OBSOLETE,	0},	/* 17 */
	{"stat",	NULL,		NOSYS_OBSOLETE,	0},	/* 18 */
	{"lseek",	lx_lseek,	0,		3},	/* 19 */
	{"getpid",	lx_getpid,	0,		0},	/* 20 */
	{"mount",	lx_mount,	0,		5},	/* 21 */
	{"umount",	lx_umount,	0,		1},	/* 22 */
	{"setuid16",	lx_setuid16,	0,		1},	/* 23 */
	{"getuid16",	lx_getuid16,	0,		0},	/* 24 */
	{"stime",	lx_stime,	0,		1},	/* 25 */
	{"ptrace",	lx_ptrace,	0,		4},	/* 26 */
	{"alarm",	lx_alarm,	0,		1},	/* 27 */
	{"fstat",	NULL,		NOSYS_OBSOLETE,	0},	/* 28 */
	{"pause",	lx_pause,	0,		0},	/* 29 */
	{"utime",	lx_utime,	0,		2},	/* 30 */
	{"stty",	NULL,		NOSYS_OBSOLETE,	0},	/* 31 */
	{"gtty",	NULL,		NOSYS_OBSOLETE,	0},	/* 32 */
	{"access",	lx_access,	0,		2},	/* 33 */
	{"nice",	lx_nice,	0,		1},	/* 34 */
	{"ftime",	NULL,		NOSYS_OBSOLETE,	0},	/* 35 */
	{"sync",	lx_sync, 	0, 		0},	/* 36 */
	{"kill",	lx_kill,	0,		2},	/* 37 */
	{"rename",	lx_rename,	0,		2},	/* 38 */
	{"mkdir",	lx_mkdir,	0,		2},	/* 39 */
	{"rmdir",	lx_rmdir,	0,		1},	/* 40 */
	{"dup",		lx_dup,		0,		1},	/* 41 */
	{"pipe",	lx_pipe,	0,		1},	/* 42 */
	{"times",	lx_times,	0,		1},	/* 43 */
	{"prof",	NULL,		NOSYS_OBSOLETE,	0},	/* 44 */
	{"brk",		lx_brk,		0,		1},	/* 45 */
	{"setgid16",	lx_setgid16,	0,		1},	/* 46 */
	{"getgid16",	lx_getgid16,	0,		0},	/* 47 */
	{"signal",	lx_signal,	0,		2},	/* 48 */
	{"geteuid16",	lx_geteuid16,	0,		0},	/* 49 */
	{"getegid16",	lx_getegid16,	0,		0},	/* 50 */
	{"acct",	NULL,		NOSYS_NO_EQUIV,	0},	/* 51 */
	{"umount2",	lx_umount2,	0,		2},	/* 52 */
	{"lock",	NULL,		NOSYS_OBSOLETE,	0},	/* 53 */
	{"ioctl",	lx_ioctl,	0,		3},	/* 54 */
	{"fcntl",	lx_fcntl,	0,		3},	/* 55 */
	{"mpx",		NULL,		NOSYS_OBSOLETE,	0},	/* 56 */
	{"setpgid",	lx_setpgid,	0,		2},	/* 57 */
	{"ulimit",	NULL,		NOSYS_OBSOLETE,	0},	/* 58 */
	{"olduname",	NULL,		NOSYS_OBSOLETE,	0},	/* 59 */
	{"umask",	lx_umask,	0,		1},	/* 60 */
	{"chroot",	lx_chroot,	0,		1},	/* 61 */
	{"ustat",	NULL,		NOSYS_OBSOLETE,	2},	/* 62 */
	{"dup2",	lx_dup2,	0,		2},	/* 63 */
	{"getppid",	lx_getppid,	0,		0},	/* 64 */
	{"getpgrp",	lx_getpgrp,	0,		0},	/* 65 */
	{"setsid",	lx_setsid,	0,		0},	/* 66 */
	{"sigaction",	lx_sigaction,	0,		3},	/* 67 */
	{"sgetmask",	NULL,		NOSYS_OBSOLETE,	0},	/* 68 */
	{"ssetmask",	NULL,		NOSYS_OBSOLETE,	0},	/* 69 */
	{"setreuid16",	lx_setreuid16,	0,		2},	/* 70 */
	{"setregid16",	lx_setregid16,	0,		2},	/* 71 */
	{"sigsuspend",	lx_sigsuspend,	0,		1},	/* 72 */
	{"sigpending",	lx_sigpending,	0,		1},	/* 73 */
	{"sethostname",	lx_sethostname,	0,		2},	/* 74 */
	{"setrlimit",	lx_setrlimit,	0,		2},	/* 75 */
	{"getrlimit",	lx_oldgetrlimit, 0,		2},	/* 76 */
	{"getrusage",	lx_getrusage,	0,		2},	/* 77 */
	{"gettimeofday", lx_gettimeofday, 0,		2},	/* 78 */
	{"settimeofday", lx_settimeofday, 0,		2},	/* 79 */
	{"getgroups16",	lx_getgroups16,	0,		2},	/* 80 */
	{"setgroups16",	lx_setgroups16,	0,		2},	/* 81 */
	{"select",	NULL,		NOSYS_OBSOLETE,	0},	/* 82 */
	{"symlink",	lx_symlink,	0,		2},	/* 83 */
	{"oldlstat",	NULL,		NOSYS_OBSOLETE,	0},	/* 84 */
	{"readlink",	lx_readlink,	0,		3},	/* 85 */
	{"uselib",	NULL,		NOSYS_KERNEL,	0},	/* 86 */
	{"swapon",	NULL,		NOSYS_KERNEL,	0},	/* 87 */
	{"reboot",	lx_reboot,	0,		4},	/* 88 */
	{"readdir",	lx_readdir,	0,		3},	/* 89 */
	{"mmap",	lx_mmap,	0,		6},	/* 90 */
	{"munmap",	lx_munmap,	0,		2},	/* 91 */
	{"truncate",	lx_truncate,	0,		2},	/* 92 */
	{"ftruncate",	lx_ftruncate,	0,		2},	/* 93 */
	{"fchmod",	lx_fchmod,	0,		2},	/* 94 */
	{"fchown16",	lx_fchown16,	0,		3},	/* 95 */
	{"getpriority",	lx_getpriority,	0,		2},	/* 96 */
	{"setpriority",	lx_setpriority,	0,		3},	/* 97 */
	{"profil",	NULL,		NOSYS_NO_EQUIV,	0},	/* 98 */
	{"statfs",	lx_statfs,	0,		2},	/* 99 */
	{"fstatfs",	lx_fstatfs,	0,		2},	/* 100 */
	{"ioperm",	NULL,		NOSYS_NO_EQUIV,	0},	/* 101 */
	{"socketcall",	lx_socketcall,	0,		2},	/* 102 */
	{"syslog",	lx_syslog,	0,		3},	/* 103 */
	{"setitimer",	lx_setitimer,	0,		3},	/* 104 */
	{"getitimer",	lx_getitimer,	0,		2},	/* 105 */
	{"stat",	lx_stat,	0,		2},	/* 106 */
	{"lstat",	lx_lstat,	0,		2},	/* 107 */
	{"fstat",	lx_fstat,	0,		2},	/* 108 */
	{"uname",	NULL,		NOSYS_OBSOLETE,	0},	/* 109 */
	{"oldiopl",	NULL,		NOSYS_NO_EQUIV,	0},	/* 110 */
	{"vhangup",	lx_vhangup,	0,		0},	/* 111 */
	{"idle",	NULL,		NOSYS_NO_EQUIV,	0},	/* 112 */
	{"vm86old",	NULL,		NOSYS_OBSOLETE,	0},	/* 113 */
	{"wait4",	lx_wait4,	0,		4},	/* 114 */
	{"swapoff",	NULL,		NOSYS_KERNEL,	0},	/* 115 */
	{"sysinfo",	lx_sysinfo32,	0,		1},	/* 116 */
	{"ipc",		lx_ipc,		0,		5},	/* 117 */
	{"fsync",	lx_fsync,	0,		1},	/* 118 */
	{"sigreturn",	lx_sigreturn,	0,		1},	/* 119 */
	{"clone",	lx_clone,	0,		5},	/* 120 */
	{"setdomainname", lx_setdomainname, 0,		2},	/* 121 */
	{"uname",	lx_uname,	0,		1},	/* 122 */
	{"modify_ldt",	lx_modify_ldt,	0,		3},	/* 123 */
	{"adjtimex",	lx_adjtimex,	0,		1},	/* 124 */
	{"mprotect",	lx_mprotect,	0,		3},	/* 125 */
	{"sigprocmask",	lx_sigprocmask,	0,		3},	/* 126 */
	{"create_module", NULL,		NOSYS_KERNEL,	0},	/* 127 */
	{"init_module",	NULL,		NOSYS_KERNEL,	0},	/* 128 */
	{"delete_module", NULL,		NOSYS_KERNEL,	0},	/* 129 */
	{"get_kernel_syms", NULL,	NOSYS_KERNEL,	0},	/* 130 */
	{"quotactl",	NULL,		NOSYS_KERNEL,	0},	/* 131 */
	{"getpgid",	lx_getpgid,	0,		1},	/* 132 */
	{"fchdir",	lx_fchdir,	0,		1},	/* 133 */
	{"bdflush",	NULL,		NOSYS_KERNEL,	0},	/* 134 */
	{"sysfs",	lx_sysfs, 	0,		3},	/* 135 */
	{"personality",	lx_personality,	0,		1},	/* 136 */
	{"afs_syscall",	NULL,		NOSYS_KERNEL,	0},	/* 137 */
	{"setfsuid16",	lx_setfsuid16,	0,		1},	/* 138 */
	{"setfsgid16",	lx_setfsgid16,	0,		1},	/* 139 */
	{"llseek",	lx_llseek,	0,		5},	/* 140 */
	{"getdents",	lx_getdents,	0,		3},	/* 141 */
	{"select",	lx_select,	0,		5},	/* 142 */
	{"flock",	lx_flock,	0,		2},	/* 143 */
	{"msync",	lx_msync,	0,		3},	/* 144 */
	{"readv",	lx_readv,	0,		3},	/* 145 */
	{"writev",	lx_writev,	0,		3},	/* 146 */
	{"getsid",	lx_getsid,	0,		1},	/* 147 */
	{"fdatasync",	lx_fdatasync,	0,		1},	/* 148 */
	{"sysctl",	lx_sysctl,	0,		1},	/* 149 */
	{"mlock",	lx_mlock,	0,		2},	/* 150 */
	{"munlock",	lx_munlock,	0,		2},	/* 151 */
	{"mlockall",	lx_mlockall,	0,		1},	/* 152 */
	{"munlockall",	lx_munlockall,	0,		0},	/* 153 */
	{"sched_setparam", lx_sched_setparam,	0,	2},	/* 154 */
	{"sched_getparam", lx_sched_getparam,	0,	2},	/* 155 */
	{"sched_setscheduler", lx_sched_setscheduler, 0, 3},	/* 156 */
	{"sched_getscheduler", lx_sched_getscheduler, 0, 1},	/* 157 */
	{"sched_yield",	lx_yield,	0,		 0},	/* 158 */
	{"sched_get_priority_max", lx_sched_get_priority_max, 0, 1}, /* 159 */
	{"sched_get_priority_min", lx_sched_get_priority_min, 0, 1}, /* 160 */
	{"sched_rr_get_interval", lx_sched_rr_get_interval, 0,	2},  /* 161 */
	{"nanosleep",	lx_nanosleep,	0,		2},	/* 162 */
	{"mremap",	lx_remap,	0,		5},	/* 163 */
	{"setresuid16",	lx_setresuid16, 0,		3},	/* 164 */
	{"getresuid16",	lx_getresuid16,	0,		3},	/* 165 */
	{"vm86",	NULL,		NOSYS_NO_EQUIV,	0},	/* 166 */
	{"query_module", lx_query_module, NOSYS_KERNEL,	5},	/* 167 */
	{"poll",	lx_poll,	0,		3},	/* 168 */
	{"nfsservctl",	NULL,		NOSYS_KERNEL,	0},	/* 169 */
	{"setresgid16",	lx_setresgid16, 0,		3},	/* 170 */
	{"getresgid16",	lx_getresgid16,	0,		3},	/* 171 */
	{"prctl",	lx_prctl,	0,		5},	/* 172 */
	{"rt_sigreturn", lx_rt_sigreturn, 0,		0},	/* 173 */
	{"rt_sigaction", lx_rt_sigaction, 0,		4},	/* 174 */
	{"rt_sigprocmask", lx_rt_sigprocmask, 0,	4},	/* 175 */
	{"rt_sigpending", lx_rt_sigpending, 0,		2},	/* 176 */
	{"rt_sigtimedwait", lx_rt_sigtimedwait,	0,	4},	/* 177 */
	{"rt_sigqueueinfo", lx_rt_sigqueueinfo,	0,	3},	/* 178 */
	{"rt_sigsuspend", lx_rt_sigsuspend, 0,		2},	/* 179 */
	{"pread64",	lx_pread64,	0,		5},	/* 180 */
	{"pwrite64",	lx_pwrite64,	0,		5},	/* 181 */
	{"chown16",	lx_chown16,	0,		3},	/* 182 */
	{"getcwd",	lx_getcwd,	0,		2},	/* 183 */
	{"capget",	lx_capget,	0,		2},	/* 184 */
	{"capset",	lx_capset,	0,		2},	/* 185 */
	{"sigaltstack",	lx_sigaltstack,	0,		2},	/* 186 */
	{"sendfile",	lx_sendfile,	0,		4},	/* 187 */
	{"getpmsg",	NULL,		NOSYS_OBSOLETE,	0},	/* 188 */
	{"putpmsg",	NULL,		NOSYS_OBSOLETE,	0},	/* 189 */
	{"vfork",	lx_vfork,	0,		0},	/* 190 */
	{"getrlimit",	lx_getrlimit,	0,		2},	/* 191 */
	{"mmap2",	lx_mmap2,	EBP_HAS_ARG6,	6},	/* 192 */
	{"truncate64",	lx_truncate64,	0,		3},	/* 193 */
	{"ftruncate64",	lx_ftruncate64,	0,		3},	/* 194 */
	{"stat64",	lx_stat64,	0,		2},	/* 195 */
	{"lstat64",	lx_lstat64,	0,		2},	/* 196 */
	{"fstat64",	lx_fstat64,	0,		2},	/* 197 */
	{"lchown",	lx_lchown,	0,		3},	/* 198 */
	{"getuid",	lx_getuid,	0,		0},	/* 199 */
	{"getgid",	lx_getgid, 	0,		0},	/* 200 */
	{"geteuid",	lx_geteuid,	0,		0},	/* 201 */
	{"getegid",	lx_getegid,	0,		0},	/* 202 */
	{"setreuid",	lx_setreuid,	0,		0},	/* 203 */
	{"setregid",	lx_setregid,	0,		0},	/* 204 */
	{"getgroups",	lx_getgroups,	0,		2},	/* 205 */
	{"setgroups",	lx_setgroups,	0,		2},	/* 206 */
	{"fchown",	lx_fchown,	0,		3},	/* 207 */
	{"setresuid",	lx_setresuid,	0,		3},	/* 208 */
	{"getresuid",	lx_getresuid,	0,		3},	/* 209 */
	{"setresgid",	lx_setresgid,	0,		3},	/* 210 */
	{"getresgid",	lx_getresgid,	0,		3},	/* 211 */
	{"chown",	lx_chown,	0,		3},	/* 212 */
	{"setuid",	lx_setuid,	0,		1},	/* 213 */
	{"setgid",	lx_setgid,	0,		1},	/* 214 */
	{"setfsuid",	lx_setfsuid,	0,		1},	/* 215 */
	{"setfsgid",	lx_setfsgid,	0,		1},	/* 216 */
	{"pivot_root",	NULL,		NOSYS_KERNEL,	0},	/* 217 */
	{"mincore",	lx_mincore,	0,		3},	/* 218 */
	{"madvise",	lx_madvise,	0,		3},	/* 219 */
	{"getdents64",	lx_getdents64,	0,		3},	/* 220 */
	{"fcntl64",	lx_fcntl64,	0,		3},	/* 221 */
	{"tux",		NULL,		NOSYS_NO_EQUIV,	0},	/* 222 */
	{"security",	NULL,		NOSYS_NO_EQUIV,	0},	/* 223 */
	{"gettid",	lx_gettid,	0,		0},	/* 224 */
	{"readahead",	NULL,		NOSYS_NO_EQUIV,	0},	/* 225 */
	{"setxattr",	NULL,		NOSYS_NO_EQUIV,	0},	/* 226 */
	{"lsetxattr",	NULL,		NOSYS_NO_EQUIV,	0},	/* 227 */
	{"fsetxattr",	NULL,		NOSYS_NO_EQUIV,	0},	/* 228 */
	{"getxattr",	lx_xattr4,	0,		4},	/* 229 */
	{"lgetxattr",	lx_xattr4,	0,		4},	/* 230 */
	{"fgetxattr",	lx_xattr4,	0,		4},	/* 231 */
	{"listxattr",	lx_xattr3,	0,		3},	/* 232 */
	{"llistxattr",	lx_xattr3,	0,		3},	/* 233 */
	{"flistxattr",	lx_xattr3,	0,		3},	/* 234 */
	{"removexattr",	lx_xattr2,	0,		2},	/* 235 */
	{"lremovexattr", lx_xattr2,	0,		2},	/* 236 */
	{"fremovexattr", lx_xattr2,	0,		2},	/* 237 */
	{"tkill",	lx_tkill,	0,		2},	/* 238 */
	{"sendfile64",	lx_sendfile64,	0,		4},	/* 239 */
	{"futex",	lx_futex,	EBP_HAS_ARG6,	6},	/* 240 */
	{"sched_setaffinity", lx_sched_setaffinity, 0,	3},	/* 241 */
	{"sched_getaffinity", lx_sched_getaffinity, 0,	3},	/* 242 */
	{"set_thread_area", lx_set_thread_area, 0,	1},	/* 243 */
	{"get_thread_area", lx_get_thread_area, 0,	1},	/* 244 */
	{"io_setup",	NULL,		NOSYS_NO_EQUIV,	0},	/* 245 */
	{"io_destroy",	NULL,		NOSYS_NO_EQUIV,	0},	/* 246 */
	{"io_getevents", NULL,		NOSYS_NO_EQUIV,	0},	/* 247 */
	{"io_submit",	NULL,		NOSYS_NO_EQUIV,	0},	/* 248 */
	{"io_cancel",	NULL,		NOSYS_NO_EQUIV,	0},	/* 249 */
	{"fadvise64",	lx_fadvise64,	0,		4},	/* 250 */
	{"nosys",	NULL,		0,		0},	/* 251 */
	{"group_exit",	lx_group_exit,	0,		1},	/* 252 */
	{"lookup_dcookie", NULL,	NOSYS_NO_EQUIV,	0},	/* 253 */
	{"epoll_create", lx_epoll_create, 0,		1},	/* 254 */
	{"epoll_ctl",	lx_epoll_ctl,	0,		4},	/* 255 */
	{"epoll_wait",	lx_epoll_wait,	0,		4},	/* 256 */
	{"remap_file_pages", NULL,	NOSYS_NO_EQUIV,	0},	/* 257 */
	{"set_tid_address", lx_set_tid_address, 0,	1},	/* 258 */
	{"timer_create", NULL,		NOSYS_UNDOC,	0},	/* 259 */
	{"timer_settime", NULL,		NOSYS_UNDOC,	0},	/* 260 */
	{"timer_gettime", NULL,		NOSYS_UNDOC,	0},	/* 261 */
	{"timer_getoverrun", NULL,	NOSYS_UNDOC,	0},	/* 262 */
	{"timer_delete", NULL,		NOSYS_UNDOC,	0},	/* 263 */
	{"clock_settime", lx_clock_settime,	0,	2},	/* 264 */
	{"clock_gettime", lx_clock_gettime,	0,	2},	/* 265 */
	{"clock_getres", lx_clock_getres,	0,	2},	/* 266 */
	{"clock_nanosleep", lx_clock_nanosleep,	0,	4},	/* 267 */
	{"statfs64",	lx_statfs64,	0,		2},	/* 268 */
	{"fstatfs64",	lx_fstatfs64,	0,		2},	/* 269 */
	{"tgkill",	lx_tgkill,	0,		3},	/* 270 */

	/* The following system calls only exist in kernel 2.6 and greater */
	{"utimes",	lx_utimes,	0,		2},	/* 271 */
	{"fadvise64_64", lx_fadvise64_64, 0,		4},	/* 272 */
	{"vserver",	NULL,		NOSYS_NULL,	0},	/* 273 */
	{"mbind",	NULL,		NOSYS_NULL,	0},	/* 274 */
	{"get_mempolicy", NULL,		NOSYS_NULL,	0},	/* 275 */
	{"set_mempolicy", NULL,		NOSYS_NULL,	0},	/* 276 */
	{"mq_open",	NULL,		NOSYS_NULL,	0},	/* 277 */
	{"mq_unlink",	NULL,		NOSYS_NULL,	0},	/* 278 */
	{"mq_timedsend", NULL,		NOSYS_NULL,	0},	/* 279 */
	{"mq_timedreceive", NULL,	NOSYS_NULL,	0},	/* 280 */
	{"mq_notify",	NULL,		NOSYS_NULL,	0},	/* 281 */
	{"mq_getsetattr", NULL,		NOSYS_NULL,	0},	/* 282 */
	{"kexec_load",	NULL,		NOSYS_NULL,	0},	/* 283 */
	{"waitid",	lx_waitid,	0,		4},	/* 284 */
	{"sys_setaltroot", NULL,	NOSYS_NULL,	0},	/* 285 */
	{"add_key",	NULL,		NOSYS_NULL,	0},	/* 286 */
	{"request_key",	NULL,		NOSYS_NULL,	0},	/* 287 */
	{"keyctl",	NULL,		NOSYS_NULL,	0},	/* 288 */
	{"ioprio_set",	NULL,		NOSYS_NULL,	0},	/* 289 */
	{"ioprio_get",	NULL,		NOSYS_NULL,	0},	/* 290 */
	{"inotify_init", lx_inotify_init, 0,		0},	/* 291 */
	{"inotify_add_watch", lx_inotify_add_watch, 0,	3},	/* 292 */
	{"inotify_rm_watch", lx_inotify_rm_watch, 0,	2},	/* 293 */
	{"migrate_pages", NULL,		NOSYS_NULL,	0},	/* 294 */
	{"openat",	lx_openat,	0,		4},	/* 295 */
	{"mkdirat",	lx_mkdirat,	0,		3},	/* 296 */
	{"mknodat",	lx_mknodat,	0,		4},	/* 297 */
	{"fchownat",	lx_fchownat,	0,		5},	/* 298 */
	{"futimesat",	lx_futimesat,	0,		3},	/* 299 */
	{"fstatat64",	lx_fstatat64,	0,		4},	/* 300 */
	{"unlinkat",	lx_unlinkat,	0,		3},	/* 301 */
	{"renameat",	lx_renameat,	0,		4},	/* 302 */
	{"linkat",	lx_linkat,	0,		5},	/* 303 */
	{"symlinkat",	lx_symlinkat,	0,		3},	/* 304 */
	{"readlinkat",	lx_readlinkat,	0,		4},	/* 305 */
	{"fchmodat",	lx_fchmodat,	0,		4},	/* 306 */
	{"faccessat",	lx_faccessat,	0,		4},	/* 307 */
	{"pselect6",	lx_pselect6,	EBP_HAS_ARG6,	6},	/* 308 */
	{"ppoll",	NULL,		NOSYS_NULL,	0},	/* 309 */
	{"unshare",	NULL,		NOSYS_NULL,	0},	/* 310 */
	{"set_robust_list", NULL,	NOSYS_NULL,	0},	/* 311 */
	{"get_robust_list", NULL,	NOSYS_NULL,	0},	/* 312 */
	{"splice",	NULL,		NOSYS_NULL,	0},	/* 313 */
	{"sync_file_range", NULL,	NOSYS_NULL,	0},	/* 314 */
	{"tee",		NULL,		NOSYS_NULL,	0},	/* 315 */
	{"vmsplice",	NULL,		NOSYS_NULL,	0},	/* 316 */
	{"move_pages",	NULL,		NOSYS_NULL,	0},	/* 317 */
	{"getcpu",	lx_getcpu,	0,		3},	/* 318 */
	{"epoll_pwait",	lx_epoll_pwait, 0,		5},	/* 319 */
	{"utimensat",	lx_utimensat,	0,		4},	/* 320 */
	{"signalfd",	NULL,		NOSYS_NULL,	0},	/* 321 */
	{"timerfd_create", NULL,	NOSYS_NULL,	0},	/* 322 */
	{"eventfd",	NULL,		NOSYS_NULL,	0},	/* 323 */
	{"fallocate",	NULL,		NOSYS_NULL,	0},	/* 324 */
	{"timerfd_settime", NULL,	NOSYS_NULL,	0},	/* 325 */
	{"timerfd_gettime", NULL,	NOSYS_NULL,	0},	/* 326 */
	{"signalfd4",	NULL,		NOSYS_NULL,	0},	/* 327 */
	{"eventfd2",	NULL,		NOSYS_NULL,	0},	/* 328 */
	{"epoll_create1", lx_epoll_create1, 0,		1},	/* 329 */
	{"dup3",	lx_dup3,	0,		3},	/* 330 */
	{"pipe2",	lx_pipe2,	0,		2},	/* 331 */
	{"inotify_init1", lx_inotify_init1, 0,		1},	/* 332 */
	{"preadv",	NULL,		NOSYS_NULL,	0},	/* 333 */
	{"pwritev",	NULL,		NOSYS_NULL,	0},	/* 334 */
	{"rt_tgsigqueueinfo", lx_rt_tgsigqueueinfo, 0,	4},	/* 335 */
	{"perf_event_open", NULL,	NOSYS_NULL,	0},	/* 336 */
	{"recvmmsg",	NULL,		NOSYS_NULL,	0},	/* 337 */
	{"fanotify_init", NULL,		NOSYS_NULL,	0},	/* 338 */
	{"fanotify_mark", NULL,		NOSYS_NULL,	0},	/* 339 */
	{"prlimit64",	lx_prlimit64,	0,		4},	/* 340 */
	{"name_to_handle_at", NULL,	NOSYS_NULL,	0},	/* 341 */
	{"open_by_handle_at", NULL,	NOSYS_NULL,	0},	/* 342 */
	{"clock_adjtime", NULL,		NOSYS_NULL,	0},	/* 343 */
	{"syncfs",	NULL,		NOSYS_NULL,	0},	/* 344 */
	{"sendmmsg",	NULL,		NOSYS_NULL,	0},	/* 345 */
	{"setns",	NULL,		NOSYS_NULL,	0},	/* 346 */
	{"process_vm_readv", NULL,	NOSYS_NULL,	0},	/* 347 */
	{"process_vm_writev", NULL,	NOSYS_NULL,	0},	/* 348 */
	{"kcmp",	NULL,		NOSYS_NULL,	0},	/* 349 */
	{"finit_module", NULL,		NOSYS_NULL,	0},	/* 350 */
	{"sched_setattr", NULL,		NOSYS_NULL,	0},	/* 351 */
	{"sched_getattr", NULL,		NOSYS_NULL,	0},	/* 352 */
};
#endif
