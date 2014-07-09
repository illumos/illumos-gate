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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
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
 * Map solaris errno to the linux equivalent.
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

/*
 * SYS_PASSTHRU denotes a system call we can just call on behalf of the
 * branded process without having to translate the arguments.
 *
 * The restriction on this is that the call in question MUST return -1 to
 * denote an error.
 */
#define	SYS_PASSTHRU		5

static char *nosys_msgs[] = {
	"Not done yet",
	"No such Linux system call",
	"No equivalent Solaris functionality",
	"Reads/modifies Linux kernel state",
	"Undocumented and/or rarely used system call",
	"Unsupported, obsolete system call"
};

struct lx_sysent {
	char    *sy_name;
	int	(*sy_callc)();
	char	sy_flags;
	char	sy_narg;
};

static struct lx_sysent sysents[LX_NSYSCALLS + 1];

static uintptr_t stack_bottom;

int lx_install = 0;		/* install mode enabled if non-zero */
boolean_t lx_is_rpm = B_FALSE;
int lx_rpm_delay = 1;
int lx_strict = 0;		/* "strict" mode enabled if non-zero */
int lx_verbose = 0;		/* verbose mode enabled if non-zero */
int lx_debug_enabled = 0;	/* debugging output enabled if non-zero */

pid_t zoneinit_pid;		/* zone init PID */

thread_key_t lx_tsd_key;

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
		 * We used to call syslog here but that idea is broken since
		 * the syslog -> vsyslog code path in the native libc clearly
		 * does things that will not work in the lx branded zone
		 * (e.g. open /proc/{pid}/psinfo).
		 */

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

extern void lx_runexe(void *argv, int32_t entry);
int lx_init(int argc, char *argv[], char *envp[]);

static int
lx_emulate_args(lx_regs_t *rp, struct lx_sysent *s, uintptr_t *args)
{
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

	return (0);
}

void
lx_emulate(lx_regs_t *rp)
{
	struct lx_sysent *s;
	uintptr_t args[6];
	uintptr_t gs = rp->lxr_gs & 0xffff;	/* %gs is only 16 bits */
	int syscall_num, ret;

	syscall_num = rp->lxr_eax;

	/*
	 * lx_brand_int80_callback() ensures that the syscall_num is sane;
	 * Use it as is.
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
		 * %eax should be reported as -ENOSYS while the orig_eax
		 * field of the user structure needs to contain the actual
		 * system call number. If we end up stopping here, the
		 * controlling process will dig the lx_regs_t structure out of
		 * our stack.
		 */
		rp->lxr_orig_eax = syscall_num;
		rp->lxr_eax = -stol_errno[ENOSYS];

		(void) syscall(SYS_brand, B_SYSENTRY, syscall_num, args);

		/*
		 * The external tracer may have modified the arguments to this
		 * system call. Refresh the argument cache to account for this.
		 */
		if ((ret = lx_emulate_args(rp, s, args)) != 0)
			goto out;
	}

	if (s->sy_callc == NULL) {
		lx_unsupported(gettext("unimplemented syscall #%d (%s): %s\n"),
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
			lx_err_fatal(gettext(
			    "%s: unable to read thread-specific data: %s"),
			    "lx_emulate", strerror(ret));

		assert(lx_tsd != 0);

		lx_tsd->lxtsd_gs = gs;

		lx_debug("lx_emulate(): gsp 0x%p, saved gs: 0x%x", lx_tsd, gs);
	}

	if (s->sy_flags == SYS_PASSTHRU)
		lx_debug("\tCalling Solaris %s()", s->sy_name);

	ret = s->sy_callc(args[0], args[1], args[2], args[3], args[4], args[5]);

	if (ret > -65536 && ret < 65536)
		lx_debug("\t= %d", ret);
	else
		lx_debug("\t= 0x%x", ret);

	if ((s->sy_flags == SYS_PASSTHRU) && (ret == -1)) {
		ret = -stol_errno[errno];
	} else {
		/*
		 * If the return value is between -4096 and 0 we assume it's an
		 * error, so we translate the Solaris error number into the
		 * Linux equivalent.
		 */
		if (ret < 0 && ret > -4096) {
			if (-ret >=
			    sizeof (stol_errno) / sizeof (stol_errno[0])) {
				lx_debug("Invalid return value from emulated "
				    "syscall %d (%s): %d\n",
				    syscall_num, s->sy_name, ret);
				assert(0);
			}

			ret = -stol_errno[-ret];
		}
	}

out:
	/*
	 * %eax holds the return code from the system call.
	 */
	rp->lxr_eax = ret;

	/*
	 * If the trace flag is set, bounce into the kernel to let it do
	 * any necessary tracing (DTrace or ptrace).
	 */
	if (lx_traceflag != 0) {
		rp->lxr_orig_eax = syscall_num;
		(void) syscall(SYS_brand, B_SYSRETURN, syscall_num, ret);
	}
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

/*ARGSUSED*/
int
lx_init(int argc, char *argv[], char *envp[])
{
	char		*r;
	auxv_t		*ap;
	int		*p, err;
	lx_elf_data_t	edp;
	lx_brand_registration_t reg;
	static lx_tsd_t lx_tsd;


	/* Look up the PID that serves as init for this zone */
	if ((err = lx_lpid_to_spid(1, &zoneinit_pid)) < 0)
		lx_err_fatal(gettext(
		    "Unable to find PID for zone init process: %s"),
		    strerror(err));

	/*
	 * Ubuntu init will fail if its TERM environment variable is not set
	 * so if we are running init, and TERM is not set, we set term and
	 * reexec so that the new environment variable is propagated to the
	 * linux application stack.
	 */
	if ((getpid() == zoneinit_pid) && (getenv("TERM") == NULL)) {
		if (setenv("TERM", "vt100", 1) < 0 || execv(argv[0], argv) < 0)
			lx_err_fatal(gettext("failed to set TERM"));
	}

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
	reg.lxbr_traceflag = &lx_traceflag;

	/*
	 * Register the address of the user-space handler with the lx
	 * brand module.
	 */
	if (syscall(SYS_brand, B_REGISTER, &reg))
		lx_err_fatal(gettext("failed to brand the process"));

	/*
	 * Download data about the lx executable from the kernel.
	 */
	if (syscall(SYS_brand, B_ELFDATA, (void *)&edp))
		lx_err_fatal(gettext(
		    "failed to get required ELF data from the kernel"));

	if (lx_ioctl_init() != 0)
		lx_err_fatal(gettext("failed to setup the %s translator"),
		    "ioctl");

	if (lx_stat_init() != 0)
		lx_err_fatal(gettext("failed to setup the %s translator"),
		    "stat");

	if (lx_statfs_init() != 0)
		lx_err_fatal(gettext("failed to setup the %s translator"),
		    "statfs");

	/*
	 * Find the aux vector on the stack.
	 */
	p = (int *)envp;
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
			default:
				break;
		}
	}

	/* Do any thunk server initalization. */
	lxt_server_init(argc, argv);

	/* Setup signal handler information. */
	if (lx_siginit())
		lx_err_fatal(gettext(
		    "failed to initialize lx signals for the branded process"));

	/* Setup thread-specific data area for managing linux threads. */
	if ((err = thr_keycreate(&lx_tsd_key, NULL)) != 0)
		lx_err_fatal(
		    gettext("%s failed: %s"), "thr_keycreate(lx_tsd_key)",
		    strerror(err));

	lx_debug("thr_keycreate created lx_tsd_key (%d)", lx_tsd_key);

	/* Initialize the thread specific data for this thread. */
	bzero(&lx_tsd, sizeof (lx_tsd));
	lx_tsd.lxtsd_gs = LWPGS_SEL;

	if ((err = thr_setspecific(lx_tsd_key, &lx_tsd)) != 0)
		lx_err_fatal(gettext(
		    "Unable to initialize thread-specific data: %s"),
		    strerror(err));

	/*
	 * Save the current context of this thread.
	 * We'll restore this context when this thread attempts to exit.
	 */
	if (getcontext(&lx_tsd.lxtsd_exit_context) != 0)
		lx_err_fatal(gettext(
		    "Unable to initialize thread-specific exit context: %s"),
		    strerror(errno));

	if (lx_tsd.lxtsd_exit == 0) {
		lx_runexe(argv, edp.ed_ldentry);
		/* lx_runexe() never returns. */
		assert(0);
	}

	/*
	 * We are here because the Linux application called the exit() or
	 * exit_group() system call.  In turn the brand library did a
	 * setcontext() to jump to the thread context state we saved above.
	 */
	if (lx_tsd.lxtsd_exit == 1)
		thr_exit((void *)lx_tsd.lxtsd_exit_status);
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

	return ((lx_regs_t *)((uintptr_t *)fr)[2]);
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
 * Create a translation routine that jumps to a particular emulation
 * module syscall.
 */
#define	IN_KERNEL_SYSCALL(name, num)		\
int						\
lx_##name(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,	\
	uintptr_t p5, uintptr_t p6)		\
{						\
	int r;					\
	lx_debug("\tsyscall %d re-vectoring to lx kernel module "	\
	    "for " #name "()", num);		\
	r = syscall(SYS_brand, B_EMULATE_SYSCALL + num, p1, p2,		\
	    p3, p4, p5, p6);			\
	return ((r == -1) ? -errno : r);		\
}

IN_KERNEL_SYSCALL(kill, 37)
IN_KERNEL_SYSCALL(brk, 45)
IN_KERNEL_SYSCALL(ustat, 62)
IN_KERNEL_SYSCALL(getppid, 64)
IN_KERNEL_SYSCALL(sysinfo, 116)
IN_KERNEL_SYSCALL(modify_ldt, 123)
IN_KERNEL_SYSCALL(adjtimex, 124)
IN_KERNEL_SYSCALL(setresuid16, 164)
IN_KERNEL_SYSCALL(setresgid16, 170)
IN_KERNEL_SYSCALL(setresuid, 208)
IN_KERNEL_SYSCALL(setresgid, 210)
IN_KERNEL_SYSCALL(gettid, 224)
IN_KERNEL_SYSCALL(tkill, 238)
IN_KERNEL_SYSCALL(futex, 240)
IN_KERNEL_SYSCALL(set_thread_area, 243)
IN_KERNEL_SYSCALL(get_thread_area, 244)
IN_KERNEL_SYSCALL(set_tid_address, 258)

static struct lx_sysent sysents[] = {
	{"nosys",	NULL,		NOSYS_NONE,	0},	/*  0 */
	{"exit",	lx_exit,	0,		1},	/*  1 */
	{"fork",	lx_fork,	0,		0},	/*  2 */
	{"read",	lx_read,	0,		3},	/*  3 */
	{"write",	write,		SYS_PASSTHRU,	3},	/*  4 */
	{"open",	lx_open,	0,		3},	/*  5 */
	{"close",	close,		SYS_PASSTHRU,	1},	/*  6 */
	{"waitpid",	lx_waitpid,	0,		3},	/*  7 */
	{"creat",	creat,		SYS_PASSTHRU,	2},	/*  8 */
	{"link",	lx_link,	0,		2},	/*  9 */
	{"unlink",	lx_unlink,	0,		1},	/* 10 */
	{"execve",	lx_execve,	0,		3},	/* 11 */
	{"chdir",	chdir,		SYS_PASSTHRU,	1},	/* 12 */
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
	{"stime",	stime,		SYS_PASSTHRU,	1},	/* 25 */
	{"ptrace",	lx_ptrace,	0,		4},	/* 26 */
	{"alarm",	(int (*)())alarm, SYS_PASSTHRU,	1},	/* 27 */
	{"fstat",	NULL,		NOSYS_OBSOLETE,	0},	/* 28 */
	{"pause",	pause,		SYS_PASSTHRU,	0},	/* 29 */
	{"utime",	lx_utime,	0,		2},	/* 30 */
	{"stty",	NULL,		NOSYS_OBSOLETE,	0},	/* 31 */
	{"gtty",	NULL,		NOSYS_OBSOLETE,	0},	/* 32 */
	{"access",	lx_access,	0,		2},	/* 33 */
	{"nice",	nice,		SYS_PASSTHRU,	1},	/* 34 */
	{"ftime",	NULL,		NOSYS_OBSOLETE,	0},	/* 35 */
	{"sync",	lx_sync, 	0, 		0},	/* 36 */
	{"kill",	lx_kill,	0,		2},	/* 37 */
	{"rename",	lx_rename,	0,		2},	/* 38 */
	{"mkdir",	mkdir,		SYS_PASSTHRU,	2},	/* 39 */
	{"rmdir",	lx_rmdir,	0,		1},	/* 40 */
	{"dup",		dup,		SYS_PASSTHRU,	1},	/* 41 */
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
	{"umask",	(int (*)())umask, SYS_PASSTHRU,	1},	/* 60 */
	{"chroot",	chroot,		SYS_PASSTHRU,	1},	/* 61 */
	{"ustat",	lx_ustat,	0,		2},	/* 62 */
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
	{"symlink",	symlink,	SYS_PASSTHRU,	2},	/* 83 */
	{"oldlstat",	NULL,		NOSYS_OBSOLETE,	0},	/* 84 */
	{"readlink",	readlink,	SYS_PASSTHRU,	3},	/* 85 */
	{"uselib",	NULL,		NOSYS_KERNEL,	0},	/* 86 */
	{"swapon",	NULL,		NOSYS_KERNEL,	0},	/* 87 */
	{"reboot",	lx_reboot,	0,		4},	/* 88 */
	{"readdir",	lx_readdir,	0,		3},	/* 89 */
	{"mmap",	lx_mmap,	0,		6},	/* 90 */
	{"munmap",	munmap,		SYS_PASSTHRU,	2},	/* 91 */
	{"truncate",	lx_truncate,	0,		2},	/* 92 */
	{"ftruncate",	lx_ftruncate,	0,		2},	/* 93 */
	{"fchmod",	fchmod,		SYS_PASSTHRU,	2},	/* 94 */
	{"fchown16",	lx_fchown16,	0,		3},	/* 95 */
	{"getpriority",	lx_getpriority,	0,		2},	/* 96 */
	{"setpriority",	lx_setpriority,	0,		3},	/* 97 */
	{"profil",	NULL,		NOSYS_NO_EQUIV,	0},	/* 98 */
	{"statfs",	lx_statfs,	0,		2},	/* 99 */
	{"fstatfs",	lx_fstatfs,	0,		2},	/* 100 */
	{"ioperm",	NULL,		NOSYS_NO_EQUIV,	0},	/* 101 */
	{"socketcall",	lx_socketcall,	0,		2},	/* 102 */
	{"syslog",	NULL,		NOSYS_KERNEL,	0},	/* 103 */
	{"setitimer",	lx_setitimer,	0,		3},	/* 104 */
	{"getitimer",	getitimer,	SYS_PASSTHRU,	2},	/* 105 */
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
	{"sysinfo",	lx_sysinfo,	0,		1},	/* 116 */
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
	{"fchdir",	fchdir,		SYS_PASSTHRU,	1},	/* 133 */
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
	{"sched_yield",	(int (*)())yield, SYS_PASSTHRU,	0},	/* 158 */
	{"sched_get_priority_max", lx_sched_get_priority_max, 0, 1}, /* 159 */
	{"sched_get_priority_min", lx_sched_get_priority_min, 0, 1}, /* 160 */
	{"sched_rr_get_interval", lx_sched_rr_get_interval, 0,	2},  /* 161 */
	{"nanosleep",	nanosleep,	SYS_PASSTHRU,	2},	/* 162 */
	{"mremap",	NULL,		NOSYS_NO_EQUIV,	0},	/* 163 */
	{"setresuid16",	lx_setresuid16,	0,		3},	/* 164 */
	{"getresuid16",	lx_getresuid16,	0,		3},	/* 165 */
	{"vm86",	NULL,		NOSYS_NO_EQUIV,	0},	/* 166 */
	{"query_module", lx_query_module, NOSYS_KERNEL,	5},	/* 167 */
	{"poll",	lx_poll,	0,		3},	/* 168 */
	{"nfsservctl",	NULL,		NOSYS_KERNEL,	0},	/* 169 */
	{"setresgid16",	lx_setresgid16,	0,		3},	/* 170 */
	{"getresgid16",	lx_getresgid16,	0,		3},	/* 171 */
	{"prctl",	lx_prctl,	0,		5},	/* 172 */
	{"rt_sigreturn", lx_rt_sigreturn, 0,		0},	/* 173 */
	{"rt_sigaction", lx_rt_sigaction, 0,		4},	/* 174 */
	{"rt_sigprocmask", lx_rt_sigprocmask, 0,	4},	/* 175 */
	{"rt_sigpending", lx_rt_sigpending, 0,		2},	/* 176 */
	{"rt_sigtimedwait", lx_rt_sigtimedwait,	0,	4},	/* 177 */
	{"sigqueueinfo", NULL,		NOSYS_UNDOC,	0},	/* 178 */
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
	{"lchown",	lchown,		SYS_PASSTHRU,	3},	/* 198 */
	{"getuid",	(int (*)())getuid, SYS_PASSTHRU, 0},	/* 199 */
	{"getgid",	(int (*)())getgid, SYS_PASSTHRU, 0},	/* 200 */
	{"geteuid",	lx_geteuid,	0,		0},	/* 201 */
	{"getegid",	lx_getegid,	0,		0},	/* 202 */
	{"setreuid",	setreuid,	SYS_PASSTHRU,	0},	/* 203 */
	{"setregid",	setregid,	SYS_PASSTHRU,	0},	/* 204 */
	{"getgroups",	getgroups,	SYS_PASSTHRU,	2},	/* 205 */
	{"setgroups",	lx_setgroups,	0,		2},	/* 206 */
	{"fchown",	lx_fchown,	0,		3},	/* 207 */
	{"setresuid",	lx_setresuid,	0,		3},	/* 208 */
	{"getresuid",	lx_getresuid,	0,		3},	/* 209 */
	{"setresgid",	lx_setresgid,	0,		3},	/* 210 */
	{"getresgid",	lx_getresgid,	0,		3},	/* 211 */
	{"chown",	lx_chown,	0,		3},	/* 212 */
	{"setuid",	setuid,		SYS_PASSTHRU,	1},	/* 213 */
	{"setgid",	setgid,		SYS_PASSTHRU,	1},	/* 214 */
	{"setfsuid",	lx_setfsuid,	0,		1},	/* 215 */
	{"setfsgid",	lx_setfsgid,	0,		1},	/* 216 */
	{"pivot_root",	NULL,		NOSYS_KERNEL,	0},	/* 217 */
	{"mincore",	mincore,	SYS_PASSTHRU,	3},	/* 218 */
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
	{"sched_setaffinity",	lx_sched_setaffinity,	0, 3},	/* 241 */
	{"sched_getaffinity",	lx_sched_getaffinity,	0, 3},	/* 242 */
	{"set_thread_area", lx_set_thread_area,	0,	1},	/* 243 */
	{"get_thread_area", lx_get_thread_area,	0,	1},	/* 244 */
	{"io_setup",	NULL,		NOSYS_NO_EQUIV,	0},	/* 245 */
	{"io_destroy",	NULL,		NOSYS_NO_EQUIV,	0},	/* 246 */
	{"io_getevents", NULL,		NOSYS_NO_EQUIV,	0},	/* 247 */
	{"io_submit",	NULL,		NOSYS_NO_EQUIV,	0},	/* 248 */
	{"io_cancel",	NULL,		NOSYS_NO_EQUIV,	0},	/* 249 */
	{"fadvise64",	lx_fadvise64,	0,		4},	/* 250 */
	{"nosys",	NULL,		0,		0},	/* 251 */
	{"group_exit",	lx_group_exit,	0,		1},	/* 252 */
	{"lookup_dcookie", NULL,	NOSYS_NO_EQUIV,	0},	/* 253 */
	{"epoll_create", epoll_create,	SYS_PASSTHRU,	1},	/* 254 */
	{"epoll_ctl",	epoll_ctl,	SYS_PASSTHRU,	4},	/* 255 */
	{"epoll_wait",	epoll_wait,	SYS_PASSTHRU,	4},	/* 256 */
	{"remap_file_pages", NULL,	NOSYS_NO_EQUIV,	0},	/* 257 */
	{"set_tid_address", lx_set_tid_address,	0,	1},	/* 258 */
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
	{"utimes",	utimes,		SYS_PASSTHRU,	2},	/* 271 */
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
	{"inotify_init", NULL,		NOSYS_NULL,	0},	/* 291 */
	{"inotify_add_watch", NULL,	NOSYS_NULL,	0},	/* 292 */
	{"inotify_rm_watch", NULL,	NOSYS_NULL,	0},	/* 293 */
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
	{"getcpu",	NULL,		NOSYS_NULL,	0},	/* 318 */
	{"epoll_pwait",	epoll_pwait,	SYS_PASSTHRU,	5},	/* 319 */
	{"utimensat",	lx_utimensat,	0,		4},	/* 320 */
	{"signalfd",	NULL,		NOSYS_NULL,	0},	/* 321 */
	{"timerfd_create", NULL,	NOSYS_NULL,	0},	/* 322 */
	{"eventfd",	NULL,		NOSYS_NULL,	0},	/* 323 */
	{"fallocate",	NULL,		NOSYS_NULL,	0},	/* 324 */
	{"timerfd_settime", NULL,	NOSYS_NULL,	0},	/* 325 */
	{"timerfd_gettime", NULL,	NOSYS_NULL,	0},	/* 326 */
	{"signalfd4",	NULL,		NOSYS_NULL,	0},	/* 327 */
	{"eventfd2",	NULL,		NOSYS_NULL,	0},	/* 328 */
	{"epoll_create1", epoll_create1, SYS_PASSTHRU,	1},	/* 329 */
	{"dup3",	lx_dup3,	0,		3},	/* 330 */
	{"pipe2",	lx_pipe2,	0,		2},	/* 331 */
	{"inotify_init1", NULL,		NOSYS_NULL,	0},	/* 332 */
	{"preadv",	NULL,		NOSYS_NULL,	0},	/* 333 */
	{"pwritev",	NULL,		NOSYS_NULL,	0},	/* 334 */
	{"rt_tgsigqueueinfo", NULL,	NOSYS_NULL,	0},	/* 335 */
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
