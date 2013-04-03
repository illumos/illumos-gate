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
 * Copyright 2012, Josef 'Jeff' Sipek <jeffpc@31bits.net>. All rights reserved.
 */

/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/resource.h>
#include <sys/termios.h>
#include <sys/param.h>
#include <sys/regset.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <sys/reg.h>

#include <libproc.h>
#include <libscf.h>
#include <alloca.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <libctf.h>
#include <errno.h>
#include <kvm.h>

#include <mdb/mdb_lex.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_signal.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_gelf.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_set.h>
#include <kmdb/kmdb_kctl.h>
#include <mdb/mdb.h>

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

#if defined(__sparc)
#define	STACK_REGISTER	SP
#else
#define	STACK_REGISTER	REG_FP
#endif

#ifdef _LP64
#define	MDB_DEF_IPATH	\
	"%r/usr/platform/%p/lib/adb/%i:" \
	"%r/usr/platform/%m/lib/adb/%i:" \
	"%r/usr/lib/adb/%i"
#define	MDB_DEF_LPATH	\
	"%r/usr/platform/%p/lib/mdb/%t/%i:" \
	"%r/usr/platform/%m/lib/mdb/%t/%i:" \
	"%r/usr/lib/mdb/%t/%i"
#else
#define	MDB_DEF_IPATH	\
	"%r/usr/platform/%p/lib/adb:" \
	"%r/usr/platform/%m/lib/adb:" \
	"%r/usr/lib/adb"
#define	MDB_DEF_LPATH	\
	"%r/usr/platform/%p/lib/mdb/%t:" \
	"%r/usr/platform/%m/lib/mdb/%t:" \
	"%r/usr/lib/mdb/%t"
#endif

#define	MDB_DEF_PROMPT "> "

/*
 * Similar to the panic_* variables in the kernel, we keep some relevant
 * information stored in a set of global _mdb_abort_* variables; in the
 * event that the debugger dumps core, these will aid core dump analysis.
 */
const char *volatile _mdb_abort_str;	/* reason for failure */
siginfo_t _mdb_abort_info;		/* signal info for fatal signal */
ucontext_t _mdb_abort_ctx;		/* context fatal signal interrupted */
int _mdb_abort_rcount;			/* number of times resume requested */
int _mdb_self_fd = -1;			/* fd for self as for valid_frame */

static void
terminate(int status)
{
	(void) mdb_signal_blockall();
	mdb_destroy();
	exit(status);
}

static void
print_frame(uintptr_t pc, int fnum)
{
	Dl_info dli;

	if (dladdr((void *)pc, &dli)) {
		mdb_iob_printf(mdb.m_err, "    [%d] %s`%s+0x%lx()\n", fnum,
		    strbasename(dli.dli_fname), dli.dli_sname,
		    pc - (uintptr_t)dli.dli_saddr);
	} else
		mdb_iob_printf(mdb.m_err, "    [%d] %p()\n", fnum, pc);
}

static int
valid_frame(struct frame *fr)
{
	static struct frame fake;
	uintptr_t addr = (uintptr_t)fr;

	if (pread(_mdb_self_fd, &fake, sizeof (fake), addr) != sizeof (fake)) {
		mdb_iob_printf(mdb.m_err, "    invalid frame (%p)\n", fr);
		return (0);
	}

	if (addr & (STACK_ALIGN - 1)) {
		mdb_iob_printf(mdb.m_err, "    mis-aligned frame (%p)\n", fr);
		return (0);
	}

	return (1);
}

/*ARGSUSED*/
static void
flt_handler(int sig, siginfo_t *sip, ucontext_t *ucp, void *data)
{
	static const struct rlimit rl = {
		(rlim_t)RLIM_INFINITY, (rlim_t)RLIM_INFINITY
	};

	const mdb_idcmd_t *idcp = NULL;

	if (mdb.m_frame != NULL && mdb.m_frame->f_cp != NULL)
		idcp = mdb.m_frame->f_cp->c_dcmd;

	if (sip != NULL)
		bcopy(sip, &_mdb_abort_info, sizeof (_mdb_abort_info));
	if (ucp != NULL)
		bcopy(ucp, &_mdb_abort_ctx, sizeof (_mdb_abort_ctx));

	_mdb_abort_info.si_signo = sig;
	(void) mdb_signal_sethandler(sig, SIG_DFL, NULL);

	/*
	 * If there is no current dcmd, or the current dcmd comes from a
	 * builtin module, we don't allow resume and always core dump.
	 */
	if (idcp == NULL || idcp->idc_modp == NULL ||
	    idcp->idc_modp == &mdb.m_rmod || idcp->idc_modp->mod_hdl == NULL)
		goto dump;

	if (mdb.m_term != NULL) {
		struct frame *fr = (struct frame *)
		    (ucp->uc_mcontext.gregs[STACK_REGISTER] + STACK_BIAS);

		char signame[SIG2STR_MAX];
		int i = 1;
		char c;

		if (sig2str(sig, signame) == -1) {
			mdb_iob_printf(mdb.m_err,
			    "\n*** %s: received signal %d at:\n",
			    mdb.m_pname, sig);
		} else {
			mdb_iob_printf(mdb.m_err,
			    "\n*** %s: received signal %s at:\n",
			    mdb.m_pname, signame);
		}

		if (ucp->uc_mcontext.gregs[REG_PC] != 0)
			print_frame(ucp->uc_mcontext.gregs[REG_PC], i++);

		while (fr != NULL && valid_frame(fr) && fr->fr_savpc != 0) {
			print_frame(fr->fr_savpc, i++);
			fr = (struct frame *)
			    ((uintptr_t)fr->fr_savfp + STACK_BIAS);
		}

query:
		mdb_iob_printf(mdb.m_err, "\n%s: (c)ore dump, (q)uit, "
		    "(r)ecover, or (s)top for debugger [cqrs]? ", mdb.m_pname);

		mdb_iob_flush(mdb.m_err);

		for (;;) {
			if (IOP_READ(mdb.m_term, &c, sizeof (c)) != sizeof (c))
				goto dump;

			switch (c) {
			case 'c':
			case 'C':
				(void) setrlimit(RLIMIT_CORE, &rl);
				mdb_iob_printf(mdb.m_err, "\n%s: attempting "
				    "to dump core ...\n", mdb.m_pname);
				goto dump;

			case 'q':
			case 'Q':
				mdb_iob_discard(mdb.m_out);
				mdb_iob_nl(mdb.m_err);
				(void) mdb_signal_unblockall();
				terminate(1);
				/*NOTREACHED*/

			case 'r':
			case 'R':
				mdb_iob_printf(mdb.m_err, "\n%s: unloading "
				    "module '%s' ...\n", mdb.m_pname,
				    idcp->idc_modp->mod_name);

				(void) mdb_module_unload(
				    idcp->idc_modp->mod_name, 0);

				(void) mdb_signal_sethandler(sig,
				    flt_handler, NULL);

				_mdb_abort_rcount++;
				mdb.m_intr = 0;
				mdb.m_pend = 0;

				(void) mdb_signal_unblockall();
				longjmp(mdb.m_frame->f_pcb, MDB_ERR_ABORT);
				/*NOTREACHED*/

			case 's':
			case 'S':
				mdb_iob_printf(mdb.m_err, "\n%s: "
				    "attempting to stop pid %d ...\n",
				    mdb.m_pname, (int)getpid());

				/*
				 * Stop ourself; if this fails or we are
				 * subsequently continued, ask again.
				 */
				(void) mdb_signal_raise(SIGSTOP);
				(void) mdb_signal_unblockall();
				goto query;
			}
		}
	}

dump:
	if (SI_FROMUSER(sip)) {
		(void) mdb_signal_block(sig);
		(void) mdb_signal_raise(sig);
	}

	(void) sigfillset(&ucp->uc_sigmask);
	(void) sigdelset(&ucp->uc_sigmask, sig);

	if (_mdb_abort_str == NULL)
		_mdb_abort_str = "fatal signal received";

	ucp->uc_flags |= UC_SIGMASK;
	(void) setcontext(ucp);
}

/*ARGSUSED*/
static void
int_handler(int sig, siginfo_t *sip, ucontext_t *ucp, void *data)
{
	if (mdb.m_intr == 0)
		longjmp(mdb.m_frame->f_pcb, MDB_ERR_SIGINT);
	else
		mdb.m_pend++;
}

static void
control_kmdb(int start)
{
	int fd;

	if ((fd = open("/dev/kmdb", O_RDONLY)) < 0)
		die("failed to open /dev/kmdb");

	if (start) {
		char *state = mdb_get_config();

		if (ioctl(fd, KMDB_IOC_START, state) < 0)
			die("failed to start kmdb");

		strfree(state);
	} else {
		if (ioctl(fd, KMDB_IOC_STOP) < 0)
			die("failed to stop kmdb");
	}

	(void) close(fd);
}

static void
usage(int status)
{
	mdb_iob_printf(mdb.m_err, "Usage: %s [-fkmuwyAFKMSUW] [+/-o option] "
	    "[-p pid] [-s dist] [-I path] [-L path]\n\t[-P prompt] "
	    "[-R root] [-V dis-version] [-e expr] "
	    "[object [core] | core | suffix]\n\n",
	    mdb.m_pname);

	mdb_iob_puts(mdb.m_err,
	    "\t-e evaluate expr and return status\n"
	    "\t-f force raw file debugging mode\n"
	    "\t-k force kernel debugging mode\n"
	    "\t-m disable demand-loading of module symbols\n"
	    "\t-o set specified debugger option (+o to unset)\n"
	    "\t-p attach to specified process-id\n"
	    "\t-s set symbol matching distance\n"
	    "\t-u force user program debugging mode\n"
	    "\t-w enable write mode\n"
	    "\t-y send terminal initialization sequences for tty mode\n"
	    "\t-A disable automatic loading of mdb modules\n"
	    "\t-F enable forcible takeover mode\n"
	    "\t-K stop operating system and enter live kernel debugger\n"
	    "\t-M preload all module symbols\n"
	    "\t-I set initial path for macro files\n"
	    "\t-L set initial path for module libs\n"
	    "\t-P set command-line prompt\n"
	    "\t-R set root directory for pathname expansion\n"
	    "\t-S suppress processing of ~/.mdbrc file\n"
	    "\t-U unload live kernel debugger\n"
	    "\t-W enable I/O-mapped memory access (kernel only)\n"
	    "\t-V set disassembler version\n");

	terminate(status);
}

static char *
mdb_scf_console_term(void)
{
	scf_simple_prop_t *prop;
	char *term = NULL;

	if ((prop = scf_simple_prop_get(NULL,
	    "svc:/system/console-login:default", "ttymon",
	    "terminal_type")) == NULL)
		return (NULL);

	if (scf_simple_prop_type(prop) == SCF_TYPE_ASTRING &&
	    (term = scf_simple_prop_next_astring(prop)) != NULL)
		term = strdup(term);

	scf_simple_prop_free(prop);
	return (term);
}

/*
 * Unpleasant hack: we might be debugging a hypervisor domain dump.
 * Earlier versions use a non-ELF file.  Later versions are ELF, but are
 * /always/ ELF64, so our standard ehdr check isn't good enough.  Since
 * we don't want to know too much about the file format, we'll ask
 * mdb_kb.
 */
#ifdef __x86
static int
identify_xvm_file(const char *file, int *longmode)
{
	int (*identify)(const char *, int *);

	if (mdb_module_load("mdb_kb", MDB_MOD_GLOBAL | MDB_MOD_SILENT) != 0)
		return (0);

	identify = (int (*)())dlsym(RTLD_NEXT, "xkb_identify");

	if (identify == NULL)
		return (0);

	return (identify(file, longmode));
}
#else
/*ARGSUSED*/
static int
identify_xvm_file(const char *file, int *longmode)
{
	return (0);
}
#endif /* __x86 */

int
main(int argc, char *argv[], char *envp[])
{
	extern int mdb_kvm_is_compressed_dump(mdb_io_t *);
	extern int mdb_kvm_is_dump(mdb_io_t *);
	mdb_tgt_ctor_f *tgt_ctor = NULL;
	const char **tgt_argv = alloca((argc + 2) * sizeof (char *));
	int tgt_argc = 0;
	mdb_tgt_t *tgt;

	char object[MAXPATHLEN], execname[MAXPATHLEN];
	mdb_io_t *in_io, *out_io, *err_io, *null_io;
	struct termios tios;
	int status, c;
	char *p;

	const char *Iflag = NULL, *Lflag = NULL, *Vflag = NULL, *pidarg = NULL;
	const char *eflag = NULL;
	int fflag = 0, Kflag = 0, Rflag = 0, Sflag = 0, Oflag = 0, Uflag = 0;

	int ttylike;
	int longmode = 0;

	stack_t sigstack;

	if (realpath(getexecname(), execname) == NULL) {
		(void) strncpy(execname, argv[0], MAXPATHLEN);
		execname[MAXPATHLEN - 1] = '\0';
	}

	mdb_create(execname, argv[0]);
	bzero(tgt_argv, argc * sizeof (char *));
	argv[0] = (char *)mdb.m_pname;
	_mdb_self_fd = open("/proc/self/as", O_RDONLY);

	mdb.m_env = envp;

	out_io = mdb_fdio_create(STDOUT_FILENO);
	mdb.m_out = mdb_iob_create(out_io, MDB_IOB_WRONLY);

	err_io = mdb_fdio_create(STDERR_FILENO);
	mdb.m_err = mdb_iob_create(err_io, MDB_IOB_WRONLY);
	mdb_iob_clrflags(mdb.m_err, MDB_IOB_AUTOWRAP);

	null_io = mdb_nullio_create();
	mdb.m_null = mdb_iob_create(null_io, MDB_IOB_WRONLY);

	in_io = mdb_fdio_create(STDIN_FILENO);
	if ((mdb.m_termtype = getenv("TERM")) != NULL) {
		mdb.m_termtype = strdup(mdb.m_termtype);
		mdb.m_flags |= MDB_FL_TERMGUESS;
	}
	mdb.m_term = NULL;

	mdb_dmode(mdb_dstr2mode(getenv("MDB_DEBUG")));
	mdb.m_pgid = getpgrp();

	if (getenv("_MDB_EXEC") != NULL)
		mdb.m_flags |= MDB_FL_EXEC;

	/*
	 * Setup an alternate signal stack.  When tearing down pipelines in
	 * terminate(), we may have to destroy the stack of the context in
	 * which we are currently executing the signal handler.
	 */
	sigstack.ss_sp = mmap(NULL, SIGSTKSZ, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (sigstack.ss_sp == MAP_FAILED)
		die("could not allocate signal stack");
	sigstack.ss_size = SIGSTKSZ;
	sigstack.ss_flags = 0;
	if (sigaltstack(&sigstack, NULL) != 0)
		die("could not set signal stack");

	(void) mdb_signal_sethandler(SIGPIPE, SIG_IGN, NULL);
	(void) mdb_signal_sethandler(SIGQUIT, SIG_IGN, NULL);

	(void) mdb_signal_sethandler(SIGILL, flt_handler, NULL);
	(void) mdb_signal_sethandler(SIGTRAP, flt_handler, NULL);
	(void) mdb_signal_sethandler(SIGIOT, flt_handler, NULL);
	(void) mdb_signal_sethandler(SIGEMT, flt_handler, NULL);
	(void) mdb_signal_sethandler(SIGFPE, flt_handler, NULL);
	(void) mdb_signal_sethandler(SIGBUS, flt_handler, NULL);
	(void) mdb_signal_sethandler(SIGSEGV, flt_handler, NULL);

	(void) mdb_signal_sethandler(SIGHUP, (mdb_signal_f *)terminate, NULL);
	(void) mdb_signal_sethandler(SIGTERM, (mdb_signal_f *)terminate, NULL);

	for (mdb.m_rdvers = RD_VERSION; mdb.m_rdvers > 0; mdb.m_rdvers--) {
		if (rd_init(mdb.m_rdvers) == RD_OK)
			break;
	}

	for (mdb.m_ctfvers = CTF_VERSION; mdb.m_ctfvers > 0; mdb.m_ctfvers--) {
		if (ctf_version(mdb.m_ctfvers) != -1)
			break;
	}

	if ((p = getenv("HISTSIZE")) != NULL && strisnum(p)) {
		mdb.m_histlen = strtoi(p);
		if (mdb.m_histlen < 1)
			mdb.m_histlen = 1;
	}

	while (optind < argc) {
		while ((c = getopt(argc, argv,
		    "e:fkmo:p:s:uwyACD:FI:KL:MOP:R:SUV:W")) != (int)EOF) {
			switch (c) {
			case 'e':
				if (eflag != NULL) {
					warn("-e already specified\n");
					terminate(2);
				}
				eflag = optarg;
				break;
			case 'f':
				fflag++;
				tgt_ctor = mdb_rawfile_tgt_create;
				break;
			case 'k':
				tgt_ctor = mdb_kvm_tgt_create;
				break;
			case 'm':
				mdb.m_tgtflags |= MDB_TGT_F_NOLOAD;
				mdb.m_tgtflags &= ~MDB_TGT_F_PRELOAD;
				break;
			case 'o':
				if (!mdb_set_options(optarg, TRUE))
					terminate(2);
				break;
			case 'p':
				tgt_ctor = mdb_proc_tgt_create;
				pidarg = optarg;
				break;
			case 's':
				if (!strisnum(optarg)) {
					warn("expected integer following -s\n");
					terminate(2);
				}
				mdb.m_symdist = (size_t)(uint_t)strtoi(optarg);
				break;
			case 'u':
				tgt_ctor = mdb_proc_tgt_create;
				break;
			case 'w':
				mdb.m_tgtflags |= MDB_TGT_F_RDWR;
				break;
			case 'y':
				mdb.m_flags |= MDB_FL_USECUP;
				break;
			case 'A':
				(void) mdb_set_options("nomods", TRUE);
				break;
			case 'C':
				(void) mdb_set_options("noctf", TRUE);
				break;
			case 'D':
				mdb_dmode(mdb_dstr2mode(optarg));
				break;
			case 'F':
				mdb.m_tgtflags |= MDB_TGT_F_FORCE;
				break;
			case 'I':
				Iflag = optarg;
				break;
			case 'L':
				Lflag = optarg;
				break;
			case 'K':
				Kflag++;
				break;
			case 'M':
				mdb.m_tgtflags |= MDB_TGT_F_PRELOAD;
				mdb.m_tgtflags &= ~MDB_TGT_F_NOLOAD;
				break;
			case 'O':
				Oflag++;
				break;
			case 'P':
				if (!mdb_set_prompt(optarg))
					terminate(2);
				break;
			case 'R':
				(void) strncpy(mdb.m_root, optarg, MAXPATHLEN);
				mdb.m_root[MAXPATHLEN - 1] = '\0';
				Rflag++;
				break;
			case 'S':
				Sflag++;
				break;
			case 'U':
				Uflag++;
				break;
			case 'V':
				Vflag = optarg;
				break;
			case 'W':
				mdb.m_tgtflags |= MDB_TGT_F_ALLOWIO;
				break;
			case '?':
				if (optopt == '?')
					usage(0);
				/* FALLTHROUGH */
			default:
				usage(2);
			}
		}

		if (optind < argc) {
			const char *arg = argv[optind++];

			if (arg[0] == '+' && strlen(arg) == 2) {
				if (arg[1] != 'o') {
					warn("illegal option -- %s\n", arg);
					terminate(2);
				}
				if (optind >= argc) {
					warn("option requires an argument -- "
					    "%s\n", arg);
					terminate(2);
				}
				if (!mdb_set_options(argv[optind++], FALSE))
					terminate(2);
			} else
				tgt_argv[tgt_argc++] = arg;
		}
	}

	if (rd_ctl(RD_CTL_SET_HELPPATH, (void *)mdb.m_root) != RD_OK) {
		warn("cannot set librtld_db helper path to %s\n", mdb.m_root);
		terminate(2);
	}

	if (mdb.m_debug & MDB_DBG_HELP)
		terminate(0); /* Quit here if we've printed out the tokens */


	if (Iflag != NULL && strchr(Iflag, ';') != NULL) {
		warn("macro path cannot contain semicolons\n");
		terminate(2);
	}

	if (Lflag != NULL && strchr(Lflag, ';') != NULL) {
		warn("module path cannot contain semicolons\n");
		terminate(2);
	}

	if (Kflag || Uflag) {
		char *nm;

		if (tgt_ctor != NULL || Iflag != NULL) {
			warn("neither -f, -k, -p, -u, nor -I "
			    "may be used with -K\n");
			usage(2);
		}

		if (Lflag != NULL)
			mdb_set_lpath(Lflag);

		if ((nm = ttyname(STDIN_FILENO)) == NULL ||
		    strcmp(nm, "/dev/console") != 0) {
			/*
			 * Due to the consequences of typing mdb -K instead of
			 * mdb -k on a tty other than /dev/console, we require
			 * -F when starting kmdb from a tty other than
			 * /dev/console.
			 */
			if (!(mdb.m_tgtflags & MDB_TGT_F_FORCE)) {
				die("-F must also be supplied to start kmdb "
				    "from non-console tty\n");
			}

			if (mdb.m_termtype == NULL || (mdb.m_flags &
			    MDB_FL_TERMGUESS)) {
				if (mdb.m_termtype != NULL)
					strfree(mdb.m_termtype);

				if ((mdb.m_termtype = mdb_scf_console_term()) !=
				    NULL)
					mdb.m_flags |= MDB_FL_TERMGUESS;
			}
		} else {
			/*
			 * When on console, $TERM (if set) takes precedence over
			 * the SMF setting.
			 */
			if (mdb.m_termtype == NULL && (mdb.m_termtype =
			    mdb_scf_console_term()) != NULL)
				mdb.m_flags |= MDB_FL_TERMGUESS;
		}

		control_kmdb(Kflag);
		terminate(0);
		/*NOTREACHED*/
	}

	if (eflag != NULL) {
		IOP_CLOSE(in_io);
		in_io = mdb_strio_create(eflag);
		mdb.m_lastret = 0;
	}

	/*
	 * If standard input appears to have tty attributes, attempt to
	 * initialize a terminal i/o backend on top of stdin and stdout.
	 */
	ttylike = (IOP_CTL(in_io, TCGETS, &tios) == 0);
	if (ttylike) {
		if ((mdb.m_term = mdb_termio_create(mdb.m_termtype,
		    in_io, out_io)) == NULL) {
			if (!(mdb.m_flags & MDB_FL_EXEC)) {
				warn("term init failed: command-line editing "
				    "and prompt will not be available\n");
			}
		} else {
			in_io = mdb.m_term;
		}
	}

	mdb.m_in = mdb_iob_create(in_io, MDB_IOB_RDONLY);
	if (mdb.m_term != NULL) {
		mdb_iob_setpager(mdb.m_out, mdb.m_term);
		if (mdb.m_flags & MDB_FL_PAGER)
			mdb_iob_setflags(mdb.m_out, MDB_IOB_PGENABLE);
		else
			mdb_iob_clrflags(mdb.m_out, MDB_IOB_PGENABLE);
	} else if (ttylike)
		mdb_iob_setflags(mdb.m_in, MDB_IOB_TTYLIKE);
	else
		mdb_iob_setbuf(mdb.m_in, mdb_alloc(1, UM_SLEEP), 1);

	mdb_pservice_init();
	mdb_lex_reset();

	if ((mdb.m_shell = getenv("SHELL")) == NULL)
		mdb.m_shell = "/bin/sh";

	/*
	 * If the debugger state is to be inherited from a previous instance,
	 * restore it now prior to path evaluation so that %R is updated.
	 */
	if ((p = getenv(MDB_CONFIG_ENV_VAR)) != NULL) {
		mdb_set_config(p);
		(void) unsetenv(MDB_CONFIG_ENV_VAR);
	}

	/*
	 * Path evaluation part 1: Create the initial module path to allow
	 * the target constructor to load a support module.  Then expand
	 * any command-line arguments that modify the paths.
	 */
	if (Iflag != NULL)
		mdb_set_ipath(Iflag);
	else
		mdb_set_ipath(MDB_DEF_IPATH);

	if (Lflag != NULL)
		mdb_set_lpath(Lflag);
	else
		mdb_set_lpath(MDB_DEF_LPATH);

	if (mdb_get_prompt() == NULL && !(mdb.m_flags & MDB_FL_ADB))
		(void) mdb_set_prompt(MDB_DEF_PROMPT);

	if (tgt_ctor == mdb_kvm_tgt_create) {
		if (pidarg != NULL) {
			warn("-p and -k options are mutually exclusive\n");
			terminate(2);
		}

		if (tgt_argc == 0)
			tgt_argv[tgt_argc++] = "/dev/ksyms";
		if (tgt_argc == 1 && strisnum(tgt_argv[0]) == 0) {
			if (mdb.m_tgtflags & MDB_TGT_F_ALLOWIO)
				tgt_argv[tgt_argc++] = "/dev/allkmem";
			else
				tgt_argv[tgt_argc++] = "/dev/kmem";
		}
	}

	if (pidarg != NULL) {
		if (tgt_argc != 0) {
			warn("-p may not be used with other arguments\n");
			terminate(2);
		}
		if (proc_arg_psinfo(pidarg, PR_ARG_PIDS, NULL, &status) == -1) {
			die("cannot attach to %s: %s\n",
			    pidarg, Pgrab_error(status));
		}
		if (strchr(pidarg, '/') != NULL)
			(void) mdb_iob_snprintf(object, MAXPATHLEN,
			    "%s/object/a.out", pidarg);
		else
			(void) mdb_iob_snprintf(object, MAXPATHLEN,
			    "/proc/%s/object/a.out", pidarg);
		tgt_argv[tgt_argc++] = object;
		tgt_argv[tgt_argc++] = pidarg;
	}

	/*
	 * Find the first argument that is not a special "-" token.  If one is
	 * found, we will examine this file and make some inferences below.
	 */
	for (c = 0; c < tgt_argc && strcmp(tgt_argv[c], "-") == 0; c++)
		continue;

	if (c < tgt_argc) {
		Elf32_Ehdr ehdr;
		mdb_io_t *io;

		/*
		 * If special "-" tokens preceded an argument, shift the entire
		 * argument list to the left to remove the leading "-" args.
		 */
		if (c > 0) {
			bcopy(&tgt_argv[c], tgt_argv,
			    sizeof (const char *) * (tgt_argc - c));
			tgt_argc -= c;
		}

		if (fflag)
			goto tcreate; /* skip re-exec and just create target */

		/*
		 * If we just have an object file name, and that file doesn't
		 * exist, and it's a string of digits, infer it to be a
		 * sequence number referring to a pair of crash dump files.
		 */
		if (tgt_argc == 1 && access(tgt_argv[0], F_OK) == -1 &&
		    strisnum(tgt_argv[0])) {

			size_t len = strlen(tgt_argv[0]) + 8;
			const char *object = tgt_argv[0];

			tgt_argv[0] = alloca(len);
			tgt_argv[1] = alloca(len);

			(void) strcpy((char *)tgt_argv[0], "unix.");
			(void) strcat((char *)tgt_argv[0], object);
			(void) strcpy((char *)tgt_argv[1], "vmcore.");
			(void) strcat((char *)tgt_argv[1], object);

			if (access(tgt_argv[0], F_OK) == -1 &&
			    access(tgt_argv[1], F_OK) != -1) {
				/*
				 * If we have a vmcore but not a unix file,
				 * set the symbol table to be the vmcore to
				 * force libkvm to extract it out of the dump.
				 */
				tgt_argv[0] = tgt_argv[1];
			} else if (access(tgt_argv[0], F_OK) == -1 &&
			    access(tgt_argv[1], F_OK) == -1) {
				(void) strcpy((char *)tgt_argv[1], "vmdump.");
				(void) strcat((char *)tgt_argv[1], object);
				if (access(tgt_argv[1], F_OK) == 0) {
					mdb_iob_printf(mdb.m_err,
					    "cannot open compressed dump; "
					    "decompress using savecore -f %s\n",
					    tgt_argv[1]);
					terminate(0);
				}
			}

			tgt_argc = 2;
		}

		/*
		 * We need to open the object file in order to determine its
		 * ELF class and potentially re-exec ourself.
		 */
		if ((io = mdb_fdio_create_path(NULL, tgt_argv[0],
		    O_RDONLY, 0)) == NULL)
			die("failed to open %s", tgt_argv[0]);

		if (tgt_argc == 1) {
			if (mdb_kvm_is_compressed_dump(io)) {
				/*
				 * We have a single vmdump.N compressed dump
				 * file; give a helpful message.
				 */
				mdb_iob_printf(mdb.m_err,
				    "cannot open compressed dump; "
				    "decompress using savecore -f %s\n",
				    tgt_argv[0]);
				terminate(0);
			} else if (mdb_kvm_is_dump(io)) {
				/*
				 * We have an uncompressed dump as our only
				 * argument; specify the dump as the symbol
				 * table to force libkvm to dig it out of the
				 * dump.
				 */
				tgt_argv[tgt_argc++] = tgt_argv[0];
			}
		}

		/*
		 * If the target is unknown or is not the rawfile target, do
		 * a gelf_check to determine if the file is an ELF file.  If
		 * it is not and the target is unknown, use the rawfile tgt.
		 * Otherwise an ELF-based target is needed, so we must abort.
		 */
		if (mdb_gelf_check(io, &ehdr, ET_NONE) == -1) {
			if (tgt_ctor != NULL) {
				(void) mdb_gelf_check(io, &ehdr, ET_EXEC);
				mdb_io_destroy(io);
				terminate(1);
			} else
				tgt_ctor = mdb_rawfile_tgt_create;
		}

		mdb_io_destroy(io);

		if (identify_xvm_file(tgt_argv[0], &longmode) == 1) {
#ifdef _LP64
			if (!longmode)
				goto reexec;
#else
			if (longmode)
				goto reexec;
#endif
			tgt_ctor = mdb_kvm_tgt_create;
			goto tcreate;
		}

		/*
		 * The object file turned out to be a user core file (ET_CORE),
		 * and no other arguments were specified, swap 0 and 1.  The
		 * proc target will infer the executable for us.
		 */
		if (ehdr.e_type == ET_CORE) {
			tgt_argv[tgt_argc++] = tgt_argv[0];
			tgt_argv[0] = NULL;
			tgt_ctor = mdb_proc_tgt_create;
		}

		/*
		 * If tgt_argv[1] is filled in, open it up and determine if it
		 * is a vmcore file.  If it is, gelf_check will fail and we
		 * set tgt_ctor to 'kvm'; otherwise we use the default.
		 */
		if (tgt_argc > 1 && strcmp(tgt_argv[1], "-") != 0 &&
		    tgt_argv[0] != NULL && pidarg == NULL) {
			Elf32_Ehdr chdr;

			if (access(tgt_argv[1], F_OK) == -1)
				die("failed to access %s", tgt_argv[1]);

			/* *.N case: drop vmdump.N from the list */
			if (tgt_argc == 3) {
				if ((io = mdb_fdio_create_path(NULL,
				    tgt_argv[2], O_RDONLY, 0)) == NULL)
					die("failed to open %s", tgt_argv[2]);
				if (mdb_kvm_is_compressed_dump(io))
					tgt_argv[--tgt_argc] = NULL;
				mdb_io_destroy(io);
			}

			if ((io = mdb_fdio_create_path(NULL, tgt_argv[1],
			    O_RDONLY, 0)) == NULL)
				die("failed to open %s", tgt_argv[1]);

			if (mdb_gelf_check(io, &chdr, ET_NONE) == -1)
				tgt_ctor = mdb_kvm_tgt_create;

			mdb_io_destroy(io);
		}

		/*
		 * At this point, we've read the ELF header for either an
		 * object file or core into ehdr.  If the class does not match
		 * ours, attempt to exec the mdb of the appropriate class.
		 */
#ifdef _LP64
		if (ehdr.e_ident[EI_CLASS] == ELFCLASS32)
			goto reexec;
#else
		if (ehdr.e_ident[EI_CLASS] == ELFCLASS64)
			goto reexec;
#endif
	}

tcreate:
	if (tgt_ctor == NULL)
		tgt_ctor = mdb_proc_tgt_create;

	tgt = mdb_tgt_create(tgt_ctor, mdb.m_tgtflags, tgt_argc, tgt_argv);

	if (tgt == NULL) {
		if (errno == EINVAL)
			usage(2); /* target can return EINVAL to get usage */
		if (errno == EMDB_TGT)
			terminate(1); /* target already printed error msg */
		die("failed to initialize target");
	}

	mdb_tgt_activate(tgt);

	mdb_create_loadable_disasms();

	if (Vflag != NULL && mdb_dis_select(Vflag) == -1)
		warn("invalid disassembler mode -- %s\n", Vflag);


	if (Rflag && mdb.m_term != NULL)
		warn("Using proto area %s\n", mdb.m_root);

	/*
	 * If the target was successfully constructed and -O was specified,
	 * we now attempt to enter piggy-mode for debugging jurassic problems.
	 */
	if (Oflag) {
		pcinfo_t pci;

		(void) strcpy(pci.pc_clname, "RT");

		if (priocntl(P_LWPID, P_MYID, PC_GETCID, (caddr_t)&pci) != -1) {
			pcparms_t pcp;
			rtparms_t *rtp = (rtparms_t *)pcp.pc_clparms;

			rtp->rt_pri = 35;
			rtp->rt_tqsecs = 0;
			rtp->rt_tqnsecs = RT_TQDEF;

			pcp.pc_cid = pci.pc_cid;

			if (priocntl(P_LWPID, P_MYID, PC_SETPARMS,
			    (caddr_t)&pcp) == -1) {
				warn("failed to set RT parameters");
				Oflag = 0;
			}
		} else {
			warn("failed to get RT class id");
			Oflag = 0;
		}

		if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
			warn("failed to lock address space");
			Oflag = 0;
		}

		if (Oflag)
			mdb_printf("%s: oink, oink!\n", mdb.m_pname);
	}

	/*
	 * Path evaluation part 2: Re-evaluate the path now that the target
	 * is ready (and thus we have access to the real platform string).
	 * Do this before reading ~/.mdbrc to allow path modifications prior
	 * to performing module auto-loading.
	 */
	mdb_set_ipath(mdb.m_ipathstr);
	mdb_set_lpath(mdb.m_lpathstr);

	if (!Sflag && (p = getenv("HOME")) != NULL) {
		char rcpath[MAXPATHLEN];
		mdb_io_t *rc_io;
		int fd;

		(void) mdb_iob_snprintf(rcpath, MAXPATHLEN, "%s/.mdbrc", p);
		fd = open64(rcpath, O_RDONLY);

		if (fd >= 0 && (rc_io = mdb_fdio_create_named(fd, rcpath))) {
			mdb_iob_t *iob = mdb_iob_create(rc_io, MDB_IOB_RDONLY);
			mdb_iob_t *old = mdb.m_in;

			mdb.m_in = iob;
			(void) mdb_run();
			mdb.m_in = old;
		}
	}

	if (!(mdb.m_flags & MDB_FL_NOMODS))
		mdb_module_load_all(0);

	(void) mdb_signal_sethandler(SIGINT, int_handler, NULL);
	while ((status = mdb_run()) == MDB_ERR_ABORT ||
	    status == MDB_ERR_OUTPUT) {
		/*
		 * If a write failed on stdout, give up.  A more informative
		 * error message will already have been printed by mdb_run().
		 */
		if (status == MDB_ERR_OUTPUT &&
		    mdb_iob_getflags(mdb.m_out) & MDB_IOB_ERR) {
			mdb_warn("write to stdout failed, exiting\n");
			break;
		}
		continue;
	}

	terminate((status == MDB_ERR_QUIT || status == 0) ?
	    (eflag != NULL && mdb.m_lastret != 0 ? 1 : 0) : 1);
	/*NOTREACHED*/
	return (0);

reexec:
	if ((p = strrchr(execname, '/')) == NULL)
		die("cannot determine absolute pathname\n");
#ifdef _LP64
#ifdef __sparc
	(void) strcpy(p, "/../sparcv7/");
#else
	(void) strcpy(p, "/../i86/");
#endif
#else
#ifdef __sparc
	(void) strcpy(p, "/../sparcv9/");
#else
	(void) strcpy(p, "/../amd64/");
#endif
#endif
	(void) strcat(p, mdb.m_pname);

	if (mdb.m_term != NULL)
		(void) IOP_CTL(in_io, TCSETSW, &tios);

	(void) putenv("_MDB_EXEC=1");
	(void) execv(execname, argv);

	/*
	 * If execv fails, suppress ENOEXEC.  Experience shows the most common
	 * reason is that the machine is booted under a 32-bit kernel, in which
	 * case it is clearer to only print the message below.
	 */
	if (errno != ENOEXEC)
		warn("failed to exec %s", execname);
#ifdef _LP64
	die("64-bit %s cannot debug 32-bit program %s\n",
	    mdb.m_pname, tgt_argv[0] ?
	    tgt_argv[0] : tgt_argv[1]);
#else
	die("32-bit %s cannot debug 64-bit program %s\n",
	    mdb.m_pname, tgt_argv[0] ?
	    tgt_argv[0] : tgt_argv[1]);
#endif

	goto tcreate;
}
