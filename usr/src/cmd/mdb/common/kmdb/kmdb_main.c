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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/termios.h>
#include <sys/param.h>
#include <sys/salib.h>

#include <alloca.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libctf.h>
#include <errno.h>
#include <ctype.h>

#include <kmdb/kmdb_promif.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_umemglue.h>
#include <kmdb/kmdb_io.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_wr.h>
#include <kmdb/kmdb_start.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_kvm.h>
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
#include <mdb/mdb.h>

#ifdef __sparc
#define	KMDB_STACK_SIZE	(384 * 1024)
#else
#define	KMDB_STACK_SIZE (192 * 1024)
#endif

caddr_t kmdb_main_stack;
size_t kmdb_main_stack_size;

#define	KMDB_DEF_IPATH	"internal"
#if defined(_LP64)
#define	KMDB_DEF_LPATH	\
	"%r/platform/%p/kernel/kmdb/%i:" \
	"%r/platform/%m/kernel/kmdb/%i:" \
	"%r/kernel/kmdb/%i"
#else
#define	KMDB_DEF_LPATH	\
	"%r/platform/%m/kernel/kmdb:" \
	"%r/kernel/kmdb"
#endif

#define	MDB_DEF_PROMPT "[%<_cpuid>]> "

#define	KMDB_DEF_TERM_TYPE	"vt100"

/*
 * Similar to the panic_* variables in the kernel, we keep some relevant
 * information stored in a set of global _mdb_abort_* variables; in the
 * event that the debugger dumps core, these will aid core dump analysis.
 */
const char *volatile _mdb_abort_str;	/* reason for failure */

/*
 * The kernel supplies a space-delimited list of directories
 * (/platform/sun4u/kernel /kernel /usr/kernel ...) which we must transform into
 * a debugger-friendly, colon-delimited module search path.  We add the kmdb
 * module directory to each component and change the delimiter.
 */
static char *
kmdb_modpath2lpath(const char *modpath)
{
#ifdef	_LP64
	static const char suffix[] = "/kmdb/%i:";
#else
	static const char suffix[] = "/kmdb:";
#endif
	const char *c;
	char *lpath, *lpend, *nlpath;
	size_t lpsz, lpres;

	if (strchr(modpath, ':') != NULL) {
		warn("invalid kernel module path\n");
		return (NULL);
	}

	lpres = lpsz = strlen(modpath) + MAXPATHLEN;
	lpend = lpath = mdb_zalloc(lpsz, UM_SLEEP);

	while (isspace(*modpath))
		modpath++;

	for (; *modpath != '\0'; modpath = c) {
		size_t sz;

		for (c = modpath; !isspace(*c) && *c != '\0'; c++)
			continue;

		sz = (c - modpath) + sizeof (suffix) - 1;
		if (sz >= lpres)
			continue;

		(void) strncpy(lpend, modpath, c - modpath);
		(void) strcpy(lpend + (c - modpath), suffix);

		lpend += sz;
		lpres -= sz;

		while (isspace(*c))
			c++;
	}

	if (lpend != lpath)
		lpend[-1] = '\0';	/* eat trailing colon */

	nlpath = strdup(lpath);
	mdb_free(lpath, lpsz);
	return (nlpath);
}

/*
 * called while the kernel is running
 */
int
kmdb_init(const char *execname, kmdb_auxv_t *kav)
{
	mdb_io_t *in_io, *out_io, *err_io, *null_io;
	mdb_tgt_ctor_f *tgt_ctor = kmdb_kvm_create;
	mdb_tgt_t *tgt;
	int i;

	/*
	 * The beginnings of debugger initialization are a bit of a dance, due
	 * to interlocking dependencies between kmdb_prom_init,
	 * mdb_umem_startup, and mdb_create.  In particular, allocator
	 * initialization can't begin until prom_init() is called,
	 * kmdb_prom_init can't finish until the allocator is ready and
	 * mdb_create has been called.  We therefore split kmdb_prom_init into
	 * two pieces, and call thembefore and after umem initialization and
	 * mdb_create.
	 */
	kmdb_prom_init_begin("kmdb", kav);
	mdb_umem_startup(kav->kav_dseg, kav->kav_dseg_size,
	    kav->kav_pagesize);
	mdb_create(execname, "kmdb");
	kmdb_prom_init_finish(kav);

	mdb.m_dseg = kav->kav_dseg;
	mdb.m_dsegsz = kav->kav_dseg_size;

	out_io = kmdb_promio_create("stdout");
	mdb.m_out = mdb_iob_create(out_io, MDB_IOB_WRONLY);

	err_io = kmdb_promio_create("stderr");
	mdb.m_err = mdb_iob_create(err_io, MDB_IOB_WRONLY);
	mdb_iob_clrflags(mdb.m_err, MDB_IOB_AUTOWRAP);

	null_io = mdb_nullio_create();
	mdb.m_null = mdb_iob_create(null_io, MDB_IOB_WRONLY);

	in_io = kmdb_promio_create("stdin");
	mdb.m_term = NULL;

	if (kav->kav_config != NULL)
		mdb_set_config(kav->kav_config);

	if (kav->kav_argv != NULL) {
		for (i = 0; kav->kav_argv[i] != NULL; i++) {
			if (!mdb_set_options(kav->kav_argv[i], TRUE))
				return (-1);
		}
	}

	if (kav->kav_flags & KMDB_AUXV_FL_NOUNLOAD)
		mdb.m_flags |= MDB_FL_NOUNLOAD;

	mdb.m_in = mdb_iob_create(in_io, MDB_IOB_RDONLY);
	mdb_iob_setflags(mdb.m_in, MDB_IOB_TTYLIKE);

	mdb_lex_reset();

	kmdb_kdi_init(kav->kav_kdi, kav);

	if (kmdb_dpi_init(kav) < 0) {
		warn("Couldn't initialize kernel/PROM interface\n");
		return (-1);
	}

	/*
	 * Path evaluation part 1: Create the initial module path to allow
	 * the target constructor to load a support module.  We base kmdb's
	 * module path off the kernel's module path unless the user has
	 * explicitly supplied one.
	 */
	mdb_set_ipath(KMDB_DEF_IPATH);
	if (strlen(mdb.m_lpathstr) > 0) {
		mdb_set_lpath(mdb.m_lpathstr);
	} else {
		char *lpath;

		if (kav->kav_modpath != NULL && *kav->kav_modpath != '\0' &&
		    (lpath = kmdb_modpath2lpath(kav->kav_modpath)) != NULL) {
			mdb_set_lpath(lpath);
			strfree(lpath);
		} else {
			mdb_set_lpath(KMDB_DEF_LPATH);
		}
	}

	if (mdb_get_prompt() == NULL)
		(void) mdb_set_prompt(MDB_DEF_PROMPT);

	tgt = mdb_tgt_create(tgt_ctor, mdb.m_tgtflags, 0, NULL);

	if (tgt == NULL) {
		warn("failed to initialize target");
		return (-1);
	}

	mdb_tgt_activate(tgt);

	mdb_create_loadable_disasms();

	/*
	 * Path evaluation part 2: Re-evaluate the path now that the target
	 * is ready (and thus we have access to the real platform string).
	 */
	mdb_set_ipath(mdb.m_ipathstr);
	mdb_set_lpath(mdb.m_lpathstr);

	if (!(mdb.m_flags & MDB_FL_NOMODS))
		mdb_module_load_all(MDB_MOD_DEFER);

	/* Allocate the main debugger stack */
	kmdb_main_stack = mdb_alloc(KMDB_STACK_SIZE, UM_SLEEP);
	kmdb_main_stack_size = KMDB_STACK_SIZE;

	kmdb_kdi_end_init();

	return (0);
}

#ifdef sun4v

void
kmdb_init_promif(char *pgmname, kmdb_auxv_t *kav)
{
	kmdb_prom_init_promif(pgmname, kav);
}

#else

/*ARGSUSED*/
void
kmdb_init_promif(char *pgmname, kmdb_auxv_t *kav)
{
	/*
	 * Fake function for non sun4v. See comments in kmdb_ctl.h
	 */
	ASSERT(0);
}

#endif

/*
 * First-time kmdb startup.  Run when kmdb has control of the machine for the
 * first time.
 */
static void
kmdb_startup(void)
{
	mdb_io_t *inio, *outio;

	if (mdb.m_termtype == NULL) {
		/*
		 * The terminal type wasn't specified, so we guess.  If we're
		 * on console, we'll get a terminal type from the PROM.  If not,
		 * we'll use the default.
		 */
		const char *ttype;

		if ((ttype = kmdb_prom_term_type()) == NULL) {
			ttype = KMDB_DEF_TERM_TYPE;
			warn("unable to determine terminal type: "
			    "assuming `%s'\n", ttype);
		}

		mdb.m_flags |= MDB_FL_TERMGUESS;
		mdb.m_termtype = strdup(ttype);

	} else if (mdb.m_flags & MDB_FL_TERMGUESS) {
		/*
		 * The terminal type wasn't specified by the user, but a guess
		 * was made using either $TERM or a property from the SMF.  A
		 * terminal type from the PROM code overrides the guess, so
		 * we'll use that if we can.
		 */
		char *promttype;

		if ((promttype = kmdb_prom_term_type()) != NULL) {
			strfree(mdb.m_termtype);
			mdb.m_termtype = strdup(promttype);
		}
	}

	inio = kmdb_promio_create("stdin");
	outio = kmdb_promio_create("stdout");

	if ((mdb.m_term = mdb_termio_create(mdb.m_termtype, inio, outio)) ==
	    NULL && strcmp(mdb.m_termtype, KMDB_DEF_TERM_TYPE) != 0) {
		warn("failed to set terminal type to `%s', using `"
		    KMDB_DEF_TERM_TYPE "'\n", mdb.m_termtype);

		strfree(mdb.m_termtype);
		mdb.m_termtype = strdup(KMDB_DEF_TERM_TYPE);

		if ((mdb.m_term = mdb_termio_create(mdb.m_termtype, inio,
		    outio)) == NULL) {
			fail("failed to set terminal type to `"
			    KMDB_DEF_TERM_TYPE "'\n");
		}
	}

	mdb_iob_destroy(mdb.m_in);
	mdb.m_in = mdb_iob_create(mdb.m_term, MDB_IOB_RDONLY);
	mdb_iob_setpager(mdb.m_out, mdb.m_term);
	mdb_iob_setflags(mdb.m_out, MDB_IOB_PGENABLE);

	kmdb_kvm_startup();

	/*
	 * kmdb_init() and kctl_activate() may have been talking to each other,
	 * and may have left some messages for us.  The driver -> debugger
	 * queue is normally processed during the resume path, so we have to
	 * do it manually here if we want it to be run for first startup.
	 */
	kmdb_dpi_process_work_queue();

	kmdb_kvm_poststartup();
}

void
kmdb_main(void)
{
	int status;

	kmdb_dpi_set_state(DPI_STATE_STOPPED, 0);
	mdb_printf("\nWelcome to kmdb\n");
	kmdb_startup();

	/*
	 * Debugger termination is a bit tricky.  For compatibility with kadb,
	 * neither an EOF on stdin nor a normal ::quit will cause the debugger
	 * to unload.  In both cases, they get a trip to OBP, after which the
	 * debugger returns.
	 *
	 * The only supported way to cause the debugger to unload is to specify
	 * the unload flag to ::quit, or to have the driver request it.  The
	 * driver request is the primary exit mechanism - the ::quit flag is
	 * provided for convenience.
	 *
	 * Both forms of "exit" (unqualified ::quit that won't cause an unload,
	 * and a driver request that will) are signalled by an MDB_ERR_QUIT.  In
	 * the latter case, however, the KDI will have the unload request.
	 */
	for (;;) {
		status = mdb_run();

		if (status == MDB_ERR_QUIT && kmdb_kdi_get_unload_request()) {
			break;

		} else if (status == MDB_ERR_QUIT || status == 0) {
			kmdb_dpi_enter_mon();

		} else if (status == MDB_ERR_OUTPUT) {
			/*
			 * If a write failed on stdout, give up.  A more
			 * informative error message will already have been
			 * printed by mdb_run().
			 */
			if (mdb_iob_getflags(mdb.m_out) & MDB_IOB_ERR)
				fail("write to stdout failed, exiting\n");

		} else if (status != MDB_ERR_ABORT) {
			fail("debugger exited abnormally (status = %s)\n",
			    mdb_err2str(status));
		}
	}

	mdb_destroy();

	kmdb_dpi_resume_unload();

	/*NOTREACHED*/
}
