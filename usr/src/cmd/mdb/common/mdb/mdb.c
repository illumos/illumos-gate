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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

/*
 * Modular Debugger (MDB)
 *
 * Refer to the white paper "A Modular Debugger for Solaris" for information
 * on the design, features, and goals of MDB.  See /shared/sac/PSARC/1999/169
 * for copies of the paper and related documentation.
 *
 * This file provides the basic construction and destruction of the debugger's
 * global state, as well as the main execution loop, mdb_run().  MDB maintains
 * a stack of execution frames (mdb_frame_t's) that keep track of its current
 * state, including a stack of input and output buffers, walk and memory
 * garbage collect lists, and a list of commands (mdb_cmd_t's).  As the
 * parser consumes input, it fills in a list of commands to execute, and then
 * invokes mdb_call(), below.  A command consists of a dcmd, telling us
 * what function to execute, and a list of arguments and other invocation-
 * specific data.  Each frame may have more than one command, kept on a list,
 * when multiple commands are separated by | operators.  New frames may be
 * stacked on old ones by nested calls to mdb_run: this occurs when, for
 * example, in the middle of processing one input source (such as a file
 * or the terminal), we invoke a dcmd that in turn calls mdb_eval().  mdb_eval
 * will construct a new frame whose input source is the string passed to
 * the eval function, and then execute this frame to completion.
 */

#include <sys/param.h>
#include <stropts.h>

#define	_MDB_PRIVATE
#include <mdb/mdb.h>

#include <mdb/mdb_context.h>
#include <mdb/mdb_argvec.h>
#include <mdb/mdb_signal.h>
#include <mdb/mdb_macalias.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_callb.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_ctf.h>
#ifdef _KMDB
#include <kmdb/kmdb_module.h>
#endif

/*
 * Macro for testing if a dcmd's return status (x) indicates that we should
 * abort the current loop or pipeline.
 */
#define	DCMD_ABORTED(x)	((x) == DCMD_USAGE || (x) == DCMD_ABORT)

extern const mdb_dcmd_t mdb_dcmd_builtins[];
extern mdb_dis_ctor_f *const mdb_dis_builtins[];

/*
 * Variable discipline for toggling MDB_FL_PSYM based on the value of the
 * undocumented '_' variable.  Once adb(1) has been removed from the system,
 * we should just remove this functionality and always disable PSYM for macros.
 */
static uintmax_t
psym_disc_get(const mdb_var_t *v)
{
	int i = (mdb.m_flags & MDB_FL_PSYM) ? 1 : 0;
	int j = (MDB_NV_VALUE(v) != 0) ? 1 : 0;

	if ((i ^ j) == 0)
		MDB_NV_VALUE((mdb_var_t *)v) = j ^ 1;

	return (MDB_NV_VALUE(v));
}

static void
psym_disc_set(mdb_var_t *v, uintmax_t value)
{
	if (value == 0)
		mdb.m_flags |= MDB_FL_PSYM;
	else
		mdb.m_flags &= ~MDB_FL_PSYM;

	MDB_NV_VALUE(v) = value;
}

/*
 * Variable discipline for making <1 (most recent offset) behave properly.
 */
static uintmax_t
roff_disc_get(const mdb_var_t *v)
{
	return (MDB_NV_VALUE(v));
}

static void
roff_disc_set(mdb_var_t *v, uintmax_t value)
{
	mdb_nv_set_value(mdb.m_proffset, MDB_NV_VALUE(v));
	MDB_NV_VALUE(v) = value;
}

/*
 * Variable discipline for exporting the representative thread.
 */
static uintmax_t
thr_disc_get(const mdb_var_t *v)
{
	mdb_tgt_status_t s;

	if (mdb.m_target != NULL && mdb_tgt_status(mdb.m_target, &s) == 0)
		return (s.st_tid);

	return (MDB_NV_VALUE(v));
}

const char **
mdb_path_alloc(const char *s, size_t *newlen)
{
	char *format = mdb_alloc(strlen(s) * 2 + 1, UM_NOSLEEP);
	const char **path;
	char *p, *q;

	struct utsname uts;
	size_t len;
	int i;

	mdb_arg_t arg_i, arg_m, arg_p, arg_r, arg_t, arg_R, arg_V;
	mdb_argvec_t argv;

	static const char *empty_path[] = { NULL };

	if (format == NULL)
		goto nomem;

	while (*s == ':')
		s++; /* strip leading delimiters */

	if (*s == '\0') {
		*newlen = 0;
		return (empty_path);
	}

	(void) strcpy(format, s);
	mdb_argvec_create(&argv);

	/*
	 * %i embedded in path string expands to ISA.
	 */
	arg_i.a_type = MDB_TYPE_STRING;
	if (mdb.m_target != NULL)
		arg_i.a_un.a_str = mdb_tgt_isa(mdb.m_target);
	else
		arg_i.a_un.a_str = mdb_conf_isa();

	/*
	 * %p embedded in path string expands to the platform name.
	 */
	arg_p.a_type = MDB_TYPE_STRING;
	if (mdb.m_target != NULL)
		arg_p.a_un.a_str = mdb_tgt_platform(mdb.m_target);
	else
		arg_p.a_un.a_str = mdb_conf_platform();

	/*
	 * %r embedded in path string expands to root directory, or
	 * to the empty string if root is "/" (to avoid // in paths).
	 */
	arg_r.a_type = MDB_TYPE_STRING;
	arg_r.a_un.a_str = strcmp(mdb.m_root, "/") ? mdb.m_root : "";

	/*
	 * %t embedded in path string expands to the target name, defaulting to
	 * kvm; this is so we can find mdb_kb, which is used during bootstrap.
	 */
	arg_t.a_type = MDB_TYPE_STRING;
	arg_t.a_un.a_str = mdb.m_target ? mdb_tgt_name(mdb.m_target) : "kvm";

	/*
	 * %R and %V expand to uname -r (release) and uname -v (version).
	 */
	if (mdb.m_target == NULL || mdb_tgt_uname(mdb.m_target, &uts) < 0)
		mdb_conf_uname(&uts);

	arg_m.a_type = MDB_TYPE_STRING;
	arg_m.a_un.a_str = uts.machine;

	arg_R.a_type = MDB_TYPE_STRING;
	arg_R.a_un.a_str = uts.release;

	arg_V.a_type = MDB_TYPE_STRING;
	if (mdb.m_flags & MDB_FL_LATEST)
		arg_V.a_un.a_str = "latest";
	else
		arg_V.a_un.a_str = uts.version;

	/*
	 * In order to expand the buffer, we examine the format string for
	 * our % tokens and construct an argvec, replacing each % token
	 * with %s along the way.  If we encounter an unknown token, we
	 * shift over the remaining format buffer and stick in %%.
	 */
	for (q = format; (q = strchr(q, '%')) != NULL; q++) {
		switch (q[1]) {
		case 'i':
			mdb_argvec_append(&argv, &arg_i);
			*++q = 's';
			break;
		case 'm':
			mdb_argvec_append(&argv, &arg_m);
			*++q = 's';
			break;
		case 'p':
			mdb_argvec_append(&argv, &arg_p);
			*++q = 's';
			break;
		case 'r':
			mdb_argvec_append(&argv, &arg_r);
			*++q = 's';
			break;
		case 't':
			mdb_argvec_append(&argv, &arg_t);
			*++q = 's';
			break;
		case 'R':
			mdb_argvec_append(&argv, &arg_R);
			*++q = 's';
			break;
		case 'V':
			mdb_argvec_append(&argv, &arg_V);
			*++q = 's';
			break;
		default:
			bcopy(q + 1, q + 2, strlen(q));
			*++q = '%';
		}
	}

	/*
	 * We're now ready to use our printf engine to format the final string.
	 * Take one lap with a NULL buffer to determine how long the final
	 * string will be, allocate it, and format it.
	 */
	len = mdb_iob_asnprintf(NULL, 0, format, argv.a_data);
	if ((p = mdb_alloc(len + 1, UM_NOSLEEP)) != NULL)
		(void) mdb_iob_asnprintf(p, len + 1, format, argv.a_data);
	else
		goto nomem;

	mdb_argvec_zero(&argv);
	mdb_argvec_destroy(&argv);

	mdb_free(format, strlen(s) * 2 + 1);
	format = NULL;

	/*
	 * Compress the string to exclude any leading delimiters.
	 */
	for (q = p; *q == ':'; q++)
		continue;
	if (q != p)
		bcopy(q, p, strlen(q) + 1);

	/*
	 * Count up the number of delimited elements.  A sequence of
	 * consecutive delimiters is only counted once.
	 */
	for (i = 1, q = p; (q = strchr(q, ':')) != NULL; i++) {
		while (*q == ':')
			q++;
	}

	if ((path = mdb_alloc(sizeof (char *) * (i + 1), UM_NOSLEEP)) == NULL) {
		mdb_free(p, len + 1);
		goto nomem;
	}

	for (i = 0, q = strtok(p, ":"); q != NULL; q = strtok(NULL, ":"))
		path[i++] = q;

	path[i] = NULL;
	*newlen = len + 1;
	return (path);

nomem:
	warn("failed to allocate memory for path");
	if (format != NULL)
		mdb_free(format, strlen(s) * 2 + 1);
	*newlen = 0;
	return (empty_path);
}

const char **
mdb_path_dup(const char *path[], size_t pathlen, size_t *npathlenp)
{
	char **npath;
	int i, j;

	for (i = 0; path[i] != NULL; i++)
		continue; /* count the path elements */

	npath = mdb_zalloc(sizeof (char *) * (i + 1), UM_SLEEP);
	if (pathlen > 0) {
		npath[0] = mdb_alloc(pathlen, UM_SLEEP);
		bcopy(path[0], npath[0], pathlen);
	}

	for (j = 1; j < i; j++)
		npath[j] = npath[0] + (path[j] - path[0]);
	npath[i] = NULL;

	*npathlenp = pathlen;
	return ((const char **)npath);
}

void
mdb_path_free(const char *path[], size_t pathlen)
{
	int i;

	for (i = 0; path[i] != NULL; i++)
		continue; /* count the path elements */

	if (i > 0) {
		mdb_free((void *)path[0], pathlen);
		mdb_free(path, sizeof (char *) * (i + 1));
	}
}

/*
 * Convert path string "s" to canonical form, expanding any %o tokens that are
 * found within the path.  The old path string is specified by "path", a buffer
 * of size MAXPATHLEN which is then overwritten with the new path string.
 */
static const char *
path_canon(char *path, const char *s)
{
	char *p = path;
	char *q = p + MAXPATHLEN - 1;

	char old[MAXPATHLEN];
	char c;

	(void) strcpy(old, p);
	*q = '\0';

	while (p < q && (c = *s++) != '\0') {
		if (c == '%') {
			if ((c = *s++) == 'o') {
				(void) strncpy(p, old, (size_t)(q - p));
				p += strlen(p);
			} else {
				*p++ = '%';
				if (p < q && c != '\0')
					*p++ = c;
				else
					break;
			}
		} else
			*p++ = c;
	}

	*p = '\0';
	return (path);
}

void
mdb_set_ipath(const char *path)
{
	if (mdb.m_ipath != NULL)
		mdb_path_free(mdb.m_ipath, mdb.m_ipathlen);

	path = path_canon(mdb.m_ipathstr, path);
	mdb.m_ipath = mdb_path_alloc(path, &mdb.m_ipathlen);
}

void
mdb_set_lpath(const char *path)
{
	if (mdb.m_lpath != NULL)
		mdb_path_free(mdb.m_lpath, mdb.m_lpathlen);

	path = path_canon(mdb.m_lpathstr, path);
	mdb.m_lpath = mdb_path_alloc(path, &mdb.m_lpathlen);

#ifdef _KMDB
	kmdb_module_path_set(mdb.m_lpath, mdb.m_lpathlen);
#endif
}

static void
prompt_update(void)
{
	(void) mdb_snprintf(mdb.m_prompt, sizeof (mdb.m_prompt),
	    mdb.m_promptraw);
	mdb.m_promptlen = strlen(mdb.m_prompt);
}

const char *
mdb_get_prompt(void)
{
	if (mdb.m_promptlen == 0)
		return (NULL);
	else
		return (mdb.m_prompt);
}

int
mdb_set_prompt(const char *p)
{
	size_t len = strlen(p);

	if (len > MDB_PROMPTLEN) {
		warn("prompt may not exceed %d characters\n", MDB_PROMPTLEN);
		return (0);
	}

	(void) strcpy(mdb.m_promptraw, p);
	prompt_update();
	return (1);
}

static mdb_frame_t frame0;

void
mdb_create(const char *execname, const char *arg0)
{
	static const mdb_nv_disc_t psym_disc = { psym_disc_set, psym_disc_get };
	static const mdb_nv_disc_t roff_disc = { roff_disc_set, roff_disc_get };
	static const mdb_nv_disc_t thr_disc = { NULL, thr_disc_get };

	static char rootdir[MAXPATHLEN];

	const mdb_dcmd_t *dcp;
	int i;

	bzero(&mdb, sizeof (mdb_t));

	mdb.m_flags = MDB_FL_PSYM | MDB_FL_PAGER | MDB_FL_BPTNOSYMSTOP |
	    MDB_FL_READBACK;
	mdb.m_radix = MDB_DEF_RADIX;
	mdb.m_nargs = MDB_DEF_NARGS;
	mdb.m_histlen = MDB_DEF_HISTLEN;
	mdb.m_armemlim = MDB_DEF_ARRMEM;
	mdb.m_arstrlim = MDB_DEF_ARRSTR;

	mdb.m_pname = strbasename(arg0);
	if (strcmp(mdb.m_pname, "adb") == 0) {
		mdb.m_flags |= MDB_FL_NOMODS | MDB_FL_ADB | MDB_FL_REPLAST;
		mdb.m_flags &= ~MDB_FL_PAGER;
	}

	mdb.m_ipathstr = mdb_zalloc(MAXPATHLEN, UM_SLEEP);
	mdb.m_lpathstr = mdb_zalloc(MAXPATHLEN, UM_SLEEP);

	(void) strncpy(rootdir, execname, sizeof (rootdir));
	rootdir[sizeof (rootdir) - 1] = '\0';
	(void) strdirname(rootdir);

	if (strcmp(strbasename(rootdir), "sparcv9") == 0 ||
	    strcmp(strbasename(rootdir), "sparcv7") == 0 ||
	    strcmp(strbasename(rootdir), "amd64") == 0 ||
	    strcmp(strbasename(rootdir), "i86") == 0)
		(void) strdirname(rootdir);

	if (strcmp(strbasename(rootdir), "bin") == 0) {
		(void) strdirname(rootdir);
		if (strcmp(strbasename(rootdir), "usr") == 0)
			(void) strdirname(rootdir);
	} else
		(void) strcpy(rootdir, "/");

	mdb.m_root = rootdir;

	mdb.m_rminfo.mi_dvers = MDB_API_VERSION;
	mdb.m_rminfo.mi_dcmds = mdb_dcmd_builtins;
	mdb.m_rminfo.mi_walkers = NULL;

	(void) mdb_nv_create(&mdb.m_rmod.mod_walkers, UM_SLEEP);
	(void) mdb_nv_create(&mdb.m_rmod.mod_dcmds, UM_SLEEP);

	mdb.m_rmod.mod_name = mdb.m_pname;
	mdb.m_rmod.mod_info = &mdb.m_rminfo;

	(void) mdb_nv_create(&mdb.m_disasms, UM_SLEEP);
	(void) mdb_nv_create(&mdb.m_modules, UM_SLEEP);
	(void) mdb_nv_create(&mdb.m_dcmds, UM_SLEEP);
	(void) mdb_nv_create(&mdb.m_walkers, UM_SLEEP);
	(void) mdb_nv_create(&mdb.m_nv, UM_SLEEP);

	mdb.m_dot = mdb_nv_insert(&mdb.m_nv, ".", NULL, 0, MDB_NV_PERSIST);
	mdb.m_rvalue = mdb_nv_insert(&mdb.m_nv, "0", NULL, 0, MDB_NV_PERSIST);

	mdb.m_roffset =
	    mdb_nv_insert(&mdb.m_nv, "1", &roff_disc, 0, MDB_NV_PERSIST);

	mdb.m_proffset = mdb_nv_insert(&mdb.m_nv, "2", NULL, 0, MDB_NV_PERSIST);
	mdb.m_rcount = mdb_nv_insert(&mdb.m_nv, "9", NULL, 0, MDB_NV_PERSIST);

	(void) mdb_nv_insert(&mdb.m_nv, "b", NULL, 0, MDB_NV_PERSIST);
	(void) mdb_nv_insert(&mdb.m_nv, "d", NULL, 0, MDB_NV_PERSIST);
	(void) mdb_nv_insert(&mdb.m_nv, "e", NULL, 0, MDB_NV_PERSIST);
	(void) mdb_nv_insert(&mdb.m_nv, "m", NULL, 0, MDB_NV_PERSIST);
	(void) mdb_nv_insert(&mdb.m_nv, "t", NULL, 0, MDB_NV_PERSIST);
	(void) mdb_nv_insert(&mdb.m_nv, "_", &psym_disc, 0, MDB_NV_PERSIST);
	(void) mdb_nv_insert(&mdb.m_nv, "hits", NULL, 0, MDB_NV_PERSIST);

	(void) mdb_nv_insert(&mdb.m_nv, "thread", &thr_disc, 0,
	    MDB_NV_PERSIST | MDB_NV_RDONLY);

	mdb.m_prsym = mdb_gelf_symtab_create_mutable();

	(void) mdb_nv_insert(&mdb.m_modules, mdb.m_pname, NULL,
	    (uintptr_t)&mdb.m_rmod, MDB_NV_RDONLY);

	for (dcp = &mdb_dcmd_builtins[0]; dcp->dc_name != NULL; dcp++)
		(void) mdb_module_add_dcmd(&mdb.m_rmod, dcp, 0);

	for (i = 0; mdb_dis_builtins[i] != NULL; i++)
		(void) mdb_dis_create(mdb_dis_builtins[i]);

	mdb_macalias_create();

	mdb_create_builtin_tgts();

	(void) mdb_callb_add(NULL, MDB_CALLB_PROMPT, (mdb_callb_f)prompt_update,
	    NULL);

	/*
	 * The call to ctf_create that this does can in fact fail, but that's
	 * okay. All of the ctf functions that might use the synthetic types
	 * make sure that this is safe.
	 */
	(void) mdb_ctf_synthetics_init();

#ifdef _KMDB
	(void) mdb_nv_create(&mdb.m_dmodctl, UM_SLEEP);
#endif
	mdb_lex_state_create(&frame0);

	mdb_list_append(&mdb.m_flist, &frame0);
	mdb.m_frame = &frame0;
}

void
mdb_destroy(void)
{
	const mdb_dcmd_t *dcp;
	mdb_var_t *v;
	int unload_mode = MDB_MOD_SILENT;

#ifdef _KMDB
	unload_mode |= MDB_MOD_DEFER;
#endif

	mdb_intr_disable();

	mdb_ctf_synthetics_fini();

	mdb_macalias_destroy();

	/*
	 * Some targets use modules during ->t_destroy, so do it first.
	 */
	if (mdb.m_target != NULL)
		(void) mdb_tgt_destroy(mdb.m_target);

	/*
	 * Unload modules _before_ destroying the disassemblers since a
	 * module that installs a disassembler should try to clean up after
	 * itself.
	 */
	mdb_module_unload_all(unload_mode);

	mdb_nv_rewind(&mdb.m_disasms);
	while ((v = mdb_nv_advance(&mdb.m_disasms)) != NULL)
		mdb_dis_destroy(mdb_nv_get_cookie(v));

	mdb_callb_remove_all();

	if (mdb.m_defdisasm != NULL)
		strfree(mdb.m_defdisasm);

	if (mdb.m_prsym != NULL)
		mdb_gelf_symtab_destroy(mdb.m_prsym);

	for (dcp = &mdb_dcmd_builtins[0]; dcp->dc_name != NULL; dcp++)
		(void) mdb_module_remove_dcmd(&mdb.m_rmod, dcp->dc_name);

	mdb_nv_destroy(&mdb.m_nv);
	mdb_nv_destroy(&mdb.m_walkers);
	mdb_nv_destroy(&mdb.m_dcmds);
	mdb_nv_destroy(&mdb.m_modules);
	mdb_nv_destroy(&mdb.m_disasms);

	mdb_free(mdb.m_ipathstr, MAXPATHLEN);
	mdb_free(mdb.m_lpathstr, MAXPATHLEN);

	if (mdb.m_ipath != NULL)
		mdb_path_free(mdb.m_ipath, mdb.m_ipathlen);

	if (mdb.m_lpath != NULL)
		mdb_path_free(mdb.m_lpath, mdb.m_lpathlen);

	if (mdb.m_in != NULL)
		mdb_iob_destroy(mdb.m_in);

	mdb_iob_destroy(mdb.m_out);
	mdb.m_out = NULL;
	mdb_iob_destroy(mdb.m_err);
	mdb.m_err = NULL;

	if (mdb.m_log != NULL)
		mdb_io_rele(mdb.m_log);

	mdb_lex_state_destroy(&frame0);
}

/*
 * The real main loop of the debugger: create a new execution frame on the
 * debugger stack, and while we have input available, call into the parser.
 */
int
mdb_run(void)
{
	volatile int err;
	mdb_frame_t f;

	mdb_intr_disable();
	mdb_frame_push(&f);

	/*
	 * This is a fresh mdb context, so ignore any pipe command we may have
	 * inherited from the previous frame.
	 */
	f.f_pcmd = NULL;

	if ((err = setjmp(f.f_pcb)) != 0) {
		int pop = (mdb.m_in != NULL &&
		    (mdb_iob_isapipe(mdb.m_in) || mdb_iob_isastr(mdb.m_in)));
		int fromcmd = (f.f_cp != NULL);

		mdb_dprintf(MDB_DBG_DSTK, "frame <%u> caught event %s\n",
		    f.f_id, mdb_err2str(err));

		/*
		 * If a syntax error or other failure has occurred, pop all
		 * input buffers pushed by commands executed in this frame.
		 */
		while (mdb_iob_stack_size(&f.f_istk) != 0) {
			if (mdb.m_in != NULL)
				mdb_iob_destroy(mdb.m_in);
			mdb.m_in = mdb_iob_stack_pop(&f.f_istk);
			yylineno = mdb_iob_lineno(mdb.m_in);
		}

		/*
		 * Reset standard output and the current frame to a known,
		 * clean state, so we can continue execution.
		 */
		mdb_iob_margin(mdb.m_out, MDB_IOB_DEFMARGIN);
		mdb_iob_clrflags(mdb.m_out, MDB_IOB_INDENT);
		mdb_iob_discard(mdb.m_out);
		mdb_frame_reset(&f);

		/*
		 * If there was an error writing to output, display a warning
		 * message if this is the topmost frame.
		 */
		if (err == MDB_ERR_OUTPUT && mdb.m_depth == 1 && errno != EPIPE)
			mdb_warn("write failed");

		/*
		 * If an interrupt or quit signal is reported, we may have been
		 * in the middle of typing or processing the command line:
		 * print a newline and discard everything in the parser's iob.
		 * Note that we do this after m_out has been reset, otherwise
		 * we could trigger a pipe context switch or cause a write
		 * to a broken pipe (in the case of a shell command) when
		 * writing the newline.
		 */
		if (err == MDB_ERR_SIGINT || err == MDB_ERR_QUIT) {
			mdb_iob_nl(mdb.m_out);
			yydiscard();
		}

		/*
		 * If we quit or abort using the output pager, reset the
		 * line count on standard output back to zero.
		 */
		if (err == MDB_ERR_PAGER || MDB_ERR_IS_FATAL(err))
			mdb_iob_clearlines(mdb.m_out);

		/*
		 * If the user requested the debugger quit or abort back to
		 * the top, or if standard input is a pipe or mdb_eval("..."),
		 * then propagate the error up the debugger stack.
		 */
		if (MDB_ERR_IS_FATAL(err) || pop != 0 ||
		    (err == MDB_ERR_PAGER && mdb.m_fmark != &f) ||
		    (err == MDB_ERR_NOMEM && !fromcmd)) {
			mdb_frame_pop(&f, err);
			return (err);
		}

		/*
		 * If we've returned here from a context where signals were
		 * blocked (e.g. a signal handler), we can now unblock them.
		 */
		if (err == MDB_ERR_SIGINT)
			(void) mdb_signal_unblock(SIGINT);
	} else
		mdb_intr_enable();

	for (;;) {
		while (mdb.m_in != NULL && (mdb_iob_getflags(mdb.m_in) &
		    (MDB_IOB_ERR | MDB_IOB_EOF)) == 0) {
			if (mdb.m_depth == 1 &&
			    mdb_iob_stack_size(&f.f_istk) == 0) {
				mdb_iob_clearlines(mdb.m_out);
				mdb_tgt_periodic(mdb.m_target);
			}

			(void) yyparse();
		}

		if (mdb.m_in != NULL) {
			if (mdb_iob_err(mdb.m_in)) {
				warn("error reading input stream %s\n",
				    mdb_iob_name(mdb.m_in));
			}
			mdb_iob_destroy(mdb.m_in);
			mdb.m_in = NULL;
		}

		if (mdb_iob_stack_size(&f.f_istk) == 0)
			break; /* return when we're out of input */

		mdb.m_in = mdb_iob_stack_pop(&f.f_istk);
		yylineno = mdb_iob_lineno(mdb.m_in);
	}

	mdb_frame_pop(&f, 0);

	/*
	 * The value of '.' is a per-frame attribute, to preserve it properly
	 * when switching frames.  But in the case of calling mdb_run()
	 * explicitly (such as through mdb_eval), we want to propagate the value
	 * of '.' to the parent.
	 */
	mdb_nv_set_value(mdb.m_dot, f.f_dot);

	return (0);
}

/*
 * The read-side of the pipe executes this service routine.  We simply call
 * mdb_run to create a new frame on the execution stack and run the MDB parser,
 * and then propagate any error code back to the previous frame.
 */
static int
runsvc(void)
{
	int err = mdb_run();

	if (err != 0) {
		mdb_dprintf(MDB_DBG_DSTK, "forwarding error %s from pipeline\n",
		    mdb_err2str(err));
		longjmp(mdb.m_frame->f_pcb, err);
	}

	return (err);
}

/*
 * Read-side pipe service routine: if we longjmp here, just return to the read
 * routine because now we have more data to consume.  Otherwise:
 * (1) if ctx_data is non-NULL, longjmp to the write-side to produce more data;
 * (2) if wriob is NULL, there is no writer but this is the first read, so we
 *     can just execute mdb_run() to completion on the current stack;
 * (3) if (1) and (2) are false, then there is a writer and this is the first
 *     read, so create a co-routine context to execute mdb_run().
 */
/*ARGSUSED*/
static void
rdsvc(mdb_iob_t *rdiob, mdb_iob_t *wriob, mdb_iob_ctx_t *ctx)
{
	if (setjmp(ctx->ctx_rpcb) == 0) {
		/*
		 * Save the current standard input into the pipe context, and
		 * reset m_in to point to the pipe.  We will restore it on
		 * the way back in wrsvc() below.
		 */
		ctx->ctx_iob = mdb.m_in;
		mdb.m_in = rdiob;

		ctx->ctx_rptr = mdb.m_frame;
		if (ctx->ctx_wptr != NULL)
			mdb_frame_switch(ctx->ctx_wptr);

		if (ctx->ctx_data != NULL)
			longjmp(ctx->ctx_wpcb, 1);
		else if (wriob == NULL)
			(void) runsvc();
		else if ((ctx->ctx_data = mdb_context_create(runsvc)) != NULL)
			mdb_context_switch(ctx->ctx_data);
		else
			mdb_warn("failed to create pipe context");
	}
}

/*
 * Write-side pipe service routine: if we longjmp here, just return to the
 * write routine because now we have free space in the pipe buffer for writing;
 * otherwise longjmp to the read-side to consume data and create space for us.
 */
/*ARGSUSED*/
static void
wrsvc(mdb_iob_t *rdiob, mdb_iob_t *wriob, mdb_iob_ctx_t *ctx)
{
	if (setjmp(ctx->ctx_wpcb) == 0) {
		ctx->ctx_wptr = mdb.m_frame;
		if (ctx->ctx_rptr != NULL)
			mdb_frame_switch(ctx->ctx_rptr);

		mdb.m_in = ctx->ctx_iob;
		longjmp(ctx->ctx_rpcb, 1);
	}
}

/*
 * Call the current frame's mdb command.  This entry point is used by the
 * MDB parser to actually execute a command once it has successfully parsed
 * a line of input.  The command is waiting for us in the current frame.
 * We loop through each command on the list, executing its dcmd with the
 * appropriate argument.  If the command has a successor, we know it had
 * a | operator after it, and so we need to create a pipe and replace
 * stdout with the pipe's output buffer.
 */
int
mdb_call(uintmax_t addr, uintmax_t count, uint_t flags)
{
	mdb_frame_t *fp = mdb.m_frame;
	mdb_cmd_t *cp, *ncp;
	mdb_iob_t *iobs[2];
	int status, err = 0;
	jmp_buf pcb;

	if (mdb_iob_isapipe(mdb.m_in))
		yyerror("syntax error");

	mdb_intr_disable();
	fp->f_cp = mdb_list_next(&fp->f_cmds);

	if (flags & DCMD_LOOP)
		flags |= DCMD_LOOPFIRST; /* set LOOPFIRST if this is a loop */

	for (cp = mdb_list_next(&fp->f_cmds); cp; cp = mdb_list_next(cp)) {
		if (mdb_list_next(cp) != NULL) {
			mdb_iob_pipe(iobs, rdsvc, wrsvc);

			mdb_iob_stack_push(&fp->f_istk, mdb.m_in, yylineno);
			mdb.m_in = iobs[MDB_IOB_RDIOB];

			mdb_iob_stack_push(&fp->f_ostk, mdb.m_out, 0);
			mdb.m_out = iobs[MDB_IOB_WRIOB];

			ncp = mdb_list_next(cp);
			mdb_vcb_inherit(cp, ncp);

			bcopy(fp->f_pcb, pcb, sizeof (jmp_buf));
			ASSERT(fp->f_pcmd == NULL);
			fp->f_pcmd = ncp;

			mdb_frame_set_pipe(fp);

			if ((err = setjmp(fp->f_pcb)) == 0) {
				status = mdb_call_idcmd(cp->c_dcmd, addr, count,
				    flags | DCMD_PIPE_OUT, &cp->c_argv,
				    &cp->c_addrv, cp->c_vcbs);

				mdb.m_lastret = status;

				ASSERT(mdb.m_in == iobs[MDB_IOB_RDIOB]);
				ASSERT(mdb.m_out == iobs[MDB_IOB_WRIOB]);
			} else {
				mdb_dprintf(MDB_DBG_DSTK, "frame <%u> caught "
				    "error %s from pipeline\n", fp->f_id,
				    mdb_err2str(err));
			}

			if (err != 0 || DCMD_ABORTED(status)) {
				mdb_iob_setflags(mdb.m_in, MDB_IOB_ERR);
				mdb_iob_setflags(mdb.m_out, MDB_IOB_ERR);
			} else {
				mdb_iob_flush(mdb.m_out);
				(void) mdb_iob_ctl(mdb.m_out, I_FLUSH,
				    (void *)FLUSHW);
			}

			mdb_frame_clear_pipe(fp);

			mdb_iob_destroy(mdb.m_out);
			mdb.m_out = mdb_iob_stack_pop(&fp->f_ostk);

			if (mdb.m_in != NULL)
				mdb_iob_destroy(mdb.m_in);

			mdb.m_in = mdb_iob_stack_pop(&fp->f_istk);
			yylineno = mdb_iob_lineno(mdb.m_in);

			fp->f_pcmd = NULL;
			bcopy(pcb, fp->f_pcb, sizeof (jmp_buf));

			if (MDB_ERR_IS_FATAL(err))
				longjmp(fp->f_pcb, err);

			if (err != 0 || DCMD_ABORTED(status) ||
			    mdb_addrvec_length(&ncp->c_addrv) == 0)
				break;

			addr = mdb_nv_get_value(mdb.m_dot);
			count = 1;
			flags = 0;

		} else {
			mdb_intr_enable();
			mdb.m_lastret = mdb_call_idcmd(cp->c_dcmd, addr, count,
			    flags, &cp->c_argv, &cp->c_addrv, cp->c_vcbs);
			mdb_intr_disable();
		}

		fp->f_cp = mdb_list_next(cp);
		mdb_cmd_reset(cp);
	}

	/*
	 * If our last-command list is non-empty, destroy it.  Then copy the
	 * current frame's cmd list to the m_lastc list and reset the frame.
	 */
	while ((cp = mdb_list_next(&mdb.m_lastc)) != NULL) {
		mdb_list_delete(&mdb.m_lastc, cp);
		mdb_cmd_destroy(cp);
	}

	mdb_list_move(&fp->f_cmds, &mdb.m_lastc);
	mdb_frame_reset(fp);
	mdb_intr_enable();
	return (err == 0);
}

uintmax_t
mdb_dot_incr(const char *op)
{
	uintmax_t odot, ndot;

	odot = mdb_nv_get_value(mdb.m_dot);
	ndot = odot + mdb.m_incr;

	if ((odot ^ ndot) & 0x8000000000000000ull)
		yyerror("'%s' would cause '.' to overflow\n", op);

	return (ndot);
}

uintmax_t
mdb_dot_decr(const char *op)
{
	uintmax_t odot, ndot;

	odot = mdb_nv_get_value(mdb.m_dot);
	ndot = odot - mdb.m_incr;

	if (ndot > odot)
		yyerror("'%s' would cause '.' to underflow\n", op);

	return (ndot);
}

mdb_iwalker_t *
mdb_walker_lookup(const char *s)
{
	const char *p = strchr(s, '`');
	mdb_var_t *v;

	if (p != NULL) {
		size_t nbytes = MIN((size_t)(p - s), MDB_NV_NAMELEN - 1);
		char mname[MDB_NV_NAMELEN];
		mdb_module_t *mod;

		(void) strncpy(mname, s, nbytes);
		mname[nbytes] = '\0';

		if ((v = mdb_nv_lookup(&mdb.m_modules, mname)) == NULL) {
			(void) set_errno(EMDB_NOMOD);
			return (NULL);
		}

		mod = mdb_nv_get_cookie(v);

		if ((v = mdb_nv_lookup(&mod->mod_walkers, ++p)) != NULL)
			return (mdb_nv_get_cookie(v));

	} else if ((v = mdb_nv_lookup(&mdb.m_walkers, s)) != NULL)
		return (mdb_nv_get_cookie(mdb_nv_get_cookie(v)));

	(void) set_errno(EMDB_NOWALK);
	return (NULL);
}

mdb_idcmd_t *
mdb_dcmd_lookup(const char *s)
{
	const char *p = strchr(s, '`');
	mdb_var_t *v;

	if (p != NULL) {
		size_t nbytes = MIN((size_t)(p - s), MDB_NV_NAMELEN - 1);
		char mname[MDB_NV_NAMELEN];
		mdb_module_t *mod;

		(void) strncpy(mname, s, nbytes);
		mname[nbytes] = '\0';

		if ((v = mdb_nv_lookup(&mdb.m_modules, mname)) == NULL) {
			(void) set_errno(EMDB_NOMOD);
			return (NULL);
		}

		mod = mdb_nv_get_cookie(v);

		if ((v = mdb_nv_lookup(&mod->mod_dcmds, ++p)) != NULL)
			return (mdb_nv_get_cookie(v));

	} else if ((v = mdb_nv_lookup(&mdb.m_dcmds, s)) != NULL)
		return (mdb_nv_get_cookie(mdb_nv_get_cookie(v)));

	(void) set_errno(EMDB_NODCMD);
	return (NULL);
}

void
mdb_dcmd_usage(const mdb_idcmd_t *idcp, mdb_iob_t *iob)
{
	const char *prefix = "", *usage = "";
	char name0 = idcp->idc_name[0];

	if (idcp->idc_usage != NULL) {
		if (idcp->idc_usage[0] == ':') {
			if (name0 != ':' && name0 != '$')
				prefix = "address::";
			else
				prefix = "address";
			usage = &idcp->idc_usage[1];

		} else if (idcp->idc_usage[0] == '?') {
			if (name0 != ':' && name0 != '$')
				prefix = "[address]::";
			else
				prefix = "[address]";
			usage = &idcp->idc_usage[1];

		} else
			usage = idcp->idc_usage;
	}

	mdb_iob_printf(iob, "Usage: %s%s %s\n", prefix, idcp->idc_name, usage);

	if (idcp->idc_help != NULL) {
		mdb_iob_printf(iob, "%s: try '::help %s' for more "
		    "information\n", mdb.m_pname, idcp->idc_name);
	}
}

static mdb_idcmd_t *
dcmd_ndef(const mdb_idcmd_t *idcp)
{
	mdb_var_t *v = mdb_nv_get_ndef(idcp->idc_var);

	if (v != NULL)
		return (mdb_nv_get_cookie(mdb_nv_get_cookie(v)));

	return (NULL);
}

static int
dcmd_invoke(mdb_idcmd_t *idcp, uintptr_t addr, uint_t flags,
    int argc, const mdb_arg_t *argv, const mdb_vcb_t *vcbs)
{
	int status;

	mdb_dprintf(MDB_DBG_DCMD, "dcmd %s`%s dot = %lr incr = %llr\n",
	    idcp->idc_modp->mod_name, idcp->idc_name, addr, mdb.m_incr);

	if ((status = idcp->idc_funcp(addr, flags, argc, argv)) == DCMD_USAGE) {
		mdb_dcmd_usage(idcp, mdb.m_err);
		goto done;
	}

	while (status == DCMD_NEXT && (idcp = dcmd_ndef(idcp)) != NULL)
		status = idcp->idc_funcp(addr, flags, argc, argv);

	if (status == DCMD_USAGE)
		mdb_dcmd_usage(idcp, mdb.m_err);

	if (status == DCMD_NEXT)
		status = DCMD_OK;
done:
	/*
	 * If standard output is a pipe and there are vcbs active, we need to
	 * flush standard out and the write-side of the pipe.  The reasons for
	 * this are explained in more detail in mdb_vcb.c.
	 */
	if ((flags & DCMD_PIPE_OUT) && (vcbs != NULL)) {
		mdb_iob_flush(mdb.m_out);
		(void) mdb_iob_ctl(mdb.m_out, I_FLUSH, (void *)FLUSHW);
	}

	return (status);
}

void
mdb_call_tab(mdb_idcmd_t *idcp, mdb_tab_cookie_t *mcp, uint_t flags,
    uintmax_t argc, mdb_arg_t *argv)
{
	if (idcp->idc_tabp == NULL)
		return;

	idcp->idc_tabp(mcp, flags, argc, argv);
}

/*
 * Call an internal dcmd directly: this code is used by module API functions
 * that need to execute dcmds, and by mdb_call() above.
 */
int
mdb_call_idcmd(mdb_idcmd_t *idcp, uintmax_t addr, uintmax_t count,
    uint_t flags, mdb_argvec_t *avp, mdb_addrvec_t *adp, mdb_vcb_t *vcbs)
{
	int is_exec = (strcmp(idcp->idc_name, "$<") == 0);
	mdb_arg_t *argv;
	int argc;
	uintmax_t i;
	int status;

	/*
	 * Update the values of dot and the most recent address and count
	 * to the values of our input parameters.
	 */
	mdb_nv_set_value(mdb.m_dot, addr);
	mdb.m_raddr = addr;
	mdb.m_dcount = count;

	/*
	 * Here the adb(1) man page lies: '9' is only set to count
	 * when the command is $<, not when it's $<<.
	 */
	if (is_exec)
		mdb_nv_set_value(mdb.m_rcount, count);

	/*
	 * We can now return if the repeat count is zero.
	 */
	if (count == 0)
		return (DCMD_OK);

	/*
	 * To guard against bad dcmds, we avoid passing the actual argv that
	 * we will use to free argument strings directly to the dcmd.  Instead,
	 * we pass a copy that will be garbage collected automatically.
	 */
	argc = avp->a_nelems;
	argv = mdb_alloc(sizeof (mdb_arg_t) * argc, UM_SLEEP | UM_GC);
	bcopy(avp->a_data, argv, sizeof (mdb_arg_t) * argc);

	if (mdb_addrvec_length(adp) != 0) {
		flags |= DCMD_PIPE | DCMD_LOOP | DCMD_LOOPFIRST | DCMD_ADDRSPEC;
		addr = mdb_addrvec_shift(adp);
		mdb_nv_set_value(mdb.m_dot, addr);
		mdb_vcb_propagate(vcbs);
		count = 1;
	}

	status = dcmd_invoke(idcp, addr, flags, argc, argv, vcbs);
	if (DCMD_ABORTED(status))
		goto done;

	/*
	 * If the command is $< and we're not receiving input from a pipe, we
	 * ignore the repeat count and just return since the macro file is now
	 * pushed on to the input stack.
	 */
	if (is_exec && mdb_addrvec_length(adp) == 0)
		goto done;

	/*
	 * If we're going to loop, we've already executed the dcmd once,
	 * so clear the LOOPFIRST flag before proceeding.
	 */
	if (flags & DCMD_LOOP)
		flags &= ~DCMD_LOOPFIRST;

	for (i = 1; i < count; i++) {
		addr = mdb_dot_incr(",");
		mdb_nv_set_value(mdb.m_dot, addr);
		status = dcmd_invoke(idcp, addr, flags, argc, argv, vcbs);
		if (DCMD_ABORTED(status))
			goto done;
	}

	while (mdb_addrvec_length(adp) != 0) {
		addr = mdb_addrvec_shift(adp);
		mdb_nv_set_value(mdb.m_dot, addr);
		mdb_vcb_propagate(vcbs);
		status = dcmd_invoke(idcp, addr, flags, argc, argv, vcbs);
		if (DCMD_ABORTED(status))
			goto done;
	}
done:
	mdb_iob_nlflush(mdb.m_out);
	return (status);
}

void
mdb_intr_enable(void)
{
	ASSERT(mdb.m_intr >= 1);
	if (mdb.m_intr == 1 && mdb.m_pend != 0) {
		(void) mdb_signal_block(SIGINT);
		mdb.m_intr = mdb.m_pend = 0;
		mdb_dprintf(MDB_DBG_DSTK, "delivering pending INT\n");
		longjmp(mdb.m_frame->f_pcb, MDB_ERR_SIGINT);
	} else
		mdb.m_intr--;
}

void
mdb_intr_disable(void)
{
	mdb.m_intr++;
	ASSERT(mdb.m_intr >= 1);
}

/*
 * Create an encoded string representing the internal user-modifiable
 * configuration of the debugger and return a pointer to it.  The string can be
 * used to initialize another instance of the debugger with the same
 * configuration as this one.
 */
char *
mdb_get_config(void)
{
	size_t r, n = 0;
	char *s = NULL;

	while ((r = mdb_snprintf(s, n,
	    "%x;%x;%x;%x;%x;%x;%lx;%x;%x;%s;%s;%s;%s;%s",
	    mdb.m_tgtflags, mdb.m_flags, mdb.m_debug, mdb.m_radix, mdb.m_nargs,
	    mdb.m_histlen, (ulong_t)mdb.m_symdist, mdb.m_execmode,
	    mdb.m_forkmode, mdb.m_root, mdb.m_termtype, mdb.m_ipathstr,
	    mdb.m_lpathstr, mdb.m_prompt)) > n) {

		mdb_free(s, n);
		n = r + 1;
		s = mdb_alloc(r + 1, UM_SLEEP);
	}

	return (s);
}

/*
 * Decode a configuration string created with mdb_get_config() and reset the
 * appropriate parts of the global mdb_t accordingly.
 */
void
mdb_set_config(const char *s)
{
	const char *p;
	size_t len;

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_tgtflags = strntoul(s, (size_t)(p - s), 16);
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_flags = strntoul(s, (size_t)(p - s), 16);
		mdb.m_flags &= ~(MDB_FL_LOG | MDB_FL_LATEST);
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_debug = strntoul(s, (size_t)(p - s), 16);
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_radix = (int)strntoul(s, (size_t)(p - s), 16);
		if (mdb.m_radix < 2 || mdb.m_radix > 16)
			mdb.m_radix = MDB_DEF_RADIX;
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_nargs = (int)strntoul(s, (size_t)(p - s), 16);
		mdb.m_nargs = MAX(mdb.m_nargs, 0);
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_histlen = (int)strntoul(s, (size_t)(p - s), 16);
		mdb.m_histlen = MAX(mdb.m_histlen, 1);
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_symdist = strntoul(s, (size_t)(p - s), 16);
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_execmode = (uchar_t)strntoul(s, (size_t)(p - s), 16);
		if (mdb.m_execmode > MDB_EM_FOLLOW)
			mdb.m_execmode = MDB_EM_ASK;
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_forkmode = (uchar_t)strntoul(s, (size_t)(p - s), 16);
		if (mdb.m_forkmode > MDB_FM_CHILD)
			mdb.m_forkmode = MDB_FM_ASK;
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_root = strndup(s, (size_t)(p - s));
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		mdb.m_termtype = strndup(s, (size_t)(p - s));
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		size_t len = MIN(sizeof (mdb.m_ipathstr) - 1, p - s);
		(void) strncpy(mdb.m_ipathstr, s, len);
		mdb.m_ipathstr[len] = '\0';
		s = p + 1;
	}

	if ((p = strchr(s, ';')) != NULL) {
		size_t len = MIN(sizeof (mdb.m_lpathstr) - 1, p - s);
		(void) strncpy(mdb.m_lpathstr, s, len);
		mdb.m_lpathstr[len] = '\0';
		s = p + 1;
	}

	p = s + strlen(s);
	len = MIN(MDB_PROMPTLEN, (size_t)(p - s));
	(void) strncpy(mdb.m_prompt, s, len);
	mdb.m_prompt[len] = '\0';
	mdb.m_promptlen = len;
}

mdb_module_t *
mdb_get_module(void)
{
	if (mdb.m_lmod)
		return (mdb.m_lmod);

	if (mdb.m_frame == NULL)
		return (NULL);

	if (mdb.m_frame->f_wcbs && mdb.m_frame->f_wcbs->w_walker &&
	    mdb.m_frame->f_wcbs->w_walker->iwlk_modp &&
	    !mdb.m_frame->f_cbactive)
		return (mdb.m_frame->f_wcbs->w_walker->iwlk_modp);

	if (mdb.m_frame->f_cp && mdb.m_frame->f_cp->c_dcmd)
		return (mdb.m_frame->f_cp->c_dcmd->idc_modp);

	return (NULL);
}
