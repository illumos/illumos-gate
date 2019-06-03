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

/*
 * Copyright 2017 Joyent, Inc.
 */

/*
 * Support for ::set dcmd.  The +/-o option processing code is provided in a
 * stand-alone function so it can be used by the command-line option processing
 * code in mdb_main.c.  This facility provides an easy way for us to add more
 * configurable options without having to add a new dcmd each time.
 */

#include <mdb/mdb_target.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

/*ARGSUSED*/
static int
opt_set_mflags(int enable, uint_t bits, const char *arg)
{
	mdb.m_flags = (mdb.m_flags & ~bits) | (bits & -enable);
	return (1);
}

/*ARGSUSED*/
static int
opt_set_tflags(int enable, uint_t bits, const char *arg)
{
	mdb.m_tgtflags = (mdb.m_tgtflags & ~bits) | (bits & -enable);
	return (1);
}

static int
opt_pager(int enable, uint_t bits, const char *arg)
{
	if (enable)
		mdb_iob_setflags(mdb.m_out, MDB_IOB_PGENABLE);
	else
		mdb_iob_clrflags(mdb.m_out, MDB_IOB_PGENABLE);

	return (opt_set_mflags(enable, bits, arg));
}

static int
opt_adb(int enable, uint_t bits, const char *arg)
{
	if (enable)
		(void) mdb_set_prompt("");
	else if (mdb.m_promptlen == 0)
		(void) mdb_set_prompt("> ");

	(void) opt_pager(1 - enable, MDB_FL_PAGER, arg);
	return (opt_set_mflags(enable, bits, arg));
}

/*ARGSUSED*/
static int
opt_armemlim(int enable, uint_t bits, const char *arg)
{
	if (strisnum(arg)) {
		mdb.m_armemlim = strtoi(arg);
		return (1);
	}
	if (strcmp(arg, "none") == 0) {
		mdb.m_armemlim = MDB_ARR_NOLIMIT;
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
opt_arstrlim(int enable, uint_t bits, const char *arg)
{
	if (strisnum(arg)) {
		mdb.m_arstrlim = strtoi(arg);
		return (1);
	}
	if (strcmp(arg, "none") == 0) {
		mdb.m_arstrlim = MDB_ARR_NOLIMIT;
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
opt_exec_mode(int enable, uint_t bits, const char *arg)
{
	if (strcmp(arg, "ask") == 0) {
		mdb.m_execmode = MDB_EM_ASK;
		return (1);
	} else if (strcmp(arg, "stop") == 0) {
		mdb.m_execmode = MDB_EM_STOP;
		return (1);
	} else if (strcmp(arg, "follow") == 0) {
		mdb.m_execmode = MDB_EM_FOLLOW;
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
opt_fork_mode(int enable, uint_t bits, const char *arg)
{
	if (strcmp(arg, "ask") == 0) {
		mdb.m_forkmode = MDB_FM_ASK;
		return (1);
	} else if (strcmp(arg, "parent") == 0) {
		mdb.m_forkmode = MDB_FM_PARENT;
		return (1);
	} else if (strcmp(arg, "child") == 0) {
		mdb.m_forkmode = MDB_FM_CHILD;
		return (1);
	}
	return (0);
}

/*ARGSUSED*/
static int
opt_set_term(int enable, uint_t bits, const char *arg)
{
	mdb.m_termtype = strdup(arg);
	mdb.m_flags &= ~MDB_FL_TERMGUESS;

	return (1);
}

int
mdb_set_options(const char *s, int enable)
{
	static const struct opdesc {
		const char *opt_name;
		int (*opt_func)(int, uint_t, const char *);
		uint_t opt_bits;
	} opdtab[] = {
		{ "adb", opt_adb, MDB_FL_REPLAST | MDB_FL_NOMODS | MDB_FL_ADB },
		{ "array_mem_limit", opt_armemlim, 0 },
		{ "array_str_limit", opt_arstrlim, 0 },
		{ "follow_exec_mode", opt_exec_mode, 0 },
		{ "follow_fork_mode", opt_fork_mode, 0 },
		{ "pager", opt_pager, MDB_FL_PAGER },
		{ "term", opt_set_term, 0 },

		{ "autowrap", opt_set_mflags, MDB_FL_AUTOWRAP },
		{ "ignoreeof", opt_set_mflags, MDB_FL_IGNEOF },
		{ "repeatlast", opt_set_mflags, MDB_FL_REPLAST },
		{ "latest", opt_set_mflags, MDB_FL_LATEST },
		{ "noctf", opt_set_mflags, MDB_FL_NOCTF },
		{ "nomods", opt_set_mflags, MDB_FL_NOMODS },
		{ "showlmid", opt_set_mflags, MDB_FL_SHOWLMID },
		{ "lmraw", opt_set_mflags, MDB_FL_LMRAW },
		{ "stop_on_bpt_nosym", opt_set_mflags, MDB_FL_BPTNOSYMSTOP },
		{ "write_readback", opt_set_mflags, MDB_FL_READBACK },

		{ "allow_io_access", opt_set_tflags, MDB_TGT_F_ALLOWIO },
		{ "nostop", opt_set_tflags, MDB_TGT_F_NOSTOP },
		{ NULL, NULL, 0 }
	};

	const struct opdesc *opp;
	char *buf = strdup(s);
	char *opt, *arg;
	int status = 1;

	for (opt = strtok(buf, ","); opt != NULL; opt = strtok(NULL, ",")) {
		if ((arg = strchr(opt, '=')) != NULL)
			*arg++ = '\0';

		for (opp = opdtab; opp->opt_name != NULL; opp++) {
			if (strcmp(opt, opp->opt_name) == 0) {
				if (opp->opt_bits != 0 && arg != NULL) {
					mdb_warn("option does not accept an "
					    "argument -- %s\n", opt);
					status = 0;
				} else if (opp->opt_bits == 0 && arg == NULL) {
					mdb_warn("option requires an argument "
					    "-- %s\n", opt);
					status = 0;
				} else if (opp->opt_func(enable != 0,
				    opp->opt_bits, arg) == 0) {
					mdb_warn("invalid argument for option "
					    "%s -- %s\n", opt, arg);
					status = 0;
				}
				break;
			}
		}

		if (opp->opt_name == NULL) {
			mdb_warn("invalid debugger option -- %s\n", opt);
			status = 0;
		}
	}

	mdb_free(buf, strlen(s) + 1);
	return (status);
}

static void
print_path(const char **path, int indent)
{
	if (path != NULL && *path != NULL) {
		for (mdb_printf("%s\n", *path++); *path != NULL; path++)
			mdb_printf("%*s%s\n", indent, " ", *path);
	}
	mdb_printf("\n");
}

#define	LABEL_INDENT	26

static void
print_properties(void)
{
	int tflags = mdb_tgt_getflags(mdb.m_target);
	uint_t oflags = mdb_iob_getflags(mdb.m_out) & MDB_IOB_AUTOWRAP;

	mdb_iob_clrflags(mdb.m_out, MDB_IOB_AUTOWRAP);
	mdb_printf("\n  macro path: ");
	print_path(mdb.m_ipath, 14);
	mdb_printf(" module path: ");
	print_path(mdb.m_lpath, 14);
	mdb_iob_setflags(mdb.m_out, oflags);

	mdb_printf("%*s %lr (%s)\n", LABEL_INDENT, "symbol matching distance:",
	    mdb.m_symdist, mdb.m_symdist ? "absolute mode" : "smart mode");

	mdb_printf("%*s ", LABEL_INDENT, "array member print limit:");
	if (mdb.m_armemlim != MDB_ARR_NOLIMIT)
		mdb_printf("%u\n", mdb.m_armemlim);
	else
		mdb_printf("none\n");

	mdb_printf(" array string print limit: ");
	if (mdb.m_arstrlim != MDB_ARR_NOLIMIT)
		mdb_printf("%u\n", mdb.m_arstrlim);
	else
		mdb_printf("none\n");

	mdb_printf("%*s \"%s\"\n", LABEL_INDENT, "command prompt:",
	    mdb.m_prompt);

	mdb_printf("%*s ", LABEL_INDENT, "debugger options:");
	(void) mdb_inc_indent(LABEL_INDENT + 1);

	/*
	 * The ::set output implicitly relies on "autowrap" being enabled, so
	 * we enable it for the duration of the command.
	 */
	oflags = mdb.m_flags;
	mdb.m_flags |= MDB_FL_AUTOWRAP;

	mdb_printf("follow_exec_mode=");
	switch (mdb.m_execmode) {
	case MDB_EM_ASK:
		mdb_printf("ask");
		break;
	case MDB_EM_STOP:
		mdb_printf("stop");
		break;
	case MDB_EM_FOLLOW:
		mdb_printf("follow");
		break;
	}

#define	COMMAFLAG(name) { mdb_printf(", "); mdb_printf(name); }

	COMMAFLAG("follow_fork_mode");
	switch (mdb.m_forkmode) {
	case MDB_FM_ASK:
		mdb_printf("ask");
		break;
	case MDB_FM_PARENT:
		mdb_printf("parent");
		break;
	case MDB_FM_CHILD:
		mdb_printf("child");
		break;
	}

	if (mdb.m_flags & MDB_FL_ADB)
		COMMAFLAG("adb");
	if (oflags & MDB_FL_AUTOWRAP)
		COMMAFLAG("autowrap");
	if (mdb.m_flags & MDB_FL_IGNEOF)
		COMMAFLAG("ignoreeof");
	if (mdb.m_flags & MDB_FL_LMRAW)
		COMMAFLAG("lmraw");
	if (mdb.m_flags & MDB_FL_PAGER)
		COMMAFLAG("pager");
	if (mdb.m_flags & MDB_FL_REPLAST)
		COMMAFLAG("repeatlast");
	if (mdb.m_flags & MDB_FL_SHOWLMID)
		COMMAFLAG("showlmid");
	if (mdb.m_flags & MDB_FL_BPTNOSYMSTOP)
		COMMAFLAG("stop_on_bpt_nosym");
	if (mdb.m_flags & MDB_FL_READBACK)
		COMMAFLAG("write_readback");
	mdb_printf("\n");
	(void) mdb_dec_indent(LABEL_INDENT + 1);

	mdb_printf("%*s ", LABEL_INDENT, "target options:");
	(void) mdb_inc_indent(LABEL_INDENT + 1);

	if (tflags & MDB_TGT_F_RDWR)
		mdb_printf("read-write");
	else
		mdb_printf("read-only");
	if (tflags & MDB_TGT_F_ALLOWIO)
		COMMAFLAG("allow-io-access");
	if (tflags & MDB_TGT_F_FORCE)
		COMMAFLAG("force-attach");
	if (tflags & MDB_TGT_F_PRELOAD)
		COMMAFLAG("preload-syms");
	if (tflags & MDB_TGT_F_NOLOAD)
		COMMAFLAG("no-load-objs");
	if (tflags & MDB_TGT_F_NOSTOP)
		COMMAFLAG("no-stop");
	mdb_printf("\n");
	(void) mdb_dec_indent(LABEL_INDENT + 1);

	mdb.m_flags = oflags;
}

/*ARGSUSED*/
int
cmd_set(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *opt_I = NULL, *opt_L = NULL, *opt_P = NULL, *opt_o = NULL;
	const char *opt_plus_o = NULL, *opt_D = NULL;
	uint_t opt_w = FALSE, opt_plus_w = FALSE, opt_W = FALSE;
	uint_t opt_plus_W = FALSE, opt_F = FALSE;
	uintptr_t opt_s = (uintptr_t)(long)-1;

	int tflags = 0;
	int i;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	/*
	 * If no options are specified, print out the current set of target
	 * and debugger properties that can be modified with ::set.
	 */
	if (argc == 0) {
		print_properties();
		return (DCMD_OK);
	}

	while ((i = mdb_getopts(argc, argv,
	    'F', MDB_OPT_SETBITS, TRUE, &opt_F,
	    'I', MDB_OPT_STR, &opt_I,
	    'L', MDB_OPT_STR, &opt_L,
	    'P', MDB_OPT_STR, &opt_P,
	    'o', MDB_OPT_STR, &opt_o,
	    's', MDB_OPT_UINTPTR, &opt_s,
	    'w', MDB_OPT_SETBITS, TRUE, &opt_w,
	    'W', MDB_OPT_SETBITS, TRUE, &opt_W,
	    'D', MDB_OPT_STR, &opt_D, NULL)) != argc) {
		uint_t n = 1;

		argv += i; /* skip past args we processed */
		argc -= i; /* adjust argc */

		if (argv[0].a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		if (strcmp(argv->a_un.a_str, "+W") == 0)
			opt_plus_W = TRUE;
		else if (strcmp(argv->a_un.a_str, "+w") == 0)
			opt_plus_w = TRUE;
		else if (strcmp(argv->a_un.a_str, "+o") == 0 &&
		    argc >= 2 && argv[1].a_type == MDB_TYPE_STRING) {
			opt_plus_o = argv[1].a_un.a_str;
			n = 2;
		} else
			return (DCMD_USAGE);

		/* remove the flag and possible argument */
		argv += n;
		argc -= n;
	}

	if ((opt_w && opt_plus_w) || (opt_W && opt_plus_W))
		return (DCMD_USAGE);

	/*
	 * Handle -w, -/+W and -F first: as these options modify the target,
	 * they are the only ::set changes that can potentially fail.  We'll
	 * use these flags to modify a copy of the target's t_flags, which we'll
	 * then pass to the target's setflags op.  This allows the target to
	 * detect newly-set and newly-cleared flags by comparing the passed
	 * value to the current t_flags.
	 */
	tflags = mdb_tgt_getflags(mdb.m_target);

	if (opt_w)
		tflags |= MDB_TGT_F_RDWR;
	if (opt_plus_w)
		tflags &= ~MDB_TGT_F_RDWR;
	if (opt_W)
		tflags |= MDB_TGT_F_ALLOWIO;
	if (opt_plus_W)
		tflags &= ~MDB_TGT_F_ALLOWIO;
	if (opt_F)
		tflags |= MDB_TGT_F_FORCE;

	if (tflags != mdb_tgt_getflags(mdb.m_target) &&
	    mdb_tgt_setflags(mdb.m_target, tflags) == -1)
		return (DCMD_ERR);

	/*
	 * Now handle everything that either can't fail or we don't care if
	 * it does.  Note that we handle +/-o first in case another option
	 * overrides a change made implicity by a +/-o argument (e.g. -P).
	 */
	if (opt_o != NULL)
		(void) mdb_set_options(opt_o, TRUE);
	if (opt_plus_o != NULL)
		(void) mdb_set_options(opt_plus_o, FALSE);
	if (opt_I != NULL) {
#ifdef _KMDB
		mdb_warn("macro path cannot be set under kmdb\n");
#else
		mdb_set_ipath(opt_I);
#endif
	}
	if (opt_L != NULL)
		mdb_set_lpath(opt_L);
	if (opt_P != NULL)
		(void) mdb_set_prompt(opt_P);
	if (opt_s != (uintptr_t)-1)
		mdb.m_symdist = (size_t)opt_s;
	if (opt_D != NULL && (i = mdb_dstr2mode(opt_D)) != MDB_DBG_HELP)
		mdb_dmode((uint_t)i);

	return (DCMD_OK);
}
