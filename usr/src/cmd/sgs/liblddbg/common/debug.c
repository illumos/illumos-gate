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

#include <libintl.h>
#include <sys/varargs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <alist.h>
#include <debug.h>
#include <_debug.h>
#include <msg.h>

/*
 * Define a debug descriptor.  Note, although this provides the default
 * definition to which most users bind, ld.so.1 must provide its own definition,
 * and thus interposition is expected.  This item should be defined NODIRECT.
 */
static Dbg_desc	_dbg_desc = { 0, 0, NULL, { 0, 0 }, { 0, 0 } };
Dbg_desc	*dbg_desc = &_dbg_desc;

int		_Dbg_cnt = 0;

/*
 * Debugging initialization and processing.  The dbg_options[] array defines
 * a set of option strings that can be specified using the -D flag or from an
 * environment variable.  For each option, a class is enabled in the d_class
 * bit mask, or an extra flag is enabled in the d_extra bit mask.
 */
static DBG_options _Dbg_options[] = {	/* Options accepted by both linkers */
	{MSG_ORIG(MSG_TOK_DETAIL),	0,	DBG_E_DETAIL},
	{MSG_ORIG(MSG_TOK_LONG),	0,	DBG_E_LONG},
	{MSG_ORIG(MSG_TOK_HELP),	0,	DBG_E_HELP},
	{MSG_ORIG(MSG_TOK_TTIME),	0,	DBG_E_TTIME},
	{MSG_ORIG(MSG_TOK_DTIME),	0,	DBG_E_DTIME},

	{MSG_ORIG(MSG_TOK_ALL),		DBG_C_ALL & ~DBG_C_DEMANGLE,	0},
	{MSG_ORIG(MSG_TOK_BASIC),	DBG_C_BASIC,			0},
	{MSG_ORIG(MSG_TOK_CAP),		DBG_C_CAP,			0},
	{MSG_ORIG(MSG_TOK_DEMANGLE),	DBG_C_DEMANGLE,			0},
	{MSG_ORIG(MSG_TOK_FILES),	DBG_C_FILES,			0},
	{MSG_ORIG(MSG_TOK_LIBS),	DBG_C_LIBS,			0},
	{MSG_ORIG(MSG_TOK_MOVE),	DBG_C_MOVE,			0},
	{MSG_ORIG(MSG_TOK_RELOC),	DBG_C_RELOC,			0},
	{MSG_ORIG(MSG_TOK_SYMBOLS),	DBG_C_SYMBOLS,			0},
	{MSG_ORIG(MSG_TOK_TLS),		DBG_C_TLS,			0},
	{MSG_ORIG(MSG_TOK_UNUSED),	DBG_C_UNUSED,			0},
	{MSG_ORIG(MSG_TOK_VERSIONS),	DBG_C_VERSIONS,			0},
	{NULL,				0,				0},
};

static DBG_options _Dbg_options_ld[] = {	/* ld only options */
	{MSG_ORIG(MSG_TOK_CLASS),	0,	DBG_E_SNAME | DBG_E_CLASS},
	{MSG_ORIG(MSG_TOK_FULLNAME),	0,	DBG_E_SNAME | DBG_E_FNAME},
	{MSG_ORIG(MSG_TOK_NAME),	0,	DBG_E_SNAME},

	{MSG_ORIG(MSG_TOK_ARGS),	DBG_C_ARGS,	0},
	{MSG_ORIG(MSG_TOK_ENTRY),	DBG_C_ENTRY,	0},
	{MSG_ORIG(MSG_TOK_GOT),		DBG_C_GOT,	0},
	{MSG_ORIG(MSG_TOK_MAP),		DBG_C_MAP,	0},
	{MSG_ORIG(MSG_TOK_SECTIONS),	DBG_C_SECTIONS,	0},
	{MSG_ORIG(MSG_TOK_SEGMENTS),	DBG_C_SEGMENTS,	0},
	{MSG_ORIG(MSG_TOK_STATS),	DBG_C_STATS,	0},
	{MSG_ORIG(MSG_TOK_STRTAB),	DBG_C_STRTAB,	0},
	{MSG_ORIG(MSG_TOK_SUPPORT),	DBG_C_SUPPORT,	0},
	{NULL,				0,		0},
};

static DBG_options _Dbg_options_rtld[] = {	/* ld.so.1 only options */
	{MSG_ORIG(MSG_TOK_AUDIT),	DBG_C_AUDITING,	0},
	{MSG_ORIG(MSG_TOK_BINDINGS),	DBG_C_BINDINGS,	0},
	{MSG_ORIG(MSG_TOK_DL),		DBG_C_DL,	0},
	{MSG_ORIG(MSG_TOK_INIT),	DBG_C_INIT,	0},
	{NULL,				0,		0},
};

/*
 * Compare name to the options found in optarr. If one matches,
 * update *dbp and return TRUE. Otherwise, FALSE.
 */
static Boolean
process_options(const char *name, Boolean set, Dbg_desc *dbp,
    DBG_options *optarr)
{
	DBG_options	*opt;

	for (opt = optarr; opt->o_name != NULL; opt++) {
		if (strcmp(name, opt->o_name) != 0)
			continue;

		if (set == TRUE) {
			if (opt->o_class)
				dbp->d_class |= opt->o_class;
			if (opt->o_extra)
				dbp->d_extra |= opt->o_extra;
		} else {
			if (opt->o_class)
				dbp->d_class &= ~(opt->o_class);
			if (opt->o_extra)
				dbp->d_extra &= ~(opt->o_extra);
		}
		return (TRUE);
	}

	return (FALSE);
}

/*
 * Provide a debugging usage message
 */
void
Dbg_help(void)
{
	Dbg_util_nl(0, DBG_NL_STD);
	dbg_print(0, MSG_INTL(MSG_USE_R1_A));
	dbg_print(0, MSG_INTL(MSG_USE_R1_B));
	dbg_print(0, MSG_INTL(MSG_USE_R1_C));
	dbg_print(0, MSG_INTL(MSG_USE_R1_D));
	dbg_print(0, MSG_INTL(MSG_USE_R1_E));
	dbg_print(0, MSG_INTL(MSG_USE_R1_F));
	dbg_print(0, MSG_INTL(MSG_USE_R1_G));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_R2_A));
	dbg_print(0, MSG_INTL(MSG_USE_R2_B));
	dbg_print(0, MSG_INTL(MSG_USE_R2_C));
	dbg_print(0, MSG_INTL(MSG_USE_R2_D));
	dbg_print(0, MSG_INTL(MSG_USE_R2_E));
	dbg_print(0, MSG_INTL(MSG_USE_R2_F));
	dbg_print(0, MSG_INTL(MSG_USE_R2_G));
	dbg_print(0, MSG_INTL(MSG_USE_R2_H));
	dbg_print(0, MSG_INTL(MSG_USE_R2_I));
	dbg_print(0, MSG_INTL(MSG_USE_R2_J));
	dbg_print(0, MSG_INTL(MSG_USE_R2_K));
	dbg_print(0, MSG_INTL(MSG_USE_R2_L));
	dbg_print(0, MSG_INTL(MSG_USE_R2_M));
	dbg_print(0, MSG_INTL(MSG_USE_R2_N));
	dbg_print(0, MSG_INTL(MSG_USE_R2_O));
	dbg_print(0, MSG_INTL(MSG_USE_R2_P));
	dbg_print(0, MSG_INTL(MSG_USE_R2_Q));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_R2_R));
	dbg_print(0, MSG_INTL(MSG_USE_R2_S));
	dbg_print(0, MSG_INTL(MSG_USE_R2_T));
	dbg_print(0, MSG_INTL(MSG_USE_R2_U));
	dbg_print(0, MSG_INTL(MSG_USE_R2_V));
	dbg_print(0, MSG_INTL(MSG_USE_R2_W));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_R3_A));
	dbg_print(0, MSG_INTL(MSG_USE_R3_B));
	dbg_print(0, MSG_INTL(MSG_USE_R3_C));
	dbg_print(0, MSG_INTL(MSG_USE_R3_D));
	dbg_print(0, MSG_INTL(MSG_USE_R3_E));
	dbg_print(0, MSG_INTL(MSG_USE_R3_F));
	dbg_print(0, MSG_INTL(MSG_USE_R3_G));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_R3_H));
	dbg_print(0, MSG_INTL(MSG_USE_R3_F));
	dbg_print(0, MSG_INTL(MSG_USE_R3_I));
	dbg_print(0, MSG_INTL(MSG_USE_R3_J));
	dbg_print(0, MSG_INTL(MSG_USE_R3_K));
	dbg_print(0, MSG_INTL(MSG_USE_R3_L));
	dbg_print(0, MSG_INTL(MSG_USE_R3_M));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_R3_N));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_HDR_DCT));
	dbg_print(0, MSG_INTL(MSG_USE_HDR_BOTH));
	dbg_print(0, MSG_INTL(MSG_USE_R4_A));
	dbg_print(0, MSG_INTL(MSG_USE_R4_B));
	dbg_print(0, MSG_INTL(MSG_USE_R4_B2));
	dbg_print(0, MSG_INTL(MSG_USE_R4_C));
	dbg_print(0, MSG_INTL(MSG_USE_R4_C2));
	dbg_print(0, MSG_INTL(MSG_USE_R4_C3));
	dbg_print(0, MSG_INTL(MSG_USE_R4_D));
	dbg_print(0, MSG_INTL(MSG_USE_R4_E));
	dbg_print(0, MSG_INTL(MSG_USE_R4_E2));
	dbg_print(0, MSG_INTL(MSG_USE_R4_E3));
	dbg_print(0, MSG_INTL(MSG_USE_R4_F));
	dbg_print(0, MSG_INTL(MSG_USE_R4_F2));
	dbg_print(0, MSG_INTL(MSG_USE_R4_F3));
	dbg_print(0, MSG_INTL(MSG_USE_R4_F4));
	dbg_print(0, MSG_INTL(MSG_USE_R4_F5));
	dbg_print(0, MSG_INTL(MSG_USE_R4_F6));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_HDR_RTLD));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A2));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A3));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A4));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A5));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A6));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A7));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A8));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A9));
	dbg_print(0, MSG_INTL(MSG_USE_R5_A0));
	dbg_print(0, MSG_INTL(MSG_USE_R5_B));
	dbg_print(0, MSG_INTL(MSG_USE_R5_C));
	dbg_print(0, MSG_INTL(MSG_USE_R5_D));
	dbg_print(0, MSG_INTL(MSG_USE_R5_E));
	dbg_print(0, MSG_INTL(MSG_USE_R5_F));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_HDR_LD));
	dbg_print(0, MSG_INTL(MSG_USE_R6_A));
	dbg_print(0, MSG_INTL(MSG_USE_R6_B));
	dbg_print(0, MSG_INTL(MSG_USE_R6_C));
	dbg_print(0, MSG_INTL(MSG_USE_R6_C2));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_HDR_CST));
	dbg_print(0, MSG_INTL(MSG_USE_HDR_BOTH));
	dbg_print(0, MSG_INTL(MSG_USE_R7_A));
	dbg_print(0, MSG_INTL(MSG_USE_R7_B));
	dbg_print(0, MSG_INTL(MSG_USE_R7_C));
	dbg_print(0, MSG_INTL(MSG_USE_R7_D));
	dbg_print(0, MSG_INTL(MSG_USE_R7_E));
	dbg_print(0, MSG_INTL(MSG_USE_R7_F));
	dbg_print(0, MSG_INTL(MSG_USE_R7_F2));
	dbg_print(0, MSG_INTL(MSG_USE_R7_G));
	dbg_print(0, MSG_INTL(MSG_USE_R7_H));
	dbg_print(0, MSG_INTL(MSG_USE_R7_I));
	dbg_print(0, MSG_INTL(MSG_USE_R7_I2));
	dbg_print(0, MSG_INTL(MSG_USE_R7_J));
	dbg_print(0, MSG_INTL(MSG_USE_R7_K));
	dbg_print(0, MSG_INTL(MSG_USE_R7_K2));
	dbg_print(0, MSG_INTL(MSG_USE_R7_L));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_HDR_RTLD));
	dbg_print(0, MSG_INTL(MSG_USE_R8_A));
	dbg_print(0, MSG_INTL(MSG_USE_R8_B));
	dbg_print(0, MSG_INTL(MSG_USE_R8_B2));
	dbg_print(0, MSG_INTL(MSG_USE_R8_C));
	dbg_print(0, MSG_INTL(MSG_USE_R8_D));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_HDR_LD));
	dbg_print(0, MSG_INTL(MSG_USE_R9_A));
	dbg_print(0, MSG_INTL(MSG_USE_R9_B));
	dbg_print(0, MSG_INTL(MSG_USE_R9_C));
	dbg_print(0, MSG_INTL(MSG_USE_R9_D));
	dbg_print(0, MSG_INTL(MSG_USE_R9_E));
	dbg_print(0, MSG_INTL(MSG_USE_R9_F));
	dbg_print(0, MSG_INTL(MSG_USE_R9_F2));
	dbg_print(0, MSG_INTL(MSG_USE_R9_G));
	dbg_print(0, MSG_INTL(MSG_USE_R9_H));
	dbg_print(0, MSG_INTL(MSG_USE_R9_H2));
	dbg_print(0, MSG_INTL(MSG_USE_R9_I));

	Dbg_util_nl(0, DBG_NL_FRC);
}

/*
 * Provide a debugging message showing the version of the linker package
 */
void
Dbg_version(void)
{
	Dbg_util_nl(0, DBG_NL_STD);
	dbg_print(0, MSG_ORIG(MSG_STR_LDVER), link_ver_string);
	Dbg_util_nl(0, DBG_NL_STD);
}

/*
 * Messaging support - funnel everything through dgettext() as this provides
 * the real binding to libc.
 */
const char *
_liblddbg_msg(Msg mid)
{
	return (dgettext(MSG_ORIG(MSG_SUNW_OST_SGS), MSG_ORIG(mid)));
}

/*
 * Given a name starting with "lmid", finish processing it. Return TRUE
 * if a valid lmid token was seen, and FALSE for any error.
 *
 * exit:
 *	On failure, returns FALSE, indicating a syntax error
 *
 *	On success:
 *	-	Appropriate flags in dbg->d_extra have been set
 *	-	Any link-map list names specified have been added to
 *		d_list, for the rtld dbg_print() to compare against
 *		link-map list names.
 *	-	TRUE is returned.
 */
static Boolean
process_lmid(char *name, Dbg_desc *dbp)
{
	/*
	 * "lmid" can have an optional argument. Allowed values are "all",
	 * "alt[0-9]+", "base", or "ldso". Alt has a variable ending, but
	 * we can use process_options() to handle the other three.
	 */
	static DBG_options options_lmid[] = {
		{MSG_ORIG(MSG_TOK_LMID_ALL),	0,	DBG_E_LMID_ALL},
		{MSG_ORIG(MSG_TOK_LMID_BASE),	0,	DBG_E_LMID_BASE},
		{MSG_ORIG(MSG_TOK_LMID_LDSO),	0,	DBG_E_LMID_LDSO},
		{NULL,				0,	0},
	};

	Dbg_desc	tmp_db;
	const char	*lmid_opt;

	/* If it's a plain "lmid", we can set the flag and return now */
	if (name[MSG_TOK_LMID_SIZE] == '\0') {
		dbp->d_extra |= DBG_E_LMID;
		return (TRUE);
	}

	/* If there's no value, its an error */
	if (conv_strproc_extract_value(name, MSG_TOK_LMID_SIZE,
	    CONV_SPEXV_F_UCASE, &lmid_opt) == 0)
		return (FALSE);

	/*
	 * ALL, BASE, or LDSO?
	 */
	tmp_db.d_extra = 0;
	if (process_options(lmid_opt, TRUE, &tmp_db, options_lmid)) {
		/*
		 * If BASE, and we haven't already seen it, add it to the
		 * rtld name matching list. For the others, setting the
		 * e_extra bit suffices.
		 */
		if (((tmp_db.d_extra & DBG_E_LMID_BASE) != 0) &&
		    ((dbp->d_extra & DBG_E_LMID_BASE) == 0) &&
		    (aplist_append(&dbp->d_list, MSG_ORIG(MSG_TOK_LMID_BASE),
		    AL_CNT_DEBUG) == NULL))
			return (FALSE);

		/* Add the resulting flags into the callers descriptor */
		dbp->d_extra |= DBG_E_LMID | tmp_db.d_extra;
		return (TRUE);
	}

	/*
	 * ALT?
	 */
	if (strncmp(lmid_opt, MSG_ORIG(MSG_TOK_LMID_ALT),
	    MSG_TOK_LMID_ALT_SIZE) == 0) {
		const char *tail = lmid_opt + MSG_TOK_LMID_ALT_SIZE;

		/* 'ALT' without a # means "all alternative link-map lists" */
		if (*tail == '\0') {
			dbp->d_extra |= DBG_E_LMID | DBG_E_LMID_ALT;
			return (TRUE);
		}

		/*
		 * It is ALT[0-9]+. Make sure the characters following 'ALT'
		 * are numbers, and then add it to the rtld name matching list.
		 */
		for (; *tail; tail++)
			if ((*tail < '0') || (*tail > '9'))
				return (FALSE);

		if (aplist_append(&dbp->d_list, lmid_opt, AL_CNT_DEBUG) == NULL)
			return (FALSE);
		dbp->d_extra |= DBG_E_LMID;
		return (TRUE);
	}

	/* It's nothing we recognize */
	return (FALSE);
}

/*
 * Validate and enable the appropriate debugging classes.
 *
 * entry:
 *	string - String to be analyzed for debugging options
 *	dbp - Pointer to debug descriptor to be initialized
 *	outfile_ret - NULL, or pointer to receive result of 'output='
 *		token. A NULL value means that the 'output=' token
 *		is not accepted. A non-NULL value means that it is.
 *
 * exit:
 *	On failure, False (0) is returned.
 *
 *	On success, string has been parsed, and the descriptor referenced
 *	by dbp has been initialized. If outfile is non-NULL, *outfile will
 *	be set to NULL if the 'output=' token is not present, and to the
 *	user supplied string otherwise. True (1) is returned.
 */
int
Dbg_setup(dbg_setup_caller_t caller, const char *string, Dbg_desc *dbp,
    const char **outfile)
{
	char		*name, *_name;	/* buffer in which to perform */
					/* strtok_r() operations. */
	char		*lasts;
	const char	*delimit = MSG_ORIG(MSG_STR_DELIMIT);

	/*
	 * Clear the help flags --- these items only apply for a single
	 * call to Dbg_setup().
	 */
	dbp->d_extra &= ~(DBG_E_HELP | DBG_E_HELP_EXIT);

	if ((_name = (char *)malloc(strlen(string) + 1)) == NULL)
		return (0);
	(void) strcpy(_name, string);

	if (outfile)
		*outfile = NULL;   /* No output file yet */

	/*
	 * The token should be of the form "-Dtok,tok,tok,...".  Separate the
	 * pieces and build up the appropriate mask, unrecognized options are
	 * flagged.
	 */
	if ((name = strtok_r(_name, delimit, &lasts)) != NULL) {
		do {
			Boolean		set;

			/* Remove leading and trailing whitespace */
			name = conv_strproc_trim(name);

			if (name[0] == '!') {
				set = FALSE;
				name++;
			} else
				set = TRUE;

			if (*name == '\0')
				continue;	/* Skip null token */

			/*
			 * First, determine if the token represents a class or
			 * extra.
			 */
			if (process_options(name, set, dbp, _Dbg_options))
				continue;
			switch (caller) {
			case DBG_CALLER_LD:	/* ld only tokens */
				if (process_options(name, set, dbp,
				    _Dbg_options_ld))
					continue;
				break;
			case DBG_CALLER_RTLD:	/* rtld only tokens */
				if (process_options(name, set, dbp,
				    _Dbg_options_rtld))
					continue;
				break;
			}

			/* The remaining options do not accept negation */
			if (!set) {
				dbg_print(0, MSG_INTL(MSG_USE_CNTNEGOPT), name);
				continue;
			}

			/*
			 * Is it an 'output=' token? This item is a special
			 * case because it depends on the presence of
			 * a non-NULL outfile argument, and because the
			 * part following the '=' is variable.
			 */
			if ((outfile != NULL) &&
			    strncmp(name, MSG_ORIG(MSG_TOK_OUTFILE),
			    MSG_TOK_OUTFILE_SIZE) == 0) {
				if (conv_strproc_extract_value(name,
				    MSG_TOK_OUTFILE_SIZE, 0, outfile))
					continue;
			}

			/*
			 * Only the rtld "lmid" token is left.
			 */
			if ((caller == DBG_CALLER_RTLD) && (strncmp(name,
			    MSG_ORIG(MSG_TOK_LMID), MSG_TOK_LMID_SIZE) == 0) &&
			    process_lmid(name, dbp))
				continue;

			/* If we make it here, the token is not understood */
			dbg_print(0, MSG_INTL(MSG_USE_UNRECOG), name);

		} while ((name = strtok_r(NULL, delimit, &lasts)) != NULL);
	}

	/*
	 * If the debug help option was specified and this is the only debug
	 * class, return an indication that the user should exit.
	 */
	if ((_Dbg_cnt++ == 0) && (dbp->d_extra & DBG_E_HELP) &&
	    (dbp->d_class == 0))
		dbp->d_extra |= DBG_E_HELP_EXIT;

	return (1);
}

/*
 * Define our own printing routine.  This provides a basic fallback, as ld(1)
 * and ld.so.1(1) provide their own routines that augment their diagnostic
 * output, and direct the output to stderr.  This item should be defined
 * NODIRECT.
 */
/* PRINTFLIKE2 */
void
dbg_print(Lm_list *lml, const char *format, ...)
{
	va_list ap;

#if	defined(lint)
	/*
	 * The lml argument is only meaningful for diagnostics sent to ld.so.1.
	 * Supress the lint error by making a dummy assignment.
	 */
	lml = 0;
#endif
	va_start(ap, format);
	(void) vprintf(format, ap);
	(void) printf(MSG_ORIG(MSG_STR_NL));
	va_end(ap);
}

/*
 * Return an internationalized state transition string. These are used by
 * various debugging output.
 */
const char *
Dbg_state_str(dbg_state_t type)
{
	static const Msg state[DBG_STATE_NUM] = {
		MSG_STR_ADD,		/* MSG_INTL(MSG_STR_ADD)  */
		MSG_STR_CURRENT,	/* MSG_INTL(MSG_STR_CURRENT) */
		MSG_STR_EXCLUDE,	/* MSG_INTL(MSG_STR_EXCLUDE) */
		MSG_STR_IGNORE,		/* MSG_INTL(MSG_STR_IGNORE) */
		MSG_STR_MOD_BEFORE,	/* MSG_INTL(MSG_STR_MOD_BEFORE) */
		MSG_STR_MOD_AFTER,	/* MSG_INTL(MSG_STR_MOD_AFTER) */
		MSG_STR_NEW,		/* MSG_INTL(MSG_STR_NEW) */
		MSG_STR_NEW_IMPLICIT,	/* MSG_INTL(MSG_STR_NEW_IMPLICIT) */
		MSG_STR_RESET,		/* MSG_INTL(MSG_STR_RESET) */
		MSG_STR_ORIGINAL,	/* MSG_INTL(MSG_STR_ORIGINAL) */
		MSG_STR_RESOLVED,	/* MSG_INTL(MSG_STR_RESOLVED) */
	};
#if DBG_STATE_NUM != (DBG_STATE_RESOLVED + 1)
#error DBG_SEG_NUM has changed. Update segtype[]
#endif

	assert(type < DBG_STATE_NUM);
	return (MSG_INTL(state[type]));
}
