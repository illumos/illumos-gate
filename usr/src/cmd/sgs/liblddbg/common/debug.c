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
static Dbg_desc	_dbg_desc = { 0, 0, 0 };
Dbg_desc	*dbg_desc = &_dbg_desc;

int		_Dbg_cnt = 0;

/*
 * Debugging initialization and processing.  The dbg_options[] array defines
 * a set of option strings that can be specified using the -D flag or from an
 * environment variable.  For each option, a class is enabled in the d_class
 * bit mask, or an extra flag is enabled in the d_extra bit mask.
 */
DBG_options _Dbg_options[] = {
	{MSG_ORIG(MSG_TOK_DETAIL),	0,	DBG_E_DETAIL},
	{MSG_ORIG(MSG_TOK_LONG),	0,	DBG_E_LONG},
	{MSG_ORIG(MSG_TOK_NAME),	0,	DBG_E_SNAME},
	{MSG_ORIG(MSG_TOK_FULLNAME),	0,	DBG_E_SNAME | DBG_E_FNAME},
	{MSG_ORIG(MSG_TOK_CLASS),	0,	DBG_E_SNAME | DBG_E_CLASS},
	{MSG_ORIG(MSG_TOK_LMID),	0,	DBG_E_LMID},

	{MSG_ORIG(MSG_TOK_ALL),		DBG_C_ALL,	0},
	{MSG_ORIG(MSG_TOK_ARGS),	DBG_C_ARGS,	0},
	{MSG_ORIG(MSG_TOK_BASIC),	DBG_C_BASIC,	0},
	{MSG_ORIG(MSG_TOK_BINDINGS),	DBG_C_BINDINGS,	0},
	{MSG_ORIG(MSG_TOK_ENTRY),	DBG_C_ENTRY,	0},
	{MSG_ORIG(MSG_TOK_FILES),	DBG_C_FILES,	0},
	{MSG_ORIG(MSG_TOK_HELP),	DBG_C_HELP,	0},
	{MSG_ORIG(MSG_TOK_LIBS),	DBG_C_LIBS,	0},
	{MSG_ORIG(MSG_TOK_MAP),		DBG_C_MAP,	0},
	{MSG_ORIG(MSG_TOK_RELOC),	DBG_C_RELOC,	0},
	{MSG_ORIG(MSG_TOK_SECTIONS),	DBG_C_SECTIONS,	0},
	{MSG_ORIG(MSG_TOK_SEGMENTS),	DBG_C_SEGMENTS,	0},
	{MSG_ORIG(MSG_TOK_SUPPORT),	DBG_C_SUPPORT,	0},
	{MSG_ORIG(MSG_TOK_SYMBOLS),	DBG_C_SYMBOLS,	0},
	{MSG_ORIG(MSG_TOK_TLS),		DBG_C_TLS,	0},
	{MSG_ORIG(MSG_TOK_AUDIT),	DBG_C_AUDITING,	0},
	{MSG_ORIG(MSG_TOK_VERSIONS),	DBG_C_VERSIONS,	0},
	{MSG_ORIG(MSG_TOK_GOT),		DBG_C_GOT,	0},
	{MSG_ORIG(MSG_TOK_MOVE),	DBG_C_MOVE,	0},
	{MSG_ORIG(MSG_TOK_STRTAB),	DBG_C_STRTAB,	0},
	{MSG_ORIG(MSG_TOK_STATS),	DBG_C_STATS,	0},
	{MSG_ORIG(MSG_TOK_UNUSED),	DBG_C_UNUSED,	0},
	{MSG_ORIG(MSG_TOK_DEMANGLE),	DBG_C_DEMANGLE,	0},
	{MSG_ORIG(MSG_TOK_CAP),		DBG_C_CAP,	0},
	{MSG_ORIG(MSG_TOK_INIT),	DBG_C_INIT,	0},
	{NULL,				NULL},
};

/*
 * Tokens may also define identifiers for diagnostics.  Presently, only ld.so.1
 * uses these strings to identify, or isolate its output to selected link-map
 * lists.  See ld.so.1:dbg_print().
 */
const char *_Dbg_strs[] = {
	MSG_ORIG(MSG_TOK_BASE),		MSG_ORIG(MSG_TOK_LDSO),
	MSG_ORIG(MSG_TOK_NEWLM),	NULL
};

/*
 * Provide a debugging usage message
 */
void
Dbg_usage()
{
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_A));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_B));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_C));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_D));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_E));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_F));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_G));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_H));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_I));
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_J));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_K));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_L));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_M));
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_N));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_O));
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_P));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_Q));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_R));
	dbg_print(0, MSG_INTL(MSG_USE_RTLD_S));

	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_LD_A));
	dbg_print(0, MSG_INTL(MSG_USE_LD_B));
	dbg_print(0, MSG_INTL(MSG_USE_LD_C));
	dbg_print(0, MSG_INTL(MSG_USE_LD_D));
	dbg_print(0, MSG_INTL(MSG_USE_LD_E));
	dbg_print(0, MSG_INTL(MSG_USE_LD_F));
	dbg_print(0, MSG_INTL(MSG_USE_LD_G));
	dbg_print(0, MSG_INTL(MSG_USE_LD_H));
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_LD_I));
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_LD_J));
	dbg_print(0, MSG_INTL(MSG_USE_LD_K));
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_LD_L));
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_LD_M));
	dbg_print(0, MSG_INTL(MSG_USE_LD_N));
	dbg_print(0, MSG_INTL(MSG_USE_LD_O));

	Dbg_util_nl(0, DBG_NL_FRC);
	Dbg_util_nl(0, DBG_NL_FRC);
	dbg_print(0, MSG_INTL(MSG_USE_ARGS));
	dbg_print(0, MSG_INTL(MSG_USE_AUDIT));
	dbg_print(0, MSG_INTL(MSG_USE_BASIC));
	dbg_print(0, MSG_INTL(MSG_USE_BINDINGS));
	dbg_print(0, MSG_INTL(MSG_USE_BINDINGS_2));
	dbg_print(0, MSG_INTL(MSG_USE_CAP));
	dbg_print(0, MSG_INTL(MSG_USE_DETAIL));
#ifdef	DEMANGLE
	dbg_print(0, MSG_INTL(MSG_USE_DEMANGLE));
#endif
	dbg_print(0, MSG_INTL(MSG_USE_ENTRY));
	dbg_print(0, MSG_INTL(MSG_USE_FILES));
	dbg_print(0, MSG_INTL(MSG_USE_GOT));
	dbg_print(0, MSG_INTL(MSG_USE_HELP));
	dbg_print(0, MSG_INTL(MSG_USE_INIT));
	dbg_print(0, MSG_INTL(MSG_USE_LIBS));
	dbg_print(0, MSG_INTL(MSG_USE_LIBS_2));
	dbg_print(0, MSG_INTL(MSG_USE_LMID));
	dbg_print(0, MSG_INTL(MSG_USE_LONG));
	dbg_print(0, MSG_INTL(MSG_USE_MAP));
	dbg_print(0, MSG_INTL(MSG_USE_MOVE));
	dbg_print(0, MSG_INTL(MSG_USE_RELOC));
	dbg_print(0, MSG_INTL(MSG_USE_SECTIONS));
	dbg_print(0, MSG_INTL(MSG_USE_SEGMENTS));
	dbg_print(0, MSG_INTL(MSG_USE_SEGMENTS_2));
	dbg_print(0, MSG_INTL(MSG_USE_STATS));
	dbg_print(0, MSG_INTL(MSG_USE_STRTAB));
	dbg_print(0, MSG_INTL(MSG_USE_STRTAB_2));
	dbg_print(0, MSG_INTL(MSG_USE_SUPPORT));
	dbg_print(0, MSG_INTL(MSG_USE_SYMBOLS));
	dbg_print(0, MSG_INTL(MSG_USE_SYMBOLS_2));
	dbg_print(0, MSG_INTL(MSG_USE_TLS));
	dbg_print(0, MSG_INTL(MSG_USE_UNUSED));
	dbg_print(0, MSG_INTL(MSG_USE_UNUSED_2));
	dbg_print(0, MSG_INTL(MSG_USE_VERSIONS));
	Dbg_util_nl(0, DBG_NL_FRC);
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
 * Validate and enable the appropriate debugging classes.
 */
uintptr_t
Dbg_setup(const char *string, Dbg_desc *dbp)
{
	char		*name, *_name;	/* buffer in which to perform */
					/* strtok_r() operations. */
	char		*lasts;
	const char	*delimit = MSG_ORIG(MSG_STR_DELIMIT);

	if ((_name = (char *)malloc(strlen(string) + 1)) == 0)
		return (S_ERROR);
	(void) strcpy(_name, string);

	/*
	 * The token should be of the form "-Dtok,tok,tok,...".  Separate the
	 * pieces and build up the appropriate mask, unrecognized options are
	 * flagged.
	 */
	if ((name = strtok_r(_name, delimit, &lasts)) != NULL) {
		do {
			DBG_options	*opt;
			const char	*str;
			Boolean		set, found = FALSE;
			int		ndx = 0;

			if (name[0] == '!') {
				set = FALSE;
				name++;
			} else
				set = TRUE;

			/*
			 * First, determine if the token represents a class or
			 * extra.
			 */
			for (opt = _Dbg_options; opt->o_name != NULL; opt++) {
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
				found = TRUE;
				break;
			}
			if (found == TRUE)
				continue;

			/*
			 * Second, determine if the token represents a known
			 * diagnostic identifier.  Note, newlm identifiers are
			 * typically followed by a numeric id, for example
			 * newlm1, newlm2 ...  Thus we only compare the
			 * initial text of the string.
			 */
			while ((str = _Dbg_strs[ndx++]) != NULL)  {
				char	*tup;

				if (strncmp(name, str, strlen(str)) != 0)
					continue;

				/*
				 * Translate lmid identifier to uppercase.
				 */
				for (tup = name; *tup; tup++) {
					if ((*tup >= 'a') && (*tup <= 'z'))
						*tup = *tup - ('a' - 'A');
				}

				/*
				 * Save this lmid.  The whole token buffer has
				 * been reallocated, so these names will remain
				 * once this routine returns.
				 */
				if (aplist_append(&dbp->d_list, name,
				    AL_CNT_DEBUG) == NULL)
					return (S_ERROR);

				found = TRUE;
				break;
			}

			if (found == FALSE)
				dbg_print(0, MSG_INTL(MSG_USE_UNRECOG), name);

		} while ((name = strtok_r(NULL, delimit, &lasts)) != NULL);
	}

	/*
	 * If the debug help option was specified dump a usage message.  If
	 * this is the only debug class, return an indication that the user
	 * should exit.
	 */
	if ((_Dbg_cnt++ == 0) && (dbp->d_class & DBG_C_HELP)) {
		Dbg_usage();
		if (dbp->d_class == DBG_C_HELP)
			return (0);
	}
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
