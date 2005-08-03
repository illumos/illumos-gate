/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	<stdlib.h>
#include	"_debug.h"
#include	"msg.h"

uint_t		_Dbg_mask;
static int	_Dbg_count = 0;


/*
 * Debugging initialization and processing.  The options structure defines
 * a set of option strings that can be specified using the -D flag or from an
 * environment variable.  For each option, a class is enabled in the _Dbg_mask
 * bit mask.
 */
static DBG_options _Dbg_options[] = {
	{MSG_ORIG(MSG_TOK_NAME),	DBG_G_SNAME},
	{MSG_ORIG(MSG_TOK_FULLNAME),	DBG_G_SNAME | DBG_G_FNAME},
	{MSG_ORIG(MSG_TOK_CLASS),	DBG_G_SNAME | DBG_G_CLASS},

	{MSG_ORIG(MSG_TOK_ALL),		DBG_LOCAL},
	{MSG_ORIG(MSG_TOK_ARGS),	DBG_ARGS},
	{MSG_ORIG(MSG_TOK_BASIC),	DBG_BASIC},
	{MSG_ORIG(MSG_TOK_BINDINGS),	DBG_BINDINGS},
	{MSG_ORIG(MSG_TOK_DETAIL),	DBG_DETAIL},
	{MSG_ORIG(MSG_TOK_ENTRY),	DBG_ENTRY},
	{MSG_ORIG(MSG_TOK_FILES),	DBG_FILES},
	{MSG_ORIG(MSG_TOK_HELP),	DBG_HELP},
	{MSG_ORIG(MSG_TOK_LIBS),	DBG_LIBS},
	{MSG_ORIG(MSG_TOK_LONG),	DBG_LONG},
	{MSG_ORIG(MSG_TOK_MAP),		DBG_MAP},
	{MSG_ORIG(MSG_TOK_RELOC),	DBG_RELOC},
	{MSG_ORIG(MSG_TOK_SECTIONS),	DBG_SECTIONS},
	{MSG_ORIG(MSG_TOK_SEGMENTS),	DBG_SEGMENTS},
	{MSG_ORIG(MSG_TOK_SUPPORT),	DBG_SUPPORT},
	{MSG_ORIG(MSG_TOK_SYMBOLS),	DBG_SYMBOLS},
	{MSG_ORIG(MSG_TOK_TLS),		DBG_TLS},
	{MSG_ORIG(MSG_TOK_AUDIT),	DBG_AUDITING},
	{MSG_ORIG(MSG_TOK_VERSIONS),	DBG_VERSIONS},
	{MSG_ORIG(MSG_TOK_GOT),		DBG_GOT},
	{MSG_ORIG(MSG_TOK_MOVE),	DBG_MOVE},
	{MSG_ORIG(MSG_TOK_STRTAB),	DBG_STRTAB},
	{MSG_ORIG(MSG_TOK_STATISTICS),	DBG_STATISTICS},
	{MSG_ORIG(MSG_TOK_UNUSED),	DBG_UNUSED},
#ifdef	DEMANGLE
	{MSG_ORIG(MSG_TOK_DEMANGLE),	DBG_DEMANGLE},
#endif
	{MSG_ORIG(MSG_TOK_CAP),		DBG_CAP},
	{MSG_ORIG(MSG_TOK_INIT),	DBG_INIT},
	{NULL,				NULL},
};

/*
 * Provide a debugging usage message
 */
static void
_Dbg_usage()
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_USE_RTLD_A));
	dbg_print(MSG_INTL(MSG_USE_RTLD_B));
	dbg_print(MSG_INTL(MSG_USE_RTLD_C));
	dbg_print(MSG_INTL(MSG_USE_RTLD_D));
	dbg_print(MSG_INTL(MSG_USE_RTLD_E));
	dbg_print(MSG_INTL(MSG_USE_RTLD_F));
	dbg_print(MSG_INTL(MSG_USE_RTLD_G));

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_USE_LD_A));
	dbg_print(MSG_INTL(MSG_USE_LD_B));
	dbg_print(MSG_INTL(MSG_USE_LD_C));
	dbg_print(MSG_INTL(MSG_USE_LD_D));
	dbg_print(MSG_INTL(MSG_USE_LD_E));
	dbg_print(MSG_INTL(MSG_USE_LD_F));
	dbg_print(MSG_INTL(MSG_USE_LD_G));
	dbg_print(MSG_INTL(MSG_USE_LD_H));
	dbg_print(MSG_INTL(MSG_USE_LD_I));
	dbg_print(MSG_INTL(MSG_USE_LD_J));

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_USE_ARGS));
	dbg_print(MSG_INTL(MSG_USE_AUDIT));
	dbg_print(MSG_INTL(MSG_USE_BASIC));
	dbg_print(MSG_INTL(MSG_USE_BINDINGS));
	dbg_print(MSG_INTL(MSG_USE_BINDINGS_2));
	dbg_print(MSG_INTL(MSG_USE_CAP));
	dbg_print(MSG_INTL(MSG_USE_DETAIL));
#ifdef	DEMANGLE
	dbg_print(MSG_INTL(MSG_USE_DEMANGLE));
#endif
	dbg_print(MSG_INTL(MSG_USE_ENTRY));
	dbg_print(MSG_INTL(MSG_USE_FILES));
	dbg_print(MSG_INTL(MSG_USE_GOT));
	dbg_print(MSG_INTL(MSG_USE_HELP));
	dbg_print(MSG_INTL(MSG_USE_INIT));
	dbg_print(MSG_INTL(MSG_USE_LIBS));
	dbg_print(MSG_INTL(MSG_USE_LIBS_2));
	dbg_print(MSG_INTL(MSG_USE_LONG));
	dbg_print(MSG_INTL(MSG_USE_MAP));
	dbg_print(MSG_INTL(MSG_USE_MOVE));
	dbg_print(MSG_INTL(MSG_USE_RELOC));
	dbg_print(MSG_INTL(MSG_USE_SECTIONS));
	dbg_print(MSG_INTL(MSG_USE_SEGMENTS));
	dbg_print(MSG_INTL(MSG_USE_SEGMENTS_2));
	dbg_print(MSG_INTL(MSG_USE_STATISTICS));
	dbg_print(MSG_INTL(MSG_USE_STRTAB));
	dbg_print(MSG_INTL(MSG_USE_STRTAB_2));
	dbg_print(MSG_INTL(MSG_USE_SUPPORT));
	dbg_print(MSG_INTL(MSG_USE_SYMBOLS));
	dbg_print(MSG_INTL(MSG_USE_SYMBOLS_2));
	dbg_print(MSG_INTL(MSG_USE_TLS));
	dbg_print(MSG_INTL(MSG_USE_UNUSED));
	dbg_print(MSG_INTL(MSG_USE_UNUSED_2));
	dbg_print(MSG_INTL(MSG_USE_VERSIONS));
}

/*
 * Validate and enable the appropriate debugging classes.
 */
uint_t
Dbg_setup(const char *string)
{
	char		*name, *_name;	/* Temporary buffer in which to */
					/* perform strtok_r() operations. */
	char		*lasts;
	DBG_opts 	opts;		/* Ptr to cycle thru _Dbg_options[]. */
	const char	*delimit = MSG_ORIG(MSG_STR_DELIMIT);

	if ((_name = (char *)malloc(strlen(string) + 1)) == 0)
		return (0);
	(void) strcpy(_name, string);

	/*
	 * The token should be of the form "-Dtok,tok,tok,...".  Separate the
	 * pieces and build up the appropriate mask, unrecognized options are
	 * flagged.
	 */
	if ((name = strtok_r(_name, delimit, &lasts)) != NULL) {
		Boolean		found, set;
		do {
			found = FALSE;
			set = TRUE;
			if (name[0] == '!') {
				set = FALSE;
				name++;
			}
			for (opts = _Dbg_options; opts->o_name != NULL;
				opts++) {
				if (strcmp(name, opts->o_name) == 0) {
					if (set == TRUE)
						_Dbg_mask |= opts->o_mask;
					else
						_Dbg_mask &= ~(opts->o_mask);
					found = TRUE;
					break;
				}
			}
			if (found == FALSE)
				dbg_print(MSG_INTL(MSG_USE_UNRECOG), name);
		} while ((name = strtok_r(NULL, delimit, &lasts)) != NULL);
	}
	(void) free(_name);

	/*
	 * If the debug help option was specified dump a usage message.  If
	 * this is the only debug option return an indication that the user
	 * should exit.
	 */
	if ((_Dbg_mask & DBG_HELP) && !_Dbg_count) {
		_Dbg_usage();
		if (_Dbg_mask == DBG_HELP)
			/* LINTED */
			return ((uint_t)S_ERROR);
	}

	_Dbg_count++;

	return (_Dbg_mask);
}

/*
 * Set the specified flags to _Dbg_mask.
 */
void
Dbg_set(uint_t flags)
{
	_Dbg_mask = flags;
}


/*
 * Messaging support - funnel everything through _dgettext() as this provides
 * a stub binding to libc, or a real binding to libintl.
 */
extern char	*_dgettext(const char *, const char *);

const char *
_liblddbg_msg(Msg mid)
{
	return (_dgettext(MSG_ORIG(MSG_SUNW_OST_SGS), MSG_ORIG(mid)));
}
