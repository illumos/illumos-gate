/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * LC_MESSAGES database generation routines for localedef.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include "localedef.h"
#include "parser.tab.h"
#include "lmessages.h"

static struct lc_messages msgs;

void
init_messages(void)
{
	(void) memset(&msgs, 0, sizeof (msgs));
}

void
add_message(wchar_t *wcs)
{
	char *str;

	if ((str = to_mb_string(wcs)) == NULL) {
		INTERR;
		return;
	}
	free(wcs);

	switch (last_kw) {
	case T_YESSTR:
		msgs.yesstr = str;
		break;
	case T_NOSTR:
		msgs.nostr = str;
		break;
	case T_YESEXPR:
		msgs.yesexpr = str;
		break;
	case T_NOEXPR:
		msgs.noexpr = str;
		break;
	default:
		free(str);
		INTERR;
		break;
	}
}

void
dump_messages(void)
{
	FILE *f;
	char *ptr;

	if (msgs.yesstr == NULL) {
		warn(_("missing field 'yesstr'"));
		msgs.yesstr = "";
	}
	if (msgs.nostr == NULL) {
		warn(_("missing field 'nostr'"));
		msgs.nostr = "";
	}

	/*
	 * CLDR likes to add : separated lists for yesstr and nostr.
	 * Legacy Solaris code does not seem to grok this.  Fix it.
	 */
	if ((ptr = strchr(msgs.yesstr, ':')) != NULL)
		*ptr = 0;
	if ((ptr = strchr(msgs.nostr, ':')) != NULL)
		*ptr = 0;

	if ((f = open_category()) == NULL) {
		return;
	}

	if ((putl_category(msgs.yesexpr, f) == EOF) ||
	    (putl_category(msgs.noexpr, f) == EOF) ||
	    (putl_category(msgs.yesstr, f) == EOF) ||
	    (putl_category(msgs.nostr, f) == EOF)) {
		return;
	}
	close_category(f);
}
