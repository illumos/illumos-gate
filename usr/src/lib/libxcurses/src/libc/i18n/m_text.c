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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MKS interface to XPG message internationalization routines.
 * Copyright 1989, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * Written by T. J. Thompson
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/i18n/rcs/m_text.c 1.18 1995/02/02 16:42:09 jeffhe Exp $";
#endif
#endif

#define	I18N	1	/* InternaltionalizatioN on */

#include <mks.h>
#include <locale.h>
#include <nl_types.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

static nl_catd catd = (nl_catd)-1;
static char *domain = NULL;	/* remember domain chosen */
static char *locale = NULL;	/* remember locale loaded */

#ifdef	M_VARIANTS
/*f
 * Note: All the text strings in the messaging database must be stored in
 * the codeset of the compiled program.  xlate will convert from that codeset,
 * into that of the user.
 */
static char *
xlate(char *s)
{
	char *new = strdup(s);
	static char *lastmsg;

	/* No memory? Return untranslated string */
	if (new == NULL)
		return s;
	/* Free previour string */
	if (lastmsg != NULL)
		free(lastmsg);
	lastmsg = new;

	/* Do *not* translate the leading ! which indicates perror */
	if (*new == '!')
		new++;
	/* And translate the string */
	M_INVARIANTINIT();
	for ( ; *new != '\0'; new++)
		*new = M_UNVARIANT(*new);

	return lastmsg;
}
#else
#define	xlate(s)	(s)
#endif

STATIC void
textclose()
{
	m_textdomain(NULL);
}

void
m_textdomain(str)
char *str;
{
	if (catd != (nl_catd)-1)
		(void)catclose(catd);
	catd = (nl_catd)-1;
	if (domain != NULL)
		free(domain);
	domain = str==NULL ? NULL : strdup(str);
}

/*f
 * Given a message id number, and a default string, call the XPG cat*
 * functions to look up the message, or return just the default string.
 */
char *
m_textmsg(id, str, cls)
int id;
const char *str;
char *cls;	/* NOT USED */
{
	int errsave = errno;
	char *nlocale;
	char *cp;

	nlocale = setlocale(LC_MESSAGES, NULL);	/* Query current locale */
	if (catd == (nl_catd)-1			        /* catalog not open */
	||  nlocale == NULL				/* impossible? */
	||  locale == NULL				/* locale never set */
	||  strcmp(locale, nlocale)!=0) {		/* locale changed */

		/* Do not re-try a failed catopen */
		if (locale != NULL && nlocale != NULL && domain != NULL
		&& strcmp(locale, nlocale) == 0) {
			errno = errsave;
			return (xlate((char *)str));
		}

		if (catd != (nl_catd)-1)
			(void)catclose(catd);
		if (domain==NULL)
			m_textdomain(M_NL_DOM);
		if (locale != NULL)
			free(locale);
		locale = nlocale==NULL ? NULL : strdup(nlocale);
#ifdef NL_CAT_LOCALE /* XPG4 - April 1992 - not final version! */
		if ((catd = catopen(domain, NL_CAT_LOCALE)) == (nl_catd)-1) {
#else
		if ((catd = catopen(domain, 0)) == (nl_catd)-1) {
#endif
			errno = errsave;
			return (xlate((char *)str));
		}
		atexit(textclose);
	}
	cp = catgets(catd, NL_SETD, id, (char *)str);
	errno = errsave;
	return xlate(cp);
}
