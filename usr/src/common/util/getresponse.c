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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <locale.h>
#include <langinfo.h>
#include <limits.h>
#include <errno.h>
#include "getresponse.h"

/* defaults - C locale values for yesstr, nostr, yesexpr (LC_MESSAGES) */
#define	DEFAULT_YESSTR  "yes"
#define	DEFAULT_NOSTR   "no"
#define	DEFAULT_YESEXPR "^[yY]"
#define	DEFAULT_NOEXPR	"^[nN]"

#define	FREE_MEM        \
	if (yesstr)     \
		free(yesstr);   \
	if (nostr)      \
		free(nostr);    \
	if (yesexpr)    \
		free(yesexpr);  \
	if (noexpr)     \
		free(noexpr)

#define	SET_DEFAULT_STRS \
	yesstr = DEFAULT_YESSTR; \
	nostr = DEFAULT_NOSTR; \
	yesexpr = DEFAULT_YESEXPR; \
	noexpr = DEFAULT_NOEXPR;

/* variables used by getresponse functions */
char    *yesstr = NULL;
char    *nostr = NULL;

/* for regcomp()/regexec() yesexpr and noexpr */
static regex_t preg_yes, preg_no;

/*
 * This function compiles a regular expression that is used to match an
 * affirmative response from the user, and also assigns the strings used
 * in the prompts that request affirmative or negative responses.  The
 * locale's values for YESEXPR, NOEXPR, YESSTR and NOSTR are used.
 *
 * If there are any problems using the locale's YESEXPR, NOEXPR, YESSTR or NOSTR
 * values, default values of YESEXPR, YESSTR and NOSTR will be used
 * as a fallback.  The default values are the same as the C locale values.
 */
int
init_yes(void)
{
	int	fallback = 0;
	char    *yesexpr;
	char	*noexpr;

	/* get yes expression and strings for yes/no prompts */
	yesstr  = strdup(nl_langinfo(YESSTR));
	nostr   = strdup(nl_langinfo(NOSTR));
	yesexpr = strdup(nl_langinfo(YESEXPR));
	noexpr  = strdup(nl_langinfo(NOEXPR));

	if (yesstr == NULL || nostr == NULL ||
	    yesexpr == NULL || noexpr == NULL) {
		FREE_MEM;
		errno = ENOMEM;
		return (-1);
	}

	/* if problem with locale strings, use default values */
	if (*yesstr == '\0' || *nostr == '\0' ||
	    *yesexpr == '\0' || *noexpr == '\0') {
		FREE_MEM;
		SET_DEFAULT_STRS;
		fallback = 1;
	}
	/* Compile the yes and no expressions */
	while (regcomp(&preg_yes, yesexpr, REG_EXTENDED | REG_NOSUB) != 0 ||
	    regcomp(&preg_no, noexpr, REG_EXTENDED | REG_NOSUB) != 0) {
		if (fallback == 1) {
			/* The fallback yesexpr failed, so exit */
			errno = EINVAL;
			return (-1);
		}
		/* The locale's yesexpr or noexpr failed so use fallback */
		FREE_MEM;
		SET_DEFAULT_STRS;
		fallback = 1;
	}
	return (0);
}

static int
yes_no(int (*func)(char *))
{
	int	i, b;
	char    ans[LINE_MAX + 1];

	/* Get user's answer */
	i = 0;
	for (;;) {
		b = getchar();
		if (b == '\n' || b == '\0' || b == EOF)
			break;
		if (i < LINE_MAX)
			ans[i] = b;
		i++;
	}
	if (i >= LINE_MAX)
		ans[LINE_MAX] = '\0';
	else
		ans[i] = '\0';

	return (func(ans));
}

static int
yes_no_check(char *ans, regex_t *reg1, regex_t *reg2)
{
	if (regexec(reg1, ans, 0, NULL, 0) == 0) {
		if (regexec(reg2, ans, 0, NULL, 0) == 0) {
			/* Both Expressions Match (reg2 conservative) */
			return (0);
		}
		/* Match */
		return (1);
	}
	return (0);
}

/*
 * yes_check() returns 1 if the input string is matched by yesexpr and is
 * not matched by noexpr;  otherwise yes_check() returns 0.
 */
int
yes_check(char *ans)
{
	return (yes_no_check(ans, &preg_yes, &preg_no));
}

/*
 * no_check() returns 1 if the input string is matched by noexpr and is
 * not matched by yesexpr;  otherwise no_check() returns 0.
 */
int
no_check(char *ans)
{
	return (yes_no_check(ans, &preg_no, &preg_yes));
}

int
yes(void)
{
	return (yes_no(yes_check));
}

int
no(void)
{
	return (yes_no(no_check));
}
