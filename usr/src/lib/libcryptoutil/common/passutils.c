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

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <locale.h>
#include <cryptoutil.h>

#define	MAX_PASS_TRIES		5	/* maximum tries to get passphrase */

#define	DEFAULT_TOKEN_PROMPT	gettext("Enter PIN for %s: ")
#define	DEFAULT_TOKEN_REPROMPT	gettext("Re-enter PIN for %s: ")
#define	DEFAULT_TOKEN_MINSIZE	gettext("PIN must be at least %d characters.\n")

#define	DEFAULT_USER_PROMPT	gettext("Enter passphrase: ")
#define	DEFAULT_USER_REPROMPT	gettext("Re-enter passphrase: ")
#define	DEFAULT_USER_MINSIZE	\
			gettext("Passphrase must be at least %d characters.\n")

#define	DEFAULT_PK11TOKEN	SOFT_TOKEN_LABEL

/*
 * Default token name
 */
char *
pkcs11_default_token(void)
{
	return (DEFAULT_PK11TOKEN);
}

/*
 * Prompt user for a passphrase or the PIN for a token.
 *
 * An optional minimum length can be enforced.  Caller can optionally also
 * reprompt for the passphrase/PIN to confirm it was entered correctly.
 * The caller must free the buffer containing the passphrase/PIN with free().
 * 0 returned for success, -1 for failure with the first passphrase/PIN,
 * -2 for failure with the optional second passphrase/PIN used to confirm.
 */
int
pkcs11_get_pass(char *token_name, char **pdata, size_t *psize, size_t min_psize,
    boolean_t with_confirmation)
{
	char	prompt[1024];
	char	*tmpbuf = NULL;
	char	*databuf = NULL;
	int	tries;

	if (token_name != NULL)
		(void) snprintf(prompt, sizeof (prompt), DEFAULT_TOKEN_PROMPT,
		    token_name);
	else
		(void) snprintf(prompt, sizeof (prompt), DEFAULT_USER_PROMPT);

	for (tries = MAX_PASS_TRIES; tries > 0; tries--) {
		tmpbuf = getpassphrase(prompt);
		if (tmpbuf == NULL)
			return (-1);

		if (strnlen(tmpbuf, min_psize) >= min_psize)
			break;

		if (token_name != NULL)
			(void) printf(DEFAULT_TOKEN_MINSIZE, min_psize);
		else
			(void) printf(DEFAULT_USER_MINSIZE, min_psize);
	}
	if (tries == 0) {
		(void) printf(gettext("Exceeded number of attempts.\n"));
		return (-1);
	}

	databuf = strdup(tmpbuf);
	(void) memset(tmpbuf, 0, strlen(tmpbuf));	/* clean up */
	if (databuf == NULL)
		return (-1);

	if (with_confirmation) {
		if (token_name != NULL)
			(void) snprintf(prompt, sizeof (prompt),
			    DEFAULT_TOKEN_REPROMPT, token_name);
		else
			(void) snprintf(prompt, sizeof (prompt),
			    DEFAULT_USER_REPROMPT);
		tmpbuf = getpassphrase(prompt);
		if (tmpbuf == NULL) {
			/* clean up */
			(void) memset(databuf, 0, strlen(databuf));
			free(databuf);
			return (-2);
		}

		if (strcmp(databuf, tmpbuf) != 0) {
			/* clean up */
			(void) memset(tmpbuf, 0, strlen(tmpbuf));
			(void) memset(databuf, 0, strlen(databuf));
			free(databuf);
			return (-2);
		}
	}

	*pdata = databuf;
	*psize = strlen(databuf);

	return (0);
}
