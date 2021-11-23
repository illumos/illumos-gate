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
 *
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <definit.h>

/* Tokens are separated by spaces, tabs and newlines. */
#define	SEPARATORS " \t\n"

typedef struct definit {
	FILE *di_fp;
	char *di_line;
	char *di_tok;
} definit_t;

int
definit_open(const char *file, void **statep)
{
	FILE *fp;
	int _errno;
	definit_t *state = NULL;

	if ((fp = fopen(file, "r")) == NULL)
		return (-1);

	if ((state = calloc(1, sizeof (*state))) == NULL)
		goto err;

	if ((state->di_line = calloc(DEFINIT_MAXLINE, sizeof (char))) == NULL)
		goto err;

	state->di_fp = fp;
	*statep = state;

	return (0);

err:
	_errno = errno;
	(void) fclose(fp);
	if (state != NULL) {
		free(state->di_line);
		free(state);
	}
	errno = _errno;
	return (-1);
}

void
definit_close(void *statep)
{
	definit_t *state = statep;

	(void) fclose(state->di_fp);
	free(state->di_line);
	free(state);
}

/*
 * This parser was written to produce the same output as the ones it replaced
 * in init and svc.startd. As such it has some shortcomings:
 * - Values may be quoted but the quotes are just stripped and separators such
 *   as whitespace are not treated specially within quotes;
 * - Lines which are longer than DEFINIT_MAXLINE -1 bytes are split. Tokens
 *   which span a split will be truncated, one way or another.
 * - Comments at the end of a line (after a token) are not supported.
 * These could be corrected in the future if strict backwards compatibility is
 * not required.
 */

static char *
definit_nextline(definit_t *state)
{
	char *line;

	while ((line = fgets(state->di_line, DEFINIT_MAXLINE, state->di_fp))
	    != NULL) {
		boolean_t inquotes;
		char *p, *bp;
		size_t wslength;

		/*
		 * Ignore blank or comment lines.
		 */
		if (line[0] == '#' || line[0] == '\0' ||
		    (wslength = strspn(line, SEPARATORS)) == strlen(line) ||
		    line[wslength] == '#') {
			continue;
		}

		/*
		 * Make a pass through the line and:
		 * - Replace any non-quoted semicolons with spaces;
		 * - Remove any quote characters.
		 *
		 * While walking this, 'p' is the current position in the line
		 * and, if any characters have been found which need to be
		 * removed, 'bp' tracks the position in the line where
		 * subsequent characters need to be written in order to close
		 * the gap; 'bp' trails 'p'.
		 * If 'bp' is NULL, no characters to remove have been found.
		 */
		inquotes = B_FALSE;
		for (p = line, bp = NULL; *p != '\0'; p++) {
			switch (*p) {
			case '"':
			case '\'':
				inquotes = !inquotes;
				if (bp == NULL)
					bp = p;
				break;
			case ';':
				if (!inquotes)
					*p = ' ';
				/* FALLTHROUGH */
			default:
				if (bp != NULL)
					*bp++ = *p;
				break;
			}
		}
		if (bp != NULL)
			*bp = '\0';

		/*
		 * Perform an initial strtok_r() call on the new line.
		 * definit_token() will repeatedly call strtok_r() until the
		 * line is consumed, and then call this function again for
		 * more input.
		 */
		if ((p = strtok_r(line, SEPARATORS, &state->di_tok)) != NULL)
			return (p);
	}

	return (NULL);
}

const char *
definit_token(void *statep)
{
	definit_t *state = statep;
	char *tok;

	for (;;) {
		tok = NULL;

		if (state->di_tok != NULL)
			tok = strtok_r(NULL, SEPARATORS, &state->di_tok);

		if (tok == NULL)
			tok = definit_nextline(state);

		if (tok == NULL)
			break;

		if (strchr(tok, '=') != NULL && *tok != '=')
			return (tok);
	}

	return (NULL);
}
