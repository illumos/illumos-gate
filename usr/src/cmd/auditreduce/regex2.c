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

/*
 * Extend regular expression matching for the file objects to allow
 * multiple regular expressions (instead of just 1), and to not select
 * regular expressions starting with a "~".  This will allow adminstrator
 * to exclude uninteresting files from the audit trail.
 */

#include <stdlib.h>
#include <string.h>
#include <libgen.h>

struct exp {
	char *s;	/* The regular is expression */
	int not;	/* Exclude if matched? */
	char *comp;	/* The compiled regular expression */
};

static char SEP = ',';		/* separator used between reg exprs */
static char NOT = '~';		/* Character used to exclude rex exprs */
static int compile = 1;		/* Must we compile the expressions */

static char *fexp = NULL;	/* full list of regular expressions */
static int nexp = 1;		/* number of regular expressions in fexp */
static struct exp *p_exp = NULL; /* list of individual expressions */

char *
re_comp2(s)
	char *s;
{
	char *p;
	int i;
	static char *er = "regcmp: error";

	compile = 1;
	if (p_exp != NULL) {
		for (i = 0; i < nexp; i++)
			if (p_exp[i].comp != NULL)
				free(p_exp[i].comp);
		free(p_exp);
	}
	if (fexp != NULL) {
		free(fexp);
	}
	fexp = strdup(s);
	for (p = fexp, nexp = 1; *p != '\0'; p++) {
		if (*p == SEP) {
			nexp++;
		}
	}
	p_exp = (struct exp *)malloc(nexp * sizeof (struct exp));
	for (i = 0, p = fexp; *p != '\0'; i++) {
		p_exp[i].comp = NULL;
		if (*p == NOT) {
			p++;
			p_exp[i].not = 1;
		} else {
			p_exp[i].not = 0;
		}
		p_exp[i].s = p;
		while (*p != SEP && *p != '\0')
			p++;
		if (*p == SEP) {
			*p = '\0';
			p++;
		}
		if (regcmp(p_exp[i].s, NULL) == NULL)
			return (er);
	}
	return (NULL);
}

int
re_exec2(s)
	char *s;
{
	int i;
	char *ret;

	if (compile) {
		for (i = 0; i < nexp; i++) {
			if ((p_exp[i].comp = regcmp(p_exp[i].s, NULL)) == NULL)
				return (-1);
		}
		compile = 0;
	}
	for (i = 0; i < nexp; i++) {
		ret = regex(p_exp[i].comp, s);
		if (ret != NULL) {
			return (!p_exp[i].not);
		}
	}

	/* no match and no more to check */
	return (0);

}
