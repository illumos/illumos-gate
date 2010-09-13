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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rcv.h"

struct name *
translate(struct name *np)
{
	struct name	*n, *t, *x;
	void	(*sigint)(int), (*sigquit)(int);
	char	*xl = value("translate");
	char	line[LINESIZE];
	char	postmark[256];
	char	*cmd;
	FILE	*pp;
	int	i;

	if (!xl)
		return np;
	askme = 0;
	postmark[0] = 0;
	i = strlen(xl) + 1;
	for (n = np; n; n = n->n_flink)
		if (! (n->n_type & GDEL))
			i += strlen(n->n_name) + 3;
	cmd = (char *)salloc((unsigned)i);
	strcpy(cmd, xl);
	for (n = np; n; n = n->n_flink)
		if (! (n->n_type & GDEL)) {
			strcat(cmd, " \"");
			strcat(cmd, n->n_name);
			strcat(cmd, "\"");
		}
	if ((pp = npopen(cmd, "r")) == NULL) {
		perror(xl);
		senderr++;
		return np;
	}
	sigint = sigset(SIGINT, SIG_IGN);
	sigquit = sigset(SIGQUIT, SIG_IGN);
	fgets(postmark, sizeof postmark, pp);
	if (postmark[0])
		{
		postmark[strlen(postmark)-1] = 0;
		assign("postmark", postmark);
		}
	for (n = np; n; n = n->n_flink) {
		if (n->n_type & GDEL)
			continue;
		if (fgets(line, sizeof line, pp) == NULL)
			break;
		line[strlen(line)-1] = 0;
		if (!strcmp(line, n->n_name))
			continue;
		x = extract(line, n->n_type);
		n->n_type |= GDEL;
		n->n_name = "";
		if (x && !x->n_flink && strpbrk(n->n_full, "(<"))
			x->n_full = splice(x->n_name, n->n_full);
		if (x) {
			t = tailof(x);
			cat(t, n->n_flink);
			n->n_flink = NULL;
			cat(n, x);
			n = t;
		}
	}
	if (getc(pp) == 'y')
		askme++;
	if (npclose(pp) != 0 || n)
		senderr++;
	sigset(SIGINT, sigint);
	sigset(SIGQUIT, sigquit);
	return np;
}
