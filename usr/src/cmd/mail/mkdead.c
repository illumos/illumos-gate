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


#ident	"%Z%%M%	%I%	%E% SMI"        /* SVr4.0 1.6 */

#include "mail.h"
/*
	Routine creates dead.letter
*/
void mkdead()
{
	static char pn[] = "mkdead";
	int aret;
	char *dotdead = &dead[1];
	gid_t egid = getegid();
	struct stat st;

	malf = (FILE *)NULL;

	/*
		Make certain that there's something to copy.
	*/
	if (!tmpf)
		return;

	/*
		Try to create dead letter in current directory
		or in home directory
	*/
	umask(umsave);
	setgid(getgid());
	if ((aret = legal(dotdead)) && stat(dotdead, &st) == 0)
		malf = fopen(dotdead, "a");
	if ((malf == NULL) || (aret == 0)) {
		/*
			try to create in $HOME
		*/
		if((hmdead = malloc(strlen(home) + strlen(dead) + 1)) == NULL) {
			fprintf(stderr, "%s: Can't malloc\n",program);
			Dout(pn, 0, "Cannot malloc.\n");
			goto out;
		}
		cat(hmdead, home, dead);
		if ((aret=legal(hmdead)) && !(stat(hmdead, &st) < 0 &&
			errno == EOVERFLOW))
			malf = fopen(hmdead, "a");
		if ((malf == NULL) || (aret == 0)) {
			fprintf(stderr,
				"%s: Cannot create %s\n",
				program,dotdead);
			Dout(pn, 0, "Cannot create %s\n", dotdead);
		out:
			fclose(tmpf);
			error = E_FILE;
			Dout(pn, 0, "error set to %d\n", error);
			umask(7);
			setegid(egid);
			return;
		}  else {
			chmod(hmdead, DEADPERM);
			fprintf(stderr,"%s: Mail saved in %s\n",program,hmdead);
		}
	} else {
		chmod(dotdead, DEADPERM);
		fprintf(stderr,"%s: Mail saved in %s\n",program,dotdead);
	}

	/*
		Copy letter into dead letter box
	*/
	umask(7);
	aret = fseek(tmpf,0L,0);
	if (aret)
		errmsg(E_DEAD,"");
	if (!copystream(tmpf, malf))
		errmsg(E_DEAD,"");
	fclose(malf);
	setegid(egid);
}

void savdead()
{
	static char pn[] = "savdead";
	setsig(SIGINT, saveint);
	dflag = 2;	/* do not send back letter on interrupt */
	Dout(pn, 0, "dflag set to 2\n");
	if (!error) {
		error = E_REMOTE;
		Dout(pn, 0, "error set to %d\n", error);
	}
	maxerr = error;
	Dout(pn, 0, "maxerr set to %d\n", maxerr);
}
