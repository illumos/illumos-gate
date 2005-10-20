/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include "refer..c"
#include <string.h>
#define	move(x, y) close(y); dup(x); close(x);

extern void err();
extern long findline();
extern void huntmain();
extern void restodir();

static int callhunt(char *, char *, char *, int);
static int dodeliv(char *, char *, char *, int);

int
corout(char *in, char *out, char *rprog, char *arg, int outlen)
{
	int pipev[2], fr1, fr2, fw1, fw2, n;

#if D1
	fprintf(stderr, "in corout, rprog /%s/ in /%s/\n",
	    rprog ? rprog : "", strlen(in) ? in : "");
#endif

	if (strcmp(rprog, "hunt") == 0)
		return (callhunt(in, out, arg, outlen));
	if (strcmp(rprog, "deliv") == 0)
		return (dodeliv(in, out, arg, outlen));
	pipe(pipev);
	fr1 = pipev[0];
	fw1 = pipev[1];
	pipe(pipev);
	fr2 = pipev[0];
	fw2 = pipev[1];
	if (fork() == 0) {
		close(fw1);
		close(fr2);
		move(fr1, 0);
		move(fw2, 1);
		if (rprog[0] != '/')
			chdir("/usr/lib/refer");
		execl(rprog, "deliv", arg, 0);
		err(gettext("Can't run %s"), rprog);
	}
	close(fw2);
	close(fr1);
	if (strlen(in) > 0)
		write(fw1, in, strlen(in));
	close(fw1);
	wait(0);
	n = read(fr2, out, outlen);
	out[n] = 0;
	close(fr2);
	return (0);
}

#define	ALEN 50

static int
callhunt(char *in, char *out, char *arg, int outlen)
{
	char *argv[20], abuff[ALEN];
	extern int typeindex;
	int argc;
	extern char one[];
	extern int onelen;
	argv[0] = "hunt";
	argv[1] = "-i";
	argv[2] = in;
	argv[3] = "-t";
	argv[4] = out;
	argv[5] = (char *)outlen;
	argv[6] = "-T";
	argv[7] = "-F1";
	argv[8] = "-o";
	argv[9] = one;
	argv[10] = (char *)onelen;
	argv[11] = abuff;
	strcpy(abuff, arg);
	if (strlen(abuff) > ALEN)
		err("abuff not big enough %d", strlen(abuff));
	argc = 6;
	huntmain(argc, argv);
	return (0);
}

static int
dodeliv(char *in, char *out, char *arg, int outlen)
{
	char *mout;
	int mlen;
#if D1
	fprintf(stderr, "in dodeliv, arg /%s/\n", arg?arg:"");
#endif
	if (arg && arg[0])
		chdir(arg);

	mlen = findline(in, &mout, outlen, 0L);

	if (mlen > 0) {
		strncpy(out, mout, outlen);
		free(mout);
	}
	restodir();
	return (0);
}
