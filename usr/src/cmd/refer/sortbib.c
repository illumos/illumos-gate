/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 1983-1988 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

#define	BUF BUFSIZ
#define	MXFILES 16

char tempfile[32];		/* temporary file for sorting keys */
int tmpfd = -1;
char *keystr = "AD";		/* default sorting on author and date */
int multauth = 0;		/* by default sort on senior author only */
int oneauth;			/* has there been author in the record? */

main(argc, argv)	/* sortbib: sort bibliographic database in place */
int argc;
char *argv[];
{
	FILE *fp[MXFILES], *tfp;
	int i;
	void onintr();

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1)		/* can't use stdin for seeking anyway */
	{
		puts(gettext("Usage:  sortbib [-sKEYS] database [...]\n\
\t-s: sort by fields in KEYS (default is AD)"));
		exit(1);
	}
	if (argc > 2 && argv[1][0] == '-' && argv[1][1] == 's')
	{
		/* if a key is specified use it, otherwise use default key */
		if (argv[1][2] != '\0')
			keystr = argv[1] + 2;
		eval(keystr);		/* evaluate A+ for multiple authors */
		argv++; argc--;
	}
	if (argc > MXFILES+1)	/* too many open file streams */
	{
		fprintf(stderr,
		gettext("sortbib: More than %d databases specified\n"),
		    MXFILES);
		exit(1);
	}
	for (i = 1; i < argc; i++)		/* open files in arg list */
		if ((fp[i-1] = fopen(argv[i], "r")) == NULL)
			error(argv[i]);
	strcpy(tempfile, "/tmp/SbibXXXXXX");	/* tempfile for sorting keys */
	if ((tmpfd = mkstemp(tempfile)) == -1)
		error(tempfile);

	(void) close(tmpfd);
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)	/* remove if interrupted */
		signal(SIGINT, onintr);
	if ((tfp = fopen(tempfile, "w")) == NULL) {
		(void) unlink(tempfile);
		error(tempfile);
	}
	for (i = 0; i < argc-1; i++)		/* read keys from bib files */
		sortbib(fp[i], tfp, i);
	fclose(tfp);
	deliver(fp, tfp);	/* do disk seeks and read from biblio files */
	(void) unlink(tempfile);
	exit(0);
	/* NOTREACHED */
}

int rsmode = 0;		/* record separator: 1 = null line, 2 = bracket */

sortbib(fp, tfp, i)	/* read records, prepare list for sorting */
FILE *fp, *tfp;
int i;
{
	long offset, lastoffset = 0, ftell();	/* byte offsets in file */
	int length, newrec, recno = 0;		/* reclen, new rec'd?, number */
	char line[BUF], fld[4][BUF];		/* one line, the sort fields */

	/* measure byte offset, then get new line */
	while (offset = ftell(fp), fgets(line, BUF, fp))
	{
		if (recno == 0)		/* accept record w/o initial newline */
			newrec = 1;
		if (line[0] == '\n')	/* accept null line record separator */
		{
			if (!rsmode)
				rsmode = 1;	/* null line mode */
			if (rsmode == 1)
				newrec = 1;
		}
		if (line[0] == '.' && line[1] == '[')	/* also accept .[ .] */
		{
			if (!rsmode)
				rsmode = 2;	/* bracket pair mode */
			if (rsmode == 2)
				newrec = 1;
		}
		if (newrec)		/* by whatever means above */
		{
			newrec = 0;
			length = offset - lastoffset;	/* measure rec len */
			if (length > BUF*8) {
				fprintf(stderr,
				gettext("sortbib: record %d longer than %d (%d)\n"),
					recno, BUF*8, length);
				(void) unlink(tempfile);
				exit(1);
			}
			if (recno++)			/* info for sorting */
			{
				fprintf(tfp, "%d %d %d : %s %s %s %s\n",
					i, lastoffset, length,
					fld[0], fld[1], fld[2], fld[3]);
				if (ferror(tfp)) {
					(void) unlink(tempfile);
					error(tempfile);
				}
			}
			*fld[0] = *fld[1] = *fld[2] = *fld[3] = NULL;
			oneauth = 0;		/* reset number of authors */
			lastoffset = offset;	/* save for next time */
		}
		if (line[0] == '%')	/* parse out fields to be sorted */
			parse(line, fld);
	}
	offset = ftell(fp);		/* measure byte offset at EOF */
	length = offset - lastoffset;	/* measure final record length */
	if (length > BUF*8)
	{
		fprintf(stderr,
		    gettext("sortbib: record %d longer than %d (%d)\n"),
		    recno, BUF*8, length);
		(void) unlink(tempfile);
		exit(1);
	}
	if (line[0] != '\n')		/* ignore null line just before EOF */
	{
		fprintf(tfp, "%d %d %d : %s %s %s %s\n",
			i, lastoffset, length,
			fld[0], fld[1], fld[2], fld[3]);
		if (ferror(tfp)) {
			(void) unlink(tempfile);
			error(tempfile);	/* disk error in /tmp */
		}
	}
}

deliver(fp, tfp)	/* deliver sorted entries out of database(s) */
FILE *fp[], *tfp;
{
	char str[BUF], buff[BUF*8];	/* for tempfile & databases */
	char cmd[80];			/* for using system sort command */
	long int offset;
	int i, length;

	/* when sorting, ignore case distinctions; tab char is ':' */
	sprintf(cmd, "sort +4f +0n +1n %s -o %s", tempfile, tempfile);
	if (system(cmd) == 127) {
		(void) unlink(tempfile);
		error("sortbib");
	}
	tfp = fopen(tempfile, "r");
	while (fgets(str, sizeof (str), tfp))
	{
		/* get file pointer, record offset, and length */
		if (sscanf(str, "%d %d %d :", &i, &offset, &length) != 3)
			error(gettext("sortbib: sorting error"));
		/* seek to proper disk location in proper file */
		if (fseek(fp[i], offset, 0) == -1) {
			(void) unlink(tempfile);
			error("sortbib");
		}
		/* read exactly one record from bibliography */
		if (fread(buff, sizeof (*buff), length, fp[i]) == 0) {
			(void) unlink(tempfile);
			error("sortbib");
		}
		/* add newline between unseparated records */
		if (buff[0] != '\n' && rsmode == 1)
			putchar('\n');
		/* write record buffer to standard output */
		if (fwrite(buff, sizeof (*buff), length, stdout) == 0) {
			(void) unlink(tempfile);
			error("sortbib");
		}
	}
}

parse(line, fld)	/* get fields out of line, prepare for sorting */
char line[];
char fld[][BUF];
{
	char wd[8][BUF/4], *strcat();
	int n, i, j;

	for (i = 0; i < 8; i++)		/* zap out old strings */
		*wd[i] = NULL;
	n = sscanf(line, "%s %s %s %s %s %s %s %s",
		wd[0], wd[1], wd[2], wd[3], wd[4], wd[5], wd[6], wd[7]);
	for (i = 0; i < 4; i++)
	{
		if (wd[0][1] == keystr[i])
		{
			if (wd[0][1] == 'A')
			{
				if (oneauth && !multauth)	/* no repeat */
					break;
				else if (oneauth)		/* mult auths */
					strcat(fld[i], "~~");
				if (!endcomma(wd[n-2]))		/* surname */
					strcat(fld[i], wd[n-1]);
				else {				/* jr. or ed. */
					strcat(fld[i], wd[n-2]);
					n--;
				}
				strcat(fld[i], " ");
				for (j = 1; j < n-1; j++)
					strcat(fld[i], wd[j]);
				oneauth = 1;
			} else if (wd[0][1] == 'D') {
				strcat(fld[i], wd[n-1]);	/* year */
				if (n > 2)
					strcat(fld[i], wd[1]);	/* month */
			} else if (wd[0][1] == 'T' || wd[0][1] == 'J') {
				j = 1;
				if (article(wd[1]))	/* skip article */
					j++;
				for (; j < n; j++)
					strcat(fld[i], wd[j]);
			} else  /* any other field */
				for (j = 1; j < n; j++)
					strcat(fld[i], wd[j]);
		}
		/* %Q quorporate or queer author - unreversed %A */
		else if (wd[0][1] == 'Q' && keystr[i] == 'A')
			for (j = 1; j < n; j++)
				strcat(fld[i], wd[j]);
	}
}

article(str)		/* see if string contains an article */
char *str;
{
	if (strcmp("The", str) == 0)	/* English */
		return (1);
	if (strcmp("A", str) == 0)
		return (1);
	if (strcmp("An", str) == 0)
		return (1);
	if (strcmp("Le", str) == 0)	/* French */
		return (1);
	if (strcmp("La", str) == 0)
		return (1);
	if (strcmp("Der", str) == 0)	/* German */
		return (1);
	if (strcmp("Die", str) == 0)
		return (1);
	if (strcmp("Das", str) == 0)
		return (1);
	if (strcmp("El", str) == 0)	/* Spanish */
		return (1);
	if (strcmp("Den", str) == 0)	/* Scandinavian */
		return (1);
	return (0);
}

eval(keystr)		/* evaluate key string for A+ marking */
char keystr[];
{
	int i, j;

	for (i = 0, j = 0; keystr[i]; i++, j++)
	{
		if (keystr[i] == '+')
		{
			multauth = 1;
			i++;
		}
		if (keystr[i] == NULL)
			break;
		keystr[j] = keystr[i];
	}
	keystr[j] = NULL;
}

error(s)		/* exit in case of various system errors */
char *s;
{
	perror(s);
	exit(1);
}

void
onintr()		/* remove tempfile in case of interrupt */
{
	fprintf(stderr, gettext("\nInterrupt\n"));
	unlink(tempfile);
	exit(1);
}

endcomma(str)
char *str;
{
	int n;

	n = strlen(str) - 1;
	if (str[n] == ',')
	{
		str[n] = NULL;
		return (1);
	}
	return (0);
}
