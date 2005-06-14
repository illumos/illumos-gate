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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	join F1 F2 on stuff */

#include	<stdio.h>
#include	<locale.h>
#include	<stdlib.h>
#include	<widec.h>
#include	<string.h>
#include	<limits.h>
#include	<malloc.h>
#include	<errno.h>
#include	<unistd.h>


static	void	output(int, int);
static	int	cmp(wchar_t *, wchar_t *);
static	int	input(int);
static	void	Usage();
static	void	init_buf();
static	void	get_buf(int, int);
static	void	get_ppi(int);
static	void	get_olist(int);
wchar_t	*wcsrchr(const wchar_t *, wchar_t);
size_t	wcslen(const wchar_t *);


#define	JOINFIELD	9999
#define	F1		0
#define	F2		1
#define	NFLD		LINE_MAX/2	/* max field per line */
#define	NOFLD		(2*NFLD) /* number arguments to -o */
#define	comp()		cmp(ppi[F1][j1], ppi[F2][j2])
#define	get1()		n1 = input(F1)
#define	get2()		n2 = input(F2)
#define	putfield(string)				\
	if (string == (wchar_t *)NULL)			\
		(void) fputs(null, stdout);		\
	else if (*string == (wchar_t)NULL)		\
		(void) fputs(null, stdout);		\
	else						\
		(void) fputws(string, stdout)

#define	max(a, b)	(a >= b ? a : b)
int	CNFLD;	/* current number of fields per line */
int	CNOFLD;	/* current number of output fields */
int	CBUFSIZE[2];	/* current size of input buffers */

static	FILE	*f[2];
static	wchar_t	*buf[2];		/* input lines */
static	wchar_t	**ppi[2];  		/* pointers to fields in lines */
static	int	j1	= 1;		/* join of this field of file 1 */
static	int	j2	= 1;		/* join of this field of file 2 */
static	int	*olist;			/* output these fields */
static	int	*olistf;		/* from these files */
static	int	no	= 0;		/* number of entries in olist */
static	wchar_t	sep1	= L' ';		/* default field separator */
static	wchar_t	sep2	= L'\t';
static	char	*null	= "";
static	int	aflg	= 0;
static	int	vflg	= 0;
static	int	tflg	= 0;

int
main(int argc, char *argv[])
{
	int	i, j;
	int	n1, n2;
	off_t	top2, bot2;
	int	cmpresult;
	int	opt, filenumber;
	int	nextargopt;
	size_t	t;
	char	buffer1[BUFSIZ];
	char	tmpfile[20];
	int	fd;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

	(void) textdomain(TEXT_DOMAIN);

	(void) init_buf(); /* allocate buffers */

	/* check for non-standard "-j#" option, last 2 arguments are files */
	for (i = 1; i < (argc - 2); i++) {
		if (strcmp(argv[i], "--") == 0)
			break;

		if (strcmp(argv[i], "-j1") == 0) {
			if (i == argc - 3)
				Usage();

			j1 = (int)strtol(argv[i+1], (char **)NULL, 10);
			for (j = i; j < argc - 1; j++) {
				argv[j] = argv[j+2];
			}
			argc -= 2;
			i--;
		} else if (strcmp(argv[i], "-j2") == 0) {
			if (i >= argc - 3)
				Usage();

			j2 = (int)strtol(argv[i+1], (char **)NULL, 10);
			for (j = i; j < argc - 1; j++) {
				argv[j] = argv[j+2];
			}
			argc -= 2;
			i--;
		}

	}

	/* check for non-standard "-o" option, last 2 arguments are files */
	for (i = 1; i < argc - 2; i++) {

		/* stop looking for -o if "--" */
		if (strcmp(argv[i], "--") == 0)
			break;

		if (strncmp(argv[i], "-o", 2) == 0) {
			if (argv[i][2] == '\0') {
				for (j = i; j < argc; j++) {
					argv[j] = argv[j+1];
				}
				argc--;
			} else {
				argv[i] += 2 + (int)strspn(&argv[i][2], " ");
			}

			if (i == argc - 2)
				Usage();

			for (no = 0; (no < 2*CNFLD) && (i < argc - 2); no++) {
				if (no > CNOFLD - 1) {
					/* Get larger table for outlists */
					/* (CNOFLD is updated.) */
					get_olist(CNOFLD + NOFLD);
				}

				if (strncmp(argv[i], "1.", 2) == 0) {
					olistf[no] = F1;
					olist[no] = (int)strtol(&argv[i][2],
					    (char **)NULL, 10);
					nextargopt = 2 + (int)
					    strspn(&argv[i][2], "0123456789");
				} else if (strncmp(argv[i], "2.", 2) == 0) {
					olistf[no] = F2;
					olist[no] = (int)strtol(&argv[i][2],
					    (char **)NULL, 10);
					nextargopt = 2 + (int)
					    strspn(&argv[i][2], "0123456789");
				} else if (argv[i][0] == '0') {
					olistf[no] = JOINFIELD;
					nextargopt = 1;
				} else
					break;

				if (olist[no] > CNFLD)
					get_ppi(olist[no]);

				if (argv[i][nextargopt] == '\0') {
					for (j = i; j < argc; j++) {
						argv[j] = argv[j+1];
					}
					argc--;
				} else if ((argv[i][nextargopt] == ' ') ||
				    (argv[i][nextargopt] == ',')) {
					argv[i] += nextargopt + 1;
				} else
					Usage();
			}
		}
	}

	/* get other options */
	while ((opt = getopt(argc, argv, "1:2:a:e:j:t:v:")) != EOF) {
		switch (opt) {
		case '1':
			j1 = (int)strtol(optarg, (char **)NULL, 10);
			break;

		case '2':
			j2 = (int)strtol(optarg, (char **)NULL, 10);
			break;

		case 'a':
		case 'v':
			filenumber = (int)strtol(optarg, (char **)NULL, 10);
			if ((filenumber != 1) && (filenumber != 2))
				Usage();

			aflg |= filenumber;
			if (opt == 'v')
				vflg |= filenumber;
			break;

		case 'e':
			null = optarg;
			break;

		case 'j':
			j1 = j2 = (int)strtol(optarg, (char **)NULL, 10);
			break;

		case 't':
			tflg = 1;
			(void) mbtowc(&sep1, optarg, MB_CUR_MAX);
			sep2 = sep1;
			break;
		}
	}
	if (j1 > CNFLD || j2 > CNFLD)
		get_ppi(max(j1, j2));

	/* check options */
	if ((j1 > CNFLD) || (j2 > CNFLD) || (j1 <= 0) || (j2 <= 0)) {
		(void) fprintf(stderr, gettext(
		    "join: bad join field number\n"));
		Usage();
	}

	/* 0 origin */
	for (i = 0; i < no; i++)
		olist[i]--;
	j1--;
	j2--;

	if (argc - optind != 2)
		Usage();

	if (strcmp(argv[optind], "-") == 0)
		f[F1] = stdin;
	else if ((f[F1] = fopen(argv[optind], "r")) == NULL) {
		perror(argv[optind]);
		exit(1);
	}

	if (strcmp(argv[optind+1], "-") == 0) {
		(void) strncpy(tmpfile, "/tmp/joinXXXXXX", 20);
		if ((fd = mkstemp(tmpfile)) < 0) {
			perror(gettext("join: cannot create tmpfile"));
			exit(1);
		}
		if ((f[F2] = fdopen(fd, "w+")) == NULL) {
			perror(gettext("join: cannot open tmpfile"));
			exit(1);
		}
		/* tmpfile is automatically removed on exit */
		(void) unlink(tmpfile);

		while ((t = fread(buffer1, 1, BUFSIZ, stdin)) != 0) {
			if ((fwrite(buffer1, 1, t, f[F2])) != t) {
				(void) fprintf(stderr, gettext(
					"join: cannot write to tmpfile\n"));
				exit(1);
			}
		}
		(void) fflush(f[F2]);
		rewind(f[F2]);
	} else if ((f[F2] = fopen(argv[optind+1], "r")) == NULL) {
		perror(argv[optind+1]);
		exit(1);
	}

	/* set bottom mark on file2 */
	bot2 = ftello(f[F2]);

	/* input a line from each file */
	get1();
	get2();

	/* while lines in both files or -a|v and lines in ether file */
	while (((n1 > 0) && (n2 > 0)) || ((aflg != 0) && ((n1 + n2) > 0))) {

		/* compare join fields */
		cmpresult = comp();

		/* joinfiled1 > joinfield2 or file1 exasted */
		if (((n1 > 0) && (n2 > 0) && (cmpresult > 0)) || (n1 == 0)) {

			/* outputing unpaired ? */
			if (aflg & 2)
				output(0, n2);

			/* mark bottom of file2 */
			bot2 = ftello(f[F2]);

			/* input line from file2 */
			get2();

		/* joinfiled1 < joinfield2 or file2 exasted */
		} else if (((n1 > 0) && (n2 > 0) && (cmpresult < 0)) ||
		    (n2 == 0)) {

			/* outputing unpaired ? */
			if (aflg & 1)
				output(n1, 0);

			/* input line from file1 */
			get1();

		/* line1 and line2 not empty and joinfield1 == joinfield2 */
		} else {
			/* for lines in file2 that match join field */
			while (n2 > 0 && comp() == 0) {

				/* if not -v output line */
				if (!vflg)
					output(n1, n2);

				/* mark top of file2 */
				top2 = ftello(f[F2]);

				/* input line from file2 */
				get2();
			}

			/* back to bottom line in file2 */
			(void) fseeko(f[F2], (off_t)bot2, SEEK_SET);

			/* input line form file1 and file2 */
			get2();
			get1();

			for (;;) {
				/* compare join fields */
				cmpresult = comp();

				/*
				 * line1 and line2 not empty and
				 * joinfield1 == joinfield2
				 */
				if (n1 > 0 && n2 > 0 && cmpresult == 0) {

					/* if not -v output line */
					if (!vflg)
						output(n1, n2);

					/* input line from file2 */
					get2();

				/* joinfiled1 < joinfield2 or file2 exasted */
				} else if (n1 > 0 && n2 > 0 && cmpresult < 0 ||
				    n2 == 0) {

					/* seek to bottom of file2 */
				(void) fseeko(f[F2], (off_t)bot2, SEEK_SET);

					/* input line form file1 and file2 */
					get2();
					get1();

				/* file1 exasted or joinfile1 > joinfield2 */
				} else {
					/* seek to top of file2 */
				(void) fseeko(f[F2], (off_t)top2, SEEK_SET);

					/* set bottom at top */
					bot2 = top2;

					/* input line form file2 */
					get2();

					break;
				}
			}
		}
	}
	return (0);
}


static int
input(int n)		/* get input line and split into fields */
{
	int i, c;
	wchar_t *bp;
	wchar_t *tbp;
	wchar_t **pp;
	int	nread;

	bp = buf[n];
	pp = ppi[n];

	errno = 0;
	if (fgetws(bp, CBUFSIZE[n], f[n]) == (wchar_t *)NULL) {
		if (errno) {
			perror("join");
			exit(1);
		}
		return (0);
	} else {
		if (errno == EILSEQ) {
			(void) fprintf(stderr, gettext(
			"join: invalid char following \""));
			(void) fputws(bp, stderr);
			(void) fprintf(stderr, "\":  ");
			perror("");
			exit(1);
		} else if (errno) {
			perror("join");
			exit(1);
		}

		/* Check for long lines */
		if (((wchar_t *)wcsrchr((wchar_t *)bp, L'\n')
			== (wchar_t *)NULL) && (size_t)wcslen((wchar_t *)bp)
			== (size_t)(CBUFSIZE[n] - 1)) {
			tbp = bp;
			nread = CBUFSIZE[n] - 1;
			while ((wchar_t *)wcsrchr((wchar_t *)tbp, L'\n')
				== (wchar_t *)NULL) {
				/* Increase buffer by LINE_MAX */
				/* (CBUFSIZE[n] is updated.) */
				get_buf(n, CBUFSIZE[n] + LINE_MAX);
				bp = buf[n];
				tbp = buf[n] + nread;

				/* Read rest of line */
				errno = 0;
				if (fgetws(tbp, LINE_MAX + 1, f[n])
					==  (wchar_t *)NULL) {
					if (errno) {
						perror("join");
						exit(1);
					}
					break;
				} else if (errno == EILSEQ) {
					(void) fprintf(stderr, gettext(
					"join: invalid char following \""));
					(void) fputws(bp, stderr);
					(void) fprintf(stderr, "\":  ");
					perror("");
					exit(1);
				} else if (errno) {
					perror("join");
					exit(1);
				}
				nread += (size_t)wcslen((wchar_t *)tbp);
			}
		}
	}

	bp = buf[n];
	i = 0;
	do {
		i++;
		/* Check for overflow of ppi[n] */
		if (i > CNFLD - 1) {    /* account for 0 termination */
			/* Reallocate larger buffers (CNFLD is updated.) */
			get_ppi(CNFLD + NFLD);
			/* Restore local pointer */
			pp = &ppi[n][i-1];
		}
		if (!tflg)	/* strip multiples */
			while ((c = *bp) == sep1 || c == sep2) {
				bp++;	/* skip blanks */
			}
		*pp++ = bp;	/* record beginning */
		while ((c = *bp) != sep1 && c != L'\n' &&
				c != sep2 && c != L'\0') {
			bp++;
		}
		*bp++ = L'\0';	/* mark end by overwriting blank */
	} while ((c != L'\n') && (c != L'\0') && (pp != &ppi[n][CNFLD]));

	*pp = (wchar_t *)NULL;


	return (i);
}


static void
output(on1, on2)	/* print items from olist */
int on1, on2;
{
	int i;

	if (no <= 0) {	/* default case */
		if (on1)
			putfield(ppi[F1][j1]);
		else
			putfield(ppi[F2][j2]);
		for (i = 0; i < on1; i++)
			if (i != j1) {
				(void) putwchar(sep1);
				putfield(ppi[F1][i]);
			}
		for (i = 0; i < on2; i++)
			if (i != j2) {
				(void) putwchar(sep1);
				putfield(ppi[F2][i]);
			}
		(void) putwchar(L'\n');
	} else {
		for (i = 0; i < no; i++) {
			if (olistf[i] == F1 && on1 <= olist[i] ||
				olistf[i] == F2 && on2 <= olist[i]) {
				(void) fputs(null, stdout);
			} else if (olistf[i] == JOINFIELD) {
				if (on1)
					putfield(ppi[F1][j1]);
				else
					putfield(ppi[F2][j2]);
			} else
				putfield(ppi[olistf[i]][olist[i]]);

			if (i < no - 1)
#if defined(__lint)	/* lint doesn't grok "%wc" */
				/* EMPTY */;
#else
				(void) printf("%wc", sep1);
#endif
			else
				(void) putwchar(L'\n');
		}
	}
}


static int
cmp(s1, s2)
wchar_t *s1, *s2;
{
	int	rc;

	if (s1 == (wchar_t *)NULL) {
		if (s2 == (wchar_t *)NULL)
			rc = 0;
		else
			rc = -1;
	} else if (s2 == (wchar_t *)NULL)
		rc = 1;
	else
		rc = wscoll(s1, s2);

	return (rc);
}


static void
Usage()
{
	(void) fprintf(stderr, gettext(
	"usage: join [-a file_number | -v file_number] [-o list [-e string]]\n"
	"            [-t char] [-1 field] [-2 field] file1 file2\n\n"
	"       join [-a file_number] [-j field] [-j1 field] [-j2 field]\n"
	"            [-o list [-e string]] [-t char] file1 file2\n"));
	exit(1);
}

/*
 *  Allocate memory for buffers.
 */
static void
init_buf()
{
	(void) get_buf(F1, LINE_MAX);
	(void) get_buf(F2, LINE_MAX);
	(void) get_ppi(NFLD);
	(void) get_olist(NOFLD);
}


static void
get_ppi(nfld)
int nfld;
{
	int i;

	for (i = 0; i < 2; i++) {
		if (ppi[i]) {
			if ((ppi[i] = (wchar_t **)realloc((char *)ppi[i],
				(unsigned)(nfld * sizeof (wchar_t *))))
					== NULL) {
				(void) fprintf(stderr,
				gettext("realloc pointer table failed\n"));
				exit(1);
			}
		} else {
			if ((ppi[i] = (wchar_t **)calloc((unsigned)nfld,
				(unsigned)sizeof (wchar_t *))) == NULL) {
				(void) fprintf(stderr,
				    gettext("calloc pointer table failed\n"));
				exit(1);
			}
		}
	}

	CNFLD = nfld;
}


static void
get_buf(i, size)
int i;
int size;
{
	if (buf[i]) {
		if ((buf[i] = (wchar_t *)
			realloc(buf[i], (unsigned)(size * sizeof (wchar_t))))
			    == NULL) {
			(void) fprintf(stderr,
			    gettext("realloc input buffer failed\n"));
			exit(1);
		}
	} else {
		if ((buf[i] = (wchar_t *)
			calloc((unsigned)size, (unsigned)sizeof (wchar_t)))
				== NULL) {
			(void) fprintf(stderr,
				gettext("calloc input buffer failed\n"));
			exit(1);
		}
	}

	CBUFSIZE[i] = size;
}


static void
get_olist(onfld)
int onfld;
{
	if (olist) {
		if ((olist = (int *)realloc((wchar_t *)olist,
			(unsigned)(onfld * sizeof (int)))) == NULL) {
			(void) fprintf(stderr,
			    gettext("realloc olist failed\n"));
			exit(1);
		}
	} else {
		if ((olist = (int *)
			calloc((unsigned)onfld, (unsigned)sizeof (int)))
			    == NULL) {
			(void) fprintf(stderr,
				    gettext("calloc olist failed\n"));
			exit(1);
		}
	}

	if (olistf) {
		if ((olistf = (int *)realloc((wchar_t *)olistf,
			(unsigned)(onfld * sizeof (int)))) == NULL) {
			(void) fprintf(stderr,
			    gettext("realloc olistf failed\n"));
		exit(1);
		}
	} else {
		if ((olistf = (int *)
		    calloc((unsigned)onfld, (unsigned)sizeof (int)))
			== NULL) {
		    (void) fprintf(stderr, gettext("calloc olistf failed\n"));
			exit(1);
		}
	}

	CNOFLD = onfld;
}
