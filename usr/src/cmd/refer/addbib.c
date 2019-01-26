/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <locale.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#define	MAXENT 50

struct skeleton {
	char prompt[20];	/* prompt user for entry */
	char keylet[5];		/* key letter for database */
} bibskel[MAXENT] = {
	"   Author:",	"%A",
	"    Title:",	"%T",
	"  Journal:",	"%J",
	"   Volume:",	"%V",
	"    Pages:",	"%P",
	"Publisher:",	"%I",
	"     City:",	"%C",
	"     Date:",	"%D",
	"    Other:",	"%O",
	" Keywords:",	"%K",	};

int entries = 10;	/* total number of entries in bibskel */
int abstract = 1;	/* asking for abstracts is the default */

static void addbib(FILE *, char *);
void bibedit(FILE *, char *, char *);
static void instruct(void);
static void rd_skel(char *);
static void trim(char []);

static void
usage(void)			/* print proper usage and exit */
{
	puts(gettext("Usage:  addbib [-p promptfile] [-a] database\n\
\t-p: the promptfile defines alternate fields\n\
\t-a: don't include prompting for the abstract\n"));
	exit(1);
}

int
main(int argc, char *argv[])	/* addbib: bibliography entry program */
{
	FILE *fp, *fopen();
	int i;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1) {
		puts(gettext(
		    "You must specify a bibliography file (database)."));
		usage();
	}
	for (i = 1; argv[i][0] == '-'; i++) {
		if (argv[i][1] == 'p') {
			if (i >= argc - 2) {
				puts(gettext("Not enough arguments for "
				    "-p option."));
				usage();
			}
			rd_skel(argv[++i]);
		} else if (argv[i][1] == 'a') {
			if (i >= argc - 1) {
				puts(gettext(
				    "No bibliofile specified after -a."));
				usage();
			}
			abstract = 0;
		} else {	/* neither -p nor -a */
			printf(gettext(
			    "Invalid command line flag: %s\n"), argv[i]);
			usage();
		}
	}
	if (i < argc - 1) {
		puts(gettext("Too many arguments with no options."));
		usage();
	}
	if ((fp = fopen(argv[i], "a")) == NULL) {
		perror(argv[i]);
		exit(1);
	}
	addbib(fp, argv[i]);	/* loop for input */
	return (0);
}

static void
addbib(FILE *fp, char *argv)	/* add entries to a bibliographic database */
{
	char line[BUFSIZ];
	int i = 0, firstln, repeat = 0, escape = 0;

	printf(gettext("Instructions? "));
	fgets(line, BUFSIZ, stdin);
	if (line[0] == 'y' || line[0] == 'Y')
		instruct();
	while (1) {
		putchar('\n');
		putc('\n', fp);
		for (i = 0; i < entries; i++) {
			printf("%s\t", gettext(bibskel[i].prompt));
			if (fgets(line, BUFSIZ, stdin) == NULL) {
				clearerr(stdin);
				break;
			}
			if (line[0] == '-' && line[1] == '\n') {
				i -= 2;
				if (i < -1) {
					printf(gettext("Too far back.\n"));
					i++;
				}
				continue;
			} else if (line[strlen(line)-2] == '\\') {
				if (line[0] != '\\') {
					line[strlen(line)-2] = '\n';
					line[strlen(line)-1] = '\0';
					trim(line);
					fprintf(fp, "%s %s",
					    bibskel[i].keylet, line);
				}
				printf("> ");
				again:
				fgets(line, BUFSIZ, stdin);
				if (line[strlen(line)-2] == '\\') {
					line[strlen(line)-2] = '\n';
					line[strlen(line)-1] = '\0';
					trim(line);
					fputs(line, fp);
					printf("> ");
					goto again;
				}
				trim(line);
				fputs(line, fp);
			} else if (line[0] != '\n') {
				trim(line);
				fprintf(fp, "%s %s", bibskel[i].keylet, line);
			}
		}
		if (abstract) {
			puts(gettext(" Abstract: (ctrl-d to end)"));
			firstln = 1;
			while (fgets(line, BUFSIZ, stdin)) {
				if (firstln && line[0] != '%') {
					fprintf(fp, "%%X ");
					firstln = 0;
				}
				fputs(line, fp);
			}
			clearerr(stdin);
		}
		fflush(fp);	/* write to file at end of each cycle */
		if (ferror(fp)) {
			perror(argv);
			exit(1);
		}
		editloop:
		printf(gettext("\nContinue? "));
			fgets(line, BUFSIZ, stdin);
		if (line[0] == 'e' || line[0] == 'v') {
			bibedit(fp, line, argv);
			goto editloop;
		}
		if (line[0] == 'q' || line[0] == 'n')
			return;
	}
}

static void
trim(char line[])		/* trim line of trailing white space */
{
	int n;

	n = strlen(line);
	while (--n >= 0) {
		if (!isspace(line[n]))
			break;
	}
	line[++n] = '\n';
	line[++n] = '\0';
}

void
bibedit(FILE *fp, char *cmd, char *arg)	/* edit database with edit, ex, or vi */
{
	int i = 0, status;

	fclose(fp);
	while (!isspace(cmd[i]))
		i++;
	cmd[i] = '\0';
	if (fork() == 0) {
		if (cmd[0] == 'v' && cmd[1] == 'i')
			execlp(cmd, cmd, "+$", arg, NULL);
		else /* either ed, ex, or edit */
			execlp(cmd, cmd, arg, NULL);
	}
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	wait(&status);
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	if ((fp = fopen(arg, "a")) == NULL) {
		perror(arg);
		exit(1);
	}
}

static void
instruct(void)		/* give user elementary directions */
{
	putchar('\n');
	puts(gettext(
	    "Addbib will prompt you for various bibliographic fields.\n"
"If you don't need a particular field, just hit RETURN,\n"
"\tand that field will not appear in the output file.\n"
"If you want to return to previous fields in the skeleton,\n"
"\ta single minus sign will go back a field at a time.\n"
"\t(This is the best way to input multiple authors.)\n"
"If you have to continue a field or add an unusual field,\n"
"\ta trailing backslash will allow a temporary escape.\n"
"Finally, (without -a) you will be prompted for an abstract\n"
"Type in as many lines as you need, and end with a ctrl-d.\n"
"To quit, type `q' or `n' when asked if you want to continue.\n"
"To edit the database, type `edit', `vi', or `ex' instead."));

}

static void
rd_skel(char *arg)		/* redo bibskel from user-supplied file */
{
	FILE *pfp, *fopen();
	char str[BUFSIZ];
	int entry, i, j;

	if ((pfp = fopen(arg, "r")) == NULL) {
		fprintf(stderr, gettext("Promptfile "));
		perror(arg);
		exit(1);
	}
	for (entry = 0; fgets(str, BUFSIZ, pfp); entry++) {
		for (i = 0; str[i] != '\t' && str[i] != '\n'; i++)
			bibskel[entry].prompt[i] = str[i];
		bibskel[entry].prompt[i] = '\0';
		if (str[i] == '\n') {
			fprintf(stderr, gettext(
			    "No tabs between promptfile fields.\n"));
			fprintf(stderr, gettext(
			    "Format: prompt-string <TAB> %%key\n"));
			exit(1);
		}
		for (i++, j = 0; str[i] != '\n'; i++, j++)
			bibskel[entry].keylet[j] = str[i];
		bibskel[entry].keylet[j] = '\0';

		if (entry >= MAXENT) {
			fprintf(stderr, gettext(
			    "Too many entries in promptfile.\n"));
			exit(1);
		}
	}
	entries = entry;
	fclose(pfp);
}
