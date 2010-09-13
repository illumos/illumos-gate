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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
	news foo	prints /var/news/foo
	news -a		prints all news items, latest first
	news -n		lists names of new items
	news -s		tells count of new items only
	news		prints items changed since last news
*/

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <signal.h>
#include <dirent.h>
#include <pwd.h>
#include <time.h>
#include <locale.h>

#define INDENT 3
#define	RD_WR_ALL	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)

#define	DATE_FMT	"%a %b %e %H:%M:%S %Y"
/*
 *	%a	abbreviated weekday name
 *	%b	abbreviated month name
 *	%e	day of month
 *	%H	hour (24-hour clock)
 *	%M	minute
 *	%S	second
 *	%Y	year
 */
/*
	The following items should not be printed.
*/
char	*ignore[] = {
		"core",
		NULL
};

struct n_file {
	long n_time;
	char n_name[MAXNAMLEN];
} *n_list;

char	NEWS[] = "/var/news";	/* directory for news items */

int	aopt = 0;	/* 1 say -a specified */
int	n_count;	/* number of items in NEWS directory */
int	number_read;	/* number of items read */
int	nopt = 0;	/* 1 say -n specified */
int	optsw;		/* for getopt */
int	opt = 0;	/* number of options specified */
int	sopt = 0;	/* 1 says -s specified */
char	stdbuf[BUFSIZ];
char	time_buf[50];	/* holds date and time string */

jmp_buf	save_addr;

void all_news(void);
int ck_num(void);
void count(char *);
void initialize(void);
void late_news(void(*)(), int);
void notify(char *);
void print_item(char *);
void read_dir(void);

int
main(int argc, char **argv)
{
	int i;

	(void)setlocale(LC_ALL, "");
	setbuf (stdout, stdbuf);
	initialize();
	read_dir();

	if (argc <= 1) {
		late_news (print_item, 1);
		ck_num();
	}
	else while ((optsw = getopt(argc, argv, "ans")) != EOF)
		switch(optsw) {
		case 'a':
			aopt++;
			opt++;
			break;

		case 'n':
			nopt++;
			opt++;
			break;

		case 's':
			sopt++;
			opt++;
			break;

		default:
			fprintf (stderr, "usage: news [-a] [-n] [-s] [items]\n");
			exit (1);
	}

        if (opt > 1) {
        	fprintf(stderr, "news: options are mutually exclusive\n");
        	exit(1);
	}

        if (opt > 0 && argc > 2) {
        	fprintf(stderr, "news: options are not allowed with file names\n");
        	exit(1);
	}

	if (aopt) {
		all_news();
		ck_num();
		exit(0);
	}

	if (nopt) {
		late_news (notify, 0);
		ck_num();
		exit(0);
	}

	if (sopt) {
		late_news (count, 0);
		exit(0);
	}

	for (i=1; i<argc; i++) print_item (argv[i]);

	return (0);
}

/*
 *	read_dir: get the file names and modification dates for the
 *	files in /var/news into n_list; sort them in reverse by
 *	modification date. We assume /var/news is the working directory.
 */

void
read_dir(void)
{
	struct dirent *nf, *readdir();
	struct stat sbuf;
	char fname[MAXNAMLEN];
	DIR *dirp;
	int i, j;

	/* Open the current directory */
	if ((dirp = opendir(".")) == NULL) {
		fprintf (stderr, "Cannot open %s\n", NEWS);
		exit (1);
	}

	/* Read the file names into n_list */
	n_count = 0;
	while (nf = readdir(dirp)) {
		strncpy (fname, nf->d_name, (unsigned) strlen(nf->d_name) + 1);
		if (nf->d_ino != (ino_t)0 && stat (fname, &sbuf) >= 0
		 && (sbuf.st_mode & S_IFMT) == S_IFREG) {
			register char **p;
			p = ignore;
			while (*p && strncmp (*p, nf->d_name, MAXNAMLEN))
				++p;
			if (!*p) {
				if (n_count++ > 0)
					n_list = (struct n_file *)
						realloc ((char *) n_list,
						(unsigned)
						(sizeof (struct n_file)
						    * n_count));
				else
					n_list = (struct n_file *) malloc
						((unsigned)
						(sizeof (struct n_file) *
						n_count));
				if (n_list == NULL) {
					fprintf (stderr, "No storage\n");
					exit (1);
				}
				n_list[n_count-1].n_time = sbuf.st_mtime;
				strncpy (n_list[n_count-1].n_name,
					nf->d_name, MAXNAMLEN);
			}
		}
	}

	/* Sort the elements of n_list in decreasing time order */
	for (i=1; i<n_count; i++)
		for (j=0; j<i; j++)
			if (n_list[j].n_time < n_list[i].n_time) {
				struct n_file temp;
				temp = n_list[i];
				n_list[i] = n_list[j];
				n_list[j] = temp;
			}

	/* Clean up */
	closedir(dirp);
}

void
initialize(void)
{
	if (signal (SIGQUIT, SIG_IGN) != (void(*)())SIG_IGN)
		signal (SIGQUIT, _exit);
	umask (((~(S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)) & S_IAMB));
	if (chdir (NEWS) < 0) {
		fprintf (stderr, "Cannot chdir to %s\n", NEWS);
		exit (1);
	}
}

void
all_news(void)
{
	int i;

	for (i=0; i<n_count; i++)
		print_item (n_list[i].n_name);
}

void
print_item(char *f)
{
	FILE *fd;
	char fname[MAXNAMLEN+1];
	static int firstitem = 1;
	void onintr();
	struct passwd *getpwuid();

	if (f == NULL) {
		return;
	}
	strncpy (fname, f, MAXNAMLEN);
	fname[MAXNAMLEN] = '\0';
	if ((fd = fopen (fname, "r")) == NULL)
		printf ("Cannot open %s/%s\n", NEWS, fname);
	else {
		register int c, ip, op;
		struct stat sbuf;
		struct passwd *pw;

		fstat (fileno (fd), &sbuf);
		if (firstitem) {
			firstitem = 0;
			putchar ('\n');
		}
		if (setjmp(save_addr))
			goto finish;
		if (signal(SIGINT, SIG_IGN) != (void(*)())SIG_IGN)
			signal(SIGINT, onintr);
		printf ("%s ", fname);
		pw = getpwuid (sbuf.st_uid);
		if (pw)
			printf ("(%s)", pw->pw_name);
		else
			printf (".....");
		cftime(time_buf, DATE_FMT, &sbuf.st_mtime); 
		printf (" %s\n", time_buf);
		op = 0;
		ip = INDENT;
		while ((c = getc (fd)) != EOF) {
			switch (c) {

			case '\r':
			case '\n':
				putchar (c);
				op = 0;
				ip = INDENT;
				break;

			case ' ':
				ip++;
				break;

			case '\b':
				if (ip > INDENT)
					ip--;
				break;

			case '\t':
				ip = ((ip - INDENT + 8) & -8) + INDENT;
				break;

			default:
				while (ip < op) {
					putchar ('\b');
					op--;
				}
				while ((ip & -8) > (op & -8)) {
					putchar ('\t');
					op = (op + 8) & -8;
				}
				while (ip > op) {
					putchar (' ');
					op++;
				}
				putchar (c);
				ip++;
				op++;
				break;
			}
		}
		fflush (stdout);
finish:
		putchar ('\n');
		fclose (fd);
		number_read++;
		if (signal(SIGINT, SIG_IGN) != (void(*)())SIG_IGN)
			signal(SIGINT, SIG_DFL);
	}
}

void
late_news(void(*emit)(), int update)
{
	long cutoff;
	int i;
	char fname[50], *cp;
	struct stat newstime;
	int fd;
	struct {
		long actime, modtime;
	} utb;
	extern char *getenv();

	/* Determine the time when last called */
	cp = getenv ("HOME");
	if (cp == NULL) {
		fprintf (stderr, "Cannot find HOME variable\n");
		exit (1);
	}
	strcpy (fname, cp);
	strcat (fname, "/");
	strcat (fname, ".news_time");
	cutoff = stat (fname, &newstime) < 0? 0: newstime.st_mtime;

	/* Print the recent items */
	for (i=0; i<n_count && n_list[i].n_time > cutoff; i++) {
		(*emit) (n_list[i].n_name);
		number_read++;
	}
	(*emit) ((char *) NULL);
	fflush (stdout);

	if (update) {
		/* Re-create the file and refresh the update time */
		if (n_count > 0 && (fd = creat (fname, RD_WR_ALL)) >= 0) {
			utb.actime = utb.modtime = n_list[0].n_time;
			close (fd);
			utime (fname, &utb);
		}
	}
}

void
notify(char *s)
{
	static int first = 1;

	if (s) {
		if (first) {
			first = 0;
			printf ("news:", NEWS);
		}
		printf (" %.14s", s);
	} else if (!first)
		putchar ('\n');
}

/*ARGSUSED*/
void
count(char *s)
{
	static int nitems = 0;

	if (s)
		nitems++;
	else {
		if (nitems) {
			printf ("%d news item", nitems);
			if (nitems != 1)
				putchar ('s');
			printf (".\n");
		}
		else printf("No news.\n");
	}
}

void
onintr()
{
	sleep(2);
	longjmp(save_addr, 1);
}

int
ck_num(void)
{
	if (sopt && !number_read) printf("No news.\n");
	return(0);
}
