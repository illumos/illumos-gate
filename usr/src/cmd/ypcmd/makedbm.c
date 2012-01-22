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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#undef NULL
#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/systeminfo.h>
#include <dlfcn.h>

#include "ypdefs.h"
#include "ypsym.h"
USE_YP_MASTER_NAME
USE_YP_LAST_MODIFIED
USE_YP_INPUT_FILE
USE_YP_OUTPUT_NAME
USE_YP_DOMAIN_NAME
USE_YP_SECURE
USE_YP_INTERDOMAIN
USE_DBM

#ifdef SYSVCONFIG
extern void sysvconfig();
#endif
extern int yp_getalias();

#define	MAXLINE 4096		/* max length of input line */
#define	DEFAULT_SEP	" "
static char *get_date();
static char *any();
static void addpair();
static void unmake();
static void usage();

int   inode_dev_valid = 0;
ino64_t inode;
dev_t dev;

/*
 * Interpose close(2) to enable us to keep one of the output
 * files open until process exit.
 */
#pragma weak _close = close
int
close(int filedes) {

	struct stat64	sb;
	static int	(*fptr)() = 0;

	if (fptr == 0) {
		fptr = (int (*)())dlsym(RTLD_NEXT, "close");
		if (fptr == 0) {
			fprintf(stderr, "makedbm: dlopen(close): %s\n",
				dlerror());
			errno = ELIBACC;
			return (-1);
		}
	}

	if (inode_dev_valid != 0 && fstat64(filedes, &sb) == 0) {
		if (sb.st_ino == inode && sb.st_dev == dev) {
			/* Keep open; pretend successful */
			return (0);
		}
	}

	return ((*fptr)(filedes));
}

int
main(argc, argv)
	int argc;
	char **argv;
{
	FILE *infp, *outfp;
	datum key, content, tmp;
	char buf[MAXLINE];
	char pagbuf[MAXPATHLEN];
	char tmppagbuf[MAXPATHLEN];
	char dirbuf[MAXPATHLEN];
	char tmpdirbuf[MAXPATHLEN];
	char *p, ic;
	char *infile, *outfile;
	char outalias[MAXPATHLEN];
	char outaliasmap[MAXNAMLEN];
	char outaliasdomain[MAXNAMLEN];
	char *last_slash, *next_to_last_slash;
	char *infilename, *outfilename, *mastername, *domainname,
	    *interdomain_bind, *security, *lower_case_keys;
	char key_sep[] = DEFAULT_SEP;
	char local_host[MAX_MASTER_NAME];
	int cnt, i;
	DBM *fdb;
	struct stat64 statbuf;
	int num_del_to_match = 0;
	/* flag to indicate if matching char can be escaped */
	int count_esp = 0;

	/* Ignore existing umask, always force 077 (owner rw only) */
	umask(077);

	infile = outfile = NULL; /* where to get files */
	/* name to imbed in database */
	infilename = outfilename = mastername = domainname = interdomain_bind =
	    security = lower_case_keys = NULL;
	argv++;
	argc--;
	while (argc > 0) {
		if (argv[0][0] == '-' && argv[0][1]) {
			switch (argv[0][1]) {
				case 'i':
					infilename = argv[1];
					argv++;
					argc--;
					break;
				case 'o':
					outfilename = argv[1];
					argv++;
					argc--;
					break;
				case 'm':
					mastername = argv[1];
					argv++;
					argc--;
					break;
				case 'b':
					interdomain_bind = argv[0];
					break;
				case 'd':
					domainname = argv[1];
					argv++;
					argc--;
					break;
				case 'l':
					lower_case_keys = argv[0];
					break;
				case 's':
					security = argv[0];
					break;
				case 'S' :
					if (strlen(argv[1]) != 1) {
						fprintf(stderr,
							"bad separator\n");
						usage();
					}
					key_sep[0] = argv[1][0];
					argv++;
					argc--;
					break;
				case 'D' :
					num_del_to_match = atoi(argv[1]);
					argv++;
					argc--;
					break;
				case 'E' :
					count_esp = 1;
					break;
				case 'u':
					unmake(argv[1]);
					argv++;
					argc--;
					exit(0);
				default:
					usage();
			}
		} else if (infile == NULL)
			infile = argv[0];
		else if (outfile == NULL)
			outfile = argv[0];
		else
			usage();
		argv++;
		argc--;
	}
	if (infile == NULL || outfile == NULL)
		usage();

	/*
	 *  do alias mapping if necessary
	 */
	last_slash = strrchr(outfile, '/');
	if (last_slash) {
		*last_slash = '\0';
		next_to_last_slash = strrchr(outfile, '/');
		if (next_to_last_slash) *next_to_last_slash = '\0';
	} else next_to_last_slash = NULL;

#ifdef DEBUG
	if (last_slash) printf("last_slash=%s\n", last_slash+1);
	if (next_to_last_slash) printf("next_to_last_slash=%s\n",
		next_to_last_slash+1);
#endif /* DEBUG */

	/* reads in alias file for system v filename translation */
#ifdef SYSVCONFIG
	sysvconfig();
#endif

	if (last_slash && next_to_last_slash) {
		if (yp_getalias(last_slash+1, outaliasmap, MAXALIASLEN) < 0) {
			if ((int)strlen(last_slash+1) <= MAXALIASLEN)
				strcpy(outaliasmap, last_slash+1);
			else
				fprintf(stderr,
				    "makedbm: warning: no alias for %s\n",
				    last_slash+1);
		}
#ifdef DEBUG
		printf("%s\n", last_slash+1);
		printf("%s\n", outaliasmap);
#endif /* DEBUG */
		if (yp_getalias(next_to_last_slash+1, outaliasdomain,
		    NAME_MAX) < 0) {
			if ((int)strlen(last_slash+1) <= NAME_MAX)
				strcpy(outaliasdomain, next_to_last_slash+1);
			else
				fprintf(stderr,
				    "makedbm: warning: no alias for %s\n",
				    next_to_last_slash+1);
		}
#ifdef DEBUG
		printf("%s\n", next_to_last_slash+1);
		printf("%s\n", outaliasdomain);
#endif /* DEBUG */
		sprintf(outalias, "%s/%s/%s", outfile, outaliasdomain,
			outaliasmap);
#ifdef DEBUG
		printf("outlias=%s\n", outalias);
#endif /* DEBUG */

	} else if (last_slash) {
		if (yp_getalias(last_slash+1, outaliasmap, MAXALIASLEN) < 0) {
			if ((int)strlen(last_slash+1) <= MAXALIASLEN)
				strcpy(outaliasmap, last_slash+1);
			else
				fprintf(stderr,
				    "makedbm: warning: no alias for %s\n",
				    last_slash+1);
		}
		if (yp_getalias(outfile, outaliasdomain, NAME_MAX) < 0) {
			if ((int)strlen(outfile) <= NAME_MAX)
				strcpy(outaliasdomain, outfile);
			else
				fprintf(stderr,
				    "makedbm: warning: no alias for %s\n",
				    last_slash+1);
		}
		sprintf(outalias, "%s/%s", outaliasdomain, outaliasmap);
	} else {
		if (yp_getalias(outfile, outalias, MAXALIASLEN) < 0) {
			if ((int)strlen(last_slash+1) <= MAXALIASLEN)
				strcpy(outalias, outfile);
			else
				fprintf(stderr,
				    "makedbm: warning: no alias for %s\n",
				    outfile);
			}
	}
#ifdef DEBUG
	fprintf(stderr, "outalias=%s\n", outalias);
	fprintf(stderr, "outfile=%s\n", outfile);
#endif /* DEBUG */

	strcpy(tmppagbuf, outalias);
	strcat(tmppagbuf, ".tmp");
	strcpy(tmpdirbuf, tmppagbuf);
	strcat(tmpdirbuf, dbm_dir);
	strcat(tmppagbuf, dbm_pag);

	/* Loop until we can lock the tmpdirbuf file */
	for (;;) {

		if (strcmp(infile, "-") != 0)
			infp = fopen(infile, "r");
		else if (fstat64(fileno(stdin), &statbuf) == -1) {
			fprintf(stderr, "makedbm: can't open stdin\n");
			exit(1);
		} else
			infp = stdin;

		if (infp == NULL) {
			fprintf(stderr, "makedbm: can't open %s\n", infile);
			exit(1);
		}

		if ((outfp = fopen(tmpdirbuf, "w")) == (FILE *)NULL) {
			fprintf(stderr, "makedbm: can't create %s\n",
				tmpdirbuf);
			exit(1);
		}

		if (lockf(fileno(outfp), F_TLOCK, 0) == 0) {
			/* Got exclusive access; save inode and dev */
			if (fstat64(fileno(outfp), &statbuf) != 0) {
				fprintf(stderr, "makedbm: can't fstat ");
				perror(tmpdirbuf);
				exit(1);
			}
			inode		= statbuf.st_ino;
			dev		= statbuf.st_dev;
			inode_dev_valid	= 1;
			break;
		}

		if (errno != EAGAIN) {
			fprintf(stderr, "makedbm: can't lock ");
			perror(tmpdirbuf);
			exit(1);
		}

		/*
		 * Someone else is holding the lock.
		 * Close both output and input file
		 * (the latter to ensure consistency
		 * if the input file is updated while
		 * we're suspended), wait a little,
		 * and try again.
		 */
		if (infp != stdin)
			(void) fclose(infp);
		(void) fclose(outfp);
		sleep(1);
	}

	if (fopen(tmppagbuf, "w") == (FILE *)NULL) {
		fprintf(stderr, "makedbm: can't create %s\n", tmppagbuf);
		exit(1);
	}
	strcpy(dirbuf, outalias);
	strcat(dirbuf, ".tmp");
	if ((fdb = dbm_open(dirbuf, O_RDWR | O_CREAT, 0644)) == NULL) {
		fprintf(stderr, "makedbm: can't open %s\n", dirbuf);
		exit(1);
	}
	strcpy(dirbuf, outalias);
	strcpy(pagbuf, outalias);
	strcat(dirbuf, dbm_dir);
	strcat(pagbuf, dbm_pag);
	while (fgets(buf, sizeof (buf), infp) != NULL) {
		p = buf;
		cnt = strlen(buf) - 1; /* erase trailing newline */
		while (p[cnt-1] == '\\') {
			p += cnt-1;
			if (fgets(p, sizeof (buf)-(p-buf), infp) == NULL)
				goto breakout;
			cnt = strlen(p) - 1;
		}
		if (strcmp(key_sep, DEFAULT_SEP) == 0) {
			p = any(buf, " \t\n", num_del_to_match, count_esp);
		} else {
			p = any(buf, key_sep, num_del_to_match, count_esp);
		}
		key.dptr = buf;
		key.dsize = p - buf;
		for (;;) {
			if (p == NULL || *p == NULL) {
				fprintf(stderr,
	"makedbm: source files is garbage!\n");
				exit(1);
			}
			if (*p != ' ' && *p != '\t' && *p != key_sep[0])
				break;
			p++;
		}
		content.dptr = p;
		content.dsize = strlen(p) - 1; /* erase trailing newline */
		if (lower_case_keys) {
			for (i = (strncmp(key.dptr, "YP_MULTI_", 9) ? 0 : 9);
					i < key.dsize; i++) {

				ic = *(key.dptr+i);
				if (isascii(ic) && isupper(ic))
					*(key.dptr+i) = tolower(ic);
			}
		}
		tmp = dbm_fetch(fdb, key);
		if (tmp.dptr == NULL) {
			if (dbm_store(fdb, key, content, 1) != 0) {
				printf("problem storing %.*s %.*s\n",
				    key.dsize, key.dptr,
				    content.dsize, content.dptr);
				exit(1);
			}
		}
#ifdef DEBUG
		else {
			printf("duplicate: %.*s %.*s\n",
			    key.dsize, key.dptr,
			    content.dsize, content.dptr);
		}
#endif
	}
	breakout:
	addpair(fdb, yp_last_modified, get_date(infile));
	if (infilename)
		addpair(fdb, yp_input_file, infilename);
	if (outfilename)
		addpair(fdb, yp_output_file, outfilename);
	if (domainname)
		addpair(fdb, yp_domain_name, domainname);
	if (security)
		addpair(fdb, yp_secure, "");
	if (interdomain_bind)
	    addpair(fdb, yp_interdomain, "");
	if (!mastername) {
		sysinfo(SI_HOSTNAME, local_host, sizeof (local_host) - 1);
		mastername = local_host;
	}
	addpair(fdb, yp_master_name, mastername);
	(void) dbm_close(fdb);
#ifdef DEBUG
	fprintf(stderr, ".tmp ndbm map closed. ndbm successful !\n");
#endif
	if (rename(tmppagbuf, pagbuf) < 0) {
		perror("makedbm: rename");
		unlink(tmppagbuf);		/* Remove the tmp files */
		unlink(tmpdirbuf);
		exit(1);
	}
	if (rename(tmpdirbuf, dirbuf) < 0) {
		perror("makedbm: rename");
		unlink(tmppagbuf); /* Remove the tmp files */
		unlink(tmpdirbuf);
		exit(1);
	}
/*
 *	sprintf(buf, "mv %s %s", tmppagbuf, pagbuf);
 *	if (system(buf) < 0)
 *		perror("makedbm: rename");
 *	sprintf(buf, "mv %s %s", tmpdirbuf, dirbuf);
 *	if (system(buf) < 0)
 *		perror("makedbm: rename");
 */
	exit(0);
}


/*
 * scans cp, looking for a match with any character
 * in match.  Returns pointer to place in cp that matched
 * (or NULL if no match)
 *
 * It will find the num_del_to_match+1
 * matching character in the line.
 *
 * The backslash escapes a delimiter if count_esp==1
 * We don't count it as a character match if
 * an escape character precedes a matching character.
 *
 */
static char *
any(cp, match, num_del_to_match, count_esp)
	register char *cp;
	char *match;
	int num_del_to_match;
	int count_esp;
{
	register char *mp, c, prev_char;
	int num_del_matched;

	num_del_matched = 0;
	prev_char = ' ';
	while (c = *cp) {
		for (mp = match; *mp; mp++) {
			if (*mp == c) {
				if (!count_esp) {
					num_del_matched++;
				} else if (prev_char != '\\') {
					num_del_matched++;
				}
				if (num_del_matched > num_del_to_match)
					return (cp);
			}
		}
		prev_char = c;
		cp++;
	}
	return ((char *)0);
}

static char *
get_date(name)
	char *name;
{
	struct stat filestat;
	static char ans[MAX_ASCII_ORDER_NUMBER_LENGTH];
	/* ASCII numeric string */

	if (strcmp(name, "-") == 0)
		sprintf(ans, "%010ld", (long)time(0));
	else {
		if (stat(name, &filestat) < 0) {
			fprintf(stderr, "makedbm: can't stat %s\n", name);
			exit(1);
		}
		sprintf(ans, "%010ld", (long)filestat.st_mtime);
	}
	return (ans);
}

void
usage()
{
	fprintf(stderr,
"usage: makedbm -u file\n	makedbm [-b] [-l] [-s] [-i YP_INPUT_FILE] "
	    "[-o YP_OUTPUT_FILE] [-d YP_DOMAIN_NAME] [-m YP_MASTER_NAME] "
	    "[-S DELIMITER] [-D NUM_DELIMITER_TO_SKIP] [-E] "
	    "infile outfile\n");
	exit(1);
}

void
addpair(fdb, str1, str2)
DBM *fdb;
char *str1, *str2;
{
	datum key;
	datum content;

	key.dptr = str1;
	key.dsize = strlen(str1);
	content.dptr  = str2;
	content.dsize = strlen(str2);
	if (dbm_store(fdb, key, content, 1) != 0) {
		printf("makedbm: problem storing %.*s %.*s\n",
		    key.dsize, key.dptr, content.dsize, content.dptr);
		exit(1);
	}
}

void
unmake(file)
	char *file;
{
	datum key, content;
	DBM *fdb;

	if (file == NULL)
		usage();

	if ((fdb = dbm_open(file, O_RDONLY, 0644)) == NULL) {
		fprintf(stderr, "makedbm: couldn't open %s dbm file\n", file);
		exit(1);
	}

	for (key = dbm_firstkey(fdb); key.dptr != NULL;
		key = dbm_nextkey(fdb)) {
		content = dbm_fetch(fdb, key);
		printf("%.*s %.*s\n", key.dsize, key.dptr,
		    content.dsize, content.dptr);
	}

	dbm_close(fdb);
}
