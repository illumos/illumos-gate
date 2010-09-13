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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

#define	MAIN	1
#include "rules.h"
#include "elfrd.h"

int verbose = 0;
struct libpath *libp, libp_hd;

int
main(int argc, char **argv)
{
	int prtfn();
	int packfn();
	int unpackfn();
	int inquirefn();
	FILE *open_rulesfile();
	FILE *rfd;
	int c;
	int fflag = 0;
	int Bflag = 0;
	int index;
	char *rulesfile;
	int typearg = 0;
	int (*wrkfunc)();
	extern char *optarg;
	extern int optind, opterr;
	extern void bld_pack_list();
	extern void usage();

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	global_flags = LF_NULL;

	rfd = open_rulesfile();

	libp = &libp_hd;
	get_libsrch_path(libp);

	/* create hash table for tracking libraries */
	if (hcreate(10000) == 0) {
		/* unlikely this ever happens or I would work around it */
		fprintf(stderr,
		    gettext("cachefspack: can't create hash table\n"));
		exit(1);
	}

	while ((c = getopt(argc, argv, "df:hiprsuvB:I:L:U:")) != -1) {
		switch (c) {
		case 'd':
			wrkfunc = prtfn;
			typearg++;
			break;
		case 'f':
			fflag++;
			rulesfile = strdup(optarg);
			break;
		case 'h':
			usage();
			exit(0);
			break;
		case 'i':
			wrkfunc = inquirefn;
			typearg++;
			break;
		case 'p':
			wrkfunc = packfn;
			typearg++;
			break;
		case 'r':
			global_flags |= LF_REGEX;
			break;
		case 's':
			global_flags |= LF_STRIP_DOTSLASH;
			break;
		case 'u':
			wrkfunc = unpackfn;
			typearg++;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'B':
			Bflag++;
			fprintf(rfd, "BASE %s\n", optarg);
			break;
		case 'I':
			fprintf(rfd, "IGNORE %s\n", optarg);
			break;
		case 'L':
			fprintf(rfd, "LIST %s\n", optarg);
			break;
		case 'U':
			typearg++;
			wrkfunc = unpackfn;
			bld_pack_list(rfd, optarg);
			break;
		default:
			usage();
			exit(1);
		}
	}

	def_lign_flags = LF_NULL;
	def_gign_flags = LF_NULL;
	def_list_flags = LF_REGEX;
	bang_list_flags = LF_STRIP_DOTSLASH;
	if (global_flags != 0) {
		def_list_flags = global_flags;
		bang_list_flags = global_flags;
	}

	if (fflag & Bflag) {
		fprintf(stderr, gettext(
		    "cachefspack: B and f options are mutually exclusive\n"));
		exit(1);
	}

	if (fflag) {
		fclose(rfd);
		rfd = fopen(rulesfile, "r");
		if (rfd == NULL) {
			fprintf(stderr, gettext(
			    "cachefspack: can't open file associated"
			    " with -f\n"));
			exit(1);
		}
	}

	if (typearg != 1) {
		if (typearg == 0) {
			wrkfunc = packfn;
		} else {
			fprintf(stderr,
			    gettext(
			    "cachefspack: only one 'd', 'i', 'p' or 'u' "));
			fprintf(stderr,
			    gettext(" option allowed\n"));
			exit(1);
		}
	}
	if (optind < argc) {
		if (fflag || Bflag) {
			fprintf(stderr,
			    gettext(
			    "cachefspack: 'B' or 'f' specified "));
			fprintf(stderr,
			    gettext("with filenames\n"));
			exit(1);
		}
		for (index = optind; index < argc; index++) {
#ifdef  DEBUG
			printf("argv[%d] = %s\n", index, argv[index]);
#endif /* DEBUG */
			bld_pack_list(rfd, argv[index]);
		}
	}
	rewind(rfd);
	read_rules(rfd, wrkfunc);
	fclose(rfd);
	return (0);
}

/*
 * The bld_pack_list() function is used to write the temporary packing
 * list function. When the BASE directory changes, a new BASE command is
 * generated. If the  filename argument(fnam) starts with a '/', then the
 * filename is assumed to be an absolute pathname. Otherwise, the filename
 * is assumed to be realtive to the current directory.
 */
void
bld_pack_list(FILE *fd, char *filename)
{
	static char last_base[MAXPATHLEN+1] = {" "};
	static char fnam[MAXPATHLEN+1];
	static int last_base_sz = 1;
	char *lastsl_pos;
	int sz;
	int endpos;
	char *cwd;

	/* strip off any trailing /'s */
	strcpy(fnam, filename);
	for (endpos = strlen(fnam) - 1; endpos > 0; endpos--) {
		if (fnam[endpos] == '/')
			fnam[endpos] = '\0';
		else
			break;
	}

	if (*fnam == '/') {	/* absolute pathname */
		lastsl_pos = strrchr(fnam, '/');
		sz = (int)lastsl_pos - (int)fnam + 1;
		if ((last_base_sz != sz) ||
		    (strncmp(last_base, fnam, sz) != 0)) {
			fprintf(fd, "BASE %.*s\n", (sz <= 1 ? sz : sz-1), fnam);
			last_base_sz = sz;
			strncpy(last_base, fnam, sz);
		}
		fprintf(fd, "LIST %s\n", &fnam[sz]);
	} else {		/* relative pathname */
		/* Really only need to call this once, ... */
		cwd = getcwd(NULL, MAXPATHLEN+1);
		sz = strlen(cwd);
		if ((last_base_sz != sz) ||
		    (strncmp(last_base, cwd, sz) != 0)) {
			fprintf(fd, "BASE %s\n", cwd);
			last_base_sz = sz;
			strncpy(last_base, cwd, sz);
		}
		free(cwd);
		fprintf(fd, "LIST %s\n", fnam);
	}
}

void
usage()
{
#ifdef  DEBUG
	printf(
	    gettext("cachefspack -[dipu] -[fBIL] [-h] [-r] [-s] [-U dir]"));
#else  /* DEBUG */
	printf(
	    gettext("cachefspack -[dipu] -[f] [-h] [-r] [-s] [-U dir]"));
#endif /* DEBUG */
	printf(gettext(" [files]\n"));
	printf("\n");
	printf(
	    gettext("Must select 1 and only 1 of the following 5 options\n"));
	printf(gettext("-d Display selected filenames\n"));
	printf(gettext("-i Display selected filenames packing status\n"));
	printf(gettext("-p Pack selected filenames\n"));
	printf(gettext("-u Unpack selected filenames\n"));
	printf(gettext("-U Unpack all files in directory 'dir'\n"));
	printf(gettext("\n"));
	printf(gettext("-f Specify input file containing rules\n"));
#ifdef  DEBUG
	printf(gettext("-B Specify BASE rule on command line\n"));
	printf(gettext("-I Specify IGNORE rule on command line\n"));
	printf(gettext("-L Specify LIST rule on command line\n"));
	printf(gettext("\n"));
#endif /* DEBUG */
	printf(gettext("-h Print usage information\n"));
	printf(gettext(
	    "-r Interpret strings in LIST rules as regular expressions\n"));
	printf(gettext("-s Strip './' from the beginning of a pattern name\n"));
	printf(gettext("-v Verbose option\n"));
	printf(gettext("files - a list of filenames to be packed/unpacked\n"));
}
