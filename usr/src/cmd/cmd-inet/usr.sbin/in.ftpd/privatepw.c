#pragma ident	"%Z%%M%	%I%	%E% SMI"

/**************************************************************************** 

   Copyright (c) 1999,2000 WU-FTPD Development Group. 
   All rights reserved.
   
   Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994 
   The Regents of the University of California.  Portions Copyright (c) 
   1993, 1994 Washington University in Saint Louis.  Portions Copyright 
   (c) 1996, 1998 Berkeley Software Design, Inc.  Portions Copyright (c) 
   1998 Sendmail, Inc.  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric 
   P. Allman.  Portions Copyright (c) 1989 Massachusetts Institute of 
   Technology.  Portions Copyright (c) 1997 by Stan Barber.  Portions 
   Copyright (C) 1991, 1992, 1993, 1994, 1995, 1996, 1997 Free Software 
   Foundation, Inc.  Portions Copyright (c) 1997 by Kent Landfield. 
 
   Use and distribution of this software and its source code are governed 
   by the terms and conditions of the WU-FTPD Software License ("LICENSE"). 
 
   $Id: privatepw.c,v 1.10 2000/07/01 18:43:59 wuftpd Exp $
 
****************************************************************************/
/*
   Subsystem:  WU-FTPD FTP Server
   Purpose:    Change WU-FTPD Guest Passwords
   File Name:  privatepw.c               

   usage: privatepw [-c] [-f passwordfile] [-g group] accessgroup
   privatepw [-d] [-f passwordfile] accessgroup
   privatepw [-l] [-f passwordfile] 
   -c:           creates a new file.
   -d:           deletes specified accessgroup.
   -l:           list contents of ftpgroups file.
   -f ftpgroups: updates the specified file.
   -g group:     set real group to the specified group.

   This software was initially written by Kent Landfield (kent@landfield.com)
 */

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <grp.h>
#include <unistd.h>
#include "config.h"
#include "pathnames.h"

#define BUFLEN 256
#define GROUPLEN 8

char *tmp;
char line[BUFLEN];
FILE *fp;
int verbose = 0;

static unsigned char itoa64[] =	/* 0 ... 63 => ascii - 64 */
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void print_copyright(void);

static void usage(void)
{
    fprintf(stderr, "usage: privatepw [-c] [-f ftpgroups] [-g group] accessgroup\n");
    fprintf(stderr, "       privatepw [-d] [-f ftpgroups] accessgroup\n");
    fprintf(stderr, "       privatepw [-l] [-f ftpgroups]\n");
    fprintf(stderr, "\t\t-c:           creates a new file.\n");
    fprintf(stderr, "\t\t-d:           deletes specified accessgroup.\n");
    fprintf(stderr, "\t\t-l:           list contents of ftpgroups file.\n");
    fprintf(stderr, "\t\t-f ftpgroups: updates the specified file.\n");
    fprintf(stderr, "\t\t-g group:     set real group to the specified group.\n");
    exit(1);
}

static void to64(register char *s, register long v, register int n)
{
    while (--n >= 0) {
	*s++ = itoa64[v & 0x3f];
	v >>= 6;
    }
}

static void terminate(void)
{
    if (tmp)
	unlink(tmp);
    exit(1);
}

static void catchintr(void)
{
    fprintf(stderr, "Interrupted.\n");
    terminate();
}

static char *savit(char *s)
{
    char *d;

    if ((d = (char *) malloc(strlen(s) + 1)) == NULL) {
	fprintf(stderr, "Whoa... Malloc failed.\n");
	terminate();
    }
    strcpy(d, s);
    return (d);
}

static int confirmed(char *accessgroup)
{
    register int ch;

    printf("Delete %s: Are your sure ? (y/n) ", accessgroup);
    ch = getc(stdin);
    if (ch == 'y')
	return (1);
    return (0);
}

static char *getgroup(char *msg)
{
    register int ch;
    register char *p;
    static char buf[GROUPLEN + 1];

    fputs(msg, stderr);
    rewind(stderr);		/* implied flush */
    for (p = buf; (ch = getc(stdin)) != EOF && ch != '\n';)
	if (p < buf + GROUPLEN)
	    *p++ = ch;
    *p = '\0';

    if (getgrnam(buf) == NULL) {
	fprintf(stderr, "Invalid group \'%s\' specified\n", buf);
	terminate();
    }
    return (buf);
}

static void addrecord(char *accessgroup, char *sysgroup, char *msg, FILE *f)
{
    char *pw, *cpw, salt[3];
#ifndef NO_CRYPT_PROTO
    extern char *crypt(const char *, const char *);
#endif
    char *getpass(const char *prompt);

    printf("%s %s\n", msg, accessgroup);

    if (sysgroup[0] == '\0')
	strcpy(sysgroup, getgroup("Real System Group to use: "));

    pw = savit((char *) getpass("New password: "));
    if (strcmp(pw, (char *) getpass("Re-type new password: "))) {
	fprintf(stderr, "They don't match, sorry.\n");
	if (tmp)
	    unlink(tmp);
	exit(1);
    }

    srand((int) time((time_t *) NULL));
    to64(&salt[0], rand(), 2);
    cpw = crypt(pw, salt);
    free(pw);
    fprintf(f, "%s:%s:%s\n", accessgroup, cpw, sysgroup);
}

static void list_privatefile(char *privatefile)
{
    if (verbose)
	fprintf(stderr, "Private File: %s file.\n", privatefile);

    if ((fp = fopen(privatefile, "r")) == NULL) {
	fprintf(stderr, "Could not open %s file.\n", privatefile);
	exit(1);
    }

    printf("\nWU-FTPD Private file: %s\n", privatefile);
    printf("accessgroup : password : system group\n");
    printf("-------\n");

    while (fgets(line, BUFLEN, fp) != NULL)
	fputs(line, stdout);
    printf("-------\n");
}

int main(int argc, char **argv)
{
    extern void (*signal(int sig, void (*disp) (int))) (int);
    extern int getopt(int argc, char *const *argv, const char *optstring);
    extern char *optarg;
    extern int optind;
    extern int opterr;

    struct stat stbuf;

    char realgroup[BUFLEN];
    char *passwdpath;
    char *cp;

    char accessgroup[BUFLEN];
    char w[BUFLEN];
    char command[BUFLEN];

    int create;
    int delete;
    int list;
    int found;
    int lineno;
    int c;

    FILE *tfp;

#ifdef HAVE_MKSTEMP
    char tmpname[BUFLEN];
    int tfd;
#endif

    opterr = 0;
    create = 0;
    delete = 0;
    list = 0;

    tmp = NULL;
    realgroup[0] = '\0';

    passwdpath = _PATH_PRIVATE;

    if (argc == 1)
	usage();

    while ((c = getopt(argc, argv, "Vvcdf:g:l")) != EOF) {
	switch (c) {
	case 'd':
	    delete++;
	    break;
	case 'c':
	    create++;
	    break;
	case 'f':
	    passwdpath = optarg;
	    break;
	case 'g':
	    strcpy(realgroup, optarg);
	    if (getgrnam(realgroup) == NULL) {
		fprintf(stderr, "Invalid group \'%s\' specified\n", realgroup);
		return (1);
	    }
	    break;
	case 'l':
	    list++;
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'V':
	    print_copyright();
	    return (0);
	    /* NOTREACHED */
	default:
	    usage();
	}
    }

    if (list) {
	list_privatefile(passwdpath);
	return (0);
    }

    if (optind >= argc) {
	fprintf(stderr, "Need to specify an accessgroup name.\n");
	usage();
    }

    signal(SIGINT, (void (*)()) catchintr);

    strcpy(accessgroup, argv[optind]);

    if (create) {
	if (stat(passwdpath, &stbuf) == 0) {
	    fprintf(stderr, "%s exists, cannot create it.\n", passwdpath);
	    fprintf(stderr, "Remove -c option or use the -f option to specify another.\n");
	    return (1);
	}

	if ((tfp = fopen(passwdpath, "w")) == NULL) {
	    fprintf(stderr, "Could not open \"%s\" for writing.\n", passwdpath);
	    perror("fopen");
	    return (1);
	}

	tmp = passwdpath;

	printf("Creating WU-FTPD Private file: %s\n", passwdpath);
	addrecord(accessgroup, realgroup, "Adding accessgroup", tfp);

	fclose(tfp);
	return (0);
    }

#ifdef HAVE_MKSTEMP
    strcpy (tmpname, "/tmp/privatepwXXXXXX");
    tmp = tmpname;
    if ((tfd = mkstemp(tmp)) < 0) {
	fprintf(stderr, "Could not open temp file.\n");
	return (1);
    }

    if ((tfp = fdopen(tfd, "w")) == NULL) {
	unlink(tmp);
	fprintf(stderr, "Could not open temp file.\n");
	return (1);
    }
#else
    tmp = tmpnam(NULL);

    if ((tfp = fopen(tmp, "w")) == NULL) {
	fprintf(stderr, "Could not open temp file.\n");
	return (1);
    }
#endif

    if ((fp = fopen(passwdpath, "r")) == NULL) {
	fprintf(stderr, "Could not open %s file.\n", passwdpath);
	fprintf(stderr, "Use -c option to create new one.\n");
	return (1);
    }

    lineno = 0;
    found = 0;

    while (fgets(line, BUFLEN, fp) != NULL) {
	lineno++;

	if (found || (line[0] == '#') || (!line[0])) {
	    fputs(line, tfp);
	    continue;
	}

	strcpy(w, line);

	if ((cp = strchr(w, ':')) == NULL) {
	    fprintf(stderr, "%s: line %d: invalid record format.\n", passwdpath, lineno);
	    continue;
	}
	*cp++ = '\0';

	if ((cp = strchr(cp, ':')) == NULL) {
	    fprintf(stderr, "%s: line %d: invalid record format.\n", passwdpath, lineno);
	    continue;
	}
	*cp++ = '\0';

	if (strcmp(accessgroup, w)) {
	    fputs(line, tfp);
	    continue;
	}
	else {
	    if (delete) {
		if (!confirmed(accessgroup))
		    terminate();
	    }
	    else {
		if (realgroup[0] == '\0') {
		    strcpy(realgroup, cp);
		    if ((cp = strchr(realgroup, '\n')) != NULL)
			*cp = '\0';
		}
		addrecord(accessgroup, realgroup, "Updating accessgroup", tfp);
	    }
	    found = 1;
	}
    }

    if (!found && !delete)
	addrecord(accessgroup, realgroup, "Adding accessgroup", tfp);
    else if (!found && delete) {
	fprintf(stderr, "%s not found in %s.\n", accessgroup, passwdpath);
	terminate();
    }

    fclose(fp);
    fclose(tfp);

    sprintf(command, "cp %s %s", tmp, passwdpath);
    system(command);
    unlink(tmp);
    return (0);
}
