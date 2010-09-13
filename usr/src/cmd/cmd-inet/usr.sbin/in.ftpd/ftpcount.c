/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************  
 
  Copyright (c) 1999,2000 WU-FTPD Development Group.  
  All rights reserved.
  
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994
    The Regents of the University of California.
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.
  Portions Copyright (c) 1998 Sendmail, Inc.
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.
  Portions Copyright (c) 1997 by Stan Barber.
  Portions Copyright (c) 1997 by Kent Landfield.
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997
    Free Software Foundation, Inc.  
 
  Use and distribution of this software and its source code are governed 
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 
  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.org/license.html.
 
  $Id: ftpcount.c,v 1.22 2000/07/01 18:17:39 wuftpd Exp $
 
****************************************************************************/
#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#if defined(VIRTUAL) && defined(INET6)
#include <netinet/in.h>
#endif

#include "pathnames.h"
#include "extensions.h"

#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif

#ifdef VIRTUAL
#define ARGS	"Vv"
#else
#define ARGS	"V"
#endif

struct c_list {
    char *class;
    struct c_list *next;
};

#ifdef VIRTUAL
extern int read_servers_line(FILE *, char *, size_t, char *, size_t);
#endif

void print_copyright(void);

char *progname;

/*************************************************************************/
/* FUNCTION  : parse_time                                                */
/* PURPOSE   : Check a single valid-time-string against the current time */
/*             and return whether or not a match occurs.                 */
/* ARGUMENTS : a pointer to the time-string                              */
/*************************************************************************/

static int parsetime(char *whattime)
{
    static char *days[] =
    {"Su", "Mo", "Tu", "We", "Th", "Fr", "Sa", "Wk"};
    time_t clock;
    struct tm *curtime;
    int wday, start, stop, ltime, validday, loop, match;

    (void) time(&clock);
    curtime = localtime(&clock);
    wday = curtime->tm_wday;
    validday = 0;
    match = 1;

    while (match && isalpha(*whattime) && isupper(*whattime)) {
	match = 0;
	for (loop = 0; loop < 8; loop++) {
	    if (strncmp(days[loop], whattime, 2) == 0) {
		whattime += 2;
		match = 1;
		if ((wday == loop) || ((loop == 7) && wday && (wday < 6)))
		    validday = 1;
	    }
	}
    }

    if (!validday) {
	if (strncmp(whattime, "Any", 3) == 0) {
	    validday = 1;
	    whattime += 3;
	}
	else
	    return (0);
    }

    if (sscanf(whattime, "%d-%d", &start, &stop) == 2) {
	ltime = curtime->tm_min + 100 * curtime->tm_hour;
	if ((start < stop) && ((ltime >= start) && ltime < stop))
	    return (1);
	if ((start > stop) && ((ltime >= start) || ltime < stop))
	    return (1);
    }
    else
	return (1);

    return (0);
}

/*************************************************************************/
/* FUNCTION  : validtime                                                 */
/* PURPOSE   : Break apart a set of valid time-strings and pass them to  */
/*             parse_time, returning whether or not ANY matches occurred */
/* ARGUMENTS : a pointer to the time-string                              */
/*************************************************************************/

static int validtime(char *ptr)
{
    char *nextptr;
    int good;

    while (1) {
	nextptr = strchr(ptr, '|');
	if (strchr(ptr, '|') == NULL)
	    return (parsetime(ptr));
	*nextptr = '\0';
	good = parsetime(ptr);
	*nextptr++ = '|';	/* gotta restore the | or things get skipped! */
	if (good)
	    return (1);
	ptr = nextptr;
    }
}

static int acl_getlimit(char *aclbuf, char *class)
{
    char *crptr, *ptr, linebuf[1024];
    int limit;

    while (*aclbuf != '\0') {
	if (strncasecmp(aclbuf, "limit", 5) == 0) {
	    for (crptr = aclbuf; *crptr++ != '\n';);
	    *--crptr = '\0';
	    (void) strlcpy(linebuf, aclbuf, sizeof(linebuf));
	    *crptr = '\n';
	    (void) strtok(linebuf, " \t");	/* returns "limit" */
	    if ((ptr = strtok(NULL, " \t")) && (strcmp(class, ptr) == 0)) {
		if ((ptr = strtok(NULL, " \t"))) {
		    limit = atoi(ptr);	/* returns limit <n> */
		    if ((ptr = strtok(NULL, " \t")) && validtime(ptr))
			return (limit);
		}
	    }
	}
	while (*aclbuf && *aclbuf++ != '\n');
    }

    return (-1);
}

/*************************************************************************/
/* FUNCTION  : lock_fd                                                   */
/* PURPOSE   : Lock a file.                                              */
/* ARGUMENTS : File descriptor of file to lock.                          */
/*************************************************************************/

static void lock_fd(int fd)
{
#ifndef HAVE_FLOCK
    struct flock arg;
#endif

#ifdef HAVE_FLOCK
    while (flock(fd, LOCK_SH)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: flock of pid file failed: %m");
#endif
#else
    arg.l_type = F_RDLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    while (-1 == fcntl(fd, F_SETLK, &arg)) {
#ifndef NO_PID_SLEEP_MSGS
	syslog(LOG_ERR, "sleeping: fcntl lock of pid file failed: %m");
#endif
#endif /* HAVE_FLOCK */
	sleep(1);
    }
#ifndef HAVE_FLOCK
#endif /* HAVE_FLOCK */
}

/*************************************************************************/
/* FUNCTION  : unlock_fd                                                 */
/* PURPOSE   : Unlock a file locked by lock_fd.                          */
/* ARGUMENTS : File descriptor of file to unlock.                        */
/*************************************************************************/

static void unlock_fd(int fd)
{
#ifndef HAVE_FLOCK
    struct flock arg;
#endif

#ifdef HAVE_FLOCK
    flock(fd, LOCK_UN);
#else
    arg.l_type = F_UNLCK;
    arg.l_whence = arg.l_start = arg.l_len = 0;
    fcntl(fd, F_SETLK, &arg);
#endif /* HAVE_FLOCK */
}

static int acl_countusers(char *class)
{
    int i, j, n, count, pidfd;
    pid_t procid;
    char pidfile[MAXPATHLEN];
    char line[1024];
    FILE *ZeFile;
    struct pidfile_header hdr;
    struct stat pinfo;
    unsigned char bits, *buf;

    snprintf(pidfile, sizeof(pidfile), _PATH_PIDNAMES, class);
    pidfd = open(pidfile, O_RDONLY);
    if (pidfd == -1) {
	return (0);
    }

    lock_fd(pidfd);
    if (read(pidfd, (void *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
	unlock_fd(pidfd);
	close(pidfd);
	return (0);
    }
    if (strcmp(progname, "ftpcount") == 0) {
	unlock_fd(pidfd);
	close(pidfd);
	return (hdr.count);
    }

    /*
     * Printing the process information can take a long time, and while we
     * hold the lock no users can join or leave this class. To minimize the
     * problem, read the whole PID file into memory then release the lock.
     */
    if (fstat(pidfd, &pinfo) != 0) {
	unlock_fd(pidfd);
	close(pidfd);
        return (0);
    }
    if ((buf = malloc((size_t)pinfo.st_size)) == NULL) {
	unlock_fd(pidfd);
	close(pidfd);
        return (0);
    }
    n = read(pidfd, buf, (size_t)pinfo.st_size);
    unlock_fd(pidfd);
    close(pidfd);
    count = 0;
    procid = 0;
    for (i = 0; i < n; i++) {
	if (buf[i] == 0) {
	    procid += CHAR_BIT;
	}
	else {
	    bits = 1;
	    for (j = 0; j < CHAR_BIT; j++) {
		if (((buf[i] & bits) != 0) &&
		    ((kill(procid, 0) == 0) || (errno == EPERM))) {
#if defined(SVR4)
#ifdef AIX
		    snprintf(line, sizeof(line), "/bin/ps %d", procid);
#elif defined(sun)
		    snprintf(line, sizeof(line), "/usr/ucb/ps auxww %ld", procid);
#else
#if defined (LINUX_BUT_NOT_REDHAT_6_0)
		    snprintf(line, sizeof(line), "/bin/ps axwww %d", procid);
#else
		    snprintf(line, sizeof(line), "/bin/ps -f -p %d", procid);
#endif
#endif
#elif defined(M_UNIX)
		    snprintf(line, sizeof(line), "/bin/ps -f -p %d", procid);
#else
		    snprintf(line, sizeof(line), "/bin/ps %d", procid);
#endif
		    ZeFile = popen(line, "r");
		    fgets(line, sizeof(line), ZeFile);
		    line[0] = '\0';
		    fgets(line, sizeof(line), ZeFile);
		    if (line[0] != '\0') {
			size_t i;
			for (i = strlen(line); (i > 0) && ((line[i - 1] == ' ') || (line[i - 1] == '\n')); --i)
			    line[i - 1] = '\0';
			printf("%s\n", line);
			count++;
		    }
		    pclose(ZeFile);
		}
		bits <<= 1;
		procid++;
	    }
	}
    }
    free(buf);
    return (count);
}

static void new_list(struct c_list **list)
{
    struct c_list *cp, *tcp;

    if (*list == NULL) {
	*list = (struct c_list *) malloc(sizeof(struct c_list));
	if (*list == NULL) {
	    perror("malloc error in new_list");
	    exit(1);
	}
    }
    else {
	cp = (*list)->next;
	while (cp) {
	    if (cp->class)
		free(cp->class);
	    tcp = cp;
	    cp = cp->next;
	    free(tcp);
	}
    }
    (*list)->next = NULL;
}

static int add_list(char *class, struct c_list **list)
{
    struct c_list *cp;

    for (cp = (*list)->next; cp; cp = cp->next) {
	if (!strcmp(cp->class, class))
	    return (-1);
    }

    cp = (struct c_list *) malloc(sizeof(struct c_list));
    if (cp == NULL) {
	perror("malloc error in add_list");
	exit(1);
    }

    cp->class = strdup(class);
    if (cp->class == NULL) {
	perror("malloc error in add_list");
	exit(1);
    }
    cp->next = (*list)->next;
    (*list)->next = cp;
    return (1);
}

static int display_info(char *ftpaccess, char *address)
{
    FILE *accessfile;
    char class[80], linebuf[1024], *aclbuf, *myaclbuf, *crptr;
    int limit;
    struct stat finfo;
    static struct c_list *list = NULL;

    if ((accessfile = fopen(ftpaccess, "r")) == NULL) {
	if (errno != ENOENT)
	    fprintf(stderr, "%s: could not open access file %s: %s\n",
		    progname, ftpaccess, strerror(errno));
	return (1);
    }
    if (fstat(fileno(accessfile), &finfo) != 0) {
	fprintf(stderr, "%s: could not fstat() access file %s: %s\n",
		progname, ftpaccess, strerror(errno));
	fclose(accessfile);
	return (1);
    }

    if (finfo.st_size == 0) {
	printf("%s: no service classes defined, no usage count kept\n", progname);
	fclose(accessfile);
	return (0);
    }
    else {
	if (!(aclbuf = (char *) malloc((size_t) finfo.st_size + 1))) {
	    fprintf(stderr, "%s: could not malloc aclbuf: %s\n",
		    progname, strerror(errno));
	    fclose(accessfile);
	    return (1);
	}
	fread(aclbuf, (size_t) finfo.st_size, 1, accessfile);
	fclose(accessfile);
	*(aclbuf + (size_t) finfo.st_size) = '\0';
    }

    (void) new_list(&list);
    myaclbuf = aclbuf;
    while (*myaclbuf != '\0') {
	if (strncasecmp(myaclbuf, "class", 5) == 0) {
	    for (crptr = myaclbuf; *crptr++ != '\n';);
	    *--crptr = '\0';
	    (void) strlcpy(linebuf, myaclbuf, sizeof(linebuf));
	    *crptr = '\n';
	    (void) strtok(linebuf, " \t");	/* returns "class" */
	    /* returns class name */
	    (void) strlcpy(class, strtok(NULL, " \t"), sizeof(class));
	    if ((add_list(class, &list)) < 0) {
		/* we have a class with multiple "class..." lines so, only
		 * display one count... */
		;
	    }
	    else {
		limit = acl_getlimit(myaclbuf, class);
#ifdef VIRTUAL
		if (address != NULL)
		    printf("%s ", address);
#endif
		if (strcmp(progname, "ftpcount")) {
		    printf("Service class %s: \n", class);
		    printf("   - %3d users ", acl_countusers(class));
		}
		else {
		    printf("Service class %-20.20s - %3d users ",
			   class, acl_countusers(class));
		}
		if (limit == -1)
		    printf("(no maximum)\n");
		else
		    printf("(%3d maximum)\n", limit);
	    }
	}
	while (*myaclbuf && *myaclbuf++ != '\n');
    }
    free(aclbuf);
    return (0);
}

int main(int argc, char **argv)
{
    int c, exitval;
    int virtual = 0;
#ifdef VIRTUAL
    FILE *svrfp;
    char *sp;
    struct stat st;
    char configdir[MAXPATHLEN];
    char accesspath[MAXPATHLEN];
#ifdef INET6
    char hostaddress[INET6_ADDRSTRLEN];
#else
    char hostaddress[32];
#endif
#endif

    if ((progname = strrchr(argv[0], '/')))
	++progname;
    else
	progname = argv[0];

    if (argc > 1) {
	while ((c = getopt(argc, argv, ARGS)) != EOF) {
	    switch (c) {
	    case 'V':
		print_copyright();
		exit(0);
#ifdef VIRTUAL
	    case 'v':
		virtual = 1;
		break;
#endif
	    default:
		fprintf(stderr, "usage: %s [-" ARGS "]\n", progname);
		exit(1);
	    }
	}
    }

    exitval = 0;
    if ((virtual == 0) && (display_info(_PATH_FTPACCESS, NULL) != 0))
	exitval = 1;

#ifdef VIRTUAL
    /*
     * Deal with the ftpaccess files at the virtual domain directory locations
     * specified in the ftpservers file.
     */
    if (virtual && ((svrfp = fopen(_PATH_FTPSERVERS, "r")) != NULL)) {
	while (read_servers_line(svrfp, hostaddress, sizeof(hostaddress),
	       configdir, sizeof(configdir)) == 1) {
	    /* get rid of any trailing slash */
	    sp = configdir + (strlen(configdir) - 1);
	    if (*sp == '/')
		*sp = '\0';

	    /* check to see that a valid directory value was supplied */
	    if ((stat(configdir, &st) == 0) &&
		((st.st_mode & S_IFMT) == S_IFDIR)) {
		snprintf(accesspath, sizeof(accesspath), "%s/ftpaccess",
			 configdir);
		if (display_info(accesspath, hostaddress) != 0)
		    exitval = 1;
	    }
	}
	fclose(svrfp);
    }
#endif
    return (exitval);
}
