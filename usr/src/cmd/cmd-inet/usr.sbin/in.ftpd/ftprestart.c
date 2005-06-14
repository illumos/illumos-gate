/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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
 
  $Id: ftprestart.c,v 1.7 2000/07/01 18:17:39 wuftpd Exp $
 
****************************************************************************/
/* ftprestart
   **
   ** removes the ftpd shutdown files.
   **
   **  In the previous versions of the wu-ftpd server it was recommended to 
   **  create a link in order for shutdown to work properly for real and 
   **  anonymous user, e.g.  If you use ftpshut, it will create a message 
   **  file at the location specified in the ftpaccess shutdown directive.
   **  ln -s /etc/shutmsg  ~ftp/etc/shutmsg 
   **  
   **  When ftp service is to be restarted after an ftpshut, the shutdown 
   **  message files must be removed. This program reads the ftpaccess
   **  file and finds the location of the system shutdown file.  It
   **  then proceeds to construct a path to the anonymous ftp area with
   **  information found in the "ftp" account.  If virtual ftp servers
   **  are enabled, the shutdown message files within those directories 
   **  are also removed.
   ** 
   **  Initial Author: Kent Landfield
 */
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <pwd.h>
#if defined(VIRTUAL) && defined(INET6)
#include <netinet/in.h>
#endif

#include "pathnames.h"

#define MAXVIRTUALS 512

char *progname;
char *msgfiles[MAXVIRTUALS];
int numfiles = 0;

#ifdef VIRTUAL
extern int read_servers_line(FILE *, char *, size_t, char *, size_t);
#endif

void print_copyright(void);

static int newfile(char *fpath)
{
    int i;
    int fnd;

    /* 
       ** Check to see if the message file path has already been
       ** seen. If so then there is no need to create it again.
     */

    fnd = 0;
    for (i = 0; i < numfiles; i++) {
	if (strcmp(msgfiles[i], fpath) == 0) {
	    fnd = 1;
	    break;
	}
    }
    if (!fnd) {
	msgfiles[numfiles++] = strdup(fpath);
	return (1);
    }
    return (0);
}

static int remove_shutdown_file(char *path)
{
    struct stat stbuf;
    int rc = 1;			/* guilty until proven innocent */

    fprintf(stderr, "%s: %s ", progname, path);

    if (stat(path, &stbuf) == 0) {
	if ((rc = unlink(path)) == 0)
	    fprintf(stderr, "removed.\n");
	else
	    perror(path);
    }
    else
	fprintf(stderr, "does not exist.\n");

    return (rc);
}

int main(int argc, char **argv)
{
    int c;

    char *p;
    char *cp = NULL;
    char linebuf[BUFSIZ];
    char shutmsg[256];
    char anonpath[MAXPATHLEN];
    FILE *accessfile;
    struct passwd *pw;

#if defined(VIRTUAL)
    FILE *svrfp;
    char *sp;
#ifdef INET6
    char hostaddress[INET6_ADDRSTRLEN];
#else
    char hostaddress[32];
#endif
    char root[MAXPATHLEN];
    char configdir[MAXPATHLEN];
    char accesspath[MAXPATHLEN];
    char altmsgpath[MAXPATHLEN];
    struct stat finfo;
#endif

    if ((progname = strrchr(argv[0], '/')))
	++progname;
    else
	progname = argv[0];  

    if (argc > 1) {
	while ((c = getopt(argc, argv, "V")) != EOF) {
	    switch (c) {
	    case 'V':
		print_copyright();
		exit(0);
	    default:
		fprintf(stderr, "usage: %s [-V]\n", progname);
		exit(1);
	    }
	}
    }

    if ((accessfile = fopen(_PATH_FTPACCESS, "r")) == NULL) {
	if (errno != ENOENT)
	    fprintf(stderr, "%s: could not open access file %s: %s\n",
		    progname, _PATH_FTPACCESS, strerror(errno));
	exit(1);
    }

    /* 
       ** Search the access file for the 'shutdown' directive.
     */

    while (fgets(linebuf, BUFSIZ, accessfile) != NULL) {
	if (strncasecmp(linebuf, "shutdown", 8) == 0) {
	    (void) strtok(linebuf, " \t");
	    (void) strlcpy(shutmsg, strtok(NULL, " \t"), sizeof(shutmsg));
	    cp = shutmsg;
	    if ((p = strchr(cp, '\n')) != NULL)
		*p = '\0';
	}
    }

    if (cp == NULL) {
	fprintf(stderr, "%s: no shutdown path defined in ftpaccess file %s.\n",
                progname, _PATH_FTPACCESS);
	exit(1);
    }

    msgfiles[numfiles++] = shutmsg;

    /*
       ** Get the location of the anonymous ftp area and check
       ** to see if there is a file shutdown file there as well. 
       ** If so, remove it.
     */
    if ((pw = getpwnam("ftp")) != NULL) {
	(void) snprintf(anonpath, sizeof(anonpath), "%s%s", pw->pw_dir,
	    shutmsg);
	if (newfile(anonpath))
	    (void) remove_shutdown_file(anonpath);
    }

#ifdef VIRTUAL
    /*
       ** Search the access file for virtual ftp servers.
       ** If found, check if there are links/shutdown
       ** message files files in the virtual server areas.
       ** If so, remove them.
     */

    rewind(accessfile);

    while (fgets(linebuf, sizeof(linebuf) - 1, accessfile) != NULL) {
	if (strncasecmp(linebuf, "virtual", 7) == 0) {
	    if ((p = strstr(linebuf, "root")) != NULL) {
		p += 4;

		if ((cp = strchr(linebuf, '\n')) != NULL)
		    *cp = '\0';

		/* skip to the path */

		while (*p && isspace(*p))
		    p++;
		cp = p;
		while (*p && isalnum(*p))
		    p++;

		(void) snprintf(altmsgpath, sizeof(altmsgpath), "%s%s", cp,
		    shutmsg);
		if (newfile(altmsgpath))
		    (void) remove_shutdown_file(altmsgpath);
	    }
	}
    }


    /*
       ** Need to deal with the access files at the virtual domain directory
       ** locations specified in the ftpservers file.
     */

    if ((svrfp = fopen(_PATH_FTPSERVERS, "r")) != NULL) {
	while (read_servers_line(svrfp, hostaddress, sizeof(hostaddress),
	       configdir, sizeof(configdir)) == 1) {
	    /* get rid of any trailing slash */
	    sp = configdir + (strlen(configdir) - 1);
	    if (*sp == '/')
		*sp = '\0';

	    /*
	       ** check to see that a valid directory value was
	       ** supplied and not something such as "INTERNAL"
	       **
	       ** It is valid to have a string such as "INTERNAL" in the
	       ** ftpservers entry. This is not an error. Silently ignore it.
	     */

	    if ((stat(configdir, &finfo) < 0) ||
		((finfo.st_mode & S_IFMT) != S_IFDIR))
		continue;

	    (void) snprintf(accesspath, sizeof(accesspath), "%s/ftpaccess",
		configdir);

	    (void) fclose(accessfile);

	    if ((accessfile = fopen(accesspath, "r")) == NULL) {
		if (errno != ENOENT) {
		    fprintf(stderr, "%s: could not open access file %s: %s\n",
			    progname, accesspath, strerror(errno));
		    continue;
		}
	    }

	    /* need to find the root path */

	    while (fgets(linebuf, sizeof(linebuf) - 1, accessfile) != NULL) {
		if ((sp = strstr(linebuf, "root")) != NULL) {
		    if ((cp = strchr(sp, '\n')) != NULL)
			*cp = '\0';	/* strip newline */
		    sp += 4;	/* skip past "root" keyword */

		    while (*sp && isspace(*sp))		/* skip whitespace to path */
			sp++;
		    cp = sp;
		    while (*sp && !isspace(*sp))
			sp++;
		    *sp = '\0';	/* truncate blanks, comments etc. */
		    (void) strlcpy(root, cp, sizeof(root));
		    break;
		}
	    }

	    rewind(accessfile);

	    /* need to find the shutdown message file path */

	    while (fgets(linebuf, sizeof(linebuf) - 1, accessfile) != NULL) {
		if ((sp = strstr(linebuf, "shutdown")) != NULL) {
		    if ((cp = strchr(sp, '\n')) != NULL)
			*cp = '\0';	/* strip newline */
		    sp += 8;	/* skip past "root" keyword */

		    while (*sp && isspace(*sp))		/* skip whitespace to path */
			sp++;
		    cp = sp;
		    while (*sp && !isspace(*sp))
			sp++;
		    *sp = '\0';	/* truncate blanks, comments etc. */
		    break;
		}
	    }

	    /*
	       ** check to make sure the admin hasn't specified 
	       ** a complete path in the 'shutdown' directive.
	     */
	    if ((sp = strstr(cp, root)) == NULL)
		(void) snprintf(altmsgpath, sizeof(altmsgpath), "%s%s", root,
		    cp);

	    if (newfile(altmsgpath))
		(void) remove_shutdown_file(altmsgpath);
	}
	fclose(svrfp);
    }
#endif /* VIRTUAL */

    fclose(accessfile);

    /*
       ** Time to remove the system wide shutdown file.
     */
    return (remove_shutdown_file(shutmsg));
}
