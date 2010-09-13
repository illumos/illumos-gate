/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
   
  $Id: private.c,v 1.12 2000/07/01 18:17:39 wuftpd Exp $  
   
****************************************************************************/
#include "config.h"

#ifndef NO_PRIVATE

#include <stdio.h>
#include <errno.h>

extern char *strsep(char **, const char *);

#include <string.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include "pathnames.h"
#include "extensions.h"
#include "proto.h"

#ifdef SECUREOSF
#define SecureWare		/* Does this mean it works for all SecureWare? */
#endif

#ifdef HPUX_10_TRUSTED
#include <hpsecurity.h>
#endif

#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
#include <prot.h>
#endif

#ifndef NO_CRYPT_PROTO
extern char *crypt(const char *, const char *);
#endif

static int group_attempts, group_given;
static char *groupname, *passbuf;

struct acgrp {
    char *gname;		/* access group name */
    char *gpass;		/* access group password */
    gid_t gr_gid;		/* group to setegid() to */
    struct acgrp *next;
};

static struct acgrp *privptr, *privtail;

extern int lgi_failure_threshold;
extern char remoteident[];

static void add_acgrp(char *gname, char *gpass, gid_t gid)
{
    struct acgrp *aptr;

    aptr = (struct acgrp *) calloc(1, sizeof(struct acgrp));
    if (aptr == NULL) {
	syslog(LOG_ERR, "calloc error in add_acgrp");
	dologout(1);
    }

    /* add element to end of list */
    if (privtail)
	privtail->next = aptr;
    privtail = aptr;
    if (!privptr)
	privptr = aptr;

    aptr->gname = strdup(gname);
    if (aptr->gname == NULL) {
	syslog(LOG_ERR, "malloc error in add_acgrp");
	dologout(1);
    }
    if (gpass == NULL)
	aptr->gpass = strdup("");
    else
	aptr->gpass = strdup(gpass);
    if (aptr->gpass == NULL) {
	syslog(LOG_ERR, "malloc error in add_acgrp");
	dologout(1);
    }
    aptr->gr_gid = gid;
}

static void parsepriv(void)
{
    char *ptr;
    char *acptr = passbuf, *line;
    char *argv[3], *p, *val;
    struct group *gr;
    int n;

    if (!passbuf || !(*passbuf))
	return;

    /* read through passbuf, stripping comments. */
    while (*acptr != '\0') {
	line = acptr;
	while (*acptr && *acptr != '\n')
	    acptr++;
	*acptr++ = '\0';

	/* deal with comments */
	if ((ptr = strchr(line, '#')) != NULL)
	    *ptr = '\0';

	if (*line == '\0')
	    continue;

	/* parse the lines... */
	for (n = 0, p = line; n < 3 && p != NULL; n++) {
	    val = (char *) strsep(&p, ":\n");
	    argv[n] = val;
	    if ((argv[n][0] == ' ') || (argv[n][0] == '\0'))
		argv[n] = NULL;
	}
	/* check their were 3 fields, if not skip the line... */
	if (n != 3 || p != NULL)
	    continue;

	if (argv[0] && argv[2]) {
	    if (argv[2][0] == '%') {
		gid_t gid = atoi(argv[2] + 1);
		if ((gr = getgrgid(gid)) != NULL)
		    add_acgrp(argv[0], argv[1], gid);
	    }
	    else {
		if ((gr = getgrnam((char *) argv[2])) != NULL)
		    add_acgrp(argv[0], argv[1], gr->gr_gid);
	    }
	    endgrent();
	}
    }
}

/*************************************************************************/
/* FUNCTION  : priv_setup                                                */
/* PURPOSE   : Set things up to use the private access password file.    */
/* ARGUMENTS : path, the path to the private access password file        */
/*************************************************************************/

void priv_setup(char *path)
{
    FILE *prvfile;
    struct stat finfo;
    struct acgrp *aptr;

    while (privptr) {
	aptr = privptr->next;
	free(privptr->gname);
	free(privptr->gpass);
	free(privptr);
	privptr = aptr;
    }
    privtail = NULL;

    if (passbuf) {
	free(passbuf);
	passbuf = NULL;
    }

    if ((prvfile = fopen(path, "r")) == NULL) {
	if (errno != ENOENT)
	    syslog(LOG_ERR, "cannot open private access file %s: %s",
		   path, strerror(errno));
	return;
    }
    if (fstat(fileno(prvfile), &finfo) != 0) {
	syslog(LOG_ERR, "cannot fstat private access file %s: %s", path,
	       strerror(errno));
	(void) fclose(prvfile);
	return;
    }
    if (finfo.st_size == 0) {
	passbuf = (char *) calloc(1, 1);
    }
    else {
	if (!(passbuf = (char *) malloc((size_t) finfo.st_size + 1))) {
	    (void) syslog(LOG_ERR, "could not malloc passbuf (%d bytes)",
			  (size_t) finfo.st_size + 1);
	    (void) fclose(prvfile);
	    return;
	}
	if (!fread(passbuf, (size_t) finfo.st_size, 1, prvfile)) {
	    (void) syslog(LOG_ERR, "error reading private access file %s: %s",
			  path, strerror(errno));
	    (void) fclose(prvfile);
	    return;
	}
	*(passbuf + finfo.st_size) = '\0';
    }
    (void) fclose(prvfile);
    (void) parsepriv();
}

/*************************************************************************/
/* FUNCTION  : priv_getent                                               */
/* PURPOSE   : Retrieve an entry from the in-memory copy of the group    */
/* access file.                                              */
/* ARGUMENTS : pointer to group name                                     */
/*************************************************************************/

static struct acgrp *priv_getent(char *group)
{
    struct acgrp *ptr;

    for (ptr = privptr; ptr; ptr = ptr->next)
	if (!strcasecmp(group, ptr->gname))
	    return (ptr);

    return (NULL);
}

/*************************************************************************/
/* FUNCTION  : priv_group                                                */
/* PURPOSE   :                                                           */
/* ARGUMENTS :                                                           */
/*************************************************************************/

void priv_group(char *group)
{
    if (groupname)
	free(groupname);

    groupname = strdup(group);
    if (groupname == NULL) {
	reply(421, "Local resource failure: malloc");
	syslog(LOG_ERR, "malloc error in priv_group");
	dologout(1);
    }
    group_given = 1;
    reply(200, "Request for access to group %s accepted.", group);
}

/*************************************************************************/
/* FUNCTION  : priv_gpass                                                */
/* PURPOSE   : validate the group access request, and if OK place user   */
/* in the proper group.                                      */
/* ARGUMENTS : group access password                                     */
/*************************************************************************/

void priv_gpass(char *gpass)
{
    char *xgpass = NULL;
    struct acgrp *grp;
    uid_t uid;

    if (group_given == 0) {
	reply(503, "Give group name with SITE GROUP first.");
	return;
    }
    /* OK, now they're getting a chance to specify a password.  Make them
     * give the group name again if they fail... */
    group_given = 0;

    grp = priv_getent(groupname);
    if (passbuf && gpass && *gpass != '\0' && grp && *grp->gpass != '\0')
#if defined(SecureWare) || defined(HPUX_10_TRUSTED)
	xgpass = bigcrypt(gpass, grp->gpass);
#else
	xgpass = crypt(gpass, grp->gpass);
#endif

    if (!(((gpass != NULL)
	   && (*gpass != '\0')
	   && (grp != NULL)
	   && (*grp->gpass != '\0')
	   && (strcmp(xgpass, grp->gpass) == 0))
	  || (((gpass == NULL)
	       || (*gpass == '\0'))
	      && (grp != NULL)
	      && (*grp->gpass == '\0'))
	)) {
	reply(530, "Group access request incorrect.");
	grp = NULL;
	if (++group_attempts >= lgi_failure_threshold) {
	    syslog(LOG_NOTICE,
		   "repeated group access failures from %s, group %s",
		   remoteident, groupname);
	    dologout(0);
	}
	sleep(group_attempts);	/* slow down password crackers */
	return;
    }

    uid = geteuid();
    setid_priv_on(0);
    setegid(grp->gr_gid);
    setid_priv_off(uid);

    reply(200, "Group access enabled.");
    group_attempts = 0;
}
#endif /* !NO_PRIVATE */
