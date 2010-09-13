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
 
  $Id: acl.c,v 1.9 2000/07/01 18:17:38 wuftpd Exp $
 
****************************************************************************/
#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include "pathnames.h"
#include "extensions.h"
#include "proto.h"

char *aclbuf = NULL;
static struct aclmember *aclmembers;

/*************************************************************************/
/* FUNCTION  : getaclentry                                               */
/* PURPOSE   : Retrieve a named entry from the ACL                       */
/* ARGUMENTS : pointer to the keyword and a handle to the acl members    */
/* RETURNS   : pointer to the acl member containing the keyword or NULL  */
/*************************************************************************/

struct aclmember *getaclentry(char *keyword, struct aclmember **next)
{
    do {
	if (!*next)
	    *next = aclmembers;
	else
	    *next = (*next)->next;
    } while (*next && strcasecmp((*next)->keyword, keyword));

    return (*next);
}

/*************************************************************************/
/* FUNCTION  : parseacl                                                  */
/* PURPOSE   : Parse the acl buffer into its components                  */
/* ARGUMENTS : A pointer to the acl file                                 */
/* RETURNS   : nothing                                                   */
/*************************************************************************/

void parseacl(void)
{
    char *ptr, *aclptr = aclbuf, *line;
    int cnt;
    struct aclmember *member, *acltail;

    if (!aclbuf || !(*aclbuf))
	return;

    aclmembers = (struct aclmember *) NULL;
    acltail = (struct aclmember *) NULL;

    while (*aclptr != '\0') {
	line = aclptr;
	while (*aclptr && *aclptr != '\n')
	    aclptr++;
	*aclptr++ = (char) NULL;

	/* deal with comments */
	if ((ptr = strchr(line, '#')) != NULL)
	    /* allowed escaped '#' chars for path-filter (DiB) */
	    if ((ptr > aclbuf) && (*(ptr - 1) != '\\'))
		*ptr = '\0';

	ptr = strtok(line, " \t");
	if (ptr) {
	    member = (struct aclmember *) calloc(1, sizeof(struct aclmember));

	    if (member == NULL) {
		syslog(LOG_ERR, "calloc error parsing acl");
		exit(1);
	    }
	    (void) strncpy(member->keyword, ptr, MAXKWLEN);
	    member->keyword[MAXKWLEN - 1] = '\0';
	    cnt = 0;
	    while ((ptr = strtok(NULL, " \t")) != NULL) {
		if (cnt >= MAXARGS) {
		    syslog(LOG_ERR,
		     "Too many args (>%d) in ftpaccess: %s %s %s %s %s ...",
			   MAXARGS - 1, member->keyword, member->arg[0],
			   member->arg[1], member->arg[2], member->arg[3]);
		    break;
		}
		member->arg[cnt++] = ptr;
	    }
	    if (acltail)
		acltail->next = member;
	    acltail = member;
	    if (!aclmembers)
		aclmembers = member;
	}
    }
}

/*************************************************************************/
/* FUNCTION  : readacl                                                   */
/* PURPOSE   : Read the acl into memory                                  */
/* ARGUMENTS : The pathname of the acl                                   */
/* RETURNS   : 0 if error, 1 if no error                                 */
/*************************************************************************/

int readacl(char *aclpath)
{
    FILE *aclfile;
    struct stat finfo;
    struct aclmember *member;
    extern int use_accessfile;

    if (!use_accessfile)
	return (0);

    while (aclmembers) {
	member = aclmembers->next;
	free(aclmembers);
	aclmembers = member;
    }

    if (aclbuf) {
	free(aclbuf);
	aclbuf = NULL;
    }

    if ((aclfile = fopen(aclpath, "r")) == NULL) {
	syslog(LOG_ERR, "cannot open access file %s: %s", aclpath,
	       strerror(errno));
	return (0);
    }
    if (fstat(fileno(aclfile), &finfo) != 0) {
	syslog(LOG_ERR, "cannot fstat access file %s: %s", aclpath,
	       strerror(errno));
	(void) fclose(aclfile);
	return (0);
    }
    if (finfo.st_size == 0) {
	aclbuf = (char *) calloc(1, 1);
    }
    else {
	if (!(aclbuf = (char *) malloc((size_t) finfo.st_size + 1))) {
	    syslog(LOG_ERR, "could not malloc aclbuf (%d bytes)", (size_t) finfo.st_size + 1);
	    (void) fclose(aclfile);
	    return (0);
	}
	if (!fread(aclbuf, (size_t) finfo.st_size, 1, aclfile)) {
	    syslog(LOG_ERR, "error reading acl file %s: %s", aclpath,
		   strerror(errno));
	    free(aclbuf);
	    aclbuf = NULL;
	    (void) fclose(aclfile);
	    return (0);
	}
	*(aclbuf + finfo.st_size) = '\0';
    }
    (void) fclose(aclfile);
    return (1);
}
