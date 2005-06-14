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
 
  $Id: conversions.c,v 1.10 2000/07/01 18:17:38 wuftpd Exp $
 
****************************************************************************/
#include "config.h"

#include <stdio.h>
#include <errno.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif

extern char *strsep(char **, const char *);

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "conversions.h"
#include "extensions.h"
#include "pathnames.h"
#include "proto.h"

/*************************************************************************/
/* FUNCTION  : readconv                                                  */
/* PURPOSE   : Read the conversions into memory                          */
/* ARGUMENTS : The pathname of the conversion file                       */
/* RETURNS   : 0 if error, 1 if no error                                 */
/*************************************************************************/

char *convbuf = NULL;
struct convert *cvtptr;

struct str2int {
    char *string;
    int value;
};

struct str2int c_list[] =
{
    {"T_REG", T_REG},
    {"T_ASCII", T_ASCII},
    {"T_DIR", T_DIR},
    {"O_COMPRESS", O_COMPRESS},
    {"O_UNCOMPRESS", O_UNCOMPRESS},
    {"O_TAR", O_TAR},
    {NULL, 0},
};

static int conv(char *str)
{
    int rc = 0;
    int counter;

    /* check for presence of ALL items in string... */

    if (str)
	for (counter = 0; c_list[counter].string; ++counter)
	    if (strstr(str, c_list[counter].string))
		rc = rc | c_list[counter].value;
    return (rc);
}

static int readconv(char *convpath)
{
    FILE *convfile;
    struct stat finfo;

    if ((convfile = fopen(convpath, "r")) == NULL) {
	if (errno != ENOENT)
	    syslog(LOG_ERR, "cannot open conversion file %s: %s",
		   convpath, strerror(errno));
	return (0);
    }
    if (fstat(fileno(convfile), &finfo) != 0) {
	syslog(LOG_ERR, "cannot fstat conversion file %s: %s", convpath,
	       strerror(errno));
	(void) fclose(convfile);
	return (0);
    }
    if (finfo.st_size == 0) {
	convbuf = (char *) calloc(1, 1);
    }
    else {
	if (!(convbuf = (char *) malloc((size_t) finfo.st_size + 1))) {
	    syslog(LOG_ERR, "could not malloc convbuf (%d bytes)", (size_t) finfo.st_size + 1);
	    (void) fclose(convfile);
	    return (0);
	}
	if (!fread(convbuf, (size_t) finfo.st_size, 1, convfile)) {
	    syslog(LOG_ERR, "error reading conv file %s: %s", convpath,
		   strerror(errno));
	    convbuf = NULL;
	    (void) fclose(convfile);
	    return (0);
	}
	*(convbuf + finfo.st_size) = '\0';
    }
    (void) fclose(convfile);
    return (1);
}

static void parseconv(void)
{
    char *ptr;
    char *convptr = convbuf, *line;
    char *argv[8], *p, *val;
    struct convert *cptr, *cvttail = (struct convert *) NULL;
    int n;

    if (!convbuf || !(*convbuf))
	return;

    /* read through convbuf, stripping comments. */
    while (*convptr != '\0') {
	line = convptr;
	while (*convptr && *convptr != '\n')
	    convptr++;
	*convptr++ = '\0';

	/* deal with comments */
	if ((ptr = strchr(line, '#')) != NULL)
	    *ptr = '\0';

	if (*line == '\0')
	    continue;

	/* parse the lines... */
	for (n = 0, p = line; n < 8 && p != NULL; n++) {
	    val = (char *) strsep(&p, ":\n");
	    argv[n] = val;
	    if ((argv[n][0] == ' ') || (argv[n][0] == '\0'))
		argv[n] = NULL;
	}
	/* check their were 8 fields, if not skip the line... */
	if (n != 8 || p != NULL)
	    continue;

	/* make sure the required elements are present */
	if ((!argv[0] && !argv[1] && !argv[2] && !argv[3]) || !argv[4] || !argv[7])
	    continue;

	/* add element to end of list */
	cptr = (struct convert *) calloc(1, sizeof(struct convert));

	if (cptr == NULL) {
	    syslog(LOG_ERR, "calloc error parsing ftpconversions");
	    exit(0);
	}
	if (cvttail)
	    cvttail->next = cptr;
	cvttail = cptr;
	if (!cvtptr)
	    cvtptr = cptr;

	cptr->stripprefix = (char *) argv[0];
	cptr->stripfix = (char *) argv[1];
	cptr->prefix = (char *) argv[2];
	cptr->postfix = (char *) argv[3];
	cptr->external_cmd = (char *) argv[4];
	cptr->types = conv((char *) argv[5]);
	cptr->options = conv((char *) argv[6]);
	cptr->name = (char *) argv[7];
    }
}

void conv_init(void)
{
    if ((readconv(_path_cvt)) <= 0)
	return;
    parseconv();
}
