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
  
  $Id: hostacc.c,v 1.8 2000/07/01 18:17:39 wuftpd Exp $ 
  
****************************************************************************/
/*
 *      hostacc.c  -  Implementation of host access for the
 *                    experimental FTP daemon developed at
 *                    Washington University.
 *
 * INITIAL AUTHOR  - Bart Muijzer    <bartm@cv.ruu.nl>
 *
 * HISTORY
 *      930316  BM      Created
 *      930317  BM      Converted to local naming convention;
 *                      added rhost_ok(), cleanup code in enghacc()
 *      930318  BM      Ported to BSD; fixed memory leaks
 *      930322  BM      Changed algorithm: not in configfile =  allow
 *                                         in configfile and match = allow|deny
 *                                         in configfile and no match = deny
 */
#include "config.h"

#ifdef  HOST_ACCESS

#include "proto.h"
#include "hostacc.h"

static char linbuf[MAXLEN];	/* Buffer to hold one line of config-file  */
static char unibuf[MAXLEN];	/* Buffer to hold unified line             */
static hacc_t *ha_arr;		/* Array with host access information      */

static FILE *ptFp;		/* FILE * into host access config file     */
static int iHaInd = 0;		/* Index in ha_arr                         */
static int iHaSize;		/* Will hold actual #elems in ha_arr       */
static int iFirstTim = 1;	/* Used by gethacc() to see if index in    */
				 /* ha_arr needs to be reset                */

/* ------------------------------------------------------------------------ *\
 * FUNCTION  : rhost_ok                                                     *
 * PURPOSE   : Check if a host is allowed to make a connection              *
 * ARGUMENTS : Remote user name, remote host name, remote host address      *
 * RETURNS   : 1 if host is granted access, 0 if not                        *
 \* ------------------------------------------------------------------------ */

int rhost_ok(char *pcRuser, char *pcRhost, char *pcRaddr)
{
    hacc_t *ptHtmp;
    char *pcHost;
    char *ha_login;
    int iInd, iLineMatch = 0, iUserSeen = 0;

    switch (sethacc()) {
    case 1:
	/* no hostaccess file; disable mechanism */
	return (1);
	/* break; */
    case -1:
	syslog(LOG_INFO, "rhost_ok: sethacc failed");
	endhacc();
	return (0);
	/* break; */
    default:
	break;
    }

    /* user names "ftp" and "anonymous" are equivalent */
    if (!strcasecmp(pcRuser, "anonymous"))
	pcRuser = "ftp";

    while (((ptHtmp = gethacc()) != (hacc_t *) NULL) && !iLineMatch) {
	if (strcasecmp(ptHtmp->ha_login, "anonymous"))
	    ha_login = ptHtmp->ha_login;
	else
	    ha_login = "ftp";

	if ((strcasecmp(pcRuser, ha_login)) && strcmp(ha_login, "*"))
	    /* wrong user, check rest of file */
	    continue;

	/*
	 * We have seen a line regarding the current user.
	 * Remember this.
	 */
	iUserSeen = 1;

	for (iInd = 0, pcHost = ptHtmp->ha_hosts[0];
	     ((iInd < MAXHST) && (pcHost != NULL) && !iLineMatch);
	     pcHost = ptHtmp->ha_hosts[++iInd]) {
	    iLineMatch = hostmatch(pcHost, pcRaddr, pcRhost);
	    if (iLineMatch) {
		iLineMatch = (ptHtmp->ha_type == ALLOW) ? 1 : 0;
		goto match;
	    }
	}
    }

  match:
    /*
     * At this point, iUserSeen == 1 if we've seen lines regarding
     * the current user, and 0 otherwise. If we reached the end of
     * the config file without a match we allow. Else, we allow or
     * deny according to the rule found.
     */

    if (endhacc()) {
	syslog(LOG_INFO, "rhost_ok: endhacc failed");
	return (0);
    }

    if (iUserSeen)
	return (ptHtmp == NULL) ? 0 : iLineMatch;
    else
	/* Nothing at all about user in configfile, allow */
	return (1);
}

/* ------------------------------------------------------------------------ *\
 * FUNCTION  : sethacc                                                      *
 * PURPOSE   : Initialize data structures for host access                   *
 * ARGUMENTS : None                                                         *
 * RETURNS   : -1 on failure, 1 if host access file doesn't exist,          *
 *             0 otherwise                                                  *
 \* ------------------------------------------------------------------------ */

static int sethacc(void)
{
    int iHaHind = 0;		/* Index in list of hosts   */
    char *pcBegin, *pcEnd, *pcColon;
    char *pcTmp1, *pcTmp2;
    int iHaMalloc = 0;		/* how many elem malloced */

    iHaInd = 0;
    iFirstTim = 1;
    /* Open config file */
    if ((ptFp = fopen(_path_ftphosts, "r")) == NULL) {
	if (errno == ENOENT)
	    return (1);
	else {
	    fatalmsg("Can't open host access file");
	    iHaSize = iHaInd;
	    return (-1);
	}
    }
    ha_arr = (hacc_t *) malloc((iHaMalloc = 10) * sizeof(hacc_t));
    if (ha_arr == NULL) {
	syslog(LOG_ERR, "malloc error in sethacc");
	exit(0);
    }

    while (fgets(linbuf, MAXLEN, ptFp) != NULL) {
	iHaHind = 0;

	/* Find first non-whitespace character */
	for (pcBegin = linbuf;
	     ((*pcBegin == '\t') || (*pcBegin == ' '));
	     pcBegin++);

	/* Get rid of comments */
	if ((pcEnd = strchr(linbuf, '#')) != NULL)
	    *pcEnd = '\0';


	/* Skip empty lines */
	if ((pcBegin == pcEnd) || (*pcBegin == '\n'))
	    continue;

	/* Substitute all whitespace by a single ":" so we can
	 * easily break on words later on. The easiest way is 
	 * to copy the result into a temporary buffer (called
	 * the "unified buffer" because it will store a line in 
	 * the same format, regardless of the format the original
	 * line was in).
	 * The result will look like: "allow:name:host:host:host"
	 */
	for (pcTmp1 = pcBegin, pcTmp2 = unibuf; *pcTmp1; pcTmp1++) {
	    if (*pcTmp1 != '\t' && *pcTmp1 != ' ' && *pcTmp1 != '\n')
		*pcTmp2++ = *pcTmp1;
	    else
		/* whitespace */
	    if (*(pcTmp2 - 1) == ':')
		continue;
	    else
		*pcTmp2++ = ':';
	}

	/* Throw away trailing whitespace, now indicated by
	 * the last character of the unified buffer being a 
	 * colon. Remember where the news string ends.
	 */
	pcEnd = (*(pcTmp2 - 1) == ':') ? (pcTmp2 - 1) : pcTmp2;
	*pcEnd = '\0';		/* Terminate new string */

	/*
	 * Check if we need to expand the array with
	 * host access information
	 */
	if (iHaInd >= iHaMalloc) {
	    ha_arr = (hacc_t *) realloc(ha_arr, (iHaMalloc += 10) * sizeof(hacc_t));
	    if (!ha_arr) {
		fatalmsg("Failed to realloc host access array");
		iHaSize = iHaInd;
		return (-1);
	    }
	}

	/* Store what's left of the line into the
	 * hacc_t structure. First the access type,
	 * then the loginname, and finally a list of
	 * hosts to which all this applies.
	 */
	pcBegin = unibuf;
	if (!strncmp(pcBegin, "deny", 4)) {
	    ha_arr[iHaInd].ha_type = DENY;
	    pcBegin += 5;
	}
	else if (!strncmp(pcBegin, "allow", 5)) {
	    ha_arr[iHaInd].ha_type = ALLOW;
	    pcBegin += 6;
	}
	else {
	    fatalmsg("Format error in host access file");
	    iHaSize = iHaInd;
	    return (-1);
	}

	if ((pcColon = strchr(pcBegin, ':')) != NULL)
	    ha_arr[iHaInd].ha_login =
		strnsav(pcBegin, (pcColon - pcBegin));
	else {
	    fatalmsg("Format error in host access file");
	    iHaSize = iHaInd;
	    return (-1);
	}

	pcBegin = pcColon + 1;
	while ((pcColon = strchr(pcBegin, ':')) != NULL) {
	    ha_arr[iHaInd].ha_hosts[iHaHind++] =
		strnsav(pcBegin, (pcColon - pcBegin));
	    pcBegin = pcColon + 1;
	    if (iHaHind >= MAXHST) {
		fatalmsg("Line too long");
		iHaSize = iHaInd;
		return (-1);
	    }
	}
	ha_arr[iHaInd].ha_hosts[iHaHind++] =
	    strnsav(pcBegin, (pcEnd - pcBegin));
	ha_arr[iHaInd].ha_hosts[iHaHind] = NULL;
	iHaInd++;
    }
    iHaSize = iHaInd;		/* Record current size of ha_arr */
    return ((feof(ptFp)) ? 0 : -1);
}

/* ------------------------------------------------------------------------ *\
 * FUNCTION  : gethacc                                                      *
 * PURPOSE   : return pointer to the next host_access structure             *
 * ARGUMENTS : None                                                         *
 * RETURNS   : NULL on failure, pointervalue otherwise                      *
 \* ------------------------------------------------------------------------ */

static hacc_t *gethacc(void)
{
    static int iHaInd;
    static hacc_t ptTmp;

    if (iFirstTim) {
	iFirstTim = 0;
	iHaInd = 0;
    }
    if (iHaInd >= iHaSize)
	return ((hacc_t *) NULL);
    else {
	memmove(&ptTmp, &(ha_arr[iHaInd]), sizeof(hacc_t));
	iHaInd++;
	return (&ptTmp);
    }
}

/* ------------------------------------------------------------------------ *\
 * FUNCTION  : endhacc                                                      *
 * PURPOSE   : Free allocated data structures for host access               *
 * ARGUMENTS : None                                                         *
 * RETURNS   : -1 on failure, 0 otherwise                                   *
 \* ------------------------------------------------------------------------ */

static int endhacc(void)
{
    int iInd;
    hacc_t *ptHtmp;

    if (ha_arr == (hacc_t *) NULL)
	return (0);

    for (ptHtmp = ha_arr;
	 ptHtmp < ha_arr + iHaSize && ptHtmp->ha_type;
	 ptHtmp++) {
	ptHtmp->ha_type = 0;
	if (ptHtmp->ha_login) {
	    free(ptHtmp->ha_login);
	    ptHtmp->ha_login = NULL;
	}
	for (iInd = 0;
	     iInd < MAXHST && ptHtmp->ha_hosts[iInd];
	     iInd++) {
	    free(ptHtmp->ha_hosts[iInd]);
	    ptHtmp->ha_hosts[iInd] = NULL;
	}
    }
    free(ha_arr);
    ha_arr = NULL;

    if (ptFp && fclose(ptFp))
	return (-1);
    return (0);
}

/* ------------------------------------------------------------------------ */

static void fatalmsg(char *pcMsg)
{
    syslog(LOG_INFO, "host_access: %s", pcMsg);
}

static char *strnsav(char *pcStr, int iLen)
{
    char *pcBuf;

    if ((pcBuf = (char *) malloc(iLen + 1)) == NULL)
	return (NULL);
    strncpy(pcBuf, pcStr, iLen);
    pcBuf[iLen] = '\0';
    return (pcBuf);
}

#endif /* HOST_ACCESS */
