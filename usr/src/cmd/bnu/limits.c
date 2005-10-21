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

#include "uucp.h"

/* add sitedep() and sysmatch() to list when ifdefs are removed below */
static int get_tokens(), siteindep();

/*  field array indexes for LIMIT parameters */

#define U_SERVICE	0
#define U_MAX		1
#define U_SYSTEM	2
#define U_MODE		3

static char * _Lwords[] = {"service", "max", "system", "mode"};

#define NUMFLDS		4

struct name_value
{
	char *name;
	char *value;
};

/*
 * manage limits file.
 */

/*
 * scan the Limits file and get the limit for the given service.
 * return SUCCESS if the limit was found, else return FAIL.
 */
int
scanlimit(service, limitval)
char *service;
struct limits *limitval;
{
	char buf[BUFSIZ];
	char *tokens[NUMFLDS];	/* fields found in LIMITS */
	char msgbuf[BUFSIZ];	/* place to build messages */
	FILE *Fp = NULL;	/* file pointer for LIMITS */
	int SIflag, SDflag;

	if ((Fp = fopen(LIMITS, "r")) == NULL) {
	    DEBUG(5, "cannot open %s\n", LIMITS);
	    sprintf(msgbuf, "fopen of %s failed with errno=%%d\n", LIMITS);
	    DEBUG(5, msgbuf, errno);
	    return(FAIL);
	}

	SIflag = FALSE;
	SDflag = TRUE;

/* The following #if (0 == 1) and #endif lines should be deleted when 
 * we expand the functionality of the Limits file to include the 
 * limit per site, and the mode for uucico.
 */
#if (0 == 1)
	if (strcmp(service, "uucico") == SAME)
	    SDflag = FALSE;
#endif

	while ((getuline(Fp, buf) > 0) && ((SIflag && SDflag) == FALSE)) {
	    if (get_tokens(buf, tokens) == FAIL)
		continue;

	    if (SIflag == FALSE) {
		if (siteindep(tokens, service, limitval) == SUCCESS)
		    SIflag = TRUE;
	    }

/* The following #if (0 == 1) and #endif lines should be deleted when 
 * we expand the functionality of the Limits file to include the 
 * limit per site, and the mode for uucico.
 */
#if (0 == 1)
	    if (SDflag == FALSE) {
		if (sitedep(tokens, limitval) == SUCCESS)
		    SDflag = TRUE;
	    }
#endif
	}

	fclose(Fp);
	if ((SIflag && SDflag) == TRUE)
	    return(SUCCESS);
	else return(FAIL);
}

/*
 * parse a line in LIMITS and return a vector
 * of fields (flds)
 *
 * return:
 *	SUCCESS - token pairs name match with the key words
 */
static int
get_tokens (line,flds)
char *line;
char *flds[];
{
	int i;
	char *p;
	struct name_value pair;

	/* initialize defaults  in case parameter is not specified */
	for (i=0;i<NUMFLDS;i++)
		flds[i] = CNULL;

	for (p=line;p && *p;) {
		p = next_token (p, &pair);

		for (i=0; i<NUMFLDS; i++) {
			if (EQUALS(pair.name, _Lwords[i])) {
				flds[i] = pair.value;
				break;
			}
			if (i == NUMFLDS-1) /* pair.name is not key */
				return FAIL;
		}
	}
	return(SUCCESS);
}
/*
 * this function can only handle the following format
 *
 *	service=uucico max=5
 *
 * return:
 *	SUCCESS - OK
 *	FAIL - service's value does not match or wrong format
 */
static int
siteindep(flds, service, limitval)
char *flds[];
char *service;
struct limits *limitval;
{

	if (!EQUALS(flds[U_SERVICE], service) || (flds[U_MAX] == CNULL))
		return(FAIL);
	if (sscanf(flds[U_MAX],"%d",&limitval->totalmax)==0)
		limitval->totalmax = -1; /* type conflict*/
	return(SUCCESS);
}

/* The following #if (0 == 1) and #endif lines should be deleted when 
 * we expand the functionality of the Limits file to include the 
 * limit per site, and the mode for uucico.
 */
#if (0 == 1)
/*
 * this function can only handle the following format
 *
 *	service=uucico system=ihnp1:ihnp3 [max=5] [mode=master]
 *
 * return:
 *	SUCCESS - OK
 *	FAIL - not uucico, no system name in Limits, 
 *		system's name does not match
 */
static int
sitedep(flds, limitval)
char *flds[];
struct limits *limitval;
{

	if (!EQUALS(flds[U_SERVICE],"uucico"))
		return FAIL; 
	if ((flds[U_SYSTEM] == CNULL) || (sysmatch(flds[U_SYSTEM]) != 0))
		return FAIL;
	if (flds[U_MAX] == CNULL)
		limitval->sitemax = 1; /* default value */
	else if (sscanf(flds[U_MAX],"%d",&limitval->sitemax)==0)
			limitval->sitemax = -1; /* type conflict*/

	if (flds[U_MODE] == CNULL)
		strcpy(limitval->mode,"master:slave");
	else
		strncpy(limitval->mode,flds[U_MODE],strlen(flds[U_MODE]));
	return(SUCCESS);
}

/*
 * this function checks if system in system's list
 * system=ihnp1:ihnp3:...
 *
 * return:
 *	SUCCESS - OK
 */
static int
sysmatch(p)
char *p;
{
	char *arg;

	while (p && *p) {
		p = nextarg(p, &arg);
	    	if (EQUALS(arg, Rmtname)) 
			return(SUCCESS);
	}
	return FAIL;
}

#endif
