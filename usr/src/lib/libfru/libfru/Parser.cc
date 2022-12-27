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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "Parser.h"

// yacc symbols
int fruparse(void);
extern int frudebug;

// global data to/from the lexer
pthread_mutex_t gParserLock;
fru_errno_t gParserErrno = FRU_SUCCESS;
char *gParserString = NULL;
Ancestor *gParserAnts   = NULL;
PathDef *gParserHead   = NULL;
int *gParserAbs    = NULL;

// returns a NULL terminated list of PathDef objects.
// and a NULL terminated list of ancestor objects this path exists in
// NOTE: ancestors may be NULL if no tags contain a valid path.
fru_errno_t
fru_field_parser(const char *path, Ancestor **ancestors,
	int *absolute, PathDef **pathDef)
{
	// lock up the globals for the parser...
	pthread_mutex_lock(&gParserLock);

	// get out a string for the parser to play with.
	gParserString = strdup(path);
	if (gParserString == NULL) {
		pthread_mutex_unlock(&gParserLock);
		return (FRU_FAILURE);
	}
	// save the head pointer for delete.
	char *delPtr = gParserString;

	// frudebug = 1;

	// set up for return data from lexer.
	gParserHead = NULL;
	gParserAnts = NULL;
	gParserErrno = FRU_SUCCESS;
	gParserAbs = absolute;
	*gParserAbs = 0;

	int rc = fruparse();

	// clean up the string we used for yacc.
	free(delPtr);
	gParserString = NULL;

	// frudebug = 0;
	if (rc != 0) {
		delete gParserHead;
		delete gParserAnts;
		fru_errno_t err = gParserErrno;
		pthread_mutex_unlock(&gParserLock);
		return (err);
	}

	/* if ((gParserHead == NULL) || (gParserAnts == NULL)) { */
	/* allow ancestors to be NULL */
	/* some elements don't have tagged ancestors */
	if (gParserHead == NULL) {
		delete gParserAnts;
		pthread_mutex_unlock(&gParserLock);
		return (FRU_FAILURE);
	}

	*pathDef = gParserHead;
	*ancestors = gParserAnts;

	pthread_mutex_unlock(&gParserLock);
	return (FRU_SUCCESS);
}
