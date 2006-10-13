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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Indexed name factory; creates unique indexed names from base name strings
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vold.h"

/*
 * Local include files
 */

#include "name_factory.h"

typedef struct name_rec {
	char		*symnamep;
	int		index;
	struct name_rec *rec_nextp;
} name_rec_t;

typedef struct indexed_name {
	char			*namep;
	int			next_index;
	name_rec_t		*symrecp;
	struct indexed_name	*nextp;
} indexed_name_t;

static indexed_name_t *name_headp;

static mutex_t name_factory_mutex = DEFAULTMUTEX;

/*
 * Declarations of private functions
 */

static name_rec_t *add_name(indexed_name_t *entryp, char *sym_namep);
static int num_digits(int number);

/*
 * Definitions of public functions
 */

void
destroy_name_factory(void)
{
	name_rec_t	*rp, *nrp;
	indexed_name_t	*this_entryp, *next_entryp;

	this_entryp = name_headp;
	while (this_entryp != NULL) {
		next_entryp = this_entryp->nextp;
		free(this_entryp->namep);
		rp = this_entryp->symrecp;
		while (rp != NULL) {
			nrp = rp->rec_nextp;
			free(rp->symnamep);
			free(rp);
			rp = nrp;
		}
		free(this_entryp);
		this_entryp = next_entryp;
	}
	name_headp = NULL;
}

name_factory_result_t
name_factory_make_name(char *sym_namep, char *base_namep,
		char **indexed_namepp)
{
	name_rec_t		*recp;
	indexed_name_t		*next_entryp;
	int			name_index, len;

	if (base_namep == NULL)
		return (NAME_FACTORY_BAD_BASE_NAME);

	(void) mutex_lock(&name_factory_mutex);

	next_entryp = name_headp;
	while (next_entryp != NULL) {
		if (strcmp(base_namep, next_entryp->namep) == 0) {
			recp = next_entryp->symrecp;
			while (recp != NULL) {
				if (strcmp(sym_namep, recp->symnamep) == 0)
					break;
				recp = recp->rec_nextp;
			}
			if (recp == NULL)
				recp = add_name(next_entryp, sym_namep);
			name_index = recp->index;
			break;
		}
		next_entryp = next_entryp->nextp;
	}
	if (next_entryp == NULL) {
		next_entryp = vold_calloc(1, sizeof (indexed_name_t));
		next_entryp->namep = vold_strdup(base_namep);
		recp = add_name(next_entryp, sym_namep);
		next_entryp->nextp = name_headp;
		name_headp = next_entryp;
		name_index = recp->index;
	}
	len = strlen(base_namep) + num_digits(name_index) + 1;
	*indexed_namepp = vold_malloc(len);
	(void) snprintf(*indexed_namepp, len, "%s%d", base_namep, name_index);

	(void) mutex_unlock(&name_factory_mutex);

	return (NAME_FACTORY_SUCCESS);
}

/*
 * Definitions of private functions
 */
static name_rec_t *
add_name(indexed_name_t *entryp, char *sym_namep)
{
	name_rec_t *recp;

	recp = vold_calloc(1, sizeof (name_rec_t));
	recp->symnamep = vold_strdup(sym_namep);
	recp->index = entryp->next_index++;
	recp->rec_nextp = entryp->symrecp;
	entryp->symrecp = recp;
	return (recp);
}

static int
num_digits(int number)
{
	int		number_of_digits;
	int		dividend;

	number_of_digits = 1;
	dividend = number/10;
	while (dividend > 0) {
		number_of_digits++;
		dividend = dividend/10;
	}
	return (number_of_digits);
}
