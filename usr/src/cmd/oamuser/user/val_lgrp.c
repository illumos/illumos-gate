/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2013 RackTop Systems.
 */


#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/param.h>
#include	<unistd.h>
#include	<users.h>
#include	<userdefs.h>
#include	"messages.h"

extern void exit();
extern char *strtok();

static gid_t *grplist;
static int ngroups_max = 0;

/* Validate a list of groups */
int	**
valid_lgroup(char *list, gid_t gid)
{
	int n_invalid = 0, i = 0, j;
	char *ptr;
	struct group *g_ptr;
	int warning;
	int dup_prim = 0; /* we don't duplicate our primary as a supplemental */

	if( !list || !*list )
		return( (int **) NULL );

	if (ngroups_max == 0) {
		ngroups_max = sysconf(_SC_NGROUPS_MAX);
		grplist = malloc((ngroups_max + 1) * sizeof (gid_t));
	}

	while ((ptr = strtok((i || n_invalid || dup_prim)? NULL: list, ","))) {

		switch (valid_group(ptr, &g_ptr, &warning)) {
		case INVALID:
			errmsg( M_INVALID, ptr, "group id" );
			n_invalid++;
			break;
		case TOOBIG:
			errmsg( M_TOOBIG, "gid", ptr );
			n_invalid++;
			break;
		case UNIQUE:
			errmsg( M_GRP_NOTUSED, ptr );
			n_invalid++;
			break;
		case NOTUNIQUE:
			/* ignore duplicated primary */
			if (g_ptr->gr_gid == gid) {
				if (!dup_prim)
					dup_prim++;
				continue;
			}

			if( !i )
				grplist[ i++ ] = g_ptr->gr_gid;
			else {
				/* Keep out duplicates */
				for( j = 0; j < i; j++ ) 
					if( g_ptr->gr_gid == grplist[j] )
						break;

				if( j == i )
					/* Not a duplicate */
					grplist[i++] = g_ptr->gr_gid;
			}
			break;
				
		}
		if (warning)
			warningmsg(warning, ptr);

		if( i >= ngroups_max ) {
			errmsg( M_MAXGROUPS, ngroups_max );
			break;
		}
	}

	/* Terminate the list */
	grplist[ i ] = -1;

	if( n_invalid )
		exit( EX_BADARG );

	return( (int **)grplist );
}
