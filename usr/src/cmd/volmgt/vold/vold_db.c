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
 * Copyright (c) 1992 by Sun Microsystems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdlib.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<dlfcn.h>

#include	"vold.h"
#include	"db.h"

#define	DB_ALLOC_CHUNK	10

static struct dbops	*default_dbops;
static struct dbops	**dbsw;
static int		ndbs = 0;
static int		nallocdbs = 0;



/*
 * Called from the database to add a new dbop into the list.
 * The first valid database seen is the "default" database.
 */
void
db_new(struct dbops *dop)
{
	int		i, na;
	struct dbops	**ndbsw;

	/*
	 * return if we've already seen this guy.
	 */

	for (i = 0; i < ndbs; i++)
		if (dbsw[i] == dop)
			return;

	if (ndbs == nallocdbs) {
		if (dbsw == 0) {
			nallocdbs = DB_ALLOC_CHUNK;
			dbsw = (struct dbops **)calloc(nallocdbs,
				sizeof (struct dbops *));
		} else {
			na = nallocdbs;
			nallocdbs += DB_ALLOC_CHUNK;
			ndbsw = (struct dbops **)calloc(nallocdbs,
				sizeof (struct dbops *));
			for (i = 0; i < na; i++)
				ndbsw[i] = dbsw[i];
			free(dbsw);
			dbsw = ndbsw;
		}
	}

	dbsw[ndbs++] = dop;
	if (default_dbops == NULL)
		default_dbops = dop;
}



/*
 * Look through all the databases to see if there are any
 * new things in the "dvn" directory.
 */
void
db_lookup(vvnode_t *dvn)
{
	int		i;
	extern char	*vold_config;

	if (default_dbops == NULL) {
		fatal(gettext("No databases configured in; check %s\n"),
			vold_config);
		/*NOTREACHED*/
	}
	/*
	 * node_startupdate and node_endupdate will remember what was
	 * added, and remove extra stuff that wasn't found in the
	 * database.
	 */
	node_startupdate(dvn);

	for (i = 0; i < ndbs; i++)
		(*dbsw[i]->dop_lookup)(dvn);

	node_endupdate(dvn);
}

/*
 * Ask the databases to setup root for us.
 */
void
db_root()
{
	int	i;

	for (i = 0; i < ndbs; i++) {
		(*dbsw[i]->dop_root)();
		if (root != NULL) {
			return;
		}
	}
	/*
	 * somebody lied about having core directories...
	 */
	if (root == NULL) {
		node_setup();
	}
}

/*
 * Sync changes made to the object up with the database.
 */
bool_t
db_update(obj_t *obj)
{
	if (obj->o_dbops == NULL) {
		obj->o_dbops = default_dbops;
	}

	return ((*obj->o_dbops->dop_update)(obj));
}

/*
 * Add a new object to the database.  If uniq == TRUE,
 * don't return an error for a name conflict, just fix
 * it.
 */
bool_t
db_add(obj_t *obj)
{
	if (obj->o_dbops == NULL) {
		obj->o_dbops = default_dbops;
	}

	return ((*obj->o_dbops->dop_add)(obj));
}


/*
 * Remove an object from the database.
 */
bool_t
db_remove(obj_t *obj)
{
	extern bool_t	node_tmpobj(obj_t *);


	if (node_tmpobj(obj)) {
		return (TRUE);
	}

	if (obj->o_dbops == NULL) {
		obj->o_dbops = default_dbops;
	}

	return ((*obj->o_dbops->dop_remove)(obj));
}


/*
 * Look through the databases to see if we have this
 * label anywhere.
 */
vol_t *
db_findlabel(char *mtype, label *la)
{
	vol_t	*v;
	int	i;

	for (i = 0; i < ndbs; i++) {
		v = (*dbsw[i]->dop_findlabel)(mtype, la);
		if (v) {
			v->v_obj.o_dbops = dbsw[i];
			return (v);
		}
	}
	return ((vol_t *)NULL);
}


/*
 * Look through the databases to see if anyone is using this key.
 */
bool_t
db_testkey(char *mtype, char *ltype, char *key)
{
	int	i;


	for (i = 0; i < ndbs; i++) {
		if (dbsw[i]->dop_testkey == NULL) {
			continue;
		}
		if ((*dbsw[i]->dop_testkey)(mtype, ltype, key) == TRUE) {
			return (TRUE);
		}
	}

	return (FALSE);
}


/*
 * return how many databases are configured
 */
int
db_configured_cnt(void)
{
	return (ndbs);
}
