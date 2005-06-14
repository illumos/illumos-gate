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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<syslog.h>
#include	<errno.h>
#include	<string.h>
#include	<pwd.h>
#include	<grp.h>
#include	<rpc/rpc.h>
#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/wait.h>
#include	<sys/time.h>
#include	<sys/stat.h>
#include	<rpcsvc/nfs_prot.h>
#include	<netinet/in.h>
#include	<sys/mnttab.h>
#include	<sys/mntent.h>
#include	<sys/mount.h>
#include	<netdb.h>
#include	<sys/signal.h>
#include	<sys/file.h>
#include	<setjmp.h>
#include	<netconfig.h>
#include	<locale.h>
#include	<ulimit.h>
#include	<rpcsvc/nis.h>
#include	<sys/systeminfo.h>

#include	"vold.h"
#include	"db_nis.h"


/* extern routines */
extern void	obj_free(obj_t *);

static void 	nis_db_lookup(vvnode_t *);
static void	nis_db_root();
static bool_t 	nis_db_update(obj_t *);
static bool_t 	nis_db_add(obj_t *);
static bool_t 	nis_db_remove(obj_t *);
static vol_t	*nis_db_findlabel(char *, label *);
static bool_t	nis_db_testkey(char *, char *, char *);

static struct dbops nis_dbops = {
	nis_db_lookup, 		/* dop_lookup */
	nis_db_root, 		/* dop_root */
	nis_db_update, 		/* dop_update */
	nis_db_add, 		/* dop_add */
	nis_db_remove, 		/* dop_remove */
	nis_db_findlabel, 	/* dop_findlabel */
	nis_db_testkey, 	/* dop_testkey */
	"nis+",			/* dop_name */
};

static bool_t	nis_db_needread();
static bool_t	nisobj_assignid(obj_t *obj);
static void	nisobj_merge(obj_t *to, obj_t *from);
static u_int	version_get();
static void	version_set(u_int vers);
static u_longlong_t nisobj_makeup(u_longlong_t);
static void	nisobj_clearup(u_int item, obj_t *obj);
static void	timeval_xdr(enum xdr_op op, struct timeval *tv,
			    void **res, size_t *sz);

/*
 * Convert a nis+ object to an obj_t
 */
static obj_t	*nisobj_to_obj(nis_object *);

static void 	convert_obj(int, obj_t *, int, void *);


#define	CONV_GET	1	/* return a pointer to the data */

#define	CONV_PUT	2
				/*
				 * convert the nis+ table format into a
				 * local storage (vol_t) format
				 */

#define	CONV_LOCALPUT	3
				/*
				 * convert a local description (e.g. a struct
				 * timeval *) into a vol_t format.  Update
				 * a flag to show something has changed.
				 */
#define	CONV_FREE	4
				/*
				 * Free space allocated as a result of
				 * a "put" operation.
				 */
#define	CONV_MERGE	5
				/*
				 * Merge two object in some reasonable
				 * way.
				 */
/*
 * This is what is returned from a CONV_GET operation.
 */
struct conv_get {
	void 	*data;
	size_t	size;
};

static char	*dtabname;	/* name of the data table */
static char	*ctabname;	/* name of the control table */

static char	*nis_directory;


#define	DB_W_RIGHTS	(NIS_READ_ACC)
#define	DB_N_RIGHTS	((NIS_READ_ACC) << 24)
#define	DB_G_RIGHTS	((NIS_READ_ACC | NIS_MODIFY_ACC |\
			NIS_CREATE_ACC | NIS_DESTROY_ACC) << 8)
#define	DB_O_RIGHTS	((NIS_READ_ACC | NIS_MODIFY_ACC |\
			NIS_CREATE_ACC | NIS_DESTROY_ACC) << 16)

#define	DB_TABLE_RIGHTS	(DB_W_RIGHTS|DB_N_RIGHTS|DB_G_RIGHTS|DB_O_RIGHTS)


/*
 * Set up the database.  If there aren't data and control tables
 * there, build them.
 */
bool_t
db_init()
{
	nis_result	*res;
	nis_object	no;
	table_col	*tc;
	table_obj	*to = &no.zo_data.objdata_u.ta_data;
	entry_col	*ec;
	entry_obj	*eo = &no.zo_data.objdata_u.en_data;
	char		namebuf[NIS_MAXNAMELEN * 2];
	char		groupname[NIS_MAXNAMELEN];
	int		i;
	int		found_ctl, found_dat;



	nis_directory = nis_local_directory();

	if (*volume_group == '\0') {
		(void) sprintf(namebuf, "%s.%s", DTABNAME, VOLDIR);
		dtabname = strdup(namebuf);

		(void) sprintf(namebuf, "%s.%s", CTABNAME, VOLDIR);
		ctabname = strdup(namebuf);
	} else {
		(void) sprintf(namebuf, "%s.%s.%s", DTABNAME, volume_group,
		    VOLDIR);
		dtabname = strdup(namebuf);

		(void) sprintf(namebuf, "%s.%s.%s", CTABNAME, volume_group,
		    VOLDIR);
		ctabname = strdup(namebuf);
	}
	/*
	 * Just see if the directory is there
	 * This allows us to print a meaningful message if the user
	 * hasn't created all the right stuff.
	 */
	if (*volume_group == NULLC) {
		(void) sprintf(namebuf, "%s.%s", VOLDIR, nis_directory);
	} else {
		(void) sprintf(namebuf, "%s.%s.%s",
		    volume_group, VOLDIR, nis_directory);
	}

	res = nis_lookup(namebuf, 0);
	if (res->status != NIS_SUCCESS) {
		if (res->status == NIS_NOTFOUND) {
			warning(gettext(
"Nis object %s was not found, it needs to be createed with nismkdir\n"),
			    namebuf);
			nis_freeresult(res);
			return (FALSE);
		} else {
			warning(gettext("Nis error %s on object %s\n"),
			    nis_sperrno(res->status), namebuf);
			nis_freeresult(res);
			return (FALSE);
		}
	}
	nis_freeresult(res);

	/* look for the control table */
	(void) sprintf(namebuf, "%s.%s", ctabname, nis_directory);

	res = nis_lookup(namebuf, 0);
	if (res->status == NIS_SUCCESS) {
		found_ctl = 1;
	} else if (res->status == NIS_NOTFOUND) {
		found_ctl = 0;
	} else {

		/* nis returned some horrible error */
		warning(gettext(
		    "nis_db_init lookup control error: nis+ says '%s'"),
		    nis_sperrno(res->status));
		nis_freeresult(res);
		return (FALSE);
	}

	nis_freeresult(res);

	/* look for the data table */
	(void) sprintf(namebuf, "%s.%s", dtabname, nis_directory);

	res = nis_lookup(namebuf, 0);
	if (res->status == NIS_SUCCESS) {
		found_dat = 1;
	} else if (res->status == NIS_NOTFOUND) {
		found_dat = 0;
	} else {

		/* nis returned some horrible error */
		warning(gettext(
		    "nis_db_init lookup data error: nis+ says '%s'"),
		    nis_sperrno(res->status));
		nis_freeresult(res);
		return (FALSE);
	}

	nis_freeresult(res);

#ifdef DEBUG
	/*
	 * let them know if we have one but not the other.
	 */
	if (found_ctl != found_dat) {
		warning("nis_db_init: Your %s table was missing, ",
		    found_ctl ? "volumes" : "control");
		warning("but your %s table was there.  Could mean",
		    found_ctl ? "control" : "volumes");
		warning("big trouble.\n");
	}
#endif	/* DEBUG */
	(void) sprintf(groupname, "%s.%s", nisplus_group, nis_directory);

	/* control table */

	if (found_ctl == 0) {
		(void) sprintf(namebuf, "%s.%s", ctabname, nis_directory);
		(void) memset(&no, 0, sizeof (nis_object));
		tc = (table_col *)calloc(ncols_control, sizeof (table_col));
		no.zo_data.zo_type = NIS_TABLE_OBJ;
		no.zo_access = DB_TABLE_RIGHTS;
		no.zo_owner = nis_local_principal();
		no.zo_group = groupname;
		to->ta_type = CTABTYPE;
		to->ta_maxcol = ncols_control;
		to->ta_sep = NISSEP;
		to->ta_cols.ta_cols_len = ncols_control;
		to->ta_cols.ta_cols_val = tc;

		for (i = 0; i < ncols_control; i++) {
			tc[i].tc_name = (char *)CT_NAME(i);
			tc[i].tc_flags = CT_TFLAG(i);
			tc[i].tc_rights = DB_TABLE_RIGHTS;
		}

		res = nis_add(namebuf, &no);

		if (res->status != NIS_SUCCESS) {
#ifdef DEBUG
			nis_print_object(&no);
#endif
			warning(gettext(
			    "nis_db_init add ctl table error: nis+ says '%s'"),
			    nis_sperrno(res->status));
			nis_freeresult(res);
			free(tc);
			return (FALSE);
		}
		nis_freeresult(res);
		free(tc);

		/*
		 * Now, we need to initialize the control table with some
		 * good poop.
		 */
		(void) memset(&no, 0, sizeof (nis_object));
		no.zo_owner = nis_local_principal();
		no.zo_data.zo_type = NIS_ENTRY_OBJ;

		ec = (entry_col *)calloc(ncols_control, sizeof (entry_col));
		eo->en_cols.en_cols_val = ec;
		eo->en_cols.en_cols_len = ncols_control;
		eo->en_type = CTABTYPE;

		/* name: really just a place holder */
		i = 0;
		ec[i].ec_value.ec_value_val = strdup(CTAB_NAME_VAL);
		ec[i].ec_value.ec_value_len =
		    strlen(ec[i].ec_value.ec_value_val)+1;
		ec[i].ec_flags = CT_EFLAG(i);

		/* xid */
		i++;
		ec[i].ec_value.ec_value_val = strdup("1");
		ec[i].ec_value.ec_value_len =
		    strlen(ec[i].ec_value.ec_value_val)+1;
		ec[i].ec_flags = CT_EFLAG(i);

		/* id */
		i++;
		ec[i].ec_value.ec_value_val = strdup("1");
		ec[i].ec_value.ec_value_len =
		    strlen(ec[i].ec_value.ec_value_val)+1;
		ec[i].ec_flags = CT_EFLAG(i);

		/* lock */
		i++;
		ec[i].ec_value.ec_value_val = strdup(CTAB_LOCK_UNLOCKED);
		ec[i].ec_value.ec_value_len =
		    strlen(ec[i].ec_value.ec_value_val)+1;
		ec[i].ec_flags = CT_EFLAG(i);

		res = nis_add_entry(namebuf, &no, 0);
		if (res->status != NIS_SUCCESS) {
#ifdef DEBUG
			nis_print_object(&no);
#endif
			warning(gettext(
			    "nis_db_init add ctl table error: nis+ says '%s'"),
			    nis_sperrno(res->status));
			nis_freeresult(res);
			free(ec);
			return (FALSE);
		}
		nis_freeresult(res);
		free(ec);

	}
	/* Create the data table */
	if (found_dat == 0) {
		(void) sprintf(namebuf, "%s.%s", dtabname, nis_directory);
		(void) memset(&no, 0, sizeof (nis_object));
		tc = (table_col *)calloc(ncols_data, sizeof (table_col));
		no.zo_data.zo_type = NIS_TABLE_OBJ;
		no.zo_access = DB_TABLE_RIGHTS;
		no.zo_owner = nis_local_principal();
		no.zo_group = groupname;
		to->ta_type = DTABTYPE;
		to->ta_maxcol = ncols_data;
		to->ta_sep = NISSEP;
		to->ta_cols.ta_cols_len = ncols_data;
		to->ta_cols.ta_cols_val = tc;

		for (i = 0; i < ncols_data; i++) {
			tc[i].tc_name = (char *)DT_NAME(i);
			tc[i].tc_flags = DT_TFLAG(i);
			tc[i].tc_rights = DB_TABLE_RIGHTS;
		}

		res = nis_add(namebuf, &no);

		if (res->status != NIS_SUCCESS) {
#ifdef DEBUG
			nis_print_object(&no);
#endif
			warning(gettext(
			"nis_db_init add data table error: nis+ says '%s'"),
				nis_sperrno(res->status));
			nis_freeresult(res);
			free(tc);
			return (FALSE);
		}

	}
	(void) db_new(&nis_dbops);
	return (TRUE);
}


/*
 * Pass in the parent of the vnode that we want to lookup.
 * In essence, this can be thought of as "we're going to do
 * a lookup in this directory, make sure it's in sync with
 * the database."
 */

void
nis_db_lookup(vvnode_t *dvn)
{
	extern void	node_setupdated(vvnode_t *, struct dbops *);
	char		namebuf[NIS_MAXNAMELEN * 2];
	nis_result	*res;
	nis_object	*no;
	char		*path, *np;
	int		i;
	u_int		err;
	obj_t		*obj;
	vvnode_t	*vn;



	if (dvn->vn_obj->o_type != VV_DIR) {
		/*
		 * this is okay since this really means we
		 * are poking around in a volume with partitions.
		 */
		return;
	}

	/*
	 * If the directory already has stuff, and we don't
	 * need to check with the database, just return.
	 */
	if (dvn->vn_child && !nis_db_needread()) {
		node_setupdated(dvn, &nis_dbops);
		if (dvn->vn_twin) {
			node_setupdated(dvn->vn_twin, &nis_dbops);
		}
		return;
	}

	path = path_make(dvn);

	/*
	 * Oh god, what an ugly pile of architecture.
	 */
	if ((strncmp(&path[1], DSKNAME, strlen(DSKNAME)) == 0) ||
	    (strncmp(&path[1], MTNAME, strlen(MTNAME)) == 0)) {
		np = malloc(strlen(path) + 2);
		np[0] = '/';
		np[1] = 'r';
		(void) strcpy(&np[2], &path[1]);
		free(path);
		path = np;
	}

	(void) sprintf(namebuf, "[%s=%s], %s.%s",
	    DT_NAME(DTAB_DIR), path, dtabname, nis_directory);

	res = nis_list(namebuf, 0, 0, 0);
	if (res->status == NIS_NOTFOUND) {
		free(path);
		nis_freeresult(res);
		debug(1, "nis_db_lookup: nothing found in '%s'\n", namebuf);
		return;
	} else if (res->status != NIS_SUCCESS) {
		debug(1, "nis_db_lookup error on '%s': nis+ says '%s'\n",
		    path, nis_sperrno(res->status));
		/*
		 * we do the setupdated here so we don't lose all of
		 * our stuff if nis+ flakes out for a while.
		 */
		node_setupdated(dvn, &nis_dbops);
		if (dvn->vn_twin) {
			node_setupdated(dvn->vn_twin, &nis_dbops);
		}
		free(path);
		nis_freeresult(res);
		return;
	}

	for (i = 0; i < NIS_RES_NUMOBJ(res); i++) {
		no = &NIS_RES_OBJECT(res)[i];
		obj = nisobj_to_obj(no);
		if (strcmp(obj->o_name, "") == 0 &&
		    strcmp(obj->o_dir, "") == 0) {
			obj_free(obj);
			continue;
		}
		vn = node_mkobj(dvn, obj, 0, &err);
		if (err != 0) {
			debug(1, "%s/%s already there (%d)\n",
			    obj->o_dir, obj->o_name, err);

			if (obj->o_xid != vn->vn_obj->o_xid) {
				nisobj_merge(vn->vn_obj, obj);
			}
			obj_free(obj);
		}
	}

	free(path);
	nis_freeresult(res);

	if (dvn->vn_twin) {
		node_setupdated(dvn->vn_twin, &nis_dbops);
	}
}


/*
 * Find root.
 */
void
nis_db_root()
{
	char		namebuf[NIS_MAXNAMELEN * 2];
	nis_result	*res;
	nis_object	*no;
	int		i;
	obj_t		*obj;


	if (root != NULL) {
		return;
	}

	(void) sprintf(namebuf, "[%s=%s], %s.%s",
	    DT_NAME(DTAB_DIR), "", dtabname, nis_directory);

	res = nis_list(namebuf, 0, 0, 0);
	if (res->status == NIS_NOTFOUND) {
		nis_freeresult(res);
		return;
	} else if (res->status != NIS_SUCCESS) {
		debug(1, "nis_db_lookup error on 'root': nis+ says '%s'\n",
		    nis_sperrno(res->status));
		nis_freeresult(res);
		return;
	}

	for (i = 0; i < NIS_RES_NUMOBJ(res); i++) {
		no = &NIS_RES_OBJECT(res)[i];
		obj = nisobj_to_obj(no);
		if ((strcmp(obj->o_name, "")  == 0) &&
		    (strcmp(obj->o_dir, "") == 0)) {
			node_root((dirat_t *)obj);
		} else {
			obj_free(obj);
		}
	}

	nis_freeresult(res);
}

#define	NIS_DB_UPDATE_MAXRECUR	5

/*
 * write the object out to the database.  if it's been changed in the
 * database, to merge the change.  The only reason for failure
 * is if the object moved or was removed.
 */
bool_t
nis_db_update(obj_t *obj)
{
	extern bool_t	node_tmpobj(obj_t *);
	extern void	obj_unlink(obj_t *);
	extern void	obj_copy(obj_t *, obj_t *);
	char		namebuf[NIS_MAXNAMELEN * 2];
	char		namebuf1[NIS_MAXNAMELEN * 2];
	nis_result	*res, *res1;
	nis_object	*no, *no1;
	entry_obj	*eo;
	entry_col	*ec;
	int		i;
	obj_t		*nobj;
	struct conv_get	cg;
	static u_int	nis_db_update_recurse;
	u_longlong_t	nis_upmask;


	/* don't even bother looking for temporary objects */
	if (node_tmpobj(obj)) {
		return (TRUE);
	}

	(void) sprintf(namebuf, "[%s=%llu], %s.%s",
	    DT_NAME(DTAB_ID), obj->o_id, dtabname, nis_directory);

	res = nis_list(namebuf, 0, 0, 0);
	if (res->status == NIS_NOTFOUND) {
		warning(gettext(
		    "nis_db_update: %s not found in database -- removing\n"),
		    obj->o_name);
		obj_unlink(obj);
		nis_freeresult(res);
		return (FALSE);
	} else if (res->status != NIS_SUCCESS) {
		warning(gettext(
		    "nis_db_update error on '%s': nis+ says '%s'\n"),
		    obj->o_name, nis_sperrno(res->status));
		nis_freeresult(res);
		return (FALSE);
	}
	if (NIS_RES_NUMOBJ(res) > 1) {
		/* very very bad */
		warning(gettext(
			"nis_db_update: database corrupted, run volck\n"));
		fatal(gettext(
			"nis_db_update: more than one object with id %d\n"),
			obj->o_id);
		/*NOTREACHED*/
	}
	no = NIS_RES_OBJECT(res);
	eo = &no->zo_data.objdata_u.en_data;
	ec = eo->en_cols.en_cols_val;
	nobj = nisobj_to_obj(no);

	if (nobj->o_xid != obj->o_xid) {
		/* conflict!  gag. */
		nisobj_merge(obj, nobj);
	}

	nis_upmask = nisobj_makeup(obj->o_upmask);

	/* if we're changing the name or directory... */
	if (nis_upmask & (1<<DTAB_NAME) || nis_upmask & (1<<DTAB_DIR)) {
		/* make sure it doesn't already exist */
		(void) sprintf(namebuf1, "[%s=%s, %s=%s], %s.%s",
		    DT_NAME(DTAB_NAME), obj->o_name, DT_NAME(DTAB_DIR),
		    obj->o_dir, dtabname, nis_directory);

		res1 = nis_list(namebuf1, 0, 0, 0);
		if (res1->status == NIS_SUCCESS) {
			no1 = NIS_RES_OBJECT(res1);
			if (strtoll((char *)ENTRY_VAL(no1, DTAB_ID), 0, 0) !=
			    obj->o_id) {
				nis_freeresult(res);
				nis_freeresult(res1);
				obj_free(nobj);
				return (FALSE);
			}
		}
		nis_freeresult(res1);
	}

	/*
	 * Take the items noted as needing updating on the object,
	 * and convert them to numbers for our table.
	 */
	obj->o_xid++;
	nis_upmask |= 1<<DTAB_XID;
	for (i = 0; i < ncols_data; i++) {
		if (nis_upmask & (1<<i)) {
			/*
			 * Note that we only have to convert objects
			 * that have actually changed.
			 */
			convert_obj(CONV_GET, obj, i, &cg);
			/* XXX do we have to free the ec_value_val? */
			ec[i].ec_value.ec_value_val = cg.data;
			ec[i].ec_value.ec_value_len = cg.size;
			ec[i].ec_flags = DT_EFLAG(i)|EN_MODIFIED;
		}
	}

	res1 = nis_modify_entry(namebuf, no, MOD_SAMEOBJ);
	if (res1->status == NIS_NOTSAMEOBJ) {

		/*
		 * I assume this means that the object was
		 * modified between the read and the write.
		 * I'll just recurse here.  I put a limit
		 * on the number of recursions.  If the max
		 * number is reached, we just take the object
		 * from the database and go from there.
		 */
		debug(1, "nis_db_update: modfailed: recursing\n");
		nis_db_update_recurse++;
		if (nis_db_update_recurse > NIS_DB_UPDATE_MAXRECUR) {
			obj_copy(obj, nobj);
		} else {
			(void) nis_db_update(obj);
		}
		nis_db_update_recurse--;
	} else if (res1->status != NIS_SUCCESS) {
		debug(1, gettext(
		    "nis_db_update error on '%s': nis+ says '%s'\n"),
		    obj->o_name, nis_sperrno(res1->status));
		obj->o_xid--;
		nis_freeresult(res);
		nis_freeresult(res1);
		obj_free(nobj);
		return (FALSE);
	}

	nis_freeresult(res);
	nis_freeresult(res1);
	obj->o_upmask = 0;	/* we've written all our changes out */
#ifdef	WHY_IS_THIS_NOT_USED
	obj_free(nobj);
#endif
	return (TRUE);
}


/*
 * need to be able to add:
 *	volumes
 *	directories
 *	symlinks
 *	links
 */
bool_t
nis_db_add(obj_t *obj)
{
	char		namebuf[NIS_MAXNAMELEN * 2];
	nis_result	*res;
	nis_object	no;
	entry_obj	*eo = &no.zo_data.objdata_u.en_data;
	entry_col	*ec;
	int		i;
	struct conv_get	cg;


	/* assign id */
	if (nisobj_assignid(obj) == FALSE)
		return (FALSE);

	obj->o_xid = 1;		/* starting xid */

	(void) sprintf(namebuf, "[%s=%s, %s=%s], %s.%s",
	    DT_NAME(DTAB_NAME), obj->o_name,
	    DT_NAME(DTAB_DIR), obj->o_dir,
	    dtabname, nis_directory);

	(void) memset(&no, 0, sizeof (nis_object));
	no.zo_owner = nis_local_principal();
	no.zo_data.zo_type = NIS_ENTRY_OBJ;

	ec = (entry_col *)calloc(ncols_data, sizeof (entry_col));

	eo->en_cols.en_cols_val = ec;
	eo->en_cols.en_cols_len = ncols_data;
	eo->en_type = DTABTYPE;

	for (i = 0; i < ncols_data; i++) {
		convert_obj(CONV_GET, obj, i, &cg);
		ec[i].ec_value.ec_value_val = cg.data;
		ec[i].ec_value.ec_value_len = cg.size;
		ec[i].ec_flags = DT_EFLAG(i);
	}

	res = nis_add_entry(namebuf, &no, 0);
	if (res->status != NIS_SUCCESS) {
		debug(1, gettext("nis_db_add error on '%s': nis+ says '%s'\n"),
			obj->o_name, nis_sperrno(res->status));
		nis_freeresult(res);
		free(ec);
		return (FALSE);
	}
	nis_freeresult(res);
	free(ec);
	return (TRUE);
}

bool_t
nis_db_remove(obj_t *obj)
{
	char		namebuf[NIS_MAXNAMELEN * 2];
	nis_result	*res;

	(void) sprintf(namebuf, "[%s=%llu], %s.%s",
	    DT_NAME(DTAB_ID), obj->o_id, dtabname, nis_directory);

	res = nis_remove_entry(namebuf, 0, 0);
	if (res->status != NIS_SUCCESS) {
		warning(gettext(
		    "nis_db_remove error on '%s': nis+ says '%s'\n"),
		    namebuf, nis_sperrno(res->status));
		nis_freeresult(res);
		return (FALSE);
	}
	nis_freeresult(res);
	return (TRUE);
}

static vol_t *
nis_db_findlabel(char *mtype, label *la)
{
	char		namebuf[NIS_MAXNAMELEN * 2];
	nis_result	*res;
	int		i;
	label		la1;
	nis_object	*no;
	vol_t		*v;
	char		*key;
	void		*d;

	key = label_key(la);
	(void) sprintf(namebuf, "[%s=%s, %s=%s, %s=%s], %s.%s",
	    DT_NAME(VOL_LABTYPE), label_ident(la->l_type),
	    DT_NAME(VOL_MEDTYPE), mtype,
	    DT_NAME(VOL_KEY), key,
	    dtabname, nis_directory);

	res = nis_list(namebuf, 0, 0, 0);
	if (res->status != NIS_SUCCESS) {
		nis_freeresult(res);
		return (NULL);
	}
	debug(6, "flabel: got %d hits on <labtype %s, medtype %s, key %s>\n",
	    NIS_RES_NUMOBJ(res), label_ident(la->l_type), mtype, key);
	free(key);

	for (i = 0; i < NIS_RES_NUMOBJ(res); i++) {
		no = &NIS_RES_OBJECT(res)[i];
		la1.l_type = label_type((char *)ENTRY_VAL(no, VOL_LABTYPE));
		la1.l_label = 0;
		debug(6, "flabel: checking against %s\n",
			(char *)ENTRY_VAL(no, DTAB_NAME));
		d = (void *)ENTRY_VAL(no, VOL_LABEL);
		label_xdr(&la1, XDR_DECODE, &d);
		if (label_compare(la, &la1) == TRUE) {
			v = (vol_t *)nisobj_to_obj(no);
			nis_freeresult(res);
			return (v);
		}
	}
	nis_freeresult(res);
	return (NULL);
}

static bool_t
nis_db_testkey(char *mtype, char *ltype, char *key)
{
	char		namebuf[NIS_MAXNAMELEN * 2];
	nis_result	*res;

	(void) sprintf(namebuf, "[%s=%s, %s=%s, %s=%s], %s.%s",
	    DT_NAME(VOL_LABTYPE), ltype,
	    DT_NAME(VOL_MEDTYPE), mtype,
	    DT_NAME(VOL_KEY), key,
	    dtabname, nis_directory);

	res = nis_list(namebuf, 0, 0, 0);
	if (res->status != NIS_SUCCESS) {
		nis_freeresult(res);
		return (FALSE);
	}
	debug(6, "testkey: got %d hits on <labtype %s, medtype %s, key %s>\n",
	    NIS_RES_NUMOBJ(res), ltype, mtype, key);

	nis_freeresult(res);

	return (TRUE);
}

/*
 * Convert a generic object update mask to a nis object update mask.
 */
static u_longlong_t
nisobj_makeup(u_longlong_t objmask)
{
	u_longlong_t	res = 0;

	if (objmask & OBJ_UP_NAME)
		res |= (1<<DTAB_NAME);
	if (objmask & OBJ_UP_DIR)
		res |= (1<<DTAB_DIR);
	if (objmask & OBJ_UP_UID)
		res |= (1<<DTAB_UID);
	if (objmask & OBJ_UP_GID)
		res |= (1<<DTAB_GID);
	if (objmask & OBJ_UP_MODE)
		res |= (1<<DTAB_MODE);
	if (objmask & OBJ_UP_ATIME)
		res |= (1<<DTAB_ATIME);
	if (objmask & OBJ_UP_MTIME)
		res |= (1<<DTAB_MTIME);
	if (objmask & OBJ_UP_CTIME)
		res |= (1<<DTAB_CTIME);
	if (objmask & OBJ_UP_NLINKS)
		res |= (1<<DTAB_NLINKS);
	if (objmask & OBJ_UP_FLAGS)
		res |= (1<<DTAB_PROPS);
	if (objmask & OBJ_UP_LABEL)
		res |= (1<<VOL_LABTYPE)|(1<<VOL_LABEL)|(1<<VOL_KEY);
	if (objmask & OBJ_UP_LOC)
		res |= (1<<VOL_LOCATION);
	return (res);
}

/*
 * Given a nis+ "item" number, clear the o_upmask entry that maps to it.
 */
static void
nisobj_clearup(u_int item, obj_t *obj)
{
	switch (item) {
	case DTAB_NAME:
		obj->o_upmask &= ~OBJ_UP_NAME;
		break;
	case DTAB_DIR:
		obj->o_upmask &= ~OBJ_UP_DIR;
		break;
	case DTAB_UID:
		obj->o_upmask &= ~OBJ_UP_UID;
		break;
	case DTAB_GID:
		obj->o_upmask &= ~OBJ_UP_GID;
		break;
	case DTAB_MODE:
		obj->o_upmask &= ~OBJ_UP_MODE;
		break;
	case DTAB_ATIME:
		obj->o_upmask &= ~OBJ_UP_ATIME;
		break;
	case DTAB_MTIME:
		obj->o_upmask &= ~OBJ_UP_MTIME;
		break;
	case DTAB_CTIME:
		obj->o_upmask &= ~OBJ_UP_CTIME;
		break;
	case DTAB_NLINKS:
		obj->o_upmask &= ~OBJ_UP_NLINKS;
		break;
	case DTAB_PROPS:
		obj->o_upmask &= ~OBJ_UP_FLAGS;
		break;
	case VOL_LABEL:
		obj->o_upmask &= ~OBJ_UP_LABEL;
		break;
	case VOL_LOCATION:
		obj->o_upmask &= ~OBJ_UP_LOC;
		break;
	default:
		debug(1, "nisobj_clearup: unknown item %d\n", item);
		break;
	}
}


#define	NIS_DB_READTIME	10

/*
 * Check to see if we need to look at the database.
 *
 * - only read from the database once per rpc or once per
 * 	second, whichever is less frequent.  Recall that we only
 *	update current_time on every rpc call.
 * - read the global xid to see if anything has changed.
 */
static bool_t
nis_db_needread()
{
	static struct timeval	last_time = {0, 0};


	if ((current_time.tv_sec - last_time.tv_sec) <= NIS_DB_READTIME) {
		return (FALSE);
	}

	last_time = current_time;

	return (TRUE);
}


void
nis_db_free(obj_t *obj)
{
	int	i;

	if (obj->o_type == VV_CHR || obj->o_type == VV_BLK) {
		/*
		 * This cleans up any mappings we might have,
		 * frees the minor numbers we've allocated, etc.
		 */
		(void) dev_devmapfree((vol_t *)obj);
	}

	for (i = 0; i < ncols_data; i++) {
		convert_obj(CONV_FREE, obj, i, 0);
	}
	free(obj);
}


#define	NIS_DB_SLPTIME	1
#define	MAX_RETRYS	10


static bool_t
nisobj_assignid(obj_t *obj)
{
	char		namebuf[NIS_MAXNAMELEN * 2];
	char		numbuf[NIS_MAXNAMELEN];
	nis_result	*res, *res1;
	nis_object	*no;
	entry_obj	*eo;
	entry_col	*ec;
	u_longlong_t	current_id;
	int		retry_count = 0;


	debug(5, "nisobj_assignid\n");

	(void) sprintf(namebuf, "[%s=%s], %s.%s",
	    CT_NAME(CTAB_NAME), CTAB_NAME_VAL,
	    ctabname, nis_directory);

	/*CONSTCOND*/
	while (1) {
		retry_count++;
		res = nis_list(namebuf, 0, 0, 0);
		if (res->status != NIS_SUCCESS) {
			warning(gettext(
			    "nisobj_assignid error on ctl: nis+ says '%s'\n"),
			    nis_sperrno(res->status));
			nis_freeresult(res);
			return (FALSE);
		}
		if (NIS_RES_NUMOBJ(res) > 1) {
			/* very very bad */
			warning(gettext("obj_id: db corrupted, run volck\n"));
			return (FALSE);
		}

		no = NIS_RES_OBJECT(res);
		current_id = strtoll((char *)ENTRY_VAL(no, CTAB_ID), 0, 0);
		eo = &no->zo_data.objdata_u.en_data;
		ec = eo->en_cols.en_cols_val;
		/* XXX probably need to free old ENTRY_VAL */
		(void) sprintf(numbuf, "%llu", current_id+1);
		ec[CTAB_ID].ec_value.ec_value_val = strdup(numbuf);

		ec[CTAB_ID].ec_value.ec_value_len =
		    strlen(ec[CTAB_ID].ec_value.ec_value_val)+1;
		ec[CTAB_ID].ec_flags = CT_EFLAG(CTAB_ID)|EN_MODIFIED;
		res1 = nis_modify_entry(namebuf, no, MOD_SAMEOBJ);
		if (res1->status == NIS_NOTSAMEOBJ) {
			/*
			 * I assume this means that the object was
			 * modified between the read and the write.
			 * We lost the race to the lock.  Loop.
			 */
			debug(1, "obj_id: lost race for id!\n");
			nis_freeresult(res);
			nis_freeresult(res1);
			continue;
		} else if (res1->status != NIS_SUCCESS) {
			warning(gettext(
				"obj_id error on control: nis+ says '%s'\n"),
				nis_sperrno(res1->status));
			nis_freeresult(res);
			nis_freeresult(res1);
			if (retry_count > MAX_RETRYS) {
				return (FALSE);
			}
			(void) sleep(NIS_DB_SLPTIME);
			continue;
		} else {
			/* everything is okay, we a good id */
			obj->o_id = current_id;
			nis_freeresult(res);
			nis_freeresult(res1);
			return (TRUE);
		}
	}
	/*NOTREACHED*/
}

/*
 * Do your best to merge these two objects.
 */
/*
 * Merge strategy:
 * If they are the same, don't do anything.
 * If our change is more recent (o_mtime) than the db object, overwite.
 * If our change is less recent, take the change and clear upmask bit.
 */
void
nisobj_merge(obj_t *to, obj_t *from)
{
	int	i;

	debug(1, "nisobj_merge: conflict on obj %s, id %llu\n",
		to->o_name, to->o_id);

	for (i = 0; i < ncols_data; i++) {
		convert_obj(CONV_MERGE, to, i, (void *)from);
	}
	/*
	 * At this point, the "to" object has an upmask that
	 * reflects only the changes that we want to make.
	 */
}

static obj_t *
nisobj_to_obj(nis_object *no)
{
	obj_t		o;
	entry_obj	*eo = &no->zo_data.objdata_u.en_data;
	entry_col	*ec = eo->en_cols.en_cols_val;
	int		i;
	vol_t		*v;
	dirat_t		*da;
	linkat_t	*la;
	symat_t		*sla;
	void		*vp;


	(void) memset(&o, 0, sizeof (obj_t));

	o.o_dbops = &nis_dbops;
	for (i = 0; i < DTAB_GEN_END+1; i++) {
		convert_obj(CONV_PUT, &o, i, ec[i].ec_value.ec_value_val);
	}
	switch (o.o_type) {
	case VV_BLK:
	case VV_CHR:
		v = (vol_t *)calloc(1, sizeof (vol_t));
		(void) memcpy(v, &o, sizeof (obj_t));
		vp = (void *)v;
		break;
	case VV_DIR:
		da = (dirat_t *)calloc(1, sizeof (dirat_t));
		(void) memcpy(da, &o, sizeof (obj_t));
		vp = (void *)da;
		break;
	case VV_LINK:
		la = (linkat_t *)calloc(1, sizeof (linkat_t));
		(void) memcpy(la, &o, sizeof (obj_t));
		vp = (void *)la;
		break;
	case VV_SYMLINK:
		sla = (symat_t *)calloc(1, sizeof (symat_t));
		(void) memcpy(sla, &o, sizeof (obj_t));
		vp = (void *)sla;
		break;
	default:
		fatal(gettext(
		    "nisobj_to_obj: unknown object from database (%d)\n"),
		    o.o_type);
		break;
	}
	for (i = DTAB_GEN_END+1; i < eo->en_cols.en_cols_len; i++) {
		convert_obj(CONV_PUT, vp, i, ec[i].ec_value.ec_value_val);
	}
	return ((obj_t *)vp);
}


static bool_t 	convert_vol(int, vol_t *, int, void *);
static bool_t 	convert_dir(int, dirat_t *, int, void *);
static bool_t 	convert_link(int, linkat_t *, int, void *);
static bool_t 	convert_symlink(int, symat_t *, int, void *);
static bool_t 	convert_part(int, partat_t *, int, void *);


static void
convert_obj(int way, obj_t *obj, int item, void *stuff)
{ /* top */
	extern char	*network_username(uid_t);
	extern char	*network_groupname(gid_t);
	extern uid_t	network_uid(char *);
	extern gid_t	network_gid(char *);
	char		buf[MAXNAMELEN];


	if (way == CONV_LOCALPUT) {
		obj->o_upmask |= 1<<item;	/* remember what we changed */
	}

	/*
	 * Right now, we only support one version.  In the future,
	 * we'll check to see if we are being asked to decode an
	 * unsupported version and fail that.  For now, we just
	 * check the one.
	 */
	if (version_get() != DTABLE_VERSION) {
		warning(gettext(
		    "Don't know how to decode a version %d nis+ db object\n"),
		    version_get());
		return;
	}

	/*
	 * Convert generic parts of an object.
	 */
	switch (item) { /* big switch */
	case DTAB_NAME:
		switch (way) /* name */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = (void *)strdup(obj->o_name);
			cg->size = strlen(cg->data)+1;
			break;
		    }
		case CONV_LOCALPUT:
		case CONV_PUT: {
			char *from = (char *)stuff;

			if (obj->o_name) {
				free(obj->o_name);
			}
			obj->o_name = strdup(from);
			break;
		}
		case CONV_FREE:
			free(obj->o_name);
			break;

		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (strcmp(obj->o_name, nobj->o_name) == 0) {
				break;
			}
			/*CSTYLED*/
			if (timercmp(&obj->o_mtime, &nobj->o_mtime, >)) {
				break;
			}
			if (obj->o_name) {
				free(obj->o_name);
			}
			obj->o_name = strdup(nobj->o_name);
			nisobj_clearup(item, obj);
			break;
		    }
		default:
			debug(1, "obj_name: unknown conversion %d\n", way);
			break;
		}
		break;

	case DTAB_DIR:
		switch (way) /* dir */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;
			char	*s;

			/* DSK and MT do not include leading '/' */
			if ((strncmp(&obj->o_dir[1], DSKNAME,
			    strlen(DSKNAME)) == 0) ||
			    (strncmp(&obj->o_dir[1], MTNAME,
			    strlen(MTNAME)) == 0)) {
				s = malloc(strlen(obj->o_dir)+2);
				s[0] = '/';
				s[1] = 'r';
				(void) strcpy(&s[2], &obj->o_dir[1]);
				cg->data = (void *)s;
			} else {
				cg->data = (void *)strdup(obj->o_dir);
			}
			cg->size = strlen(cg->data)+1;
			break;
		    }
		case CONV_LOCALPUT:
		case CONV_PUT: {
			char *from = (char *)stuff;

			if (obj->o_dir) {
				free(obj->o_dir);
			}
			obj->o_dir = strdup(from);
			break;
		}
		case CONV_FREE:
			free(obj->o_dir);
			break;

		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (strcmp(obj->o_dir, nobj->o_dir) == 0) {
				break;
			}
			/*CSTYLED*/
			if (timercmp(&obj->o_mtime, &nobj->o_mtime, >)) {
				break;
			}
			if (obj->o_dir) {
				free(obj->o_dir);
			}
			obj->o_dir = strdup(nobj->o_dir);
			nisobj_clearup(item, obj);
			break;
		    }

		default:
			debug(1, "obj_dir: unknown conversion %d\n", way);
			break;
		}
		break;

	/*
	 * The implementation of version is a bit hacky.  I
	 * know that "name" will always be first and "version"
	 * will always be second.  I keep the version being used
	 * in a static, so that later calls will do the "put"
	 * correctly.
	 */
	case DTAB_VERSION:
		switch (way) /* vers */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			(void) sprintf(buf, "%d", DTABLE_VERSION);
			cg->data = (void *)strdup(buf);
			cg->size = strlen(buf)+1;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;

			u_int vers = strtol(from, NULL, 0);
			version_set(vers);
			break;
		}
		case CONV_FREE:
		case CONV_MERGE:
			break;
		default:
			debug(1, "obj_vers: unknown conversion %d\n", way);
			break;
		}
		break;

	case DTAB_XID:
		switch (way) /* xid */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			(void) sprintf(buf, "%llu", obj->o_xid);
			cg->data = (char *)strdup(buf);
			cg->size = strlen(buf)+1;
			break;
		    }
		case CONV_LOCALPUT: {
			u_longlong_t	*from = (u_longlong_t *)stuff;

			obj->o_xid = *from;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;

			obj->o_xid = strtoll(from, NULL, 0);
			break;
		}
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (obj->o_xid == nobj->o_xid) {
				debug(1, "why are we merging these two?\n");
				break;
			}
			/*
			 * Always take the biggest xid.
			 */
			if (obj->o_xid > nobj->o_xid) {
				break;
			}
			/*
			 * changing the mask here is a bit bogus since
			 * we're about to bump the xid and set the mask
			 * by hand anyway.
			 */
			obj->o_xid = nobj->o_xid;
			break;
		    }
		default:
			debug(1, "obj_xid: unknown conversion %d\n", way);
			break;
		}
		break;

	case DTAB_TYPE:
		switch (way) /* type */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			switch (obj->o_type) {
			case VV_DIR:
				cg->data = strdup(DTAB_TYPE_DIR);
				break;
			case VV_BLK:
			case VV_CHR:
				cg->data = strdup(DTAB_TYPE_VOL);
				break;
			case VV_LINK:
				cg->data = strdup(DTAB_TYPE_LNK);
				break;
			case VV_SYMLINK:
				cg->data = strdup(DTAB_TYPE_SLNK);
				break;
			}
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT: {
			char	*type = (char *)stuff;
			if (strcmp(type, DTAB_TYPE_DIR) == 0) {
				obj->o_type = VV_DIR;
			} else if (strcmp(type, DTAB_TYPE_VOL) == 0) {
				obj->o_type = VV_CHR;
			} else if (strcmp(type, DTAB_TYPE_LNK) == 0) {
				obj->o_type = VV_LINK;
			} else if (strcmp(type, DTAB_TYPE_SLNK) == 0) {
				obj->o_type = VV_SYMLINK;
			}
			break;
		    }
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (obj->o_type == nobj->o_type) {
				break;
			}
			debug(1, "convert_obj: can't change type\n");
			break;
		    }
		default:
			debug(1, "obj_type: unknown conversion %d\n", way);
			break;
		}
		break;

	case DTAB_ID:
		switch (way) /* id */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			(void) sprintf(buf, "%llu", obj->o_id);
			cg->data = strdup(buf);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;

			obj->o_id = strtoull(from, NULL, 0);
			break;
		}
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (obj->o_id == nobj->o_id) {
				break;
			}

			debug(1, "convert_obj: can't change id\n");
			break;
		    }
		default:
			debug(1, "obj_id: unknown conversion %d\n", way);
			break;
		}
		break;
	case DTAB_UID:
		switch (way) /* uid */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;
			cg->data = (void *)network_username(obj->o_uid);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;
			obj->o_uid = network_uid(from);
			break;
		    }
		case CONV_LOCALPUT: {
			uid_t	*from = (uid_t *)stuff;

			obj->o_uid = *from;
			break;
		    }
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (obj->o_uid == nobj->o_uid) {
				break;
			}
			/*CSTYLED*/
			if (timercmp(&obj->o_mtime, &nobj->o_mtime, >)) {
				break;
			}
			obj->o_uid = nobj->o_uid;
			nisobj_clearup(item, obj);
			break;
		    }
		default:
			debug(1, "obj_uid: unknown conversion %d\n", way);
			break;
		}
		break;
	case DTAB_GID:
		switch (way) /* gid */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;
			cg->data = (void *)network_groupname(obj->o_gid);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;
			obj->o_gid = network_gid(from);
			break;
		}
		case CONV_LOCALPUT: {
			gid_t	*from = (gid_t *)stuff;

			obj->o_gid = *from;
			break;
		    }
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (obj->o_gid == nobj->o_gid) {
				break;
			}
			/*CSTYLED*/
			if (timercmp(&obj->o_mtime, &nobj->o_mtime, >)) {
				break;
			}
			obj->o_gid = nobj->o_gid;
			nisobj_clearup(item, obj);
			break;
		    }
		default:
			debug(1, "obj_gid: unknown conversion %d\n",
				way);
			break;
		}
		break;
	case DTAB_MODE:
		switch (way) /* mode */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			/* we write it in octal to be nice guys */
			(void) sprintf(buf, "0%lo", obj->o_mode);
			cg->data = strdup(buf);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_LOCALPUT: {
			mode_t *from = (mode_t *)stuff;

			obj->o_mode = *from;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;

			/* it automatically figures out octal or whatever */
			obj->o_mode = (mode_t)strtol(from, NULL, 0);
			break;
		}
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (obj->o_mode == nobj->o_mode) {
				break;
			}
			/*CSTYLED*/
			if (timercmp(&obj->o_mtime, &nobj->o_mtime, >)) {
				break;
			}
			obj->o_mode = nobj->o_mode;
			nisobj_clearup(item, obj);
			break;
		    }
		default:
			debug(1, "obj_mode: unknown conversion %d\n", way);
			break;
		}
		break;
	case DTAB_NLINKS:
		switch (way) /* nlinks */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			/* we write it in octal to be nice guys */
			(void) sprintf(buf, "%u", obj->o_nlinks);
			cg->data = strdup(buf);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_LOCALPUT: {
			u_int *from = (u_int *)stuff;

			obj->o_nlinks = *from;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;

			/* it automatically figures out octal or whatever */
			obj->o_nlinks = (mode_t)strtol(from, NULL, 0);
			break;
		}
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			obj_t	*nobj = (obj_t *)stuff;
			if (obj->o_nlinks == nobj->o_nlinks) {
				break;
			}
			/*CSTYLED*/
			if (timercmp(&obj->o_mtime, &nobj->o_mtime, >)) {
				break;
			}
			obj->o_nlinks = nobj->o_nlinks;
			nisobj_clearup(item, obj);
			break;
		    }
		default:
			debug(1, "obj_nlinks: unknown conversion %d\n", way);
			break;
		}
		break;
	case DTAB_ATIME:
	case DTAB_MTIME:
	case DTAB_CTIME: {
		struct timeval *tv, *mtv;
		obj_t	*nobj = (obj_t *)stuff; /* for CONV_MERGE */

		switch (item) {
		case DTAB_ATIME:
			tv = &obj->o_atime;
			if (way == CONV_MERGE) {
				mtv = &nobj->o_atime;
			}
			break;
		case DTAB_MTIME:
			tv = &obj->o_mtime;
			if (way == CONV_MERGE) {
				mtv = &nobj->o_mtime;
			}
			break;
		case DTAB_CTIME:
			tv = &obj->o_ctime;
			if (way == CONV_MERGE) {
				mtv = &nobj->o_ctime;
			}
			break;
		}
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			timeval_xdr(XDR_ENCODE, tv, &cg->data, &cg->size);
			break;
		    }
		case CONV_PUT: {
			timeval_xdr(XDR_DECODE, tv, &stuff, NULL);
			break;
		}
		case CONV_LOCALPUT: {
			struct timeval *from = (struct timeval *)stuff;

			*tv = *from;
			break;
		    }
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			/*CSTYLED*/
			if (timercmp(tv, mtv, ==)) {
				break;
			}
			/*
			 * With time, always use the latest time.
			 */
			/*CSTYLED*/
			if (timercmp(tv, mtv, >)) {
				break;
			}
			*tv = *mtv;
			nisobj_clearup(item, obj);
			break;
		    }
		default:
			debug(1, "obj_time: unknown conversion %d\n", way);
			break;
		}
		break;
	    }
	default:
		/*
		 * The item to be converted wasn't object generic,
		 * so now we'll try an object specific function.
		 */
		switch (obj->o_type) {
		case VV_BLK:
		case VV_CHR:
			(void) convert_vol(way, (vol_t *)obj, item, stuff);
			break;
		case VV_DIR:
			(void) convert_dir(way, (dirat_t *)obj, item, stuff);
			break;
		case VV_LINK:
			(void) convert_link(way, (linkat_t *)obj, item, stuff);
			break;
		case VV_SYMLINK:
			(void) convert_symlink(way, (symat_t *)obj, item,
			    stuff);
			break;
		case VV_PART:
			(void) convert_part(way, (partat_t *)obj, item, stuff);
			break;
		default:
			fatal(gettext("convert_obj: bad object type %d\n"),
				obj->o_type);
			break;
		}
	}
}


static bool_t
convert_vol(int way, vol_t *v, int item, void *stuff)
{
	extern size_t	label_size(int);


	switch (item) {
	case DTAB_PROPS:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = (void *)props_get(v);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT: {
			char	*from = (char *)stuff;

			props_set(v, from);
			break;
		}
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			vol_t *nv = (vol_t *)stuff;

			props_merge(v, nv);	/* merge the flags... */
			nisobj_clearup(item, &v->v_obj);
			break;
		}
		default:
			debug(1, "vol_props: unknown conversion %d\n", way);
			break;
		}
		break;

	case VOL_MEDTYPE:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = (void *)strdup(v->v_mtype);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_LOCALPUT:
		case CONV_PUT: {
			char *from = (char *)stuff;

			if (v->v_mtype)
				free(v->v_mtype);
			v->v_mtype = strdup(from);
			break;
		}
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			vol_t	*nv = (vol_t *)stuff;
			if (strcmp(v->v_mtype, nv->v_mtype) == 0) {
				break;
			}
			if (timercmp(&v->v_obj.o_mtime,
				/*CSTYLED*/
			    &nv->v_obj.o_mtime, >)){
				break;
			}
			debug(1, "why are we merging these two?\n");
			if (v->v_mtype)
				free(v->v_mtype);
			v->v_mtype = strdup(nv->v_mtype);
			nisobj_clearup(item, &v->v_obj);
			break;
		    }
		default:
			debug(1, "vol_type: unknown conversion %d\n", way);
			break;
		}
		break;

	case VOL_LABTYPE:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = strdup(label_ident(v->v_label.l_type));
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;

			v->v_label.l_type = label_type(from);
			break;
		}
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			vol_t	*nv = (vol_t *)stuff;

			if (v->v_label.l_type == nv->v_label.l_type) {
				break;
			}
			if (timercmp(&v->v_obj.o_mtime,
				/*CSTYLED*/
			    &nv->v_obj.o_mtime, >)){
				break;
			}
			v->v_label.l_type = nv->v_label.l_type;
			nisobj_clearup(item, &v->v_obj);
			break;
		    }
		default:
			debug(1, "vol_labtype: unknown conversion %d\n", way);
			break;
		}
		break;
	case VOL_LABEL:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			label_xdr(&v->v_label, XDR_ENCODE, &cg->data);
			cg->size = label_xdrsize(v->v_label.l_type);
			break;
		    }
		case CONV_PUT:
			label_xdr(&v->v_label, XDR_DECODE, &stuff);
			break;
		case CONV_LOCALPUT: {
			label	*nl = (label *)stuff;

			if (v->v_label.l_label) {
				free(v->v_label.l_label);
			}
			v->v_label.l_type = nl->l_type;
			/*
			 * Here we just assume that we've been "given"
			 * the pointer to the label to manage as
			 * our very own.
			 */
			v->v_label.l_label = nl->l_label;
			/*
			 * if we write a new label, both the label
			 * type and the key may have changed.
			 */
#ifdef notdef
			v->v_obj.o_upmask |= ((1<<VOL_LABTYPE)|(1<<VOL_KEY));
#endif
			break;
		    }
		case CONV_FREE:
			free(v->v_label.l_label);
			break;
		case CONV_MERGE: {
			vol_t	*nv = (vol_t *)stuff;
			u_int	lsz;

			if (label_compare(&v->v_label,
			    &nv->v_label) == TRUE) {
				break;
			}
			if (timercmp(&v->v_obj.o_mtime,
				/*CSTYLED*/
			    &nv->v_obj.o_mtime, >)){
				break;
			}

			if (v->v_label.l_label) {
				free(v->v_label.l_label);
			}
			lsz = label_size(v->v_label.l_type);
			v->v_label.l_label = (void *)malloc(lsz);
			(void) memcpy(v->v_label.l_label, nv->v_label.l_label,
			    lsz);
			nisobj_clearup(item, &v->v_obj);
			break;
		    }
		default:
			debug(1, "vol_label: unknown conversion %d\n", way);
			break;
		}
		break;
	case VOL_KEY:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = (void *)label_key(&v->v_label);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT:
		case CONV_FREE:
		case CONV_MERGE:
			/*
			 * nothing to do here, it's generated from the
			 * label and not saved.
			 */
			break;
		default:
			debug(1, "vol_key: unknown conversion %d\n", way);
			break;
		}
		break;
	case VOL_LOCATION:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			if (v->v_location) {
				cg->data = strdup(v->v_location);
			} else {
				cg->data = strdup("");
			}
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT: {
			char	*from = (char *)stuff;

			v->v_basedev = location_localdev(from);
			v->v_location = strdup(from);
			break;
		}
		case CONV_LOCALPUT: {
			char 	*from = (char  *)stuff;

			v->v_location = location_newdev(v->v_location, from);
			v->v_basedev = location_localdev(v->v_location);
			break;
		    }
		case CONV_FREE:
			if (v->v_location) {
				free(v->v_location);
			}
			break;
		case CONV_MERGE:
			/* not sure this is right */
			debug(1, "location merge: think about this\n");
			break;
		default:
			debug(1, "vol_location: unknown conversion %d\n", way);
			break;
		}
		break;
	default:
		break;
	}
	return (TRUE);
}

/*
 * directory attributes ("da") not used, bu here for compatability with
 * other routines
 */
/*ARGSUSED*/
static bool_t
convert_dir(int way, dirat_t *da, int item, void *stuff)
{
	switch (item) {
	case DTAB_PROPS:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = strdup("");
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT:
		case CONV_FREE:
		case CONV_MERGE:
			break;

		default:
			debug(1, "dir_props: unknown conversion %d\n", way);
			break;
		}
		break;

	default:
		break;
	}
	return (TRUE);
}


static bool_t
convert_link(int way, linkat_t *la, int item, void *stuff)
{
	char		buf[MAXNAMELEN];

	switch (item) {
	case DTAB_PROPS:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = strdup("");
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT:
		case CONV_FREE:
		case CONV_MERGE:
			break;
		default:
			debug(1, "link_props: unknown conversion %d\n", way);
			break;
		}
		break;

	case LNK_PTR:
		switch (way) /* la_id */ {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			(void) sprintf(buf, "%llu", la->la_id);
			cg->data = strdup(buf);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT: {
			char *from = (char *)stuff;

			la->la_id = strtoull(from, NULL, 0);
			break;
		}
		case CONV_FREE:
			break;
		case CONV_MERGE: {
			linkat_t *nla = (linkat_t *)stuff;

			if (la->la_id == nla->la_id) {
				break;
			}

			debug(1, "link_id: can't change id\n");
			break;
		    }
		default:
			debug(1, "link_id: unknown conversion %d\n", way);
			break;
		}
		break;

	default:
		break;
	}
	return (TRUE);
}


static bool_t
convert_symlink(int way, symat_t *sla, int item, void *stuff)
{
	switch (item) {
	case DTAB_PROPS:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = strdup("");
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT:
		case CONV_FREE:
		case CONV_MERGE:
			break;
		default:
			debug(1, "symlink_props: unknown conversion %d\n",
				way);
			break;
		}
		break;

	case SYM_PTR:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = strdup(sla->sla_ptr);
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT:
		case CONV_LOCALPUT: {
			char	*from = (char *)stuff;

			if (sla->sla_ptr) {
				free(sla->sla_ptr);
			}
			sla->sla_ptr = strdup(from);
			break;
		    }
		case CONV_FREE:
			free(sla->sla_ptr);
			break;
		case CONV_MERGE: {
			symat_t	*nsla = (symat_t *)stuff;
			if (strcmp(sla->sla_ptr, nsla->sla_ptr) == 0) {
				break;
			}
			if (timercmp(&sla->sla_obj.o_mtime,
				/*CSTYLED*/
			    &sla->sla_obj.o_mtime, >)) {
				break;
			}
			free(sla->sla_ptr);
			sla->sla_ptr = nsla->sla_ptr;
			nisobj_clearup(item, &sla->sla_obj);
			break;
		    }
		default:
			debug(1, "symlink_ptr: unknown conversion %d\n", way);
			break;
		}
		break;

	default:
		break;
	}
	return (TRUE);
}

/*
 * partition attributes ("pa") not used, bu here for compatability with
 * other routines
 */
/*ARGSUSED*/
static bool_t
convert_part(int way, partat_t *pa, int item, void *stuff)
{
	switch (item) {
	case DTAB_PROPS:
		switch (way) {
		case CONV_GET: {
			struct conv_get *cg = (struct conv_get *)stuff;

			cg->data = strdup("");
			cg->size = strlen((char *)cg->data)+1;
			break;
		    }
		case CONV_PUT:
		case CONV_FREE:
		case CONV_MERGE:
			break;
		default:
			debug(1, "symlink_props: unknown conversion %d\n",
				way);
			break;
		}
		break;


	default:
		break;
	}
	return (TRUE);
}



static u_int convert_version = DTABLE_VERSION;

/*
 * set the current version for convert to operate on
 */
static void
version_set(u_int vers)
{
	convert_version = vers;
}

/*
 * return the current version that convert is operating on
 */
static u_int
version_get()
{
	return (convert_version);
}

static void
timeval_xdr(enum xdr_op op, struct timeval *tv, void **res, size_t *sz)
{
	char	buf[BUFSIZ];
	XDR	xdrs;
	size_t	lsz;

	if (op == XDR_ENCODE) {
		xdrmem_create(&xdrs, buf, BUFSIZ, op);
		xdr_nfstime(&xdrs, (nfstime *)tv);
		*sz = xdr_sizeof(xdr_nfstime, (void *)tv);
		*res = malloc(*sz);
		(void) memcpy(*res, buf, *sz);
		xdr_destroy(&xdrs);
	} else if (op == XDR_DECODE) {
		lsz = xdr_sizeof(xdr_nfstime, (void *)tv);
		xdrmem_create(&xdrs, *res, lsz, op);
		xdr_nfstime(&xdrs, (nfstime *)tv);
		xdr_destroy(&xdrs);
	}
}
