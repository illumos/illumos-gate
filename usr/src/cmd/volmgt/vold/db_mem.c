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

#include	<string.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<sys/param.h>

#include	"vold.h"


static void	memdb_lookup(vvnode_t *);
static void	memdb_root(void);
static bool_t	memdb_update(obj_t *);
static bool_t	memdb_add(obj_t *);
static bool_t	memdb_remove(obj_t *);
static vol_t	*memdb_findlabel(char *, label *);
static bool_t	memdb_testkey(char *, char *, char *);

/*
 * Note that this mem id business is a bit of a hack,
 * and assumes that TMPID_BASE in vold_node.c will not
 * collide with this id space.
 *
 * The core trouble here is that we are not using any form
 * of permanent storage to keep our id numbers (or objects, of course)
 * in.
 */
#define	MEMID_BASE	0x4000000000000000
static u_longlong_t	memid = MEMID_BASE+1;

static struct dbops mem_dbops = {
	memdb_lookup, 		/* dop_lookup */
	memdb_root, 		/* dop_root */
	memdb_update, 		/* dop_update */
	memdb_add, 		/* dop_add */
	memdb_remove, 		/* dop_remove */
	memdb_findlabel, 	/* dop_findlabel */
	memdb_testkey, 		/* dop_testkey */
	"mem",			/* dop_name */
};

#define	MEMDB_ID_HASH_SIZE	64
#define	MEMDB_LABEL_HASH_SIZE	64

static struct q	memdb_id_hash[MEMDB_ID_HASH_SIZE];
static struct q memdb_key_hash[MEMDB_LABEL_HASH_SIZE];

struct mdbobj;	/* forward decl */

struct id_hash {
	struct q	q;		/* hash queue */
	struct mdbobj	*ih_mo;		/* the datum */
};

struct key_hash {
	struct q	q;		/* hash queue */
	char		*kh_key;	/* key from label_key */
	char		*kh_mtype;	/* media type */
	struct mdbobj	*kh_mo;		/* the datum */
};

struct mdbobj {
	struct id_hash	*mo_id;		/* pointer to our id hash ent */
	struct key_hash	*mo_key;	/* pointer to our key hash ent */
	obj_t		*mo_obj;	/* the actual data */
};

static struct mdbobj 	*id_find(obj_t *);


bool_t
db_init(void)
{
	/*
	 * We're always here.
	 */
	db_new(&mem_dbops);
	return (TRUE);	/* always have a database */
}


static void
memdb_lookup(vvnode_t *dvn)
{
	extern void	node_setupdated(vvnode_t *, struct dbops *);

	/* mark all of our objects as "seen" */
	node_setupdated(dvn, &mem_dbops);
}


static void
memdb_root(void)
{
	/* we never have root modes stored away, so... */
}


static bool_t
memdb_update(obj_t *obj)
{
	extern size_t	label_size(int);
	struct mdbobj 	*mo;
	obj_t		*dob;



	if ((mo = id_find(obj)) == NULL) {
		debug(1,
		    "memdb: couldn't find object id %llu in database (%s)\n",
		    obj->o_id, obj->o_name);
		return (FALSE);
	}
	dob = mo->mo_obj;

	if (obj->o_upmask & OBJ_UP_NAME) {
		free(dob->o_name);
		dob->o_name = strdup(obj->o_name);
	}

	if (obj->o_upmask & OBJ_UP_DIR) {
		free(dob->o_dir);
		dob->o_dir = strdup(obj->o_dir);
	}

	if (obj->o_upmask & OBJ_UP_UID) {
		dob->o_uid = obj->o_uid;
	}

	if (obj->o_upmask & OBJ_UP_GID) {
		dob->o_gid = obj->o_gid;
	}

	if (obj->o_upmask & OBJ_UP_MODE) {
		dob->o_mode = obj->o_mode;
	}

	if (obj->o_upmask & OBJ_UP_ATIME) {
		dob->o_atime = obj->o_atime;
	}

	if (obj->o_upmask & OBJ_UP_MTIME) {
		dob->o_mtime = obj->o_mtime;
	}

	if (obj->o_upmask & OBJ_UP_CTIME) {
		dob->o_ctime = obj->o_ctime;
	}

	if (obj->o_upmask & OBJ_UP_NLINKS) {
		dob->o_nlinks = obj->o_nlinks;
	}

	if (obj->o_upmask & OBJ_UP_FLAGS) {
		vol_t	*v = (vol_t *)obj, *nv = (vol_t *)dob;

		nv->v_flags = v->v_flags;
	}

	if (obj->o_upmask & OBJ_UP_LOC) {
		vol_t	*v = (vol_t *)obj, *nv = (vol_t *)dob;
		if (nv->v_location) {
			free(nv->v_location);
		}
		nv->v_location = strdup(v->v_location);
	}

	if (obj->o_upmask & OBJ_UP_LABEL) {
		vol_t	*v = (vol_t *)obj, *nv = (vol_t *)dob;
		char	*key;
		size_t	lsize;

		key = label_key(&v->v_label);
		if (strcmp(key, mo->mo_key->kh_key)) {
			/*
			 * if the keys are different, move us to the right
			 * hash queue.
			 */
			REMQUE(memdb_key_hash[hash_string(mo->mo_key->kh_key)
			    % MEMDB_LABEL_HASH_SIZE], mo->mo_key);
			free(mo->mo_key->kh_key);
			mo->mo_key->kh_key = key;
			INSQUE(memdb_key_hash[hash_string(mo->mo_key->kh_key)
			    % MEMDB_LABEL_HASH_SIZE], mo->mo_key);
		}
		nv->v_label.l_type = v->v_label.l_type;
		if (v->v_label.l_label) {
			lsize = label_size(v->v_label.l_type);
			free(nv->v_label.l_label);
			nv->v_label.l_label = (void *)malloc(lsize);
			(void) memcpy((void *)nv->v_label.l_label,
			    (void *)v->v_label.l_label, lsize);
		}
	}
	obj->o_upmask = 0;

	return (TRUE);
}

static bool_t
memdb_add(obj_t *obj)
{
	struct id_hash	*id;
	struct key_hash	*key;
	struct mdbobj	*mo;
	vol_t		*v;



	obj->o_xid = 1;
	obj->o_id = memid++;

	id = (struct id_hash *)calloc(1, sizeof (struct id_hash));
	mo = (struct mdbobj *)calloc(1, sizeof (struct mdbobj));
	mo->mo_id = id;
	mo->mo_obj = obj_dup(obj);
	id->ih_mo = mo;

	/* put it in our id hash list */
	INSQUE(memdb_id_hash[obj->o_id % MEMDB_ID_HASH_SIZE], id);

	if (obj->o_type == VV_BLK || obj->o_type == VV_CHR) {
		/* if it's a volume, add it to our key hash */
		v = (vol_t *)obj;
		key = (struct key_hash *)calloc(1, sizeof (struct key_hash));
		key->kh_key = label_key(&v->v_label);
		key->kh_mtype = strdup(v->v_mtype);
		key->kh_mo = mo;
#ifdef	DEBUG_DB
		debug(6, "memdb_add: adding (%s, %s, %s) to bucket %d\n",
		    key->kh_mtype, label_ident(v->v_label.l_type),
		    key->kh_key,
		    hash_string(key->kh_key) % MEMDB_LABEL_HASH_SIZE);
#endif
		mo->mo_key = key;
		INSQUE(memdb_key_hash[hash_string(key->kh_key)
		    % MEMDB_LABEL_HASH_SIZE], key);
	}
	return (TRUE);
}


static bool_t
memdb_remove(obj_t *obj)
{
	extern void	obj_free(obj_t *);
	struct mdbobj	*mo;


	if ((mo = id_find(obj)) == NULL) {
		debug(1,
		    "memdb: couldn't find object id %llu in database (%s)\n",
		    obj->o_id, obj->o_name);
		return (FALSE);
	}

	/*
	 * Free the various things we've allocated and remove things
	 * from hash chains.
	 */
	obj_free(mo->mo_obj);
	REMQUE(memdb_id_hash[obj->o_id % MEMDB_ID_HASH_SIZE], mo->mo_id);
	free(mo->mo_id);
	if (mo->mo_key) {
		REMQUE(memdb_key_hash[hash_string(mo->mo_key->kh_key)
			% MEMDB_LABEL_HASH_SIZE], mo->mo_key);
		free(mo->mo_key->kh_mtype);
		free(mo->mo_key->kh_key);
		free(mo->mo_key);
	}
	free(mo);
	return (TRUE);
}


static vol_t *
memdb_findlabel(char *mtype, label *la)
{
	struct key_hash	*kh;
	uint_t		hashed_key;
	char		*key;


	key = label_key(la);
	hashed_key = hash_string(key);
	kh = HEAD(struct key_hash,
		memdb_key_hash[hashed_key % MEMDB_LABEL_HASH_SIZE]);

	while (kh) {
		if (strcmp(key, kh->kh_key) == 0 &&
		    strcmp(mtype, kh->kh_mtype) == 0) {
			free(key);
			return ((vol_t *)kh->kh_mo->mo_obj);
		}
		kh = NEXT(struct key_hash, kh);
	}
	free(key);
	return (NULL);
}


/*
 * test the supplied key to see if it already exists
 */
static bool_t
memdb_testkey(char *mtype, char *ltype, char *key)
{
	struct key_hash	*kh;
	uint_t		hashed_key;
	vol_t		*v;


#ifdef	DEBUG_DB
	debug(3, "memdb_testkey(%s, %s, %s): entering\n",
	    mtype ? mtype : "<null ptr",
	    ltype ? ltype : "<null ptr",
	    key ? key : "<null ptr");
#endif

	hashed_key = hash_string(key);
	kh = HEAD(struct key_hash,
		memdb_key_hash[hashed_key % MEMDB_LABEL_HASH_SIZE]);

#ifdef	DEBUG_DB
	debug(6, "memdb_testkey: hashed_key=%u, bucket#=%d\n",
	    hashed_key, hashed_key % MEMDB_LABEL_HASH_SIZE);
#endif
	while (kh) {
		v = (vol_t *)kh->kh_mo->mo_obj;
#ifdef	DEBUG_DB
		debug(6, "memdb_testkey: looking at (%s, %s, %s) ...\n",
		    kh->kh_mtype, label_ident(v->v_label.l_type),
		    kh->kh_key);
#endif
		if ((strcmp(key, kh->kh_key) == 0) &&
		    (strcmp(mtype, kh->kh_mtype) == 0) &&
		    (strcmp(ltype, label_ident(v->v_label.l_type)) == 0)) {
#ifdef	DEBUG_DB
			debug(3,
			    "memdb_testkey: returning TRUE (key found)\n");
#endif
			return (TRUE);
		}
		kh = NEXT(struct key_hash, kh);
	}
#ifdef	DEBUG_DB
	debug(3, "memdb_testkey: returning FALSE (key NOT found)\n");
#endif
	return (FALSE);
}


static struct mdbobj *
id_find(obj_t *obj)
{
	struct id_hash	*id;
	id = HEAD(struct id_hash,
		memdb_id_hash[obj->o_id % MEMDB_ID_HASH_SIZE]);
	while (id) {
		if (id->ih_mo->mo_obj->o_id == obj->o_id) {
			return (id->ih_mo);
		}
		id = NEXT(struct id_hash, id);
	}
	return (NULL);
}
