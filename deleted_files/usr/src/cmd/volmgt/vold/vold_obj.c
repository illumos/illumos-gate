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

#include	<stdlib.h>
#include	<string.h>
#include	"vold.h"



void
change_name(obj_t *obj, char *name)
{
	if (obj->o_name) {
		free(obj->o_name);
	}
	obj->o_name = strdup(name);

	obj->o_upmask |= OBJ_UP_NAME;
}

void
change_dir(obj_t *obj, char *dir)
{
	if (obj->o_dir)
		free(obj->o_dir);
	obj->o_dir = strdup(dir);

	obj->o_upmask |= OBJ_UP_DIR;
}

void
change_uid(obj_t *obj, uid_t uid)
{
	obj->o_uid = uid;
	obj->o_upmask |= OBJ_UP_UID;
}

void
change_gid(obj_t *obj, gid_t gid)
{
	obj->o_gid = gid;
	obj->o_upmask |= OBJ_UP_GID;
}

void
change_mode(obj_t *obj, mode_t mode)
{
	obj->o_mode = mode;
	obj->o_upmask |= OBJ_UP_MODE;
}

/* XXX: not currently used */
void
change_nlinks(obj_t *obj, uint_t nlinks)
{
	obj->o_nlinks = nlinks;
	obj->o_upmask |= OBJ_UP_NLINKS;
}

void
change_atime(obj_t *obj, struct timeval *tv)
{
	obj->o_atime = *tv;
	obj->o_upmask |= OBJ_UP_ATIME;
}

void
change_mtime(obj_t *obj, struct timeval *tv)
{
	obj->o_mtime = *tv;
	obj->o_upmask |= OBJ_UP_MTIME;
}

/* XXX: not currently used */
void
change_ctime(obj_t *obj, struct timeval *tv)
{
	obj->o_ctime = *tv;
	obj->o_upmask |= OBJ_UP_CTIME;
}

/*
 * Add or remove the volume from a drive on this machine.
 * To remove, specify a path of NULL.
 */
void
change_location(obj_t *obj, char *path)
{
	vol_t	*v = (vol_t *)obj;

	v->v_location = location_newdev(v->v_location, path);
	v->v_basedev = location_localdev(v->v_location);
	if (v->v_basedev == NODEV)
		v->v_basedev = v->v_device;
	obj->o_upmask |= OBJ_UP_LOC;
}

/*
 * Change the flags associated with a volume.  These get
 * converted into "properties" when they get written to the nis+
 * database.
 * Flags are normally set by props_set, so we don't try to do
 * anything fancy here.
 */
void
change_flags(obj_t *obj)
{
	obj->o_upmask |= OBJ_UP_FLAGS;
}

void
change_label(obj_t *obj, label *la)
{
	vol_t	*v = (vol_t *)obj;

	if (v->v_label.l_label)
		free(v->v_label.l_label);
	v->v_label.l_type = la->l_type;
	v->v_label.l_label = la->l_label;
	obj->o_upmask |= OBJ_UP_LABEL;
}


void
obj_unlink(obj_t *obj)
{
	struct vnwrap 	*ovw;
	struct vnwrap 	*vw;


	ovw = node_findnode(obj->o_id, FN_ANY, FN_ANY, FN_ANY);
	for (vw = ovw; vw != NULL; vw = vw->vw_next) {
		node_unlink(vw->vw_node);
	}
	node_findnode_free(ovw);
}


/* DEPRECIATED */
/*ARGSUSED*/
void
obj_copy(obj_t *to, obj_t *from)
{

	ASSERT(0);
#ifdef NO_LONGER_USED
	if (to->o_type != from->o_type) {
		fatal("obj_copy: objects aren't the same type\n");
		/*NOTREACHED*/
	}
	switch (from->o_type) {
	case VV_CHR:
	case VV_BLK:
		(void) memcpy((void *)to, (void *)from, sizeof (vol_t));
		break;
	case VV_DIR:
		(void) memcpy((void *)to, (void *)from, sizeof (dirat_t));
		break;
	case VV_LINK:
		(void) memcpy((void *)to, (void *)from, sizeof (linkat_t));
		break;
	case VV_SYMLINK:
		(void) memcpy((void *)to, (void *)from, sizeof (symat_t));
		break;
	default:
		fatal("obj_copy: unknown object type %d, name %s\n",
		    from->o_type, from->o_name);
	}
#endif
}


/*
 * Free all the memory associated with any type object.
 */
void
obj_free(obj_t *obj)
{
	switch (obj->o_type) {
	case VV_BLK:
	case VV_CHR: {
		vol_t	*v = (vol_t *)obj;

		if (v->v_label.l_label) {
			free(v->v_label.l_label);
		}
		if (v->v_mtype) {
			free(v->v_mtype);
		}
		(void) dev_devmapfree(v);
		/*
		 * dev_devmapfree rewacks v_location which means that
		 * we have to free it *after* rather than before.
		 */
		if (v->v_location)
			free(v->v_location);
		break;
	}
	case VV_SYMLINK: {
		symat_t *sla = (symat_t *)obj;
		free(sla->sla_ptr);
		break;
	}
	case VV_LINK:
	case VV_DIR:
	case VV_PART:
		break;
	}
	free(obj->o_name);
	free(obj->o_dir);
	free(obj);
}


obj_t *
obj_dup(obj_t *obj)
{
	extern size_t	label_size(int);
	obj_t		*nobj;


	switch (obj->o_type) {
	case VV_BLK:
	case VV_CHR: {
		vol_t	*v, *nv;
		size_t	lsize;

		v = (vol_t *)obj;
		nv = (vol_t *)calloc(1, sizeof (vol_t));
		lsize = label_size(v->v_label.l_type);

		(void) memcpy((void *)nv, (void *)v, sizeof (vol_t));
		nv->v_devmap = NULL;
		if (v->v_location) {
			nv->v_location = strdup(v->v_location);
		}
		nv->v_label.l_label = (void *)malloc(lsize);
		(void) memcpy((void *)nv->v_label.l_label,
		    (void *)v->v_label.l_label, lsize);
		if (v->v_mtype) {
			nv->v_mtype = strdup(v->v_mtype);
		}
		nobj = (obj_t *)nv;
		break;
	}
	case VV_SYMLINK: {
		symat_t	*sla, *nsla;

		sla = (symat_t *)obj;
		nsla = (symat_t *)calloc(1, sizeof (symat_t));
		(void) memcpy((void *)nsla, (void *)sla, sizeof (symat_t));
		nsla->sla_ptr = strdup(sla->sla_ptr);
		nobj = (obj_t *)nsla;
		break;
	}
	case VV_LINK: {
		linkat_t	*nla;

		nla = (linkat_t *)calloc(1, sizeof (linkat_t));
		(void) memcpy((void *)nla, (void *)obj, sizeof (linkat_t));
		nobj = (obj_t *)nla;
		break;
	}
	case VV_DIR: {
		dirat_t		*nda;

		nda = (dirat_t *)calloc(1, sizeof (dirat_t));
		(void) memcpy((void *)nda, (void *)obj, sizeof (dirat_t));
		nobj = (obj_t *)nda;
		break;
	}
	case VV_PART: {
		partat_t	*npa;

		npa = (partat_t *)calloc(1, sizeof (partat_t));
		(void) memcpy((void *)npa, (void *)obj, sizeof (partat_t));
		nobj = (obj_t *)npa;
		break;
	}
	default:
		fatal(gettext("obj_dup: can't dup a type %d object (%s/%s)\n"),
		    obj->o_type, obj->o_dir, obj->o_name);
		/*NOTREACHED*/
	}
	nobj->o_name = strdup(obj->o_name);
	nobj->o_dir = strdup(obj->o_dir);
	return (nobj);
}

/*
 * Return a path that represents the "base" of an object.
 */
char *
obj_basepath(obj_t *obj)
{
	struct vnwrap	*vw, *nvw;
	vvnode_t	*vn = NULL;
	char		*s, *p, *q;

	vw = node_findnode(obj->o_id, FN_ANY, DIR_RDSK, FN_ANY);
	if (vw == NULL)
		return (strdup(obj->o_name));

	for (nvw = vw; nvw; nvw = nvw->vw_next) {
		if (nvw->vw_node->vn_dirtype == DIR_RDSK) {
			vn = nvw->vw_node;
			break;
		}
	}
	ASSERT(vn != NULL);

	node_findnode_free(vw);
	s = path_make(vn);
	p = strstr(s, "rdsk/");	/* it MUST have this string */
	ASSERT(p != NULL);
	p += strlen("rdsk/");
	q = strdup(p);
	free(s);
	return (q);
}
