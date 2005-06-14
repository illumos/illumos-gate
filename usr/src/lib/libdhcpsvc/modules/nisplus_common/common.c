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
 * This file contains functions, data shared among the two nisplus modules.
 */

#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include <string.h>
#include <sys/systeminfo.h>
#include "nisplus_impl.h"

/*
 * Config file settings for NIS+ modules
 */
nis_name	default_nis_group;
uint_t		default_nis_access;
uint_t		default_nis_ttl;

/*
 * dhcptab table column description
 */
static table_col	dt_desc[COLS_DT] = {
	{ "key",	TA_SEARCHABLE,	0 },
	{ "flag",	TA_SEARCHABLE,	0 },
	{ "value",	0,		0 }
};

int
dsvcnis_maperror_to_dsvc(nis_error err, zotypes context)
{
	int dsvc_error;

	switch (err) {
	case NIS_SUCCESS: 	/* Success */
		/* FALLTHRU */
	case NIS_S_SUCCESS: 	/* Object retrieved successfully from cache */
		dsvc_error = DSVC_SUCCESS;
		break;
	case NIS_NAMEEXISTS: 	/* Object with same name exists */
		if (context == TABLE_OBJ)
			dsvc_error = DSVC_TABLE_EXISTS;
		else
			dsvc_error = DSVC_EXISTS;
		break;
	case NIS_PERMISSION: 	/* Permission denied */
		/* FALLTHRU */
	case NIS_NOTOWNER: 	/* Not owner */
		dsvc_error = DSVC_ACCESS;
		break;
	case NIS_NOSUCHNAME:	/* Not Found, no such name */
		/* FALLTHRU */
	case NIS_NOTFOUND: 	/* Not found */
		/* FALLTHRU */
	case NIS_S_NOTFOUND:	/* Probably not found */
		/* FALLTHRU */
		switch (context) {
		case DIRECTORY_OBJ:
			dsvc_error = DSVC_NO_LOCATION;
			break;
		case TABLE_OBJ:
			dsvc_error = DSVC_NO_TABLE;
			break;
		case ENTRY_OBJ:
			/* FALLTHRU */
		default:
			dsvc_error = DSVC_NOENT;
			break;
		}
		break;
	case NIS_NOSUCHTABLE:	/* Database for table does not exist */
		dsvc_error = DSVC_NO_TABLE;
		break;
	case NIS_TRYAGAIN: 	/* Server busy, try again */
		/* FALLTHRU */
	case NIS_DUMPLATER: 	/* Master server busy, full dump rescheduled. */
		dsvc_error = DSVC_BUSY;
		break;
	case NIS_UNKNOWNOBJ: 	/* Unknown object */
		/* FALLTHRU */
	case NIS_INVALIDOBJ:	/* Invalid object for operation */
		/* FALLTHRU */
	case NIS_BADNAME:	/* Malformed Name, or illegal name */
		/* FALLTHRU */
	case NIS_TYPEMISMATCH:	/* Entry/Table type mismatch */
		/* FALLTHRU */
	case NIS_BADOBJECT:	/* Illegal object type for operation */
		/* FALLTHRU */
	case NIS_BADATTRIBUTE:	/* Missing or malformed attribute */
		/* FALLTHRU */
	case NIS_NOTSEARCHABLE:	/* Named object is not searchable */
		/* FALLTHRU */
	case NIS_BADREQUEST:	/* Query illegal for named table */
		dsvc_error = DSVC_INTERNAL;
		break;
	case NIS_NOTSAMEOBJ:	/* Passed object is not the same object */
				/* on server */
		dsvc_error = DSVC_COLLISION;
		break;
	case NIS_UNAVAIL: 	/* NIS+ service unavailable / not installed */
		/* FALLTHRU */
	case NIS_COLDSTART_ERR:	/* Error in accessing NIS+ cold start file */
		/* FALLTHRU */
	case NIS_NAMEUNREACHABLE:	/* NIS+ servers unreachable */
		dsvc_error = DSVC_UNAVAILABLE;
		break;
	case NIS_NOFILESPACE: 	/* No file space on server */
		/* FALLTHRU */
	case NIS_NOPROC:	/* Unable to create process on server */
		/* FALLTHRU */
	case NIS_NOCALLBACK:	/* Unable to create callback */
		dsvc_error = DSVC_NO_RESOURCES;
		break;
	case NIS_NOMEMORY: 	/* Server out of memory */
		dsvc_error = DSVC_NO_MEMORY;
		break;
	case NIS_SYSTEMERROR: 	/* Generic system error */
		/* FALLTHRU */
	case NIS_RPCERROR:	/* Error in RPC subsystem */
		/* FALLTHRU */
	case NIS_FAIL:		/* NIS+ operation failed */
		/* FALLTHRU */
	default:
		dsvc_error = DSVC_MODULE_ERR;
		break;
	}

	return (dsvc_error);
}

/*
 * Return an dsvcnis_handle_t initialized with the arguments. Returns pointer
 * to handle if successful, NULL otherwise. Caller is responsible for freeing
 * the handle. Function copies arguments.
 */
dsvcnis_handle_t *
dsvcnis_init_handle(const nis_name full_name, uint_t flags, nis_object *objp)
{
	dsvcnis_handle_t	*nhp;

	if ((nhp = calloc(1, sizeof (dsvcnis_handle_t))) == NULL)
		return (NULL);

	(void) strlcpy(nhp->h_cookie, DSVC_NIS_COOKIE, sizeof (nhp->h_cookie));
	if ((nhp->h_name = strdup(full_name)) == NULL) {
		free(nhp);
		return (NULL);
	}
	if ((nhp->h_object = nis_clone_object(objp, NULL)) == NULL) {
		free(nhp->h_name);
		free(nhp);
		return (NULL);
	}

	nhp->h_flags = flags;

	return (nhp);
}

/*
 * Validate a NIS+ handle instance.
 */
boolean_t
dsvcnis_validate_handle(dsvcnis_handle_t *nhp)
{
	if (nhp == NULL || strncmp(nhp->h_cookie, DSVC_NIS_COOKIE,
	    sizeof (DSVC_NIS_COOKIE)) != 0)
		return (B_FALSE);
	return (B_TRUE);
}

/*
 * Free a dsvcnis_handle_t.
 */
int
dsvcnis_free_handle(dsvcnis_handle_t **nis_hpp)
{
	if (!dsvcnis_validate_handle(*nis_hpp))
		return (DSVC_INVAL);

	free((*nis_hpp)->h_name);
	if ((*nis_hpp)->h_object != NULL)
		(void) nis_destroy_object((*nis_hpp)->h_object);
	free(*nis_hpp);
	*nis_hpp = NULL;

	return (DSVC_SUCCESS);
}

/*
 * Returns a copy of the type TABLE_OBJ in objpp for success,
 * DSVC* error codes otherwise.
 */
int
dsvcnis_get_tobject(const char *table_type, const nis_name name,
    const nis_name location, nis_object **objpp)
{
	int		error;
	nis_object	*objp;
	nis_result	*resp;
	char		nbuf[NIS_MAXNAMELEN + 1];

	*objpp = NULL;

	(void) snprintf(nbuf, sizeof (nbuf), "%s.%s", name, location);

	error = dsvcnis_validate_object(NIS_TABLE_OBJ, nbuf, &resp,
	    HARD_LOOKUP | NO_CACHE);
	if (error != DSVC_SUCCESS)
		return (error);

	objp = NIS_RES_OBJECT(resp);
	if (__type_of(objp) == TABLE_OBJ &&
	    strcmp(objp->TA_data.ta_type, table_type) == 0) {
		if ((*objpp = nis_clone_object(objp, NULL)) == NULL)
			error = DSVC_NO_MEMORY;
		else
			error = DSVC_SUCCESS;
	} else
		error = DSVC_NO_TABLE;
	nis_freeresult(resp);

	return (error);
}

/*
 * Sets fields from TABLE_OBJ that is cached in handle.
 */
int
dsvcnis_set_table_fields(dsvcnis_handle_t *nhp, nis_object *op)
{
	if (nhp->h_object->zo_name != NULL) {
		if ((op->zo_name = strdup(nhp->h_object->zo_name)) == NULL)
			return (DSVC_NO_MEMORY);
	}
	if (nhp->h_object->zo_owner != NULL) {
		if ((op->zo_owner = strdup(nhp->h_object->zo_owner)) == NULL) {
			free(op->zo_name);
			return (DSVC_NO_MEMORY);
		}
	}
	if (nhp->h_object->zo_group != NULL) {
		if ((op->zo_group = strdup(nhp->h_object->zo_group)) == NULL) {
			free(op->zo_name);
			free(op->zo_owner);
			return (DSVC_NO_MEMORY);
		}
	}
	if (nhp->h_object->zo_domain != NULL) {
		op->zo_domain = strdup(nhp->h_object->zo_domain);
		if (op->zo_domain == NULL) {
			free(op->zo_name);
			free(op->zo_owner);
			free(op->zo_group);
			return (DSVC_NO_MEMORY);
		}
	}

	op->zo_ttl = nhp->h_object->zo_ttl;

	return (DSVC_SUCCESS);
}

/*
 * Given a NISPLUS object, validate it, and return the nis_result.
 * Directories must be absolute, as we don't want NIS+ to do any implicit
 * expansion for us.
 */
int
dsvcnis_validate_object(zotypes type, const nis_name object_name,
    nis_result **respp, uint_t flags)
{
	int		error;
	nis_object	*objp;

	if (object_name[strlen(object_name) - 1] != '.')
		return (DSVC_BAD_PATH);

	*respp = nis_lookup(object_name, flags);

	if (NIS_RES_STATUS(*respp) != NIS_SUCCESS &&
	    NIS_RES_STATUS(*respp) != NIS_S_SUCCESS) {
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(*respp), type);
		nis_freeresult(*respp);
		*respp = NULL;
		return (error);
	}

	objp = NIS_RES_OBJECT(*respp);

	if (NIS_RES_NUMOBJ(*respp) != 1 || __type_of(objp) != type) {
		nis_freeresult(*respp);
		*respp = NULL;
		return (DSVC_BAD_PATH);
	}

	return (DSVC_SUCCESS);
}

/*
 * Figure out who the owner will be of any object we create. Returns value
 * in buf argument, which blen in size.
 */
int
dsvcnis_get_username(char *buf, size_t blen)
{
	nis_result	*ures;
	char		*user_nam = NULL, *user_dom = NULL;
	char		abuf[NIS_MAXNAMELEN + 1], bbuf[NIS_MAXNAMELEN + 1];

	/*
	 * Construct owner principal name and check existence.
	 * Set all access rights for owner.
	 * If user not specified, get process's real userid.
	 */
	if ((user_nam = (char *)nis_local_principal()) != NULL) {
		(void) strlcpy(abuf, user_nam, sizeof (abuf));
		user_nam = strtok_r(abuf, ".", &user_dom);
	} else
		return (DSVC_NO_CRED);

	/* Add domain name and trailing period to NIS name buffer */
	if (user_dom == NULL || user_dom[0] == '\0')
		user_dom = nis_local_directory();

	(void) strlcpy(buf, user_nam, blen);
	if (user_dom != NULL) {
		(void) strlcat(buf, ".", blen);
		(void) strlcat(buf, user_dom, blen);
		TRAIL_DOT(buf);
	}

	/* Look up the NIS name in the specified domain's cred table */
	if ((user_dom = strchr(buf, '.')) == NULL)
		user_dom = "";
	(void) snprintf(bbuf, sizeof (bbuf),
	    "[cname=%s,auth_type=DES],cred.org_dir%s", buf, user_dom);

	ures = nis_list(bbuf, FOLLOW_LINKS, NULL, NULL);
	if (NIS_RES_STATUS(ures) != NIS_SUCCESS &&
	    NIS_RES_STATUS(ures) != NIS_S_SUCCESS) {
		nis_freeresult(ures);
		return (DSVC_NO_CRED);
	}
	nis_freeresult(ures);

	return (DSVC_SUCCESS);
}

/*
 * Function to construct a NIS+ group name from groupname and domain.
 * Must be a valid NIS+ group in the specified domain. Result is stored in buf,
 * a buffer of blen in size.
 */
int
dsvcnis_get_groupname(char *buf, size_t blen)
{
	char		*group_nam = default_nis_group, *group_dom = NULL;
	nis_result	*gres;
	char		gbuf[NIS_MAXNAMELEN + 1], tbuf[NIS_MAXNAMELEN + 1];

	/*
	 * Construct group name if specified and check existence.
	 * If valid group, set all access rights for it.
	 * If group not specified, get default group from NIS_GROUP env var.
	 */
	if (group_nam == NULL)
		group_nam = (char *)nis_local_group();

	if (group_nam == NULL || group_nam[0] == '\0')
		return (DSVC_NOENT);	/* no group */

	(void) strlcpy(gbuf, group_nam, sizeof (gbuf));
	group_nam = strtok_r(gbuf, ".", &group_dom);

	/* Add domain name and trailing dot to NIS group name buffer */
	if (group_dom == NULL || group_dom[0] == '\0')
		group_dom = nis_local_directory();

	if (group_dom != NULL) {
		(void) snprintf(tbuf, sizeof (tbuf), "%s.groups_dir.%s",
		    group_nam, group_dom);
		TRAIL_DOT(tbuf);
		(void) snprintf(buf, blen, "%s.%s", group_nam, group_dom);
		TRAIL_DOT(buf);
	} else {
		(void) snprintf(tbuf, sizeof (tbuf), "%s.groups_dir",
		    group_nam);
		(void) strlcpy(buf, group_nam, blen);
	}

	/* Look up group name in the specified domain */
	gres = nis_lookup(tbuf, FOLLOW_LINKS);
	if (NIS_RES_STATUS(gres) != NIS_SUCCESS &&
	    NIS_RES_STATUS(gres) != NIS_S_SUCCESS) {
		nis_freeresult(gres);
		buf[0] = '\0';
		return (DSVC_NOENT);
	}
	nis_freeresult(gres);

	return (DSVC_SUCCESS);
}

/*
 * Given a access mask and desired access mode, check if the current user
 * has the requested rights. This function is from
 * usr/src/lib/libnsl/nis/gen/nis_misc_proc.c. Really should export that
 * function...
 */
boolean_t
dsvcnis_ckperms(uint_t right, uint_t mask, nis_object *objp)
{
	nis_name	pr;

	pr = nis_local_principal();

	if (NIS_NOBODY(mask, right) || (NIS_WORLD(mask, right) &&
	    (pr != NULL && strcmp(pr, "nobody") != 0)) ||
	    (NIS_OWNER(mask, right) &&
	    (pr != NULL && nis_dir_cmp(pr, objp->zo_owner) == SAME_NAME)) ||
	    (NIS_GROUP(mask, right) &&
	    (strlen(objp->zo_group) > (size_t)(1)) &&
	    (pr != NULL && __do_ismember(pr, objp, nis_lookup))))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Return a signature given an object instance
 */
uint64_t
dsvcnis_obj_to_sig(const nis_object *obp)
{
	return ((uint64_t)(obp->zo_oid.ctime) << 32 | obp->zo_oid.mtime);
}

/*
 *  Set an object instance id based upon a signature value
 */
void
dsvcnis_sig_to_obj(uint64_t sig, nis_object *op)
{
	op->zo_oid.ctime = (uint32_t)(sig >> 32);
	op->zo_oid.mtime = (uint32_t)(sig & 0x00000000ffffffff);
}

/*
 * Convert a nis_object ENTRY_OBJ to a dt_rec_t. Caller is responsible for
 * freeing result.
 */
static int
dsvcnis_entryobj_to_dtrec(const nis_object *objp, dt_rec_t **dtpp)
{
	dt_rec_t	*dtp;

	if ((dtp = calloc(1, sizeof (dt_rec_t))) == NULL)
		return (DSVC_NO_MEMORY);

	/* key */
	(void) strlcpy(dtp->dt_key, ENTRY_VAL(objp, KEY_DT),
	    sizeof (dtp->dt_key));

	/* flag */
	dtp->dt_type = ENTRY_VAL(objp, FLAG_DT)[0];

	/* value */
	if ((dtp->dt_value = strdup(ENTRY_VAL(objp, VALUE_DT))) == NULL) {
		free(dtp);
		return (DSVC_NO_MEMORY);
	}

	/* OID -> signature */
	dtp->dt_sig = dsvcnis_obj_to_sig(objp);

	*dtpp = dtp;
	return (DSVC_SUCCESS);
}

/*
 * Convert a dt_rec_t into a nis_object ENTRY_OBJ. Table related fields will
 * be filled in by the functions with the appropriate context. Caller is
 * responsible for freeing result.
 */
static int
dsvcnis_dtrec_to_entryobj(const dt_rec_t *dtp, nis_object **eop)
{
	nis_object	*nop;

	if ((nop = calloc(1, sizeof (nis_object))) == NULL)
		return (DSVC_NO_MEMORY);

	__type_of(nop) = ENTRY_OBJ;
	nop->zo_access = DEFAULT_RIGHTS;
	if ((nop->EN_data.en_type = strdup(TYPE_DT)) == NULL) {
		free(nop);
		return (DSVC_NO_MEMORY);
	}
	nop->EN_data.en_cols.en_cols_val = calloc(COLS_DT, sizeof (entry_col));
	if (nop->EN_data.en_cols.en_cols_val == NULL) {
		free(nop->EN_data.en_type);
		free(nop);
		return (DSVC_NO_MEMORY);
	}
	nop->EN_data.en_cols.en_cols_len = COLS_DT;

	/* key */
	if ((ENTRY_VAL(nop, KEY_DT) = strdup(dtp->dt_key)) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	ENTRY_LEN(nop, KEY_DT) = strlen(ENTRY_VAL(nop, KEY_DT)) + 1;

	/* flag */
	if ((ENTRY_VAL(nop, FLAG_DT) = calloc(1, sizeof (char) * 2)) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	ENTRY_VAL(nop, FLAG_DT)[0] = dtp->dt_type;
	ENTRY_LEN(nop, FLAG_DT) = strlen(ENTRY_VAL(nop, FLAG_DT)) + 1;

	/* value */
	if ((ENTRY_VAL(nop, VALUE_DT) = strdup(dtp->dt_value)) == NULL) {
		nis_destroy_object(nop);
		return (DSVC_NO_MEMORY);
	}
	ENTRY_LEN(nop, VALUE_DT) = strlen(ENTRY_VAL(nop, VALUE_DT)) + 1;

	/* signature -> OID */
	dsvcnis_sig_to_obj(dtp->dt_sig, nop);

	*eop = nop;

	return (DSVC_SUCCESS);
}
/*
 *  Given a key and value, generate a nisplus query spec. Returns pointer to
 *  dynamically allocated query spec for success, NULL otherwise. Caller is
 *  responsible for freeing buffer.
 */
#define	DSVC_QFMTSZ		3	/* ",=" */
#define	DSVC_QFMT_MAXINT	11	/* 4294967296 + null */
static char *
qspec(const char *keyp, dsvcnis_qtype_t type, void *valp)
{
	char 	*sp;
	int	len, tlen;

	len = strlen(keyp) + DSVC_QFMTSZ + 1 /* null */;

	if (type == DSVCNIS_STR) {
		len += strlen(valp);
		if ((sp = malloc(len)) == NULL)
			return (NULL);
		tlen = snprintf(sp, len, ", %s=%s", keyp, (char *)valp);
	} else {
		len += DSVC_QFMT_MAXINT;
		if ((sp = malloc(len)) == NULL)
			return (NULL);
		tlen = snprintf(sp, len, ", %s=%d", keyp, *(int *)valp);
	}

	if ((tlen + 1) < len) {
		/* this shouldn't fail - we're giving memory back.  */
		return (realloc(sp, tlen + 1));
	}
	return (sp);
}

/*
 *  Append/build a nisplus query spec. Caller is responsible for freeing
 *  memory. Returns DSVC_SUCCESS if the specification was appended to,
 *  DSVC_NO_MEMORY if no memory is to be found. Note that the scpp argument
 *  must point to a NULL if a new specification is to be built.
 */
int
dsvcnis_add_to_qspec(char **scpp, const char *keyp, dsvcnis_qtype_t type,
    void *valp)
{
	char 	*qp, *np;
	int	len;

	qp = qspec(keyp, type, valp);

	if (qp == NULL)
		return (DSVC_NO_MEMORY);

	if (*scpp == NULL) {
		*scpp = qp;
		return (DSVC_SUCCESS);
	}

	len = strlen(*scpp) + strlen(qp) + 1;
	if ((np = realloc(*scpp, len)) == NULL) {
		free(*scpp);
		*scpp = NULL;
		return (DSVC_NO_MEMORY);
	}

	(void) strlcat(np, qp, len);
	*scpp = np;
	return (DSVC_SUCCESS);
}

/*
 * Given a dt_rec_t and a query, generate a nisplus search criteria string.
 * Returns dynamically allocated search criteria if successful, NULL otherwise
 */
static char *
dsvcnis_dtquery_to_searchcriteria(const dt_rec_t *dtp, uint_t query,
    nis_name tablep)
{
	char	*scp = NULL, *tp;
	int	err = DSVC_SUCCESS, len;

	/* only two fields are queryable, KEY and TYPE. */
	if (DSVC_QISEQ(query, DT_QKEY) && dtp->dt_key[0] != '\0') {
		err = dsvcnis_add_to_qspec(&scp, dt_desc[KEY_DT].tc_name,
		    DSVCNIS_STR, (void *)dtp->dt_key);
	}
	if (err == DSVC_SUCCESS && DSVC_QISEQ(query, DT_QTYPE)) {
		char	type_str[2];

		type_str[0] = dtp->dt_type;
		type_str[1] = '\0';

		err = dsvcnis_add_to_qspec(&scp, dt_desc[FLAG_DT].tc_name,
		    DSVCNIS_STR, type_str);
	}

	if (err != DSVC_SUCCESS) {
		free(scp);
		return (NULL);
	}

	/* if this is a NULL query, allocate just enough for start spec */
	if (scp == NULL) {
		if ((scp = calloc(1, 2)) == NULL) /* [ + \0 */
			return (NULL);
	}

	scp[0] = '[';	/* Start of spec */
	len = strlen(tablep) + 3; /* room for ']' + ',' + \0 */
	if ((tp = realloc(scp, strlen(scp) + len)) == NULL) {
		free(scp);
		return (NULL);
	}
	scp = tp;
	(void) snprintf(&scp[strlen(scp)], len, "],%s", tablep); /* end spec */

	return (scp);
}

/*
 * Verify if nisplus is configured on this host. We do this by verifying that
 * the local directory exists. If location happens to be non-null, we verify
 * that the location is a valid directory object.
 */
int
status(const char *location)
{
	nis_result	*resp;
	nis_name	dirname;
	int		error;

	if (location == NULL) {
		if ((dirname = nis_local_directory()) == NULL)
			return (DSVC_INTERNAL);
	} else
		dirname = (nis_name)location;

	error = dsvcnis_validate_object(NIS_DIRECTORY_OBJ, dirname, &resp,
	    HARD_LOOKUP);

	if (error == DSVC_SUCCESS)
		nis_freeresult(resp);

	return (error);
}

/*
 * Return the data store API version supported by this module.  This version
 * was implemented to support version 1 of the API.
 */
int
version(int *vp)
{
	*vp = DSVC_PUBLIC_VERSION;
	return (DSVC_SUCCESS);
}

/*
 * NIS+ name space. There can be a hierarchy of directories, served on
 * different servers (potentially). This hierarchy must be contiguous; once
 * the root is uncovered, there cannot be non-existent subdirectories
 * between the root and other existent subdirectories.
 *
 * Thus, the task at hand is to find the last directory server (farthest from
 * the root), then create any required subdirectories on that server in order
 * to produce the final directory where we'll be storing our table objects. The
 * ability to create subdirectories on that server is of course dependent on
 * whether we have the appropriate credentials.
 *
 * The directory argument must be absolute ('.' terminated). Otherwise, we
 * risk some unhelpful magic that NIS+ might do underneath us.
 *
 * This function blocks if NIS+ is not available.
 */
int
mklocation(const char *directory)
{
	unsigned int	dlen;
	int		error = DSVC_SUCCESS;
	char		*ep, *lp = NULL, *parent_dir;
	nis_server	**srvpp = NULL, **tpp;
	nis_error	nerr;
	nis_result	*parent, *child;
	nis_object	*pobjp, *cobjp;

	dlen = strlen(directory);

	/* Must be fully qualified */
	if (directory[dlen - 1] != '.')
		return (DSVC_INVAL);

	/* Find last directory server */
	for (ep = (char *)&directory[dlen - 2]; ep > directory - 1; ep--) {

		if (*(ep - 1) != '.' && ep != directory)
			continue;

		if ((tpp = nis_getservlist((nis_name)ep)) != NULL) {
			if (srvpp != NULL)
				nis_freeservlist(srvpp);
			srvpp = tpp;
			lp = ep;
		} else {
			if (srvpp != NULL)
				break; /* last */
		}
	}

	if (srvpp == NULL)
		return (DSVC_BAD_PATH); /* Invalid directory spec */

	nis_freeservlist(srvpp);

	/*
	 * "lp" is last legal directory. We start there and move backward
	 * creating the children as we go.
	 */

	if (strcmp(directory, lp) == 0)
		return (DSVC_EXISTS); /* directory already exists */

	parent_dir = lp;
	parent = NULL;
	for (ep = lp - 2; ep > directory - 1; ep--) {

		if (*(ep - 1) != '.' && ep != directory)
			continue;

		if (parent == NULL) {
			/* Get parent directory object */
			for (;;) {
				parent = nis_lookup((nis_name)parent_dir,
				    MASTER_ONLY);
				error = dsvcnis_maperror_to_dsvc(
				    NIS_RES_STATUS(parent), NIS_DIRECTORY_OBJ);
				if (error == DSVC_SUCCESS)
					break;
				nis_freeresult(parent);
				if (error != DSVC_BUSY)
					return (error);
				(void) sleep(NIS_BUSY_PAUSE);
			}
		}

		/*
		 * Convert directory into subdirectory. Preserve
		 * parent's attributes in child.
		 */

		pobjp = &(NIS_RES_OBJECT(parent)[0]);
		if (__type_of(pobjp) != NIS_DIRECTORY_OBJ) {
			nis_freeresult(parent);
			return (DSVC_INVAL); /* not a directory */
		}

		if ((cobjp = nis_clone_object(pobjp, NULL)) == NULL) {
			nis_freeresult(parent);
			return (DSVC_NO_MEMORY);
		}
		nis_freeresult(parent);

		/* change the name */
		free(cobjp->DI_data.do_name);
		if ((cobjp->DI_data.do_name = strdup(ep)) == NULL) {
			nis_destroy_object(cobjp);
			return (DSVC_NO_MEMORY);
		}

		/* add new object to name space */
		for (;;) {
			child = nis_add((nis_name)ep, cobjp);
			error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(child),
			    NIS_DIRECTORY_OBJ);
			if (error == DSVC_SUCCESS)
				break;
			if (error != DSVC_BUSY) {
				nis_freeresult(child);
				nis_destroy_object(cobjp);
				return (error);
			}
			(void) sleep(NIS_BUSY_PAUSE);
		}

		nis_destroy_object(cobjp);
		nis_freeresult(child);

		/*
		 * Look up the new object. Really too bad that nis_add
		 * can't return an object.
		 */
		for (;;) {
			child = nis_lookup((nis_name)ep, MASTER_ONLY);
			error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(child),
			    NIS_DIRECTORY_OBJ);
			if (error == DSVC_SUCCESS)
				break;
			if (error != DSVC_BUSY) {
				nis_freeresult(child);
				(void) nis_remove((nis_name)ep, 0);
				return (error);
			}
			(void) sleep(NIS_BUSY_PAUSE);
		}

		cobjp = &(NIS_RES_OBJECT(child)[0]);

		/* create the associated directory */
		for (;;) {
			nerr = nis_mkdir((nis_name)ep,
			    &(cobjp->DI_data.do_servers.do_servers_val[0]));
			error = dsvcnis_maperror_to_dsvc(nerr,
			    NIS_DIRECTORY_OBJ);
			if (error == DSVC_SUCCESS)
				break;
			if (error != DSVC_BUSY) {
				(void) nis_remove((nis_name)ep, 0);
				nis_freeresult(child);
				return (error);
			}
			(void) sleep(NIS_BUSY_PAUSE);
		}

		/* Now child becomes parent */
		parent = child;
		parent_dir = ep;
		child = NULL;
	}

	if (parent != NULL)
		nis_freeresult(parent);

	return (error);
}

/*
 * List the current number of dhcptab container objects located at the
 * NIS_DIRECTORY 'location' in listppp. Return number of list elements
 * in 'count'.  If no objects exist, then 'count' is set to 0 and
 * DSVC_SUCCESS is returned.
 *
 * This function will block if NIS+ is unavailable.
 */
int
list_dt(const char *location, char ***listppp, uint_t *count)
{
	int		i, error, terr;
	nis_result	*resp;
	char		**tlistpp = NULL;

	*count = 0;
	*listppp = NULL;

	error = dsvcnis_validate_object(NIS_DIRECTORY_OBJ, (nis_name)location,
	    &resp, HARD_LOOKUP);
	if (error != DSVC_SUCCESS)
		return (error);
	nis_freeresult(resp);

	for (;;) {
		resp = nis_list((nis_name)location, FOLLOW_LINKS, NULL, NULL);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_TABLE_OBJ);

		if (error == DSVC_SUCCESS)
			break;

		nis_freeresult(resp);

		if (error == DSVC_NO_TABLE) {
			/* Not having any containers is a fine result. */
			return (DSVC_SUCCESS);
		}

		if (error != DSVC_BUSY)
			return (error);

		(void) sleep(NIS_BUSY_PAUSE);
	}

	for (i = 0, tlistpp = *listppp; i < NIS_RES_NUMOBJ(resp); i++) {
		nis_object	*nop, *op = &NIS_RES_OBJECT(resp)[i];

		for (;;) {
			terr = dsvcnis_get_tobject(TYPE_DT, op->zo_name,
			    (nis_name)location, &nop);
			if (terr == DSVC_BUSY)
				(void) sleep(NIS_BUSY_PAUSE);
			else
				break;
		}
		if (terr != DSVC_SUCCESS)
			continue;

		if (__type_of(nop) == TABLE_OBJ &&
		    strcmp(nop->TA_data.ta_type, TYPE_DT) == 0) {
			nis_destroy_object(nop);
			tlistpp = realloc(tlistpp, (++*count) *
			    sizeof (char **));
			if (tlistpp == NULL || (tlistpp[*count - 1] =
			    strdup(op->zo_name)) == NULL) {
				error = DSVC_NO_MEMORY;
				if (tlistpp != NULL)
					*listppp = tlistpp;
				break;
			}
			*listppp = tlistpp;
		} else
			nis_destroy_object(nop);
	}

	nis_freeresult(resp);

	if (error != DSVC_SUCCESS) {
		if (*listppp != NULL) {
			for (i = *count - 1; i >= 0; i--)
				free((*listppp)[i]);
			free(*listppp);
			*listppp = NULL;
		}
		*count = 0;
	}

	return (error);
}

/*
 * Creates or opens the "dhcptab" container in location and initializes
 * handlep to point to the instance handle. When creating a new dhcptab, the
 * caller's identity is used for owner/permissions. Performs any initialization
 * needed by data store.
 */
int
open_dt(void **handlep, const char *location, uint_t flags)
{
	nis_object		*op = NULL;
	dsvcnis_handle_t	*nhp = NULL;
	uint_t			f_access = 0;
	int			error;
	char			full_name[NIS_MAXNAMELEN + 1];

	(void) snprintf(full_name, sizeof (full_name), DT_TBL_NAME ".%s",
	    location);

	if (flags & DSVC_READ)
		f_access |= NIS_READ_ACC;
	if (flags & DSVC_WRITE)
		f_access |= (NIS_MODIFY_ACC | NIS_CREATE_ACC | NIS_DESTROY_ACC);

	if (flags & DSVC_CREATE) {
		uint_t		access = DEFAULT_RIGHTS;
		nis_object	o;
		table_obj	*top;
		nis_result	*resp = NULL;
		char		owner[NIS_MAXNAMELEN + 1],
				group[NIS_MAXNAMELEN + 1];

		(void) memset(&o, 0, sizeof (o));

		o.zo_owner = owner;
		if ((error = dsvcnis_get_username(o.zo_owner,
		    sizeof (owner))) != DSVC_SUCCESS)
			return (error);

		o.zo_group = group;
		if ((error = dsvcnis_get_groupname(o.zo_group,
		    sizeof (group))) != DSVC_SUCCESS)
			o.zo_group = NULL;

		o.zo_name = DT_TBL_NAME;
		o.zo_domain = (nis_name)location;

		if (default_nis_access != 0)
			access = default_nis_access;

		o.zo_access = access | f_access;

		if (default_nis_ttl == 0)
			o.zo_ttl = NIS_DEF_TTL;
		else
			o.zo_ttl = default_nis_ttl;

		__type_of(&o) = TABLE_OBJ;
		top = &o.TA_data;
		top->ta_type = TYPE_DT;
		top->ta_path = "";
		top->ta_maxcol = COLS_DT;
		top->ta_sep = DEFAULT_COL_SEP;
		top->ta_cols.ta_cols_len = COLS_DT;
		top->ta_cols.ta_cols_val = dt_desc;

		resp = nis_add(full_name, &o);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_TABLE_OBJ);
		nis_freeresult(resp);
		if (error != DSVC_SUCCESS)
			return (error);
	}

	error = dsvcnis_get_tobject(TYPE_DT, DT_TBL_NAME, (nis_name)location,
	    &op);
	if (error != DSVC_SUCCESS) {
		if (error == DSVC_NOENT && !(flags & DSVC_CREATE))
			error = DSVC_NO_TABLE;
		return (error);
	}

	if (!dsvcnis_ckperms(f_access, op->zo_access, op)) {
		nis_destroy_object(op);
		return (DSVC_ACCESS);
	}

	nhp = dsvcnis_init_handle(full_name, flags, op);
	nis_destroy_object(op);
	if (nhp == NULL)
		return (DSVC_NO_MEMORY);

	*handlep = nhp;

	return (DSVC_SUCCESS);
}

/*
 * Frees instance handle, cleans up per instance state.
 */
int
close_dt(void **handlepp)
{
	return (dsvcnis_free_handle((dsvcnis_handle_t **)handlepp));
}

/*
 * Searches the dhcptab container for instances that match the query
 * described by the combination of query and targetp.  If the partial
 * argument is true, then lookup operations that are unable to
 * complete entirely are allowed (and considered successful).  The
 * query argument consists of 2 fields, each 16 bits long.  The lower
 * 16 bits selects which fields {key, flags} of targetp are to be
 * considered in the query.  The upper 16 bits identifies whether a
 * particular field value must match (bit set) or not match (bit
 * clear).  Bits 2-15 in both 16 bit fields are currently unused, and
 * must be set to 0.  The count field specifies the maximum number of
 * matching records to return, or -1 if any number of records may be
 * returned.  The recordspp argument is set to point to the resulting
 * list of records; if recordspp is passed in as NULL then no records
 * are actually returned. Note that these records are dynamically
 * allocated, thus the caller is responsible for freeing them.  The
 * number of records found is returned in nrecordsp; a value of 0
 * means that no records matched the query.
 */
int
lookup_dt(void *handle, boolean_t partial, uint_t query, int count,
    const dt_rec_t *targetp, dt_rec_list_t **recordspp, uint_t *nrecordsp)
{
	dsvcnis_handle_t	*nhp = (dsvcnis_handle_t *)handle;
	nis_result		*resp;
	dt_rec_list_t		*tlp, *hlp = NULL;
	dt_rec_t		*dtp;
	char			*scp;
	int			error, i;
	uint_t			num, list_flags = FOLLOW_LINKS;

	if (!dsvcnis_validate_handle(nhp))
		return (DSVC_INVAL);

	if (!(nhp->h_flags & DSVC_READ))
		return (DSVC_ACCESS);

	scp = dsvcnis_dtquery_to_searchcriteria(targetp, query, nhp->h_name);
	if (scp == NULL)
		return (DSVC_NO_MEMORY);

	if (!(nhp->h_flags & DSVC_NONBLOCK))
		list_flags |= HARD_LOOKUP;

	resp = nis_list(scp, list_flags, NULL, NULL);
	free(scp);
	error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp), NIS_ENTRY_OBJ);
	if (error != DSVC_SUCCESS) {
		if (error == DSVC_NOENT) {
			/* no records matched the query */
			error = DSVC_SUCCESS;
			*nrecordsp = 0;
			if (recordspp != NULL)
				*recordspp = NULL;
		}
		nis_freeresult(resp);
		return (error);
	}

	/*
	 * Fastpath for queries w/o negative aspects for which no records are
	 * to be returned.
	 */
	if (recordspp == NULL && !DSVC_QISNEQ(query, DT_QALL)) {
		*nrecordsp = NIS_RES_NUMOBJ(resp);
		nis_freeresult(resp);
		return (DSVC_SUCCESS);
	}

	for (i = 0, num = 0; i < NIS_RES_NUMOBJ(resp) && (count < 0 ||
	    num < count); i++) {

		nis_object	*op = &NIS_RES_OBJECT(resp)[i];

		/*
		 * The query has gotten the records that match
		 * the "positive" aspects of the query. Weed out
		 * the records that match the "negative" aspect.
		 */
		if ((DSVC_QISNEQ(query, DT_QKEY) &&
		    strcmp(targetp->dt_key, ENTRY_VAL(op, KEY_DT)) == 0) ||
		    (DSVC_QISNEQ(query, DT_QTYPE) &&
		    targetp->dt_type == ENTRY_VAL(op, FLAG_DT)[0]))
			continue;

		error = dsvcnis_entryobj_to_dtrec(op, &dtp);
		if (error != DSVC_SUCCESS) {
			if (partial)
				break;
			nis_freeresult(resp);
			free_dtrec_list(hlp);
			return (error);
		}
		if ((tlp = add_dtrec_to_list(dtp, hlp)) == NULL) {
			if (partial)
				break;
			nis_freeresult(resp);
			free_dtrec(dtp);
			free_dtrec_list(hlp);
			return (DSVC_NO_MEMORY);
		} else {
			hlp = tlp;
			num++;
		}
	}

	nis_freeresult(resp);

	*nrecordsp = num;
	if (recordspp != NULL)
		*recordspp = hlp;

	return (DSVC_SUCCESS);
}

/*
 * Add the record pointed to by to from the dhcptab container referred
 * to by the handle.  addp's signature will be updated by the
 * underlying public module.
 */
int
add_dt(void *handle, dt_rec_t *addp)
{
	dsvcnis_handle_t	*nhp = (dsvcnis_handle_t *)handle;
	nis_object		*op;
	nis_result		*resp;
	int			error;

	if (!dsvcnis_validate_handle(nhp))
		return (DSVC_INVAL);

	if (!(nhp->h_flags & DSVC_WRITE))
		return (DSVC_ACCESS);

	addp->dt_sig = 0;	/* New records have 0 signatures */

	if ((error = dsvcnis_dtrec_to_entryobj(addp, &op)) != DSVC_SUCCESS)
		return (error);

	if ((error = dsvcnis_set_table_fields(nhp, op)) != DSVC_SUCCESS) {
		nis_destroy_object(op);
		return (error);
	}

	for (;;) {
		resp = nis_add_entry(nhp->h_name, op, RETURN_RESULT);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_ENTRY_OBJ);
		if (error == DSVC_BUSY && !(nhp->h_flags & DSVC_NONBLOCK)) {
			nis_freeresult(resp);
			(void) sleep(NIS_BUSY_PAUSE);
		} else
			break;
	}

	nis_destroy_object(op);

	if (error == DSVC_SUCCESS) {
		nis_object	*nop;

		nop = NIS_RES_OBJECT(resp);

		/* oid -> signature */
		addp->dt_sig = dsvcnis_obj_to_sig(nop);
	}

	nis_freeresult(resp);

	return (error);
}

/*
 * Atomically modify the record origp with the record newp in the
 * dhcptab container referred to by the handle.  newp's signature will
 * be updated by the underlying public module.  If an update collision
 * occurs, no update of the data store occurs.
 */
int
modify_dt(void *handle, const dt_rec_t *origp, dt_rec_t *newp)
{
	dsvcnis_handle_t	*nhp = (dsvcnis_handle_t *)handle;
	nis_object		*op, *nop;
	nis_result		*resp;
	char			*scp;
	int			error;
	uint_t			query, flags;

	if (!dsvcnis_validate_handle(nhp))
		return (DSVC_INVAL);

	if (!(nhp->h_flags & DSVC_WRITE))
		return (DSVC_ACCESS);

	/*
	 * MOD_SAMEOBJ ensures that the signature of the obj to modify has
	 * not changed in the table (detects update collisions).
	 */
	flags = MOD_SAMEOBJ | RETURN_RESULT;

	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QKEY);
	DSVC_QEQ(query, DT_QTYPE);
	scp = dsvcnis_dtquery_to_searchcriteria(origp, query, nhp->h_name);
	if (scp == NULL)
		return (DSVC_NO_MEMORY);

	if ((error = dsvcnis_dtrec_to_entryobj(origp, &op)) != DSVC_SUCCESS) {
		free(scp);
		return (error);
	}

	if ((error = dsvcnis_dtrec_to_entryobj(newp, &nop)) != DSVC_SUCCESS) {
		free(scp);
		nis_destroy_object(op);
		return (error);
	}

	if ((error = dsvcnis_set_table_fields(nhp, nop)) != DSVC_SUCCESS) {
		free(scp);
		nis_destroy_object(op);
		nis_destroy_object(nop);
		return (error);
	}

	/* copy object ID */
	nop->zo_oid.ctime = op->zo_oid.ctime;
	nop->zo_oid.mtime = op->zo_oid.mtime;

	nis_destroy_object(op);

	if (origp->dt_key != newp->dt_key)
		ENTRY_FLAGS(nop, KEY_DT) |= EN_MODIFIED;

	if (origp->dt_type != newp->dt_type)
		ENTRY_FLAGS(nop, FLAG_DT) |= EN_MODIFIED;

	if (ENTRY_FLAGS(nop, KEY_DT) & EN_MODIFIED &&
	    ENTRY_FLAGS(nop, FLAG_DT) & EN_MODIFIED) {
		/*
		 * We set MOD_EXCLUSIVE because the combination of
		 * key and type fields is unique, and we want nisplus
		 * to check to see if there would be a collision (matching
		 * record), and not perform the modify if a collision occurs.
		 * Allows us to do an atomic modify.
		 */
		flags |= MOD_EXCLUSIVE;
	}

	if (strcmp(origp->dt_value, newp->dt_value) != 0)
		ENTRY_FLAGS(nop, VALUE_DT) |= EN_MODIFIED;

	for (;;) {
		resp = nis_modify_entry(scp, nop, flags);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_ENTRY_OBJ);
		if (error == DSVC_BUSY && !(nhp->h_flags & DSVC_NONBLOCK)) {
			nis_freeresult(resp);
			(void) sleep(NIS_BUSY_PAUSE);
		} else
			break;
	}

	free(scp);
	nis_destroy_object(nop);

	if (error == DSVC_SUCCESS)
		newp->dt_sig = dsvcnis_obj_to_sig(NIS_RES_OBJECT(resp));

	nis_freeresult(resp);

	return (error);
}

/*
 * Delete the record referred to by dtp from the dhcptab container
 * referred to by the handle. If an update collision occurs, no
 * deletion of matching record in data store is done.  Caller is
 * responsible for freeing any dynamically allocated arguments.
 */
int
delete_dt(void *handle, const dt_rec_t *dtp)
{
	dsvcnis_handle_t	*nhp = (dsvcnis_handle_t *)handle;
	nis_result		*resp;
	nis_object		*op;
	char			*scp;
	int			error;
	uint_t			query;

	if (!dsvcnis_validate_handle(nhp))
		return (DSVC_INVAL);

	if (!(nhp->h_flags & DSVC_WRITE))
		return (DSVC_ACCESS);

	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QKEY);
	DSVC_QEQ(query, DT_QTYPE);
	scp = dsvcnis_dtquery_to_searchcriteria(dtp, query, nhp->h_name);
	if (scp == NULL)
		return (DSVC_NO_MEMORY);

	if (dtp->dt_sig != 0) {
		/* Caller is interested in knowing about a collision */
		error = dsvcnis_dtrec_to_entryobj(dtp, &op);
		if (error != DSVC_SUCCESS) {
			free(scp);
			return (error);
		}
	} else
		op = NULL;

	for (;;) {
		resp = nis_remove_entry(scp, op, 0);
		error = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_ENTRY_OBJ);
		nis_freeresult(resp);
		if (error == DSVC_BUSY && !(nhp->h_flags & DSVC_NONBLOCK))
			(void) sleep(NIS_BUSY_PAUSE);
		else
			break;
	}

	free(scp);

	if (op != NULL)
		nis_destroy_object(op);

	return (error);
}

/*
 * Remove dhcptab container in location from data store
 *
 * This function blocks if NIS+ is unavailable.
 */
int
remove_dt(const char *location)
{
	nis_result	*resp;
	nis_object	*op;
	int		err;
	char		full_name[NIS_MAXNAMELEN + 1], sc[NIS_MAXNAMELEN + 1];

	(void) snprintf(full_name, sizeof (full_name), DT_TBL_NAME ".%s",
	    location);

	/* Empty the entire table */
	(void) snprintf(sc, sizeof (sc), "[],%s", full_name);

	for (;;) {
		resp = nis_remove_entry(sc, NULL, REM_MULTIPLE);
		err = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_ENTRY_OBJ);
		nis_freeresult(resp);
		if (err == DSVC_SUCCESS || err == DSVC_NOENT)
			break;
		if (err != DSVC_BUSY)
			return (err);
		(void) sleep(NIS_BUSY_PAUSE);
	}

	/* now remove the table */
	for (;;) {
		err = dsvcnis_get_tobject(TYPE_DT, DT_TBL_NAME,
		    (nis_name)location, &op);
		if (err == DSVC_SUCCESS)
			break;
		if (err != DSVC_BUSY)
			return (err);
		(void) sleep(NIS_BUSY_PAUSE);
	}

	for (;;) {
		resp = nis_remove((nis_name)full_name, op);
		err = dsvcnis_maperror_to_dsvc(NIS_RES_STATUS(resp),
		    NIS_TABLE_OBJ);
		nis_freeresult(resp);
		if (err != DSVC_BUSY)
			break;
		(void) sleep(NIS_BUSY_PAUSE);
	}

	nis_destroy_object(op);

	return (err);
}

/*
 * Frees instance handle, cleans up per instance state.
 */
int
close_dn(void **handlepp)
{
	return (dsvcnis_free_handle((dsvcnis_handle_t **)handlepp));
}
