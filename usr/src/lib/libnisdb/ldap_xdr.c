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
 * Copyright 2015 Gary Mills
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <string.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpcsvc/nis.h>

#include "db_mindex_c.h"

#include "ldap_xdr.h"
#include "ldap_util.h"

#include "nis_clnt.h"

/*
 * In order not to change the on-disk NIS+ DB format, we need make sure
 * that XDR does nothing for the new structures added to various C++
 * classes.
 */

bool_t
xdr___nis_table_mapping_t(XDR *xdrs, void *t) {
	return (TRUE);
}

bool_t
xdr___nisdb_ptr_t(XDR *xdrs, void *ptr) {
	return (TRUE);
}

bool_t
xdr___nisdb_dictionary_defer_t(XDR *xdrs, void *defer) {
	return (TRUE);
}

bool_t
xdr___nisdb_rwlock_t(XDR *xdrs, void *rw) {
	return (TRUE);
}

bool_t
xdr___nisdb_flag_t(XDR *xdrs, void *flag) {
	return (TRUE);
}

/*
 * Imported from rpc.nisd/nis_db.c
 *
 * Special abbreviated XDR string which knows that the namep parameter (mainly
 * owner and group) has a trailing end which matches the last 'n' characters
 * in the domainname part.  It makes use of those common characters to
 * encode/decode this information.  We append an integer string to the
 * name to be encoded which denotes the place in the domainname from where the
 * common string starts.  For example, if the name was "foo.my.domain." and the
 * domainname was "my.domain.", the name would be encoded as "foo.10" because
 * the length of the common part "my.domain." is 10.
 */
bool_t
xdr_nis_name_abbrev(
	XDR		*xdrs,
	nis_name	*namep,
	nis_name	domainname)	/* domainname field from the table */
{
	size_t	name_len, dom_len, min_len;
	char 	buf[NIS_MAXNAMELEN];
	char 	*name;
	char	*lenstr, *tmp;
	int	i;

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		/* Get the start of the common part */
		name = *namep;
		name_len = strlen(name);
		if (name_len == 0)
			return (xdr_nis_name(xdrs, namep));
		dom_len = strlen(domainname);
		min_len = (name_len < dom_len) ? name_len : dom_len;
		for (i = 1; i <= min_len; i++) {
			if (name[name_len - i] != domainname[dom_len - i])
				break;
		}
		i--;
		memcpy(buf, name, name_len - i);
		sprintf(buf + name_len - i, ".%d", dom_len - i);
		tmp = buf;
		return (xdr_nis_name(xdrs, &tmp));

	case XDR_DECODE:
		tmp = buf;
		if (!xdr_nis_name(xdrs, &tmp))
		    return (FALSE);
		if ((buf[0] == '\0') || buf[strlen(buf) - 1] == '.') {
			/* It is either a FQN or a NULL string */
			if (*namep) {
				strcpy(*namep, buf);
				return (TRUE);
			} else {
				if ((*namep = strdup(buf)) == NULL)
					return (FALSE);
				else
					return (TRUE);
			}
		}
		/* Now concoct the new name */
		if ((lenstr = strrchr(buf, '.')) == NULL) {
			/* something went wrong here */
			syslog(LOG_ERR,
				"xdr_nis_name_abbrev: no dot found in %s", buf);
			return (FALSE);
		}
		i = atoi(lenstr + 1);
		strcpy(lenstr, domainname + i);
		if (*namep) {
			strcpy(*namep, buf);
		} else {
			if ((*namep = strdup(buf)) == NULL)
				return (FALSE);
		}
		return (TRUE);

	default:
		return (xdr_nis_name(xdrs, namep));
	}
}

/*
 * Imported from rpc.nisd/nis_db.c
 *
 * special XDR for fetus object.  We create the actual object from the
 * "forming" object plus the table object.  We create this special object to
 * save the following components of the nis_object:
 *	zo_name and zo_domain: replaced by just the length field of 0.  We had
 *		to keep the length field for backward compatibility.  If we
 *		ever change the object format, we should fix this.
 *	zo_owner and zo_group: we condensed it by abbreviating the common part
 *		shared between the table object and the entry object
 *	en_type: Avoided altogether
 *	zo_type and other en_data: Avoided altogether.
 *
 * XXX: If the definition of nis_object ever changes, this should be changed.
 */
bool_t
xdr_nis_fetus_object(
	XDR		*xdrs,
	nis_object	*objp,	/* Entry object */
	nis_object	*tobj)	/* Table object */
{
	uint_t	size;

	if (xdrs->x_op == XDR_FREE)
		return (xdr_nis_object(xdrs, objp));
	if (!xdr_nis_oid(xdrs, &objp->zo_oid))
		return (FALSE);

	/*
	 * While encoding of zo_name, we put 0 in the length field, while for
	 * decoding, we get the name from the table object.
	 */
	if (xdrs->x_op == XDR_ENCODE) {
		size = 0;
		if (!xdr_u_int(xdrs, &size))
			return (FALSE);
	} else {
		if (!xdr_u_int(xdrs, &size))
			return (FALSE);
		if (size == 0) {	/* shrinked format */
			/* get the name from the table object */
			if ((objp->zo_name = strdup(tobj->zo_name)) == NULL)
				return (FALSE);
		} else {
			/*
			 * We are opening up the xdr_string implementation here
			 * because we called xdr_u_int() earlier.
			 */
			if ((objp->zo_name = (char *)malloc(size + 1)) == NULL)
				return (FALSE);
			if (!xdr_opaque(xdrs, objp->zo_name, size))
				return (FALSE);
		}
	}

	/*
	 * We use the xdr_nis_name_abbrev() function for both owner
	 * and group which constructs the name from the domain name.
	 */
	if (!xdr_nis_name_abbrev(xdrs, &objp->zo_owner, tobj->zo_domain))
		return (FALSE);
	if (!xdr_nis_name_abbrev(xdrs, &objp->zo_group, tobj->zo_domain))
		return (FALSE);

	/*
	 * While encoding of zo_domain, we put 0 in the length field, while for
	 * decoding, we get the name from the table object.  Same as above for
	 * the name.  Could have used a function instead.
	 */
	if (xdrs->x_op == XDR_ENCODE) {
		size = 0;
		if (!xdr_u_int(xdrs, &size))
			return (FALSE);
	} else {
		if (!xdr_u_int(xdrs, &size))
			return (FALSE);
		if (size == 0) {	/* shrinked format */
			/* get the name from the table object */
			if ((objp->zo_domain = strdup(tobj->zo_domain)) == NULL)
				return (FALSE);
		} else {
			/*
			 * We are opening up the xdr_string implementation here
			 * because we called xdr_u_int() earlier.
			 */
			if ((objp->zo_domain = (char *)malloc(size + 1))
				== NULL)
				return (FALSE);
			if (!xdr_opaque(xdrs, objp->zo_domain, size))
				return (FALSE);
		}
	}

	if (!xdr_u_int(xdrs, &objp->zo_access))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->zo_ttl))
		return (FALSE);

	/*
	 * We know that this is an entry object, so we'll save all the entry_obj
	 * space because we can recreate it later.
	 */
	if (xdrs->x_op == XDR_ENCODE)
		return (TRUE);
	/* Now for the DECODE case, just handcraft the entries and ignore XDR */
	objp->zo_data.zo_type = NIS_ENTRY_OBJ;
	if ((objp->zo_data.objdata_u.en_data.en_type =
		strdup(tobj->zo_data.objdata_u.ta_data.ta_type)) == NULL)
		return (FALSE);
	objp->zo_data.objdata_u.en_data.en_cols.en_cols_val = NULL;
	objp->zo_data.objdata_u.en_data.en_cols.en_cols_len = 0;
	return (TRUE);
}

static const char	*in_directory = "IN_DIRECTORY";

/*
 * Given an input NIS+ object, create the kind
 * of pseudo-entry_obj (with an XDR-encoded nis_object in the
 * first column) that's stored in the DB. Note that:
 *
 *	If the input object is an entry, it's assumed to have the
 *	columns moved up one step (col 0 in en_cols.en_cols_val[1],
 *	etc.). en_cols.en_cols_val[0] will be overwritten. The
 *	input object will be changed (some pointers set to zero,
 *	etc.) on exit.
 *
 *	'eo' is assumed to be a pointer to an empty entry_obj (or,
 *	at least, one that can be overwritten). It must not be a
 *	pointer to the entry_obj in 'obj'. If the input object is
 *	of a type other than entry, the 'eo' pointer must have
 *	en_cols.en_cols_val appropriately initialized to an array of
 *	(at least) length one.
 *
 *	'tobj' is a pointer to the table object for the table for
 *	which the entry_obj is destined. It's needed for entry objects,
 *	but unused for other object types.
 */
entry_obj *
makePseudoEntryObj(nis_object *obj, entry_obj *eo, nis_object *tobj) {
	int		bufsize;
	char		*buf;
	XDR		xdrs;
	bool_t		xret;
	uint_t		ecl;
	entry_col	*ecv;
	char		*myself = "makePseudoEntryObj";

	if (obj == 0 || eo == 0)
		return (0);

	if (obj->zo_data.zo_type == NIS_ENTRY_OBJ) {
		*eo = obj->zo_data.objdata_u.en_data;
		eo->en_type = 0;

		/*
		 * To prevent the XDR function from making a copy of
		 * the entry columns, we set the columns structure to
		 * 0 (ie no column data)
		 */
		ecl = obj->EN_data.en_cols.en_cols_len;
		ecv = obj->EN_data.en_cols.en_cols_val;
		obj->EN_data.en_cols.en_cols_len  = 0;
		obj->EN_data.en_cols.en_cols_val  = 0;
	} else {
		eo->en_type = (char *)in_directory;
	}

	bufsize = xdr_sizeof(xdr_nis_object, obj);
	buf = am(myself, bufsize);
	if (buf == 0) {
		if (obj->zo_data.zo_type == NIS_ENTRY_OBJ) {
			obj->EN_data.en_cols.en_cols_len = ecl;
			obj->EN_data.en_cols.en_cols_val = ecv;
		}
		return (0);
	}

	xdrmem_create(&xdrs, (char *)buf, bufsize, XDR_ENCODE);

	if (obj->zo_data.zo_type == NIS_ENTRY_OBJ) {
		xret = xdr_nis_fetus_object(&xdrs, obj, tobj);
	} else {
		xret = xdr_nis_object(&xdrs, obj);
	}

	/* Restore the 'obj' */
	if (obj->zo_data.zo_type == NIS_ENTRY_OBJ) {
		obj->EN_data.en_cols.en_cols_len = ecl;
		obj->EN_data.en_cols.en_cols_val = ecv;
	}

	if (!xret) {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: XDR encode failure", myself);
		sfree(buf);
		return (0);
	}

	eo->en_cols.en_cols_val[0].ec_value.ec_value_val = buf;
	eo->en_cols.en_cols_val[0].ec_value.ec_value_len = xdr_getpos(&xdrs);
	eo->en_cols.en_cols_val[0].ec_flags = EN_BINARY+EN_XDR;

	return (eo);
}

nis_object *
unmakePseudoEntryObj(entry_obj *e, nis_object *tobj) {
	nis_object	*o;
	XDR		xdrs;
	bool_t		stat;
	char		*myself = "unmakePseudoEntryObj";

	if (e == 0 || e->en_cols.en_cols_val == 0 ||
			e->en_cols.en_cols_len == 0)
		return (0);

	o = am(myself, sizeof (*o));
	if (o == 0)
		return (0);

	xdrmem_create(&xdrs, e->en_cols.en_cols_val[0].ec_value.ec_value_val,
			e->en_cols.en_cols_val[0].ec_value.ec_value_len,
			XDR_DECODE);

	if (tobj != 0 && (e->en_type == 0 || e->en_type[0] == '\0')) {
		stat = xdr_nis_fetus_object(&xdrs, o, tobj);
	} else {
		stat = xdr_nis_object(&xdrs, o);
	}

	if (!stat) {
		sfree(o);
		o = 0;
	}

	/*
	 * If it's an entry object, construct the column information.
	 * We make this a copy, so that 'o' can be freed using
	 * nis_destroy_object().
	 */
	if (o != 0 && o->zo_data.zo_type == NIS_ENTRY_OBJ &&
			o->zo_data.objdata_u.en_data.en_cols.en_cols_val == 0 &&
			e->en_cols.en_cols_len > 1) {
		entry_col	*ec, *oec;
		uint_t		i, *ocl;

		ec = am(myself, (e->en_cols.en_cols_len - 1) * sizeof (ec[0]));
		if (ec == 0) {
			nis_destroy_object(o);
			return (0);
		}

		o->zo_data.objdata_u.en_data.en_cols.en_cols_val = ec;
		o->zo_data.objdata_u.en_data.en_cols.en_cols_len = 0;
		ocl = &o->zo_data.objdata_u.en_data.en_cols.en_cols_len;
		oec = e->en_cols.en_cols_val;

		for (i = 1; i < e->en_cols.en_cols_len; i++) {
			uint_t	len;

			if (oec[i].ec_value.ec_value_val != 0) {
				len = oec[i].ec_value.ec_value_len;
				if (len == 0)
					len++;
				ec[i-1].ec_value.ec_value_val = am(myself, len);
				if (ec[i-1].ec_value.ec_value_val == 0) {
					nis_destroy_object(o);
					return (0);
				}
				(void) memcpy(ec[i-1].ec_value.ec_value_val,
						oec[i].ec_value.ec_value_val,
						oec[i].ec_value.ec_value_len);
				ec[i-1].ec_value.ec_value_len =
						oec[i].ec_value.ec_value_len;
			} else {
				ec[i-1].ec_value.ec_value_val = 0;
				ec[i-1].ec_value.ec_value_len = 0;
			}
			*ocl += 1;
		}
	}

	/*
	 * If it's an entry, and we have the table object, make sure
	 * zo_name and en_type either already are set, or get them
	 * from the table.
	 */
	if (o != 0 && o->zo_data.zo_type == NIS_ENTRY_OBJ && tobj != 0) {
		if (o->zo_name == 0)
			o->zo_name = sdup(myself, T, tobj->zo_name);
		if (o->zo_data.objdata_u.en_data.en_type == 0)
			o->zo_data.objdata_u.en_data.en_type = sdup(myself, T,
				tobj->zo_data.objdata_u.ta_data.ta_type);
	}

	return (o);
}

/*
 * Input:  A (nis_object *), and (optionally) an (entry_obj *) array.
 * Output: Pointer to an XDR:ed version of an (xdr_nis_object_t).
 */
void *
xdrNisObject(nis_object *obj, entry_obj **ea, int numEa, int *xdrLenP) {
	xdr_nis_object_t	xno;
	void			*buf;
	int			xdrLen;
	XDR			xdrs;
	bool_t			xret;
	char			*myself = "xdrNisObject";

	if (obj == 0)
		return (0);

	/*
	 * The version tells us what the XDR:ed buffer contains.
	 * Should be incremented whenever xdr_nis_object_t changes
	 * incompatibly.
	 */
	xno.xversion = 1;

	xno.obj = obj;

	if (obj->zo_data.zo_type == NIS_DIRECTORY_OBJ &&
			ea != 0 && numEa > 0) {
		int	i;

		/*
		 * The ea[] array is expected to contain the kind of
		 * pseudo-entry object stored in the nisdb incarnation
		 * of a NIS+ directory. Column zero contains the XDR:ed
		 * directory entry object (which we ignore), while column
		 * one contains the name of said entry. It's the latter
		 * that we borrow for use in the dirEntry[] list of the
		 * xdr_nis_object_t.
		 */

		xno.dirEntry.dirEntry_len = 0;
		xno.dirEntry.dirEntry_val = am(myself, numEa *
			sizeof (xno.dirEntry.dirEntry_val[0]));
		if (xno.dirEntry.dirEntry_val == 0)
			return (0);

		for (i = 0; i < numEa; i++) {
			if (ea[i] == 0 || ea[i]->en_cols.en_cols_val == 0 ||
					ea[i]->en_cols.en_cols_len != 2 ||
					ea[i]->en_cols.en_cols_val[1].
						ec_value.ec_value_len == 0)
				continue;
			/*
			 * Yes, there's a NUL at the end of the dir entry
			 * name.
			 */
			xno.dirEntry.dirEntry_val[xno.dirEntry.dirEntry_len] =
				ea[i]->en_cols.en_cols_val[1].
					ec_value.ec_value_val;
			xno.dirEntry.dirEntry_len++;
		}
	} else {
		/* No directory entries */
		xno.dirEntry.dirEntry_len = 0;
		xno.dirEntry.dirEntry_val = 0;
	}

	xdrLen = xdr_sizeof(xdr_xdr_nis_object_t, &xno);
	buf = am(myself, xdrLen);
	if (buf == 0)
		return (0);

	xdrmem_create(&xdrs, (char *)buf, xdrLen, XDR_ENCODE);

	xret = xdr_xdr_nis_object_t(&xdrs, &xno);

	sfree(xno.dirEntry.dirEntry_val);

	if (!xret) {
		sfree(buf);
		return (0);
	}

	if (xdrLenP != 0)
		*xdrLenP = xdrLen;

	return (buf);
}

/*
 * Input:  Pointer to an XDR:ed version of an (xdr_nis_object_t).
 * Output: Pointer to a (nis_object *) and (if the object is a
 *         directory) a pointer to an array of (entry_obj *).
 */
nis_object *
unXdrNisObject(void *buf, int bufLen, entry_obj ***eaP, int *numEaP) {
	xdr_nis_object_t	*xno;
	XDR			xdrs;
	bool_t			xret;
	entry_obj		**ea;
	int			numEa;
	nis_object		*o;
	char			*myself = "unXdrNisObject";

	if (buf == 0 || bufLen <= 0)
		return (0);

	xno = am(myself, sizeof (*xno));
	if (xno == 0)
		return (0);

	xdrmem_create(&xdrs, buf, bufLen, XDR_DECODE);
	xret = xdr_xdr_nis_object_t(&xdrs, xno);

	if (!xret) {
		sfree(xno);
		return (0);
	}

	switch (xno->xversion) {
	case 1:
		break;
	default:
		xdr_free(xdr_xdr_nis_object_t, (char *)xno);
		sfree(xno);
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Unknown xdr_nis_object_t version %d",
			myself, xno->xversion);
		return (0);
	}

	if (eaP != 0 && numEaP != 0 && xno->dirEntry.dirEntry_len > 0 &&
			xno->dirEntry.dirEntry_val != 0) {
		ea = am(myself, xno->dirEntry.dirEntry_len * sizeof (ea[0]));
		if (ea == 0) {
			xdr_free(xdr_xdr_nis_object_t, (char *)xno);
			sfree(xno);
			return (0);
		}
		for (numEa = 0; numEa < xno->dirEntry.dirEntry_len; numEa++) {
			ea[numEa] = am(myself, sizeof (*ea[numEa]));
			if (ea[numEa] != 0) {
				ea[numEa]->en_cols.en_cols_len = 2;
				ea[numEa]->en_cols.en_cols_val = am(myself,
					ea[numEa]->en_cols.en_cols_len *
				sizeof (ea[numEa]->en_cols.en_cols_val[0]));
			}
			if (ea[numEa] == 0 ||
					ea[numEa]->en_cols.en_cols_val == 0) {
				int	i;
				for (i = 0; i < numEa; i++) {
					sfree(ea[i]->en_cols.en_cols_val);
					sfree(ea[i]);
				}
				sfree(ea);
				xdr_free(xdr_xdr_nis_object_t, (char *)xno);
				sfree(xno);
				return (0);
			}
			/* Leave column 0 (XDR:ed object) empty */
			ea[numEa]->en_cols.en_cols_val[0].
				ec_value.ec_value_len = 0;
			ea[numEa]->en_cols.en_cols_val[0].
				ec_value.ec_value_val = 0;
			/*
			 * Fill in name of dir entry. The DB counts the NUL
			 * as part of the dir entry name; hence, add one
			 * to the string length.
			 */
			ea[numEa]->en_cols.en_cols_val[1].
				ec_value.ec_value_len = slen(xno->dirEntry.
					dirEntry_val[numEa]) + 1;
			ea[numEa]->en_cols.en_cols_val[1].
				ec_value.ec_value_val =
					xno->dirEntry.dirEntry_val[numEa];
		}
		*eaP = ea;
		*numEaP = numEa;
		/*
		 * The xno->dirEntry.dirEntry_val[] pointers are duplicated
		 * in 'ea'. Set the xno pointers to zero, so that the xdr_free
		 * doesn't free the 'ea' data.
		 */
		if (numEa > 0) {
			int	i;
			for (i = 0; i < numEa; i++) {
				xno->dirEntry.dirEntry_val[i] = 0;
			}
		}
	} else {
		if (eaP != 0)
			*eaP = 0;
		if (numEaP != 0)
			*numEaP = 0;
	}

	o = xno->obj;
	xno->obj = 0;
	xdr_free(xdr_xdr_nis_object_t, (char *)xno);
	sfree(xno);

	return (o);
}

void
freeEntryObjArray(entry_obj **ea, int numEa) {
	int	i;

	if (ea == 0)
		return;

	for (i = 0; i < numEa; i++) {
		int	j;

		for (j = 0; j < ea[i]->en_cols.en_cols_len; j++) {
			sfree(ea[i]->en_cols.en_cols_val[j].
				ec_value.ec_value_val);
		}

		sfree(ea[i]->en_cols.en_cols_val);
	}

	sfree(ea);
}

/*
 * Return TRUE if 'o1' and 'o2' are the same, FALSE otherwise.
 * We perform the comparison by XDR encoding the objects, and then
 * checking the XDR buffers for equality. However, we don't want to
 * include the zo_oid (i.e., ctime and mtime) in the comparison.
 */
bool_t
sameNisPlusObj(nis_object *o1, nis_object *o2) {
	XDR		x1, x2;
	void		*b1, *b2;
	int		l1, l2;
	bool_t		ret;
	nis_object	obj1, obj2;
	char		*myself = "sameNisPlusObj";

	if (o1 == o2)
		return (TRUE);
	else if (o1 == 0 || o2 == 0)
		return (FALSE);

	/*
	 * We want to exclude the zo_oid from the comparison. In order
	 * not to modify the objects (even very briefly), we do this by
	 * making copies (nis_object itself only, not the underlying
	 * structures accessed through pointers), and setting the zo_oid
	 * to zero in the copies.
	 */
	obj1 = *o1;
	obj2 = *o2;
	obj1.zo_oid.ctime = obj1.zo_oid.mtime = 0;
	obj2.zo_oid.ctime = obj2.zo_oid.mtime = 0;

	l1 = xdr_sizeof(xdr_nis_object, &obj1);
	l2 = xdr_sizeof(xdr_nis_object, &obj2);
	if (l1 != l2)
		return (FALSE);

	b1 = am(myself, l1);
	b2 = am(myself, l2);
	if (b1 == 0 || b2 == 0) {
		sfree(b1);
		sfree(b2);
		return (FALSE);
	}

	xdrmem_create(&x1, (char *)b1, l1, XDR_ENCODE);
	xdrmem_create(&x2, (char *)b2, l2, XDR_ENCODE);

	if (xdr_nis_object(&x1, &obj1) && xdr_nis_object(&x2, &obj2)) {
		ret = (memcmp(b1, b2, l1) == 0);
	} else {
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: xdr_nis_object() error",
			myself);
		ret = FALSE;
	}

	sfree(b1);
	sfree(b2);

	return (ret);
}

/*
 * A wrapper/convenience function for sameNisPlusObj() that extracts
 * the object in column zero of 'e2'.
 */
bool_t
sameNisPlusPseudoObj(nis_object *o1, entry_obj *e2) {
	nis_object	*o2;
	bool_t		res;

	if (o1 == 0 && e2 == 0)
		return (TRUE);
	else if (e2 == 0)
		return (FALSE);

	o2 = unmakePseudoEntryObj(e2, 0);
	if (o2 == 0)
		return ((o1 == 0) ? TRUE : FALSE);

	res = sameNisPlusObj(o1, o2);

	nis_destroy_object(o2);

	return (res);
}
