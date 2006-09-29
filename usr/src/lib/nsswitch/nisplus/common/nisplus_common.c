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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * nisplus_common.c
 *
 * Common code used by name-service-switch "nisplus" backends
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nisplus_common.h"
#include "nisplus_tables.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <rpcsvc/nislib.h>

#define	ORGDIR1		".org_dir"
#define	ORGDIR2		".org_dir."
#define	ORGDIRLEN	7

extern uint_t __nis_force_hard_lookups;
extern int inet_pton(int, const char *, void *);

static nss_status_t
switch_err(nis_res)
	nis_result	*nis_res;
{
	if (nis_res == 0) {
		return (NSS_UNAVAIL);
	}

	switch (NIS_RES_STATUS(nis_res)) {
	    case NIS_SUCCESS:
	    case NIS_S_SUCCESS:
	    case NIS_CBRESULTS:
		errno = 0;
		return (NSS_SUCCESS);

	    case NIS_NOTFOUND:
	    case NIS_PARTIAL:
	    case NIS_NOSUCHNAME:
		errno = 0;
		return (NSS_NOTFOUND);

	    case NIS_NAMEUNREACHABLE:
	    case NIS_S_NOTFOUND:
	    case NIS_TRYAGAIN:
		return (NSS_TRYAGAIN);

	    default:
		return (NSS_UNAVAIL);
	}
}

nss_status_t
_nss_nisplus_list(name, extra_flags, res_p)
	const char	*name;
	int		extra_flags;
	nis_result	**res_p;
{
	*res_p = nis_list((char *)name, NIS_LIST_COMMON | extra_flags |
				__nis_force_hard_lookups, 0, 0);
	return (switch_err(*res_p));
}

static nss_status_t
process_val(args, be, result)
	nss_XbyY_args_t		*args;
	nisplus_backend_t	*be;
	nis_result		*result;
{
	nss_status_t	res;
	int		parsestat;

	args->returnval = NULL;
	args->returnlen = 0;

	if ((res = switch_err(result)) != NSS_SUCCESS) {
		return (res);
	}
	if (NIS_RES_OBJECT(result) == 0) {
		return (NSS_NOTFOUND);
	}
	parsestat = (be->obj2str)(NIS_RES_NUMOBJ(result),
			NIS_RES_OBJECT(result), be, args);
	if (parsestat != NSS_STR_PARSE_SUCCESS)
		goto fail;

	/*
	 * If called by nscd's switch engine, the data
	 * is available in args->buf.buffer and there is
	 * no need to marshall it.
	 *
	 * Note for some dbs like ethers, the obj2str()
	 * routine will always put the NFF data in
	 * be->buffer because we cannot determine if
	 * we are inside nscd or inside the application.
	 */
	if (args->buf.result == NULL && be->buffer == NULL) {
		args->returnval = args->buf.buffer;
		if (args->buf.buffer != NULL)
			args->returnlen = strlen(args->buf.buffer);
		return (NSS_SUCCESS);
	}

	/*
	 * If the data is in be->buffer it needs
	 * to be marshalled.
	 */
	if (args->str2ent == NULL) {
		parsestat = NSS_STR_PARSE_PARSE;
		goto fail;
	}
	parsestat = (*args->str2ent)(be->buffer,
			be->buflen,
			args->buf.result,
			args->buf.buffer,
			args->buf.buflen);
	if (parsestat == NSS_STR_PARSE_SUCCESS) {
		if (be->buffer != NULL) {
			free(be->buffer);
			be->buffer = NULL;
			be->buflen = 0;
		}
		args->returnval = args->buf.result;
		if (args->buf.result != NULL)
			args->returnlen = 1;
		else if (args->buf.buffer != NULL) {
			args->returnval = args->buf.buffer;
			args->returnlen = strlen(args->buf.buffer);
		}
		return (NSS_SUCCESS);
	}

fail:
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
		be->buflen = 0;
	}
	if (parsestat == NSS_STR_PARSE_ERANGE) {
		args->erange = 1;
		/* We won't find this otherwise, anyway */
		return (NSS_NOTFOUND);
	} else if (parsestat == NSS_STR_PARSE_PARSE) {
		return (NSS_NOTFOUND);
	}
	return (NSS_UNAVAIL);
}

nss_status_t
_nss_nisplus_lookup(be, argp, column_name, keyname)
	nisplus_backend_t	*be;
	nss_XbyY_args_t		*argp;
	const char		*column_name;
	const char		*keyname;
{
	nis_result		*r;
	char namebuf[BUFSIZ];
	nss_status_t	res;

	/* make sure we don't overflow stack: 1223320 */
	if ((strlen(column_name) +	/* size of column name	*/
	    strlen(keyname) +		/* size of keyname	*/
	    strlen(be->table_name)) +	/* size of table name	*/
	    4				/* size of '[' + '=' + ']' + '\0' */
	    > sizeof (namebuf)) {	/* BUFSIZ for array	*/
		return (NSS_NOTFOUND);
	}

	/*
	 * Assumes that "keyname" is a null-terminated string.
	 */
	(void) snprintf(namebuf, BUFSIZ, "[%s=%s]%s", column_name, keyname,
		be->table_name);
	r = nis_list(namebuf, NIS_LIST_COMMON | USE_DGRAM |
					__nis_force_hard_lookups, 0, 0);
	res = process_val(argp, be, r);
	if (r != 0)
		nis_freeresult(r);

	return (res);
}


/*
 * _nss_nisplus_expand_lookup() -- Takes an unqualified or partially
 * qualified name as a key and uses EXPAND_NAME to do a DNS-style lookup.
 * Map <name>.<domain> => [<column_name>=<name>]<table>.org_dir.<domain>
 * and in the (common) degenerate case
 * <name> => [<column_name>=<name>]<table>.org_dir
 *
 * Can also take a hostaddr as a key.  In that case, use the degenerate
 * mapping described above.
 */
nss_status_t
_nss_nisplus_expand_lookup(be, argp, column_name, keyname, table)
	nisplus_backend_t	*be;
	nss_XbyY_args_t		*argp;
	const char		*column_name;
	const char		*keyname;
	const char		*table; /* one component table name (no dots) */
{
	nis_result		*r;
	char namebuf[BUFSIZ];
	const char *directory;
	char *p;
	nss_status_t	res;

	/* make sure we don't overflow stack: 1223320 */
	if ((strlen(column_name) +	/* size of column name	*/
	    strlen(keyname) +		/* size of keyname	*/
	    strlen(ORGDIR1) +		/* size of .org_dir	*/
	    strlen(table)) +		/* size of table name	*/
	    4				/* size of '[' + '=' + ']' + '\0' */
	    > sizeof (namebuf)) {	/* BUFSIZ for array	*/
		return (NSS_NOTFOUND);
	}

	/*
	 * Assumes that "keyname" is a null-terminated string.
	 */
	if (((directory = nis_local_directory()) == 0) ||
			(directory[0] == '.' && directory[1] == '\0')) {
			return (0);
	}
	(void) snprintf(namebuf, sizeof (namebuf), "[%s=", column_name);
	if (strcmp(column_name, HOST_TAG_NAME) == 0) {
		p = strchr(keyname, '.');
		if (p == 0) {
			(void) strlcat(namebuf, keyname, sizeof (namebuf));
		} else {
			(void) strncat(namebuf, keyname, p - keyname);
		}
	} else {
		(void) strlcat(namebuf, keyname, sizeof (namebuf));
		p = 0;
	}
	(void) strlcat(namebuf, "]", sizeof (namebuf));
	(void) strlcat(namebuf, table, sizeof (namebuf));
	(void) strlcat(namebuf, ORGDIR1, sizeof (namebuf));
	if (p != 0) {
		(void) strlcat(namebuf, p, sizeof (namebuf));
	}
	r = nis_list(namebuf, EXPAND_NAME | USE_DGRAM | NIS_LIST_COMMON |
						__nis_force_hard_lookups, 0, 0);
	res = process_val(argp, be, r);
	if (r != 0)
		nis_freeresult(r);

	return (res);
}

nss_backend_t *
_nss_nisplus_constr(ops, n_ops, tblname, obj2str)
	nisplus_backend_op_t	ops[];
	int			n_ops;
	const char		*tblname; /* (Unqualified) name of NIS+ table */
	nisplus_obj2str_func	obj2str;
{
	const char		*directory = nis_local_directory();
	nisplus_backend_t	*be;

#ifdef DEBUG
	(void) fprintf(stdout, "Constructor called\n");
#endif	/* DEBUG */

	if (directory == 0 ||
		(directory[0] == '.' && directory[1] == '\0') ||
		(be = (nisplus_backend_t *)calloc(1, sizeof (*be))) == 0) {
			return (0);
	}
	be->ops	= ops;
	be->n_ops = n_ops;
	be->directory = directory;
	if ((be->table_name = (char *)malloc
		(strlen(tblname) + ORGDIRLEN + strlen(directory) + 3)) == 0) {
		free(be);
		return (0);
	}
	(void) strcpy(be->table_name, tblname);
	(void) strcat(be->table_name, ORGDIR2);
	(void) strcat(be->table_name, directory);
	be->obj2str = obj2str;
	be->path_count = -1;

	return ((nss_backend_t *)be);
}

/*ARGSUSED*/
nss_status_t
_nss_nisplus_destr(be, dummy)
	nisplus_backend_t	*be;
	void			*dummy;
{
	if (be != 0) {
		/* === Should change to invoke ops[ENDENT] ? */
		(void) _nss_nisplus_endent(be, 0);
		if (be->table_name != 0) {
			free(be->table_name);
		}
		if (be->buffer != NULL) {
			free(be->buffer);
		}
		free(be);
	}
	return (NSS_SUCCESS);	/* In case anyone is dumb enough to check */
}

static void
nis_cursor_set_next(be, from)
	nisplus_backend_t	*be;
	struct netobj *from;
{
	if (from->n_len == 0) {
		/*
		 * Grunge to treat netobj with n_len == 0 as a distinct netobj
		 */
		if (be->cursor.max_len == 0) {
			/*
			 * Could trust malloc(0) to do the right thing;
			 * would rather not.
			 */
			be->cursor.max_len = 1;
			be->cursor.no.n_bytes =
				(char *)malloc(be->cursor.max_len);
		}
	} else {
		if (be->cursor.max_len < from->n_len) {
			if (be->cursor.max_len != 0) {
				free(be->cursor.no.n_bytes);
			}
			be->cursor.max_len = from->n_len;
			be->cursor.no.n_bytes =
				(char *)malloc(be->cursor.max_len);
		}
		(void) memcpy(be->cursor.no.n_bytes, from->n_bytes,
				from->n_len);
	}
	be->cursor.no.n_len = from->n_len;
}

nss_status_t
_nss_nisplus_getent(be, a)
	nisplus_backend_t	*be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nis_result		*r;
	nss_status_t		res;

next_table:
	if (be->path_index >= be->path_count)
		return (NSS_NOTFOUND);

	if (be->cursor.no.n_len == 0) {
		r = nis_first_entry(be->path_list[be->path_index]);
	} else {
		r = nis_next_entry(be->path_list[be->path_index],
				&be->cursor.no);
	}
	if (r && r->status == NIS_NOTFOUND && be->path_index < be->path_count) {
		be->path_index++;
		be->cursor.no.n_len = 0;
		nis_freeresult(r);
		r = 0;
		goto next_table;
	}

	if (switch_err(r) == NSS_SUCCESS) {
		nis_cursor_set_next(be, &r->cookie);
	}
	res = process_val(argp, be, r);

	if (r != 0)
		nis_freeresult(r);

	return (res);
}

/*ARGSUSED*/
nss_status_t
_nss_nisplus_setent(be, dummy)
	nisplus_backend_t	*be;
	void			*dummy;
{
	size_t n;
	char *table_name;
	char *table_path;
	char *p;
	nss_status_t ns_status;
	nis_result *res;
	nis_object *tobj;

	be->buffer = NULL;
	be->buflen = 0;
	be->flag = 0;
	if (be->path_list == 0) {
		res = nis_lookup(be->table_name, NIS_LIST_COMMON |
					__nis_force_hard_lookups);
		if (res == 0 || res->status != NIS_SUCCESS) {
			ns_status = switch_err(res);
			if (res)
				nis_freeresult(res);
			return (ns_status);
		}
		tobj = res->objects.objects_val;
		if (__type_of(tobj) != NIS_TABLE_OBJ) {
			nis_freeresult(res);
			return (NSS_UNAVAIL);
		}

		/*
		 *  If the name is actually a link to a table, then
		 *  the table name will be different (since we followed
		 *  links).  We get the name of the real table here.
		 */
		n = strlen(tobj->zo_name) + strlen(tobj->zo_domain) + 2;
		table_name = (char *)malloc(n);
		if (table_name == 0) {
			nis_freeresult(res);
			return (NSS_UNAVAIL);
		}
		(void) strcpy(table_name, tobj->zo_name);
		(void) strcat(table_name, ".");
		(void) strcat(table_name, tobj->zo_domain);

		/* save table path */
		table_path = res->objects.objects_val[0].TA_data.ta_path;

		/* find approximate number of path entries */
		n = 2;    /* +1 for table itself, +1 for path with no colons */
		p = table_path;
		while ((p = strchr(p, ':')) != 0) {
			n++;
			p++;    /* skip ':' */
		}

		/* allocate path list to hold 'n' entries */
		be->path_list = (nis_name *)malloc(n * sizeof (nis_name));
		if (be->path_list == 0) {
			nis_freeresult(res);
			free(table_name);
			return (NSS_UNAVAIL);
		}

		/* steal table_path from res so it is not freed */
		be->table_path = res->objects.objects_val[0].TA_data.ta_path;
		res->objects.objects_val[0].TA_data.ta_path = 0;
		nis_freeresult(res);

		be->path_list[0] = table_name;
		be->path_count = __nis_parse_path(be->table_path,
				&be->path_list[1], (int)(n - 1));
		be->path_count++;    /* for entry at index 0 */
	}
	be->path_index = 0;

	/*
	 * Don't bother freeing no.n_bytes, because we'll
	 * probably need it
	 */
	be->cursor.no.n_len = 0;
	return (NSS_SUCCESS);
}

/*ARGSUSED*/
nss_status_t
_nss_nisplus_endent(be, dummy)
	nisplus_backend_t	*be;
	void			*dummy;
{
	if (be->cursor.no.n_bytes != 0) {
		free(be->cursor.no.n_bytes);
		be->cursor.no.n_bytes = 0;
	}
	if (be->table_path)
		free(be->table_path);
	if (be->path_list) {
		free(be->path_list[0]);
		free(be->path_list);
	}
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
		be->buflen = 0;
	}
	be->flag = 0;
	be->table_path = 0;
	be->path_list = 0;
	be->path_index = 0;
	be->path_count = -1;
	be->cursor.no.n_len = 0;
	be->cursor.max_len = 0;
	return (NSS_SUCCESS);
}

int
nis_aliases_object2str(nis_object *obj, int nobj,
		const char *cname, const char *protokey,
		char *linep, char *limit) {

	char			*p, *name, *proto;
	int			cnamelen, namelen, protolen, protokeylen;
	struct entry_col	*ecol;

	cnamelen = strlen(cname);
	protokeylen = (protokey) ? strlen(protokey) : 0;

	/*
	 * process remaining entries
	 */
	for (; nobj > 0; --nobj, obj++) {
		/* object should be non-null */
		if (obj == NULL)
			return (NSS_STR_PARSE_PARSE);

		if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
			obj->EN_data.en_cols.en_cols_len < NETDB_COL) {
			/* namespace/table/object is curdled */
			return (NSS_STR_PARSE_PARSE);
		}
		ecol = obj->EN_data.en_cols.en_cols_val;

		if (protokey != NULL) {
			/* skip if protocols doesn't match for services */
			__NISPLUS_GETCOL_OR_RETURN(ecol, SERV_NDX_PROTO,
				protolen, proto);
			if (protolen != protokeylen ||
				strncasecmp(proto, protokey, protolen) != 0)
				continue;
		}

		__NISPLUS_GETCOL_OR_CONTINUE(ecol, NETDB_NDX_NAME,
			namelen, name);

		/*
		 * add the "name" to the list if it doesn't
		 * match the "cname"
		 */
		if (cnamelen != namelen ||
				strncmp(name, cname, namelen) != 0) {
			p = linep + 1 + namelen;
			if (p >= limit)
				return (NSS_STR_PARSE_ERANGE);
			(void) snprintf(linep, (size_t)(limit - linep),
					" %s", name);
			linep = p;
		}
	}
	return (NSS_STR_PARSE_SUCCESS);
}
