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
 * Copyright (c) 1991-1999 by Sun Microsystems, Inc.
 * All rights reserved.
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
#include <stdlib.h>
#include <arpa/inet.h>
#include <rpcsvc/nislib.h>

#define	ORGDIR1		".org_dir"
#define	ORGDIR2		".org_dir."
#define	ORGDIRLEN	7

extern u_int __nis_force_hard_lookups;
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
		return (NSS_SUCCESS);

	    case NIS_NOTFOUND:
	    case NIS_PARTIAL:
	    case NIS_NOSUCHNAME:
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

nss_status_t
process_val(args, be, result)
	nss_XbyY_args_t	*args;
	nisplus_backend_t	*be;
	nis_result	*result;
{
	nss_status_t	res;
	int	parsestat;

	if ((res = switch_err(result)) != NSS_SUCCESS) {
		return (res);
	}
	if (NIS_RES_OBJECT(result) == 0) {
		return (NSS_NOTFOUND);
	}
	parsestat = (be->obj2ent)(NIS_RES_NUMOBJ(result),
			NIS_RES_OBJECT(result), args);
	if (parsestat == NSS_STR_PARSE_SUCCESS) {
		args->returnval = args->buf.result;
		res = NSS_SUCCESS;
	} else if (parsestat == NSS_STR_PARSE_ERANGE) {
		args->returnval = 0;
		args->erange = 1;
		/* We won't find this otherwise, anyway */
		res = NSS_NOTFOUND;
	} else if (parsestat == NSS_STR_PARSE_PARSE) {
		args->returnval = 0;
		res = NSS_NOTFOUND;
	}
	return (res);
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
	sprintf(namebuf, "[%s=%s]%s", column_name, keyname,
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
	sprintf(namebuf, "[%s=", column_name);
	if (strcmp(column_name, HOST_TAG_NAME) == 0) {
		p = strchr(keyname, '.');
		if (p == 0) {
			strcat(namebuf, keyname);
		} else {
			strncat(namebuf, keyname, p - keyname);
		}
	} else {
		strcat(namebuf, keyname);
		p = 0;
	}
	strcat(namebuf, "]");
	strcat(namebuf, table);
	strcat(namebuf, ORGDIR1);
	if (p != 0) {
		strcat(namebuf, p);
	}
	r = nis_list(namebuf, EXPAND_NAME | USE_DGRAM | NIS_LIST_COMMON |
						__nis_force_hard_lookups, 0, 0);
	res = process_val(argp, be, r);
	if (r != 0)
		nis_freeresult(r);

	return (res);
}

nss_backend_t *
_nss_nisplus_constr(ops, n_ops, tblname, obj2ent)
	nisplus_backend_op_t	ops[];
	int			n_ops;
	const char		*tblname;	/* (Unqualified) name of */
						/* NIS+ table		 */
	nisplus_obj2ent_func	obj2ent;
{
	const char		*directory = nis_local_directory();
	nisplus_backend_t	*be;

#ifdef DEBUG
fprintf(stderr, "Constructor called\n");
#endif	/* DEBUG */

	if (directory == 0 ||
		(directory[0] == '.' && directory[1] == '\0') ||
	    (be = (nisplus_backend_t *)malloc(sizeof (*be))) == 0) {
		return (0);
	}
	be->ops		= ops;
	be->n_ops	= n_ops;

	be->directory	= directory;
	if ((be->table_name	= (char *)malloc
		(strlen(tblname) + ORGDIRLEN + strlen(directory) + 3)) == 0)
		return (0);
	strcpy(be->table_name, tblname);
	strcat(be->table_name, ORGDIR2);
	strcat(be->table_name, directory);

	be->obj2ent	= obj2ent;
	be->cursor.no.n_bytes	= 0;
	be->cursor.no.n_len	= 0;
	be->cursor.max_len	= 0;

	/* this indicates that the path_list stuff is not initialized */
	be->path_list = 0;
	be->table_path = 0;
	be->path_index = 0;
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
		_nss_nisplus_endent(be, 0);
		if (be->table_name != 0) {
			free(be->table_name);
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
		memcpy(be->cursor.no.n_bytes, from->n_bytes, from->n_len);
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
		strcpy(table_name, tobj->zo_name);
		strcat(table_name, ".");
		strcat(table_name, tobj->zo_domain);

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
				&be->path_list[1], n - 1);
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
	be->table_path = 0;
	be->path_list = 0;
	be->path_index = 0;
	be->path_count = -1;
	be->cursor.no.n_len	= 0;
	be->cursor.max_len	= 0;
	return (NSS_SUCCESS);
}


/*
 * returns NSS_STR_PARSE_PARSE if no aliases found.
 *
 * Overly loaded interface. Trying to do to many things using one common
 * code. Main purpose is to extract cname and aliases from NIS+ entry object(s)
 * for netdb databases: hosts, networks, protocols, rpc and services.
 *
 * hosts have always been special. We have special case code to deal with
 * multiple addresses. cnamep is overloaded to indicate this special case,
 * when NULL, otherwise it is set to point to the cname field in the caller's
 * structure to be populated.
 *
 * services are weird since they sometimes use 1-1/2 keys, e.g. name and proto
 * or port and proto. The NIS+ services table also has an extra column. The
 * special argument, proto, when non-NULL, serves the purpose of indicating
 * that we are parsing a services entry, and have specified the protocol which
 * must be used for screening. It is also non-NULL, and set to the proto field
 * of the first NIS+ entry by nis_obj2ent(), in case of enumeration on
 * services, and getservbyname/port calls where caller used a null proto,
 * which implies the caller can accept "any" protocol with the matching
 * name/port. The proto argument is NULL for all non-services searches.
 */
int
netdb_aliases_from_nisobj(obj, nobj, proto, alias_list, aliaspp, cnamep, count)
	/* IN */
	nis_object	*obj;
	int		nobj;
	const	char *proto;
	/* IN-OUT */
	char	**alias_list;	/* beginning of the buffer and alias vector */
	char	**aliaspp;	/* end of the buffer + 1 */
	char	**cnamep;
	/* OUT */
	int	*count;	/* number of distinct aliases/address found */
{
	return (__netdb_aliases_from_nisobj(obj, nobj, proto, alias_list,
		aliaspp, cnamep, count, 0));
}


int
__netdb_aliases_from_nisobj(obj, nobj, proto, alias_list, aliaspp, cnamep,
		count, af_type)
	/* IN */
	nis_object	*obj;
	int		nobj;
	const	char *proto;
	int	af_type;	/* address family for host mapping only */
	/* IN-OUT */
	char	**alias_list;	/* beginning of the buffer and alias vector */
	char	**aliaspp;	/* end of the buffer + 1 */
	char	**cnamep;
	/* OUT */
	int	*count;	/* number of distinct aliases/address found */
{
	int isaddr = (cnamep == 0);

	*count = 0;
	if ((char *)alias_list >= *aliaspp) {
		/*
		 * Input condition not met. We must get a contiguous
		 * area (alias_list, *aliaspp - 1).
		 */
		return (NSS_STR_PARSE_PARSE);
	}
	for (/* */; nobj > 0; obj++, nobj--) {
		/*
		 * in every iteration, pull the
		 * address/alias/cname, copy it, set and update
		 * the pointers vector if it is not a duplicate.
		 */
		struct entry_col *ecol;
		char *val;
		int   len;

		if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		    (obj->EN_data.en_cols.en_cols_len < NETDB_COL)) {
			/* namespace/table/object is curdled */
			return (NSS_STR_PARSE_PARSE);
		}
		ecol = obj->EN_data.en_cols.en_cols_val;

		/*
		 * ASSUMPTION: cname and name field in NIS+ tables are
		 * null terminated and the len includes the null char.
		 */
		if (isaddr) {
			EC_SET(ecol, HOST_NDX_ADDR, len, val);
		} else {

			if (proto) {
				/*
				 * indicates we screen for a desired proto
				 * in the case of getservbyname/port()
				 * with a non-null proto arg
				 */
				EC_SET(ecol, SERV_NDX_PROTO, len, val);
				if (len < 2)
					return (NSS_STR_PARSE_PARSE);
				if (strcmp(proto, val) != 0)
					continue; /* ignore this entry */
			}

			if (*cnamep == 0) {
				/* canonical name, hasn't been set so far */
				EC_SET(ecol, NETDB_NDX_CNAME, len, val);
				if (len < 2)
					return (NSS_STR_PARSE_PARSE);
				*aliaspp -= len;
				if (*aliaspp <=
					(char *)&(alias_list[*count + 1])) {
				/*
				 * Has to be room for the pointer to
				 * the name we're about to add, as
				 * well as the final NULL ptr.
				 */
					return (NSS_STR_PARSE_ERANGE);
				}
				memcpy(*aliaspp, val, len);
				*cnamep = *aliaspp;
			}
			EC_SET(ecol, NETDB_NDX_NAME, len, val);
		}
		if (len > 0) {
			int i;
			struct in6_addr addr6;
			struct in_addr addr;

			if (isaddr) { /* special case for host addresses */

				if (af_type == AF_INET) {
					if (inet_pton(AF_INET, val,
							(void *) &addr) != 1)
						continue; /* skip entry */
				} else {
				/*
				 * We now allow IPv4 and IPv6 addrs in the
				 * ipnodes table. If found, convert it to a
				 * v4 mapped IPv6 address.
				 */
					if (inet_pton(AF_INET6, val,
						(void *) &addr6) != 1) {
						if (inet_pton(AF_INET, val,
							(void *) &addr) != 1) {
							continue;
							/* skip entry */
						} else {
							IN6_INADDR_TO_V4MAPPED(
							    &addr,
							    &addr6);
						}
					}
				}

				/* Check for duplicate address */
				for (i = 0; i < *count; i++) {
					if (af_type == AF_INET) {
						if (memcmp(alias_list[i], &addr,
						    sizeof (struct in_addr))
						    == 0) {
							goto next_obj;
						}
					} else {
						if (memcmp(alias_list[i],
						    &addr6,
						    sizeof (struct in6_addr))
						    == 0) {
							goto next_obj;
						}
					}
				}
				/*
				 * Hope nobody treats an h_addr_list[i] as a
				 * null terminated string. We are not storing
				 * that here.
				 */
				if (af_type == AF_INET)
					*aliaspp -= sizeof (struct in_addr);
				else
					*aliaspp -= sizeof (struct in6_addr);
			} else {
				/* Check for duplicate alias */
				for (i = 0; i < *count; i++) {
					if (strcmp(alias_list[i], val) == 0) {
						goto next_obj;
					}
				}
				*aliaspp -= len;
			}
			alias_list[i] = *aliaspp;
			if (*aliaspp <= (char *)&(alias_list[i + 1])) {
				/*
				 * Has to be room for the pointer to
				 * the address we're about to add, as
				 * well as the final NULL ptr.
				 */
				return (NSS_STR_PARSE_ERANGE);
			}
			if (isaddr) {
				if (af_type == AF_INET)
					memcpy(alias_list[i], (char *)&addr,
						sizeof (struct in_addr));
				else
					memcpy(alias_list[i], (char *)&addr6,
						sizeof (struct in6_addr));
			} else {
				memcpy(*aliaspp, val, len);
			}
			++(*count);
		}
		next_obj:
			;
	}
	alias_list[*count] = NULL;
	if (*count == 0)
		return (NSS_STR_PARSE_PARSE);
	else
		return (NSS_STR_PARSE_SUCCESS);
}
