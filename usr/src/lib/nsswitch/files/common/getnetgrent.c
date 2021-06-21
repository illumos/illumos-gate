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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	files/getnetgrent.c -- "files" backend for nsswitch "netgroup" database
 *
 *	The API for netgroups differs sufficiently from that for the average
 *	getXXXbyYYY function that we use very few of the support routines in
 *	files_common.h.
 *
 *	The implementation of setnetgrent()/getnetgrent() here follows the
 *	the 4.x code, inasmuch as the setnetgrent() routine does all the work
 *	of traversing the netgroup graph and building a (potentially large)
 *	list in memory, and getnetgrent() just steps down the list.
 *
 *	An alternative, and probably better, implementation would lazy-eval
 *	the netgroup graph in response to getnetgrent() calls (though
 *	setnetgrent() should still check for the top-level netgroup name
 *	and return NSS_SUCCESS / NSS_NOTFOUND).
 */

#include "files_common.h"
#include <ctype.h>
#include <rpcsvc/ypclnt.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <sys/sysmacros.h>

/*
 * Tricky debug support
 */

#pragma weak __nss_files_netgr_debug
#pragma weak __nss_files_netgr_error
extern void __nss_files_netgr_debug(const char *, ...);
extern void __nss_files_netgr_error(const char *, ...);

/*
 * Start of stuff borrowed from getgrent.c
 */
static uint_t
hash_netgrname(nss_XbyY_args_t *argp, int keyhash, const char *line,
    int linelen)
{
	const char	*name;
	uint_t		namelen, i;
	uint_t		hash = 0;

	if (keyhash) {
		name = argp->key.name;
		namelen = strlen(name);
	} else {
		name = line;
		namelen = 0;
		while (linelen-- && !isspace(*line)) {
			line++;
			namelen++;
		}
	}

	for (i = 0; i < namelen; i++)
		hash = hash * 15 + name[i];
	return (hash);
}

static files_hash_func hash_netgr[1] = { hash_netgrname };

static files_hash_t hashinfo = {
	DEFAULTMUTEX,
	sizeof (struct nss_netgrent),
	NSS_LINELEN_NETGROUP,
	1,
	hash_netgr
};

static int
check_netgrname(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char *linep, *limit;
	const char *keyp = argp->key.name;

	linep = line;
	limit = line + linelen;

	/* +/- entries valid for compat source only */
	if (linelen == 0 || *line == '+' || *line == '-')
		return (0);
	while (*keyp && linep < limit && *keyp == *linep) {
		keyp++;
		linep++;
	}
	return (linep < limit && *keyp == '\0' && isspace(*linep));
}

static nss_status_t
getbyname(files_backend_ptr_t be, void *a)
{
	return (_nss_files_XY_hash(be, a, 1, &hashinfo, 0, check_netgrname));
}

/*
 * End of stuff borrowed from getgrent.c
 *
 * Now some "glue" functions based loosely on
 *   lib/libc/port/gen/getgrnam_r.c
 */


/*
 * This is a special purpose str2ent (parse) function used only in
 * the _nss_files_getbyname() below.  A general-purpose version of
 * this parser would copy the incoming line buffer to the passed
 * temporary buffer, and fill in the passed struct nss_netgrent with
 * pointers into that temporary buffer.  Our caller only needs the
 * list of members of this netgroup, and since that string already
 * exists in ready-to-use form in the incoming line buffer, we just
 * use that.  Also special here is the fact that we allocate a copy
 * of the member list, both because the caller wants it allocated,
 * and because the buffer at *instr will change after we return.
 * The caller passes null for a temporary buffer, which we ignore.
 *
 * See the test program: cmd/nsstest/netgr_get.c
 * for a more generic version of this function.
 */
static int
str2netgr(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	const char sep[] = " \t\n";
	struct nss_netgrent *netgr = ent;
	const char *p;

	/* skip leading space */
	p = instr;
	while (isspace(*p))
		p++;

	/* should be at the key */
	if (*p == '\0')
		return (NSS_STR_PARSE_PARSE);
	/* Full parser would set netgr_name = p here. */

	/* skip the key ... */
	p = strpbrk(p, sep);
	if (p == NULL)
		return (NSS_STR_PARSE_PARSE);
	/* Full parser would store a null at *p here. */

	/* skip separators */
	while (isspace(*p))
		p++;

	/*
	 * Should be at the members list, which is the
	 * rest of the input line.
	 */
	if (*p == '\0')
		return (NSS_STR_PARSE_PARSE);

	/*
	 * Caller wants this allocated.  Do it now,
	 * before the inbuf gets re-used.
	 */
	netgr->netgr_members = strdup(p);
	if (netgr->netgr_members == NULL)
		return (NSS_STR_PARSE_PARSE);

	return (NSS_STR_PARSE_SUCCESS);
}

/*
 * This is a compatibility "shim" used by top_down() to get
 * the list of members for some netgroup.  On success, the
 * list of members is returned in allocated memory via valp.
 */
static nss_status_t
netgr_get_members(struct files_backend *be,
    const char *name, char **valp)
{
	struct nss_netgrent netgr;
	nss_XbyY_args_t args;
	nss_status_t result;

	if (name == (const char *)NULL)
		return (NSS_ERROR);

	(void) memset(&netgr, '\0', sizeof (netgr));
	(void) memset(&args, '\0', sizeof (args));
	args.buf.result = &netgr;
	args.str2ent = str2netgr;
	args.key.name = name;
	result = getbyname(be, &args);

	if (result == NSS_SUCCESS) {
		/* Note: allocated memory. */
		*valp = netgr.netgr_members;
		if (*valp == NULL)
			result = NSS_UNAVAIL;
	}

	return (result);
}


/*
 * End "glue" functions
 *
 * The rest of this is based on:
 *  lib/nsswitch/nis/common/getnetgrent.c
 */


/*
 * The nss_backend_t for a getnetgrent() sequence;  we actually give the
 *   netgroup frontend a pointer to one of these structures in response to
 *   a (successful) setnetgrent() call on the files_backend backend
 *   described further down in this file.
 */

struct files_getnetgr_be;
typedef nss_status_t	(*files_getnetgr_op_t)(
	struct files_getnetgr_be *, void *);

struct files_getnetgr_be {
	files_getnetgr_op_t	*ops;
	nss_dbop_t		n_ops;
	/*
	 * State for set/get/endnetgrent()
	 */
	char			*netgroup;
	struct grouplist	*all_members;
	struct grouplist	*next_member;
};

struct grouplist {  /* One element of the list generated by a setnetgrent() */
	char			*triple[NSS_NETGR_N];
	struct	grouplist	*gl_nxt;
};

static nss_status_t
getnetgr_set(struct files_getnetgr_be *be, void *a)
{
	const char		*netgroup = (const char *) a;

	if (be->netgroup != NULL &&
	    strcmp(be->netgroup, netgroup) == 0) {
		/* We already have the member-list;  regurgitate it */
		be->next_member = be->all_members;
		return (NSS_SUCCESS);
	}
	return (NSS_NOTFOUND);
}

static nss_status_t
getnetgr_get(struct files_getnetgr_be *be, void *a)
{
	struct nss_getnetgrent_args *args = (struct nss_getnetgrent_args *)a;
	struct grouplist	*mem;

	if ((mem = be->next_member) == 0) {
		args->status = NSS_NETGR_NO;
	} else {
		char			*buffer	= args->buffer;
		int			buflen	= args->buflen;
		enum nss_netgr_argn	i;

		args->status = NSS_NETGR_FOUND;

		for (i = 0;  i < NSS_NETGR_N;  i++) {
			const char	*str;
			ssize_t	len;

			if ((str = mem->triple[i]) == 0) {
				args->retp[i] = NULL;
			} else if ((len = strlen(str) + 1) <= buflen) {
				args->retp[i] = buffer;
				(void) memcpy(buffer, str, len);
				buffer += len;
				buflen -= len;
			} else {
				args->status = NSS_NETGR_NOMEM;
				break;
			}
		}
		be->next_member	= mem->gl_nxt;
	}
	return (NSS_SUCCESS);	/* Yup, even for end-of-list, i.e. */
				/* do NOT advance to next backend. */
}

static nss_status_t
getnetgr_end(struct files_getnetgr_be *be, void *dummy)
{
	struct grouplist	*gl;
	struct grouplist	*next;

	for (gl = be->all_members; gl != NULL; gl = next) {
		enum nss_netgr_argn	i;

		next = gl->gl_nxt;
		for (i = NSS_NETGR_MACHINE; i < NSS_NETGR_N; i++) {
			free(gl->triple[i]);
		}
		free(gl);
	}
	be->all_members = NULL;
	be->next_member = NULL;
	free(be->netgroup);
	be->netgroup = NULL;
	return (NSS_SUCCESS);
}

static nss_status_t
getnetgr_destr(struct files_getnetgr_be	*be, void *dummy)
{
	if (be != NULL) {
		(void) getnetgr_end(be, NULL);
		free(be);
	}
	return (NSS_SUCCESS);
}

static files_getnetgr_op_t getnetgr_ops[] = {
	getnetgr_destr,
	getnetgr_end,
	getnetgr_set,
	getnetgr_get,	/* getnetgrent_r() */
};


/*
 * The nss_backend_t for innetgr() and setnetgrent().
 * Also getbyname(), but that's only for testing.
 */



/*
 * Code to do top-down search in the graph defined by the 'netgroup' YP map
 */

/*
 * ===> This code is now used for setnetgrent(), not just innetgr().
 *
 * If the easy way doesn't pan out, recursively search the 'netgroup' map.
 * In order to do this, we:
 *
 *    -	remember all the netgroup names we've seen during this search,
 *	whether or not we've expanded them yet (we want fast insertion
 *	with duplicate-detection, so use yet another chained hash table),
 *
 *    -	keep a list of all the netgroups we haven't expanded yet (we just
 *	want fast insertion and pop-first, so a linked list will do fine).
 *	If we insert at the head, we get a depth-first search;  insertion
 *	at the tail gives breadth-first (?), which seems preferable (?).
 *
 * A netgrnam struct contains pointers for both the hash-table and the list.
 * It also contains the netgroup name;  note that we embed the name at the
 * end of the structure rather than holding a pointer to yet another
 * malloc()ed region.
 *
 * A netgrtab structure contains the hash-chain heads and the head/tail
 * pointers for the expansion list.
 */

struct netgrnam {
	struct netgrnam	*hash_chain;
	struct netgrnam	*expand_next;
	char		name[1];	/* Really [strlen(name) + 1] */
};

#define	HASHMOD	113

struct netgrtab {
	struct netgrnam	*expand_first;
	struct netgrnam	**expand_lastp;
	struct netgrnam	*hash_heads[HASHMOD];
};

static void
ngt_init(struct netgrtab *ngt)
{
	(void) memset((void *)ngt, '\0', sizeof (*ngt));
	ngt->expand_lastp = &ngt->expand_first;
}

/* === ? Change ngt_init() and ngt_destroy() to malloc/free struct netgrtab */

static void
/* ==> ? Should return 'failed' (out-of-memory) status ? */
ngt_insert(struct netgrtab *ngt, const char *name, size_t namelen)
{
	unsigned	hashval;
	size_t		i;
	struct netgrnam	*cur;
	struct netgrnam	**head;

	if (__nss_files_netgr_debug != NULL) {
		__nss_files_netgr_debug(
		    "ngt_insert: ngt=%p names=%s", ngt, name);
	}

	for (hashval = 0, i = 0;  i < namelen;  i++) {
		hashval = (hashval << 2) + hashval +
		    ((const unsigned char *)name)[i];
	}
	head = &ngt->hash_heads[hashval % HASHMOD];
	for (cur = *head;  cur != 0;  cur = cur->hash_chain) {
		if (strncmp(cur->name, name, namelen) == 0 &&
		    cur->name[namelen] == 0) {
			return;		/* Already in table, do nothing */
		}
	}
	/* Create new netgrnam struct */
	cur = malloc(offsetof(struct netgrnam, name) + namelen + 1);
	if (cur == NULL) {
		return;			/* Out of memory, too bad */
	}
	(void) memcpy(cur->name, name, namelen);
	cur->name[namelen] = '\0';

	/* Insert in hash table */
	cur->hash_chain = *head;
	*head = cur;

	/* Insert in expansion list (insert at end for breadth-first search */
	cur->expand_next = NULL;
	*ngt->expand_lastp = cur;
	ngt->expand_lastp = &cur->expand_next;
}

static const char *
ngt_next(struct netgrtab *ngt)
{
	struct netgrnam	*first;

	if ((first = ngt->expand_first) == NULL) {
		return (NULL);
	}
	if ((ngt->expand_first = first->expand_next) == NULL) {
		ngt->expand_lastp = &ngt->expand_first;
	}
	return (first->name);
}

static void
ngt_destroy(struct netgrtab *ngt)
{
	struct netgrnam	*cur;
	struct netgrnam *next;
	int		i;

	for (i = 0;  i < HASHMOD;  i++) {
		for (cur = ngt->hash_heads[i]; cur != NULL; ) {
			next = cur->hash_chain;
			free(cur);
			cur = next;
		}
	}
	/* Don't bother zeroing pointers;  must do init if we want to reuse */
}

typedef const char *ccp;

static nss_status_t
top_down(struct files_backend *be, const char **groups, int ngroups,
    int (*func)(ccp triple[3], void *iter_args, nss_status_t *return_val),
    void *iter_args)
{
	struct netgrtab		*ngt;
	/* netgrtab goes on the heap, not the stack, because it's large and */
	/* stacks may not be all that big in multi-threaded programs. */

	const char		*group;
	int			nfound;
	int			done;
	nss_status_t		result;

	if ((ngt = malloc(sizeof (*ngt))) == NULL) {
		return (NSS_UNAVAIL);
	}
	ngt_init(ngt);

	while (ngroups > 0) {
		ngt_insert(ngt, *groups, strlen(*groups));
		groups++;
		ngroups--;
	}

	done	= 0;	/* Set to 1 to indicate that we cut the iteration  */
			/*   short (and 'result' holds the return value)   */
	nfound	= 0;	/* Number of successful netgroup getbyname calls   */

	while (!done && (group = ngt_next(ngt)) != NULL) {
		char		*val = NULL;
		char		*p;

		result = netgr_get_members(be, group, &val);
		if (result != NSS_SUCCESS) {
			if (result == NSS_NOTFOUND) {
				if (__nss_files_netgr_error != NULL)
					__nss_files_netgr_error(
			    "files netgroup lookup: %s doesn't exist",
					    group);
			} else {
				if (__nss_files_netgr_error != NULL)
					__nss_files_netgr_error(
			"files netgroup lookup: getbyname returned [%s]",
					    strerror(errno));
				done = 1;	/* Give up, return result */
			}
			/* Don't need to clean up anything */
			continue;
		}

		if (__nss_files_netgr_debug != NULL) {
			__nss_files_netgr_debug(
			    "ngt_top: ngt=%p grp=%s members=\"%s\"",
			    ngt, group, val);
		}

		nfound++;

		if ((p = strpbrk(val, "#\n")) != NULL) {
			*p = '\0';
		}
		p = val;

		/* Parse val into triples and recursive netgroup references */
		for (;;) {
			ccp			triple[NSS_NETGR_N];
			int			syntax_err;
			enum nss_netgr_argn	i;

			while (isspace(*p))
				p++;
			if (*p == '\0') {
				/* Finished processing this particular val */
				break;
			}
			if (*p != '(') {
				/* Doesn't look like the start of a triple, */
				/*   so assume it's a recursive netgroup.   */
				char *start = p;
				p = strpbrk(start, " \t");
				if (p == 0) {
					/* Point p at the final '\0' */
					p = start + strlen(start);
				}
				ngt_insert(ngt, start, (size_t)(p - start));
				continue;
			}

			/* Main case:  a (machine, user, domain) triple */
			p++;
			syntax_err = 0;
			for (i = NSS_NETGR_MACHINE; i < NSS_NETGR_N; i++) {
				char		*start;
				char		*limit;
				const char	*terminators = ",) \t";

				if (i == NSS_NETGR_DOMAIN) {
					/* Don't allow comma */
					terminators++;
				}
				while (isspace(*p))
					p++;
				start = p;
				limit = strpbrk(start, terminators);
				if (limit == 0) {
					syntax_err++;
					break;
				}
				p = limit;
				while (isspace(*p))
					p++;
				if (*p == terminators[0]) {
					/*
					 * Successfully parsed this name and
					 *   the separator after it (comma or
					 *   right paren); leave p ready for
					 *   next parse.
					 */
					p++;
					if (start == limit) {
						/* Wildcard */
						triple[i] = 0;
					} else {
						*limit = '\0';
						triple[i] = start;
					}
				} else {
					syntax_err++;
					break;
				}
			}

			if (syntax_err) {
/*
 * ===> log it;
 * ===> try skipping past next ')';  failing that, abandon the line;
 */
				break;	/* Abandon this line */
			} else if ((*func)(triple, iter_args, &result) == 0) {
				/* Return result, good or bad */
				done = 1;
				break;
			}
		}
		/* End of inner loop over val[] */
		free(val);
		val = NULL;
	}
	/* End of outer loop (!done && ngt_next(ngt) != 0) */

	ngt_destroy(ngt);
	free(ngt);

	if (done) {
		return (result);
	} else if (nfound > 0) {
		/* ==== ? Should only do this if all the top-level groups */
		/*	  exist in YP?					  */
		return (NSS_SUCCESS);
	} else {
		return (NSS_NOTFOUND);
	}
}


/*
 * Code for setnetgrent()
 */

/*
 * Iterator function for setnetgrent():  copy triple, add to be->all_members
 */
static int
save_triple(ccp trippp[NSS_NETGR_N], void *headp_arg,
    nss_status_t *return_val)
{
	struct grouplist	**headp = headp_arg;
	struct grouplist	*gl;
	enum nss_netgr_argn	i;

	if (__nss_files_netgr_debug != NULL) {
		__nss_files_netgr_debug(
		    "save_tripple: h=%s u=%s d=%s",
		    trippp[0] ? trippp[0] : "*",
		    trippp[1] ? trippp[1] : "*",
		    trippp[2] ? trippp[2] : "*");
	}

	if ((gl = malloc(sizeof (*gl))) == NULL) {
		/* Out of memory */
		*return_val = NSS_UNAVAIL;
		return (0);
	}
	for (i = NSS_NETGR_MACHINE;  i < NSS_NETGR_N;  i++) {
		if (trippp[i] == NULL) {
			/* Wildcard */
			gl->triple[i] = NULL;
		} else if ((gl->triple[i] = strdup(trippp[i])) == NULL) {
			/* Out of memory.  Free any we've allocated */
			enum nss_netgr_argn	j;

			for (j = NSS_NETGR_MACHINE;  j < i;  j++) {
				free(gl->triple[j]);
			}
			free(gl);
			*return_val = NSS_UNAVAIL;
			return (0);
		}
	}
	gl->gl_nxt = *headp;
	*headp = gl;
	return (1);	/* Tell top_down() to keep iterating */
}

static nss_status_t
netgr_set(struct files_backend *be, void *a)
{
	struct nss_setnetgrent_args *args = (struct nss_setnetgrent_args *)a;
	struct files_getnetgr_be	*get_be;
	nss_status_t		res;

	get_be = malloc(sizeof (*get_be));
	if (get_be == NULL) {
		return (NSS_UNAVAIL);
	}

	get_be->all_members = NULL;
	res = top_down(be, &args->netgroup, 1, save_triple,
	    &get_be->all_members);

	if (res == NSS_SUCCESS) {
		get_be->ops		= getnetgr_ops;
		get_be->n_ops		= ARRAY_SIZE(getnetgr_ops);
		get_be->netgroup	= strdup(args->netgroup);
		if (get_be->netgroup == NULL) {
			/* Out of memory. */
			args->iterator = NULL;
			free(get_be);
			return (NSS_UNAVAIL);
		}
		get_be->next_member	= get_be->all_members;

		args->iterator		= (nss_backend_t *)get_be;
	} else {
		args->iterator		= NULL;
		free(get_be);
	}
	return (res);
}


/*
 * Code for innetgr()
 */

/*
 * Iterator function for innetgr():  Check whether triple matches args
 */
static int
match_triple(ccp triple[NSS_NETGR_N], void *ia_arg, nss_status_t *return_val)
{
	struct nss_innetgr_args	*ia = ia_arg;
	enum nss_netgr_argn	i;

	if (__nss_files_netgr_debug != NULL) {
		__nss_files_netgr_debug(
		    "match_triple: h=%s u=%s d=%s",
		    triple[0] ? triple[0] : "*",
		    triple[1] ? triple[1] : "*",
		    triple[2] ? triple[2] : "*");
	}

	for (i = NSS_NETGR_MACHINE;  i < NSS_NETGR_N;  i++) {
		int		(*cmpf)(const char *, const char *);
		char		**argv;
		uint_t		n;
		const char	*name = triple[i];
		int		argc = ia->arg[i].argc;

		if (argc == 0 || name == NULL) {
			/* Wildcarded on one side or t'other */
			continue;
		}
		argv = ia->arg[i].argv;
		cmpf = (i == NSS_NETGR_MACHINE) ? strcasecmp : strcmp;
		for (n = 0;  n < argc;  n++) {
			if ((*cmpf)(argv[n], name) == 0) {
				break;
			}
		}
		if (n >= argc) {
			/* Match failed, tell top_down() to keep looking */
			return (1);
		}
	}
	/* Matched on all three, so quit looking and declare victory */

	if (__nss_files_netgr_debug != NULL)
		__nss_files_netgr_debug("match_triple: found");

	ia->status = NSS_NETGR_FOUND;
	*return_val = NSS_SUCCESS;
	return (0);
}

/*
 * Used to have easy_way() and it's support functions here.
 */

static nss_status_t
netgr_in(struct files_backend *be, void *a)
{
	struct nss_innetgr_args	*ia = (struct nss_innetgr_args *)a;
	nss_status_t		res;

	ia->status = NSS_NETGR_NO;

	/*
	 * Used to have "easy_way" calls here for the cases
	 * where we have just a user, or just a machine.
	 *
	 * That was important for NIS, where getting the list of
	 * members for some netgroup was a yp_match call that may
	 * need to go over-the-wire.  Here in the "files" backend,
	 * getting the members of a group (getbyname) is a strictly
	 * local operation, and is cached (see hashinfo above) so
	 * it can normally complete with just memory operations.
	 *
	 * With a low-cost getbyname operation, the simple
	 * top_down algorithm has acceptable performance.
	 */

	/* Nope, try the slow way */
	ia->status = NSS_NETGR_NO;
	res = top_down(be, (const char **)ia->groups.argv, ia->groups.argc,
	    match_triple, ia);
	return (res);
}


/*
 * (Almost) boilerplate for a switch backend
 */

static nss_status_t
netgr_destr(struct files_backend *be, void *dummy)
{
	free(be);
	return (NSS_SUCCESS);
}

static files_backend_op_t netgroup_ops[] = {
	netgr_destr,
	NULL,		/* No endent, because no setent/getent */
	NULL,		/* No setent;  setnetgrent() is really a getXbyY() */
	NULL,		/* No getent in the normal sense */

	netgr_in,	/* innetgr(), via NSS_DBOP_NETGROUP_IN */
	netgr_set,	/* setnetgrent(), via NSS_DBOP_NETGROUP_SET */
	getbyname,	/* For testing, via NSS_DBOP_NETGROUP_BYNAME */
};

/*
 * This is the one-and-only external entry point in this file.
 * It's called by the NSS framework when loading this backend.
 */
nss_backend_t *
_nss_files_netgroup_constr(const char *dummy1, const char *dummy2,
    const char *dummy3)
{
	nss_backend_t	*be;

	be = _nss_files_constr(netgroup_ops,
	    ARRAY_SIZE(netgroup_ops),
	    "/etc/netgroup",
	    NSS_LINELEN_NETGROUP,
	    &hashinfo);

	return (be);
}
