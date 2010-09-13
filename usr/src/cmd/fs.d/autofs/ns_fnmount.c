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
 * ns_fnmount.c
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <xfn/xfn.h>
#include "automount.h"
#include "ns_fnutils.h"


/*
 * The maximum sizes of map names, key names, composite names, and status
 * descriptions, including the trailing '\0'.
 */
#define	MAPNAMESZ	(size_t)(AUTOFS_MAXCOMPONENTLEN + 1)
#define	KEYNAMESZ	(size_t)(AUTOFS_MAXCOMPONENTLEN + 1)
#define	COMPNAMESZ	(size_t)(MAPNAMESZ - FNPREFIXLEN + KEYNAMESZ - 2)
#define	DESCSZ		(size_t)512

typedef struct mapent	mapent;
typedef struct mapline	mapline;


/*
 * The name of an attribute.
 */
static const FN_identifier_t attr_exported = {FN_ID_STRING, 8, "exported"};


/*
 * Given a request by a particular user to mount the name "key" under
 * map/context "map", and a set of default mount options, return (in
 * "res") either a list of mapents giving the mounts that need to be
 * performed, or a symbolic link to be created for a user-relative
 * context.  If "shallow" is true return, in place of the list of
 * mapents, a single mapent representing an indirect mount point.
 *
 *	void
 *	getmapent_fn(char *key, char *map, char *opts, uid_t uid,
 *	      bool_t shallow, getmapent_fn_res *res);
 */

/*
 * Given a reference, its composite name, default mount options, and a
 * mapent root, return a list of mapents to mount.  If "shallow" is
 * true return, in place of the list of mapents, a single mapent
 * representing an indirect mount point.  The map and key strings are
 * pieces of the composite name such that:
 * "FNPREFIX/cname" == "map/key".
 */
static mapent *
process_ref(const FN_ref_t *ref, const char *cname, char *map, char *key,
    char *opts, char *root, bool_t shallow, FN_status_t *status);

/*
 * Traverse the namespace to find a frontier below ref along which
 * future mounts may need to be triggered.  Add to mapents the
 * corresponding direct autofs mount points.
 *     map:	map name for ref
 *     maplen:	strlen(map)
 *     mntpnt:	suffix of map where the current mount request begins
 *		(starts off as "", and grows as we traverse the namespace)
 *     opts:	default mount options
 *     status:	passed from above to avoid having to allocate one on each call
 * Works by calling frontier_aux() on each name bound under ref.
 * Return the new mapents, or free mapents and return NULL on failure.
 */
static mapent *
frontier(mapent *mapents, const FN_ref_t *ref, char *map, size_t maplen,
    char *mntpnt, char *opts, FN_status_t *status);

/*
 * Called by frontier(), once for each "name" that it finds.  map is
 * passed unchanged from frontier().  ref is the reference named by
 * "map/name".  If ref is found to be along the frontier, add the
 * corresponding direct autofs mount point to mapents.  Otherwise
 * continue traversing the namespace to find the frontier.  Other
 * arguments and the return value are as for frontier().
 */
static mapent *
frontier_aux(mapent *mapents, const FN_ref_t *ref, char *map, size_t maplen,
    char *mntpnt, const char *name, char *opts, FN_status_t *status);

/*
 * Given a reference with an address type of ADDR_HOST and its
 * composite name, check the attr_exported attribute to determine if
 * the corresponding directory is exported.  Return FALSE on error.
 */
static bool_t
exported(const FN_ref_t *ref, const char *cname, FN_status_t *status);

/*
 * Find a reference's address type and, if "data" is not NULL, its
 * data string.  If there is no address of a known type, set *typep to
 * NUM_ADDRTYPES; if there are several, stop after finding the first.
 * Return 0 on success.
 */
static int
addr_from_ref(const FN_ref_t *ref, const char *cname, addrtype_t *typep,
    char *data, size_t datasz);

/*
 * Decode an address's data into a string.  Return 0 on success.
 */
static int
str_from_addr(const char *cname, const FN_ref_addr_t *addr, char str[],
    size_t strsz);

/*
 * Given a map name and its current length, append "/name".  Return
 * the new length.  On error, syslog a warning and return 0.
 */
static size_t
append_mapname(char *map, size_t maplen, const char *name);

/*
 * Concatenate two strings using the given separator.  The result is a
 * newly-allocated string, or NULL on error.
 */
static char *
concat(const char *s1, char sep, const char *s2);

/*
 * Add the "nosuid" option to a mapent.  Also check for a sneaky
 * hacker trying to override this option by manually inserting a
 * multiple mount entry into the XFN namespace.  Return FALSE on error.
 */
static bool_t
safe_mapent(mapent *me);

/*
 * Append "nosuid" to a list of options.  The result is a
 * newly-allocated string, or NULL on error.
 */
static char *
safe_opts(const char *opts);

/*
 * Trim comments and trailing whitespace from ml->linebuf, then
 * unquote it and leave the result in ml.  Return 0 on success.
 */
static int
trim_line(mapline *ml);

/*
 * Determine whether ml contains an option string (such as "-ro") and
 * nothing else.
 */
static bool_t
opts_only(const mapline *ml);

/*
 * Allocate a new mapent structure.  The arguments must have been
 * malloc'ed, and are owned by the mapent; they are freed if
 * new_mapent() fails.  If any argument is NULL, the call fails and a
 * memory allocation failure is logged.  A root argument of 'noroot'
 * indicates that the map_root field does not need to be set (it's
 * only needed in the first of a list of mapents).
 */
static char *noroot = "[no root]";
static mapent *
new_mapent(char *root, char *mntpnt, char *fstype, char *mntopts, char *host,
    char *dir);

/*
 * Determine whether cname is a user-relative binding -- such as "myself" --
 * in the initial context.
 */
static bool_t
is_user_relative(const char *cname);

/*
 * Given the name of a user-relative binding, return an equivalent
 * name that is not user-relative.
 */
static char *
equiv_name(FN_ctx_t *, const char *cname, FN_status_t *);

void
getmapent_fn(char *key, char *map, char *opts, uid_t uid, bool_t shallow,
    getmapent_fn_res *res)
{
	size_t			maplen;
	FN_status_t		*status;
	FN_ctx_t		*init_ctx = NULL;
	int			statcode;
	char			cname[COMPNAMESZ];
	FN_composite_name_t	*compname;
	FN_ref_t		*ref;
	char			mapname[MAPNAMESZ];
	char			*root;

	res->type = FN_NONE;
	res->m_or_l.mapents = NULL;

	if (init_fn() != 0) {
		return;
	}

	/*
	 * For direct mounts, the key is the entire path, and the map
	 * name already has the final key component appended.  Split
	 * apart the map name and key.  The "root" of the mapent is
	 * "/key" for indirect mounts, and "" for direct mounts.
	 */
	strcpy(mapname, map);
	if (key[0] == '/') {
		key = strrchr(key, '/') + 1;
		*strrchr(mapname, '/') = '\0';
		root = strdup("");
	} else {
		root = concat("", '/', key);
	}
	map = mapname;
	maplen = strlen(map);

	if ((maplen - FNPREFIXLEN + strlen(key)) >= COMPNAMESZ) {
		if (verbose) {
			syslog(LOG_ERR, "name %s/%s too long", map, key);
		}
		return;
	}
	if (maplen == FNPREFIXLEN) {
		strcpy(cname, key);
	} else {
		sprintf(cname, "%s/%s", map + FNPREFIXLEN + 1, key);
	}

	status = fn_status_create();
	if (status == NULL) {
		if (verbose) {
			syslog(LOG_ERR, "Could not create FNS status object");
		}
		return;
	}
	init_ctx = _fn_ctx_handle_from_initial_with_uid(uid, 0, status);
	if (init_ctx == NULL) {
		logstat(status, "", "No initial context");
		goto done;
	}

#ifndef XFN1ENV
	if (is_user_relative(cname)) {
		res->type = FN_SYMLINK;
		res->m_or_l.symlink = equiv_name(init_ctx, cname, status);
		goto done;
	}
#endif

	if ((compname = new_cname(cname)) == NULL) {
		goto done;
	}
	ref = fn_ctx_lookup(init_ctx, compname, status);
	statcode = fn_status_code(status);
	fn_composite_name_destroy(compname);

	if (trace > 1 && !shallow) {
		trace_prt(1, "  FNS traversal: %s\n", cname);
	}

	if (ref == NULL) {
		if ((statcode != FN_E_NAME_NOT_FOUND) &&
		    (statcode != FN_E_NOT_A_CONTEXT)) {
			logstat(status, "lookup failed on", cname);
		}
		goto done;
	}

	res->type = FN_MAPENTS;
	res->m_or_l.mapents =
	    process_ref(ref, cname, map, key, opts, root, shallow, status);
	fn_ref_destroy(ref);
done:
	fn_ctx_handle_destroy(init_ctx);
	fn_status_destroy(status);
}


static mapent *
process_ref(const FN_ref_t *ref, const char *cname, char *map, char *key,
    char *opts, char *root, bool_t shallow, FN_status_t *status)
{
	addrtype_t	addrtype;
	mapline		ml;
	char		*addrdata = ml.linebuf;
	mapent		*mapents;
	bool_t		self;
	char		*homedir;
	size_t		maplen;
	char		*colon;
	char		*nfshost;
	char		*nfsdir;

	if ((reftype(ref) < NUM_REFTYPES) &&
	    (addr_from_ref(ref, cname, &addrtype, addrdata, LINESZ) == 0)) {

		switch (addrtype) {
		case ADDR_MOUNT:
			if (trim_line(&ml) != 0) {
				return (NULL);
			}
			if (opts_only(&ml)) {
				/* parse_entry() can't handle such lines */
				if (macro_expand("&", ml.linebuf,
				    ml.lineqbuf, LINESZ)) {
					syslog(LOG_ERR,
					"%s/%s: opts too long (max %d chars)",
					    FNPREFIX, cname, LINESZ - 1);
					return (NULL);
				}
				opts = ml.linebuf + 1;	/* skip '-' */
				goto indirect;
			}
			mapents = parse_entry(key, map, opts, &ml, NULL, 0,
			    TRUE);
			if (mapents == NULL || !safe_mapent(mapents)) {
				free_mapent(mapents);
				return (NULL);
			}
			free(mapents->map_root);
			mapents->map_root = root;
			break;

		case ADDR_HOST:
			/*
			 * Address is of the form "host:dir".
			 * If "dir" is not supplied, it defaults to "/".
			 */
			colon = strchr(addrdata, ':');
			if (colon == NULL || colon[1] == '\0') {
				nfsdir = strdup("/");
			} else {
				*colon = '\0';
				nfsdir = strdup(colon + 1);
			}
			nfshost = strdup(addrdata);
			/*
			 * If nfshost is the local host, the NFS mount
			 * request will be converted to a loopback
			 * mount.  Otherwise check that the file system
			 * is exported.
			 */
			if (nfshost != NULL) {
				self = self_check(nfshost);
				if (!self && !exported(ref, cname, status)) {
					if (transient(status)) {
						return (NULL);
					} else {
						goto indirect;
					}
				}
			}
			mapents = new_mapent(root, strdup(""), strdup("nfs"),
			    safe_opts(opts), nfshost, nfsdir);
			if (self && !shallow) {
				return (mapents);
			}
			break;

		case ADDR_USER:
			homedir = strdup(addrdata);
			homedir[strcspn(homedir, " \t\r\n")] = '\0';
			mapents = new_mapent(root, strdup(""), strdup("lofs"),
			    strdup(opts), strdup(""), homedir);
			break;
		}

		if (mapents == NULL) {
			return (NULL);
		}
		if (shallow) {
			mapents->map_root = NULL;	/* don't free "root" */
			free_mapent(mapents);
			goto indirect;
		}

		/* "map" => "map/key" */
		if ((maplen = append_mapname(map, strlen(map), key)) == 0) {
			return (mapents);
		}
		return (frontier(mapents, ref, map, maplen, map + maplen,
		    opts, status));
	}

	/* Ref type wasn't recognized. */

indirect:
	/* Install an indirect autofs mount point. */
	return (new_mapent(root, strdup(""), strdup("autofs"), strdup(opts),
	    strdup(""), concat(map, '/', key)));
}


/*
 * All that this function really does is call frontier_aux() on every
 * name bound under ref.  The rest is error checking(!)
 *
 * The error handling strategy is to reject the entire mount request
 * (by freeing mapents) if any (potentially) transient error occurs,
 * and to treat nontransient errors as holes in the affected portions
 * of the namespace.
 */
static mapent *
frontier(mapent *mapents, const FN_ref_t *ref, char *map, size_t maplen,
    char *mntpnt, char *opts, FN_status_t *status)
{
	FN_ctx_t		*ctx;
	FN_bindinglist_t	*bindings = NULL;
	FN_ref_t		*child_ref;
	FN_string_t		*child_s;
	const char		*child;
	unsigned int		statcode;

	ctx = fn_ctx_handle_from_ref(ref, XFN2(0) status);
	if (ctx == NULL) {
		if (fn_status_code(status) != FN_E_NO_SUPPORTED_ADDRESS) {
			logstat(status, "from_ref failed for", map);
		}
		goto checkerr_return;
	}

	bindings = fn_ctx_list_bindings(ctx, empty_cname, status);
	fn_ctx_handle_destroy(ctx);
	if (bindings == NULL) {
		logstat(status, "list_bindings failed for", map);
		goto checkerr_return;
	}

	while ((child_s = fn_bindinglist_next(bindings, &child_ref, status))
	    != NULL) {
		child = (const char *)fn_string_str(child_s, &statcode);
		if (child == NULL) {
			if (verbose) {
				syslog(LOG_ERR,
				    "FNS string error listing %s", map);
			}
			fn_string_destroy(child_s);
			goto err_return;
		}
		mapents = frontier_aux(mapents, child_ref, map, maplen,
		    mntpnt, child, opts, status);
		fn_string_destroy(child_s);
		fn_ref_destroy(child_ref);
		if (mapents == NULL) {
			goto noerr_return;
		}
	}
	if (fn_status_is_success(status)) {
		goto noerr_return;
	} else {
		logstat(status, "error while listing", map);
		/* Fall through to checkerr_return. */
	}

checkerr_return:
	if (!transient(status)) {
		goto noerr_return;
	}
err_return:
	free_mapent(mapents);
	mapents = NULL;
noerr_return:
	fn_bindinglist_destroy(bindings XFN1(status));
	return (mapents);
}


static mapent *
frontier_aux(mapent *mapents, const FN_ref_t *ref, char *map, size_t maplen,
    char *mntpnt, const char *name, char *opts, FN_status_t *status)
{
	addrtype_t	addrtype;
	bool_t		at_frontier;
	mapent		*me;
	size_t		maplen_save = maplen;
	char		*cname = map + FNPREFIXLEN + 1;	/* for error msgs */

	if (reftype(ref) >= NUM_REFTYPES) {
		/*
		 * We could instead install an indirect autofs mount point
		 * here.  That would allow, for example, a user to be bound
		 * beneath a file system.
		 */
		return (mapents);
	}

	/* "map" => "map/name" */
	if ((maplen = append_mapname(map, maplen, name)) == 0) {
		return (mapents);
	}
	if (trace > 1) {
		trace_prt(1, "  FNS traversal: %s/\n", cname);
	}

	/*
	 * If this is an address type that we know how to mount, then
	 * we have reached the frontier.
	 */
	at_frontier = (addr_from_ref(ref, cname, &addrtype, NULL, 0) == 0);
	/*
	 * For an ADDR_HOST address, treat a non-exported directory as
	 * if the address type were not known:  continue searching for
	 * exported subdirectories.
	 */
	if (at_frontier && (addrtype == ADDR_HOST)) {
		if (!exported(ref, cname, status)) {
			if (transient(status)) {
				free_mapent(mapents);
				return (NULL);
			} else {
				at_frontier = FALSE;
			}
		}
	}
	/*
	 * If we have reached the frontier, install a direct autofs
	 * mount point (which will trigger the actual mount if the
	 * user steps on it later).  Otherwise, continue traversing
	 * the namespace looking for known address types.
	 */
	if (at_frontier) {
		opts = (opts[0] != '\0')
		    ? concat(opts, ',', "direct")
		    : strdup("direct");
		me = new_mapent(noroot, strdup(mntpnt), strdup("autofs"), opts,
		    strdup(""), strdup(map));
		if (me != NULL) {
			/* Link new mapent into list (not at the head). */
			me->map_next = mapents->map_next;
			mapents->map_next = me;
		} else {
			free_mapent(mapents);
			mapents = NULL;
		}
	} else {
		mapents =
		    frontier(mapents, ref, map, maplen, mntpnt, opts, status);
	}
	map[maplen_save] = '\0';	/* "map/name" => "map" */
	return (mapents);
}


static bool_t
exported(const FN_ref_t *ref, const char *cname, FN_status_t *status)
{
	FN_ctx_t		*ctx;
	FN_attribute_t		*attr;

	ctx = fn_ctx_handle_from_ref(ref, XFN2(0) status);
	if (ctx == NULL) {
		logstat(status, "from_ref failed for", cname);
		return (FALSE);
	}
	attr = fn_attr_get(ctx, empty_cname, &attr_exported, XFN2(1) status);
	fn_ctx_handle_destroy(ctx);

	switch (fn_status_code(status)) {
	case FN_SUCCESS:
		fn_attribute_destroy(attr);
		break;
	case FN_E_NO_SUCH_ATTRIBUTE:
		break;
	default:
		logstat(status, "could not get attributes for", cname);
	}
	return (attr != NULL);
}


static int
addr_from_ref(const FN_ref_t *ref, const char *cname, addrtype_t *typep,
    char *data, size_t datasz)
{
	const FN_ref_addr_t	*addr;
	void			*iter_pos;

	addr = fn_ref_first(ref, &iter_pos);
	if (addr == NULL) {
		if (verbose) {
			syslog(LOG_ERR, "FNS ref with no address: %s", cname);
		}
		return (-1);
	}
	while (addr != NULL) {
		*typep = addrtype(addr);
		if (*typep < NUM_ADDRTYPES) {
			return ((data != NULL)
			    ? str_from_addr(cname, addr, data, datasz)
			    : 0);
		}
		addr = fn_ref_next(ref, &iter_pos);
	}
	return (-1);
}


static int
str_from_addr(const char *cname, const FN_ref_addr_t *addr, char str[],
    size_t strsz)
{
	XDR	xdr;
	int	res;

	xdrmem_create(&xdr, (caddr_t)fn_ref_addr_data(addr),
	    fn_ref_addr_length(addr), XDR_DECODE);
	if (!xdr_string(&xdr, &str, strsz)) {
		if (verbose) {
			syslog(LOG_ERR,
			    "Could not decode FNS address for %s", cname);
		}
		res = -1;
	} else {
		res = 0;
	}
	xdr_destroy(&xdr);
	return (res);
}

static size_t
append_mapname(char *map, size_t maplen, const char *name)
{
	size_t namelen = strlen(name);

	if (maplen + 1 + namelen >= MAPNAMESZ) {
		if (verbose) {
			syslog(LOG_ERR, "FNS name %s/%s too long",
			    map + FNPREFIXLEN + 1, name);
		}
		return (0);
	}
	sprintf(map + maplen, "/%s", name);
	return (maplen + 1 + namelen);
}


static char *
concat(const char *s1, char sep, const char *s2)
{
	char *s = malloc(strlen(s1) + 1 + strlen(s2) + 1);

	if (s != NULL) {
		sprintf(s, "%s%c%s", s1, sep, s2);
	}
	return (s);
}


static bool_t
safe_mapent(mapent *me)
{
	char	*opts;

	if (me->map_next != NULL) {
		/* Multiple mounts don't belong in XFN namespace. */
		return (NULL);
	}
	opts = me->map_mntopts;
	me->map_mntopts = safe_opts(opts);
	free(opts);
	return (me->map_mntopts != NULL);
}


static char *
safe_opts(const char *opts)
{
	char	*start;
	size_t	len;

	if (opts[0] == '\0') {
		return (strdup(MNTOPT_NOSUID));
	}

	/* A quick-and-dirty check to see if "nosuid" is already there. */
	start = strstr(opts, MNTOPT_NOSUID);
	len = sizeof (MNTOPT_NOSUID) - 1;	/* "-1" for trailing '\0' */
	if (start != NULL) {
		while (start > opts && isspace(*(start - 1))) {
			start--;
		}
		if ((start == opts || *(start - 1) == ',') &&
		    opts[len] == ',' || opts[len] == '\0') {
			return (strdup(opts));
		}
	}
	return (concat(opts, ',', MNTOPT_NOSUID));
}


static int
trim_line(mapline *ml)
{
	char	*end;	/* pointer to '\0' at end of linebuf */

	end = ml->linebuf + strcspn(ml->linebuf, "#");
	while ((end > ml->linebuf) && isspace(end[-1])) {
		end--;
	}
	if (end <= ml->linebuf) {
		return (-1);
	}
	*end = '\0';
	unquote(ml->linebuf, ml->lineqbuf);
	return (0);
}


static bool_t
opts_only(const mapline *ml)
{
	const char *s = ml->linebuf;
	const char *q = ml->lineqbuf;

	if (*s != '-') {
		return (FALSE);
	}
	for (; *s != '\0'; s++, q++) {
		if (isspace(*s) && (*q == ' ')) {
			return (FALSE);
		}
	}
	return (TRUE);
}


static mapent *
new_mapent(char *root, char *mntpnt, char *fstype, char *mntopts, char *host,
    char *dir)
{
	mapent		*me;
	struct mapfs	*mfs;
	char		*mounter = NULL;

	me = calloc(1, sizeof (*me));
	mfs = calloc(1, sizeof (*mfs));
	if (fstype != NULL) {
		mounter = strdup(fstype);
	}
	if ((mntpnt == NULL) || (fstype == NULL) || (mntopts == NULL) ||
	    (host == NULL) || (dir == NULL) || (me == NULL) || (mfs == NULL) ||
	    (mounter == NULL) || (root == NULL)) {
		log_mem_failure();
		free(me);
		free(mfs);
		free(mounter);
		free(root);
		free(mntpnt);
		free(fstype);
		free(mntopts);
		free(host);
		free(dir);
		return (NULL);
	}
	me->map_root	= (root != noroot) ? root : NULL;
	me->map_fstype	= fstype;
	me->map_mounter	= mounter;
	me->map_mntpnt	= mntpnt;
	me->map_mntopts	= mntopts;
	me->map_fsw	= NULL;
	me->map_fswq    = NULL;
	me->map_fs	= mfs;
	mfs->mfs_host	= host;
	mfs->mfs_dir	= dir;
	me->map_mntlevel = -1;
	me->map_modified = FALSE;
	me->map_faked = FALSE;
	me->map_err = 0;		/* MAPENT_NOERR */
	return (me);
}


#ifndef XFN1ENV

/*
 * User-relative bindings in the initial context, and the leading components
 * of their non-user-relative equivalents.  Leading components are listed in
 * the order in which they should be tried.  Each list is NULL-terminated
 * (the compiler generously does this for us).
 * For "myorgunit", for example, we first check if it is equivalent to
 * "thisorgunit".  If not, we translate it into "org/<something>".
 */
#define	MAX_LEADS 3

static struct {
	const char	*binding;
	const char	*leads[MAX_LEADS + 1];
} user_rel[] = {
	{"thisuser",	{"user", "thisorgunit", "org"}},
	{"myself",	{"user", "thisorgunit", "org"}},
	{"_myself",	{"_user", "_thisorgunit", "_orgunit"}},
	{"myorgunit",	{"thisorgunit", "org"}},
	{"_myorgunit",	{"_thisorgunit", "_orgunit"}},
	{"myens",	{"thisens"}},
	{"_myens",	{"_thisens"}}
};


static bool_t
is_user_relative(const char *cname)
{
	int	i;

	for (i = 0; i < sizeof (user_rel) / sizeof (user_rel[0]); i++) {
		if (strcmp(cname, user_rel[i].binding) == 0) {
			return (TRUE);
		}
	}
	return (FALSE);
}


static char *
equiv_name(FN_ctx_t *ctx, const char *cname, FN_status_t *status)
{
	FN_composite_name_t	*name;
	FN_string_t		*leading_name;
	FN_composite_name_t	*equiv;
	FN_string_t		*equiv_string;
	const char		*equiv_str;
	char			*equiv_str_dup;
	const char		**leads;
	unsigned int		stat;
	int			i;

	for (i = 0; i < sizeof (user_rel) / sizeof (user_rel[0]); i++) {
		if (strcmp(cname, user_rel[i].binding) == 0) {
			break;
		}
	}
	if ((name = new_cname(cname)) == NULL) {
		return (NULL);
	}
	leads = user_rel[i].leads;	/* array of leading names to try */
	do {
		leading_name = fn_string_from_str((unsigned char *)*leads);
		if (leading_name == NULL) {
			log_mem_failure();
			fn_composite_name_destroy(name);
			return (NULL);
		}
		equiv = prelim_fn_ctx_equivalent_name(ctx, name, leading_name,
		    status);
		fn_string_destroy(leading_name);
	} while (equiv == NULL && *++leads != NULL);

	fn_composite_name_destroy(name);

	if (equiv == NULL) {
		if (transient(status)) {
			logstat(status, "could not find equivalent of", cname);
		}
		return (NULL);
	}
	equiv_string = fn_string_from_composite_name(equiv, &stat);
	fn_composite_name_destroy(equiv);
	if (equiv_string == NULL) {
		log_mem_failure();
		return (NULL);
	}
	equiv_str = (const char *)fn_string_str(equiv_string, &stat);
	if (equiv_str == NULL ||
	    (equiv_str_dup = strdup(equiv_str)) == NULL) {
		log_mem_failure();
		fn_string_destroy(equiv_string);
		return (NULL);
	}
	fn_string_destroy(equiv_string);
	return (equiv_str_dup);
}

#endif	/* XFN1ENV */
