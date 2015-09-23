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
 *	autod_parse.c
 *
 *	Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 *      Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>
#include <pwd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/tiuser.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <thread.h>
#include <rpc/rpc.h>
#include <rpcsvc/mount.h>
#include <fcntl.h>
#include <limits.h>
#include "automount.h"

/*
 * This structure is used to determine the hierarchical
 * relationship between directories
 */
typedef struct _hiernode {
	char dirname[MAXFILENAMELEN+1];
	struct _hiernode *subdir;
	struct _hiernode *leveldir;
	struct mapent *mapent;
} hiernode;

void free_mapent(struct mapent *);

static int mapline_to_mapent(struct mapent **, struct mapline *, char *, char *,
				char *, char *, uint_t);
static int hierarchical_sort(struct mapent *, hiernode **, char *, char *);
static int push_options(hiernode *, char *, char *, int);
static int set_mapent_opts(struct mapent *, char *, char *, char *);
static void get_opts(char *, char *, char *, bool_t *);
static int fstype_opts(struct mapent *, char *, char *, char *);
static int modify_mapents(struct mapent **, char *, char *, char *, hiernode *,
			char *, uint_t, bool_t);
static int set_and_fake_mapent_mntlevel(hiernode *, char *, char *, char *,
				struct mapent **, uint_t, char *, bool_t);
static int mark_level1_root(hiernode *, char *);
static int mark_and_fake_level1_noroot(hiernode *, char *, char *, char *,
				    struct mapent **, uint_t i, char *);
static int convert_mapent_to_automount(struct mapent *, char *, char *);
static int automount_opts(char **, char *);
static int parse_fsinfo(char *, struct mapent *);
static int parse_nfs(char *, struct mapent *, char *, char *, char **, char **,
				int);
static int parse_special(struct mapent *, char *, char *, char **, char **,
				int);
static int get_dir_from_path(char *, char **, int);
static int alloc_hiernode(hiernode **, char *);
static void free_hiernode(hiernode *);
static void trace_mapents(char *, struct mapent *);
static void trace_hierarchy(hiernode *, int);
static struct mapent *do_mapent_hosts(char *, char *, uint_t);
static void freeex_ent(struct exportnode *);
static void freeex(struct exportnode *);
static void dump_mapent_err(struct mapent *, char *, char *);

#define	PARSE_OK	0
#define	PARSE_ERROR	-1
#define	MAX_FSLEN	32

/*
 * mapentry error type defininitions
 */
#define	MAPENT_NOERR	0
#define	MAPENT_UATFS	1

/*
 * parse_entry(char *key, char *mapname, char *mapopts, struct mapline *ml,
 *			char *subdir, uint_t isdirect, bool_t mount_access)
 * Parses the data in ml to build a mapentry list containing the information
 * for the mounts/lookups to be performed. Builds an intermediate mapentry list
 * by processing ml, hierarchically sorts (builds a tree of) the list according
 * to mountpoint. Then pushes options down the hierarchy, and fills in the mount
 * file system. Finally, modifies the intermediate list depending on how far
 * in the hierarchy the current request is (uses subdir). Deals with special
 * case of /net map parsing.
 * Returns a pointer to the head of the mapentry list.
 */
struct mapent *
parse_entry(char *key, char *mapname, char *mapopts, struct mapline *ml,
			char *subdir, uint_t isdirect, bool_t mount_access)
{
	char *p;
	char defaultopts[AUTOFS_MAXOPTSLEN];

	struct mapent *mapents = NULL;
	hiernode *rootnode = NULL;
	char *lp = ml->linebuf;

	if (trace > 1)
		trace_prt(1, "  mapline: %s\n", ml->linebuf);

	/*
	 * Assure the key is only one token long.
	 * This prevents options from sneaking in through the
	 * command line or corruption of /etc/mnttab.
	 */
	for (p = key; *p != '\0'; p++) {
		if (isspace(*p)) {
			syslog(LOG_ERR,
			"parse_entry: bad key in map %s: %s", mapname, key);
			return ((struct mapent *)NULL);
		}
	}

	/*
	 * select the appropriate parser, and build the mapentry list
	 */
	if (strcmp(lp, "-hosts") == 0) {
		/*
		 * the /net parser - uses do_mapent_hosts to build mapents.
		 * The mapopts are considered default for every entry, so we
		 * don't push options down hierarchies.
		 */
		mapents = do_mapent_hosts(mapopts, key, isdirect);
		if (mapents == NULL)		/* nothing to free */
			return (mapents);

		if (trace > 3)
			trace_mapents("do_mapent_hosts:(return)", mapents);

		if (hierarchical_sort(mapents, &rootnode, key, mapname)
		    != PARSE_OK)
			goto parse_error;
	} else {
		/*
		 * all other parsing
		 */
		if (mapline_to_mapent(&mapents, ml, key, mapname,
		    mapopts, defaultopts, isdirect) != PARSE_OK)
			goto parse_error;

		if (mapents == NULL)
			return (mapents);

		if (hierarchical_sort(mapents, &rootnode, key, mapname)
		    != PARSE_OK)
			goto parse_error;

		if (push_options(rootnode, defaultopts, mapopts,
		    MAPENT_NOERR) != PARSE_OK)
			goto parse_error;

		if (trace > 3) {
			trace_prt(1, "\n\tpush_options (return)\n");
			trace_prt(0, "\tdefault options=%s\n", defaultopts);
			trace_hierarchy(rootnode, 0);
		};

		if (parse_fsinfo(mapname, mapents) != PARSE_OK)
			goto parse_error;
	}

	/*
	 * Modify the mapentry list. We *must* do this only after
	 * the mapentry list is completely built (since we need to
	 * have parse_fsinfo called first).
	 */
	if (modify_mapents(&mapents, mapname, mapopts, subdir,
	    rootnode, key, isdirect, mount_access) != PARSE_OK)
		goto parse_error;

	/*
	 * XXX: its dangerous to use rootnode after modify mapents as
	 * it may be pointing to mapents that have been freed
	 */
	if (rootnode != NULL)
		free_hiernode(rootnode);

	return (mapents);

parse_error:
	syslog(LOG_ERR, "parse_entry: mapentry parse error: map=%s key=%s",
	    mapname, key);
	free_mapent(mapents);
	if (rootnode != NULL)
		free_hiernode(rootnode);
	return ((struct mapent *)NULL);
}


/*
 * mapline_to_mapent(struct mapent **mapents, struct mapline *ml,
 *		char *key, char *mapname, char *mapopts, char *defaultopts,
 *              uint_t isdirect)
 * Parses the mapline information in ml word by word to build an intermediate
 * mapentry list, which is passed back to the caller. The mapentries may have
 * holes (example no options), as they are completed only later. The logic is
 * awkward, but needed to provide the supported flexibility in the map entries.
 * (especially the first line). Note that the key is the full pathname of the
 * directory to be mounted in a direct map, and ml is the mapentry beyond key.
 * Returns PARSE_OK or an appropriate error value.
 */
static int
mapline_to_mapent(struct mapent **mapents, struct mapline *ml, char *key,
		char *mapname, char *mapopts, char *defaultopts,
		uint_t isdirect)
{
	struct mapent *me = NULL;
	struct mapent *mp;
	char w[MAXPATHLEN];
	char wq[MAXPATHLEN];
	char w1[MAXPATHLEN];
	int implied;

	char *lp = ml->linebuf;
	char *lq = ml->lineqbuf;

	/* do any macro expansions that are required to complete ml */
	if (macro_expand(key, lp, lq, LINESZ)) {
		syslog(LOG_ERR,
		"mapline_to_mapent: map %s: line too long (max %d chars)",
		    mapname, LINESZ - 1);
		return (PARSE_ERROR);
	}
	if (trace > 3 && (strcmp(ml->linebuf, lp) != 0))
		trace_prt(1,
		    "  mapline_to_mapent: (expanded) mapline (%s,%s)\n",
		    ml->linebuf, ml->lineqbuf);

	/* init the head of mapentry list to null */
	*mapents = NULL;

	/*
	 * Get the first word - its either a '-' if default options provided,
	 * a '/', if the mountroot is implicitly provided, or a mount filesystem
	 * if the mountroot is implicit. Note that if the first word begins with
	 * a '-' then the second must be read and it must be a mountpoint or a
	 * mount filesystem. Use mapopts if no default opts are provided.
	 */
	if (getword(w, wq, &lp, &lq, ' ', sizeof (w)) == -1)
		return (PARSE_ERROR);
	if (*w == '-') {
		strcpy(defaultopts, w);
		if (getword(w, wq, &lp, &lq, ' ', sizeof (w)) == -1)
			return (PARSE_ERROR);
	} else
		strcpy(defaultopts, mapopts);

	/*
	 * implied is true if there is no '/'
	 * We need the same code path if we have an smbfs mount.
	 */
	implied = (*w != '/') || (strstr(defaultopts, "fstype=smbfs") != NULL);
	while (*w == '/' || implied) {
		mp = me;
		if ((me = (struct mapent *)malloc(sizeof (*me))) == NULL)
			goto alloc_failed;
		(void) memset((char *)me, 0, sizeof (*me));
		if (*mapents == NULL)	/* special case of head */
			*mapents = me;
		else
			mp->map_next = me;

		/*
		 * direct maps get an empty string as root - to be filled
		 * by the entire path later. Indirect maps get /key as the
		 * map root. Note that xfn maps don't care about the root
		 * - they override it in getmapent_fn().
		 */
		if (isdirect) {
			*w1 = '\0';
		} else {
			strcpy(w1, "/");
			strcat(w1, key);
		}
		if ((me->map_root = strdup(w1)) == NULL)
			goto alloc_failed;

		/* mntpnt is empty for the mount root */
		if (strcmp(w, "/") == 0 || implied)
			me->map_mntpnt = strdup("");
		else
			me->map_mntpnt = strdup(w);
		if (me->map_mntpnt == NULL)
			goto alloc_failed;

		/*
		 * If implied, the word must be a mount filesystem,
		 * and its already read in; also turn off implied - its
		 * not applicable except for the mount root. Else,
		 * read another (or two) words depending on if there's
		 * an option.
		 */
		if (implied)   /* must be a mount filesystem */
			implied = 0;
		else {
			if (getword(w, wq, &lp, &lq, ' ', sizeof (w)) == -1)
				return (PARSE_ERROR);
			if (w[0] == '-') {
				/* mount options */
				if ((me->map_mntopts = strdup(w)) == NULL)
					goto alloc_failed;
				if (getword(w, wq, &lp, &lq, ' ',
				    sizeof (w)) == -1)
					return (PARSE_ERROR);
			}
		}

		/*
		 * must be a mount filesystem or a set of filesystems at
		 * this point.
		 */
		if (w[0] == '\0' || w[0] == '-') {
			syslog(LOG_ERR,
			"mapline_to_mapent: bad location=%s map=%s key=%s",
			    w, mapname, key);
			return (PARSE_ERROR);
		}

		/*
		 * map_fsw and map_fswq hold information which will be
		 * used to determine filesystem information at a later
		 * point. This is required since we can only find out
		 * about the mount file system after the directories
		 * are hierarchically sorted and options have been pushed
		 * down the hierarchies.
		 */
		if (((me->map_fsw = strdup(w)) == NULL) ||
		    ((me->map_fswq = strdup(wq)) == NULL))
			goto alloc_failed;

		/*
		 * the next word, if any, is either another mount point or a
		 * mount filesystem if more than one server is listed.
		 */
		if (getword(w, wq, &lp, &lq, ' ', sizeof (w)) == -1)
			return (PARSE_ERROR);
		while (*w && *w != '/') {	/* more than 1 server listed */
			int len;
			char *fsw, *fswq;
			len = strlen(me->map_fsw) + strlen(w) + 4;
			if ((fsw = (char *)malloc(len)) == NULL)
				goto alloc_failed;
			sprintf(fsw, "%s   %s", me->map_fsw, w);
			free(me->map_fsw);
			me->map_fsw = fsw;
			len = strlen(me->map_fswq) + strlen(wq) + 4;
			if ((fswq = (char *)malloc(len)) == NULL)
				goto alloc_failed;
			sprintf(fswq, "%s   %s", me->map_fswq, wq);
			free(me->map_fswq);
			me->map_fswq = fswq;
			if (getword(w, wq, &lp, &lq, ' ', sizeof (w)) == -1)
				return (PARSE_ERROR);
		}

		/* initialize flags */
		me->map_mntlevel = -1;
		me->map_modified = FALSE;
		me->map_faked = FALSE;
		me->map_err = MAPENT_NOERR;

		me->map_next = NULL;
	}

	if (*mapents == NULL || w[0] != '\0') {	/* sanity check */
		if (verbose) {
			if (*mapents == NULL)
				syslog(LOG_ERR,
				"mapline_to_mapent: parsed with null mapents");
			else
				syslog(LOG_ERR,
				"mapline_to_mapent: parsed nononempty w=%s", w);
		}
		return (PARSE_ERROR);
	}

	if (trace > 3)
		trace_mapents("mapline_to_mapent:", *mapents);

	return (PARSE_OK);

alloc_failed:
	syslog(LOG_ERR, "mapline_to_mapent: Memory allocation failed");
	return (ENOMEM);
}

/*
 * hierarchical_sort(struct mapent *mapents, hiernode **rootnode, char *key
 *                   char *mapname)
 * sorts the mntpnts in each mapent to build a hierarchy of nodes, with
 * with the rootnode being the mount root. The hierarchy is setup as
 * levels, and subdirs below each level. Provides a link from node to
 * the relevant mapentry.
 * Returns PARSE_OK or appropriate error value
 */
static int
hierarchical_sort(struct mapent *mapents, hiernode **rootnode, char *key,
	char *mapname)
{
	hiernode *prevnode, *currnode, *newnode;
	char *path;
	char dirname[MAXFILENAMELEN];

	int rc = PARSE_OK;
	struct mapent *me = mapents;

	/* allocate the rootnode with a default path of "" */
	*rootnode = NULL;
	if ((rc = alloc_hiernode(rootnode, "")) != PARSE_OK)
		return (rc);

	/*
	 * walk through mapents - for each mapent, locate the position
	 * within the hierarchy by walking across leveldirs, and
	 * subdirs of matched leveldirs. Starts one level below
	 * the root (assumes an implicit match with rootnode).
	 * XXX - this could probably be done more cleanly using recursion.
	 */
	while (me != NULL) {

		path = me->map_mntpnt;

		if ((rc = get_dir_from_path(dirname, &path,
		    sizeof (dirname))) != PARSE_OK)
			return (rc);

		prevnode = *rootnode;
		currnode = (*rootnode)->subdir;

		while (dirname[0] != '\0') {
			if (currnode != NULL) {
				if (strcmp(currnode->dirname, dirname) == 0) {
					/*
					 * match found - mntpnt is a child of
					 * this node
					 */
					prevnode = currnode;
					currnode = currnode->subdir;
				} else {
					prevnode = currnode;
					currnode = currnode->leveldir;

					if (currnode == NULL) {
						/*
						 * No more leveldirs to match.
						 * Add a new one
						 */
						if ((rc = alloc_hiernode
						    (&newnode, dirname))
						    != PARSE_OK)
							return (rc);
						prevnode->leveldir = newnode;
						prevnode = newnode;
						currnode = newnode->subdir;
					} else {
						/* try this leveldir */
						continue;
					}
				}
			} else {
				/* no more subdirs to match. Add a new one */
				if ((rc = alloc_hiernode(&newnode,
				    dirname)) != PARSE_OK)
					return (rc);
				prevnode->subdir = newnode;
				prevnode = newnode;
				currnode = newnode->subdir;
			}
			if ((rc = get_dir_from_path(dirname, &path,
			    sizeof (dirname))) != PARSE_OK)
				return (rc);
		}

		if (prevnode->mapent != NULL) {
			/* duplicate mntpoint found */
			syslog(LOG_ERR,
			"hierarchical_sort: duplicate mntpnt map=%s key=%s",
			    mapname, key);
			return (PARSE_ERROR);
		}

		/* provide a pointer from node to mapent */
		prevnode->mapent = me;
		me = me->map_next;
	}

	if (trace > 3) {
		trace_prt(1, "\n\thierarchical_sort:\n");
		trace_hierarchy(*rootnode, 0);	/* 0 is rootnode's level */
	}

	return (rc);
}

/*
 * push_options(hiernode *node, char *opts, char *mapopts, int err)
 * Pushes the options down a hierarchical structure. Works recursively from the
 * root, which is passed in on the first call. Uses a replacement policy.
 * If a node points to a mapentry, and it has an option, then thats the option
 * for that mapentry. Else, the node's mapent inherits the option from the
 * default (which may be the global option for the entry or mapopts).
 * err is useful in flagging entries with errors in pushing options.
 * returns PARSE_OK or appropriate error value.
 */
static int
push_options(hiernode *node, char *defaultopts, char *mapopts, int err)
{
	int rc = PARSE_OK;
	struct mapent *me = NULL;

	/* ensure that all the dirs at a level are passed the default options */
	while (node != NULL) {
		me = node->mapent;
		if (me != NULL) {	/* not all nodes point to a mapentry */
			me->map_err = err;
			if ((rc = set_mapent_opts(me, me->map_mntopts,
			    defaultopts, mapopts)) != PARSE_OK)
				return (rc);
		}

		/* push the options to subdirs */
		if (node->subdir != NULL) {
			if (node->mapent && strcmp(node->mapent->map_fstype,
			    MNTTYPE_AUTOFS) == 0)
				err = MAPENT_UATFS;
			if ((rc = push_options(node->subdir, defaultopts,
			    mapopts, err)) != PARSE_OK)
				return (rc);
		}
		node = node->leveldir;
	}
	return (rc);
}

#define	FSTYPE "fstype"
#define	FSTYPE_EQ "fstype="
#define	NO_OPTS ""

/*
 * set_mapent_opts(struct mapent *me, char *opts, char *defaultopts,
 *			char *mapopts)
 * sets the mapentry's options, fstype and mounter fields by separating
 * out the fstype part from the opts. Use default options if opts is NULL.
 * Note taht defaultopts may be the same as mapopts.
 * Returns PARSE_OK or appropriate error value.
 */
static int
set_mapent_opts(struct mapent *me, char *opts, char *defaultopts,
		char *mapopts)
{
	char entryopts[AUTOFS_MAXOPTSLEN];
	char fstype[MAX_FSLEN], mounter[MAX_FSLEN];
	int rc = PARSE_OK;
	bool_t fstype_opt = FALSE;

	strcpy(fstype, MNTTYPE_NFS);		/* default */

	/* set options to default options, if none exist for this entry */
	if (opts == NULL) {
		opts = defaultopts;
		if (defaultopts == NULL) { /* NULL opts for entry */
			strcpy(mounter, fstype);
			goto done;
		}
	}
	if (*opts == '-')
		opts++;

	/* separate opts into fstype and (other) entrypopts */
	get_opts(opts,	entryopts, fstype, &fstype_opt);

	/* replace any existing opts */
	if (me->map_mntopts != NULL)
		free(me->map_mntopts);
	if ((me->map_mntopts = strdup(entryopts)) == NULL)
		return (ENOMEM);
	strcpy(mounter,	fstype);

	/*
	 * child options are exactly fstype = somefs, we need to do some
	 * more option pushing work.
	 */
	if (fstype_opt == TRUE &&
	    (strcmp(me->map_mntopts, NO_OPTS) == 0)) {
		free(me->map_mntopts);
		if ((rc = fstype_opts(me, opts, defaultopts,
		    mapopts)) != PARSE_OK)
			return (rc);
	}

done:
	if (((me->map_fstype = strdup(fstype)) == NULL) ||
	    ((me->map_mounter = strdup(mounter)) == NULL)) {
		if (me->map_fstype != NULL)
			free(me->map_fstype);
		syslog(LOG_ERR, "set_mapent_opts: No memory");
		return (ENOMEM);
	}

	return (rc);
}

/*
 * Check the option string for an "fstype"
 * option.  If found, return the fstype
 * and the option string with the fstype
 * option removed, e.g.
 *
 *  input:  "fstype=nfs,ro,nosuid"
 *  opts:   "ro,nosuid"
 *  fstype: "nfs"
 *
 * Also indicates if the fstype option was present
 * by setting a flag, if the pointer to the flag
 * is not NULL.
 */
static void
get_opts(input, opts, fstype, fstype_opt)
	char *input;
	char *opts; 	/* output */
	char *fstype;   /* output */
	bool_t *fstype_opt;
{
	char *p, *pb;
	char buf[MAXOPTSLEN];
	char *placeholder;

	*opts = '\0';
	(void) strcpy(buf, input);
	pb = buf;
	while (p = (char *)strtok_r(pb, ",", &placeholder)) {
		pb = NULL;
		if (strncmp(p, FSTYPE_EQ, 7) == 0) {
			if (fstype_opt != NULL)
				*fstype_opt = TRUE;
			(void) strcpy(fstype, p + 7);
		} else {
			if (*opts)
				(void) strcat(opts, ",");
			(void) strcat(opts, p);
		}
	}
}

/*
 * fstype_opts(struct mapent *me, char *opts, char *defaultopts,
 *				char *mapopts)
 * We need to push global options to the child entry if it is exactly
 * fstype=somefs.
 */
static int
fstype_opts(struct mapent *me, char *opts, char *defaultopts,
				char *mapopts)
{
	char pushentryopts[AUTOFS_MAXOPTSLEN];
	char pushfstype[MAX_FSLEN];

	if (defaultopts && *defaultopts == '-')
		defaultopts++;

	/*
	 * the options to push are the global defaults for the entry,
	 * if they exist, or mapopts, if the global defaults for the
	 * entry does not exist.
	 */
	if (strcmp(defaultopts, opts) == 0) {
		if (*mapopts == '-')
			mapopts++;
		get_opts(mapopts, pushentryopts, pushfstype, NULL);
	} else {
		get_opts(defaultopts, pushentryopts, pushfstype, NULL);
	}

	me->map_mntopts = strdup(pushentryopts);

	if (!me->map_mntopts) {
		syslog(LOG_ERR, "fstype_opts: No memory");
		return (ENOMEM);
	}

	return (PARSE_OK);
}

/*
 * modify_mapents(struct mapent **mapents, char *mapname,
 *			char *mapopts, char *subdir, hiernode *rootnode,
 * 			char *key, uint_t isdirect, bool_t mount_access)
 * modifies the intermediate mapentry list into the final one, and passes
 * back a pointer to it. The final list may contain faked mapentries for
 * hiernodes that do not point to a mapentry, or converted mapentries, if
 * hiernodes that point to a mapentry need to be converted from nfs to autofs.
 * mounts. Entries that are not directly 1 level below the subdir are removed.
 * Returns PARSE_OK or PARSE_ERROR
 */
static int
modify_mapents(struct mapent **mapents, char *mapname,
			char *mapopts, char *subdir, hiernode *rootnode,
			char *key, uint_t isdirect, bool_t mount_access)
{
	struct mapent *mp = NULL;
	char w[MAXPATHLEN];

	struct mapent *me;
	int rc = PARSE_OK;
	struct mapent *faked_mapents = NULL;

	/*
	 * correct the mapentry mntlevel from default -1 to level depending on
	 * position in hierarchy, and build any faked mapentries, if required
	 * at one level below the rootnode given by subdir.
	 */
	if ((rc = set_and_fake_mapent_mntlevel(rootnode, subdir, key, mapname,
	    &faked_mapents, isdirect, mapopts, mount_access)) != PARSE_OK)
		return (rc);

	/*
	 * attaches faked mapents to real mapents list. Assumes mapents
	 * is not NULL.
	 */
	me = *mapents;
	while (me->map_next != NULL)
		me = me->map_next;
	me->map_next = faked_mapents;

	/*
	 * get rid of nodes marked at level -1
	 */
	me = *mapents;
	while (me != NULL) {
		if ((me->map_mntlevel ==  -1) || (me->map_err) ||
		    (mount_access == FALSE && me->map_mntlevel == 0)) {
			/*
			 * syslog any errors and free entry
			 */
			if (me->map_err)
				dump_mapent_err(me, key, mapname);

			if (me ==  (*mapents)) {
				/* special case when head has to be freed */
				*mapents = me->map_next;
				if ((*mapents) ==  NULL) {
					/* something wierd happened */
					if (verbose)
						syslog(LOG_ERR,
						"modify_mapents: level error");
					return (PARSE_ERROR);
				}

				/* separate out the node */
				me->map_next = NULL;
				free_mapent(me);
				me = *mapents;
			} else {
				mp->map_next = me->map_next;
				me->map_next = NULL;
				free_mapent(me);
				me = mp->map_next;
			}
			continue;
		}

		/*
		 * convert level 1 mapents that are not already autonodes
		 * to autonodes
		 */
		if (me->map_mntlevel == 1 &&
		    (strcmp(me->map_fstype, MNTTYPE_AUTOFS) != 0) &&
		    (me->map_faked != TRUE)) {
			if ((rc = convert_mapent_to_automount(me, mapname,
			    mapopts)) != PARSE_OK)
				return (rc);
		}
		strcpy(w, (me->map_mntpnt+strlen(subdir)));
		strcpy(me->map_mntpnt, w);
		mp = me;
		me = me->map_next;
	}

	if (trace > 3)
		trace_mapents("modify_mapents:", *mapents);

	return (PARSE_OK);
}

/*
 * set_and_fake_mapent_mntlevel(hiernode *rootnode, char *subdir, char *key,
 *			char *mapname, struct mapent **faked_mapents,
 *			uint_t isdirect, char *mapopts, bool_t mount_access)
 * sets the mapentry mount levels (depths) with respect to the subdir.
 * Assigns a value of 0 to the new root. Finds the level1 directories by
 * calling mark_*_level1_*(). Also cleans off extra /'s in level0 and
 * level1 map_mntpnts. Note that one level below the new root is an existing
 * mapentry if there's a mapentry (nfs mount) corresponding to the root,
 * and the direct subdir set for the root, if there's no mapentry corresponding
 * to the root (we install autodirs). Returns PARSE_OK or error value.
 */
static int
set_and_fake_mapent_mntlevel(hiernode *rootnode, char *subdir, char *key,
		char *mapname, struct mapent **faked_mapents,
		uint_t isdirect, char *mapopts, bool_t mount_access)
{
	char dirname[MAXFILENAMELEN];
	char traversed_path[MAXPATHLEN]; /* used in building fake mapentries */

	char *subdir_child = subdir;
	hiernode *prevnode = rootnode;
	hiernode *currnode = rootnode->subdir;
	int rc = PARSE_OK;
	traversed_path[0] = '\0';

	/*
	 * find and mark the root by tracing down subdir. Use traversed_path
	 * to keep track of how far we go, while guaranteeing that it
	 * contains no '/' at the end. Took some mucking to get that right.
	 */
	if ((rc = get_dir_from_path(dirname, &subdir_child, sizeof (dirname)))
	    != PARSE_OK)
		return (rc);

	if (dirname[0] != '\0')
		sprintf(traversed_path, "%s/%s", traversed_path, dirname);

	prevnode = rootnode;
	currnode = rootnode->subdir;
	while (dirname[0] != '\0' && currnode != NULL) {
		if (strcmp(currnode->dirname, dirname) == 0) {

			/* subdir is a child of currnode */
			prevnode = currnode;
			currnode = currnode->subdir;

			if ((rc = get_dir_from_path(dirname, &subdir_child,
			    sizeof (dirname))) != PARSE_OK)
				return (rc);
			if (dirname[0] != '\0')
				sprintf(traversed_path, "%s/%s",
				    traversed_path, dirname);

		} else {
			/* try next leveldir */
			prevnode = currnode;
			currnode = currnode->leveldir;
		}
	}

	if (dirname[0] != '\0') {
		if (verbose)
			syslog(LOG_ERR,
			"set_and_fake_mapent_mntlevel: subdir=%s error: map=%s",
			    subdir, mapname);
		return (PARSE_ERROR);
	}

	/*
	 * see if level of root really points to a mapent and if
	 * have access to that filessystem - call appropriate
	 * routine to mark level 1 nodes, and build faked entries
	 */
	if (prevnode->mapent != NULL && mount_access == TRUE) {
		if (trace > 3)
			trace_prt(1, "  node mountpoint %s\t travpath=%s\n",
			    prevnode->mapent->map_mntpnt, traversed_path);

		/*
		 * Copy traversed path map_mntpnt to get rid of any extra
		 * '/' the map entry may contain.
		 */
		if (strlen(prevnode->mapent->map_mntpnt) <
		    strlen(traversed_path)) { /* sanity check */
			if (verbose)
				syslog(LOG_ERR,
				"set_and_fake_mapent_mntlevel: path=%s error",
				    traversed_path);
			return (PARSE_ERROR);
		}
		if (strcmp(prevnode->mapent->map_mntpnt, traversed_path) != 0)
			strcpy(prevnode->mapent->map_mntpnt, traversed_path);

		prevnode->mapent->map_mntlevel = 0; /* root level is 0 */
		if (currnode != NULL) {
			if ((rc = mark_level1_root(currnode,
			    traversed_path)) != PARSE_OK)
				return (rc);
		}
	} else if (currnode != NULL) {
		if (trace > 3)
			trace_prt(1, "  No rootnode, travpath=%s\n",
			    traversed_path);
		if ((rc = mark_and_fake_level1_noroot(currnode,
		    traversed_path, key, mapname, faked_mapents, isdirect,
		    mapopts)) != PARSE_OK)
			return (rc);
	}

	if (trace > 3) {
		trace_prt(1, "\n\tset_and_fake_mapent_mntlevel\n");
		trace_hierarchy(rootnode, 0);
	}

	return (rc);
}


/*
 * mark_level1_root(hiernode *node, char *traversed_path)
 * marks nodes upto one level below the rootnode given by subdir
 * recursively. Called if rootnode points to a mapent.
 * In this routine, a level 1 node is considered to be the 1st existing
 * mapentry below the root node, so there's no faking involved.
 * Returns PARSE_OK or error value
 */
static int
mark_level1_root(hiernode *node, char *traversed_path)
{
	/* ensure we touch all leveldirs */
	while (node) {
		/*
		 * mark node level as 1, if one exists - else walk down
		 * subdirs until we find one.
		 */
		if (node->mapent ==  NULL) {
			char w[MAXPATHLEN];

			if (node->subdir != NULL) {
				sprintf(w, "%s/%s", traversed_path,
				    node->dirname);
				if (mark_level1_root(node->subdir, w)
				    == PARSE_ERROR)
					return (PARSE_ERROR);
			} else {
				if (verbose) {
					syslog(LOG_ERR,
					"mark_level1_root: hierarchy error");
				}
				return (PARSE_ERROR);
			}
		} else {
			char w[MAXPATHLEN];

			sprintf(w, "%s/%s", traversed_path, node->dirname);
			if (trace > 3)
				trace_prt(1, "  node mntpnt %s\t travpath %s\n",
				    node->mapent->map_mntpnt, w);

			/* replace mntpnt with travpath to clean extra '/' */
			if (strlen(node->mapent->map_mntpnt) < strlen(w)) {
				if (verbose) {
					syslog(LOG_ERR,
					"mark_level1_root: path=%s error",
					    traversed_path);
				}
				return (PARSE_ERROR);
			}
			if (strcmp(node->mapent->map_mntpnt, w) != 0)
				strcpy(node->mapent->map_mntpnt, w);
			node->mapent->map_mntlevel = 1;
		}
		node = node->leveldir;
	}
	return (PARSE_OK);
}

/*
 * mark_and_fake_level1_noroot(hiernode *node, char *traversed_path,
 * 			char *key,char *mapname, struct mapent **faked_mapents,
 *			uint_t isdirect, char *mapopts)
 * Called if the root of the hierarchy does not point to a mapent. marks nodes
 * upto one physical level below the rootnode given by subdir. checks if
 * there's a real mapentry. If not, it builds a faked one (autonode) at that
 * point. The faked autonode is direct, with the map being the same as the
 * original one from which the call originated. Options are same as that of
 * the map and assigned in automount_opts(). Returns PARSE_OK or error value.
 */
static int
mark_and_fake_level1_noroot(hiernode *node, char *traversed_path,
			char *key, char *mapname, struct mapent **faked_mapents,
			uint_t isdirect, char *mapopts)
{
	struct mapent *me;
	int rc = 0;
	char faked_map_mntpnt[MAXPATHLEN];
	char w1[MAXPATHLEN];
	char w[MAXPATHLEN];

	while (node != NULL) {
		if (node->mapent != NULL) {
			/*
			 * existing mapentry at level 1 - copy travpath to
			 * get rid of extra '/' in mntpnt
			 */
			sprintf(w, "%s/%s", traversed_path, node->dirname);
			if (trace > 3)
				trace_prt(1, "  node mntpnt=%s\t travpath=%s\n",
				    node->mapent->map_mntpnt, w);
			if (strlen(node->mapent->map_mntpnt) < strlen(w)) {
				/* sanity check */
				if (verbose)
					syslog(LOG_ERR,
					"mark_fake_level1_noroot:path=%s error",
					    traversed_path);
				return (PARSE_ERROR);
			}
			if (strcmp(node->mapent->map_mntpnt, w) != 0)
				strcpy(node->mapent->map_mntpnt, w);
			node->mapent->map_mntlevel = 1;
		} else {
			/*
			 * build the faked autonode
			 */
			if ((me = (struct mapent *)malloc(sizeof (*me)))
			    == NULL) {
				syslog(LOG_ERR,
				"mark_and_fake_level1_noroot: out of memory");
				return (ENOMEM);
			}
			(void) memset((char *)me, 0, sizeof (*me));

			if ((me->map_fs = (struct mapfs *)
			    malloc(sizeof (struct mapfs))) == NULL)
				return (ENOMEM);
			(void) memset(me->map_fs, 0, sizeof (struct mapfs));

			if (isdirect) {
				*w1 = '\0';
			} else {
				strcpy(w1, "/");
				strcat(w1, key);
			}
			me->map_root = strdup(w1);

			sprintf(faked_map_mntpnt, "%s/%s", traversed_path,
			    node->dirname);
			me->map_mntpnt = strdup(faked_map_mntpnt);
			me->map_fstype = strdup(MNTTYPE_AUTOFS);
			me->map_mounter = strdup(MNTTYPE_AUTOFS);

			/* set options */
			if ((rc = automount_opts(&me->map_mntopts, mapopts))
			    != PARSE_OK)
				return (rc);
			me->map_fs->mfs_dir = strdup(mapname);
			me->map_mntlevel = 1;
			me->map_modified = FALSE;
			me->map_faked = TRUE;   /* mark as faked */
			if (me->map_root == NULL ||
			    me->map_mntpnt == NULL ||
			    me->map_fstype == NULL ||
			    me->map_mounter == NULL ||
			    me->map_mntopts == NULL ||
			    me->map_fs->mfs_dir == NULL) {
				syslog(LOG_ERR,
				"mark_and_fake_level1_noroot: out of memory");
				free_mapent(*faked_mapents);
				return (ENOMEM);
			}

			if (*faked_mapents == NULL)
				*faked_mapents = me;
			else {			/* attach to the head */
				me->map_next = *faked_mapents;
				*faked_mapents = me;
			}
			node->mapent = me;
		}
		node = node->leveldir;
	}
	return (rc);
}

/*
 * convert_mapent_to_automount(struct mapent *me, char *mapname,
 *				char *mapopts)
 * change the mapentry me to an automount - free fields first and NULL them
 * to avoid freeing again, while freeing the mapentry at a later stage.
 * Could have avoided freeing entries here as we don't really look at them.
 * Give the converted mapent entry the options that came with the map using
 * automount_opts(). Returns PARSE_OK or appropriate error value.
 */
static int
convert_mapent_to_automount(struct mapent *me, char *mapname,
				char *mapopts)
{
	struct mapfs *mfs = me->map_fs;		/* assumes it exists */
	int rc = PARSE_OK;

	/* free relevant entries */
	if (mfs->mfs_host) {
		free(mfs->mfs_host);
		mfs->mfs_host = NULL;
	}
	while (me->map_fs->mfs_next != NULL) {
		mfs = me->map_fs->mfs_next;
		if (mfs->mfs_host)
			free(mfs->mfs_host);
		if (mfs->mfs_dir)
			free(mfs->mfs_dir);
		me->map_fs->mfs_next = mfs->mfs_next;	/* nulls eventually */
		free((void*)mfs);
	}

	/* replace relevant entries */
	if (me->map_fstype)
		free(me->map_fstype);
	if ((me->map_fstype = strdup(MNTTYPE_AUTOFS)) == NULL)
		goto alloc_failed;

	if (me->map_mounter)
		free(me->map_mounter);
	if ((me->map_mounter = strdup(me->map_fstype)) == NULL)
		goto alloc_failed;

	if (me->map_fs->mfs_dir)
		free(me->map_fs->mfs_dir);
	if ((me->map_fs->mfs_dir = strdup(mapname)) == NULL)
		goto alloc_failed;

	/* set options */
	if (me->map_mntopts)
		free(me->map_mntopts);
	if ((rc = automount_opts(&me->map_mntopts, mapopts)) != PARSE_OK)
		return (rc);

	/* mucked with this entry, set the map_modified field to TRUE */
	me->map_modified = TRUE;

	return (rc);

alloc_failed:
	syslog(LOG_ERR,
	    "convert_mapent_to_automount: Memory allocation failed");
	return (ENOMEM);
}

/*
 * automount_opts(char **map_mntopts, char *mapopts)
 * modifies automount opts - gets rid of all "indirect" and "direct" strings
 * if they exist, and then adds a direct string to force a direct automount.
 * Rest of the mapopts stay intact. Returns PARSE_OK or appropriate error.
 */
static int
automount_opts(char **map_mntopts, char *mapopts)
{
	char *opts;
	char *opt;
	int len;
	char *placeholder;
	char buf[AUTOFS_MAXOPTSLEN];

	char *addopt = "direct";

	len = strlen(mapopts)+ strlen(addopt)+2;	/* +2 for ",", '\0' */
	if (len > AUTOFS_MAXOPTSLEN) {
		syslog(LOG_ERR,
		"option string %s too long (max=%d)", mapopts,
		    AUTOFS_MAXOPTSLEN-8);
		return (PARSE_ERROR);
	}

	if (((*map_mntopts) = ((char *)malloc(len))) == NULL) {
		syslog(LOG_ERR,	"automount_opts: Memory allocation failed");
		return (ENOMEM);
	}
	memset(*map_mntopts, 0, len);

	strcpy(buf, mapopts);
	opts = buf;
	while ((opt = strtok_r(opts, ",", &placeholder)) != NULL) {
		opts = NULL;

		/* remove trailing and leading spaces */
		while (isspace(*opt))
			opt++;
		len = strlen(opt)-1;
		while (isspace(opt[len]))
			opt[len--] = '\0';

		/*
		 * if direct or indirect found, get rid of it, else put it
		 * back
		 */
		if ((strcmp(opt, "indirect") == 0) ||
		    (strcmp(opt, "direct") == 0))
			continue;
		if (*map_mntopts[0] != '\0')
			strcat(*map_mntopts, ",");
		strcat(*map_mntopts, opt);
	}

	/* add the direct string at the end */
	if (*map_mntopts[0] != '\0')
		strcat(*map_mntopts,	",");
	strcat(*map_mntopts, addopt);

	return (PARSE_OK);
}

/*
 * parse_fsinfo(char *mapname, struct mapent *mapents)
 * parses the filesystem information stored in me->map_fsw and me->map_fswq
 * and calls appropriate filesystem parser.
 * Returns PARSE_OK or an appropriate error value.
 */
static int
parse_fsinfo(char *mapname, struct mapent *mapents)
{
	struct mapent *me = mapents;
	char *bufp;
	char *bufq;
	int wordsz = MAXPATHLEN;
	int err = 0;

	while (me != NULL) {
		bufp = "";
		bufq = "";
		if (strcmp(me->map_fstype, MNTTYPE_NFS) == 0) {
			err = parse_nfs(mapname, me, me->map_fsw,
			    me->map_fswq, &bufp, &bufq, wordsz);
		} else {
			err = parse_special(me, me->map_fsw, me->map_fswq,
			    &bufp, &bufq, wordsz);
		}

		if (err != PARSE_OK || *me->map_fsw != '\0' ||
		    *me->map_fswq != '\0') {
			/* sanity check */
			if (verbose)
				syslog(LOG_ERR,
				"parse_fsinfo: mount location error %s",
				    me->map_fsw);
			return (PARSE_ERROR);
		}

		me = me->map_next;
	}

	if (trace > 3) {
		trace_mapents("parse_fsinfo:", mapents);
	}

	return (PARSE_OK);
}

/*
 * This function parses the map entry for a nfs type file system
 * The input is the string lp (and lq) which can be one of the
 * following forms:
 * a) host[(penalty)][,host[(penalty)]]... :/directory
 * b) host[(penalty)]:/directory[ host[(penalty)]:/directory]...
 * This routine constructs a mapfs link-list for each of
 * the hosts and the corresponding file system. The list
 * is then attatched to the mapent struct passed in.
 */
int
parse_nfs(mapname, me, fsw, fswq, lp, lq, wsize)
	struct mapent *me;
	char *mapname, *fsw, *fswq, **lp, **lq;
	int wsize;
{
	struct mapfs *mfs, **mfsp;
	char *wlp, *wlq;
	char *hl, hostlist[1024], *hlq, hostlistq[1024];
	char hostname_and_penalty[MXHOSTNAMELEN+5];
	char *hn, *hnq, hostname[MXHOSTNAMELEN+1];
	char dirname[MAXPATHLEN+1], subdir[MAXPATHLEN+1];
	char qbuff[MAXPATHLEN+1], qbuff1[MAXPATHLEN+1];
	char pbuff[10], pbuffq[10];
	int penalty;
	char w[MAXPATHLEN];
	char wq[MAXPATHLEN];
	int host_cnt;

	mfsp = &me->map_fs;
	*mfsp = NULL;

	/*
	 * there may be more than one entry in the map list. Get the
	 * first one. Use temps to handle the word information and
	 * copy back into fsw and fswq fields when done.
	 */
	*lp = fsw;
	*lq = fswq;
	if (getword(w, wq, lp, lq, ' ', wsize) == -1)
		return (PARSE_ERROR);
	while (*w && *w != '/') {
		bool_t maybe_url;

		maybe_url = TRUE;

		wlp = w; wlq = wq;
		if (getword(hostlist, hostlistq, &wlp, &wlq, ':',
			    sizeof (hostlist)) == -1)
			return (PARSE_ERROR);
		if (!*hostlist)
			goto bad_entry;

		if (strcmp(hostlist, "nfs") != 0)
			maybe_url = FALSE;

		if (getword(dirname, qbuff, &wlp, &wlq, ':',
					sizeof (dirname)) == -1)
			return (PARSE_ERROR);
		if (*dirname == '\0')
			goto bad_entry;

		if (maybe_url == TRUE && strncmp(dirname, "//", 2) != 0)
			maybe_url = FALSE;

		/*
		 * See the next block comment ("Once upon a time ...") to
		 * understand this. It turns the deprecated concept
		 * of "subdir mounts" produced some useful code for handling
		 * the possibility of a ":port#" in the URL.
		 */
		if (maybe_url == FALSE)
			*subdir = '/';
		else
			*subdir = ':';

		*qbuff = ' ';

		/*
		 * Once upon time, before autofs, there was support for
		 * "subdir mounts". The idea was to "economize" the
		 * number of mounts, so if you had a number of entries
		 * all referring to a common subdirectory, e.g.
		 *
		 *	carol    seasons:/export/home11/carol
		 *	ted	 seasons:/export/home11/ted
		 *	alice	 seasons:/export/home11/alice
		 *
		 * then you could tell the automounter to mount a
		 * common mountpoint which was delimited by the second
		 * colon:
		 *
		 *	carol    seasons:/export/home11:carol
		 *	ted	 seasons:/export/home11:ted
		 *	alice	 seasons:/export/home11:alice
		 *
		 * The automounter would mount seasons:/export/home11
		 * then for any other map entry that referenced the same
		 * directory it would build a symbolic link that
		 * appended the remainder of the path after the second
		 * colon, i.e.  once the common subdir was mounted, then
		 * other directories could be accessed just by link
		 * building - no further mounts required.
		 *
		 * In theory the "mount saving" idea sounded good. In
		 * practice the saving didn't amount to much and the
		 * symbolic links confused people because the common
		 * mountpoint had to have a pseudonym.
		 *
		 * To remain backward compatible with the existing
		 * maps, we interpret a second colon as a slash.
		 */
		if (getword(subdir+1, qbuff+1, &wlp, &wlq, ':',
				sizeof (subdir)) == -1)
			return (PARSE_ERROR);

		if (*(subdir+1))
			(void) strcat(dirname, subdir);

		hl = hostlist; hlq = hostlistq;

		host_cnt = 0;
		for (;;) {

			if (getword(hostname_and_penalty, qbuff, &hl, &hlq, ',',
				sizeof (hostname_and_penalty)) == -1)
				return (PARSE_ERROR);
			if (!*hostname_and_penalty)
				break;

			host_cnt++;
			if (host_cnt > 1)
				maybe_url = FALSE;

			hn = hostname_and_penalty;
			hnq = qbuff;
			if (getword(hostname, qbuff1, &hn, &hnq, '(',
				sizeof (hostname)) == -1)
				return (PARSE_ERROR);
			if (hostname[0] == '\0')
				goto bad_entry;

			if (strcmp(hostname, hostname_and_penalty) == 0) {
				penalty = 0;
			} else {
				maybe_url = FALSE;
				hn++; hnq++;
				if (getword(pbuff, pbuffq, &hn, &hnq, ')',
					sizeof (pbuff)) == -1)
					return (PARSE_ERROR);
				if (!*pbuff)
					penalty = 0;
				else
					penalty = atoi(pbuff);
			}
			mfs = (struct mapfs *)malloc(sizeof (*mfs));
			if (mfs == NULL) {
				syslog(LOG_ERR,
				"parse_nfs: Memory allocation failed");
				return (PARSE_ERROR);
			}
			(void) memset(mfs, 0, sizeof (*mfs));
			*mfsp = mfs;
			mfsp = &mfs->mfs_next;

			if (maybe_url == TRUE) {
				char *host;
				char *path;
				char *sport;

				host = dirname+2;
				path = strchr(host, '/');
				if (path == NULL) {
					syslog(LOG_ERR,
					"parse_nfs: illegal nfs url syntax: %s",
					host);

					return (PARSE_ERROR);
				}
				*path = '\0';
				sport =  strchr(host, ':');

				if (sport != NULL && sport < path) {
					*sport = '\0';
					mfs->mfs_port = atoi(sport+1);

					if (mfs->mfs_port > USHRT_MAX) {
						syslog(LOG_ERR,
							"parse_nfs: invalid "
							"port number (%d) in "
							"NFS URL",
							mfs->mfs_port);

						return (PARSE_ERROR);
					}

				}

				path++;
				if (*path == '\0')
					path = ".";

				mfs->mfs_flags |= MFS_URL;

				mfs->mfs_host = strdup(host);
				mfs->mfs_dir = strdup(path);
			} else {
				mfs->mfs_host = strdup(hostname);
				mfs->mfs_dir = strdup(dirname);
			}

			mfs->mfs_penalty = penalty;
			if (mfs->mfs_host == NULL || mfs->mfs_dir == NULL) {
				syslog(LOG_ERR,
				"parse_nfs: Memory allocation failed");
				return (PARSE_ERROR);
			}
		}
		/*
		 * We check host_cnt to make sure we haven't parsed an entry
		 * with no host information.
		 */
		if (host_cnt == 0) {
			syslog(LOG_ERR,
			"parse_nfs: invalid host specified - bad entry "
			"in map %s \"%s\"",
			mapname, w);
			return (PARSE_ERROR);
		}
		if (getword(w, wq, lp, lq, ' ', wsize) == -1)
			return (PARSE_ERROR);
	}

	strcpy(fsw, w);
	strcpy(fswq, wq);

	return (PARSE_OK);

bad_entry:
	syslog(LOG_ERR, "parse_nfs: bad entry in map %s \"%s\"", mapname, w);
	return (PARSE_ERROR);
}

static int
parse_special(me, w, wq, lp, lq, wsize)
	struct mapent *me;
	char *w, *wq, **lp, **lq;
	int wsize;
{
	char devname[MAXPATHLEN + 1], qbuf[MAXPATHLEN + 1];
	char *wlp, *wlq;
	struct mapfs *mfs;

	wlp = w;
	wlq = wq;
	if (getword(devname, qbuf, &wlp, &wlq, ' ', sizeof (devname)) == -1)
		return (PARSE_ERROR);
	if (devname[0] == '\0')
		return (PARSE_ERROR);

	mfs = (struct mapfs *)malloc(sizeof (struct mapfs));
	if (mfs == NULL)
		return (PARSE_ERROR);
	(void) memset(mfs, 0, sizeof (*mfs));

	/*
	 * A device name that begins with a slash could
	 * be confused with a mountpoint path, hence use
	 * a colon to escape a device string that begins
	 * with a slash, e.g.
	 *
	 *	foo  -ro  /bar  foo:/bar
	 * and
	 *	foo  -ro  /dev/sr0
	 *
	 * would confuse the parser.  The second instance
	 * must use a colon:
	 *
	 *	foo  -ro  :/dev/sr0
	 */
	mfs->mfs_dir = strdup(&devname[devname[0] == ':']);
	if (mfs->mfs_dir == NULL)
		return (PARSE_ERROR);
	me->map_fs = mfs;
	if (getword(w, wq, lp, lq, ' ', wsize) == -1)
		return (PARSE_ERROR);
	return (0);
}

/*
 * get_dir_from_path(char *dir, char **path, int dirsz)
 * gets the directory name dir from path for max string of length dirsz.
 * A modification of the getword routine. Assumes the delimiter is '/'
 * and that excess /'s are redundant.
 * Returns PARSE_OK or PARSE_ERROR
 */
static int
get_dir_from_path(char *dir, char **path, int dirsz)
{
	char *tmp = dir;
	int count = dirsz;

	if (dirsz <= 0) {
		if (verbose)
			syslog(LOG_ERR,
			"get_dir_from_path: invalid directory size %d", dirsz);
		return (PARSE_ERROR);
	}

	/* get rid of leading /'s in path */
	while (**path == '/')
		(*path)++;

	/* now at a word or at the end of path */
	while ((**path) && ((**path) != '/')) {
		if (--count <= 0) {
			*tmp = '\0';
			syslog(LOG_ERR,
			"get_dir_from_path: max pathlength exceeded %d", dirsz);
			return (PARSE_ERROR);
		}
		*dir++ = *(*path)++;
	}

	*dir = '\0';

	/* get rid of trailing /'s in path */
	while (**path == '/')
		(*path)++;

	return (PARSE_OK);
}

/*
 * alloc_hiernode(hiernode **newnode, char *dirname)
 * allocates a new hiernode corresponding to a new directory entry
 * in the hierarchical structure, and passes a pointer to it back
 * to the calling program.
 * Returns PARSE_OK or appropriate error value.
 */
static int
alloc_hiernode(hiernode **newnode, char *dirname)
{
	if ((*newnode = (hiernode *)malloc(sizeof (hiernode))) == NULL) {
		syslog(LOG_ERR,	"alloc_hiernode: Memory allocation failed");
		return (ENOMEM);
	}

	memset(((char *)*newnode), 0, sizeof (hiernode));
	strcpy(((*newnode)->dirname), dirname);
	return (PARSE_OK);
}

/*
 * free_hiernode(hiernode *node)
 * frees the allocated hiernode given the head of the structure
 * recursively calls itself until it frees entire structure.
 * Returns nothing.
 */
static void
free_hiernode(hiernode *node)
{
	hiernode *currnode = node;
	hiernode *prevnode = NULL;

	while (currnode != NULL) {
		if (currnode->subdir != NULL)
			free_hiernode(currnode->subdir);
		prevnode = currnode;
		currnode = currnode->leveldir;
		free((void*)prevnode);
	}
}

/*
 * free_mapent(struct mapent *)
 * free the mapentry and its fields
 */
void
free_mapent(me)
	struct mapent *me;
{
	struct mapfs *mfs;
	struct mapent *m;

	while (me) {
		while (me->map_fs) {
			mfs = me->map_fs;
			if (mfs->mfs_host)
				free(mfs->mfs_host);
			if (mfs->mfs_dir)
				free(mfs->mfs_dir);
			if (mfs->mfs_args)
				free(mfs->mfs_args);
			if (mfs->mfs_nconf)
				freenetconfigent(mfs->mfs_nconf);
			me->map_fs = mfs->mfs_next;
			free((char *)mfs);
		}

		if (me->map_root)
			free(me->map_root);
		if (me->map_mntpnt)
			free(me->map_mntpnt);
		if (me->map_mntopts)
			free(me->map_mntopts);
		if (me->map_fstype)
			free(me->map_fstype);
		if (me->map_mounter)
			free(me->map_mounter);
		if (me->map_fsw)
			free(me->map_fsw);
		if (me->map_fswq)
			free(me->map_fswq);

		m = me;
		me = me->map_next;
		free((char *)m);
	}
}

/*
 * trace_mapents(struct mapent *mapents)
 * traces through the mapentry structure and prints it element by element
 * returns nothing
 */
static void
trace_mapents(char *s, struct mapent *mapents)
{
	struct mapfs  *mfs;
	struct mapent *me;

	trace_prt(1, "\n\t%s\n", s);
	for (me = mapents; me; me = me->map_next) {
		trace_prt(1, "  (%s,%s)\t %s%s -%s\n",
		    me->map_fstype ? me->map_fstype : "",
		    me->map_mounter ? me->map_mounter : "",
		    me->map_root  ? me->map_root : "",
		    me->map_mntpnt ? me->map_mntpnt : "",
		    me->map_mntopts ? me->map_mntopts : "");
		for (mfs = me->map_fs; mfs; mfs = mfs->mfs_next)
			trace_prt(0, "\t\t%s:%s\n",
			    mfs->mfs_host ? mfs->mfs_host: "",
			    mfs->mfs_dir ? mfs->mfs_dir : "");

		trace_prt(1, "\tme->map_fsw=%s\n",
		    me->map_fsw ? me->map_fsw:"",
		    me->map_fswq ? me->map_fsw:"");
		trace_prt(1, "\t mntlevel=%d\t%s\t%s err=%d\n",
		    me->map_mntlevel,
		    me->map_modified ? "modify=TRUE":"modify=FALSE",
		    me->map_faked ? "faked=TRUE":"faked=FALSE",
		    me->map_err);
	}
}

/*
 * trace_hierarchy(hiernode *node)
 * traces the allocated hiernode given the head of the structure
 * recursively calls itself until it traces entire structure.
 * the first call made at the root is made with a zero level.
 * nodelevel is simply used to print tab and make the tracing clean.
 * Returns nothing.
 */
static void
trace_hierarchy(hiernode *node, int nodelevel)
{
	hiernode *currnode = node;
	int i;

	while (currnode != NULL) {
		if (currnode->subdir != NULL) {
			for (i = 0; i < nodelevel; i++)
				trace_prt(0, "\t");
			trace_prt(0, "\t(%s, ",
			    currnode->dirname ? currnode->dirname :"");
			if (currnode->mapent) {
				trace_prt(0, "%d, %s)\n",
				    currnode->mapent->map_mntlevel,
				    currnode->mapent->map_mntopts ?
				    currnode->mapent->map_mntopts:"");
			}
			else
				trace_prt(0, " ,)\n");
			nodelevel++;
			trace_hierarchy(currnode->subdir, nodelevel);
		} else {
			for (i = 0; i < nodelevel; i++)
				trace_prt(0, "\t");
			trace_prt(0, "\t(%s, ",
			    currnode->dirname ? currnode->dirname :"");
			if (currnode->mapent) {
				trace_prt(0, "%d, %s)\n",
				    currnode->mapent->map_mntlevel,
				    currnode->mapent->map_mntopts ?
				    currnode->mapent->map_mntopts:"");
			}
			else
				trace_prt(0, ", )\n");
		}
		currnode = currnode->leveldir;
	}
}

struct mapent *
do_mapent_hosts(mapopts, host, isdirect)
	char *mapopts, *host;
	uint_t isdirect;
{
	CLIENT *cl;
	struct mapent *me, *ms, *mp;
	struct mapfs *mfs;
	struct exportnode *ex = NULL;
	struct exportnode *exlist, *texlist, **texp, *exnext;
	struct timeval timeout;
	enum clnt_stat clnt_stat;
	char name[MAXPATHLEN];
	char entryopts[MAXOPTSLEN];
	char fstype[32], mounter[32];
	int exlen, duplicate;
	struct mnttab mb;	/* needed for hasmntopt() to get nfs version */
	rpcvers_t nfsvers;	/* version in map options, 0 if not there */
	rpcvers_t vers, versmin; /* used to negotiate nfs vers in pingnfs() */
	int retries, delay;
	int foundvers;

	if (trace > 1)
		trace_prt(1, "  do_mapent_hosts: host %s\n", host);

	/* check for special case: host is me */

	if (self_check(host)) {
		ms = (struct mapent *)malloc(sizeof (*ms));
		if (ms == NULL)
			goto alloc_failed;
		(void) memset((char *)ms, 0, sizeof (*ms));
		(void) strcpy(fstype, MNTTYPE_NFS);
		get_opts(mapopts, entryopts, fstype, NULL);
		ms->map_mntopts = strdup(entryopts);
		if (ms->map_mntopts == NULL)
			goto alloc_failed;
		ms->map_mounter = strdup(fstype);
		if (ms->map_mounter == NULL)
			goto alloc_failed;
		ms->map_fstype = strdup(MNTTYPE_NFS);
		if (ms->map_fstype == NULL)
			goto alloc_failed;

		if (isdirect)
			name[0] = '\0';
		else {
			(void) strcpy(name, "/");
			(void) strcat(name, host);
		}
		ms->map_root = strdup(name);
		if (ms->map_root == NULL)
			goto alloc_failed;
		ms->map_mntpnt = strdup("");
		if (ms->map_mntpnt == NULL)
			goto alloc_failed;
		mfs = (struct mapfs *)malloc(sizeof (*mfs));
		if (mfs == NULL)
			goto alloc_failed;
		(void) memset((char *)mfs, 0, sizeof (*mfs));
		ms->map_fs = mfs;
		mfs->mfs_host = strdup(host);
		if (mfs->mfs_host == NULL)
			goto alloc_failed;
		mfs->mfs_dir  = strdup("/");
		if (mfs->mfs_dir == NULL)
			goto alloc_failed;

		/* initialize mntlevel and modify */
		ms->map_mntlevel = -1;
		ms->map_modified = FALSE;
		ms->map_faked = FALSE;

		if (trace > 1)
			trace_prt(1,
			"  do_mapent_hosts: self-host %s OK\n", host);

		return (ms);
	}

	/*
	 * Call pingnfs. Note that we can't have replicated hosts in /net.
	 * XXX - we would like to avoid duplicating the across the wire calls
	 * made here in nfsmount(). The pingnfs cache should help avoid it.
	 */
	mb.mnt_mntopts = mapopts;
	foundvers = nopt(&mb, MNTOPT_VERS, (int *)&nfsvers);
	if (!foundvers)
		nfsvers = 0;
	if (set_versrange(nfsvers, &vers, &versmin) != 0) {
		syslog(LOG_ERR, "Incorrect NFS version specified for %s", host);
		return ((struct mapent *)NULL);
	}
	if (pingnfs(host, get_retry(mapopts) + 1, &vers, versmin, 0, FALSE,
	    NULL, NULL) != RPC_SUCCESS)
		return ((struct mapent *)NULL);

	retries = get_retry(mapopts);
	delay = INITDELAY;
retry:
	/* get export list of host */
	cl = clnt_create(host, MOUNTPROG, MOUNTVERS, "circuit_v");
	if (cl == NULL) {
		cl = clnt_create(host, MOUNTPROG, MOUNTVERS, "datagram_v");
		if (cl == NULL) {
			syslog(LOG_ERR,
			"do_mapent_hosts: %s %s", host, clnt_spcreateerror(""));
			return ((struct mapent *)NULL);
		}

	}
#ifdef MALLOC_DEBUG
	add_alloc("CLNT_HANDLE", cl, 0, __FILE__, __LINE__);
	add_alloc("AUTH_HANDLE", cl->cl_auth, 0,
		__FILE__, __LINE__);
#endif

	timeout.tv_usec = 0;
	timeout.tv_sec  = 25;
	if (clnt_stat = clnt_call(cl, MOUNTPROC_EXPORT, xdr_void, 0,
				xdr_exports, (caddr_t)&ex, timeout)) {

		if (retries-- > 0) {
			clnt_destroy(cl);
			DELAY(delay);
			goto retry;
		}

		syslog(LOG_ERR,
			"do_mapent_hosts: %s: export list: %s",
			host, clnt_sperrno(clnt_stat));
#ifdef MALLOC_DEBUG
		drop_alloc("CLNT_HANDLE", cl, __FILE__, __LINE__);
		drop_alloc("AUTH_HANDLE", cl->cl_auth,
			__FILE__, __LINE__);
#endif
		clnt_destroy(cl);
		return ((struct mapent *)NULL);
	}

#ifdef MALLOC_DEBUG
	drop_alloc("CLNT_HANDLE", cl, __FILE__, __LINE__);
	drop_alloc("AUTH_HANDLE", cl->cl_auth,
		__FILE__, __LINE__);
#endif
	clnt_destroy(cl);

	if (ex == NULL) {
		if (trace > 1)
			trace_prt(1,
			    gettext("  getmapent_hosts: null export list\n"));
		return ((struct mapent *)NULL);
	}

	/* now sort by length of names - to get mount order right */
	exlist = ex;
	texlist = NULL;
#ifdef lint
	exnext = NULL;
#endif
	for (; ex; ex = exnext) {
		exnext = ex->ex_next;
		exlen = strlen(ex->ex_dir);
		duplicate = 0;
		for (texp = &texlist; *texp; texp = &((*texp)->ex_next)) {
			if (exlen < (int)strlen((*texp)->ex_dir))
				break;
			duplicate = (strcmp(ex->ex_dir, (*texp)->ex_dir) == 0);
			if (duplicate) {
				/* disregard duplicate entry */
				freeex_ent(ex);
				break;
			}
		}
		if (!duplicate) {
			ex->ex_next = *texp;
			*texp = ex;
		}
	}
	exlist = texlist;

	(void) strcpy(fstype, MNTTYPE_NFS);
	get_opts(mapopts, entryopts, fstype, NULL);
	(void) strcpy(mounter, fstype);

	/* Now create a mapent from the export list */
	ms = NULL;
	me = NULL;

	for (ex = exlist; ex; ex = ex->ex_next) {
		mp = me;
		me = (struct mapent *)malloc(sizeof (*me));
		if (me == NULL)
			goto alloc_failed;
		(void) memset((char *)me, 0, sizeof (*me));

		if (ms == NULL)
			ms = me;
		else
			mp->map_next = me;

		if (isdirect)
			name[0] = '\0';
		else {
			(void) strcpy(name, "/");
			(void) strcat(name, host);
		}
		me->map_root = strdup(name);
		if (me->map_root == NULL)
			goto alloc_failed;

		*name = '\0';
		if (strcmp(ex->ex_dir, "/") != 0) {
			if (*(ex->ex_dir) != '/')
				(void) strcpy(name, "/");
			(void) strcat(name, ex->ex_dir);
		}
		me->map_mntpnt = strdup(name);
		if (me->map_mntpnt == NULL)
			goto alloc_failed;

		me->map_fstype = strdup(fstype);
		if (me->map_fstype == NULL)
			goto alloc_failed;
		me->map_mounter = strdup(mounter);
		if (me->map_mounter == NULL)
			goto alloc_failed;
		me->map_mntopts = strdup(entryopts);
		if (me->map_mntopts == NULL)
			goto alloc_failed;

		mfs = (struct mapfs *)malloc(sizeof (*mfs));
		if (mfs == NULL)
			goto alloc_failed;
		(void) memset((char *)mfs, 0, sizeof (*mfs));
		me->map_fs = mfs;
		mfs->mfs_host = strdup(host);
		if (mfs->mfs_host == NULL)
			goto alloc_failed;
		mfs->mfs_dir = strdup(ex->ex_dir);
		if (mfs->mfs_dir == NULL)
			goto alloc_failed;

		/* initialize mntlevel and modify values */
		me->map_mntlevel = -1;
		me->map_modified = FALSE;
		me->map_faked = FALSE;
	}
	freeex(exlist);

	if (trace > 1)
		trace_prt(1, "  do_mapent_hosts: host %s OK\n", host);

	return (ms);

alloc_failed:
	syslog(LOG_ERR, "do_mapent_hosts: Memory allocation failed");
	free_mapent(ms);
	freeex(exlist);
	return ((struct mapent *)NULL);
}


static void
freeex_ent(ex)
	struct exportnode *ex;
{
	struct groupnode *groups, *tmpgroups;

	free(ex->ex_dir);
	groups = ex->ex_groups;
	while (groups) {
		free(groups->gr_name);
		tmpgroups = groups->gr_next;
		free((char *)groups);
		groups = tmpgroups;
	}
	free((char *)ex);
}

static void
freeex(ex)
	struct exportnode *ex;
{
	struct exportnode *tmpex;

	while (ex) {
		tmpex = ex->ex_next;
		freeex_ent(ex);
		ex = tmpex;
	}
}

static const char uatfs_err[] = "submount under fstype=autofs not supported";
/*
 * dump_mapent_err(struct mapent *me, char *key, char *mapname)
 * syslog appropriate error in mapentries.
 */
static void dump_mapent_err(struct mapent *me, char *key, char *mapname)
{
	switch (me->map_err) {
	case MAPENT_NOERR:
		if (verbose)
			syslog(LOG_ERR,
			"map=%s key=%s mntpnt=%s: no error");
		break;
	case MAPENT_UATFS:
		syslog(LOG_ERR,
		"mountpoint %s in map %s key %s not mounted: %s",
		    me->map_mntpnt, mapname, key, uatfs_err);
		break;
	default:
		if (verbose)
			syslog(LOG_ERR,
			"map=%s key=%s mntpnt=%s: unknown mapentry error");
	}
}
