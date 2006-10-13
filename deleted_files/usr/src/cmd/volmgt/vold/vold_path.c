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
 * Copyright (c) 1994,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/param.h>

#include	"vold.h"


char	*path_flip(char *);
char	*path_nisquotequote(char *);

/*
 * for now, this is a bit on the terse side, however someday I
 * might want to have it return more information about the
 * path.
 */
/*
 * return the type of a "full" pathname (see below).
 */
uint_t
path_type(vvnode_t *fvn)
{
	vvnode_t	*vn;
	vvnode_t	*ovn;


	if (fvn == NULL || fvn->vn_parent == NULL) {
		return (0);
	}

	/* crawl up to the top */
	ovn = fvn;
	for (vn = fvn->vn_parent;
	    vn->vn_parent != NULL;
	    ovn = vn, vn = vn->vn_parent) {
		/* do nothing */;
	}

	if (strcmp(ovn->vn_name, DEVNAME) == 0) {
		return (DIR_DEV);
	}
	if (strcmp(ovn->vn_name, RDSKNAME) == 0) {
		return (DIR_RDSK);
	}
	if (strcmp(ovn->vn_name, DSKNAME) == 0) {
		return (DIR_DSK);
	}
	if (strcmp(ovn->vn_name, RMTNAME) == 0) {
		return (DIR_RMT);
	}
	if (strcmp(ovn->vn_name, MTNAME) == 0) {
		return (DIR_MT);
	}
	/* oops -- don't recognize this type */
	return (DIR_UNKNOWN);
}


/*
 * Return a path to a vnode.  Must crawl up the file system tree
 * to figure this out.  It's a little nasty because walking up
 * the tree gives up the path in the wrong order.
 *
 * Th maximum number of components in a path name is MAXCOMP.
 * The worst case is /a/a/a/a/a/a/a (i.e.
 * '/' and a single chararcter dir name).
 */

#define	MAXCOMP	(MAXPATHLEN/2)

char *
path_make(vvnode_t *vn)
{
	vvnode_t 	*vp;
	char		*comp[MAXCOMP];
	char		buf[MAXPATHLEN];
	int		i;
	int		len;



	if (vn == NULL) {
		return (strdup(vold_root));
	}

	/*
	 * Crawl up the tree, remembering each vn_name on
	 * the way up.
	 */
	for (i = 0, vp = vn; vp->vn_parent && i < MAXCOMP;
	    vp = vp->vn_parent, i++) {
		comp[i] = vp->vn_name;
	}

	/* stick the root in there */
	(void) strcpy(buf, vold_root);
	len = strlen(vold_root);

	/* go back down the list */
	for (i -= 1; i >= 0; i--) {
		len += strlen(comp[i]);
		if (len >= MAXPATHLEN) {
			warning("path too long, vn 0x%x, name %s\n",
				vn, vn->vn_name);
			break;
		}
		(void) strcat(buf, "/");
		(void) strcat(buf, comp[i]);
	}
	return (strdup(buf));
}


/*
 * This function takes a path returned from mnttab, and returns
 * a path that can replace it based on the new renamed path.
 * There are several special cases.
 */
char *
path_mntrename(char *mntpth, char *to, char *rname)
{
	char	buf[MAXPATHLEN+1];
	char	**mp;
	char	**ts;
	int	i;
	int	mpstop;


	/* break paths into components */
	mp = path_split(mntpth);
	ts = path_split(to);

	/* find out where the rename point is in the mount path */
	for (i = 0; mp[i]; i++)
		if (strcmp(mp[i], rname) == 0)
			break;
	if (mp[i])
		mpstop = i + 1;
	else
		mpstop = i;

	buf[0] = '\0';

	for (i = 0; ts[i]; i++) {
		(void) strcat(buf, "/");
		(void) strcat(buf, ts[i]);
	}

	for (i = mpstop; mp[i]; i++) {
		(void) strcat(buf, "/");
		(void) strcat(buf, mp[i]);
	}
	path_freeps(mp);
	path_freeps(ts);

	return (strdup(buf));
}

/*
 * Take a path and split it into components, each one sits in
 * its own element of the char** returned.  It is terminated
 * by a null string.
 */
char **
path_split(char *path)
{
	char	*np, *s, *p, **val;
	int	i;

	if (*path == '/') {
		path++;
	}
	s = path;
	i = 0;
	while (p = strchr(s, '/')) {
		i++;
		s = p+1;
	}
	val = (char **)malloc((size_t)(sizeof (char *) * (i+2)));
	np = strdup(path);

	s = np;
	i = 0;
	while (p = strchr(s, '/')) {
		val[i++] = s;
		*p = '\0';
		s = p+1;
	}
	val[i++] = s;
	val[i] = 0;
	return (val);
}

/*
 * Free a split path (allocated by path_split).
 */
void
path_freeps(char **ps)
{
	free(ps[0]);	/* malloc'd the whole wad with strdup */
	free(ps);
}

#ifdef UNUSED
/*
 * take a regular UNIX pathname with /'s and turn it into a nis+
 * name with .'s.  Unfortunatly, . in a filename must be quoted.
 * That is what the first bit of nastyness is.
 */
char *
path_nis(char *path)
{
	char	*s, *f, *t, *np = NULL;
	uint_t	count = 0;
	uint_t	len = strlen(path);
	uint_t	endquote;

	/* flip the thing around */
	path = path_flip(path);

	path = path_nisquotequote(path);
	/* work on the dot quoting */
	s = path;
	while ((s = strchr(s, '.')) != NULL) {
		s++;	/* advance beyond the '.'! */
		count += 2; /* two extra " for each . */
	}

	if (count) {
		len += count;
#ifdef TESTPATH
		np = (char *)calloc(1024, sizeof (char));
#else
		np = (char *)calloc(len+1, sizeof (char));
#endif
		if (np == NULL)
			fatal("path_nis");

		f = path;
		t = np;
		while (*f) {
			if (*f == '.') {
				endquote = 0;
				s = strrchr(np, '/');
				if (s) {
					*++s = '"';
					f = f - (t - s);
					t = s + 1;
				} else {
					t = np;
					*t++ = '"';
					f = path;
				}
				while (*f) {
					if (*f == '/') {
						*t++ = '"';
						*t++ = *f++;
						endquote = 1;
						break;
					} else {
						*t++ = *f++;
					}
				}
				if (endquote == 0) {
					*t++ = '"';
				}
			} else {
				*t++ = *f++;
			}
		}
		*t = '\0';
		free(path);
		path = np;
	}

	/* convert all '/' to '.' */
	while ((s = strchr(path, '/')) != NULL)
		*s = '.';
	return (path);
}



char *
path_unnis(char *path)
{
	char	*s, *p;
	char	*np;
	uint_t	quote = 0;

	np = (char *)malloc(strlen(path)+1);
	p = np;
	s = path;
	while (*s) {
		if (*s == '"') {
			if (*(s+1) == '"') {
				/* quoting a quote */
				s += 2;
				*p++ = '"';
			} else {
				/* quotes inserted for a '.' */
				s++;
				if (quote == 1)
					quote = 0;
				else
					quote = 1;
			}
			continue;
		}
		if (*s == '.') {
			/* if we're in a quote, a '.' is a '.' */
			if (quote == 1)
				*p++ = '.';
			/* otherwise, a '.' is a '/' */
			else
				*p++ = '/';

			s++;
			continue;
		}
		*p++ = *s++;
	}
	free(path);
	return (path_flip(np));
}

char *
path_nisquotequote(char *path)
{
	char	*f, *t, *np;
	uint_t	count;

	f = path;
	while ((f = strchr(f, '"')) != NULL) {
		f++;	/* advance beyond the '"'! */
		count += 1; /* one extra " for each " */
	}

#ifdef TESTPATH
	np = (char *)calloc(1024, sizeof (char));
#else
	np = (char *)calloc(strlen(path)+count+1, sizeof (char));
#endif
	if (np == NULL)
		fatal("path_nisquotequote");

	f = path;
	t = np;
	while (*f) {
		if (*f == '"')
			*t++ = '"';
		*t++ = *f++;
	}
	free(path);
	return (np);
}
#endif /* UNUSED */

/*
 * This is the old crappy (and slow) version of path_make.
 */
#ifdef notdef
/*
 * return a full path name starting at the root of the filesystem,
 * i.e. /vol/rdsk/blah.
 */
char *
path_make(vvnode_t *vn)
{
	vvnode_t 	*vp;
	uint_t		count = 0;
	char		*pn, *s;
	uint_t		len;


	if (vn == NULL) {
		/* root case */
		return (strdup(vold_root));
	}

	pn = (char *)malloc(MAXPATHLEN);
	pn[0] = '\0';

	count += strlen(vold_root);
	for (vp = vn; vp->vn_parent; vp = vp->vn_parent) {
		count += strlen(vp->vn_name);
		if (count > MAXPATHLEN-1) {
			warning("pathname for %s too deep!\n", vn->vn_name);
			/* cheezy error out */
			return (strdup(vold_root));
		}
		(void) strcat(pn, vp->vn_name);
		(void) strcat(pn, "/");
	}
	(void) strcat(pn, &vold_root[1]);	/* wack off leading '/' */
	(void) strcat(pn, "/");

	/* now flip it (free's pn and makes it a more reasonable size) */
	return (path_flip(pn));
}


char *
path_flip(char *path)
{
	char	*np, *s;
	uint_t	rooted;

	/* flip the string */
#ifdef TESTPATH
	np = (char *)calloc(MAXPATHLEN, sizeof (char));
#else
	np = (char *)calloc(strlen(path)+1, sizeof (char));
#endif
	if (np == NULL) {
		fatal("path_flip");
	}

	if (path[0] == '/') {
		rooted = 1;
	} else {
		rooted = 0;
	}
	while ((s = strrchr(path, '/')) != NULL) {
		(void) strcat(np, s+1);
		(void) strcat(np, "/");
		*s = '\0';
	}
	if (rooted == 0) {
		(void) strcat(np, path);
		(void) strcat(np, "/");
	}

	if ((s = strrchr(np, '/')) != NULL) {
		*s = '\0';
	}

	free(path);
	return (np);
}
#endif
