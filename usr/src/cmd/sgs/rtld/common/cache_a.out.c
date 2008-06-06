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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * 4.x ld.so directory caching: run-time link-editor specific functions.
 */

#include	<dirent.h>
#include	<string.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	"_a.out.h"
#include	"cache_a.out.h"
#include	"_rtld.h"
#include	"msg.h"

static int	stol();
static int	rest_ok();
static int	verscmp();
static void	fix_lo();
static int	extract_name();
static int	hash();

static struct link_object *get_lo();
static struct dbd *new_dbd();
static struct db *find_so();

#define	SKIP_DOT(str)	((*str == '.')  ? ++str : str)
#define	EMPTY(str)	((str == NULL) || (*str == '\0'))
#define	isdigit(c)	(((c) >= '0') && ((c) <= '9') ? 1:0)

static struct dbd *dbd_head = NULL;	/* head of data bases */


/*
 * Given a db - find the highest shared versioned object. The
 * highest versioned object is the .so  with a matching major number
 * but the highest minor number
 */
char *
ask_db(dbp, file)
	struct db *dbp;
	const char *file;
{
	char *libname, *n;
	char *mnp;
	char *mjp;
	int liblen;
	int major = 0;
	int to_min;
	struct dbe *ep;
	struct link_object *tlop;
	int index;

	n = (char *)file;
	if ((liblen = extract_name(&n)) == -1)
		return (NULL);
	if ((libname = malloc(liblen + 1)) == 0)
		return (NULL);
	(void) strncpy(libname, n, liblen);
	libname[liblen] = NULL;

	if (strncmp(MSG_ORIG(MSG_FIL_DOTSODOT), (n + liblen),
	    MSG_FIL_DOTSODOT_SIZE))
		return (NULL);

	mnp = mjp = ((char *)file + MSG_FIL_LIB_SIZE + liblen +
	    MSG_FIL_DOTSODOT_SIZE);
	if (!(stol(mjp, '.', &mnp, &major) && (*mnp == '.') &&
	    rest_ok(mnp + 1)))
		return (NULL);
	to_min = mnp - file + 1;

	/*
	 * Search appropriate hash bucket for a matching entry.
	 */
	index = hash(libname, liblen, major);
	for (ep = (struct dbe *)&(dbp->db_hash[index]); (ep && ep->dbe_lop);
	    ep = ep->dbe_next == 0 ? NULL :
	    /* LINTED */
	    (struct dbe *)&AP(dbp)[ep->dbe_next]) {
		/* LINTED */
		tlop = (struct link_object *)&AP(dbp)[ep->dbe_lop];
		if (tlop->lo_major == major)
			if (strcmp((char *)&AP(dbp)[tlop->lo_name],
			    libname) == 0)
				break;
	}

	/*
	 * If no entry was found, we've lost.
	 */
	if (!(ep && ep->dbe_lop))
		return (NULL);
	if (verscmp(file + to_min,
	    &AP(dbp)[ep->dbe_name] + tlop->lo_minor) > 0)
		eprintf(&lml_main, ERR_WARNING, MSG_INTL(MSG_GEN_OLDREV),
		    &AP(dbp)[ep->dbe_name], file + to_min);
	return (&AP(dbp)[ep->dbe_name]);
}

/*
 * Given a directory name - give back a data base. The data base may have
 * orginated from the mmapped file or temporarily created
 */
struct db *
lo_cache(const char *ds)
{
	struct db *dbp;			/* database pointer */
	struct dbd *dbdp;		/* working database descriptor */
	struct dbd **dbdpp;		/* insertion pointer */

	dbdpp = &dbd_head;
	for (dbdp = dbd_head; dbdp; dbdp = dbdp->dbd_next) {
		if (strcmp(ds, &AP(dbdp->dbd_db)[dbdp->dbd_db->db_name]) == 0)
			return (dbdp->dbd_db);
		dbdpp = &dbdp->dbd_next;
	}
	if (dbp = find_so(ds)) {
		(void) new_dbd(dbdpp, dbp);
	}
	return (dbp);
}

/*
 * Build a database for the directory "ds".
 */
static struct db *
find_so(const char *ds)
{
	int fd;				/* descriptor on directory */
	int n;				/* bytes from getdents */
	char *cp;			/* working char * */
	struct stat sb;			/* buffer for stat'ing directory */
	struct db *dbp;			/* database */
	static caddr_t buf = NULL;	/* buffer for doing getdents */
	static long bs;			/* cached blocksize for getdents */
	struct link_object *tlop;	/* working link object ptr. */
	struct dirent *dp;		/* directory entry ptr. */
	struct dbe *ep;			/* working db_entry ptr. */
	char *mnp;			/* where minor version begins */
	char *mjp;			/* where major version begins */
	int m;				/* the major number */
	int to_min;			/* index into string of minor */
	int cplen;			/* length of X */
	int index;			/* the hash value */

	/*
	 * Try to open directory.  Failing that, just return silently.
	 */
	if ((fd = open(ds, O_RDONLY)) == -1)
		return ((struct db *)NULL);

	/*
	 * If we have not yet gotten a buffer for reading directories,
	 * allocate it now.  Size it according to the most efficient size
	 * for the first directory we open successfully.
	 */
	if (!buf) {
		if (fstat(fd, &sb) == -1) {
			(void) close(fd);
			return ((struct db *)NULL);
		}
		bs = sb.st_blksize;
		buf = calloc(bs, 1);
	}

	/*
	 * Have a directory, have a buffer.  Allocate up a database
	 * and initialize it.
	 */
	dbp = calloc(sizeof (struct db), 1);
	dbp->db_name = RELPTR(dbp, calloc((strlen(ds) + 1), 1));
	(void) strcpy((char *)&AP(dbp)[dbp->db_name], ds);

	/*
	 * Scan the directory looking for shared libraries.  getdents()
	 * failures are silently ignored and terminate the scan.
	 */
	/* LINTED */
	while ((n = getdents(fd, (struct dirent *)buf, bs)) > 0)
		/* LINTED */
		for (dp = (struct dirent *)buf;
		    /* LINTED */
		    dp && (dp < (struct dirent *)(buf + n));
		    /* LINTED */
		    dp = (struct dirent *)((dp->d_reclen == 0) ?
		    NULL : (char *)dp + dp->d_reclen)) {

			/*
			 * If file starts with a "lib", then extract the X
			 * from libX.
			 */
			cp = dp->d_name;
			if ((cplen = extract_name(&cp)) == -1)
				continue;

			/*
			 * Is the next component ".so."?
			 */
			if (strncmp(MSG_ORIG(MSG_FIL_DOTSODOT), (cp + cplen),
			    MSG_FIL_DOTSODOT_SIZE))
				continue;

			/*
			 * Check if next component is the major number and
			 * whether following components are legal.
			 */
			mnp = mjp = (dp->d_name + MSG_FIL_LIB_SIZE + cplen +
			    MSG_FIL_DOTSODOT_SIZE);
			if (!(stol(mjp, '.', &mnp, &m) && (*mnp == '.') &&
			    rest_ok(mnp + 1)))
				continue;
			to_min = mnp - dp->d_name + 1;

			/*
			 * Have libX.so.major.minor - attempt to add it to the
			 * cache. If there is another with the same major
			 * number then the chose the object with the highest
			 * minor number
			 */
			index = hash(cp, cplen, m);
			ep = &(dbp->db_hash[index]);
			if (ep->dbe_lop == NULL) {
				ep->dbe_lop = (long)get_lo(dbp, cp,
				    cplen, m, to_min);
				/* LINTED */
				tlop = (struct link_object *)
				    &AP(dbp)[ep->dbe_lop];
				(void) strcpy(&AP(dbp)[tlop->lo_next],
				    dp->d_name);
				continue;
			}
			for (ep = &(dbp->db_hash[index]); ep;
			    /* LINTED */
			    ep = (struct dbe *)&AP(dbp)[ep->dbe_next]) {
				/* LINTED */
				tlop = (struct link_object *)
				    &AP(dbp)[ep->dbe_lop];

				/*
				 * Choose the highest minor version
				 */
				if ((tlop->lo_major == m) &&
				    (strncmp(&AP(dbp)[tlop->lo_name],
				    cp, cplen) == 0) &&
				    (*(&AP(dbp)[tlop->lo_name +
				    cplen]) == '\0')) {
					if (verscmp(dp->d_name + to_min,
					    (char *)(&AP(dbp)[tlop->lo_next]
					    + to_min)) > 0)
						(void) strcpy(&AP(dbp)
						    [tlop->lo_next],
						    dp->d_name);
					break;
				}
				if (ep->dbe_next == NULL) {
					ep->dbe_next = RELPTR(dbp,
					    calloc(sizeof (struct dbe), 1));
					/* LINTED */
					ep  = (struct dbe *)
					    &AP(dbp)[ep->dbe_next];
					ep->dbe_lop = (long)get_lo(dbp,
					    cp, cplen, m, to_min);
					/* LINTED */
					tlop = (struct link_object *)
					    &AP(dbp)[ep->dbe_lop];
					(void) strcpy(&AP(dbp)[tlop->lo_next],
					    dp->d_name);
					break;
				}
			}
		}
	fix_lo(dbp);
	(void) close(fd);
	return (dbp);
}

/*
 * Allocate and fill in the fields for a link_object
 */
static struct link_object *
get_lo(dbp, cp, cplen, m, n)
	struct db *dbp;			/* data base */
	char *cp;			/* ptr. to X of libX */
	int cplen;			/* length of X */
	int m;				/* major version */
	int n;				/* index to minor version */
{
	struct link_object *lop;	/* link_object to be returned */
	struct link_object *tlop;	/* working copy of the above */

	/*
	 * Allocate a link object prototype in the database heap.
	 * Store the numeric major (interface) number, but the minor
	 * number is stored in the database as an index to the string
	 * representing the minor version.  By keeping the minor version
	 * as a string, "subfields" (i.e., major.minor[.other.fields. etc.])
	 * are permitted.  Although not meaningful to the link editor, this
	 * permits run-time substitution of arbitrary customer revisions,
	 * although introducing the confusion of overloading the lo_minor
	 * field in the database (!)
	 */
	lop = (struct link_object *)RELPTR(dbp,
	    calloc(sizeof (struct link_object), 1));
	/* LINTED */
	tlop = (struct link_object *)&AP(dbp)[(long)lop];
	tlop->lo_major = m;
	tlop->lo_minor = n;

	/*
	 * Allocate space for the complete path name on the host program's
	 * heap -- as we have to save it from the directory buffer which
	 * might otherwise get re-used on us.  Note that this space
	 * is wasted -- we can not assume that it can be reclaimed.
	 */
	tlop->lo_next = (long)RELPTR(dbp, calloc(MAXNAMLEN, 1));

	/*
	 * Store the prototype name in the link object in the database.
	 */
	tlop->lo_name = (long)RELPTR(dbp, calloc((cplen + 1), 1));
	(void) strncpy((char *)&AP(dbp)[tlop->lo_name], cp, cplen);
	return (lop);
}

/*
 * Pull the "X" from libX, set name to X and return the
 * length of X
 */
static int
extract_name(name)
	char **name;
{
	char *ls;			/* string after LIB root */
	char *dp;			/* string before first delimiter */

	if (strncmp(*name, MSG_ORIG(MSG_FIL_LIB), MSG_FIL_LIB_SIZE) == 0) {
		ls = *name + MSG_FIL_LIB_SIZE;
		if ((dp = (char *)strchr(ls, '.')) != (char *)0) {
			*name = ls;
			return (dp - ls);
		}
	}
	return (-1);
}

/*
 * Make a pass through the data base to set the dbe_name of a dbe.  This
 * is necessary because there may be several revisions of a library
 * but only one will be chosen.
 */
static void
fix_lo(dbp)
	struct db *dbp;
{
	int i;				/* loop temporary */
	int dirlen = strlen(&AP(dbp)[dbp->db_name]);
					/* length of directory pathname */
	char *cp;			/* working temporary */
	char *tp;			/* working temporary */
	struct dbe *ep;			/* working copy of dbe */
	struct link_object *lop;	/* working copy of link_object */

	for (i = 0; i < DB_HASH; i++) {
		for (ep = &(dbp->db_hash[i]); ep && ep->dbe_lop;
		    (ep = ep->dbe_next == 0 ? NULL :
		    /* LINTED */
		    (struct dbe *)&AP(dbp)[ep->dbe_next])) {
			/* LINTED */
			lop = (struct link_object *)&AP(dbp)[ep->dbe_lop];
			tp = &AP(dbp)[lop->lo_next];
			ep->dbe_name = RELPTR(dbp,
			    calloc((dirlen + strlen(tp) + 2), 1));
			lop->lo_minor += dirlen + 1;
			cp = strncpy(&AP(dbp)[ep->dbe_name],
			    &AP(dbp)[dbp->db_name], dirlen);
			cp = strncpy(cp + dirlen, MSG_ORIG(MSG_STR_SLASH),
			    MSG_STR_SLASH_SIZE);
			(void) strcpy(cp + 1, tp);
		}
	}
}

/*
 * Allocate a new dbd, append it after dbdpp and set the dbd_dbp to dbp.
 */
static struct dbd *
new_dbd(dbdpp, dbp)
	struct dbd **dbdpp;		/* insertion point */
	struct db *dbp;			/* db associated with this dbd */
{
	struct dbd *dbdp;		/* working dbd ptr. */

	dbdp = malloc(sizeof (struct dbd));
	dbdp->dbd_db = dbp;
	dbdp->dbd_next = NULL;
	*dbdpp = dbdp;
	return (dbdp);
}

/*
 * Calculate hash index for link object.
 * This is based on X.major from libX.so.major.minor.
 */
static int
hash(np, nchrs, m)
	char *np; 			/* X of libX */
	int nchrs;			/* no of chrs. to hash on */
	int m;				/* the major version */
{
	int h;				/* for loop counter */
	char *cp;			/* working (char *) ptr */

	for (h = 0, cp = np; h < nchrs; h++, cp++)
		h = (h << 1) + *cp;
	h += (h << 1) + m;
	h = ((h & 0x7fffffff) % DB_HASH);
	return (h);
}

/*
 * Test whether the string is of digit[.digit]* format
 */
static int
rest_ok(str)
	char *str;			/* input string */
{
	int dummy;			/* integer place holder */
	int legal = 1;			/* return flag */

	while (!EMPTY(str)) {
		if (!stol(str, '.', &str, &dummy)) {
			legal = 0;
			break;
		}
		if (EMPTY(str))
			break;
		else
			/* LINTED */
			(SKIP_DOT(str));
	}
	return (legal);
}

/*
 * Compare 2 strings and test whether they are of the form digit[.digit]*.
 * It will return -1, 0, or 1 depending on whether c1p is less, equal or
 * greater than c2p
 */
static int
verscmp(const char *c1p, const char *c2p)
{
	char	*l_c1p = (char *)c1p;	/* working copy of c1p */
	char	*l_c2p = (char *)c2p;	/* working copy of c2p */
	int	l_c1p_ok = 0;		/* is c1p a legal string */
	int	c2p_dig = 0;		/* int that c1p currently */
					/*	represents */
	int	c1p_dig = 0;		/* int that c2p currently */
					/*	represents */

	while (((l_c1p_ok = stol(l_c1p, '.', &l_c1p, &c1p_dig)) == 1) &&
	    stol(l_c2p, '.', &l_c2p, &c2p_dig) && (c2p_dig == c1p_dig)) {
		if (EMPTY(l_c1p) && EMPTY(l_c2p))
			return (0);
		else if (EMPTY(l_c1p) && !EMPTY(l_c2p) &&
		    rest_ok(SKIP_DOT(l_c2p)))
			return (-1);
		else if (EMPTY(l_c2p) && !EMPTY(l_c1p) &&
		    rest_ok(SKIP_DOT(l_c1p)))
			return (1);
		l_c1p++; l_c2p++;
	};
	if (!l_c1p_ok)
		return (-1);
	else if (c1p_dig < c2p_dig)
		return (-1);
	else if ((c1p_dig > c2p_dig) && rest_ok(SKIP_DOT(l_c1p)))
		return (1);
	else return (-1);
}

/*
 * "stol" attempts to interpret a collection of characters between delimiters
 * as a decimal digit. It stops interpreting when it reaches a delimiter or
 * when character does not represent a digit. In the first case it returns
 * success and the latter failure.
 */
static int
stol(cp, delimit, ptr, i)
	char *cp;			/* ptr to input string */
	char delimit;			/* delimiter */
	char **ptr;			/* left pointing to next del. or */
					/* illegal character */
	int *i;				/* digit that the string represents */
{
	int c = 0;			/* current char */
	int n = 0;			/* working copy of i */
	int neg = 0;			/* is number negative */

	if (ptr != (char **)0)
		*ptr = cp; /* in case no number is formed */

	if (EMPTY(cp))
		return (0);

	if (!isdigit(c = *cp) && (c == '-')) {
		neg++;
		c = *++cp;
	};
	if (EMPTY(cp) || !isdigit(c))
		return (0);

	while (isdigit(c = *cp) && (*cp++ != '\0')) {
		n *= 10;
		n += c - '0';
	};
	if (ptr != (char **)0)
		*ptr = cp;

	if ((*cp == '\0') || (*cp == delimit)) {
		*i = neg ? -n : n;
		return (1);
	};
	return (0);
}
