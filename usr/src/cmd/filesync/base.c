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
 * Copyright (c) 1995 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	base.c
 *
 * purpose:
 *	routines to create, traverse, read and write the baseline database
 *
 * contents:
 *	manipulation:
 *		add_base, add_file_to_base, add_file_to_dir
 *		(static) add_file_to_list
 *	reading baseline:
 *		read_baseline
 *		(static) gettype
 *	writing baseline:
 *		write_baseline
 *		(static) bw_header, bw_base, bw_file, showtype
 */
#ident	"%W%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "filesync.h"
#include "database.h"
#include "messages.h"

#define	BASE_MAJOR	1		/* base file format major rev	*/
#define	BASE_MINOR	2		/* base file format minor rev	*/
#define	BASE_TAG	"filesync-BaseLine"

/*
 * globals
 */
struct base omnibase;			/* dummy to hold global rules	*/
struct base *bases;			/* pointer to the base list	*/

/*
 * locals
 */
static int num_bases;			/* used to generate sequence #s	*/
static errmask_t bw_header(FILE *);	/* write out baseline header	*/
static errmask_t bw_base(FILE *, struct base *); /* write out one base	*/
static errmask_t bw_file(FILE *, struct file *, int);
static struct file *add_file_to_list(struct file **, const char *);
static char showtype(int);
static long gettype(int);

/*
 * routine:
 *	add_base
 *
 * purpose:
 *	to find a base pair in the chain, adding it if necessary
 *
 * parameters:
 *	spec for source directory
 *	spec for dest directory
 *
 * returns:
 *	pointer to the base pair
 *
 */
struct base *
add_base(const char *src, const char *dst)
{	struct base *bp, **bpp;

	/* first see if we already have it */
	for (bpp = &bases; (bp = *bpp) != 0; bpp = &bp->b_next) {
		/* base must match on both src and dst	*/
		if (strcmp(src, bp->b_src_spec))
			continue;
		if (strcmp(dst, bp->b_dst_spec))
			continue;

		if (opt_debug & DBG_BASE)
			fprintf(stderr, "BASE: FOUND base=%d, src=%s, dst=%s\n",
				bp->b_ident, src, dst);
		return (bp);
	}

	/* no joy, so we have to allocate one		*/
	bp = malloc(sizeof (struct base));
	if (bp == 0)
		nomem("base structure");

	/* initialize the new base			*/
	memset((void *) bp, 0, sizeof (struct base));
	bp->b_ident = ++num_bases;
	bp->b_src_spec = strdup(src);
	bp->b_dst_spec = strdup(dst);

	/* names are expanded at run-time, and this is run-time	*/
	if ((bp->b_src_name = expand(bp->b_src_spec)) == 0) {
		fprintf(stderr, gettext(ERR_badbase), bp->b_src_spec);
		exit(ERR_FILES);
	}

	if ((bp->b_dst_name = expand(bp->b_dst_spec)) == 0) {
		fprintf(stderr, gettext(ERR_badbase), bp->b_dst_spec);
		exit(ERR_FILES);
	}

	/* chain it in					*/
	*bpp = bp;

	if (opt_debug & DBG_BASE)
		fprintf(stderr, "BASE: ADDED base=%d, src=%s, dst=%s\n",
			bp->b_ident, src, dst);

	return (bp);
}

/*
 * routine:
 *	add_file_to_list
 *
 * purpose:
 *	to find a file on a list, or if necessary add it to the list
 *
 *	this is an internal routine, used only by add_file_to_base
 *	and add_file_to_dir.
 *
 * parameters:
 *	pointer to the list head
 *
 * returns:
 *	pointer to a file structure
 *
 * notes:
 *
 *	list is sorted to provide some search optimization
 *
 *	most files are in the baseline, and so come in in alphabetical
 *	order.  If we keep a guess pointer to the last file we added/found,
 *	there is a better than even chance that this one should be
 *	added immediately onto the end of it ... and in so doing we
 * 	can save ourselves the trouble of searching the lists most
 *	of the time.
 *
 *	this win would be even better if the FTW traversal was sorted,
 *	but building the baseline is enough of a win to justify the
 *	feature ... but even without this we run a 60%-70% hit rate.
 */
static struct file *
add_file_to_list(struct file **pp, const char *name)
{	struct file *fp, *new;
	int rslt;

	static struct file **last_list;
	static struct file *last_file;

	/*
	 * start with the guess pointer, we hope to find that
	 * this request will be satisfied by the next file in
	 * the list.  The two cases we are trying to optimize
	 * are:
	 *	appending to the list, with appends in alphabetical order
	 *	searches of the list, with searches in alphabetical order
	 */
	if (last_list == pp && (new = last_file) != 0) {
		/* we like to think we belong farther down-list	*/
		if (strcmp(name, new->f_name) > 0) {
			fp = new->f_next;
			/* if we're at the end, we just won	*/
			if (fp == 0) {
				pp = &new->f_next;
				goto makeit;
			}

			/* or if the next one is what we want	*/
			if (strcmp(name, fp->f_name) == 0) {
				fp->f_flags &= ~F_NEW;
				new = fp;
				goto gotit;
			}
		}
	}

	/*
	 * our guess pointer failed, so it is exhaustive search time
	 */
	last_list = pp;

	for (fp = *pp; fp; pp = &fp->f_next, fp = *pp) {
		rslt = strcmp(name, fp->f_name);

		/* see if we got a match	*/
		if (rslt == 0) {
			fp->f_flags &= ~F_NEW;
			new = fp;
			goto gotit;
		}

		/* see if we should go no farther	*/
		if (rslt < 0)
			break;
	}

makeit:
	/*
	 * we didn't find it:
	 *	pp points at where our pointer should go
	 *	fp points at the node after ours
	 */
	new = (struct file *) malloc(sizeof (*new));
	if (new == 0)
		nomem("file structure");

	/* initialize the new node	*/
	memset((void *) new, 0, sizeof (struct file));
	new->f_name = strdup(name);
	new->f_flags = F_NEW;

	/* chain it into the list	*/
	new->f_next = fp;
	*pp = new;

gotit:	/* remember this as our next guess pointer	*/
	last_file = new;
	return (new);
}

/*
 * routine:
 *	add_file_to_base
 *
 * purpose:
 *	to add a file-node to a baseline
 *
 * parameters:
 *	pointer to base
 *	name of file to be added
 *
 * returns:
 *	pointer to file structure
 */
struct file *
add_file_to_base(struct base *bp, const char *name)
{	struct file *fp;

	fp = add_file_to_list(&bp->b_files, name);
	fp->f_base = bp;
	fp->f_depth = 0;

	if (opt_debug & DBG_LIST)
		fprintf(stderr, "LIST: base=%d, %s file=%s\n",
			bp->b_ident, (fp->f_flags&F_NEW) ? "NEW" : "FOUND",
			name);

	return (fp);
}

/*
 * routine:
 *	add_file_to_dir
 *
 * purpose:
 *	to add a file-node to a directory
 *
 * parameters:
 *	pointer to file entry for directory
 *	name of file to be added
 *
 * returns:
 *	pointer to file structure
 */
struct file *
add_file_to_dir(struct file *dp, const char *name)
{	struct file *fp;

	fp = add_file_to_list(&dp->f_files, name);
	fp->f_base = dp->f_base;
	fp->f_depth = dp->f_depth + 1;

	if (opt_debug & DBG_LIST)
		fprintf(stderr, "LIST: dir=%s, %s file=%s\n",
			dp->f_name, (fp->f_flags&F_NEW) ? "NEW" : "FOUND",
			name);

	return (fp);
}

/*
 * routine:
 *	read_baseline
 *
 * purpose:
 *	to read in the baseline file
 *
 * parameters:
 *	name of baseline file
 *
 * returns:
 *	error mask
 */
errmask_t
read_baseline(char *name)
{	FILE *file;
	errmask_t errs = 0;

	char *s;
	char *s1 = 0;
	char type;
	char *field = "???";

	unsigned long l;
	unsigned long long ll;	/* intermediate for 64 bit file support	*/
	int level;
	int major, minor;

	struct base *bp = 0;
	struct file *fp;
	struct fileinfo *ip;
	aclent_t *ap;

	struct file *dirstack[ MAX_DEPTH ];

	file = fopen(name, "r");
	if (file == NULL) {
		fprintf(stderr, gettext(ERR_open), gettext(TXT_base),
			name);
		return (ERR_FILES);
	}
	lex_linenum = 0;

	if (opt_debug & DBG_FILES)
		fprintf(stderr, "FILE: READ BASELINE %s\n", name);

	while (!feof(file)) {
		/* find the first token on the line	*/
		s = lex(file);

		/* skip blank lines and comments	*/
		if (s == 0 || *s == 0 || *s == '#' || *s == '*')
			continue;

		field = "keyword";

		/* see if the first token is a known keyword	*/
		if (strcmp(s, "VERSION") == 0 || strcmp(s, BASE_TAG) == 0) {
			s = lex(0);
			field = gettext(TXT_noargs);
			if (s == 0)
				goto bad;

			major = strtol(s, &s1, 10);
			field = gettext(TXT_badver);
			if (*s1 != '.')
				goto bad;
			minor = strtol(&s1[1], 0, 10);

			if (major != BASE_MAJOR || minor > BASE_MINOR) {
				fprintf(stderr, gettext(ERR_badver),
					major, minor, gettext(TXT_base), name);
				errs |= ERR_FILES;
			}
			s1 = 0;
			continue;
		}

		if (strcmp(s, "BASE_SRC") == 0) {
			s = lex(0);
			field = "source directory";
			if (s == 0)
				goto bad;
			s1 = strdup(s);
			bp = 0;
			continue;
		}

		if (strcmp(s, "BASE_DST") == 0) {
			s = lex(0);
			field = "destination directory";
			if (s == 0)
				goto bad;

			/* make sure we have a source too */
			if (s1 == 0) {
				field = "no source directory";
				goto bad;
			}

			bp = add_base(s1, s);
			free(s1);
			s1 = 0;
			continue;
		}

		if (strcmp(s, "FILE") == 0) {
			/* make sure we have a base to add to */
			if (bp == 0) {
				field = "missing base";
				goto bad;
			}

			s = lex(0);	/* level	*/
			field = "level";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			level = l;

			s = lex(0);	/* type	*/
			field = "file type";
			if (s == 0 || *s == 0)
				goto bad;
			type = *s;
			if (gettype(type) < 0)
				goto bad;

			s = lex(0);	/* name	*/
			field = "file name";
			if (s == 0 || *s == 0)
				goto bad;

			/* allocate a file structure for this entry	*/
			if (level == 0)
				fp = add_file_to_base(bp, s);
			else
				fp = add_file_to_dir(dirstack[level-1], s);

			fp->f_flags |= F_IN_BASELINE;

			/* maintain the directory stack			*/
			if (level >= MAX_DEPTH) {
				fprintf(stderr, gettext(ERR_deep), s);
				exit(ERR_OTHER);
			}

			dirstack[ level ] = fp;

			/* get a pointer to the baseline file info structure */
			ip = &fp->f_info[ OPT_BASE ];

			ip->f_type = gettype(type);	/* note file type */

			s = lex(0);	/* modes	*/
			field = "file modes";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			ip->f_mode = l;

			s = lex(0);	/* uid	*/
			field = "file UID";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			ip->f_uid = l;

			s = lex(0);	/* gid	*/
			field = "file GID";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			ip->f_gid = l;

			s = lex(0);	/* source inode	*/
			field = "source i#";
			if (s == 0 || *s == 0)
				goto bad;
			ll = strtoull(s, 0, 0);
			fp->f_s_inum = (ino_t) ll;

			s = lex(0);	/* source major	*/
			field = "source major";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			fp->f_s_maj = l;

			s = lex(0);	/* source minor	*/
			field = "source minor";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			fp->f_s_min = l;

			s = lex(0);	/* source nlink	*/
			field = "source nlink";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			fp->f_s_nlink = l;

			s = lex(0);	/* source mod	*/
			field = "source modtime";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			fp->f_s_modtime = l;

			s = lex(0);	/* dest inode	*/
			field = "destination i#";
			if (s == 0 || *s == 0)
				goto bad;
			ll = strtoull(s, 0, 0);
			fp->f_d_inum = (ino_t) ll;

			s = lex(0);	/* dest major	*/
			field = "destination major";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			fp->f_d_maj = l;

			s = lex(0);	/* dest minor	*/
			field = "destination minor";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			fp->f_d_min = l;

			s = lex(0);	/* dest nlink	*/
			field = "dest nlink";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			fp->f_d_nlink = l;

			s = lex(0);	/* dest mod	*/
			field = "dest modtime";
			if (s == 0 || *s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			fp->f_d_modtime = l;

			s = lex(0);	/* major or size */

			if (type == 'C' || type == 'B') {
				field = "rdev major";
				if (s == 0 || *s == 0)
					goto bad;
				l = strtoul(s, 0, 0);
				ip->f_rd_maj = l;

				s = lex(0);	/* minor */
				field = "rdev minor";
				if (s == 0 || *s == 0)
					goto bad;
				l = strtoul(s, 0, 0);
				ip->f_rd_min = l;
			} else {
				field = "file size";
				if (s == 0 || *s == 0)
					goto bad;
				ll = strtoul(s, 0, 0);
				ip->f_size = (off_t) ll;	/* size	*/
			}

			/*
			 * all fields after this point were added to the
			 * 1.0 format and so should be considered optional
			 */
			s = lex(0);		/* acl length ? */
			field = "acl count";
			if (s && *s) {
				l = strtoul(s, 0, 0);
				ip->f_numacls = l;
				ip->f_acls = (aclent_t *) malloc(ip->f_numacls *
						sizeof (aclent_t));
				if (ip->f_acls == 0)
					nomem("Access Control List");
			}

			continue;
		}

		if (strcmp(s, "ACL") == 0) {
			/* make sure there is a place to put the ACL	*/
			if (ip == 0 || ip->f_acls == 0) {
				field = "ACL w/o FILE/LIST";
				goto bad;
			}

			/* acl entry number	*/
			s = lex(0);
			field = "acl index";
			if (s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			if (l >= ip->f_numacls)
				goto bad;
			else
				ap = &ip->f_acls[l];

			/* acl entry type	*/
			s = lex(0);
			field = "acl type";
			if (s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			ap->a_type = l;

			/* acl entry ID		*/
			s = lex(0);
			field = "acl id";
			if (s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			ap->a_id = l;

			/* acl entry perms	*/
			s = lex(0);
			field = "acl perm";
			if (s == 0)
				goto bad;
			l = strtoul(s, 0, 0);
			ap->a_perm = l;

			continue;
		}

	bad:	/* log the error and continue processing to find others	*/
		fprintf(stderr, gettext(ERR_badinput), lex_linenum,
			field, name);
		errs |= ERR_FILES;
	}

	(void) fclose(file);
	return (errs);
}

/*
 * routine:
 *	write_baseline
 *
 * purpose:
 *	to rewrite the baseline file
 *
 * parameters:
 *	name of the new baseline file
 *
 * returns:
 *	error mask
 */
errmask_t
write_baseline(char *name)
{	FILE *newfile;
	errmask_t errs = 0;
	struct base *bp;
	char tmpname[ MAX_PATH ];

	if (opt_debug & DBG_FILES)
		fprintf(stderr, "FILE: WRITE BASELINE %s\n", name);

	/* if no-touch is specified, we don't update files	*/
	if (opt_notouch)
		return (0);

	/* create a temporary output file			*/
	sprintf(tmpname, "%s-TMP", name);

	/* create our output file	*/
	newfile = fopen(tmpname, "w+");
	if (newfile == NULL) {
		fprintf(stderr, gettext(ERR_creat), gettext(TXT_base),
				tmpname);
		return (ERR_FILES);
	}

	errs |= bw_header(newfile);
	for (bp = bases; bp; bp = bp->b_next)
		errs |= bw_base(newfile, bp);

	if (ferror(newfile)) {
		fprintf(stderr, gettext(ERR_write), gettext(TXT_base),
			tmpname);
		errs |= ERR_FILES;
	}

	if (fclose(newfile)) {
		fprintf(stderr, gettext(ERR_fclose), gettext(TXT_base),
			tmpname);
		errs |= ERR_FILES;
	}

	/* now switch the new file for the old one	*/
	if (errs == 0)
		if (rename(tmpname, name) != 0) {
			fprintf(stderr, gettext(ERR_rename),
				gettext(TXT_base), tmpname, name);
			errs |= ERR_FILES;
		}

	return (errs);
}

/*
 * routine:
 *	bw_header
 *
 * purpose:
 *	to write out a baseline header
 *
 * parameters:
 *	FILE* for the output file
 *
 * returns:
 *	error mask
 *
 * notes:
 */
static errmask_t
bw_header(FILE *file)
{	time_t now;
	struct tm *local;

	/* figure out what time it is	*/
	(void) time(&now);
	local = localtime(&now);

	fprintf(file, "%s %d.%d\n", BASE_TAG, BASE_MAJOR, BASE_MINOR);
	fprintf(file, "#\n");
	fprintf(file, "# filesync baseline, last written by %s, %s",
		cuserid((char *) 0), asctime(local));
	fprintf(file, "#\n");

	return (0);
}

/*
 * routine:
 *	bw_base
 *
 * purpose:
 *	to write out the summary for one base-pair
 *
 * parameters:
 *	FILE * for the output file
 *
 * returns:
 *	error mask
 *
 * notes:
 */
static errmask_t
bw_base(FILE *file, struct base *bp)
{	struct file *fp;
	errmask_t errs = 0;

	/* see if this base is to be dropped from baseline	*/
	if (bp->b_flags & F_REMOVE)
		return (0);

	fprintf(file, "\n");
	fprintf(file, "BASE_SRC %s\n", noblanks(bp->b_src_spec));
	fprintf(file, "BASE_DST %s\n", noblanks(bp->b_dst_spec));

	for (fp = bp->b_files; fp; fp = fp->f_next)
		errs |= bw_file(file, fp, 0);

	return (errs);
}

/*
 * routine:
 *	bw_file
 *
 * purpose:
 *	to write a file description out to the baseline
 *
 * parameters:
 *	output FILE
 *	pointer to file description
 *	recursion depth
 *
 * returns:
 *	error mask
 *
 * notes:
 *	some of the information we write out is kept separately
 *	for source and destination files because the values should
 *	be expected to be different for different systems/copies.
 *
 *	if a file has an unresolved conflict, we want to leave
 *	the old values in place so that we continue to compare
 *	files against the last time they agreed.
 */
static errmask_t
bw_file(FILE *file, struct file *fp, int depth)
{	struct file *cp;
	int i;
	errmask_t errs = 0;
	long long ll;		/* intermediate for 64 bit file support	*/
	struct fileinfo *ip = &fp->f_info[OPT_BASE];

	/* if this file is to be removed from baseline, skip it	*/
	if (fp->f_flags & F_REMOVE)
		return (0);

	/*
	 * if this node is in conflict, or if it has not been
	 * evaluated this time around, we should just leave the
	 * baseline file the way it was before.  If there is a
	 * conflict, let the baseline reflect the last agreement.
	 * If the node wasn't evaluated, let the baseline reflect
	 * our last knowledge.
	 */
	if (fp->f_flags & F_CONFLICT || (fp->f_flags&F_EVALUATE) == 0) {
		fp->f_info[OPT_SRC].f_ino	= fp->f_s_inum;
		fp->f_info[OPT_SRC].f_nlink	= fp->f_s_nlink;
		fp->f_info[OPT_SRC].f_d_maj	= fp->f_s_maj;
		fp->f_info[OPT_SRC].f_d_min 	= fp->f_s_min;
		fp->f_info[OPT_SRC].f_modtime	= fp->f_s_modtime;
		fp->f_info[OPT_DST].f_ino	= fp->f_d_inum;
		fp->f_info[OPT_DST].f_nlink	= fp->f_d_nlink;
		fp->f_info[OPT_DST].f_d_maj	= fp->f_d_maj;
		fp->f_info[OPT_DST].f_d_min	= fp->f_d_min;
		fp->f_info[OPT_DST].f_modtime 	= fp->f_d_modtime;
	}

	/* write out the entry for this file		*/
	fprintf(file, "FILE %d %c %-20s 0%04o", depth, showtype(ip->f_type),
		noblanks(fp->f_name), ip->f_mode);
	fprintf(file, " %6ld %6ld", ip->f_uid, ip->f_gid);

	ll = fp->f_info[OPT_SRC].f_ino;
	fprintf(file, "\t%6lld %4ld %4ld %4d 0x%08lx",
			ll,
			fp->f_info[OPT_SRC].f_d_maj,
			fp->f_info[OPT_SRC].f_d_min,
			fp->f_info[OPT_SRC].f_nlink,
			fp->f_info[OPT_SRC].f_modtime);

	ll = fp->f_info[OPT_DST].f_ino;
	fprintf(file, "\t%6lld %4ld %4ld %4d 0x%08lx",
			ll,
			fp->f_info[OPT_DST].f_d_maj,
			fp->f_info[OPT_DST].f_d_min,
			fp->f_info[OPT_DST].f_nlink,
			fp->f_info[OPT_DST].f_modtime);

	/* last fields are file type specific	*/
	if (S_ISBLK(ip->f_type) || S_ISCHR(ip->f_type))
		fprintf(file, "\t%4ld %4ld", ip->f_rd_maj, ip->f_rd_min);
	else {
		ll = ip->f_size;
		fprintf(file, "\t%lld", ll);
	}

	/* ACL count goes at the end because it was added	*/
	fprintf(file, "\t%d", ip->f_numacls);

	fprintf(file, "\n");

	/* if this file has ACLs, we have to write them out too	*/
	for (i = 0; i < ip->f_numacls; i++)
		fprintf(file, "ACL %d %d %ld %o\n", i, ip->f_acls[i].a_type,
			ip->f_acls[i].a_id, ip->f_acls[i].a_perm);

	/* then enumerate all of the children (if any)	*/
	for (cp = fp->f_files; cp; cp = cp->f_next)
		errs |= bw_file(file, cp, depth + 1);

	return (errs);
}

/*
 * routines:
 *	gettype/showtype
 *
 * purpose:
 *	to convert between a file type (as found in a mode word)
 *	and a single character representation
 *
 * parameters/return
 *	mode word -> character
 *	character -> mode word
 */
static char types[16] = "-PC?DNB?F?S?s???";

static char showtype(int mode)
{
	return (types[ (mode & S_IFMT) >> 12 ]);
}

static long gettype(int code)
{	int i;

	for (i = 0; i < 16; i++)
		if (types[i] == code)
			return (i << 12);

	return (-1);
}
