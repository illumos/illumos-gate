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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <search.h>

#include <dirent.h>
#include <fnmatch.h>
#include <sys/stat.h>

#include "rules.h"

extern char *mstrdup(const char *);

/*
 * The do_base_dir() function is called when a BASE command is encountered
 * in the input directives or end-of-file is reach on the input directive
 * file. This function causes the commands associated with the previous
 * BASE command to be executed. for example,
 *
 *	BASE a/b/c
 *	LIST ...
 *	IGNORE ...
 *	BASE d/e/f (this command will cause do_base_dir() to be called for
 *		   base directory a/b/c)
 *
 * Input arguments:
 *	dirpath - the BASE directory being operated on
 *	incld_lst - A list of strings to be matched obtained from the
 *		    LIST commands associated with the BASE directory.
 *	excld_lst - A list of strings to be matched obtained from the
 *		    IGNORE commands associated with the BASE directory.
 *	func	- A function to be called for each matched file. The
 *		  functions allow files to be  packed, unpacked,
 *		  examined and filenames printed.
 */

void
do_base_dir(char *dirpath, struct item *incld_lst, struct item *excld_lst,
    int (*func)(char *, char *, DIR *, int))
{
	struct item *iitem;
	int err;
	int files_processed = 0;
	struct item symlk_hd, *symlk, *symlk_sv;
	struct stat64 statbuf;
	char linkbuf[MAXPATHLEN];
	int sz;
	char *s;
	char *mk_base_dir(char *, char *);

#ifdef DEBUG
	prtitem("Global IGNOREs", &gign_hd);
	prtitem("LIST cmds", &list_hd);
	prtitem("Local IGNOREs", &lign_hd);
#endif /* DEBUG */


	symlk = &symlk_hd;
	symlk_hd.i_next = (struct item *)0;

	iitem  = incld_lst->i_next;
	if (iitem == (struct item *)0)
		return;
	while (iitem != (struct item *)0) {
#ifdef DEBUG
		printf("do_base_dir: iitem->i_str = %s  iitem->i_flag = %x\n",
		    iitem->i_str, iitem->i_flag);
		fflush(stdout);
#endif /* DEBUG */
		err = do_list_item(dirpath, iitem->i_str,
		    iitem->i_flag, excld_lst, 0, &symlk, func);
		if (err == 0) {
			fprintf(stderr,
			    gettext("cachefspack: basedir = %s"),
			    dirpath);
			fprintf(stderr,
			    gettext("    %s - no file(s) selected\n"),
			    iitem->i_str);
		}
		iitem = iitem->i_next;
	};
	/*
	 * Invoke 'func' for each component of the BASE
	 * directory.
	 */
	func_dir_path(dirpath, func);

	if (lstat64(dirpath, &statbuf) < 0) {
		perror(gettext("Can't stat base directory"));
	} else {
		if (S_ISLNK(statbuf.st_mode)) {
			sz = readlink(dirpath, linkbuf, MAXPATHLEN-1);
			if (sz > 0) {
				linkbuf[sz] = '\0';
				s = mk_base_dir(dirpath, linkbuf);
				if (s != (char *)0) {
					func_dir_path(s, func);
				}
			}
		}
	}

#ifdef DEBUG
	prtitem("Symbolic Links", &symlk_hd);
#endif /* DEBUG */
	iitem = symlk_hd.i_next;
	if (iitem == (struct item *)0)
		return;
	while (iitem != (struct item *)0) {
#ifdef DEBUG
		printf("do_bas sl: iitem->i_str = %s  iitem->i_flag = %x\n",
		    iitem->i_str, iitem->i_flag);
		fflush(stdout);
#endif /* DEBUG */
		files_processed = do_list_item(iitem->i_str, "*",
		    (LF_SYMLINK | LF_REGEX), excld_lst, 0, &symlk, func);
		if (files_processed) {
			/*
			 * Invoke 'func' for each component of the BASE
			 * directory.
			 */
			func_dir_path(iitem->i_str, func);
		}
		symlk_sv = iitem;
		iitem = iitem->i_next;
		symlk_hd.i_next = iitem;
		free(symlk_sv);
#ifdef DEBUG
		prtitem("Symbolic Links loop", &symlk_hd);
#endif /* DEBUG */
	}
}

/*
 * The do_list_item() function is called for each LIST item associated with
 * a BASE directory. It does the work of descending directories and matching
 * filenames.
 *
 * Input arguments:
 *	dirpath - the BASE directory being operated on
 *	pat - The argument from the LIST command to match
 *	flags - Flags which affect how patterns are matched:
 *		LF_STRIP_DOTSLASH - means strip off "." and/or "/" at the
 *				    beginning of the pattern to match.
 *		LF_REGEX - Means match the pattern as a regular expression.
 *			   Otherwise, an exact match of characters is required.
 *	excld_lst - A list of strings to be matched obtained from the
 *		    IGNORE commands associated with the BASE directory.
 *	func - A function to be called for each matched file. The
 *		functions allow files to be  packed, unpacked,
 *		examined and filenames printed.
 *
 * Return values:
 *	0 -  'func' NOT invoked for any file
 *	1 -  'func' invoked for at least 1 file
 */
int
do_list_item(char *dirpath, char *pat, int flags, struct item *excld_lst,
    DIR *pdir, struct item **symlk_lst, int (*func)(char *, char *, DIR *, int))
{
	static char statnam[MAXPATHLEN];
	static int glastpos = 0;
	static int basedir_lastpos;
	static int depth = 0;
	static int unwind = 0;
	static int do_dir = 0;
	static int sl_cnt;
	static int retval;
	static char linkbuf[MAXPATHLEN];
	DIR *dir, *parent_dir;
	struct dirent64 *dirent;
	int match;
	int err;
	struct stat64 statbuf;
	int llastpos;
	struct item *eitem;
	int excld_flag;
	char *p;
	int diropn;
	int len;
	int sz;
	void process_symlk();

	strcpy(&statnam[glastpos], dirpath);
	len = strlen(statnam) - 1;
	if (statnam[len] != '/') {
		strcat(statnam, "/");
	}
	parent_dir = pdir;
	llastpos = glastpos;
	glastpos = strlen(statnam);
	if (depth == 0) {
		basedir_lastpos = glastpos;
		sl_cnt = slash_cnt(pat);
		retval = 0;
	}
	depth++;

	diropn = 0;
	dir = opendir(statnam);
	if (dir == NULL) {
		fprintf(stderr, gettext("\ncachefspack: %s - "), statnam);
		perror(gettext("Can't open directory"));
		goto out;
	}
	diropn = 1;

	while (1) {
		dirent = readdir64(dir);
		if (dirent == NULL) { /* EOF */
			if ((depth-1) > do_dir) {
				do_dir = depth - 1;
			}
			break;
		}
		/*
		 * If file is '..' skip it
		 */
		if (strcmp(dirent->d_name, "..") == 0) {
			continue;
		}
		/*
		 * Apply excludes if this is not a LISTed directory
		 * NOTE: names from IGNORE commands are matched against the
		 *	 component name(a name between '/' marks), not the
		 *	 whole pathname.
		 */
		if (flags & LF_SYMLINK) {
			match = ((depth-1) >= sl_cnt);
		} else {
			match = ((depth-1) > sl_cnt);
		}
		if (match) {
			eitem = excld_lst->i_next;
			excld_flag = 0;
			while (eitem != (struct item *)0) {
				match = gmatch(dirent->d_name, eitem->i_str);
				if (match == 1) {
					excld_flag = 1;
					break;
				}
				eitem = eitem->i_next;
			}
			if (excld_flag == 1) {
				continue;
			}
		}
		strcpy(&statnam[glastpos], dirent->d_name);
		err = lstat64(statnam, &statbuf);
		if (err < 0) {
			fprintf(stderr,
			    gettext("cachefspack: %s - stat failed"),
			    statnam);
			perror(gettext(" "));
			continue;
		}
		p = pat;
		if (flags & LF_STRIP_DOTSLASH) {
			if (strncmp(p, "./", 2) == 0) {
				p += 2;
			}
		}
		if (S_ISDIR(statbuf.st_mode)) {
#ifdef DEBUG
			printf("directory:  &statnam[basedir_lastpos] = %s\n",
			&statnam[basedir_lastpos]);
			printf("statbuf.st_mode = %o\n", statbuf.st_mode);
			printf("depth = %d sl_cnt = %d\n", depth, sl_cnt);
			fflush(stdout);
#endif /* DEBUG */
			if ((depth-1) == sl_cnt) {
				if (flags & LF_REGEX) {
					match =
					    gmatch(&statnam[basedir_lastpos],
					    p);
				} else {
					match =
					    (strcmp(&statnam[basedir_lastpos],
					    p) == 0);
				}
				if (match) {
					/*
					 * Don't descend '.' directory
					 * but match it
					 */
					if (strcmp(dirent->d_name, ".") != 0) {
						do_list_item(dirent->d_name,
						    "*", flags, excld_lst,
						    dir, symlk_lst, func);
					} else {
						if ((depth-1) > do_dir) {
							do_dir = depth - 1;
						}
						(void) func(statnam,
						    dirent->d_name,
						    dir, depth);
					}
					retval = 1;
					if (unwind = discont_srch(flags, p)) {
						goto out;
					}
				}
				continue;
			}
			/*
			 * Don't descend '.' directory
			 */
			if (strcmp(dirent->d_name, ".") != 0) {
				do_list_item(dirent->d_name, p, flags,
				    excld_lst, dir, symlk_lst, func);
			}
			if (unwind) {
				goto out;
			}
			continue;
		}
		if (S_ISLNK(statbuf.st_mode)) {
			if (flags & LF_SYMLINK)
			    continue;
#ifdef DEBUG
			printf("sym link : &statnam[basedir_lastpos] = %s\n",
			&statnam[basedir_lastpos]);
			printf("statbuf.st_mode = %o\n", statbuf.st_mode);
			printf("statnam = %s\n", statnam);
#endif /* DEBUG */
			/*
			 * Symbolic link was explicitly specified or matches a
			 * regular expression in a LIST item. Thus we follow
			 * the link. Otherwise, just call 'func' for the link
			 * name.
			 */
#ifdef DEBUG
			printf("depth = %d  sl_cnt = %d\n", depth, sl_cnt);
			fflush(stdout);
#endif /* DEBUG */
			if ((depth-1) == sl_cnt) {
				if (flags & LF_REGEX) {
					match =
					    gmatch(&statnam[basedir_lastpos],
					    p);
				} else {
					match =
					    (strcmp(&statnam[basedir_lastpos],
					    p) == 0);
				}
#ifdef DEBUG
				printf("match = %d\n", match);
				fflush(stdout);
#endif /* DEBUG */
				if (match) {
					if ((depth-1) > do_dir) {
						do_dir = depth - 1;
					}
					retval = 1;
					(void) func(statnam, dirent->d_name,
					    dir, depth);
					sz = readlink(
					    statnam, linkbuf, MAXPATHLEN-1);
#ifdef DEBUG
					printf("linkbuf = %s\n", linkbuf);
					printf("sz = %d\n", sz);
					fflush(stdout);
#endif /* DEBUG */
					if (sz < 0) {
						continue;
					}
					linkbuf[sz] = '\0';
					process_symlk(linkbuf, statnam,
					    glastpos, symlk_lst, func);
					if (unwind = discont_srch(flags, p)) {
						goto out;
					}
				}
			}
			if ((depth-1) > sl_cnt) {
				if ((depth-1) > do_dir) {
					do_dir = depth - 1;
				}
				retval = 1;
				(void) func(statnam, dirent->d_name, dir,
				    depth);
				sz = readlink(statnam, linkbuf, MAXPATHLEN-1);
#ifdef DEBUG
				printf("linkbuf = %s\n", linkbuf);
				printf("sz = %d\n", sz);
				fflush(stdout);
#endif /* DEBUG */
				if (sz < 0) {
					continue;
				}
				linkbuf[sz] = '\0';
				process_symlk(linkbuf, statnam, glastpos,
				    symlk_lst, func);
				if (unwind = discont_srch(flags, p)) {
					goto out;
				}
			}
			continue;
		}
		/*
		 * File must be a regular file -
		 * Does it match the specified pattern?
		 */
#ifdef DEBUG
		printf("reg file : &statnam[basedir_lastpos] = %s  p = %s\n",
			&statnam[basedir_lastpos], p);
		printf("statbuf.st_mode = %o\n", statbuf.st_mode);
		fflush(stdout);
#endif /* DEBUG */
		if (flags & LF_REGEX) {
			match = gmatch(&statnam[basedir_lastpos], p);
		} else {
			match = (strcmp(&statnam[basedir_lastpos], p) == 0);
		}
		if (!match) {
			continue;
		}
		if ((depth - 1) > do_dir) {
			do_dir = depth - 1;
		}
		retval = 1;
		(void) func(statnam, dirent->d_name, dir, depth);
		/*
		 * If the file is an executable, check to see if shared
		 * libraries need to be packed.
		 */
		if (statbuf.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
			process_executable(statnam, func);
		}

		if (unwind = discont_srch(flags, p)) {
			goto out;
		}
	}
out:
	depth--;
	if (depth == 0) {
		unwind = 0;
	}
	statnam[glastpos] = '\0';
	if (do_dir) {
		do_dir--;
#ifdef DEBUG
		printf("out:  call func\n");
		fflush(stdout);
		printf("out: statnam = %s\n", statnam);
		fflush(stdout);
		printf("out: &statnam[llastpos] = %s\n", &statnam[llastpos]);
		fflush(stdout);
#endif /* DEBUG */
		if (func(statnam, &statnam[llastpos], parent_dir, depth) < 0) {
			do_dir = 0;
		}
	}
	glastpos = llastpos;
	if (diropn)
	    closedir(dir);
	return (retval);
}

/*
 * Count all the '/' characters in the string except for those
 * in the first character position and last character position
 * of the string.
 */
int
slash_cnt(char *str)
{
	char *p = str;
	int len;
	int i;
	int count = 0;

#ifdef DEBUG
	printf("slash_cnt: str = %s", str);
#endif /* DEBUG */
	/*
	 * NOTE //a, /a and ./a are the same
	 */
	if (*p == '.')
	    p++;
	while (*p == '/')
	    p++;
	len = strlen(str) - 1;
	for (i = 0; i < len; i++) {
		if (*p == '/') {
			count++;
			i--;
			while (*p == '/') {
				p++;
				i++;
			}
		} else {
			p++;
		}
	}
#ifdef DEBUG
	printf("  count = %d\n", count);
	fflush(stdout);
#endif /* DEBUG */
	return (count);
}

/*
 * For each directory in the path name, call 'func'.
 */
int
func_dir_path(char *path, int (*func)(char *, char *, DIR *, int))
{
	char *dnam;
	char *fnam;
	char *pathtmp;
	DIR *dir;
	char *get_fname(char *);
	char *get_dirname(char *);
	ENTRY hitem, *hitemp;

#ifdef DEBUG
	printf("func_dir_path: path = %s\n", path);
	fflush(stdout);
#endif /* DEBUG */
	fnam = path;
	dnam = path;
	pathtmp = mstrdup(path);
	while (fnam != NULL) {

		fnam = get_fname(dnam);
		dnam = get_dirname(dnam);
		if (fnam != (char *)0) {
			if (strcmp(fnam, "..") == 0) {
				free(pathtmp);
				pathtmp = mstrdup(dnam);
				continue;
			}
		}
#ifdef DEBUG
		if (fnam != (char *)0) {
			printf("func_dir_path: fnam = %s\n", fnam);
		}
		printf("func_dir_path: dnam = %s  pathtmp = %s\n",
		    dnam,  pathtmp);
		fflush(stdout);
#endif /* DEBUG */

		hitem.key = mstrdup(pathtmp);
		hitem.data = 0;
		hitemp = hsearch(hitem, FIND);
		if (hitemp != NULL) {
			/*
			 * If hash item data is 0, item has not been packed.
			 * If hash item data is 1, item has been packed.
			 */
#ifdef DEBUG
			printf("func_dir_path: key = %s hitemp->data = %x\n",
			    hitemp->key, hitemp->data);
			fflush(stdout);
#endif /* DEBUG */
			if (hitemp->data == (char *)1)
			    break;
			hitemp->data = (char *)1;
		} else {
			hitem.key = mstrdup(pathtmp);
			hitem.data = (char *)1;
			if (hsearch(hitem, ENTER) == NULL) {
				fprintf(stderr,
				    gettext("cachefspack: hash table full\n"));
			}
		}

		dir = opendir(dnam);
		if (dir != NULL) {
			if (func(pathtmp, fnam, dir, 0) < 0) {
#ifdef DEBUG
				printf("func_dir_path: errno = %d\n", errno);
				fflush(stdout);
#endif /* DEBUG */
				closedir(dir);
				return (-1);
			}
			closedir(dir);
		} else {
			printf(gettext("cachefspack:  error opening dir -"));
			printf("%s\n", dnam);
			fflush(stdout);
		}

		free(pathtmp);
		pathtmp = mstrdup(dnam);
	}
	free(pathtmp);
	return (0);
}
void
process_symlk(char *lkpath, char *relpath, int rel_lastpos,
    struct item **symlk, int (*func)(char *, char *, DIR *, int))
{
	struct stat64 lstatbuf;
	char *l;
	struct item *add_item(struct item *, char *, int);
	int len;

	/*
	 * if the link has a relative pathname, append the name to
	 * current path.
	 */
	if (*lkpath != '/') {
		len = strlen(lkpath);
		if ((len + rel_lastpos + 2) > MAXPATHLEN) {
			fprintf(stderr, gettext("can't process sym link - %s"),
			    lkpath);
			return;
		}
		strcpy(&relpath[rel_lastpos], lkpath);
		l = relpath;
	} else {
		l = lkpath;
	}
#ifdef DEBUG
	printf("process_symlk: lkpath = %s\n", lkpath);
	printf("process_symlk: l = %s\n", l);
	printf("lstatbuf.st_mode = %o\n", lstatbuf.st_mode);
	fflush(stdout);
#endif /* DEBUG */
	if (lstat64(l, &lstatbuf) < 0) {
		fprintf(stderr, gettext("Can't lstat sym link - %s"), l);
		perror(" ");
		return;
	}
	if (S_ISDIR(lstatbuf.st_mode)) {
		*symlk = add_item(*symlk, l, 0);
	}
	if (S_ISREG(lstatbuf.st_mode)) {
		func_dir_path(l, func);
	}
}

int
discont_srch(int flags, char *pat)
{
	char *wild;

#ifdef DEBUG
	printf("discont_srch: flags = %x  pat = %s\n", flags, pat);
	fflush(stdout);
#endif /* DEBUG */

	/*
	 * if patterns are NOT being matched as regular expressions
	 * we can have at most 1 match. We got it so quit.
	 */
	if ((flags & LF_REGEX) != LF_REGEX) {
#ifdef DEBUG
		printf("discont_srch: ! LF_REGEX\n");
		fflush(stdout);
#endif /* DEBUG */
		return (1);
	}
	/*
	 * if the pattern does not contain wildcard characters and
	 * we have found a match we are done.
	 */
	if (WILDCARD(wild, pat) == NULL) {
#ifdef DEBUG
		printf("discont_srch: wild = %x\n", wild);
		fflush(stdout);
#endif /* DEBUG */
		return (1);
	}
	return (0);
}

#ifdef DEBUG
prtitem(char *str, struct item *hd)
{
	struct item *p = hd->i_next;

	printf("\n%s\n\n", str);
	while (p != (struct item *)0) {
		printf("str = %s\n", p->i_str);
		p = p->i_next;
	}
}
#endif /* DEBUG */
