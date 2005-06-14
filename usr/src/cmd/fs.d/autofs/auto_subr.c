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
 * Copyright (c) 1988-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <thread.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/signal.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/tiuser.h>
#include <sys/utsname.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>
#include <assert.h>
#include "automount.h"

static char *check_hier(char *);
static int natisa(char *, size_t);

struct mntlist *current_mounts;

static bool_t nodirect_map = FALSE;

void
dirinit(char *mntpnt, char *map, char *opts, int direct, char **stack,
	char ***stkptr)
{
	struct autodir *dir;
	char *p;

	if (strcmp(map, "-null") == 0) {
		if (strcmp(mntpnt, "/-") == 0)
			nodirect_map = TRUE;
		goto enter;
	}

	p = mntpnt + (strlen(mntpnt) - 1);
	if (*p == '/')
		*p = '\0';	/* trim trailing / */
	if (*mntpnt != '/') {
		pr_msg("dir %s must start with '/'", mntpnt);
		return;
	}
	if (p = check_hier(mntpnt)) {
		pr_msg("hierarchical mountpoint: %s and %s",
			p, mntpnt);
		return;
	}

	/*
	 * If it's a direct map then call dirinit
	 * for every map entry.
	 */
	if ((strcmp(mntpnt, "/-") == 0) && !(nodirect_map)) {
		(void) loaddirect_map(map, map, opts, stack, stkptr);
		return;
	}

enter:
	dir = (struct autodir *)malloc(sizeof (*dir));
	if (dir == NULL)
		goto alloc_failed;
	dir->dir_name = strdup(mntpnt);
	if (dir->dir_name == NULL)
		goto alloc_failed;
	dir->dir_map = strdup(map);
	if (dir->dir_map == NULL)
		goto alloc_failed;
	dir->dir_opts = strdup(opts);
	if (dir->dir_opts == NULL)
		goto alloc_failed;
	dir->dir_direct = direct;
	dir->dir_remount = 0;
	dir->dir_next = NULL;

	/*
	 * Append to dir chain
	 */
	if (dir_head == NULL)
		dir_head = dir;
	else
		dir_tail->dir_next = dir;

	dir->dir_prev = dir_tail;
	dir_tail = dir;

	return;

alloc_failed:
	if (dir != NULL) {
		if (dir->dir_opts)
			free(dir->dir_opts);
		if (dir->dir_map)
			free(dir->dir_map);
		if (dir->dir_name)
			free(dir->dir_name);
		free(dir);
	}
	pr_msg("dirinit: memory allocation failed");
}

/*
 *  Check whether the mount point is a
 *  subdirectory or a parent directory
 *  of any previously mounted automount
 *  mount point.
 */
static char *
check_hier(mntpnt)
	char *mntpnt;
{
	register struct autodir *dir;
	register char *p, *q;

	for (dir = dir_head; dir; dir = dir->dir_next) {
		p = dir->dir_name;
		q = mntpnt;
		for (; *p == *q; p++, q++)
			if (*p == '\0')
				break;
		if (*p == '/' && *q == '\0')
			return (dir->dir_name);
		if (*p == '\0' && *q == '/')
			return (dir->dir_name);
		if (*p == '\0' && *q == '\0')
			return (NULL);
	}
	return (NULL);	/* it's not a subdir or parent */
}

/*
 * Gets the next token from the string "p" and copies
 * it into "w".  Both "wq" and "w" are quote vectors
 * for "w" and "p".  Delim is the character to be used
 * as a delimiter for the scan.  A space means "whitespace".
 * The call to getword must provide buffers w and wq of size at
 * least wordsz. getword() will pass strings of maximum length
 * (wordsz-1), since it needs to null terminate the string.
 * Returns 0 on ok and -1 on error.
 */
int
getword(char *w, char *wq, char **p, char **pq, char delim, int wordsz)
{
	char *tmp = w;
	char *tmpq = wq;
	int count = wordsz;

	if (wordsz <= 0) {
		if (verbose)
			syslog(LOG_ERR,
			"getword: input word size %d must be > 0", wordsz);
		return (-1);
	}

	while ((delim == ' ' ? isspace(**p) : **p == delim) && **pq == ' ')
		(*p)++, (*pq)++;

	while (**p &&
		!((delim == ' ' ? isspace(**p) : **p == delim) &&
			**pq == ' ')) {
		if (--count <= 0) {
			*tmp = '\0';
			*tmpq = '\0';
			syslog(LOG_ERR,
			"maximum word length (%d) exceeded", wordsz);
			return (-1);
		}
		*w++  = *(*p)++;
		*wq++ = *(*pq)++;
	}
	*w  = '\0';
	*wq = '\0';

	return (0);
}

/*
 * get_line attempts to get a line from the map, upto LINESZ. A line in
 * the map is a concatenation of lines if the continuation symbol '\'
 * is used at the end of the line. Returns line on success, a NULL on
 * EOF, and an empty string on lines > linesz.
 */
char *
get_line(FILE *fp, char *map, char *line, int linesz)
{
	register char *p = line;
	register int len;
	int excess = 0;

	*p = '\0';

	for (;;) {
		if (fgets(p, linesz - (p-line), fp) == NULL) {
			return (*line ? line : NULL);	/* EOF */
		}

		len = strlen(line);
		if (len <= 0) {
			p = line;
			continue;
		}
		p = &line[len - 1];

		/*
		 * Is input line too long?
		 */
		if (*p != '\n') {
			excess = 1;
			/*
			 * Perhaps last char read was '\'. Reinsert it
			 * into the stream to ease the parsing when we
			 * read the rest of the line to discard.
			 */
			(void) ungetc(*p, fp);
			break;
		}
trim:
		/* trim trailing white space */
		while (p >= line && isspace(*(uchar_t *)p))
			*p-- = '\0';
		if (p < line) {			/* empty line */
			p = line;
			continue;
		}

		if (*p == '\\') {		/* continuation */
			*p = '\0';
			continue;
		}

		/*
		 * Ignore comments. Comments start with '#'
		 * which must be preceded by a whitespace, unless
		 * if '#' is the first character in the line.
		 */
		p = line;
		while (p = strchr(p, '#')) {
			if (p == line || isspace(*(p-1))) {
				*p-- = '\0';
				goto trim;
			}
			p++;
		}
		break;
	}
	if (excess) {
		int c;

		/*
		 * discard rest of line and return an empty string.
		 * done to set the stream to the correct place when
		 * we are done with this line.
		 */
		while ((c = getc(fp)) != EOF) {
			*p = c;
			if (*p == '\n')		/* end of the long line */
				break;
			else if (*p == '\\') {		/* continuation */
				if (getc(fp) == EOF)	/* ignore next char */
					break;
			}
		}
		syslog(LOG_ERR,
			"map %s: line too long (max %d chars)",
			map, linesz-1);
		*line = '\0';
	}

	return (line);
}

/*
 * Gets the retry=n entry from opts.
 * Returns 0 if retry=n is not present in option string,
 * retry=n is invalid, or when option string is NULL.
 */
int
get_retry(char *opts)
{
	int retry = 0;
	char buf[MAXOPTSLEN];
	char *p, *pb, *lasts;

	if (opts == NULL)
		return (retry);

	(void) strcpy(buf, opts);
	pb = buf;
	while (p = (char *)strtok_r(pb, ",", &lasts)) {
		pb = NULL;
		if (strncmp(p, "retry=", 6) == 0)
			retry = atoi(p+6);
	}
	return (retry > 0 ? retry : 0);
}

/*
 * Returns zero if "opt" is found in mnt->mnt_opts, setting
 * *sval to whatever follows the equal sign after "opt".
 * str_opt allocates a string long enough to store the value of
 * "opt" plus a terminating null character and returns it as *sval.
 * It is the responsability of the caller to deallocate *sval.
 * *sval will be equal to NULL upon return if either "opt=" is not found,
 * or "opt=" has no value associated with it.
 *
 * stropt will return -1 on error.
 */
int
str_opt(struct mnttab *mnt, char *opt, char **sval)
{
	char *str, *comma;

	/*
	 * is "opt" in the options field?
	 */
	if (str = hasmntopt(mnt, opt)) {
		str += strlen(opt);
		if (*str++ != '=' ||
		    (*str == ',' || *str == '\0')) {
			syslog(LOG_ERR, "Bad option field");
			return (-1);
		}
		comma = strchr(str, ',');
		if (comma != NULL)
			*comma = '\0';
		*sval = strdup(str);
		if (comma != NULL)
			*comma = ',';
		if (*sval == NULL)
			return (-1);
	} else
		*sval = NULL;

	return (0);
}

/*
 * Performs text expansions in the string "pline".
 * "plineq" is the quote vector for "pline".
 * An identifier prefixed by "$" is replaced by the
 * corresponding environment variable string.  A "&"
 * is replaced by the key string for the map entry.
 *
 * This routine will return an error (non-zero) if *size* would be
 * exceeded after expansion, indicating that the macro_expand failed.
 * This is to prevent writing past the end of pline and plineq.
 * Both pline and plineq are left untouched in such error case.
 */
int
macro_expand(key, pline, plineq, size)
	char *key, *pline, *plineq;
	int size;
{
	register char *p,  *q;
	register char *bp, *bq;
	register char *s;
	char buffp[LINESZ], buffq[LINESZ];
	char namebuf[64], *pn;
	int expand = 0;
	struct utsname name;
	char isaname[64];

	p = pline;  q = plineq;
	bp = buffp; bq = buffq;

	while (*p) {
		if (*p == '&' && *q == ' ') {	/* insert key */
			/*
			 * make sure we don't overflow buffer
			 */
			if ((int)((bp - buffp) + strlen(key)) < size) {
				for (s = key; *s; s++) {
					*bp++ = *s;
					*bq++ = ' ';
				}
				expand++;
				p++; q++;
				continue;
			} else {
				/*
				 * line too long...
				 */
				return (1);
			}
		}

		if (*p == '$' && *q == ' ') {	/* insert env var */
			p++; q++;
			pn = namebuf;
			if (*p == '{') {
				p++; q++;
				while (*p && *p != '}') {
					*pn++ = *p++;
					q++;
				}
				if (*p) {
					p++; q++;
				}
			} else {
				while (*p && (*p == '_' || isalnum(*p))) {
					*pn++ = *p++;
					q++;
				}
			}
			*pn = '\0';

			s = getenv(namebuf);
			if (!s) {
				/* not found in env */
				if (strcmp(namebuf, "HOST") == 0) {
					(void) uname(&name);
					s = name.nodename;
				} else if (strcmp(namebuf, "OSREL") == 0) {
					(void) uname(&name);
					s = name.release;
				} else if (strcmp(namebuf, "OSNAME") == 0) {
					(void) uname(&name);
					s = name.sysname;
				} else if (strcmp(namebuf, "OSVERS") == 0) {
					(void) uname(&name);
					s = name.version;
				} else if (strcmp(namebuf, "NATISA") == 0) {
					if (natisa(isaname, sizeof (isaname)))
						s = isaname;
				}
			}

			if (s) {
				if ((int)((bp - buffp) + strlen(s)) < size) {
					while (*s) {
						*bp++ = *s++;
						*bq++ = ' ';
					}
				} else {
					/*
					 * line too long...
					 */
					return (1);
				}
			}
			expand++;
			continue;
		}
		/*
		 * Since buffp needs to be null terminated, we need to
		 * check that there's still room in the buffer to
		 * place at least two more characters, *p and the
		 * terminating null.
		 */
		if (bp - buffp == size - 1) {
			/*
			 * There was not enough room for at least two more
			 * characters, return with an error.
			 */
			return (1);
		}
		/*
		 * The total number of characters so far better be less
		 * than the size of buffer passed in.
		 */
		*bp++ = *p++;
		*bq++ = *q++;

	}
	if (!expand)
		return (0);
	*bp = '\0';
	*bq = '\0';
	/*
	 * We know buffp/buffq will fit in pline/plineq since we
	 * processed at most size characters.
	 */
	(void) strcpy(pline, buffp);
	(void) strcpy(plineq, buffq);

	return (0);
}

/*
 * Removes quotes from the string "str" and returns
 * the quoting information in "qbuf". e.g.
 * original str: 'the "quick brown" f\ox'
 * unquoted str: 'the quick brown fox'
 * and the qbuf: '    ^^^^^^^^^^^  ^ '
 */
void
unquote(str, qbuf)
	char *str, *qbuf;
{
	register int escaped, inquote, quoted;
	register char *ip, *bp, *qp;
	char buf[LINESZ];

	escaped = inquote = quoted = 0;

	for (ip = str, bp = buf, qp = qbuf; *ip; ip++) {
		if (!escaped) {
			if (*ip == '\\') {
				escaped = 1;
				quoted++;
				continue;
			} else
			if (*ip == '"') {
				inquote = !inquote;
				quoted++;
				continue;
			}
		}

		*bp++ = *ip;
		*qp++ = (inquote || escaped) ? '^' : ' ';
		escaped = 0;
	}
	*bp = '\0';
	*qp = '\0';
	if (quoted)
		(void) strcpy(str, buf);
}

/*
 * Removes trailing spaces from string "s".
 */
void
trim(s)
	char *s;
{
	char *p = &s[strlen(s) - 1];

	while (p >= s && isspace(*(uchar_t *)p))
		*p-- = '\0';
}

/*
 * try to allocate memory using malloc, if malloc fails, then flush the
 * rddir caches, and retry. If the second allocation after the readdir
 * caches have been flushed fails too, then return NULL to indicate
 * memory could not be allocated.
 */
char *
auto_rddir_malloc(unsigned nbytes)
{
	char *p;
	int again = 0;

	if ((p = malloc(nbytes)) == NULL) {
		/*
		 * No memory, free rddir caches and try again
		 */
		mutex_lock(&cleanup_lock);
		cond_signal(&cleanup_start_cv);
		if (cond_wait(&cleanup_done_cv, &cleanup_lock)) {
			mutex_unlock(&cleanup_lock);
			syslog(LOG_ERR, "auto_rddir_malloc interrupted\n");
		} else {
			mutex_unlock(&cleanup_lock);
			again = 1;
		}
	}

	if (again)
		p = malloc(nbytes);

	return (p);
}

/*
 * try to strdup a string, if it fails, then flush the rddir caches,
 * and retry. If the second strdup fails, return NULL to indicate failure.
 */
char *
auto_rddir_strdup(const char *s1)
{
	char *s2;
	int again = 0;

	if ((s2 = strdup(s1)) == NULL) {
		/*
		 * No memory, free rddir caches and try again
		 */
		mutex_lock(&cleanup_lock);
		cond_signal(&cleanup_start_cv);
		if (cond_wait(&cleanup_done_cv, &cleanup_lock)) {
			mutex_unlock(&cleanup_lock);
			syslog(LOG_ERR, "auto_rddir_strdup interrupted\n");
		} else {
			mutex_unlock(&cleanup_lock);
			again = 1;
		}
	}

	if (again)
		s2 = strdup(s1);

	return (s2);
}

/*
 * Returns a pointer to the entry corresponding to 'name' if found,
 * otherwise it returns NULL.
 */
struct dir_entry *
btree_lookup(struct dir_entry *head, char *name)
{
	register struct dir_entry *p;
	register int direction;

	for (p = head; p != NULL; ) {
		direction = strcmp(name, p->name);
		if (direction == 0)
			return (p);
		if (direction > 0)
			p = p->right;
		else p = p->left;
	}
	return (NULL);
}

/*
 * Add entry to binary tree
 * Duplicate entries are not added
 */
void
btree_enter(struct dir_entry **head, struct dir_entry *ent)
{
	register struct dir_entry *p, *prev = NULL;
	register int direction;

	ent->right = ent->left = NULL;
	if (*head == NULL) {
		*head = ent;
		return;
	}

	for (p = *head; p != NULL; ) {
		prev = p;
		direction = strcmp(ent->name, p->name);
		if (direction == 0) {
			/*
			 * entry already in btree
			 */
			return;
		}
		if (direction > 0)
			p = p->right;
		else p = p->left;
	}
	assert(prev != NULL);
	if (direction > 0)
		prev->right = ent;
	else prev->left = ent;
}

/*
 * If entry doesn't exist already, add it to the linear list
 * after '*last' and to the binary tree list.
 * If '*last == NULL' then the list is walked till the end.
 * *last is always set to the new element after successful completion.
 * if entry already exists '*last' is only updated if not previously
 * provided.
 */
int
add_dir_entry(char *name, struct dir_entry **list, struct dir_entry **last)
{
	struct dir_entry *e, *l;

	if ((*list != NULL) && (*last == NULL)) {
		/*
		 * walk the list to find last element
		 */
		for (l = *list; l != NULL; l = l->next)
			*last = l;
	}

	if (btree_lookup(*list, name) == NULL) {
		/*
		 * not a duplicate, add it to list
		 */
		/* LINTED pointer alignment */
		e = (struct dir_entry *)
			auto_rddir_malloc(sizeof (struct dir_entry));
		if (e == NULL)
			return (ENOMEM);
		(void) memset((char *)e, 0, sizeof (*e));
		e->name = auto_rddir_strdup(name);
		if (e->name == NULL) {
			free(e);
			return (ENOMEM);
		}
		e->next = NULL;
		if (*list == NULL) {
			/*
			 * list is empty
			 */
			*list = *last = e;
		} else {
			/*
			 * append to end of list
			 */
			assert(*last != NULL);
			(*last)->next = e;
			*last = e;
		}
		/*
		 * add to binary tree
		 */
		btree_enter(list, e);
	}
	return (0);
}

/*
 * Print trace output.
 * Like fprintf(stderr, fmt, ...) except that if "id" is nonzero, the output
 * is preceeded by the ID of the calling thread.
 */
#define	FMT_BUFSIZ 1024

void
trace_prt(int id, char *fmt, ...)
{
	va_list args;

	char buf[FMT_BUFSIZ];

	if (id) {
		(void) sprintf(buf, "t%u\t%s", thr_self(), fmt);
		fmt = buf;
	}
	va_start(args, fmt);
	(void) vfprintf(stderr, fmt, args);
	va_end(args);
}

/*
 * Extract the isalist(5) for userland from the kernel.
 */
static char *
isalist(void)
{
	char *buf;
	size_t bufsize = BUFSIZ;	/* wild guess */
	long ret;

	buf = malloc(bufsize);
	do {
		ret = sysinfo(SI_ISALIST, buf, bufsize);
		if (ret == -1l)
			return (NULL);
		if (ret > bufsize) {
			bufsize = ret;
			buf = realloc(buf, bufsize);
		} else
			break;
	} while (buf != NULL);

	return (buf);
}

/*
 * Classify isa's as to bitness of the corresponding ABIs.
 * isa's which have no "official" system ABI are returned
 * unrecognised i.e. zero bits.
 */
static int
bitness(char *isaname)
{
	if (strcmp(isaname, "sparc") == 0 ||
	    strcmp(isaname, "i386") == 0)
		return (32);

	if (strcmp(isaname, "sparcv9") == 0)
		return (64);

	return (0);
}

/*
 * Find the left-most element in the isalist that matches our idea of a
 * system ABI.
 *
 * On machines with only one ABI, this is usually the same as uname -p.
 */
static int
natisa(char *buf, size_t bufsize)
{
	int bits;
	char *isa, *list;
	char *lasts;

	if ((list = isalist()) == NULL)
		return (0);

	for (isa = strtok_r(list, " ", &lasts);
	    isa; isa = strtok_r(0, " ", &lasts))
		if ((bits = bitness(isa)) != 0)
			break;	/* ignore "extension" architectures */

	if (isa == 0 || bits == 0) {
		free(list);
		return (0);	/* can't figure it out :( */
	}

	(void) strncpy(buf, isa, bufsize);
	free(list);

	return (1);
}
