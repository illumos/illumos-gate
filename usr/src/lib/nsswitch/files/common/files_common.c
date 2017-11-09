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
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2017, Joyent, Inc.
 */

/*
 * Common code and structures used by name-service-switch "files" backends.
 */

/*
 * An implementation that used mmap() sensibly would be a wonderful thing,
 *   but this here is just yer standard fgets() thang.
 */

#include "files_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

/*ARGSUSED*/
nss_status_t
_nss_files_setent(be, dummy)
	files_backend_ptr_t	be;
	void			*dummy;
{
	if (be->f == 0) {
		if (be->filename == 0) {
			/* Backend isn't initialized properly? */
			return (NSS_UNAVAIL);
		}
		if ((be->f = fopen(be->filename, "rF")) == 0) {
			return (NSS_UNAVAIL);
		}
	} else {
		rewind(be->f);
	}
	return (NSS_SUCCESS);
}

/*ARGSUSED*/
nss_status_t
_nss_files_endent(be, dummy)
	files_backend_ptr_t	be;
	void			*dummy;
{
	if (be->f != 0) {
		(void) fclose(be->f);
		be->f = 0;
	}
	if (be->buf != 0) {
		free(be->buf);
		be->buf = 0;
	}
	return (NSS_SUCCESS);
}

/*
 * This routine reads a line, including the processing of continuation
 * characters.  It always leaves (or inserts) \n\0 at the end of the line.
 * It returns the length of the line read, excluding the \n\0.  Who's idea
 * was this?
 * Returns -1 on EOF.
 *
 * Note that since each concurrent call to _nss_files_read_line has
 * it's own FILE pointer, we can use getc_unlocked w/o difficulties,
 * a substantial performance win.
 */
int
_nss_files_read_line(f, buffer, buflen)
	FILE			*f;
	char			*buffer;
	int			buflen;
{
	int			linelen;	/* 1st unused slot in buffer */
	int			c;

	/*CONSTCOND*/
	while (1) {
		linelen = 0;
		while (linelen < buflen - 1) {	/* "- 1" saves room for \n\0 */
			switch (c = getc_unlocked(f)) {
			case EOF:
				if (linelen == 0 ||
				    buffer[linelen - 1] == '\\') {
					return (-1);
				} else {
					buffer[linelen    ] = '\n';
					buffer[linelen + 1] = '\0';
					return (linelen);
				}
			case '\n':
				if (linelen > 0 &&
				    buffer[linelen - 1] == '\\') {
					--linelen;  /* remove the '\\' */
				} else {
					buffer[linelen    ] = '\n';
					buffer[linelen + 1] = '\0';
					return (linelen);
				}
				break;
			default:
				buffer[linelen++] = c;
			}
		}
		/* Buffer overflow -- eat rest of line and loop again */
		/* ===> Should syslog() */
		do {
			c = getc_unlocked(f);
			if (c == EOF) {
				return (-1);
			}
		} while (c != '\n');
	}
	/*NOTREACHED*/
}

/*
 * used only for getgroupbymem() now.
 */
nss_status_t
_nss_files_do_all(be, args, filter, func)
	files_backend_ptr_t	be;
	void			*args;
	const char		*filter;
	files_do_all_func_t	func;
{
	long			grlen;
	char			*buffer;
	int			buflen;
	nss_status_t		res;

	if (be->buf == 0) {
		if ((grlen = sysconf(_SC_GETGR_R_SIZE_MAX)) > 0)
			be->minbuf = grlen;
		if ((be->buf = malloc(be->minbuf)) == 0)
			return (NSS_UNAVAIL);
	}
	buffer = be->buf;
	buflen = be->minbuf;

	if ((res = _nss_files_setent(be, 0)) != NSS_SUCCESS) {
		return (res);
	}

	res = NSS_NOTFOUND;

	do {
		int		linelen;

		if ((linelen = _nss_files_read_line(be->f, buffer,
		    buflen)) < 0) {
			/* End of file */
			break;
		}
		if (filter != 0 && strstr(buffer, filter) == 0) {
			/*
			 * Optimization:  if the entry doesn't contain the
			 *   filter string then it can't be the entry we want,
			 *   so don't bother looking more closely at it.
			 */
			continue;
		}
		res = (*func)(buffer, linelen, args);

	} while (res == NSS_NOTFOUND);

	(void) _nss_files_endent(be, 0);
	return (res);
}

/*
 * Could implement this as an iterator function on top of _nss_files_do_all(),
 *   but the shared code is small enough that it'd be pretty silly.
 */
nss_status_t
_nss_files_XY_all(be, args, netdb, filter, check)
	files_backend_ptr_t	be;
	nss_XbyY_args_t		*args;
	int			netdb;		/* whether it uses netdb */
						/* format or not */
	const char		*filter;	/* advisory, to speed up */
						/* string search */
	files_XY_check_func	check;	/* NULL means one-shot, for getXXent */
{
	char			*r;
	nss_status_t		res;
	int	parsestat;
	int (*func)();

	if (filter != NULL && *filter == '\0')
		return (NSS_NOTFOUND);
	if (be->buf == 0 || (be->minbuf < args->buf.buflen)) {
		if (be->minbuf < args->buf.buflen) {
			if (be->buf == 0) {
				be->minbuf = args->buf.buflen;
			} else if (
			    (r = realloc(be->buf, args->buf.buflen)) != NULL) {
				be->buf = r;
				be->minbuf = args->buf.buflen;
			}
		}
		if (be->buf == 0 &&
			(be->buf = malloc(be->minbuf)) == 0)
				return (NSS_UNAVAIL);
	}

	if (check != 0 || be->f == 0) {
		if ((res = _nss_files_setent(be, 0)) != NSS_SUCCESS) {
			return (res);
		}
	}

	res = NSS_NOTFOUND;

	/*CONSTCOND*/
	while (1) {
		char		*instr	= be->buf;
		int		linelen;

		if ((linelen = _nss_files_read_line(be->f, instr,
		    be->minbuf)) < 0) {
			/* End of file */
			args->returnval = 0;
			args->returnlen = 0;
			break;
		}
		if (filter != 0 && strstr(instr, filter) == 0) {
			/*
			 * Optimization:  if the entry doesn't contain the
			 *   filter string then it can't be the entry we want,
			 *   so don't bother looking more closely at it.
			 */
			continue;
		}
		if (netdb) {
			char		*first;
			char		*last;

			if ((last = strchr(instr, '#')) == 0) {
				last = instr + linelen;
			}
			*last-- = '\0';		/* Nuke '\n' or #comment */

			/*
			 * Skip leading whitespace.  Normally there isn't
			 *   any, so it's not worth calling strspn().
			 */
			for (first = instr;  isspace(*first);  first++) {
				;
			}
			if (*first == '\0') {
				continue;
			}
			/*
			 * Found something non-blank on the line.  Skip back
			 * over any trailing whitespace;  since we know
			 * there's non-whitespace earlier in the line,
			 * checking for termination is easy.
			 */
			while (isspace(*last)) {
				--last;
			}

			linelen = last - first + 1;
			if (first != instr) {
					instr = first;
			}
		}

		args->returnval = 0;
		args->returnlen = 0;

		if (check != NULL && (*check)(args, instr, linelen) == 0)
			continue;

		parsestat = NSS_STR_PARSE_SUCCESS;
		if (be->filename != NULL) {
			/*
			 * Special case for passwd and group wherein we
			 * replace uids/gids > MAXUID by ID_NOBODY
			 * because files backend does not support
			 * ephemeral ids.
			 */
			if (strcmp(be->filename, PF_PATH) == 0)
				parsestat = validate_passwd_ids(instr,
				    &linelen, be->minbuf, 2);
			else if (strcmp(be->filename, GF_PATH) == 0)
				parsestat = validate_group_ids(instr,
				    &linelen, be->minbuf, 2, check);
		}

		if (parsestat == NSS_STR_PARSE_SUCCESS) {
			func = args->str2ent;
			parsestat = (*func)(instr, linelen, args->buf.result,
			    args->buf.buffer, args->buf.buflen);
		}

		if (parsestat == NSS_STR_PARSE_SUCCESS) {
			args->returnval = (args->buf.result != NULL)?
					args->buf.result : args->buf.buffer;
			args->returnlen = linelen;
			res = NSS_SUCCESS;
			break;
		} else if (parsestat == NSS_STR_PARSE_ERANGE) {
			args->erange = 1;
			break;
		} /* else if (parsestat == NSS_STR_PARSE_PARSE) don't care ! */
	}

	/*
	 * stayopen is set to 0 by default in order to close the opened
	 * file.  Some applications may break if it is set to 1.
	 */
	if (check != 0 && !args->stayopen) {
		(void) _nss_files_endent(be, 0);
	}

	return (res);
}

/*
 * File hashing support.  Critical for sites with large (e.g. 1000+ lines)
 * /etc/passwd or /etc/group files.  Currently only used by getpw*() and
 * getgr*() routines, but any files backend can use this stuff.
 */
static void
_nss_files_hash_destroy(files_hash_t *fhp)
{
	free(fhp->fh_table);
	fhp->fh_table = NULL;
	free(fhp->fh_line);
	fhp->fh_line = NULL;
	free(fhp->fh_file_start);
	fhp->fh_file_start = NULL;
}
#ifdef PIC
/*
 * It turns out the hashing stuff really needs to be disabled for processes
 * other than the nscd; the consumption of swap space and memory is otherwise
 * unacceptable when the nscd is killed w/ a large passwd file (4M) active.
 * See 4031930 for details.
 * So we just use this psuedo function to enable the hashing feature.  Since
 * this function name is private, we just create a function w/ the name
 *  __nss_use_files_hash in the nscd itself and everyone else uses the old
 * interface.
 * We also disable hashing for .a executables to avoid problems with large
 * files....
 */

#pragma weak __nss_use_files_hash

extern void  __nss_use_files_hash(void);
#endif /* pic */

/*ARGSUSED*/
nss_status_t
_nss_files_XY_hash(files_backend_ptr_t be, nss_XbyY_args_t *args,
	int netdb, files_hash_t *fhp, int hashop, files_XY_check_func check)
{
	/* LINTED E_FUNC_VAR_UNUSED */
	int fd, retries, ht, stat;
	/* LINTED E_FUNC_VAR_UNUSED */
	uint_t hash, line, f;
	/* LINTED E_FUNC_VAR_UNUSED */
	files_hashent_t *hp, *htab;
	/* LINTED E_FUNC_VAR_UNUSED */
	char *cp, *first, *last;
	/* LINTED E_FUNC_VAR_UNUSED */
	nss_XbyY_args_t xargs;
	/* LINTED E_FUNC_VAR_UNUSED */
	struct stat64 st;

#ifndef PIC
	return (_nss_files_XY_all(be, args, netdb, 0, check));
}
#else
	if (__nss_use_files_hash == 0)
		return (_nss_files_XY_all(be, args, netdb, 0, check));

	mutex_lock(&fhp->fh_lock);
retry:
	retries = 100;
	while (stat64(be->filename, &st) < 0) {
		/*
		 * This can happen only in two cases: Either the file is
		 * completely missing and we were not able to read it yet
		 * (fh_table is NULL), or there is some brief period when the
		 * file is being modified/renamed.  Keep trying until things
		 * settle down, but eventually give up.
		 */
		if (fhp->fh_table == NULL || --retries == 0)
			goto unavail;
		poll(0, 0, 100);
	}

	if (st.st_mtim.tv_sec == fhp->fh_mtime.tv_sec &&
	    st.st_mtim.tv_nsec == fhp->fh_mtime.tv_nsec &&
	    fhp->fh_table != NULL) {
		htab = &fhp->fh_table[hashop * fhp->fh_size];
		hash = fhp->fh_hash_func[hashop](args, 1, NULL, 0);
		for (hp = htab[hash % fhp->fh_size].h_first; hp != NULL;
		    hp = hp->h_next) {
			if (hp->h_hash != hash)
				continue;
			line = hp - htab;
			if ((*check)(args, fhp->fh_line[line].l_start,
					fhp->fh_line[line].l_len) == 0)
				continue;

			if (be->filename != NULL) {
				stat = NSS_STR_PARSE_SUCCESS;
				if (strcmp(be->filename, PF_PATH) == 0)
					stat = validate_passwd_ids(
					    fhp->fh_line[line].l_start,
					    &fhp->fh_line[line].l_len,
					    fhp->fh_line[line].l_len + 1,
					    1);
				else if (strcmp(be->filename, GF_PATH) == 0)
					stat = validate_group_ids(
					    fhp->fh_line[line].l_start,
					    &fhp->fh_line[line].l_len,
					    fhp->fh_line[line].l_len + 1,
					    1, check);
				if (stat != NSS_STR_PARSE_SUCCESS) {
					if (stat == NSS_STR_PARSE_ERANGE)
						args->erange = 1;
					continue;
				}
			}

			if ((*args->str2ent)(fhp->fh_line[line].l_start,
			    fhp->fh_line[line].l_len, args->buf.result,
			    args->buf.buffer, args->buf.buflen) ==
			    NSS_STR_PARSE_SUCCESS) {
				args->returnval = (args->buf.result)?
					args->buf.result:args->buf.buffer;
				args->returnlen = fhp->fh_line[line].l_len;
				mutex_unlock(&fhp->fh_lock);
				return (NSS_SUCCESS);
			} else {
				args->erange = 1;
			}
		}
		args->returnval = 0;
		args->returnlen = 0;
		mutex_unlock(&fhp->fh_lock);
		return (NSS_NOTFOUND);
	}

	_nss_files_hash_destroy(fhp);

	if (st.st_size > SSIZE_MAX)
		goto unavail;

	if ((fhp->fh_file_start = malloc((ssize_t)st.st_size + 1)) == NULL)
		goto unavail;

	if ((fd = open(be->filename, O_RDONLY)) < 0)
		goto unavail;

	if (read(fd, fhp->fh_file_start, (ssize_t)st.st_size) !=
	    (ssize_t)st.st_size) {
		close(fd);
		goto retry;
	}

	close(fd);

	fhp->fh_file_end = fhp->fh_file_start + (off_t)st.st_size;
	*fhp->fh_file_end = '\n';
	fhp->fh_mtime = st.st_mtim;

	/*
	 * If the file changed since we read it, or if it's less than
	 * 1-2 seconds old, don't trust it; its modification may still
	 * be in progress.  The latter is a heuristic hack to minimize
	 * the likelihood of damage if someone modifies /etc/mumble
	 * directly (as opposed to editing and renaming a temp file).
	 *
	 * Note: the cast to u_int is there in case (1) someone rdated
	 * the system backwards since the last modification of /etc/mumble
	 * or (2) this is a diskless client whose time is badly out of sync
	 * with its server.  The 1-2 second age hack doesn't cover these
	 * cases -- oh well.
	 */
	if (stat64(be->filename, &st) < 0 ||
	    st.st_mtim.tv_sec != fhp->fh_mtime.tv_sec ||
	    st.st_mtim.tv_nsec != fhp->fh_mtime.tv_nsec ||
	    (uint_t)(time(0) - st.st_mtim.tv_sec + 2) < 4) {
		poll(0, 0, 1000);
		goto retry;
	}

	line = 1;
	for (cp = fhp->fh_file_start; cp < fhp->fh_file_end; cp++)
		if (*cp == '\n')
			line++;

	for (f = 2; f * f <= line; f++) {	/* find next largest prime */
		if (line % f == 0) {
			f = 1;
			line++;
		}
	}

	fhp->fh_size = line;
	fhp->fh_line = malloc(line * sizeof (files_linetab_t));
	fhp->fh_table = calloc(line * fhp->fh_nhtab, sizeof (files_hashent_t));
	if (fhp->fh_line == NULL || fhp->fh_table == NULL)
		goto unavail;

	line = 0;
	cp = fhp->fh_file_start;
	while (cp < fhp->fh_file_end) {
		first = cp;
		while (*cp != '\n')
			cp++;
		if (cp > first && *(cp - 1) == '\\') {
			memmove(first + 2, first, cp - first - 1);
			cp = first + 2;
			continue;
		}
		last = cp;
		*cp++ = '\0';
		if (netdb) {
			if ((last = strchr(first, '#')) == 0)
				last = cp - 1;
			*last-- = '\0';		/* nuke '\n' or #comment */
			while (isspace(*first))	/* nuke leading whitespace */
				first++;
			if (*first == '\0')	/* skip content-free lines */
				continue;
			while (isspace(*last))	/* nuke trailing whitespace */
				--last;
			*++last = '\0';
		}
		for (ht = 0; ht < fhp->fh_nhtab; ht++) {
			hp = &fhp->fh_table[ht * fhp->fh_size + line];
			hp->h_hash = fhp->fh_hash_func[ht](&xargs, 0, first,
					last - first);
		}
		fhp->fh_line[line].l_start = first;
		fhp->fh_line[line++].l_len = last - first;
	}

	/*
	 * Populate the hash tables in reverse order so that the hash chains
	 * end up in forward order.  This ensures that hashed lookups find
	 * things in the same order that a linear search of the file would.
	 * This is essential in cases where there could be multiple matches.
	 * For example: until 2.7, root and smtp both had uid 0; but we
	 * certainly wouldn't want getpwuid(0) to return smtp.
	 */
	for (ht = 0; ht < fhp->fh_nhtab; ht++) {
		htab = &fhp->fh_table[ht * fhp->fh_size];
		for (hp = &htab[line - 1]; hp >= htab; hp--) {
			uint_t bucket = hp->h_hash % fhp->fh_size;
			hp->h_next = htab[bucket].h_first;
			htab[bucket].h_first = hp;
		}
	}

	goto retry;

unavail:
	_nss_files_hash_destroy(fhp);
	mutex_unlock(&fhp->fh_lock);
	return (NSS_UNAVAIL);
}
#endif /* PIC */

nss_status_t
_nss_files_getent_rigid(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*args = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_all(be, args, 0, 0, 0));
}

nss_status_t
_nss_files_getent_netdb(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*args = (nss_XbyY_args_t *)a;

	return (_nss_files_XY_all(be, args, 1, 0, 0));
}

/*ARGSUSED*/
nss_status_t
_nss_files_destr(be, dummy)
	files_backend_ptr_t	be;
	void			*dummy;
{
	if (be != 0) {
		if (be->f != 0) {
			(void) _nss_files_endent(be, 0);
		}
		if (be->hashinfo != NULL) {
			(void) mutex_lock(&be->hashinfo->fh_lock);
			if (--be->hashinfo->fh_refcnt == 0)
				_nss_files_hash_destroy(be->hashinfo);
			(void) mutex_unlock(&be->hashinfo->fh_lock);
		}
		free(be);
	}
	return (NSS_SUCCESS);	/* In case anyone is dumb enough to check */
}

nss_backend_t *
_nss_files_constr(ops, n_ops, filename, min_bufsize, fhp)
	files_backend_op_t	ops[];
	int			n_ops;
	const char		*filename;
	int			min_bufsize;
	files_hash_t		*fhp;
{
	files_backend_ptr_t	be;

	if ((be = (files_backend_ptr_t)malloc(sizeof (*be))) == 0) {
		return (0);
	}
	be->ops		= ops;
	be->n_ops	= n_ops;
	be->filename	= filename;
	be->minbuf	= min_bufsize;
	be->f		= 0;
	be->buf		= 0;
	be->hashinfo	= fhp;

	if (fhp != NULL) {
		(void) mutex_lock(&fhp->fh_lock);
		fhp->fh_refcnt++;
		(void) mutex_unlock(&fhp->fh_lock);
	}

	return ((nss_backend_t *)be);
}

int
_nss_files_check_name_colon(nss_XbyY_args_t *argp, const char *line,
	int linelen)
{
	const char	*linep, *limit;
	const char	*keyp = argp->key.name;

	linep = line;
	limit = line + linelen;
	while (*keyp && linep < limit && *keyp == *linep) {
		keyp++;
		linep++;
	}
	return (linep < limit && *keyp == '\0' && *linep == ':');
}

/*
 * This routine is used to parse lines of the form:
 * 	name number aliases
 * It returns 1 if the key in argp matches any one of the
 * names in the line, otherwise 0
 * Used by rpc, networks, protocols
 */
int
_nss_files_check_name_aliases(nss_XbyY_args_t *argp, const char *line,
	int linelen)
{
	const char	*limit, *linep, *keyp;

	linep = line;
	limit = line + linelen;
	keyp = argp->key.name;

	/* compare name */
	while (*keyp && linep < limit && !isspace(*linep) && *keyp == *linep) {
		keyp++;
		linep++;
	}
	if (*keyp == '\0' && linep < limit && isspace(*linep))
		return (1);
	/* skip remainder of the name, if any */
	while (linep < limit && !isspace(*linep))
		linep++;
	/* skip the delimiting spaces */
	while (linep < limit && isspace(*linep))
		linep++;
	/* compare with the aliases */
	while (linep < limit) {
		/*
		 * 1st pass: skip number
		 * Other passes: skip remainder of the alias name, if any
		 */
		while (linep < limit && !isspace(*linep))
			linep++;
		/* skip the delimiting spaces */
		while (linep < limit && isspace(*linep))
			linep++;
		/* compare with the alias name */
		keyp = argp->key.name;
		while (*keyp && linep < limit && !isspace(*linep) &&
		    *keyp == *linep) {
			keyp++;
			linep++;
		}
		if (*keyp == '\0' && (linep == limit || isspace(*linep)))
			return (1);
	}
	return (0);
}

/*
 * A few NSS modules hold onto data for the duration of their module. In this
 * case, when that module goes away, we must free that data. This is a place
 * that allows for modules to register items to take care of.
 */
#pragma fini(_nss_files_fini)
static void
_nss_files_fini(void)
{
	getexecattr_fini();
}
