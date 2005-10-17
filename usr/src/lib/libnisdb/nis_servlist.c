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

#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <malloc.h>
#include <strings.h>
#include "nis_servlist.h"
#include "nisdb_rw.h"

#ifdef	MEM_DEBUG
#define	XFREE		xfree
#define	XMALLOC		xmalloc
#define	XCALLOC		xcalloc
#define	XSTRDUP		xstrdup
#ifdef	__STDC__
extern void xfree(void *);
extern char *xstrdup(char *);
extern char *xmalloc(int);
extern char *xcalloc(int, int);
#else	/* __STDC__ */
extern void xfree();
extern char *xstrdup();
extern char *xmalloc();
extern char *xcalloc();
#endif	/* __STDC__ */
#else	/* MEM_DEBUG */
#define	XFREE		free
#define	XMALLOC		malloc
#define	XCALLOC		calloc
#define	XSTRDUP		strdup
#endif	/* MEM_DEBUG */

extern char	*nis_data(char *s);

/* Imported from rpc.nisd/nis_subr_proc.c */

#define	GETSERVER(o, n) (((o)->DI_data.do_servers.do_servers_val) + n)
#define	MAXSERVER(o)    (o)->DI_data.do_servers.do_servers_len

/*
 * This is a link list of all the directories served by this server.
 */
struct nis_dir_list {
	char	*name;
	struct nis_dir_list *next;
};
static struct nis_dir_list *dirlisthead = NULL;
static bool_t dir_init = FALSE;

DECLRWLOCK(dirlist);

/* this function must be protected by dirlist */
static int init_dir_list(const char *filename)
{
	FILE	*fr;
	char	buf[BUFSIZ];
	char	*name, *end;
	struct nis_dir_list *tmp;

	/* initialize only once */
	if (dir_init)
		return (1);
	dir_init = TRUE;

	fr = fopen(filename, "r");
	if (fr == NULL) {
		/* The server is just starting out */
		return (-1);
	}
	while (fgets(buf, BUFSIZ, fr)) {
		name = buf;
		while (isspace(*name))
			name++;
		end = name;
		while (!isspace(*end))
			end++;
		*end = NULL;
		tmp = XMALLOC(sizeof (struct nis_dir_list));
		if (tmp == NULL) {
			/* Should never really happen */
			fclose(fr);
			return (0);
		}
		if ((tmp->name = strdup(name)) == NULL) {
			/* Should never really happen */
			XFREE(tmp);
			fclose(fr);
			return (0);
		}
		tmp->next = dirlisthead;
		dirlisthead = tmp;
	}
	fclose(fr);
	return (1);
}

/*
 * nis_server_control() controls various aspects of server administration.
 */
int
nis_server_control(infotype, op, argp)
	enum NIS_SERVER_INFO	infotype;
	enum NIS_SERVER_OP	op;
	void			*argp;
{
	char	filename[BUFSIZ], tmpname[BUFSIZ];
	char	buf[BUFSIZ];
	FILE	*fr, *fw;
	char	*name, *end;
	int	ss;
	char	oldval;
	char    *dirs;
	int	i;
	int	ret;
	struct stat st;
	struct nis_dir_list *tmp, *prev;

	filename[0] = NULL;
	strcat(filename, nis_data("serving_list"));
	switch (infotype) {
	    case SERVING_LIST:
		/*
		 * The file "serving_list" contains one directory name per
		 * line.
		 */
		switch (op) {
		    case DIR_ADD:
			WLOCK(dirlist);
			(void) init_dir_list(filename);
			/* Check whether I already serve this directory? */
			for (tmp = dirlisthead; tmp; tmp = tmp->next)
				if (strcasecmp(tmp->name, (char *)argp) == 0) {
					WULOCK(dirlist);
					return (1);
				}
			fw = fopen(filename, "r+");
			if (fw == NULL) {
				ss = stat(filename, &st);
				if (ss == -1 && errno == ENOENT) {
					fw = fopen(filename, "a+");
				}
				if (fw == NULL) {
					syslog(LOG_ERR,
					"could not open file %s for updating",
						filename);
					WULOCK(dirlist);
					return (0);
				}
			}

			/* Add it to the incore copy */
			tmp = XMALLOC(sizeof (struct nis_dir_list));
			if (tmp == NULL) {
				/* Should never really happen */
				fclose(fw);
				WULOCK(dirlist);
				return (0);
			}
			if ((tmp->name = strdup((char *)argp)) == NULL) {
				/* Should never really happen */
				fclose(fw);
				XFREE(tmp);
				WULOCK(dirlist);
				return (0);
			}
			tmp->next = dirlisthead;
			dirlisthead = tmp;

			/* Add it to the file */
			while (fgets(buf, BUFSIZ, fw)) {
				name = buf;
				while (isspace(*name))
					name++;
				end = name;
				while (!isspace(*end))
					end++;
				*end = NULL;
				if (strcasecmp(name, (char *)argp) == 0) {
					/* already exists */
					fclose(fw);
					WULOCK(dirlist);
					return (1);
				}
			}
			fprintf(fw, "%s\n", (char *)argp);
			fclose(fw);
			WULOCK(dirlist);
			return (1);

		    case DIR_DELETE:
			WLOCK(dirlist);
			(void) init_dir_list(filename);
			prev = dirlisthead;
			for (tmp = dirlisthead; tmp; tmp = tmp->next) {
				if (strcasecmp(tmp->name, (char *)argp) == 0) {
					if (tmp == dirlisthead)
						dirlisthead = tmp->next;
					else
						prev->next = tmp->next;
					XFREE(tmp->name);
					XFREE(tmp);
					break;
				}
				prev = tmp;
			}
			if (tmp == NULL) {
				/* It wasnt found, so return success */
				WULOCK(dirlist);
				return (1);
			}

			fr = fopen(filename, "r");
			if (fr == NULL) {
				syslog(LOG_ERR,
				"could not open file %s for reading",
					filename);
				WULOCK(dirlist);
				return (0);
			}
			sprintf(tmpname, "%s.tmp", filename);
			fw = fopen(tmpname, "w");
			if (fw == NULL) {
				syslog(LOG_ERR,
				"could not open file %s for updating",
					tmpname);
				fclose(fr);
				WULOCK(dirlist);
				return (0);
			}
			while (fgets(buf, BUFSIZ, fr)) {
				name = buf;
				while (isspace(*name))
					name++;
				end = name;
				while (!isspace(*end))
					end++;
				oldval = *end;
				*end = NULL;
				if (strcasecmp(name, (char *)argp) == 0) {
					continue; /* skip this one */
				}
				*end = oldval;
				fputs(buf, fw);
			}
			fclose(fr);
			fclose(fw);
			rename(tmpname, filename);
			WULOCK(dirlist);
			return (1);

		    case DIR_INITLIST:
			WLOCK(dirlist);
			ret = init_dir_list(filename);
			WULOCK(dirlist);
			return (ret);

		    case DIR_GETLIST:
			/* don't acquire write lock unless not inited */
			if (!dir_init) {
				WLOCK(dirlist);
				(void) init_dir_list(filename);
				WULOCK(dirlist);
			}
			i = 0;
			RLOCK(dirlist);
			for (tmp = dirlisthead; tmp; tmp = tmp->next) {
				i += strlen(tmp->name) + 1;
			}
			if (i == 0)
				i = 1;
			dirs = (char *)malloc(i);
			if (dirs == NULL) {
				RULOCK(dirlist);
				return (0);
			}
			dirs[0] = '\0';
			for (tmp = dirlisthead; tmp; tmp = tmp->next) {
				if (*dirs != '\0')
					strcat(dirs, " ");
				strcat(dirs, tmp->name);
			}
			*((char **)argp) = dirs;
			RULOCK(dirlist);
			return (1);

		    case DIR_SERVED:	/* Do I serve this directory */
			/* don't acquire write lock unless not inited */
			if (!dir_init) {
				WLOCK(dirlist);
				(void) init_dir_list(filename);
				WULOCK(dirlist);
			}
			RLOCK(dirlist);
			for (tmp = dirlisthead; tmp; tmp = tmp->next)
				if (strcasecmp(tmp->name, (char *)argp) == 0) {
					RULOCK(dirlist);
					return (1);
				}
			RULOCK(dirlist);
			return (0);

		    default:
			return (0);
		}
	    default:
		return (0);
	}
}

/*
 * nis_isserving()
 *
 * This function returns state indicating whether or not we serve the
 * indicated directory.
 * 0 = we don't serve it
 * n = which server we are (1 == master)
 */
int
nis_isserving(nis_object *dobj)
{
	int			ns, i;	/* number of servers */
	nis_name		me = nis_local_host();

	if (__type_of(dobj) != NIS_DIRECTORY_OBJ)
		return (0);

	ns = MAXSERVER(dobj);
	/*
	 * POLICY : Should host names be compared in a case independent
	 *	    mode?
	 * ANSWER : Yes, to support the semantics of DNS and existing
	 *	    software which assume hostnames are case insensitive.
	 */

	if (nis_dir_cmp(me, GETSERVER(dobj, 0)->name) == SAME_NAME)
		return (1);

	/* Not master, check to see if we serve as a replica */
	for (i = 1; i < ns; i++) {
		if (nis_dir_cmp(me, GETSERVER(dobj, i)->name) == SAME_NAME)
			return (i+1);
	}
	return (0);
}
