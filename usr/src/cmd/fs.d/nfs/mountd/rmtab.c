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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <errno.h>
#include <rpcsvc/mount.h>
#include <sys/pathconf.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <signal.h>
#include <locale.h>
#include <unistd.h>
#include <thread.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sharefs/share.h>
#include "../lib/sharetab.h"
#include "hashset.h"
#include "mountd.h"

static char RMTAB[] = "/etc/rmtab";
static FILE *rmtabf = NULL;

/*
 * There is nothing magic about the value selected here. Too low,
 * and mountd might spend too much time rewriting the rmtab file.
 * Too high, it won't do it frequently enough.
 */
static int rmtab_del_thresh = 250;

#define	RMTAB_TOOMANY_DELETED()	\
	((rmtab_deleted > rmtab_del_thresh) && (rmtab_deleted > rmtab_inuse))

/*
 * mountd's version of a "struct mountlist". It is the same except
 * for the added ml_pos field.
 */
struct mntentry {
	char  *m_host;
	char  *m_path;
	long   m_pos;
};

static HASHSET mntlist;

static int mntentry_equal(const void *, const void *);
static uint32_t mntentry_hash(const void *);
static int mntlist_contains(char *, char *);
static void rmtab_delete(long);
static long rmtab_insert(char *, char *);
static void rmtab_rewrite(void);
static void rmtab_parse(char *buf);
static bool_t xdr_mntlistencode(XDR * xdrs, HASHSET * mntlist);

#define	exstrdup(s) \
	strcpy(exmalloc(strlen(s)+1), s)


static int rmtab_inuse;
static int rmtab_deleted;

static rwlock_t rmtab_lock;	/* lock to protect rmtab list */


/*
 * Check whether the given client/path combination
 * already appears in the mount list.
 */

static int
mntlist_contains(char *host, char *path)
{
	struct mntentry m;

	m.m_host = host;
	m.m_path = path;

	return (h_get(mntlist, &m) != NULL);
}


/*
 *  Add an entry to the mount list.
 *  First check whether it's there already - the client
 *  may have crashed and be rebooting.
 */

static void
mntlist_insert(char *host, char *path)
{
	if (!mntlist_contains(host, path)) {
		struct mntentry *m;

		m = exmalloc(sizeof (struct mntentry));

		m->m_host = exstrdup(host);
		m->m_path = exstrdup(path);
		m->m_pos = rmtab_insert(host, path);
		(void) h_put(mntlist, m);
	}
}

void
mntlist_new(char *host, char *path)
{
	(void) rw_wrlock(&rmtab_lock);
	mntlist_insert(host, path);
	(void) rw_unlock(&rmtab_lock);
}

/*
 * Delete an entry from the mount list.
 */

void
mntlist_delete(char *host, char *path)
{
	struct mntentry *m, mm;

	mm.m_host = host;
	mm.m_path = path;

	(void) rw_wrlock(&rmtab_lock);

	if ((m = (struct mntentry *)h_get(mntlist, &mm)) != NULL) {
		rmtab_delete(m->m_pos);

		(void) h_delete(mntlist, m);

		free(m->m_path);
		free(m->m_host);
		free(m);

		if (RMTAB_TOOMANY_DELETED())
			rmtab_rewrite();
	}
	(void) rw_unlock(&rmtab_lock);
}

/*
 * Delete all entries for a host from the mount list
 */

void
mntlist_delete_all(char *host)
{
	HASHSET_ITERATOR iterator;
	struct mntentry *m;

	(void) rw_wrlock(&rmtab_lock);

	iterator = h_iterator(mntlist);

	while ((m = (struct mntentry *)h_next(iterator)) != NULL) {
		if (strcasecmp(m->m_host, host))
			continue;

		rmtab_delete(m->m_pos);

		(void) h_delete(mntlist, m);

		free(m->m_path);
		free(m->m_host);
		free(m);
	}

	if (RMTAB_TOOMANY_DELETED())
		rmtab_rewrite();

	(void) rw_unlock(&rmtab_lock);

	if (iterator != NULL)
		free(iterator);
}

/*
 * Equivalent to xdr_mountlist from librpcsvc but for HASHSET
 * rather that for a linked list. It is used only to encode data
 * from HASHSET before sending it over the wire.
 */

static bool_t
xdr_mntlistencode(XDR *xdrs, HASHSET *mntlist)
{
	HASHSET_ITERATOR iterator = h_iterator(*mntlist);

	for (;;) {
		struct mntentry *m = (struct mntentry *)h_next(iterator);
		bool_t more_data = (m != NULL);

		if (!xdr_bool(xdrs, &more_data)) {
			if (iterator != NULL)
				free(iterator);
			return (FALSE);
		}

		if (!more_data)
			break;

		if ((!xdr_name(xdrs, &m->m_host)) ||
		    (!xdr_dirpath(xdrs, &m->m_path))) {
			if (iterator != NULL)
				free(iterator);
			return (FALSE);
		}

	}

	if (iterator != NULL)
		free(iterator);

	return (TRUE);
}

void
mntlist_send(SVCXPRT *transp)
{
	(void) rw_rdlock(&rmtab_lock);

	errno = 0;
	if (!svc_sendreply(transp, xdr_mntlistencode, (char *)&mntlist))
		log_cant_reply(transp);

	(void) rw_unlock(&rmtab_lock);
}

/*
 * Compute a 32 bit hash value for an mntlist entry.
 */

/*
 * The string hashing algorithm is from the "Dragon Book" --
 * "Compilers: Principles, Tools & Techniques", by Aho, Sethi, Ullman
 *
 * And is modified for this application from usr/src/uts/common/os/modhash.c
 */

static uint_t
mntentry_str_hash(char *s, uint_t hash)
{
	uint_t	g;

	for (; *s != '\0'; s++) {
		hash = (hash << 4) + *s;
		if ((g = (hash & 0xf0000000)) != 0) {
			hash ^= (g >> 24);
			hash ^= g;
		}
	}

	return (hash);
}

static uint32_t
mntentry_hash(const void *p)
{
	struct mntentry *m = (struct mntentry *)p;
	uint_t hash;

	hash = mntentry_str_hash(m->m_host, 0);
	hash = mntentry_str_hash(m->m_path, hash);

	return (hash);
}

/*
 * Compare mntlist entries.
 * The comparison ignores a value of m_pos.
 */

static int
mntentry_equal(const void *p1, const void *p2)
{
	struct mntentry *m1 = (struct mntentry *)p1;
	struct mntentry *m2 = (struct mntentry *)p2;

	return ((strcasecmp(m1->m_host, m2->m_host) ||
	    strcmp(m1->m_path, m2->m_path)) ? 0 : 1);
}

/*
 * Rewrite /etc/rmtab with a current content of mntlist.
 */
static void
rmtab_rewrite()
{
	if (rmtabf)
		(void) fclose(rmtabf);

	/* Rewrite the file. */
	if ((rmtabf = fopen(RMTAB, "w+")) != NULL) {
		HASHSET_ITERATOR iterator;
		struct mntentry *m;

		(void) fchmod(fileno(rmtabf),
		    (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH));
		rmtab_inuse = rmtab_deleted = 0;

		iterator = h_iterator(mntlist);

		while ((m = (struct mntentry *)h_next(iterator)) != NULL)
			m->m_pos = rmtab_insert(m->m_host, m->m_path);
		if (iterator != NULL)
			free(iterator);
	}
}

/*
 * Parse the content of /etc/rmtab and insert the entries into mntlist.
 * The buffer s should be ended with a NUL char.
 */

static void
rmtab_parse(char *s)
{
	char  *host;
	char  *path;
	char  *tmp;
	struct in6_addr ipv6addr;

host_part:
	if (*s == '#')
		goto skip_rest;

	host = s;
	for (;;) {
		switch (*s++) {
		case '\0':
			return;
		case '\n':
			goto host_part;
		case ':':
			s[-1] = '\0';
			goto path_part;
		case '[':
			tmp = strchr(s, ']');
			if (tmp) {
				*tmp = '\0';
				if (inet_pton(AF_INET6, s, &ipv6addr) > 0) {
					host = s;
					s = ++tmp;
				} else
					*tmp = ']';
			}
		default:
			continue;
		}
	}

path_part:
	path = s;
	for (;;) {
		switch (*s++) {
		case '\n':
			s[-1] = '\0';
			if (*host && *path)
				mntlist_insert(host, path);
			goto host_part;
		case '\0':
			if (*host && *path)
				mntlist_insert(host, path);
			return;
		default:
			continue;
		}
	}

skip_rest:
	for (;;) {
		switch (*++s) {
		case '\n':
			goto host_part;
		case '\0':
			return;
		default:
			continue;
		}
	}
}

/*
 * Read in contents of rmtab.
 * Call rmtab_parse to parse the file and store entries in mntlist.
 * Rewrites the file to get rid of unused entries.
 */

#define	RMTAB_LOADLEN	(16*2024)	/* Max bytes to read at a time */

void
rmtab_load()
{
	FILE *fp;

	(void) rwlock_init(&rmtab_lock, USYNC_THREAD, NULL);

	/*
	 * Don't need to lock the list at this point
	 * because there's only a single thread running.
	 */
	mntlist = h_create(mntentry_hash, mntentry_equal, 101, 0.75);

	if ((fp = fopen(RMTAB, "r")) != NULL) {
		char buf[RMTAB_LOADLEN+1];
		size_t len;

		/*
		 * Read at most RMTAB_LOADLEN bytes from /etc/rmtab.
		 * - if fread returns RMTAB_LOADLEN we can be in the middle
		 *   of a line so change the last newline character into NUL
		 *   and seek back to the next character after newline.
		 * - otherwise set NUL behind the last character read.
		 */
		while ((len = fread(buf, 1, RMTAB_LOADLEN, fp)) > 0) {
			if (len == RMTAB_LOADLEN) {
				int i;

				for (i = 1; i < len; i++) {
					if (buf[len-i] == '\n') {
						buf[len-i] = '\0';
						(void) fseek(fp, -i + 1,
						    SEEK_CUR);
						goto parse;
					}
				}
			}

			/* Put a NUL character at the end of buffer */
			buf[len] = '\0';
	parse:
			rmtab_parse(buf);
		}
		(void) fclose(fp);
	}
	rmtab_rewrite();
}

/*
 * Write an entry at the current location in rmtab
 * for the given client and path.
 *
 * Returns the starting position of the entry
 * or -1 if there was an error.
 */

long
rmtab_insert(char *host, char *path)
{
	long   pos;
	struct in6_addr ipv6addr;

	if (rmtabf == NULL || fseek(rmtabf, 0L, 2) == -1) {
		return (-1);
	}
	pos = ftell(rmtabf);

	/*
	 * Check if host is an IPv6 literal
	 */

	if (inet_pton(AF_INET6, host, &ipv6addr) > 0) {
		if (fprintf(rmtabf, "[%s]:%s\n", host, path) == EOF) {
			return (-1);
		}
	} else {
		if (fprintf(rmtabf, "%s:%s\n", host, path) == EOF) {
			return (-1);
		}
	}
	if (fflush(rmtabf) == EOF) {
		return (-1);
	}
	rmtab_inuse++;
	return (pos);
}

/*
 * Mark as unused the rmtab entry at the given offset in the file.
 */

void
rmtab_delete(long pos)
{
	if (rmtabf != NULL && pos != -1 && fseek(rmtabf, pos, 0) == 0) {
		(void) fprintf(rmtabf, "#");
		(void) fflush(rmtabf);

		rmtab_inuse--;
		rmtab_deleted++;
	}
}
