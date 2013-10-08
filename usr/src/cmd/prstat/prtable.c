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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2009 Chad Mynhier
 */

#include <procfs.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <ctype.h>
#include <string.h>
#include <libintl.h>
#include <errno.h>
#include <zone.h>
#include <libzonecfg.h>
#include <wchar.h>

#include "prstat.h"
#include "prutil.h"
#include "prtable.h"

static plwp_t	*plwp_tbl[PLWP_TBL_SZ];

void
lwpid_init()
{
	(void) memset(&plwp_tbl, 0, sizeof (plwp_t *) * PLWP_TBL_SZ);
}

static uid_t
pwd_getid(char *name)
{
	struct passwd *pwd;

	if ((pwd = getpwnam(name)) == NULL)
		Die(gettext("invalid user name: %s\n"), name);
	return (pwd->pw_uid);
}

void
pwd_getname(uid_t uid, char *name, size_t length, int noresolve,
    int trunc, size_t width)
{
	struct passwd *pwd;
	size_t n;

	if (noresolve || (pwd = getpwuid(uid)) == NULL) {
		n = snprintf(NULL, 0, "%u", uid);
		if (trunc && n > width)
			(void) snprintf(name, length, "%.*u%c",
			    width - 1, uid, '*');
		else
			(void) snprintf(name, length, "%u", uid);
	} else {
		n = mbstowcs(NULL, pwd->pw_name, 0);
		if (n == (size_t)-1)
			(void) snprintf(name, length, "%s", "ERROR");
		else if (trunc && n > width)
			(void) snprintf(name, length, "%.*s%c",
			    width - 1, pwd->pw_name, '*');
		else
			(void) snprintf(name, length, "%s", pwd->pw_name);
	}
}

void
add_uid(uidtbl_t *tbl, char *name)
{
	uid_t *uid;

	if (tbl->n_size == tbl->n_nent) {	/* reallocation */
		if ((tbl->n_size *= 2) == 0)
			tbl->n_size = 4;	/* first time */
		tbl->n_list = Realloc(tbl->n_list, tbl->n_size*sizeof (uid_t));
	}

	uid = &tbl->n_list[tbl->n_nent++];

	if (isdigit(name[0])) {
		*uid = Atoi(name);
	} else {
		*uid = pwd_getid(name);
	}
}

int
has_uid(uidtbl_t *tbl, uid_t uid)
{
	size_t i;

	if (tbl->n_nent) {	/* do linear search if table is not empty */
		for (i = 0; i < tbl->n_nent; i++)
			if (tbl->n_list[i] == uid)
				return (1);
	} else {
		return (1);	/* if table is empty return true */
	}

	return (0);		/* nothing has been found */
}

void
add_element(table_t *table, long element)
{
	if (table->t_size == table->t_nent) {
		if ((table->t_size *= 2) == 0)
			table->t_size = 4;
		table->t_list = Realloc(table->t_list,
		    table->t_size * sizeof (long));
	}
	table->t_list[table->t_nent++] = element;
}

int
has_element(table_t *table, long element)
{
	size_t i;

	if (table->t_nent) {	/* do linear search if table is not empty */
		for (i = 0; i < table->t_nent; i++)
			if (table->t_list[i] == element)
				return (1);
	} else {		/* if table is empty then */
		return (1);	/* pretend that element was found */
	}

	return (0);	/* element was not found */
}

int
foreach_element(table_t *table, void *buf, void (*walker)(long, void *))
{
	size_t i;

	if (table->t_nent) {
		for (i = 0; i < table->t_nent; i++)
			walker(table->t_list[i], buf);
	} else {
		return (0);
	}
	return (1);
}

void
add_zone(zonetbl_t *tbl, char *str)
{
	zonename_t *entp;
	zoneid_t id;
	char *cp;

	/*
	 * str should be either the name of a configured zone, or the
	 * id of a running zone.  If str is a zone name, store the name
	 * in the table; otherwise, just store the id.
	 */
	if (zone_get_id(str, &id) != 0) {
		Die(gettext("unknown zone -- %s\n"), str);
		/*NOTREACHED*/
	}

	/* was zone specified by name or id? */
	errno = 0;
	if (id == (zoneid_t)strtol(str, &cp, 0) && errno == 0 && cp != str &&
	    *cp == '\0') {
		/* found it by id, don't store the name */
		str = NULL;
	}

	if (tbl->z_size == tbl->z_nent) {	/* reallocation */
		if ((tbl->z_size *= 2) == 0)
			tbl->z_size = 4;	/* first time */
		tbl->z_list =
		    Realloc(tbl->z_list, tbl->z_size * sizeof (zonename_t));
	}

	entp = &tbl->z_list[tbl->z_nent++];
	if (str)
		(void) strlcpy(entp->z_name, str, ZONENAME_MAX);
	else
		entp->z_name[0] = '\0';
	entp->z_id = id;
}

int
has_zone(zonetbl_t *tbl, zoneid_t id)
{
	long i;

	if (tbl->z_nent) {	/* do linear search if table is not empty */
		for (i = 0; i < tbl->z_nent; i++)
			if (tbl->z_list[i].z_id == id)
				return (1);
		return (0);	/* nothing has been found */
	}

	return (1);	/* if table is empty return true */
}

/*
 * Lookup ids for each zone name; this is done once each time /proc
 * is scanned to avoid calling getzoneidbyname for each process.
 */
void
convert_zone(zonetbl_t *tbl)
{
	long i;
	zoneid_t id;
	char *name;

	for (i = 0; i < tbl->z_nent; i++) {
		name = tbl->z_list[i].z_name;
		if (name != NULL) {
			if ((id = getzoneidbyname(name)) != -1)
				tbl->z_list[i].z_id = id;
		}
	}
}

void
lwpid_add(lwp_info_t *lwp, pid_t pid, id_t lwpid)
{
	plwp_t *elm = Zalloc(sizeof (plwp_t));
	int hash = pid % PLWP_TBL_SZ;

	elm->l_pid = pid;
	elm->l_lwpid = lwpid;
	elm->l_lwp = lwp;
	elm->l_next = plwp_tbl[hash]; /* add in front of chain */
	plwp_tbl[hash] = elm;
}

void
lwpid_del(pid_t pid, id_t lwpid)
{
	plwp_t *elm, *elm_prev;
	int hash = pid % PLWP_TBL_SZ;

	elm = plwp_tbl[hash];
	elm_prev = NULL;

	while (elm) {
		if ((elm->l_pid == pid) && (elm->l_lwpid == lwpid)) {
			if (!elm_prev)	/* first chain element */
				plwp_tbl[hash] = elm->l_next;
			else
				elm_prev->l_next = elm->l_next;
			free(elm);
			break;
		} else {
			elm_prev = elm;
			elm = elm->l_next;
		}
	}
}

static plwp_t *
lwpid_getptr(pid_t pid, id_t lwpid)
{
	plwp_t *elm = plwp_tbl[pid % PLWP_TBL_SZ];
	while (elm) {
		if ((elm->l_pid == pid) && (elm->l_lwpid == lwpid))
			return (elm);
		else
			elm = elm->l_next;
	}
	return (NULL);
}

lwp_info_t *
lwpid_get(pid_t pid, id_t lwpid)
{
	plwp_t *elm = lwpid_getptr(pid, lwpid);
	if (elm)
		return (elm->l_lwp);
	else
		return (NULL);
}

int
lwpid_pidcheck(pid_t pid)
{
	plwp_t *elm;
	elm = plwp_tbl[pid % PLWP_TBL_SZ];
	while (elm) {
		if (elm->l_pid == pid)
			return (1);
		else
			elm = elm->l_next;
	}
	return (0);
}

int
lwpid_is_active(pid_t pid, id_t lwpid)
{
	plwp_t *elm = lwpid_getptr(pid, lwpid);
	if (elm)
		return (elm->l_active);
	else
		return (0);
}

void
lwpid_set_active(pid_t pid, id_t lwpid)
{
	plwp_t *elm = lwpid_getptr(pid, lwpid);
	if (elm)
		elm->l_active = LWP_ACTIVE;
}
