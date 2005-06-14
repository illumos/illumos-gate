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
 *	npd_cache.c
 *	NPD cache routines
 *
 *	Copyright (c) 1994-2001 Sun Microsystems, Inc.
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <shadow.h>
#include <synch.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nispasswd.h>
#include <ctype.h>
#include "npd_cache.h"

extern NIS_HASH_TABLE upd_list;
extern long	cache_time;
static int __nis_hash_key(nis_name name, NIS_HASH_TABLE *table);

void
free_upd_item(upd)
struct	update_item	*upd;
{
	if (upd == NULL)
		return;

	upd = (struct update_item *)nis_remove_item(upd->ul_item.name,
					&upd_list);
	if (upd == NULL)
		return;

	free(upd->ul_item.name);
	free(upd->ul_user);
	free(upd->ul_domain);
	(void) memset(upd->ul_oldpass, 0, sizeof (upd->ul_oldpass));
	free(upd->ul_oldpass);
	free(upd);
	upd = NULL;
}

/*
 * return 0 if an entry already exists
 * return -1 if out of memory
 * return 1 on successful addition
 */
int
add_upd_item(principal, user, sameuser, domain, ident, rval, key, pass)
nis_name principal;
char	*user;
bool_t	sameuser;
char	*domain;
ulong_t	ident;
ulong_t	rval;
des_block *key;
char	*pass;
{
	struct	update_item	*old = NULL, *tmp = NULL;

	if ((principal == NULL || *principal == '\0') ||
		(user == NULL || *user == '\0') ||
		(domain == NULL || *domain == '\0') ||
		(pass == NULL || *pass == '\0'))
		return (0);

	old = (struct update_item *)nis_find_item(principal, &upd_list);
	if (old != NULL) {
		return (0);
	}

	tmp = (struct update_item *)calloc(1, sizeof (struct update_item));
	if (tmp == NULL)
		return (-1);

	tmp->ul_item.name = strdup(principal);
	if (tmp->ul_item.name == NULL) {
		free(tmp);
		return (-1);
	}
	tmp->ul_user = strdup(user);
	if (tmp->ul_user == NULL) {
		free(tmp->ul_item.name);
		free(tmp);
		return (-1);
	}
	tmp->ul_domain = strdup(domain);
	if (tmp->ul_domain == NULL) {
		free(tmp->ul_user);
		free(tmp->ul_item.name);
		free(tmp);
		return (-1);
	}
	tmp->ul_oldpass = strdup(pass);
	if (tmp->ul_oldpass == NULL) {
		free(tmp->ul_domain);
		free(tmp->ul_user);
		free(tmp->ul_item.name);
		free(tmp);
		return (-1);
	}
	tmp->ul_sameuser = sameuser;
	tmp->ul_ident = ident;
	tmp->ul_rval = rval;
	tmp->ul_key = *key;
	tmp->ul_attempt = 1;
	tmp->ul_expire = time(NULL) + cache_time;

	return (nis_insert_item((NIS_HASH_ITEM *) tmp, &upd_list));
}

bool_t
find_upd_item(principal, upd)
nis_name	principal;
struct	update_item	**upd;
{
	struct	update_item *found = NULL;

	if (principal == NULL || *principal == '\0')
		return (FALSE);

	found = (struct update_item *)nis_find_item(principal, &upd_list);
	if (found == NULL)
		return (FALSE);
	*upd = found;
	return (TRUE);
}

int
__npd_hash_key(name)
nis_name	name;
{
	int key = __nis_hash_key(name, &upd_list);

	return (key >= 0 ? key+1 : key);
}

struct update_item *
__npd_item_by_key(key)
int	key;
{
	int	size;

	key -= 1;
	size = sizeof (upd_list.keys) / sizeof (upd_list.keys[0]);

	if (key < 0 || key >= size)
		return (NULL);
	return ((struct update_item *)upd_list.keys[key]);
}

/* the following macro improves performance */
#define	LOWER(c)	(isupper((c)) ? _tolower((c)) : (c))

static int
__nis_hash_key(name, table)
nis_name	name;
NIS_HASH_TABLE	*table;
{
	int	key = 0;
	unsigned char *s;

	if ((name == NULL || *name == '\0') || table == NULL)
		return (-1);

	for (s = (unsigned char *) name; *s != 0; s++)
		key += LOWER(*s);
	key %= (sizeof (table->keys) / sizeof (table->keys[0]));

	return (key);
}

void
__npd_print_entry(prin)
char	*prin;
{
	struct	update_item	*pi;

	if (find_upd_item(prin, &pi) == TRUE) {
		syslog(LOG_ERR, "user=%s, sameuser=%d",
			pi->ul_user, pi->ul_sameuser);
		syslog(LOG_ERR, "ident=%ld, rval=%ld",
			pi->ul_ident, pi->ul_rval);
		syslog(LOG_ERR, "attempt=%d, domain=%s",
			pi->ul_attempt, pi->ul_domain);
		return;
	} else {
		syslog(LOG_ERR, "no entry found for %s", prin);
		return;
	}
}
