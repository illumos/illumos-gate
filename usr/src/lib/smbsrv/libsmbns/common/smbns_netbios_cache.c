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

#include <synch.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <smbsrv/libsmbns.h>
#include <smbns_netbios.h>

#define	NETBIOS_HTAB_SZ	128
#define	NETBIOS_HKEY_SZ	(NETBIOS_NAME_SZ + NETBIOS_DOMAIN_NAME_MAX)

#define	NETBIOS_NAMEBUF  char namebuf[20]

#define	NETBIOS_SAME_IP(addr1, addr2) \
	((addr1)->sin.sin_addr.s_addr == (addr2)->sin.sin_addr.s_addr)

int smb_netbios_name_debug = 0;

typedef char nb_key_t[NETBIOS_HKEY_SZ];
static HT_HANDLE *smb_netbios_cache = 0;
static rwlock_t nb_cache_lock;

static char *smb_strname(struct name_entry *name, char *buf, int bufsize);
static void hash_callback(HT_ITEM *item);
static int smb_netbios_match(const char *key1, const char *key2, size_t n);
static void smb_netbios_cache_key(char *key, unsigned char *name,
					unsigned char *scope);

int
smb_netbios_cache_init()
{
	(void) rw_wrlock(&nb_cache_lock);
	if (smb_netbios_cache == 0) {
		smb_netbios_cache = ht_create_table(NETBIOS_HTAB_SZ,
		    NETBIOS_HKEY_SZ, HTHF_FIXED_KEY);
		if (smb_netbios_cache == 0) {
			syslog(LOG_ERR,
			    "smbd: cannot create NetBIOS name cache");
			(void) rw_unlock(&nb_cache_lock);
			return (0);
		}
		(void) ht_register_callback(smb_netbios_cache, hash_callback);
		ht_set_cmpfn(smb_netbios_cache, smb_netbios_match);
	}
	(void) rw_unlock(&nb_cache_lock);

	return (1);
}

void
smb_netbios_cache_fini()
{
	(void) rw_wrlock(&nb_cache_lock);
	ht_destroy_table(smb_netbios_cache);
	smb_netbios_cache = 0;
	(void) rw_unlock(&nb_cache_lock);
}

void
smb_netbios_cache_clean()
{
	(void) rw_wrlock(&nb_cache_lock);
	(void) ht_clean_table(smb_netbios_cache);
	(void) rw_unlock(&nb_cache_lock);
}

/*
 * smb_netbios_cache_lookup
 *
 * Searches the name cache for the given entry, if found
 * the entry will be locked before returning to caller
 * so caller MUST unlock the entry after it's done with it.
 */
struct name_entry *
smb_netbios_cache_lookup(struct name_entry *name)
{
	HT_ITEM *item;
	nb_key_t key;
	struct name_entry *entry = NULL;
	unsigned char scope[SMB_PI_MAX_SCOPE];
	unsigned char hostname[MAXHOSTNAMELEN];

	if (NETBIOS_NAME_IS_STAR(name->name)) {
		/* Return our address */
		(void) smb_config_getstr(SMB_CI_NBSCOPE, (char *)scope,
		    sizeof (scope));
		(void) utf8_strupr((char *)scope);

		if (smb_getnetbiosname((char *)hostname, MAXHOSTNAMELEN) != 0)
			return (NULL);

		smb_encode_netbios_name(hostname, 0x00, scope, name);
	}

	(void) rw_rdlock(&nb_cache_lock);

	smb_netbios_cache_key(key, name->name, name->scope);
	item = ht_find_item(smb_netbios_cache, key);
	if (item) {
		entry = (struct name_entry *)item->hi_data;
		(void) mutex_lock(&entry->mtx);
		if ((entry->attributes & NAME_ATTR_CONFLICT) != 0) {
			(void) mutex_unlock(&entry->mtx);
			entry = NULL;
		}
	}

	(void) rw_unlock(&nb_cache_lock);
	return (entry);
}

void
smb_netbios_cache_unlock_entry(struct name_entry *name)
{
	if (name)
		(void) mutex_unlock(&name->mtx);
}

/*
 * smb_netbios_cache_lookup_addr
 *
 * lookup the given 'name' in the cache and then checks
 * if the address also matches with the found entry.
 * 'name' is supposed to contain only one address.
 *
 * The found entry will be locked before returning to caller
 * so caller MUST unlock the entry after it's done with it.
 */
struct name_entry *
smb_netbios_cache_lookup_addr(struct name_entry *name)
{
	struct name_entry *entry = 0;
	struct addr_entry *addr;
	struct addr_entry *name_addr;
	HT_ITEM *item;
	nb_key_t key;

	(void) rw_rdlock(&nb_cache_lock);
	smb_netbios_cache_key(key, name->name, name->scope);
	item = ht_find_item(smb_netbios_cache, key);

	if (item && item->hi_data) {
		name_addr = &name->addr_list;
		entry = (struct name_entry *)item->hi_data;
		(void) mutex_lock(&entry->mtx);
		addr = &entry->addr_list;
		do {
			if (NETBIOS_SAME_IP(addr, name_addr)) {
				/* note that entry lock isn't released here */
				(void) rw_unlock(&nb_cache_lock);
				return (entry);
			}
			addr = addr->forw;
		} while (addr != &entry->addr_list);
		(void) mutex_unlock(&entry->mtx);
	}

	(void) rw_unlock(&nb_cache_lock);
	return (0);
}

int
smb_netbios_cache_insert(struct name_entry *name)
{
	struct name_entry *entry;
	struct addr_entry *addr;
	struct addr_entry *name_addr;
	HT_ITEM *item;
	nb_key_t key;

	/* No point in adding a name with IP address 255.255.255.255 */
	if (name->addr_list.sin.sin_addr.s_addr == 0xffffffff)
		return (0);

	(void) rw_wrlock(&nb_cache_lock);
	smb_netbios_cache_key(key, name->name, name->scope);
	item = ht_find_item(smb_netbios_cache, key);

	if (item && item->hi_data) {
		/* Name already exists */
		entry = (struct name_entry *)item->hi_data;
		(void) mutex_lock(&entry->mtx);

		name_addr = &name->addr_list;
		addr = &entry->addr_list;
		if (NETBIOS_SAME_IP(addr, name_addr) &&
		    (addr->sin.sin_port == name_addr->sin.sin_port)) {
			entry->attributes |=
			    name_addr->attributes & NAME_ATTR_LOCAL;
			syslog(LOG_DEBUG, "cache_insert: exists");
			(void) mutex_unlock(&entry->mtx);
			(void) rw_unlock(&nb_cache_lock);
			return (0); /* exists */
		}

		/* Was not primary: looks for others */
		for (addr = entry->addr_list.forw;
		    addr != &entry->addr_list; addr = addr->forw) {
			if (NETBIOS_SAME_IP(addr, name_addr) &&
			    (addr->sin.sin_port == name_addr->sin.sin_port)) {
				syslog(LOG_DEBUG, "cache_insert: dup");
				(void) mutex_unlock(&entry->mtx);
				(void) rw_unlock(&nb_cache_lock);
				return (0); /* exists */
			}
		}

		addr = (struct addr_entry *)malloc(sizeof (struct addr_entry));
		if (addr == 0) {
			(void) mutex_unlock(&entry->mtx);
			(void) rw_unlock(&nb_cache_lock);
			return (-1);
		}
		*addr = name->addr_list;
		entry->attributes |= addr->attributes;
		QUEUE_INSERT_TAIL(&entry->addr_list, addr);
		(void) mutex_unlock(&entry->mtx);
		(void) rw_unlock(&nb_cache_lock);
		return (0);
	}

	entry = (struct name_entry *)malloc(sizeof (struct name_entry));
	if (entry == 0) {
		(void) rw_unlock(&nb_cache_lock);
		return (-1);
	}
	*entry = *name;
	entry->addr_list.forw = entry->addr_list.back = &entry->addr_list;
	entry->attributes |= entry->addr_list.attributes;
	(void) mutex_init(&entry->mtx, 0, 0);
	if (ht_replace_item(smb_netbios_cache, key, entry) == 0) {
		free(entry);
		(void) rw_unlock(&nb_cache_lock);
		return (-1);
	}

	(void) rw_unlock(&nb_cache_lock);
	return (0);
}


void
smb_netbios_cache_delete(struct name_entry *name)
{
	nb_key_t key;
	HT_ITEM *item;
	struct name_entry *entry;

	(void) rw_wrlock(&nb_cache_lock);
	smb_netbios_cache_key(key, name->name, name->scope);
	item = ht_find_item(smb_netbios_cache, key);
	if (item && item->hi_data) {
		entry = (struct name_entry *)item->hi_data;
		(void) mutex_lock(&entry->mtx);
		ht_mark_delete(smb_netbios_cache, item);
		(void) mutex_unlock(&entry->mtx);
	}
	(void) rw_unlock(&nb_cache_lock);
}

/*
 * smb_netbios_cache_insert_list
 *
 * Insert a name with multiple addresses
 */
int
smb_netbios_cache_insert_list(struct name_entry *name)
{
	struct name_entry entry;
	struct addr_entry *addr;

	addr = &name->addr_list;
	do {
		smb_init_name_struct(NETBIOS_EMPTY_NAME, 0, name->scope,
		    addr->sin.sin_addr.s_addr,
		    addr->sin.sin_port,
		    name->attributes,
		    addr->attributes,
		    &entry);
		(void) memcpy(entry.name, name->name, NETBIOS_NAME_SZ);
		entry.addr_list.refresh_ttl = entry.addr_list.ttl =
		    addr->refresh_ttl;
		(void) smb_netbios_cache_insert(&entry);
		addr = addr->forw;
	} while (addr != &name->addr_list);

	return (0);
}

void
smb_netbios_cache_update_entry(struct name_entry *entry,
    struct name_entry *name)
{
	struct addr_entry *addr;
	struct addr_entry *name_addr;

	addr = &entry->addr_list;
	name_addr = &name->addr_list;

	if (IS_UNIQUE(entry->attributes)) {
		do {
			addr->ttl = name_addr->ttl;
			addr = addr->forw;
		} while (addr != &entry->addr_list);

	} else {
		do {
			if (NETBIOS_SAME_IP(addr, name_addr) &&
			    (addr->sin.sin_port == name_addr->sin.sin_port)) {
				addr->ttl = name_addr->ttl;
				return;
			}
			addr = addr->forw;
		} while (addr != &entry->addr_list);
	}
}

/*
 * smb_netbios_cache_status
 *
 * Scan the name cache and gather status for
 * Node Status response for names in the given scope
 */
unsigned char *
smb_netbios_cache_status(unsigned char *buf, int bufsize, unsigned char *scope)
{
	HT_ITERATOR hti;
	HT_ITEM *item;
	struct name_entry *name;
	unsigned char *numnames;
	unsigned char *scan;
	unsigned char *scan_end;

	scan = buf;
	scan_end = scan + bufsize;

	numnames = scan++;
	*numnames = 0;

	(void) rw_rdlock(&nb_cache_lock);
	item = ht_findfirst(smb_netbios_cache, &hti);
	do {
		if (item == 0)
			break;

		if (item->hi_data == 0)
			continue;

		if ((scan + NETBIOS_NAME_SZ + 2) >= scan_end)
			/* no room for adding next entry */
			break;

		name = (struct name_entry *)item->hi_data;
		(void) mutex_lock(&name->mtx);

		if (IS_LOCAL(name->attributes) &&
		    (strcasecmp((char *)scope, (char *)name->scope) == 0)) {
			bcopy(name->name, scan, NETBIOS_NAME_SZ);
			scan += NETBIOS_NAME_SZ;
			*scan++ = PUBLIC_BITS(name->attributes) >> 8;
			*scan++ = PUBLIC_BITS(name->attributes);
			(*numnames)++;
		}

		(void) mutex_unlock(&name->mtx);
	} while ((item = ht_findnext(&hti)) != 0);
	(void) rw_unlock(&nb_cache_lock);

	return (scan);
}

void
smb_netbios_cache_reset_ttl()
{
	struct addr_entry *addr;
	struct name_entry *name;
	HT_ITERATOR hti;
	HT_ITEM *item;

	(void) rw_rdlock(&nb_cache_lock);
	item = ht_findfirst(smb_netbios_cache, &hti);
	do {
		if (item == 0)
			break;

		if (item->hi_data == 0)
			continue;

		name = (struct name_entry *)item->hi_data;
		(void) mutex_lock(&name->mtx);

		addr = &name->addr_list;
		do {
			if (addr->ttl < 1) {
				if (addr->refresh_ttl)
					addr->ttl = addr->refresh_ttl;
				else
					addr->refresh_ttl = addr->ttl =
					    TO_SECONDS(DEFAULT_TTL);
			}
			addr = addr->forw;
		} while (addr != &name->addr_list);

		(void) mutex_unlock(&name->mtx);
	} while ((item = ht_findnext(&hti)) != 0);
	(void) rw_unlock(&nb_cache_lock);
}

/*
 * Returns TRUE when given name is added to the refresh queue
 * FALSE if not.
 */
static boolean_t
smb_netbios_cache_insrefq(name_queue_t *refq, HT_ITEM *item)
{
	struct name_entry *name;
	struct name_entry *refent;

	name = (struct name_entry *)item->hi_data;

	if (IS_LOCAL(name->attributes)) {
		if (IS_UNIQUE(name->attributes)) {
			refent = smb_netbios_name_dup(name, 1);
			if (refent)
				QUEUE_INSERT_TAIL(&refq->head, refent)

			/* next name */
			return (B_TRUE);
		}
	} else {
		ht_mark_delete(smb_netbios_cache, item);
		refent = smb_netbios_name_dup(name, 0);
		if (refent)
			QUEUE_INSERT_TAIL(&refq->head, refent)

		/* next name */
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * smb_netbios_cache_refresh
 *
 * Scans the name cache and add all local unique names
 * and non-local names the passed refresh queue. Non-
 * local names will also be marked as deleted.
 *
 * NOTE that the caller MUST protect the queue using
 * its mutex
 */
void
smb_netbios_cache_refresh(name_queue_t *refq)
{
	struct name_entry *name;
	struct addr_entry *addr;
	HT_ITERATOR hti;
	HT_ITEM *item;

	bzero(&refq->head, sizeof (refq->head));
	refq->head.forw = refq->head.back = &refq->head;

	(void) rw_rdlock(&nb_cache_lock);
	item = ht_findfirst(smb_netbios_cache, &hti);
	do { /* name loop */
		if (item == 0)
			break;

		if (item->hi_data == 0)
			continue;

		name = (struct name_entry *)item->hi_data;
		(void) mutex_lock(&name->mtx);

		addr = &name->addr_list;
		do { /* address loop */
			if (addr->ttl > 0) {
				addr->ttl--;
				if (addr->ttl == 0) {
					if (smb_netbios_cache_insrefq(refq,
					    item))
						break;
				}
			}
			addr = addr->forw;
		} while (addr != &name->addr_list);

		(void) mutex_unlock(&name->mtx);
	} while ((item = ht_findnext(&hti)) != 0);
	(void) rw_unlock(&nb_cache_lock);
}

/*
 * smb_netbios_cache_delete_locals
 *
 * Scans the name cache and add all local names to
 * the passed delete queue.
 *
 * NOTE that the caller MUST protect the queue using
 * its mutex
 */
void
smb_netbios_cache_delete_locals(name_queue_t *delq)
{
	struct name_entry *entry;
	struct name_entry *delent;
	HT_ITERATOR hti;
	HT_ITEM *item;

	bzero(&delq->head, sizeof (delq->head));
	delq->head.forw = delq->head.back = &delq->head;

	(void) rw_wrlock(&nb_cache_lock);
	item = ht_findfirst(smb_netbios_cache, &hti);
	do {
		if (item == 0)
			break;

		if (item->hi_data == 0)
			continue;

		entry = (struct name_entry *)item->hi_data;
		(void) mutex_lock(&entry->mtx);

		if (IS_LOCAL(entry->attributes)) {
			ht_mark_delete(smb_netbios_cache, item);
			delent = smb_netbios_name_dup(entry, 1);
			if (delent)
				QUEUE_INSERT_TAIL(&delq->head, delent)
		}

		(void) mutex_unlock(&entry->mtx);
	} while ((item = ht_findnext(&hti)) != 0);
	(void) rw_unlock(&nb_cache_lock);
}

void
smb_netbios_name_freeaddrs(struct name_entry *entry)
{
	struct addr_entry *addr;

	if (entry == 0)
		return;

	while ((addr = entry->addr_list.forw) != &entry->addr_list) {
		QUEUE_CLIP(addr);
		free(addr);
	}
}

/*
 * smb_netbios_cache_count
 *
 * Returns the number of names in the cache
 */
int
smb_netbios_cache_count()
{
	int cnt;

	(void) rw_rdlock(&nb_cache_lock);
	cnt = ht_get_total_items(smb_netbios_cache);
	(void) rw_unlock(&nb_cache_lock);

	return (cnt);
}

void
smb_netbios_cache_dump(void)
{
	struct name_entry *name;
	HT_ITERATOR hti;
	HT_ITEM *item;

	(void) rw_rdlock(&nb_cache_lock);
	item = ht_findfirst(smb_netbios_cache, &hti);
	while (item) {
		if (item->hi_data) {
			name = (struct name_entry *)item->hi_data;
			(void) mutex_lock(&name->mtx);
			smb_netbios_name_dump(name);
			(void) mutex_unlock(&name->mtx);
		}
		item = ht_findnext(&hti);
	}
	(void) rw_unlock(&nb_cache_lock);
}

void
smb_netbios_name_dump(struct name_entry *entry)
{
	struct addr_entry *addr;
	int count = 0;

	if (smb_netbios_name_debug == 0)
		return;

	syslog(LOG_DEBUG, "name='%15.15s<%02X>' scope='%s' attr=0x%x",
	    entry->name, entry->name[15],
	    entry->scope, entry->attributes);
	addr = &entry->addr_list;
	do {
		syslog(LOG_DEBUG, "addr_list[%d]:", count++);
		syslog(LOG_DEBUG, "  attributes     = 0x%x", addr->attributes);
		syslog(LOG_DEBUG, "  conflict_timer = %d",
		    addr->conflict_timer);
		syslog(LOG_DEBUG, "  refresh_ttl    = %d", addr->refresh_ttl);
		syslog(LOG_DEBUG, "  ttl            = %d", addr->ttl);
		syslog(LOG_DEBUG, "  sin.sin_addr   = %s",
		    inet_ntoa(addr->sin.sin_addr));
		syslog(LOG_DEBUG, "  sin.sin_port   = %d", addr->sin.sin_port);
		syslog(LOG_DEBUG, "  sin.sinlen     = %d", addr->sinlen);
		addr = addr->forw;
	} while (addr != &entry->addr_list);
}

void
smb_netbios_name_logf(struct name_entry *entry)
{
	struct addr_entry *addr;
	NETBIOS_NAMEBUF;

	(void) smb_strname(entry, namebuf, sizeof (namebuf));
	syslog(LOG_DEBUG, "%s flags=0x%x\n", namebuf, entry->attributes);
	addr = &entry->addr_list;
	do {
		syslog(LOG_DEBUG, "  %s ttl=%d flags=0x%x",
		    inet_ntoa(addr->sin.sin_addr),
		    addr->ttl, addr->attributes);
		addr = addr->forw;
	} while (addr && (addr != &entry->addr_list));
}

/*
 * smb_netbios_name_dup
 *
 * Duplicate the given name entry. If 'alladdr' is 0 only
 * copy the primary address otherwise duplicate all the
 * addresses. NOTE that the duplicate structure is not
 * like a regular cache entry i.e. it's a contiguous block
 * of memory and each addr structure doesn't have it's own
 * allocated memory. So, the returned structure can be freed
 * by one free call.
 */
struct name_entry *
smb_netbios_name_dup(struct name_entry *entry, int alladdr)
{
	struct addr_entry *addr;
	struct addr_entry *dup_addr;
	struct name_entry *dup;
	int addr_cnt = 0;
	int size = 0;

	if (alladdr) {
		addr = entry->addr_list.forw;
		while (addr && (addr != &entry->addr_list)) {
			addr_cnt++;
			addr = addr->forw;
		}
	}

	size = sizeof (struct name_entry) +
	    (addr_cnt * sizeof (struct addr_entry));
	dup = (struct name_entry *)malloc(size);
	if (dup == 0)
		return (0);

	bzero(dup, size);

	dup->forw = dup->back = dup;
	dup->attributes = entry->attributes;
	(void) memcpy(dup->name, entry->name, NETBIOS_NAME_SZ);
	(void) strlcpy((char *)dup->scope, (char *)entry->scope,
	    NETBIOS_DOMAIN_NAME_MAX);
	dup->addr_list = entry->addr_list;
	dup->addr_list.forw = dup->addr_list.back = &dup->addr_list;

	if (alladdr == 0)
		return (dup);

	/* LINTED - E_BAD_PTR_CAST_ALIGN */
	dup_addr = (struct addr_entry *)((unsigned char *)dup +
	    sizeof (struct name_entry));

	addr = entry->addr_list.forw;
	while (addr && (addr != &entry->addr_list)) {
		*dup_addr = *addr;
		QUEUE_INSERT_TAIL(&dup->addr_list, dup_addr);
		addr = addr->forw;
		dup_addr++;
	}

	return (dup);
}

static char *
smb_strname(struct name_entry *name, char *buf, int bufsize)
{
	char *p;

	(void) snprintf(buf, bufsize, "%15.15s", name->name);
	p = strchr(buf, ' ');
	if (p)
		(void) snprintf(p, 5, "<%02X>", name->name[15]);

	return (buf);
}

static void
hash_callback(HT_ITEM *item)
{
	struct name_entry *entry;

	if (item && item->hi_data) {
		entry = (struct name_entry *)item->hi_data;
		smb_netbios_name_freeaddrs(entry);
		free(entry);
	}
}


/*ARGSUSED*/
static int
smb_netbios_match(const char *key1, const char *key2, size_t n)
{
	int res;

	res = bcmp(key1, key2, NETBIOS_NAME_SZ);
	if (res == 0) {
		/* Names are the same, compare scopes */
		res = strcmp(key1 + NETBIOS_NAME_SZ, key2 + NETBIOS_NAME_SZ);
	}

	return (res);
}

static void
smb_netbios_cache_key(char *key, unsigned char *name, unsigned char *scope)
{
	bzero(key, NETBIOS_HKEY_SZ);
	(void) memcpy(key, name, NETBIOS_NAME_SZ);
	(void) memcpy(key + NETBIOS_NAME_SZ, scope,
	    strlen((const char *)scope));
}
