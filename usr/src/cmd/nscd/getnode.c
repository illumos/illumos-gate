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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines to handle getipnode* calls in nscd. Note that the
 * getnodeby* APIs were renamed getipnodeby*. The interfaces
 * related to them in the nscd will remain as getnode*.
 */

#include <assert.h>
#include <errno.h>
#include <memory.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/door.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread.h>
#include <unistd.h>
#include <ucred.h>
#include <nss_common.h>
#include <inet/ip6.h>

#include "getxby_door.h"
#include "server_door.h"
#include "nscd.h"

static hash_t *addr_hash;		/* node address hash */
static hash_t *nnam_hash;		/* node name hash */
static mutex_t  node_lock = DEFAULTMUTEX;
static waiter_t node_wait;

static void getnode_addrkeepalive(int keep, int interval);
static void getnode_invalidate_unlocked(void);
static void getnode_namekeepalive(int keep, int interval);
static void update_node_bucket(nsc_bucket_t ** old, nsc_bucket_t *new,
		int callnumber);
static nsc_bucket_t *fixbuffer(nsc_return_t *in, int maxlen);
static void do_findnaddrs(nsc_bucket_t *ptr, int *table, char *addr);
static void do_findnnams(nsc_bucket_t *ptr, int *table, char *name);
static void do_invalidate(nsc_bucket_t ** ptr, int callnumber);

/*
 * Create a combined key
 * combined key =
 * name + ":" + af_family(in %d format) + ":" + flags(in %d format)
 * name = foo, af_family = 26, flags = 3, addrconfig = 1
 * key = "foo:26:3"
 * The string is allocated and caller has to free it.
 *
 * Insert ":" in between to ensure the uniqueness of the key.
 *
 * af_family: [2 | 26] ([AF_INET  | AF_INET6])
 * flags: 0 - strict
 *	  1 - AI_V4MAPPED
 *	  3 - (AI_V4MAPPED | AI_ALL)
 *	  4 - AI_ADDRCONFIG
 *	  5 - AI_DEFAULT (AI_V4MAPPED | AI_ADDRCONFIG)
 *	  7 - (AI_V4MAPPED | AI_ALL | AI_ADDRCONFIG)
 */
static char *
get_ipnode_combined_key(nsc_call_t *in) {
	int	len;
	char	*key;
	char	af_str[8];		/* in %d  format */
	char	flags_str[8];		/* in %d  format */

	snprintf(af_str, 8, "%d", in->nsc_u.ipnode.af_family);
	snprintf(flags_str, 8, "%d", in->nsc_u.ipnode.flags);
	/* name + ":" + af_str + ":" + flags_str + 1 */
	len = strlen(in->nsc_u.ipnode.name) + strlen(af_str) +
		strlen(flags_str) +  3;

	if ((key = (char *)malloc(len)) == NULL)
		return (NULL);

	snprintf(key, len, "%s:%s:%s", in->nsc_u.ipnode.name, af_str,
		flags_str);
	return (key);
}
/*
 * Parse key and copy the values to out
 */
static void
copy_ipnode_combined_key(char *key, nsc_call_t *out) {
	char	*token, *lasts;

	if ((token = strtok_r(key, ":", &lasts)) != NULL) {
		/* copy name */
		(void) strncpy(out->nsc_u.ipnode.name, token,
						NSCDMAXNAMELEN);
		if ((token = strtok_r(NULL, ":", &lasts)) != NULL) {
			/* Copy af_family */
			out->nsc_u.ipnode.af_family = atoi(token);

			if ((token = strtok_r(NULL, ":", &lasts)) != NULL) {
				/* Copy flags */
				out->nsc_u.ipnode.flags = atoi(token);
			}
		}
	}
}

static void
safe_inet_ntop(int af, const void  *addr,  char  *cp, size_t size)
{
	if (inet_ntop(af, addr, cp, size) != cp) {
		/*
		 * Called only for logging purposes...
		 * this should never happen in the nscd... but
		 * just in case we'll make sure we have a
		 * plausible error message.
		 */
		(void) snprintf(cp, size, "<inet_ntop returned %s>",
		    strerror(errno));
	}
}

void
getnode_init(void)
{
	addr_hash = make_hash(current_admin.node.nsc_suggestedsize);
	nnam_hash = make_hash(current_admin.node.nsc_suggestedsize);
}

static void
do_invalidate(nsc_bucket_t ** ptr, int callnumber)
{
	if (*ptr != NULL && *ptr != (nsc_bucket_t *)-1) {
		/* leave pending calls alone */
		update_node_bucket(ptr, NULL, callnumber);
	}
}

static void
do_findnnams(nsc_bucket_t *ptr, int *table, char *name)
{
	/*
	 * be careful with ptr - it may be -1 or NULL.
	 */

	if (ptr != NULL && ptr != (nsc_bucket_t *)-1) {
		/* leave pending calls alone */
		char *tmp = (char *)insertn(table, ptr->nsc_hits,
			(int)strdup(name));
		if (tmp != (char *)-1)
			free(tmp);
	}
}

static void
do_findnaddrs(nsc_bucket_t *ptr, int *table, char *addr)
{

	if (ptr != NULL && ptr != (nsc_bucket_t *)-1) {

		/* leave pending calls alone */
		char *tmp = (char *)insertn(table, ptr->nsc_hits,
			(int)strdup(addr));
		if (tmp != (char *)-1)
			free(tmp);
	}
}

void
getnode_revalidate(void)
{
	for (;;) {
		int slp;
		int interval;
		int count;

		slp = current_admin.node.nsc_pos_ttl;

		if (slp < 60)
			slp = 60;

		if ((count = current_admin.node.nsc_keephot) != 0) {
			interval = (slp/2)/count;
			if (interval == 0) interval = 1;
			(void) sleep(slp*2/3);
			getnode_namekeepalive(count, interval);
			getnode_addrkeepalive(count, interval);
		} else {
			(void) sleep(slp);
		}
	}
}

static void
getnode_namekeepalive(int keep, int interval)
{
	int *table;
	union {
		nsc_data_t  ping;
		char space[sizeof (nsc_data_t) + NSCDMAXNAMELEN];
	} u;

	int i;

	if (!keep)
		return;

	table = maken(keep);
	(void) mutex_lock(&node_lock);
	operate_hash(nnam_hash, do_findnnams, (char *)table);
	(void) mutex_unlock(&node_lock);

	for (i = 1; i <= keep; i++) {
		char *tmp;
		u.ping.nsc_call.nsc_callnumber = GETIPNODEBYNAME;

		if ((tmp = (char *)table[keep + 1 + i]) == (char *)-1)
			continue; /* unused slot in table */
		if (current_admin.debug_level >= DBG_ALL)
			logit("keepalive: reviving node %s\n", tmp);
		copy_ipnode_combined_key(tmp, &u.ping.nsc_call);

		launch_update(&u.ping.nsc_call);
		(void) sleep(interval);
	}

	for (i = 1; i <= keep; i++) {
		char *tmp;
		if ((tmp = (char *)table[keep + 1 + i]) != (char *)-1)
			free(tmp);
	}

	free(table);
}

static void
getnode_addrkeepalive(int keep, int interval)
{
	int *table;
	union {
		nsc_data_t  ping;
		char space[sizeof (nsc_data_t) + 80];
	} u;

	int i;

	if (!keep)
		return;

	table = maken(keep);
	(void) mutex_lock(&node_lock);
	operate_hash(addr_hash, do_findnaddrs, (char *)table);
	(void) mutex_unlock(&node_lock);

	for (i = 1; i <= keep; i++) {
		char *tmp;
		char addr[IPV6_ADDR_LEN];

		u.ping.nsc_call.nsc_callnumber = GETIPNODEBYADDR;

		if ((tmp = (char *)table[keep + 1 + i]) == (char *)-1)
			continue; /* enused slot in table */
		u.ping.nsc_call.nsc_u.addr.a_type = AF_INET6;
		u.ping.nsc_call.nsc_u.addr.a_length = IPV6_ADDR_LEN;
		if (inet_pton(AF_INET6, (const char *) tmp, (void *) addr) !=
		    1)
			continue; /* illegal address - skip it */
		else {
			(void) memcpy(u.ping.nsc_call.nsc_u.addr.a_data,
			    addr, IPV6_ADDR_LEN);
			if (current_admin.debug_level >= DBG_ALL)
				logit("keepalive: reviving address %s\n", tmp);
			launch_update(&u.ping.nsc_call);
		}
		(void) sleep(interval);
	}

	for (i = 1; i <= keep; i++) {
		char *tmp;
		if ((tmp = (char *)table[keep + 1 + i]) != (char *)-1)
		free(tmp);
	}

	free(table);
}

/*
 *   This routine marks all entries as invalid
 *
 */

void
getnode_invalidate(void)
{
	(void) mutex_lock(&node_lock);
	getnode_invalidate_unlocked();
	(void) mutex_unlock(&node_lock);
}

static void
getnode_invalidate_unlocked(void)
{
	operate_hash_addr(nnam_hash, do_invalidate, (char *)GETIPNODEBYNAME);
	operate_hash_addr(addr_hash, do_invalidate, (char *)GETIPNODEBYADDR);
	current_admin.node.nsc_invalidate_count++;
}

/*
 * Mark only the ipnodebyname cache entries as invalid
 */

void
getnode_name_invalidate(void)
{
	(void) mutex_lock(&node_lock);
	operate_hash_addr(nnam_hash, do_invalidate, (char *)GETIPNODEBYNAME);
	current_admin.node.nsc_invalidate_count++;
	(void) mutex_unlock(&node_lock);
}

void
getnode_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in, time_t now)
{
	int		out_of_date;
	nsc_bucket_t	*retb;
	char 		**bucket, *key;

	static time_t	lastmod;

	int bufferspace = maxsize - sizeof (nsc_return_t);

	if (current_admin.node.nsc_enabled == 0) {
		out->nsc_return_code = NOSERVER;
		out->nsc_bufferbytesused = sizeof (*out);
		return;
	}

	(void) mutex_lock(&node_lock);

	if (current_admin.node.nsc_check_files) {
		struct stat buf;

		if (stat("/etc/inet/ipnodes", &buf) < 0) {
			/*EMPTY*/;
		} else if (lastmod == 0) {
			lastmod = buf.st_mtime;
		} else if (lastmod < buf.st_mtime) {
			getnode_invalidate_unlocked();
			lastmod = buf.st_mtime;
		}
	}


	if (current_admin.debug_level >= DBG_ALL) {
		if (MASKUPDATEBIT(in->nsc_callnumber) == GETIPNODEBYADDR) {
			char addr[INET6_ADDRSTRLEN];
			safe_inet_ntop(AF_INET6,
			    (const void *)in->nsc_u.addr.a_data, addr,
			    sizeof (addr));
			logit("getnode_lookup: looking for address %s\n", addr);
		} else {
			logit("getnode_lookup: looking for nodename %s:%d:%d\n",
				in->nsc_u.ipnode.name,
				in->nsc_u.ipnode.af_family,
				in->nsc_u.ipnode.flags);
		}
	}

	for (;;) {
		if (MASKUPDATEBIT(in->nsc_callnumber) == GETIPNODEBYADDR) {
			char addr[INET6_ADDRSTRLEN];
			if (inet_ntop(AF_INET6,
			    (const void *)in->nsc_u.addr.a_data,
			    addr, sizeof (addr)) == NULL) {
				out->nsc_errno = NSS_NOTFOUND;
				out->nsc_return_code = NOTFOUND;
				out->nsc_bufferbytesused = sizeof (*out);
				goto getout;
			}
			bucket = get_hash(addr_hash, addr);
		} else { /* bounce excessively long requests */
			if (strlen(in->nsc_u.ipnode.name) > NSCDMAXNAMELEN) {
				ucred_t *uc = NULL;

				if (door_ucred(&uc) != 0) {
					logit("getnode_lookup: Name too long, "
					    "but no user credential: %s\n",
					    strerror(errno));
				} else {
					logit("getnode_lookup: Name too long "
					    "from pid %d uid %d\n",
					    ucred_getpid(uc),
					    ucred_getruid(uc));
					ucred_free(uc);
				}

				out->nsc_errno = NSS_NOTFOUND;
				out->nsc_return_code = NOTFOUND;
				out->nsc_bufferbytesused = sizeof (*out);
				goto getout;
			}
			if ((key = get_ipnode_combined_key(in)) == NULL) {

				out->nsc_errno = NSS_NOTFOUND;
				out->nsc_return_code = NOTFOUND;
				out->nsc_bufferbytesused = sizeof (*out);
				goto getout;
			}

			bucket = get_hash(nnam_hash, key);
			free(key);
		}

		if (*bucket == (char *)-1) {	/* pending lookup */
			if (get_clearance(in->nsc_callnumber) != 0) {
				/* no threads available */
				out->nsc_return_code = NOSERVER;
				/* cannot process now */
				out->nsc_bufferbytesused = sizeof (*out);
				current_admin.node.nsc_throttle_count++;
				goto getout;
			}
			nscd_wait(&node_wait, &node_lock, bucket);
			release_clearance(in->nsc_callnumber);
			continue; /* go back and relookup hash bucket */
		}
		break;
	}

	/*
	 * check for no name_service mode
	 */

	if (*bucket == NULL && current_admin.avoid_nameservice) {
		out->nsc_return_code = NOTFOUND;
		out->nsc_bufferbytesused = sizeof (*out);
	} else if ((*bucket == NULL) ||	/* New entry in name service */
	    (in->nsc_callnumber & UPDATEBIT) || /* needs updating */
	    (out_of_date = (!current_admin.avoid_nameservice &&
		(current_admin.node.nsc_old_data_ok == 0) &&
		(((nsc_bucket_t *)*bucket)->nsc_timestamp < now)))) {
		/* time has expired */
		int saved_errno;
		int saved_hits = 0;
		struct hostent *p;

		if (get_clearance(in->nsc_callnumber) != 0) {
			/* no threads available */
			out->nsc_return_code = NOSERVER;
			/* cannot process now */
			out->nsc_bufferbytesused = sizeof (* out);
			current_admin.node.nsc_throttle_count++;
			goto getout;
		}

		if (*bucket != NULL) {
			saved_hits = ((nsc_bucket_t *)*bucket)->nsc_hits;
		}

		/*
		 * block any threads accessing this bucket if data is
		 * non-existent or out of date
		 */

		if (*bucket == NULL || out_of_date) {
			update_node_bucket((nsc_bucket_t **)bucket,
					(nsc_bucket_t *)-1,
					in->nsc_callnumber);
		} else {
		/*
		 * if still not -1 bucket we are doing update... mark to
		 * prevent pileups of threads if the name service is hanging...
		 */
			((nsc_bucket_t *)(*bucket))->nsc_status |=
				ST_UPDATE_PENDING;
			/* cleared by deletion of old data */
		}
		(void) mutex_unlock(&node_lock);

		if (MASKUPDATEBIT(in->nsc_callnumber) == GETIPNODEBYADDR) {
			p = _uncached_getipnodebyaddr(in->nsc_u.addr.a_data,
					in->nsc_u.addr.a_length,
					in->nsc_u.addr.a_type,
					&out->nsc_u.hst,
					out->nsc_u.buff+sizeof (struct hostent),
					bufferspace,
					&saved_errno);
		} else {
			p = _uncached_getipnodebyname(in->nsc_u.ipnode.name,
					&out->nsc_u.hst,
					out->nsc_u.buff+sizeof (struct hostent),
					bufferspace,
					in->nsc_u.ipnode.af_family,
					in->nsc_u.ipnode.flags,
					&saved_errno);
		}

		(void) mutex_lock(&node_lock);

		release_clearance(in->nsc_callnumber);

		if (p == NULL) { /* data not found */
			if (current_admin.debug_level >= DBG_CANT_FIND) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
				    GETIPNODEBYADDR) {
					char addr[INET6_ADDRSTRLEN];
					safe_inet_ntop(AF_INET6,
					(const void *)in->nsc_u.addr.a_data,
					addr, sizeof (addr));
					logit("getnode_lookup: nscd COULDN'T "\
						"FIND address %s\n", addr);
				} else {
					logit("getnode_lookup: nscd COULDN'T "\
						"FIND node name %s:%d:%d\n",
						in->nsc_u.ipnode.name,
						in->nsc_u.ipnode.af_family,
						in->nsc_u.ipnode.flags);
				}
			}

			if (!(UPDATEBIT & in->nsc_callnumber))
				current_admin.node.nsc_neg_cache_misses++;

			retb = (nsc_bucket_t *)malloc(sizeof (nsc_bucket_t));
			retb->nsc_refcount = 1;
			retb->nsc_data.nsc_return_code = NOTFOUND;
			retb->nsc_data.nsc_bufferbytesused =
				sizeof (nsc_return_t);
			retb->nsc_data.nsc_errno = saved_errno;
			(void) memcpy(out, &(retb->nsc_data),
				retb->nsc_data.nsc_bufferbytesused);
			update_node_bucket((nsc_bucket_t **)bucket, retb,
				in->nsc_callnumber);
			goto getout;
		}

		else {
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
				    GETIPNODEBYADDR) {
					char addr[INET6_ADDRSTRLEN];
					safe_inet_ntop(AF_INET6,
					(const void *)in->nsc_u.addr.a_data,
					addr, sizeof (addr));
					logit("getnode_lookup: nscd FOUND "\
					    "addr %s\n", addr);
				} else {
					logit("getnode_lookup: nscd FOUND "\
					    "node name %s:%d:%d\n",
					    in->nsc_u.ipnode.name,
					    in->nsc_u.ipnode.af_family,
					    in->nsc_u.ipnode.flags);
				}
			}
			if (!(UPDATEBIT & in->nsc_callnumber))
			    current_admin.node.nsc_pos_cache_misses++;

			retb = fixbuffer(out, bufferspace);

			update_node_bucket((nsc_bucket_t **)bucket, retb,
				in->nsc_callnumber);
			if (saved_hits)
				retb->nsc_hits = saved_hits;
		}
	} else { 	/* found entry in cache */
		retb = (nsc_bucket_t *)*bucket;

		retb->nsc_hits++;

		(void) memcpy(out, &(retb->nsc_data),
			retb->nsc_data.nsc_bufferbytesused);

		if (out->nsc_return_code == SUCCESS) {
			if (!(UPDATEBIT & in->nsc_callnumber))
			    current_admin.node.nsc_pos_cache_hits++;
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
				    GETIPNODEBYADDR) {
					char addr[INET6_ADDRSTRLEN];
					safe_inet_ntop(AF_INET6,
					    (const void *)in->nsc_u.addr.a_data,
					    addr, sizeof (addr));
					logit("getnode_lookup: found address "\
					    "%s in cache\n", addr);
				} else {
					logit("getnode_lookup: found node "\
					    "name %s:%d:%d in cache\n",
					    in->nsc_u.ipnode.name,
					    in->nsc_u.ipnode.af_family,
					    in->nsc_u.ipnode.flags);
				}
			}
		} else {
			if (!(UPDATEBIT & in->nsc_callnumber))
			    current_admin.node.nsc_neg_cache_hits++;
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
				    GETIPNODEBYADDR) {
					char addr[INET6_ADDRSTRLEN];
					safe_inet_ntop(AF_INET6,
					    (const void *)in->nsc_u.addr.a_data,
					    addr, sizeof (addr));
					logit("getnode_lookup: %s marked as "\
					    "NOT FOUND in cache.\n", addr);
				} else {
					logit("getnode_lookup: %s:%d:%d marked"\
					    " as NOT FOUND in cache.\n",
					    in->nsc_u.ipnode.name,
					    in->nsc_u.ipnode.af_family,
					    in->nsc_u.ipnode.flags);
				}
			}
		}

		if ((retb->nsc_timestamp < now) &&
		    !(in->nsc_callnumber & UPDATEBIT) &&
		    !(retb->nsc_status & ST_UPDATE_PENDING)) {
			logit("launch update since time = %d\n",
			    retb->nsc_timestamp);
			retb->nsc_status |= ST_UPDATE_PENDING;
			/* cleared by deletion of old data */
			launch_update(in);
		}
	}

getout:

	(void) mutex_unlock(&node_lock);
}


/*ARGSUSED*/
static void
update_node_bucket(nsc_bucket_t ** old, nsc_bucket_t *new, int callnumber)
{
	if (*old != NULL && *old != (nsc_bucket_t *)-1) { /* old data exists */
		free(*old);
		current_admin.node.nsc_entries--;
	}

	/*
	 *  we can do this before reseting *old since we're holding the lock
	 */

	else if (*old == (nsc_bucket_t *)-1) {
		nscd_signal(&node_wait, (char **)old);
	}

	*old = new;

	if ((new != NULL) &&
	    (new != (nsc_bucket_t *)-1)) {
		/* real data, not just update pending or invalidate */

		new->nsc_hits = 1;
		new->nsc_status = 0;
		new->nsc_refcount = 1;
		current_admin.node.nsc_entries++;

		if (new->nsc_data.nsc_return_code == SUCCESS) {
			new->nsc_timestamp = time(NULL) +
				current_admin.node.nsc_pos_ttl;
		} else {
			new->nsc_timestamp = time(NULL) +
				current_admin.node.nsc_neg_ttl;
		}
	}
}

/* Allocate a bucket to fit the data(nsc_return_t *in size) */
/* copy the data into the bucket and return the bucket */

/*ARGSUSED*/
static nsc_bucket_t *
fixbuffer(nsc_return_t *in, int maxlen)
{
	nsc_return_t *out;
	nsc_bucket_t *retb;
	char *dest;
	char ** aliaseslist;
	char ** addrlist;
	int offset;
	int strs;
	int i;
	int numaliases;
	int numaddrs;

	/* find out the size of the data block we're going to need */

	strs = 1 + strlen(in->nsc_u.hst.h_name);
	for (numaliases = 0; in->nsc_u.hst.h_aliases[numaliases]; numaliases++)
		strs += 1 + strlen(in->nsc_u.hst.h_aliases[numaliases]);
	strs += sizeof (char *) * (numaliases+1);
	for (numaddrs = 0; in->nsc_u.hst.h_addr_list[numaddrs]; numaddrs++)
		strs += in->nsc_u.hst.h_length;
	strs += sizeof (char *) * (numaddrs+1+3);

	/* allocate it and copy it in code doesn't assume packing */
	/* order in original buffer */

	if ((retb = (nsc_bucket_t *)malloc(sizeof (*retb) + strs)) == NULL) {
		return (NULL);
	}

	out = &(retb->nsc_data);
	out->nsc_bufferbytesused = sizeof (*in) + strs;
	out->nsc_return_code 	= SUCCESS;
	out->nsc_errno 		= 0;

	dest = retb->nsc_data.nsc_u.buff + sizeof (struct hostent);
	offset = (int)dest;

	/* allocat the h_aliases list and the h_addr_list first to align 'em. */
	aliaseslist = (char **)dest;

	dest += sizeof (char *) * (numaliases+1);

	addrlist = (char **)dest;

	dest += sizeof (char *) * (numaddrs+1);

	(void) strcpy(dest, in->nsc_u.hst.h_name);
	strs = 1 + strlen(in->nsc_u.hst.h_name);
	out->nsc_u.hst.h_name = dest - offset;
	dest += strs;


	/* fill out the h_aliases list */

	for (i = 0; i < numaliases; i++) {
		(void) strcpy(dest, in->nsc_u.hst.h_aliases[i]);
		strs = 1 + strlen(in->nsc_u.hst.h_aliases[i]);
		aliaseslist[i] = dest - offset;
		dest += strs;
	}
	aliaseslist[i] = 0;	/* null term ptr chain */

	out->nsc_u.hst.h_aliases = (char **)((int)aliaseslist-offset);

	/* fill out the h_addr list */

	dest = (char *)(((int)dest + 3) & ~3);

	for (i = 0; i < numaddrs; i++) {
		(void) memcpy(dest, in->nsc_u.hst.h_addr_list[i],
			in->nsc_u.hst.h_length);
		strs = in->nsc_u.hst.h_length;
		addrlist[i] = dest - offset;
		dest += strs;
		dest = (char *)(((int)dest + 3) & ~3);
	}

	addrlist[i] = 0;	/* null term ptr chain */

	out->nsc_u.hst.h_addr_list = (char **)((int)addrlist-offset);

	out->nsc_u.hst.h_length = in->nsc_u.hst.h_length;
	out->nsc_u.hst.h_addrtype = in->nsc_u.hst.h_addrtype;

	(void) memcpy(in, &(retb->nsc_data),
	    retb->nsc_data.nsc_bufferbytesused);

	return (retb);

}

void
getnode_nam_reaper()
{
	nsc_reaper("getnode_nam", nnam_hash, &current_admin.node, &node_lock);
}

void
getnode_addr_reaper()
{
	nsc_reaper("getnode_addr", addr_hash, &current_admin.node, &node_lock);
}
