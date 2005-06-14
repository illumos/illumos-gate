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
 * Routines to handle gethost* calls in nscd
 */

#include <assert.h>
#include <errno.h>
#include <memory.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/door.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread.h>
#include <unistd.h>
#include <ucred.h>
#include <nss_common.h>

#include "getxby_door.h"
#include "server_door.h"
#include "nscd.h"

static hash_t *addr_hash;
static hash_t *hnam_hash;
static mutex_t  host_lock = DEFAULTMUTEX;
static waiter_t host_wait;

static void gethost_addrkeepalive(int keep, int interval);
static void gethost_invalidate_unlocked(void);
static void gethost_namekeepalive(int keep, int interval);
static int addr_to_int(char *addr);
static int int_to_addr(int h);
static void update_host_bucket(nsc_bucket_t **old, nsc_bucket_t *new,
    int callnumber);
static nsc_bucket_t *fixbuffer(nsc_return_t *in, int maxlen);
static void do_findhaddrs(nsc_bucket_t *ptr, int *table, int intaddr);
static void do_findhnams(nsc_bucket_t *ptr, int *table, char *name);
static void do_invalidate(nsc_bucket_t **ptr, int callnumber);

static int
addr_to_int(char *addr)
{
	union {
		char data[4];
		int  hashval;
	} u;

/*
 * following code is byte order dependant, but since all we use this for
 * is hashing this works out just fine.
 */
	u.data[0] = *addr++;
	u.data[1] = *addr++;
	u.data[2] = *addr++;
	u.data[3] = *addr++;

	return (u.hashval);
}

static int
int_to_addr(int h)
{
	union {
		char data[4];
		int  hashval;
	} u;

/*
 * following code is byte order dependant, but since all we use this for
 * is hashing this works out just fine.
 */
	u.hashval = h;
	return (* ((int *)u.data));
}

void
gethost_init(void)
{
	addr_hash = make_ihash(current_admin.host.nsc_suggestedsize);
	hnam_hash = make_hash(current_admin.host.nsc_suggestedsize);
}

static void
do_invalidate(nsc_bucket_t ** ptr, int callnumber)
{
	if (*ptr != NULL && *ptr != (nsc_bucket_t *)-1) {
		/* leave pending calls alone */
		update_host_bucket(ptr, NULL, callnumber);
	}
}

static void
do_findhnams(nsc_bucket_t *ptr, int *table, char *name)
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
do_findhaddrs(nsc_bucket_t *ptr, int *table, int intaddr)
{
	if (ptr != NULL && ptr != (nsc_bucket_t *)-1) {
		/* leave pending calls alone */
		insertn(table, ptr->nsc_hits, int_to_addr(intaddr));
	}
}

void
gethost_revalidate(void)
{
	for (;;) {
		int slp;
		int interval;
		int count;

		slp = current_admin.host.nsc_pos_ttl;

		if (slp < 60)
			slp = 60;
		count = current_admin.host.nsc_keephot;
		if (count != 0) {
			interval = (slp/2)/count;
			if (interval == 0) interval = 1;
			sleep(slp*2/3);
			gethost_namekeepalive(count, interval);
			gethost_addrkeepalive(count, interval);
		} else {
			sleep(slp);
		}
	}
}

static void
gethost_namekeepalive(int keep, int interval)
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
	mutex_lock(&host_lock);
	operate_hash(hnam_hash, do_findhnams, (char *)table);
	mutex_unlock(&host_lock);

	for (i = 1; i <= keep; i++) {
		char *tmp;
		u.ping.nsc_call.nsc_callnumber = GETHOSTBYNAME;

		if ((tmp = (char *)table[keep + 1 + i]) == (char *)-1)
			continue; /* unused slot in table */
		if (current_admin.debug_level >= DBG_ALL)
			logit("keepalive: reviving host %s\n", tmp);
		strcpy(u.ping.nsc_call.nsc_u.name, tmp);

		launch_update(&u.ping.nsc_call);
		sleep(interval);
	}

	for (i = 1; i <= keep; i++) {
		char *tmp;
		if ((tmp = (char *)table[keep + 1 + i]) != (char *)-1)
			free(tmp);
	}

	free(table);
}

static void
gethost_addrkeepalive(int keep, int interval)
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
	mutex_lock(&host_lock);
	operate_hash(addr_hash, do_findhaddrs, (char *)table);
	mutex_unlock(&host_lock);

	for (i = 1; i <= keep; i++) {
		int tmp;
		u.ping.nsc_call.nsc_callnumber = GETHOSTBYADDR;

		if ((tmp = table[keep + 1 + i]) == -1)
			continue; /* unused slot in table */
		u.ping.nsc_call.nsc_u.addr.a_type = AF_INET;
		u.ping.nsc_call.nsc_u.addr.a_length = sizeof (int);
		memcpy(u.ping.nsc_call.nsc_u.addr.a_data, &tmp, sizeof (int));
		launch_update(&u.ping.nsc_call);
		sleep(interval);
	}

	free(table);
}

/*
 *   This routine marks all entries as invalid
 *
 */
void
gethost_invalidate(void)
{
	mutex_lock(&host_lock);
	gethost_invalidate_unlocked();
	mutex_unlock(&host_lock);
}

static void
gethost_invalidate_unlocked(void)
{
	operate_hash_addr(hnam_hash, do_invalidate, (char *)GETHOSTBYNAME);
	operate_hash_addr(addr_hash, do_invalidate, (char *)GETHOSTBYADDR);
	current_admin.host.nsc_invalidate_count++;
}

void
gethost_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in, time_t now)
{
	int		out_of_date;
	nsc_bucket_t	*retb;
	char 		**bucket;

	static time_t	lastmod;

	int bufferspace = maxsize - sizeof (nsc_return_t);

	if (current_admin.host.nsc_enabled == 0) {
		out->nsc_return_code = NOSERVER;
		out->nsc_bufferbytesused = sizeof (*out);
		return;
	}

	mutex_lock(&host_lock);

	if (current_admin.host.nsc_check_files) {
		struct stat buf;

		if (stat("/etc/hosts", &buf) < 0) {
			/*EMPTY*/;
		} else if (lastmod == 0) {
			lastmod = buf.st_mtime;
		} else if (lastmod < buf.st_mtime) {
			gethost_invalidate_unlocked();
			lastmod = buf.st_mtime;
		}
	}


	if (current_admin.debug_level >= DBG_ALL) {
		if (MASKUPDATEBIT(in->nsc_callnumber) == GETHOSTBYADDR) {
			logit("gethost_lookup: looking for address %s\n",
			inet_ntoa(*((struct in_addr *)in->nsc_u.addr.a_data)));
		} else {
			logit("gethost_lookup: looking for hostname %s\n",
				in->nsc_u.name);
		}
	}

	for (;;) {
		if (MASKUPDATEBIT(in->nsc_callnumber) == GETHOSTBYADDR) {
			bucket = get_hash(addr_hash,
				(char *)addr_to_int(in->nsc_u.addr.a_data));
		} else { /* bounce excessively long requests */
			if (strlen(in->nsc_u.name) > NSCDMAXNAMELEN) {
				ucred_t *uc = NULL;

				if (door_ucred(&uc) != 0) {
					logit("gethost_lookup: Name too long, "
					    "but no user credential: %s\n",
					    strerror(errno));
				} else {
					logit("gethost_lookup: Name too long "
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
			bucket = get_hash(hnam_hash, in->nsc_u.name);
		}

		if (*bucket == (char *)-1) {	/* pending lookup */
			if (get_clearance(in->nsc_callnumber) != 0) {
				/* no threads available */
				out->nsc_return_code = NOSERVER;
				/* cannot process now */
				out->nsc_bufferbytesused = sizeof (*out);
				current_admin.host.nsc_throttle_count++;
				goto getout;
			}
			nscd_wait(&host_wait, &host_lock, bucket);
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
		(current_admin.host.nsc_old_data_ok == 0) &&
		(((nsc_bucket_t *)*bucket)->nsc_timestamp < now)))) {
		/* time has expired */
		int saved_errno;
		int saved_hits = 0;
		struct hostent *p;

		if (get_clearance(in->nsc_callnumber) != 0) {
			/* no threads available */
			out->nsc_return_code = NOSERVER;
			/* cannot process now */
			out->nsc_bufferbytesused = sizeof (*out);
			current_admin.host.nsc_throttle_count++;
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
			update_host_bucket((nsc_bucket_t **)bucket,
						(nsc_bucket_t *)-1,
						in->nsc_callnumber);
		} else {
		/*
		 * if still not -1 bucket we are doing update... mark
		 * to prevent pileups of threads if the name service
		 * is hanging....
		 */
			((nsc_bucket_t *)(*bucket))->nsc_status |=
						ST_UPDATE_PENDING;
			/* cleared by deletion of old data */
		}
		mutex_unlock(&host_lock);

		if (MASKUPDATEBIT(in->nsc_callnumber) == GETHOSTBYADDR) {
			p = _uncached_gethostbyaddr_r(in->nsc_u.addr.a_data,
				in->nsc_u.addr.a_length,
				in->nsc_u.addr.a_type,
				&out->nsc_u.hst,
				out->nsc_u.buff+sizeof (struct hostent),
						bufferspace,
						&saved_errno);
		} else {
			p = _uncached_gethostbyname_r(in->nsc_u.name,
				&out->nsc_u.hst,
				out->nsc_u.buff+sizeof (struct hostent),
						bufferspace,
						&saved_errno);
		}

		mutex_lock(&host_lock);

		release_clearance(in->nsc_callnumber);

		if (p == NULL) { /* data not found */
			if (current_admin.debug_level >= DBG_CANT_FIND) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
					GETHOSTBYADDR) {
		logit("gethost_lookup: nscd COULDN'T FIND address %s\n",
			inet_ntoa(*((struct in_addr *)in->nsc_u.addr.a_data)));
				} else {
		logit("gethost_lookup: nscd COULDN'T FIND host name %s\n",
						in->nsc_u.name);
				}
			}

			if (!(UPDATEBIT & in->nsc_callnumber))
				current_admin.host.nsc_neg_cache_misses++;

			retb = (nsc_bucket_t *)malloc(sizeof (nsc_bucket_t));

			retb->nsc_refcount = 1;
			retb->nsc_data.nsc_return_code = NOTFOUND;
			retb->nsc_data.nsc_bufferbytesused =
				sizeof (nsc_return_t);
			retb->nsc_data.nsc_errno = saved_errno;
			memcpy(out, &(retb->nsc_data),
				retb->nsc_data.nsc_bufferbytesused);
			update_host_bucket((nsc_bucket_t **)bucket, retb,
				in->nsc_callnumber);
			goto getout;
		} else {
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
						GETHOSTBYADDR) {
				logit("gethost_lookup: nscd FOUND addr %s\n",
			inet_ntoa(*((struct in_addr *)in->nsc_u.addr.a_data)));
				} else {
			logit("gethost_lookup: nscd FOUND host name %s\n",
						in->nsc_u.name);
				}
			}
			if (!(UPDATEBIT & in->nsc_callnumber))
				current_admin.host.nsc_pos_cache_misses++;

			retb = fixbuffer(out, bufferspace);

			update_host_bucket((nsc_bucket_t **)bucket, retb,
				in->nsc_callnumber);
			if (saved_hits)
				retb->nsc_hits = saved_hits;
		}
	} else { 	/* found entry in cache */
		retb = (nsc_bucket_t *)*bucket;

		retb->nsc_hits++;

		memcpy(out, &(retb->nsc_data),
			retb->nsc_data.nsc_bufferbytesused);

		if (out->nsc_return_code == SUCCESS) {
			if (!(UPDATEBIT & in->nsc_callnumber))
			    current_admin.host.nsc_pos_cache_hits++;
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
					GETHOSTBYADDR) {
			logit("gethost_lookup: found address %s in cache\n",
			inet_ntoa(*((struct in_addr *)in->nsc_u.addr.a_data)));
				} else {
			logit("gethost_lookup: found host name %s in cache\n",
						in->nsc_u.name);
				}
			}
		} else {
			if (!(UPDATEBIT & in->nsc_callnumber))
			    current_admin.host.nsc_neg_cache_hits++;
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
					GETHOSTBYADDR) {
		logit("gethost_lookup: %s marked as NOT FOUND in cache.\n",
			inet_ntoa(*((struct in_addr *)in->nsc_u.addr.a_data)));
				} else {
		logit("gethost_lookup: %s marked as NOT FOUND in cache.\n",
						in->nsc_u.name);
				}
			}
		}

		if ((retb->nsc_timestamp < now) &&
			!(in->nsc_callnumber & UPDATEBIT) &&
			!(retb->nsc_status & ST_UPDATE_PENDING)) {
		logit("launch update since time = %d\n", retb->nsc_timestamp);
			/* cleared by deletion of old data */
			retb->nsc_status |= ST_UPDATE_PENDING;
			launch_update(in);
		}
	}

getout:

	mutex_unlock(&host_lock);
}

/*ARGSUSED*/
static void
update_host_bucket(nsc_bucket_t **old, nsc_bucket_t *new, int callnumber)
{
	if (*old != NULL && *old != (nsc_bucket_t *)-1) {
		/* old data exists */
		free(*old);
		current_admin.host.nsc_entries--;
	}

	/*
	 *  we can do this before reseting *old since we're holding the lock
	 */

	else if (*old == (nsc_bucket_t *)-1) {
		nscd_signal(&host_wait, (char **)old);
	}



	*old = new;

	if ((new != NULL) &&
		(new != (nsc_bucket_t *)-1)) {
		/* real data, not just update pending or invalidate */

		new->nsc_hits = 1;
		new->nsc_status = 0;
		new->nsc_refcount = 1;
		current_admin.host.nsc_entries++;

		if (new->nsc_data.nsc_return_code == SUCCESS) {
			new->nsc_timestamp = time(NULL) +
				current_admin.host.nsc_pos_ttl;
		} else {
			new->nsc_timestamp = time(NULL) +
				current_admin.host.nsc_neg_ttl;
		}
	}
}


/*ARGSUSED*/
static nsc_bucket_t *
fixbuffer(nsc_return_t *in, int maxlen)
{
	nsc_return_t *out;
	nsc_bucket_t *retb;
	char *dest;
	char **aliaseslist;
	char **addrlist;
	int offset;
	int strs;
	int i;
	int numaliases;
	int numaddrs;

	/*
	 *  find out the size of the data block we're going to need
	 */

	strs = 1 + strlen(in->nsc_u.hst.h_name);
	for (numaliases = 0; in->nsc_u.hst.h_aliases[numaliases]; numaliases++)
		strs += 1 + strlen(in->nsc_u.hst.h_aliases[numaliases]);
	strs += sizeof (char *) * (numaliases+1);
	for (numaddrs = 0; in->nsc_u.hst.h_addr_list[numaddrs]; numaddrs++)
		strs += in->nsc_u.hst.h_length;
	strs += sizeof (char *) * (numaddrs+1+3);

	/*
	 * allocate it and copy it in
	 * code doesn't assume packing order in original buffer
	 */

	if ((retb = (nsc_bucket_t *)malloc(sizeof (*retb) + strs)) == NULL) {
		return (NULL);
	}

	out = &(retb->nsc_data);
	out->nsc_bufferbytesused = sizeof (*in) + strs;
	out->nsc_return_code 	= SUCCESS;
	out->nsc_errno 		= 0;


	dest = retb->nsc_data.nsc_u.buff + sizeof (struct hostent);

	offset = (int)dest;

	/*
	 * allocat the h_aliases list and the h_addr_list first to align 'em.
	 */
	aliaseslist = (char **)dest;

	dest += sizeof (char *) * (numaliases+1);

	addrlist = (char **)dest;

	dest += sizeof (char *) * (numaddrs+1);

	strcpy(dest, in->nsc_u.hst.h_name);
	strs = 1 + strlen(in->nsc_u.hst.h_name);
	out->nsc_u.hst.h_name = dest - offset;
	dest += strs;


	/*
	 * fill out the h_aliases list
	 */
	for (i = 0; i < numaliases; i++) {
		strcpy(dest, in->nsc_u.hst.h_aliases[i]);
		strs = 1 + strlen(in->nsc_u.hst.h_aliases[i]);
		aliaseslist[i] = dest - offset;
		dest += strs;
	}
	aliaseslist[i] = 0;	/* null term ptr chain */

	out->nsc_u.hst.h_aliases = (char **)((int)aliaseslist-offset);

	/*
	 * fill out the h_addr list
	 */

	dest = (char *)(((int)dest + 3) & ~3);

	for (i = 0; i < numaddrs; i++) {
		memcpy(dest, in->nsc_u.hst.h_addr_list[i],
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

	memcpy(in, &(retb->nsc_data), retb->nsc_data.nsc_bufferbytesused);

	return (retb);

}

void
gethost_nam_reaper()
{
	nsc_reaper("gethost_nam", hnam_hash, &current_admin.host, &host_lock);
}

void
gethost_addr_reaper()
{
	nsc_reaper("gethost_addr", addr_hash, &current_admin.host, &host_lock);
}
