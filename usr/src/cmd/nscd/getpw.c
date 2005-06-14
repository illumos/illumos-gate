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
 * Routines to handle getpw* calls in nscd
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
#include <nss_common.h>
#include <ucred.h>

#include "getxby_door.h"
#include "server_door.h"

#include "nscd.h"

static hash_t *uid_hash;
static hash_t *nam_hash;
static mutex_t  passwd_lock = DEFAULTMUTEX;
static waiter_t passwd_wait;

static void getpw_invalidate_unlocked(void);
static void getpw_namekeepalive(int keep, int interval);
static void getpw_uidkeepalive(int keep, int interval);
static void update_pw_bucket(nsc_bucket_t **old, nsc_bucket_t *new,
    int callnumber);
static nsc_bucket_t *fixbuffer(nsc_return_t *in, int maxlen);
static void do_findnams(nsc_bucket_t *ptr, int *table, char *name);
static void do_finduids(nsc_bucket_t *ptr, int *table, int uid);
static void do_invalidate(nsc_bucket_t **ptr, int callnumber);

void
getpw_init(void)
{
	uid_hash = make_ihash(current_admin.passwd.nsc_suggestedsize);
	nam_hash = make_hash(current_admin.passwd.nsc_suggestedsize);
}

static void
do_invalidate(nsc_bucket_t ** ptr, int callnumber)
{
	if (*ptr != NULL && *ptr != (nsc_bucket_t *)-1) {
		/* leave pending calls alone */
		update_pw_bucket(ptr, NULL, callnumber);
	}
}

static void
do_finduids(nsc_bucket_t *ptr, int *table, int uid)
{

	/*
	 * be careful with ptr - it may be -1 or NULL.
	 */
	if (ptr != NULL && ptr != (nsc_bucket_t *)-1) {
		insertn(table, ptr->nsc_hits, uid);
	}
}

static void
do_findnams(nsc_bucket_t *ptr, int *table, char *name)
{

	/*
	 * be careful with ptr - it may be -1 or NULL.
	 */
	if (ptr != NULL && ptr != (nsc_bucket_t *)-1) {
		char *tmp = (char *)insertn(table, ptr->nsc_hits,
			(int)strdup(name));
		if (tmp != (char *)-1)
			free(tmp);
	}
}



void
getpw_revalidate(void)
{
	for (;;) {
		int slp;
		int interval;
		int count;

		slp = current_admin.passwd.nsc_pos_ttl;

		if (slp < 60) {
			slp = 60;
		}

		if ((count = current_admin.passwd.nsc_keephot) != 0) {
			interval = (slp / 2)/count;
			if (interval == 0) interval = 1;
			sleep(slp * 2 / 3);
			getpw_uidkeepalive(count, interval);
			getpw_namekeepalive(count, interval);
		} else {
			sleep(slp);
		}
	}
}

static void
getpw_uidkeepalive(int keep, int interval)
{
	int *table;
	nsc_data_t  ping;
	int i;

	if (!keep)
		return;

	table = maken(keep);
	mutex_lock(&passwd_lock);
	operate_hash(uid_hash, do_finduids, (char *)table);
	mutex_unlock(&passwd_lock);

	for (i = 1; i <= keep; i++) {
	    ping.nsc_call.nsc_callnumber = GETPWUID;
	    if ((ping.nsc_call.nsc_u.uid = table[keep + 1 + i]) == -1)
		continue; /* unused slot in table */
	    launch_update(&ping.nsc_call);
	    sleep(interval);
	}
	free(table);
}


static void
getpw_namekeepalive(int keep, int interval)
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
	mutex_lock(&passwd_lock);
	operate_hash(nam_hash, do_findnams, (char *)table);
	mutex_unlock(&passwd_lock);

	for (i = 1; i <= keep; i++) {
		char *tmp;
		u.ping.nsc_call.nsc_callnumber = GETPWNAM;

		if ((tmp = (char *)table[keep + 1 + i]) == (char *)-1)
			continue; /* unused slot in table */

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




/*
 *   This routine marks all entries as invalid
 *
 */
void
getpw_invalidate(void)
{
	mutex_lock(&passwd_lock);
	getpw_invalidate_unlocked();
	mutex_unlock(&passwd_lock);
}

static void
getpw_invalidate_unlocked(void)
{
	operate_hash_addr(nam_hash, do_invalidate, (char *)GETPWNAM);
	operate_hash_addr(uid_hash, do_invalidate, (char *)GETPWUID);
	current_admin.passwd.nsc_invalidate_count++;
}

void
getpw_lookup(nsc_return_t *out, int maxsize, nsc_call_t *in, time_t now)
{
	int		out_of_date;
	nsc_bucket_t	*retb;
	char 		**bucket;

	static time_t	lastmod;

	int bufferspace = maxsize - sizeof (nsc_return_t);

	if (current_admin.passwd.nsc_enabled == 0) {
		out->nsc_return_code = NOSERVER;
		out->nsc_bufferbytesused = sizeof (*out);
		return;
	}

	mutex_lock(&passwd_lock);

	if (current_admin.passwd.nsc_check_files) {
		struct stat buf;

		if (stat("/etc/passwd", &buf) < 0) {
			/*EMPTY*/;
		} else if (lastmod == 0) {
			lastmod = buf.st_mtime;
		} else if (lastmod < buf.st_mtime) {
			getpw_invalidate_unlocked();
			lastmod = buf.st_mtime;
		}
	}

	if (current_admin.debug_level >= DBG_ALL) {
		if (MASKUPDATEBIT(in->nsc_callnumber) == GETPWUID) {
			logit("getpw_lookup: looking for uid %d\n",
				in->nsc_u.uid);
		} else {
			logit("getpw_lookup: looking for name %s\n",
				in->nsc_u.name);
		}
	}

	for (;;) {
		if (MASKUPDATEBIT(in->nsc_callnumber) == GETPWUID) {
			bucket = get_hash(uid_hash, (char *)in->nsc_u.uid);
		} else { /* make reasonableness check here  */
			if (strlen(in->nsc_u.name) > NSCDMAXNAMELEN) {
				ucred_t *uc = NULL;

				if (door_ucred(&uc) != 0) {
					logit("getpw_lookup: Name too long, "
					    "but no user credential: %s\n",
					    strerror(errno));
				} else {

					logit("getpw_lookup: Name too long "
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
			bucket = get_hash(nam_hash, in->nsc_u.name);
		}

		if (*bucket == (char *)-1) {	/* pending lookup */
			if (get_clearance(in->nsc_callnumber) != 0) {
				/* no threads available */
				out->nsc_return_code = NOSERVER;
				/* cannot process now */
				out->nsc_bufferbytesused = sizeof (*out);
				current_admin.passwd.nsc_throttle_count++;
				goto getout;
			}
			nscd_wait(&passwd_wait, &passwd_lock, bucket);
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
	} else if (*bucket == NULL ||
	    (in->nsc_callnumber & UPDATEBIT) ||
	    (out_of_date = (!current_admin.avoid_nameservice &&
		(current_admin.passwd.nsc_old_data_ok == 0) &&
		(((nsc_bucket_t *)*bucket)->nsc_timestamp < now)))) {
		/*
		 * time has expired
		 */
		int saved_errno;
		int saved_hits = 0;
		struct passwd *p;

		if (get_clearance(in->nsc_callnumber) != 0) {
			/* no threads available */
			out->nsc_return_code = NOSERVER;
			/* cannot process now */
			out->nsc_bufferbytesused = sizeof (*out);
			current_admin.passwd.nsc_throttle_count++;
			goto getout;
		}
		if (*bucket != NULL) {
			saved_hits = ((nsc_bucket_t *)*bucket)->nsc_hits;
		}

		/*
		 *  block any threads accessing this bucket if data
		 *  is non-existent or out of date
		 */

		if (*bucket == NULL || out_of_date) {
			update_pw_bucket((nsc_bucket_t **)bucket,
					(nsc_bucket_t *)-1,
					in->nsc_callnumber);
		} else {
			/*
			 * if still not -1 bucket we are doing
			 * update... mark to prevent pileups of threads if
			 * the name service is hanging..
			 */
			((nsc_bucket_t *)(*bucket))->nsc_status |=
				ST_UPDATE_PENDING;
			/* cleared by deletion of old data */
		}
		mutex_unlock(&passwd_lock);

		if (MASKUPDATEBIT(in->nsc_callnumber) == GETPWUID) {
			p = _uncached_getpwuid_r(in->nsc_u.uid, &out->nsc_u.pwd,
				out->nsc_u.buff+sizeof (struct passwd),
				bufferspace);
			saved_errno = errno;
		} else {
			p = _uncached_getpwnam_r(in->nsc_u.name,
				&out->nsc_u.pwd,
				out->nsc_u.buff+sizeof (struct passwd),
				bufferspace);
			saved_errno = errno;
		}

		mutex_lock(&passwd_lock);

		release_clearance(in->nsc_callnumber);

		if (p == NULL) { /* data not found */
			if (current_admin.debug_level >= DBG_CANT_FIND) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
					GETPWUID) {
			logit("getpw_lookup: nscd COULDN'T FIND uid %d\n",
					in->nsc_u.uid);
				} else {
		logit("getpw_lookup: nscd COULDN'T FIND passwd name %s\n",
						in->nsc_u.name);
				}
			}

			if (!(UPDATEBIT & in->nsc_callnumber))
			    current_admin.passwd.nsc_neg_cache_misses++;

			retb = (nsc_bucket_t *)malloc(sizeof (nsc_bucket_t));

			retb->nsc_refcount = 1;
			retb->nsc_data.nsc_bufferbytesused =
				sizeof (nsc_return_t);
			retb->nsc_data.nsc_return_code = NOTFOUND;
			retb->nsc_data.nsc_errno = saved_errno;
			memcpy(out, &retb->nsc_data,
				retb->nsc_data.nsc_bufferbytesused);
			update_pw_bucket((nsc_bucket_t **)bucket, retb,
				in->nsc_callnumber);
			goto getout;
		} else {
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
					GETPWUID) {
				logit("getpw_lookup: nscd FOUND uid %d\n",
						in->nsc_u.uid);
				} else {
			logit("getpw_lookup: nscd FOUND passwd name %s\n",
						in->nsc_u.name);
				}
			}
			if (!(UPDATEBIT & in->nsc_callnumber))
			    current_admin.passwd.nsc_pos_cache_misses++;

			retb = fixbuffer(out, bufferspace);
			update_pw_bucket((nsc_bucket_t **)bucket,
				retb, in->nsc_callnumber);
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
			    current_admin.passwd.nsc_pos_cache_hits++;
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
					GETPWUID) {
			logit("getpw_lookup: found uid %d in cache\n",
						in->nsc_u.uid);
				} else {
			logit("getpw_lookup: found name %s in cache\n",
						in->nsc_u.name);
				}
			}
		} else {
			if (!(UPDATEBIT & in->nsc_callnumber))
			    current_admin.passwd.nsc_neg_cache_hits++;
			if (current_admin.debug_level >= DBG_ALL) {
				if (MASKUPDATEBIT(in->nsc_callnumber) ==
					GETPWUID) {
		logit("getpw_lookup: %d marked as NOT FOUND in cache.\n",
						in->nsc_u.uid);
				} else {
		logit("getpw_lookup: %s marked as NOT FOUND in cache.\n",
						in->nsc_u.name);
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

	mutex_unlock(&passwd_lock);

	/*
	 *	secure mode check - blank out passwd if call sucessfull
	 *	and caller != effective id
	 */
	if ((current_admin.passwd.nsc_secure_mode != 0) &&
		(out->nsc_return_code == SUCCESS) &&
		!(UPDATEBIT & in->nsc_callnumber)) {

		ucred_t *uc = NULL;

		if (door_ucred(&uc) != 0) {
			perror("door_ucred");
		} else {
			if (ucred_geteuid(uc) != out->nsc_u.pwd.pw_uid) {
				/*
				 *  write *NP* into passwd field if
				 *  not already that way... we fixed
				 *  the buffer code so there's always room.
				 */
				int len;

				char *foo = out->nsc_u.buff
					+ sizeof (struct passwd)
					+ (int)out->nsc_u.pwd.pw_passwd;

				len = strlen(foo);
				if (len > 0 &&
				    strcmp(foo, "*NP*") != 0 &&
				    strcmp(foo, "x") != 0) {
					if (len < 5)
						len = 5;
					strncpy(foo, "*NP*", len);
					/*
					 * strncpy will
					 * blank all
					 */
				}
			}
			ucred_free(uc);
		}
	}
}

/*ARGSUSED*/
static void
update_pw_bucket(nsc_bucket_t **old, nsc_bucket_t *new, int callnumber)
{
	if (*old != NULL && *old != (nsc_bucket_t *)-1) {
		/* old data exists */
		free(*old);
		current_admin.passwd.nsc_entries--;
	}

	/*
	 *  we can do this before reseting *old since we're holding the lock
	 */

	else if (*old == (nsc_bucket_t *)-1) {
		nscd_signal(&passwd_wait, (char **)old);
	}



	*old = new;

	if ((new != NULL) &&
		(new != (nsc_bucket_t *)-1)) {
		/* real data, not just update pending or invalidate */

		new->nsc_hits = 1;
		new->nsc_status = 0;
		new->nsc_refcount = 1;
		current_admin.passwd.nsc_entries++;

		if (new->nsc_data.nsc_return_code == SUCCESS) {
			new->nsc_timestamp = time(NULL) +
				current_admin.passwd.nsc_pos_ttl;
		} else {
			new->nsc_timestamp = time(NULL) +
				current_admin.passwd.nsc_neg_ttl;
		}
	}
}


/*ARGSUSED*/
static nsc_bucket_t *
fixbuffer(nsc_return_t *in, int maxlen)
{
	nsc_bucket_t *retb;
	char *dest;

	nsc_return_t  *out;
	int offset;
	int strs;
	int pwlen;

	/*
	 * find out the size of the data block we're going to need
	 */

	strs = 0;
	strs += 1 + strlen(in->nsc_u.pwd.pw_name);
	pwlen = strlen(in->nsc_u.pwd.pw_passwd);
	if (pwlen < 4)
	    pwlen = 4;
	strs += 1 + pwlen;
	strs += 1 + strlen(in->nsc_u.pwd.pw_age);
	strs += 1 + strlen(in->nsc_u.pwd.pw_comment);
	strs += 1 + strlen(in->nsc_u.pwd.pw_gecos);
	strs += 1 + strlen(in->nsc_u.pwd.pw_dir);
	strs += 1 + strlen(in->nsc_u.pwd.pw_shell);


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

	out->nsc_u.pwd.pw_uid = in->nsc_u.pwd.pw_uid;
	out->nsc_u.pwd.pw_gid = in->nsc_u.pwd.pw_gid;

	dest = retb->nsc_data.nsc_u.buff + sizeof (struct passwd);

	offset = (int)dest;

	strcpy(dest, in->nsc_u.pwd.pw_name);
	strs = 1 + strlen(in->nsc_u.pwd.pw_name);
	out->nsc_u.pwd.pw_name = dest - offset;
	dest += strs;

	strcpy(dest, in->nsc_u.pwd.pw_passwd);
	strs = 1 + pwlen;
	out->nsc_u.pwd.pw_passwd = dest - offset;
	dest += strs;

	strcpy(dest, in->nsc_u.pwd.pw_age);
	strs = 1 + strlen(in->nsc_u.pwd.pw_age);
	out->nsc_u.pwd.pw_age = dest - offset;
	dest += strs;

	strcpy(dest, in->nsc_u.pwd.pw_comment);
	strs = 1 + strlen(in->nsc_u.pwd.pw_comment);
	out->nsc_u.pwd.pw_comment = dest - offset;
	dest += strs;

	strcpy(dest, in->nsc_u.pwd.pw_gecos);
	strs = 1 + strlen(in->nsc_u.pwd.pw_gecos);
	out->nsc_u.pwd.pw_gecos = dest - offset;
	dest += strs;

	strcpy(dest, in->nsc_u.pwd.pw_dir);
	strs = 1 + strlen(in->nsc_u.pwd.pw_dir);
	out->nsc_u.pwd.pw_dir = dest - offset;
	dest += strs;

	strcpy(dest, in->nsc_u.pwd.pw_shell);
	out->nsc_u.pwd.pw_shell = dest - offset;

	memcpy(in, out, retb->nsc_data.nsc_bufferbytesused);


	return (retb);

}

void
getpw_uid_reaper()
{
	nsc_reaper("getpw_uid", uid_hash, &current_admin.passwd, &passwd_lock);
}

void
getpw_nam_reaper()
{
	nsc_reaper("getpw_nam", nam_hash, &current_admin.passwd, &passwd_lock);
}
