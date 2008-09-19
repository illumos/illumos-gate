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
 * This file contains the library interface for the nwamd libdoor(3LIB)
 * service.  This library is intended for use by an external GUI utility to
 * provide status information to users and allow control over nwam behavior in
 * certain situations.
 */

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <door.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <libdladm.h>

#include <libnwam.h>

/* Special include files; data structures shared with nwamd */
#include <defines.h>
#include <structures.h>

static int door_fd = -1;

/*
 * This lock protects the library against descriptor leaks caused by multiple
 * threads attempting to race at opening the door.  It also protects the door
 * users by preventing reinit while busy.
 */
static pthread_mutex_t door_lock = PTHREAD_MUTEX_INITIALIZER;
static uint_t door_users;

#define	BUFFER_SIZE	256

/* ARGSUSED */
static void
door_cancel_handler(void *arg)
{
	(void) pthread_mutex_lock(&door_lock);
	door_users--;
	(void) pthread_mutex_unlock(&door_lock);
}

/*
 * This wraps around door_call(3C), and makes sure that interrupts and error
 * cases are handled in a reasonable way and that we always have an accurate
 * door user count.
 */
static int
make_door_call(nwam_door_cmd_t *cmd, void **bufp, size_t *size,
    size_t *rsize)
{
	door_arg_t arg;
	int retv;

	(void) memset(&arg, 0, sizeof (arg));
	arg.data_ptr = (char *)cmd;
	arg.data_size = sizeof (*cmd);
	arg.rbuf = *bufp;
	arg.rsize = *rsize;

	/*
	 * In order to avoid blocking and starving out the init routine, we
	 * check here for a descriptor before attempting to take a lock.
	 */
	if (door_fd == -1) {
		errno = EBADF;
		return (-1);
	}

	if ((retv = pthread_mutex_lock(&door_lock)) != 0) {
		errno = retv;
		return (-1);
	}
	pthread_cleanup_push(door_cancel_handler, NULL);
	door_users++;
	(void) pthread_mutex_unlock(&door_lock);
	/* The door_call function doesn't restart, so take care of that */
	do {
		errno = 0;
		if ((retv = door_call(door_fd, &arg)) == 0)
			break;
	} while (errno == EINTR);
	pthread_cleanup_pop(1);

	/* No legitimate door call on our server returns without data */
	if (retv == 0 && arg.data_size == 0) {
		retv = -1;
		errno = EBADF;
	}

	*bufp = arg.rbuf;
	*size = arg.data_size;
	*rsize = arg.rsize;

	return (retv);
}

/*
 * This is a common clean-up function for the door-calling routines.  It checks
 * for the daemon's standard error return mechanism (single integer with an
 * errno) and for the special case of an oversized return buffer.
 */
static int
handle_errors(int retv, void *dbuf, void *obuf, size_t dsize, size_t rsize)
{
	int err = errno;

	if (retv == 0 && dsize == sizeof (int) && (err = *(int *)dbuf) != 0)
		retv = -1;
	if (dbuf != obuf)
		(void) munmap(dbuf, rsize);
	errno = err;
	return (retv);
}

/*
 * Convert the internal libdladm representation of WLAN attributes into a text
 * representation that we can send to the client.  The passed-in 'strbuf'
 * parameter points to a buffer that's known to be large enough to hold all of
 * the strings.
 */
static char *
wlan_convert(libnwam_wlan_attr_t *wla, dladm_wlan_attr_t *wa, char *strbuf)
{
	static const struct {
		uint_t flag;
		char *(*cvt)(void *, char *);
		size_t offsf;
		size_t offst;
	} cvtable[] = {
		{
			DLADM_WLAN_ATTR_ESSID,
			(char *(*)(void *, char *))dladm_wlan_essid2str,
			offsetof(dladm_wlan_attr_t, wa_essid),
			offsetof(libnwam_wlan_attr_t, wla_essid)
		},
		{
			DLADM_WLAN_ATTR_BSSID,
			(char *(*)(void *, char *))dladm_wlan_bssid2str,
			offsetof(dladm_wlan_attr_t, wa_bssid),
			offsetof(libnwam_wlan_attr_t, wla_bssid)
		},
		{
			DLADM_WLAN_ATTR_SECMODE,
			(char *(*)(void *, char *))dladm_wlan_secmode2str,
			offsetof(dladm_wlan_attr_t, wa_secmode),
			offsetof(libnwam_wlan_attr_t, wla_secmode)
		},
		{
			DLADM_WLAN_ATTR_STRENGTH,
			(char *(*)(void *, char *))dladm_wlan_strength2str,
			offsetof(dladm_wlan_attr_t, wa_strength),
			offsetof(libnwam_wlan_attr_t, wla_strength)
		},
		{
			DLADM_WLAN_ATTR_MODE,
			(char *(*)(void *, char *))dladm_wlan_mode2str,
			offsetof(dladm_wlan_attr_t, wa_mode),
			offsetof(libnwam_wlan_attr_t, wla_mode)
		},
		{
			DLADM_WLAN_ATTR_SPEED,
			(char *(*)(void *, char *))dladm_wlan_speed2str,
			offsetof(dladm_wlan_attr_t, wa_speed),
			offsetof(libnwam_wlan_attr_t, wla_speed)
		},
		{
			DLADM_WLAN_ATTR_AUTH,
			(char *(*)(void *, char *))dladm_wlan_auth2str,
			offsetof(dladm_wlan_attr_t, wa_auth),
			offsetof(libnwam_wlan_attr_t, wla_auth)
		},
		{
			DLADM_WLAN_ATTR_BSSTYPE,
			(char *(*)(void *, char *))dladm_wlan_bsstype2str,
			offsetof(dladm_wlan_attr_t, wa_bsstype),
			offsetof(libnwam_wlan_attr_t, wla_bsstype)
		},
		{ 0, NULL, 0 }
	};
	int i;
	char **cptr;

	for (i = 0; cvtable[i].cvt != NULL; i++) {
		/* LINTED: pointer alignment */
		cptr = (char **)((char *)wla + cvtable[i].offst);
		if (wa->wa_valid & cvtable[i].flag) {
			*cptr = cvtable[i].cvt((char *)wa + cvtable[i].offsf,
			    strbuf);
			strbuf += strlen(strbuf) + 1;
		} else {
			*cptr = "";
		}
	}
	/* This one element is a simple integer, not a string */
	if (wa->wa_valid & DLADM_WLAN_ATTR_CHANNEL)
		wla->wla_channel = wa->wa_channel;
	return (strbuf);
}

/*
 * Wait for an event from the daemon and return it to the caller in allocated
 * storage.
 */
libnwam_event_data_t *
libnwam_wait_event(void)
{
	libnwam_event_data_t *led = NULL;
	int retv;
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	nwam_descr_event_t *nde;
	boolean_t has_wlan_attrs;
	char *str;

	cmd.ndc_type = ndcWaitEvent;
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	if (retv == 0 && cmd_size == sizeof (int))
		retv = *(int *)cmd_ret;
	if (retv == 0 && cmd_size == sizeof (*nde)) {
		nde = cmd_ret;
		has_wlan_attrs = (nde->nde_type == deWlanKeyNeeded ||
		    nde->nde_type == deWlanDisconnect ||
		    nde->nde_type == deWlanConnected);
		led = calloc(1, sizeof (*led) + strlen(nde->nde_interface) + 1 +
		    (has_wlan_attrs ? DLADM_STRSIZE * WLA_NUM_STRS : 0));
		if (led != NULL) {
			led->led_type = nde->nde_type;
			if (led->led_type == deInterfaceUp) {
				led->led_v4address = nde->nde_v4address;
				led->led_prefixlen = nde->nde_prefixlen;
			}
			if (led->led_type == deInterfaceDown ||
			    led->led_type == deLLPUnselected)
				led->led_cause = nde->nde_cause;
			str = (char *)(led + 1);
			(void) strcpy(led->led_interface = str,
			    nde->nde_interface);
			str += strlen(str) + 1;
			if (has_wlan_attrs)
				(void) wlan_convert(&led->led_wlan,
				    &nde->nde_attrs, str);
		}
	}
	if (cmd_ret != cmd_buf)
		(void) munmap(cmd_ret, cmd_rsize);
	if (led == NULL && retv > 0)
		errno = retv;
	return (led);
}

/* Free an allocated event */
void
libnwam_free_event(libnwam_event_data_t *led)
{
	free(led);
}

/*
 * Get a list of Lower-Layer Profiles (interfaces) in a single allocated array.
 */
libnwam_llp_t *
libnwam_get_llp_list(uint_t *numllp)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;
	const nwam_llp_data_t *nld;
	const llp_t *llp, *maxllp;
	size_t strsize;
	libnwam_llp_t *nllp, *nllpret;
	char *sbuf;

	*numllp = 0;

	cmd.ndc_type = ndcGetLLPList;
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	nld = cmd_ret;
	if (retv != 0 || cmd_size < sizeof (*nld) ||
	    cmd_size < sizeof (*nld) + nld->nld_count * sizeof (*llp)) {
		if (cmd_ret != cmd_buf)
			(void) munmap(cmd_ret, cmd_rsize);
		errno = retv == 0 ? EBADF : retv;
		return (NULL);
	}
	/* Figure room needed to return strings to caller */
	llp = (const llp_t *)(nld + 1);
	maxllp = llp + nld->nld_count;
	strsize = 0;
	while (llp < maxllp) {
		strsize += strlen(llp->llp_lname) + 1;
		llp++;
	}
	nllpret = malloc(nld->nld_count * sizeof (*nllp) + strsize);
	if (nllpret != NULL) {
		nllp = nllpret;
		sbuf = (char *)(nllp + nld->nld_count);
		llp = (const llp_t *)(nld + 1);
		/* Convert internal to external structures */
		while (llp < maxllp) {
			nllp->llp_interface = strcpy(sbuf, llp->llp_lname);
			sbuf += strlen(llp->llp_lname) + 1;
			nllp->llp_pri = llp->llp_pri;
			nllp->llp_type = llp->llp_type;
			nllp->llp_ipv4src = llp->llp_ipv4src;
			nllp->llp_primary =
			    strcmp(nld->nld_selected, llp->llp_lname) == 0;
			nllp->llp_locked =
			    strcmp(nld->nld_locked, llp->llp_lname) == 0;
			nllp->llp_link_failed = llp->llp_failed;
			nllp->llp_dhcp_failed = llp->llp_dhcp_failed;
			nllp->llp_link_up = llp->llp_link_up;
			nllp->llp_need_wlan = llp->llp_need_wlan;
			nllp->llp_need_key = llp->llp_need_key;
			nllp++;
			llp++;
		}
		*numllp = nld->nld_count;
	}
	if (cmd_ret != cmd_buf)
		(void) munmap(cmd_ret, cmd_rsize);
	return (nllpret);
}

/* Free an LLP list */
void
libnwam_free_llp_list(libnwam_llp_t *llp)
{
	free(llp);
}

/* Set the priority for a single LLP */
int
libnwam_set_llp_priority(const char *ifname, int prio)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;

	cmd.ndc_type = ndcSetLLPPriority;
	(void) strlcpy(cmd.ndc_interface, ifname, sizeof (cmd.ndc_interface));
	cmd.ndc_priority = prio;
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	return (handle_errors(retv, cmd_ret, cmd_buf, cmd_size, cmd_rsize));
}

/* Lock a single LLP as selected */
int
libnwam_lock_llp(const char *ifname)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;

	cmd.ndc_type = ndcLockLLP;
	if (ifname != NULL) {
		(void) strlcpy(cmd.ndc_interface, ifname,
		    sizeof (cmd.ndc_interface));
	} else {
		cmd.ndc_interface[0] = '\0';
	}
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	return (handle_errors(retv, cmd_ret, cmd_buf, cmd_size, cmd_rsize));
}

/* Get an array listing the scanned WLANs (Access Points) and attributes */
libnwam_wlan_t *
libnwam_get_wlan_list(uint_t *numwlans)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;
	struct wireless_lan *wllp, *maxwllp;
	size_t count, strsize;
	libnwam_wlan_t *wlan, *wlanret;
	char *sbuf;

	cmd.ndc_type = ndcGetWlanList;
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	if (retv != 0 || cmd_size < sizeof (*wllp)) {
		if (cmd_ret != cmd_buf)
			(void) munmap(cmd_ret, cmd_rsize);
		errno = retv == 0 ? EBADF : retv;
		*numwlans = 0;
		return (NULL);
	}
	/* Figure amount of storage needed for strings */
	wllp = cmd_ret;
	count = cmd_size / sizeof (*wllp);
	maxwllp = wllp + count;
	strsize = 0;
	while (wllp < maxwllp) {
		strsize += strlen(wllp->wl_if_name) + 1;
		wllp++;
	}
	wlanret = malloc(count * (sizeof (*wlan) + DLADM_STRSIZE *
	    WLA_NUM_STRS) + strsize);
	if (wlanret != NULL) {
		wlan = wlanret;
		sbuf = (char *)(wlan + count);
		wllp = cmd_ret;
		/* Convert internal to external structures */
		while (wllp < maxwllp) {
			wlan->wlan_interface = strcpy(sbuf, wllp->wl_if_name);
			sbuf += strlen(wllp->wl_if_name) + 1;
			wlan->wlan_known = wllp->known;
			wlan->wlan_haskey = wllp->cooked_key != NULL;
			wlan->wlan_connected = wllp->connected;
			sbuf = wlan_convert(&wlan->wlan_attrs, &wllp->attrs,
			    sbuf);
			wllp++;
			wlan++;
		}
	} else {
		count = 0;
	}
	*numwlans = count;
	if (cmd_ret != cmd_buf)
		(void) munmap(cmd_ret, cmd_rsize);
	return (wlanret);
}

/* Free array of WLANs */
void
libnwam_free_wlan_list(libnwam_wlan_t *wlans)
{
	free(wlans);
}

/* Get the non-volatile list of known user-specified Access Points */
libnwam_known_ap_t *
libnwam_get_known_ap_list(uint_t *numkas)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;
	nwam_known_ap_t *nka;
	libnwam_known_ap_t *kabuf, *kastart, *maxkabuf;
	libnwam_known_ap_t *kap, *kapret;
	char *sbuf;
	uint_t count;

	cmd.ndc_type = ndcGetKnownAPList;
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	nka = cmd_ret;
	if (retv != 0 || cmd_size < sizeof (*nka) ||
	    nka->nka_count * sizeof (*kabuf) >= cmd_size) {
		if (cmd_ret != cmd_buf)
			(void) munmap(cmd_ret, cmd_rsize);
		errno = retv == 0 ? EBADF : retv;
		*numkas = 0;
		return (NULL);
	}
	if ((kapret = malloc(cmd_size)) != NULL) {
		kap = kapret;
		sbuf = (char *)(kap + nka->nka_count);
		kabuf = kastart = (libnwam_known_ap_t *)(nka + 1);
		maxkabuf = kabuf + nka->nka_count;
		cmd_size -= sizeof (*nka);
		/*
		 * Buffer returned from daemon has string offsets in place of
		 * pointers; convert back to pointers for user.
		 */
		while (kabuf < maxkabuf) {
			if ((uintptr_t)kabuf->ka_essid >= cmd_size ||
			    memchr((char *)kastart + (uintptr_t)kabuf->ka_essid,
			    0, cmd_size - (uintptr_t)kabuf->ka_essid) == NULL)
				break;
			kap->ka_essid = strcpy(sbuf,
			    (char *)kastart + (uintptr_t)kabuf->ka_essid);
			sbuf += strlen(sbuf) + 1;
			if ((uintptr_t)kabuf->ka_bssid >= cmd_size ||
			    memchr((char *)kastart + (uintptr_t)kabuf->ka_bssid,
			    0, cmd_size - (uintptr_t)kabuf->ka_bssid) == NULL)
				break;
			kap->ka_bssid = strcpy(sbuf,
			    (char *)kastart + (uintptr_t)kabuf->ka_bssid);
			sbuf += strlen(sbuf) + 1;
			kap->ka_haskey = kabuf->ka_haskey;
			kabuf++;
			kap++;
		}
		count = kap - kapret;
	} else {
		count = 0;
	}
	*numkas = count;
	if (cmd_ret != cmd_buf)
		(void) munmap(cmd_ret, cmd_rsize);
	return (kapret);
}

/* Free a Known AP list */
void
libnwam_free_known_ap_list(libnwam_known_ap_t *kas)
{
	free(kas);
}

/*
 * Add a new AP to the "known" list so that we'll automatically connect.
 * BSSID is optional.
 */
int
libnwam_add_known_ap(const char *essid, const char *bssid)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;

	cmd.ndc_type = ndcAddKnownAP;
	(void) strlcpy(cmd.ndc_essid, essid, sizeof (cmd.ndc_essid));
	(void) strlcpy(cmd.ndc_bssid, bssid, sizeof (cmd.ndc_bssid));
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	return (handle_errors(retv, cmd_ret, cmd_buf, cmd_size, cmd_rsize));
}

/*
 * Delete an AP from the "known" list so that we won't connect to it
 * automatically.  BSSID is optional.
 */
int
libnwam_delete_known_ap(const char *essid, const char *bssid)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;

	cmd.ndc_type = ndcDeleteKnownAP;
	(void) strlcpy(cmd.ndc_essid, essid, sizeof (cmd.ndc_essid));
	(void) strlcpy(cmd.ndc_bssid, bssid, sizeof (cmd.ndc_bssid));
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	return (handle_errors(retv, cmd_ret, cmd_buf, cmd_size, cmd_rsize));
}

/*
 * Select a particular Access Point (WLAN) for use on a given interface.  This
 * may disconnect from the current AP if the link is already connected.
 */
int
libnwam_select_wlan(const char *ifname, const char *essid, const char *bssid)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;

	cmd.ndc_type = ndcSelectWlan;
	(void) strlcpy(cmd.ndc_interface, ifname, sizeof (cmd.ndc_interface));
	(void) strlcpy(cmd.ndc_essid, essid, sizeof (cmd.ndc_essid));
	(void) strlcpy(cmd.ndc_bssid, bssid, sizeof (cmd.ndc_bssid));
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	return (handle_errors(retv, cmd_ret, cmd_buf, cmd_size, cmd_rsize));
}

/*
 * Set the encryption key needed for a given AP.  The key string is cleartext.
 */
int
libnwam_wlan_key(const char *ifname, const char *essid, const char *bssid,
    const char *key)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;

	cmd.ndc_type = ndcWlanKey;
	(void) strlcpy(cmd.ndc_interface, ifname, sizeof (cmd.ndc_interface));
	(void) strlcpy(cmd.ndc_essid, essid, sizeof (cmd.ndc_essid));
	(void) strlcpy(cmd.ndc_bssid, bssid, sizeof (cmd.ndc_bssid));
	(void) strlcpy(cmd.ndc_key, key, sizeof (cmd.ndc_key));
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	return (handle_errors(retv, cmd_ret, cmd_buf, cmd_size, cmd_rsize));
}

/* Initiate wireless scan on the indicated interface */
int
libnwam_start_rescan(const char *ifname)
{
	nwam_door_cmd_t cmd;
	uintptr_t cmd_buf[BUFFER_SIZE];
	void *cmd_ret = cmd_buf;
	size_t cmd_rsize = sizeof (cmd_buf);
	size_t cmd_size;
	int retv;

	cmd.ndc_type = ndcStartRescan;
	(void) strlcpy(cmd.ndc_interface, ifname, sizeof (cmd.ndc_interface));
	retv = make_door_call(&cmd, &cmd_ret, &cmd_size, &cmd_rsize);
	return (handle_errors(retv, cmd_ret, cmd_buf, cmd_size, cmd_rsize));
}

/* Shut down the library. */
int
libnwam_fini(void)
{
	int retv;

	if ((retv = pthread_mutex_lock(&door_lock)) != 0) {
		errno = retv;
		return (-1);
	}
	if (door_fd != -1) {
		retv = close(door_fd);
		door_fd = -1;
	}
	(void) pthread_mutex_unlock(&door_lock);
	return (retv);
}

/*
 * Initialize the library for use.  Waittime is the number of seconds
 * (approximate) to wait for the daemon to become available if it isn't ready
 * immediately.  This may be -1 to wait forever, or 0 to open the connection to
 * the daemon without waiting (i.e., fail if not ready now).
 */
int
libnwam_init(int waittime)
{
	nwam_door_cmd_t cmd;
	door_arg_t arg;
	int newfd;
	int retv;

	for (;;) {
		if ((retv = pthread_mutex_lock(&door_lock)) != 0) {
			errno = retv;
			break;
		}
		if (door_users != 0) {
			errno = EBUSY;
			(void) pthread_mutex_unlock(&door_lock);
			break;
		}
		if (door_fd != -1) {
			(void) close(door_fd);
			door_fd = -1;
		}
		newfd = open(DOOR_FILENAME,
		    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY);
		if (newfd != -1) {
			/* Make a dummy call to make sure daemon is running */
			cmd.ndc_type = ndcNull;
			(void) memset(&arg, 0, sizeof (arg));
			arg.data_ptr = (char *)&cmd;
			arg.data_size = sizeof (cmd);
			arg.rbuf = (char *)&retv;
			arg.rsize = sizeof (retv);
			if (door_call(newfd, &arg) == 0) {
				if (arg.rbuf != (char *)&retv)
					(void) munmap(arg.rbuf, arg.data_size);
				if (arg.data_size == sizeof (int)) {
					if (retv == 0) {
						/* Call worked; we're done. */
						door_fd = newfd;
						(void) pthread_mutex_unlock(
						    &door_lock);
						return (0);
					} else {
						errno = retv;
					}
				} else {
					errno = EINVAL;
				}
				/*
				 * Zero data means daemon terminated.
				 * Otherwise, this is a permanent error.  No
				 * point in waiting around and retrying for a
				 * permanent problem.
				 */
				if (arg.data_size != 0) {
					(void) pthread_mutex_unlock(&door_lock);
					(void) close(newfd);
					break;
				}
			}
			(void) close(newfd);
		}
		(void) pthread_mutex_unlock(&door_lock);
		if (waittime == 0)
			break;
		if (waittime > 0)
			waittime--;
		/*
		 * We could do something smarter here, but decline to for now.
		 * This is "good enough" for NWAM Phase 0.5.
		 */
		(void) sleep(1);
	}
	return (-1);
}
