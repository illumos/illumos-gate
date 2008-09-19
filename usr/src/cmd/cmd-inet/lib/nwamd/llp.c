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
 * This file contains the routines that manipulate Link Layer Profiles
 * (aka LLPs) and various support functions.  This includes parsing and
 * updating of the /etc/nwam/llp file.
 *
 * The daemon maintains a list of llp_t structures that represent the
 * provided configuration information for a link.  After the llp file
 * is read, entries are added to the LLP list for any known links
 * (identified by checking the interface list, which is based on the
 * v4 interfaces present after 'ifconfig -a plumb') which were not
 * represented in the llp file.  These entries contain the default
 * "automatic" settings: plumb both IPv4 and IPv6, use DHCP on the
 * v4 interface, and accept router- and DHCPv6-assigned addresses on
 * the v6 interface.  The default entries created by the daemon are
 * also added to the llp file.
 *
 * LLP priority is assigned based on two factors: the order within
 * the llp file, with earlier entries having higher priority; and
 * a preference for wired interfaces before wireless.  Entries that
 * are added to the file by the daemon are added *after* any existing
 * entries; within the added block, wired entries are added before
 * wireless.  Thus if the llp file is never modified externally, wired
 * will generally be ordered before wireless.  However, if the
 * administrator creates the file with wireless entries before wired,
 * that priority order will be respected.
 *
 * The llp list is protected by the global llp_lock, which must be
 * pthread_mutex_lock()'d before reading or writing the list.  Only the main
 * thread can write to the list; this allows the main thread to deal with read
 * access to structure pointers without holding locks and without the
 * complexity of reference counts.  All other threads must hold llp_lock for
 * the duration of any read access to the data, and must not deal directly in
 * structure pointers.  (A thread may also hold machine_lock to block the main
 * thread entirely in order to manipulate the data; such use is isolated to the
 * door interface.)
 *
 * Functions in this file have comments noting where the main thread alone is
 * the caller.  These functions do not need to acquire the lock.
 *
 * If you hold both ifs_lock and llp_lock, you must take ifs_lock first.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <atomic.h>
#include <pthread.h>
#include <signal.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

/* Lock to protect the llp list. */
static pthread_mutex_t llp_lock = PTHREAD_MUTEX_INITIALIZER;

/* Accessed only from main thread or with llp_lock held */
llp_t *link_layer_profile;

static struct qelem llp_list;
static llp_t *locked_llp;

/*
 * Global variable to hold the highest priority.  Need to use the atomic
 * integer arithmetic functions to update it.
 */
static uint32_t llp_highest_pri;

static void print_llp_list(void);

void
initialize_llp(void)
{
	llp_list.q_forw = llp_list.q_back = &llp_list;
}

char *
llp_prnm(llp_t *llp)
{
	if (llp == NULL)
		return ("null_llp");
	else if (llp->llp_lname == NULL)
		return ("null_lname");
	else
		return (llp->llp_lname);
}

/*
 * This function removes a given LLP from the global list and discards it.
 * Called only from the main thread.
 */
void
llp_delete(llp_t *llp)
{
	if (pthread_mutex_lock(&llp_lock) == 0) {
		if (llp == locked_llp)
			locked_llp = NULL;
		assert(llp != link_layer_profile);
		remque(&llp->llp_links);
		(void) pthread_mutex_unlock(&llp_lock);
		free(llp->llp_ipv6addrstr);
		free(llp->llp_ipv4addrstr);
		free(llp);
	}
}

static void
llp_list_free(void)
{
	int retv;
	llp_t *llp;

	locked_llp = NULL;
	if ((retv = pthread_mutex_lock(&llp_lock)) != 0) {
		/* Something very serious is wrong... */
		syslog(LOG_ERR, "llp_list_free: cannot lock mutex: %s",
		    strerror(retv));
		return;
	}
	while (llp_list.q_forw != &llp_list) {
		llp = (llp_t *)llp_list.q_forw;
		remque(&llp->llp_links);
		free(llp->llp_ipv6addrstr);
		free(llp->llp_ipv4addrstr);
		free(llp);
	}
	(void) pthread_mutex_unlock(&llp_lock);
}

/*
 * Called either from main thread or with llp_lock held.
 */
llp_t *
llp_lookup(const char *link)
{
	llp_t *llp;

	if (link == NULL)
		return (NULL);

	for (llp = (llp_t *)llp_list.q_forw; llp != (llp_t *)&llp_list;
	    llp = (llp_t *)llp->llp_links.q_forw) {
		if (strcmp(link, llp->llp_lname) == 0)
			break;
	}
	if (llp == (llp_t *)&llp_list)
		llp = NULL;
	return (llp);
}

/*
 * Choose the higher priority llp of the two passed in.  If one is
 * NULL, the other will be higher priority.  If both are NULL, NULL
 * is returned.
 *
 * Assumes that both are available (i.e. doesn't check IFF_RUNNING
 * or IF_DHCPFAILED flag values).
 */
llp_t *
llp_high_pri(llp_t *a, llp_t *b)
{
	if (a == NULL || a->llp_links.q_forw == NULL)
		return (b);
	else if (b == NULL || b->llp_links.q_forw == NULL)
		return (a);

	/* Check for locked LLP selection for user interface */
	if (a == locked_llp)
		return (a);
	else if (b == locked_llp)
		return (b);

	if (a->llp_failed && !b->llp_failed)
		return (b);
	if (!a->llp_failed && b->llp_failed)
		return (a);

	/*
	 * Higher priority is represented by a lower number.  This seems a
	 * bit backwards, but for now it makes assigning priorities very easy.
	 */
	return ((a->llp_pri <= b->llp_pri) ? a : b);
}

/*
 * Chooses the highest priority link that corresponds to an available
 * interface.  Called only in the main thread.
 */
llp_t *
llp_best_avail(void)
{
	llp_t *llp, *rtnllp;

	if ((rtnllp = locked_llp) == NULL) {
		for (llp = (llp_t *)llp_list.q_forw; llp != (llp_t *)&llp_list;
		    llp = (llp_t *)llp->llp_links.q_forw) {
			if (is_interface_ok(llp->llp_lname))
				rtnllp = llp_high_pri(llp, rtnllp);
		}
	}

	return (rtnllp);
}

/*
 * Called only by the main thread.  Note that this leaves link_layer_profile
 * set to NULL only in the case of abject failure, and then leaves llp_failed
 * set.
 */
static void
llp_activate(llp_t *llp)
{
	char *host;
	/*
	 * Choosing "dhcp" as a hostname is unsupported right now.
	 * We use hostname="dhcp" as a keyword telling bringupinterface()
	 * to use dhcp on the interface.
	 */
	char *dhcpstr = "dhcp";

	assert(link_layer_profile == NULL);

	host = (llp->llp_ipv4src == IPV4SRC_DHCP) ? dhcpstr :
	    llp->llp_ipv4addrstr;

	report_llp_selected(llp->llp_lname);
	switch (bringupinterface(llp->llp_lname, host, llp->llp_ipv6addrstr,
	    llp->llp_ipv6onlink)) {
	case SUCCESS:
		llp->llp_failed = B_FALSE;
		llp->llp_waiting = B_FALSE;
		link_layer_profile = llp;
		dprintf("llp_activate: activated llp for %s", llp_prnm(llp));
		break;
	case FAILURE:
		llp->llp_failed = B_TRUE;
		llp->llp_waiting = B_FALSE;
		dprintf("llp_activate: failed to bring up %s", llp_prnm(llp));
		report_llp_unselected(llp->llp_lname, dcFailed);
		link_layer_profile = NULL;
		break;
	case WAITING:
		llp->llp_failed = B_FALSE;
		llp->llp_waiting = B_TRUE;
		link_layer_profile = llp;
		dprintf("llp_activate: waiting for %s", llp_prnm(llp));
	}
}

/*
 * Replace the currently active link layer profile with the one
 * specified.  And since we're changing the lower layer stuff,
 * we need to first deactivate the current upper layer profile.
 * An upper layer profile will be reactivated later, when we get
 * confirmation that the new llp is fully up (has an address
 * assigned).
 *
 * If the new llp is the same as the currently active one, don't
 * do anything.
 *
 * Called only by the main thread.
 */
void
llp_swap(llp_t *newllp, libnwam_diag_cause_t cause)
{
	int minpri;

	if (newllp == link_layer_profile)
		return;

	deactivate_upper_layer_profile();

	if (link_layer_profile != NULL) {
		dprintf("taking down current link layer profile (%s)",
		    llp_prnm(link_layer_profile));
		report_llp_unselected(link_layer_profile->llp_lname, cause);
		link_layer_profile->llp_waiting = B_FALSE;
		link_layer_profile = NULL;
	}

	/*
	 * Establish the new link layer profile.  If we have trouble setting
	 * it, then try to get another.  Note that llp_activate sets llp_failed
	 * on failure, so this loop is guaranteed to terminate.
	 */
	while (newllp != NULL) {
		dprintf("bringing up new link layer profile (%s)",
		    llp_prnm(newllp));
		llp_activate(newllp);
		newllp = NULL;
		if (link_layer_profile == NULL &&
		    (newllp = llp_best_avail()) != NULL &&
		    newllp->llp_failed)
			newllp = NULL;
	}

	/*
	 * Knock down all interfaces that are at a lower (higher-numbered)
	 * priority than the new one.  If there isn't a new one, then leave
	 * everything as it is.
	 */
	if (link_layer_profile == NULL) {
		minpri = -1;
		if (locked_llp != NULL)
			dprintf("taking down all but %s", llp_prnm(locked_llp));
	} else {
		minpri = link_layer_profile->llp_pri;
		dprintf("taking down remaining interfaces below priority %d",
		    minpri);
	}
	for (newllp = (llp_t *)llp_list.q_forw; newllp != (llp_t *)&llp_list;
	    newllp = (llp_t *)newllp->llp_links.q_forw) {
		if (newllp == link_layer_profile)
			continue;
		if ((link_layer_profile != NULL && newllp->llp_pri > minpri) ||
		    (locked_llp != NULL && newllp != locked_llp))
			takedowninterface(newllp->llp_lname, cause);
		else
			clear_cached_address(newllp->llp_lname);
	}
}

/*
 * Create the named LLP with default settings.  Called only in main thread.
 */
llp_t *
llp_add(const char *name)
{
	int retv;
	llp_t *llp;

	if ((llp = calloc(1, sizeof (llp_t))) == NULL) {
		syslog(LOG_ERR, "cannot allocate LLP: %m");
		return (NULL);
	}

	if (strlcpy(llp->llp_lname, name, sizeof (llp->llp_lname)) >=
	    sizeof (llp->llp_lname)) {
		syslog(LOG_ERR, "llp: link name '%s' too long; ignoring entry",
		    name);
		free(llp);
		return (NULL);
	}

	llp->llp_fileorder = llp->llp_pri =
	    atomic_add_32_nv(&llp_highest_pri, 1);
	llp->llp_ipv4src = IPV4SRC_DHCP;
	llp->llp_type = find_if_type(llp->llp_lname);
	llp->llp_ipv6onlink = B_TRUE;

	/*
	 * should be a no-op, but for now, make sure we only
	 * create llps for wired and wireless interfaces.
	 */
	if (llp->llp_type != IF_WIRED && llp->llp_type != IF_WIRELESS) {
		syslog(LOG_ERR, "llp: wrong type of interface for %s", name);
		free(llp);
		return (NULL);
	}

	if ((retv = pthread_mutex_lock(&llp_lock)) != 0) {
		/* Something very serious is wrong... */
		syslog(LOG_ERR, "llp: cannot lock mutex: %s", strerror(retv));
		free(llp);
		return (NULL);
	}

	insque(&llp->llp_links, llp_list.q_back);

	(void) pthread_mutex_unlock(&llp_lock);

	dprintf("created llp for link %s, priority %d", llp->llp_lname,
	    llp->llp_pri);
	return (llp);
}

/*
 * Walker function to pass to walk_interface() to find out if
 * an interface description is missing from LLPFILE.  If it is,
 * add it.
 *
 * Currently, IF_TUN type interfaces are special-cased: they are
 * only handled as user-enabled, layered links (which may be created
 * as part of a higher-layer profile, for example).  Thus, they
 * shouldn't be considered when looking at the llp list, so don't
 * add them here.
 *
 * ifs_lock is held when this function is called.  Called only in main thread.
 */
static void
find_and_add_llp(struct interface *ifp, void *arg)
{
	FILE *fp = arg;

	if (ifp->if_type != IF_TUN && llp_lookup(ifp->if_name) == NULL) {
		switch (ifp->if_family) {
		case AF_INET:
			(void) fprintf(fp, "%s\tdhcp\n", ifp->if_name);
			break;

		case AF_INET6:
			(void) fprintf(fp, "%s\tipv6\n", ifp->if_name);
			break;

		default:
			syslog(LOG_ERR, "interface %s family %d?!",
			    ifp->if_name, ifp->if_family);
			return;
		}
		dprintf("Added %s to %s", ifp->if_name, LLPFILE);
		/* If we run out of memory, ignore this interface for now. */
		(void) llp_add(ifp->if_name);
	}
}

static void
print_llp_list(void)
{
	llp_t *wp;

	dprintf("Walking llp list");
	for (wp = (llp_t *)llp_list.q_forw; wp != (llp_t *)&llp_list;
	    wp = (llp_t *)wp->llp_links.q_forw)
		dprintf("==> %s", wp->llp_lname);
}

/*
 * This function parses /etc/nwam/llp which describes the phase 0 link layer
 * profile.  The file is line oriented with each line containing tab or space
 * delimited fields.  Each address family (IPv4, IPv6) is described on a
 * separate line.
 * The first field is a link name.
 * The second field can be either static, dhcp, ipv6, noipv6, or priority.
 * If the second field is static then the next field is an ipv4 address which
 *    can contain a prefix.  Previous versions of this file could contain a
 *    hostname in this field which is no longer supported.
 * If the second field is dhcp then dhcp will be used on the interface.
 * If the second field is ipv6 then an ipv6 interface is plumbed up.  The
 *    outcome of this is that if offered by the network in.ndpd and dhcp
 *    will conspire to put addresses on additional ipv6 logical interfaces.
 *    If the next field is non-null then it is taken to be an IPv6 address
 *    and possible prefix which are applied to the interface.
 * If the second field is noipv6 then no ipv6 interfaces will be put on that
 *    link.
 * If the second field is priority, then the next field is an integer
 *    specifying the link priority.
 *
 * Called only in main thread.
 */
void
llp_parse_config(void)
{
	static const char STATICSTR[] = "static";
	static const char DHCP[] = "dhcp";
	static const char IPV6[] = "ipv6";
	static const char NOIPV6[] = "noipv6";
	static const char PRIORITY[] = "priority";
	FILE *fp;
	char line[LINE_MAX];
	char *cp, *lasts, *lstr, *srcstr, *addrstr;
	int lnum;
	llp_t *llp;

	/* Create the NWAM directory in case it does not exist. */
	if (mkdir(LLPDIRNAME, LLPDIRMODE) != 0 &&
	    errno != EEXIST) {
		syslog(LOG_ERR, "could not create %s: %m", LLPDIRNAME);
		return;
	}

	fp = fopen(LLPFILE, "r+");
	if (fp == NULL) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "open LLP config file: %m");
			return;
		}
		if ((fp = fopen(LLPFILE, "w+")) == NULL) {
			syslog(LOG_ERR, "create LLP config file: %m");
			return;
		}
	}

	llp_list_free();

	for (lnum = 1; fgets(line, sizeof (line), fp) != NULL; lnum++) {
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		cp = line;
		while (isspace(*cp))
			cp++;

		if (*cp == '#' || *cp == '\0')
			continue;

		dprintf("parsing llp conf file line %d...", lnum);

		if (((lstr = strtok_r(cp, " \t", &lasts)) == NULL) ||
		    ((srcstr = strtok_r(NULL, " \t", &lasts)) == NULL)) {
			syslog(LOG_ERR, "llp:%d: not enough tokens; "
			    "ignoring entry", lnum);
			continue;
		}

		if ((llp = llp_lookup(lstr)) == NULL &&
		    (llp = llp_add(lstr)) == NULL) {
			syslog(LOG_ERR, "llp:%d: cannot add entry", lnum);
			continue;
		}

		if (strcasecmp(srcstr, STATICSTR) == 0) {
			if ((addrstr = strtok_r(NULL, " \t", &lasts)) == NULL ||
			    atoi(addrstr) == 0) { /* crude check for number */
				syslog(LOG_ERR, "llp:%d: missing ipaddr "
				    "for static config", lnum);
			} else if ((addrstr = strdup(addrstr)) == NULL) {
				syslog(LOG_ERR, "llp:%d: cannot save address",
				    lnum);
			} else {
				free(llp->llp_ipv4addrstr);
				llp->llp_ipv4src = IPV4SRC_STATIC;
				llp->llp_ipv4addrstr = addrstr;
			}

		} else if (strcasecmp(srcstr, DHCP) == 0) {
			llp->llp_ipv4src = IPV4SRC_DHCP;

		} else if (strcasecmp(srcstr, IPV6) == 0) {
			llp->llp_ipv6onlink = B_TRUE;
			if ((addrstr = strtok_r(NULL, " \t", &lasts)) == NULL) {
				(void) 0;
			} else if ((addrstr = strdup(addrstr)) == NULL) {
				syslog(LOG_ERR, "llp:%d: cannot save address",
				    lnum);
			} else {
				free(llp->llp_ipv6addrstr);
				llp->llp_ipv6addrstr = addrstr;
			}

		} else if (strcasecmp(srcstr, NOIPV6) == 0) {
			llp->llp_ipv6onlink = B_FALSE;

		} else if (strcasecmp(srcstr, PRIORITY) == 0) {
			if ((addrstr = strtok_r(NULL, " \t", &lasts)) == NULL) {
				syslog(LOG_ERR,
				    "llp:%d: missing priority value", lnum);
			} else {
				llp->llp_pri = atoi(addrstr);
			}

		} else {
			syslog(LOG_ERR, "llp:%d: unrecognized field '%s'", lnum,
			    srcstr);
		}
	}

	/*
	 * So we have read in the llp file, is there an interface which
	 * it does not describe?  If yes, we'd better add it to the
	 * file for future reference.
	 */
	walk_interface(find_and_add_llp, fp);

	(void) fclose(fp);

	print_llp_list();
}

/*
 * Called only from the main thread.
 */
void
llp_add_file(const llp_t *llp)
{
	FILE *fp;

	if ((fp = fopen(LLPFILE, "a")) == NULL)
		return;
	(void) fprintf(fp, "%s\tdhcp\n", llp->llp_lname);
	(void) fclose(fp);
}

/*
 * This function rewrites the LLP configuration file entry for a given
 * interface and keyword.  If the keyword is present, then it is updated if
 * removeonly is B_FALSE, otherwise it's removed.  If the keyword is not
 * present, then it is added immediately after the last entry for that
 * interface if removeonly is B_FALSE, otherwise no action is taken.  User
 * comments are preserved.
 *
 * To preserve file integrity, this is called only from the main thread.
 */
static void
llp_update_config(const char *ifname, const char *keyword, const char *optval,
    boolean_t removeonly)
{
	FILE *fpin, *fpout;
	char line[LINE_MAX];
	char *cp, *lstr, *keystr, *valstr, *lasts;
	boolean_t matched_if, copying;
	long match_pos;

	if ((fpin = fopen(LLPFILE, "r")) == NULL)
		return;
	if ((fpout = fopen(LLPFILETMP, "w")) == NULL) {
		syslog(LOG_ERR, "create LLP temporary config file: %m");
		(void) fclose(fpin);
		return;
	}
	matched_if = copying = B_FALSE;
restart:
	while (fgets(line, sizeof (line), fpin) != NULL) {
		cp = line + strlen(line) - 1;
		if (cp >= line && *cp == '\n')
			*cp = '\0';

		cp = line;
		while (isspace(*cp))
			cp++;

		lstr = NULL;
		if (copying || *cp == '#' ||
		    (lstr = strtok_r(cp, " \t", &lasts)) == NULL ||
		    strcmp(lstr, ifname) != 0) {
			if (!matched_if || copying) {
				/*
				 * It's ugly to write through the pointer
				 * returned as the third argument of strtok_r,
				 * but doing so saves a data copy.
				 */
				if (lstr != NULL && lasts != NULL)
					lasts[-1] = '\t';
				(void) fprintf(fpout, "%s\n", line);
			}
			continue;
		}

		if (lasts != NULL)
			lasts[-1] = '\t';

		/*
		 * If we've found the keyword, then process removal or update
		 * of the value.
		 */
		if ((keystr = strtok_r(NULL, " \t", &lasts)) != NULL &&
		    strcmp(keystr, keyword) == 0) {
			matched_if = copying = B_TRUE;
			if (removeonly)
				continue;
			valstr = strtok_r(NULL, " \t", &lasts);
			if ((valstr == NULL && optval == NULL) ||
			    (valstr != NULL && optval != NULL &&
			    strcmp(valstr, optval) == 0)) {
				/* Value identical; abort update */
				goto no_change;
			}
			if (optval == NULL) {
				(void) fprintf(fpout, "%s\t%s\n", ifname,
				    keyword);
			} else {
				(void) fprintf(fpout, "%s\t%s %s\n", ifname,
				    keyword, optval);
			}
			continue;
		}

		/* Otherwise, record the last possible insertion point */
		matched_if = B_TRUE;
		match_pos = ftell(fpin);
		if (lasts != NULL)
			lasts[-1] = '\t';
		(void) fprintf(fpout, "%s\n", line);
	}
	if (!copying) {
		/* keyword not encountered; we're done if deleting */
		if (removeonly)
			goto no_change;
		/* need to add keyword and value */
		if (optval == NULL) {
			(void) fprintf(fpout, "%s\t%s\n", ifname, keyword);
		} else {
			(void) fprintf(fpout, "%s\t%s %s\n", ifname, keyword,
			    optval);
		}
		/* copy the rest of the file */
		(void) fseek(fpin, match_pos, SEEK_SET);
		copying = B_TRUE;
		goto restart;
	}
	(void) fclose(fpin);
	(void) fclose(fpout);
	if (rename(LLPFILETMP, LLPFILE) != 0) {
		syslog(LOG_ERR, "rename LLP temporary config file: %m");
		(void) unlink(LLPFILETMP);
	}
	return;

no_change:
	(void) fclose(fpin);
	(void) fclose(fpout);
	(void) unlink(LLPFILETMP);
}

/*
 * This is called back from the main thread by the state machine.
 */
void
llp_write_changed_priority(llp_t *llp)
{
	if (llp->llp_pri == llp->llp_fileorder) {
		llp_update_config(llp->llp_lname, "priority", NULL, B_TRUE);
	} else {
		char prival[32];

		(void) snprintf(prival, sizeof (prival), "%d", llp->llp_pri);
		llp_update_config(llp->llp_lname, "priority", prival, B_FALSE);
	}
}

/*
 * Called by the door interface: set LLP priority and schedule an LLP update if
 * this interface has changed.
 */
int
set_llp_priority(const char *ifname, int prio)
{
	llp_t *llp;
	int retv;

	if (prio < 0)
		return (EINVAL);

	if ((retv = pthread_mutex_lock(&llp_lock)) != 0)
		return (retv);
	if ((llp = llp_lookup(ifname)) != NULL) {
		llp->llp_failed = B_FALSE;
		if (llp->llp_pri != prio) {
			llp->llp_pri = prio;
			(void) np_queue_add_event(EV_USER, ifname);
		}
		retv = 0;
	} else {
		retv = ENXIO;
	}
	(void) pthread_mutex_unlock(&llp_lock);
	return (retv);
}

/*
 * Called by the door interface: set a locked LLP and schedule an LLP update if
 * the locked LLP has changed.
 */
int
set_locked_llp(const char *ifname)
{
	llp_t *llp;
	int retv;

	if ((retv = pthread_mutex_lock(&llp_lock)) != 0)
		return (retv);
	if (ifname[0] == '\0') {
		if (locked_llp != NULL) {
			ifname = locked_llp->llp_lname;
			locked_llp = NULL;
			(void) np_queue_add_event(EV_USER, ifname);
		}
	} else if ((llp = llp_lookup(ifname)) != NULL) {
		locked_llp = llp;
		if (llp != link_layer_profile)
			(void) np_queue_add_event(EV_USER, ifname);
	} else {
		retv = ENXIO;
	}
	(void) pthread_mutex_unlock(&llp_lock);
	return (retv);
}

/* Copy string to pre-allocated buffer. */
static void
strinsert(char **dest, const char *src, char **buf)
{
	if (*dest != NULL) {
		*dest = strcpy(*buf, src);
		*buf += strlen(src) + 1;
	}
}

/*
 * Sample the list of LLPs and copy to a single buffer for return through the
 * door interface.
 */
llp_t *
get_llp_list(size_t *lsize, uint_t *countp, char *selected, char *locked)
{
	llp_t *llplist, *llpl, *llp;
	char *strptr;
	uint_t nllp;
	size_t strspace;
	int retv;

	*lsize = 0;
	if ((retv = pthread_mutex_lock(&llp_lock)) != 0) {
		errno = retv;
		return (NULL);
	}
	(void) strlcpy(selected, link_layer_profile == NULL ? "" :
	    link_layer_profile->llp_lname, LIFNAMSIZ);
	(void) strlcpy(locked, locked_llp == NULL ? "" :
	    locked_llp->llp_lname, LIFNAMSIZ);
	nllp = 0;
	strspace = 0;
	for (llp = (llp_t *)llp_list.q_forw; llp != (llp_t *)&llp_list;
	    llp = (llp_t *)llp->llp_links.q_forw) {
		nllp++;
		if (llp->llp_ipv4addrstr != NULL)
			strspace += strlen(llp->llp_ipv4addrstr) + 1;
		if (llp->llp_ipv6addrstr != NULL)
			strspace += strlen(llp->llp_ipv6addrstr) + 1;
	}
	*countp = nllp;
	/* Note that malloc doesn't guarantee a NULL return for zero count */
	llplist = nllp == 0 ? NULL :
	    malloc(sizeof (*llplist) * nllp + strspace);
	if (llplist != NULL) {
		*lsize = sizeof (*llplist) * nllp + strspace;
		llpl = llplist;
		strptr = (char *)(llplist + nllp);
		for (llp = (llp_t *)llp_list.q_forw; llp != (llp_t *)&llp_list;
		    llp = (llp_t *)llp->llp_links.q_forw) {
			*llpl = *llp;
			strinsert(&llpl->llp_ipv4addrstr, llp->llp_ipv4addrstr,
			    &strptr);
			strinsert(&llpl->llp_ipv6addrstr, llp->llp_ipv6addrstr,
			    &strptr);
			llpl++;
		}
	}
	(void) pthread_mutex_unlock(&llp_lock);

	/* Add in the special door-only state flags */
	llpl = llplist;
	while (nllp-- > 0) {
		get_interface_state(llpl->llp_lname, &llpl->llp_dhcp_failed,
		    &llpl->llp_link_up);
		if (llpl->llp_type == IF_WIRELESS) {
			get_wireless_state(llpl->llp_lname,
			    &llpl->llp_need_wlan, &llpl->llp_need_key);
		}
		llpl++;
	}
	return (llplist);
}

/*
 * This is called for the special case when there are outstanding requests sent
 * to the user interface, and the user interface disappears.  We handle this
 * case by re-running bringupinterface() without deselecting.  That function
 * will call the wireless and DHCP-related parts again, and they should proceed
 * in automatic mode, because the UI is now gone.
 *
 * Called only by the main thread or by a thread holding machine_lock.
 */
void
llp_reselect(void)
{
	llp_t *llp;
	const char *host;

	/*
	 * If there's no active profile, or if the active profile isn't waiting
	 * on the UI, then just return; nothing to do.
	 */
	if ((llp = link_layer_profile) == NULL || !llp->llp_waiting)
		return;

	host = (llp->llp_ipv4src == IPV4SRC_DHCP) ? "dhcp" :
	    llp->llp_ipv4addrstr;

	dprintf("llp_reselect: bringing up %s", llp_prnm(llp));
	switch (bringupinterface(llp->llp_lname, host, llp->llp_ipv6addrstr,
	    llp->llp_ipv6onlink)) {
	case SUCCESS:
		llp->llp_failed = B_FALSE;
		llp->llp_waiting = B_FALSE;
		dprintf("llp_reselect: activated llp for %s", llp_prnm(llp));
		break;
	case FAILURE:
		llp->llp_failed = B_TRUE;
		llp->llp_waiting = B_FALSE;
		dprintf("llp_reselect: failed to bring up %s", llp_prnm(llp));
		report_llp_unselected(llp->llp_lname, dcFailed);
		link_layer_profile = NULL;
		break;
	case WAITING:
		llp->llp_failed = B_FALSE;
		dprintf("llp_reselect: waiting for %s", llp_prnm(llp));
	}
}

/*
 * This is used by the wireless module to check on the selected LLP.  We don't
 * do periodic rescans if a wireless interface is current and if its connection
 * state is good.
 */
void
llp_get_name_and_type(char *ifname, size_t ifnlen,
    libnwam_interface_type_t *iftype)
{
	*ifname = '\0';
	*iftype = IF_UNKNOWN;

	if (pthread_mutex_lock(&llp_lock) == 0) {
		if (link_layer_profile != NULL) {
			(void) strlcpy(ifname, link_layer_profile->llp_lname,
			    ifnlen);
			*iftype = link_layer_profile->llp_type;
		}
		(void) pthread_mutex_unlock(&llp_lock);
	}
}

/*
 * This is called by the interface.c module to check if an interface needs to
 * run DHCP.  It's intentionally called without ifs_lock held.
 */
libnwam_ipv4src_t
llp_get_ipv4src(const char *ifname)
{
	libnwam_ipv4src_t src = IPV4SRC_DHCP;
	llp_t *llp;

	if (pthread_mutex_lock(&llp_lock) == 0) {
		if ((llp = llp_lookup(ifname)) != NULL)
			src = llp->llp_ipv4src;
		(void) pthread_mutex_unlock(&llp_lock);
	}
	return (src);
}

/*
 * Dump out the LLP state via debug messages.
 */
void
print_llp_status(void)
{
	llp_t *llp;

	if (pthread_mutex_lock(&llp_lock) == 0) {
		if (link_layer_profile == NULL)
			dprintf("no LLP selected");
		else
			dprintf("LLP %s selected",
			    link_layer_profile->llp_lname);
		if (locked_llp == NULL)
			dprintf("no LLP locked");
		else
			dprintf("LLP %s locked", locked_llp->llp_lname);
		for (llp = (llp_t *)llp_list.q_forw;
		    llp != (llp_t *)&llp_list;
		    llp = (llp_t *)llp->llp_links.q_forw) {
			dprintf("LLP %s pri %d file order %d type %d "
			    "%sfailed %swaiting src %d v4addr %s v6addr %s "
			    "v6 %son-link",
			    llp->llp_lname, llp->llp_pri, llp->llp_fileorder,
			    (int)llp->llp_type, llp->llp_failed ? "" : "not ",
			    llp->llp_waiting ? "" : "not ",
			    (int)llp->llp_ipv4src,
			    STRING(llp->llp_ipv4addrstr),
			    STRING(llp->llp_ipv6addrstr),
			    llp->llp_ipv6onlink ? "not " : "");
		}
		(void) pthread_mutex_unlock(&llp_lock);
	}
}
