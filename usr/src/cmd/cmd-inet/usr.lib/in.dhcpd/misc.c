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
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/dhcp.h>
#include <netdb.h>
#include <sys/mman.h>
#include <locale.h>
#include <tnf/probe.h>
#include <resolv.h>

#include "dhcpd.h"
#include "per_dnet.h"
#include "interfaces.h"

#ifdef	DEBUG
/*
 * Datastore debugging functions.
 *
 * A simple datastore simulation, using the magic DBG_MEMORY_NET network,
 * is provided, to test the program with minimal datastore overhead.
 * A concatenated reclist is used to speed record manipulation.
 * Note that other networks continue to pass-thru to libdhcpsvc, to allow
 * live comparison.
 */

/* Simple datastore database. */
typedef struct db {
	lease_t dn_lease;
	char	dn_cid[128];
	char	dn_macro[2];
	uchar_t	dn_cid_len;
	uchar_t	dn_flags;
} dbg_t;

typedef struct reclist {
	dn_rec_list_t d_reclist;
	dn_rec_t d_rec;
} dbg_rec_t;

#define		DBG_MAXTABLE	16
static dsvc_handle_t dbg_handle[DBG_MAXTABLE];	/* simulated handle */
static rwlock_t	dbg_lock[DBG_MAXTABLE];		/* locks */
static uint32_t	dbg_size = 4096;		/* table size */
static uint32_t	dbg_msize;			/* mapped size */
static uint32_t	dbg_mask = 0xFFFF;		/* table mask */

static uint32_t	dbg_cid = 0;			/* starting cid */
static uint32_t	dbg_flags = 0;			/* starting flags */
static uint32_t	dbg_lease = 0;			/* starting lease */
static char	dbg_macro = '1';		/* macro */
#endif	/* DEBUG */

int
dhcp_open_dd(dsvc_handle_t *handp, dsvc_datastore_t *ddp, dsvc_contype_t type,
    const char *name, uint_t flags)
{
#ifndef	DEBUG
	return (open_dd(handp, ddp, type, name, flags));

#else	/* DEBUG */
	int ret;
	int hind;
	int net;
	int pgmsk = sysconf(_SC_PAGESIZE) - 1;

	if (dbg_net && memcmp(name, dbg_net, strlen(dbg_net)) == 0) {
		for (net = 0, hind = strlen(dbg_net); name[hind] != '.'; hind++)
			net += (net * 10) + (name[hind] - '0');
		if (net > DBG_MAXTABLE)
			return (DSVC_NO_TABLE);

		if (dbg_handle[net] == NULL) {
			dbg_msize = (sizeof (dbg_t) * dbg_size + pgmsk) &
			    ~pgmsk;
			/* LINTED [alignment ok] */
			dbg_handle[net] = (dsvc_handle_t)mmap(0, dbg_msize,
			    PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
			if ((char *)dbg_handle[net] == MAP_FAILED) {
				dbg_handle[net] = NULL;
				return (DSVC_INVAL);
			}
		}
		*handp = (void *)net;
		ret = DSVC_SUCCESS;
	} else
		ret = open_dd(handp, ddp, type, name, flags);

	return (ret);
#endif	/* DEBUG */
}

int
dhcp_close_dd(dsvc_handle_t *handp)
{
#ifndef	DEBUG
	return (close_dd(handp));

#else	/* DEBUG */
	int ret;
	int hind = (int)*handp;

	if (dbg_net && hind >= 0 && hind < DBG_MAXTABLE) {
		if (dbg_handle[hind] != NULL) {
			(void) munmap((char *)dbg_handle[hind], dbg_msize);
			dbg_handle[hind] = (dsvc_handle_t)NULL;
			ret = DSVC_SUCCESS;
		}
	} else
		ret = close_dd(handp);

	return (ret);
#endif	/* DEBUG */
}

/*
 * Detach the element from a list, and return it. If the list is empty, NULL is
 * returned.
 */
dn_rec_list_t *
detach_dnrec_from_list(dn_rec_list_t *prevp, dn_rec_list_t *elemp,
    dn_rec_list_t **listpp)
{
	if (prevp == NULL) {
		if (elemp == *listpp && elemp != NULL) {
			/* head of the list */
			*listpp = (*listpp)->dnl_next;
			elemp->dnl_next = NULL;
		}
	} else if (prevp->dnl_next != NULL) {
		/* somewhere in the middle */
		prevp->dnl_next = elemp->dnl_next;
		elemp->dnl_next = NULL;
	} else
		assert(elemp == NULL);

	return (elemp);
}

/*
 * Attach an unattached element (elemp) to a list (*listpp).
 */
static void
attach_dnrec_to_list(dn_rec_list_t *elemp, dn_rec_list_t **listpp)
{
	if (*listpp != NULL)
		elemp->dnl_next = *listpp;
	*listpp = elemp;
}

/*
 * dhcp_lookup_dd: perform lookup_dd.
 */
static int
dhcp_lookup_dd(dsvc_handle_t hand, boolean_t partial, uint_t query,
    int count, const void *targetp, void **recordsp, uint_t *nrecordsp)
{
#ifndef	DEBUG
	return (lookup_dd(hand, partial, query, count, targetp, recordsp,
	    nrecordsp));

#else	/* DEBUG */
	int		ret;
	int 		hind = (int)hand;
	int 		ind;
	dn_rec_t	*inp;
	dn_rec_list_t	**outp = (dn_rec_list_t **)recordsp;
	dbg_t		*dbp;
	dbg_t		*endp;
	dbg_rec_t	*rp;
	dn_rec_t	*recp;
	dn_rec_list_t	*reclp;
	dbg_t		*dbg_db;

	if (dbg_net && hind >= 0 && hind < DBG_MAXTABLE) {
		dbg_db = (dbg_t *)dbg_handle[hind];

		if (outp)
			*outp = NULL;
		if (nrecordsp)
			*nrecordsp = 0;
		inp = (dn_rec_t *)targetp;

		(void) rw_rdlock(&dbg_lock[hind]);
		/*
		 * Simple linear search, aided by the fact that
		 * the server currently checks flags.
		 */
		if (DSVC_QISEQ(query, DN_QCIP)) {
			ind = inp->dn_cip.s_addr & dbg_mask;
			dbp = &dbg_db[ind];
			endp = &dbg_db[ind + 1];
		} else {
			ind = 0;
			dbp = dbg_db;
			endp = &dbg_db[dbg_size];
		}
		for (; dbp < endp; dbp++, ind++) {
			/*
			 * Initialize record. fields will be zero'd
			 * when initially mmap'd.
			 */
			if (dbp->dn_cid_len == 0) {
				/* Skip server address to avoid arp issues. */
				if (ind == (ntohl(server_ip.s_addr) % 256))
					continue;
				if (dbg_cid)
					(void) snprintf(dbp->dn_cid,
					    sizeof (dbp->dn_cid), "%8X",
					    dbg_cid++);
				dbp->dn_flags = dbg_flags;
				dbp->dn_lease = dbg_lease;
				dbp->dn_macro[0] = dbg_macro;
				dbp->dn_macro[1] = '\0';
				dbp->dn_cid_len = 1;
			}
			if (DSVC_QISEQ(query, DN_QCID) &&
			    (inp->dn_cid[0] != dbp->dn_cid[0] ||
			    memcmp(dbp->dn_cid, inp->dn_cid, inp->dn_cid_len)))
				continue;

			rp = (dbg_rec_t *)smalloc(sizeof (dbg_rec_t));
			reclp = &rp->d_reclist;
			recp = &rp->d_rec;

			if (nrecordsp)
				(*nrecordsp)++;

			reclp->dnl_rec = recp;
			recp->dn_lease = dbp->dn_lease;
			recp->dn_sip.s_addr = ntohl(owner_ip->s_addr);
			recp->dn_cip.s_addr = 0xd000000 + (hind << 16) + ind;
			recp->dn_cid_len = dbp->dn_cid_len;
			recp->dn_flags = dbp->dn_flags;
			recp->dn_macro[0] = dbp->dn_macro[0];
			recp->dn_macro[1] = '\0';
			if ((recp->dn_cid[0] = dbp->dn_cid[0]) != '\0')
				(void) memcpy(recp->dn_cid, dbp->dn_cid,
				    dbp->dn_cid_len);
			if (*outp == NULL)
				*outp = reclp;
			else {
				reclp->dnl_next = *outp;
				*outp = reclp;
			}
			if (count > 0 && nrecordsp && *nrecordsp >= count)
				break;
		}
		(void) rw_unlock(&dbg_lock[hind]);
		ret = DSVC_SUCCESS;
	} else
		ret = lookup_dd(hand, partial, query, count, targetp,
		    recordsp, nrecordsp);

	return (ret);
#endif	/* DEBUG */
}

int
dhcp_modify_dd_entry(dsvc_handle_t hand, const void *origp, void *newp)
{
#ifndef	DEBUG
	return (modify_dd_entry(hand, origp, newp));

#else	/* DEBUG */
	int 		ret;
	int 		hind = (int)hand;
	int 		ind;
	dn_rec_t	*dnp;
	dbg_t		*dbp;
	dbg_t		*dbg_db;

	if (dbg_net && hind >= 0 && hind < DBG_MAXTABLE) {
		dbg_db = (dbg_t *)dbg_handle[hind];

		dnp = (dn_rec_t *)newp;
		ind = dnp->dn_cip.s_addr & dbg_mask;
		dbp = &dbg_db[ind];
		(void) rw_wrlock(&dbg_lock[hind]);
		dbp->dn_lease = dnp->dn_lease;
		dbp->dn_cid_len = dnp->dn_cid_len;
		dbp->dn_flags = dnp->dn_flags;
		/*
		 * Performance: avoid routine call when NULL string
		 * is being copied.
		 */
		if ((dbp->dn_cid[0] = dnp->dn_cid[0]) != '\0')
			(void) memcpy(dbp->dn_cid, dnp->dn_cid,
			    dnp->dn_cid_len);
		(void) rw_unlock(&dbg_lock[hind]);
		ret = DSVC_SUCCESS;
	} else
		ret = modify_dd_entry(hand, origp, newp);

	return (ret);
#endif	/* DEBUG */
}

void
dhcp_free_dd_list(dsvc_handle_t hand, void *listp)
{
#ifndef	DEBUG
	free_dd_list(hand, listp);

#else	/* DEBUG */
	dn_rec_list_t *ptr;
	int hind = (int)hand;

	if (dbg_net && hind >= 0 && hind < DBG_MAXTABLE) {
		while ((ptr = listp) != NULL) {
			listp = ptr->dnl_next;
			free(ptr);
		}
	} else
		free_dd_list(hand, listp);
#endif	/* DEBUG */
}

/*
 * cmp_lrusort: qsort() comparison routine to sort lru list.
 */
static int
cmp_lrusort(const void *a, const void *b)
{
	dn_rec_list_t *r1 = *(dn_rec_list_t **)a;
	dn_rec_list_t *r2 = *(dn_rec_list_t **)b;

	if (r1->dnl_rec->dn_lease < r2->dnl_rec->dn_lease)
		return (-1);
	else if (r1->dnl_rec->dn_lease == r2->dnl_rec->dn_lease)
		return (0);
	else
		return (1);
}

/*
 * get_lrusort: quick sort of eligible lru container entries.
 */
static dn_rec_list_t *
get_lrusort(dsvc_dnet_t *pnd, dn_rec_list_t *lrup, uint_t *lrecords)
{
	size_t nel;
	size_t size = *lrecords * sizeof (dn_rec_list_t *);
	dn_rec_list_t *from, **to, *next, *freerec = NULL;
	dn_rec_list_t *lrupage;
	dn_rec_t *rp;
	time_t reuse_time = time(NULL) - min_lru;
	uint_t records = 0;
#ifndef	NDEBUG
	int cnt = 0;
#endif	/* !NDEBUG */

	(void) mutex_lock(&pnd->lrupage_mtx);
	if (pnd->lrupage == NULL || pnd->lrusize < size) {
		if (pnd->lrupage != NULL)
			free(pnd->lrupage);
		pnd->lrupage = (dn_rec_list_t **)smalloc(size);
		pnd->lrusize = size;
	}
	if ((to = pnd->lrupage) == NULL) {
		pnd->lrusize = 0;
		(void) mutex_unlock(&pnd->lrupage_mtx);
		return (lrup);
	}

	/*
	 * Build a list of entries, discarding those which are in use.
	 */
	*to = NULL;
	for (from = lrup; from != NULL; from = next) {
		next = from->dnl_next;
		rp = from->dnl_rec;
		if (rp->dn_lease > reuse_time ||
		    (rp->dn_flags & DN_FAUTOMATIC) ||
		    rp->dn_lease == DHCP_PERM) {
			from->dnl_next = freerec;
			freerec = from;
		} else {
			records++;
			*(to++) = from;
		}
		assert(++cnt <= *lrecords);
	}

	/*
	 * Sort any usable elements, and relink.
	 */
	nel = (int)(to - pnd->lrupage);
	if (nel > 0) {
		if (nel > 1)
			qsort(pnd->lrupage, nel, sizeof (dn_rec_list_t *),
			    cmp_lrusort);
		for (to = pnd->lrupage; nel > 0; to++, nel--)
			(*to)->dnl_next = *(to + 1);
		to--;
		(*to)->dnl_next = NULL;
	}

	/*
	 * Free any unusable elements, return any usable elements.
	 */
	if (freerec)
		dhcp_free_dd_list(pnd->dh, freerec);
	*lrecords = records;

	lrupage = *(pnd->lrupage);
	(void) mutex_unlock(&pnd->lrupage_mtx);
	return (lrupage);
}

/*
 * dhcp_lookup_dd_classify: perform lookup_dd(), or use existing records
 * if supplied, and classify the results based on the type of search criteria
 * being employed. Centralized policy for DN_FMANUAL and DN_FUNUSABLE flag
 * processing are implemented here. Classification is specialized
 * based on these specific search criteria:
 *
 *	S_CID		A CID match is requested. Perform DN_FMANUAL and
 *			DN_FUNUSABLE processing.
 *	S_FREE		A search for free records. Only examine first
 *			matching record.
 *	S_LRU		A search for lru records. Perform sort if needed,
 *			and only examine first matching record.
 *
 * A matching record is detached and returned if found (ok ||
 * manual + unusable). Other successful matches are returned in recordsp as
 * a cache.
 */
void *
dhcp_lookup_dd_classify(dsvc_dnet_t *pnd, boolean_t partial, uint_t query,
    int count, const dn_rec_t *targetp, void **recordsp, int searchtype)
{
	int		err;
	uint_t		rec_cnt = 0, manual = 0;
	dn_rec_t	*dnp;
	dn_rec_list_t	*nlp = NULL, *dnlp = NULL;
	dn_rec_list_t	*unulp = NULL;		/* list of unusables, !manual */
	dn_rec_list_t	*unu_m_lp = NULL;	/* list of unusable + manual */
	dn_rec_list_t	*m_lp = NULL;		/* list of manual records */
	dn_rec_list_t	*cachep = NULL;		/* match cache */
	struct in_addr	swapaddr;
	char		ntoab[INET_ADDRSTRLEN];

	/*
	 * Lookup records matching the specified criteria, or use
	 * records from a previous lookup supplied for classification.
	 */
	if (*recordsp == NULL) {

		TNF_PROBE_1_DEBUG(classify, "classify classify",
		    "classify_query%debug 'in func classify'",
		    tnf_long, query, query);

		err = dhcp_lookup_dd(pnd->dh, partial, query, count, targetp,
		    (void **)recordsp, &rec_cnt);

		TNF_PROBE_1_DEBUG(classify_cid_end, "classify classify_end",
		    "classify_end%debug 'in func classify'",
		    tnf_long, rec_cnt, rec_cnt);

		/*
		 * If any error occurs, mark the dsvc_dnet_t table
		 * for immediate close and reopen. Let the protocol
		 * perform recover, rather than attempting time-consuming
		 * in-place error recovery.
		 */
		if (err != DSVC_SUCCESS) {
			(void) mutex_lock(&pnd->pnd_mtx);
			pnd->flags |= DHCP_PND_ERROR;
			hash_Dtime(pnd->hand, 0);
			(void) mutex_unlock(&pnd->pnd_mtx);
#ifdef	DEBUG
			dhcpmsg(LOG_DEBUG, "classify failure %s\n",
				dhcpsvc_errmsg(err));
#endif	/* DEBUG */
			*recordsp = NULL;
			return (NULL);
		}

		/*
		 * For LRU classification, sort returned records based
		 * on dn_lease field. Discards records with valid lease
		 * times; adjusts rec_cnt accordingly.
		 */
		if (searchtype & S_LRU)
			*recordsp = get_lrusort(pnd, *recordsp, &rec_cnt);

	}

	/*
	 * Record classification: scan through all records, performing
	 * DN_FUNUSABLE and DN_FMANUAL processing. Note that most of the
	 * work has been performed by the datastore query. Remove the matching
	 * entry from the singlely-linked record list, for return. Free any
	 * non-matching entries prior to the match. Pass back any additional
	 * entries after the match in the recordsp pointer for possible re-use
	 * by the caching code.
	 */

	for (nlp = detach_dnrec_from_list(NULL, *recordsp,
	    (dn_rec_list_t **)recordsp); nlp != NULL;
	    nlp = detach_dnrec_from_list(NULL, *recordsp,
	    (dn_rec_list_t **)recordsp)) {
		/*
		 * If we find that there is a DN_FMANUAL entry that is
		 * DN_FUNUSABLE, we fail the request, when performing a
		 * CID search, even though there may be other CID matches. In
		 * the CID case, those other CID matches are errors, because
		 * there should be one and only one record for a client if that
		 * record is marked as being DN_FMANUALly assigned. We tell
		 * the user how many of those CID matches there are. If there
		 * are no DN_FMANUAL records, the first matching record which
		 * is USABLE wins.
		 */
		dnp = nlp->dnl_rec;
		if (dnp->dn_flags & DN_FUNUSABLE) {
			if ((searchtype & (S_CID|S_FREE|S_LRU)) == S_CID) {
				char	cidbuf[DHCP_MAX_OPT_SIZE];
				uint_t	blen = sizeof (cidbuf);

				(void) octet_to_hexascii(targetp->dn_cid,
				    targetp->dn_cid_len,
				    cidbuf, &blen);

				swapaddr.s_addr = htonl(dnp->dn_cip.s_addr);

				dhcpmsg(LOG_NOTICE, "(%1$s,%2$s) "
				    "currently marked as unusable.\n", cidbuf,
				    inet_ntop(AF_INET, &swapaddr, ntoab,
				    sizeof (ntoab)));
			}

			/* build list of unusable records */
			if (dnp->dn_flags & DN_FMANUAL) {
				attach_dnrec_to_list(nlp, &unu_m_lp);
				manual++;
			} else
				attach_dnrec_to_list(nlp, &unulp);
		} else {
			if (dnp->dn_flags & DN_FMANUAL) {
				attach_dnrec_to_list(nlp, &m_lp);
				manual++;
			} else
				attach_dnrec_to_list(nlp, &cachep);
			/*
			 * These searches do not require examining all
			 * matches.
			 */
			if (searchtype & (S_FREE|S_LRU))
				break;
		}
	}

	/*
	 * Warnings are printed for CID searches which end with
	 * DN_FUNUSABLE|DN_FMANUAL match(es).
	 */
	if (m_lp != NULL || unu_m_lp != NULL) {
		if (manual > 1) {
			char	cidbuf[DHCP_MAX_OPT_SIZE];
			uint_t	blen = sizeof (cidbuf);

			(void) octet_to_hexascii(targetp->dn_cid,
				targetp->dn_cid_len,
				cidbuf, &blen);
			dhcpmsg(LOG_WARNING,
			    "Manual allocation (%1$s) has %2$d other MANUAL"
			    " records. It should have 0.\n", cidbuf,
			    manual - 1);
		}
		if (unu_m_lp != NULL) {
			dnlp = detach_dnrec_from_list(NULL, unu_m_lp,
			    &unu_m_lp);
		} else
			dnlp = detach_dnrec_from_list(NULL, m_lp, &m_lp);
	}

	/* Free any unusable entries */
	if (unulp != NULL)
		dhcp_free_dd_list(pnd->dh, unulp);

	/* any other... */
	if (dnlp == NULL)
		dnlp = detach_dnrec_from_list(NULL, cachep, &cachep);

	/*
	 * Return any unused elements for possible caching use. These are
	 * the  additional manual + unusable (as punishment for having
	 * multiple items), manual, and and any others.
	 */
	if (cachep != NULL)
		attach_dnrec_to_list(cachep, (dn_rec_list_t **)recordsp);
	if (m_lp != NULL)
		attach_dnrec_to_list(m_lp, (dn_rec_list_t **)recordsp);
	if (unu_m_lp != NULL)
		attach_dnrec_to_list(unu_m_lp, (dn_rec_list_t **)recordsp);

	/*
	 * Return one of the matching record(s).
	 */
	return (dnlp);
}

/*
 * Error message function. If debugging off, then logging goes to
 * syslog.
 *
 * Must be MT SAFE - called by various threads as well as the main thread.
 */

/*VARARGS2*/
void
dhcpmsg(int errlevel, const char *fmtp, ...)
{
	char		buff[BUFSIZ], errbuf[BUFSIZ];
	const char *f = buff;
	va_list		ap;

	if (debug < 0)
		return;

	va_start(ap, fmtp);

	if (debug > 0)  {
		if (errlevel != LOG_ERR)
			(void) snprintf(errbuf, sizeof (errbuf),
			    "%lx: ", time(NULL));
		else
			(void) snprintf(errbuf, sizeof (errbuf),
			    "%lx: (%s)", time(NULL), strerror(errno));
		(void) snprintf(buff, sizeof (buff), "%s %s", errbuf,
		    gettext(fmtp));
		(void) vfprintf(stderr, f, ap);
	} else if (debug == 0)
		(void) vsyslog(errlevel, gettext(fmtp), ap);

	va_end(ap);
}

/*
 * smalloc()  --  safe malloc()
 *
 * Always returns a valid pointer(if it returns at all).  The allocated
 * memory is initialized to all zeros.  If malloc() returns an error, a
 * message is printed using the syslog() function and the program aborts
 * with a status of 1.
 *
 * Must be MT SAFE - called by threads other than the main thread.
 */
void *
smalloc(uint_t nbytes)
{
	char		*retvalue;

	if ((retvalue = calloc(nbytes, sizeof (char))) == NULL) {
		dhcpmsg(LOG_ERR, "Cannot allocate memory (%s), exiting\n",
		    strerror(errno));
		exit(1);
	}
	return (retvalue);
}

/*
 * srealloc()  --  safe realloc()
 *
 * Always returns a valid pointer(if it returns at all).
 * If realloc() returns an error, a message is printed using the syslog()
 * function and the program aborts with a status of 1.
 * Unlike smalloc(), does not initialize the buffer to all zeros.
 *
 * Must be MT SAFE - called by threads other than the main thread.
 */
void *
srealloc(void *arg, uint_t nbytes)
{
	if ((arg = realloc(arg, nbytes)) == NULL) {
		dhcpmsg(LOG_ERR, "Cannot allocate memory (%s), exiting\n",
		    strerror(errno));
		exit(1);
	}
	return (arg);
}

/*
 * Matches the speficied ip address with our owner_ip addresses.
 * Returns NULL if no match is found.
 */
struct in_addr *
match_ownerip(in_addr_t new)
{
	struct in_addr *oip = owner_ip;

	while (oip->s_addr != INADDR_ANY && oip->s_addr != new)
		oip++;
	return ((oip->s_addr != INADDR_ANY) ? oip : NULL);
}

/*
 * qualify_hostname()  --  concatenate host  "."  domain  "."  NULL
 */
int
qualify_hostname(char *fqname, const char *host, const char *domain,
    int host_length, int domain_length)
{
	char *fqptr;

	if (domain_length + host_length + 2 > NS_MAXDNAME) {
		dhcpmsg(LOG_ERR, "qualify_hostname: FQDN too long\n");
		return (-1);
	}

	fqptr = fqname;

	(void) memcpy(fqptr, host, host_length);
	fqptr += host_length;

	*fqptr = '.';
	fqptr++;

	(void) memcpy(fqptr, domain, domain_length);
	fqptr += domain_length;

	*fqptr = '.';
	*(fqptr+1) = '\0';

	return (0);
}
