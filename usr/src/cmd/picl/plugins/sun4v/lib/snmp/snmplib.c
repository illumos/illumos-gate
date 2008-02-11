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

/*
 * The snmp library helps to prepare the PDUs and communicate with
 * the snmp agent on the SP side via the ds_snmp driver.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <sys/ds_snmp.h>

#include "libpiclsnmp.h"
#include "snmplib.h"
#include "asn1.h"
#include "pdu.h"
#include "debug.h"

#pragma init(libpiclsnmp_init)		/* need this in .init */

/*
 * Data from the MIB is fetched based on the hints about object
 * groups received from (possibly many threads in) the application.
 * However, the fetched data is kept in a common cache for use across
 * all threads, so even a GETBULK is issued only when absolutely
 * necessary.
 *
 * Note that locking is not fine grained (there's no locking per row)
 * since we don't expect too many MT consumers right away.
 *
 */
static mutex_t	mibcache_lock;
static nvlist_t	**mibcache = NULL;
static uint_t	n_mibcache_rows = 0;

static mutex_t snmp_reqid_lock;
static int snmp_reqid = 1;

#ifdef SNMP_DEBUG
uint_t snmp_nsends = 0;
uint_t snmp_sentbytes = 0;
uint_t snmp_nrecvs = 0;
uint_t snmp_rcvdbytes = 0;
#endif

#ifdef USE_SOCKETS
#define	SNMP_DEFAULT_PORT	161
#define	SNMP_MAX_RECV_PKTSZ	(64 * 1024)
#endif

/*
 * Static function declarations
 */
static void	libpiclsnmp_init(void);

static int	lookup_int(char *, int, int *, int);
static int	lookup_str(char *, int, char **, int);
static int	lookup_bitstr(char *, int, uchar_t **, uint_t *, int);

static oidgroup_t *locate_oid_group(struct picl_snmphdl *, char *);
static int	search_oid_in_group(char *, char *, int);

static snmp_pdu_t *fetch_single(struct picl_snmphdl *, char *, int, int *);
static snmp_pdu_t *fetch_next(struct picl_snmphdl *, char *, int, int *);
static void	fetch_bulk(struct picl_snmphdl *, char *, int, int, int, int *);
static int	fetch_single_str(struct picl_snmphdl *, char *, int,
		    char **, int *);
static int	fetch_single_int(struct picl_snmphdl *, char *, int,
		    int *, int *);
static int	fetch_single_bitstr(struct picl_snmphdl *, char *, int,
		    uchar_t **, uint_t *, int *);

static int	snmp_send_request(struct picl_snmphdl *, snmp_pdu_t *, int *);
static int	snmp_recv_reply(struct picl_snmphdl *, snmp_pdu_t *, int *);

static int	mibcache_realloc(int);
static void	mibcache_populate(snmp_pdu_t *, int);
static char	*oid_to_oidstr(oid *, size_t);


static void
libpiclsnmp_init(void)
{
	(void) mutex_init(&mibcache_lock, USYNC_THREAD, NULL);
	if (mibcache_realloc(0) < 0)
		(void) mutex_destroy(&mibcache_lock);

	(void) mutex_init(&snmp_reqid_lock, USYNC_THREAD, NULL);

	LOGINIT();
}

picl_snmphdl_t
snmp_init()
{
	struct picl_snmphdl	*smd;
#ifdef USE_SOCKETS
	int	sbuf = (1 << 15);	/* 16K */
	int	rbuf = (1 << 17);	/* 64K */
	char	*snmp_agent_addr;
#endif

	smd = (struct picl_snmphdl *)calloc(1, sizeof (struct picl_snmphdl));
	if (smd == NULL)
		return (NULL);

#ifdef USE_SOCKETS
	if ((snmp_agent_addr = getenv("SNMP_AGENT_IPADDR")) == NULL)
		return (NULL);

	if ((smd->fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		return (NULL);

	(void) setsockopt(smd->fd, SOL_SOCKET, SO_SNDBUF, &sbuf, sizeof (int));
	(void) setsockopt(smd->fd, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof (int));

	memset(&smd->agent_addr, 0, sizeof (struct sockaddr_in));
	smd->agent_addr.sin_family = AF_INET;
	smd->agent_addr.sin_port = htons(SNMP_DEFAULT_PORT);
	smd->agent_addr.sin_addr.s_addr = inet_addr(snmp_agent_addr);
#else
	smd->fd = open(DS_SNMP_DRIVER, O_RDWR);
	if (smd->fd < 0) {
		free(smd);
		return (NULL);
	}
#endif

	return ((picl_snmphdl_t)smd);
}

void
snmp_fini(picl_snmphdl_t hdl)
{
	struct picl_snmphdl	*smd = (struct picl_snmphdl *)hdl;

	if (smd) {
		if (smd->fd >= 0) {
			(void) close(smd->fd);
		}
		free(smd);
	}
}

int
snmp_reinit(picl_snmphdl_t hdl, int clr_linkreset)
{
	struct picl_snmphdl *smd = (struct picl_snmphdl *)hdl;
	nvlist_t *nvl;
	int i;

	(void) mutex_lock(&mibcache_lock);

	for (i = 0; i < n_mibcache_rows; i++) {
		if ((nvl = mibcache[i]) != NULL)
			nvlist_free(nvl);
	}

	n_mibcache_rows = 0;
	if (mibcache) {
		free(mibcache);
		mibcache = NULL;
	}

	(void) mutex_unlock(&mibcache_lock);

	if (clr_linkreset) {
		if (smd == NULL || smd->fd < 0)
			return (-1);
		else
			return (ioctl(smd->fd, DSSNMP_CLRLNKRESET, NULL));
	}

	return (0);
}

void
snmp_register_group(picl_snmphdl_t hdl, char *oidstrs, int n_oids, int is_vol)
{
	struct picl_snmphdl *smd = (struct picl_snmphdl *)hdl;
	oidgroup_t	*oidg;
	oidgroup_t	*curr, *prev;
	char		*p;
	int		i, sz;

	/*
	 * Allocate a new oidgroup_t
	 */
	oidg = (oidgroup_t *)calloc(1, sizeof (struct oidgroup));
	if (oidg == NULL)
		return;

	/*
	 * Determine how much space is required to register this group
	 */
	sz = 0;
	p = oidstrs;
	for (i = 0; i < n_oids; i++) {
		sz += strlen(p) + 1;
		p = oidstrs + sz;
	}

	/*
	 * Create this oid group
	 */
	if ((p = (char *)malloc(sz)) == NULL) {
		free((void *) oidg);
		return;
	}

	(void) memcpy(p, oidstrs, sz);

	oidg->next = NULL;
	oidg->oidstrs = p;
	oidg->n_oids = n_oids;
	oidg->is_volatile = is_vol;

	/*
	 * Link it to the tail of the list of oid groups
	 */
	for (prev = NULL, curr = smd->group; curr; curr = curr->next)
		prev = curr;

	if (prev == NULL)
		smd->group = oidg;
	else
		prev->next = oidg;
}

/*
 * snmp_get_int() takes in an OID and returns the integer value
 * of the object referenced in the passed arg. It returns 0 on
 * success and -1 on failure.
 */
int
snmp_get_int(picl_snmphdl_t hdl, char *prefix, int row, int *val,
    int *snmp_syserr)
{
	struct picl_snmphdl *smd = (struct picl_snmphdl *)hdl;
	oidgroup_t	*grp;
	int	ret;
	int	err = 0;

	if (smd == NULL || prefix == NULL || val == NULL)
		return (-1);

	/*
	 * If this item should not be cached, fetch it directly from
	 * the agent using fetch_single_xxx()
	 */
	if ((grp = locate_oid_group(smd, prefix)) == NULL) {
		ret = fetch_single_int(smd, prefix, row, val, &err);

		if (snmp_syserr)
			*snmp_syserr = err;

		return (ret);
	}

	/*
	 * is it in the cache ?
	 */
	if (lookup_int(prefix, row, val, grp->is_volatile) == 0)
		return (0);

	/*
	 * fetch it from the agent and populate the cache
	 */
	fetch_bulk(smd, grp->oidstrs, grp->n_oids, row, grp->is_volatile, &err);
	if (snmp_syserr)
		*snmp_syserr = err;

	/*
	 * look it up again and return it
	 */
	if (lookup_int(prefix, row, val, grp->is_volatile) < 0)
		return (-1);

	return (0);
}

/*
 * snmp_get_str() takes in an OID and returns the string value
 * of the object referenced in the passed arg. Memory for the string
 * is allocated within snmp_get_str() and is expected to be freed by
 * the caller when it is no longer needed. The function returns 0
 * on success and -1 on failure.
 */
int
snmp_get_str(picl_snmphdl_t hdl, char *prefix, int row, char **strp,
    int *snmp_syserr)
{
	struct picl_snmphdl *smd = (struct picl_snmphdl *)hdl;
	oidgroup_t	*grp;
	char	*val;
	int	ret;
	int	err = 0;

	if (smd == NULL || prefix == NULL || strp == NULL)
		return (-1);

	/*
	 * Check if this item is cacheable or not. If not, call
	 * fetch_single_* to get it directly from the agent
	 */
	if ((grp = locate_oid_group(smd, prefix)) == NULL) {
		ret = fetch_single_str(smd, prefix, row, strp, &err);

		if (snmp_syserr)
			*snmp_syserr = err;

		return (ret);
	}

	/*
	 * See if it's in the cache already
	 */
	if (lookup_str(prefix, row, &val, grp->is_volatile) == 0) {
		if ((*strp = strdup(val)) == NULL)
			return (-1);
		else
			return (0);
	}

	/*
	 * Fetch it from the agent and populate cache
	 */
	fetch_bulk(smd, grp->oidstrs, grp->n_oids, row, grp->is_volatile, &err);
	if (snmp_syserr)
		*snmp_syserr = err;

	/*
	 * Retry lookup
	 */
	if (lookup_str(prefix, row, &val, grp->is_volatile) < 0)
		return (-1);


	if ((*strp = strdup(val)) == NULL)
		return (-1);
	else
		return (0);
}

/*
 * snmp_get_bitstr() takes in an OID and returns the bit string value
 * of the object referenced in the passed args. Memory for the bitstring
 * is allocated within the function and is expected to be freed by
 * the caller when it is no longer needed. The function returns 0
 * on success and -1 on failure.
 */
int
snmp_get_bitstr(picl_snmphdl_t hdl, char *prefix, int row, uchar_t **bitstrp,
    uint_t *nbytes, int *snmp_syserr)
{
	struct picl_snmphdl *smd = (struct picl_snmphdl *)hdl;
	oidgroup_t	*grp;
	uchar_t	*val;
	int	ret;
	int	err = 0;

	if (smd == NULL || prefix == NULL || bitstrp == NULL || nbytes == NULL)
		return (-1);

	/*
	 * Check if this item is cacheable or not. If not, call
	 * fetch_single_* to get it directly from the agent
	 */
	if ((grp = locate_oid_group(smd, prefix)) == NULL) {
		ret = fetch_single_bitstr(smd, prefix, row, bitstrp,
		    nbytes, &err);

		if (snmp_syserr)
			*snmp_syserr = err;

		return (ret);
	}

	/*
	 * See if it's in the cache already
	 */
	if (lookup_bitstr(prefix, row, &val, nbytes, grp->is_volatile) == 0) {
		if ((*bitstrp = (uchar_t *)calloc(*nbytes, 1)) == NULL)
			return (-1);
		(void) memcpy(*bitstrp, (const void *)val, *nbytes);
		return (0);
	}

	/*
	 * Fetch it from the agent and populate cache
	 */
	fetch_bulk(smd, grp->oidstrs, grp->n_oids, row, grp->is_volatile, &err);
	if (snmp_syserr)
		*snmp_syserr = err;

	/*
	 * Retry lookup
	 */
	if (lookup_bitstr(prefix, row, &val, nbytes, grp->is_volatile) < 0)
		return (-1);

	if ((*bitstrp = (uchar_t *)calloc(*nbytes, 1)) == NULL)
		return (-1);
	(void) memcpy(*bitstrp, (const void *)val, *nbytes);

	return (0);
}

/*
 * snmp_get_nextrow() is similar in operation to SNMP_GETNEXT, but
 * only just. In particular, this is only expected to return the next
 * valid row number for the same object, not its value. Since we don't
 * have any other means, we use this to determine the number of rows
 * in the table (and the valid ones). This function returns 0 on success
 * and -1 on failure.
 */
int
snmp_get_nextrow(picl_snmphdl_t hdl, char *prefix, int row, int *nextrow,
    int *snmp_syserr)
{
	struct picl_snmphdl *smd = (struct picl_snmphdl *)hdl;
	snmp_pdu_t *reply_pdu;
	pdu_varlist_t *vp;
	char	*nxt_oidstr;
	int	err = 0;

	if (smd == NULL || prefix == NULL || nextrow == NULL) {
		if (snmp_syserr)
			*snmp_syserr = EINVAL;
		return (-1);
	}

	/*
	 * The get_nextrow results should *never* go into any cache,
	 * since these relationships are dynamically discovered each time.
	 */
	if ((reply_pdu = fetch_next(smd, prefix, row, &err)) == NULL) {
		if (snmp_syserr)
			*snmp_syserr = err;
		return (-1);
	}

	/*
	 * We are not concerned about the "value" of the lexicographically
	 * next object; we only care about the name of that object and
	 * its row number (and whether such an object exists or not).
	 */
	vp = reply_pdu->vars;

	/*
	 * This indicates that we're at the end of the MIB view.
	 */
	if (vp == NULL || vp->name == NULL || vp->type == SNMP_NOSUCHOBJECT ||
	    vp->type == SNMP_NOSUCHINSTANCE || vp->type == SNMP_ENDOFMIBVIEW) {
		snmp_free_pdu(reply_pdu);
		if (snmp_syserr)
			*snmp_syserr = ENOSPC;
		return (-1);
	}

	/*
	 * need to be able to convert the OID
	 */
	if ((nxt_oidstr = oid_to_oidstr(vp->name, vp->name_len - 1)) == NULL) {
		snmp_free_pdu(reply_pdu);
		if (snmp_syserr)
			*snmp_syserr = ENOMEM;
		return (-1);
	}

	/*
	 * We're on to the next table.
	 */
	if (strcmp(nxt_oidstr, prefix) != 0) {
		free(nxt_oidstr);
		snmp_free_pdu(reply_pdu);
		if (snmp_syserr)
			*snmp_syserr = ENOENT;
		return (-1);
	}

	/*
	 * Ok, so we've got an oid that's simply the next valid row of the
	 * passed on object, return this row number.
	 */
	*nextrow = (vp->name)[vp->name_len-1];

	free(nxt_oidstr);
	snmp_free_pdu(reply_pdu);

	return (0);
}

/*
 * Request ids for snmp messages to the agent are sequenced here.
 */
int
snmp_get_reqid(void)
{
	int	ret;

	(void) mutex_lock(&snmp_reqid_lock);

	ret = snmp_reqid++;

	(void) mutex_unlock(&snmp_reqid_lock);

	return (ret);
}

static int
lookup_int(char *prefix, int row, int *valp, int is_vol)
{
	int32_t	*val_arr;
	uint_t	nelem;
	struct timeval tv;
	int	elapsed;

	(void) mutex_lock(&mibcache_lock);

	if (row >= n_mibcache_rows) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	if (mibcache[row] == NULL) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	/*
	 * If this is a volatile property, we should be searching
	 * for an integer-timestamp pair
	 */
	if (is_vol) {
		if (nvlist_lookup_int32_array(mibcache[row], prefix,
		    &val_arr, &nelem) != 0) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}
		if (nelem != 2 || val_arr[1] < 0) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}
		if (gettimeofday(&tv, NULL) < 0) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}
		elapsed = tv.tv_sec - val_arr[1];
		if (elapsed < 0 || elapsed > MAX_INCACHE_TIME) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}

		*valp = (int)val_arr[0];
	} else {
		if (nvlist_lookup_int32(mibcache[row], prefix, valp) != 0) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}
	}

	(void) mutex_unlock(&mibcache_lock);

	return (0);
}

static int
lookup_str(char *prefix, int row, char **valp, int is_vol)
{
	char	**val_arr;
	uint_t	nelem;
	struct timeval tv;
	int	elapsed;

	(void) mutex_lock(&mibcache_lock);

	if (row >= n_mibcache_rows) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	if (mibcache[row] == NULL) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	/*
	 * If this is a volatile property, we should be searching
	 * for a string-timestamp pair
	 */
	if (is_vol) {
		if (nvlist_lookup_string_array(mibcache[row], prefix,
		    &val_arr, &nelem) != 0) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}
		if (nelem != 2 || atoi(val_arr[1]) <= 0) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}
		if (gettimeofday(&tv, NULL) < 0) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}
		elapsed = tv.tv_sec - atoi(val_arr[1]);
		if (elapsed < 0 || elapsed > MAX_INCACHE_TIME) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}

		*valp = val_arr[0];
	} else {
		if (nvlist_lookup_string(mibcache[row], prefix, valp) != 0) {
			(void) mutex_unlock(&mibcache_lock);
			return (-1);
		}
	}

	(void) mutex_unlock(&mibcache_lock);

	return (0);
}

static int
lookup_bitstr(char *prefix, int row, uchar_t **valp, uint_t *nelem, int is_vol)
{
	(void) mutex_lock(&mibcache_lock);

	if (row >= n_mibcache_rows) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	if (mibcache[row] == NULL) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	/*
	 * We don't support volatile bit string values yet. The nvlist
	 * functions don't support bitstring arrays like they do charstring
	 * arrays, so we would need to do things in a convoluted way,
	 * probably by attaching the timestamp as part of the byte array
	 * itself. However, the need for volatile bitstrings isn't there
	 * yet, to justify the effort.
	 */
	if (is_vol) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	if (nvlist_lookup_byte_array(mibcache[row], prefix, valp, nelem) != 0) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	(void) mutex_unlock(&mibcache_lock);

	return (0);
}

static int
search_oid_in_group(char *prefix, char *oidstrs, int n_oids)
{
	char	*p;
	int	i;

	p = oidstrs;
	for (i = 0; i < n_oids; i++) {
		if (strcmp(p, prefix) == 0)
			return (0);

		p += strlen(p) + 1;
	}

	return (-1);
}

static oidgroup_t *
locate_oid_group(struct picl_snmphdl *smd, char *prefix)
{
	oidgroup_t	*grp;

	if (smd == NULL)
		return (NULL);

	if (smd->group == NULL)
		return (NULL);

	for (grp = smd->group; grp; grp = grp->next) {
		if (search_oid_in_group(prefix, grp->oidstrs,
		    grp->n_oids) == 0) {
			return (grp);
		}
	}

	return (NULL);
}

static int
fetch_single_int(struct picl_snmphdl *smd, char *prefix, int row, int *ival,
    int *snmp_syserr)
{
	snmp_pdu_t *reply_pdu;
	pdu_varlist_t *vp;

	if ((reply_pdu = fetch_single(smd, prefix, row, snmp_syserr)) == NULL)
		return (-1);

	/*
	 * Note that we don't make any distinction between unsigned int
	 * value and signed int value at this point, since we provide
	 * only snmp_get_int() at the higher level. While it is possible
	 * to provide an entirely separate interface such as snmp_get_uint(),
	 * that's quite unnecessary, because we don't do any interpretation
	 * of the received value. Besides, the sizes of int and uint are
	 * the same and the sizes of all pointers are the same (so val.iptr
	 * would be the same as val.uiptr in pdu_varlist_t). If/when we
	 * violate any of these assumptions, it will be time to add
	 * snmp_get_uint().
	 */
	vp = reply_pdu->vars;
	if (vp == NULL || vp->val.iptr == NULL) {
		snmp_free_pdu(reply_pdu);
		return (-1);
	}

	*ival = *(vp->val.iptr);

	snmp_free_pdu(reply_pdu);

	return (0);
}

static int
fetch_single_str(struct picl_snmphdl *smd, char *prefix, int row, char **valp,
    int *snmp_syserr)
{
	snmp_pdu_t *reply_pdu;
	pdu_varlist_t *vp;

	if ((reply_pdu = fetch_single(smd, prefix, row, snmp_syserr)) == NULL)
		return (-1);

	vp = reply_pdu->vars;
	if (vp == NULL || vp->val.str == NULL) {
		snmp_free_pdu(reply_pdu);
		return (-1);
	}

	*valp = strdup((const char *)(vp->val.str));

	snmp_free_pdu(reply_pdu);

	return (0);
}

static int
fetch_single_bitstr(struct picl_snmphdl *smd, char *prefix, int row,
    uchar_t **valp, uint_t *nelem, int *snmp_syserr)
{
	snmp_pdu_t *reply_pdu;
	pdu_varlist_t *vp;

	if ((reply_pdu = fetch_single(smd, prefix, row, snmp_syserr)) == NULL)
		return (-1);

	vp = reply_pdu->vars;
	if (vp == NULL || vp->val.str == NULL) {
		snmp_free_pdu(reply_pdu);
		return (-1);
	}

	if ((*valp = (uchar_t *)calloc(vp->val_len, 1)) == NULL) {
		snmp_free_pdu(reply_pdu);
		return (-1);
	}

	*nelem = vp->val_len;
	(void) memcpy(*valp, (const void *)(vp->val.str),
	    (size_t)(vp->val_len));

	snmp_free_pdu(reply_pdu);

	return (0);
}

static snmp_pdu_t *
fetch_single(struct picl_snmphdl *smd, char *prefix, int row, int *snmp_syserr)
{
	snmp_pdu_t	*pdu, *reply_pdu;

	LOGGET(TAG_CMD_REQUEST, prefix, row);

	if ((pdu = snmp_create_pdu(SNMP_MSG_GET, 0, prefix, 1, row)) == NULL)
		return (NULL);

	LOGPDU(TAG_REQUEST_PDU, pdu);

	if (snmp_make_packet(pdu) < 0) {
		snmp_free_pdu(pdu);
		return (NULL);
	}

	LOGPKT(TAG_REQUEST_PKT, pdu->req_pkt, pdu->req_pktsz);

	if (snmp_send_request(smd, pdu, snmp_syserr) < 0) {
		snmp_free_pdu(pdu);
		return (NULL);
	}

	if (snmp_recv_reply(smd, pdu, snmp_syserr) < 0) {
		snmp_free_pdu(pdu);
		return (NULL);
	}

	LOGPKT(TAG_RESPONSE_PKT, pdu->reply_pkt, pdu->reply_pktsz);

	reply_pdu = snmp_parse_reply(pdu->reqid, pdu->reply_pkt,
	    pdu->reply_pktsz);

	LOGPDU(TAG_RESPONSE_PDU, reply_pdu);

	snmp_free_pdu(pdu);

	return (reply_pdu);
}

static void
fetch_bulk(struct picl_snmphdl *smd, char *oidstrs, int n_oids,
    int row, int is_vol, int *snmp_syserr)
{
	snmp_pdu_t	*pdu, *reply_pdu;
	int		max_reps;

	LOGBULK(TAG_CMD_REQUEST, n_oids, oidstrs, row);

	/*
	 * If we're fetching volatile properties using BULKGET, don't
	 * venture to get multiple rows (passing max_reps=0 will make
	 * snmp_create_pdu() fetch SNMP_DEF_MAX_REPETITIONS rows)
	 */
	max_reps = is_vol ? 1 : 0;

	pdu = snmp_create_pdu(SNMP_MSG_GETBULK, max_reps, oidstrs, n_oids, row);
	if (pdu == NULL)
		return;

	LOGPDU(TAG_REQUEST_PDU, pdu);

	/*
	 * Make an ASN.1 encoded packet from the PDU information
	 */
	if (snmp_make_packet(pdu) < 0) {
		snmp_free_pdu(pdu);
		return;
	}

	LOGPKT(TAG_REQUEST_PKT, pdu->req_pkt, pdu->req_pktsz);

	/*
	 * Send the request packet to the agent
	 */
	if (snmp_send_request(smd, pdu, snmp_syserr) < 0) {
		snmp_free_pdu(pdu);
		return;
	}

	/*
	 * Receive response from the agent into the reply packet buffer
	 * in the request PDU
	 */
	if (snmp_recv_reply(smd, pdu, snmp_syserr) < 0) {
		snmp_free_pdu(pdu);
		return;
	}

	LOGPKT(TAG_RESPONSE_PKT, pdu->reply_pkt, pdu->reply_pktsz);

	/*
	 * Parse the reply, validate the response and create a
	 * reply-PDU out of the information. Populate the mibcache
	 * with the received values.
	 */
	reply_pdu = snmp_parse_reply(pdu->reqid, pdu->reply_pkt,
	    pdu->reply_pktsz);
	if (reply_pdu) {
		LOGPDU(TAG_RESPONSE_PDU, reply_pdu);

		if (reply_pdu->errstat == SNMP_ERR_NOERROR)
			mibcache_populate(reply_pdu, is_vol);

		snmp_free_pdu(reply_pdu);
	}

	snmp_free_pdu(pdu);
}

static snmp_pdu_t *
fetch_next(struct picl_snmphdl *smd, char *prefix, int row, int *snmp_syserr)
{
	snmp_pdu_t	*pdu, *reply_pdu;

	LOGNEXT(TAG_CMD_REQUEST, prefix, row);

	pdu = snmp_create_pdu(SNMP_MSG_GETNEXT, 0, prefix, 1, row);
	if (pdu == NULL)
		return (NULL);

	LOGPDU(TAG_REQUEST_PDU, pdu);

	if (snmp_make_packet(pdu) < 0) {
		snmp_free_pdu(pdu);
		return (NULL);
	}

	LOGPKT(TAG_REQUEST_PKT, pdu->req_pkt, pdu->req_pktsz);

	if (snmp_send_request(smd, pdu, snmp_syserr) < 0) {
		snmp_free_pdu(pdu);
		return (NULL);
	}

	if (snmp_recv_reply(smd, pdu, snmp_syserr) < 0) {
		snmp_free_pdu(pdu);
		return (NULL);
	}

	LOGPKT(TAG_RESPONSE_PKT, pdu->reply_pkt, pdu->reply_pktsz);

	reply_pdu = snmp_parse_reply(pdu->reqid, pdu->reply_pkt,
	    pdu->reply_pktsz);

	LOGPDU(TAG_RESPONSE_PDU, reply_pdu);

	snmp_free_pdu(pdu);

	return (reply_pdu);
}

static int
snmp_send_request(struct picl_snmphdl *smd, snmp_pdu_t *pdu, int *snmp_syserr)
{
	extern int	errno;
#ifdef USE_SOCKETS
	int		ret;
#endif

	if (smd->fd < 0)
		return (-1);

	if (pdu == NULL || pdu->req_pkt == NULL)
		return (-1);

#ifdef USE_SOCKETS
	ret = -1;
	while (ret < 0) {
		LOGIO(TAG_SENDTO, smd->fd, pdu->req_pkt, pdu->req_pktsz);

		ret = sendto(smd->fd, pdu->req_pkt, pdu->req_pktsz, 0,
		    (struct sockaddr *)&smd->agent_addr,
		    sizeof (struct sockaddr));
		if (ret < 0 && errno != EINTR) {
			return (-1);
		}
	}
#else
	LOGIO(TAG_WRITE, smd->fd, pdu->req_pkt, pdu->req_pktsz);

	if (write(smd->fd, pdu->req_pkt, pdu->req_pktsz) < 0) {
		if (snmp_syserr)
			*snmp_syserr = errno;
		return (-1);
	}
#endif

#ifdef SNMP_DEBUG
	snmp_nsends++;
	snmp_sentbytes += pdu->req_pktsz;
#endif

	return (0);
}

static int
snmp_recv_reply(struct picl_snmphdl *smd, snmp_pdu_t *pdu, int *snmp_syserr)
{
	struct dssnmp_info	snmp_info;
	size_t	pktsz;
	uchar_t	*pkt;
	extern int errno;
#ifdef USE_SOCKETS
	struct sockaddr_in 	from;
	int	fromlen;
	ssize_t	msgsz;
#endif

	if (smd->fd < 0 || pdu == NULL)
		return (-1);

#ifdef USE_SOCKETS
	if ((pkt = (uchar_t *)calloc(1, SNMP_MAX_RECV_PKTSZ)) == NULL)
		return (-1);

	fromlen = sizeof (struct sockaddr_in);

	LOGIO(TAG_RECVFROM, smd->fd, pkt, SNMP_MAX_RECV_PKTSZ);

	msgsz = recvfrom(smd->fd, pkt, SNMP_MAX_RECV_PKTSZ, 0,
	    (struct sockaddr *)&from, &fromlen);
	if (msgsz  < 0 || msgsz >= SNMP_MAX_RECV_PKTSZ) {
		free(pkt);
		return (-1);
	}

	pktsz = (size_t)msgsz;
#else
	LOGIO(TAG_IOCTL, smd->fd, DSSNMP_GETINFO, &snmp_info);

	/*
	 * The ioctl will block until we have snmp data available
	 */
	if (ioctl(smd->fd, DSSNMP_GETINFO, &snmp_info) < 0) {
		if (snmp_syserr)
			*snmp_syserr = errno;
		return (-1);
	}

	pktsz = snmp_info.size;
	if ((pkt = (uchar_t *)calloc(1, pktsz)) == NULL)
		return (-1);

	LOGIO(TAG_READ, smd->fd, pkt, pktsz);

	if (read(smd->fd, pkt, pktsz) < 0) {
		free(pkt);
		if (snmp_syserr)
			*snmp_syserr = errno;
		return (-1);
	}
#endif

	pdu->reply_pkt = pkt;
	pdu->reply_pktsz = pktsz;

#ifdef SNMP_DEBUG
	snmp_nrecvs++;
	snmp_rcvdbytes += pktsz;
#endif

	return (0);
}

static int
mibcache_realloc(int hint)
{
	uint_t		count = (uint_t)hint;
	nvlist_t	**p;

	if (hint < 0)
		return (-1);

	(void) mutex_lock(&mibcache_lock);

	if (hint < n_mibcache_rows) {
		(void) mutex_unlock(&mibcache_lock);
		return (0);
	}

	count =  ((count >> MIBCACHE_BLK_SHIFT) + 1) << MIBCACHE_BLK_SHIFT;

	p = (nvlist_t **)calloc(count, sizeof (nvlist_t *));
	if (p == NULL) {
		(void) mutex_unlock(&mibcache_lock);
		return (-1);
	}

	if (mibcache) {
		(void) memcpy((void *) p, (void *) mibcache,
		    n_mibcache_rows * sizeof (nvlist_t *));
		free((void *) mibcache);
	}

	mibcache = p;
	n_mibcache_rows = count;

	(void) mutex_unlock(&mibcache_lock);

	return (0);
}


/*
 * Scan each variable in the returned PDU's bindings and populate
 * the cache appropriately
 */
static void
mibcache_populate(snmp_pdu_t *pdu, int is_vol)
{
	pdu_varlist_t	*vp;
	int		row, ret;
	char		*oidstr;
	struct timeval	tv;
	int		tod;	/* in secs */
	char		tod_str[MAX_INT_LEN];
	int		ival_arr[2];
	char		*sval_arr[2];

	/*
	 * If we're populating volatile properties, we also store a
	 * timestamp with each property value. When we lookup, we
	 * check the current time against this timestamp to determine
	 * if we need to refetch the value or not (refetch if it has
	 * been in for far too long).
	 */
	if (is_vol) {
		if (gettimeofday(&tv, NULL) < 0)
			tod = -1;
		else
			tod = (int)tv.tv_sec;

		tod_str[0] = 0;
		(void) snprintf(tod_str, MAX_INT_LEN, "%d", tod);

		ival_arr[1] = tod;
		sval_arr[1] = (char *)tod_str;
	}

	for (vp = pdu->vars; vp; vp = vp->nextvar) {
		if (vp->type != ASN_INTEGER && vp->type != ASN_OCTET_STR &&
		    vp->type != ASN_BIT_STR) {
			continue;
		}

		if (vp->name == NULL || vp->val.str == NULL)
			continue;

		row = (vp->name)[vp->name_len-1];

		(void) mutex_lock(&mibcache_lock);

		if (row >= n_mibcache_rows) {
			(void) mutex_unlock(&mibcache_lock);
			if (mibcache_realloc(row) < 0)
				continue;
			(void) mutex_lock(&mibcache_lock);
		}
		ret = 0;
		if (mibcache[row] == NULL)
			ret = nvlist_alloc(&mibcache[row], NV_UNIQUE_NAME, 0);

		(void) mutex_unlock(&mibcache_lock);

		if (ret != 0)
			continue;

		/*
		 * Convert the standard OID form into an oid string that
		 * we can use as the key to lookup. Since we only search
		 * by the prefix (mibcache is really an array of nvlist_t
		 * pointers), ignore the leaf subid.
		 */
		oidstr = oid_to_oidstr(vp->name, vp->name_len - 1);
		if (oidstr == NULL)
			continue;

		(void) mutex_lock(&mibcache_lock);

		if (vp->type == ASN_INTEGER) {
			if (is_vol) {
				ival_arr[0] = *(vp->val.iptr);
				(void) nvlist_add_int32_array(mibcache[row],
				    oidstr, ival_arr, 2);
			} else {
				(void) nvlist_add_int32(mibcache[row],
				    oidstr, *(vp->val.iptr));
			}

		} else if (vp->type == ASN_OCTET_STR) {
			if (is_vol) {
				sval_arr[0] = (char *)vp->val.str;
				(void) nvlist_add_string_array(mibcache[row],
				    oidstr, sval_arr, 2);
			} else {
				(void) nvlist_add_string(mibcache[row],
				    oidstr, (const char *)(vp->val.str));
			}
		} else if (vp->type == ASN_BIT_STR) {
			/*
			 * We don't support yet bit string objects that are
			 * volatile values.
			 */
			if (!is_vol) {
				(void) nvlist_add_byte_array(mibcache[row],
				    oidstr, (uchar_t *)(vp->val.str),
				    (uint_t)vp->val_len);
			}
		}
		(void) mutex_unlock(&mibcache_lock);

		free(oidstr);
	}
}

static char *
oid_to_oidstr(oid *objid, size_t n_subids)
{
	char	*oidstr;
	char	subid_str[MAX_INT_LEN];
	int	i, isize;
	size_t	oidstr_sz;

	/*
	 * ugly, but for now this will have to do.
	 */
	oidstr_sz = sizeof (subid_str) * n_subids;
	oidstr = calloc(1, oidstr_sz);

	for (i = 0; i < n_subids; i++) {
		(void) memset(subid_str, 0, sizeof (subid_str));
		isize = snprintf(subid_str, sizeof (subid_str), "%d",
		    objid[i]);
		if (isize >= sizeof (subid_str))
			return (NULL);

		(void) strlcat(oidstr, subid_str, oidstr_sz);
		if (i < (n_subids - 1))
			(void) strlcat(oidstr, ".", oidstr_sz);
	}

	return (oidstr);
}
