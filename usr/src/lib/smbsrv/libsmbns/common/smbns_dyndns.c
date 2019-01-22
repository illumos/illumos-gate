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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <net/if.h>
#include <resolv.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <syslog.h>
#include <gssapi/gssapi.h>
#include <kerberosv5/krb5.h>

#include <smbns_dyndns.h>
#include <smbns_krb.h>

/*
 * The following can be removed once head/arpa/nameser_compat.h
 * defines BADSIG, BADKEY and BADTIME.
 */
#ifndef	BADSIG
#define	BADSIG ns_r_badsig
#endif /* BADSIG */

#ifndef	BADKEY
#define	BADKEY ns_r_badkey
#endif /* BADKEY */

#ifndef	BADTIME
#define	BADTIME ns_r_badtime
#endif /* BADTIME */

/* internal use, in dyndns_add_entry */
#define	DEL_NONE			2

/* Maximum retires if not authoritative */
#define	MAX_AUTH_RETRIES		3

/* Number of times to retry a DNS query */
#define	DYNDNS_MAX_QUERY_RETRIES	3

/* Timeout value, in seconds, for DNS query responses */
#define	DYNDNS_QUERY_TIMEOUT		2

static uint16_t dns_msgid;
mutex_t dns_msgid_mtx;

#define	DYNDNS_OP_CLEAR			1
#define	DYNDNS_OP_UPDATE		2

#define	DYNDNS_STATE_INIT		0
#define	DYNDNS_STATE_READY		1
#define	DYNDNS_STATE_PUBLISHING		2
#define	DYNDNS_STATE_STOPPING		3

typedef struct dyndns_qentry {
	list_node_t	dqe_lnd;
	int		dqe_op;
	/* fully-qualified domain name is in lower case */
	char		dqe_fqdn[MAXHOSTNAMELEN];
} dyndns_qentry_t;

typedef struct dyndns_queue {
	list_t		ddq_list;
	mutex_t		ddq_mtx;
	cond_t		ddq_cv;
	uint32_t	ddq_state;
} dyndns_queue_t;

static dyndns_queue_t dyndns_queue;

static void dyndns_queue_request(int, const char *);
static void dyndns_queue_flush(list_t *);
static void dyndns_process(list_t *);
static int dyndns_update_core(char *);
static int dyndns_clear_rev_zone(char *);
static void dyndns_msgid_init(void);
static int dyndns_get_msgid(void);
static void dyndns_syslog(int, int, const char *);

void
dyndns_start(void)
{
	(void) mutex_lock(&dyndns_queue.ddq_mtx);

	if (dyndns_queue.ddq_state != DYNDNS_STATE_INIT) {
		(void) mutex_unlock(&dyndns_queue.ddq_mtx);
		return;
	}

	dyndns_msgid_init();

	list_create(&dyndns_queue.ddq_list, sizeof (dyndns_qentry_t),
	    offsetof(dyndns_qentry_t, dqe_lnd));
	dyndns_queue.ddq_state = DYNDNS_STATE_READY;

	(void) mutex_unlock(&dyndns_queue.ddq_mtx);
}

void
dyndns_stop(void)
{
	(void) mutex_lock(&dyndns_queue.ddq_mtx);

	switch (dyndns_queue.ddq_state) {
	case DYNDNS_STATE_READY:
	case DYNDNS_STATE_PUBLISHING:
		dyndns_queue.ddq_state = DYNDNS_STATE_STOPPING;
		(void) cond_signal(&dyndns_queue.ddq_cv);
		break;
	default:
		break;
	}

	(void) mutex_unlock(&dyndns_queue.ddq_mtx);
}

/*
 * Clear all records in both zones.
 */
void
dyndns_clear_zones(void)
{
	char fqdn[MAXHOSTNAMELEN];

	if (smb_getfqdomainname(fqdn, MAXHOSTNAMELEN) != 0) {
		syslog(LOG_ERR, "dyndns: failed to get domainname");
		return;
	}

	dyndns_queue_request(DYNDNS_OP_CLEAR, fqdn);
}

/*
 * Update all records in both zones.
 */
void
dyndns_update_zones(void)
{
	char fqdn[MAXHOSTNAMELEN];

	if (smb_getfqdomainname(fqdn, MAXHOSTNAMELEN) != 0) {
		syslog(LOG_ERR, "dyndns: failed to get domainname");
		return;
	}

	dyndns_queue_request(DYNDNS_OP_UPDATE, fqdn);
}

/*
 * Add a request to the queue.
 *
 * To comply with RFC 4120 section 6.2.1, entry->dqe_fqdn is converted
 * to lower case.
 */
static void
dyndns_queue_request(int op, const char *fqdn)
{
	dyndns_qentry_t *entry;

	if (!smb_config_getbool(SMB_CI_DYNDNS_ENABLE))
		return;

	if ((entry = malloc(sizeof (dyndns_qentry_t))) == NULL)
		return;

	bzero(entry, sizeof (dyndns_qentry_t));
	entry->dqe_op = op;
	(void) strlcpy(entry->dqe_fqdn, fqdn, MAXNAMELEN);
	(void) smb_strlwr(entry->dqe_fqdn);

	(void) mutex_lock(&dyndns_queue.ddq_mtx);

	switch (dyndns_queue.ddq_state) {
	case DYNDNS_STATE_READY:
	case DYNDNS_STATE_PUBLISHING:
		list_insert_tail(&dyndns_queue.ddq_list, entry);
		(void) cond_signal(&dyndns_queue.ddq_cv);
		break;
	default:
		free(entry);
		break;
	}

	(void) mutex_unlock(&dyndns_queue.ddq_mtx);
}

/*
 * Flush all remaining items from the specified list/queue.
 */
static void
dyndns_queue_flush(list_t *lst)
{
	dyndns_qentry_t *entry;

	while ((entry = list_head(lst)) != NULL) {
		list_remove(lst, entry);
		free(entry);
	}
}

/*
 * Dyndns update thread.  While running, the thread waits on a condition
 * variable until notified that an entry needs to be updated.
 *
 * If the outgoing queue is not empty, the thread wakes up every 60 seconds
 * to retry.
 */
/*ARGSUSED*/
void *
dyndns_publisher(void *arg)
{
	dyndns_qentry_t *entry;
	list_t publist;

	(void) mutex_lock(&dyndns_queue.ddq_mtx);
	if (dyndns_queue.ddq_state != DYNDNS_STATE_READY) {
		(void) mutex_unlock(&dyndns_queue.ddq_mtx);
		return (NULL);
	}
	dyndns_queue.ddq_state = DYNDNS_STATE_PUBLISHING;
	(void) mutex_unlock(&dyndns_queue.ddq_mtx);

	list_create(&publist, sizeof (dyndns_qentry_t),
	    offsetof(dyndns_qentry_t, dqe_lnd));

	for (;;) {
		(void) mutex_lock(&dyndns_queue.ddq_mtx);

		while (list_is_empty(&dyndns_queue.ddq_list) &&
		    (dyndns_queue.ddq_state == DYNDNS_STATE_PUBLISHING)) {
			(void) cond_wait(&dyndns_queue.ddq_cv,
			    &dyndns_queue.ddq_mtx);
		}

		if (dyndns_queue.ddq_state != DYNDNS_STATE_PUBLISHING) {
			(void) mutex_unlock(&dyndns_queue.ddq_mtx);
			break;
		}

		/*
		 * Transfer queued items to the local list so that
		 * the mutex can be released.
		 */
		while ((entry = list_head(&dyndns_queue.ddq_list)) != NULL) {
			list_remove(&dyndns_queue.ddq_list, entry);
			list_insert_tail(&publist, entry);
		}

		(void) mutex_unlock(&dyndns_queue.ddq_mtx);

		dyndns_process(&publist);
	}

	(void) mutex_lock(&dyndns_queue.ddq_mtx);
	dyndns_queue_flush(&dyndns_queue.ddq_list);
	list_destroy(&dyndns_queue.ddq_list);
	dyndns_queue.ddq_state = DYNDNS_STATE_INIT;
	(void) mutex_unlock(&dyndns_queue.ddq_mtx);

	dyndns_queue_flush(&publist);
	list_destroy(&publist);
	return (NULL);
}

/*
 * Remove items from the queue and process them.
 */
static void
dyndns_process(list_t *publist)
{
	dyndns_qentry_t *entry;

	while ((entry = list_head(publist)) != NULL) {
		(void) mutex_lock(&dyndns_queue.ddq_mtx);
		if (dyndns_queue.ddq_state != DYNDNS_STATE_PUBLISHING) {
			(void) mutex_unlock(&dyndns_queue.ddq_mtx);
			dyndns_queue_flush(publist);
			return;
		}
		(void) mutex_unlock(&dyndns_queue.ddq_mtx);

		list_remove(publist, entry);

		switch (entry->dqe_op) {
		case DYNDNS_OP_CLEAR:
			(void) dyndns_clear_rev_zone(entry->dqe_fqdn);
			break;
		case DYNDNS_OP_UPDATE:
			(void) dyndns_update_core(entry->dqe_fqdn);
			break;
		default:
			break;
		}

		free(entry);
	}
}

/*
 * Dynamic DNS update API for kclient.
 *
 * Returns 0 upon success.  Otherwise, returns -1.
 */
int
dyndns_update(char *fqdn)
{
	int rc;

	if (smb_nic_init() != SMB_NIC_SUCCESS)
		return (-1);

	dyndns_msgid_init();
	(void) smb_strlwr(fqdn);
	rc = dyndns_update_core(fqdn);
	smb_nic_fini();
	return (rc);
}

/*
 * Initializes the DNS message ID counter using the algorithm
 * that resolver library uses to initialize the ID field of any res
 * structure.
 */
static void
dyndns_msgid_init(void)
{
	struct timeval now;

	(void) gettimeofday(&now, NULL);
	(void) mutex_lock(&dns_msgid_mtx);
	dns_msgid = (0xffff & (now.tv_sec ^ now.tv_usec ^ getpid()));
	(void) mutex_unlock(&dns_msgid_mtx);
}

static int
dyndns_get_msgid(void)
{
	uint16_t id;

	(void) mutex_lock(&dns_msgid_mtx);
	id = ++dns_msgid;
	(void) mutex_unlock(&dns_msgid_mtx);
	return (id);
}

/*
 * Log a DNS error message
 */
static void
dyndns_syslog(int severity, int errnum, const char *text)
{
	struct {
		int errnum;
		char *errmsg;
	} errtab[] = {
		{ FORMERR,  "message format error" },
		{ SERVFAIL, "server internal error" },
		{ NXDOMAIN, "entry should exist but does not exist" },
		{ NOTIMP,   "not supported" },
		{ REFUSED,  "operation refused" },
		{ YXDOMAIN, "entry should not exist but does exist" },
		{ YXRRSET,  "RRSet should not exist but does exist" },
		{ NXRRSET,  "RRSet should exist but does not exist" },
		{ NOTAUTH,  "server is not authoritative for specified zone" },
		{ NOTZONE,  "name not within specified zone" },
		{ BADSIG,   "bad transaction signature (TSIG)" },
		{ BADKEY,   "bad transaction key (TKEY)" },
		{ BADTIME,  "time not synchronized" },
	};

	char *errmsg = "unknown error";
	int i;

	if (errnum == NOERROR)
		return;

	for (i = 0; i < (sizeof (errtab) / sizeof (errtab[0])); ++i) {
		if (errtab[i].errnum == errnum) {
			errmsg = errtab[i].errmsg;
			break;
		}
	}

	syslog(severity, "dyndns: %s: %s: %d", text, errmsg, errnum);
}

/*
 * display_stat
 * Display GSS error message from error code.  This routine is used to display
 * the mechanism independent and mechanism specific error messages for GSS
 * routines.  The major status error code is the mechanism independent error
 * code and the minor status error code is the mechanism specific error code.
 * Parameters:
 *   maj: GSS major status
 *   min: GSS minor status
 * Returns:
 *   None
 */
static void
display_stat(OM_uint32 maj, OM_uint32 min)
{
	gss_buffer_desc msg;
	OM_uint32 msg_ctx = 0;
	OM_uint32 min2;

	(void) gss_display_status(&min2, maj, GSS_C_GSS_CODE, GSS_C_NULL_OID,
	    &msg_ctx, &msg);
	syslog(LOG_ERR, "dyndns: GSS major status error: %s",
	    (char *)msg.value);
	(void) gss_release_buffer(&min2, &msg);

	(void) gss_display_status(&min2, min, GSS_C_MECH_CODE, GSS_C_NULL_OID,
	    &msg_ctx, &msg);
	syslog(LOG_ERR, "dyndns: GSS minor status error: %s",
	    (char *)msg.value);
	(void) gss_release_buffer(&min2, &msg);
}

static char *
dyndns_put_nshort(char *buf, uint16_t val)
{
	uint16_t nval;

	nval = htons(val);
	(void) memcpy(buf, &nval, sizeof (uint16_t));
	buf += sizeof (uint16_t);
	return (buf);
}

static char *
dyndns_get_nshort(char *buf, uint16_t *val)
{
	uint16_t nval;

	(void) memcpy(&nval, buf, sizeof (uint16_t));
	*val = ntohs(nval);
	buf += sizeof (uint16_t);
	return (buf);
}

static char *
dyndns_put_nlong(char *buf, uint32_t val)
{
	uint32_t lval;

	lval = htonl(val);
	(void) memcpy(buf, &lval, sizeof (uint32_t));
	buf += sizeof (uint32_t);
	return (buf);
}

static char *
dyndns_put_byte(char *buf, char val)
{
	*buf = val;
	buf++;
	return (buf);
}




static char *
dyndns_put_int(char *buf, int val)
{
	(void) memcpy(buf, &val, sizeof (int));
	buf += sizeof (int);
	return (buf);
}

static char *
dyndns_put_v6addr(char *buf, smb_inaddr_t *val)
{

	val->a_family = AF_INET6;
	(void) memcpy(buf, &val->a_ipv6, IN6ADDRSZ);
	buf += IN6ADDRSZ;
	return (buf);
}
/*
 * dyndns_stuff_str
 * Converts a domain string by removing periods and replacing with a byte value
 * of how many characters following period.  A byte value is placed in front
 * to indicate how many characters before first period.  A NULL character is
 * placed at the end. i.e. host.procom.com -> 4host5procom3com0
 * Buffer space checking is done by caller.
 * Parameters:
 *   ptr : address of pointer to buffer to store converted string
 *   zone: domain name string
 * Returns:
 *   ptr: address of pointer to next available buffer space
 *   -1 : error
 *    0 : success
 */
static int
dyndns_stuff_str(char **ptr, char *zone)
{
	int len;
	char *lenPtr, *zonePtr;

	for (zonePtr = zone; *zonePtr; ) {
		lenPtr = *ptr;
		*ptr = *ptr + 1;
		len = 0;
		while (*zonePtr != '.' && *zonePtr != 0) {
			*ptr = dyndns_put_byte(*ptr, *zonePtr);
			zonePtr++;
			len++;
		}
		*lenPtr = len;
		if (*zonePtr == '.')
			zonePtr++;
	}
	*ptr = dyndns_put_byte(*ptr, 0);
	return (0);
}

/*
 * dyndns_build_header
 * Build the header for DNS query and DNS update request message.
 * Parameters:
 *   ptr               : address of pointer to buffer to store header
 *   buf_len           : buffer length
 *   msg_id            : message id
 *   query_req         : use REQ_QUERY for query message or REQ_UPDATE for
 *                       update message
 *   quest_zone_cnt    : number of question record for query message or
 *                       number of zone record for update message
 *   ans_prereq_cnt    : number of answer record for query message or
 *                       number of prerequisite record for update message
 *   nameser_update_cnt: number of name server for query message or
 *                       number of update record for update message
 *   addit_cnt         : number of additional record
 *   flags             : query flags word
 * Returns:
 *   ptr: address of pointer to next available buffer space
 *   -1 : error
 *    0 : success
 */
static int
dyndns_build_header(char **ptr, int buf_len, uint16_t msg_id, int query_req,
    uint16_t quest_zone_cnt, uint16_t ans_prereq_cnt,
    uint16_t nameser_update_cnt, uint16_t addit_cnt, int flags)
{
	uint16_t opcode;

	if (buf_len < 12) {
		syslog(LOG_ERR, "dyndns header section: buffer too small");
		return (-1);
	}

	*ptr = dyndns_put_nshort(*ptr, msg_id);	/* mesg ID */
	if (query_req == REQ_QUERY)
		opcode = ns_o_query;	/* query msg */
	else
		opcode = ns_o_update << 11;	/* update msg */
	opcode |= flags;
	/* mesg opcode */
	*ptr = dyndns_put_nshort(*ptr, opcode);
	/* zone record count */
	*ptr = dyndns_put_nshort(*ptr, quest_zone_cnt);
	/* prerequiste record count */
	*ptr = dyndns_put_nshort(*ptr, ans_prereq_cnt);
	/* update record count */
	*ptr = dyndns_put_nshort(*ptr, nameser_update_cnt);
	/* additional record count */
	*ptr = dyndns_put_nshort(*ptr, addit_cnt);

	return (0);
}

/*
 * dyndns_build_quest_zone
 * Build the question section for query message or zone section for
 * update message.
 * Parameters:
 *   ptr    : address of pointer to buffer to store question or zone section
 *   buf_len: buffer length
 *   name   : question or zone name
 *   type   : type of question or zone
 *   class  : class of question or zone
 * Returns:
 *   ptr: address of pointer to next available buffer space
 *   -1 : error
 *    0 : success
 */
static int
dyndns_build_quest_zone(char **ptr, int buf_len, char *name, int type,
	int class)
{
	char *zonePtr;

	if ((strlen(name) + 6) > buf_len) {
		syslog(LOG_ERR, "dyndns question section: buffer too small");
		return (-1);
	}

	zonePtr = *ptr;
	(void) dyndns_stuff_str(&zonePtr, name);
	*ptr = zonePtr;
	*ptr = dyndns_put_nshort(*ptr, type);
	*ptr = dyndns_put_nshort(*ptr, class);
	return (0);
}

/*
 * dyndns_build_update
 * Build update section of update message for adding and removing a record.
 * If the ttl value is 0 then this message is for record deletion.
 *
 * Parameters:
 *   ptr     : address of pointer to buffer to store update section
 *   buf_len : buffer length
 *   name    : resource name of this record
 *   type    : type of this record
 *   class   : class of this record
 *   ttl     : time-to-live, cached time of this entry by others and not
 *             within DNS database, a zero value for record(s) deletion
 *   data    : data of this resource record
 *   forw_rev: UPDATE_FORW for forward zone, UPDATE_REV for reverse zone
 *   add_del : UPDATE_ADD for adding entry, UPDATE_DEL for removing zone
 *   del_type: DEL_ONE for deleting one entry, DEL_ALL for deleting all
 *             entries of the same resource name.  Only valid for UPDATE_DEL.
 * Returns:
 *   ptr: address of pointer to next available buffer space
 *   -1 : error
 *    0 : success
 */
static int
dyndns_build_update(char **ptr, int buf_len, char *name, int type, int class,
	uint32_t ttl, char *data, int forw_rev, int add_del, int del_type)
{
	char *namePtr;
	int rec_len, data_len;
	smb_inaddr_t ipaddr;
	int isv4 = 1;

	rec_len = strlen(name) + 10;
	if (inet_pton(AF_INET, data, &ipaddr) == 1)
		isv4 = 1;
	else if (inet_pton(AF_INET6, data, &ipaddr) == 1)
		isv4 = 0;

	if (add_del == UPDATE_ADD) {
		if (forw_rev == UPDATE_FORW)
			data_len = isv4 ? 4 : 16;
		else
			data_len = strlen(data) + 2;
	} else {
		if (del_type == DEL_ALL)
			data_len = 0;
		else if (forw_rev == UPDATE_FORW)
			data_len = isv4 ? 4 : 16;
		else
			data_len = strlen(data) + 2;
	}
	if (rec_len + data_len > buf_len) {
		syslog(LOG_ERR, "dyndns update section: buffer too small");
		return (-1);
	}

	namePtr = *ptr;
	(void) dyndns_stuff_str(&namePtr, name);
	*ptr = namePtr;
	if (isv4)
		*ptr = dyndns_put_nshort(*ptr, type);
	else
		*ptr = dyndns_put_nshort(*ptr, ns_t_aaaa);
	*ptr = dyndns_put_nshort(*ptr, class);
	*ptr = dyndns_put_nlong(*ptr, ttl);

	if (add_del == UPDATE_DEL && del_type == DEL_ALL) {
		*ptr = dyndns_put_nshort(*ptr, 0);
		return (0);
	}

	if (forw_rev == UPDATE_FORW) {
		if (isv4) {
			*ptr = dyndns_put_nshort(*ptr, 4);
			*ptr = dyndns_put_int(*ptr, ipaddr.a_ipv4);
		} else {
			*ptr = dyndns_put_nshort(*ptr, 16);
			*ptr = dyndns_put_v6addr(*ptr, &ipaddr);
		}
	} else {
		*ptr = dyndns_put_nshort(*ptr, strlen(data)+2);
		namePtr = *ptr;
		(void) dyndns_stuff_str(&namePtr, data);	/* hostname */
		*ptr = namePtr;
	}
	return (0);
}

/*
 * dyndns_build_tkey
 * Build TKEY section to establish security context for secure dynamic DNS
 * update.  DNS header and question sections need to be build before this
 * section.  The TKEY data are the tokens generated during security context
 * establishment and the TKEY message is used to transmit those tokens, one
 * at a time, to the DNS server.
 * Parameters:
 *   ptr       : address of pointer to buffer to store TKEY
 *   buf_len   : buffer length
 *   name      : key name, must be unique and same as for TSIG record
 *   key_expire: expiration time of this key in second
 *   data      : TKEY data
 *   data_size : data size
 * Returns:
 *   ptr: address of the pointer to the next available buffer space
 *   -1 : error
 *    0 : success
 */
static int
dyndns_build_tkey(char **ptr, int buf_len, char *name, int key_expire,
	char *data, int data_size)
{
	char *namePtr;
	struct timeval tp;

	if (strlen(name)+2 + 45 + data_size > buf_len) {
		syslog(LOG_ERR, "dyndns TKEY: buffer too small");
		return (-1);
	}

	namePtr = *ptr;
	(void) dyndns_stuff_str(&namePtr, name);	/* unique global name */
	*ptr = namePtr;
	*ptr = dyndns_put_nshort(*ptr, ns_t_tkey);
	*ptr = dyndns_put_nshort(*ptr, ns_c_any);
	*ptr = dyndns_put_nlong(*ptr, 0);
	/* 19 + 14 + data_size + 2 */
	*ptr = dyndns_put_nshort(*ptr, 35 + data_size);
	namePtr = *ptr;
	(void) dyndns_stuff_str(&namePtr, "gss.microsoft.com");
	*ptr = namePtr;
	(void) gettimeofday(&tp, 0);
	*ptr = dyndns_put_nlong(*ptr, tp.tv_sec);	/* inception */
	/* expiration, 86400 */
	*ptr = dyndns_put_nlong(*ptr, tp.tv_sec + key_expire);
	*ptr = dyndns_put_nshort(*ptr, MODE_GSS_API);	/* mode: gss-api */
	*ptr = dyndns_put_nshort(*ptr, 0);		/* error */
	*ptr = dyndns_put_nshort(*ptr, data_size);	/* key size */
	(void) memcpy(*ptr, data, data_size);	/* key data */
	*ptr += data_size;
	*ptr = dyndns_put_nshort(*ptr, 0);	/* other */
	return (0);
}

/*
 * dyndns_build_tsig
 * Build TSIG section for secure dynamic DNS update.  This routine will be
 * called twice.  First called with TSIG_UNSIGNED, and second with TSIG_SIGNED.
 * The TSIG data is NULL and ignored for TSIG_UNSIGNED and is the update request
 * message encrypted for TSIG_SIGNED.  The message id must be the same id as the
 * one in the update request before it is encrypted.
 * Parameters:
 *   ptr        : address of pointer to buffer to store TSIG
 *   buf_len    : buffer length
 *   msg_id     : message id
 *   name       : key name, must be the same as in TKEY record
 *   fudge_time : amount of error time allow in seconds
 *   data       : TSIG data if TSIG_SIGNED, otherwise NULL
 *   data_size  : size of data, otherwise 0 if data is NULL
 *   data_signed: TSIG_SIGNED to indicate data is signed and encrypted,
 *                otherwise TSIG_UNSIGNED
 * Returns:
 *   ptr: address of pointer to next available buffer space
 *   -1 : error
 *    0 : success
 */
static int
dyndns_build_tsig(char **ptr, int buf_len, int msg_id, char *name,
	int fudge_time, char *data, int data_size, int data_signed)
{
	char *namePtr;
	struct timeval tp;
	int signtime, fudge, rec_len;

	if (data_signed == TSIG_UNSIGNED)
		rec_len = strlen(name)+2 + 37;
	else
		rec_len = strlen(name)+2 + 45 + data_size;

	if (rec_len > buf_len) {
		syslog(LOG_ERR, "dyndns TSIG: buffer too small");
		return (-1);
	}

	namePtr = *ptr;
	(void) dyndns_stuff_str(&namePtr, name);	/* unique global name */
	*ptr = namePtr;
	if (data_signed == TSIG_SIGNED)
		*ptr = dyndns_put_nshort(*ptr, ns_t_tsig);
	*ptr = dyndns_put_nshort(*ptr, ns_c_any);
	*ptr = dyndns_put_nlong(*ptr, 0);
	if (data_signed == TSIG_SIGNED) {
		/* 19 + 10 + data_size + 6 */
		*ptr = dyndns_put_nshort(*ptr, 35 + data_size);
	}
	namePtr = *ptr;
	(void) dyndns_stuff_str(&namePtr, "gss.microsoft.com");
	*ptr = namePtr;
	(void) gettimeofday(&tp, 0);
	signtime = tp.tv_sec >> 16;
	*ptr = dyndns_put_nlong(*ptr, signtime);	/* sign time */
	fudge = tp.tv_sec << 16;
	fudge |= fudge_time;
	*ptr = dyndns_put_nlong(*ptr, fudge);	/* fudge time */
	if (data_signed == TSIG_SIGNED) {
		/* signed data size */
		*ptr = dyndns_put_nshort(*ptr, data_size);
		(void) memcpy(*ptr, data, data_size);	/* signed data */
		*ptr += data_size;
		*ptr = dyndns_put_nshort(*ptr, msg_id);	/* original id */
	}
	*ptr = dyndns_put_nshort(*ptr, 0);	/* error */
	*ptr = dyndns_put_nshort(*ptr, 0);	/* other */
	return (0);
}

/*
 * dyndns_open_init_socket
 * This routine creates a SOCK_STREAM or SOCK_DGRAM socket and initializes it
 * by doing bind() and setting linger option to off.
 *
 * Parameters:
 *   sock_type: SOCK_STREAM for TCP or SOCK_DGRAM for UDP
 *   dest_addr: destination address in network byte order
 *   port     : destination port number
 * Returns:
 *   descriptor: descriptor referencing the created socket
 *   -1        : error
 */

static int
dyndns_open_init_socket(int sock_type, smb_inaddr_t *dest_addr, int port)
{
	int s;
	struct sockaddr_in my_addr;
	struct sockaddr_in6 my6_addr;
	struct sockaddr_in serv_addr;
	struct sockaddr_in6 serv6_addr;
	int family;

	family = dest_addr->a_family;

	if ((s = socket(family, sock_type, 0)) == -1) {
		syslog(LOG_ERR, "dyndns: socket error\n");
		return (-1);
	}
	if (family == AF_INET) {
		bzero(&my_addr, sizeof (my_addr));
		my_addr.sin_family = family;
		my_addr.sin_port = htons(0);
		my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(s, (struct sockaddr *)&my_addr,
		    sizeof (my_addr)) < 0) {
			syslog(LOG_ERR, "dyndns: client bind err\n");
			(void) close(s);
			return (-1);
		}
		serv_addr.sin_family = family;
		serv_addr.sin_port = htons(port);
		serv_addr.sin_addr.s_addr = dest_addr->a_ipv4;
		if (connect(s, (struct sockaddr *)&serv_addr,
		    sizeof (struct sockaddr_in)) < 0) {
			syslog(LOG_ERR, "dyndns: client connect (%s)\n",
			    strerror(errno));
			(void) close(s);
			return (-1);
		}
	} else {
		bzero(&my6_addr, sizeof (my6_addr));
		my6_addr.sin6_family = family;
		my6_addr.sin6_port = htons(0);
		bzero(&my6_addr.sin6_addr.s6_addr, IN6ADDRSZ);
		if (bind(s, (struct sockaddr *)&my6_addr,
		    sizeof (my6_addr)) < 0) {
			syslog(LOG_ERR, "dyndns: client bind err\n");
			(void) close(s);
			return (-1);
		}
		serv6_addr.sin6_family = family;
		serv6_addr.sin6_port = htons(port);
		bcopy(&serv6_addr.sin6_addr.s6_addr, &dest_addr->a_ipv6,
		    IN6ADDRSZ);
		if (connect(s, (struct sockaddr *)&serv6_addr,
		    sizeof (struct sockaddr_in6)) < 0) {
			syslog(LOG_ERR, "dyndns: client connect err (%s)\n",
			    strerror(errno));
			(void) close(s);
			return (-1);
		}
	}
	return (s);
}
/*
 * dyndns_build_tkey_msg
 * This routine is used to build the TKEY message to transmit GSS tokens
 * during GSS security context establishment for secure DNS update.  The
 * TKEY message format uses the DNS query message format.  The TKEY section
 * is the answer section of the query message format.
 * Microsoft uses a value of 86400 seconds (24 hours) for key expiration time.
 * Parameters:
 *   buf     : buffer to build and store TKEY message
 *   key_name: a unique key name, this same key name must be also be used in
 *             the TSIG message
 *   out_tok : TKEY message data (GSS tokens)
 * Returns:
 *   id          : message id of this TKEY message
 *   message size: the size of the TKEY message
 *   -1          : error
 */
static int
dyndns_build_tkey_msg(char *buf, char *key_name, uint16_t *id,
	gss_buffer_desc *out_tok)
{
	int queryReq, zoneCount, preqCount, updateCount, additionalCount;
	int zoneType, zoneClass;
	char *bufptr;

	queryReq = REQ_QUERY;
	/* query section of query request */
	zoneCount = 1;
	/* answer section of query request */
	preqCount = 1;
	updateCount = 0;
	additionalCount = 0;

	(void) memset(buf, 0, MAX_TCP_SIZE);
	bufptr = buf;
	*id = dyndns_get_msgid();

	/* add TCP length info that follows this field */
	bufptr = dyndns_put_nshort(bufptr,
	    26 + (strlen(key_name)+2)*2 + 35 + out_tok->length);

	if (dyndns_build_header(&bufptr, BUFLEN_TCP(bufptr, buf), *id, queryReq,
	    zoneCount, preqCount, updateCount, additionalCount, 0) == -1) {
		return (-1);
	}

	zoneType = ns_t_tkey;
	zoneClass = ns_c_in;
	if (dyndns_build_quest_zone(&bufptr, BUFLEN_TCP(bufptr, buf), key_name,
	    zoneType, zoneClass) == -1) {
		return (-1);
	}

	if (dyndns_build_tkey(&bufptr, BUFLEN_TCP(bufptr, buf), key_name,
	    86400, out_tok->value, out_tok->length) == -1) {
		return (-1);
	}

	return (bufptr - buf);
}

/*
 * dyndns_establish_sec_ctx
 * This routine is used to establish a security context with the DNS server
 * by building TKEY messages and sending them to the DNS server.  TKEY messages
 * are also received from the DNS server for processing.   The security context
 * establishment is done with the GSS client on the system producing a token
 * and sending the token within the TKEY message to the GSS server on the DNS
 * server.  The GSS server then processes the token and then send a TKEY reply
 * message with a new token to be processed by the GSS client.  The GSS client
 * processes the new token and then generates a new token to be sent to the
 * GSS server.  This cycle is continued until the security establishment is
 * done.  TCP is used to send and receive TKEY messages.
 * Parameters:
 *   cred_handle  : handle to credential
 *   s           : socket descriptor to DNS server
 *   key_name    : TKEY key name
 *   dns_hostname: fully qualified DNS hostname which will be used for
 *                 constructing the DNS service principal name.
 *   oid         : contains Kerberos 5 object identifier
 * Returns:
 *   gss_context    : handle to security context
 */
static int
dyndns_establish_sec_ctx(gss_ctx_id_t *gss_context, gss_cred_id_t cred_handle,
    int s, char *key_name, char *dns_hostname, gss_OID oid)
{
	uint16_t id, rid, rsz;
	char buf[MAX_TCP_SIZE], buf2[MAX_TCP_SIZE];
	int ret;
	char *service_name, *tmpptr;
	int service_sz;
	OM_uint32 min, maj, time_rec;
	gss_buffer_desc service_buf, in_tok, out_tok;
	gss_name_t target_name;
	gss_buffer_desc *inputptr;
	int gss_flags;
	OM_uint32 ret_flags;
	int buf_sz;

	service_sz = strlen(dns_hostname) + 5;
	service_name = (char *)malloc(sizeof (char) * service_sz);
	if (service_name == NULL)
		return (-1);

	(void) snprintf(service_name, service_sz, "DNS@%s", dns_hostname);
	service_buf.value = service_name;
	service_buf.length = strlen(service_name)+1;
	if ((maj = gss_import_name(&min, &service_buf,
	    GSS_C_NT_HOSTBASED_SERVICE, &target_name)) != GSS_S_COMPLETE) {
		display_stat(maj, min);
		(void) free(service_name);
		return (-1);
	}
	(void) free(service_name);

	inputptr = GSS_C_NO_BUFFER;
	*gss_context = GSS_C_NO_CONTEXT;
	gss_flags = GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG | GSS_C_REPLAY_FLAG |
	    GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
	do {
		maj = gss_init_sec_context(&min, cred_handle, gss_context,
		    target_name, oid, gss_flags, 0, NULL, inputptr, NULL,
		    &out_tok, &ret_flags, &time_rec);

		if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
			assert(gss_context);
			if (*gss_context != GSS_C_NO_CONTEXT)
				(void) gss_delete_sec_context(&min,
				    gss_context, NULL);

			display_stat(maj, min);
			(void) gss_release_name(&min, &target_name);
			return (-1);
		}

		if ((maj == GSS_S_COMPLETE) &&
		    !(ret_flags & GSS_C_REPLAY_FLAG)) {
			syslog(LOG_ERR, "dyndns: No GSS_C_REPLAY_FLAG");
			if (out_tok.length > 0)
				(void) gss_release_buffer(&min, &out_tok);
			(void) gss_release_name(&min, &target_name);
			return (-1);
		}

		if ((maj == GSS_S_COMPLETE) &&
		    !(ret_flags & GSS_C_MUTUAL_FLAG)) {
			syslog(LOG_ERR, "dyndns: No GSS_C_MUTUAL_FLAG");
			if (out_tok.length > 0)
				(void) gss_release_buffer(&min, &out_tok);
			(void) gss_release_name(&min, &target_name);
			return (-1);
		}

		if (out_tok.length > 0) {
			if ((buf_sz = dyndns_build_tkey_msg(buf, key_name,
			    &id, &out_tok)) <= 0) {
				(void) gss_release_buffer(&min, &out_tok);
				(void) gss_release_name(&min, &target_name);
				return (-1);
			}

			(void) gss_release_buffer(&min, &out_tok);

			if (send(s, buf, buf_sz, 0) == -1) {
				syslog(LOG_ERR, "dyndns: TKEY send error");
				(void) gss_release_name(&min, &target_name);
				return (-1);
			}

			bzero(buf2, MAX_TCP_SIZE);
			if (recv(s, buf2, MAX_TCP_SIZE, 0) == -1) {
				syslog(LOG_ERR, "dyndns: TKEY recv error");
				(void) gss_release_name(&min, &target_name);
				return (-1);
			}

			ret = buf2[5] & 0xf;	/* error field in TCP */
			if (ret != NOERROR) {
				dyndns_syslog(LOG_ERR, ret, "TKEY reply");
				(void) gss_release_name(&min, &target_name);
				return (-1);
			}

			tmpptr = &buf2[2];
			(void) dyndns_get_nshort(tmpptr, &rid);
			if (id != rid) {
				(void) gss_release_name(&min, &target_name);
				return (-1);
			}

			tmpptr = &buf2[59+(strlen(key_name)+2)*2];
			(void) dyndns_get_nshort(tmpptr, &rsz);
			in_tok.length = rsz;

			/* bsd38 -> 2*7=14 */
			in_tok.value = &buf2[61+(strlen(key_name)+2)*2];
			inputptr = &in_tok;
		}

	} while (maj != GSS_S_COMPLETE);

	(void) gss_release_name(&min, &target_name);

	return (0);
}

/*
 * dyndns_get_sec_context
 * Get security context for secure dynamic DNS update.  This routine opens
 * a TCP socket to the DNS server and establishes a security context with
 * the DNS server using host principal to perform secure dynamic DNS update.
 * Parameters:
 *   hostname: fully qualified hostname
 *   dns_ip  : ip address of hostname in network byte order
 * Returns:
 *   gss_handle: gss credential handle
 *   gss_context: gss security context
 *   -1: error
 *    0: success
 */

static gss_ctx_id_t
dyndns_get_sec_context(const char *hostname, smb_inaddr_t *dns_ip)
{
	int s;
	gss_cred_id_t cred_handle;
	gss_ctx_id_t gss_context;
	gss_OID oid;
	char *key_name, dns_hostname[MAXHOSTNAMELEN];

	cred_handle = GSS_C_NO_CREDENTIAL;
	oid = GSS_C_NO_OID;
	key_name = (char *)hostname;

	if (smb_getnameinfo(dns_ip, dns_hostname,
	    sizeof (dns_hostname), 0)) {
		return (NULL);
	}
	if ((s = dyndns_open_init_socket(SOCK_STREAM, dns_ip, 53)) < 0) {
		return (NULL);
	}

	if (dyndns_establish_sec_ctx(&gss_context, cred_handle, s, key_name,
	    dns_hostname, oid))
		gss_context = NULL;

	(void) close(s);
	return (gss_context);
}

/*
 * dyndns_build_add_remove_msg
 * This routine builds the update request message for adding and removing DNS
 * entries which is used for non-secure and secure DNS update.
 * This routine builds an UDP message.
 * Parameters:
 *   buf        : buffer to build message
 *   update_zone: the type of zone to update, use UPDATE_FORW for forward
 *                lookup zone, use UPDATE_REV for reverse lookup zone
 *   hostname   : fully qualified hostname to update DNS with
 *   ip_addr    : IP address of hostname
 *   life_time  : cached time of this entry by others and not within DNS
 *                database
 *   update_type: UPDATE_ADD to add entry, UPDATE_DEL to remove entry
 *   del_type   : DEL_ONE for deleting one entry, DEL_ALL for deleting all
 *                entries of the same resource name.  Only valid for UPDATE_DEL.
 *   addit_cnt  : Indicate how many record is in the additional section of
 *                the DNS message.  A value of zero is always used with
 *                non-secure update message. For secure update message,
 *                the value will be one because the signed TSIG message
 *                is added as the additional record of the DNS update message.
 *   id         : DNS message ID.  If a positive value then this ID value is
 *                used, otherwise the next incremented value is used
 *   level      : This is the domain level which we send the request to, level
 *                zero is the default level, it can go upto 2 in reverse zone
 *                and virtually to any level in forward zone.
 * Returns:
 *   buf      : buffer containing update message
 *   id       : DNS message ID
 *   int      : size of update message
 *   -1       : error
 *
 * This function is changed to handle dynamic DNS update retires to higher
 * authoritative domains.
 */
static int
dyndns_build_add_remove_msg(char *buf, int update_zone, const char *hostname,
	const char *ip_addr, int life_time, int update_type, int del_type,
	int addit_cnt, uint16_t *id, int level)
{
	int a, b, c, d;
	char *bufptr;
	int queryReq, zoneCount, preqCount, updateCount, additionalCount;
	char *zone, *resource, *data, zone_buf[100], resrc_buf[100];
	int zoneType, zoneClass, type, class, ttl;
	char *p;
	smb_inaddr_t tmp_addr;
	int i, j, k;
	int fourcnt;

	queryReq = REQ_UPDATE;
	zoneCount = 1;
	preqCount = 0;
	updateCount = 1;
	additionalCount = addit_cnt;

	(void) memset(buf, 0, NS_PACKETSZ);
	bufptr = buf;

	if (*id == 0)
		*id = dyndns_get_msgid();

	if (dyndns_build_header(&bufptr, BUFLEN_UDP(bufptr, buf), *id, queryReq,
	    zoneCount, preqCount, updateCount, additionalCount, 0) == -1) {
		return (-1);
	}

	zoneType = ns_t_soa;
	zoneClass = ns_c_in;

	if (update_zone == UPDATE_FORW) {
		p = (char *)hostname;

		/* Try higher domains according to the level requested */
		do {
			/* domain */
			if ((zone = (char *)strchr(p, '.')) == NULL)
				return (-1);
			zone += 1;
			p = zone;
		} while (--level >= 0);
		resource = (char *)hostname;
		data = (char *)ip_addr;
	} else {
		if (inet_pton(AF_INET, ip_addr, &tmp_addr) == 1) {
			(void) sscanf(ip_addr, "%d.%d.%d.%d", &a, &b, &c, &d);
			(void) sprintf(zone_buf, "%d.%d.%d.in-addr.arpa",
			    c, b, a);
			zone = p = zone_buf;

			/* Try higher domains based on level requested */
			while (--level >= 0) {
				/* domain */
				if ((zone = (char *)strchr(p, '.')) == NULL) {
					return (-1);
				}
				zone += 1;
				p = zone;
			}
			(void) sprintf(resrc_buf, "%d.%d.%d.%d.in-addr.arpa",
			    d, c, b, a);
		} else {
			/*
			 * create reverse nibble ipv6 format
			 */
			bzero(resrc_buf, 100);
			i = 0;
			j = 0;
			while (ip_addr[i] != 0)
				i++;
			i--;
			while (i >= 0) {
				fourcnt = 3;
				while ((i >= 0) && (ip_addr[i] != ':')) {
					resrc_buf[j++] = ip_addr[i];
					(void) strcat(&resrc_buf[j++], ".");
					fourcnt --;
					i--;
				}
				for (k = 0; k <= fourcnt; k++) {
					resrc_buf[j++] = '0';
					(void) strcat(&resrc_buf[j++], ".");
				}
				i--;
			}
			(void) strcat(resrc_buf, "ip6.arpa");
			(void) strcpy(zone_buf, &resrc_buf[32]);
			zone = zone_buf;
		}
		resource = resrc_buf;	/* ip info */
		data = (char *)hostname;
	}
	if (dyndns_build_quest_zone(&bufptr, BUFLEN_UDP(bufptr, buf), zone,
	    zoneType, zoneClass) == -1) {
		return (-1);
	}

	if (update_zone == UPDATE_FORW)
		type = ns_t_a;
	else
		type = ns_t_ptr;

	if (update_type == UPDATE_ADD) {
		class = ns_c_in;
		ttl = life_time;
	} else {
		if (del_type == DEL_ONE)
			class = ns_c_none;	/* remove one */
		else
			class = ns_c_any;	/* remove all */
		ttl = 0;
	}
	if (dyndns_build_update(&bufptr, BUFLEN_UDP(bufptr, buf),
	    resource, type, class, ttl, data, update_zone,
	    update_type, del_type) == -1) {
		return (-1);
	}

	return (bufptr - buf);
}

/*
 * dyndns_build_unsigned_tsig_msg
 * This routine is used to build the unsigned TSIG message for signing.  The
 * unsigned TSIG message contains the update request message with certain TSIG
 * fields included.  An error time of 300 seconds is used for fudge time.  This
 * is the number used by Microsoft clients.
 * This routine builds a UDP message.
 * Parameters:
 *   buf        : buffer to build message
 *   update_zone: the type of zone to update, use UPDATE_FORW for forward
 *                lookup zone, use UPDATE_REV for reverse lookup zone
 *   hostname   : fully qualified hostname to update DNS with
 *   ip_addr    : IP address of hostname
 *   life_time  : cached time of this entry by others and not within DNS
 *                database
 *   update_type: UPDATE_ADD to add entry, UPDATE_DEL to remove entry
 *   del_type   : DEL_ONE for deleting one entry, DEL_ALL for deleting all
 *                entries of the same resource name.  Only valid for UPDATE_DEL.
 *   key_name   : same key name used in TKEY message
 *   id         : DNS message ID.  If a positive value then this ID value is
 *                used, otherwise the next incremented value is used
 *   level      : This is the domain level which we send the request to, level
 *                zero is the default level, it can go upto 2 in reverse zone
 *                and virtually to any level in forward zone.
 * Returns:
 *   buf      : buffer containing update message
 *   id       : DNS message ID
 *   int      : size of update message
 *   -1       : error
 */
static int
dyndns_build_unsigned_tsig_msg(char *buf, int update_zone, const char *hostname,
	const char *ip_addr, int life_time, int update_type, int del_type,
	char *key_name, uint16_t *id, int level)
{
	char *bufptr;
	int buf_sz;

	if ((buf_sz = dyndns_build_add_remove_msg(buf, update_zone, hostname,
	    ip_addr, life_time, update_type, del_type, 0, id, level)) <= 0) {
		return (-1);
	}

	bufptr = buf + buf_sz;

	if (dyndns_build_tsig(&bufptr, BUFLEN_UDP(bufptr, buf), 0,
	    key_name, 300, NULL, 0, TSIG_UNSIGNED) == -1) {
		return (-1);
	}

	return (bufptr - buf);
}

/*
 * dyndns_build_signed_tsig_msg
 * This routine build the signed TSIG message which contains the update
 * request message encrypted.  An error time of 300 seconds is used for fudge
 * time.  This is the number used by Microsoft clients.
 * This routine builds a UDP message.
 * Parameters:
 *   buf        : buffer to build message
 *   update_zone: the type of zone to update, use UPDATE_FORW for forward
 *                lookup zone, use UPDATE_REV for reverse lookup zone
 *   hostname   : fully qualified hostname to update DNS with
 *   ip_addr    : IP address of hostname
 *   life_time  : cached time of this entry by others and not within DNS
 *                database
 *   update_type: UPDATE_ADD to add entry, UPDATE_DEL to remove entry
 *   del_type   : DEL_ONE for deleting one entry, DEL_ALL for deleting all
 *                entries of the same resource name.  Only valid for UPDATE_DEL.
 *   key_name   : same key name used in TKEY message
 *   id         : DNS message ID.  If a positive value then this ID value is
 *                used, otherwise the next incremented value is used
 *   in_mic     : the update request message encrypted
 *   level      : This is the domain level which we send the request to, level
 *                zero is the default level, it can go upto 2 in reverse zone
 *                and virtually to any level in forward zone.
 *
 * Returns:
 *   buf      : buffer containing update message
 *   id       : DNS message ID
 *   int      : size of update message
 *   -1       : error
 */
static int
dyndns_build_signed_tsig_msg(char *buf, int update_zone, const char *hostname,
	const char *ip_addr, int life_time, int update_type, int del_type,
	char *key_name, uint16_t *id, gss_buffer_desc *in_mic, int level)
{
	char *bufptr;
	int buf_sz;

	if ((buf_sz = dyndns_build_add_remove_msg(buf, update_zone, hostname,
	    ip_addr, life_time, update_type, del_type, 1, id, level)) <= 0) {
		return (-1);
	}

	bufptr = buf + buf_sz;

	if (dyndns_build_tsig(&bufptr, BUFLEN_UDP(bufptr, buf),
	    *id, key_name, 300, in_mic->value,
	    in_mic->length, TSIG_SIGNED) == -1) {
		return (-1);
	}

	return (bufptr - buf);
}

/*
 * dyndns_udp_send_recv
 * This routine sends and receives UDP DNS request and reply messages.
 *
 * Pre-condition: Caller must call dyndns_open_init_socket() before calling
 * this function.
 *
 * Parameters:
 *   s        : socket descriptor
 *   buf      : buffer containing data to send
 *   buf_sz   : size of data to send
 * Returns:
 *   -1     : error
 *   rec_buf: reply dat
 *    0     : success
 */

static int
dyndns_udp_send_recv(int s, char *buf, int buf_sz, char *rec_buf)
{
	int i, retval, addr_len;
	struct timeval tv, timeout;
	fd_set rfds;
	struct sockaddr_in6 from_addr;

	timeout.tv_usec = 0;
	timeout.tv_sec = DYNDNS_QUERY_TIMEOUT;

	for (i = 0; i <= DYNDNS_MAX_QUERY_RETRIES; i++) {
		if (send(s, buf, buf_sz, 0) == -1) {
			syslog(LOG_ERR, "dyndns: UDP send error (%s)",
			    strerror(errno));
			return (-1);
		}

		FD_ZERO(&rfds);
		FD_SET(s, &rfds);

		tv = timeout;

		retval = select(s+1, &rfds, NULL, NULL, &tv);

		if (retval == -1) {
			return (-1);
		} else if (retval > 0) {
			bzero(rec_buf, NS_PACKETSZ);
			addr_len = sizeof (struct sockaddr_in6);
			if (recvfrom(s, rec_buf, NS_PACKETSZ, 0,
			    (struct sockaddr *)&from_addr, &addr_len) == -1) {
				syslog(LOG_ERR, "dyndns: UDP recv error ");
				return (-1);
			}
			break;
		}
	}

	/* did not receive anything */
	if (i == (DYNDNS_MAX_QUERY_RETRIES + 1)) {
		syslog(LOG_ERR, "dyndns: max retries for UDP recv reached");
		return (-1);
	}

	return (0);
}
/*
 * dyndns_sec_add_remove_entry
 * Perform secure dynamic DNS update after getting security context.
 * This routine opens a UDP socket to the DNS sever, gets the security context,
 * builds the unsigned TSIG message and signed TSIG message.  The signed TSIG
 * message containing the encrypted update request message is sent to the DNS
 * server.  The response is received and check for error.  If there is no
 * error then credential handle and security context are released and the local
 * NSS cached is purged.
 * Parameters:
 *   update_zone : UPDATE_FORW for forward zone, UPDATE_REV for reverse zone
 *   hostname    : fully qualified hostname
 *   ip_addr     : ip address of hostname in string format
 *   life_time   : cached time of this entry by others and not within DNS
 *                 database
 *   max_retries : maximum retries for sending DNS update request
 *   recv_timeout: receive timeout
 *   update_type : UPDATE_ADD for adding entry, UPDATE_DEL for removing entry
 *   del_type    : DEL_ONE for deleting one entry, DEL_ALL for deleting all
 *                 entries of the same resource name.  Only valid for UPDATE_DEL
 *   dns_str     : DNS IP address in string format
 * Returns:
 *   -1: error
 *    0: success
 *
 * This function is enhanced to handle the case of NOTAUTH error when DNS server
 * is not authoritative for specified zone. In this case we need to resend the
 * same request to the higher authoritative domains.
 * This is true for both secure and unsecure dynamic DNS updates.
 */
static int
dyndns_sec_add_remove_entry(int update_zone, const char *hostname,
    const char *ip_addr, int life_time, int update_type, int del_type,
    char *dns_str)
{
	int s2;
	uint16_t id, rid;
	char buf[NS_PACKETSZ], buf2[NS_PACKETSZ];
	int ret;
	OM_uint32 min, maj;
	gss_buffer_desc in_mic, out_mic;
	gss_ctx_id_t gss_context;
	smb_inaddr_t dns_ip;
	char *key_name;
	int buf_sz;
	int level = 0;

	assert(dns_str);
	assert(*dns_str);

	if (inet_pton(AF_INET, dns_str, &dns_ip) == 1)
		dns_ip.a_family = AF_INET;
	else if (inet_pton(AF_INET6, dns_str, &dns_ip) == 1)
		dns_ip.a_family = AF_INET6;

sec_retry_higher:

	if ((gss_context = dyndns_get_sec_context(hostname,
	    &dns_ip)) == NULL) {
		return (-1);
	}

	key_name = (char *)hostname;

	if ((s2 = dyndns_open_init_socket(SOCK_DGRAM, &dns_ip, 53)) < 0) {
		if (gss_context != GSS_C_NO_CONTEXT)
			(void) gss_delete_sec_context(&min, &gss_context, NULL);
		return (-1);
	}

	id = 0;
	if ((buf_sz = dyndns_build_unsigned_tsig_msg(buf, update_zone, hostname,
	    ip_addr, life_time, update_type, del_type,
	    key_name, &id, level)) <= 0) {
		(void) close(s2);
		if (gss_context != GSS_C_NO_CONTEXT)
			(void) gss_delete_sec_context(&min, &gss_context, NULL);
		return (-1);
	}

	in_mic.length = buf_sz;
	in_mic.value = buf;

	/* sign update message */
	if ((maj = gss_get_mic(&min, gss_context, 0, &in_mic, &out_mic)) !=
	    GSS_S_COMPLETE) {
		display_stat(maj, min);
		(void) close(s2);
		if (gss_context != GSS_C_NO_CONTEXT)
			(void) gss_delete_sec_context(&min, &gss_context, NULL);
		return (-1);
	}

	if ((buf_sz = dyndns_build_signed_tsig_msg(buf, update_zone, hostname,
	    ip_addr, life_time, update_type, del_type, key_name, &id,
	    &out_mic, level)) <= 0) {
		(void) close(s2);
		(void) gss_release_buffer(&min, &out_mic);
		if (gss_context != GSS_C_NO_CONTEXT)
			(void) gss_delete_sec_context(&min, &gss_context, NULL);
		return (-1);
	}

	(void) gss_release_buffer(&min, &out_mic);

	if (dyndns_udp_send_recv(s2, buf, buf_sz, buf2)) {
		(void) close(s2);
		if (gss_context != GSS_C_NO_CONTEXT)
			(void) gss_delete_sec_context(&min, &gss_context, NULL);
		return (-1);
	}

	(void) close(s2);

	if (gss_context != GSS_C_NO_CONTEXT)
		(void) gss_delete_sec_context(&min, &gss_context, NULL);

	ret = buf2[3] & 0xf;	/* error field in UDP */

	/*
	 * If it is a NOTAUTH error we should retry with higher domains
	 * until we get a successful reply or the maximum retries is met.
	 */
	if (ret == NOTAUTH && level++ < MAX_AUTH_RETRIES)
		goto sec_retry_higher;

	/* check here for update request is successful */
	if (ret != NOERROR) {
		dyndns_syslog(LOG_ERR, ret, "TSIG reply");
		return (-1);
	}

	(void) dyndns_get_nshort(buf2, &rid);
	if (id != rid)
		return (-1);

	return (0);
}

/*
 * dyndns_seach_entry
 * Query DNS server for entry.  This routine can indicate if an entry exist
 * or not during forward or reverse lookup.  Also can indicate if the data
 * of the entry matched.  For example, for forward lookup, the entry is
 * searched using the hostname and the data is the IP address.  For reverse
 * lookup, the entry is searched using the IP address and the data is the
 * hostname.
 * Parameters:
 *   update_zone: UPDATE_FORW for forward zone, UPDATE_REV for reverse zone
 *   hostname   : fully qualified hostname
 *   ip_addr    : ip address of hostname in string format
 *   update_type: UPDATE_ADD for adding entry, UPDATE_DEL for removing entry
 * Returns:
 *   time_out: no use
 *   is_match: is 1 for found matching entry, otherwise 0
 *   1       : an entry exist but not necessarily match
 *   0       : an entry does not exist
 */
/*ARGSUSED*/

static int
dyndns_search_entry(int update_zone, const char *hostname, const char *ip_addr,
    int update_type, struct timeval *time_out, int *is_match)
{
	smb_inaddr_t ipaddr, dnsip;
	char dns_hostname[NI_MAXHOST];
	struct addrinfo hints, *res = NULL;
	int salen;
	int family;

	*is_match = 0;
	if (inet_pton(AF_INET, ip_addr, &ipaddr) == 1) {
		salen = sizeof (ipaddr.a_ipv4);
		family = AF_INET;
	} else if (inet_pton(AF_INET6, ip_addr, &ipaddr) == 1) {
		salen = sizeof (ipaddr.a_ipv6);
		family = AF_INET6;
	}
	if (update_zone == UPDATE_FORW) {
		bzero((char *)&hints, sizeof (hints));
		hints.ai_family = family;
		hints.ai_flags = AI_NUMERICHOST;
		if (getaddrinfo(hostname, NULL, &hints, &res)) {
			return (0);
		}
		if (res) {
			/*
			 * if both ips aren't the same family skip to
			 * the next record
			 */
			do {
				if ((res->ai_family == AF_INET) &&
				    (family == AF_INET)) {
					(void) memcpy(&dnsip, &res->ai_addr[0],
					    salen);
					if (ipaddr.a_ipv4 ==
					    dnsip.a_ipv4) {
						*is_match = 1;
						break;
					}
				} else if ((res->ai_family == AF_INET6) &&
				    (family == AF_INET6)) {
					(void) memcpy(&dnsip, &res->ai_addr[0],
					    salen);
					/* need compare macro here */
					if (!memcmp(&ipaddr, &dnsip,
					    IN6ADDRSZ)) {
						*is_match = 1;
						break;
					}
				}
			} while (res->ai_next);
			freeaddrinfo(res);
			return (1);
		}
	} else {
		if (smb_getnameinfo(&ipaddr, dns_hostname, NI_MAXHOST, 0))
			return (0);

		if (strncasecmp(dns_hostname, hostname,
		    strlen(hostname)) == 0) {
			*is_match = 1;
		}
		return (1);
	}

	/* entry does not exist */
	return (0);
}

/*
 * dyndns_add_remove_entry
 * Perform non-secure dynamic DNS update.  If it fails and host principal
 * keys can be found in the local keytab file, secure update will be performed.
 *
 * This routine opens a UDP socket to the DNS sever, build the update request
 * message, and sends the message to the DNS server.  The response is received
 * and check for error.  If there is no error then the local NSS cached is
 * purged.  DNS may be used to check to see if an entry already exist before
 * adding or to see if an entry does exist before removing it.  Adding
 * duplicate entries or removing non-existing entries does not cause any
 * problems.  DNS is not check when doing a delete all.
 * Parameters:
 *   update_zone: UPDATE_FORW for forward zone, UPDATE_REV for reverse zone
 *   hostname   : fully qualified hostname
 *   ip_addr    : ip address of hostname in string format
 *   life_time  : cached time of this entry by others and not within DNS
 *                database
 *   update_type: UPDATE_ADD to add entry, UPDATE_DEL to remove entry
 *   do_check   : DNS_CHECK to check first in DNS, DNS_NOCHECK for no DNS
 *                checking before update
 *   del_type   : DEL_ONE for deleting one entry, DEL_ALL for deleting all
 *                entries of the same resource name.  Only valid for UPDATE_DEL.
 *   dns_str    : DNS IP address in string format
 * Returns:
 *   -1: error
 *    0: success
 *
 * This function is enhanced to handle the case of NOTAUTH error when DNS server
 * is not authoritative for specified zone. In this case we need to resend the
 * same request to the higher authoritative domains.
 * This is true for both secure and unsecure dynamic DNS updates.
 */
static int
dyndns_add_remove_entry(int update_zone, const char *hostname,
    const char *ip_addr, int life_time, int update_type,
    int do_check, int del_type, char *dns_str)
{
	int s;
	uint16_t id, rid;
	char buf[NS_PACKETSZ], buf2[NS_PACKETSZ];
	int ret;
	int is_exist, is_match;
	struct timeval timeout;
	int buf_sz;
	int level = 0;
	smb_inaddr_t dns_ip;
	char *fqdn;
	char *p;

	assert(dns_str);
	assert(*dns_str);

	if (do_check == DNS_CHECK && del_type != DEL_ALL) {
		is_exist = dyndns_search_entry(update_zone, hostname, ip_addr,
		    update_type, &timeout, &is_match);

		if (update_type == UPDATE_ADD && is_exist && is_match) {
			return (0);
		} else if (update_type == UPDATE_DEL && !is_exist) {
			return (0);
		}
	}

	if (inet_pton(AF_INET, dns_str, &dns_ip) == 1)
		dns_ip.a_family = AF_INET;
	else if (inet_pton(AF_INET6, dns_str, &dns_ip) == 1)
		dns_ip.a_family = AF_INET6;

retry_higher:
	if ((s = dyndns_open_init_socket(SOCK_DGRAM, &dns_ip, 53)) < 0)
		return (-1);

	id = 0;
	if ((buf_sz = dyndns_build_add_remove_msg(buf, update_zone, hostname,
	    ip_addr, life_time, update_type, del_type, 0, &id, level)) <= 0) {
		(void) close(s);
		return (-1);
	}

	if (dyndns_udp_send_recv(s, buf, buf_sz, buf2)) {
		(void) close(s);
		return (-1);
	}

	(void) close(s);

	ret = buf2[3] & 0xf;	/* error field in UDP */

	/*
	 * If it is a NOTAUTH error we should retry with higher domains
	 * until we get a successful reply
	 */
	if (ret == NOTAUTH && level++ < MAX_AUTH_RETRIES)
		goto retry_higher;

	/* check here for update request is successful */
	if (ret == NOERROR) {
		(void) dyndns_get_nshort(buf2, &rid);
		if (id != rid)
			return (-1);
		return (0);
	}

	if (ret == NOTIMP) {
		dyndns_syslog(LOG_NOTICE, NOTIMP, "dynamic updates");
		return (-1);
	} else if (ret == NOTAUTH) {
		dyndns_syslog(LOG_NOTICE, NOTAUTH, "DNS");
		return (-1);
	}

	if ((p = strchr(hostname, '.')) == NULL)
		return (-1);

	fqdn = ++p;
	if (smb_krb5_kt_find(SMB_KRB5_PN_ID_HOST_FQHN, fqdn,
	    SMBNS_KRB5_KEYTAB)) {
		ret = dyndns_sec_add_remove_entry(update_zone, hostname,
		    ip_addr, life_time, update_type, del_type, dns_str);
	} else {
		syslog(LOG_NOTICE, "dyndns: secure update failed: cannot find "
		    "host principal \"%s\" in local keytab file.", hostname);
	}

	return (ret);
}

/*
 * dyndns_add_entry
 * Main routine to add an entry into DNS.  The attempt will be made on the
 * the servers returned by smb_get_nameserver().  Upon a successful
 * attempt on any one of the server, the function will exit with 0.
 * Otherwise, -1 is retuned to indicate the update attempt on all the
 * nameservers has failed.
 *
 * Parameters:
 *   update_zone: the type of zone to update, use UPDATE_FORW for forward
 *                lookup zone, use UPDATE_REV for reverse lookup zone
 *   hostname   : fully qualified hostname
 *   ip_addr    : ip address of hostname in string format
 *   life_time  : cached time of this entry by others and not within DNS
 *                database
 * Returns:
 *   -1: error
 *    0: success
 */
static int
dyndns_add_entry(int update_zone, const char *hostname, const char *ip_addr,
    int life_time)
{
	const char *dns_str;
	char *which_zone;
	smb_inaddr_t ns_list[MAXNS];
	char dns_buf[INET6_ADDRSTRLEN];
	int i, cnt;
	int rc = 0;

	if (hostname == NULL || ip_addr == NULL) {
		return (-1);
	}
	cnt = smb_get_nameservers(&ns_list[0], MAXNS);

	for (i = 0; i < cnt; i++) {
		dns_str = smb_inet_ntop(&ns_list[i], dns_buf,
		    SMB_IPSTRLEN(ns_list[i].a_family));
		if (dns_str == NULL)
			continue;

		which_zone = (update_zone == UPDATE_FORW) ?
		    "forward" : "reverse";
		syslog(LOG_DEBUG, "dyndns %s lookup zone update %s (%s)",
		    which_zone, hostname, ip_addr);

		if (dyndns_add_remove_entry(update_zone, hostname,
		    ip_addr, life_time,
		    UPDATE_ADD, DNS_NOCHECK, DEL_NONE, dns_buf) != -1) {
			rc = 1;
			break;
		}
	}

	return (rc ? 0 : -1);
}

/*
 * dyndns_remove_entry
 * Main routine to remove an entry or all entries of the same resource name
 * from DNS.  The update attempt will be made on the primary DNS server.  If
 * there is a failure then another attempt will be made on the secondary DNS
 * server.
 * Parameters:
 *   update_zone: the type of zone to update, use UPDATE_FORW for forward
 *                lookup zone, use UPDATE_REV for reverse lookup zone
 *   hostname   : fully qualified hostname
 *   ip_addr    : ip address of hostname in string format
 *   del_type   : DEL_ONE for deleting one entry, DEL_ALL for deleting all
 *                entries of the same resource name.  Only valid for UPDATE_DEL
 * Returns:
 *   -1: error
 *    0: success
 */
static int
dyndns_remove_entry(int update_zone, const char *hostname, const char *ip_addr,
	int del_type)
{
	const char *dns_str;
	smb_inaddr_t ns_list[MAXNS];
	char dns_buf[INET6_ADDRSTRLEN];
	int i, cnt, scnt;

	if ((hostname == NULL || ip_addr == NULL)) {
		return (-1);
	}
	cnt = smb_get_nameservers(ns_list, MAXNS);
	scnt = 0;
	for (i = 0; i < cnt; i++) {
		dns_str = smb_inet_ntop(&ns_list[i], dns_buf,
		    SMB_IPSTRLEN(ns_list[i].a_family));
		if (dns_str == NULL)
			continue;
		if (update_zone == UPDATE_FORW) {
			if (del_type == DEL_ONE) {
				syslog(LOG_DEBUG, "Dynamic update "
				    "on forward lookup "
				    "zone for %s (%s)...\n", hostname, ip_addr);
			} else {
				syslog(LOG_DEBUG, "Removing all "
				    "entries of %s "
				    "in forward lookup zone...\n", hostname);
			}
		} else {
			if (del_type == DEL_ONE) {
				syslog(LOG_DEBUG, "Dynamic update "
				    "on reverse lookup "
				    "zone for %s (%s)...\n", hostname, ip_addr);
			} else {
				syslog(LOG_DEBUG, "Removing all "
				    "entries of %s "
				    "in reverse lookup zone...\n", ip_addr);
			}
		}
		if (dyndns_add_remove_entry(update_zone, hostname, ip_addr, 0,
		    UPDATE_DEL, DNS_NOCHECK, del_type, dns_buf) != -1) {
			scnt++;
			break;
		}
	}
	if (scnt)
		return (0);
	return (-1);
}

/*
 * dyndns_update_core
 * Perform dynamic update on both forward and reverse lookup zone using
 * the specified hostname and IP addresses.  Before updating DNS, existing
 * host entries with the same hostname in the forward lookup zone are removed
 * and existing pointer entries with the same IP addresses in the reverse
 * lookup zone are removed.  After DNS update, host entries for current
 * hostname will show current IP addresses and pointer entries for current
 * IP addresses will show current hostname.
 * Parameters:
 *  fqdn - fully-qualified domain name (in lower case)
 *
 * Returns:
 *   -1: some dynamic DNS updates errors
 *    0: successful or DDNS disabled.
 */
int
dyndns_update_core(char *fqdn)
{
	int forw_update_ok, error;
	char my_ip[INET6_ADDRSTRLEN];
	const char *my_str;
	smb_niciter_t ni;
	int rc;
	char fqhn[MAXHOSTNAMELEN];

	if (fqdn == NULL || *fqdn == '\0')
		return (0);

	if (!smb_config_getbool(SMB_CI_DYNDNS_ENABLE))
		return (0);
	if (smb_gethostname(fqhn, MAXHOSTNAMELEN, SMB_CASE_LOWER) != 0)
		return (-1);

	/*
	 * To comply with RFC 4120 section 6.2.1, the fully-qualified hostname
	 * must be set to lower case.
	 */
	(void) snprintf(fqhn, MAXHOSTNAMELEN, "%s.%s", fqhn, fqdn);

	error = 0;
	forw_update_ok = 0;

	/*
	 * Dummy IP is okay since we are removing all using the hostname.
	 */
	if (dyndns_remove_entry(UPDATE_FORW, fqhn, "1.1.1.1", DEL_ALL) == 0) {
		forw_update_ok = 1;
	} else {
		error++;
	}

	if (smb_nic_getfirst(&ni) != SMB_NIC_SUCCESS)
		return (-1);

	do {
		if (ni.ni_nic.nic_sysflags & IFF_PRIVATE)
			continue;
		/* first try ipv4, then ipv6 */
		my_str = smb_inet_ntop(&ni.ni_nic.nic_ip, my_ip,
		    SMB_IPSTRLEN(ni.ni_nic.nic_ip.a_family));
		if (my_str == NULL) {
			error++;
			continue;
		}

		if (forw_update_ok) {
			rc = dyndns_add_entry(UPDATE_FORW, fqhn, my_str,
			    DDNS_TTL);

			if (rc == -1)
				error++;
		}

		rc = dyndns_remove_entry(UPDATE_REV, fqhn, my_str, DEL_ALL);
		if (rc == 0) {
			rc = dyndns_add_entry(UPDATE_REV, fqhn, my_str,
			    DDNS_TTL);
		}

		if (rc == -1)
			error++;

	} while (smb_nic_getnext(&ni) == SMB_NIC_SUCCESS);

	return ((error == 0) ? 0 : -1);
}

/*
 * dyndns_clear_rev_zone
 * Clear the rev zone records. Must be called to clear the OLD if list
 * of down records prior to updating the list with new information.
 *
 * Parameters:
 *   fqdn - fully-qualified domain name (in lower case)
 * Returns:
 *   -1: some dynamic DNS updates errors
 *    0: successful or DDNS disabled.
 */
int
dyndns_clear_rev_zone(char *fqdn)
{
	int error;
	char my_ip[INET6_ADDRSTRLEN];
	smb_niciter_t ni;
	int rc;
	char fqhn[MAXHOSTNAMELEN];
	const char *my_str;

	if (!smb_config_getbool(SMB_CI_DYNDNS_ENABLE))
		return (0);

	if (smb_gethostname(fqhn, MAXHOSTNAMELEN, SMB_CASE_LOWER) != 0)
		return (-1);

	/*
	 * To comply with RFC 4120 section 6.2.1, the fully-qualified hostname
	 * must be set to lower case.
	 */
	(void) snprintf(fqhn, MAXHOSTNAMELEN, "%s.%s", fqhn, fqdn);

	error = 0;

	if (smb_nic_getfirst(&ni) != SMB_NIC_SUCCESS)
		return (-1);

	do {
		if (ni.ni_nic.nic_sysflags & IFF_PRIVATE)
			continue;
		my_str = smb_inet_ntop(&ni.ni_nic.nic_ip, my_ip,
		    SMB_IPSTRLEN(ni.ni_nic.nic_ip.a_family));
		if (my_str == NULL) {
			error++;
			continue;
		}

		rc = dyndns_remove_entry(UPDATE_REV, fqhn, my_ip, DEL_ALL);
		if (rc != 0)
			error++;

	} while (smb_nic_getnext(&ni) == SMB_NIC_SUCCESS);

	return ((error == 0) ? 0 : -1);
}
