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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FMA Event Transport Module
 *
 * Plugin for sending/receiving FMA events to/from a remote endoint.
 */

#include <netinet/in.h>
#include <errno.h>
#include <sys/fm/protocol.h>
#include <sys/sysmacros.h>
#include <pthread.h>
#include <strings.h>
#include <ctype.h>
#include <link.h>
#include <libnvpair.h>
#include "etm_xport_api.h"
#include "etm_proto.h"

/*
 * ETM declarations
 */

typedef enum etm_connection_status {
	C_UNINITIALIZED = 0,
	C_OPEN,				/* Connection is open */
	C_CLOSED,			/* Connection is closed */
	C_LIMBO,			/* Bad value in header from peer */
	C_TIMED_OUT			/* Reconnection to peer timed out */
} etm_connstat_t;

typedef enum etm_fmd_queue_status {
	Q_UNINITIALIZED = 100,
	Q_INIT_PENDING,			/* Queue initialization in progress */
	Q_OPEN,				/* Queue is open */
	Q_SUSPENDED			/* Queue is suspended */
} etm_qstat_t;

/* Per endpoint data */
typedef struct etm_endpoint_map {
	uint8_t epm_ver;		/* Protocol version being used */
	char *epm_ep_str;		/* Endpoint ID string */
	int epm_xprtflags;		/* FMD transport open flags */
	etm_xport_hdl_t epm_tlhdl;	/* Transport Layer instance handle */
	pthread_mutex_t epm_lock;	/* Protects remainder of struct */
	pthread_cond_t epm_tx_cv;	/* Cond var for send/transmit */
	int epm_txbusy;			/* Busy doing send/transmit */
	fmd_xprt_t *epm_xprthdl;	/* FMD transport handle */
	etm_qstat_t epm_qstat;		/* Status of fmd xprt queue */
	nvlist_t *epm_ep_nvl;		/* Endpoint ID nv_list */
	etm_xport_conn_t epm_oconn;	/* Connection for outgoing events */
	etm_connstat_t epm_cstat;	/* Status of connection */
	id_t epm_timer_id;		/* Timer id */
	int epm_timer_in_use;		/* Indicates if timer is in use */
	hrtime_t epm_reconn_end;	/* Reconnection end time */
	struct etm_endpoint_map *epm_next;
} etm_epmap_t;

#define	ETM_HDR_INVALID (ETM_HDR_TYPE_TOO_HIGH + 1)
#define	ETM_HDR_BADVERSION (ETM_HDR_TYPE_TOO_HIGH + 2)
#define	ETM_HDR_BADTYPE (ETM_HDR_TYPE_TOO_HIGH + 3)
#define	ETM_EP_INST_MAX 4		/* Max chars in endpt instance */
#define	ETM_CLIENT_XPRT_FLAGS FMD_XPRT_RDWR
#define	ETM_SERVER_XPRT_FLAGS (FMD_XPRT_RDWR | FMD_XPRT_ACCEPT)

#define	ALLOC_BUF(hdl, buf, size) \
	buf = fmd_hdl_zalloc((hdl), (size), FMD_SLEEP);

#define	FREE_BUF(hdl, buf, size) fmd_hdl_free((hdl), (buf), (size));

#define	IS_CLIENT(mp)	(((mp)->epm_xprtflags & FMD_XPRT_ACCEPT) ? 0 : 1)

#define	INCRSTAT(x)	{	(void) pthread_mutex_lock(&Etm_mod_lock);   \
				(x)++;					    \
				(void) pthread_mutex_unlock(&Etm_mod_lock); \
			}

#define	DECRSTAT(x)	{	(void) pthread_mutex_lock(&Etm_mod_lock);   \
				(x)--;					    \
				(void) pthread_mutex_unlock(&Etm_mod_lock); \
			}

#define	ADDSTAT(x, y)	{	(void) pthread_mutex_lock(&Etm_mod_lock);   \
				(x) += (y);				    \
				(void) pthread_mutex_unlock(&Etm_mod_lock); \
			}

/*
 * Global variables
 */
static pthread_mutex_t Etm_mod_lock = PTHREAD_MUTEX_INITIALIZER;
					/* Protects globals */
static hrtime_t Reconn_interval;	/* Time between reconnection attempts */
static hrtime_t Reconn_timeout;		/* Time allowed for reconnection */
static hrtime_t Rw_timeout;		/* Time allowed for I/O operation  */
static int Etm_dump = 0;		/* Enables hex dump for debug */
static int Etm_exit = 0;		/* Flag for exit */
static etm_epmap_t *Epmap_head = NULL;	/* Head of list of epmap structs */

/* Module statistics */
static struct etm_stats {
	/* read counters */
	fmd_stat_t read_ack;
	fmd_stat_t read_bytes;
	fmd_stat_t read_msg;
	fmd_stat_t post_filter;
	/* write counters */
	fmd_stat_t write_ack;
	fmd_stat_t write_bytes;
	fmd_stat_t write_msg;
	fmd_stat_t send_filter;
	/* error counters */
	fmd_stat_t error_protocol;
	fmd_stat_t error_drop_read;
	fmd_stat_t error_read;
	fmd_stat_t error_read_badhdr;
	fmd_stat_t error_write;
	fmd_stat_t error_send_filter;
	fmd_stat_t error_post_filter;
	/* misc */
	fmd_stat_t peer_count;

} Etm_stats = {
	/* read counters */
	{ "read_ack", FMD_TYPE_UINT64, "ACKs read" },
	{ "read_bytes", FMD_TYPE_UINT64, "Bytes read" },
	{ "read_msg", FMD_TYPE_UINT64, "Messages read" },
	{ "post_filter", FMD_TYPE_UINT64, "Drops by post_filter" },
	/* write counters */
	{ "write_ack", FMD_TYPE_UINT64, "ACKs sent" },
	{ "write_bytes", FMD_TYPE_UINT64, "Bytes sent" },
	{ "write_msg", FMD_TYPE_UINT64, "Messages sent" },
	{ "send_filter", FMD_TYPE_UINT64, "Drops by send_filter" },
	/* ETM error counters */
	{ "error_protocol", FMD_TYPE_UINT64, "ETM protocol errors" },
	{ "error_drop_read", FMD_TYPE_UINT64, "Dropped read messages" },
	{ "error_read", FMD_TYPE_UINT64, "Read I/O errors" },
	{ "error_read_badhdr", FMD_TYPE_UINT64, "Bad headers read" },
	{ "error_write", FMD_TYPE_UINT64, "Write I/O errors" },
	{ "error_send_filter", FMD_TYPE_UINT64, "Send filter errors" },
	{ "error_post_filter", FMD_TYPE_UINT64, "Post filter errors" },
	/* ETM Misc */
	{ "peer_count", FMD_TYPE_UINT64, "Number of peers initialized" },
};

/*
 * ETM Private functions
 */

/*
 * Hex dump for debug.
 */
static void
etm_hex_dump(fmd_hdl_t *hdl, void *buf, size_t buflen, int direction)
{
	int i, j, k;
	int16_t *c;

	if (Etm_dump == 0)
		return;

	j = buflen / 16;	/* Number of complete 8-column rows */
	k = buflen % 16;	/* Is there a last (non-8-column) row? */

	if (direction)
		fmd_hdl_debug(hdl, "--- WRITE Message Dump ---");
	else
		fmd_hdl_debug(hdl, "---  READ Message Dump ---");

	fmd_hdl_debug(hdl, "   Displaying %d bytes", buflen);

	/* Dump the complete 8-column rows */
	for (i = 0; i < j; i++) {
		c = (int16_t *)buf + (i * 8);
		fmd_hdl_debug(hdl, "%3d: %4x %4x %4x %4x   %4x %4x %4x %4x", i,
		    *(c+0), *(c+1), *(c+2), *(c+3),
		    *(c+4), *(c+5), *(c+6), *(c+7));
	}

	/* Dump the last (incomplete) row */
	c = (int16_t *)buf + (i * 8);
	switch (k) {
	case 4:
		fmd_hdl_debug(hdl, "%3d: %4x %4x", i, *(c+0), *(c+1));
		break;
	case 8:
		fmd_hdl_debug(hdl, "%3d: %4x %4x %4x %4x", i, *(c+0), *(c+1),
		    *(c+2), *(c+3));
		break;
	case 12:
		fmd_hdl_debug(hdl, "%3d: %4x %4x %4x %4x   %4x %4x", i, *(c+0),
		    *(c+1), *(c+2), *(c+3), *(c+4), *(c+5));
		break;
	}

	fmd_hdl_debug(hdl, "---      End Dump      ---");
}

/*
 * Provide the length of a message based on the data in the given ETM header.
 */
static size_t
etm_get_msglen(void *buf)
{
	etm_proto_hdr_t *hp = (etm_proto_hdr_t *)buf;

	return (ntohl(hp->hdr_msglen));
}

/*
 * Check the contents of the ETM header for errors.
 * Return the header type (hdr_type).
 */
static int
etm_check_hdr(fmd_hdl_t *hdl, etm_epmap_t *mp, void *buf)
{
	etm_proto_hdr_t *hp = (etm_proto_hdr_t *)buf;

	if (bcmp(hp->hdr_delim, ETM_DELIM, ETM_DELIMLEN) != 0) {
		fmd_hdl_debug(hdl, "Bad delimiter in ETM header from %s "
		    ": 0x%x\n", mp->epm_ep_str, hp->hdr_delim);
		return (ETM_HDR_INVALID);
	}

	if ((hp->hdr_type == ETM_HDR_C_HELLO) ||
	    (hp->hdr_type == ETM_HDR_S_HELLO)) {
		/* Until version is negotiated, other fields may be wrong */
		return (hp->hdr_type);
	}

	if (hp->hdr_ver != mp->epm_ver) {
		fmd_hdl_debug(hdl, "Bad version in ETM header from %s : 0x%x\n",
		    mp->epm_ep_str, hp->hdr_ver);
		return (ETM_HDR_BADVERSION);
	}

	if ((hp->hdr_type == ETM_HDR_TYPE_TOO_LOW) ||
	    (hp->hdr_type >= ETM_HDR_TYPE_TOO_HIGH)) {
		fmd_hdl_debug(hdl, "Bad type in ETM header from %s : 0x%x\n",
		    mp->epm_ep_str, hp->hdr_type);
		return (ETM_HDR_BADTYPE);
	}

	return (hp->hdr_type);
}

/*
 * Create an ETM header of a given type in the given buffer.
 * Return length of header.
 */
static size_t
etm_create_hdr(void *buf, uint8_t ver, uint8_t type, uint32_t msglen)
{
	etm_proto_hdr_t *hp = (etm_proto_hdr_t *)buf;

	bcopy(ETM_DELIM, hp->hdr_delim, ETM_DELIMLEN);
	hp->hdr_ver = ver;
	hp->hdr_type = type;
	hp->hdr_msglen = htonl(msglen);

	return (ETM_HDRLEN);
}

/*
 * Convert message bytes to nvlist and post to fmd.
 * Return zero for success, non-zero for failure.
 *
 * Note : nvl is free'd by fmd.
 */
static int
etm_post_msg(fmd_hdl_t *hdl, etm_epmap_t *mp, void *buf, size_t buflen)
{
	nvlist_t *nvl;
	int rv;

	if (nvlist_unpack((char *)buf, buflen, &nvl, 0)) {
		fmd_hdl_error(hdl, "failed to unpack message");
		return (1);
	}

	rv = etm_xport_post_filter(hdl, nvl, mp->epm_ep_str);
	if (rv == ETM_XPORT_FILTER_DROP) {
		fmd_hdl_debug(hdl, "post_filter dropped event");
		INCRSTAT(Etm_stats.post_filter.fmds_value.ui64);
		nvlist_free(nvl);
		return (0);
	} else if (rv == ETM_XPORT_FILTER_ERROR) {
		fmd_hdl_debug(hdl, "post_filter error : %s", strerror(errno));
		INCRSTAT(Etm_stats.error_post_filter.fmds_value.ui64);
		/* Still post event */
	}

	(void) pthread_mutex_lock(&mp->epm_lock);
	(void) pthread_mutex_lock(&Etm_mod_lock);
	if (!Etm_exit) {
		(void) pthread_mutex_unlock(&Etm_mod_lock);
		if (mp->epm_qstat == Q_OPEN) {
			fmd_xprt_post(hdl, mp->epm_xprthdl, nvl, 0);
			rv = 0;
		} else if (mp->epm_qstat == Q_SUSPENDED) {
			fmd_xprt_resume(hdl, mp->epm_xprthdl);
			if (mp->epm_timer_in_use) {
				fmd_timer_remove(hdl, mp->epm_timer_id);
				mp->epm_timer_in_use = 0;
			}
			mp->epm_qstat = Q_OPEN;
			fmd_hdl_debug(hdl, "queue resumed for %s",
			    mp->epm_ep_str);
			fmd_xprt_post(hdl, mp->epm_xprthdl, nvl, 0);
			rv = 0;
		} else {
			fmd_hdl_debug(hdl, "unable to post message, qstat = %d",
			    mp->epm_qstat);
			nvlist_free(nvl);
			/* Remote peer will attempt to resend event */
			rv = 2;
		}
	} else {
		(void) pthread_mutex_unlock(&Etm_mod_lock);
		fmd_hdl_debug(hdl, "unable to post message, module exiting");
		nvlist_free(nvl);
		/* Remote peer will attempt to resend event */
		rv = 3;
	}

	(void) pthread_mutex_unlock(&mp->epm_lock);

	return (rv);
}

/*
 * Handle the startup handshake to the server.  The client always initiates
 * the startup handshake.  In the following sequence, we are the client and
 * the remote endpoint is the server.
 *
 *	Client sends C_HELLO and transitions to Q_INIT_PENDING state.
 *	Server sends S_HELLO and transitions to Q_INIT_PENDING state.
 *	Client sends ACK and transitions to Q_OPEN state.
 *	Server receives ACK and transitions to Q_OPEN state.
 *
 * Return 0 for success, nonzero for failure.
 */
static int
etm_handle_startup(fmd_hdl_t *hdl, etm_epmap_t *mp)
{
	etm_proto_hdr_t *hp;
	size_t hdrlen = ETM_HDRLEN;
	int hdrstat;
	char hbuf[ETM_HDRLEN];

	if ((mp->epm_oconn = etm_xport_open(hdl, mp->epm_tlhdl)) == NULL)
		return (1);

	mp->epm_cstat = C_OPEN;

	hdrlen = etm_create_hdr(hbuf, mp->epm_ver, ETM_HDR_C_HELLO, 0);

	if ((etm_xport_write(hdl, mp->epm_oconn, Rw_timeout, hbuf,
	    hdrlen)) != hdrlen) {
		fmd_hdl_error(hdl, "Failed to write C_HELLO to %s",
		    mp->epm_ep_str);
		return (2);
	}

	mp->epm_qstat = Q_INIT_PENDING;

	if ((etm_xport_read(hdl, mp->epm_oconn, Rw_timeout, hbuf,
	    hdrlen)) != hdrlen) {
		fmd_hdl_error(hdl, "Failed to read S_HELLO from %s",
		    mp->epm_ep_str);
		return (3);
	}

	hdrstat = etm_check_hdr(hdl, mp, hbuf);

	if (hdrstat != ETM_HDR_S_HELLO) {
		fmd_hdl_error(hdl, "Protocol error, did not receive S_HELLO "
		    "from %s", mp->epm_ep_str);
		return (4);
	}

	/*
	 * Get version from the server.
	 * Currently, only one version is supported.
	 */
	hp = (etm_proto_hdr_t *)(void *)hbuf;
	if (hp->hdr_ver != ETM_PROTO_V1) {
		fmd_hdl_error(hdl, "Unable to use same version as %s : %d",
		    mp->epm_ep_str, hp->hdr_ver);
		return (5);
	}
	mp->epm_ver = hp->hdr_ver;

	hdrlen = etm_create_hdr(hbuf, mp->epm_ver, ETM_HDR_ACK, 0);

	if ((etm_xport_write(hdl, mp->epm_oconn, Rw_timeout, hbuf,
	    hdrlen)) != hdrlen) {
		fmd_hdl_error(hdl, "Failed to write ACK for S_HELLO to %s",
		    mp->epm_ep_str);
		return (6);
	}

	/*
	 * Call fmd_xprt_open and fmd_xprt_setspecific with
	 * Etm_mod_lock held to avoid race with etm_send thread.
	 */
	(void) pthread_mutex_lock(&Etm_mod_lock);
	if ((mp->epm_xprthdl = fmd_xprt_open(hdl, mp->epm_xprtflags,
	    mp->epm_ep_nvl, NULL)) == NULL) {
		fmd_hdl_abort(hdl, "Failed to init xprthdl for %s",
		    mp->epm_ep_str);
	}
	fmd_xprt_setspecific(hdl, mp->epm_xprthdl, mp);
	(void) pthread_mutex_unlock(&Etm_mod_lock);

	mp->epm_qstat = Q_OPEN;
	fmd_hdl_debug(hdl, "queue open for %s",  mp->epm_ep_str);

	return (0);
}

/*
 * Open a connection to the peer, send a SHUTDOWN message,
 * and close the connection.
 */
static void
etm_send_shutdown(fmd_hdl_t *hdl, etm_epmap_t *mp)
{
	size_t hdrlen = ETM_HDRLEN;
	char hbuf[ETM_HDRLEN];

	if ((mp->epm_oconn = etm_xport_open(hdl, mp->epm_tlhdl)) == NULL)
		return;

	hdrlen = etm_create_hdr(hbuf, mp->epm_ver, ETM_HDR_SHUTDOWN, 0);

	(void) etm_xport_write(hdl, mp->epm_oconn, Rw_timeout, hbuf, hdrlen);

	(void) etm_xport_close(hdl, mp->epm_oconn);
	mp->epm_oconn = NULL;
}

/*
 * Alloc a nvlist and add a string for the endpoint.
 * Return zero for success, non-zero for failure.
 */
static int
etm_get_ep_nvl(fmd_hdl_t *hdl, etm_epmap_t *mp)
{
	/*
	 * Cannot use nvlist_xalloc(3NVPAIR) due to a recursive mutex situation
	 * in fmd when this nvlist_t is free'd.
	 */
	(void) nvlist_alloc(&mp->epm_ep_nvl, NV_UNIQUE_NAME, 0);

	if (nvlist_add_string(mp->epm_ep_nvl, "domain-id", mp->epm_ep_str)) {
		fmd_hdl_error(hdl, "failed to add domain-id string to nvlist "
		    "for %s", mp->epm_ep_str);
		nvlist_free(mp->epm_ep_nvl);
		return (1);
	}

	return (0);
}

/*
 * Free the nvlist for the endpoint_id string.
 */
/*ARGSUSED*/
static void
etm_free_ep_nvl(fmd_hdl_t *hdl, etm_epmap_t *mp)
{
	nvlist_free(mp->epm_ep_nvl);
}

/*
 * Check for a duplicate endpoint/peer string.
 */
/*ARGSUSED*/
static int
etm_check_dup_ep_str(fmd_hdl_t *hdl, char *epname)
{
	etm_epmap_t *mp;

	for (mp = Epmap_head; mp != NULL; mp = mp->epm_next)
		if (strcmp(epname, mp->epm_ep_str) == 0)
			return (1);

	return (0);
}

/*
 * Attempt to re-open a connection with the remote endpoint.
 */
static void
etm_reconnect(fmd_hdl_t *hdl, etm_epmap_t *mp)
{
	if ((mp->epm_reconn_end > 0) && (mp->epm_cstat == C_UNINITIALIZED)) {
		if (gethrtime() < mp->epm_reconn_end) {
			if ((mp->epm_oconn = etm_xport_open(hdl,
			    mp->epm_tlhdl)) == NULL) {
				fmd_hdl_debug(hdl, "reconnect failed for %s",
				    mp->epm_ep_str);
				mp->epm_timer_id = fmd_timer_install(hdl, mp,
				    NULL, Reconn_interval);
				mp->epm_timer_in_use = 1;
			} else {
				fmd_hdl_debug(hdl, "reconnect success for %s",
				    mp->epm_ep_str);
				mp->epm_reconn_end = 0;
				mp->epm_cstat = C_OPEN;
			}
		} else {
			fmd_hdl_error(hdl, "Reconnect timed out for %s\n",
			    mp->epm_ep_str);
			mp->epm_reconn_end = 0;
			mp->epm_cstat = C_TIMED_OUT;
		}
	}

	if (mp->epm_cstat == C_OPEN) {
		fmd_xprt_resume(hdl, mp->epm_xprthdl);
		mp->epm_qstat = Q_OPEN;
		fmd_hdl_debug(hdl, "queue resumed for %s",  mp->epm_ep_str);
	}
}

/*
 * Suspend a given connection and setup for reconnection retries.
 * Assume caller holds lock on epm_lock.
 */
static void
etm_suspend_reconnect(fmd_hdl_t *hdl, etm_epmap_t *mp)
{
	(void) pthread_mutex_lock(&Etm_mod_lock);
	if (Etm_exit) {
		(void) pthread_mutex_unlock(&Etm_mod_lock);
		return;
	}
	(void) pthread_mutex_unlock(&Etm_mod_lock);

	if (mp->epm_oconn != NULL) {
		(void) etm_xport_close(hdl, mp->epm_oconn);
		mp->epm_oconn = NULL;
	}

	mp->epm_reconn_end = gethrtime() + Reconn_timeout;
	mp->epm_cstat = C_UNINITIALIZED;

	if (mp->epm_xprthdl != NULL) {
		fmd_xprt_suspend(hdl, mp->epm_xprthdl);
		mp->epm_qstat = Q_SUSPENDED;
		fmd_hdl_debug(hdl, "queue suspended for %s",  mp->epm_ep_str);

		if (mp->epm_timer_in_use == 0) {
			mp->epm_timer_id = fmd_timer_install(hdl, mp, NULL,
			    Reconn_interval);
			mp->epm_timer_in_use = 1;
		}
	}
}

/*
 * Reinitialize the connection. The old fmd_xprt_t handle must be
 * removed/closed first.
 * Assume caller holds lock on epm_lock.
 */
static void
etm_reinit(fmd_hdl_t *hdl, etm_epmap_t *mp)
{
	/*
	 * To avoid a deadlock, wait for etm_send to finish before
	 * calling fmd_xprt_close()
	 */
	while (mp->epm_txbusy)
		(void) pthread_cond_wait(&mp->epm_tx_cv, &mp->epm_lock);

	if (mp->epm_xprthdl != NULL) {
		fmd_xprt_close(hdl, mp->epm_xprthdl);
		fmd_hdl_debug(hdl, "queue closed for %s", mp->epm_ep_str);
		mp->epm_xprthdl = NULL;
		/* mp->epm_ep_nvl is free'd in fmd_xprt_close */
		mp->epm_ep_nvl = NULL;
	}

	if (mp->epm_timer_in_use) {
		fmd_timer_remove(hdl, mp->epm_timer_id);
		mp->epm_timer_in_use = 0;
	}

	if (mp->epm_oconn != NULL) {
		(void) etm_xport_close(hdl, mp->epm_oconn);
		mp->epm_oconn = NULL;
	}

	mp->epm_cstat = C_UNINITIALIZED;
	mp->epm_qstat = Q_UNINITIALIZED;
}

/*
 * Receive data from ETM transport layer.
 * Note : This is not the fmdo_recv entry point.
 *
 */
static int
etm_recv(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_epmap_t *mp)
{
	size_t buflen, hdrlen;
	void *buf;
	char hbuf[ETM_HDRLEN];
	int hdrstat, rv;

	hdrlen = ETM_HDRLEN;

	if ((etm_xport_read(hdl, conn, Rw_timeout, hbuf, hdrlen)) != hdrlen) {
		fmd_hdl_debug(hdl, "failed to read header from %s",
		    mp->epm_ep_str);
		INCRSTAT(Etm_stats.error_read.fmds_value.ui64);
		return (EIO);
	}

	hdrstat = etm_check_hdr(hdl, mp, hbuf);

	switch (hdrstat) {
	case ETM_HDR_INVALID:
		(void) pthread_mutex_lock(&mp->epm_lock);
		if (mp->epm_cstat == C_OPEN)
			mp->epm_cstat = C_CLOSED;
		(void) pthread_mutex_unlock(&mp->epm_lock);

		INCRSTAT(Etm_stats.error_read_badhdr.fmds_value.ui64);
		rv = ECANCELED;
		break;

	case ETM_HDR_BADTYPE:
	case ETM_HDR_BADVERSION:
		hdrlen = etm_create_hdr(hbuf, mp->epm_ver, ETM_HDR_NAK, 0);

		if ((etm_xport_write(hdl, conn, Rw_timeout, hbuf,
		    hdrlen)) != hdrlen) {
			fmd_hdl_debug(hdl, "failed to write NAK to %s",
			    mp->epm_ep_str);
			INCRSTAT(Etm_stats.error_write.fmds_value.ui64);
			return (EIO);
		}

		(void) pthread_mutex_lock(&mp->epm_lock);
		mp->epm_cstat = C_LIMBO;
		(void) pthread_mutex_unlock(&mp->epm_lock);

		INCRSTAT(Etm_stats.error_read_badhdr.fmds_value.ui64);
		rv = ENOTSUP;
		break;

	case ETM_HDR_C_HELLO:
		/* Client is initiating a startup handshake */
		(void) pthread_mutex_lock(&mp->epm_lock);
		etm_reinit(hdl, mp);
		mp->epm_qstat = Q_INIT_PENDING;
		(void) pthread_mutex_unlock(&mp->epm_lock);

		hdrlen = etm_create_hdr(hbuf, mp->epm_ver, ETM_HDR_S_HELLO, 0);

		if ((etm_xport_write(hdl, conn, Rw_timeout, hbuf,
		    hdrlen)) != hdrlen) {
			fmd_hdl_debug(hdl, "failed to write S_HELLO to %s",
			    mp->epm_ep_str);
			INCRSTAT(Etm_stats.error_write.fmds_value.ui64);
			return (EIO);
		}

		rv = 0;
		break;

	case ETM_HDR_ACK:
		(void) pthread_mutex_lock(&mp->epm_lock);
		if (mp->epm_qstat == Q_INIT_PENDING) {
			/* This is client's ACK from startup handshake */
			/* mp->epm_ep_nvl is free'd in fmd_xprt_close */
			if (mp->epm_ep_nvl == NULL)
				(void) etm_get_ep_nvl(hdl, mp);

			/*
			 * Call fmd_xprt_open and fmd_xprt_setspecific with
			 * Etm_mod_lock held to avoid race with etm_send thread.
			 */
			(void) pthread_mutex_lock(&Etm_mod_lock);
			if ((mp->epm_xprthdl = fmd_xprt_open(hdl,
			    mp->epm_xprtflags, mp->epm_ep_nvl, NULL)) == NULL) {
				fmd_hdl_abort(hdl, "Failed to init xprthdl "
				    "for %s", mp->epm_ep_str);
			}
			fmd_xprt_setspecific(hdl, mp->epm_xprthdl, mp);
			(void) pthread_mutex_unlock(&Etm_mod_lock);

			mp->epm_qstat = Q_OPEN;
			(void) pthread_mutex_unlock(&mp->epm_lock);
			fmd_hdl_debug(hdl, "queue open for %s",
			    mp->epm_ep_str);
		} else {
			(void) pthread_mutex_unlock(&mp->epm_lock);
			fmd_hdl_debug(hdl, "protocol error, not expecting ACK "
			    "from %s\n", mp->epm_ep_str);
			INCRSTAT(Etm_stats.error_protocol.fmds_value.ui64);
		}

		rv = 0;
		break;

	case ETM_HDR_SHUTDOWN:
		fmd_hdl_debug(hdl, "received shutdown from %s",
		    mp->epm_ep_str);

		(void) pthread_mutex_lock(&mp->epm_lock);

		etm_reinit(hdl, mp);

		if (IS_CLIENT(mp)) {
			/*
			 * A server shutdown is considered to be temporary.
			 * Prepare for reconnection.
			 */
			mp->epm_timer_id = fmd_timer_install(hdl, mp, NULL,
			    Reconn_interval);

			mp->epm_timer_in_use = 1;
		}

		(void) pthread_mutex_unlock(&mp->epm_lock);

		rv = ECANCELED;
		break;

	case ETM_HDR_MSG:
		(void) pthread_mutex_lock(&mp->epm_lock);
		if (mp->epm_qstat == Q_UNINITIALIZED) {
			/* Peer (client) is unaware that we've restarted */
			(void) pthread_mutex_unlock(&mp->epm_lock);
			hdrlen = etm_create_hdr(hbuf, mp->epm_ver,
			    ETM_HDR_S_RESTART, 0);

			if ((etm_xport_write(hdl, conn, Rw_timeout, hbuf,
			    hdrlen)) != hdrlen) {
				fmd_hdl_debug(hdl, "failed to write S_RESTART "
				    "to %s", mp->epm_ep_str);
				INCRSTAT(Etm_stats.error_write.fmds_value.ui64);
				return (EIO);
			}

			return (ECANCELED);
		}
		(void) pthread_mutex_unlock(&mp->epm_lock);

		buflen = etm_get_msglen(hbuf);
		ALLOC_BUF(hdl, buf, buflen);

		if (etm_xport_read(hdl, conn, Rw_timeout, buf,
		    buflen) != buflen) {
			fmd_hdl_debug(hdl, "failed to read message from %s",
			    mp->epm_ep_str);
			FREE_BUF(hdl, buf, buflen);
			INCRSTAT(Etm_stats.error_read.fmds_value.ui64);
			return (EIO);
		}

		INCRSTAT(Etm_stats.read_msg.fmds_value.ui64);
		ADDSTAT(Etm_stats.read_bytes.fmds_value.ui64, buflen);

		etm_hex_dump(hdl, buf, buflen, 0);

		if (etm_post_msg(hdl, mp, buf, buflen)) {
			INCRSTAT(Etm_stats.error_drop_read.fmds_value.ui64);
			FREE_BUF(hdl, buf, buflen);
			return (EIO);
		}

		FREE_BUF(hdl, buf, buflen);

		hdrlen = etm_create_hdr(hbuf, mp->epm_ver, ETM_HDR_ACK, 0);

		if ((etm_xport_write(hdl, conn, Rw_timeout, hbuf,
		    hdrlen)) != hdrlen) {
			fmd_hdl_debug(hdl, "failed to write ACK to %s",
			    mp->epm_ep_str);
			INCRSTAT(Etm_stats.error_write.fmds_value.ui64);
			return (EIO);
		}

		INCRSTAT(Etm_stats.write_ack.fmds_value.ui64);

		/*
		 * If we got this far and the current state of the
		 * outbound/sending connection is TIMED_OUT or
		 * LIMBO, then we should reinitialize it.
		 */
		(void) pthread_mutex_lock(&mp->epm_lock);
		if (mp->epm_cstat == C_TIMED_OUT ||
		    mp->epm_cstat == C_LIMBO) {
			if (mp->epm_oconn != NULL) {
				(void) etm_xport_close(hdl, mp->epm_oconn);
				mp->epm_oconn = NULL;
			}
			mp->epm_cstat = C_UNINITIALIZED;
			fmd_xprt_resume(hdl, mp->epm_xprthdl);
			if (mp->epm_timer_in_use) {
				fmd_timer_remove(hdl, mp->epm_timer_id);
				mp->epm_timer_in_use = 0;
			}
			mp->epm_qstat = Q_OPEN;
			fmd_hdl_debug(hdl, "queue resumed for %s",
			    mp->epm_ep_str);
		}
		(void) pthread_mutex_unlock(&mp->epm_lock);

		rv = 0;
		break;

	default:
		fmd_hdl_debug(hdl, "protocol error, unexpected header "
		    "from %s : %d", mp->epm_ep_str, hdrstat);
		INCRSTAT(Etm_stats.error_protocol.fmds_value.ui64);
		rv = 0;
	}

	return (rv);
}

/*
 * ETM transport layer callback function.
 * The transport layer calls this function to :
 *	(a) pass an incoming message (flag == ETM_CBFLAG_RECV)
 *	(b) tell us to reinitialize the connection (flag == ETM_CBFLAG_REINIT)
 */
static int
etm_cb_func(fmd_hdl_t *hdl, etm_xport_conn_t conn, etm_cb_flag_t flag,
    void *arg)
{
	etm_epmap_t *mp = (etm_epmap_t *)arg;
	int rv = 0;

	(void) pthread_mutex_lock(&Etm_mod_lock);
	if (Etm_exit) {
		(void) pthread_mutex_unlock(&Etm_mod_lock);
		return (ECANCELED);
	}
	(void) pthread_mutex_unlock(&Etm_mod_lock);

	switch (flag) {
	case ETM_CBFLAG_RECV:
		rv = etm_recv(hdl, conn, mp);
		break;
	case ETM_CBFLAG_REINIT:
		(void) pthread_mutex_lock(&mp->epm_lock);
		etm_reinit(hdl, mp);
		etm_send_shutdown(hdl, mp);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		/*
		 * Return ECANCELED so the transport layer will close the
		 * server connection.  The transport layer is responsible for
		 * reestablishing this connection (should a connection request
		 * arrive from the peer).
		 */
		rv = ECANCELED;
		break;
	default:
		fmd_hdl_debug(hdl, "Unknown callback flag : 0x%x", flag);
		rv = ENOTSUP;
	}

	return (rv);
}

/*
 * Allocate and initialize an etm_epmap_t struct for the given endpoint
 * name string.
 */
static void
etm_init_epmap(fmd_hdl_t *hdl, char *epname, int flags)
{
	etm_epmap_t *newmap;

	if (etm_check_dup_ep_str(hdl, epname)) {
		fmd_hdl_debug(hdl, "skipping duplicate peer : %s", epname);
		return;
	}

	newmap = fmd_hdl_zalloc(hdl, sizeof (etm_epmap_t), FMD_SLEEP);
	newmap->epm_ep_str = fmd_hdl_strdup(hdl, epname, FMD_SLEEP);
	newmap->epm_xprtflags = flags;
	newmap->epm_cstat = C_UNINITIALIZED;
	newmap->epm_qstat = Q_UNINITIALIZED;
	newmap->epm_ver = ETM_PROTO_V1;	/* Currently support one proto ver */
	newmap->epm_txbusy = 0;

	(void) pthread_mutex_init(&newmap->epm_lock, NULL);
	(void) pthread_cond_init(&newmap->epm_tx_cv, NULL);

	if (etm_get_ep_nvl(hdl, newmap)) {
		fmd_hdl_strfree(hdl, newmap->epm_ep_str);
		fmd_hdl_free(hdl, newmap, sizeof (etm_epmap_t));
		return;
	}

	(void) pthread_mutex_lock(&newmap->epm_lock);

	if ((newmap->epm_tlhdl = etm_xport_init(hdl, newmap->epm_ep_str,
	    etm_cb_func, newmap)) == NULL) {
		fmd_hdl_debug(hdl, "failed to init tlhdl for %s\n",
		    newmap->epm_ep_str);
		etm_free_ep_nvl(hdl, newmap);
		(void) pthread_mutex_unlock(&newmap->epm_lock);
		(void) pthread_mutex_destroy(&newmap->epm_lock);
		fmd_hdl_strfree(hdl, newmap->epm_ep_str);
		fmd_hdl_free(hdl, newmap, sizeof (etm_epmap_t));
		return;
	}

	if (IS_CLIENT(newmap)) {
		if (etm_handle_startup(hdl, newmap)) {
			/*
			 * For whatever reason, we could not complete the
			 * startup handshake with the server.  Set the timer
			 * and try again.
			 */
			if (newmap->epm_oconn != NULL) {
				(void) etm_xport_close(hdl, newmap->epm_oconn);
				newmap->epm_oconn = NULL;
			}
			newmap->epm_cstat = C_UNINITIALIZED;
			newmap->epm_qstat = Q_UNINITIALIZED;
			newmap->epm_timer_id = fmd_timer_install(hdl, newmap,
			    NULL, Reconn_interval);
			newmap->epm_timer_in_use = 1;
		}
	} else {
		/*
		 * We may be restarting after a crash.  If so, the client
		 * may be unaware of this.
		 */
		etm_send_shutdown(hdl, newmap);
	}

	/* Add this transport instance handle to the list */
	newmap->epm_next = Epmap_head;
	Epmap_head = newmap;

	(void) pthread_mutex_unlock(&newmap->epm_lock);

	INCRSTAT(Etm_stats.peer_count.fmds_value.ui64);
}

/*
 * Parse the given property list string and call etm_init_epmap
 * for each endpoint.
 */
static void
etm_create_epmaps(fmd_hdl_t *hdl, char *eplist, int flags)
{
	char *epstr, *ep, *prefix, *lasts, *numstr;
	char epname[MAXPATHLEN];
	size_t slen, nlen;
	int beg, end, i;

	if (eplist == NULL)
		return;
	/*
	 * Create a copy of eplist for parsing.
	 * strtok/strtok_r(3C) will insert null chars to the string.
	 * Therefore, fmd_hdl_strdup/fmd_hdl_strfree cannot be used.
	 */
	slen = strlen(eplist);
	epstr = fmd_hdl_zalloc(hdl, slen + 1, FMD_SLEEP);
	(void) strcpy(epstr, eplist);

	/*
	 * The following are supported for the "client_list" and
	 * "server_list" properties :
	 *
	 *    A space-separated list of endpoints.
	 *	"dev:///dom0 dev:///dom1 dev:///dom2"
	 *
	 *    An array syntax for a range of instances.
	 *	"dev:///dom[0:2]"
	 *
	 *    A combination of both.
	 *	"dev:///dom0 dev:///dom[1:2]"
	 */
	ep = strtok_r(epstr, " ", &lasts);
	while (ep != NULL) {
		if (strchr(ep, '[') != NULL) {
			/*
			 * This string is using array syntax.
			 * Check the string for correct syntax.
			 */
			if ((strchr(ep, ':') == NULL) ||
			    (strchr(ep, ']') == NULL)) {
				fmd_hdl_error(hdl, "Syntax error in property "
				    "that includes : %s\n", ep);
				ep = strtok_r(NULL, " ", &lasts);
				continue;
			}

			/* expand the array syntax */
			prefix = strtok(ep, "[");

			numstr = strtok(NULL, ":");
			if ((numstr == NULL) || (!isdigit(*numstr))) {
				fmd_hdl_error(hdl, "Syntax error in property "
				    "that includes : %s[\n", prefix);
				ep = strtok_r(NULL, " ", &lasts);
				continue;
			}
			beg = atoi(numstr);

			numstr = strtok(NULL, "]");
			if ((numstr == NULL) || (!isdigit(*numstr))) {
				fmd_hdl_error(hdl, "Syntax error in property "
				    "that includes : %s[\n", prefix);
				ep = strtok_r(NULL, " ", &lasts);
				continue;
			}
			end = atoi(numstr);

			nlen = strlen(prefix) + ETM_EP_INST_MAX;

			if (nlen > MAXPATHLEN) {
				fmd_hdl_error(hdl, "Endpoint prop string "
				    "exceeds MAXPATHLEN\n");
				ep = strtok_r(NULL, " ", &lasts);
				continue;
			}

			for (i = beg; i <= end; i++) {
				bzero(epname, MAXPATHLEN);
				(void) snprintf(epname, nlen, "%s%d",
				    prefix, i);
				etm_init_epmap(hdl, epname, flags);
			}
		} else {
			etm_init_epmap(hdl, ep, flags);
		}

		ep = strtok_r(NULL, " ", &lasts);
	}

	fmd_hdl_free(hdl, epstr, slen + 1);
}

/*
 * Free the transport infrastructure for an endpoint.
 */
static void
etm_free_epmap(fmd_hdl_t *hdl, etm_epmap_t *mp)
{
	size_t hdrlen;
	char hbuf[ETM_HDRLEN];

	(void) pthread_mutex_lock(&mp->epm_lock);

	/*
	 * If an etm_send thread is in progress, wait for it to finish.
	 * The etm_recv thread is managed by the transport layer and will
	 * be destroyed with etm_xport_fini().
	 */
	while (mp->epm_txbusy)
		(void) pthread_cond_wait(&mp->epm_tx_cv, &mp->epm_lock);

	if (mp->epm_timer_in_use)
		fmd_timer_remove(hdl, mp->epm_timer_id);

	if (mp->epm_oconn != NULL) {
		hdrlen = etm_create_hdr(hbuf, mp->epm_ver,
		    ETM_HDR_SHUTDOWN, 0);
		(void) etm_xport_write(hdl, mp->epm_oconn, Rw_timeout, hbuf,
		    hdrlen);
		(void) etm_xport_close(hdl, mp->epm_oconn);
		mp->epm_oconn = NULL;
	}

	if (mp->epm_xprthdl != NULL) {
		fmd_xprt_close(hdl, mp->epm_xprthdl);
		/* mp->epm_ep_nvl is free'd in fmd_xprt_close */
		mp->epm_ep_nvl = NULL;
	}

	if (mp->epm_ep_nvl != NULL)
		etm_free_ep_nvl(hdl, mp);

	if (mp->epm_tlhdl != NULL)
		(void) etm_xport_fini(hdl, mp->epm_tlhdl);

	(void) pthread_mutex_unlock(&mp->epm_lock);
	(void) pthread_mutex_destroy(&mp->epm_lock);
	fmd_hdl_strfree(hdl, mp->epm_ep_str);
	fmd_hdl_free(hdl, mp, sizeof (etm_epmap_t));
	DECRSTAT(Etm_stats.peer_count.fmds_value.ui64);
}

/*
 * FMD entry points
 */

/*
 * FMD fmdo_send entry point.
 * Send an event to the remote endpoint and receive an ACK.
 */
static int
etm_send(fmd_hdl_t *hdl, fmd_xprt_t *xprthdl, fmd_event_t *ep, nvlist_t *nvl)
{
	etm_epmap_t *mp;
	nvlist_t *msgnvl;
	int hdrstat, rv, cnt = 0;
	char *buf, *nvbuf, *class;
	size_t nvsize, buflen, hdrlen;
	struct timespec tms;

	(void) pthread_mutex_lock(&Etm_mod_lock);
	if (Etm_exit) {
		(void) pthread_mutex_unlock(&Etm_mod_lock);
		return (FMD_SEND_RETRY);
	}
	(void) pthread_mutex_unlock(&Etm_mod_lock);

	mp = fmd_xprt_getspecific(hdl, xprthdl);

	for (;;) {
		if (pthread_mutex_trylock(&mp->epm_lock) == 0) {
			break;
		} else {
			/*
			 * Another thread may be (1) trying to close this
			 * fmd_xprt_t, or (2) posting an event to it.
			 * If (1), don't want to spend too much time here.
			 * If (2), allow it to finish and release epm_lock.
			 */
			if (cnt++ < 10) {
				tms.tv_sec = 0;
				tms.tv_nsec = (cnt * 10000);
				(void) nanosleep(&tms, NULL);

			} else {
				return (FMD_SEND_RETRY);
			}
		}
	}

	mp->epm_txbusy++;

	if (mp->epm_qstat == Q_UNINITIALIZED) {
		mp->epm_txbusy--;
		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		return (FMD_SEND_FAILED);
	}

	if (mp->epm_cstat == C_CLOSED) {
		etm_suspend_reconnect(hdl, mp);
		mp->epm_txbusy--;
		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		return (FMD_SEND_RETRY);
	}

	if (mp->epm_cstat == C_LIMBO) {
		if (mp->epm_oconn != NULL) {
			(void) etm_xport_close(hdl, mp->epm_oconn);
			mp->epm_oconn = NULL;
		}

		fmd_xprt_suspend(hdl, xprthdl);
		mp->epm_qstat = Q_SUSPENDED;
		mp->epm_txbusy--;
		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		fmd_hdl_debug(hdl, "queue suspended for %s", mp->epm_ep_str);
		return (FMD_SEND_RETRY);
	}

	if (mp->epm_oconn == NULL) {
		if ((mp->epm_oconn = etm_xport_open(hdl, mp->epm_tlhdl))
		    == NULL) {
			etm_suspend_reconnect(hdl, mp);
			mp->epm_txbusy--;
			(void) pthread_cond_broadcast(&mp->epm_tx_cv);
			(void) pthread_mutex_unlock(&mp->epm_lock);
			return (FMD_SEND_RETRY);
		} else {
			mp->epm_cstat = C_OPEN;
		}
	}

	if (nvlist_lookup_string(nvl, FM_CLASS, &class) != 0)
		fmd_hdl_abort(hdl, "No class string in nvlist");

	msgnvl = fmd_xprt_translate(hdl, xprthdl, ep);
	if (msgnvl == NULL) {
		mp->epm_txbusy--;
		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		fmd_hdl_error(hdl, "Failed to translate event %p\n",
		    (void *) ep);
		return (FMD_SEND_FAILED);
	}

	rv = etm_xport_send_filter(hdl, msgnvl, mp->epm_ep_str);
	if (rv == ETM_XPORT_FILTER_DROP) {
		mp->epm_txbusy--;
		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		fmd_hdl_debug(hdl, "send_filter dropped event");
		nvlist_free(msgnvl);
		INCRSTAT(Etm_stats.send_filter.fmds_value.ui64);
		return (FMD_SEND_SUCCESS);
	} else if (rv == ETM_XPORT_FILTER_ERROR) {
		fmd_hdl_debug(hdl, "send_filter error : %s", strerror(errno));
		INCRSTAT(Etm_stats.error_send_filter.fmds_value.ui64);
		/* Still send event */
	}

	(void) pthread_mutex_unlock(&mp->epm_lock);

	(void) nvlist_size(msgnvl, &nvsize, NV_ENCODE_XDR);

	hdrlen = ETM_HDRLEN;
	buflen = nvsize + hdrlen;

	ALLOC_BUF(hdl, buf, buflen);

	nvbuf = buf + hdrlen;

	(void) etm_create_hdr(buf, mp->epm_ver, ETM_HDR_MSG, nvsize);

	if (rv = nvlist_pack(msgnvl, &nvbuf, &nvsize, NV_ENCODE_XDR, 0)) {
		(void) pthread_mutex_lock(&mp->epm_lock);
		mp->epm_txbusy--;
		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		fmd_hdl_error(hdl, "Failed to pack event : %s\n", strerror(rv));
		nvlist_free(msgnvl);
		FREE_BUF(hdl, buf, buflen);
		return (FMD_SEND_FAILED);
	}

	nvlist_free(msgnvl);

	if (etm_xport_write(hdl, mp->epm_oconn, Rw_timeout, buf,
	    buflen) != buflen) {
		fmd_hdl_debug(hdl, "failed to send message to %s",
		    mp->epm_ep_str);
		(void) pthread_mutex_lock(&mp->epm_lock);
		etm_suspend_reconnect(hdl, mp);
		mp->epm_txbusy--;
		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		FREE_BUF(hdl, buf, buflen);
		INCRSTAT(Etm_stats.error_write.fmds_value.ui64);
		return (FMD_SEND_RETRY);
	}

	INCRSTAT(Etm_stats.write_msg.fmds_value.ui64);
	ADDSTAT(Etm_stats.write_bytes.fmds_value.ui64, nvsize);

	etm_hex_dump(hdl, nvbuf, nvsize, 1);

	if (etm_xport_read(hdl, mp->epm_oconn, Rw_timeout, buf,
	    hdrlen) != hdrlen) {
		fmd_hdl_debug(hdl, "failed to read ACK from %s",
		    mp->epm_ep_str);
		(void) pthread_mutex_lock(&mp->epm_lock);
		etm_suspend_reconnect(hdl, mp);
		mp->epm_txbusy--;
		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);
		FREE_BUF(hdl, buf, buflen);
		INCRSTAT(Etm_stats.error_read.fmds_value.ui64);
		return (FMD_SEND_RETRY);
	}

	hdrstat = etm_check_hdr(hdl, mp, buf);
	FREE_BUF(hdl, buf, buflen);

	if (hdrstat == ETM_HDR_ACK) {
		INCRSTAT(Etm_stats.read_ack.fmds_value.ui64);
	} else {
		(void) pthread_mutex_lock(&mp->epm_lock);

		(void) etm_xport_close(hdl, mp->epm_oconn);
		mp->epm_oconn = NULL;

		if (hdrstat == ETM_HDR_NAK) {
			/* Peer received a bad value in the header */
			if (mp->epm_xprthdl != NULL) {
				mp->epm_cstat = C_LIMBO;
				fmd_xprt_suspend(hdl, xprthdl);
				mp->epm_qstat = Q_SUSPENDED;
				fmd_hdl_debug(hdl, "received NAK, queue "
				    "suspended for %s", mp->epm_ep_str);
			}

			rv = FMD_SEND_RETRY;

		} else if (hdrstat == ETM_HDR_S_RESTART) {
			/* Server has restarted */
			mp->epm_cstat = C_CLOSED;
			mp->epm_qstat = Q_UNINITIALIZED;
			fmd_hdl_debug(hdl, "server %s restarted",
			    mp->epm_ep_str);
			/*
			 * Cannot call fmd_xprt_close here, so we'll do it
			 * on the timeout thread.
			 */
			if (mp->epm_timer_in_use == 0) {
				mp->epm_timer_id = fmd_timer_install(
				    hdl, mp, NULL, 0);
				mp->epm_timer_in_use = 1;
			}

			/*
			 * fault.* or list.* events will be replayed if a
			 * transport is opened with the same auth.
			 * Other events will be discarded.
			 */
			rv = FMD_SEND_FAILED;

		} else {
			mp->epm_cstat = C_CLOSED;
			fmd_hdl_debug(hdl, "bad ACK from %s", mp->epm_ep_str);

			rv = FMD_SEND_RETRY;
		}

		mp->epm_txbusy--;

		(void) pthread_cond_broadcast(&mp->epm_tx_cv);
		(void) pthread_mutex_unlock(&mp->epm_lock);

		INCRSTAT(Etm_stats.error_read_badhdr.fmds_value.ui64);

		return (rv);
	}

	(void) pthread_mutex_lock(&mp->epm_lock);
	mp->epm_txbusy--;
	(void) pthread_cond_broadcast(&mp->epm_tx_cv);
	(void) pthread_mutex_unlock(&mp->epm_lock);

	return (FMD_SEND_SUCCESS);
}

/*
 * FMD fmdo_timeout entry point..
 */
/*ARGSUSED*/
static void
etm_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	etm_epmap_t *mp = (etm_epmap_t *)data;

	(void) pthread_mutex_lock(&mp->epm_lock);

	mp->epm_timer_in_use = 0;

	if (mp->epm_qstat == Q_UNINITIALIZED) {
		/* Server has shutdown and we (client) need to reconnect */
		if (mp->epm_xprthdl != NULL) {
			fmd_xprt_close(hdl, mp->epm_xprthdl);
			fmd_hdl_debug(hdl, "queue closed for %s",
			    mp->epm_ep_str);
			mp->epm_xprthdl = NULL;
			/* mp->epm_ep_nvl is free'd in fmd_xprt_close */
			mp->epm_ep_nvl = NULL;
		}

		if (mp->epm_ep_nvl == NULL)
			(void) etm_get_ep_nvl(hdl, mp);

		if (etm_handle_startup(hdl, mp)) {
			if (mp->epm_oconn != NULL) {
				(void) etm_xport_close(hdl, mp->epm_oconn);
				mp->epm_oconn = NULL;
			}
			mp->epm_cstat = C_UNINITIALIZED;
			mp->epm_qstat = Q_UNINITIALIZED;
			mp->epm_timer_id = fmd_timer_install(hdl, mp, NULL,
			    Reconn_interval);
			mp->epm_timer_in_use = 1;
		}
	} else {
		etm_reconnect(hdl, mp);
	}

	(void) pthread_mutex_unlock(&mp->epm_lock);
}

/*
 * FMD Module declarations
 */
static const fmd_hdl_ops_t etm_ops = {
	NULL,		/* fmdo_recv */
	etm_timeout,	/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	etm_send,	/* fmdo_send */
};

static const fmd_prop_t etm_props[] = {
	{ "client_list", FMD_TYPE_STRING, NULL },
	{ "server_list", FMD_TYPE_STRING, NULL },
	{ "reconnect_interval",	FMD_TYPE_UINT64, "10000000000" },
	{ "reconnect_timeout", FMD_TYPE_UINT64, "300000000000" },
	{ "rw_timeout", FMD_TYPE_UINT64, "2000000000" },
	{ "filter_path", FMD_TYPE_STRING, NULL },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t etm_info = {
	"Event Transport Module", "2.0", &etm_ops, etm_props
};

/*
 * Initialize the transport for use by ETM.
 */
void
_fmd_init(fmd_hdl_t *hdl)
{
	char *propstr;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &etm_info) != 0) {
		return; /* invalid data in configuration file */
	}

	/* Create global stats */
	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (Etm_stats) / sizeof (fmd_stat_t), (fmd_stat_t *)&Etm_stats);

	/* Get module properties */
	Reconn_timeout = fmd_prop_get_int64(hdl, "reconnect_timeout");
	Reconn_interval = fmd_prop_get_int64(hdl, "reconnect_interval");
	Rw_timeout = fmd_prop_get_int64(hdl, "rw_timeout");

	propstr = fmd_prop_get_string(hdl, "client_list");
	etm_create_epmaps(hdl, propstr, ETM_SERVER_XPRT_FLAGS);
	fmd_prop_free_string(hdl, propstr);

	propstr = fmd_prop_get_string(hdl, "server_list");
	etm_create_epmaps(hdl, propstr, ETM_CLIENT_XPRT_FLAGS);
	fmd_prop_free_string(hdl, propstr);

	if (Etm_stats.peer_count.fmds_value.ui64 == 0) {
		fmd_hdl_debug(hdl, "Failed to init any endpoint\n");
		fmd_hdl_unregister(hdl);
		return;
	}
}

/*
 * Teardown the transport
 */
void
_fmd_fini(fmd_hdl_t *hdl)
{
	etm_epmap_t *mp, *next;

	(void) pthread_mutex_lock(&Etm_mod_lock);
	Etm_exit = 1;
	(void) pthread_mutex_unlock(&Etm_mod_lock);

	mp = Epmap_head;

	while (mp) {
		next = mp->epm_next;
		etm_free_epmap(hdl, mp);
		mp = next;
	}

	fmd_hdl_unregister(hdl);
}
