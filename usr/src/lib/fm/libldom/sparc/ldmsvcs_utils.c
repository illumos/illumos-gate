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

#include <stdlib.h>
#include <stdio.h>

#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <umem.h>
#include <alloca.h>
#include <sys/processor.h>
#include <poll.h>
#include <pthread.h>
#include <values.h>
#include <libscf.h>

#include <ctype.h>

#include "ldmsvcs_utils.h"

#define	ASSERT(cnd) \
	((void) ((cnd) || ((void) fprintf(stderr, \
		"assertion failure in %s:%d: %s\n", \
		__FILE__, __LINE__, #cnd), 0)))

#define	FDS_VLDC \
	"/devices/virtual-devices@100/channel-devices@200/" \
	"/virtual-channel-client@1:ldmfma"

/* allow timeouts in sec that are nearly forever but small enough for an int */
#define	LDM_TIMEOUT_CEILING	(MAXINT / 2)

#define	MIN(x, y)	((x) < (y) ? (x) : (y))

/*
 * functions in this file are for version 1.0 of FMA domain services
 */
static ds_ver_t ds_vers[] = {
	{ 1, 0 }
};

#define	DS_NUM_VER	(sizeof (ds_vers) / sizeof (ds_ver_t))

/*
 * information for each channel
 */
struct ldmsvcs_info {
	pthread_mutex_t mt;
	pthread_cond_t cv;
	fds_channel_t fds_chan;
	fds_reg_svcs_t fmas_svcs;
	int cv_twait;
};

/*
 * struct listdata_s and struct poller_s are used to maintain the state of
 * the poller thread.  this thread is used to manage incoming messages and
 * pass those messages onto the correct requesting thread.  see the "poller
 * functions" section for more details.
 */
struct listdata_s {
	enum {
		UNUSED,
		PENDING,
		ARRIVED
	} status;
	uint64_t req_num;
	int fd;
	size_t datalen;
};

static struct poller_s {
	pthread_mutex_t mt;
	pthread_cond_t cv;
	pthread_t polling_tid;
	int doreset;
	int doexit;
	int nclients;
	struct listdata_s **list;
	int list_len;
	int pending_count;
} pollbase = {
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	0,
	1,
	0,
	0,
	NULL,
	0,
	0
};


static struct ldmsvcs_info *channel_init(struct ldom_hdl *lhp);
static int channel_openreset(struct ldmsvcs_info *lsp);
static int read_msg(struct ldmsvcs_info *lsp);

static int
get_smf_int_val(char *prop_nm, int min, int max, int default_val)
{
	scf_simple_prop_t	*prop;		/* SMF property */
	int64_t			*valp;		/* prop value ptr */
	int64_t			val;		/* prop value to return */

	val = default_val;
	if ((prop = scf_simple_prop_get(NULL, LDM_SVC_NM, LDM_PROP_GROUP_NM,
	    prop_nm)) != NULL) {
		if ((valp = scf_simple_prop_next_integer(prop)) != NULL) {
			val = *valp;
			if (val < min)
				val = min;
			else if (val > max)
				val = max;
		}
		scf_simple_prop_free(prop);
	}
	return ((int)val);
}

static void
channel_close(struct ldmsvcs_info *lsp)
{
	(void) pthread_mutex_lock(&lsp->mt);

	if (lsp->fds_chan.state == CHANNEL_OPEN ||
	    lsp->fds_chan.state == CHANNEL_READY) {
		(void) close(lsp->fds_chan.fd);
		lsp->cv_twait = get_smf_int_val(LDM_INIT_TO_PROP_NM,
		    0, LDM_TIMEOUT_CEILING, LDM_INIT_WAIT_TIME);
		lsp->fds_chan.state = CHANNEL_CLOSED;
	}

	(void) pthread_mutex_unlock(&lsp->mt);
}

/*
 * read size bytes of data from a streaming fd into buf
 */
static int
read_stream(int fd, void *buf, size_t size)
{
	pollfd_t pollfd;
	ssize_t rv;
	size_t data_left;
	ptrdiff_t currentp;

	pollfd.events = POLLIN;
	pollfd.revents = 0;
	pollfd.fd = fd;

	currentp = (ptrdiff_t)buf;
	data_left = size;

	/*
	 * data may come in bits and pieces
	 */
	do {
		if ((rv = read(fd, (void *)currentp, data_left)) < 0) {
			if (errno == EAGAIN && poll(&pollfd, 1, -1) > 0)
				continue;	/* retry */
			else
				return (1);
		}

		data_left -= rv;
		currentp += rv;
	} while (data_left > 0);

	return (0);
}


/*
 * poller functions
 *
 * at init time, a thread is created for the purpose of monitoring incoming
 * messages and doing one of the following:
 *
 * 1. doing the initial handshake and version negotiation
 *
 * 2. handing incoming data off to the requesting thread (which is an fmd
 * module or scheme thread)
 */
static int
poller_handle_data(int fd, size_t payloadsize)
{
	uint64_t *req_num;
	void *pr;
	size_t prlen;
	int i;

	prlen = sizeof (ds_data_handle_t) + sizeof (uint64_t);

	if (payloadsize < prlen)
		return (1);

	pr = alloca(prlen);

	if (read_stream(fd, pr, prlen) != 0)
		return (1);

	req_num = (uint64_t *)((ptrdiff_t)pr + sizeof (ds_data_handle_t));

	(void) pthread_mutex_lock(&pollbase.mt);

	for (i = 0; i < pollbase.list_len; i++) {
		if (pollbase.list[i]->req_num == *req_num) {
			ASSERT(pollbase.list[i]->status == PENDING);

			pollbase.list[i]->status = ARRIVED;
			pollbase.list[i]->fd = fd;
			pollbase.list[i]->datalen = payloadsize - prlen;

			pollbase.pending_count--;
			(void) pthread_cond_broadcast(&pollbase.cv);
			break;
		}
	}

	/*
	 * now wait for receiving thread to read in the data
	 */
	if (i < pollbase.list_len) {
		while (pollbase.list[i]->status == ARRIVED)
			(void) pthread_cond_wait(&pollbase.cv, &pollbase.mt);
	}

	(void) pthread_mutex_unlock(&pollbase.mt);

	return (0);
}


/*
 * note that this function is meant to handle only DS_DATA messages
 */
static int
poller_recv_data(struct ldom_hdl *lhp, uint64_t req_num, int index,
		void **resp, size_t *resplen)
{
	struct timespec twait;
	int ier;

	ier = 0;
	twait.tv_sec = time(NULL) + lhp->lsinfo->cv_twait;
	twait.tv_nsec = 0;

	(void) pthread_mutex_lock(&pollbase.mt);

	ASSERT(pollbase.list[index]->req_num == req_num);

	while (pollbase.list[index]->status == PENDING &&
	    pollbase.doreset == 0 && ier == 0)
		ier = pthread_cond_timedwait(&pollbase.cv, &pollbase.mt,
		    &twait);

	if (ier == 0) {
		if (pollbase.doreset == 0) {
			ASSERT(pollbase.list[index]->status == ARRIVED);

			/*
			 * need to add req_num to beginning of resp
			 */
			*resplen = pollbase.list[index]->datalen +
			    sizeof (uint64_t);
			*resp = lhp->allocp(*resplen);
			*((uint64_t *)*resp) = req_num;

			if (read_stream(pollbase.list[index]->fd,
			    (void *)((ptrdiff_t)*resp + sizeof (uint64_t)),
			    *resplen - sizeof (uint64_t)) != 0)
				ier = ETIMEDOUT;

			pollbase.list[index]->status = UNUSED;
			pollbase.list[index]->req_num = 0;
			(void) pthread_cond_broadcast(&pollbase.cv);
		} else {
			if (--(pollbase.pending_count) == 0)
				(void) pthread_cond_broadcast(&pollbase.cv);
		}
	}

	(void) pthread_mutex_unlock(&pollbase.mt);

	ASSERT(ier == 0 || ier == ETIMEDOUT);

	return (ier);
}


static void
poller_add_client(void)
{
	(void) pthread_mutex_lock(&pollbase.mt);
	pollbase.nclients++;
	(void) pthread_mutex_unlock(&pollbase.mt);
}


static void
poller_remove_client(void)
{
	(void) pthread_mutex_lock(&pollbase.mt);
	pollbase.nclients--;
	ASSERT(pollbase.nclients >= 0);
	(void) pthread_mutex_unlock(&pollbase.mt);
}


static int
poller_add_pending(struct ldom_hdl *lhp, uint64_t req_num)
{
	int newlen, index, i, j;

	(void) pthread_mutex_lock(&pollbase.mt);
	pollbase.pending_count++;

	for (j = 0, index = -1; j < 2 && index == -1; j++) {
		for (i = 0; i < pollbase.list_len; i++) {
			if (pollbase.list[i]->status == UNUSED) {
				pollbase.list[i]->status = PENDING;
				pollbase.list[i]->req_num = req_num;
				pollbase.list[i]->datalen = 0;
				index = i;
				break;
			}
		}

		if (index == -1) {
			struct listdata_s **newlist, **oldlist;

			/*
			 * get to this point if list is not long enough.
			 * check for a runaway list.  since requests are
			 * synchronous (clients send a request and need to
			 * wait for the result before returning) the size
			 * of the list cannot be much more than the number
			 * of clients.
			 */
			ASSERT(pollbase.list_len < pollbase.nclients + 1);

			newlen = pollbase.list_len + 5;
			newlist = lhp->allocp(newlen *
			    sizeof (struct listdata_s));

			for (i = 0; i < pollbase.list_len; i++)
				newlist[i] = pollbase.list[i];

			oldlist = pollbase.list;
			pollbase.list = newlist;
			lhp->freep(oldlist, pollbase.list_len *
			    sizeof (struct listdata_s));

			for (i = pollbase.list_len; i < newlen; i++) {
				pollbase.list[i] =
				    lhp->allocp(sizeof (struct listdata_s));
				pollbase.list[i]->status = UNUSED;
			}

			pollbase.list_len = newlen;
		}
	}

	(void) pthread_mutex_unlock(&pollbase.mt);
	ASSERT(index != -1);

	return (index);
}


static void
poller_delete_pending(uint64_t req_num, int index)
{
	(void) pthread_mutex_lock(&pollbase.mt);

	ASSERT(pollbase.list[index]->req_num == req_num);
	pollbase.list[index]->status = UNUSED;

	if (--(pollbase.pending_count) == 0 && pollbase.doreset == 1)
		(void) pthread_cond_broadcast(&pollbase.cv);

	(void) pthread_mutex_unlock(&pollbase.mt);
}


static void
poller_shutdown(void)
{
	(void) pthread_mutex_lock(&pollbase.mt);

	pollbase.doexit = 1;

	(void) pthread_mutex_unlock(&pollbase.mt);
}


/*
 * perform the polling of incoming messages.  manage any resets (usually
 * due to one end of the connection being closed) as well as exit
 * conditions.
 */
static void *
poller_loop(void *arg)
{
	struct ldmsvcs_info *lsp;
	pollfd_t pollfd;
	int ier;

	lsp = (struct ldmsvcs_info *)arg;

	for (;;) {
		(void) pthread_mutex_lock(&pollbase.mt);

		if (pollbase.doexit) {
			(void) pthread_mutex_unlock(&pollbase.mt);
			break;
		}

		if (pollbase.doreset) {
			int i;

			while (pollbase.pending_count > 0)
				(void) pthread_cond_wait(&pollbase.cv,
				    &pollbase.mt);

			ASSERT(pollbase.pending_count == 0);
			for (i = 0; i < pollbase.list_len; i++)
				pollbase.list[i]->status = UNUSED;

			pollbase.doreset = 0;
		}
		(void) pthread_mutex_unlock(&pollbase.mt);

		if ((ier = channel_openreset(lsp)) == 1) {
			continue;
		} else if (ier == 2) {
			/*
			 * start exit preparations
			 */
			poller_shutdown();
			continue;
		}

		pollfd.events = POLLIN;
		pollfd.revents = 0;
		pollfd.fd = lsp->fds_chan.fd;

		if (poll(&pollfd, 1, -1) <= 0 || read_msg(lsp) != 0) {
			/*
			 * read error and/or fd got closed
			 */
			(void) pthread_mutex_lock(&pollbase.mt);
			pollbase.doreset = 1;
			(void) pthread_mutex_unlock(&pollbase.mt);

			channel_close(lsp);
		}
	}

	return (NULL);
}


/*
 * create the polling thread
 */
static int
poller_init(struct ldmsvcs_info *lsp)
{
	int rc = 0;

	(void) pthread_mutex_lock(&pollbase.mt);

	if (pollbase.polling_tid == 0) {
		pthread_attr_t attr;

		/*
		 * create polling thread for receiving messages
		 */
		(void) pthread_attr_init(&attr);
		(void) pthread_attr_setdetachstate(&attr,
		    PTHREAD_CREATE_DETACHED);

		if (pthread_create(&pollbase.polling_tid, &attr,
		    poller_loop, lsp) != 0)
			rc = 1;

		(void) pthread_attr_destroy(&attr);
	}

	(void) pthread_mutex_unlock(&pollbase.mt);

	return (rc);
}


/*
 * utilities for message handlers
 */
static int
fds_send(struct ldmsvcs_info *lsp, void *msg, size_t msglen)
{
	static pthread_mutex_t mt = PTHREAD_MUTEX_INITIALIZER;

	(void) pthread_mutex_lock(&mt);

	if (write(lsp->fds_chan.fd, msg, msglen) != msglen) {
		channel_close(lsp);
		(void) pthread_mutex_unlock(&mt);
		return (ETIMEDOUT);
	}

	(void) pthread_mutex_unlock(&mt);
	return (0);
}


/*
 * Find the max and min version supported
 */
static void
fds_min_max_versions(uint16_t *min_major, uint16_t *max_major)
{
	int i;

	*min_major = ds_vers[0].major;
	*max_major = *min_major;

	for (i = 1; i < DS_NUM_VER; i++) {
		if (ds_vers[i].major < *min_major)
			*min_major = ds_vers[i].major;

		if (ds_vers[i].major > *max_major)
			*max_major = ds_vers[i].major;
	}
}

/*
 * check whether the major and minor numbers requested by remote ds client
 * can be satisfied.  if the requested major is supported, true is
 * returned, and the agreed minor is returned in new_minor.  if the
 * requested major is not supported, the routine returns false, and the
 * closest major is returned in *new_major, upon which the ds client should
 * renegotiate.  the closest major is the just lower that the requested
 * major number.
 */
static boolean_t
fds_negotiate_version(uint16_t req_major, uint16_t *new_majorp,
    uint16_t *new_minorp)
{
	int i = 0;
	uint16_t major, lower_major;
	uint16_t min_major, max_major;
	boolean_t found_match = B_FALSE;

	fds_min_max_versions(&min_major, &max_major);

	/*
	 * if the minimum version supported is greater than the version
	 * requested, return the lowest version supported
	 */
	if (min_major > req_major) {
		*new_majorp = min_major;
		return (B_FALSE);
	}

	/*
	 * if the largest version supported is lower than the version
	 * requested, return the largest version supported
	 */
	if (max_major < req_major) {
		*new_majorp = max_major;
		return (B_FALSE);
	}

	/*
	 * now we know that the requested version lies between the min and
	 * max versions supported.  check if the requested major can be
	 * found in supported versions.
	 */
	lower_major = min_major;
	for (i = 0; i < DS_NUM_VER; i++) {
		major = ds_vers[i].major;
		if (major == req_major) {
			found_match = B_TRUE;
			*new_minorp = ds_vers[i].minor;
			*new_majorp = major;
			break;
		} else if ((major < req_major) && (major > lower_major))
			lower_major = major;
	}

	/*
	 * If  no match is found, return the closest available number
	 */
	if (!found_match)
		*new_majorp = lower_major;

	return (found_match);
}


/*
 * return 0 if service is added; 1 if service is a duplicate
 */
static int
fds_svc_add(struct ldmsvcs_info *lsp, ds_reg_req_t *req, int minor)
{
	fds_svc_t *svc;
	int i, rc;

	svc = NULL;
	for (i = 0; i < lsp->fmas_svcs.nsvcs; i++) {
		if (strcmp(lsp->fmas_svcs.tbl[i]->name, req->svc_id) == 0) {
			svc = lsp->fmas_svcs.tbl[i];
			break;
		}
	}

	if (svc == NULL)
		return (0);	/* we don't need this service */

	(void) pthread_mutex_lock(&lsp->fmas_svcs.mt);

	/*
	 * duplicate registration is OK --- we retain the previous entry
	 * (which has not been unregistered anyway)
	 */
	if (svc->state == DS_SVC_ACTIVE) {
		rc = 1;
	} else {
		svc->state = DS_SVC_ACTIVE;
		svc->hdl = req->svc_handle;
		svc->ver.major = req->major_vers;
		svc->ver.minor = minor;

		rc = 0;
		(void) pthread_cond_broadcast(&lsp->fmas_svcs.cv);
	}

	(void) pthread_mutex_unlock(&lsp->fmas_svcs.mt);

	return (rc);
}


static void
fds_svc_reset(struct ldmsvcs_info *lsp, int index)
{
	int i, start, end;

	if (index >= 0) {
		start = index;
		end = index + 1;
	} else {
		start = 0;
		end = lsp->fmas_svcs.nsvcs;
	}

	(void) pthread_mutex_lock(&lsp->fmas_svcs.mt);

	for (i = start; i < end; i++) {
		lsp->fmas_svcs.tbl[i]->hdl = 0;
		lsp->fmas_svcs.tbl[i]->state = DS_SVC_INVAL;
		lsp->fmas_svcs.tbl[i]->ver.major =
		    ds_vers[DS_NUM_VER - 1].major;
		lsp->fmas_svcs.tbl[i]->ver.minor =
		    ds_vers[DS_NUM_VER - 1].minor;
	}

	(void) pthread_mutex_unlock(&lsp->fmas_svcs.mt);
}


static int
fds_svc_remove(struct ldmsvcs_info *lsp, ds_svc_hdl_t svc_handle)
{
	int i;

	for (i = 0; i < lsp->fmas_svcs.nsvcs; i++) {
		if (lsp->fmas_svcs.tbl[i]->hdl == svc_handle) {
			fds_svc_reset(lsp, i);
			return (0);
		}
	}

	return (1);
}


/*
 * message handlers
 */
/*ARGSUSED*/
static void
ds_handle_msg_noop(struct ldmsvcs_info *lsp, void *buf, size_t len)
{
}

static void
ds_handle_init_req(struct ldmsvcs_info *lsp, void *buf, size_t len)
{
	ds_init_req_t *req;
	uint16_t new_major, new_minor;
	size_t msglen;

	req = (ds_init_req_t *)buf;

	/* sanity check the incoming message */
	if (len != sizeof (ds_init_req_t)) {
		channel_close(lsp);
		return;
	}

	/*
	 * Check version info. ACK only if the major numbers exactly
	 * match. The service entity can retry with a new minor
	 * based on the response sent as part of the NACK.
	 */
	if (fds_negotiate_version(req->major_vers, &new_major, &new_minor)) {
		ds_hdr_t *H;
		ds_init_ack_t *R;

		msglen = sizeof (ds_hdr_t) + sizeof (ds_init_ack_t);
		H = alloca(msglen);
		R = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));

		H->msg_type = DS_INIT_ACK;
		H->payload_len = sizeof (ds_init_ack_t);
		R->minor_vers = MIN(new_minor, req->minor_vers);

		if (fds_send(lsp, H, msglen) != 0)
			return;

		(void) pthread_mutex_lock(&lsp->mt);
		ASSERT(lsp->fds_chan.state == CHANNEL_OPEN);
		lsp->fds_chan.state = CHANNEL_READY;

		/*
		 * Now the channel is ready after the handshake completes.
		 * Reset the timeout to a smaller value for receiving messages
		 * from the domain services.
		 */
		lsp->cv_twait = get_smf_int_val(LDM_RUNNING_TO_PROP_NM,
		    0, LDM_TIMEOUT_CEILING, LDM_RUNNING_WAIT_TIME);

		(void) pthread_mutex_unlock(&lsp->mt);
	} else {
		ds_hdr_t *H;
		ds_init_nack_t *R;

		msglen = sizeof (ds_hdr_t) + sizeof (ds_init_nack_t);
		H = alloca(msglen);
		R = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));

		H->msg_type = DS_INIT_NACK;
		H->payload_len = sizeof (ds_init_nack_t);
		R->major_vers = new_major;

		(void) fds_send(lsp, H, msglen);
		/*
		 * do not update state; remote end may attempt to initiate
		 * connection with a different version
		 */
	}
}


/*ARGSUSED*/
static void
ds_handle_reg_req(struct ldmsvcs_info *lsp, void *buf, size_t len)
{
	ds_reg_req_t *req;
	char *msg;
	uint16_t new_major, new_minor;
	size_t msglen;
	int dup_svcreg = 0;

	req = (ds_reg_req_t *)buf;
	msg = (char *)req->svc_id;

	/*
	 * Service must be NULL terminated
	 */
	if (req->svc_id == NULL || strlen(req->svc_id) == 0 ||
	    msg[strlen(req->svc_id)] != '\0') {
		channel_close(lsp);
		return;
	}

	if (fds_negotiate_version(req->major_vers, &new_major, &new_minor) &&
	    (dup_svcreg = fds_svc_add(lsp, req,
	    MIN(new_minor, req->minor_vers))) == 0) {

		/*
		 * Check version info. ACK only if the major numbers
		 * exactly match. The service entity can retry with a new
		 * minor based on the response sent as part of the NACK.
		 */
		ds_hdr_t *H;
		ds_reg_ack_t *R;

		msglen = sizeof (ds_hdr_t) + sizeof (ds_reg_ack_t);
		H = alloca(msglen);
		bzero(H, msglen);
		R = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));

		H->msg_type = DS_REG_ACK;
		H->payload_len = sizeof (ds_reg_ack_t);
		R->svc_handle = req->svc_handle;
		R->minor_vers = MIN(new_minor, req->minor_vers);

		(void) fds_send(lsp, H, msglen);
	} else {
		ds_hdr_t *H;
		ds_reg_nack_t *R;

		msglen = sizeof (ds_hdr_t) + sizeof (ds_reg_nack_t);
		H = alloca(msglen);
		bzero(H, msglen);
		R = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));

		H->msg_type = DS_REG_NACK;
		H->payload_len = sizeof (ds_reg_nack_t);
		R->svc_handle = req->svc_handle;
		R->major_vers = new_major;

		if (dup_svcreg)
			R->result = DS_REG_DUP;
		else
			R->result = DS_REG_VER_NACK;

		(void) fds_send(lsp, H, msglen);
	}
}


/*ARGSUSED*/
static void
ds_handle_unreg(struct ldmsvcs_info *lsp, void *buf, size_t len)
{
	ds_unreg_req_t *req;
	size_t msglen;

	req = (ds_unreg_req_t *)buf;

	if (fds_svc_remove(lsp, req->svc_handle) == 0) {
		ds_hdr_t *H;
		ds_unreg_ack_t *R;

		msglen = sizeof (ds_hdr_t) + sizeof (ds_unreg_ack_t);
		H = alloca(msglen);
		R = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));

		H->msg_type = DS_REG_ACK;
		H->payload_len = sizeof (ds_unreg_ack_t);
		R->svc_handle = req->svc_handle;

		(void) fds_send(lsp, H, msglen);
	} else {
		ds_hdr_t *H;
		ds_unreg_nack_t *R;

		msglen = sizeof (ds_hdr_t) + sizeof (ds_unreg_nack_t);
		H = alloca(msglen);
		R = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));

		H->msg_type = DS_REG_NACK;
		H->payload_len = sizeof (ds_unreg_nack_t);
		R->svc_handle = req->svc_handle;

		(void) fds_send(lsp, H, msglen);
	}
}


/*
 * Message handler lookup table (v1.0 only for now) Future
 * versions can add their own lookup table.
 */
typedef void (*ds_msg_handler_t)(struct ldmsvcs_info *lsp,
				void *buf, size_t len);

static const ds_msg_handler_t ds_msg_handlers[] = {
	ds_handle_init_req,		/* DS_INIT_REQ */
	ds_handle_msg_noop,		/* DS_INIT_ACK */
	ds_handle_msg_noop,		/* DS_INIT_NACK */
	ds_handle_reg_req,		/* DS_REG_REQ */
	ds_handle_msg_noop,		/* DS_REG_ACK */
	ds_handle_msg_noop,		/* DS_REG_NACK */
	ds_handle_unreg,		/* DS_UNREG */
	ds_handle_msg_noop,		/* DS_UNREG_ACK */
	ds_handle_msg_noop,		/* DS_UNREG_NACK */
	ds_handle_msg_noop,		/* DS_DATA */
	ds_handle_msg_noop		/* DS_NACK */
};


/*
 * message and service internal functions
 */
static void
fds_svc_alloc(struct ldom_hdl *lhp, struct ldmsvcs_info *lsp)
{
	int i;
	static char *name[] = { LDM_DS_NAME_CPU, LDM_DS_NAME_MEM,
			LDM_DS_NAME_PRI, LDM_DS_NAME_IOD, NULL };

	(void) pthread_mutex_init(&lsp->fmas_svcs.mt, NULL);
	(void) pthread_cond_init(&lsp->fmas_svcs.cv, NULL);

	for (lsp->fmas_svcs.nsvcs = 0; name[lsp->fmas_svcs.nsvcs] != NULL;
	    lsp->fmas_svcs.nsvcs++)
		;

	lsp->fmas_svcs.tbl = (fds_svc_t **)lhp->allocp(sizeof (fds_svc_t *) *
	    lsp->fmas_svcs.nsvcs);

	for (i = 0; i < lsp->fmas_svcs.nsvcs; i++) {
		lsp->fmas_svcs.tbl[i] =
		    (fds_svc_t *)lhp->allocp(sizeof (fds_svc_t));
		bzero(lsp->fmas_svcs.tbl[i], sizeof (fds_svc_t));
		lsp->fmas_svcs.tbl[i]->name = name[i];
	}
}


static fds_svc_t *
fds_svc_lookup(struct ldmsvcs_info *lsp, char *name)
{
	struct timespec twait;
	fds_svc_t *svc;
	int i, ier;

	if (pthread_mutex_lock(&lsp->fmas_svcs.mt) == EINVAL)
		return (NULL);	/* uninitialized or destroyed mutex */

	svc = NULL;
	for (i = 0; i < lsp->fmas_svcs.nsvcs; i++) {
		if (strcmp(lsp->fmas_svcs.tbl[i]->name, name) == 0) {
			svc = lsp->fmas_svcs.tbl[i];
			break;
		}
	}

	ASSERT(svc != NULL);

	if (svc->state == DS_SVC_INACTIVE) {
		/* service is not registered */
		ier = ETIMEDOUT;
	} else {
		ier = 0;
		twait.tv_sec = time(NULL) + lsp->cv_twait;
		twait.tv_nsec = 0;

		while (svc->state != DS_SVC_ACTIVE && ier == 0 &&
		    lsp->fds_chan.state != CHANNEL_UNUSABLE)
			ier = pthread_cond_timedwait(&lsp->fmas_svcs.cv,
			    &lsp->fmas_svcs.mt, &twait);

		/*
		 * By now, the ds service should have registered already.
		 * If it does not, ldmd probably does not support this service.
		 * Then mark the service state as inactive.
		 */
		if (ier == ETIMEDOUT) {
			svc->state = DS_SVC_INACTIVE;
		}
	}

	(void) pthread_mutex_unlock(&lsp->fmas_svcs.mt);

	if (ier == 0)
		return (svc);
	else
		return (NULL);
}


static uint64_t
fds_svc_req_num(void)
{
	static uint64_t req_num = 1;

	return (req_num++);
}


/*
 * return 0 if successful, 1 if otherwise
 */
static int
read_msg(struct ldmsvcs_info *lsp)
{
	ds_hdr_t header;
	void *msg_buf;

	/*
	 * read the header
	 */
	if (read_stream(lsp->fds_chan.fd, &header, sizeof (ds_hdr_t)) != 0)
		return (1);

	if (header.msg_type >=
	    sizeof (ds_msg_handlers) / sizeof (ds_msg_handler_t))
		return (1);

	/*
	 * handle data as a special case
	 */
	if (header.msg_type == 9)
		return (poller_handle_data(lsp->fds_chan.fd,
		    header.payload_len));

	/*
	 * all other types of messages should be small
	 */
	ASSERT(header.payload_len < 1024);
	msg_buf = alloca(header.payload_len);

	/*
	 * read the payload
	 */
	if (read_stream(lsp->fds_chan.fd, msg_buf, header.payload_len) != 0)
		return (1);

	(*ds_msg_handlers[header.msg_type])(lsp, msg_buf, header.payload_len);

	return (0);
}


/*
 * return values:
 *  0 - success
 *  1 - problem with opening the channel
 *  2 - channed not opened; request to exit has been detected
 */
static int
channel_openreset(struct ldmsvcs_info *lsp)
{
	int ier;

	ier = pthread_mutex_lock(&lsp->mt);

	if (ier == EINVAL || lsp->fds_chan.state == CHANNEL_EXIT ||
	    lsp->fds_chan.state == CHANNEL_UNUSABLE) {
		(void) pthread_mutex_unlock(&lsp->mt);
		return (2);
	}

	if (lsp->fds_chan.state == CHANNEL_UNINITIALIZED ||
	    lsp->fds_chan.state == CHANNEL_CLOSED) {
		(void) pthread_cond_broadcast(&lsp->cv);

		if ((lsp->fds_chan.fd = open(FDS_VLDC, O_RDWR)) < 0) {
			lsp->fds_chan.state = CHANNEL_UNUSABLE;
			lsp->cv_twait = get_smf_int_val(LDM_RUNNING_TO_PROP_NM,
			    0, LDM_TIMEOUT_CEILING, LDM_RUNNING_WAIT_TIME);
			(void) pthread_mutex_unlock(&lsp->mt);
			(void) pthread_cond_broadcast(&lsp->fmas_svcs.cv);

			return (2);
		} else {
			vldc_opt_op_t op;

			op.op_sel = VLDC_OP_SET;
			op.opt_sel = VLDC_OPT_MODE;
			op.opt_val = LDC_MODE_RELIABLE;

			if (ioctl(lsp->fds_chan.fd, VLDC_IOCTL_OPT_OP,
			    &op) != 0) {
				(void) close(lsp->fds_chan.fd);
				(void) pthread_mutex_unlock(&lsp->mt);
				return (1);
			}
		}
		lsp->fds_chan.state = CHANNEL_OPEN;
	}

	if (lsp->fds_chan.state == CHANNEL_OPEN) {
		/*
		 * reset various channel parameters
		 */
		lsp->fds_chan.ver.major = 0;
		lsp->fds_chan.ver.minor = 0;
		fds_svc_reset(lsp, -1);
	}
	(void) pthread_mutex_unlock(&lsp->mt);

	return (0);
}


static void
channel_fini(void)
{
	struct ldmsvcs_info *lsp;

	/*
	 * End the poller thread
	 */
	poller_shutdown();

	if ((lsp = channel_init(NULL)) == NULL)
		return;

	(void) pthread_mutex_lock(&lsp->mt);

	lsp->fds_chan.state = CHANNEL_EXIT;
	(void) close(lsp->fds_chan.fd);

	(void) pthread_mutex_unlock(&lsp->mt);
}


static struct ldmsvcs_info *
channel_init(struct ldom_hdl *lhp)
{
	static pthread_mutex_t mt = PTHREAD_MUTEX_INITIALIZER;
	static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
	static struct ldmsvcs_info *root = NULL;
	static int busy_init = 0;

	struct timespec twait;
	int expired;

	(void) pthread_mutex_lock(&mt);

	while (busy_init == 1)
		(void) pthread_cond_wait(&cv, &mt);

	if (root != NULL || (lhp == NULL && root == NULL)) {
		(void) pthread_mutex_unlock(&mt);
		return (root);
	}

	/*
	 * get to this point if we need to open the channel
	 */
	busy_init = 1;
	(void) pthread_mutex_unlock(&mt);

	root = (struct ldmsvcs_info *)
	    lhp->allocp(sizeof (struct ldmsvcs_info));
	bzero(root, sizeof (struct ldmsvcs_info));

	root->fds_chan.state = CHANNEL_UNINITIALIZED;
	root->cv_twait = get_smf_int_val(LDM_INIT_TO_PROP_NM,
	    0, LDM_TIMEOUT_CEILING, LDM_INIT_WAIT_TIME);

	if (pthread_mutex_init(&root->mt, NULL) != 0 ||
	    pthread_cond_init(&root->cv, NULL) != 0) {
		lhp->freep(root, sizeof (struct ldmsvcs_info));
		return (NULL);
	}

	fds_svc_alloc(lhp, root);
	fds_svc_reset(root, -1);

	(void) poller_init(root);

	expired = 0;
	twait.tv_sec = time(NULL) + 10;
	twait.tv_nsec = 0;

	(void) pthread_mutex_lock(&root->mt);

	/*
	 * wait for channel to become uninitialized.  this should be quick.
	 */
	while (root->fds_chan.state == CHANNEL_UNINITIALIZED && expired == 0)
		expired = pthread_cond_timedwait(&root->cv, &root->mt, &twait);

	if (root->fds_chan.state == CHANNEL_UNUSABLE)
		expired = 1;

	(void) pthread_mutex_unlock(&root->mt);

	(void) pthread_mutex_lock(&mt);
	busy_init = 0;
	(void) pthread_mutex_unlock(&mt);
	(void) pthread_cond_broadcast(&cv);

	(void) atexit(channel_fini);

	if (expired == 0)
		return (root);
	else
		return (NULL);
}


static int
sendrecv(struct ldom_hdl *lhp, uint64_t req_num,
	void *msg, size_t msglen, ds_svc_hdl_t *svc_hdl, char *svcname,
	void **resp, size_t *resplen)
{
	struct ldmsvcs_info *lsp;
	fds_svc_t *svc;
	int maxretries, index, i, ier;

	lsp = lhp->lsinfo;
	i = 0;
	maxretries = 1;

	do {
		/*
		 * if any of the calls in this loop fail, retry some number
		 * of times before giving up.
		 */
		if ((svc = fds_svc_lookup(lsp, svcname)) == NULL) {
			(void) pthread_mutex_lock(&lsp->mt);

			if (lsp->fds_chan.state != CHANNEL_READY)
				ier = ETIMEDOUT;	/* channel not ready */
			else
				ier = ENOTSUP;		/* service not ready */

			(void) pthread_mutex_unlock(&lsp->mt);

			continue;
		} else {
			ier = 0;
			*svc_hdl = svc->hdl;
		}

		index = poller_add_pending(lhp, req_num);

		if ((ier = fds_send(lsp, msg, msglen)) != 0 ||
		    (ier = poller_recv_data(lhp, req_num, index, resp,
		    resplen)) != 0)
			poller_delete_pending(req_num, index);

	} while (i++ < maxretries && ier != 0);

	ASSERT(ier == 0 || ier == ETIMEDOUT || ier == ENOTSUP);

	return (ier);
}


/*
 * input:
 *   msg_type - requested operation: FMA_CPU_REQ_STATUS or FMA_CPU_REQ_OFFLINE
 *   cpuid - physical cpu id
 *
 * normal return values:
 *   P_OFFLINE - cpu is offline
 *   P_ONLINE - cpu is online
 *
 * abnormal return values:
 *   ETIMEDOUT - LDOM manager is not responding
 *   ENOTSUP - LDOM service for cpu offlining/status is not available
 *   ENOMSG - got an unexpected response from the LDOM cpu service
 */
static int
cpu_request(struct ldom_hdl *lhp, uint32_t msg_type, uint32_t cpuid)
{
	ds_hdr_t *H;
	ds_data_handle_t *D;
	fma_cpu_service_req_t *R;

	char *svcname = LDM_DS_NAME_CPU;
	fma_cpu_resp_t *respmsg;
	void *resp;
	size_t resplen, reqmsglen;
	int rc;

	if (lhp->lsinfo == NULL)
		return (ENOMSG);

	reqmsglen = sizeof (ds_hdr_t) + sizeof (ds_data_handle_t) +
	    sizeof (fma_cpu_service_req_t);

	H = lhp->allocp(reqmsglen);
	D = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));
	R = (void *)((ptrdiff_t)D + sizeof (ds_data_handle_t));

	H->msg_type = DS_DATA;
	H->payload_len = sizeof (ds_data_handle_t) +
	    sizeof (fma_cpu_service_req_t);

	R->req_num = fds_svc_req_num();
	R->msg_type = msg_type;
	R->cpu_id = cpuid;

	if ((rc = sendrecv(lhp, R->req_num, H, reqmsglen,
	    &D->svc_handle, svcname, &resp, &resplen)) != 0) {
		lhp->freep(H, reqmsglen);
		return (rc);
	}

	lhp->freep(H, reqmsglen);

	ASSERT(resplen == sizeof (fma_cpu_resp_t));
	respmsg = (fma_cpu_resp_t *)resp;

	rc = ENOMSG;
	if (respmsg->result == FMA_CPU_RESP_OK) {
		if (respmsg->status == FMA_CPU_STAT_ONLINE)
			rc = P_ONLINE;
		else if (respmsg->status == FMA_CPU_STAT_OFFLINE)
			rc = P_OFFLINE;
	} else {
		if (msg_type == FMA_CPU_REQ_OFFLINE &&
		    respmsg->status == FMA_CPU_STAT_OFFLINE)
			rc = P_OFFLINE;
	}

	lhp->freep(resp, resplen);

	return (rc);
}


/*
 * input:
 *   msg_type - requested operation: FMA_MEM_REQ_STATUS or FMA_MEM_REQ_RETIRE
 *   pa - starting address of memory page
 *   pgsize - memory page size in bytes
 *
 * normal return values for msg_type == FMA_MEM_REQ_STATUS:
 *   0 - page is retired
 *   EAGAIN - page is scheduled for retirement
 *   EIO - page not scheduled for retirement
 *   EINVAL - error
 *
 * normal return values for msg_type == FMA_MEM_REQ_RETIRE:
 *   0 - success in retiring page
 *   EIO - page is already retired
 *   EAGAIN - page is scheduled for retirement
 *   EINVAL - error
 *
 * abnormal return values (regardless of msg_type)
 *   ETIMEDOUT - LDOM manager is not responding
 *   ENOTSUP - LDOM service for cpu offlining/status is not available
 *   ENOMSG - got an unexpected response from the LDOM cpu service
 */
static int
mem_request(struct ldom_hdl *lhp, uint32_t msg_type, uint64_t pa,
	    uint64_t pgsize)
{
	ds_hdr_t *H;
	ds_data_handle_t *D;
	fma_mem_service_req_t *R;

	char *svcname = LDM_DS_NAME_MEM;
	fma_mem_resp_t *respmsg;
	void *resp;
	size_t resplen, reqmsglen;
	int rc;

	if (lhp->lsinfo == NULL)
		return (ENOMSG);

	reqmsglen = sizeof (ds_hdr_t) + sizeof (ds_data_handle_t) +
	    sizeof (fma_mem_service_req_t);

	H = lhp->allocp(reqmsglen);
	bzero(H, reqmsglen);
	D = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));
	R = (void *)((ptrdiff_t)D + sizeof (ds_data_handle_t));

	H->msg_type = DS_DATA;
	H->payload_len = sizeof (ds_data_handle_t) +
	    sizeof (fma_mem_service_req_t);

	R->req_num = fds_svc_req_num();
	R->msg_type = msg_type;
	R->real_addr = pa;
	R->length = pgsize;

	if ((rc = sendrecv(lhp, R->req_num, H, reqmsglen,
	    &D->svc_handle, svcname, &resp, &resplen)) != 0) {
		lhp->freep(H, reqmsglen);
		return (rc);
	}

	lhp->freep(H, reqmsglen);

	ASSERT(resplen == sizeof (fma_mem_resp_t));
	respmsg = (fma_mem_resp_t *)resp;

	rc = ENOMSG;
	if (msg_type == FMA_MEM_REQ_STATUS) {
		if (respmsg->result == FMA_MEM_RESP_OK) {
			if (respmsg->status == FMA_MEM_STAT_RETIRED)
				rc = 0;		/* page is retired */
			else if (respmsg->status == FMA_MEM_STAT_NOTRETIRED)
				rc = EIO;	/* page is not scheduled */
		} else if (respmsg->result == FMA_MEM_RESP_FAILURE) {
			if (respmsg->status == FMA_MEM_STAT_NOTRETIRED)
				rc = EAGAIN;	/* page is scheduled */
			else if (respmsg->status == FMA_MEM_STAT_ILLEGAL)
				rc = EINVAL;
		}
	} else if (msg_type == FMA_MEM_REQ_RETIRE) {
		if (respmsg->result == FMA_MEM_RESP_OK) {
			if (respmsg->status == FMA_MEM_STAT_RETIRED)
				rc = 0;		/* is successfully retired */
		} else if (respmsg->result == FMA_MEM_RESP_FAILURE) {
			if (respmsg->status == FMA_MEM_STAT_RETIRED)
				rc = EIO;	/* is already retired */
			else if (respmsg->status == FMA_MEM_STAT_NOTRETIRED)
				rc = EAGAIN;	/* is scheduled to retire */
			else if (respmsg->status == FMA_MEM_STAT_ILLEGAL)
				rc = EINVAL;
		}
	} else if (msg_type == FMA_MEM_REQ_RESURRECT) {
		if (respmsg->result == FMA_MEM_RESP_OK) {
			if (respmsg->status == FMA_MEM_STAT_NOTRETIRED)
				rc = 0;		/* is successfully unretired */
		} if (respmsg->result == FMA_MEM_RESP_FAILURE) {
			if (respmsg->status == FMA_MEM_STAT_RETIRED)
				rc = EAGAIN; 	/* page couldn't be locked */
			else if (respmsg->status == FMA_MEM_STAT_NOTRETIRED)
				rc = EIO;	/* page isn't retired already */
			else if (respmsg->status == FMA_MEM_STAT_ILLEGAL)
				rc = EINVAL;
		}
	}

	lhp->freep(resp, resplen);

	return (rc);
}


/*
 * APIs
 */
int
ldmsvcs_check_channel(void)
{
	struct stat buf;

	if (stat(FDS_VLDC, &buf) == 0)
		return (0);	/* vldc exists */
	else if (errno == ENOENT || errno == ENOTDIR)
		return (1);	/* vldc does not exist */
	else
		return (-1);	/* miscellaneous error */
}


/*ARGSUSED*/
void
ldmsvcs_init(struct ldom_hdl *lhp)
{
	if (ldmsvcs_check_channel() != 0)
		return;

	lhp->lsinfo = channel_init(lhp);
	poller_add_client();
}


/*ARGSUSED*/
void
ldmsvcs_fini(struct ldom_hdl *lhp)
{
	if (ldmsvcs_check_channel() != 0)
		return;

	poller_remove_client();
}


/*ARGSUSED*/
ssize_t
ldmsvcs_get_core_md(struct ldom_hdl *lhp, uint64_t **buf)
{
	ds_hdr_t *H;
	ds_data_handle_t *D;
	fma_req_pri_t *R;

	char *svcname = LDM_DS_NAME_PRI;
	void *resp;
	size_t resplen, reqmsglen;
	ssize_t buflen;
	int rc;

	if (lhp->lsinfo == NULL)
		return (-1);

	reqmsglen = sizeof (ds_hdr_t) + sizeof (ds_data_handle_t) +
	    sizeof (fma_req_pri_t);

	H = lhp->allocp(reqmsglen);
	D = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));
	R = (void *)((ptrdiff_t)D + sizeof (ds_data_handle_t));

	H->msg_type = DS_DATA;
	H->payload_len = sizeof (ds_data_handle_t) +
	    sizeof (fma_req_pri_t);

	R->req_num = fds_svc_req_num();

	if ((rc = sendrecv(lhp, R->req_num, H, reqmsglen,
	    &D->svc_handle, svcname, &resp, &resplen)) != 0) {
		lhp->freep(H, reqmsglen);
		errno = rc;
		return (-1);
	}

	lhp->freep(H, reqmsglen);

	/*
	 * resp should contain the req_num immediately followed by the PRI
	 * (the latter may or may not be present).  unfortunately, the
	 * current compiler flags cause a warning for the following
	 * definition
	 *
	 * typedef struct {
	 *    uint64_t req_num;
	 *    uint8_t pri[];
	 *  } fma_pri_resp_t;
	 *
	 * so we do not use the struct here.
	 */
	if (resplen <= sizeof (uint64_t)) {
		lhp->freep(resp, resplen);
		if (resplen == sizeof (uint64_t))
			return (0);
		else
			return (-1);
	}

	buflen = resplen - sizeof (uint64_t);
	*buf = lhp->allocp(buflen);

	bcopy((void *)((ptrdiff_t)resp + sizeof (uint64_t)), *buf, buflen);
	lhp->freep(resp, resplen);

	return (buflen);
}


/*
 * see cpu_request() for a description of return values
 */
int
ldmsvcs_cpu_req_status(struct ldom_hdl *lhp, uint32_t cpuid)
{
	return (cpu_request(lhp, FMA_CPU_REQ_STATUS, cpuid));
}


int
ldmsvcs_cpu_req_offline(struct ldom_hdl *lhp, uint32_t cpuid)
{
	return (cpu_request(lhp, FMA_CPU_REQ_OFFLINE, cpuid));
}

int
ldmsvcs_cpu_req_online(struct ldom_hdl *lhp, uint32_t cpuid)
{
	return (cpu_request(lhp, FMA_CPU_REQ_ONLINE, cpuid));
}

/*
 * see mem_request() for a description of return values
 */
int
ldmsvcs_mem_req_status(struct ldom_hdl *lhp, uint64_t pa)
{
	return (mem_request(lhp, FMA_MEM_REQ_STATUS, pa, getpagesize()));
}

int
ldmsvcs_mem_req_retire(struct ldom_hdl *lhp, uint64_t pa)
{
	return (mem_request(lhp, FMA_MEM_REQ_RETIRE, pa, getpagesize()));
}

int
ldmsvcs_mem_req_unretire(struct ldom_hdl *lhp, uint64_t pa)
{
	return (mem_request(lhp, FMA_MEM_REQ_RESURRECT, pa, getpagesize()));
}

int
ldmsvcs_io_req_id(struct ldom_hdl *lhp, uint64_t addr, uint_t type,
    uint64_t *virt_addr, char *name, int name_len, uint64_t *did)
{

	ds_hdr_t *H;
	ds_data_handle_t *D;
	fma_io_req_t *R;

	char *svcname = LDM_DS_NAME_IOD;
	void *resp;
	fma_io_resp_t *iop;
	size_t resplen, reqmsglen;
	int offset;
	int rc;

	if (lhp->lsinfo == NULL)
		return (-1);

	reqmsglen = sizeof (ds_hdr_t) + sizeof (ds_data_handle_t) +
	    sizeof (fma_io_req_t);

	H = lhp->allocp(reqmsglen);
	D = (void *)((ptrdiff_t)H + sizeof (ds_hdr_t));
	R = (void *)((ptrdiff_t)D + sizeof (ds_data_handle_t));

	H->msg_type = DS_DATA;
	H->payload_len = sizeof (ds_data_handle_t) + sizeof (fma_io_req_t);

	R->req_num = fds_svc_req_num();
	R->msg_type = type;
	R->rsrc_address = addr;

	rc = ENOMSG;
	if ((rc = sendrecv(lhp, R->req_num, H, reqmsglen,
	    &D->svc_handle, svcname, &resp, &resplen)) != 0) {
		lhp->freep(H, reqmsglen);
		return (rc);
	}
	lhp->freep(H, reqmsglen);

	/*
	 * resp should contain the req_num, status, virtual addr, domain id
	 * and the domain name. The domain name may or may not be present.
	 */
	offset = sizeof (fma_io_resp_t);
	if (resplen < offset) {
		lhp->freep(resp, resplen);
		return (-1);
	}

	iop = (fma_io_resp_t *)resp;
	switch (iop->result) {
	case FMA_IO_RESP_OK:
		/* success */
		rc = 0;
		*virt_addr = iop->virt_rsrc_address;
		*did = iop->domain_id;
		if (name == NULL || name_len <= 0)
			break;
		*name = '\0';
		if (resplen > offset) {
			(void) strncpy(name, (char *)((ptrdiff_t)resp + offset),
			    name_len);
		}
		break;
	default:
		rc = -1;
		break;
	}

	lhp->freep(resp, resplen);
	return (rc);
}

/* end file */
