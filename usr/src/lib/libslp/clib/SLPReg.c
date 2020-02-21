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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains all functions pertaining to registrations:
 *	SLPReg
 *	SLPDereg
 *	SLPDelAttrs
 *
 * Each function talks only to the local slpd, and receives a SrvAck
 * reply.
 *
 * These calls can operate in sync or async mode. Sync mode operates
 * as follows:
 *	format params into a char *msg
 *	send this msg to slpd
 *	invoke the SLPRegReport callback with the error code found in the
 *		reply from slpd
 *	return
 *
 * Async mode operates as follows:
 *	format the params into a char *msg
 *	there is one thread per process which handles async regs
 *	make sure this thread is running
 *	the reg_thread monitors the global static reg_q for messages
 *	a queue message is represented as a struct reg_q_msg
 *	caller thread places the reg msg on the reg_q, and returns
 *	the reg_thread reads the message from the reg_q, and sends the
 *		msg to slpd
 *	the reg_thread then invokes the SLPRegReport callback with the error
 *		code found in the reply from slpd
 *	once started, the reg_thread manages registration refreshing.
 *		If there are no registrations to refresh, the thread exits.
 */

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <syslog.h>
#include <slp-internal.h>
#include <sys/time.h>
#include <time.h>

/* Indices into a reg_msg iovec for auth blocks */
#define	SLP_URL_AUTH	1
#define	SLP_ATTR_AUTH	3

/* A registration / de-registration message */
struct reg_msg {
	struct iovec *msgiov;	/* msg contents */
	int msgiov_len;		/* number of iovec components in msgiov */
	struct iovec urlbytes;
	struct iovec attrbytes;
	int urlauth;		/* index into authiov for URL auth blocks */
	int attrauth;		/* index into authiov for attr auth blocks */
};

/*
 * This is the message bundle passed to the reg thread via a queue.
 */
struct reg_q_msg {
	struct reg_msg *msg;
	slp_handle_impl_t *hp;
	SLPRegReport *cb;
	void *cookie;
};

/*
 * These structures and vars are used for automatic re-registering.
 */
static struct rereg_entry {
	char *url;
	struct reg_msg *msg;
	time_t wake_time;
	unsigned short lifetime;
	struct rereg_entry *next;
} *reregs;

static time_t next_wake_time;
static unsigned short granularity = 3600;
static mutex_t rereg_lock = DEFAULTMUTEX;	/* protects the rereg struct */
static mutex_t start_lock = DEFAULTMUTEX;	/* protects reg_thr creation */

static slp_queue_t *reg_q;	/* the global registration queue */
static int slp_reg_thr_running;	/* positive if reg_thread is running */

/* Private Utility Routines */

static SLPBoolean check_reregs();
static SLPError add_rereg(const char *, struct reg_msg *, unsigned short);
static unsigned short dereg_rereg(const char *);

static SLPError enqueue_reg(slp_handle_impl_t *, struct reg_msg *,
			    void *, SLPRegReport *);
static SLPError reg_impl(slp_handle_impl_t *, struct reg_msg *,
				void *, SLPRegReport *);
static void *reg_thread(void *);
static SLPError start_reg_thr();
static SLPError reg_common(slp_handle_impl_t *, struct reg_msg *,
				void *, SLPRegReport *);
static SLPError UnpackSrvAck(char *, SLPError *);
static SLPError packSrvReg(slp_handle_impl_t *, const char *,
				unsigned short, const char *, const char *,
				const char *, SLPBoolean, struct reg_msg **);
static SLPError packSrvDereg(slp_handle_impl_t *, const char *,
				const char *, const char *, struct reg_msg **);
static SLPError find_SAscopes(char **scopes);
static void free_msgiov(struct iovec *, int);

/* Public API SA functionality */

SLPError SLPReg(SLPHandle   hSLP, const char  *pcSrvURL,
		const unsigned short usLifetime,
		const char  *pcSrvType,
		const char  *pcAttrs, SLPBoolean  fresh,
		SLPRegReport callback, void *pvUser) {
	SLPError err;
	char *pcScopeList;
	struct reg_msg *msg;

	if (!hSLP || !pcSrvURL || !*pcSrvURL || !pcSrvType ||
	    !pcAttrs || !callback) {
		return (SLP_PARAMETER_BAD);
	}

	if ((strlen(pcSrvURL) > SLP_MAX_STRINGLEN) ||
	    (strlen(pcSrvType) > SLP_MAX_STRINGLEN) ||
	    (strlen(pcAttrs) > SLP_MAX_STRINGLEN)) {
	    return (SLP_PARAMETER_BAD);
	}

	if ((err = find_SAscopes(&pcScopeList)) != SLP_OK) {
		return (err);
	}

	if ((err = slp_start_call(hSLP)) != SLP_OK)
		return (err);

	/* format params into msg */
	if ((err = packSrvReg(
		hSLP, pcSrvURL, usLifetime, pcSrvType,
		pcScopeList, pcAttrs, fresh, &msg)) != SLP_OK) {
		free(pcScopeList);
		slp_end_call(hSLP);
		return (err);
	}

	if ((err = reg_common(hSLP, msg, pvUser, callback)) == SLP_OK &&
	    usLifetime == SLP_LIFETIME_MAXIMUM) {
		struct reg_msg *rereg_msg;

		/* create a rereg message, with no attrs */
		err = packSrvReg(
			hSLP, pcSrvURL, usLifetime,
			pcSrvType, pcScopeList, "", SLP_TRUE, &rereg_msg);
		if (err == SLP_OK) {
			err = add_rereg(pcSrvURL, rereg_msg, usLifetime);
		}
	}

	free(pcScopeList);
	return (err);
}

static SLPError packSrvReg(slp_handle_impl_t *hp, const char *url,
				unsigned short lifetime, const char *type,
				const char *scope, const char *attrs,
				SLPBoolean fresh, struct reg_msg **msg) {
	char *m = NULL;
	SLPError err;
	size_t msgLen, tmplen, len = 0;
	time_t ts;
	struct timeval tp[1];

	/* calculate the timestamp */
	(void) gettimeofday(tp, NULL);
	ts = tp->tv_sec + lifetime;

	/* create the reg_msg */
	*msg = NULL;
	if (!(*msg = calloc(1, sizeof (**msg)))) {
		slp_err(LOG_CRIT, 0, "packSrvReg", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	/* compute the total messge length */
	msgLen =
		slp_hdrlang_length(hp) +
		/* URL entry */
		5 + strlen(url) +
		/* srv reg msg */
		2 + strlen(type) +
		2 + strlen(scope) +
		2 + strlen(attrs);

	/*
	 * Allocate memory for all the message except the auth blocks.
	 * The iovec msgiov actually contains only pointers into this
	 * memory.
	 */
	if (!(m = calloc(msgLen, 1))) {
		slp_err(LOG_CRIT, 0, "packSrvReg", "out of memory");
		err = SLP_MEMORY_ALLOC_FAILED;
		goto error;
	}

	/*
	 * Create iovec for the msg. The iovec components are layed out thus:
	 *   0: header + URL
	 *   1: URL auth block count, URL auth block
	 *   2: attrs
	 *   3: attrs auth block count, attr auth block
	 */
	if (!((*msg)->msgiov = calloc(4, sizeof (*((*msg)->msgiov))))) {
		slp_err(LOG_CRIT, 0, "packSrvReg", "out of memory");
		err = SLP_MEMORY_ALLOC_FAILED;
		goto error;
	}
	(*msg)->msgiov_len = 4;

	if ((err = slp_add_header(hp->locale, m, msgLen, SRVREG, 0, &len))
	    != SLP_OK)
		goto error;
	/* set fresh flag */
	if (fresh)
		slp_set_fresh(m);

	/* URL entry */
	len++;	/* skip reserved byte in URL entry */
	if ((err = slp_add_sht(m, msgLen, lifetime, &len)) != SLP_OK)
		goto error;

	/* save pointer to URL for signing */
	tmplen = len;
	(*msg)->urlbytes.iov_base = m + len;

	if ((err = slp_add_string(m, msgLen, url, &len)) != SLP_OK)
		goto error;

	(*msg)->urlbytes.iov_len = len - tmplen;

	(*msg)->msgiov[0].iov_base = m;
	(*msg)->msgiov[0].iov_len = len;

	/* add auth blocks for URL */
	err = slp_sign(&((*msg)->urlbytes), 1, ts,
			(*msg)->msgiov, SLP_URL_AUTH);
	if (err != SLP_OK) {
		goto error;
	}

	(*msg)->msgiov[2].iov_base = m + len;

	/* type, scopes, and attrs */
	if ((err = slp_add_string(m, msgLen, type, &len)) != SLP_OK)
		goto error;
	if ((err = slp_add_string(m, msgLen, scope, &len)) != SLP_OK)
		goto error;

	/* save pointer to attr for signing */
	tmplen = len;
	(*msg)->attrbytes.iov_base = m + len;

	if ((err = slp_add_string(m, msgLen, attrs, &len)) != SLP_OK)
		goto error;

	(*msg)->attrbytes.iov_len = len - tmplen;

	/* length of 2nd portion is len - length of 1st portion */
	(*msg)->msgiov[2].iov_len = len - (*msg)->msgiov[0].iov_len;

	/* add auth blocks for attrs */
	err = slp_sign(&((*msg)->attrbytes), 1, ts,
			(*msg)->msgiov, SLP_ATTR_AUTH);
	if (err != SLP_OK) {
		goto error;
	}

	/* adjust msgLen with authblocks, and set header length */
	msgLen += (*msg)->msgiov[SLP_URL_AUTH].iov_len;
	msgLen += (*msg)->msgiov[SLP_ATTR_AUTH].iov_len;

	/* make sure msgLen is valid */
	if (msgLen > SLP_MAX_MSGLEN) {
		err = SLP_PARAMETER_BAD;
		goto error;
	}
	slp_set_length(m, msgLen);

	return (SLP_OK);
error:
	if (m) free(m);
	if (*msg) {
		if ((*msg)->msgiov) free_msgiov((*msg)->msgiov, 4);
		free(*msg);
	}
	*msg = NULL;
	return (err);
}

SLPError SLPDereg(SLPHandle hSLP, const char *pURL,
			SLPRegReport callback, void *pvUser) {
	char *pcScopeList;
	struct reg_msg *msg;
	SLPError err;

	if (!hSLP || !pURL || !*pURL || !callback) {
		return (SLP_PARAMETER_BAD);
	}

	if (strlen(pURL) > SLP_MAX_STRINGLEN) {
	    return (SLP_PARAMETER_BAD);
	}

	if ((err = find_SAscopes(&pcScopeList))
	    != SLP_OK) {
		return (err);
	}

	if ((err = slp_start_call(hSLP)) != SLP_OK)
		return (err);

	/* format params into msg */
	if ((err = packSrvDereg(hSLP, pURL, pcScopeList, NULL, &msg))
	    != SLP_OK) {
		free(pcScopeList);
		slp_end_call(hSLP);
		return (err);
	}

	if ((err = reg_common(hSLP, msg, pvUser, callback)) == SLP_OK) {
		(void) dereg_rereg(pURL);
	}

	free(pcScopeList);
	return (err);
}

SLPError SLPDelAttrs(SLPHandle hSLP, const char *pURL,
			const char *pcAttrs,
			SLPRegReport callback, void *pvUser) {
	SLPError err;
	char *pcScopeList;
	struct reg_msg *msg;

	if (!hSLP || !pURL || !*pURL || !pcAttrs || !callback) {
		return (SLP_PARAMETER_BAD);
	}

	if ((strlen(pURL) > SLP_MAX_STRINGLEN) ||
	    (strlen(pcAttrs) > SLP_MAX_STRINGLEN)) {
	    return (SLP_PARAMETER_BAD);
	}

	if ((err = find_SAscopes(&pcScopeList))
	    != SLP_OK) {
		return (err);
	}

	if ((err = slp_start_call(hSLP)) != SLP_OK)
		return (err);

	/* format params into msg */
	if ((err = packSrvDereg(hSLP, pURL, pcScopeList, pcAttrs, &msg))
	    != SLP_OK) {
		free(pcScopeList);
		slp_end_call(hSLP);
		return (err);
	}

	free(pcScopeList);
	return (reg_common(hSLP, msg, pvUser, callback));
}

static SLPError packSrvDereg(slp_handle_impl_t *hp, const char *url,
				const char *scopes, const char *attrs,
				struct reg_msg  **msg) {
	char *m = NULL;
	SLPError err;
	size_t msgLen, tmplen, len = 0;

	/* create the reg_msg */
	*msg = NULL;
	if (!(*msg = calloc(1, sizeof (**msg)))) {
		slp_err(LOG_CRIT, 0, "packSrvReg", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	/* compute the total message length */
	attrs = (attrs ? attrs : "");
	msgLen =
		slp_hdrlang_length(hp) +
		2 + strlen(scopes) +
		/* URL entry */
		5 + strlen(url) +
		2 + strlen(attrs);

	if (!(m = calloc(msgLen, 1))) {
		slp_err(LOG_CRIT, 0, "packSrvDereg", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	/*
	 * Create iovec for the msg. The iovec components are layed out thus:
	 *   0: header + URL
	 *   1: URL auth block count, URL auth block
	 *   2: attrs
	 */
	if (!((*msg)->msgiov = calloc(3, sizeof (*((*msg)->msgiov))))) {
		slp_err(LOG_CRIT, 0, "packSrvDereg", "out of memory");
		err = SLP_MEMORY_ALLOC_FAILED;
		goto error;
	}
	(*msg)->msgiov_len = 3;

	if ((err = slp_add_header(
		hp->locale, m, msgLen, SRVDEREG, 0, &len)) != SLP_OK)
		goto error;

	/* scopes */
	if ((err = slp_add_string(m, msgLen, scopes, &len)) != SLP_OK)
		goto error;

	/* URL Entry */
	len++;	/* skip reserved byte in URL entry */
	if ((err = slp_add_sht(m, msgLen, 0, &len)) != SLP_OK)
		goto error;

	/* save pointer to URL for signing */
	tmplen = len;
	(*msg)->urlbytes.iov_base = m + len;

	if ((err = slp_add_string(m, msgLen, url, &len)) != SLP_OK)
		goto error;

	(*msg)->urlbytes.iov_len = len - tmplen;

	(*msg)->msgiov[0].iov_base = m;
	(*msg)->msgiov[0].iov_len = len;

	/* add auth blocks for URL */
	err = slp_sign(&((*msg)->urlbytes), 1, 0,
			(*msg)->msgiov, SLP_URL_AUTH);
	if (err != SLP_OK) {
		goto error;
	}

	(*msg)->msgiov[2].iov_base = m + len;

	/* tag list */
	if ((err = slp_add_string(m, msgLen, attrs, &len)) != SLP_OK)
		goto error;

	/* length of 2nd portion is len - length of 1st portion */
	(*msg)->msgiov[2].iov_len = len - (*msg)->msgiov[0].iov_len;

	/* adjust msgLen with authblocks, and set header length */
	msgLen += (*msg)->msgiov[SLP_URL_AUTH].iov_len;

	/* make sure msgLen is valid */
	if (msgLen > SLP_MAX_MSGLEN) {
		err = SLP_PARAMETER_BAD;
		goto error;
	}
	slp_set_length(m, msgLen);

	return (SLP_OK);
error:
	if (m) free(m);
	if (*msg) {
		if ((*msg)->msgiov) free_msgiov((*msg)->msgiov, 3);
		free(*msg);
	}
	*msg = NULL;
	return (err);
}

/*
 * Passes the packed message to the routines which talk to slpd.
 */
static SLPError reg_common(slp_handle_impl_t *hp, struct reg_msg *msg,
				void *cookie, SLPRegReport callback) {
	SLPError err;

	if (!slp_reg_thr_running)
		if ((err = start_reg_thr()) != SLP_OK)
			goto reg_done;

	if (hp->async)
		err = enqueue_reg(hp, msg, cookie, callback);
	else
		err = reg_impl(hp, msg, cookie, callback);

reg_done:
	/* If an error occurred, end_call() will not have happened */
	if (err != SLP_OK)
		slp_end_call(hp);
	return (err);
}

/*
 * Put a reg message on the queue. Assumes reg_thread is running.
 */
static SLPError enqueue_reg(slp_handle_impl_t *hp, struct reg_msg *msg,
			    void *cookie, SLPRegReport cb) {
	struct reg_q_msg *rmsg;

	if (!(rmsg = malloc(sizeof (*rmsg)))) {
		slp_err(LOG_CRIT, 0, "enqueue_reg", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	rmsg->msg = msg;
	rmsg->hp = hp;
	rmsg->cb = cb;
	rmsg->cookie = cookie;

	return (slp_enqueue(reg_q, rmsg));
}

/*
 * Create a new reg_q and start the reg thread.
 */
static SLPError start_reg_thr() {
	SLPError err = SLP_OK;
	int terr;

	(void) mutex_lock(&start_lock);
	/* make sure someone else hasn't already intialized the thread */
	if (slp_reg_thr_running) {
		goto start_done;
	}

	/* create the reg queue */
	reg_q = slp_new_queue(&err);
	if (err != SLP_OK) {
		goto start_done;
	}

	/* start the reg thread */
	if ((terr = thr_create(
		0, 0, reg_thread,
		NULL, 0, NULL)) != 0) {
		slp_err(LOG_CRIT, 0, "start_reg_thr",
			"could not start thread: %s",
			strerror(terr));
		slp_destroy_queue(reg_q);
		err = SLP_INTERNAL_SYSTEM_ERROR;
		goto start_done;
	}
	slp_reg_thr_running = 1;

start_done:
	(void) mutex_unlock(&start_lock);
	return (err);
}

/*
 * This is what the permanent reg thread runs; it just sits in a loop
 * monitoring the reg_q for new reg messages.
 *
 * To conserve resources,
 * if there are no more registrations to refresh, it will exit.
 */
static void *
reg_thread(void *arg __unused)
{
	timestruc_t timeout;
	timeout.tv_nsec = 0;

	for (;;) {
		SLPBoolean etimed;
		struct reg_q_msg *rmsg;

		/* get the next message from the queue */
		timeout.tv_sec =
		    next_wake_time ? next_wake_time : time(NULL) + 5;
		rmsg = slp_dequeue_timed(reg_q, &timeout, &etimed);
		if (!rmsg && etimed == SLP_TRUE) {
			/* timed out */
			if (!check_reregs()) {
				/* no more reregs; shut down this thread */
				(void) mutex_lock(&start_lock);
				slp_destroy_queue(reg_q);
				slp_reg_thr_running = 0;
				(void) mutex_unlock(&start_lock);
				thr_exit(NULL);
			}
			continue;
		}
		if (!rmsg)
			continue;

		/* got a new message */
		(void) reg_impl(rmsg->hp, rmsg->msg, rmsg->cookie, rmsg->cb);
		free(rmsg);
		(void) check_reregs();
	}
}

/*
 * Unpacks a SrvAck.
 * 'reply' should point to the beginning of the header.
 */
static SLPError UnpackSrvAck(char *reply, SLPError *ans) {
	SLPError err;
	unsigned short langlen, call_err;
	char *p = reply + SLP_HDRLEN;

	langlen = slp_get_langlen(reply);
	p += langlen;
	if ((err = slp_get_sht(p, 0, NULL, &call_err)) != SLP_OK)
		return (err);

	*ans = slp_map_err(call_err);

	return (SLP_OK);
}

/*
 * The dispatcher for SA messages. Sends a message to slpd, unpacks and
 * dispatches the reply to the user callback.
 */
static SLPError reg_impl(slp_handle_impl_t *hp, struct reg_msg *msg,
				void *cookie, SLPRegReport cb) {
	char *reply = NULL;
	SLPError err, call_err;

	if (hp->cancel)
		goto transaction_complete;

	if ((err = slp_send2slpd_iov(msg->msgiov, msg->msgiov_len, &reply))
	    != SLP_OK)
		goto transaction_complete;

	/* through with msg, so free it now */
	free_msgiov(msg->msgiov, msg->msgiov_len);
	free(msg);

	if ((err = UnpackSrvAck(reply, &call_err)) != SLP_OK)
		goto transaction_complete;

	/* the reg thread doubles as the consumer thread for SA calls */
	hp->consumer_tid = thr_self();

	cb(hp, call_err, cookie);

transaction_complete:
	if (reply) {
		free(reply);
	}
	slp_end_call(hp);
	return (err);
}

/*
 * Re-registration routines
 */

/*
 * Adds the registration contained in 'msg' to the refresh registration
 * list managed by reg_thread.
 * Only registrations which are meant to be permanent are refreshed,
 * so we only allow reg's with lifetime == SLP_LIFETIME_PERMANENT into
 * the rereg table.
 */
static SLPError add_rereg(const char *url, struct reg_msg *msg,
				unsigned short lifetime) {
	struct rereg_entry *reg;
	SLPError err = SLP_OK;

	if (lifetime != SLP_LIFETIME_MAXIMUM) {
		return (SLP_OK);
	}

	(void) mutex_lock(&rereg_lock);
	/* alloc a new rereg entry */
	if (!(reg = malloc(sizeof (*reg)))) {
		slp_err(LOG_CRIT, 0, "add_rereg", "out of memory");
		err = SLP_MEMORY_ALLOC_FAILED;
		goto done;
	}

	if (!(reg->url = strdup(url))) {
		free(reg);
		slp_err(LOG_CRIT, 0, "add_rereg", "out of memory");
		err = SLP_MEMORY_ALLOC_FAILED;
		goto done;
	}

	reg->msg = msg;
	reg->lifetime = lifetime;
	reg->wake_time = (time(NULL) + lifetime) - 60;
	reg->next = NULL;

	/* adjust the next wake time if necessary */
	next_wake_time =
		reg->wake_time < next_wake_time ?
		reg->wake_time : next_wake_time;

	/* add the rereg to the list */
	if (!reregs) {
		/* first one */
		reregs = reg;
		goto done;
	}

	/* else add it to the beginning of the list */
	reg->next = reregs;
	reregs = reg;

done:
	(void) mutex_unlock(&rereg_lock);
	return (err);
}

/*
 * Walks through the rereg list and re-registers any which will expire
 * before the reg thread wakes up and checks again.
 * Returns true if there are more reregs on the list, false if none.
 */
static SLPBoolean check_reregs() {
	struct rereg_entry *p;
	time_t now, shortest_wait;
	SLPBoolean more = SLP_TRUE;

	(void) mutex_lock(&rereg_lock);

	if (!reregs) {
		more = SLP_FALSE;
		goto done;
	}

	now = time(NULL);
	shortest_wait = now + reregs->lifetime;

	for (p = reregs; p; p = p->next) {
		if (now > (p->wake_time - granularity)) {
		    char *reply;

		    /* rereg it, first recalculating signature */
		    (void) slp_sign(&(p->msg->urlbytes), 1, now + p->lifetime,
				    p->msg->msgiov, 1);
		    (void) slp_sign(&(p->msg->attrbytes), 1, now + p->lifetime,
				    p->msg->msgiov, 3);

		    (void) slp_send2slpd_iov(
				p->msg->msgiov, p->msg->msgiov_len, &reply);
		    if (reply)
			    free(reply);

		    p->wake_time = now + p->lifetime;
		}

		if (p->wake_time < shortest_wait)
			shortest_wait = p->wake_time;
	}
	next_wake_time = shortest_wait;

done:
	(void) mutex_unlock(&rereg_lock);
	return (more);
}

/*
 * Removes the refresh registration for 'url'.
 */
static unsigned short dereg_rereg(const char *url) {
	struct rereg_entry *p, *q;
	unsigned short lifetime = 0;

	(void) mutex_lock(&rereg_lock);
	for (p = q = reregs; p; p = p->next) {
		if (slp_strcasecmp(p->url, url) == 0) {
			/* found it; remove it from the list */
			if (p == q) {
				/* first one on list */
				reregs = p->next;
			} else {
				q->next = p->next;
			}

			/* free the entry */
			lifetime = p->lifetime;
			free(p->url);
			/* free the message memory */
			free(p->msg->msgiov[0].iov_base);
			/* free the URL auth block */
			free(p->msg->msgiov[SLP_URL_AUTH].iov_base);
			/* free the attr auth block */
			free(p->msg->msgiov[SLP_ATTR_AUTH].iov_base);
			/* free the message iovec */
			free(p->msg->msgiov);
			/* finally, free the message structure */
			free(p->msg);
			free(p);

			goto done;
		}

		q = p;
	}

done:
	(void) mutex_unlock(&rereg_lock);
	return (lifetime);
}

/*
 * Returns configured scopes in scopes. Caller should free *scopes
 * when done. If the scope string is too long for an SLP string, the
 * string is truncated.
 */
static SLPError find_SAscopes(char **scopes) {
	SLPError err;

	if ((err = slp_administrative_scopes(scopes, SLP_TRUE))
	    != SLP_OK) {
		return (err);
	}

	/* Ensure string is not too long */
	if (strlen(*scopes) > SLP_MAX_STRINGLEN) {
		/* truncate the string */
		if ((*scopes)[SLP_MAX_STRINGLEN - 1] == ',') {
			/* scopes can't end with ',' */
			(*scopes)[SLP_MAX_STRINGLEN - 1] = 0;
		} else {
			(*scopes)[SLP_MAX_STRINGLEN] = 0;
		}
	}

	return (SLP_OK);
}

/*
 * Does all the dirty work of freeing a msgiov.
 */
static void free_msgiov(struct iovec *msgiov, int iovlen) {
	/* free the message memory */
	free(msgiov[0].iov_base);
	/* free the URL auth block */
	free(msgiov[SLP_URL_AUTH].iov_base);
	if (iovlen == 4) {
		/* free the attr auth block */
		free(msgiov[SLP_ATTR_AUTH].iov_base);
	}
	/* free the message iovec */
	free(msgiov);
}
