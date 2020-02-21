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
 * Module for all network transactions. SLP messages can be multicast,
 * unicast over UDP, or unicast over TCP; this module provides routines
 * for all three. TCP transactions are handled by a single dedicated
 * thread, while multicast and UDP unicast messages are sent by the
 * calling thread.
 *
 * slp_uc_tcp_send:	enqueues a message on the TCP transaction thread's
 *				queue.
 * slp_tcp_wait:	blocks until all TCP-enqueued transactions for
 *				a given SLP handle are complete
 * slp_uc_udp_send:	unicasts a message using a datagram
 * slp_mc_send:		multicasts a message
 */

/*
 * todo: correct multicast interfaces;
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <slp-internal.h>
#include <slp_net_utils.h>

/*
 * TCP thread particulars
 */
static SLPBoolean tcp_thr_running = SLP_FALSE;
static slp_queue_t *tcp_q;
static int tcp_sockfd;
static mutex_t start_lock = DEFAULTMUTEX;

/* Used to pass arguments to the TCP thread, via 'tcp_q' */
struct tcp_rqst {
	slp_handle_impl_t *hp;
	slp_target_t *target;
	const char *scopes;
	SLPBoolean free_target;
	unsigned short xid;
};

/* Used to keep track of broadcast interfaces */
struct bc_ifs {
	struct sockaddr_in *sin;
	int num_ifs;
};

/*
 * Private utility routines
 */
static SLPError start_tcp_thr();
static void *tcp_thread(void *);
static SLPError make_header(slp_handle_impl_t *, char *, const char *);
static void udp_make_msghdr(struct sockaddr_in *, struct iovec *, int,
			    struct msghdr *);
static SLPError make_mc_target(slp_handle_impl_t *,
				struct sockaddr_in *, char *,
				struct pollfd **, nfds_t *, struct bc_ifs *);
static SLPError make_bc_target(slp_handle_impl_t *, struct in_addr *,
				int, struct bc_ifs *);
static SLPError mc_sendmsg(struct pollfd *, struct msghdr *,
				struct bc_ifs *);
static SLPError bc_sendmsg(struct pollfd *, struct msghdr *, struct bc_ifs *);
static void mc_recvmsg(struct pollfd *, nfds_t, slp_handle_impl_t *,
			const char *, char *, void **, unsigned long long,
			unsigned long long, unsigned long long *,
			int *, int *, int);
static void free_pfds(struct pollfd *, nfds_t);
static void tcp_handoff(slp_handle_impl_t *, const char *,
			struct sockaddr_in *, unsigned short);
static unsigned long long now_millis();
static int wait_for_response(unsigned long long, int *,
				unsigned long long, unsigned long long *,
				struct pollfd [], nfds_t);
static int add2pr_list(slp_msg_t *, struct sockaddr_in *, void **);
static void free_pr_node(void *, VISIT, int, void *);

/*
 * Unicasts a message using TCP. 'target' is a targets list
 * containing DAs corresponding to 'scopes'. 'free_target' directs
 * tcp_thread to free the target list when finished; this is useful
 * when a target needs to be synthesised by another message thread
 * (such as slp_mc_send for tcp_handoffs). If this message is a
 * retransmission due to a large reply, 'xid' should be the same as for
 * the original message.
 *
 * This call returns as soon as the message has been enqueued on 'tcp_q'.
 * Callers interested in knowing when the transaction has completed
 * should call slp_tcp_wait with the same SLP handle.
 */
void slp_uc_tcp_send(slp_handle_impl_t *hp, slp_target_t *target,
			const char *scopes, SLPBoolean free_target,
			unsigned short xid) {
	struct tcp_rqst *rqst;

	/* initialize TCP vars in handle, if necessary */
	if (!hp->tcp_lock) {
		if (!(hp->tcp_lock = malloc(sizeof (*(hp->tcp_lock))))) {
			slp_err(LOG_CRIT, 0, "slp_uc_tcp_send",
				"out of memory");
			return;
		}
		(void) mutex_init(hp->tcp_lock, USYNC_THREAD, NULL);
	}
	if (!hp->tcp_wait) {
		if (!(hp->tcp_wait = malloc(sizeof (*(hp->tcp_wait))))) {
			slp_err(LOG_CRIT, 0, "slp_uc_tcp_send",
				"out of memory");
			return;
		}
		(void) cond_init(hp->tcp_wait, USYNC_THREAD, NULL);
	}
	(void) mutex_lock(hp->tcp_lock);
	(hp->tcp_ref_cnt)++;
	(void) mutex_unlock(hp->tcp_lock);

	/* start TCP thread, if not already running */
	if (!tcp_thr_running)
		if (start_tcp_thr() != SLP_OK)
			return;

	/* create and enqueue the request */
	if (!(rqst = malloc(sizeof (*rqst)))) {
		slp_err(LOG_CRIT, 0, "slp_uc_tcp_send", "out of memory");
		return;
	}
	rqst->hp = hp;
	rqst->target = target;
	rqst->scopes = scopes;
	rqst->free_target = free_target;
	rqst->xid = xid;
	(void) slp_enqueue(tcp_q, rqst);
}

/*
 * Wait for TCP to complete, if a transaction corresponding to this
 * SLP handle is pending. If none are pending, returns immediately.
 */
void slp_tcp_wait(slp_handle_impl_t *hp) {
	(void) mutex_lock(hp->tcp_lock);
	while (hp->tcp_ref_cnt > 0)
		(void) cond_wait(hp->tcp_wait, hp->tcp_lock);
	(void) mutex_unlock(hp->tcp_lock);
}

/*
 * Unicasts a message using datagrams. 'target' should contain a
 * list of DAs corresponding to 'scopes'.
 *
 * This call does not return until the transaction has completed. It
 * may handoff a message to the TCP thread if necessary, but will not
 * wait for that transaction to complete. Hence callers should always
 * invoke slp_tcp_wait before cleaning up resources.
 */
void slp_uc_udp_send(slp_handle_impl_t *hp, slp_target_t *target,
			const char *scopes) {
	slp_target_t *ctarg;
	struct sockaddr_in *sin;
	struct msghdr msg[1];
	char header[SLP_DEFAULT_SENDMTU];
	int sockfd;
	size_t mtu;
	SLPBoolean use_tcp;
	struct pollfd pfd[1];
	unsigned long long now, sent;
	char *reply = NULL;

	use_tcp = SLP_FALSE;
	/* build the header and iovec */
	if (make_header(hp, header, scopes) != SLP_OK)
		return;

	mtu = slp_get_mtu();

	/* walk targets list until we either succeed or run out of targets */
	for (ctarg = target; ctarg; ctarg = slp_next_failover(ctarg)) {
		char *state;
		const char *timeouts;
		int timeout;

		sin = (struct sockaddr_in *)slp_get_target_sin(ctarg);

		/* make the socket, msghdr and reply buf */
		if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			slp_err(LOG_CRIT, 0, "slp_uc_udp_send",
				"could not create socket: %s",
				strerror(errno));
			return;
		}
		pfd[0].fd = sockfd;
		pfd[0].events = POLLRDNORM;

		udp_make_msghdr(sin, hp->msg.iov, hp->msg.iovlen, msg);
		if (!reply && !(reply = malloc(mtu))) {
			(void) close(sockfd);
			slp_err(LOG_CRIT, 0, "slp_uc_udp_send",
				"out of memory");
			return;
		}

		/* timeout loop */
		timeouts = SLPGetProperty(SLP_CONFIG_DATAGRAMTIMEOUTS);
		state = (char *)timeouts;
		for (timeout = slp_get_next_onlist(&state);
			timeout != -1 &&
			!hp->cancel;
			timeout = slp_get_next_onlist(&state)) {
			int pollerr;

			if (sendmsg(sockfd, msg, 0) < 0) {
				slp_err(LOG_CRIT, 0, "slp_uc_udp_send",
					"sendmsg failed: %s", strerror(errno));
				continue; /* try again */
			}
			sent = now_millis();

			pollerr = wait_for_response(
				0, &timeout, sent, &now, pfd, 1);

			if (pollerr == 0)
				/* timeout */
				continue;
			if (pollerr < 0)
				break;

			/* only using one fd, so no need to scan pfd */
			if (recvfrom(sockfd, reply, mtu, 0, NULL, NULL) < 0) {
				/* if reply overflows, hand off to TCP */
				if (errno == ENOMEM) {
					free(reply); reply = NULL;
					use_tcp = SLP_TRUE;
					break;
				}
				slp_err(LOG_CRIT, 0, "slp_uc_udp_send",
					"recvfrom failed: %s",
					strerror(errno));
			} else {
				/* success -- but check error code */
				slp_proto_err errcode = slp_get_errcode(reply);
				switch (errcode) {
				case SLP_MSG_PARSE_ERROR:
				case SLP_VER_NOT_SUPPORTED:
				case SLP_SICK_DA:
				case SLP_DA_BUSY_NOW:
				case SLP_OPTION_NOT_UNDERSTOOD:
				case SLP_RQST_NOT_SUPPORTED: {
				    char addrbuf[INET6_ADDRSTRLEN], *cname;

				    cname = slp_ntop(addrbuf, INET6_ADDRSTRLEN,
					(const void *) &(sin->sin_addr));
				    cname = cname ? cname : "[invalid addr]";

				    /* drop it */
				    slp_err(LOG_INFO, 0,
				"DA %s returned error code %d; dropping reply",
							cname, errcode);
				    free(reply); reply = NULL;
				}
				}
			}
			break;
		}
		if (timeout != -1)
			/* success or cancel */
			break;
		/* else failure */
		slp_mark_target_failed(ctarg);
	}
	(void) close(sockfd);
	if (!ctarg || hp->cancel) {
		/* failed all attempts or canceled by consumer */
		if (reply) free(reply);
		return;
	}
	/* success or tcp handoff */
	if (reply) {
		if (slp_get_overflow(reply))
			use_tcp = SLP_TRUE;
		else
			slp_mark_target_used(ctarg);
		(void) slp_enqueue(hp->q, reply);
	}
	if (use_tcp)
		slp_uc_tcp_send(
			hp, ctarg, scopes, SLP_FALSE, slp_get_xid(header));
}

/*
 * Multicasts (or broadcasts) a message, using multicast convergance
 * to collect results. Large replies will cause the message to be handed
 * off to the TCP thread.
 *
 * This call does not return until the transaction is complete. It does
 * not, however, wait until pending TCP transactions are complete, so
 * callers should always invoke slp_tcp_wait before cleaning up any
 * resources.
 */
void slp_mc_send(slp_handle_impl_t *hp, const char *scopes) {
	char header[SLP_DEFAULT_SENDMTU], *state;
	const char *timeouts;
	struct sockaddr_in sin[1];
	struct msghdr msg[1];
	int maxwait, timeout, noresults, anyresults;
	unsigned long long final_to, now, sent;
	struct pollfd *pfd;
	nfds_t nfds;
	void *collator = NULL;
	struct bc_ifs bcifs;

	/* build the header and iovec */
	if (make_header(hp, header, scopes) != SLP_OK)
		return;

	(void) memset(sin, 0, sizeof (sin));
	if (make_mc_target(hp, sin, header, &pfd, &nfds, &bcifs) != SLP_OK)
		return;
	udp_make_msghdr(sin, hp->msg.iov, hp->msg.iovlen, msg);

	maxwait = slp_get_mcmaxwait();
	maxwait = maxwait ? maxwait : SLP_DEFAULT_MAXWAIT;

	/* set the final timeout */
	now = now_millis();
	final_to = now + maxwait;

	/* timeout prep and loop */
	timeouts = SLPGetProperty(SLP_CONFIG_MULTICASTTIMEOUTS);
	state = (char *)timeouts;
	noresults = anyresults = 0;

	for (timeout = slp_get_next_onlist(&state);
		timeout != -1 &&
		now < final_to &&
		noresults < 2 &&
		!hp->cancel;
		timeout = slp_get_next_onlist(&state)) {

		/* send msg */
		if (mc_sendmsg(pfd, msg, &bcifs) != SLP_OK) {
			continue; /* try again */
		}
		sent = now_millis();

		/* receive results */
		mc_recvmsg(pfd, nfds, hp, scopes, header, &collator, final_to,
			sent, &now, &noresults, &anyresults, timeout);

		if (!anyresults)
			noresults++;
		anyresults = 0;
	}
	/* clean up PR list collator */
	if (collator)
		slp_twalk(collator, free_pr_node, 0, NULL);

	/* close all fds in pfd */
	free_pfds(pfd, nfds);

	/* free broadcast addrs, if used */
	if (bcifs.sin) free(bcifs.sin);
}

/*
 * Private net helper routines
 */

/*
 * Starts the tcp_thread and allocates any necessary resources.
 */
static SLPError
start_tcp_thr(void)
{
	SLPError err;
	int terr;

	(void) mutex_lock(&start_lock);
	/* make sure someone else hasn't already intialized the thread */
	if (tcp_thr_running) {
		(void) mutex_unlock(&start_lock);
		return (SLP_OK);
	}

	/* create the tcp queue */
	if (!(tcp_q = slp_new_queue(&err))) {
		(void) mutex_unlock(&start_lock);
		return (err);
	}

	/* start the tcp thread */
	if ((terr = thr_create(0, 0, tcp_thread, NULL, 0, NULL)) != 0) {
		slp_err(LOG_CRIT, 0, "start_tcp_thr",
		    "could not start thread: %s", strerror(terr));
		(void) mutex_unlock(&start_lock);
		return (SLP_INTERNAL_SYSTEM_ERROR);
	}

	tcp_thr_running = SLP_TRUE;
	(void) mutex_unlock(&start_lock);
	return (SLP_OK);
}

/*
 * Called by the tcp thread to shut itself down. The queue must be
 * empty (and should be, since the tcp thread will only shut itself
 * down if nothing has been put in its queue for the timeout period).
 */
static void end_tcp_thr() {
	(void) mutex_lock(&start_lock);

	tcp_thr_running = SLP_FALSE;
	slp_destroy_queue(tcp_q);

	(void) mutex_unlock(&start_lock);
	thr_exit(NULL);
}

/*
 * The thread of control for the TCP thread. This sits in a loop, waiting
 * on 'tcp_q' for new messages. If no message appear after 30 seconds,
 * this thread cleans up resources and shuts itself down.
 */
static void *
tcp_thread(void *arg __unused)
{
	struct tcp_rqst *rqst;
	char *reply, header[SLP_DEFAULT_SENDMTU];
	timestruc_t to[1];
	to->tv_nsec = 0;

	for (;;) {
		slp_target_t *ctarg, *targets;
		slp_handle_impl_t *hp;
		const char *scopes;
		struct sockaddr_in *sin;
		SLPBoolean free_target, etimed;
		unsigned short xid;

		/* set idle shutdown timeout */
		to->tv_sec = time(NULL) + 30;
		/* get the next request from the tcp queue */
		if (!(rqst = slp_dequeue_timed(tcp_q, to, &etimed))) {
			if (!etimed)
				continue;
			else
				end_tcp_thr();
		}

		hp = rqst->hp;
		scopes = rqst->scopes;
		targets = rqst->target;
		free_target = rqst->free_target;
		xid = rqst->xid;
		free(rqst);
		reply = NULL;

		/* Check if this handle has been cancelled */
		if (hp->cancel)
			goto transaction_complete;

		/* build the header and iovec */
		if (make_header(hp, header, scopes) != SLP_OK) {
			if (free_target) slp_free_target(targets);
			continue;
		}
		if (xid)
			slp_set_xid(header, xid);

	/* walk targets list until we either succeed or run out of targets */
		for (ctarg = targets; ctarg && !hp->cancel;
		    ctarg = slp_next_failover(ctarg)) {

			sin = (struct sockaddr_in *)slp_get_target_sin(ctarg);

			/* create the socket */
			if ((tcp_sockfd = socket(AF_INET, SOCK_STREAM, 0))
			    < 0) {
				slp_err(LOG_CRIT, 0, "tcp_thread",
				    "could not create socket: %s",
				    strerror(errno));
				ctarg = NULL;
				break;
			}

			/* connect to target */
			if (connect(tcp_sockfd, (struct sockaddr *)sin,
			    sizeof (*sin)) < 0) {
				slp_err(LOG_INFO, 0, "tcp_thread",
				    "could not connect, error = %s",
				    strerror(errno));
				goto failed;
			}

			/* send the message and read the reply */
			if (writev(tcp_sockfd, hp->msg.iov, hp->msg.iovlen)
			    == -1) {
				slp_err(LOG_INFO, 0, "tcp_thread",
				    "could not send, error = %s",
				    strerror(errno));
				goto failed;
			}

			/* if success, break out of failover loop */
			if ((slp_tcp_read(tcp_sockfd, &reply)) == SLP_OK) {
				(void) close(tcp_sockfd);
				break;
			}

		/* else if timed out, mark target failed and try next one */
failed:
			(void) close(tcp_sockfd);
			slp_mark_target_failed(ctarg);
		}

		if (hp->cancel) {
			if (reply) {
				free(reply);
			}
		} else if (ctarg) {
			/* success */
			(void) slp_enqueue(hp->q, reply);
			slp_mark_target_used(ctarg);
		}

	/* If all TCP transactions on this handle are complete, send notice */
transaction_complete:
		(void) mutex_lock(hp->tcp_lock);
		if (--(hp->tcp_ref_cnt) == 0)
			(void) cond_signal(hp->tcp_wait);
		(void) mutex_unlock(hp->tcp_lock);

		if (free_target)
			slp_free_target(targets);
	}
	return (NULL);
}

/*
 * Performs a full read for TCP replies, dynamically allocating a
 * buffer large enough to hold the reply.
 */
SLPError slp_tcp_read(int sockfd, char **reply) {
	char lenbuf[5], *p;
	size_t nleft;
	ssize_t nread;
	unsigned int len;

	/* find out how long the reply is */
	nleft = 5;
	p = lenbuf;
	while (nleft != 0) {
		if ((nread = read(sockfd, p, 5)) < 0) {
			if (errno == EINTR)
				nread = 0;
			else
				return (SLP_NETWORK_ERROR);
		} else if (nread == 0)
			/* shouldn't hit EOF here */
			return (SLP_NETWORK_ERROR);
		nleft -= nread;
		p += nread;
	}

	len = slp_get_length(lenbuf);

	/* allocate space for the reply, and copy in what we've already read */
	/* This buffer gets freed by a msg-specific unpacking routine later */
	if (!(*reply = malloc(len))) {
		slp_err(LOG_CRIT, 0, "tcp_read", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	(void) memcpy(*reply, lenbuf, 5);

	/* read the rest of the message */
	nleft = len - 5;
	p = *reply + 5;
	while (nleft != 0) {
		if ((nread = read(sockfd, p, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;
			else {
				free(*reply);
				return (SLP_NETWORK_ERROR);
			}
		} else if (nread == 0)
			/*
			 * shouldn't hit EOF here, but perhaps we've
			 * gotten something useful, so return OK.
			 */
			return (SLP_OK);

		nleft -= nread;
		p += nread;
	}

	return (SLP_OK);
}

/*
 * Lays in a SLP header for this message into the scatter / gather
 * array 'iov'. 'header' is the buffer used to contain the header,
 * and must contain enough space. 'scopes' should contain a string
 * with the scopes to be used for this message.
 */
static SLPError make_header(slp_handle_impl_t *hp, char *header,
			    const char *scopes) {
	SLPError err;
	size_t msgLen, off;
	int i;
	size_t mtu;
	unsigned short slen = (unsigned short)strlen(scopes);

	mtu = slp_get_mtu();
	msgLen = slp_hdrlang_length(hp);
	hp->msg.iov[0].iov_base = header;
	hp->msg.iov[0].iov_len = msgLen;	/* now the length of the hdr */

	/* use the remaining buffer in header for the prlist */
	hp->msg.prlist->iov_base = header + msgLen;

	for (i = 1; i < hp->msg.iovlen; i++) {
		msgLen += hp->msg.iov[i].iov_len;
	}
	msgLen += slen;

	off = 0;
	if ((err = slp_add_header(hp->locale, header, mtu,
					hp->fid, msgLen, &off)) != SLP_OK)
		return (err);

	/* start out with empty prlist */
	hp->msg.prlist->iov_len = 0;

	/* store the scope string len into the space provided by the caller */
	off = 0;
	if ((err = slp_add_sht((char *)hp->msg.scopeslen.iov_base,
				2, slen, &off)) != SLP_OK) {
		return (err);
	}
	hp->msg.scopes->iov_base = (caddr_t)scopes;
	hp->msg.scopes->iov_len = slen;

	return (SLP_OK);
}

/*
 * Populates a struct msghdr suitable for use with sendmsg.
 */
static void udp_make_msghdr(struct sockaddr_in *sin, struct iovec *iov,
			    int iovlen, struct msghdr *msg) {
	msg->msg_name = (caddr_t)sin;
	msg->msg_namelen = 16;
	msg->msg_iov = iov;
	msg->msg_iovlen = iovlen;
	msg->msg_accrights = NULL;
	msg->msg_accrightslen = 0;
}

/*
 * Sets the address on 'sin', sets the flag in the message header,
 * and creates an array of pollfds for all interfaces we need to
 * use. If we need to use only broadcast, and net.slp.interfaces
 * is set, fills bcifs with an array of subnet broadcast addresses
 * to which we should send. Returns err != SLP_OK only on catastrophic
 * error.
 */
static SLPError make_mc_target(slp_handle_impl_t *hp,
				struct sockaddr_in *sin, char *header,
				struct pollfd **fds, nfds_t *nfds,
				struct bc_ifs *bcifs) {

	unsigned char ttl = slp_get_multicastTTL();
	char *ifs_string;
	SLPBoolean have_valid_if = SLP_FALSE;
	SLPBoolean use_broadcast = slp_get_usebroadcast();
	int fd, i, num_givenifs;
	struct in_addr *given_ifs = NULL;
	nfds_t nfd_i;

	sin->sin_port = htons(SLP_PORT);
	sin->sin_family = AF_INET;
	slp_set_mcast(header);

	/* Get the desired multicast interfaces, if set */
	bcifs->sin = NULL;
	*fds = NULL;
	if ((ifs_string = (char *)SLPGetProperty(
		SLP_CONFIG_INTERFACES)) != NULL && *ifs_string) {

		char *p, *tstate;

		/* count the number of IFs given */
		p = strchr(ifs_string, ',');
		for (num_givenifs = 1; p; num_givenifs++) {
			p = strchr(p + 1, ',');
		}

		/* copy the given IFs into an array for easier processing */
		if (!(given_ifs = calloc(num_givenifs, sizeof (*given_ifs)))) {
			slp_err(LOG_CRIT, 0, "make_mc_target",
						"out of memory");
			return (SLP_MEMORY_ALLOC_FAILED);
		}

		i = 0;
		/* strtok_r will destructively modify, so make a copy first */
		if (!(ifs_string = strdup(ifs_string))) {
			slp_err(LOG_CRIT, 0, "make_mc_target",
						"out of memory");
			free(given_ifs);
			return (SLP_MEMORY_ALLOC_FAILED);
		}
		for (
			p = strtok_r(ifs_string, ",", &tstate);
			p;
			p = strtok_r(NULL, ",", &tstate)) {

			if (slp_pton(p, &(given_ifs[i])) < 1) {
				/* skip */
				num_givenifs--;
				continue;
			}
			i++;
		}
		*nfds = num_givenifs;
		free(ifs_string);

		/* allocate a pollfd array for all interfaces */
		if (!(*fds = calloc(num_givenifs, sizeof (**fds)))) {
			slp_err(LOG_CRIT, 0, "make_mc_target",
						"out of memory");
			free(ifs_string);
			free(given_ifs);
			return (SLP_MEMORY_ALLOC_FAILED);
		}

		/* lay the given interfaces into the pollfd array */
		for (i = 0; i < num_givenifs; i++) {

			/* create a socket to bind to this interface */
			if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
				slp_err(LOG_CRIT, 0, "make_mc_target",
						"could not create socket: %s",
						strerror(errno));
				free_pfds(*fds, *nfds);
				return (SLP_INTERNAL_SYSTEM_ERROR);
			}

			/* fill in the pollfd structure */
			(*fds)[i].fd = fd;
			(*fds)[i].events |= POLLRDNORM;

			if (use_broadcast) {
				struct sockaddr_in bcsin[1];

				(void) memcpy(
					&(bcsin->sin_addr), &(given_ifs[i]),
					sizeof (bcsin->sin_addr));
				bcsin->sin_family = AF_INET;
				bcsin->sin_port = 0;

				/* bind fd to interface */
				if (bind(fd, (struct sockaddr *)bcsin,
						sizeof (*bcsin)) == 0) {
					continue;
				}
				/* else fallthru to default (multicast) */
				slp_err(LOG_INFO, 0, "make_mc_target",
				"could not set broadcast interface: %s",
					strerror(errno));
			}
			/* else use multicast */
			if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
					&(given_ifs[i]), sizeof (given_ifs[i]))
					< 0) {

					slp_err(LOG_INFO, 0, "make_mc_target",
				"could not set multicast interface: %s",
							strerror(errno));
					continue;
			}

			have_valid_if = SLP_TRUE;
		}

		if (use_broadcast) {
		    SLPError err;

		    if ((err = make_bc_target(
					hp, given_ifs, num_givenifs, bcifs))
			!= SLP_OK) {

			if (err == SLP_MEMORY_ALLOC_FAILED) {
			    /* the only thing which is really a showstopper */
			    return (err);
			}

			/* else no valid interfaces */
			have_valid_if = SLP_FALSE;
		    }
		}
		free(given_ifs);
	}

	if (!have_valid_if) {
		if (*fds && !have_valid_if) {
			/* couldn't process net.slp.interfaces property */
			free(*fds);
		}

		/* bind to default interface */
		if (!(*fds = calloc(1, sizeof (**fds)))) {
			slp_err(LOG_CRIT, 0, "make_mc_target",
						"out of memory");
			return (SLP_MEMORY_ALLOC_FAILED);
		}

		if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			slp_err(LOG_CRIT, 0, "make_mc_target",
						"could not create socket: %s",
						strerror(errno));
			free(*fds);
			return (SLP_INTERNAL_SYSTEM_ERROR);
		}

		(**fds).fd = fd;
		(**fds).events |= POLLRDNORM;
		*nfds = 1;
	}

	/* set required options on all configured fds */
	for (nfd_i = 0; nfd_i < *nfds; nfd_i++) {
		if (use_broadcast) {
			const int on = 1;
			if (setsockopt((*fds)[nfd_i].fd, SOL_SOCKET,
					SO_BROADCAST,
					(void *) &on, sizeof (on)) < 0) {
				slp_err(LOG_CRIT, 0, "make_mc_target",
					"could not enable broadcast: %s",
					strerror(errno));
			}
		} else {
			if (setsockopt((*fds)[nfd_i].fd, IPPROTO_IP,
					IP_MULTICAST_TTL, &ttl, 1) < 0) {
				slp_err(LOG_CRIT, 0, "make_mc_target",
					    "could not set multicast TTL: %s",
					    strerror(errno));
			}
		}
	}

	if (use_broadcast) {
	    sin->sin_addr.s_addr = INADDR_BROADCAST;
	} else {
		sin->sin_addr.s_addr = SLP_MULTICAST_ADDRESS;
	}

	return (SLP_OK);
}

/*
 * Obtains the subnet broadcast address for each interface specified
 * in net.slp.interfaces, and fill bcifs->sin with an array of these
 * addresses.
 */
static SLPError make_bc_target(slp_handle_impl_t *hp,
				struct in_addr *given_ifs,
				int num_givenifs, struct bc_ifs *bcifs) {
	SLPError err;
	int i;

	if ((err = slp_broadcast_addrs(hp, given_ifs, num_givenifs,
					&(bcifs->sin), &(bcifs->num_ifs)))
	    != SLP_OK) {
	    return (err);
	}

	/* set SLP port on each sockaddr_in */
	for (i = 0; i < bcifs->num_ifs; i++) {
		bcifs->sin[i].sin_port = htons(SLP_PORT);
	}

	return (SLP_OK);
}

/*
 * Sends msg on 1st fd in fds for multicast, or on all interfaces
 * specified in net.slp.interfaces for broadcast. Returns SLP_OK if
 * msg was sent successfully on at least one interface; otherwise
 * returns SLP_NETWORK_ERROR if msg was not sent on any interfaces.
 */
static SLPError mc_sendmsg(struct pollfd *fds,
				struct msghdr *msg, struct bc_ifs *bcifs) {

	if (slp_get_usebroadcast()) {
	    char *ifs = (char *)SLPGetProperty(SLP_CONFIG_INTERFACES);

	    /* hand off to broadcast-specific send function */
	    if (ifs && *ifs && bc_sendmsg(fds, msg, bcifs) == SLP_OK) {
		return (SLP_OK);
	    }

		/*
		 * else  no ifs given, or bc_sendmsg failed, so send on
		 * general broadcast addr (255.255.255.255). This will
		 * cause the message to be sent on all interfaces. The
		 * address will have been set in make_mc_target.
		 */
	}

	/*
	 * Send only on one interface -- let routing take care of
	 * sending the message everywhere it needs to go. Sending
	 * on more than one interface can cause nasty routing loops.
	 * Note that this approach doesn't work with partitioned
	 * networks.
	 */
	if (sendmsg(fds[0].fd, msg, 0) < 0) {
		slp_err(LOG_CRIT, 0, "mc_sendmsg",
			"sendmsg failed: %s", strerror(errno));
		return (SLP_NETWORK_ERROR);
	}

	return (SLP_OK);
}

/*
 * Send msg to each subnet broadcast address in bcifs->sin. Note
 * that we can send on any fd (regardless of which interface to which
 * it is bound), since the kernel will take care of routing for us.
 * Returns err != SLP_OK only if no message was sent on any interface.
 */
static SLPError bc_sendmsg(struct pollfd *fds, struct msghdr *msg,
				struct bc_ifs *bcifs) {
	int i;
	SLPBoolean sent_one = SLP_FALSE;

	for (i = 0; i < bcifs->num_ifs; i++) {
		msg->msg_name = (caddr_t)&(bcifs->sin[i]);

		if (sendmsg(fds[0].fd, msg, 0) < 0) {
			slp_err(LOG_CRIT, 0, "bc_sendmsg",
				"sendmsg failed: %s", strerror(errno));
			continue;
		}
		sent_one = SLP_TRUE;
	}
	return (sent_one ? SLP_OK : SLP_NETWORK_ERROR);
}

/*
 * This is where the bulk of the multicast convergance algorithm resides.
 * mc_recvmsg() waits for data to be ready on any fd in pfd, iterates
 * through pfd and reads data from ready fd's. It also checks timeouts
 * and user-cancels.
 *
 * Parameters:
 *   pfd	IN	an array of pollfd structs containing fds to poll
 *   nfds	IN	number of elements in pfd
 *   hp		IN	SLPHandle from originating call
 *   scopes	IN	scopes to use for this message
 *   header	IN	the SLP message header for this message
 *   collator	IN/OUT	btree collator for PR list
 *   final_to	IN	final timeout
 *   sent	IN	time when message was sent
 *   now	IN/OUT	set to current time at beginning of convergance
 *   noresults	OUT	set to 0 if any results are received
 *   anyresults	OUT	set to true if any results are received
 *   timeout	IN	time for this convergence iteration
 *
 * Returns only if an error has occured, or if either this retransmit
 * timeout or the final timeout has expired, or if hp->cancel becomes true.
 */
static void mc_recvmsg(struct pollfd *pfd, nfds_t nfds, slp_handle_impl_t *hp,
			const char *scopes, char *header, void **collator,
			unsigned long long final_to,
			unsigned long long sent,
			unsigned long long *now,
			int *noresults, int *anyresults, int timeout) {
	char *reply = NULL;
	nfds_t i;
	struct sockaddr_in responder;
	int pollerr;
	socklen_t addrlen = sizeof (responder);
	size_t mtu = slp_get_mtu();

	for (; !hp->cancel; ) {
	    /* wait until we can read something */
	    pollerr = wait_for_response(
				final_to, &timeout, sent, now, pfd, nfds);
	    if (pollerr == 0)
		/* timeout */
		goto cleanup;
	    if (pollerr < 0)
		/* error */
		goto cleanup;

	    /* iterate through all fds to find one with data to read */
	    for (i = 0; !hp->cancel && i < nfds; i++) {

		if (pfd[i].fd < 0 ||
		    !(pfd[i].revents & (POLLRDNORM | POLLERR))) {

		    /* unused fd or unwanted event */
		    continue;
		}

		/* alloc reply buffer */
		if (!reply && !(reply = malloc(mtu))) {
		    slp_err(LOG_CRIT, 0, "mc_revcmsg", "out of memory");
		    return;
	    }
		if (recvfrom(pfd[i].fd, reply, mtu, 0,
				(struct sockaddr *)&responder,
				(int *)&addrlen) < 0) {

		    /* if reply overflows, hand off to TCP */
		    if (errno == ENOMEM) {
			free(reply); reply = NULL;
			tcp_handoff(hp, scopes,
					&responder, slp_get_xid(header));
			continue;
		    }

		    /* else something nasty happened */
		    slp_err(LOG_CRIT, 0, "mc_recvmsg",
					"recvfrom failed: %s",
					strerror(errno));
		    continue;
		} else {
		    /* success */
		    if (slp_get_overflow(reply)) {
			tcp_handoff(hp, scopes,
					&responder, slp_get_xid(header));
		    }
			/*
			 * Add to the PR list. If this responder has already
			 * answered, it doesn't count.
			 */
		    if (add2pr_list(&(hp->msg), &responder, collator)) {
			(void) slp_enqueue(hp->q, reply);
			*noresults = 0;
			*anyresults = 1;
			reply = NULL;
		    }

		    /* if we've exceeded maxwait, break out */
		    *now = now_millis();
		    if (*now > final_to)
			goto cleanup;

		} /* end successful receive */

	    } /* end fd iteration */

	    /* reset poll's timeout */
	    timeout = timeout - (int)(*now - sent);
	    if (timeout <= 0) {
		goto cleanup;
	    }

	} /* end main poll loop */

cleanup:
	if (reply) {
	    free(reply);
	}
}

/*
 * Closes any open sockets and frees the pollfd array.
 */
static void free_pfds(struct pollfd *pfds, nfds_t nfds) {
	nfds_t i;

	for (i = 0; i < nfds; i++) {
	    if (pfds[i].fd <= 0) {
		continue;
	    }

	    (void) close(pfds[i].fd);
	}

	free(pfds);
}

/*
 * Hands off a message to the TCP thread, fabricating a new target
 * from 'sin'. 'xid' will be used to create the XID for the TCP message.
 */
static void tcp_handoff(slp_handle_impl_t *hp, const char *scopes,
			struct sockaddr_in *sin, unsigned short xid) {
	slp_target_t *target;

	target = slp_fabricate_target(sin);
	slp_uc_tcp_send(hp, target, scopes, SLP_TRUE, xid);
}

/*
 * Returns the current time in milliseconds.
 */
static unsigned long long now_millis() {
	unsigned long long i;
	struct timeval tv[1];

	(void) gettimeofday(tv, NULL);
	i = (unsigned long long) tv->tv_sec * 1000;
	i += tv->tv_usec / 1000;
	return (i);
}

/*
 * A wrapper around poll which waits until a reply comes in. This will
 * wait no longer than 'timeout' before returning. poll can return
 * even if no data is on the pipe or timeout has occured, so the
 * additional paramaters are used to break out of the wait loop if
 * we have exceeded the timeout value. 'final_to' is ignored if it is 0.
 *
 * returns:	< 0 on error
 *		0 on timeout
 *		> 0 on success (i.e. ready to read data).
 * side effect: 'now' is set to the time when poll found data on the pipe.
 */
static int wait_for_response(
	unsigned long long final_to,
	int *timeout,
	unsigned long long sent,
	unsigned long long *now,
	struct pollfd pfd[], nfds_t nfds) {

	int when, pollerr;

	/* wait until we can read something */
	for (;;) {
		pollerr = poll(pfd, nfds, *timeout);
		*now = now_millis();

		/* ready to read */
		if (pollerr > 0)
			return (pollerr);

		/* time out */
		if (pollerr == 0)
			/* timeout */
			return (0);

		/* error */
		if (pollerr < 0)
			if (errno == EAGAIN || errno == EINTR) {
				/* poll is weird. */
				when = (int)(*now - sent);
				if (
					(final_to != 0 && *now > final_to) ||
					when > *timeout)
					break;
				*timeout = *timeout - when;
				continue;
			} else {
				slp_err(LOG_INFO, 0, "wait for response",
					"poll error: %s",
					strerror(errno));
				return (pollerr);
			}
	}

	return (0);
}

/*
 * Adds the cname of the host whose address is in 'sin' to this message's
 * previous responder list. The message is contained in 'msg'.
 * 'collator' contains the complete previous responder list, so that
 * even if the PR list in the message overflows and must be truncated,
 * the function can still correctly determine if we have heard from this
 * host before.
 *
 * returns:	1 if this is the first time we've heard from this host
 *		0 is this is a duplicate reply
 */
static int add2pr_list(
	slp_msg_t *msg,
	struct sockaddr_in *sin,
	void **collator) {

	char **res, *cname, *p, *header;
	size_t mtu;
	size_t len, off, namelen;
	unsigned short prlen;

	/* Attempt to resolve the responder's IP address to its host name */
	if (!(cname = slp_gethostbyaddr((char *)&(sin->sin_addr),
					sizeof (sin->sin_addr))))
		return (0);

	res = slp_tsearch(
		cname, collator,
		(int (*)(const void *, const void *)) strcasecmp);
	if (*res != cname) {
		/* duplicate */
		slp_err(LOG_INFO, 0, "add2pr_list",
			"drop PR ignored by host: %s",
			cname);
		free(cname);
		return (0);
	}

	/* new responder: add to the msg PR list if there is room */
	mtu = slp_get_mtu();

	header = msg->iov[0].iov_base;
	len = slp_get_length(header);

	namelen = strlen(cname);
	if ((namelen + 2 + len) >= mtu)
		return (1);	/* no room */

	/* else  there is enough room */
	prlen = (unsigned short)msg->prlist->iov_len;
	p = msg->prlist->iov_base + prlen;
	*p = 0;

	if (prlen) {
		namelen++;	/* add the ',' */
		(void) strcat(p, ",");
	}
	(void) strcat(p, cname);

	/* update msg and pr list length */
	len += namelen;
	slp_set_length(header, len);
	prlen += (unsigned short)namelen;
	off = 0;
	(void) slp_add_sht(msg->prlistlen.iov_base, 2, prlen, &off);
	msg->prlist->iov_len += namelen;

	return (1);
}

/*
 * The iterator function used while traversing the previous responder
 * tree. Just frees resources.
 */
/*ARGSUSED2*/
static void free_pr_node(void *node, VISIT order, int level, void *cookie) {
	if (order == endorder || order == leaf) {
		char *pr = *(char **)node;
		free(pr);
		free(node);
	}
}
