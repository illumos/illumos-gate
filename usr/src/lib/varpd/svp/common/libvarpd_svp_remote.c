/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Remote backend management
 *
 * For more information, see the big theory statement in
 * lib/varpd/svp/common/libvarpd_svp.c.
 */

#include <umem.h>
#include <strings.h>
#include <string.h>
#include <stddef.h>
#include <thread.h>
#include <synch.h>
#include <assert.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <libidspace.h>

#include <libvarpd_provider.h>
#include <libvarpd_svp.h>

typedef struct svp_shoot_vl3 {
	svp_query_t		ssv_query;
	struct sockaddr_in6	ssv_sock;
	svp_log_vl3_t 		*ssv_vl3;
	svp_sdlog_t		*ssv_log;
} svp_shoot_vl3_t;

static mutex_t svp_remote_lock = ERRORCHECKMUTEX;
static avl_tree_t svp_remote_tree;
static svp_timer_t svp_dns_timer;
static id_space_t *svp_idspace;
static int svp_dns_timer_rate = 30;	/* seconds */

static void
svp_remote_mkfmamsg(svp_remote_t *srp, svp_degrade_state_t state, char *buf,
    size_t buflen)
{
	switch (state) {
	case SVP_RD_DNS_FAIL:
		(void) snprintf(buf, buflen, "failed to resolve or find "
		    "entries for hostname %s", srp->sr_hostname);
		break;
	case SVP_RD_REMOTE_FAIL:
		(void) snprintf(buf, buflen, "cannot reach any remote peers");
		break;
	default:
		(void) snprintf(buf, buflen, "unkonwn error state: %d", state);
	}
}

static int
svp_remote_comparator(const void *l, const void *r)
{
	int ret;
	const svp_remote_t *lr = l, *rr = r;

	ret = strcmp(lr->sr_hostname, rr->sr_hostname);
	if (ret > 0)
		return (1);
	else if (ret < 0)
		return (-1);

	if (lr->sr_rport > rr->sr_rport)
		return (1);
	else if (lr->sr_rport < rr->sr_rport)
		return (-1);

	return (memcmp(&lr->sr_uip, &rr->sr_uip, sizeof (struct in6_addr)));
}

void
svp_query_release(svp_query_t *sqp)
{
	id_free(svp_idspace, sqp->sq_header.svp_id);
}

static void
svp_remote_destroy(svp_remote_t *srp)
{
	size_t len;

	/*
	 * Clean up any unrelated DNS information. At this point we know that
	 * we're not in the remote tree. That means, that svp_remote_dns_timer
	 * cannot queue us. However, if any of our DNS related state flags are
	 * set, we have to hang out.
	 */
	mutex_enter(&srp->sr_lock);
	while (srp->sr_state &
	    (SVP_RS_LOOKUP_SCHEDULED | SVP_RS_LOOKUP_INPROGRESS)) {
		(void) cond_wait(&srp->sr_cond, &srp->sr_lock);
	}
	mutex_exit(&srp->sr_lock);
	svp_shootdown_fini(srp);

	if (cond_destroy(&srp->sr_cond) != 0)
		libvarpd_panic("failed to destroy cond sr_cond");

	if (mutex_destroy(&srp->sr_lock) != 0)
		libvarpd_panic("failed to destroy mutex sr_lock");

	if (srp->sr_addrinfo != NULL)
		freeaddrinfo(srp->sr_addrinfo);
	len = strlen(srp->sr_hostname) + 1;
	umem_free(srp->sr_hostname, len);
	umem_free(srp, sizeof (svp_remote_t));
}

static int
svp_remote_create(const char *host, uint16_t port, struct in6_addr *uip,
    svp_remote_t **outp)
{
	size_t hlen;
	svp_remote_t *remote;

	assert(MUTEX_HELD(&svp_remote_lock));

	remote = umem_zalloc(sizeof (svp_remote_t), UMEM_DEFAULT);
	if (remote == NULL) {
		mutex_exit(&svp_remote_lock);
		return (ENOMEM);
	}

	if (svp_shootdown_init(remote) != 0) {
		umem_free(remote, sizeof (svp_remote_t));
		mutex_exit(&svp_remote_lock);
		return (ENOMEM);
	}

	hlen = strlen(host) + 1;
	remote->sr_hostname = umem_alloc(hlen, UMEM_DEFAULT);
	if (remote->sr_hostname == NULL) {
		svp_shootdown_fini(remote);
		umem_free(remote, sizeof (svp_remote_t));
		mutex_exit(&svp_remote_lock);
		return (ENOMEM);
	}
	remote->sr_rport = port;
	if (mutex_init(&remote->sr_lock,
	    USYNC_THREAD | LOCK_ERRORCHECK, NULL) != 0)
		libvarpd_panic("failed to create mutex sr_lock");
	if (cond_init(&remote->sr_cond, USYNC_PROCESS, NULL) != 0)
		libvarpd_panic("failed to create cond sr_cond");
	list_create(&remote->sr_conns, sizeof (svp_conn_t),
	    offsetof(svp_conn_t, sc_rlist));
	avl_create(&remote->sr_tree, svp_comparator, sizeof (svp_t),
	    offsetof(svp_t, svp_rlink));
	(void) strlcpy(remote->sr_hostname, host, hlen);
	remote->sr_count = 1;
	remote->sr_uip = *uip;

	svp_shootdown_start(remote);

	*outp = remote;
	return (0);
}

int
svp_remote_find(char *host, uint16_t port, struct in6_addr *uip,
    svp_remote_t **outp)
{
	int ret;
	svp_remote_t lookup, *remote;

	lookup.sr_hostname = host;
	lookup.sr_rport = port;
	lookup.sr_uip = *uip;
	mutex_enter(&svp_remote_lock);
	remote = avl_find(&svp_remote_tree, &lookup, NULL);
	if (remote != NULL) {
		assert(remote->sr_count > 0);
		remote->sr_count++;
		*outp = remote;
		mutex_exit(&svp_remote_lock);
		return (0);
	}

	if ((ret = svp_remote_create(host, port, uip, outp)) != 0) {
		mutex_exit(&svp_remote_lock);
		return (ret);
	}

	avl_add(&svp_remote_tree, *outp);
	mutex_exit(&svp_remote_lock);

	/* Make sure DNS is up to date */
	svp_host_queue(*outp);

	return (0);
}

void
svp_remote_release(svp_remote_t *srp)
{
	mutex_enter(&svp_remote_lock);
	mutex_enter(&srp->sr_lock);
	srp->sr_count--;
	if (srp->sr_count != 0) {
		mutex_exit(&srp->sr_lock);
		mutex_exit(&svp_remote_lock);
		return;
	}
	mutex_exit(&srp->sr_lock);

	avl_remove(&svp_remote_tree, srp);
	mutex_exit(&svp_remote_lock);
	svp_remote_destroy(srp);
}

int
svp_remote_attach(svp_remote_t *srp, svp_t *svp)
{
	svp_t check;
	avl_index_t where;

	mutex_enter(&srp->sr_lock);
	if (svp->svp_remote != NULL)
		libvarpd_panic("failed to create mutex sr_lock");

	/*
	 * We require everything except shootdowns
	 */
	if (svp->svp_cb.scb_vl2_lookup == NULL)
		libvarpd_panic("missing callback scb_vl2_lookup");
	if (svp->svp_cb.scb_vl3_lookup == NULL)
		libvarpd_panic("missing callback scb_vl3_lookup");
	if (svp->svp_cb.scb_vl2_invalidate == NULL)
		libvarpd_panic("missing callback scb_vl2_invalidate");
	if (svp->svp_cb.scb_vl3_inject == NULL)
		libvarpd_panic("missing callback scb_vl3_inject");

	check.svp_vid = svp->svp_vid;
	if (avl_find(&srp->sr_tree, &check, &where) != NULL)
		libvarpd_panic("found duplicate entry with vid %ld",
		    svp->svp_vid);
	avl_insert(&srp->sr_tree, svp, where);
	svp->svp_remote = srp;
	mutex_exit(&srp->sr_lock);

	return (0);
}

void
svp_remote_detach(svp_t *svp)
{
	svp_t *lookup;
	svp_remote_t *srp = svp->svp_remote;

	if (srp == NULL)
		libvarpd_panic("trying to detach remote when none exists");

	mutex_enter(&srp->sr_lock);
	lookup = avl_find(&srp->sr_tree, svp, NULL);
	if (lookup == NULL || lookup != svp)
		libvarpd_panic("inconsitent remote avl tree...");
	avl_remove(&srp->sr_tree, svp);
	svp->svp_remote = NULL;
	mutex_exit(&srp->sr_lock);
	svp_remote_release(srp);
}

/*
 * Walk the list of connections and find the first one that's available, the
 * move it to the back of the list so it's less likely to be used again.
 */
static boolean_t
svp_remote_conn_queue(svp_remote_t *srp, svp_query_t *sqp)
{
	svp_conn_t *scp;

	assert(MUTEX_HELD(&srp->sr_lock));
	for (scp = list_head(&srp->sr_conns); scp != NULL;
	    scp = list_next(&srp->sr_conns, scp)) {
		mutex_enter(&scp->sc_lock);
		if (scp->sc_cstate != SVP_CS_ACTIVE) {
			mutex_exit(&scp->sc_lock);
			continue;
		}
		svp_conn_queue(scp, sqp);
		mutex_exit(&scp->sc_lock);
		list_remove(&srp->sr_conns, scp);
		list_insert_tail(&srp->sr_conns, scp);
		return (B_TRUE);
	}

	return (B_FALSE);
}

static void
svp_remote_vl2_lookup_cb(svp_query_t *sqp, void *arg)
{
	svp_t *svp = sqp->sq_svp;
	svp_vl2_ack_t *vl2a = (svp_vl2_ack_t *)sqp->sq_wdata;

	if (sqp->sq_status == SVP_S_OK)
		svp->svp_cb.scb_vl2_lookup(svp, sqp->sq_status,
		    (struct in6_addr *)vl2a->sl2a_addr, ntohs(vl2a->sl2a_port),
		    arg);
	else
		svp->svp_cb.scb_vl2_lookup(svp, sqp->sq_status, NULL, 0, arg);
}

void
svp_remote_vl2_lookup(svp_t *svp, svp_query_t *sqp, const uint8_t *mac,
    void *arg)
{
	svp_remote_t *srp;
	svp_vl2_req_t *vl2r = &sqp->sq_rdun.sqd_vl2r;

	srp = svp->svp_remote;
	sqp->sq_func = svp_remote_vl2_lookup_cb;
	sqp->sq_arg = arg;
	sqp->sq_svp = svp;
	sqp->sq_state = SVP_QUERY_INIT;
	sqp->sq_header.svp_ver = htons(SVP_CURRENT_VERSION);
	sqp->sq_header.svp_op = htons(SVP_R_VL2_REQ);
	sqp->sq_header.svp_size = htonl(sizeof (svp_vl2_req_t));
	sqp->sq_header.svp_id = id_alloc(svp_idspace);
	if (sqp->sq_header.svp_id == (id_t)-1)
		libvarpd_panic("failed to allcoate from svp_idspace: %d",
		    errno);
	sqp->sq_header.svp_crc32 = htonl(0);
	sqp->sq_rdata = vl2r;
	sqp->sq_rsize = sizeof (svp_vl2_req_t);
	sqp->sq_wdata = NULL;
	sqp->sq_wsize = 0;

	bcopy(mac, vl2r->sl2r_mac, ETHERADDRL);
	vl2r->sl2r_vnetid = ntohl(svp->svp_vid);

	mutex_enter(&srp->sr_lock);
	if (svp_remote_conn_queue(srp, sqp) == B_FALSE)
		svp->svp_cb.scb_vl2_lookup(svp, SVP_S_FATAL, NULL, 0, arg);
	mutex_exit(&srp->sr_lock);
}

static void
svp_remote_vl3_lookup_cb(svp_query_t *sqp, void *arg)
{
	svp_t *svp = sqp->sq_svp;
	svp_vl3_ack_t *vl3a = (svp_vl3_ack_t *)sqp->sq_wdata;

	if (sqp->sq_status == SVP_S_OK)
		svp->svp_cb.scb_vl3_lookup(svp, sqp->sq_status, vl3a->sl3a_mac,
		    (struct in6_addr *)vl3a->sl3a_uip, ntohs(vl3a->sl3a_uport),
		    arg);
	else
		svp->svp_cb.scb_vl3_lookup(svp, sqp->sq_status, NULL, NULL, 0,
		    arg);
}

static void
svp_remote_vl3_common(svp_remote_t *srp, svp_query_t *sqp,
    const struct sockaddr *addr,  svp_query_f func, void *arg, uint32_t vid)
{
	svp_vl3_req_t *vl3r = &sqp->sq_rdun.sdq_vl3r;

	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		libvarpd_panic("unexpected sa_family for the vl3 lookup");

	sqp->sq_func = func;
	sqp->sq_arg = arg;
	sqp->sq_state = SVP_QUERY_INIT;
	sqp->sq_header.svp_ver = htons(SVP_CURRENT_VERSION);
	sqp->sq_header.svp_op = htons(SVP_R_VL3_REQ);
	sqp->sq_header.svp_size = htonl(sizeof (svp_vl3_req_t));
	sqp->sq_header.svp_id = id_alloc(svp_idspace);
	if (sqp->sq_header.svp_id == (id_t)-1)
		libvarpd_panic("failed to allcoate from svp_idspace: %d",
		    errno);
	sqp->sq_header.svp_crc32 = htonl(0);
	sqp->sq_rdata = vl3r;
	sqp->sq_rsize = sizeof (svp_vl3_req_t);
	sqp->sq_wdata = NULL;
	sqp->sq_wsize = 0;

	if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)addr;
		vl3r->sl3r_type = htonl(SVP_VL3_IPV6);
		bcopy(&s6->sin6_addr, vl3r->sl3r_ip,
		    sizeof (struct in6_addr));
	} else {
		struct sockaddr_in *s4 = (struct sockaddr_in *)addr;
		struct in6_addr v6;

		vl3r->sl3r_type = htonl(SVP_VL3_IP);
		IN6_INADDR_TO_V4MAPPED(&s4->sin_addr, &v6);
		bcopy(&v6, vl3r->sl3r_ip, sizeof (struct in6_addr));
	}
	vl3r->sl3r_vnetid = htonl(vid);

	mutex_enter(&srp->sr_lock);
	if (svp_remote_conn_queue(srp, sqp) == B_FALSE) {
		sqp->sq_status = SVP_S_FATAL;
		sqp->sq_func(sqp, arg);
	}
	mutex_exit(&srp->sr_lock);
}

/*
 * This is a request to do a VL3 look-up that originated internally as opposed
 * to coming from varpd. As such we need a slightly different query callback
 * function upon completion and don't go through the normal path with the svp_t.
 */
void
svp_remote_vl3_logreq(svp_remote_t *srp, svp_query_t *sqp, uint32_t vid,
    const struct sockaddr *addr, svp_query_f func, void *arg)
{
	svp_remote_vl3_common(srp, sqp, addr, func, arg, vid);
}

void
svp_remote_vl3_lookup(svp_t *svp, svp_query_t *sqp,
    const struct sockaddr *addr, void *arg)
{
	svp_remote_t *srp = svp->svp_remote;

	sqp->sq_svp = svp;
	svp_remote_vl3_common(srp, sqp, addr, svp_remote_vl3_lookup_cb,
	    arg, svp->svp_vid);
}

static void
svp_remote_log_request_cb(svp_query_t *sqp, void *arg)
{
	svp_remote_t *srp = sqp->sq_arg;

	assert(sqp->sq_wdata != NULL);
	if (sqp->sq_status == SVP_S_OK)
		svp_shootdown_logr_cb(srp, sqp->sq_status, sqp->sq_wdata,
		    sqp->sq_size);
	else
		svp_shootdown_logr_cb(srp, sqp->sq_status, NULL, 0);
}

void
svp_remote_log_request(svp_remote_t *srp, svp_query_t *sqp, void *buf,
    size_t buflen)
{
	svp_log_req_t *logr = &sqp->sq_rdun.sdq_logr;
	boolean_t queued;

	sqp->sq_func = svp_remote_log_request_cb;
	sqp->sq_state = SVP_QUERY_INIT;
	sqp->sq_arg = srp;
	sqp->sq_header.svp_ver = htons(SVP_CURRENT_VERSION);
	sqp->sq_header.svp_op = htons(SVP_R_LOG_REQ);
	sqp->sq_header.svp_size = htonl(sizeof (svp_log_req_t));
	sqp->sq_header.svp_id = id_alloc(svp_idspace);
	if (sqp->sq_header.svp_id == (id_t)-1)
		libvarpd_panic("failed to allcoate from svp_idspace: %d",
		    errno);
	sqp->sq_header.svp_crc32 = htonl(0);
	sqp->sq_rdata = logr;
	sqp->sq_rsize = sizeof (svp_log_req_t);
	sqp->sq_wdata = buf;
	sqp->sq_wsize = buflen;

	logr->svlr_count = htonl(buflen);
	bcopy(&srp->sr_uip, logr->svlr_ip, sizeof (struct in6_addr));

	/*
	 * If this fails, there isn't much that we can't do. Give the callback
	 * with a fatal status.
	 */
	mutex_enter(&srp->sr_lock);
	queued = svp_remote_conn_queue(srp, sqp);
	mutex_exit(&srp->sr_lock);

	if (queued == B_FALSE)
		svp_shootdown_logr_cb(srp, SVP_S_FATAL, NULL, 0);
}

static void
svp_remote_lrm_request_cb(svp_query_t *sqp, void *arg)
{
	svp_remote_t *srp = arg;

	svp_shootdown_lrm_cb(srp, sqp->sq_status);
}

void
svp_remote_lrm_request(svp_remote_t *srp, svp_query_t *sqp, void *buf,
    size_t buflen)
{
	boolean_t queued;
	svp_lrm_req_t *svrr = buf;

	sqp->sq_func = svp_remote_lrm_request_cb;
	sqp->sq_state = SVP_QUERY_INIT;
	sqp->sq_arg = srp;
	sqp->sq_header.svp_ver = htons(SVP_CURRENT_VERSION);
	sqp->sq_header.svp_op = htons(SVP_R_LOG_RM);
	sqp->sq_header.svp_size = htonl(buflen);
	sqp->sq_header.svp_id = id_alloc(svp_idspace);
	if (sqp->sq_header.svp_id == (id_t)-1)
		libvarpd_panic("failed to allcoate from svp_idspace: %d",
		    errno);
	sqp->sq_header.svp_crc32 = htonl(0);
	sqp->sq_rdata = buf;
	sqp->sq_rsize = buflen;
	sqp->sq_wdata = NULL;
	sqp->sq_wsize = 0;

	/*
	 * We need to fix up the count to be in proper network order.
	 */
	svrr->svrr_count = htonl(svrr->svrr_count);

	/*
	 * If this fails, there isn't much that we can't do. Give the callback
	 * with a fatal status.
	 */
	mutex_enter(&srp->sr_lock);
	queued = svp_remote_conn_queue(srp, sqp);
	mutex_exit(&srp->sr_lock);

	if (queued == B_FALSE)
		svp_shootdown_logr_cb(srp, SVP_S_FATAL, NULL, 0);
}

/* ARGSUSED */
void
svp_remote_dns_timer(void *unused)
{
	svp_remote_t *s;
	mutex_enter(&svp_remote_lock);
	for (s = avl_first(&svp_remote_tree); s != NULL;
	    s = AVL_NEXT(&svp_remote_tree, s)) {
		svp_host_queue(s);
	}
	mutex_exit(&svp_remote_lock);
}

void
svp_remote_resolved(svp_remote_t *srp, struct addrinfo *newaddrs)
{
	struct addrinfo *a;
	svp_conn_t *scp;
	int ngen;

	mutex_enter(&srp->sr_lock);
	srp->sr_gen++;
	ngen = srp->sr_gen;
	mutex_exit(&srp->sr_lock);

	for (a = newaddrs; a != NULL; a = a->ai_next) {
		struct in6_addr in6;
		struct in6_addr *addrp;

		if (a->ai_family != AF_INET && a->ai_family != AF_INET6)
			continue;

		if (a->ai_family == AF_INET) {
			struct sockaddr_in *v4;
			v4 = (struct sockaddr_in *)a->ai_addr;
			addrp = &in6;
			IN6_INADDR_TO_V4MAPPED(&v4->sin_addr, addrp);
		} else {
			struct sockaddr_in6 *v6;
			v6 = (struct sockaddr_in6 *)a->ai_addr;
			addrp = &v6->sin6_addr;
		}

		mutex_enter(&srp->sr_lock);
		for (scp = list_head(&srp->sr_conns); scp != NULL;
		    scp = list_next(&srp->sr_conns, scp)) {
			mutex_enter(&scp->sc_lock);
			if (bcmp(addrp, &scp->sc_addr,
			    sizeof (struct in6_addr)) == 0) {
				scp->sc_gen = ngen;
				mutex_exit(&scp->sc_lock);
				break;
			}
			mutex_exit(&scp->sc_lock);
		}

		/*
		 * We need to be careful in the assumptions that we make here,
		 * as there's a good chance that svp_conn_create will
		 * drop the svp_remote_t`sr_lock to kick off its effective event
		 * loop.
		 */
		if (scp == NULL)
			(void) svp_conn_create(srp, addrp);
		mutex_exit(&srp->sr_lock);
	}

	/*
	 * Now it's time to clean things up. We do not actively clean up the
	 * current connections that we have, instead allowing them to stay
	 * around assuming that they're still useful. Instead, we go through and
	 * purge the degraded list for anything that's from an older generation.
	 */
	mutex_enter(&srp->sr_lock);
	for (scp = list_head(&srp->sr_conns); scp != NULL;
	    scp = list_next(&srp->sr_conns, scp)) {
		boolean_t fall = B_FALSE;
		mutex_enter(&scp->sc_lock);
		if (scp->sc_gen < srp->sr_gen)
			fall = B_TRUE;
		mutex_exit(&scp->sc_lock);
		if (fall == B_TRUE)
			svp_conn_fallout(scp);
	}
	mutex_exit(&srp->sr_lock);
}

/*
 * This connection is in the process of being reset, we need to reassign all of
 * its queries to other places or mark them as fatal. Note that the first
 * connection was the one in flight when this failed. We always mark it as
 * failed to avoid trying to reset its state.
 */
void
svp_remote_reassign(svp_remote_t *srp, svp_conn_t *scp)
{
	boolean_t first = B_TRUE;
	assert(MUTEX_HELD(&srp->sr_lock));
	assert(MUTEX_HELD(&srp->sr_lock));
	svp_query_t *sqp;

	/*
	 * As we try to reassigning all of its queries, remove it from the list.
	 */
	list_remove(&srp->sr_conns, scp);

	while ((sqp = list_remove_head(&scp->sc_queries)) != NULL) {

		if (first == B_TRUE) {
			sqp->sq_status = SVP_S_FATAL;
			sqp->sq_func(sqp, sqp->sq_arg);
			continue;
		}

		sqp->sq_acttime = -1;

		/*
		 * We may want to maintain a queue of these for some time rather
		 * than just failing them all.
		 */
		if (svp_remote_conn_queue(srp, sqp) == B_FALSE) {
			sqp->sq_status = SVP_S_FATAL;
			sqp->sq_func(sqp, sqp->sq_arg);
		}
	}

	/*
	 * Now that we're done, go ahead and re-insert.
	 */
	list_insert_tail(&srp->sr_conns, scp);
}

void
svp_remote_degrade(svp_remote_t *srp, svp_degrade_state_t flag)
{
	int sf, nf;
	char buf[256];

	assert(MUTEX_HELD(&srp->sr_lock));

	if (flag == SVP_RD_ALL || flag == 0)
		libvarpd_panic("invalid flag passed to degrade");

	if ((flag & srp->sr_degrade) != 0) {
		return;
	}

	sf = ffs(srp->sr_degrade);
	nf = ffs(flag);
	srp->sr_degrade |= flag;
	if (sf == 0 || sf > nf) {
		svp_t *svp;
		svp_remote_mkfmamsg(srp, flag, buf, sizeof (buf));

		for (svp = avl_first(&srp->sr_tree); svp != NULL;
		    svp = AVL_NEXT(&srp->sr_tree, svp)) {
			libvarpd_fma_degrade(svp->svp_hdl, buf);
		}
	}
}

void
svp_remote_restore(svp_remote_t *srp, svp_degrade_state_t flag)
{
	int sf, nf;

	assert(MUTEX_HELD(&srp->sr_lock));
	sf = ffs(srp->sr_degrade);
	if ((srp->sr_degrade & flag) != flag)
		return;
	srp->sr_degrade &= ~flag;
	nf = ffs(srp->sr_degrade);

	/*
	 * If we're now empty, restore the device. If we still are degraded, but
	 * we now have a higher base than we used to, change the message.
	 */
	if (srp->sr_degrade == 0) {
		svp_t *svp;
		for (svp = avl_first(&srp->sr_tree); svp != NULL;
		    svp = AVL_NEXT(&srp->sr_tree, svp)) {
			libvarpd_fma_restore(svp->svp_hdl);
		}
	} else if (nf != sf) {
		svp_t *svp;
		char buf[256];

		svp_remote_mkfmamsg(srp, 1U << (nf - 1), buf, sizeof (buf));
		for (svp = avl_first(&srp->sr_tree); svp != NULL;
		    svp = AVL_NEXT(&srp->sr_tree, svp)) {
			libvarpd_fma_degrade(svp->svp_hdl, buf);
		}
	}
}

void
svp_remote_shootdown_vl3_cb(svp_query_t *sqp, void *arg)
{
	svp_shoot_vl3_t *squery = arg;
	svp_log_vl3_t *svl3 = squery->ssv_vl3;
	svp_sdlog_t *sdl = squery->ssv_log;

	if (sqp->sq_status == SVP_S_OK) {
		svp_t *svp, lookup;

		svp_remote_t *srp = sdl->sdl_remote;
		svp_vl3_ack_t *vl3a = (svp_vl3_ack_t *)sqp->sq_wdata;

		lookup.svp_vid = ntohl(svl3->svl3_vnetid);
		mutex_enter(&srp->sr_lock);
		if ((svp = avl_find(&srp->sr_tree, &lookup, NULL)) != NULL) {
			svp->svp_cb.scb_vl3_inject(svp, ntohs(svl3->svl3_vlan),
			    (struct in6_addr *)svl3->svl3_ip, vl3a->sl3a_mac,
			    NULL);
		}
		mutex_exit(&srp->sr_lock);

	}

	svp_shootdown_vl3_cb(sqp->sq_status, svl3, sdl);

	umem_free(squery, sizeof (svp_shoot_vl3_t));
}

void
svp_remote_shootdown_vl3(svp_remote_t *srp, svp_log_vl3_t *svl3,
    svp_sdlog_t *sdl)
{
	svp_shoot_vl3_t *squery;

	squery = umem_zalloc(sizeof (svp_shoot_vl3_t), UMEM_DEFAULT);
	if (squery == NULL) {
		svp_shootdown_vl3_cb(SVP_S_FATAL, svl3, sdl);
		return;
	}

	squery->ssv_vl3 = svl3;
	squery->ssv_log = sdl;
	squery->ssv_sock.sin6_family = AF_INET6;
	bcopy(svl3->svl3_ip, &squery->ssv_sock.sin6_addr,
	    sizeof (svl3->svl3_ip));
	svp_remote_vl3_logreq(srp, &squery->ssv_query, ntohl(svl3->svl3_vnetid),
	    (struct sockaddr *)&squery->ssv_sock, svp_remote_shootdown_vl3_cb,
	    squery);
}

void
svp_remote_shootdown_vl2(svp_remote_t *srp, svp_log_vl2_t *svl2)
{
	svp_t *svp, lookup;

	lookup.svp_vid = ntohl(svl2->svl2_vnetid);
	mutex_enter(&srp->sr_lock);
	if ((svp = avl_find(&srp->sr_tree, &lookup, NULL)) != NULL) {
		svp->svp_cb.scb_vl2_invalidate(svp, svl2->svl2_mac);
	}
	mutex_exit(&srp->sr_lock);
}

int
svp_remote_init(void)
{
	svp_idspace = id_space_create("svp_req_ids", 1, INT32_MAX);
	if (svp_idspace == NULL)
		return (errno);
	avl_create(&svp_remote_tree, svp_remote_comparator,
	    sizeof (svp_remote_t), offsetof(svp_remote_t, sr_gnode));
	svp_dns_timer.st_func = svp_remote_dns_timer;
	svp_dns_timer.st_arg = NULL;
	svp_dns_timer.st_oneshot = B_FALSE;
	svp_dns_timer.st_value = svp_dns_timer_rate;
	svp_timer_add(&svp_dns_timer);
	return (0);
}

void
svp_remote_fini(void)
{
	svp_timer_remove(&svp_dns_timer);
	avl_destroy(&svp_remote_tree);
	if (svp_idspace == NULL)
		id_space_destroy(svp_idspace);
}
