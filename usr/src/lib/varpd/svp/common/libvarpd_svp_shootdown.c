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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Shootdown processing logic.
 *
 * For more information, see the big theory statement in
 * lib/varpd/svp/common/libvarpd_svp.c.
 */

#include <umem.h>
#include <sys/uuid.h>
#include <assert.h>
#include <strings.h>
#include <errno.h>
#include <sys/debug.h>

#include <libvarpd_provider.h>
#include <libvarpd_svp.h>

/*
 * When we've determined that there's nothing left for us to do, then we go
 * ahead and wait svp_shootdown_base seconds + up to an additional
 * svp_shootdown_base seconds before asking again. However, if there is actually
 * some work going on, just use the svp_shootdown_cont time.
 */
static int svp_shootdown_base = 5;
static int svp_shootdown_cont = 1;

/*
 * These are sizes for our logack and logrm buffers. The sizing of the shootdown
 * buffere would give us approximately 18 or so VL3 entries and 32 VL2 entries
 * or some combination thereof. While it's a bit of overkill, we just use the
 * same sized buffer for the list of uuids that we pass to remove log entries
 * that we've acted upon.
 */
static int svp_shootdown_buf = 1024;

static void
svp_shootdown_schedule(svp_sdlog_t *sdl, boolean_t cont)
{
	assert(MUTEX_HELD(&sdl->sdl_lock));

	if (cont == B_TRUE) {
		sdl->sdl_timer.st_value = svp_shootdown_cont;
	} else {
		sdl->sdl_timer.st_value = svp_shootdown_base +
		    arc4random_uniform(svp_shootdown_base + 1);
	}
	svp_timer_add(&sdl->sdl_timer);
}

void
svp_shootdown_lrm_cb(svp_remote_t *srp, svp_status_t status)
{
	svp_sdlog_t *sdl = &srp->sr_shoot;

	mutex_enter(&sdl->sdl_lock);
	sdl->sdl_flags &= ~SVP_SD_RUNNING;
	svp_shootdown_schedule(sdl, B_TRUE);
	mutex_exit(&sdl->sdl_lock);

	if (status != SVP_S_OK) {
		(void) bunyan_warn(svp_bunyan, "SVP_R_LOG_RM failed",
		    BUNYAN_T_STRING, "remote_host", srp->sr_hostname,
		    BUNYAN_T_INT32, "remote_port", srp->sr_rport,
		    BUNYAN_T_INT32, "status", status,
		    BUNYAN_T_END);
	}
}

static void
svp_shootdown_ref(svp_sdlog_t *sdl)
{
	mutex_enter(&sdl->sdl_lock);
	sdl->sdl_ref++;
	mutex_exit(&sdl->sdl_lock);
}

static void
svp_shootdown_rele(svp_sdlog_t *sdl)
{
	svp_lrm_req_t *svrr = sdl->sdl_logrm;
	boolean_t next;

	mutex_enter(&sdl->sdl_lock);
	VERIFY(sdl->sdl_ref > 0);
	sdl->sdl_ref--;
	if (sdl->sdl_ref > 0) {
		mutex_exit(&sdl->sdl_lock);
		return;
	}

	/*
	 * At this point we know that we hold the last reference, therefore it's
	 * safe for us to go ahead and clean up and move on and attempt to
	 * deliver the reply. We always deliver the reply by going through the
	 * timer. This can be rather important as the final reference may be
	 * coming through a failed query and it's not always safe for us to
	 * callback into the remote routines from this context.
	 *
	 * We should only do this if we have a non-zero number of entries to
	 * take down.
	 */
	sdl->sdl_flags &= ~SVP_SD_RUNNING;
	if (svrr->svrr_count > 0) {
		sdl->sdl_flags |= SVP_SD_DORM;
		next = B_TRUE;
	} else {
		next = B_FALSE;
	}
	svp_shootdown_schedule(sdl, next);
	mutex_exit(&sdl->sdl_lock);
}

/*
 * This is a callback used to indicate that the VL3 lookup has completed and an
 * entry, if any, has been injected. If the command succeeded, eg. we got that
 * the status was OK or that it was not found, then we will add it to he list to
 * shoot down. Otherwise, there's nothing else for us to really do here.
 */
void
svp_shootdown_vl3_cb(svp_status_t status, svp_log_vl3_t *vl3, svp_sdlog_t *sdl)
{
	svp_lrm_req_t *svrr = sdl->sdl_logrm;

	mutex_enter(&sdl->sdl_lock);
	if (status == SVP_S_OK || status == SVP_S_NOTFOUND) {
		bcopy(vl3->svl3_id, &svrr->svrr_ids[svrr->svrr_count * 16],
		    UUID_LEN);
		svrr->svrr_count++;
	}
	mutex_exit(&sdl->sdl_lock);

	svp_shootdown_rele(sdl);
}

static int
svp_shootdown_logr_shoot(void *data, svp_log_type_t type, void *arg)
{
	svp_sdlog_t *sdl = arg;
	svp_remote_t *srp = sdl->sdl_remote;
	svp_lrm_req_t *svrr = sdl->sdl_logrm;

	if (type != SVP_LOG_VL2 && type != SVP_LOG_VL3)
		libvarpd_panic("encountered unknown type: %d\n", type);

	if (type == SVP_LOG_VL2) {
		svp_log_vl2_t *svl2 = data;
		svp_remote_shootdown_vl2(srp, svl2);
		mutex_enter(&sdl->sdl_lock);
		bcopy(svl2->svl2_id, &svrr->svrr_ids[svrr->svrr_count * 16],
		    UUID_LEN);
		svrr->svrr_count++;
		mutex_exit(&sdl->sdl_lock);
	} else {
		svp_log_vl3_t *svl3 = data;

		/* Take a hold for the duration of this request */
		svp_shootdown_ref(sdl);
		svp_remote_shootdown_vl3(srp, svl3, sdl);
	}

	return (0);
}

static int
svp_shootdown_logr_count(void *data, svp_log_type_t type, void *arg)
{
	uint_t *u = arg;
	*u = *u + 1;
	return (0);
}


static int
svp_shootdown_logr_iter(svp_remote_t *srp, void *buf, size_t len,
    int (*cb)(void *, svp_log_type_t, void *), void *arg)
{
	int ret;
	off_t cboff = 0;
	uint32_t *typep, type;
	svp_log_vl2_t *svl2;
	svp_log_vl3_t *svl3;

	/* Adjust for initial status word */
	assert(len >= sizeof (uint32_t));
	len -= sizeof (uint32_t);
	cboff += sizeof (uint32_t);

	while (len > 0) {
		size_t opsz;

		if (len < sizeof (uint32_t)) {
			(void) bunyan_warn(svp_bunyan,
			    "failed to get initial shootdown tag",
			    BUNYAN_T_STRING, "remote_host", srp->sr_hostname,
			    BUNYAN_T_INT32, "remote_port", srp->sr_rport,
			    BUNYAN_T_INT32, "response_size", cboff + len,
			    BUNYAN_T_INT32, "response_offset", cboff,
			    BUNYAN_T_END);
			return (-1);
		}

		typep = buf + cboff;
		type = ntohl(*typep);
		if (type == SVP_LOG_VL2) {
			opsz = sizeof (svp_log_vl2_t);
			if (len < opsz) {
				(void) bunyan_warn(svp_bunyan,
				    "not enough data for svp_log_vl2_t",
				    BUNYAN_T_STRING, "remote_host",
				    srp->sr_hostname,
				    BUNYAN_T_INT32, "remote_port",
				    srp->sr_rport,
				    BUNYAN_T_INT32, "response_size",
				    cboff + len,
				    BUNYAN_T_INT32, "response_offset", cboff,
				    BUNYAN_T_END);
				return (-1);
			}
			svl2 = (void *)typep;
			if ((ret = cb(svl2, type, arg)) != 0)
				return (ret);
		} else if (type == SVP_LOG_VL3) {

			opsz = sizeof (svp_log_vl3_t);
			if (len < opsz) {
				(void) bunyan_warn(svp_bunyan,
				    "not enough data for svp_log_vl3_t",
				    BUNYAN_T_STRING, "remote_host",
				    srp->sr_hostname,
				    BUNYAN_T_INT32, "remote_port",
				    srp->sr_rport,
				    BUNYAN_T_INT32, "response_size",
				    cboff + len,
				    BUNYAN_T_INT32, "response_offset", cboff,
				    BUNYAN_T_END);
				return (-1);
			}
			svl3 = (void *)typep;
			if ((ret = cb(svl3, type, arg)) != 0)
				return (ret);
		} else {
			(void) bunyan_warn(svp_bunyan,
			    "unknown log structure type",
			    BUNYAN_T_STRING, "remote_host",
			    srp->sr_hostname,
			    BUNYAN_T_INT32, "remote_port", srp->sr_rport,
			    BUNYAN_T_INT32, "response_size", cboff + len,
			    BUNYAN_T_INT32, "response_offset", cboff,
			    BUNYAN_T_INT32, "structure_type", type,
			    BUNYAN_T_END);
			return (-1);
		}
		len -= opsz;
		cboff += opsz;
	}

	return (0);
}

void
svp_shootdown_logr_cb(svp_remote_t *srp, svp_status_t status, void *cbdata,
    size_t cbsize)
{
	uint_t count;
	svp_sdlog_t *sdl = &srp->sr_shoot;

	if (status != SVP_S_OK) {
		(void) bunyan_warn(svp_bunyan,
		    "log request not OK",
		    BUNYAN_T_STRING, "remote_host", srp->sr_hostname,
		    BUNYAN_T_INT32, "remote_port", srp->sr_rport,
		    BUNYAN_T_INT32, "response_size", cbsize,
		    BUNYAN_T_INT32, "status", status,
		    BUNYAN_T_END);
		mutex_enter(&sdl->sdl_lock);
		sdl->sdl_flags &= ~SVP_SD_RUNNING;
		svp_shootdown_schedule(sdl, B_FALSE);
		mutex_exit(&sdl->sdl_lock);
		return;
	}

	/*
	 * First go ahead and count the number of entries. This effectively
	 * allows us to validate that all the data is valid, if this fails, then
	 * we fail the request.
	 */
	count = 0;
	if ((svp_shootdown_logr_iter(srp, cbdata, cbsize,
	    svp_shootdown_logr_count, &count)) != 0) {
		mutex_enter(&sdl->sdl_lock);
		sdl->sdl_flags &= ~SVP_SD_RUNNING;
		svp_shootdown_schedule(sdl, B_FALSE);
		mutex_exit(&sdl->sdl_lock);
		return;
	}

	/*
	 * If we have no entries, then we're also done.
	 */
	if (count == 0) {
		mutex_enter(&sdl->sdl_lock);
		sdl->sdl_flags &= ~SVP_SD_RUNNING;
		svp_shootdown_schedule(sdl, B_FALSE);
		mutex_exit(&sdl->sdl_lock);
		return;
	}

	/*
	 * We have work to do. Because we may have asynchronous VL3 tasks, we're
	 * going to first grab a reference before we do the iteration. Then, for
	 * each asynchronous VL3 request we make, that'll also grab a hold. Once
	 * we're done with the iteration, we'll drop our hold. If that's the
	 * last one, it'll move on accordingly.
	 */
	svp_shootdown_ref(sdl);
	bzero(sdl->sdl_logrm, svp_shootdown_buf);

	/*
	 * If this fails, we're going to determine what to do next based on the
	 * number of entries that were entered into the log removal. At this
	 * point success or failure don't really look different, all it changes
	 * is how many entries we have to remove.
	 */
	(void) svp_shootdown_logr_iter(srp, cbdata, cbsize,
	    svp_shootdown_logr_shoot, sdl);

	/*
	 * Now that we're done with our work, release the hold. If we don't have
	 * any vl3 tasks outstanding, this'll trigger the next phase of the log
	 * removals.
	 */
	svp_shootdown_rele(sdl);
}

static void
svp_shootdown_timer(void *arg)
{
	svp_sdlog_t *sdl = arg;
	svp_remote_t *srp = sdl->sdl_remote;
	boolean_t init = B_TRUE;

	mutex_enter(&sdl->sdl_lock);

	/*
	 * If we've been asked to quiesce, we're done.
	 */
	if ((sdl->sdl_flags & SVP_SD_QUIESCE) != 0) {
		mutex_exit(&sdl->sdl_lock);
		return;
	}

	/*
	 * We shouldn't be able to have ourselves currently be running and reach
	 * here. If that's the case, we should immediately panic.
	 */
	if ((sdl->sdl_flags & SVP_SD_RUNNING) != 0) {
		libvarpd_panic("remote %p shootdown timer fired while still "
		    "running", srp);
	}

	if ((sdl->sdl_flags & SVP_SD_DORM) != 0) {
		sdl->sdl_flags &= ~SVP_SD_DORM;
		init = B_FALSE;
	}

	sdl->sdl_flags |= SVP_SD_RUNNING;
	mutex_exit(&sdl->sdl_lock);

	if (init == B_FALSE) {
		svp_lrm_req_t *svrr = sdl->sdl_logrm;

		bzero(&sdl->sdl_query, sizeof (svp_query_t));
		svp_remote_lrm_request(sdl->sdl_remote, &sdl->sdl_query, svrr,
		    sizeof (*svrr) + 16 * svrr->svrr_count);
	} else {
		bzero(&sdl->sdl_query, sizeof (svp_query_t));
		svp_remote_log_request(srp, &sdl->sdl_query, sdl->sdl_logack,
		    svp_shootdown_buf);
	}
}

void
svp_shootdown_fini(svp_remote_t *srp)
{
	svp_sdlog_t *sdl = &srp->sr_shoot;

	mutex_enter(&sdl->sdl_lock);
	sdl->sdl_flags |= SVP_SD_QUIESCE;
	mutex_exit(&sdl->sdl_lock);

	svp_timer_remove(&sdl->sdl_timer);

	mutex_enter(&sdl->sdl_lock);

	/*
	 * Normally svp_timer_remove would be enough. However, the query could
	 * have been put out again outside of the svp_timer interface. Therefore
	 * we still need to check for SVP_SD_RUNNING.
	 */
	while (sdl->sdl_flags & SVP_SD_RUNNING)
		(void) cond_wait(&sdl->sdl_cond, &sdl->sdl_lock);
	mutex_exit(&sdl->sdl_lock);

	umem_free(sdl->sdl_logack, svp_shootdown_buf);
	umem_free(sdl->sdl_logrm, svp_shootdown_buf);
	sdl->sdl_logack = NULL;
	sdl->sdl_logrm = NULL;
	(void) cond_destroy(&sdl->sdl_cond);
	(void) mutex_destroy(&sdl->sdl_lock);
}

void
svp_shootdown_start(svp_remote_t *srp)
{
	svp_sdlog_t *sdl = &srp->sr_shoot;

	mutex_enter(&sdl->sdl_lock);
	svp_shootdown_schedule(sdl, B_FALSE);
	mutex_exit(&sdl->sdl_lock);
}

int
svp_shootdown_init(svp_remote_t *srp)
{
	int ret;
	svp_sdlog_t *sdl = &srp->sr_shoot;
	if ((ret = mutex_init(&sdl->sdl_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL)) != 0)
		return (ret);

	if ((ret = cond_init(&sdl->sdl_cond, USYNC_THREAD, NULL)) != 0) {
		(void) mutex_destroy(&sdl->sdl_lock);
		return (ret);
	}

	if ((sdl->sdl_logack = umem_alloc(svp_shootdown_buf, UMEM_DEFAULT)) ==
	    NULL) {
		ret = errno;
		(void) cond_destroy(&sdl->sdl_cond);
		(void) mutex_destroy(&sdl->sdl_lock);
		return (ret);
	}

	if ((sdl->sdl_logrm = umem_alloc(svp_shootdown_buf, UMEM_DEFAULT)) ==
	    NULL) {
		ret = errno;
		umem_free(sdl->sdl_logack, svp_shootdown_buf);
		(void) cond_destroy(&sdl->sdl_cond);
		(void) mutex_destroy(&sdl->sdl_lock);
		return (ret);
	}

	sdl->sdl_remote = srp;
	sdl->sdl_timer.st_oneshot = B_TRUE;
	sdl->sdl_timer.st_func = svp_shootdown_timer;
	sdl->sdl_timer.st_arg = sdl;

	return (0);
}
