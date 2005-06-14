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

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>
#include <sys/fm/protocol.h>
#include <sys/sysmacros.h>
#include <sys/dumphdr.h>
#include <sys/dumpadm.h>

#include <libsysevent.h>
#include <libnvpair.h>
#include <alloca.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <door.h>

#undef MUTEX_HELD
#undef RW_READ_HELD
#undef RW_WRITE_HELD

#include <fmd_transport.h>
#include <fmd_thread.h>
#include <fmd_dispq.h>
#include <fmd_event.h>
#include <fmd_conf.h>
#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd_string.h>
#include <fmd_log.h>
#include <fmd_module.h>
#include <fmd_scheme.h>
#include <fmd_protocol.h>
#include <fmd_ctl.h>

#include <fmd.h>

static void
fmd_transport_server(void *dip)
{
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	(void) pthread_mutex_lock(&fmd.d_xprt_lock);

	while (fmd.d_xprt_wait != 0) {
		TRACE((FMD_DBG_XPRT, "door server waiting to be unpaused"));
		(void) pthread_cond_wait(&fmd.d_xprt_cv, &fmd.d_xprt_lock);
	}

	(void) pthread_mutex_unlock(&fmd.d_xprt_lock);
	TRACE((FMD_DBG_XPRT, "door server starting for dip %p", dip));
	(void) door_return(NULL, 0, NULL, 0);
	TRACE((FMD_DBG_XPRT, "door server stopping for dip %p", dip));
}

static void
fmd_transport_server_create(door_info_t *dip)
{
	if (fmd_thread_create(fmd.d_rmod, fmd_transport_server, dip) == NULL)
		fmd_panic("failed to create server for door %p", (void *)dip);
}

/*
 * Under extreme low-memory situations where we cannot event unpack the event,
 * we can request that the transport redeliver the event later by returning
 * EAGAIN.  If we do this too many times, the transport will drop the event.
 * Rather than keeping state per-event, we simply attempt a garbage-collect,
 * bump a retry statistic, and return EAGAIN hoping that enough free memory
 * will be available by the time the event is redelivered by the transport.
 */
static int
fmd_transport_again(sysevent_t *sep, fmd_t *dp)
{
	fmd_modhash_tryapply(fmd.d_mod_hash, fmd_module_trygc);
	fmd_scheme_hash_trygc(fmd.d_schemes);

	TRACE((FMD_DBG_XPRT, "retrying sysevent %p", (void *)sep));

	(void) pthread_mutex_lock(&dp->d_stats_lock);
	dp->d_stats->ds_retried.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&dp->d_stats_lock);

	return (EAGAIN);
}

static int
fmd_transport_event(sysevent_t *sep, fmd_t *dp)
{
	uint64_t seq = sysevent_get_seq(sep);
	fmd_event_t *ep;
	nvlist_t *nvl;
	hrtime_t hrt;
	char *class;
	int isproto;

	(void) pthread_mutex_lock(&dp->d_stats_lock);
	dp->d_stats->ds_received.fmds_value.ui64++;
	(void) pthread_mutex_unlock(&dp->d_stats_lock);

	if (strcmp(sysevent_get_class_name(sep), EC_FM) != 0) {
		fmd_error(EFMD_XPRT_CLASS, "discarding event 0x%llx: unexpected"
		    " transport class %s\n", seq, sysevent_get_class_name(sep));

		(void) pthread_mutex_lock(&dp->d_stats_lock);
		dp->d_stats->ds_discarded.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&dp->d_stats_lock);

		return (0);
	}

	if (sysevent_get_attr_list(sep, &nvl) != 0) {
		if (errno == EAGAIN || errno == ENOMEM)
			return (fmd_transport_again(sep, dp));

		fmd_error(EFMD_XPRT_INVAL, "discarding event 0x%llx: missing "
		    "or invalid payload", seq);

		(void) pthread_mutex_lock(&dp->d_stats_lock);
		dp->d_stats->ds_discarded.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&dp->d_stats_lock);

		return (0);
	}

	if (nvlist_lookup_string(nvl, FM_CLASS, &class) != 0) {
		fmd_error(EFMD_XPRT_INVAL, "discarding event 0x%llx: missing "
		    "required \"%s\" payload element", seq, FM_CLASS);

		(void) pthread_mutex_lock(&dp->d_stats_lock);
		dp->d_stats->ds_discarded.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&dp->d_stats_lock);

		nvlist_free(nvl);
		return (0);
	}

	/*
	 * If we are using the native system clock, we can get a tighter event
	 * time bound by asking sysevent when the event was enqueued.  If we're
	 * using simulated clocks, this time has no meaning to us: use HRT_NOW.
	 */
	if (dp->d_clockops == &fmd_timeops_native)
		sysevent_get_time(sep, &hrt);
	else
		hrt = FMD_HRT_NOW;

	if ((isproto = strncmp(class, FMD_RSRC_CLASS, FMD_RSRC_CLASS_LEN)) != 0)
		ep = fmd_event_create(FMD_EVT_PROTOCOL, hrt, nvl, class);
	else
		ep = fmd_event_create(FMD_EVT_CTL, hrt, nvl, fmd_ctl_init(nvl));

	(void) pthread_rwlock_rdlock(&dp->d_log_lock);
	fmd_log_append(dp->d_errlog, ep, NULL);
	(void) pthread_rwlock_unlock(&dp->d_log_lock);

	if (isproto)
		fmd_dispq_dispatch(dp->d_disp, ep, class);
	else
		fmd_modhash_dispatch(dp->d_mod_hash, ep);

	return (0);
}

/*
 * Bind to the sysevent channel we use for listening for error events and then
 * subscribe to appropriate events received over this channel.  The effect of
 * performing a subscribe is that a door_create() occurs inside the library,
 * so we first call door_server_create() and install our own custom door server
 * create callback which performs application-specific thread initialization.
 */
void
fmd_transport_init(void)
{
	const char *errchan, *sid, *class;

	(void) fmd_conf_getprop(fmd.d_conf, "errchan", &errchan);
	(void) fmd_conf_getprop(fmd.d_conf, "xprt.sid", &sid);
	(void) fmd_conf_getprop(fmd.d_conf, "xprt.class", &class);

	if (class == NULL)
		class = EC_ALL; /* default is to subscribe to all events */

	if (errchan == NULL || sid == NULL) {
		fmd_error(EFMD_EXIT, "errchan and xprt_sid properties must "
		    "be defined to initialize event transport\n");
	}

	(void) door_server_create(fmd_transport_server_create);

	if ((errno = sysevent_evc_bind(errchan, &fmd.d_xprt_chan,
	    EVCH_CREAT | EVCH_HOLD_PEND)) != 0) {
		fmd_error(EFMD_EXIT, "failed to bind to event "
		    "transport channel %s", errchan);
	}

	if ((errno = sysevent_evc_subscribe(fmd.d_xprt_chan,
	    sid, class, (int (*)())fmd_transport_event, &fmd,
	    EVCH_SUB_KEEP | EVCH_SUB_DUMP)) == 0) {
		fmd_dprintf(FMD_DBG_XPRT, "transport '%s' open\n", errchan);
		return; /* subscription succeded; we're done */
	}

	if (errno == EEXIST) {
		fmd_error(EFMD_EXIT, "another fault management daemon "
		    "is active on event transport channel %s\n", errchan);
	} else {
		fmd_error(EFMD_EXIT, "failed to subscribe to %s events "
		    "on event transport channel %s", class, errchan);
	}
}

/*
 * Close the channel by unsubscribing and unbinding.  We only do this when a
 * a non-default channel has been selected.  If we're using FM_ERROR_CHAN,
 * the system default, we do *not* want to unsubscribe because the kernel will
 * remove the subscriber queue and any events published in our absence will
 * therefore be lost.  This scenario may occur when, for example, fmd is sent
 * a SIGTERM by init(1M) during reboot but an error is detected and makes it
 * into the sysevent channel queue before init(1M) manages to call uadmin(2).
 */
void
fmd_transport_fini(void)
{
	const char *errchan, *sid;
	static evchan_t *evc;

	(void) fmd_conf_getprop(fmd.d_conf, "errchan", &errchan);
	(void) fmd_conf_getprop(fmd.d_conf, "xprt.sid", &sid);

	evc = fmd.d_xprt_chan; /* save in BSS so ::findleaks won't kvetch */

	if (strcmp(errchan, FM_ERROR_CHAN) != 0) {
		sysevent_evc_unsubscribe(evc, sid);
		sysevent_evc_unbind(evc);
	}
}

/*
 * Checksum algorithm used by the dump transport for verifying the content of
 * error reports saved on the dump device (copy of the kernel's checksum32()).
 */
uint32_t
fmd_transport_checksum(void *cp_arg, size_t length)
{
	uchar_t *cp, *ep;
	uint32_t sum = 0;

	for (cp = cp_arg, ep = cp + length; cp < ep; cp++)
		sum = ((sum >> 1) | (sum << 31)) + *cp;

	return (sum);
}

void
fmd_transport_replay(void)
{
	char *dumpdev = NULL;
	off64_t off, off0;
	int fd, err;

	/*
	 * Determine the appropriate dump device to use for replaying pending
	 * error reports.  If the xprt.device property is NULL (default), we
	 * open and query /dev/dump to determine the current dump device.
	 */
	if (fmd_conf_getprop(fmd.d_conf,
	    "xprt.device", &dumpdev) != 0 || dumpdev == NULL) {
		if ((fd = open("/dev/dump", O_RDONLY)) == -1) {
			fmd_error(EFMD_XPRT_OPEN, "failed to open /dev/dump "
			    "to locate dump device for event replay");
			return;
		}

		dumpdev = alloca(PATH_MAX);
		err = ioctl(fd, DIOCGETDEV, dumpdev);
		(void) close(fd);

		if (err == -1) {
			if (errno != ENODEV) {
				fmd_error(EFMD_XPRT_OPEN, "failed to obtain "
				    "path to dump device for event replay");
			}
			return;
		}
	}

	if (strcmp(dumpdev, "/dev/null") == 0)
		return; /* return silently and skip replay for /dev/null */

	/*
	 * Open the appropriate device and then determine the offset of the
	 * start of the ereport dump region located at the end of the device.
	 */
	if ((fd = open64(dumpdev, O_RDWR | O_DSYNC)) == -1) {
		fmd_error(EFMD_XPRT_OPEN, "failed to open dump transport %s "
		    "(pending events will not be replayed)", dumpdev);
		return;
	}

	off = DUMP_OFFSET + DUMP_LOGSIZE + DUMP_ERPTSIZE;
	off = off0 = lseek64(fd, -off, SEEK_END) & -DUMP_OFFSET;

	if (off == (off64_t)-1LL) {
		fmd_error(EFMD_XPRT_OPEN, "failed to seek dump transport %s "
		    "(pending events will not be replayed)", dumpdev);
		(void) close(fd);
		return;
	}

	/*
	 * The ereport dump region is a sequence of erpt_dump_t headers each of
	 * which is followed by packed nvlist data.  We iterate over them in
	 * order, unpacking and dispatching each one to our dispatch queue.
	 */
	for (;;) {
		char nvbuf[ERPT_DATA_SZ];
		uint32_t chksum;
		erpt_dump_t ed;
		nvlist_t *nvl;

		fmd_event_t *ep = NULL;
		fmd_timeval_t ftv, tod;
		char *class, *p;
		hrtime_t hrt;
		uint64_t ena;

		if (pread64(fd, &ed, sizeof (ed), off) != sizeof (ed)) {
			fmd_error(EFMD_XPRT_READ, "failed to read from dump "
			    "transport %s (pending events lost)", dumpdev);
			break;
		}

		if (ed.ed_magic == 0 && ed.ed_size == 0)
			break; /* end of list: all zero */

		if (ed.ed_magic == 0) {
			off += sizeof (ed) + ed.ed_size;
			continue; /* continue searching */
		}

		if (ed.ed_magic != ERPT_MAGIC) {
			/*
			 * Stop reading silently if the first record has the
			 * wrong magic number; this likely indicates that we
			 * rebooted from non-FMA bits or paged over the dump.
			 */
			if (off == off0)
				break;

			fmd_error(EFMD_XPRT_INVAL, "invalid dump transport "
			    "record at %llx (magic number %x, expected %x)\n",
			    (u_longlong_t)off, ed.ed_magic, ERPT_MAGIC);
			break;
		}

		if (ed.ed_size > ERPT_DATA_SZ) {
			fmd_error(EFMD_XPRT_INVAL, "invalid dump transport "
			    "record at %llx size (%u exceeds limit)\n",
			    (u_longlong_t)off, ed.ed_size);
			break;
		}

		if (pread64(fd, nvbuf, ed.ed_size,
		    off + sizeof (ed)) != ed.ed_size) {
			fmd_error(EFMD_XPRT_READ, "failed to read dump "
			    "transport event (offset %llx)", (u_longlong_t)off);

			(void) pthread_mutex_lock(&fmd.d_stats_lock);
			fmd.d_stats->ds_lost.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&fmd.d_stats_lock);

			goto next;
		}

		if ((chksum = fmd_transport_checksum(nvbuf,
		    ed.ed_size)) != ed.ed_chksum) {
			fmd_error(EFMD_XPRT_INVAL, "dump transport event at "
			    "offset %llx is corrupt (checksum %x != %x)\n",
			    (u_longlong_t)off, chksum, ed.ed_chksum);

			(void) pthread_mutex_lock(&fmd.d_stats_lock);
			fmd.d_stats->ds_lost.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&fmd.d_stats_lock);

			goto next;
		}

		if ((err = nvlist_xunpack(nvbuf,
		    ed.ed_size, &nvl, &fmd.d_nva)) != 0) {
			fmd_error(EFMD_XPRT_INVAL, "failed to unpack dump "
			    "transport event at offset %llx: %s\n",
			    (u_longlong_t)off, fmd_strerror(err));

			(void) pthread_mutex_lock(&fmd.d_stats_lock);
			fmd.d_stats->ds_lost.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&fmd.d_stats_lock);

			goto next;
		}

		if (nvlist_lookup_string(nvl, FM_CLASS, &class) != 0) {
			fmd_error(EFMD_XPRT_INVAL, "discarding dump transport "
			    "event at offset %llx: missing required \"%s\" "
			    "payload element\n", (u_longlong_t)off, FM_CLASS);

			(void) pthread_mutex_lock(&fmd.d_stats_lock);
			fmd.d_stats->ds_discarded.fmds_value.ui64++;
			(void) pthread_mutex_unlock(&fmd.d_stats_lock);

			nvlist_free(nvl);
			goto next;
		}

		/*
		 * If ed_hrt_nsec is set it contains the gethrtime() value from
		 * when the event was originally enqueued for the transport.
		 * If it is zero, we use the weaker bound ed_hrt_base instead.
		 */
		if (ed.ed_hrt_nsec != 0)
			hrt = ed.ed_hrt_nsec;
		else
			hrt = ed.ed_hrt_base;

		/*
		 * If this is an FMA protocol event of class "ereport.*" that
		 * contains valid ENA, we can improve the precision of 'hrt'.
		 */
		if ((p = strchr(class, '.')) != NULL && strncmp(class,
		    FM_EREPORT_CLASS, (size_t)(p - class)) == 0 &&
		    nvlist_lookup_uint64(nvl, FM_EREPORT_ENA, &ena) == 0)
			hrt = fmd_time_ena2hrt(hrt, ena);

		/*
		 * Now convert 'hrt' to an adjustable TOD based on the values
		 * in ed_tod_base which correspond to one another and are
		 * sampled before reboot using the old gethrtime() clock.
		 * fmd_event_recreate() will use this TOD value to re-assign
		 * the event an updated gethrtime() value based on the current
		 * value of the non-adjustable gethrtime() clock.  Phew.
		 */
		tod.ftv_sec = ed.ed_tod_base.sec;
		tod.ftv_nsec = ed.ed_tod_base.nsec;
		fmd_time_hrt2tod(ed.ed_hrt_base, &tod, hrt, &ftv);

		ep = fmd_event_recreate(FMD_EVT_PROTOCOL,
		    &ftv, nvl, class, NULL, 0, 0);

		(void) pthread_rwlock_rdlock(&fmd.d_log_lock);
		fmd_log_append(fmd.d_errlog, ep, NULL);
		(void) pthread_rwlock_unlock(&fmd.d_log_lock);

		(void) pthread_mutex_lock(&fmd.d_stats_lock);
		fmd.d_stats->ds_replayed.fmds_value.ui64++;
		(void) pthread_mutex_unlock(&fmd.d_stats_lock);
next:
		/*
		 * Reset the magic number for the event record to zero so that
		 * we do not replay the same event multiple times.
		 */
		ed.ed_magic = 0;

		if (pwrite64(fd, &ed, sizeof (ed), off) != sizeof (ed)) {
			fmd_error(EFMD_XPRT_MARK, "failed to mark dump "
			    "transport event (offset %llx)", (u_longlong_t)off);
		}

		if (ep != NULL)
			fmd_dispq_dispatch(fmd.d_disp, ep, class);

		off += sizeof (ed) + ed.ed_size;
	}

	(void) close(fd);
}
