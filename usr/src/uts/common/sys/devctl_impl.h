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

#ifndef	_SYS_DEVCTL_IMPL_H
#define	_SYS_DEVCTL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * /etc/devices/devid_cache
 * Leave some padding for easy extension in the future
 */

#define	NVPF_HDR_MAGIC		0xdeb1dcac
#define	NVPF_HDR_VERSION	1
#define	NVPF_HDR_SIZE		128

typedef struct nvpacked_file_hdr {
	union {
		struct nvfp_hdr {
			uint32_t	magic;
			int32_t		version;
			int64_t		size;
			uint16_t	hdr_chksum;
			uint16_t	chksum;
		} nvpf;
		uchar_t		nvpf_pad[NVPF_HDR_SIZE];
	} un;
} nvpf_hdr_t;

#define	nvpf_magic		un.nvpf.magic
#define	nvpf_version		un.nvpf.version
#define	nvpf_size		un.nvpf.size
#define	nvpf_hdr_chksum		un.nvpf.hdr_chksum
#define	nvpf_chksum		un.nvpf.chksum

/*
 * The top-level nvpair identifiers in the
 * /etc/devices/devid_cache nvlist format
 */
#define	DP_DEVID_ID		"devid"


typedef struct nvp_list {
	char		*nvp_devpath;
	int		nvp_flags;
	dev_info_t	*nvp_dip;
	ddi_devid_t	nvp_devid;
	struct nvp_list	*nvp_next;
	struct nvp_list	*nvp_prev;
} nvp_list_t;

/*
 * nvp_flags
 */
#define	NVP_DEVID_REGISTERED	0x01	/* devid registered on this boot */
#define	NVP_DEVID_DIP		0x02	/* devinfo valid for this devid */


#ifdef	_KERNEL

/*
 * Descriptor used for kernel-level file i/o
 */
typedef struct kfile {
	struct vnode	*kf_vp;
	int		kf_vnflags;
	char		*kf_fname;
	offset_t	kf_fpos;
	int		kf_state;
} kfile_t;

/*
 * File descriptor for files in the nvlist format
 */
typedef struct nvfiledesc {
	char		*nvf_name;
	int		nvf_flags;
	nvp_list_t	*nvf_list;
	nvp_list_t	*nvf_tail;
	krwlock_t	nvf_lock;
} nvfd_t;


/*
 * Discovery refers to the heroic effort made to discover a device which
 * cannot be accessed.  Discovery involves walking the entire device tree
 * attaching all possible disk instances, to search for the device referenced
 * by a devid.  Obviously, full device discovery is something to be avoided
 * where at all possible.  Note that simply invoking devfsadm(1M) is
 * equivalent to running full discovery at the devid cache level.
 *
 * Reasons why a disk may not be accessible:
 *	disk powered off
 *	disk removed or cable disconnected
 *	disk or adapter broken
 *
 * Note that discovery is not needed and cannot succeed in any of these
 * cases.
 *
 * When discovery may succeed:
 *	Discovery will result in success when a device has been moved
 *	to a different address.  Note that it's recommended that
 *	devfsadm(1M) be invoked (no arguments required) whenever a system's
 *	h/w configuration has been updated.  Alternatively, a
 *	reconfiguration boot can be used to accomplish the same result.
 *
 * Note that discovery is not necessary to be able to correct an access
 * failure for a device which was powered off.  Assuming the cache has an
 * entry for such a device, simply powering it on should permit the system
 * to access it.  If problems persist after powering it on, invoke devfsadm(1M).
 *
 * Tunables
 *
 * devid_discovery_boot (default 1)
 *	Number of times discovery will be attempted prior to mounting root.
 *	Must be at least once to recover from corrupted or missing
 *	devid cache backing store.  Probably there's no reason to ever
 * 	set this to greater than one as a missing device will remain
 *	unavailable no matter how often the system searches for it.
 *
 * devid_discovery_postboot (default 1)
 *	Number of times discovery will be attempted after mounting root.
 *	This must be performed at least once to discover any devices
 *	needed after root is mounted which may have been powered
 *	off and moved before booting.
 *	Setting this to a larger positive number will introduce
 *	some inconsistency in system operation.  Searching for a device
 *	will take an indeterminate amount of time, sometimes slower,
 *	sometimes faster.  In addition, the system will sometimes
 *	discover a newly powered on device, sometimes it won't.
 *	Use of this option is not therefore recommended.
 *
 * devid_discovery_postboot_always (default 0)
 *	Set to 1, the system will always attempt full discovery.
 *
 * devid_discovery_secs (default 0)
 *	Set to a positive value, the system will attempt full discovery
 *	but with a minimum delay between attempts.  A device search
 *	within the period of time specified will result in failure.
 *
 * devid_cache_read_disable (default 0)
 *	Set to 1 to disable reading /etc/devices/devid_cache.
 *	Devid cache will continue to operate normally but
 *	at least one discovery attempt will be required.
 *
 * devid_cache_write_disable (default 0)
 *	Set to 1 to disable updates to /etc/devices/devid_cache.
 *	Any updates to the devid cache will not be preserved across a reboot.
 *
 * kfio_report_error (default 0)
 *	Set to 1 to enable some error messages related to low-level
 *	kernel file i/o operations.
 *
 * devid_report_error (default 0)
 *	Set to 1 to enable some error messages related to devid
 *	cache failures.
 *
 * nvpflush_delay (default 10)
 *	The number of seconds after data is marked dirty before the
 *	flush daemon is triggered to flush the data.  A longer period
 *	of time permits more data updates per write.  Note that
 *	every update resets the timer so no repository write will
 *	occur while data is being updated continuously.
 *
 * nvpdaemon_idle_time (default 60)
 *	The number of seconds the daemon will sleep idle before exiting.
 *
 */
extern int devid_discovery_boot;
extern int devid_discovery_postboot;
extern int devid_discovery_postboot_always;
extern int devid_discovery_secs;

extern int devid_cache_read_disable;
extern int devid_cache_write_disable;

/*
 * More thorough error reporting available both debug &
 * non-debug kernels, but turned off by default.
 */
extern int kfio_report_error;		/* kernel file i/o operations */
extern int devid_report_error;		/* devid cache operations */

/*
 * Suffix of temporary file for updates
 */
#define	MAX_SUFFIX_LEN		4
#define	NEW_FILENAME_SUFFIX	"new"

/*
 * nvf_flags
 */
#define	NVF_DIRTY	0x01		/* needs to be flushed */
#define	NVF_FLUSHING	0x02		/* in process of being flushed */
#define	NVF_ERROR	0x04		/* most recent flush failed */
#define	NVF_READONLY	0x10		/* file is read-only */
#define	NVF_CREATE_MSG	0x20		/* file not found on boot, emit msg */
#define	NVF_REBUILD_MSG	0x40		/* file was found corrupted, emit msg */

#define	NVF_IS_DIRTY(nvfd)	((nvfd)->nvf_flags & NVF_DIRTY)
#define	NVF_MARK_DIRTY(nvfd)	((nvfd)->nvf_flags |= NVF_DIRTY)
#define	NVF_CLEAR_DIRTY(nvfd)	((nvfd)->nvf_flags &= ~NVF_DIRTY)

#define	NVF_IS_READONLY(nvfd)	((nvfd)->nvf_flags & NVF_READONLY)
#define	NVF_MARK_READONLY(nvfd)	((nvfd)->nvf_flags |= NVF_READONLY)
#define	NVF_CLR_READONLY(nvfd)	((nvfd)->nvf_flags &= ~NVF_READONLY)

#ifdef	DEBUG

#define	NVPDAEMON_DEBUG(args)	{ if (nvpdaemon_debug) cmn_err args; }
#define	KFDEBUG(args)		{ if (kfio_debug) cmn_err args; }
#define	KFDEBUG1(args)		{ if (kfio_debug > 1) cmn_err args; }
#define	KFDEBUG2(args)		{ if (kfio_debug > 2) cmn_err args; }
#define	KFDUMP(args)		{ if (kfio_debug > 2) args; }
#define	DEVID_DEBUG(args)	{ if (devid_debug) cmn_err args; }
#define	DEVID_DEBUG1(args)	{ if (devid_debug > 1) cmn_err args; }
#define	DEVID_DEBUG2(args)	{ if (devid_debug > 2) cmn_err args; }
#define	DEVID_DUMP(args)	{ if (devid_debug > 2) args; }
#define	DEVID_LOG_REG(args)	{ if (devid_log_registers) devid_log args; }
#define	DEVID_LOG_FIND(args)	{ if (devid_log_finds) devid_log args; }
#define	DEVID_LOG_LOOKUP(args)	{ if (devid_log_lookups) cmn_err args; }
#define	DEVID_LOG_MATCH(args)	{ if (devid_log_matches) devid_log args; }
#define	DEVID_LOG_PATHS(args)	{ if (devid_log_paths) cmn_err args; }
#define	DEVID_LOG_ERR(args)	{ if (devid_log_failures) devid_log args; }
#define	DEVID_LOG_DISC(args)	{ if (devid_log_discovery) cmn_err args; }
#define	DEVID_LOG_HOLD(args)	{ if (devid_log_hold) cmn_err args; }
#define	DEVID_LOG_UNREG(args)	{ if (devid_log_unregisters) cmn_err args; }
#define	DEVID_LOG_REMOVE(args)	{ if (devid_log_removes) cmn_err args; }
#define	DEVID_LOG_STALE(args)	{ if (devid_log_stale) devid_log args; }
#define	DEVID_LOG_DETACH(args)	{ if (devid_log_detaches) cmn_err args; }


#define	NVP_DEVID_DEBUG_PATH(arg) {					\
		if (nvp_devid_debug)					\
			cmn_err(CE_CONT, "%s\n", arg);			\
	}

#define	NVP_DEVID_DEBUG_DEVID(arg) {					\
		if (nvp_devid_debug) {					\
			char *ds = ddi_devid_str_encode(arg, NULL);	\
			cmn_err(CE_CONT, "devid: %s\n", ds);		\
			ddi_devid_str_free(ds);				\
		}							\
	}

static void devid_log(char *, ddi_devid_t, char *);

#else

#define	NVPDAEMON_DEBUG(args)
#define	KFDEBUG(args)
#define	KFDEBUG1(args)
#define	KFDEBUG2(args)
#define	KFDUMP(args)
#define	DEVID_DEBUG(args)
#define	DEVID_DEBUG1(args)
#define	DEVID_DEBUG2(args)
#define	DEVID_DUMP(args)
#define	DEVID_LOG_REG(args)
#define	DEVID_LOG_FIND(args)
#define	DEVID_LOG_LOOKUP(args)
#define	DEVID_LOG_MATCH(args)
#define	DEVID_LOG_PATHS(args)
#define	DEVID_LOG_ERR(args)
#define	DEVID_LOG_DISC(args)
#define	DEVID_LOG_HOLD(args)
#define	DEVID_LOG_UNREG(args)
#define	DEVID_LOG_REMOVE(args)
#define	DEVID_LOG_STALE(args)
#define	DEVID_LOG_DETACH(args)
#define	NVP_DEVID_DEBUG_PATH(arg)
#define	NVP_DEVID_DEBUG_DEVID(arg)

#endif	/* DEBUG */

#define	KFIOERR(args)		{ if (kfio_report_error) cmn_err args; }
#define	DEVIDERR(args)		{ if (devid_report_error) cmn_err args; }


static void wake_nvpflush_daemon(nvfd_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVCTL_IMPL_H */
