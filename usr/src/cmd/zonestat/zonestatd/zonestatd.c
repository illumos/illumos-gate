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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <alloca.h>
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <door.h>
#include <errno.h>
#include <exacct.h>
#include <ctype.h>
#include <fcntl.h>
#include <kstat.h>
#include <libcontract.h>
#include <libintl.h>
#include <libscf.h>
#include <zonestat.h>
#include <zonestat_impl.h>
#include <limits.h>
#include <pool.h>
#include <procfs.h>
#include <rctl.h>
#include <thread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <synch.h>
#include <sys/acctctl.h>
#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/fork.h>
#include <sys/param.h>
#include <sys/priocntl.h>
#include <sys/fxpriocntl.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/swap.h>
#include <sys/systeminfo.h>
#include <thread.h>
#include <sys/list.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/vm_usage.h>
#include <sys/wait.h>
#include <sys/zone.h>
#include <time.h>
#include <ucred.h>
#include <unistd.h>
#include <vm/anon.h>
#include <zone.h>
#include <zonestat.h>

#define	MAX_PSET_NAME	1024	/* Taken from PV_NAME_MAX_LEN */
#define	ZSD_PSET_UNLIMITED	UINT16_MAX
#define	ZONESTAT_EXACCT_FILE	"/var/adm/exacct/zonestat-process"

/*
 * zonestatd implements gathering cpu and memory utilization data for
 * running zones.  It has these components:
 *
 * zsd_server:
 *	Door server to respond to client connections.  Each client
 *	will connect using libzonestat.so, which will open and
 *	call /var/tmp/.zonestat_door.  Each connecting client is given
 *	a file descriptor to the stat server.
 *
 *	The zsd_server also responds to zoneadmd, which reports when a
 *	new zone is booted.  This is used to fattach the zsd_server door
 *	into the new zone.
 *
 * zsd_stat_server:
 *	Receives client requests for the current utilization data.  Each
 *	client request will cause zonestatd to update the current utilization
 *	data by kicking the stat_thread.
 *
 *	If the client is in a non-global zone, the utilization data will
 *	be filtered to only show the given zone.  The usage by all other zones
 *	will be added to the system utilization.
 *
 * stat_thread:
 *	The stat thread implements querying the system to determine the
 *	current utilization data for each running zone.  This includes
 *	inspecting the system's processor set configuration, as well as details
 *	of each zone, such as their configured limits, and which processor
 *	sets they are running in.
 *
 *	The stat_thread will only update memory utilization data as often as
 *	the configured config/sample_interval on the zones-monitoring service.
 */

/*
 * The private vmusage structure unfortunately uses size_t types, and assumes
 * the caller's bitness matches the kernel's bitness.  Since the getvmusage()
 * system call is contracted, and zonestatd is 32 bit, the following structures
 * are used to interact with a 32bit or 64 bit kernel.
 */
typedef struct zsd_vmusage32 {
	id_t vmu_zoneid;
	uint_t vmu_type;
	id_t vmu_id;

	uint32_t vmu_rss_all;
	uint32_t vmu_rss_private;
	uint32_t vmu_rss_shared;
	uint32_t vmu_swap_all;
	uint32_t vmu_swap_private;
	uint32_t vmu_swap_shared;
} zsd_vmusage32_t;

typedef struct zsd_vmusage64 {
	id_t vmu_zoneid;
	uint_t vmu_type;
	id_t vmu_id;
	/*
	 * An amd64 kernel will align the following uint64_t members, but a
	 * 32bit i386 process will not without help.
	 */
	int vmu_align_next_members_on_8_bytes;
	uint64_t vmu_rss_all;
	uint64_t vmu_rss_private;
	uint64_t vmu_rss_shared;
	uint64_t vmu_swap_all;
	uint64_t vmu_swap_private;
	uint64_t vmu_swap_shared;
} zsd_vmusage64_t;

struct zsd_zone;

/* Used to store a zone's usage of a pset */
typedef struct zsd_pset_usage {
	struct zsd_zone	*zsu_zone;
	struct zsd_pset	*zsu_pset;

	list_node_t	zsu_next;

	zoneid_t	zsu_zoneid;
	boolean_t	zsu_found;	/* zone bound at end of interval */
	boolean_t	zsu_active;	/* zone was bound during interval */
	boolean_t	zsu_new;	/* zone newly bound in this interval */
	boolean_t	zsu_deleted;	/* zone was unbound in this interval */
	boolean_t	zsu_empty;	/* no procs in pset in this interval */
	time_t		zsu_start;	/* time when zone was found in pset */
	hrtime_t	zsu_hrstart;	/* time when zone  was found in pset */
	uint64_t	zsu_cpu_shares;
	uint_t		zsu_scheds;	/* schedulers found in this pass */
	timestruc_t	zsu_cpu_usage;	/* cpu time used */
} zsd_pset_usage_t;

/* Used to store a pset's utilization */
typedef struct zsd_pset {
	psetid_t	zsp_id;
	list_node_t	zsp_next;
	char		zsp_name[ZS_PSETNAME_MAX];

	uint_t		zsp_cputype;	/* default, dedicated or shared */
	boolean_t	zsp_found;	/* pset found at end of interval */
	boolean_t	zsp_new;	/* pset new in this interval */
	boolean_t	zsp_deleted;	/* pset deleted in this interval */
	boolean_t	zsp_active;	/* pset existed during interval */
	boolean_t	zsp_empty;	/* no processes in pset */
	time_t		zsp_start;
	hrtime_t	zsp_hrstart;

	uint64_t	zsp_online;	/* online cpus in interval */
	uint64_t	zsp_size;	/* size in this interval */
	uint64_t	zsp_min;	/* configured min in this interval */
	uint64_t	zsp_max;	/* configured max in this interval */
	int64_t		zsp_importance;	/* configured max in this interval */

	uint_t		zsp_scheds;	/* scheds of processes found in pset */
	uint64_t	zsp_cpu_shares;	/* total shares in this interval */

	timestruc_t	zsp_total_time;
	timestruc_t	zsp_usage_kern;
	timestruc_t	zsp_usage_zones;

	/* Individual zone usages of pset */
	list_t		zsp_usage_list;
	int		zsp_nusage;

	/* Summed kstat values from individual cpus in pset */
	timestruc_t	zsp_idle;
	timestruc_t	zsp_intr;
	timestruc_t	zsp_kern;
	timestruc_t	zsp_user;

} zsd_pset_t;

/* Used to track an individual cpu's utilization as reported by kstats */
typedef struct zsd_cpu {
	processorid_t	zsc_id;
	list_node_t	zsc_next;
	psetid_t	zsc_psetid;
	psetid_t	zsc_psetid_prev;
	zsd_pset_t	*zsc_pset;

	boolean_t	zsc_found;	/* cpu online in this interval */
	boolean_t	zsc_onlined;	/* cpu onlined during this interval */
	boolean_t	zsc_offlined;	/* cpu offlined during this interval */
	boolean_t	zsc_active;	/* cpu online during this interval */
	boolean_t	zsc_allocated;	/* True if cpu has ever been found */

	/* kstats this interval */
	uint64_t	zsc_nsec_idle;
	uint64_t	zsc_nsec_intr;
	uint64_t	zsc_nsec_kern;
	uint64_t	zsc_nsec_user;

	/* kstats in most recent interval */
	uint64_t	zsc_nsec_idle_prev;
	uint64_t	zsc_nsec_intr_prev;
	uint64_t	zsc_nsec_kern_prev;
	uint64_t	zsc_nsec_user_prev;

	/* Total kstat increases since zonestatd started reading kstats */
	timestruc_t	zsc_idle;
	timestruc_t	zsc_intr;
	timestruc_t	zsc_kern;
	timestruc_t	zsc_user;

} zsd_cpu_t;

/* Used to describe an individual zone and its utilization */
typedef struct zsd_zone {
	zoneid_t	zsz_id;
	list_node_t	zsz_next;
	char		zsz_name[ZS_ZONENAME_MAX];
	uint_t		zsz_cputype;
	uint_t		zsz_iptype;
	time_t		zsz_start;
	hrtime_t	zsz_hrstart;

	char		zsz_pool[ZS_POOLNAME_MAX];
	char		zsz_pset[ZS_PSETNAME_MAX];
	int		zsz_default_sched;
	/* These are deduced by inspecting processes */
	psetid_t	zsz_psetid;
	uint_t		zsz_scheds;

	boolean_t	zsz_new;	/* zone booted during this interval */
	boolean_t	zsz_deleted;	/* halted during this interval */
	boolean_t	zsz_active;	/* running in this interval */
	boolean_t	zsz_empty;	/* no processes in this interval */
	boolean_t	zsz_gone;	/* not installed in this interval */
	boolean_t	zsz_found;	/* Running at end of this interval */

	uint64_t	zsz_cpu_shares;
	uint64_t	zsz_cpu_cap;
	uint64_t	zsz_ram_cap;
	uint64_t	zsz_locked_cap;
	uint64_t	zsz_vm_cap;

	uint64_t	zsz_cpus_online;
	timestruc_t	zsz_cpu_usage;	/* cpu time of cpu cap */
	timestruc_t	zsz_cap_time;	/* cpu time of cpu cap */
	timestruc_t	zsz_share_time; /* cpu time of share of cpu */
	timestruc_t	zsz_pset_time;  /* time of all psets zone is bound to */

	uint64_t	zsz_usage_ram;
	uint64_t	zsz_usage_locked;
	uint64_t	zsz_usage_vm;

	uint64_t	zsz_processes_cap;
	uint64_t	zsz_lwps_cap;
	uint64_t	zsz_shm_cap;
	uint64_t	zsz_shmids_cap;
	uint64_t	zsz_semids_cap;
	uint64_t	zsz_msgids_cap;
	uint64_t	zsz_lofi_cap;

	uint64_t	zsz_processes;
	uint64_t	zsz_lwps;
	uint64_t	zsz_shm;
	uint64_t	zsz_shmids;
	uint64_t	zsz_semids;
	uint64_t	zsz_msgids;
	uint64_t	zsz_lofi;

} zsd_zone_t;

/*
 * Used to track the cpu usage of an individual processes.
 *
 * zonestatd sweeps /proc each interval and charges the cpu usage of processes.
 * to their zone.  As processes exit, their extended accounting records are
 * read and the difference of their total and known usage is charged to their
 * zone.
 *
 * If a process is never seen in /proc, the total usage on its extended
 * accounting record will be charged to its zone.
 */
typedef struct zsd_proc {
	list_node_t	zspr_next;
	pid_t		zspr_ppid;
	psetid_t	zspr_psetid;
	zoneid_t	zspr_zoneid;
	int		zspr_sched;
	timestruc_t	zspr_usage;
} zsd_proc_t;

/* Used to track the overall resource usage of the system */
typedef struct zsd_system {

	uint64_t zss_ram_total;
	uint64_t zss_ram_kern;
	uint64_t zss_ram_zones;

	uint64_t zss_locked_kern;
	uint64_t zss_locked_zones;

	uint64_t zss_vm_total;
	uint64_t zss_vm_kern;
	uint64_t zss_vm_zones;

	uint64_t zss_swap_total;
	uint64_t zss_swap_used;

	timestruc_t zss_idle;
	timestruc_t zss_intr;
	timestruc_t zss_kern;
	timestruc_t zss_user;

	timestruc_t zss_cpu_total_time;
	timestruc_t zss_cpu_usage_kern;
	timestruc_t zss_cpu_usage_zones;

	uint64_t zss_maxpid;
	uint64_t zss_processes_max;
	uint64_t zss_lwps_max;
	uint64_t zss_shm_max;
	uint64_t zss_shmids_max;
	uint64_t zss_semids_max;
	uint64_t zss_msgids_max;
	uint64_t zss_lofi_max;

	uint64_t zss_processes;
	uint64_t zss_lwps;
	uint64_t zss_shm;
	uint64_t zss_shmids;
	uint64_t zss_semids;
	uint64_t zss_msgids;
	uint64_t zss_lofi;

	uint64_t zss_ncpus;
	uint64_t zss_ncpus_online;

} zsd_system_t;

/*
 * A dumping ground for various information and structures used to compute
 * utilization.
 *
 * This structure is used to track the system while clients are connected.
 * When The first client connects, a zsd_ctl is allocated and configured by
 * zsd_open().  When all clients disconnect, the zsd_ctl is closed.
 */
typedef struct zsd_ctl {
	kstat_ctl_t	*zsctl_kstat_ctl;

	/* To track extended accounting */
	int		zsctl_proc_fd;		/* Log currently being used */
	ea_file_t	zsctl_proc_eaf;
	struct stat64	zsctl_proc_stat;
	int		zsctl_proc_open;
	int		zsctl_proc_fd_next;	/* Log file to use next */
	ea_file_t	zsctl_proc_eaf_next;
	struct stat64	zsctl_proc_stat_next;
	int		zsctl_proc_open_next;

	/* pool configuration handle */
	pool_conf_t	*zsctl_pool_conf;
	int		zsctl_pool_status;
	int		zsctl_pool_changed;

	/* The above usage tacking structures */
	zsd_system_t	*zsctl_system;
	list_t		zsctl_zones;
	list_t		zsctl_psets;
	list_t		zsctl_cpus;
	zsd_cpu_t	*zsctl_cpu_array;
	zsd_proc_t	*zsctl_proc_array;

	/* Various system info */
	uint64_t	zsctl_maxcpuid;
	uint64_t	zsctl_maxproc;
	uint64_t	zsctl_kern_bits;
	uint64_t	zsctl_pagesize;

	/* Used to track time available under a cpu cap. */
	uint64_t	zsctl_hrtime;
	uint64_t	zsctl_hrtime_prev;
	timestruc_t	zsctl_hrtime_total;

	struct timeval	zsctl_timeofday;

	/* Caches for arrays allocated for use by various system calls */
	psetid_t	*zsctl_pset_cache;
	uint_t		zsctl_pset_ncache;
	processorid_t	*zsctl_cpu_cache;
	uint_t		zsctl_cpu_ncache;
	zoneid_t	*zsctl_zone_cache;
	uint_t		zsctl_zone_ncache;
	struct swaptable *zsctl_swap_cache;
	uint64_t	zsctl_swap_cache_size;
	uint64_t	zsctl_swap_cache_num;
	zsd_vmusage64_t	*zsctl_vmusage_cache;
	uint64_t	zsctl_vmusage_cache_num;

	/* Info about procfs for scanning /proc */
	pool_value_t	*zsctl_pool_vals[3];

	/* Counts on tracked entities */
	uint_t		zsctl_nzones;
	uint_t		zsctl_npsets;
	uint_t		zsctl_npset_usages;
} zsd_ctl_t;

zsd_ctl_t		*g_ctl;
boolean_t		g_open;		/* True if g_ctl is open */
int			g_hasclient;	/* True if any clients are connected */

/*
 * The usage cache is updated by the stat_thread, and copied to clients by
 * the zsd_stat_server.  Mutex and cond are to synchronize between the
 * stat_thread and the stat_server.
 */
zs_usage_cache_t	*g_usage_cache;
mutex_t			g_usage_cache_lock;
cond_t			g_usage_cache_kick;
uint_t			g_usage_cache_kickers;
cond_t			g_usage_cache_wait;
char			*g_usage_cache_buf;
uint_t			g_usage_cache_bufsz;
uint64_t		g_gen_next;

/* fds of door servers */
int			g_server_door;
int			g_stat_door;

/*
 * Starting and current time.  Used to throttle memory calculation, and to
 * mark new zones and psets with their boot and creation time.
 */
time_t			g_now;
time_t			g_start;
hrtime_t		g_hrnow;
hrtime_t		g_hrstart;
uint64_t		g_interval;

/*
 * main() thread.
 */
thread_t		g_main;

/* PRINTFLIKE1 */
static void
zsd_warn(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);

	(void) fprintf(stderr, gettext("zonestat: Warning: "));
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
}

/* PRINTFLIKE1 */
static void
zsd_error(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);

	(void) fprintf(stderr, gettext("zonestat: Error: "));
	(void) vfprintf(stderr, fmt, alist);
	(void) fprintf(stderr, "\n");
	va_end(alist);
	exit(1);
}

/* Turns on extended accounting if not configured externally */
int
zsd_enable_cpu_stats()
{
	char *path = ZONESTAT_EXACCT_FILE;
	char oldfile[MAXPATHLEN];
	int ret, state = AC_ON;
	ac_res_t res[6];

	/*
	 * Start a new accounting file  if accounting not configured
	 * externally.
	 */

	res[0].ar_id = AC_PROC_PID;
	res[0].ar_state = AC_ON;
	res[1].ar_id = AC_PROC_ANCPID;
	res[1].ar_state = AC_ON;
	res[2].ar_id = AC_PROC_CPU;
	res[2].ar_state = AC_ON;
	res[3].ar_id = AC_PROC_TIME;
	res[3].ar_state = AC_ON;
	res[4].ar_id = AC_PROC_ZONENAME;
	res[4].ar_state = AC_ON;
	res[5].ar_id = AC_NONE;
	res[5].ar_state = AC_ON;
	if (acctctl(AC_PROC | AC_RES_SET, res, sizeof (res)) != 0) {
		zsd_warn(gettext("Unable to set accounting resources"));
		return (-1);
	}
	/* Only set accounting file if none is configured */
	ret = acctctl(AC_PROC | AC_FILE_GET, oldfile, sizeof (oldfile));
	if (ret < 0) {

		(void) unlink(path);
		if (acctctl(AC_PROC | AC_FILE_SET, path, strlen(path) + 1)
		    == -1) {
			zsd_warn(gettext("Unable to set accounting file"));
			return (-1);
		}
	}
	if (acctctl(AC_PROC | AC_STATE_SET, &state, sizeof (state)) == -1) {
		zsd_warn(gettext("Unable to enable accounting"));
		return (-1);
	}
	return (0);
}

/* Turns off extended accounting if not configured externally */
int
zsd_disable_cpu_stats()
{
	char *path = ZONESTAT_EXACCT_FILE;
	int ret, state = AC_OFF;
	ac_res_t res[6];
	char oldfile[MAXPATHLEN];

	/* If accounting file is externally configured, leave it alone */
	ret = acctctl(AC_PROC | AC_FILE_GET, oldfile, sizeof (oldfile));
	if (ret == 0 && strcmp(oldfile, path) != 0)
		return (0);

	res[0].ar_id = AC_PROC_PID;
	res[0].ar_state = AC_OFF;
	res[1].ar_id = AC_PROC_ANCPID;
	res[1].ar_state = AC_OFF;
	res[2].ar_id = AC_PROC_CPU;
	res[2].ar_state = AC_OFF;
	res[3].ar_id = AC_PROC_TIME;
	res[3].ar_state = AC_OFF;
	res[4].ar_id = AC_PROC_ZONENAME;
	res[4].ar_state = AC_OFF;
	res[5].ar_id = AC_NONE;
	res[5].ar_state = AC_OFF;
	if (acctctl(AC_PROC | AC_RES_SET, res, sizeof (res)) != 0) {
		zsd_warn(gettext("Unable to clear accounting resources"));
		return (-1);
	}
	if (acctctl(AC_PROC | AC_FILE_SET, NULL, 0) == -1) {
		zsd_warn(gettext("Unable to clear accounting file"));
		return (-1);
	}
	if (acctctl(AC_PROC | AC_STATE_SET, &state, sizeof (state)) == -1) {
		zsd_warn(gettext("Unable to diable accounting"));
		return (-1);
	}

	(void) unlink(path);
	return (0);
}

/*
 * If not configured externally, deletes the current extended accounting file
 * and starts a new one.
 *
 * Since the stat_thread holds an open handle to the accounting file, it will
 * read all remaining entries from the old file before switching to
 * read the new one.
 */
int
zsd_roll_exacct(void)
{
	int ret;
	char *path = ZONESTAT_EXACCT_FILE;
	char oldfile[MAXPATHLEN];

	/* If accounting file is externally configured, leave it alone */
	ret = acctctl(AC_PROC | AC_FILE_GET, oldfile, sizeof (oldfile));
	if (ret == 0 && strcmp(oldfile, path) != 0)
		return (0);

	if (unlink(path) != 0)
		/* Roll it next time */
		return (0);

	if (acctctl(AC_PROC | AC_FILE_SET, path, strlen(path) + 1) == -1) {
		zsd_warn(gettext("Unable to set accounting file"));
		return (-1);
	}
	return (0);
}

/* Contract stuff for zone_enter() */
int
init_template(void)
{
	int fd;
	int err = 0;

	fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (fd == -1)
		return (-1);

	/*
	 * For now, zoneadmd doesn't do anything with the contract.
	 * Deliver no events, don't inherit, and allow it to be orphaned.
	 */
	err |= ct_tmpl_set_critical(fd, 0);
	err |= ct_tmpl_set_informative(fd, 0);
	err |= ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR);
	err |= ct_pr_tmpl_set_param(fd, CT_PR_PGRPONLY | CT_PR_REGENT);
	if (err || ct_tmpl_activate(fd)) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * Contract stuff for zone_enter()
 */
int
contract_latest(ctid_t *id)
{
	int cfd, r;
	ct_stathdl_t st;
	ctid_t result;

	if ((cfd = open64(CTFS_ROOT "/process/latest", O_RDONLY)) == -1)
		return (errno);

	if ((r = ct_status_read(cfd, CTD_COMMON, &st)) != 0) {
		(void) close(cfd);
		return (r);
	}

	result = ct_status_get_id(st);
	ct_status_free(st);
	(void) close(cfd);

	*id = result;
	return (0);
}

static int
close_on_exec(int fd)
{
	int flags = fcntl(fd, F_GETFD, 0);
	if ((flags != -1) && (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1))
		return (0);
	return (-1);
}

int
contract_open(ctid_t ctid, const char *type, const char *file, int oflag)
{
	char path[PATH_MAX];
	int n, fd;

	if (type == NULL)
		type = "all";

	n = snprintf(path, PATH_MAX, CTFS_ROOT "/%s/%ld/%s", type, ctid, file);
	if (n >= sizeof (path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	fd = open64(path, oflag);
	if (fd != -1) {
		if (close_on_exec(fd) == -1) {
			int err = errno;
			(void) close(fd);
			errno = err;
			return (-1);
		}
	}
	return (fd);
}

int
contract_abandon_id(ctid_t ctid)
{
	int fd, err;

	fd = contract_open(ctid, "all", "ctl", O_WRONLY);
	if (fd == -1)
		return (errno);

	err = ct_ctl_abandon(fd);
	(void) close(fd);

	return (err);
}
/*
 * Attach the zsd_server to a zone.  Called for each zone when zonestatd
 * starts, and for each newly booted zone when zoneadmd contacts the zsd_server
 *
 * Zone_enter is used to avoid reaching into zone to fattach door.
 */
static void
zsd_fattach_zone(zoneid_t zid, int door, boolean_t detach_only)
{
	char *path = ZS_DOOR_PATH;
	int fd, pid, stat, tmpl_fd;
	ctid_t ct;

	if ((tmpl_fd = init_template()) == -1) {
		zsd_warn("Unable to init template");
		return;
	}

	pid = forkx(0);
	if (pid < 0) {
		(void) ct_tmpl_clear(tmpl_fd);
		zsd_warn(gettext(
		    "Unable to fork to add zonestat to zoneid %d\n"), zid);
		return;
	}

	if (pid == 0) {
		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		if (zid != 0 && zone_enter(zid) != 0) {
			if (errno == EINVAL) {
				_exit(0);
			}
			_exit(1);
		}
		(void) fdetach(path);
		(void) unlink(path);
		if (detach_only)
			_exit(0);
		fd = open(path, O_CREAT|O_RDWR, 0644);
		if (fd < 0)
			_exit(2);
		if (fattach(door, path) != 0)
			_exit(3);
		_exit(0);
	}
	if (contract_latest(&ct) == -1)
		ct = -1;
	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);
	(void) contract_abandon_id(ct);
	while (waitpid(pid, &stat, 0) != pid)
		;
	if (WIFEXITED(stat) && WEXITSTATUS(stat) == 0)
		return;

	zsd_warn(gettext("Unable to attach door to zoneid: %d"), zid);

	if (WEXITSTATUS(stat) == 1)
		zsd_warn(gettext("Cannot entering zone"));
	else if (WEXITSTATUS(stat) == 2)
		zsd_warn(gettext("Unable to create door file: %s"), path);
	else if (WEXITSTATUS(stat) == 3)
		zsd_warn(gettext("Unable to fattach file: %s"), path);

	zsd_warn(gettext("Internal error entering zone: %d"), zid);
}

/*
 * Zone lookup and allocation functions to manage list of currently running
 * zones.
 */
static zsd_zone_t *
zsd_lookup_zone(zsd_ctl_t *ctl, char *zonename, zoneid_t zoneid)
{
	zsd_zone_t *zone;

	for (zone = list_head(&ctl->zsctl_zones); zone != NULL;
	    zone = list_next(&ctl->zsctl_zones, zone)) {
		if (strcmp(zone->zsz_name, zonename) == 0) {
			if (zoneid != -1)
				zone->zsz_id = zoneid;
			return (zone);
		}
	}
	return (NULL);
}

static zsd_zone_t *
zsd_lookup_zone_byid(zsd_ctl_t *ctl, zoneid_t zoneid)
{
	zsd_zone_t *zone;

	for (zone = list_head(&ctl->zsctl_zones); zone != NULL;
	    zone = list_next(&ctl->zsctl_zones, zone)) {
		if (zone->zsz_id == zoneid)
			return (zone);
	}
	return (NULL);
}

static zsd_zone_t *
zsd_allocate_zone(zsd_ctl_t *ctl, char *zonename, zoneid_t zoneid)
{
	zsd_zone_t *zone;

	if ((zone = (zsd_zone_t *)calloc(1, sizeof (zsd_zone_t))) == NULL)
		return (NULL);

	(void) strlcpy(zone->zsz_name, zonename, sizeof (zone->zsz_name));
	zone->zsz_id = zoneid;
	zone->zsz_found = B_FALSE;

	/*
	 * Allocate as deleted so if not found in first pass, zone is deleted
	 * from list.  This can happen if zone is returned by zone_list, but
	 * exits before first attempt to fetch zone details.
	 */
	zone->zsz_start = g_now;
	zone->zsz_hrstart = g_hrnow;
	zone->zsz_deleted = B_TRUE;

	zone->zsz_cpu_shares = ZS_LIMIT_NONE;
	zone->zsz_cpu_cap = ZS_LIMIT_NONE;
	zone->zsz_ram_cap = ZS_LIMIT_NONE;
	zone->zsz_locked_cap = ZS_LIMIT_NONE;
	zone->zsz_vm_cap = ZS_LIMIT_NONE;

	zone->zsz_processes_cap = ZS_LIMIT_NONE;
	zone->zsz_lwps_cap = ZS_LIMIT_NONE;
	zone->zsz_shm_cap = ZS_LIMIT_NONE;
	zone->zsz_shmids_cap = ZS_LIMIT_NONE;
	zone->zsz_semids_cap = ZS_LIMIT_NONE;
	zone->zsz_msgids_cap = ZS_LIMIT_NONE;
	zone->zsz_lofi_cap = ZS_LIMIT_NONE;

	ctl->zsctl_nzones++;

	return (zone);
}

static zsd_zone_t *
zsd_lookup_insert_zone(zsd_ctl_t *ctl, char *zonename, zoneid_t zoneid)
{
	zsd_zone_t *zone, *tmp;

	if ((zone = zsd_lookup_zone(ctl, zonename, zoneid)) != NULL)
		return (zone);

	if ((zone = zsd_allocate_zone(ctl, zonename, zoneid)) == NULL)
		return (NULL);

	/* Insert sorted by zonename */
	tmp = list_head(&ctl->zsctl_zones);
	while (tmp != NULL && strcmp(zonename, tmp->zsz_name) > 0)
		tmp = list_next(&ctl->zsctl_zones, tmp);

	list_insert_before(&ctl->zsctl_zones, tmp, zone);
	return (zone);
}

/*
 * Mark all zones as not existing.  As zones are found, they will
 * be marked as existing.  If a zone is not found, then it must have
 * halted.
 */
static void
zsd_mark_zones_start(zsd_ctl_t *ctl)
{

	zsd_zone_t *zone;

	for (zone = list_head(&ctl->zsctl_zones); zone != NULL;
	    zone = list_next(&ctl->zsctl_zones, zone)) {
		zone->zsz_found = B_FALSE;
	}
}

/*
 * Mark each zone as not using pset.  If processes are found using the
 * pset, the zone will remain bound to the pset.  If none of a zones
 * processes are bound to the pset, the zone's usage of the pset will
 * be deleted.
 *
 */
static void
zsd_mark_pset_usage_start(zsd_pset_t *pset)
{
	zsd_pset_usage_t *usage;

	for (usage = list_head(&pset->zsp_usage_list);
	    usage != NULL;
	    usage = list_next(&pset->zsp_usage_list, usage)) {
		usage->zsu_found = B_FALSE;
		usage->zsu_empty = B_TRUE;
	}
}

/*
 * Mark each pset as not existing.  If a pset is found, it will be marked
 * as existing.  If a pset is not found, it wil be deleted.
 */
static void
zsd_mark_psets_start(zsd_ctl_t *ctl)
{
	zsd_pset_t *pset;

	for (pset = list_head(&ctl->zsctl_psets); pset != NULL;
	    pset = list_next(&ctl->zsctl_psets, pset)) {
		pset->zsp_found = B_FALSE;
		zsd_mark_pset_usage_start(pset);
	}
}

/*
 * A pset was found.  Update its information
 */
static void
zsd_mark_pset_found(zsd_pset_t *pset, uint_t type, uint64_t online,
    uint64_t size, uint64_t min, uint64_t max, int64_t importance)
{
	pset->zsp_empty = B_TRUE;
	pset->zsp_deleted = B_FALSE;

	assert(pset->zsp_found == B_FALSE);

	/* update pset flags */
	if (pset->zsp_active == B_FALSE)
		/* pset not seen on previous interval.  It is new. */
		pset->zsp_new = B_TRUE;
	else
		pset->zsp_new = B_FALSE;

	pset->zsp_found = B_TRUE;
	pset->zsp_cputype = type;
	pset->zsp_online = online;
	pset->zsp_size = size;
	pset->zsp_min = min;
	pset->zsp_max = max;
	pset->zsp_importance = importance;
	pset->zsp_cpu_shares = 0;
	pset->zsp_scheds = 0;
	pset->zsp_active = B_TRUE;
}

/*
 * A zone's process was found using a pset. Charge the process to the pset and
 * the per-zone data for the pset.
 */
static void
zsd_mark_pset_usage_found(zsd_pset_usage_t *usage, uint_t sched)
{
	zsd_zone_t *zone = usage->zsu_zone;
	zsd_pset_t *pset = usage->zsu_pset;

	/* Nothing to do if already found */
	if (usage->zsu_found == B_TRUE)
		goto add_stats;

	usage->zsu_found = B_TRUE;
	usage->zsu_empty = B_FALSE;

	usage->zsu_deleted = B_FALSE;
	/* update usage flags */
	if (usage->zsu_active == B_FALSE)
		usage->zsu_new = B_TRUE;
	else
		usage->zsu_new = B_FALSE;

	usage->zsu_scheds = 0;
	usage->zsu_cpu_shares = ZS_LIMIT_NONE;
	usage->zsu_active = B_TRUE;
	pset->zsp_empty = B_FALSE;
	zone->zsz_empty = B_FALSE;

add_stats:
	/* Detect zone's pset id, and if it is bound to multiple psets */
	if (zone->zsz_psetid == ZS_PSET_ERROR)
		zone->zsz_psetid = pset->zsp_id;
	else if (zone->zsz_psetid != pset->zsp_id)
		zone->zsz_psetid = ZS_PSET_MULTI;

	usage->zsu_scheds |= sched;
	pset->zsp_scheds |= sched;
	zone->zsz_scheds |= sched;

	/* Record if FSS is co-habitating with conflicting scheduler */
	if ((pset->zsp_scheds & ZS_SCHED_FSS) &&
	    usage->zsu_scheds & (
	    ZS_SCHED_TS | ZS_SCHED_IA | ZS_SCHED_FX)) {
		usage->zsu_scheds |= ZS_SCHED_CONFLICT;

		pset->zsp_scheds |= ZS_SCHED_CONFLICT;
	}

}

/* Add cpu time for a process to a pset, zone, and system totals */
static void
zsd_add_usage(zsd_ctl_t *ctl, zsd_pset_usage_t *usage, timestruc_t *delta)
{
	zsd_system_t *system = ctl->zsctl_system;
	zsd_zone_t *zone = usage->zsu_zone;
	zsd_pset_t *pset = usage->zsu_pset;

	TIMESTRUC_ADD_TIMESTRUC(usage->zsu_cpu_usage, *delta);
	TIMESTRUC_ADD_TIMESTRUC(pset->zsp_usage_zones, *delta);
	TIMESTRUC_ADD_TIMESTRUC(zone->zsz_cpu_usage, *delta);
	TIMESTRUC_ADD_TIMESTRUC(system->zss_cpu_usage_zones, *delta);
}

/* Determine which processor sets have been deleted */
static void
zsd_mark_psets_end(zsd_ctl_t *ctl)
{
	zsd_pset_t *pset, *tmp;

	/*
	 * Mark pset as not exists, and deleted if it existed
	 * previous interval.
	 */
	pset = list_head(&ctl->zsctl_psets);
	while (pset != NULL) {
		if (pset->zsp_found == B_FALSE) {
			pset->zsp_empty = B_TRUE;
			if (pset->zsp_deleted == B_TRUE) {
				tmp = pset;
				pset = list_next(&ctl->zsctl_psets, pset);
				list_remove(&ctl->zsctl_psets, tmp);
				free(tmp);
				ctl->zsctl_npsets--;
				continue;
			} else {
				/* Pset vanished during this interval */
				pset->zsp_new = B_FALSE;
				pset->zsp_deleted = B_TRUE;
				pset->zsp_active = B_TRUE;
			}
		}
		pset = list_next(&ctl->zsctl_psets, pset);
	}
}

/* Determine which zones are no longer bound to processor sets */
static void
zsd_mark_pset_usages_end(zsd_ctl_t *ctl)
{
	zsd_pset_t *pset;
	zsd_zone_t *zone;
	zsd_pset_usage_t *usage, *tmp;

	/*
	 * Mark pset as not exists, and deleted if it existed previous
	 * interval.
	 */
	for (pset = list_head(&ctl->zsctl_psets); pset != NULL;
	    pset = list_next(&ctl->zsctl_psets, pset)) {
		usage = list_head(&pset->zsp_usage_list);
		while (usage != NULL) {
			/*
			 * Mark pset as not exists, and deleted if it existed
			 * previous interval.
			 */
			if (usage->zsu_found == B_FALSE ||
			    usage->zsu_zone->zsz_deleted == B_TRUE ||
			    usage->zsu_pset->zsp_deleted == B_TRUE) {
				tmp = usage;
				usage = list_next(&pset->zsp_usage_list,
				    usage);
				list_remove(&pset->zsp_usage_list, tmp);
				free(tmp);
				pset->zsp_nusage--;
				ctl->zsctl_npset_usages--;
				continue;
			} else {
				usage->zsu_new = B_FALSE;
				usage->zsu_deleted = B_TRUE;
				usage->zsu_active = B_TRUE;
			}
			/* Add cpu shares for usages that are in FSS */
			zone = usage->zsu_zone;
			if (usage->zsu_scheds & ZS_SCHED_FSS &&
			    zone->zsz_cpu_shares != ZS_SHARES_UNLIMITED &&
			    zone->zsz_cpu_shares != 0) {
				zone = usage->zsu_zone;
				usage->zsu_cpu_shares = zone->zsz_cpu_shares;
				pset->zsp_cpu_shares += zone->zsz_cpu_shares;
			}
			usage = list_next(&pset->zsp_usage_list,
			    usage);
		}
	}
}

/* A zone has been found.  Update its information */
static void
zsd_mark_zone_found(zsd_ctl_t *ctl, zsd_zone_t *zone, uint64_t cpu_shares,
    uint64_t cpu_cap, uint64_t ram_cap, uint64_t locked_cap,
    uint64_t vm_cap, uint64_t processes_cap, uint64_t processes,
    uint64_t lwps_cap, uint64_t lwps, uint64_t shm_cap, uint64_t shm,
    uint64_t shmids_cap, uint64_t shmids, uint64_t semids_cap,
    uint64_t semids, uint64_t msgids_cap, uint64_t msgids, uint64_t lofi_cap,
    uint64_t lofi, char *poolname, char *psetname, uint_t sched, uint_t cputype,
    uint_t iptype)
{
	zsd_system_t *sys = ctl->zsctl_system;

	assert(zone->zsz_found == B_FALSE);

	/*
	 * Mark zone as exists, and new if it did not exist in previous
	 * interval.
	 */
	zone->zsz_found = B_TRUE;
	zone->zsz_empty = B_TRUE;
	zone->zsz_deleted = B_FALSE;

	/*
	 * Zone is new.  Assume zone's properties are the same over entire
	 * interval.
	 */
	if (zone->zsz_active == B_FALSE)
		zone->zsz_new = B_TRUE;
	else
		zone->zsz_new = B_FALSE;

	(void) strlcpy(zone->zsz_pool, poolname, sizeof (zone->zsz_pool));
	(void) strlcpy(zone->zsz_pset, psetname, sizeof (zone->zsz_pset));
	zone->zsz_default_sched = sched;

	/* Schedulers updated later as processes are found */
	zone->zsz_scheds = 0;

	/* Cpus updated later as psets bound are identified */
	zone->zsz_cpus_online = 0;

	zone->zsz_cputype = cputype;
	zone->zsz_iptype = iptype;
	zone->zsz_psetid = ZS_PSET_ERROR;
	zone->zsz_cpu_cap = cpu_cap;
	zone->zsz_cpu_shares = cpu_shares;
	zone->zsz_ram_cap = ram_cap;
	zone->zsz_locked_cap = locked_cap;
	zone->zsz_vm_cap = vm_cap;
	zone->zsz_processes_cap = processes_cap;
	zone->zsz_processes = processes;
	zone->zsz_lwps_cap = lwps_cap;
	zone->zsz_lwps = lwps;
	zone->zsz_shm_cap = shm_cap;
	zone->zsz_shm = shm;
	zone->zsz_shmids_cap = shmids_cap;
	zone->zsz_shmids = shmids;
	zone->zsz_semids_cap = semids_cap;
	zone->zsz_semids = semids;
	zone->zsz_msgids_cap = msgids_cap;
	zone->zsz_msgids = msgids;
	zone->zsz_lofi_cap = lofi_cap;
	zone->zsz_lofi = lofi;

	sys->zss_processes += processes;
	sys->zss_lwps += lwps;
	sys->zss_shm += shm;
	sys->zss_shmids += shmids;
	sys->zss_semids += semids;
	sys->zss_msgids += msgids;
	sys->zss_lofi += lofi;
	zone->zsz_active = B_TRUE;
}


/* Determine which zones have halted */
static void
zsd_mark_zones_end(zsd_ctl_t *ctl)
{
	zsd_zone_t *zone, *tmp;

	/*
	 * Mark zone as not existing, or delete if it did not exist in
	 * previous interval.
	 */
	zone = list_head(&ctl->zsctl_zones);
	while (zone != NULL) {
		if (zone->zsz_found == B_FALSE) {
			zone->zsz_empty = B_TRUE;
			if (zone->zsz_deleted == B_TRUE) {
				/*
				 * Zone deleted in prior interval,
				 * so it no longer exists.
				 */
				tmp = zone;
				zone = list_next(&ctl->zsctl_zones, zone);
				list_remove(&ctl->zsctl_zones, tmp);
				free(tmp);
				ctl->zsctl_nzones--;
				continue;
			} else {
				zone->zsz_new = B_FALSE;
				zone->zsz_deleted = B_TRUE;
				zone->zsz_active = B_TRUE;
			}
		}
		zone = list_next(&ctl->zsctl_zones, zone);
	}
}

/*
 * Mark cpus as not existing.  If a cpu is found, it will be updated.  If
 * a cpu is not found, then it must have gone offline, so it will be
 * deleted.
 *
 * The kstat tracking data is rolled so that the usage since the previous
 * interval can be determined.
 */
static void
zsd_mark_cpus_start(zsd_ctl_t *ctl, boolean_t roll)
{
	zsd_cpu_t *cpu;

	/*
	 * Mark all cpus as not existing.  As cpus are found, they will
	 * be marked as existing.
	 */
	for (cpu = list_head(&ctl->zsctl_cpus); cpu != NULL;
	    cpu = list_next(&ctl->zsctl_cpus, cpu)) {
		cpu->zsc_found = B_FALSE;
		if (cpu->zsc_active == B_TRUE && roll) {
			cpu->zsc_psetid_prev = cpu->zsc_psetid;
			cpu->zsc_nsec_idle_prev = cpu->zsc_nsec_idle;
			cpu->zsc_nsec_intr_prev = cpu->zsc_nsec_intr;
			cpu->zsc_nsec_kern_prev = cpu->zsc_nsec_kern;
			cpu->zsc_nsec_user_prev = cpu->zsc_nsec_user;
		}
	}
}

/*
 * An array the size of the maximum number of cpus is kept.  Within this array
 * a list of the online cpus is maintained.
 */
zsd_cpu_t *
zsd_lookup_insert_cpu(zsd_ctl_t *ctl, processorid_t cpuid)
{
	zsd_cpu_t *cpu;

	assert(cpuid < ctl->zsctl_maxcpuid);
	cpu = &(ctl->zsctl_cpu_array[cpuid]);
	assert(cpuid == cpu->zsc_id);

	if (cpu->zsc_allocated == B_FALSE) {
		cpu->zsc_allocated = B_TRUE;
		list_insert_tail(&ctl->zsctl_cpus, cpu);
	}
	return (cpu);
}

/* A cpu has been found.  Update its information */
static void
zsd_mark_cpu_found(zsd_cpu_t *cpu, zsd_pset_t *pset, psetid_t psetid)
{
	/*
	 * legacy processor sets, the cpu may move while zonestatd is
	 * inspecting, causing it to be found twice.  In this case, just
	 * leave cpu in the first processor set in which it was found.
	 */
	if (cpu->zsc_found == B_TRUE)
		return;

	/* Mark cpu as online */
	cpu->zsc_found = B_TRUE;
	cpu->zsc_offlined = B_FALSE;
	cpu->zsc_pset = pset;
	/*
	 * cpu is newly online.
	 */
	if (cpu->zsc_active == B_FALSE) {
		/*
		 * Cpu is newly online.
		 */
		cpu->zsc_onlined = B_TRUE;
		cpu->zsc_psetid = psetid;
		cpu->zsc_psetid_prev = psetid;
	} else {
		/*
		 * cpu online during previous interval.  Save properties at
		 * start of interval
		 */
		cpu->zsc_onlined = B_FALSE;
		cpu->zsc_psetid = psetid;

	}
	cpu->zsc_active = B_TRUE;
}

/* Remove all offlined cpus from the list of tracked cpus */
static void
zsd_mark_cpus_end(zsd_ctl_t *ctl)
{
	zsd_cpu_t *cpu, *tmp;
	int id;

	/* Mark cpu as online or offline */
	cpu = list_head(&ctl->zsctl_cpus);
	while (cpu != NULL) {
		if (cpu->zsc_found == B_FALSE) {
			if (cpu->zsc_offlined == B_TRUE) {
				/*
				 * cpu offlined in prior interval. It is gone.
				 */
				tmp = cpu;
				cpu = list_next(&ctl->zsctl_cpus, cpu);
				list_remove(&ctl->zsctl_cpus, tmp);
				/* Clear structure for future use */
				id = tmp->zsc_id;
				bzero(tmp, sizeof (zsd_cpu_t));
				tmp->zsc_id = id;
				tmp->zsc_allocated = B_FALSE;
				tmp->zsc_psetid = ZS_PSET_ERROR;
				tmp->zsc_psetid_prev = ZS_PSET_ERROR;

			} else {
				/*
				 * cpu online at start of interval.  Treat
				 * as still online, since it was online for
				 * some portion of the interval.
				 */
				cpu->zsc_offlined = B_TRUE;
				cpu->zsc_onlined = B_FALSE;
				cpu->zsc_active = B_TRUE;
				cpu->zsc_psetid = cpu->zsc_psetid_prev;
				cpu->zsc_pset = NULL;
			}
		}
		cpu = list_next(&ctl->zsctl_cpus, cpu);
	}
}

/* Some utility functions for managing the list of processor sets */
static zsd_pset_t *
zsd_lookup_pset_byid(zsd_ctl_t *ctl, psetid_t psetid)
{
	zsd_pset_t *pset;

	for (pset = list_head(&ctl->zsctl_psets); pset != NULL;
	    pset = list_next(&ctl->zsctl_psets, pset)) {
		if (pset->zsp_id == psetid)
			return (pset);
	}
	return (NULL);
}

static zsd_pset_t *
zsd_lookup_pset(zsd_ctl_t *ctl, char *psetname, psetid_t psetid)
{
	zsd_pset_t *pset;

	for (pset = list_head(&ctl->zsctl_psets); pset != NULL;
	    pset = list_next(&ctl->zsctl_psets, pset)) {
		if (strcmp(pset->zsp_name, psetname) == 0) {
			if (psetid != -1)
				pset->zsp_id = psetid;
			return (pset);
		}
	}
	return (NULL);
}

static zsd_pset_t *
zsd_allocate_pset(zsd_ctl_t *ctl, char *psetname, psetid_t psetid)
{
	zsd_pset_t *pset;

	if ((pset = (zsd_pset_t *)calloc(1, sizeof (zsd_pset_t))) == NULL)
		return (NULL);

	(void) strlcpy(pset->zsp_name, psetname, sizeof (pset->zsp_name));
	pset->zsp_id = psetid;
	pset->zsp_found = B_FALSE;
	/*
	 * Allocate as deleted so if not found in first pass, pset is deleted
	 * from list.  This can happen if pset is returned by pset_list, but
	 * is destroyed before first attempt to fetch pset details.
	 */
	list_create(&pset->zsp_usage_list, sizeof (zsd_pset_usage_t),
	    offsetof(zsd_pset_usage_t, zsu_next));

	pset->zsp_hrstart = g_hrnow;
	pset->zsp_deleted = B_TRUE;
	pset->zsp_empty = B_TRUE;
	ctl->zsctl_npsets++;

	return (pset);
}

static zsd_pset_t *
zsd_lookup_insert_pset(zsd_ctl_t *ctl, char *psetname, psetid_t psetid)
{
	zsd_pset_t *pset, *tmp;

	if ((pset = zsd_lookup_pset(ctl, psetname, psetid)) != NULL)
		return (pset);

	if ((pset = zsd_allocate_pset(ctl, psetname, psetid)) == NULL)
		return (NULL);

	/* Insert sorted by psetname */
	tmp = list_head(&ctl->zsctl_psets);
	while (tmp != NULL && strcmp(psetname, tmp->zsp_name) > 0)
		tmp = list_next(&ctl->zsctl_psets, tmp);

	list_insert_before(&ctl->zsctl_psets, tmp, pset);
	return (pset);
}

/* Some utility functions for managing the list of zones using each pset */
static zsd_pset_usage_t *
zsd_lookup_usage(zsd_pset_t *pset, zsd_zone_t *zone)
{
	zsd_pset_usage_t *usage;

	for (usage = list_head(&pset->zsp_usage_list); usage != NULL;
	    usage = list_next(&pset->zsp_usage_list, usage))
		if (usage->zsu_zone == zone)
			return (usage);

	return (NULL);
}

static zsd_pset_usage_t *
zsd_allocate_pset_usage(zsd_ctl_t *ctl, zsd_pset_t *pset, zsd_zone_t *zone)
{
	zsd_pset_usage_t *usage;

	if ((usage = (zsd_pset_usage_t *)calloc(1, sizeof (zsd_pset_usage_t)))
	    == NULL)
		return (NULL);

	list_link_init(&usage->zsu_next);
	usage->zsu_zone = zone;
	usage->zsu_zoneid = zone->zsz_id;
	usage->zsu_pset = pset;
	usage->zsu_found = B_FALSE;
	usage->zsu_active = B_FALSE;
	usage->zsu_new = B_FALSE;
	/*
	 * Allocate as not deleted.  If a process is found in a pset for
	 * a zone, the usage will not be deleted until at least the next
	 * interval.
	 */
	usage->zsu_start = g_now;
	usage->zsu_hrstart = g_hrnow;
	usage->zsu_deleted = B_FALSE;
	usage->zsu_empty = B_TRUE;
	usage->zsu_scheds = 0;
	usage->zsu_cpu_shares = ZS_LIMIT_NONE;

	ctl->zsctl_npset_usages++;
	pset->zsp_nusage++;

	return (usage);
}

static zsd_pset_usage_t *
zsd_lookup_insert_usage(zsd_ctl_t *ctl, zsd_pset_t *pset, zsd_zone_t *zone)
{
	zsd_pset_usage_t *usage, *tmp;

	if ((usage = zsd_lookup_usage(pset, zone))
	    != NULL)
		return (usage);

	if ((usage = zsd_allocate_pset_usage(ctl, pset, zone)) == NULL)
		return (NULL);

	tmp = list_head(&pset->zsp_usage_list);
	while (tmp != NULL && strcmp(zone->zsz_name, tmp->zsu_zone->zsz_name)
	    > 0)
		tmp = list_next(&pset->zsp_usage_list, tmp);

	list_insert_before(&pset->zsp_usage_list, tmp, usage);
	return (usage);
}

static void
zsd_refresh_system(zsd_ctl_t *ctl)
{
	zsd_system_t *system = ctl->zsctl_system;

	/* Re-count these values each interval */
	system->zss_processes = 0;
	system->zss_lwps = 0;
	system->zss_shm = 0;
	system->zss_shmids = 0;
	system->zss_semids = 0;
	system->zss_msgids = 0;
	system->zss_lofi = 0;
}


/* Reads each cpu's kstats, and adds the usage to the cpu's pset */
static void
zsd_update_cpu_stats(zsd_ctl_t *ctl, zsd_cpu_t *cpu)
{
	zsd_system_t *sys;
	processorid_t cpuid;
	zsd_pset_t *pset_prev;
	zsd_pset_t *pset;
	kstat_t *kstat;
	kstat_named_t *knp;
	kid_t kid;
	uint64_t idle, intr, kern, user;

	sys = ctl->zsctl_system;
	pset = cpu->zsc_pset;
	knp = NULL;
	kid = -1;
	cpuid = cpu->zsc_id;

	/* Get the cpu time totals for this cpu */
	kstat = kstat_lookup(ctl->zsctl_kstat_ctl, "cpu", cpuid, "sys");
	if (kstat == NULL)
		return;

	kid = kstat_read(ctl->zsctl_kstat_ctl, kstat, NULL);
	if (kid == -1)
		return;

	knp = kstat_data_lookup(kstat, "cpu_nsec_idle");
	if (knp == NULL || knp->data_type != KSTAT_DATA_UINT64)
		return;

	idle = knp->value.ui64;

	knp = kstat_data_lookup(kstat, "cpu_nsec_kernel");
	if (knp == NULL || knp->data_type != KSTAT_DATA_UINT64)
		return;

	kern = knp->value.ui64;

	knp = kstat_data_lookup(kstat, "cpu_nsec_user");
	if (knp == NULL || knp->data_type != KSTAT_DATA_UINT64)
		return;

	user = knp->value.ui64;

	/*
	 * Tracking intr time per cpu just exists for future enhancements.
	 * The value is presently always zero.
	 */
	intr = 0;
	cpu->zsc_nsec_idle = idle;
	cpu->zsc_nsec_intr = intr;
	cpu->zsc_nsec_kern = kern;
	cpu->zsc_nsec_user = user;

	if (cpu->zsc_onlined == B_TRUE) {
		/*
		 * cpu is newly online.  There is no reference value,
		 * so just record its current stats for comparison
		 * on next stat read.
		 */
		cpu->zsc_nsec_idle_prev = cpu->zsc_nsec_idle;
		cpu->zsc_nsec_intr_prev = cpu->zsc_nsec_intr;
		cpu->zsc_nsec_kern_prev = cpu->zsc_nsec_kern;
		cpu->zsc_nsec_user_prev = cpu->zsc_nsec_user;
		return;
	}

	/*
	 * Calculate relative time since previous refresh.
	 * Paranoia.  Don't let time  go backwards.
	 */
	idle = intr = kern = user = 0;
	if (cpu->zsc_nsec_idle > cpu->zsc_nsec_idle_prev)
		idle = cpu->zsc_nsec_idle - cpu->zsc_nsec_idle_prev;

	if (cpu->zsc_nsec_intr > cpu->zsc_nsec_intr_prev)
		intr = cpu->zsc_nsec_intr - cpu->zsc_nsec_intr_prev;

	if (cpu->zsc_nsec_kern > cpu->zsc_nsec_kern_prev)
		kern = cpu->zsc_nsec_kern - cpu->zsc_nsec_kern_prev;

	if (cpu->zsc_nsec_user > cpu->zsc_nsec_user_prev)
		user = cpu->zsc_nsec_user - cpu->zsc_nsec_user_prev;

	/* Update totals for cpu usage */
	TIMESTRUC_ADD_NANOSEC(cpu->zsc_idle, idle);
	TIMESTRUC_ADD_NANOSEC(cpu->zsc_intr, intr);
	TIMESTRUC_ADD_NANOSEC(cpu->zsc_kern, kern);
	TIMESTRUC_ADD_NANOSEC(cpu->zsc_user, user);

	/*
	 * Add cpu's stats to its pset if it is known to be in
	 * the pset since previous read.
	 */
	if (cpu->zsc_psetid == cpu->zsc_psetid_prev ||
	    cpu->zsc_psetid_prev == ZS_PSET_ERROR ||
	    (pset_prev = zsd_lookup_pset_byid(ctl,
	    cpu->zsc_psetid_prev)) == NULL) {
		TIMESTRUC_ADD_NANOSEC(pset->zsp_idle, idle);
		TIMESTRUC_ADD_NANOSEC(pset->zsp_intr, intr);
		TIMESTRUC_ADD_NANOSEC(pset->zsp_kern, kern);
		TIMESTRUC_ADD_NANOSEC(pset->zsp_user, user);
	} else {
		/*
		 * Last pset was different than current pset.
		 * Best guess is to split usage between the two.
		 */
		TIMESTRUC_ADD_NANOSEC(pset_prev->zsp_idle, idle / 2);
		TIMESTRUC_ADD_NANOSEC(pset_prev->zsp_intr, intr / 2);
		TIMESTRUC_ADD_NANOSEC(pset_prev->zsp_kern, kern / 2);
		TIMESTRUC_ADD_NANOSEC(pset_prev->zsp_user, user / 2);

		TIMESTRUC_ADD_NANOSEC(pset->zsp_idle,
		    (idle / 2) + (idle % 2));
		TIMESTRUC_ADD_NANOSEC(pset->zsp_intr,
		    (intr / 2) + (intr % 2));
		TIMESTRUC_ADD_NANOSEC(pset->zsp_kern,
		    (kern / 2) + (kern % 2));
		TIMESTRUC_ADD_NANOSEC(pset->zsp_user,
		    (user / 2) + (user % 2));
	}
	TIMESTRUC_ADD_NANOSEC(sys->zss_idle, idle);
	TIMESTRUC_ADD_NANOSEC(sys->zss_intr, intr);
	TIMESTRUC_ADD_NANOSEC(sys->zss_kern, kern);
	TIMESTRUC_ADD_NANOSEC(sys->zss_user, user);
}

/* Determine the details of a processor set by pset_id */
static int
zsd_get_pool_pset(zsd_ctl_t *ctl, psetid_t psetid, char *psetname,
    size_t namelen, uint_t *cputype, uint64_t *online, uint64_t *size,
    uint64_t *min, uint64_t *max, int64_t *importance)
{
	uint_t old, num;

	pool_conf_t *conf = ctl->zsctl_pool_conf;
	pool_value_t **vals = ctl->zsctl_pool_vals;
	pool_resource_t **res_list = NULL;
	pool_resource_t *pset;
	pool_component_t **cpus = NULL;
	processorid_t *cache;
	const char *string;
	uint64_t uint64;
	int64_t int64;
	int i, ret, type;

	if (ctl->zsctl_pool_status == POOL_DISABLED) {

		/*
		 * Inspect legacy psets
		 */
		for (;;) {
			old = num = ctl->zsctl_cpu_ncache;
			ret = pset_info(psetid, &type, &num,
			    ctl->zsctl_cpu_cache);
			if (ret < 0) {
				/* pset is gone.  Tell caller to retry */
				errno = EINTR;
				return (-1);
			}
			if (num <= old) {
			/* Success */
				break;
			}
			if ((cache = (processorid_t *)realloc(
			    ctl->zsctl_cpu_cache, num *
			    sizeof (processorid_t))) != NULL) {
				ctl->zsctl_cpu_ncache = num;
				ctl->zsctl_cpu_cache = cache;
			} else {
				/*
				 * Could not allocate to get new cpu list.
				 */
				zsd_warn(gettext(
				    "Could not allocate for cpu list"));
				errno = ENOMEM;
				return (-1);
			}
		}
		/*
		 * Old school pset.  Just make min and max equal
		 * to its size
		 */
		if (psetid == ZS_PSET_DEFAULT) {
			*cputype = ZS_CPUTYPE_DEFAULT_PSET;
			(void) strlcpy(psetname, "pset_default", namelen);
		} else {
			*cputype = ZS_CPUTYPE_PSRSET_PSET;
			(void) snprintf(psetname, namelen,
			    "SUNWlegacy_pset_%d", psetid);
		}

		/*
		 * Just treat legacy pset as a simple pool pset
		 */
		*online = num;
		*size = num;
		*min = num;
		*max = num;
		*importance = 1;

		return (0);
	}

	/* Look up the pool pset using the pset id */
	res_list = NULL;
	pool_value_set_int64(vals[1], psetid);
	if (pool_value_set_name(vals[1], "pset.sys_id")
	    != PO_SUCCESS)
		goto err;

	if (pool_value_set_name(vals[0], "type") != PO_SUCCESS)
		goto err;
	if (pool_value_set_string(vals[0], "pset") != PO_SUCCESS)
		goto err;
	if ((res_list = pool_query_resources(conf, &num, vals)) == NULL)
		goto err;
	if (num != 1)
		goto err;
	pset = res_list[0];
	free(res_list);
	res_list = NULL;
	if (pool_get_property(conf, pool_resource_to_elem(conf, pset),
	    "pset.name", vals[0]) != POC_STRING ||
	    pool_value_get_string(vals[0], &string) != PO_SUCCESS)
		goto err;

	(void) strlcpy(psetname, string, namelen);
	if (strncmp(psetname, "SUNWtmp", strlen("SUNWtmp")) == 0)
		*cputype = ZS_CPUTYPE_DEDICATED;
	else if (psetid == ZS_PSET_DEFAULT)
		*cputype = ZS_CPUTYPE_DEFAULT_PSET;
	else
		*cputype = ZS_CPUTYPE_POOL_PSET;

	/* Get size, min, max, and importance */
	if (pool_get_property(conf, pool_resource_to_elem(conf,
	    pset), "pset.size", vals[0]) == POC_UINT &&
	    pool_value_get_uint64(vals[0], &uint64) == PO_SUCCESS)
		*size = uint64;
	else
		*size = 0;

		/* Get size, min, max, and importance */
	if (pool_get_property(conf, pool_resource_to_elem(conf,
	    pset), "pset.min", vals[0]) == POC_UINT &&
	    pool_value_get_uint64(vals[0], &uint64) == PO_SUCCESS)
		*min = uint64;
	else
		*min = 0;
	if (*min >= ZSD_PSET_UNLIMITED)
		*min = ZS_LIMIT_NONE;

	if (pool_get_property(conf, pool_resource_to_elem(conf,
	    pset), "pset.max", vals[0]) == POC_UINT &&
	    pool_value_get_uint64(vals[0], &uint64) == PO_SUCCESS)
		*max = uint64;
	else
		*max = ZS_LIMIT_NONE;

	if (*max >= ZSD_PSET_UNLIMITED)
		*max = ZS_LIMIT_NONE;

	if (pool_get_property(conf, pool_resource_to_elem(conf,
	    pset), "pset.importance", vals[0]) == POC_INT &&
	    pool_value_get_int64(vals[0], &int64) == PO_SUCCESS)
		*importance = int64;
	else
		*importance = (uint64_t)1;

	*online = 0;
	if (*size == 0)
		return (0);

	/* get cpus */
	cpus = pool_query_resource_components(conf, pset, &num, NULL);
	if (cpus == NULL)
		goto err;

	/* Make sure there is space for cpu id list */
	if (num > ctl->zsctl_cpu_ncache) {
		if ((cache = (processorid_t *)realloc(
		    ctl->zsctl_cpu_cache, num *
		    sizeof (processorid_t))) != NULL) {
			ctl->zsctl_cpu_ncache = num;
			ctl->zsctl_cpu_cache = cache;
		} else {
			/*
			 * Could not allocate to get new cpu list.
			 */
			zsd_warn(gettext(
			    "Could not allocate for cpu list"));
			goto err;
		}
	}

	/* count the online cpus */
	for (i = 0; i < num; i++) {
		if (pool_get_property(conf, pool_component_to_elem(
		    conf, cpus[i]), "cpu.status", vals[0]) != POC_STRING ||
		    pool_value_get_string(vals[0], &string) != PO_SUCCESS)
			goto err;

		if (strcmp(string, "on-line") != 0 &&
		    strcmp(string, "no-intr") != 0)
			continue;

		if (pool_get_property(conf, pool_component_to_elem(
		    conf, cpus[i]), "cpu.sys_id", vals[0]) != POC_INT ||
		    pool_value_get_int64(vals[0], &int64) != PO_SUCCESS)
			goto err;

		(*online)++;
		ctl->zsctl_cpu_cache[i] = (psetid_t)int64;
	}
	free(cpus);
	return (0);
err:
	if (res_list != NULL)
		free(res_list);
	if (cpus != NULL)
		free(cpus);

	/*
	 * The pools operations should succeed since the conf is a consistent
	 * snapshot.  Tell caller there is no need to retry.
	 */
	errno = EINVAL;
	return (-1);
}

/*
 * Update the current list of processor sets.
 * This also updates the list of online cpus, and each cpu's pset membership.
 */
static void
zsd_refresh_psets(zsd_ctl_t *ctl)
{
	int i, j, ret, state;
	uint_t old, num;
	uint_t cputype;
	int64_t sys_id, importance;
	uint64_t online, size, min, max;
	zsd_system_t *system;
	zsd_pset_t *pset;
	zsd_cpu_t *cpu;
	psetid_t *cache;
	char psetname[ZS_PSETNAME_MAX];
	processorid_t cpuid;
	pool_value_t *pv_save = NULL;
	pool_resource_t **res_list = NULL;
	pool_resource_t *res;
	pool_value_t **vals;
	pool_conf_t *conf;
	boolean_t roll_cpus = B_TRUE;

	/* Zero cpu counters to recount them */
	system = ctl->zsctl_system;
	system->zss_ncpus = 0;
	system->zss_ncpus_online = 0;
retry:
	ret = pool_get_status(&state);
	if (ret == 0 && state == POOL_ENABLED) {

		conf = ctl->zsctl_pool_conf;
		vals = ctl->zsctl_pool_vals;
		pv_save = vals[1];
		vals[1] = NULL;

		if (ctl->zsctl_pool_status == POOL_DISABLED) {
			if (pool_conf_open(ctl->zsctl_pool_conf,
			    pool_dynamic_location(), PO_RDONLY) == 0) {
				ctl->zsctl_pool_status = POOL_ENABLED;
				ctl->zsctl_pool_changed = POU_PSET;
			}
		} else {
			ctl->zsctl_pool_changed = 0;
			ret = pool_conf_update(ctl->zsctl_pool_conf,
			    &(ctl->zsctl_pool_changed));
			if (ret < 0) {
				/* Pools must have become disabled */
				(void) pool_conf_close(ctl->zsctl_pool_conf);
				ctl->zsctl_pool_status = POOL_DISABLED;
				if (pool_error() == POE_SYSTEM && errno ==
				    ENOTACTIVE)
					goto retry;

				zsd_warn(gettext(
				    "Unable to update pool configuration"));
				/* Not able to get pool info.  Don't update. */
				goto err;
			}
		}
		/* Get the list of psets using libpool */
		if (pool_value_set_name(vals[0], "type") != PO_SUCCESS)
			goto err;

		if (pool_value_set_string(vals[0], "pset") != PO_SUCCESS)
			goto err;
		if ((res_list = pool_query_resources(conf, &num, vals))
		    == NULL)
			goto err;

		if (num > ctl->zsctl_pset_ncache)  {
			if ((cache = (psetid_t *)realloc(ctl->zsctl_pset_cache,
			    (num) * sizeof (psetid_t))) == NULL) {
				goto err;
			}
			ctl->zsctl_pset_ncache = num;
			ctl->zsctl_pset_cache = cache;
		}
		/* Save the pset id of each pset */
		for (i = 0; i < num; i++) {
			res = res_list[i];
			if (pool_get_property(conf, pool_resource_to_elem(conf,
			    res), "pset.sys_id", vals[0]) != POC_INT ||
			    pool_value_get_int64(vals[0], &sys_id)
			    != PO_SUCCESS)
				goto err;
			ctl->zsctl_pset_cache[i] = (int)sys_id;
		}
		vals[1] = pv_save;
		pv_save = NULL;
	} else {
		if (ctl->zsctl_pool_status == POOL_ENABLED) {
			(void) pool_conf_close(ctl->zsctl_pool_conf);
			ctl->zsctl_pool_status = POOL_DISABLED;
		}
		/* Get the pset list using legacy psets */
		for (;;) {
			old = num = ctl->zsctl_pset_ncache;
			(void) pset_list(ctl->zsctl_pset_cache, &num);
			if ((num + 1) <= old) {
				break;
			}
			if ((cache = (psetid_t *)realloc(ctl->zsctl_pset_cache,
			    (num + 1) * sizeof (psetid_t))) != NULL) {
				ctl->zsctl_pset_ncache = num + 1;
				ctl->zsctl_pset_cache = cache;
			} else {
				/*
				 * Could not allocate to get new pset list.
				 * Give up
				 */
				return;
			}
		}
		/* Add the default pset to list */
		ctl->zsctl_pset_cache[num] = ctl->zsctl_pset_cache[0];
		ctl->zsctl_pset_cache[0] = ZS_PSET_DEFAULT;
		num++;
	}
psets_changed:
	zsd_mark_cpus_start(ctl, roll_cpus);
	zsd_mark_psets_start(ctl);
	roll_cpus = B_FALSE;

	/* Refresh cpu membership of all psets */
	for (i = 0; i < num; i++) {

		/* Get pool pset information */
		sys_id = ctl->zsctl_pset_cache[i];
		if (zsd_get_pool_pset(ctl, sys_id, psetname, sizeof (psetname),
		    &cputype, &online, &size, &min, &max, &importance)
		    != 0) {
			if (errno == EINTR)
				goto psets_changed;
			zsd_warn(gettext("Failed to get info for pset %d"),
			    sys_id);
			continue;
		}

		system->zss_ncpus += size;
		system->zss_ncpus_online += online;

		pset = zsd_lookup_insert_pset(ctl, psetname,
		    ctl->zsctl_pset_cache[i]);

		/* update pset info */
		zsd_mark_pset_found(pset, cputype, online, size, min,
		    max, importance);

		/* update each cpu in pset */
		for (j = 0; j < pset->zsp_online; j++) {
			cpuid = ctl->zsctl_cpu_cache[j];
			cpu = zsd_lookup_insert_cpu(ctl, cpuid);
			zsd_mark_cpu_found(cpu, pset, sys_id);
		}
	}
err:
	if (res_list != NULL)
		free(res_list);
	if (pv_save != NULL)
		vals[1] = pv_save;
}



/*
 * Fetch the current pool and pset name for the given zone.
 */
static void
zsd_get_zone_pool_pset(zsd_ctl_t *ctl, zsd_zone_t *zone,
    char *pool, int poollen, char *pset, int psetlen, uint_t *cputype)
{
	poolid_t poolid;
	pool_t **pools = NULL;
	pool_resource_t **res_list = NULL;
	char poolname[ZS_POOLNAME_MAX];
	char psetname[ZS_PSETNAME_MAX];
	pool_conf_t *conf = ctl->zsctl_pool_conf;
	pool_value_t *pv_save = NULL;
	pool_value_t **vals = ctl->zsctl_pool_vals;
	const char *string;
	int ret;
	int64_t int64;
	uint_t num;

	ret = zone_getattr(zone->zsz_id, ZONE_ATTR_POOLID,
	    &poolid, sizeof (poolid));
	if (ret < 0)
		goto lookup_done;

	pv_save = vals[1];
	vals[1] = NULL;
	pools = NULL;
	res_list = NULL;

	/* Default values if lookup fails */
	(void) strlcpy(poolname, "pool_default", sizeof (poolname));
	(void) strlcpy(psetname, "pset_default", sizeof (poolname));
	*cputype = ZS_CPUTYPE_DEFAULT_PSET;

	/* no dedicated cpu if pools are disabled */
	if (ctl->zsctl_pool_status == POOL_DISABLED)
		goto lookup_done;

	/* Get the pool name using the id */
	pool_value_set_int64(vals[0], poolid);
	if (pool_value_set_name(vals[0], "pool.sys_id") != PO_SUCCESS)
		goto lookup_done;

	if ((pools = pool_query_pools(conf, &num, vals)) == NULL)
		goto lookup_done;

	if (num != 1)
		goto lookup_done;

	if (pool_get_property(conf, pool_to_elem(conf, pools[0]),
	    "pool.name", vals[0]) != POC_STRING ||
	    pool_value_get_string(vals[0], &string) != PO_SUCCESS)
		goto lookup_done;
	(void) strlcpy(poolname, (char *)string, sizeof (poolname));

	/* Get the name of the pset for the pool */
	if (pool_value_set_name(vals[0], "type") != PO_SUCCESS)
		goto lookup_done;

	if (pool_value_set_string(vals[0], "pset") != PO_SUCCESS)
		goto lookup_done;

	if ((res_list = pool_query_pool_resources(conf, pools[0], &num, vals))
	    == NULL)
		goto lookup_done;

	if (num != 1)
		goto lookup_done;

	if (pool_get_property(conf, pool_resource_to_elem(conf,
	    res_list[0]), "pset.sys_id", vals[0]) != POC_INT ||
	    pool_value_get_int64(vals[0], &int64) != PO_SUCCESS)
		goto lookup_done;

	if (int64 == ZS_PSET_DEFAULT)
		*cputype = ZS_CPUTYPE_DEFAULT_PSET;

	if (pool_get_property(conf, pool_resource_to_elem(conf,
	    res_list[0]), "pset.name", vals[0]) != POC_STRING ||
	    pool_value_get_string(vals[0], &string) != PO_SUCCESS)
		goto lookup_done;

	(void) strlcpy(psetname, (char *)string, sizeof (psetname));

	if (strncmp(psetname, "SUNWtmp_", strlen("SUNWtmp_")) == 0)
		*cputype = ZS_CPUTYPE_DEDICATED;
	if (strncmp(psetname, "SUNW_legacy_", strlen("SUNW_legacy_")) == 0)
		*cputype = ZS_CPUTYPE_PSRSET_PSET;
	else
		*cputype = ZS_CPUTYPE_POOL_PSET;

lookup_done:

	if (pv_save != NULL)
		vals[1] = pv_save;

	if (res_list)
		free(res_list);
	if (pools)
		free(pools);

	(void) strlcpy(pool, poolname, poollen);
	(void) strlcpy(pset, psetname, psetlen);
}

/* Convert scheduler names to ZS_* scheduler flags */
static uint_t
zsd_schedname2int(char *clname, int pri)
{
	uint_t sched = 0;

	if (strcmp(clname, "TS") == 0) {
		sched = ZS_SCHED_TS;
	} else if (strcmp(clname, "IA") == 0) {
		sched = ZS_SCHED_IA;
	} else if (strcmp(clname, "FX") == 0) {
		if (pri > 59) {
			sched = ZS_SCHED_FX_60;
		} else {
			sched = ZS_SCHED_FX;
		}
	} else if (strcmp(clname, "RT") == 0) {
		sched = ZS_SCHED_RT;

	} else if (strcmp(clname, "FSS") == 0) {
		sched = ZS_SCHED_FSS;
	}
	return (sched);
}

static uint64_t
zsd_get_zone_rctl_limit(char *name)
{
	rctlblk_t *rblk;

	rblk = (rctlblk_t *)alloca(rctlblk_size());
	if (getrctl(name, NULL, rblk, RCTL_FIRST)
	    != 0) {
		return (ZS_LIMIT_NONE);
	}
	return (rctlblk_get_value(rblk));
}

static uint64_t
zsd_get_zone_rctl_usage(char *name)
{
	rctlblk_t *rblk;

	rblk = (rctlblk_t *)alloca(rctlblk_size());
	if (getrctl(name, NULL, rblk, RCTL_USAGE)
	    != 0) {
		return (0);
	}
	return (rctlblk_get_value(rblk));
}

#define	ZSD_NUM_RCTL_VALS 19

/*
 * Fetch the limit information for a zone.  This uses zone_enter() as the
 * getrctl(2) system call only returns rctl information for the zone of
 * the caller.
 */
static int
zsd_get_zone_caps(zsd_ctl_t *ctl, zsd_zone_t *zone, uint64_t *cpu_shares,
    uint64_t *cpu_cap, uint64_t *ram_cap, uint64_t *locked_cap,
    uint64_t *vm_cap, uint64_t *processes_cap, uint64_t *processes,
    uint64_t *lwps_cap, uint64_t *lwps, uint64_t *shm_cap, uint64_t *shm,
    uint64_t *shmids_cap, uint64_t *shmids, uint64_t *semids_cap,
    uint64_t *semids, uint64_t *msgids_cap, uint64_t *msgids,
    uint64_t *lofi_cap, uint64_t *lofi, uint_t *sched)
{
	int p[2], pid, tmpl_fd, ret;
	ctid_t ct;
	char class[PC_CLNMSZ];
	uint64_t vals[ZSD_NUM_RCTL_VALS];
	zsd_system_t *sys = ctl->zsctl_system;
	int i = 0;
	int res = 0;

	/* Treat all caps as no cap on error */
	*cpu_shares = ZS_LIMIT_NONE;
	*cpu_cap = ZS_LIMIT_NONE;
	*ram_cap = ZS_LIMIT_NONE;
	*locked_cap = ZS_LIMIT_NONE;
	*vm_cap = ZS_LIMIT_NONE;

	*processes_cap = ZS_LIMIT_NONE;
	*lwps_cap = ZS_LIMIT_NONE;
	*shm_cap = ZS_LIMIT_NONE;
	*shmids_cap = ZS_LIMIT_NONE;
	*semids_cap = ZS_LIMIT_NONE;
	*msgids_cap = ZS_LIMIT_NONE;
	*lofi_cap = ZS_LIMIT_NONE;

	*processes = 0;
	*lwps = 0;
	*shm = 0;
	*shmids = 0;
	*semids = 0;
	*msgids = 0;
	*lofi = 0;

	/* Get the ram cap first since it is a zone attr */
	ret = zone_getattr(zone->zsz_id, ZONE_ATTR_PHYS_MCAP,
	    ram_cap, sizeof (*ram_cap));
	if (ret < 0 || *ram_cap == 0)
		*ram_cap = ZS_LIMIT_NONE;

	/* Get the zone's default scheduling class */
	ret = zone_getattr(zone->zsz_id, ZONE_ATTR_SCHED_CLASS,
	    class, sizeof (class));
	if (ret < 0)
		return (-1);

	*sched = zsd_schedname2int(class, 0);

	/* rctl caps must be fetched from within the zone */
	if (pipe(p) != 0)
		return (-1);

	if ((tmpl_fd = init_template()) == -1) {
		(void) close(p[0]);
		(void) close(p[1]);
		return (-1);
	}
	pid = forkx(0);
	if (pid < 0) {
		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(p[0]);
		(void) close(p[1]);
		return (-1);
	}
	if (pid == 0) {

		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		(void) close(p[0]);
		if (zone->zsz_id != getzoneid()) {
			if (zone_enter(zone->zsz_id) < 0) {
				(void) close(p[1]);
				_exit(0);
			}
		}

		/* Get caps for zone, and write them to zonestatd parent. */
		vals[i++] = zsd_get_zone_rctl_limit("zone.cpu-shares");
		vals[i++] = zsd_get_zone_rctl_limit("zone.cpu-cap");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-locked-memory");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-swap");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-processes");
		vals[i++] = zsd_get_zone_rctl_usage("zone.max-processes");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-lwps");
		vals[i++] = zsd_get_zone_rctl_usage("zone.max-lwps");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-shm-memory");
		vals[i++] = zsd_get_zone_rctl_usage("zone.max-shm-memory");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-shm-ids");
		vals[i++] = zsd_get_zone_rctl_usage("zone.max-shm-ids");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-sem-ids");
		vals[i++] = zsd_get_zone_rctl_usage("zone.max-sem-ids");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-msg-ids");
		vals[i++] = zsd_get_zone_rctl_usage("zone.max-msg-ids");
		vals[i++] = zsd_get_zone_rctl_limit("zone.max-lofi");
		vals[i++] = zsd_get_zone_rctl_usage("zone.max-lofi");

		if (write(p[1], vals, ZSD_NUM_RCTL_VALS * sizeof (uint64_t)) !=
		    ZSD_NUM_RCTL_VALS * sizeof (uint64_t)) {
			(void) close(p[1]);
			_exit(1);
		}

		(void) close(p[1]);
		_exit(0);
	}
	if (contract_latest(&ct) == -1)
		ct = -1;

	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);
	(void) close(p[1]);
	while (waitpid(pid, NULL, 0) != pid)
		;

	/* Read cap from child in zone */
	if (read(p[0], vals, ZSD_NUM_RCTL_VALS * sizeof (uint64_t)) !=
	    ZSD_NUM_RCTL_VALS * sizeof (uint64_t)) {
		res = -1;
		goto cleanup;
	}
	i = 0;
	*cpu_shares = vals[i++];
	*cpu_cap = vals[i++];
	*locked_cap = vals[i++];
	*vm_cap = vals[i++];
	*processes_cap = vals[i++];
	*processes = vals[i++];
	*lwps_cap = vals[i++];
	*lwps = vals[i++];
	*shm_cap = vals[i++];
	*shm = vals[i++];
	*shmids_cap = vals[i++];
	*shmids = vals[i++];
	*semids_cap = vals[i++];
	*semids = vals[i++];
	*msgids_cap = vals[i++];
	*msgids = vals[i++];
	*lofi_cap = vals[i++];
	*lofi = vals[i++];

	/* Interpret maximum values as no cap */
	if (*cpu_cap == UINT32_MAX || *cpu_cap == 0)
		*cpu_cap = ZS_LIMIT_NONE;
	if (*processes_cap == sys->zss_processes_max)
		*processes_cap = ZS_LIMIT_NONE;
	if (*lwps_cap == sys->zss_lwps_max)
		*lwps_cap = ZS_LIMIT_NONE;
	if (*shm_cap == sys->zss_shm_max)
		*shm_cap = ZS_LIMIT_NONE;
	if (*shmids_cap == sys->zss_shmids_max)
		*shmids_cap = ZS_LIMIT_NONE;
	if (*semids_cap == sys->zss_semids_max)
		*semids_cap = ZS_LIMIT_NONE;
	if (*msgids_cap == sys->zss_msgids_max)
		*msgids_cap = ZS_LIMIT_NONE;
	if (*lofi_cap == sys->zss_lofi_max)
		*lofi_cap = ZS_LIMIT_NONE;


cleanup:
	(void) close(p[0]);
	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);
	(void) contract_abandon_id(ct);

	return (res);
}

/* Update the current list of running zones */
static void
zsd_refresh_zones(zsd_ctl_t *ctl)
{
	zsd_zone_t *zone;
	uint_t old, num;
	ushort_t flags;
	int i, ret;
	zoneid_t *cache;
	uint64_t cpu_shares;
	uint64_t cpu_cap;
	uint64_t ram_cap;
	uint64_t locked_cap;
	uint64_t vm_cap;
	uint64_t processes_cap;
	uint64_t processes;
	uint64_t lwps_cap;
	uint64_t lwps;
	uint64_t shm_cap;
	uint64_t shm;
	uint64_t shmids_cap;
	uint64_t shmids;
	uint64_t semids_cap;
	uint64_t semids;
	uint64_t msgids_cap;
	uint64_t msgids;
	uint64_t lofi_cap;
	uint64_t lofi;

	char zonename[ZS_ZONENAME_MAX];
	char poolname[ZS_POOLNAME_MAX];
	char psetname[ZS_PSETNAME_MAX];
	uint_t sched;
	uint_t cputype;
	uint_t iptype;

	/* Get the current list of running zones */
	for (;;) {
		old = num = ctl->zsctl_zone_ncache;
		(void) zone_list(ctl->zsctl_zone_cache, &num);
		if (num <= old)
			break;
		if ((cache = (zoneid_t *)realloc(ctl->zsctl_zone_cache,
		    (num) * sizeof (zoneid_t))) != NULL) {
			ctl->zsctl_zone_ncache = num;
			ctl->zsctl_zone_cache = cache;
		} else {
			/* Could not allocate to get new zone list.  Give up */
			return;
		}
	}

	zsd_mark_zones_start(ctl);

	for (i = 0; i < num; i++) {

		ret = getzonenamebyid(ctl->zsctl_zone_cache[i],
		    zonename, sizeof (zonename));
		if (ret < 0)
			continue;

		zone = zsd_lookup_insert_zone(ctl, zonename,
		    ctl->zsctl_zone_cache[i]);

		ret = zone_getattr(ctl->zsctl_zone_cache[i], ZONE_ATTR_FLAGS,
		    &flags, sizeof (flags));
		if (ret < 0)
			continue;

		if (flags & ZF_NET_EXCL)
			iptype = ZS_IPTYPE_EXCLUSIVE;
		else
			iptype = ZS_IPTYPE_SHARED;

		zsd_get_zone_pool_pset(ctl, zone, poolname, sizeof (poolname),
		    psetname, sizeof (psetname), &cputype);

		if (zsd_get_zone_caps(ctl, zone, &cpu_shares, &cpu_cap,
		    &ram_cap, &locked_cap, &vm_cap, &processes_cap, &processes,
		    &lwps_cap, &lwps, &shm_cap, &shm, &shmids_cap, &shmids,
		    &semids_cap, &semids, &msgids_cap, &msgids, &lofi_cap,
		    &lofi, &sched) != 0)
			continue;

		zsd_mark_zone_found(ctl, zone, cpu_shares, cpu_cap, ram_cap,
		    locked_cap, vm_cap, processes_cap, processes, lwps_cap,
		    lwps, shm_cap, shm, shmids_cap, shmids, semids_cap,
		    semids, msgids_cap, msgids, lofi_cap, lofi, poolname,
		    psetname, sched, cputype, iptype);
	}
}

/* Fetch the details of a process from its psinfo_t */
static void
zsd_get_proc_info(zsd_ctl_t *ctl, psinfo_t *psinfo, psetid_t *psetid,
    psetid_t *prev_psetid, zoneid_t *zoneid, zoneid_t *prev_zoneid,
    timestruc_t *delta, uint_t *sched)
{
	timestruc_t d;
	zsd_proc_t *proc;

	/* Get cached data for proc */
	proc = &(ctl->zsctl_proc_array[psinfo->pr_pid]);
	*psetid = psinfo->pr_lwp.pr_bindpset;

	if (proc->zspr_psetid == ZS_PSET_ERROR)
		*prev_psetid = *psetid;
	else
		*prev_psetid = proc->zspr_psetid;

	*zoneid = psinfo->pr_zoneid;
	if (proc->zspr_zoneid == -1)
		*prev_zoneid = *zoneid;
	else
		*prev_zoneid = proc->zspr_zoneid;

	TIMESTRUC_DELTA(d, psinfo->pr_time, proc->zspr_usage);
	*delta = d;

	*sched = zsd_schedname2int(psinfo->pr_lwp.pr_clname,
	    psinfo->pr_lwp.pr_pri);

	/* Update cached data for proc */
	proc->zspr_psetid = psinfo->pr_lwp.pr_bindpset;
	proc->zspr_zoneid = psinfo->pr_zoneid;
	proc->zspr_sched = *sched;
	proc->zspr_usage.tv_sec = psinfo->pr_time.tv_sec;
	proc->zspr_usage.tv_nsec = psinfo->pr_time.tv_nsec;
	proc->zspr_ppid = psinfo->pr_ppid;
}

/*
 * Reset the known cpu usage of a process. This is done after a process
 * exits so that if the pid is recycled, data from its previous life is
 * not reused
 */
static void
zsd_flush_proc_info(zsd_proc_t *proc)
{
	proc->zspr_usage.tv_sec = 0;
	proc->zspr_usage.tv_nsec = 0;
}

/*
 * Open the current extended accounting file.  On initialization, open the
 * file as the current file to be used.  Otherwise, open the file as the
 * next file to use of the current file reaches EOF.
 */
static int
zsd_open_exacct(zsd_ctl_t *ctl, boolean_t init)
{
	int ret, oret, state, trys = 0, flags;
	int *fd, *open;
	ea_file_t *eaf;
	struct stat64 *stat;
	char path[MAXPATHLEN];

	/*
	 * The accounting file is first opened at the tail.  Following
	 * opens to new accounting files are opened at the head.
	 */
	if (init == B_TRUE) {
		flags = EO_NO_VALID_HDR | EO_TAIL;
		fd = &ctl->zsctl_proc_fd;
		eaf = &ctl->zsctl_proc_eaf;
		stat = &ctl->zsctl_proc_stat;
		open = &ctl->zsctl_proc_open;
	} else {
		flags = EO_NO_VALID_HDR | EO_HEAD;
		fd = &ctl->zsctl_proc_fd_next;
		eaf = &ctl->zsctl_proc_eaf_next;
		stat = &ctl->zsctl_proc_stat_next;
		open = &ctl->zsctl_proc_open_next;
	}

	*fd = -1;
	*open = 0;
retry:
	/* open accounting files for cpu consumption */
	ret = acctctl(AC_STATE_GET | AC_PROC, &state, sizeof (state));
	if (ret != 0) {
		zsd_warn(gettext("Unable to get process accounting state"));
		goto err;
	}
	if (state != AC_ON) {
		if (trys > 0) {
			zsd_warn(gettext(
			    "Unable to enable process accounting"));
			goto err;
		}
		(void) zsd_enable_cpu_stats();
		trys++;
		goto retry;
	}

	ret = acctctl(AC_FILE_GET | AC_PROC, path, sizeof (path));
	if (ret != 0) {
		zsd_warn(gettext("Unable to get process accounting file"));
		goto err;
	}

	if ((*fd = open64(path, O_RDONLY, 0)) >= 0 &&
	    (oret = ea_fdopen(eaf, *fd, NULL, flags, O_RDONLY)) == 0)
		ret = fstat64(*fd, stat);

	if (*fd < 0 || oret < 0 || ret < 0) {
		struct timespec ts;

		/*
		 * It is possible the accounting file is momentarily unavailable
		 * because it is being rolled.  Try for up to half a second.
		 *
		 * If failure to open accounting file persists, give up.
		 */
		if (oret == 0)
			(void) ea_close(eaf);
		else if (*fd >= 0)
			(void) close(*fd);
		if (trys > 500) {
			zsd_warn(gettext(
			    "Unable to open process accounting file"));
			goto err;
		}
		/* wait one millisecond */
		ts.tv_sec = 0;
		ts.tv_nsec = NANOSEC / 1000;
		(void) nanosleep(&ts, NULL);
		goto retry;
	}
	*open = 1;
	return (0);
err:
	if (*fd >= 0)
		(void) close(*fd);
	*open = 0;
	*fd = -1;
	return (-1);
}

/*
 * Walk /proc and charge each process to its zone and processor set.
 * Then read exacct data for exited processes, and charge them as well.
 */
static void
zsd_refresh_procs(zsd_ctl_t *ctl, boolean_t init)
{
	DIR *dir;
	struct dirent *dent;
	psinfo_t psinfo;
	int fd, ret;
	zsd_proc_t *proc, *pproc, *tmp, *next;
	list_t pplist, plist;
	zsd_zone_t *zone, *prev_zone;
	zsd_pset_t *pset, *prev_pset;
	psetid_t psetid, prev_psetid;
	zoneid_t zoneid, prev_zoneid;
	zsd_pset_usage_t *usage, *prev_usage;
	char path[MAXPATHLEN];

	ea_object_t object;
	ea_object_t pobject;
	boolean_t hrtime_expired = B_FALSE;
	struct timeval interval_end;

	timestruc_t delta, d1, d2;
	uint_t sched = 0;

	/*
	 * Get the current accounting file.  The current accounting file
	 * may be different than the file in use, as the accounting file
	 * may have been rolled, or manually changed by an admin.
	 */
	ret = zsd_open_exacct(ctl, init);
	if (ret != 0) {
		zsd_warn(gettext("Unable to track process accounting"));
		return;
	}

	/*
	 * Mark the current time as the interval end time.  Don't track
	 * processes that exit after this time.
	 */
	(void) gettimeofday(&interval_end, NULL);

	dir = opendir("/proc");
	if (dir == NULL) {
		zsd_warn(gettext("Unable to open /proc"));
		return;
	}

	/* Walk all processes and compute each zone's usage on each pset. */
	while ((dent = readdir(dir)) != NULL) {

		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		(void) snprintf(path, sizeof (path), "/proc/%s/psinfo",
		    dent->d_name);

		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;

		if (read(fd, &psinfo, sizeof (psinfo)) != sizeof (psinfo)) {
			(void) close(fd);
			continue;
		}
		(void) close(fd);

		zsd_get_proc_info(ctl, &psinfo, &psetid, &prev_psetid,
		    &zoneid, &prev_zoneid, &delta, &sched);

		d1.tv_sec = delta.tv_sec / 2;
		d1.tv_nsec = delta.tv_nsec / 2;
		d2.tv_sec = (delta.tv_sec / 2) + (delta.tv_sec % 2);
		d2.tv_nsec = (delta.tv_nsec / 2) + (delta.tv_nsec % 2);

		/* Get the zone and pset this process is running in */
		zone = zsd_lookup_zone_byid(ctl, zoneid);
		if (zone == NULL)
			continue;
		pset = zsd_lookup_pset_byid(ctl, psetid);
		if (pset == NULL)
			continue;
		usage = zsd_lookup_insert_usage(ctl, pset, zone);
		if (usage == NULL)
			continue;

		/*
		 * Get the usage of the previous zone and pset if they were
		 * different.
		 */
		if (zoneid != prev_zoneid)
			prev_zone = zsd_lookup_zone_byid(ctl, prev_zoneid);
		else
			prev_zone = NULL;

		if (psetid != prev_psetid)
			prev_pset = zsd_lookup_pset_byid(ctl, prev_psetid);
		else
			prev_pset = NULL;

		prev_usage = NULL;
		if (prev_zone != NULL || prev_pset != NULL) {
			if (prev_zone == NULL)
				prev_zone = zone;
			if (prev_pset == NULL)
				prev_pset = pset;

			prev_usage = zsd_lookup_insert_usage(ctl, prev_pset,
			    prev_zone);
		}

		/* Update the usage with the processes info */
		if (prev_usage == NULL) {
			zsd_mark_pset_usage_found(usage, sched);
		} else {
			zsd_mark_pset_usage_found(usage, sched);
			zsd_mark_pset_usage_found(prev_usage, sched);
		}

		/*
		 * First time around is just to get a starting point.  All
		 * usages will be zero.
		 */
		if (init == B_TRUE)
			continue;

		if (prev_usage == NULL) {
			zsd_add_usage(ctl, usage, &delta);
		} else {
			zsd_add_usage(ctl, usage, &d1);
			zsd_add_usage(ctl, prev_usage, &d2);
		}
	}
	(void) closedir(dir);

	/*
	 * No need to collect exited proc data on initialization.  Just
	 * caching the usage of the known processes to get a zero starting
	 * point.
	 */
	if (init == B_TRUE)
		return;

	/*
	 * Add accounting records to account for processes which have
	 * exited.
	 */
	list_create(&plist, sizeof (zsd_proc_t),
	    offsetof(zsd_proc_t, zspr_next));
	list_create(&pplist, sizeof (zsd_proc_t),
	    offsetof(zsd_proc_t, zspr_next));

	for (;;) {
		pid_t pid;
		pid_t ppid;
		timestruc_t user, sys, proc_usage;
		timestruc_t finish;
		int numfound = 0;

		bzero(&object, sizeof (object));
		proc = NULL;
		zone = NULL;
		pset = NULL;
		usage = NULL;
		ret = ea_get_object(&ctl->zsctl_proc_eaf, &object);
		if (ret == EO_ERROR) {
			if (ea_error() == EXR_EOF) {

				struct stat64 *stat;
				struct stat64 *stat_next;

				/*
				 * See if the next accounting file is the
				 * same as the current accounting file.
				 */
				stat = &(ctl->zsctl_proc_stat);
				stat_next = &(ctl->zsctl_proc_stat_next);
				if (stat->st_ino == stat_next->st_ino &&
				    stat->st_dev == stat_next->st_dev) {
					/*
					 * End of current accounting file is
					 * reached, so finished.  Clear EOF
					 * bit for next time around.
					 */
					ea_clear(&ctl->zsctl_proc_eaf);
					break;
				} else {
					/*
					 * Accounting file has changed.  Move
					 * to current accounting file.
					 */
					(void) ea_close(&ctl->zsctl_proc_eaf);

					ctl->zsctl_proc_fd =
					    ctl->zsctl_proc_fd_next;
					ctl->zsctl_proc_eaf =
					    ctl->zsctl_proc_eaf_next;
					ctl->zsctl_proc_stat =
					    ctl->zsctl_proc_stat_next;

					ctl->zsctl_proc_fd_next = -1;
					ctl->zsctl_proc_open_next = 0;
					continue;
				}
			} else {
				/*
				 * Other accounting error.  Give up on
				 * accounting.
				 */
				goto ea_err;
			}
		}
		/* Skip if not a process group */
		if ((object.eo_catalog & EXT_TYPE_MASK) != EXT_GROUP ||
		    (object.eo_catalog & EXD_DATA_MASK) != EXD_GROUP_PROC) {
			(void) ea_free_item(&object, EUP_ALLOC);
			continue;
		}

		/* The process group entry should be complete */
		while (numfound < 9) {
			bzero(&pobject, sizeof (pobject));
			ret = ea_get_object(&ctl->zsctl_proc_eaf,
			    &pobject);
			if (ret < 0) {
				(void) ea_free_item(&object, EUP_ALLOC);
				zsd_warn(
				    "unable to get process accounting data");
				goto ea_err;
			}
			/* Next entries should be process data */
			if ((pobject.eo_catalog & EXT_TYPE_MASK) ==
			    EXT_GROUP) {
				(void) ea_free_item(&object, EUP_ALLOC);
				(void) ea_free_item(&pobject, EUP_ALLOC);
				zsd_warn(
				    "process data of wrong type");
				goto ea_err;
			}
			switch (pobject.eo_catalog & EXD_DATA_MASK) {
			case EXD_PROC_PID:
				pid = pobject.eo_item.ei_uint32;
				proc = &(ctl->zsctl_proc_array[pid]);
				/*
				 * This process should not be currently in
				 * the list of processes to process.
				 */
				assert(!list_link_active(&proc->zspr_next));
				numfound++;
				break;
			case EXD_PROC_ANCPID:
				ppid = pobject.eo_item.ei_uint32;
				pproc = &(ctl->zsctl_proc_array[ppid]);
				numfound++;
				break;
			case EXD_PROC_ZONENAME:
				zone = zsd_lookup_zone(ctl,
				    pobject.eo_item.ei_string, -1);
				numfound++;
				break;
			case EXD_PROC_CPU_USER_SEC:
				user.tv_sec =
				    pobject.eo_item.ei_uint64;
				numfound++;
				break;
			case EXD_PROC_CPU_USER_NSEC:
				user.tv_nsec =
				    pobject.eo_item.ei_uint64;
				numfound++;
				break;
			case EXD_PROC_CPU_SYS_SEC:
				sys.tv_sec =
				    pobject.eo_item.ei_uint64;
				numfound++;
				break;
			case EXD_PROC_CPU_SYS_NSEC:
				sys.tv_nsec =
				    pobject.eo_item.ei_uint64;
				numfound++;
				break;
			case EXD_PROC_FINISH_SEC:
				finish.tv_sec =
				    pobject.eo_item.ei_uint64;
				numfound++;
				break;
			case EXD_PROC_FINISH_NSEC:
				finish.tv_nsec =
				    pobject.eo_item.ei_uint64;
				numfound++;
				break;
			}
			(void) ea_free_item(&pobject, EUP_ALLOC);
		}
		(void) ea_free_item(&object, EUP_ALLOC);
		if (numfound != 9) {
			zsd_warn(gettext(
			    "Malformed process accounting entry found"));
			goto proc_done;
		}

		if (finish.tv_sec > interval_end.tv_sec ||
		    (finish.tv_sec == interval_end.tv_sec &&
		    finish.tv_nsec > (interval_end.tv_usec * 1000)))
			hrtime_expired = B_TRUE;

		/*
		 * Try to identify the zone and pset to which this
		 * exited process belongs.
		 */
		if (zone == NULL)
			goto proc_done;

		/* Save proc info */
		proc->zspr_ppid = ppid;
		proc->zspr_zoneid = zone->zsz_id;

		prev_psetid = ZS_PSET_ERROR;
		sched = 0;

		/*
		 * The following tries to deduce the processes pset.
		 *
		 * First choose pset and sched using cached value from the
		 * most recent time the process has been seen.
		 *
		 * pset and sched can change across zone_enter, so make sure
		 * most recent sighting of this process was in the same
		 * zone before using most recent known value.
		 *
		 * If there is no known value, use value of processes
		 * parent.  If parent is unknown, walk parents until a known
		 * parent is found.
		 *
		 * If no parent in the zone is found, use the zone's default
		 * pset and scheduling class.
		 */
		if (proc->zspr_psetid != ZS_PSET_ERROR) {
			prev_psetid = proc->zspr_psetid;
			pset = zsd_lookup_pset_byid(ctl, prev_psetid);
			sched = proc->zspr_sched;
		} else if (pproc->zspr_zoneid == zone->zsz_id &&
		    pproc->zspr_psetid != ZS_PSET_ERROR) {
			prev_psetid = pproc->zspr_psetid;
			pset = zsd_lookup_pset_byid(ctl, prev_psetid);
			sched = pproc->zspr_sched;
		}

		if (pset == NULL) {
			/*
			 * Process or processes parent has never been seen.
			 * Save to deduce a known parent later.
			 */
			proc_usage = sys;
			TIMESTRUC_ADD_TIMESTRUC(proc_usage, user);
			TIMESTRUC_DELTA(delta, proc_usage,
			    proc->zspr_usage);
			proc->zspr_usage = delta;
			list_insert_tail(&plist, proc);
			continue;
		}

		/* Add the zone's usage to the pset */
		usage = zsd_lookup_insert_usage(ctl, pset, zone);
		if (usage == NULL)
			goto proc_done;

		zsd_mark_pset_usage_found(usage, sched);

		/* compute the usage to add for the exited proc */
		proc_usage = sys;
		TIMESTRUC_ADD_TIMESTRUC(proc_usage, user);
		TIMESTRUC_DELTA(delta, proc_usage,
		    proc->zspr_usage);

		zsd_add_usage(ctl, usage, &delta);
proc_done:
		zsd_flush_proc_info(proc);

		if (hrtime_expired == B_TRUE)
			break;
	}
	/*
	 * close next accounting file.
	 */
	if (ctl->zsctl_proc_open_next) {
		(void) ea_close(
		    &ctl->zsctl_proc_eaf_next);
		ctl->zsctl_proc_open_next = 0;
		ctl->zsctl_proc_fd_next = -1;
	}

	/* For the remaining processes, use pset and sched of a known parent */
	proc = list_head(&plist);
	while (proc != NULL) {
		next = proc;
		for (;;) {
			if (next->zspr_ppid == 0 || next->zspr_ppid == -1) {
				/*
				 * Kernel process, or parent is unknown, skip
				 * process, remove from process list.
				 */
				tmp = proc;
				proc = list_next(&plist, proc);
				list_link_init(&tmp->zspr_next);
				break;
			}
			pproc = &(ctl->zsctl_proc_array[next->zspr_ppid]);
			if (pproc->zspr_zoneid != proc->zspr_zoneid) {
				/*
				 * Parent in different zone.  Save process and
				 * use zone's default pset and sched below
				 */
				tmp = proc;
				proc = list_next(&plist, proc);
				list_remove(&plist, tmp);
				list_insert_tail(&pplist, tmp);
				break;
			}
			/* Parent has unknown pset, Search parent's parent  */
			if (pproc->zspr_psetid == ZS_PSET_ERROR) {
				next = pproc;
				continue;
			}
			/* Found parent with known pset.  Use its info */
			proc->zspr_psetid = pproc->zspr_psetid;
			proc->zspr_sched = pproc->zspr_sched;
			next->zspr_psetid = pproc->zspr_psetid;
			next->zspr_sched = pproc->zspr_sched;
			zone = zsd_lookup_zone_byid(ctl,
			    proc->zspr_zoneid);
			if (zone == NULL) {
				tmp = proc;
				proc = list_next(&plist, proc);
				list_remove(&plist, tmp);
				list_link_init(&tmp->zspr_next);
				break;
			}
			pset = zsd_lookup_pset_byid(ctl,
			    proc->zspr_psetid);
			if (pset == NULL) {
				tmp = proc;
				proc = list_next(&plist, proc);
				list_remove(&plist, tmp);
				list_link_init(&tmp->zspr_next);
				break;
			}
			/* Add the zone's usage to the pset */
			usage = zsd_lookup_insert_usage(ctl, pset, zone);
			if (usage == NULL) {
				tmp = proc;
				proc = list_next(&plist, proc);
				list_remove(&plist, tmp);
				list_link_init(&tmp->zspr_next);
				break;
			}
			zsd_mark_pset_usage_found(usage, proc->zspr_sched);
			zsd_add_usage(ctl, usage, &proc->zspr_usage);
			zsd_flush_proc_info(proc);
			tmp = proc;
			proc = list_next(&plist, proc);
			list_remove(&plist, tmp);
			list_link_init(&tmp->zspr_next);
			break;
		}
	}
	/*
	 * Process has never been seen.  Using zone info to
	 * determine pset and scheduling class.
	 */
	proc = list_head(&pplist);
	while (proc != NULL) {

		zone = zsd_lookup_zone_byid(ctl, proc->zspr_zoneid);
		if (zone == NULL)
			goto next;
		if (zone->zsz_psetid != ZS_PSET_ERROR &&
		    zone->zsz_psetid != ZS_PSET_MULTI) {
			prev_psetid = zone->zsz_psetid;
			pset = zsd_lookup_pset_byid(ctl, prev_psetid);
		} else {
			pset = zsd_lookup_pset(ctl, zone->zsz_pset, -1);
			if (pset != NULL)
				prev_psetid = pset->zsp_id;
		}
		if (pset == NULL)
			goto next;

		sched = zone->zsz_scheds;
		/*
		 * Ignore FX high scheduling class if it is not the
		 * only scheduling class in the zone.
		 */
		if (sched != ZS_SCHED_FX_60)
			sched &= (~ZS_SCHED_FX_60);
		/*
		 * If more than one scheduling class has been found
		 * in the zone, use zone's default scheduling class for
		 * this process.
		 */
		if ((sched & (sched - 1)) != 0)
			sched = zone->zsz_default_sched;

		/* Add the zone's usage to the pset */
		usage = zsd_lookup_insert_usage(ctl, pset, zone);
		if (usage == NULL)
			goto next;

		zsd_mark_pset_usage_found(usage, sched);
		zsd_add_usage(ctl, usage, &proc->zspr_usage);
next:
		tmp = proc;
		proc = list_next(&pplist, proc);
		zsd_flush_proc_info(tmp);
		list_link_init(&tmp->zspr_next);
	}
	return;
ea_err:
	/*
	 * Close the next accounting file if we have not transitioned to it
	 * yet.
	 */
	if (ctl->zsctl_proc_open_next) {
		(void) ea_close(&ctl->zsctl_proc_eaf_next);
		ctl->zsctl_proc_open_next = 0;
		ctl->zsctl_proc_fd_next = -1;
	}
}

/*
 * getvmusage(2) uses size_t's in the passwd data structure, which differ
 * in size for 32bit and 64 bit kernels.  Since this is a contracted interface,
 * and zonestatd does not necessarily match the kernel's bitness, marshal
 * results appropriately.
 */
static int
zsd_getvmusage(zsd_ctl_t *ctl, uint_t flags, time_t age, zsd_vmusage64_t *buf,
    uint64_t *nres)
{
	zsd_vmusage32_t *vmu32;
	zsd_vmusage64_t *vmu64;
	uint32_t nres32;
	int i;
	int ret;

	if (ctl->zsctl_kern_bits == 32)  {
		nres32 = *nres;
		ret = syscall(SYS_rusagesys, _RUSAGESYS_GETVMUSAGE,
		    flags, age, (uintptr_t)buf, (uintptr_t)&nres32);
		*nres = nres32;
		if (ret == 0 && buf != NULL) {
			/*
			 * An array of vmusage32_t's has been returned.
			 * Convert it to an array of vmusage64_t's.
			 */
			vmu32 = (zsd_vmusage32_t *)buf;
			vmu64 = (zsd_vmusage64_t *)buf;
			for (i = nres32 - 1; i >= 0; i--) {

				vmu64[i].vmu_zoneid = vmu32[i].vmu_zoneid;
				vmu64[i].vmu_type = vmu32[i].vmu_type;
				vmu64[i].vmu_type = vmu32[i].vmu_type;
				vmu64[i].vmu_rss_all = vmu32[i].vmu_rss_all;
				vmu64[i].vmu_rss_private =
				    vmu32[i].vmu_rss_private;
				vmu64[i].vmu_rss_shared =
				    vmu32[i].vmu_rss_shared;
				vmu64[i].vmu_swap_all = vmu32[i].vmu_swap_all;
				vmu64[i].vmu_swap_private =
				    vmu32[i].vmu_swap_private;
				vmu64[i].vmu_swap_shared =
				    vmu32[i].vmu_swap_shared;
			}
		}
		return (ret);
	} else {
		/*
		 * kernel is 64 bit, so use 64 bit structures as zonestat
		 * expects.
		 */
		return (syscall(SYS_rusagesys, _RUSAGESYS_GETVMUSAGE,
		    flags, age, (uintptr_t)buf, (uintptr_t)nres));

	}
}

/*
 * Update the current physical, virtual, and locked memory usage of the
 * running zones.
 */
static void
zsd_refresh_memory(zsd_ctl_t *ctl, boolean_t init)
{

	uint64_t phys_total;
	uint64_t phys_used;
	uint64_t phys_zones;
	uint64_t phys_zones_overcount;
	uint64_t phys_zones_extra;
	uint64_t phys_zones_credit;

	uint64_t vm_free;
	uint64_t vm_used;

	uint64_t disk_swap_total;
	uint64_t disk_swap_used;	/* disk swap with contents */

	uint64_t physmem;
	uint64_t pp_kernel;
	uint64_t arc_size = 0;
	struct anoninfo ani;

	int num_swap_devices;
	struct swaptable *swt;
	struct swapent *swent;
	size_t swt_size;
	char *path;

	zsd_vmusage64_t *vmusage;
	uint64_t num_vmusage;

	int i, ret;

	zsd_system_t *sys;
	zsd_zone_t *zone;
	int vmu_nzones;

	kstat_t *kstat;
	char kstat_name[KSTAT_STRLEN];
	kstat_named_t *knp;
	kid_t kid;

	if (init)
		return;

	sys = ctl->zsctl_system;

	/* interrogate swap devices to find the amount of disk swap */
disk_swap_again:
	num_swap_devices = swapctl(SC_GETNSWP, NULL);

	if (num_swap_devices == 0) {
		sys->zss_swap_total = disk_swap_total = 0;
		sys->zss_swap_used = disk_swap_used = 0;
		/* No disk swap */
		goto disk_swap_done;
	}
	/* see if swap table needs to be larger */
	if (num_swap_devices > ctl->zsctl_swap_cache_num) {
		swt_size = sizeof (int) +
		    (num_swap_devices * sizeof (struct swapent)) +
		    (num_swap_devices * MAXPATHLEN);
		if (ctl->zsctl_swap_cache != NULL)
			free(ctl->zsctl_swap_cache);

		swt = (struct swaptable *)malloc(swt_size);
		if (swt == NULL) {
			/*
			 * Could not allocate to get list of swap devices.
			 * Just use data from the most recent read, which will
			 * be zero if this is the first read.
			 */
			zsd_warn(gettext("Unable to allocate to determine "
			    "virtual memory"));
			disk_swap_total = sys->zss_swap_total;
			disk_swap_used = sys->zss_swap_used;
			goto disk_swap_done;
		}
		swent = swt->swt_ent;
		path = (char *)swt + (sizeof (int) +
		    num_swap_devices * sizeof (swapent_t));
		for (i = 0; i < num_swap_devices; i++, swent++) {
			swent->ste_path = path;
			path += MAXPATHLEN;
		}
		swt->swt_n = num_swap_devices;
		ctl->zsctl_swap_cache = swt;
		ctl->zsctl_swap_cache_size = swt_size;
		ctl->zsctl_swap_cache_num = num_swap_devices;
	}
	num_swap_devices = swapctl(SC_LIST, ctl->zsctl_swap_cache);
	if (num_swap_devices < 0) {
		/* More swap devices have arrived */
		if (errno == ENOMEM)
			goto disk_swap_again;

		zsd_warn(gettext("Unable to determine disk swap devices"));
		/* Unexpected error.  Use existing data */
		disk_swap_total = sys->zss_swap_total;
		disk_swap_used = sys->zss_swap_used;
		goto disk_swap_done;
	}

	/* add up the disk swap */
	disk_swap_total = 0;
	disk_swap_used = 0;
	swent = ctl->zsctl_swap_cache->swt_ent;
	for (i = 0; i < num_swap_devices; i++, swent++) {
		disk_swap_total += swent->ste_pages;
		disk_swap_used += (swent->ste_pages - swent->ste_free);
	}
	disk_swap_total *= ctl->zsctl_pagesize;
	disk_swap_used *= ctl->zsctl_pagesize;

	sys->zss_swap_total = disk_swap_total;
	sys->zss_swap_used = disk_swap_used;

disk_swap_done:

	/* get system pages kstat */
	kid = -1;
	kstat = kstat_lookup(ctl->zsctl_kstat_ctl, "unix", 0, "system_pages");
	if (kstat == NULL)
		zsd_warn(gettext("Unable to lookup system pages kstat"));
	else
		kid = kstat_read(ctl->zsctl_kstat_ctl, kstat, NULL);

	if (kid == -1) {
		zsd_warn(gettext("Unable to read system pages kstat"));
		return;
	} else {
		knp = kstat_data_lookup(kstat, "physmem");
		if (knp == NULL) {
			zsd_warn(gettext("Unable to read physmem"));
		} else {
			if (knp->data_type == KSTAT_DATA_UINT64)
				physmem = knp->value.ui64;
			else if (knp->data_type == KSTAT_DATA_UINT32)
				physmem = knp->value.ui32;
			else
				return;
		}
		knp = kstat_data_lookup(kstat, "pp_kernel");
		if (knp == NULL) {
			zsd_warn(gettext("Unable to read pp_kernel"));
		} else {
			if (knp->data_type == KSTAT_DATA_UINT64)
				pp_kernel = knp->value.ui64;
			else if (knp->data_type == KSTAT_DATA_UINT32)
				pp_kernel = knp->value.ui32;
			else
				return;
		}
	}
	physmem *= ctl->zsctl_pagesize;
	pp_kernel *= ctl->zsctl_pagesize;

	/* get the zfs arc size if available */
	arc_size = 0;
	kid = -1;
	kstat = kstat_lookup(ctl->zsctl_kstat_ctl, "zfs", 0, "arcstats");
	if (kstat != NULL)
		kid = kstat_read(ctl->zsctl_kstat_ctl, kstat, NULL);
	if (kid != -1) {
		knp = kstat_data_lookup(kstat, "size");
		if (knp != NULL)
			if (knp->data_type == KSTAT_DATA_UINT64)
				arc_size = knp->value.ui64;
	}

	/* Try to get swap information */
	if (swapctl(SC_AINFO, &ani) < 0) {
		zsd_warn(gettext("Unable to get swap info"));
		return;
	}

vmusage_again:
	/* getvmusage to get physical memory usage */
	vmusage = ctl->zsctl_vmusage_cache;
	num_vmusage = ctl->zsctl_vmusage_cache_num;

	ret = zsd_getvmusage(ctl, VMUSAGE_SYSTEM | VMUSAGE_ALL_ZONES, 0,
	    vmusage, &num_vmusage);

	if (ret != 0) {
		/* Unexpected error.  Use existing data */
		if (errno != EOVERFLOW) {
			zsd_warn(gettext(
			    "Unable to read physical memory usage"));
			phys_zones = sys->zss_ram_zones;
			goto vmusage_done;
		}
	}
	/* vmusage results cache too small */
	if (num_vmusage > ctl->zsctl_vmusage_cache_num) {

		size_t size = sizeof (zsd_vmusage64_t) * num_vmusage;

		if (ctl->zsctl_vmusage_cache != NULL)
			free(ctl->zsctl_vmusage_cache);
		vmusage = (zsd_vmusage64_t *)malloc(size);
		if (vmusage == NULL) {
			zsd_warn(gettext("Unable to alloc to determine "
			    "physical memory usage"));
			phys_zones = sys->zss_ram_zones;
			goto vmusage_done;
		}
		ctl->zsctl_vmusage_cache = vmusage;
		ctl->zsctl_vmusage_cache_num = num_vmusage;
		goto vmusage_again;
	}

	phys_zones_overcount = 0;
	vmu_nzones = 0;
	for (i = 0; i < num_vmusage; i++) {
		switch (vmusage[i].vmu_type) {
		case VMUSAGE_SYSTEM:
			/* total pages backing user process mappings */
			phys_zones = sys->zss_ram_zones =
			    vmusage[i].vmu_rss_all;
			break;
		case VMUSAGE_ZONE:
			vmu_nzones++;
			phys_zones_overcount += vmusage[i].vmu_rss_all;
			zone = zsd_lookup_zone_byid(ctl, vmusage[i].vmu_id);
			if (zone != NULL)
				zone->zsz_usage_ram = vmusage[i].vmu_rss_all;
			break;
		default:
			break;
		}
	}
	/*
	 * Figure how much memory was double counted due to text sharing
	 * between zones.  Credit this back so that the sum of the zones
	 * equals the total zone ram usage;
	 */
	phys_zones_extra = phys_zones_overcount - phys_zones;
	phys_zones_credit = phys_zones_extra / vmu_nzones;

vmusage_done:

	/* walk the zones to get swap and locked kstats.  Fetch ram cap. */
	sys->zss_locked_zones = 0;
	sys->zss_vm_zones = 0;
	for (zone = list_head(&ctl->zsctl_zones); zone != NULL;
	    zone = list_next(&ctl->zsctl_zones, zone)) {

		/* If zone halted during interval, show memory usage as none */
		if (zone->zsz_active == B_FALSE ||
		    zone->zsz_deleted == B_TRUE) {
			zone->zsz_usage_ram = 0;
			zone->zsz_usage_vm = 0;
			zone->zsz_usage_locked = 0;
			continue;
		}

		if (phys_zones_credit > 0) {
			if (zone->zsz_usage_ram > phys_zones_credit) {
				zone->zsz_usage_ram -= phys_zones_credit;
			}
		}
		/*
		 * Get zone's swap usage.  Since zone could have halted,
		 * treats as zero if cannot read
		 */
		zone->zsz_usage_vm = 0;
		(void) snprintf(kstat_name, sizeof (kstat_name),
		    "swapresv_zone_%d", zone->zsz_id);
		kid = -1;
		kstat = kstat_lookup(ctl->zsctl_kstat_ctl, "caps",
		    zone->zsz_id, kstat_name);
		if (kstat != NULL)
			kid = kstat_read(ctl->zsctl_kstat_ctl, kstat, NULL);
		if (kid != -1) {
			knp = kstat_data_lookup(kstat, "usage");
			if (knp != NULL &&
			    knp->data_type == KSTAT_DATA_UINT64) {
				zone->zsz_usage_vm = knp->value.ui64;
				sys->zss_vm_zones += knp->value.ui64;
			}
		}
		/*
		 * Get zone's locked usage.  Since zone could have halted,
		 * treats as zero if cannot read
		 */
		zone->zsz_usage_locked = 0;
		(void) snprintf(kstat_name, sizeof (kstat_name),
		    "lockedmem_zone_%d", zone->zsz_id);
		kid = -1;
		kstat = kstat_lookup(ctl->zsctl_kstat_ctl, "caps",
		    zone->zsz_id, kstat_name);
		if (kstat != NULL)
			kid = kstat_read(ctl->zsctl_kstat_ctl, kstat, NULL);
		if (kid != -1) {
			knp = kstat_data_lookup(kstat, "usage");
			if (knp != NULL &&
			    knp->data_type == KSTAT_DATA_UINT64) {
				zone->zsz_usage_locked = knp->value.ui64;
				/*
				 * Since locked memory accounting for zones
				 * can double count ddi locked memory, cap each
				 * zone's locked usage at its ram usage.
				 */
				if (zone->zsz_usage_locked >
				    zone->zsz_usage_ram)
					zone->zsz_usage_locked =
					    zone->zsz_usage_ram;
				sys->zss_locked_zones +=
				    zone->zsz_usage_locked;
			}
		}
	}

	phys_total =
	    sysconf(_SC_PHYS_PAGES) * ctl->zsctl_pagesize;

	phys_used = (sysconf(_SC_PHYS_PAGES) - sysconf(_SC_AVPHYS_PAGES))
	    * ctl->zsctl_pagesize;

	/* Compute remaining statistics */
	sys->zss_ram_total = phys_total;
	sys->zss_ram_zones = phys_zones;
	sys->zss_ram_kern = phys_used - phys_zones - arc_size;

	/*
	 * The total for kernel locked memory should include
	 * segkp locked pages, but oh well.  The arc size is subtracted,
	 * as that physical memory is reclaimable.
	 */
	sys->zss_locked_kern = pp_kernel - arc_size;
	/* Add memory used by kernel startup and obp to kernel locked */
	if ((phys_total - physmem) > 0)
		sys->zss_locked_kern += phys_total - physmem;

	/*
	 * Add in the portion of (RAM+DISK) that is not available as swap,
	 * and consider it swap used by the kernel.
	 */
	sys->zss_vm_total = phys_total + disk_swap_total;
	vm_free = (ani.ani_max - ani.ani_resv) * ctl->zsctl_pagesize;
	vm_used = sys->zss_vm_total - vm_free;
	sys->zss_vm_kern = vm_used - sys->zss_vm_zones - arc_size;
}

/*
 * Charge each cpu's usage to its processor sets.  Also add the cpu's total
 * time to each zone using the processor set.  This tracks the maximum
 * amount of cpu time that a zone could have used.
 */
static void
zsd_refresh_cpu_stats(zsd_ctl_t *ctl, boolean_t init)
{
	zsd_system_t *sys;
	zsd_zone_t *zone;
	zsd_pset_usage_t *usage;
	zsd_cpu_t *cpu;
	zsd_cpu_t *cpu_next;
	zsd_pset_t *pset;
	timestruc_t ts;
	uint64_t hrtime;
	timestruc_t delta;

	/* Update the per-cpu kstat data */
	cpu_next = list_head(&ctl->zsctl_cpus);
	while (cpu_next != NULL) {
		cpu = cpu_next;
		cpu_next = list_next(&ctl->zsctl_cpus, cpu);
		zsd_update_cpu_stats(ctl, cpu);
	}
	/* Update the elapsed real time */
	hrtime = gethrtime();
	if (init) {
		/* first time around, store hrtime for future comparision */
		ctl->zsctl_hrtime = hrtime;
		ctl->zsctl_hrtime_prev = hrtime;

	} else {
		/* Compute increase in hrtime since the most recent read */
		ctl->zsctl_hrtime_prev = ctl->zsctl_hrtime;
		ctl->zsctl_hrtime = hrtime;
		if ((hrtime = hrtime - ctl->zsctl_hrtime_prev) > 0)
			TIMESTRUC_ADD_NANOSEC(ctl->zsctl_hrtime_total, hrtime);
	}

	/* On initialization, all psets have zero time  */
	if (init)
		return;

	for (pset = list_head(&ctl->zsctl_psets); pset != NULL;
	    pset = list_next(&ctl->zsctl_psets, pset)) {

		if (pset->zsp_active == B_FALSE) {
			zsd_warn(gettext("Internal error,inactive pset found"));
			continue;
		}

		/* sum total used time for pset */
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
		TIMESTRUC_ADD_TIMESTRUC(ts, pset->zsp_intr);
		TIMESTRUC_ADD_TIMESTRUC(ts, pset->zsp_kern);
		TIMESTRUC_ADD_TIMESTRUC(ts, pset->zsp_user);
		/* kernel time in pset is total time minus zone time */
		TIMESTRUC_DELTA(pset->zsp_usage_kern, ts,
		    pset->zsp_usage_zones);
		if (pset->zsp_usage_kern.tv_sec < 0 ||
		    pset->zsp_usage_kern.tv_nsec < 0) {
			pset->zsp_usage_kern.tv_sec = 0;
			pset->zsp_usage_kern.tv_nsec = 0;
		}
		/* Total pset elapsed time is used time plus idle time */
		TIMESTRUC_ADD_TIMESTRUC(ts, pset->zsp_idle);

		TIMESTRUC_DELTA(delta, ts, pset->zsp_total_time);

		for (usage = list_head(&pset->zsp_usage_list); usage != NULL;
		    usage = list_next(&pset->zsp_usage_list, usage)) {

			zone = usage->zsu_zone;
			if (usage->zsu_cpu_shares != ZS_LIMIT_NONE &&
			    usage->zsu_cpu_shares != ZS_SHARES_UNLIMITED &&
			    usage->zsu_cpu_shares != 0) {
				/*
				 * Figure out how many nanoseconds of share time
				 * to give to the zone
				 */
				hrtime = delta.tv_sec;
				hrtime *= NANOSEC;
				hrtime += delta.tv_nsec;
				hrtime *= usage->zsu_cpu_shares;
				hrtime /= pset->zsp_cpu_shares;
				TIMESTRUC_ADD_NANOSEC(zone->zsz_share_time,
				    hrtime);
			}
			/* Add pset time to each zone using pset */
			TIMESTRUC_ADD_TIMESTRUC(zone->zsz_pset_time, delta);

			zone->zsz_cpus_online += pset->zsp_online;
		}
		pset->zsp_total_time = ts;
	}

	for (zone = list_head(&ctl->zsctl_zones); zone != NULL;
	    zone = list_next(&ctl->zsctl_zones, zone)) {

		/* update cpu cap tracking if the zone has a cpu cap */
		if (zone->zsz_cpu_cap != ZS_LIMIT_NONE) {
			uint64_t elapsed;

			elapsed = ctl->zsctl_hrtime - ctl->zsctl_hrtime_prev;
			elapsed *= zone->zsz_cpu_cap;
			elapsed = elapsed / 100;
			TIMESTRUC_ADD_NANOSEC(zone->zsz_cap_time, elapsed);
		}
	}
	sys = ctl->zsctl_system;
	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	TIMESTRUC_ADD_TIMESTRUC(ts, sys->zss_intr);
	TIMESTRUC_ADD_TIMESTRUC(ts, sys->zss_kern);
	TIMESTRUC_ADD_TIMESTRUC(ts, sys->zss_user);

	/* kernel time in pset is total time minus zone time */
	TIMESTRUC_DELTA(sys->zss_cpu_usage_kern, ts,
	    sys->zss_cpu_usage_zones);
	if (sys->zss_cpu_usage_kern.tv_sec < 0 ||
	    sys->zss_cpu_usage_kern.tv_nsec < 0) {
		sys->zss_cpu_usage_kern.tv_sec = 0;
		sys->zss_cpu_usage_kern.tv_nsec = 0;
	}
	/* Total pset elapsed time is used time plus idle time */
	TIMESTRUC_ADD_TIMESTRUC(ts, sys->zss_idle);
	sys->zss_cpu_total_time = ts;
}

/*
 * Saves current usage data to a cache that is read by libzonestat when
 * calling zs_usage_read().
 *
 * All pointers in the cached data structure are set to NULL.  When
 * libzonestat reads the cached data, it will set the pointers relative to
 * its address space.
 */
static void
zsd_usage_cache_update(zsd_ctl_t *ctl)
{
	zs_usage_cache_t *cache;
	zs_usage_cache_t *old;
	zs_usage_t *usage;

	zs_system_t *sys;
	zsd_system_t *dsys;
	zs_zone_t *zone = NULL;
	zsd_zone_t *dzone;
	zs_pset_t *pset = NULL;
	zsd_pset_t *dpset;
	zs_pset_zone_t *pusage;
	zsd_pset_usage_t *dpusage;

	char *next;
	uint_t size, i, j;

	size =
	    sizeof (zs_usage_cache_t) +
	    sizeof (zs_usage_t) +
	    sizeof (zs_system_t) +
	    sizeof (zs_zone_t) * ctl->zsctl_nzones +
	    sizeof (zs_pset_t) *  ctl->zsctl_npsets +
	    sizeof (zs_pset_zone_t) * ctl->zsctl_npset_usages;

	cache = (zs_usage_cache_t *)malloc(size);
	if (cache == NULL) {
		zsd_warn(gettext("Unable to allocate usage cache\n"));
		return;
	}

	next = (char *)cache;
	cache->zsuc_size = size - sizeof (zs_usage_cache_t);
	next += sizeof (zs_usage_cache_t);

	/* LINTED */
	usage = cache->zsuc_usage = (zs_usage_t *)next;
	next += sizeof (zs_usage_t);
	usage->zsu_start = g_start;
	usage->zsu_hrstart = g_hrstart;
	usage->zsu_time = g_now;
	usage->zsu_hrtime = g_hrnow;
	usage->zsu_nzones = ctl->zsctl_nzones;
	usage->zsu_npsets = ctl->zsctl_npsets;
	usage->zsu_system = NULL;

	/* LINTED */
	sys = (zs_system_t *)next;
	next += sizeof (zs_system_t);
	dsys = ctl->zsctl_system;
	sys->zss_ram_total = dsys->zss_ram_total;
	sys->zss_ram_kern = dsys->zss_ram_kern;
	sys->zss_ram_zones = dsys->zss_ram_zones;
	sys->zss_locked_kern = dsys->zss_locked_kern;
	sys->zss_locked_zones = dsys->zss_locked_zones;
	sys->zss_vm_total = dsys->zss_vm_total;
	sys->zss_vm_kern = dsys->zss_vm_kern;
	sys->zss_vm_zones = dsys->zss_vm_zones;
	sys->zss_swap_total = dsys->zss_swap_total;
	sys->zss_swap_used = dsys->zss_swap_used;
	sys->zss_ncpus = dsys->zss_ncpus;
	sys->zss_ncpus_online = dsys->zss_ncpus_online;

	sys->zss_processes_max = dsys->zss_maxpid;
	sys->zss_lwps_max = dsys->zss_lwps_max;
	sys->zss_shm_max = dsys->zss_shm_max;
	sys->zss_shmids_max = dsys->zss_shmids_max;
	sys->zss_semids_max = dsys->zss_semids_max;
	sys->zss_msgids_max = dsys->zss_msgids_max;
	sys->zss_lofi_max = dsys->zss_lofi_max;

	sys->zss_processes = dsys->zss_processes;
	sys->zss_lwps = dsys->zss_lwps;
	sys->zss_shm = dsys->zss_shm;
	sys->zss_shmids = dsys->zss_shmids;
	sys->zss_semids = dsys->zss_semids;
	sys->zss_msgids = dsys->zss_msgids;
	sys->zss_lofi = dsys->zss_lofi;

	sys->zss_cpu_total_time = dsys->zss_cpu_total_time;
	sys->zss_cpu_usage_zones = dsys->zss_cpu_usage_zones;
	sys->zss_cpu_usage_kern = dsys->zss_cpu_usage_kern;

	for (i = 0, dzone = list_head(&ctl->zsctl_zones);
	    i < ctl->zsctl_nzones;
	    i++, dzone = list_next(&ctl->zsctl_zones, dzone)) {
		/* LINTED */
		zone = (zs_zone_t *)next;
		next += sizeof (zs_zone_t);
		list_link_init(&zone->zsz_next);
		zone->zsz_system = NULL;

		(void) strlcpy(zone->zsz_name, dzone->zsz_name,
		    sizeof (zone->zsz_name));
		(void) strlcpy(zone->zsz_pool, dzone->zsz_pool,
		    sizeof (zone->zsz_pool));
		(void) strlcpy(zone->zsz_pset, dzone->zsz_pset,
		    sizeof (zone->zsz_pset));
		zone->zsz_id = dzone->zsz_id;
		zone->zsz_cputype = dzone->zsz_cputype;
		zone->zsz_iptype = dzone->zsz_iptype;
		zone->zsz_start = dzone->zsz_start;
		zone->zsz_hrstart = dzone->zsz_hrstart;
		zone->zsz_scheds = dzone->zsz_scheds;
		zone->zsz_cpu_shares = dzone->zsz_cpu_shares;
		zone->zsz_cpu_cap = dzone->zsz_cpu_cap;
		zone->zsz_ram_cap = dzone->zsz_ram_cap;
		zone->zsz_vm_cap = dzone->zsz_vm_cap;
		zone->zsz_locked_cap = dzone->zsz_locked_cap;
		zone->zsz_cpu_usage = dzone->zsz_cpu_usage;
		zone->zsz_cpus_online = dzone->zsz_cpus_online;
		zone->zsz_pset_time = dzone->zsz_pset_time;
		zone->zsz_cap_time = dzone->zsz_cap_time;
		zone->zsz_share_time = dzone->zsz_share_time;
		zone->zsz_usage_ram = dzone->zsz_usage_ram;
		zone->zsz_usage_locked = dzone->zsz_usage_locked;
		zone->zsz_usage_vm = dzone->zsz_usage_vm;

		zone->zsz_processes_cap = dzone->zsz_processes_cap;
		zone->zsz_lwps_cap = dzone->zsz_lwps_cap;
		zone->zsz_shm_cap = dzone->zsz_shm_cap;
		zone->zsz_shmids_cap = dzone->zsz_shmids_cap;
		zone->zsz_semids_cap = dzone->zsz_semids_cap;
		zone->zsz_msgids_cap = dzone->zsz_msgids_cap;
		zone->zsz_lofi_cap = dzone->zsz_lofi_cap;

		zone->zsz_processes = dzone->zsz_processes;
		zone->zsz_lwps = dzone->zsz_lwps;
		zone->zsz_shm = dzone->zsz_shm;
		zone->zsz_shmids = dzone->zsz_shmids;
		zone->zsz_semids = dzone->zsz_semids;
		zone->zsz_msgids = dzone->zsz_msgids;
		zone->zsz_lofi = dzone->zsz_lofi;
	}

	for (i = 0, dpset = list_head(&ctl->zsctl_psets);
	    i < ctl->zsctl_npsets;
	    i++, dpset = list_next(&ctl->zsctl_psets, dpset)) {
		/* LINTED */
		pset = (zs_pset_t *)next;
		next += sizeof (zs_pset_t);
		list_link_init(&pset->zsp_next);
		(void) strlcpy(pset->zsp_name, dpset->zsp_name,
		    sizeof (pset->zsp_name));
		pset->zsp_id = dpset->zsp_id;
		pset->zsp_cputype = dpset->zsp_cputype;
		pset->zsp_start = dpset->zsp_start;
		pset->zsp_hrstart = dpset->zsp_hrstart;
		pset->zsp_online = dpset->zsp_online;
		pset->zsp_size = dpset->zsp_size;
		pset->zsp_min = dpset->zsp_min;
		pset->zsp_max = dpset->zsp_max;
		pset->zsp_importance = dpset->zsp_importance;
		pset->zsp_scheds = dpset->zsp_scheds;
		pset->zsp_cpu_shares = dpset->zsp_cpu_shares;
		pset->zsp_total_time = dpset->zsp_total_time;
		pset->zsp_usage_kern = dpset->zsp_usage_kern;
		pset->zsp_usage_zones = dpset->zsp_usage_zones;
		pset->zsp_nusage = dpset->zsp_nusage;
		/* Add pset usages for pset */
		for (j = 0, dpusage = list_head(&dpset->zsp_usage_list);
		    j < dpset->zsp_nusage;
		    j++, dpusage = list_next(&dpset->zsp_usage_list, dpusage)) {
			/* LINTED */
			pusage = (zs_pset_zone_t *)next;
			next += sizeof (zs_pset_zone_t);
			/* pointers are computed by client */
			pusage->zspz_pset = NULL;
			pusage->zspz_zone = NULL;
			list_link_init(&pusage->zspz_next);
			pusage->zspz_zoneid = dpusage->zsu_zone->zsz_id;
			pusage->zspz_start = dpusage->zsu_start;
			pusage->zspz_hrstart = dpusage->zsu_hrstart;
			pusage->zspz_hrstart = dpusage->zsu_hrstart;
			pusage->zspz_cpu_shares = dpusage->zsu_cpu_shares;
			pusage->zspz_scheds = dpusage->zsu_scheds;
			pusage->zspz_cpu_usage = dpusage->zsu_cpu_usage;
		}
	}

	/* Update the current cache pointer */
	(void) mutex_lock(&g_usage_cache_lock);
	old = g_usage_cache;
	cache->zsuc_ref = 1;
	cache->zsuc_gen = g_gen_next;
	usage->zsu_gen = g_gen_next;
	usage->zsu_size = size;
	g_usage_cache = cache;
	if (old != NULL) {
		old->zsuc_ref--;
		if (old->zsuc_ref == 0)
			free(old);
	}
	g_gen_next++;
	/* Wake up any clients that are waiting for this calculation */
	if (g_usage_cache_kickers > 0) {
		(void) cond_broadcast(&g_usage_cache_wait);
	}
	(void) mutex_unlock(&g_usage_cache_lock);
}

static zs_usage_cache_t *
zsd_usage_cache_hold_locked()
{
	zs_usage_cache_t *ret;

	ret = g_usage_cache;
	ret->zsuc_ref++;
	return (ret);
}

void
zsd_usage_cache_rele(zs_usage_cache_t *cache)
{
	(void) mutex_lock(&g_usage_cache_lock);
	cache->zsuc_ref--;
	if (cache->zsuc_ref == 0)
		free(cache);
	(void) mutex_unlock(&g_usage_cache_lock);
}

/* Close the handles held by zsd_open() */
void
zsd_close(zsd_ctl_t *ctl)
{
	zsd_zone_t *zone;
	zsd_pset_t *pset;
	zsd_pset_usage_t *usage;
	zsd_cpu_t *cpu;
	int id;

	if (ctl->zsctl_kstat_ctl) {
		(void) kstat_close(ctl->zsctl_kstat_ctl);
		ctl->zsctl_kstat_ctl = NULL;
	}
	if (ctl->zsctl_proc_open) {
		(void) ea_close(&ctl->zsctl_proc_eaf);
		ctl->zsctl_proc_open = 0;
		ctl->zsctl_proc_fd = -1;
	}
	if (ctl->zsctl_pool_conf) {
		if (ctl->zsctl_pool_status == POOL_ENABLED)
			(void) pool_conf_close(ctl->zsctl_pool_conf);
		ctl->zsctl_pool_status = POOL_DISABLED;
	}

	while ((zone = list_head(&ctl->zsctl_zones)) != NULL) {
		list_remove(&ctl->zsctl_zones, zone);
		free(zone);
		ctl->zsctl_nzones--;
	}

	while ((pset = list_head(&ctl->zsctl_psets)) != NULL) {
		while ((usage = list_head(&pset->zsp_usage_list))
		    != NULL) {
			list_remove(&pset->zsp_usage_list, usage);
			ctl->zsctl_npset_usages--;
			free(usage);
		}
		list_remove(&ctl->zsctl_psets, pset);
		free(pset);
		ctl->zsctl_npsets--;
	}

	/* Release all cpus being tracked */
	while (cpu = list_head(&ctl->zsctl_cpus)) {
		list_remove(&ctl->zsctl_cpus, cpu);
		id = cpu->zsc_id;
		bzero(cpu, sizeof (zsd_cpu_t));
		cpu->zsc_id = id;
		cpu->zsc_allocated = B_FALSE;
		cpu->zsc_psetid = ZS_PSET_ERROR;
		cpu->zsc_psetid_prev = ZS_PSET_ERROR;
	}

	assert(ctl->zsctl_npset_usages == 0);
	assert(ctl->zsctl_npsets == 0);
	assert(ctl->zsctl_nzones == 0);
	(void) zsd_disable_cpu_stats();
}


/*
 * Update the utilization data for all zones and processor sets.
 */
static int
zsd_read(zsd_ctl_t *ctl, boolean_t init, boolean_t do_memory)
{
	(void) kstat_chain_update(ctl->zsctl_kstat_ctl);
	(void) gettimeofday(&(ctl->zsctl_timeofday), NULL);

	zsd_refresh_system(ctl);

	/*
	 * Memory calculation is expensive.  Only update it on sample
	 * intervals.
	 */
	if (do_memory == B_TRUE)
		zsd_refresh_memory(ctl, init);
	zsd_refresh_zones(ctl);
	zsd_refresh_psets(ctl);
	zsd_refresh_procs(ctl, init);
	zsd_refresh_cpu_stats(ctl, init);

	/*
	 * Delete objects that no longer exist.
	 * Pset usages must be deleted first as they point to zone and
	 * pset objects.
	 */
	zsd_mark_pset_usages_end(ctl);
	zsd_mark_psets_end(ctl);
	zsd_mark_cpus_end(ctl);
	zsd_mark_zones_end(ctl);

	/*
	 * Save results for clients.
	 */
	zsd_usage_cache_update(ctl);

	/*
	 * Roll process accounting file.
	 */
	(void) zsd_roll_exacct();
	return (0);
}

/*
 * Get the system rctl, which is the upper most limit
 */
static uint64_t
zsd_get_system_rctl(char *name)
{
	rctlblk_t *rblk, *rblk_last;

	rblk = (rctlblk_t *)alloca(rctlblk_size());
	rblk_last = (rctlblk_t *)alloca(rctlblk_size());

	if (getrctl(name, NULL, rblk_last, RCTL_FIRST) != 0)
		return (ZS_LIMIT_NONE);

	while (getrctl(name, rblk_last, rblk, RCTL_NEXT) == 0)
		(void) bcopy(rblk, rblk_last, rctlblk_size());

	return (rctlblk_get_value(rblk_last));
}

/*
 * Open any necessary subsystems for collecting utilization data,
 * allocate and initialize data structures, and get initial utilization.
 *
 * Errors:
 *	ENOMEM	out of memory
 *	EINVAL  other error
 */
static zsd_ctl_t *
zsd_open(zsd_ctl_t *ctl)
{
	zsd_system_t *system;

	char path[MAXPATHLEN];
	struct statvfs svfs;
	int ret;
	int i;
	size_t size;
	int err;

	if (ctl == NULL && (ctl = (zsd_ctl_t *)calloc(1,
	    sizeof (zsd_ctl_t))) == NULL) {
			zsd_warn(gettext("Out of Memory"));
			errno = ENOMEM;
			goto err;
	}
	ctl->zsctl_proc_fd = -1;

	/* open kstats */
	if (ctl->zsctl_kstat_ctl == NULL &&
	    (ctl->zsctl_kstat_ctl = kstat_open()) == NULL) {
		err = errno;
		zsd_warn(gettext("Unable to open kstats"));
		errno = err;
		if (errno != ENOMEM)
			errno = EAGAIN;
		goto err;
	}

	/*
	 * These are set when the accounting file is opened by
	 * zsd_update_procs()
	 */
	ctl->zsctl_proc_fd = -1;
	ctl->zsctl_proc_fd_next = -1;
	ctl->zsctl_proc_open = 0;
	ctl->zsctl_proc_open_next = 0;

	(void) zsd_enable_cpu_stats();

	/* Create structures to track usage */
	if (ctl->zsctl_system == NULL && (ctl->zsctl_system = (zsd_system_t *)
	    calloc(1, sizeof (zsd_system_t))) == NULL) {
		ret = -1;
		zsd_warn(gettext("Out of Memory"));
		errno = ENOMEM;
		goto err;
	}
	system = ctl->zsctl_system;
	/* get the kernel bitness to know structure layout for getvmusage */
	ret = sysinfo(SI_ARCHITECTURE_64, path, sizeof (path));
	if (ret < 0)
		ctl->zsctl_kern_bits = 32;
	else
		ctl->zsctl_kern_bits = 64;
	ctl->zsctl_pagesize = sysconf(_SC_PAGESIZE);

	size = sysconf(_SC_CPUID_MAX);
	ctl->zsctl_maxcpuid = size;
	if (ctl->zsctl_cpu_array == NULL && (ctl->zsctl_cpu_array =
	    (zsd_cpu_t *)calloc(size + 1, sizeof (zsd_cpu_t))) == NULL) {
		zsd_warn(gettext("Out of Memory"));
		errno = ENOMEM;
		goto err;
	}
	for (i = 0; i <= ctl->zsctl_maxcpuid; i++) {
		ctl->zsctl_cpu_array[i].zsc_id = i;
		ctl->zsctl_cpu_array[i].zsc_allocated = B_FALSE;
		ctl->zsctl_cpu_array[i].zsc_psetid = ZS_PSET_ERROR;
		ctl->zsctl_cpu_array[i].zsc_psetid_prev = ZS_PSET_ERROR;
	}
	if (statvfs("/proc", &svfs) != 0 ||
	    strcmp("/proc", svfs.f_fstr) != 0) {
		zsd_warn(gettext("/proc not a procfs filesystem"));
		errno = EINVAL;
		goto err;
	}

	size = sysconf(_SC_MAXPID) + 1;
	ctl->zsctl_maxproc = size;
	if (ctl->zsctl_proc_array == NULL &&
	    (ctl->zsctl_proc_array = (zsd_proc_t *)calloc(size,
	    sizeof (zsd_proc_t))) == NULL) {
		zsd_warn(gettext("Out of Memory"));
		errno = ENOMEM;
		goto err;
	}
	for (i = 0; i <= ctl->zsctl_maxproc; i++) {
		list_link_init(&(ctl->zsctl_proc_array[i].zspr_next));
		ctl->zsctl_proc_array[i].zspr_psetid = ZS_PSET_ERROR;
		ctl->zsctl_proc_array[i].zspr_zoneid = -1;
		ctl->zsctl_proc_array[i].zspr_usage.tv_sec = 0;
		ctl->zsctl_proc_array[i].zspr_usage.tv_nsec = 0;
		ctl->zsctl_proc_array[i].zspr_ppid = -1;
	}

	list_create(&ctl->zsctl_zones, sizeof (zsd_zone_t),
	    offsetof(zsd_zone_t, zsz_next));

	list_create(&ctl->zsctl_psets, sizeof (zsd_pset_t),
	    offsetof(zsd_pset_t, zsp_next));

	list_create(&ctl->zsctl_cpus, sizeof (zsd_cpu_t),
	    offsetof(zsd_cpu_t, zsc_next));

	if (ctl->zsctl_pool_conf == NULL &&
	    (ctl->zsctl_pool_conf = pool_conf_alloc()) == NULL) {
		zsd_warn(gettext("Out of Memory"));
		errno = ENOMEM;
		goto err;
	}
	ctl->zsctl_pool_status = POOL_DISABLED;
	ctl->zsctl_pool_changed = 0;

	if (ctl->zsctl_pool_vals[0] == NULL &&
	    (ctl->zsctl_pool_vals[0] = pool_value_alloc()) == NULL) {
		zsd_warn(gettext("Out of Memory"));
		errno = ENOMEM;
		goto err;
	}
	if (ctl->zsctl_pool_vals[1] == NULL &&
	    (ctl->zsctl_pool_vals[1] = pool_value_alloc()) == NULL) {
		zsd_warn(gettext("Out of Memory"));
		errno = ENOMEM;
		goto err;
	}
	ctl->zsctl_pool_vals[2] = NULL;

	/*
	 * get system limits
	 */
	system->zss_maxpid = size = sysconf(_SC_MAXPID);
	system->zss_processes_max = zsd_get_system_rctl("zone.max-processes");
	system->zss_lwps_max = zsd_get_system_rctl("zone.max-lwps");
	system->zss_shm_max = zsd_get_system_rctl("zone.max-shm-memory");
	system->zss_shmids_max = zsd_get_system_rctl("zone.max-shm-ids");
	system->zss_semids_max = zsd_get_system_rctl("zone.max-sem-ids");
	system->zss_msgids_max = zsd_get_system_rctl("zone.max-msg-ids");
	system->zss_lofi_max = zsd_get_system_rctl("zone.max-lofi");

	g_gen_next = 1;

	if (zsd_read(ctl, B_TRUE, B_FALSE) != 0)
		zsd_warn(gettext("Reading zone statistics failed"));

	return (ctl);
err:
	if (ctl)
		zsd_close(ctl);

	return (NULL);
}

/* Copy utilization data to buffer, filtering data if non-global zone. */
static void
zsd_usage_filter(zoneid_t zid, zs_usage_cache_t *cache, zs_usage_t *usage,
    boolean_t is_gz)
{
	zs_usage_t *cusage;
	zs_system_t *sys, *csys;
	zs_zone_t *zone, *czone;
	zs_pset_t *pset, *cpset;
	zs_pset_zone_t *pz, *cpz, *foundpz;
	size_t size = 0, csize = 0;
	char *start, *cstart;
	int i, j;
	timestruc_t delta;

	/* Privileged users in the global zone get everything */
	if (is_gz) {
		cusage = cache->zsuc_usage;
		(void) bcopy(cusage, usage, cusage->zsu_size);
		return;
	}

	/* Zones just get their own usage */
	cusage = cache->zsuc_usage;

	start = (char *)usage;
	cstart = (char *)cusage;
	size += sizeof (zs_usage_t);
	csize += sizeof (zs_usage_t);

	usage->zsu_start = cusage->zsu_start;
	usage->zsu_hrstart = cusage->zsu_hrstart;
	usage->zsu_time = cusage->zsu_time;
	usage->zsu_hrtime = cusage->zsu_hrtime;
	usage->zsu_gen = cusage->zsu_gen;
	usage->zsu_nzones = 1;
	usage->zsu_npsets = 0;

	/* LINTED */
	sys = (zs_system_t *)(start + size);
	/* LINTED */
	csys = (zs_system_t *)(cstart + csize);
	size += sizeof (zs_system_t);
	csize += sizeof (zs_system_t);

	/* Save system limits but not usage */
	*sys = *csys;
	sys->zss_ncpus = 0;
	sys->zss_ncpus_online = 0;

	/* LINTED */
	zone = (zs_zone_t *)(start + size);
	/* LINTED */
	czone = (zs_zone_t *)(cstart + csize);
	/* Find the matching zone */
	for (i = 0; i < cusage->zsu_nzones; i++) {
		if (czone->zsz_id == zid) {
			*zone = *czone;
			size += sizeof (zs_zone_t);
		}
		csize += sizeof (zs_zone_t);
		/* LINTED */
		czone = (zs_zone_t *)(cstart + csize);
	}
	sys->zss_ram_kern += (sys->zss_ram_zones - zone->zsz_usage_ram);
	sys->zss_ram_zones = zone->zsz_usage_ram;

	sys->zss_vm_kern += (sys->zss_vm_zones - zone->zsz_usage_vm);
	sys->zss_vm_zones = zone->zsz_usage_vm;

	sys->zss_locked_kern += (sys->zss_locked_zones -
	    zone->zsz_usage_locked);
	sys->zss_locked_zones = zone->zsz_usage_locked;

	TIMESTRUC_DELTA(delta, sys->zss_cpu_usage_zones, zone->zsz_cpu_usage);
	TIMESTRUC_ADD_TIMESTRUC(sys->zss_cpu_usage_kern, delta);
	sys->zss_cpu_usage_zones = zone->zsz_cpu_usage;

	/* LINTED */
	pset = (zs_pset_t *)(start + size);
	/* LINTED */
	cpset = (zs_pset_t *)(cstart + csize);
	for (i = 0; i < cusage->zsu_npsets; i++) {
		csize += sizeof (zs_pset_t);
		/* LINTED */
		cpz = (zs_pset_zone_t *)(csize + cstart);
		foundpz = NULL;
		for (j = 0; j < cpset->zsp_nusage; j++) {
			if (cpz->zspz_zoneid == zid)
				foundpz = cpz;

			csize += sizeof (zs_pset_zone_t);
			/* LINTED */
			cpz = (zs_pset_zone_t *)(csize + cstart);
		}
		if (foundpz != NULL) {
			size += sizeof (zs_pset_t);
			/* LINTED */
			pz = (zs_pset_zone_t *)(start + size);
			size += sizeof (zs_pset_zone_t);

			*pset = *cpset;
			*pz = *foundpz;

			TIMESTRUC_DELTA(delta, pset->zsp_usage_zones,
			    pz->zspz_cpu_usage);
			TIMESTRUC_ADD_TIMESTRUC(pset->zsp_usage_kern, delta);
			pset->zsp_usage_zones = pz->zspz_cpu_usage;
			pset->zsp_nusage = 1;
			usage->zsu_npsets++;
			sys->zss_ncpus += pset->zsp_size;
			sys->zss_ncpus_online += pset->zsp_online;
		}
		/* LINTED */
		cpset = (zs_pset_t *)(cstart + csize);
	}
	usage->zsu_size = size;
}

/*
 * Respond to new connections from libzonestat.so.  Also respond to zoneadmd,
 * which reports new zones.
 */
/* ARGSUSED */
static void
zsd_server(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc)
{
	int *args, cmd;
	door_desc_t door;
	ucred_t *ucred;
	const priv_set_t *eset;

	if (argp == DOOR_UNREF_DATA) {
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}

	if (arg_size != sizeof (cmd) * 2) {
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}

	/* LINTED */
	args = (int *)argp;
	cmd = args[0];

	/* If connection, return door to stat server */
	if (cmd == ZSD_CMD_CONNECT) {

		/* Verify client compilation version */
		if (args[1] != ZS_VERSION) {
			args[1] = ZSD_STATUS_VERSION_MISMATCH;
			(void) door_return(argp, sizeof (cmd) * 2, NULL, 0);
			thr_exit(NULL);
		}
		ucred = alloca(ucred_size());
		/* Verify client permission */
		if (door_ucred(&ucred) != 0) {
			args[1] = ZSD_STATUS_INTERNAL_ERROR;
			(void) door_return(argp, sizeof (cmd) * 2, NULL, 0);
			thr_exit(NULL);
		}

		eset = ucred_getprivset(ucred, PRIV_EFFECTIVE);
		if (eset == NULL) {
			args[1] = ZSD_STATUS_INTERNAL_ERROR;
			(void) door_return(argp, sizeof (cmd) * 2, NULL, 0);
			thr_exit(NULL);
		}
		if (!priv_ismember(eset, PRIV_PROC_INFO)) {
			args[1] = ZSD_STATUS_PERMISSION;
			(void) door_return(argp, sizeof (cmd) * 2, NULL, 0);
			thr_exit(NULL);
		}

		/* Return stat server door */
		args[1] = ZSD_STATUS_OK;
		door.d_attributes = DOOR_DESCRIPTOR;
		door.d_data.d_desc.d_descriptor = g_stat_door;
		(void) door_return(argp, sizeof (cmd) * 2, &door, 1);
		thr_exit(NULL);
	}

	/* Respond to zoneadmd informing zonestatd of a new zone */
	if (cmd == ZSD_CMD_NEW_ZONE) {
		zsd_fattach_zone(args[1], g_server_door, B_FALSE);
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}

	args[1] = ZSD_STATUS_INTERNAL_ERROR;
	(void) door_return(argp, sizeof (cmd) * 2, NULL, 0);
	thr_exit(NULL);
}

/*
 * Respond to libzonestat.so clients with the current utlilzation data.
 */
/* ARGSUSED */
static void
zsd_stat_server(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc)
{
	uint64_t *args, cmd;
	zs_usage_cache_t *cache;
	int ret;
	char *rvalp;
	size_t rvals;
	zs_usage_t *usage;
	ucred_t *ucred;
	zoneid_t zoneid;
	const priv_set_t *eset;
	boolean_t is_gz = B_FALSE;

	/* Tell stat thread there are no more clients */
	if (argp == DOOR_UNREF_DATA) {
		(void) mutex_lock(&g_usage_cache_lock);
		g_hasclient = B_FALSE;
		(void) cond_signal(&g_usage_cache_kick);
		(void) mutex_unlock(&g_usage_cache_lock);
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}
	if (arg_size != sizeof (cmd) * 2) {
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}
	/* LINTED */
	args = (uint64_t *)argp;
	cmd = args[0];
	if (cmd != ZSD_CMD_READ) {
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}
	ucred = alloca(ucred_size());
	if (door_ucred(&ucred) != 0) {
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}
	zoneid = ucred_getzoneid(ucred);

	if (zoneid == GLOBAL_ZONEID)
		is_gz = B_TRUE;

	eset = ucred_getprivset(ucred, PRIV_EFFECTIVE);
	if (eset == NULL) {
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}
	if (!priv_ismember(eset, PRIV_PROC_INFO)) {
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}
	(void) mutex_lock(&g_usage_cache_lock);
	g_hasclient = B_TRUE;

	/*
	 * Force a new cpu calculation for client.  This will force a
	 * new memory calculation if the memory data is older than the
	 * sample period.
	 */
	g_usage_cache_kickers++;
	(void) cond_signal(&g_usage_cache_kick);
	ret = cond_wait(&g_usage_cache_wait, &g_usage_cache_lock);
	g_usage_cache_kickers--;
	if (ret != 0 && errno == EINTR) {
		(void) mutex_unlock(&g_usage_cache_lock);
		zsd_warn(gettext(
		    "Interrupted before writing usage size to client\n"));
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}
	cache = zsd_usage_cache_hold_locked();
	if (cache == NULL) {
		zsd_warn(gettext("Usage cache empty.\n"));
		(void) door_return(NULL, 0, NULL, 0);
		thr_exit(NULL);
	}
	(void) mutex_unlock(&g_usage_cache_lock);

	/* Copy current usage data to stack to send to client */
	usage = (zs_usage_t *)alloca(cache->zsuc_size);

	/* Filter out results if caller is non-global zone */
	zsd_usage_filter(zoneid, cache, usage, is_gz);

	rvalp = (void *)usage;
	rvals = usage->zsu_size;
	zsd_usage_cache_rele(cache);

	(void) door_return(rvalp, rvals, NULL, 0);
	thr_exit(NULL);
}

static volatile boolean_t g_quit;

/* ARGSUSED */
static void
zonestat_quithandler(int sig)
{
	g_quit = B_TRUE;
}

/*
 * The stat thread generates new utilization data when clients request
 * it.  It also manages opening and closing the subsystems used to gather
 * data depending on if clients exist.
 */
/* ARGSUSED */
void *
stat_thread(void *arg)
{
	time_t start;
	time_t now;
	time_t next_memory;
	boolean_t do_memory;
	boolean_t do_read;
	boolean_t do_close;

	start = time(NULL);
	if (start < 0) {
		if (g_quit == B_TRUE)
			goto quit;
		zsd_warn(gettext("Unable to fetch current time"));
		g_quit = B_TRUE;
		goto quit;
	}

	next_memory = start;
	while (g_quit == B_FALSE) {
		for (;;) {
			/*
			 * These are used to decide if the most recent memory
			 * calculation was within a sample interval,
			 * and weather or not the usage collection needs to
			 * be opened or closed.
			 */
			do_memory = B_FALSE;
			do_read = B_FALSE;
			do_close = B_FALSE;

			/*
			 * If all clients have gone, close usage collecting
			 */
			(void) mutex_lock(&g_usage_cache_lock);
			if (!g_hasclient && g_open == B_TRUE) {
				do_close = B_TRUE;
				(void) mutex_unlock(&g_usage_cache_lock);
				break;
			}
			if (g_quit == B_TRUE) {
				(void) mutex_unlock(
				    &g_usage_cache_lock);
				break;
			}
			/*
			 * Wait for a usage data request
			 */
			if (g_usage_cache_kickers == 0) {
				(void) cond_wait(&g_usage_cache_kick,
				    &g_usage_cache_lock);
			}
			now = time(NULL);
			if (now < 0) {
				if (g_quit == B_TRUE) {
					(void) mutex_unlock(
					    &g_usage_cache_lock);
					goto quit;
				}
				g_quit = B_TRUE;
				(void) mutex_unlock(&g_usage_cache_lock);
				zsd_warn(gettext(
				    "Unable to fetch current time"));
				goto quit;
			}
			if (g_hasclient) {
				do_read = B_TRUE;
				if (now >= next_memory) {
					do_memory = B_TRUE;
					next_memory = now + g_interval;
				}
			} else {
				do_close = B_TRUE;
			}
			(void) mutex_unlock(&g_usage_cache_lock);
			if (do_read || do_close)
				break;
		}
		g_now = now;
		g_hrnow = gethrtime();
		if (g_hasclient && g_open == B_FALSE) {
			g_start = g_now;
			g_hrstart = g_hrnow;
			g_ctl = zsd_open(g_ctl);
			if (g_ctl == NULL)
				zsd_warn(gettext(
				    "Unable to open zone statistics"));
			else
				g_open = B_TRUE;
		}
		if (do_read && g_ctl) {
			if (zsd_read(g_ctl, B_FALSE, do_memory) != 0) {
				zsd_warn(gettext(
				    "Unable to read zone statistics"));
				g_quit = B_TRUE;
				return (NULL);
			}
		}
		(void) mutex_lock(&g_usage_cache_lock);
		if (!g_hasclient && g_open == B_TRUE && g_ctl) {
			(void) mutex_unlock(&g_usage_cache_lock);
			zsd_close(g_ctl);
			g_open = B_FALSE;
		} else {
			(void) mutex_unlock(&g_usage_cache_lock);
		}
	}
quit:
	if (g_open)
		zsd_close(g_ctl);

	(void) thr_kill(g_main, SIGINT);
	thr_exit(NULL);
	return (NULL);
}

void
zsd_set_fx()
{
	pcinfo_t pcinfo;
	pcparms_t pcparms;

	(void) strlcpy(pcinfo.pc_clname, "FX", sizeof (pcinfo.pc_clname));
	if (priocntl(0, 0, PC_GETCID, (caddr_t)&pcinfo) == -1) {
		zsd_warn(gettext("cannot get FX class parameters"));
		return;
	}
	pcparms.pc_cid = pcinfo.pc_cid;
	((fxparms_t *)pcparms.pc_clparms)->fx_upri = 60;
	((fxparms_t *)pcparms.pc_clparms)->fx_uprilim = 60;
	((fxparms_t *)pcparms.pc_clparms)->fx_tqsecs = 0;
	((fxparms_t *)pcparms.pc_clparms)->fx_tqnsecs = FX_NOCHANGE;
	if (priocntl(P_PID, getpid(), PC_SETPARMS, (caddr_t)&pcparms) == -1)
		zsd_warn(gettext("cannot enter the FX class"));
}

static int pipe_fd;

static void
daemonize_ready(char status)
{
	/*
	 * wake the parent with a clue
	 */
	(void) write(pipe_fd, &status, 1);
	(void) close(pipe_fd);
}

static int
daemonize_start(void)
{
	char data;
	int status;

	int filedes[2];
	pid_t pid;

	(void) close(0);
	(void) dup2(2, 1);

	if (pipe(filedes) < 0)
		return (-1);

	(void) fflush(NULL);

	if ((pid = fork1()) < 0)
		return (-1);

	if (pid != 0) {
		/*
		 * parent
		 */
		struct sigaction act;

		act.sa_handler = SIG_DFL;
		(void) sigemptyset(&act.sa_mask);
		act.sa_flags = 0;

		(void) sigaction(SIGPIPE, &act, NULL);  /* ignore SIGPIPE */

		(void) close(filedes[1]);
		if (read(filedes[0], &data, 1) == 1) {
			/* forward ready code via exit status */
			exit(data);
		}
		status = -1;
		(void) wait4(pid, &status, 0, NULL);
		/* daemon process exited before becoming ready */
		if (WIFEXITED(status)) {
			/* assume daemon process printed useful message */
			exit(WEXITSTATUS(status));
		} else {
			zsd_warn(gettext("daemon process killed or died"));
			exit(1);
		}
	}

	/*
	 * child
	 */
	pipe_fd = filedes[1];
	(void) close(filedes[0]);

	/*
	 * generic Unix setup
	 */
	(void) setsid();
	(void) umask(0000);

	return (0);
}

static void
fattach_all_zones(boolean_t detach_only)
{
	zoneid_t *zids;
	uint_t nzids, nzids_last;
	int i;

again:
	(void) zone_list(NULL, &nzids);
	nzids_last = nzids;
	zids = (zoneid_t *)malloc(sizeof (zoneid_t) * nzids_last);
	if (zids == NULL)
		zsd_error(gettext("Out of memory"));

	(void) zone_list(zids, &nzids);
	if (nzids > nzids_last) {
		free(zids);
		goto again;
	}
	for (i = 0; i < nzids; i++)
		zsd_fattach_zone(zids[i], g_server_door, detach_only);

	free(zids);
}

int
main(int argc, char *argv[])
{

	int arg;
	thread_t tid;
	scf_simple_prop_t *prop;
	uint64_t *intervalp;
	boolean_t opt_cleanup = B_FALSE;

	g_main = thr_self();
	g_quit = B_FALSE;
	(void) signal(SIGINT, zonestat_quithandler);
	(void) signal(SIGTERM, zonestat_quithandler);
	(void) signal(SIGHUP, zonestat_quithandler);
/*	(void) sigignore(SIGCHLD); */
	(void) sigignore(SIGPIPE);

	if (getzoneid() != GLOBAL_ZONEID)
		zsd_error(gettext("Must be run from global zone only"));

	while ((arg = getopt(argc, argv, "c"))
	    != EOF) {
		switch (arg) {
		case 'c':
			opt_cleanup = B_TRUE;
			break;
		default:
			zsd_error(gettext("Invalid option"));
		}
	}

	if (opt_cleanup) {
		if (zsd_disable_cpu_stats() != 0)
			exit(1);
		else
			exit(0);
	}

	/* Get the configured sample interval */
	prop = scf_simple_prop_get(NULL, "svc:/system/zones-monitoring:default",
	    "config", "sample_interval");
	if (prop == NULL)
		zsd_error(gettext("Unable to fetch SMF property "
		    "\"config/sample_interval\""));

	if (scf_simple_prop_type(prop) != SCF_TYPE_COUNT)
		zsd_error(gettext("Malformed SMF property "
		    "\"config/sample_interval\".  Must be of type \"count\""));

	intervalp = scf_simple_prop_next_count(prop);
	g_interval = *intervalp;
	if (g_interval == 0)
		zsd_error(gettext("Malformed SMF property "
		    "\"config/sample_interval\".  Must be greater than zero"));

	scf_simple_prop_free(prop);

	if (daemonize_start() < 0)
		zsd_error(gettext("Unable to start daemon\n"));

	/* Run at high priority */
	zsd_set_fx();

	(void) mutex_init(&g_usage_cache_lock, USYNC_THREAD, NULL);
	(void) cond_init(&g_usage_cache_kick, USYNC_THREAD, NULL);
	(void) cond_init(&g_usage_cache_wait, USYNC_THREAD, NULL);

	g_server_door = door_create(zsd_server, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	if (g_server_door < 0)
		zsd_error(gettext("Unable to create server door\n"));


	g_stat_door = door_create(zsd_stat_server, NULL, DOOR_UNREF_MULTI |
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	if (g_stat_door < 0)
		zsd_error(gettext("Unable to create statistics door\n"));

	fattach_all_zones(B_FALSE);

	if (thr_create(NULL, 0, stat_thread, NULL, 0, &tid) != 0)
		zsd_error(gettext("Unable to create statistics thread\n"));

	daemonize_ready(0);

	/* Wait for signal to quit */
	while (g_quit == B_FALSE)
		(void) pause();

	/* detach doors */
	fattach_all_zones(B_TRUE);

	(void) door_revoke(g_server_door);
	(void) door_revoke(g_stat_door);

	/* kick stat thread and wait for it to close the statistics */
	(void) mutex_lock(&g_usage_cache_lock);
	g_quit = B_TRUE;
	(void) cond_signal(&g_usage_cache_kick);
	(void) mutex_unlock(&g_usage_cache_lock);
	(void) thr_join(tid, NULL, NULL);
	return (0);
}
