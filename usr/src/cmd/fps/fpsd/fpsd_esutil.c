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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <thread.h>
#include <time.h>
#include <sys/systeminfo.h>
#include <sys/cred.h>
#include <dirent.h>
#include <libdevinfo.h>
#include <sys/pm.h>
#include <sys/ppmio.h>
#include <locale.h>

#include "fpsapi.h"
#include "fpsd.h"
#include "messages.h"


#define	DEV_PM	"/devices/pseudo/pm@0:pm"
#define	DEFAULT_CPU_FULL_POWER	3

int  is_estar_system = 0;   /* Not an E* system, by default */
int  sys_pm_state = PM_SYSTEM_PM_DISABLED; /* By default autopm disabled */


static di_node_t  fps_di_root = DI_NODE_NIL;
static di_prom_handle_t  fps_di_prom = DI_PROM_HANDLE_NIL;
static char **cpu_dpaths = NULL;  /* Used only on E* system */
static	int	*proc_ids = NULL;	/* Used only on E* system */
static	int	num_cpus = 0;	/* Used only on E* system */
static int  devpm_fd = -1;	/* Used only on E* system */
static int  full_pwr = DEFAULT_CPU_FULL_POWER;

/*
 * Initialize system PM state enable/disable and
 * enable system default info logging accordingly.
 * Note: Even for systems for which CPU PM is not enabled by
 * default, disk PM may be enabled explicitly using power.conf;
 * If power management is enabled, disable informational logging
 * by default.
 *   Some platforms don't have /dev/pm entry. It is perfectly OK.
 * Don't complain if there is no /dev/pm entry.
 * The platforms on which CPU PM is enabled by default, would
 * ofcourse have /dev/pm entry.
 *
 * Note: open_dev_pm() should have been called initially before
 *       calling this function.
 *
 */

void
update_pm_state()
{
	int pm_stat;

	if (devpm_fd == -1)
		return;

	pm_stat = ioctl(devpm_fd, PM_GET_PM_STATE);

	if (pm_stat == -1)
		return;

	sys_pm_state = pm_stat;

}

/*
 * Some platforms don't support power management. (neither CPU nor disk)
 * Those platforms don't have /dev/pm entry. Don't complain in such case.
 * Some platfors support PM only for disks. (they have /dev/pm entry.
 * and logging is disabled on those platforms.)
 * Some platforms support PM for both disks and CPUs (apart from others).
 * Those platforms also have /dev/pm entry.
 * Note that even desktops which support CPU PM E* can be custom
 * configured to remove power management drivers. In that case,
 * there won't be any /dev/pm entry and it is valid config.
 *
 */

static  void  open_dev_pm()
{
	devpm_fd = open(DEV_PM, O_RDWR);

}

/*
 * Initialize Estar info database.
 *
 */

void
init_estar_db()
{
	di_node_t  fnode, node;
	di_prop_t  nextp;
	char *path = NULL;
	int cpu_i;
	int  is_pmprop_found = 0;
	pm_req_t  pmreq;
	uchar_t  *prop_data = NULL;

	/*
	 * First open /dev/pm and keep it open for later uses.
	 * Note that this needs to be open on all power management supported
	 * systems. Some systems support power mgmt on only some
	 * devices like disk, but not CPU. /dev/pm does not exist on
	 * some platforms. Also PM drivers can be removed on custom
	 * configurations.
	 */
	open_dev_pm();

	if (devpm_fd == -1)
		return;

	fps_di_root = di_init("/", DINFOCPYALL);

	if (DI_NODE_NIL == fps_di_root) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, DI_INIT_FAIL);
	}

	fps_di_prom = di_prom_init();

	if (DI_PROM_HANDLE_NIL == fps_di_prom) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, DI_PROM_INIT_FAIL);
		di_fini(fps_di_root);
	}

	if (di_prom_prop_lookup_bytes(fps_di_prom, fps_di_root,
	    "energystar-v3", &prop_data) == -1)
		goto exit_es;

	/*
	 * As a final check, also check for "us" driver property pm-components
	 * On Estar systems, the driver should define this property.
	 */

	fnode = node = di_drv_first_node("us", fps_di_root);

	if (DI_NODE_NIL == node) {
		goto exit_es;
	}

	is_pmprop_found = 0;
	for (nextp = di_prop_next(node, DI_PROP_NIL); nextp != DI_PROP_NIL;
	    nextp = di_prop_next(node, nextp)) {
		if (strcmp(di_prop_name(nextp), "pm-components") == 0) {
			is_pmprop_found = 1;
			break;
		}
	}

	if (!is_pmprop_found)
		goto exit_es;

	is_estar_system = 1;  /* CPU power mgmt supported E* system */

	num_cpus = 0;
	while (node != DI_NODE_NIL) {
		num_cpus++;
		node = di_drv_next_node(node);
	}

	cpu_dpaths = (char **)calloc(num_cpus+1, sizeof (char *));
	proc_ids = (int *)calloc(num_cpus+1, sizeof (int));
	proc_ids[num_cpus] = -1;  /* Terminate processor ids by -1 */

	cpu_i = 0;
	for (node = fnode; node != DI_NODE_NIL; node = di_drv_next_node(node)) {
		proc_ids[cpu_i] = -1;
		cpu_dpaths[cpu_i] = NULL;

		path = di_devfs_path(node);
		if (NULL == path)
			continue;
		cpu_dpaths[cpu_i] = strdup(path);
		di_devfs_path_free(path);
	/*
	 * Keep the mapping between path and processor IDs.
	 * Currently, processor IDs are not used. But may be used in future.
	 */

	/*
	 * On workstation platforms (where CPU E* supported),
	 * processor ID and instance numbers are same.
	 * This may change in future. So watch out.
	 */

		proc_ids[cpu_i]  = di_instance(node); /* Currently unused. */
		cpu_i++;
	}

	proc_ids[cpu_i] = -1;
	cpu_dpaths[cpu_i] = NULL;

	/* Initialize what "FULL POWER" mode is. */
	full_pwr = DEFAULT_CPU_FULL_POWER;

	pmreq.physpath = cpu_dpaths[0];
	pmreq.component = 0;
	pmreq.value = 0;
	pmreq.data  = NULL;
	pmreq.datasize  = 0;


	full_pwr = ioctl(devpm_fd, PM_GET_FULL_POWER, &pmreq);
	if (full_pwr == -1)
		full_pwr = DEFAULT_CPU_FULL_POWER;
exit_es:

	if (fps_di_root != DI_NODE_NIL) {
		di_fini(fps_di_root);
		fps_di_root = DI_NODE_NIL;
	}
	if (DI_PROM_HANDLE_NIL != fps_di_prom) {
		di_prom_fini(fps_di_prom);
		fps_di_prom = DI_PROM_HANDLE_NIL;
	}
}

/*
 *  Return the min(idle_times), min(remaining_times), max(rem_time) for all
 *  CPUs in full power mode. The "remain time" is the remaining
 *  threshold time after which the CPU will make next lower level
 *  power transition if left idle.
 *  If the CPUs are not in full power mode or could not exactly determine
 *  the power mode then return -1.
 *  return 0 if CPUs are in full power mode.
 */

int
get_idle_rem_stats(int *min_idle, int *min_rem, int *max_rem)
{
	int idle_time;
	int pmstats[2];
	int i;
	pm_req_t  pmreq;
	int ret;

	*min_idle = -1;
	*min_rem = -1;
	*max_rem = -1;

	for (i = 0; i < num_cpus; i++) {

		pmreq.physpath = cpu_dpaths[i];
		pmreq.component = 0;
		pmreq.value = 0;
		pmreq.data  = pmstats;
		pmreq.datasize  = sizeof (pmstats);
		idle_time = ioctl(devpm_fd, PM_GET_TIME_IDLE, &pmreq);
		if (idle_time == -1)
			continue;
		ret = ioctl(devpm_fd, PM_GET_STATS, &pmreq);

		/* Now pmstats[0] = cur power level; pmstats[1]=remain time */
		if (ret == -1)
			continue;
		if (pmstats[0] != full_pwr)
			continue;

		if ((*min_idle == -1) || (idle_time < *min_idle))
			*min_idle = idle_time;
		if (*min_rem == -1 || pmstats[1] < *min_rem) {
			*min_rem = pmstats[1];

		/*
		 * The remain time can be negative if there are 2 cpus
		 * and 1 cpu is ready to transition and the other one is not
		 */
			if (*min_rem < 0)
				*min_rem = 0;
		}
		if (*max_rem == -1 || pmstats[1] > *max_rem)
			*max_rem = pmstats[1];
	}

	return
	    ((*min_idle == -1 || *min_rem == -1 || *max_rem == -1) ? -1 : 0);
}

/*
 * Wait until CPU comes to full power state or timeout occurs.
 * If multiple threads call this function, execute the
 * PM ioctl system call only once.
 * This is better than all 3 threads polling cpu pwr state same time.
 *
 * Callers of this function should not assume that on returning from
 * this function CPU will be in full power state.
 * (They should check again).
 * This function just optimizes for performance during wait.
 *
 *
 */

void
wait_for_pm_state_change()
{
	int res;
	static mutex_t wrlck;
	static int  is_active = 0;
	static pm_req_t  pmreq;
	static pm_state_change_t  pmsc;
	static char  path[MAXPATHLEN];

	int pwr = 0;
	int cur_lvl = 0; /* 0 = unknown. 1=low, 3=full power */

	pmreq.physpath = cpu_dpaths[0];
	pmreq.component = 0;
	pmreq.value = 0;
	pmreq.data  = NULL;
	pmreq.datasize  = 0;


	(void) mutex_lock(&wrlck);

	if (!is_active) {    /* This is the first thread trying to wait */
		is_active = 1;
		(void) mutex_unlock(&wrlck);

		pmsc.physpath = path;
		pmsc.size = MAXPATHLEN;
		path[0] = 0; /* init not required. Just in case... */

	/*
	 * PM starts buffering the state changes after the first call to
	 * PM_GET_STATE_CHANGE/PM_GET_STATE_CHANGE_WAIT
	 *
	 *   The PM_GET_STATE_CHANGE is a non-blocking call where as _WAIT is
	 * blocking call. The PM_GET_STATE_CHANGE also returns all the info
	 * about the latest buffered state change if already buffered event is
	 * available. So it is important to drain out all old events,
	 * if you are only interested in future events.
	 *
	 * After the state changes the exact information/timestamp about
	 * state changes are reflected in the ioctl struct.
	 * To keep things simple, after draining out all buffered info,
	 * we issue get current power to get the current power level and
	 * then we issue another _WAIT command to get the next power change.
	 *
	 */

		do {

			res =  ioctl(devpm_fd, PM_GET_STATE_CHANGE, &pmsc);

			if (res == -1 && errno != EWOULDBLOCK) {
				fpsd_message(FPSD_NO_EXIT, FPS_WARNING,
				    INTERNAL_FAILURE_WARN,
				    strerror(errno));
				/* 1 second sleep. Avoid busy loop */
				(void) poll(NULL, 0, 1000);
				/* Probably will succeed in next call. */
				goto psc_complete;
			}

		} while (errno != EWOULDBLOCK);

		/* drain out all buffered state changes */

		/* If current state is full power, then get out. */

		do {
			pwr = ioctl(devpm_fd, PM_GET_CURRENT_POWER, &pmreq);
			if (pwr != -1) break;
			if (errno == EAGAIN) {
				(void) poll(NULL, 0, 1000);  /* 1 sec sleep */
				continue;
			} else {
				fpsd_message(FPSD_NO_EXIT, FPS_WARNING,
				    INTERNAL_FAILURE_WARN1,
				    strerror(errno));
				(void) poll(NULL, 0, 1000);  /* 1 sec sleep */
				goto psc_complete;
			}
			/*CONSTCOND*/
		} while (1);

		if (pwr == full_pwr)
			goto psc_complete;

		while (cur_lvl != full_pwr) {
			pmsc.physpath = path;
			pmsc.size = MAXPATHLEN;
			path[0] = 0; /* init not required. Just in case... */

			do {
				res = ioctl(devpm_fd,
				    PM_GET_STATE_CHANGE_WAIT, &pmsc);
				if (res == -1 && errno == EINTR) {
					/* 1 second sleep */
					(void) poll(NULL, 0, 1000);
				}
			} while (res == -1 && errno == EINTR);

			if (res == -1) {
				fpsd_message(FPSD_NO_EXIT, FPS_WARNING,
				    INTERNAL_FAILURE_WARN2,
				    strerror(errno));
		/*
		 * If there are failures in state change ioctl, just would
		 * fall back to normal polling of status later. get out quiet.
		 */
			/* avoid busy loop -- 1 second sleep */
			(void) poll(NULL, 0, 1000);
			goto psc_complete;
		}

		if (strcmp(pmsc.physpath, cpu_dpaths[0]) == 0 &&
		    pmsc.new_level == full_pwr)
			cur_lvl = full_pwr;
		}

psc_complete:
		(void) mutex_lock(&wrlck);
		is_active = 0;
		(void) mutex_unlock(&wrlck);

	} else {
		/* Release the lock first */
		(void) mutex_unlock(&wrlck);
	/*
	 * Already one other thread is active issuing ioctl call.
	 * Just poll here to check the local flag without any expensive
	 * ioctl calls until the transition is complete.
	 */
		(void) poll(NULL, 0, 1000); /* first time 1 second wait */
		for (;;) {
			(void) mutex_lock(&wrlck);
			if (!is_active) {
				(void) mutex_unlock(&wrlck);
				break;
			}
			(void) mutex_unlock(&wrlck);
			(void) poll(NULL, 0, 4000); /* 4 seconds wait */
		}
	}
}
