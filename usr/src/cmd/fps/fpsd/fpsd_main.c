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
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <synch.h>
#include <syslog.h>
#include <pthread.h>
#include <thread.h>
#include <signal.h>
#include <limits.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/wait.h>
#include <sys/processor.h>
#include <ctype.h>
#include <poll.h>
#include <sys/wait.h>
#include <dirent.h>
#include <kstat.h>
#include <libscf.h>
#include <sys/pset.h>
#include <sys/param.h>
#include <sys/corectl.h>
#include <libgen.h>
#include <priv_utils.h>
#include <fpsapi.h>

#include "fpsd.h"
#include "messages.h"

/* Only messages of priority 'debug_level' and lower will be logged */
int debug_level = DFLT_DBG_LVL;

fpsd_t  fpsd;
mach_conf_t fpsd_conf;
char  fps_tst_path[MAXPATHLEN + MAXNAMELEN];

void terminate_process();

/* Local Static Variables */

static int  door_id = -1;
static char *str_fps_fmri = NULL;

/* Local static functions */

static int check_if_supported_CPU(char *cpu_brand, char *arch);
static int read_conf_props();
static  void fpsd_fini();
static int reprobe_and_reread_config();
static int fpsd_probe_config();
static int fpsd_probe(mach_conf_t *m_stat);


/* ARGSUSED */
void
sig_hup_handler(int sig, siginfo_t *siginfo, void *sigctx)
{
	fpsd_message(FPSD_NO_EXIT, FPS_INFO,
	    SIGNAL_INFO, "HUP", SIGHUP);
	fpsd_read_config();
}

void
fpsd_read_config()
{
	int ret;

	ret = reprobe_and_reread_config();
	if (NO_CPUS_2_TEST == ret) {
		while (NO_CPUS_2_TEST == ret) {
			sleep(600);
			ret = reprobe_and_reread_config();
		}
	}
}

static int
reprobe_and_reread_config()
{
	int ret;

	fpsd.d_conf->m_reprobe = 1;
	if (fpsd_probe(fpsd.d_conf) != 0) {
		(void) fpsd_message(FPSD_EXIT_ERROR,
		    FPS_ERROR, UNSUPPORTED_SYSTEM);
	}
	ret = fpsd_probe_config();
	if (ZERO_INTERVAL == ret) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR,
		    FPSD_ZERO_INTVL, fpsd.d_interval);
	}
	return (ret);

}

static int
daemon_exists()
{
	int door_fd;
	struct door_info dinfo;

	door_fd = open(FPS_DOOR_FILE, O_RDONLY);
	if (door_fd < 0)
		return (NO_DAEMON);
	if (door_info(door_fd, &dinfo) < 0) {
		(void) close(door_fd);
		return (NO_DAEMON);
	}
	if ((dinfo.di_attributes & DOOR_REVOKED) ||
	    (dinfo.di_data != (uintptr_t)FPS_DOOR_COOKIE)) {
		(void) close(door_fd);
		return (NO_DAEMON);
	}
	if (dinfo.di_target != getpid()) {
		/* Daemon exists; different process */
		(void) close(door_fd);
		return (DAEMON_EXISTS);
	} else {
		(void) close(door_fd);
		return (DAEMON_EXISTS_AND_SAME_PROC); /* Same process */
	}

}

static  int
fps_setup_door(void)
{

	struct stat	stbuf;
	int newfd;

	/*  Create the door */
	door_id = door_create(fps_door_handler, FPS_DOOR_COOKIE, 0);

	if (door_id < 0) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, DAEMON_DOOR_FAIL,
		    strerror(errno));
		return (-1);
	}

	if (stat(FPS_DOOR_FILE, &stbuf) < 0) {
		if ((newfd = creat(FPS_DOOR_FILE, 0600)) < 0) {
			fpsd_message(FPSD_NO_EXIT, FPS_ERROR,
			    DAEMON_DOOR_FILE_FAIL, strerror(errno));
			return (-1);
		}
		(void) close(newfd);
	}

	if (fattach(door_id, FPS_DOOR_FILE) < 0) {
		if ((errno != EBUSY) || (fdetach(FPS_DOOR_FILE) < 0) ||
		    (fattach(door_id, FPS_DOOR_FILE) < 0)) {
			fpsd_message(FPSD_NO_EXIT, FPS_ERROR,
			    DAEMON_DOOR_FATTACH_FAIL,
			    strerror(errno));
			return (-1);
		}
	}

	return (0);
}

void
terminate_process()
{
	fpsd_fini();
	if (door_id >= 0) {
		(void) door_revoke(door_id);
		(void) unlink(FPS_DOOR_FILE);
	}
}

static int
become_daemon_init()
{
	int pfds[2];
	pid_t pid;
	int status;
	sigset_t set, oset;

	/*
	 * Block all signals prior to the fork and leave them blocked in
	 * the parent so we don't get in a situation where the parent gets
	 * SIGINT and returns non-zero exit status and the child is
	 * actually running. In the child, restore the signal mask once
	 * we've done our setsid().
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);
	(void) sigdelset(&set, SIGHUP);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);


	if (pipe(pfds) == -1)
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, DAEMON_PIPE_FAIL,
		    strerror(errno));

	if ((pid = fork()) == -1)
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, DAEMON_FORK_FAIL,
		    strerror(errno));

	/*
	 * If we're the parent process, wait for either the child to send
	 * us the appropriate exit status over the pipe or for the read to
	 * fail (presumably with 0 for EOF if our child terminated
	 * abnormally). If the read fails, exit with either the child's
	 * exit status if it exited or with FPSD_EXIT_ERROR if it died
	 * from a fatal signal.
	 */
	if (pid != 0) { /* Parent */
		(void) close(pfds[1]);

		if (read(pfds[0], &status, sizeof (status)) == sizeof (status))
			_exit(status);

		if (waitpid(pid, &status, 0) == pid && WIFEXITED(status))
			_exit(WEXITSTATUS(status));

		_exit(FPSD_EXIT_ERROR);
	}

	fpsd.d_pid = getpid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL); /* Restore signal mask */
	(void) setsid();
	(void) chdir("/");
	(void) umask(022);
	(void) close(pfds[0]);
	return (pfds[1]);
}


static void
become_daemon_fini(int fd)
{
	(void) close(fd);
	if ((fd = open("/dev/null", O_RDWR)) >= 0) {
		(void) fcntl(fd, F_DUP2FD, STDIN_FILENO);
		(void) fcntl(fd, F_DUP2FD, STDOUT_FILENO);
		(void) fcntl(fd, F_DUP2FD, STDERR_FILENO);
		(void) close(fd);
	}

}

/*
 * Calculates the number of iterations needed for each testable cpu
 * based on the frequency and using the following table. This table
 * tells how much time it takes for the matrix sizes on a processor
 * with frequencies upto 1000MHz/1500 MHz/ 2000 MHz. This data is
 * based on profiling done earlier.
 *
 * f\p\t| 100  200   300   400    500     600     700     800     900 ms
 * ======================================================================
 * 1000  1-28 29-50 51-62 63-72  73-81   82-90   91-98   99-105  106-112
 * 1500  1-36 37-64 65-80 81-93  94-106  107-115 116-126 127-134 135-144
 * 2000  1-39 40-70 71-87 88-102 103-113 114-126 127-137 138-148 149-157
 *
 * If asc is 0, these iterations will be executed in the descending of
 * of matrix size; else the iterations will be executed in the increasing
 * order of matrix sizes. This is done to average out the execution time
 * as large matrices mean more time to complete the test.
 */

static void
calculateTotalIterations(mach_conf_t *m_stat)
{
	const int num_iterations_1K = 112;
	const int num_iterations_1500 = 144;
	const int num_iterations_2K = 157;

	int total_iterations = 0;
	int asc = 1;
	int i;
	int freq;

	if (m_stat->m_cpuids_size <= 0) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR,
		    FPSD_NO_CPUS_TO_TEST);
	}
	m_stat->m_num_cpus_to_test = 0;
	for (i = 0; i < m_stat->m_cpuids_size; i++) {
		if (m_stat->m_cpus[i].disable_test)
			continue;
		freq = m_stat->m_cpus[i].frequency;
		m_stat->m_cpus[i].asc = asc;
		if (freq < 1500) {
			total_iterations += num_iterations_1K;
			m_stat->m_cpus[i].total_iterations = num_iterations_1K;
		} else if (freq < 2000) {
			total_iterations += num_iterations_1500;
			m_stat->m_cpus[i].total_iterations =
			    num_iterations_1500;
		} else {
			total_iterations += num_iterations_2K;
			m_stat->m_cpus[i].total_iterations = num_iterations_2K;
		}
		if (asc) {
			m_stat->m_cpus[i].previous_iteration = 0;
			asc = 0;
		} else {
			m_stat->m_cpus[i].previous_iteration =
			    m_stat->m_cpus[i].total_iterations + 1;
			asc = 1;
		}
		m_stat->m_num_cpus_to_test++;
	}
	fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, TOT_ITERS,
	    total_iterations, m_stat->m_num_cpus_to_test);
	fpsd.d_conf->total_iter = total_iterations;
}

/*
 * Calculates the time interval between the tests invocation in seconds.
 * The goal is to complete once all iterations for all cpus in a 24hr
 * period.
 */

static int
calculateTimeInterval()
{
	int total_iterations = fpsd.d_conf->total_iter;
	int intvl;

	if (total_iterations <= 0) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, FPSD_MIS_CALCULATIONS,
		    total_iterations);
	}
	intvl = (24*60*60) / (total_iterations);
	fpsd.d_interval = intvl;
	return (1);
}

/*
 * Checks if a platform is supported by looking for the corresponding
 * binary under /usr/lib/fps/ARCH/CPU_BRAND/fptest; (e.g) ARCH = sun4u,
 * CPU_BRAND = UltraSPARC-III;
 */

static int
check_if_supported_CPU(char *cpu_brand, char *arch)
{
	(void) snprintf(fps_tst_path, sizeof (fps_tst_path), "%s/%s/%s/%s",
	    FPS_DIR, arch, cpu_brand, FPS_FPUTST_NAME);
	fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, FPTST_BIN_PTH, fps_tst_path);
	if (access(fps_tst_path, X_OK) == 0)
		return (1);
	else
		return (0);
}

/*
 * fpsd_probe(): probes system configuration and
 * sets up the fpsd_t structure.
 * Returns 0 on success, non-zero on failure.
 *
 */
static int
fpsd_probe(mach_conf_t *m_stat)
{
	kstat_ctl_t *kstat_ctl;
	kstat_t *fps_kstat;
	kstat_named_t *kstat_cpu_name;
	kstat_named_t *kstat_cpu_freq;
	char *cpu_brand = NULL;
	int cpu_freq;
	int supported;
	int i;
	int cpuid_index;

	processorid_t *cpuid_list;
	kid_t ret;
	int total_onln = sysconf(_SC_NPROCESSORS_ONLN);

	/* probe the system and fill in mach_conf_t elements */

	(void) sysinfo(SI_MACHINE, m_stat->m_machine,
	    sizeof (m_stat->m_machine) - 1);

	if (1 == m_stat->m_reprobe) {
		/* Reprobe request */
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, REPRBE_REQ);
		fpsd.d_iteration = 0;
		fpsd.d_interval = 0;
		fpsd.d_fpuid_index = 0;
		m_stat->m_num_on_fpuids = 0;
		m_stat->m_cpuids_size = 0;
		m_stat->total_iter = 0;
		m_stat->m_reprobe = 0;
		m_stat->m_num_cpus_to_test = 0;

		if (NULL != fpsd.d_ignore_cpuid) {
			free(fpsd.d_ignore_cpuid);
		}
	}

	/*
	 * Find number of online FPUs, and initialize
	 * m_stat->m_num_on_fpuids. Then collect kstat
	 * cpu_info for each.
	 */

	cpuid_list = (processorid_t *)malloc(m_stat->m_num_fpus *
	    sizeof (processorid_t));
	if (NULL == cpuid_list) {
		fpsd_message(FPSD_NO_EXIT, FPS_INFO, LIBRARY_CALL_FAIL,
		    "malloc", strerror(errno));
		return (-1);
	}

	cpuid_index = 0;
	for (i = 0; i < m_stat->m_max_cpuid; i++) {
		if (p_online(i, P_STATUS) == P_ONLINE) {
			cpuid_list[cpuid_index++] = i;
		}
		if (cpuid_index == total_onln) {
			/* Break after all onln cpuids found */
			break;
		}
	}
	m_stat->m_num_on_fpuids = (uint_t)cpuid_index;
	fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, NUM_ONLN_CPUS,
	    m_stat->m_num_on_fpuids);

	/*
	 * Get cpu-brand info all valid cpuids using kstat.
	 * This is needed to take care
	 * of mixed cpu scenario
	 */

	kstat_ctl = kstat_open();
	if (NULL == kstat_ctl) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, LIBRARY_CALL_FAIL,
		    "kstat_open", strerror(errno));
		free(cpuid_list);
		return (-1);
	}


	for (i = 0; i < m_stat->m_num_on_fpuids; i++) {

		supported = 0;
		fps_kstat = NULL;

		fps_kstat = kstat_lookup(kstat_ctl, "cpu_info",
		    cpuid_list[i], NULL);
		if (NULL == fps_kstat) {
			fpsd_message(FPSD_NO_EXIT, FPS_INFO,
			    LIBRARY_CALL_FAIL, "kstat_lookup",
			    strerror(errno));
			kstat_close(kstat_ctl);
			free(cpuid_list);
			return (-1);
		}
		ret = kstat_read(kstat_ctl, fps_kstat, NULL);
		if (ret != -1) {
			kstat_cpu_name = kstat_data_lookup(fps_kstat,
			    "brand");
			if (NULL != kstat_cpu_name) {
				cpu_brand = KSTAT_NAMED_STR_PTR(
				    kstat_cpu_name);

				supported = check_if_supported_CPU(
				    cpu_brand, m_stat->m_machine);
			}
		} else {
			fpsd_message(FPSD_NO_EXIT, FPS_INFO,
			    CPU_BRAND_PROBE_FAIL, cpuid_list[i]);
			(void) kstat_close(kstat_ctl);
			free(cpuid_list);
			return (-1);
		}
		if (!supported) {
			fpsd_message(FPSD_NO_EXIT, FPS_INFO,
			    CPU_NOT_SUPPORTED, cpu_brand,
			    cpuid_list[i]);
			m_stat->m_cpus[i].disable_test = 1;
			(void) strcpy(m_stat->m_cpus[i].fptest_path, "");
		} else {
			m_stat->m_cpus[i].disable_test = 0;
			m_stat->m_num_cpus_to_test++;
			(void) strlcpy(m_stat->m_cpus[i].fptest_path,
			    fps_tst_path,
			    sizeof (m_stat->m_cpus[i].fptest_path));
		}

		/* Get frequency */

		kstat_cpu_freq = kstat_data_lookup(fps_kstat,
		    "clock_MHz");
		if (NULL != kstat_cpu_freq) {
			cpu_freq = (int)kstat_cpu_freq->value.l;
		} else {
			fpsd_message(FPSD_NO_EXIT, FPS_INFO,
			    FREQ_PROBE_FAIL, cpuid_list[i]);
			kstat_close(kstat_ctl);
			free(cpuid_list);
			return (-1);
		}

		m_stat->m_cpus[i].cpuid = cpuid_list[i];
		m_stat->m_cpus[i].frequency = cpu_freq;
		(void) strncpy(m_stat->m_cpus[i].brand, cpu_brand,
		    sizeof (m_stat->m_cpus[i].brand));
		m_stat->m_cpus[i].num_failures = 0;

		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, CPU_INFO,
		    cpuid_list[i], m_stat->m_cpus[i].brand,
		    cpu_freq);
	}
	m_stat->m_cpuids_size = (int)m_stat->m_num_on_fpuids;
	fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
	    NUM_CPUS_2_TST, m_stat->m_cpuids_size);
	free(cpuid_list);
	kstat_close(kstat_ctl);
	if (m_stat->m_num_cpus_to_test <= 0) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR,
		    FPSD_NO_CPUS_TO_TEST);
		return (-1);
	}
	return (0);
}

/*
 * returns 1 if cpuid is found in the list of cpus to be
 * excluded from testing.
 */
static int
ignore_cpu(int cpuid)
{
	int found = 0;
	int i;
	processorid_t   *ignore_cpus = fpsd.d_ignore_cpuid;
	for (i = 0; (i < fpsd.num_ignore_cpus) && (!found); i++) {
		if (ignore_cpus[i] == cpuid) {
			found = 1;
		}
	}
	return (found);
}

/*
 * This function parses the string of cpu-ids separated by
 * "," , constructs the list and disables testing on those
 * cpus. This function assumes fpsd_probe has been called and all
 * the machine config info is available in structure fpsd.
 */

static int
parse_and_set_cpu_id_list(char *strCPUs)
{
	char *last;
	int num_cpus = 0, invalid = 0;
	int *tmp_cpus;
	int num_cpus_to_test = 0;
	int i;
	int t_cpuid;
	char *cpu_id;
	static int first_time = 1;

	tmp_cpus = (int *)malloc((int)fpsd.d_conf->m_num_fpus * sizeof (int));
	if (NULL == tmp_cpus)
		return (-1);
	cpu_id = strtok_r(strCPUs, ",", &last);

	while ((NULL != cpu_id) && (!invalid)) {
		(void) strtol(cpu_id, (char **)NULL, 10);
		if (errno != EINVAL) {
			tmp_cpus[num_cpus++] =
			    (int)strtol(cpu_id, (char **)NULL, 10);
			cpu_id = strtok_r(NULL, ",", &last);
		} else {
			fpsd_message(FPSD_NO_EXIT, FPS_ERROR,
			    INVAL_PROP_VALUE, strCPUs);
			invalid = 1;
		}
		if (num_cpus == fpsd.d_conf->m_num_fpus) {
			/* More than max supported cpus */
			fpsd_message(FPSD_NO_EXIT, FPS_ERROR,
			    INVAL_PROP_VALUE, strCPUs);
			invalid = 1;
		}
	}
	if (num_cpus) {
		fpsd.d_ignore_cpuid = (processorid_t *)malloc(
		    sizeof (processorid_t) * (int) num_cpus);
		if (NULL != fpsd.d_ignore_cpuid) {
			for (i = 0; i < num_cpus; i++) {
				fpsd.d_ignore_cpuid[i] = tmp_cpus[i];
			}
			fpsd.num_ignore_cpus = num_cpus;
		} else {
			fpsd.num_ignore_cpus = 0;
		}
	} else if ((num_cpus == 0) || (invalid)) {
		fpsd.d_ignore_cpuid = NULL;
		fpsd.num_ignore_cpus = 0;
	}
	free(tmp_cpus);
	fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, NUM_IGN_CPUS,
	    fpsd.num_ignore_cpus);
	if ((fpsd.num_ignore_cpus > 0) && (fpsd.d_conf->m_cpuids_size > 0)) {
		for (i = 0; i < fpsd.d_conf->m_cpuids_size; i++) {
			t_cpuid = fpsd.d_conf->m_cpus[i].cpuid;
			if (ignore_cpu(t_cpuid)) {
				fpsd.d_conf->m_cpus[i].disable_test = 1;
				fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
				    IGN_CPUS, t_cpuid);
			} else {
				num_cpus_to_test++;
			}
		}
		fpsd.d_conf->m_num_cpus_to_test = num_cpus_to_test;
		if (num_cpus_to_test <= 0)  {
			if (1 == first_time) {
				fpsd_message(FPSD_NO_EXIT, FPS_ERROR,
				    ALL_CPUS_EXCLDED);
				first_time = 0;
			} else {
				fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
				    ALL_CPUS_EXCLDED);
			}
			return (NO_CPUS_2_TEST);
		}
	}
	first_time = 1;
	return (0);
}

#define	CLEAN_UP_SCF_STUFF	{	\
	if (scf_handle_p) {	\
		scf_handle_unbind(scf_handle_p);	\
		scf_handle_destroy(scf_handle_p);	\
	}	\
	if (inst)	\
		scf_instance_destroy(inst);	\
	if (pg)	\
		scf_pg_destroy(pg);	\
	if (scf_prop_p)	\
		scf_property_destroy(scf_prop_p);	\
	if (value)	\
		scf_value_destroy(value);	\
}

/* Read properties from SMF configuration repository using libscf APIs */

static int
read_conf_props()
{
	scf_handle_t *scf_handle_p;
	scf_property_t *scf_prop_p = NULL;
	scf_instance_t *inst = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_value_t	*value = NULL;
	int ret_val = -1;
	int val;
	int64_t intvl;
	int name_len;
	char *strCPUs;

	scf_handle_p = scf_handle_create(SCF_VERSION);
	if ((NULL != scf_handle_p) && (NULL != str_fps_fmri)) {
		if (scf_handle_bind(scf_handle_p) != -1) {
			inst = scf_instance_create(scf_handle_p);
			pg = scf_pg_create(scf_handle_p);
			scf_prop_p = scf_property_create(scf_handle_p);
			if ((NULL == inst) || (NULL == pg) ||
			    (NULL == scf_prop_p)) {
				fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
				    CREATE_FAIL,
				    scf_strerror(scf_error()));
				CLEAN_UP_SCF_STUFF
				return (-1);
			}
			val = scf_handle_decode_fmri(scf_handle_p,
			    str_fps_fmri,
			    NULL, NULL, inst, pg, scf_prop_p, 0);
			if (val != 0) {
				fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
				    HANDLE_DECODE_FAIL,
				    scf_strerror(scf_error()));
				CLEAN_UP_SCF_STUFF
				return (-1);
			}
			val = scf_instance_get_pg_composed(inst, NULL,
			    SMF_FPS_PROP_GRP_NAME, pg);
			if (val != 0) {
				fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
				    INSTANCE_PG_GET_FAIL,
				    scf_strerror(scf_error()));
				CLEAN_UP_SCF_STUFF
				return (-1);
			}
			val = scf_pg_get_property(pg, SMF_PROP_INTVL,
			    scf_prop_p);
			/* Read interval property if defined */
			if (val == 0) {
				value = scf_value_create(scf_handle_p);
				val = scf_property_get_value(scf_prop_p, value);
				val = scf_value_get_integer(value, &intvl);
				if (intvl != 0) {
					fpsd.d_interval = (int)intvl;
					fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
					    INTVL_VAL, intvl);
					ret_val = 0;
				}
			} else {
				fpsd_message(FPSD_NO_EXIT, FPS_INFO,
				    PROP_UNDEFINED, SMF_PROP_INTVL,
				    scf_strerror(scf_error()));
			}
			/*
			 * Read property "exclude_cpus" if defined - this is
			 * the array of cpu-ids to be excluded from testing.
			 */
			val = scf_pg_get_property(pg, SMF_PROP_EXCLD_CPUS,
			    scf_prop_p);
			if (val == 0) {
				val = scf_property_get_value(scf_prop_p, value);
				name_len =
				    scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
				strCPUs = malloc(name_len +1);
				if (NULL == strCPUs) {
					fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
					    LIBRARY_CALL_FAIL, "malloc");
					CLEAN_UP_SCF_STUFF
					return (-1);
				}
				val = scf_value_get_astring(value,
				    strCPUs, name_len);
				if (strlen(strCPUs) > 0) {
					fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
					    EXCL_CPUS, strCPUs);
					ret_val =
					    parse_and_set_cpu_id_list(
					    strCPUs);
				}
			} else {
				fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
				    PROP_UNDEFINED,
				    SMF_PROP_EXCLD_CPUS,
				    scf_strerror(scf_error()));
			}
		}
	}

	/* Clean up */

	CLEAN_UP_SCF_STUFF
	return (ret_val);
}

static int fpsd_init() {
	mach_conf_t *m_conf_p;

	debug_level = DFLT_DBG_LVL;
	fpsd.d_fg = 0;
	fpsd.d_daemon = 0;
	fpsd.d_ignore_cpuid = NULL;
	fpsd.d_iteration = 0;
	fpsd.d_interval = 0;
	fpsd.d_fpuid_index = 0;
	fpsd.d_rootdir = "/";
	fpsd.d_pid = getpid();
	fpsd.d_conf = &fpsd_conf;
	fpsd.d_ts_hup = 0;

	m_conf_p = fpsd.d_conf;
	m_conf_p->m_machine[0] = '\0';
	m_conf_p->m_num_on_fpuids = 0;
	m_conf_p->m_cpuids_size = 0;
	m_conf_p->total_iter = 0;
	m_conf_p->m_reprobe = 0;
	m_conf_p->m_num_cpus_to_test = 0;
	m_conf_p->m_num_fpus = (uint_t)sysconf(_SC_NPROCESSORS_MAX);

	(void) mutex_init(&log_mutex, USYNC_THREAD, NULL);

	m_conf_p->m_max_cpuid = (int)sysconf(_SC_CPUID_MAX) + 1;

	/*
	 * Allocate enough memory to accomodate maximum number of CPUs
	 * supported by this platform.
	 */
	m_conf_p->m_cpus = malloc(sizeof (fps_cpu_t) *
			m_conf_p->m_num_fpus);
	if (NULL == m_conf_p->m_cpus)
		return (1);
	else
		return (0);

}

static void
fpsd_fini() {
	if (fpsd.d_ignore_cpuid)
		free(fpsd.d_ignore_cpuid);
	if (fpsd.d_conf->m_cpus)
		free(fpsd.d_conf->m_cpus);
}

static int
fpsd_probe_config()
{
	int smf_invoked = 0;
	int ret = 0;

	/*
	 * Use smf_get_state to get the status of the service to see
	 * if the status is "online" by now. If so, read the proper-
	 * ties defined using SCF.
	 */

	if (NULL != str_fps_fmri) {
		const char *smf_state = smf_get_state(str_fps_fmri);
		if ((smf_state) && (strncmp(smf_state,
		    SCF_STATE_STRING_ONLINE,
		    strlen(SCF_STATE_STRING_ONLINE)) == 0)) {
			smf_invoked = 1;
			(void) fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
			    SMF_INVOKED, smf_state);

			/* Read SMF properties if invoked thro' SMF */
			ret = read_conf_props();
			if (ret == NO_CPUS_2_TEST) {
				return (ret);
			}
		} else {
			(void) fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
			    CL_INVOKED, (smf_state) ?
			    smf_state : "No SMF service named fpsd");
		}
	}
	calculateTotalIterations(fpsd.d_conf);
	if ((ret == -1) || (!smf_invoked) || (fpsd.d_interval <= 0)) {
		ret = calculateTimeInterval();
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
		    PRINT_INTVL, fpsd.d_interval);
		if ((ret != 1) || (fpsd.d_interval <= 0)) {
			return (ZERO_INTERVAL);
		}
	}
	return (0);
}

int
main(int argc, char **argv)
{

	int sig;
	sigset_t  sigs;
	/* Pipe fd to write the status back to parent after becoming daemon */
	int pfd = -1;
	int status = FPSD_INIT_SUCCESS;
	char rcvsigstr[32];
	int c;
	int ret;
	struct rlimit rlim;
	char path[MAXPATHLEN];
	int probe_status = -1;
	const char *progname;
	struct	sigaction	act;

	progname = strrchr(argv[0], '/');
	if (NULL != progname)
		progname++;
	else
		progname = argv[0];

#ifndef TEXT_DOMAIN		/* Should be defined via Makefile */
#define	TEXT_DOMAIN  "SUNW_FPS"
#endif

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	openlog(FPS_DAEMON_NAME, LOG_PID, LOG_DAEMON);

	if (fpsd_init()) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, DAEMON_INIT_FAIL);
	}

	/*
	 * Set our per-process core file path to leave core files in
	 * var/fps/core directory, named after the PID to aid in
	 * debugging, and make sure that there is no restriction on core
	 * file size.
	 */

	if ((ret = access(FPS_CORE_DIR, W_OK)) != 0) {
		if ((ret = mkdirp(FPS_CORE_DIR, 0755)) != 0) {
			fpsd_message(FPSD_NO_EXIT, FPS_ERROR,
			    CORE_DIR_CREATION_FAILED,
			    FPS_CORE_DIR, strerror(errno));
		}
	}

	if (ret == 0) {
		(void) snprintf(path, sizeof (path), "%s/core.%s.%%p",
		    FPS_CORE_DIR, progname);
		(void) core_set_process_path(path, strlen(path) + 1,
		    fpsd.d_pid);
		rlim.rlim_cur = RLIM_INFINITY;
		rlim.rlim_max = RLIM_INFINITY;

		(void) setrlimit(RLIMIT_CORE, &rlim);
	}


	/*  parse arguments */
	while ((c = getopt(argc, argv, "dl:")) != EOF) {
		switch (c) {
		case 'd':
			fpsd.d_fg = 1;
			break;

		case 'l':
			debug_level = atoi(optarg);
			if (debug_level < 0)
				debug_level = DFLT_DBG_LVL;
			break;

		default:
			fpsd_message(FPSD_EXIT_USAGE, FPS_ERROR, USAGE_MSG,
			    progname);
			break;
		}
	}


	/*
	 * Reset all of our privilege sets to the minimum set of required
	 * privileges.  We continue to run as root so that files we create
	 * such as logs and checkpoints are secured in the /var
	 * filesystem.
	 */
	if (__init_daemon_priv(PU_RESETGROUPS | PU_LIMITPRIVS | PU_INHERITPRIVS,
	    0, 0, /* run as uid 0 and gid 0 */
	    PRIV_FILE_DAC_EXECUTE, PRIV_FILE_DAC_READ, PRIV_FILE_DAC_SEARCH,
	    PRIV_FILE_DAC_WRITE, PRIV_FILE_OWNER, PRIV_PROC_OWNER,
	    PRIV_PROC_PRIOCNTL, PRIV_SYS_ADMIN, PRIV_SYS_CONFIG,
	    PRIV_SYS_DEVICES, PRIV_SYS_RES_CONFIG,
	    PRIV_NET_PRIVADDR, NULL) != 0) {

		(void) fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR,
		    INSUFFICIENT_PRIVS, progname);
	}


	if (!fpsd.d_fg) {   /* Now become daemon */
		pfd = become_daemon_init();
	} else {
		(void) chdir(FPS_DIR);
	}

	if (daemon_exists()) {
		/*
		 * If another instance of fpsd daemon is already running;
		 * exit. Should not clean up door file
		 */
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR,
		    DAEMON_ALREADY_RUNNING);
	}

	/*
	 * Setup door prevents any more instances of fpsd from running.
	 */
	if (fps_setup_door() == -1) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, DOOR_SETUP_FAIL);
	}

	/*
	 * Some desktop platforms satisfy E* guidelines. Here CPU power
	 * management is enabled by default. The scheduling algorithms
	 * change on these platforms to not to do testing on idle system
	 * to save power.
	 */
	init_estar_db();    /* Initialize Estar config data base */
	/* Print message on CPU E* enabled system */
	if (is_estar_system)
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, ESTAR_INFO);

	if ((probe_status = fpsd_probe(fpsd.d_conf)) != 0) {
		(void) fpsd_message(FPSD_NO_EXIT, FPS_ERROR,
		    UNSUPPORTED_SYSTEM);
	}

	if (!fpsd.d_fg) {   /* Complete daemonize proces */

		fpsd.d_daemon = 1;
		/*
		 * Now that we're running, if a pipe fd was specified, write an
		 * exit status to it to indicate that our parent process can
		 * safely detach.
		 */
		if (pfd >= 0) {
			(void) write(pfd, &status, sizeof (status));
		}
		become_daemon_fini(pfd);

	} else {
		/*
		 * Mask all signals before creating sched thread. We will
		 * unmask selective siganls from main thread. This ensures
		 * that only main thread handles signals. This is done in
		 * become_daemon() if we had to daemonize.
		 */

		(void) sigfillset(&sigs);
		(void) sigprocmask(SIG_BLOCK, &sigs, NULL);
	}

	/*
	 * Give some time for SMF to read the exit status
	 * of parent and update fpsd fmri state
	 */
	(void) poll(NULL, 0, 3*1000);

	str_fps_fmri = getenv("SMF_FMRI");
	if (NULL != str_fps_fmri) {
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, SMF_INVKD, str_fps_fmri);
	} else {
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, CLI_INVKD);
	}

	if (probe_status != 0) {
		/* Exit child proces too */

		if (NULL != str_fps_fmri) {
			const char *smf_state = smf_get_state(str_fps_fmri);
			if (NULL != smf_state) {
				smf_disable_instance(str_fps_fmri,
				    SMF_TEMPORARY);
				(void) fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
				    FPSD_STATE, smf_state);
				(void) poll(NULL, 0, 3*1000);
			}
		}
		terminate_process();
		_exit(FPSD_EXIT_ERROR);
	}

	act.sa_sigaction = sig_hup_handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO;
	(void) sigaction(SIGHUP, &act, NULL);
	fpsd_read_config();

	/*
	 * On estar-systems, if interval < MIN_INTERVAL, scheduling tests will
	 * reset the idle counter and prevent system from going to sleep.
	 * To  avoid this, setting interval to MIN_INTERVAL.
	 */

	if ((is_estar_system) && (fpsd.d_interval < MIN_INTERVAL)) {
		fpsd.d_interval = MIN_INTERVAL;
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, MIN_INTERVAL_MSG,
		    fpsd.d_interval, MIN_INTERVAL);
	}

	(void) sigfillset(&sigs);
	(void) sigprocmask(SIG_BLOCK, &sigs, NULL);

	/* Run scheduling thread */
	if ((ret == 0) && thr_create(NULL, 0,
	    test_fpu_thr, (void *) NULL, THR_BOUND, NULL) != 0) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, THR_CREATION_FAIL);
	}

	/*
	 * We unmask selective signals here. Besides terminating on
	 * SIGINT & SIGTERM, we handle SIGHUP that is used to cause
	 * daemon to re-read the SMF properties.
	 */
	(void) sigemptyset(&sigs);
	(void) sigaddset(&sigs, SIGINT);
	(void) sigaddset(&sigs, SIGTERM);
	(void) sigaddset(&sigs, SIGHUP);
	(void) sigprocmask(SIG_UNBLOCK, &sigs, NULL);

	for (;;) {
		(void) sigwait(&sigs, &sig);
		(void) sig2str(sig, rcvsigstr);

		if (sig != -1) {
			fpsd_message(FPSD_NO_EXIT, FPS_INFO,
			    SIGNAL_INFO, rcvsigstr, sig);
			switch (sig) {
				case SIGINT:
				case SIGTERM:
					terminate_process();
					_exit(FPSD_EXIT_ERROR);
					break;
				case SIGHUP:
					fpsd.d_ts_hup = gethrtime();
					break;
				default: break;
			}
		}
	}
#pragma error_messages(off, E_STATEMENT_NOT_REACHED)
	/* NOTREACHED */
	return (0);
}
