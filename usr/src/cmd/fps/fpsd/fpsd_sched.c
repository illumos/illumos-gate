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
#include <sys/pset.h>
#include <ctype.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/pm.h>
#include <sys/iso/signal_iso.h>
#include <sys/procset.h>

#include "fpsapi.h"
#include "fpsd.h"
#include "messages.h"

/* Local Functions */

static int
check_invoke_prog(int   devid, time_t *last,
unsigned  tstswap, int frequency, int group_no, int fpu_index);

static int identify_fpu_to_run_test(int *freq, int *iteration, int *fpu_index);

void  *test_fpu_thr(void *arg);

#define	CPU_TST_FORK_FAIL	{\
	error = errno;							\
	fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FORK_FAIL_MSG,	\
		testpath, strerror(error)); \
	return (-1);							\
	}

#define	CPU_TST_EXEC_FAIL	{		\
	error = errno;							\
	fpsd_message(FPSD_EXIT_ERROR,\
		FPS_ERROR, TST_EXEC_FAIL, testpath, strerror(error)); \
	}

static int boot_tst_delay = FPS_BOOT_TST_DELAY;

/* Increments failure for the cpu */
static void
record_failure(int devid, int index) {
	if ((index >= 0) &&
		(index < fpsd.d_conf->m_cpuids_size)) {
		fpsd.d_conf->m_cpus[index].num_failures++;
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,
			RECORD_FAILURE_MSG, devid, index);
	}
}

/* Returns 1 if testing is diabled for the cpu, else 0 */

static int
check_if_disabled(int fpu_index) {
	int is_disabled;

	is_disabled = fpsd.d_conf->m_cpus[fpu_index].disable_test;
	if (is_disabled) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * Forks and executes "fptest" and waits for an amount
 * of time equal to the time to schedule next "fptest".
 * Times out if the test does not complete and unbinds
 * and terminates the test.
 * Return : 0 = Nothing Invoked. 1 = invoked OK. -1 = Failure.
 */
static int
check_invoke_prog(int   devid,		/* cpu-id */
		time_t *last,	/* Last time it was invoked */
		unsigned  tstswap, /* Expected swap space required for test */
		int	frequency, /* Frequency of the processor under test */
		int	group_no, /* Group no. ==> matrix size to be used */
		int	fpu_index)
{
	int  error;
	hrtime_t   start_hrtime = 0, end_hrtime = 0, hrmsecs = 0;
	hrtime_t   hrsecs = 0;
	pid_t  pid = -1;
	int  exit_status = 0;
	char cpuid_c[64];
	char frequency_c[10];
	char group_c[10];
	int ret = 0;
	int status = 0;
	char *testpath;
	char sig_str[32];
	int elapsed_time;
	int status_available;
	int max_timeout;
	int pb_ret;

	testpath = fpsd.d_conf->m_cpus[fpu_index].fptest_path;
	if (check_if_disabled(fpu_index)) {
		return (0);
	}

	/* Compare all in seconds.  */

	*last = time(NULL);

	(void) snprintf(cpuid_c, sizeof (cpuid_c), "%d", devid);
	(void) snprintf(frequency_c, sizeof (frequency_c), "%d", frequency);
	(void) snprintf(group_c, sizeof (group_c), "%d", group_no);

	/* Check if enough swap space is there; Return 0 if not. */

	if (get_free_swap() < (uint64_t)(tstswap+FPS_SWAP_RESERVE)) {
		fpsd_message(FPSD_NO_EXIT, FPS_WARNING, SWAP_WARN, testpath);
		return (ret);
	}

	fpsd_message(FPSD_NO_EXIT, FPS_INFO, START_TEST_MSG,
	    testpath, frequency_c, group_c, cpuid_c);

	start_hrtime = gethrtime();

	pid = fork1();  /* fork1() duplicates only the calling thread */
	if (pid == 0) {
		(void) execl(testpath,   /* Path */
		    FPS_FPUTST_NAME,	/* Arg 0 */
		"-f",
		    frequency_c, /* Frequency */
		"-p",
		    group_c,	/* Group no. */
		"-d",
		    cpuid_c,	/* CPU ID */
		    (char *)NULL);

		CPU_TST_EXEC_FAIL	/* Should never reach here */
	}

	if (pid == -1)
		CPU_TST_FORK_FAIL

	/* Synchronously wait here till the child dies */

	elapsed_time = 0;
	status_available = 0;
	max_timeout = fpsd.d_interval * 1000;
	while (elapsed_time < max_timeout) {
		if (pid == waitpid((pid_t)pid, &status, WNOHANG)) {
			status_available = 1;
			break;
		} else {
			elapsed_time += 50;
			(void) poll(NULL, 0, 50);   /* wait 50 milli sec. */
		}
	}

	if (!status_available) {
		exit_status = FPU_TIMED_OUT;
	} else {
		exit_status = WEXITSTATUS(status);
		if (exit_status == 0xFF) {
			/* As WEXITSTATUS returns 0xFF */
			exit_status = FPU_UNSUPPORT;
		}
	}
	if (exit_status == FPU_UNSUPPORT) {
		/* Reprobe */
		fpsd.d_conf->m_reprobe = 1;
		ret = 1;
	} else if (exit_status == FPU_OK) {
		/* Increment iteration */
		fpsd.d_iteration++;
		ret = 1;
	} else if ((exit_status == FPU_FOROFFLINE) ||
	    (exit_status == FPU_BIND_FAIL)) {
		/* Force reprobe */
		fpsd.d_conf->m_reprobe = 1;
		ret = 1;
	} else if (exit_status == FPU_INVALID_ARG) {
		/* This should not happen; so force exit */
		fpsd_message(FPSD_EXIT_TEST_USAGE, FPS_ERROR,
		    FPU_INVALID_ARG_MSG);
	} else if ((exit_status == FPU_SIG_SEGV) ||
	    (exit_status == FPU_SIG_BUS)) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FPU_SIG_RCVD,
		    devid);
		record_failure(devid, fpu_index);
		ret = -1; /* Retry */
	} else if (exit_status == FPU_SIG_FPE) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FPU_FPE_MSG,
		    devid);
		record_failure(devid, fpu_index);
		ret = -1;
	} else if (exit_status == FPU_SIG_ILL) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FPU_SIG_ILL_MSG,
		    devid);
		record_failure(devid, fpu_index);
		ret = -1;
	} else if (exit_status == FPU_SYSCALL_FAIL) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FPU_SYSCALL_FAIL_MSG,
		    devid);
		record_failure(devid, fpu_index);
		fpsd.d_iteration++; /* Iteration skipped */
		ret = 1; /* Record failure and move on */
	} else if (exit_status == FPU_EREPORT_INCOM) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FPU_EREPORT_INCOM_MSG,
		    devid);
		fpsd.d_conf->m_reprobe = 1;
		ret = 1;
	} else if (exit_status == FPU_SYSCALL_TRYAGAIN) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FPU_SYSCALL_TRYAGAIN_MSG);
		ret = -1; /* Retry as it could be some resource issue */
	} else if (exit_status == FPU_EREPORT_FAIL) {
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FPU_EREPORT_FAIL_MSG,
		    devid);
		ret = -1;
	} else if (exit_status == FPU_TIMED_OUT) {
		pb_ret = processor_bind(P_PID, pid, PBIND_NONE, NULL);
		if (pb_ret == -1) {
			fpsd_message(FPSD_NO_EXIT, FPS_INFO,
			    UNBIND_FAIL_MSG,
			    strerror(errno));
		}
		(void) kill(pid, SIGINT);
		while (pid != waitpid((pid_t)pid, &status, WUNTRACED)) {
			(void) poll(NULL, 0, 10);
			(void) kill(pid, SIGINT);
		}
		fpsd_message(FPSD_NO_EXIT, FPS_ERROR, FPU_TIMED_OUT_MSG, devid);
		record_failure(devid, fpu_index);
		ret = -1;
	}

	/*
	 * The following is the case if the test ended due to a
	 * signal and did not have a handler for the signal.
	 */
	if (WIFSIGNALED(status)) {
		(void) sig2str(WTERMSIG(status), sig_str);
		fpsd_message(FPSD_NO_EXIT, FPS_INFO,
		    TST_SIGNALED_MSG, devid,
		    frequency, sig_str);
		record_failure(devid, fpu_index);
		ret = -1; /* Retry */
	}

	end_hrtime = gethrtime();
	hrmsecs = ((end_hrtime - start_hrtime)/
	    ((hrtime_t)1000*1000));
	hrsecs  = hrmsecs / 1000;
	fpsd_message(FPSD_NO_EXIT, FPS_INFO, END_TST_MSG,  (int)pid,
	    (int)(hrsecs/(60*60)),
	    (int)((hrsecs%3600)/60),
	    (int)(hrsecs%60),
	    (int)(hrmsecs%1000),
	    cpuid_c);

	fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, EXIT_STAT_MSG, exit_status);

	return (ret);
}

/*
 *  The test scheduling thread.
 */

void  *
test_fpu_thr(/* ARGSUSED */ void *arg)
{
	time_t cur = 0,   /* current time in secs */
	    last = 0;   /* Last time this level testing done in secs */
	int    ret;

	int	intvl = 0;	/* interval */
	unsigned	tswap = 0;
	int	poll_intvl;
	long	num_cpus;
	int	idle = 0, remain = 0, max_remain = 0;
	time_t last_wakeup = 0, wakeup_elapse;
	int fpuid;
	int frequency;
	int group_no;

	int force_skip_test_if_pm_idle = 1;
	int fpu_index;
	int max_idle_time_4_tst_run;
	int j;

	/*
	 * If enabled, do not run test on idle system, even if test intvl
	 * explicitly specified.
	 */

/*
 * Minimum time to wait before scheduling tests
 * when the system just wakes up from sleep.
 */
#define	MINSLEEP	8

	num_cpus =  sysconf(_SC_NPROCESSORS_ONLN);

	intvl =  poll_intvl = fpsd.d_interval;

	tswap = FPS_LOWTST_SWAP;

	cur  =  time(NULL);

	/*
	 * Initialize last time test done based on earlier bootup testing.
	 * This decides when the first time scheduling of the test is
	 * to be done.
	 */

	/*
	 * In systems with less than 3 processors, the initial testing
	 * has been found to affect the system bootup time.
	 * Wait for 5 min for those systems before starting any testing.
	 */

	if (num_cpus < 3)
		fps_wait_secs(boot_tst_delay);

	/* Soft bind before once before starting test. */
	if (processor_bind(P_PID, P_MYID, PBIND_SOFT, NULL) != 0) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, SYSTEM_CALL_FAIL,
		    "processor_bind", strerror(errno));
	}

	if (pset_bind(PS_SOFT, P_PID, P_MYID, NULL) != 0) {
		fpsd_message(FPSD_EXIT_ERROR, FPS_ERROR, SYSTEM_CALL_FAIL,
		    "pset_bind", strerror(errno));
	}

#define	MAX_IDLE_TIME_FOR_TSTRUN	10

	if (intvl/2 > MAX_IDLE_TIME_FOR_TSTRUN) {
		max_idle_time_4_tst_run =
		    MAX_IDLE_TIME_FOR_TSTRUN;
	} else {
		max_idle_time_4_tst_run =
		    (intvl/2) +
		    MAX_TEST_RUN_TIME;
	}

	cur  =  time(NULL);
	last = 0; /* Force the invocation by setting last to zero. */


	for (;;) {
		time_t elapse;

		cur =  time(NULL);
		elapse = cur - last;

		/*
		 * Sleep for intvl secs amount of time.
		 */

		if (elapse >= (time_t)intvl)
			poll_intvl = 0;
		else  /* Don't sleep more than 1 min at a time */
			poll_intvl = (int)((time_t)intvl-elapse);

		/*
		 * Until poll_intvl becomes zero, sleep.
		 * If poll gets interrupted for any reason, then also works.
		 */

		if (poll_intvl > 0) {
			(void) poll(NULL, 0, poll_intvl*1000);
			continue;
		}

#define	INVOKE_PROG	{	\
	fpuid = identify_fpu_to_run_test(&frequency, &group_no, &fpu_index);\
	if (fpuid == -1) {\
		/* Testing could not be done on any cpu */\
		(void) poll(NULL, 0, 20); /* Wait for some time */\
		continue;\
	}\
	ret = check_invoke_prog(fpuid, &last, tswap, frequency,	\
		group_no, fpu_index); \
	if (ret == -1) {	\
		for (j = 0; (j < MAX_RETRIES) && (ret != 1); j++) {	\
			(void) poll(NULL, 0, RETRY_INTVL);	\
			fpsd_message(FPSD_NO_EXIT, FPS_DEBUG,	\
				RESCHEDULE_MSG, fpuid);\
			ret = check_invoke_prog(fpuid, &last, tswap,	\
				frequency, group_no, fpu_index); \
		}	\
		if (ret == -1) {	\
			/*\
			 * Tried MAX_RETRIES times. Still seeing failures\
			 * on this fpu. Skip this iteration and move on.\
			 */\
			fpsd.d_iteration++;	\
		}	\
	}	\
	}

		/*
		 * If power management is disabled (or not supported) on the
		 * system, just go ahead, invoke the program.
		 */
		update_pm_state();  /* Update current PM state. */
		if (sys_pm_state != PM_SYSTEM_PM_ENABLED) {
		/* autopm disabled. Just go ahead invoke program. */
			INVOKE_PROG
			continue;
		}

		/*
		 *  Power management is enabled. This system may be CPU PM
		 * enabled system or just disk(and other) PM enabled.
		 * If CPU PM not supported, just invoke the program.
		 */
		if (!is_estar_system) {
			INVOKE_PROG
			continue;
		}

		/* This system is CPU PM currently supported & enabled. */

		/*
		 * By deafult, tests are not invoked on E* compliant system.
		 * However if force_skip_test_if_pm_idle is set to 0, tests
		 * will be invoked. This is kept for debugging purposes for now.
		 * Should be removed if no use cases.
		 */

		if (!force_skip_test_if_pm_idle) {
			INVOKE_PROG
			continue;
		}

		/*
		 * If the system is in sleep mode, wait until it comes
		 * to full power mode.
		 */

		/* If CPUs are not in full power mode, this will return -1 */
		ret = get_idle_rem_stats(&idle, &remain, &max_remain);

		/*
		 * Wait until CPU comes to full power mode.
		 * Call wait for state change function -- the return from the
		 * function does not guarantee that the system is in full power
		 * mode. So get the current status later as well.
		 */
		if (ret == -1) {
			while (ret == -1) {
				/* Avoid busy loop in any case */
				(void) poll(NULL, 0, 1000);
				/* Wait until CPU comes to full pwr */
				wait_for_pm_state_change();
				ret = get_idle_rem_stats(&idle, &remain,
				    &max_remain);
			}

			/* Remember the last time that we woke up. */
			last_wakeup = time(NULL);
		}

	/*
	 * To meet E* requirements, the system should go to
	 * deep sleep mode in 30 mins on default configs.
	 * The CPU power management does this by 14.25min+14.25min
	 * so total 28.5mins. (in sleep mode followed by deep sleep).
	 * Running the test as the system just becomes active,
	 * may reset the idle counter and may delay the transition.
	 * However since we have 1.5 mins cushion to meet E*
	 * requirements, we are just making use of it.
	 *
	 * If system is idle for more than 10 seconds, wait
	 * until the system idle time is less than 10  seconds.
	 * Poll in 2 sec interval, so we will catch it as soon
	 * as the system idle time goes low (as it just becomes busy).
	 * Basically don't run test on an idle system.
	 * If the system is continously busy, then this will
	 * result in continously scheduling the test.
	 *
	 * Running test on a system which is just 10 seconds idle,
	 * may reset the idle counter.
	 * This will postpone the idle transition to it's lowest power
	 * by worst case of  10 secs + worst case run time for fptest
	 * that is approximately 1 sec = 11 sec.
	 * This is below the 1.5mins cushion CPU PM now has to make
	 * idle transition.
	 *
	 * So if d_interval/2 >= 10 follow the above logic. Else, reduce
	 * max_idle_time_4_tstrun = d_interval/2 + max_time_taken_by_test
	 * (which is <= 1s). We want to be conservative in scheduling
	 * test rather than utilize the cushion to maximum possible
	 * extent.
	 * Note: The E* desktop systems have atmost 2 processors, but
	 * this will work even for more processors in which case the
	 * interval will be less or if the interval is configured thro'
	 * SMF.
	 * As long as atleast any one processor is in full power mode,
	 * all processors have to be in same power level.
	 */

		/* Invoke program if system is "busy" */

		if (idle <= max_idle_time_4_tst_run) {
	/*
	 * If the system is just waking up from sleep, don't rush into
	 * testing immediately to avoid hiccups in performance.
	 *
	 */
			wakeup_elapse = time(NULL) - last_wakeup;
			if (wakeup_elapse < MINSLEEP) {
				fps_wait_secs((int)(MINSLEEP-wakeup_elapse));
			}
			INVOKE_PROG
			continue;
		}

	/* The system is "idle". Wait until it becomes "busy" */
		while (idle > max_idle_time_4_tst_run) {

	/*
	 * Once in max_idle_time_4_tst_run/2 secs, we are issuing
	 * ioctl call to catch the system as soon as it becomes
	 * "busy". Polling is not an efficient way to do this,
	 * but this is the only way we got right now.
	 */
			fps_wait_secs(max_idle_time_4_tst_run / 2);
			ret = get_idle_rem_stats(&idle, &remain, &max_remain);
			if (ret == -1) break; /* Incase now in sleep mode */
		}
		continue;

	} /* End infinite for loop */

#pragma error_messages(off, E_STATEMENT_NOT_REACHED)
	/* NOTREACHED */
	return (NULL);
}

/*
 * Identifies the fpu on which test will be scheduled next.
 */

static int
identify_fpu_to_run_test(int *freq, int *iteration, int *fpu_index) {
	int fpuid = -1;
	int ascend;
	int tmp_iter;
	fps_cpu_t fps_cpu;
	int i;
	int num_onln;
	/* Timestamp at which SIGHUP ts was checked last */
	static hrtime_t	ts_hup_chkd = 0;
	hrtime_t tmp_ts;

	*iteration = *freq = 0;
	while (fpuid == -1) {
		num_onln = (int)sysconf(_SC_NPROCESSORS_ONLN);
		if (num_onln != fpsd.d_conf->m_num_on_fpuids) {
			fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, REPROBE_MSG);
			fpsd.d_conf->m_reprobe = 1;
		}

		tmp_ts = fpsd.d_ts_hup;
		if (fpsd.d_ts_hup > ts_hup_chkd) {
			fpsd.d_conf->m_reprobe = 1;
		}
		ts_hup_chkd = tmp_ts;

		if (1 == fpsd.d_conf->m_reprobe) {
			fpsd_read_config();
		}
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, IDENTIFY_FPU_MSG,
			fpsd.d_fpuid_index, fpsd.d_iteration,
			fpsd.d_conf->total_iter, fpsd.d_conf->m_cpuids_size);
		if (fpsd.d_iteration == fpsd.d_conf->total_iter) {
			/* One pass completed */
			fpsd.d_iteration = 0;

			/* Reinit iterations */
			for (i = 0; i < fpsd.d_conf->m_cpuids_size; i++) {
				if (fpsd.d_conf->m_cpus[i].disable_test)
					continue;
				ascend = fpsd.d_conf->m_cpus[i].asc;
				if (ascend) {
				fpsd.d_conf->m_cpus[i].previous_iteration = 0;
				} else {
				fpsd.d_conf->m_cpus[i].previous_iteration =
				fpsd.d_conf->m_cpus[i].total_iterations + 1;
				}
			}
		}
		if (fpsd.d_iteration == 0) { /* Beginning of one pass */
			fpsd.d_fpuid_index = 0;
			while (fpsd.d_fpuid_index <
				fpsd.d_conf->m_cpuids_size) {
				if (fpsd.d_conf->m_cpus[fpsd.d_fpuid_index].\
					disable_test) {
					fpsd.d_fpuid_index++;
				} else {
					break;
				}
			}
			if (fpsd.d_fpuid_index ==  fpsd.d_conf->m_cpuids_size) {
				return (-1);
			}
		} else {
			if (fpsd.d_fpuid_index ==
				(fpsd.d_conf->m_cpuids_size-1)) {
				/* One iteration done for all fpus */
				fpsd.d_fpuid_index = 0;
			} else {
				fpsd.d_fpuid_index++;
			}
		}
		fps_cpu = fpsd.d_conf->m_cpus[fpsd.d_fpuid_index];
		fpuid = fps_cpu.cpuid;
		if (fps_cpu.disable_test) {
			fpuid = -1;
			continue;
		}
		*freq = fps_cpu.frequency;

		/* Find the iteration no. */
		tmp_iter = fps_cpu.previous_iteration;
		ascend = fpsd.d_conf->m_cpus[fpsd.d_fpuid_index].asc;
		if (ascend) {
			if (tmp_iter == fps_cpu.total_iterations) {
			/*
			 * 1 pass completed for this fpu;
			 * skip this fpu and goto the next fpu
			 */
				fpuid = -1;
				continue;
			} else {
				fpsd.d_conf->m_cpus[fpsd.d_fpuid_index].\
					previous_iteration++;
			}
		} else {
			/* This FPU is tested in descending order of */
			/* iteration no. ==> matrix size */
			if (tmp_iter == 1) {
				/*
				 * 1 pass completed for this fpu;
				 * skip this fpu and goto the next fpu
				 */
				fpuid = -1;
				continue;
			} else {
				fpsd.d_conf->m_cpus[fpsd.d_fpuid_index].\
					previous_iteration--;
			}
		}
		*iteration =
		fpsd.d_conf->m_cpus[fpsd.d_fpuid_index].previous_iteration;
		*fpu_index = fpsd.d_fpuid_index;
		fpsd_message(FPSD_NO_EXIT, FPS_DEBUG, IDENTIFY_FPU_RTN_MSG,
		fpuid, *iteration, *freq,
		fpsd.d_conf->m_cpus[fpsd.d_fpuid_index].previous_iteration,
		fps_cpu.total_iterations);
	}
	return (fpuid);
}
