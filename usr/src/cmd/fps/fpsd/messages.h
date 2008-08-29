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

#ifndef	_MESSAGES_H
#define	_MESSAGES_H

/*
 * Messages
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <libintl.h>

/* Messages used in fpsd_main.c */

#define	DAEMON_ALREADY_RUNNING   \
	gettext("Can not start daemon when another instance"\
		" is already running.\n")

#define	DAEMON_INIT_FAIL   \
	gettext("Could not intialize state structures for the daemon.\n")

#define	DAEMON_PIPE_FAIL   \
	gettext("Failed to create pipe for daemonizing : %s\n")

#define	DAEMON_FORK_FAIL   \
	gettext("Failed to fork daemon into background : %s\n")

#define	DAEMON_DOOR_FAIL   \
	gettext("Library call door_create failed : %s\n")

#define	DAEMON_DOOR_FILE_FAIL   \
	gettext("Could not create door file : %s\n")

#define	DAEMON_DOOR_FATTACH_FAIL   \
	gettext("Could not fattach to door file : %s\n")

#define	CORE_DIR_CREATION_FAILED \
	gettext("%s directory could not be created for "\
		"storing core files : %s\n")

#define	LIBRARY_CALL_FAIL	\
	gettext("Library call %s failed : %s\n")

#define	SYSTEM_CALL_FAIL	\
	gettext("System call %s failed : %s\n")

#define	INVALID_CPUID	\
	gettext("Invalid cpuid: %s\n")

#define	CPU_NOT_SUPPORTED	\
	gettext("%s CPU brand of CPU ID %d is not supported by FP Scrubber.\n")

#define	CPU_BRAND_PROBE_FAIL	\
	gettext("Could not read Brand for CPU ID %d.\n")

#define	FREQ_PROBE_FAIL	\
	gettext("Could not probe frequency for CPU ID %d.\n")

#define	FPSD_ZERO_INTVL	\
	gettext("Some error occured in calculating interval;"\
		" interval calculated = %d\n")

#define	FPSD_NO_CPUS_TO_TEST	\
	gettext("FP Scrubber is not supported on "\
		" the processors that are online\n")

#define	SMF_INVOKED \
	gettext("Program started through SMF; state = %s\n")

#define	CL_INVOKED \
	gettext("Program started through command line; state = %s\n")

#define	INSUFFICIENT_PRIVS \
	gettext("Insufficient priviliges to run %s. Exiting...\n")

#define	UNSUPPORTED_SYSTEM \
	gettext("System configuration probe failed. Exiting ...\n")

#define	THR_CREATION_FAIL \
	gettext("Initialization Failure: " \
	" Could not create test scheduling thread.\n")

#define	ESTAR_INFO \
	gettext("Actual testing is done only when the system " \
	" is not in idle state.\n")

#define	PROP_UNDEFINED \
	gettext("Reading of property %s failed for the "\
	"service instance; reason : %s\n")

#define	USAGE_MSG	gettext("\nUsage: %s  [-dl[0..3]] \n")

#define	DOOR_SETUP_FAIL \
	gettext("Could not setup lock mechanism."\
	" This might happen if another instance of fpsd is running.\n")

#define	PRINT_INTVL	gettext("Calculated time interval =  %d .\n")

#define	SIGNAL_INFO	gettext("Process received SIG%s (%d) signal.\n")

#define	FORK_FAIL_MSG	gettext("Could not start CPU test program: %s\n" \
	"System call fork() failed. Reason: %s\n")

#define	TST_EXEC_FAIL	gettext("Could not execute CPU test program: %s"\
	"\n      Reason: %s\n")

#define	SWAP_WARN	gettext("Low swap space: Test: %s -n was not invoked.")

#define	START_TEST_MSG	gettext("Start Test :%s -f %s -p %s -d %s\n")

#define	END_TST_MSG	\
	gettext("End Test (PID=%d) Time: %dH.%dM.%dS.%dMsecs    %s\n")

#define	DI_INIT_FAIL	\
	gettext("Could not get device info tree information: "	\
	" di_init() failed.\n")

#define	DI_PROM_INIT_FAIL	\
	gettext("Could not get PROM tree information: "	\
	" di_prom_init() failed.\n")

#define	INTERNAL_FAILURE_WARN	\
	gettext("Would recover from internal software failure:\n"\
	"     ioctl /dev/pm PM_GET_STATE_CHANGE : %s\n")

#define	INTERNAL_FAILURE_WARN1	\
	gettext("Would recover from internal software failure:\n"\
	"     ioctl /dev/pm PM_GET_CURRENT_POWER : %s\n")

#define	INTERNAL_FAILURE_WARN2	\
	gettext("Would recover from internal software failure:\n"\
	"     ioctl /dev/pm PM_GET_STATE_CHANGE_WAIT : %s\n")

#define	FPU_INVALID_ARG_MSG     \
	gettext("Invalid arguments passed to fp-test\n")

#define	FPU_SIG_RCVD    \
	gettext("FP test on %d received signal.\n")

#define	FPU_SIG_ILL_MSG \
	gettext("FP test on FPU %d received SIGILL.\n")

#define	FPU_SYSCALL_FAIL_MSG    \
	gettext("Syscall failed for FP test on FPU %d\n")

#define	FPU_EREPORT_INCOM_MSG   \
	gettext("FP test on FPU %d could not complete ereport generation.\n")

#define	FPU_FPE_MSG     \
	gettext("FP test encountered floating point exception on FPU %d.\n")

#define	FPU_SYSCALL_TRYAGAIN_MSG        \
	gettext("Syscall failed probably due to temporary "\
		"unavailability of resources; Trying again!\n")

#define	INVAL_PROP_VALUE        \
	gettext("Invalid property value defined: %s;\n"\
		"\tIgnoring field exclude_cpus.\n")

#define	FPU_EREPORT_FAIL_MSG	\
	gettext("FP test on FPU %d could not file ereport.\n")

#define	FPU_TIMED_OUT_MSG	\
	gettext("Test could not be scheduled on FPU %d; Daemon timed out\n")

#define	FPSD_MIS_CALCULATIONS	\
	gettext("There was some errorin calculating total iterations "\
		"in one pass: %d\n")

#define	REPROBE_MSG	\
	gettext("Num onln cpus changed; Reprobing...\n")

#define	IDENTIFY_FPU_MSG	\
	gettext("In the beginning, fpuid_index = %d, "	\
		"d_iteration = %d, tot_iter = %d, Total cpus = %d\n")

#define	IDENTIFY_FPU_RTN_MSG	\
	gettext("Before returning, fpuid = %d, iter = %d, freq= %d, "	\
		"prev_iter = %d, total_iter = %d\n")

#define	RECORD_FAILURE_MSG	\
	gettext("Recording failure for fpu %d at %d\n")

#define	EXIT_STAT_MSG	\
	gettext("FP test exit status = %d\n")

#define	INTVL_CHANGED_MSG	\
	gettext("Interval changed in scheduler: %d\n")

#define	RESCHEDULE_MSG	\
	gettext("Rescheduling test for %d\n")

#define	TOT_ITERS	\
	gettext("Total iterations = %d, number of cpus to test = %d\n")

#define	NUM_ONLN_CPUS	\
	gettext("Numberofonlncpus=%d:\n")

#define	CPU_INFO	\
	gettext("Cpuid = %d, cpu brand = %s, frequency = %d\n")

#define	NUM_CPUS_2_TST	\
	gettext("Cpuids_size after probe = %d\n")

#define	NUM_IGN_CPUS	\
	gettext("Number of cpus to be excluded from testing = %d\n")

#define	IGN_CPUS	\
	gettext("Ignoring cpu %d\n")

#define	CREATE_FAIL	\
	gettext("Unable to create SCF instance/property group/property: %s\n")

#define	HANDLE_DECODE_FAIL	\
	gettext("Unable to decode FMRI : %s")

#define	SNAPSHOT_CREAT_FAIL	\
	gettext("Unable to create SCF snapshot: %s\n")

#define	INST_SNAPSHOT_GET_FAIL	\
	gettext("Unable to set snapshot in instance: %s\n")

#define	INSTANCE_PG_GET_FAIL	\
	gettext("Instance properties could not be obtained: %s\n")

#define	INTVL_VAL	\
	gettext("From SMF repository, interval = %lld\n")

#define	EXCL_CPUS	\
	gettext("From SMF repository, cpus to be excluded = %s\n")

#define	SMF_INVKD	\
	gettext("SMF invoked; fpsd fmri = %s\n")

#define	CLI_INVKD	\
	gettext("CLI invocation\n")

#define	FPTST_BIN_PTH	\
	gettext("Searching for fptest binary location = %s\n")

#define	FPSD_STATE	\
	gettext("Service disabled successfully. \n")

#define	DISABLE_SVC_FAILED	\
	gettext("Disabling service failed; Current state = %s\n")

#define	REPRBE_REQ	\
	gettext("Reprobe request recd.\n")

#define	DOOR_HNDLR_MSG	\
	gettext("Server received door call: Version %d; type: %x; len:%d \n")

#define	UNBIND_FAIL_MSG	\
	gettext("Unable to unbind after fptest timeout: %s\n")

#define	TST_SIGNALED_MSG	\
	gettext("Fptest on cpu %d, matrix size = %d died due to signal %s\n")

#define	MIN_INTERVAL_MSG	\
	gettext("Calculated interval = %d which is less than min interval.\n"\
	"Setting interval to %d\n")

#define	ALL_CPUS_EXCLDED	\
	gettext("All cpus are excluded from testing through "\
		"config/exclude_cpus properties for the service. \n")

#define	GET_TIME_FAILED	\
	gettext("gettimeofday failed: %s\n")

#define	LOCAL_TIME_FAILED	\
	gettext("localtime_r failed: %s\n")

#define	STRFTIME_FAILED	\
	gettext("strftime failed: buffer[%d] too small\n")

#define	PRINT_BUFFER	\
	gettext("%s")

#define	ZERO_CPUS_2_TST	\
	gettext("Assertion failed: While trying to calculate total"\
		" iterations, no cpus to test.\n")

#define	INVALID_FPU_ID	\
	gettext("Assertion failed: An FPU could not be identified "\
		"to schedule test.\n")

#define	REPROBE_FAILURE	\
	gettext("Reprobe failed. Exiting...\n")

#ifdef __cplusplus
}
#endif

#endif	/* _MESSAGES_H */
