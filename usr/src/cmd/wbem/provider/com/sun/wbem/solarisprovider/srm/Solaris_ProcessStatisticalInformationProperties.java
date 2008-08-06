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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Solaris_ProcessStatisticalInformationProperties.java
 */


package com.sun.wbem.solarisprovider.srm;

/**
 * Defines property names of the Solaris_ProcessStatisticalInformation and
 * the corresponding keys in the RDS protocol
 * @author SMI
 */
public interface Solaris_ProcessStatisticalInformationProperties {
    /**
     * The cumulative number of nanoseconds that this process has spent in
     * User mode over its lifetime.
     */
    static final String USERMODETIME = "UserModeTime";
    static final String USERMODETIME_KEY = "id_usr";
    /**
     * The cumulative number of nanoseconds that this process has spent in
     * System mode over its lifetime.
     */
    static final String SYSTEMMODETIME = "SystemModeTime";
    static final String SYSTEMMODETIME_KEY = "id_sys";
    /**
     * The cumulative number of nanoseconds that this process has spent in
     * System Traps over its lifetime.
     */
    static final String SYSTEMTRAPTIME = "SystemTrapTime";
    static final String SYSTEMTRAPTIME_KEY = "id_ttime";
    /**
     * The cumulative number of nanoseconds that this process has spent
     * sleeping in Text Page Faults over its lifetime.
     */
    static final String TEXTPAGEFAULTSLEEPTIME = "TextPageFaultSleepTime";
    static final String TEXTPAGEFAULTSLEEPTIME_KEY = "id_tpftime";
    /**
     * The cumulative number of nanoseconds that this process has spent
     * sleeping in Data Page Faults over its lifetime.
     */
    static final String DATAPAGEFAULTSLEEPTIME = "DataPageFaultSleepTime";
    static final String DATAPAGEFAULTSLEEPTIME_KEY = "id_dpftime";
    /**
     * The cumulative number of nanoseconds that this process has spent
     * sleeping in System Page Faults over its lifetime.
     */
    static final String SYSTEMPAGEFAULTSLEEPTIME = "SystemPageFaultSleepTime";
    static final String SYSTEMPAGEFAULTSLEEPTIME_KEY = "id_kpftime";
    /**
     * The cumulative number of nanoseconds that this process has spent
     * sleeping on User Lock Waits over its lifetime.
     */
    static final String USERLOCKWAITSLEEPTIME = "UserLockWaitSleepTime";
    static final String USERLOCKWAITSLEEPTIME_KEY = "id_lck";
    /**
     * The cumulative number of nanoseconds that this process has spent
     * sleeping in all other ways over its lifetime.
     */
    static final String OTHERSLEEPTIME = "OtherSleepTime";
    static final String OTHERSLEEPTIME_KEY = "id_slp";
    /**
     * The cumulative number of nanoseconds that this process has spent
     * Waiting for CPU over its lifetime.
     */
    static final String WAITCPUTIME = "WaitCPUTime";
    static final String WAITCPUTIME_KEY = "id_lat";
    /**
     * The cumulative number of nanoseconds that this process has spent
     * Stopped over its lifetime.
     */
    static final String STOPPEDTIME = "StoppedTime";
    static final String STOPPEDTIME_KEY = "id_stime";
    /**
     * The cumulative number of Minor Page Faults engendered by the process
     * over its lifetime
     */
    static final String MINORPAGEFAULTS = "MinorPageFaults";
    static final String MINORPAGEFAULTS_KEY = "id_minf";
    /**
     * The cumulative number of Major Page Faults engendered by the process
     * over its lifetime.
     */
    static final String MAJORPAGEFAULTS = "MajorPageFaults";
    static final String MAJORPAGEFAULTS_KEY = "id_majf";
    /**
     * The cumulative number of swap operations engendered by the process
     * over its lifetime.
     */
    static final String SWAPOPERATIONS = "SwapOperations";
    static final String SWAPOPERATIONS_KEY = "id_nswap";
    /**
     * The cumulative number of blocks Read by the process over its lifetime.
     */
    static final String BLOCKSREAD = "BlocksRead";
    static final String BLOCKSREAD_KEY = "id_inblk";
    /**
     * The cumulative number of blocks Written by the process over its lifetime.
     */
    static final String BLOCKSWRITTEN = "BlocksWritten";
    static final String BLOCKSWRITTEN_KEY = "id_oublk";
    /**
     * The cumulative number of Messages Sent by the process over its lifetime
     */
    static final String MESSAGESSENT = "MessagesSent";
    static final String MESSAGESSENT_KEY = "id_msnd";
    /**
     * The cumulative number of Messages Received by the process over
     * its lifetime.
     */
    static final String MESSAGESRECEIVED = "MessagesReceived";
    static final String MESSAGESRECEIVED_KEY = "id_mrcv";
    /**
     * The cumulative number of Signals taken by the process over its lifetime.
     */
    static final String SIGNALSRECEIVED = "SignalsReceived";
    static final String SIGNALSRECEIVED_KEY = "id_sigs";
    /**
     * The cumulative number of Voluntary Context Switches made by the process
     * over its lifetime.
     */
    static final String VOLUNTARYCONTEXTSWITCHES = "VoluntaryContextSwitches";
    static final String VOLUNTARYCONTEXTSWITCHES_KEY = "id_vctx";
    /**
     * The cumulative number of Involuntary Context Switches made by
     * the process over its lifetime.
     */
    static final String INVOLUNTARYCONTEXTSWITCHES =
    "InvoluntaryContextSwitches";
    static final String INVOLUNTARYCONTEXTSWITCHES_KEY =
    "id_ictx";
    /**
     * The cumulative number of system calls made by the process over its
     * lifetime.
     */
    static final String SYSTEMCALLSMADE = "SystemCallsMade";
    static final String SYSTEMCALLSMADE_KEY = "id_scl";
    /**
     * The cumulative number of character I/O bytes Read and Written
     * by the process over its lifetime.
     */
    static final String CHARACTERIOUSAGE = "CharacterIOUsage";
    static final String CHARACTERIOUSAGE_KEY = "id_ioch";
    /**
     * The total number of KiloBytes of memory consumed by the process
     * heap at the time that it is sampled.
     */
    static final String PROCESSHEAPSIZE = "ProcessHeapSize";
    static final String PROCESSHEAPSIZE_KEY = "id_hpsize";
    /**
     * The size of the process virtual address space in KiloBytes.
     */
    static final String PROCESSVMSIZE = "ProcessVMSize";
    static final String PROCESSVMSIZE_KEY = "id_size";
    /**
     * The resident set size of the process in KiloBytes
     */
    static final String PROCESSRESIDENTSETSIZE = "ProcessResidentSetSize";
    static final String PROCESSRESIDENTSETSIZE_KEY = "id_rssize";
    /**
     * The percent CPU time used by the process.
     */
    static final String PERCENTCPUTIME = "PercentCPUTime";
    static final String PERCENTCPUTIME_KEY = "id_pctcpu";
    /**
     * The ratio of the process resident set size to physical memory
     */
    static final String PERCENTMEMORYSIZE = "PercentMemorySize";
    static final String PERCENTMEMORYSIZE_KEY = "id_pctmem";
    /**
     * Time in User mode and System mode spent by the process in milliseconds.
     * If this information is not available, a value of 0 should be used.
     */
    static final String USERSYSTEMMODETIME = "UserSystemModeTime";
    static final String USERSYSTEMMODETIME_KEY = "id_time";
    /**
     * The number of threads active in the current Process.
     */
    static final String NUMTHREADS = "NumThreads";
    static final String NUMTHREADS_KEY = "id_nlwps";
    /**
     * The system clock time at which the sample was taken.
     */
    static final String TIMESTAMP = "Timestamp";
    static final String TIMESTAMP_KEY = "id_timestamp";
}
