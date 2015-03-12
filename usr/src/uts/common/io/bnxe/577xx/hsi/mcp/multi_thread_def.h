/****************************************************************************
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
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 *
 * Name:        mcp_multi_thread.h
 *
 * Description: Multi-thread definition and structures
 *
 * Created:     10 Oct 2011 yanivr
 ****************************************************************************/

/****************************************************************************
 * Include                                                                  *
 ****************************************************************************/
#ifndef MULTI_THREAD_DEF_H
#define MULTI_THREAD_DEF_H

#define MAX_THREAD_QUEUE 16
#define THREAD_STACK_SIZE 1500
#define STACK_FILL 0xbadbeef

typedef enum  {
	MISC_THREAD,
	LINK_THREAD,
	NET_THREAD,
	OCSD_THREAD,
	NUM_THREADS
}thread_name_e;

// This enum is  just for the complete picture.
// The running thread knows it is running so the only interesting state is the SLEEPING one

typedef enum {
	IDLE,
	RUNNING,
	SLEEPING
}thread_state_e;

typedef struct papo_arg_t {
	u16 path;
	u16 port;
} papo_t;

struct eeprom_arg_t {
	u16 pf_num;
	u16 is_specific_phy;
       u32 io_rsp; /* The response to write */
};

struct task_t {
	u16 op_id;
	u16 entry_count;
	union {
		struct papo_arg_t	papo;
		struct eeprom_arg_t	eeprom;
	}args;
};

struct tasks_queue_t {
	struct 	task_t task[MAX_THREAD_QUEUE]; /* The request queue. */
	u32 front;            /* For de-queue */
	u32 rear;             /* For queuing */
	u32 attributes;
#define TASK_ALWAYS_QUEUED 	(1<<0)
};

#ifdef MFW
typedef u8 (* THREAD_FUNC_PTR)    (struct task_t *i_task);
#else
#define THREAD_FUNC_PTR u32
#endif

struct mt_thread_stat {
	u32 total_cpu_time;
	u32 times_in_cpu;
	u32 going_to_sleep_count;
	u32 waking_up_count;
	u32 swim_failure_cnt;
	u32 swim_failure_timeout_cnt;
};

struct thread_t {
	u32 current_SP;            /* Current_SP will be initialized as the start of stack */
	u32 stack_guard_addr;
	THREAD_FUNC_PTR main_func; /* Entry point to the thread. */
	u32 start_time;            /* The time that the thread started to run */
	u32 time_slice_ticks;      /* Const value initialized once during compilation (only for the Network Manager) */
	u32 /* thread_state_e*/  state;
	u32 sleep_time;            /* In ticks */
	u32 sleep_length;          /* In ticks */
	u32 swim_load_fail_time;
	struct tasks_queue_t queue;
	struct mt_thread_stat stat;
};

struct scheduler_stat_t {
	u32 times_called;
};

struct scheduler_t {
	u32 cur_thread;
	struct scheduler_stat_t stat;
};

// Main structure
struct multi_thread_t {
	struct thread_t thread[NUM_THREADS];
	struct scheduler_t sched;
};

#endif // MULTI_THREAD_DEF_H
