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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _RCM_SCRIPT_IMPL_H
#define	_RCM_SCRIPT_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	TRUE	1
#define	FALSE	0

/* Minimum and maximum rcm scripting API version supported. */
#define	SCRIPT_API_MIN_VER		1
#define	SCRIPT_API_MAX_VER		1

/*
 * Default maximum time (in seconds) allocated for an rcm command
 * before SIGABRT is sent.
 */
#define	SCRIPT_CMD_TIMEOUT		60

/*
 * Maximum time (in seconds) allocated after sending SIGABRT before
 * the script is killed.
 */
#define	SCRIPT_ABORT_TIMEOUT		10

/*
 * Maximum time (in seconds) for which the rcm daemon checks whether
 * a script is killed or not after the rcm daemon kills the script.
 */
#define	SCRIPT_KILL_TIMEOUT		3

/* Maximum number of command line parameters passed to a script */
#define	MAX_ARGS			16

/* Maximum number of environment parameters passed to a script */
#define	MAX_ENV_PARAMS			64

#define	MAX_LINE_LEN			(4*1024)
#define	MAX_FLAGS_NAME_LEN		64

/* exit codes */
typedef enum {
	E_SUCCESS,
	E_FAILURE,
	E_UNSUPPORTED_CMD,
	E_REFUSE
} script_exit_codes_t;

/* This structure is used to maintain a list of current dr'ed resources */
typedef struct {
	rcm_queue_t queue;
	char *resource_name;
} drreq_t;

/*
 * Main data structure for rcm scripting. There will be one instance of
 * this structure for every rcm script. A pointer to this structure is
 * kept in module structure.
 */
typedef struct script_info {
	/*
	 * Used to maintain a queue of script_info structures
	 * Global variable script_info_q is the head of the queue.
	 */
	rcm_queue_t queue;

	rcm_queue_t drreq_q;	/* queue head for current dr'ed resources */

	module_t *module;
	rcm_handle_t *hdl;

	char *script_full_name;	/* name of the script including path */
	char *script_name;	/* name of the script without path component */

	/*
	 * file descriptors used to communicate with the script
	 * pipe1 is used to capture script's stdout
	 * pipe2 is used to capture script's stderr
	 */
	int pipe1[2];
	int pipe2[2];

	pid_t pid;		/* process id of the script process */
	thread_t tid;		/* thread id of the stderr reader thread */

	/*
	 * Lock to protect the fileds in this structure and also to protect
	 * the communication channel to the script.
	 */
	mutex_t channel_lock;

	int ver;		/* scripting api version of the script */
	int cmd;		/* current rcm scripting command */
	int cmd_timeout;	/* timeout value in seconds */
	int exit_status;	/* exit status of the script */

	/* time stamp of the script when it was last run */
	time_t lastrun;

	char *func_info_buf;
	char *func_info_buf_curptr;
	int func_info_buf_len;

	char *resource_usage_info_buf;
	char *resource_usage_info_buf_curptr;
	int resource_usage_info_buf_len;

	char *failure_reason_buf;
	char *failure_reason_buf_curptr;
	int failure_reason_buf_len;
	uint_t flags;
} script_info_t;

/*
 * script_info_t:flags
 */
#define	STDERR_THREAD_CREATED	1

#define	PARENT_END_OF_PIPE	0
#define	CHILD_END_OF_PIPE	1

#define	PS_STATE_FILE_VER	1

typedef struct state_element {
	uint32_t flags;
	uint32_t reserved;	/* for 64 bit alignment */
	/* followed by actual state element */
} state_element_t;

/*
 * state_element_t:flags
 * The following flag when set indicates that the state element is
 * currently in use. When not set indicates that the state element is free.
 */
#define	STATE_ELEMENT_IN_USE	0x1

/*
 * This structure defines the layout of state file used by rcm scripting
 */
typedef struct state_file {
	uint32_t version;
	uint32_t max_elements;	/* number of state elements */
	/* followed by an array of state elements of type state_element_t */
} state_file_t;

typedef struct state_file_descr {
	uint32_t version;
	int fd;			/* file descriptor to the state file */
	size_t element_size;	/* size of one state element */

	/*
	 * number of state elements to allocate at a time when the state file
	 * grows.
	 */
	int chunk_size;

	/*
	 * index into the state element array where the next search will
	 * begin for an empty slot.
	 */
	int index;

	/* pointer to mmapped state file */
	state_file_t *state_file;
} state_file_descr_t;

/* round up to n byte boundary. n must be power of 2 for this macro to work */
#define	RSCR_ROUNDUP(x, n)	(((x) + ((n) - 1)) & (~((n) - 1)))

typedef struct ps_state_element {
	pid_t pid;
	char script_name[MAXNAMELEN];
} ps_state_element_t;

/* maximum number of additional env variables for capacity specific stuff */
#define	MAX_CAPACITY_PARAMS	10

typedef struct capacity_descr {
	char *resource_name;
	int match_type;
	struct {
		char *nvname;
		char *envname;
	} param[MAX_CAPACITY_PARAMS];
} capacity_descr_t;

/* capacity_descr_t:match_type */
#define	MATCH_INVALID		0
#define	MATCH_EXACT		1
#define	MATCH_PREFIX		2

#ifdef	__cplusplus
}
#endif

#endif /* _RCM_SCRIPT_IMPL_H */
