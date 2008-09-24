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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <libproc.h>
#include "ramdata.h"
#include "proto.h"
#include "htbl.h"

/*
 * ramdata.c -- read/write data definitions are collected here.
 * Default initialization of zero applies in all cases.
 */

thread_key_t private_key;	/* set by thr_keycreate() */
char	*command;		/* name of command ("truss") */
int	interrupt;		/* interrupt signal was received */
int	sigusr1;		/* received SIGUSR1 (release process) */
int	sfd;			/* shared tmp file descriptor */
pid_t	created;		/* if process was created, its process id */
uid_t	Euid;			/* truss's effective uid */
uid_t	Egid;			/* truss's effective gid */
uid_t	Ruid;			/* truss's real uid */
uid_t	Rgid;			/* truss's real gid */
prcred_t credentials;		/* traced process credentials */
int	istty;			/* TRUE iff output is a tty */
time_t	starttime;		/* start time */

int	Fflag;			/* option flags from getopt() */
int	fflag;
int	cflag;
int	aflag;
int	eflag;
int	iflag;
int	lflag;
int	tflag;
int	pflag;
int	sflag;
int	mflag;
int	oflag;
int	vflag;
int	xflag;
int	hflag;

int	dflag;
int	Dflag;
int	Eflag;
int	Tflag;
int	Sflag;
int	Mflag;

sysset_t trace;			/* sys calls to trace */
sysset_t traceeven;		/* sys calls to trace even if not reported */
sysset_t verbose;		/* sys calls to be verbose about */
sysset_t rawout;		/* sys calls to show in raw mode */
sigset_t signals;		/* signals to trace */
fltset_t faults;		/* faults to trace */
fileset_t readfd;		/* read() file descriptors to dump */
fileset_t writefd;		/* write() file descriptors to dump */

mutex_t	truss_lock;		/* protects almost everything */
cond_t	truss_cv;
mutex_t count_lock;		/* lock protecting count struct Cp */

htbl_t	*fcall_tbl;		/* ptr to hash tbl counting function calls */

int	truss_nlwp;		/* number of truss lwps */
int	truss_maxlwp;		/* number of entries in truss_lwpid */
lwpid_t	*truss_lwpid;		/* array of truss lwpid's */

struct counts *Cp;		/* for counting: malloc() or shared memory */
struct global_psinfo *gps;	/* contains global process information */

struct dynlib *Dynlib;		/* for tracing functions in shared libraries */
struct dynpat *Dynpat;
struct dynpat *Lastpat;
struct bkpt **bpt_hashtable;	/* breakpoint hash table */
uint_t	nthr_create;		/* number of thr_create() calls seen so far */
struct callstack *callstack;	/* the callstack array */
uint_t	nstack;			/* number of detected stacks */
rd_agent_t *Rdb_agent;		/* run-time linker debug handle */
td_thragent_t *Thr_agent;	/* thread debug handle */
int	not_consist;		/* used while rebuilding breakpoint table */
int	delete_library;		/* used while rebuilding breakpoint table */

pid_t	ancestor;		/* top-level parent process id */
int	descendent;		/* TRUE iff descendent of top level */
int	is_vfork_child;		/* TRUE iff process is a vfork()ed child */

int	ngrab;			/* number of pid's that were grabbed */

struct ps_prochandle *Proc;	/* global reference to process */
int	data_model;		/* PR_MODEL_LP64 or PR_MODEL_ILP32 */

long	pagesize;		/* bytes per page; should be per-process */

int	exit_called;		/* _exit() syscall was seen */

lwpid_t	primary_lwp;		/* representative lwp on process grab */

sysset_t syshang;		/* sys calls to make process hang */
sigset_t sighang;		/* signals to make process hang */
fltset_t flthang;		/* faults to make process hang */

sigset_t emptyset;		/* no signals, for thr_sigsetmask() */
sigset_t fillset;		/* all signals, for thr_sigsetmask() */

int	leave_hung;		/* if TRUE, leave the process hung */
