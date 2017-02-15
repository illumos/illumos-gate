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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

/*
 * interfaces to exec a command and run it till all loadobjects have
 * been loaded (rtld sync point).
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "prb_proc_int.h"
#include "dbg.h"

/*
 * Defines
 */

#define	PRELOAD		"LD_PRELOAD"
#define	LIBPROBE	"libtnfprobe.so.1"

/*
 * Local declarations
 */

static prb_status_t sync_child(int pid, volatile shmem_msg_t *smp,
					prb_proc_ctl_t **proc_pp);

/*
 * prb_child_create()  - this routine instantiates and rendevous with the
 * target child process.  This routine returns an opaque handle for the
 * childs /proc entry.
 */
prb_status_t
prb_child_create(const char *cmdname, char * const *cmdargs,
    const char *loption, const char *libtnfprobe_path,
    char * const *envp, prb_proc_ctl_t **ret_val)
{
	prb_status_t	prbstat;
	pid_t		childpid;
	char		executable_name[PATH_MAX + 2];
	extern char	**environ;
	char * const *	env_to_use;
	size_t		loptlen, probepathlen;
	volatile shmem_msg_t *smp;

	/* initialize shmem communication buffer to cause child to wait */
	prbstat = prb_shmem_init(&smp);
	if (prbstat)
		return (prbstat);

	/* fork to create the child process */
	childpid = fork();
	if (childpid == (pid_t)-1) {
		DBG(perror("prb_child_create: fork failed"));
		return (prb_status_map(errno));
	}
	if (childpid == 0) {
		char		   *oldenv;
		char		   *newenv;

		/* ---- CHILD PROCESS ---- */

		DBG_TNF_PROBE_1(prb_child_create_1, "libtnfctl",
		    "sunw%verbosity 1; sunw%debug 'child process created'",
		    tnf_long, pid, getpid());

		if (envp) {
			env_to_use = envp;
			goto ContChild;
		}

		/* append libtnfprobe.so to the LD_PRELOAD environment */
		loptlen = (loption) ? strlen(loption) : 0;
		/* probepathlen has a "/" added in ("+ 1") */
		probepathlen = (libtnfprobe_path) ?
		    (strlen(libtnfprobe_path) + 1) : 0;
		oldenv = getenv(PRELOAD);
		if (oldenv) {
			newenv = (char *)malloc(strlen(PRELOAD) +
			    1 +	/* "=" */
			    strlen(oldenv) +
			    1 +	/* " " */
			    probepathlen +
			    strlen(LIBPROBE) +
			    1 +	/* " " */
			    loptlen +
			    1);	/* NULL */

			if (!newenv)
				goto ContChild;
			(void) strcpy(newenv, PRELOAD);
			(void) strcat(newenv, "=");
			(void) strcat(newenv, oldenv);
			(void) strcat(newenv, " ");
			if (probepathlen) {
				(void) strcat(newenv, libtnfprobe_path);
				(void) strcat(newenv, "/");
			}
			(void) strcat(newenv, LIBPROBE);
			if (loptlen) {
				(void) strcat(newenv, " ");
				(void) strcat(newenv, loption);
			}
		} else {
			newenv = (char *)malloc(strlen(PRELOAD) +
			    1 +	/* "=" */
			    probepathlen +
			    strlen(LIBPROBE) +
			    1 +	/* " " */
			    loptlen +
			    1);	/* NULL */
			if (!newenv)
				goto ContChild;
			(void) strcpy(newenv, PRELOAD);
			(void) strcat(newenv, "=");
			if (probepathlen) {
				(void) strcat(newenv, libtnfprobe_path);
				(void) strcat(newenv, "/");
			}
			(void) strcat(newenv, LIBPROBE);
			if (loptlen) {
				(void) strcat(newenv, " ");
				(void) strcat(newenv, loption);
			}
		}
		(void) putenv((char *)newenv);
		env_to_use = environ;
		/*
		 * We don't check the return value of putenv because the
		 * desired libraries might already be in the target, even
		 * if our effort to change the environment fails.  We
		 * should continue either way ...
		 */
ContChild:
		/* wait until the parent releases us */
		(void) prb_shmem_wait(smp);

		DBG_TNF_PROBE_1(prb_child_create_2, "libtnfctl",
		    "sunw%verbosity 2; "
		    "sunw%debug 'child process about to exec'",
		    tnf_string, cmdname, cmdname);

		/*
		 * make the child it's own process group.
		 * This is so that signals delivered to parent are not
		 * also delivered to child.
		 */
		(void) setpgrp();
		prbstat = find_executable(cmdname, executable_name);
		if (prbstat) {
			DBG((void) fprintf(stderr, "prb_child_create: %s\n",
			    prb_status_str(prbstat)));
			/* parent waits for exit */
			_exit(1);
		}
		if (execve(executable_name, cmdargs, env_to_use) == -1) {
			DBG(perror("prb_child_create: exec failed"));
			_exit(1);
		}

		/* Never reached */
		_exit(1);
	}
	/* ---- PARENT PROCESS ---- */
	/* child is waiting for us */

	prbstat = sync_child(childpid, smp, ret_val);
	if (prbstat) {
		return (prbstat);
	}

	return (PRB_STATUS_OK);

}

/*
 * interface that registers the address of the debug structure
 * in the target process.  This is where the linker maintains all
 * the information about the loadobjects
 */
void
prb_dbgaddr(prb_proc_ctl_t *proc_p, uintptr_t dbgaddr)
{
	proc_p->dbgaddr = dbgaddr;
}

/*
 * continue the child until the run time linker has loaded in all
 * the loadobjects (rtld sync point)
 */
static prb_status_t
sync_child(int childpid, volatile shmem_msg_t *smp, prb_proc_ctl_t **proc_pp)
{
	prb_proc_ctl_t		*proc_p, *oldproc_p;
	prb_status_t		prbstat = PRB_STATUS_OK;
	prb_status_t		tempstat;
	prb_proc_state_t	pstate;

	prbstat = prb_proc_open(childpid, proc_pp);
	if (prbstat)
		return (prbstat);

	proc_p = *proc_pp;

	prbstat = prb_proc_stop(proc_p);
	if (prbstat)
		goto ret_failure;

	/*
	 * default is to kill-on-last-close.  In case we cannot sync with
	 * target, we don't want the target to continue.
	 */
	prbstat = prb_proc_setrlc(proc_p, B_FALSE);
	if (prbstat)
		goto ret_failure;

	prbstat = prb_proc_setklc(proc_p, B_TRUE);
	if (prbstat)
		goto ret_failure;

	/* REMIND: do we have to wait on SYS_exec also ? */
	prbstat = prb_proc_exit(proc_p, SYS_execve, PRB_SYS_ADD);
	if (prbstat)
		goto ret_failure;

	prbstat = prb_proc_entry(proc_p, SYS_exit, PRB_SYS_ADD);
	if (prbstat)
		goto ret_failure;

	prbstat = prb_shmem_clear(smp);
	if (prbstat)
		goto ret_failure;

	prbstat = prb_proc_cont(proc_p);
	if (prbstat)
		goto ret_failure;

	prbstat = prb_proc_wait(proc_p, B_FALSE, NULL);
	switch (prbstat) {
	case PRB_STATUS_OK:
		break;
	case EAGAIN:
		/*
		 * If we had exec'ed a setuid/setgid program PIOCWSTOP
		 * will return EAGAIN.  Reopen the 'fd' and try again.
		 * Read the last section of /proc man page - we reopen first
		 * and then close the old fd.
		 */
		oldproc_p = proc_p;
		tempstat = prb_proc_reopen(childpid, proc_pp);
		proc_p = *proc_pp;
		if (tempstat) {
			/* here EACCES means exec'ed a setuid/setgid program */
			(void) prb_proc_close(oldproc_p);
			return (tempstat);
		}

		(void) prb_proc_close(oldproc_p);
		break;
	default:
		goto ret_failure;
	}

	prbstat = prb_shmem_free(smp);
	if (prbstat)
		goto ret_failure;

	prbstat = prb_proc_state(proc_p, &pstate);
	if (prbstat)
		goto ret_failure;

	if (pstate.ps_issysexit && (pstate.ps_syscallnum == SYS_execve)) {
		/* expected condition */
		prbstat = PRB_STATUS_OK;
	} else {
		prbstat = prb_status_map(ENOENT);
		goto ret_failure;
	}

	/* clear old interest mask */
	prbstat = prb_proc_exit(proc_p, 0, PRB_SYS_NONE);
	if (prbstat)
		goto ret_failure;

	prbstat = prb_proc_entry(proc_p, 0, PRB_SYS_NONE);
	if (prbstat)
		goto ret_failure;

	/* Successful return */
	return (PRB_STATUS_OK);

ret_failure:
	(void) prb_proc_close(proc_p);
	return (prbstat);
}
