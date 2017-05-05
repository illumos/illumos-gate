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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/isa_defs.h>

#include <stdio.h>
#include <stdio_ext.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stack.h>
#include <link.h>
#include <limits.h>
#include <libelf.h>
#include <thread_db.h>
#include <libproc.h>
#include <setjmp.h>

static	char	*command;
static	int	Fflag;
static	int	is64;
static	GElf_Sym sigh;

/*
 * To keep the list of user-level threads for a multithreaded process.
 */
struct threadinfo {
	struct threadinfo *next;
	id_t	threadid;
	id_t	lwpid;
	td_thr_state_e state;
	uintptr_t startfunc;
	uintptr_t exitval;
	prgregset_t regs;
};

static struct threadinfo *thr_head, *thr_tail;

#define	TRUE	1
#define	FALSE	0

#define	MAX_ARGS	8

/*
 * To support debugging java programs, we display java frames within a stack.
 * The logic to walk the java frames is contained in libjvm_db.so, which is
 * found in the same directory as libjvm.so, linked with the program.  If we are
 * debugging a 32-bit app with a 64-binary, then the debugging library is found
 * in the '64' subdirectory.  If we find libjvm_db.so, then we fill in these
 * stub routines.
 */
typedef struct jvm_agent jvm_agent_t;
typedef int java_stack_f(void *, prgregset_t, const char *, int, int, void *);

/*
 * The j_agent_create function takes a version parameter.  This ensures that the
 * interface can evolve appropriately.
 */
#define	JVM_DB_VERSION	1
static void *libjvm;
typedef jvm_agent_t *(*j_agent_create_f)(struct ps_prochandle *, int);
typedef void (*j_agent_destroy_f)(jvm_agent_t *);
typedef int (*j_frame_iter_f)(jvm_agent_t *, prgregset_t, java_stack_f *,
    void *);

static j_agent_create_f j_agent_create;
static j_agent_destroy_f j_agent_destroy;
static j_frame_iter_f j_frame_iter;

static jvm_agent_t *load_libjvm(struct ps_prochandle *P);
static void reset_libjvm(jvm_agent_t *);

/*
 * Similar to what's done for debugging java programs, here are prototypes for
 * the library that allows us to debug Python programs.
 */
#define	PYDB_VERSION	1
static void *libpython;

typedef struct pydb_agent pydb_agent_t;

typedef pydb_agent_t *(*pydb_agent_create_f)(struct ps_prochandle *P, int vers);
typedef void (*pydb_agent_destroy_f)(pydb_agent_t *py);
typedef int (*pydb_pc_frameinfo_f)(pydb_agent_t *py, uintptr_t pc,
    uintptr_t frame_addr, char *fbuf, size_t bufsz);

static pydb_agent_create_f pydb_agent_create;
static pydb_agent_destroy_f pydb_agent_destroy;
static pydb_pc_frameinfo_f pydb_pc_frameinfo;

static pydb_agent_t *load_libpython(struct ps_prochandle *P);
static void reset_libpython(pydb_agent_t *);
/*
 * Since we must maintain both a proc handle and a jvm handle, this structure
 * is the basic type that gets passed around.
 */
typedef struct pstack_handle {
	struct ps_prochandle *proc;
	jvm_agent_t *jvm;
	int ignore_frame;
	const char *lwps;
	int count;
	pydb_agent_t *pydb;
} pstack_handle_t;

static	int	thr_stack(const td_thrhandle_t *, void *);
static	void	free_threadinfo(void);
static	struct threadinfo *find_thread(id_t);
static	int	all_call_stacks(pstack_handle_t *, int);
static	void	tlhead(id_t, id_t, const char *);
static	int	print_frame(void *, prgregset_t, uint_t, const long *);
static	void	print_zombie(struct ps_prochandle *, struct threadinfo *);
static	void	print_syscall(const lwpstatus_t *, prgregset_t);
static	void	call_stack(pstack_handle_t *, const lwpstatus_t *);

/*
 * The number of active and zombie threads.
 */
static	int	nthreads;

int
main(int argc, char **argv)
{
	int retc = 0;
	int opt;
	int errflg = FALSE;
	core_content_t content = CC_CONTENT_DATA | CC_CONTENT_ANON |
	    CC_CONTENT_STACK;
	struct rlimit rlim;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	/* options */
	while ((opt = getopt(argc, argv, "F")) != EOF) {
		switch (opt) {
		case 'F':
			/*
			 * If the user specifies the force option, we'll
			 * consent to printing out other threads' stacks
			 * even if the main stack is absent.
			 */
			content &= ~CC_CONTENT_STACK;
			Fflag = PGRAB_FORCE;
			break;
		default:
			errflg = TRUE;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (errflg || argc <= 0) {
		(void) fprintf(stderr,
		    "usage:\t%s [-F] { pid | core }[/lwps] ...\n", command);
		(void) fprintf(stderr, "  (show process call stack)\n");
		(void) fprintf(stderr,
		    "  -F: force grabbing of the target process\n");
		exit(2);
	}

	/*
	 * Make sure we'll have enough file descriptors to handle a target
	 * that has many many mappings.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	(void) proc_initstdio();

	while (--argc >= 0) {
		int gcode;
		psinfo_t psinfo;
		const psinfo_t *tpsinfo;
		struct ps_prochandle *Pr = NULL;
		td_thragent_t *Tap;
		int threaded;
		pstack_handle_t handle;
		const char *lwps, *arg;

		(void) proc_flushstdio();

		arg = *argv++;

		if ((Pr = proc_arg_xgrab(arg, NULL, PR_ARG_ANY,
		    Fflag, &gcode, &lwps)) == NULL) {
			(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
			    command, arg, Pgrab_error(gcode));
			retc++;
			continue;
		}

		if ((tpsinfo = Ppsinfo(Pr)) == NULL) {
			(void) fprintf(stderr, "%s: cannot examine %s: "
			    "lost control of process\n", command, arg);
			Prelease(Pr, 0);
			retc++;
			continue;
		}
		(void) memcpy(&psinfo, tpsinfo, sizeof (psinfo_t));
		proc_unctrl_psinfo(&psinfo);

		if (Pstate(Pr) == PS_DEAD) {
			if ((Pcontent(Pr) & content) != content) {
				(void) fprintf(stderr, "%s: core '%s' has "
				    "insufficient content\n", command, arg);
				retc++;
				continue;
			}
			(void) printf("core '%s' of %d:\t%.70s\n",
			    arg, (int)psinfo.pr_pid, psinfo.pr_psargs);
		} else {
			(void) printf("%d:\t%.70s\n",
			    (int)psinfo.pr_pid, psinfo.pr_psargs);
		}

		is64 = (psinfo.pr_dmodel == PR_MODEL_LP64);

		if (Pgetauxval(Pr, AT_BASE) != -1L && Prd_agent(Pr) == NULL) {
			(void) fprintf(stderr, "%s: warning: librtld_db failed "
			    "to initialize; symbols from shared libraries will "
			    "not be available\n", command);
		}

		/*
		 * First we need to get a thread agent handle.
		 */
		if (td_init() != TD_OK ||
		    td_ta_new(Pr, &Tap) != TD_OK)	/* no libc */
			threaded = FALSE;
		else {
			/*
			 * Iterate over all threads, calling:
			 *   thr_stack(td_thrhandle_t *Thp, NULL);
			 * for each one to generate the list of threads.
			 */
			nthreads = 0;
			(void) td_ta_thr_iter(Tap, thr_stack, NULL,
			    TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
			    TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);

			(void) td_ta_delete(Tap);
			threaded = TRUE;
		}

		handle.proc = Pr;
		handle.jvm = load_libjvm(Pr);
		handle.pydb = load_libpython(Pr);
		handle.lwps = lwps;
		handle.count = 0;

		if (all_call_stacks(&handle, threaded) != 0)
			retc++;
		if (threaded)
			free_threadinfo();

		reset_libjvm(handle.jvm);
		reset_libpython(handle.pydb);
		Prelease(Pr, 0);

		if (handle.count == 0)
			(void) fprintf(stderr, "%s: no matching LWPs found\n",
			    command);
	}

	(void) proc_finistdio();

	return (retc);
}

/*
 * Thread iteration call-back function.
 * Called once for each user-level thread.
 * Used to build the list of all threads.
 */
/* ARGSUSED1 */
static int
thr_stack(const td_thrhandle_t *Thp, void *cd)
{
	td_thrinfo_t thrinfo;
	struct threadinfo *tip;
	td_err_e error;

	if (td_thr_get_info(Thp, &thrinfo) != TD_OK)
		return (0);

	tip = malloc(sizeof (struct threadinfo));
	tip->next = NULL;
	tip->threadid = thrinfo.ti_tid;
	tip->lwpid = thrinfo.ti_lid;
	tip->state = thrinfo.ti_state;
	tip->startfunc = thrinfo.ti_startfunc;
	tip->exitval = (uintptr_t)thrinfo.ti_exitval;
	nthreads++;

	if (thrinfo.ti_state == TD_THR_ZOMBIE ||
	    ((error = td_thr_getgregs(Thp, tip->regs)) != TD_OK &&
	    error != TD_PARTIALREG))
		(void) memset(tip->regs, 0, sizeof (prgregset_t));

	if (thr_tail)
		thr_tail->next = tip;
	else
		thr_head = tip;
	thr_tail = tip;

	return (0);
}

static void
free_threadinfo()
{
	struct threadinfo *tip = thr_head;
	struct threadinfo *next;

	while (tip) {
		next = tip->next;
		free(tip);
		tip = next;
	}

	thr_head = thr_tail = NULL;
}

/*
 * Find and eliminate the thread corresponding to the given lwpid.
 */
static struct threadinfo *
find_thread(id_t lwpid)
{
	struct threadinfo *tip;

	for (tip = thr_head; tip; tip = tip->next) {
		if (lwpid == tip->lwpid) {
			tip->lwpid = 0;
			return (tip);
		}
	}
	return (NULL);
}

static int
thread_call_stack(void *data, const lwpstatus_t *psp,
    const lwpsinfo_t *pip)
{
	char lwpname[THREAD_NAME_MAX] = "";
	pstack_handle_t *h = data;
	lwpstatus_t lwpstatus;
	struct threadinfo *tip;

	if (!proc_lwp_in_set(h->lwps, pip->pr_lwpid))
		return (0);
	h->count++;

	if ((tip = find_thread(pip->pr_lwpid)) == NULL)
		return (0);

	(void) Plwp_getname(h->proc, pip->pr_lwpid,
	    lwpname, sizeof (lwpname));

	tlhead(tip->threadid, pip->pr_lwpid, lwpname);
	tip->threadid = 0;	/* finish eliminating tid */
	if (psp)
		call_stack(h, psp);
	else {
		if (tip->state == TD_THR_ZOMBIE)
			print_zombie(h->proc, tip);
		else {
			(void) memset(&lwpstatus, 0, sizeof (lwpstatus));
			(void) memcpy(lwpstatus.pr_reg, tip->regs,
			    sizeof (prgregset_t));
			call_stack(h, &lwpstatus);
		}
	}
	return (0);
}

static int
lwp_call_stack(void *data,
    const lwpstatus_t *psp, const lwpsinfo_t *pip)
{
	char lwpname[THREAD_NAME_MAX] = "";
	pstack_handle_t *h = data;

	if (!proc_lwp_in_set(h->lwps, pip->pr_lwpid))
		return (0);
	h->count++;

	(void) Plwp_getname(h->proc, pip->pr_lwpid,
	    lwpname, sizeof (lwpname));

	tlhead(0, pip->pr_lwpid, lwpname);
	if (psp)
		call_stack(h, psp);
	else
		(void) printf("\t** zombie "
		    "(exited, not detached, not yet joined) **\n");
	return (0);
}

static int
all_call_stacks(pstack_handle_t *h, int dothreads)
{
	struct ps_prochandle *Pr = h->proc;
	pstatus_t status = *Pstatus(Pr);

	(void) memset(&sigh, 0, sizeof (GElf_Sym));
	(void) Plookup_by_name(Pr, "libc.so", "sigacthandler", &sigh);

	if ((status.pr_nlwp + status.pr_nzomb) <= 1 &&
	    !(dothreads && nthreads > 1)) {
		if (proc_lwp_in_set(h->lwps, status.pr_lwp.pr_lwpid)) {
			call_stack(h, &status.pr_lwp);
			h->count++;
		}
	} else {
		lwpstatus_t lwpstatus;
		struct threadinfo *tip;
		id_t tid;

		if (dothreads)
			(void) Plwp_iter_all(Pr, thread_call_stack, h);
		else
			(void) Plwp_iter_all(Pr, lwp_call_stack, h);

		/* for each remaining thread w/o an lwp */
		(void) memset(&lwpstatus, 0, sizeof (lwpstatus));
		for (tip = thr_head; tip; tip = tip->next) {

			if (!proc_lwp_in_set(h->lwps, tip->lwpid))
				tip->threadid = 0;

			if ((tid = tip->threadid) != 0) {
				(void) memcpy(lwpstatus.pr_reg, tip->regs,
				    sizeof (prgregset_t));
				tlhead(tid, tip->lwpid, NULL);
				if (tip->state == TD_THR_ZOMBIE)
					print_zombie(Pr, tip);
				else
					call_stack(h, &lwpstatus);
			}
			tip->threadid = 0;
			tip->lwpid = 0;
		}
	}
	return (0);
}

/* The width of the header */
#define	HEAD_WIDTH	(62)
static void
tlhead(id_t threadid, id_t lwpid, const char *name)
{
	char buf[128] = { 0 };
	char num[16];
	ssize_t amt = 0;
	int i;

	if (threadid == 0 && lwpid == 0)
		return;

	if (lwpid > 0) {
		(void) snprintf(num, sizeof (num), "%d", (int)lwpid);
		(void) strlcat(buf, "thread# ", sizeof (buf));
		(void) strlcat(buf, num, sizeof (buf));
	}

	if (threadid > 0) {
		(void) snprintf(num, sizeof (num), "%d", (int)threadid);
		if (lwpid > 0)
			(void) strlcat(buf, " / ", sizeof (buf));
		(void) strlcat(buf, "lwp# ", sizeof (buf));
		(void) strlcat(buf, num, sizeof (buf));
	}

	if (name != NULL && strlen(name) > 0) {
		(void) strlcat(buf, " [", sizeof (buf));
		(void) strlcat(buf, name, sizeof (buf));
		(void) strlcat(buf, "]", sizeof (buf));
	}

	amt = (HEAD_WIDTH - strlen(buf) - 2);
	if (amt < 4)
		amt = 4;

	for (i = 0; i < amt / 2; i++)
		(void) putc('-', stdout);
	(void) printf(" %s ", buf);
	for (i = 0; i < (amt / 2) + (amt % 2); i++)
		(void) putc('-', stdout);
	(void) putc('\n', stdout);
}

/*ARGSUSED*/
static int
print_java_frame(void *cld, prgregset_t gregs, const char *name, int bci,
    int line, void *handle)
{
	int length = (is64 ? 16 : 8);

	(void) printf(" %.*lx * %s", length, (long)gregs[R_PC], name);

	if (bci != -1) {
		(void) printf("+%d", bci);
		if (line)
			(void) printf(" (line %d)", line);
	}
	(void) printf("\n");

	return (0);
}

static sigjmp_buf jumpbuf;

/*ARGSUSED*/
static void
fatal_signal(int signo)
{
	siglongjmp(jumpbuf, 1);
}

static int
print_frame(void *cd, prgregset_t gregs, uint_t argc, const long *argv)
{
	pstack_handle_t *h = cd;
	struct ps_prochandle *Pr = h->proc;
	uintptr_t pc = gregs[R_PC];
	char buff[255];
	GElf_Sym sym;
	uintptr_t start;
	int length = (is64? 16 : 8);
	int i;

	/*
	 * If we are in a system call, we display the entry frame in a more
	 * readable manner, using the name of the system call.  In this case, we
	 * want to ignore this first frame, since we already displayed it
	 * separately.
	 */
	if (h->ignore_frame) {
		h->ignore_frame = 0;
		return (0);
	}

	(void) sprintf(buff, "%.*lx", length, (long)pc);
	(void) strcpy(buff + length, " ????????");
	if (Plookup_by_addr(Pr, pc,
	    buff + 1 + length, sizeof (buff) - 1 - length, &sym) == 0) {
		start = sym.st_value;
	} else if (h->jvm != NULL) {
		int ret;
		void (*segv)(int), (*bus)(int), (*ill)(int);

		segv = signal(SIGSEGV, fatal_signal);
		bus = signal(SIGBUS, fatal_signal);
		ill = signal(SIGILL, fatal_signal);

		/* Insure against a bad libjvm_db */
		if (sigsetjmp(jumpbuf, 0) == 0)
			ret = j_frame_iter(h->jvm, gregs, print_java_frame,
			    NULL);
		else
			ret = -1;

		(void) signal(SIGSEGV, segv);
		(void) signal(SIGBUS, bus);
		(void) signal(SIGILL, ill);

		if (ret == 0)
			return (ret);
	} else {
		start = pc;
	}

	(void) printf(" %-17s (", buff);
	for (i = 0; i < argc && i < MAX_ARGS; i++)
		(void) printf((i+1 == argc) ? "%lx" : "%lx, ", argv[i]);
	if (i != argc)
		(void) printf("...");
	(void) printf((start != pc) ? ") + %lx\n" : ")\n", (long)(pc - start));

	if (h->pydb != NULL && argc > 0) {
		char buf_py[1024];
		int rc;

		rc = pydb_pc_frameinfo(h->pydb, pc, argv[0], buf_py,
		    sizeof (buf_py));
		if (rc == 0) {
			(void) printf("   %s", buf_py);
		}
	}

	/*
	 * If the frame's pc is in the "sigh" (a.k.a. signal handler, signal
	 * hack, or *sigh* ...) range, then we're about to cross a signal
	 * frame.  The signal number is the first argument to this function.
	 */
	if (pc - sigh.st_value < sigh.st_size) {
		if (sig2str((int)argv[0], buff) == -1)
			(void) strcpy(buff, " Unknown");
		(void) printf(" --- called from signal handler with "
		    "signal %d (SIG%s) ---\n", (int)argv[0], buff);
	}

	return (0);
}

static void
print_zombie(struct ps_prochandle *Pr, struct threadinfo *tip)
{
	char buff[255];
	GElf_Sym sym;
	uintptr_t start;
	int length = (is64? 16 : 8);

	(void) sprintf(buff, "%.*lx", length, (long)tip->startfunc);
	(void) strcpy(buff + length, " ????????");
	if (Plookup_by_addr(Pr, tip->startfunc,
	    buff + 1 + length, sizeof (buff) - 1 - length, &sym) == 0)
		start = sym.st_value;
	else
		start = tip->startfunc;
	(void) printf(" %s()", buff);
	if (start != tip->startfunc)	/* doesn't happen? */
		(void) printf("+%lx", (long)(tip->startfunc - start));
	(void) printf(", exit value = 0x%.*lx\n", length, (long)tip->exitval);
	(void) printf("\t** zombie "
	    "(exited, not detached, not yet joined) **\n");
}

static void
print_syscall(const lwpstatus_t *psp, prgregset_t reg)
{
	char sname[32];
	int length = (is64? 16 : 8);
	uint_t i;

	(void) proc_sysname(psp->pr_syscall, sname, sizeof (sname));
	(void) printf(" %.*lx %-8s (", length, (long)reg[R_PC], sname);
	for (i = 0; i < psp->pr_nsysarg; i++)
		(void) printf((i+1 == psp->pr_nsysarg)? "%lx" : "%lx, ",
		    (long)psp->pr_sysarg[i]);
	(void) printf(")\n");
}

static void
call_stack(pstack_handle_t *h, const lwpstatus_t *psp)
{
	prgregset_t reg;

	(void) memcpy(reg, psp->pr_reg, sizeof (reg));

	if ((psp->pr_flags & (PR_ASLEEP|PR_VFORKP)) ||
	    ((psp->pr_flags & PR_ISTOP) &&
	    (psp->pr_why == PR_SYSENTRY ||
	    psp->pr_why == PR_SYSEXIT))) {
		print_syscall(psp, reg);
		h->ignore_frame = 1;
	} else {
		h->ignore_frame = 0;
	}

	(void) Pstack_iter(h->proc, reg, print_frame, h);
}

/*ARGSUSED*/
static int
jvm_object_iter(void *cd, const prmap_t *pmp, const char *obj)
{
	char path[PATH_MAX];
	char *name;
	char *s1, *s2;
	struct ps_prochandle *Pr = cd;

	if ((name = strstr(obj, "/libjvm.so")) == NULL)
		name = strstr(obj, "/libjvm_g.so");

	if (name) {
		(void) strcpy(path, obj);
		if (Pstatus(Pr)->pr_dmodel != PR_MODEL_NATIVE) {
			s1 = name;
			s2 = path + (s1 - obj);
			(void) strcpy(s2, "/64");
			s2 += 3;
			(void) strcpy(s2, s1);
		}

		s1 = strstr(obj, ".so");
		s2 = strstr(path, ".so");
		(void) strcpy(s2, "_db");
		s2 += 3;
		(void) strcpy(s2, s1);

		if ((libjvm = dlopen(path, RTLD_LAZY|RTLD_GLOBAL)) != NULL)
			return (1);
	}

	return (0);
}

static jvm_agent_t *
load_libjvm(struct ps_prochandle *Pr)
{
	jvm_agent_t *ret;

	/*
	 * Iterate through all the loaded objects in the target, looking
	 * for libjvm.so.  If we find libjvm.so we'll try to load the
	 * corresponding libjvm_db.so that lives in the same directory.
	 *
	 * At first glance it seems like we'd want to use
	 * Pobject_iter_resolved() here since we'd want to make sure that
	 * we have the full path to the libjvm.so.  But really, we don't
	 * want that since we're going to be dlopen()ing a library and
	 * executing code from that path, and therefore we don't want to
	 * load any library code that could be from a zone since it could
	 * have been replaced with a trojan.  Hence, we use Pobject_iter().
	 * So if we're debugging java processes in a zone from the global
	 * zone, and we want to get proper java stack stack frames, then
	 * the same jvm that is running within the zone needs to be
	 * installed in the global zone.
	 */
	(void) Pobject_iter(Pr, jvm_object_iter, Pr);

	if (libjvm) {
		j_agent_create = (j_agent_create_f)
		    dlsym(libjvm, "Jagent_create");
		j_agent_destroy = (j_agent_destroy_f)
		    dlsym(libjvm, "Jagent_destroy");
		j_frame_iter = (j_frame_iter_f)
		    dlsym(libjvm, "Jframe_iter");

		if (j_agent_create == NULL || j_agent_destroy == NULL ||
		    j_frame_iter == NULL ||
		    (ret = j_agent_create(Pr, JVM_DB_VERSION)) == NULL) {
			reset_libjvm(NULL);
			return (NULL);
		}

		return (ret);
	}

	return (NULL);
}

static void
reset_libjvm(jvm_agent_t *agent)
{
	if (libjvm) {
		if (agent)
			j_agent_destroy(agent);

		(void) dlclose(libjvm);
	}

	j_agent_create = NULL;
	j_agent_destroy = NULL;
	j_frame_iter = NULL;
	libjvm = NULL;
}

/*ARGSUSED*/
static int
python_object_iter(void *cd, const prmap_t *pmp, const char *obj)
{
	char path[PATH_MAX];
	char *name;
	char *s1, *s2;
	struct ps_prochandle *Pr = cd;

	name = strstr(obj, "/libpython");

	if (name) {
		(void) strcpy(path, obj);
		if (Pstatus(Pr)->pr_dmodel != PR_MODEL_NATIVE) {
			s1 = name;
			s2 = path + (s1 - obj);
			(void) strcpy(s2, "/64");
			s2 += 3;
			(void) strcpy(s2, s1);
		}

		s1 = strstr(obj, ".so");
		s2 = strstr(path, ".so");
		(void) strcpy(s2, "_db");
		s2 += 3;
		(void) strcpy(s2, s1);

		if ((libpython = dlopen(path, RTLD_LAZY|RTLD_GLOBAL)) != NULL)
			return (1);
	}

	return (0);
}

static pydb_agent_t *
load_libpython(struct ps_prochandle *Pr)
{
	pydb_agent_t *pdb;

	(void) Pobject_iter(Pr, python_object_iter, Pr);

	if (libpython) {
		pydb_agent_create = (pydb_agent_create_f)
		    dlsym(libpython, "pydb_agent_create");
		pydb_agent_destroy = (pydb_agent_destroy_f)
		    dlsym(libpython, "pydb_agent_destroy");
		pydb_pc_frameinfo = (pydb_pc_frameinfo_f)
		    dlsym(libpython, "pydb_pc_frameinfo");

		if (pydb_agent_create == NULL || pydb_agent_destroy == NULL ||
		    pydb_pc_frameinfo == NULL) {
			(void) dlclose(libpython);
			libpython = NULL;
			return (NULL);
		}

		pdb = pydb_agent_create(Pr, PYDB_VERSION);
		if (pdb == NULL) {
			(void) dlclose(libpython);
			libpython = NULL;
			return (NULL);
		}
		return (pdb);
	}

	return (NULL);
}

static void
reset_libpython(pydb_agent_t *pdb)
{
	if (libpython != NULL) {
		if (pdb != NULL) {
			pydb_agent_destroy(pdb);
		}
		(void) dlclose(libpython);
	}

	libpython = NULL;
	pydb_agent_create = NULL;
	pydb_agent_destroy = NULL;
	pydb_pc_frameinfo = NULL;
}
