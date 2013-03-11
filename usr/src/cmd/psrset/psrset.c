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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

/*
 * psrset - create and manage processor sets
 */

#include <sys/types.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/pset.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <locale.h>
#include <string.h>
#include <limits.h>
#include <procfs.h>
#include <libproc.h>
#include <stdarg.h>
#include <zone.h>

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN 	"SYS_TEST"	/* Use this only if it wasn't */
#endif

#define	MAX_PROCFS_PATH	80

#define	ERR_OK		0		/* exit status for success */
#define	ERR_FAIL	1		/* exit status for errors */
#define	ERR_USAGE	2		/* exit status for usage errors */

static char *progname;
static int errors;
static char cflag;
static char dflag;
static char aflag;
static char rflag;
static char iflag;
static char bflag;
static char uflag;
static char Uflag;
static char qflag;
static char Qflag;
static char pflag;
static char nflag;
static char fflag;
static char Fflag;
static char eflag;
static char zflag;
static const char *zname;

extern int pset_assign_forced(psetid_t, processorid_t, psetid_t *);

/*PRINTFLIKE1*/
static void
warn(char *format, ...)
{
	int err = errno;
	va_list alist;

	(void) fprintf(stderr, "%s: ", progname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(err));
}

/*PRINTFLIKE1*/
static void
die(char *format, ...)
{
	int err = errno;
	va_list alist;

	(void) fprintf(stderr, "%s: ", progname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(err));
	exit(ERR_FAIL);
}

static struct ps_prochandle *
grab_proc(id_t pid)
{
	int ret;
	struct ps_prochandle *Pr;

	if ((Pr = Pgrab(pid, 0, &ret)) == NULL) {
		warn(gettext("cannot control process %d: %s\n"),
		    (int)pid, Pgrab_error(ret));
		errors = ERR_FAIL;
		return (NULL);
	}

	return (Pr);
}

static void
rele_proc(struct ps_prochandle *Pr)
{
	if (Pr == NULL)
		return;
	Prelease(Pr, 0);
}

static void
bind_err(psetid_t pset, const char *zname, id_t pid, id_t lwpid, int err)
{
	char    *msg;

	switch (pset) {
	case PS_NONE:
		msg = gettext("unbind");
		break;
	case PS_QUERY:
		msg = gettext("query");
		break;
	default:
		msg = gettext("bind");
		break;
	}

	errno = err;
	if (zname != NULL)
		warn(gettext("cannot %s zone %s"), msg, zname);
	else if (lwpid == -1)
		warn(gettext("cannot %s pid %d"), msg, pid);
	else
		warn(gettext("cannot %s lwpid %d/%d"), msg, pid, lwpid);
}

/*
 * Output for create.
 */
static void
create_out(psetid_t pset)
{
	(void) printf("%s %d\n", gettext("created processor set"), pset);
}

/*
 * Output for assign.
 */
static void
assign_out(processorid_t cpu, psetid_t old, psetid_t new)
{
	if (old == PS_NONE) {
		if (new == PS_NONE)
			(void) printf(gettext("processor %d: was not assigned,"
			    " now not assigned\n"), cpu);
		else
			(void) printf(gettext("processor %d: was not assigned,"
			    " now %d\n"), cpu, new);
	} else {
		if (new == PS_NONE)
			(void) printf(gettext("processor %d: was %d, "
			    "now not assigned\n"), cpu, old);
		else
			(void) printf(gettext("processor %d: was %d, "
			    "now %d\n"), cpu, old, new);
	}
}

/*
 * Output for query.
 */
static void
query_out(id_t pid, id_t lwpid, psetid_t pset)
{
	char *proclwp;
	char pidstr[21];

	if (lwpid == -1) {
		(void) snprintf(pidstr, 20, "%d", pid);
		proclwp = "process";
	} else {
		(void) snprintf(pidstr, 20, "%d/%d", pid, lwpid);
		proclwp = "lwp";
	}

	if (pset == PS_NONE)
		(void) printf(gettext("%s id %s: not bound\n"),
		    proclwp, pidstr);
	else
		(void) printf(gettext("%s id %s: %d\n"), proclwp, pidstr, pset);
}

/*
 * Output for info.
 */
static void
info_out(psetid_t pset, int type, uint_t numcpus, processorid_t *cpus)
{
	int i;
	if (type == PS_SYSTEM)
		(void) printf(gettext("system processor set %d:"), pset);
	else
		(void) printf(gettext("user processor set %d:"), pset);
	if (numcpus == 0)
		(void) printf(gettext(" empty"));
	else if (numcpus > 1)
		(void) printf(gettext(" processors"));
	else
		(void) printf(gettext(" processor"));
	for (i = 0; i < numcpus; i++)
		(void) printf(" %d", cpus[i]);
	(void) printf("\n");
}

/*
 * Output for print.
 */
static void
print_out(processorid_t cpu, psetid_t pset)
{
	if (pset == PS_NONE)
		(void) printf(gettext("processor %d: not assigned\n"), cpu);
	else
		(void) printf(gettext("processor %d: %d\n"), cpu, pset);
}

/*
 * Output for bind.
 */
static void
bind_out(id_t pid, id_t lwpid, psetid_t old, psetid_t new)
{
	char *proclwp;
	char pidstr[21];

	if (lwpid == -1) {
		(void) snprintf(pidstr, 20, "%d", pid);
		proclwp = "process";
	} else {
		(void) snprintf(pidstr, 20, "%d/%d", pid, lwpid);
		proclwp = "lwp";
	}

	if (old == PS_NONE) {
		if (new == PS_NONE)
			(void) printf(gettext("%s id %s: was not bound, "
			    "now not bound\n"), proclwp, pidstr);
		else
			(void) printf(gettext("%s id %s: was not bound, "
			    "now %d\n"), proclwp, pidstr, new);
	} else {
		if (new == PS_NONE)
			(void) printf(gettext("%s id %s: was %d, "
			    "now not bound\n"), proclwp, pidstr, old);
		else
			(void) printf(gettext("%s id %s: was %d, "
			    "now %d\n"), proclwp, pidstr, old, new);
	}
}

static void
bind_lwp(id_t pid, id_t lwpid, psetid_t pset)
{
	psetid_t old_pset;

	if (pset_bind_lwp(pset, lwpid, pid, &old_pset) != 0) {
		bind_err(pset, NULL, pid, lwpid, errno);
		errors = ERR_FAIL;
	}
	if (errors != ERR_FAIL) {
		if (qflag)
			query_out(pid, lwpid, old_pset);
		else
			bind_out(pid, lwpid, old_pset, pset);
	}
}

static int
do_cpu(psetid_t pset, processorid_t cpu, int print, int mustexist)
{
	psetid_t old_pset;
	int err;

	if ((!Fflag && pset_assign(pset, cpu, &old_pset) != 0) ||
	    (Fflag && pset_assign_forced(pset, cpu, &old_pset) != 0)) {
		if (errno == EINVAL && !mustexist)
			return (EINVAL);
		err = errno;

		switch (pset) {
		case PS_NONE:
			warn(gettext("cannot remove processor %d"), cpu);
			break;
		case PS_QUERY:
			warn(gettext("cannot query processor %d"), cpu);
			break;
		default:
			warn(gettext("cannot assign processor %d"), cpu);
			break;
		}
		return (err);
	}
	if (print)
		print_out(cpu, old_pset);
	else
		assign_out(cpu, old_pset, pset);
	return (0);
}

static int
do_range(psetid_t pset, processorid_t first, processorid_t last, int print)
{
	processorid_t cpu;
	int error = ERR_OK;
	int err;
	int found_one = 0;

	for (cpu = first; cpu <= last; cpu++) {
		if ((err = do_cpu(pset, cpu, print, 0)) == 0)
			found_one = 1;
		else if (err != EINVAL)
			error = ERR_FAIL;
	}
	if (!found_one && error == ERR_OK) {
		warn(gettext("no processors in range %d-%d\n"), first, last);
		error = ERR_FAIL;
	}
	return (error);
}

static int
do_info(psetid_t pset)
{
	int	type;
	uint_t	numcpus;
	processorid_t	*cpus;

	numcpus = (uint_t)sysconf(_SC_NPROCESSORS_MAX);
	cpus = (processorid_t *)
	    malloc(numcpus * sizeof (processorid_t));
	if (cpus == NULL) {
		warn(gettext("memory allocation failed"));
		return (ERR_FAIL);
	}
	if (pset_info(pset, &type, &numcpus, cpus) != 0) {
		warn(gettext("cannot get info for processor set %d"), pset);
		free(cpus);
		return (ERR_FAIL);
	}
	info_out(pset, type, numcpus, cpus);
	free(cpus);
	return (ERR_OK);
}

static int
do_destroy(psetid_t pset)
{
	if (pset_destroy(pset) != 0) {
		warn(gettext("could not remove processor set %d"), pset);
		return (ERR_FAIL);
	}
	(void) printf(gettext("removed processor set %d\n"), pset);
	return (ERR_OK);
}

static int
do_intr(psetid_t pset, int flag)
{
	uint_t i, numcpus;
	processorid_t *cpus;
	int error = ERR_OK;

	numcpus = (uint_t)sysconf(_SC_NPROCESSORS_MAX);
	cpus = (processorid_t *)
	    malloc(numcpus * sizeof (processorid_t));
	if (cpus == NULL) {
		warn(gettext("memory allocation failed"));
		return (ERR_FAIL);
	}
	if (pset_info(pset, NULL, &numcpus, cpus) != 0) {
		warn(gettext(
		    "cannot set interrupt status for processor set %d"), pset);
		free(cpus);
		return (ERR_FAIL);
	}
	for (i = 0; i < numcpus; i++) {
		int status = p_online(cpus[i], P_STATUS);
		if (status != P_OFFLINE && status != P_POWEROFF &&
		    status != flag) {
			if (p_online(cpus[i], flag) == -1) {
				warn(gettext("processor %d"), cpus[i]);
				error = ERR_FAIL;
			}
		}
	}
	free(cpus);
	return (error);
}

/*
 * Query the type and CPUs for all active processor sets in the system.
 */
static int
info_all(void)
{
	psetid_t *psetlist;
	uint_t	npsets, oldnpsets;
	int	i;
	int	errors = ERR_OK;

	if (pset_list(NULL, &npsets) != 0) {
		warn(gettext("cannot get number of processor sets"));
		return (1);
	}
	for (;;) {
		psetlist = malloc(sizeof (psetid_t) * npsets);
		if (psetlist == NULL) {
			warn(gettext("memory allocation failed"));
			return (ERR_FAIL);
		}
		oldnpsets = npsets;
		if (pset_list(psetlist, &npsets) != 0) {
			warn(gettext("cannot get list of processor sets"));
			free(psetlist);
			return (ERR_FAIL);
		}
		if (npsets <= oldnpsets)
			break;
		free(psetlist);
	}

	for (i = 0; i < npsets; i++) {
		if (do_info(psetlist[i]))
			errors = ERR_FAIL;
	}
	free(psetlist);
	return (errors);
}

/*
 * Query the processor set assignments for all CPUs in the system.
 */
static int
print_all(void)
{
	psetid_t	pset;
	processorid_t cpuid, max_cpuid;
	int	errors = ERR_OK;

	max_cpuid = (processorid_t)sysconf(_SC_CPUID_MAX);
	for (cpuid = 0; cpuid <= max_cpuid; cpuid++) {
		if (pset_assign(PS_QUERY, cpuid, &pset) == 0) {
			if (pset != PS_NONE)
				print_out(cpuid, pset);
		} else if (errno != EINVAL) {
			warn(gettext("cannot query processor %d"), cpuid);
			errors = ERR_FAIL;
		}
	}
	return (errors);
}

/*ARGSUSED*/
static int
query_all_proc(psinfo_t *psinfo, lwpsinfo_t *lwpsinfo, void *arg)
{
	id_t pid = psinfo->pr_pid;
	psetid_t binding;

	if (pset_bind(PS_QUERY, P_PID, pid, &binding) < 0) {
		/*
		 * Ignore search errors.  The process may have exited
		 * since we read the directory.
		 */
		if (errno == ESRCH)
			return (0);
		bind_err(PS_QUERY, NULL, pid, -1, errno);
		errors = ERR_FAIL;
		return (0);
	}
	if (binding != PS_NONE)
		query_out(pid, -1, binding);
	return (0);
}

static int
query_all_lwp(psinfo_t *psinfo, lwpsinfo_t *lwpsinfo, void *arg)
{
	id_t pid = psinfo->pr_pid;
	id_t lwpid = lwpsinfo->pr_lwpid;
	psetid_t *cpuid = arg;
	psetid_t binding = lwpsinfo->pr_bindpset;

	if (psinfo->pr_nlwp == 1)
		lwpid = -1;	/* report process bindings if only 1 lwp */
	if ((cpuid != NULL && *cpuid == binding) ||
	    (cpuid == NULL && binding != PBIND_NONE))
		query_out(pid, lwpid, binding);
	return (0);
}

void
exec_cmd(psetid_t pset, char **argv)
{
	if (pset_bind(pset, P_PID, P_MYID, NULL) != 0) {
		warn(gettext("cannot exec in processor set %d"), pset);
		return;
	}

	(void) execvp(argv[0], argv);
	warn(gettext("cannot exec command %s"), argv[0]);
}

int
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: \n"
	    "\t%1$s -c [-F] [processor_id ...]\n"
	    "\t%1$s -d processor_set_id ...\n"
	    "\t%1$s -n processor_set_id\n"
	    "\t%1$s -f processor_set_id\n"
	    "\t%1$s -e processor_set_id command [argument(s)...]\n"
	    "\t%1$s -a [-F] processor_set_id processor_id ...\n"
	    "\t%1$s -r [-F] processor_id ...\n"
	    "\t%1$s -p [processorid ...]\n"
	    "\t%1$s -b processor_set_id pid[/lwpids] ...\n"
	    "\t%1$s -b -z zonename processor_set_id\n"
	    "\t%1$s -u pid[/lwpids] ...\n"
	    "\t%1$s -q [pid[/lwpids] ...]\n"
	    "\t%1$s -U [processor_set_id] ...\n"
	    "\t%1$s -Q [processor_set_id] ...\n"
	    "\t%1$s [-i] [processor_set_id ...]\n"),
	    progname);
	return (ERR_USAGE);
}

/*
 * Query, set, or clear bindings for the range of LWPs in the given process.
 */
static int
do_lwps(id_t pid, const char *range, psetid_t pset)
{
	char procfile[MAX_PROCFS_PATH];
	struct ps_prochandle *Pr;
	struct prheader header;
	struct lwpsinfo *lwp;
	char *lpsinfo, *ptr;
	psetid_t binding;
	int nent, size;
	int i, fd, found;

	/*
	 * Report bindings for LWPs in process 'pid'.
	 */
	(void) snprintf(procfile, MAX_PROCFS_PATH,
	    "/proc/%d/lpsinfo", (int)pid);
	if ((fd = open(procfile, O_RDONLY)) < 0) {
		if (errno == ENOENT)
			errno = ESRCH;
		bind_err(pset, NULL, pid, -1, errno);
		return (ERR_FAIL);
	}
	if (pread(fd, &header, sizeof (header), 0) != sizeof (header)) {
		(void) close(fd);
		bind_err(pset, NULL, pid, -1, errno);
		return (ERR_FAIL);
	}
	nent = header.pr_nent;
	size = header.pr_entsize * nent;
	ptr = lpsinfo = malloc(size);
	if (lpsinfo == NULL) {
		bind_err(pset, NULL, pid, -1, errno);
		return (ERR_FAIL);
	}
	if (pread(fd, lpsinfo, size, sizeof (header)) != size) {
		bind_err(pset, NULL, pid, -1, errno);
		free(lpsinfo);
		(void) close(fd);
		return (ERR_FAIL);
	}

	if ((bflag || uflag) && (Pr = grab_proc(pid)) == NULL) {
		free(lpsinfo);
		(void) close(fd);
		return (ERR_FAIL);
	}
	found = 0;
	for (i = 0; i < nent; i++, ptr += header.pr_entsize) {
		/*LINTED ALIGNMENT*/
		lwp = (lwpsinfo_t *)ptr;
		binding = lwp->pr_bindpset;
		if (!proc_lwp_in_set(range, lwp->pr_lwpid))
			continue;
		found++;
		if (bflag || uflag)
			bind_lwp(pid, lwp->pr_lwpid, pset);
		else if (binding != PBIND_NONE)
			query_out(pid, lwp->pr_lwpid, binding);
	}
	if (bflag || uflag)
		rele_proc(Pr);
	free(lpsinfo);
	(void) close(fd);
	if (found == 0) {
		warn(gettext("cannot %s lwpid %d/%s: "
		    "No matching LWPs found\n"),
		    bflag ? "bind" : "query", pid, range);
		return (ERR_FAIL);
	}
	return (ERR_OK);
}

int
main(int argc, char *argv[])
{
	extern int optind;
	int	c;
	id_t	pid;
	processorid_t	cpu;
	psetid_t	pset, old_pset;
	zoneid_t	zid;
	char	*errptr;

	progname = argv[0];	/* put actual command name in messages */

	(void) setlocale(LC_ALL, "");	/* setup localization */
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "cdFarpibqQuUnfez:")) != EOF) {
		switch (c) {
		case 'c':
			cflag = 1;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'e':
			eflag = 1;
			break;
		case 'a':
			aflag = 1;
			break;
		case 'r':
			rflag = 1;
			pset = PS_NONE;
			break;
		case 'p':
			pflag = 1;
			pset = PS_QUERY;
			break;
		case 'i':
			iflag = 1;
			break;
		case 'b':
			bflag = 1;
			break;
		case 'u':
			uflag = 1;
			pset = PS_NONE;
			break;
		case 'U':
			Uflag = 1;
			break;
		case 'q':
			qflag = 1;
			pset = PS_QUERY;
			break;
		case 'Q':
			Qflag = 1;
			break;
		case 'f':
			fflag = 1;
			break;
		case 'F':
			Fflag = 1;
			break;
		case 'n':
			nflag = 1;
			break;
		case 'z':
			if (!bflag) {
				warn(gettext("-z can only be used after -b\n"));
				return (usage());
			}
			if (zflag) {
				warn(gettext("-z can only be specified "
				    "once\n"));
				return (usage());
			}
			zflag = 1;
			zname = optarg;
			break;
		default:
			return (usage());
		}
	}

	/*
	 * Make sure that at most one of the options was specified.
	 */
	c = cflag + dflag + aflag + rflag + pflag +
	    iflag + bflag + uflag + Uflag +
	    qflag + Qflag + fflag + nflag + eflag;
	if (c < 1) {				/* nothing specified */
		iflag = 1;			/* default is to get info */
	} else if (c > 1) {
		warn(gettext("options are mutually exclusive\n"));
		return (usage());
	}

	if (Fflag && (cflag + aflag + rflag == 0))
		return (usage());

	errors = 0;
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		/*
		 * Handle single option cases.
		 */
		if (qflag) {
			(void) proc_walk(query_all_proc, NULL, PR_WALK_PROC);
			return (errors);
		}
		if (Qflag) {
			(void) proc_walk(query_all_lwp, NULL, PR_WALK_LWP);
			return (errors);
		}
		if (Uflag) {
			if (pset_bind(PS_NONE, P_ALL, 0, &old_pset) != 0)
				die(gettext("failed to unbind all LWPs"));
		}
		if (pflag)
			return (print_all());
		if (iflag)
			return (info_all());
	}

	/*
	 * Get processor set id.
	 */
	if (aflag || bflag || fflag || nflag || eflag) {
		if (argc < 1) {
			/* must specify processor set */
			warn(gettext("must specify processor set\n"));
			return (usage());
		}
		pset = strtol(*argv, &errptr, 10);
		if (errptr != NULL && *errptr != '\0' || pset < 0) {
			warn(gettext("invalid processor set ID %s\n"), *argv);
			return (ERR_FAIL);
		}
		argv++;
		argc--;
	}

	if (cflag) {
		if (pset_create(&pset) != 0) {
			warn(gettext("could not create processor set"));
			return (ERR_FAIL);
		} else {
			create_out(pset);
			if (argc == 0)
				return (ERR_OK);
		}
	} else if (iflag || dflag) {
		if (argc == 0) {
			warn(gettext("must specify at least one "
			    "processor set\n"));
			return (usage());
		}
		/*
		 * Go through listed processor sets.
		 */
		for (; argc > 0; argv++, argc--) {
			pset = (psetid_t)strtol(*argv, &errptr, 10);
			if (errptr != NULL && *errptr != '\0') {
				warn(gettext("invalid processor set ID %s\n"),
				    *argv);
				errors = ERR_FAIL;
				continue;
			}
			if (iflag) {
				errors = do_info(pset);
			} else {
				errors = do_destroy(pset);
			}
		}
	} else if (nflag) {
		errors = do_intr(pset, P_ONLINE);
	} else if (fflag) {
		errors = do_intr(pset, P_NOINTR);
	} else if (eflag) {
		if (argc == 0) {
			warn(gettext("must specify command\n"));
			return (usage());
		}
		exec_cmd(pset, argv);
		/* if returning, must have had an error */
		return (ERR_USAGE);
	}

	if (cflag || aflag || rflag || pflag) {
		/*
		 * Perform function for each processor specified.
		 */
		if (argc == 0) {
			warn(gettext("must specify at least one processor\n"));
			return (usage());
		}

		/*
		 * Go through listed processors.
		 */
		for (; argc > 0; argv++, argc--) {
			if (strchr(*argv, '-') == NULL) {
				/* individual processor id */
				cpu = (processorid_t)strtol(*argv, &errptr, 10);
				if (errptr != NULL && *errptr != '\0') {
					warn(gettext("invalid processor "
					    "ID %s\n"), *argv);
					errors = ERR_FAIL;
					continue;
				}
				if (do_cpu(pset, cpu, pflag, 1))
					errors = ERR_FAIL;
			} else {
				/* range of processors */
				processorid_t first, last;

				first = (processorid_t)
				    strtol(*argv, &errptr, 10);
				if (*errptr++ != '-') {
					warn(gettext(
					    "invalid processor range %s\n"),
					    *argv);
					errors = ERR_USAGE;
					continue;
				}
				last = (processorid_t)
				    strtol(errptr, &errptr, 10);
				if ((errptr != NULL && *errptr != '\0') ||
				    last < first || first < 0) {
					warn(gettext(
					    "invalid processor range %s\n"),
					    *argv);
					errors = ERR_USAGE;
					continue;
				}
				if (do_range(pset, first, last, pflag))
					errors = ERR_FAIL;
			}
		}
	} else if (bflag || uflag || qflag) {
		/*
		 * Perform function for each pid/lwpid specified.
		 */
		if (argc == 0 && !zflag) {
			warn(gettext("must specify at least one pid\n"));
			return (usage());
		} else if (argc > 0 && zflag) {
			warn(gettext("cannot specify extra pids with -z\n"));
			return (usage());
		}

		if (zflag) {
			zid = getzoneidbyname(zname);
			if (zid < 0) {
				warn(gettext("invalid zone name: %s\n"),
				    zname);
				errors = ERR_FAIL;
			} else if (pset_bind(pset, P_ZONEID, zid,
			    &old_pset) < 0) {
				bind_err(pset, zname, -1, -1, errno);
				errors = ERR_FAIL;
			} else {
				(void) printf(gettext("zone %s: bound to %d\n"),
				    zname, pset);
			}
		}

		/*
		 * Go through listed processes/lwp_ranges.
		 */
		for (; argc > 0; argv++, argc--) {
			pid = (id_t)strtol(*argv, &errptr, 10);
			if (errno != 0 ||
			    (errptr != NULL && *errptr != '\0' &&
			    *errptr != '/')) {
				warn(gettext("invalid process ID: %s\n"),
				    *argv);
				continue;
			}
			if (errptr != NULL && *errptr == '/') {
				int ret;
				/*
				 * Handle lwp range case
				 */
				const char *lwps = (const char *)(++errptr);
				if (*lwps == '\0' ||
				    proc_lwp_range_valid(lwps) != 0) {
					warn(gettext("invalid lwp range "
					    "for pid %d\n"), (int)pid);
					errors = ERR_FAIL;
					continue;
				}
				if (!qflag)
					(void) proc_initstdio();
				ret = do_lwps(pid, lwps, pset);
				if (!qflag)
					(void) proc_finistdio();
				if (ret != ERR_OK)
					errors = ret;
			} else {
				/*
				 * Handle whole process case.
				 */
				if (pset_bind(pset, P_PID, pid,
				    &old_pset) < 0) {
					bind_err(pset, NULL, pid, -1, errno);
					errors = ERR_FAIL;
					continue;
				}
				if (qflag)
					query_out(pid, -1, old_pset);
				else
					bind_out(pid, -1, old_pset, pset);
			}
		}
	}

	if (Qflag || Uflag) {
		/*
		 * Go through listed processor set IDs.
		 */
		for (; argc > 0; argv++, argc--) {
			errno = 0;
			pset = (id_t)strtol(*argv, &errptr, 10);
			if (errno != 0 ||
			    (errptr != NULL && *errptr != '\0')) {
				warn(gettext("invalid processor set ID\n"));
				continue;
			}
			if (Qflag) {
				(void) proc_walk(query_all_lwp,
				    &pset, PR_WALK_LWP);
				continue;
			}
			if (Uflag) {
				if (pset_bind(PS_NONE, P_PSETID, pset,
				    &old_pset) != 0) {
					warn(gettext("failed to unbind from "
					    "processor set %d"), (int)pset);
					errors = ERR_FAIL;
				}
				continue;
			}
		}
	}

	return (errors);
}
