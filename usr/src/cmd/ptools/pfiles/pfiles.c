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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 */
/*
 * Copyright (c) 2017 Joyent, Inc.  All Rights reserved.
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2024 Oxide Computer Company
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <limits.h>
#include <door.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/stropts.h>
#include <sys/timod.h>
#include <sys/file.h>
#include <sys/un.h>
#include <libproc.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ucred.h>
#include <zone.h>

static char *command;
static volatile int interrupt;
static int Fflag;
static boolean_t nflag = B_FALSE;

static	void	intr(int);
static	void	dofcntl(struct ps_prochandle *, const prfdinfo_t *, int, int);
static	void	dosocket(struct ps_prochandle *, const prfdinfo_t *);
static	void	dosocknames(struct ps_prochandle *, const prfdinfo_t *);
static	void	dofifo(struct ps_prochandle *, const prfdinfo_t *);
static	void	show_files(struct ps_prochandle *);
static	void	show_fileflags(int);
static	void	show_door(struct ps_prochandle *, const prfdinfo_t *);

int
main(int argc, char **argv)
{
	int retc = 0;
	int opt;
	int errflg = 0;
	struct ps_prochandle *Pr;

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	/* options */
	while ((opt = getopt(argc, argv, "Fn")) != EOF) {
		switch (opt) {
		case 'F':		/* force grabbing (no O_EXCL) */
			Fflag = PGRAB_FORCE;
			break;
		case 'n':
			nflag = B_TRUE;
			break;
		default:
			errflg = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (errflg || argc <= 0) {
		(void) fprintf(stderr, "usage:\t%s [-F] { pid | core } ...\n",
		    command);
		(void) fprintf(stderr,
		    "  (report open files of each process)\n");
		(void) fprintf(stderr,
		    "  -F: force grabbing of the target process\n");
		exit(2);
	}

	/* catch signals from terminal */
	if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGHUP, intr);
	if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGINT, intr);
	if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGQUIT, intr);
	(void) sigset(SIGPIPE, intr);
	(void) sigset(SIGTERM, intr);

	(void) proc_initstdio();


	while (--argc >= 0 && !interrupt) {
		char *arg;
		psinfo_t psinfo;
		pid_t pid;
		int gret;

		(void) proc_flushstdio();

		arg = *argv++;

		/* get the specified pid and the psinfo struct */
		if ((pid = proc_arg_psinfo(arg, PR_ARG_PIDS,
		    &psinfo, &gret)) == -1) {

			if ((Pr = proc_arg_xgrab(arg, NULL, PR_ARG_CORES,
			    Fflag, &gret, NULL)) == NULL) {
				(void) fprintf(stderr,
				    "%s: cannot examine %s: %s\n",
				    command, arg, Pgrab_error(gret));
				retc++;
				continue;
			}
			if (proc_arg_psinfo(arg, PR_ARG_ANY, &psinfo,
			    &gret) < 0) {
				(void) fprintf(stderr,
				    "%s: cannot examine %s: %s\n",
				    command, arg, Pgrab_error(gret));
				retc++;
				Prelease(Pr, 0);
				continue;
			}
			(void) printf("core '%s' of %d:\t%.70s\n",
			    arg, (int)psinfo.pr_pid, psinfo.pr_psargs);

			show_files(Pr);
			Prelease(Pr, 0);

		} else if ((Pr = Pgrab(pid, Fflag, &gret)) != NULL) {
			if (Pcreate_agent(Pr) == 0) {
				proc_unctrl_psinfo(&psinfo);
				(void) printf("%d:\t%.70s\n",
				    (int)pid, psinfo.pr_psargs);
				show_files(Pr);
				Pdestroy_agent(Pr);
			} else {
				(void) fprintf(stderr,
				    "%s: cannot control process %d\n",
				    command, (int)pid);
				retc++;
			}
			Prelease(Pr, 0);
			Pr = NULL;
		} else {
			switch (gret) {
			case G_SYS:
				proc_unctrl_psinfo(&psinfo);
				(void) printf("%d:\t%.70s\n", (int)pid,
				    psinfo.pr_psargs);
				(void) printf("  [system process]\n");
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %d\n",
				    command, Pgrab_error(gret), (int)pid);
				retc++;
				break;
			}
		}
	}

	(void) proc_finistdio();

	if (interrupt && retc == 0)
		retc++;
	return (retc);
}

/* ARGSUSED */
static void
intr(int sig)
{
	interrupt = 1;
}

/* ------ begin specific code ------ */

static int
show_paths(uint_t type, const void *data, size_t len, void *arg __unused)
{
	if (type == PR_PATHNAME)
		(void) printf("      %.*s\n", len, data);
	return (0);
}

static int
show_file(void *data, const prfdinfo_t *info)
{
	struct ps_prochandle *Pr = data;
	char unknown[12];
	char *s;
	mode_t mode;

	if (interrupt)
		return (1);

	mode = info->pr_mode;

	switch (mode & S_IFMT) {
	case S_IFCHR: s = "S_IFCHR"; break;
	case S_IFBLK: s = "S_IFBLK"; break;
	case S_IFIFO: s = "S_IFIFO"; break;
	case S_IFDIR: s = "S_IFDIR"; break;
	case S_IFREG: s = "S_IFREG"; break;
	case S_IFLNK: s = "S_IFLNK"; break;
	case S_IFSOCK: s = "S_IFSOCK"; break;
	case S_IFDOOR: s = "S_IFDOOR"; break;
	case S_IFPORT: s = "S_IFPORT"; break;
	default:
		s = unknown;
		(void) sprintf(s, "0x%.4x ", (int)mode & S_IFMT);
		break;
	}

	(void) printf("%4d: %s mode:0%.3o", info->pr_fd, s,
	    (int)mode & ~S_IFMT);

	(void) printf(" dev:%u,%u",
	    (unsigned)info->pr_major, (unsigned)info->pr_minor);

	if ((mode & S_IFMT) == S_IFPORT) {
		(void) printf(" uid:%d gid:%d",
		    (int)info->pr_uid, (int)info->pr_gid);
		(void) printf(" size:%lld\n", (longlong_t)info->pr_size);
		return (0);
	}

	(void) printf(" ino:%llu uid:%d gid:%d",
	    (u_longlong_t)info->pr_ino, (int)info->pr_uid, (int)info->pr_gid);

	if ((info->pr_rmajor == (major_t)NODEV) &&
	    (info->pr_rminor == (minor_t)NODEV))
		(void) printf(" size:%lld\n", (longlong_t)info->pr_size);
	else
		(void) printf(" rdev:%u,%u\n",
		    (unsigned)info->pr_rmajor, (unsigned)info->pr_rminor);

	if (!nflag) {
		dofcntl(Pr, info,
		    (mode & (S_IFMT|S_ENFMT|S_IXGRP)) == (S_IFREG|S_ENFMT),
		    (mode & S_IFMT) == S_IFDOOR);

		if (Pstate(Pr) != PS_DEAD) {
			switch (mode & S_IFMT) {
			case S_IFSOCK:
				dosocket(Pr, info);
				break;
			case S_IFIFO:
				dofifo(Pr, info);
				break;
			case S_IFCHR:
				/*
				 * This may be a TLI endpoint. If so, it will
				 * have socket names in the fdinfo and this
				 * will print them.
				 */
				dosocknames(Pr, info);
				break;
			}
		}

		(void) proc_fdinfowalk(info, show_paths, NULL);

		if (info->pr_offset != -1) {
			(void) printf("      offset:%lld\n",
			    (long long)info->pr_offset);
		}
	}

	return (0);
}

static void
show_files(struct ps_prochandle *Pr)
{
	struct rlimit rlim;

	if (pr_getrlimit(Pr, RLIMIT_NOFILE, &rlim) == 0) {
		ulong_t nfd = rlim.rlim_cur;
		if (nfd == RLIM_INFINITY)
			(void) printf(
			    "  Current rlimit: unlimited file descriptors\n");
		else
			(void) printf(
			    "  Current rlimit: %lu file descriptors\n", nfd);
	}

	(void) Pfdinfo_iter(Pr, show_file, Pr);
}

static void
show_fdflags(int fdflags)
{
	if (fdflags <= 0)
		return;

	/*
	 * show_fileflags() already has printed content here. We translate these
	 * back to the O_ versions for consistency with the flags that were
	 * already printed.
	 */
	if ((fdflags & FD_CLOEXEC) != 0) {
		(void) printf("|O_CLOEXEC");
	}

	if ((fdflags & FD_CLOFORK) != 0) {
		(void) printf("|O_CLOFORK");
	}
}

/* examine open file with fcntl() */
static void
dofcntl(struct ps_prochandle *Pr, const prfdinfo_t *info, int mandatory,
    int isdoor)
{
	int fileflags;
	int fdflags;

	fileflags = info->pr_fileflags;
	fdflags = info->pr_fdflags;

	if (fileflags != -1 || fdflags != -1) {
		(void) printf("      ");
		if (fileflags != -1)
			show_fileflags(fileflags);
		if (fdflags != -1)
			show_fdflags(fdflags);
		if (isdoor && (Pstate(Pr) != PS_DEAD))
			show_door(Pr, info);
		(void) fputc('\n', stdout);
	} else if (isdoor && (Pstate(Pr) != PS_DEAD)) {
		(void) printf("    ");
		show_door(Pr, info);
		(void) fputc('\n', stdout);
	}

	if (Pstate(Pr) != PS_DEAD) {
		if (info->pr_locktype != F_UNLCK &&
		    (info->pr_locksysid != -1 || info->pr_lockpid != -1)) {
			unsigned long sysid = info->pr_locksysid;

			(void) printf("      %s %s lock set",
			    mandatory ? "mandatory" : "advisory",
			    info->pr_locktype == F_RDLCK? "read" : "write");
			if (sysid)
				(void) printf(" by system 0x%lX", sysid);
			if (info->pr_lockpid != -1)
				(void) printf(" by process %d",
				    (int)info->pr_lockpid);
			(void) fputc('\n', stdout);
		}
	}
}

#define	ALL_O_FLAGS	O_ACCMODE | O_NDELAY | O_NONBLOCK | O_APPEND | \
			O_SYNC | O_DSYNC | O_RSYNC | O_XATTR | \
			O_CREAT | O_TRUNC | O_EXCL | O_NOCTTY | O_LARGEFILE | \
			__FLXPATH

static void
show_fileflags(int flags)
{
	char buffer[147];
	char *str = buffer;

	switch (flags & O_ACCMODE) {
	case O_RDONLY:
		(void) strcpy(str, "O_RDONLY");
		break;
	case O_WRONLY:
		(void) strcpy(str, "O_WRONLY");
		break;
	case O_RDWR:
		(void) strcpy(str, "O_RDWR");
		break;
	case O_SEARCH:
		(void) strcpy(str, "O_SEARCH");
		break;
	case O_EXEC:
		(void) strcpy(str, "O_EXEC");
		break;
	default:
		(void) sprintf(str, "0x%x", flags & O_ACCMODE);
		break;
	}

	if (flags & O_NDELAY)
		(void) strcat(str, "|O_NDELAY");
	if (flags & O_NONBLOCK)
		(void) strcat(str, "|O_NONBLOCK");
	if (flags & O_APPEND)
		(void) strcat(str, "|O_APPEND");
	if (flags & O_SYNC)
		(void) strcat(str, "|O_SYNC");
	if (flags & O_DSYNC)
		(void) strcat(str, "|O_DSYNC");
	if (flags & O_RSYNC)
		(void) strcat(str, "|O_RSYNC");
	if (flags & O_CREAT)
		(void) strcat(str, "|O_CREAT");
	if (flags & O_TRUNC)
		(void) strcat(str, "|O_TRUNC");
	if (flags & O_EXCL)
		(void) strcat(str, "|O_EXCL");
	if (flags & O_NOCTTY)
		(void) strcat(str, "|O_NOCTTY");
	if (flags & O_LARGEFILE)
		(void) strcat(str, "|O_LARGEFILE");
	if (flags & O_XATTR)
		(void) strcat(str, "|O_XATTR");
	if (flags & __FLXPATH)
		(void) strcat(str, "|__FLXPATH");
	if (flags & ~(ALL_O_FLAGS))
		(void) sprintf(str + strlen(str), "|0x%x",
		    flags & ~(ALL_O_FLAGS));

	(void) printf("%s", str);
}

/* show process on the other end of a door, socket or fifo */
static void
show_peer_process(pid_t ppid)
{
	psinfo_t psinfo;

	if (proc_get_psinfo(ppid, &psinfo) == 0)
		(void) printf(" %s[%d]", psinfo.pr_fname, (int)ppid);
	else
		(void) printf(" pid %d", (int)ppid);
}

/* show door info */
static void
show_door(struct ps_prochandle *Pr, const prfdinfo_t *info)
{
	door_info_t door_info;

	if (pr_door_info(Pr, info->pr_fd, &door_info) != 0)
		return;

	(void) printf("  door to");
	show_peer_process(door_info.di_target);
}

/*
 * Print out the socket address pointed to by `sa'.  `len' is only
 * needed for AF_UNIX sockets.
 */
static void
show_sockaddr(const char *str, const struct sockaddr *sa, socklen_t len)
{
	struct sockaddr_in *so_in = (struct sockaddr_in *)(void *)sa;
	struct sockaddr_in6 *so_in6 = (struct sockaddr_in6 *)(void *)sa;
	struct sockaddr_un *so_un = (struct sockaddr_un *)sa;
	char  abuf[INET6_ADDRSTRLEN];
	const char *p;

	if (len == 0)
		return;

	switch (sa->sa_family) {
	default:
		return;
	case AF_INET:
		(void) printf("\t%s: AF_INET %s  port: %u\n", str,
		    inet_ntop(AF_INET, &so_in->sin_addr, abuf, sizeof (abuf)),
		    ntohs(so_in->sin_port));
		return;
	case AF_INET6:
		(void) printf("\t%s: AF_INET6 %s  port: %u\n", str,
		    inet_ntop(AF_INET6, &so_in6->sin6_addr,
		    abuf, sizeof (abuf)),
		    ntohs(so_in->sin_port));
		return;
	case AF_UNIX:
		if (len >= sizeof (so_un->sun_family)) {
			(void) printf("\t%s: AF_UNIX %.*s\n",
			    str, len - sizeof (so_un->sun_family),
			    so_un->sun_path);
		}
		return;
	case AF_IMPLINK:	p = "AF_IMPLINK";	break;
	case AF_PUP:		p = "AF_PUP";		break;
	case AF_CHAOS:		p = "AF_CHAOS";		break;
	case AF_NS:		p = "AF_NS";		break;
	case AF_NBS:		p = "AF_NBS";		break;
	case AF_ECMA:		p = "AF_ECMA";		break;
	case AF_DATAKIT:	p = "AF_DATAKIT";	break;
	case AF_CCITT:		p = "AF_CCITT";		break;
	case AF_SNA:		p = "AF_SNA";		break;
	case AF_DECnet:		p = "AF_DECnet";	break;
	case AF_DLI:		p = "AF_DLI";		break;
	case AF_LAT:		p = "AF_LAT";		break;
	case AF_HYLINK:		p = "AF_HYLINK";	break;
	case AF_APPLETALK:	p = "AF_APPLETALK";	break;
	case AF_NIT:		p = "AF_NIT";		break;
	case AF_802:		p = "AF_802";		break;
	case AF_OSI:		p = "AF_OSI";		break;
	case AF_X25:		p = "AF_X25";		break;
	case AF_OSINET:		p = "AF_OSINET";	break;
	case AF_GOSIP:		p = "AF_GOSIP";		break;
	case AF_IPX:		p = "AF_IPX";		break;
	case AF_ROUTE:		p = "AF_ROUTE";		break;
	case AF_KEY:		p = "AF_KEY";		break;
	case AF_POLICY:		p = "AF_POLICY";	break;
	case AF_LINK:		p = "AF_LINK";		break;
	case AF_LX_NETLINK:	p = "AF_LX_NETLINK";	break;
	}

	(void) printf("\t%s: %s\n", str, p);
}

/*
 * Print out the process information for the other end of local sockets
 * and fifos
 */
static void
show_ucred(const char *str, ucred_t *cred)
{
	pid_t upid = ucred_getpid(cred);
	zoneid_t uzid = ucred_getzoneid(cred);
	char zonename[ZONENAME_MAX];

	if ((upid != -1) || (uzid != -1)) {
		(void) printf("\t%s:", str);
		if (upid != -1) {
			show_peer_process(upid);
		}
		if (uzid != -1) {
			if (getzonenamebyid(uzid, zonename, sizeof (zonename))
			    != -1) {
				(void) printf(" zone: %s[%d]", zonename,
				    (int)uzid);
			} else {
				(void) printf(" zoneid: %d", (int)uzid);
			}
		}
		(void) printf("\n");
	}
}

static void
show_socktype(uint_t type)
{
	static const char *types[] = {
		NULL, "DGRAM", "STREAM", NULL, "RAW", "RDM", "SEQPACKET"
	};

	if (type < sizeof (types) / sizeof (*types) && types[type] != NULL)
		(void) printf("\tSOCK_%s\n", types[type]);
	else
		(void) printf("\tunknown socket type %u\n", type);
}

#define	BUFSIZE	200
static void
show_sockopts(struct ps_prochandle *Pr, const prfdinfo_t *info)
{
	const int *val;
	size_t vlen;
	char buf[BUFSIZE];
	char buf1[32];
	char ipaddr[INET_ADDRSTRLEN];
	int i;
	const in_addr_t *nexthop_val;
	const prsockopts_bool_opts_t *opts;
	struct boolopt {
		int		opt;
		const char	*name;
	};
	static struct boolopt boolopts[] = {
	    { PR_SO_DEBUG,		"SO_DEBUG,"	},
	    { PR_SO_REUSEADDR,		"SO_REUSEADDR,"	},
	    { PR_SO_KEEPALIVE,		"SO_KEEPALIVE,"	},
	    { PR_SO_DONTROUTE,		"SO_DONTROUTE,"	},
	    { PR_SO_BROADCAST,		"SO_BROADCAST,"	},
	    { PR_SO_OOBINLINE,		"SO_OOBINLINE,"	},
	    { PR_SO_DGRAM_ERRIND,	"SO_DGRAM_ERRIND,"},
	    { PR_SO_ALLZONES,		"SO_ALLZONES,"	},
	    { PR_SO_MAC_EXEMPT,		"SO_MAC_EXEMPT," },
	    { PR_SO_MAC_IMPLICIT,	"SO_MAC_IMPLICIT," },
	    { PR_SO_EXCLBIND,		"SO_EXCLBIND," },
	    { PR_SO_VRRP,		"SO_VRRP," },
	    { PR_UDP_NAT_T_ENDPOINT,	"UDP_NAT_T_ENDPOINT," },
	};
	const struct linger *l;

	opts = proc_fdinfo_misc(info, PR_SOCKOPTS_BOOL_OPTS, NULL);

	buf[0] = '!';		/* sentinel value, never printed */
	buf[1] = '\0';

	for (i = 0; i < sizeof (boolopts) / sizeof (boolopts[0]); i++) {
		if (opts != NULL && opts->prsock_bool_opts & boolopts[i].opt)
			(void) strlcat(buf, boolopts[i].name, sizeof (buf));
	}

	l = proc_fdinfo_misc(info, PR_SOCKOPT_LINGER, NULL);
	if (l != NULL && l->l_onoff != 0) {
		(void) snprintf(buf1, sizeof (buf1), "SO_LINGER(%d),",
		    l->l_linger);
		(void) strlcat(buf, buf1, sizeof (buf));
	}

	val = proc_fdinfo_misc(info, PR_SOCKOPT_SNDBUF, NULL);
	if (val != NULL) {
		(void) snprintf(buf1, sizeof (buf1), "SO_SNDBUF(%d),", *val);
		(void) strlcat(buf, buf1, sizeof (buf));
	}

	val = proc_fdinfo_misc(info, PR_SOCKOPT_RCVBUF, NULL);
	if (val != NULL) {
		(void) snprintf(buf1, sizeof (buf1), "SO_RCVBUF(%d),", *val);
		(void) strlcat(buf, buf1, sizeof (buf));
	}


	nexthop_val = proc_fdinfo_misc(info, PR_SOCKOPT_IP_NEXTHOP, &vlen);
	if (nexthop_val != NULL && vlen > 0) {
		(void) inet_ntop(AF_INET, (void *) nexthop_val,
		    ipaddr, sizeof (ipaddr));
		(void) snprintf(buf1, sizeof (buf1), "IP_NEXTHOP(%s),",
		    ipaddr);
		(void) strlcat(buf, buf1, sizeof (buf));
	}

	buf[strlen(buf) - 1] = '\0'; /* overwrites sentinel if no options */
	if (buf[1] != '\0')
		(void) printf("\t%s\n", buf+1);
}

#define	MAXNALLOC	32
static void
show_sockfilters(struct ps_prochandle *Pr, const prfdinfo_t *info)
{
	struct fil_info *fi;
	int i = 0, nalloc = 2, len = nalloc * sizeof (*fi);
	boolean_t printhdr = B_TRUE;
	int fd = info->pr_fd;

	fi = calloc(nalloc, sizeof (*fi));
	if (fi == NULL) {
		perror("calloc");
		return;
	}
	/* CONSTCOND */
	while (1) {
		if (pr_getsockopt(Pr, fd, SOL_FILTER, FIL_LIST, fi, &len) != 0)
			break;
		/* No filters */
		if (len == 0)
			break;
		/* Make sure buffer was large enough */
		if (fi->fi_pos >= nalloc) {
			struct fil_info *new;

			nalloc = fi->fi_pos + 1;
			if (nalloc > MAXNALLOC)
				break;
			len = nalloc * sizeof (*fi);
			new = realloc(fi, nalloc * sizeof (*fi));
			if (new == NULL) {
				perror("realloc");
				break;
			}
			fi = new;
			continue;
		}

		for (i = 0; (i + 1) * sizeof (*fi) <= len; i++) {
			if (fi[i].fi_flags & FILF_BYPASS)
				continue;
			if (printhdr) {
				(void) printf("\tfilters: ");
				printhdr = B_FALSE;
			}
			(void) printf("%s", fi[i].fi_name);
			if (fi[i].fi_flags != 0) {
				(void) printf("(");
				if (fi[i].fi_flags & FILF_AUTO)
					(void) printf("auto,");
				if (fi[i].fi_flags & FILF_PROG)
					(void) printf("prog,");
				(void) printf("\b)");
			}
			if (fi[i].fi_pos == 0) /* last one */
				break;
			(void) printf(",");
		}
		if (!printhdr)
			(void) printf("\n");
		break;
	}
	free(fi);
}

/* print peer credentials for sockets and named pipes */
static void
dopeerucred(struct ps_prochandle *Pr, const prfdinfo_t *info)
{
	ucred_t *peercred = NULL;	/* allocated by getpeerucred */

	if (pr_getpeerucred(Pr, info->pr_fd, &peercred) == 0) {
		show_ucred("peer", peercred);
		ucred_free(peercred);
	}
}

static void
dosocknames(struct ps_prochandle *Pr, const prfdinfo_t *info)
{
	const struct sockaddr *sa;
	size_t vlen;

	sa = proc_fdinfo_misc(info, PR_SOCKETNAME, &vlen);
	if (sa != NULL)
		show_sockaddr("sockname", sa, vlen);

	sa = proc_fdinfo_misc(info, PR_PEERSOCKNAME, &vlen);
	if (sa != NULL)
		show_sockaddr("peername", sa, vlen);
}

/* the file is a socket */
static void
dosocket(struct ps_prochandle *Pr, const prfdinfo_t *info)
{
	const int *type;

	type = proc_fdinfo_misc(info, PR_SOCKOPT_TYPE, NULL);
	if (type != NULL)
		show_socktype((uint_t)*type);

	show_sockopts(Pr, info);
	show_sockfilters(Pr, info);
	dosocknames(Pr, info);
	dopeerucred(Pr, info);
}

/* the file is a fifo (aka "named pipe") */
static void
dofifo(struct ps_prochandle *Pr, const prfdinfo_t *info)
{
	dopeerucred(Pr, info);
}
