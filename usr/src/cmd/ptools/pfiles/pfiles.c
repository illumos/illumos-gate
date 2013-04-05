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
 * Copyright (c) 2013 Joyent, Inc.  All Rights reserved.
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
#include <sys/un.h>
#include <libproc.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ucred.h>
#include <zone.h>

#define	copyflock(dst, src) \
	(dst).l_type = (src).l_type;		\
	(dst).l_whence = (src).l_whence;	\
	(dst).l_start = (src).l_start;		\
	(dst).l_len = (src).l_len;		\
	(dst).l_sysid = (src).l_sysid;		\
	(dst).l_pid = (src).l_pid;

static char *command;
static volatile int interrupt;
static int Fflag;
static boolean_t nflag = B_FALSE;

static	void	intr(int);
static	void	dofcntl(struct ps_prochandle *, prfdinfo_t *, int, int);
static	void	dosocket(struct ps_prochandle *, int);
static	void	dofifo(struct ps_prochandle *, int);
static	void	dotli(struct ps_prochandle *, int);
static	void	show_files(struct ps_prochandle *);
static	void	show_fileflags(int);
static	void	show_door(struct ps_prochandle *, int);
static	int	getflock(struct ps_prochandle *, int, struct flock *);

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
show_file(void *data, prfdinfo_t *info)
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
			char *dev;

			if ((mode & S_IFMT) == S_IFSOCK)
				dosocket(Pr, info->pr_fd);
			else if ((mode & S_IFMT) == S_IFIFO)
				dofifo(Pr, info->pr_fd);

			if ((mode & S_IFMT) == S_IFCHR &&
			    (dev = strrchr(info->pr_path, ':')) != NULL) {
				/*
				 * There's no elegant way to determine
				 * if a character device supports TLI,
				 * so we lame out and just check a
				 * hardcoded list of known TLI devices.
				 */
				int i;
				const char *tlidevs[] = {
				    "tcp", "tcp6", "udp", "udp6", NULL
				};

				dev++; /* skip past the `:' */
				for (i = 0; tlidevs[i] != NULL; i++) {
					if (strcmp(dev, tlidevs[i]) == 0) {
						dotli(Pr, info->pr_fd);
						break;
					}
				}
			}
		}

		if (info->pr_path[0] != '\0')
			(void) printf("      %s\n", info->pr_path);

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


static int
getflock(struct ps_prochandle *Pr, int fd, struct flock *flock_native)
{
	int ret;
#ifdef _LP64
	struct flock64_32 flock_target;

	if (Pstatus(Pr)->pr_dmodel == PR_MODEL_ILP32) {
		copyflock(flock_target, *flock_native);
		ret = pr_fcntl(Pr, fd, F_GETLK, &flock_target);
		copyflock(*flock_native, flock_target);
		return (ret);
	}
#endif /* _LP64 */
	ret = pr_fcntl(Pr, fd, F_GETLK, flock_native);
	return (ret);
}

/* examine open file with fcntl() */
static void
dofcntl(struct ps_prochandle *Pr, prfdinfo_t *info, int mandatory, int isdoor)
{
	struct flock flock;
	int fileflags;
	int fdflags;
	int fd;

	fd = info->pr_fd;

	fileflags = info->pr_fileflags;
	fdflags = info->pr_fdflags;

	if (fileflags != -1 || fdflags != -1) {
		(void) printf("      ");
		if (fileflags != -1)
			show_fileflags(fileflags);
		if (fdflags != -1 && (fdflags & FD_CLOEXEC))
			(void) printf(" FD_CLOEXEC");
		if (isdoor && (Pstate(Pr) != PS_DEAD))
			show_door(Pr, fd);
		(void) fputc('\n', stdout);
	} else if (isdoor && (Pstate(Pr) != PS_DEAD)) {
		(void) printf("    ");
		show_door(Pr, fd);
		(void) fputc('\n', stdout);
	}

	flock.l_type = F_WRLCK;
	flock.l_whence = 0;
	flock.l_start = 0;
	flock.l_len = 0;
	flock.l_sysid = 0;
	flock.l_pid = 0;
	if ((Pstate(Pr) != PS_DEAD) && (getflock(Pr, fd, &flock) != -1)) {
		if (flock.l_type != F_UNLCK && (flock.l_sysid || flock.l_pid)) {
			unsigned long sysid = flock.l_sysid;

			(void) printf("      %s %s lock set by",
			    mandatory ? "mandatory" : "advisory",
			    flock.l_type == F_RDLCK? "read" : "write");
			if (sysid)
				(void) printf(" system 0x%lX", sysid);
			if (flock.l_pid)
				(void) printf(" process %d", (int)flock.l_pid);
			(void) fputc('\n', stdout);
		}
	}
}

#define	ALL_O_FLAGS	O_ACCMODE | O_NDELAY | O_NONBLOCK | O_APPEND | \
			O_SYNC | O_DSYNC | O_RSYNC | O_XATTR | \
			O_CREAT | O_TRUNC | O_EXCL | O_NOCTTY | O_LARGEFILE

static void
show_fileflags(int flags)
{
	char buffer[136];
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
show_door(struct ps_prochandle *Pr, int fd)
{
	door_info_t door_info;

	if (pr_door_info(Pr, fd, &door_info) != 0)
		return;

	(void) printf("  door to");
	show_peer_process(door_info.di_target);
}

/*
 * Print out the socket address pointed to by `sa'.  `len' is only
 * needed for AF_UNIX sockets.
 */
static void
show_sockaddr(const char *str, struct sockaddr *sa, socklen_t len)
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
			/* Null terminate */
			len -= sizeof (so_un->sun_family);
			so_un->sun_path[len] = '\0';
			(void) printf("\t%s: AF_UNIX %s\n",
			    str, so_un->sun_path);
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
	case AF_LINK:		p = "AF_LINK";		break;
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
show_sockopts(struct ps_prochandle *Pr, int fd)
{
	int val, vlen;
	char buf[BUFSIZE];
	char buf1[32];
	char ipaddr[INET_ADDRSTRLEN];
	int i;
	in_addr_t nexthop_val;
	struct boolopt {
		int		level;
		int		opt;
		const char	*name;
	};
	static struct boolopt boolopts[] = {
	    { SOL_SOCKET, SO_DEBUG,		"SO_DEBUG,"	},
	    { SOL_SOCKET, SO_REUSEADDR,		"SO_REUSEADDR,"	},
	    { SOL_SOCKET, SO_KEEPALIVE,		"SO_KEEPALIVE,"	},
	    { SOL_SOCKET, SO_DONTROUTE,		"SO_DONTROUTE,"	},
	    { SOL_SOCKET, SO_BROADCAST,		"SO_BROADCAST,"	},
	    { SOL_SOCKET, SO_OOBINLINE,		"SO_OOBINLINE,"	},
	    { SOL_SOCKET, SO_DGRAM_ERRIND,	"SO_DGRAM_ERRIND,"},
	    { SOL_SOCKET, SO_ALLZONES,		"SO_ALLZONES,"	},
	    { SOL_SOCKET, SO_MAC_EXEMPT,	"SO_MAC_EXEMPT," },
	    { SOL_SOCKET, SO_MAC_IMPLICIT,	"SO_MAC_IMPLICIT," },
	    { SOL_SOCKET, SO_EXCLBIND,		"SO_EXCLBIND," },
	    { SOL_SOCKET, SO_VRRP,		"SO_VRRP," },
	    { IPPROTO_UDP, UDP_NAT_T_ENDPOINT,	"UDP_NAT_T_ENDPOINT," },
	};
	struct linger l;

	buf[0] = '!';		/* sentinel value, never printed */
	buf[1] = '\0';

	for (i = 0; i < sizeof (boolopts) / sizeof (boolopts[0]); i++) {
		vlen = sizeof (val);
		if (pr_getsockopt(Pr, fd, boolopts[i].level, boolopts[i].opt,
		    &val, &vlen) == 0 && val != 0)
			(void) strlcat(buf, boolopts[i].name, sizeof (buf));
	}

	vlen = sizeof (l);
	if (pr_getsockopt(Pr, fd, SOL_SOCKET, SO_LINGER, &l, &vlen) == 0 &&
	    l.l_onoff != 0) {
		(void) snprintf(buf1, sizeof (buf1), "SO_LINGER(%d),",
		    l.l_linger);
		(void) strlcat(buf, buf1, sizeof (buf));
	}

	vlen = sizeof (val);
	if (pr_getsockopt(Pr, fd, SOL_SOCKET, SO_SNDBUF, &val, &vlen) == 0) {
		(void) snprintf(buf1, sizeof (buf1), "SO_SNDBUF(%d),", val);
		(void) strlcat(buf, buf1, sizeof (buf));
	}
	vlen = sizeof (val);
	if (pr_getsockopt(Pr, fd, SOL_SOCKET, SO_RCVBUF, &val, &vlen) == 0) {
		(void) snprintf(buf1, sizeof (buf1), "SO_RCVBUF(%d),", val);
		(void) strlcat(buf, buf1, sizeof (buf));
	}
	vlen = sizeof (nexthop_val);
	if (pr_getsockopt(Pr, fd, IPPROTO_IP, IP_NEXTHOP, &nexthop_val,
	    &vlen) == 0) {
		if (vlen > 0) {
			(void) inet_ntop(AF_INET, (void *) &nexthop_val,
			    ipaddr, sizeof (ipaddr));
			(void) snprintf(buf1, sizeof (buf1), "IP_NEXTHOP(%s),",
			    ipaddr);
			(void) strlcat(buf, buf1, sizeof (buf));
		}
	}

	buf[strlen(buf) - 1] = '\0'; /* overwrites sentinel if no options */
	if (buf[1] != '\0')
		(void) printf("\t%s\n", buf+1);
}

#define	MAXNALLOC	32
static void
show_sockfilters(struct ps_prochandle *Pr, int fd)
{
	struct fil_info *fi;
	int i = 0, nalloc = 2, len = nalloc * sizeof (*fi);
	boolean_t printhdr = B_TRUE;

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
dopeerucred(struct ps_prochandle *Pr, int fd)
{
	ucred_t *peercred = NULL;	/* allocated by getpeerucred */

	if (pr_getpeerucred(Pr, fd, &peercred) == 0) {
		show_ucred("peer", peercred);
		ucred_free(peercred);
	}
}

/* the file is a socket */
static void
dosocket(struct ps_prochandle *Pr, int fd)
{
	/* A buffer large enough for PATH_MAX size AF_UNIX address */
	long buf[(sizeof (short) + PATH_MAX + sizeof (long) - 1)
	    / sizeof (long)];
	struct sockaddr *sa = (struct sockaddr *)buf;
	socklen_t len;
	int type, tlen;

	tlen = sizeof (type);
	if (pr_getsockopt(Pr, fd, SOL_SOCKET, SO_TYPE, &type, &tlen) == 0)
		show_socktype((uint_t)type);

	show_sockopts(Pr, fd);
	show_sockfilters(Pr, fd);

	len = sizeof (buf);
	if (pr_getsockname(Pr, fd, sa, &len) == 0)
		show_sockaddr("sockname", sa, len);

	len = sizeof (buf);
	if (pr_getpeername(Pr, fd, sa, &len) == 0)
		show_sockaddr("peername", sa, len);

	dopeerucred(Pr, fd);
}

/* the file is a fifo (aka "named pipe") */
static void
dofifo(struct ps_prochandle *Pr, int fd)
{
	dopeerucred(Pr, fd);
}

/* the file is a TLI endpoint */
static void
dotli(struct ps_prochandle *Pr, int fd)
{
	struct strcmd strcmd;

	strcmd.sc_len = STRCMDBUFSIZE;
	strcmd.sc_timeout = 5;

	strcmd.sc_cmd = TI_GETMYNAME;
	if (pr_ioctl(Pr, fd, _I_CMD, &strcmd, sizeof (strcmd)) == 0)
		show_sockaddr("sockname", (void *)&strcmd.sc_buf, 0);

	strcmd.sc_cmd = TI_GETPEERNAME;
	if (pr_ioctl(Pr, fd, _I_CMD, &strcmd, sizeof (strcmd)) == 0)
		show_sockaddr("peername", (void *)&strcmd.sc_buf, 0);
}
