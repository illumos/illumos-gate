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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
static	void	dofcntl(struct ps_prochandle *, int, int, int);
static	void	dosocket(struct ps_prochandle *, int);
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
		(void) fprintf(stderr, "usage:\t%s [-F] pid ...\n",
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

		/* get the specified pid and the psinfo struct */
		if ((pid = proc_arg_psinfo(arg = *argv++, PR_ARG_PIDS,
		    &psinfo, &gret)) == -1) {
			(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
			    command, arg, Pgrab_error(gret));
			retc++;
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
			case G_SELF:
				proc_unctrl_psinfo(&psinfo);
				(void) printf("%d:\t%.70s\n", (int)pid,
				    psinfo.pr_psargs);
				if (gret == G_SYS)
					(void) printf("  [system process]\n");
				else
					show_files(NULL);
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

static void
show_files(struct ps_prochandle *Pr)
{
	DIR *dirp;
	struct dirent *dentp;
	const char *dev;
	char pname[100];
	char fname[PATH_MAX];
	struct stat64 statb;
	struct rlimit rlim;
	pid_t pid;
	int fd;
	char *s;
	int ret;

	if (pr_getrlimit(Pr, RLIMIT_NOFILE, &rlim) == 0) {
		ulong_t nfd = rlim.rlim_cur;
		if (nfd == RLIM_INFINITY)
			(void) printf(
			    "  Current rlimit: unlimited file descriptors\n");
		else
			(void) printf(
			    "  Current rlimit: %lu file descriptors\n", nfd);
	}

	/* in case we are doing this to ourself */
	pid = (Pr == NULL)? getpid() : Pstatus(Pr)->pr_pid;

	(void) sprintf(pname, "/proc/%d/fd", (int)pid);
	if ((dirp = opendir(pname)) == NULL) {
		(void) fprintf(stderr, "%s: cannot open directory %s\n",
		    command, pname);
		return;
	}

	/* for each open file --- */
	while ((dentp = readdir(dirp)) != NULL && !interrupt) {
		char unknown[12];
		dev_t rdev;

		/* skip '.' and '..' */
		if (!isdigit(dentp->d_name[0]))
			continue;

		fd = atoi(dentp->d_name);
		if (pr_fstat64(Pr, fd, &statb) == -1) {
			s = unknown;
			(void) sprintf(s, "%4d", fd);
			perror(s);
			continue;
		}

		rdev = NODEV;
		switch (statb.st_mode & S_IFMT) {
		case S_IFCHR: s = "S_IFCHR"; rdev = statb.st_rdev; break;
		case S_IFBLK: s = "S_IFBLK"; rdev = statb.st_rdev; break;
		case S_IFIFO: s = "S_IFIFO"; break;
		case S_IFDIR: s = "S_IFDIR"; break;
		case S_IFREG: s = "S_IFREG"; break;
		case S_IFLNK: s = "S_IFLNK"; break;
		case S_IFSOCK: s = "S_IFSOCK"; break;
		case S_IFDOOR: s = "S_IFDOOR"; break;
		case S_IFPORT: s = "S_IFPORT"; break;
		default:
			s = unknown;
			(void) sprintf(s, "0x%.4x ",
			    (int)statb.st_mode & S_IFMT);
			break;
		}

		(void) printf("%4d: %s mode:0%.3o", fd, s,
		    (int)statb.st_mode & ~S_IFMT);

		if (major(statb.st_dev) != (major_t)NODEV &&
		    minor(statb.st_dev) != (minor_t)NODEV)
			(void) printf(" dev:%lu,%lu",
			    (ulong_t)major(statb.st_dev),
			    (ulong_t)minor(statb.st_dev));
		else
			(void) printf(" dev:0x%.8lX", (long)statb.st_dev);

		if ((statb.st_mode & S_IFMT) == S_IFPORT) {
			(void) printf(" uid:%d gid:%d",
			    (int)statb.st_uid,
			    (int)statb.st_gid);
			(void) printf(" size:%lld\n",
			    (longlong_t)statb.st_size);
			continue;
		}

		(void) printf(" ino:%llu uid:%d gid:%d",
		    (u_longlong_t)statb.st_ino,
		    (int)statb.st_uid, (int)statb.st_gid);

		if (rdev == NODEV)
			(void) printf(" size:%lld\n",
			    (longlong_t)statb.st_size);
		else if (major(rdev) != (major_t)NODEV &&
		    minor(rdev) != (minor_t)NODEV)
			(void) printf(" rdev:%lu,%lu\n",
			    (ulong_t)major(rdev), (ulong_t)minor(rdev));
		else
			(void) printf(" rdev:0x%.8lX\n", (long)rdev);

		if (!nflag) {
			dofcntl(Pr, fd,
			    (statb.st_mode & (S_IFMT|S_ENFMT|S_IXGRP))
			    == (S_IFREG|S_ENFMT),
			    (statb.st_mode & S_IFMT) == S_IFDOOR);

			if ((statb.st_mode & S_IFMT) == S_IFSOCK)
				dosocket(Pr, fd);

			(void) sprintf(pname, "/proc/%d/path/%d", (int)pid, fd);

			if ((ret = readlink(pname, fname, PATH_MAX - 1)) <= 0)
				continue;

			fname[ret] = '\0';

			if ((statb.st_mode & S_IFMT) == S_IFCHR &&
			    (dev = strrchr(fname, ':')) != NULL) {
				/*
				 * There's no elegant way to determine if a
				 * character device supports TLI, so we lame
				 * out and just check a hardcoded list of
				 * known TLI devices.
				 */
				int i;
				const char *tlidevs[] =
				    { "tcp", "tcp6", "udp", "udp6", NULL };

				dev++; /* skip past the `:' */
				for (i = 0; tlidevs[i] != NULL; i++) {
					if (strcmp(dev, tlidevs[i]) == 0) {
						dotli(Pr, fd);
						break;
					}
				}
			}
			(void) printf("      %s\n", fname);
		}
	}
	(void) closedir(dirp);
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
dofcntl(struct ps_prochandle *Pr, int fd, int mandatory, int isdoor)
{
	struct flock flock;
	int fileflags;
	int fdflags;

	fileflags = pr_fcntl(Pr, fd, F_GETXFL, 0);
	fdflags = pr_fcntl(Pr, fd, F_GETFD, 0);

	if (fileflags != -1 || fdflags != -1) {
		(void) printf("      ");
		if (fileflags != -1)
			show_fileflags(fileflags);
		if (fdflags != -1 && (fdflags & FD_CLOEXEC))
			(void) printf(" FD_CLOEXEC");
		if (isdoor)
			show_door(Pr, fd);
		(void) fputc('\n', stdout);
	} else if (isdoor) {
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
	if (getflock(Pr, fd, &flock) != -1) {
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

#ifdef O_PRIV
#define	ALL_O_FLAGS	O_ACCMODE | O_NDELAY | O_NONBLOCK | O_APPEND | \
			O_PRIV | O_SYNC | O_DSYNC | O_RSYNC | O_XATTR | \
			O_CREAT | O_TRUNC | O_EXCL | O_NOCTTY | O_LARGEFILE
#else
#define	ALL_O_FLAGS	O_ACCMODE | O_NDELAY | O_NONBLOCK | O_APPEND | \
			O_SYNC | O_DSYNC | O_RSYNC | O_XATTR | \
			O_CREAT | O_TRUNC | O_EXCL | O_NOCTTY | O_LARGEFILE
#endif

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
#ifdef O_PRIV
	if (flags & O_PRIV)
		(void) strcat(str, "|O_PRIV");
#endif
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

/* show door info */
static void
show_door(struct ps_prochandle *Pr, int fd)
{
	door_info_t door_info;
	psinfo_t psinfo;

	if (pr_door_info(Pr, fd, &door_info) != 0)
		return;

	if (proc_get_psinfo(door_info.di_target, &psinfo) != 0)
		psinfo.pr_fname[0] = '\0';

	(void) printf("  door to ");
	if (psinfo.pr_fname[0] != '\0')
		(void) printf("%s[%d]", psinfo.pr_fname,
		    (int)door_info.di_target);
	else
		(void) printf("pid %d", (int)door_info.di_target);
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
	    { SOL_SOCKET, SO_EXCLBIND,		"SO_EXCLBIND," },
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

	len = sizeof (buf);
	if (pr_getsockname(Pr, fd, sa, &len) == 0)
		show_sockaddr("sockname", sa, len);

	len = sizeof (buf);
	if (pr_getpeername(Pr, fd, sa, &len) == 0)
		show_sockaddr("peername", sa, len);
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
