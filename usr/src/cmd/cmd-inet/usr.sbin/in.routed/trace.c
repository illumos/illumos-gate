/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/routed/trace.c,v 1.6 2000/08/11 08:24:38 sheldonh Exp $
 */

#include "defs.h"
#include "pathnames.h"
#include <signal.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <strings.h>
#include <fcntl.h>
#include <protocols/routed.h>

#define	NRECORDS	50		/* size of circular trace buffer */

int	tracelevel, new_tracelevel;
FILE	*ftrace = stdout;		/* output trace file */
static const char *sigtrace_pat = "%s";
static char savetracename[MAXPATHLEN+1];
static char *ripcmds[RIPCMD_MAX] =
	{"#0", "REQUEST", "RESPONSE", "TRACEON", "TRACEOFF", "POLL",
	"POLLENTRY"};
char	inittracename[MAXPATHLEN+1];
static boolean_t file_trace;	/* 1=tracing to file, not stdout */

static void tmsg(const char *, ...);

const char *
rip_strerror(int err)
{
	const char *cp = strerror(err);
	static char msgbuf[64];

	if (cp == NULL) {
		if (err == 0) {
			cp = "success";
		} else {
			(void) snprintf(msgbuf, sizeof (msgbuf),
			    "unknown error %d", err);
			cp = msgbuf;
		}
	}
	return (cp);
}

/* convert IP address to a string, but not into a single buffer */
char *
naddr_ntoa(in_addr_t a)
{
#define	NUM_BUFS 4
	static int bufno;
	static struct {
	    char    str[INET_ADDRSTRLEN];	/* xxx.xxx.xxx.xxx\0 */
	} bufs[NUM_BUFS];
	char *s;
	struct in_addr addr;

	addr.s_addr = a;
	s = strcpy(bufs[bufno].str, inet_ntoa(addr));
	bufno = (bufno+1) % NUM_BUFS;
	return (s);
#undef NUM_BUFS
}


const char *
saddr_ntoa(struct sockaddr_storage *ss)
{
	return (ss == NULL) ? "?" : naddr_ntoa(S_ADDR(ss));
}


static char *
ts(time_t secs)
{
	static char s[20];

	secs += epoch.tv_sec;
	(void) strftime(s, sizeof (s), "%T", localtime(&secs));
	return (s);
}

static char *
ts_full(struct timeval *tv)
{
	static char s[32];
	time_t secs;
	int len;

	secs = tv->tv_sec + epoch.tv_sec;
	(void) strftime(s, sizeof (s), "%Y/%m/%d %T", localtime(&secs));
	len = strlen(s);
	(void) snprintf(s + len, sizeof (s) - len, ".%06ld", tv->tv_usec);
	return (s);
}

/*
 * On each event, display a time stamp.
 * This assumes that 'now' is update once for each event, and
 * that at least now.tv_usec changes.
 */
static struct timeval lastlog_time;

void
lastlog(void)
{
	if (lastlog_time.tv_sec != now.tv_sec ||
	    lastlog_time.tv_usec != now.tv_usec) {
		(void) fprintf(ftrace, "-- %s --\n", ts_full(&now));
		lastlog_time = now;
	}
}


static void
tmsg(const char *p, ...)
{
	va_list args;

	if (ftrace != NULL) {
		lastlog();
		va_start(args, p);
		(void) vfprintf(ftrace, p, args);
		(void) fputc('\n', ftrace);
		(void) fflush(ftrace);
		(void) va_end(args);
	}
}


void
trace_close(int zap_stdio)
{
	int fd;


	(void) fflush(stdout);
	(void) fflush(stderr);

	if (ftrace != NULL && zap_stdio) {
		if (ftrace != stdout)
			(void) fclose(ftrace);
		ftrace = NULL;
		fd = open("/dev/null", O_RDWR);
		if (isatty(STDIN_FILENO))
			(void) dup2(fd, STDIN_FILENO);
		if (isatty(STDOUT_FILENO))
			(void) dup2(fd, STDOUT_FILENO);
		if (isatty(STDERR_FILENO))
			(void) dup2(fd, STDERR_FILENO);
		(void) close(fd);
	}
	lastlog_time.tv_sec = 0;
}


void
trace_flush(void)
{
	if (ftrace != NULL) {
		(void) fflush(ftrace);
		if (ferror(ftrace))
			trace_off("tracing off: %s",
			    rip_strerror(ferror(ftrace)));
	}
}


void
trace_off(const char *p, ...)
{
	va_list args;


	if (ftrace != NULL) {
		lastlog();
		va_start(args, p);
		(void) vfprintf(ftrace, p, args);
		(void) fputc('\n', ftrace);
		(void) va_end(args);
	}
	trace_close(file_trace);

	new_tracelevel = tracelevel = 0;
}


/* log a change in tracing */
void
tracelevel_msg(const char *pat,
    int dump)		/* -1=no dump, 0=default, 1=force */
{
	static const char *off_msgs[MAX_TRACELEVEL] = {
		"Tracing actions stopped",
		"Tracing packets stopped",
		"Tracing packet contents stopped",
		"Tracing kernel changes stopped",
		"Tracing routing socket messages stopped",
	};
	static const char *on_msgs[MAX_TRACELEVEL] = {
		"Tracing actions started",
		"Tracing packets started",
		"Tracing packet contents started",
		"Tracing kernel changes started",
		"Tracing routing socket messages started",
	};
	uint_t old_tracelevel = tracelevel;


	if (new_tracelevel < 0)
		new_tracelevel = 0;
	else if (new_tracelevel > MAX_TRACELEVEL)
		new_tracelevel = MAX_TRACELEVEL;

	if (new_tracelevel < tracelevel) {
		if (new_tracelevel <= 0) {
			trace_off(pat, off_msgs[0]);
		} else {
			do {
				tmsg(pat, off_msgs[tracelevel]);
			} while (--tracelevel != new_tracelevel);
		}

	} else if (new_tracelevel > tracelevel) {
		do {
			tmsg(pat, on_msgs[tracelevel++]);
		} while (tracelevel != new_tracelevel);
	}

	if (dump > 0 ||
	    (dump == 0 && old_tracelevel == 0 && tracelevel != 0))
		trace_dump();
}

void
set_tracefile(const char *filename,
    const char *pat,
    int dump)			/* -1=no dump, 0=default, 1=force */
{
	struct stat stbuf;
	struct stat stbuf2;
	FILE *n_ftrace;
	const char *fn;
	int nfd;
	boolean_t allow_create;

	/*
	 * main() calls this routine with "dump == -1".  All others
	 * call it with 0, so we take dump == -1 to mean "can create
	 * the file."
	 */
	allow_create = (dump == -1);

	/*
	 * Allow a null filename to increase the level if the trace file
	 * is already open or if coming from a trusted source, such as
	 * a signal or the command line.
	 */
	if (filename == NULL || filename[0] == '\0') {
		filename = NULL;
		if (ftrace == NULL) {
			if (inittracename[0] == '\0') {
				msglog("missing trace file name");
				return;
			}
			fn = inittracename;
		} else {
			goto set_tracelevel;
		}

	} else if (strcmp(filename, "dump/../table") == 0) {
		trace_dump();
		return;

	} else {
		/*
		 * Allow the file specified with "-T file" to be reopened,
		 * but require all other names specified over the net to
		 * match the official path.  The path can specify a directory
		 * in which the file is to be created.
		 */

		if (strcmp(filename, inittracename) != 0) {
			if (strncmp(filename, PATH_TRACE,
			    sizeof (PATH_TRACE)-1) != 0 ||
			    (strstr(filename, "../") != NULL)) {
				msglog("wrong trace file \"%s\"", filename);
				return;
			}
			if (stat(PATH_TRACE, &stbuf) == -1) {
				fn = PATH_TRACE;
				goto missing_file;
			}
			if (filename[sizeof (PATH_TRACE) - 1] != '\0' &&
			    (filename[sizeof (PATH_TRACE) - 1] != '/' ||
			    !S_ISDIR(stbuf.st_mode))) {
				goto bad_file_type;
			}
			if (S_ISDIR(stbuf.st_mode))
				allow_create = _B_TRUE;
		}

		fn = filename;
	}
	/* fn cannot be null here */

	/* If the new tracefile exists, it must be a regular file. */
	if (lstat(fn, &stbuf) == -1) {
		if (!allow_create)
			goto missing_file;
		nfd = open(fn, O_CREAT|O_EXCL|O_WRONLY, 0644);
		if (nfd != -1 && fstat(nfd, &stbuf) == -1) {
			(void) close(nfd);
			goto missing_file;
		}
	} else if (S_ISREG(stbuf.st_mode)) {
		nfd = open(fn, O_APPEND|O_WRONLY, 0644);
	} else {
		goto bad_file_type;
	}

	if (nfd == -1 || (n_ftrace = fdopen(nfd, "a")) == NULL) {
		msglog("failed to open trace file \"%s\" %s", fn,
		    rip_strerror(errno));
		if (fn == inittracename)
			inittracename[0] = '\0';
		if (nfd != -1)
			(void) close(nfd);
		return;
	}

	if (fstat(nfd, &stbuf2) == -1 || !S_ISREG(stbuf2.st_mode) ||
	    stbuf2.st_dev != stbuf.st_dev || stbuf2.st_ino != stbuf.st_ino) {
		msglog("trace file \"%s\" moved", fn);
		(void) fclose(n_ftrace);
		return;
	}

	tmsg("switch to trace file %s", fn);
	trace_close(file_trace = _B_TRUE);
	(void) dup2(nfd, STDOUT_FILENO);
	(void) dup2(nfd, STDERR_FILENO);

	if (fn != savetracename)
		(void) strlcpy(savetracename, fn, sizeof (savetracename) - 1);
	ftrace = n_ftrace;

set_tracelevel:
	if (new_tracelevel == 0 || filename == NULL)
		new_tracelevel++;
	tracelevel_msg(pat, dump != 0 ? dump : (filename != NULL));
	return;

missing_file:
	msglog("trace \"%s\" missing", fn);
	return;

bad_file_type:
	msglog("wrong type (%#x) of trace file \"%s\"", stbuf.st_mode, fn);
}


/* ARGSUSED */
void
sigtrace_more(int s)
{
	new_tracelevel++;
	sigtrace_pat = "SIGUSR1: %s";
	if (signal(s, sigtrace_more) == SIG_ERR)
		msglog("signal: %s", rip_strerror(errno));
}


/* ARGSUSED */
void
sigtrace_less(int s)
{
	new_tracelevel--;
	sigtrace_pat = "SIGUSR2: %s";
	if (signal(s, sigtrace_less) == SIG_ERR)
		msglog("signal: %s", rip_strerror(errno));
}

/* ARGSUSED */
void
sigtrace_dump(int s)
{
	trace_dump();
	if (signal(s, sigtrace_dump) == SIG_ERR)
		msglog("signal: %s", rip_strerror(errno));
}

/* Set tracing after a signal. */
void
set_tracelevel(void)
{
	if (new_tracelevel == tracelevel)
		return;

	/*
	 * If tracing entirely off, and there was no tracefile specified
	 * on the command line, then leave it off.
	 */
	if (new_tracelevel > tracelevel && ftrace == NULL) {
		if (savetracename[0] != '\0') {
			set_tracefile(savetracename, sigtrace_pat, 0);
		} else if (inittracename[0] != '\0') {
			set_tracefile(inittracename, sigtrace_pat, 0);
		} else {
			new_tracelevel = 0;
			return;
		}
	} else {
		tracelevel_msg(sigtrace_pat, 0);
	}
}


/* display an address */
char *
addrname(in_addr_t addr,	/* in network byte order */
    in_addr_t	mask,
    int	force)			/* 0=show mask if nonstandard, */
{					/*	1=always show mask, 2=never */
#define	NUM_BUFS 4
	static int bufno;
	static struct {
	/*
	 * this array can hold either of the following strings terminated
	 * by a null character:
	 * "xxx.xxx.xxx.xxx/xx"
	 * "xxx.xxx.xxx.xxx (mask xxx.xxx.xxx.xxx)"
	 *
	 */
	    char    str[2*INET_ADDRSTRLEN + sizeof (" (mask )")];
	} bufs[NUM_BUFS];
	char *s, *sp;
	in_addr_t dmask;
	int i, len;
	struct in_addr tmp_addr;

	tmp_addr.s_addr = addr;
	len = strlcpy(bufs[bufno].str, inet_ntoa(tmp_addr),
	    sizeof (bufs[bufno].str));
	s = bufs[bufno].str;
	bufno = (bufno+1) % NUM_BUFS;

	if (force == 1 || (force == 0 && mask != std_mask(addr))) {
		sp = &s[strlen(s)];

		dmask = mask & -mask;
		if (mask + dmask == 0) {
			i = ffs(mask);
			(void) snprintf(sp,
			    (sizeof (bufs[bufno].str) - len), "/%d",
			    (NBBY * sizeof (in_addr_t) + 1) - i);

		} else {
			(void) snprintf(sp,
			    (sizeof (bufs[bufno].str) - len), " (mask %s)",
			    naddr_ntoa(htonl(mask)));
		}
	}

	return (s);
#undef NUM_BUFS
}


/* display a bit-field */
struct or_bits {
	uint8_t	origin;
	const char *origin_name;
};

static struct or_bits origin_bits[] = {
	{ RO_RIP,		"RIP" },
	{ RO_RDISC,		"RDISC" },
	{ RO_STATIC,		"STATIC" },
	{ RO_LOOPBCK,		"LOOPBCK" },
	{ RO_PTOPT,		"PTOPT" },
	{ RO_NET_SYN,		"NET_SYN" },
	{ RO_IF,		"IF" },
	{ RO_FILE,		"FILE" },
	{ RO_NONE,		"     " },
	{ 0,			NULL}
};

/* display a bit-field */
struct bits {
	uint64_t	bits_mask;
	uint64_t	bits_clear;
	const char	*bits_name;
};

static struct bits if_bits[] = {
	{ IFF_BROADCAST,	0,		"BROADCAST" },
	{ IFF_DEBUG,		0,		"DEBUG" },
	{ IFF_LOOPBACK,		0,		"LOOPBACK" },
	{ IFF_POINTOPOINT,	0,		"POINTOPOINT" },
	{ IFF_NOTRAILERS,	0,		"NOTRAILERS" },
	{ IFF_RUNNING,		0,		"RUNNING" },
	{ IFF_NOARP,		0,		"NOARP" },
	{ IFF_PROMISC,		0,		"PROMISC" },
	{ IFF_ALLMULTI,		0,		"ALLMULTI" },
	{ IFF_INTELLIGENT,	0,		"INTELLIGENT" },
	{ IFF_MULTICAST,	0,		"MULTICAST" },
	{ IFF_MULTI_BCAST,	0,		"MULTI_BCAST" },
	{ IFF_UNNUMBERED,	0,		"UNNUMBERED" },
	{ IFF_DHCPRUNNING,	0,		"DHCP" },
	{ IFF_PRIVATE,		0,		"PRIVATE" },
	{ IFF_NOXMIT,		0,		"NOXMIT" },
	{ IFF_NOLOCAL,		0,		"NOLOCAL" },
	{ IFF_DEPRECATED,	0,		"DEPRECATED" },
	{ IFF_ADDRCONF,		0,		"ADDRCONF" },
	{ IFF_ROUTER,		0,		"ROUTER" },
	{ IFF_NONUD,		0,		"NONUD" },
	{ IFF_ANYCAST,		0,		"ANYCAST" },
	{ IFF_NORTEXCH,		0,		"NORTEXCH" },
	{ IFF_IPV4,		0,		"IPv4" },
	{ IFF_IPV6,		0,		"IPv6" },
	{ IFF_NOFAILOVER,	0,		"NOFAILOVER" },
	{ IFF_FAILED,		0,		"FAILED" },
	{ IFF_STANDBY,		0,		"STANDBY" },
	{ IFF_INACTIVE,		0,		"INACTIVE" },
	{ IFF_OFFLINE,		0,		"OFFLINE" },
	{ IFF_XRESOLV,		0,		"XRESOLV" },
	{ IFF_COS_ENABLED,	0,		"CoS" },
	{ IFF_PREFERRED,	0,		"PREFERRED" },
	{ IFF_TEMPORARY,	0,		"TEMPORARY" },
	{ IFF_FIXEDMTU,		0,		"FIXEDMTU" },
	{ IFF_VIRTUAL,		0,		"VIRTUAL"},
	{ IFF_IPMP,		0,		"IPMP"},
	{ 0,			0,		NULL}
};

static struct bits is_bits[] = {
	{ IS_ALIAS,		0,		"ALIAS" },
	{ IS_SUBNET,		0,		"" },
	{ IS_REMOTE,		(IS_NO_RDISC |
				IS_BCAST_RDISC), "REMOTE" },
	{ IS_PASSIVE,		(IS_NO_RDISC |
				IS_NO_RIP |
				IS_NO_SUPER_AG |
				IS_PM_RDISC |
				IS_NO_AG),	"PASSIVE" },
	{ IS_EXTERNAL,		0,		"EXTERNAL" },
	{ IS_CHECKED,		0,		"" },
	{ IS_ALL_HOSTS,		0,		"" },
	{ IS_ALL_ROUTERS,	0,		"" },
	{ IS_DISTRUST,		0,		"DISTRUST" },
	{ IS_BROKE,		IS_SICK,	"BROKEN" },
	{ IS_SICK,		0,		"SICK" },
	{ IS_DUP,		0,		"DUPLICATE" },
	{ IS_REDIRECT_OK,	0,		"REDIRECT_OK" },
	{ IS_NEED_NET_SYN,	0,		"" },
	{ IS_NO_AG,		IS_NO_SUPER_AG,	"NO_AG" },
	{ IS_NO_SUPER_AG,	0,		"NO_SUPER_AG" },
	{ (IS_NO_RIPV1_IN |
	    IS_NO_RIPV2_IN |
	    IS_NO_RIPV1_OUT |
	    IS_NO_RIPV2_OUT),	0,		"NO_RIP" },
	{ (IS_NO_RIPV1_IN |
	    IS_NO_RIPV1_OUT),	0,		"RIPV2" },
	{ IS_NO_RIPV1_IN,	0,		"NO_RIPV1_IN" },
	{ IS_NO_RIPV2_IN,	0,		"NO_RIPV2_IN" },
	{ IS_NO_RIPV1_OUT,	0,		"NO_RIPV1_OUT" },
	{ IS_NO_RIPV2_OUT,	0,		"NO_RIPV2_OUT" },
	{ IS_NO_RIP_MCAST,	0,		"NO_RIP_MCAST" },
	{ (IS_NO_ADV_IN |
	    IS_NO_SOL_OUT |
	    IS_NO_ADV_OUT),	IS_BCAST_RDISC,	"NO_RDISC" },
	{ IS_NO_SOL_OUT,	0,		"NO_SOLICIT" },
	{ IS_SOL_OUT,		0,		"SEND_SOLICIT" },
	{ IS_NO_ADV_OUT,	IS_BCAST_RDISC,	"NO_RDISC_ADV" },
	{ IS_ADV_OUT,		0,		"RDISC_ADV" },
	{ IS_BCAST_RDISC,	0,		"BCAST_RDISC" },
	{ IS_PM_RDISC,		0,		"" },
	{ IS_NO_HOST,		0,		"NO_HOST" },
	{ IS_SUPPRESS_RDISC,	0,		"SUPPRESS_RDISC" },
	{ IS_FLUSH_RDISC,	0,		"FLUSH_RDISC" },
	{ 0,			0,		NULL}
};

static struct bits rs_bits[] = {
	{ RS_IF,		0,		"IF" },
	{ RS_NET_INT,		RS_NET_SYN,	"NET_INT" },
	{ RS_NET_SYN,		0,		"NET_SYN" },
	{ RS_SUBNET,		0,		"" },
	{ RS_LOCAL,		0,		"LOCAL" },
	{ RS_MHOME,		0,		"MHOME" },
	{ RS_STATIC,		0,		"STATIC" },
	{ RS_NOPROPAGATE,	0,		"NOPROP" },
	{ RS_BADIF,		0,		"BADIF" },
	{ 0,			0,		NULL}
};

static struct bits ks_bits[] = {
	{ KS_NEW,	0,		"NEW" },
	{ KS_DELETE,	0,		"DELETE" },
	{ KS_ADD,	0,		"ADD" },
	{ KS_CHANGE,	0,		"CHANGE" },
	{ KS_DEL_ADD,	0,		"DEL_ADD" },
	{ KS_STATIC,	0,		"STATIC" },
	{ KS_GATEWAY,	0,		"GATEWAY" },
	{ KS_DYNAMIC,	0,		"DYNAMIC" },
	{ KS_DELETED,	0,		"DELETED" },
	{ KS_PRIVATE,	0,		"PRIVATE" },
	{ KS_CHECK,	0,		"CHECK" },
	{ KS_IF,	0,		"IF" },
	{ KS_PASSIVE,	0,		"PASSIVE" },
	{ KS_DEPRE_IF,	0,		"DEPRE_IF" },
	{ KS_FILE,	0,		"FILE" },
	{ 0,		0,		NULL}
};

static void
trace_bits(const struct bits *tbl,
    uint64_t field,
    boolean_t force)
{
	uint64_t b;
	char c;

	if (force) {
		(void) putc('<', ftrace);
		c = '\0';
	} else {
		c = '<';
	}

	while (field != 0 &&
	    (b = tbl->bits_mask) != 0) {
		if ((b & field) == b) {
			if (tbl->bits_name[0] != '\0') {
				if (c != '\0')
					(void) putc(c, ftrace);
				(void) fprintf(ftrace, "%s", tbl->bits_name);
				c = '|';
			}
			field &= ~(b | tbl->bits_clear);
		}
		tbl++;
	}
	if (field != 0) {
		if (c != '\0')
			(void) putc(c, ftrace);
		(void) fprintf(ftrace, "%#llx", field);
		c = '|';
	}

	if (c != '<' || force)
		(void) fputs("> ", ftrace);
}

static char *
trace_string(const struct bits *tbl, uint_t field, boolean_t force)
{
	const struct bits *tbp;
	char *sbuf, *cp, chr;
	size_t slen;

	/* minimum default string */
	slen = sizeof ("<0x12345678>");
	for (tbp = tbl; tbp->bits_mask != 0; tbp++)
		if (tbp->bits_name[0] != '\0')
			slen += strlen(tbp->bits_name) + 1;
	if ((sbuf = malloc(slen)) == NULL)
		return (NULL);
	cp = sbuf;

	if (force) {
		*cp++ = '<';
		chr = '\0';
	} else {
		chr = '<';
	}

	while (field != 0 && tbl->bits_mask != 0) {
		if ((tbl->bits_mask & field) == tbl->bits_mask) {
			if (tbl->bits_name[0] != '\0') {
				if (chr != '\0')
					*cp++ = chr;
				(void) strcpy(cp, tbl->bits_name);
				cp += strlen(tbl->bits_name);
				chr = '|';
			}
			field &= ~(tbl->bits_mask | tbl->bits_clear);
		}
		tbl++;
	}
	if (field != 0) {
		if (chr != '\0')
			*cp++ = chr;
		cp += sprintf(cp, "%#x", field);
		chr = '|';
	}

	if (chr != '<' || force)
		*cp++ = '>';
	*cp = '\0';
	return (sbuf);
}

char *
if_bit_string(uint_t field, boolean_t force)
{
	return (trace_string(if_bits, field, force));
}

char *
rtname(in_addr_t dst,
    in_addr_t mask,
    in_addr_t gate)
{
	static char buf[sizeof ("xxx.xxx.xxx.xxx/xx-->xxx.xxx.xxx.xxx")];
	int i;

	(void) snprintf(buf, sizeof (buf), "%-16s-->", addrname(dst, mask, 0));
	i = strlen(buf);
	(void) snprintf(&buf[i], (sizeof (buf) -i), "%-*s", 15+24-MAX(24, i),
	    naddr_ntoa(gate));
	return (buf);
}


static void
print_rts(struct rt_spare *rts,
    int force_metric,		/* -1=suppress, 0=default */
    int force_ifp,		/* -1=suppress, 0=default */
    int force_router,		/* -1=suppress, 0=default, 1=display */
    int force_tag,		/* -1=suppress, 0=default, 1=display */
    int force_time)		/* 0=suppress, 1=display */
{
	int i;

	if (force_metric >= 0)
		(void) fprintf(ftrace, "metric=%-2d ", rts->rts_metric);
	if (force_ifp >= 0)
		(void) fprintf(ftrace, "%s ", (rts->rts_ifp == 0 ?
		    "if?" : rts->rts_ifp->int_name));
	if (force_router > 0 ||
	    (force_router == 0 && rts->rts_router != rts->rts_gate))
		(void) fprintf(ftrace, "router=%s ",
		    naddr_ntoa(rts->rts_router));
	if (force_time > 0)
		(void) fprintf(ftrace, "%s ", ts(rts->rts_time));
	if (force_tag > 0 ||
	    (force_tag == 0 && rts->rts_tag != 0))
		(void) fprintf(ftrace, "tag=%#x ", ntohs(rts->rts_tag));
	if (rts->rts_de_ag != 0) {
		for (i = 1; (uint_t)(1 << i) <= rts->rts_de_ag; i++)
			continue;
		(void) fprintf(ftrace, "de_ag=%d ", i);
	}
	(void) fprintf(ftrace, "flags 0x%x ", rts->rts_flags);

}


static void
print_rtsorigin(const struct or_bits *tbl, uint8_t route_origin)
{

	uint8_t tblentry;
	while ((tblentry = tbl->origin) != 0) {
		if (tblentry == route_origin) {
			(void) fprintf(ftrace, "origin=%s ", tbl->origin_name);
		}
		tbl++;
	}
}


void
trace_if(const char *act, struct interface *ifp)
{
	if (!TRACEACTIONS || ftrace == NULL)
		return;

	lastlog();
	(void) fprintf(ftrace, "%-3s interface %-4s #%-3d ", act,
	    ifp->int_name,
	    ifp->int_phys != NULL ? ifp->int_phys->phyi_index : 0);
	(void) fprintf(ftrace, "%-15s-->%-15s",
	    naddr_ntoa(ifp->int_addr),
	    addrname(((ifp->int_if_flags & IFF_POINTOPOINT) ?
	    ifp->int_dstaddr : htonl(ifp->int_net)),
	    ifp->int_mask, 1));
	if (ifp->int_metric != 0)
		(void) fprintf(ftrace, " metric=%d", ifp->int_metric);
	if (!IS_RIP_OUT_OFF(ifp->int_state) &&
	    ifp->int_d_metric != 0)
		(void) fprintf(ftrace, " fake_default=%d", ifp->int_d_metric);
	(void) fputs("\n    ", ftrace);
	trace_bits(if_bits, ifp->int_if_flags, _B_FALSE);
	trace_bits(is_bits, ifp->int_state, _B_FALSE);
	(void) fputc('\n', ftrace);
}

void
trace_khash(const struct khash *krt)
{
	if (ftrace == NULL)
		return;

	lastlog();
	(void) fprintf(ftrace, "  %-15s-->%-15s metric=%d ",
	    addrname(krt->k_dst, krt->k_mask, 0),
	    naddr_ntoa(krt->k_gate), krt->k_metric);
	if (krt->k_ifp != NULL)
		(void) fprintf(ftrace, "ifp %s ", krt->k_ifp->int_name);
	else
		(void) fprintf(ftrace, "ifp NULL ");
	(void) fprintf(ftrace, "%s ", ts(krt->k_keep));
	(void) fprintf(ftrace, "%s ", ts(krt->k_redirect_time));
	trace_bits(ks_bits, krt->k_state, _B_TRUE);
	(void) fputc('\n', ftrace);
}

void
trace_dr(const struct dr *drp)
{
	if (ftrace == NULL)
		return;

	lastlog();
	(void) fprintf(ftrace, "  %-4s %-15s %s ",
	    drp->dr_ifp != NULL ? drp->dr_ifp->int_name : "?",
	    naddr_ntoa(drp->dr_gate), ts(drp->dr_ts));
	(void) fprintf(ftrace, "%s %d %u\n", ts(drp->dr_life),
	    SIGN_PREF(drp->dr_recv_pref), drp->dr_pref);
}

void
trace_upslot(struct rt_entry *rt,
    struct rt_spare *rts,
    struct rt_spare *new)
{
	if (!TRACEACTIONS || ftrace == NULL)
		return;

	if (rts->rts_gate == new->rts_gate &&
	    rts->rts_router == new->rts_router &&
	    rts->rts_metric == new->rts_metric &&
	    rts->rts_tag == new->rts_tag &&
	    rts->rts_de_ag == new->rts_de_ag)
		return;

	lastlog();
	if (new->rts_gate == 0) {
		(void) fprintf(ftrace, "Del #%d %-35s ",
		    (int)(rts - rt->rt_spares),
		    rtname(rt->rt_dst, rt->rt_mask, rts->rts_gate));
		print_rts(rts, 0, 0, 0, 0,
		    (rts != rt->rt_spares ||
		    AGE_RT(rt->rt_state, rts->rts_origin, new->rts_ifp)));

	} else if (rts->rts_gate != RIP_DEFAULT) {
		(void) fprintf(ftrace, "Chg #%d %-35s ",
		    (int)(rts - rt->rt_spares),
		    rtname(rt->rt_dst, rt->rt_mask, rts->rts_gate));
		print_rts(rts, 0, 0,
		    rts->rts_gate != new->rts_gate,
		    rts->rts_tag != new->rts_tag,
		    rts != rt->rt_spares ||
		    AGE_RT(rt->rt_state, rts->rts_origin, rt->rt_ifp));

		(void) fprintf(ftrace, "\n       %19s%-16s ", "",
		    (new->rts_gate != rts->rts_gate ?
		    naddr_ntoa(new->rts_gate) : ""));
		print_rts(new,
		    ((new->rts_metric == rts->rts_metric) ? -1 : 0),
		    ((new->rts_ifp == rts->rts_ifp) ? -1 : 0),
		    0,
		    rts->rts_tag != new->rts_tag,
		    (new->rts_time != rts->rts_time &&
		    (rts != rt->rt_spares ||
		    AGE_RT(rt->rt_state, new->rts_origin, new->rts_ifp))));

	} else {
		(void) fprintf(ftrace, "Add #%d %-35s ",
		    (int)(rts - rt->rt_spares),
		    rtname(rt->rt_dst, rt->rt_mask, new->rts_gate));
		print_rts(new, 0, 0, 0, 0,
		    (rts != rt->rt_spares ||
		    AGE_RT(rt->rt_state, new->rts_origin, new->rts_ifp)));
	}
	(void) fputc('\n', ftrace);
}


/* miscellaneous message checked by the caller */
void
trace_misc(const char *p, ...)
{
	va_list args;

	if (ftrace == NULL)
		return;

	lastlog();
	va_start(args, p);
	(void) vfprintf(ftrace, p, args);
	(void) fputc('\n', ftrace);
	(void) va_end(args);
}


/* display a message if tracing actions */
void
trace_act(const char *p, ...)
{
	va_list args;

	if (!TRACEACTIONS || ftrace == NULL)
		return;

	lastlog();
	va_start(args, p);
	(void) vfprintf(ftrace, p, args);
	(void) fputc('\n', ftrace);
	(void) va_end(args);
}


/* display a message if tracing packets */
void
trace_pkt(const char *p, ...)
{
	va_list args;

	if (!TRACEPACKETS || ftrace == NULL)
		return;

	lastlog();
	va_start(args, p);
	(void) vfprintf(ftrace, p, args);
	(void) fputc('\n', ftrace);
	(void) va_end(args);
}


void
trace_change(struct rt_entry *rt,
    uint16_t	state,
    struct	rt_spare *new,
    const char	*label)
{
	if (ftrace == NULL)
		return;

	if (rt->rt_metric == new->rts_metric &&
	    rt->rt_gate == new->rts_gate &&
	    rt->rt_router == new->rts_router &&
	    rt->rt_state == state &&
	    rt->rt_tag == new->rts_tag &&
	    rt->rt_de_ag == new->rts_de_ag)
		return;

	lastlog();
	(void) fprintf(ftrace, "%s %-35s ",
	    label,
	    rtname(rt->rt_dst, rt->rt_mask, rt->rt_gate));
	print_rts(rt->rt_spares,
	    0, 0, 0, 0, AGE_RT(rt->rt_state, rt->rt_spares->rts_origin,
	    rt->rt_ifp));
	print_rtsorigin(origin_bits, rt->rt_spares->rts_origin);
	trace_bits(rs_bits, rt->rt_state, rt->rt_state != state);

	(void) fprintf(ftrace, "\n%*s %19s%-16s ",
	    strlen(label), "", "",
	    (rt->rt_gate != new->rts_gate ?
	    naddr_ntoa(new->rts_gate) : ""));
	print_rts(new,
	    ((new->rts_metric == rt->rt_metric) ? -1 : 0),
	    ((new->rts_ifp == rt->rt_ifp) ? -1 : 0),
	    0,
	    rt->rt_tag != new->rts_tag,
	    (rt->rt_time != new->rts_time &&
	    AGE_RT(rt->rt_state, new->rts_origin, new->rts_ifp)));
	if (rt->rt_state != state) {
		print_rtsorigin(origin_bits, new->rts_origin);
		trace_bits(rs_bits, state, _B_TRUE);
	}
	(void) fputc('\n', ftrace);
}


void
trace_add_del(const char *action, struct rt_entry *rt)
{
	if (ftrace == NULL)
		return;

	lastlog();
	(void) fprintf(ftrace, "%s    %-35s ",
	    action,
	    rtname(rt->rt_dst, rt->rt_mask, rt->rt_gate));
	print_rts(rt->rt_spares, 0, 0, 0, 0, AGE_RT(rt->rt_state,
	    rt->rt_spares->rts_origin, rt->rt_ifp));
	print_rtsorigin(origin_bits, rt->rt_spares->rts_origin);
	trace_bits(rs_bits, rt->rt_state, _B_FALSE);
	(void) fputc('\n', ftrace);
}


/* ARGSUSED */
static int
walk_trace(struct radix_node *rn,
    void *w)
{
#define	RT ((struct rt_entry *)rn)
	struct rt_spare *rts;
	int i;

	(void) fprintf(ftrace, "  %-35s ",
	    rtname(RT->rt_dst, RT->rt_mask, RT->rt_gate));
	print_rts(&RT->rt_spares[0], 0, 0, 0, 0,
	    AGE_RT(RT->rt_state, RT->rt_spares[0].rts_origin, RT->rt_ifp));
	print_rtsorigin(origin_bits, RT->rt_spares[0].rts_origin);
	trace_bits(rs_bits, RT->rt_state, _B_FALSE);
	if (RT->rt_poison_time >= now_garbage &&
	    RT->rt_poison_metric < RT->rt_metric)
		(void) fprintf(ftrace, "pm=%d@%s",
		    RT->rt_poison_metric, ts(RT->rt_poison_time));
	(void) fprintf(ftrace, "%d spare slots", RT->rt_num_spares);

	rts = &RT->rt_spares[1];
	for (i = 1; i < RT->rt_num_spares; i++, rts++) {
		if (rts->rts_gate != RIP_DEFAULT) {
			(void) fprintf(ftrace, "\n    #%d%15s%-16s ",
			    i, "", naddr_ntoa(rts->rts_gate));
			print_rts(rts, 0, 0, 0, 0, 1);
			print_rtsorigin(origin_bits, rts->rts_origin);
		}
	}
	(void) fputc('\n', ftrace);

	return (0);
}


void
trace_dump(void)
{
	struct interface *ifp;

	if (ftrace == NULL)
		return;
	lastlog();

	/*
	 * Warning: the rtquery.trace.* family of STC tests depend on
	 * the log file format here.  If you need to change this next
	 * message, make sure that you change the TRACE_DUMP variable
	 * as well.
	 */
	(void) fputs("current daemon state:\n", ftrace);
	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next)
		trace_if("", ifp);
	(void) fputs("Routes:\n", ftrace);
	(void) rn_walktree(rhead, walk_trace, NULL);
	(void) fputs("Kernel routes:\n", ftrace);
	kern_dump();
	(void) fputs("Discovered routers:\n", ftrace);
	rdisc_dump();
}


void
trace_rip(const char *dir1, const char *dir2,
    struct sockaddr_in *who,
    struct interface *ifp,
    struct rip *msg,
    int size)			/* total size of message */
{
	struct netinfo *n, *lim;
#define	NA ((struct netauth *)n)
	int i, seen_route;
	struct in_addr tmp_mask;

	if (!TRACEPACKETS || ftrace == NULL)
		return;

	lastlog();
	if (msg->rip_cmd >= RIPCMD_MAX || msg->rip_vers == 0) {
		(void) fprintf(ftrace, "%s bad RIPv%d cmd=%d %s"
		    " %s.%d size=%d\n",
		    dir1, msg->rip_vers, msg->rip_cmd, dir2,
		    naddr_ntoa(who->sin_addr.s_addr),
		    ntohs(who->sin_port),
		    size);
		return;
	}

	(void) fprintf(ftrace, "%s RIPv%d %s %s %s.%d%s%s\n",
	    dir1, msg->rip_vers, ripcmds[msg->rip_cmd], dir2,
	    naddr_ntoa(who->sin_addr.s_addr), ntohs(who->sin_port),
	    ifp ? " via " : "", ifp ? ifp->int_name : "");
	if (!TRACECONTENTS)
		return;

	seen_route = 0;
	switch (msg->rip_cmd) {
	case RIPCMD_REQUEST:
	case RIPCMD_RESPONSE:

		n = msg->rip_nets;
		tmp_mask.s_addr = n->n_mask;
		lim = n + (size - 4) / sizeof (struct netinfo);
		for (; n < lim; n++) {
			if (!seen_route &&
			    n->n_family == RIP_AF_UNSPEC &&
			    ntohl(n->n_metric) == HOPCNT_INFINITY &&
			    msg->rip_cmd == RIPCMD_REQUEST &&
			    (n+1 == lim ||
			    (n+2 == lim &&
			    (n+1)->n_family == RIP_AF_AUTH))) {
				(void) fputs("\tQUERY ", ftrace);
				if (n->n_dst != 0)
					(void) fprintf(ftrace, "%s ",
					    naddr_ntoa(n->n_dst));
				if (n->n_mask != 0)
					(void) fprintf(ftrace, "mask=%s ",
					    inet_ntoa(tmp_mask));
				if (n->n_nhop != 0)
					(void) fprintf(ftrace, "nhop=%s ",
					    naddr_ntoa(n->n_nhop));
				if (n->n_tag != 0)
					(void) fprintf(ftrace, "tag=%#x ",
					    ntohs(n->n_tag));
				(void) fputc('\n', ftrace);
				continue;
			}

			if (n->n_family == RIP_AF_AUTH) {
				if (NA->a_type == RIP_AUTH_PW &&
				    n == msg->rip_nets) {
					(void) fprintf(ftrace, "\tPassword"
					    " Authentication: \"%s\"\n",
					    qstring(NA->au.au_pw,
					    RIP_AUTH_PW_LEN));
					continue;
				}

				if (NA->a_type == RIP_AUTH_MD5 &&
				    n == msg->rip_nets) {
					(void) fprintf(ftrace,
					    "\tMD5 Auth"
					    " pkt_len=%d KeyID=%u"
					    " auth_len=%d"
					    " seqno=%#x"
					    " rsvd=%#hx,%#hx\n",
					    ntohs(NA->au.a_md5.md5_pkt_len),
					    NA->au.a_md5.md5_keyid,
					    NA->au.a_md5.md5_auth_len,
					    ntohl(NA->au.a_md5.md5_seqno),
					    ntohs(NA->au.a_md5.rsvd[0]),
					    ntohs(NA->au.a_md5.rsvd[1]));
					continue;
				}
				(void) fprintf(ftrace,
				    "\tAuthentication type %d: ",
				    ntohs(NA->a_type));
				for (i = 0; i < (int)sizeof (NA->au.au_pw);
				    i++)
					(void) fprintf(ftrace, "%02x ",
					    NA->au.au_pw[i]);
				(void) fputc('\n', ftrace);
				continue;
			}

			seen_route = 1;
			if (n->n_family != RIP_AF_INET) {
				(void) fprintf(ftrace,
				    "\t(af %d) %-18s mask=%s ",
				    ntohs(n->n_family),
				    naddr_ntoa(n->n_dst),
				    inet_ntoa(tmp_mask));
			} else if (msg->rip_vers == RIPv1) {
				(void) fprintf(ftrace, "\t%-18s ",
				    addrname(n->n_dst, ntohl(n->n_mask),
				    n->n_mask == 0 ? 2 : 1));
			} else {
				(void) fprintf(ftrace, "\t%-18s ",
				    addrname(n->n_dst, ntohl(n->n_mask),
				    n->n_mask == 0 ? 2 : 0));
			}
			(void) fprintf(ftrace, "metric=%-2lu ",
			    (unsigned long)ntohl(n->n_metric));
			if (n->n_nhop != 0)
				(void) fprintf(ftrace, " nhop=%s ",
				    naddr_ntoa(n->n_nhop));
			if (n->n_tag != 0)
				(void) fprintf(ftrace, "tag=%#x",
				    ntohs(n->n_tag));
			(void) fputc('\n', ftrace);
		}
		if (size != (char *)n - (char *)msg)
			(void) fprintf(ftrace, "truncated record, len %d\n",
			    size);
		break;

	case RIPCMD_TRACEON:
		(void) fprintf(ftrace, "\tfile=\"%.*s\"\n", size - 4,
		    msg->rip_tracefile);
		break;

	case RIPCMD_TRACEOFF:
		break;
	}
}
