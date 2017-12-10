/*
 * utils.c - various utility functions used in pppd.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1999 The Australian National University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the Australian National University.  The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef __linux__
#define	_GNU_SOURCE
#endif
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <netdb.h>
#include <utmp.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef SVR4
#include <sys/mkdev.h>
#endif

#include "pppd.h"

#if defined(SUNOS4)
extern char *strerror();
#endif

/* Don't log to stdout until we're sure it's ok to do so. */
bool early_log = 1;

static void pr_log __P((void *, const char *, ...));
static void logit __P((int, const char *, va_list));
static void vslp_printer __P((void *, const char *, ...));
static void format_packet __P((u_char *, int,
    void (*) (void *, const char *, ...), void *));

struct buffer_info {
    char *ptr;
    int len;
};

/*
 * strllen - like strlen, but doesn't run past end of input.
 */
size_t
strllen(str, len)
    const char *str;
    size_t len;
{
    size_t ret;

    for (ret = 0; ret < len; ret++)
	if (*str++ == '\0')
	    break;
    return (ret);
}

/*
 * slprintf - format a message into a buffer.  Like sprintf except we
 * also specify the length of the output buffer, and we handle %m
 * (error message), %v (visible string), %q (quoted string), %t
 * (current time), %I (IP address), %P (PPP packet), and %B (sequence
 * of bytes) formats.  Doesn't do floating-point formats.  Returns the
 * number of chars put into buf.
 */
int
slprintf __V((char *buf, int buflen, const char *fmt, ...))
{
    va_list args;
    int n;

#if defined(__STDC__)
    va_start(args, fmt);
#else
    char *buf;
    int buflen;
    const char *fmt;
    va_start(args);
    buf = va_arg(args, char *);
    buflen = va_arg(args, int);
    fmt = va_arg(args, const char *);
#endif
    n = vslprintf(buf, buflen, fmt, args);
    va_end(args);
    return (n);
}

/*
 * Print to file or, if argument is NULL, to syslog at debug level.
 */
int
flprintf __V((FILE *strptr, const char *fmt, ...))
{
    va_list args;
    int n;
    char buf[1024], *bp, *nlp, *ebp;

#if defined(__STDC__)
    va_start(args, fmt);
#else
    FILE *strptr;
    const char *fmt;
    va_start(args);
    strptr = va_arg(args, FILE *);
    fmt = va_arg(args, const char *);
#endif
    n = vslprintf(buf, sizeof (buf), fmt, args);
    va_end(args);
    if (strptr == NULL) {
	bp = buf;
	ebp = buf + n;
	while (bp < ebp) {
	    if ((nlp = strchr(bp, '\n')) == NULL)
		nlp = ebp;
	    if (nlp > bp) {
		*nlp = '\0';
		syslog(LOG_DEBUG, "%s", bp);
	    }
	    bp = nlp + 1;
	}
    } else {
	n = fwrite(buf, 1, n, strptr);
    }
    return (n);
}

/*
 * vslprintf - like slprintf, takes a va_list instead of a list of args.
 */
#define OUTCHAR(c)	(buflen > 0? (--buflen, *buf++ = (c)): 0)

int
vslprintf(buf, buflen, fmt, args)
    char *buf;
    int buflen;
    const char *fmt;
    va_list args;
{
    int c, n, longs;
    int width, prec, fillch;
    int base, len, neg, quoted;
#ifdef SOL2
    uint64_t val;
    int64_t sval;
#else
    unsigned long val;
    long sval;
#endif
    char *buf0, *mstr;
    const char *f, *str;
    unsigned char *p;
    char num[32];	/* 2^64 is 20 chars decimal, 22 octal */
    time_t t;
    u_int32_t ip;
    static const char hexchars[] = "0123456789abcdef";
    struct buffer_info bufinfo;

    buf0 = buf;
    --buflen;
    while (buflen > 0) {
	for (f = fmt; *f != '%' && *f != 0; ++f)
	    ;
	if (f > fmt) {
	    len = f - fmt;
	    if (len > buflen)
		len = buflen;
	    (void) memcpy(buf, fmt, len);
	    buf += len;
	    buflen -= len;
	    fmt = f;
	}
	if (*fmt == 0)
	    break;
	c = *++fmt;
	width = 0;
	prec = -1;
	fillch = ' ';
	if (c == '0') {
	    fillch = '0';
	    c = *++fmt;
	}
	if (c == '*') {
	    width = va_arg(args, int);
	    c = *++fmt;
	} else {
	    while (isdigit(c)) {
		width = width * 10 + c - '0';
		c = *++fmt;
	    }
	}
	if (c == '.') {
	    c = *++fmt;
	    if (c == '*') {
		prec = va_arg(args, int);
		c = *++fmt;
	    } else {
		prec = 0;
		while (isdigit(c)) {
		    prec = prec * 10 + c - '0';
		    c = *++fmt;
		}
	    }
	}
	longs = 0;
	if (c == 'l') {
	    longs++;
	    c = *++fmt;
	    if (c == 'l') {
		longs++;
		c = *++fmt;
	    }
	}
	str = 0;
	base = 0;
	neg = 0;
	val = 0;
	++fmt;
	switch (c) {
	case 'u':
#ifdef SOL2
	    if (longs >= 2)
		val = va_arg(args, uint64_t);
	    else
#endif
	    if (longs > 0)
		val = va_arg(args, unsigned long);
	    else
		val = va_arg(args, unsigned int);
	    base = 10;
	    break;
	case 'd':
#ifdef SOL2
	    if (longs >= 2)
		sval = va_arg(args, int64_t);
	    else
#endif
	    if (longs > 0)
		sval = va_arg(args, long);
	    else
		sval = va_arg(args, int);
	    if (sval < 0) {
		neg = 1;
		val = -sval;
	    } else
		val = sval;
	    base = 10;
	    break;
	case 'o':
#ifdef SOL2
	    if (longs >= 2)
		val = va_arg(args, uint64_t);
	    else
#endif
	    if (longs > 0)
		val = va_arg(args, unsigned long);
	    else
		val = va_arg(args, unsigned int);
	    base = 8;
	    break;
	case 'x':
	case 'X':
#ifdef SOL2
	    if (longs >= 2)
		val = va_arg(args, uint64_t);
	    else
#endif
	    if (longs > 0)
		val = va_arg(args, unsigned long);
	    else
		val = va_arg(args, unsigned int);
	    base = 16;
	    break;
	case 'p':
	    val = (unsigned long) va_arg(args, void *);
	    base = 16;
	    neg = 2;
	    break;
	case 's':
	    str = va_arg(args, const char *);
	    break;
	case 'c':
	    num[0] = va_arg(args, int);
	    num[1] = 0;
	    str = num;
	    break;
	case 'm':
	    str = strerror(errno);
	    break;
	case 'I':
	    ip = va_arg(args, u_int32_t);
	    ip = ntohl(ip);
	    (void) slprintf(num, sizeof(num), "%d.%d.%d.%d", (ip >> 24) & 0xff,
		(ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
	    str = num;
	    break;
	case 't':
	    (void) time(&t);
	    mstr = ctime(&t);
	    mstr += 4;		/* chop off the day name */
	    mstr[15] = 0;	/* chop off year and newline */
	    str = (const char *)mstr;
	    break;
	case 'v':		/* "visible" string */
	case 'q':		/* quoted string */
	    quoted = c == 'q';
	    p = va_arg(args, unsigned char *);
	    if (fillch == '0' && prec >= 0) {
		n = prec;
	    } else {
		n = strlen((char *)p);
		if (prec >= 0 && n > prec)
		    n = prec;
	    }
	    while (n > 0 && buflen > 0) {
		c = *p++;
		--n;
		if (!quoted && c >= 0x80) {
		    (void) OUTCHAR('M');
		    (void) OUTCHAR('-');
		    c -= 0x80;
		}
		if (quoted && (c == '"' || c == '\\'))
		    (void) OUTCHAR('\\');
		if (c < 0x20 || (0x7f <= c && c < 0xa0)) {
		    if (quoted) {
			(void) OUTCHAR('\\');
			switch (c) {
			case '\t':	(void) OUTCHAR('t');	break;
			case '\n':	(void) OUTCHAR('n');	break;
			case '\b':	(void) OUTCHAR('b');	break;
			case '\f':	(void) OUTCHAR('f');	break;
			default:
			    (void) OUTCHAR('x');
			    (void) OUTCHAR(hexchars[c >> 4]);
			    (void) OUTCHAR(hexchars[c & 0xf]);
			}
		    } else {
			if (c == '\t')
			    (void) OUTCHAR(c);
			else {
			    (void) OUTCHAR('^');
			    (void) OUTCHAR(c ^ 0x40);
			}
		    }
		} else
		    (void) OUTCHAR(c);
	    }
	    continue;
	case 'P':		/* print PPP packet */
	    bufinfo.ptr = buf;
	    bufinfo.len = buflen + 1;
	    p = va_arg(args, unsigned char *);
	    n = va_arg(args, int);
	    format_packet(p, n, vslp_printer, &bufinfo);
	    buf = bufinfo.ptr;
	    buflen = bufinfo.len - 1;
	    continue;
	case 'B':
	    p = va_arg(args, unsigned char *);
	    if ((n = prec) > width && width > 0)
		n = width;
	    /* For safety's sake */
	    if (n > 2000)
		    n = 2000;
	    while (--n >= 0) {
		c = *p++;
		if (fillch == ' ')
		    (void) OUTCHAR(' ');
		(void) OUTCHAR(hexchars[(c >> 4) & 0xf]);
		(void) OUTCHAR(hexchars[c & 0xf]);
	    }
	    if (prec > width && width > 0) {
		(void) OUTCHAR('.');
		(void) OUTCHAR('.');
		(void) OUTCHAR('.');
	    }
	    continue;
	default:
	    *buf++ = '%';
	    if (c != '%')
		--fmt;		/* so %z outputs %z etc. */
	    --buflen;
	    continue;
	}
	if (base != 0) {
	    mstr = num + sizeof(num);
	    *--mstr = 0;
	    while (mstr > num + neg) {
		*--mstr = hexchars[val % base];
		val = val / base;
		if (--prec <= 0 && val == 0)
		    break;
	    }
	    switch (neg) {
	    case 1:
		*--mstr = '-';
		break;
	    case 2:
		*--mstr = 'x';
		*--mstr = '0';
		break;
	    }
	    len = num + sizeof(num) - 1 - mstr;
	    str = (const char *)mstr;
	} else {
	    len = strlen(str);
	    if (prec >= 0 && len > prec)
		len = prec;
	}
	if (width > 0) {
	    if (width > buflen)
		width = buflen;
	    if ((n = width - len) > 0) {
		buflen -= n;
		for (; n > 0; --n)
		    *buf++ = fillch;
	    }
	}
	if (len > buflen)
	    len = buflen;
	(void) memcpy(buf, str, len);
	buf += len;
	buflen -= len;
    }
    *buf = 0;
    return (buf - buf0);
}

/*
 * vslp_printer - used in processing a %P format
 */
static void
vslp_printer __V((void *arg, const char *fmt, ...))
{
    int n;
    va_list pvar;
    struct buffer_info *bi;

#if defined(__STDC__)
    va_start(pvar, fmt);
#else
    void *arg;
    const char *fmt;
    va_start(pvar);
    arg = va_arg(pvar, void *);
    fmt = va_arg(pvar, const char *);
#endif

    bi = (struct buffer_info *) arg;
    n = vslprintf(bi->ptr, bi->len, fmt, pvar);
    va_end(pvar);

    bi->ptr += n;
    bi->len -= n;
}

/*
 * log_packet - format a packet and log it.
 */

static char line[256];		/* line to be logged accumulated here */
static char *linep;

void
log_packet(p, len, prefix, level)
    u_char *p;
    int len;
    const char *prefix;
    int level;
{
    (void) strlcpy(line, prefix, sizeof(line));
    linep = line + strlen(line);
    format_packet(p, len, pr_log, (void *)level);
    if (linep != line)
	syslog(level, "%s", line);
}

/*
 * format_packet - make a readable representation of a packet,
 * calling `printer(arg, format, ...)' to output it.
 */
static void
format_packet(p, len, printer, arg)
    u_char *p;
    int len;
    void (*printer) __P((void *, const char *, ...));
    void *arg;
{
    int i, n;
    u_short proto;
    struct protent *protp;

    if (len >= PPP_HDRLEN && p[0] == PPP_ALLSTATIONS && p[1] == PPP_UI) {
	p += 2;
	GETSHORT(proto, p);
	len -= PPP_HDRLEN;
	for (i = 0; (protp = protocols[i]) != NULL; ++i)
	    if (proto == protp->protocol)
		break;
	if (protp != NULL) {
	    printer(arg, "[%s", protp->name);
	    n = (*protp->printpkt)(p, len, printer, arg);
	    printer(arg, "]");
	    p += n;
	    len -= n;
	} else {
	    for (i = 0; (protp = protocols[i]) != NULL; ++i)
		if (proto == (protp->protocol & ~0x8000))
		    break;
	    if (protp != NULL && protp->data_name != NULL) {
		printer(arg, "[%s data] %8.*B", protp->data_name, len, p);
		len = 0;
	    } else
		printer(arg, "[proto=0x%x]", proto);
	}
    }

    printer(arg, "%32.*B", len, p);
}

static void
pr_log __V((void *arg, const char *fmt, ...))
{
    int n;
    va_list pvar;
    char buf[256];

#if defined(__STDC__)
    va_start(pvar, fmt);
#else
    void *arg;
    const char *fmt;
    va_start(pvar);
    arg = va_arg(pvar, void *);
    fmt = va_arg(pvar, const char *);
#endif

    n = vslprintf(buf, sizeof(buf), fmt, pvar);
    va_end(pvar);

    if (linep + n + 1 > line + sizeof(line)) {
	syslog((int)arg, "%s", line);
	linep = line;
    }
    (void) strlcpy(linep, buf, line + sizeof(line) - linep);
    linep += n;
}

/*
 * print_string - print a readable representation of a string using
 * printer.
 */
void
print_string(p, len, printer, arg)
    char *p;
    int len;
    void (*printer) __P((void *, const char *, ...));
    void *arg;
{
    int c;

    printer(arg, "\"");
    for (; len > 0; --len) {
	c = *p++;
	if (isprint(c)) {
	    if (c == '\\' || c == '"')
		printer(arg, "\\");
	    printer(arg, "%c", c);
	} else {
	    switch (c) {
	    case '\n':
		printer(arg, "\\n");
		break;
	    case '\r':
		printer(arg, "\\r");
		break;
	    case '\t':
		printer(arg, "\\t");
		break;
	    default:
		printer(arg, "\\%.3o", c);
	    }
	}
    }
    printer(arg, "\"");
}

/*
 * logit - does the hard work for fatal et al.
 */
static void
logit(level, fmt, args)
    int level;
    const char *fmt;
    va_list args;
{
    int n;
    char buf[1024];

    n = vslprintf(buf, sizeof(buf), fmt, args);
    syslog(level, "%s", buf);
    if (log_to_fd >= 0 && (level != LOG_DEBUG || debug) &&
	(!early_log || log_to_specific_fd)) {
	if (buf[n-1] != '\n')
	    buf[n++] = '\n';
	if (write(log_to_fd, buf, n) != n)
	    log_to_fd = -1;
    }
}

/*
 * fatal - log an error message and die horribly.
 */
void
fatal __V((const char *fmt, ...))
{
    va_list pvar;

#if defined(__STDC__)
    va_start(pvar, fmt);
#else
    const char *fmt;
    va_start(pvar);
    fmt = va_arg(pvar, const char *);
#endif

    logit(LOG_ERR, fmt, pvar);
    va_end(pvar);

    die(1);			/* as promised */
}

/*
 * error - log an error message.
 */
void
error __V((const char *fmt, ...))
{
    va_list pvar;

#if defined(__STDC__)
    va_start(pvar, fmt);
#else
    const char *fmt;
    va_start(pvar);
    fmt = va_arg(pvar, const char *);
#endif

    logit(LOG_ERR, fmt, pvar);
    va_end(pvar);
}

/*
 * warn - log a warning message.
 */
void
warn __V((const char *fmt, ...))
{
    va_list pvar;

#if defined(__STDC__)
    va_start(pvar, fmt);
#else
    const char *fmt;
    va_start(pvar);
    fmt = va_arg(pvar, const char *);
#endif

    logit(LOG_WARNING, fmt, pvar);
    va_end(pvar);
}

/*
 * notice - log a notice-level message.
 */
void
notice __V((const char *fmt, ...))
{
    va_list pvar;

#if defined(__STDC__)
    va_start(pvar, fmt);
#else
    const char *fmt;
    va_start(pvar);
    fmt = va_arg(pvar, const char *);
#endif

    logit(LOG_NOTICE, fmt, pvar);
    va_end(pvar);
}

/*
 * info - log an informational message.
 */
void
info __V((const char *fmt, ...))
{
    va_list pvar;

#if defined(__STDC__)
    va_start(pvar, fmt);
#else
    const char *fmt;
    va_start(pvar);
    fmt = va_arg(pvar, const char *);
#endif

    logit(LOG_INFO, fmt, pvar);
    va_end(pvar);
}

/*
 * dbglog - log a debug message.
 */
void
dbglog __V((const char *fmt, ...))
{
    va_list pvar;

#if defined(__STDC__)
    va_start(pvar, fmt);
#else
    const char *fmt;
    va_start(pvar);
    fmt = va_arg(pvar, const char *);
#endif

    logit(LOG_DEBUG, fmt, pvar);
    va_end(pvar);
}

/*
 * Code names for regular PPP messages.  Used by LCP and most NCPs,
 * not used by authentication protocols.
 */
const char *
code_name(int code, int shortflag)
{
    static const char *codelist[] = {
	"Vendor-Extension", "Configure-Request", "Configure-Ack",
	"Configure-Nak", "Configure-Reject", "Terminate-Request",
	"Terminate-Ack", "Code-Reject", "Protocol-Reject",
	"Echo-Request", "Echo-Reply", "Discard-Request",
	"Identification", "Time-Remaining",
	"Reset-Request", "Reset-Ack"
    };
    static const char *shortcode[] = {
	"VendExt", "ConfReq", "ConfAck",
	"ConfNak", "ConfRej", "TermReq",
	"TermAck", "CodeRej", "ProtRej",
	"EchoReq", "EchoRep", "DiscReq",
	"Ident", "TimeRem",
	"ResetReq", "ResetAck"
    };
    static char msgbuf[64];

    if (code < 0 || code >= sizeof (codelist) / sizeof (*codelist)) {
	if (shortflag)
	    (void) slprintf(msgbuf, sizeof (msgbuf), "Code#%d", code);
	else
	    (void) slprintf(msgbuf, sizeof (msgbuf), "unknown code %d", code);
	return ((const char *)msgbuf);
    }
    return (shortflag ? shortcode[code] : codelist[code]);
}

/* Procedures for locking the serial device using a lock file. */
#ifndef LOCK_DIR
#ifdef _linux_
#define LOCK_DIR	"/var/lock"
#else
#ifdef SVR4
#define LOCK_DIR	"/var/spool/locks"
#else
#define LOCK_DIR	"/var/spool/lock"
#endif
#endif
#endif /* LOCK_DIR */

static char lock_file[MAXPATHLEN];

/*
 * lock - create a lock file for the named device
 */
int
lock(dev)
    char *dev;
{
#ifdef LOCKLIB
    int result;

    result = mklock (dev, (void *) 0);
    if (result == 0) {
	(void) strlcpy(lock_file, sizeof(lock_file), dev);
	return (0);
    }

    if (result > 0)
        notice("Device %s is locked by pid %d", dev, result);
    else
	error("Can't create lock file %s", lock_file);
    return (-1);

#else /* LOCKLIB */

    char lock_buffer[12];
    int fd, pid, n;

#ifdef SVR4
    struct stat sbuf;

    if (stat(dev, &sbuf) < 0) {
	error("Can't get device number for %s: %m", dev);
	return (-1);
    }
    if ((sbuf.st_mode & S_IFMT) != S_IFCHR) {
	error("Can't lock %s: not a character device", dev);
	return (-1);
    }
    (void) slprintf(lock_file, sizeof(lock_file), "%s/LK.%03d.%03d.%03d",
	     LOCK_DIR, major(sbuf.st_dev),
	     major(sbuf.st_rdev), minor(sbuf.st_rdev));
#else
    char *p;

    if ((p = strrchr(dev, '/')) != NULL)
	dev = p + 1;
    (void) slprintf(lock_file, sizeof(lock_file), "%s/LCK..%s", LOCK_DIR, dev);
#endif

    while ((fd = open(lock_file, O_EXCL | O_CREAT | O_RDWR, 0644)) < 0) {
	if (errno != EEXIST) {
	    error("Can't create lock file %s: %m", lock_file);
	    break;
	}

	/* Read the lock file to find out who has the device locked. */
	fd = open(lock_file, O_RDONLY, 0);
	if (fd < 0) {
	    if (errno == ENOENT) /* This is just a timing problem. */
		continue;
	    error("Can't open existing lock file %s: %m", lock_file);
	    break;
	}
#ifndef LOCK_BINARY
	n = read(fd, lock_buffer, 11);
#else
	n = read(fd, &pid, sizeof(pid));
#endif /* LOCK_BINARY */
	(void) close(fd);
	fd = -1;
	if (n <= 0) {
	    error("Can't read pid from lock file %s", lock_file);
	    break;
	}

	/* See if the process still exists. */
#ifndef LOCK_BINARY
	lock_buffer[n] = 0;
	pid = atoi(lock_buffer);
#endif /* LOCK_BINARY */
	if (pid == getpid())
	    return (1);		/* somebody else locked it for us */
	if (pid == 0
	    || (kill(pid, 0) == -1 && errno == ESRCH)) {
	    if (unlink (lock_file) == 0) {
		notice("Removed stale lock on %s (pid %d)", dev, pid);
		continue;
	    }
	    warn("Couldn't remove stale lock on %s", dev);
	} else
	    notice("Device %s is locked by pid %d", dev, pid);
	break;
    }

    if (fd < 0) {
	lock_file[0] = 0;
	return (-1);
    }

    pid = getpid();
#ifndef LOCK_BINARY
    (void) slprintf(lock_buffer, sizeof(lock_buffer), "%10d\n", pid);
    (void) write (fd, lock_buffer, 11);
#else
    (void) write(fd, &pid, sizeof (pid));
#endif
    (void) close(fd);
    return (0);

#endif
}

/*
 * relock - called to update our lockfile when we are about to detach,
 * thus changing our pid (we fork, the child carries on, and the parent dies).
 * Note that this is called by the parent, with pid equal to the pid
 * of the child.  This avoids a potential race which would exist if
 * we had the child rewrite the lockfile (the parent might die first,
 * and another process could think the lock was stale if it checked
 * between when the parent died and the child rewrote the lockfile).
 */
int
relock(pid)
    int pid;
{
#ifdef LOCKLIB
    /* XXX is there a way to do this? */
    return (-1);
#else /* LOCKLIB */

    int fd;
    char lock_buffer[12];

    if (lock_file[0] == 0)
	return (-1);
    fd = open(lock_file, O_WRONLY, 0);
    if (fd < 0) {
	error("Couldn't reopen lock file %s: %m", lock_file);
	lock_file[0] = 0;
	return (-1);
    }

#ifndef LOCK_BINARY
    (void) slprintf(lock_buffer, sizeof(lock_buffer), "%10d\n", pid);
    (void) write (fd, lock_buffer, 11);
#else
    (void) write(fd, &pid, sizeof(pid));
#endif /* LOCK_BINARY */
    (void) close(fd);
    return (0);

#endif /* LOCKLIB */
}

/*
 * unlock - remove our lockfile
 */
void
unlock()
{
    if (lock_file[0]) {
#ifdef LOCKLIB
	(void) rmlock(lock_file, (void *) 0);
#else
	(void) unlink(lock_file);
#endif
	lock_file[0] = 0;
    }
}

const char *
signal_name(int signum)
{
#if defined(SOL2) || defined(__linux__) || defined(_linux_)
    const char *cp;

    if ((cp = strsignal(signum)) != NULL)
	return (cp);
#else
    extern char *sys_siglist[];
    extern int sys_nsig;

    if (signum >= 0 && signum < sys_nsig && sys_siglist[signum] != NULL)
	return (sys_siglist[signum]);
#endif
    return ("??");
}
