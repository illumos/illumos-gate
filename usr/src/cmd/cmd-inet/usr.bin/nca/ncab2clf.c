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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 *	Converts binary log files to CLF (Common Log Format).
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <locale.h>
#include <errno.h>
#include <time.h>
#include <synch.h>
#include <syslog.h>

#ifndef	TRUE
#define	TRUE	1
#endif	/* TRUE */

#ifndef	FALSE
#define	FALSE	0
#endif	/* FALSE */

#include "ncadoorhdr.h"
#include "ncalogd.h"

extern char *gettext();

typedef	enum	{	/* Boolean type */
	false = 0,
	true  = 1
} bool;

static const char *const
g_method_strings[8] = {
	"UNKNOWN",
	"OPTIONS",
	"GET",
	"HEAD",
	"POST",
	"PUT",
	"DELETE",
	"TRACE"
};

/* Short month strings */
static const char * const sMonthStr [12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec",
};

#define	SEC_PER_MIN		(60)
#define	SEC_PER_HOUR		(60*60)
#define	SEC_PER_DAY		(24*60*60)
#define	SEC_PER_YEAR		(365*24*60*60)
#define	LEAP_TO_70		(70/4)

#define	KILO_BYTE		(1024)
#define	MEGA_BYTE		(KILO_BYTE * KILO_BYTE)
#define	GIGA_BYTE		(KILO_BYTE * MEGA_BYTE)

#define	CLF_DATE_BUF_LENGTH	(128)
#define	OUTFILE_BUF_SIZE	(256 * KILO_BYTE)

static bool	g_enable_directio = true;
static ssize_t	g_invalid_count = 0;
static ssize_t	g_skip_count = 0;
static char	*g_start_time_str = NULL;

/* init value must match logd & NCA kmod */
static ssize_t	g_n_log_upcall = 0;

/* input binary file was written in 64k chunks by default  */
static ssize_t	g_infile_blk_size = NCA_DEFAULT_LOG_BUF_SIZE;

/* num of output records, by default infinite */
static ssize_t	g_out_records = -1;

/* start time for log output, default none (i.e. output all) */
static struct tm g_start_time;

/*
 * http_version(version)
 *
 * Returns out the string of a given http version
 */

static char *
http_version(int http_ver)
{
	char	*ver_num;

	switch (http_ver) {
	case HTTP_0_9:
	case HTTP_0_0:
		ver_num = "HTTP/0.9";
		break;
	case HTTP_ERR:
	case HTTP_1_0:
		ver_num = "HTTP/1.0";
		break;
	case HTTP_1_1:
		ver_num = "HTTP/1.1";
		break;
	default:
		ver_num = "HTTP/unknown";
	}

	return (ver_num);
}

static bool
valid_version(int http_ver)
{
	switch (http_ver) {
	case HTTP_0_9:
	case HTTP_0_0:
	case HTTP_1_0:
	case HTTP_1_1:
		return (true);
	default:
		break;
	}

	return (false);
}

static bool
valid_method(int method)
{
	switch (method) {
	case NCA_OPTIONS:
	case NCA_GET:
	case NCA_HEAD:
	case NCA_POST:
	case NCA_PUT:
	case NCA_DELETE:
	case NCA_TRACE:
		return (true);
	default:
		break;
	}

	return (false);
}

/*
 * http_method
 *
 *   Returns the method string for the given method.
 */

static char *
http_method(int method)
{
	if (method < sizeof (g_method_strings) / sizeof (g_method_strings[0]))
		return ((char *)(g_method_strings[method]));
	else
		return ((char *)(g_method_strings[0]));
}

/* sMonth: Return short month string */

static const char *
sMonth(int index)
{
	return (sMonthStr[index]);
}

/*
 * Debug formatting routine.  Returns a character string representation of the
 * addr in buf, of the form xxx.xxx.xxx.xxx.  This routine takes the address
 * as a pointer.  The "xxx" parts including left zero padding so the final
 * string will fit easily in tables.  It would be nice to take a padding
 * length argument instead.
 */

static char *
ip_dot_saddr(uchar_t *addr, char *buf)
{
	(void) sprintf(buf, "%03d.%03d.%03d.%03d",
	    addr[0] & 0xFF, addr[1] & 0xFF, addr[2] & 0xFF, addr[3] & 0xFF);
	return (buf);
}

/*
 * Debug formatting routine.  Returns a character string representation of the
 * addr in buf, of the form xxx.xxx.xxx.xxx.  This routine takes the address
 * in the form of a ipaddr_t and calls ip_dot_saddr with a pointer.
 */

static char *
ip_dot_addr(ipaddr_t addr, char *buf)
{
	return (ip_dot_saddr((uchar_t *)&addr, buf));
}

static int
http_clf_date(char *buf, int bufsize, time_t t)
{
	struct tm	local_time;
	long		time_zone_info;
	char		sign;

	if (localtime_r(&t, &local_time) == NULL)
		return (0);

	if (g_start_time.tm_year > 0 &&
	    (local_time.tm_year < g_start_time.tm_year ||
	    (local_time.tm_year == g_start_time.tm_year &&
	    local_time.tm_mon < g_start_time.tm_mon ||
	    (local_time.tm_mon == g_start_time.tm_mon &&
	    local_time.tm_mday < g_start_time.tm_mday ||
	    (local_time.tm_mday == g_start_time.tm_mday &&
	    local_time.tm_hour < g_start_time.tm_hour ||
	    (local_time.tm_hour == g_start_time.tm_hour &&
	    local_time.tm_min < g_start_time.tm_min ||
	    (local_time.tm_min == g_start_time.tm_min &&
	    local_time.tm_sec < g_start_time.tm_sec))))))) {
		/* clf record before the specified start time */
		return (1);
	}

	if (local_time.tm_isdst)
		time_zone_info = -timezone + SEC_PER_HOUR;
	else
		time_zone_info = -timezone;

	if (time_zone_info < 0) {
		sign = '-';
		time_zone_info = -time_zone_info;
	} else {
		sign = '+';
	}

	(void) snprintf(buf, bufsize,
	    "[%02d/%s/%04d:%02d:%02d:%02d %c%02ld%02ld]",
	    local_time.tm_mday, sMonth(local_time.tm_mon),
	    1900 + local_time.tm_year, local_time.tm_hour,
	    local_time.tm_min, local_time.tm_sec,
	    sign, time_zone_info / SEC_PER_HOUR,
	    time_zone_info % SEC_PER_HOUR);

	return (0);
}

/*
 * xmalloc(size)
 * Abort if malloc fails
 */

static void *
xmalloc(size_t size)
{
	void *p;

	if (! size)
		size = 1;

	if ((p = malloc(size)) == NULL) {
		syslog(LOG_ERR, gettext("Error: ncab2clf: Out of memory\n"));
		abort();
	}

	return (p);
}

/*
 * xstrdup(string)
 *   duplicate string
 */

static char *
xstrdup(const char *string)
{
	char	*new_string;

	if (string) {
		new_string = xmalloc(strlen(string) + 1);
		(void) strcpy(new_string, string);

		return (new_string);
	}

	return (NULL);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "\nncab2clf [-Dhv] [-b <block-size>] [-i <binary-log-file>] "
	    "[-n <n>]\n"
	    "    [-o <output-file>] [-s <date/time>]\n"
	    "\tconverts a NCA binary log file to HTTP CLF"
	    " (Common Log Format)\n\n"
	    "\t-b <block-size>\n"
	    "\t\tinput file blocking size in KB\n"
	    "\t\t- default is 64K bytes\n"
	    "\t-D\tdisable directio on <output-file-name>\n"
	    "\t-h\tthis usage message\n"
	    "\t-i <binary-log-file>\n"
	    "\t\tspecify input file\n"
	    "\t-n <n>\n"
	    "\t\toutput <n> CLF records\n"
	    "\t-o <output-file>\n"
	    "\t\tspecify output file\n"
	    "\t-s <date/time>\n"
	    "\t\tskip any records before <date/time>\n"
	    "\t\t- <date/time> may be in CLF format\n"
	    "\t\t- <date/time> may be in time format as specified "
	    "by touch(1)\n"
	    "\t-v\tverbose output\n"
	    "\tNote: if no <output-file> - output goes to standard output\n"
	    "\tNote: if no <binary-log-file> - input is taken from standard "
	    "input\n"));

	exit(3);
}

/*
 * atoi_for2(p, value)
 *   - stores the numerical value of the two digit string p into value
 *   - return TRUE upon success and FALSE upon failure
 */

static int
atoi_for2(char *p, int *value)
{

	*value = (*p - '0') * 10 + *(p+1) - '0';
	if ((*value < 0) || (*value > 99))
		return (FALSE);
	return (TRUE);
}

/*
 * parse_time(t, tm)
 *   - parses the string t to retrieve the UNIX time format as specified by
 *     touch(1).
 *   - return TRUE upon success and FALSE upon failure
 */

static int
parse_time(char *t, struct tm *tm)
{
	int		century = 0;
	int		seconds = 0;
	time_t		when;
	char		*p;

	/*
	 * time in the following format (defined by the touch(1) spec):
	 *	[[CC]YY]MMDDhhmm[.SS]
	 */
	if ((p = strchr(t, '.')) != NULL) {
		if (strchr(p+1, '.') != NULL)
			return (FALSE);
		if (!atoi_for2(p+1, &seconds))
			return (FALSE);
		*p = '\0';
	}

	when = time(0);
	bzero(tm, sizeof (struct tm));
	tm->tm_year = localtime(&when)->tm_year;

	switch (strlen(t)) {
		case 12:	/* CCYYMMDDhhmm */
			if (!atoi_for2(t, &century))
				return (FALSE);
			t += 2;
			/* FALLTHROUGH */
		case 10:	/* YYMMDDhhmm */
			if (!atoi_for2(t, &tm->tm_year))
				return (FALSE);
			t += 2;
			if (century == 0) {
				if (tm->tm_year < 69)
					tm->tm_year += 100;
			} else
				tm->tm_year += (century - 19) * 100;
			/* FALLTHROUGH */
		case 8:		/* MMDDhhmm */
			if (!atoi_for2(t, &tm->tm_mon))
				return (FALSE);
			tm->tm_mon--;
			t += 2;

			if (!atoi_for2(t, &tm->tm_mday))
				return (FALSE);
			t += 2;

			if (!atoi_for2(t, &tm->tm_hour))
				return (FALSE);
			t += 2;

			if (!atoi_for2(t, &tm->tm_min))
				return (FALSE);

			tm->tm_sec = seconds;
			break;
		default:
			return (FALSE);
	}

	return (TRUE);
}

static void
close_files(int ifd, int ofd)
{
	if (ifd != STDIN_FILENO)
		(void) close(ifd);

	if (ofd != STDOUT_FILENO)
		(void) close(ofd);
}

/*
 * Read the requested number of bytes from the given file descriptor
 */

static ssize_t
read_n_bytes(int fd, char *buf, ssize_t bufsize)
{
	ssize_t	num_to_read = bufsize;
	ssize_t	num_already_read = 0;
	ssize_t	i;

	while (num_to_read > 0) {

		i = read(fd, &(buf[num_already_read]), num_to_read);
		if (i < 0) {
			if (errno == EINTR)
				continue;
			else
				(void) fprintf(stderr, gettext(
				    "Error: ncab2clf: "
				    "reading input file: %s\n"),
				    strerror(errno));
			return (-1);	/* some wierd interrupt */
		}

		if (i == 0)
			break;

		num_already_read += i;
		num_to_read -= i;
	}

	return (num_already_read);
}

/*
 * Write the requested number of bytes to the given file descriptor
 */

static ssize_t
write_n_bytes(int fd, char *buf, ssize_t bufsize)
{
	ssize_t	num_to_write = bufsize;
	ssize_t	num_written = 0;
	ssize_t	i;

	while (num_to_write > 0) {

		i = write(fd, &(buf[num_written]), num_to_write);
		if (i < 0) {
			if (errno == EINTR)
				continue;
			else
				(void) fprintf(stderr, gettext(
				    "Error: ncab2clf: "
				    "writing output file: %s\n"),
				    strerror(errno));
			return (-1);	/* some wierd interrupt */
		}

		num_written += i;
		num_to_write -= i;
	}

	return (num_written);
}

/* do constraint checks and determine if it's a valid header */

static bool
is_valid_header(void *ibuf)
{
	nca_log_buf_hdr_t	*h;
	nca_log_stat_t		*s;

	h = (nca_log_buf_hdr_t *)ibuf;

	/* Do some validity checks on ibuf */

	if (((h->nca_loghdr).nca_version != NCA_LOG_VERSION1) ||
	    ((h->nca_loghdr).nca_op != log_op)) {
		return (false);
	}

	s = &(h->nca_logstats);

	if (g_n_log_upcall == 0) {
		g_n_log_upcall = s->n_log_upcall;
	} else {
		if ((++g_n_log_upcall) != (ssize_t)s->n_log_upcall) {
			(void) fprintf(stderr, gettext(
			    "Warning: ncab2clf:"
			    " expected record number (%d) is"
			    " different from the one seen (%d)\n."
			    " Resetting the expected record"
			    " number.\n"), g_n_log_upcall, s->n_log_upcall);

			g_n_log_upcall = s->n_log_upcall;
		}
	}

	return (true);
}

/* convert input binary buffer into CLF */

static int
b2clf_buf(
	void	*ibuf,
	char	*obuf,
	ssize_t	isize,
	ssize_t	osize,
	ssize_t	*out_size)
{
	nca_log_buf_hdr_t	*h;
	nca_log_stat_t		*s;
	nca_request_log_t	*r;

	char	*br;
	void	*er;
	char	ip_buf[64];
	ssize_t	max_input_size, num_bytes_read;
	int	n_recs;
	bool	error_seen;

	ssize_t	count;
	char	clf_timebuf[CLF_DATE_BUF_LENGTH];
	char	*method;
	char	*http_version_string;
	char	*ruser;
	char	*req_url;
	char	*remote_ip;

	h = (nca_log_buf_hdr_t *)ibuf;
	s = &(h->nca_logstats);
	r = (nca_request_log_t *)(&(h[1]));

	/* OK, it's a valid buffer which we can use, go ahead and convert it */

	max_input_size = (ssize_t)isize - sizeof (nca_log_buf_hdr_t);

	*out_size = 0;
	error_seen = false;
	num_bytes_read = 0;
	for (n_recs = 0; n_recs < s->n_log_recs; n_recs++) {

		/* Make sure there is enough space in the output buffer */

		if ((*out_size >= osize) ||
		    (num_bytes_read >= max_input_size)) {
			error_seen = true;
			break;
		}

		if (http_clf_date(clf_timebuf, sizeof (clf_timebuf),
		    ((time_t)r->start_process_time))) {
			/* A start time was speced and we're not there yet */
			++g_skip_count;
			goto skip;
		}

		/* Only logs valid HTTP ops */

		if ((! valid_method((int)r->method)) ||
		    (! valid_version((int)r->version))) {
			++g_invalid_count;
			goto skip;
		}

		method = http_method((int)r->method);
		http_version_string = http_version((int)r->version);

		remote_ip = ip_dot_addr(r->remote_host, (char *)&ip_buf);
		if (r->remote_user_len) {
			ruser = NCA_REQLOG_RDATA(r, remote_user);
		} else {
			ruser = "-";
		}

		if (r->request_url_len) {
			req_url = NCA_REQLOG_RDATA(r, request_url);
		} else {
			req_url = "UNKNOWN";
		}

		count = (ssize_t)snprintf(&(obuf[*out_size]), osize - *out_size,
		    "%s %s %s %s \"%s %s %s\" %d %d\n",
		    ((remote_ip) ? remote_ip : "-"),
		    /* should be remote_log_name */
		    "-",
		    ruser,
		    clf_timebuf,
		    method,
		    req_url,
		    http_version_string,
		    r->response_status,
		    r->response_len);

		*out_size += count;
	skip:
		br = (char *)r;
		er = ((char *)r) + NCA_LOG_REC_SIZE(r);

		/*LINTED*/
		r = (nca_request_log_t *)NCA_LOG_ALIGN(er);
		num_bytes_read += (ssize_t)(((char *)r) - br);
		if (g_out_records > 0 && --g_out_records == 0)
			break;
	}

	if (error_seen) {
		(void) fprintf(stderr, gettext(
		    "Error: ncab2clf: Input buffer not fully converted.\n"));

		if (n_recs != s->n_log_recs)
			(void) fprintf(stderr, gettext(
			    "Warning: ncab2clf: "
			    "Converted only %d of %d records\n"),
			    n_recs, s->n_log_recs);
	}

	return (0);
}

static int
b2clf(int ifd, int ofd)
{
	char	*ibuf;
	char	*obuf;
	bool	error_seen;
	bool	eof_seen;
	ssize_t	num_iterations, ni, nh, no, olen;

	nca_log_buf_hdr_t	*h;
	nca_log_stat_t		*s;

	ibuf = xmalloc(g_infile_blk_size);
	obuf = xmalloc(OUTFILE_BUF_SIZE);
	error_seen = false;

	eof_seen = false;
	num_iterations = 0;
	while (! eof_seen && g_out_records != 0) {
		++num_iterations;

		nh = ni = no = 0;

		/* read the binary header first */
		nh = read_n_bytes(ifd, ibuf, sizeof (nca_log_buf_hdr_t));
		if (nh != sizeof (nca_log_buf_hdr_t)) {
			eof_seen = true;
			break;
		}

		if (! is_valid_header(ibuf)) {
			(void) fprintf(stderr, gettext(
			    "Error: ncab2clf: "
			    "Can't convert the input data to CLF\n"));
			continue;
		}

		/* read the data to be converted */
		/* LINTED */
		h = (nca_log_buf_hdr_t *)ibuf;
		s = &(h->nca_logstats);

		if (s->n_log_size == 0)
			continue;

		ni = read_n_bytes(ifd, &(ibuf[nh]), (ssize_t)s->n_log_size);
		if (ni < 0) {
			error_seen = true;
			break;
		} else if (ni < (ssize_t)s->n_log_size) {
			eof_seen = true;
		}

		if (ni == 0)
			break;

		/* convert binary input into text output */

		if (b2clf_buf(ibuf, obuf, ni + nh, OUTFILE_BUF_SIZE, &olen)) {
			(void) fprintf(stderr, gettext(
			    "Error: ncab2clf: "
			    "Can't convert the input data to CLF\n"));
			error_seen = true;
			break;
		}

		/* write out the text data */
		no = write_n_bytes(ofd, obuf, olen);
		if (no != olen) {
			error_seen = true;
			break;
		}

		bzero(ibuf, nh + ni);
		bzero(obuf, no);
	}

	free(ibuf);
	free(obuf);

	if (error_seen)
		return (-1);

	return (0);
}


int
main(int argc, char **argv)
{
	int	c;
	int	ifd;		/* input fd - binary log file */
	int	ofd;
	struct tm t;

	char	*infile = NULL;  /* input file name */
	char	*outfile = NULL; /* output file name */

	char	monstr[64];

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	/* parse any arguments */
	while ((c = getopt(argc, argv, "hvDi:o:b:n:s:")) != EOF) {
		switch (c) {
		case 'h':
			usage();
			break;
		case 'i':
			infile = xstrdup(optarg);
			break;
		case 'D':
			g_enable_directio = false;
			break;
		case 'o':
			outfile = xstrdup(optarg);
			break;
		case 'b':
			g_infile_blk_size = (KILO_BYTE * atoi(optarg));
			break;
		case 'n':
			g_out_records = atoi(optarg);
			break;
		case 's':
			g_start_time_str = strdup(optarg);
			bzero(&t, sizeof (t));
			if (sscanf(optarg, "%d/%3s/%d:%d:%d:%d", &t.tm_mday,
			    &monstr[0], &t.tm_year, &t.tm_hour, &t.tm_min,
			    &t.tm_sec) == 6) {
				/* Valid CLF time (e.g. 06/Apr/2001:09:14:14) */
				t.tm_mon = 0;
				do {
					if (strcasecmp(monstr,
					    sMonthStr[t.tm_mon]) == 0)
						break;
				} while (t.tm_mon++ < 12);
				t.tm_year -= 1900;
				g_start_time = t;
			} else if (parse_time(optarg, &t)) {
				g_start_time = t;
			} else {
				(void) fprintf(stderr,
				    gettext("Error: ncab2clf:"
				    " %s: unrecognized date/time.\n"),
				    optarg);
			}
			break;
		case 'v':
			(void) fprintf(stderr, gettext("Error: ncab2clf: "
			    "verbose functionality not yet supported\n"));
			exit(3);
			break;
		case '?':
			usage();
			break;
		}
	}

	/* set up the input stream */

	if (infile) {

		if ((ifd = open(infile, O_RDONLY)) < 0) {
			(void) fprintf(stderr,
			    gettext("Error: ncab2clf: "
			    "Failure to open binary log file %s: %s\n"),
			    infile, strerror(errno));
			exit(1);
		}

	} else {
		ifd = STDIN_FILENO;
	}

	/* set up the output stream */

	if (outfile) {

		if ((ofd = open(outfile, O_WRONLY|O_CREAT, 0644)) < 0) {
			(void) fprintf(stderr, gettext(
			    "Error: ncab2clf: "
			    "Failure to open output file %s: %s\n"),
			    outfile, strerror(errno));
			exit(1);
		}

		/* Enable directio on output stream if specified */

		if (g_enable_directio)
			(void) directio(ofd, DIRECTIO_ON);

	} else {
		ofd = STDOUT_FILENO;
	}

	if ((b2clf(ifd, ofd) != 0)) {
		close_files(ifd, ofd);
		exit(2);
	}

	close_files(ifd, ofd);

	if (g_invalid_count) {
		(void) fprintf(stderr, gettext("Warning: ncab2clf: %d"
		" number of invalid log records encountered in binary input"
		" file were skipped\n"), g_invalid_count);
	}
	if (g_skip_count) {
		(void) fprintf(stderr, gettext("Warning: ncab2clf:"
		    " %d log records in binary input file before %s"
		    " were skipped\n"),
		    g_skip_count, g_start_time_str);
	}

	return (0);
}
