/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2009 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*               Roland Mainz <roland.mainz@nrubsig.org>                *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include	<shell.h>
#include	<stdio.h>
#include	<stdbool.h>
#include	<option.h>
#include	<stk.h>
#include	<tm.h>
#include	"name.h"
#undef nv_isnull
#ifndef SH_DICT
#   define SH_DICT     "libshell"
#endif
#include	<poll.h>
#ifdef __GNUC__
#include <alloca.h>
#endif /* __GNUC__ */

#define sh_contexttoshb(context)	((Shbltin_t*)(context))
#define sh_contexttoshell(context)	((context)?(sh_contexttoshb(context)->shp):(NULL))

static const char sh_optpoll[] =
"[-?\n@(#)$Id: poll (AT&T Labs Research) 2009-05-14 $\n]"
"[-author?Roland Mainz <roland.mainz@nrubsig.org]"
"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"
"[+NAME? poll - input/output multiplexing]"
"[+DESCRIPTION?The poll command provides applications with a mechanism "
	"for multiplexing input/output over a set of file descriptors. "
	"For each member of the array variable \bvar\b, "
	"poll examines the given file descriptor in the subscript \b.fd\b "
	"for the event(s) specified in the subscript \b.events\b."
	"The poll command identifies those file descriptors on which an "
	"application can read or write data, or on which certain events have "
	"occurred.]"
"[+?The \bvar\b argument specifies the file descriptors to be examined "
	"and the events of interest for each file descriptor. "
	"It is a array of structured variables with one member for each open "
	"file descriptor of interest. The array's members contain the following "
	"subscripts:]{"
		"[+?\b.fd\b       # file descriptor]"
		"[+?\b.events\b   # requested events]"
		"[+?\b.revents\b  # returned event]"
	"}"
"[+?The \bfd\b variable specifies an open file descriptor and the "
	"\bevents\b and \brevents\b members are strings constructed from "
	"a concaternation of the following event flags, seperated by '|':]"
	"{ "
	"[+POLLIN?Data other than high priority data may be "
		"read without blocking. For STREAMS, this "
		"flag is set in revents even if the message "
		"is of zero length.]"
	"[+POLLRDNORM?Normal data (priority band equals 0) may be "
		"read without blocking. For STREAMS, this "
		"flag is set in revents even if the message "
		"is of zero length.]"
	"[+POLLRDBAND?Data from a non-zero priority band may be "
		"read without blocking. For STREAMS, this "
		"flag is set in revents even if the message "
		"is of zero length.]"
	"[+POLLPRI?High priority data may be received without "
		"blocking. For STREAMS, this flag is set in "
		"revents even if the message is of zero "
		"length.]"
	"[+POLLOUT?Normal data (priority band equals 0) may be "
		"written without blocking.]"
	"[+POLLWRNORM?The same as POLLOUT.]"
	"[+POLLWRBAND?Priority data (priority band > 0) may be "
		"written.  This event only examines bands "
		"that have been written to at least once.]"
	"[+POLLERR?An error has occurred on the device or "
		"stream.  This flag is only valid in the "
		"revents bitmask; it is not used in the "
		"events member.]"
	"[+POLLHUP?A hangup has occurred on the stream. This "
		"event and POLLOUT are mutually exclusive; a "
		"stream can never be writable if a hangup has "
		"occurred. However, this event and POLLIN, "
		", POLLRDBAND, or POLLPRI are not "
		"mutually exclusive. This flag is only valid "
		"in the revents bitmask; it is not used in "
		"the events member.]"
	"[+POLLNVAL?The specified fd value does not belong to an "
		"open file. This flag is only valid in the "
		"revents member; it is not used in the events "
		"member.]"
   "}"
"]"

"[+?If the value fd is less than 0, events is ignored and "
	"revents is set to 0 in that entry on return from poll.]"

"[+?The results of the poll query are stored in the revents "
	"member in the \bvar\b structure. POLL*-strings are set in the \brevents\b "
	"variable to indicate which of the requested events are true. "
	"If none are true, the \brevents\b will be an empty string when "
	"the poll command returns. The event flags "
	"POLLHUP, POLLERR, and POLLNVAL are always set in \brevents\b "
	"if the conditions they indicate are true; this occurs even "
	"though these flags were not present in events.]"

"[+?If none of the defined events have occurred on any selected "
	"file descriptor, poll waits at least timeout milliseconds "
	"for an event to occur on any of the selected file descriptors. "
	"On a computer where millisecond timing accuracy is not "
	"available, timeout is rounded up to the nearest legal value "
	"available on that system. If the value timeout is 0, poll "
	"returns immediately. If the value of timeout is -1, poll "
	"blocks until a requested event occurs or until the call is "
	"interrupted.]"

"[+?The poll function supports regular files, terminal and "
	"pseudo-terminal devices, STREAMS-based files, FIFOs and "
	"pipes. The behavior of poll on elements of fds that refer "
	"to other types of file is unspecified.]"

"[+?The poll function supports sockets.]"

"[+?A file descriptor for a socket that is listening for connections "
	"will indicate that it is ready for reading, once connections "
	"are available. A file descriptor for a socket that "
	"is connecting asynchronously will indicate that it is ready "
	"for writing, once a connection has been established.]"
 
"[+?Regular files always poll TRUE for reading and writing.]"

"[e:eventarray]:[fdcount?Upon successful completion, an indexed array "
	"of strings is returned which contains a list of array subscripts "
	"in the poll array which received events.]"
"[t:timeout]:[seconds?Timeout in seconds. If the value timeout is 0, "
	"poll returns immediately. If the value of timeout is -1, poll "
	"blocks until a requested event occurs or until the call is "
	"interrupted.]"
"[T:mtimeout]:[milliseconds?Timeout in milliseconds. If the value timeout is 0, "
	"poll returns immediately. If the value of timeout is -1, poll "
	"blocks until a requested event occurs or until the call is "
	"interrupted.]"
"\n"
"\nvar\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bopen\b(1),\btmpfile\b(1),\bdup\b(1),\bclose\b(1),\bpoll\b(2)]"
;

/*
 * |mystpcpy| - like |strcpy()| but returns the end of the buffer
 *
 * Copy string s2 to s1.  s1 must be large enough.
 * return s1-1 (position of string terminator ('\0') in destnation buffer).
 */
static
char *mystpcpy(char *s1, const char *s2)
{
        while (*s1++ = *s2++)
                ;
        return (s1-1);
}

static
Namval_t *nv_open_fmt(Dt_t *dict, int flags, const char *namefmt, ...)
{
	char 	varnamebuff[PATH_MAX];
	va_list	ap;

	va_start(ap, namefmt);
	vsnprintf(varnamebuff, sizeof(varnamebuff), namefmt, ap);
	va_end(ap);
	
	return nv_open(varnamebuff, dict, flags);
}

static
int poll_strtoevents(const char *str)
{
	int events = 0;
    
	if (strstr(str, "POLLIN"))     events |= POLLIN;
	if (strstr(str, "POLLRDNORM")) events |= POLLRDNORM;
	if (strstr(str, "POLLRDBAND")) events |= POLLRDBAND;
	if (strstr(str, "POLLPRI"))    events |= POLLPRI;
	if (strstr(str, "POLLOUT"))    events |= POLLOUT;
	if (strstr(str, "POLLWRNORM")) events |= POLLWRNORM;
	if (strstr(str, "POLLWRBAND")) events |= POLLWRBAND;
	if (strstr(str, "POLLERR"))    events |= POLLERR;
	if (strstr(str, "POLLHUP"))    events |= POLLHUP;
	if (strstr(str, "POLLNVAL"))   events |= POLLNVAL;

	return events;
}


static
void poll_eventstostr(char *s, int events)
{
	*s='\0';
	if (!events)
		return;
	
	if (events & POLLIN)		s=mystpcpy(s, "POLLIN|");
	if (events & POLLRDNORM)	s=mystpcpy(s, "POLLRDNORM|");
	if (events & POLLRDBAND)	s=mystpcpy(s, "POLLRDBAND|");
	if (events & POLLPRI)		s=mystpcpy(s, "POLLPRI|");
	if (events & POLLOUT)		s=mystpcpy(s, "POLLOUT|");
	if (events & POLLWRNORM)	s=mystpcpy(s, "POLLWRNORM|");
	if (events & POLLWRBAND)	s=mystpcpy(s, "POLLWRBAND|");
	if (events & POLLERR)		s=mystpcpy(s, "POLLERR|");
	if (events & POLLHUP)		s=mystpcpy(s, "POLLHUP|");
	if (events & POLLNVAL)		s=mystpcpy(s, "POLLNVAL|");

	/* Remove trailling '|' */
	s--;
	if(*s=='|')
		*s='\0';
}

#undef  getconf
#define getconf(x)      strtol(astconf(x,NiL,NiL),NiL,0)
		
extern int b_poll(int argc, char *argv[], void *extra)
{
	Namval_t *np;
	Shell_t *shp = sh_contexttoshell(extra);
	char *varname;
	int n;
	int fd;
	nfds_t numpollfd = 0;
	int i;
	char *s;
	double timeout = -1.;
	char buff[PATH_MAX*2+1]; /* enogth to hold two variable names */
	char *eventarrayname = NULL;

	while (n = optget(argv, sh_optpoll)) switch (n)
	{
	    case 't':
	    case 'T':
		errno = 0;
		timeout = strtod(opt_info.arg, (char **)NULL);	
		if (errno != 0)
			errormsg(SH_DICT, ERROR_system(1), "%s: invalid timeout", opt_info.arg);

		/* -t uses seconds, -T milliseconds */
		if (n == 't')
			timeout *= 1000.;
		break;
	    case 'e':
	    	eventarrayname = opt_info.arg;
		break;
	    case ':':
		errormsg(SH_DICT, 2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT, ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(argc!=1)
		errormsg(SH_DICT, ERROR_usage(2), optusage((char*)0));

        varname = argv[0];

	Namval_t *array_np, *array_np_sub;
	const char *subname;

	array_np = nv_open(varname, shp->var_tree, NV_NOFAIL|NV_NOADD);
	if (!array_np)
		errormsg(SH_DICT, ERROR_system(1), "cannot find array variable %s", varname);
	if(!nv_isattr(array_np, NV_ARRAY))
		errormsg(SH_DICT, ERROR_system(1), "variable %s is not an array", varname);

	/* Count number of array elememts. We need to do it "manually" to
	 * handle sparse indexed and associative arrays */
	nv_putsub(array_np, NULL, ARRAY_SCAN);
	array_np_sub = array_np;
	do
	{
		if (!(subname=nv_getsub(array_np_sub)))
			break;
		numpollfd++;
	} while( array_np_sub && nv_nextsub(array_np_sub) );

#ifdef __GNUC__
        /*
         * Allocate stack space via |alloca()| for gcc builds since ctfconvert
         * is unable to handle VLAs from gcc. We need this until CR #6379193
	 * is fixed.
         */
	struct pollfd *pollfd = alloca(sizeof(struct pollfd)*(numpollfd+1));
#else
	/* We must allocate one more entry with VLA with zero elements do not work with all compilers */
	struct pollfd pollfd[numpollfd+1];
#endif /* __GNUC__ */

	nv_putsub(array_np, NULL, ARRAY_SCAN);
	array_np_sub = array_np;
	i = 0;
	do
	{
		if (!(subname=nv_getsub(array_np_sub)))
			break;

		np = nv_open_fmt(shp->var_tree, NV_NOFAIL|NV_NOADD, "%s[%s].fd", varname, subname);
		if (!np)
			errormsg(SH_DICT, ERROR_system(1), "missing pollfd %s[%s].fd", varname, subname);
		fd = (int)nv_getnum(np);
		if (fd < 0 || fd > OPEN_MAX)
			errormsg(SH_DICT, ERROR_system(1), "invalid pollfd fd %d", fd);
		nv_close(np);
		pollfd[i].fd = fd;

		np = nv_open_fmt(shp->var_tree, NV_NOFAIL|NV_NOADD, "%s[%s].events", varname, subname);
		if (!np)
			errormsg(SH_DICT, ERROR_system(1), "missing pollfd %s[%s].events", varname, subname);

		s = nv_getval(np);
		if (!s)
			errormsg(SH_DICT, ERROR_system(1), "missing pollfd events value");
		pollfd[i].events  = poll_strtoevents(s);
		nv_close(np);

		pollfd[i].revents = 0;
		
		i++;
	} while( array_np_sub && nv_nextsub(array_np_sub) );
	
	n = poll(pollfd, numpollfd, timeout);
	/* FixMe: EGAIN and EINTR may require extra handling */
	if (n < 0)
		errormsg(SH_DICT, ERROR_system(1), "failure");

	if (eventarrayname)
	{
		np = nv_open_fmt(shp->var_tree, NV_VARNAME|NV_ARRAY|NV_NOFAIL, "%s", eventarrayname);
		if (!np)
			errormsg(SH_DICT, ERROR_system(1), "couldn't create poll count variable %s", eventarrayname);
		nv_close(np);
	}

	nv_putsub(array_np, NULL, ARRAY_SCAN);
	array_np_sub = array_np;
	i = 0;
	do
	{
		if (!(subname=nv_getsub(array_np_sub)))
			break;
	
		np = nv_open_fmt(shp->var_tree, NV_NOFAIL, "%s[%s].revents", varname, subname);
		if (!np)
			errormsg(SH_DICT, ERROR_system(1), "couldn't create pollfd %s[%s].revents", varname, subname);

		poll_eventstostr(buff, pollfd[i].revents);
	
		nv_putval(np, buff, 0);
		nv_close(np);
		
		if (eventarrayname && pollfd[i].revents)
		{
			sprintf(buff, "%s+=( '%s' )", eventarrayname, subname);
			sh_trap(buff, 0);
		}
		
		i++;
	} while( array_np_sub && nv_nextsub(array_np_sub) );
	
	nv_close(array_np);
	
	return(0);
}
