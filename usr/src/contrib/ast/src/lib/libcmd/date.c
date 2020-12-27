/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * date -- set/display date
 */

static const char usage[] =
"[-?\n@(#)$Id: date (AT&T Research) 2011-01-27 $\n]"
USAGE_LICENSE
"[+NAME?date - set/list/convert dates]"
"[+DESCRIPTION?\bdate\b sets the current date and time (with appropriate"
"	privilege), lists the current date or file dates, or converts"
"	dates.]"
"[+?Most common \adate\a forms are recognized, including those for"
"	\bcrontab\b(1), \bls\b(1), \btouch\b(1), and the default"
"	output from \bdate\b itself.]"
"[+?If the \adate\a operand consists of 4, 6, 8, 10 or 12 digits followed"
"	by an optional \b.\b and two digits then it is interpreted as:"
"	\aHHMM.SS\a, \addHHMM.SS\a, \ammddHHMM.SS\a, \ammddHHMMyy.SS\a or"
"	\ayymmddHHMM.SS\a, or \ammddHHMMccyy.SS\a or \accyymmddHHMM.SS\a."
"	Conflicting standards and practice allow a leading or trailing"
"	2 or 4 digit year for the 10 and 12 digit forms; the X/Open trailing"
"	form is used to disambiguate (\btouch\b(1) uses the leading form.)"
"	Avoid the 10 digit form to avoid confusion. The digit fields are:]{"
"		[+cc?Century - 1, 19-20.]"
"		[+yy?Year in century, 00-99.]"
"		[+mm?Month, 01-12.]"
"		[+dd?Day of month, 01-31.]"
"		[+HH?Hour, 00-23.]"
"		[+MM?Minute, 00-59.]"
"		[+SS?Seconds, 00-60.]"
"}"
"[+?If more than one \adate\a operand is specified then:]{"
"		[+1.?Each operand sets the reference date for the next"
"			operand.]"
"		[+2.?The date is listed for each operand.]"
"		[+3.?The system date is not set.]"
"}"

"[a:access-time|atime?List file argument access times.]"
"[c:change-time|ctime?List file argument change times.]"
"[d:date?Use \adate\a as the current date and do not set the system"
"	clock.]:[date]"
"[e:epoch?Output the date in seconds since the epoch."
"	Equivalent to \b--format=%s\b.]"
"[E:elapsed?Interpret pairs of arguments as start and stop dates, sum the"
"	differences between all pairs, and list the result as a"
"	\bfmtelapsed\b(3) elapsed time on the standard output. If there are"
"	an odd number of arguments then the last time argument is differenced"
"	with the current time.]"
"[f:format?Output the date according to the \bstrftime\b(3) \aformat\a."
"	For backwards compatibility, a first argument of the form"
"	\b+\b\aformat\a is equivalent to \b-f\b format."
"	\aformat\a is in \bprintf\b(3) style, where %\afield\a names"
"	a fixed size field, zero padded if necessary,"
"	and \\\ac\a and \\\annn\a sequences are as in C. Invalid"
"	%\afield\a specifications and all other characters are copied"
"	without change. \afield\a may be preceded by \b%-\b to turn off"
"	padding or \b%_\b to pad with space, otherwise numeric fields"
"	are padded with \b0\b and string fields are padded with space."
"	\afield\a may also be preceded by \bE\b for alternate era"
"	representation or \bO\b for alternate digit representation (if"
"	supported by the current locale.) Finally, an integral \awidth\a"
"	preceding \afield\a truncates the field to \awidth\a characters."
"	The fields are:]:[format]{"
"		[+%?% character]"
"		[+a?abbreviated weekday name]"
"		[+A?full weekday name]"
"		[+b?abbreviated month name]"
"		[+B?full month name]"
"		[+c?\bctime\b(3) style date without the trailing newline]"
"		[+C?2-digit century]"
"		[+d?day of month number]"
"		[+D?date as \amm/dd/yy\a]"
"		[+e?blank padded day of month number]"
"		[+f?locale default override date format]"
"		[+F?%ISO 8601:2000 standard date format; equivalent to Y-%m-%d]"
"		[+g?\bls\b(1) \b-l\b recent date with \ahh:mm\a]"
"		[+G?\bls\b(1) \b-l\b distant date with \ayyyy\a]"
"		[+h?abbreviated month name]"
"		[+H?24-hour clock hour]"
"		[+i?international \bdate\b(1) date with time zone type name]"
"		[+I?12-hour clock hour]"
"		[+j?1-offset Julian date]"
"		[+J?0-offset Julian date]"
"		[+k?\bdate\b(1) style date]"
"		[+K?all numeric date; equivalent to \b%Y-%m-%d+%H:%M:%S\b; \b%_[EO]]K\b for space separator, %OK adds \b.%N\b, \b%EK\b adds \b%.N%z\b, \b%_EK\b adds \b.%N %z\b]"
"		[+l?\bls\b(1) \b-l\b date; equivalent to \b%Q/%g/%G/\b]"
"		[+L?locale default date format]"
"		[+m?month number]"
"		[+M?minutes]"
"		[+n?newline character]"
"		[+N?nanoseconds 000000000-999999999]"
"		[+p?meridian (e.g., \bAM\b or \bPM\b)]"
"		[+q?time zone type name (nation code)]"
"		[+Q?\a<del>recent<del>distant<del>\a: \a<del>\a is a unique"
"			delimter character; \arecent\a format for recent"
"			dates, \adistant\a format otherwise]"
"		[+r?12-hour time as \ahh:mm:ss meridian\a]"
"		[+R?24-hour time as \ahh:mm\a]"
"		[+s?number of seconds since the epoch; \a.prec\a preceding"
"			\bs\b appends \aprec\a nanosecond digits, \b9\b if"
"			\aprec\a is omitted]"
"		[+S?seconds 00-60]"
"		[+t?tab character]"
"		[+T?24-hour time as \ahh:mm:ss\a]"
"		[+u?weekday number 1(Monday)-7]"
"		[+U?week number with Sunday as the first day]"
"		[+V?ISO week number (i18n is \afun\a)]"
"		[+w?weekday number 0(Sunday)-6]"
"		[+W?week number with Monday as the first day]"
"		[+x?locale date style that includes month, day and year]"
"		[+X?locale time style that includes hours and minutes]"
"		[+y?2-digit year (you'll be sorry)]"
"		[+Y?4-digit year]"
"		[+z?time zone \aSHHMM\a west of GMT offset where S is"
"			\b+\b or \b-\b, use pad _ for \aSHH:MM\a]"
"		[+Z?time zone name]"
"		[+=[=]][-+]]flag?set (default or +) or clear (-) \aflag\a"
"			for the remainder of \aformat\a, or for the remainder"
"			of the process if \b==\b is specified. \aflag\a may be:]{"
"			[+l?enable leap second adjustments]"
"			[+n?convert \b%S\b as \b%S.%N\b]"
"			[+u?UTC time zone]"
"		}"
"		[+#?equivalent to %s]"
"		[+??alternate?use \aalternate\a format if a default format"
"			override has not been specified, e.g., \bls\b(1) uses"
"			\"%?%l\"; export TM_OPTIONS=\"format='\aoverride\a'\""
"			to override the default]"
"}"
"[i:incremental|adjust?Set the system time in incrementatl adjustments to"
"	avoid complete time shift shock. Negative adjustments still maintain"
"	monotonic increasing time. Not available on all systems.]"
"[L:last?List only the last time for multiple \adate\a operands.]"
"[l:leap-seconds?Include leap seconds in time calculations. Leap seconds"
"	after the ast library release date are not accounted for.]"
"[m:modify-time|mtime?List file argument modify times.]"
"[n!:network?Set network time.]"
"[p:parse?Add \aformat\a to the list of \bstrptime\b(3) parse conversion"
"	formats. \aformat\a follows the same conventions as the"
"	\b--format\b option, with the addition of these format"
"	fields:]:[format]{"
"		[+|?If the format failed before this point then restart"
"			the parse with the remaining format.]"
"		[+&?Call the \btmdate\b(3) heuristic parser. This is"
"			is the default when \b--parse\b is omitted.]"
"}"
"[R:rfc-2822?List date and time in RFC 2822 format "
    "(%a, %-e %h %Y %H:%M:%S %z).]"
"[T:rfc-3339?List date and time in RFC 3339 format according to "
    "\atype\a:]:[type]"
    "{"
        "[d:date?(%Y-%m-%d)]"
        "[s:seconds?(%Y-%m-%d %H:%M:%S%_z)]"
        "[n:ns|nanoseconds?(%Y-%m-%d %H:%M:%S.%N%_z)]"
    "}"
"[s:show?Show the date without setting the system time.]"
"[u:utc|gmt|zulu|universal?Output dates in \acoordinated universal time\a (UTC).]"
"[U:unelapsed?Interpret each argument as \bfmtelapsed\b(3) elapsed"
"	time and list the \bstrelapsed\b(3) 1/\ascale\a seconds.]#[scale]"
"[z:list-zones?List the known time zone table and exit. The table columns"
"	are: country code, standard zone name, savings time zone name,"
"	minutes west of \bUTC\b, and savings time minutes offset. Blank"
"	or empty entries are listed as \b-\b.]"

"\n"
"\n[ +format | date ... | file ... ]\n"
"\n"

"[+SEE ALSO?\bcrontab\b(1), \bls\b(1), \btouch\b(1), \bfmtelapsed\b(3),"
"	\bstrftime\b(3), \bstrptime\b(3), \btm\b(3)]"
;

#include <cmd.h>
#include <ls.h>
#include <proc.h>
#include <tmx.h>
#include <times.h>

typedef struct Fmt
{
	struct Fmt*	next;
	char*		format;
} Fmt_t;

#ifndef ENOSYS
#define ENOSYS		EINVAL
#endif

/*
 * set the system clock
 * the standards wimped out here
 */

static int
settime(Shbltin_t* context, const char* cmd, Time_t now, int adjust, int network)
{
	char*		s;
	char**		argv;
	char*		args[5];
	char		buf[1024];

	if (!adjust && !network)
		return tmxsettime(now);
	argv = args;
	s = "/usr/bin/date";
	if (!streq(cmd, s) && (!eaccess(s, X_OK) || !eaccess(s+=4, X_OK)))
	{
		*argv++ = s;
		if (streq(astconf("UNIVERSE", NiL, NiL), "att"))
		{
			tmxfmt(buf, sizeof(buf), "%m%d%H" "%M%Y.%S", now);
			if (adjust)
				*argv++ = "-a";
		}
		else
		{
			tmxfmt(buf, sizeof(buf), "%Y%m%d%H" "%M.%S", now);
			if (network)
				*argv++ = "-n";
			if (tm_info.flags & TM_UTC)
				*argv++ = "-u";
		}
		*argv++ = buf;
		*argv = 0;
		if (!sh_run(context, argv - args, args))
			return 0;
	}
	return -1;
}

/*
 * convert s to Time_t with error checking
 */

static Time_t
convert(register Fmt_t* f, char* s, Time_t now)
{
	char*	t;
	char*	u;

	do
	{
		now = tmxscan(s, &t, f->format, &u, now, 0);
		if (!*t && (!f->format || !*u))
			break;
	} while (f = f->next);
	if (!f || *t)
		error(3, "%s: invalid date specification", f ? t : s);
	return now;
}

int
b_date(int argc, register char** argv, Shbltin_t* context)
{
	register int	n;
	register char*	s;
	register Fmt_t*	f;
	char*		t;
	unsigned long	u;
	Time_t		now;
	Time_t		ts;
	Time_t		te;
	Time_t		e;
	char		buf[1024];
	Fmt_t*		fmts;
	Fmt_t		fmt;
	struct stat	st;

	char*		cmd = argv[0];	/* original command path	*/
	char*		format = 0;	/* tmxfmt() format		*/
	char*		string = 0;	/* date string			*/
	int		elapsed = 0;	/* args are start/stop pairs	*/
	int		filetime = 0;	/* use this st_ time field	*/
	int		increment = 0;	/* incrementally adjust time	*/
	int		last = 0;	/* display the last time arg	*/
	Tm_zone_t*	listzones = 0;	/* known time zone table	*/
	int		network = 0;	/* don't set network time	*/
	int		show = 0;	/* show date and don't set	*/
	int		unelapsed = 0;	/* fmtelapsed() => strelapsed	*/

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	tm_info.flags = TM_DATESTYLE;
	fmts = &fmt;
	fmt.format = "";
	fmt.next = 0;
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'a':
		case 'c':
		case 'm':
			filetime = opt_info.option[1];
			continue;
		case 'd':
			string = opt_info.arg;
			show = 1;
			continue;
		case 'e':
			format = "%s";
			continue;
		case 'E':
			elapsed = 1;
			continue;
		case 'f':
			format = opt_info.arg;
			continue;
		case 'i':
			increment = 1;
			continue;
		case 'l':
			tm_info.flags |= TM_LEAP;
			continue;
		case 'L':
			last = 1;
			continue;
		case 'n':
			network = 1;
			continue;
		case 'p':
			if (!(f = newof(0, Fmt_t, 1, 0)))
				error(ERROR_SYSTEM|3, "out of space [format]");
			f->next = fmts;
			f->format = opt_info.arg;
			fmts = f;
			continue;
		case 'R':
			format = "%a, %-e %h %Y %H:%M:%S %z";
			continue;
		case 's':
			show = 1;
			continue;
		case 'T':
			switch (opt_info.num)
			{
			case 'd':
				format = "%Y-%m-%d";
				continue;
			case 'n':
				format = "%Y-%m-%d %H:%M:%S.%N%_z";
				continue;
			case 's':
				format = "%Y-%m-%d %H:%M:%S%_z";
				continue;
			}
			continue;
		case 'u':
			tm_info.flags |= TM_UTC;
			continue;
		case 'U':
			unelapsed = (int)opt_info.num;
			continue;
		case 'z':
			listzones = tm_data.zone;
			continue;
		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors)
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	now = tmxgettime();
	if (listzones)
	{
		s = "-";
		while (listzones->standard)
		{
			if (listzones->type)
				s = listzones->type;
			sfprintf(sfstdout, "%3s %4s %4s %4d %4d\n", s, *listzones->standard ? listzones->standard : "-", listzones->daylight ? listzones->daylight : "-", listzones->west, listzones->dst);
			listzones++;
			show = 1;
		}
	}
	else if (elapsed)
	{
		e = 0;
		while (s = *argv++)
		{
			if (!(t = *argv++))
			{
				argv--;
				t = "now";
			}
			ts = convert(fmts, s, now);
			te = convert(fmts, t, now);
			if (te > ts)
				e += te - ts;
			else
				e += ts - te;
		}
		sfputr(sfstdout, fmtelapsed((unsigned long)tmxsec(e), 1), '\n');
		show = 1;
	}
	else if (unelapsed)
	{
		while (s = *argv++)
		{
			u = strelapsed(s, &t, unelapsed);
			if (*t)
				error(3, "%s: invalid elapsed time", s);
			sfprintf(sfstdout, "%lu\n", u);
		}
		show = 1;
	}
	else if (filetime)
	{
		if (!*argv)
			error(ERROR_USAGE|4, "%s", optusage(NiL));
		n = argv[1] != 0;
		while (s = *argv++)
		{
			if (stat(s, &st))
				error(2, "%s: not found", s);
			else
			{
				switch (filetime)
				{
				case 'a':
					now = tmxgetatime(&st);
					break;
				case 'c':
					now = tmxgetctime(&st);
					break;
				default:
					now = tmxgetmtime(&st);
					break;
				}
				tmxfmt(buf, sizeof(buf), format, now);
				if (n)
					sfprintf(sfstdout, "%s: %s\n", s, buf);
				else
					sfprintf(sfstdout, "%s\n", buf);
				show = 1;
			}
		}
	}
	else
	{
		if ((s = *argv) && !format && *s == '+')
		{
			format = s + 1;
			argv++;
			s = *argv;
		}
		if (s || (s = string))
		{
			if (*argv && string)
				error(ERROR_USAGE|4, "%s", optusage(NiL));
			now = convert(fmts, s, now);
			if (*argv && (s = *++argv))
			{
				show = 1;
				do
				{
					if (!last)
					{
						tmxfmt(buf, sizeof(buf), format, now);
						sfprintf(sfstdout, "%s\n", buf);
					}
					now = convert(fmts, s, now);
				} while (s = *++argv);
			}
		}
		else
			show = 1;
		if (format || show)
		{
			tmxfmt(buf, sizeof(buf), format, now);
			sfprintf(sfstdout, "%s\n", buf);
		}
		else if (settime(context, cmd, now, increment, network))
			error(ERROR_SYSTEM|3, "cannot set system time");
	}
	while (fmts != &fmt)
	{
		f = fmts;
		fmts = fmts->next;
		free(f);
	}
	tm_info.flags = 0;
	if (show && sfsync(sfstdout))
		error(ERROR_system(0), "write error");
	return error_info.errors != 0;
}
