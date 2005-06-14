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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * auditconfig - set and display audit parameters
 */

#include <locale.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <nlist.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <pwd.h>
#include <libintl.h>
#include <zone.h>

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

#define	AC_ARG_AUDIT			0
#define	AC_ARG_CHKCONF			1
#define	AC_ARG_CONF			2
#define	AC_ARG_GETASID			3	/* same as GETSID */
#define	AC_ARG_GETAUDIT			4
#define	AC_ARG_GETAUID			5
#define	AC_ARG_GETCAR			6
#define	AC_ARG_GETCLASS			7	/* same as GETESTATE */
#define	AC_ARG_GETCOND			8
#define	AC_ARG_GETCWD			9
#define	AC_ARG_GETESTATE		10
#define	AC_ARG_GETKERNSTATE		11
#define	AC_ARG_GETKMASK			12	/* same as GETKERNSTATE */
#define	AC_ARG_GETPINFO			13
#define	AC_ARG_GETPOLICY		14
#define	AC_ARG_GETQBUFSZ		15
#define	AC_ARG_GETQCTRL			16
#define	AC_ARG_GETQDELAY		17
#define	AC_ARG_GETQHIWATER		18
#define	AC_ARG_GETQLOWATER		19
#define	AC_ARG_GETSID			20
#define	AC_ARG_GETSTAT			21
#define	AC_ARG_GETTERMID		22
#define	AC_ARG_GETUSERAUDIT		23	/* only CMW syscall w/out */
#define	AC_ARG_LSEVENT			24
#define	AC_ARG_LSPOLICY			25
#define	AC_ARG_SETASID			26
#define	AC_ARG_SETAUDIT			27
#define	AC_ARG_SETAUID			28
#define	AC_ARG_SETCLASS			29	/* same as SETESTATE */
/*	AC_ARG_SETCOND			30 */
#define	AC_ARG_SETESTATE		31
#define	AC_ARG_SETKERNSTATE		32
#define	AC_ARG_SETKMASK			33	/* same as SETKERNSTATE */
#define	AC_ARG_SETPMASK			34
#define	AC_ARG_SETSMASK			35
#define	AC_ARG_SETSTAT			36
#define	AC_ARG_SETPOLICY		37
#define	AC_ARG_SETQBUFSZ		38
#define	AC_ARG_SETQCTRL			39
#define	AC_ARG_SETQDELAY		40
#define	AC_ARG_SETQHIWATER		41
#define	AC_ARG_SETQLOWATER		42
#define	AC_ARG_SETTERMID		43
#define	AC_ARG_SETUMASK			44
#define	AC_ARG_SETUSERAUDIT		45
#define	AC_ARG_GETFSIZE			46
#define	AC_ARG_SETFSIZE			47
#define	AC_ARG_GETKAUDIT		48
#define	AC_ARG_SETKAUDIT		49
#define	AC_ARG_ACONF			50
#define	AC_ARG_CHKACONF			51

#define	AC_KERN_EVENT 		0
#define	AC_USER_EVENT 		1

#define	NONE(s) (!strlen(s) ? gettext("none") : s)

#define	ALL_POLICIES   (AUDIT_AHLT|\
			AUDIT_ARGE|\
			AUDIT_ARGV|\
			AUDIT_CNT|\
			AUDIT_GROUP|\
			AUDIT_PASSWD|\
			AUDIT_WINDATA|\
			AUDIT_SEQ|\
			AUDIT_TRAIL|\
			AUDIT_PATH|\
			AUDIT_PUBLIC|\
			AUDIT_ZONENAME|\
			AUDIT_PERZONE)

#define	NO_POLICIES  (0)

#define	ONEK 1024

/* This should be defined in <string.h>, but it is not */
extern int strncasecmp();

/*
 * remove this after the audit.h is fixed
 */

struct arg_entry {
	char *arg_str;
	char *arg_opts;
	int auditconfig_cmd;
};

struct policy_entry {
	char *policy_str;
	uint_t policy_mask;
	char *policy_desc;
};

static struct arg_entry arg_table[] = {
	{ "-aconf",		"",			AC_ARG_ACONF},
	{ "-audit",	"event sorf retval string",	AC_ARG_AUDIT},
	{ "-chkaconf",		"",			AC_ARG_CHKACONF},
	{ "-chkconf",		"",			AC_ARG_CHKCONF},
	{ "-conf",		"",			AC_ARG_CONF},
	{ "-getasid",		"",			AC_ARG_GETASID},
	{ "-getaudit",		"",			AC_ARG_GETAUDIT},
	{ "-getauid",		"",			AC_ARG_GETAUID},
	{ "-getcar",		"",			AC_ARG_GETCAR},
	{ "-getclass",		"",			AC_ARG_GETCLASS},
	{ "-getcond",		"",			AC_ARG_GETCOND},
	{ "-getcwd",		"",			AC_ARG_GETCWD},
	{ "-getestate",		"event",		AC_ARG_GETESTATE},
	{ "-getfsize",		"",			AC_ARG_GETFSIZE},
	{ "-getkaudit",		"",			AC_ARG_GETKAUDIT},
	{ "-getkernstate",	"",			AC_ARG_GETKERNSTATE},
	{ "-getkmask",		"",			AC_ARG_GETKMASK},
	{ "-getpinfo",		"",			AC_ARG_GETPINFO},
	{ "-getpolicy",		"",			AC_ARG_GETPOLICY},
	{ "-getqbufsz",		"",			AC_ARG_GETQBUFSZ},
	{ "-getqctrl",		"",			AC_ARG_GETQCTRL},
	{ "-getqdelay",		"",			AC_ARG_GETQDELAY},
	{ "-getqhiwater",	"",			AC_ARG_GETQHIWATER},
	{ "-getqlowater",	"",			AC_ARG_GETQLOWATER},
	{ "-getsid",		"",			AC_ARG_GETSID},
	{ "-getstat",		"",			AC_ARG_GETSTAT},
	{ "-gettermid",		"",			AC_ARG_GETTERMID},
	{ "-gettid",		"",			AC_ARG_GETTERMID},
	{ "-getuseraudit",	"user",			AC_ARG_GETUSERAUDIT},
	{ "-lsevent",		"",			AC_ARG_LSEVENT},
	{ "-lspolicy",		"",			AC_ARG_LSPOLICY},
	{ "-setasid",		"asid [cmd]",		AC_ARG_SETASID},
	{ "-setaudit",	"auid audit_flags termid sid [cmd]",
							AC_ARG_SETAUDIT},
	{ "-setauid",		"auid [cmd]",		AC_ARG_SETAUID},
	{ "-setclass",		"event audit_flags",	AC_ARG_SETCLASS},
	{ "-setestate",		"event audit_flags",	AC_ARG_SETESTATE},
	{ "-setfsize",		"filesize",		AC_ARG_SETFSIZE},
	{ "-setkaudit",		"type IP_address",	AC_ARG_SETKAUDIT},
	{ "-setkernstate",	"audit_flags",		AC_ARG_SETKERNSTATE},
	{ "-setkmask",		"audit_flags",		AC_ARG_SETKMASK},
	{ "-setpmask",	"pid audit_flags [cmd]",	AC_ARG_SETPMASK},
	{ "-setpolicy",		"policy_flags",		AC_ARG_SETPOLICY},
	{ "-setqbufsz",		"bufsz",		AC_ARG_SETQBUFSZ},
	{ "-setqctrl",	"hiwater lowater bufsz delay",	AC_ARG_SETQCTRL},
	{ "-setqdelay",		"delay",		AC_ARG_SETQDELAY},
	{ "-setqhiwater",	"hiwater",		AC_ARG_SETQHIWATER},
	{ "-setqlowater",	"lowater",		AC_ARG_SETQLOWATER},
	{ "-setsmask",		"asid audit_flags",	AC_ARG_SETSMASK},
	{ "-setstat",		"",			AC_ARG_SETSTAT},
	{ "-settid",		"tid [cmd]",		AC_ARG_SETTERMID},
	{ "-setumask",		"user audit_flags",	AC_ARG_SETUMASK},
	{ "-setuseraudit",	"user audit_flags",	AC_ARG_SETUSERAUDIT}
};

#define	ARG_TBL_SZ (sizeof (arg_table) / sizeof (struct arg_entry))

static struct arg_entry arg2_table[] = {
	{ "-chkconf",	"",				AC_ARG_CHKCONF},
	{ "-conf",	"",				AC_ARG_CONF},
	{ "-getcond",	"",				AC_ARG_GETCOND},
	{ "-getclass",	"event",			AC_ARG_GETCLASS},
	{ "-setclass",	"event audit_flags",		AC_ARG_SETCLASS},
	{ "-lsevent",	"",				AC_ARG_LSEVENT},
	{ "-lspolicy",	"",				AC_ARG_LSPOLICY},
	{ "-getpolicy",	"",				AC_ARG_GETPOLICY},
	{ "-setpolicy",	"policy_flags",			AC_ARG_SETPOLICY},
	{ "-getstat",	"",				AC_ARG_GETSTAT},
	{ "-getpinfo",	"pid",				AC_ARG_GETPINFO},
	{ "-setpmask",	"pid audit_flags",		AC_ARG_SETPMASK},
	{ "-setsmask",	"asid audit_flags",		AC_ARG_SETSMASK},
	{ "-setumask",	"user audit_flags",		AC_ARG_SETUMASK},
	{ "-getfsize",	"",				AC_ARG_GETFSIZE},
	{ "-setfsize",	"filesize",			AC_ARG_SETFSIZE}
	};

#define	ARG2_TBL_SZ (sizeof (arg2_table) / sizeof (struct arg_entry))

static struct policy_entry policy_table[] = {
	{"ahlt",  AUDIT_AHLT,   "halt machine if it can not record an "
	    "async event"},
	{"arge",  AUDIT_ARGE,   "include exec environment args in audit recs"},
	{"argv",  AUDIT_ARGV,   "include exec command line args in audit recs"},
	{"cnt",   AUDIT_CNT,    "when no more space, drop recs and keep a cnt"},
	{"group", AUDIT_GROUP,  "include supplementary groups in audit recs"},
	{"seq",   AUDIT_SEQ,    "include a sequence number in audit recs"},
	{"trail", AUDIT_TRAIL,  "include trailer token in audit recs"},
	{"path",  AUDIT_PATH,   "allow multiple paths per event"},
	{"public",  AUDIT_PUBLIC,   "audit public files"},
	{"zonename", AUDIT_ZONENAME,    "generate zonename token"},
	{"perzone", AUDIT_PERZONE,	"use a separate queue and auditd per "
	    "zone"},
	{"all",   ALL_POLICIES, "all policies"},
	{"none",  NO_POLICIES,  "no policies"}
	};

#define	POLICY_TBL_SZ (sizeof (policy_table) / sizeof (struct policy_entry))

static char *progname;

static au_event_ent_t *egetauevnam();
static au_event_ent_t *egetauevnum();
static char *strtolower();
static int arg_ent_compare();
static int cond2str();
static int policy2str();
static int str2type();
static int str2policy();
static int str2ipaddr();
static int strisflags();
static int strisipaddr();
static int strisnum();
static struct arg_entry *get_arg_ent();
static struct policy_entry *get_policy_ent();
static uid_t get_user_id();
static void chk_event_num();
static void chk_event_str();
static void chk_retval();
static void chk_sorf();
static void chk_tid();
static void do_aconf();
static void do_args();
static void do_audit();
static void do_chkaconf();
static void do_chkconf();
static void do_conf();
static void do_getasid();
static void do_getaudit();
static void do_getkaudit();
static void do_setkaudit();
static void do_getauid();
static void do_getcar();
static void do_getclass();
static void do_getcond();
static void do_getcwd();
static void do_getkmask();
static void do_getpinfo();
static void do_getpolicy();
static void do_getqbufsz();
static void do_getqctrl();
static void do_getqdelay();
static void do_getqhiwater();
static void do_getqlowater();
static void do_getstat();
static void do_gettermid();
static void do_getuseraudit();
static void do_lsevent();
static void do_lspolicy();
static void do_setasid();
static void do_setaudit();
static void do_setauid();
static void do_setclass();
static void do_setkmask();
static void do_setpmask();
static void do_setsmask();
static void do_setumask();
static void do_setpolicy();
static void do_setqbufsz();
static void do_setqctrl();
static void do_setqdelay();
static void do_setqhiwater();
static void do_setqlowater();
static void do_setstat();
static void do_settid();
static void do_setuseraudit();
static void do_getfsize();
static void do_setfsize();
static void str2mask();
static void str2tid();
static void strsplit();

static void eauditon();
static void egetaudit();
static void egetkaudit();
static void esetkaudit();
static void egetauditflagsbin();
static void egetauid();
static void esetaudit();
static void esetauid();
static void execit();
static void exit_error(char *, ...);
static void exit_usage();
static void parse_args();
static void print_asid();
static void print_auid();
static void print_mask();
static void print_mask1();
static void print_stats();
static void print_tid_ex();

extern char *sys_errlist[];

int
main(argc, argv)
	int argc;
	char **argv;
{
	progname = "auditconfig";

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1) {
		exit_usage(0);
		exit(0);
	}

	if (argc == 2 &&
		(argv[1][0] == '?' ||
		strcmp(argv[1], "-h") == 0 ||
		strcmp(argv[1], "-?") == 0))
		exit_usage(0);

	parse_args(argv);

	do_args(argv);

	return (0);
}

/*
 * parse_args()
 *     Desc: Checks command line argument syntax.
 *     Inputs: Command line argv;
 *     Returns: If a syntax error is detected, a usage message is printed
 *              and exit() is called. If a syntax error is not detected,
 *              parse_args() returns without a value.
 */
static void
parse_args(char **argv)
{
	struct arg_entry *ae;

	au_mask_t pmask;
	au_mask_t smask;
	au_mask_t umask;
	uint_t type;
	uint_t addr[4];

	for (++argv; *argv; argv++) {
		if ((ae = get_arg_ent(*argv)) == (struct arg_entry *)0) {
			exit_usage(1);
		}

		switch (ae->auditconfig_cmd) {

		case AC_ARG_AUDIT:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (strisnum(*argv)) {
				chk_event_num(AC_USER_EVENT,
					(au_event_t)atol(*argv));
			} else
				chk_event_str(AC_USER_EVENT, *argv);
			++argv;
			if (!*argv)
				exit_usage(1);
			chk_sorf(*argv);
			++argv;
			if (!*argv)
				exit_usage(1);
			chk_retval(*argv);
			++argv;
			if (!*argv)
				exit_usage(1);
			break;

		case AC_ARG_CHKCONF:
			break;

		case AC_ARG_CONF:
			break;

		case AC_ARG_ACONF:
			break;

		case AC_ARG_CHKACONF:
			break;

		case AC_ARG_GETASID:
		case AC_ARG_GETSID:
			break;

		case AC_ARG_GETAUID:
			break;

		case AC_ARG_GETAUDIT:
			break;

		case AC_ARG_GETKAUDIT:
			break;

		case AC_ARG_GETCLASS:
		case AC_ARG_GETESTATE:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (strisnum(*argv))
				chk_event_num(AC_KERN_EVENT,
					(au_event_t)atol(*argv));
			else
				chk_event_str(AC_KERN_EVENT, *argv);
			break;

		case AC_ARG_GETCAR:
			break;

		case AC_ARG_GETCOND:
			break;

		case AC_ARG_GETCWD:
			break;

		case AC_ARG_GETKERNSTATE:
		case AC_ARG_GETKMASK:
			break;

		case AC_ARG_GETPOLICY:
			break;

		case AC_ARG_GETQBUFSZ:
			break;

		case AC_ARG_GETQCTRL:
			break;

		case AC_ARG_GETQDELAY:
			break;

		case AC_ARG_GETQHIWATER:
			break;

		case AC_ARG_GETQLOWATER:
			break;

		case AC_ARG_GETSTAT:
			break;

		case AC_ARG_GETTERMID:
			break;

		case AC_ARG_GETUSERAUDIT:
			++argv;
			if (!*argv)
				exit_usage(1);
			break;

		case AC_ARG_LSEVENT:
			break;

		case AC_ARG_LSPOLICY:
			break;

		case AC_ARG_SETASID:
			++argv;
			if (!*argv)
				exit_usage(1);

			while (*argv)
				++argv;
			--argv;

			break;

		case AC_ARG_SETAUID:
			++argv;
			if (!*argv)
				exit_usage(1);

			while (*argv)
				++argv;
			--argv;

			break;

		case AC_ARG_SETAUDIT:
			++argv;
			if (!*argv)
				exit_usage(1);

			while (*argv)
				++argv;
			--argv;

			break;

		case AC_ARG_SETKAUDIT:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (str2type (*argv, &type))
				exit_error(gettext(
					"Invalid IP address type specified."));
			++argv;
			if (!*argv)
				exit_usage(1);

			if (str2ipaddr(*argv, addr, type))
				exit_error(gettext(
					"Invalid IP address specified."));
			break;

		case AC_ARG_SETCLASS:
		case AC_ARG_SETESTATE:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (strisnum(*argv))
				chk_event_num(AC_KERN_EVENT,
					(au_event_t)atol(*argv));
			else
				chk_event_str(AC_KERN_EVENT, *argv);
			++argv;
			if (!*argv)
				exit_usage(1);
			str2mask(*argv, &pmask);
			break;

		case AC_ARG_SETKERNSTATE:
		case AC_ARG_SETKMASK:
			++argv;
			if (!*argv)
				exit_usage(1);
			str2mask(*argv, &pmask);
			break;

		case AC_ARG_SETPOLICY:
			++argv;
			if (!*argv)
				exit_usage(1);
			break;

		case AC_ARG_SETSTAT:
			break;

		case AC_ARG_GETPINFO:
			++argv;
			if (!*argv)
				exit_usage(1);
			break;

		case AC_ARG_SETPMASK:
			++argv;
			if (!*argv)
				exit_usage(1);
			++argv;
			if (!*argv)
				exit_usage(1);
			str2mask(*argv, &pmask);
			break;

		case AC_ARG_SETQBUFSZ:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext("Invalid bufsz specified."));
			break;

		case AC_ARG_SETQCTRL:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext(
					"Invalid hiwater specified."));
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext(
					gettext("Invalid lowater specified.")));
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext("Invalid bufsz specified."));
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext("Invalid delay specified."));
			break;

		case AC_ARG_SETQDELAY:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext("Invalid delay specified."));
			break;

		case AC_ARG_SETQHIWATER:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext(
					"Invalid hiwater specified."));
			break;

		case AC_ARG_SETQLOWATER:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext(
					"Invalid lowater specified."));
			break;

		case AC_ARG_SETTERMID:
			++argv;
			if (!*argv)
				exit_usage(1);
			chk_tid(*argv);
			break;

		case AC_ARG_SETUSERAUDIT:
			++argv;
			if (!*argv)
				exit_usage(1);
			++argv;
			if (!*argv)
				exit_usage(1);
			break;
		case AC_ARG_SETSMASK:
			++argv;
			if (!*argv)
				exit_usage(1);
			++argv;
			if (!*argv)
				exit_usage(1);
			str2mask(*argv, &smask);
			break;

		case AC_ARG_SETUMASK:
			++argv;
			if (!*argv)
				exit_usage(1);
			++argv;
			if (!*argv)
				exit_usage(1);
			str2mask(*argv, &umask);
			break;

		case AC_ARG_GETFSIZE:
			break;

		case AC_ARG_SETFSIZE:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(gettext(
					"Invalid hiwater specified."));
			break;

		default:
			exit_error(gettext("Internal error #1."));
			break;


		}
	}
}


/*
 * do_args()
 *     Desc: Do command line arguments in the order in which they appear.
 */
static void
do_args(argv)
	char **argv;
{
	struct arg_entry *ae;

	for (++argv; *argv; argv++) {
		ae = get_arg_ent(*argv);

		switch (ae->auditconfig_cmd) {

		case AC_ARG_AUDIT:
			{
				char sorf;
				int  retval;
				char *event_name;
				char *audit_str;

				++argv;
				event_name = *argv;
				++argv;
				sorf = (char)atoi(*argv);
				++argv;
				retval = atoi(*argv);
				++argv;
				audit_str = *argv;
				do_audit(event_name, sorf, retval, audit_str);
			}
			break;

		case AC_ARG_CHKCONF:
			do_chkconf();
			break;

		case AC_ARG_CONF:
			do_conf();
			break;

		case AC_ARG_CHKACONF:
			do_chkaconf();
			break;

		case AC_ARG_ACONF:
			do_aconf();
			break;

		case AC_ARG_GETASID:
		case AC_ARG_GETSID:
			do_getasid();
			break;

		case AC_ARG_GETAUID:
			do_getauid();
			break;

		case AC_ARG_GETAUDIT:
			do_getaudit();
			break;

		case AC_ARG_GETKAUDIT:
			do_getkaudit();
			break;

		case AC_ARG_GETCLASS:
		case AC_ARG_GETESTATE:
			++argv;
			do_getclass(*argv);
			break;

		case AC_ARG_GETCAR:
			do_getcar();
			break;

		case AC_ARG_GETCOND:
			do_getcond();
			break;

		case AC_ARG_GETCWD:
			do_getcwd();
			break;

		case AC_ARG_GETKERNSTATE:
		case AC_ARG_GETKMASK:
			do_getkmask();
			break;

		case AC_ARG_GETPOLICY:
			do_getpolicy();
			break;

		case AC_ARG_GETQBUFSZ:
			do_getqbufsz();
			break;

		case AC_ARG_GETQCTRL:
			do_getqctrl();
			break;

		case AC_ARG_GETQDELAY:
			do_getqdelay();
			break;

		case AC_ARG_GETQHIWATER:
			do_getqhiwater();
			break;

		case AC_ARG_GETQLOWATER:
			do_getqlowater();
			break;

		case AC_ARG_GETSTAT:
			do_getstat();
			break;

		case AC_ARG_GETTERMID:
			do_gettermid();
			break;

		case AC_ARG_GETUSERAUDIT:
			++argv;
			do_getuseraudit(*argv);
			break;

		case AC_ARG_LSEVENT:
			do_lsevent();
			break;

		case AC_ARG_LSPOLICY:
			do_lspolicy();
			break;

		case AC_ARG_SETASID:
			{
				char *sid_str;

				++argv;
				sid_str = *argv;
				++argv;
				do_setasid(sid_str, argv);
			}
			break;

		case AC_ARG_SETAUID:
			{
				char *user;

				++argv;
				user = *argv;
				++argv;
				do_setauid(user, argv);
			}
			break;

		case AC_ARG_SETAUDIT:
			{
				char *user_str;
				char *mask_str;
				char *tid_str;
				char *sid_str;

				++argv;
				user_str = *argv;
				++argv;
				mask_str = *argv;
				++argv;
				tid_str = *argv;
				++argv;
				sid_str = *argv;
				++argv;
				do_setaudit(user_str, mask_str,
				    tid_str, sid_str, argv);
			}
			break;

		case AC_ARG_SETKAUDIT:
			{
				char *address_type, *address;

				++argv; address_type = *argv;
				++argv; address = *argv;
				do_setkaudit(address_type, address);
			}
			break;

		case AC_ARG_SETCLASS:
		case AC_ARG_SETESTATE:
			{
				char *event_str, *audit_flags;

				++argv; event_str = *argv;
				++argv; audit_flags = *argv;
				do_setclass(event_str, audit_flags);
			}
			break;

		case AC_ARG_SETKERNSTATE:
		case AC_ARG_SETKMASK:
			++argv;
			do_setkmask(*argv);
			break;

		case AC_ARG_SETPOLICY:
			++argv;
			do_setpolicy(*argv);
			break;

		case AC_ARG_GETPINFO:
			{
				char *pid_str;

				++argv;
				pid_str = *argv;
				do_getpinfo(pid_str);
			}
			break;

		case AC_ARG_SETPMASK:
			{
				char *pid_str;
				char *audit_flags;

				++argv;
				pid_str = *argv;
				++argv;
				audit_flags = *argv;
				do_setpmask(pid_str, audit_flags);
			}
			break;

		case AC_ARG_SETSTAT:
			do_setstat();
			break;

		case AC_ARG_SETQBUFSZ:
			++argv;
			do_setqbufsz(*argv);
			break;

		case AC_ARG_SETQCTRL:
			{
				char *hiwater, *lowater, *bufsz, *delay;

				++argv; hiwater = *argv;
				++argv; lowater = *argv;
				++argv; bufsz = *argv;
				++argv; delay = *argv;
				do_setqctrl(hiwater, lowater, bufsz, delay);
			}
			break;
		case AC_ARG_SETQDELAY:
			++argv;
			do_setqdelay(*argv);
			break;

		case AC_ARG_SETQHIWATER:
			++argv;
			do_setqhiwater(*argv);
			break;

		case AC_ARG_SETQLOWATER:
			++argv;
			do_setqlowater(*argv);
			break;

		case AC_ARG_SETTERMID:
			++argv;
			do_settid(*argv);
			break;

		case AC_ARG_SETUSERAUDIT:
			{
				char *user;
				char *aflags;

				++argv;
				user = *argv;
				++argv;
				aflags = *argv;
				do_setuseraudit(user, aflags);
			}
			break;
		case AC_ARG_SETSMASK:
			{
				char *asid_str;
				char *audit_flags;

				++argv;
				asid_str = *argv;
				++argv;
				audit_flags = *argv;
				do_setsmask(asid_str, audit_flags);
			}
			break;
		case AC_ARG_SETUMASK:
			{
				char *auid_str;
				char *audit_flags;

				++argv;
				auid_str = *argv;
				++argv;
				audit_flags = *argv;
				do_setumask(auid_str, audit_flags);
			}
			break;
		case AC_ARG_GETFSIZE:
			do_getfsize();
			break;
		case AC_ARG_SETFSIZE:
			++argv;
			do_setfsize(*argv);
			break;

		default:
			exit_error(gettext("Internal error #2."));
			break;

		}
	}

}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_chkconf()
{
	register au_event_ent_t *evp;
	au_mask_t pmask;
	char conf_aflags[256];
	char run_aflags[256];
	au_stat_t as;
	int class;
	int			len;
	struct au_evclass_map	cmap;

	pmask.am_success = pmask.am_failure = 0;
	eauditon(A_GETSTAT, (caddr_t)&as, 0);

	setauevent();
	if ((evp = getauevent()) == (au_event_ent_t *)NULL) {
		(void) exit_error(gettext(
			"NO AUDIT EVENTS: Could not read %s\n."),
			AUDITEVENTFILE);
	}

	setauevent();
	while ((evp = getauevent()) != (au_event_ent_t *)NULL) {
		cmap.ec_number = evp->ae_number;
		len = sizeof (struct au_evclass_map);
		if (evp->ae_number <= as.as_numevent)
			if (auditon(A_GETCLASS, (caddr_t)&cmap, len) == -1) {
				(void) printf("%s(%d):%s",
				evp->ae_name, evp->ae_number, gettext(
"UNKNOWN EVENT: Could not get class for event. Configuration may be bad.\n"));
			} else {
				class = cmap.ec_class;
				if (class != evp->ae_class) {
					conf_aflags[0] = run_aflags[0] = '\0';
					pmask.am_success = class;
					pmask.am_failure = class;
					(void) getauditflagschar(run_aflags,
						&pmask, 0);
					pmask.am_success = evp->ae_class;
					pmask.am_failure = evp->ae_class;
					(void) getauditflagschar(conf_aflags,
						&pmask, 0);

					(void) printf(gettext(
"%s(%d): CLASS MISMATCH: runtime class (%s) != configured class (%s)\n"),
					evp->ae_name, evp->ae_number,
					NONE(run_aflags), NONE(conf_aflags));
				}
			}
	}
	endauevent();

}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */
static void
do_conf()
{
	register au_event_ent_t *evp;
	register int i;
	au_evclass_map_t ec;
	au_stat_t as;

	eauditon(A_GETSTAT, (caddr_t)&as, 0);

	i = 0;
	setauevent();
	while ((evp = getauevent()) != (au_event_ent_t *)NULL) {
		if (evp->ae_number <= as.as_numevent) {
			++i;
			ec.ec_number = evp->ae_number;
			ec.ec_class = evp->ae_class;
			eauditon(A_SETCLASS, (caddr_t)&ec, (int)sizeof (ec));
		}
	}
	endauevent();
	(void) printf(gettext("Configured %d kernel events.\n"), i);

}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_chkaconf()
{
	char buf[1024];
	au_mask_t pmask, kmask;

	if (getacna(buf, sizeof (buf)) < 0) {
		(void) fprintf(stderr,
		    gettext("bad non-attributable flags in audit_control\n"));
		exit(1);
	}

	if (getauditflagsbin(buf, &pmask) < 0) {
		(void) fprintf(stderr,
		    gettext("bad audit flag value encountered\n"));
		exit(1);
	}

	eauditon(A_GETKMASK, (caddr_t)&kmask, (int)sizeof (kmask));

	if ((pmask.am_success != kmask.am_success) ||
	    (pmask.am_failure != kmask.am_failure)) {
		char kbuf[2048];
		if (getauditflagschar(kbuf, &kmask, 0) < 0) {
			(void) fprintf(stderr,
			    gettext("bad kernel non-attributable mask\n"));
			exit(1);
		}
		(void) printf(gettext("non-attributable event mismatch "));
		(void) printf(gettext("audit_control(%s) kernel(%s)\n"),
			buf, kbuf);
	}
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_aconf()
{
	char buf[2048];
	au_mask_t pmask;

	if (getacna(buf, sizeof (buf)) < 0) {
		(void) fprintf(stderr,
		    gettext("bad non-attributable flags in audit_control\n"));
		exit(1);
	}

	if (getauditflagsbin(buf, &pmask) < 0) {
		(void) fprintf(stderr,
		    gettext("bad audit flag value encountered\n"));
		exit(1);
	}

	eauditon(A_SETKMASK, (caddr_t)&pmask, (int)sizeof (pmask));

	(void) printf(gettext("Configured non-attributable events.\n"));
}

static void
do_audit(event, sorf, retval, audit_str)
	char *event;
	char sorf;
	int retval;
	char *audit_str;
{
	int rtn;
	int rd;
	au_event_t event_num;
	au_event_ent_t *evp;
	auditinfo_addr_t ai;
	token_t *tokp;

	egetaudit(&ai, sizeof (ai));

	if (strisnum(event)) {
		event_num = (au_event_t)atoi(event);
		evp = egetauevnum(event_num);
	} else
		evp = egetauevnam(event);

	rtn = au_preselect(evp->ae_number, &ai.ai_mask, (int)sorf,
		AU_PRS_USECACHE);

	if (rtn == -1)
		exit_error("%s\n%s %d\n",
			gettext("Check audit event configuration."),
			gettext("Could not get audit class for event number"),
			evp->ae_number);

	/* record is preselected */
	if (rtn == 1) {
		if ((rd = au_open()) == -1)
			exit_error(gettext(
				"Could not get and audit record descriptor\n"));
		if ((tokp = au_to_me()) == (token_t *)NULL)
			exit_error(gettext(
				"Could not allocate subject token\n"));
		if (au_write(rd, tokp) == -1)
exit_error(gettext("Could not construct subject token of audit record\n"));
		if ((tokp = au_to_text(audit_str)) == (token_t *)NULL)
			exit_error(gettext("Could not allocate text token\n"));
		if (au_write(rd, tokp) == -1)
exit_error(gettext("Could not construct text token of audit record\n"));
#ifdef _LP64
		if ((tokp = au_to_return64(sorf, retval)) == (token_t *)NULL)
#else
		if ((tokp = au_to_return32(sorf, retval)) == (token_t *)NULL)
#endif
			exit_error(gettext(
				"Could not allocate return token\n"));
		if (au_write(rd, tokp) == -1)
			exit_error(gettext(
			"Could not construct return token of audit record\n"));
		if (au_close(rd, 1, evp->ae_number) == -1)
			exit_error(gettext(
				"Could not write audit record: %s\n"),
					strerror(errno));
	}
}

static void
do_getauid()
{
	au_id_t auid;

	egetauid(&auid);
	print_auid(auid);
}

static void
do_getaudit()
{
	auditinfo_addr_t ai;

	egetaudit(&ai, sizeof (ai));
	print_auid(ai.ai_auid);
	print_mask(gettext("process preselection mask"), &ai.ai_mask);
	print_tid_ex(&ai.ai_termid);
	print_asid(ai.ai_asid);
}

static void
do_getkaudit()
{
	auditinfo_addr_t ai;

	egetkaudit(&ai, sizeof (ai));
	print_auid(ai.ai_auid);
	print_mask(gettext("process preselection mask"), &ai.ai_mask);
	print_tid_ex(&ai.ai_termid);
	print_asid(ai.ai_asid);
}

/*
 * per zone if AUDIT_PERZONE set, else only in global zone.
 */

static void
do_setkaudit(t, s)
	char *t;
	char *s;
{
	uint_t type;
	auditinfo_addr_t ai;

	egetkaudit(&ai, sizeof (ai));
	(void) str2type(t, &type);
	(void) str2ipaddr(s, &ai.ai_termid.at_addr[0], type);
	ai.ai_termid.at_type = type;
	esetkaudit(&ai, sizeof (ai));
}

/*
 * returns zone-relative root
 */

static void
do_getcar()
{
	char path[MAXPATHLEN];

	eauditon(A_GETCAR, (caddr_t)path, (int)sizeof (path));
	(void) printf(gettext("current active root = %s\n"), path);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_getclass(event_str)
	char *event_str;
{
	au_evclass_map_t ec;
	au_event_ent_t *evp;
	au_event_t event_number;
	char *event_name;
	char desc[256];

	if (strisnum(event_str)) {
		event_number = atol(event_str);
		if ((evp = egetauevnum(event_number)) !=
				(au_event_ent_t *)NULL) {
			event_number = evp->ae_number;
			event_name = evp->ae_name;
		} else
			event_name = gettext("unknown");
	} else {
		event_name = event_str;
		if ((evp = egetauevnam(event_str)) != (au_event_ent_t *)NULL)
			event_number = evp->ae_number;
	}

	ec.ec_number = event_number;
	eauditon(A_GETCLASS, (caddr_t)&ec, 0);

	(void) sprintf(desc, gettext("audit class mask for event %s(%d)"),
			event_name, event_number);
	print_mask1(desc, ec.ec_class);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.  (AUC_DISABLED is always global, the other states are per zone
 * if AUDIT_PERZONE is set)
 */

static void
do_getcond()
{
	char cond_str[16];
	uint_t cond;

	eauditon(A_GETCOND, (caddr_t)&cond, (int)sizeof (cond));

	(void) cond2str(cond, cond_str);
	(void) printf(gettext("audit condition = %s\n"), cond_str);
}

/*
 * returned path is relative to zone root
 */

static void
do_getcwd()
{
	char path[MAXPATHLEN];

	eauditon(A_GETCWD, (caddr_t)path, (int)sizeof (path));
	(void) printf(gettext("current working directory = %s\n"), path);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_getkmask()
{
	au_mask_t pmask;

	eauditon(A_GETKMASK, (caddr_t)&pmask, (int)sizeof (pmask));
	print_mask(gettext("audit flags for non-attributable events"), &pmask);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set. (some policies can only be set from the global zone, but all
 * can be read from anywhere.)
 */

static void
do_getpolicy()
{
	char policy_str[1024];
	uint_t policy;

	eauditon(A_GETPOLICY, (caddr_t)&policy, 0);
	(void) policy2str(policy, policy_str, sizeof (policy_str));
	(void) printf(gettext("audit policies = %s\n"), policy_str);
}

static void
do_getpinfo(pid_str)
	char *pid_str;
{
	struct auditpinfo_addr ap;

	if (strisnum(pid_str))
		ap.ap_pid = (pid_t)atoi(pid_str);
	else
		exit_usage(1);

	eauditon(A_GETPINFO_ADDR, (caddr_t)&ap, sizeof (ap));

	print_auid(ap.ap_auid);
	print_mask(gettext("process preselection mask"), &(ap.ap_mask));
	print_tid_ex(&(ap.ap_termid));
	print_asid(ap.ap_asid);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_getqbufsz()
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("audit queue buffer size (bytes) = %ld\n"),
		qctrl.aq_bufsz);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_getqctrl()
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("audit queue hiwater mark (records) = %ld\n"),
		qctrl.aq_hiwater);
	(void) printf(gettext("audit queue lowater mark (records) = %ld\n"),
		qctrl.aq_lowater);
	(void) printf(gettext("audit queue buffer size (bytes) = %ld\n"),
		qctrl.aq_bufsz);
	(void) printf(gettext("audit queue delay (ticks) = %ld\n"),
		qctrl.aq_delay);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_getqdelay()
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("audit queue delay (ticks) = %ld\n"),
		qctrl.aq_delay);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_getqhiwater()
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("audit queue hiwater mark (records) = %ld\n"),
		qctrl.aq_hiwater);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_getqlowater()
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("audit queue lowater mark (records) = %ld\n"),
		qctrl.aq_lowater);
}

static void
do_getasid()
{
	auditinfo_addr_t ai;

	if (getaudit_addr(&ai, sizeof (ai))) {
		exit_error(gettext("getaudit_addr(2) failed"));
	}
	print_asid(ai.ai_asid);
}

/*
 * The stats are for the entire system unless AUDIT_PERZONE is set.
 */

static void
do_getstat()
{
	au_stat_t as;

	eauditon(A_GETSTAT, (caddr_t)&as, 0);
	print_stats(&as);
}

static void
do_gettermid()
{
	auditinfo_addr_t ai;

	if (getaudit_addr(&ai, sizeof (ai))) {
		exit_error(gettext("getaudit_addr(2) failed"));
	}
	print_tid_ex(&ai.ai_termid);
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_getfsize()
{
	au_fstat_t fstat;

	eauditon(A_GETFSIZE, (caddr_t)&fstat, 0);
	(void) printf(gettext("Maximum file size %d, current file size %d\n"),
		fstat.af_filesz, fstat.af_currsz);
}

/*ARGSUSED*/
static void
do_getuseraudit(user)
char *user;
{
	(void) printf(gettext("-getuseraudit supported on SunOS CMW only.\n"));
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_lsevent()
{
	register au_event_ent_t *evp;
	au_mask_t pmask;
	char auflags[256];

	setauevent();
	if ((evp = getauevent()) == (au_event_ent_t *)NULL) {
		(void) exit_error(gettext(
			"NO AUDIT EVENTS: Could not read %s\n."),
			AUDITEVENTFILE);
	}

	setauevent();
	while ((evp = getauevent()) != (au_event_ent_t *)NULL) {
		pmask.am_success = pmask.am_failure = evp->ae_class;
		if (getauditflagschar(auflags, &pmask, 0) == -1)
			(void) strcpy(auflags, "unknown");
		(void) printf("%-30s %5d %s %s\n",
			evp->ae_name, evp->ae_number, auflags, evp->ae_desc);
	}
	endauevent();
}

/*
 * The returned value is for the global zone unless AUDIT_PERZONE is
 * set.
 */

static void
do_lspolicy()
{
	int i;

	/*
	 * TRANSLATION_NOTE
	 *	Print a properly aligned header.
	 */
	(void) printf(gettext("policy string    description:\n"));
	for (i = 0; i < POLICY_TBL_SZ; i++)
		(void) printf("%-17s%s\n",
			policy_table[i].policy_str,
			gettext(policy_table[i].policy_desc));
}

static void
do_setasid(sid_str, argv)
	char *sid_str;
	char **argv;
{
	struct auditinfo_addr ai;

	if (getaudit_addr(&ai, sizeof (ai))) {
		exit_error(gettext("getaudit_addr(2) failed"));
	}
	ai.ai_asid = (au_asid_t)atol(sid_str);
	if (setaudit_addr(&ai, sizeof (ai))) {
		exit_error(gettext("setaudit_addr(2) failed"));
	}
	execit(argv);
}

static void
do_setaudit(user_str, mask_str, tid_str, sid_str, argv)
	char *user_str;
	char *mask_str;
	char *tid_str;
	char *sid_str;
	char **argv;
{
	auditinfo_addr_t ai;

	ai.ai_auid = (au_id_t)get_user_id(user_str);
	str2mask(mask_str, &ai.ai_mask),
	str2tid(tid_str, &ai.ai_termid);
	ai.ai_asid = (au_asid_t)atol(sid_str);

	esetaudit(&ai, sizeof (ai));
	execit(argv);
}

static void
do_setauid(user, argv)
	char *user;
	char **argv;
{
	au_id_t auid;

	auid = get_user_id(user);
	esetauid(&auid);
	execit(argv);
}

static void
do_setpmask(pid_str, audit_flags)
	char *pid_str;
	char *audit_flags;
{
	struct auditpinfo ap;

	if (strisnum(pid_str))
		ap.ap_pid = (pid_t)atoi(pid_str);
	else
		exit_usage(1);

	str2mask(audit_flags, &ap.ap_mask);

	eauditon(A_SETPMASK, (caddr_t)&ap, (int)sizeof (ap));
}

static void
do_setsmask(asid_str, audit_flags)
	char *asid_str;
	char *audit_flags;
{
	struct auditinfo ainfo;

	if (strisnum(asid_str))
		ainfo.ai_asid = (pid_t)atoi(asid_str);
	else
		exit_usage(1);

	str2mask(audit_flags, &ainfo.ai_mask);

	eauditon(A_SETSMASK, (caddr_t)&ainfo, (int)sizeof (ainfo));
}

static void
do_setumask(auid_str, audit_flags)
	char *auid_str;
	char *audit_flags;
{
	struct auditinfo ainfo;

	if (strisnum(auid_str))
		ainfo.ai_auid = (pid_t)atoi(auid_str);
	else
		exit_usage(1);

	str2mask(audit_flags, &ainfo.ai_mask);

	eauditon(A_SETUMASK, (caddr_t)&ainfo, (int)sizeof (ainfo));
}

/*
 * local zone use is valid if AUDIT_PERZONE is set, otherwise the
 * syscall returns EPERM.
 */

static void
do_setstat()
{
	au_stat_t as;

	as.as_audit	= (uint_t)-1;
	as.as_auditctl	= (uint_t)-1;
	as.as_dropped	= (uint_t)-1;
	as.as_enqueue	= (uint_t)-1;
	as.as_generated	= (uint_t)-1;
	as.as_kernel	= (uint_t)-1;
	as.as_nonattrib	= (uint_t)-1;
	as.as_rblocked	= (uint_t)-1;
	as.as_totalsize	= (uint_t)-1;
	as.as_wblocked	= (uint_t)-1;
	as.as_written	= (uint_t)-1;

	eauditon(A_SETSTAT, (caddr_t)&as, (int)sizeof (as));
	(void) puts(gettext("audit stats reset"));
}

/*ARGSUSED*/
static void
do_setuseraudit(user, auditflags)
	char *user;
	char *auditflags;
{
	(void) printf(gettext("-setuseraudit supported on SunOS CMW only.\n"));
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_setclass(event_str, audit_flags)
	char *event_str;
	char *audit_flags;
{
	au_event_t event;
	int mask;
	au_mask_t pmask;
	au_evclass_map_t ec;
	au_event_ent_t *evp;

	if (strisnum(event_str))
		event = (uint_t)atol(event_str);
	else {
		if ((evp = egetauevnam(event_str)) != (au_event_ent_t *)NULL)
			event = evp->ae_number;
	}

	if (strisnum(audit_flags))
		mask = atoi(audit_flags);
	else {
		str2mask(audit_flags, &pmask);
		mask = pmask.am_success | pmask.am_failure;
	}

	ec.ec_number = event;
	ec.ec_class = mask;
	eauditon(A_SETCLASS, (caddr_t)&ec, (int)sizeof (ec));
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_setkmask(audit_flags)
char *audit_flags;
{
	au_mask_t pmask;

	str2mask(audit_flags, &pmask);
	eauditon(A_SETKMASK, (caddr_t)&pmask, (int)sizeof (pmask));
	print_mask(gettext("audit flags for non-attributable events"), &pmask);
}

/*
 * ahlt and perzone are global zone only; the other policies are valid
 * in a local zone if AUDIT_PERZONE is set.  The kernel insures that
 * a local zone can't change ahlt and perzone (EINVAL).
 */

static void
do_setpolicy(policy_str)
char *policy_str;
{
	uint_t	policy;

	switch (str2policy(policy_str, &policy)) {
	case 2:
		exit_error(gettext(
			"policy (%s) invalid in a local zone."),
			policy_str);
		break;
	default:
		exit_error(gettext(
		    "Invalid policy (%s) specified."),
		    policy_str);
		break;
	case 0:
		eauditon(A_SETPOLICY, (caddr_t)&policy, 0);
		break;
	}
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_setqbufsz(bufsz)
char *bufsz;
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	qctrl.aq_bufsz = atol(bufsz);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_setqctrl(hiwater, lowater, bufsz, delay)
	char *hiwater;
	char *lowater;
	char *bufsz;
	char *delay;
{
	struct au_qctrl qctrl;

	qctrl.aq_hiwater = atol(hiwater);
	qctrl.aq_lowater = atol(lowater);
	qctrl.aq_bufsz = atol(bufsz);
	qctrl.aq_delay = atol(delay);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_setqdelay(delay)
char *delay;
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	qctrl.aq_delay = atol(delay);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_setqhiwater(hiwater)
char *hiwater;
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	qctrl.aq_hiwater = atol(hiwater);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_setqlowater(lowater)
	char *lowater;
{
	struct au_qctrl qctrl;

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	qctrl.aq_lowater = atol(lowater);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_settid(char *tid_str)
{
	struct auditinfo_addr ai;

	if (getaudit_addr(&ai, sizeof (ai))) {
		exit_error(gettext("getaudit_addr(2) failed"));
	}

	str2tid(tid_str, &ai.ai_termid);

	if (setaudit_addr(&ai, sizeof (ai))) {
		exit_error(gettext("setaudit_addr(2) failed"));
	}
}

/*
 * AUDIT_PERZONE set:  valid in all zones
 * AUDIT_PERZONE not set: valid in global zone only
 */

static void
do_setfsize(size)
	char *size;
{
	au_fstat_t fstat;

	fstat.af_filesz = atol(size);
	eauditon(A_SETFSIZE, (caddr_t)&fstat, 0);
}

static void
eauditon(cmd, data, length)
	int cmd;
	caddr_t data;
	int length;
{
	if (auditon(cmd, data, length) == -1)
		exit_error(gettext("auditon(2) failed."));
}

static void
egetauid(auid)
	au_id_t *auid;
{
	if (getauid(auid) == -1)
		exit_error(gettext("getauid(2) failed."));
}

static void
egetaudit(ai, size)
	auditinfo_addr_t *ai;
	int size;
{
	if (getaudit_addr(ai, size) == -1)
		exit_error(gettext("getaudit_addr(2) failed."));
}

static void
egetkaudit(ai, size)
	auditinfo_addr_t *ai;
	int size;
{
	if (auditon(A_GETKAUDIT, (char *)ai, size) < 0)
		exit_error(gettext("auditon: A_GETKAUDIT failed."));
}

static void
esetkaudit(ai, size)
	auditinfo_addr_t *ai;
	int size;
{
	if (auditon(A_SETKAUDIT, (char *)ai, size) < 0)
		exit_error(gettext("auditon: A_SETKAUDIT failed."));
}

static void
egetauditflagsbin(auditflags, pmask)
	char *auditflags;
	au_mask_t *pmask;
{
	pmask->am_success = pmask->am_failure = 0;

	if (strcmp(auditflags, "none") == 0)
		return;

	if (getauditflagsbin(auditflags, pmask) < 0) {
		exit_error(gettext("Could not get audit flags (%s)"),
			auditflags);
	}
}

static au_event_ent_t *
egetauevnum(event_number)
	au_event_t event_number;
{
	au_event_ent_t *evp;

	if ((evp = getauevnum(event_number)) == (au_event_ent_t *)NULL)
		exit_error(gettext("Could not get audit event %d"),
			event_number);

	return (evp);
}

static au_event_ent_t *
egetauevnam(event_name)
	char *event_name;
{
	register au_event_ent_t *evp;

	if ((evp = getauevnam(event_name)) == (au_event_ent_t *)NULL)
		exit_error(gettext("Could not get audit event %s"), event_name);

	return (evp);
}

static void
esetauid(auid)
	au_id_t *auid;
{
	if (setauid(auid) == -1)
		exit_error(gettext("setauid(2) failed."));
}

static void
esetaudit(ai, size)
	auditinfo_addr_t *ai;
	int size;
{
	if (setaudit_addr(ai, size) == -1)
		exit_error(gettext("setaudit_addr(2) failed."));
}

static uid_t
get_user_id(user)
	char *user;
{
	struct passwd *pwd;
	uid_t uid;

	setpwent();
	if (isdigit(*user)) {
		uid = atoi(user);
		if ((pwd = getpwuid(uid)) == (struct passwd *)NULL) {
			exit_error(gettext("Invalid user: %s"), user);
		}
	} else {
		if ((pwd = getpwnam(user)) == (struct passwd *)NULL) {
			exit_error(gettext("Invalid user: %s"), user);
		}
	}
	endpwent();

	return (pwd->pw_uid);
}

/*
 * get_arg_ent()
 *     Inputs: command line argument string
 *     Returns ptr to policy_entry if found; null, if not found
 */
static struct arg_entry *
get_arg_ent(arg_str)
	char *arg_str;
{
	struct arg_entry key;

	key.arg_str = arg_str;

	return ((struct arg_entry *)bsearch((char *)&key,
	    (char *)arg_table, ARG_TBL_SZ, sizeof (struct arg_entry),
	    arg_ent_compare));
}

/*
 * arg_ent_compare()
 *     Compares two command line arguments to determine which is
 *       lexicographically greater.
 *     Inputs: two argument map table entry pointers
 *     Returns: > 1: aep1->arg_str > aep2->arg_str
 *              < 1: aep1->arg_str < aep2->arg_str
 *                0: aep1->arg_str = aep->arg_str2
 */
static int
arg_ent_compare(aep1, aep2)
struct arg_entry *aep1, *aep2;
{
	return (strcmp(aep1->arg_str, aep2->arg_str));
}

/*
 * Convert mask of the following forms:
 *
 *    audit_flags (ie. +lo,-ad,pc)
 *    0xffffffff,0xffffffff
 *    ffffffff,ffffffff
 *    20,20
 */
static void
str2mask(mask_str, mp)
	char *mask_str;
	au_mask_t *mp;
{

	char sp[256];
	char fp[256];

	mp->am_success = 0;
	mp->am_failure = 0;

	/*
	 * a mask of the form +aa,bb,cc,-dd
	 */
	if (strisflags(mask_str)) {
		egetauditflagsbin(mask_str, mp);
	/*
	 * a mask of the form 0xffffffff,0xffffffff or 1,1
	 */
	} else {
		strsplit(mask_str, sp, fp, ',');

		if (strlen(sp) > (size_t)2 && !strncasecmp(sp, "0x", 2))
			(void) sscanf(sp + 2, "%x", &mp->am_success);
		else
			(void) sscanf(sp, "%u", &mp->am_success);

		if (strlen(fp) > (size_t)2 && !strncasecmp(fp, "0x", 2))
			(void) sscanf(fp + 2, "%x", &mp->am_failure);
		else
			(void) sscanf(fp, "%u", &mp->am_failure);
	}
}

/*
 * tid_str is major,minor,host  -- host is a name or an ip address
 */

static void
str2tid(char *tid_str, au_tid_addr_t *tp)
{
	char *major_str = (char *)NULL;
	char *minor_str = (char *)NULL;
	char *host_str = (char *)NULL;
	major_t major = 0;
	major_t minor = 0;
	dev_t dev = 0;
	struct hostent *phe;
	int err;
	uint32_t ibuf;
	uint32_t ibuf6[4];

	tp->at_port = 0;
	tp->at_type = 0;
	bzero(tp->at_addr, 16);

	major_str = tid_str;
	if ((minor_str = strchr(tid_str, ',')) != NULL) {
		*minor_str = '\0';
		minor_str++;
	}

	if (minor_str)
		if ((host_str = strchr(minor_str, ',')) != NULL) {
			*host_str = '\0';
			host_str++;
		}

	if (major_str)
		major = (major_t)atoi(major_str);

	if (minor_str)
		minor = (minor_t)atoi(minor_str);

	if ((dev = makedev(major, minor)) != NODEV)
		tp->at_port = dev;

	if (host_str) {
		if (strisipaddr(host_str)) {
		    if (inet_pton(AF_INET, host_str, &ibuf)) {
			tp->at_addr[0] = ibuf;
			tp->at_type = AU_IPv4;
		    } else if (inet_pton(AF_INET6, host_str, ibuf6)) {
			tp->at_addr[0] = ibuf6[0];
			tp->at_addr[1] = ibuf6[1];
			tp->at_addr[2] = ibuf6[2];
			tp->at_addr[3] = ibuf6[3];
			tp->at_type = AU_IPv6;
		    }
		} else {
			phe = getipnodebyname((const void *)host_str,
				AF_INET, 0, &err);
			if (phe == 0) {
				phe = getipnodebyname((const void *)host_str,
					AF_INET6, 0, &err);
			}

			if (phe != NULL) {
				if (phe->h_addrtype == AF_INET6) {
					/* address is IPv6 (128 bits) */
					(void) memcpy(&tp->at_addr[0],
						phe->h_addr_list[0], 16);
					tp->at_type = AU_IPv6;
				} else {
					/* address is IPv4 (32 bits) */
					(void) memcpy(&tp->at_addr[0],
						phe->h_addr_list[0], 4);
					tp->at_type = AU_IPv4;
				}
				freehostent(phe);
			}
		}
	}
}

static int
cond2str(cond, cond_str)
	uint_t cond;
	char *cond_str;
{
	*cond_str = '\0';

	if (cond == AUC_AUDITING) {
		(void) strcpy(cond_str, "auditing");
		return (0);
	}

	if ((cond == AUC_NOAUDIT) || (cond == AUC_INIT_AUDIT)) {
		(void) strcpy(cond_str, "noaudit");
		return (0);
	}

	if (cond == AUC_UNSET) {
		(void) strcpy(cond_str, "unset");
		return (0);
	}

	if (cond == AUC_NOSPACE) {
		(void) strcpy(cond_str, "nospace");
		return (0);
	}

	return (1);
}

static struct policy_entry *
get_policy_ent(policy)
	char *policy;
{
	int i;

	for (i = 0; i < POLICY_TBL_SZ; i++)
		if (strcmp(strtolower(policy),
			policy_table[i].policy_str) == 0)
			return (&policy_table[i]);

	return ((struct policy_entry *)NULL);
}

static int
str2policy(char *policy_str, uint_t *policy_mask)
{
	char		*buf;
	char		*tok;
	char		pfix;
	boolean_t	is_all = 0;
	uint_t		pm = 0;
	uint_t		curp = 0;
	struct		policy_entry *pep;

	pfix = *policy_str;

	if (pfix == '-' || pfix == '+' || pfix == '=')
		++policy_str;

	if ((buf = strdup(policy_str)) == NULL)
		return (1);

	for (tok = strtok(buf, ","); tok != NULL;
				tok = strtok(NULL, ",")) {
		if ((pep = get_policy_ent(tok)) == NULL) {
			return (1);
		} else {
			pm |= pep->policy_mask;
			if (pep->policy_mask == ALL_POLICIES)
				is_all = 1;
		}
	}

	free(buf);

	if (pfix == '-') {
		if (!is_all && (getzoneid() != GLOBAL_ZONEID) &&
		    (pm & ~AUDIT_LOCAL))
			return (2);

		eauditon(A_GETPOLICY, (caddr_t)&curp, 0);
		if (getzoneid() != GLOBAL_ZONEID)
			curp &= AUDIT_LOCAL;
		*policy_mask = curp & ~pm;
	} else if (pfix == '+') {
		/*
		 * if the user is in a local zone and tries ahlt or
		 * perzone, that's an error.  But if the user uses "all"
		 * then make it work
		 */
		if (!is_all && (getzoneid() != GLOBAL_ZONEID) &&
		    (pm & ~AUDIT_LOCAL))
			return (2);
		eauditon(A_GETPOLICY, (caddr_t)&curp, 0);
		if (getzoneid() != GLOBAL_ZONEID) {
			curp &= AUDIT_LOCAL;
			if (is_all)
				pm &= AUDIT_LOCAL;
		}
		*policy_mask = curp | pm;
	} else {
		if (is_all && (getzoneid() != GLOBAL_ZONEID))
			pm &= AUDIT_LOCAL;

		*policy_mask = pm;
	}
	return (0);
}

static int
policy2str(policy, policy_str, len)
	uint_t policy;
	char *policy_str;
	size_t len;
{
	int i, j;

	if (policy == ALL_POLICIES) {
		(void) strcpy(policy_str, "all");
		return (1);
	}

	if (policy == NO_POLICIES) {
		(void) strcpy(policy_str, "none");
		return (1);
	}

	*policy_str = '\0';

	for (i = 0, j = 0; i < POLICY_TBL_SZ; i++)
		if (policy & policy_table[i].policy_mask &&
		    policy_table[i].policy_mask != ALL_POLICIES) {
			if (j++)
				(void) strcat(policy_str, ",");
			(void) strlcat(policy_str,
			    policy_table[i].policy_str, len);
		}

	if (*policy_str)
		return (0);

	return (1);
}


static int
strisnum(s)
	char *s;
{
	if (s == (char *)NULL || !*s)
		return (0);

	for (; *s == '-' || *s == '+'; s++)

	if (!*s)
		return (0);

	for (; *s; s++)
		if (!isdigit(*s))
			return (0);

	return (1);
}

static int
strisflags(s)
	char *s;
{
	if (s == (char *)NULL || !*s)
		return (0);

	for (; *s; s++) {
		if (!isalpha(*s) &&
			(*s != '+' && *s != '-' && *s != '^' && *s != ','))
			return (0);
	}

	return (1);
}

static int
strisipaddr(s)
	char *s;
{
	int dot = 0;
	int colon = 0;

	/* no string */
	if ((s == (char *)NULL) || (!*s))
		return (0);

	for (; *s; s++) {
		if (!(isxdigit(*s) || *s != '.' || *s != ':'))
			return (0);
		if (*s == '.') dot++;
		if (*s == ':') colon++;
	}

	if (dot && colon)
		return (0);

	if (!dot && !colon)
		return (0);

	return (1);
}

static void
strsplit(s, p1, p2, c)
	char *s;
	char *p1;
	char *p2;
	char c;
{
	*p1 = *p2 = '\0';

	while (*s != '\0' && *s != c)
		*p1++ = *s++;
	*p1 = '\0';
	s++;

	while (*s != '\0')
		*p2++ = *s++;
	*p2 = '\0';
}

static char *
strtolower(s)
	char *s;
{
	char *save;

	for (save = s; *s; s++)
		(void) tolower(*s);

	return (save);
}

static void
chk_event_num(etype, event)
	int etype;
	au_event_t event;
{
	au_stat_t as;

	eauditon(A_GETSTAT, (caddr_t)&as, 0);

	if (etype == AC_KERN_EVENT) {
		if (event > as.as_numevent) {
			exit_error(gettext("Invalid kernel audit event number "
			"specified.\n\t%d is outside allowable range 0-%d."),
			    event, as.as_numevent);
		}
	} else  { /* user event */
		if (event <= as.as_numevent) {
			exit_error(gettext(
			"Invalid user level audit event number specified %d."),
				event);
		}
	}
}

static void
chk_event_str(etype, event_str)
	int etype;
	char *event_str;
{
	au_event_ent_t *evp;
	au_stat_t as;

	eauditon(A_GETSTAT, (caddr_t)&as, 0);

	evp = egetauevnam(event_str);
	if (etype == AC_KERN_EVENT && (evp->ae_number > as.as_numevent)) {
		exit_error(
		    gettext("Invalid kernel audit event string specified.\n"
			"\t\"%s\" appears to be a user level event. "
			"Check configuration."),
		    event_str);
	} else if (etype == AC_USER_EVENT &&
			(evp->ae_number < as.as_numevent)) {
		exit_error(
		    gettext("Invalid user audit event string specified.\n"
			"\t\"%s\" appears to be a kernel event. "
			"Check configuration."),
		    event_str);
	}
}

static void
chk_sorf(sorf_str)
	char *sorf_str;
{
	if (!strisnum(sorf_str))
		exit_error(gettext("Invalid sorf specified: %s"), sorf_str);
}

static void
chk_retval(retval_str)
	char *retval_str;
{
	if (!strisnum(retval_str))
		exit_error(gettext("Invalid retval specified: %s"), retval_str);
}

static void
chk_tid(tid_str)
	char *tid_str;
{
	int c;
	char *p;

	/* need two commas (maj,min,hostname) */


	for (p = tid_str, c = 0; *p; p++)
		if (*p == ',')
			++c;
	if (c != 2)
		exit_error(gettext("Invalid tid specified: %s"), tid_str);
}

static void
execit(argv)
	char **argv;
{
	char *shell;

	if (*argv)
		(void) execvp(*argv, argv);
	else {
		if (((shell = getenv("SHELL")) == (char *)NULL) ||
			*shell != '/')
			shell = "/bin/csh";

		(void) execlp(shell, shell, (char *)NULL);
	}

	exit_error(gettext("exec(2) failed"));
}

/*
 * exit_error()
 *     Desc: Prints an error message along with corresponding system
 *                  error number and error message, then exits.
 *     Inputs: Program name, program error message.
 */
/*PRINTFLIKE1*/
static void
exit_error(char *fmt, ...)
{
	va_list args;

	(void) fprintf(stderr, "%s: ", progname);

	va_start(args, fmt);
	(void) vfprintf(stderr, fmt, args);
	va_end(args);

	(void) fputc('\n', stderr);
	if (errno)
		(void) fprintf(stderr, gettext("%s: error = %s(%d)\n"),
			progname, strerror(errno), errno);
	(void) fflush(stderr);

	exit(1);
}

static void
exit_usage(status)
	int status;
{
	FILE *fp;
	int i;

	fp = (status ? stderr : stdout);
	(void) fprintf(fp, gettext("usage: %s option ...\n"), progname);

	for (i = 0; i < ARG2_TBL_SZ; i++)
		(void) fprintf(fp, " %s %s\n",
			arg2_table[i].arg_str, arg2_table[i].arg_opts);

	exit(status);
}

static void
print_asid(asid)
	au_asid_t asid;
{
	(void) printf(gettext("audit session id = %u\n"), asid);
}

static void
print_auid(auid)
	au_id_t auid;
{
	struct passwd *pwd;
	char *username;

	setpwent();
	if ((pwd = getpwuid((uid_t)auid)) != (struct passwd *)NULL)
		username = pwd->pw_name;
	else
		username = gettext("unknown");
	endpwent();

	(void) printf(gettext("audit id = %s(%d)\n"), username, auid);
}

static void
print_mask(desc, pmp)
	char *desc;
	au_mask_t *pmp;
{
	char auflags[512];

	if (getauditflagschar(auflags, pmp, NULL) < 0)
		(void) strlcpy(auflags, gettext("unknown"), sizeof (auflags));

	(void) printf("%s = %s(0x%x,0x%x)\n",
		desc, auflags, pmp->am_success, pmp->am_failure);
}

static void
print_mask1(desc, mask1)
	char *desc;
	au_class_t	mask1;
{
	(void) printf("%s = 0x%x\n", desc, (int)mask1);
}

static void
print_stats(s)
	au_stat_t *s;
{
	int offset[12];   /* used to line the header up correctly */
	char buf[512];

	(void) sprintf(buf, "%4lu %n%4lu %n%4lu %n%4lu %n%4lu %n%4lu %n%4lu "
	    "%n%4lu %n%4lu %n%4lu %n%4lu %n%4lu%n",
	    (ulong_t)s->as_generated,	&(offset[0]),
	    (ulong_t)s->as_nonattrib,	&(offset[1]),
	    (ulong_t)s->as_kernel,	&(offset[2]),
	    (ulong_t)s->as_audit,	&(offset[3]),
	    (ulong_t)s->as_auditctl,	&(offset[4]),
	    (ulong_t)s->as_enqueue,	&(offset[5]),
	    (ulong_t)s->as_written,	&(offset[6]),
	    (ulong_t)s->as_wblocked,	&(offset[7]),
	    (ulong_t)s->as_rblocked,	&(offset[8]),
	    (ulong_t)s->as_dropped,	&(offset[9]),
	    (ulong_t)s->as_totalsize / ONEK, &(offset[10]),
	    (ulong_t)s->as_memused / ONEK, &(offset[11]));

	/*
	 * TRANSLATION_NOTE
	 *	Print a properly aligned header.
	 */
	(void) printf("%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n",
		offset[0] - 1,			gettext("gen"),
		offset[1] - offset[0] -1,	gettext("nona"),
		offset[2] - offset[1] -1,	gettext("kern"),
		offset[3] - offset[2] -1,	gettext("aud"),
		offset[4] - offset[3] -1,	gettext("ctl"),
		offset[5] - offset[4] -1,	gettext("enq"),
		offset[6] - offset[5] -1,	gettext("wrtn"),
		offset[7] - offset[6] -1,	gettext("wblk"),
		offset[8] - offset[7] -1,	gettext("rblk"),
		offset[9] - offset[8] -1,	gettext("drop"),
		offset[10] - offset[9] -1,	gettext("tot"),
		offset[11] - offset[10],	gettext("mem"));

	(void) puts(buf);
}

static void
print_tid_ex(tidp)
	au_tid_addr_t *tidp;
{
	struct hostent *phe;
	char *hostname;
	struct in_addr ia;
	uint32_t *addr;
	int err;
	char buf[256];
	char *bufp;


	/* IPV6 or IPV4 address */
	if (tidp->at_type == AU_IPv4) {
		if ((phe = gethostbyaddr((char *)&tidp->at_addr[0],
					sizeof (tidp->at_addr[0]),
					AF_INET)) != (struct hostent *)NULL)
			hostname = phe->h_name;
		else
			hostname = gettext("unknown");

		ia.s_addr = tidp->at_addr[0];

		(void) printf(gettext(
			"terminal id (maj,min,host) = %u,%u,%s(%s)\n"),
			major(tidp->at_port), minor(tidp->at_port),
			hostname, inet_ntoa(ia));
	} else {
		addr = &tidp->at_addr[0];
		phe = getipnodebyaddr((const void *)addr, 16, AF_INET6, &err);

		bzero(buf, sizeof (buf));

		(void) inet_ntop(AF_INET6, (void *)addr, buf,
						sizeof (buf));
		if (phe == (struct hostent *)0) {
			bufp = gettext("unknown");
		} else
			bufp = phe->h_name;

		(void) printf(gettext(
			"terminal id (maj,min,host) = %u,%u,%s(%s)\n"),
			major(tidp->at_port), minor(tidp->at_port),
			bufp, buf);
		if (phe)
			freehostent(phe);
	}
}

static int
str2ipaddr(s, addr, type)
	char *s;
	uint32_t *addr;
	uint32_t type;
{
	int j, sl;
	char *ss;
	unsigned int v;

	bzero(addr, 16);
	if (strisipaddr(s)) {
		if (type == AU_IPv4) {
			if (inet_pton(AF_INET, s, addr))
				return (0);
			return (1);
		}
		if (type == AU_IPv6) {
			if (inet_pton(AF_INET6, s, addr))
				return (0);
			return (1);
		}
		return (1);
	} else {
		if (type == AU_IPv4) {
			(void) sscanf(s, "%x", &addr[0]);
			return (0);
		}
		if (type == AU_IPv6) {
			sl = strlen(s);
			ss = s;
			for (j = 3; j >= 0; j--) {
				if ((sl - 8) <= 0) {
					(void) sscanf(s, "%x", &v);
					addr[j] = v;
					return (0);
				}
				ss = &s[sl-8];
				(void) sscanf(ss, "%x", &v);
				addr[j] = v;
				sl -= 8;
				*ss = '\0';
			}
		}
		return (0);
	}
}

static int
str2type(s, type)
	char *s;
	uint_t *type;
{
	if (strcmp(s, "ipv6") == 0) {
		*type = AU_IPv6;
		return (0);
	}
	if (strcmp(s, "ipv4") == 0) {
		*type = AU_IPv4;
		return (0);
	}

	return (1);
}
