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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2019, Joyent, Inc.
 */

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
#include <libscf_priv.h>
#include <tsol/label.h>
#include <bsm/libbsm.h>
#include <audit_policy.h>
#include <audit_scf.h>

enum	commands {
	AC_ARG_ACONF,
	AC_ARG_AUDIT,
	AC_ARG_CHKACONF,
	AC_ARG_CHKCONF,
	AC_ARG_CONF,
	AC_ARG_GETASID,
	AC_ARG_GETAUDIT,
	AC_ARG_GETAUID,
	AC_ARG_GETCAR,
	AC_ARG_GETCLASS,
	AC_ARG_GETCOND,
	AC_ARG_GETCWD,
	AC_ARG_GETESTATE,
	AC_ARG_GETFLAGS,
	AC_ARG_GETKAUDIT,
	AC_ARG_GETKMASK,
	AC_ARG_GETNAFLAGS,
	AC_ARG_GETPINFO,
	AC_ARG_GETPLUGIN,
	AC_ARG_GETPOLICY,
	AC_ARG_GETQBUFSZ,
	AC_ARG_GETQCTRL,
	AC_ARG_GETQDELAY,
	AC_ARG_GETQHIWATER,
	AC_ARG_GETQLOWATER,
	AC_ARG_GETSTAT,
	AC_ARG_GETTERMID,
	AC_ARG_LSEVENT,
	AC_ARG_LSPOLICY,
	AC_ARG_SETASID,
	AC_ARG_SETAUDIT,
	AC_ARG_SETAUID,
	AC_ARG_SETCLASS,
	AC_ARG_SETFLAGS,
	AC_ARG_SETKAUDIT,
	AC_ARG_SETKMASK,
	AC_ARG_SETNAFLAGS,
	AC_ARG_SETPLUGIN,
	AC_ARG_SETPMASK,
	AC_ARG_SETPOLICY,
	AC_ARG_SETQBUFSZ,
	AC_ARG_SETQCTRL,
	AC_ARG_SETQDELAY,
	AC_ARG_SETQHIWATER,
	AC_ARG_SETQLOWATER,
	AC_ARG_SETSMASK,
	AC_ARG_SETSTAT,
	AC_ARG_SETUMASK,
	AC_ARG_SET_TEMPORARY
};

#define	AC_KERN_EVENT		0
#define	AC_USER_EVENT		1

#define	NONE(s) (!strlen(s) ? gettext("none") : s)

#define	ONEK 1024

/*
 * remove this after the audit.h is fixed
 */
struct arg_entry {
	char		*arg_str;
	char		*arg_opts;
	enum commands	auditconfig_cmd;
	boolean_t	temporary_allowed;	/* -t allowed for the option */
};
typedef struct arg_entry arg_entry_t;

/* arg_table - command option and usage message table */
static arg_entry_t arg_table[] = {
	{ "-aconf",	"",			AC_ARG_ACONF,	B_FALSE},
	{ "-audit",	" event sorf retval string", AC_ARG_AUDIT, B_FALSE},
	{ "-chkaconf",	"",			AC_ARG_CHKACONF, B_FALSE},
	{ "-chkconf",	"",			AC_ARG_CHKCONF,	B_FALSE},
	{ "-conf",	"",			AC_ARG_CONF,	B_FALSE},
	{ "-getasid",	"",			AC_ARG_GETASID,	B_FALSE},
	{ "-getaudit",	"",			AC_ARG_GETAUDIT, B_FALSE},
	{ "-getauid",	"",			AC_ARG_GETAUID, B_FALSE},
	{ "-getcar",	"",			AC_ARG_GETCAR,	B_FALSE},
	{ "-getclass",	" event",		AC_ARG_GETCLASS, B_FALSE},
	{ "-getcond",	"",			AC_ARG_GETCOND,	B_FALSE},
	{ "-getcwd",	"",			AC_ARG_GETCWD,	B_FALSE},
	{ "-getestate",	" event",		AC_ARG_GETESTATE, B_FALSE},
	{ "-getflags",	"",			AC_ARG_GETFLAGS, B_FALSE},
	{ "-getkaudit",	"",			AC_ARG_GETKAUDIT, B_FALSE},
	{ "-getkmask",	"",			AC_ARG_GETKMASK, B_FALSE},
	{ "-getnaflags", "",			AC_ARG_GETNAFLAGS, B_FALSE},
	{ "-getpinfo",	" pid",			AC_ARG_GETPINFO, B_FALSE},
	{ "-getplugin",	" [plugin]",		AC_ARG_GETPLUGIN, B_FALSE},
	{ "-getpolicy",	"",			AC_ARG_GETPOLICY, B_TRUE},
	{ "-getqbufsz",	"",			AC_ARG_GETQBUFSZ, B_TRUE},
	{ "-getqctrl",	"",			AC_ARG_GETQCTRL, B_TRUE},
	{ "-getqdelay",	"",			AC_ARG_GETQDELAY, B_TRUE},
	{ "-getqhiwater", "",			AC_ARG_GETQHIWATER, B_TRUE},
	{ "-getqlowater", "",			AC_ARG_GETQLOWATER, B_TRUE},
	{ "-getstat",	"",			AC_ARG_GETSTAT,	B_FALSE},
	{ "-gettid",	"",			AC_ARG_GETTERMID, B_FALSE},
	{ "-lsevent",	"",			AC_ARG_LSEVENT,	B_FALSE},
	{ "-lspolicy",	"",			AC_ARG_LSPOLICY, B_FALSE},
	{ "-setasid",	" asid [cmd]",		AC_ARG_SETASID,	B_FALSE},
	{ "-setaudit",	" auid audit_flags termid asid [cmd]",
						AC_ARG_SETAUDIT, B_FALSE},
	{ "-setauid",	" auid [cmd]",		AC_ARG_SETAUID,	B_FALSE},
	{ "-setclass",	" event audit_flags",	AC_ARG_SETCLASS, B_FALSE},
	{ "-setflags",	" audit_flags",		AC_ARG_SETFLAGS, B_FALSE},
	{ "-setkaudit",	" type IP_address",	AC_ARG_SETKAUDIT, B_FALSE},
	{ "-setkmask",	" audit_flags",		AC_ARG_SETKMASK, B_FALSE},
	{ "-setnaflags", " audit_naflags",	AC_ARG_SETNAFLAGS, B_FALSE},
	{ "-setplugin",	" name active|inactive [attributes [qsize]]",
						AC_ARG_SETPLUGIN, B_FALSE},
	{ "-setpmask",	" pid audit_flags",	AC_ARG_SETPMASK, B_FALSE},
	{ "-setpolicy",	" [+|-]policy_flags",	AC_ARG_SETPOLICY, B_TRUE},
	{ "-setqbufsz",	" bufsz",		AC_ARG_SETQBUFSZ, B_TRUE},
	{ "-setqctrl",	" hiwater lowater bufsz delay",
						AC_ARG_SETQCTRL, B_TRUE},
	{ "-setqdelay",	" delay",		AC_ARG_SETQDELAY, B_TRUE},
	{ "-setqhiwater", " hiwater",		AC_ARG_SETQHIWATER, B_TRUE},
	{ "-setqlowater", " lowater",		AC_ARG_SETQLOWATER, B_TRUE},
	{ "-setsmask",	" asid audit_flags",	AC_ARG_SETSMASK, B_FALSE},
	{ "-setstat",	"",			AC_ARG_SETSTAT, B_FALSE},
	{ "-setumask",	" user audit_flags",	AC_ARG_SETUMASK, B_FALSE},
	{ "-t",		"",			AC_ARG_SET_TEMPORARY, B_FALSE},
};

#define	ARG_TBL_SZ (sizeof (arg_table) / sizeof (arg_entry_t))

char	*progname = "auditconfig";

/*
 * temporary_set true to get/set only kernel settings,
 *		 false to get/set kernel settings and service properties
 */
static boolean_t temporary_set = B_FALSE;

static au_event_ent_t *egetauevnam(char *event_name);
static au_event_ent_t *egetauevnum(au_event_t event_number);
static int arg_ent_compare(const void *aep1, const void *aep2);
static char *cond2str(void);
static int policy2str(uint32_t policy, char *policy_str, size_t len);
static int str2type(char *s, uint_t *type);
static int str2policy(char *policy_str, uint32_t *policy_mask);
static int str2ipaddr(char *s, uint32_t *addr, uint32_t type);
static int strisipaddr(char *s);
static int strisnum(char *s);
static arg_entry_t *get_arg_ent(char *arg_str);
static uid_t get_user_id(char *user);
static void chk_arg_len(char *argv, uint_t len);
static void chk_event_num(int etype, au_event_t event);
static void chk_event_str(int etype, char *event_str);
static void chk_known_plugin(char *plugin_str);
static void chk_retval(char *retval_str);
static void chk_sorf(char *sorf_str);
static void do_aconf(void);
static void do_args(char **argv, au_mask_t *mask);
static void do_audit(char *, char, int, char *);
static void do_chkaconf(void);
static void do_chkconf(void);
static void do_conf(void);
static void do_getasid(void);
static void do_getaudit(void);
static void do_getkaudit(void);
static void do_setkaudit(char *t, char *s);
static void do_getauid(void);
static void do_getcar(void);
static void do_getclass(char *event_str);
static void do_getcond(void);
static void do_getcwd(void);
static void do_getflags(void);
static void do_getkmask(void);
static void do_getnaflags(void);
static void do_getpinfo(char *pid_str);
static void do_getplugin(char *plugin_str);
static void do_getpolicy(void);
static void do_getqbufsz(void);
static void do_getqctrl(void);
static void do_getqdelay(void);
static void do_getqhiwater(void);
static void do_getqlowater(void);
static void do_getstat(void);
static void do_gettermid(void);
static void do_lsevent(void);
static void do_lspolicy(void);
static void do_setasid(char *sid_str, char **argv);
static void do_setaudit(char *user_str, char *mask_str, char *tid_str,
    char *sid_str, char **argv);
static void do_setauid(char *user, char **argv);
static void do_setclass(char *event_str, au_mask_t *mask);
static void do_setflags(char *audit_flags, au_mask_t *amask);
static void do_setkmask(au_mask_t *pmask);
static void do_setnaflags(char *audit_naflags, au_mask_t *namask);
static void do_setpmask(char *pid_str, au_mask_t *mask);
static void do_setsmask(char *asid_str, au_mask_t *mask);
static void do_setumask(char *auid_str, au_mask_t *mask);
static void do_setplugin(char *plugin_str, boolean_t plugin_state,
    char *plugin_attr, int plugin_qsize);
static void do_setpolicy(char *policy_str);
static void do_setqbufsz(char *bufsz);
static void do_setqctrl(char *hiwater, char *lowater, char *bufsz, char *delay);
static void do_setqdelay(char *delay);
static void do_setqhiwater(char *hiwater);
static void do_setqlowater(char *lowater);
static void do_setstat(void);
static void str2tid(char *tid_str, au_tid_addr_t *tp);

static void eauditon(int cmd, caddr_t data, int length);
static void echkflags(char *auditflags, au_mask_t *mask);
static void egetaudit(auditinfo_addr_t *ai, int size);
static void egetauditflagsbin(char *auditflags, au_mask_t *pmask);
static void egetauid(au_id_t *auid);
static void egetkaudit(auditinfo_addr_t *ai, int size);
static void esetaudit(auditinfo_addr_t *ai, int size);
static void esetauid(au_id_t *auid);
static void esetkaudit(auditinfo_addr_t *ai, int size);
static void execit(char **argv);
static void exit_error(char *fmt, ...);
static void exit_usage(int status);
static void parse_args(int argc, char **argv, au_mask_t *mask);
static void print_asid(au_asid_t asid);
static void print_auid(au_id_t auid);
static void print_mask(char *desc, au_mask_t *pmp);
static void print_plugin(char *plugin_name, kva_t *plugin_kva);
static void print_tid_ex(au_tid_addr_t *tidp);

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

int
main(int argc, char **argv)
{
	au_mask_t mask;			/* for options manipulating flags */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argc == 1) {
		exit_usage(0);
	}

	if (argc == 2 &&
	    (argv[1][0] == '?' ||
	    strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "-?") == 0)) {
		exit_usage(0);
	}

	parse_args(argc, argv, &mask);
	do_args(argv, &mask);

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
parse_args(int argc, char **argv, au_mask_t *mask)
{
	arg_entry_t *ae;

	uint_t type;
	uint_t addr[4];

	for (++argv; *argv; argv++) {
		if ((ae = get_arg_ent(*argv)) == NULL) {
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
			} else {
				chk_event_str(AC_USER_EVENT, *argv);
			}
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
		case AC_ARG_CONF:
		case AC_ARG_ACONF:
		case AC_ARG_CHKACONF:
		case AC_ARG_GETASID:
		case AC_ARG_GETAUID:
		case AC_ARG_GETAUDIT:
		case AC_ARG_GETKAUDIT:
			break;

		case AC_ARG_GETCLASS:
		case AC_ARG_GETESTATE:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (strisnum(*argv)) {
				chk_event_num(AC_KERN_EVENT,
				    (au_event_t)atol(*argv));
			} else {
				chk_event_str(AC_KERN_EVENT, *argv);
			}
			break;

		case AC_ARG_GETCAR:
		case AC_ARG_GETCOND:
		case AC_ARG_GETCWD:
		case AC_ARG_GETFLAGS:
		case AC_ARG_GETKMASK:
		case AC_ARG_GETNAFLAGS:
			break;

		case AC_ARG_GETPLUGIN:
			if (*++argv == NULL) {
				--argv;
				break;
			}
			if (get_arg_ent(*argv) != NULL) {
				--argv;
			} else {
				chk_arg_len(*argv, PLUGIN_MAXBUF);
				chk_known_plugin(*argv);
			}
			break;

		case AC_ARG_GETPOLICY:
		case AC_ARG_GETQBUFSZ:
		case AC_ARG_GETQCTRL:
		case AC_ARG_GETQDELAY:
		case AC_ARG_GETQHIWATER:
		case AC_ARG_GETQLOWATER:
		case AC_ARG_GETSTAT:
		case AC_ARG_GETTERMID:
		case AC_ARG_LSEVENT:
		case AC_ARG_LSPOLICY:
			break;

		case AC_ARG_SETASID:
		case AC_ARG_SETAUID:
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
				exit_error(
				    gettext("Invalid IP address specified."));
			break;

		case AC_ARG_SETCLASS:
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
			echkflags(*argv, mask);
			break;

		case AC_ARG_SETFLAGS:
			++argv;
			if (!*argv)
				exit_usage(1);
			chk_arg_len(*argv, PRESELECTION_MAXBUF);
			echkflags(*argv, mask);
			break;

		case AC_ARG_SETKMASK:
			++argv;
			if (!*argv)
				exit_usage(1);
			echkflags(*argv, mask);
			break;

		case AC_ARG_SETNAFLAGS:
			++argv;
			if (!*argv)
				exit_usage(1);
			chk_arg_len(*argv, PRESELECTION_MAXBUF);
			echkflags(*argv, mask);
			break;

		case AC_ARG_SETPLUGIN:
			if (*++argv == NULL || get_arg_ent(*argv) != NULL) {
				exit_usage(1);
			}
			chk_known_plugin(*argv);
			chk_arg_len(*argv, PLUGIN_MAXBUF);
			if (*++argv == NULL || strcmp(*argv, "active") != 0 &&
			    strcmp(*argv, "inactive") != 0) {
				exit_usage(1);
			}
			if (*++argv == NULL || get_arg_ent(*argv) != NULL) {
				--argv;
				break;
			}
			chk_arg_len(*argv, PLUGIN_MAXATT);
			if (*++argv == NULL || get_arg_ent(*argv) != NULL) {
				--argv;
				break;
			}
			if (atoi(*argv) < 0) {
				exit_error(gettext("Incorrect qsize specified "
				    "(%s)."), *argv);
			}
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
			echkflags(*argv, mask);
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
				exit_error(
				    gettext("Invalid hiwater specified."));
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv))
				exit_error(
				    gettext("Invalid lowater specified."));
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
			if (!strisnum(*argv)) {
				exit_error(
				    gettext("Invalid hiwater specified."));
			}
			break;

		case AC_ARG_SETQLOWATER:
			++argv;
			if (!*argv)
				exit_usage(1);
			if (!strisnum(*argv)) {
				exit_error(
				    gettext("Invalid lowater specified."));
			}
			break;

		case AC_ARG_SETSMASK:
		case AC_ARG_SETUMASK:
			++argv;
			if (!*argv)
				exit_usage(1);
			++argv;
			if (!*argv)
				exit_usage(1);
			echkflags(*argv, mask);
			break;

		case AC_ARG_SET_TEMPORARY:
			/* Do not accept single -t option. */
			if (argc == 2) {
				exit_error(
				    gettext("Only the -t option specified "
				    "(it is not a standalone option)."));
			}
			temporary_set = B_TRUE;
			break;

		default:
			exit_error(gettext("Internal error #1."));
			break;
		}
	}
}


/*
 * do_args() - do command line arguments in the order in which they appear.
 * Function return values returned by the underlying functions; the semantics
 * they should follow is to return B_TRUE on successful execution, B_FALSE
 * otherwise.
 */
static void
do_args(char **argv, au_mask_t *mask)
{
	arg_entry_t	*ae;

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

		case AC_ARG_GETFLAGS:
			do_getflags();
			break;

		case AC_ARG_GETKMASK:
			do_getkmask();
			break;

		case AC_ARG_GETNAFLAGS:
			do_getnaflags();
			break;

		case AC_ARG_GETPLUGIN:
			{
				char	*plugin_str = NULL;

				++argv;
				if (*argv != NULL) {
					if (get_arg_ent(*argv) != NULL) {
						--argv;
					} else {
						plugin_str = *argv;
					}
				} else {
					--argv;
				}

				do_getplugin(plugin_str);
			}
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
				do_setaudit(user_str, mask_str, tid_str,
				    sid_str, argv);
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
			{
				char *event_str;

				++argv;
				event_str = *argv;
				do_setclass(event_str, mask);

				++argv;
			}
			break;

		case AC_ARG_SETFLAGS:
			++argv;
			do_setflags(*argv, mask);
			break;

		case AC_ARG_SETKMASK:
			++argv;
			do_setkmask(mask);
			break;

		case AC_ARG_SETNAFLAGS:
			++argv;
			do_setnaflags(*argv, mask);
			break;

		case AC_ARG_SETPLUGIN:
			{
				char		*plugin_str = NULL;
				boolean_t	plugin_state = B_FALSE;
				char		*plugin_att = NULL;
				int		plugin_qsize = -1;

				plugin_str = *++argv;
				if (strcmp(*++argv, "active") == 0) {
					plugin_state = B_TRUE;
				}
				if (*++argv != NULL &&
				    get_arg_ent(*argv) == NULL) {
					plugin_att = *argv;
					if (*++argv != NULL &&
					    get_arg_ent(*argv) == NULL) {
						plugin_qsize = atoi(*argv);
					} else {
						--argv;
					}
				} else {
					--argv;
				}

				do_setplugin(plugin_str, plugin_state,
				    plugin_att, plugin_qsize);
			}
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

				++argv;
				pid_str = *argv;
				do_setpmask(pid_str, mask);

				++argv;
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

		case AC_ARG_SETSMASK:
			{
				char *asid_str;

				++argv;
				asid_str = *argv;
				do_setsmask(asid_str, mask);

				++argv;
			}
			break;
		case AC_ARG_SETUMASK:
			{
				char *auid_str;

				++argv;
				auid_str = *argv;
				do_setumask(auid_str, mask);

				++argv;
			}
			break;
		case AC_ARG_SET_TEMPORARY:
			break;

		default:
			exit_error(gettext("Internal error #2."));
			break;
		}
	}
}

/*
 * do_chkconf() - the returned value is for the global zone unless AUDIT_PERZONE
 * is set.
 */
static void
do_chkconf(void)
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
	if (getauevent() == NULL) {
		exit_error(gettext("NO AUDIT EVENTS: Could not read %s\n."),
		    AUDITEVENTFILE);
	}

	setauevent();
	while ((evp = getauevent()) != NULL) {
		cmap.ec_number = evp->ae_number;
		len = sizeof (struct au_evclass_map);
		if (evp->ae_number <= as.as_numevent) {
			if (auditon(A_GETCLASS, (caddr_t)&cmap, len) == -1) {
				(void) printf("%s(%hu):%s",
				    evp->ae_name, evp->ae_number,
				    gettext("UNKNOWN EVENT: Could not get "
				    "class for event. Configuration may "
				    "be bad.\n"));
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
					    "%s(%hu): CLASS MISMATCH: "
					    "runtime class (%s) != "
					    "configured class (%s)\n"),
					    evp->ae_name, evp->ae_number,
					    NONE(run_aflags),
					    NONE(conf_aflags));
				}
			}
		}
	}
	endauevent();
}

/*
 * do_conf() - configure the kernel events. The value returned to the user is
 * for the global zone unless AUDIT_PERZONE is set.
 */
static void
do_conf(void)
{
	register au_event_ent_t *evp;
	register int i;
	au_evclass_map_t ec;
	au_stat_t as;

	eauditon(A_GETSTAT, (caddr_t)&as, 0);

	i = 0;
	setauevent();
	while ((evp = getauevent()) != NULL) {
		if (evp->ae_number <= as.as_numevent) {
			++i;
			ec.ec_number = evp->ae_number;
			ec.ec_class = evp->ae_class;
			eauditon(A_SETCLASS, (caddr_t)&ec, sizeof (ec));
		}
	}
	endauevent();
	(void) printf(gettext("Configured %d kernel events.\n"), i);

}

/*
 * do_chkaconf() - report a mismatch if the runtime class mask of a kernel audit
 * event does not match the configured class mask. The value returned to the
 * user is for the global zone unless AUDIT_PERZONE is set.
 */
static void
do_chkaconf(void)
{
	char		*namask_cfg;
	au_mask_t	pmask, kmask;

	if (!do_getnaflags_scf(&namask_cfg) || namask_cfg == NULL) {
		exit_error(gettext("Could not get configured value."));
	}
	egetauditflagsbin(namask_cfg, &pmask);

	eauditon(A_GETKMASK, (caddr_t)&kmask, sizeof (kmask));

	if ((pmask.am_success != kmask.am_success) ||
	    (pmask.am_failure != kmask.am_failure)) {
		char kbuf[2048];
		if (getauditflagschar(kbuf, &kmask, 0) < 0) {
			free(namask_cfg);
			(void) fprintf(stderr,
			    gettext("bad kernel non-attributable mask\n"));
			exit(1);
		}
		(void) printf(
		    gettext("non-attributable event flags mismatch:\n"));
		(void) printf(gettext("active non-attributable audit flags "
		    "= %s\n"), kbuf);
		(void) printf(gettext("configured non-attributable audit flags "
		    "= %s\n"), namask_cfg);
	}
	free(namask_cfg);
}

/*
 * do_aconf - configures the non-attributable events. The value returned to the
 * user is for the global zone unless AUDIT_PERZONE is set.
 */
static void
do_aconf(void)
{
	au_mask_t	namask;
	char		*namask_cfg;

	if (!do_getnaflags_scf(&namask_cfg) || namask_cfg == NULL) {
		exit_error(gettext("Could not get configured value."));
	}
	egetauditflagsbin(namask_cfg, &namask);
	free(namask_cfg);

	eauditon(A_SETKMASK, (caddr_t)&namask, sizeof (namask));
	(void) printf(gettext("Configured non-attributable event mask.\n"));
}

/*
 * do_audit() - construct an audit record for audit event event using the
 * process's audit characteristics containing a text token string audit_str. The
 * return token is constructed from the success/failure flag sort. Returned
 * value retval is an errno value.
 */
static void
do_audit(char *event, char sorf, int retval, char *audit_str)
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
	} else {
		evp = egetauevnam(event);
	}

	rtn = au_preselect(evp->ae_number, &ai.ai_mask, (int)sorf,
	    AU_PRS_USECACHE);

	if (rtn == -1) {
		exit_error("%s\n%s %hu\n",
		    gettext("Check audit event configuration."),
		    gettext("Could not get audit class for event number"),
		    evp->ae_number);
	}

	/* record is preselected */
	if (rtn == 1) {
		if ((rd = au_open()) == -1) {
			exit_error(gettext(
			    "Could not get and audit record descriptor\n"));
		}
		if ((tokp = au_to_me()) == NULL) {
			exit_error(
			    gettext("Could not allocate subject token\n"));
		}
		if (au_write(rd, tokp) == -1) {
			exit_error(gettext("Could not construct subject token "
			    "of audit record\n"));
		}
		if (is_system_labeled()) {
			if ((tokp = au_to_mylabel()) == NULL) {
				exit_error(gettext(
				    "Could not allocate label token\n"));
			}
			if (au_write(rd, tokp) == -1) {
				exit_error(gettext("Could not "
				    "construct label token of audit record\n"));
			}
		}

		if ((tokp = au_to_text(audit_str)) == NULL)
			exit_error(gettext("Could not allocate text token\n"));
		if (au_write(rd, tokp) == -1)
			exit_error(gettext("Could not construct text token of "
			    "audit record\n"));
#ifdef _LP64
		if ((tokp = au_to_return64(sorf, retval)) == NULL)
#else
		if ((tokp = au_to_return32(sorf, retval)) == NULL)
#endif
			exit_error(
			    gettext("Could not allocate return token\n"));
		if (au_write(rd, tokp) == -1) {
			exit_error(gettext("Could not construct return token "
			    "of audit record\n"));
		}
		if (au_close(rd, 1, evp->ae_number) == -1) {
			exit_error(
			    gettext("Could not write audit record: %s\n"),
			    strerror(errno));
		}
	}
}

/*
 * do_getauid() - print the audit id of the current process.
 */
static void
do_getauid(void)
{
	au_id_t auid;

	egetauid(&auid);
	print_auid(auid);
}

/*
 * do_getaudit() - print the audit characteristics of the current process.
 */
static void
do_getaudit(void)
{
	auditinfo_addr_t ai;

	egetaudit(&ai, sizeof (ai));
	print_auid(ai.ai_auid);
	print_mask(gettext("process preselection mask"), &ai.ai_mask);
	print_tid_ex(&ai.ai_termid);
	print_asid(ai.ai_asid);
}

/*
 * do_getkaudit() - print the audit characteristics of the current zone.
 */
static void
do_getkaudit(void)
{
	auditinfo_addr_t ai;

	egetkaudit(&ai, sizeof (ai));
	print_auid(ai.ai_auid);
	print_mask(gettext("process preselection mask"), &ai.ai_mask);
	print_tid_ex(&ai.ai_termid);
	print_asid(ai.ai_asid);
}

/*
 * do_setkaudit() - set IP address_type/address of machine to specified values;
 * valid per zone if AUDIT_PERZONE is set, else only in global zone.
 */
static void
do_setkaudit(char *t, char *s)
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
 * do_getcar() - print the zone-relative root
 */
static void
do_getcar(void)
{
	char path[MAXPATHLEN];

	eauditon(A_GETCAR, (caddr_t)path, sizeof (path));
	(void) printf(gettext("current active root = %s\n"), path);
}

/*
 * do_getclass() - print the preselection mask associated with the specified
 * kernel audit event. The displayed value is for the global zone unless
 * AUDIT_PERZONE is set.
 */
static void
do_getclass(char *event_str)
{
	au_evclass_map_t ec;
	au_event_ent_t *evp;
	au_event_t event_number;
	char *event_name;

	if (strisnum(event_str)) {
		event_number = atol(event_str);
		if ((evp = egetauevnum(event_number)) != NULL) {
			event_number = evp->ae_number;
			event_name = evp->ae_name;
		} else {
			event_name = gettext("unknown");
		}
	} else {
		event_name = event_str;
		if ((evp = egetauevnam(event_str)) != NULL) {
			event_number = evp->ae_number;
		}
	}

	ec.ec_number = event_number;
	eauditon(A_GETCLASS, (caddr_t)&ec, 0);

	(void) printf(gettext("audit class mask for event %s(%hu) = 0x%x\n"),
	    event_name, event_number, ec.ec_class);
}

/*
 * do_getcond() - the printed value is for the global zone unless
 * AUDIT_PERZONE is set. (AUC_DISABLED is always global, the other states are
 * per zone if AUDIT_PERZONE is set)
 */
static void
do_getcond(void)
{
	(void) printf(gettext("audit condition = %s\n"), cond2str());
}

/*
 * do_getcwd() - the printed path is relative to the current zone root
 */
static void
do_getcwd(void)
{
	char path[MAXPATHLEN];

	eauditon(A_GETCWD, (caddr_t)path, sizeof (path));
	(void) printf(gettext("current working directory = %s\n"), path);
}

/*
 * do_getflags() - the printed value is for the global zone unless AUDIT_PERZONE
 * is set.
 */
static void
do_getflags(void)
{
	au_mask_t	amask;
	char		*amask_cfg;

	eauditon(A_GETAMASK, (caddr_t)&amask, sizeof (amask));
	print_mask(gettext("active user default audit flags"), &amask);

	if (!do_getflags_scf(&amask_cfg) || amask_cfg == NULL) {
		exit_error(gettext("Could not get configured value."));
	}
	egetauditflagsbin(amask_cfg, &amask);
	print_mask(gettext("configured user default audit flags"), &amask);
	free(amask_cfg);
}

/*
 * do_getkmask() - the printed value is for the global zone unless AUDIT_PERZONE
 * is set.
 */
static void
do_getkmask(void)
{
	au_mask_t pmask;

	eauditon(A_GETKMASK, (caddr_t)&pmask, sizeof (pmask));
	print_mask(gettext("active non-attributable audit flags"), &pmask);
}

/*
 * do_getnaflags() - the printed value is for the global zone unless
 * AUDIT_PERZONE is set.
 */
static void
do_getnaflags(void)
{
	au_mask_t	namask;
	char		*namask_cfg;

	eauditon(A_GETKMASK, (caddr_t)&namask, sizeof (namask));
	print_mask(gettext("active non-attributable audit flags"), &namask);

	if (!do_getnaflags_scf(&namask_cfg) || namask_cfg == NULL) {
		exit_error(gettext("Could not get configured value."));
	}
	egetauditflagsbin(namask_cfg, &namask);
	print_mask(gettext("configured non-attributable audit flags"), &namask);
	free(namask_cfg);
}

/*
 * do_getpolicy() - print active and configured kernel audit policy relative to
 * the current zone.
 */
static void
do_getpolicy(void)
{
	char			policy_str[1024];
	uint32_t		policy;

	if (!temporary_set) {
		if (!do_getpolicy_scf(&policy)) {
			exit_error(gettext("Could not get configured values."));
		}
		(void) policy2str(policy, policy_str, sizeof (policy_str));
		(void) printf(gettext("configured audit policies = %s\n"),
		    policy_str);
	}

	eauditon(A_GETPOLICY, (caddr_t)&policy, 0);
	(void) policy2str(policy, policy_str, sizeof (policy_str));
	(void) printf(gettext("active audit policies = %s\n"), policy_str);
}


/*
 * do_getpinfo() - print the audit ID, preselection mask, terminal ID, and
 * audit session ID for the specified process.
 */
static void
do_getpinfo(char *pid_str)
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
 * do_getplugin() - print plugin configuration.
 */
static void
do_getplugin(char *plugin_str)
{
	scf_plugin_kva_node_t	*plugin_kva_ll;
	scf_plugin_kva_node_t	*plugin_kva_ll_head;

	if (!do_getpluginconfig_scf(plugin_str, &plugin_kva_ll)) {
		exit_error(gettext("Could not get plugin configuration."));
	}

	plugin_kva_ll_head = plugin_kva_ll;

	while (plugin_kva_ll != NULL) {
		print_plugin(plugin_kva_ll->plugin_name,
		    plugin_kva_ll->plugin_kva);
		plugin_kva_ll = plugin_kva_ll->next;
		if (plugin_kva_ll != NULL) {
			(void) printf("\n");
		}
	}
	plugin_kva_ll_free(plugin_kva_ll_head);
}

/*
 * do_getqbufsz() - print the active and configured audit queue write buffer
 * size relative to the current zone.
 */
static void
do_getqbufsz(void)
{
	struct au_qctrl qctrl;

	if (!temporary_set) {
		if (!do_getqbufsz_scf(&qctrl.aq_bufsz)) {
			exit_error(gettext("Could not get configured value."));
		}

		if (qctrl.aq_bufsz == 0) {
			(void) printf(gettext(
			    "no configured audit queue buffer size\n"));
		} else {
			(void) printf(gettext("configured audit queue "
			    "buffer size (bytes) = %d\n"), qctrl.aq_bufsz);
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("active audit queue buffer size (bytes) = %d\n"),
	    qctrl.aq_bufsz);
}

/*
 * do_getqctrl() - print the configured and active audit queue write buffer
 * size, audit queue hiwater mark, audit queue lowater mark, audit queue prod
 * interval (ticks) relative to the current zone.
 */
static void
do_getqctrl(void)
{
	struct au_qctrl	qctrl;

	if (!temporary_set) {
		if (!do_getqctrl_scf(&qctrl)) {
			exit_error(gettext("Could not get configured values."));
		}

		if (qctrl.aq_hiwater == 0) {
			(void) printf(gettext(
			    "no configured audit queue hiwater mark\n"));
		} else {
			(void) printf(gettext("configured audit queue "
			    "hiwater mark (records) = %d\n"), qctrl.aq_hiwater);
		}
		if (qctrl.aq_lowater == 0) {
			(void) printf(gettext(
			    "no configured audit queue lowater mark\n"));
		} else {
			(void) printf(gettext("configured audit queue "
			    "lowater mark (records) = %d\n"), qctrl.aq_lowater);
		}
		if (qctrl.aq_bufsz == 0) {
			(void) printf(gettext(
			    "no configured audit queue buffer size\n"));
		} else {
			(void) printf(gettext("configured audit queue "
			    "buffer size (bytes) = %d\n"), qctrl.aq_bufsz);
		}
		if (qctrl.aq_delay == 0) {
			(void) printf(gettext(
			    "no configured audit queue delay\n"));
		} else {
			(void) printf(gettext("configured audit queue "
			    "delay (ticks) = %ld\n"), qctrl.aq_delay);
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("active audit queue hiwater mark "
	    "(records) = %d\n"), qctrl.aq_hiwater);
	(void) printf(gettext("active audit queue lowater mark "
	    "(records) = %d\n"), qctrl.aq_lowater);
	(void) printf(gettext("active audit queue buffer size (bytes) = %d\n"),
	    qctrl.aq_bufsz);
	(void) printf(gettext("active audit queue delay (ticks) = %ld\n"),
	    qctrl.aq_delay);
}

/*
 * do_getqdelay() - print, relative to the current zone, the configured and
 * active interval at which audit queue is prodded to start output.
 */
static void
do_getqdelay(void)
{
	struct au_qctrl qctrl;

	if (!temporary_set) {
		if (!do_getqdelay_scf(&qctrl.aq_delay)) {
			exit_error(gettext("Could not get configured value."));
		}

		if (qctrl.aq_delay == 0) {
			(void) printf(gettext(
			    "no configured audit queue delay\n"));
		} else {
			(void) printf(gettext("configured audit queue "
			    "delay (ticks) = %ld\n"), qctrl.aq_delay);
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("active audit queue delay (ticks) = %ld\n"),
	    qctrl.aq_delay);
}

/*
 * do_getqhiwater() - print, relative to the current zone, the high water
 * point in undelivered audit records when audit generation will block.
 */
static void
do_getqhiwater(void)
{
	struct au_qctrl qctrl;

	if (!temporary_set) {
		if (!do_getqhiwater_scf(&qctrl.aq_hiwater)) {
			exit_error(gettext("Could not get configured value."));
		}

		if (qctrl.aq_hiwater == 0) {
			(void) printf(gettext(
			    "no configured audit queue hiwater mark\n"));
		} else {
			(void) printf(gettext("configured audit queue "
			    "hiwater mark (records) = %d\n"), qctrl.aq_hiwater);
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("active audit queue hiwater mark "
	    "(records) = %d\n"), qctrl.aq_hiwater);
}

/*
 * do_getqlowater() - print, relative to the current zone, the low water point
 * in undelivered audit records where blocked processes will resume.
 */
static void
do_getqlowater(void)
{
	struct au_qctrl qctrl;

	if (!temporary_set) {
		if (!do_getqlowater_scf(&qctrl.aq_lowater)) {
			exit_error(gettext("Could not get configured value."));
		}

		if (qctrl.aq_lowater == 0) {
			(void) printf(gettext(
			    "no configured audit queue lowater mark\n"));
		} else {
			(void) printf(gettext("configured audit queue "
			    "lowater mark (records) = %d\n"), qctrl.aq_lowater);
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	(void) printf(gettext("active audit queue lowater mark "
	    "(records) = %d\n"), qctrl.aq_lowater);
}

/*
 * do_getasid() - print out the audit session-ID.
 */
static void
do_getasid(void)
{
	auditinfo_addr_t ai;

	if (getaudit_addr(&ai, sizeof (ai))) {
		exit_error(gettext("getaudit_addr(2) failed"));
	}
	print_asid(ai.ai_asid);
}

/*
 * do_getstat() - the printed statistics are for the entire system unless
 * AUDIT_PERZONE is set.
 */
static void
do_getstat(void)
{
	au_stat_t as;
	int offset[12];   /* used to line the header up correctly */
	char buf[512];

	eauditon(A_GETSTAT, (caddr_t)&as, 0);
	(void) sprintf(buf, "%4lu %n%4lu %n%4lu %n%4lu %n%4lu %n%4lu %n%4lu "
	    "%n%4lu %n%4lu %n%4lu %n%4lu %n%4lu%n",
	    (ulong_t)as.as_generated,	&(offset[0]),
	    (ulong_t)as.as_nonattrib,	&(offset[1]),
	    (ulong_t)as.as_kernel,	&(offset[2]),
	    (ulong_t)as.as_audit,	&(offset[3]),
	    (ulong_t)as.as_auditctl,	&(offset[4]),
	    (ulong_t)as.as_enqueue,	&(offset[5]),
	    (ulong_t)as.as_written,	&(offset[6]),
	    (ulong_t)as.as_wblocked,	&(offset[7]),
	    (ulong_t)as.as_rblocked,	&(offset[8]),
	    (ulong_t)as.as_dropped,	&(offset[9]),
	    (ulong_t)as.as_totalsize / ONEK, &(offset[10]),
	    (ulong_t)as.as_memused / ONEK, &(offset[11]));

	/*
	 * TRANSLATION_NOTE
	 *	Print a properly aligned header.
	 */
	(void) printf("%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n",
	    offset[0] - 1,		gettext("gen"),
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

	(void) printf("%s\n", buf);
}

/*
 * do_gettermid() - print audit terminal ID for current process.
 */
static void
do_gettermid(void)
{
	auditinfo_addr_t ai;

	if (getaudit_addr(&ai, sizeof (ai))) {
		exit_error(gettext("getaudit_addr(2) failed"));
	}
	print_tid_ex(&ai.ai_termid);
}

/*
 * do_lsevent() - display the active kernel and user level audit event
 * information. The printed events are for the global zone unless AUDIT_PERZONE
 * is set.
 */
static void
do_lsevent(void)
{
	register au_event_ent_t *evp;
	au_mask_t pmask;
	char auflags[256];

	setauevent();
	if (getauevent() == NULL) {
		exit_error(gettext("NO AUDIT EVENTS: Could not read %s\n."),
		    AUDITEVENTFILE);
	}

	setauevent();
	while ((evp = getauevent()) != NULL) {
		pmask.am_success = pmask.am_failure = evp->ae_class;
		if (getauditflagschar(auflags, &pmask, 0) == -1)
			(void) strcpy(auflags, "unknown");
		(void) printf("%-30s %5hu %s %s\n",
		    evp->ae_name, evp->ae_number, auflags, evp->ae_desc);
	}
	endauevent();
}

/*
 * do_lspolicy() - display the kernel audit policies with a description  of each
 * policy. The printed value is for the global zone unless AUDIT_PERZONE is set.
 */
static void
do_lspolicy(void)
{
	int i;

	/*
	 * TRANSLATION_NOTE
	 *	Print a properly aligned header.
	 */
	(void) printf(gettext("policy string    description:\n"));
	for (i = 0; i < POLICY_TBL_SZ; i++) {
		(void) printf("%-17s%s\n", policy_table[i].policy_str,
		    gettext(policy_table[i].policy_desc));
	}
}

/*
 * do_setasid() - execute shell or cmd with specified session-ID.
 */
static void
do_setasid(char *sid_str, char **argv)
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

/*
 * do_setaudit() - execute shell or cmd with specified audit characteristics.
 */
static void
do_setaudit(char *user_str, char *mask_str, char *tid_str, char *sid_str,
    char **argv)
{
	auditinfo_addr_t ai;

	ai.ai_auid = (au_id_t)get_user_id(user_str);
	egetauditflagsbin(mask_str, &ai.ai_mask),
	    str2tid(tid_str, &ai.ai_termid);
	ai.ai_asid = (au_asid_t)atol(sid_str);

	esetaudit(&ai, sizeof (ai));
	execit(argv);
}

/*
 * do_setauid() - execute shell or cmd with specified audit-ID.
 */
static void
do_setauid(char *user, char **argv)
{
	au_id_t auid;

	auid = get_user_id(user);
	esetauid(&auid);
	execit(argv);
}

/*
 * do_setpmask() - set the preselection mask of the specified process; valid
 * per zone if AUDIT_PERZONE is set, else only in global zone.
 */
static void
do_setpmask(char *pid_str, au_mask_t *mask)
{
	struct auditpinfo ap;

	if (strisnum(pid_str)) {
		ap.ap_pid = (pid_t)atoi(pid_str);
	} else {
		exit_usage(1);
	}

	ap.ap_mask.am_success = mask->am_success;
	ap.ap_mask.am_failure = mask->am_failure;

	eauditon(A_SETPMASK, (caddr_t)&ap, sizeof (ap));
}

/*
 * do_setsmask() - set the preselection mask of all processes with the specified
 * audit session-ID; valid per zone if AUDIT_PERZONE is set, else only in global
 * zone.
 */
static void
do_setsmask(char *asid_str, au_mask_t *mask)
{
	struct auditinfo ainfo;

	if (strisnum(asid_str)) {
		ainfo.ai_asid = (au_asid_t)atoi(asid_str);
	} else {
		exit_usage(1);
	}

	ainfo.ai_mask.am_success = mask->am_success;
	ainfo.ai_mask.am_failure = mask->am_failure;

	eauditon(A_SETSMASK, (caddr_t)&ainfo, sizeof (ainfo));
}

/*
 * do_setumask() -  set the preselection mask of all processes with the
 * specified audit-ID; valid per zone if AUDIT_PERZONE is set, else only in
 * global zone.
 */
static void
do_setumask(char *auid_str, au_mask_t *mask)
{
	struct auditinfo ainfo;

	if (strisnum(auid_str)) {
		ainfo.ai_auid = (au_id_t)atoi(auid_str);
	} else {
		exit_usage(1);
	}

	ainfo.ai_mask.am_success = mask->am_success;
	ainfo.ai_mask.am_failure = mask->am_failure;

	eauditon(A_SETUMASK, (caddr_t)&ainfo, sizeof (ainfo));
}

/*
 * do_setstat() - reset audit statistics counters; local zone use is valid if
 * AUDIT_PERZONE is set, otherwise the syscall returns EPERM.
 */
static void
do_setstat(void)
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

	eauditon(A_SETSTAT, (caddr_t)&as, sizeof (as));
	(void) printf("%s\n", gettext("audit stats reset"));
}

/*
 * do_setclass() - map the kernel event event_str to the classes specified by
 * audit flags (mask); valid per zone if AUDIT_PERZONE is set, else only in
 * global zone.
 */
static void
do_setclass(char *event_str, au_mask_t *mask)
{
	au_event_t event;
	au_evclass_map_t ec;
	au_event_ent_t *evp;

	if (strisnum(event_str)) {
		event = (uint_t)atol(event_str);
	} else {
		if ((evp = egetauevnam(event_str)) != NULL) {
			event = evp->ae_number;
		}
	}

	ec.ec_number = event;
	ec.ec_class = (mask->am_success | mask->am_failure);

	eauditon(A_SETCLASS, (caddr_t)&ec, sizeof (ec));
}

/*
 * do_setflags() - set configured and active default user preselection masks;
 * valid per zone if AUDIT_PERZONE is set, else only in global zone.
 */
static void
do_setflags(char *audit_flags, au_mask_t *amask)
{
	eauditon(A_SETAMASK, (caddr_t)amask, sizeof (*amask));

	if (!do_setflags_scf(audit_flags)) {
		print_mask(gettext("active user default audit flags"), amask);
		exit_error(gettext("Could not store configuration value."));
	}
	print_mask(gettext("user default audit flags"), amask);
}

/*
 * do_setkmask() - set non-attributable audit flags of machine; valid per zone
 * if AUDIT_PERZONE is set, else only in global zone.
 */
static void
do_setkmask(au_mask_t *pmask)
{
	eauditon(A_SETKMASK, (caddr_t)pmask, sizeof (*pmask));
	print_mask(gettext("active non-attributable audit flags"), pmask);
}

/*
 * do_setnaflags() - set configured and active non-attributable selection flags
 * of machine; valid per zone if AUDIT_PERZONE is set, else only in global zone.
 */
static void
do_setnaflags(char *audit_naflags, au_mask_t *namask)
{
	eauditon(A_SETKMASK, (caddr_t)namask, sizeof (*namask));

	if (!do_setnaflags_scf(audit_naflags)) {
		print_mask(
		    gettext("active non-attributable audit flags"), namask);
		exit_error(gettext("Could not store configuration value."));
	}
	print_mask(gettext("non-attributable audit flags"), namask);
}

/*
 * do_setplugin() - set the given plugin plugin_str configuration values.
 */
static void
do_setplugin(char *plugin_str, boolean_t plugin_state, char *plugin_attr,
    int plugin_qsize)
{
	if (!do_setpluginconfig_scf(plugin_str, plugin_state, plugin_attr,
	    plugin_qsize)) {
		exit_error(gettext("Could not set plugin configuration."));
	}
}

/*
 * do_setpolicy() - set the active and configured kernel audit policy; active
 * values can be changed per zone if AUDIT_PERZONE is set, else only in global
 * zone.
 *
 * ahlt and perzone are global zone only. The kernel ensures that a local zone
 * can't change ahlt and perzone (EINVAL).
 */
static void
do_setpolicy(char *policy_str)
{
	uint32_t	policy = 0;

	switch (str2policy(policy_str, &policy)) {
	case 0:
		if (!temporary_set) {
			if (!do_getpolicy_scf(&policy)) {
				exit_error(gettext("Unable to get current "
				    "policy values from the SMF repository"));
			}
			(void) str2policy(policy_str, &policy);

			if (!do_setpolicy_scf(policy)) {
				exit_error(gettext("Could not store "
				    "configuration values."));
			}
		}
		eauditon(A_SETPOLICY, (caddr_t)&policy, 0);
		break;
	case 2:
		exit_error(gettext("policy (%s) invalid in a local zone."),
		    policy_str);
		break;
	default:
		exit_error(gettext("Invalid policy (%s) specified."),
		    policy_str);
		break;
	}
}

/*
 * do_setqbufsz() - set the active and configured audit queue write buffer size
 * (bytes); active values can be changed per zone if AUDIT_PERZONE is set, else
 * only in global zone.
 */
static void
do_setqbufsz(char *bufsz)
{
	struct au_qctrl qctrl;

	if (!temporary_set) {
		qctrl.aq_bufsz = (size_t)atol(bufsz);
		if (!do_setqbufsz_scf(&qctrl.aq_bufsz)) {
			exit_error(gettext(
			    "Could not store configuration value."));
		}
		if (qctrl.aq_bufsz == 0) {
			return;
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	qctrl.aq_bufsz = (size_t)atol(bufsz);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * do_setqctrl() - set the active and configured audit queue write buffer size
 * (bytes), hiwater audit record count, lowater audit record count, and wakeup
 * interval (ticks); active values can be changed per zone if AUDIT_PERZONE is
 * set, else only in global zone.
 */
static void
do_setqctrl(char *hiwater, char *lowater, char *bufsz, char *delay)
{
	struct au_qctrl	qctrl;

	qctrl.aq_hiwater = (size_t)atol(hiwater);
	qctrl.aq_lowater = (size_t)atol(lowater);
	qctrl.aq_bufsz = (size_t)atol(bufsz);
	qctrl.aq_delay = (clock_t)atol(delay);

	if (!temporary_set) {
		struct au_qctrl qctrl_act;

		if (!do_setqctrl_scf(&qctrl)) {
			exit_error(gettext(
			    "Could not store configuration values."));
		}

		eauditon(A_GETQCTRL, (caddr_t)&qctrl_act, 0);
		if (qctrl.aq_hiwater == 0) {
			qctrl.aq_hiwater = qctrl_act.aq_hiwater;
		}
		if (qctrl.aq_lowater == 0) {
			qctrl.aq_lowater = qctrl_act.aq_lowater;
		}
		if (qctrl.aq_bufsz == 0) {
			qctrl.aq_bufsz = qctrl_act.aq_bufsz;
		}
		if (qctrl.aq_delay == 0) {
			qctrl.aq_delay = qctrl_act.aq_delay;
		}
	}

	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * do_setqdelay() - set the active and configured audit queue wakeup interval
 * (ticks); active values can be changed per zone if AUDIT_PERZONE is set, else
 * only in global zone.
 */
static void
do_setqdelay(char *delay)
{
	struct au_qctrl qctrl;

	if (!temporary_set) {
		qctrl.aq_delay = (clock_t)atol(delay);
		if (!do_setqdelay_scf(&qctrl.aq_delay)) {
			exit_error(gettext(
			    "Could not store configuration value."));
		}
		if (qctrl.aq_delay == 0) {
			return;
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	qctrl.aq_delay = (clock_t)atol(delay);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * do_setqhiwater() - sets the active and configured number of undelivered audit
 * records in the audit queue at which audit record generation blocks; active
 * values can be changed per zone if AUDIT_PERZONE is set, else only in global
 * zone.
 */
static void
do_setqhiwater(char *hiwater)
{
	struct au_qctrl qctrl;

	if (!temporary_set) {
		qctrl.aq_hiwater = (size_t)atol(hiwater);
		if (!do_setqhiwater_scf(&qctrl.aq_hiwater)) {
			exit_error(gettext(
			    "Could not store configuration value."));
		}
		if (qctrl.aq_hiwater == 0) {
			return;
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	qctrl.aq_hiwater = (size_t)atol(hiwater);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

/*
 * do_setqlowater() - set the active and configured number of undelivered audit
 * records in the audit queue at which blocked auditing processes unblock;
 * active values can be changed per zone if AUDIT_PERZONE is set, else only in
 * global zone.
 */
static void
do_setqlowater(char *lowater)
{
	struct au_qctrl qctrl;

	if (!temporary_set) {
		qctrl.aq_lowater = (size_t)atol(lowater);
		if (!do_setqlowater_scf(&qctrl.aq_lowater)) {
			exit_error(gettext(
			    "Could not store configuration value."));
		}
		if (qctrl.aq_lowater == 0) {
			return;
		}
	}

	eauditon(A_GETQCTRL, (caddr_t)&qctrl, 0);
	qctrl.aq_lowater = (size_t)atol(lowater);
	eauditon(A_SETQCTRL, (caddr_t)&qctrl, 0);
}

static void
eauditon(int cmd, caddr_t data, int length)
{
	if (auditon(cmd, data, length) == -1)
		exit_error(gettext("auditon(2) failed."));
}

static void
egetauid(au_id_t *auid)
{
	if (getauid(auid) == -1)
		exit_error(gettext("getauid(2) failed."));
}

static void
egetaudit(auditinfo_addr_t *ai, int size)
{
	if (getaudit_addr(ai, size) == -1)
		exit_error(gettext("getaudit_addr(2) failed."));
}

static void
egetkaudit(auditinfo_addr_t *ai, int size)
{
	if (auditon(A_GETKAUDIT, (char *)ai, size) < 0)
		exit_error(gettext("auditon: A_GETKAUDIT failed."));
}

static void
esetkaudit(auditinfo_addr_t *ai, int size)
{
	if (auditon(A_SETKAUDIT, (char *)ai, size) < 0)
		exit_error(gettext("auditon: A_SETKAUDIT failed."));
}

static void
egetauditflagsbin(char *auditflags, au_mask_t *pmask)
{
	if (strcmp(auditflags, "none") == 0) {
		pmask->am_success = pmask->am_failure = 0;
		return;
	}

	if (getauditflagsbin(auditflags, pmask) < 0) {
		exit_error(gettext("Could not get audit flags (%s)"),
		    auditflags);
	}
}

static void
echkflags(char *auditflags, au_mask_t *mask)
{
	char		*err = "";
	char		*err_ptr;

	if (!__chkflags(auditflags, mask, B_FALSE, &err)) {
		err_ptr = err;
		while (*err_ptr != ',' && *err_ptr != '\0') {
			err_ptr++;
		}
		*err_ptr = '\0';
		exit_error(gettext("Unknown audit flags and/or prefixes "
		    "encountered: %s"), err);
	}
}

static au_event_ent_t *
egetauevnum(au_event_t event_number)
{
	au_event_ent_t *evp;

	if ((evp = getauevnum(event_number)) == NULL) {
		exit_error(gettext("Could not get audit event %hu"),
		    event_number);
	}

	return (evp);
}

static au_event_ent_t *
egetauevnam(char *event_name)
{
	register au_event_ent_t *evp;

	if ((evp = getauevnam(event_name)) == NULL)
		exit_error(gettext("Could not get audit event %s"), event_name);

	return (evp);
}

static void
esetauid(au_id_t *auid)
{
	if (setauid(auid) == -1)
		exit_error(gettext("setauid(2) failed."));
}

static void
esetaudit(auditinfo_addr_t *ai, int size)
{
	if (setaudit_addr(ai, size) == -1)
		exit_error(gettext("setaudit_addr(2) failed."));
}

static uid_t
get_user_id(char *user)
{
	struct passwd *pwd;
	uid_t uid;

	if (isdigit(*user)) {
		uid = atoi(user);
		if ((pwd = getpwuid(uid)) == NULL) {
			exit_error(gettext("Invalid user: %s"), user);
		}
	} else {
		if ((pwd = getpwnam(user)) == NULL) {
			exit_error(gettext("Invalid user: %s"), user);
		}
	}

	return (pwd->pw_uid);
}

/*
 * get_arg_ent()
 *     Inputs: command line argument string
 *     Returns ptr to struct arg_entry if found; null, if not found
 */
static arg_entry_t *
get_arg_ent(char *arg_str)
{
	arg_entry_t key;

	key.arg_str = arg_str;

	return ((arg_entry_t *)bsearch((char *)&key, (char *)arg_table,
	    ARG_TBL_SZ, sizeof (arg_entry_t), arg_ent_compare));
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
arg_ent_compare(const void *aep1, const void *aep2)
{
	return (strcmp(((arg_entry_t *)aep1)->arg_str,
	    ((arg_entry_t *)aep2)->arg_str));
}

/*
 * tid_str is major,minor,host  -- host is a name or an ip address
 */
static void
str2tid(char *tid_str, au_tid_addr_t *tp)
{
	char *major_str;
	char *minor_str;
	char *host_str = NULL;
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

	if (minor_str) {
		if ((host_str = strchr(minor_str, ',')) != NULL) {
			*host_str = '\0';
			host_str++;
		}
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

static char *
cond2str(void)
{
	uint_t cond;

	eauditon(A_GETCOND, (caddr_t)&cond, sizeof (cond));

	switch (cond) {

	case AUC_AUDITING:
		return ("auditing");

	case AUC_NOAUDIT:
	case AUC_INIT_AUDIT:
		return ("noaudit");

	case AUC_UNSET:
		return ("unset");

	case AUC_NOSPACE:
		return ("nospace");

	default:
		return ("");
	}
}

/*
 *	exit = 0, success
 *	       1, error
 *	       2, bad zone
 */
static int
str2policy(char *policy_str, uint32_t *policy_mask)
{
	char		*buf;
	char		*tok;
	char		pfix;
	boolean_t	is_all = B_FALSE;
	uint32_t	pm = 0;
	uint32_t	curp;

	pfix = *policy_str;

	if (pfix == '-' || pfix == '+' || pfix == '=')
		++policy_str;

	if ((buf = strdup(policy_str)) == NULL)
		return (1);

	for (tok = strtok(buf, ","); tok != NULL; tok = strtok(NULL, ",")) {
		uint32_t tok_pm;
		if (((tok_pm = get_policy(tok)) == 0) &&
		    ((strcasecmp(tok, "none") != 0))) {
			free(buf);
			return (1);
		} else {
			pm |= tok_pm;
			if (tok_pm == ALL_POLICIES) {
				is_all = B_TRUE;
			}
		}
	}
	free(buf);

	/* reuse policy mask if already set to some value */
	if (*policy_mask != 0) {
		curp = *policy_mask;
	} else {
		(void) auditon(A_GETPOLICY, (caddr_t)&curp, 0);
	}

	if (pfix == '-') {
		if (!is_all &&
		    (getzoneid() != GLOBAL_ZONEID) &&
		    (pm & ~AUDIT_LOCAL)) {
			return (2);
		}

		if (getzoneid() != GLOBAL_ZONEID)
			curp &= AUDIT_LOCAL;
		*policy_mask = curp & ~pm;

	} else if (pfix == '+') {
		/*
		 * In a local zone, accept specifying "all", but not
		 * individually specifying global-zone only policies.
		 * Limit to all locally allowed, so system call doesn't
		 * fail.
		 */
		if (!is_all &&
		    (getzoneid() != GLOBAL_ZONEID) &&
		    (pm & ~AUDIT_LOCAL)) {
			return (2);
		}

		if (getzoneid() != GLOBAL_ZONEID) {
			curp &= AUDIT_LOCAL;
			if (is_all) {
				pm &= AUDIT_LOCAL;
			}
		}
		*policy_mask = curp | pm;

	} else {
		/*
		 * In a local zone, accept specifying "all", but not
		 * individually specifying global-zone only policies.
		 * Limit to all locally allowed, so system call doesn't
		 * fail.
		 */
		if (!is_all &&
		    (getzoneid() != GLOBAL_ZONEID) &&
		    (pm & ~AUDIT_LOCAL)) {
			return (2);
		}

		if (is_all && (getzoneid() != GLOBAL_ZONEID)) {
			pm &= AUDIT_LOCAL;
		}
		*policy_mask = pm;
	}
	return (0);
}

static int
policy2str(uint32_t policy, char *policy_str, size_t len)
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

	for (i = 0, j = 0; i < POLICY_TBL_SZ; i++) {
		if (policy & policy_table[i].policy_mask &&
		    policy_table[i].policy_mask != ALL_POLICIES) {
			if (j++) {
				(void) strcat(policy_str, ",");
			}
			(void) strlcat(policy_str, policy_table[i].policy_str,
			    len);
		}
	}

	if (*policy_str)
		return (0);

	return (1);
}


static int
strisnum(char *s)
{
	if (s == NULL || !*s)
		return (0);

	for (; *s == '-' || *s == '+'; s++) {
		if (!*s)
			return (0);
	}

	for (; *s; s++) {
		if (!isdigit(*s))
			return (0);
	}

	return (1);
}

static int
strisipaddr(char *s)
{
	int dot = 0;
	int colon = 0;

	/* no string */
	if ((s == NULL) || (!*s))
		return (0);

	for (; *s; s++) {
		if (!(isxdigit(*s) || *s != '.' || *s != ':'))
			return (0);
		if (*s == '.')
			dot++;
		if (*s == ':')
			colon++;
	}

	if (dot && colon)
		return (0);

	if (!dot && !colon)
		return (0);

	return (1);
}

static void
chk_arg_len(char *argv, uint_t len)
{
	if ((strlen(argv) + 1) > len) {
		*(argv + len - 1) = '\0';
		exit_error(gettext("Argument too long (%s..)."), argv);
	}
}

static void
chk_event_num(int etype, au_event_t event)
{
	au_stat_t as;

	eauditon(A_GETSTAT, (caddr_t)&as, 0);

	if (etype == AC_KERN_EVENT) {
		if (event > as.as_numevent) {
			exit_error(gettext(
			    "Invalid kernel audit event number specified.\n"
			    "\t%hu is outside allowable range 0-%d."),
			    event, as.as_numevent);
		}
	} else  {
		/* user event */
		if (event <= as.as_numevent) {
			exit_error(gettext("Invalid user level audit event "
			    "number specified %hu."), event);
		}
	}
}

static void
chk_event_str(int etype, char *event_str)
{
	au_event_ent_t *evp;
	au_stat_t as;

	eauditon(A_GETSTAT, (caddr_t)&as, 0);

	evp = egetauevnam(event_str);
	if (etype == AC_KERN_EVENT && (evp->ae_number > as.as_numevent)) {
		exit_error(gettext(
		    "Invalid kernel audit event string specified.\n"
		    "\t\"%s\" appears to be a user level event. "
		    "Check configuration."), event_str);
	} else if (etype == AC_USER_EVENT &&
	    (evp->ae_number < as.as_numevent)) {
		exit_error(gettext(
		    "Invalid user audit event string specified.\n"
		    "\t\"%s\" appears to be a kernel event. "
		    "Check configuration."), event_str);
	}
}

static void
chk_known_plugin(char *plugin_str)
{
	if ((strlen(plugin_str) + 1) > PLUGIN_MAXBUF) {
		exit_error(gettext("Plugin name too long.\n"));
	}

	if (!plugin_avail_scf(plugin_str)) {
		exit_error(gettext("No such plugin configured: %s"),
		    plugin_str);
	}
}

static void
chk_sorf(char *sorf_str)
{
	if (!strisnum(sorf_str))
		exit_error(gettext("Invalid sorf specified: %s"), sorf_str);
}

static void
chk_retval(char *retval_str)
{
	if (!strisnum(retval_str))
		exit_error(gettext("Invalid retval specified: %s"), retval_str);
}

static void
execit(char **argv)
{
	char *args, *args_pos;
	size_t len = 0;
	size_t n = 0;
	char **argv_pos;

	if (*argv) {
		/* concatenate argument array to be passed to sh -c "..." */
		for (argv_pos = argv; *argv_pos; argv_pos++)
			len += strlen(*argv_pos) + 1;

		if ((args = malloc(len + 1)) == NULL)
			exit_error(
			    gettext("Allocation for command/arguments failed"));

		args_pos = args;
		for (argv_pos = argv; *argv_pos; argv_pos++) {
			n += snprintf(args_pos, len - n, "%s ", *argv_pos);
			args_pos = args + n;
		}
		/* strip the last space */
		args[strlen(args)] = '\0';

		(void) execl("/bin/sh", "sh", "-c", args, NULL);
	} else {
		(void) execl("/bin/sh", "sh", NULL);
	}

	exit_error(gettext("exec(2) failed"));
}

static void
exit_usage(int status)
{
	FILE *fp;
	int i;

	fp = (status ? stderr : stdout);
	(void) fprintf(fp, gettext("usage: %s option ...\n"), progname);

	for (i = 0; i < ARG_TBL_SZ; i++) {
		/* skip the -t option; it's not a standalone option */
		if (arg_table[i].auditconfig_cmd == AC_ARG_SET_TEMPORARY) {
			continue;
		}

		(void) fprintf(fp, " %s%s%s\n",
		    arg_table[i].arg_str, arg_table[i].arg_opts,
		    (arg_table[i].temporary_allowed ? " [-t]" : ""));
	}

	exit(status);
}

static void
print_asid(au_asid_t asid)
{
	(void) printf(gettext("audit session id = %u\n"), asid);
}

static void
print_auid(au_id_t auid)
{
	struct passwd *pwd;
	char *username;

	if ((pwd = getpwuid((uid_t)auid)) != NULL)
		username = pwd->pw_name;
	else
		username = gettext("unknown");

	(void) printf(gettext("audit id = %s(%d)\n"), username, auid);
}

static void
print_mask(char *desc, au_mask_t *pmp)
{
	char auflags[512];

	if (getauditflagschar(auflags, pmp, 0) < 0)
		(void) strlcpy(auflags, gettext("unknown"), sizeof (auflags));

	(void) printf("%s = %s(0x%x,0x%x)\n",
	    desc, auflags, pmp->am_success, pmp->am_failure);
}

static void
print_plugin(char *plugin_name, kva_t *plugin_kva)
{
	char		att_str[PLUGIN_MAXATT];
	boolean_t	plugin_active;
	char		*active_str;
	char		*qsize_ptr;
	int		qsize;

	if ((active_str = kva_match(plugin_kva, "active")) == NULL) {
		(void) printf(gettext("Audit service configuration error: "
		    "\"active\" property not found\n"));
		return;
	}

	plugin_active = (boolean_t)atoi(active_str);
	qsize_ptr = kva_match(plugin_kva, "qsize");
	qsize = atoi(qsize_ptr == NULL ? "-1" : qsize_ptr);

	(void) printf(gettext("Plugin: %s (%s)\n"), plugin_name,
	    plugin_active ? "active" : "inactive");

	free_static_att_kva(plugin_kva);

	switch (_kva2str(plugin_kva, att_str, PLUGIN_MAXATT, "=", ";")) {
	case 0:
		(void) printf(gettext("\tAttributes: %s\n"), att_str);
		break;
	case 1:
		exit_error(gettext("Internal error - buffer size too small."));
		break;
	default:
		exit_error(gettext("Internal error."));
		break;
	}

	if (qsize != 0) {
		(void) printf(gettext("\tQueue size: %d %s\n"), qsize,
		    qsize == -1 ? "(internal error: value not available)" : "");
	}
}

static void
print_tid_ex(au_tid_addr_t *tidp)
{
	struct hostent *phe;
	char *hostname;
	struct in_addr ia;
	uint32_t *addr;
	int err;
	char buf[INET6_ADDRSTRLEN];
	char *bufp;


	/* IPV6 or IPV4 address */
	if (tidp->at_type == AU_IPv4) {
		if ((phe = gethostbyaddr((char *)&tidp->at_addr[0],
		    sizeof (tidp->at_addr[0]), AF_INET)) != NULL) {
			hostname = phe->h_name;
		} else {
			hostname = gettext("unknown");
		}

		ia.s_addr = tidp->at_addr[0];

		(void) printf(gettext(
		    "terminal id (maj,min,host) = %lu,%lu,%s(%s)\n"),
		    major(tidp->at_port), minor(tidp->at_port),
		    hostname, inet_ntoa(ia));
	} else {
		addr = &tidp->at_addr[0];
		phe = getipnodebyaddr((const void *)addr, 16, AF_INET6, &err);

		bzero(buf, sizeof (buf));

		(void) inet_ntop(AF_INET6, (void *)addr, buf, sizeof (buf));
		if (phe == NULL) {
			bufp = gettext("unknown");
		} else {
			bufp = phe->h_name;
		}

		(void) printf(gettext(
		    "terminal id (maj,min,host) = %lu,%lu,%s(%s)\n"),
		    major(tidp->at_port), minor(tidp->at_port),
		    bufp, buf);
		if (phe) {
			freehostent(phe);
		}
	}
}

static int
str2ipaddr(char *s, uint32_t *addr, uint32_t type)
{
	int j, sl;
	char *ss;
	unsigned int v;

	bzero(addr, 16);
	if (strisipaddr(s)) {
		if (type == AU_IPv4) {
			if (inet_pton(AF_INET, s, addr)) {
				return (0);
			}
			return (1);
		} else if (type == AU_IPv6) {
			if (inet_pton(AF_INET6, s, addr))
				return (0);
			return (1);
		}
		return (1);
	} else {
		if (type == AU_IPv4) {
			(void) sscanf(s, "%x", &addr[0]);
			return (0);
		} else if (type == AU_IPv6) {
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
str2type(char *s, uint_t *type)
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

/*
 * exit_error() - print an error message along with corresponding system error
 * number and error message, then exit. Inputs - program error format and
 * message.
 */
/*PRINTFLIKE1*/
static void
exit_error(char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	prt_error_va(fmt, args);
	va_end(args);

	exit(1);
}
