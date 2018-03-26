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
 *
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/sysconf.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>
#include <ctype.h>
#include <time.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <door.h>
#include <setjmp.h>

#include <ipsec_util.h>
#include <ikedoor.h>

static int	doorfd = -1;

/*
 * These are additional return values for the command line parsing
 * function (parsecmd()).  They are specific to this utility, but
 * need to share the same space as the IKE_SVC_* defs, without conflicts.
 * So they're defined relative to the end of that range.
 */
#define	IKEADM_HELP_GENERAL	IKE_SVC_MAX + 1
#define	IKEADM_HELP_GET		IKE_SVC_MAX + 2
#define	IKEADM_HELP_SET		IKE_SVC_MAX + 3
#define	IKEADM_HELP_ADD		IKE_SVC_MAX + 4
#define	IKEADM_HELP_DEL		IKE_SVC_MAX + 5
#define	IKEADM_HELP_DUMP	IKE_SVC_MAX + 6
#define	IKEADM_HELP_FLUSH	IKE_SVC_MAX + 7
#define	IKEADM_HELP_READ	IKE_SVC_MAX + 8
#define	IKEADM_HELP_WRITE	IKE_SVC_MAX + 9
#define	IKEADM_HELP_TOKEN	IKE_SVC_MAX + 10
#define	IKEADM_HELP_HELP	IKE_SVC_MAX + 11
#define	IKEADM_EXIT		IKE_SVC_MAX + 12

/*
 * Disable default TAB completion for now (until some brave soul tackles it).
 */
/* ARGSUSED */
static
CPL_MATCH_FN(no_match)
{
	return (0);
}

static void command_complete(int s) __NORETURN;
static void usage(void) __NORETURN;

static void
command_complete(int s)
{
	if (interactive) {
		longjmp(env, 1);
	} else {
		exit(s);
	}
}

static void
usage(void)
{
	if (!interactive) {
		(void) fprintf(stderr, gettext("Usage:\t"
		    "ikeadm [ -hnp ] cmd obj [cmd-specific options]\n"));
		(void) fprintf(stderr, gettext("      \tikeadm help\n"));
	} else {
		(void) fprintf(stderr,
		    gettext("\nType help for usage info\n"));
	}

	command_complete(1);
}

static void
print_help()
{
	(void) printf(gettext("Valid commands and objects:\n"));
	(void) printf(
	    "\tget   debug|priv|stats|p1|rule|preshared|defaults [%s]\n",
	    gettext("identifier"));
	(void) printf("\tset   priv %s\n", gettext("level"));
	(void) printf("\tset   debug %s [%s]\n",
	    gettext("level"), gettext("filename"));
	(void) printf("\tadd   rule|preshared {%s}|%s\n",
	    gettext("definition"), gettext("filename"));
	(void) printf("\tdel   p1|rule|preshared %s\n", gettext("identifier"));
	(void) printf("\tdump  p1|rule|preshared|certcache|groups|"
	    "encralgs|authalgs\n");
	(void) printf("\tflush p1|certcache\n");
	(void) printf("\tread  rule|preshared [%s]\n", gettext("filename"));
	(void) printf("\twrite rule|preshared %s\n", gettext("filename"));
	(void) printf("\ttoken <login|logout> %s\n",
	    gettext("<PKCS#11 Token Object>"));
	(void) printf(
	    "\thelp  [get|set|add|del|dump|flush|read|write|token|help]\n");
	(void) printf("\texit  %s\n", gettext("exit the program"));
	(void) printf("\tquit  %s\n", gettext("exit the program"));

	command_complete(0);
}

static void
print_get_help()
{
	(void) printf(
	    gettext("This command gets information from in.iked.\n\n"));
	(void) printf(gettext("Objects that may be retrieved include:\n"));
	(void) printf("\tdebug\t\t");
	(void) printf(gettext("the current debug level\n"));
	(void) printf("\tpriv\t\t");
	(void) printf(gettext("the current privilege level\n"));
	(void) printf("\tstats\t\t");
	(void) printf(gettext("current usage statistics\n"));
	(void) printf("\tp1\t\t");
	(void) printf(gettext("a phase 1 SA, identified by\n"));
	(void) printf(gettext("\t\t\t  local_ip remote_ip OR\n"));
	(void) printf(gettext("\t\t\t  init_cookie resp_cookie\n"));
	(void) printf("\trule\t\t");
	(void) printf(gettext("a phase 1 rule, identified by its label\n"));
	(void) printf("\tpreshared\t");
	(void) printf(gettext("a preshared key, identified by\n"));
	(void) printf(gettext("\t\t\t  local_ip remote_ip OR\n"));
	(void) printf(gettext("\t\t\t  local_id remote_id\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_set_help()
{
	(void) printf(gettext("This command sets values in in.iked.\n\n"));
	(void) printf(gettext("Objects that may be set include:\n"));
	(void) printf("\tdebug\t\t");
	(void) printf(gettext("change the debug level\n"));
	(void) printf("\tpriv\t\t");
	(void) printf(
	    gettext("change the privilege level (may only be lowered)\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_add_help()
{
	(void) printf(
	    gettext("This command adds items to in.iked's tables.\n\n"));
	(void) printf(gettext("Objects that may be set include:\n"));
	(void) printf("\trule\t\t");
	(void) printf(gettext("a phase 1 policy rule\n"));
	(void) printf("\tpreshared\t");
	(void) printf(gettext("a preshared key\n"));
	(void) printf(
	    gettext("\nObjects may be entered on the command-line, as a\n"));
	(void) printf(
	    gettext("series of keywords and tokens contained in curly\n"));
	(void) printf(
	    gettext("braces ('{', '}'); or the name of a file containing\n"));
	(void) printf(gettext("the object definition may be provided.\n\n"));
	(void) printf(
	    gettext("For security purposes, preshared keys may only be\n"));
	(void) printf(
	    gettext("entered on the command-line if ikeadm is running in\n"));
	(void) printf(gettext("interactive mode.\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_del_help()
{
	(void) printf(
	    gettext("This command deletes an item from in.iked's tables.\n\n"));
	(void) printf(gettext("Objects that may be deleted include:\n"));
	(void) printf("\tp1\t\t");
	(void) printf(gettext("a phase 1 SA, identified by\n"));
	(void) printf(gettext("\t\t\t  local_ip remote_ip OR\n"));
	(void) printf(gettext("\t\t\t  init_cookie resp_cookie\n"));
	(void) printf("\trule\t\t");
	(void) printf(gettext("a phase 1 rule, identified by its label\n"));
	(void) printf("\tpreshared\t");
	(void) printf(gettext("a preshared key, identified by\n"));
	(void) printf(gettext("\t\t\t  local_ip remote_ip OR\n"));
	(void) printf(gettext("\t\t\t  local_id remote_id\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_dump_help()
{
	(void) printf(
	    gettext("This command dumps one of in.iked's tables.\n\n"));
	(void) printf(gettext("Tables that may be dumped include:\n"));
	(void) printf("\tp1\t\t");
	(void) printf(gettext("all phase 1 SAs\n"));
	(void) printf("\trule\t\t");
	(void) printf(gettext("all phase 1 rules\n"));
	(void) printf("\tpreshared\t");
	(void) printf(gettext("all preshared keys\n"));
	(void) printf("\tcertcache\t");
	(void) printf(gettext("all cached certificates\n"));
	(void) printf("\tgroups\t\t");
	(void) printf(gettext("all implemented Diffie-Hellman groups\n"));
	(void) printf("\tencralgs\t");
	(void) printf(gettext("all encryption algorithms for IKE\n"));
	(void) printf("\tauthalgs\t");
	(void) printf(gettext("all authentication algorithms IKE\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_flush_help()
{
	(void) printf(
	    gettext("This command clears one of in.iked's tables.\n\n"));
	(void) printf(gettext("Tables that may be flushed include:\n"));
	(void) printf("\tp1\t\t");
	(void) printf(gettext("all phase 1 SAs\n"));
	(void) printf("\tcertcache\t");
	(void) printf(gettext("all cached certificates\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_read_help()
{
	(void) printf(
	    gettext("This command reads a new configuration file into\n"));
	(void) printf(
	    gettext("in.iked, discarding the old configuration info.\n\n"));
	(void) printf(gettext("Sets of data that may be read include:\n"));
	(void) printf("\trule\t\t");
	(void) printf(gettext("all phase 1 rules\n"));
	(void) printf("\tpreshared\t");
	(void) printf(gettext("all preshared keys\n\n"));
	(void) printf(
	    gettext("A filename may be provided to specify a source file\n"));
	(void) printf(gettext("other than the default.\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_write_help()
{
	(void) printf(
	    gettext("This command writes in.iked's current configuration\n"));
	(void) printf(gettext("out to a config file.\n\n"));
	(void) printf(gettext("Sets of data that may be written include:\n"));
	(void) printf("\trule\t\t");
	(void) printf(gettext("all phase 1 rules\n"));
	(void) printf("\tpreshared\t");
	(void) printf(gettext("all preshared keys\n\n"));
	(void) printf(
	    gettext("A filename must be provided to specify the file to\n"));
	(void) printf(gettext("which the information should be written.\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_token_help()
{
	(void) printf(gettext(
	    "This command logs IKE into and out of PKCS#11 tokens.\n\n"));
	(void) printf(gettext("Commands include:\n"));
	(void) printf("\tlogin <PKCS#11 Token Object>\t");
	(void) printf(gettext("log into token\n"));
	(void) printf("\tlogout <PKCS#11 Token Object>\t");
	(void) printf(gettext("log out of token\n\n"));
	(void) printf(
	    gettext("The PKCS#11 Token Object name must be "
	    "enclosed in quotation marks.\n"));
	(void) printf("\n");

	command_complete(0);
}

static void
print_help_help()
{
	(void) printf(
	    gettext("This command provides information about commands.\n\n"));
	(void) printf(
	    gettext("The 'help' command alone provides a list of valid\n"));
	(void) printf(
	    gettext("commands, along with the valid objects for each.\n"));
	(void) printf(
	    gettext("'help' followed by a valid command name provides\n"));
	(void) printf(gettext("further information about that command.\n"));
	(void) printf("\n");

	command_complete(0);
}

/*PRINTFLIKE1*/
static void
message(char *fmt, ...)
{
	va_list	ap;
	char	msgbuf[BUFSIZ];

	va_start(ap, fmt);
	(void) vsnprintf(msgbuf, BUFSIZ, fmt, ap);
	(void) fprintf(stderr, gettext("ikeadm: %s\n"), msgbuf);
	va_end(ap);
}

static int
open_door(void)
{
	if (doorfd >= 0)
		(void) close(doorfd);
	doorfd = open(DOORNM, O_RDONLY);
	return (doorfd);
}

static ike_service_t *
ikedoor_call(char *reqp, int size, door_desc_t *descp, int ndesc)
{
	door_arg_t	arg;
	int retries = 0;

	arg.data_ptr = reqp;
	arg.data_size = size;
	arg.desc_ptr = descp;
	arg.desc_num = ndesc;
	arg.rbuf = (char *)NULL;
	arg.rsize = 0;

retry:
	if (door_call(doorfd, &arg) < 0) {
		if ((errno == EBADF) && ((++retries < 2) &&
		    (open_door() >= 0)))
			goto retry;
		(void) fprintf(stderr,
		    gettext("Unable to communicate with in.iked\n"));
		Bail("door_call failed");
	}

	if ((ndesc > 0) && (descp->d_attributes & DOOR_RELEASE) &&
	    ((errno == EBADF) || (errno == EFAULT))) {
		/* callers assume passed fds will be closed no matter what */
		(void) close(descp->d_data.d_desc.d_descriptor);
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	return ((ike_service_t *)arg.rbuf);
}

/*
 * Parsing functions
 */

/* stolen from ipseckey.c, with a second tier added */
static int
parsecmd(char *cmdstr, char *objstr)
{
#define	MAXOBJS		11
	struct objtbl {
		char	*obj;
		int	token;
	};
	static struct cmdtbl {
		char		*cmd;
		int		null_obj_token;
		struct objtbl	objt[MAXOBJS];
	} table[] = {
		{"get", IKE_SVC_ERROR, {
				{"debug",	IKE_SVC_GET_DBG},
				{"priv",	IKE_SVC_GET_PRIV},
				{"stats",	IKE_SVC_GET_STATS},
				{"p1",		IKE_SVC_GET_P1},
				{"rule",	IKE_SVC_GET_RULE},
				{"preshared",	IKE_SVC_GET_PS},
				{"defaults",	IKE_SVC_GET_DEFS},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"set", IKE_SVC_ERROR, {
				{"debug",	IKE_SVC_SET_DBG},
				{"priv",	IKE_SVC_SET_PRIV},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"token", IKE_SVC_ERROR, {
				{"login",	IKE_SVC_SET_PIN},
				{"logout",	IKE_SVC_DEL_PIN},
				{NULL,		IKE_SVC_ERROR},
			}
		},
		{"add", IKE_SVC_ERROR, {
				{"rule",	IKE_SVC_NEW_RULE},
				{"preshared",	IKE_SVC_NEW_PS},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"del", IKE_SVC_ERROR, {
				{"p1",		IKE_SVC_DEL_P1},
				{"rule",	IKE_SVC_DEL_RULE},
				{"preshared",	IKE_SVC_DEL_PS},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"dump", IKE_SVC_ERROR, {
				{"p1",		IKE_SVC_DUMP_P1S},
				{"rule",	IKE_SVC_DUMP_RULES},
				{"preshared",	IKE_SVC_DUMP_PS},
				{"certcache",	IKE_SVC_DUMP_CERTCACHE},
				{"groups",	IKE_SVC_DUMP_GROUPS},
				{"encralgs",	IKE_SVC_DUMP_ENCRALGS},
				{"authalgs",	IKE_SVC_DUMP_AUTHALGS},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"flush", IKE_SVC_ERROR, {
				{"p1",		IKE_SVC_FLUSH_P1S},
				{"certcache",	IKE_SVC_FLUSH_CERTCACHE},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"read", IKE_SVC_ERROR, {
				{"rule",	IKE_SVC_READ_RULES},
				{"preshared",	IKE_SVC_READ_PS},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"write", IKE_SVC_ERROR, {
				{"rule",	IKE_SVC_WRITE_RULES},
				{"preshared",	IKE_SVC_WRITE_PS},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"help", IKEADM_HELP_GENERAL, {
				{"get",		IKEADM_HELP_GET},
				{"set",		IKEADM_HELP_SET},
				{"add",		IKEADM_HELP_ADD},
				{"del",		IKEADM_HELP_DEL},
				{"dump",	IKEADM_HELP_DUMP},
				{"flush",	IKEADM_HELP_FLUSH},
				{"read",	IKEADM_HELP_READ},
				{"write",	IKEADM_HELP_WRITE},
				{"token",	IKEADM_HELP_TOKEN},
				{"help",	IKEADM_HELP_HELP},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"exit", IKEADM_EXIT, {
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"quit", IKEADM_EXIT, {
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{"dbg", IKE_SVC_ERROR, {
				{"rbdump",	IKE_SVC_DBG_RBDUMP},
				{NULL,		IKE_SVC_ERROR}
			}
		},
		{NULL,	IKE_SVC_ERROR, {
				{NULL,		IKE_SVC_ERROR}
			}
		}
	};
	struct cmdtbl	*ct = table;
	struct objtbl	*ot;

	if (cmdstr == NULL) {
		return (IKE_SVC_ERROR);
	}

	while (ct->cmd != NULL && strcmp(ct->cmd, cmdstr) != 0)
		ct++;
	ot = ct->objt;

	if (ct->cmd == NULL) {
		message(gettext("Unrecognized command '%s'"), cmdstr);
		return (ot->token);
	}

	if (objstr == NULL) {
		return (ct->null_obj_token);
	}

	while (ot->obj != NULL && strcmp(ot->obj, objstr) != 0)
		ot++;

	if (ot->obj == NULL)
		message(gettext("Unrecognized object '%s'"), objstr);

	return (ot->token);
}

/*
 * Parsing functions:
 * Parse command-line identification info.  All return -1 on failure,
 * or the number of cmd-line args "consumed" on success (though argc
 * and argv params are not actually modified).
 */

static int
parse_label(int argc, char **argv, char *label)
{
	if ((argc < 1) || (argv == NULL))
		return (-1);

	if (strlcpy(label, argv[0], MAX_LABEL_LEN) >= MAX_LABEL_LEN)
		return (-1);

	return (1);
}

/*
 * Parse a PKCS#11 token get the label.
 */
static int
parse_token(int argc, char **argv, char *token_label)
{
	if ((argc < 1) || (argv == NULL))
		return (-1);

	if (strlcpy(token_label, argv[0], PKCS11_TOKSIZE) >= PKCS11_TOKSIZE)
		return (-1);

	return (0);
}

/*
 * Parse an address off the command line. In the hpp param, either
 * return a hostent pointer (caller frees) or a pointer to a dummy_he_t
 * (must also be freed by the caller; both cases are handled by the
 * macro FREE_HE).  The new getipnodebyname() call does the Right Thing
 * (TM), even with raw addresses (colon-separated IPv6 or dotted decimal
 * IPv4).
 * (mostly stolen from ipseckey.c, though some tweaks were made
 * to better serve our purposes here.)
 */

typedef struct {
	struct hostent	he;
	char		*addtl[2];
} dummy_he_t;

static int
parse_addr(int argc, char **argv, struct hostent **hpp)
{
	int		hp_errno;
	struct hostent	*hp = NULL;
	dummy_he_t	*dhp;
	char		*addr1;

	if ((argc < 1) || (argv == NULL) || (argv[0] == NULL))
		return (-1);

	if (!nflag) {
		/*
		 * Try name->address first.  Assume AF_INET6, and
		 * get IPV4s, plus IPv6s iff IPv6 is configured.
		 */
		hp = getipnodebyname(argv[0], AF_INET6, AI_DEFAULT | AI_ALL,
		    &hp_errno);
	} else {
		/*
		 * Try a normal address conversion only.  malloc a
		 * dummy_he_t to construct a fake hostent.  Caller
		 * will know to free this one using free_he().
		 */
		dhp = (dummy_he_t *)malloc(sizeof (dummy_he_t));
		addr1 = (char *)malloc(sizeof (struct in6_addr));
		if (inet_pton(AF_INET6, argv[0], addr1) == 1) {
			dhp->he.h_addr_list = dhp->addtl;
			dhp->addtl[0] = addr1;
			dhp->addtl[1] = NULL;
			hp = &dhp->he;
			dhp->he.h_addrtype = AF_INET6;
			dhp->he.h_length = sizeof (struct in6_addr);
		} else if (inet_pton(AF_INET, argv[0], addr1) == 1) {
			dhp->he.h_addr_list = dhp->addtl;
			dhp->addtl[0] = addr1;
			dhp->addtl[1] = NULL;
			hp = &dhp->he;
			dhp->he.h_addrtype = AF_INET;
			dhp->he.h_length = sizeof (struct in_addr);
		} else {
			hp = NULL;
		}
	}

	*hpp = hp;

	if (hp == NULL) {
		message(gettext("Unknown address %s."), argv[0]);
		return (-1);
	}

	return (1);
}

/*
 * Free a dummy_he_t structure that was malloc'd in parse_addr().
 * Unfortunately, callers of parse_addr don't want to know about
 * dummy_he_t structs, so all they have is a pointer to the struct
 * hostent; so that's what's passed in.  To manage this, we make
 * the assumption that the struct hostent is the first field in
 * the dummy_he_t, and therefore a pointer to it is a pointer to
 * the dummy_he_t.
 */
static void
free_he(struct hostent *hep)
{
	dummy_he_t	*p = (dummy_he_t *)hep;

	assert(p != NULL);

	if (p->addtl[0])
		free(p->addtl[0]);
	if (p->addtl[1])
		free(p->addtl[1]);

	free(p);
}

#define	FREE_HE(x) \
	if (nflag) \
		free_he(x); \
	else \
		freehostent(x)

static void
headdr2sa(char *hea, struct sockaddr_storage *sa, int len)
{
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;

	if (len == sizeof (struct in6_addr)) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)hea)) {
			sin = (struct sockaddr_in *)sa;
			(void) memset(sin, 0, sizeof (*sin));
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			IN6_V4MAPPED_TO_INADDR((struct in6_addr *)hea,
			    &sin->sin_addr);
			sin->sin_family = AF_INET;
		} else {
			sin6 = (struct sockaddr_in6 *)sa;
			(void) memset(sin6, 0, sizeof (*sin6));
			(void) memcpy(&sin6->sin6_addr, hea,
			    sizeof (struct in6_addr));
			sin6->sin6_family = AF_INET6;
		}
	} else {
		sin = (struct sockaddr_in *)sa;
		(void) memset(sin, 0, sizeof (*sin));
		(void) memcpy(&sin->sin_addr, hea, sizeof (struct in_addr));
		sin->sin_family = AF_INET;
	}
}

/*
 * The possible ident-type keywords that might be used on the command
 * line.  This is a superset of the ones supported by ipseckey, those
 * in the ike config file, and those in ike.preshared.
 */
static keywdtab_t	idtypes[] = {
	/* ip, ipv4, and ipv6 are valid for preshared keys... */
	{SADB_IDENTTYPE_RESERVED,	"ip"},
	{SADB_IDENTTYPE_RESERVED,	"ipv4"},
	{SADB_IDENTTYPE_RESERVED,	"ipv6"},
	{SADB_IDENTTYPE_PREFIX,		"prefix"},
	{SADB_IDENTTYPE_PREFIX,		"ipv4-prefix"},
	{SADB_IDENTTYPE_PREFIX,		"ipv6-prefix"},
	{SADB_IDENTTYPE_PREFIX,		"subnet"},
	{SADB_IDENTTYPE_PREFIX,		"subnetv4"},
	{SADB_IDENTTYPE_PREFIX,		"subnetv6"},
	{SADB_IDENTTYPE_FQDN,		"fqdn"},
	{SADB_IDENTTYPE_FQDN,		"dns"},
	{SADB_IDENTTYPE_FQDN,		"domain"},
	{SADB_IDENTTYPE_FQDN,		"domainname"},
	{SADB_IDENTTYPE_USER_FQDN,	"user_fqdn"},
	{SADB_IDENTTYPE_USER_FQDN,	"mbox"},
	{SADB_IDENTTYPE_USER_FQDN,	"mailbox"},
	{SADB_X_IDENTTYPE_DN,		"dn"},
	{SADB_X_IDENTTYPE_DN,		"asn1dn"},
	{SADB_X_IDENTTYPE_GN,		"gn"},
	{SADB_X_IDENTTYPE_GN,		"asn1gn"},
	{SADB_X_IDENTTYPE_ADDR_RANGE,	"ipv4-range"},
	{SADB_X_IDENTTYPE_ADDR_RANGE,	"ipv6-range"},
	{SADB_X_IDENTTYPE_ADDR_RANGE,	"rangev4"},
	{SADB_X_IDENTTYPE_ADDR_RANGE,	"rangev6"},
	{SADB_X_IDENTTYPE_KEY_ID,	"keyid"},
	{NULL,	0}
};

static int
parse_idtype(char *type, uint16_t *idnum)
{
	keywdtab_t	*idp;

	if (type == NULL)
		return (-1);

	for (idp = idtypes; idp->kw_str != NULL; idp++) {
		if (strcasecmp(idp->kw_str, type) == 0) {
			if (idnum != NULL)
				*idnum = idp->kw_tag;
			return (1);
		}
	}

	return (-1);
}

/*
 * The sadb_ident_t is malloc'd, since its length varies;
 * so the caller must free() it when done with the data.
 */
static int
parse_ident(int argc, char **argv, sadb_ident_t **idpp)
{
	int		alloclen, consumed;
	sadb_ident_t	*idp;
	if ((argc < 2) || (argv == NULL) || (argv[0] == NULL) ||
	    (argv[1] == NULL))
		return (-1);

	alloclen = sizeof (sadb_ident_t) + IKEDOORROUNDUP(strlen(argv[1]) + 1);
	*idpp = idp = (sadb_ident_t *)malloc(alloclen);
	if (idp == NULL)
		Bail("parsing identity");

	if ((consumed = parse_idtype(argv[0], &idp->sadb_ident_type)) < 0) {
		message(gettext("unknown identity type %s."), argv[0]);
		return (-1);
	}

	idp->sadb_ident_len = SADB_8TO64(alloclen);
	idp->sadb_ident_reserved = 0;
	idp->sadb_ident_id = 0;

	/* now copy in identity param */
	(void) strlcpy((char *)(idp + 1), argv[1],
	    alloclen - (sizeof (sadb_ident_t)));

	return (++consumed);
}

static int
parse_cky(int argc, char **argv, uint64_t *ckyp)
{
	u_longlong_t	arg;

	if ((argc < 1) || (argv[0] == NULL))
		return (-1);

	errno = 0;
	arg = strtoull(argv[0], NULL, 0);
	if (errno != 0) {
		message(gettext("failed to parse cookie %s."), argv[0]);
		return (-1);
	}

	*ckyp = (uint64_t)arg;

	return (1);
}

static int
parse_addr_pr(int argc, char **argv, struct hostent **h1pp,
    struct hostent **h2pp)
{
	int	rtn, consumed = 0;

	if ((rtn = parse_addr(argc, argv, h1pp)) < 0) {
		return (-1);
	}
	consumed = rtn;
	argc -= rtn;
	argv += rtn;

	if ((rtn = parse_addr(argc, argv, h2pp)) < 0) {
		FREE_HE(*h1pp);
		return (-1);
	}
	consumed += rtn;

	return (consumed);
}

/*
 * The sadb_ident_ts are malloc'd, since their length varies;
 * so the caller must free() them when done with the data.
 */
static int
parse_ident_pr(int argc, char **argv, sadb_ident_t **id1pp,
    sadb_ident_t **id2pp)
{
	int	rtn, consumed = 0;

	if ((rtn = parse_ident(argc, argv, id1pp)) < 0) {
		return (-1);
	}
	consumed = rtn;
	argc -= rtn;
	argv += rtn;

	(*id1pp)->sadb_ident_exttype = SADB_EXT_IDENTITY_SRC;

	if ((rtn = parse_ident(argc, argv, id2pp)) < 0) {
		free(*id1pp);
		return (-1);
	}
	consumed += rtn;

	(*id2pp)->sadb_ident_exttype = SADB_EXT_IDENTITY_DST;

	return (consumed);
}

static int
parse_cky_pr(int argc, char **argv, ike_cky_pr_t *cpr)
{
	int	rtn, consumed = 0;

	if ((rtn = parse_cky(argc, argv, &cpr->cky_i)) < 0) {
		return (-1);
	}
	consumed = rtn;
	argc -= rtn;
	argv += rtn;

	if ((rtn = parse_cky(argc, argv, &cpr->cky_r)) < 0) {
		return (-1);
	}
	consumed += rtn;

	return (consumed);
}

/*
 * Preshared key field types...used for parsing preshared keys that
 * have been entered on the command line.  The code to parse preshared
 * keys (parse_ps, parse_key, parse_psfldid, parse_ikmtype, ...) is
 * mostly duplicated from in.iked's readps.c.
 */
#define	PSFLD_LOCID	1
#define	PSFLD_LOCIDTYPE	2
#define	PSFLD_REMID	3
#define	PSFLD_REMIDTYPE	4
#define	PSFLD_MODE	5
#define	PSFLD_KEY	6

static keywdtab_t	psfldtypes[] = {
	{PSFLD_LOCID,		"localid"},
	{PSFLD_LOCIDTYPE,	"localidtype"},
	{PSFLD_REMID,		"remoteid"},
	{PSFLD_REMIDTYPE,	"remoteidtype"},
	{PSFLD_MODE,		"ike_mode"},
	{PSFLD_KEY,		"key"},
	{NULL,	0}
};

static int
parse_psfldid(char *type, uint16_t *idnum)
{
	keywdtab_t	*pfp;

	if (type == NULL)
		return (-1);

	for (pfp = psfldtypes; pfp->kw_str != NULL; pfp++) {
		if (strcasecmp(pfp->kw_str, type) == 0) {
			if (idnum != NULL)
				*idnum = pfp->kw_tag;
			return (1);
		}
	}

	return (-1);
}

static keywdtab_t	ikemodes[] = {
	{IKE_XCHG_IDENTITY_PROTECT,	"main"},
	{IKE_XCHG_AGGRESSIVE,		"aggressive"},
	{IKE_XCHG_IP_AND_AGGR,		"both"},
	{NULL,	0}
};

static int
parse_ikmtype(char *mode, uint16_t *modenum)
{
	keywdtab_t	*ikmp;

	if (mode == NULL)
		return (-1);

	for (ikmp = ikemodes; ikmp->kw_str != NULL; ikmp++) {
		if (strcasecmp(ikmp->kw_str, mode) == 0) {
			if (modenum != NULL)
				*modenum = ikmp->kw_tag;
			return (1);
		}
	}

	return (-1);
}

#define	hd2num(hd) (((hd) >= '0' && (hd) <= '9') ? ((hd) - '0') : \
	(((hd) >= 'a' && (hd) <= 'f') ? ((hd) - 'a' + 10) : ((hd) - 'A' + 10)))

static uint8_t *
parse_key(char *input, uint_t *keybuflen, uint_t *lbits)
{
	uint8_t	*keyp, *keybufp;
	uint_t	i, hexlen = 0, bits, alloclen;

	for (i = 0; input[i] != '\0' && input[i] != '/'; i++)
		hexlen++;

	if (input[i] == '\0') {
		bits = 0;
	} else {
		/* Have /nn. */
		input[i] = '\0';
		if (sscanf((input + i + 1), "%u", &bits) != 1)
			return (NULL);

		/* hexlen is in nibbles */
		if (((bits + 3) >> 2) > hexlen)
			return (NULL);

		/*
		 * Adjust hexlen down if user gave us too small of a bit
		 * count.
		 */
		if ((hexlen << 2) > bits + 3) {
			hexlen = (bits + 3) >> 2;
			input[hexlen] = '\0';
		}
	}

	/*
	 * Allocate.  Remember, hexlen is in nibbles.
	 */

	alloclen = (hexlen/2 + (hexlen & 0x1));
	keyp = malloc(alloclen);

	if (keyp == NULL)
		return (NULL);

	keybufp = keyp;
	*keybuflen = alloclen;
	if (bits == 0)
		*lbits = (hexlen + (hexlen & 0x1)) << 2;
	else
		*lbits = bits;

	/*
	 * Read in nibbles.  Read in odd-numbered as shifted high.
	 * (e.g. 123 becomes 0x1230).
	 */
	for (i = 0; input[i] != '\0'; i += 2) {
		boolean_t second = (input[i + 1] != '\0');

		if (!isxdigit(input[i]) ||
		    (!isxdigit(input[i + 1]) && second)) {
			free(keyp);
			return (NULL);
		}
		*keyp = (hd2num(input[i]) << 4);
		if (second)
			*keyp |= hd2num(input[i + 1]);
		else
			break; /* out of for loop. */
		keyp++;
	}

	/* zero the remaining bits if we're a non-octet amount. */
	if (bits & 0x7)
		*((input[i] == '\0') ? keyp - 1 : keyp) &=
		    0xff << (8 - (bits & 0x7));
	return (keybufp);
}

/*
 * the ike_ps_t struct (plus trailing data) will be allocated here,
 * so it will need to be freed by the caller.
 */
static int
parse_ps(int argc, char **argv, ike_ps_t **presharedpp, int *len)
{
	uint_t		c = 0, locidlen, remidlen, keylen, keybits;
	uint_t		a_locidtotal = 0, a_remidtotal = 0;
	char		*locid, *remid, *locpfx = NULL, *rempfx = NULL;
	uint8_t		*keyp = NULL;
	uint16_t	fldid, locidtype, remidtype, mtype;
	struct hostent	*loche = NULL, *remhe = NULL;
	ike_ps_t	*psp = NULL;
	sadb_ident_t	*sidp;
	boolean_t	whacked = B_FALSE;
	int pfxlen = 0;

	if ((argv[c] == NULL) || (argv[c][0] != '{'))
		return (-1);
	if (argv[c][1] != 0) {
		/* no space between '{' and first token */
		argv[c]++;
	} else {
		c++;
	}
	if ((argv[argc - 1][strlen(argv[argc - 1]) - 1] == '}') &&
	    (argv[argc - 1][0] != '}')) {
		/*
		 * whack '}' without a space before it or parsers break.
		 * Remember this trailing character for later
		 */
		argv[argc - 1][strlen(argv[argc - 1]) - 1] = '\0';
		whacked = B_TRUE;
	}

	/* Default to type IP */
	locidtype = remidtype = SADB_IDENTTYPE_RESERVED;
	/* Default to base exchanges */
	mtype = IKE_XCHG_BASE;

	while ((c < argc) && (argv[c] != NULL) && (argv[c][0] != '}')) {
		if ((argv[c + 1] == NULL) || (argv[c + 1][0] == '}'))
			goto bail;
		if (parse_psfldid(argv[c++], &fldid) < 0)
			goto bail;
		switch (fldid) {
		case PSFLD_LOCID:
			locid = argv[c++];
			locidlen = strlen(locid) + 1;
			break;
		case PSFLD_LOCIDTYPE:
			if (parse_idtype(argv[c++], &locidtype) < 0)
				goto bail;
			break;
		case PSFLD_REMID:
			remid = argv[c++];
			remidlen = strlen(remid) + 1;
			break;
		case PSFLD_REMIDTYPE:
			if (parse_idtype(argv[c++], &remidtype) < 0)
				goto bail;
			break;
		case PSFLD_MODE:
			if (parse_ikmtype(argv[c++], &mtype) < 0)
				goto bail;
			break;
		case PSFLD_KEY:
			keyp  = parse_key(argv[c++], &keylen, &keybits);
			if (keyp == NULL)
				goto bail;
			break;
		}
	}

	/* Make sure the line was terminated with '}' */
	if (argv[c] == NULL) {
		if (!whacked)
			goto bail;
	} else if (argv[c][0] != '}') {
		goto bail;
	}

	/*
	 * make sure we got all the required fields.  If no idtype, assume
	 * ip addr; if that translation fails, we'll catch the error then.
	 */
	if (locid == NULL || remid == NULL || keyp == NULL || mtype == 0)
		goto bail;

	/* figure out the size buffer we need */
	*len = sizeof (ike_ps_t);
	if (locidtype != SADB_IDENTTYPE_RESERVED) {
		a_locidtotal = IKEDOORROUNDUP(sizeof (sadb_ident_t) + locidlen);
		*len += a_locidtotal;
	}
	if (remidtype != SADB_IDENTTYPE_RESERVED) {
		a_remidtotal = IKEDOORROUNDUP(sizeof (sadb_ident_t) + remidlen);
		*len += a_remidtotal;
	}
	*len += keylen;

	psp = malloc(*len);
	if (psp == NULL)
		goto bail;
	(void) memset(psp, 0, *len);

	psp->ps_ike_mode = mtype;

	psp->ps_localid_off = sizeof (ike_ps_t);
	if (locidtype == SADB_IDENTTYPE_RESERVED) {
		locpfx = strchr(locid, '/');
		if (locpfx != NULL) {
			*locpfx = '\0';
			locpfx++;
		}

		/*
		 * this is an ip address, store in the sockaddr field;
		 * we won't use an sadb_ident_t.
		 */
		psp->ps_localid_len = 0;
		if (parse_addr(1, &locid, &loche) < 0)
			goto bail;
		if (loche->h_addr_list[1] != NULL) {
			message(gettext("preshared key identifier cannot "
			    "match multiple IP addresses"));
			goto bail;
		}
		headdr2sa(loche->h_addr_list[0], &psp->ps_ipaddrs.loc_addr,
		    loche->h_length);
		FREE_HE(loche);
	} else {
		psp->ps_localid_len = sizeof (sadb_ident_t) + locidlen;
		sidp = (sadb_ident_t *)((int)psp + psp->ps_localid_off);
		sidp->sadb_ident_len = psp->ps_localid_len;
		sidp->sadb_ident_type = locidtype;
		(void) strlcpy((char *)(sidp + 1), locid, a_locidtotal);
	}

	psp->ps_remoteid_off = psp->ps_localid_off + a_locidtotal;
	if (remidtype == SADB_IDENTTYPE_RESERVED) {
		rempfx = strchr(remid, '/');
		if (rempfx != NULL) {
			*rempfx = '\0';
			rempfx++;
		}

		/*
		 * this is an ip address, store in the sockaddr field;
		 * we won't use an sadb_ident_t.
		 */
		psp->ps_remoteid_len = 0;
		if (parse_addr(1, &remid, &remhe) < 0)
			goto bail;
		if (remhe->h_addr_list[1] != NULL) {
			message(gettext("preshared key identifier cannot "
			    "match multiple IP addresses"));
			goto bail;
		}
		headdr2sa(remhe->h_addr_list[0], &psp->ps_ipaddrs.rem_addr,
		    remhe->h_length);
		FREE_HE(remhe);
	} else {
		/* make sure we have at least 16-bit alignment */
		if (remidlen & 0x1)
			remidlen++;
		psp->ps_remoteid_len = sizeof (sadb_ident_t) + remidlen;
		sidp = (sadb_ident_t *)((int)psp + psp->ps_remoteid_off);
		sidp->sadb_ident_len = psp->ps_remoteid_len;
		sidp->sadb_ident_type = remidtype;
		(void) strlcpy((char *)(sidp + 1), remid, a_remidtotal);
	}

	psp->ps_key_off = psp->ps_remoteid_off + a_remidtotal;
	psp->ps_key_len = keylen;
	psp->ps_key_bits = keybits;
	(void) memcpy((uint8_t *)((int)psp + psp->ps_key_off), keyp, keylen);
	if (locpfx != NULL && ((pfxlen = atoi(locpfx)) > 0))
		psp->ps_localid_plen = pfxlen;
	if (rempfx != NULL && ((pfxlen = atoi(rempfx)) > 0))
		psp->ps_remoteid_plen = pfxlen;

	*presharedpp = psp;

	return (c);

bail:
	if (loche != NULL)
		FREE_HE(loche);
	if (remhe != NULL)
		FREE_HE(remhe);
	if (keyp != NULL)
		free(keyp);
	if (psp != NULL)
		free(psp);

	*presharedpp = NULL;

	return (-1);
}

/*
 * Printing functions
 *
 * A potential point of confusion here is that the ikeadm-specific string-
 * producing functions do not match the ipsec_util.c versions in style: the
 * ikeadm-specific functions return a string (and are named foostr), while
 * the ipsec_util.c functions actually print the string to the file named
 * in the second arg to the function (and are named dump_foo).
 *
 * Localization for ikeadm seems more straightforward when complete
 * phrases are translated rather than: a part of a phrase, a call to
 * dump_foo(), and more of the phrase.  It could also accommodate
 * non-English grammar more easily.
 */

static char *
errstr(int err)
{
	static char	rtn[MAXLINESIZE];

	switch (err) {
	case IKE_ERR_NO_OBJ:
		return (gettext("No data returned"));
	case IKE_ERR_NO_DESC:
		return (gettext("No destination provided"));
	case IKE_ERR_ID_INVALID:
		return (gettext("Id info invalid"));
	case IKE_ERR_LOC_INVALID:
		return (gettext("Destination invalid"));
	case IKE_ERR_CMD_INVALID:
		return (gettext("Command invalid"));
	case IKE_ERR_DATA_INVALID:
		return (gettext("Supplied data invalid"));
	case IKE_ERR_CMD_NOTSUP:
		return (gettext("Unknown command"));
	case IKE_ERR_REQ_INVALID:
		return (gettext("Request invalid"));
	case IKE_ERR_NO_PRIV:
		return (gettext("Not allowed at current privilege level"));
	case IKE_ERR_NO_AUTH:
		return (gettext("User not authorized"));
	case IKE_ERR_SYS_ERR:
		return (gettext("System error"));
	case IKE_ERR_DUP_IGNORED:
		return (gettext("One or more duplicate entries ignored"));
	case IKE_ERR_NO_TOKEN:
		return (gettext(
		    "token login failed or no objects on device"));
	case IKE_ERR_IN_PROGRESS:
		return (gettext(
		    "Duplicate operation already in progress"));
	case IKE_ERR_NO_MEM:
		return (gettext(
		    "Insufficient memory"));
	default:
		(void) snprintf(rtn, MAXLINESIZE,
		    gettext("<unknown error %d>"), err);
		return (rtn);
	}
}

static char *
dbgstr(int bit)
{
	static char	rtn[MAXLINESIZE];

	switch (bit) {
	case D_CERT:
		return (gettext("Certificate management"));
	case D_KEY:
		return (gettext("Key management"));
	case D_OP:
		return (gettext("Operational"));
	case D_P1:
		return (gettext("Phase 1 SA creation"));
	case D_P2:
		return (gettext("Phase 2 SA creation"));
	case D_PFKEY:
		return (gettext("PF_KEY interface"));
	case D_POL:
		return (gettext("Policy management"));
	case D_PROP:
		return (gettext("Proposal construction"));
	case D_DOOR:
		return (gettext("Door interface"));
	case D_CONFIG:
		return (gettext("Config file processing"));
	case D_LABEL:
		return (gettext("MAC label processing"));
	default:
		(void) snprintf(rtn, MAXLINESIZE,
		    gettext("<unknown flag 0x%x>"), bit);
		return (rtn);
	}
}

static char *
privstr(int priv)
{
	static char	rtn[MAXLINESIZE];

	switch (priv) {
	case IKE_PRIV_MINIMUM:
		return (gettext("base privileges"));
	case IKE_PRIV_MODKEYS:
		return (gettext("access to preshared key information"));
	case IKE_PRIV_KEYMAT:
		return (gettext("access to keying material"));
	default:
		(void) snprintf(rtn, MAXLINESIZE,
		    gettext("<unknown level %d>"), priv);
		return (rtn);
	}
}

static char *
xchgstr(int xchg)
{
	static char	rtn[MAXLINESIZE];

	switch (xchg) {
	case IKE_XCHG_NONE:
		return (gettext("<unspecified>"));
	case IKE_XCHG_BASE:
		return (gettext("base"));
	case IKE_XCHG_IDENTITY_PROTECT:
		return (gettext("main mode (identity protect)"));
	case IKE_XCHG_AUTH_ONLY:
		return (gettext("authentication only"));
	case IKE_XCHG_AGGRESSIVE:
		return (gettext("aggressive mode"));
	case IKE_XCHG_IP_AND_AGGR:
		return (gettext("main and aggressive mode"));
	case IKE_XCHG_ANY:
		return (gettext("any mode"));
	default:
		(void) snprintf(rtn, MAXLINESIZE,
		    gettext("<unknown %d>"), xchg);
		return (rtn);
	}
}

static char *
statestr(int state)
{
	static char	rtn[MAXLINESIZE];

	switch (state) {
	case IKE_SA_STATE_INIT:
		return (gettext("INITIALIZING"));
	case IKE_SA_STATE_SENT_SA:
		return (gettext("SENT FIRST MSG (SA)"));
	case IKE_SA_STATE_SENT_KE:
		return (gettext("SENT SECOND MSG (KE)"));
	case IKE_SA_STATE_SENT_LAST:
		return (gettext("SENT FINAL MSG"));
	case IKE_SA_STATE_DONE:
		return (gettext("ACTIVE"));
	case IKE_SA_STATE_DELETED:
		return (gettext("DELETED"));
	case IKE_SA_STATE_INVALID:
		return (gettext("<invalid>"));
	default:
		(void) snprintf(rtn, MAXLINESIZE,
		    gettext("<unknown %d>"), state);
		return (rtn);
	}
}

static char *
authmethstr(int meth)
{
	static char	rtn[MAXLINESIZE];

	switch (meth) {
	case IKE_AUTH_METH_PRE_SHARED_KEY:
		return (gettext("pre-shared key"));
	case IKE_AUTH_METH_DSS_SIG:
		return (gettext("DSS signatures"));
	case IKE_AUTH_METH_RSA_SIG:
		return (gettext("RSA signatures"));
	case IKE_AUTH_METH_RSA_ENCR:
		return (gettext("RSA Encryption"));
	case IKE_AUTH_METH_RSA_ENCR_REVISED:
		return (gettext("Revised RSA Encryption"));
	default:
		(void) snprintf(rtn, MAXLINESIZE,
		    gettext("<unknown %d>"), meth);
		return (rtn);
	}
}

static char *
prfstr(int prf)
{
	static char	rtn[MAXLINESIZE];

	switch (prf) {
	case IKE_PRF_NONE:
		return (gettext("<none/unavailable>"));
	case IKE_PRF_HMAC_MD5:
		return ("HMAC MD5");
	case IKE_PRF_HMAC_SHA1:
		return ("HMAC SHA1");
	case IKE_PRF_HMAC_SHA256:
		return ("HMAC SHA256");
	case IKE_PRF_HMAC_SHA384:
		return ("HMAC SHA384");
	case IKE_PRF_HMAC_SHA512:
		return ("HMAC SHA512");
	default:
		(void) snprintf(rtn, MAXLINESIZE,
		    gettext("<unknown %d>"), prf);
		return (rtn);
	}
}

static char *
dhstr(int grp)
{
	static char	rtn[MAXLINESIZE];

	switch (grp) {
	case 0:
		return (gettext("<unavailable>"));
	case IKE_GRP_DESC_MODP_768:
		return (gettext("768-bit MODP (group 1)"));
	case IKE_GRP_DESC_MODP_1024:
		return (gettext("1024-bit MODP (group 2)"));
	case IKE_GRP_DESC_EC2N_155:
		return (gettext("EC2N group on GP[2^155]"));
	case IKE_GRP_DESC_EC2N_185:
		return (gettext("EC2N group on GP[2^185]"));
	case IKE_GRP_DESC_MODP_1536:
		return (gettext("1536-bit MODP (group 5)"));
	case IKE_GRP_DESC_MODP_2048:
		return (gettext("2048-bit MODP (group 14)"));
	case IKE_GRP_DESC_MODP_3072:
		return (gettext("3072-bit MODP (group 15)"));
	case IKE_GRP_DESC_MODP_4096:
		return (gettext("4096-bit MODP (group 16)"));
	case IKE_GRP_DESC_MODP_6144:
		return (gettext("6144-bit MODP (group 17)"));
	case IKE_GRP_DESC_MODP_8192:
		return (gettext("8192-bit MODP (group 18)"));
	case IKE_GRP_DESC_ECP_256:
		return (gettext("256-bit ECP (group 19)"));
	case IKE_GRP_DESC_ECP_384:
		return (gettext("384-bit ECP (group 20)"));
	case IKE_GRP_DESC_ECP_521:
		return (gettext("521-bit ECP (group 21)"));
	case IKE_GRP_DESC_MODP_1024_160:
		return (
		    gettext("1024-bit MODP with 160-bit subprime (group 22)"));
	case IKE_GRP_DESC_MODP_2048_224:
		return (
		    gettext("2048-bit MODP with 224-bit subprime (group 23)"));
	case IKE_GRP_DESC_MODP_2048_256:
		return (
		    gettext("2048-bit MODP with 256-bit subprime (group 24)"));
	case IKE_GRP_DESC_ECP_192:
		return (gettext("192-bit ECP (group 25)"));
	case IKE_GRP_DESC_ECP_224:
		return (gettext("224-bit ECP (group 26)"));
	default:
		(void) snprintf(rtn, MAXLINESIZE, gettext("<unknown %d>"), grp);
		return (rtn);
	}
}

static void
print_hdr(char *prefix, ike_p1_hdr_t *hdrp)
{
	char sbuf[TBUF_SIZE];
	char tbuf[TBUF_SIZE];
	time_t ltime = (time_t)hdrp->p1hdr_dpd_time;

	(void) printf(
	    gettext("%s Cookies: Initiator 0x%llx  Responder 0x%llx\n"),
	    prefix, ntohll(hdrp->p1hdr_cookies.cky_i),
	    ntohll(hdrp->p1hdr_cookies.cky_r));
	(void) printf(gettext("%s The local host is the %s.\n"), prefix,
	    hdrp->p1hdr_isinit ? gettext("initiator") : gettext("responder"));
	(void) printf(gettext("%s ISAKMP version %d.%d; %s exchange\n"), prefix,
	    hdrp->p1hdr_major, hdrp->p1hdr_minor, xchgstr(hdrp->p1hdr_xchg));
	(void) printf(gettext("%s Current state is %s\n"), prefix,
	    statestr(hdrp->p1hdr_state));
	if (hdrp->p1hdr_support_dpd == B_FALSE) {
		return;
	}
	(void) printf(gettext("%s Dead Peer Detection (RFC 3706)"
	    " enabled"), prefix);
	if (hdrp->p1hdr_dpd_state < DPD_IN_PROGRESS) {
		(void) printf("\n");
		return;
	}
	if (strftime(tbuf, TBUF_SIZE, NULL,
	    localtime(&ltime)) == 0) {
		(void) strlcpy(tbuf, gettext("<time conversion failed>"),
		    TBUF_SIZE);
	}
	(void) printf(gettext("\n%s Dead Peer Detection handshake "), prefix);
	switch (hdrp->p1hdr_dpd_state) {
	case DPD_SUCCESSFUL:
		(void) strlcpy(sbuf, gettext("was successful at "), TBUF_SIZE);
		break;
	case DPD_FAILURE:
		(void) strlcpy(sbuf, gettext("failed at "), TBUF_SIZE);
		break;
	case DPD_IN_PROGRESS:
		(void) strlcpy(sbuf, gettext("is in progress."), TBUF_SIZE);
		break;
	}
	(void) printf("%s %s", sbuf,
	    (hdrp->p1hdr_dpd_state == DPD_IN_PROGRESS) ? "" : tbuf);
	(void) printf("\n");
}

static void
print_lt_limits(char *prefix, ike_p1_xform_t *xfp)
{
	char byte_str[BYTE_STR_SIZE]; /* byte lifetime string representation */
	char secs_str[SECS_STR_SIZE]; /* lifetime string representation */

	(void) printf(gettext("%s Lifetime limits:\n"), prefix);
	(void) printf(gettext("%s %u seconds%s; %u kbytes %sprotected\n"),
	    prefix, xfp->p1xf_max_secs, secs2out(xfp->p1xf_max_secs,
	    secs_str, sizeof (secs_str), SPC_BEGIN), xfp->p1xf_max_kbytes,
	    bytecnt2out((uint64_t)xfp->p1xf_max_kbytes << 10, byte_str,
	    sizeof (byte_str), SPC_END));
	(void) printf(gettext("%s keying material for IPsec SAs can be "
	    "provided %u times%s\n"), prefix, xfp->p1xf_max_keyuses,
	    xfp->p1xf_max_keyuses == 0 ? " (no limit)" : "");
}

#define	LT_USAGE_LEN	16	/* 1 uint64 + 2 uint32s */
static void
print_lt_usage(char *prefix, ike_p1_stats_t *sp)
{
	time_t	scratch;
	char	tbuf[TBUF_SIZE];
	char	bytestr[BYTE_STR_SIZE]; /* byte lifetime representation */

	(void) printf(gettext("%s Current usage:\n"), prefix);
	scratch = (time_t)sp->p1stat_start;
	if (strftime(tbuf, TBUF_SIZE, NULL, localtime(&scratch)) == 0)
		(void) strlcpy(tbuf, gettext("<time conversion failed>"),
		    TBUF_SIZE);
	(void) printf(gettext("%s SA was created at %s\n"), prefix, tbuf);
	(void) printf(gettext("%s %u kbytes %sprotected\n"),
	    prefix, sp->p1stat_kbytes,
	    bytecnt2out((uint64_t)sp->p1stat_kbytes << 10, bytestr,
	    sizeof (bytestr), SPC_END));
	(void) printf(gettext("%s keying material for IPsec SAs provided "
	    "%u times\n"), prefix, sp->p1stat_keyuses);
}

static void
print_xform(char *prefix, ike_p1_xform_t *xfp, boolean_t print_lifetimes)
{
	(void) printf(gettext("%s Authentication method: %s"), prefix,
	    authmethstr(xfp->p1xf_auth_meth));
	(void) printf(gettext("\n%s Encryption alg: "), prefix);
	(void) dump_ealg(xfp->p1xf_encr_alg, stdout);
	if (xfp->p1xf_encr_low_bits != 0) {
		(void) printf(gettext("(%d..%d)"), xfp->p1xf_encr_low_bits,
		    xfp->p1xf_encr_high_bits);
	} else if ((xfp->p1xf_encr_low_bits == 0) &&
	    (xfp->p1xf_encr_high_bits != 0)) {
		/*
		 * High bits is a placeholder for
		 * negotiated algorithm strength
		 */
		(void) printf(gettext("(%d)"), xfp->p1xf_encr_high_bits);
	}
	(void) printf(gettext("; Authentication alg: "));
	(void) dump_aalg(xfp->p1xf_auth_alg, stdout);
	(void) printf("\n%s ", prefix);
	if (xfp->p1xf_prf != 0)
		(void) printf(gettext("PRF: %s ; "), prfstr(xfp->p1xf_prf));
	(void) printf(gettext("Oakley Group: %s\n"),
	    dhstr(xfp->p1xf_dh_group));
	if (xfp->p1xf_pfs == 0) {
		(void) printf(gettext("%s Phase 2 PFS is not used\n"), prefix);
	} else {
		(void) printf(gettext(
		    "%s Phase 2 PFS is required (Oakley Group: %s)\n"),
		    prefix, dhstr(xfp->p1xf_pfs));
	}

	if (print_lifetimes)
		print_lt_limits(prefix, xfp);
}

static void
print_lifetime(char *prefix, ike_p1_xform_t *xfp, ike_p1_stats_t *sp,
    int statlen)
{
	time_t	current, remain, exp;
	char	tbuf[TBUF_SIZE];
	char	byte_str[BYTE_STR_SIZE]; /* byte lifetime representation */
	char	secs_str[SECS_STR_SIZE]; /* seconds lifetime representation */

	current = time(NULL);

	print_lt_limits(prefix, xfp);

	/*
	 * make sure the stats struct we've been passed is as big
	 * as we expect it to be.  The usage stats are at the end,
	 * so anything less than the size we expect won't work.
	 */
	if (statlen >= sizeof (ike_p1_stats_t)) {
		print_lt_usage(prefix, sp);
	} else {
		return;
	}

	(void) printf(gettext("%s Expiration info:\n"), prefix);

	if (xfp->p1xf_max_kbytes != 0)
		(void) printf(gettext("%s %u more bytes %scan be "
		    "protected.\n"),
		    prefix, xfp->p1xf_max_kbytes - sp->p1stat_kbytes,
		    bytecnt2out((uint64_t)(xfp->p1xf_max_kbytes -
		    sp->p1stat_kbytes) << 10, byte_str, sizeof (byte_str),
		    SPC_END));

	if (xfp->p1xf_max_keyuses != 0)
		(void) printf(gettext("%s Keying material can be provided "
		    "%u more times.\n"), prefix,
		    xfp->p1xf_max_keyuses - sp->p1stat_keyuses);

	if (xfp->p1xf_max_secs != 0) {
		exp = (time_t)sp->p1stat_start + (time_t)xfp->p1xf_max_secs;
		remain = exp - current;
		if (strftime(tbuf, TBUF_SIZE, NULL, localtime(&exp)) == 0)
			(void) strlcpy(tbuf,
			    gettext("<time conversion failed>"), TBUF_SIZE);
		/*
		 * The SA may have expired but still exist because libike
		 * has not freed it yet.
		 */
		if (remain > 0) {
			(void) printf(gettext(
			    "%s SA expires in %lu seconds%s\n"),
			    prefix, remain, secs2out(remain, secs_str,
			    sizeof (secs_str), SPC_BEGIN));
			(void) printf(gettext("%s Time of expiration: %s\n"),
			    prefix, tbuf);
		} else {
			(void) printf(gettext("%s SA Expired at %s\n"),
			    prefix, tbuf);
		}
	}
}

/* used to verify structure lengths... */
#define	COUNTER_32BIT	4
#define	COUNTER_PAIR	8

static void
print_p1stats(char *prefix, ike_p1_stats_t *sp, int statlen,
    boolean_t print_lifetimes)
{
	if (statlen < COUNTER_PAIR)
		return;
	(void) printf(gettext("%s %u Quick Mode SAs created; "), prefix,
	    sp->p1stat_new_qm_sas);
	(void) printf(gettext("%u Quick Mode SAs deleted\n"),
	    sp->p1stat_del_qm_sas);
	statlen -= COUNTER_PAIR;

	if ((print_lifetimes) && (statlen >= LT_USAGE_LEN))
		print_lt_usage(prefix, sp);
}

static void
print_errs(char *prefix, ike_p1_errors_t *errp, int errlen)
{
	/*
	 * Don't try to break this one up; it's either all or nothing!
	 */
	if (errlen < sizeof (ike_p1_errors_t))
		return;

	(void) printf(gettext("%s %u RX errors: "), prefix,
	    errp->p1err_decrypt + errp->p1err_hash + errp->p1err_otherrx);
	(void) printf(gettext("%u decryption, %u hash, %u other\n"),
	    errp->p1err_decrypt, errp->p1err_hash, errp->p1err_otherrx);
	(void) printf(gettext("%s %u TX errors\n"), prefix, errp->p1err_tx);
}

static void
print_addr_range(char *prefix, ike_addr_pr_t *pr)
{
	boolean_t	range = B_TRUE;
	struct sockaddr_storage	*beg, *end;
	struct sockaddr_in	*bsin, *esin;
	struct sockaddr_in6	*bsin6, *esin6;

	beg = &pr->beg_iprange;
	end = &pr->end_iprange;

	if (beg->ss_family != end->ss_family) {
		(void) printf(gettext("%s invalid address range\n"), prefix);
		return;
	}

	switch (beg->ss_family) {
	case AF_INET:
		bsin = (struct sockaddr_in *)beg;
		esin = (struct sockaddr_in *)end;
		if ((uint32_t)bsin->sin_addr.s_addr ==
		    (uint32_t)esin->sin_addr.s_addr)
			range = B_FALSE;
		break;
	case AF_INET6:
		bsin6 = (struct sockaddr_in6 *)beg;
		esin6 = (struct sockaddr_in6 *)end;
		if (IN6_ARE_ADDR_EQUAL(&bsin6->sin6_addr, &esin6->sin6_addr))
			range = B_FALSE;
		break;
	default:
		(void) printf(gettext("%s invalid address range\n"), prefix);
		return;
	}

	(void) printf("%s ", prefix);
	(void) dump_sockaddr((struct sockaddr *)beg, 0, B_TRUE, stdout, nflag);
	if (range) {
		(void) printf(" - ");
		(void) dump_sockaddr((struct sockaddr *)end, 0, B_TRUE, stdout,
		    nflag);
	}
	(void) printf("\n");

}

/*
 * used to tell printing function if info should be identified
 * as belonging to initiator, responder, or neither
 */
#define	IS_INITIATOR	1
#define	IS_RESPONDER	2
#define	DONT_PRINT_INIT	3

static void
print_addr(char *prefix, struct sockaddr_storage *sa, int init_instr,
    int mask)
{
	(void) printf(gettext("%s Address"), prefix);

	if (init_instr != DONT_PRINT_INIT)
		(void) printf(" (%s):\n", (init_instr == IS_INITIATOR) ?
		    gettext("Initiator") : gettext("Responder"));
	else
		(void) printf(":\n");

	(void) printf("%s ", prefix);
	(void) dump_sockaddr((struct sockaddr *)sa, mask, B_FALSE, stdout,
	    nflag);
}

static void
print_id(char *prefix, sadb_ident_t *idp, int init_instr)
{
	boolean_t	canprint;

	switch (init_instr) {
	case IS_INITIATOR:
		(void) printf(gettext("%s Initiator identity, "), prefix);
		break;
	case IS_RESPONDER:
		(void) printf(gettext("%s Responder identity, "), prefix);
		break;
	case DONT_PRINT_INIT:
		(void) printf(gettext("%s Identity, "), prefix);
		break;
	default:
		(void) printf(gettext("<invalid identity>\n"));
		return;
	}
	(void) printf(gettext("uid=%d, type "), idp->sadb_ident_id);
	canprint = dump_sadb_idtype(idp->sadb_ident_type, stdout, NULL);
	if (canprint) {
		(void) printf("\n%s %s\n", prefix, (char *)(idp + 1));
	} else {
		(void) printf(gettext("\n%s "), prefix);
		print_asn1_name(stdout,
		    (const unsigned char *)(idp + 1),
		    SADB_64TO8(idp->sadb_ident_len) - sizeof (sadb_ident_t));
	}
}

static void
print_idspec(char *prefix, char *idp, int icnt, int ecnt)
{
	int	i;

	(void) printf(gettext("%s Identity descriptors:\n"), prefix);

	for (i = 0; i < icnt; i++) {
		if (i == 0)
			(void) printf(gettext("%s Includes:\n"), prefix);
		(void) printf("%s    %s\n", prefix, idp);
		idp += strlen(idp) + 1;
	}

	for (i = 0; i < ecnt; i++) {
		if (i == 0)
			(void) printf(gettext("%s Excludes:\n"), prefix);
		(void) printf("%s    %s\n", prefix, idp);
		idp += strlen(idp) + 1;
	}
}

static void
print_keys(char *prefix, ike_p1_key_t *keyp, int size)
{
	uint32_t	*curp;
	ike_p1_key_t	*p;
	int		ssize;

	curp = (uint32_t *)keyp;

	ssize = sizeof (ike_p1_key_t);

	while ((intptr_t)curp - (intptr_t)keyp < size) {
		size_t p1klen, len;

		p = (ike_p1_key_t *)curp;
		p1klen = p->p1key_len;
		len = p1klen - ssize;

		p1klen = roundup(p1klen, sizeof (ike_p1_key_t));
		if (p1klen < ssize) {
			(void) printf(gettext("Short key\n"));
			break;
		}

		switch (p->p1key_type) {
		case IKE_KEY_PRESHARED:
			(void) printf(gettext("%s Pre-shared key (%d bytes): "),
			    prefix, len);
			break;
		case IKE_KEY_SKEYID:
			(void) printf(gettext("%s SKEYID (%d bytes): "),
			    prefix, len);
			break;
		case IKE_KEY_SKEYID_D:
			(void) printf(gettext("%s SKEYID_d (%d bytes): "),
			    prefix, len);
			break;
		case IKE_KEY_SKEYID_A:
			(void) printf(gettext("%s SKEYID_a (%d bytes): "),
			    prefix, len);
			break;
		case IKE_KEY_SKEYID_E:
			(void) printf(gettext("%s SKEYID_e (%d bytes): "),
			    prefix, len);
			break;
		case IKE_KEY_ENCR:
			(void) printf(gettext("%s Encryption key (%d bytes): "),
			    prefix, len);
			break;
		case IKE_KEY_IV:
			(void) printf(
			    gettext("%s Initialization vector (%d bytes): "),
			    prefix, len);
			break;
		default:
			(void) printf(gettext("%s Unidentified key info %p %d"),
			    prefix, p, p1klen);
			goto badkey;
		}
		(void) dump_key((uint8_t *)(p + 1), SADB_8TO1(len), 0,
		    stdout, B_FALSE);
badkey:
		(void) printf("\n");
		assert(IS_P2ALIGNED(p1klen, 8));
		curp += (p1klen >> 2);
	}
}

static void
print_group_header(void)
{
	(void) printf(gettext("\nList of Diffie-Hellman groups for setting "
	    "up IKE SAs"));
	(void) printf(gettext("\nThe values match the IPsec attribute "
	    "assigned numbers published by IANA\n\n"));
	(void) printf("%-6s%-9s%-50s\n",
	    gettext("Value"), gettext("Strength"), gettext("Description"));
}

static void
print_group(ike_group_t *gp)
{
	(void) printf("%-6u%-9u%-50s\n",
	    gp->group_number, gp->group_bits, gp->group_label);
}

static void
print_encralg_header(void)
{
	(void) printf(gettext("\nList of encryption algorithms for IKE"));
	(void) printf(gettext("\nThe values match the IPsec attribute "
	    "assigned numbers published by IANA\n\n"));
	(void) printf("%-6s%-20s%-15s\n", gettext("Value"),
	    gettext("Name"), gettext("Keylen range"));
}

static void
print_encralg(ike_encralg_t *ep)
{
	char keylen_str[16];

	(void) strlcpy(keylen_str, "N/A", sizeof (keylen_str));
	if (ep->encr_keylen_min != 0 || ep->encr_keylen_max != 0)
		(void) snprintf(keylen_str, sizeof (keylen_str), "%d-%d",
		    ep->encr_keylen_min, ep->encr_keylen_max);
	(void) printf("%-6u%-20s%-15s\n",
	    ep->encr_value, ep->encr_name, keylen_str);
}

static void
print_authalg_header(void)
{
	(void) printf(gettext("\nList of authentication algorithms for IKE"));
	(void) printf(gettext("\nThe values match the IPsec attribute "
	    "assigned numbers published by IANA\n\n"));
	(void) printf("%-6s%-20s\n", gettext("Value"), gettext("Name"));
}

static void
print_authalg(ike_authalg_t *ap)
{
	(void) printf("%-6u%-20s\n",
	    ap->auth_value, ap->auth_name);
}

static void
print_p1(ike_p1_sa_t *p1)
{
	ike_p1_stats_t	*sp;
	ike_p1_errors_t	*ep;
	ike_p1_key_t	*kp;
	sadb_ident_t	*lidp, *ridp;
	int		lstat, rstat;

	(void) printf("\n");
	print_hdr("IKESA:", &p1->p1sa_hdr);
	print_xform("XFORM:", &p1->p1sa_xform, B_FALSE);

	if (p1->p1sa_hdr.p1hdr_isinit) {
		lstat = IS_INITIATOR;
		rstat = IS_RESPONDER;
	} else {
		lstat = IS_RESPONDER;
		rstat = IS_INITIATOR;
	}
	print_addr("LOCIP:", &p1->p1sa_ipaddrs.loc_addr, lstat, 0);
	print_addr("REMIP:", &p1->p1sa_ipaddrs.rem_addr, rstat, 0);

	/*
	 * the stat len might be 0; but still make the call
	 * to print_lifetime() to pick up the xform info
	 */
	sp = (ike_p1_stats_t *)((int)(p1) + p1->p1sa_stat_off);
	print_lifetime("LIFTM:", &p1->p1sa_xform, sp, p1->p1sa_stat_len);

	if (p1->p1sa_stat_len > 0) {
		print_p1stats("STATS:", sp, p1->p1sa_stat_len, B_FALSE);
	}

	if (p1->p1sa_error_len > 0) {
		ep = (ike_p1_errors_t *)((int)(p1) + p1->p1sa_error_off);
		print_errs("ERRS: ", ep, p1->p1sa_error_len);
	}

	if (p1->p1sa_localid_len > 0) {
		lidp = (sadb_ident_t *)((int)(p1) + p1->p1sa_localid_off);
		print_id("LOCID:", lidp, lstat);
	}

	if (p1->p1sa_remoteid_len > 0) {
		ridp = (sadb_ident_t *)((int)(p1) + p1->p1sa_remoteid_off);
		print_id("REMID:", ridp, rstat);
	}

	if (p1->p1sa_key_len > 0) {
		kp = (ike_p1_key_t *)((int)(p1) + p1->p1sa_key_off);
		print_keys("KEY:  ", kp, p1->p1sa_key_len);
	}
}

static void
print_certcache(ike_certcache_t *c)
{
	(void) printf("\n");

	(void) printf(gettext("CERTIFICATE CACHE ID: %d\n"), c->cache_id);
	(void) printf(gettext("\tSubject Name: <%s>\n"),
	    (c->subject != NULL) ? c->subject : gettext("Name unavailable"));
	(void) printf(gettext("\t Issuer Name: <%s>\n"),
	    (c->issuer != NULL) ? c->issuer : gettext("Name unavailable"));
	if ((int)c->certclass == -1)
		(void) printf(gettext("\t\t[trusted certificate]\n"));
	switch (c->linkage) {
	case CERT_OFF_WIRE:
		(void) printf(gettext("\t\t[Public certificate only]\n"));
		(void) printf(gettext(
		    "\t\t[Obtained via certificate payload]\n"));
		break;
	case CERT_NO_PRIVKEY:
		(void) printf(gettext("\t\t[Public certificate only]\n"));
		break;
	case CERT_PRIVKEY_LOCKED:
		(void) printf(gettext(
		    "\t\t[Private key linked but locked]\n"));
		break;
	case CERT_PRIVKEY_AVAIL:
		(void) printf(gettext("\t\t[Private key available]\n"));
		break;
	}
}

static void
print_ps(ike_ps_t *ps)
{
	sadb_ident_t	*lidp, *ridp;
	uint8_t		*keyp;

	(void) printf("\n");

	(void) printf(gettext("PSKEY: For %s exchanges\n"),
	    xchgstr(ps->ps_ike_mode));

	if (ps->ps_key_len > 0) {
		keyp = (uint8_t *)((int)(ps) + ps->ps_key_off);
		(void) printf(gettext("PSKEY: Pre-shared key (%d bytes): "),
		    ps->ps_key_len);
		(void) dump_key(keyp, ps->ps_key_bits, 0, stdout, B_FALSE);
		(void) printf("\n");
	}

	/*
	 * We get *either* and address or an ident, never both.  So if
	 * the ident is there, don't try printing an address.
	 */
	if (ps->ps_localid_len > 0) {
		lidp = (sadb_ident_t *)
		    ((int)(ps) + ps->ps_localid_off);
		print_id("LOCID:", lidp, DONT_PRINT_INIT);
	} else {
		print_addr("LOCIP:", &ps->ps_ipaddrs.loc_addr, DONT_PRINT_INIT,
		    ps->ps_localid_plen > 0 ? ps->ps_localid_plen : 0);
	}

	if (ps->ps_remoteid_len > 0) {
		ridp = (sadb_ident_t *)
		    ((int)(ps) + ps->ps_remoteid_off);
		print_id("REMID:", ridp, DONT_PRINT_INIT);
	} else {
		print_addr("REMIP:", &ps->ps_ipaddrs.rem_addr, DONT_PRINT_INIT,
		    ps->ps_remoteid_plen > 0 ? ps->ps_remoteid_plen : 0);
	}
}

#define	PREFIXLEN	16

static void
print_rule(ike_rule_t *rp)
{
	char		prefix[PREFIXLEN];
	int		i;
	ike_p1_xform_t	*xfp;
	ike_addr_pr_t	*lipp, *ripp;
	char		*lidp, *ridp;
	char byte_str[BYTE_STR_SIZE]; /* kbyte string representation */
	char secs_str[SECS_STR_SIZE]; /* seconds string representation */

	(void) printf("\n");
	(void) printf(gettext("GLOBL: Label '%s', key manager cookie %u\n"),
	    rp->rule_label, rp->rule_kmcookie);
	(void) printf(gettext("GLOBL: local_idtype="));
	(void) dump_sadb_idtype(rp->rule_local_idtype, stdout, NULL);
	(void) printf(gettext(", ike_mode=%s\n"), xchgstr(rp->rule_ike_mode));
	(void) printf(gettext(
	    "GLOBL: p1_nonce_len=%u, p2_nonce_len=%u, p2_pfs=%s (group %u)\n"),
	    rp->rule_p1_nonce_len, rp->rule_p2_nonce_len,
	    (rp->rule_p2_pfs) ? gettext("true") : gettext("false"),
	    rp->rule_p2_pfs);
	(void) printf(
	    gettext("GLOBL: p2_lifetime=%u seconds%s\n"),
	    rp->rule_p2_lifetime_secs, secs2out(rp->rule_p2_lifetime_secs,
	    secs_str, sizeof (secs_str), SPC_BEGIN));
	(void) printf(
	    gettext("GLOBL: p2_softlife=%u seconds%s\n"),
	    rp->rule_p2_softlife_secs, secs2out(rp->rule_p2_softlife_secs,
	    secs_str, sizeof (secs_str), SPC_BEGIN));
	(void) printf(
	    gettext("GLOBL: p2_idletime=%u seconds%s\n"),
	    rp->rule_p2_idletime_secs, secs2out(rp->rule_p2_idletime_secs,
	    secs_str, sizeof (secs_str), SPC_BEGIN));
	/*
	 * Perform explicit conversion before passing to bytecnt2out()
	 * to avoid integer overflow.
	 */
	(void) printf(
	    gettext("GLOBL: p2_lifetime_kb=%u kilobytes%s\n"),
	    rp->rule_p2_lifetime_kb,
	    bytecnt2out((uint64_t)(rp->rule_p2_lifetime_kb) << 10,
	    byte_str, sizeof (byte_str), SPC_BEGIN));
	(void) printf(
	    gettext("GLOBL: p2_softlife_kb=%u kilobytes%s\n"),
	    rp->rule_p2_softlife_kb,
	    bytecnt2out(((uint64_t)(rp->rule_p2_softlife_kb)) << 10,
	    byte_str, sizeof (byte_str), SPC_BEGIN));

	if (rp->rule_locip_cnt > 0) {
		(void) printf(gettext("LOCIP: IP address range(s):\n"));
		lipp = (ike_addr_pr_t *)((int)rp + rp->rule_locip_off);
		for (i = 0; i < rp->rule_locip_cnt; i++, lipp++) {
			print_addr_range("LOCIP:", lipp);
		}
	}

	if (rp->rule_remip_cnt > 0) {
		(void) printf(gettext("REMIP: IP address range(s):\n"));
		ripp = (ike_addr_pr_t *)((int)rp + rp->rule_remip_off);
		for (i = 0; i < rp->rule_remip_cnt; i++, ripp++) {
			print_addr_range("REMIP:", ripp);
		}
	}

	if (rp->rule_locid_inclcnt + rp->rule_locid_exclcnt > 0) {
		lidp = (char *)((int)rp + rp->rule_locid_off);
		print_idspec("LOCID:", lidp, rp->rule_locid_inclcnt,
		    rp->rule_locid_exclcnt);
	}

	if (rp->rule_remid_inclcnt + rp->rule_remid_exclcnt > 0) {
		ridp = (char *)((int)rp + rp->rule_remid_off);
		print_idspec("REMID:", ridp, rp->rule_remid_inclcnt,
		    rp->rule_remid_exclcnt);
	}

	if (rp->rule_xform_cnt > 0) {
		(void) printf(gettext("XFRMS: Available Transforms:\n"));
		xfp = (ike_p1_xform_t *)((int)rp +  rp->rule_xform_off);
		for (i = 0; i < rp->rule_xform_cnt; i++, xfp++) {
			(void) snprintf(prefix, PREFIXLEN, "XF %2u:", i);
			print_xform(prefix, xfp, B_TRUE);
		}
	}
}

#undef	PREFIXLEN

#define	PRSACNTS(init, resp) \
		(void) printf(gettext("initiator: %10u   responder: %10u\n"), \
		    (init), (resp))

static void
print_stats(ike_stats_t *sp, int len)
{
	/*
	 * before printing each line, make sure the structure we were
	 * given is big enough to include the fields needed.
	 */
	if (len < COUNTER_PAIR)
		return;
	(void) printf(gettext("Phase 1 SA counts:\n"));
	(void) printf(gettext("Current:   "));
	PRSACNTS(sp->st_init_p1_current, sp->st_resp_p1_current);
	len -= COUNTER_PAIR;

	if (len < COUNTER_PAIR)
		return;
	(void) printf(gettext("Total:     "));
	PRSACNTS(sp->st_init_p1_total, sp->st_resp_p1_total);
	len -= COUNTER_PAIR;

	if (len < COUNTER_PAIR)
		return;
	(void) printf(gettext("Attempted: "));
	PRSACNTS(sp->st_init_p1_attempts, sp->st_resp_p1_attempts);
	len -= COUNTER_PAIR;

	if (len < (COUNTER_PAIR + COUNTER_32BIT))
		return;
	(void) printf(gettext("Failed:    "));
	PRSACNTS(sp->st_init_p1_noresp + sp->st_init_p1_respfail,
	    sp->st_resp_p1_fail);
	(void) printf(
	    gettext("           initiator fails include %u time-out(s)\n"),
	    sp->st_init_p1_noresp);

	if (len < PATH_MAX)
		return;
	if (*(sp->st_pkcs11_libname) != '\0')
		(void) printf(gettext("PKCS#11 library linked in from %s\n"),
		    sp->st_pkcs11_libname);
}

/* Print one line of 'get defaults' output (i.e. single value). */
static void
print_defaults(char *label, char *description, char *unit,
    uint_t current, uint_t def)
{
	(void) printf("%-18s%-10s%11u %-10s%-26s\n", label,
	    (current != def) ? gettext("config") : gettext("default"),
	    current, unit, description);
}

/*
 * Print out defaults used by in.iked, the argument is a buffer containing
 * two ike_defaults_t's, the first contains the hard coded defaults, the second
 * contains the actual values used. If these differ, then the defaults have been
 * changed via a config file entry. Note that "-" indicates this default
 * is not tunable via ike.config(4) or is system wide tunable.
 */
static void
do_print_defaults(ike_defaults_t *dp)
{
	ike_defaults_t *ddp;
	ddp = (ike_defaults_t *)(dp + 1);

	(void) printf(gettext("\nGlobal defaults. Some values can be"
	    " over-ridden on a per rule basis.\n"));
	(void) printf(gettext("\nSystem defaults are time delayed.\n\n"));

	(void) printf("%-18s%-10s%-12s%-10s%-26s\n\n",
	    gettext("Token:"), gettext("Source:"), gettext("Value:"),
	    gettext("Unit:"), gettext("Description:"));

	/* iked tunables */
	print_defaults("p1_lifetime_secs", gettext("phase 1 lifetime"),
	    gettext("seconds"), ddp->rule_p1_lifetime_secs,
	    dp->rule_p1_lifetime_secs);

	print_defaults("-", gettext("minimum phase 1 lifetime"),
	    gettext("seconds"), ddp->rule_p1_minlife,
	    dp->rule_p1_minlife);

	print_defaults("p1_nonce_len", gettext("phase 1 nonce length"),
	    gettext("bytes"), ddp->rule_p1_nonce_len,
	    dp->rule_p1_nonce_len);

	print_defaults("p2_lifetime_secs", gettext("phase 2 lifetime"),
	    gettext("seconds"), ddp->rule_p2_lifetime_secs,
	    dp->rule_p2_lifetime_secs);

	print_defaults("p2_softlife_secs", gettext("phase 2 soft lifetime"),
	    gettext("seconds"), ddp->rule_p2_softlife_secs,
	    dp->rule_p2_softlife_secs);

	print_defaults("p2_idletime_secs", gettext("phase 2 idle time"),
	    gettext("seconds"), ddp->rule_p2_idletime_secs,
	    dp->rule_p2_idletime_secs);

	print_defaults("p2_lifetime_kb", gettext("phase 2 lifetime"),
	    gettext("kilobytes"), ddp->rule_p2_lifetime_kb,
	    dp->rule_p2_lifetime_kb);

	print_defaults("p2_softlife_kb", gettext("phase 2 soft lifetime"),
	    gettext("kilobytes"), ddp->rule_p2_softlife_kb,
	    dp->rule_p2_softlife_kb);

	/* system wide tunables */
	print_defaults("-", gettext("system phase 2 lifetime"),
	    gettext("seconds"), ddp->sys_p2_lifetime_secs,
	    dp->sys_p2_lifetime_secs);

	print_defaults("-", gettext("system phase 2 soft lifetime"),
	    gettext("seconds"), ddp->sys_p2_softlife_secs,
	    dp->sys_p2_softlife_secs);

	print_defaults("-", gettext("system phase 2 idle time"),
	    gettext("seconds"), ddp->sys_p2_idletime_secs,
	    dp->sys_p2_idletime_secs);

	print_defaults("-", gettext("system phase 2 lifetime"),
	    gettext("bytes"), ddp->sys_p2_lifetime_bytes,
	    dp->sys_p2_lifetime_bytes);

	print_defaults("-", gettext("system phase 2 soft lifetime"),
	    gettext("bytes"), ddp->sys_p2_softlife_bytes,
	    dp->sys_p2_softlife_bytes);

	/* minimum and maximum values */
	print_defaults("-", gettext("minimum phase 2 hard lifetime"),
	    gettext("seconds"), ddp->rule_p2_minlife_hard_secs,
	    dp->rule_p2_minlife_hard_secs);

	print_defaults("-", gettext("minimum phase 2 soft lifetime"),
	    gettext("seconds"), ddp->rule_p2_minlife_soft_secs,
	    dp->rule_p2_minlife_soft_secs);

	print_defaults("-", gettext("minimum phase 2 idle lifetime"),
	    gettext("seconds"), ddp->rule_p2_minlife_idle_secs,
	    dp->rule_p2_minlife_idle_secs);

	print_defaults("-", gettext("minimum phase 2 hard lifetime"),
	    gettext("kilobytes"), ddp->rule_p2_minlife_hard_kb,
	    dp->rule_p2_minlife_hard_kb);

	print_defaults("-", gettext("minimum phase 2 soft lifetime"),
	    gettext("kilobytes"), ddp->rule_p2_minlife_soft_kb,
	    dp->rule_p2_minlife_soft_kb);

	print_defaults("-", gettext("minimum phase 2 delta"),
	    gettext("seconds"), ddp->rule_p2_mindiff_secs,
	    dp->rule_p2_mindiff_secs);

	print_defaults("-", gettext("minimum phase 2 delta"),
	    gettext("kilobytes"), ddp->rule_p2_mindiff_kb,
	    dp->rule_p2_mindiff_kb);

	print_defaults("-", gettext("maximum phase 2 lifetime"),
	    gettext("seconds"), ddp->rule_p2_maxlife_secs,
	    dp->rule_p2_maxlife_secs);

	print_defaults("-", gettext("conversion factor"),
	    gettext("kbytes/s"), ddp->conversion_factor,
	    dp->conversion_factor);

	print_defaults("-", gettext("maximum phase 2 lifetime"),
	    gettext("kilobytes"), ddp->rule_p2_maxlife_kb,
	    dp->rule_p2_maxlife_kb);

	/* other values */
	print_defaults("p2_nonce_len", gettext("phase 2 nonce length"),
	    gettext("bytes"), ddp->rule_p2_nonce_len,
	    dp->rule_p2_nonce_len);

	print_defaults("p2_pfs", gettext("phase 2 PFS"),
	    " ", ddp->rule_p2_pfs, dp->rule_p2_pfs);

	print_defaults("max_certs", gettext("max certificates"),
	    " ", ddp->rule_max_certs, dp->rule_max_certs);

	print_defaults("-", gettext("IKE port number"),
	    " ", ddp->rule_ike_port, dp->rule_ike_port);

	print_defaults("-", gettext("NAT-T port number"),
	    " ", ddp->rule_natt_port, dp->rule_natt_port);
}

static void
print_categories(int level)
{
	int	mask;

	if (level == 0) {
		(void) printf(gettext("No debug categories enabled.\n"));
		return;
	}

	(void) printf(gettext("Debug categories enabled:"));
	for (mask = 1; mask <= D_HIGHBIT; mask <<= 1) {
		if (level & mask)
			(void) printf("\n\t%s", dbgstr(mask));
	}
	(void) printf("\n");
}

/*PRINTFLIKE2*/
static void
ikeadm_err_exit(ike_err_t *err, char *fmt, ...)
{
	va_list	ap;
	char	bailbuf[BUFSIZ];

	va_start(ap, fmt);
	(void) vsnprintf(bailbuf, BUFSIZ, fmt, ap);
	va_end(ap);
	if ((err != NULL) && (err->ike_err == IKE_ERR_SYS_ERR)) {
		bail_msg("%s: %s", bailbuf, (err->ike_err_unix == 0) ?
		    gettext("<unknown error>") : strerror(err->ike_err_unix));
	} else {
		bail_msg("%s: %s", bailbuf, (err == NULL) ?
		    gettext("<unknown error>") : errstr(err->ike_err));
	}
}

/*PRINTFLIKE2*/
static void
ikeadm_err_msg(ike_err_t *err, char *fmt, ...)
{
	va_list	ap;
	char	mbuf[BUFSIZ];

	va_start(ap, fmt);
	(void) vsnprintf(mbuf, BUFSIZ, fmt, ap);
	va_end(ap);
	if ((err != NULL) && (err->ike_err == IKE_ERR_SYS_ERR)) {
		message("%s: %s", mbuf, (err->ike_err_unix == 0) ?
		    gettext("<unknown error>") :
		    ((err->ike_err_unix == EEXIST) ?
		    gettext("Duplicate entry") :
		    strerror(err->ike_err_unix)));
	} else {
		message("%s: %s", mbuf, (err == NULL) ?
		    gettext("<unknown error>") : errstr(err->ike_err));
	}
}


/*
 * Command functions
 */

/*
 * Exploit the fact that ike_dbg_t and ike_priv_t have identical
 * formats in the following two functions.
 */
static void
do_getvar(int cmd)
{
	ike_service_t	req, *rtn;
	ike_dbg_t	*dreq;
	char		*varname;

	switch (cmd) {
	case IKE_SVC_GET_DBG:
		varname = gettext("debug");
		break;
	case IKE_SVC_GET_PRIV:
		varname = gettext("privilege");
		break;
	default:
		bail_msg(gettext("unrecognized get command (%d)"), cmd);
	}

	dreq = &req.svc_dbg;
	dreq->cmd = cmd;
	dreq->dbg_level = 0;

	rtn = ikedoor_call((char *)&req, sizeof (ike_dbg_t), NULL, 0);

	if ((rtn == NULL) || (rtn->svc_err.cmd == IKE_SVC_ERROR)) {
		ikeadm_err_exit(&rtn->svc_err,
		    gettext("error getting %s level"), varname);
	}
	dreq = &rtn->svc_dbg;
	(void) printf(gettext("Current %s level is 0x%x"),
	    varname, dreq->dbg_level);

	if (cmd == IKE_SVC_GET_DBG) {
		(void) printf("\n");
		print_categories(dreq->dbg_level);
	} else {
		(void) printf(gettext(", %s enabled\n"),
		    privstr(dreq->dbg_level));
	}
}

/*
 * Log into a token and unlock all objects
 * referenced by PKCS#11 hint files.
 */
static void
do_setdel_pin(int cmd, int argc, char **argv)
{
	ike_service_t	req, *rtn;
	ike_pin_t	*preq;
	char		token_label[PKCS11_TOKSIZE];
	char		*token_pin;
	char		prompt[80];

	if (argc < 1)
		Bail(gettext("Must specify PKCS#11 token object."));

	preq = &req.svc_pin;
	preq->cmd = cmd;

	switch (cmd) {
	case IKE_SVC_SET_PIN:
		if (parse_token(argc, argv, token_label) != 0)
			Bail("Invalid syntax for \"token login\"");
		(void) snprintf(prompt, sizeof (prompt),
		    "Enter PIN for PKCS#11 token \'%s\': ", token_label);
		token_pin =
		    getpassphrase(prompt);
		(void) strlcpy((char *)preq->token_pin, token_pin, MAX_PIN_LEN);
		bzero(token_pin, strlen(token_pin));
		break;
	case IKE_SVC_DEL_PIN:
		if (parse_token(argc, argv, token_label) != 0)
			Bail("Invalid syntax for \"token logout\"");
		break;
	default:
		bail_msg(gettext("unrecognized token command (%d)"), cmd);
	}

	(void) strlcpy(preq->pkcs11_token, token_label, PKCS11_TOKSIZE);

	rtn = ikedoor_call((char *)&req, sizeof (ike_pin_t), NULL, 0);
	if (cmd == IKE_SVC_SET_PIN)
		bzero(preq->token_pin, sizeof (preq->token_pin));

	if ((rtn == NULL) || (rtn->svc_err.cmd == IKE_SVC_ERROR)) {
		ikeadm_err_exit(&rtn->svc_err,
		    gettext("PKCS#11 operation"));
	}
	preq = &rtn->svc_pin;
	message(gettext("PKCS#11 operation successful"));
}

static void
do_setvar(int cmd, int argc, char **argv)
{
	ike_service_t	req, *rtn;
	ike_dbg_t	*dreq;
	door_desc_t	*descp = NULL, desc;
	int		fd, ndesc = 0;
	uint32_t	reqlevel;
	char		*varname;

	if (argc < 1)
		Bail("unspecified level");
	reqlevel = strtoul(argv[0], NULL, 0);

	switch (cmd) {
	case IKE_SVC_SET_DBG:
		if (argc > 2)
			Bail("Too many arguments to \"set debug\"");
		varname = gettext("debug");
		if (reqlevel == 0) {
			/* check for a string... */
			reqlevel = parsedbgopts(argv[0]);
		}
		if (reqlevel == D_INVALID)
			bail_msg(gettext("Bad debug flag: %s"), argv[0]);
		break;
	case IKE_SVC_SET_PRIV:
		if (argc > 1)
			Bail("Too many arguments to \"set priv\"");

		varname = gettext("privilege");
		if (reqlevel == 0) {
			/* check for a string... */
			reqlevel = privstr2num(argv[0]);
		}
		if (reqlevel > IKE_PRIV_MAXIMUM)
			bail_msg(gettext("Bad privilege flag: %s"), argv[0]);
		break;
	default:
		bail_msg(gettext("unrecognized set command (%d)"), cmd);
	}

	dreq = &req.svc_dbg;
	dreq->cmd = cmd;
	dreq->dbg_level = reqlevel;

	if ((argc == 2) && (cmd == IKE_SVC_SET_DBG)) {
		fd = open(argv[1], O_RDWR | O_CREAT | O_APPEND,
		    S_IRUSR | S_IWUSR);
		if (fd < 0)
			Bail("open debug file");
		desc.d_data.d_desc.d_descriptor = fd;
		desc.d_attributes = DOOR_DESCRIPTOR;
		descp = &desc;
		ndesc = 1;
	}

	rtn = ikedoor_call((char *)&req, sizeof (ike_dbg_t), descp, ndesc);

	if ((rtn == NULL) || (rtn->svc_err.cmd == IKE_SVC_ERROR)) {
		ikeadm_err_exit(&rtn->svc_err,
		    gettext("error setting %s level"), varname);
	}
	dreq = &rtn->svc_dbg;
	(void) printf(
	    gettext("Successfully changed %s level from 0x%x to 0x%x\n"),
	    varname, dreq->dbg_level, reqlevel);

	if (cmd == IKE_SVC_SET_DBG) {
		print_categories(reqlevel);
	} else {
		(void) printf(gettext("New privilege level 0x%x enables %s\n"),
		    reqlevel, privstr(reqlevel));
	}
}

static void
do_getstats(int cmd)
{
	ike_service_t	*rtn;
	ike_statreq_t	sreq, *sreqp;
	ike_stats_t	*sp;

	sreq.cmd = cmd;

	rtn = ikedoor_call((char *)&sreq, sizeof (ike_statreq_t), NULL, 0);
	if ((rtn == NULL) || (rtn->svc_err.cmd == IKE_SVC_ERROR)) {
		ikeadm_err_exit(&rtn->svc_err, gettext("error getting stats"));
	}

	sreqp = &rtn->svc_stats;
	sp = (ike_stats_t *)(sreqp + 1);
	print_stats(sp, sreqp->stat_len);
}

static void
do_getdefs(int cmd)
{
	ike_service_t	*rtn;
	ike_defreq_t	dreq, *dreqp;
	ike_defaults_t	*dp;

	dreq.cmd = cmd;

	rtn = ikedoor_call((char *)&dreq, sizeof (ike_defreq_t), NULL, 0);
	if ((rtn == NULL) || (rtn->svc_err.cmd == IKE_SVC_ERROR)) {
		ikeadm_err_exit(&rtn->svc_err,
		    gettext("error getting defaults"));
	}

	dreqp = &rtn->svc_defaults;
	dp = (ike_defaults_t *)(dreqp + 1);

	/*
	 * Before printing each line, make sure the structure we were
	 * given is big enough to include the fields needed.
	 * Silently bail out of there is a version mismatch.
	 */
	if (dreqp->stat_len < ((2 * sizeof (ike_defaults_t))
	    + sizeof (ike_defreq_t)) || dreqp->version != DOORVER) {
		return;
	}
	do_print_defaults(dp);
}

static void
do_dump(int cmd)
{
	char		*name;
	ike_service_t	req, *rtn;
	ike_dump_t	*dreq, *dump;

	switch (cmd) {
	case IKE_SVC_DUMP_P1S:
		name = gettext("phase 1 SA info");
		break;
	case IKE_SVC_DUMP_RULES:
		name = gettext("policy rules");
		break;
	case IKE_SVC_DUMP_PS:
		name = gettext("preshared keys");
		break;
	case IKE_SVC_DUMP_CERTCACHE:
		name = gettext("certcache");
		break;
	case IKE_SVC_DUMP_GROUPS:
		name = gettext("groups");
		print_group_header();
		break;
	case IKE_SVC_DUMP_ENCRALGS:
		name = gettext("encralgs");
		print_encralg_header();
		break;
	case IKE_SVC_DUMP_AUTHALGS:
		name = gettext("authalgs");
		print_authalg_header();
		break;
	default:
		bail_msg(gettext("unrecognized dump command (%d)"), cmd);
	}

	dreq = &req.svc_dump;
	dreq->cmd = cmd;
	dreq->dump_len = 0;
	dreq->dump_next = 0;
	do {
		rtn = ikedoor_call((char *)&req, sizeof (ike_dump_t),
		    NULL, 0);
		if ((rtn == NULL) || (rtn->svc_err.cmd == IKE_SVC_ERROR)) {
			if (rtn && (rtn->svc_err.ike_err == IKE_ERR_NO_OBJ)) {
				/* no entries to print */
				break;
			}
			ikeadm_err_exit(&rtn->svc_err,
			    gettext("error getting %s"), name);
		}
		dump = &rtn->svc_dump;

		switch (cmd) {
		case IKE_SVC_DUMP_P1S:
			print_p1((ike_p1_sa_t *)(dump + 1));
			break;
		case IKE_SVC_DUMP_RULES:
			print_rule((ike_rule_t *)(dump + 1));
			break;
		case IKE_SVC_DUMP_PS:
			print_ps((ike_ps_t *)(dump + 1));
			break;
		case IKE_SVC_DUMP_CERTCACHE:
			print_certcache((ike_certcache_t *)(dump + 1));
			break;
		case IKE_SVC_DUMP_GROUPS:
			print_group((ike_group_t *)(dump + 1));
			break;
		case IKE_SVC_DUMP_ENCRALGS:
			print_encralg((ike_encralg_t *)(dump + 1));
			break;
		case IKE_SVC_DUMP_AUTHALGS:
			print_authalg((ike_authalg_t *)(dump + 1));
			break;
		}

		dreq->dump_next = dump->dump_next;

		(void) munmap((char *)rtn, dump->dump_len);

	} while (dreq->dump_next);

	(void) printf(gettext("\nCompleted dump of %s\n"), name);
}

static void
do_getdel_doorcall(int cmd, int idlen, int idtype, char *idp, char *name)
{
	int		totallen;
	char		*p;
	ike_service_t	*reqp, *rtnp;
	ike_get_t	*getp;
	boolean_t	getcmd;

	getcmd = ((cmd == IKE_SVC_GET_P1) || (cmd == IKE_SVC_GET_RULE) ||
	    (cmd == IKE_SVC_GET_PS));

	/*
	 * WARNING: to avoid being redundant, this code takes advantage
	 * of the fact that the ike_get_t and ike_del_t structures are
	 * identical (only the field names differ, their function and
	 * size are the same).  If for some reason those structures
	 * change, this code will need to be re-written to accomodate
	 * that difference.
	 */
	totallen = sizeof (ike_get_t) + idlen;
	if ((reqp = (ike_service_t *)malloc(totallen)) == NULL)
		Bail("malloc(id)");

	getp = &reqp->svc_get;
	getp->cmd = cmd;
	getp->get_len = totallen;
	getp->get_idtype = idtype;
	p = (char *)(getp + 1);

	(void) memcpy(p, idp, idlen);

	rtnp = ikedoor_call((char *)reqp, totallen, NULL, 0);
	if ((rtnp == NULL) || (rtnp->svc_err.cmd == IKE_SVC_ERROR)) {
		if (rtnp && (rtnp->svc_err.ike_err == IKE_ERR_NO_OBJ)) {
			message(gettext("Could not find requested %s."), name);
		} else {
			ikeadm_err_msg(&rtnp->svc_err, gettext("error %s %s"),
			    (getcmd) ? gettext("getting") : gettext("deleting"),
			    name);
		}
		free(reqp);
		return;
	}
	getp = &rtnp->svc_get;

	if (getcmd) {
		switch (cmd) {
		case IKE_SVC_GET_P1:
			print_p1((ike_p1_sa_t *)(getp + 1));
			break;
		case IKE_SVC_GET_PS:
			print_ps((ike_ps_t *)(getp + 1));
			break;
		case IKE_SVC_GET_RULE:
			print_rule((ike_rule_t *)(getp + 1));
			break;
		}
	} else {
		message(gettext("Successfully deleted selected %s."), name);
	}

	(void) munmap((char *)rtnp, getp->get_len);
	free(reqp);
}

static void
do_getdel(int cmd, int argc, char **argv)
{
	int		idlen, idtype = 0, i, j;
	int		bytelen1, bytelen2;
	char		*name, *idp, *p, *p1, *p2;
	ike_addr_pr_t	apr;
	ike_cky_pr_t	cpr;
	sadb_ident_t	*sid1p, *sid2p;
	struct hostent	*he1p, *he2p;
	char		label[MAX_LABEL_LEN];

	if ((argc < 1) || (argv[0] == NULL)) {
		Bail("not enough identification info");
	}

	switch (cmd) {
	case IKE_SVC_GET_P1:
	case IKE_SVC_DEL_P1:
		name = gettext("phase 1 SA");
		/*
		 * The first token must either be an address (or hostname)
		 * or a cookie.  We require cookies to be entered as hex
		 * numbers, beginning with 0x; so if our token starts with
		 * that, it's a cookie.
		 */
		if (strncmp(argv[0], "0x", 2) == 0) {
			if (parse_cky_pr(argc, argv, &cpr) >= 0) {
				idtype = IKE_ID_CKY_PAIR;
				idlen = sizeof (ike_cky_pr_t);
				idp = (char *)&cpr;
			}
		} else {
			if (parse_addr_pr(argc, argv, &he1p, &he2p) >= 0) {
				idtype = IKE_ID_ADDR_PAIR;
				idlen = sizeof (ike_addr_pr_t);
			}
		}
		break;

	case IKE_SVC_GET_RULE:
	case IKE_SVC_DEL_RULE:
		name = gettext("policy rule");
		if (parse_label(argc, argv, label) >= 0) {
			idtype = IKE_ID_LABEL;
			idlen = MAX_LABEL_LEN;
			idp = label;
		}
		break;

	case IKE_SVC_GET_PS:
	case IKE_SVC_DEL_PS:
		name = gettext("preshared key");
		/*
		 * The first token must either be an address or an ident
		 * type.  Check for an ident type to determine which it is.
		 */
		if (parse_idtype(argv[0], NULL) >= 0) {
			if (parse_ident_pr(argc, argv, &sid1p, &sid2p) >= 0) {
				idtype = IKE_ID_IDENT_PAIR;
				idlen = SADB_64TO8(sid1p->sadb_ident_len) +
				    SADB_64TO8(sid2p->sadb_ident_len);
			}
		} else {
			if (parse_addr_pr(argc, argv, &he1p, &he2p) >= 0) {
				idtype = IKE_ID_ADDR_PAIR;
				idlen = sizeof (ike_addr_pr_t);
			}
		}
		break;

	default:
		bail_msg(gettext("unrecognized get/del command (%d)"), cmd);
	}

	switch (idtype) {
	case IKE_ID_ADDR_PAIR:
		/*
		 * we might have exploding addrs here; do every possible
		 * combination.
		 */
		i = 0;
		j = 0;
		while ((p1 = he1p->h_addr_list[i++]) != NULL) {
			headdr2sa(p1, &apr.loc_addr, he1p->h_length);

			while ((p2 = he2p->h_addr_list[j++]) != NULL) {
				headdr2sa(p2, &apr.rem_addr, he2p->h_length);
				do_getdel_doorcall(cmd, idlen, idtype,
				    (char *)&apr, name);
			}
		}
		FREE_HE(he1p);
		FREE_HE(he2p);
		break;

	case IKE_ID_IDENT_PAIR:
		bytelen1 = SADB_64TO8(sid1p->sadb_ident_len);
		bytelen2 = SADB_64TO8(sid2p->sadb_ident_len);
		if (idlen != bytelen1 + bytelen2)
			Bail("ident syntax error");
		idp = p = (char *)malloc(idlen);
		if (p == NULL)
			Bail("malloc(id)");
		(void) memcpy(p, (char *)sid1p, bytelen1);
		p += bytelen1;
		(void) memcpy(p, (char *)sid2p, bytelen2);
		do_getdel_doorcall(cmd, idlen, idtype, idp, name);
		free(idp);
		free(sid1p);
		free(sid2p);
		break;

	case IKE_ID_CKY_PAIR:
	case IKE_ID_LABEL:
		do_getdel_doorcall(cmd, idlen, idtype, idp, name);
		break;

	case 0:
	default:
		bail_msg(gettext("invalid %s identification\n"), name);
	}
}

/*
 * Copy source into target, inserting an escape character ('\') before
 * any quotes that appear.  Return true on success, false on failure.
 */
static boolean_t
escapequotes(char *target, char *source, int tlen)
{
	int	s, t, len = strlen(source) + 1;

	if (tlen < len)
		return (B_FALSE);

	for (s = 0, t = 0; s < len && t < tlen; s++) {
		if (source[s] == '\"')
			target[t++] = '\\';
		target[t++] = source[s];
	}

	if ((t == tlen) && (s < len))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Return true if the arg following the given keyword should
 * be in quotes (i.e. is a string), false if not.
 */
static boolean_t
quotedfield(char *keywd)
{
	if ((strncmp(keywd, "label", strlen("label") + 1) == 0) ||
	    (strncmp(keywd, "local_id", strlen("local_id") + 1) == 0) ||
	    (strncmp(keywd, "remote_id", strlen("remote_id") + 1) == 0))
		return (B_TRUE);

	return (B_FALSE);
}

static void
do_new(int cmd, int argc, char **argv)
{
	ike_service_t	*rtn;
	ike_new_t	new, *newp = NULL;
	door_desc_t	desc, *descp = NULL;
	int		i, fd, ndesc = 0, buflen;
	char		*name, tmpfilepath[32];
	FILE		*tmpfile;

	switch (cmd) {
	case IKE_SVC_NEW_PS:
		name = gettext("preshared key");
		break;
	case IKE_SVC_NEW_RULE:
		name = gettext("policy rule");
		break;
	default:
		bail_msg(gettext("unrecognized new command (%d)"), cmd);
	}

	if (argc == 1) {
		/* We've been given a file to read from */
		fd = open(argv[0], O_RDONLY);
		if (fd < 0)
			Bail("open source file");

		desc.d_data.d_desc.d_descriptor = fd;
		desc.d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
		descp = &desc;
		ndesc = 1;

		new.cmd = cmd;
		new.new_len = 0;
		newp = &new;
		buflen = sizeof (ike_new_t);

	} else if ((argc > 1) && (cmd == IKE_SVC_NEW_PS)) {
		/*
		 * This is an alternative to using the tmpfile method
		 * for preshared keys.  It means we're duplicating the
		 * parsing effort that happens in readps.c; but it
		 * does avoid having the key sitting in a file.
		 */
		ike_ps_t	*psp;
		int		pslen;

		/*
		 * must be in interactive mode; don't want keys in
		 * the process args.
		 */
		if (!interactive)
			Bail("Must be in interactive mode to add key info.");
		if (parse_ps(argc, argv, &psp, &pslen) < 0) {
			errno = 0;
			Bail("invalid preshared key definition");
		}
		newp = malloc(sizeof (ike_new_t) + pslen);
		if (newp == NULL)
			Bail("alloc pskey");
		newp->cmd = cmd;
		newp->new_len = sizeof (ike_new_t) + pslen;
		(void) memcpy((char *)(newp + 1), psp, pslen);
		buflen = newp->new_len;
		/* parse_ps allocated the ike_ps_t buffer; free it now */
		free(psp);

	} else if ((argc > 1) && (cmd == IKE_SVC_NEW_RULE)) {
		/*
		 * We've been given the item in argv.  However, parsing
		 * rules can get more than a little messy, and in.iked
		 * already has a great parser for this stuff!  So don't
		 * fool around with trying to do the parsing here. Just
		 * write it out to a tempfile, and send the fd to in.iked.
		 *
		 * We could conceivably do this for preshared keys,
		 * rather than duplicating the parsing effort; but that
		 * would mean the key would be written out to a file,
		 * which isn't such a good idea.
		 */
		boolean_t	doquotes = B_FALSE;
		int		rtn;

		if ((argv[0][0] != '{') ||
		    (argv[argc - 1][strlen(argv[argc - 1]) - 1] != '}'))
			bail_msg(gettext("improperly formatted %s"), name);

		/* attempt to use a fairly unpredictable file name... */
		(void) sprintf(tmpfilepath, "/var/run/%x", (int)gethrtime());
		fd = open(tmpfilepath, O_RDWR | O_CREAT | O_EXCL,
		    S_IRUSR | S_IWUSR);
		if (fd < 0)
			Bail("cannot open tmpfile");

		/* and make it inaccessible asap */
		if (unlink(tmpfilepath) < 0) {
			(void) close(fd);
			Bail("tmpfile error");
		}

		tmpfile = fdopen(fd, "w");
		if (tmpfile == NULL) {
			(void) close(fd);
			Bail("cannot write to tmpfile");
		}

		for (i = 0; i < argc; i++) {
			/*
			 * We have to do some gyrations with our string here,
			 * to properly handle quotes.  There are two issues:
			 * - some of the fields of a rule may have embedded
			 *   whitespace, and thus must be quoted on the cmd
			 *   line.  The shell removes the quotes, and gives
			 *   us a single argv string; but we need to put the
			 *   quotes back in when we write the string out to
			 *   file.  The doquotes boolean is set when we
			 *   process a keyword which will be followed by a
			 *   string value (so the NEXT argv element will be
			 *   quoted).
			 * - there might be a quote character in a field,
			 *   that was escaped on the cmdline.  The shell
			 *   removes the escape char, and leaves the quote
			 *   in the string it gives us.  We need to put the
			 *   escape char back in before writing to file.
			 */
			char	field[MAXLINESIZE];
			if (!escapequotes(field, argv[i], MAXLINESIZE))
				Bail("write to tmpfile failed (arg too big)");
			if (doquotes) {
				rtn = fprintf(tmpfile, "\"%s\"\n", field);
				doquotes = B_FALSE;
			} else {
				rtn = fprintf(tmpfile, "%s\n", field);
			}
			if (rtn < 0)
				Bail("write to tmpfile failed");
			/*
			 * check if this is a keyword identifying
			 * a field that needs to be quoted.
			 */
			doquotes = quotedfield(argv[i]);
		}
		if (fflush(tmpfile) == EOF)
			Bail("write to tmpfile failed");
		/* rewind so that the daemon will get the beginning */
		rewind(tmpfile);

		desc.d_data.d_desc.d_descriptor = fd;
		desc.d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
		descp = &desc;
		ndesc = 1;

		new.cmd = cmd;
		new.new_len = 0;
		newp = &new;
		buflen = sizeof (ike_new_t);

	} else {
		/* not enough information! */
		bail_msg(gettext("missing %s description or file name"), name);
	}

	rtn = ikedoor_call((char *)newp, buflen, descp, ndesc);

	if ((rtn == NULL) || (rtn->svc_err.cmd == IKE_SVC_ERROR)) {
		ikeadm_err_msg(&rtn->svc_err,
		    gettext("error creating new %s"), name);
	} else {
		message(gettext("Successfully created new %s."), name);
	}
}

static void
do_flush(int cmd)
{
	ike_service_t	*rtnp;
	ike_flush_t	flush;

	if (cmd != IKE_SVC_FLUSH_P1S && cmd != IKE_SVC_FLUSH_CERTCACHE) {
		bail_msg(gettext("unrecognized flush command (%d)."), cmd);
	}

	flush.cmd = cmd;

	rtnp = ikedoor_call((char *)&flush, sizeof (ike_flush_t), NULL, 0);
	if ((rtnp == NULL) || (rtnp->svc_err.cmd == IKE_SVC_ERROR)) {
		ikeadm_err_exit(&rtnp->svc_err, gettext("error doing flush"));
	}
	if (cmd == IKE_SVC_FLUSH_P1S)
		message(gettext("Successfully flushed P1 SAs."));
	else
		message(gettext("Successfully flushed cert cache."));
}

static void
do_rw(int cmd, int argc, char **argv)
{
	ike_service_t	*rtnp;
	ike_rw_t	rw;
	door_desc_t	desc, *descp = NULL;
	int		oflag, omode, fd, ndesc = 0;
	char		*op, *obj = NULL;
	boolean_t	writing = B_FALSE;

	switch (cmd) {
	case IKE_SVC_READ_PS:
		obj = gettext("preshared key");
		/* FALLTHRU */
	case IKE_SVC_READ_RULES:
		if (obj == NULL)
			obj = gettext("policy rule");
		op = gettext("read");
		oflag = O_RDONLY;
		omode = 0;
		break;

	case IKE_SVC_WRITE_PS:
		obj = gettext("preshared key");
		/* FALLTHRU */
	case IKE_SVC_WRITE_RULES:
		if (obj == NULL)
			obj = gettext("policy rule");
		op = gettext("write");
		oflag = O_RDWR | O_CREAT | O_EXCL;
		omode = S_IRUSR | S_IWUSR;

		/* for write commands, dest location must be specified */
		if (argc < 1) {
			bail_msg(gettext("destination location required "
			    "to write %ss"), obj);
		}
		writing = B_TRUE;
		break;

	default:
		bail_msg(gettext("unrecognized read/write command (%d)."), cmd);
	}

	rw.cmd = cmd;

	if (argc >= 1) {
		rw.rw_loc = IKE_RW_LOC_USER_SPEC;
		fd = open(argv[0], oflag, omode);
		if (fd < 0)
			Bail("open user-specified file");

		desc.d_data.d_desc.d_descriptor = fd;
		desc.d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
		descp = &desc;
		ndesc = 1;
	} else {
		rw.rw_loc = IKE_RW_LOC_DEFAULT;
	}

	rtnp = ikedoor_call((char *)&rw, sizeof (ike_rw_t), descp, ndesc);
	if ((rtnp == NULL) || (rtnp->svc_err.cmd == IKE_SVC_ERROR)) {
		/*
		 * Need to remove the target file in the
		 * case of a failed write command.
		 */
		if (writing) {
			/*
			 * argv[0] must be valid if we're writing; we
			 * exit before setting this boolean if not.
			 */
			(void) unlink(argv[0]);
			(void) close(fd);

			if ((rtnp != NULL) &&
			    (rtnp->svc_err.ike_err == IKE_ERR_NO_OBJ)) {
				message(gettext("No %s information to write."),
				    obj);
				return;
			}
		}
		ikeadm_err_exit(&rtnp->svc_err, gettext("error doing %s"), op);
	}
	message(gettext("Completed %s of %s configuration information."),
	    op, obj);
}

static void
do_rbdump()
{
	ike_cmd_t	req;
	ike_service_t	*rtnp;

	req.cmd = IKE_SVC_DBG_RBDUMP;

	rtnp = ikedoor_call((char *)&req, sizeof (ike_cmd_t), NULL, 0);
	if ((rtnp == NULL) || (rtnp->svc_err.cmd == IKE_SVC_ERROR)) {
		ikeadm_err_exit(&rtnp->svc_err, gettext("error doing flush"));
	}
	message(gettext("Successfully dumped rulebase; check iked dbg"));
}

#define	REQ_ARG_CNT	1

/*ARGSUSED*/
static void
parseit(int argc, char **argv, char *notused, boolean_t notused_either)
{
	int	cmd, cmd_obj_args = 1;
	char	*cmdstr, *objstr;

	if (interactive) {
		if (argc == 0)
			return;
	}

	if (argc < REQ_ARG_CNT) {
		usage();
	}

	cmdstr = argv[0];
	if (argc > REQ_ARG_CNT) {
		cmd_obj_args++;
		objstr = argv[1];
	} else {
		objstr = NULL;
	}
	cmd = parsecmd(cmdstr, objstr);

	/* skip over args specifying command/object */
	argc -= cmd_obj_args;
	argv += cmd_obj_args;

	switch (cmd) {
	case IKE_SVC_GET_DEFS:
		if (argc != 0) {
			print_get_help();
			break;
		}
		do_getdefs(cmd);
		break;
	case IKE_SVC_GET_DBG:
	case IKE_SVC_GET_PRIV:
		if (argc != 0) {
			print_get_help();
			break;
		}
		do_getvar(cmd);
		break;
	case IKE_SVC_GET_STATS:
		if (argc != 0) {
			print_get_help();
			break;
		}
		do_getstats(cmd);
		break;
	case IKE_SVC_SET_DBG:
	case IKE_SVC_SET_PRIV:
		do_setvar(cmd, argc, argv);
		break;
	case IKE_SVC_SET_PIN:
	case IKE_SVC_DEL_PIN:
		do_setdel_pin(cmd, argc, argv);
		break;
	case IKE_SVC_DUMP_P1S:
	case IKE_SVC_DUMP_RULES:
	case IKE_SVC_DUMP_GROUPS:
	case IKE_SVC_DUMP_ENCRALGS:
	case IKE_SVC_DUMP_AUTHALGS:
	case IKE_SVC_DUMP_PS:
	case IKE_SVC_DUMP_CERTCACHE:
		if (argc != NULL) {
			print_dump_help();
			break;
		}
		do_dump(cmd);
		break;
	case IKE_SVC_GET_P1:
	case IKE_SVC_GET_RULE:
	case IKE_SVC_GET_PS:
	case IKE_SVC_DEL_P1:
	case IKE_SVC_DEL_RULE:
	case IKE_SVC_DEL_PS:
		do_getdel(cmd, argc, argv);
		break;
	case IKE_SVC_NEW_RULE:
	case IKE_SVC_NEW_PS:
		do_new(cmd, argc, argv);
		break;
	case IKE_SVC_FLUSH_P1S:
	case IKE_SVC_FLUSH_CERTCACHE:
		if (argc != 0) {
			print_flush_help();
			break;
		}
		do_flush(cmd);
		break;
	case IKE_SVC_READ_RULES:
	case IKE_SVC_READ_PS:
	case IKE_SVC_WRITE_RULES:
	case IKE_SVC_WRITE_PS:
		do_rw(cmd, argc, argv);
		break;
	case IKEADM_HELP_GENERAL:
		print_help();
		break;
	case IKEADM_HELP_GET:
		print_get_help();
		break;
	case IKEADM_HELP_SET:
		print_set_help();
		break;
	case IKEADM_HELP_ADD:
		print_add_help();
		break;
	case IKEADM_HELP_DEL:
		print_del_help();
		break;
	case IKEADM_HELP_DUMP:
		print_dump_help();
		break;
	case IKEADM_HELP_FLUSH:
		print_flush_help();
		break;
	case IKEADM_HELP_READ:
		print_read_help();
		break;
	case IKEADM_HELP_WRITE:
		print_write_help();
		break;
	case IKEADM_HELP_TOKEN:
		print_token_help();
		break;
	case IKEADM_HELP_HELP:
		print_help_help();
		break;
	case IKEADM_EXIT:
		if (interactive)
			exit(0);
		break;
	case IKE_SVC_DBG_RBDUMP:
		do_rbdump();
		break;
	case IKE_SVC_ERROR:
		usage();
	default:
		exit(0);
	}
}

int
main(int argc, char **argv)
{
	char	ch;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((ch = getopt(argc, argv, "hpn")) != EOF) {
		switch (ch) {
		case 'h':
			print_help();
			return (0);
		case 'p':
			pflag = B_TRUE;
			break;
		case 'n':
			nflag = B_TRUE;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (open_door() < 0) {
		(void) fprintf(stderr,
		    gettext("Unable to communicate with in.iked\n"));
		Bail("open_door failed");
	}

	if (*argv == NULL) {
		/* no cmd-line args, do interactive mode */
		do_interactive(stdin, NULL, "ikeadm> ", NULL, parseit,
		    no_match);
	}

	parseit(argc, argv, NULL, B_FALSE);

	return (0);
}
