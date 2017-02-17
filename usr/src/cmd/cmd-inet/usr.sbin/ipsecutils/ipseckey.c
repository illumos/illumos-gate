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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * NOTE:I'm trying to use "struct sadb_foo" instead of "sadb_foo_t"
 *	as a maximal PF_KEY portability test.
 *
 *	Also, this is a deliberately single-threaded app, also for portability
 *	to systems without POSIX threads.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/fcntl.h>
#include <net/pfkeyv2.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/uio.h>

#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <netdb.h>
#include <pwd.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <fcntl.h>
#include <strings.h>
#include <ctype.h>
#include <sys/cladm.h>

#include <ipsec_util.h>

static int keysock;
static int cluster_socket;
static uint32_t seq;
static pid_t mypid;
static boolean_t vflag = B_FALSE;	/* Verbose? */
static boolean_t cflag = B_FALSE;	/* Check Only */

char *my_fmri = NULL;
FILE *debugfile = stdout;
static struct sockaddr_in cli_addr;
static boolean_t in_cluster_mode = B_FALSE;

#define	MAX_GET_SIZE	1024
/*
 * WARN() and ERROR() do the same thing really, with ERROR() the function
 * that prints the error buffer needs to be called at the end of a code block
 * This will print out all accumulated errors before bailing. The WARN()
 * macro calls handle_errors() in such a way that it prints the message
 * then continues.
 * If the FATAL() macro used call handle_errors() immediately.
 */
#define	ERROR(x, y, z)  x = record_error(x, y, z)
#define	ERROR1(w, x, y, z)  w = record_error(w, x, y, z)
#define	ERROR2(v, w, x, y, z)  v = record_error(v, w, x, y, z)
#define	WARN(x, y, z) ERROR(x, y, z);\
	handle_errors(x, NULL, B_FALSE, B_FALSE); x = NULL
#define	WARN1(w, x, y, z) ERROR1(w, x, y, z);\
	handle_errors(w, NULL, B_FALSE, B_FALSE); w = NULL
#define	WARN2(v, w, x, y, z) ERROR2(v, w, x, y, z);\
	handle_errors(v, NULL, B_FALSE, B_FALSE); v = NULL
#define	FATAL(x, y, z) ERROR(x, y, z);\
	handle_errors(x, y, B_TRUE, B_TRUE)
#define	FATAL1(w, x, y, z) ERROR1(w, x, y, z);\
	handle_errors(w, x, B_TRUE, B_TRUE)

/* Defined as a uint64_t array for alignment purposes. */
static uint64_t get_buffer[MAX_GET_SIZE];

/*
 * Disable default TAB completion for now (until some brave soul tackles it).
 */
/* ARGSUSED */
static
CPL_MATCH_FN(no_match)
{
	return (0);
}

/*
 * Create/Grow a buffer large enough to hold error messages. If *ebuf
 * is not NULL then it will contain a copy of the command line that
 * triggered the error/warning, copy this into a new buffer or
 * append new messages to the existing buffer.
 */
/*PRINTFLIKE1*/
char *
record_error(char *ep, char *ebuf, char *fmt, ...)
{
	char *err_ptr;
	char tmp_buff[1024];
	va_list ap;
	int length = 0;
	err_ptr = ep;

	va_start(ap, fmt);
	length = vsnprintf(tmp_buff, sizeof (tmp_buff), fmt, ap);
	va_end(ap);

	/* There is a new line character */
	length++;

	if (ep == NULL) {
		if (ebuf != NULL)
			length += strlen(ebuf);
	} else  {
		length += strlen(ep);
	}

	if (err_ptr == NULL)
		err_ptr = calloc(length, sizeof (char));
	else
		err_ptr = realloc(err_ptr, length);

	if (err_ptr == NULL)
		Bail("realloc() failure");

	/*
	 * If (ep == NULL) then this is the first error to record,
	 * copy in the command line that triggered this error/warning.
	 */
	if (ep == NULL && ebuf != NULL)
		(void) strlcpy(err_ptr, ebuf, length);

	/*
	 * Now the actual error.
	 */
	(void) strlcat(err_ptr, tmp_buff, length);
	return (err_ptr);
}

/*
 * If not in interactive mode print usage message and exit.
 */
static void
usage(void)
{
	if (!interactive) {
		(void) fprintf(stderr, gettext("Usage:\t"
		    "ipseckey [ -nvp ] | cmd [sa_type] [extfield value]*\n"));
		(void) fprintf(stderr,
		    gettext("\tipseckey [ -nvp ] -f infile\n"));
		(void) fprintf(stderr,
		    gettext("\tipseckey [ -nvp ] -s outfile\n"));
		EXIT_FATAL(NULL);
	} else {
		(void) fprintf(stderr,
		    gettext("Type help or ? for usage info\n"));
	}
}


/*
 * Print out any errors, tidy up as required.
 * error pointer ep will be free()'d
 */
void
handle_errors(char *ep, char *ebuf, boolean_t fatal, boolean_t done)
{
	if (ep != NULL) {
		if (my_fmri == NULL) {
			/*
			 * For now suppress the errors when run from smf(5)
			 * because potentially sensitive information could
			 * end up in a publicly readable logfile.
			 */
			(void) fprintf(stdout, "%s\n", ep);
			(void) fflush(stdout);
		}
		free(ep);
		if (fatal) {
			if (ebuf != NULL) {
				free(ebuf);
			}
			/* reset command buffer */
			if (interactive)
				longjmp(env, 1);
		} else {
			return;
		}
	} else {
		/*
		 * No errors, if this is the last time that this function
		 * is called, free(ebuf) and reset command buffer.
		 */
		if (done) {
			if (ebuf != NULL) {
				free(ebuf);
			}
			/* reset command buffer */
			if (interactive)
				longjmp(env, 1);
		}
		return;
	}
	EXIT_FATAL(NULL);
}

/*
 * Initialize a PF_KEY base message.
 */
static void
msg_init(struct sadb_msg *msg, uint8_t type, uint8_t satype)
{
	msg->sadb_msg_version = PF_KEY_V2;
	msg->sadb_msg_type = type;
	msg->sadb_msg_errno = 0;
	msg->sadb_msg_satype = satype;
	/* For starters... */
	msg->sadb_msg_len = SADB_8TO64(sizeof (*msg));
	msg->sadb_msg_reserved = 0;
	msg->sadb_msg_seq = ++seq;
	msg->sadb_msg_pid = mypid;
}

/*
 * parseXXX and rparseXXX commands parse input and convert them to PF_KEY
 * field values, or do the reverse for the purposes of saving the SA tables.
 * (See the save_XXX functions.)
 */

#define	CMD_NONE	0
#define	CMD_UPDATE	2
#define	CMD_UPDATE_PAIR	3
#define	CMD_ADD		4
#define	CMD_DELETE	5
#define	CMD_DELETE_PAIR	6
#define	CMD_GET		7
#define	CMD_FLUSH	9
#define	CMD_DUMP	10
#define	CMD_MONITOR	11
#define	CMD_PMONITOR	12
#define	CMD_QUIT	13
#define	CMD_SAVE	14
#define	CMD_HELP	15

/*
 * Parse the command.
 */
static int
parsecmd(char *cmdstr)
{
	static struct cmdtable {
		char *cmd;
		int token;
	} table[] = {
		/*
		 * Q: Do we want to do GETSPI?
		 * A: No, it's for automated key mgmt. only.  Either that,
		 *    or it isn't relevant until we support non IPsec SA types.
		 */
		{"update",		CMD_UPDATE},
		{"update-pair",		CMD_UPDATE_PAIR},
		{"add",			CMD_ADD},
		{"delete", 		CMD_DELETE},
		{"delete-pair",		CMD_DELETE_PAIR},
		{"get", 		CMD_GET},
		/*
		 * Q: And ACQUIRE and REGISTER and EXPIRE?
		 * A: not until we support non IPsec SA types.
		 */
		{"flush",		CMD_FLUSH},
		{"dump",		CMD_DUMP},
		{"monitor",		CMD_MONITOR},
		{"passive_monitor",	CMD_PMONITOR},
		{"pmonitor",		CMD_PMONITOR},
		{"quit",		CMD_QUIT},
		{"exit",		CMD_QUIT},
		{"save",		CMD_SAVE},
		{"help",		CMD_HELP},
		{"?",			CMD_HELP},
		{NULL,			CMD_NONE}
	};
	struct cmdtable *ct = table;

	while (ct->cmd != NULL && strcmp(ct->cmd, cmdstr) != 0)
		ct++;
	return (ct->token);
}

/*
 * Convert a number from a command line.  I picked "u_longlong_t" for the
 * number because we need the largest number available.  Also, the strto<num>
 * calls don't deal in units of uintNN_t.
 */
static u_longlong_t
parsenum(char *num, boolean_t bail, char *ebuf)
{
	u_longlong_t rc = 0;
	char *end = NULL;
	char *ep = NULL;

	if (num == NULL) {
		FATAL(ep, ebuf, gettext("Unexpected end of command line,"
		    " was expecting a number.\n"));
		/* NOTREACHED */
	}

	errno = 0;
	rc = strtoull(num, &end, 0);
	if (errno != 0 || end == num || *end != '\0') {
		if (bail) {
			FATAL1(ep, ebuf, gettext(
			"Expecting a number, not \"%s\"!\n"), num);
		} else {
			/*
			 * -1, while not optimal, is sufficiently out of range
			 * for most of this function's applications when
			 * we don't just bail.
			 */
			return ((u_longlong_t)-1);
		}
	}
	handle_errors(ep, NULL, B_FALSE, B_FALSE);
	return (rc);
}

/*
 * Parse and reverse parse a specific SA type (AH, ESP, etc.).
 */
static struct typetable {
	char *type;
	int token;
} type_table[] = {
	{"all",	SADB_SATYPE_UNSPEC},
	{"ah",	SADB_SATYPE_AH},
	{"esp",	SADB_SATYPE_ESP},
	/* PF_KEY NOTE:  More to come if net/pfkeyv2.h gets updated. */
	{NULL,	0}	/* Token value is irrelevant for this entry. */
};


static int
parsesatype(char *type, char *ebuf)
{
	struct typetable *tt = type_table;
	char *ep = NULL;

	if (type == NULL)
		return (SADB_SATYPE_UNSPEC);

	while (tt->type != NULL && strcasecmp(tt->type, type) != 0)
		tt++;

	/*
	 * New SA types (including ones keysock maintains for user-land
	 * protocols) may be added, so parse a numeric value if possible.
	 */
	if (tt->type == NULL) {
		tt->token = (int)parsenum(type, B_FALSE, ebuf);
		if (tt->token == -1) {
			ERROR1(ep, ebuf, gettext(
			    "Unknown SA type (%s).\n"), type);
			tt->token = SADB_SATYPE_UNSPEC;
		}
	}
	handle_errors(ep, NULL, interactive ? B_TRUE : B_FALSE, B_FALSE);
	return (tt->token);
}

#define	NEXTEOF		0
#define	NEXTNONE	1
#define	NEXTNUM		2
#define	NEXTSTR		3
#define	NEXTNUMSTR	4
#define	NEXTADDR	5
#define	NEXTHEX		6
#define	NEXTIDENT	7
#define	NEXTADDR4	8
#define	NEXTADDR6	9
#define	NEXTLABEL	10

#define	TOK_EOF			0
#define	TOK_UNKNOWN		1
#define	TOK_SPI			2
#define	TOK_REPLAY		3
#define	TOK_STATE		4
#define	TOK_AUTHALG		5
#define	TOK_ENCRALG		6
#define	TOK_FLAGS		7
#define	TOK_SOFT_ALLOC		8
#define	TOK_SOFT_BYTES		9
#define	TOK_SOFT_ADDTIME	10
#define	TOK_SOFT_USETIME	11
#define	TOK_HARD_ALLOC		12
#define	TOK_HARD_BYTES		13
#define	TOK_HARD_ADDTIME	14
#define	TOK_HARD_USETIME	15
#define	TOK_CURRENT_ALLOC	16
#define	TOK_CURRENT_BYTES	17
#define	TOK_CURRENT_ADDTIME	18
#define	TOK_CURRENT_USETIME	19
#define	TOK_SRCADDR		20
#define	TOK_DSTADDR		21
#define	TOK_PROXYADDR		22
#define	TOK_AUTHKEY		23
#define	TOK_ENCRKEY		24
#define	TOK_SRCIDTYPE		25
#define	TOK_DSTIDTYPE		26
#define	TOK_DPD			27
#define	TOK_SENS_LEVEL		28
#define	TOK_SENS_MAP		29
#define	TOK_INTEG_LEVEL		30
#define	TOK_INTEG_MAP		31
#define	TOK_SRCADDR6		32
#define	TOK_DSTADDR6		33
#define	TOK_PROXYADDR6		34
#define	TOK_SRCPORT		35
#define	TOK_DSTPORT		36
#define	TOK_PROTO		37
#define	TOK_ENCAP		38
#define	TOK_NATLOC		39
#define	TOK_NATREM		40
#define	TOK_NATLPORT		41
#define	TOK_NATRPORT		42
#define	TOK_IPROTO		43
#define	TOK_IDSTADDR		44
#define	TOK_IDSTADDR6		45
#define	TOK_ISRCPORT		46
#define	TOK_IDSTPORT		47
#define	TOK_PAIR_SPI		48
#define	TOK_FLAG_INBOUND	49
#define	TOK_FLAG_OUTBOUND	50
#define	TOK_REPLAY_VALUE	51
#define	TOK_IDLE_ADDTIME	52
#define	TOK_IDLE_USETIME	53
#define	TOK_RESERVED		54
#define	TOK_LABEL		55
#define	TOK_OLABEL		56
#define	TOK_IMPLABEL		57


static struct toktable {
	char *string;
	int token;
	int next;
} tokens[] = {
	/* "String",		token value,		next arg is */
	{"spi",			TOK_SPI,		NEXTNUM},
	{"pair-spi",		TOK_PAIR_SPI,		NEXTNUM},
	{"replay",		TOK_REPLAY,		NEXTNUM},
	{"state",		TOK_STATE,		NEXTNUMSTR},
	{"auth_alg",		TOK_AUTHALG,		NEXTNUMSTR},
	{"authalg",		TOK_AUTHALG,		NEXTNUMSTR},
	{"encr_alg",		TOK_ENCRALG,		NEXTNUMSTR},
	{"encralg",		TOK_ENCRALG,		NEXTNUMSTR},
	{"flags",		TOK_FLAGS,		NEXTNUM},
	{"soft_alloc",		TOK_SOFT_ALLOC,		NEXTNUM},
	{"soft_bytes",		TOK_SOFT_BYTES,		NEXTNUM},
	{"soft_addtime",	TOK_SOFT_ADDTIME,	NEXTNUM},
	{"soft_usetime",	TOK_SOFT_USETIME,	NEXTNUM},
	{"hard_alloc",		TOK_HARD_ALLOC,		NEXTNUM},
	{"hard_bytes",		TOK_HARD_BYTES,		NEXTNUM},
	{"hard_addtime",	TOK_HARD_ADDTIME,	NEXTNUM},
	{"hard_usetime",	TOK_HARD_USETIME,	NEXTNUM},
	{"current_alloc",	TOK_CURRENT_ALLOC,	NEXTNUM},
	{"current_bytes",	TOK_CURRENT_BYTES,	NEXTNUM},
	{"current_addtime",	TOK_CURRENT_ADDTIME,	NEXTNUM},
	{"current_usetime",	TOK_CURRENT_USETIME,	NEXTNUM},

	{"saddr",		TOK_SRCADDR,		NEXTADDR},
	{"srcaddr",		TOK_SRCADDR,		NEXTADDR},
	{"src",			TOK_SRCADDR,		NEXTADDR},
	{"daddr",		TOK_DSTADDR,		NEXTADDR},
	{"dstaddr",		TOK_DSTADDR,		NEXTADDR},
	{"dst",			TOK_DSTADDR,		NEXTADDR},
	{"proxyaddr",		TOK_PROXYADDR,		NEXTADDR},
	{"proxy",		TOK_PROXYADDR,		NEXTADDR},
	{"innersrc",		TOK_PROXYADDR,		NEXTADDR},
	{"isrc",		TOK_PROXYADDR,		NEXTADDR},
	{"innerdst",		TOK_IDSTADDR,		NEXTADDR},
	{"idst",		TOK_IDSTADDR,		NEXTADDR},

	{"sport",		TOK_SRCPORT,		NEXTNUM},
	{"dport",		TOK_DSTPORT,		NEXTNUM},
	{"innersport",		TOK_ISRCPORT,		NEXTNUM},
	{"isport",		TOK_ISRCPORT,		NEXTNUM},
	{"innerdport",		TOK_IDSTPORT,		NEXTNUM},
	{"idport",		TOK_IDSTPORT,		NEXTNUM},
	{"proto",		TOK_PROTO,		NEXTNUM},
	{"ulp",			TOK_PROTO,		NEXTNUM},
	{"iproto",		TOK_IPROTO,		NEXTNUM},
	{"iulp",		TOK_IPROTO,		NEXTNUM},

	{"saddr6",		TOK_SRCADDR6,		NEXTADDR},
	{"srcaddr6",		TOK_SRCADDR6,		NEXTADDR},
	{"src6",		TOK_SRCADDR6,		NEXTADDR},
	{"daddr6",		TOK_DSTADDR6,		NEXTADDR},
	{"dstaddr6",		TOK_DSTADDR6,		NEXTADDR},
	{"dst6",		TOK_DSTADDR6,		NEXTADDR},
	{"proxyaddr6",		TOK_PROXYADDR6,		NEXTADDR},
	{"proxy6",		TOK_PROXYADDR6,		NEXTADDR},
	{"innersrc6",		TOK_PROXYADDR6,		NEXTADDR},
	{"isrc6",		TOK_PROXYADDR6,		NEXTADDR},
	{"innerdst6",		TOK_IDSTADDR6,		NEXTADDR},
	{"idst6",		TOK_IDSTADDR6,		NEXTADDR},

	{"authkey",		TOK_AUTHKEY,		NEXTHEX},
	{"encrkey",		TOK_ENCRKEY,		NEXTHEX},
	{"srcidtype",		TOK_SRCIDTYPE,		NEXTIDENT},
	{"dstidtype",		TOK_DSTIDTYPE,		NEXTIDENT},
	{"dpd",			TOK_DPD,		NEXTNUM},
	{"sens_level",		TOK_SENS_LEVEL,		NEXTNUM},
	{"sens_map",		TOK_SENS_MAP,		NEXTHEX},
	{"integ_level",		TOK_INTEG_LEVEL,	NEXTNUM},
	{"integ_map",		TOK_INTEG_MAP,		NEXTHEX},
	{"nat_loc",		TOK_NATLOC,		NEXTADDR},
	{"nat_rem",		TOK_NATREM,		NEXTADDR},
	{"nat_lport",		TOK_NATLPORT,		NEXTNUM},
	{"nat_rport",		TOK_NATRPORT,		NEXTNUM},
	{"encap",		TOK_ENCAP,		NEXTNUMSTR},

	{"outbound",		TOK_FLAG_OUTBOUND,	NULL},
	{"inbound",		TOK_FLAG_INBOUND,	NULL},

	{"reserved_bits",	TOK_RESERVED,		NEXTNUM},
	{"replay_value",	TOK_REPLAY_VALUE,	NEXTNUM},
	{"idle_addtime",	TOK_IDLE_ADDTIME,	NEXTNUM},
	{"idle_usetime",	TOK_IDLE_USETIME,	NEXTNUM},

	{"label",		TOK_LABEL,		NEXTLABEL},
	{"outer-label",		TOK_OLABEL,		NEXTLABEL},
	{"implicit-label",	TOK_IMPLABEL,		NEXTLABEL},

	{NULL,			TOK_UNKNOWN,		NEXTEOF}
};

/*
 * Q:	Do I need stuff for proposals, combinations, supported algorithms,
 *	or SPI ranges?
 *
 * A:	Probably not, but you never know.
 *
 * Parse out extension header type values.
 */
static int
parseextval(char *value, int *next)
{
	struct toktable *tp;

	if (value == NULL)
		return (TOK_EOF);

	for (tp = tokens; tp->string != NULL; tp++)
		if (strcmp(value, tp->string) == 0)
			break;

	/*
	 * Since the OS controls what extensions are available, we don't have
	 * to parse numeric values here.
	 */

	*next = tp->next;
	return (tp->token);
}

/*
 * Parse possible state values.
 */
static uint8_t
parsestate(char *state, char *ebuf)
{
	struct states {
		char *state;
		uint8_t retval;
	} states[] = {
		{"larval",	SADB_SASTATE_LARVAL},
		{"mature",	SADB_SASTATE_MATURE},
		{"dying",	SADB_SASTATE_DYING},
		{"dead",	SADB_SASTATE_DEAD},
		{NULL,		0}
	};
	struct states *sp;
	char *ep = NULL;

	if (state == NULL) {
		FATAL(ep, ebuf, "Unexpected end of command line "
		    "was expecting a state.\n");
	}

	for (sp = states; sp->state != NULL; sp++) {
		if (strcmp(sp->state, state) == 0)
			return (sp->retval);
	}
	ERROR1(ep, ebuf, gettext("Unknown state type \"%s\"\n"), state);
	handle_errors(ep, NULL, B_FALSE, B_FALSE);
	return (0);
}

/*
 * Return the numerical algorithm identifier corresponding to the specified
 * algorithm name.
 */
static uint8_t
parsealg(char *alg, int proto_num, char *ebuf)
{
	u_longlong_t invalue;
	struct ipsecalgent *algent;
	char *ep = NULL;

	if (alg == NULL) {
		FATAL(ep, ebuf, gettext("Unexpected end of command line, "
		    "was expecting an algorithm name.\n"));
	}

	algent = getipsecalgbyname(alg, proto_num, NULL);
	if (algent != NULL) {
		uint8_t alg_num;

		alg_num = algent->a_alg_num;
		if (ALG_FLAG_COUNTERMODE & algent->a_alg_flags)
			WARN1(ep, ebuf, gettext(
			    "Using manual keying with a Counter mode algorithm "
			    "such as \"%s\" may be insecure!\n"),
			    algent->a_names[0]);
		freeipsecalgent(algent);

		return (alg_num);
	}

	/*
	 * Since algorithms can be loaded during kernel run-time, check for
	 * numeric algorithm values too.  PF_KEY can catch bad ones with EINVAL.
	 */
	invalue = parsenum(alg, B_FALSE, ebuf);
	if (invalue != (u_longlong_t)-1 &&
	    (u_longlong_t)(invalue & (u_longlong_t)0xff) == invalue)
		return ((uint8_t)invalue);

	if (proto_num == IPSEC_PROTO_ESP) {
		ERROR1(ep, ebuf, gettext(
		    "Unknown encryption algorithm type \"%s\"\n"), alg);
	} else {
		ERROR1(ep, ebuf, gettext(
		    "Unknown authentication algorithm type \"%s\"\n"), alg);
	}
	handle_errors(ep, NULL, B_FALSE, B_FALSE);
	return (0);
}

/*
 * Parse and reverse parse out a source/destination ID type.
 */
static struct idtypes {
	char *idtype;
	uint8_t retval;
} idtypes[] = {
	{"prefix",	SADB_IDENTTYPE_PREFIX},
	{"fqdn",	SADB_IDENTTYPE_FQDN},
	{"domain",	SADB_IDENTTYPE_FQDN},
	{"domainname",	SADB_IDENTTYPE_FQDN},
	{"user_fqdn",	SADB_IDENTTYPE_USER_FQDN},
	{"mailbox",	SADB_IDENTTYPE_USER_FQDN},
	{"der_dn",	SADB_X_IDENTTYPE_DN},
	{"der_gn",	SADB_X_IDENTTYPE_GN},
	{NULL,		0}
};

static uint16_t
parseidtype(char *type, char *ebuf)
{
	struct idtypes *idp;
	u_longlong_t invalue;
	char *ep = NULL;

	if (type == NULL) {
		/* Shouldn't reach here, see callers for why. */
		FATAL(ep, ebuf, gettext("Unexpected end of command line, "
		    "was expecting a type.\n"));
	}

	for (idp = idtypes; idp->idtype != NULL; idp++) {
		if (strcasecmp(idp->idtype, type) == 0)
			return (idp->retval);
	}
	/*
	 * Since identity types are almost arbitrary, check for numeric
	 * algorithm values too.  PF_KEY can catch bad ones with EINVAL.
	 */
	invalue = parsenum(type, B_FALSE, ebuf);
	if (invalue != (u_longlong_t)-1 &&
	    (u_longlong_t)(invalue & (u_longlong_t)0xffff) == invalue)
		return ((uint16_t)invalue);


	ERROR1(ep, ebuf, gettext("Unknown identity type \"%s\"\n"), type);

	handle_errors(ep, NULL, B_FALSE, B_FALSE);
	return (0);
}

/*
 * Parse an address off the command line.  Return length of sockaddr,
 * and either return a hostent pointer (caller frees).  The new
 * getipnodebyname() call does the Right Thing (TM), even with
 * raw addresses (colon-separated IPv6 or dotted decimal IPv4).
 */

static struct {
	struct hostent he;
	char *addtl[2];
	} dummy;
static union {
	struct in6_addr ipv6;
	struct in_addr ipv4;
	uint64_t aligner;
} addr1;

static int
parseaddr(char *addr, struct hostent **hpp, boolean_t v6only, char *ebuf)
{
	int hp_errno;
	struct hostent *hp = NULL;
	char *ep = NULL;

	if (addr == NULL) {
		FATAL(ep, ebuf, gettext("Unexpected end of command line, "
		    "was expecting an address.\n"));
	}

	if (!nflag) {
		/*
		 * Try name->address first.  Assume AF_INET6, and
		 * get IPv4's, plus IPv6's if and only if IPv6 is configured.
		 * This means to add IPv6 SAs, you must have IPv6
		 * up-and-running.  (AI_DEFAULT works here.)
		 */
		hp = getipnodebyname(addr, AF_INET6,
		    (v6only ? AI_ADDRCONFIG : (AI_DEFAULT | AI_ALL)),
		    &hp_errno);
	} else {
		/*
		 * Try a normal address conversion only.  Use "dummy"
		 * to construct a fake hostent.  Caller will know not
		 * to free this one.
		 */
		if (inet_pton(AF_INET6, addr, &addr1) == 1) {
			dummy.he.h_addr_list = dummy.addtl;
			dummy.addtl[0] = (char *)&addr1;
			dummy.addtl[1] = NULL;
			hp = &dummy.he;
			dummy.he.h_addrtype = AF_INET6;
			dummy.he.h_length = sizeof (struct in6_addr);
		} else if (inet_pton(AF_INET, addr, &addr1) == 1) {
			/*
			 * Remap to AF_INET6 anyway.
			 */
			dummy.he.h_addr_list = dummy.addtl;
			dummy.addtl[0] = (char *)&addr1;
			dummy.addtl[1] = NULL;
			hp = &dummy.he;
			dummy.he.h_addrtype = AF_INET6;
			dummy.he.h_length = sizeof (struct in6_addr);
			/*
			 * NOTE:  If macro changes to disallow in-place
			 * conversion, rewhack this.
			 */
			IN6_INADDR_TO_V4MAPPED(&addr1.ipv4, &addr1.ipv6);
		} else {
			hp = NULL;
		}
	}

	if (hp == NULL)
		WARN1(ep, ebuf, gettext("Unknown address %s."), addr);

	*hpp = hp;
	/* Always return sockaddr_in6 for now. */
	handle_errors(ep, NULL, B_FALSE, B_FALSE);
	return (sizeof (struct sockaddr_in6));
}

/*
 * Parse a hex character for a key.  A string will take the form:
 *	xxxxxxxxx/nn
 * where
 *	xxxxxxxxx == a string of hex characters ([0-9][a-f][A-F])
 *	nn == an optional decimal "mask".  If it is not present, it
 *	is assumed that the hex string will be rounded to the nearest
 *	byte, where odd nibbles, like 123 will become 0x0123.
 *
 * NOTE:Unlike the expression of IP addresses, I will not allow an
 *	excessive "mask".  For example 2112/50 is very illegal.
 * NOTE2:	This key should be in canonical order.  Consult your man
 *		pages per algorithm about said order.
 */

#define	hd2num(hd) (((hd) >= '0' && (hd) <= '9') ? ((hd) - '0') : \
	(((hd) >= 'a' && (hd) <= 'f') ? ((hd) - 'a' + 10) : ((hd) - 'A' + 10)))

static struct sadb_key *
parsekey(char *input, char *ebuf, uint_t reserved_bits)
{
	struct sadb_key *retval;
	uint_t i, hexlen = 0, bits, alloclen;
	uint8_t *key;
	char *ep = NULL;

	if (input == NULL) {
		FATAL(ep, ebuf, gettext("Unexpected end of command line, "
		    "was expecting a key.\n"));
	}
	/* Allow hex values prepended with 0x convention */
	if ((strnlen(input, sizeof (hexlen)) > 2) &&
	    (strncasecmp(input, "0x", 2) == 0))
		input += 2;

	for (i = 0; input[i] != '\0' && input[i] != '/'; i++)
		hexlen++;

	if (input[i] == '\0') {
		bits = 0;
	} else {
		/* Have /nn. */
		input[i] = '\0';
		if (sscanf((input + i + 1), "%u", &bits) != 1) {
			FATAL1(ep, ebuf, gettext(
			    "\"%s\" is not a bit specifier.\n"),
			    (input + i + 1));
		}
		/* hexlen in nibbles */
		if (((bits + 3) >> 2) > hexlen) {
			ERROR2(ep, ebuf, gettext(
			    "bit length %d is too big for %s.\n"), bits, input);
		}
		/*
		 * Adjust hexlen down if user gave us too small of a bit
		 * count.
		 */
		if ((hexlen << 2) > bits + 3) {
			WARN2(ep, ebuf, gettext(
			    "WARNING: Lower bits will be truncated "
			    "for:\n\t%s/%d.\n"), input, bits);
			hexlen = (bits + 3) >> 2;
			input[hexlen] = '\0';
		}
	}

	/*
	 * Allocate.  Remember, hexlen is in nibbles.
	 */

	alloclen = sizeof (*retval) + roundup((hexlen/2 + (hexlen & 0x1)), 8);
	retval = malloc(alloclen);

	if (retval == NULL)
		Bail("malloc(parsekey)");
	retval->sadb_key_len = SADB_8TO64(alloclen);

	retval->sadb_key_reserved = reserved_bits;

	if (bits == 0)
		retval->sadb_key_bits = (hexlen + (hexlen & 0x1)) << 2;
	else
		retval->sadb_key_bits = bits;

	/*
	 * Read in nibbles.  Read in odd-numbered as shifted high.
	 * (e.g. 123 becomes 0x1230).
	 */

	key = (uint8_t *)(retval + 1);
	for (i = 0; input[i] != '\0'; i += 2) {
		boolean_t second = (input[i + 1] != '\0');

		if (!isxdigit(input[i]) ||
		    (!isxdigit(input[i + 1]) && second)) {
			ERROR1(ep, ebuf, gettext(
			    "string '%s' not a hex value.\n"), input);
			free(retval);
			retval = NULL;
			break;
		}
		*key = (hd2num(input[i]) << 4);
		if (second)
			*key |= hd2num(input[i + 1]);
		else
			break;	/* out of for loop. */
		key++;
	}

	/* bzero the remaining bits if we're a non-octet amount. */
	if (bits & 0x7)
		*((input[i] == '\0') ? key - 1 : key) &=
		    0xff << (8 - (bits & 0x7));

	handle_errors(ep, NULL, B_FALSE, B_FALSE);
	return (retval);
}

#include <tsol/label.h>

#define	PARSELABEL_BAD_TOKEN ((struct sadb_sens *)-1)

static struct sadb_sens *
parselabel(int token, char *label)
{
	bslabel_t *sl = NULL;
	int err, len;
	sadb_sens_t *sens;
	int doi = 1;  /* XXX XXX DEFAULT_DOI XXX XXX */

	err = str_to_label(label, &sl, MAC_LABEL, L_DEFAULT, NULL);
	if (err < 0)
		return (NULL);

	len = ipsec_convert_sl_to_sens(doi, sl, NULL);

	sens = malloc(len);
	if (sens == NULL) {
		Bail("malloc parsed label");
		/* Should exit before reaching here... */
		return (NULL);
	}

	(void) ipsec_convert_sl_to_sens(doi, sl, sens);

	switch (token) {
	case TOK_LABEL:
		break;

	case TOK_OLABEL:
		sens->sadb_sens_exttype = SADB_X_EXT_OUTER_SENS;
		break;

	case TOK_IMPLABEL:
		sens->sadb_sens_exttype = SADB_X_EXT_OUTER_SENS;
		sens->sadb_x_sens_flags = SADB_X_SENS_IMPLICIT;
		break;

	default:
		free(sens);
		/*
		 * Return a different return code for a bad label, but really,
		 * this would be a caller error.
		 */
		return (PARSELABEL_BAD_TOKEN);
	}

	return (sens);
}

/*
 * Write a message to the PF_KEY socket.  If verbose, print the message
 * heading into the kernel.
 */
static int
key_write(int fd, void *msg, size_t len)
{
	if (vflag) {
		(void) printf(
		    gettext("VERBOSE ON:  Message to kernel looks like:\n"));
		(void) printf("==========================================\n");
		print_samsg(stdout, msg, B_FALSE, vflag, nflag);
		(void) printf("==========================================\n");
	}

	return (write(fd, msg, len));
}

/*
 * SIGALRM handler for time_critical_enter.
 */
static void
time_critical_catch(int signal)
{
	if (signal == SIGALRM) {
		errx(1, gettext("Reply message from PF_KEY timed out."));
	} else {
		errx(1, gettext("Caught signal %d while trying to receive"
		    "PF_KEY reply message"), signal);
	}
	/* errx() calls exit. */
}

#define	TIME_CRITICAL_TIME 10	/* In seconds */

/*
 * Enter a "time critical" section where key is waiting for a return message.
 */
static void
time_critical_enter(void)
{
	(void) signal(SIGALRM, time_critical_catch);
	(void) alarm(TIME_CRITICAL_TIME);
}

/*
 * Exit the "time critical" section after getting an appropriate return
 * message.
 */
static void
time_critical_exit(void)
{
	(void) alarm(0);
	(void) signal(SIGALRM, SIG_DFL);
}

/*
 * Construct a PF_KEY FLUSH message for the SA type specified.
 */
static void
doflush(int satype)
{
	struct sadb_msg msg;
	int rc;

	msg_init(&msg, SADB_FLUSH, (uint8_t)satype);
	rc = key_write(keysock, &msg, sizeof (msg));
	if (rc == -1)
		Bail("write() to PF_KEY socket failed (in doflush)");

	time_critical_enter();
	do {
		rc = read(keysock, &msg, sizeof (msg));
		if (rc == -1)
			Bail("read (in doflush)");
	} while (msg.sadb_msg_seq != seq || msg.sadb_msg_pid != mypid);
	time_critical_exit();

	/*
	 * I should _never_ hit the following unless:
	 *
	 * 1. There is a kernel bug.
	 * 2. There is another process filling in its pid with mine, and
	 *    issuing a different message that would cause a different result.
	 */
	if (msg.sadb_msg_type != SADB_FLUSH ||
	    msg.sadb_msg_satype != (uint8_t)satype) {
		syslog((LOG_NOTICE|LOG_AUTH),
		    gettext("doflush: Return message not of type SADB_FLUSH!"));
		Bail("doflush: Return message not of type SADB_FLUSH!");
	}

	if (msg.sadb_msg_errno != 0) {
		errno = msg.sadb_msg_errno;
		if (errno == EINVAL) {
			print_diagnostic(stderr, msg.sadb_x_msg_diagnostic);
			warnx(gettext("Cannot flush SA type %d."), satype);
		}
		Bail("return message (in doflush)");
	}
}

/*
 * save_XXX functions are used when "saving" the SA tables to either a
 * file or standard output.  They use the dump_XXX functions where needed,
 * but mostly they use the rparseXXX functions.
 */

/*
 * Because "save" and "dump" both use the SADB_DUMP message, fold both
 * into the same function.
 */
static void
dodump(int satype, FILE *ofile)
{
	struct sadb_msg *msg = (struct sadb_msg *)get_buffer;
	int rc;

	if (ofile != NULL) {
		(void) fprintf(ofile,
		    gettext("# This key file was generated by the"));
		(void) fprintf(ofile,
		    gettext(" ipseckey(1m) command's 'save' feature.\n\n"));
	}
	msg_init(msg, SADB_DUMP, (uint8_t)satype);
	rc = key_write(keysock, msg, sizeof (*msg));
	if (rc == -1)
		Bail("write to PF_KEY socket failed (in dodump)");

	do {
		/*
		 * For DUMP, do only the read as a time critical section.
		 */
		time_critical_enter();
		rc = read(keysock, get_buffer, sizeof (get_buffer));
		time_critical_exit();
		if (rc == -1)
			Bail("read (in dodump)");
		if (msg->sadb_msg_pid == mypid &&
		    msg->sadb_msg_type == SADB_DUMP &&
		    msg->sadb_msg_seq != 0 &&
		    msg->sadb_msg_errno == 0) {
			if (ofile == NULL) {
				print_samsg(stdout, get_buffer, B_FALSE, vflag,
				    nflag);
				(void) putchar('\n');
			} else {
				save_assoc(get_buffer, ofile);
			}
		}
	} while (msg->sadb_msg_pid != mypid ||
	    (msg->sadb_msg_errno == 0 && msg->sadb_msg_seq != 0));

	if (ofile != NULL && ofile != stdout)
		(void) fclose(ofile);

	if (msg->sadb_msg_errno == 0) {
		if (ofile == NULL)
			(void) printf(
			    gettext("Dump succeeded for SA type %d.\n"),
			    satype);
	} else {
		print_diagnostic(stderr, msg->sadb_x_msg_diagnostic);
		errno = msg->sadb_msg_errno;
		Bail("Dump failed");
	}
}

#define	SCOPE_UNSPEC 0
#define	SCOPE_LINKLOCAL 1
#define	SCOPE_SITELOCAL 2
#define	SCOPE_GLOBAL 3
#define	SCOPE_V4COMPAT 4
#define	SCOPE_LOOPBACK 5	/* Pedantic, yes, but necessary. */

static int
ipv6_addr_scope(struct in6_addr *addr)
{
	/* Don't return anything regarding multicast for now... */

	if (IN6_IS_ADDR_UNSPECIFIED(addr))
		return (SCOPE_UNSPEC);

	if (IN6_IS_ADDR_LINKLOCAL(addr))
		return (SCOPE_LINKLOCAL);

	if (IN6_IS_ADDR_SITELOCAL(addr))
		return (SCOPE_SITELOCAL);

	if (IN6_IS_ADDR_V4COMPAT(addr))
		return (SCOPE_V4COMPAT);

	if (IN6_IS_ADDR_LOOPBACK(addr))
		return (SCOPE_LOOPBACK);

	/* For now, return global by default. */
	return (SCOPE_GLOBAL);
}

/*
 * doaddresses():
 *
 * Used by doaddup() and dodelget() to create new SA's based on the
 * provided source and destination addresses hostent.
 *
 * sadb_msg_type: expected PF_KEY reply message type
 * sadb_msg_satype: expected PF_KEY reply satype
 * cmd: user command
 * srchp: hostent for the source address(es)
 * dsthp: hostent for the destination address(es)
 * src: points to the SADB source address extension
 * dst: points to the SADB destination address extension
 * unspec_src: indicates an unspecified source address.
 * buffer: pointer to the SADB buffer to use with PF_KEY
 * buffer_size: size of buffer
 * spi: spi for this message (set by caller)
 * srcport: source port if specified
 * dstport: destination port if specified
 * proto: IP protocol number if specified
 * iproto: Inner (tunnel mode) IP protocol number if specified
 * NATT note: we are going to assume a semi-sane world where NAT
 * boxen don't explode to multiple addresses.
 */
static void
doaddresses(uint8_t sadb_msg_type, uint8_t sadb_msg_satype, int cmd,
    struct hostent *srchp, struct hostent *dsthp,
    struct sadb_address *src, struct sadb_address *dst,
    boolean_t unspec_src, uint64_t *buffer, int buffer_size, uint32_t spi,
    char *ebuf)
{
	boolean_t last_dst;
	struct sockaddr_in6 *sin6;
	struct sadb_msg *msgp;
	int i, rc;
	char **walker;	/* For the SRC and PROXY walking functions. */
	char *first_match;
	uint64_t savebuf[MAX_GET_SIZE];
	uint16_t srcport = 0, dstport = 0;
	char *ep = NULL;

	/*
	 * Okay, now we have "src", "dst", and maybe "proxy" reassigned
	 * to point into the buffer to be written to PF_KEY, we can do
	 * potentially several writes based on destination address.
	 *
	 * First, obtain port numbers from passed-in extensions.
	 */

	if (src != NULL) {
		sin6 = (struct sockaddr_in6 *)(src + 1);
		srcport = ntohs(sin6->sin6_port);
	}
	if (dst != NULL) {
		sin6 = (struct sockaddr_in6 *)(dst + 1);
		dstport = ntohs(sin6->sin6_port);
	}

	/*
	 * The rules for ADD, GET, and UPDATE: (NOTE:  This assumes IPsec.
	 * If other consumers of PF_KEY happen, this will have to be
	 * rewhacked.):
	 *
	 *	Do a message for every possible DST address.
	 *
	 *	If a source or proxy address explodes, keep unspecified
	 *	(and mention unspecified).
	 *
	 * DELETE is different, because you can leave either "src" or "dst"
	 * blank!  You need to explode if one of them is full, and not assume
	 * that the other is set.
	 */

	if (dsthp == NULL) {
		/*
		 * No destination address specified.
		 * With extended diagnostics, we don't have to bail the
		 * non-DELETE cases here.  The EINVAL diagnostics will be
		 * enough to inform the user(s) what happened.
		 */
		i = 0;
		do {
			if (srchp == &dummy.he) {
				/* Just to be sure... */
				srchp->h_addr_list[1] = NULL;
			} else if (srchp != NULL) {
				/* Degenerate case, h_addr_list[0] == NULL. */
				if (srchp->h_addr_list[i] == NULL)
					Bail("Empty source address list");

				/*
				 * Fill in the src sockaddr.
				 */
				sin6 = (struct sockaddr_in6 *)(src + 1);
				bzero(sin6, sizeof (*sin6));
				bcopy(srchp->h_addr_list[i], &sin6->sin6_addr,
				    sizeof (struct in6_addr));
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = htons(srcport);
			}

			/* Save off a copy for later writing... */
			msgp = (struct sadb_msg *)buffer;
			bcopy(buffer, savebuf, SADB_64TO8(msgp->sadb_msg_len));

			rc = key_write(keysock, buffer,
			    SADB_64TO8(msgp->sadb_msg_len));
			if (rc == -1)
				Bail("write() to PF_KEY socket "
				    "(in doaddresses)");
			/*
			 * Sends the message to the Solaris Cluster daemon
			 */

			if (in_cluster_mode) {
				(void) sendto(cluster_socket, buffer,
				    SADB_64TO8(msgp->sadb_msg_len), 0,
				    (struct sockaddr *)&cli_addr,
				    sizeof (cli_addr));
			}

			time_critical_enter();
			do {
				rc = read(keysock, buffer, buffer_size);
				if (rc == -1)
					Bail("read (in doaddresses)");
			} while (msgp->sadb_msg_seq != seq ||
			    msgp->sadb_msg_pid != mypid);
			time_critical_exit();

			if (msgp->sadb_msg_type != sadb_msg_type ||
			    msgp->sadb_msg_satype != sadb_msg_satype) {
				syslog((LOG_NOTICE|LOG_AUTH), gettext(
				    "doaddresses: Unexpected returned message "
				    "(%d exp %d)\n"), msgp->sadb_msg_type,
				    sadb_msg_type);
				Bail("doaddresses: Unexpected returned "
				    "message");
			}

			errno = msgp->sadb_msg_errno;
			if (errno != 0) {
				if (errno == EINVAL) {
					WARN(ep, ebuf, gettext(
					    "One of the entered "
					    "values is incorrect."));
					print_diagnostic(stderr,
					    msgp->sadb_x_msg_diagnostic);
				} else {
					Bail("return message (in doaddresses)");
				}
			}

			/* ...and then restore the saved buffer. */
			msgp = (struct sadb_msg *)savebuf;
			bcopy(savebuf, buffer, SADB_64TO8(msgp->sadb_msg_len));
		} while (srchp != NULL && srchp->h_addr_list[++i] != NULL);
		return;
	}

	/*
	 * Go through the list of all dst addresses, trying to find matching
	 * src address for each. If the first address is == dummy.he we will go
	 * through the loop just once. If any other hp is == dummy.he, then we
	 * don't have to apply any silly rules.
	 */
	for (i = 0; dsthp->h_addr_list[i] != NULL; i++) {
		if (dsthp == &dummy.he) {
			/* Just to be sure... */
			dsthp->h_addr_list[1] = NULL;
		} else {
			/*
			 * Fill in the dst sockaddr.
			 */
			sin6 = (struct sockaddr_in6 *)(dst + 1);
			bzero(sin6, sizeof (*sin6));
			bcopy(dsthp->h_addr_list[i], &sin6->sin6_addr,
			    sizeof (struct in6_addr));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(dstport);
		}

		last_dst = (dsthp->h_addr_list[i + 1] == NULL);

		/*
		 * Try and assign src, if there's any ambiguity.
		 */
		if (!unspec_src && srchp != &dummy.he) {
			if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
				/*
				 * IPv4 address.  Find an IPv4 address, then
				 * keep looking for a second one.  If a second
				 * exists, print a message, and fill in the
				 * unspecified address.
				 */
				first_match = NULL;

				for (walker = srchp->h_addr_list;
				    *walker != NULL; walker++) {
					/* LINTED E_BAD_PTR_CAST_ALIGN */
					if (IN6_IS_ADDR_V4MAPPED(
					    (struct in6_addr *)*walker)) {
						if (first_match != NULL)
							break;
						else
							first_match = *walker;
					}
				}
				sin6 = (struct sockaddr_in6 *)(src + 1);
				bzero(sin6, sizeof (*sin6));

				if (first_match == NULL) {
					/*
					 * No IPv4 hits. Is this the last
					 * destination address in the list ?
					 */
					ERROR1(ep, ebuf, gettext(
					    "No IPv4 source address "
					    "for name %s.\n"), srchp->h_name);
					if (last_dst) {
						FATAL(ep, ebuf, gettext(
						    "No match for destination "
						    "IP address.\n"));
					} else {
						/* Continue, but do I print? */
						continue;  /* for loop */
					}

					/* I should never reach here. */
				}

				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = htons(srcport);
				if (*walker != NULL) {
					/*
					 * Early loop exit.  It must've been
					 * multiple hits...
					 *
					 * Issue a null-source warning?
					 */
					WARN1(ep, ebuf, gettext(
					    "Multiple IPv4 source addresses "
					    "for %s, using unspecified source "
					    "instead."), srchp->h_name);
				} else {
					/*
					 * If I reach here w/o hitting the
					 * previous if statements, I have a
					 * single source address for this
					 * destination.
					 */
					bcopy(first_match, &sin6->sin6_addr,
					    sizeof (struct in6_addr));
				}
			} else {
				/*
				 * IPv6 address.  Find an IPv6 address.
				 * Unlike IPv4 addresses, things can get a
				 * little more sticky with scopes, etc.
				 */
				int dst_scope, src_scope;

				dst_scope = ipv6_addr_scope(&sin6->sin6_addr);

				first_match = NULL;
				for (walker = srchp->h_addr_list;
				    *walker != NULL; walker++) {
					/* LINTED E_BAD_PTR_CAST_ALIGN */
					if (!IN6_IS_ADDR_V4MAPPED(
					    (struct in6_addr *)*walker)) {
						/*
						 * Set first-match, etc.
						 * Take into account scopes,
						 * and other IPv6 thingies.
						 */
						src_scope = ipv6_addr_scope(
						    /* LINTED E_BAD_PTR_CAST */
						    (struct in6_addr *)*walker);
						if (src_scope == SCOPE_UNSPEC ||
						    src_scope == dst_scope) {
							if (first_match !=
							    NULL)
								break;
							else
								first_match =
								    *walker;
						}
					}
				}

				sin6 = (struct sockaddr_in6 *)(src + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_port = htons(srcport);
				if (first_match == NULL) {
					/*
					 * No IPv6 hits. Is this the last
					 * destination address in the list ?
					 */
					ERROR1(ep, ebuf, gettext(
					    "No IPv6 source address of "
					    "matching scope for name %s.\n"),
					    srchp->h_name);
					if (last_dst) {
						FATAL(ep, ebuf, gettext(
						    "No match for IPV6 "
						    "destination "
						    "address.\n"));
					} else {
						/* Continue, but do I print? */
						continue;  /* for loop */
					}

					/* I should never reach here. */
				}
				sin6->sin6_family = AF_INET6;
				if (*walker != NULL) {
					/*
					 * Early loop exit.  Issue a
					 * null-source warning?
					 */
					WARN1(ep, ebuf, gettext(
					    "Multiple IPv6 source addresses "
					    "for %s of the same scope, using "
					    "unspecified source instead.\n"),
					    srchp->h_name);
				} else {
					/*
					 * If I reach here w/o hitting the
					 * previous if statements, I have a
					 * single source address for this
					 * destination.
					 */
					bcopy(first_match, &sin6->sin6_addr,
					    sizeof (struct in6_addr));
				}
			}
		}

		/*
		 * If there are errors at this point there is no
		 * point sending anything to PF_KEY.
		 */
		handle_errors(ep, ebuf, B_TRUE, B_FALSE);

		/* Save off a copy for later writing... */
		msgp = (struct sadb_msg *)buffer;
		bcopy(buffer, savebuf, SADB_64TO8(msgp->sadb_msg_len));

		rc = key_write(keysock, buffer, SADB_64TO8(msgp->sadb_msg_len));
		if (rc == -1)
			Bail("write() to PF_KEY socket (in doaddresses)");

		if (in_cluster_mode) {
			(void) sendto(cluster_socket, buffer,
			    SADB_64TO8(msgp->sadb_msg_len), 0,
			    (struct sockaddr *)&cli_addr,
			    sizeof (cli_addr));
		}
		/* Blank the key for paranoia's sake. */
		bzero(buffer, buffer_size);
		time_critical_enter();
		do {
			rc = read(keysock, buffer, buffer_size);
			if (rc == -1)
				Bail("read (in doaddresses)");
		} while (msgp->sadb_msg_seq != seq ||
		    msgp->sadb_msg_pid != mypid);
		time_critical_exit();

		/*
		 * I should _never_ hit the following unless:
		 *
		 * 1. There is a kernel bug.
		 * 2. Another process is mistakenly using my pid in a PF_KEY
		 *    message.
		 */
		if (msgp->sadb_msg_type != sadb_msg_type ||
		    msgp->sadb_msg_satype != sadb_msg_satype) {
			syslog((LOG_NOTICE|LOG_AUTH), gettext(
			    "doaddresses: Unexpected returned message "
			    "(%d exp %d)\n"), msgp->sadb_msg_type,
			    sadb_msg_type);
			Bail("doaddresses: Unexpected returned message");
		}

		if (msgp->sadb_msg_errno != 0) {
			char addrprint[INET6_ADDRSTRLEN];
			int on_errno = 0;
			char *on_errno_msg;

			/*
			 * Print different error messages depending
			 * on the SADB message type being processed.
			 * If we get a ESRCH error for a GET/DELETE
			 * messages, we report that the SA does not
			 * exist. If we get a EEXIST error for a
			 * ADD/UPDATE message, we report that the
			 * SA already exists.
			 */
			if (sadb_msg_type == SADB_GET ||
			    sadb_msg_type == SADB_DELETE) {
				on_errno = ESRCH;
				on_errno_msg = "does not exist";
			} else if (sadb_msg_type == SADB_ADD ||
			    sadb_msg_type == SADB_UPDATE) {
				on_errno = EEXIST;
				on_errno_msg = "already exists";
			}

			errno = msgp->sadb_msg_errno;
			if (errno == on_errno) {
				ERROR2(ep, ebuf, gettext(
				    "Association (type = %s) "
				    "with spi 0x%x and addr\n"),
				    rparsesatype(msgp->sadb_msg_satype),
				    ntohl(spi));
				ERROR2(ep, ebuf, "%s %s.\n",
				    do_inet_ntop(dsthp->h_addr_list[i],
				    addrprint, sizeof (addrprint)),
				    on_errno_msg);
				msgp = (struct sadb_msg *)savebuf;
				bcopy(savebuf, buffer,
				    SADB_64TO8(msgp->sadb_msg_len));
				continue;
			} else {
				if (errno == EINVAL || errno == ESRCH) {
					ERROR2(ep, ebuf, gettext(
					    "PF_KEY Diagnostic code %u: %s.\n"),
					    msgp->sadb_x_msg_diagnostic,
					    keysock_diag(
					    msgp->sadb_x_msg_diagnostic));
				} else {
					Bail("return message (in doaddresses)");
				}
			}
		}

		if (cmd == CMD_GET) {
			if (msgp->sadb_msg_len > MAX_GET_SIZE) {
				WARN1(ep, ebuf, gettext("WARNING:  "
				    "SA information bigger than %d bytes.\n"),
				    SADB_64TO8(MAX_GET_SIZE));
			}
			print_samsg(stdout, buffer, B_FALSE, vflag, nflag);
		}

		handle_errors(ep, ebuf, B_TRUE, B_FALSE);

		/* ...and then restore the saved buffer. */
		msgp = (struct sadb_msg *)savebuf;
		bcopy(savebuf, buffer, SADB_64TO8(msgp->sadb_msg_len));
		lines_added++;
	}

	/* Degenerate case, h_addr_list[0] == NULL. */
	if (i == 0)
		Bail("Empty destination address list");

	/*
	 * free(ebuf) even if there are no errors.
	 * handle_errors() won't return here.
	 */
	handle_errors(ep, ebuf, B_TRUE, B_TRUE);
}

/*
 * Perform an add or an update.  ADD and UPDATE are similar in the extensions
 * they need.
 */
static void
doaddup(int cmd, int satype, char *argv[], char *ebuf)
{
	uint64_t *buffer, *nexthdr;
	struct sadb_msg msg;
	struct sadb_sa *assoc = NULL;
	struct sadb_x_pair *sadb_pair = NULL;
	struct sadb_address *src = NULL, *dst = NULL;
	struct sadb_address *isrc = NULL, *idst = NULL;
	struct sadb_address *natt_local = NULL, *natt_remote = NULL;
	struct sadb_key *encrypt = NULL, *auth = NULL;
	struct sadb_ident *srcid = NULL, *dstid = NULL;
	struct sadb_lifetime *hard = NULL, *soft = NULL;  /* Current? */
	struct sadb_lifetime *idle = NULL;
	struct sadb_x_replay_ctr *replay_ctr = NULL;
	struct sadb_sens *label = NULL, *olabel = NULL;
	struct sockaddr_in6 *sin6;
	/* MLS TODO:  Need sensitivity eventually. */
	int next, token, sa_len, alloclen, totallen = sizeof (msg), prefix;
	uint32_t spi = 0;
	uint_t reserved_bits = 0;
	uint8_t	sadb_msg_type;
	char *thiscmd, *pstr;
	boolean_t readstate = B_FALSE, unspec_src = B_FALSE;
	boolean_t alloc_inner = B_FALSE, use_natt = B_FALSE;
	struct hostent *srchp = NULL, *dsthp = NULL, *isrchp = NULL,
	    *idsthp = NULL;
	struct hostent *natt_lhp = NULL, *natt_rhp = NULL;
	uint16_t srcport = 0, dstport = 0, natt_lport = 0, natt_rport = 0,
	    isrcport = 0, idstport = 0;
	uint8_t proto = 0, iproto = 0;
	char *ep = NULL;

	switch (cmd) {
	case CMD_ADD:
		thiscmd = "add";
		sadb_msg_type = SADB_ADD;
		break;
	case CMD_UPDATE:
		thiscmd = "update";
		sadb_msg_type = SADB_UPDATE;
		break;
	case CMD_UPDATE_PAIR:
		thiscmd = "update-pair";
		sadb_msg_type = SADB_X_UPDATEPAIR;
		break;
	}

	msg_init(&msg, sadb_msg_type, (uint8_t)satype);
	/* Assume last element in argv is set to NULL. */
	do {
		token = parseextval(*argv, &next);
		argv++;
		switch (token) {
		case TOK_EOF:
			/* Do nothing, I'm done. */
			break;
		case TOK_UNKNOWN:
			ERROR1(ep, ebuf, gettext(
			    "Unknown extension field \"%s\" \n"), *(argv - 1));
			break;
		case TOK_SPI:
		case TOK_PAIR_SPI:
		case TOK_REPLAY:
		case TOK_STATE:
		case TOK_AUTHALG:
		case TOK_ENCRALG:
		case TOK_ENCAP:
			/*
			 * May want to place this chunk of code in a function.
			 *
			 * This code checks for duplicate entries on a command
			 * line.
			 */

			/* Allocate the SADB_EXT_SA extension. */
			if (assoc == NULL) {
				assoc = malloc(sizeof (*assoc));
				if (assoc == NULL)
					Bail("malloc(assoc)");
				bzero(assoc, sizeof (*assoc));
				assoc->sadb_sa_exttype = SADB_EXT_SA;
				assoc->sadb_sa_len =
				    SADB_8TO64(sizeof (*assoc));
				totallen += sizeof (*assoc);
			}
			switch (token) {
			case TOK_SPI:
				/*
				 * If some cretin types in "spi 0" then they
				 * can type in another SPI.
				 */
				if (assoc->sadb_sa_spi != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single SPI value.\n"));
					break;
				}
				/* Must convert SPI to network order! */
				assoc->sadb_sa_spi =
				    htonl((uint32_t)parsenum(*argv, B_TRUE,
				    ebuf));
				if (assoc->sadb_sa_spi == 0) {
					ERROR(ep, ebuf, gettext(
					    "Invalid SPI value \"0\" .\n"));
				}
				break;
			case TOK_PAIR_SPI:
				if (cmd == CMD_UPDATE_PAIR) {
					ERROR(ep, ebuf, gettext(
					    "pair-spi can not be used with the "
					    "\"update-pair\" command.\n"));
				}
				if (sadb_pair == NULL) {
					sadb_pair = malloc(sizeof (*sadb_pair));
					if (assoc == NULL)
						Bail("malloc(assoc)");
					bzero(sadb_pair, sizeof (*sadb_pair));
					totallen += sizeof (*sadb_pair);
				}
				if (sadb_pair->sadb_x_pair_spi != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single pair SPI value.\n"));
					break;
				}
				/* Must convert SPI to network order! */
				sadb_pair->sadb_x_pair_len =
				    SADB_8TO64(sizeof (*sadb_pair));
				sadb_pair->sadb_x_pair_exttype =
				    SADB_X_EXT_PAIR;
				sadb_pair->sadb_x_pair_spi =
				    htonl((uint32_t)parsenum(*argv, B_TRUE,
				    ebuf));
				if (sadb_pair->sadb_x_pair_spi == 0) {
					ERROR(ep, ebuf, gettext(
					    "Invalid SPI value \"0\" .\n"));
				}
				assoc->sadb_sa_flags |=
				    SADB_X_SAFLAGS_PAIRED;
				break;
			case TOK_REPLAY:
				/*
				 * That same cretin can do the same with
				 * replay.
				 */
				if (assoc->sadb_sa_replay != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single replay window size.\n"));
					break;
				}
				assoc->sadb_sa_replay =
				    (uint8_t)parsenum(*argv, B_TRUE, ebuf);
				if (assoc->sadb_sa_replay != 0) {
					WARN(ep, ebuf, gettext(
					    "WARNING:  Replay with manual"
					    " keying considered harmful.\n"));
				}
				break;
			case TOK_STATE:
				/*
				 * 0 is an actual state value, LARVAL.  This
				 * means that one can type in the larval state
				 * and then type in another state on the same
				 * command line.
				 */
				if (assoc->sadb_sa_state != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single SA state.\n"));
					break;
				}
				assoc->sadb_sa_state = parsestate(*argv,
				    ebuf);
				readstate = B_TRUE;
				break;
			case TOK_AUTHALG:
				if (assoc->sadb_sa_auth != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single auth algorithm.\n"));
					break;
				}
				assoc->sadb_sa_auth = parsealg(*argv,
				    IPSEC_PROTO_AH, ebuf);
				break;
			case TOK_ENCRALG:
				if (satype == SADB_SATYPE_AH) {
					ERROR(ep, ebuf, gettext("Cannot specify"
					    " encryption with SA type ah.\n"));
					break;
				}
				if (assoc->sadb_sa_encrypt != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single encryption algorithm.\n"));
					break;
				}
				assoc->sadb_sa_encrypt = parsealg(*argv,
				    IPSEC_PROTO_ESP, ebuf);
				break;
			case TOK_ENCAP:
				if (use_natt) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify single"
					    " encapsulation.\n"));
					break;
				}
				if (strncmp(*argv, "udp", 3)) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify udp"
					    " encapsulation.\n"));
					break;
				}
				use_natt = B_TRUE;
				/* set assoc flags later */
				break;
			}
			argv++;
			break;
		case TOK_SRCPORT:
			if (srcport != 0) {
				ERROR(ep, ebuf,  gettext("Can only specify "
				    "single source port.\n"));
				break;
			}
			srcport = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_DSTPORT:
			if (dstport != 0) {
				ERROR(ep, ebuf, gettext("Can only specify "
				    "single destination port.\n"));
				break;
			}
			dstport = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_ISRCPORT:
			alloc_inner = B_TRUE;
			if (isrcport != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single inner-source port.\n"));
				break;
			}
			isrcport = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_IDSTPORT:
			alloc_inner = B_TRUE;
			if (idstport != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single inner-destination port.\n"));
				break;
			}
			idstport = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_NATLPORT:
			if (natt_lport != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single NAT-T local port.\n"));
				break;
			}
			natt_lport = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_NATRPORT:
			if (natt_rport != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single NAT-T remote port.\n"));
				break;
			}
			natt_rport = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;

		case TOK_PROTO:
			if (proto != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single protocol.\n"));
				break;
			}
			proto = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_IPROTO:
			alloc_inner = B_TRUE;
			if (iproto != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single inner protocol.\n"));
				break;
			}
			iproto = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_SRCADDR:
		case TOK_SRCADDR6:
			if (src != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single source address.\n"));
				break;
			}
			sa_len = parseaddr(*argv, &srchp,
			    (token == TOK_SRCADDR6), ebuf);
			if (srchp == NULL) {
				ERROR1(ep, ebuf, gettext(
				    "Unknown src address \"%s\"\n"), *argv);
				break;
			}
			argv++;
			/*
			 * Round of the sockaddr length to an 8 byte
			 * boundary to make PF_KEY happy.
			 */
			alloclen = sizeof (*src) + roundup(sa_len, 8);
			src = malloc(alloclen);
			if (src == NULL)
				Bail("malloc(src)");
			totallen += alloclen;
			src->sadb_address_len = SADB_8TO64(alloclen);
			src->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
			src->sadb_address_reserved = 0;
			src->sadb_address_prefixlen = 0;
			src->sadb_address_proto = 0;
			if (srchp == &dummy.he) {
				/*
				 * Single address with -n flag.
				 */
				sin6 = (struct sockaddr_in6 *)(src + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(srchp->h_addr_list[0], &sin6->sin6_addr,
				    sizeof (struct in6_addr));
			}
			break;
		case TOK_DSTADDR:
		case TOK_DSTADDR6:
			if (dst != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single "
				    "destination address.\n"));
				break;
			}
			sa_len = parseaddr(*argv, &dsthp,
			    (token == TOK_DSTADDR6), ebuf);
			if (dsthp == NULL) {
				ERROR1(ep, ebuf, gettext(
				    "Unknown dst address \"%s\"\n"), *argv);
				break;
			}
			argv++;
			alloclen = sizeof (*dst) + roundup(sa_len, 8);
			dst = malloc(alloclen);
			if (dst == NULL)
				Bail("malloc(dst)");
			totallen += alloclen;
			dst->sadb_address_len = SADB_8TO64(alloclen);
			dst->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
			dst->sadb_address_reserved = 0;
			dst->sadb_address_prefixlen = 0;
			dst->sadb_address_proto = 0;
			if (dsthp == &dummy.he) {
				/*
				 * Single address with -n flag.
				 */
				sin6 = (struct sockaddr_in6 *)(dst + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(dsthp->h_addr_list[0], &sin6->sin6_addr,
				    sizeof (struct in6_addr));
			}
			break;
		case TOK_PROXYADDR:
		case TOK_PROXYADDR6:
			if (isrc != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single "
				    "proxy/inner-source address.\n"));
				break;
			}
			if ((pstr = strchr(*argv, '/')) != NULL) {
				/* Parse out the prefix. */
				errno = 0;
				prefix = strtol(pstr + 1, NULL, 10);
				if (errno != 0) {
					ERROR1(ep, ebuf, gettext(
					    "Invalid prefix %s."), pstr);
					break;
				}
				/* Recycle pstr */
				alloclen = (int)(pstr - *argv);
				pstr = malloc(alloclen + 1);
				if (pstr == NULL) {
					Bail("malloc(pstr)");
				}
				(void) strlcpy(pstr, *argv, alloclen + 1);
			} else {
				pstr = *argv;
				/*
				 * Assume mapping to AF_INET6, and we're a host.
				 * XXX some miscreants may still make classful
				 * assumptions.  If this is a problem, fix it
				 * here.
				 */
				prefix = 128;
			}
			sa_len = parseaddr(pstr, &isrchp,
			    (token == TOK_PROXYADDR6), ebuf);
			if (isrchp == NULL) {
				ERROR1(ep, ebuf, gettext(
				    "Unknown proxy/inner-source address "
				    "\"%s\"\n"), *argv);
				break;
			}
			if (pstr != *argv)
				free(pstr);
			argv++;
			alloclen = sizeof (*isrc) + roundup(sa_len, 8);
			isrc = malloc(alloclen);
			if (isrc == NULL)
				Bail("malloc(isrc)");
			totallen += alloclen;
			isrc->sadb_address_len = SADB_8TO64(alloclen);
			isrc->sadb_address_exttype = SADB_EXT_ADDRESS_PROXY;
			isrc->sadb_address_reserved = 0;
			isrc->sadb_address_prefixlen = prefix;
			isrc->sadb_address_proto = 0;
			if (isrchp == &dummy.he ||
			    isrchp->h_addr_list[1] == NULL) {
				/*
				 * Single address with -n flag or single name.
				 */
				sin6 = (struct sockaddr_in6 *)(isrc + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(isrchp->h_addr_list[0], &sin6->sin6_addr,
				    sizeof (struct in6_addr));
				/*
				 * normalize prefixlen for IPv4-mapped
				 * addresses.
				 */
				if (prefix <= 32 &&
				    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
					isrc->sadb_address_prefixlen += 96;
				alloc_inner = B_TRUE;
			} else {
				/*
				 * If the proxy/isrc address is vague, don't
				 * bother.
				 */
				totallen -= alloclen;
				free(isrc);
				isrc = NULL;
				WARN1(ep, ebuf, gettext(
				    "Proxy/inner-source address %s "
				    "is vague, not using.\n"), isrchp->h_name);
				freehostent(isrchp);
				isrchp = NULL;
				break;
			}
			break;
		case TOK_IDSTADDR:
		case TOK_IDSTADDR6:
			if (idst != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single "
				    "inner-destination address.\n"));
				break;
			}
			if ((pstr = strchr(*argv, '/')) != NULL) {
				/* Parse out the prefix. */
				errno = 0;
				prefix = strtol(pstr + 1, NULL, 10);
				if (errno != 0) {
					ERROR1(ep, ebuf, gettext(
					    "Invalid prefix %s.\n"), pstr);
					break;
				}
				/* Recycle pstr */
				alloclen = (int)(pstr - *argv);
				pstr = malloc(alloclen + 1);
				if (pstr == NULL) {
					Bail("malloc(pstr)");
				}
				(void) strlcpy(pstr, *argv, alloclen + 1);
			} else {
				pstr = *argv;
				/*
				 * Assume mapping to AF_INET6, and we're a host.
				 * XXX some miscreants may still make classful
				 * assumptions.  If this is a problem, fix it
				 * here.
				 */
				prefix = 128;
			}
			sa_len = parseaddr(pstr, &idsthp,
			    (token == TOK_IDSTADDR6), ebuf);
			if (idsthp == NULL) {
				ERROR1(ep, ebuf, gettext(
				    "Unknown Inner Src address "
				    " \"%s\"\n"), *argv);
				break;
			}
			if (pstr != *argv)
				free(pstr);
			argv++;
			alloclen = sizeof (*idst) + roundup(sa_len, 8);
			idst = malloc(alloclen);
			if (idst == NULL)
				Bail("malloc(idst)");
			totallen += alloclen;
			idst->sadb_address_len = SADB_8TO64(alloclen);
			idst->sadb_address_exttype =
			    SADB_X_EXT_ADDRESS_INNER_DST;
			idst->sadb_address_reserved = 0;
			idst->sadb_address_prefixlen = prefix;
			idst->sadb_address_proto = 0;
			if (idsthp == &dummy.he ||
			    idsthp->h_addr_list[1] == NULL) {
				/*
				 * Single address with -n flag or single name.
				 */
				sin6 = (struct sockaddr_in6 *)(idst + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(idsthp->h_addr_list[0], &sin6->sin6_addr,
				    sizeof (struct in6_addr));
				/*
				 * normalize prefixlen for IPv4-mapped
				 * addresses.
				 */
				if (prefix <= 32 &&
				    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
					idst->sadb_address_prefixlen += 96;
				alloc_inner = B_TRUE;
			} else {
				/*
				 * If the idst address is vague, don't bother.
				 */
				totallen -= alloclen;
				free(idst);
				idst = NULL;
				WARN1(ep, ebuf, gettext(
				    "Inner destination address %s "
				    "is vague, not using.\n"), idsthp->h_name);
				freehostent(idsthp);
				idsthp = NULL;
				break;
			}
			break;
		case TOK_NATLOC:
			if (natt_local != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single NAT-T local address.\n"));
				break;
			}
			sa_len = parseaddr(*argv, &natt_lhp, 0, ebuf);
			if (natt_lhp == NULL) {
				ERROR1(ep, ebuf, gettext(
				    "Unknown NAT-T local address \"%s\"\n"),
				    *argv);
				break;
			}
			argv++;
			/*
			 * Round of the sockaddr length to an 8 byte
			 * boundary to make PF_KEY happy.
			 */
			alloclen = sizeof (*natt_local) + roundup(sa_len, 8);
			natt_local = malloc(alloclen);
			if (natt_local == NULL)
				Bail("malloc(natt_local)");
			totallen += alloclen;
			natt_local->sadb_address_len = SADB_8TO64(alloclen);
			natt_local->sadb_address_exttype =
			    SADB_X_EXT_ADDRESS_NATT_LOC;
			natt_local->sadb_address_reserved = 0;
			natt_local->sadb_address_prefixlen = 0;
			natt_local->sadb_address_proto = 0;
			if (natt_lhp == &dummy.he ||
			    natt_lhp->h_addr_list[1] == NULL) {
				/*
				 * Single address with -n flag or single name.
				 */
				sin6 = (struct sockaddr_in6 *)(natt_local + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(natt_lhp->h_addr_list[0],
				    &sin6->sin6_addr, sizeof (struct in6_addr));
			} else {
				/*
				 * If the nat-local address is vague, don't
				 * bother.
				 */
				totallen -= alloclen;
				free(natt_local);
				natt_local = NULL;
				WARN1(ep, ebuf, gettext(
				    "NAT-T local address %s "
				    "is vague, not using.\n"),
				    natt_lhp->h_name);
				freehostent(natt_lhp);
				natt_lhp = NULL;
				break;
			}
			break;
		case TOK_NATREM:
			if (natt_remote != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single NAT-T remote address.\n"));
				break;
			}
			sa_len = parseaddr(*argv, &natt_rhp, 0, ebuf);
			if (natt_rhp == NULL) {
				ERROR1(ep, ebuf, gettext(
				    "Unknown NAT-T remote address \"%s\"\n"),
				    *argv);
				break;
			}
			argv++;
			/*
			 * Round of the sockaddr length to an 8 byte
			 * boundary to make PF_KEY happy.
			 */
			alloclen = sizeof (*natt_remote) + roundup(sa_len, 8);
			natt_remote = malloc(alloclen);
			if (natt_remote == NULL)
				Bail("malloc(natt_remote)");
			totallen += alloclen;
			natt_remote->sadb_address_len = SADB_8TO64(alloclen);
			natt_remote->sadb_address_exttype =
			    SADB_X_EXT_ADDRESS_NATT_REM;
			natt_remote->sadb_address_reserved = 0;
			natt_remote->sadb_address_prefixlen = 0;
			natt_remote->sadb_address_proto = 0;
			if (natt_rhp == &dummy.he ||
			    natt_rhp->h_addr_list[1] == NULL) {
				/*
				 * Single address with -n flag or single name.
				 */
				sin6 = (struct sockaddr_in6 *)(natt_remote + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(natt_rhp->h_addr_list[0],
				    &sin6->sin6_addr, sizeof (struct in6_addr));
			} else {
				/*
				 * If the nat-renote address is vague, don't
				 * bother.
				 */
				totallen -= alloclen;
				free(natt_remote);
				natt_remote = NULL;
				WARN1(ep, ebuf, gettext(
				    "NAT-T remote address %s "
				    "is vague, not using.\n"),
				    natt_rhp->h_name);
				freehostent(natt_rhp);
				natt_rhp = NULL;
				break;
			}
			break;
		case TOK_ENCRKEY:
			if (encrypt != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify "
				    "single encryption key.\n"));
				break;
			}
			if (assoc != NULL &&
			    assoc->sadb_sa_encrypt == SADB_EALG_NULL) {
				FATAL(ep, ebuf, gettext(
				    "Cannot specify a key with NULL "
				    "encryption algorithm.\n"));
				break;
			}
			encrypt = parsekey(*argv, ebuf, reserved_bits);
			argv++;
			if (encrypt == NULL) {
				ERROR(ep, ebuf, gettext(
				    "Invalid encryption key.\n"));
				break;
			}
			totallen += SADB_64TO8(encrypt->sadb_key_len);
			encrypt->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
			break;
		case TOK_AUTHKEY:
			if (auth != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single"
				    " authentication key.\n"));
				break;
			}
			auth = parsekey(*argv, ebuf, 0);
			argv++;
			if (auth == NULL) {
				ERROR(ep, ebuf, gettext(
				    "Invalid authentication key.\n"));
				break;
			}
			totallen += SADB_64TO8(auth->sadb_key_len);
			auth->sadb_key_exttype = SADB_EXT_KEY_AUTH;
			break;
		case TOK_SRCIDTYPE:
			if (*argv == NULL || *(argv + 1) == NULL) {
				FATAL(ep, ebuf, gettext(
				    "Unexpected end of command "
				    "line - Expecting Src Type.\n"));
				/* NOTREACHED */
				break;
			}
			if (srcid != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single"
				    " source certificate identity.\n"));
				break;
			}
			alloclen = sizeof (*srcid) +
			    roundup(strlen(*(argv + 1)) + 1, 8);
			srcid = malloc(alloclen);
			if (srcid == NULL)
				Bail("malloc(srcid)");
			totallen += alloclen;
			srcid->sadb_ident_type = parseidtype(*argv, ebuf);
			argv++;
			srcid->sadb_ident_len = SADB_8TO64(alloclen);
			srcid->sadb_ident_exttype = SADB_EXT_IDENTITY_SRC;
			srcid->sadb_ident_reserved = 0;
			srcid->sadb_ident_id = 0;  /* Not useful here. */
			(void) strlcpy((char *)(srcid + 1), *argv, alloclen);
			argv++;
			break;
		case TOK_DSTIDTYPE:
			if (*argv == NULL || *(argv + 1) == NULL) {
				ERROR(ep, ebuf, gettext(
				    "Unexpected end of command"
				    " line - expecting dst type.\n"));
				break;
			}
			if (dstid != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single destination "
				    "certificate identity.\n"));
				break;
			}
			alloclen = sizeof (*dstid) +
			    roundup(strlen(*(argv + 1)) + 1, 8);
			dstid = malloc(alloclen);
			if (dstid == NULL)
				Bail("malloc(dstid)");
			totallen += alloclen;
			dstid->sadb_ident_type = parseidtype(*argv, ebuf);
			argv++;
			dstid->sadb_ident_len = SADB_8TO64(alloclen);
			dstid->sadb_ident_exttype = SADB_EXT_IDENTITY_DST;
			dstid->sadb_ident_reserved = 0;
			dstid->sadb_ident_id = 0;  /* Not useful here. */
			(void) strlcpy((char *)(dstid + 1), *argv, alloclen);
			argv++;
			break;
		case TOK_HARD_ALLOC:
		case TOK_HARD_BYTES:
		case TOK_HARD_ADDTIME:
		case TOK_HARD_USETIME:
			if (hard == NULL) {
				hard = malloc(sizeof (*hard));
				if (hard == NULL)
					Bail("malloc(hard_lifetime)");
				bzero(hard, sizeof (*hard));
				hard->sadb_lifetime_exttype =
				    SADB_EXT_LIFETIME_HARD;
				hard->sadb_lifetime_len =
				    SADB_8TO64(sizeof (*hard));
				totallen += sizeof (*hard);
			}
			switch (token) {
			case TOK_HARD_ALLOC:
				if (hard->sadb_lifetime_allocations != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify single"
					    " hard allocation limit.\n"));
					break;
				}
				hard->sadb_lifetime_allocations =
				    (uint32_t)parsenum(*argv, B_TRUE, ebuf);
				break;
			case TOK_HARD_BYTES:
				if (hard->sadb_lifetime_bytes != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single hard byte limit.\n"));
					break;
				}
				hard->sadb_lifetime_bytes = parsenum(*argv,
				    B_TRUE, ebuf);
				break;
			case TOK_HARD_ADDTIME:
				if (hard->sadb_lifetime_addtime != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single past-add lifetime.\n"));
					break;
				}
				hard->sadb_lifetime_addtime = parsenum(*argv,
				    B_TRUE, ebuf);
				break;
			case TOK_HARD_USETIME:
				if (hard->sadb_lifetime_usetime != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify "
					    "single past-use lifetime.\n"));
					break;
				}
				hard->sadb_lifetime_usetime = parsenum(*argv,
				    B_TRUE, ebuf);
				break;
			}
			argv++;
			break;
		case TOK_SOFT_ALLOC:
		case TOK_SOFT_BYTES:
		case TOK_SOFT_ADDTIME:
		case TOK_SOFT_USETIME:
			if (soft == NULL) {
				soft = malloc(sizeof (*soft));
				if (soft == NULL)
					Bail("malloc(soft_lifetime)");
				bzero(soft, sizeof (*soft));
				soft->sadb_lifetime_exttype =
				    SADB_EXT_LIFETIME_SOFT;
				soft->sadb_lifetime_len =
				    SADB_8TO64(sizeof (*soft));
				totallen += sizeof (*soft);
			}
			switch (token) {
			case TOK_SOFT_ALLOC:
				if (soft->sadb_lifetime_allocations != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify single"
					    " soft allocation limit.\n"));
					break;
				}
				soft->sadb_lifetime_allocations =
				    (uint32_t)parsenum(*argv, B_TRUE, ebuf);
				break;
			case TOK_SOFT_BYTES:
				if (soft->sadb_lifetime_bytes != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify single"
					    " soft byte limit.\n"));
					break;
				}
				soft->sadb_lifetime_bytes = parsenum(*argv,
				    B_TRUE, ebuf);
				break;
			case TOK_SOFT_ADDTIME:
				if (soft->sadb_lifetime_addtime != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify single"
					    " past-add lifetime.\n"));
					break;
				}
				soft->sadb_lifetime_addtime = parsenum(*argv,
				    B_TRUE, ebuf);
				break;
			case TOK_SOFT_USETIME:
				if (soft->sadb_lifetime_usetime != 0) {
					ERROR(ep, ebuf, gettext(
					    "Can only specify single"
					    " past-use lifetime.\n"));
					break;
				}
				soft->sadb_lifetime_usetime = parsenum(*argv,
				    B_TRUE, ebuf);
				break;
			}
			argv++;
			break;
		case TOK_FLAG_INBOUND:
			assoc->sadb_sa_flags |= SADB_X_SAFLAGS_INBOUND;
			break;
		case TOK_FLAG_OUTBOUND:
			assoc->sadb_sa_flags |= SADB_X_SAFLAGS_OUTBOUND;
			break;
		case TOK_REPLAY_VALUE:
			if (replay_ctr != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single "
				    "replay value."));
				break;
			}
			replay_ctr = calloc(1, sizeof (*replay_ctr));
			if (replay_ctr == NULL) {
				Bail("malloc(replay value)");
			}
			/*
			 * We currently do not support a 64-bit
			 * replay value.  RFC 4301 will require one,
			 * however, and we have a field in place when
			 * 4301 is built.
			 */
			replay_ctr->sadb_x_rc_exttype = SADB_X_EXT_REPLAY_VALUE;
			replay_ctr->sadb_x_rc_len =
			    SADB_8TO64(sizeof (*replay_ctr));
			totallen += sizeof (*replay_ctr);
			replay_ctr->sadb_x_rc_replay32 = (uint32_t)parsenum(
			    *argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_IDLE_ADDTIME:
		case TOK_IDLE_USETIME:
			if (idle == NULL) {
				idle = calloc(1, sizeof (*idle));
				if (idle == NULL) {
					Bail("malloc idle lifetime");
				}
				idle->sadb_lifetime_exttype =
				    SADB_X_EXT_LIFETIME_IDLE;
				idle->sadb_lifetime_len =
				    SADB_8TO64(sizeof (*idle));
				totallen += sizeof (*idle);
			}
			switch (token) {
			case TOK_IDLE_ADDTIME:
				idle->sadb_lifetime_addtime =
				    (uint32_t)parsenum(*argv,
				    B_TRUE, ebuf);
				break;
			case TOK_IDLE_USETIME:
				idle->sadb_lifetime_usetime =
				    (uint32_t)parsenum(*argv,
				    B_TRUE, ebuf);
				break;
			}
			argv++;
			break;
		case TOK_RESERVED:
			if (encrypt != NULL)
				ERROR(ep, ebuf, gettext(
				    "Reserved bits need to be "
				    "specified before key.\n"));
			reserved_bits = (uint_t)parsenum(*argv,
			    B_TRUE, ebuf);
			argv++;
			break;
		case TOK_LABEL:
			label = parselabel(token, *argv);
			argv++;
			if (label == NULL) {
				ERROR(ep, ebuf,
				    gettext("Malformed security label\n"));
				break;
			} else if (label == PARSELABEL_BAD_TOKEN) {
				Bail("Internal token value error");
			}
			totallen += SADB_64TO8(label->sadb_sens_len);
			break;

		case TOK_OLABEL:
		case TOK_IMPLABEL:
			olabel = parselabel(token, *argv);
			argv++;
			if (label == NULL) {
				ERROR(ep, ebuf,
				    gettext("Malformed security label\n"));
				break;
			} else if (label == PARSELABEL_BAD_TOKEN) {
				Bail("Internal token value error");
			}
			totallen += SADB_64TO8(olabel->sadb_sens_len);
			break;
		default:
			ERROR1(ep, ebuf, gettext(
			    "Don't use extension %s for add/update.\n"),
			    *(argv - 1));
			break;
		}
	} while (token != TOK_EOF);

	handle_errors(ep, ebuf, B_TRUE, B_FALSE);

#define	PORT_ONLY_ALLOCATE(af, socktype, exttype, extvar, port) {  \
	alloclen = sizeof (sadb_address_t) + roundup(sizeof (socktype), 8); \
	(extvar) = calloc(1, alloclen); \
	if ((extvar) == NULL) { \
		Bail("malloc(implicit port)"); \
	} \
	totallen += alloclen; \
	(extvar)->sadb_address_len = SADB_8TO64(alloclen); \
	(extvar)->sadb_address_exttype = (exttype); \
	/* sin/sin6 has equivalent offsets for ports! */ \
	sin6 = (struct sockaddr_in6 *)((extvar) + 1); \
	sin6->sin6_family = (af); \
	sin6->sin6_port = (port); \
	}

	/*
	 * If we specify inner ports or NAT ports w/o addresses, we still need
	 * to allocate.  Also, if we have one inner address, we need the
	 * other, even if we don't specify anything.
	 */
	if (use_natt) {
		if (natt_lport != 0 && natt_local == NULL) {
			PORT_ONLY_ALLOCATE(AF_INET, struct sockaddr_in,
			    SADB_X_EXT_ADDRESS_NATT_LOC, natt_local,
			    natt_lport);
		}

		if (natt_rport != 0 && natt_remote == NULL) {
			PORT_ONLY_ALLOCATE(AF_INET, struct sockaddr_in,
			    SADB_X_EXT_ADDRESS_NATT_REM, natt_remote,
			    natt_rport);
		}
	} else {
		if (natt_lport != 0 || natt_rport != 0) {
			ERROR(ep, ebuf, gettext("Must specify 'encap udp' "
			    "with any NAT-T port.\n"));
		} else if (natt_local != NULL || natt_remote != NULL) {
			ERROR(ep, ebuf, gettext("Must specify 'encap udp' "
			    "with any NAT-T address.\n"));
		}
	}

	if (alloc_inner && idst == NULL) {
		PORT_ONLY_ALLOCATE(AF_INET6, struct sockaddr_in6,
		    SADB_X_EXT_ADDRESS_INNER_DST, idst, 0);
	}

	if (alloc_inner && isrc == NULL) {
		PORT_ONLY_ALLOCATE(AF_INET6, struct sockaddr_in6,
		    SADB_X_EXT_ADDRESS_INNER_SRC, isrc, 0);
	}
#undef PORT_ONLY_ALLOCATE

	/*
	 * Okay, so now I have all of the potential extensions!
	 * Allocate a single contiguous buffer.  Keep in mind that it'll
	 * be enough because the key itself will be yanked.
	 */

	if (src == NULL && dst != NULL) {
		/*
		 * Set explicit unspecified source address.
		 */
		size_t lenbytes = SADB_64TO8(dst->sadb_address_len);

		unspec_src = B_TRUE;
		totallen += lenbytes;
		src = malloc(lenbytes);
		if (src == NULL)
			Bail("malloc(implicit src)");
		/* Confusing, but we're copying from DST to SRC.  :) */
		bcopy(dst, src, lenbytes);
		src->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
		sin6 = (struct sockaddr_in6 *)(src + 1);
		bzero(sin6, sizeof (*sin6));
		sin6->sin6_family = AF_INET6;
	}

	msg.sadb_msg_len = SADB_8TO64(totallen);

	buffer = malloc(totallen);
	nexthdr = buffer;
	bcopy(&msg, nexthdr, sizeof (msg));
	nexthdr += SADB_8TO64(sizeof (msg));
	if (assoc != NULL) {
		if (assoc->sadb_sa_spi == 0) {
			ERROR1(ep, ebuf, gettext(
			    "The SPI value is missing for "
			    "the association you wish to %s.\n"), thiscmd);
		}
		if (assoc->sadb_sa_auth == 0 && assoc->sadb_sa_encrypt == 0 &&
		    cmd == CMD_ADD) {
			free(assoc);
			FATAL(ep, ebuf, gettext(
			    "Select at least one algorithm "
			    "for this add.\n"));
		}

		/* Hack to let user specify NULL ESP implicitly. */
		if (msg.sadb_msg_satype == SADB_SATYPE_ESP &&
		    assoc->sadb_sa_encrypt == 0)
			assoc->sadb_sa_encrypt = SADB_EALG_NULL;

		/* 0 is an actual value.  Print a warning if it was entered. */
		if (assoc->sadb_sa_state == 0) {
			if (readstate) {
				ERROR(ep, ebuf, gettext(
				    "WARNING: Cannot set LARVAL SA state.\n"));
			}
			assoc->sadb_sa_state = SADB_SASTATE_MATURE;
		}

		if (use_natt) {
			if (natt_remote != NULL)
				assoc->sadb_sa_flags |= SADB_X_SAFLAGS_NATT_REM;
			if (natt_local != NULL)
				assoc->sadb_sa_flags |= SADB_X_SAFLAGS_NATT_LOC;
		}

		if (alloc_inner) {
			/*
			 * For now, assume RFC 3884's dream of transport-mode
			 * SAs with inner IP address selectors will not
			 * happen.
			 */
			assoc->sadb_sa_flags |= SADB_X_SAFLAGS_TUNNEL;
			if (proto != 0 && proto != IPPROTO_ENCAP &&
			    proto != IPPROTO_IPV6) {
				ERROR1(ep, ebuf, gettext(
				    "WARNING: Protocol type %d not "
				    "for use with Tunnel-Mode SA.\n"), proto);
				/* Continue and let PF_KEY scream... */
			}
		}

		bcopy(assoc, nexthdr, SADB_64TO8(assoc->sadb_sa_len));
		nexthdr += assoc->sadb_sa_len;
		/* Save the SPI for the case of an error. */
		spi = assoc->sadb_sa_spi;
		free(assoc);
	} else {
		if (spi == 0)
			ERROR1(ep, ebuf, gettext(
			    "Need to define SPI for %s.\n"), thiscmd);
		ERROR1(ep, ebuf, gettext(
		    "Need SA parameters for %s.\n"), thiscmd);
	}

	if (sadb_pair != NULL) {
		if (sadb_pair->sadb_x_pair_spi == 0) {
			ERROR1(ep, ebuf, gettext(
			    "The SPI value is missing for the "
			    "association you wish to %s.\n"), thiscmd);
		}
		bcopy(sadb_pair, nexthdr,
		    SADB_64TO8(sadb_pair->sadb_x_pair_len));
		nexthdr += sadb_pair->sadb_x_pair_len;
		free(sadb_pair);
	}

	if (hard != NULL) {
		bcopy(hard, nexthdr, SADB_64TO8(hard->sadb_lifetime_len));
		nexthdr += hard->sadb_lifetime_len;
		free(hard);
	}

	if (soft != NULL) {
		bcopy(soft, nexthdr, SADB_64TO8(soft->sadb_lifetime_len));
		nexthdr += soft->sadb_lifetime_len;
		free(soft);
	}

	if (idle != NULL) {
		bcopy(idle, nexthdr, SADB_64TO8(idle->sadb_lifetime_len));
		nexthdr += idle->sadb_lifetime_len;
		free(idle);
	}

	if (encrypt == NULL && auth == NULL && cmd == CMD_ADD) {
		ERROR(ep, ebuf, gettext(
		    "Must have at least one key for an add.\n"));
	}

	if (encrypt != NULL) {
		bcopy(encrypt, nexthdr, SADB_64TO8(encrypt->sadb_key_len));
		nexthdr += encrypt->sadb_key_len;
		bzero(encrypt, SADB_64TO8(encrypt->sadb_key_len));
		free(encrypt);
	}

	if (auth != NULL) {
		bcopy(auth, nexthdr, SADB_64TO8(auth->sadb_key_len));
		nexthdr += auth->sadb_key_len;
		bzero(auth, SADB_64TO8(auth->sadb_key_len));
		free(auth);
	}

	if (srcid != NULL) {
		bcopy(srcid, nexthdr, SADB_64TO8(srcid->sadb_ident_len));
		nexthdr += srcid->sadb_ident_len;
		free(srcid);
	}

	if (dstid != NULL) {
		bcopy(dstid, nexthdr, SADB_64TO8(dstid->sadb_ident_len));
		nexthdr += dstid->sadb_ident_len;
		free(dstid);
	}

	if (dst != NULL) {
		bcopy(dst, nexthdr, SADB_64TO8(dst->sadb_address_len));
		free(dst);
		dst = (struct sadb_address *)nexthdr;
		dst->sadb_address_proto = proto;
		((struct sockaddr_in6 *)(dst + 1))->sin6_port = htons(dstport);
		nexthdr += dst->sadb_address_len;
	} else {
		FATAL1(ep, ebuf, gettext(
		    "Need destination address for %s.\n"), thiscmd);
	}

	if (use_natt) {
		if (natt_remote == NULL && natt_local == NULL) {
			ERROR(ep, ebuf, gettext(
			    "Must specify NAT-T remote or local address "
			    "for UDP encapsulation.\n"));
		}

		if (natt_remote != NULL) {
			bcopy(natt_remote, nexthdr,
			    SADB_64TO8(natt_remote->sadb_address_len));
			free(natt_remote);
			natt_remote = (struct sadb_address *)nexthdr;
			nexthdr += natt_remote->sadb_address_len;
			((struct sockaddr_in6 *)(natt_remote + 1))->sin6_port =
			    htons(natt_rport);
		}

		if (natt_local != NULL) {
			bcopy(natt_local, nexthdr,
			    SADB_64TO8(natt_local->sadb_address_len));
			free(natt_local);
			natt_local = (struct sadb_address *)nexthdr;
			nexthdr += natt_local->sadb_address_len;
			((struct sockaddr_in6 *)(natt_local + 1))->sin6_port =
			    htons(natt_lport);
		}
	}

	handle_errors(ep, ebuf, B_TRUE, B_FALSE);

	/*
	 * PF_KEY requires a source address extension, even if the source
	 * address itself is unspecified. (See "Set explicit unspecified..."
	 * code fragment above. Destination reality check was above.)
	 */
	bcopy(src, nexthdr, SADB_64TO8(src->sadb_address_len));
	free(src);
	src = (struct sadb_address *)nexthdr;
	src->sadb_address_proto = proto;
	((struct sockaddr_in6 *)(src + 1))->sin6_port = htons(srcport);
	nexthdr += src->sadb_address_len;

	if (isrc != NULL) {
		bcopy(isrc, nexthdr, SADB_64TO8(isrc->sadb_address_len));
		free(isrc);
		isrc = (struct sadb_address *)nexthdr;
		isrc->sadb_address_proto = iproto;
		((struct sockaddr_in6 *)(isrc + 1))->sin6_port =
		    htons(isrcport);
		nexthdr += isrc->sadb_address_len;
	}

	if (idst != NULL) {
		bcopy(idst, nexthdr, SADB_64TO8(idst->sadb_address_len));
		free(idst);
		idst = (struct sadb_address *)nexthdr;
		idst->sadb_address_proto = iproto;
		((struct sockaddr_in6 *)(idst + 1))->sin6_port =
		    htons(idstport);
		nexthdr += idst->sadb_address_len;
	}

	if (replay_ctr != NULL) {
		bcopy(replay_ctr, nexthdr,
		    SADB_64TO8(replay_ctr->sadb_x_rc_len));
		nexthdr += replay_ctr->sadb_x_rc_len;
		free(replay_ctr);
	}

	if (label != NULL) {
		bcopy(label, nexthdr, SADB_64TO8(label->sadb_sens_len));
		nexthdr += label->sadb_sens_len;
		free(label);
		label = NULL;
	}

	if (olabel != NULL) {
		bcopy(olabel, nexthdr, SADB_64TO8(olabel->sadb_sens_len));
		nexthdr += olabel->sadb_sens_len;
		free(olabel);
		olabel = NULL;
	}

	if (cflag) {
		/*
		 * Assume the checked cmd would have worked if it was actually
		 * used. doaddresses() will increment lines_added if it
		 * succeeds.
		 */
		lines_added++;
	} else {
		doaddresses(sadb_msg_type, satype,
		    cmd, srchp, dsthp, src, dst, unspec_src, buffer, totallen,
		    spi, ebuf);
	}

	if (isrchp != NULL && isrchp != &dummy.he)
		freehostent(isrchp);
	if (idsthp != NULL && idsthp != &dummy.he)
		freehostent(idsthp);
	if (srchp != NULL && srchp != &dummy.he)
		freehostent(srchp);
	if (dsthp != NULL && dsthp != &dummy.he)
		freehostent(dsthp);
	if (natt_lhp != NULL && natt_lhp != &dummy.he)
		freehostent(natt_lhp);
	if (natt_rhp != NULL && natt_rhp != &dummy.he)
		freehostent(natt_rhp);
	free(ebuf);
	free(buffer);
}

/*
 * DELETE and GET are similar, in that they only need the extensions
 * required to _find_ an SA, and then either delete it or obtain its
 * information.
 */
static void
dodelget(int cmd, int satype, char *argv[], char *ebuf)
{
	struct sadb_msg *msg = (struct sadb_msg *)get_buffer;
	uint64_t *nextext;
	struct sadb_sa *assoc = NULL;
	struct sadb_address *src = NULL, *dst = NULL;
	int next, token, sa_len;
	char *thiscmd;
	uint32_t spi;
	uint8_t	sadb_msg_type;
	struct hostent *srchp = NULL, *dsthp = NULL;
	struct sockaddr_in6 *sin6;
	boolean_t unspec_src = B_TRUE;
	uint16_t srcport = 0, dstport = 0;
	uint8_t proto = 0;
	char *ep = NULL;
	uint32_t sa_flags = 0;

	/* Set the first extension header to right past the base message. */
	nextext = (uint64_t *)(msg + 1);
	bzero(nextext, sizeof (get_buffer) - sizeof (*msg));

	switch (cmd) {
	case CMD_GET:
		thiscmd = "get";
		sadb_msg_type = SADB_GET;
		break;
	case CMD_DELETE:
		thiscmd = "delete";
		sadb_msg_type = SADB_DELETE;
		break;
	case CMD_DELETE_PAIR:
		thiscmd = "delete-pair";
		sadb_msg_type = SADB_X_DELPAIR;
		break;
	}

	msg_init(msg, sadb_msg_type, (uint8_t)satype);

#define	ALLOC_ADDR_EXT(ext, exttype)			\
	(ext) = (struct sadb_address *)nextext;		\
	nextext = (uint64_t *)((ext) + 1);		\
	nextext += SADB_8TO64(roundup(sa_len, 8));	\
	(ext)->sadb_address_exttype = exttype;		\
	(ext)->sadb_address_len = nextext - ((uint64_t *)ext);

	/* Assume last element in argv is set to NULL. */
	do {
		token = parseextval(*argv, &next);
		argv++;
		switch (token) {
		case TOK_EOF:
			/* Do nothing, I'm done. */
			break;
		case TOK_UNKNOWN:
			ERROR1(ep, ebuf, gettext(
			    "Unknown extension field \"%s\"\n"), *(argv - 1));
			break;
		case TOK_SPI:
			if (assoc != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single SPI value.\n"));
				break;
			}
			assoc = (struct sadb_sa *)nextext;
			nextext = (uint64_t *)(assoc + 1);
			assoc->sadb_sa_len = SADB_8TO64(sizeof (*assoc));
			assoc->sadb_sa_exttype = SADB_EXT_SA;
			assoc->sadb_sa_spi = htonl((uint32_t)parsenum(*argv,
			    B_TRUE, ebuf));
			spi = assoc->sadb_sa_spi;
			argv++;
			break;
		case TOK_SRCPORT:
			if (srcport != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single source port.\n"));
				break;
			}
			srcport = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_DSTPORT:
			if (dstport != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only "
				    "specify single destination port.\n"));
				break;
			}
			dstport = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_PROTO:
			if (proto != 0) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single protocol.\n"));
				break;
			}
			proto = parsenum(*argv, B_TRUE, ebuf);
			argv++;
			break;
		case TOK_SRCADDR:
		case TOK_SRCADDR6:
			if (src != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single source addr.\n"));
				break;
			}
			sa_len = parseaddr(*argv, &srchp,
			    (token == TOK_SRCADDR6), ebuf);
			if (srchp == NULL) {
				ERROR1(ep, ebuf, gettext(
				    "Unknown source address \"%s\"\n"), *argv);
				break;
			}
			argv++;

			unspec_src = B_FALSE;

			ALLOC_ADDR_EXT(src, SADB_EXT_ADDRESS_SRC);

			if (srchp == &dummy.he) {
				/*
				 * Single address with -n flag.
				 */
				sin6 = (struct sockaddr_in6 *)(src + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(srchp->h_addr_list[0], &sin6->sin6_addr,
				    sizeof (struct in6_addr));
			}
			/* The rest is pre-bzeroed for us. */
			break;
		case TOK_DSTADDR:
		case TOK_DSTADDR6:
			if (dst != NULL) {
				ERROR(ep, ebuf, gettext(
				    "Can only specify single destination "
				    "address.\n"));
				break;
			}
			sa_len = parseaddr(*argv, &dsthp,
			    (token == TOK_SRCADDR6), ebuf);
			if (dsthp == NULL) {
				ERROR1(ep, ebuf, gettext(
				    "Unknown destination address \"%s\"\n"),
				    *argv);
				break;
			}
			argv++;

			ALLOC_ADDR_EXT(dst, SADB_EXT_ADDRESS_DST);

			if (dsthp == &dummy.he) {
				/*
				 * Single address with -n flag.
				 */
				sin6 = (struct sockaddr_in6 *)(dst + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(dsthp->h_addr_list[0], &sin6->sin6_addr,
				    sizeof (struct in6_addr));
			}
			/* The rest is pre-bzeroed for us. */
			break;
		case TOK_FLAG_INBOUND:
			sa_flags |= SADB_X_SAFLAGS_INBOUND;
			break;
		case TOK_FLAG_OUTBOUND:
			sa_flags |= SADB_X_SAFLAGS_OUTBOUND;
			break;
		default:
			ERROR2(ep, ebuf, gettext(
			    "Don't use extension %s for '%s' command.\n"),
			    *(argv - 1), thiscmd);
			break;
		}
	} while (token != TOK_EOF);

	handle_errors(ep, ebuf, B_TRUE, B_FALSE);

	if (assoc == NULL) {
		FATAL1(ep, ebuf, gettext(
		    "Need SA parameters for %s.\n"), thiscmd);
	}

	/* We can set the flags now with valid assoc in hand. */
	assoc->sadb_sa_flags |= sa_flags;

	if ((srcport != 0) && (src == NULL)) {
		ALLOC_ADDR_EXT(src, SADB_EXT_ADDRESS_SRC);
		sin6 = (struct sockaddr_in6 *)(src + 1);
		src->sadb_address_proto = proto;
		bzero(sin6, sizeof (*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(srcport);
	}

	if ((dstport != 0) && (dst == NULL)) {
		ALLOC_ADDR_EXT(dst, SADB_EXT_ADDRESS_DST);
		sin6 = (struct sockaddr_in6 *)(dst + 1);
		src->sadb_address_proto = proto;
		bzero(sin6, sizeof (*sin6));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(dstport);
	}

	/* So I have enough of the message to send it down! */
	msg->sadb_msg_len = nextext - get_buffer;

	if (cflag) {
		/*
		 * Assume the checked cmd would have worked if it was actually
		 * used. doaddresses() will increment lines_added if it
		 * succeeds.
		 */
		lines_added++;
	} else {
		doaddresses(sadb_msg_type, satype,
		    cmd, srchp, dsthp, src, dst, unspec_src, get_buffer,
		    sizeof (get_buffer), spi, NULL);
	}

	if (srchp != NULL && srchp != &dummy.he)
		freehostent(srchp);
	if (dsthp != NULL && dsthp != &dummy.he)
		freehostent(dsthp);
}

/*
 * "ipseckey monitor" should exit very gracefully if ^C is tapped provided
 * it is not running in interactive mode.
 */
static void
monitor_catch(int signal)
{
	if (!interactive)
		errx(signal, gettext("Bailing on signal %d."), signal);
}

/*
 * Loop forever, listening on PF_KEY messages.
 */
static void
domonitor(boolean_t passive)
{
	struct sadb_msg *samsg;
	struct sigaction newsig, oldsig;
	int rc;

	/* Catch ^C. */
	newsig.sa_handler = monitor_catch;
	newsig.sa_flags = 0;
	(void) sigemptyset(&newsig.sa_mask);
	(void) sigaddset(&newsig.sa_mask, SIGINT);
	(void) sigaction(SIGINT, &newsig, &oldsig);

	samsg = (struct sadb_msg *)get_buffer;
	if (!passive) {
		(void) printf(gettext("Actively"));
		msg_init(samsg, SADB_X_PROMISC, 1);	/* Turn ON promisc. */
		rc = key_write(keysock, samsg, sizeof (*samsg));
		if (rc == -1)
			Bail("write (SADB_X_PROMISC)");
	} else {
		(void) printf(gettext("Passively"));
	}
	(void) printf(gettext(" monitoring the PF_KEY socket.\n"));

	for (; ; ) {
		/*
		 * I assume that read() is non-blocking, and will never
		 * return 0.
		 */
		rc = read(keysock, samsg, sizeof (get_buffer));
		if (rc == -1) {
			if (errno == EINTR && interactive)
				goto out;
			else
				Bail("read (in domonitor)");
		}
		(void) printf(gettext("Read %d bytes.\n"), rc);
		/*
		 * Q:  Should I use the same method of printing as GET does?
		 * A:  For now, yes.
		 */
		print_samsg(stdout, get_buffer, B_TRUE, vflag, nflag);
		(void) putchar('\n');
	}

out:
	if (interactive)
		/* restore SIGINT behavior */
		(void) sigaction(SIGINT, &oldsig, NULL);
}

/*
 * Either mask or unmask all relevant signals.
 */
static void
mask_signals(boolean_t unmask)
{
	sigset_t set;
	static sigset_t oset;

	if (unmask) {
		(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	} else {
		(void) sigfillset(&set);
		(void) sigprocmask(SIG_SETMASK, &set, &oset);
	}
}

/*
 * Assorted functions to print help text.
 */
#define	puts_tr(s) (void) puts(gettext(s))

static void
doattrhelp()
{
	int i;

	puts_tr("\nSA attributes:");

	for (i = 0; tokens[i].string != NULL; i++) {
		if (i%3 == 0)
			(void) printf("\n");
		(void) printf("    %-15.15s", tokens[i].string);
	}
	(void) printf("\n");
}

static void
dohelpcmd(char *cmds)
{
	int cmd;

	if (strcmp(cmds, "attr") == 0) {
		doattrhelp();
		return;
	}

	cmd = parsecmd(cmds);
	switch (cmd) {
	case CMD_UPDATE:
		puts_tr("update	 - Update an existing SA");
		break;
	case CMD_UPDATE_PAIR:
		puts_tr("update-pair - Update an existing pair of SA's");
		break;
	case CMD_ADD:
		puts_tr("add	 - Add a new security association (SA)");
		break;
	case CMD_DELETE:
		puts_tr("delete - Delete an SA");
		break;
	case CMD_DELETE_PAIR:
		puts_tr("delete-pair - Delete a pair of SA's");
		break;
	case CMD_GET:
		puts_tr("get - Display an SA");
		break;
	case CMD_FLUSH:
		puts_tr("flush - Delete all SAs");
		puts_tr("");
		puts_tr("Optional arguments:");
		puts_tr("all        delete all SAs");
		puts_tr("esp        delete just ESP SAs");
		puts_tr("ah         delete just AH SAs");
		puts_tr("<number>   delete just SAs with type given by number");
		puts_tr("");
		break;
	case CMD_DUMP:
		puts_tr("dump - Display all SAs");
		puts_tr("");
		puts_tr("Optional arguments:");
		puts_tr("all        display all SAs");
		puts_tr("esp        display just ESP SAs");
		puts_tr("ah         display just AH SAs");
		puts_tr("<number>   display just SAs with type "
		    "given by number");
		puts_tr("");
		break;
	case CMD_MONITOR:
		puts_tr("monitor - Monitor all PF_KEY reply messages.");
		break;
	case CMD_PMONITOR:
		puts_tr(
"pmonitor, passive_monitor - Monitor PF_KEY messages that");
		puts_tr(
"                            reply to all PF_KEY sockets.");
		break;

	case CMD_QUIT:
		puts_tr("quit, exit - Exit the program");
		break;
	case CMD_SAVE:
		puts_tr("save	    - Saves all SAs to a file");
		break;
	case CMD_HELP:
		puts_tr("help	    - Display list of commands");
		puts_tr("help <cmd> - Display help for command");
		puts_tr("help attr  - Display possible SA attributes");
		break;
	default:
		(void) printf(gettext("%s: Unknown command\n"), cmds);
		break;
	}
}


static void
dohelp(char *cmds)
{
	if (cmds != NULL) {
		dohelpcmd(cmds);
		return;
	}
	puts_tr("Commands");
	puts_tr("--------");
	puts_tr("?, help  - Display this list");
	puts_tr("help <cmd> - Display help for command");
	puts_tr("help attr  - Display possible SA attributes");
	puts_tr("quit, exit - Exit the program");
	puts_tr("monitor - Monitor all PF_KEY reply messages.");
	puts_tr("pmonitor, passive_monitor - Monitor PF_KEY messages that");
	puts_tr("                            reply to all PF_KEY sockets.");
	puts_tr("");
	puts_tr("The following commands are of the form:");
	puts_tr("    <command> {SA type} {attribute value}*");
	puts_tr("");
	puts_tr("add (interactive only) - Add a new security association (SA)");
	puts_tr("update (interactive only) - Update an existing SA");
	puts_tr("update-pair (interactive only) - Update an existing SA pair");
	puts_tr("delete - Delete an SA");
	puts_tr("delete-pair - Delete an SA pair");
	puts_tr("get - Display an SA");
	puts_tr("flush - Delete all SAs");
	puts_tr("dump - Display all SAs");
	puts_tr("save - Saves all SAs to a file");
}

/*
 * "Parse" a command line from argv.
 */
static void
parseit(int argc, char *argv[], char *ebuf, boolean_t read_cmdfile)
{
	int cmd, satype;
	char *ep = NULL;

	if (argc == 0)
		return;
	cmd = parsecmd(*argv++);

	/*
	 * Some commands loop forever and should only be run from the command
	 * line, they should never be run from a command file as this may
	 * be used at boot time.
	 */
	switch (cmd) {
	case CMD_HELP:
		if (read_cmdfile)
			ERROR(ep, ebuf, gettext("Help not appropriate in "
			    "config file."));
		else
			dohelp(*argv);
		return;
	case CMD_MONITOR:
		if (read_cmdfile)
			ERROR(ep, ebuf, gettext("Monitor not appropriate in "
			    "config file."));
		else {
			domonitor(B_FALSE);
			/*
			 * Return from the function in interactive mode to
			 * avoid error message in the next switch statement.
			 * Also print newline to prevent prompt clobbering.
			 * The same is done for CMD_PMONITOR.
			 */
			if (interactive) {
				(void) printf("\n");
				return;
			}
		}
		break;
	case CMD_PMONITOR:
		if (read_cmdfile)
			ERROR(ep, ebuf, gettext("Monitor not appropriate in "
			    "config file."));
		else {
			domonitor(B_TRUE);
			if (interactive) {
				(void) printf("\n");
				return;
			}
		}
		break;
	case CMD_QUIT:
		EXIT_OK(NULL);
	}

	handle_errors(ep, ebuf, B_FALSE, B_FALSE);

	satype = parsesatype(*argv, ebuf);

	if (satype != SADB_SATYPE_UNSPEC) {
		argv++;
	} else {
		/*
		 * You must specify either "all" or a specific SA type
		 * for the "save" command.
		 */
		if (cmd == CMD_SAVE)
			if (*argv == NULL) {
				FATAL(ep, ebuf, gettext(
				    "Must specify a specific "
				    "SA type for save.\n"));
			} else {
				argv++;
			}
	}

	switch (cmd) {
	case CMD_FLUSH:
		if (argc > 2) {
			ERROR(ep, ebuf, gettext("Too many arguments for "
			    "flush command"));
			handle_errors(ep, ebuf,
			    interactive ? B_TRUE : B_FALSE, B_FALSE);
		}
		if (!cflag)
			doflush(satype);
		/*
		 * If this was called because of an entry in a cmd file
		 * then this action needs to be counted to prevent
		 * do_interactive() treating this as an error.
		 */
		lines_added++;
		break;
	case CMD_ADD:
	case CMD_UPDATE:
	case CMD_UPDATE_PAIR:
		/*
		 * NOTE: Shouldn't allow ADDs or UPDATEs with keying material
		 * from the command line.
		 */
		if (!interactive) {
			errx(1, gettext(
			    "can't do ADD or UPDATE from the command line.\n"));
		}
		if (satype == SADB_SATYPE_UNSPEC) {
			FATAL(ep, ebuf, gettext(
			    "Must specify a specific SA type."));
			/* NOTREACHED */
		}
		/* Parse for extensions, including keying material. */
		doaddup(cmd, satype, argv, ebuf);
		break;
	case CMD_DELETE:
	case CMD_DELETE_PAIR:
	case CMD_GET:
		if (satype == SADB_SATYPE_UNSPEC) {
			FATAL(ep, ebuf, gettext(
			    "Must specify a single SA type."));
			/* NOTREACHED */
		}
		/* Parse for bare minimum to locate an SA. */
		dodelget(cmd, satype, argv, ebuf);
		break;
	case CMD_DUMP:
		if (read_cmdfile)
			ERROR(ep, ebuf, gettext("Dump not appropriate in "
			    "config file."));
		else {
			if (argc > 2) {
				ERROR(ep, ebuf, gettext("Too many arguments "
				    "for dump command"));
				handle_errors(ep, ebuf,
				    interactive ? B_TRUE : B_FALSE, B_FALSE);
			}
			dodump(satype, NULL);
		}
		break;
	case CMD_SAVE:
		if (read_cmdfile) {
			ERROR(ep, ebuf, gettext("Save not appropriate in "
			    "config file."));
		} else {
			mask_signals(B_FALSE);	/* Mask signals */
			dodump(satype, opensavefile(argv[0]));
			mask_signals(B_TRUE);	/* Unmask signals */
		}
		break;
	default:
		warnx(gettext("Unknown command (%s).\n"),
		    *(argv - ((satype == SADB_SATYPE_UNSPEC) ? 1 : 2)));
		usage();
	}
	handle_errors(ep, ebuf, B_FALSE, B_FALSE);
}

int
main(int argc, char *argv[])
{
	int ch;
	FILE *infile = stdin, *savefile;
	boolean_t dosave = B_FALSE, readfile = B_FALSE;
	char *configfile = NULL;
	struct stat sbuf;
	int bootflags;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Check to see if the command is being run from smf(5).
	 */
	my_fmri = getenv("SMF_FMRI");

	openlog("ipseckey", LOG_CONS, LOG_AUTH);
	if (getuid() != 0) {
		errx(1, "Insufficient privileges to run ipseckey.");
	}

	/* umask me to paranoid, I only want to create files read-only */
	(void) umask((mode_t)00377);

	while ((ch = getopt(argc, argv, "pnvf:s:c:")) != EOF)
		switch (ch) {
		case 'p':
			pflag = B_TRUE;
			break;
		case 'n':
			nflag = B_TRUE;
			break;
		case 'v':
			vflag = B_TRUE;
			break;
		case 'c':
			cflag = B_TRUE;
			/* FALLTHRU */
		case 'f':
			if (dosave)
				usage();

			/*
			 * Use stat() to check and see if the user inadvertently
			 * passed in a bad pathname, or the name of a directory.
			 * We should also check to see if the filename is a
			 * pipe. We use stat() here because fopen() will block
			 * unless the other end of the pipe is open. This would
			 * be undesirable, especially if this is called at boot
			 * time. If we ever need to support reading from a pipe
			 * or special file, this should be revisited.
			 */
			if (stat(optarg, &sbuf) == -1) {
				EXIT_BADCONFIG2("Invalid pathname: %s\n",
				    optarg);
			}
			if (!(sbuf.st_mode & S_IFREG)) {
				EXIT_BADCONFIG2("%s - Not a regular file\n",
				    optarg);
			}
			infile = fopen(optarg, "r");
			if (infile == NULL) {
				EXIT_BADCONFIG2("Unable to open configuration "
				    "file: %s\n", optarg);
			}
			/*
			 * The input file contains keying information, because
			 * this is sensative, we should only accept data from
			 * this file if the file is root owned and only readable
			 * by privileged users. If the command is being run by
			 * the administrator, issue a warning, if this is run by
			 * smf(5) (IE: boot time) and the permissions are too
			 * open, we will fail, the SMF service will end up in
			 * maintenace mode. The check is made with fstat() to
			 * eliminate any possible TOT to TOU window.
			 */
			if (fstat(fileno(infile), &sbuf) == -1) {
				(void) fclose(infile);
				EXIT_BADCONFIG2("Unable to stat configuration "
				    "file: %s\n", optarg);
			}
			if (INSECURE_PERMS(sbuf)) {
				if (my_fmri != NULL) {
					(void) fclose(infile);
					EXIT_BADCONFIG2("Config file "
					    "%s has insecure permissions.",
					    optarg);
				} else 	{
					(void) fprintf(stderr, gettext(
					    "Config file %s has insecure "
					    "permissions, will be rejected in "
					    "permanent config.\n"), optarg);
				}
			}
			configfile = strdup(optarg);
			readfile = B_TRUE;
			break;
		case 's':
			if (readfile)
				usage();
			dosave = B_TRUE;
			savefile = opensavefile(optarg);
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	mypid = getpid();

	keysock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

	if (keysock == -1) {
		if (errno == EPERM) {
			EXIT_BADPERM("Insufficient privileges to open "
			    "PF_KEY socket.\n");
		} else {
			/* some other reason */
			EXIT_FATAL("Opening PF_KEY socket");
		}
	}

	if ((_cladm(CL_INITIALIZE, CL_GET_BOOTFLAG, &bootflags) != 0) ||
	    (bootflags & CLUSTER_BOOTED)) {
		in_cluster_mode = B_TRUE;
		cluster_socket = socket(AF_INET, SOCK_DGRAM, 0);
		cli_addr.sin_family = AF_INET;
		cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		cli_addr.sin_port = htons(CLUSTER_UDP_PORT);
	}

	if (dosave) {
		mask_signals(B_FALSE);	/* Mask signals */
		dodump(SADB_SATYPE_UNSPEC, savefile);
		mask_signals(B_TRUE);	/* Unmask signals */
		EXIT_OK(NULL);
	}

	/*
	 * When run from smf(5) flush any existing SA's first
	 * otherwise you will end up in maintenance mode.
	 */
	if ((my_fmri != NULL) && readfile) {
		(void) fprintf(stdout, gettext(
		    "Flushing existing SA's before adding new SA's\n"));
		(void) fflush(stdout);
		doflush(SADB_SATYPE_UNSPEC);
	}
	if (infile != stdin || argc == 0) {
		/* Go into interactive mode here. */
		do_interactive(infile, configfile, "ipseckey> ", my_fmri,
		    parseit, no_match);
	}
	parseit(argc, argv, NULL, B_FALSE);

	return (0);
}
