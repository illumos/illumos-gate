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
 * NOTE:I'm trying to use "struct sadb_foo" instead of "sadb_foo_t"
 *	as a maximal PF_KEY portability test.
 *
 *	Also, this is a deliberately single-threaded app, also for portability
 *	to systems without POSIX threads.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


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
#include <netdb.h>
#include <pwd.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <fcntl.h>
#include <strings.h>
#include <ctype.h>

#include <ipsec_util.h>

static char numprint[NBUF_SIZE];
static int keysock;
static uint32_t seq;
static pid_t mypid;
static boolean_t vflag = B_FALSE;	/* Verbose? */

#define	MAX_GET_SIZE	1024
/* Defined as a uint64_t array for alignment purposes. */
static uint64_t get_buffer[MAX_GET_SIZE];

/* local prototypes */
static const char *do_inet_ntop(const void *, char *, size_t);
static void printsatime(int64_t, const char *, const char *, const char *);

/*
 * When something syntactically bad happens while reading commands,
 * print it.  For command line, exit.  For reading from a file, exit, and
 * print the offending line number.  For interactive, just print the error
 * and reset the program state with the longjmp().
 */
static void
usage(void)
{
	if (readfile) {
		warnx(gettext("Parse error on line %u."), lineno);
	}
	if (!interactive) {
		(void) fprintf(stderr, gettext("Usage:\t"
		    "ipseckey [ -nvp ] | cmd [sa_type] [extfield value]*\n"));
		(void) fprintf(stderr,
		    gettext("\tipseckey [ -nvp ] -f infile\n"));
		(void) fprintf(stderr,
		    gettext("\tipseckey [ -nvp ] -s outfile\n"));
		exit(1);
	} else {
		longjmp(env, 1);
	}
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
#define	CMD_ADD		3
#define	CMD_DELETE	4
#define	CMD_GET		5
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
		{"add",			CMD_ADD},
		{"delete", 		CMD_DELETE},
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
parsenum(char *num, boolean_t bail)
{
	u_longlong_t rc;
	char *end = NULL;

	if (num == NULL) {
		warnx(gettext("Unexpected end of command line."));
		usage();
	}

	errno = 0;
	rc = strtoull(num, &end, 0);
	if (errno != 0 || end == num || *end != '\0') {
		if (bail) {
			/* Errno message printed by warn(). */
			warn(gettext("Expecting a number, but got"));
			usage();
		} else {
			/*
			 * -1, while not optimal, is sufficiently out of range
			 * for most of this function's applications when
			 * we don't just bail.
			 */
			return ((u_longlong_t)-1);
		}
	}

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

static char *
rparsesatype(int type)
{
	struct typetable *tt = type_table;

	while (tt->type != NULL && type != tt->token)
		tt++;

	if (tt->type == NULL) {
		(void) snprintf(numprint, NBUF_SIZE, "%d", type);
	} else {
		return (tt->type);
	}

	return (numprint);
}

static int
parsesatype(char *type)
{
	struct typetable *tt = type_table;

	if (type == NULL)
		return (SADB_SATYPE_UNSPEC);

	while (tt->type != NULL && strcasecmp(tt->type, type) != 0)
		tt++;

	/*
	 * New SA types (including ones keysock maintains for user-land
	 * protocols) may be added, so parse a numeric value if possible.
	 */
	if (tt->type == NULL) {
		tt->token = (int)parsenum(type, B_FALSE);
		if (tt->token == -1) {
			warnx(gettext("Unknown SA type (%s)."), type);
			usage();
		}
	}

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

static struct toktable {
	char *string;
	int token;
	int next;
} tokens[] = {
	/* "String",		token value,		next arg is */
	{"spi",			TOK_SPI,		NEXTNUM},
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

	{"sport",		TOK_SRCPORT,		NEXTNUM},
	{"dport",		TOK_DSTPORT,		NEXTNUM},
	{"proto",		TOK_PROTO,		NEXTNUM},
	{"ulp",			TOK_PROTO,		NEXTNUM},

	{"saddr6",		TOK_SRCADDR6,		NEXTADDR},
	{"srcaddr6",		TOK_SRCADDR6,		NEXTADDR},
	{"src6",		TOK_SRCADDR6,		NEXTADDR},
	{"daddr6",		TOK_DSTADDR6,		NEXTADDR},
	{"dstaddr6",		TOK_DSTADDR6,		NEXTADDR},
	{"dst6",		TOK_DSTADDR6,		NEXTADDR},
	{"proxyaddr6",		TOK_PROXYADDR6,		NEXTADDR},
	{"proxy6",		TOK_PROXYADDR6,		NEXTADDR},

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
parsestate(char *state)
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

	if (state == NULL) {
		warnx(gettext("Unexpected end of command line."));
		usage();
	}

	for (sp = states; sp->state != NULL; sp++) {
		if (strcmp(sp->state, state) == 0)
			return (sp->retval);
	}
	warnx(gettext("Unknown state type %s."), state);
	usage();
	/* NOTREACHED */
	return (0);
}

/*
 * Return a string containing the name of the specified numerical algorithm
 * identifier.
 */
static char *
rparsealg(uint8_t alg, int proto_num)
{
	static struct ipsecalgent *holder = NULL; /* we're single-threaded */

	if (holder != NULL)
		freeipsecalgent(holder);

	holder = getipsecalgbynum(alg, proto_num, NULL);
	if (holder == NULL) {
		(void) snprintf(numprint, NBUF_SIZE, "%d", alg);
		return (numprint);
	}

	return (*(holder->a_names));
}

/*
 * Return the numerical algorithm identifier corresponding to the specified
 * algorithm name.
 */
static uint8_t
parsealg(char *alg, int proto_num)
{
	u_longlong_t invalue;
	struct ipsecalgent *algent;

	if (alg == NULL) {
		warnx(gettext("Unexpected end of command line."));
		usage();
	}

	algent = getipsecalgbyname(alg, proto_num, NULL);
	if (algent != NULL) {
		uint8_t alg_num;

		alg_num = algent->a_alg_num;
		freeipsecalgent(algent);

		return (alg_num);
	}

	/*
	 * Since algorithms can be loaded during kernel run-time, check for
	 * numeric algorithm values too.  PF_KEY can catch bad ones with EINVAL.
	 */
	invalue = parsenum(alg, B_FALSE);
	if (invalue != (u_longlong_t)-1 &&
	    (u_longlong_t)(invalue & (u_longlong_t)0xff) == invalue)
		return ((uint8_t)invalue);

	if (proto_num == IPSEC_PROTO_ESP)
		warnx(gettext("Unknown encryption algorithm type %s."), alg);
	else
		warnx(gettext("Unknown authentication algorithm type %s."),
		    alg);
	usage();
	/* NOTREACHED */
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

static char *
rparseidtype(uint16_t type)
{
	struct idtypes *idp;

	for (idp = idtypes; idp->idtype != NULL; idp++) {
		if (type == idp->retval)
			return (idp->idtype);
	}

	(void) snprintf(numprint, NBUF_SIZE, "%d", type);
	return (numprint);
}

static uint16_t
parseidtype(char *type)
{
	struct idtypes *idp;
	u_longlong_t invalue;

	if (type == NULL) {
		/* Shouldn't reach here, see callers for why. */
		warnx(gettext("Unexpected end of command line."));
		usage();
	}

	for (idp = idtypes; idp->idtype != NULL; idp++) {
		if (strcasecmp(idp->idtype, type) == 0)
			return (idp->retval);
	}
	/*
	 * Since identity types are almost arbitrary, check for numeric
	 * algorithm values too.  PF_KEY can catch bad ones with EINVAL.
	 */
	invalue = parsenum(type, B_FALSE);
	if (invalue != (u_longlong_t)-1 &&
	    (u_longlong_t)(invalue & (u_longlong_t)0xffff) == invalue)
		return ((uint16_t)invalue);


	warnx(gettext("Unknown identity type %s."), type);
	usage();
	/* NOTREACHED */
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
parseaddr(char *addr, struct hostent **hpp, boolean_t v6only)
{
	int hp_errno;
	struct hostent *hp = NULL;

	if (addr == NULL) {
		warnx(gettext("Unexpected end of command line."));
		usage();
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
			 * Remape to AF_INET6 anyway.
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

	if (hp == NULL) {
		warnx(gettext("Unknown address %s."), addr);
		usage();
	}

	*hpp = hp;
	/* Always return sockaddr_storage for now. */
	return (sizeof (struct sockaddr_storage));
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
parsekey(char *input)
{
	struct sadb_key *retval;
	uint_t i, hexlen = 0, bits, alloclen;
	uint8_t *key;

	if (input == NULL) {
		warnx(gettext("Unexpected end of command line."));
		usage();
	}

	for (i = 0; input[i] != '\0' && input[i] != '/'; i++)
		hexlen++;

	if (input[i] == '\0') {
		bits = 0;
	} else {
		/* Have /nn. */
		input[i] = '\0';
		if (sscanf((input + i + 1), "%u", &bits) != 1) {
			warnx(gettext("%s is not a bit specifier."),
			    (input + i + 1));
			usage();
		}
		/* hexlen in nibbles */
		if (((bits + 3) >> 2) > hexlen) {
			warnx(gettext("bit length %d is too big for %s."),
			    bits, input);
			usage();
		}
		/*
		 * Adjust hexlen down if user gave us too small of a bit
		 * count.
		 */
		if ((hexlen << 2) > bits + 3) {
			warnx(gettext("WARNING: Lower bits will be truncated "
			    "for:\n\t%s/%d."), input, bits);
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
	retval->sadb_key_reserved = 0;
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
			warnx(gettext("string '%s' not a hex string."), input);
			usage();
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

	return (retval);
}

/*
 * Expand the diagnostic code into a message.
 */
static void
print_diagnostic(FILE *file, uint16_t diagnostic)
{
	/* Use two spaces so above strings can fit on the line. */
	(void) fprintf(file, gettext("  Diagnostic code %u:  %s.\n"),
	    diagnostic, keysock_diag(diagnostic));
}

/*
 * Prints the base PF_KEY message.
 */
static void
print_sadb_msg(struct sadb_msg *samsg, time_t wallclock)
{
	if (wallclock != 0)
		printsatime(wallclock, gettext("%sTimestamp: %s\n"), "", NULL);

	(void) printf(gettext("Base message (version %u) type "),
	    samsg->sadb_msg_version);
	switch (samsg->sadb_msg_type) {
	case SADB_RESERVED:
		(void) printf(gettext("RESERVED (warning: set to 0)"));
		break;
	case SADB_GETSPI:
		(void) printf("GETSPI");
		break;
	case SADB_UPDATE:
		(void) printf("UPDATE");
		break;
	case SADB_ADD:
		(void) printf("ADD");
		break;
	case SADB_DELETE:
		(void) printf("DELETE");
		break;
	case SADB_GET:
		(void) printf("GET");
		break;
	case SADB_ACQUIRE:
		(void) printf("ACQUIRE");
		break;
	case SADB_REGISTER:
		(void) printf("REGISTER");
		break;
	case SADB_EXPIRE:
		(void) printf("EXPIRE");
		break;
	case SADB_FLUSH:
		(void) printf("FLUSH");
		break;
	case SADB_DUMP:
		(void) printf("DUMP");
		break;
	case SADB_X_PROMISC:
		(void) printf("X_PROMISC");
		break;
	case SADB_X_INVERSE_ACQUIRE:
		(void) printf("X_INVERSE_ACQUIRE");
		break;
	default:
		(void) printf(gettext("Unknown (%u)"), samsg->sadb_msg_type);
		break;
	}
	(void) printf(gettext(", SA type "));

	switch (samsg->sadb_msg_satype) {
	case SADB_SATYPE_UNSPEC:
		(void) printf(gettext("<unspecified/all>"));
		break;
	case SADB_SATYPE_AH:
		(void) printf("AH");
		break;
	case SADB_SATYPE_ESP:
		(void) printf("ESP");
		break;
	case SADB_SATYPE_RSVP:
		(void) printf("RSVP");
		break;
	case SADB_SATYPE_OSPFV2:
		(void) printf("OSPFv2");
		break;
	case SADB_SATYPE_RIPV2:
		(void) printf("RIPv2");
		break;
	case SADB_SATYPE_MIP:
		(void) printf(gettext("Mobile IP"));
		break;
	default:
		(void) printf(gettext("<unknown %u>"), samsg->sadb_msg_satype);
		break;
	}

	(void) printf(".\n");

	if (samsg->sadb_msg_errno != 0) {
		(void) printf(gettext("Error %s from PF_KEY.\n"),
		    strerror(samsg->sadb_msg_errno));
		print_diagnostic(stdout, samsg->sadb_x_msg_diagnostic);
	}

	(void) printf(gettext("Message length %u bytes, seq=%u, pid=%u.\n"),
	    SADB_64TO8(samsg->sadb_msg_len), samsg->sadb_msg_seq,
	    samsg->sadb_msg_pid);
}

/*
 * Print the SA extension for PF_KEY.
 */
static void
print_sa(char *prefix, struct sadb_sa *assoc)
{
	if (assoc->sadb_sa_len != SADB_8TO64(sizeof (*assoc))) {
		warnx(gettext("WARNING: SA info extension length (%u) is bad."),
		    SADB_64TO8(assoc->sadb_sa_len));
	}

	(void) printf(gettext("%sSADB_ASSOC spi=0x%x, replay=%u, state="),
	    prefix, ntohl(assoc->sadb_sa_spi), assoc->sadb_sa_replay);
	switch (assoc->sadb_sa_state) {
	case SADB_SASTATE_LARVAL:
		(void) printf(gettext("LARVAL"));
		break;
	case SADB_SASTATE_MATURE:
		(void) printf(gettext("MATURE"));
		break;
	case SADB_SASTATE_DYING:
		(void) printf(gettext("DYING"));
		break;
	case SADB_SASTATE_DEAD:
		(void) printf(gettext("DEAD"));
		break;
	default:
		(void) printf(gettext("<unknown %u>"), assoc->sadb_sa_state);
	}

	if (assoc->sadb_sa_auth != SADB_AALG_NONE) {
		(void) printf(gettext("\n%sAuthentication algorithm = "),
		    prefix);
		(void) dump_aalg(assoc->sadb_sa_auth, stdout);
	}

	if (assoc->sadb_sa_encrypt != SADB_EALG_NONE) {
		(void) printf(gettext("\n%sEncryption algorithm = "), prefix);
		(void) dump_ealg(assoc->sadb_sa_encrypt, stdout);
	}

	(void) printf(gettext("\n%sflags=0x%x < "), prefix,
	    assoc->sadb_sa_flags);
	if (assoc->sadb_sa_flags & SADB_SAFLAGS_PFS)
		(void) printf("PFS ");
	if (assoc->sadb_sa_flags & SADB_SAFLAGS_NOREPLAY)
		(void) printf("NOREPLAY ");

	/* BEGIN Solaris-specific flags. */
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_USED)
		(void) printf("X_USED ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_UNIQUE)
		(void) printf("X_UNIQUE ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_AALG1)
		(void) printf("X_AALG1 ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_AALG2)
		(void) printf("X_AALG2 ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_EALG1)
		(void) printf("X_EALG1 ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_EALG2)
		(void) printf("X_EALG2 ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_NATT_LOC)
		(void) printf("X_NATT_LOC ");
	if (assoc->sadb_sa_flags & SADB_X_SAFLAGS_NATT_REM)
		(void) printf("X_NATT_REM ");
	/* END Solaris-specific flags. */

	(void) printf(">\n");
}

static void
printsatime(int64_t lt, const char *msg, const char *pfx, const char *pfx2)
{
	char tbuf[TBUF_SIZE]; /* For strftime() call. */
	const char *tp = tbuf;
	time_t t = lt;
	if (t != lt) {
		if (lt > 0)
			t = LONG_MAX;
		else
			t = LONG_MIN;
	}

	if (strftime(tbuf, TBUF_SIZE, NULL, localtime(&t)) == 0)
		tp = gettext("<time conversion failed>");
	(void) printf(msg, pfx, tp);
	if (vflag && (pfx2 != NULL))
		(void) printf(gettext("%s\t(raw time value %llu)\n"), pfx2, lt);
}

/*
 * Print the SA lifetime information.  (An SADB_EXT_LIFETIME_* extension.)
 */
static void
print_lifetimes(time_t wallclock, struct sadb_lifetime *current,
    struct sadb_lifetime *hard, struct sadb_lifetime *soft)
{
	int64_t scratch;
	char *soft_prefix = gettext("SLT: ");
	char *hard_prefix = gettext("HLT: ");
	char *current_prefix = gettext("CLT: ");

	if (current != NULL &&
	    current->sadb_lifetime_len != SADB_8TO64(sizeof (*current))) {
		warnx(gettext("WARNING: CURRENT lifetime extension length "
			"(%u) is bad."),
		    SADB_64TO8(current->sadb_lifetime_len));
	}

	if (hard != NULL &&
	    hard->sadb_lifetime_len != SADB_8TO64(sizeof (*hard))) {
		warnx(gettext("WARNING: HARD lifetime "
			"extension length (%u) is bad."),
		    SADB_64TO8(hard->sadb_lifetime_len));
	}

	if (soft != NULL &&
	    soft->sadb_lifetime_len != SADB_8TO64(sizeof (*soft))) {
		warnx(gettext("WARNING: SOFT lifetime "
		    "extension length (%u) is bad."),
		    SADB_64TO8(soft->sadb_lifetime_len));
	}

	(void) printf(" LT: Lifetime information\n");

	if (current != NULL) {
		/* Express values as current values. */
		(void) printf(gettext(
		    "%s%llu bytes protected, %u allocations used.\n"),
		    current_prefix, current->sadb_lifetime_bytes,
		    current->sadb_lifetime_allocations);
		printsatime(current->sadb_lifetime_addtime,
		    gettext("%sSA added at time %s\n"),
		    current_prefix, current_prefix);
		if (current->sadb_lifetime_usetime != 0) {
			printsatime(current->sadb_lifetime_usetime,
			    gettext("%sSA first used at time %s\n"),
			    current_prefix, current_prefix);
		}
		printsatime(wallclock, gettext("%sTime now is %s\n"),
		    current_prefix, current_prefix);
	}

	if (soft != NULL) {
		(void) printf(gettext("%sSoft lifetime information:  "),
		    soft_prefix);
		(void) printf(gettext("%llu bytes of lifetime, %u "
		    "allocations.\n"), soft->sadb_lifetime_bytes,
		    soft->sadb_lifetime_allocations);
		(void) printf(gettext("%s%llu seconds of post-add lifetime.\n"),
		    soft_prefix, soft->sadb_lifetime_addtime);
		(void) printf(gettext("%s%llu seconds of post-use lifetime.\n"),
		    soft_prefix, soft->sadb_lifetime_usetime);
		/* If possible, express values as time remaining. */
		if (current != NULL) {
			if (soft->sadb_lifetime_bytes != 0)
				(void) printf(gettext(
				    "%s%llu more bytes can be protected.\n"),
				    soft_prefix,
				    (soft->sadb_lifetime_bytes >
					current->sadb_lifetime_bytes) ?
				    (soft->sadb_lifetime_bytes -
					current->sadb_lifetime_bytes) : (0));
			if (soft->sadb_lifetime_addtime != 0 ||
			    (soft->sadb_lifetime_usetime != 0 &&
				current->sadb_lifetime_usetime != 0)) {
				int64_t adddelta, usedelta;

				if (soft->sadb_lifetime_addtime != 0) {
					adddelta =
					    current->sadb_lifetime_addtime +
					    soft->sadb_lifetime_addtime -
					    wallclock;
				} else {
					adddelta = TIME_MAX;
				}

				if (soft->sadb_lifetime_usetime != 0 &&
				    current->sadb_lifetime_usetime != 0) {
					usedelta =
					    current->sadb_lifetime_usetime +
					    soft->sadb_lifetime_usetime -
					    wallclock;
				} else {
					usedelta = TIME_MAX;
				}
				(void) printf("%s", soft_prefix);
				scratch = MIN(adddelta, usedelta);
				if (scratch >= 0) {
					(void) printf(gettext("Soft expiration "
					    "occurs in %lld seconds, "),
					    scratch);
				} else {
					(void) printf(gettext(
					    "Soft expiration occurred "));
				}
				scratch += wallclock;
				printsatime(scratch, gettext("%sat %s.\n"), "",
				    soft_prefix);
			}
		}
	}

	if (hard != NULL) {
		(void) printf(gettext("%sHard lifetime information:  "),
		    hard_prefix);
		(void) printf(gettext("%llu bytes of lifetime, "
		    "%u allocations.\n"), hard->sadb_lifetime_bytes,
		    hard->sadb_lifetime_allocations);
		(void) printf(gettext("%s%llu seconds of post-add lifetime.\n"),
		    hard_prefix, hard->sadb_lifetime_addtime);
		(void) printf(gettext("%s%llu seconds of post-use lifetime.\n"),
		    hard_prefix, hard->sadb_lifetime_usetime);
		/* If possible, express values as time remaining. */
		if (current != NULL) {
			if (hard->sadb_lifetime_bytes != 0)
				(void) printf(gettext(
				    "%s%llu more bytes can be protected.\n"),
				    hard_prefix,
				    (hard->sadb_lifetime_bytes >
					current->sadb_lifetime_bytes) ?
				    (hard->sadb_lifetime_bytes -
					current->sadb_lifetime_bytes) : (0));
			if (hard->sadb_lifetime_addtime != 0 ||
			    (hard->sadb_lifetime_usetime != 0 &&
				current->sadb_lifetime_usetime != 0)) {
				int64_t adddelta, usedelta;

				if (hard->sadb_lifetime_addtime != 0) {
					adddelta =
					    current->sadb_lifetime_addtime +
					    hard->sadb_lifetime_addtime -
					    wallclock;
				} else {
					adddelta = TIME_MAX;
				}

				if (hard->sadb_lifetime_usetime != 0 &&
				    current->sadb_lifetime_usetime != 0) {
					usedelta =
					    current->sadb_lifetime_usetime +
					    hard->sadb_lifetime_usetime -
					    wallclock;
				} else {
					usedelta = TIME_MAX;
				}
				(void) printf("%s", hard_prefix);
				scratch = MIN(adddelta, usedelta);
				if (scratch >= 0) {
					(void) printf(gettext("Hard expiration "
					    "occurs in %lld seconds, "),
					    scratch);
				} else {
					(void) printf(gettext(
					    "Hard expiration occured "));
				}
				scratch += wallclock;
				printsatime(scratch, gettext("%sat %s.\n"), "",
				    hard_prefix);
			}
		}
	}
}

/*
 * Print an SADB_EXT_ADDRESS_* extension.
 */
static void
print_address(char *prefix, struct sadb_address *addr)
{
	struct protoent *pe;

	(void) printf("%s", prefix);
	switch (addr->sadb_address_exttype) {
	case SADB_EXT_ADDRESS_SRC:
		(void) printf(gettext("Source address "));
		break;
	case SADB_EXT_ADDRESS_DST:
		(void) printf(gettext("Destination address "));
		break;
	case SADB_EXT_ADDRESS_PROXY:
		(void) printf(gettext("Proxy address "));
		break;
	case SADB_X_EXT_ADDRESS_NATT_LOC:
		(void) printf(gettext("NATT local address "));
		break;
	case SADB_X_EXT_ADDRESS_NATT_REM:
		(void) printf(gettext("NATT remote address "));
		break;
	}

	(void) printf(gettext("(proto=%d"), addr->sadb_address_proto);
	if (!nflag) {
		if (addr->sadb_address_proto == 0) {
			(void) printf(gettext("/<unspecified>"));
		} else if ((pe = getprotobynumber(addr->sadb_address_proto))
		    != NULL) {
			(void) printf("/%s", pe->p_name);
		} else {
			(void) printf(gettext("/<unknown>"));
		}
	}
	(void) printf(gettext(")\n%s"), prefix);
	(void) dump_sockaddr((struct sockaddr *)(addr + 1), B_FALSE, stdout);
}

/*
 * Print an SADB_EXT_KEY extension.
 */
static void
print_key(char *prefix, struct sadb_key *key)
{
	(void) printf("%s", prefix);

	switch (key->sadb_key_exttype) {
	case SADB_EXT_KEY_AUTH:
		(void) printf(gettext("Authentication"));
		break;
	case SADB_EXT_KEY_ENCRYPT:
		(void) printf(gettext("Encryption"));
		break;
	}

	(void) printf(gettext(" key.\n%s"), prefix);
	(void) dump_key((uint8_t *)(key + 1), key->sadb_key_bits, stdout);
	(void) putchar('\n');
}

/*
 * Print an SADB_EXT_IDENTITY_* extension.
 */
static void
print_ident(char *prefix, struct sadb_ident *id)
{
	boolean_t canprint = B_TRUE;

	(void) printf("%s", prefix);
	switch (id->sadb_ident_exttype) {
	case SADB_EXT_IDENTITY_SRC:
		(void) printf(gettext("Source"));
		break;
	case SADB_EXT_IDENTITY_DST:
		(void) printf(gettext("Destination"));
		break;
	}

	(void) printf(gettext(" identity, uid=%d, type "), id->sadb_ident_id);
	canprint = dump_sadb_idtype(id->sadb_ident_type, stdout, NULL);
	(void) printf("\n%s", prefix);
	if (canprint)
		(void) printf("%s\n", (char *)(id + 1));
	else
		(void) printf(gettext("<cannot print>\n"));
}

/*
 * Print an SADB_SENSITIVITY extension.
 */
static void
print_sens(char *prefix, struct sadb_sens *sens)
{
	uint64_t *bitmap = (uint64_t *)(sens + 1);
	int i;

	(void) printf(
	    gettext("%sSensitivity DPD %d, sens level=%d, integ level=%d\n"),
	    prefix, sens->sadb_sens_dpd, sens->sadb_sens_sens_level,
	    sens->sadb_sens_integ_level);
	for (i = 0; sens->sadb_sens_sens_len-- > 0; i++, bitmap++)
		(void) printf(
		    gettext("%s Sensitivity BM extended word %d 0x%llx\n"),
		    i, *bitmap);
	for (i = 0; sens->sadb_sens_integ_len-- > 0; i++, bitmap++)
		(void) printf(
		    gettext("%s Integrity BM extended word %d 0x%llx\n"),
		    i, *bitmap);
}

/*
 * Print an SADB_EXT_PROPOSAL extension.
 */
static void
print_prop(char *prefix, struct sadb_prop *prop)
{
	struct sadb_comb *combs;
	int i, numcombs;

	(void) printf(gettext("%sProposal, replay counter = %u.\n"), prefix,
	    prop->sadb_prop_replay);

	numcombs = prop->sadb_prop_len - SADB_8TO64(sizeof (*prop));
	numcombs /= SADB_8TO64(sizeof (*combs));

	combs = (struct sadb_comb *)(prop + 1);

	for (i = 0; i < numcombs; i++) {
		(void) printf(gettext("%s Combination #%u "), prefix, i + 1);
		if (combs[i].sadb_comb_auth != SADB_AALG_NONE) {
			(void) printf(gettext("Authentication = "));
			(void) dump_aalg(combs[i].sadb_comb_auth, stdout);
			(void) printf(gettext("  minbits=%u, maxbits=%u.\n%s "),
			    combs[i].sadb_comb_auth_minbits,
			    combs[i].sadb_comb_auth_maxbits, prefix);
		}

		if (combs[i].sadb_comb_encrypt != SADB_EALG_NONE) {
			(void) printf(gettext("Encryption = "));
			(void) dump_ealg(combs[i].sadb_comb_encrypt, stdout);
			(void) printf(gettext("  minbits=%u, maxbits=%u.\n%s "),
			    combs[i].sadb_comb_encrypt_minbits,
			    combs[i].sadb_comb_encrypt_maxbits, prefix);
		}

		(void) printf(gettext("HARD: "));
		if (combs[i].sadb_comb_hard_allocations)
			(void) printf(gettext("alloc=%u "),
			    combs[i].sadb_comb_hard_allocations);
		if (combs[i].sadb_comb_hard_bytes)
			(void) printf(gettext("bytes=%llu "),
			    combs[i].sadb_comb_hard_bytes);
		if (combs[i].sadb_comb_hard_addtime)
			(void) printf(gettext("post-add secs=%llu "),
			    combs[i].sadb_comb_hard_addtime);
		if (combs[i].sadb_comb_hard_usetime)
			(void) printf(gettext("post-use secs=%llu"),
			    combs[i].sadb_comb_hard_usetime);

		(void) printf(gettext("\n%s SOFT: "), prefix);
		if (combs[i].sadb_comb_soft_allocations)
			(void) printf(gettext("alloc=%u "),
			    combs[i].sadb_comb_soft_allocations);
		if (combs[i].sadb_comb_soft_bytes)
			(void) printf(gettext("bytes=%llu "),
			    combs[i].sadb_comb_soft_bytes);
		if (combs[i].sadb_comb_soft_addtime)
			(void) printf(gettext("post-add secs=%llu "),
			    combs[i].sadb_comb_soft_addtime);
		if (combs[i].sadb_comb_soft_usetime)
			(void) printf(gettext("post-use secs=%llu"),
			    combs[i].sadb_comb_soft_usetime);
		(void) putchar('\n');
	}
}

/*
 * Print an extended proposal (SADB_X_EXT_EPROP).
 */
static void
print_eprop(char *prefix, struct sadb_prop *eprop)
{
	uint64_t *sofar;
	struct sadb_x_ecomb *ecomb;
	struct sadb_x_algdesc *algdesc;
	int i, j;

	(void) printf(gettext("%sExtended Proposal, replay counter = %u, "),
	    prefix, eprop->sadb_prop_replay);
	(void) printf(gettext("number of combinations = %u.\n"),
	    eprop->sadb_x_prop_numecombs);

	sofar = (uint64_t *)(eprop + 1);
	ecomb = (struct sadb_x_ecomb *)sofar;

	for (i = 0; i < eprop->sadb_x_prop_numecombs; ) {
		(void) printf(gettext("%s Extended combination #%u:\n"),
		    prefix, ++i);

		(void) printf(gettext("%s HARD: "), prefix);
		(void) printf(gettext("alloc=%u, "),
		    ecomb->sadb_x_ecomb_hard_allocations);
		(void) printf(gettext("bytes=%llu, "),
		    ecomb->sadb_x_ecomb_hard_bytes);
		(void) printf(gettext("post-add secs=%llu, "),
		    ecomb->sadb_x_ecomb_hard_addtime);
		(void) printf(gettext("post-use secs=%llu\n"),
		    ecomb->sadb_x_ecomb_hard_usetime);

		(void) printf(gettext("%s SOFT: "), prefix);
		(void) printf(gettext("alloc=%u, "),
		    ecomb->sadb_x_ecomb_soft_allocations);
		(void) printf(gettext("bytes=%llu, "),
		    ecomb->sadb_x_ecomb_soft_bytes);
		(void) printf(gettext("post-add secs=%llu, "),
		    ecomb->sadb_x_ecomb_soft_addtime);
		(void) printf(gettext("post-use secs=%llu\n"),
		    ecomb->sadb_x_ecomb_soft_usetime);

		sofar = (uint64_t *)(ecomb + 1);
		algdesc = (struct sadb_x_algdesc *)sofar;

		for (j = 0; j < ecomb->sadb_x_ecomb_numalgs; ) {
			(void) printf(gettext("%s Alg #%u "), prefix, ++j);
			switch (algdesc->sadb_x_algdesc_satype) {
			case SADB_SATYPE_ESP:
				(void) printf(gettext("for ESP "));
				break;
			case SADB_SATYPE_AH:
				(void) printf(gettext("for AH "));
				break;
			default:
				(void) printf(gettext("for satype=%d "),
				    algdesc->sadb_x_algdesc_satype);
			}
			switch (algdesc->sadb_x_algdesc_algtype) {
			case SADB_X_ALGTYPE_CRYPT:
				(void) printf(gettext("Encryption = "));
				(void) dump_ealg(algdesc->sadb_x_algdesc_alg,
				    stdout);
				break;
			case SADB_X_ALGTYPE_AUTH:
				(void) printf(gettext("Authentication = "));
				(void) dump_aalg(algdesc->sadb_x_algdesc_alg,
				    stdout);
				break;
			default:
				(void) printf(gettext("algtype(%d) = alg(%d)"),
				    algdesc->sadb_x_algdesc_algtype,
				    algdesc->sadb_x_algdesc_alg);
				break;
			}

			(void) printf(gettext("  minbits=%u, maxbits=%u.\n"),
			    algdesc->sadb_x_algdesc_minbits,
			    algdesc->sadb_x_algdesc_maxbits);

			sofar = (uint64_t *)(++algdesc);
		}
		ecomb = (struct sadb_x_ecomb *)sofar;
	}
}

/*
 * Print an SADB_EXT_SUPPORTED extension.
 */
static void
print_supp(char *prefix, struct sadb_supported *supp)
{
	struct sadb_alg *algs;
	int i, numalgs;

	(void) printf(gettext("%sSupported "), prefix);
	switch (supp->sadb_supported_exttype) {
	case SADB_EXT_SUPPORTED_AUTH:
		(void) printf(gettext("authentication"));
		break;
	case SADB_EXT_SUPPORTED_ENCRYPT:
		(void) printf(gettext("encryption"));
		break;
	}
	(void) printf(gettext(" algorithms.\n"));

	algs = (struct sadb_alg *)(supp + 1);
	numalgs = supp->sadb_supported_len - SADB_8TO64(sizeof (*supp));
	numalgs /= SADB_8TO64(sizeof (*algs));
	for (i = 0; i < numalgs; i++) {
		(void) printf("%s", prefix);
		switch (supp->sadb_supported_exttype) {
		case SADB_EXT_SUPPORTED_AUTH:
			(void) dump_aalg(algs[i].sadb_alg_id, stdout);
			break;
		case SADB_EXT_SUPPORTED_ENCRYPT:
			(void) dump_ealg(algs[i].sadb_alg_id, stdout);
			break;
		}
		(void) printf(gettext(" minbits=%u, maxbits=%u, ivlen=%u.\n"),
		    algs[i].sadb_alg_minbits, algs[i].sadb_alg_maxbits,
		    algs[i].sadb_alg_ivlen);
	}
}

/*
 * Print an SADB_EXT_SPIRANGE extension.
 */
static void
print_spirange(char *prefix, struct sadb_spirange *range)
{
	(void) printf(gettext("%sSPI Range, min=0x%x, max=0x%x\n"), prefix,
	    htonl(range->sadb_spirange_min),
	    htonl(range->sadb_spirange_max));
}

/*
 * Print an SADB_X_EXT_KM_COOKIE extension.
 */

static void
print_kmc(char *prefix, struct sadb_x_kmc *kmc)
{
	char *cookie_label;

	if ((cookie_label = kmc_lookup_by_cookie(kmc->sadb_x_kmc_cookie)) ==
	    NULL)
		cookie_label = gettext("<Label not found.>");

	(void) printf(gettext("%sProtocol %u, cookie=\"%s\" (%u)\n"), prefix,
	    kmc->sadb_x_kmc_proto, cookie_label, kmc->sadb_x_kmc_cookie);
}

/*
 * Take a PF_KEY message pointed to buffer and print it.  Useful for DUMP
 * and GET.
 */
static void
print_samsg(uint64_t *buffer, boolean_t want_timestamp)
{
	uint64_t *current;
	struct sadb_msg *samsg = (struct sadb_msg *)buffer;
	struct sadb_ext *ext;
	struct sadb_lifetime *currentlt = NULL, *hardlt = NULL, *softlt = NULL;
	int i;
	time_t wallclock;

	(void) time(&wallclock);

	print_sadb_msg(samsg, want_timestamp ? wallclock : 0);
	current = (uint64_t *)(samsg + 1);
	while (current - buffer < samsg->sadb_msg_len) {
		int lenbytes;

		ext = (struct sadb_ext *)current;
		lenbytes = SADB_64TO8(ext->sadb_ext_len);
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			print_sa(gettext("SA: "), (struct sadb_sa *)current);
			break;
		/*
		 * Pluck out lifetimes and print them at the end.  This is
		 * to show relative lifetimes.
		 */
		case SADB_EXT_LIFETIME_CURRENT:
			currentlt = (struct sadb_lifetime *)current;
			break;
		case SADB_EXT_LIFETIME_HARD:
			hardlt = (struct sadb_lifetime *)current;
			break;
		case SADB_EXT_LIFETIME_SOFT:
			softlt = (struct sadb_lifetime *)current;
			break;

		case SADB_EXT_ADDRESS_SRC:
			print_address(gettext("SRC: "),
			    (struct sadb_address *)current);
			break;
		case SADB_EXT_ADDRESS_DST:
			print_address(gettext("DST: "),
			    (struct sadb_address *)current);
			break;
		case SADB_EXT_ADDRESS_PROXY:
			print_address(gettext("PXY: "),
			    (struct sadb_address *)current);
			break;
		case SADB_EXT_KEY_AUTH:
			print_key(gettext("AKY: "), (struct sadb_key *)current);
			break;
		case SADB_EXT_KEY_ENCRYPT:
			print_key(gettext("EKY: "), (struct sadb_key *)current);
			break;
		case SADB_EXT_IDENTITY_SRC:
			print_ident(gettext("SID: "),
			    (struct sadb_ident *)current);
			break;
		case SADB_EXT_IDENTITY_DST:
			print_ident(gettext("DID: "),
			    (struct sadb_ident *)current);
			break;
		case SADB_EXT_SENSITIVITY:
			print_sens(gettext("SNS: "),
			    (struct sadb_sens *)current);
			break;
		case SADB_EXT_PROPOSAL:
			print_prop(gettext("PRP: "),
			    (struct sadb_prop *)current);
			break;
		case SADB_EXT_SUPPORTED_AUTH:
			print_supp(gettext("SUA: "),
			    (struct sadb_supported *)current);
			break;
		case SADB_EXT_SUPPORTED_ENCRYPT:
			print_supp(gettext("SUE: "),
			    (struct sadb_supported *)current);
			break;
		case SADB_EXT_SPIRANGE:
			print_spirange(gettext("SPR: "),
			    (struct sadb_spirange *)current);
			break;
		case SADB_X_EXT_EPROP:
			print_eprop(gettext("EPR: "),
			    (struct sadb_prop *)current);
			break;
		case SADB_X_EXT_KM_COOKIE:
			print_kmc(gettext("KMC: "),
			    (struct sadb_x_kmc *)current);
			break;
		case SADB_X_EXT_ADDRESS_NATT_REM:
			print_address(gettext("NRM: "),
			    (struct sadb_address *)current);
			break;
		case SADB_X_EXT_ADDRESS_NATT_LOC:
			print_address(gettext("NLC: "),
			    (struct sadb_address *)current);
			break;
		default:
			(void) printf(gettext(
			    "UNK: Unknown ext. %d, len %d.\n"),
			    ext->sadb_ext_type, lenbytes);
			for (i = 0; i < ext->sadb_ext_len; i++)
				(void) printf(gettext("UNK: 0x%llx\n"),
				    ((uint64_t *)ext)[i]);
			break;
		}
		current += ext->sadb_ext_len;
	}
	/*
	 * Print lifetimes NOW.
	 */
	if (currentlt != NULL || hardlt != NULL || softlt != NULL)
		print_lifetimes(wallclock, currentlt, hardlt, softlt);

	if (current - buffer != samsg->sadb_msg_len) {
		warnx(gettext("WARNING: insufficient buffer "
			"space or corrupt message."));
	}

	(void) fflush(stdout);	/* Make sure our message is out there. */
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
		print_samsg(msg, B_FALSE);
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
 * Print save information for a lifetime extension.
 *
 * NOTE : It saves the lifetime in absolute terms.  For example, if you
 * had a hard_usetime of 60 seconds, you'll save it as 60 seconds, even though
 * there may have been 59 seconds burned off the clock.
 */
static boolean_t
save_lifetime(struct sadb_lifetime *lifetime, FILE *ofile)
{
	char *prefix;

	prefix = (lifetime->sadb_lifetime_exttype == SADB_EXT_LIFETIME_SOFT) ?
	    "soft" : "hard";

	if (putc('\t', ofile) == EOF)
		return (B_FALSE);

	if (lifetime->sadb_lifetime_allocations != 0 && fprintf(ofile,
	    "%s_alloc %u ", prefix, lifetime->sadb_lifetime_allocations) < 0)
		return (B_FALSE);

	if (lifetime->sadb_lifetime_bytes != 0 && fprintf(ofile,
	    "%s_bytes %llu ", prefix, lifetime->sadb_lifetime_bytes) < 0)
		return (B_FALSE);

	if (lifetime->sadb_lifetime_addtime != 0 && fprintf(ofile,
	    "%s_addtime %llu ", prefix, lifetime->sadb_lifetime_addtime) < 0)
		return (B_FALSE);

	if (lifetime->sadb_lifetime_usetime != 0 && fprintf(ofile,
	    "%s_usetime %llu ", prefix, lifetime->sadb_lifetime_usetime) < 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Print save information for an address extension.
 */
static boolean_t
save_address(struct sadb_address *addr, FILE *ofile)
{
	char *printable_addr, buf[INET6_ADDRSTRLEN];
	const char *prefix, *pprefix;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(addr + 1);
	struct sockaddr_in *sin = (struct sockaddr_in *)sin6;
	int af = sin->sin_family;

	/*
	 * Address-family reality check.
	 */
	if (af != AF_INET6 && af != AF_INET)
		return (B_FALSE);

	switch (addr->sadb_address_exttype) {
	case SADB_EXT_ADDRESS_SRC:
		prefix = "src";
		pprefix = "sport";
		break;
	case SADB_EXT_ADDRESS_DST:
		prefix = "dst";
		pprefix = "dport";
		break;
	case SADB_EXT_ADDRESS_PROXY:
		prefix = "proxy";
		pprefix = NULL;
		break;
	case SADB_X_EXT_ADDRESS_NATT_LOC:
		prefix = "nat_loc ";
		pprefix = "nat_lport";
		break;
	case SADB_X_EXT_ADDRESS_NATT_REM:
		prefix = "nat_rem ";
		pprefix = "nat_rport";
		break;
	}

	if (fprintf(ofile, "    %s ", prefix) < 0)
		return (B_FALSE);

	/*
	 * Do not do address-to-name translation, given that we live in
	 * an age of names that explode into many addresses.
	 */
	printable_addr = (char *)inet_ntop(af,
	    (af == AF_INET) ? (char *)&sin->sin_addr : (char *)&sin6->sin6_addr,
	    buf, sizeof (buf));
	if (printable_addr == NULL)
		printable_addr = "<inet_ntop() failed>";
	if (fprintf(ofile, "%s", printable_addr) < 0)
		return (B_FALSE);

	/*
	 * The port is in the same position for struct sockaddr_in and
	 * struct sockaddr_in6.  We exploit that property here.
	 */
	if ((pprefix != NULL) && (sin->sin_port != 0))
		(void) fprintf(ofile, " %s %d", pprefix, ntohs(sin->sin_port));

	return (B_TRUE);
}

/*
 * Print save information for a key extension. Returns whether writing
 * to the specified output file was successful or not.
 */
static boolean_t
save_key(struct sadb_key *key, FILE *ofile)
{
	char *prefix;

	if (putc('\t', ofile) == EOF)
		return (B_FALSE);

	prefix = (key->sadb_key_exttype == SADB_EXT_KEY_AUTH) ? "auth" : "encr";

	if (fprintf(ofile, "%skey ", prefix) < 0)
		return (B_FALSE);

	if (dump_key((uint8_t *)(key + 1), key->sadb_key_bits, ofile) == -1)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Print save information for an identity extension.
 */
static boolean_t
save_ident(struct sadb_ident *ident, FILE *ofile)
{
	char *prefix;

	if (putc('\t', ofile) == EOF)
		return (B_FALSE);

	prefix = (ident->sadb_ident_exttype == SADB_EXT_IDENTITY_SRC) ? "src" :
	    "dst";

	if (fprintf(ofile, "%sidtype %s ", prefix,
	    rparseidtype(ident->sadb_ident_type)) < 0)
		return (B_FALSE);

	if (ident->sadb_ident_type == SADB_X_IDENTTYPE_DN ||
	    ident->sadb_ident_type == SADB_X_IDENTTYPE_GN) {
		if (fprintf(ofile, gettext("<can-not-print>")) < 0)
			return (B_FALSE);
	} else {
		if (fprintf(ofile, "%s", (char *)(ident + 1)) < 0)
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * "Save" a security association to an output file.
 *
 * NOTE the lack of calls to gettext() because I'm outputting parseable stuff.
 * ALSO NOTE that if you change keywords (see parsecmd()), you'll have to
 * change them here as well.
 */
static void
save_assoc(uint64_t *buffer, FILE *ofile)
{
	int seen_proto = 0;
	uint64_t *current;
	struct sadb_address *addr;
	struct sadb_msg *samsg = (struct sadb_msg *)buffer;
	struct sadb_ext *ext;
#define	bail2(s)	do { \
				int t = errno; \
				(void) fclose(ofile); \
				errno = t; \
				interactive = B_FALSE;	/* Guarantees exit. */ \
				Bail(s); \
			} while (B_FALSE)	/* How do I lint-clean this? */

#define	savenl() if (fputs(" \\\n", ofile) == EOF) { bail2("savenl"); }

	if (fputs("# begin assoc\n", ofile) == EOF)
		Bail("save_assoc: Opening comment of SA");
	if (fprintf(ofile, "add %s ", rparsesatype(samsg->sadb_msg_satype)) < 0)
		Bail("save_assoc: First line of SA");
	/* LINTED E_CONST_COND */
	savenl();

	current = (uint64_t *)(samsg + 1);
	while (current - buffer < samsg->sadb_msg_len) {
		struct sadb_sa *assoc;

		ext = (struct sadb_ext *)current;
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
			assoc = (struct sadb_sa *)ext;
			if (assoc->sadb_sa_state != SADB_SASTATE_MATURE) {
				if (fprintf(ofile, "# WARNING: SA was dying "
				    "or dead.\n") < 0) {
					/* LINTED E_CONST_COND */
					bail2("save_assoc: fprintf not mature");
				}
			}
			if (fprintf(ofile, "    spi 0x%x ",
			    ntohl(assoc->sadb_sa_spi)) < 0)
				/* LINTED E_CONST_COND */
				bail2("save_assoc: fprintf spi");
			if (fprintf(ofile, "encr_alg %s ",
			    rparsealg(assoc->sadb_sa_encrypt,
				IPSEC_PROTO_ESP)) < 0)
				/* LINTED E_CONST_COND */
				bail2("save_assoc: fprintf encrypt");
			if (fprintf(ofile, "auth_alg %s ",
			    rparsealg(assoc->sadb_sa_auth,
				IPSEC_PROTO_AH)) < 0)
				/* LINTED E_CONST_COND */
				bail2("save_assoc: fprintf auth");
			if (fprintf(ofile, "replay %d ",
			    assoc->sadb_sa_replay) < 0)
				/* LINTED E_CONST_COND */
				bail2("save_assoc: fprintf replay");
			if (assoc->sadb_sa_flags & (SADB_X_SAFLAGS_NATT_LOC |
			    SADB_X_SAFLAGS_NATT_REM)) {
				if (fprintf(ofile, "encap udp") < 0)
					/* LINTED E_CONST_COND */
					bail2("save_assoc: fprintf encap");
			}
			/* LINTED E_CONST_COND */
			savenl();
			break;
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
			if (!save_lifetime((struct sadb_lifetime *)ext, ofile))
				/* LINTED E_CONST_COND */
				bail2("save_lifetime");
			/* LINTED E_CONST_COND */
			savenl();
			break;
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_X_EXT_ADDRESS_NATT_REM:
		case SADB_X_EXT_ADDRESS_NATT_LOC:
			addr = (struct sadb_address *)ext;
			if (!seen_proto && addr->sadb_address_proto) {
				(void) fprintf(ofile, "    proto %d",
				    addr->sadb_address_proto);
				/* LINTED E_CONST_COND */
				savenl();
				seen_proto = 1;
			}
			if (!save_address(addr, ofile))
				/* LINTED E_CONST_COND */
				bail2("save_address");
			/* LINTED E_CONST_COND */
			savenl();
			break;
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
			if (!save_key((struct sadb_key *)ext, ofile))
				/* LINTED E_CONST_COND */
				bail2("save_address");
			/* LINTED E_CONST_COND */
			savenl();
			break;
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
			if (!save_ident((struct sadb_ident *)ext, ofile))
				/* LINTED E_CONST_COND */
				bail2("save_address");
			/* LINTED E_CONST_COND */
			savenl();
			break;
		case SADB_EXT_SENSITIVITY:
		default:
			/* Skip over irrelevant extensions. */
			break;
		}
		current += ext->sadb_ext_len;
	}

	if (fputs(gettext("\n# end assoc\n\n"), ofile) == EOF)
		/* LINTED E_CONST_COND */
		bail2("save_assoc: last fputs");
}

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
				print_samsg(get_buffer, B_FALSE);
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
 * dstport: destination port is specified
 * proto: IP protocol number if specified
 * NATT note: we are going to assume a semi-sane world where NAT
 * boxen don't explode to multiple addresses.
 */
static void
doaddresses(uint8_t sadb_msg_type, uint8_t sadb_msg_satype, int cmd,
    struct hostent *srchp, struct hostent *dsthp,
    struct sadb_address *src, struct sadb_address *dst,
    boolean_t unspec_src, uint64_t *buffer, int buffer_size, uint32_t spi,
    uint16_t srcport, uint16_t dstport, uint16_t proto,
    struct hostent *natt_lhp, struct hostent *natt_rhp,
    struct sadb_address *natt_loc, struct sadb_address *natt_rem,
    uint16_t natt_lport, uint16_t natt_rport)
{
	boolean_t single_dst;
	struct sockaddr_in6 *sin6;
	struct sadb_msg *msgp;
	int i, rc;
	char **walker;	/* For the SRC and PROXY walking functions. */
	char *first_match;
	uint64_t savebuf[SADB_8TO64(MAX_GET_SIZE)];

	/*
	 * Okay, now we have "src", "dst", and maybe "proxy" reassigned
	 * to point into the buffer to be written to PF_KEY, we can do
	 * potentially several writes based on destination address.
	 *
	 * First, fill in port numbers and protocol in extensions.
	 */

	if ((proto == 0) && ((srcport != 0) || (dstport != 0))) {
		warnx(gettext("WARNING: ports without proto is nonsensical."));
		/*
		 * Don't worry about it, it just may make the SA not match
		 * any outbound traffic, or it perhaps could be perverted
		 * by the kernel to cover both TCP and UDP traffic on the
		 * same port (e.g. DNS).
		 */
	}

	if (src != NULL) {
		src->sadb_address_proto = proto;
		sin6 = (struct sockaddr_in6 *)(src + 1);
		sin6->sin6_port = htons(srcport);
	}
	if (dst != NULL) {
		dst->sadb_address_proto = proto;
		sin6 = (struct sockaddr_in6 *)(dst + 1);
		sin6->sin6_port = htons(dstport);
	}
	if (natt_loc != NULL) {
		sin6 = (struct sockaddr_in6 *)(natt_loc + 1);
		bzero(sin6, sizeof (*sin6));
		bcopy(natt_lhp->h_addr_list[0], &sin6->sin6_addr,
		    sizeof (struct in6_addr));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(natt_lport);
	}
	if (natt_rem != NULL) {
		sin6 = (struct sockaddr_in6 *)(natt_rem + 1);
		bzero(sin6, sizeof (*sin6));
		bcopy(natt_rhp->h_addr_list[0], &sin6->sin6_addr,
		    sizeof (struct in6_addr));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(natt_rport);
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
	 * If dsthp is == dummy.he, then go through the loop once.
	 * If any other hp is == dummy.he, then you don't have to apply any
	 * silly rules.
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
					warnx(gettext("One of the entered "
						"values is incorrect."));
					print_diagnostic(stderr,
					    msgp->sadb_x_msg_diagnostic);
				}
				Bail("return message (in doaddresses)");
			}

			/* ...and then restore the saved buffer. */
			msgp = (struct sadb_msg *)savebuf;
			bcopy(savebuf, buffer, SADB_64TO8(msgp->sadb_msg_len));
		} while (srchp != NULL && srchp->h_addr_list[++i] != NULL);
		return;
	}

	single_dst = (dsthp == &dummy.he || dsthp->h_addr_list[1] == NULL);

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
					 * No IPv4 hits.  Is this a single
					 * dest?
					 */
					warnx(gettext(
					    "No IPv4 source address "
					    "for name %s."), srchp->h_name);
					if (single_dst) {
						/* Error. */
						usage();
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
					warnx(gettext(
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
					 * No IPv6 hits.  Is this a single
					 * dest?
					 */
					warnx(gettext(
					    "No IPv6 source address of "
					    "matching scope for name %s."),
					    srchp->h_name);
					if (single_dst) {
						/* Error. */
						usage();
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
					warnx(gettext(
					    "Multiple IPv6 source addresses "
					    "for %s of the same scope, using "
					    "unspecified source instead."),
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

		/* Save off a copy for later writing... */
		msgp = (struct sadb_msg *)buffer;
		bcopy(buffer, savebuf, SADB_64TO8(msgp->sadb_msg_len));

		rc = key_write(keysock, buffer, SADB_64TO8(msgp->sadb_msg_len));
		if (rc == -1)
			Bail("write() to PF_KEY socket (in doaddresses)");

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
				warnx(gettext("Association (type = %s) "
				    "with spi 0x%x and addr\n%s %s."),
				    rparsesatype(msgp->sadb_msg_satype),
				    ntohl(spi),
				    do_inet_ntop(dsthp->h_addr_list[i],
					addrprint, sizeof (addrprint)),
				    on_errno_msg);
				msgp = (struct sadb_msg *)savebuf;
				bcopy(savebuf, buffer,
				    SADB_64TO8(msgp->sadb_msg_len));
				continue;
			} else {
				if (errno == EINVAL) {
					warnx(gettext("One of the entered "
						"values is incorrect."));
					print_diagnostic(stderr,
					    msgp->sadb_x_msg_diagnostic);
				}
				Bail("return message (in doaddresses)");
			}
		}
		if (cmd == CMD_GET) {
			if (SADB_64TO8(msgp->sadb_msg_len) > MAX_GET_SIZE) {
				warnx(gettext("WARNING:  "
				    "SA information bigger than %d bytes."),
				    MAX_GET_SIZE);
			}
			print_samsg(buffer, B_FALSE);
		}

		/* ...and then restore the saved buffer. */
		msgp = (struct sadb_msg *)savebuf;
		bcopy(savebuf, buffer, SADB_64TO8(msgp->sadb_msg_len));
	}

	/* Degenerate case, h_addr_list[0] == NULL. */
	if (i == 0)
		Bail("Empty destination address list");
}

/*
 * Perform an add or an update.  ADD and UPDATE are similar in the extensions
 * they need.
 */
static void
doaddup(int cmd, int satype, char *argv[])
{
	uint64_t *buffer, *nexthdr;
	struct sadb_msg msg;
	struct sadb_sa *assoc = NULL;
	struct sadb_address *src = NULL, *dst = NULL, *proxy = NULL;
	struct sadb_address *natt_local = NULL, *natt_remote = NULL;
	struct sadb_key *encrypt = NULL, *auth = NULL;
	struct sadb_ident *srcid = NULL, *dstid = NULL;
	struct sadb_lifetime *hard = NULL, *soft = NULL;  /* Current? */
	struct sockaddr_in6 *sin6;
	/* MLS TODO:  Need sensitivity eventually. */
	int next, token, sa_len, alloclen, totallen = sizeof (msg);
	uint32_t spi;
	char *thiscmd;
	boolean_t readstate = B_FALSE, unspec_src = B_FALSE, use_natt = B_FALSE;
	struct hostent *srchp = NULL, *dsthp = NULL, *proxyhp = NULL;
	struct hostent *natt_lhp = NULL, *natt_rhp = NULL;
	uint16_t srcport = 0, dstport = 0, natt_lport = 0, natt_rport = 0;
	uint8_t proto = 0;

	thiscmd = (cmd == CMD_ADD) ? "add" : "update";

	msg_init(&msg, ((cmd == CMD_ADD) ? SADB_ADD : SADB_UPDATE),
	    (uint8_t)satype);

	/* Assume last element in argv is set to NULL. */
	do {
		token = parseextval(*argv, &next);
		argv++;
		switch (token) {
		case TOK_EOF:
			/* Do nothing, I'm done. */
			break;
		case TOK_UNKNOWN:
			warnx(gettext("Unknown extension field %s."),
			    *(argv - 1));
			usage();	/* Will exit program. */
			break;
		case TOK_SPI:
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
				 * If some cretin types in "spi 0" then he/she
				 * can type in another SPI.
				 */
				if (assoc->sadb_sa_spi != 0) {
					warnx(gettext("Can only specify "
						"single SPI value."));
					usage();
				}
				/* Must convert SPI to network order! */
				assoc->sadb_sa_spi =
				    htonl((uint32_t)parsenum(*argv, B_TRUE));
				break;
			case TOK_REPLAY:
				/*
				 * That same cretin can do the same with
				 * replay.
				 */
				if (assoc->sadb_sa_replay != 0) {
					warnx(gettext("Can only specify "
						"single replay wsize."));
					usage();
				}
				assoc->sadb_sa_replay =
				    (uint8_t)parsenum(*argv, B_TRUE);
				if (assoc->sadb_sa_replay != 0) {
					warnx(gettext(
					    "WARNING:  Replay with manual"
					    " keying considered harmful."));
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
					warnx(gettext("Can only specify "
						"single SA state."));
					usage();
				}
				assoc->sadb_sa_state = parsestate(*argv);
				readstate = B_TRUE;
				break;
			case TOK_AUTHALG:
				if (assoc->sadb_sa_auth != 0) {
					warnx(gettext("Can only specify "
						"single auth algorithm."));
					usage();
				}
				assoc->sadb_sa_auth = parsealg(*argv,
				    IPSEC_PROTO_AH);
				break;
			case TOK_ENCRALG:
				if (assoc->sadb_sa_encrypt != 0) {
					warnx(gettext("Can only specify single"
						" encryption algorithm."));
					usage();
				}
				assoc->sadb_sa_encrypt = parsealg(*argv,
				    IPSEC_PROTO_ESP);
				break;
			case TOK_ENCAP:
				if (use_natt) {
					warnx(gettext("Can only specify single"
					    " encapsulation."));
					usage();
				}
				if (strncmp(*argv, "udp", 3)) {
					warnx(gettext("Can only specify udp"
					    " encapsulation."));
					usage();
				}
				use_natt = B_TRUE;
				/* set assoc flags later */
				break;
			}
			argv++;
			break;
		case TOK_SRCPORT:
			if (srcport != 0) {
				warnx(gettext("Can only specify "
					"single source port."));
				usage();
			}
			srcport = parsenum(*argv, B_TRUE);
			argv++;
			break;
		case TOK_DSTPORT:
			if (dstport != 0) {
				warnx(gettext("Can only specify "
				    "single destination port."));
				usage();
			}
			dstport = parsenum(*argv, B_TRUE);
			argv++;
			break;
		case TOK_NATLPORT:
			if (natt_lport != 0) {
				warnx(gettext("Can only specify "
				    "single natt local port."));
				usage();
			}

			if (natt_rport != 0) {
				warnx(gettext("Can only specify "
				    "one of natt remote and local port."));
				usage();
			}
			natt_lport = parsenum(*argv, B_TRUE);
			argv++;
			break;
		case TOK_NATRPORT:
			if (natt_rport != 0) {
				warnx(gettext("Can only specify "
				    "single natt remote port."));
				usage();
			}

			if (natt_lport != 0) {
				warnx(gettext("Can only specify "
				    "one of natt remote and local port."));
				usage();
			}
			natt_rport = parsenum(*argv, B_TRUE);
			argv++;
			break;

		case TOK_PROTO:
			if (proto != 0) {
				warnx(gettext("Can only specify "
				    "single protocol."));
				usage();
			}
			proto = parsenum(*argv, B_TRUE);
			argv++;
			break;
		case TOK_SRCADDR:
		case TOK_SRCADDR6:
			if (src != NULL) {
				warnx(gettext("Can only specify "
					"single source address."));
				usage();
			}
			sa_len = parseaddr(*argv, &srchp,
			    (token == TOK_SRCADDR6));
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
				warnx(gettext("Can only specify single "
				    "destination address."));
				usage();
			}
			sa_len = parseaddr(*argv, &dsthp,
			    (token == TOK_DSTADDR6));
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
			if (proxy != NULL) {
				warnx(gettext("Can only specify single "
					"proxy address."));
				usage();
			}
			sa_len = parseaddr(*argv, &proxyhp,
			    (token == TOK_PROXYADDR6));
			argv++;
			alloclen = sizeof (*proxy) + roundup(sa_len, 8);
			proxy = malloc(alloclen);
			if (proxy == NULL)
				Bail("malloc(proxy)");
			totallen += alloclen;
			proxy->sadb_address_len = SADB_8TO64(alloclen);
			proxy->sadb_address_exttype = SADB_EXT_ADDRESS_PROXY;
			proxy->sadb_address_reserved = 0;
			proxy->sadb_address_prefixlen = 0;
			proxy->sadb_address_proto = 0;
			if (proxyhp == &dummy.he ||
			    proxyhp->h_addr_list[1] == NULL) {
				/*
				 * Single address with -n flag or single name.
				 */
				sin6 = (struct sockaddr_in6 *)(proxy + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(proxyhp->h_addr_list[0], &sin6->sin6_addr,
				    sizeof (struct in6_addr));
			} else {
				/*
				 * If the proxy address is vague, don't bother.
				 */
				totallen -= alloclen;
				free(proxy);
				proxy = NULL;
				warnx(gettext("Proxy address %s is vague, not"
					" using."), proxyhp->h_name);
				freehostent(proxyhp);
				proxyhp = NULL;
			}
			break;
		case TOK_NATLOC:
			if (natt_local != NULL) {
				warnx(gettext("Can only specify "
					"single natt local address."));
				usage();
			}
			sa_len = parseaddr(*argv, &natt_lhp, 0);
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
			if (natt_lhp == &dummy.he) {
				/*
				 * Single address with -n flag.
				 */
				sin6 = (struct sockaddr_in6 *)(natt_local + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(natt_lhp->h_addr_list[0],
				    &sin6->sin6_addr, sizeof (struct in6_addr));
			}
			break;
		case TOK_NATREM:
			if (natt_remote != NULL) {
				warnx(gettext("Can only specify "
					"single natt remote address."));
				usage();
			}
			sa_len = parseaddr(*argv, &natt_rhp, 0);
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
			if (natt_rhp == &dummy.he) {
				/*
				 * Single address with -n flag.
				 */
				sin6 = (struct sockaddr_in6 *)(natt_remote + 1);
				bzero(sin6, sizeof (*sin6));
				sin6->sin6_family = AF_INET6;
				bcopy(natt_rhp->h_addr_list[0],
				    &sin6->sin6_addr, sizeof (struct in6_addr));
			}
			break;
		case TOK_ENCRKEY:
			if (encrypt != NULL) {
				warnx(gettext("Can only specify "
					"single encryption key."));
				usage();
			}
			encrypt = parsekey(*argv);
			totallen += SADB_64TO8(encrypt->sadb_key_len);
			argv++;
			encrypt->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
			break;
		case TOK_AUTHKEY:
			if (auth != NULL) {
				warnx(gettext("Can only specify single"
					" authentication key."));
				usage();
			}
			auth = parsekey(*argv);
			argv++;
			totallen += SADB_64TO8(auth->sadb_key_len);
			auth->sadb_key_exttype = SADB_EXT_KEY_AUTH;
			break;
		case TOK_SRCIDTYPE:
			if (*argv == NULL || *(argv + 1) == NULL) {
				warnx(gettext("Unexpected end of command "
					"line."));
				usage();
			}
			if (srcid != NULL) {
				warnx(gettext("Can only specify single"
					" source certificate identity."));
				usage();
			}
			alloclen = sizeof (*srcid) +
			    roundup(strlen(*(argv + 1)) + 1, 8);
			srcid = malloc(alloclen);
			if (srcid == NULL)
				Bail("malloc(srcid)");
			totallen += alloclen;
			srcid->sadb_ident_type = parseidtype(*argv);
			argv++;
			srcid->sadb_ident_len = SADB_8TO64(alloclen);
			srcid->sadb_ident_exttype = SADB_EXT_IDENTITY_SRC;
			srcid->sadb_ident_reserved = 0;
			srcid->sadb_ident_id = 0;  /* Not useful here. */
			/* Can use strcpy because I allocate my own memory. */
			(void) strcpy((char *)(srcid + 1), *argv);
			argv++;
			break;
		case TOK_DSTIDTYPE:
			if (*argv == NULL || *(argv + 1) == NULL) {
				warnx(gettext("Unexpected end of command"
					" line."));
				usage();
			}
			if (dstid != NULL) {
				warnx(gettext("Can only specify single destina"
					"tion certificate identity."));
				usage();
			}
			alloclen = sizeof (*dstid) +
			    roundup(strlen(*(argv + 1)) + 1, 8);
			dstid = malloc(alloclen);
			if (dstid == NULL)
				Bail("malloc(dstid)");
			totallen += alloclen;
			dstid->sadb_ident_type = parseidtype(*argv);
			argv++;
			dstid->sadb_ident_len = SADB_8TO64(alloclen);
			dstid->sadb_ident_exttype = SADB_EXT_IDENTITY_DST;
			dstid->sadb_ident_reserved = 0;
			dstid->sadb_ident_id = 0;  /* Not useful here. */
			/* Can use strcpy because I allocate my own memory. */
			(void) strcpy((char *)(dstid + 1), *argv);
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
					warnx(gettext("Can only specify single"
						" hard allocation limit."));
					usage();
				}
				hard->sadb_lifetime_allocations =
				    (uint32_t)parsenum(*argv, B_TRUE);
				break;
			case TOK_HARD_BYTES:
				if (hard->sadb_lifetime_bytes != 0) {
					warnx(gettext("Can only specify "
						"single hard byte limit."));
					usage();
				}
				hard->sadb_lifetime_bytes = parsenum(*argv,
				    B_TRUE);
				break;
			case TOK_HARD_ADDTIME:
				if (hard->sadb_lifetime_addtime != 0) {
					warnx(gettext("Can only specify "
						"single past-add lifetime."));
					usage();
				}
				hard->sadb_lifetime_addtime = parsenum(*argv,
				    B_TRUE);
				break;
			case TOK_HARD_USETIME:
				if (hard->sadb_lifetime_usetime != 0) {
					warnx(gettext("Can only specify "
						"single past-use lifetime."));
					usage();
				}
				hard->sadb_lifetime_usetime = parsenum(*argv,
				    B_TRUE);
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
					warnx(gettext("Can only specify single"
						" soft allocation limit."));
					usage();
				}
				soft->sadb_lifetime_allocations =
				    (uint32_t)parsenum(*argv, B_TRUE);
				break;
			case TOK_SOFT_BYTES:
				if (soft->sadb_lifetime_bytes != 0) {
					warnx(gettext("Can only specify single"
						" soft byte limit."));
					usage();
				}
				soft->sadb_lifetime_bytes = parsenum(*argv,
				    B_TRUE);
				break;
			case TOK_SOFT_ADDTIME:
				if (soft->sadb_lifetime_addtime != 0) {
					warnx(gettext("Can only specify single"
						" past-add lifetime."));
					usage();
				}
				soft->sadb_lifetime_addtime = parsenum(*argv,
				    B_TRUE);
				break;
			case TOK_SOFT_USETIME:
				if (soft->sadb_lifetime_usetime != 0) {
					warnx(gettext("Can only specify single"
						" past-use lifetime."));
					usage();
				}
				soft->sadb_lifetime_usetime = parsenum(*argv,
				    B_TRUE);
				break;
			}
			argv++;
			break;
		default:
			warnx(gettext("Don't use extension %s for add/update."),
			    *(argv - 1));
			usage();
			break;
		}
	} while (token != TOK_EOF);

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
			warnx(gettext("The SPI value is missing for "
				"the association you wish to %s."), thiscmd);
			usage();
		}
		if (assoc->sadb_sa_auth == 0 && assoc->sadb_sa_encrypt == 0 &&
			cmd == CMD_ADD) {
			warnx(gettext("Select at least one algorithm "
				"for this add."));
			usage();
		}

		/* Hack to let user specify NULL ESP implicitly. */
		if (msg.sadb_msg_satype == SADB_SATYPE_ESP &&
		    assoc->sadb_sa_encrypt == 0)
			assoc->sadb_sa_encrypt = SADB_EALG_NULL;

		/* 0 is an actual value.  Print a warning if it was entered. */
		if (assoc->sadb_sa_state == 0) {
			if (readstate)
				warnx(gettext(
				    "WARNING: Cannot set LARVAL SA state."));
			assoc->sadb_sa_state = SADB_SASTATE_MATURE;
		}

		if (use_natt) {
			if (natt_remote != NULL)
				assoc->sadb_sa_flags |= SADB_X_SAFLAGS_NATT_REM;
			if (natt_local != NULL)
				assoc->sadb_sa_flags |= SADB_X_SAFLAGS_NATT_LOC;
		}

		bcopy(assoc, nexthdr, SADB_64TO8(assoc->sadb_sa_len));
		nexthdr += assoc->sadb_sa_len;
		/* Save the SPI for the case of an error. */
		spi = assoc->sadb_sa_spi;
		free(assoc);
	} else {
		warnx(gettext("Need SA parameters for %s."), thiscmd);
		usage();
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

	if (encrypt == NULL && auth == NULL && cmd == CMD_ADD) {
		warnx(gettext("Must have at least one key for an add."));
		usage();
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
		nexthdr += dst->sadb_address_len;
	} else {
		warnx(gettext("Need destination address for %s."), thiscmd);
		usage();
	}

	if (use_natt) {
		if (natt_remote == NULL && natt_local == NULL) {
			warnx(gettext(
			    "Must specify natt remote or local address "
			    "for UDP encapsulation."));
			usage();
		}

		if (natt_lport != 0 && natt_local == NULL) {
			warnx(gettext("If natt local port is specified, natt "
			    "local address must also be specified."));
			usage();
		}

		if (natt_rport != 0 && natt_remote == NULL) {
			warnx(gettext("If natt remote port is specified, natt "
			    "remote address must also be specified."));
			usage();
		}

		if (natt_remote != NULL) {
			free(natt_remote);
			natt_remote = (struct sadb_address *)nexthdr;
			nexthdr += natt_remote->sadb_address_len;
		}
		if (natt_local != NULL) {
			bcopy(natt_local, nexthdr,
			    SADB_64TO8(natt_local->sadb_address_len));
			free(natt_local);
			natt_local = (struct sadb_address *)nexthdr;
			nexthdr += natt_local->sadb_address_len;
		}
	}
	/*
	 * PF_KEY requires a source address extension, even if the source
	 * address itself is unspecified. (See "Set explicit unspecified..."
	 * code fragment above. Destination reality check was above.)
	 */
	bcopy(src, nexthdr, SADB_64TO8(src->sadb_address_len));
	free(src);
	src = (struct sadb_address *)nexthdr;
	nexthdr += src->sadb_address_len;

	if (proxy != NULL) {
		bcopy(proxy, nexthdr, SADB_64TO8(proxy->sadb_address_len));
		free(proxy);
		proxy = (struct sadb_address *)nexthdr;
		nexthdr += proxy->sadb_address_len;
	}

	doaddresses((cmd == CMD_ADD) ? SADB_ADD : SADB_UPDATE, satype, cmd,
	    srchp, dsthp, src, dst, unspec_src, buffer, totallen, spi,
	    srcport, dstport, proto, natt_lhp, natt_rhp,
	    natt_local, natt_remote, natt_lport, natt_rport);

	free(buffer);

	if (proxyhp != NULL && proxyhp != &dummy.he)
		freehostent(proxyhp);
	if (srchp != NULL && srchp != &dummy.he)
		freehostent(srchp);
	if (dsthp != NULL && dsthp != &dummy.he)
		freehostent(dsthp);
	if (natt_lhp != NULL && natt_lhp != &dummy.he)
		freehostent(natt_lhp);
	if (natt_rhp != NULL && natt_rhp != &dummy.he)
		freehostent(natt_rhp);
}

/*
 * DELETE and GET are similar, in that they only need the extensions
 * required to _find_ an SA, and then either delete it or obtain its
 * information.
 */
static void
dodelget(int cmd, int satype, char *argv[])
{
	struct sadb_msg *msg = (struct sadb_msg *)get_buffer;
	uint64_t *nextext;
	struct sadb_sa *assoc = NULL;
	struct sadb_address *src = NULL, *dst = NULL;
	int next, token, sa_len;
	char *thiscmd;
	uint32_t spi;
	struct hostent *srchp = NULL, *dsthp = NULL;
	struct sockaddr_in6 *sin6;
	boolean_t unspec_src = B_TRUE;
	uint16_t srcport = 0, dstport = 0;
	uint8_t proto = 0;

	msg_init(msg, ((cmd == CMD_GET) ? SADB_GET : SADB_DELETE),
	    (uint8_t)satype);
	/* Set the first extension header to right past the base message. */
	nextext = (uint64_t *)(msg + 1);
	bzero(nextext, sizeof (get_buffer) - sizeof (*msg));

	thiscmd = (cmd == CMD_GET) ? "get" : "delete";

	/* Assume last element in argv is set to NULL. */
	do {
		token = parseextval(*argv, &next);
		argv++;
		switch (token) {
		case TOK_EOF:
			/* Do nothing, I'm done. */
			break;
		case TOK_UNKNOWN:
			warnx(gettext("Unknown extension field %s."),
			    *(argv - 1));
			usage();	/* Will exit program. */
			break;
		case TOK_SPI:
			if (assoc != NULL) {
				warnx(gettext(
				    "Can only specify single SPI value."));
				usage();
			}
			assoc = (struct sadb_sa *)nextext;
			nextext = (uint64_t *)(assoc + 1);
			assoc->sadb_sa_len = SADB_8TO64(sizeof (*assoc));
			assoc->sadb_sa_exttype = SADB_EXT_SA;
			assoc->sadb_sa_spi = htonl((uint32_t)parsenum(*argv,
			    B_TRUE));
			spi = assoc->sadb_sa_spi;
			argv++;
			break;
		case TOK_SRCPORT:
			if (srcport != 0) {
				warnx(gettext(
				    "Can only specify single source port."));
				usage();
			}
			srcport = parsenum(*argv, B_TRUE);
			argv++;
			break;
		case TOK_DSTPORT:
			if (dstport != 0) {
				warnx(gettext("Can only "
				    "specify single destination port."));
				usage();
			}
			dstport = parsenum(*argv, B_TRUE);
			argv++;
			break;
		case TOK_PROTO:
			if (proto != 0) {
				warnx(gettext(
				    "Can only specify single protocol."));
				usage();
			}
			proto = parsenum(*argv, B_TRUE);
			argv++;
			break;
		case TOK_SRCADDR:
		case TOK_SRCADDR6:
			if (src != NULL) {
				warnx(gettext(
				    "Can only specify single source addr."));
				usage();
			}
			sa_len = parseaddr(*argv, &srchp,
			    (token == TOK_SRCADDR6));
			argv++;

			unspec_src = B_FALSE;
			src = (struct sadb_address *)nextext;
			nextext = (uint64_t *)(src + 1);
			nextext += SADB_8TO64(roundup(sa_len, 8));
			src->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
			src->sadb_address_len = nextext - ((uint64_t *)src);
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
				warnx(gettext("Can only specify single dest. "
					"addr."));
				usage();
			}
			sa_len = parseaddr(*argv, &dsthp,
			    (token == TOK_SRCADDR6));
			argv++;

			dst = (struct sadb_address *)nextext;
			nextext = (uint64_t *)(dst + 1);
			nextext += SADB_8TO64(roundup(sa_len, 8));
			dst->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
			dst->sadb_address_len = nextext - ((uint64_t *)dst);
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
		default:
			warnx(gettext("Don't use extension %s "
			    "for '%s' command."), *(argv - 1), thiscmd);
			usage();	/* Will exit program. */
			break;
		}
	} while (token != TOK_EOF);

	/* So I have enough of the message to send it down! */
	msg->sadb_msg_len = nextext - get_buffer;

	doaddresses((cmd == CMD_GET) ? SADB_GET : SADB_DELETE, satype, cmd,
	    srchp, dsthp, src, dst, unspec_src, get_buffer,
	    sizeof (get_buffer), spi, srcport, dstport, proto,
	    NULL, NULL, NULL, NULL, 0, 0);

	if (srchp != NULL && srchp != &dummy.he)
		freehostent(srchp);
	if (dsthp != NULL && dsthp != &dummy.he)
		freehostent(dsthp);
}

/*
 * "ipseckey monitor" should exit very gracefully if ^C is tapped.
 */
static void
monitor_catch(int signal)
{
	errx(signal, gettext("Bailing on signal %d."), signal);
}

/*
 * Loop forever, listening on PF_KEY messages.
 */
static void
domonitor(boolean_t passive)
{
	struct sadb_msg *samsg;
	int rc;

	/* Catch ^C. */
	(void) signal(SIGINT, monitor_catch);

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
		if (rc == -1)
			Bail("read (in domonitor)");
		(void) printf(gettext("Read %d bytes.\n"), rc);
		/*
		 * Q:  Should I use the same method of printing as GET does?
		 * A:  For now, yes.
		 */
		print_samsg(get_buffer, B_TRUE);
		(void) putchar('\n');
	}
}

/*
 * Open the output file for the "save" command.
 */
static FILE *
opensavefile(char *filename)
{
	int fd;
	FILE *retval;
	struct stat buf;

	/*
	 * If the user specifies "-" or doesn't give a filename, then
	 * dump to stdout.  Make sure to document the dangers of files
	 * that are NFS, directing your output to strange places, etc.
	 */
	if (filename == NULL || strcmp("-", filename) == 0)
		return (stdout);

	/*
	 * open the file with the create bits set.  Since I check for
	 * real UID == root in main(), I won't worry about the ownership
	 * problem.
	 */
	fd = open(filename, O_WRONLY | O_EXCL | O_CREAT | O_TRUNC, S_IRUSR);
	if (fd == -1) {
		if (errno != EEXIST)
			bail_msg("%s %s: %s", filename, gettext("open error"),
			    strerror(errno));
		fd = open(filename, O_WRONLY | O_TRUNC, 0);
		if (fd == -1)
			bail_msg("%s %s: %s", filename, gettext("open error"),
			    strerror(errno));
		if (fstat(fd, &buf) == -1) {
			(void) close(fd);
			bail_msg("%s fstat: %s", filename, strerror(errno));
		}
		if (S_ISREG(buf.st_mode) &&
		    ((buf.st_mode & S_IAMB) != S_IRUSR)) {
			warnx(gettext("WARNING: Save file already exists with "
				"permission %o."), buf.st_mode & S_IAMB);
			warnx(gettext("Normal users may be able to read IPsec "
				"keying material."));
		}
	}

	/* Okay, we have an FD.  Assign it to a stdio FILE pointer. */
	retval = fdopen(fd, "w");
	if (retval == NULL) {
		(void) close(fd);
		bail_msg("%s %s: %s", filename, gettext("fdopen error"),
		    strerror(errno));
	}
	return (retval);
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
 * Wrapper for inet_ntop(3SOCKET). Expects AF_INET6 address.
 * Process the address as a AF_INET address if it is a IPv4 mapped
 * address.
 */
static const char *
do_inet_ntop(const void *addr, char *cp, size_t size)
{
	boolean_t isv4;
	struct in6_addr *inaddr6 = (struct in6_addr *)addr;
	struct in_addr inaddr;

	if ((isv4 = IN6_IS_ADDR_V4MAPPED(inaddr6)) == B_TRUE) {
		IN6_V4MAPPED_TO_INADDR(inaddr6, &inaddr);
	}

	return (inet_ntop(isv4 ? AF_INET : AF_INET6,
	    isv4 ? (void *)&inaddr : inaddr6, cp, size));
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
	case CMD_ADD:
		puts_tr("add	 - Add a new security association (SA)");
		break;
	case CMD_DELETE:
		puts_tr("delete - Delete an SA");
		break;
	case CMD_GET:
		puts_tr("get - Display an SA");
		break;
	case CMD_FLUSH:
		puts_tr("flush - Delete all SAs");
		break;
	case CMD_DUMP:
		puts_tr("dump - Display all SAs");
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
	puts_tr("delete - Delete an SA");
	puts_tr("get - Display an SA");
	puts_tr("flush - Delete all SAs");
	puts_tr("dump - Display all SAs");
	puts_tr("save - Saves all SAs to a file");
}

/*
 * "Parse" a command line from argv.
 */
static void
parseit(int argc, char *argv[])
{
	int cmd, satype;

	if (argc == 0)
		return;
	cmd = parsecmd(*argv++);

	switch (cmd) {
	case CMD_HELP:
		dohelp(*argv);
		return;
	case CMD_MONITOR:
		domonitor(B_FALSE);
		break;
	case CMD_PMONITOR:
		domonitor(B_TRUE);
		break;
	case CMD_QUIT:
		exit(0);
	}

	satype = parsesatype(*argv);

	if (satype != SADB_SATYPE_UNSPEC) {
		argv++;
	} else {
		/*
		 * You must specify either "all" or a specific SA type
		 * for the "save" command.
		 */
		if (cmd == CMD_SAVE)
			if (*argv == NULL) {
				warnx(gettext("Must specify a specific "
					"SA type for save."));
				usage();
			} else {
				argv++;
			}
	}

	switch (cmd) {
	case CMD_FLUSH:
		doflush(satype);
		break;
	case CMD_ADD:
	case CMD_UPDATE:
		/*
		 * NOTE: Shouldn't allow ADDs or UPDATEs with keying material
		 * from the command line.
		 */
		if (!interactive) {
			errx(1, gettext(
			    "can't do ADD or UPDATE from the command line."));
		}
		if (satype == SADB_SATYPE_UNSPEC) {
			warnx(gettext("Must specify a specific SA type."));
			usage();
			/* NOTREACHED */
		}
		/* Parse for extensions, including keying material. */
		doaddup(cmd, satype, argv);
		break;
	case CMD_DELETE:
	case CMD_GET:
		if (satype == SADB_SATYPE_UNSPEC) {
			warnx(gettext("Must specify a single SA type."));
			usage();
			/* NOTREACHED */
		}
		/* Parse for bare minimum to locate an SA. */
		dodelget(cmd, satype, argv);
		break;
	case CMD_DUMP:
		dodump(satype, NULL);
		break;
	case CMD_SAVE:
		mask_signals(B_FALSE);	/* Mask signals */
		dodump(satype, opensavefile(argv[0]));
		mask_signals(B_TRUE);	/* Unmask signals */
		break;
	default:
		warnx(gettext("Unknown command (%s)."),
		    *(argv - ((satype == SADB_SATYPE_UNSPEC) ? 1 : 2)));
		usage();
	}
}

int
main(int argc, char *argv[])
{
	int ch;
	FILE *infile = stdin, *savefile;
	boolean_t dosave = B_FALSE, readfile = B_FALSE;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	openlog("ipseckey", LOG_CONS, LOG_AUTH);
	if (getuid() != 0) {
		errx(1, "You must be root to run ipseckey.");
	}

	/* umask me to paranoid, I only want to create files read-only */
	(void) umask((mode_t)00377);

	while ((ch = getopt(argc, argv, "pnvf:s:")) != EOF)
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
		case 'f':
			if (dosave)
				usage();
			infile = fopen(optarg, "r");
			if (infile == NULL)
				bail(optarg);
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

	if (keysock == -1)
		Bail("Opening PF_KEY socket");

	if (dosave) {
		mask_signals(B_FALSE);	/* Mask signals */
		dodump(SADB_SATYPE_UNSPEC, savefile);
		mask_signals(B_TRUE);	/* Unmask signals */
		exit(0);
	}

	if (infile != stdin || *argv == NULL) {
		/* Go into interactive mode here. */
		do_interactive(infile, "ipseckey> ", parseit);
	}

	parseit(argc, argv);

	return (0);
}
