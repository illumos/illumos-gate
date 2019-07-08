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
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <stropts.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <locale.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/sysmacros.h>	/* MIN, MAX */
#include <sys/sockio.h>
#include <net/pfkeyv2.h>
#include <net/pfpolicy.h>
#include <inet/ipsec_impl.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/systeminfo.h>
#include <nss_dbdefs.h>					/* NSS_BUFLEN_HOSTS */
#include <netinet/in.h>
#include <assert.h>
#include <inet/ip.h>
#include <ipsec_util.h>
#include <netinet/in_systm.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

/*
 * Globals
 */
int lfd;
char *my_fmri;
FILE *debugfile = stderr;

#define	USAGE() if (!smf_managed) usage()
/*
 * Buffer length to read in pattern/properties.
 */
#define	MAXLEN			1024

/* Max length of tunnel interface string identifier */
#define	TUNNAMEMAXLEN		LIFNAMSIZ

/*
 * Used by parse_one and parse/parse_action to communicate
 * the errors. -1 is failure, which is not defined here.
 */
enum parse_errors {PARSE_SUCCESS, PARSE_EOF};

/*
 * For spdsock_get_ext() diagnostics.
 */
#define	SPDSOCK_DIAG_BUF_LEN	128
static char spdsock_diag_buf[SPDSOCK_DIAG_BUF_LEN];

/*
 * Define CURL here so that while you are reading
 * this code, it does not affect "vi" in pattern
 * matching.
 */
#define	CURL_BEGIN		'{'
#define	CURL_END		'}'
#define	BACK_SLASH		'\\'
#define	MAXARGS			20
#define	NOERROR			0

/*
 * IPSEC_CONF_ADD should start with 1, so that when multiple commands
 * are given, we can fail the request.
 */

enum ipsec_cmds {IPSEC_CONF_ADD = 1, IPSEC_CONF_DEL, IPSEC_CONF_VIEW,
    IPSEC_CONF_FLUSH, IPSEC_CONF_LIST, IPSEC_CONF_SUB, IPSEC_CONF_REPLACE};

static const char policy_conf_file[] = "/var/run/ipsecpolicy.conf";
static const char lock_file[] = "/var/run/ipsecconf.lock";
static const char index_tag[] = "#INDEX";

#define	POLICY_CONF_FILE	policy_conf_file
#define	LOCK_FILE		lock_file
#define	INDEX_TAG		index_tag

/*
 * Valid algorithm length.
 */
#define	VALID_ALG_LEN		40

/* Types of Error messages */
typedef enum error_type {BAD_ERROR, DUP_ERROR, REQ_ERROR} error_type_t;

/* Error message human readable conversions */
static char *sys_error_message(int);
static void error_message(error_type_t, int, int);
static int get_pf_pol_socket(void);

static int cmd;
static char *filename;
static char lo_buf[MAXLEN];			/* Leftover buffer */

/*
 * The new SPD_EXT_TUN_NAME extension has a tunnel name in it.  Use the empty
 * string ("", stored in the char value "all_polheads") for all policy heads
 * (global and all tunnels).  Set interface_name to NULL for global-only, or
 * specify a name of an IP-in-IP tunnel.
 */
static char *interface_name;
static char all_polheads;	/* So we can easily get "". */

/* Error reporting stuff */
#define	CBUF_LEN		8192		/* Maximum size of the cmd */
/*
 * Following are used for reporting errors with arguments.
 * We store the line numbers of each argument as we parse them,
 * so that the error reporting is more specific. We can have only
 * (MAXARGS - 1) arguments between any pair of CURL_BEGIN CURL_END.
 * Because a single command can be made up of multiple action/property
 * combinations, the maximum command size is (2 * (MAXARGS -1)) for each
 * of patterns, properties and actions.
 */
#define	ARG_BUF_LEN		((2 * 3 * (MAXARGS - 1)) + 1)
static int arg_indices[ARG_BUF_LEN];
static int argindex;
static int linecount;
static char cbuf[CBUF_LEN];				/* Command buffer */
static int cbuf_offset;


#define	BYPASS_POLICY_BOOST		0x00800000
#define	ESP_POLICY_BOOST		0x00400000
#define	AH_POLICY_BOOST			0x00200000
#define	INITIAL_BASE_PRIORITY		0x000fffff

/*
 * the number used to order the
 * rules starts at a certain base and
 * goes down.  i.e. rules earlier in
 * the file are checked first
 */
static uint32_t priority = INITIAL_BASE_PRIORITY;

#define	AH_AUTH		0
#define	ESP_ENCR	1
#define	ESP_AUTH	2


/*
 * for deleting adds on error
 */

typedef struct d_list_s
{
	struct d_list_s *next;
	int index;
} d_list_t;

static d_list_t *d_list = NULL;
static d_list_t *d_tail = NULL;


/*
 * Used for multi-homed source/dest hosts.
 */
static struct hostent *shp, *dhp;
static unsigned int splen, dplen;
static char tunif[TUNNAMEMAXLEN];
static boolean_t has_saprefix, has_daprefix;
static uint32_t seq_cnt = 0;

/* lexxed out action and related properties */
typedef struct ap_s
{
	char *act;
	char *prop[MAXARGS + 1];
} ap_t;


/* one lexxed out rule */
typedef struct act_prop_s {
	char *pattern[MAXARGS + 1];
	ap_t ap[MAXARGS + 1];
} act_prop_t;

typedef struct
{
	uint8_t	 alg_id;
	uint32_t alg_minbits;
	uint32_t alg_maxbits;
} algreq_t;

/* structure to hold all information for one act_prop_t */
typedef struct ips_act_props_s {
	struct ips_act_props_s	*iap_next;
	struct ips_conf_s		*iap_head;

/*
 * IPsec action types (in SPD_ATTR_TYPE attribute)
 * SPD_ACTTYPE_DROP	0x0001
 * SPD_ACTTYPE_PASS	0x0002
 * SPD_ACTTYPE_IPSEC	0x0003
 */
	uint16_t	iap_action;
	uint16_t	iap_act_tok;

/*
 * Action ATTR flags (in SPD_ATTR_FLAGS attribute)
 *	SPD_APPLY_AH		0x0001
 *	SPD_APPLY_ESP		0x0002
 *	SPD_APPLY_SE		0x0004  * self-encapsulation *
 *	SPD_APPLY_COMP		0x0008	* compression; NYI *
 *	SPD_APPLY_UNIQUE	0x0010	* unique per-flow SA *
 *	SPD_APPLY_BYPASS	0x0020	* bypass policy *
 */
	uint16_t	iap_attr;
	uint16_t	iap_attr_tok[5];

	algreq_t	iap_aauth;
	algreq_t	iap_eencr;
	algreq_t	iap_eauth;

	uint32_t iap_life_soft_time;
	uint32_t iap_life_hard_time;
	uint32_t iap_life_soft_bytes;
	uint32_t iap_life_hard_bytes;

} ips_act_props_t;

#define	V4_PART_OF_V6(v6)	v6._S6_un._S6_u32[3]

typedef struct ips_conf_s {
	/* selector */
	uint16_t patt_tok[8];
	uint8_t has_saddr;
	uint8_t has_daddr;
	uint8_t has_smask;
	uint8_t has_dmask;
	uint8_t has_type;
	uint8_t has_code;
	uint8_t has_negotiate;
	uint8_t has_tunnel;
	uint16_t swap;

	struct in6_addr	ips_src_addr_v6;
	struct in6_addr	ips_src_mask_v6;
	struct in6_addr	ips_dst_addr_v6;
	struct in6_addr	ips_dst_mask_v6;
	uint8_t 		ips_src_mask_len;
	uint8_t 		ips_dst_mask_len;
	in_port_t		ips_src_port_min;
	in_port_t		ips_src_port_max;
	in_port_t		ips_dst_port_min;
	in_port_t		ips_dst_port_max;
	uint8_t			ips_icmp_type;
	uint8_t			ips_icmp_type_end;
	uint8_t			ips_icmp_code;
	uint8_t			ips_icmp_code_end;
	uint8_t			ips_ulp_prot;
	uint8_t			ips_ipsec_prot;
	uint8_t			ips_isv4;
	/*
	 * SPD_RULE_FLAG_INBOUND		0x0001
	 * SPD_RULE_FLAG_OUTBOUND		0x0002
	 */
	uint8_t			ips_dir;
	/*
	 * Keep track of tunnel separately due to explosion of ways to set
	 * inbound/outbound.
	 */
	boolean_t		ips_tunnel;
	uint64_t		ips_policy_index;
	uint32_t		ips_act_cnt;
	ips_act_props_t	*ips_acts;
} ips_conf_t;

#define	ips_src_addr	V4_PART_OF_V6(ips_src_addr_v6)
#define	ips_dst_addr	V4_PART_OF_V6(ips_dst_addr_v6)

static int ipsecconf_nflag;		/* Used only with -l option */
static int ipsecconf_qflag;		/* Used only with -a|-r option */

typedef struct str_val {
	const char *string;
	int value;
} str_val_t;

typedef struct str_tval {
	const char *string;
	int tok_val;
	int value;
} str_tval_t;

static int	parse_int(const char *);
static int	parse_index(const char *, char *);
static int	attach_tunname(spd_if_t *);
static void	usage(void);
static int	ipsec_conf_del(int, boolean_t);
static int	ipsec_conf_add(boolean_t, boolean_t, boolean_t);
static int	ipsec_conf_sub(void);
static int	ipsec_conf_flush(int);
static int	ipsec_conf_view(void);
static int	ipsec_conf_list(void);
static int	lock(void);
static int	unlock(int);
static int	parse_one(FILE *, act_prop_t *);
static void	reconfigure();
static void	in_prefixlentomask(unsigned int, uchar_t *);
static int	in_getprefixlen(char *);
static int	parse_address(int, char *);
#ifdef DEBUG_HEAVY
static void	pfpol_msg_dump(spd_msg_t *msg, char *);
#endif /* DEBUG_HEAVY */
static void	print_pfpol_msg(spd_msg_t *);
static int	pfp_delete_rule(uint64_t);
static void	ipsec_conf_admin(uint8_t);
static void	print_bit_range(int, int);
static void	nuke_adds();
static boolean_t combined_mode(uint_t);

#ifdef DEBUG
static void	dump_conf(ips_conf_t *);
#endif

typedef struct
{
	uint32_t	id;
	uint32_t	minkeybits;
	uint32_t	maxkeybits;
	uint32_t	defkeybits;
	uint32_t	incr;
} alginfo_t;

static int ipsec_nalgs[3];
static alginfo_t known_algs[3][256];

#define	IPS_SRC_MASK SPD_EXT_LCLADDR + 100
#define	IPS_DST_MASK SPD_EXT_REMADDR + 100

/*
 * if inbound, src=remote, dst=local
 * if outbound, src=local, dst=remote
 */

#define	TOK_saddr	1
#define	TOK_daddr	2
#define	TOK_sport	3
#define	TOK_dport	4
#define	TOK_smask	5
#define	TOK_dmask	6
#define	TOK_ulp	7
#define	TOK_local	8
#define	TOK_lport	9
#define	TOK_remote	10
#define	TOK_rport	11
#define	TOK_dir 	12
#define	TOK_type	13
#define	TOK_code	14
#define	TOK_negotiate	15
#define	TOK_tunnel	16

#define	IPS_SA SPD_ATTR_END
#define	IPS_DIR SPD_ATTR_EMPTY
#define	IPS_NEG SPD_ATTR_NOP


static str_tval_t pattern_table[] = {
	{"saddr", 		TOK_saddr,		SPD_EXT_LCLADDR},
	{"src",			TOK_saddr,		SPD_EXT_LCLADDR},
	{"srcaddr",		TOK_saddr,		SPD_EXT_LCLADDR},
	{"daddr", 		TOK_daddr,		SPD_EXT_REMADDR},
	{"dst",			TOK_daddr,		SPD_EXT_REMADDR},
	{"dstaddr",		TOK_daddr,		SPD_EXT_REMADDR},
	{"sport", 		TOK_sport,		SPD_EXT_LCLPORT},
	{"dport", 		TOK_dport,		SPD_EXT_REMPORT},
	{"smask", 		TOK_smask,		IPS_SRC_MASK},
	{"dmask", 		TOK_dmask,		IPS_DST_MASK},
	{"ulp", 		TOK_ulp,		SPD_EXT_PROTO},
	{"proto", 		TOK_ulp,		SPD_EXT_PROTO},
	{"local",		TOK_local,		SPD_EXT_LCLADDR},
	{"laddr",		TOK_local,		SPD_EXT_LCLADDR},
	{"lport",		TOK_lport,		SPD_EXT_LCLPORT},
	{"remote",		TOK_remote,		SPD_EXT_REMADDR},
	{"raddr",		TOK_remote,		SPD_EXT_REMADDR},
	{"rport",		TOK_rport,		SPD_EXT_REMPORT},
	{"dir",			TOK_dir,		IPS_DIR},
	{"type",		TOK_type,		SPD_EXT_ICMP_TYPECODE},
	{"code",		TOK_code,		SPD_EXT_ICMP_TYPECODE},
	{"negotiate",		TOK_negotiate,		IPS_NEG},
	{"tunnel",		TOK_tunnel,		SPD_EXT_TUN_NAME},
	{NULL, 			0,				0},
};

#define	TOK_apply	1
#define	TOK_permit	2
#define	TOK_ipsec	3
#define	TOK_bypass	4
#define	TOK_drop	5
#define	TOK_or		6

static str_tval_t action_table[] = {
	{"apply", 		TOK_apply,		SPD_ACTTYPE_IPSEC},
	{"permit", 		TOK_permit,		SPD_ACTTYPE_IPSEC},
	{"ipsec", 		TOK_ipsec,		SPD_ACTTYPE_IPSEC},
	{"bypass", 		TOK_bypass,		SPD_ACTTYPE_PASS},
	{"pass", 		TOK_bypass,		SPD_ACTTYPE_PASS},
	{"drop", 		TOK_drop,		SPD_ACTTYPE_DROP},
	{"or",			TOK_or,			0},
	{NULL, 			0,				0},
};

static str_val_t property_table[] = {
	{"auth_algs", 		SPD_ATTR_AH_AUTH},
	{"encr_algs", 		SPD_ATTR_ESP_ENCR},
	{"encr_auth_algs",	SPD_ATTR_ESP_AUTH},
	{"sa",				IPS_SA},
	{"dir",				IPS_DIR},
	{NULL,				0},
};

static str_val_t icmp_type_table[] = {
	{"unreach",	ICMP_UNREACH},
	{"echo",	ICMP_ECHO},
	{"echorep",	ICMP_ECHOREPLY},
	{"squench",	ICMP_SOURCEQUENCH},
	{"redir",	ICMP_REDIRECT},
	{"timex",	ICMP_TIMXCEED},
	{"paramprob",	ICMP_PARAMPROB},
	{"timest",	ICMP_TSTAMP},
	{"timestrep",	ICMP_TSTAMPREPLY},
	{"inforeq",	ICMP_IREQ},
	{"inforep",	ICMP_IREQREPLY},
	{"maskreq",	ICMP_MASKREQ},
	{"maskrep",	ICMP_MASKREPLY},
	{"unreach6",	ICMP6_DST_UNREACH},
	{"pkttoobig6",	ICMP6_PACKET_TOO_BIG},
	{"timex6",	ICMP6_TIME_EXCEEDED},
	{"paramprob6",	ICMP6_PARAM_PROB},
	{"echo6", 	ICMP6_ECHO_REQUEST},
	{"echorep6",	ICMP6_ECHO_REPLY},
	{"router-sol6",	ND_ROUTER_SOLICIT},
	{"router-ad6",	ND_ROUTER_ADVERT},
	{"neigh-sol6",	ND_NEIGHBOR_SOLICIT},
	{"neigh-ad6",	ND_NEIGHBOR_ADVERT},
	{"redir6",	ND_REDIRECT},
	{NULL,		0},
};

static str_val_t icmp_code_table[] = {
	{"net-unr",		ICMP_UNREACH_NET},
	{"host-unr",		ICMP_UNREACH_HOST},
	{"proto-unr",		ICMP_UNREACH_PROTOCOL},
	{"port-unr",		ICMP_UNREACH_PORT},
	{"needfrag",		ICMP_UNREACH_NEEDFRAG},
	{"srcfail",		ICMP_UNREACH_SRCFAIL},
	{"net-unk",		ICMP_UNREACH_NET_UNKNOWN},
	{"host-unk",		ICMP_UNREACH_HOST_UNKNOWN},
	{"isolate",		ICMP_UNREACH_ISOLATED},
	{"net-prohib",		ICMP_UNREACH_NET_PROHIB},
	{"host-prohib",		ICMP_UNREACH_HOST_PROHIB},
	{"net-tos",		ICMP_UNREACH_TOSNET},
	{"host-tos",		ICMP_UNREACH_TOSHOST},
	{"filter-prohib",	ICMP_UNREACH_FILTER_PROHIB},
	{"host-preced",		ICMP_UNREACH_HOST_PRECEDENCE},
	{"cutoff-preced",	ICMP_UNREACH_PRECEDENCE_CUTOFF},
	{"no-route6",		ICMP6_DST_UNREACH_NOROUTE},
	{"adm-prohib6",		ICMP6_DST_UNREACH_ADMIN},
	{"addr-unr6",		ICMP6_DST_UNREACH_ADDR},
	{"port-unr6",		ICMP6_DST_UNREACH_NOPORT},
	{"hop-limex6",		ICMP6_TIME_EXCEED_TRANSIT},
	{"frag-re-timex6",	ICMP6_TIME_EXCEED_REASSEMBLY},
	{"err-head6",		ICMP6_PARAMPROB_HEADER},
	{"unrec-head6",		ICMP6_PARAMPROB_NEXTHEADER},
	{"unreq-opt6",		ICMP6_PARAMPROB_OPTION},
	{NULL,			0},
};

static sigset_t set, oset;


static boolean_t
add_index(int index)
{
	d_list_t *temp = malloc(sizeof (d_list_t));

	if (temp == NULL) {
		warn("malloc");
		return (B_TRUE);
	}

	temp->index = index;
	temp->next = NULL;

	if (d_tail == NULL) {
		d_list = d_tail = temp;
		return (B_FALSE);
	}

	d_tail->next = temp;
	d_tail = temp;

	return (B_FALSE);
}

static int
block_all_signals()
{
	if (sigfillset(&set) == -1) {
		warn("sigfillset");
		return (-1);
	}
	if (sigprocmask(SIG_SETMASK, &set, &oset) == -1) {
		warn("sigprocmask");
		return (-1);
	}
	return (0);
}

static int
restore_all_signals()
{
	if (sigprocmask(SIG_SETMASK, &oset, NULL) == -1) {
		warn("sigprocmask");
		return (-1);
	}
	return (0);
}

/* allocate an ips_act_props_t and link it in correctly */
static ips_act_props_t *
alloc_iap(ips_conf_t *parent)
{
	ips_act_props_t *ret;
	ips_act_props_t *next = parent->ips_acts;
	ips_act_props_t *current = NULL;

	ret = (ips_act_props_t *)calloc(sizeof (ips_act_props_t), 1);

	if (ret == NULL)
		return (NULL);

	ret->iap_head = parent;

	while (next != NULL) {
		current = next;
		next = next->iap_next;
	}

	if (current != NULL)
		current->iap_next = ret;
	else
		parent->ips_acts = ret;

	parent->ips_act_cnt++;

	return (ret);
}

/*
 * This function exit()s if it fails.
 */
static void
fetch_algorithms()
{
	struct spd_msg msg;
	struct spd_ext_actions *actp;
	struct spd_attribute *attr, *endattr;
	spd_ext_t *exts[SPD_EXT_MAX+1];
	uint64_t reply_buf[256];
	int sfd;
	int cnt, retval;
	uint64_t *start, *end;
	alginfo_t alg = {0, 0, 0, 0, 0};
	uint_t algtype;
	static boolean_t has_run = B_FALSE;

	if (has_run)
		return;
	else
		has_run = B_TRUE;

	sfd = get_pf_pol_socket();
	if (sfd < 0) {
		err(-1, gettext("unable to open policy socket"));
	}

	(void) memset(&msg, 0, sizeof (msg));
	msg.spd_msg_version = PF_POLICY_V1;
	msg.spd_msg_type = SPD_ALGLIST;
	msg.spd_msg_len = SPD_8TO64(sizeof (msg));

	cnt = write(sfd, &msg, sizeof (msg));
	if (cnt != sizeof (msg)) {
		if (cnt < 0) {
			err(-1, gettext("alglist failed: write"));
		} else {
			errx(-1, gettext("alglist failed: short write"));
		}
	}

	cnt = read(sfd, reply_buf, sizeof (reply_buf));

	retval = spdsock_get_ext(exts, (spd_msg_t *)reply_buf, SPD_8TO64(cnt),
	    spdsock_diag_buf, SPDSOCK_DIAG_BUF_LEN);

	if (retval == KGE_LEN && exts[0]->spd_ext_len == 0) {
		/*
		 * No algorithms are defined in the kernel, which caused
		 * the extension length to be zero, and spdsock_get_ext()
		 * to fail with a KGE_LEN error. This is not an error
		 * condition, so we return nicely.
		 */
		(void) close(sfd);
		return;
	} else if (retval != 0) {
		if (strlen(spdsock_diag_buf) != 0)
			warnx(spdsock_diag_buf);
		err(1, gettext("fetch_algorithms failed"));
	}

	if (!exts[SPD_EXT_ACTION]) {
		errx(1, gettext("fetch_algorithms: action missing?!"));
	}

	actp = (struct spd_ext_actions *)exts[SPD_EXT_ACTION];
	start = (uint64_t *)actp;
	end = (start + actp->spd_actions_len);
	endattr = (struct spd_attribute *)end;
	attr = (struct spd_attribute *)&actp[1];

	algtype = 0;

	while (attr < endattr) {
		switch (attr->spd_attr_tag) {
		case SPD_ATTR_NOP:
		case SPD_ATTR_EMPTY:
			break;
		case SPD_ATTR_END:
			attr = endattr;
			/* FALLTHRU */
		case SPD_ATTR_NEXT:
			known_algs[algtype][ipsec_nalgs[algtype]] = alg;
			ipsec_nalgs[algtype]++;
			break;

		case SPD_ATTR_ENCR_MINBITS:
		case SPD_ATTR_AH_MINBITS:
		case SPD_ATTR_ESPA_MINBITS:
			alg.minkeybits = attr->spd_attr_value;
			break;

		case SPD_ATTR_ENCR_MAXBITS:
		case SPD_ATTR_AH_MAXBITS:
		case SPD_ATTR_ESPA_MAXBITS:
			alg.maxkeybits = attr->spd_attr_value;
			break;

		case SPD_ATTR_ENCR_DEFBITS:
		case SPD_ATTR_AH_DEFBITS:
		case SPD_ATTR_ESPA_DEFBITS:
			alg.defkeybits = attr->spd_attr_value;
			break;

		case SPD_ATTR_ENCR_INCRBITS:
		case SPD_ATTR_AH_INCRBITS:
		case SPD_ATTR_ESPA_INCRBITS:
			alg.incr = attr->spd_attr_value;
			break;

		case SPD_ATTR_AH_AUTH:
		case SPD_ATTR_ESP_AUTH:
		case SPD_ATTR_ESP_ENCR:
			alg.id = attr->spd_attr_value;
			algtype = attr->spd_attr_tag - SPD_ATTR_AH_AUTH;
			break;
		}
		attr++;
	}

	(void) close(sfd);
}

/* data dependant transform (act_cnt) */
#define	ATTR(ap, tag, value) \
do { (ap)->spd_attr_tag = (tag); \
	(ap)->spd_attr_value = (value); \
	ap++; } while (0)

static struct spd_attribute *
emit_alg(struct spd_attribute *ap, int type, const algreq_t *ar,
    int algattr, int minbitattr, int maxbitattr)
{
	int id = ar->alg_id;
	int minbits, i;

	if (id != 0) {
		/* LINTED E_CONST_COND */
		ATTR(ap, algattr, ar->alg_id);

		minbits = ar->alg_minbits;
		if (minbits == 0) {
			for (i = 0; i < ipsec_nalgs[type]; i++) {
				if (known_algs[type][i].id == id)
					break;
			}
			if (i < ipsec_nalgs[type])
				minbits = known_algs[type][i].defkeybits;
		}
		if (minbits != 0)
			/* LINTED E_CONST_COND */
			ATTR(ap, minbitattr, minbits);
		if (ar->alg_maxbits != SPD_MAX_MAXBITS)
			/* LINTED E_CONST_COND */
			ATTR(ap, maxbitattr, ar->alg_maxbits);
	}

	return (ap);
}



static struct spd_attribute *
ips_act_props_to_action(struct spd_attribute *ap, uint32_t *rule_priorityp,
    const ips_act_props_t *act_ptr)
{
	uint32_t rule_priority = *rule_priorityp;

	/* LINTED E_CONST_COND */
	ATTR(ap, SPD_ATTR_EMPTY, 0);

	/* type */
	/* LINTED E_CONST_COND */
	ATTR(ap, SPD_ATTR_TYPE, act_ptr->iap_action);

	if (act_ptr->iap_action == SPD_ACTTYPE_PASS)
		rule_priority |= BYPASS_POLICY_BOOST;

	/* flags */
	if (act_ptr->iap_attr != 0)
		/* LINTED E_CONST_COND */
		ATTR(ap, SPD_ATTR_FLAGS, act_ptr->iap_attr);

	/* esp */
	if (act_ptr->iap_attr & SPD_APPLY_ESP) {
		rule_priority |= ESP_POLICY_BOOST;

		/* encr */
		ap = emit_alg(ap, ESP_ENCR, &act_ptr->iap_eencr,
		    SPD_ATTR_ESP_ENCR,
		    SPD_ATTR_ENCR_MINBITS, SPD_ATTR_ENCR_MAXBITS);

		/* auth */
		ap = emit_alg(ap, ESP_AUTH, &act_ptr->iap_eauth,
		    SPD_ATTR_ESP_AUTH,
		    SPD_ATTR_ESPA_MINBITS, SPD_ATTR_ESPA_MAXBITS);
	}

	/* ah */
	if (act_ptr->iap_attr & SPD_APPLY_AH) {
		rule_priority |= AH_POLICY_BOOST;
		/* auth */
		ap = emit_alg(ap, AH_AUTH, &act_ptr->iap_aauth,
		    SPD_ATTR_AH_AUTH,
		    SPD_ATTR_AH_MINBITS, SPD_ATTR_AH_MAXBITS);
	}

	/* lifetimes */
	if (act_ptr->iap_life_soft_time != 0)
		/* LINTED E_CONST_COND */
		ATTR(ap, SPD_ATTR_LIFE_SOFT_TIME, act_ptr->iap_life_soft_time);
	if (act_ptr->iap_life_hard_time != 0)
		/* LINTED E_CONST_COND */
		ATTR(ap, SPD_ATTR_LIFE_HARD_TIME, act_ptr->iap_life_hard_time);
	if (act_ptr->iap_life_soft_bytes != 0)
		/* LINTED E_CONST_COND */
		ATTR(ap, SPD_ATTR_LIFE_SOFT_BYTES,
		    act_ptr->iap_life_soft_bytes);
	if (act_ptr->iap_life_hard_bytes != 0)
		/* LINTED E_CONST_COND */
		ATTR(ap, SPD_ATTR_LIFE_HARD_BYTES,
		    act_ptr->iap_life_hard_bytes);

	/* LINTED E_CONST_COND */
	ATTR(ap, SPD_ATTR_NEXT, 0);

	*rule_priorityp = rule_priority;

	return (ap);
}

static boolean_t
alg_rangecheck(uint_t type, uint_t algid, const algreq_t *ar)
{
	int i;
	uint_t minbits = ar->alg_minbits;
	uint_t maxbits = ar->alg_maxbits;

	for (i = 0; i < ipsec_nalgs[type]; i++) {
		if (known_algs[type][i].id == algid)
			break;
	}

	if (i >= ipsec_nalgs[type]) {
		/*
		 * The kernel (where we populate known_algs from) doesn't
		 * return the id's associated with NONE algorithms so we
		 * test here if this was the reason the algorithm wasn't
		 * found before wrongly failing.
		 */
		if (((type == ESP_ENCR) && (algid == SADB_EALG_NONE)) ||
		    ((type == ESP_AUTH) && (algid == SADB_AALG_NONE)) ||
		    ((type == AH_AUTH) && (algid == SADB_AALG_NONE))) {
			return (B_TRUE);
		} else {
			return (B_FALSE); /* not found */
		}
	}

	if ((minbits == 0) && (maxbits == 0))
		return (B_TRUE);

	minbits = MAX(minbits, known_algs[type][i].minkeybits);
	maxbits = MIN(maxbits, known_algs[type][i].maxkeybits);

	/* we could also check key increments here.. */
	return (minbits <= maxbits); /* non-null intersection */
}

/*
 * Inspired by uts/common/inet/spd.c:ipsec_act_wildcard_expand()
 */

static struct spd_attribute *
ips_act_wild_props_to_action(struct spd_attribute *ap,
    uint32_t *rule_priorityp, uint16_t *act_cntp,
    const ips_act_props_t *act_ptr)
{
	ips_act_props_t tact = *act_ptr;
	boolean_t use_ah, use_esp, use_espa, combined;
	boolean_t wild_auth, wild_encr, wild_eauth;
	uint_t	auth_alg, auth_idx, auth_min, auth_max;
	uint_t	eauth_alg, eauth_idx, eauth_min, eauth_max;
	uint_t  encr_alg, encr_idx, encr_min, encr_max;

	use_ah = !!(act_ptr->iap_attr & SPD_APPLY_AH);
	use_esp = !!(act_ptr->iap_attr & SPD_APPLY_ESP);
	use_espa = !!(act_ptr->iap_attr & SPD_APPLY_ESPA);
	auth_alg = act_ptr->iap_aauth.alg_id;
	eauth_alg = act_ptr->iap_eauth.alg_id;
	encr_alg = act_ptr->iap_eencr.alg_id;

	wild_auth = use_ah && (auth_alg == SADB_AALG_NONE);
	wild_eauth = use_espa && (eauth_alg == SADB_AALG_NONE);
	wild_encr = use_esp && (encr_alg == SADB_EALG_NONE);

	auth_min = auth_max = auth_alg;
	eauth_min = eauth_max = eauth_alg;
	encr_min = encr_max = encr_alg;

	/*
	 * set up for explosion.. for each dimension, expand output
	 * size by the explosion factor.
	 */
	if (wild_auth) {
		auth_min = 0;
		auth_max = ipsec_nalgs[AH_AUTH] - 1;
	}
	if (wild_eauth) {
		eauth_min = 0;
		eauth_max = ipsec_nalgs[ESP_AUTH] - 1;
	}
	if (wild_encr) {
		encr_min = 0;
		encr_max = ipsec_nalgs[ESP_ENCR] - 1;
	}

#define	WHICH_ALG(type, wild, idx) ((wild)?(known_algs[type][idx].id):(idx))

	for (encr_idx = encr_min; encr_idx <= encr_max; encr_idx++) {
		encr_alg = WHICH_ALG(ESP_ENCR, wild_encr, encr_idx);

		if (use_esp &&
		    !alg_rangecheck(ESP_ENCR, encr_alg, &act_ptr->iap_eencr))
			continue;

		combined = combined_mode(encr_alg);

		for (auth_idx = auth_min; auth_idx <= auth_max; auth_idx++) {
			auth_alg = WHICH_ALG(AH_AUTH, wild_auth, auth_idx);

			if (use_ah &&
			    !alg_rangecheck(AH_AUTH, auth_alg,
			    &act_ptr->iap_aauth))
				continue;


			for (eauth_idx = eauth_min; eauth_idx <= eauth_max;
			    eauth_idx++) {
				eauth_alg = WHICH_ALG(ESP_AUTH, wild_eauth,
				    eauth_idx);

				if (!combined && use_espa &&
				    !alg_rangecheck(ESP_AUTH, eauth_alg,
				    &act_ptr->iap_eauth))
					continue;

				tact.iap_eencr.alg_id = encr_alg;
				tact.iap_aauth.alg_id = auth_alg;

				/*
				 * If the cipher is combined-mode don't do any
				 * ESP authentication.
				 */
				tact.iap_eauth.alg_id =
				    combined ? SADB_AALG_NONE : eauth_alg;

				(*act_cntp)++;
				ap = ips_act_props_to_action(ap,
				    rule_priorityp, &tact);

				/* Stop now if the cipher is combined-mode. */
				if (combined)
					break;	/* Out of for loop. */
			}
		}
	}

#undef WHICH_ALG

	return (ap);
}

/* huge, but not safe since no length checking is done */
#define	MAX_POL_MSG_LEN 16384


/*
 * hand in some ips_conf_t's, get back an
 * iovec of pfpol messages.
 * this function converts the internal ips_conf_t into
 * a form that pf_pol can use.
 * return 0 on success, 1 on failure
 */
static int
ips_conf_to_pfpol_msg(int ipsec_cmd, ips_conf_t *inConf, int num_ips,
    struct iovec *msg)
{
	int i;
	ips_conf_t *conf;
	uint64_t *scratch = NULL;

	for (i = 0; i < num_ips; i++) {
		uint16_t *msg_len;
		uint16_t act_cnt = 0;
		uint64_t *next = NULL;
		spd_msg_t *spd_msg;
		spd_address_t *spd_address;
		struct spd_rule *spd_rule;
		struct spd_proto *spd_proto;
		struct spd_portrange *spd_portrange;
		struct spd_ext_actions *spd_ext_actions;
		struct spd_attribute *ap;
		struct spd_typecode *spd_typecode;
		spd_if_t *spd_if;
		ips_act_props_t *act_ptr;
		uint32_t rule_priority = 0;

		scratch = calloc(1, MAX_POL_MSG_LEN);
		msg[i].iov_base = (char *)scratch;
		if (scratch == NULL) {
			warn(gettext("memory"));
			return (1);
		}
		conf = &(inConf[i]);

		spd_msg = (spd_msg_t *)scratch;
		next = (uint64_t *)&(spd_msg[1]);

		msg_len = &(spd_msg->spd_msg_len);

		spd_msg->spd_msg_version = PF_POLICY_V1;
		spd_msg->spd_msg_pid = getpid();
		spd_msg->spd_msg_seq = ++seq_cnt;

		switch (ipsec_cmd) {
		case SPD_ADDRULE:
			spd_msg->spd_msg_type = SPD_ADDRULE;
			break;

		default:
			warnx("%s %d", gettext("bad command:"), ipsec_cmd);
			spd_msg->spd_msg_type = SPD_ADDRULE;
			break;
		}

		/*
		 * SELECTOR
		 */

		spd_msg->spd_msg_spdid = SPD_STANDBY;

		/* rule */
		spd_rule = (struct spd_rule *)next;

		spd_rule->spd_rule_len = SPD_8TO64(sizeof (struct spd_rule));
		spd_rule->spd_rule_type = SPD_EXT_RULE;
		spd_rule->spd_rule_flags = conf->ips_dir;
		if (conf->ips_tunnel)
			spd_rule->spd_rule_flags |= SPD_RULE_FLAG_TUNNEL;

		next = (uint64_t *)&(spd_rule[1]);

		/* proto */
		if (conf->ips_ulp_prot != 0) {
			spd_proto = (struct spd_proto *)next;
			spd_proto->spd_proto_len =
			    SPD_8TO64(sizeof (struct spd_proto));
			spd_proto->spd_proto_exttype = SPD_EXT_PROTO;
			spd_proto->spd_proto_number = conf->ips_ulp_prot;
			next = (uint64_t *)&(spd_proto[1]);
		}

		/* tunnel */
		if (conf->has_tunnel != 0) {
			spd_if = (spd_if_t *)next;
			spd_if->spd_if_len =
			    SPD_8TO64(P2ROUNDUP(strlen(tunif) + 1, 8) +
			    sizeof (spd_if_t));
			spd_if->spd_if_exttype = SPD_EXT_TUN_NAME;
			(void) strlcpy((char *)spd_if->spd_if_name, tunif,
			    TUNNAMEMAXLEN);
			next = (uint64_t *)(spd_if) + spd_if->spd_if_len;
		}

		/* icmp type/code */
		if (conf->ips_ulp_prot == IPPROTO_ICMP ||
		    conf->ips_ulp_prot == IPPROTO_ICMPV6) {
			if (conf->has_type) {
				spd_typecode = (struct spd_typecode *)next;
				spd_typecode->spd_typecode_len =
				    SPD_8TO64(sizeof (struct spd_typecode));
				spd_typecode->spd_typecode_exttype =
				    SPD_EXT_ICMP_TYPECODE;
				spd_typecode->spd_typecode_type =
				    conf->ips_icmp_type;
				spd_typecode->spd_typecode_type_end =
				    conf->ips_icmp_type_end;
				if (conf->has_code) {
					spd_typecode->spd_typecode_code =
					    conf->ips_icmp_code;
					spd_typecode->spd_typecode_code_end =
					    conf->ips_icmp_code_end;
				} else {
					spd_typecode->spd_typecode_code = 255;
					spd_typecode->spd_typecode_code_end
					    = 255;
				}
				next = (uint64_t *)&(spd_typecode[1]);
			}
		}

		/* src port */
		if (conf->ips_src_port_min != 0 ||
		    conf->ips_src_port_max != 0) {
			spd_portrange = (struct spd_portrange *)next;
			spd_portrange->spd_ports_len =
			    SPD_8TO64(sizeof (struct spd_portrange));
			spd_portrange->spd_ports_exttype =
			    (conf->swap)?SPD_EXT_REMPORT:SPD_EXT_LCLPORT;
			spd_portrange->spd_ports_minport =
			    conf->ips_src_port_min;
			spd_portrange->spd_ports_maxport =
			    conf->ips_src_port_max;
			next = (uint64_t *)&(spd_portrange[1]);
		}
		/* dst port */
		if (conf->ips_dst_port_min != 0 ||
		    conf->ips_dst_port_max != 0) {
			spd_portrange = (struct spd_portrange *)next;
			spd_portrange->spd_ports_len =
			    SPD_8TO64(sizeof (struct spd_portrange));
			spd_portrange->spd_ports_exttype =
			    (conf->swap)?SPD_EXT_LCLPORT:SPD_EXT_REMPORT;
			spd_portrange->spd_ports_minport =
			    conf->ips_dst_port_min;
			spd_portrange->spd_ports_maxport =
			    conf->ips_dst_port_max;
			next = (uint64_t *)&(spd_portrange[1]);
		}

		/* saddr */
		if (conf->has_saddr) {
			spd_address = (spd_address_t *)next;
			next = (uint64_t *)(spd_address + 1);

			spd_address->spd_address_exttype =
			    (conf->swap)?SPD_EXT_REMADDR:SPD_EXT_LCLADDR;
			spd_address->spd_address_prefixlen =
			    conf->ips_src_mask_len;

			if (conf->ips_isv4) {
				spd_address->spd_address_af = AF_INET;
				(void) memcpy(next, &(conf->ips_src_addr),
				    sizeof (ipaddr_t));
				spd_address->spd_address_len = 2;
				next += SPD_8TO64(sizeof (ipaddr_t) + 4);
				if (!conf->has_smask)
					spd_address->spd_address_prefixlen = 32;
			} else {
				spd_address->spd_address_af = AF_INET6;
				(void) memcpy(next, &(conf->ips_src_addr_v6),
				    sizeof (in6_addr_t));
				spd_address->spd_address_len = 3;
				next += SPD_8TO64(sizeof (in6_addr_t));
				if (!conf->has_smask)
					spd_address->spd_address_prefixlen
					    = 128;
			}
		}

		/* daddr */
		if (conf->has_daddr) {
			spd_address = (spd_address_t *)next;

			next = (uint64_t *)(spd_address + 1);

			spd_address->spd_address_exttype =
			    (conf->swap)?SPD_EXT_LCLADDR:SPD_EXT_REMADDR;
			spd_address->spd_address_prefixlen =
			    conf->ips_dst_mask_len;

			if (conf->ips_isv4) {
				spd_address->spd_address_af = AF_INET;
				(void) memcpy(next, &conf->ips_dst_addr,
				    sizeof (ipaddr_t));
				spd_address->spd_address_len = 2;
				/* "+ 4" below is for padding. */
				next += SPD_8TO64(sizeof (ipaddr_t) + 4);
				if (!conf->has_dmask)
					spd_address->spd_address_prefixlen = 32;
			} else {
				spd_address->spd_address_af = AF_INET6;
				(void) memcpy(next, &(conf->ips_dst_addr_v6),
				    sizeof (in6_addr_t));
				spd_address->spd_address_len = 3;
				next += SPD_8TO64(sizeof (in6_addr_t));
				if (!conf->has_dmask)
					spd_address->spd_address_prefixlen
					    = 128;
			}
		}

		/* actions */
		spd_ext_actions = (struct spd_ext_actions *)next;

		spd_ext_actions->spd_actions_exttype = SPD_EXT_ACTION;

		act_ptr = conf->ips_acts;
		ap = (struct spd_attribute *)(&spd_ext_actions[1]);

		rule_priority = priority--;

		for (act_ptr = conf->ips_acts; act_ptr != NULL;
		    act_ptr = act_ptr->iap_next) {
			ap = ips_act_wild_props_to_action(ap, &rule_priority,
			    &act_cnt, act_ptr);
		}
		ap[-1].spd_attr_tag = SPD_ATTR_END;

		next = (uint64_t *)ap;

		spd_rule->spd_rule_priority = rule_priority;

		msg[i].iov_len = (uintptr_t)next - (uintptr_t)msg[i].iov_base;
		*msg_len = (uint16_t)SPD_8TO64(msg[i].iov_len);
		spd_ext_actions->spd_actions_count = act_cnt;
		spd_ext_actions->spd_actions_len =
		    SPD_8TO64((uintptr_t)next - (uintptr_t)spd_ext_actions);
#ifdef DEBUG_HEAVY
		printf("pfpol msg len in uint64_t's = %d\n", *msg_len);
		printf("pfpol test_len in bytes = %d\n", msg[i].iov_len);
		pfpol_msg_dump((spd_msg_t *)scratch,
		    "ips_conf_to_pfpol_msg");
#endif
	}

#undef ATTR
	return (0);
}

static int
get_pf_pol_socket(void)
{
	int s = socket(PF_POLICY, SOCK_RAW, PF_POLICY_V1);
	if (s < 0) {
		if (errno == EPERM) {
			EXIT_BADPERM("Insufficient privileges to open "
			    "PF_POLICY socket.");
		} else {
			warn(gettext("(loading pf_policy) socket:"));
		}
	}

	return (s);
}


static int
send_pf_pol_message(int ipsec_cmd, ips_conf_t *conf, int *diag)
{
	int retval;
	int cnt;
	int total_len;
	struct iovec polmsg;
	spd_msg_t *return_buf;
	spd_ext_t *exts[SPD_EXT_MAX+1];
	int fd = get_pf_pol_socket();

	*diag = 0;

	if (fd < 0)
		return (EBADF);

	retval = ips_conf_to_pfpol_msg(ipsec_cmd, conf, 1, &polmsg);

	if (retval) {
		(void) close(fd);
		return (ENOMEM);
	}

	total_len = polmsg.iov_len;

	cnt = writev(fd, &polmsg, 1);

#ifdef DEBUG_HEAVY
	(void) printf("cnt = %d\n", cnt);
#endif
	if (cnt < 0) {
		warn(gettext("pf_pol write"));
	} else {
		return_buf = (spd_msg_t *)calloc(total_len, 1);

		if (return_buf == NULL) {
			warn(gettext("memory"));
		} else {
			cnt = read(fd, (void*)return_buf, total_len);
#ifdef	DEBUG_HEAVY
			(void) printf("pf_pol read: cnt = %d(%d)\n", cnt,
			    total_len);
#endif

			if (cnt > 8 && return_buf->spd_msg_errno) {
				*diag = return_buf->spd_msg_diagnostic;
				if (!ipsecconf_qflag) {
					warnx("%s: %s",
					    gettext("Kernel returned"),
					    sys_error_message(
					    return_buf->spd_msg_errno));
				}
				if (*diag != 0)
					(void) printf(gettext(
					    "\t(spdsock diagnostic: %s)\n"),
					    spdsock_diag(*diag));
#ifdef DEBUG_HEAVY
				pfpol_msg_dump((spd_msg_t *)polmsg.iov_base,
				    "message in");
				pfpol_msg_dump(return_buf,
				    "send_pf_pol_message");
#endif
				retval = return_buf->spd_msg_errno;
				free(return_buf);
				free(polmsg.iov_base);
				(void) close(fd);
				return (retval);
			}

			retval = spdsock_get_ext(exts, return_buf,
			    return_buf->spd_msg_len, NULL, 0);
			/* ignore retval */

			if (exts[SPD_EXT_RULE]) {
				conf->ips_policy_index =
				    ((struct spd_rule *)
				    exts[SPD_EXT_RULE])->spd_rule_index;

				if (add_index(conf->ips_policy_index)) {
					free(return_buf);
					free(polmsg.iov_base);
					(void) close(fd);
					return (ENOMEM);
				}
			}

			free(return_buf);
		}
	}

	free(polmsg.iov_base);
	(void) close(fd);

	return (0);

}

int
main(int argc, char *argv[])
{
	int ret, flushret;
	int c;
	int index;
	boolean_t smf_managed;
	boolean_t just_check = B_FALSE;
	boolean_t replace_policy = B_FALSE;

	char *smf_warning = gettext(
	    "\n\tIPsec policy should be managed using smf(5). Modifying\n"
	    "\tthe IPsec policy from the command line while the 'policy'\n"
	    "\tservice is enabled could result in an inconsistent\n"
	    "\tsecurity policy.\n\n");

	flushret = 0;
	cmd = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	openlog("ipsecconf", LOG_CONS, LOG_AUTH);

	/*
	 * We don't immediately check for privilege here. This is done by IP
	 * when we open /dev/ip below.
	 */

	if (argc == 1) {
		cmd = IPSEC_CONF_VIEW;
		goto done;
	}
	my_fmri = getenv("SMF_FMRI");
	if (my_fmri == NULL)
		smf_managed = B_FALSE;
	else
		smf_managed = B_TRUE;

	while ((c = getopt(argc, argv, "nlfLFa:qd:r:i:c:")) != EOF) {
		switch (c) {
		case 'F':
			if (interface_name != NULL) {
				USAGE();
				EXIT_FATAL("interface name not required.");
			}
			/* Apply to all policy heads - global and tunnels. */
			interface_name = &all_polheads;
			/* FALLTHRU */
		case 'f':
			/*
			 * The policy flush command can be specified with -a
			 * to perform an atomic policy replace. It can't be
			 * specified with any other flags.
			 */
			if (cmd == IPSEC_CONF_ADD) {
				cmd = IPSEC_CONF_REPLACE;
				break;
			}
			if (cmd != 0) {
				USAGE();
				EXIT_FATAL("Multiple commands specified");
			}
			cmd = IPSEC_CONF_FLUSH;
			break;
		case 'L':
			if (interface_name != NULL) {
				USAGE();
				EXIT_FATAL("interface name not required.");
			}
			/* Apply to all policy heads - global and tunnels. */
			interface_name = &all_polheads;
			/* FALLTHRU */
		case 'l':
			/* Only one command at a time */
			if (cmd != 0) {
				USAGE();
				EXIT_FATAL("Multiple commands specified");
			}
			cmd = IPSEC_CONF_LIST;
			break;
		case 'c':
			just_check = B_TRUE;
			ipsecconf_qflag++;
			/* FALLTHRU */
		case 'a':
			if (cmd == IPSEC_CONF_FLUSH) {
				cmd = IPSEC_CONF_REPLACE;
				filename = optarg;
				break;
			}
			/* Only one command at a time, and no interface name */
			if (cmd != 0 || interface_name != NULL) {
				USAGE();
				EXIT_FATAL("Multiple commands or interface "
				    "not required.");
			}
			cmd = IPSEC_CONF_ADD;
			filename = optarg;
			break;
		case 'd':
			/*
			 * Only one command at a time.  Interface name is
			 * optional.
			 */
			if (cmd != 0) {
				USAGE();
				EXIT_FATAL("Multiple commands specified");
			}
			cmd = IPSEC_CONF_DEL;
			index = parse_index(optarg, NULL);
			break;
		case 'n' :
			ipsecconf_nflag++;
			break;
		case 'q' :
			ipsecconf_qflag++;
			break;
		case 'r' :
			/* Only one command at a time, and no interface name */
			if (cmd != 0 || interface_name != NULL) {
				USAGE();
				EXIT_FATAL("Multiple commands or interface "
				    "not required.");
			}
			cmd = IPSEC_CONF_SUB;
			filename = optarg;
			break;
		case 'i':
			if (interface_name != NULL) {
				EXIT_FATAL("Interface name already selected");
			}
			interface_name = optarg;
			/* Check for some cretin using the all-polheads name. */
			if (strlen(optarg) == 0) {
				USAGE();
				EXIT_FATAL("Invalid interface name.");
			}
			break;
		default :
			USAGE();
			EXIT_FATAL("Bad usage.");
		}
	}

done:
	ret = 0;
	lfd = lock();

	/*
	 * ADD, FLUSH, DELETE needs to do two operations.
	 *
	 * 1) Update/delete/empty the POLICY_CONF_FILE.
	 * 2) Make an ioctl and tell IP to update its state.
	 *
	 * We already lock()ed so that only one instance of this
	 * program runs. We also need to make sure that the above
	 * operations are atomic i.e we don't want to update the file
	 * and get interrupted before we could tell IP. To make it
	 * atomic we block all the signals and restore them.
	 */
	switch (cmd) {
	case IPSEC_CONF_LIST:
		fetch_algorithms();
		ret = ipsec_conf_list();
		break;
	case IPSEC_CONF_FLUSH:
		if ((ret = block_all_signals()) == -1) {
			break;
		}
		if (!smf_managed && !ipsecconf_qflag)
			(void) fprintf(stdout, "%s", smf_warning);
		ret = ipsec_conf_flush(SPD_ACTIVE);
		(void) restore_all_signals();
		break;
	case IPSEC_CONF_VIEW:
		if (interface_name != NULL) {
			EXIT_FATAL("Cannot view for one interface only.");
		}
		ret = ipsec_conf_view();
		break;
	case IPSEC_CONF_DEL:
		if (index == -1) {
			warnx(gettext("Invalid index"));
			ret = -1;
			break;
		}
		if ((ret = block_all_signals()) == -1) {
			break;
		}
		if (!smf_managed && !ipsecconf_qflag)
			(void) fprintf(stdout, "%s", smf_warning);
		ret = ipsec_conf_del(index, B_FALSE);
		(void) restore_all_signals();
		flushret = ipsec_conf_flush(SPD_STANDBY);
		break;
	case IPSEC_CONF_REPLACE:
		replace_policy = B_TRUE;
		/* FALLTHRU */
	case IPSEC_CONF_ADD:
		/*
		 * The IPsec kernel modules should only be loaded
		 * if there is a policy to install, for this
		 * reason ipsec_conf_add() calls fetch_algorithms()
		 * and ipsec_conf_flush() only when appropriate.
		 */
		if ((ret = block_all_signals()) == -1) {
			break;
		}
		if (!smf_managed && !ipsecconf_qflag)
			(void) fprintf(stdout, "%s", smf_warning);
		ret = ipsec_conf_add(just_check, smf_managed, replace_policy);
		(void) restore_all_signals();
		break;
	case IPSEC_CONF_SUB:
		fetch_algorithms();
		if ((ret = block_all_signals()) == -1) {
			break;
		}
		if (!smf_managed && !ipsecconf_qflag)
			(void) fprintf(stdout, "%s", smf_warning);
		ret = ipsec_conf_sub();
		(void) restore_all_signals();
		flushret = ipsec_conf_flush(SPD_STANDBY);
		break;
	default :
		/* If no argument is given but a "-" */
		USAGE();
		EXIT_FATAL("Bad usage.");
	}

	(void) unlock(lfd);
	if (ret != 0 || flushret != 0)
		ret = 1;
	return (ret);
}

static void
perm_check(void)
{
	if (errno == EACCES)
		EXIT_BADPERM("Insufficient privilege to run ipsecconf.");
	else
		warn(gettext("Cannot open lock file %s"), LOCK_FILE);

	EXIT_BADPERM(NULL);
}

static int
lock()
{
	int fd;
	struct stat sbuf1;
	struct stat sbuf2;

	/*
	 * Open the file with O_CREAT|O_EXCL. If it exists already, it
	 * will fail. If it already exists, check whether it looks like
	 * the one we created.
	 */
	(void) umask(0077);
	if ((fd = open(LOCK_FILE, O_EXCL|O_CREAT|O_RDWR, S_IRUSR|S_IWUSR))
	    == -1) {
		if (errno != EEXIST) {
			/* Some other problem. Will exit. */
			perm_check();
		}

		/*
		 * open() returned an EEXIST error. We don't fail yet
		 * as it could be a residual from a previous
		 * execution.
		 * File exists. make sure it is OK. We need to lstat()
		 * as fstat() stats the file pointed to by the symbolic
		 * link.
		 */
		if (lstat(LOCK_FILE, &sbuf1) == -1) {
			EXIT_FATAL2("Cannot lstat lock file %s", LOCK_FILE);
		}
		/*
		 * Check whether it is a regular file and not a symbolic
		 * link. Its link count should be 1. The owner should be
		 * root and the file should be empty.
		 */
		if (!S_ISREG(sbuf1.st_mode) ||
		    sbuf1.st_nlink != 1 ||
		    sbuf1.st_uid != 0 ||
		    sbuf1.st_size != 0) {
			EXIT_FATAL2("Bad lock file %s", LOCK_FILE);
		}
		if ((fd = open(LOCK_FILE, O_CREAT|O_RDWR,
		    S_IRUSR|S_IWUSR)) == -1) {
			/* Will exit */
			perm_check();
		}
		/*
		 * Check whether we opened the file that we lstat()ed.
		 */
		if (fstat(fd, &sbuf2) == -1) {
			EXIT_FATAL2("Cannot lstat lock file %s", LOCK_FILE);
		}
		if (sbuf1.st_dev != sbuf2.st_dev ||
		    sbuf1.st_ino != sbuf2.st_ino) {
			/* File changed after we did the lstat() above */
			EXIT_FATAL2("Bad lock file %s", LOCK_FILE);
		}
	}
	if (lockf(fd, F_LOCK, 0) == -1) {
		EXIT_FATAL2("Cannot lockf %s", LOCK_FILE);
	}
	return (fd);
}

static int
unlock(int fd)
{
	if (lockf(fd, F_ULOCK, 0) == -1) {
		warn("lockf");
		return (-1);
	}
	return (0);
}

/* send in TOK_* */
static void
print_pattern_string(int type)
{
	int j;

	for (j = 0; pattern_table[j].string != NULL; j++) {
		if (type == pattern_table[j].tok_val) {
			(void) printf("%s ", pattern_table[j].string);
			return;
		}
	}
}

static void
print_icmp_typecode(uint8_t type, uint8_t type_end, uint8_t code,
    uint8_t code_end)
{
	(void) printf("type %d", type);
	if (type_end != type)
		(void) printf("-%d ", type_end);
	else
		(void) printf(" ");
	if (code != 255) {
		(void) printf("code %d", code);
		if (code_end != code)
			(void) printf("-%d ", code_end);
		else
			(void) printf(" ");
	}
}


static void
print_spd_flags(uint32_t flags)
{
	flags &= (SPD_RULE_FLAG_INBOUND|SPD_RULE_FLAG_OUTBOUND);

	if (flags == SPD_RULE_FLAG_OUTBOUND)
		(void) printf("dir out ");
	else if (flags == SPD_RULE_FLAG_INBOUND)
		(void) printf("dir in ");
	else if (flags == (SPD_RULE_FLAG_INBOUND|SPD_RULE_FLAG_OUTBOUND))
		(void) printf("dir both ");
}

static void
print_bit_range(int min, int max)
{
	if (min != 0 || (max != 0 && max != SPD_MAX_MAXBITS)) {
		(void) printf("(");
		if (min != 0)
			(void) printf("%d", min);
		if (min != 0 && max != 0 && min != max) {
			(void) printf("..");
			if (max != 0 && max != SPD_MAX_MAXBITS)
				(void) printf("%d", max);
		}
		(void) printf(")");
	}
}

static void
print_alg(const char *tag, algreq_t *algreq, int proto_num)
{
	int min = algreq->alg_minbits;
	int max = algreq->alg_maxbits;
	struct ipsecalgent *alg;

	/*
	 * This function won't be called with alg_id == 0, so we don't
	 * have to worry about ANY vs. NONE here.
	 */

	(void) printf("%s ", tag);

	alg = getipsecalgbynum(algreq->alg_id, proto_num, NULL);
	if (alg == NULL) {
		(void) printf("%d", algreq->alg_id);
	} else {
		(void) printf("%s", alg->a_names[0]);
		freeipsecalgent(alg);
	}

	print_bit_range(min, max);
	(void) printf(" ");
}

static void
print_ulp(uint8_t proto)
{
	struct protoent *pe;

	if (proto == 0)
		return;

	print_pattern_string(TOK_ulp);
	pe = NULL;
	if (!ipsecconf_nflag) {
		pe = getprotobynumber(proto);
	}
	if (pe != NULL)
		(void) printf("%s ", pe->p_name);
	else
		(void) printf("%d ", proto);
}

/* needs to do ranges */
static void
print_port(uint16_t in_port, int type)
{
	in_port_t port = ntohs(in_port);
	struct servent *sp;

	if (port == 0)
		return;

	print_pattern_string(type);
	sp = NULL;
	if (!ipsecconf_nflag)
		sp = getservbyport(port, NULL);

	if (sp != NULL)
		(void) printf("%s ", sp->s_name);
	else
		(void) printf("%d ", port);
}

/*
 * Print the address, given as "raw" input via the void pointer.
 */
static void
print_raw_address(void *input, boolean_t isv4)
{
	char  *cp;
	struct hostent *hp;
	char	domain[MAXHOSTNAMELEN + 1];
	struct in_addr addr;
	struct in6_addr addr6;
	char abuf[INET6_ADDRSTRLEN];
	int error_num;
	struct in6_addr in_addr;
	uchar_t *addr_ptr;
	sa_family_t af;
	int addr_len;

	if (isv4) {
		af = AF_INET;
		(void) memcpy(&V4_PART_OF_V6(in_addr), input, 4);
		/* we don't print unspecified addresses */
		IN6_V4MAPPED_TO_INADDR(&in_addr, &addr);
		if (addr.s_addr == INADDR_ANY)
			return;
		addr_ptr = (uchar_t *)&addr.s_addr;
		addr_len = IPV4_ADDR_LEN;
	} else {
		(void) memcpy(&addr6, input, 16);
		af = AF_INET6;
		/* we don't print unspecified addresses */
		if (IN6_IS_ADDR_UNSPECIFIED(&addr6))
			return;
		addr_ptr = (uchar_t *)&addr6.s6_addr;
		addr_len = sizeof (struct in6_addr);
	}

	cp = NULL;
	if (!ipsecconf_nflag) {
		if (sysinfo(SI_HOSTNAME, domain, MAXHOSTNAMELEN) != -1 &&
		    (cp = strchr(domain, '.')) != NULL) {
			(void) strlcpy(domain, cp + 1, sizeof (domain));
		} else {
			domain[0] = 0;
		}
		cp = NULL;
		hp = getipnodebyaddr(addr_ptr, addr_len, af, &error_num);
		if (hp) {
			if ((cp = strchr(hp->h_name, '.')) != 0 &&
			    strcasecmp(cp + 1, domain) == 0)
				*cp = 0;
			cp = hp->h_name;
		}
	}

	if (cp) {
		(void) printf("%s", cp);
	} else {
		(void) printf("%s", inet_ntop(af, addr_ptr, abuf,
		    INET6_ADDRSTRLEN));
	}
}

/*
 * Get the next SPD_DUMP message from the PF_POLICY socket.  A single
 * read may contain multiple messages.  This function uses static buffers,
 * and is therefore non-reentrant, so if you lift it for an MT application,
 * be careful.
 *
 * Return NULL if there's an error.
 */
static spd_msg_t *
ipsec_read_dump(int pfd)
{
	static uint64_t buf[SADB_8TO64(CBUF_LEN)];
	static uint64_t *offset;
	static int len;		/* In uint64_t units. */
	spd_msg_t *retval;

	/* Assume offset and len are initialized to NULL and 0. */

	if ((offset - len == buf) || (offset == NULL)) {
		/* read a new block from the socket. */
		len = read(pfd, &buf, sizeof (buf));
		if (len == -1) {
			warn(gettext("rule dump: bad read"));
			return (NULL);
		}
		offset = buf;
		len = SADB_8TO64(len);
	} /* Else I still have more messages from a previous read. */

	retval = (spd_msg_t *)offset;
	offset += retval->spd_msg_len;
	if (offset > buf + len) {
		warnx(gettext("dump read: message corruption,"
		    " %d len exceeds %d boundary."),
		    SADB_64TO8((uintptr_t)(offset - buf)),
		    SADB_64TO8((uintptr_t)(len)));
		return (NULL);
	}

	return (retval);
}

/*
 * returns 0 on success
 * -1 on read error
 * >0  on invalid returned message
 */

static int
ipsec_conf_list(void)
{
	int ret;
	int pfd;
	struct spd_msg *msg;
	int cnt;
	spd_msg_t *rmsg;
	spd_ext_t *exts[SPD_EXT_MAX+1];
	/*
	 * Add an extra 8 bytes of space (+1 uint64_t) to avoid truncation
	 * issues.
	 */
	uint64_t buffer[
	    SPD_8TO64(sizeof (*msg) + sizeof (spd_if_t) + LIFNAMSIZ) + 1];

	pfd = get_pf_pol_socket();

	if (pfd == -1) {
		warnx(gettext("Error getting list of policies from kernel"));
		return (-1);
	}

	(void) memset(buffer, 0, sizeof (buffer));
	msg = (struct spd_msg *)buffer;
	msg->spd_msg_version = PF_POLICY_V1;
	msg->spd_msg_type = SPD_DUMP;
	msg->spd_msg_len = SPD_8TO64(sizeof (*msg));

	msg->spd_msg_len += attach_tunname((spd_if_t *)(msg + 1));

	cnt = write(pfd, msg, SPD_64TO8(msg->spd_msg_len));

	if (cnt < 0) {
		warn(gettext("dump: invalid write() return"));
		(void) close(pfd);
		return (-1);
	}

	rmsg = ipsec_read_dump(pfd);

	if (rmsg == NULL || rmsg->spd_msg_errno != 0) {
		warnx("%s: %s", gettext("ruleset dump failed"),
		    (rmsg == NULL ?
		    gettext("read error") :
		    sys_error_message(rmsg->spd_msg_errno)));
		(void) close(pfd);
		return (-1);
	}


	for (;;) {
		/* read rule */
		rmsg = ipsec_read_dump(pfd);

		if (rmsg == NULL) {
			(void) close(pfd);
			return (-1);
		}

		if (rmsg->spd_msg_errno != 0) {
			warnx("%s: %s", gettext("dump read: bad message"),
			    sys_error_message(rmsg->spd_msg_errno));
			(void) close(pfd);
			return (-1);
		}

		ret = spdsock_get_ext(exts, rmsg, rmsg->spd_msg_len,
		    spdsock_diag_buf, SPDSOCK_DIAG_BUF_LEN);
		if (ret != 0) {
			if (strlen(spdsock_diag_buf) != 0)
				warnx(spdsock_diag_buf);
			warnx("%s: %s", gettext("dump read: bad message"),
			    sys_error_message(rmsg->spd_msg_errno));
			(void) close(pfd);
			return (ret);
		}

		/*
		 * End of dump..
		 */
		if (exts[SPD_EXT_RULESET] != NULL)
			break;	/* and return 0. */

		print_pfpol_msg(rmsg);
	}

	(void) close(pfd);
	return (0);
}

static void
print_iap(ips_act_props_t *iap)
{

	/* action */
	switch (iap->iap_action) {
	case SPD_ACTTYPE_PASS:
		(void) printf("pass ");
		break;
	case SPD_ACTTYPE_DROP:
		(void) printf("drop ");
		break;
	case SPD_ACTTYPE_IPSEC:
		(void) printf("ipsec ");
		break;
	}

	/* properties */
	(void) printf("%c ", CURL_BEGIN);
	if (iap->iap_action == SPD_ACTTYPE_IPSEC) {
		if (iap->iap_attr & SPD_APPLY_AH &&
		    iap->iap_aauth.alg_id != 0)
			print_alg("auth_algs", &iap->iap_aauth,
			    IPSEC_PROTO_AH);

		if (iap->iap_attr & SPD_APPLY_ESP) {
			print_alg("encr_algs", &iap->iap_eencr,
			    IPSEC_PROTO_ESP);
			if (iap->iap_eauth.alg_id != 0)
				print_alg("encr_auth_algs", &iap->iap_eauth,
				    IPSEC_PROTO_AH);
		}
		if (iap->iap_attr & SPD_APPLY_UNIQUE)
			(void) printf("sa unique ");
		else
			(void) printf("sa shared ");
	}
	(void) printf("%c ", CURL_END);
}


static void
print_pfpol_msg(spd_msg_t *msg)
{
	spd_ext_t *exts[SPD_EXT_MAX+1];
	spd_address_t *spd_address;
	struct spd_rule *spd_rule;
	struct spd_proto *spd_proto;
	struct spd_portrange *spd_portrange;
	struct spd_ext_actions *spd_ext_actions;
	struct spd_typecode *spd_typecode;
	struct spd_attribute *app;
	spd_if_t *spd_if;
	uint32_t rv;
	uint16_t act_count;

	rv = spdsock_get_ext(exts, msg, msg->spd_msg_len, spdsock_diag_buf,
	    SPDSOCK_DIAG_BUF_LEN);

	if (rv == KGE_OK && exts[SPD_EXT_RULE] != NULL) {
		spd_if = (spd_if_t *)exts[SPD_EXT_TUN_NAME];
		spd_rule = (struct spd_rule *)exts[SPD_EXT_RULE];
		if (spd_if == NULL) {
			(void) printf("%s %lld\n", INDEX_TAG,
			    spd_rule->spd_rule_index);
		} else {
			(void) printf("%s %s,%lld\n", INDEX_TAG,
			    (char *)spd_if->spd_if_name,
			    spd_rule->spd_rule_index);
		}
	} else {
		if (strlen(spdsock_diag_buf) != 0)
			warnx(spdsock_diag_buf);
		warnx(gettext("print_pfpol_msg: malformed PF_POLICY message."));
		return;
	}

	(void) printf("%c ", CURL_BEGIN);

	if (spd_if != NULL) {
		(void) printf("tunnel %s negotiate %s ",
		    (char *)spd_if->spd_if_name,
		    (spd_rule->spd_rule_flags & SPD_RULE_FLAG_TUNNEL) ?
		    "tunnel" : "transport");
	}

	if (exts[SPD_EXT_PROTO] != NULL) {
		spd_proto = (struct spd_proto *)exts[SPD_EXT_PROTO];
		print_ulp(spd_proto->spd_proto_number);
	}

	if (exts[SPD_EXT_LCLADDR] != NULL) {
		spd_address = (spd_address_t *)exts[SPD_EXT_LCLADDR];

		(void) printf("laddr ");
		print_raw_address((spd_address + 1),
		    (spd_address->spd_address_len == 2));
		(void) printf("/%d ", spd_address->spd_address_prefixlen);
	}

	if (exts[SPD_EXT_LCLPORT] != NULL) {
		spd_portrange = (struct spd_portrange *)exts[SPD_EXT_LCLPORT];
		if (spd_portrange->spd_ports_minport != 0) {
			print_port(spd_portrange->spd_ports_minport,
			    TOK_lport);
		}
	}


	if (exts[SPD_EXT_REMADDR] != NULL) {
		spd_address = (spd_address_t *)exts[SPD_EXT_REMADDR];

		(void) printf("raddr ");
		print_raw_address((spd_address + 1),
		    (spd_address->spd_address_len == 2));
		(void) printf("/%d ", spd_address->spd_address_prefixlen);
	}

	if (exts[SPD_EXT_REMPORT] != NULL) {
		spd_portrange =
		    (struct spd_portrange *)exts[SPD_EXT_REMPORT];
		if (spd_portrange->spd_ports_minport != 0) {
			print_port(
			    spd_portrange->spd_ports_minport, TOK_rport);
		}
	}

	if (exts[SPD_EXT_ICMP_TYPECODE] != NULL) {
		spd_typecode =
		    (struct spd_typecode *)exts[SPD_EXT_ICMP_TYPECODE];
		print_icmp_typecode(spd_typecode->spd_typecode_type,
		    spd_typecode->spd_typecode_type_end,
		    spd_typecode->spd_typecode_code,
		    spd_typecode->spd_typecode_code_end);
	}

	if (exts[SPD_EXT_RULE] != NULL) {
		spd_rule = (struct spd_rule *)exts[SPD_EXT_RULE];
		print_spd_flags(spd_rule->spd_rule_flags);
	}


	(void) printf("%c ", CURL_END);

	if (exts[SPD_EXT_ACTION] != NULL) {
		ips_act_props_t iap;
		int or_needed = 0;

		(void) memset(&iap, 0, sizeof (iap));
		spd_ext_actions =
		    (struct spd_ext_actions *)exts[SPD_EXT_ACTION];
		app = (struct spd_attribute *)(spd_ext_actions + 1);

		for (act_count = 0;
		    act_count < spd_ext_actions->spd_actions_len -1;
		    act_count++) {

			switch (app->spd_attr_tag) {

			case SPD_ATTR_NOP:
				break;

			case SPD_ATTR_END:
				/* print */
				if (or_needed) {
					(void) printf("or ");
				} else {
					or_needed = 1;
				}
				print_iap(&iap);
				break;

			case SPD_ATTR_EMPTY:
				/* clear */
				(void) memset(&iap, 0, sizeof (iap));
				break;

			case SPD_ATTR_NEXT:
				/* print */
				if (or_needed) {
					(void) printf("or ");
				} else {
					or_needed = 1;
				}

				print_iap(&iap);
				break;

			case SPD_ATTR_TYPE:
				iap.iap_action = app->spd_attr_value;
				break;

			case SPD_ATTR_FLAGS:
				iap.iap_attr = app->spd_attr_value;
				break;

			case SPD_ATTR_AH_AUTH:
				iap.iap_aauth.alg_id = app->spd_attr_value;
				break;

			case SPD_ATTR_ESP_ENCR:
				iap.iap_eencr.alg_id = app->spd_attr_value;
				break;

			case SPD_ATTR_ESP_AUTH:
				iap.iap_eauth.alg_id = app->spd_attr_value;
				break;

			case SPD_ATTR_ENCR_MINBITS:
				iap.iap_eencr.alg_minbits = app->spd_attr_value;
				break;

			case SPD_ATTR_ENCR_MAXBITS:
				iap.iap_eencr.alg_maxbits = app->spd_attr_value;
				break;

			case SPD_ATTR_AH_MINBITS:
				iap.iap_aauth.alg_minbits = app->spd_attr_value;
				break;

			case SPD_ATTR_AH_MAXBITS:
				iap.iap_aauth.alg_maxbits = app->spd_attr_value;
				break;

			case SPD_ATTR_ESPA_MINBITS:
				iap.iap_eauth.alg_minbits = app->spd_attr_value;
				break;

			case SPD_ATTR_ESPA_MAXBITS:
				iap.iap_eauth.alg_maxbits = app->spd_attr_value;
				break;

			case SPD_ATTR_LIFE_SOFT_TIME:
			case SPD_ATTR_LIFE_HARD_TIME:
			case SPD_ATTR_LIFE_SOFT_BYTES:
			case SPD_ATTR_LIFE_HARD_BYTES:
			default:
				(void) printf("\tattr %d: %X-%d\n",
				    act_count,
				    app->spd_attr_tag,
				    app->spd_attr_value);
				break;
			}
			app++;
		}
	}

	(void) printf("\n");
}

#ifdef DEBUG_HEAVY
static void
pfpol_msg_dump(spd_msg_t *msg, char *tag)
{
	spd_ext_t *exts[SPD_EXT_MAX+1];
	uint32_t i;
	spd_address_t *spd_address;
	struct spd_rule *spd_rule;
	struct spd_proto *spd_proto;
	struct spd_portrange *spd_portrange;
	struct spd_typecode *spd_typecode;
	struct spd_ext_actions *spd_ext_actions;
	struct spd_attribute *app;
	spd_if_t *spd_if;
	char abuf[INET6_ADDRSTRLEN];
	uint32_t rv;
	uint16_t act_count;

	rv = spdsock_get_ext(exts, msg, msg->spd_msg_len, NULL, 0);
	if (rv != KGE_OK)
		return;

	(void) printf("===========%s==============\n", tag);
	(void) printf("pfpol_msg_dump %d\n-------------------\n", rv);

	(void) printf("spd_msg_version:%d\n", msg->spd_msg_version);
	(void) printf("spd_msg_type:%d\n", msg->spd_msg_type);
	(void) printf("spd_msg_errno:%d\n", msg->spd_msg_errno);
	(void) printf("spd_msg_spdid:%d\n", msg->spd_msg_spdid);
	(void) printf("spd_msg_len:%d\n", msg->spd_msg_len);
	(void) printf("spd_msg_diagnostic:%d\n", msg->spd_msg_diagnostic);
	(void) printf("spd_msg_seq:%d\n", msg->spd_msg_seq);
	(void) printf("spd_msg_pid:%d\n", msg->spd_msg_pid);

	for (i = 1; i <= SPD_EXT_MAX; i++) {
		if (exts[i] == NULL) {
			printf("skipped %d\n", i);
			continue;
		}

		switch (i) {
		case SPD_EXT_TUN_NAME:
			spd_if = (spd_if_t *)exts[i];
			(void) printf("spd_if = %s\n", spd_if->spd_if_name);
			break;

		case SPD_EXT_ICMP_TYPECODE:
			spd_typecode = (struct spd_typecode *)exts[i];
			(void) printf("icmp type %d-%d code %d-%d\n",
			    spd_typecode->spd_typecode_type,
			    spd_typecode->spd_typecode_type_end,
			    spd_typecode->spd_typecode_code,
			    spd_typecode->spd_typecode_code_end);
			break;

		case SPD_EXT_LCLPORT:
			spd_portrange = (struct spd_portrange *)exts[i];
			(void) printf("local ports %d-%d\n",
			    spd_portrange->spd_ports_minport,
			    spd_portrange->spd_ports_maxport);

			break;

		case SPD_EXT_REMPORT:
			spd_portrange = (struct spd_portrange *)exts[i];
			(void) printf("remote ports %d-%d\n",
			    spd_portrange->spd_ports_minport,
			    spd_portrange->spd_ports_maxport);

			break;

		case SPD_EXT_PROTO:
			spd_proto = (struct spd_proto *)exts[i];
			(void) printf("proto:spd_proto_exttype %d\n",
			    spd_proto->spd_proto_exttype);
			(void) printf("proto:spd_proto_number %d\n",
			    spd_proto->spd_proto_number);
			break;

		case SPD_EXT_LCLADDR:
		case SPD_EXT_REMADDR:
			spd_address = (spd_address_t *)exts[i];
			if (i == SPD_EXT_LCLADDR)
				(void) printf("local addr ");
			else
				(void) printf("remote addr ");


			(void) printf("%s\n",
			    inet_ntop(spd_address->spd_address_af,
			    (void *) (spd_address +1), abuf,
			    INET6_ADDRSTRLEN));

			(void) printf("prefixlen: %d\n",
			    spd_address->spd_address_prefixlen);
			break;

		case SPD_EXT_ACTION:
			spd_ext_actions = (struct spd_ext_actions *)exts[i];
			(void) printf("spd_ext_action\n");
			(void) printf("spd_actions_count %d\n",
			    spd_ext_actions->spd_actions_count);
			app = (struct spd_attribute *)(spd_ext_actions + 1);

			for (act_count = 0;
			    act_count < spd_ext_actions->spd_actions_len -1;
			    act_count++) {
				(void) printf("\tattr %d: %X-%d\n", act_count,
				    app->spd_attr_tag, app->spd_attr_value);
				app++;
			}

			break;

		case SPD_EXT_RULE:
			spd_rule = (struct spd_rule *)exts[i];
			(void) printf("spd_rule_priority: 0x%x\n",
			    spd_rule->spd_rule_priority);
			(void) printf("spd_rule_flags: %d\n",
			    spd_rule->spd_rule_flags);
			break;

		case SPD_EXT_RULESET:
			(void) printf("spd_ext_ruleset\n");
			break;
		default:
			(void) printf("default\n");
			break;
		}
	}

	(void) printf("-------------------\n");
	(void) printf("=========================\n");
}
#endif /* DEBUG_HEAVY */

static int
ipsec_conf_view()
{
	char buf[MAXLEN];
	FILE *fp;

	fp = fopen(POLICY_CONF_FILE, "r");
	if (fp == NULL) {
		if (errno == ENOENT) {
			/*
			 * The absence of POLICY_CONF_FILE should
			 * not cause the command to exit with a
			 * non-zero status, since this condition
			 * is valid when no policies were previously
			 * defined.
			 */
			return (0);
		}
		warn(gettext("%s cannot be opened"), POLICY_CONF_FILE);
		return (-1);
	}
	while (fgets(buf, MAXLEN, fp) != NULL) {
		/* Don't print removed entries */
		if (*buf == ';')
			continue;
		if (strlen(buf) != 0)
			buf[strlen(buf) - 1] = '\0';
		(void) puts(buf);
	}
	return (0);
}

/*
 * Delete nlines from start in the POLICY_CONF_FILE.
 */
static int
delete_from_file(int start, int nlines)
{
	FILE *fp;
	char ibuf[MAXLEN];
	int len;

	if ((fp = fopen(POLICY_CONF_FILE, "r+b")) == NULL) {
		warn(gettext("%s cannot be opened"), POLICY_CONF_FILE);
		return (-1);
	}

	/*
	 * Insert a ";", read the line and discard it. Repeat
	 * this logic nlines - 1 times. For the last line there
	 * is just a newline character. We can't just insert a
	 * single ";" character instead of the newline character
	 * as it would affect the next line. Thus when we comment
	 * the last line we seek one less and insert a ";"
	 * character, which will replace the newline of the
	 * penultimate line with ; and newline of the last line
	 * will become part of the previous line.
	 */
	do {
		/*
		 * It is not enough to seek just once and expect the
		 * subsequent fgets below to take you to the right
		 * offset of the next line. fgets below seems to affect
		 * the offset. Thus we need to seek, replace with ";",
		 * and discard a line using fgets for every line.
		 */
		if (fseek(fp, start, SEEK_SET) == -1) {
			warn("fseek");
			return (-1);
		}
		if (fputc(';', fp) < 0) {
			warn("fputc");
			return (-1);
		}
		/*
		 * Flush the above ";" character before we do the fgets().
		 * Without this, fgets() gets confused with offsets.
		 */
		(void) fflush(fp);
		len = 0;
		while (fgets(ibuf, MAXLEN, fp) != NULL) {
			len += strlen(ibuf);
			if (ibuf[len - 1] == '\n') {
				/*
				 * We have read a complete line.
				 */
				break;
			}
		}
		/*
		 * We read the line after ";" character has been inserted.
		 * Thus len does not count ";". To advance to the next line
		 * increment by 1.
		 */
		start += (len + 1);
		/*
		 * If nlines == 2, we will be commenting out the last
		 * line next, which has only one newline character.
		 * If we blindly replace it with ";", it will  be
		 * read as part of the next line which could have
		 * a INDEX string and thus confusing ipsec_conf_view.
		 * Thus, we seek one less and replace the previous
		 * line's newline character with ";", and the
		 * last line's newline character will become part of
		 * the previous line.
		 */
		if (nlines == 2)
			start--;
	} while (--nlines != 0);
	(void) fclose(fp);
	if (nlines != 0)
		return (-1);
	else
		return (0);
}

/*
 * Delete an entry from the file by inserting a ";" at the
 * beginning of the lines to be removed.
 */
static int
ipsec_conf_del(int policy_index, boolean_t ignore_spd)
{
	act_prop_t *act_props = malloc(sizeof (act_prop_t));
	char *buf;
	FILE *fp;
	char ibuf[MAXLEN];
	int ibuf_len, index_len, index;
	int ret = 0;
	int offset, prev_offset;
	int nlines;
	char lifname[LIFNAMSIZ];

	if (act_props == NULL) {
		warn(gettext("memory"));
		return (-1);
	}

	fp = fopen(POLICY_CONF_FILE, "r");
	if (fp == NULL) {
		warn(gettext("%s cannot be opened"), POLICY_CONF_FILE);
		free(act_props);
		return (-1);
	}

	index_len = strlen(INDEX_TAG);
	index = 0;
	for (offset = prev_offset = 0; fgets(ibuf, MAXLEN, fp) != NULL;
	    offset += ibuf_len) {
		prev_offset = offset;
		ibuf_len = strlen(ibuf);

		if (strncmp(ibuf, INDEX_TAG, index_len) != 0) {
			continue;
		}

		/*
		 * This line contains INDEX_TAG
		 */
		buf = ibuf + index_len;
		buf++;			/* Skip the space */
		index = parse_index(buf, lifname);
		if (index == -1) {
			warnx(gettext("Invalid index in the file"));
			free(act_props);
			return (-1);
		}
		if (index == policy_index &&
		    (interface_name == NULL ||
		    strncmp(interface_name, lifname, LIFNAMSIZ) == 0)) {
			if (!ignore_spd) {
				ret = parse_one(fp, act_props);
				if (ret == -1) {
					warnx(gettext("Invalid policy entry "
					    "in the file"));
					free(act_props);
					return (-1);
				}
			}
			/*
			 * nlines is the number of lines we should comment
			 * out. linecount tells us how many lines this command
			 * spans. And we need to remove the line with INDEX
			 * and an extra line we added during ipsec_conf_add.
			 *
			 * NOTE : If somebody added a policy entry which does
			 * not have a newline, ipsec_conf_add() fills in the
			 * newline. Hence, there is always 2 extra lines
			 * to delete.
			 */
			nlines = linecount + 2;
			goto delete;
		}
	}

	if (!ignore_spd)
		ret = pfp_delete_rule(policy_index);

	if (ret != 0) {
		warnx(gettext("Deletion incomplete. Please "
		    "flush all the entries and re-configure :"));
		reconfigure();
		free(act_props);
		return (ret);
	}
	free(act_props);
	return (ret);

delete:
	/* Delete nlines from prev_offset */
	(void) fclose(fp);
	ret = delete_from_file(prev_offset, nlines);

	if (ret != 0) {
		warnx(gettext("Deletion incomplete. Please "
		    "flush all the entries and re-configure :"));
		reconfigure();
		free(act_props);
		return (ret);
	}

	if (!ignore_spd)
		ret = pfp_delete_rule(policy_index);

	if (ret != 0) {
		warnx(gettext("Deletion incomplete. Please "
		    "flush all the entries and re-configure :"));
		reconfigure();
		free(act_props);
		return (ret);
	}
	free(act_props);
	return (0);
}

static int
pfp_delete_rule(uint64_t index)
{
	struct spd_msg *msg;
	struct spd_rule *rule;
	int sfd;
	int cnt, len, alloclen;

	sfd = get_pf_pol_socket();
	if (sfd < 0) {
		warn(gettext("unable to open policy socket"));
		return (-1);
	}

	/*
	 * Add an extra 8 bytes of space (+1 uint64_t) to avoid truncation
	 * issues.
	 */
	alloclen = sizeof (spd_msg_t) + sizeof (struct spd_rule) +
	    sizeof (spd_if_t) + LIFNAMSIZ + 8;
	msg = (spd_msg_t *)malloc(alloclen);

	if (msg == NULL) {
		warn("malloc");
		return (-1);
	}

	rule = (struct spd_rule *)(msg + 1);

	(void) memset(msg, 0, alloclen);
	msg->spd_msg_version = PF_POLICY_V1;
	msg->spd_msg_type = SPD_DELETERULE;
	msg->spd_msg_len = SPD_8TO64(sizeof (spd_msg_t)
	    + sizeof (struct spd_rule));

	rule->spd_rule_type = SPD_EXT_RULE;
	rule->spd_rule_len = SPD_8TO64(sizeof (struct spd_rule));
	rule->spd_rule_index = index;

	msg->spd_msg_len += attach_tunname((spd_if_t *)(rule + 1));

	len = SPD_64TO8(msg->spd_msg_len);
	cnt = write(sfd, msg, len);

	if (cnt != len) {
		if (cnt < 0) {
			warn(gettext("Delete failed: write"));
			(void) close(sfd);
			free(msg);
			return (-1);
		} else {
			(void) close(sfd);
			free(msg);
			warnx(gettext("Delete failed: short write"));
			return (-1);
		}
	}

	cnt = read(sfd, msg, len);
	if (cnt != len) {
		if (cnt < 0) {
			warn(gettext("Delete failed: read"));
			(void) close(sfd);
			free(msg);
			return (-1);
		} else {
			(void) close(sfd);
			free(msg);
			warnx(gettext("Delete failed while reading reply"));
			return (-1);
		}
	}
	(void) close(sfd);
	if (msg->spd_msg_errno != 0) {
		errno = msg->spd_msg_errno;
		warn(gettext("Delete failed: SPD_FLUSH"));
		free(msg);
		return (-1);
	}

	free(msg);
	return (0);
}

static int
ipsec_conf_flush(int db)
{
	int pfd, cnt, len;
	int sfd;
	struct spd_msg *msg;
	/*
	 * Add an extra 8 bytes of space (+1 uint64_t) to avoid truncation
	 * issues.
	 */
	uint64_t buffer[
	    SPD_8TO64(sizeof (*msg) + sizeof (spd_if_t) + LIFNAMSIZ) + 1];

	sfd = get_pf_pol_socket();
	if (sfd < 0) {
		warn(gettext("unable to open policy socket"));
		return (-1);
	}

	(void) memset(buffer, 0, sizeof (buffer));
	msg = (struct spd_msg *)buffer;
	msg->spd_msg_version = PF_POLICY_V1;
	msg->spd_msg_type = SPD_FLUSH;
	msg->spd_msg_len = SPD_8TO64(sizeof (*msg));
	msg->spd_msg_spdid = db;

	msg->spd_msg_len += attach_tunname((spd_if_t *)(msg + 1));

	len = SPD_64TO8(msg->spd_msg_len);
	cnt = write(sfd, msg, len);
	if (cnt != len) {
		if (cnt < 0) {
			warn(gettext("Flush failed: write"));
			return (-1);
		} else {
			warnx(gettext("Flush failed: short write"));
			return (-1);
		}
	}

	cnt = read(sfd, msg, len);
	if (cnt != len) {
		if (cnt < 0) {
			warn(gettext("Flush failed: read"));
			return (-1);
		} else {
			warnx(gettext("Flush failed while reading reply"));
			return (-1);
		}
	}
	(void) close(sfd);
	if (msg->spd_msg_errno != 0) {
		warnx("%s: %s", gettext("Flush failed: SPD_FLUSH"),
		    sys_error_message(msg->spd_msg_errno));
		return (-1);
	}

	/* Truncate the file */
	if (db == SPD_ACTIVE) {
		if ((pfd = open(POLICY_CONF_FILE, O_TRUNC|O_RDWR)) == -1) {
			if (errno == ENOENT) {
				/*
				 * The absence of POLICY_CONF_FILE should
				 * not cause the command to exit with a
				 * non-zero status, since this condition
				 * is valid when no policies were previously
				 * defined.
				 */
				return (0);
			}
			warn(gettext("%s cannot be truncated"),
			    POLICY_CONF_FILE);
			return (-1);
		}
		(void) close(pfd);
	}
	return (0);
}

/*
 * function to send SPD_FLIP and SPD_CLONE messages
 * Do it for ALL polheads for simplicity's sake.
 */
static void
ipsec_conf_admin(uint8_t type)
{
	int cnt;
	int sfd;
	struct spd_msg *msg;
	uint64_t buffer[
	    SPD_8TO64(sizeof (struct spd_msg) + sizeof (spd_if_t))];
	char *save_ifname;

	sfd = get_pf_pol_socket();
	if (sfd < 0) {
		err(-1, gettext("unable to open policy socket"));
	}

	(void) memset(buffer, 0, sizeof (buffer));
	msg = (struct spd_msg *)buffer;
	msg->spd_msg_version = PF_POLICY_V1;
	msg->spd_msg_type = type;
	msg->spd_msg_len = SPD_8TO64(sizeof (buffer));

	save_ifname = interface_name;
	/* Apply to all policy heads - global and tunnels. */
	interface_name = &all_polheads;
	(void) attach_tunname((spd_if_t *)(msg + 1));
	interface_name = save_ifname;

	cnt = write(sfd, msg, sizeof (buffer));
	if (cnt != sizeof (buffer)) {
		if (cnt < 0) {
			err(-1, gettext("admin failed: write"));
		} else {
			errx(-1, gettext("admin failed: short write"));
		}
	}

	cnt = read(sfd, msg, sizeof (buffer));
	if (cnt != sizeof (buffer)) {
		if (cnt < 0) {
			err(-1, gettext("admin failed: read"));
		} else {
			errx(-1, gettext("admin failed while reading reply"));
		}
	}
	(void) close(sfd);
	if (msg->spd_msg_errno != 0) {
		errno = msg->spd_msg_errno;
		err(-1, gettext("admin failed"));
	}
}

static void
reconfigure()
{
	(void) fprintf(stderr, gettext(
	    "\tipsecconf -f \n "
	    "\tipsecconf -a policy_file\n"));
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	"Usage:	ipsecconf\n"
	"\tipsecconf -a ([-]|<filename>) [-q]\n"
	"\tipsecconf -c <filename>\n"
	"\tipsecconf -r ([-]|<filename>) [-q]\n"
	"\tipsecconf -d [-i tunnel-interface] <index>\n"
	"\tipsecconf -d <tunnel-interface,index>\n"
	"\tipsecconf -l [-n] [-i tunnel-interface]\n"
	"\tipsecconf -f [-i tunnel-interface]\n"
	"\tipsecconf -L [-n]\n"
	"\tipsecconf -F\n"));
}

/*
 * a type consists of
 * "type" <int>{ "-" <int>}
 * or
 * "type" keyword
 *
 * a code consists of
 * "code" <int>{ "-" <int>}
 * or
 * "code" keyword
 */


static int
parse_type_code(const char *str, const str_val_t *table)
{
	char *end1, *end2;
	int res1 = 0, res2 = 0;
	int i;

	if (isdigit(str[0])) {
		res1 = strtol(str, &end1, 0);

		if (end1 == str) {
			return (-1);
		}

		if (res1 > 255 || res1 < 0) {
			return (-1);
		}

		if (*end1 == '-') {
			end1++;
			res2 = strtol(end1, &end2, 0);
			if (res2 > 255 || res2 < 0) {
				return (-1);
			}
		} else {
			end2 = end1;
		}

		while (isspace(*end2))
			end2++;

		if (*end2 != '\0') {
			return (-1);
		}

		return (res1 + (res2 << 8));
	}

	for (i = 0; table[i].string; i++) {
		if (strcmp(str, table[i].string) == 0) {
			return (table[i].value);
		}
	}

	return (-1);
}

static int
parse_int(const char *str)
{
	char *end;
	int res;

	res = strtol(str, &end, 0);
	if (end == str)
		return (-1);
	while (isspace(*end))
		end++;
	if (*end != '\0')
		return (-1);
	return (res);
}

/*
 * Parses <interface>,<index>.  Sets iname or the global interface_name (if
 * iname == NULL) to <interface> and returns <index>.  Calls exit() if we have
 * an interface_name already set.
 */
static int
parse_index(const char *str, char *iname)
{
	char *intf, *num, *copy;
	int rc;

	copy = strdup(str);
	if (copy == NULL) {
		EXIT_FATAL("Out of memory.");
	}

	intf = strtok(copy, ",");
	/* Just want the rest of the string unmolested, so use "" for arg2. */
	num = strtok(NULL, "");
	if (num == NULL) {
		/* No comma found, just parse it like an int. */
		free(copy);
		return (parse_int(str));
	}

	if (iname != NULL) {
		(void) strlcpy(iname, intf, LIFNAMSIZ);
	} else {
		if (interface_name != NULL) {
			EXIT_FATAL("Interface name already selected");
		}

		interface_name = strdup(intf);
		if (interface_name == NULL) {
			EXIT_FATAL("Out of memory.");
		}
	}

	rc = parse_int(num);
	free(copy);
	return (rc);
}

/*
 * Convert a mask to a prefix length.
 * Returns prefix length on success, -1 otherwise.
 */
static int
in_getprefixlen(char *mask)
{
	int prefixlen;
	char *end;

	prefixlen = (int)strtol(mask, &end, 10);
	if (prefixlen < 0) {
		return (-1);
	}
	if (mask == end) {
		return (-1);
	}
	if (*end != '\0') {
		return (-1);
	}
	return (prefixlen);
}

/*
 * Convert a prefix length to a mask.
 * Assumes the mask array is zero'ed by the caller.
 */
static void
in_prefixlentomask(unsigned int prefixlen, uchar_t *mask)
{
	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			*mask++ = 0xFF;
			prefixlen -= 8;
			continue;
		}
		*mask |= 1 << (8 - prefixlen);
		prefixlen--;
	}
}


static int
parse_address(int type, char *addr_str)
{
	char *ptr;
	int prefix_len = 0;
	struct netent *ne = NULL;
	struct hostent *hp = NULL;
	int h_errno;
	struct in_addr netaddr;
	struct in6_addr *netaddr6;
	struct hostent *ne_hent;
	boolean_t	has_mask = B_FALSE;

	ptr = strchr(addr_str, '/');
	if (ptr != NULL) {
		has_mask = B_TRUE;
		*ptr++ = '\0';

		prefix_len = in_getprefixlen(ptr);
		if (prefix_len < 0) {
			warnx(gettext("Unparseable prefix: '%s'."), ptr);
			return (-1);
		}
	}

	/*
	 * getipnodebyname() is thread safe. This allows us to hold on to the
	 * returned hostent structure, which is pointed to by the shp and
	 * dhp globals for the source and destination addresses, respectively.
	 */
	hp = getipnodebyname(addr_str, AF_INET6, AI_DEFAULT | AI_ALL, &h_errno);
	if (hp != NULL) {
		/*
		 * We come here for both a hostname and
		 * any host address /network address.
		 */
		assert(hp->h_addrtype == AF_INET6);
	} else if ((ne = getnetbyname(addr_str)) != NULL) {
		switch (ne->n_addrtype) {
		case AF_INET:
			/*
			 * Allocate a struct hostent and initialize
			 * it with the address corresponding to the
			 * network number previously returned by
			 * getnetbyname(). Freed by do_address_adds()
			 * once the policy is defined.
			 */
			ne_hent = malloc(sizeof (struct hostent));
			if (ne_hent == NULL) {
				warn("malloc");
				return (-1);
			}
			ne_hent->h_addr_list = malloc(2*sizeof (char *));
			if (ne_hent->h_addr_list == NULL) {
				warn("malloc");
				free(ne_hent);
				return (-1);
			}
			netaddr6 = malloc(sizeof (struct in6_addr));
			if (netaddr6 == NULL) {
				warn("malloc");
				free(ne_hent->h_addr_list);
				free(ne_hent);
				return (-1);
			}
			ne_hent->h_addr_list[0] = (char *)netaddr6;
			ne_hent->h_addr_list[1] = NULL;
			netaddr = inet_makeaddr(ne->n_net, INADDR_ANY);
			IN6_INADDR_TO_V4MAPPED(&netaddr, netaddr6);
			hp = ne_hent;
			break;
		default:
			warnx(gettext("Address type %d not supported."),
			    ne->n_addrtype);
			return (-1);
		}
	} else {
		warnx(gettext("Could not resolve address %s."), addr_str);
		return (-1);
	}

	if (type == IPSEC_CONF_SRC_ADDRESS) {
		shp = hp;
		if (has_mask)
			splen = prefix_len;
		has_saprefix = has_mask;
	} else {
		dhp = hp;
		if (has_mask)
			dplen = prefix_len;
		has_daprefix = has_mask;
	}

	return (0);
}

/*
 * Add port-only entries.  Make sure to add them in both the V6 and V4 tables!
 */
static int
do_port_adds(ips_conf_t *cptr)
{
	int ret, diag;

	assert(IN6_IS_ADDR_UNSPECIFIED(&cptr->ips_src_addr_v6));
	assert(IN6_IS_ADDR_UNSPECIFIED(&cptr->ips_dst_addr_v6));

#ifdef DEBUG_HEAVY
	(void) dump_conf(cptr);
#endif

	ret = send_pf_pol_message(SPD_ADDRULE, cptr, &diag);
	if (ret != 0 && !ipsecconf_qflag) {
		warnx(
		    gettext("Could not add IPv4 policy for sport %d, dport %d "
		    "- diagnostic %d - %s"), ntohs(cptr->ips_src_port_min),
		    ntohs(cptr->ips_dst_port_min), diag, spdsock_diag(diag));
	}

	return (ret);
}

/*
 * Nuke a list of policy entries.
 * rewrite this to use flipping
 * d_list isn't freed because we will be
 * exiting the program soon.
 */
static void
nuke_adds()
{
	d_list_t *temp = d_list;
	FILE *policy_fp;

	policy_fp = fopen(POLICY_CONF_FILE, "a");
	if (policy_fp == NULL) {
		warn(gettext("%s cannot be opened"), POLICY_CONF_FILE);
	} else {
		(void) fprintf(policy_fp, "\n\n");
		(void) fflush(policy_fp);
	}

	while (temp != NULL) {
		(void) ipsec_conf_del(temp->index, B_TRUE);
		temp = temp->next;
	}
}

/*
 * Set mask info from the specified prefix len. Fail if multihomed.
 */
static int
set_mask_info(struct hostent *hp, unsigned int plen, struct in6_addr *mask_v6)
{
	struct in6_addr addr;
	struct in_addr mask_v4;

	if (hp->h_addr_list[1] != NULL) {
		return (EOPNOTSUPP);
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(mask_v6)) {
		return (EBUSY);
	}

	bcopy(hp->h_addr_list[0], &addr, sizeof (struct in6_addr));
	if (IN6_IS_ADDR_V4MAPPED(&addr)) {
		if (plen > IP_ABITS) {
			return (ERANGE);
		}
		(void) memset(&mask_v4, 0, sizeof (mask_v4));
		in_prefixlentomask(plen, (uchar_t *)&mask_v4);
		IN6_INADDR_TO_V4MAPPED(&mask_v4, mask_v6);
	} else {
		if (plen > IPV6_ABITS) {
			return (ERANGE);
		}
		/* mask_v6 is already zero (unspecified), see test above */
		in_prefixlentomask(plen, (uchar_t *)mask_v6);
	}
	return (0);
}

/*
 * Initialize the specified IPv6 address with all f's.
 */
static void
init_addr_wildcard(struct in6_addr *addr_v6, boolean_t isv4)
{
	if (isv4) {
		uint32_t addr_v4 = 0xffffffff;
		IN6_INADDR_TO_V4MAPPED((struct in_addr *)&addr_v4, addr_v6);
	} else {
		(void) memset(addr_v6, 0xff, sizeof (struct in6_addr));
	}
}

/*
 * Called at the end to actually add policy.  Handles single and multi-homed
 * cases.
 */
static int
do_address_adds(ips_conf_t *cptr, int *diag)
{
	int i, j;
	int ret = 0;	/* For ioctl() call. */
	int rc = 0;	/* My own return code. */
	struct in6_addr zeroes = {0, 0, 0, 0};
	char *ptr[2];
	struct hostent hent;
	boolean_t isv4;
	int add_count = 0;

	/*
	 * dst_hent may not be initialized if a destination
	 * address was not given. It will be initalized with just
	 * one address if a destination address was given. In both
	 * the cases, we initialize here with ipsc_dst_addr and enter
	 * the loop below.
	 */
	if (dhp == NULL) {
		assert(shp != NULL);
		hent.h_addr_list = ptr;
		ptr[0] = (char *)&zeroes.s6_addr;
		ptr[1] = NULL;
		dhp = &hent;
	} else if (shp == NULL) {
		assert(dhp != NULL);
		hent.h_addr_list = ptr;
		ptr[0] = (char *)&zeroes.s6_addr;
		ptr[1] = NULL;
		shp = &hent;
	}

	/*
	 * Set mask info here.  Bail if multihomed and there's a prefix len.
	 */
	if (has_saprefix) {
		rc = set_mask_info(shp, splen, &cptr->ips_src_mask_v6);
		if (rc != 0)
			goto bail;
		cptr->ips_src_mask_len = splen;
	}

	if (has_daprefix) {
		rc = set_mask_info(dhp, dplen, &cptr->ips_dst_mask_v6);
		if (rc != 0)
			goto bail;
		cptr->ips_dst_mask_len = dplen;
	}

	for (i = 0; shp->h_addr_list[i] != NULL; i++) {
		bcopy(shp->h_addr_list[i], &cptr->ips_src_addr_v6,
		    sizeof (struct in6_addr));
		isv4 = cptr->ips_isv4 =
		    IN6_IS_ADDR_V4MAPPED(&cptr->ips_src_addr_v6);
		if (IN6_IS_ADDR_UNSPECIFIED(&cptr->ips_src_mask_v6) &&
		    shp != &hent) {
			init_addr_wildcard(&cptr->ips_src_mask_v6, isv4);
		}

		for (j = 0; dhp->h_addr_list[j] != NULL; j++) {
			bcopy(dhp->h_addr_list[j], &cptr->ips_dst_addr_v6,
			    sizeof (struct in6_addr));
			if (IN6_IS_ADDR_UNSPECIFIED(&cptr->ips_src_addr_v6)) {
				/*
				 * Src was not specified, so update isv4 flag
				 * for this policy according to the family
				 * of the destination address.
				 */
				isv4 = cptr->ips_isv4 =
				    IN6_IS_ADDR_V4MAPPED(
				    &cptr->ips_dst_addr_v6);
			} else if ((dhp != &hent) && (isv4 !=
			    IN6_IS_ADDR_V4MAPPED(&cptr->ips_dst_addr_v6))) {
				/* v6/v4 mismatch. */
				continue;
			}
			if (IN6_IS_ADDR_UNSPECIFIED(&cptr->ips_dst_mask_v6) &&
			    dhp != &hent) {
				init_addr_wildcard(&cptr->ips_dst_mask_v6,
				    isv4);
			}

			ret = send_pf_pol_message(SPD_ADDRULE, cptr, diag);

			if (ret == 0) {
				add_count++;
			} else {
				/* For now, allow duplicate/overlap policies. */
				if (ret != EEXIST) {
					/*
					 * We have an error where we added
					 * some, but had errors with others.
					 * Undo the previous adds, and
					 * bail.
					 */
					rc = ret;
					goto bail;
				}
			}

			bzero(&cptr->ips_dst_mask_v6,
			    sizeof (struct in6_addr));
		}

		bzero(&cptr->ips_src_mask_v6, sizeof (struct in6_addr));
	}

bail:
	if (shp != &hent)
		freehostent(shp);
	shp = NULL;
	if (dhp != &hent)
		freehostent(dhp);
	dhp = NULL;
	splen = 0;
	dplen = 0;

	if ((add_count == 0) && (rc == 0)) {
		/*
		 * No entries were added. We failed all adds
		 * because the entries already existed, or because
		 * no v4 or v6 src/dst pairs were found. Either way,
		 * we must fail here with an appropriate error
		 * to avoid a corresponding entry from being added
		 * to ipsecpolicy.conf.
		 */
		if ((ret == EEXIST)) {
			/* All adds failed with EEXIST */
			rc = EEXIST;
		} else {
			/* No matching v4 or v6 src/dst pairs */
			rc = ESRCH;
		}
	}

	return (rc);
}

static int
parse_mask(int type, char *mask_str, ips_conf_t *cptr)
{
	struct in_addr mask;
	struct in6_addr *mask6;

	if (type == IPSEC_CONF_SRC_MASK) {
		mask6 = &cptr->ips_src_mask_v6;
	} else {
		mask6 = &cptr->ips_dst_mask_v6;
	}

	if ((strncasecmp(mask_str, "0x", 2) == 0) &&
	    (strchr(mask_str, '.') == NULL)) {
		/* Is it in the form 0xff000000 ? */
		char *end;

		mask.s_addr = strtoul(mask_str, &end, 0);
		if (end == mask_str) {
			return (-1);
		}
		if (*end != '\0') {
			return (-1);
		}
		mask.s_addr = htonl(mask.s_addr);
	} else {
		/*
		 * Since inet_addr() returns -1 on error, we have
		 * to convert a broadcast address ourselves.
		 */
		if (strcmp(mask_str, "255.255.255.255") == 0) {
			mask.s_addr = 0xffffffff;
		} else {
			mask.s_addr = inet_addr(mask_str);
			if (mask.s_addr == (unsigned int)-1)
				return (-1);
		}
	}

	/* Should we check for non-contiguous masks ? */
	if (mask.s_addr == 0)
		return (-1);
	IN6_INADDR_TO_V4MAPPED(&mask, mask6);


	if (type == IPSEC_CONF_SRC_MASK) {
		cptr->ips_src_mask_len = in_masktoprefix(mask6->s6_addr,
		    B_TRUE);
	} else {
		cptr->ips_dst_mask_len = in_masktoprefix(mask6->s6_addr,
		    B_TRUE);
	}

	return (0);
}

static int
parse_port(int type, char *port_str, ips_conf_t *conf)
{
	struct servent *sent;
	in_port_t port;
	int ret;

	sent = getservbyname(port_str, NULL);
	if (sent == NULL) {
		ret = parse_int(port_str);
		if (ret < 0 || ret >= 65536) {
			return (-1);
		}
		port = htons((in_port_t)ret);
	} else {
		port = sent->s_port;
	}
	if (type == IPSEC_CONF_SRC_PORT) {
		conf->ips_src_port_min = conf->ips_src_port_max = port;
	} else {
		conf->ips_dst_port_min = conf->ips_dst_port_max = port;
	}
	return (0);
}

static boolean_t
combined_mode(uint_t alg_id)
{
	struct ipsecalgent *alg;
	boolean_t rc;

	alg = getipsecalgbynum(alg_id, IPSEC_PROTO_ESP, NULL);
	if (alg != NULL) {
		rc = (ALG_FLAG_COMBINED & alg->a_alg_flags);
		freeipsecalgent(alg);
	} else {
		rc = B_FALSE;
	}

	return (rc);
}

static int
valid_algorithm(int proto_num, const char *str)
{
	const char *tmp;
	int ret;
	struct ipsecalgent *alg;

	/* Short-circuit "none" */
	if (strncasecmp("none", str, 5) == 0)
		return (-2);

	alg = getipsecalgbyname(str, proto_num, NULL);
	if (alg != NULL) {
		ret = alg->a_alg_num;
		freeipsecalgent(alg);
		return (ret);
	}

	/*
	 * Look whether it could be a valid number.
	 * We support numbers also so that users can
	 * load algorithms as they need it. We can't
	 * check for validity of numbers here. It will
	 * be checked when the SA is negotiated/looked up.
	 * parse_int uses strtol(str), which converts 3DES
	 * to a valid number i.e looks only at initial
	 * number part. If we come here we should expect
	 * only a decimal number.
	 */
	tmp = str;
	while (*tmp) {
		if (!isdigit(*tmp))
			return (-1);
		tmp++;
	}

	ret = parse_int(str);
	if (ret > 0 && ret <= 255)
		return (ret);
	else
		return (-1);
}

static int
parse_ipsec_alg(char *str, ips_act_props_t *iap, int alg_type)
{
	int alg_value;
	int remainder;
	char tstr[VALID_ALG_LEN];
	char *lens = NULL;
	char *l1_str;
	int l1 = 0;
	char *l2_str;
	int l2 = SPD_MAX_MAXBITS;
	algreq_t *ap;
	uint_t a_type;

	fetch_algorithms();

	/*
	 * Make sure that we get a null terminated string.
	 * For a bad input, we truncate at VALID_ALG_LEN.
	 */
	remainder = strlen(str);
	(void) strlcpy(tstr, str, VALID_ALG_LEN);
	lens = strtok(tstr, "()");
	remainder -= strlen(lens);
	lens = strtok(NULL, "()");

	if (lens != NULL) {
		int len1 = 0;
		int len2 = SPD_MAX_MAXBITS;
		int len_all = strlen(lens);
		int dot_start = (lens[0] == '.');

		/*
		 * Check to see if the keylength arg is at the end of the
		 * token, the "()" is 2 characters.
		 */
		remainder -= strlen(lens);
		if (remainder > 2)
			return (1);

		l1_str = strtok(lens, ".");
		l2_str = strtok(NULL, ".");
		if (l1_str != NULL) {
			l1 = parse_int(l1_str);
			len1 = strlen(l1_str);
			if (len1 < 0)
				return (1);
		}
		if (l2_str != NULL) {
			l2 = parse_int(l2_str);
			len2 = strlen(l2_str);
			if (len2 < 0)
				return (1);
		}

		if (len_all == len1) {
			/* alg(n) */
			l2 = l1;
		} else if (dot_start) {
			/* alg(..n) */
			l2 = l1;
			l1 = 0;
		} else if ((len_all - 2) == len1) {
			/* alg(n..) */
			l2 = SPD_MAX_MAXBITS;
		} /* else alg(n..m) */
	}

	if (alg_type == SPD_ATTR_AH_AUTH ||
	    alg_type == SPD_ATTR_ESP_AUTH) {
		alg_value = valid_algorithm(IPSEC_PROTO_AH, tstr);
	} else {
		alg_value = valid_algorithm(IPSEC_PROTO_ESP, tstr);
	}
	if (alg_value < 0) {
		/* Invalid algorithm or "none" */
		return (alg_value);
	}

	if (alg_type == SPD_ATTR_AH_AUTH) {
		a_type = AH_AUTH;
		iap->iap_attr |= SPD_APPLY_AH;
		ap = &(iap->iap_aauth);
	} else if (alg_type == SPD_ATTR_ESP_AUTH) {
		a_type = ESP_AUTH;
		iap->iap_attr |= SPD_APPLY_ESP|SPD_APPLY_ESPA;
		ap = &(iap->iap_eauth);
	} else {
		a_type = ESP_ENCR;
		iap->iap_attr |= SPD_APPLY_ESP;
		ap = &(iap->iap_eencr);
	}

	ap->alg_id = alg_value;
	ap->alg_minbits = l1;
	ap->alg_maxbits = l2;

	if (!alg_rangecheck(a_type, alg_value, ap))
		return (1);

	return (0);
}

static char *
sys_error_message(int syserr)
{
	char *mesg;

	switch (syserr) {
	case EEXIST:
		mesg = gettext("Entry already exists");
		break;
	case ENOENT:
		mesg = gettext("Tunnel not found");
		break;
	case EINVAL:
		mesg = gettext("Invalid entry");
		break;
	default :
		mesg = strerror(syserr);
	}
	return (mesg);
}

static void
error_message(error_type_t error, int type, int line)
{
	char *mesg;

	switch (type) {
	case IPSEC_CONF_SRC_ADDRESS:
		mesg = gettext("Source Address");
		break;
	case IPSEC_CONF_DST_ADDRESS:
		mesg = gettext("Destination Address");
		break;
	case IPSEC_CONF_SRC_PORT:
		mesg = gettext("Source Port");
		break;
	case IPSEC_CONF_DST_PORT:
		mesg = gettext("Destination Port");
		break;
	case IPSEC_CONF_SRC_MASK:
		mesg = gettext("Source Mask");
		break;
	case IPSEC_CONF_DST_MASK:
		mesg = gettext("Destination Mask");
		break;
	case IPSEC_CONF_ULP:
		mesg = gettext("Upper Layer Protocol");
		break;
	case IPSEC_CONF_IPSEC_AALGS:
		mesg = gettext("Authentication Algorithm");
		break;
	case IPSEC_CONF_IPSEC_EALGS:
		mesg = gettext("Encryption Algorithm");
		break;
	case IPSEC_CONF_IPSEC_EAALGS:
		mesg = gettext("ESP Authentication Algorithm");
		break;
	case IPSEC_CONF_IPSEC_SA:
		mesg = gettext("SA");
		break;
	case IPSEC_CONF_IPSEC_DIR:
		mesg = gettext("Direction");
		break;
	case IPSEC_CONF_ICMP_TYPE:
		mesg = gettext("ICMP type");
		break;
	case IPSEC_CONF_ICMP_CODE:
		mesg = gettext("ICMP code");
		break;
	case IPSEC_CONF_NEGOTIATE:
		mesg = gettext("Negotiate");
		break;
	case IPSEC_CONF_TUNNEL:
		mesg = gettext("Tunnel");
		break;
	default :
		return;
	}
	/*
	 * If we never read a newline character, we don't want
	 * to print 0.
	 */
	warnx(gettext("%s%s%s %s on line: %d"),
	    (error == BAD_ERROR) ? gettext("Bad") : "",
	    (error == DUP_ERROR) ? gettext("Duplicate") : "",
	    (error == REQ_ERROR) ? gettext("Requires") : "",
	    mesg,
	    (arg_indices[line] == 0) ? 1 : arg_indices[line]);
}

static int
validate_properties(ips_act_props_t *cptr, boolean_t dir, boolean_t is_alg)
{
	if (cptr->iap_action == SPD_ACTTYPE_PASS ||
	    cptr->iap_action == SPD_ACTTYPE_DROP) {
		if (!dir) {
			warnx(gettext("dir string "
			    "not found for bypass policy"));
		}

		if (is_alg) {
			warnx(gettext("Algorithms found for bypass policy"));
			return (-1);
		}
		return (0);
	}
	if (!is_alg) {
		warnx(gettext("No IPsec algorithms given"));
		return (-1);
	}
	if (cptr->iap_attr == 0) {
		warnx(gettext("No SA attribute"));
		return (-1);
	}
	return (0);
}

/*
 * This function is called only to parse a single rule's worth of
 * action strings.  This is called after parsing pattern and before
 * parsing properties.  Thus we may have something in the leftover
 * buffer while parsing the pattern, which we need to handle here.
 */
static int
parse_action(FILE *fp, char **action, char **leftover)
{
	char *cp;
	char ibuf[MAXLEN];
	char *tmp_buf;
	char *buf;
	boolean_t new_stuff;

	if (*leftover != NULL) {
		buf = *leftover;
		new_stuff = B_FALSE;
		goto scan;
	}
	while (fgets(ibuf, MAXLEN, fp) != NULL) {
		new_stuff = B_TRUE;
		if (ibuf[strlen(ibuf) - 1] == '\n')
			linecount++;
		buf = ibuf;
scan:
		/* Truncate at the beginning of a comment */
		cp = strchr(buf, '#');
		if (cp != NULL)
			*cp = '\0';

		/* Skip any whitespace */
		while (*buf != '\0' && isspace(*buf))
			buf++;

		/* Empty line */
		if (*buf == '\0')
			continue;

		/*
		 * Store the command for error reporting
		 * and ipsec_conf_add().
		 */
		if (new_stuff) {
			/*
			 * Check for buffer overflow including the null
			 * terminating character.
			 */
			int len = strlen(ibuf);
			if ((cbuf_offset + len + 1) >= CBUF_LEN)
				return (-1);

			(void) strcpy(cbuf + cbuf_offset, ibuf);
			cbuf_offset += len;
		}
		/*
		 * Start of the non-empty non-space character.
		 */
		tmp_buf = buf;

		/* Skip until next whitespace or CURL_BEGIN */
		while (*buf != '\0' && !isspace(*buf) &&
		    *buf != CURL_BEGIN)
			buf++;

		if (*buf != '\0') {
			if (tmp_buf == buf) /* No action token */
				goto error;
			if (*buf == CURL_BEGIN) {
				*buf = '\0';
				/* Allocate an extra byte for the null also */
				if ((*action = malloc(strlen(tmp_buf) + 1)) ==
				    NULL) {
					warn("malloc");
					return (ENOMEM);
				}
				(void) strcpy(*action, tmp_buf);
				*buf = CURL_BEGIN;
			} else {
				/* We have hit a space */
				*buf++ = '\0';
				/* Allocate an extra byte for the null also */
				if ((*action = malloc(strlen(tmp_buf) + 1)) ==
				    NULL) {
					warn("malloc");
					return (ENOMEM);
				}
				(void) strcpy(*action, tmp_buf);
			}
			/*
			 * Copy the rest of the line into the
			 * leftover buffer.
			 */
			if (*buf != '\0') {
				(void) strlcpy(lo_buf, buf, sizeof (lo_buf));
				*leftover = lo_buf;
			} else {
				*leftover = NULL;
			}
		} else {
			/* Allocate an extra byte for the null also */
			if ((*action = malloc(strlen(tmp_buf) + 1)) ==
			    NULL) {
				warn("malloc");
				return (ENOMEM);
			}
			(void) strcpy(*action, tmp_buf);
			*leftover = NULL;
		}
		if (argindex >= ARG_BUF_LEN) {
			warnx(gettext("(parsing one command) "
			    "Too many selectors before action."));
			return (-1);
		}
		arg_indices[argindex++] = linecount;
		return (PARSE_SUCCESS);
	}
	/*
	 * Return error, on an empty action field.
	 */
error:
	warnx(gettext("(parsing one command) "
	    "Missing action token."));
	return (-1);
}

/*
 * This is called to parse pattern or properties that is enclosed
 * between CURL_BEGIN and CURL_END.
 */
static int
parse_pattern_or_prop(FILE *fp, char *argvec[], char **leftover)
{
	char *cp;
	int i = 0;
	boolean_t curl_begin_seen = B_FALSE;
	char ibuf[MAXLEN];
	char *tmp_buf;
	char *buf;
	boolean_t new_stuff;

	/*
	 * When parsing properties, leftover buffer could have the
	 * leftovers of the previous fgets().
	 */
	if (*leftover != NULL) {
		buf = *leftover;
		new_stuff = B_FALSE;
		goto scan;
	}
	while (fgets(ibuf, MAXLEN, fp) != NULL) {
		new_stuff = B_TRUE;
#ifdef DEBUG_HEAVY
		(void) printf("%s\n", ibuf);
#endif
		if (ibuf[strlen(ibuf) - 1] == '\n')
			linecount++;
		buf = ibuf;
scan:
		/* Truncate at the beginning of a comment */
		cp = strchr(buf, '#');
		if (cp != NULL)
			*cp = '\0';

		/* Skip any whitespace */
		while (*buf != '\0' && isspace(*buf))
			buf++;

		/* Empty line */
		if (*buf == '\0')
			continue;
		/*
		 * Store the command for error reporting
		 * and ipsec_conf_add().
		 */
		if (new_stuff) {
			/*
			 * Check for buffer overflow including the null
			 * terminating character.
			 */
			int len = strlen(ibuf);
			if ((cbuf_offset + len + 1) >= CBUF_LEN)
				return (-1);
			(void) strcpy(cbuf + cbuf_offset, ibuf);
			cbuf_offset += len;
		}
		/*
		 * First non-space character should be
		 * a curly bracket.
		 */
		if (!curl_begin_seen) {
			if (*buf != CURL_BEGIN) {
				/*
				 * If we never read a newline character,
				 * we don't want to print 0.
				 */
				warnx(gettext("line %d : pattern must start "
				    "with \"%c\" character"),
				    (linecount == 0) ? 1 : linecount,
				    CURL_BEGIN);
				return (-1);
			}
			buf++;
			curl_begin_seen = B_TRUE;
		}
		/*
		 * Arguments are separated by white spaces or
		 * newlines. Scan till you see a CURL_END.
		 */
		while (*buf != '\0') {
			if (*buf == CURL_END) {
ret:
				*buf++ = '\0';
				/*
				 * Copy the rest of the line into the
				 * leftover buffer if any.
				 */
				if (*buf != '\0') {
					(void) strlcpy(lo_buf, buf,
					    sizeof (lo_buf));
					*leftover = lo_buf;
				} else {
					*leftover = NULL;
				}
				return (PARSE_SUCCESS);
			}
			/*
			 * Skip any trailing whitespace until we see a
			 * non white-space character.
			 */
			while (*buf != '\0' && isspace(*buf))
				buf++;

			if (*buf == CURL_END)
				goto ret;

			/* Scan the next line as this buffer is empty */
			if (*buf == '\0')
				break;

			if (i >= MAXARGS) {
				warnx(
				    gettext("Number of Arguments exceeded %d"),
				    i);
				return (-1);
			}
			/*
			 * Non-empty, Non-space buffer.
			 */
			tmp_buf = buf++;
			/*
			 * Real scan of the argument takes place here.
			 * Skip past till space or CURL_END.
			 */
			while (*buf != '\0' && !isspace(*buf) &&
			    *buf != CURL_END) {
				buf++;
			}
			/*
			 * Either a space or we have hit the CURL_END or
			 * the real end.
			 */
			if (*buf != '\0') {
				if (*buf == CURL_END) {
					*buf++ = '\0';
					if ((argvec[i] = malloc(strlen(tmp_buf)
					    + 1)) == NULL) {
						warn("malloc");
						return (ENOMEM);
					}
					if (strlen(tmp_buf) != 0) {
						(void) strcpy(argvec[i],
						    tmp_buf);
						if (argindex >= ARG_BUF_LEN)
							goto toomanyargs;
						arg_indices[argindex++] =
						    linecount;
					}
					/*
					 * Copy the rest of the line into the
					 * leftover buffer.
					 */
					if (*buf != '\0') {
						(void) strlcpy(lo_buf, buf,
						    sizeof (lo_buf));
						*leftover = lo_buf;
					} else {
						*leftover = NULL;
					}
					return (PARSE_SUCCESS);
				} else {
					*buf++ = '\0';
				}
			}
			/*
			 * Copy this argument and scan for the buffer more
			 * if it is non-empty. If it is empty scan for
			 * the next line.
			 */
			if ((argvec[i] = malloc(strlen(tmp_buf) + 1)) ==
			    NULL) {
				warn("malloc");
				return (ENOMEM);
			}
			(void) strcpy(argvec[i++], tmp_buf);
			if (argindex >= ARG_BUF_LEN) {
			/*
			 * The number of tokens in a single policy entry
			 * exceeds the number of buffers available to fully
			 * parse the policy entry.
			 */
toomanyargs:
				warnx(gettext("(parsing one command) "
				    "Too many tokens in single policy entry."));
				return (-1);
			}
			arg_indices[argindex++] = linecount;
		}
	}
	/*
	 * If nothing is given in the file, it is okay.
	 * If something is given in the file and it is
	 * not CURL_BEGIN, we would have returned error
	 * above. If curl_begin_seen and we are here,
	 * something is wrong.
	 */
	if (curl_begin_seen) {
		warnx(gettext("(parsing one command) "
		    "Pattern or Properties incomplete."));
		return (-1);
	}
	return (PARSE_EOF);		/* Nothing more in the file */
}

/*
 * Parse one command i.e {pattern} action {properties}.
 *
 * {pattern} ( action {prop} | pass | drop ) (or ...)*
 */
static int
parse_one(FILE *fp, act_prop_t *act_props)
{
	char *leftover;
	int ret;
	int i;
	int ap_num = 0;
	enum parse_state {pattern, action, prop } pstate;

	has_daprefix = has_saprefix = B_FALSE;

	(void) memset(act_props, 0, sizeof (act_prop_t));
	pstate = pattern;

	ret = 0;
	leftover = NULL;
	argindex = 0;
	cbuf_offset = 0;
	assert(shp == NULL && dhp == NULL);

	for (;;) {
		switch (pstate) {
		case pattern:
		{
#ifdef DEBUG_HEAVY
			(void) printf("pattern\n");
#endif
			ret = parse_pattern_or_prop(fp,
			    act_props->pattern, &leftover);
			if (ret == PARSE_EOF) {
				/* EOF reached */
				return (PARSE_EOF);
			}
			if (ret != 0) {
				ret = -1;
				goto err;
			}
			pstate = action;
			break;
		}
		case action:
		{
#ifdef DEBUG_HEAVY
			(void) printf("action\n");
#endif
			ret = parse_action(fp,
			    &act_props->ap[ap_num].act, &leftover);
			if (ret != 0) {
				ret = -1;
				goto err;
			}

			/*
			 * Validate action now itself so that we don't
			 * proceed too much into the bad world.
			 */
			for (i = 0; action_table[i].string; i++) {
				if (strcmp(act_props->ap[ap_num].act,
				    action_table[i].string) == 0)
					break;
			}

			if (action_table[i].tok_val == TOK_or) {
				/* hit an or, go again */
				break;
			}

			if (action_table[i].string == NULL) {
				/*
				 * If we never read a newline
				 * character, we don't want
				 * to print 0.
				 */
				warnx(gettext("(parsing one command) "
				    "Invalid action on line %d: %s"),
				    (linecount == 0) ? 1 : linecount,
				    act_props->ap[ap_num].act);
				return (-1);
			}

			pstate = prop;
			break;
		}
		case prop:
		{
#ifdef DEBUG_HEAVY
			(void) printf("prop\n");
#endif
			ret = parse_pattern_or_prop(fp,
			    act_props->ap[ap_num].prop, &leftover);
			if (ret != 0) {
				if (ret == PARSE_EOF) {
					warnx(gettext("(parsing one command) "
					    "Missing properties."));
				}
				ret = -1;
				goto err;
			}

			if (leftover != NULL) {
				/* Accomodate spaces at the end */
				while (*leftover != '\0') {
					if (*leftover == BACK_SLASH) {
						warnx(gettext("Invalid line "
						    "continuation character."));
						ret = -1;
						goto err;
					}
					if (*leftover == 'o') {
						leftover++;
						if (*leftover == 'r') {
							leftover++;
							ap_num++;
							pstate = action;
							goto again;
						}
					}
					if (!isspace(*leftover)) {
						ret = -1;
						goto err;
					}
					leftover++;
				}
				return (0);
			}
			ap_num++;
			if (ap_num > MAXARGS)
				return (0);
			pstate = action; /* or */
			break;
		} /* case prop: */
		} /* switch(pstate) */

again:
		if (ap_num > MAXARGS) {
			warnx(gettext("Too many actions."));
			return (-1);
		}
	} /* for(;;) */
err:
	if (ret != 0) {
		/*
		 * If we never read a newline character, we don't want
		 * to print 0.
		 */
		warnx(gettext("Error before or at line %d"),
		    (linecount == 0) ? 1 : linecount);
	}
	return (ret);
}

/*
 * convert an act_propts_t to an ips_conf_t
 */

static int
form_ipsec_conf(act_prop_t *act_props, ips_conf_t *cptr)
{
	int i, j, k;
	int tok_count = 0;
	struct protoent *pent;
	boolean_t saddr, daddr, ipsec_aalg, ipsec_ealg, ipsec_eaalg, dir;
	boolean_t old_style, new_style, auth_covered, is_no_alg;
	boolean_t is_combined_mode;
	struct in_addr mask;
	int line_no;
	int ret;
	int ap_num = 0;
	int type, code, type_end, code_end;
#ifdef DEBUG_HEAVY
	/*
	 * pattern => act_props->pattern
	 * action => act_props->ap[].act
	 * properties => act_props->ap[].prop
	 */
	(void) printf("\npattern\n------------\n");
	for (i = 0; act_props->pattern[i] != NULL; i++)
		(void) printf("%s\n", act_props->pattern[i]);
	(void) printf("apz\n----------\n");
	for (j = 0; act_props->ap[j].act != NULL; j++) {

		(void) printf("act%d->%s\n", j, act_props->ap[j].act);
		for (i = 0; act_props->ap[j].prop[i] != NULL; i++)
			(void) printf("%dprop%d->%s\n",
			    j, i, act_props->ap[j].prop[i]);
	}
	(void) printf("------------\n\n");
#endif

	(void) memset(cptr, 0, sizeof (ips_conf_t));
	saddr = daddr = ipsec_aalg = ipsec_ealg = ipsec_eaalg = dir = B_FALSE;
	old_style = new_style = is_no_alg = is_combined_mode = B_FALSE;
	/*
	 * Get the Pattern. NULL pattern is valid.
	 */
	for (i = 0, line_no = 0; act_props->pattern[i]; i++, line_no++) {
		for (j = 0; pattern_table[j].string; j++) {
			if (strcmp(act_props->pattern[i],
			    pattern_table[j].string) == 0)
				break;
		}

		if (pattern_table[j].string == NULL) {
			/*
			 * If we never read a newline character, we don't want
			 * to print 0.
			 */
			warnx(gettext("Invalid pattern on line %d: %s"),
			    (arg_indices[line_no] == 0) ? 1 :
			    arg_indices[line_no], act_props->pattern[i]);
			return (-1);
		}

		cptr->patt_tok[tok_count++] = pattern_table[j].tok_val;

		switch (pattern_table[j].tok_val) {

		case TOK_dir:
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_IPSEC_DIR, line_no);
				return (-1);
			}

			if (strncmp(act_props->pattern[i], "in", 2) == 0) {
				cptr->ips_dir = SPD_RULE_FLAG_INBOUND;
			} else if (strncmp(
			    act_props->pattern[i], "out", 3) == 0) {
				cptr->ips_dir = SPD_RULE_FLAG_OUTBOUND;
			} else if (strncmp(
			    act_props->pattern[i], "both", 4) == 0) {
				if (old_style) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_DIR, line_no);
					return (-1);
				}
				new_style = B_TRUE;
				cptr->ips_dir =
				    SPD_RULE_FLAG_OUTBOUND |
				    SPD_RULE_FLAG_INBOUND;
			} else {
				error_message(BAD_ERROR,
				    IPSEC_CONF_IPSEC_DIR, line_no);
				return (-1);
			}
			dir = B_TRUE;
			break;

		case TOK_local:
			if (old_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_ADDRESS, line_no);
				return (-1);
			}
			new_style = B_TRUE;

			if (saddr) {
				error_message(DUP_ERROR,
				    IPSEC_CONF_SRC_ADDRESS, line_no);
				return (-1);
			}
			/*
			 * Use this to detect duplicates rather
			 * than 0 like other cases, because 0 for
			 * address means INADDR_ANY.
			 */
			saddr = B_TRUE;
			cptr->has_saddr = 1;
			/*
			 * Advance to the string containing
			 * the address.
			 */
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_ADDRESS, line_no);
				return (-1);
			}
			if (parse_address(IPSEC_CONF_SRC_ADDRESS,
			    act_props->pattern[i]) != 0) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_ADDRESS, line_no);
				return (-1);
			}
			if (!cptr->has_smask)
				cptr->has_smask = has_saprefix;

			break;
		case TOK_remote:
			if (old_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_ADDRESS, line_no);
				return (-1);
			}
			new_style = B_TRUE;

			if (daddr) {
				error_message(DUP_ERROR,
				    IPSEC_CONF_DST_ADDRESS, line_no);
				return (-1);
			}
			/*
			 * Use this to detect duplicates rather
			 * than 0 like other cases, because 0 for
			 * address means INADDR_ANY.
			 */
			daddr = B_TRUE;
			cptr->has_daddr = 1;
			/*
			 * Advance to the string containing
			 * the address.
			 */
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_ADDRESS, line_no);
				return (-1);
			}
			if (parse_address(IPSEC_CONF_DST_ADDRESS,
			    act_props->pattern[i]) != 0) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_ADDRESS, line_no);
				return (-1);
			}
			if (!cptr->has_dmask)
				cptr->has_dmask = has_daprefix;
			break;

		case TOK_saddr:
			if (new_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_ADDRESS, line_no);
				return (-1);
			}
			old_style = B_TRUE;

			if (saddr) {
				error_message(DUP_ERROR,
				    IPSEC_CONF_SRC_ADDRESS, line_no);
				return (-1);
			}
			/*
			 * Use this to detect duplicates rather
			 * than 0 like other cases, because 0 for
			 * address means INADDR_ANY.
			 */
			saddr = B_TRUE;
			cptr->has_saddr = 1;
			/*
			 * Advance to the string containing
			 * the address.
			 */
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_ADDRESS, line_no);
				return (-1);
			}

			if (parse_address(IPSEC_CONF_SRC_ADDRESS,
			    act_props->pattern[i]) != 0) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_ADDRESS, line_no);
				return (-1);
			}
			/* shp or bhp? */
			if (!cptr->has_smask)
				cptr->has_smask = has_saprefix;
			break;

		case TOK_daddr:
			if (new_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_ADDRESS, line_no);
				return (-1);
			}
			old_style = B_TRUE;

			if (daddr) {
				error_message(DUP_ERROR,
				    IPSEC_CONF_DST_ADDRESS, line_no);
				return (-1);
			}
			/*
			 * Use this to detect duplicates rather
			 * than 0 like other cases, because 0 for
			 * address means INADDR_ANY.
			 */
			daddr = B_TRUE;
			cptr->has_daddr = 1;
			/*
			 * Advance to the string containing
			 * the address.
			 */
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_ADDRESS, line_no);
				return (-1);
			}
			if (parse_address(IPSEC_CONF_DST_ADDRESS,
			    act_props->pattern[i]) != 0) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_ADDRESS, line_no);
				return (-1);
			}
			if (!cptr->has_dmask)
				cptr->has_dmask = has_daprefix;
			break;

		case TOK_sport:
			if (new_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_PORT, line_no);
				return (-1);
			}
			old_style = B_TRUE;

			if (cptr->ips_src_port_min != 0) {
				error_message(DUP_ERROR, IPSEC_CONF_SRC_PORT,
				    line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR, IPSEC_CONF_SRC_PORT,
				    line_no);
				return (-1);
			}
			ret = parse_port(IPSEC_CONF_SRC_PORT,
			    act_props->pattern[i], cptr);
			if (ret != 0) {
				error_message(BAD_ERROR, IPSEC_CONF_SRC_PORT,
				    line_no);
				return (-1);
			}
			break;
		case TOK_dport:
			if (new_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_PORT, line_no);
				return (-1);
			}
			old_style = B_TRUE;

			if (cptr->ips_dst_port_min != 0) {
				error_message(DUP_ERROR, IPSEC_CONF_DST_PORT,
				    line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR, IPSEC_CONF_DST_PORT,
				    line_no);
				return (-1);
			}
			ret = parse_port(IPSEC_CONF_DST_PORT,
			    act_props->pattern[i],
			    cptr);
			if (ret != 0) {
				error_message(BAD_ERROR, IPSEC_CONF_DST_PORT,
				    line_no);
				return (-1);
			}
			break;

		case TOK_lport:
			if (old_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_PORT, line_no);
				return (-1);
			}
			new_style = B_TRUE;

			if (cptr->ips_src_port_min != 0) {
				error_message(DUP_ERROR, IPSEC_CONF_SRC_PORT,
				    line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR, IPSEC_CONF_SRC_PORT,
				    line_no);
				return (-1);
			}
			ret = parse_port(IPSEC_CONF_SRC_PORT,
			    act_props->pattern[i],
			    cptr);
			if (ret != 0) {
				error_message(BAD_ERROR, IPSEC_CONF_SRC_PORT,
				    line_no);
				return (-1);
			}
			break;

		case TOK_rport:
			if (old_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_PORT, line_no);
				return (-1);
			}
			new_style = B_TRUE;

			if (cptr->ips_dst_port_min != 0) {
				error_message(DUP_ERROR, IPSEC_CONF_DST_PORT,
				    line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR, IPSEC_CONF_DST_PORT,
				    line_no);
				return (-1);
			}
			ret = parse_port(IPSEC_CONF_DST_PORT,
			    act_props->pattern[i],
			    cptr);
			if (ret != 0) {
				error_message(BAD_ERROR, IPSEC_CONF_DST_PORT,
				    line_no);
				return (-1);
			}
			break;

		case TOK_smask:
			if (new_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_SRC_MASK, line_no);
				return (-1);
			}
			old_style = B_TRUE;
			cptr->has_smask = B_TRUE;

			IN6_V4MAPPED_TO_INADDR(&cptr->ips_src_mask_v6, &mask);
			if (mask.s_addr != 0) {
				error_message(DUP_ERROR, IPSEC_CONF_SRC_MASK,
				    line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR, IPSEC_CONF_SRC_MASK,
				    line_no);
				return (-1);
			}
			ret = parse_mask(IPSEC_CONF_SRC_MASK,
			    act_props->pattern[i],
			    cptr);
			if (ret != 0) {
				error_message(BAD_ERROR, IPSEC_CONF_SRC_MASK,
				    line_no);
				return (-1);
			}
			break;
		case TOK_dmask:
			if (new_style) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_DST_MASK, line_no);
				return (-1);
			}
			old_style = B_TRUE;
			cptr->has_dmask = B_TRUE;

			IN6_V4MAPPED_TO_INADDR(&cptr->ips_dst_mask_v6, &mask);
			if (mask.s_addr != 0) {
				error_message(DUP_ERROR, IPSEC_CONF_DST_MASK,
				    line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR, IPSEC_CONF_DST_MASK,
				    line_no);
				return (-1);
			}
			ret = parse_mask(IPSEC_CONF_DST_MASK,
			    act_props->pattern[i],
			    cptr);
			if (ret != 0) {
				error_message(BAD_ERROR, IPSEC_CONF_DST_MASK,
				    line_no);
				return (-1);
			}
			break;
		case TOK_ulp:
			if (cptr->ips_ulp_prot != 0) {
				error_message(DUP_ERROR,
				    IPSEC_CONF_ULP, line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_ULP, line_no);
				return (-1);
			}
			pent = getprotobyname(act_props->pattern[i]);
			if (pent == NULL) {
				int ulp;
				ulp = parse_int(act_props->pattern[i]);
				if (ulp == -1) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_ULP, line_no);
					return (-1);
				}
				cptr->ips_ulp_prot = ulp;
			} else {
				cptr->ips_ulp_prot = pent->p_proto;
			}
			break;
		case TOK_type:
			if (cptr->has_type) {
				error_message(DUP_ERROR,
				    IPSEC_CONF_ICMP_TYPE, line_no);
				return (-1);
			}

			i++, line_no++;
			type = parse_type_code(act_props->pattern[i],
			    icmp_type_table);

			if (type > 65536 || type < 0) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_ICMP_TYPE, line_no);
				return (-1);
			}

			type_end = type / 256;
			type = type % 256;

			if (type_end < type)
				type_end = type;

			cptr->has_type = 1;
			cptr->ips_icmp_type = (uint8_t)type;
			cptr->ips_icmp_type_end = (uint8_t)type_end;
			break;
		case TOK_code:
			if (!cptr->has_type) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_ICMP_CODE, line_no);
				return (-1);
			}

			if (cptr->has_code) {
				error_message(DUP_ERROR,
				    IPSEC_CONF_ICMP_CODE, line_no);
				return (-1);
			}

			i++, line_no++;

			code = parse_type_code(act_props->pattern[i],
			    icmp_code_table);
			if (type > 65536 || type < 0) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_ICMP_CODE, line_no);
				return (-1);
			}
			code_end = code / 256;
			code = code % 256;

			if (code_end < code)
				code_end = code;

			cptr->has_code = 1;
			cptr->ips_icmp_code = (uint8_t)code;
			cptr->ips_icmp_code_end = (uint8_t)code_end;
			break;
		case TOK_tunnel:
			if (cptr->has_tunnel == 1) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_TUNNEL, line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_TUNNEL, line_no);
				return (-1);
			}

			if (strlcpy(tunif, act_props->pattern[i],
			    TUNNAMEMAXLEN) >= TUNNAMEMAXLEN) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_TUNNEL, line_no);
				return (-1);
			}
			cptr->has_tunnel = 1;
			break;
		case TOK_negotiate:
			if (cptr->has_negotiate == 1) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_NEGOTIATE, line_no);
				return (-1);
			}
			i++, line_no++;
			if (act_props->pattern[i] == NULL) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_NEGOTIATE, line_no);
				return (-1);
			}

			if (strncmp(act_props->pattern[i], "tunnel", 6) == 0) {
				cptr->ips_tunnel = B_TRUE;
			} else if (strncmp(
			    act_props->pattern[i], "transport", 9) != 0) {
				error_message(BAD_ERROR,
				    IPSEC_CONF_NEGOTIATE, line_no);
				return (-1);
			}
			cptr->has_negotiate = 1;
			break;
		}

	}

	/* Sanity check that certain tokens occur together */
	if (cptr->has_tunnel + cptr->has_negotiate == 1) {
		if (cptr->has_negotiate == 0) {
			error_message(REQ_ERROR, IPSEC_CONF_NEGOTIATE, line_no);
		} else {
			error_message(REQ_ERROR, IPSEC_CONF_TUNNEL, line_no);
		}
		errx(1, gettext(
		    "tunnel and negotiate tokens must occur together"));
		return (-1);
	}

	/*
	 * Get the actions.
	 */

	for (ap_num = 0; act_props->ap[ap_num].act != NULL; ap_num++) {
		ips_act_props_t *iap;

		if (ap_num > 0) {
			/* or's only with new style */
			if (old_style) {
				(void) printf("%s\n", gettext(
				    "or's only with new style"));
				return (-1);
			}
			new_style = B_TRUE;
		}

		ipsec_aalg = ipsec_ealg = ipsec_eaalg = auth_covered = B_FALSE;
		tok_count = 0;

		for (k = 0; action_table[k].string; k++) {
			if (strcmp(act_props->ap[ap_num].act,
			    action_table[k].string) == 0)
				break;
		}
		/*
		 * The following thing should never happen as
		 * we have already tested for its validity in parse.
		 */
		if (action_table[k].string == NULL) {
			warnx(gettext("(form act)Invalid action on line "
			    "%d: %s"), (arg_indices[line_no] == 0) ? 1 :
			    arg_indices[line_no],
			    act_props->ap[ap_num].act);
			warnx("%s", act_props->ap[ap_num].act);
			return (-1);
		}

		/* we have a good action alloc an iap */
		iap = alloc_iap(cptr);

		iap->iap_action = action_table[k].value;
		iap->iap_act_tok = action_table[k].tok_val;

		switch (action_table[k].tok_val) {
		case TOK_apply:
			cptr->ips_dir = SPD_RULE_FLAG_OUTBOUND;
			break;
		case TOK_permit:
			cptr->ips_dir = SPD_RULE_FLAG_INBOUND;
			break;
		case TOK_ipsec:
			if (old_style) {
				/* Using saddr/daddr with ipsec action. */
				if (!dir) {
					/* No direction specified */
					error_message(REQ_ERROR,
					    IPSEC_CONF_IPSEC_DIR, line_no);
					return (-1);
				}
				if (cptr->ips_dir == SPD_RULE_FLAG_INBOUND)
					/*
					 * Need to swap addresses if
					 * 'dir in' or translation to
					 * laddr/raddr will be incorrect.
					 */
					cptr->swap = 1;
			}
			if (!dir)
				cptr->ips_dir =
				    SPD_RULE_FLAG_INBOUND
				    |SPD_RULE_FLAG_OUTBOUND;
			break;
		case TOK_bypass:
		case TOK_drop:
			is_no_alg = B_TRUE;
			break;
		}

		line_no++;
		/*
		 * Get the properties. NULL properties is not valid.
		 * Later checks will catch it.
		 */
		for (i = 0; act_props->ap[ap_num].prop[i]; i++, line_no++) {
			for (j = 0; property_table[j].string; j++) {
				if (strcmp(act_props->ap[ap_num].prop[i],
				    property_table[j].string) == 0) {
					break;
				}
			}
			if (property_table[j].string == NULL) {
				warnx(gettext("Invalid properties on line "
				    "%d: %s"),
				    (arg_indices[line_no] == 0) ?
				    1 : arg_indices[line_no],
				    act_props->ap[ap_num].prop[i]);
				return (-1);
			}

			iap->iap_attr_tok[tok_count++]
			    = property_table[j].value;

			switch (property_table[j].value) {
			case SPD_ATTR_AH_AUTH:
				if (ipsec_aalg) {
					error_message(DUP_ERROR,
					    IPSEC_CONF_IPSEC_AALGS, line_no);
					return (-1);
				}
				i++, line_no++;
				if (act_props->ap[ap_num].prop[i] == NULL) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_AALGS, line_no);
					return (-1);
				}
				ret = parse_ipsec_alg(
				    act_props->ap[ap_num].prop[i],
				    iap, SPD_ATTR_AH_AUTH);
				if (ret == -2) {
					/* "none" - ignore */
					break;
				}
				if (ret != 0) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_AALGS, line_no);
					return (-1);
				}
				ipsec_aalg = B_TRUE;
				auth_covered = B_TRUE;
				break;
			case SPD_ATTR_ESP_ENCR:
				/*
				 * If this option was not given
				 * and encr_auth_algs was given,
				 * we provide null-encryption.  We do the
				 * setting after we parse all the options.
				 */
				if (ipsec_ealg) {
					error_message(DUP_ERROR,
					    IPSEC_CONF_IPSEC_EALGS, line_no);
					return (-1);
				}
				i++, line_no++;
				if (act_props->ap[ap_num].prop[i] == NULL) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_EALGS, line_no);
					return (-1);
				}
				ret = parse_ipsec_alg(
				    act_props->ap[ap_num].prop[i],
				    iap, SPD_ATTR_ESP_ENCR);
				if (ret == -2) {
					/* "none" - ignore */
					break;
				}
				if (ret != 0) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_EALGS, line_no);
					return (-1);
				}
				is_combined_mode =
				    combined_mode(iap->iap_eencr.alg_id);
				ipsec_ealg = B_TRUE;
				break;
			case SPD_ATTR_ESP_AUTH:
				/*
				 * If this option was not given and encr_algs
				 * option was given, we still pass a default
				 * value in ipsc_esp_auth_algs. This is to
				 * encourage the use of authentication with
				 * ESP.
				 */
				if (ipsec_eaalg) {
					error_message(DUP_ERROR,
					    IPSEC_CONF_IPSEC_EAALGS, line_no);
					return (-1);
				}
				i++, line_no++;
				if (act_props->ap[ap_num].prop[i] == NULL) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_EAALGS, line_no);
					return (-1);
				}
				ret = parse_ipsec_alg(
				    act_props->ap[ap_num].prop[i],
				    iap, SPD_ATTR_ESP_AUTH);
				if (ret == -2) {
					/* "none" - ignore */
					break;
				}
				if (ret != 0) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_EAALGS, line_no);
					return (-1);
				}
				ipsec_eaalg = B_TRUE;
				auth_covered = B_TRUE;
				break;
			case IPS_SA:
				i++, line_no++;
				if (act_props->ap[ap_num].prop[i] == NULL) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_SA, line_no);
					return (-1);
				}

				if (strcmp(act_props->ap[ap_num].prop[i],
				    "unique") == 0) {
					iap->iap_attr |= SPD_APPLY_UNIQUE;
				} else if (strcmp(act_props->ap[ap_num].prop[i],
				    "shared") != 0) {
					/* "shared" is default. */
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_SA, line_no);
					return (-1);
				}

				break;
			case IPS_DIR:
				if (dir) {
					error_message(DUP_ERROR,
					    IPSEC_CONF_IPSEC_DIR, line_no);
					return (-1);
				}
				if (new_style) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_DIR, line_no);
					return (-1);
				}
				old_style = B_TRUE;
				dir = B_TRUE;
				i++, line_no++;
				if (act_props->ap[ap_num].prop[i] == NULL) {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_DIR, line_no);
					return (-1);
				}
				if (strcmp(act_props->ap[ap_num].prop[i],
				    "out") == 0) {
					cptr->ips_dir = SPD_RULE_FLAG_OUTBOUND;
				} else if (strcmp(act_props->ap[ap_num].prop[i],
				    "in") == 0) {
					cptr->ips_dir = SPD_RULE_FLAG_INBOUND;
				} else {
					error_message(BAD_ERROR,
					    IPSEC_CONF_IPSEC_DIR, line_no);
					return (-1);
				}
				if ((cptr->ips_dir & SPD_RULE_FLAG_INBOUND) &&
				    iap->iap_act_tok == TOK_apply) {
					warnx(gettext("Direction"
					    " in conflict with action"));
					return (-1);
				}
				if ((cptr->ips_dir & SPD_RULE_FLAG_OUTBOUND) &&
				    iap->iap_act_tok == TOK_permit) {
					warnx(gettext("Direction"
					    "in conflict with action"));
					return (-1);
				}

				break;
			}
		}

		if (is_combined_mode) {
			if (ipsec_eaalg) {
				warnx(gettext("ERROR: Rule on line %d: "
				    "Combined mode and esp authentication not "
				    "supported together."),
				    arg_indices[line_no] == 0 ? 1 :
				    arg_indices[line_no]);
				return (-1);
			}
			auth_covered = B_TRUE;
		}
		/* Warn here about no authentication! */
		if (!auth_covered && !is_no_alg) {
			warnx(gettext("DANGER:  Rule on line %d "
			    "has encryption with no authentication."),
			    arg_indices[line_no] == 0 ? 1 :
			    arg_indices[line_no]);
		}

		if (!ipsec_ealg && ipsec_eaalg) {
			/*
			 * If the user has specified the auth alg to be used
			 * with encryption and did not provide a encryption
			 * algorithm, provide null encryption.
			 */
			iap->iap_eencr.alg_id = SADB_EALG_NULL;
			ipsec_ealg = B_TRUE;
		}

		/* Set the level of IPSEC protection we want */
		if (ipsec_aalg && (ipsec_ealg || ipsec_eaalg)) {
			iap->iap_attr |= SPD_APPLY_AH|SPD_APPLY_ESP;
		} else if (ipsec_aalg) {
			iap->iap_attr |= SPD_APPLY_AH;
		} else if (ipsec_ealg || ipsec_eaalg) {
			iap->iap_attr |= SPD_APPLY_ESP;
		}

		/* convert src/dst to local/remote */
		if (!new_style) {
			switch (cptr->ips_acts->iap_act_tok) {
			case TOK_apply:
				/* outbound */
				/* src=local, dst=remote */
				/* this is ok. */
				break;

			case TOK_permit:
				/* inbound */
				/* src=remote, dst=local */
				/* switch */
				cptr->swap = 1;
				break;
			case TOK_bypass:
			case TOK_drop:
				/* check the direction for what to do */
				if (cptr->ips_dir == SPD_RULE_FLAG_INBOUND)
					cptr->swap = 1;
				break;
			default:
				break;
			}
		}
		/* Validate the properties */
		if (ret = validate_properties(iap, dir,
		    (ipsec_aalg || ipsec_ealg || ipsec_eaalg))) {
			return (ret);
		}
	}

	return (0);

}

static int
print_cmd_buf(FILE *fp, int error)
{
	*(cbuf + cbuf_offset) = '\0';

	if (fp == stderr) {
		if (error != EEXIST) {
			warnx(gettext("Malformed command (fatal):\n%s"), cbuf);
			return (0);
		}
		if (ipsecconf_qflag) {
			return (0);
		}
		warnx(gettext("Duplicate policy entry (ignored):\n%s"), cbuf);
	} else {
		if (fprintf(fp, "%s", cbuf) == -1) {
			warn("fprintf");
			return (-1);
		}
	}

	return (0);
}

#ifdef	DEBUG

static uchar_t *
addr_ptr(int isv4, struct in6_addr *addr6, struct in_addr *addr4)
{
	if (isv4) {
		IN6_V4MAPPED_TO_INADDR(addr6, addr4);
		return ((uchar_t *)&addr4->s_addr);
	} else {
		return ((uchar_t *)&addr6->s6_addr);
	}
}

static void
dump_algreq(const char *tag, algreq_t *alg)
{
	(void) printf("%s algid %d, bits %d..%d\n",
	    tag, alg->alg_id, alg->alg_minbits, alg->alg_maxbits);
}

static void
dump_conf(ips_conf_t *conf)
{
	boolean_t isv4 = conf->ips_isv4;
	struct in_addr addr;
	char buf[INET6_ADDRSTRLEN];
	int af;
	ips_act_props_t *iap = conf->ips_acts;

	af = isv4 ? AF_INET : AF_INET6;

	(void) printf("Source Addr is %s\n",
	    inet_ntop(af, addr_ptr(isv4, &conf->ips_src_addr_v6, &addr),
	    buf, INET6_ADDRSTRLEN));

	(void) printf("Dest Addr is %s\n",
	    inet_ntop(af, addr_ptr(isv4, &conf->ips_dst_addr_v6, &addr),
	    buf, INET6_ADDRSTRLEN));

	(void) printf("Source Mask is %s\n",
	    inet_ntop(af, addr_ptr(isv4, &conf->ips_src_mask_v6, &addr),
	    buf, INET6_ADDRSTRLEN));

	(void) printf("Dest Mask is %s\n",
	    inet_ntop(af, addr_ptr(isv4, &conf->ips_dst_mask_v6, &addr),
	    buf, INET6_ADDRSTRLEN));

	(void) printf("Source port %d\n", ntohs(conf->ips_src_port_min));
	(void) printf("Dest port %d\n", ntohs(conf->ips_dst_port_min));
	(void) printf("ULP %d\n", conf->ips_ulp_prot);

	(void) printf("ICMP type %d-%d code %d-%d", conf->ips_icmp_type,
	    conf->ips_icmp_type_end,
	    conf->ips_icmp_code,
	    conf->ips_icmp_code_end);

	while (iap != NULL) {
		(void) printf("------------------------------------\n");
		(void) printf("IPsec act is %d\n", iap->iap_action);
		(void) printf("IPsec attr is %d\n", iap->iap_attr);
		dump_algreq("AH authentication", &iap->iap_aauth);
		dump_algreq("ESP authentication", &iap->iap_eauth);
		dump_algreq("ESP encryption", &iap->iap_eencr);
		(void) printf("------------------------------------\n");
		iap = iap->iap_next;
	}

	(void) fflush(stdout);
}
#endif	/* DEBUG */


static int
ipsec_conf_add(boolean_t just_check, boolean_t smf_managed, boolean_t replace)
{
	act_prop_t *act_props = malloc(sizeof (act_prop_t));
	ips_conf_t conf;
	FILE *fp, *policy_fp;
	int ret, flushret, i, j, diag, num_rules, good_rules;
	char *warning = gettext(
	    "\tWARNING : New policy entries that are being added may\n "
	    "\taffect the existing connections. Existing connections\n"
	    "\tthat are not subjected to policy constraints, may be\n"
	    "\tsubjected to policy constraints because of the new\n"
	    "\tpolicy. This can disrupt the communication of the\n"
	    "\texisting connections.\n\n");

	boolean_t first_time = B_TRUE;
	num_rules = 0;
	good_rules = 0;

	if (act_props == NULL) {
		warn(gettext("memory"));
		return (-1);
	}

	if (strcmp(filename, "-") == 0)
		fp = stdin;
	else
		fp = fopen(filename, "r");

	/*
	 * Treat the non-existence of a policy file as a special
	 * case when ipsecconf is being managed by smf(5).
	 * The assumption is the administrator has not yet
	 * created a policy file, this should not force the service
	 * into maintenance mode.
	 */

	if (fp == NULL) {
		if (smf_managed) {
			(void) fprintf(stdout, gettext(
			    "Policy configuration file (%s) does not exist.\n"
			    "IPsec policy not configured.\n"), filename);
			return (0);
		}
		warn(gettext("%s : Policy config file cannot be opened"),
		    filename);
		usage();
		return (-1);
	}
	/*
	 * This will create the file if it does not exist.
	 * Make sure the umask is right.
	 */
	(void) umask(0022);
	policy_fp = fopen(POLICY_CONF_FILE, "a");
	if (policy_fp == NULL) {
		warn(gettext("%s cannot be opened"), POLICY_CONF_FILE);
		return (-1);
	}

	/*
	 * Pattern, action, and properties are allocated in
	 * parse_pattern_or_prop and in parse_action (called by
	 * parse_one) as we parse arguments.
	 */
	while ((ret = parse_one(fp, act_props)) != PARSE_EOF) {
		num_rules++;
		if (ret != 0) {
			(void) print_cmd_buf(stderr, NOERROR);
			continue;
		}

		/*
		 * If there is no action and parse returned success,
		 * it means that there is nothing to add.
		 */
		if (act_props->pattern[0] == NULL &&
		    act_props->ap[0].act == NULL)
				break;

		ret = form_ipsec_conf(act_props, &conf);
		if (ret != 0) {
			warnx(gettext("form_ipsec_conf error"));
			(void) print_cmd_buf(stderr, NOERROR);
			/* Reset globals before trying the next rule. */
			if (shp != NULL) {
				freehostent(shp);
				shp = NULL;
			}
			if (dhp != NULL) {
				freehostent(dhp);
				dhp = NULL;
			}
			splen = 0;
			dplen = 0;
			continue;
		}

		good_rules++;

		if (first_time) {
			/*
			 * Time to assume that there are valid policy entries.
			 * If the IPsec kernel modules are not loaded this
			 * will load them now.
			 */
			first_time = B_FALSE;
			fetch_algorithms();
			ipsec_conf_admin(SPD_CLONE);

			/*
			 * The default behaviour for IPSEC_CONF_ADD is to append
			 * the new rules to the existing policy. If a new rule
			 * collides with an existing rule, the new rule won't be
			 * added.
			 *
			 * To perform an atomic policy replace, we really don't
			 * care what the existing policy was, just replace it
			 * with the new one. Remove all rules from the SPD_CLONE
			 * policy before checking the new rules.
			 */
			if (replace) {
				flushret = ipsec_conf_flush(SPD_STANDBY);
				if (flushret != 0)
					return (flushret);
			}
		}

		/*
		 * shp, dhp, splen, and dplen are globals set by
		 * form_ipsec_conf() while parsing the addresses.
		 */
		if (shp == NULL && dhp == NULL) {
			switch (do_port_adds(&conf)) {
			case 0:
				/* no error */
				break;
			case EEXIST:
				/* duplicate entries, continue adds */
				(void) print_cmd_buf(stderr, EEXIST);
				goto next;
			default:
				/* other error, bail */
				ret = -1;
				goto bail;
			}
		} else {
			ret = do_address_adds(&conf, &diag);
			switch (ret) {
			case 0:
				/* no error. */
				break;
			case EEXIST:
				(void) print_cmd_buf(stderr, EEXIST);
				goto next;
			case EBUSY:
				warnx(gettext(
				    "Can't set mask and /NN prefix."));
				ret = -1;
				break;
			case ENOENT:
				warnx(gettext("Cannot find tunnel "
				    "interface %s."), interface_name);
				ret = -1;
				break;
			case EINVAL:
				/*
				 * PF_POLICY didn't like what we sent.  We
				 * can't check all input up here, but we
				 * do in-kernel.
				 */
				warnx(gettext("PF_POLICY invalid input:\n\t%s"),
				    spdsock_diag(diag));
				break;
			case EOPNOTSUPP:
				warnx(gettext("Can't set /NN"
				    " prefix on multi-host name."));
				ret = -1;
				break;
			case ERANGE:
				warnx(gettext("/NN prefix is too big!"));
				ret = -1;
				break;
			case ESRCH:
				warnx(gettext("No matching IPv4 or "
				    "IPv6 saddr/daddr pairs"));
				ret = -1;
				break;
			default:
				/* Should never get here. */
				errno = ret;
				warn(gettext("Misc. error"));
				ret = -1;
			}
			if (ret == -1)
				goto bail;
		}

		/*
		 * Go ahead and add policy entries to config file.
		 * The # should help re-using the ipsecpolicy.conf
		 * for input again as # will be treated as comment.
		 */
		if (fprintf(policy_fp, "%s %lld \n", INDEX_TAG,
		    conf.ips_policy_index) == -1) {
			warn("fprintf");
			warnx(gettext("Addition incomplete, Please "
			    "flush all the entries and re-configure :"));
			reconfigure();
			ret = -1;
			break;
		}
		if (print_cmd_buf(policy_fp, NOERROR) == -1) {
			warnx(gettext("Addition incomplete. Please "
			    "flush all the entries and re-configure :"));
			reconfigure();
			ret = -1;
			break;
		}
		/*
		 * We add one newline by default to separate out the
		 * entries. If the last character is not a newline, we
		 * insert a newline for free. This makes sure that all
		 * entries look consistent in the file.
		 */
		if (*(cbuf + cbuf_offset - 1) == '\n') {
			if (fprintf(policy_fp, "\n") == -1) {
				warn("fprintf");
				warnx(gettext("Addition incomplete. "
				    "Please flush all the entries and "
				    "re-configure :"));
				reconfigure();
				ret = -1;
				break;
			}
		} else {
			if (fprintf(policy_fp, "\n\n") == -1) {
				warn("fprintf");
				warnx(gettext("Addition incomplete. "
				    "Please flush all the entries and "
				    "re-configure :"));
				reconfigure();
				ret = -1;
				break;
			}
		}
next:
		/*
		 * Make sure this gets to the disk before
		 * we parse the next entry.
		 */
		(void) fflush(policy_fp);
		for (i = 0; act_props->pattern[i] != NULL; i++)
			free(act_props->pattern[i]);
		for (j = 0; act_props->ap[j].act != NULL; j++) {
			free(act_props->ap[j].act);
			for (i = 0; act_props->ap[j].prop[i] != NULL; i++)
				free(act_props->ap[j].prop[i]);
		}
	}
	if (ret == PARSE_EOF)
		ret = 0; /* Not an error */
bail:
	if (ret == -1) {
		(void) print_cmd_buf(stderr, EINVAL);
		for (i = 0; act_props->pattern[i] != NULL; i++)
			free(act_props->pattern[i]);
		for (j = 0; act_props->ap[j].act != NULL; j++) {
			free(act_props->ap[j].act);
			for (i = 0; act_props->ap[j].prop[i] != NULL; i++)
				free(act_props->ap[j].prop[i]);
		}
	}
#ifdef DEBUG_HEAVY
	(void) printf("ipsec_conf_add: ret val = %d\n", ret);
	(void) fflush(stdout);
#endif
	if (num_rules == 0 && ret == 0) {
		nuke_adds();
		(void) restore_all_signals();
		(void) unlock(lfd);
		EXIT_OK("Policy file does not contain any valid rules.");
	}
	if (num_rules != good_rules) {
		/* This is an error */
		nuke_adds();
		(void) restore_all_signals();
		(void) unlock(lfd);
		EXIT_BADCONFIG2("%d policy rule(s) contained errors.",
		    num_rules - good_rules);
	}
	/* looks good, flip it in */
	if (ret == 0 && !just_check) {
		if (!ipsecconf_qflag) {
			(void) printf("%s", warning);
		}
		if (smf_managed)
			warnx(gettext("%d policy rules added."), good_rules);
		ipsec_conf_admin(SPD_FLIP);
	} else {
		nuke_adds();
		if (just_check) {
			(void) fprintf(stdout, gettext("IPsec configuration "
			    "does not contain any errors.\n"));
			(void) fprintf(stdout, gettext(
			    "IPsec policy was not modified.\n"));
			(void) fflush(stdout);
		}
	}
	flushret = ipsec_conf_flush(SPD_STANDBY);
	if (flushret != 0)
		return (flushret);
	return (ret);
}


static int
ipsec_conf_sub()
{
	act_prop_t *act_props = malloc(sizeof (act_prop_t));
	FILE *remove_fp, *policy_fp;
	char rbuf[MAXLEN], pbuf[MAXLEN], /* remove buffer, and policy buffer */
	    *warning = gettext(
	    "\tWARNING: Policy entries that are being removed may\n"
	    "\taffect the existing connections.  Existing connections\n"
	    "\tthat are subjected to policy constraints may no longer\n"
	    "\tbe subjected to policy contraints because of its\n"
	    "\tremoval.  This can compromise security, and disrupt\n"
	    "\tthe communication of the existing connection.\n"
	    "\tConnections that are latched will remain unaffected\n"
	    "\tuntil they close.\n");
	int ret = 0;
	int index_len, pindex = 0; /* init value in case of pfile error */

	if (act_props == NULL) {
		warn(gettext("memory"));
		return (-1);
	}

	/* clone into standby DB */
	(void) ipsec_conf_admin(SPD_CLONE);

	if (strcmp(filename, "-") == 0)
		remove_fp = stdin;
	else
		remove_fp = fopen(filename, "r");

	if (remove_fp == NULL) {
		warn(gettext("%s : Input file cannot be opened"), filename);
		usage();
		free(act_props);
		return (-1);
	}

	/* open policy file so we can locate the correct policy */
	(void) umask(0022);  /* in case it gets created! */
	policy_fp = fopen(POLICY_CONF_FILE, "r+");
	if (policy_fp == NULL) {
		warn(gettext("%s cannot be opened"), POLICY_CONF_FILE);
		(void) fclose(remove_fp);
		free(act_props);
		return (-1);
	}

	/* don't print the warning if we're in q[uiet] mode */
	if (!ipsecconf_qflag)
		(void) printf("%s", warning);

	/* this bit is done primarily so we can read what we write */
	index_len = strlen(INDEX_TAG);

	/*
	 * We want to look for the policy in rbuf in the policy file.
	 * Go through the list of policies to remove, locating each one.
	 */
	while (fgets(rbuf, MAXLEN, remove_fp) != NULL) {
		char *buf;
		int offset, prev_offset, prev_prev_offset, nlines;
		fpos_t ipos;
		int pbuf_len = 0;
		char *tmp;
		/* skip blanks here (so we don't need to do it below)! */
		for (tmp = rbuf; (*tmp != '\0') && isspace(*tmp); )
			tmp++;

		if (*tmp == '\0')
			continue; /* while(); */

		/* skip the INDEX_TAG lines in the remove buffer */
		if (strncasecmp(rbuf, INDEX_TAG, index_len) == 0)
			continue;

		/* skip commented lines */
		if (*tmp == '#')
			continue; /* while(); */

		/*
		 * We start by presuming only good policies are in the pfile,
		 * and so only good policies from the rfile will match them.
		 * ipsec_conf_del ensures this later by calling parse_one() on
		 * pfile before it deletes the entry.
		 */
		for (offset = prev_offset = prev_prev_offset = 0;
		    fgets(pbuf, MAXLEN, policy_fp) != NULL;
		    offset += pbuf_len) {
			prev_offset = offset;
			pbuf_len = strlen(pbuf);

			/* skip blank lines which seperate policy entries */
			if (pbuf[0] == '\n')
				continue;

			/* if we found an index, save it */
			if (strncasecmp(pbuf, INDEX_TAG, index_len) == 0) {
				buf = pbuf + index_len;
				buf++;
				if ((pindex = parse_index(buf, NULL)) == -1) {
					/* bad index, we can't continue */
					warnx(gettext(
					    "Invalid index in the file"));
					(void) fclose(remove_fp);
					(void) fclose(policy_fp);
					free(act_props);
					return (-1);
				}

				/* save this position in case it's the one */
				if (fgetpos(policy_fp, &ipos) != 0) {
					(void) fclose(remove_fp);
					(void) fclose(policy_fp);
					free(act_props);
					return (-1);
				}
			}

			/* Does pbuf contain the remove policy? */
			if (strncasecmp(rbuf, pbuf, pbuf_len) == 0) {
				/* we found the one to remove! */
				if (pindex == 0) {
					warnx(gettext("Didn't find a valid "
					    "index for policy"));
					(void) fclose(remove_fp);
					(void) fclose(policy_fp);
					free(act_props);
					return (-1);
				}

				/* off it - back up to the last INDEX! */
				if (fsetpos(policy_fp, &ipos) != 0) {
					(void) fclose(remove_fp);
					(void) fclose(policy_fp);
					free(act_props);
					return (-1);
				}

				/* parse_one sets linecount = #lines to off */
				if (parse_one(policy_fp, act_props) == -1) {
					warnx(gettext("Invalid policy entry "
					    "in the file"));
					(void) fclose(remove_fp);
					(void) fclose(policy_fp);
					free(act_props);
					return (-1);
				}

				nlines = linecount + 2;
				goto delete;
			}
			/*
			 * When we find a match, we want to pass the offset
			 * of the line that is before it - the INDEX_TAG line.
			 */
			prev_prev_offset = prev_offset;
		}
		/* Didn't find a match - look at the next remove policy */
		continue; /* while(); */

delete:
		(void) fclose(policy_fp);

		if (delete_from_file(prev_prev_offset, nlines) != 0) {
			warnx(gettext("delete_from_file failure.  "
			    "Please flush all entries and re-configure :"));
			reconfigure();
			(void) fclose(remove_fp);
			free(act_props);
			return (-1);
		}

		if (pfp_delete_rule(pindex) != 0) {
			warnx(gettext("Deletion incomplete. Please flush"
			    "all the entries and re-configure :"));
			reconfigure();
			(void) fclose(remove_fp);
			free(act_props);
			return (-1);
		}

		/* reset the globals */
		linecount = 0;
		pindex = 0;
		/* free(NULL) also works. */
		free(interface_name);
		interface_name = NULL;

		/* reopen for next pass, automagically starting over. */
		policy_fp = fopen(POLICY_CONF_FILE, "r");
		if (policy_fp == NULL) {
			warn(gettext("%s cannot be re-opened, can't continue"),
			    POLICY_CONF_FILE);
			(void) fclose(remove_fp);
			free(act_props);
			return (-1);
		}

	} /* read next remove policy */

	if ((ret = pfp_delete_rule(pindex)) != 0) {
		warnx(gettext("Removal incomplete.  Please flush "
		    "all the entries and re-configure :"));
		reconfigure();
		free(act_props);
		return (ret);
	}

	/* nothing left to look for */
	(void) fclose(remove_fp);
	free(act_props);

	return (0);
}

/*
 * Constructs a tunnel interface ID extension.  Returns the length
 * of the extension in 64-bit-words.
 */
static int
attach_tunname(spd_if_t *tunname)
{
	if (tunname == NULL || interface_name == NULL)
		return (0);

	tunname->spd_if_exttype = SPD_EXT_TUN_NAME;
	/*
	 * Use "-3" because there's 4 bytes in the message itself, and
	 * we lose one because of the '\0' terminator.
	 */
	tunname->spd_if_len = SPD_8TO64(
	    P2ROUNDUP(sizeof (*tunname) + strlen(interface_name) - 3, 8));
	(void) strlcpy((char *)tunname->spd_if_name, interface_name, LIFNAMSIZ);
	return (tunname->spd_if_len);
}
