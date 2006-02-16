%{
#include "ipf.h"
#undef	OPT_NAT
#undef	OPT_VERBOSE
#include "ipmon_l.h"
#include "ipmon.h"

#define	YYDEBUG	1

extern	void	yyerror __P((char *));
extern	int	yyparse __P((void));
extern	int	yylex __P((void));
extern	int	yydebug;
extern	FILE	*yyin;
extern	int	yylineNum;

typedef	struct	opt	{
	struct	opt	*o_next;
	int		o_line;
	int		o_type;
	int		o_num;
	char		*o_str;
	struct in_addr	o_ip;
} opt_t;

static	void	build_action __P((struct opt *));
static	opt_t	*new_opt __P((int));

static	action_t	*alist = NULL;
%}

%union	{
	char	*str;
	u_32_t	num;
	struct in_addr	addr;
	struct opt	*opt;
	union	i6addr	ip6;
}

%token  <num>   YY_NUMBER YY_HEX
%token  <str>   YY_STR
%token	  YY_COMMENT 
%token	  YY_CMP_EQ YY_CMP_NE YY_CMP_LE YY_CMP_GE YY_CMP_LT YY_CMP_GT
%token	  YY_RANGE_OUT YY_RANGE_IN
%token  <ip6>   YY_IPV6

%token	IPM_ACTION IPM_BODY IPM_COMMENT IPM_DIRECTION IPM_DSTIP IPM_DSTPORT
%token	IPM_EVERY IPM_EXECUTE IPM_GROUP IPM_INTERFACE IPM_IN IPM_NO IPM_OUT
%token	IPM_PACKET IPM_PACKETS IPM_POOL IPM_PROTOCOL IPM_RESULT IPM_RULE
%token	IPM_SECOND IPM_SECONDS IPM_SRCIP IPM_SRCPORT IPM_TAG IPM_YES
%type	<addr> ipv4
%type	<opt> direction dstip dstport every execute group interface option
%type	<opt> options protocol result rule srcip srcport tag

%%
file:	line
	| assign
	| file line
	| file assign
	;

line:	IPM_ACTION '{' options '}' ';'	{ build_action($3); resetlexer(); }
	| IPM_COMMENT
	;

assign:	YY_STR assigning YY_STR ';'		{ set_variable($1, $3);
						  resetlexer();
						  free($1);
						  free($3);
						} 
	;

assigning:
	'='					{ yyvarnext = 1; }
	;

options:
	option					{ $$ = $1; }
	| option ',' options			{ $1->o_next = $3; $$ = $1; }
	;

option:	direction				{ $$ = $1; }
	| dstip					{ $$ = $1; }
	| dstport				{ $$ = $1; }
	| every					{ $$ = $1; }
	| execute				{ $$ = $1; }
	| group					{ $$ = $1; }
	| interface				{ $$ = $1; }
	| protocol				{ $$ = $1; }
	| result				{ $$ = $1; }
	| rule					{ $$ = $1; }
	| srcip					{ $$ = $1; }
	| srcport				{ $$ = $1; }
	| tag					{ $$ = $1; }
	;

direction:
	IPM_DIRECTION '=' IPM_IN		{ $$ = new_opt(IPM_DIRECTION);
						  $$->o_num = IPM_IN; }
	| IPM_DIRECTION '=' IPM_OUT		{ $$ = new_opt(IPM_DIRECTION);
						  $$->o_num = IPM_OUT; }
	;

dstip:	IPM_DSTIP '=' ipv4 '/' YY_NUMBER	{ $$ = new_opt(IPM_DSTIP);
						  $$->o_ip = $3;
						  $$->o_num = $5; }
	;

dstport:
	IPM_DSTPORT '=' YY_NUMBER		{ $$ = new_opt(IPM_DSTPORT);
						  $$->o_num = $3; }
	| IPM_DSTPORT '=' YY_STR		{ $$ = new_opt(IPM_DSTPORT);
						  $$->o_str = $3; }
	;

every:	IPM_EVERY IPM_SECOND			{ $$ = new_opt(IPM_SECOND);
						  $$->o_num = 1; }
	| IPM_EVERY YY_NUMBER IPM_SECONDS	{ $$ = new_opt(IPM_SECOND);
						  $$->o_num = $2; }
	| IPM_EVERY IPM_PACKET			{ $$ = new_opt(IPM_PACKET);
						  $$->o_num = 1; }
	| IPM_EVERY YY_NUMBER IPM_PACKETS	{ $$ = new_opt(IPM_PACKET);
						  $$->o_num = $2; }
	;

execute:
	IPM_EXECUTE '=' YY_STR			{ $$ = new_opt(IPM_EXECUTE);
						  $$->o_str = $3; }
	;

group:	IPM_GROUP '=' YY_NUMBER			{ $$ = new_opt(IPM_GROUP);
						  $$->o_num = $3; }
	| IPM_GROUP '=' YY_STR			{ $$ = new_opt(IPM_GROUP);
						  $$->o_str = $3; }
	;

interface:
	IPM_INTERFACE '=' YY_STR		{ $$ = new_opt(IPM_INTERFACE);
						  $$->o_str = $3; }
	;

protocol:
	IPM_PROTOCOL '=' YY_NUMBER		{ $$ = new_opt(IPM_PROTOCOL);
						  $$->o_num = $3; }
	| IPM_PROTOCOL '=' YY_STR		{ $$ = new_opt(IPM_PROTOCOL);
						  $$->o_num = getproto($3);
						  free($3);
						}
	;

result:	IPM_RESULT '=' YY_STR			{ $$ = new_opt(IPM_RESULT);
						  $$->o_str = $3; }
	;

rule:	IPM_RULE '=' YY_NUMBER			{ $$ = new_opt(IPM_RULE);
						  $$->o_num = YY_NUMBER; }
	;

srcip:	IPM_SRCIP '=' ipv4 '/' YY_NUMBER	{ $$ = new_opt(IPM_SRCIP);
						  $$->o_ip = $3;
						  $$->o_num = $5; }
	;

srcport:
	IPM_SRCPORT '=' YY_NUMBER		{ $$ = new_opt(IPM_SRCPORT);
						  $$->o_num = $3; }
	| IPM_SRCPORT '=' YY_STR		{ $$ = new_opt(IPM_SRCPORT);
						  $$->o_str = $3; }
	;

tag:	IPM_TAG '=' YY_NUMBER			{ $$ = new_opt(IPM_TAG);
						  $$->o_num = $3; }
	;

ipv4:   YY_NUMBER '.' YY_NUMBER '.' YY_NUMBER '.' YY_NUMBER
		{ if ($1 > 255 || $3 > 255 || $5 > 255 || $7 > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  $$.s_addr = ($1 << 24) | ($3 << 16) | ($5 << 8) | $7;
		  $$.s_addr = htonl($$.s_addr);
		}
%%
static	struct	wordtab	yywords[] = {
	{ "action",	IPM_ACTION },
	{ "body",	IPM_BODY },
	{ "direction",	IPM_DIRECTION },
	{ "dstip",	IPM_DSTIP },
	{ "dstport",	IPM_DSTPORT },
	{ "every",	IPM_EVERY },
	{ "execute",	IPM_EXECUTE },
	{ "group",	IPM_GROUP },
	{ "in",		IPM_IN },
	{ "interface",	IPM_INTERFACE },
	{ "no",		IPM_NO },
	{ "out",	IPM_OUT },
	{ "packet",	IPM_PACKET },
	{ "packets",	IPM_PACKETS },
	{ "protocol",	IPM_PROTOCOL },
	{ "result",	IPM_RESULT },
	{ "rule",	IPM_RULE },
	{ "second",	IPM_SECOND },
	{ "seconds",	IPM_SECONDS },
	{ "srcip",	IPM_SRCIP },
	{ "srcport",	IPM_SRCPORT },
	{ "tag",	IPM_TAG },
	{ "yes",	IPM_YES },
	{ NULL,		0 }
};

static int macflags[15][2] = {
	{ IPM_DIRECTION,	IPMAC_DIRECTION	},
	{ IPM_DSTIP,		IPMAC_DSTIP	},
	{ IPM_DSTPORT,		IPMAC_DSTPORT	},
	{ IPM_EXECUTE,		IPMAC_EXECUTE	},
	{ IPM_GROUP,		IPMAC_GROUP	},
	{ IPM_INTERFACE,	IPMAC_INTERFACE	},
	{ IPM_PACKET,		IPMAC_EVERY	},
	{ IPM_PROTOCOL,		IPMAC_PROTOCOL	},
	{ IPM_RESULT,		IPMAC_RESULT	},
	{ IPM_RULE,		IPMAC_RULE	},
	{ IPM_SECOND,		IPMAC_EVERY	},
	{ IPM_SRCIP,		IPMAC_SRCIP	},
	{ IPM_SRCPORT,		IPMAC_SRCPORT	},
	{ IPM_TAG,		IPMAC_TAG 	},
	{ 0, 0 }
};

static opt_t *new_opt(type)
int type;
{
	opt_t *o;

	o = (opt_t *)malloc(sizeof(*o));
	if (o == NULL)
		yyerror("sorry, out of memory");
	o->o_type = type;
	o->o_line = yylineNum;
	o->o_num = 0;
	o->o_str = (char *)0;
	return o;
}

static void build_action(olist)
opt_t *olist;
{
	action_t *a;
	opt_t *o;
	u_32_t m;
	char c;
	int i;

	a = (action_t *)calloc(1, sizeof(*a));
	if (!a)
		return;
	while ((o = olist)) {
		for (i = 0; macflags[i][0]; i++)
			if (macflags[i][0] == o->o_type)
				break;
		if (macflags[i][1] & a->ac_mflag) {
			fprintf(stderr, "%s redfined on line %d\n",
				yykeytostr(o->o_type), yylineNum);
			if (o->o_str != NULL)
				free(o->o_str);
			olist = o->o_next;
			free(o);
			continue;
		}

		a->ac_mflag |= macflags[i][1];

		switch (o->o_type)
		{
		case IPM_DIRECTION :
			a->ac_direction = o->o_num;
			break;
		case IPM_DSTIP :
			a->ac_dip = o->o_ip.s_addr;
			for (i = o->o_num, m = 0; i; i--) {
				m >>= 1;
				m |= 0x80000000;
			}
			a->ac_dmsk = htonl(m);
			break;
		case IPM_DSTPORT :
			a->ac_dport = htons(o->o_num);
			break;
		case IPM_EXECUTE :
			a->ac_exec = o->o_str;
			c = *o->o_str;
			if (c== '"'|| c == '\'') {
				if (o->o_str[strlen(o->o_str) - 1] == c) {
					a->ac_run = strdup(o->o_str + 1);
					a->ac_run[strlen(a->ac_run) - 1] ='\0';
				} else
					a->ac_run = o->o_str;
			} else
				a->ac_run = o->o_str;
			o->o_str = NULL;
			break;
		case IPM_INTERFACE :
			a->ac_iface = o->o_str;
			o->o_str = NULL;
			break;
		case IPM_GROUP : 
			if (o->o_str != NULL)
				strncpy(a->ac_group, o->o_str, FR_GROUPLEN);
			else
				sprintf(a->ac_group, "%d", o->o_num);
			break;
		case IPM_PACKET :
			a->ac_packet = o->o_num;
			break;
		case IPM_PROTOCOL :
			a->ac_proto = o->o_num;
			break;
		case IPM_RULE :
			a->ac_rule = o->o_num;
			break;
		case IPM_RESULT :
			if (!strcasecmp(o->o_str, "pass"))
				a->ac_result = IPMR_PASS;
			else if (!strcasecmp(o->o_str, "block"))
				a->ac_result = IPMR_BLOCK;
			else if (!strcasecmp(o->o_str, "short"))
				a->ac_result = IPMR_SHORT;
			else if (!strcasecmp(o->o_str, "nomatch"))
				a->ac_result = IPMR_NOMATCH;
			else if (!strcasecmp(o->o_str, "log"))
				a->ac_result = IPMR_LOG;
			break;
		case IPM_SECOND :
			a->ac_second = o->o_num;
			break;
		case IPM_SRCIP :
			a->ac_sip = o->o_ip.s_addr;
			for (i = o->o_num, m = 0; i; i--) {
				m >>= 1;
				m |= 0x80000000;
			}
			a->ac_smsk = htonl(m);
			break;
		case IPM_SRCPORT :
			a->ac_sport = htons(o->o_num);
			break;
		case IPM_TAG :
			a->ac_tag = o->o_num;
			break;
		default :
			break;
		}

		olist = o->o_next;
		if (o->o_str != NULL)
			free(o->o_str);
		free(o);
	}
	a->a_next = alist;
	alist = a;
}


void check_action(buf, opts, log)
char *buf;
int opts;
char *log;
{
	struct timeval tv;
	ipflog_t *ipf;
	tcphdr_t *tcp;
	iplog_t *ipl;
	action_t *a;
	u_long t1;
	ip_t *ip;

	ipl = (iplog_t *)buf;
	ipf = (ipflog_t *)(ipl +1);
	ip = (ip_t *)(ipf + 1);
	tcp = (tcphdr_t *)((char *)ip + (IP_HL(ip) << 2));

	for (a = alist; a; a = a->a_next) {
		if (a->ac_mflag & IPMAC_DIRECTION) {
			if (a->ac_direction == IPM_IN) {
				if (!(ipf->fl_flags & FR_INQUE))
					continue;
			} else if (a->ac_direction == IPM_OUT) {
				if (!(ipf->fl_flags & FR_OUTQUE))
					continue;
			}
		}

		if (a->ac_mflag & IPMAC_EVERY) {
			gettimeofday(&tv, NULL);
			t1 = tv.tv_sec - a->ac_lastsec;
			if (tv.tv_usec <= a->ac_lastusec)
				t1--;
			if (a->ac_second) {
				if (t1 < a->ac_second)
					continue;
				a->ac_lastsec = tv.tv_sec;
				a->ac_lastusec = tv.tv_usec;
			}

			if (a->ac_packet) {
				if (!a->ac_pktcnt)
					a->ac_pktcnt++;
				else if (a->ac_pktcnt == a->ac_packet) {
					a->ac_pktcnt = 0;
					continue;
				} else {
					a->ac_pktcnt++;
					continue;
				}
			}
		}

		if (a->ac_mflag & IPMAC_DSTIP) {
			if ((ip->ip_dst.s_addr & a->ac_dmsk) != a->ac_dip)
				continue;
		}

		if (a->ac_mflag & IPMAC_DSTPORT) {
			if (ip->ip_p != IPPROTO_UDP && ip->ip_p != IPPROTO_TCP)
				continue;
			if (tcp->th_dport != a->ac_dport)
				continue;
		}

		if (a->ac_mflag & IPMAC_GROUP) {
			if (strncmp(a->ac_group, ipf->fl_group,
				    FR_GROUPLEN) != 0)
				continue;
		}

		if (a->ac_mflag & IPMAC_INTERFACE) {
			if (strcmp(a->ac_iface, ipf->fl_ifname))
				continue;
		}

		if (a->ac_mflag & IPMAC_PROTOCOL) {
			if (a->ac_proto != ip->ip_p)
				continue;
		}

		if (a->ac_mflag & IPMAC_RESULT) {
			if (ipf->fl_lflags & FI_SHORT) {
				if (a->ac_result != IPMR_SHORT)
					continue;
			} else if (FR_ISPASS(ipf->fl_flags)) {
				if (a->ac_result != IPMR_PASS)
					continue;
			} else if (FR_ISBLOCK(ipf->fl_flags)) {
				if (a->ac_result != IPMR_BLOCK)
					continue;
			} else if (ipf->fl_flags & FF_LOGNOMATCH) {
				if (a->ac_result != IPMR_NOMATCH)
					continue;
			} else {	/* Log only */
				if (a->ac_result != IPMR_LOG)
					continue;
			}
		}

		if (a->ac_mflag & IPMAC_RULE) {
			if (a->ac_rule != ipf->fl_rule)
				continue;
		}

		if (a->ac_mflag & IPMAC_SRCIP) {
			if ((ip->ip_src.s_addr & a->ac_smsk) != a->ac_sip)
				continue;
		}

		if (a->ac_mflag & IPMAC_SRCPORT) {
			if (ip->ip_p != IPPROTO_UDP && ip->ip_p != IPPROTO_TCP)
				continue;
			if (tcp->th_sport != a->ac_sport)
				continue;
		}

		if (a->ac_mflag & IPMAC_TAG) {
			if (a->ac_tag != ipf->fl_tag)
				continue;
		}

		/*
		 * It matched so now execute the command
		 */
		if (a->ac_exec) {
			switch (fork())
			{
			case 0 :
			{
				FILE *pi;

				pi = popen(a->ac_run, "w");
				if (pi) {
					fprintf(pi, "%s\n", log);
					if (opts & OPT_HEXHDR) {
						dumphex(pi, 0, buf,
							sizeof(*ipl) +
							sizeof(*ipf));
					}
					if (opts & OPT_HEXBODY) {
						dumphex(pi, 0, (char *)ip,
							ipf->fl_hlen +
							ipf->fl_plen);
					}
					pclose(pi);
				}
				exit(1);
			}
			case -1 :
				break;
			default :
				break;
			}
		}
	}
}


int load_config(file)
char *file;
{
	FILE *fp;

	yylineNum = 0;

	(void) yysettab(yywords);

	fp = fopen(file, "r");
	if (!fp) {
		perror("load_config:fopen:");
		return -1;
	}
	yyin = fp;
	while (!feof(fp))
		yyparse();
	fclose(fp);
	return 0;
}
