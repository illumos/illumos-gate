%{
/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include "ipf.h"
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <syslog.h>
#ifdef IPFILTER_BPF
# include <net/bpf.h>
# include <pcap-int.h>
# include <pcap.h>
#endif
#if SOLARIS2 >= 10
#include "ip_pool.h"
#include "ip_htable.h"
#include "ipl.h"
#else
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
#include "netinet/ipl.h"
#endif
#include "ipf_l.h"

#define	YYDEBUG	1
#define	DOALL(x)	for (fr = frc; fr != NULL; fr = fr->fr_next) { x }
#define	DOREM(x)	for (; fr != NULL; fr = fr->fr_next) { x }
#if SOLARIS2 >= 10
#define VNI	"vni"
#define VNISTRLEN 3
#endif

#define OPTION_LOG		0x1
#define OPTION_QUICK		0x2
#define OPTION_DUP		0x4
#define OPTION_PROUTE		0x8
#define OPTION_ON		0x10
#define OPTION_REPLYTO		0x20
#define OPTION_FROUTE		0x40

extern	void	yyerror __P((char *));
extern	int	yyparse __P((void));
extern	int	yylex __P((void));
extern	int	yydebug;
extern	FILE	*yyin;
extern	int	yylineNum;

static	void	newrule __P((void));
static	void	setipftype __P((void));
static	u_32_t	lookuphost __P((char *));
static	void	dobpf __P((char *));
static	void	resetaddr __P((void));
static	struct	alist_s	*newalist __P((struct alist_s *));
static	u_int	makehash __P((struct alist_s *));
static	int	makepool __P((struct alist_s *));
static	frentry_t *addrule __P((void));
static	void	setsyslog __P((void));
static	void	unsetsyslog __P((void));
static	void	fillgroup __P((frentry_t *));

frentry_t	*fr = NULL, *frc = NULL, *frtop = NULL, *frold = NULL;

static	int		ifpflag = 0;
static	int		nowith = 0;
static	int		dynamic = -1;
static	int		pooled = 0;
static	int		hashed = 0;
static	int		nrules = 0;
static	int		newlist = 0;
static	int		added = 0;
static	int		ipffd = -1;
static	int		*yycont = 0;
static	int		ruleopts = 0;
static	ioctlfunc_t	ipfioctl[IPL_LOGSIZE];
static	addfunc_t	ipfaddfunc = NULL;
static	wordtab_t	addrwords[4];
static	wordtab_t	maskwords[5];
static	wordtab_t	*savewords;

%}
%union	{
	char	*str;
	u_32_t	num;
	struct	in_addr	ipa;
	frentry_t	fr;
	frtuc_t	*frt;
	struct	alist_s	*alist;
	struct	{
		u_short	p1;
		u_short	p2;
		int	pc;
	} pc;
	struct	{
		union	i6addr	a;
		union	i6addr	m;
	} ipp;
	union	i6addr	ip6;
};

%type	<num>	portnum facility priority icmpcode seclevel secname icmptype
%type	<num>	opt compare range opttype flagset optlist ipv6hdrlist ipv6hdr
%type	<num>	portc porteq 
%type	<ipa>	hostname ipv4 ipv4mask
%type	<ip6>	ipv6mask
%type	<ipp>	addr ipaddr
%type	<str>	servicename name interfacename
%type	<pc>	portrange portcomp
%type	<alist>	addrlist poollist

%token	<num>	YY_NUMBER YY_HEX
%token	<str>	YY_STR
%token		YY_COMMENT
%token		YY_CMP_EQ YY_CMP_NE YY_CMP_LE YY_CMP_GE YY_CMP_LT YY_CMP_GT
%token		YY_RANGE_OUT YY_RANGE_IN
%token	<ip6>	YY_IPV6

%token	IPFY_PASS IPFY_BLOCK IPFY_COUNT IPFY_CALL
%token	IPFY_RETICMP IPFY_RETRST IPFY_RETICMPASDST
%token	IPFY_IN IPFY_OUT
%token	IPFY_QUICK IPFY_ON IPFY_OUTVIA IPFY_INVIA
%token	IPFY_DUPTO IPFY_TO IPFY_FROUTE IPFY_REPLY_TO
%token	IPFY_TOS IPFY_TTL IPFY_PROTO
%token	IPFY_HEAD IPFY_GROUP
%token	IPFY_AUTH IPFY_PREAUTH IPFY_DIVERT
%token	IPFY_LOG IPFY_BODY IPFY_FIRST IPFY_LEVEL IPFY_ORBLOCK
%token	IPFY_LOGTAG IPFY_TAG IPFY_SKIP
%token	IPFY_FROM IPFY_ALL IPFY_ANY IPFY_BPF IPFY_POOL IPFY_HASH
%token	IPFY_PPS
%token	IPFY_ESP IPFY_AH
%token	IPFY_WITH IPFY_AND IPFY_NOT IPFY_NO IPFY_OPT
%token	IPFY_TCPUDP IPFY_TCP IPFY_UDP
%token	IPFY_FLAGS IPFY_MULTICAST
%token	IPFY_MASK IPFY_BROADCAST IPFY_NETWORK IPFY_NETMASKED IPFY_PEER
%token	IPFY_PORT
%token	IPFY_NOW
%token	IPFY_ICMP IPFY_ICMPTYPE IPFY_ICMPCODE
%token	IPFY_IPOPTS IPFY_SHORT IPFY_NAT IPFY_BADSRC IPFY_LOWTTL IPFY_FRAG
%token	IPFY_MBCAST IPFY_BAD IPFY_BADNAT IPFY_OOW IPFY_NEWISN IPFY_NOICMPERR
%token	IPFY_KEEP IPFY_STATE IPFY_FRAGS IPFY_LIMIT IPFY_STRICT IPFY_AGE
%token	IPFY_IPOPT_NOP IPFY_IPOPT_RR IPFY_IPOPT_ZSU IPFY_IPOPT_MTUP
%token	IPFY_IPOPT_MTUR IPFY_IPOPT_ENCODE IPFY_IPOPT_TS IPFY_IPOPT_TR
%token	IPFY_IPOPT_SEC IPFY_IPOPT_LSRR IPFY_IPOPT_ESEC IPFY_IPOPT_CIPSO
%token	IPFY_IPOPT_SATID IPFY_IPOPT_SSRR IPFY_IPOPT_ADDEXT IPFY_IPOPT_VISA
%token	IPFY_IPOPT_IMITD IPFY_IPOPT_EIP IPFY_IPOPT_FINN IPFY_IPOPT_DPS
%token	IPFY_IPOPT_SDB IPFY_IPOPT_NSAPA IPFY_IPOPT_RTRALRT IPFY_IPOPT_UMP
%token	IPFY_SECCLASS IPFY_SEC_UNC IPFY_SEC_CONF IPFY_SEC_RSV1 IPFY_SEC_RSV2
%token	IPFY_SEC_RSV4 IPFY_SEC_SEC IPFY_SEC_TS IPFY_SEC_RSV3

%token	IPF6_V6HDRS IPFY_IPV6OPT IPFY_IPV6OPT_DSTOPTS IPFY_IPV6OPT_HOPOPTS
%token	IPFY_IPV6OPT_IPV6 IPFY_IPV6OPT_NONE IPFY_IPV6OPT_ROUTING

%token	IPFY_ICMPT_UNR IPFY_ICMPT_ECHO IPFY_ICMPT_ECHOR IPFY_ICMPT_SQUENCH
%token	IPFY_ICMPT_REDIR IPFY_ICMPT_TIMEX IPFY_ICMPT_PARAMP IPFY_ICMPT_TIMEST
%token	IPFY_ICMPT_TIMESTREP IPFY_ICMPT_INFOREQ IPFY_ICMPT_INFOREP
%token	IPFY_ICMPT_MASKREQ IPFY_ICMPT_MASKREP IPFY_ICMPT_ROUTERAD
%token	IPFY_ICMPT_ROUTERSOL

%token	IPFY_ICMPC_NETUNR IPFY_ICMPC_HSTUNR IPFY_ICMPC_PROUNR IPFY_ICMPC_PORUNR
%token	IPFY_ICMPC_NEEDF IPFY_ICMPC_SRCFAIL IPFY_ICMPC_NETUNK IPFY_ICMPC_HSTUNK
%token	IPFY_ICMPC_ISOLATE IPFY_ICMPC_NETPRO IPFY_ICMPC_HSTPRO
%token	IPFY_ICMPC_NETTOS IPFY_ICMPC_HSTTOS IPFY_ICMPC_FLTPRO IPFY_ICMPC_HSTPRE
%token	IPFY_ICMPC_CUTPRE

%token	IPFY_FAC_KERN IPFY_FAC_USER IPFY_FAC_MAIL IPFY_FAC_DAEMON IPFY_FAC_AUTH
%token	IPFY_FAC_SYSLOG IPFY_FAC_LPR IPFY_FAC_NEWS IPFY_FAC_UUCP IPFY_FAC_CRON
%token	IPFY_FAC_LOCAL0 IPFY_FAC_LOCAL1 IPFY_FAC_LOCAL2 IPFY_FAC_LOCAL3
%token	IPFY_FAC_LOCAL4 IPFY_FAC_LOCAL5 IPFY_FAC_LOCAL6 IPFY_FAC_LOCAL7
%token	IPFY_FAC_SECURITY IPFY_FAC_FTP IPFY_FAC_AUTHPRIV IPFY_FAC_AUDIT
%token	IPFY_FAC_LFMT IPFY_FAC_CONSOLE

%token	IPFY_PRI_EMERG IPFY_PRI_ALERT IPFY_PRI_CRIT IPFY_PRI_ERR IPFY_PRI_WARN
%token	IPFY_PRI_NOTICE IPFY_PRI_INFO IPFY_PRI_DEBUG
%%
file:	line
	| assign
	| file line
	| file assign
	;

line:	xx rule		{ while ((fr = frtop) != NULL) {
				frtop = fr->fr_next;
				fr->fr_next = NULL;
				(*ipfaddfunc)(ipffd, ipfioctl[IPL_LOGIPF], fr);
				fr->fr_next = frold;
				frold = fr;
			  }
			  resetlexer();
			}
	| YY_COMMENT
	;

xx:	{ newrule(); }
	;

assign:	YY_STR assigning YY_STR ';'	{ set_variable($1, $3);
					  resetlexer();
					  free($1);
					  free($3);
					}
	;

assigning:
	'='				{ yyvarnext = 1; }
	;

rule:	inrule
	| outrule
	;

inrule:
	rulehead markin { ruleopts = 0; } inopts rulemain ruletail
	;

outrule:
	rulehead markout { ruleopts = 0; } outopts rulemain ruletail
	;

rulehead:
	collection action
	| insert collection action
	;

markin:	IPFY_IN				{ fr->fr_flags |= FR_INQUE; }
	;

markout:
	IPFY_OUT			{ fr->fr_flags |= FR_OUTQUE; }
	;

rulemain:
	ipfrule
	| bpfrule
	;

ipfrule:
	tos ttl proto ip
	;

bpfrule:
	IPFY_BPF '{' YY_STR '}' 	{ dobpf($3); free($3); }
	;

ruletail:
	keep head group tag pps age new
	;

insert:
	'@' YY_NUMBER			{ fr->fr_hits = (U_QUAD_T)$2; }
	;

collection:
	| YY_NUMBER			{ fr->fr_collect = $1; }
	;

action:	block
	| IPFY_PASS			{ fr->fr_flags |= FR_PASS; }
	| IPFY_DIVERT YY_NUMBER		{ fr->fr_flags |= FR_DIVERT;
					  fr->fr_arg = $2; }
	| log
	| IPFY_COUNT			{ fr->fr_flags |= FR_ACCOUNT; }
	| auth
	| IPFY_SKIP YY_NUMBER		{ fr->fr_flags |= FR_SKIP;
					  fr->fr_arg = $2; }
	| IPFY_CALL func
	| IPFY_CALL IPFY_NOW func	{ fr->fr_flags |= FR_CALLNOW; }
	;

block:	blocked
	| blocked blockreturn
	;

blocked:
	IPFY_BLOCK			{ fr->fr_flags = FR_BLOCK; }
	;
blockreturn:
	IPFY_RETICMP			{ fr->fr_flags |= FR_RETICMP; }
	| IPFY_RETICMP returncode	{ fr->fr_flags |= FR_RETICMP; }
	| IPFY_RETICMPASDST		{ fr->fr_flags |= FR_FAKEICMP; }
	| IPFY_RETICMPASDST returncode	{ fr->fr_flags |= FR_FAKEICMP; }
	| IPFY_RETRST			{ fr->fr_flags |= FR_RETRST; }
	;

log:	IPFY_LOG			{ fr->fr_flags |= FR_LOG; }
	| IPFY_LOG logoptions		{ fr->fr_flags |= FR_LOG; }
	;

auth:	IPFY_AUTH			{ fr->fr_flags |= FR_AUTH; }
	| IPFY_AUTH IPFY_RETRST		{ fr->fr_flags |= (FR_AUTH|FR_RETRST);}
	| IPFY_PREAUTH			{ fr->fr_flags |= FR_PREAUTH; }
	;

func:	YY_STR '/' YY_NUMBER	{ fr->fr_func = nametokva($1,
							  ipfioctl[IPL_LOGIPF]);
				  fr->fr_arg = $3;
				  free($1); }
	;

inopts:
	| inopts inopt
	;

inopt:
	logopt
	{
		if ( ruleopts & OPTION_LOG )
			yyerror("Duplicate log option");
		ruleopts |= OPTION_LOG;
	}	
	| quick
	{
		if ( ruleopts & OPTION_QUICK )
			yyerror("Duplicate quick option");
		ruleopts |= OPTION_QUICK;
	} 
	| on
	{
		if ( ruleopts & OPTION_ON )
			yyerror("Duplicate on option");
		ruleopts |= OPTION_ON;
	} 
	| dup
	{
		if ( ruleopts & OPTION_DUP )
			yyerror("Duplicate dup option");
		ruleopts |= OPTION_DUP;
	} 
	| froute
	{
		if ( ruleopts & OPTION_FROUTE )
			yyerror("Duplicate froute option");
		ruleopts |= OPTION_FROUTE;
	} 
	| proute
	{
		if ( ruleopts & OPTION_PROUTE )
			yyerror("Duplicate proute option");
		ruleopts |= OPTION_PROUTE;
	} 
	| replyto
	{
		if ( ruleopts & OPTION_REPLYTO )
			yyerror("Duplicate replyto option");
		ruleopts |= OPTION_REPLYTO;
	} 
	;

outopts:
	| outopts outopt
	;

outopt:
	logopt
	{
		if ( ruleopts & OPTION_LOG )
			yyerror("Duplicate log option");
		ruleopts |= OPTION_LOG;
	} 
	| quick
	{
		if ( ruleopts & OPTION_QUICK )
			yyerror("Duplicate quick option");
		ruleopts |= OPTION_QUICK;
	} 
	| on
	{
		if ( ruleopts & OPTION_ON )
			yyerror("Duplicate on option");
		ruleopts |= OPTION_ON;
	} 
	| dup
	{
		if ( ruleopts & OPTION_DUP )
			yyerror("Duplicate dup option");
		ruleopts |= OPTION_DUP;
	}
	| proute
	{
		if ( ruleopts & OPTION_PROUTE )
			yyerror("Duplicate proute option");
		ruleopts |= OPTION_PROUTE;
	} 
	| replyto
	{
		if ( ruleopts & OPTION_REPLYTO )
			yyerror("Duplicate replyto option");
		ruleopts |= OPTION_REPLYTO;
	} 
	;

tos:	| settos YY_NUMBER	{ DOALL(fr->fr_tos = $2; fr->fr_mtos = 0xff;) }
	| settos YY_HEX	{ DOALL(fr->fr_tos = $2; fr->fr_mtos = 0xff;) }
	| settos lstart toslist lend
	;

settos:	IPFY_TOS			{ setipftype(); }
	;

toslist:
	YY_NUMBER	{ DOALL(fr->fr_tos = $1; fr->fr_mtos = 0xff;) }
	| YY_HEX	{ DOREM(fr->fr_tos = $1; fr->fr_mtos = 0xff;) }
	| toslist lmore YY_NUMBER
			{ DOREM(fr->fr_tos = $3; fr->fr_mtos = 0xff;) }
	| toslist lmore YY_HEX	
			{ DOREM(fr->fr_tos = $3; fr->fr_mtos = 0xff;) }
	;

ttl:	| setttl YY_NUMBER
			{ DOALL(fr->fr_ttl = $2; fr->fr_mttl = 0xff;) }
	| setttl lstart ttllist lend
	;

lstart:	'('				{ newlist = 1; fr = frc; added = 0; }
	;

lend:	')'				{ nrules += added; }
	;

lmore:	lanother			{ if (newlist == 1) {
						newlist = 0;
					  }
					  fr = addrule();
					  if (yycont != NULL)
					  	*yycont = 1;
					}
	;

lanother:
	| ','
	;

setttl:	IPFY_TTL			{ setipftype(); }
	;

ttllist:
	YY_NUMBER	{ DOREM(fr->fr_ttl = $1; fr->fr_mttl = 0xff;) }
	| ttllist lmore YY_NUMBER
			{ DOREM(fr->fr_ttl = $3; fr->fr_mttl = 0xff;) }
	;

proto:	| protox protocol		{ yyresetdict(); }
	;

protox:	IPFY_PROTO			{ setipftype();
					  fr = frc;
					  yysetdict(NULL); }
	;

ip:	srcdst flags with icmp
	;

group:	| IPFY_GROUP YY_STR		{ DOALL(strncpy(fr->fr_group, $2, \
							FR_GROUPLEN); \
							fillgroup(fr););
					  free($2); }
	| IPFY_GROUP YY_NUMBER		{ DOALL(sprintf(fr->fr_group, "%d", \
							$2); \
							fillgroup(fr);) }
	;

head:	| IPFY_HEAD YY_STR		{ DOALL(strncpy(fr->fr_grhead, $2, \
							FR_GROUPLEN););
					  free($2); }
	| IPFY_HEAD YY_NUMBER		{ DOALL(sprintf(fr->fr_grhead, "%d", \
							$2);) }
	;

tag:	| IPFY_TAG YY_NUMBER		{ DOALL(fr->fr_logtag = $2;) }
	| IPFY_TAG '(' taglist ')'

taglist:
	tagspec
	| taglist ',' tagspec
	;

tagspec:
	IPFY_NAT '=' YY_STR		{ DOALL(strncpy(fr->fr_nattag.ipt_tag,\
						$3, 16););
					  free($3); }
	| IPFY_NAT '=' YY_NUMBER	{ DOALL(sprintf(fr->fr_nattag.ipt_tag,\
						"%15d", $3);) }
	| IPFY_LOG '=' YY_NUMBER	{ DOALL(fr->fr_logtag = $3;) }
	;

pps:	| IPFY_PPS YY_NUMBER		{ DOALL(fr->fr_pps = $2;) }
	;

new:	| savegroup file restoregroup
	;

savegroup:
	'{'
	;

restoregroup:
	'}'
	;

logopt:	log
	;

quick:
	IPFY_QUICK			{ fr->fr_flags |= FR_QUICK; }
	;

on:	IPFY_ON onname
	| IPFY_ON onname IPFY_INVIA vianame
	| IPFY_ON onname IPFY_OUTVIA vianame
	;

onname:	interfacename
		{
#if SOLARIS2 >=10
		char *cp;
#endif
		strncpy(fr->fr_ifnames[0], $1, sizeof(fr->fr_ifnames[0]));
#if SOLARIS2 >= 10
		if (strncmp(VNI, $1, VNISTRLEN) == 0) {
			cp = $1 + VNISTRLEN;
			cp += strspn(cp, "0123456789");
			if (*cp == '\0' || *cp == ':') {
				fprintf(stderr, "%d: Warning- %s specified. vni"
				    " is a virtual interface, use a physical"
				    " interface instead. See vni(7D)\n", 
				    yylineNum, $1);
			}
		}
#endif
		  free($1);
		}
	| interfacename ',' name
		{ 
#if SOLARIS2 >= 10
		char *cp;
#endif
		strncpy(fr->fr_ifnames[0], $1, sizeof(fr->fr_ifnames[0]));
#if SOLARIS2 >= 10
		if (strncmp(VNI, $1, VNISTRLEN) == 0) {
			cp = $1 + VNISTRLEN;
			cp += strspn(cp, "0123456789");
			if (*cp == '\0' || *cp == ':') {
				fprintf(stderr, "%d: Warning- %s specified. vni"
				    " is a virtual interface, use a physical"
				    " interface instead. See vni(7D)\n", 
				    yylineNum, $1);
			}
		}
#endif
		  free($1);
		  strncpy(fr->fr_ifnames[1], $3, sizeof(fr->fr_ifnames[1]));
#if SOLARIS2 >= 10
		if (strncmp(VNI, $3, VNISTRLEN) == 0) {
			cp = $3 + VNISTRLEN;
			cp += strspn(cp, "0123456789");
			if (*cp == '\0' || *cp == ':') {
				fprintf(stderr, "%d: Warning- %s specified. vni"
				    " is a virtual interface, use a physical"
				    " interface instead. See vni(7D)\n", 
				    yylineNum, $3);
			}
		}
#endif
		  free($3);
		}
	;

vianame:
	interfacename
		{
#if SOLARIS2 >= 10
		char *cp;
#endif
		strncpy(fr->fr_ifnames[2], $1, sizeof(fr->fr_ifnames[2]));
#if SOLARIS2 >= 10
		if (strncmp(VNI, $1, VNISTRLEN) == 0) {
			cp = $1 + VNISTRLEN;
			cp += strspn(cp, "0123456789");
			if (*cp == '\0' || *cp == ':') {
				fprintf(stderr, "%d: Warning- %s specified. vni"
				    " is a virtual interface, use a physical"
				    " interface instead. See vni(7D)\n", 
				    yylineNum, $1);
			}
		}
#endif
		  free($1);
		}
	| interfacename ',' name
		{ 
#if SOLARIS2 >= 10
		char *cp;
#endif
		strncpy(fr->fr_ifnames[2], $1, sizeof(fr->fr_ifnames[2]));
#if SOLARIS2 >= 10
		if (strncmp(VNI, $1, VNISTRLEN) == 0) {
			cp = $1 + VNISTRLEN;
			cp += strspn(cp, "0123456789");
			if (*cp == '\0' || *cp == ':') {
				fprintf(stderr, "%d: Warning- %s specified. vni"
				    " is a virtual interface, use a physical"
				    " interface instead. See vni(7D)\n", 
				    yylineNum, $1);
			}
		}
#endif
		  free($1);
		  strncpy(fr->fr_ifnames[3], $3, sizeof(fr->fr_ifnames[3]));
#if SOLARIS2 >= 10
		if (strncmp(VNI, $3, VNISTRLEN) == 0) {
			cp = $3 + VNISTRLEN;
			cp += strspn(cp, "0123456789");
			if (*cp == '\0' || *cp == ':') {
				fprintf(stderr, "%d: Warning- %s specified. vni"
				    " is a virtual interface, use a physical"
				    " interface instead. See vni(7D)\n", 
				    yylineNum, $3);
			}
		}
#endif
		  free($3);
		}
	;

dup:	IPFY_DUPTO name
	{ strncpy(fr->fr_dif.fd_ifname, $2, sizeof(fr->fr_dif.fd_ifname));
	  free($2);
	}
	| IPFY_DUPTO name ':' hostname
	{ strncpy(fr->fr_dif.fd_ifname, $2, sizeof(fr->fr_dif.fd_ifname));
	  fr->fr_dif.fd_ip = $4;
	  free($2);
	}
	;

froute:	IPFY_FROUTE			{ fr->fr_flags |= FR_FASTROUTE; }
	;

proute:	IPFY_TO name
	{ strncpy(fr->fr_tif.fd_ifname, $2, sizeof(fr->fr_tif.fd_ifname));
	  free($2);
	}
	| IPFY_TO name ':' hostname
	{ strncpy(fr->fr_tif.fd_ifname, $2, sizeof(fr->fr_tif.fd_ifname));
	  fr->fr_tif.fd_ip = $4;
	  free($2);
	}
	;

replyto:
	IPFY_REPLY_TO name
	{ strncpy(fr->fr_rif.fd_ifname, $2, sizeof(fr->fr_rif.fd_ifname));
	  free($2);
	}
	| IPFY_REPLY_TO name ':' hostname
	{ strncpy(fr->fr_rif.fd_ifname, $2, sizeof(fr->fr_rif.fd_ifname));
	  fr->fr_rif.fd_ip = $4;
	  free($2);
	}
	;

logoptions:
	logoption
	| logoptions logoption
	;

logoption:
	IPFY_BODY			{ fr->fr_flags |= FR_LOGBODY; }
	| IPFY_FIRST			{ fr->fr_flags |= FR_LOGFIRST; }
	| IPFY_ORBLOCK			{ fr->fr_flags |= FR_LOGORBLOCK; }
	| level loglevel		{ unsetsyslog(); }
	;

returncode:
	starticmpcode icmpcode ')'	{ fr->fr_icode = $2; yyresetdict(); }
	;

starticmpcode:
	'('				{ yysetdict(icmpcodewords); }
	;

srcdst:	IPFY_ALL
	| fromto
	;

protocol:
	YY_NUMBER		{ DOREM(fr->fr_proto = $1; \
					fr->fr_mproto = 0xff;) }
	| YY_STR		{ if (!strcmp($1, "tcp-udp")) {
					DOREM(fr->fr_flx |= FI_TCPUDP; \
					      fr->fr_mflx |= FI_TCPUDP;)
				  } else {
					int p = getproto($1);
					if (p == -1)
						fprintf(stderr, "protocol unknown: %s, line %d\n", $1, yylineNum);
					DOREM(fr->fr_proto = p; \
						fr->fr_mproto = 0xff;)
				  }
				  free($1);
				}
	| YY_STR nextstring YY_STR
				{ if (!strcmp($1, "tcp") &&
				      !strcmp($3, "udp")) {
					DOREM(fr->fr_flx |= FI_TCPUDP; \
					      fr->fr_mflx |= FI_TCPUDP;)
				  } else
					YYERROR;
				  free($1);
				  free($3);
				}
	;

nextstring:
	'/'			{ yysetdict(NULL); }
	;

fromto:	from srcobject to dstobject	{ yyexpectaddr = 0; yycont = NULL; }
	| to dstobject			{ yyexpectaddr = 0; yycont = NULL; }
	| from srcobject		{ yyexpectaddr = 0; yycont = NULL; }
	;

from:	IPFY_FROM			{ setipftype();
					  if (fr == NULL)
						fr = frc;
					  yyexpectaddr = 1;
					  yycont = &yyexpectaddr;
					  yysetdict(addrwords);
					  resetaddr(); }
	;

to:	IPFY_TO				{ if (fr == NULL)
						fr = frc;
					  yyexpectaddr = 1;
					  yycont = &yyexpectaddr;
					  yysetdict(addrwords);
					  resetaddr(); }
	;

with:	| andwith withlist
	;

andwith:
	IPFY_WITH			{ nowith = 0; setipftype(); }
	| IPFY_AND			{ nowith = 0; setipftype(); }
	;

flags:	| IPFY_FLAGS flagset	
		{ DOALL(fr->fr_tcpf = $2; fr->fr_tcpfm = FR_TCPFMAX;) }
	| IPFY_FLAGS flagset '/' flagset
		{ DOALL(fr->fr_tcpf = $2; fr->fr_tcpfm = $4;) }
	| IPFY_FLAGS '/' flagset
		{ DOALL(fr->fr_tcpf = 0; fr->fr_tcpfm = $3;) }
	| IPFY_FLAGS YY_NUMBER
		{ DOALL(fr->fr_tcpf = $2; fr->fr_tcpfm = FR_TCPFMAX;) }
	| IPFY_FLAGS '/' YY_NUMBER
		{ DOALL(fr->fr_tcpf = 0; fr->fr_tcpfm = $3;) }
	| IPFY_FLAGS YY_NUMBER '/' YY_NUMBER
		{ DOALL(fr->fr_tcpf = $2; fr->fr_tcpfm = $4;) }
	| IPFY_FLAGS flagset '/' YY_NUMBER
		{ DOALL(fr->fr_tcpf = $2; fr->fr_tcpfm = $4;) }
	| IPFY_FLAGS YY_NUMBER '/' flagset
		{ DOALL(fr->fr_tcpf = $2; fr->fr_tcpfm = $4;) }
	;

flagset:
	YY_STR				{ $$ = tcpflags($1); free($1); }
	| YY_HEX			{ $$ = $1; }
	;

srcobject:
	srcaddr srcport
	| '!' srcaddr srcport
		{ DOALL(fr->fr_flags |= FR_NOTSRCIP;) }
	| fromport
	;

srcaddr:
	addr	{ DOREM(bcopy(&($1.a), &fr->fr_ip.fi_src, sizeof($1.a)); \
			bcopy(&($1.m), &fr->fr_mip.fi_src, sizeof($1.m)); \
			if (dynamic != -1) { \
				fr->fr_satype = ifpflag; \
				fr->fr_ipf->fri_sifpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_satype = FRI_LOOKUP;)
		}
	| lstart srcaddrlist lend
	;

srcaddrlist:
	addr	{ DOREM(bcopy(&($1.a), &fr->fr_ip.fi_src, sizeof($1.a)); \
			bcopy(&($1.m), &fr->fr_mip.fi_src, sizeof($1.m)); \
			if (dynamic != -1) { \
				fr->fr_satype = ifpflag; \
				fr->fr_ipf->fri_sifpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_satype = FRI_LOOKUP;)
		}
	| srcaddrlist lmore addr
		{ DOREM(bcopy(&($3.a), &fr->fr_ip.fi_src, sizeof($3.a)); \
			bcopy(&($3.m), &fr->fr_mip.fi_src, sizeof($3.m)); \
			if (dynamic != -1) { \
				fr->fr_satype = ifpflag; \
				fr->fr_ipf->fri_sifpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_satype = FRI_LOOKUP;)
		}
	;

srcport:
	| portcomp
		{ DOALL(fr->fr_scmp = $1.pc; fr->fr_sport = $1.p1;) }
	| portrange
		{ DOALL(fr->fr_scmp = $1.pc; fr->fr_sport = $1.p1; \
			fr->fr_stop = $1.p2;) }
	| porteq lstart srcportlist lend
		{ yyresetdict(); }
	;

fromport:
	portcomp
		{ DOALL(fr->fr_scmp = $1.pc; fr->fr_sport = $1.p1;) }
	| portrange
		{ DOALL(fr->fr_scmp = $1.pc; fr->fr_sport = $1.p1; \
			fr->fr_stop = $1.p2;) }
	| porteq lstart srcportlist lend
		{ yyresetdict(); }
	;

srcportlist:
	portnum		{ DOREM(fr->fr_scmp = FR_EQUAL; fr->fr_sport = $1;) }
	| srcportlist lmore portnum
			{ DOREM(fr->fr_scmp = FR_EQUAL; fr->fr_sport = $3;) }
	;

dstobject:
	toport
	| dstaddr dstport
	| '!' dstaddr dstport
			{ DOALL(fr->fr_flags |= FR_NOTDSTIP;) }
	;

dstaddr:
	addr	{ DOREM(bcopy(&($1.a), &fr->fr_ip.fi_dst, sizeof($1.a)); \
			bcopy(&($1.m), &fr->fr_mip.fi_dst, sizeof($1.m)); \
			if (dynamic != -1) { \
				fr->fr_datype = ifpflag; \
				fr->fr_ipf->fri_difpidx = dynamic; \
			  } else if (pooled || hashed) \
				fr->fr_datype = FRI_LOOKUP;)
		}
	| lstart dstaddrlist lend
	;

dstaddrlist:
	addr	{ DOREM(bcopy(&($1.a), &fr->fr_ip.fi_dst, sizeof($1.a)); \
			bcopy(&($1.m), &fr->fr_mip.fi_dst, sizeof($1.m)); \
			if (dynamic != -1) { \
				fr->fr_datype = ifpflag; \
				fr->fr_ipf->fri_difpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_datype = FRI_LOOKUP;)
		}
	| dstaddrlist lmore addr
		{ DOREM(bcopy(&($3.a), &fr->fr_ip.fi_dst, sizeof($3.a)); \
			bcopy(&($3.m), &fr->fr_mip.fi_dst, sizeof($3.m)); \
			if (dynamic != -1) { \
				fr->fr_datype = ifpflag; \
				fr->fr_ipf->fri_difpidx = dynamic; \
			} else if (pooled || hashed) \
				fr->fr_datype = FRI_LOOKUP;)
		}
	;


dstport:
	| portcomp
		{ DOALL(fr->fr_dcmp = $1.pc; fr->fr_dport = $1.p1;) }
	| portrange
		{ DOALL(fr->fr_dcmp = $1.pc; fr->fr_dport = $1.p1; \
			fr->fr_dtop = $1.p2;) }
	| porteq lstart dstportlist lend
		{ yyresetdict(); }
	;

toport:
	portcomp
		{ DOALL(fr->fr_dcmp = $1.pc; fr->fr_dport = $1.p1;) }
	| portrange
		{ DOALL(fr->fr_dcmp = $1.pc; fr->fr_dport = $1.p1; \
			fr->fr_dtop = $1.p2;) }
	| porteq lstart dstportlist lend
		{ yyresetdict(); }
	;

dstportlist:
	portnum		{ DOREM(fr->fr_dcmp = FR_EQUAL; fr->fr_dport = $1;) }
	| dstportlist lmore portnum
			{ DOREM(fr->fr_dcmp = FR_EQUAL; fr->fr_dport = $3;) }
	;

addr:	pool '/' YY_NUMBER		{ pooled = 1;
					  yyexpectaddr = 0;
					  $$.a.iplookuptype = IPLT_POOL;
					  $$.a.iplookupnum = $3; }
	| pool '=' '(' poollist ')'	{ pooled = 1;
					  yyexpectaddr = 0;
					  $$.a.iplookuptype = IPLT_POOL;
					  $$.a.iplookupnum = makepool($4); }
	| hash '/' YY_NUMBER		{ hashed = 1;
					  yyexpectaddr = 0;
					  $$.a.iplookuptype = IPLT_HASH;
					  $$.a.iplookupnum = $3; }
	| hash '=' '(' addrlist ')'	{ hashed = 1;
					  yyexpectaddr = 0;
					  $$.a.iplookuptype = IPLT_HASH;
					  $$.a.iplookupnum = makehash($4); }
	| ipaddr			{ bcopy(&$1, &$$, sizeof($$));
					  yyexpectaddr = 0; }
	;

ipaddr:	IPFY_ANY			{ bzero(&($$), sizeof($$));
					  yyresetdict();
					  yyexpectaddr = 0; }
	| hostname			{ $$.a.in4 = $1;
					  $$.m.in4_addr = 0xffffffff;
					  yyexpectaddr = 0; }
	| hostname			{ yyresetdict();
					  $$.a.in4_addr = $1.s_addr; }
		maskspace		{ yysetdict(maskwords); }
		ipv4mask		{ $$.m.in4_addr = $5.s_addr;
					  $$.a.in4_addr &= $5.s_addr;
					  yyresetdict();
					  yyexpectaddr = 0; }
	| YY_IPV6			{ bcopy(&$1, &$$.a, sizeof($$.a));
					  fill6bits(128, (u_32_t *)&$$.m);
					  yyresetdict();
					  yyexpectaddr = 0; }
	| YY_IPV6			{ yyresetdict();
					  bcopy(&$1, &$$.a, sizeof($$.a)); }
		maskspace		{ yysetdict(maskwords); }
		ipv6mask		{ bcopy(&$5, &$$.m, sizeof($$.m));
					  yyresetdict();
					  yyexpectaddr = 0; }
	;

maskspace:
	'/'
	| IPFY_MASK
	;

ipv4mask:
	ipv4				{ $$ = $1; }
	| YY_HEX			{ $$.s_addr = htonl($1); }
	| YY_NUMBER			{ ntomask(4, $1, (u_32_t *)&$$); }
	| IPFY_BROADCAST		{ if (ifpflag == FRI_DYNAMIC) {
						$$.s_addr = 0;
						ifpflag = FRI_BROADCAST;
					  } else
						YYERROR;
					}
	| IPFY_NETWORK			{ if (ifpflag == FRI_DYNAMIC) {
						$$.s_addr = 0;
						ifpflag = FRI_NETWORK;
					  } else
						YYERROR;
					}
	| IPFY_NETMASKED		{ if (ifpflag == FRI_DYNAMIC) {
						$$.s_addr = 0;
						ifpflag = FRI_NETMASKED;
					  } else
						YYERROR;
					}
	| IPFY_PEER			{ if (ifpflag == FRI_DYNAMIC) {
						$$.s_addr = 0;
						ifpflag = FRI_PEERADDR;
					  } else
						YYERROR;
					}
	;

ipv6mask:
	YY_NUMBER			{ ntomask(6, $1, $$.i6); }
	| IPFY_BROADCAST		{ if (ifpflag == FRI_DYNAMIC) {
						bzero(&$$, sizeof($$));
						ifpflag = FRI_BROADCAST;
					  } else
						YYERROR;
					}
	| IPFY_NETWORK			{ if (ifpflag == FRI_DYNAMIC) {
						bzero(&$$, sizeof($$));
						ifpflag = FRI_BROADCAST;
					  } else
						YYERROR;
					}
	| IPFY_NETMASKED		{ if (ifpflag == FRI_DYNAMIC) {
						bzero(&$$, sizeof($$));
						ifpflag = FRI_BROADCAST;
					  } else
						YYERROR;
					}
	| IPFY_PEER			{ if (ifpflag == FRI_DYNAMIC) {
						bzero(&$$, sizeof($$));
						ifpflag = FRI_BROADCAST;
					  } else
						YYERROR;
					}
	;

hostname:
	ipv4				{ $$ = $1; }
	| YY_NUMBER			{ $$.s_addr = $1; }
	| YY_HEX			{ $$.s_addr = $1; }
	| YY_STR			{ $$.s_addr = lookuphost($1);
					  free($1);
					  if ($$.s_addr == 0 &&
						ifpflag != FRI_DYNAMIC)
						yyerror("Unknown hostname");
					}
	;

addrlist:
	ipaddr		{ $$ = newalist(NULL);
			  bcopy(&($1.a), &($$->al_i6addr), sizeof($1.a));
			  bcopy(&($1.m), &($$->al_i6mask), sizeof($1.m)); }
	| addrlist ',' ipaddr
			{ $$ = newalist($1);
			  bcopy(&($3.a), &($$->al_i6addr), sizeof($3.a));
			  bcopy(&($3.m), &($$->al_i6mask), sizeof($3.m)); }
	;

pool:	IPFY_POOL	{ yyexpectaddr = 0; yycont = NULL; yyresetdict(); }
	;

hash:	IPFY_HASH	{ yyexpectaddr = 0; yycont = NULL; yyresetdict(); }
	;

poollist:
	ipaddr		{ $$ = newalist(NULL);
			  bcopy(&($1.a), &($$->al_i6addr), sizeof($1.a));
			  bcopy(&($1.m), &($$->al_i6mask), sizeof($1.m)); }
	| '!' ipaddr	{ $$ = newalist(NULL);
			  $$->al_not = 1;
			  bcopy(&($2.a), &($$->al_i6addr), sizeof($2.a));
			  bcopy(&($2.m), &($$->al_i6mask), sizeof($2.m)); }
	| poollist ',' ipaddr
			{ $$ = newalist($1);
			  bcopy(&($3.a), &($$->al_i6addr), sizeof($3.a));
			  bcopy(&($3.m), &($$->al_i6mask), sizeof($3.m)); }
	| poollist ',' '!' ipaddr
			{ $$ = newalist($1);
			  $$->al_not = 1;
			  bcopy(&($4.a), &($$->al_i6addr), sizeof($4.a));
			  bcopy(&($4.m), &($$->al_i6mask), sizeof($4.m)); }
	;

port:	IPFY_PORT			{ yyexpectaddr = 0;
					  yycont = NULL;
					}
	;

portc:	port compare			{ $$ = $2;
					  yysetdict(NULL); }
	| porteq			{ $$ = $1; }
	;

porteq:	port '='			{ $$ = FR_EQUAL;
					  yysetdict(NULL); }
	;

portr:	IPFY_PORT			{ yyexpectaddr = 0;
					  yycont = NULL;
					  yysetdict(NULL); }
	;

portcomp:
	portc portnum			{ $$.pc = $1;
					  $$.p1 = $2;
					  yyresetdict(); }
	;

portrange:
	portr portnum range portnum	{ $$.p1 = $2;
					  $$.pc = $3;
					  $$.p2 = $4;
					  yyresetdict(); }
	;

icmp:	| itype icode
	;

itype:	seticmptype icmptype
	{ DOALL(fr->fr_icmp = htons($2 << 8); fr->fr_icmpm = htons(0xff00););
	  yyresetdict();
	}
	| seticmptype lstart typelist lend	{ yyresetdict(); }
	;

seticmptype:
	IPFY_ICMPTYPE				{ setipftype();
						  yysetdict(icmptypewords); }
	;

icode:	| seticmpcode icmpcode
	{ DOALL(fr->fr_icmp |= htons($2); fr->fr_icmpm |= htons(0xff););
	  yyresetdict();
	}
	| seticmpcode lstart codelist lend	{ yyresetdict(); }
	;

seticmpcode:
	IPFY_ICMPCODE				{ yysetdict(icmpcodewords); }
	;

typelist:
	icmptype
	{ DOREM(fr->fr_icmp = htons($1 << 8); fr->fr_icmpm = htons(0xff00);) }
	| typelist lmore icmptype
	{ DOREM(fr->fr_icmp = htons($3 << 8); fr->fr_icmpm = htons(0xff00);) }
	;

codelist:
	icmpcode
	{ DOREM(fr->fr_icmp |= htons($1); fr->fr_icmpm |= htons(0xff);) }
	| codelist lmore icmpcode
	{ DOREM(fr->fr_icmp |= htons($3); fr->fr_icmpm |= htons(0xff);) }
	;

age:	| IPFY_AGE YY_NUMBER		{ DOALL(fr->fr_age[0] = $2; \
						fr->fr_age[1] = $2;) }
	| IPFY_AGE YY_NUMBER '/' YY_NUMBER
					{ DOALL(fr->fr_age[0] = $2; \
						fr->fr_age[1] = $4;) }
	;

keep:	| IPFY_KEEP keepstate
	| IPFY_KEEP keepfrag
	| IPFY_KEEP keepstate IPFY_KEEP keepfrag
	;

keepstate:
	IPFY_STATE stateoptlist		{ DOALL(fr->fr_flags |= FR_KEEPSTATE;)}
	;

keepfrag:
	IPFY_FRAGS fragoptlist		{ DOALL(fr->fr_flags |= FR_KEEPFRAG;) }
	;

fragoptlist:
	| '(' fragopts ')'
	;

fragopts:
	fragopt lanother fragopts
	| fragopt
	;

fragopt:
	IPFY_STRICT			{ DOALL(fr->fr_flags |= FR_FRSTRICT;) }
	;

stateoptlist:
	| '(' stateopts ')'
	;

stateopts:
	stateopt lanother stateopts
	| stateopt
	;

stateopt:
	IPFY_LIMIT YY_NUMBER	{ DOALL(fr->fr_statemax = $2;) }
	| IPFY_STRICT		{ DOALL(if (fr->fr_proto != IPPROTO_TCP) { \
						YYERROR; \
					  } else \
						fr->fr_flags |= FR_STSTRICT;)
				}
	| IPFY_NEWISN		{ DOALL(if (fr->fr_proto != IPPROTO_TCP) { \
						YYERROR; \
					  } else \
						fr->fr_flags |= FR_NEWISN;)
				}
	| IPFY_NOICMPERR	{ DOALL(fr->fr_flags |= FR_NOICMPERR;) }
	;

portnum:
	servicename			{ $$ = ntohs(getport(frc, $1));
					  if ($$ == -1)
						fprintf(stderr, "service unknown: %s, line %d\n", $1, yylineNum);
					  free($1);
					}
	| YY_NUMBER			{ $$ = $1; }
	;

withlist:
	withopt
	| withlist withopt
	;

withopt:
	opttype		{ DOALL(fr->fr_flx |= $1; fr->fr_mflx |= $1;) }
	| notwith opttype
			{ DOALL(fr->fr_mflx |= $2;) }
	| IPFY_OPT ipopts
	| notwith IPFY_OPT ipopts
	| startv6hdrs ipv6hdrs
	;

startv6hdrs:
	IPF6_V6HDRS	{ if (use_inet6 == 0)
				yyerror("only available with IPv6");
			}
	;

notwith:
	IPFY_NOT			{ nowith = 1; }
	| IPFY_NO			{ nowith = 1; }
	;

opttype:
	IPFY_IPOPTS			{ $$ = FI_OPTIONS; }
	| IPFY_SHORT			{ $$ = FI_SHORT; }
	| IPFY_NAT			{ $$ = FI_NATED; }
	| IPFY_BAD			{ $$ = FI_BAD; }
	| IPFY_BADNAT			{ $$ = FI_BADNAT; }
	| IPFY_BADSRC			{ $$ = FI_BADSRC; }
	| IPFY_LOWTTL			{ $$ = FI_LOWTTL; }
	| IPFY_FRAG			{ $$ = FI_FRAG; }
	| IPFY_MBCAST			{ $$ = FI_MBCAST; }
	| IPFY_MULTICAST		{ $$ = FI_MULTICAST; }
	| IPFY_BROADCAST		{ $$ = FI_BROADCAST; }
	| IPFY_STATE			{ $$ = FI_STATE; }
	| IPFY_OOW			{ $$ = FI_OOW; }
	;

ipopts:	optlist		{ DOALL(fr->fr_mip.fi_optmsk |= $1;
				if (!nowith)
					fr->fr_ip.fi_optmsk |= $1;)
			}
	;

optlist:
	opt				{ $$ |= $1; }
	| optlist ',' opt		{ $$ |= $1 | $3; }
	;

ipv6hdrs:
	ipv6hdrlist	{ DOALL(fr->fr_mip.fi_optmsk |= $1;
				if (!nowith)
					fr->fr_ip.fi_optmsk |= $1;)
			}
	;

ipv6hdrlist:
	ipv6hdr				{ $$ |= $1; }
	| ipv6hdrlist ',' ipv6hdr	{ $$ |= $1 | $3; }
	;

secname:
	seclevel			{ $$ |= $1; }
	| secname ',' seclevel		{ $$ |= $1 | $3; }
	;

seclevel:
	IPFY_SEC_UNC			{ $$ = secbit(IPSO_CLASS_UNCL); }
	| IPFY_SEC_CONF			{ $$ = secbit(IPSO_CLASS_CONF); }
	| IPFY_SEC_RSV1			{ $$ = secbit(IPSO_CLASS_RES1); }
	| IPFY_SEC_RSV2			{ $$ = secbit(IPSO_CLASS_RES2); }
	| IPFY_SEC_RSV3			{ $$ = secbit(IPSO_CLASS_RES3); }
	| IPFY_SEC_RSV4			{ $$ = secbit(IPSO_CLASS_RES4); }
	| IPFY_SEC_SEC			{ $$ = secbit(IPSO_CLASS_SECR); }
	| IPFY_SEC_TS			{ $$ = secbit(IPSO_CLASS_TOPS); }
	;

icmptype:
	YY_NUMBER			{ $$ = $1; }
	| IPFY_ICMPT_UNR		{ $$ = ICMP_UNREACH; }
	| IPFY_ICMPT_ECHO		{ $$ = ICMP_ECHO; }
	| IPFY_ICMPT_ECHOR		{ $$ = ICMP_ECHOREPLY; }
	| IPFY_ICMPT_SQUENCH		{ $$ = ICMP_SOURCEQUENCH; }
	| IPFY_ICMPT_REDIR		{ $$ = ICMP_REDIRECT; }
	| IPFY_ICMPT_TIMEX		{ $$ = ICMP_TIMXCEED; }
	| IPFY_ICMPT_PARAMP		{ $$ = ICMP_PARAMPROB; }
	| IPFY_ICMPT_TIMEST		{ $$ = ICMP_TSTAMP; }
	| IPFY_ICMPT_TIMESTREP		{ $$ = ICMP_TSTAMPREPLY; }
	| IPFY_ICMPT_INFOREQ		{ $$ = ICMP_IREQ; }
	| IPFY_ICMPT_INFOREP		{ $$ = ICMP_IREQREPLY; }
	| IPFY_ICMPT_MASKREQ		{ $$ = ICMP_MASKREQ; }
	| IPFY_ICMPT_MASKREP		{ $$ = ICMP_MASKREPLY; }
	| IPFY_ICMPT_ROUTERAD		{ $$ = ICMP_ROUTERADVERT; }
	| IPFY_ICMPT_ROUTERSOL		{ $$ = ICMP_ROUTERSOLICIT; }
	;

icmpcode:
	YY_NUMBER			{ $$ = $1; }
	| IPFY_ICMPC_NETUNR		{ $$ = ICMP_UNREACH_NET; }
	| IPFY_ICMPC_HSTUNR		{ $$ = ICMP_UNREACH_HOST; }
	| IPFY_ICMPC_PROUNR		{ $$ = ICMP_UNREACH_PROTOCOL; }
	| IPFY_ICMPC_PORUNR		{ $$ = ICMP_UNREACH_PORT; }
	| IPFY_ICMPC_NEEDF		{ $$ = ICMP_UNREACH_NEEDFRAG; }
	| IPFY_ICMPC_SRCFAIL		{ $$ = ICMP_UNREACH_SRCFAIL; }
	| IPFY_ICMPC_NETUNK		{ $$ = ICMP_UNREACH_NET_UNKNOWN; }
	| IPFY_ICMPC_HSTUNK		{ $$ = ICMP_UNREACH_HOST_UNKNOWN; }
	| IPFY_ICMPC_ISOLATE		{ $$ = ICMP_UNREACH_ISOLATED; }
	| IPFY_ICMPC_NETPRO		{ $$ = ICMP_UNREACH_NET_PROHIB; }
	| IPFY_ICMPC_HSTPRO		{ $$ = ICMP_UNREACH_HOST_PROHIB; }
	| IPFY_ICMPC_NETTOS		{ $$ = ICMP_UNREACH_TOSNET; }
	| IPFY_ICMPC_HSTTOS		{ $$ = ICMP_UNREACH_TOSHOST; }
	| IPFY_ICMPC_FLTPRO		{ $$ = ICMP_UNREACH_ADMIN_PROHIBIT; }
	| IPFY_ICMPC_HSTPRE		{ $$ = 14; }
	| IPFY_ICMPC_CUTPRE		{ $$ = 15; }
	;

opt:
	IPFY_IPOPT_NOP			{ $$ = getoptbyvalue(IPOPT_NOP); }
	| IPFY_IPOPT_RR			{ $$ = getoptbyvalue(IPOPT_RR); }
	| IPFY_IPOPT_ZSU		{ $$ = getoptbyvalue(IPOPT_ZSU); }
	| IPFY_IPOPT_MTUP		{ $$ = getoptbyvalue(IPOPT_MTUP); }
	| IPFY_IPOPT_MTUR		{ $$ = getoptbyvalue(IPOPT_MTUR); }
	| IPFY_IPOPT_ENCODE		{ $$ = getoptbyvalue(IPOPT_ENCODE); }
	| IPFY_IPOPT_TS			{ $$ = getoptbyvalue(IPOPT_TS); }
	| IPFY_IPOPT_TR			{ $$ = getoptbyvalue(IPOPT_TR); }
	| IPFY_IPOPT_SEC		{ $$ = getoptbyvalue(IPOPT_SECURITY); }
	| IPFY_IPOPT_LSRR		{ $$ = getoptbyvalue(IPOPT_LSRR); }
	| IPFY_IPOPT_ESEC		{ $$ = getoptbyvalue(IPOPT_E_SEC); }
	| IPFY_IPOPT_CIPSO		{ $$ = getoptbyvalue(IPOPT_CIPSO); }
	| IPFY_IPOPT_SATID		{ $$ = getoptbyvalue(IPOPT_SATID); }
	| IPFY_IPOPT_SSRR		{ $$ = getoptbyvalue(IPOPT_SSRR); }
	| IPFY_IPOPT_ADDEXT		{ $$ = getoptbyvalue(IPOPT_ADDEXT); }
	| IPFY_IPOPT_VISA		{ $$ = getoptbyvalue(IPOPT_VISA); }
	| IPFY_IPOPT_IMITD		{ $$ = getoptbyvalue(IPOPT_IMITD); }
	| IPFY_IPOPT_EIP		{ $$ = getoptbyvalue(IPOPT_EIP); }
	| IPFY_IPOPT_FINN		{ $$ = getoptbyvalue(IPOPT_FINN); }
	| IPFY_IPOPT_DPS		{ $$ = getoptbyvalue(IPOPT_DPS); }
	| IPFY_IPOPT_SDB		{ $$ = getoptbyvalue(IPOPT_SDB); }
	| IPFY_IPOPT_NSAPA		{ $$ = getoptbyvalue(IPOPT_NSAPA); }
	| IPFY_IPOPT_RTRALRT		{ $$ = getoptbyvalue(IPOPT_RTRALRT); }
	| IPFY_IPOPT_UMP		{ $$ = getoptbyvalue(IPOPT_UMP); }
	| IPFY_SECCLASS secname
			{ DOALL(fr->fr_mip.fi_secmsk |= $2;
				if (!nowith)
					fr->fr_ip.fi_secmsk |= $2;)
			  $$ = 0;
			}
	;

ipv6hdr:
	IPFY_AH			{ $$ = getv6optbyvalue(IPPROTO_AH); }
	| IPFY_IPV6OPT_DSTOPTS	{ $$ = getv6optbyvalue(IPPROTO_DSTOPTS); }
	| IPFY_ESP		{ $$ = getv6optbyvalue(IPPROTO_ESP); }
	| IPFY_IPV6OPT_HOPOPTS	{ $$ = getv6optbyvalue(IPPROTO_HOPOPTS); }
	| IPFY_IPV6OPT_IPV6	{ $$ = getv6optbyvalue(IPPROTO_IPV6); }
	| IPFY_IPV6OPT_NONE	{ $$ = getv6optbyvalue(IPPROTO_NONE); }
	| IPFY_IPV6OPT_ROUTING	{ $$ = getv6optbyvalue(IPPROTO_ROUTING); }
	| IPFY_FRAG		{ $$ = getv6optbyvalue(IPPROTO_FRAGMENT); }
	;

level:	IPFY_LEVEL			{ setsyslog(); }
	;

loglevel:
	priority			{ fr->fr_loglevel = LOG_LOCAL0|$1; }
	| facility '.' priority		{ fr->fr_loglevel = $1 | $3; }
	;

facility:
	IPFY_FAC_KERN			{ $$ = LOG_KERN; }
	| IPFY_FAC_USER			{ $$ = LOG_USER; }
	| IPFY_FAC_MAIL			{ $$ = LOG_MAIL; }
	| IPFY_FAC_DAEMON		{ $$ = LOG_DAEMON; }
	| IPFY_FAC_AUTH			{ $$ = LOG_AUTH; }
	| IPFY_FAC_SYSLOG		{ $$ = LOG_SYSLOG; }
	| IPFY_FAC_LPR			{ $$ = LOG_LPR; }
	| IPFY_FAC_NEWS			{ $$ = LOG_NEWS; }
	| IPFY_FAC_UUCP			{ $$ = LOG_UUCP; }
	| IPFY_FAC_CRON			{ $$ = LOG_CRON; }
	| IPFY_FAC_FTP			{ $$ = LOG_FTP; }
	| IPFY_FAC_AUTHPRIV		{ $$ = LOG_AUTHPRIV; }
	| IPFY_FAC_AUDIT		{ $$ = LOG_AUDIT; }
	| IPFY_FAC_LFMT			{ $$ = LOG_LFMT; }
	| IPFY_FAC_LOCAL0		{ $$ = LOG_LOCAL0; }
	| IPFY_FAC_LOCAL1		{ $$ = LOG_LOCAL1; }
	| IPFY_FAC_LOCAL2		{ $$ = LOG_LOCAL2; }
	| IPFY_FAC_LOCAL3		{ $$ = LOG_LOCAL3; }
	| IPFY_FAC_LOCAL4		{ $$ = LOG_LOCAL4; }
	| IPFY_FAC_LOCAL5		{ $$ = LOG_LOCAL5; }
	| IPFY_FAC_LOCAL6		{ $$ = LOG_LOCAL6; }
	| IPFY_FAC_LOCAL7		{ $$ = LOG_LOCAL7; }
	| IPFY_FAC_SECURITY		{ $$ = LOG_SECURITY; }
	;

priority:
	IPFY_PRI_EMERG			{ $$ = LOG_EMERG; }
	| IPFY_PRI_ALERT		{ $$ = LOG_ALERT; }
	| IPFY_PRI_CRIT			{ $$ = LOG_CRIT; }
	| IPFY_PRI_ERR			{ $$ = LOG_ERR; }
	| IPFY_PRI_WARN			{ $$ = LOG_WARNING; }
	| IPFY_PRI_NOTICE		{ $$ = LOG_NOTICE; }
	| IPFY_PRI_INFO			{ $$ = LOG_INFO; }
	| IPFY_PRI_DEBUG		{ $$ = LOG_DEBUG; }
	;

compare:
	'='				{ $$ = FR_EQUAL; }
	| YY_CMP_EQ			{ $$ = FR_EQUAL; }
	| YY_CMP_NE			{ $$ = FR_NEQUAL; }
	| YY_CMP_LT			{ $$ = FR_LESST; }
	| YY_CMP_LE			{ $$ = FR_LESSTE; }
	| YY_CMP_GT			{ $$ = FR_GREATERT; }
	| YY_CMP_GE			{ $$ = FR_GREATERTE; }
	;

range:	YY_RANGE_IN			{ $$ = FR_INRANGE; }
	| YY_RANGE_OUT			{ $$ = FR_OUTRANGE; }
	| ':'				{ $$ = FR_INCRANGE; }
	;

servicename:
	YY_STR				{ $$ = $1; }
	;

interfacename:	YY_STR			{ $$ = $1; }
	| YY_STR ':' YY_NUMBER
		{ $$ = $1;
#if SOLARIS2 >= 10
		if (strncmp(VNI, $1, VNISTRLEN) != 0)
#endif
		  fprintf(stderr, "%d: Logical interface %s:%d unsupported, "
			"use the physical interface %s instead.\n",
			yylineNum, $1, $3, $1);
		}
	;

name:	YY_STR				{ $$ = $1; }
	;

ipv4:	YY_NUMBER '.' YY_NUMBER '.' YY_NUMBER '.' YY_NUMBER
		{ if ($1 > 255 || $3 > 255 || $5 > 255 || $7 > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  $$.s_addr = ($1 << 24) | ($3 << 16) | ($5 << 8) | $7;
		  $$.s_addr = htonl($$.s_addr);
		}
	;
%%


static	struct	wordtab ipfwords[] = {
	{ "addext",			IPFY_IPOPT_ADDEXT },
	{ "age",			IPFY_AGE },
	{ "ah",				IPFY_AH },
	{ "all",			IPFY_ALL },
	{ "and",			IPFY_AND },
	{ "auth",			IPFY_AUTH },
	{ "bad",			IPFY_BAD },
	{ "bad-nat",			IPFY_BADNAT },
	{ "bad-src",			IPFY_BADSRC },
	{ "bcast",			IPFY_BROADCAST },
	{ "block",			IPFY_BLOCK },
	{ "body",			IPFY_BODY },
	{ "bpf",			IPFY_BPF },
	{ "call",			IPFY_CALL },
	{ "cipso",			IPFY_IPOPT_CIPSO },
	{ "code",			IPFY_ICMPCODE },
	{ "confid",			IPFY_SEC_CONF },
	{ "count",			IPFY_COUNT },
	{ "divert",			IPFY_DIVERT },
	{ "dps",			IPFY_IPOPT_DPS },
	{ "dstopts",			IPFY_IPV6OPT_DSTOPTS },
	{ "dup-to",			IPFY_DUPTO },
	{ "e-sec",			IPFY_IPOPT_ESEC },
	{ "eip",			IPFY_IPOPT_EIP },
	{ "encode",			IPFY_IPOPT_ENCODE },
	{ "eq",				YY_CMP_EQ },
	{ "esp",			IPFY_ESP },
	{ "fastroute",			IPFY_FROUTE },
	{ "first",			IPFY_FIRST },
	{ "finn",			IPFY_IPOPT_FINN },
	{ "frag",			IPFY_FRAG },
	{ "flags",			IPFY_FLAGS },
	{ "frags",			IPFY_FRAGS },
	{ "from",			IPFY_FROM },
	{ "ge",				YY_CMP_GE },
	{ "group",			IPFY_GROUP },
	{ "gt",				YY_CMP_GT },
	{ "head",			IPFY_HEAD },
	{ "hopopts",			IPFY_IPV6OPT_HOPOPTS },
	{ "host-preced",		IPFY_ICMPC_HSTPRE },
	{ "host-prohib",		IPFY_ICMPC_HSTPRO },
	{ "host-tos",			IPFY_ICMPC_HSTTOS },
	{ "host-unk",			IPFY_ICMPC_HSTUNK },
	{ "host-unr",			IPFY_ICMPC_HSTUNR },
	{ "icmp",			IPFY_ICMP },
	{ "icmp-type",			IPFY_ICMPTYPE },
	{ "imitd",			IPFY_IPOPT_IMITD },
	{ "in",				IPFY_IN },
	{ "in-via",			IPFY_INVIA },
	{ "ipopt",			IPFY_IPOPTS },
	{ "ipopts",			IPFY_IPOPTS },
	{ "ipv6",			IPFY_IPV6OPT_IPV6 },
	{ "keep",			IPFY_KEEP },
	{ "le",				YY_CMP_LE },
	{ "level",			IPFY_LEVEL },
	{ "limit",			IPFY_LIMIT },
	{ "log",			IPFY_LOG },
	{ "lowttl",			IPFY_LOWTTL },
	{ "lsrr",			IPFY_IPOPT_LSRR },
	{ "lt",				YY_CMP_LT },
	{ "mask",			IPFY_MASK },
	{ "mbcast",			IPFY_MBCAST },
	{ "mtup",			IPFY_IPOPT_MTUP },
	{ "mtur",			IPFY_IPOPT_MTUR },
	{ "multicast",			IPFY_MULTICAST },
	{ "nat",			IPFY_NAT },
	{ "ne",				YY_CMP_NE },
	{ "net",			IPFY_NETWORK },
	{ "newisn",			IPFY_NEWISN },
	{ "no",				IPFY_NO },
	{ "no-icmp-err",		IPFY_NOICMPERR },
	{ "none",			IPFY_IPV6OPT_NONE },
	{ "nop",			IPFY_IPOPT_NOP },
	{ "now",			IPFY_NOW },
	{ "not",			IPFY_NOT },
	{ "nsapa",			IPFY_IPOPT_NSAPA },
	{ "oow",			IPFY_OOW },
	{ "on",				IPFY_ON },
	{ "opt",			IPFY_OPT },
	{ "or-block",			IPFY_ORBLOCK },
	{ "out",			IPFY_OUT },
	{ "out-via",			IPFY_OUTVIA },
	{ "pass",			IPFY_PASS },
	{ "port",			IPFY_PORT },
	{ "pps",			IPFY_PPS },
	{ "preauth",			IPFY_PREAUTH },
	{ "proto",			IPFY_PROTO },
	{ "quick",			IPFY_QUICK },
	{ "reply-to",			IPFY_REPLY_TO },
	{ "reserv-1",			IPFY_SEC_RSV1 },
	{ "reserv-2",			IPFY_SEC_RSV2 },
	{ "reserv-3",			IPFY_SEC_RSV3 },
	{ "reserv-4",			IPFY_SEC_RSV4 },
	{ "return-icmp",		IPFY_RETICMP },
	{ "return-icmp-as-dest",	IPFY_RETICMPASDST },
	{ "return-rst",			IPFY_RETRST },
	{ "routing",			IPFY_IPV6OPT_ROUTING },
	{ "rr",				IPFY_IPOPT_RR },
	{ "rtralrt",			IPFY_IPOPT_RTRALRT },
	{ "satid",			IPFY_IPOPT_SATID },
	{ "sdb",			IPFY_IPOPT_SDB },
	{ "sec",			IPFY_IPOPT_SEC },
	{ "sec-class",			IPFY_SECCLASS },
	{ "secret",			IPFY_SEC_SEC },
	{ "skip",			IPFY_SKIP },
	{ "short",			IPFY_SHORT },
	{ "ssrr",			IPFY_IPOPT_SSRR },
	{ "state",			IPFY_STATE },
	{ "strict",			IPFY_STRICT },
	{ "tag",			IPFY_TAG },
	{ "tcp",			IPFY_TCP },
	{ "tcp-udp",			IPFY_TCPUDP },
	{ "tos",			IPFY_TOS },
	{ "topsecret",			IPFY_SEC_TS },
	{ "to",				IPFY_TO },
	{ "tr",				IPFY_IPOPT_TR },
	{ "ts",				IPFY_IPOPT_TS },
	{ "ttl",			IPFY_TTL },
	{ "udp",			IPFY_UDP },
	{ "ump",			IPFY_IPOPT_UMP },
	{ "unclass",			IPFY_SEC_UNC },
	{ "v6hdrs",			IPF6_V6HDRS },
	{ "visa",			IPFY_IPOPT_VISA },
	{ "with",			IPFY_WITH },
	{ "zsu",			IPFY_IPOPT_ZSU },
	{ NULL,				0 }
};

static	struct	wordtab	addrwords[4] = {
	{ "any",			IPFY_ANY },
	{ "hash",			IPFY_HASH },
	{ "pool",			IPFY_POOL },
	{ NULL,				0 }
};

static	struct	wordtab	maskwords[5] = {
	{ "broadcast",			IPFY_BROADCAST },
	{ "netmasked",			IPFY_NETMASKED },
	{ "network",			IPFY_NETWORK },
	{ "peer",			IPFY_PEER },
	{ NULL,				0 }
};

static	struct	wordtab icmptypewords[16] = {
	{ "echo",			IPFY_ICMPT_ECHO },
	{ "echorep",			IPFY_ICMPT_ECHOR },
	{ "inforeq",			IPFY_ICMPT_INFOREQ },
	{ "inforep",			IPFY_ICMPT_INFOREP },
	{ "maskrep",			IPFY_ICMPT_MASKREP },
	{ "maskreq",			IPFY_ICMPT_MASKREQ },
	{ "paramprob",			IPFY_ICMPT_PARAMP },
	{ "redir",			IPFY_ICMPT_REDIR },
	{ "unreach",			IPFY_ICMPT_UNR },
	{ "routerad",			IPFY_ICMPT_ROUTERAD },
	{ "routersol",			IPFY_ICMPT_ROUTERSOL },
	{ "squench",			IPFY_ICMPT_SQUENCH },
	{ "timest",			IPFY_ICMPT_TIMEST },
	{ "timestrep",			IPFY_ICMPT_TIMESTREP },
	{ "timex",			IPFY_ICMPT_TIMEX },
	{ NULL,				0 },
};

static	struct	wordtab icmpcodewords[17] = {
	{ "cutoff-preced",		IPFY_ICMPC_CUTPRE },
	{ "filter-prohib",		IPFY_ICMPC_FLTPRO },
	{ "isolate",			IPFY_ICMPC_ISOLATE },
	{ "needfrag",			IPFY_ICMPC_NEEDF },
	{ "net-prohib",			IPFY_ICMPC_NETPRO },
	{ "net-tos",			IPFY_ICMPC_NETTOS },
	{ "host-preced",		IPFY_ICMPC_HSTPRE },
	{ "host-prohib",		IPFY_ICMPC_HSTPRO },
	{ "host-tos",			IPFY_ICMPC_HSTTOS },
	{ "host-unk",			IPFY_ICMPC_HSTUNK },
	{ "host-unr",			IPFY_ICMPC_HSTUNR },
	{ "net-unk",			IPFY_ICMPC_NETUNK },
	{ "net-unr",			IPFY_ICMPC_NETUNR },
	{ "port-unr",			IPFY_ICMPC_PORUNR },
	{ "proto-unr",			IPFY_ICMPC_PROUNR },
	{ "srcfail",			IPFY_ICMPC_SRCFAIL },
	{ NULL,				0 },
};

static	struct	wordtab logwords[] = {
	{ "kern",			IPFY_FAC_KERN },
	{ "user",			IPFY_FAC_USER },
	{ "mail",			IPFY_FAC_MAIL },
	{ "daemon",			IPFY_FAC_DAEMON },
	{ "auth",			IPFY_FAC_AUTH },
	{ "syslog",			IPFY_FAC_SYSLOG },
	{ "lpr",			IPFY_FAC_LPR },
	{ "news",			IPFY_FAC_NEWS },
	{ "uucp",			IPFY_FAC_UUCP },
	{ "cron",			IPFY_FAC_CRON },
	{ "ftp",			IPFY_FAC_FTP },
	{ "authpriv",			IPFY_FAC_AUTHPRIV },
	{ "audit",			IPFY_FAC_AUDIT },
	{ "logalert",			IPFY_FAC_LFMT },
	{ "console",			IPFY_FAC_CONSOLE },
	{ "security",			IPFY_FAC_SECURITY },
	{ "local0",			IPFY_FAC_LOCAL0 },
	{ "local1",			IPFY_FAC_LOCAL1 },
	{ "local2",			IPFY_FAC_LOCAL2 },
	{ "local3",			IPFY_FAC_LOCAL3 },
	{ "local4",			IPFY_FAC_LOCAL4 },
	{ "local5",			IPFY_FAC_LOCAL5 },
	{ "local6",			IPFY_FAC_LOCAL6 },
	{ "local7",			IPFY_FAC_LOCAL7 },
	{ "emerg",			IPFY_PRI_EMERG },
	{ "alert",			IPFY_PRI_ALERT },
	{ "crit",			IPFY_PRI_CRIT },
	{ "err",			IPFY_PRI_ERR },
	{ "warn",			IPFY_PRI_WARN },
	{ "notice",			IPFY_PRI_NOTICE },
	{ "info",			IPFY_PRI_INFO },
	{ "debug",			IPFY_PRI_DEBUG },
	{ NULL,				0 },
};




int ipf_parsefile(fd, addfunc, iocfuncs, filename)
int fd;
addfunc_t addfunc;
ioctlfunc_t *iocfuncs;
char *filename;
{
	FILE *fp = NULL;
	char *s;

	yylineNum = 1;
	yysettab(ipfwords);

	s = getenv("YYDEBUG");
	if (s != NULL)
		yydebug = atoi(s);
	else
		yydebug = 0;

	if (strcmp(filename, "-")) {
		fp = fopen(filename, "r");
		if (fp == NULL) {
			fprintf(stderr, "fopen(%s) failed: %s\n", filename,
				STRERROR(errno));
			return -1;
		}
	} else
		fp = stdin;

	while (ipf_parsesome(fd, addfunc, iocfuncs, fp) == 1)
		;
	if (fp != NULL)
		fclose(fp);
	return 0;
}


int ipf_parsesome(fd, addfunc, iocfuncs, fp)
int fd;
addfunc_t addfunc;
ioctlfunc_t *iocfuncs;
FILE *fp;
{
	char *s;
	int i;

	ipffd = fd;
	for (i = 0; i <= IPL_LOGMAX; i++)
		ipfioctl[i] = iocfuncs[i];
	ipfaddfunc = addfunc;

	if (feof(fp))
		return 0;
	i = fgetc(fp);
	if (i == EOF)
		return 0;
	if (ungetc(i, fp) == 0)
		return 0;
	if (feof(fp))
		return 0;
	s = getenv("YYDEBUG");
	if (s != NULL)
		yydebug = atoi(s);
	else
		yydebug = 0;

	yyin = fp;
	yyparse();
	return 1;
}


static void newrule()
{
	frentry_t *frn;

	frn = (frentry_t *)calloc(1, sizeof(frentry_t));
	for (fr = frtop; fr != NULL && fr->fr_next != NULL; fr = fr->fr_next)
		;
	if (fr != NULL)
		fr->fr_next = frn;
	if (frtop == NULL)
		frtop = frn;
	fr = frn;
	frc = frn;
	fr->fr_loglevel = 0xffff;
	fr->fr_isc = (void *)-1;
	fr->fr_logtag = FR_NOLOGTAG;
	fr->fr_type = FR_T_NONE;
	if (use_inet6 != 0)
		fr->fr_v = 6;
	else
		fr->fr_v = 4;

	nrules = 1;
}


static void setipftype()
{
	for (fr = frc; fr != NULL; fr = fr->fr_next) {
		if (fr->fr_type == FR_T_NONE) {
			fr->fr_type = FR_T_IPF;
			fr->fr_data = (void *)calloc(sizeof(fripf_t), 1);
			fr->fr_dsize = sizeof(fripf_t);
			fr->fr_ip.fi_v = frc->fr_v;
			fr->fr_mip.fi_v = 0xf;
			fr->fr_ipf->fri_sifpidx = -1;
			fr->fr_ipf->fri_difpidx = -1;
		}
		if (fr->fr_type != FR_T_IPF) {
			fprintf(stderr, "IPF Type not set\n");
		}
	}
}


static frentry_t *addrule()
{
	frentry_t *f, *f1, *f2;
	int count;

	for (f2 = frc; f2->fr_next != NULL; f2 = f2->fr_next)
		;

	count = nrules;
	if (count == 0) {
		f = (frentry_t *)calloc(sizeof(*f), 1);
		added++;
		f2->fr_next = f;
		bcopy(f2, f, sizeof(*f));
		if (f2->fr_caddr != NULL) {
			f->fr_caddr = malloc(f->fr_dsize);
			bcopy(f2->fr_caddr, f->fr_caddr, f->fr_dsize);
		}
		f->fr_next = NULL;
		return f;
	}
	f = f2;
	for (f1 = frc; count > 0; count--, f1 = f1->fr_next) {
		f->fr_next = (frentry_t *)calloc(sizeof(*f), 1);
		added++;
		f = f->fr_next;
		bcopy(f1, f, sizeof(*f));
		f->fr_next = NULL;
		if (f->fr_caddr != NULL) {
			f->fr_caddr = malloc(f->fr_dsize);
			bcopy(f1->fr_caddr, f->fr_caddr, f->fr_dsize);
		}
	}

	return f2->fr_next;
}


static u_32_t lookuphost(name)
char *name;
{
	u_32_t addr;
	int i;

	hashed = 0;
	pooled = 0;
	dynamic = -1;

	for (i = 0; i < 4; i++) {
		if (strncmp(name, frc->fr_ifnames[i],
			    sizeof(frc->fr_ifnames[i])) == 0) {
			ifpflag = FRI_DYNAMIC;
			dynamic = i;
			return 0;
		}
	}

	if (gethost(name, &addr) == -1) {
		return 0;
	}
	return addr;
}


static void dobpf(phrase)
char *phrase;
{
#ifdef IPFILTER_BPF
	struct bpf_program bpf;
	struct pcap *p;
	u_32_t l;
	char *s;
	int i;

	for (fr = frc; fr != NULL; fr = fr->fr_next) {
		if (fr->fr_type != FR_T_NONE) {
			fprintf(stderr, "cannoy mix IPF and BPF matching\n");
			return;
		}
		fr->fr_type = FR_T_IPF;

		if (!strncmp(phrase, "\"0x", 2)) {
			phrase++;
			fr->fr_data = malloc(4);

			for (i = 0, s = strtok(phrase, " \r\n\t"; s != NULL;
			     s = strtok(NULL, " \r\n\t"), i++) {
				fr->fr_data = realloc(fr->fr_data, (i + 1) * 4);
				l = (u_32_t)strtol(s, NULL, 0);
				((u_32_t *)fr->fr_data)[i] = l;
			}
			return;
		}

		bzero((char *)&bpf, sizeof(bpf));
		p = pcap_open_dead(DLT_RAW, 1);
		if (!p) {
			fprintf(stderr, "pcap_open_dead failed\n");
			return;
		}

		if (pcap_compile(p, &bpf, phrase, 1, 0xffffffff) {
			pcap_perror(p, "ipf");
			pcap_close(p);
			fprintf(stderr, "pcap parsing failed\n");
			return;
		}
		pcap_close(p);

		fr->fr_dsize = bpf.bf_len * sizeof(struct bpf_insn);
		fr->fr_data = malloc(bpf.bf_len);
		bcopy((char *)bpf.bf_insns, fr->fr_data, bpf.bf_len);
		if (!bpf_validate(fr->fr_data, bpf.bf_len)) {
			fprintf(stderr, "BPF validation failed\n");
			return;
		}
	}

	if (opts & OPT_DEBUG)
		bpf_dump(&bpf, 0);
#else
	fprintf(stderr, "BPF expressions for matching not supported\n");
#endif
}


static void resetaddr()
{
	hashed = 0;
	pooled = 0;
	dynamic = -1;
}


static alist_t *newalist(ptr)
alist_t *ptr;
{
	alist_t *al;

	al = malloc(sizeof(*al));
	if (al == NULL)
		return NULL;
	al->al_not = 0;
	al->al_next = ptr;
	return al;
}


static int makepool(list)
alist_t *list;
{
	ip_pool_node_t *n, *top;
	ip_pool_t pool;
	alist_t *a;
	int num;

	if (list == NULL)
		return 0;
	top = calloc(1, sizeof(*top));
	if (top == NULL)
		return 0;
	
	for (n = top, a = list; (n != NULL) && (a != NULL); a = a->al_next) {
		n->ipn_addr.adf_addr.in4.s_addr = a->al_1;
		n->ipn_mask.adf_addr.in4.s_addr = a->al_2;
		n->ipn_info = a->al_not;
		if (a->al_next != NULL) {
			n->ipn_next = calloc(1, sizeof(*n));
			n = n->ipn_next;
		}
	}

	bzero((char *)&pool, sizeof(pool));
	pool.ipo_unit = IPL_LOGIPF;
	pool.ipo_list = top;
	num = load_pool(&pool, ipfioctl[IPL_LOGLOOKUP]);

	while ((n = top) != NULL) {
		top = n->ipn_next;
		free(n);
	}
	return num;
}


static u_int makehash(list)
alist_t *list;
{
	iphtent_t *n, *top;
	iphtable_t iph;
	alist_t *a;
	int num;

	if (list == NULL)
		return 0;
	top = calloc(1, sizeof(*top));
	if (top == NULL)
		return 0;
	
	for (n = top, a = list; (n != NULL) && (a != NULL); a = a->al_next) {
		n->ipe_addr.in4_addr = a->al_1;
		n->ipe_mask.in4_addr = a->al_2;
		n->ipe_value = 0;
		if (a->al_next != NULL) {
			n->ipe_next = calloc(1, sizeof(*n));
			n = n->ipe_next;
		}
	}

	bzero((char *)&iph, sizeof(iph));
	iph.iph_unit = IPL_LOGIPF;
	iph.iph_type = IPHASH_LOOKUP;
	*iph.iph_name = '\0';

	if (load_hash(&iph, top, ipfioctl[IPL_LOGLOOKUP]) == 0)
		sscanf(iph.iph_name, "%u", &num);
	else
		num = 0;

	while ((n = top) != NULL) {
		top = n->ipe_next;
		free(n);
	}
	return num;
}


void ipf_addrule(fd, ioctlfunc, ptr)
int fd;
ioctlfunc_t ioctlfunc;
void *ptr;
{
	u_int add, del;
	frentry_t *fr;
	ipfobj_t obj;

	fr = ptr;
	add = 0;
	del = 0;

	bzero((char *)&obj, sizeof(obj));
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(*fr);
	obj.ipfo_type = IPFOBJ_FRENTRY;
	obj.ipfo_ptr = ptr;

	if ((opts & OPT_DONOTHING) != 0)
		fd = -1;

	if (opts & OPT_ZERORULEST) {
		add = SIOCZRLST;
	} else if (opts & OPT_INACTIVE) {
		add = (u_int)fr->fr_hits ? SIOCINIFR :
					   SIOCADIFR;
		del = SIOCRMIFR;
	} else {
		add = (u_int)fr->fr_hits ? SIOCINAFR :
					   SIOCADAFR;
		del = SIOCRMAFR;
	}

	if (fr && (opts & OPT_OUTQUE))
		fr->fr_flags |= FR_OUTQUE;
	if (fr->fr_hits)
		fr->fr_hits--;
	if (fr && (opts & OPT_VERBOSE))
		printfr(fr, ioctlfunc);

	if (opts & OPT_DEBUG) {
		binprint(fr, sizeof(*fr));
		if (fr->fr_data != NULL)
			binprint(fr->fr_data, fr->fr_dsize);
	}

	if ((opts & OPT_ZERORULEST) != 0) {
		if ((*ioctlfunc)(fd, add, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(SIOCZRLST)");
			}
		} else {
#ifdef	USE_QUAD_T
			printf("hits %qd bytes %qd ",
				(long long)fr->fr_hits,
				(long long)fr->fr_bytes);
#else
			printf("hits %ld bytes %ld ",
				fr->fr_hits, fr->fr_bytes);
#endif
			printfr(fr, ioctlfunc);
		}
	} else if ((opts & OPT_REMOVE) != 0) {
		if ((*ioctlfunc)(fd, del, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(delete rule)");
			}
		}
	} else {
		if ((*ioctlfunc)(fd, add, (void *)&obj) == -1) {
			if (!(opts & OPT_DONOTHING)) {
				fprintf(stderr, "%d:", yylineNum);
				fprintf(stderr,"ioctl(add/insert rule) failed: rule exists\n");
			}
		}
	}
}


static void setsyslog()
{
	savewords = yysettab(logwords);
	yybreakondot = 1;
}


static void unsetsyslog()
{
	yysettab(savewords);
	yybreakondot = 0;
}


static void fillgroup(fr)
frentry_t *fr;
{
	frentry_t *f;
	int i;

	for (f = frold; f != NULL; f = f->fr_next)
		if (strncmp(f->fr_grhead, fr->fr_group, FR_GROUPLEN) == 0)
			break;
	if (f == NULL)
		return;

	/*
	 * Only copy down matching fields if the rules are of the same type
	 * and are of ipf type.
	 */
	if (f->fr_type != fr->fr_type || f->fr_type != FR_T_IPF)
		return;

	if (fr->fr_v == 0 && f->fr_v != 0)
		fr->fr_v = f->fr_v;

	if (fr->fr_mproto == 0 && f->fr_mproto != 0)
		fr->fr_mproto = f->fr_mproto;
	if (fr->fr_proto == 0 && f->fr_proto != 0)
		fr->fr_proto = f->fr_proto;

	if (fr->fr_proto == IPPROTO_TCP) {
		if (fr->fr_tcpfm == 0 && f->fr_tcpfm != 0)
			fr->fr_tcpfm = f->fr_tcpfm;
		if (fr->fr_tcpf == 0 && f->fr_tcpf != 0)
			fr->fr_tcpf = f->fr_tcpf;
	}

	if (fr->fr_proto == IPPROTO_ICMP) {
		if (fr->fr_icmpm == 0 && f->fr_icmpm != 0)
			fr->fr_icmpm = f->fr_icmpm;
		if (fr->fr_icmp == 0 && f->fr_icmp != 0)
			fr->fr_icmp = f->fr_icmp;
	}

	if (fr->fr_optbits == 0 && f->fr_optbits != 0)
		fr->fr_optbits = f->fr_optbits;
	if (fr->fr_optmask == 0 && f->fr_optmask != 0)
		fr->fr_optmask = f->fr_optmask;
	if (fr->fr_secbits == 0 && f->fr_secbits != 0)
		fr->fr_secbits = f->fr_secbits;
	if (fr->fr_secmask == 0 && f->fr_secmask != 0)
		fr->fr_secmask = f->fr_secmask;
	if (fr->fr_authbits == 0 && f->fr_authbits != 0)
		fr->fr_authbits = f->fr_authbits;
	if (fr->fr_authmask == 0 && f->fr_authmask != 0)
		fr->fr_authmask = f->fr_authmask;

	for (i = 0; i < 3; i++) {
		if (*f->fr_ifnames[i] != '\0' && *fr->fr_ifnames[i] == '\0')
			strncpy(fr->fr_ifnames[i], f->fr_ifnames[i],
				sizeof(f->fr_ifnames[i]));
	}
}
