%{
/*
 * Copyright (C) 2001-2008 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2019 Joyent, Inc.
 */

#ifdef  __FreeBSD__
# ifndef __FreeBSD_cc_version
#  include <osreldate.h>
# else
#  if __FreeBSD_cc_version < 430000
#   include <osreldate.h>
#  endif
# endif
#endif
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#if !defined(__SVR4) && !defined(__GNUC__)
#include <strings.h>
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <sys/time.h>
#include <syslog.h>
#include <net/if.h>
#include <uuid/uuid.h>
#if __FreeBSD_version >= 300000
# include <net/if_var.h>
#endif
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "ipf.h"
#include "netinet/ipl.h"
#include "ipnat_l.h"

#define	YYDEBUG	1

extern	int	yyerror __P((const char *));
extern	int	yyparse __P((void));
extern	int	yylex __P((void));
extern	int	yydebug;
extern	FILE	*yyin;
extern	int	yylineNum;

static	ipnat_t		*nattop = NULL;
static	ipnat_t		*nat = NULL;
static	int		natfd = -1;
static	ioctlfunc_t	natioctlfunc = NULL;
static	addfunc_t	nataddfunc = NULL;

static	void	newnatrule __P((void));
static	void	setnatproto __P((int));

%}
%union	{
	char	*str;
	u_32_t	num;
	struct	{
		i6addr_t	a;
		int		v;
	} ipa;
	frentry_t	fr;
	frtuc_t	*frt;
	u_short	port;
	struct	{
		u_short	p1;
		u_short	p2;
		int	pc;
	} pc;
	struct	{
		i6addr_t	a;
		i6addr_t	m;
		int	v;
	} ipp;
	union	i6addr	ip6;
	uuid_t	uuid;
};

%token  <num>   YY_NUMBER YY_HEX
%token  <str>   YY_STR
%token	  YY_COMMENT
%token	  YY_CMP_EQ YY_CMP_NE YY_CMP_LE YY_CMP_GE YY_CMP_LT YY_CMP_GT
%token	  YY_RANGE_OUT YY_RANGE_IN
%token  <ip6>   YY_IPV6
%token  <uuid>	YY_UUID

%token	IPNY_MAPBLOCK IPNY_RDR IPNY_PORT IPNY_PORTS IPNY_AUTO IPNY_RANGE
%token	IPNY_MAP IPNY_BIMAP IPNY_FROM IPNY_TO IPNY_MASK IPNY_PORTMAP IPNY_ANY
%token	IPNY_ROUNDROBIN IPNY_FRAG IPNY_AGE IPNY_ICMPIDMAP IPNY_PROXY
%token	IPNY_TCP IPNY_UDP IPNY_TCPUDP IPNY_STICKY IPNY_MSSCLAMP IPNY_TAG
%token	IPNY_TLATE IPNY_SEQUENTIAL
%type	<port> portspec
%type	<num> hexnumber compare range proto
%type	<num> saddr daddr sobject dobject mapfrom rdrfrom dip
%type	<ipa> hostname ipv4 ipaddr
%type	<ipp> addr rhaddr
%type	<pc> portstuff
%%
file:	line
	| assign
	| file line
	| file assign
	;

line:	xx rule		{ while ((nat = nattop) != NULL) {
				if (nat->in_v == 0)
					nat->in_v = 4;
				nattop = nat->in_next;
				(*nataddfunc)(natfd, natioctlfunc, nat);
				free(nat);
			  }
			  resetlexer();
			}
	| YY_COMMENT
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

xx:					{ newnatrule(); }
	;

rule:	map eol
	| mapblock eol
	| redir eol
	;

eol:	| ';'
	;

map:	mapit ifnames addr IPNY_TLATE rhaddr proxy mapoptions
				{ if ($3.v != 0 && $3.v != $5.v && $5.v != 0)
					yyerror("1.address family mismatch");
				  bcopy(&$3.a, &nat->in_in[0], sizeof($3.a));
				  bcopy(&$3.m, &nat->in_in[1], sizeof($3.a));
				  bcopy(&$5.a, &nat->in_out[0], sizeof($5.a));
				  bcopy(&$5.m, &nat->in_out[1], sizeof($5.a));
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDP) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				}
	| mapit ifnames addr IPNY_TLATE rhaddr mapport mapoptions
				{ if ($3.v != 0 && $3.v != $5.v && $5.v != 0)
					yyerror("2.address family mismatch");
				  bcopy(&$3.a, &nat->in_in[0], sizeof($3.a));
				  bcopy(&$3.m, &nat->in_in[1], sizeof($3.a));
				  bcopy(&$5.a, &nat->in_out[0], sizeof($5.a));
				  bcopy(&$5.m, &nat->in_out[1], sizeof($5.a));
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDPICMPQ) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				}
	| mapit ifnames mapfrom IPNY_TLATE rhaddr proxy mapoptions
				{ if ($3 != 0 && $3 != $5.v && $5.v != 0)
					yyerror("3.address family mismatch");
				  bcopy(&$5.a, &nat->in_out[0], sizeof($5.a));
				  bcopy(&$5.m, &nat->in_out[1], sizeof($5.a));
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDP) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				}
	| mapit ifnames mapfrom IPNY_TLATE rhaddr mapport mapoptions
				{ if ($3 != 0 && $3 != $5.v && $5.v != 0)
					yyerror("4.address family mismatch");
				  bcopy(&$5.a, &nat->in_out[0], sizeof($5.a));
				  bcopy(&$5.m, &nat->in_out[1], sizeof($5.a));
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDPICMPQ) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				}
	;

mapblock:
	mapblockit ifnames addr IPNY_TLATE addr ports mapoptions
				{ if ($3.v != 0 && $3.v != $5.v && $5.v != 0)
					yyerror("5.address family mismatch");
				  bcopy(&$3.a, &nat->in_in[0], sizeof($3.a));
				  bcopy(&$3.m, &nat->in_in[1], sizeof($3.a));
				  bcopy(&$5.a, &nat->in_out[0], sizeof($5.a));
				  bcopy(&$5.m, &nat->in_out[1], sizeof($5.a));
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_flags & IPN_TCPUDP) == 0)
					setnatproto(nat->in_p);
				  if (((nat->in_redir & NAT_MAPBLK) != 0) ||
				      ((nat->in_flags & IPN_AUTOPORTMAP) != 0))
					nat_setgroupmap(nat);
				}
	;

redir:	rdrit ifnames addr dport IPNY_TLATE dip nport setproto rdroptions
				{ if ($6 != 0 && $3.v != 0 && $6 != $3.v)
					yyerror("6.address family mismatch");
				  bcopy(&$3.a, &nat->in_out[0], sizeof($3.a));
				  bcopy(&$3.m, &nat->in_out[1], sizeof($3.a));
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				  if ((nat->in_p == 0) &&
				      ((nat->in_flags & IPN_TCPUDP) == 0) &&
				      (nat->in_pmin != 0 ||
				       nat->in_pmax != 0 ||
				       nat->in_pnext != 0))
						setnatproto(IPPROTO_TCP);
				}
	| rdrit ifnames rdrfrom IPNY_TLATE dip nport setproto rdroptions
				{ if ($5 != 0 && $3 != 0 && $5 != $3)
					yyerror("7.address family mismatch");
				  if ((nat->in_p == 0) &&
				      ((nat->in_flags & IPN_TCPUDP) == 0) &&
				      (nat->in_pmin != 0 ||
				       nat->in_pmax != 0 ||
				       nat->in_pnext != 0))
					setnatproto(IPPROTO_TCP);
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				}
	| rdrit ifnames addr IPNY_TLATE dip setproto rdroptions
				{ if ($5 != 0 && $3.v != 0 && $5 != $3.v)
					yyerror("8.address family mismatch");
				  bcopy(&$3.a, &nat->in_out[0], sizeof($3.a));
				  bcopy(&$3.m, &nat->in_out[1], sizeof($3.a));
				  if (nat->in_ifnames[1][0] == '\0')
					strncpy(nat->in_ifnames[1],
						nat->in_ifnames[0],
						sizeof(nat->in_ifnames[0]));
				}
	;

proxy:	| IPNY_PROXY IPNY_PORT portspec YY_STR '/' proto
			{ strncpy(nat->in_plabel, $4, sizeof(nat->in_plabel));
			  if (nat->in_dcmp == 0) {
				nat->in_dport = htons($3);
			  } else if ($3 != nat->in_dport) {
				yyerror("proxy port numbers not consistant");
			  }
			  setnatproto($6);
			  free($4);
			}
	| IPNY_PROXY IPNY_PORT YY_STR YY_STR '/' proto
			{ int pnum;
			  strncpy(nat->in_plabel, $4, sizeof(nat->in_plabel));
			  pnum = getportproto($3, $6);
			  if (pnum == -1)
				yyerror("invalid port number");
			  nat->in_dport = pnum;
			  setnatproto($6);
			  free($3);
			  free($4);
			}
	;

setproto:
	| proto				{ if (nat->in_p != 0 ||
					      nat->in_flags & IPN_TCPUDP)
						yyerror("protocol set twice");
					  setnatproto($1);
					}
	| IPNY_TCPUDP			{ if (nat->in_p != 0 ||
					      nat->in_flags & IPN_TCPUDP)
						yyerror("protocol set twice");
					  nat->in_flags |= IPN_TCPUDP;
					  nat->in_p = 0;
					}
	| IPNY_TCP '/' IPNY_UDP		{ if (nat->in_p != 0 ||
					      nat->in_flags & IPN_TCPUDP)
						yyerror("protocol set twice");
					  nat->in_flags |= IPN_TCPUDP;
					  nat->in_p = 0;
					}
	;

rhaddr:	addr				{ $$.a = $1.a;
					  $$.m = $1.m;
					  $$.v = $1.v;
					  if ($$.v == 0)
						$$.v = nat->in_v;
					  yyexpectaddr = 0; }
	| IPNY_RANGE hostname '-' hostname
					{ if ($2.v != 0 && $4.v != 0 && $4.v != $2.v)
						yyerror("9.address family "
							"mismatch");
					  $$.v = $2.v;
					  $$.a = $2.a;
					  $$.m = $4.a;
					  nat->in_flags |= IPN_IPRANGE;
					  yyexpectaddr = 0; }
	;

dip:
	hostname			{ bcopy(&$1.a, &nat->in_in[0],
						sizeof($1.a));
					  if ($1.v == 0)
						$1.v = nat->in_v;
					  if ($1.v == 4) {
						nat->in_inmsk = 0xffffffff;
					  } else {
						nat->in_in[1].i6[0] = 0xffffffff;
						nat->in_in[1].i6[1] = 0xffffffff;
						nat->in_in[1].i6[2] = 0xffffffff;
						nat->in_in[1].i6[3] = 0xffffffff;
					  }
					  $$ = $1.v;
					}
	| hostname '/' YY_NUMBER        { if ($1.v == 0)
						$1.v = nat->in_v;
					  if ($1.v == 4 &&
					      ($1.a.in4.s_addr != 0 ||
					      ($3 != 0 && $3 != 32)))
						yyerror("Invalid mask for dip");
					  else if ($1.v == 6 &&
					      ($1.a.in4.s_addr != 0 ||
					      ($3 != 0 && $3 != 128)))
						yyerror("Invalid mask for dip");
					  else if ($1.v == 0 ) {
						if ($1.a.in4.s_addr == 0 &&
						    ($3 == 32 || $3 == 0))
							$1.v = 4;
						else if ($3 == 128)
							$1.v = 6;
					  }
					  bcopy(&$1.a, &nat->in_in[0],
						sizeof($1.a));
					  ntomask($1.v, $3,
						(u_32_t *)&nat->in_in[1]);
					  nat->in_in[0].i6[0] &= nat->in_in[1].i6[0];
					  nat->in_in[0].i6[0] &= nat->in_in[1].i6[1];
					  nat->in_in[0].i6[0] &= nat->in_in[1].i6[2];
					  nat->in_in[0].i6[0] &= nat->in_in[1].i6[3];
					  nat->in_v = $1.v;
					  $$ = $1.v;
					}
	| hostname ',' { yyexpectaddr = 1; } hostname
					{ if ($1.v != $4.v)
						yyerror("10.address family "
							"mismatch");
					  $$ = $1.v;
					  nat->in_flags |= IPN_SPLIT;
					  bcopy(&$1.a, &nat->in_in[0],
						sizeof($1.a));
					  bcopy(&$4.a, &nat->in_in[1],
						sizeof($4.a));
					  yyexpectaddr = 0; }
	;

portspec:
	YY_NUMBER			{ if ($1 > 65535)	/* Unsigned */
						yyerror("invalid port number");
					  else
						$$ = $1;
					}
	| YY_STR			{ if (getport(NULL, $1, &($$)) == -1)
						yyerror("invalid port number");
					  $$ = ntohs($$);
					}
	;

dport:	| IPNY_PORT portspec			{ nat->in_pmin = htons($2);
						  nat->in_pmax = htons($2); }
	| IPNY_PORT portspec '-' portspec	{ nat->in_pmin = htons($2);
						  nat->in_pmax = htons($4); }
	| IPNY_PORT portspec ':' portspec	{ nat->in_pmin = htons($2);
						  nat->in_pmax = htons($4); }
	;

nport:	IPNY_PORT portspec		{ nat->in_pnext = htons($2); }
	| IPNY_PORT '=' portspec	{ nat->in_pnext = htons($3);
					  nat->in_flags |= IPN_FIXEDDPORT;
					}
	;

ports:	| IPNY_PORTS YY_NUMBER		{ nat->in_pmin = $2; }
	| IPNY_PORTS IPNY_AUTO		{ nat->in_flags |= IPN_AUTOPORTMAP; }
	;

mapit:	IPNY_MAP			{ nat->in_redir = NAT_MAP; }
	| IPNY_BIMAP			{ nat->in_redir = NAT_BIMAP; }
	;

rdrit:	IPNY_RDR			{ nat->in_redir = NAT_REDIRECT; }
	;

mapblockit:
	IPNY_MAPBLOCK			{ nat->in_redir = NAT_MAPBLK; }
	;

mapfrom:
	from sobject IPNY_TO dobject	{ if ($2 != 0 && $4 != 0 && $2 != $4)
						yyerror("11.address family "
							"mismatch");
					  $$ = $2;
					}
	| from sobject '!' IPNY_TO dobject
					{ if ($2 != 0 && $5 != 0 && $2 != $5)
						yyerror("12.address family "
							"mismatch");
					  nat->in_flags |= IPN_NOTDST;
					  $$ = $2;
					}
	;

rdrfrom:
	from sobject IPNY_TO dobject	{ if ($2 != 0 && $4 != 0 && $2 != $4)
						yyerror("13.address family "
							"mismatch");
					  $$ = $2;
					}
	| '!' from sobject IPNY_TO dobject
					{ if ($3 != 0 && $5 != 0 && $3 != $5)
						yyerror("14.address family "
							"mismatch");
					  nat->in_flags |= IPN_NOTSRC;
					  $$ = $3;
					}
	;

from:	IPNY_FROM			{ nat->in_flags |= IPN_FILTER;
					  yyexpectaddr = 1; }
	;

ifnames:
	ifname				{ yyexpectaddr = 1; }
	| ifname ',' otherifname	{ yyexpectaddr = 1; }
	;

ifname:	YY_STR			{ strncpy(nat->in_ifnames[0], $1,
					  sizeof(nat->in_ifnames[0]));
				  nat->in_ifnames[0][LIFNAMSIZ - 1] = '\0';
				  free($1);
				}
	;

otherifname:
	YY_STR			{ strncpy(nat->in_ifnames[1], $1,
					  sizeof(nat->in_ifnames[1]));
				  nat->in_ifnames[1][LIFNAMSIZ - 1] = '\0';
				  free($1);
				}
	;

mapport:
	IPNY_PORTMAP tcpudp portspec ':' portspec randport
			{ nat->in_pmin = htons($3);
			  nat->in_pmax = htons($5);
			}
	| IPNY_PORTMAP tcpudp IPNY_AUTO randport
			{ nat->in_flags |= IPN_AUTOPORTMAP;
			  nat->in_pmin = htons(1024);
			  nat->in_pmax = htons(65535);
			}
	| IPNY_ICMPIDMAP YY_STR YY_NUMBER ':' YY_NUMBER
			{ if (strcmp($2, "icmp") != 0) {
				yyerror("icmpidmap not followed by icmp");
			  }
			  free($2);
			  if ($3 < 0 || $3 > 65535)
				yyerror("invalid ICMP Id number");
			  if ($5 < 0 || $5 > 65535)
				yyerror("invalid ICMP Id number");
			  nat->in_flags = IPN_ICMPQUERY;
			  nat->in_pmin = htons($3);
			  nat->in_pmax = htons($5);
			}
	;

randport:
	| IPNY_SEQUENTIAL	{ nat->in_flags |= IPN_SEQUENTIAL; }
	;

sobject:
	saddr				{ $$ = $1; }
	| saddr IPNY_PORT portstuff	{ nat->in_sport = $3.p1;
					  nat->in_stop = $3.p2;
					  nat->in_scmp = $3.pc;
					  $$ = $1;
					}
	;

saddr:	addr				{ if (nat->in_redir == NAT_REDIRECT) {
						bcopy(&$1.a, &nat->in_src[0],
							sizeof($1.a));
						bcopy(&$1.m, &nat->in_src[1],
							sizeof($1.a));
					  } else {
						bcopy(&$1.a, &nat->in_in[0],
							sizeof($1.a));
						bcopy(&$1.m, &nat->in_in[1],
							sizeof($1.a));
					  }
					  $$ = $1.v;
					}
	;

dobject:
	daddr				{ $$ = $1; }
	| daddr IPNY_PORT portstuff	{ nat->in_dport = $3.p1;
					  nat->in_dtop = $3.p2;
					  nat->in_dcmp = $3.pc;
					  if (nat->in_redir == NAT_REDIRECT)
						nat->in_pmin = htons($3.p1);
					}
	;

daddr:	addr				{ if (nat->in_redir == NAT_REDIRECT) {
						bcopy(&$1.a, &nat->in_out[0],
							sizeof($1.a));
						bcopy(&$1.m, &nat->in_out[1],
							sizeof($1.a));
					  } else {
						bcopy(&$1.a, &nat->in_src[0],
							sizeof($1.a));
						bcopy(&$1.m, &nat->in_src[1],
							sizeof($1.a));
					  }
					  $$ = $1.v;
					}
	;

addr:	IPNY_ANY			{ yyexpectaddr = 0;
					  bzero(&$$.a, sizeof($$.a));
					  bzero(&$$.m, sizeof($$.a));
					  $$.v = nat->in_v;
					}
	| hostname			{ $$.a = $1.a;
					  $$.v = $1.v;
					  if ($$.v == 4) {
						$$.m.in4.s_addr = 0xffffffff;
					  } else {
						$$.m.i6[0] = 0xffffffff;
						$$.m.i6[1] = 0xffffffff;
						$$.m.i6[2] = 0xffffffff;
						$$.m.i6[3] = 0xffffffff;
					  }
					  yyexpectaddr = 0;
					}
	| hostname '/' YY_NUMBER	{ $$.a = $1.a;
					  if ($1.v == 0) {
						if ($1.a.in4.s_addr != 0)
							yyerror("invalid addr");
						if ($3 == 0 || $3 == 32)
							$1.v = 4;
						else if ($3 == 128)
							$1.v = 6;
						else
							yyerror("invalid mask");
						nat->in_v = $1.v;
					  }
					  ntomask($1.v, $3, (u_32_t *)&$$.m);
					  $$.a.i6[0] &= $$.m.i6[0];
					  $$.a.i6[1] &= $$.m.i6[1];
					  $$.a.i6[2] &= $$.m.i6[2];
					  $$.a.i6[3] &= $$.m.i6[3];
					  $$.v = $1.v;
					  yyexpectaddr = 0;
					}
	| hostname '/' ipaddr		{ if ($1.v != $3.v) {
						yyerror("1.address family "
							"mismatch");
					  }
					  $$.a = $1.a;
					  $$.m = $3.a;
					  $$.a.i6[0] &= $$.m.i6[0];
					  $$.a.i6[1] &= $$.m.i6[1];
					  $$.a.i6[2] &= $$.m.i6[2];
					  $$.a.i6[3] &= $$.m.i6[3];
					  $$.v = $1.v;
					  yyexpectaddr = 0;
					}
	| hostname '/' hexnumber	{ $$.a = $1.a;
					  $$.m.in4.s_addr = htonl($3);
					  $$.a.in4.s_addr &= $$.m.in4.s_addr;
					  $$.v = 4;
					}
	| hostname IPNY_MASK ipaddr	{ if ($1.v != $3.v) {
						yyerror("2.address family "
							"mismatch");
					  }
					  $$.a = $1.a;
					  $$.m = $3.a;
					  $$.a.i6[0] &= $$.m.i6[0];
					  $$.a.i6[1] &= $$.m.i6[1];
					  $$.a.i6[2] &= $$.m.i6[2];
					  $$.a.i6[3] &= $$.m.i6[3];
					  $$.v = $1.v;
					  yyexpectaddr = 0;
					}
	| hostname IPNY_MASK hexnumber	{ $$.a = $1.a;
					  $$.m.in4.s_addr = htonl($3);
					  $$.a.in4.s_addr &= $$.m.in4.s_addr;
					  $$.v = 4;
					}
	;

portstuff:
	compare portspec		{ $$.pc = $1; $$.p1 = $2; }
	| portspec range portspec	{ $$.pc = $2; $$.p1 = $1; $$.p2 = $3; }
	;

mapoptions:
	rr frag age mssclamp nattag setproto
	;

rdroptions:
	rr frag age sticky mssclamp rdrproxy nattag
	;

nattag:	| IPNY_TAG YY_STR		{ strncpy(nat->in_tag.ipt_tag, $2,
						  sizeof(nat->in_tag.ipt_tag));
					}

rr:	| IPNY_ROUNDROBIN		{ nat->in_flags |= IPN_ROUNDR; }
	;

frag:	| IPNY_FRAG			{ nat->in_flags |= IPN_FRAG; }
	;

age:	| IPNY_AGE YY_NUMBER			{ nat->in_age[0] = $2;
						  nat->in_age[1] = $2; }
	| IPNY_AGE YY_NUMBER '/' YY_NUMBER	{ nat->in_age[0] = $2;
						  nat->in_age[1] = $4; }
	;

sticky:	| IPNY_STICKY			{ if (!(nat->in_flags & IPN_ROUNDR) &&
					      !(nat->in_flags & IPN_SPLIT)) {
						fprintf(stderr,
		"'sticky' for use with round-robin/IP splitting only\n");
					  } else
						nat->in_flags |= IPN_STICKY;
					}
	;

mssclamp:
	| IPNY_MSSCLAMP YY_NUMBER		{ nat->in_mssclamp = $2; }
	;

tcpudp:	| IPNY_TCP			{ setnatproto(IPPROTO_TCP); }
	| IPNY_UDP			{ setnatproto(IPPROTO_UDP); }
	| IPNY_TCPUDP			{ nat->in_flags |= IPN_TCPUDP;
					  nat->in_p = 0;
					}
	| IPNY_TCP '/' IPNY_UDP		{ nat->in_flags |= IPN_TCPUDP;
					  nat->in_p = 0;
					}
	;

rdrproxy:
	IPNY_PROXY YY_STR
					{ strncpy(nat->in_plabel, $2,
						  sizeof(nat->in_plabel));
					  nat->in_dport = nat->in_pnext;
					  nat->in_dport = htons(nat->in_dport);
					  free($2);
					}
	| proxy				{ if (nat->in_plabel[0] != '\0') {
						  nat->in_pmin = nat->in_dport;
						  nat->in_pmax = nat->in_pmin;
						  nat->in_pnext = nat->in_pmin;
					  }
					}
	;

proto:	YY_NUMBER			{ $$ = $1; }
	| IPNY_TCP			{ $$ = IPPROTO_TCP; }
	| IPNY_UDP			{ $$ = IPPROTO_UDP; }
	| YY_STR			{ $$ = getproto($1); free($1); }
	;

hexnumber:
	YY_HEX				{ $$ = $1; }
	;

hostname:
	YY_STR				{ i6addr_t addr;
					  if (gethost($1, &addr, 0) == 0) {
						$$.a = addr;
						$$.v = 4;
					  } else
					  if (gethost($1, &addr, 1) == 0) {
						$$.a = addr;
						$$.v = 6;
					  } else {
						yyerror("Unknown hostname");
					  }
					  if ($$.v != 0)
						nat->in_v = $$.v;
					  free($1);
					}
	| YY_NUMBER			{ bzero(&$$.a, sizeof($$.a));
					  $$.a.in4.s_addr = htonl($1);
					  if ($$.a.in4.s_addr != 0)
						$$.v = 4;
					  else
						$$.v = nat->in_v;
					  if ($$.v != 0)
						nat->in_v = $$.v;
					}
	| ipv4				{ $$ = $1;
					  nat->in_v = 4;
					}
	| YY_IPV6			{ $$.a = $1;
					  $$.v = 6;
					  nat->in_v = 6;
					}
	| YY_NUMBER YY_IPV6		{ $$.a = $2;
					  $$.v = 6;
					}
	;

compare:
	'='				{ $$ = FR_EQUAL; }
	| YY_CMP_EQ			{ $$ = FR_EQUAL; }
	| YY_CMP_NE			{ $$ = FR_NEQUAL; }
	| YY_CMP_LT			{ $$ = FR_LESST; }
	| YY_CMP_LE			{ $$ = FR_LESSTE; }
	| YY_CMP_GT			{ $$ = FR_GREATERT; }
	| YY_CMP_GE			{ $$ = FR_GREATERTE; }

range:
	YY_RANGE_OUT			{ $$ = FR_OUTRANGE; }
	| YY_RANGE_IN			{ $$ = FR_INRANGE; }
	;

ipaddr:	ipv4				{ $$ = $1; }
	| YY_IPV6			{ $$.a = $1;
					  $$.v = 6;
					}
	;

ipv4:	YY_NUMBER '.' YY_NUMBER '.' YY_NUMBER '.' YY_NUMBER
		{ if ($1 > 255 || $3 > 255 || $5 > 255 || $7 > 255) {
			yyerror("Invalid octet string for IP address");
			return 0;
		  }
		  $$.a.in4.s_addr = ($1 << 24) | ($3 << 16) | ($5 << 8) | $7;
		  $$.a.in4.s_addr = htonl($$.a.in4.s_addr);
		  $$.v = 4;
		}
	;

%%


static	wordtab_t	yywords[] = {
	{ "age",	IPNY_AGE },
	{ "any",	IPNY_ANY },
	{ "auto",	IPNY_AUTO },
	{ "bimap",	IPNY_BIMAP },
	{ "frag",	IPNY_FRAG },
	{ "from",	IPNY_FROM },
	{ "icmpidmap",	IPNY_ICMPIDMAP },
	{ "mask",	IPNY_MASK },
	{ "map",	IPNY_MAP },
	{ "map-block",	IPNY_MAPBLOCK },
	{ "mssclamp",	IPNY_MSSCLAMP },
	{ "netmask",	IPNY_MASK },
	{ "port",	IPNY_PORT },
	{ "portmap",	IPNY_PORTMAP },
	{ "ports",	IPNY_PORTS },
	{ "proxy",	IPNY_PROXY },
	{ "range",	IPNY_RANGE },
	{ "rdr",	IPNY_RDR },
	{ "round-robin",IPNY_ROUNDROBIN },
	{ "sequential",	IPNY_SEQUENTIAL },
	{ "sticky",	IPNY_STICKY },
	{ "tag",	IPNY_TAG },
	{ "tcp",	IPNY_TCP },
	{ "tcpudp",	IPNY_TCPUDP },
	{ "to",		IPNY_TO },
	{ "udp",	IPNY_UDP },
	{ "-",		'-' },
	{ "->",		IPNY_TLATE },
	{ "eq",		YY_CMP_EQ },
	{ "ne",		YY_CMP_NE },
	{ "lt",		YY_CMP_LT },
	{ "gt",		YY_CMP_GT },
	{ "le",		YY_CMP_LE },
	{ "ge",		YY_CMP_GE },
	{ NULL,		0 }
};


int ipnat_parsefile(fd, addfunc, ioctlfunc, filename)
int fd;
addfunc_t addfunc;
ioctlfunc_t ioctlfunc;
char *filename;
{
	FILE *fp = NULL;
	char *s;

	(void) yysettab(yywords);

	s = getenv("YYDEBUG");
	if (s)
		yydebug = atoi(s);
	else
		yydebug = 0;

	if (strcmp(filename, "-")) {
		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr, "fopen(%s) failed: %s\n", filename,
				STRERROR(errno));
			return -1;
		}
	} else
		fp = stdin;

	while (ipnat_parsesome(fd, addfunc, ioctlfunc, fp) == 1)
		;
	if (fp != NULL)
		fclose(fp);
	return 0;
}


int ipnat_parsesome(fd, addfunc, ioctlfunc, fp)
int fd;
addfunc_t addfunc;
ioctlfunc_t ioctlfunc;
FILE *fp;
{
	char *s;
	int i;

	yylineNum = 1;

	natfd = fd;
	nataddfunc = addfunc;
	natioctlfunc = ioctlfunc;

	if (feof(fp))
		return 0;
	i = fgetc(fp);
	if (i == EOF)
		return 0;
	if (ungetc(i, fp) == EOF)
		return 0;
	if (feof(fp))
		return 0;
	s = getenv("YYDEBUG");
	if (s)
		yydebug = atoi(s);
	else
		yydebug = 0;

	yyin = fp;
	yyparse();
	return 1;
}


static void newnatrule()
{
	ipnat_t *n;

	n = calloc(1, sizeof(*n));
	if (n == NULL)
		return;

	if (nat == NULL)
		nattop = nat = n;
	else {
		nat->in_next = n;
		nat = n;
	}
}


static void setnatproto(p)
int p;
{
	nat->in_p = p;

	switch (p)
	{
	case IPPROTO_TCP :
		nat->in_flags |= IPN_TCP;
		nat->in_flags &= ~IPN_UDP;
		break;
	case IPPROTO_UDP :
		nat->in_flags |= IPN_UDP;
		nat->in_flags &= ~IPN_TCP;
		break;
	case IPPROTO_ICMP :
		nat->in_flags &= ~IPN_TCPUDP;
		if (!(nat->in_flags & IPN_ICMPQUERY)) {
			nat->in_dcmp = 0;
			nat->in_scmp = 0;
			nat->in_pmin = 0;
			nat->in_pmax = 0;
			nat->in_pnext = 0;
		}
		break;
	default :
		if ((nat->in_redir & NAT_MAPBLK) == 0) {
			/* Only reset dcmp/scmp in case dport/sport not set */
			if (0 == nat->in_tuc.ftu_dport)
				nat->in_dcmp = 0;
			if (0 == nat->in_tuc.ftu_sport)
				nat->in_scmp = 0;
			nat->in_pmin = 0;
			nat->in_pmax = 0;
			nat->in_pnext = 0;
			nat->in_flags &= ~IPN_TCPUDP;
		}
		break;
	}

	if ((nat->in_flags & (IPN_TCPUDP|IPN_FIXEDDPORT)) == IPN_FIXEDDPORT)
		nat->in_flags &= ~IPN_FIXEDDPORT;
}


void ipnat_addrule(fd, ioctlfunc, ptr)
int fd;
ioctlfunc_t ioctlfunc;
void *ptr;
{
	ioctlcmd_t add, del;
	ipfobj_t obj;
	ipnat_t *ipn;

	ipn = ptr;
	bzero((char *)&obj, sizeof(obj));
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(ipnat_t);
	obj.ipfo_type = IPFOBJ_IPNAT;
	obj.ipfo_ptr = ptr;
	add = 0;
	del = 0;

	if ((opts & OPT_DONOTHING) != 0)
		fd = -1;

	if (opts & OPT_ZERORULEST) {
		add = SIOCZRLST;
	} else if (opts & OPT_INACTIVE) {
		add = SIOCADNAT;
		del = SIOCRMNAT;
	} else {
		add = SIOCADNAT;
		del = SIOCRMNAT;
	}

	if (ipn && (opts & OPT_VERBOSE))
		printnat(ipn, opts);

	if (opts & OPT_DEBUG)
		binprint(ipn, sizeof(*ipn));

	if ((opts & OPT_ZERORULEST) != 0) {
		if ((*ioctlfunc)(fd, add, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(SIOCZRLST)");
			}
		} else {
#ifdef	USE_QUAD_T
/*
			printf("hits %qd bytes %qd ",
				(long long)fr->fr_hits,
				(long long)fr->fr_bytes);
*/
#else
/*
			printf("hits %ld bytes %ld ",
				fr->fr_hits, fr->fr_bytes);
*/
#endif
			printnat(ipn, opts);
		}
	} else if ((opts & OPT_REMOVE) != 0) {
		if ((*ioctlfunc)(fd, del, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(delete nat rule)");
			}
		}
	} else {
		if ((*ioctlfunc)(fd, add, (void *)&obj) == -1) {
			if ((opts & OPT_DONOTHING) == 0) {
				fprintf(stderr, "%d:", yylineNum);
				perror("ioctl(add/insert nat rule)");
			}
		}
	}
}

