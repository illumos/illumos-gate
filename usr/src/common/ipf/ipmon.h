/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * @(#)ip_fil.h	1.35 6/5/96
 * $Id: ipmon.h,v 2.6 2002/12/27 16:07:15 darrenr Exp $
 */


typedef	struct	action	{
	struct	action	*a_next;
	int	ac_mflag;	/* collection of things to compare */
	int	ac_direction;
	char	ac_group[FR_GROUPLEN];
	int	ac_proto;
	int	ac_rule;
	int	ac_packet;
	int	ac_second;
	int	ac_result;
	int	ac_tag;
	u_32_t	ac_sip;
	u_32_t	ac_smsk;	
	u_32_t	ac_dip;
	u_32_t	ac_dmsk;	
	u_short	ac_sport;
	u_short	ac_dport;
	char	*ac_exec;
	char	*ac_run;
	char	*ac_iface;
	/*
	 * used with ac_packet/ac_second
	 */
	struct	timeval	ac_last;
	int	ac_pktcnt;
} action_t;

#define	ac_lastsec	ac_last.tv_sec
#define	ac_lastusec	ac_last.tv_usec

#define	IPMAC_DIRECTION	0x0001
#define	IPMAC_DSTIP	0x0002
#define	IPMAC_DSTPORT	0x0004
#define	IPMAC_EVERY	0x0008
#define	IPMAC_EXECUTE	0x0010
#define	IPMAC_GROUP	0x0020
#define	IPMAC_INTERFACE	0x0040
#define	IPMAC_PROTOCOL	0x0080
#define	IPMAC_RESULT	0x0100
#define	IPMAC_RULE	0x0200
#define	IPMAC_SRCIP	0x0400
#define	IPMAC_SRCPORT	0x0800
#define	IPMAC_TAG	0x1000

#define	IPMR_BLOCK	1
#define	IPMR_PASS	2
#define	IPMR_NOMATCH	3
#define	IPMR_SHORT	4
#define	IPMR_LOG	5

#define	OPT_SYSLOG	0x001
#define	OPT_RESOLVE	0x002
#define	OPT_HEXBODY	0x004
#define	OPT_VERBOSE	0x008
#define	OPT_HEXHDR	0x010
#define	OPT_TAIL	0x020
#define	OPT_NAT		0x080
#define	OPT_STATE	0x100
#define	OPT_FILTER	0x200
#define	OPT_PORTNUM	0x400
#define	OPT_LOGALL	(OPT_NAT|OPT_STATE|OPT_FILTER)

#define	HOSTNAME_V4(a,b)	hostname((a), 4, (u_32_t *)&(b))

#ifndef	LOGFAC
#define	LOGFAC	LOG_LOCAL0
#endif

extern	int	load_config __P((char *));
extern	void	dumphex __P((FILE *, int, char *, int));
extern	void	check_action __P((char *, int, char *));
extern	char	*getword __P((int));
