/*
 * Copyright 2001, QNX Software Systems Ltd. All Rights Reserved
 *
 * This source code has been published by QNX Software Systems Ltd. (QSSL).
 * However, any use, reproduction, modification, distribution or transfer of
 * this software, or any software which includes or is based upon any of this
 * code, is only permitted under the terms of the QNX Open Community License
 * version 1.0 (see licensing.qnx.com for details) or as otherwise expressly
 * authorized by a written license agreement from QSSL. For more information,
 * please email licensing@qnx.com.
 *
 * For more details, see QNX_OCL.txt provided with this distribution.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Simple H.323 proxy
 *
 *      by xtang@canada.com
 *	ported to ipfilter 3.4.20 by Michael Grant mg-ipf@grant.org
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if __FreeBSD_version >= 220000 && defined(_KERNEL)
# include <sys/fcntl.h>
# include <sys/filio.h>
#else
# ifndef linux
#  include <sys/ioctl.h>
# endif
#endif

#define IPF_H323_PROXY

typedef struct ifs_h323pxy {
	frentry_t	h323_fr;
	int		h323_proxy_init;
} ifs_h323pxy_t;

int  ippr_h323_init __P((void **, ipf_stack_t *));
void  ippr_h323_fini __P((void **, ipf_stack_t *));
int  ippr_h323_new __P((fr_info_t *, ap_session_t *, nat_t *, void *));
void ippr_h323_del __P((ap_session_t *, void *, ipf_stack_t *));
int  ippr_h323_out __P((fr_info_t *, ap_session_t *, nat_t *, void *));
int  ippr_h323_in __P((fr_info_t *, ap_session_t *, nat_t *, void *));

int  ippr_h245_new __P((fr_info_t *, ap_session_t *, nat_t *, void *));
int  ippr_h245_out __P((fr_info_t *, ap_session_t *, nat_t *, void *));
int  ippr_h245_in __P((fr_info_t *, ap_session_t *, nat_t *, void *));

static int find_port __P((int, caddr_t, int datlen, int *, u_short *));


static int find_port(ipaddr, data, datlen, off, port)
int ipaddr;
caddr_t data;
int datlen, *off;
unsigned short *port;
{
	u_32_t addr, netaddr;
	u_char *dp;
	int offset;

	if (datlen < 6)
		return -1;
	
	*port = 0;
	offset = *off;
	dp = (u_char *)data;
	netaddr = ntohl(ipaddr);

	for (offset = 0; offset <= datlen - 6; offset++, dp++) {
		addr = (dp[0] << 24) | (dp[1] << 16) | (dp[2] << 8) | dp[3];
		if (netaddr == addr)
		{
			*port = (*(dp + 4) << 8) | *(dp + 5);
			break;
		}
	}
	*off = offset;
  	return (offset > datlen - 6) ? -1 : 0;
}

/*
 * Initialize local structures.
 */
/*ARGSUSED*/
int ippr_h323_init(private, ifs)
void **private;
ipf_stack_t *ifs;
{
	ifs_h323pxy_t *ifsh323;

	KMALLOC(ifsh323, ifs_h323pxy_t *);
	if (ifsh323 == NULL)
		return -1;

	ifsh323->h323_fr.fr_ref = 1;
	ifsh323->h323_fr.fr_flags = FR_INQUE|FR_PASS|FR_QUICK|FR_KEEPSTATE;
	MUTEX_INIT(&ifsh323->h323_fr.fr_lock, "H323 proxy rule lock");
	ifsh323->h323_proxy_init = 1;

	*private = (void *)ifsh323;

	return 0;
}


/*ARGSUSED*/
void ippr_h323_fini(private, ifs)
void **private;
ipf_stack_t *ifs;
{
	ifs_h323pxy_t *ifsh323 = *((ifs_h323pxy_t **)private);

	if (ifsh323->h323_proxy_init == 1) {
		MUTEX_DESTROY(&ifsh323->h323_fr.fr_lock);
		ifsh323->h323_proxy_init = 0;
	}

	KFREE(ifsh323);
	*private = NULL;
}

/*ARGSUSED*/
int ippr_h323_new(fin, aps, nat, private)
fr_info_t *fin;
ap_session_t *aps;
nat_t *nat;
void *private;
{
	fin = fin;	/* LINT */
	nat = nat;	/* LINT */

	aps->aps_data = NULL;
	aps->aps_psiz = 0;

	return 0;
}

/*ARGSUSED*/
void ippr_h323_del(aps, private, ifs)
ap_session_t *aps;
void *private;
ipf_stack_t *ifs;
{
	int i;
	ipnat_t *ipn;
	
	if (aps->aps_data) {
		for (i = 0, ipn = aps->aps_data;
		     i < (aps->aps_psiz / sizeof(ipnat_t));
		     i++, ipn = (ipnat_t *)((char *)ipn + sizeof(*ipn)))
		{
			/*
			 * Check the comment in ippr_h323_in() function,
			 * just above fr_nat_ioctl() call.
			 * We are lucky here because this function is not
			 * called with ipf_nat locked.
			 */
			if (fr_nat_ioctl((caddr_t)ipn, SIOCRMNAT, NAT_SYSSPACE|
				         NAT_LOCKHELD|FWRITE, 0, NULL, ifs) == -1) {
				/*EMPTY*/;
				/* log the error */
			}
		}
		KFREES(aps->aps_data, aps->aps_psiz);
		/* avoid double free */
		aps->aps_data = NULL;
		aps->aps_psiz = 0;
	}
	return;
}


/*ARGSUSED*/
int ippr_h323_in(fin, aps, nat, private)
fr_info_t *fin;
ap_session_t *aps;
nat_t *nat;
void *private;
{
	int ipaddr, off, datlen;
	unsigned short port;
	caddr_t data;
	tcphdr_t *tcp;
	ip_t *ip;
	ipf_stack_t *ifs = fin->fin_ifs;

	ip = fin->fin_ip;
	tcp = (tcphdr_t *)fin->fin_dp;
	ipaddr = ip->ip_src.s_addr;
	
	data = (caddr_t)tcp + (TCP_OFF(tcp) << 2);
	datlen = fin->fin_dlen - (TCP_OFF(tcp) << 2);
	if (find_port(ipaddr, data, datlen, &off, &port) == 0) {
		ipnat_t *ipn;
		char *newarray;

		/* setup a nat rule to set a h245 proxy on tcp-port "port"
		 * it's like:
		 *   map <if> <inter_ip>/<mask> -> <gate_ip>/<mask> proxy port <port> <port>/tcp
		 */
		KMALLOCS(newarray, char *, aps->aps_psiz + sizeof(*ipn));
		if (newarray == NULL) {
			return -1;
		}
		ipn = (ipnat_t *)&newarray[aps->aps_psiz];
		bcopy((caddr_t)nat->nat_ptr, (caddr_t)ipn, sizeof(ipnat_t));
		(void) strncpy(ipn->in_plabel, "h245", APR_LABELLEN);
		
		ipn->in_inip = nat->nat_inip.s_addr;
		ipn->in_inmsk = 0xffffffff;
		ipn->in_dport = htons(port);
		/*
		 * we got a problem here. we need to call fr_nat_ioctl() to add
		 * the h245 proxy rule, but since we already hold (READ locked)
		 * the nat table rwlock (ipf_nat), if we go into fr_nat_ioctl(),
		 * it will try to WRITE lock it. This will causing dead lock
		 * on RTP.
		 *
		 * The quick & dirty solution here is release the read lock,
		 * call fr_nat_ioctl() and re-lock it.
		 * A (maybe better) solution is do a UPGRADE(), and instead
		 * of calling fr_nat_ioctl(), we add the nat rule ourself.
		 */
		RWLOCK_EXIT(&ifs->ifs_ipf_nat);
		if (fr_nat_ioctl((caddr_t)ipn, SIOCADNAT,
				 NAT_SYSSPACE|FWRITE, 0, NULL, ifs) == -1) {
			READ_ENTER(&ifs->ifs_ipf_nat);
			return -1;
		}
		READ_ENTER(&ifs->ifs_ipf_nat);
		if (aps->aps_data != NULL && aps->aps_psiz > 0) {
			bcopy(aps->aps_data, newarray, aps->aps_psiz);
			KFREES(aps->aps_data, aps->aps_psiz);
		}
		aps->aps_data = newarray;
		aps->aps_psiz += sizeof(*ipn);
	}
	return 0;
}


/*ARGSUSED*/
int ippr_h245_new(fin, aps, nat, private)
fr_info_t *fin;
ap_session_t *aps;
nat_t *nat;
void *private;
{
	fin = fin;	/* LINT */
	nat = nat;	/* LINT */

	aps->aps_data = NULL;
	aps->aps_psiz = 0;
	return 0;
}


/*ARGSUSED*/
int ippr_h245_out(fin, aps, nat, private)
fr_info_t *fin;
ap_session_t *aps;
nat_t *nat;
void *private;
{
	int ipaddr, off, datlen;
	tcphdr_t *tcp;
	caddr_t data;
	u_short port;
	ip_t *ip;
	ipf_stack_t *ifs = fin->fin_ifs;

	aps = aps;	/* LINT */

	ip = fin->fin_ip;
	tcp = (tcphdr_t *)fin->fin_dp;
	ipaddr = nat->nat_inip.s_addr;
	data = (caddr_t)tcp + (TCP_OFF(tcp) << 2);
	datlen = fin->fin_dlen - (TCP_OFF(tcp) << 2);
	if (find_port(ipaddr, data, datlen, &off, &port) == 0) {
		fr_info_t fi;
		nat_t     *nat2;

/*		port = htons(port); */
		nat2 = nat_outlookup(fin->fin_ifp, IPN_UDP, IPPROTO_UDP,
				    ip->ip_src, ip->ip_dst);
		if (nat2 == NULL) {
			struct ip newip;
			struct udphdr udp;
			
			bcopy((caddr_t)ip, (caddr_t)&newip, sizeof(newip));
			newip.ip_len = fin->fin_hlen + sizeof(udp);
			newip.ip_p = IPPROTO_UDP;
			newip.ip_src = nat->nat_inip;
			
			bzero((char *)&udp, sizeof(udp));
			udp.uh_sport = port;
			
			bcopy((caddr_t)fin, (caddr_t)&fi, sizeof(fi));
			fi.fin_fi.fi_p = IPPROTO_UDP;
			fi.fin_data[0] = port;
			fi.fin_data[1] = 0;
			fi.fin_dp = (char *)&udp;

			nat2 = nat_new(&fi, nat->nat_ptr, NULL,
				       NAT_SLAVE|IPN_UDP|SI_W_DPORT,
				       NAT_OUTBOUND);
			if (nat2 != NULL) {
				(void) nat_proto(&fi, nat2, IPN_UDP);
				nat_update(&fi, nat2, nat2->nat_ptr);

				nat2->nat_ptr->in_hits++;
#ifdef	IPFILTER_LOG
				nat_log(nat2, (u_int)(nat->nat_ptr->in_redir),
					ifs);
#endif
				bcopy((caddr_t)&ip->ip_src.s_addr,
				      data + off, 4);
				bcopy((caddr_t)&nat2->nat_outport,
				      data + off + 4, 2);
			}
		}
	}
	return 0;
}
