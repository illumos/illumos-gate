/*
 * Copyright (C) 2001-2003 by Darren Reed
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Simple ISAKMP transparent proxy for in-kernel use.  For use with the NAT
 * code.
 *
 * $Id: ip_ipsec_pxy.c,v 2.20.2.7 2005/07/15 21:56:50 darrenr Exp $
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#define	IPF_IPSEC_PROXY

typedef struct ifs_ipsecpxy {
	frentry_t		ipsecfr;
	ipftq_t			*ipsecnattqe;
	ipftq_t			*ipsecstatetqe;
	char			ipsec_buffer[1500];
	int			ipsec_proxy_init;
	int			ipsec_proxy_ttl;
} ifs_ipsecpxy_t;

int ippr_ipsec_init __P((void **, ipf_stack_t *));
void ippr_ipsec_fini __P((void **, ipf_stack_t *));
int ippr_ipsec_new __P((fr_info_t *, ap_session_t *, nat_t *, void *));
void ippr_ipsec_del __P((ap_session_t *, void *, ipf_stack_t *));
int ippr_ipsec_inout __P((fr_info_t *, ap_session_t *, nat_t *, void *));
int ippr_ipsec_match __P((fr_info_t *, ap_session_t *, nat_t *, void *));

/*
 * IPSec application proxy initialization.
 */
int ippr_ipsec_init(private, ifs)
void **private;
ipf_stack_t *ifs;
{
	ifs_ipsecpxy_t *ifsipsec;

	KMALLOC(ifsipsec, ifs_ipsecpxy_t *);
	if (ifsipsec == NULL)
		return -1;

	bzero((char *)&ifsipsec->ipsecfr, sizeof(ifsipsec->ipsecfr));
	ifsipsec->ipsecfr.fr_ref = 1;
	ifsipsec->ipsecfr.fr_flags = FR_OUTQUE|FR_PASS|FR_QUICK|FR_KEEPSTATE;
	MUTEX_INIT(&ifsipsec->ipsecfr.fr_lock, "IPsec proxy rule lock");
	ifsipsec->ipsec_proxy_init = 1;
	ifsipsec->ipsec_proxy_ttl = 60;

	ifsipsec->ipsecnattqe = fr_addtimeoutqueue(&ifs->ifs_nat_utqe, ifsipsec->ipsec_proxy_ttl, ifs);
	if (ifsipsec->ipsecnattqe == NULL) {
		MUTEX_DESTROY(&ifsipsec->ipsecfr.fr_lock);
		KFREE(ifsipsec);
		return -1;
	}
	ifsipsec->ipsecstatetqe = fr_addtimeoutqueue(&ifs->ifs_ips_utqe, ifsipsec->ipsec_proxy_ttl, ifs);
	if (ifsipsec->ipsecstatetqe == NULL) {
		if (fr_deletetimeoutqueue(ifsipsec->ipsecnattqe) == 0)
			fr_freetimeoutqueue(ifsipsec->ipsecnattqe, ifs);
		ifsipsec->ipsecnattqe = NULL;
		MUTEX_DESTROY(&ifsipsec->ipsecfr.fr_lock);
		KFREE(ifsipsec);
		return -1;
	}

	ifsipsec->ipsecnattqe->ifq_flags |= IFQF_PROXY;
	ifsipsec->ipsecstatetqe->ifq_flags |= IFQF_PROXY;

	ifsipsec->ipsecfr.fr_age[0] = ifsipsec->ipsec_proxy_ttl;
	ifsipsec->ipsecfr.fr_age[1] = ifsipsec->ipsec_proxy_ttl;

	*private = (void *)ifsipsec;

	return 0;
}


void ippr_ipsec_fini(private, ifs)
void **private;
ipf_stack_t *ifs;
{
	ifs_ipsecpxy_t *ifsipsec = *((ifs_ipsecpxy_t **)private);

	if (ifsipsec->ipsecnattqe != NULL) {
		if (fr_deletetimeoutqueue(ifsipsec->ipsecnattqe) == 0)
			fr_freetimeoutqueue(ifsipsec->ipsecnattqe, ifs);
	}
	ifsipsec->ipsecnattqe = NULL;
	if (ifsipsec->ipsecstatetqe != NULL) {
		if (fr_deletetimeoutqueue(ifsipsec->ipsecstatetqe) == 0)
			fr_freetimeoutqueue(ifsipsec->ipsecstatetqe, ifs);
	}
	ifsipsec->ipsecstatetqe = NULL;

	if (ifsipsec->ipsec_proxy_init == 1) {
		MUTEX_DESTROY(&ifsipsec->ipsecfr.fr_lock);
		ifsipsec->ipsec_proxy_init = 0;
	}

	KFREE(ifsipsec);
	*private = NULL;
}


/*
 * Setup for a new IPSEC proxy.
 */
int ippr_ipsec_new(fin, aps, nat, private)
fr_info_t *fin;
ap_session_t *aps;
nat_t *nat;
void *private;
{
	ipsec_pxy_t *ipsec;
	fr_info_t fi;
	ipnat_t *ipn;
	char *ptr;
	int p, off, dlen, ttl;
	mb_t *m;
	ip_t *ip;
	ipf_stack_t *ifs = fin->fin_ifs;
	ifs_ipsecpxy_t *ifsipsec = (ifs_ipsecpxy_t *)private;

	off = fin->fin_plen - fin->fin_dlen + fin->fin_ipoff;
	bzero(ifsipsec->ipsec_buffer, sizeof(ifsipsec->ipsec_buffer));
	ip = fin->fin_ip;
	m = fin->fin_m;

	dlen = M_LEN(m) - off;
	if (dlen < 16)
		return -1;
	COPYDATA(m, off, MIN(sizeof(ifsipsec->ipsec_buffer), dlen),
		 ifsipsec->ipsec_buffer);

	if (nat_outlookup(fin, 0, IPPROTO_ESP, nat->nat_inip,
			  ip->ip_dst) != NULL)
		return -1;

	aps->aps_psiz = sizeof(*ipsec);
	KMALLOCS(aps->aps_data, ipsec_pxy_t *, sizeof(*ipsec));
	if (aps->aps_data == NULL)
		return -1;

	ipsec = aps->aps_data;
	bzero((char *)ipsec, sizeof(*ipsec));

	/*
	 * Create NAT rule against which the tunnel/transport mapping is
	 * created.  This is required because the current NAT rule does not
	 * describe ESP but UDP instead.
	 */
	ipn = &ipsec->ipsc_rule;
	ttl = IPF_TTLVAL(ifsipsec->ipsecnattqe->ifq_ttl);
	ipn->in_tqehead[0] = fr_addtimeoutqueue(&ifs->ifs_nat_utqe, ttl, ifs);
	ipn->in_tqehead[1] = fr_addtimeoutqueue(&ifs->ifs_nat_utqe, ttl, ifs);
	ipn->in_ifps[0] = fin->fin_ifp;
	ipn->in_apr = NULL;
	ipn->in_use = 1;
	ipn->in_hits = 1;
	ipn->in_nip = ntohl(nat->nat_outip.s_addr);
	ipn->in_ippip = 1;
	ipn->in_inip = nat->nat_inip.s_addr;
	ipn->in_inmsk = 0xffffffff;
	ipn->in_outip = fin->fin_saddr;
	ipn->in_outmsk = nat->nat_outip.s_addr;
	ipn->in_srcip = fin->fin_saddr;
	ipn->in_srcmsk = 0xffffffff;
	ipn->in_redir = NAT_MAP;
	bcopy(nat->nat_ptr->in_ifnames[0], ipn->in_ifnames[0],
	      sizeof(ipn->in_ifnames[0]));
	ipn->in_p = IPPROTO_ESP;

	bcopy((char *)fin, (char *)&fi, sizeof(fi));
	fi.fin_fi.fi_p = IPPROTO_ESP;
	fi.fin_fr = &ifsipsec->ipsecfr;
	fi.fin_data[0] = 0;
	fi.fin_data[1] = 0;
	p = ip->ip_p;
	ip->ip_p = IPPROTO_ESP;
	fi.fin_flx &= ~(FI_TCPUDP|FI_STATE|FI_FRAG);
	fi.fin_flx |= FI_IGNORE;

	ptr = ifsipsec->ipsec_buffer;
	bcopy(ptr, (char *)ipsec->ipsc_icookie, sizeof(ipsec_cookie_t));
	ptr += sizeof(ipsec_cookie_t);
	bcopy(ptr, (char *)ipsec->ipsc_rcookie, sizeof(ipsec_cookie_t));
	/*
	 * The responder cookie should only be non-zero if the initiator
	 * cookie is non-zero.  Therefore, it is safe to assume(!) that the
	 * cookies are both set after copying if the responder is non-zero.
	 */
	if ((ipsec->ipsc_rcookie[0]|ipsec->ipsc_rcookie[1]) != 0)
		ipsec->ipsc_rckset = 1;

	ipsec->ipsc_nat = nat_new(&fi, ipn, &ipsec->ipsc_nat,
				  NAT_SLAVE|SI_WILDP, NAT_OUTBOUND);
	if (ipsec->ipsc_nat != NULL) {
		(void) nat_proto(&fi, ipsec->ipsc_nat, 0);
		nat_update(&fi, ipsec->ipsc_nat, ipn);

		fi.fin_data[0] = 0;
		fi.fin_data[1] = 0;
		ipsec->ipsc_state = fr_addstate(&fi, &ipsec->ipsc_state,
						SI_WILDP);
	}
	ip->ip_p = p & 0xff;
	return 0;
}


/*
 * For outgoing IKE packets.  refresh timeouts for NAT & state entries, if
 * we can.  If they have disappeared, recreate them.
 */
int ippr_ipsec_inout(fin, aps, nat, private)
fr_info_t *fin;
ap_session_t *aps;
nat_t *nat;
void *private;
{
	ipsec_pxy_t *ipsec;
	fr_info_t fi;
	ip_t *ip;
	int p;
	ipf_stack_t *ifs = fin->fin_ifs;
	ifs_ipsecpxy_t *ifsipsec = (ifs_ipsecpxy_t *)private;

	if ((fin->fin_out == 1) && (nat->nat_dir == NAT_INBOUND))
		return 0;

	if ((fin->fin_out == 0) && (nat->nat_dir == NAT_OUTBOUND))
		return 0;

	ipsec = aps->aps_data;

	if (ipsec != NULL) {
		ip = fin->fin_ip;
		p = ip->ip_p;

		if ((ipsec->ipsc_nat == NULL) || (ipsec->ipsc_state == NULL)) {
			bcopy((char *)fin, (char *)&fi, sizeof(fi));
			fi.fin_fi.fi_p = IPPROTO_ESP;
			fi.fin_fr = &ifsipsec->ipsecfr;
			fi.fin_data[0] = 0;
			fi.fin_data[1] = 0;
			ip->ip_p = IPPROTO_ESP;
			fi.fin_flx &= ~(FI_TCPUDP|FI_STATE|FI_FRAG);
			fi.fin_flx |= FI_IGNORE;
		}

		/*
		 * Update NAT timeout/create NAT if missing.
		 */
		if (ipsec->ipsc_nat != NULL)
			fr_queueback(&ipsec->ipsc_nat->nat_tqe, ifs);
		else {
			ipsec->ipsc_nat = nat_new(&fi, &ipsec->ipsc_rule,
						  &ipsec->ipsc_nat,
						  NAT_SLAVE|SI_WILDP,
						  nat->nat_dir);
			if (ipsec->ipsc_nat != NULL) {
				(void) nat_proto(&fi, ipsec->ipsc_nat, 0);
				nat_update(&fi, ipsec->ipsc_nat,
					   &ipsec->ipsc_rule);
			}
		}

		/*
		 * Update state timeout/create state if missing.
		 */
		READ_ENTER(&ifs->ifs_ipf_state);
		if (ipsec->ipsc_state != NULL) {
			fr_queueback(&ipsec->ipsc_state->is_sti, ifs);
			ipsec->ipsc_state->is_die = nat->nat_age;
			RWLOCK_EXIT(&ifs->ifs_ipf_state);
		} else {
			RWLOCK_EXIT(&ifs->ifs_ipf_state);
			fi.fin_data[0] = 0;
			fi.fin_data[1] = 0;
			ipsec->ipsc_state = fr_addstate(&fi,
							&ipsec->ipsc_state,
							SI_WILDP);
		}
		ip->ip_p = p;
	}
	return 0;
}


/*
 * This extends the NAT matching to be based on the cookies associated with
 * a session and found at the front of IKE packets.  The cookies are always
 * in the same order (not reversed depending on packet flow direction as with
 * UDP/TCP port numbers).
 */
/*ARGSUSED*/
int ippr_ipsec_match(fin, aps, nat, private)
fr_info_t *fin;
ap_session_t *aps;
nat_t *nat;
void *private;
{
	ipsec_pxy_t *ipsec;
	u_32_t cookies[4];
	mb_t *m;
	int off;

	nat = nat;	/* LINT */

	if ((fin->fin_dlen < sizeof(cookies)) || (fin->fin_flx & FI_FRAG))
		return -1;

	off = fin->fin_plen - fin->fin_dlen + fin->fin_ipoff;
	ipsec = aps->aps_data;
	m = fin->fin_m;
	COPYDATA(m, off, sizeof(cookies), (char *)cookies);

	if ((cookies[0] != ipsec->ipsc_icookie[0]) ||
	    (cookies[1] != ipsec->ipsc_icookie[1]))
		return -1;

	if (ipsec->ipsc_rckset == 0) {
		if ((cookies[2]|cookies[3]) == 0) {
			return 0;
		}
		ipsec->ipsc_rckset = 1;
		ipsec->ipsc_rcookie[0] = cookies[2];
		ipsec->ipsc_rcookie[1] = cookies[3];
		return 0;
	}

	if ((cookies[2] != ipsec->ipsc_rcookie[0]) ||
	    (cookies[3] != ipsec->ipsc_rcookie[1]))
		return -1;
	return 0;
}


/*
 * clean up after ourselves.
 */
/*ARGSUSED*/
void ippr_ipsec_del(aps, private, ifs)
ap_session_t *aps;
void *private;
ipf_stack_t *ifs;
{
	ipsec_pxy_t *ipsec;

	ipsec = aps->aps_data;

	if (ipsec != NULL) {
		/*
		 * Don't bother changing any of the NAT structure details,
		 * *_del() is on a callback from aps_free(), from nat_delete()
		 */

		READ_ENTER(&ifs->ifs_ipf_state);
		if (ipsec->ipsc_state != NULL) {
			ipsec->ipsc_state->is_die = ifs->ifs_fr_ticks + 1;
			ipsec->ipsc_state->is_me = NULL;
			fr_queuefront(&ipsec->ipsc_state->is_sti);
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_state);

		ipsec->ipsc_state = NULL;
		ipsec->ipsc_nat = NULL;
	}
}
