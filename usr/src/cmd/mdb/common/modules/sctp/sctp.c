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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/mdb_modapi.h>
#include <sys/socket.h>
#include <sys/list.h>
#include <sys/strsun.h>

#include <mdb/mdb_stdlib.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/sctp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ipclassifier.h>

#include <sctp/sctp_impl.h>
#include <sctp/sctp_addr.h>

#define	MDB_SCTP_SHOW_FLAGS	0x1
#define	MDB_SCTP_DUMP_ADDRS	0x2
#define	MDB_SCTP_SHOW_HASH	0x4
#define	MDB_SCTP_SHOW_OUT	0x8
#define	MDB_SCTP_SHOW_IN	0x10
#define	MDB_SCTP_SHOW_MISC	0x20
#define	MDB_SCTP_SHOW_RTT	0x40
#define	MDB_SCTP_SHOW_STATS	0x80
#define	MDB_SCTP_SHOW_FLOW	0x100
#define	MDB_SCTP_SHOW_HDR	0x200
#define	MDB_SCTP_SHOW_PMTUD	0x400
#define	MDB_SCTP_SHOW_RXT	0x800
#define	MDB_SCTP_SHOW_CONN	0x1000
#define	MDB_SCTP_SHOW_CLOSE	0x2000
#define	MDB_SCTP_SHOW_EXT	0x4000

#define	MDB_SCTP_SHOW_ALL	0xffffffff

/*
 * Copy from usr/src/uts/common/os/list.c.  Should we have a generic
 * mdb list walker?
 */
#define	list_object(a, node) ((void *)(((char *)node) - (a)->list_offset))

static int
ns_to_stackid(uintptr_t kaddr)
{
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), kaddr) == -1) {
		mdb_warn("failed to read netdstack info %p", kaddr);
		return (0);
	}
	return (nss.netstack_stackid);
}

int
sctp_stacks_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("netstack", wsp) == -1) {
		mdb_warn("can't walk 'netstack'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
sctp_stacks_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), wsp->walk_addr) == -1) {
		mdb_warn("can't read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	kaddr = (uintptr_t)nss.netstack_modules[NS_SCTP];
	return (wsp->walk_callback(kaddr, wsp->walk_layer, wsp->walk_cbdata));
}

static char *
sctp_faddr_state(int state)
{
	char *statestr;

	switch (state) {
	case SCTP_FADDRS_UNREACH:
		statestr = "Unreachable";
		break;
	case SCTP_FADDRS_DOWN:
		statestr = "Down";
		break;
	case SCTP_FADDRS_ALIVE:
		statestr = "Alive";
		break;
	case SCTP_FADDRS_UNCONFIRMED:
		statestr = "Unconfirmed";
		break;
	default:
		statestr = "Unknown";
		break;
	}
	return (statestr);
}

/* ARGSUSED */
static int
sctp_faddr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	sctp_faddr_t fa[1];
	char *statestr;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(fa, sizeof (*fa), addr) == -1) {
		mdb_warn("cannot read fadder at %p", addr);
		return (DCMD_ERR);
	}

	statestr = sctp_faddr_state(fa->sf_state);
	mdb_printf("%<u>%p\t%<b>%N%</b>\t%s%</u>\n", addr, &fa->sf_faddr,
	    statestr);
	mdb_printf("next\t\t%?p\tsaddr\t%N\n", fa->sf_next, &fa->sf_saddr);
	mdb_printf("rto\t\t%?d\tsrtt\t\t%?d\n", fa->sf_rto, fa->sf_srtt);
	mdb_printf("rttvar\t\t%?d\trtt_updates\t%?u\n", fa->sf_rttvar,
	    fa->sf_rtt_updates);
	mdb_printf("strikes\t\t%?d\tmax_retr\t%?d\n", fa->sf_strikes,
	    fa->sf_max_retr);
	mdb_printf("hb_expiry\t%?ld\thb_interval\t%?u\n", fa->sf_hb_expiry,
	    fa->sf_hb_interval);
	mdb_printf("pmss\t\t%?u\tcwnd\t\t%?u\n", fa->sf_pmss, fa->sf_cwnd);
	mdb_printf("ssthresh\t%?u\tsuna\t\t%?u\n", fa->sf_ssthresh,
	    fa->sf_suna);
	mdb_printf("pba\t\t%?u\tacked\t\t%?u\n", fa->sf_pba, fa->sf_acked);
	mdb_printf("lastactive\t%?ld\thb_secret\t%?#lx\n", fa->sf_lastactive,
	    fa->sf_hb_secret);
	mdb_printf("rxt_unacked\t%?u\n", fa->sf_rxt_unacked);
	mdb_printf("timer_mp\t%?p\tixa\t\t%?p\n", fa->sf_timer_mp, fa->sf_ixa);
	mdb_printf("hb_enabled\t%?d\thb_pending\t%?d\n"
	    "timer_running\t%?d\tdf\t\t%?d\n"
	    "pmtu_discovered\t%?d\tisv4\t\t%?d\n"
	    "retransmissions\t%?u\n",
	    fa->sf_hb_enabled, fa->sf_hb_pending, fa->sf_timer_running,
	    fa->sf_df, fa->sf_pmtu_discovered, fa->sf_isv4, fa->sf_T3expire);

	return (DCMD_OK);
}

static void
print_set(sctp_set_t *sp)
{
	mdb_printf("\tbegin\t%<b>%?x%</b>\t\tend\t%<b>%?x%</b>\n",
	    sp->begin, sp->end);
	mdb_printf("\tnext\t%?p\tprev\t%?p\n", sp->next, sp->prev);
}

/* ARGSUSED */
static int
sctp_set(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	sctp_set_t sp[1];

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(sp, sizeof (*sp), addr) == -1)
		return (DCMD_ERR);

	print_set(sp);

	return (DCMD_OK);
}

static void
dump_sack_info(uintptr_t addr)
{
	sctp_set_t sp[1];

	while (addr != 0) {
		if (mdb_vread(sp, sizeof (*sp), addr) == -1) {
			mdb_warn("failed to read sctp_set at %p", addr);
			return;
		}

		addr = (uintptr_t)sp->next;
		print_set(sp);
	}
}

static int
dump_msghdr(mblk_t *meta)
{
	sctp_msg_hdr_t smh;

	if (mdb_vread(&smh, sizeof (smh), (uintptr_t)meta->b_rptr) == -1)
		return (-1);

	mdb_printf("%<u>msg_hdr_t at \t%?p\tsentto\t%?p%</u>\n",
	    meta->b_rptr, SCTP_CHUNK_DEST(meta));
	mdb_printf("\tttl\t%?ld\ttob\t%?ld\n", smh.smh_ttl, smh.smh_tob);
	mdb_printf("\tsid\t%?u\tssn\t%?u\n", smh.smh_sid, smh.smh_ssn);
	mdb_printf("\tppid\t%?u\tflags\t%?s\n", smh.smh_ppid,
	    smh.smh_flags & MSG_UNORDERED ? "unordered" : " ");
	mdb_printf("\tcontext\t%?u\tmsglen\t%?d\n", smh.smh_context,
	    smh.smh_msglen);

	return (0);
}

static int
dump_datahdr(mblk_t *mp)
{
	sctp_data_hdr_t	sdc;
	uint16_t		sdh_int16;
	uint32_t		sdh_int32;

	if (mdb_vread(&sdc, sizeof (sdc), (uintptr_t)mp->b_rptr) == -1)
		return (-1);

	mdb_printf("%<u>data_chunk_t \t%?p\tsentto\t%?p%</u>\n",
	    mp->b_rptr, SCTP_CHUNK_DEST(mp));
	mdb_printf("\tsent\t%?d\t", SCTP_CHUNK_ISSENT(mp)?1:0);
	mdb_printf("retrans\t%?d\n", SCTP_CHUNK_WANT_REXMIT(mp)?1:0);
	mdb_printf("\tacked\t%?d\t", SCTP_CHUNK_ISACKED(mp)?1:0);
	mdb_printf("sackcnt\t%?u\n", SCTP_CHUNK_SACKCNT(mp));

	mdb_nhconvert(&sdh_int16, &sdc.sdh_len, sizeof (sdc.sdh_len));
	mdb_printf("\tlen\t%?d\t", sdh_int16);
	mdb_printf("BBIT=%d", SCTP_DATA_GET_BBIT(&sdc) == 0 ? 0 : 1);
	mdb_printf("EBIT=%d", SCTP_DATA_GET_EBIT(&sdc) == 0 ? 0 : 1);

	mdb_nhconvert(&sdh_int32, &sdc.sdh_tsn, sizeof (sdc.sdh_tsn));
	mdb_nhconvert(&sdh_int16, &sdc.sdh_sid, sizeof (sdc.sdh_sid));
	mdb_printf("\ttsn\t%?x\tsid\t%?hu\n", sdh_int32, sdh_int16);

	mdb_nhconvert(&sdh_int16, &sdc.sdh_ssn, sizeof (sdc.sdh_ssn));
	mdb_nhconvert(&sdh_int32, &sdc.sdh_payload_id,
	    sizeof (sdc.sdh_payload_id));
	mdb_printf("\tssn\t%?hu\tppid\t%?d\n", sdh_int16, sdh_int32);

	return (0);
}

static int
sctp_sent_list(mblk_t *addr)
{
	mblk_t meta, mp;

	if (!addr)
		return (0);

	if (mdb_vread(&meta, sizeof (meta), (uintptr_t)addr) == -1)
		return (-1);

	for (;;) {
		dump_msghdr(&meta);

		if (meta.b_cont == NULL) {
			mdb_printf("No data chunks with message header!\n");
			return (-1);
		}
		if (mdb_vread(&mp, sizeof (mp),
		    (uintptr_t)meta.b_cont) == -1) {
			return (-1);
		}
		for (;;) {
			dump_datahdr(&mp);
			if (!mp.b_next)
				break;

			if (mdb_vread(&mp, sizeof (mp),
			    (uintptr_t)(mp.b_next)) == -1)
				return (-1);
		}
		if (meta.b_next == NULL)
			break;
		if (mdb_vread(&meta, sizeof (meta),
		    (uintptr_t)meta.b_next) == -1)
			return (-1);
	}

	return (0);
}

static int
sctp_unsent_list(mblk_t *addr)
{
	mblk_t meta;

	if (!addr)
		return (0);

	if (mdb_vread(&meta, sizeof (meta), (uintptr_t)addr) == -1)
		return (-1);

	for (;;) {
		dump_msghdr(&meta);

		if (meta.b_next == NULL)
			break;

		if (mdb_vread(&meta, sizeof (meta),
		    (uintptr_t)meta.b_next) == -1)
			return (-1);
	}

	return (0);
}

/* ARGSUSED */
static int
sctp_xmit_list(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	sctp_t sctp;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&sctp, sizeof (sctp), addr) == -1)
		return (DCMD_ERR);

	mdb_printf("%<b>Chunkified TX list%</b>\n");
	if (sctp_sent_list(sctp.sctp_xmit_head) < 0)
		return (DCMD_ERR);

	mdb_printf("%<b>Unchunkified TX list%</b>\n");
	if (sctp_unsent_list(sctp.sctp_xmit_unsent) < 0)
		return (DCMD_ERR);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
sctp_mdata_chunk(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	sctp_data_hdr_t dc;
	mblk_t mp;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&mp, sizeof (mp), addr) == -1)
		return (DCMD_ERR);

	if (mdb_vread(&dc, sizeof (dc), (uintptr_t)mp.b_rptr) == -1)
		return (DCMD_ERR);

	mdb_printf("%<b>%-?p%</b>tsn\t%?x\tsid\t%?hu\n", addr,
	    dc.sdh_tsn, dc.sdh_sid);
	mdb_printf("%-?sssn\t%?hu\tppid\t%?x\n", "", dc.sdh_ssn,
	    dc.sdh_payload_id);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
sctp_istr_msgs(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	mblk_t			istrmp;
	mblk_t			dmp;
	sctp_data_hdr_t		dp;
	uintptr_t		daddr;
	uintptr_t		chaddr;
	boolean_t		bbit;
	boolean_t		ebit;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	do {
		if (mdb_vread(&istrmp, sizeof (istrmp), addr) == -1)
			return (DCMD_ERR);

		mdb_printf("\tistr mblk at %p: next: %?p\n"
		    "\t\tprev: %?p\tcont: %?p\n", addr, istrmp.b_next,
		    istrmp.b_prev, istrmp.b_cont);
		daddr = (uintptr_t)&istrmp;
		do {
			if (mdb_vread(&dmp, sizeof (dmp), daddr) == -1)
				break;
			chaddr = (uintptr_t)dmp.b_rptr;
			if (mdb_vread(&dp, sizeof (dp), chaddr) == -1)
				break;

			bbit = (SCTP_DATA_GET_BBIT(&dp) != 0);
			ebit = (SCTP_DATA_GET_EBIT(&dp) != 0);

			mdb_printf("\t\t\ttsn: %x  bbit: %d  ebit: %d\n",
			    dp.sdh_tsn, bbit, ebit);


			daddr = (uintptr_t)dmp.b_cont;
		} while (daddr != 0);

		addr = (uintptr_t)istrmp.b_next;
	} while (addr != 0);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
sctp_reass_list(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	sctp_reass_t srp;
	mblk_t srpmp;
	sctp_data_hdr_t dp;
	mblk_t dmp;
	uintptr_t daddr;
	uintptr_t chaddr;
	boolean_t bbit, ebit;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	do {
		if (mdb_vread(&srpmp, sizeof (srpmp), addr) == -1)
			return (DCMD_ERR);

		if (mdb_vread(&srp, sizeof (srp),
		    (uintptr_t)srpmp.b_datap->db_base) == -1)
			return (DCMD_ERR);

		mdb_printf("\treassembly mblk at %p: next: %?p\n"
		    "\t\tprev: %?p\tcont: %?p\n", addr, srpmp.b_next,
		    srpmp.b_prev, srpmp.b_cont);
		mdb_printf("\t\tssn: %hu\tneeded: %hu\tgot: %hu\ttail: %?p\n"
		    "\t\tpartial_delivered: %s\n", srp.sr_ssn, srp.sr_needed,
		    srp.sr_got, srp.sr_tail, srp.sr_partial_delivered ? "TRUE" :
		    "FALSE");

		/* display the contents of this ssn's reassemby list */
		daddr = DB_TYPE(&srpmp) == M_CTL ? (uintptr_t)srpmp.b_cont :
		    (uintptr_t)&srpmp;
		do {
			if (mdb_vread(&dmp, sizeof (dmp), daddr) == -1)
				break;
			chaddr = (uintptr_t)dmp.b_rptr;
			if (mdb_vread(&dp, sizeof (dp), chaddr) == -1)
				break;

			bbit = (SCTP_DATA_GET_BBIT(&dp) != 0);
			ebit = (SCTP_DATA_GET_EBIT(&dp) != 0);

			mdb_printf("\t\t\ttsn: %x  bbit: %d  ebit: %d\n",
			    dp.sdh_tsn, bbit, ebit);

			daddr = (uintptr_t)dmp.b_cont;
		} while (daddr != 0);

		addr = (uintptr_t)srpmp.b_next;
	} while (addr != 0);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
sctp_uo_reass_list(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	sctp_data_hdr_t	dp;
	mblk_t		dmp;
	uintptr_t	chaddr;
	boolean_t	bbit;
	boolean_t	ebit;
	boolean_t	ubit;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	do {
		if (mdb_vread(&dmp, sizeof (dmp), addr) == -1)
			return (DCMD_ERR);

		mdb_printf("\treassembly mblk at %p: next: %?p\n"
		    "\t\tprev: %?p\n", addr, dmp.b_next, dmp.b_prev);

		chaddr = (uintptr_t)dmp.b_rptr;
		if (mdb_vread(&dp, sizeof (dp), chaddr) == -1)
			break;

		bbit = (SCTP_DATA_GET_BBIT(&dp) != 0);
		ebit = (SCTP_DATA_GET_EBIT(&dp) != 0);
		ubit = (SCTP_DATA_GET_UBIT(&dp) != 0);

		mdb_printf("\t\t\tsid: %hu ssn: %hu tsn: %x "
		    "flags: %x (U=%d B=%d E=%d)\n", dp.sdh_sid, dp.sdh_ssn,
		    dp.sdh_tsn, dp.sdh_flags, ubit, bbit, ebit);

		addr = (uintptr_t)dmp.b_next;
	} while (addr != 0);

	return (DCMD_OK);
}

static int
sctp_instr(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	sctp_instr_t sip;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&sip, sizeof (sip), addr) == -1)
		return (DCMD_ERR);

	mdb_printf("%<b>%-?p%</b>\n\tmsglist\t%?p\tnmsgs\t%?d\n"
	    "\tnextseq\t%?d\treass\t%?p\n", addr, sip.istr_msgs,
	    sip.istr_nmsgs, sip.nextseq, sip.istr_reass);
	mdb_set_dot(addr + sizeof (sip));

	return (sctp_reass_list((uintptr_t)sip.istr_reass, flags, ac, av));
}

static const char *
state2str(sctp_t *sctp)
{
	switch (sctp->sctp_state) {
	case SCTPS_IDLE:		return ("SCTPS_IDLE");
	case SCTPS_BOUND:		return ("SCTPS_BOUND");
	case SCTPS_LISTEN:		return ("SCTPS_LISTEN");
	case SCTPS_COOKIE_WAIT:		return ("SCTPS_COOKIE_WAIT");
	case SCTPS_COOKIE_ECHOED:	return ("SCTPS_COOKIE_ECHOED");
	case SCTPS_ESTABLISHED:		return ("SCTPS_ESTABLISHED");
	case SCTPS_SHUTDOWN_PENDING:	return ("SCTPS_SHUTDOWN_PENDING");
	case SCTPS_SHUTDOWN_SENT:	return ("SCTPS_SHUTDOWN_SENT");
	case SCTPS_SHUTDOWN_RECEIVED:	return ("SCTPS_SHUTDOWN_RECEIVED");
	case SCTPS_SHUTDOWN_ACK_SENT:	return ("SCTPS_SHUTDOWN_ACK_SENT");
	default:			return ("UNKNOWN STATE");
	}
}

static void
show_sctp_flags(sctp_t *sctp)
{
	mdb_printf("\tunderstands_asconf\t%d\n",
	    sctp->sctp_understands_asconf);
	mdb_printf("\tdebug\t\t\t%d\n", sctp->sctp_connp->conn_debug);
	mdb_printf("\tcchunk_pend\t\t%d\n", sctp->sctp_cchunk_pend);
	mdb_printf("\tdgram_errind\t\t%d\n",
	    sctp->sctp_connp->conn_dgram_errind);

	mdb_printf("\tlinger\t\t\t%d\n", sctp->sctp_connp->conn_linger);
	if (sctp->sctp_lingering)
		return;
	mdb_printf("\tlingering\t\t%d\n", sctp->sctp_lingering);
	mdb_printf("\tloopback\t\t%d\n", sctp->sctp_loopback);
	mdb_printf("\tforce_sack\t\t%d\n", sctp->sctp_force_sack);

	mdb_printf("\tack_timer_runing\t%d\n", sctp->sctp_ack_timer_running);
	mdb_printf("\trecvdstaddr\t\t%d\n",
	    sctp->sctp_connp->conn_recv_ancillary.crb_recvdstaddr);
	mdb_printf("\thwcksum\t\t\t%d\n", sctp->sctp_hwcksum);
	mdb_printf("\tunderstands_addip\t%d\n", sctp->sctp_understands_addip);

	mdb_printf("\tbound_to_all\t\t%d\n", sctp->sctp_bound_to_all);
	mdb_printf("\tcansleep\t\t%d\n", sctp->sctp_cansleep);
	mdb_printf("\tdetached\t\t%d\n", sctp->sctp_detached);
	mdb_printf("\tsend_adaptation\t\t%d\n", sctp->sctp_send_adaptation);

	mdb_printf("\trecv_adaptation\t\t%d\n", sctp->sctp_recv_adaptation);
	mdb_printf("\tndelay\t\t\t%d\n", sctp->sctp_ndelay);
	mdb_printf("\tcondemned\t\t%d\n", sctp->sctp_condemned);
	mdb_printf("\tchk_fast_rexmit\t\t%d\n", sctp->sctp_chk_fast_rexmit);

	mdb_printf("\tprsctp_aware\t\t%d\n", sctp->sctp_prsctp_aware);
	mdb_printf("\tlinklocal\t\t%d\n", sctp->sctp_linklocal);
	mdb_printf("\trexmitting\t\t%d\n", sctp->sctp_rexmitting);
	mdb_printf("\tzero_win_probe\t\t%d\n", sctp->sctp_zero_win_probe);

	mdb_printf("\trecvsndrcvinfo\t\t%d\n", sctp->sctp_recvsndrcvinfo);
	mdb_printf("\trecvassocevnt\t\t%d\n", sctp->sctp_recvassocevnt);
	mdb_printf("\trecvpathevnt\t\t%d\n", sctp->sctp_recvpathevnt);
	mdb_printf("\trecvsendfailevnt\t%d\n", sctp->sctp_recvsendfailevnt);

	mdb_printf("\trecvpeerevnt\t\t%d\n", sctp->sctp_recvpeererr);
	mdb_printf("\trecvchutdownevnt\t%d\n", sctp->sctp_recvshutdownevnt);
	mdb_printf("\trecvcpdnevnt\t\t%d\n", sctp->sctp_recvpdevnt);
	mdb_printf("\trecvcalevnt\t\t%d\n\n", sctp->sctp_recvalevnt);
}

/*
 * Given a sctp_saddr_ipif_t, print out its address.  This assumes
 * that addr contains the sctp_addr_ipif_t structure already and this
 * function does not need to read it in.
 */
/* ARGSUSED */
static int
print_saddr(uintptr_t ptr, const void *addr, void *cbdata)
{
	sctp_saddr_ipif_t *saddr = (sctp_saddr_ipif_t *)addr;
	sctp_ipif_t ipif;
	char *statestr;

	/* Read in the sctp_ipif object */
	if (mdb_vread(&ipif, sizeof (ipif), (uintptr_t)saddr->saddr_ipifp) ==
	    -1) {
		mdb_warn("cannot read ipif at %p", saddr->saddr_ipifp);
		return (WALK_ERR);
	}

	switch (ipif.sctp_ipif_state) {
	case SCTP_IPIFS_CONDEMNED:
		statestr = "Condemned";
		break;
	case SCTP_IPIFS_INVALID:
		statestr = "Invalid";
		break;
	case SCTP_IPIFS_DOWN:
		statestr = "Down";
		break;
	case SCTP_IPIFS_UP:
		statestr = "Up";
		break;
	default:
		statestr = "Unknown";
		break;
	}
	mdb_printf("\t%p\t%N% (%s", saddr->saddr_ipifp, &ipif.sctp_ipif_saddr,
	    statestr);
	if (saddr->saddr_ipif_dontsrc == 1)
		mdb_printf("/Dontsrc");
	if (saddr->saddr_ipif_unconfirmed == 1)
		mdb_printf("/Unconfirmed");
	if (saddr->saddr_ipif_delete_pending == 1)
		mdb_printf("/DeletePending");
	mdb_printf(")\n");
	mdb_printf("\t\t\tid %d zoneid %d IPIF flags %x\n",
	    ipif.sctp_ipif_id,
	    ipif.sctp_ipif_zoneid, ipif.sctp_ipif_flags);
	return (WALK_NEXT);
}

/*
 * Given a sctp_faddr_t, print out its address.  This assumes that
 * addr contains the sctp_faddr_t structure already and this function
 * does not need to read it in.
 */
static int
print_faddr(uintptr_t ptr, const void *addr, void *cbdata)
{
	char	*statestr;
	sctp_faddr_t *faddr = (sctp_faddr_t *)addr;
	int *i = cbdata;

	statestr = sctp_faddr_state(faddr->sf_state);

	mdb_printf("\t%d:\t%N\t%?p (%s)\n", (*i)++, &faddr->sf_faddr, ptr,
	    statestr);
	return (WALK_NEXT);
}

int
sctp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	sctp_t sctps, *sctp;
	conn_t conns, *connp;
	int i;
	uint_t opts = 0;
	uint_t paddr = 0;
	in_port_t lport, fport;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&sctps, sizeof (sctps), addr) == -1) {
		mdb_warn("failed to read sctp_t at: %p\n", addr);
		return (DCMD_ERR);
	}
	sctp = &sctps;

	if (mdb_vread(&conns, sizeof (conns),
	    (uintptr_t)sctp->sctp_connp) == -1) {
		mdb_warn("failed to read conn_t at: %p\n", sctp->sctp_connp);
		return (DCMD_ERR);
	}

	connp = &conns;

	connp->conn_sctp = sctp;
	sctp->sctp_connp = connp;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, MDB_SCTP_SHOW_ALL, &opts,
	    'f', MDB_OPT_SETBITS, MDB_SCTP_SHOW_FLAGS, &opts,
	    'h', MDB_OPT_SETBITS, MDB_SCTP_SHOW_HASH, &opts,
	    'o', MDB_OPT_SETBITS, MDB_SCTP_SHOW_OUT, &opts,
	    'i', MDB_OPT_SETBITS, MDB_SCTP_SHOW_IN, &opts,
	    'm', MDB_OPT_SETBITS, MDB_SCTP_SHOW_MISC, &opts,
	    'r', MDB_OPT_SETBITS, MDB_SCTP_SHOW_RTT, &opts,
	    'S', MDB_OPT_SETBITS, MDB_SCTP_SHOW_STATS, &opts,
	    'F', MDB_OPT_SETBITS, MDB_SCTP_SHOW_FLOW, &opts,
	    'H', MDB_OPT_SETBITS, MDB_SCTP_SHOW_HDR, &opts,
	    'p', MDB_OPT_SETBITS, MDB_SCTP_SHOW_PMTUD, &opts,
	    'R', MDB_OPT_SETBITS, MDB_SCTP_SHOW_RXT, &opts,
	    'C', MDB_OPT_SETBITS, MDB_SCTP_SHOW_CONN, &opts,
	    'c', MDB_OPT_SETBITS, MDB_SCTP_SHOW_CLOSE, &opts,
	    'e', MDB_OPT_SETBITS, MDB_SCTP_SHOW_EXT, &opts,
	    'P', MDB_OPT_SETBITS, 1, &paddr,
	    'd', MDB_OPT_SETBITS, MDB_SCTP_DUMP_ADDRS, &opts) != argc) {
		return (DCMD_USAGE);
	}

	/* non-verbose faddrs, suitable for pipelines to sctp_faddr */
	if (paddr != 0) {
		sctp_faddr_t faddr, *fp;
		for (fp = sctp->sctp_faddrs; fp != NULL; fp = faddr.sf_next) {
			if (mdb_vread(&faddr, sizeof (faddr), (uintptr_t)fp)
			    == -1) {
				mdb_warn("failed to read faddr at %p",
				    fp);
				return (DCMD_ERR);
			}
			mdb_printf("%p\n", fp);
		}
		return (DCMD_OK);
	}

	mdb_nhconvert(&lport, &connp->conn_lport, sizeof (lport));
	mdb_nhconvert(&fport, &connp->conn_fport, sizeof (fport));
	mdb_printf("%<u>%p% %22s S=%-6hu D=%-6hu% STACK=%d ZONE=%d%</u>", addr,
	    state2str(sctp), lport, fport,
	    ns_to_stackid((uintptr_t)connp->conn_netstack), connp->conn_zoneid);

	if (sctp->sctp_faddrs) {
		sctp_faddr_t faddr;
		if (mdb_vread(&faddr, sizeof (faddr),
		    (uintptr_t)sctp->sctp_faddrs) != -1)
			mdb_printf("%<u> %N%</u>", &faddr.sf_faddr);
	}
	mdb_printf("\n");

	if (opts & MDB_SCTP_DUMP_ADDRS) {
		mdb_printf("%<b>Local and Peer Addresses%</b>\n");

		/* Display source addresses */
		mdb_printf("nsaddrs\t\t%?d\n", sctp->sctp_nsaddrs);
		(void) mdb_pwalk("sctp_walk_saddr", print_saddr, NULL, addr);

		/* Display peer addresses */
		mdb_printf("nfaddrs\t\t%?d\n", sctp->sctp_nfaddrs);
		i = 1;
		(void) mdb_pwalk("sctp_walk_faddr", print_faddr, &i, addr);

		mdb_printf("lastfaddr\t%?p\tprimary\t\t%?p\n",
		    sctp->sctp_lastfaddr, sctp->sctp_primary);
		mdb_printf("current\t\t%?p\tlastdata\t%?p\n",
		    sctp->sctp_current, sctp->sctp_lastdata);
	}

	if (opts & MDB_SCTP_SHOW_OUT) {
		mdb_printf("%<b>Outbound Data%</b>\n");
		mdb_printf("xmit_head\t%?p\txmit_tail\t%?p\n",
		    sctp->sctp_xmit_head, sctp->sctp_xmit_tail);
		mdb_printf("xmit_unsent\t%?p\txmit_unsent_tail%?p\n",
		    sctp->sctp_xmit_unsent, sctp->sctp_xmit_unsent_tail);
		mdb_printf("xmit_unacked\t%?p\n", sctp->sctp_xmit_unacked);
		mdb_printf("unacked\t\t%?u\tunsent\t\t%?ld\n",
		    sctp->sctp_unacked, sctp->sctp_unsent);
		mdb_printf("ltsn\t\t%?x\tlastack_rxd\t%?x\n",
		    sctp->sctp_ltsn, sctp->sctp_lastack_rxd);
		mdb_printf("recovery_tsn\t%?x\tadv_pap\t\t%?x\n",
		    sctp->sctp_recovery_tsn, sctp->sctp_adv_pap);
		mdb_printf("num_ostr\t%?hu\tostrcntrs\t%?p\n",
		    sctp->sctp_num_ostr, sctp->sctp_ostrcntrs);
		mdb_printf("pad_mp\t\t%?p\terr_chunks\t%?p\n",
		    sctp->sctp_pad_mp, sctp->sctp_err_chunks);
		mdb_printf("err_len\t\t%?u\n", sctp->sctp_err_len);

		mdb_printf("%<b>Default Send Parameters%</b>\n");
		mdb_printf("def_stream\t%?u\tdef_flags\t%?x\n",
		    sctp->sctp_def_stream, sctp->sctp_def_flags);
		mdb_printf("def_ppid\t%?x\tdef_context\t%?x\n",
		    sctp->sctp_def_ppid, sctp->sctp_def_context);
		mdb_printf("def_timetolive\t%?u\n",
		    sctp->sctp_def_timetolive);
	}

	if (opts & MDB_SCTP_SHOW_IN) {
		mdb_printf("%<b>Inbound Data%</b>\n");
		mdb_printf("sack_info\t%?p\tsack_gaps\t%?d\n",
		    sctp->sctp_sack_info, sctp->sctp_sack_gaps);
		dump_sack_info((uintptr_t)sctp->sctp_sack_info);
		mdb_printf("ftsn\t\t%?x\tlastacked\t%?x\n",
		    sctp->sctp_ftsn, sctp->sctp_lastacked);
		mdb_printf("istr_nmsgs\t%?d\tsack_toggle\t%?d\n",
		    sctp->sctp_istr_nmsgs, sctp->sctp_sack_toggle);
		mdb_printf("ack_mp\t\t%?p\n", sctp->sctp_ack_mp);
		mdb_printf("num_istr\t%?hu\tinstr\t\t%?p\n",
		    sctp->sctp_num_istr, sctp->sctp_instr);
		mdb_printf("unord_reass\t%?p\n", sctp->sctp_uo_frags);
	}

	if (opts & MDB_SCTP_SHOW_RTT) {
		mdb_printf("%<b>RTT Tracking%</b>\n");
		mdb_printf("rtt_tsn\t\t%?x\tout_time\t%?ld\n",
		    sctp->sctp_rtt_tsn, sctp->sctp_out_time);
	}

	if (opts & MDB_SCTP_SHOW_FLOW) {
		mdb_printf("%<b>Flow Control%</b>\n");
		mdb_printf("tconn_sndbuf\t%?d\n"
		    "conn_sndlowat\t%?d\tfrwnd\t\t%?u\n"
		    "rwnd\t\t%?u\tlast advertised rwnd\t%?u\n"
		    "rxqueued\t%?u\tcwnd_max\t%?u\n", connp->conn_sndbuf,
		    connp->conn_sndlowat, sctp->sctp_frwnd,
		    sctp->sctp_rwnd, sctp->sctp_arwnd, sctp->sctp_rxqueued,
		    sctp->sctp_cwnd_max);
	}

	if (opts & MDB_SCTP_SHOW_HDR) {
		mdb_printf("%<b>Composite Headers%</b>\n");
		mdb_printf("iphc\t\t%?p\tiphc6\t\t%?p\n"
		    "iphc_len\t%?d\tiphc6_len\t%?d\n"
		    "hdr_len\t\t%?d\thdr6_len\t%?d\n"
		    "ipha\t\t%?p\tip6h\t\t%?p\n"
		    "ip_hdr_len\t%?d\tip_hdr6_len\t%?d\n"
		    "sctph\t\t%?p\tsctph6\t\t%?p\n"
		    "lvtag\t\t%?x\tfvtag\t\t%?x\n", sctp->sctp_iphc,
		    sctp->sctp_iphc6, sctp->sctp_iphc_len,
		    sctp->sctp_iphc6_len, sctp->sctp_hdr_len,
		    sctp->sctp_hdr6_len, sctp->sctp_ipha, sctp->sctp_ip6h,
		    sctp->sctp_ip_hdr_len, sctp->sctp_ip_hdr6_len,
		    sctp->sctp_sctph, sctp->sctp_sctph6, sctp->sctp_lvtag,
		    sctp->sctp_fvtag);
	}

	if (opts & MDB_SCTP_SHOW_PMTUD) {
		mdb_printf("%<b>PMTUd%</b>\n");
		mdb_printf("last_mtu_probe\t%?ld\tmtu_probe_intvl\t%?ld\n"
		    "mss\t\t%?u\n",
		    sctp->sctp_last_mtu_probe, sctp->sctp_mtu_probe_intvl,
		    sctp->sctp_mss);
	}

	if (opts & MDB_SCTP_SHOW_RXT) {
		mdb_printf("%<b>Retransmit Info%</b>\n");
		mdb_printf("cookie_mp\t%?p\tstrikes\t\t%?d\n"
		    "max_init_rxt\t%?d\tpa_max_rxt\t%?d\n"
		    "pp_max_rxt\t%?d\trto_max\t\t%?u\n"
		    "rto_min\t\t%?u\trto_initial\t%?u\n"
		    "init_rto_max\t%?u\n"
		    "rxt_nxttsn\t%?u\trxt_maxtsn\t%?u\n", sctp->sctp_cookie_mp,
		    sctp->sctp_strikes, sctp->sctp_max_init_rxt,
		    sctp->sctp_pa_max_rxt, sctp->sctp_pp_max_rxt,
		    sctp->sctp_rto_max, sctp->sctp_rto_min,
		    sctp->sctp_rto_initial, sctp->sctp_rto_max_init,
		    sctp->sctp_rxt_nxttsn, sctp->sctp_rxt_maxtsn);
	}

	if (opts & MDB_SCTP_SHOW_CONN) {
		mdb_printf("%<b>Connection State%</b>\n");
		mdb_printf("last_secret_update%?ld\n",
		    sctp->sctp_last_secret_update);

		mdb_printf("secret\t\t");
		for (i = 0; i < SCTP_SECRET_LEN; i++) {
			if (i % 2 == 0)
				mdb_printf("0x%02x", sctp->sctp_secret[i]);
			else
				mdb_printf("%02x ", sctp->sctp_secret[i]);
		}
		mdb_printf("\n");
		mdb_printf("old_secret\t");
		for (i = 0; i < SCTP_SECRET_LEN; i++) {
			if (i % 2 == 0)
				mdb_printf("0x%02x", sctp->sctp_old_secret[i]);
			else
				mdb_printf("%02x ", sctp->sctp_old_secret[i]);
		}
		mdb_printf("\n");
	}

	if (opts & MDB_SCTP_SHOW_STATS) {
		mdb_printf("%<b>Stats Counters%</b>\n");
		mdb_printf("opkts\t\t%?llu\tobchunks\t%?llu\n"
		    "odchunks\t%?llu\toudchunks\t%?llu\n"
		    "rxtchunks\t%?llu\tT1expire\t%?lu\n"
		    "T2expire\t%?lu\tT3expire\t%?lu\n"
		    "msgcount\t%?llu\tprsctpdrop\t%?llu\n"
		    "AssocStartTime\t%?lu\n",
		    sctp->sctp_opkts, sctp->sctp_obchunks,
		    sctp->sctp_odchunks, sctp->sctp_oudchunks,
		    sctp->sctp_rxtchunks, sctp->sctp_T1expire,
		    sctp->sctp_T2expire, sctp->sctp_T3expire,
		    sctp->sctp_msgcount, sctp->sctp_prsctpdrop,
		    sctp->sctp_assoc_start_time);
		mdb_printf("ipkts\t\t%?llu\tibchunks\t%?llu\n"
		    "idchunks\t%?llu\tiudchunks\t%?llu\n"
		    "fragdmsgs\t%?llu\treassmsgs\t%?llu\n",
		    sctp->sctp_ipkts, sctp->sctp_ibchunks,
		    sctp->sctp_idchunks, sctp->sctp_iudchunks,
		    sctp->sctp_fragdmsgs, sctp->sctp_reassmsgs);
	}

	if (opts & MDB_SCTP_SHOW_HASH) {
		mdb_printf("%<b>Hash Tables%</b>\n");
		mdb_printf("conn_hash_next\t%?p\t", sctp->sctp_conn_hash_next);
		mdb_printf("conn_hash_prev\t%?p\n", sctp->sctp_conn_hash_prev);

		mdb_printf("listen_hash_next%?p\t",
		    sctp->sctp_listen_hash_next);
		mdb_printf("listen_hash_prev%?p\n",
		    sctp->sctp_listen_hash_prev);
		mdb_nhconvert(&lport, &connp->conn_lport, sizeof (lport));
		mdb_printf("[ listen_hash bucket\t%?d ]\n",
		    SCTP_LISTEN_HASH(lport));

		mdb_printf("conn_tfp\t%?p\t", sctp->sctp_conn_tfp);
		mdb_printf("listen_tfp\t%?p\n", sctp->sctp_listen_tfp);

		mdb_printf("bind_hash\t%?p\tptpbhn\t\t%?p\n",
		    sctp->sctp_bind_hash, sctp->sctp_ptpbhn);
		mdb_printf("bind_lockp\t%?p\n",
		    sctp->sctp_bind_lockp);
		mdb_printf("[ bind_hash bucket\t%?d ]\n",
		    SCTP_BIND_HASH(lport));
	}

	if (opts & MDB_SCTP_SHOW_CLOSE) {
		mdb_printf("%<b>Cleanup / Close%</b>\n");
		mdb_printf("shutdown_faddr\t%?p\tclient_errno\t%?d\n"
		    "lingertime\t%?d\trefcnt\t\t%?hu\n",
		    sctp->sctp_shutdown_faddr, sctp->sctp_client_errno,
		    connp->conn_lingertime, sctp->sctp_refcnt);
	}

	if (opts & MDB_SCTP_SHOW_MISC) {
		mdb_printf("%<b>Miscellaneous%</b>\n");
		mdb_printf("bound_if\t%?u\theartbeat_mp\t%?p\n"
		    "family\t\t%?u\tipversion\t%?hu\n"
		    "hb_interval\t%?u\tautoclose\t%?d\n"
		    "active\t\t%?ld\ttx_adaptation_code%?x\n"
		    "rx_adaptation_code%?x\ttimer_mp\t%?p\n"
		    "partial_delivery_point\t%?d\n",
		    connp->conn_bound_if, sctp->sctp_heartbeat_mp,
		    connp->conn_family,
		    connp->conn_ipversion,
		    sctp->sctp_hb_interval, sctp->sctp_autoclose,
		    sctp->sctp_active, sctp->sctp_tx_adaptation_code,
		    sctp->sctp_rx_adaptation_code, sctp->sctp_timer_mp,
		    sctp->sctp_pd_point);
	}

	if (opts & MDB_SCTP_SHOW_EXT) {
		mdb_printf("%<b>Extensions and Reliable Ctl Chunks%</b>\n");
		mdb_printf("cxmit_list\t%?p\tlcsn\t\t%?x\n"
		    "fcsn\t\t%?x\n", sctp->sctp_cxmit_list, sctp->sctp_lcsn,
		    sctp->sctp_fcsn);
	}

	if (opts & MDB_SCTP_SHOW_FLAGS) {
		mdb_printf("%<b>Flags%</b>\n");
		show_sctp_flags(sctp);
	}

	return (DCMD_OK);
}

typedef struct fanout_walk_data {
	int index;
	int size;
	uintptr_t sctp;
	sctp_tf_t *fanout;
	uintptr_t (*getnext)(sctp_t *);
} fanout_walk_data_t;

typedef struct fanout_init {
	const char *nested_walker_name;
	size_t offset;	/* for what used to be a symbol */
	int (*getsize)(sctp_stack_t *);
	uintptr_t (*getnext)(sctp_t *);
} fanout_init_t;

static uintptr_t
listen_next(sctp_t *sctp)
{
	return ((uintptr_t)sctp->sctp_listen_hash_next);
}

/* ARGSUSED */
static int
listen_size(sctp_stack_t *sctps)
{
	return (SCTP_LISTEN_FANOUT_SIZE);
}

static uintptr_t
conn_next(sctp_t *sctp)
{
	return ((uintptr_t)sctp->sctp_conn_hash_next);
}

static int
conn_size(sctp_stack_t *sctps)
{
	int size;
	uintptr_t kaddr;

	kaddr = (uintptr_t)&sctps->sctps_conn_hash_size;

	if (mdb_vread(&size, sizeof (size), kaddr) == -1) {
		mdb_warn("can't read 'sctps_conn_hash_size' at %p", kaddr);
		return (1);
	}
	return (size);
}

static uintptr_t
bind_next(sctp_t *sctp)
{
	return ((uintptr_t)sctp->sctp_bind_hash);
}

/* ARGSUSED */
static int
bind_size(sctp_stack_t *sctps)
{
	return (SCTP_BIND_FANOUT_SIZE);
}

static uintptr_t
find_next_hash_item(fanout_walk_data_t *fw)
{
	sctp_tf_t tf;
	sctp_t sctp;

	/* first try to continue down the hash chain */
	if (fw->sctp != 0) {
		/* try to get next in hash chain */
		if (mdb_vread(&sctp, sizeof (sctp), fw->sctp) == -1) {
			mdb_warn("failed to read sctp at %p", fw->sctp);
			return (0);
		}
		fw->sctp = fw->getnext(&sctp);
		if (fw->sctp != 0)
			return (fw->sctp);
		else
			/* end of chain; go to next bucket */
			fw->index++;
	}

	/* find a new hash chain, traversing the buckets */
	for (; fw->index < fw->size; fw->index++) {
		/* read the current hash line for an sctp */
		if (mdb_vread(&tf, sizeof (tf),
		    (uintptr_t)(fw->fanout + fw->index)) == -1) {
			mdb_warn("failed to read tf at %p",
			    fw->fanout + fw->index);
			return (0);
		}
		if (tf.tf_sctp != NULL) {
			/* start of a new chain */
			fw->sctp = (uintptr_t)tf.tf_sctp;
			return (fw->sctp);
		}
	}
	return (0);
}

static int
fanout_stack_walk_init(mdb_walk_state_t *wsp)
{
	fanout_walk_data_t *lw;
	fanout_init_t *fi = wsp->walk_arg;
	sctp_stack_t *sctps = (sctp_stack_t *)wsp->walk_addr;
	uintptr_t kaddr;

	if (mdb_vread(&kaddr, sizeof (kaddr),
	    wsp->walk_addr + fi->offset) == -1) {
		mdb_warn("can't read sctp fanout at %p",
		    wsp->walk_addr + fi->offset);
		return (WALK_ERR);
	}

	lw = mdb_alloc(sizeof (*lw), UM_SLEEP);
	lw->index = 0;
	lw->size = fi->getsize(sctps);
	lw->sctp = 0;
	lw->fanout = (sctp_tf_t *)kaddr;
	lw->getnext = fi->getnext;

	if ((wsp->walk_addr = find_next_hash_item(lw)) == 0) {
		return (WALK_DONE);
	}
	wsp->walk_data = lw;
	return (WALK_NEXT);
}

static int
fanout_stack_walk_step(mdb_walk_state_t *wsp)
{
	fanout_walk_data_t *fw = wsp->walk_data;
	uintptr_t addr = wsp->walk_addr;
	sctp_t sctp;
	int status;

	if (mdb_vread(&sctp, sizeof (sctp), addr) == -1) {
		mdb_warn("failed to read sctp at %p", addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(addr, &sctp, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	if ((wsp->walk_addr = find_next_hash_item(fw)) == 0)
		return (WALK_DONE);

	return (WALK_NEXT);
}

static void
fanout_stack_walk_fini(mdb_walk_state_t *wsp)
{
	fanout_walk_data_t *fw = wsp->walk_data;

	mdb_free(fw, sizeof (*fw));
}

int
fanout_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("sctp_stacks", wsp) == -1) {
		mdb_warn("can't walk 'sctp_stacks'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
fanout_walk_step(mdb_walk_state_t *wsp)
{
	fanout_init_t *fi = wsp->walk_arg;

	if (mdb_pwalk(fi->nested_walker_name, wsp->walk_callback,
	    wsp->walk_cbdata, wsp->walk_addr) == -1) {
		mdb_warn("couldn't walk '%s'for address %p",
		    fi->nested_walker_name, wsp->walk_addr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
sctps_walk_init(mdb_walk_state_t *wsp)
{

	if (mdb_layered_walk("sctp_stacks", wsp) == -1) {
		mdb_warn("can't walk 'sctp_stacks'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
sctps_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;

	kaddr = wsp->walk_addr + OFFSETOF(sctp_stack_t, sctps_g_list);
	if (mdb_pwalk("list", wsp->walk_callback,
	    wsp->walk_cbdata, kaddr) == -1) {
		mdb_warn("couldn't walk 'list' for address %p", kaddr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
sctp_walk_faddr_init(mdb_walk_state_t *wsp)
{
	sctp_t sctp;

	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (mdb_vread(&sctp, sizeof (sctp), wsp->walk_addr) == -1) {
		mdb_warn("failed to read sctp at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	if ((wsp->walk_addr = (uintptr_t)sctp.sctp_faddrs) != 0)
		return (WALK_NEXT);
	else
		return (WALK_DONE);
}

static int
sctp_walk_faddr_step(mdb_walk_state_t *wsp)
{
	uintptr_t faddr_ptr = wsp->walk_addr;
	sctp_faddr_t sctp_faddr;
	int status;

	if (mdb_vread(&sctp_faddr, sizeof (sctp_faddr_t), faddr_ptr) == -1) {
		mdb_warn("failed to read sctp_faddr_t at %p", faddr_ptr);
		return (WALK_ERR);
	}
	status = wsp->walk_callback(faddr_ptr, &sctp_faddr, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);
	if ((faddr_ptr = (uintptr_t)sctp_faddr.sf_next) == 0) {
		return (WALK_DONE);
	} else {
		wsp->walk_addr = faddr_ptr;
		return (WALK_NEXT);
	}
}

/*
 * Helper structure for sctp_walk_saddr.  It stores the sctp_t being walked,
 * the current index to the sctp_saddrs[], and the current count of the
 * sctp_saddr_ipif_t list.
 */
typedef struct {
	sctp_t	sctp;
	int	hash_index;
	int	cur_cnt;
} saddr_walk_t;

static int
sctp_walk_saddr_init(mdb_walk_state_t *wsp)
{
	sctp_t *sctp;
	int i;
	saddr_walk_t *swalker;

	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	swalker = mdb_alloc(sizeof (saddr_walk_t), UM_SLEEP);
	sctp = &swalker->sctp;
	if (mdb_vread(sctp, sizeof (sctp_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read sctp at %p", wsp->walk_addr);
		mdb_free(swalker, sizeof (saddr_walk_t));
		return (WALK_ERR);
	}

	/* Find the first source address. */
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		if (sctp->sctp_saddrs[i].ipif_count > 0) {
			list_t *addr_list;

			addr_list = &sctp->sctp_saddrs[i].sctp_ipif_list;
			wsp->walk_addr = (uintptr_t)list_object(addr_list,
			    addr_list->list_head.list_next);

			/* Recode the current info */
			swalker->hash_index = i;
			swalker->cur_cnt = 1;
			wsp->walk_data = swalker;

			return (WALK_NEXT);
		}
	}
	return (WALK_DONE);
}

static int
sctp_walk_saddr_step(mdb_walk_state_t *wsp)
{
	uintptr_t saddr_ptr = wsp->walk_addr;
	sctp_saddr_ipif_t saddr;
	saddr_walk_t *swalker;
	sctp_t *sctp;
	int status;
	int i, j;

	if (mdb_vread(&saddr, sizeof (sctp_saddr_ipif_t), saddr_ptr) == -1) {
		mdb_warn("failed to read sctp_saddr_ipif_t at %p", saddr_ptr);
		return (WALK_ERR);
	}
	status = wsp->walk_callback(saddr_ptr, &saddr, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	swalker = (saddr_walk_t *)wsp->walk_data;
	sctp = &swalker->sctp;
	i = swalker->hash_index;
	j = swalker->cur_cnt;

	/*
	 * If there is still a source address in the current list, return it.
	 * Otherwise, go to the next list in the sctp_saddrs[].
	 */
	if (j++ < sctp->sctp_saddrs[i].ipif_count) {
		wsp->walk_addr = (uintptr_t)saddr.saddr_ipif.list_next;
		swalker->cur_cnt = j;
		return (WALK_NEXT);
	} else {
		list_t *lst;

		for (i = i + 1; i < SCTP_IPIF_HASH; i++) {
			if (sctp->sctp_saddrs[i].ipif_count > 0) {
				lst = &sctp->sctp_saddrs[i].sctp_ipif_list;
				wsp->walk_addr = (uintptr_t)list_object(
				    lst, lst->list_head.list_next);
				swalker->hash_index = i;
				swalker->cur_cnt = 1;
				return (WALK_NEXT);
			}
		}
	}
	return (WALK_DONE);
}

static void
sctp_walk_saddr_fini(mdb_walk_state_t *wsp)
{
	saddr_walk_t *swalker = (saddr_walk_t *)wsp->walk_data;

	mdb_free(swalker, sizeof (saddr_walk_t));
}


typedef struct ill_walk_data {
	sctp_ill_hash_t ills[SCTP_ILL_HASH];
	uint32_t	count;
} ill_walk_data_t;

typedef struct ipuf_walk_data {
	sctp_ipif_hash_t ipifs[SCTP_IPIF_HASH];
	uint32_t	count;
} ipif_walk_data_t;


int
sctp_ill_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("sctp_stacks", wsp) == -1) {
		mdb_warn("can't walk 'sctp_stacks'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
sctp_ill_walk_step(mdb_walk_state_t *wsp)
{
	if (mdb_pwalk("sctp_stack_walk_ill", wsp->walk_callback,
	    wsp->walk_cbdata, wsp->walk_addr) == -1) {
		mdb_warn("couldn't walk 'sctp_stack_walk_ill' for addr %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/*
 * wsp->walk_addr is the address of sctps_ill_list
 */
static int
sctp_stack_ill_walk_init(mdb_walk_state_t *wsp)
{
	ill_walk_data_t iw;
	intptr_t i;
	uintptr_t kaddr, uaddr;
	size_t offset;

	kaddr = wsp->walk_addr + OFFSETOF(sctp_stack_t, sctps_ills_count);
	if (mdb_vread(&iw.count, sizeof (iw.count), kaddr) == -1) {
		mdb_warn("can't read sctps_ills_count at %p", kaddr);
		return (WALK_ERR);
	}
	kaddr = wsp->walk_addr + OFFSETOF(sctp_stack_t, sctps_g_ills);

	if (mdb_vread(&kaddr, sizeof (kaddr), kaddr) == -1) {
		mdb_warn("can't read scpts_g_ills %p", kaddr);
		return (WALK_ERR);
	}
	if (mdb_vread(&iw.ills, sizeof (iw.ills), kaddr) == -1) {
		mdb_warn("failed to read 'sctps_g_ills'");
		return (0);
	}

	/* Find the first ill. */
	for (i = 0; i < SCTP_ILL_HASH; i++) {
		if (iw.ills[i].ill_count > 0) {
			uaddr = (uintptr_t)&iw.ills[i].sctp_ill_list;
			offset = uaddr - (uintptr_t)&iw.ills;
			if (mdb_pwalk("list", wsp->walk_callback,
			    wsp->walk_cbdata, kaddr+offset) == -1) {
				mdb_warn("couldn't walk 'list' for address %p",
				    kaddr);
				return (WALK_ERR);
			}
		}
	}
	return (WALK_DONE);
}

static int
sctp_stack_ill_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

int
sctp_ipif_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("sctp_stacks", wsp) == -1) {
		mdb_warn("can't walk 'sctp_stacks'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
sctp_ipif_walk_step(mdb_walk_state_t *wsp)
{
	if (mdb_pwalk("sctp_stack_walk_ipif", wsp->walk_callback,
	    wsp->walk_cbdata, wsp->walk_addr) == -1) {
		mdb_warn("couldn't walk 'sctp_stack_walk_ipif' for addr %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/*
 * wsp->walk_addr is the address of sctps_ipif_list
 */
static int
sctp_stack_ipif_walk_init(mdb_walk_state_t *wsp)
{
	ipif_walk_data_t iw;
	intptr_t i;
	uintptr_t kaddr, uaddr;
	size_t offset;

	kaddr = wsp->walk_addr + OFFSETOF(sctp_stack_t, sctps_g_ipifs_count);
	if (mdb_vread(&iw.count, sizeof (iw.count), kaddr) == -1) {
		mdb_warn("can't read sctps_g_ipifs_count at %p", kaddr);
		return (WALK_ERR);
	}
	kaddr = wsp->walk_addr + OFFSETOF(sctp_stack_t, sctps_g_ipifs);

	if (mdb_vread(&kaddr, sizeof (kaddr), kaddr) == -1) {
		mdb_warn("can't read scpts_g_ipifs %p", kaddr);
		return (WALK_ERR);
	}
	if (mdb_vread(&iw.ipifs, sizeof (iw.ipifs), kaddr) == -1) {
		mdb_warn("failed to read 'sctps_g_ipifs'");
		return (0);
	}

	/* Find the first ipif. */
	for (i = 0; i < SCTP_IPIF_HASH; i++) {
		if (iw.ipifs[i].ipif_count > 0) {
			uaddr = (uintptr_t)&iw.ipifs[i].sctp_ipif_list;
			offset = uaddr - (uintptr_t)&iw.ipifs;
			if (mdb_pwalk("list", wsp->walk_callback,
			    wsp->walk_cbdata, kaddr+offset) == -1) {
				mdb_warn("couldn't walk 'list' for address %p",
				    kaddr);
				return (WALK_ERR);
			}
		}
	}
	return (WALK_DONE);
}

static int
sctp_stack_ipif_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * Initialization function for the per CPU SCTP stats counter walker of a given
 * SCTP stack.
 */
int
sctps_sc_walk_init(mdb_walk_state_t *wsp)
{
	sctp_stack_t sctps;

	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (mdb_vread(&sctps, sizeof (sctps), wsp->walk_addr) == -1) {
		mdb_warn("failed to read sctp_stack_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	if (sctps.sctps_sc_cnt == 0)
		return (WALK_DONE);

	/*
	 * Store the sctp_stack_t pointer in walk_data.  The stepping function
	 * used it to calculate if the end of the counter has reached.
	 */
	wsp->walk_data = (void *)wsp->walk_addr;
	wsp->walk_addr = (uintptr_t)sctps.sctps_sc;
	return (WALK_NEXT);
}

/*
 * Stepping function for the per CPU SCTP stats counterwalker.
 */
int
sctps_sc_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	sctp_stack_t sctps;
	sctp_stats_cpu_t *stats;
	char *next, *end;

	if (mdb_vread(&sctps, sizeof (sctps), (uintptr_t)wsp->walk_data) ==
	    -1) {
		mdb_warn("failed to read sctp_stack_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	if (mdb_vread(&stats, sizeof (stats), wsp->walk_addr) == -1) {
		mdb_warn("failed ot read sctp_stats_cpu_t at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	status = wsp->walk_callback((uintptr_t)stats, &stats, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	next = (char *)wsp->walk_addr + sizeof (sctp_stats_cpu_t *);
	end = (char *)sctps.sctps_sc + sctps.sctps_sc_cnt *
	    sizeof (sctp_stats_cpu_t *);
	if (next >= end)
		return (WALK_DONE);
	wsp->walk_addr = (uintptr_t)next;
	return (WALK_NEXT);
}

static void
sctp_help(void)
{
	mdb_printf("Print information for a given SCTP sctp_t\n\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-a\t All the information\n");
	mdb_printf("\t-f\t Flags\n");
	mdb_printf("\t-h\t Hash Tables\n");
	mdb_printf("\t-o\t Outbound Data\n");
	mdb_printf("\t-i\t Inbound Data\n");
	mdb_printf("\t-m\t Miscellaneous Information\n");
	mdb_printf("\t-r\t RTT Tracking\n");
	mdb_printf("\t-S\t Stats Counters\n");
	mdb_printf("\t-F\t Flow Control\n");
	mdb_printf("\t-H\t Composite Headers\n");
	mdb_printf("\t-p\t PMTUD\n");
	mdb_printf("\t-R\t Retransmit Information\n");
	mdb_printf("\t-C\t Connection State\n");
	mdb_printf("\t-c\t Cleanup / Close\n");
	mdb_printf("\t-e\t Extensions and Reliable Control Chunks\n");
	mdb_printf("\t-d\t Local and Peer addresses\n");
	mdb_printf("\t-P\t Peer addresses\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "sctp", ":[-afhoimrSFHpRCcedP]",
	    "display sctp control structure", sctp, sctp_help },
	{ "sctp_set", ":", "display a SCTP set", sctp_set },
	{ "sctp_faddr", ":", "display a faddr", sctp_faddr },
	{ "sctp_istr_msgs", ":", "display msg list on an instream",
	    sctp_istr_msgs },
	{ "sctp_mdata_chunk", ":", "display a data chunk in an mblk",
	    sctp_mdata_chunk },
	{ "sctp_xmit_list", ":", "display sctp xmit lists", sctp_xmit_list },
	{ "sctp_instr", ":", "display instr", sctp_instr },
	{ "sctp_reass_list", ":", "display reass list", sctp_reass_list },
	{ "sctp_uo_reass_list", ":", "display un-ordered reass list",
	    sctp_uo_reass_list },
	{ NULL }
};

static const fanout_init_t listen_fanout_init = {
	"sctp_stack_listen_fanout", OFFSETOF(sctp_stack_t, sctps_listen_fanout),
	listen_size, listen_next
};

static const fanout_init_t conn_fanout_init = {
	"sctp_stack_conn_fanout",  OFFSETOF(sctp_stack_t, sctps_conn_fanout),
	conn_size, conn_next
};

static const fanout_init_t bind_fanout_init = {
	"sctp_stack_bind_fanout", OFFSETOF(sctp_stack_t, sctps_bind_fanout),
	bind_size, bind_next
};

static const mdb_walker_t walkers[] = {
	{ "sctps", "walk the full chain of sctps for all stacks",
	    sctps_walk_init, sctps_walk_step, NULL },
	{ "sctp_listen_fanout", "walk the sctp listen fanout for all stacks",
	    fanout_walk_init, fanout_walk_step, NULL,
	    (void *)&listen_fanout_init },
	{ "sctp_conn_fanout", "walk the sctp conn fanout for all stacks",
	    fanout_walk_init, fanout_walk_step, NULL,
	    (void *)&conn_fanout_init },
	{ "sctp_bind_fanout", "walk the sctp bind fanout for all stacks",
	    fanout_walk_init, fanout_walk_step, NULL,
	    (void *)&bind_fanout_init },
	{ "sctp_stack_listen_fanout",
	    "walk the sctp listen fanout for one stack",
	    fanout_stack_walk_init, fanout_stack_walk_step,
	    fanout_stack_walk_fini,
	    (void *)&listen_fanout_init },
	{ "sctp_stack_conn_fanout", "walk the sctp conn fanout for one stack",
	    fanout_stack_walk_init, fanout_stack_walk_step,
	    fanout_stack_walk_fini,
	    (void *)&conn_fanout_init },
	{ "sctp_stack_bind_fanout", "walk the sctp bind fanoutfor one stack",
	    fanout_stack_walk_init, fanout_stack_walk_step,
	    fanout_stack_walk_fini,
	    (void *)&bind_fanout_init },
	{ "sctp_walk_faddr", "walk the peer address list of a given sctp_t",
	    sctp_walk_faddr_init, sctp_walk_faddr_step, NULL },
	{ "sctp_walk_saddr", "walk the local address list of a given sctp_t",
	    sctp_walk_saddr_init, sctp_walk_saddr_step, sctp_walk_saddr_fini },
	{ "sctp_walk_ill", "walk the sctp_g_ills list for all stacks",
	    sctp_ill_walk_init, sctp_ill_walk_step, NULL },
	{ "sctp_walk_ipif", "walk the sctp_g_ipif list for all stacks",
		sctp_ipif_walk_init, sctp_ipif_walk_step, NULL },
	{ "sctp_stack_walk_ill", "walk the sctp_g_ills list for one stack",
		sctp_stack_ill_walk_init, sctp_stack_ill_walk_step, NULL },
	{ "sctp_stack_walk_ipif", "walk the sctp_g_ipif list for one stack",
		sctp_stack_ipif_walk_init, sctp_stack_ipif_walk_step, NULL },
	{ "sctps_sc", "walk all the per CPU stats counters of a sctp_stack_t",
		sctps_sc_walk_init, sctps_sc_walk_step, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
