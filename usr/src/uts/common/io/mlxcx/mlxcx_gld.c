/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2021, the University of Queensland
 * Copyright 2020 RackTop Systems, Inc.
 * Copyright 2023 MNX Cloud, Inc.
 */

/*
 * Mellanox Connect-X 4/5/6 driver.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/sysmacros.h>
#include <sys/vlan.h>

#include <sys/pattr.h>
#include <sys/dlpi.h>

#include <sys/mac_provider.h>

/* Need these for mac_vlan_header_info() */
#include <sys/mac_client.h>
#include <sys/mac_client_priv.h>

#include <mlxcx.h>

static char *mlxcx_priv_props[] = {
	NULL
};

#define	MBITS		1000000ULL
#define	GBITS		(1000ULL * MBITS)

static uint64_t
mlxcx_speed_to_bits(mlxcx_eth_proto_t proto, mlxcx_ext_eth_proto_t ext_proto)
{
	/*
	 * Older parts only used "proto", but starting with ConnectX-6, there
	 * might be speeds & link-types in an extended set of proto bits.
	 *
	 * We check the old bits first because the extended bits do not report
	 * media on links (e.g. nothing like MLXCX_EXTPROTO_100GBASE_CR2
	 * for a 50Gbit lane).
	 *
	 * In the case of, e.g., 100GBASE_CR4 both proto and ext_proto have
	 * bits set, but the extended proto bits are a generic CAUI4 indicator
	 * that could be for CR4, KR4, etc. If we get a legitimate single-bit
	 * value, we don't worry about ext_proto. This may change in the face
	 * of other HW or cabling, however.
	 */
	switch (proto) {
	case MLXCX_PROTO_NONE:	/* Aka "0" */
		/* Go straight to checking ext_proto. */
		break;
	case MLXCX_PROTO_SGMII_100BASE:
	case MLXCX_PROTO_100BASE_TX:
		return (100ULL * MBITS);
	case MLXCX_PROTO_SGMII:
	case MLXCX_PROTO_1000BASE_KX:
	case MLXCX_PROTO_1000BASE_T:
		return (1000ULL * MBITS);
	case MLXCX_PROTO_10GBASE_CX4:
	case MLXCX_PROTO_10GBASE_KX4:
	case MLXCX_PROTO_10GBASE_KR:
	case MLXCX_PROTO_10GBASE_CR:
	case MLXCX_PROTO_10GBASE_SR:
	case MLXCX_PROTO_10GBASE_ER_LR:
	case MLXCX_PROTO_10GBASE_T:
		return (10ULL * GBITS);
	case MLXCX_PROTO_40GBASE_CR4:
	case MLXCX_PROTO_40GBASE_KR4:
	case MLXCX_PROTO_40GBASE_SR4:
	case MLXCX_PROTO_40GBASE_LR4_ER4:
		return (40ULL * GBITS);
	case MLXCX_PROTO_25GBASE_CR:
	case MLXCX_PROTO_25GBASE_KR:
	case MLXCX_PROTO_25GBASE_SR:
		return (25ULL * GBITS);
	case MLXCX_PROTO_50GBASE_SR2:
	case MLXCX_PROTO_50GBASE_CR2:
	case MLXCX_PROTO_50GBASE_KR2:
		return (50ULL * GBITS);
	case MLXCX_PROTO_100GBASE_CR4:
	case MLXCX_PROTO_100GBASE_SR4:
	case MLXCX_PROTO_100GBASE_KR4:
	case MLXCX_PROTO_100GBASE_LR4_ER4:
		return (100ULL * GBITS);
	default:
		/*
		 * We've checked for 0 explicitly above, so don't worry here.
		 *
		 * There ARE legitimate single-bit values we don't support,
		 * and should just return 0 immediately.  We will ASSERT()
		 * that it's a single-bit value, however, since the passed-in
		 * values are from the "operational" register, which is only
		 * supposed to have one bit set. If the assertion fails
		 * there's either a hardware error or a severe
		 * misunderstanding of the register.
		 */
		ASSERT0((uint32_t)proto & ((uint32_t)proto - 1U));
		return (0);
	}

	switch (ext_proto) {
	case MLXCX_EXTPROTO_SGMII_100BASE:
		return (100ULL * MBITS);
	case MLXCX_EXTPROTO_1000BASE_X_SGMII:
		return (1000ULL * MBITS);
	case MLXCX_EXTPROTO_5GBASE_R:
		return (5ULL * GBITS);
	case MLXCX_EXTPROTO_10GBASE_XFI_XAUI_1:
		return (10ULL * GBITS);
	case MLXCX_EXTPROTO_40GBASE_XLAUI_4_XLPPI_4:
		return (40ULL * GBITS);
	case MLXCX_EXTPROTO_25GAUI_1_25GBASE_CR_KR:
		return (25ULL * GBITS);
	case MLXCX_EXTPROTO_50GAUI_2_LAUI_2_50GBASE_CR2_KR2:
	case MLXCX_EXTPROTO_50GAUI_1_LAUI_1_50GBASE_CR_KR:
		return (50ULL * GBITS);
	case MLXCX_EXTPROTO_CAUI_4_100GBASE_CR4_KR4:
	case MLXCX_EXTPROTO_100GAUI_2_100GBASE_CR2_KR2:
	case MLXCX_EXTPROTO_100GAUI_1_100GBASE_CR_KR:
		return (100ULL * GBITS);
	case MLXCX_EXTPROTO_200GAUI_4_200GBASE_CR4_KR4:
	case MLXCX_EXTPROTO_200GAUI_2_200GBASE_CR2_KR2:
		return (200ULL * GBITS);
	case MLXCX_EXTPROTO_400GAUI_8_400GBASE_CR8:
	case MLXCX_EXTPROTO_400GAUI_4_400GBASE_CR4:
		return (400ULL * GBITS);
	default:
		/*
		 * There ARE legitimate single-bit values we don't support,
		 * and should just return 0 immediately.  We will ASSERT()
		 * that it's a single-bit value, however, for reasons detailed
		 * in the prior `default` case.
		 */
		ASSERT0((uint32_t)ext_proto & ((uint32_t)ext_proto - 1U));
		break;
	}

	return (0);
}

static link_fec_t
mlxcx_fec_to_link_fec(mlxcx_pplm_fec_active_t mlxcx_fec)
{
	if ((mlxcx_fec & MLXCX_PPLM_FEC_ACTIVE_NONE) != 0)
		return (LINK_FEC_NONE);

	if ((mlxcx_fec & MLXCX_PPLM_FEC_ACTIVE_FIRECODE) != 0)
		return (LINK_FEC_BASE_R);

	if ((mlxcx_fec & (MLXCX_PPLM_FEC_ACTIVE_RS528 |
	    MLXCX_PPLM_FEC_ACTIVE_RS271 | MLXCX_PPLM_FEC_ACTIVE_RS544 |
	    MLXCX_PPLM_FEC_ACTIVE_RS272)) != 0)
		return (LINK_FEC_RS);

	return (LINK_FEC_NONE);
}

static boolean_t
mlxcx_link_fec_cap(link_fec_t fec, mlxcx_pplm_fec_caps_t *pfecp)
{
	mlxcx_pplm_fec_caps_t pplm_fec = 0;

	if ((fec & LINK_FEC_AUTO) != 0) {
		pplm_fec = MLXCX_PPLM_FEC_CAP_AUTO;
		fec &= ~LINK_FEC_AUTO;
	} else if ((fec & LINK_FEC_NONE) != 0) {
		pplm_fec = MLXCX_PPLM_FEC_CAP_NONE;
		fec &= ~LINK_FEC_NONE;
	} else if ((fec & LINK_FEC_RS) != 0) {
		pplm_fec |= MLXCX_PPLM_FEC_CAP_RS;
		fec &= ~LINK_FEC_RS;
	} else if ((fec & LINK_FEC_BASE_R) != 0) {
		pplm_fec |= MLXCX_PPLM_FEC_CAP_FIRECODE;
		fec &= ~LINK_FEC_BASE_R;
	}

	/*
	 * Only one fec option is allowed.
	 */
	if (fec != 0)
		return (B_FALSE);

	*pfecp = pplm_fec;

	return (B_TRUE);
}

static int
mlxcx_mac_stat_rfc_2863(mlxcx_t *mlxp, mlxcx_port_t *port, uint_t stat,
    uint64_t *val)
{
	int ret = 0;
	boolean_t ok;
	mlxcx_register_data_t data;
	mlxcx_ppcnt_rfc_2863_t *st;

	ASSERT(mutex_owned(&port->mlp_mtx));

	bzero(&data, sizeof (data));
	data.mlrd_ppcnt.mlrd_ppcnt_local_port = port->mlp_num + 1;
	data.mlrd_ppcnt.mlrd_ppcnt_grp = MLXCX_PPCNT_GRP_RFC_2863;
	data.mlrd_ppcnt.mlrd_ppcnt_clear = MLXCX_PPCNT_NO_CLEAR;

	ok = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_PPCNT, &data);
	if (!ok)
		return (EIO);
	st = &data.mlrd_ppcnt.mlrd_ppcnt_rfc_2863;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = from_be64(st->mlppc_rfc_2863_in_octets);
		break;
	case MAC_STAT_MULTIRCV:
		*val = from_be64(st->mlppc_rfc_2863_in_mcast_pkts);
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = from_be64(st->mlppc_rfc_2863_in_bcast_pkts);
		break;
	case MAC_STAT_MULTIXMT:
		*val = from_be64(st->mlppc_rfc_2863_out_mcast_pkts);
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = from_be64(st->mlppc_rfc_2863_out_bcast_pkts);
		break;
	case MAC_STAT_IERRORS:
		*val = from_be64(st->mlppc_rfc_2863_in_errors);
		break;
	case MAC_STAT_UNKNOWNS:
		*val = from_be64(st->mlppc_rfc_2863_in_unknown_protos);
		break;
	case MAC_STAT_OERRORS:
		*val = from_be64(st->mlppc_rfc_2863_out_errors);
		break;
	case MAC_STAT_OBYTES:
		*val = from_be64(st->mlppc_rfc_2863_out_octets);
		break;
	default:
		ret = ENOTSUP;
	}

	return (ret);
}

static int
mlxcx_mac_stat_ieee_802_3(mlxcx_t *mlxp, mlxcx_port_t *port, uint_t stat,
    uint64_t *val)
{
	int ret = 0;
	boolean_t ok;
	mlxcx_register_data_t data;
	mlxcx_ppcnt_ieee_802_3_t *st;

	ASSERT(mutex_owned(&port->mlp_mtx));

	bzero(&data, sizeof (data));
	data.mlrd_ppcnt.mlrd_ppcnt_local_port = port->mlp_num + 1;
	data.mlrd_ppcnt.mlrd_ppcnt_grp = MLXCX_PPCNT_GRP_IEEE_802_3;
	data.mlrd_ppcnt.mlrd_ppcnt_clear = MLXCX_PPCNT_NO_CLEAR;

	ok = mlxcx_cmd_access_register(mlxp, MLXCX_CMD_ACCESS_REGISTER_READ,
	    MLXCX_REG_PPCNT, &data);
	if (!ok)
		return (EIO);
	st = &data.mlrd_ppcnt.mlrd_ppcnt_ieee_802_3;

	switch (stat) {
	case MAC_STAT_IPACKETS:
		*val = from_be64(st->mlppc_ieee_802_3_frames_rx);
		break;
	case MAC_STAT_OPACKETS:
		*val = from_be64(st->mlppc_ieee_802_3_frames_tx);
		break;
	case ETHER_STAT_ALIGN_ERRORS:
		*val = from_be64(st->mlppc_ieee_802_3_align_err);
		break;
	case ETHER_STAT_FCS_ERRORS:
		*val = from_be64(st->mlppc_ieee_802_3_fcs_err);
		break;
	case ETHER_STAT_TOOLONG_ERRORS:
		*val = from_be64(st->mlppc_ieee_802_3_frame_too_long_err);
		break;
	default:
		ret = ENOTSUP;
	}

	return (ret);
}

static int
mlxcx_mac_stat(void *arg, uint_t stat, uint64_t *val)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_port_t *port = &mlxp->mlx_ports[0];
	int ret = 0;

	mutex_enter(&port->mlp_mtx);

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = mlxcx_speed_to_bits(port->mlp_oper_proto,
		    port->mlp_ext_oper_proto);
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
		break;
	case MAC_STAT_RBYTES:
	case MAC_STAT_MULTIRCV:
	case MAC_STAT_BRDCSTRCV:
	case MAC_STAT_MULTIXMT:
	case MAC_STAT_BRDCSTXMT:
	case MAC_STAT_IERRORS:
	case MAC_STAT_UNKNOWNS:
	case MAC_STAT_OERRORS:
	case MAC_STAT_OBYTES:
		ret = mlxcx_mac_stat_rfc_2863(mlxp, port, stat, val);
		break;
	case MAC_STAT_IPACKETS:
	case MAC_STAT_OPACKETS:
	case ETHER_STAT_ALIGN_ERRORS:
	case ETHER_STAT_FCS_ERRORS:
	case ETHER_STAT_TOOLONG_ERRORS:
		ret = mlxcx_mac_stat_ieee_802_3(mlxp, port, stat, val);
		break;
	case MAC_STAT_NORCVBUF:
		*val = port->mlp_stats.mlps_rx_drops;
		break;
	default:
		ret = ENOTSUP;
	}

	mutex_exit(&port->mlp_mtx);

	return (ret);
}

static int
mlxcx_mac_led_set(void *arg, mac_led_mode_t mode, uint_t flags)
{
	mlxcx_t *mlxp = arg;
	mlxcx_port_t *port = &mlxp->mlx_ports[0];
	int ret = 0;

	if (flags != 0) {
		return (EINVAL);
	}

	mutex_enter(&port->mlp_mtx);

	switch (mode) {
	case MAC_LED_DEFAULT:
	case MAC_LED_OFF:
		if (!mlxcx_cmd_set_port_led(mlxp, port, 0)) {
			ret = EIO;
			break;
		}
		break;
	case MAC_LED_IDENT:
		if (!mlxcx_cmd_set_port_led(mlxp, port, UINT16_MAX)) {
			ret = EIO;
			break;
		}
		break;
	default:
		ret = ENOTSUP;
	}

	mutex_exit(&port->mlp_mtx);

	return (ret);
}

static int
mlxcx_mac_txr_info(void *arg, uint_t id, mac_transceiver_info_t *infop)
{
	mlxcx_t *mlxp = arg;
	mlxcx_module_status_t st;

	if (!mlxcx_cmd_query_module_status(mlxp, id, &st, NULL))
		return (EIO);

	if (st != MLXCX_MODULE_UNPLUGGED)
		mac_transceiver_info_set_present(infop, B_TRUE);

	if (st == MLXCX_MODULE_PLUGGED)
		mac_transceiver_info_set_usable(infop, B_TRUE);

	return (0);
}

static int
mlxcx_mac_txr_read(void *arg, uint_t id, uint_t page, void *vbuf,
    size_t nbytes, off_t offset, size_t *nread)
{
	mlxcx_t *mlxp = arg;
	mlxcx_register_data_t data;
	uint8_t *buf = vbuf;
	boolean_t ok;
	size_t take, done = 0;
	uint8_t i2c_addr;

	if (id != 0 || vbuf == NULL || nbytes == 0 || nread == NULL)
		return (EINVAL);

	if (nbytes > 256 || offset >= 256 || (offset + nbytes > 256))
		return (EINVAL);

	/*
	 * The PRM is really not very clear about any of this, but it seems
	 * that the i2c_device_addr field in MCIA is the SFP+ spec "page"
	 * number shifted right by 1 bit. They're written in the SFF spec
	 * like "1010000X" so Mellanox just dropped the X.
	 *
	 * This means that if we want page 0xA0, we put 0x50 in the
	 * i2c_device_addr field.
	 *
	 * The "page_number" field in MCIA means something else. Don't ask me
	 * what. FreeBSD leaves it as zero, so we will too!
	 */
	i2c_addr = page >> 1;

	while (done < nbytes) {
		take = nbytes - done;
		if (take > sizeof (data.mlrd_mcia.mlrd_mcia_data))
			take = sizeof (data.mlrd_mcia.mlrd_mcia_data);

		bzero(&data, sizeof (data));
		ASSERT3U(id, <=, 0xff);
		data.mlrd_mcia.mlrd_mcia_module = (uint8_t)id;
		data.mlrd_mcia.mlrd_mcia_i2c_device_addr = i2c_addr;
		data.mlrd_mcia.mlrd_mcia_device_addr = to_be16(offset);
		data.mlrd_mcia.mlrd_mcia_size = to_be16(take);

		ok = mlxcx_cmd_access_register(mlxp,
		    MLXCX_CMD_ACCESS_REGISTER_READ, MLXCX_REG_MCIA, &data);
		if (!ok) {
			*nread = 0;
			return (EIO);
		}

		if (data.mlrd_mcia.mlrd_mcia_status != MLXCX_MCIA_STATUS_OK) {
			*nread = 0;
			return (EIO);
		}

		bcopy(data.mlrd_mcia.mlrd_mcia_data, &buf[done], take);

		done += take;
		offset += take;
	}
	*nread = done;
	return (0);
}

static int
mlxcx_mac_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	mlxcx_work_queue_t *wq = (mlxcx_work_queue_t *)rh;
	(void) wq;

	/*
	 * We should add support for using hw flow counters and such to
	 * get per-ring statistics. Not done yet though!
	 */

	switch (stat) {
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

static int
mlxcx_mac_start(void *arg)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	(void) mlxp;
	return (0);
}

static void
mlxcx_mac_stop(void *arg)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	(void) mlxp;
}

static mblk_t *
mlxcx_mac_ring_tx(void *arg, mblk_t *mp)
{
	mlxcx_work_queue_t *sq = (mlxcx_work_queue_t *)arg;
	mlxcx_t *mlxp = sq->mlwq_mlx;
	mlxcx_completion_queue_t *cq;
	mlxcx_buffer_t *b;
	mac_header_info_t mhi;
	mblk_t *kmp, *nmp;
	uint8_t inline_hdrs[MLXCX_MAX_INLINE_HEADERLEN];
	size_t inline_hdrlen, rem, off;
	uint32_t chkflags = 0;
	boolean_t ok;
	size_t take = 0;
	uint_t bcount;

	VERIFY(mp->b_next == NULL);

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &chkflags);

	if (mac_vlan_header_info(mlxp->mlx_mac_hdl, mp, &mhi) != 0) {
		/*
		 * We got given a frame without a valid L2 header on it. We
		 * can't really transmit that (mlx parts don't like it), so
		 * we will just drop it on the floor.
		 */
		freemsg(mp);
		return (NULL);
	}

	inline_hdrlen = rem = mhi.mhi_hdrsize;

	kmp = mp;
	off = 0;
	while (rem > 0) {
		const ptrdiff_t sz = MBLKL(kmp);
		ASSERT3S(sz, >=, 0);
		ASSERT3U(sz, <=, SIZE_MAX);
		take = sz;
		if (take > rem)
			take = rem;
		bcopy(kmp->b_rptr, inline_hdrs + off, take);
		rem -= take;
		off += take;
		if (take == sz) {
			take = 0;
			kmp = kmp->b_cont;
		}
	}

	bcount = mlxcx_buf_bind_or_copy(mlxp, sq, kmp, take, &b);
	if (bcount == 0) {
		atomic_or_uint(&sq->mlwq_state, MLXCX_WQ_BLOCKED_MAC);
		return (mp);
	}

	mutex_enter(&sq->mlwq_mtx);
	VERIFY3U(sq->mlwq_inline_mode, <=, MLXCX_ETH_INLINE_L2);
	cq = sq->mlwq_cq;

	/*
	 * state is a single int, so read-only access without the CQ lock
	 * should be fine.
	 */
	if (cq->mlcq_state & MLXCX_CQ_TEARDOWN) {
		mutex_exit(&sq->mlwq_mtx);
		mlxcx_buf_return_chain(mlxp, b, B_FALSE);
		return (NULL);
	}

	if ((sq->mlwq_state & (MLXCX_WQ_TEARDOWN | MLXCX_WQ_STARTED)) !=
	    MLXCX_WQ_STARTED) {
		mutex_exit(&sq->mlwq_mtx);
		mlxcx_buf_return_chain(mlxp, b, B_FALSE);
		return (NULL);
	}

	/*
	 * If the completion queue buffer count is already at or above
	 * the high water mark, or the addition of this new chain will
	 * exceed the CQ ring size, then indicate we are blocked.
	 */
	if (cq->mlcq_bufcnt >= cq->mlcq_bufhwm ||
	    (cq->mlcq_bufcnt + bcount) > cq->mlcq_nents) {
		atomic_or_uint(&cq->mlcq_state, MLXCX_CQ_BLOCKED_MAC);
		goto blocked;
	}

	if (sq->mlwq_wqebb_used >= sq->mlwq_bufhwm) {
		atomic_or_uint(&sq->mlwq_state, MLXCX_WQ_BLOCKED_MAC);
		goto blocked;
	}

	ok = mlxcx_sq_add_buffer(mlxp, sq, inline_hdrs, inline_hdrlen,
	    chkflags, b);
	if (!ok) {
		atomic_or_uint(&cq->mlcq_state, MLXCX_CQ_BLOCKED_MAC);
		atomic_or_uint(&sq->mlwq_state, MLXCX_WQ_BLOCKED_MAC);
		goto blocked;
	}

	/*
	 * Now that we've successfully enqueued the rest of the packet,
	 * free any mblks that we cut off while inlining headers.
	 */
	for (; mp != kmp; mp = nmp) {
		nmp = mp->b_cont;
		freeb(mp);
	}

	mutex_exit(&sq->mlwq_mtx);

	return (NULL);

blocked:
	mutex_exit(&sq->mlwq_mtx);
	mlxcx_buf_return_chain(mlxp, b, B_TRUE);
	return (mp);
}

static int
mlxcx_mac_setpromisc(void *arg, boolean_t on)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_port_t *port = &mlxp->mlx_ports[0];
	mlxcx_flow_group_t *fg;
	mlxcx_flow_entry_t *fe;
	mlxcx_flow_table_t *ft;
	mlxcx_ring_group_t *g;
	int ret = 0;
	uint_t idx;

	mutex_enter(&port->mlp_mtx);

	/*
	 * First, do the top-level flow entry on the root flow table for
	 * the port. This catches all traffic that doesn't match any MAC
	 * MAC filters.
	 */
	ft = port->mlp_rx_flow;
	mutex_enter(&ft->mlft_mtx);
	fg = port->mlp_promisc;
	fe = list_head(&fg->mlfg_entries);
	if (on && !(fe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED)) {
		if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
			ret = EIO;
		}
	} else if (!on && (fe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED)) {
		if (!mlxcx_cmd_delete_flow_table_entry(mlxp, fe)) {
			ret = EIO;
		}
	}
	mutex_exit(&ft->mlft_mtx);

	/*
	 * If we failed to change the top-level entry, don't bother with
	 * trying the per-group ones.
	 */
	if (ret != 0) {
		mutex_exit(&port->mlp_mtx);
		return (ret);
	}

	/*
	 * Then, do the per-rx-group flow entries which catch traffic that
	 * matched a MAC filter but failed to match a VLAN filter.
	 */
	for (idx = 0; idx < mlxp->mlx_rx_ngroups; ++idx) {
		g = &mlxp->mlx_rx_groups[idx];

		mutex_enter(&g->mlg_mtx);

		ft = g->mlg_rx_vlan_ft;
		mutex_enter(&ft->mlft_mtx);

		fg = g->mlg_rx_vlan_promisc_fg;
		fe = list_head(&fg->mlfg_entries);
		if (on && !(fe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED)) {
			if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
				ret = EIO;
			}
		} else if (!on && (fe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED)) {
			if (!mlxcx_cmd_delete_flow_table_entry(mlxp, fe)) {
				ret = EIO;
			}
		}

		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
	}

	mutex_exit(&port->mlp_mtx);
	return (ret);
}

static int
mlxcx_mac_multicast(void *arg, boolean_t add, const uint8_t *addr)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_port_t *port = &mlxp->mlx_ports[0];
	mlxcx_ring_group_t *g = &mlxp->mlx_rx_groups[0];
	int ret = 0;

	mutex_enter(&port->mlp_mtx);
	mutex_enter(&g->mlg_mtx);
	if (add) {
		if (!mlxcx_add_umcast_entry(mlxp, port, g, addr)) {
			ret = EIO;
		}
	} else {
		if (!mlxcx_remove_umcast_entry(mlxp, port, g, addr)) {
			ret = EIO;
		}
	}
	mutex_exit(&g->mlg_mtx);
	mutex_exit(&port->mlp_mtx);
	return (ret);
}

static int
mlxcx_group_add_mac(void *arg, const uint8_t *mac_addr)
{
	mlxcx_ring_group_t *g = arg;
	mlxcx_t *mlxp = g->mlg_mlx;
	mlxcx_port_t *port = g->mlg_port;
	int ret = 0;

	mutex_enter(&port->mlp_mtx);
	mutex_enter(&g->mlg_mtx);
	if (!mlxcx_add_umcast_entry(mlxp, port, g, mac_addr)) {
		ret = EIO;
	}
	mutex_exit(&g->mlg_mtx);
	mutex_exit(&port->mlp_mtx);

	return (ret);
}

static int
mlxcx_group_add_vlan(mac_group_driver_t gh, uint16_t vid)
{
	mlxcx_ring_group_t *g = (mlxcx_ring_group_t *)gh;
	mlxcx_t *mlxp = g->mlg_mlx;
	int ret = 0;
	boolean_t tagged = B_TRUE;

	if (vid == MAC_VLAN_UNTAGGED) {
		vid = 0;
		tagged = B_FALSE;
	}

	mutex_enter(&g->mlg_mtx);
	if (!mlxcx_add_vlan_entry(mlxp, g, tagged, vid)) {
		ret = EIO;
	}
	mutex_exit(&g->mlg_mtx);

	return (ret);
}

static int
mlxcx_group_remove_vlan(mac_group_driver_t gh, uint16_t vid)
{
	mlxcx_ring_group_t *g = (mlxcx_ring_group_t *)gh;
	mlxcx_t *mlxp = g->mlg_mlx;
	int ret = 0;
	boolean_t tagged = B_TRUE;

	if (vid == MAC_VLAN_UNTAGGED) {
		vid = 0;
		tagged = B_FALSE;
	}

	mutex_enter(&g->mlg_mtx);
	if (!mlxcx_remove_vlan_entry(mlxp, g, tagged, vid)) {
		ret = EIO;
	}
	mutex_exit(&g->mlg_mtx);

	return (ret);
}

static int
mlxcx_group_remove_mac(void *arg, const uint8_t *mac_addr)
{
	mlxcx_ring_group_t *g = arg;
	mlxcx_t *mlxp = g->mlg_mlx;
	mlxcx_port_t *port = g->mlg_port;
	int ret = 0;

	mutex_enter(&port->mlp_mtx);
	mutex_enter(&g->mlg_mtx);
	if (!mlxcx_remove_umcast_entry(mlxp, port, g, mac_addr)) {
		ret = EIO;
	}
	mutex_exit(&g->mlg_mtx);
	mutex_exit(&port->mlp_mtx);

	return (ret);
}

static int
mlxcx_mac_ring_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	mlxcx_work_queue_t *wq = (mlxcx_work_queue_t *)rh;
	mlxcx_completion_queue_t *cq = wq->mlwq_cq;
	mlxcx_ring_group_t *g = wq->mlwq_group;
	mlxcx_t *mlxp = wq->mlwq_mlx;

	ASSERT(cq != NULL);
	ASSERT(g != NULL);

	ASSERT(wq->mlwq_type == MLXCX_WQ_TYPE_SENDQ ||
	    wq->mlwq_type == MLXCX_WQ_TYPE_RECVQ);
	if (wq->mlwq_type == MLXCX_WQ_TYPE_SENDQ &&
	    !mlxcx_tx_ring_start(mlxp, g, wq))
		return (EIO);
	if (wq->mlwq_type == MLXCX_WQ_TYPE_RECVQ &&
	    !mlxcx_rx_ring_start(mlxp, g, wq))
		return (EIO);

	mutex_enter(&cq->mlcq_mtx);
	cq->mlcq_mac_gen = gen_num;
	mutex_exit(&cq->mlcq_mtx);

	return (0);
}

static void
mlxcx_mac_ring_stop(mac_ring_driver_t rh)
{
	mlxcx_work_queue_t *wq = (mlxcx_work_queue_t *)rh;
	mlxcx_completion_queue_t *cq = wq->mlwq_cq;
	mlxcx_t *mlxp = wq->mlwq_mlx;
	mlxcx_buf_shard_t *s;
	mlxcx_buffer_t *buf;

	/*
	 * To prevent deadlocks and sleeping whilst holding either the
	 * CQ mutex or WQ mutex, we split the stop processing into two
	 * parts.
	 *
	 * With the CQ amd WQ mutexes held the appropriate WQ is stopped.
	 * The Q in the HCA is set to Reset state and flagged as no
	 * longer started. Atomic with changing this WQ state, the buffer
	 * shards are flagged as draining.
	 *
	 * Now, any requests for buffers and attempts to submit messages
	 * will fail and once we're in this state it is safe to relinquish
	 * the CQ and WQ mutexes. Allowing us to complete the ring stop
	 * by waiting for the buffer lists, with the exception of
	 * the loaned list, to drain. Buffers on the loaned list are
	 * not under our control, we will get them back when the mblk tied
	 * to the buffer is freed.
	 */

	mutex_enter(&cq->mlcq_mtx);
	mutex_enter(&wq->mlwq_mtx);

	if (wq->mlwq_state & MLXCX_WQ_STARTED) {
		if (wq->mlwq_type == MLXCX_WQ_TYPE_RECVQ &&
		    !mlxcx_cmd_stop_rq(mlxp, wq)) {
			mutex_exit(&wq->mlwq_mtx);
			mutex_exit(&cq->mlcq_mtx);
			return;
		}
		if (wq->mlwq_type == MLXCX_WQ_TYPE_SENDQ &&
		    !mlxcx_cmd_stop_sq(mlxp, wq)) {
			mutex_exit(&wq->mlwq_mtx);
			mutex_exit(&cq->mlcq_mtx);
			return;
		}
	}
	ASSERT0(wq->mlwq_state & MLXCX_WQ_STARTED);

	mlxcx_shard_draining(wq->mlwq_bufs);
	if (wq->mlwq_foreign_bufs != NULL)
		mlxcx_shard_draining(wq->mlwq_foreign_bufs);


	if (wq->mlwq_state & MLXCX_WQ_BUFFERS) {
		list_t cq_buffers;

		/*
		 * Take the buffers away from the CQ. If the CQ is being
		 * processed and the WQ has been stopped, a completion
		 * which does not match to a buffer will be ignored.
		 */
		list_create(&cq_buffers, sizeof (mlxcx_buffer_t),
		    offsetof(mlxcx_buffer_t, mlb_cq_entry));

		list_move_tail(&cq_buffers, &cq->mlcq_buffers);

		mutex_enter(&cq->mlcq_bufbmtx);
		list_move_tail(&cq_buffers, &cq->mlcq_buffers_b);
		mutex_exit(&cq->mlcq_bufbmtx);

		cq->mlcq_bufcnt = 0;

		mutex_exit(&wq->mlwq_mtx);
		mutex_exit(&cq->mlcq_mtx);

		/* Return any outstanding buffers to the free pool. */
		while ((buf = list_remove_head(&cq_buffers)) != NULL) {
			mlxcx_buf_return_chain(mlxp, buf, B_FALSE);
		}
		list_destroy(&cq_buffers);

		s = wq->mlwq_bufs;
		mutex_enter(&s->mlbs_mtx);
		while (!list_is_empty(&s->mlbs_busy))
			cv_wait(&s->mlbs_free_nonempty, &s->mlbs_mtx);
		while ((buf = list_head(&s->mlbs_free)) != NULL) {
			mlxcx_buf_destroy(mlxp, buf);
		}
		mutex_exit(&s->mlbs_mtx);

		s = wq->mlwq_foreign_bufs;
		if (s != NULL) {
			mutex_enter(&s->mlbs_mtx);
			while (!list_is_empty(&s->mlbs_busy))
				cv_wait(&s->mlbs_free_nonempty, &s->mlbs_mtx);
			while ((buf = list_head(&s->mlbs_free)) != NULL) {
				mlxcx_buf_destroy(mlxp, buf);
			}
			mutex_exit(&s->mlbs_mtx);
		}

		mutex_enter(&wq->mlwq_mtx);
		wq->mlwq_state &= ~MLXCX_WQ_BUFFERS;
		mutex_exit(&wq->mlwq_mtx);
	} else {
		mutex_exit(&wq->mlwq_mtx);
		mutex_exit(&cq->mlcq_mtx);
	}
}

static int
mlxcx_mac_group_start(mac_group_driver_t gh)
{
	mlxcx_ring_group_t *g = (mlxcx_ring_group_t *)gh;
	mlxcx_t *mlxp = g->mlg_mlx;

	VERIFY3S(g->mlg_type, ==, MLXCX_GROUP_RX);
	ASSERT(mlxp != NULL);

	if (g->mlg_state & MLXCX_GROUP_RUNNING)
		return (0);

	if (!mlxcx_rx_group_start(mlxp, g))
		return (EIO);

	return (0);
}

static void
mlxcx_mac_fill_tx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_ring_group_t *g;
	mlxcx_work_queue_t *wq;
	mac_intr_t *mintr = &infop->mri_intr;

	if (rtype != MAC_RING_TYPE_TX)
		return;
	ASSERT3S(group_index, ==, -1);

	g = &mlxp->mlx_tx_groups[0];
	ASSERT(g->mlg_state & MLXCX_GROUP_INIT);
	mutex_enter(&g->mlg_mtx);

	ASSERT3S(ring_index, >=, 0);
	ASSERT3S(ring_index, <, g->mlg_nwqs);

	wq = &g->mlg_wqs[ring_index];

	wq->mlwq_cq->mlcq_mac_hdl = rh;

	infop->mri_driver = (mac_ring_driver_t)wq;
	infop->mri_start = mlxcx_mac_ring_start;
	infop->mri_stop = mlxcx_mac_ring_stop;
	infop->mri_tx = mlxcx_mac_ring_tx;
	infop->mri_stat = mlxcx_mac_ring_stat;

	mintr->mi_ddi_handle = mlxp->mlx_intr_handles[
	    wq->mlwq_cq->mlcq_eq->mleq_intr_index];

	mutex_exit(&g->mlg_mtx);
}

static int
mlxcx_mac_ring_intr_enable(mac_intr_handle_t intrh)
{
	mlxcx_completion_queue_t *cq = (mlxcx_completion_queue_t *)intrh;
	mlxcx_t *mlxp = cq->mlcq_mlx;

	/*
	 * We are going to call mlxcx_arm_cq() here, so we take the arm lock
	 * as well as the CQ one to make sure we don't race against
	 * mlxcx_intr_n().
	 */
	mutex_enter(&cq->mlcq_arm_mtx);
	mutex_enter(&cq->mlcq_mtx);
	if (cq->mlcq_state & MLXCX_CQ_POLLING) {
		atomic_and_uint(&cq->mlcq_state, ~MLXCX_CQ_POLLING);
		if (!(cq->mlcq_state & MLXCX_CQ_ARMED))
			mlxcx_arm_cq(mlxp, cq);
	}
	mutex_exit(&cq->mlcq_mtx);
	mutex_exit(&cq->mlcq_arm_mtx);

	return (0);
}

static int
mlxcx_mac_ring_intr_disable(mac_intr_handle_t intrh)
{
	mlxcx_completion_queue_t *cq = (mlxcx_completion_queue_t *)intrh;

	mutex_enter(&cq->mlcq_mtx);
	atomic_or_uint(&cq->mlcq_state, MLXCX_CQ_POLLING);
	mutex_exit(&cq->mlcq_mtx);

	return (0);
}

static mblk_t *
mlxcx_mac_ring_rx_poll(void *arg, int poll_bytes)
{
	mlxcx_work_queue_t *wq = (mlxcx_work_queue_t *)arg;
	mlxcx_completion_queue_t *cq = wq->mlwq_cq;
	mlxcx_t *mlxp = wq->mlwq_mlx;
	mblk_t *mp;

	ASSERT(cq != NULL);
	ASSERT3S(poll_bytes, >, 0);
	if (poll_bytes == 0)
		return (NULL);

	mutex_enter(&cq->mlcq_mtx);
	mp = mlxcx_rx_poll(mlxp, cq, poll_bytes);
	mutex_exit(&cq->mlcq_mtx);

	return (mp);
}

static void
mlxcx_mac_fill_rx_ring(void *arg, mac_ring_type_t rtype, const int group_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_ring_group_t *g;
	mlxcx_work_queue_t *wq;
	mac_intr_t *mintr = &infop->mri_intr;

	if (rtype != MAC_RING_TYPE_RX)
		return;
	ASSERT3S(group_index, >=, 0);
	ASSERT3S(group_index, <, mlxp->mlx_rx_ngroups);

	g = &mlxp->mlx_rx_groups[group_index];
	ASSERT(g->mlg_state & MLXCX_GROUP_INIT);
	mutex_enter(&g->mlg_mtx);

	ASSERT3S(ring_index, >=, 0);
	ASSERT3S(ring_index, <, g->mlg_nwqs);

	ASSERT(g->mlg_state & MLXCX_GROUP_WQS);
	wq = &g->mlg_wqs[ring_index];

	wq->mlwq_cq->mlcq_mac_hdl = rh;

	infop->mri_driver = (mac_ring_driver_t)wq;
	infop->mri_start = mlxcx_mac_ring_start;
	infop->mri_stop = mlxcx_mac_ring_stop;
	infop->mri_poll = mlxcx_mac_ring_rx_poll;
	infop->mri_stat = mlxcx_mac_ring_stat;

	mintr->mi_handle = (mac_intr_handle_t)wq->mlwq_cq;
	mintr->mi_enable = mlxcx_mac_ring_intr_enable;
	mintr->mi_disable = mlxcx_mac_ring_intr_disable;

	mintr->mi_ddi_handle = mlxp->mlx_intr_handles[
	    wq->mlwq_cq->mlcq_eq->mleq_intr_index];

	mutex_exit(&g->mlg_mtx);
}

static void
mlxcx_mac_fill_rx_group(void *arg, mac_ring_type_t rtype, const int index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_ring_group_t *g;

	if (rtype != MAC_RING_TYPE_RX)
		return;

	ASSERT3S(index, >=, 0);
	ASSERT3S(index, <, mlxp->mlx_rx_ngroups);
	g = &mlxp->mlx_rx_groups[index];
	ASSERT(g->mlg_state & MLXCX_GROUP_INIT);

	g->mlg_mac_hdl = gh;

	infop->mgi_driver = (mac_group_driver_t)g;
	infop->mgi_start = mlxcx_mac_group_start;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = mlxcx_group_add_mac;
	infop->mgi_remmac = mlxcx_group_remove_mac;
	infop->mgi_addvlan = mlxcx_group_add_vlan;
	infop->mgi_remvlan = mlxcx_group_remove_vlan;

	infop->mgi_count = g->mlg_nwqs;
}

static boolean_t
mlxcx_mac_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mac_capab_rings_t *cap_rings;
	mac_capab_led_t *cap_leds;
	mac_capab_transceiver_t *cap_txr;
	uint_t i, n = 0;

	switch (cap) {

	case MAC_CAPAB_RINGS:
		cap_rings = cap_data;
		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		switch (cap_rings->mr_type) {
		case MAC_RING_TYPE_TX:
			cap_rings->mr_gnum = 0;
			cap_rings->mr_rnum = mlxp->mlx_tx_groups[0].mlg_nwqs;
			cap_rings->mr_rget = mlxcx_mac_fill_tx_ring;
			cap_rings->mr_gget = NULL;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		case MAC_RING_TYPE_RX:
			cap_rings->mr_gnum = mlxp->mlx_rx_ngroups;
			for (i = 0; i < mlxp->mlx_rx_ngroups; ++i)
				n += mlxp->mlx_rx_groups[i].mlg_nwqs;
			cap_rings->mr_rnum = n;
			cap_rings->mr_rget = mlxcx_mac_fill_rx_ring;
			cap_rings->mr_gget = mlxcx_mac_fill_rx_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
			break;
		default:
			return (B_FALSE);
		}
		break;

	case MAC_CAPAB_HCKSUM:
		if (mlxp->mlx_caps->mlc_checksum) {
			*(uint32_t *)cap_data = HCKSUM_INET_FULL_V4 |
			    HCKSUM_INET_FULL_V6 | HCKSUM_IPHDRCKSUM;
		}
		break;

	case MAC_CAPAB_LED:
		cap_leds = cap_data;

		cap_leds->mcl_flags = 0;
		cap_leds->mcl_modes = MAC_LED_DEFAULT | MAC_LED_OFF |
		    MAC_LED_IDENT;
		cap_leds->mcl_set = mlxcx_mac_led_set;
		break;

	case MAC_CAPAB_TRANSCEIVER:
		cap_txr = cap_data;

		cap_txr->mct_flags = 0;
		cap_txr->mct_ntransceivers = 1;
		cap_txr->mct_info = mlxcx_mac_txr_info;
		cap_txr->mct_read = mlxcx_mac_txr_read;
		break;

	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
mlxcx_mac_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_port_t *port = &mlxp->mlx_ports[0];

	mutex_enter(&port->mlp_mtx);

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;
	case MAC_PROP_MTU:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		mac_prop_info_set_range_uint32(prh, MLXCX_MTU_OFFSET,
		    port->mlp_max_mtu);
		mac_prop_info_set_default_uint32(prh,
		    port->mlp_mtu - MLXCX_MTU_OFFSET);
		break;
	case MAC_PROP_AUTONEG:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh, 1);
		break;
	case MAC_PROP_ADV_FEC_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_fec(prh, LINK_FEC_AUTO);
		break;
	case MAC_PROP_EN_FEC_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_RW);
		mac_prop_info_set_default_fec(prh, LINK_FEC_AUTO);
		break;
	case MAC_PROP_ADV_400GFDX_CAP:
	case MAC_PROP_EN_400GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_400G) != 0);
		break;
	case MAC_PROP_ADV_200GFDX_CAP:
	case MAC_PROP_EN_200GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_200G) != 0);
		break;
	case MAC_PROP_ADV_100GFDX_CAP:
	case MAC_PROP_EN_100GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    ((port->mlp_oper_proto & MLXCX_PROTO_100G) != 0 ||
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_100G)) != 0);
		break;
	case MAC_PROP_ADV_50GFDX_CAP:
	case MAC_PROP_EN_50GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    ((port->mlp_oper_proto & MLXCX_PROTO_50G) != 0 ||
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_50G)) != 0);
		break;
	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_EN_40GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    ((port->mlp_oper_proto & MLXCX_PROTO_40G) != 0 ||
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_40G)) != 0);
		break;
	case MAC_PROP_ADV_25GFDX_CAP:
	case MAC_PROP_EN_25GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    ((port->mlp_oper_proto & MLXCX_PROTO_25G) != 0 ||
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_25G)) != 0);
		break;
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    ((port->mlp_oper_proto & MLXCX_PROTO_10G) != 0 ||
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_10G)) != 0);
		break;
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    ((port->mlp_oper_proto & MLXCX_PROTO_1G) != 0 ||
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_1G)) != 0);
		break;
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_default_uint8(prh,
		    ((port->mlp_oper_proto & MLXCX_PROTO_100M) != 0 ||
		    (port->mlp_ext_oper_proto & MLXCX_EXTPROTO_100M)) != 0);
		break;
	default:
		break;
	}

	mutex_exit(&port->mlp_mtx);
}

static int
mlxcx_mac_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_port_t *port = &mlxp->mlx_ports[0];
	int ret = 0;
	uint32_t new_mtu, new_hw_mtu, old_mtu;
	mlxcx_buf_shard_t *sh;
	boolean_t allocd = B_FALSE;
	boolean_t relink = B_FALSE;
	link_fec_t fec;
	mlxcx_pplm_fec_caps_t cap_fec;

	mutex_enter(&port->mlp_mtx);

	switch (pr_num) {
	case MAC_PROP_MTU:
		bcopy(pr_val, &new_mtu, sizeof (new_mtu));
		new_hw_mtu = new_mtu + MLXCX_MTU_OFFSET;
		if (new_hw_mtu == port->mlp_mtu)
			break;
		if (new_hw_mtu > port->mlp_max_mtu) {
			ret = EINVAL;
			break;
		}
		sh = list_head(&mlxp->mlx_buf_shards);
		for (; sh != NULL; sh = list_next(&mlxp->mlx_buf_shards, sh)) {
			mutex_enter(&sh->mlbs_mtx);
			if (!list_is_empty(&sh->mlbs_free) ||
			    !list_is_empty(&sh->mlbs_busy) ||
			    !list_is_empty(&sh->mlbs_loaned)) {
				allocd = B_TRUE;
				mutex_exit(&sh->mlbs_mtx);
				break;
			}
			mutex_exit(&sh->mlbs_mtx);
		}
		if (allocd) {
			ret = EBUSY;
			break;
		}
		old_mtu = port->mlp_mtu;
		ret = mac_maxsdu_update(mlxp->mlx_mac_hdl, new_mtu);
		if (ret != 0)
			break;
		port->mlp_mtu = new_hw_mtu;
		if (!mlxcx_cmd_modify_nic_vport_ctx(mlxp, port,
		    MLXCX_MODIFY_NIC_VPORT_CTX_MTU)) {
			port->mlp_mtu = old_mtu;
			(void) mac_maxsdu_update(mlxp->mlx_mac_hdl, old_mtu);
			ret = EIO;
			break;
		}
		if (!mlxcx_cmd_set_port_mtu(mlxp, port)) {
			port->mlp_mtu = old_mtu;
			(void) mac_maxsdu_update(mlxp->mlx_mac_hdl, old_mtu);
			ret = EIO;
			break;
		}
		break;

	case MAC_PROP_EN_FEC_CAP:
		bcopy(pr_val, &fec, sizeof (fec));
		if (!mlxcx_link_fec_cap(fec, &cap_fec)) {
			ret = EINVAL;
			break;
		}

		/*
		 * Don't change the FEC if it is already at the requested
		 * setting AND the port is up.
		 * When the port is down, always set the FEC and attempt
		 * to retrain the link.
		 */
		if (fec == port->mlp_fec_requested &&
		    fec == mlxcx_fec_to_link_fec(port->mlp_fec_active) &&
		    port->mlp_oper_status != MLXCX_PORT_STATUS_DOWN)
			break;

		/*
		 * The most like cause of this failing is an invalid
		 * or unsupported fec option.
		 */
		if (!mlxcx_cmd_modify_port_fec(mlxp, port, cap_fec)) {
			ret = EINVAL;
			break;
		}

		port->mlp_fec_requested = fec;

		/*
		 * For FEC to become effective, the link needs to go back
		 * to training and negotiation state. This happens when
		 * the link transitions from down to up, force a relink.
		 */
		relink = B_TRUE;
		break;

	default:
		ret = ENOTSUP;
		break;
	}

	if (relink) {
		if (!mlxcx_cmd_modify_port_status(mlxp, port,
		    MLXCX_PORT_STATUS_DOWN) ||
		    !mlxcx_cmd_modify_port_status(mlxp, port,
		    MLXCX_PORT_STATUS_UP)) {
			ret = EIO;
		}
	}
	mutex_exit(&port->mlp_mtx);

	return (ret);
}

static int
mlxcx_mac_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	mlxcx_t *mlxp = (mlxcx_t *)arg;
	mlxcx_port_t *port = &mlxp->mlx_ports[0];
	uint64_t speed;
	int ret = 0;

	mutex_enter(&port->mlp_mtx);

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
		if (pr_valsize < sizeof (link_duplex_t)) {
			ret = EOVERFLOW;
			break;
		}
		/* connectx parts only support full duplex */
		*(link_duplex_t *)pr_val = LINK_DUPLEX_FULL;
		break;
	case MAC_PROP_SPEED:
		if (pr_valsize < sizeof (uint64_t)) {
			ret = EOVERFLOW;
			break;
		}
		speed = mlxcx_speed_to_bits(port->mlp_oper_proto,
		    port->mlp_ext_oper_proto);
		bcopy(&speed, pr_val, sizeof (speed));
		break;
	case MAC_PROP_STATUS:
		if (pr_valsize < sizeof (link_state_t)) {
			ret = EOVERFLOW;
			break;
		}
		switch (port->mlp_oper_status) {
		case MLXCX_PORT_STATUS_UP:
		case MLXCX_PORT_STATUS_UP_ONCE:
			*(link_state_t *)pr_val = LINK_STATE_UP;
			break;
		case MLXCX_PORT_STATUS_DOWN:
			*(link_state_t *)pr_val = LINK_STATE_DOWN;
			break;
		default:
			*(link_state_t *)pr_val = LINK_STATE_UNKNOWN;
		}
		break;
	case MAC_PROP_AUTONEG:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val = port->mlp_autoneg;
		break;
	case MAC_PROP_ADV_FEC_CAP:
		if (pr_valsize < sizeof (link_fec_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(link_fec_t *)pr_val =
		    mlxcx_fec_to_link_fec(port->mlp_fec_active);
		break;
	case MAC_PROP_EN_FEC_CAP:
		if (pr_valsize < sizeof (link_fec_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(link_fec_t *)pr_val = port->mlp_fec_requested;
		break;
	case MAC_PROP_MTU:
		if (pr_valsize < sizeof (uint32_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint32_t *)pr_val = port->mlp_mtu - MLXCX_MTU_OFFSET;
		break;
	case MAC_PROP_ADV_400GFDX_CAP:
	case MAC_PROP_EN_400GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val =
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_400G) != 0;
		break;
	case MAC_PROP_ADV_200GFDX_CAP:
	case MAC_PROP_EN_200GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val =
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_200G) != 0;
		break;
	case MAC_PROP_ADV_100GFDX_CAP:
	case MAC_PROP_EN_100GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val = (port->mlp_max_proto &
		    MLXCX_PROTO_100G) != 0 ||
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_100G) != 0;
		break;
	case MAC_PROP_ADV_50GFDX_CAP:
	case MAC_PROP_EN_50GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val = (port->mlp_max_proto &
		    MLXCX_PROTO_50G) != 0 ||
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_50G) != 0;
		break;
	case MAC_PROP_ADV_40GFDX_CAP:
	case MAC_PROP_EN_40GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val = (port->mlp_max_proto &
		    MLXCX_PROTO_40G) != 0 ||
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_40G) != 0;
		break;
	case MAC_PROP_ADV_25GFDX_CAP:
	case MAC_PROP_EN_25GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val = (port->mlp_max_proto &
		    MLXCX_PROTO_25G) != 0 ||
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_25G) != 0;
		break;
	case MAC_PROP_ADV_10GFDX_CAP:
	case MAC_PROP_EN_10GFDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val = (port->mlp_max_proto &
		    MLXCX_PROTO_10G) != 0 ||
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_10G) != 0;
		break;
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_EN_1000FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val = (port->mlp_max_proto &
		    MLXCX_PROTO_1G) != 0 ||
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_1G) != 0;
		break;
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_EN_100FDX_CAP:
		if (pr_valsize < sizeof (uint8_t)) {
			ret = EOVERFLOW;
			break;
		}
		*(uint8_t *)pr_val = (port->mlp_max_proto &
		    MLXCX_PROTO_100M) != 0 ||
		    (port->mlp_ext_max_proto & MLXCX_EXTPROTO_100M) != 0;
		break;
	default:
		ret = ENOTSUP;
		break;
	}

	mutex_exit(&port->mlp_mtx);

	return (ret);
}

#define	MLXCX_MAC_CALLBACK_FLAGS \
	(MC_GETCAPAB | MC_GETPROP | MC_PROPINFO | MC_SETPROP)

static mac_callbacks_t mlxcx_mac_callbacks = {
	.mc_callbacks = MLXCX_MAC_CALLBACK_FLAGS,
	.mc_getstat = mlxcx_mac_stat,
	.mc_start = mlxcx_mac_start,
	.mc_stop = mlxcx_mac_stop,
	.mc_setpromisc = mlxcx_mac_setpromisc,
	.mc_multicst = mlxcx_mac_multicast,
	.mc_ioctl = NULL,
	.mc_getcapab = mlxcx_mac_getcapab,
	.mc_setprop = mlxcx_mac_setprop,
	.mc_getprop = mlxcx_mac_getprop,
	.mc_propinfo = mlxcx_mac_propinfo,
	.mc_tx = NULL,
	.mc_unicst = NULL,
};

boolean_t
mlxcx_register_mac(mlxcx_t *mlxp)
{
	mac_register_t *mac = mac_alloc(MAC_VERSION);
	mlxcx_port_t *port;
	int ret;

	if (mac == NULL)
		return (B_FALSE);

	VERIFY3U(mlxp->mlx_nports, ==, 1);
	port = &mlxp->mlx_ports[0];

	mutex_enter(&port->mlp_mtx);

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = mlxp;
	mac->m_dip = mlxp->mlx_dip;
	mac->m_src_addr = port->mlp_mac_address;
	mac->m_callbacks = &mlxcx_mac_callbacks;
	mac->m_min_sdu = MLXCX_MTU_OFFSET;
	mac->m_max_sdu = port->mlp_mtu - MLXCX_MTU_OFFSET;
	mac->m_margin = VLAN_TAGSZ;
	mac->m_priv_props = mlxcx_priv_props;
	mac->m_v12n = MAC_VIRT_LEVEL1;

	ret = mac_register(mac, &mlxp->mlx_mac_hdl);
	if (ret != 0) {
		mlxcx_warn(mlxp, "mac_register() returned %d", ret);
	}
	mac_free(mac);

	mutex_exit(&port->mlp_mtx);

	mlxcx_update_link_state(mlxp, port);

	return (ret == 0);
}
