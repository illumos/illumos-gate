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
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* tp.c */

#include "common.h"
#include "regs.h"
#include "tp.h"
#ifdef CONFIG_CHELSIO_T1_1G
#include "fpga_defs.h"
#endif

struct petp {
	adapter_t *adapter;
};

/* Pause deadlock avoidance parameters */
#define DROP_MSEC 16
#define DROP_PKTS_CNT  1

#ifdef CONFIG_CHELSIO_T1_OFFLOAD

static inline u32 pm_num_pages(u32 size, u32 pg_size)
{
	u32 num = size / pg_size;
	num -= num % 24;
	return num;
}

static void tp_pm_configure(adapter_t *adapter, struct tp_params *p)
{
	u32 num;

	num = pm_num_pages(p->pm_size - p->pm_rx_base, p->pm_rx_pg_size);
	if (p->pm_rx_num_pgs > num)
		p->pm_rx_num_pgs = num;

	num = pm_num_pages(p->pm_rx_base - p->pm_tx_base, p->pm_tx_pg_size);
	if (p->pm_tx_num_pgs > num)
		p->pm_tx_num_pgs = num;

	t1_write_reg_4(adapter, A_TP_PM_SIZE, p->pm_size);
	t1_write_reg_4(adapter, A_TP_PM_RX_BASE, p->pm_rx_base);
	t1_write_reg_4(adapter, A_TP_PM_TX_BASE, p->pm_tx_base);
	t1_write_reg_4(adapter, A_TP_PM_DEFRAG_BASE, p->pm_size);
	t1_write_reg_4(adapter, A_TP_PM_RX_PG_SIZE, p->pm_rx_pg_size);
	t1_write_reg_4(adapter, A_TP_PM_RX_MAX_PGS, p->pm_rx_num_pgs);
	t1_write_reg_4(adapter, A_TP_PM_TX_PG_SIZE, p->pm_tx_pg_size);
	t1_write_reg_4(adapter, A_TP_PM_TX_MAX_PGS, p->pm_tx_num_pgs);
}

static void tp_cm_configure(adapter_t *adapter, u32 cm_size)
{
	u32 mm_base = (cm_size >> 1);
	u32 mm_sub_size = (cm_size >> 5);

	t1_write_reg_4(adapter, A_TP_CM_SIZE, cm_size);
	t1_write_reg_4(adapter, A_TP_CM_MM_BASE, mm_base);
	t1_write_reg_4(adapter, A_TP_CM_TIMER_BASE, (cm_size >> 2) * 3);
	t1_write_reg_4(adapter, A_TP_CM_MM_P_FLST_BASE,
		       mm_base + 5 * mm_sub_size);
	t1_write_reg_4(adapter, A_TP_CM_MM_TX_FLST_BASE,
		       mm_base + 6 * mm_sub_size);
	t1_write_reg_4(adapter, A_TP_CM_MM_RX_FLST_BASE,
		       mm_base + 7 * mm_sub_size);
	t1_write_reg_4(adapter, A_TP_CM_MM_MAX_P, 0x40000);
}

static unsigned int tp_delayed_ack_ticks(adapter_t *adap, unsigned int tp_clk)
{
	u32 tr = t1_read_reg_4(adap, A_TP_TIMER_RESOLUTION);

	return tp_clk /	(1 << G_DELAYED_ACK_TIMER_RESOLUTION(tr));
}

static unsigned int t1_tp_ticks_per_sec(adapter_t *adap, unsigned int tp_clk)
{
	u32 tr = t1_read_reg_4(adap, A_TP_TIMER_RESOLUTION);

	return tp_clk /	(1 << G_GENERIC_TIMER_RESOLUTION(tr));
}

static void tp_set_tcp_time_params(adapter_t *adapter, unsigned int tp_clk)
{
	u32 tps = t1_tp_ticks_per_sec(adapter, tp_clk);
	u32 tp_scnt;

#define SECONDS * tps
	t1_write_reg_4(adapter, A_TP_2MSL, (1 SECONDS)/2);
	t1_write_reg_4(adapter, A_TP_RXT_MIN, (1 SECONDS)/4);
	t1_write_reg_4(adapter, A_TP_RXT_MAX, 64 SECONDS);
	t1_write_reg_4(adapter, A_TP_PERS_MIN, (1 SECONDS)/2);
	t1_write_reg_4(adapter, A_TP_PERS_MAX, 64 SECONDS);
	t1_write_reg_4(adapter, A_TP_KEEP_IDLE, 7200 SECONDS);
	t1_write_reg_4(adapter, A_TP_KEEP_INTVL, 75 SECONDS);
	t1_write_reg_4(adapter, A_TP_INIT_SRTT, 3 SECONDS);
	t1_write_reg_4(adapter, A_TP_FINWAIT2_TIME, 60 SECONDS);
	t1_write_reg_4(adapter, A_TP_FAST_FINWAIT2_TIME, 3 SECONDS);
#undef SECONDS

	/* Set Retransmission shift max */
	tp_scnt = t1_read_reg_4(adapter, A_TP_SHIFT_CNT);
	tp_scnt &= (~V_RETRANSMISSION_MAX(0x3f));
	tp_scnt |= V_RETRANSMISSION_MAX(14);
	t1_write_reg_4(adapter, A_TP_SHIFT_CNT, tp_scnt);

	/* Set DACK timer to 200ms */
	t1_write_reg_4(adapter, A_TP_DACK_TIME,
		       tp_delayed_ack_ticks(adapter, tp_clk) / 5);
}

int t1_tp_set_coalescing_size(struct petp *tp, unsigned int size)
{
	u32 val;

	if (size > TP_MAX_RX_COALESCING_SIZE)
		return -EINVAL;

	val = t1_read_reg_4(tp->adapter, A_TP_PARA_REG3);

	if (tp->adapter->params.nports > 1)
		size = 9904;
	
	if (size) {
		u32 v = t1_is_T1B(tp->adapter) ? 0 : V_MAX_RX_SIZE(size);

		/* Set coalescing size. */
		t1_write_reg_4(tp->adapter, A_TP_PARA_REG2, 
			       V_RX_COALESCE_SIZE(size) | v);

		val |= (F_RX_COALESCING_PSH_DELIVER | F_RX_COALESCING_ENABLE);
	} else
		val &= ~F_RX_COALESCING_ENABLE;

	t1_write_reg_4(tp->adapter, A_TP_PARA_REG3, val);
	return 0;
}

void t1_tp_get_mib_statistics(adapter_t *adap, struct tp_mib_statistics *tps)
{
	u32 *data = (u32 *)tps;
	int i;

	t1_write_reg_4(adap, A_TP_MIB_INDEX, 0);

	for (i = 0; i < sizeof(*tps) / sizeof(u32); i++)
		*data++ = t1_read_reg_4(adap, A_TP_MIB_DATA);
}
#endif

static void tp_init(adapter_t *ap, const struct tp_params *p,
		    unsigned int tp_clk)
{
	if (t1_is_asic(ap)) {
		u32 val;

		val = F_TP_IN_CSPI_CPL | F_TP_IN_CSPI_CHECK_IP_CSUM |
		      F_TP_IN_CSPI_CHECK_TCP_CSUM | F_TP_IN_ESPI_ETHERNET;
		if (!p->pm_size)
			val |= F_OFFLOAD_DISABLE;
		else
			val |= F_TP_IN_ESPI_CHECK_IP_CSUM |
				F_TP_IN_ESPI_CHECK_TCP_CSUM;
		t1_write_reg_4(ap, A_TP_IN_CONFIG, val);
		t1_write_reg_4(ap, A_TP_OUT_CONFIG, F_TP_OUT_CSPI_CPL |
			       F_TP_OUT_ESPI_ETHERNET |
			       F_TP_OUT_ESPI_GENERATE_IP_CSUM |
			       F_TP_OUT_ESPI_GENERATE_TCP_CSUM);
		t1_write_reg_4(ap, A_TP_GLOBAL_CONFIG, V_IP_TTL(64) |
			       F_PATH_MTU /* IP DF bit */ |
			       V_5TUPLE_LOOKUP(p->use_5tuple_mode) |
			       V_SYN_COOKIE_PARAMETER(29));

                /*
                 * Enable pause frame deadlock prevention.
                 */
                if (is_T2(ap) && ap->params.nports > 1) {
                        u32 drop_ticks = DROP_MSEC * (tp_clk / 1000);
                                                                                
                        t1_write_reg_4(ap, A_TP_TX_DROP_CONFIG,
                                       F_ENABLE_TX_DROP | F_ENABLE_TX_ERROR |
                                       V_DROP_TICKS_CNT(drop_ticks) |
                                       V_NUM_PKTS_DROPPED(DROP_PKTS_CNT));
                }

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
		t1_write_reg_4(ap, A_TP_GLOBAL_RX_CREDITS, 0xffffffff);
		val = V_WINDOW_SCALE(1) | F_MSS | V_DEFAULT_PEER_MSS(576);
		
		/* We don't want timestamps for T204, otherwise we don't know
		 * the MSS.
		 */
		if (ap->params.nports == 1)
			val |= V_TIMESTAMP(1);
		t1_write_reg_4(ap, A_TP_TCP_OPTIONS, val);
		t1_write_reg_4(ap, A_TP_DACK_CONFIG, V_DACK_MSS_SELECTOR(1) |
			       F_DACK_AUTO_CAREFUL | V_DACK_MODE(1));
		t1_write_reg_4(ap, A_TP_BACKOFF0, 0x3020100);
		t1_write_reg_4(ap, A_TP_BACKOFF1, 0x7060504);
		t1_write_reg_4(ap, A_TP_BACKOFF2, 0xb0a0908);
		t1_write_reg_4(ap, A_TP_BACKOFF3, 0xf0e0d0c);
		
		/* We do scheduling in software for T204, increase the cong.
		 * window to avoid TP holding on to payload longer than we 
		 * expect.
		 */
		if (ap->params.nports == 1)
			t1_write_reg_4(ap, A_TP_PARA_REG0, 0xd1269324);
		else
			t1_write_reg_4(ap, A_TP_PARA_REG0, 0xd6269324);
		t1_write_reg_4(ap, A_TP_SYNC_TIME_HI, 0);
		t1_write_reg_4(ap, A_TP_SYNC_TIME_LO, 0);
		t1_write_reg_4(ap, A_TP_INT_ENABLE, 0);
		t1_write_reg_4(ap, A_TP_CM_FC_MODE, 0);   /* Enable CM cache */
		t1_write_reg_4(ap, A_TP_PC_CONGESTION_CNTL, 0x6186);

		/*
		 * Calculate the time between modulation events, which affects
		 * both the Tx and Rx pipelines.  Larger values force the Tx
		 * pipeline to wait before processing modulation events, thus
		 * allowing Rx to use the pipeline.  A really small delay can
		 * starve the Rx side from accessing the pipeline.
		 *
		 * A balanced value is optimal.  This is roughly 9us per 1G.
		 * The Tx needs a low delay time for handling a lot of small
		 * packets. Too big of a delay could cause Tx not to achieve
		 * line rate.
		 */
		val = (9 * tp_clk) / 1000000;
		/* adjust for multiple ports */
		if (ap->params.nports > 1) {
			val = 0;
		}
		if (is_10G(ap))               /* adjust for 10G */
			val /= 10;
		/*
		 * Bit 0 must be 0 to keep the timer insertion property.
		 */
		t1_write_reg_4(ap, A_TP_TIMER_SEPARATOR, val & ~1);

		t1_write_reg_4(ap, A_TP_TIMER_RESOLUTION, 0xF0011);
		tp_set_tcp_time_params(ap, tp_clk);

		/* PR3229 */
		if (is_T2(ap)) {
			val = t1_read_reg_4(ap, A_TP_PC_CONFIG);
			val |= V_DIS_TX_FILL_WIN_PUSH(1);
			t1_write_reg_4(ap, A_TP_PC_CONFIG, val);
		}

#ifdef CONFIG_CHELSIO_T1_1G
	} else {    /* FPGA */
		t1_write_reg_4(ap, A_TP_TIMER_RESOLUTION, 0xD000A);
#endif
#endif
	}
}

void t1_tp_destroy(struct petp *tp)
{
	t1_os_free((void *)tp, sizeof(*tp));
}

struct petp * __devinit t1_tp_create(adapter_t *adapter, struct tp_params *p)
{
	struct petp *tp = t1_os_malloc_wait_zero(sizeof(*tp));
	if (!tp)
		return NULL;

	tp->adapter = adapter;

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (p->pm_size) {                     /* Default PM partitioning */
		p->pm_rx_base = p->pm_size >> 1;
#ifdef TDI_SUPPORT
		p->pm_tx_base = 2048 * 1024;    /* reserve 2 MByte for REGION MAP */
#else
		p->pm_tx_base = 64 * 1024;    /* reserve 64 kbytes for REGION MAP */
#endif
		p->pm_rx_pg_size = 64 * 1024;

		if (adapter->params.nports == 1)
			p->pm_tx_pg_size = 64 * 1024;
		else
			p->pm_tx_pg_size = 16 * 1024;
		p->pm_rx_num_pgs = pm_num_pages(p->pm_size - p->pm_rx_base,
						p->pm_rx_pg_size);
		p->pm_tx_num_pgs = pm_num_pages(p->pm_rx_base - p->pm_tx_base,
						p->pm_tx_pg_size);
	}
#endif
	return tp;
}

void t1_tp_intr_enable(struct petp *tp)
{
	u32 tp_intr = t1_read_reg_4(tp->adapter, A_PL_ENABLE);

#ifdef CONFIG_CHELSIO_T1_1G
	if (!t1_is_asic(tp->adapter)) {
		/* FPGA */
		t1_write_reg_4(tp->adapter, FPGA_TP_ADDR_INTERRUPT_ENABLE,
			       0xffffffff);
		t1_write_reg_4(tp->adapter, A_PL_ENABLE,
			       tp_intr | FPGA_PCIX_INTERRUPT_TP);
	} else
#endif
	{
		/* We don't use any TP interrupts */
		t1_write_reg_4(tp->adapter, A_TP_INT_ENABLE, 0);
		t1_write_reg_4(tp->adapter, A_PL_ENABLE,
			       tp_intr | F_PL_INTR_TP);
	}
}

void t1_tp_intr_disable(struct petp *tp)
{
	u32 tp_intr = t1_read_reg_4(tp->adapter, A_PL_ENABLE);

#ifdef CONFIG_CHELSIO_T1_1G
	if (!t1_is_asic(tp->adapter)) {
		/* FPGA */
		t1_write_reg_4(tp->adapter, FPGA_TP_ADDR_INTERRUPT_ENABLE, 0);
		t1_write_reg_4(tp->adapter, A_PL_ENABLE,
			       tp_intr & ~FPGA_PCIX_INTERRUPT_TP);
	} else 
#endif
	{
		t1_write_reg_4(tp->adapter, A_TP_INT_ENABLE, 0);
		t1_write_reg_4(tp->adapter, A_PL_ENABLE,
			       tp_intr & ~F_PL_INTR_TP);
	}
}

void t1_tp_intr_clear(struct petp *tp)
{
#ifdef CONFIG_CHELSIO_T1_1G
	if (!t1_is_asic(tp->adapter)) {
		t1_write_reg_4(tp->adapter, FPGA_TP_ADDR_INTERRUPT_CAUSE,
			       0xffffffff);
		t1_write_reg_4(tp->adapter, A_PL_CAUSE, FPGA_PCIX_INTERRUPT_TP);
		return;
	}
#endif
	t1_write_reg_4(tp->adapter, A_TP_INT_CAUSE, 0xffffffff);
	t1_write_reg_4(tp->adapter, A_PL_CAUSE, F_PL_INTR_TP);
}

int t1_tp_intr_handler(struct petp *tp)
{
	u32 cause;

#ifdef CONFIG_CHELSIO_T1_1G
	/* FPGA doesn't support TP interrupts. */
	if (!t1_is_asic(tp->adapter))
		return 1;
#endif

	cause = t1_read_reg_4(tp->adapter, A_TP_INT_CAUSE);
	t1_write_reg_4(tp->adapter, A_TP_INT_CAUSE, cause);
	return 0;
}

static void set_csum_offload(struct petp *tp, u32 csum_bit, int enable)
{
	u32 val = t1_read_reg_4(tp->adapter, A_TP_GLOBAL_CONFIG);

	if (enable)
		val |= csum_bit;
	else
		val &= ~csum_bit;
	t1_write_reg_4(tp->adapter, A_TP_GLOBAL_CONFIG, val);
}

void t1_tp_set_ip_checksum_offload(struct petp *tp, int enable)
{
	set_csum_offload(tp, F_IP_CSUM, enable);
}

void t1_tp_set_udp_checksum_offload(struct petp *tp, int enable)
{
	set_csum_offload(tp, F_UDP_CSUM, enable);
}

void t1_tp_set_tcp_checksum_offload(struct petp *tp, int enable)
{
	set_csum_offload(tp, F_TCP_CSUM, enable);
}

/*
 * Initialize TP state.  tp_params contains initial settings for some TP
 * parameters, particularly the one-time PM and CM settings.
 */
int t1_tp_reset(struct petp *tp, struct tp_params *p, unsigned int tp_clk)
{
	int busy = 0;
	adapter_t *adapter = tp->adapter;

	tp_init(adapter, p, tp_clk);
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	if (p->pm_size) {
		tp_pm_configure(adapter, p);
		tp_cm_configure(adapter, p->cm_size);

		t1_write_reg_4(adapter, A_TP_RESET, F_CM_MEMMGR_INIT);
		busy = t1_wait_op_done(adapter, A_TP_RESET, F_CM_MEMMGR_INIT,
				0, 1000, 5);
	}
#endif
	if (!busy)
		t1_write_reg_4(adapter, A_TP_RESET, F_TP_RESET);
	else
		CH_ERR("%s: TP initialization timed out\n",
		       adapter_name(adapter));
	return busy;
}
