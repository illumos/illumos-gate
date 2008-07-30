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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SPARC64 VI & VII Performance Counter Backend
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/modctl.h>
#include <sys/machsystm.h>
#include <sys/sdt.h>
#include <sys/cpu_impl.h>

static int opl_pcbe_init(void);
static uint_t opl_pcbe_ncounters(void);
static const char *opl_pcbe_impl_name(void);
static const char *opl_pcbe_cpuref(void);
static char *opl_pcbe_list_events(uint_t picnum);
static char *opl_pcbe_list_attrs(void);
static uint64_t opl_pcbe_event_coverage(char *event);
static uint64_t opl_pcbe_overflow_bitmap(void);
static int opl_pcbe_configure(uint_t picnum, char *event, uint64_t preset,
    uint32_t flags, uint_t nattrs, kcpc_attr_t *attrs, void **data,
    void *token);
static void opl_pcbe_program(void *token);
static void opl_pcbe_allstop(void);
static void opl_pcbe_sample(void *token);
static void opl_pcbe_free(void *config);

extern void ultra_setpcr(uint64_t);
extern uint64_t ultra_getpcr(void);
extern void ultra_setpic(uint64_t);
extern uint64_t ultra_getpic(void);
extern uint64_t ultra_gettick(void);

pcbe_ops_t opl_pcbe_ops = {
	PCBE_VER_1,
	CPC_CAP_OVERFLOW_INTERRUPT,
	opl_pcbe_ncounters,
	opl_pcbe_impl_name,
	opl_pcbe_cpuref,
	opl_pcbe_list_events,
	opl_pcbe_list_attrs,
	opl_pcbe_event_coverage,
	opl_pcbe_overflow_bitmap,
	opl_pcbe_configure,
	opl_pcbe_program,
	opl_pcbe_allstop,
	opl_pcbe_sample,
	opl_pcbe_free
};

typedef struct _opl_pcbe_config {
	uint8_t		opl_picno;	/* From 0 to 7 */
	uint32_t	opl_bits;	/* %pcr event code unshifted */
	uint32_t	opl_flags;	/* user/system/priv */
	uint32_t	opl_pic;	/* unshifted raw %pic value */
} opl_pcbe_config_t;

struct nametable {
	const uint8_t	bits;
	const char	*name;
};

/*
 * Performance Control Register (PCR)
 *
 * +----------+-----+-----+------+----+
 * |      0   | OVF |  0  | OVR0 | 0  |
 * +----------+-----+-----+------+----+
 * 63     48  47:32  31:27   26    25
 *
 * +----+----+--- -+----+-----+---+-----+-----+----+----+----+
 * | NC |  0 | SC  | 0  | SU  | 0 | SL  |ULRO | UT | ST |PRIV|
 * +----+----+-----+----+-----+---+-----+-----+----+----+----+
 * 24:22  21  20:18  17  16:11 10  9:4     3    2    1    0
 *
 * ULRO and OVRO bits should be on upon accessing pcr unless
 * those fields need to be updated.
 * Turn off these bits when updating SU/SL or OVF field
 * (during initialization, etc.).
 *
 *
 * Performance Instrumentation Counter (PIC)
 * Four PICs are implemented in SPARC64 VI and VII,
 * each PIC is accessed using PCR.SC as a select field.
 *
 * +------------------------+--------------------------+
 * |         PICU	    |		PICL	       |
 * +------------------------+--------------------------+
 *  63			 32  31			      0
 */

#define	PIC_MASK (((uint64_t)1 << 32) - 1)

#define	SPARC64_VI_PCR_PRIVPIC  UINT64_C(0)

#define	CPC_SPARC64_VI_PCR_SYS_SHIFT	1
#define	CPC_SPARC64_VI_PCR_USR_SHIFT	2

#define	CPC_SPARC64_VI_PCR_PICL_SHIFT	4
#define	CPC_SPARC64_VI_PCR_PICU_SHIFT	11
#define	CPC_SPARC64_VI_PCR_PIC_MASK	UINT64_C(0x3F)

#define	CPC_SPARC64_VI_NPIC		8

#define	CPC_SPARC64_VI_PCR_ULRO_SHIFT	3
#define	CPC_SPARC64_VI_PCR_SC_SHIFT	18
#define	CPC_SPARC64_VI_PCR_SC_MASK	UINT64_C(0x7)
#define	CPC_SPARC64_VI_PCR_NC_SHIFT	22
#define	CPC_SPARC64_VI_PCR_NC_MASK	UINT64_C(0x7)
#define	CPC_SPARC64_VI_PCR_OVRO_SHIFT	26
#define	CPC_SPARC64_VI_PCR_OVF_SHIFT	32
#define	CPC_SPARC64_VI_PCR_OVF_MASK	UINT64_C(0xffff)

#define	SPARC64_VI_PCR_SYS	(UINT64_C(1) << CPC_SPARC64_VI_PCR_SYS_SHIFT)
#define	SPARC64_VI_PCR_USR	(UINT64_C(1) << CPC_SPARC64_VI_PCR_USR_SHIFT)
#define	SPARC64_VI_PCR_ULRO	(UINT64_C(1) << CPC_SPARC64_VI_PCR_ULRO_SHIFT)
#define	SPARC64_VI_PCR_OVRO	(UINT64_C(1) << CPC_SPARC64_VI_PCR_OVRO_SHIFT)
#define	SPARC64_VI_PCR_OVF	(CPC_SPARC64_VI_PCR_OVF_MASK << \
					CPC_SPARC64_VI_PCR_OVF_SHIFT)

#define	SPARC64_VI_NUM_PIC_PAIRS	4

#define	SPARC64_VI_PCR_SEL_PIC(pcr, picno) {				\
	pcr &= ~((CPC_SPARC64_VI_PCR_SC_MASK				\
		<< CPC_SPARC64_VI_PCR_SC_SHIFT));			\
									\
	pcr |= (((picno) & CPC_SPARC64_VI_PCR_SC_MASK)			\
		<< CPC_SPARC64_VI_PCR_SC_SHIFT);			\
}

#define	SPARC64_VI_PCR_SEL_EVENT(pcr, sl, su) {				\
	pcr &= ~((CPC_SPARC64_VI_PCR_PIC_MASK				\
		<< CPC_SPARC64_VI_PCR_PICL_SHIFT)			\
	    | (CPC_SPARC64_VI_PCR_PIC_MASK				\
		<< CPC_SPARC64_VI_PCR_PICU_SHIFT));			\
									\
	pcr |= (((sl) & CPC_SPARC64_VI_PCR_PIC_MASK)			\
		<< CPC_SPARC64_VI_PCR_PICL_SHIFT);			\
	pcr |= (((su) & CPC_SPARC64_VI_PCR_PIC_MASK)			\
		<< CPC_SPARC64_VI_PCR_PICU_SHIFT);			\
}

#define	SPARC64_VI_CHK_OVF(pcr, picno)					\
	((pcr) & (UINT64_C(1) << (CPC_SPARC64_VI_PCR_OVF_SHIFT + picno)))

#define	SPARC64_VI_CLR_OVF(pcr, picno) {				\
	pcr &= ~(UINT64_C(1) << (CPC_SPARC64_VI_PCR_OVF_SHIFT + picno)); \
}

#define	NT_END 0xFF

static const uint64_t   allstopped = SPARC64_VI_PCR_PRIVPIC |
	SPARC64_VI_PCR_ULRO | SPARC64_VI_PCR_OVRO;

#define	SPARC64_VI_EVENTS_comm_0		\
	{0x0,	"cycle_counts"},		\
	{0x1,	"instruction_counts"}

#define	SPARC64_VI_EVENTS_comm_1		\
	{0x5,	"op_stv_wait"},			\
	{0x8,	"load_store_instructions"},	\
	{0x9,	"branch_instructions"},		\
	{0xa,	"floating_instructions"},	\
	{0xb,	"impdep2_instructions"},	\
	{0xc,	"prefetch_instructions"}

#define	SPARC64_VI_EVENTS_comm_2		\
	{0x1a,	"active_cycle_count"}

static const struct nametable SPARC64_VI_names_l0[] = {
	SPARC64_VI_EVENTS_comm_0,
	{0x2,	"only_this_thread_active"},
	{0x3,	"w_cse_window_empty"},
	{0x4,	"w_op_stv_wait_nc_pend"},
	SPARC64_VI_EVENTS_comm_1,
	{0x12,	"flush_rs"},
	{0x13,	"2iid_use"},
	{0x15,	"toq_rsbr_phantom"},
	{0x16,	"trap_int_vector"},
	{0x18,	"ts_by_sxmiss"},
	{0x18,	"both_threads_active"},
	SPARC64_VI_EVENTS_comm_2,
	{0x1d,	"op_stv_wait_sxmiss"},
	{0x1e,	"eu_comp_wait"},
	{0x23,	"op_l1_thrashing"},
	{0x24,	"swpf_fail_all"},
	{0x30,	"sx_miss_wait_pf"},
	{0x31,	"jbus_cpi_count"},
	{0x36,	"jbus_reqbus1_busy"},
	{NT_END, ""}
};

static const struct nametable SPARC64_VI_names_u0[] = {
	SPARC64_VI_EVENTS_comm_0,
	{0x2,	"instruction_flow_counts"},
	{0x3,	"iwr_empty"},
	SPARC64_VI_EVENTS_comm_1,
	{0x12,	"rs1"},
	{0x13,	"1iid_use"},
	{0x16,	"trap_all"},
	{0x18,	"thread_switch_all"},
	{0x18,	"only_this_thread_active"},
	SPARC64_VI_EVENTS_comm_2,
	{0x1b,	"rsf_pmmi"},
	{0x1d,	"act_thread_suspend"},
	{0x1e,	"cse_window_empty"},
	{0x1f,	"inh_cmit_gpr_2write"},
	{0x23,	"if_l1_thrashing"},
	{0x24,	"swpf_success_all"},
	{0x30,	"sx_miss_wait_dm"},
	{0x31,	"jbus_bi_count"},
	{0x34,	"lost_softpf_pfp_full"},
	{0x36,	"jbus_reqbus0_busy"},
	{NT_END, ""}
};

static const struct nametable SPARC64_VI_names_l1[] = {
	SPARC64_VI_EVENTS_comm_0,
	{0x2,	"single_mode_instructions"},
	{0x3,	"w_branch_comp_wait"},
	{0x4,	"w_op_stv_wait_sxmiss_ex"},
	SPARC64_VI_EVENTS_comm_1,
	{0x13,	"4iid_use"},
	{0x15,	"flush_rs"},
	{0x16,	"trap_spill"},
	{0x18,	"ts_by_timer"},
	SPARC64_VI_EVENTS_comm_2,
	{0x1b,	"0iid_use"},
	{0x1d,	"op_stv_wait_nc_pend"},
	{0x1e,	"0endop"},
	{0x20,	"write_op_uTLB"},
	{0x30,	"sx_miss_count_pf"},
	{0x31,	"jbus_cpd_count"},
	{0x32,	"snres_64"},
	{0x36,	"jbus_reqbus3_busy"},
	{NT_END, ""}
};

static const struct nametable SPARC64_VI_names_u1[] = {
	SPARC64_VI_EVENTS_comm_0,
	{0x2,	"single_mode_cycle_counts"},
	{0x3,	"w_eu_comp_wait"},
	{0x4,	"w_op_stv_wait_sxmiss"},
	SPARC64_VI_EVENTS_comm_1,
	{0x13,	"3iid_use"},
	{0x16,	"trap_int_level"},
	{0x18,	"ts_by_data_arrive"},
	{0x18,	"both_threads_empty"},
	SPARC64_VI_EVENTS_comm_2,
	{0x1b,	"op_stv_wait_nc_pend"},
	{0x1d,	"op_stv_wait_sxmiss_ex"},
	{0x1e,	"branch_comp_wait"},
	{0x20,	"write_if_uTLB"},
	{0x30,	"sx_miss_count_dm"},
	{0x31,	"jbus_cpb_count"},
	{0x32,	"snres_256"},
	{0x34,	"lost_softpf_by_abort"},
	{0x36,	"jbus_reqbus2_busy"},
	{NT_END, ""}
};

static const struct nametable SPARC64_VI_names_l2[] = {
	SPARC64_VI_EVENTS_comm_0,
	{0x2,	"d_move_wait"},
	{0x3,	"w_op_stv_wait"},
	{0x4,	"w_fl_comp_wait"},
	SPARC64_VI_EVENTS_comm_1,
	{0x13,	"sync_intlk"},
	{0x16,	"trap_trap_inst"},
	{0x18,	"ts_by_if"},
	SPARC64_VI_EVENTS_comm_2,
	{0x1e,	"fl_comp_wait"},
	{0x20,	"op_r_iu_req_mi_go"},
	{0x30,	"sx_read_count_pf"},
	{0x31,	"jbus_odrbus_busy"},
	{0x33,	"sx_miss_count_dm_if"},
	{0x36,	"jbus_odrbus1_busy"},
	{NT_END, ""}
};

static const struct nametable SPARC64_VI_names_u2[] = {
	SPARC64_VI_EVENTS_comm_0,
	{0x2,	"instruction_flow_counts"},
	{0x3,	"iwr_empty"},
	SPARC64_VI_EVENTS_comm_1,
	{0x16,	"trap_fill"},
	{0x18,	"ts_by_intr"},
	SPARC64_VI_EVENTS_comm_2,
	{0x1b,	"flush_rs"},
	{0x1d,	"cse_window_empty_sp_full"},
	{0x1e,	"op_stv_wait_ex"},
	{0x1f,	"3endop"},
	{0x20,	"if_r_iu_req_mi_go"},
	{0x24,	"swpf_lbs_hit"},
	{0x30,	"sx_read_count_dm"},
	{0x31,	"jbus_reqbus_busy"},
	{0x33,	"sx_btc_count"},
	{0x36,	"jbus_odrbus0_busy"},
	{NT_END, ""}
};

static const struct nametable SPARC64_VI_names_l3[] = {
	SPARC64_VI_EVENTS_comm_0,
	{0x2,	"xma_inst"},
	{0x3,	"w_0endop"},
	{0x4,	"w_op_stv_wait_ex"},
	SPARC64_VI_EVENTS_comm_1,
	{0x16,	"trap_DMMU_miss"},
	{0x18,	"ts_by_suspend"},
	{0x19,	"ts_by_other"},
	SPARC64_VI_EVENTS_comm_2,
	{0x1b,	"decall_intlk"},
	{0x1e,	"2endop"},
	{0x1f,	"op_stv_wait_sxmiss"},
	{0x20,	"op_wait_all"},
	{0x30,	"dvp_count_pf"},
	{0x33,	"sx_miss_count_dm_opex"},
	{0x36,	"jbus_odrbus3_busy"},
	{NT_END, ""}
};

static const struct nametable SPARC64_VI_names_u3[] = {
	SPARC64_VI_EVENTS_comm_0,
	{0x2,	"cse_priority_wait"},
	{0x3,	"w_d_move"},
	{0x4,	"w_cse_window_empty_sp_full"},
	SPARC64_VI_EVENTS_comm_1,
	{0x13,	"regwin_intlk"},
	{0x15,	"rs1"},
	{0x16,	"trap_IMMU_miss"},
	SPARC64_VI_EVENTS_comm_2,
	{0x1d,	"both_threads_suspended"},
	{0x1e,	"1endop"},
	{0x1f,	"op_stv_wait_sxmiss_ex"},
	{0x20,	"if_wait_all"},
	{0x30,	"dvp_count_dm"},
	{0x33,	"sx_miss_count_dm_opsh"},
	{0x36,	"jbus_odrbus2_busy"},
	{NT_END, ""}
};

#undef	SPARC64_VI_EVENTS_comm_0
#undef	SPARC64_VI_EVENTS_comm_1
#undef	SPARC64_VI_EVENTS_comm_2

static const struct nametable *SPARC64_VI_names[CPC_SPARC64_VI_NPIC] = {
	SPARC64_VI_names_l0,
	SPARC64_VI_names_u0,
	SPARC64_VI_names_l1,
	SPARC64_VI_names_u1,
	SPARC64_VI_names_l2,
	SPARC64_VI_names_u2,
	SPARC64_VI_names_l3,
	SPARC64_VI_names_u3
};

opl_pcbe_config_t nullpic[CPC_SPARC64_VI_NPIC] = {
	{0, 0x3f, 0, 0},
	{1, 0x3f, 0, 0},
	{2, 0x3f, 0, 0},
	{3, 0x3f, 0, 0},
	{4, 0x3f, 0, 0},
	{5, 0x3f, 0, 0},
	{6, 0x3f, 0, 0},
	{7, 0x3f, 0, 0}
};

static const struct nametable **events;
static const char *opl_impl_name;
static const char *opl_cpuref;
static char *pic_events[CPC_SPARC64_VI_NPIC];

static const char *sp_6_ref = "See the \"SPARC64 VI extensions\" and "
	"\"SPARC64 VII extensions\" for descriptions of these events.";

static int
opl_pcbe_init(void)
{
	const struct nametable	*n;
	int			i;
	size_t			size;

	/*
	 * Discover type of CPU
	 *
	 * Point nametable to that CPU's table
	 */
	switch (ULTRA_VER_IMPL(ultra_getver())) {
	case OLYMPUS_C_IMPL:
	case JUPITER_IMPL:
		events = SPARC64_VI_names;
		opl_impl_name = "SPARC64 VI & VII";
		opl_cpuref = sp_6_ref;
		break;
	default:
		return (-1);
	}

	/*
	 * Initialize the list of events for each PIC.
	 * Do two passes: one to compute the size necessary and another
	 * to copy the strings. Need room for event, comma, and NULL terminator.
	 */
	for (i = 0; i < CPC_SPARC64_VI_NPIC; i++) {
		size = 0;
		for (n = events[i]; n->bits != NT_END; n++)
			size += strlen(n->name) + 1;
		pic_events[i] = kmem_alloc(size + 1, KM_SLEEP);
		*pic_events[i] = '\0';
		for (n = events[i]; n->bits != NT_END; n++) {
			(void) strcat(pic_events[i], n->name);
			(void) strcat(pic_events[i], ",");
		}
		/*
		 * Remove trailing comma.
		 */
		pic_events[i][size - 1] = '\0';
	}

	return (0);
}

static uint_t
opl_pcbe_ncounters(void)
{
	return (CPC_SPARC64_VI_NPIC);
}

static const char *
opl_pcbe_impl_name(void)
{
	return (opl_impl_name);
}

static const char *
opl_pcbe_cpuref(void)
{
	return (opl_cpuref);
}

static char *
opl_pcbe_list_events(uint_t picnum)
{
	ASSERT(picnum >= 0 && picnum < cpc_ncounters);

	return (pic_events[picnum]);
}

static char *
opl_pcbe_list_attrs(void)
{
	return ("");
}

static const struct nametable *
find_event(int regno, char *name)
{
	const struct nametable *n;

	n = events[regno];

	for (; n->bits != NT_END; n++)
		if (strcmp(name, n->name) == 0)
			return (n);

	return (NULL);
}

static uint64_t
opl_pcbe_event_coverage(char *event)
{
	uint64_t bitmap = 0;

	int	i;
	for (i = 0; i < CPC_SPARC64_VI_NPIC; i++) {
		if (find_event(i, event) != NULL)
			bitmap |= (1 << i);
	}

	return (bitmap);
}

/*
 * Check if counter overflow and clear it.
 */
static uint64_t
opl_pcbe_overflow_bitmap(void)
{
	uint64_t	pcr;

	pcr = ultra_getpcr();
	DTRACE_PROBE1(sparc64__getpcr, uint64_t, pcr);

	return ((pcr & SPARC64_VI_PCR_OVF) >> CPC_SPARC64_VI_PCR_OVF_SHIFT);
}

/*ARGSUSED*/
static int
opl_pcbe_configure(uint_t picnum, char *event, uint64_t preset, uint32_t flags,
    uint_t nattrs, kcpc_attr_t *attrs, void **data, void *token)
{
	opl_pcbe_config_t *conf;
	const struct nametable *n;
	opl_pcbe_config_t *other_config;

	/*
	 * If we've been handed an existing configuration, we need only preset
	 * the counter value.
	 */
	if (*data != NULL) {
		conf = *data;
		conf->opl_pic = (uint32_t)preset;
		return (0);
	}

	if (picnum < 0 || picnum >= CPC_SPARC64_VI_NPIC)
		return (CPC_INVALID_PICNUM);

	if (nattrs != 0)
		return (CPC_INVALID_ATTRIBUTE);

	/*
	 * Find other requests that will be programmed with this one, and ensure
	 * the flags don't conflict.
	 */
	if (((other_config = kcpc_next_config(token, NULL, NULL)) != NULL) &&
	    (other_config->opl_flags != flags))
		return (CPC_CONFLICTING_REQS);

	if ((n = find_event(picnum, event)) == NULL)
		return (CPC_INVALID_EVENT);

	conf = kmem_alloc(sizeof (opl_pcbe_config_t), KM_SLEEP);

	conf->opl_picno = picnum;
	conf->opl_bits = (uint32_t)n->bits;
	conf->opl_flags = flags;
	conf->opl_pic = (uint32_t)preset;

	*data = conf;
	return (0);
}

static void
opl_pcbe_program(void *token)
{
	opl_pcbe_config_t	*pic[CPC_SPARC64_VI_NPIC];
	opl_pcbe_config_t	*firstconfig;
	opl_pcbe_config_t	*tmp;
	uint64_t		pcr;
	uint64_t		curpic;
	uint8_t			bitmap = 0;	/* for used pic config */
	int			i;
	opl_pcbe_config_t	dummypic[CPC_SPARC64_VI_NPIC];

	/* Get next pic config */
	firstconfig = tmp = kcpc_next_config(token, NULL, NULL);

	while (tmp != NULL) {
		ASSERT(tmp->opl_picno < CPC_SPARC64_VI_NPIC);
		ASSERT(firstconfig->opl_flags == tmp->opl_flags);
		pic[tmp->opl_picno] = tmp;
		bitmap |= (uint8_t)(1 << tmp->opl_picno);
		tmp = kcpc_next_config(token, tmp, NULL);
	}
	if (bitmap == 0)
		panic("opl_pcbe: token %p has no configs", token);

	/* Fill in unused pic config */
	for (i = 0; i < CPC_SPARC64_VI_NPIC; i++) {
		if (bitmap & (1 << i))
			continue;

		dummypic[i] = nullpic[i];
		dummypic[i].opl_flags = firstconfig->opl_flags;
		pic[i] = &dummypic[i];
	}

	/*
	 * For each counter pair, initialize event settings and
	 * counter values.
	 */
	ultra_setpcr(allstopped);
	pcr = allstopped;
	pcr &= ~SPARC64_VI_PCR_ULRO;
	for (i = 0; i < SPARC64_VI_NUM_PIC_PAIRS; i++) {
		SPARC64_VI_PCR_SEL_PIC(pcr, i);
		SPARC64_VI_PCR_SEL_EVENT(pcr, pic[i*2]->opl_bits,
		    pic[i*2 + 1]->opl_bits);

		ultra_setpcr(pcr);
		curpic = (uint64_t)(pic[i*2]->opl_pic |
		    ((uint64_t)pic[i*2 + 1]->opl_pic << 32));
		ultra_setpic(curpic);
	}

	/*
	 * For each counter pair, enable the trace flags to start
	 * counting. Re-read the counters to sample the counter value now
	 * and use that as the baseline for future samples.
	 */

	/* Get PCR */
	pcr = ultra_getpcr();
	pcr |= SPARC64_VI_PCR_ULRO;
	pcr &= ~(SPARC64_VI_PCR_OVRO | SPARC64_VI_PCR_OVF);

	if (pic[0]->opl_flags & CPC_COUNT_USER)
		pcr |= SPARC64_VI_PCR_USR;
	if (pic[0]->opl_flags & CPC_COUNT_SYSTEM)
		pcr |= SPARC64_VI_PCR_SYS;

	/* Set counter values */

	for (i = 0; i < SPARC64_VI_NUM_PIC_PAIRS; i++) {
		SPARC64_VI_PCR_SEL_PIC(pcr, i);
		SPARC64_VI_PCR_SEL_EVENT(pcr, pic[i*2]->opl_bits,
		    pic[i*2 + 1]->opl_bits);

		ultra_setpcr(pcr);
		DTRACE_PROBE1(sparc64__setpcr, uint64_t, pcr);

		curpic = ultra_getpic();
		DTRACE_PROBE1(sparc64__newpic, uint64_t, curpic);
		pic[i*2]->opl_pic = (uint32_t)(curpic & PIC_MASK);
		pic[i*2 + 1]->opl_pic = (uint32_t)(curpic >> 32);
	}
	pcr |= SPARC64_VI_PCR_OVRO;
	ultra_setpcr(pcr);
}

static void
opl_pcbe_allstop(void)
{
	ultra_setpcr(allstopped);
}


static void
opl_pcbe_sample(void *token)
{
	uint64_t		curpic;
	uint64_t		pcr;
	uint64_t		overflow;
	int64_t			diff;
	uint64_t		*pic_data[CPC_SPARC64_VI_NPIC];
	uint64_t		*dtmp;
	opl_pcbe_config_t	*pic[CPC_SPARC64_VI_NPIC];
	opl_pcbe_config_t	*ctmp;
	opl_pcbe_config_t	*firstconfig;
	uint8_t			bitmap = 0;	/* for used pic config */
	int			i;
	opl_pcbe_config_t dummypic[CPC_SPARC64_VI_NPIC];
	uint64_t dummypic_data[CPC_SPARC64_VI_NPIC];

	/* Get next pic config */
	firstconfig = ctmp = kcpc_next_config(token, NULL, &dtmp);

	while (ctmp != NULL) {
		ASSERT(ctmp->opl_picno < CPC_SPARC64_VI_NPIC);
		ASSERT(firstconfig->opl_flags == ctmp->opl_flags);
		pic[ctmp->opl_picno] = ctmp;
		pic_data[ctmp->opl_picno] = dtmp;
		bitmap |= (uint8_t)(1 << ctmp->opl_picno);
		ctmp = kcpc_next_config(token, ctmp, &dtmp);
	}
	if (bitmap == 0)
		panic("opl_pcbe: token %p has no configs", token);

	/* Fill in unuse pic config */
	for (i = 0; i < CPC_SPARC64_VI_NPIC; i++) {
		if (bitmap & (1 << i))
			continue;

		dummypic[i] = nullpic[i];
		dummypic[i].opl_flags = firstconfig->opl_flags;
		pic[i] = &dummypic[i];

		dummypic_data[i] = 0;
		pic_data[i] = &dummypic_data[i];
	}

	pcr = ultra_getpcr();
	pcr &= ~SPARC64_VI_PCR_OVRO;
	pcr |= SPARC64_VI_PCR_ULRO;

	for (i = 0; i < SPARC64_VI_NUM_PIC_PAIRS; i++) {
		SPARC64_VI_PCR_SEL_PIC(pcr, i);
		SPARC64_VI_PCR_SEL_EVENT(pcr, pic[i*2]->opl_bits,
		    pic[i*2 + 1]->opl_bits);

		ultra_setpcr(pcr);

		curpic = ultra_getpic();
		DTRACE_PROBE1(sparc64__getpic, unit64_t, curpic);

		diff = (curpic & PIC_MASK) - (uint64_t)pic[i*2]->opl_pic;
		overflow = SPARC64_VI_CHK_OVF(pcr, i*2);
		if (overflow || (diff < 0)) {
			SPARC64_VI_CLR_OVF(pcr, i*2);
			ultra_setpcr(pcr);
			diff += (1ll << 32);
		}
		*pic_data[i*2] += diff;

		diff = (curpic >> 32) - (uint64_t)pic[i*2 + 1]->opl_pic;
		overflow = SPARC64_VI_CHK_OVF(pcr, i*2 + 1);
		if (overflow || (diff < 0)) {
			SPARC64_VI_CLR_OVF(pcr, i*2 + 1);
			ultra_setpcr(pcr);
			diff += (1ll << 32);
		}
		*pic_data[i*2 + 1] += diff;

		pic[i*2]->opl_pic = (uint32_t)(curpic & PIC_MASK);
		pic[i*2 + 1]->opl_pic = (uint32_t)(curpic >> 32);
	}
	pcr = ultra_getpcr();
	pcr |= SPARC64_VI_PCR_OVRO;
	ultra_setpcr(pcr);
}

static void
opl_pcbe_free(void *config)
{
	kmem_free(config, sizeof (opl_pcbe_config_t));
}


static struct modlpcbe modlpcbe = {
	&mod_pcbeops,
	"SPARC64 VI&VII Perf Cntrs v%I%",
	&opl_pcbe_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modlpcbe,
};

int
_init(void)
{
	if (opl_pcbe_init() != 0)
		return (ENOTSUP);
	return (mod_install(&modl));
}

int
_fini(void)
{
	return (mod_remove(&modl));
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&modl, mi));
}
