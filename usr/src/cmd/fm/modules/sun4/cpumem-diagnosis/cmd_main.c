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

/*
 * CPU/Memory error diagnosis engine for the UltraSPARC III, IV, T1,
 * SPARC64 VI and SPARC64 VII families of processors.
 */

#include <cmd_state.h>
#include <cmd_cpu.h>

#ifdef sun4u
#include <cmd_ecache.h>
#include <cmd_Lxcache.h>
#endif /* sun4u */

#include <cmd_mem.h>
#include <cmd_page.h>
#include <cmd_dimm.h>
#ifdef sun4u
#include <cmd_dp.h>
#include <cmd_opl.h>
#endif
#include <cmd_bank.h>
#include <cmd.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <sys/async.h>

#ifdef	sun4v
#include <sys/fm/ldom.h>
static fmd_hdl_t *init_hdl;
ldom_hdl_t *cpumem_diagnosis_lhp;
#endif

cmd_t cmd;

#ifdef sun4u
cmd_list_t opl_cpu_list;
#endif	/* sun4u */

typedef struct cmd_subscriber {
	const char *subr_class;
	cmd_evdisp_t (*subr_func)(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
	    const char *, cmd_errcl_t);
	cmd_errcl_t subr_arg;
	cmd_evdisp_stat_t subr_stat;
} cmd_subscriber_t;

/*ARGSUSED*/
cmd_evdisp_t
cmd_nop(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (CMD_EVD_UNUSED);
}

#ifdef sun4u
/*
 * It used to be that cmd_opluecpu_detio() was called directly, with a
 * 'class' argument of ereport.io.oberon.xxx.  But the code underlying
 * cmd_opluecpu_detio() assumed that the class would always be of the form
 * ereport.cpu.<cputype>.<subclass>.
 *
 * Rather than generalizing the underlying code, the following adjusts the
 * input to cmd_opluecpu_detio() so that it conforms to the above expectation.
 */

/*ARGSUSED*/
cmd_evdisp_t
opl_opluecpu_detio(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	return (cmd_opluecpu_detio(hdl, ep, nvl,
	    "ereport.cpu.SPARC64-VI.", clcode));
}
#endif	/* sun4u */

static cmd_subscriber_t cmd_subscribers[] = {
#ifdef sun4u
	{ "ereport.cpu.*.ucc", 		cmd_xxc,	CMD_ERRCL_UCC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.ucu",		cmd_xxu,	CMD_ERRCL_UCU |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.cpc",		cmd_xxc,	CMD_ERRCL_CPC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.cpu",		cmd_xxu,	CMD_ERRCL_CPU |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.wdc",		cmd_xxc,	CMD_ERRCL_WDC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.wdu",		cmd_xxu,	CMD_ERRCL_WDU |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.edc",		cmd_xxc,	CMD_ERRCL_EDC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.edu-st",	cmd_xxu,	CMD_ERRCL_EDU_ST |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.edu-bl",	cmd_xxu,	CMD_ERRCL_EDU_BL |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-ucc", 	cmd_xxc,	CMD_ERRCL_L3_UCC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-ucu",	cmd_xxu,	CMD_ERRCL_L3_UCU |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-cpc",	cmd_xxc,	CMD_ERRCL_L3_CPC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-cpu",	cmd_xxu,	CMD_ERRCL_L3_CPU |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-wdc",	cmd_xxc,	CMD_ERRCL_L3_WDC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-wdu",	cmd_xxu,	CMD_ERRCL_L3_WDU |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-edc",	cmd_xxc,	CMD_ERRCL_L3_EDC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-edu-st",	cmd_xxu,	CMD_ERRCL_L3_EDU_ST |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-edu-bl",	cmd_xxu,	CMD_ERRCL_L3_EDU_BL |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.l3-mecc",	cmd_xxu,	CMD_ERRCL_L3_MECC |
    CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.ipe",		cmd_icache },
	{ "ereport.cpu.*.idspe",	cmd_icache },
	{ "ereport.cpu.*.itspe",	cmd_icache },
	{ "ereport.cpu.*.dpe",		cmd_dcache },
	{ "ereport.cpu.*.ddspe",	cmd_dcache },
	{ "ereport.cpu.*.dtspe",	cmd_dcache },
	{ "ereport.cpu.*.pdspe",	cmd_pcache },
	{ "ereport.cpu.*.itlbpe",	cmd_itlb },
	{ "ereport.cpu.*.dtlbpe",	cmd_dtlb },
	{ "ereport.cpu.*.thce",		cmd_txce, CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.tsce",		cmd_txce },
	{ "ereport.cpu.*.l3-thce",	cmd_l3_thce, CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.ce",		cmd_ce },
	{ "ereport.cpu.*.emc",		cmd_ce },
	{ "ereport.cpu.*.ue",		cmd_ue },
	{ "ereport.cpu.*.due",		cmd_ue },
	{ "ereport.cpu.*.emu",		cmd_ue },
	{ "ereport.cpu.*.frc",		cmd_frx,	CMD_ERRCL_FRC },
	{ "ereport.cpu.*.rce",		cmd_rxe,	CMD_ERRCL_RCE },
	{ "ereport.cpu.*.fru",		cmd_frx,	CMD_ERRCL_FRU },
	{ "ereport.cpu.*.rue",		cmd_rxe,	CMD_ERRCL_RUE },
	{ "ereport.cpu.*.eti",		cmd_txce },
	{ "ereport.cpu.*.etc",		cmd_txce },
	{ "ereport.io.*.ecc.drce",	cmd_ioxe,	CMD_ERRCL_IOCE },
	{ "ereport.io.*.ecc.dwce",	cmd_ioxe,	CMD_ERRCL_IOCE },
	{ "ereport.io.*.ecc.drue",	cmd_ioxe,	CMD_ERRCL_IOUE },
	{ "ereport.io.*.ecc.dwue",	cmd_ioxe,	CMD_ERRCL_IOUE },
	{ "ereport.io.*.ecc.s-drce",	cmd_ioxe_sec },
	{ "ereport.io.*.ecc.s-dwce",	cmd_ioxe_sec },
	{ "ereport.io.*.ecc.s-drue",	cmd_ioxe_sec },
	{ "ereport.io.*.ecc.s-dwue",	cmd_ioxe_sec },
	{ "ereport.io.fire.jbc.ce_asyn", cmd_ioxe,	CMD_ERRCL_IOCE },
	{ "ereport.io.fire.jbc.ue_asyn", cmd_ioxe,	CMD_ERRCL_IOUE },
	{ "ereport.asic.*.cds.cds-dp", 	cmd_dp_cds },
	{ "ereport.asic.*.dx.dx-dp",	cmd_dp_dx },
	{ "ereport.asic.*.sdi.sdi-dp", 	cmd_dp_ex },
	{ "ereport.asic.*.cp.cp-dp", 	cmd_dp_cp },
	{ "ereport.asic.*.rp.rp-dp", 	cmd_dp_cp },
	{ "ereport.asic.mac.mi-ue",			cmd_opl_mac_common },
	{ "ereport.asic.mac.ptrl-ue",			cmd_opl_mac_common },
	{ "ereport.asic.mac.mi-ce",			cmd_opl_mac_common },
	{ "ereport.asic.mac.ptrl-ce",			cmd_opl_mac_common },
	{ "ereport.asic.mac.ptrl-ice",			cmd_opl_mac_common },
	{ "ereport.asic.mac.mi-cmpe",			cmd_opl_mac_common },
	{ "ereport.asic.mac.ptrl-cmpe",			cmd_opl_mac_common },
	{ "ereport.asic.mac.mi-sue",			cmd_opl_mac_common },
	{ "ereport.asic.mac.ptrl-sue",			cmd_opl_mac_common },
	{ "ereport.asic.mac.mi-mue",			cmd_opl_mac_common },
	{ "ereport.asic.mac.ptrl-mue",			cmd_opl_mac_common },
	{ "ereport.cpu.*.ue-mem",			cmd_opl_cpu_mem },
	{ "ereport.cpu.*.ue-channel",			cmd_nop },
	{ "ereport.cpu.*.ue-cpu",			cmd_opluecpu_detcpu },
	{ "ereport.cpu.*.ue-path",			cmd_nop },
	{ "ereport.cpu.*.inv-sfsr",			cmd_oplinv_sfsr },
	{ "ereport.cpu.*.berr",				cmd_nop },
	{ "ereport.cpu.*.bto",				cmd_nop },
	{ "ereport.cpu.*.mtlb",				cmd_oplmtlb },
	{ "ereport.cpu.*.tlbp",				cmd_opltlbp },
	{ "ereport.cpu.*.inv-uge",			cmd_oplinv_urg },
	{ "ereport.cpu.*.cre",				cmd_oplcre },
	{ "ereport.cpu.*.tsb-ctx",			cmd_opltsb_ctx },
	{ "ereport.cpu.*.tsbp",				cmd_opltsbp },
	{ "ereport.cpu.*.pstate",			cmd_oplpstate },
	{ "ereport.cpu.*.tstate",			cmd_opltstate },
	{ "ereport.cpu.*.iug-f",			cmd_opliug_f },
	{ "ereport.cpu.*.iug-r",			cmd_opliug_r },
	{ "ereport.cpu.*.sdc",				cmd_oplsdc },
	{ "ereport.cpu.*.wdt",				cmd_oplwdt },
	{ "ereport.cpu.*.dtlb",				cmd_opldtlb },
	{ "ereport.cpu.*.itlb",				cmd_oplitlb },
	{ "ereport.cpu.*.core-err",			cmd_oplcore_err },
	{ "ereport.cpu.*.dae",				cmd_opldae },
	{ "ereport.cpu.*.iae",				cmd_opliae },
	{ "ereport.cpu.*.uge",				cmd_opluge },
	{ "ereport.io.oberon.ubc.dmarduea-mem",		cmd_opl_io_mem },
	{ "ereport.io.oberon.ubc.dmarduea-channel",	cmd_nop },
	{ "ereport.io.oberon.ubc.dmarduea-cpu",		opl_opluecpu_detio },
	{ "ereport.io.oberon.ubc.dmarduea-path",	cmd_nop },
	{ "ereport.io.oberon.ubc.dmardueb-mem",		cmd_opl_io_mem },
	{ "ereport.io.oberon.ubc.dmardueb-channel",	cmd_nop },
	{ "ereport.io.oberon.ubc.dmardueb-cpu",		opl_opluecpu_detio },
	{ "ereport.io.oberon.ubc.dmardueb-path",	cmd_nop },
	{ "ereport.io.oberon.ubc.piowtue-mem",		cmd_opl_io_mem },
	{ "ereport.io.oberon.ubc.piowtue-channel",	cmd_nop },
	{ "ereport.io.oberon.ubc.piowtue-cpu",		opl_opluecpu_detio },
	{ "ereport.io.oberon.ubc.piowtue-path",		cmd_nop },
	{ "ereport.io.oberon.ubc.piowbeue-mem",		cmd_opl_io_mem },
	{ "ereport.io.oberon.ubc.piowbeue-channel",	cmd_nop },
	{ "ereport.io.oberon.ubc.piowbeue-cpu",		opl_opluecpu_detio },
	{ "ereport.io.oberon.ubc.piowbeue-path",	cmd_nop },
	{ "ereport.io.oberon.ubc.piorbeue-mem",		cmd_opl_io_mem },
	{ "ereport.io.oberon.ubc.piorbeue-channel",	cmd_nop },
	{ "ereport.io.oberon.ubc.piorbeue-cpu",		opl_opluecpu_detio },
	{ "ereport.io.oberon.ubc.piorbeue-path",	cmd_nop },
#else /* i.e. sun4v */
	{ "ereport.cpu.*.irc",		cmd_irc },
	{ "ereport.cpu.*.iru", 		cmd_iru },
	{ "ereport.cpu.*.frc",		cmd_frc },
	{ "ereport.cpu.*.fru",		cmd_fru },
	{ "ereport.cpu.*.mau",		cmd_mau },
	{ "ereport.cpu.*.imdu",		cmd_itlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dmdu",		cmd_dtlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dmsu",		cmd_dtlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.imtu",		cmd_itlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dmtu",		cmd_dtlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.itc",		cmd_icache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.idc",		cmd_icache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dtc",		cmd_dcache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.ddc",		cmd_dcache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.irfc",		cmd_irc },
	{ "ereport.cpu.*.irfu",		cmd_iru },
	{ "ereport.cpu.*.frfc",		cmd_frc },
	{ "ereport.cpu.*.frfu",		cmd_fru },





	{ "ereport.cpu.*.mamu",		cmd_mau,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.ittm",		cmd_itlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.ittp",		cmd_itlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.itdp",		cmd_itlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.itmu",		cmd_itlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dttm",		cmd_dtlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dttp",		cmd_dtlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dtdp",		cmd_dtlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dtmu",		cmd_dtlb,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.icvp",		cmd_icache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.ictp",		cmd_icache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.ictm",		cmd_icache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.icdp",		cmd_xxc,
	    CMD_ERRCL_ICDP | CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dcvp",		cmd_dcache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dctp",		cmd_dcache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dctm",		cmd_dcache,	CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.dcdp",		cmd_xxc,
	    CMD_ERRCL_DCDP | CMD_CPU_LEVEL_CORE },
	{ "ereport.cpu.*.itl2c",	cmd_xxc,	CMD_ERRCL_LDAC |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.dtl2c",	cmd_xxc,	CMD_ERRCL_LDAC |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.icl2c",	cmd_xxc,	CMD_ERRCL_LDAC |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.dcl2c",	cmd_xxc,	CMD_ERRCL_LDAC |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.mal2c",	cmd_xxc,	CMD_ERRCL_LDAC |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.cwql2c",	cmd_xxc,	CMD_ERRCL_LDAC |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lvc",		cmd_txce,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.itl2u",	cmd_xxu,	CMD_ERRCL_IL2U |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.dtl2u",	cmd_xxu,	CMD_ERRCL_DL2U |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.icl2u",	cmd_xxu,	CMD_ERRCL_IL2U |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.dcl2u",	cmd_xxu,	CMD_ERRCL_DL2U |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.mal2u",	cmd_xxu,	CMD_ERRCL_LDAU |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.cwql2u",	cmd_xxu,	CMD_ERRCL_LDAU |
		CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lvf",		cmd_l2ctl,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lrf",		cmd_l2ctl,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ltu",		cmd_l2ctl,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.itl2nd",	cmd_nop_train,	CMD_ERRCL_IL2ND },
	{ "ereport.cpu.*.dtl2nd",	cmd_nop_train,	CMD_ERRCL_DL2ND },
	{ "ereport.cpu.*.icl2nd",	cmd_nop_train,	CMD_ERRCL_IL2ND },
	{ "ereport.cpu.*.dcl2nd",	cmd_nop_train,	CMD_ERRCL_DL2ND },
	{ "ereport.cpu.*.l2nd",		cmd_nop_train,	CMD_ERRCL_L2ND },
	{ "ereport.cpu.*.mal2nd",	cmd_nop_train,	CMD_ERRCL_L2ND },
	{ "ereport.cpu.*.cwql2nd",	cmd_nop_train,	CMD_ERRCL_L2ND },
	{ "ereport.cpu.*.ldac",		cmd_xxc, 	CMD_ERRCL_LDAC |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ldwc",		cmd_xxc,	CMD_ERRCL_LDWC |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ldrc",		cmd_xxc,	CMD_ERRCL_LDRC |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ldsc", 	cmd_xxc,	CMD_ERRCL_LDSC |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ltc",		cmd_txce,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ldau",		cmd_xxu, 	CMD_ERRCL_LDAU |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ldwu",		cmd_xxu,	CMD_ERRCL_LDWU |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ldru",		cmd_xxu,	CMD_ERRCL_LDRU |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.ldsu",		cmd_xxu,	CMD_ERRCL_LDSU |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lvu",		cmd_l2ctl, 	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lru",		cmd_l2ctl,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.fbr",		cmd_fb },
	{ "ereport.cpu.*.fbu",		cmd_fb_train,	CMD_ERRCL_FBU },
	{ "ereport.cpu.*.dac",		cmd_ce,		CMD_ERRCL_DAC },
	{ "ereport.cpu.*.dsc",		cmd_ce,		CMD_ERRCL_DSC },
	{ "ereport.cpu.*.dau",		cmd_ue_train,	CMD_ERRCL_DAU },
	{ "ereport.cpu.*.dbu",		cmd_fw_defect,	CMD_ERRCL_DBU },
	{ "ereport.cpu.*.dsu",		cmd_ue,		CMD_ERRCL_DSU },
	{ "ereport.cpu.*.sbdpc",	cmd_miscregs_train,
	    CMD_ERRCL_SBDPC | CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.sbdlc",	cmd_miscregs_train,
	    CMD_ERRCL_SBDLC | CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.sbdpu",	cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.sbdlu",	cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.sbdio",	cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.sbapp",	cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.mrau",		cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.scac",		cmd_miscregs_train,
	    CMD_ERRCL_SBDPC | CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.scau",		cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.tccp",		cmd_miscregs_train,
	    CMD_ERRCL_TCCP | CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.tccd",		cmd_miscregs_train,
	    CMD_ERRCL_TCCD | CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.tcup",		cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.tcud",		cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.tsac",		cmd_miscregs_train,
	    CMD_ERRCL_SBDPC | CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.tsau",		cmd_miscregs_ue,
	    CMD_CPU_LEVEL_THREAD },
	{ "ereport.cpu.*.cbce",		cmd_xxc,	CMD_ERRCL_CBCE |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.dce",		cmd_nop },
	{ "ereport.cpu.*.wbue",		cmd_xxu,	CMD_ERRCL_WBUE |
	    CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lfu-slf",	cmd_lfu_ce,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lfu-rtf",	cmd_lfu_ue,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lfu-tto",	cmd_lfu_ue,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lfu-cto",	cmd_lfu_ue,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.lfu-mlf",	cmd_lfu_ue,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.frack",	cmd_lfu_pe,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.fsr",		cmd_lfu_pe,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.fdr", 		cmd_lfu_pe,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.to",  		cmd_lfu_pe,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.cpu.*.snptyp",	cmd_lfu_pe,	CMD_CPU_LEVEL_CHIP },
	{ "ereport.fm.ferg.invalid",	cmd_fw_defect },
#endif /* sun4u */
	{ "ereport.cpu.*.fpu.hwcopy",	cmd_fpu },
	{ NULL, NULL }
};

static void
cmd_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	cmd_subscriber_t *sp;
	int disp;

	fmd_hdl_debug(hdl, "cmd_recv: begin: %s\n", strrchr(class, '.') + 1);

	for (sp = cmd_subscribers; sp->subr_class != NULL; sp++) {
		if (fmd_nvl_class_match(hdl, nvl, sp->subr_class)) {
			disp = sp->subr_func(hdl, ep, nvl, class, sp->subr_arg);
			((fmd_stat_t *)&sp->subr_stat)[disp].fmds_value.ui64++;
			fmd_hdl_debug(hdl, "cmd_recv: done: %s (disp %d)\n",
			    strrchr(class, '.') + 1, disp);
			return;
		}
	}

	fmd_hdl_debug(hdl, "cmd_recv: dropping %s - unable to handle\n", class);
}

static void
cmd_timeout(fmd_hdl_t *hdl, id_t id, void *arg)
{
	uintptr_t	timertype = (uintptr_t)arg;

	switch (timertype) {
		case CMD_TIMERTYPE_MEM:
			cmd_mem_timeout(hdl, id);
			break;

#ifdef sun4u
		case CMD_TIMERTYPE_DP:

			cmd_dp_timeout(hdl, id);
			break;
		case CMD_TIMERTYPE_ANONYMOUS_TAG_ERROR:

			cmd_Lxcache_anonymous_tag_error_timeout(hdl, id);
			break;
#endif

		case CMD_TIMERTYPE_CPU_UEC_FLUSH:
		case CMD_TIMERTYPE_CPU_XR_WAITER:
			cmd_cpu_timeout(hdl, id, (void *)timertype);
			break;

		default:
			break;
	}
}

static void
cmd_close(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	cmd_case_closer_t *cl = fmd_case_getspecific(hdl, cp);
	const char *uuid = fmd_case_uuid(hdl, cp);

	/*
	 * Our active cases all have closers registered in case-specific data.
	 * Cases in the process of closing (for which we've freed all associated
	 * data, but which haven't had an fmd-initiated fmdo_close callback)
	 * have had their case-specific data nulled out.
	 */
	fmd_hdl_debug(hdl, "close case %s%s\n", uuid,
	    (cl == NULL ? " (no cl)" : ""));

	if (cl != NULL)
		cl->cl_func(hdl, cl->cl_arg);
}

static void
cmd_gc(fmd_hdl_t *hdl)
{
	cmd_cpu_gc(hdl);
	cmd_mem_gc(hdl);
#ifdef sun4u
	cmd_Lxcache_gc(hdl);
#endif
}

static cmd_stat_t cmd_stats = {
	{ "bad_det", FMD_TYPE_UINT64, "detector missing or malformed" },
	{ "bad_cpu_asru", FMD_TYPE_UINT64, "CPU ASRU missing or malformed" },
	{ "bad_mem_asru", FMD_TYPE_UINT64, "memory ASRU missing or malformed" },
	{ "bad_close", FMD_TYPE_UINT64, "case close for nonexistent case" },
	{ "old_erpt", FMD_TYPE_UINT64, "ereport out of date wrt hardware" },
	{ "cpu_creat", FMD_TYPE_UINT64, "created new cpu structure" },
	{ "dimm_creat", FMD_TYPE_UINT64, "created new mem module structure" },
	{ "bank_creat", FMD_TYPE_UINT64, "created new mem bank structure" },
	{ "page_creat", FMD_TYPE_UINT64, "created new page structure" },
	{ "cache_creat", FMD_TYPE_UINT64, "created new cache structure" },
	{ "ce_unknown", FMD_TYPE_UINT64, "unknown CEs" },
	{ "ce_interm", FMD_TYPE_UINT64, "intermittent CEs" },
	{ "ce_ppersis", FMD_TYPE_UINT64, "possibly persistent CEs" },
	{ "ce_persis", FMD_TYPE_UINT64, "persistent CEs" },
	{ "ce_leaky", FMD_TYPE_UINT64, "leaky CEs" },
	{ "ce_psticky_noptnr", FMD_TYPE_UINT64,
	    "possibly sticky CEs, no partner test" },
	{ "ce_psticky_ptnrnoerr", FMD_TYPE_UINT64,
	    "possibly sticky CEs, partner sees no CE" },
	{ "ce_psticky_ptnrclrd", FMD_TYPE_UINT64,
	    "possibly sticky CEs, partner can clear CE" },
	{ "ce_sticky", FMD_TYPE_UINT64, "sticky CEs" },
	{ "xxu_ue_match", FMD_TYPE_UINT64, "xxUs obviated by UEs" },
	{ "xxu_retr_flt", FMD_TYPE_UINT64, "xxUs obviated by faults" },
	{ "cpu_migrat", FMD_TYPE_UINT64, "CPUs migrated to new version" },
	{ "dimm_migrat", FMD_TYPE_UINT64, "DIMMs migrated to new version" },
	{ "bank_migrat", FMD_TYPE_UINT64, "banks migrated to new version" },
#ifdef sun4u
	{ "dp_ignored_ce", FMD_TYPE_UINT64,
	    "memory CEs ignored due to DP error or fault" },
	{ "dp_ignored_ue", FMD_TYPE_UINT64,
	    "memory UEs ignored due to DP fault" },
	{ "dp_deferred_ue", FMD_TYPE_UINT64,
	    "memory UEs deferred due to DP error" },
#endif
#ifdef sun4v
	{ "branch_creat", FMD_TYPE_UINT64, "created new mem branch structure" },
#endif
};

static const fmd_prop_t fmd_props[] = {
	{ "icache_n", FMD_TYPE_UINT32, "8" },
	{ "icache_t", FMD_TYPE_TIME, "168h" },
	{ "dcache_n", FMD_TYPE_UINT32, "8" },
	{ "dcache_t", FMD_TYPE_TIME, "168h" },
	{ "pcache_n", FMD_TYPE_UINT32, "2" },
	{ "pcache_t", FMD_TYPE_TIME, "168h" },
#ifdef sun4u
	{ "itlb_n", FMD_TYPE_UINT32, "2" },
	{ "itlb_t", FMD_TYPE_TIME, "168h" },
	{ "dtlb_n", FMD_TYPE_UINT32, "2" },
	{ "dtlb_t", FMD_TYPE_TIME, "168h" },
	{ "l2tag_n", FMD_TYPE_UINT32, "4" },
	{ "l2tag_t", FMD_TYPE_TIME, "1h" },
	{ "l2data_n", FMD_TYPE_UINT32, "12" },
	{ "l2data_t", FMD_TYPE_TIME, "1h" },
#else
	{ "itlb_n", FMD_TYPE_UINT32, "8" },
	{ "itlb_t", FMD_TYPE_TIME, "168h" },
	{ "dtlb_n", FMD_TYPE_UINT32, "8" },
	{ "dtlb_t", FMD_TYPE_TIME, "168h" },
	{ "l2tag_n", FMD_TYPE_UINT32, "8" },
	{ "l2tag_t", FMD_TYPE_TIME, "20h" },
	{ "l2data_n", FMD_TYPE_UINT32, "8" },
	{ "l2data_t", FMD_TYPE_TIME, "2h" },
#endif
	{ "l3tag_n", FMD_TYPE_UINT32, "4" },
	{ "l3tag_t", FMD_TYPE_TIME, "1h" },
	{ "l3data_n", FMD_TYPE_UINT32, "12" },
	{ "l3data_t", FMD_TYPE_TIME, "1h" },
	{ "ce_n", FMD_TYPE_UINT32, "2" },
	{ "ce_t", FMD_TYPE_TIME, "72h" },
	{ "ireg_n", FMD_TYPE_UINT32, "8" },
	{ "ireg_t", FMD_TYPE_TIME, "168h" },
	{ "freg_n", FMD_TYPE_UINT32, "8" },
	{ "freg_t", FMD_TYPE_TIME, "168h" },
	{ "mau_n", FMD_TYPE_UINT32, "0" },
	{ "mau_t", FMD_TYPE_TIME, "168h" },
	{ "misc_regs_n", FMD_TYPE_UINT32, "8"},
	{ "misc_regs_t", FMD_TYPE_TIME, "168h" },
	{ "iorxefrx_window", FMD_TYPE_TIME, "3s" },
#ifdef sun4u
	{ "xxcu_trdelay", FMD_TYPE_TIME, "200ms" },
#else
	{ "xxcu_trdelay", FMD_TYPE_TIME, "15s"},
#endif /* sun4u */
	{ "xxcu_restart_delay", FMD_TYPE_TIME, "1s" },
	{ "num_xxcu_waiters", FMD_TYPE_UINT32, "128" },
	{ "thresh_tpct_sysmem", FMD_TYPE_UINT64, "100" },
	{ "thresh_abs_sysmem", FMD_TYPE_UINT64, "0" },
	{ "thresh_abs_badrw", FMD_TYPE_UINT64, "128" },
	{ "max_perm_ce_dimm", FMD_TYPE_UINT32, "128" },
	{ "low_ce_thresh", FMD_TYPE_UINT32, "128" },
	{ "hi_ce_thresh", FMD_TYPE_UINT32, "512" },
	{ "dupce", FMD_TYPE_UINT32, "120"},
	{ "nupos", FMD_TYPE_UINT32, "4"},
#ifdef sun4v
	{ "fbr_n", FMD_TYPE_UINT32, "14" },
	{ "fbr_t", FMD_TYPE_TIME, "30min"},
	/* delta_ena value = 0x500000000nsec ~= 22sec */
	{ "delta_ena", FMD_TYPE_UINT64, "0x50000000000000"},
#endif
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	cmd_recv,	/* fmdo_recv */
	cmd_timeout,	/* fmdo_timeout */
	cmd_close,	/* fmdo_close */
	NULL,		/* fmdo_stats */
	cmd_gc		/* fmdo_gc */
};

static const fmd_hdl_info_t fmd_info = {
	"CPU/Memory Diagnosis", CMD_VERSION, &fmd_ops, fmd_props
};

static const struct cmd_evdisp_name {
	const char *evn_name;
	const char *evn_desc;
} cmd_evdisp_names[] = {
	{ "%s", "ok %s ereports" },			/* CMD_EVD_OK */
	{ "bad_%s", "bad %s ereports" },		/* CMD_EVD_BAD */
	{ "unused_%s", "unused %s ereports" },		/* CMD_EVD_UNUSED */
	{ "redun_%s", "redundant %s ereports" },	/* CMD_EVD_REDUN */
};

void
_fmd_fini(fmd_hdl_t *hdl)
{

#ifdef	sun4v
	ldom_fini(cpumem_diagnosis_lhp);
#endif
	cmd_cpu_fini(hdl);
	cmd_mem_fini(hdl);
	cmd_page_fini(hdl);
#ifdef sun4u
	cmd_dp_fini(hdl);
#endif

	fmd_hdl_free(hdl, cmd.cmd_xxcu_trw,
	    sizeof (cmd_xxcu_trw_t) * cmd.cmd_xxcu_ntrw);
	nvlist_free(cmd.cmd_auth);
}

#ifdef	sun4v
static void *
cpumem_diagnosis_init_alloc(size_t size)
{
	return (fmd_hdl_alloc(init_hdl, size, FMD_SLEEP));
}

static void
cpumem_diagnosis_init_free(void *addr, size_t size)
{
	fmd_hdl_free(init_hdl, addr, size);
}
#endif

/* find_auth -- find hardware platform authority within libtopo */

/* ARGSUSED */
static int
find_auth(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	nvlist_t *rsrc, *auth;

	if (cmd.cmd_auth != NULL)
		return (TOPO_WALK_TERMINATE); /* don't overwrite previous */

	if (topo_node_resource(node, &rsrc, &err) < 0)
		return (TOPO_WALK_NEXT);	/* no resource, try next */
	if (nvlist_lookup_nvlist(rsrc, FM_FMRI_AUTHORITY, &auth) < 0) {
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT);	/* no authority, try next */
	}
	(void) nvlist_dup(auth, &cmd.cmd_auth, NV_UNIQUE_NAME);
	nvlist_free(rsrc);
	return (TOPO_WALK_TERMINATE);	/* if no space, give up */
}

/* init_auth -- read hardware platform authority from libtopo */

void
init_auth(fmd_hdl_t *hdl)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return;
	if ((twp = topo_walk_init(thp,
	    FM_FMRI_SCHEME_HC, find_auth, NULL, &err))
	    == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return;
	}
	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);
}

void
_fmd_init(fmd_hdl_t *hdl)
{
	cmd_subscriber_t *sp;
	cpu_family_t cpu_family;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* error in configuration file or fmd_info */

	cpu_family = cmd_cpu_check_support();

	if (cpu_family == CMD_CPU_FAM_UNSUPPORTED) {
		fmd_hdl_debug(hdl, "no supported CPUs found");
		fmd_hdl_unregister(hdl);
		return;
	}

	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-III.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-IIIplus.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-IIIi.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-IIIiplus.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-IV.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-IVplus.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-T2.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-T2plus.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.ultraSPARC-T1.*");
	fmd_hdl_subscribe(hdl, "ereport.fm.ferg.invalid");

	fmd_hdl_subscribe(hdl, "ereport.io.tom.ecc.drce");
	fmd_hdl_subscribe(hdl, "ereport.io.tom.ecc.dwce");
	fmd_hdl_subscribe(hdl, "ereport.io.tom.ecc.drue");
	fmd_hdl_subscribe(hdl, "ereport.io.tom.ecc.dwue");
	fmd_hdl_subscribe(hdl, "ereport.io.sch.ecc.drce");
	fmd_hdl_subscribe(hdl, "ereport.io.sch.ecc.dwce");
	fmd_hdl_subscribe(hdl, "ereport.io.sch.ecc.drue");
	fmd_hdl_subscribe(hdl, "ereport.io.sch.ecc.dwue");
	fmd_hdl_subscribe(hdl, "ereport.io.xmits.ecc.drce");
	fmd_hdl_subscribe(hdl, "ereport.io.xmits.ecc.dwce");
	fmd_hdl_subscribe(hdl, "ereport.io.xmits.ecc.drue");
	fmd_hdl_subscribe(hdl, "ereport.io.xmits.ecc.dwue");

	/*
	 * Need to subscribe to secondary I/O ECC ereports, but
	 * since they contain no data regarding the failure we
	 * are unable to do anything with them.
	 */
	fmd_hdl_subscribe(hdl, "ereport.io.tom.ecc.s-drce");
	fmd_hdl_subscribe(hdl, "ereport.io.tom.ecc.s-dwce");
	fmd_hdl_subscribe(hdl, "ereport.io.tom.ecc.s-drue");
	fmd_hdl_subscribe(hdl, "ereport.io.tom.ecc.s-dwue");
	fmd_hdl_subscribe(hdl, "ereport.io.sch.ecc.s-drce");
	fmd_hdl_subscribe(hdl, "ereport.io.sch.ecc.s-dwce");
	fmd_hdl_subscribe(hdl, "ereport.io.sch.ecc.s-drue");
	fmd_hdl_subscribe(hdl, "ereport.io.sch.ecc.s-dwue");
	fmd_hdl_subscribe(hdl, "ereport.io.xmits.ecc.s-drce");
	fmd_hdl_subscribe(hdl, "ereport.io.xmits.ecc.s-dwce");
	fmd_hdl_subscribe(hdl, "ereport.io.xmits.ecc.s-drue");
	fmd_hdl_subscribe(hdl, "ereport.io.xmits.ecc.s-dwue");

#ifdef sun4u
	/*
	 * Subscribe to datapath events
	 */
	fmd_hdl_subscribe(hdl, "ereport.asic.*.cds.cds-dp");
	fmd_hdl_subscribe(hdl, "ereport.asic.*.dx.dx-dp");
	fmd_hdl_subscribe(hdl, "ereport.asic.*.sdi.sdi-dp");
	fmd_hdl_subscribe(hdl, "ereport.asic.*.cp.cp-dp");
	fmd_hdl_subscribe(hdl, "ereport.asic.*.rp.rp-dp");

	/*
	 * OPL platform specific subscriptions.
	 */
	fmd_hdl_subscribe(hdl, "ereport.cpu.SPARC64-VI.*");
	fmd_hdl_subscribe(hdl, "ereport.cpu.SPARC64-VII.*");
	fmd_hdl_subscribe(hdl, "ereport.asic.mac.*");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.dmarduea-mem");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.dmarduea-channel");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.dmarduea-cpu");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.dmarduea-path");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.dmardueb-mem");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.dmardueb-channel");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.dmardueb-cpu");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.dmardueb-path");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piowtue-mem");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piowtue-channel");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piowtue-cpu");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piowtue-path");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piowbeue-mem");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piowbeue-channel");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piowbeue-cpu");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piowbeue-path");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piorbeue-mem");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piorbeue-channel");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piorbeue-cpu");
	fmd_hdl_subscribe(hdl, "ereport.io.oberon.ubc.piorbeue-path");
#endif
	fmd_hdl_subscribe(hdl, "ereport.io.fire.jbc.ce_asyn");
	fmd_hdl_subscribe(hdl, "ereport.io.fire.jbc.ue_asyn");

	bzero(&cmd, sizeof (cmd_t));

#ifdef sun4u
	bzero(&opl_cpu_list, sizeof (cmd_list_t));
#endif	/* sun4u */

	cmd.cmd_stats = (cmd_stat_t *)fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (cmd_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&cmd_stats);

	for (sp = cmd_subscribers; sp->subr_class != NULL; sp++) {
		const char *type = strrchr(sp->subr_class, '.') + 1;
		int i;

		for (i = 0; i < sizeof (cmd_evdisp_names) /
		    sizeof (struct cmd_evdisp_name); i++) {
			fmd_stat_t *stat = ((fmd_stat_t *)&sp->subr_stat) + i;

			(void) snprintf(stat->fmds_name,
			    sizeof (stat->fmds_name),
			    cmd_evdisp_names[i].evn_name, type);

			stat->fmds_type = FMD_TYPE_UINT64;
			(void) snprintf(stat->fmds_desc,
			    sizeof (stat->fmds_desc),
			    cmd_evdisp_names[i].evn_desc, type);

			(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, 1, stat);
		}
	}

	cmd.cmd_pagesize = sysconf(_SC_PAGESIZE);
	cmd.cmd_pagemask = ~((uint64_t)cmd.cmd_pagesize - 1);

	cmd.cmd_iorxefrx_window = fmd_prop_get_int64(hdl, "iorxefrx_window");

#ifdef sun4u
	if (cmd_cpu_ecache_support() && cmd_ecache_init() < 0) {
		_fmd_fini(hdl);
		fmd_hdl_abort(hdl, "failed to find device for E-cache flush");
	}
#endif

	if ((cmd.cmd_thresh_tpct_sysmem = fmd_prop_get_int64(hdl,
	    "thresh_tpct_sysmem")) > 100000) {
		_fmd_fini(hdl);
		fmd_hdl_abort(hdl, "page retirement threshold is >100%");
	}

	cmd.cmd_thresh_abs_sysmem = fmd_prop_get_int64(hdl,
	    "thresh_abs_sysmem");
	cmd.cmd_thresh_abs_badrw = fmd_prop_get_int64(hdl,
	    "thresh_abs_badrw");

	cmd.cmd_xxcu_trdelay = fmd_prop_get_int64(hdl, "xxcu_trdelay");

	cmd.cmd_xxcu_ntrw = fmd_prop_get_int32(hdl, "num_xxcu_waiters");
	cmd.cmd_xxcu_trw = fmd_hdl_zalloc(hdl, sizeof (cmd_xxcu_trw_t) *
	    cmd.cmd_xxcu_ntrw, FMD_SLEEP);
	cmd.cmd_low_ce_thresh = fmd_prop_get_int32(hdl, "low_ce_thresh");
	cmd.cmd_hi_ce_thresh = fmd_prop_get_int32(hdl, "hi_ce_thresh");
	cmd.cmd_dupce = fmd_prop_get_int32(hdl, "dupce");
	cmd.cmd_nupos = fmd_prop_get_int32(hdl, "nupos");

#ifdef sun4v
	cmd.cmd_delta_ena = fmd_prop_get_int64(hdl, "delta_ena");
#endif

	cmd.cmd_l2data_serd.cs_name = "l2data";
	cmd.cmd_l2data_serd.cs_n = fmd_prop_get_int32(hdl, "l2data_n");
	cmd.cmd_l2data_serd.cs_t = fmd_prop_get_int64(hdl, "l2data_t");

	cmd.cmd_l3data_serd.cs_name = "l3data";
	cmd.cmd_l3data_serd.cs_n = fmd_prop_get_int32(hdl, "l3data_n");
	cmd.cmd_l3data_serd.cs_t = fmd_prop_get_int64(hdl, "l3data_t");

	cmd.cmd_miscregs_serd.cs_name = "misc_regs";
	cmd.cmd_miscregs_serd.cs_n = fmd_prop_get_int32(hdl, "misc_regs_n");
	cmd.cmd_miscregs_serd.cs_t = fmd_prop_get_int64(hdl, "misc_regs_t");

	cmd.cmd_dcache_serd.cs_name = "dcache";
	cmd.cmd_dcache_serd.cs_n = fmd_prop_get_int32(hdl, "dcache_n");
	cmd.cmd_dcache_serd.cs_t = fmd_prop_get_int64(hdl, "dcache_t");

	cmd.cmd_icache_serd.cs_name = "icache";
	cmd.cmd_icache_serd.cs_n = fmd_prop_get_int32(hdl, "icache_n");
	cmd.cmd_icache_serd.cs_t = fmd_prop_get_int64(hdl, "icache_t");

	if (cmd_state_restore(hdl) < 0) {
		_fmd_fini(hdl);
		fmd_hdl_abort(hdl, "failed to restore saved state\n");
	}

#ifdef	sun4v
	init_hdl = hdl;
	cpumem_diagnosis_lhp = ldom_init(cpumem_diagnosis_init_alloc,
	    cpumem_diagnosis_init_free);
#endif

	init_auth(hdl);
}
