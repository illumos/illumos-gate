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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Field information for most the various supported classes logs: supported log
 * pages, supported commands, supported features, and supported management
 * commands.
 */

#include <sys/stddef.h>
#include <sys/sysmacros.h>

#include "nvmeadm.h"

static const nvmeadm_field_bit_t suplog_fid_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "lsupp",
	.nfb_desc = "Log Page Identifier",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "ios",
	.nfb_desc = "Index Offset",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 16, .nfb_hibit = 31,
	.nfb_short = "lidsp",
	.nfb_desc = "LID Specific Parameter",
	.nfb_type = NVMEADM_FT_HEX
} };

#define	SUPLOG(f)	{ .nf_off = offsetof(nvme_suplog_log_t, nl_logs[f]), \
	.nf_len = sizeof (((nvme_suplog_log_t *)NULL)->nl_logs[f]), \
	.nf_short = "lids" #f, .nf_desc = "Log Page Identifier " #f, \
	NVMEADM_F_BITS(suplog_fid_bits) }

static const nvmeadm_field_t suplog_fields[] = {
	SUPLOG(0), SUPLOG(1), SUPLOG(2), SUPLOG(3),
	SUPLOG(4), SUPLOG(5), SUPLOG(6), SUPLOG(7),
	SUPLOG(8), SUPLOG(9), SUPLOG(10), SUPLOG(11),
	SUPLOG(12), SUPLOG(13), SUPLOG(14), SUPLOG(15),
	SUPLOG(16), SUPLOG(17), SUPLOG(18), SUPLOG(19),
	SUPLOG(20), SUPLOG(21), SUPLOG(22), SUPLOG(23),
	SUPLOG(24), SUPLOG(25), SUPLOG(26), SUPLOG(27),
	SUPLOG(28), SUPLOG(29), SUPLOG(30), SUPLOG(31),
	SUPLOG(32), SUPLOG(33), SUPLOG(34), SUPLOG(35),
	SUPLOG(36), SUPLOG(37), SUPLOG(38), SUPLOG(39),
	SUPLOG(40), SUPLOG(41), SUPLOG(42), SUPLOG(43),
	SUPLOG(44), SUPLOG(45), SUPLOG(46), SUPLOG(47),
	SUPLOG(48), SUPLOG(49), SUPLOG(50), SUPLOG(51),
	SUPLOG(52), SUPLOG(53), SUPLOG(54), SUPLOG(55),
	SUPLOG(56), SUPLOG(57), SUPLOG(58), SUPLOG(59),
	SUPLOG(60), SUPLOG(61), SUPLOG(62), SUPLOG(63),
	SUPLOG(64), SUPLOG(65), SUPLOG(66), SUPLOG(67),
	SUPLOG(68), SUPLOG(69), SUPLOG(70), SUPLOG(71),
	SUPLOG(72), SUPLOG(73), SUPLOG(74), SUPLOG(75),
	SUPLOG(76), SUPLOG(77), SUPLOG(78), SUPLOG(79),
	SUPLOG(80), SUPLOG(81), SUPLOG(82), SUPLOG(83),
	SUPLOG(84), SUPLOG(85), SUPLOG(86), SUPLOG(87),
	SUPLOG(88), SUPLOG(89), SUPLOG(90), SUPLOG(91),
	SUPLOG(92), SUPLOG(93), SUPLOG(94), SUPLOG(95),
	SUPLOG(96), SUPLOG(97), SUPLOG(98), SUPLOG(99),
	SUPLOG(100), SUPLOG(101), SUPLOG(102), SUPLOG(103),
	SUPLOG(104), SUPLOG(105), SUPLOG(106), SUPLOG(107),
	SUPLOG(108), SUPLOG(109), SUPLOG(110), SUPLOG(111),
	SUPLOG(112), SUPLOG(113), SUPLOG(114), SUPLOG(115),
	SUPLOG(116), SUPLOG(117), SUPLOG(118), SUPLOG(119),
	SUPLOG(120), SUPLOG(121), SUPLOG(122), SUPLOG(123),
	SUPLOG(124), SUPLOG(125), SUPLOG(126), SUPLOG(127),
	SUPLOG(128), SUPLOG(129), SUPLOG(130), SUPLOG(131),
	SUPLOG(132), SUPLOG(133), SUPLOG(134), SUPLOG(135),
	SUPLOG(136), SUPLOG(137), SUPLOG(138), SUPLOG(139),
	SUPLOG(140), SUPLOG(141), SUPLOG(142), SUPLOG(143),
	SUPLOG(144), SUPLOG(145), SUPLOG(146), SUPLOG(147),
	SUPLOG(148), SUPLOG(149), SUPLOG(150), SUPLOG(151),
	SUPLOG(152), SUPLOG(153), SUPLOG(154), SUPLOG(155),
	SUPLOG(156), SUPLOG(157), SUPLOG(158), SUPLOG(159),
	SUPLOG(160), SUPLOG(161), SUPLOG(162), SUPLOG(163),
	SUPLOG(164), SUPLOG(165), SUPLOG(166), SUPLOG(167),
	SUPLOG(168), SUPLOG(169), SUPLOG(170), SUPLOG(171),
	SUPLOG(172), SUPLOG(173), SUPLOG(174), SUPLOG(175),
	SUPLOG(176), SUPLOG(177), SUPLOG(178), SUPLOG(179),
	SUPLOG(180), SUPLOG(181), SUPLOG(182), SUPLOG(183),
	SUPLOG(184), SUPLOG(185), SUPLOG(186), SUPLOG(187),
	SUPLOG(188), SUPLOG(189), SUPLOG(190), SUPLOG(191),
	SUPLOG(192), SUPLOG(193), SUPLOG(194), SUPLOG(195),
	SUPLOG(196), SUPLOG(197), SUPLOG(198), SUPLOG(199),
	SUPLOG(200), SUPLOG(201), SUPLOG(202), SUPLOG(203),
	SUPLOG(204), SUPLOG(205), SUPLOG(206), SUPLOG(207),
	SUPLOG(208), SUPLOG(209), SUPLOG(210), SUPLOG(211),
	SUPLOG(212), SUPLOG(213), SUPLOG(214), SUPLOG(215),
	SUPLOG(216), SUPLOG(217), SUPLOG(218), SUPLOG(219),
	SUPLOG(220), SUPLOG(221), SUPLOG(222), SUPLOG(223),
	SUPLOG(224), SUPLOG(225), SUPLOG(226), SUPLOG(227),
	SUPLOG(228), SUPLOG(229), SUPLOG(230), SUPLOG(231),
	SUPLOG(232), SUPLOG(233), SUPLOG(234), SUPLOG(235),
	SUPLOG(236), SUPLOG(237), SUPLOG(238), SUPLOG(239),
	SUPLOG(240), SUPLOG(241), SUPLOG(242), SUPLOG(243),
	SUPLOG(244), SUPLOG(245), SUPLOG(246), SUPLOG(247),
	SUPLOG(248), SUPLOG(249), SUPLOG(250), SUPLOG(251),
	SUPLOG(252), SUPLOG(253), SUPLOG(254), SUPLOG(255)
};

const nvmeadm_log_field_info_t suplog_field_info = {
	.nlfi_log = "suplog",
	.nlfi_fields = suplog_fields,
	.nlfi_nfields = ARRAY_SIZE(suplog_fields),
	.nlfi_min = sizeof (nvme_suplog_t),
};

static const nvmeadm_field_bit_t supcmd_csp_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "nscpe",
	.nfb_desc = "Namespace Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "cscpe",
	.nfb_desc = "Controller Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "nsetcpe",
	.nfb_desc = "NVM Set Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "egscpe",
	.nfb_desc = "Endurance Group Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "dscpe",
	.nfb_desc = "Domain Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 5, .nfb_hibit = 5,
	.nfb_short = "nsscpe",
	.nfb_desc = "NVM Subsystem Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_bit_t supcmd_cs_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "csupp",
	.nfb_desc = "Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "lbcc",
	.nfb_desc = "Logical Block Content",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "ncc",
	.nfb_desc = "Namespace Capability",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "nic",
	.nfb_desc = "Namespace Inventory",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "ccc",
	.nfb_desc = "Controller Capability",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 14, .nfb_hibit = 15,
	.nfb_short = "cser",
	.nfb_desc = "Command Submission and Execution Relaxations",
	.nfb_vers = &nvme_vers_2v1,
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no relaxation", "any namespace" },
}, {
	.nfb_lowbit = 16, .nfb_hibit = 18,
	.nfb_short = "cse",
	.nfb_desc = "Command Submission and Execution",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no restriction", "same namespace", "any namespace" },
}, {
	.nfb_lowbit = 19, .nfb_hibit = 19,
	.nfb_short = "uss",
	.nfb_vers = &nvme_vers_1v4,
	.nfb_desc = "UUID Selection",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 20, .nfb_hibit = 31,
	.nfb_short = "csp",
	.nfb_desc = "Command Scope",
	.nfb_vers = &nvme_vers_2v0,
	NVMEADM_FB_BITS(supcmd_csp_bits)
} };

#define	SUPCMD_A(f)	{ .nf_off = offsetof(nvme_cmdeff_log_t, cme_admin[f]), \
	.nf_len = sizeof (((nvme_cmdeff_log_t *)NULL)->cme_admin[f]), \
	.nf_short = "acs" #f, .nf_desc = "Admin Command Supported " #f, \
	NVMEADM_F_BITS(supcmd_cs_bits) }

#define	SUPCMD_I(f)	{ .nf_off = offsetof(nvme_cmdeff_log_t, cme_io[f]), \
	.nf_len = sizeof (((nvme_cmdeff_log_t *)NULL)->cme_io[f]), \
	.nf_short = "iocs" #f, .nf_desc = "I/O Command Supported " #f, \
	NVMEADM_F_BITS(supcmd_cs_bits) }


static const nvmeadm_field_t supcmd_fields[] = {
	SUPCMD_A(0), SUPCMD_A(1), SUPCMD_A(2), SUPCMD_A(3),
	SUPCMD_A(4), SUPCMD_A(5), SUPCMD_A(6), SUPCMD_A(7),
	SUPCMD_A(8), SUPCMD_A(9), SUPCMD_A(10), SUPCMD_A(11),
	SUPCMD_A(12), SUPCMD_A(13), SUPCMD_A(14), SUPCMD_A(15),
	SUPCMD_A(16), SUPCMD_A(17), SUPCMD_A(18), SUPCMD_A(19),
	SUPCMD_A(20), SUPCMD_A(21), SUPCMD_A(22), SUPCMD_A(23),
	SUPCMD_A(24), SUPCMD_A(25), SUPCMD_A(26), SUPCMD_A(27),
	SUPCMD_A(28), SUPCMD_A(29), SUPCMD_A(30), SUPCMD_A(31),
	SUPCMD_A(32), SUPCMD_A(33), SUPCMD_A(34), SUPCMD_A(35),
	SUPCMD_A(36), SUPCMD_A(37), SUPCMD_A(38), SUPCMD_A(39),
	SUPCMD_A(40), SUPCMD_A(41), SUPCMD_A(42), SUPCMD_A(43),
	SUPCMD_A(44), SUPCMD_A(45), SUPCMD_A(46), SUPCMD_A(47),
	SUPCMD_A(48), SUPCMD_A(49), SUPCMD_A(50), SUPCMD_A(51),
	SUPCMD_A(52), SUPCMD_A(53), SUPCMD_A(54), SUPCMD_A(55),
	SUPCMD_A(56), SUPCMD_A(57), SUPCMD_A(58), SUPCMD_A(59),
	SUPCMD_A(60), SUPCMD_A(61), SUPCMD_A(62), SUPCMD_A(63),
	SUPCMD_A(64), SUPCMD_A(65), SUPCMD_A(66), SUPCMD_A(67),
	SUPCMD_A(68), SUPCMD_A(69), SUPCMD_A(70), SUPCMD_A(71),
	SUPCMD_A(72), SUPCMD_A(73), SUPCMD_A(74), SUPCMD_A(75),
	SUPCMD_A(76), SUPCMD_A(77), SUPCMD_A(78), SUPCMD_A(79),
	SUPCMD_A(80), SUPCMD_A(81), SUPCMD_A(82), SUPCMD_A(83),
	SUPCMD_A(84), SUPCMD_A(85), SUPCMD_A(86), SUPCMD_A(87),
	SUPCMD_A(88), SUPCMD_A(89), SUPCMD_A(90), SUPCMD_A(91),
	SUPCMD_A(92), SUPCMD_A(93), SUPCMD_A(94), SUPCMD_A(95),
	SUPCMD_A(96), SUPCMD_A(97), SUPCMD_A(98), SUPCMD_A(99),
	SUPCMD_A(100), SUPCMD_A(101), SUPCMD_A(102), SUPCMD_A(103),
	SUPCMD_A(104), SUPCMD_A(105), SUPCMD_A(106), SUPCMD_A(107),
	SUPCMD_A(108), SUPCMD_A(109), SUPCMD_A(110), SUPCMD_A(111),
	SUPCMD_A(112), SUPCMD_A(113), SUPCMD_A(114), SUPCMD_A(115),
	SUPCMD_A(116), SUPCMD_A(117), SUPCMD_A(118), SUPCMD_A(119),
	SUPCMD_A(120), SUPCMD_A(121), SUPCMD_A(122), SUPCMD_A(123),
	SUPCMD_A(124), SUPCMD_A(125), SUPCMD_A(126), SUPCMD_A(127),
	SUPCMD_A(128), SUPCMD_A(129), SUPCMD_A(130), SUPCMD_A(131),
	SUPCMD_A(132), SUPCMD_A(133), SUPCMD_A(134), SUPCMD_A(135),
	SUPCMD_A(136), SUPCMD_A(137), SUPCMD_A(138), SUPCMD_A(139),
	SUPCMD_A(140), SUPCMD_A(141), SUPCMD_A(142), SUPCMD_A(143),
	SUPCMD_A(144), SUPCMD_A(145), SUPCMD_A(146), SUPCMD_A(147),
	SUPCMD_A(148), SUPCMD_A(149), SUPCMD_A(150), SUPCMD_A(151),
	SUPCMD_A(152), SUPCMD_A(153), SUPCMD_A(154), SUPCMD_A(155),
	SUPCMD_A(156), SUPCMD_A(157), SUPCMD_A(158), SUPCMD_A(159),
	SUPCMD_A(160), SUPCMD_A(161), SUPCMD_A(162), SUPCMD_A(163),
	SUPCMD_A(164), SUPCMD_A(165), SUPCMD_A(166), SUPCMD_A(167),
	SUPCMD_A(168), SUPCMD_A(169), SUPCMD_A(170), SUPCMD_A(171),
	SUPCMD_A(172), SUPCMD_A(173), SUPCMD_A(174), SUPCMD_A(175),
	SUPCMD_A(176), SUPCMD_A(177), SUPCMD_A(178), SUPCMD_A(179),
	SUPCMD_A(180), SUPCMD_A(181), SUPCMD_A(182), SUPCMD_A(183),
	SUPCMD_A(184), SUPCMD_A(185), SUPCMD_A(186), SUPCMD_A(187),
	SUPCMD_A(188), SUPCMD_A(189), SUPCMD_A(190), SUPCMD_A(191),
	SUPCMD_A(192), SUPCMD_A(193), SUPCMD_A(194), SUPCMD_A(195),
	SUPCMD_A(196), SUPCMD_A(197), SUPCMD_A(198), SUPCMD_A(199),
	SUPCMD_A(200), SUPCMD_A(201), SUPCMD_A(202), SUPCMD_A(203),
	SUPCMD_A(204), SUPCMD_A(205), SUPCMD_A(206), SUPCMD_A(207),
	SUPCMD_A(208), SUPCMD_A(209), SUPCMD_A(210), SUPCMD_A(211),
	SUPCMD_A(212), SUPCMD_A(213), SUPCMD_A(214), SUPCMD_A(215),
	SUPCMD_A(216), SUPCMD_A(217), SUPCMD_A(218), SUPCMD_A(219),
	SUPCMD_A(220), SUPCMD_A(221), SUPCMD_A(222), SUPCMD_A(223),
	SUPCMD_A(224), SUPCMD_A(225), SUPCMD_A(226), SUPCMD_A(227),
	SUPCMD_A(228), SUPCMD_A(229), SUPCMD_A(230), SUPCMD_A(231),
	SUPCMD_A(232), SUPCMD_A(233), SUPCMD_A(234), SUPCMD_A(235),
	SUPCMD_A(236), SUPCMD_A(237), SUPCMD_A(238), SUPCMD_A(239),
	SUPCMD_A(240), SUPCMD_A(241), SUPCMD_A(242), SUPCMD_A(243),
	SUPCMD_A(244), SUPCMD_A(245), SUPCMD_A(246), SUPCMD_A(247),
	SUPCMD_A(248), SUPCMD_A(249), SUPCMD_A(250), SUPCMD_A(251),
	SUPCMD_A(252), SUPCMD_A(253), SUPCMD_A(254), SUPCMD_A(255),
	SUPCMD_I(0), SUPCMD_I(1), SUPCMD_I(2), SUPCMD_I(3),
	SUPCMD_I(4), SUPCMD_I(5), SUPCMD_I(6), SUPCMD_I(7),
	SUPCMD_I(8), SUPCMD_I(9), SUPCMD_I(10), SUPCMD_I(11),
	SUPCMD_I(12), SUPCMD_I(13), SUPCMD_I(14), SUPCMD_I(15),
	SUPCMD_I(16), SUPCMD_I(17), SUPCMD_I(18), SUPCMD_I(19),
	SUPCMD_I(20), SUPCMD_I(21), SUPCMD_I(22), SUPCMD_I(23),
	SUPCMD_I(24), SUPCMD_I(25), SUPCMD_I(26), SUPCMD_I(27),
	SUPCMD_I(28), SUPCMD_I(29), SUPCMD_I(30), SUPCMD_I(31),
	SUPCMD_I(32), SUPCMD_I(33), SUPCMD_I(34), SUPCMD_I(35),
	SUPCMD_I(36), SUPCMD_I(37), SUPCMD_I(38), SUPCMD_I(39),
	SUPCMD_I(40), SUPCMD_I(41), SUPCMD_I(42), SUPCMD_I(43),
	SUPCMD_I(44), SUPCMD_I(45), SUPCMD_I(46), SUPCMD_I(47),
	SUPCMD_I(48), SUPCMD_I(49), SUPCMD_I(50), SUPCMD_I(51),
	SUPCMD_I(52), SUPCMD_I(53), SUPCMD_I(54), SUPCMD_I(55),
	SUPCMD_I(56), SUPCMD_I(57), SUPCMD_I(58), SUPCMD_I(59),
	SUPCMD_I(60), SUPCMD_I(61), SUPCMD_I(62), SUPCMD_I(63),
	SUPCMD_I(64), SUPCMD_I(65), SUPCMD_I(66), SUPCMD_I(67),
	SUPCMD_I(68), SUPCMD_I(69), SUPCMD_I(70), SUPCMD_I(71),
	SUPCMD_I(72), SUPCMD_I(73), SUPCMD_I(74), SUPCMD_I(75),
	SUPCMD_I(76), SUPCMD_I(77), SUPCMD_I(78), SUPCMD_I(79),
	SUPCMD_I(80), SUPCMD_I(81), SUPCMD_I(82), SUPCMD_I(83),
	SUPCMD_I(84), SUPCMD_I(85), SUPCMD_I(86), SUPCMD_I(87),
	SUPCMD_I(88), SUPCMD_I(89), SUPCMD_I(90), SUPCMD_I(91),
	SUPCMD_I(92), SUPCMD_I(93), SUPCMD_I(94), SUPCMD_I(95),
	SUPCMD_I(96), SUPCMD_I(97), SUPCMD_I(98), SUPCMD_I(99),
	SUPCMD_I(100), SUPCMD_I(101), SUPCMD_I(102), SUPCMD_I(103),
	SUPCMD_I(104), SUPCMD_I(105), SUPCMD_I(106), SUPCMD_I(107),
	SUPCMD_I(108), SUPCMD_I(109), SUPCMD_I(110), SUPCMD_I(111),
	SUPCMD_I(112), SUPCMD_I(113), SUPCMD_I(114), SUPCMD_I(115),
	SUPCMD_I(116), SUPCMD_I(117), SUPCMD_I(118), SUPCMD_I(119),
	SUPCMD_I(120), SUPCMD_I(121), SUPCMD_I(122), SUPCMD_I(123),
	SUPCMD_I(124), SUPCMD_I(125), SUPCMD_I(126), SUPCMD_I(127),
	SUPCMD_I(128), SUPCMD_I(129), SUPCMD_I(130), SUPCMD_I(131),
	SUPCMD_I(132), SUPCMD_I(133), SUPCMD_I(134), SUPCMD_I(135),
	SUPCMD_I(136), SUPCMD_I(137), SUPCMD_I(138), SUPCMD_I(139),
	SUPCMD_I(140), SUPCMD_I(141), SUPCMD_I(142), SUPCMD_I(143),
	SUPCMD_I(144), SUPCMD_I(145), SUPCMD_I(146), SUPCMD_I(147),
	SUPCMD_I(148), SUPCMD_I(149), SUPCMD_I(150), SUPCMD_I(151),
	SUPCMD_I(152), SUPCMD_I(153), SUPCMD_I(154), SUPCMD_I(155),
	SUPCMD_I(156), SUPCMD_I(157), SUPCMD_I(158), SUPCMD_I(159),
	SUPCMD_I(160), SUPCMD_I(161), SUPCMD_I(162), SUPCMD_I(163),
	SUPCMD_I(164), SUPCMD_I(165), SUPCMD_I(166), SUPCMD_I(167),
	SUPCMD_I(168), SUPCMD_I(169), SUPCMD_I(170), SUPCMD_I(171),
	SUPCMD_I(172), SUPCMD_I(173), SUPCMD_I(174), SUPCMD_I(175),
	SUPCMD_I(176), SUPCMD_I(177), SUPCMD_I(178), SUPCMD_I(179),
	SUPCMD_I(180), SUPCMD_I(181), SUPCMD_I(182), SUPCMD_I(183),
	SUPCMD_I(184), SUPCMD_I(185), SUPCMD_I(186), SUPCMD_I(187),
	SUPCMD_I(188), SUPCMD_I(189), SUPCMD_I(190), SUPCMD_I(191),
	SUPCMD_I(192), SUPCMD_I(193), SUPCMD_I(194), SUPCMD_I(195),
	SUPCMD_I(196), SUPCMD_I(197), SUPCMD_I(198), SUPCMD_I(199),
	SUPCMD_I(200), SUPCMD_I(201), SUPCMD_I(202), SUPCMD_I(203),
	SUPCMD_I(204), SUPCMD_I(205), SUPCMD_I(206), SUPCMD_I(207),
	SUPCMD_I(208), SUPCMD_I(209), SUPCMD_I(210), SUPCMD_I(211),
	SUPCMD_I(212), SUPCMD_I(213), SUPCMD_I(214), SUPCMD_I(215),
	SUPCMD_I(216), SUPCMD_I(217), SUPCMD_I(218), SUPCMD_I(219),
	SUPCMD_I(220), SUPCMD_I(221), SUPCMD_I(222), SUPCMD_I(223),
	SUPCMD_I(224), SUPCMD_I(225), SUPCMD_I(226), SUPCMD_I(227),
	SUPCMD_I(228), SUPCMD_I(229), SUPCMD_I(230), SUPCMD_I(231),
	SUPCMD_I(232), SUPCMD_I(233), SUPCMD_I(234), SUPCMD_I(235),
	SUPCMD_I(236), SUPCMD_I(237), SUPCMD_I(238), SUPCMD_I(239),
	SUPCMD_I(240), SUPCMD_I(241), SUPCMD_I(242), SUPCMD_I(243),
	SUPCMD_I(244), SUPCMD_I(245), SUPCMD_I(246), SUPCMD_I(247),
	SUPCMD_I(248), SUPCMD_I(249), SUPCMD_I(250), SUPCMD_I(251),
	SUPCMD_I(252), SUPCMD_I(253), SUPCMD_I(254), SUPCMD_I(255)
};

const nvmeadm_log_field_info_t supcmd_field_info = {
	.nlfi_log = "supcmd",
	.nlfi_fields = supcmd_fields,
	.nlfi_nfields = ARRAY_SIZE(supcmd_fields),
	.nlfi_min = sizeof (nvme_cmdeff_log_t),
};

static const nvmeadm_field_bit_t supmicmd_cs_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "csupp",
	.nfb_desc = "Command",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "lbcc",
	.nfb_desc = "Logical Block Content",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "ncc",
	.nfb_desc = "Namespace Capability",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "nic",
	.nfb_desc = "Namespace Inventory",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "ccc",
	.nfb_desc = "Controller Capability",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 20, .nfb_hibit = 31,
	.nfb_short = "csp",
	.nfb_desc = "Command Scope",
	.nfb_vers = &nvme_vers_2v0,
	NVMEADM_FB_BITS(supcmd_csp_bits)
} };

#define	SUPMICMD(f)	{ .nf_off = offsetof(nvme_supmicmd_log_t, \
	mcl_cmds[f]), \
	.nf_len = sizeof (((nvme_supmicmd_log_t *)NULL)->mcl_cmds[f]), \
	.nf_short = "mics" #f, .nf_desc = \
	"Management Interface Command Supported " #f, \
	NVMEADM_F_BITS(supmicmd_cs_bits) }

static const nvmeadm_field_t supmicmd_fields[] = {
	SUPMICMD(0), SUPMICMD(1), SUPMICMD(2), SUPMICMD(3),
	SUPMICMD(4), SUPMICMD(5), SUPMICMD(6), SUPMICMD(7),
	SUPMICMD(8), SUPMICMD(9), SUPMICMD(10), SUPMICMD(11),
	SUPMICMD(12), SUPMICMD(13), SUPMICMD(14), SUPMICMD(15),
	SUPMICMD(16), SUPMICMD(17), SUPMICMD(18), SUPMICMD(19),
	SUPMICMD(20), SUPMICMD(21), SUPMICMD(22), SUPMICMD(23),
	SUPMICMD(24), SUPMICMD(25), SUPMICMD(26), SUPMICMD(27),
	SUPMICMD(28), SUPMICMD(29), SUPMICMD(30), SUPMICMD(31),
	SUPMICMD(32), SUPMICMD(33), SUPMICMD(34), SUPMICMD(35),
	SUPMICMD(36), SUPMICMD(37), SUPMICMD(38), SUPMICMD(39),
	SUPMICMD(40), SUPMICMD(41), SUPMICMD(42), SUPMICMD(43),
	SUPMICMD(44), SUPMICMD(45), SUPMICMD(46), SUPMICMD(47),
	SUPMICMD(48), SUPMICMD(49), SUPMICMD(50), SUPMICMD(51),
	SUPMICMD(52), SUPMICMD(53), SUPMICMD(54), SUPMICMD(55),
	SUPMICMD(56), SUPMICMD(57), SUPMICMD(58), SUPMICMD(59),
	SUPMICMD(60), SUPMICMD(61), SUPMICMD(62), SUPMICMD(63),
	SUPMICMD(64), SUPMICMD(65), SUPMICMD(66), SUPMICMD(67),
	SUPMICMD(68), SUPMICMD(69), SUPMICMD(70), SUPMICMD(71),
	SUPMICMD(72), SUPMICMD(73), SUPMICMD(74), SUPMICMD(75),
	SUPMICMD(76), SUPMICMD(77), SUPMICMD(78), SUPMICMD(79),
	SUPMICMD(80), SUPMICMD(81), SUPMICMD(82), SUPMICMD(83),
	SUPMICMD(84), SUPMICMD(85), SUPMICMD(86), SUPMICMD(87),
	SUPMICMD(88), SUPMICMD(89), SUPMICMD(90), SUPMICMD(91),
	SUPMICMD(92), SUPMICMD(93), SUPMICMD(94), SUPMICMD(95),
	SUPMICMD(96), SUPMICMD(97), SUPMICMD(98), SUPMICMD(99),
	SUPMICMD(100), SUPMICMD(101), SUPMICMD(102), SUPMICMD(103),
	SUPMICMD(104), SUPMICMD(105), SUPMICMD(106), SUPMICMD(107),
	SUPMICMD(108), SUPMICMD(109), SUPMICMD(110), SUPMICMD(111),
	SUPMICMD(112), SUPMICMD(113), SUPMICMD(114), SUPMICMD(115),
	SUPMICMD(116), SUPMICMD(117), SUPMICMD(118), SUPMICMD(119),
	SUPMICMD(120), SUPMICMD(121), SUPMICMD(122), SUPMICMD(123),
	SUPMICMD(124), SUPMICMD(125), SUPMICMD(126), SUPMICMD(127),
	SUPMICMD(128), SUPMICMD(129), SUPMICMD(130), SUPMICMD(131),
	SUPMICMD(132), SUPMICMD(133), SUPMICMD(134), SUPMICMD(135),
	SUPMICMD(136), SUPMICMD(137), SUPMICMD(138), SUPMICMD(139),
	SUPMICMD(140), SUPMICMD(141), SUPMICMD(142), SUPMICMD(143),
	SUPMICMD(144), SUPMICMD(145), SUPMICMD(146), SUPMICMD(147),
	SUPMICMD(148), SUPMICMD(149), SUPMICMD(150), SUPMICMD(151),
	SUPMICMD(152), SUPMICMD(153), SUPMICMD(154), SUPMICMD(155),
	SUPMICMD(156), SUPMICMD(157), SUPMICMD(158), SUPMICMD(159),
	SUPMICMD(160), SUPMICMD(161), SUPMICMD(162), SUPMICMD(163),
	SUPMICMD(164), SUPMICMD(165), SUPMICMD(166), SUPMICMD(167),
	SUPMICMD(168), SUPMICMD(169), SUPMICMD(170), SUPMICMD(171),
	SUPMICMD(172), SUPMICMD(173), SUPMICMD(174), SUPMICMD(175),
	SUPMICMD(176), SUPMICMD(177), SUPMICMD(178), SUPMICMD(179),
	SUPMICMD(180), SUPMICMD(181), SUPMICMD(182), SUPMICMD(183),
	SUPMICMD(184), SUPMICMD(185), SUPMICMD(186), SUPMICMD(187),
	SUPMICMD(188), SUPMICMD(189), SUPMICMD(190), SUPMICMD(191),
	SUPMICMD(192), SUPMICMD(193), SUPMICMD(194), SUPMICMD(195),
	SUPMICMD(196), SUPMICMD(197), SUPMICMD(198), SUPMICMD(199),
	SUPMICMD(200), SUPMICMD(201), SUPMICMD(202), SUPMICMD(203),
	SUPMICMD(204), SUPMICMD(205), SUPMICMD(206), SUPMICMD(207),
	SUPMICMD(208), SUPMICMD(209), SUPMICMD(210), SUPMICMD(211),
	SUPMICMD(212), SUPMICMD(213), SUPMICMD(214), SUPMICMD(215),
	SUPMICMD(216), SUPMICMD(217), SUPMICMD(218), SUPMICMD(219),
	SUPMICMD(220), SUPMICMD(221), SUPMICMD(222), SUPMICMD(223),
	SUPMICMD(224), SUPMICMD(225), SUPMICMD(226), SUPMICMD(227),
	SUPMICMD(228), SUPMICMD(229), SUPMICMD(230), SUPMICMD(231),
	SUPMICMD(232), SUPMICMD(233), SUPMICMD(234), SUPMICMD(235),
	SUPMICMD(236), SUPMICMD(237), SUPMICMD(238), SUPMICMD(239),
	SUPMICMD(240), SUPMICMD(241), SUPMICMD(242), SUPMICMD(243),
	SUPMICMD(244), SUPMICMD(245), SUPMICMD(246), SUPMICMD(247),
	SUPMICMD(248), SUPMICMD(249), SUPMICMD(250), SUPMICMD(251),
	SUPMICMD(252), SUPMICMD(253), SUPMICMD(254), SUPMICMD(255),
};

const nvmeadm_log_field_info_t supmicmd_field_info = {
	.nlfi_log = "supmicmd",
	.nlfi_fields = supmicmd_fields,
	.nlfi_nfields = ARRAY_SIZE(supmicmd_fields),
	.nlfi_min = sizeof (nvme_supmicmd_log_t),
};

static const nvmeadm_field_bit_t supfeat_csp_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "nscpe",
	.nfb_desc = "Namespace Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "cscpe",
	.nfb_desc = "Controller Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "nsetcpe",
	.nfb_desc = "NVM Set Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "egscpe",
	.nfb_desc = "Endurance Group Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "dscpe",
	.nfb_desc = "Domain Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 5, .nfb_hibit = 5,
	.nfb_short = "nsscpe",
	.nfb_desc = "NVM Subsystem Scope",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
}, {
	.nfb_lowbit = 6, .nfb_hibit = 6,
	.nfb_short = "cdqscp",
	.nfb_desc = "Controller Data Queue",
	.nfb_vers = &nvme_vers_2v1,
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "no", "yes" }
} };

static const nvmeadm_field_bit_t supfeat_cs_bits[] = { {
	.nfb_lowbit = 0, .nfb_hibit = 0,
	.nfb_short = "fsupp",
	.nfb_desc = "Feature",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 1, .nfb_hibit = 1,
	.nfb_short = "lbcc",
	.nfb_desc = "Logical Block Content",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 2, .nfb_hibit = 2,
	.nfb_short = "ncc",
	.nfb_desc = "Namespace Capability",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 3, .nfb_hibit = 3,
	.nfb_short = "nic",
	.nfb_desc = "Namespace Inventory",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 4, .nfb_hibit = 4,
	.nfb_short = "ccc",
	.nfb_desc = "Controller Capability",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unchanged", "changed" }
}, {
	.nfb_lowbit = 19, .nfb_hibit = 19,
	.nfb_short = "uss",
	.nfb_vers = &nvme_vers_1v4,
	.nfb_desc = "UUID Selection",
	.nfb_type = NVMEADM_FT_STRMAP,
	.nfb_strs = { "unsupported", "supported" }
}, {
	.nfb_lowbit = 20, .nfb_hibit = 31,
	.nfb_short = "csp",
	.nfb_desc = "Command Scope",
	.nfb_vers = &nvme_vers_2v0,
	NVMEADM_FB_BITS(supfeat_csp_bits)
} };

#define	SUPFEAT(f)	{ .nf_off = offsetof(nvme_supfeat_log_t, \
	nsl_feats[f]), \
	.nf_len = sizeof (((nvme_supfeat_log_t *)NULL)->nsl_feats[f]), \
	.nf_short = "fis" #f, .nf_desc = "Feature Identifier Supported " #f, \
	NVMEADM_F_BITS(supfeat_cs_bits) }

static const nvmeadm_field_t supfeat_fields[] = {
	SUPFEAT(0), SUPFEAT(1), SUPFEAT(2), SUPFEAT(3),
	SUPFEAT(4), SUPFEAT(5), SUPFEAT(6), SUPFEAT(7),
	SUPFEAT(8), SUPFEAT(9), SUPFEAT(10), SUPFEAT(11),
	SUPFEAT(12), SUPFEAT(13), SUPFEAT(14), SUPFEAT(15),
	SUPFEAT(16), SUPFEAT(17), SUPFEAT(18), SUPFEAT(19),
	SUPFEAT(20), SUPFEAT(21), SUPFEAT(22), SUPFEAT(23),
	SUPFEAT(24), SUPFEAT(25), SUPFEAT(26), SUPFEAT(27),
	SUPFEAT(28), SUPFEAT(29), SUPFEAT(30), SUPFEAT(31),
	SUPFEAT(32), SUPFEAT(33), SUPFEAT(34), SUPFEAT(35),
	SUPFEAT(36), SUPFEAT(37), SUPFEAT(38), SUPFEAT(39),
	SUPFEAT(40), SUPFEAT(41), SUPFEAT(42), SUPFEAT(43),
	SUPFEAT(44), SUPFEAT(45), SUPFEAT(46), SUPFEAT(47),
	SUPFEAT(48), SUPFEAT(49), SUPFEAT(50), SUPFEAT(51),
	SUPFEAT(52), SUPFEAT(53), SUPFEAT(54), SUPFEAT(55),
	SUPFEAT(56), SUPFEAT(57), SUPFEAT(58), SUPFEAT(59),
	SUPFEAT(60), SUPFEAT(61), SUPFEAT(62), SUPFEAT(63),
	SUPFEAT(64), SUPFEAT(65), SUPFEAT(66), SUPFEAT(67),
	SUPFEAT(68), SUPFEAT(69), SUPFEAT(70), SUPFEAT(71),
	SUPFEAT(72), SUPFEAT(73), SUPFEAT(74), SUPFEAT(75),
	SUPFEAT(76), SUPFEAT(77), SUPFEAT(78), SUPFEAT(79),
	SUPFEAT(80), SUPFEAT(81), SUPFEAT(82), SUPFEAT(83),
	SUPFEAT(84), SUPFEAT(85), SUPFEAT(86), SUPFEAT(87),
	SUPFEAT(88), SUPFEAT(89), SUPFEAT(90), SUPFEAT(91),
	SUPFEAT(92), SUPFEAT(93), SUPFEAT(94), SUPFEAT(95),
	SUPFEAT(96), SUPFEAT(97), SUPFEAT(98), SUPFEAT(99),
	SUPFEAT(100), SUPFEAT(101), SUPFEAT(102), SUPFEAT(103),
	SUPFEAT(104), SUPFEAT(105), SUPFEAT(106), SUPFEAT(107),
	SUPFEAT(108), SUPFEAT(109), SUPFEAT(110), SUPFEAT(111),
	SUPFEAT(112), SUPFEAT(113), SUPFEAT(114), SUPFEAT(115),
	SUPFEAT(116), SUPFEAT(117), SUPFEAT(118), SUPFEAT(119),
	SUPFEAT(120), SUPFEAT(121), SUPFEAT(122), SUPFEAT(123),
	SUPFEAT(124), SUPFEAT(125), SUPFEAT(126), SUPFEAT(127),
	SUPFEAT(128), SUPFEAT(129), SUPFEAT(130), SUPFEAT(131),
	SUPFEAT(132), SUPFEAT(133), SUPFEAT(134), SUPFEAT(135),
	SUPFEAT(136), SUPFEAT(137), SUPFEAT(138), SUPFEAT(139),
	SUPFEAT(140), SUPFEAT(141), SUPFEAT(142), SUPFEAT(143),
	SUPFEAT(144), SUPFEAT(145), SUPFEAT(146), SUPFEAT(147),
	SUPFEAT(148), SUPFEAT(149), SUPFEAT(150), SUPFEAT(151),
	SUPFEAT(152), SUPFEAT(153), SUPFEAT(154), SUPFEAT(155),
	SUPFEAT(156), SUPFEAT(157), SUPFEAT(158), SUPFEAT(159),
	SUPFEAT(160), SUPFEAT(161), SUPFEAT(162), SUPFEAT(163),
	SUPFEAT(164), SUPFEAT(165), SUPFEAT(166), SUPFEAT(167),
	SUPFEAT(168), SUPFEAT(169), SUPFEAT(170), SUPFEAT(171),
	SUPFEAT(172), SUPFEAT(173), SUPFEAT(174), SUPFEAT(175),
	SUPFEAT(176), SUPFEAT(177), SUPFEAT(178), SUPFEAT(179),
	SUPFEAT(180), SUPFEAT(181), SUPFEAT(182), SUPFEAT(183),
	SUPFEAT(184), SUPFEAT(185), SUPFEAT(186), SUPFEAT(187),
	SUPFEAT(188), SUPFEAT(189), SUPFEAT(190), SUPFEAT(191),
	SUPFEAT(192), SUPFEAT(193), SUPFEAT(194), SUPFEAT(195),
	SUPFEAT(196), SUPFEAT(197), SUPFEAT(198), SUPFEAT(199),
	SUPFEAT(200), SUPFEAT(201), SUPFEAT(202), SUPFEAT(203),
	SUPFEAT(204), SUPFEAT(205), SUPFEAT(206), SUPFEAT(207),
	SUPFEAT(208), SUPFEAT(209), SUPFEAT(210), SUPFEAT(211),
	SUPFEAT(212), SUPFEAT(213), SUPFEAT(214), SUPFEAT(215),
	SUPFEAT(216), SUPFEAT(217), SUPFEAT(218), SUPFEAT(219),
	SUPFEAT(220), SUPFEAT(221), SUPFEAT(222), SUPFEAT(223),
	SUPFEAT(224), SUPFEAT(225), SUPFEAT(226), SUPFEAT(227),
	SUPFEAT(228), SUPFEAT(229), SUPFEAT(230), SUPFEAT(231),
	SUPFEAT(232), SUPFEAT(233), SUPFEAT(234), SUPFEAT(235),
	SUPFEAT(236), SUPFEAT(237), SUPFEAT(238), SUPFEAT(239),
	SUPFEAT(240), SUPFEAT(241), SUPFEAT(242), SUPFEAT(243),
	SUPFEAT(244), SUPFEAT(245), SUPFEAT(246), SUPFEAT(247),
	SUPFEAT(248), SUPFEAT(249), SUPFEAT(250), SUPFEAT(251),
	SUPFEAT(252), SUPFEAT(253), SUPFEAT(254), SUPFEAT(255),
};

const nvmeadm_log_field_info_t supfeat_field_info = {
	.nlfi_log = "supfeat",
	.nlfi_fields = supfeat_fields,
	.nlfi_nfields = ARRAY_SIZE(supfeat_fields),
	.nlfi_min = sizeof (nvme_supfeat_log_t),
};
