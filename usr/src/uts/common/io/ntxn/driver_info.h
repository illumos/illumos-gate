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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _driver_info_h_
#define	_driver_info_h_

static const unm_brdinfo_t unm_boards[] = {
	{UNM_BRDTYPE_P2_SB31_10G_CX4,	1, NX_P2_MN_TYPE_ROMIMAGE,
			"XGb CX4"},
	{UNM_BRDTYPE_P2_SB31_10G_HMEZ,	2, NX_P2_MN_TYPE_ROMIMAGE,
			"XGb HMEZ"},
	{UNM_BRDTYPE_P2_SB31_10G_IMEZ,	2, NX_P2_MN_TYPE_ROMIMAGE,
			"XGb IMEZ"},
	{UNM_BRDTYPE_P2_SB31_10G,		1, NX_P2_MN_TYPE_ROMIMAGE,
			"XGb XFP"},
	{UNM_BRDTYPE_P2_SB35_4G,		4, NX_P2_MN_TYPE_ROMIMAGE,
		    "Quad Gb"},
	{UNM_BRDTYPE_P2_SB31_2G,		2, NX_P2_MN_TYPE_ROMIMAGE,
			"Dual Gb"},
	{UNM_BRDTYPE_P3_REF_QG,			4, NX_P3_MN_TYPE_ROMIMAGE,
			"Reference card - Quad Gig "},
	{UNM_BRDTYPE_P3_HMEZ,			2, NX_P3_CT_TYPE_ROMIMAGE,
			"Dual XGb HMEZ"},
	{UNM_BRDTYPE_P3_10G_CX4_LP,    2, NX_P3_CT_TYPE_ROMIMAGE,
			"Dual XGb CX4 LP"},
	{UNM_BRDTYPE_P3_4_GB,			4, NX_P3_CT_TYPE_ROMIMAGE,
			"Quad Gig LP"},
	{UNM_BRDTYPE_P3_IMEZ,			2, NX_P3_CT_TYPE_ROMIMAGE,
			"Dual XGb IMEZ"},
	{UNM_BRDTYPE_P3_10G_SFP_PLUS,	2, NX_P3_CT_TYPE_ROMIMAGE,
			"Dual XGb SFP+ LP"},
	{UNM_BRDTYPE_P3_10000_BASE_T,	1, NX_P3_CT_TYPE_ROMIMAGE,
			"XGB 10G BaseT LP"},
	{UNM_BRDTYPE_P3_XG_LOM,			2, NX_P3_CT_TYPE_ROMIMAGE,
			"Dual XGb LOM"},
	{UNM_BRDTYPE_P3_4_GB_MM,		4, NX_P3_CT_TYPE_ROMIMAGE,
			"NX3031 with Gigabit Ethernet"},
	{UNM_BRDTYPE_P3_10G_CX4,		2, NX_P3_CT_TYPE_ROMIMAGE,
			"Reference card - Dual CX4 Option"},
	{UNM_BRDTYPE_P3_10G_XFP,		1, NX_P3_CT_TYPE_ROMIMAGE,
			"Reference card - Single XFP Option"},
	{UNM_BRDTYPE_P3_10G_TRP,		2, NX_P3_CT_TYPE_ROMIMAGE,
			"NX3031 with 1/10 Gigabit Ethernet"},
};

#endif /* !_driver_info_h_ */
