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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FM_SPARC64_VI_H
#define	_SYS_FM_SPARC64_VI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* ereport class subcategories for SPARC64-VI */
#define	FM_EREPORT_CPU_SPARC64_VI	"SPARC64-VI"
#define	FM_EREPORT_CPU_SPARC64_VII	"SPARC64-VII"
#define	FM_EREPORT_CPU_UNSUPPORTED	"unsupported"

/*
 * Ereport payload definitions.
 */
#define	FM_EREPORT_PAYLOAD_NAME_SFSR		"sfsr"
#define	FM_EREPORT_PAYLOAD_NAME_SFAR		"sfar"
#define	FM_EREPORT_PAYLOAD_NAME_UGESR		"ugesr"
#define	FM_EREPORT_PAYLOAD_NAME_PC		"pc"
#define	FM_EREPORT_PAYLOAD_NAME_TL		"tl"
#define	FM_EREPORT_PAYLOAD_NAME_TT		"tt"
#define	FM_EREPORT_PAYLOAD_NAME_PRIV		"privileged"
#define	FM_EREPORT_PAYLOAD_NAME_RESOURCE	"resource"
#define	FM_EREPORT_PAYLOAD_NAME_FLT_STATUS	"flt-status"

#define	FM_EREPORT_PAYLOAD_FLAG_SFSR		0x00000001
#define	FM_EREPORT_PAYLOAD_FLAG_SFAR		0x00000002
#define	FM_EREPORT_PAYLOAD_FLAG_UGESR		0x00000004
#define	FM_EREPORT_PAYLOAD_FLAG_PC		0x00000008
#define	FM_EREPORT_PAYLOAD_FLAG_TL		0x00000010
#define	FM_EREPORT_PAYLOAD_FLAG_TT		0x00000020
#define	FM_EREPORT_PAYLOAD_FLAG_PRIV		0x00000040
#define	FM_EREPORT_PAYLOAD_FLAG_RESOURCE	0x00000080
#define	FM_EREPORT_PAYLOAD_FLAG_FLT_STATUS	0x00000100

#define	FM_EREPORT_PAYLOAD_FLAGS_TRAP \
	    (FM_EREPORT_PAYLOAD_FLAG_TL | \
	    FM_EREPORT_PAYLOAD_FLAG_TT)

#define	FM_EREPORT_PAYLOAD_SYNC	(FM_EREPORT_PAYLOAD_FLAG_SFSR | \
					FM_EREPORT_PAYLOAD_FLAG_SFAR | \
					FM_EREPORT_PAYLOAD_FLAG_PC | \
					FM_EREPORT_PAYLOAD_FLAGS_TRAP | \
					FM_EREPORT_PAYLOAD_FLAG_PRIV | \
					FM_EREPORT_PAYLOAD_FLAG_FLT_STATUS | \
					FM_EREPORT_PAYLOAD_FLAG_RESOURCE)

#define	FM_EREPORT_PAYLOAD_URGENT	(FM_EREPORT_PAYLOAD_FLAG_UGESR | \
					FM_EREPORT_PAYLOAD_FLAG_PC | \
					FM_EREPORT_PAYLOAD_FLAGS_TRAP | \
					FM_EREPORT_PAYLOAD_FLAG_PRIV)

/*
 * FM_EREPORT_PAYLOAD_SYNC
 */

#define	FM_EREPORT_CPU_UE_MEM		"ue-mem"
#define	FM_EREPORT_CPU_UE_CHANNEL	"ue-channel"
#define	FM_EREPORT_CPU_UE_CPU		"ue-cpu"
#define	FM_EREPORT_CPU_UE_PATH		"ue-path"
#define	FM_EREPORT_CPU_BERR		"berr"
#define	FM_EREPORT_CPU_BTO		"bto"
#define	FM_EREPORT_CPU_MTLB		"mtlb"
#define	FM_EREPORT_CPU_TLBP		"tlbp"
#define	FM_EREPORT_CPU_INV_SFSR 	"inv-sfsr"

/*
 * FM_EREPORT_PAYLOAD_URGENT
 */

#define	FM_EREPORT_CPU_CRE	"cre"
#define	FM_EREPORT_CPU_TSBCTX	"tsb-ctx"
#define	FM_EREPORT_CPU_TSBP	"tsbp"
#define	FM_EREPORT_CPU_PSTATE	"pstate"
#define	FM_EREPORT_CPU_TSTATE	"tstate"
#define	FM_EREPORT_CPU_IUG_F	"iug-f"
#define	FM_EREPORT_CPU_IUG_R	"iug-r"
#define	FM_EREPORT_CPU_SDC	"sdc"
#define	FM_EREPORT_CPU_WDT	"wdt"
#define	FM_EREPORT_CPU_DTLB	"dtlb"
#define	FM_EREPORT_CPU_ITLB	"itlb"
#define	FM_EREPORT_CPU_CORE 	"core-err"
#define	FM_EREPORT_CPU_DAE 	"dae"
#define	FM_EREPORT_CPU_IAE 	"iae"
#define	FM_EREPORT_CPU_UGE 	"uge"
#define	FM_EREPORT_CPU_INV_URG	"inv-uge"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FM_SPARC64_VI_H */
