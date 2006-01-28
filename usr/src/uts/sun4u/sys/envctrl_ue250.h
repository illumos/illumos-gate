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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ENVCTRL_UE250_H
#define	_SYS_ENVCTRL_UE250_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * envctrl_ue250.h
 *
 * This header file contains environmental control definitions specific
 * to the UltraEnterprise-250 platform.
 */

#define	ENVCTRL_UE250_OVERTEMP_TIMEOUT_USEC	60 * MICROSEC
#define	ENVCTRL_UE250_BLINK_TIMEOUT_USEC	500 * (MICROSEC / MILLISEC)

/* Keyswitch Definitions */
#define	ENVCTRL_UE250_FSP_KEYMASK	0xC0
#define	ENVCTRL_UE250_FSP_POMASK	0x20
#define	ENVCTRL_UE250_FSP_KEYLOCKED	0x00
#define	ENVCTRL_UE250_FSP_KEYOFF	0xC0
#define	ENVCTRL_UE250_FSP_KEYDIAG	0x80
#define	ENVCTRL_UE250_FSP_KEYON		0x40

/* Front Status Panel Definitions */
#define	ENVCTRL_UE250_FSP_DISK_ERR	0x01
#define	ENVCTRL_UE250_FSP_PS_ERR	0x02
#define	ENVCTRL_UE250_FSP_TEMP_ERR	0x04
#define	ENVCTRL_UE250_FSP_GEN_ERR	0x08
#define	ENVCTRL_UE250_FSP_ACTIVE	0x10
#define	ENVCTRL_UE250_FSP_POWER	0x20
#define	ENVCTRL_UE250_FSP_USRMASK		\
	(ENVCTRL_UE250_FSP_DISK_ERR | ENVCTRL_UE250_FSP_GEN_ERR)

#define	ENVCTRL_UE250_FSP_OFF		0x4F

#define	ENVCTRL_UE250_MAX_DISKS		6
#define	ENVCTRL_UE250_MAXPS 		0x02	/* 0 based array */

#define	ENVCTRL_UE250_PDB_TEMP_DEV	0x94
#define	ENVCTRL_UE250_CPU_TEMP_DEV	0x9E
#define	ENVCTRL_UE250_CPU0_PORT		0
#define	ENVCTRL_UE250_CPU1_PORT		1
#define	ENVCTRL_UE250_MB0_PORT		2
#define	ENVCTRL_UE250_MB1_PORT		3
#define	ENVCTRL_UE250_PDB_TEMP_PORT	0
#define	ENVCTRL_UE250_SCSI_TEMP_PORT	3

#define	ENVCTRL_UE250_CPU0_SENSOR	0
#define	ENVCTRL_UE250_CPU1_SENSOR	1
#define	ENVCTRL_UE250_MB0_SENSOR	2
#define	ENVCTRL_UE250_MB1_SENSOR	3
#define	ENVCTRL_UE250_PDB_SENSOR	4
#define	ENVCTRL_UE250_SCSI_SENSOR	5

#define	ENVCTRL_UE250_MAX_CPU_TEMP	80

#define	ENVCTRL_UE250_PCF8591_BASE_ADDR		0x90
#define	ENVCTRL_UE250_PCF8574A_BASE_ADDR	0x70
#define	ENVCTRL_UE250_PCF8574_BASE_ADDR		0x40

#define	ENVCTRL_UE250_DFLOP_INIT0		0x77
#define	ENVCTRL_UE250_DFLOP_INIT1		0x7F
#define	ENVCTRL_UE250_DEVINTR_INIT0		0xF7
#define	ENVCTRL_UE250_DEVINTR_INIT1		0xFF
#define	ENVCTRL_UE250_INTR_LATCH_CLR		0xFE

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ENVCTRL_UE250_H */
