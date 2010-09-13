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

#ifndef	_SYS_FIBRE_CHANNEL_IMPL_FCAL_H
#define	_SYS_FIBRE_CHANNEL_IMPL_FCAL_H


#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Loop Initilization Identifier values
 */
#define	LID_LISM	0x1101
#define	LID_LIFA	0x1102
#define	LID_LIPA	0x1103
#define	LID_LIHA	0x1104
#define	LID_LISA	0x1105
#define	LID_LIRP	0x1106
#define	LID_LILP	0x1107

/*
 * lilp_magic definitions
 */
#define	MAGIC_LISM	0x01
#define	MAGIC_LIFA	0x02
#define	MAGIC_LIPA	0x03
#define	MAGIC_LIHA	0x04
#define	MAGIC_LISA	0x05
#define	MAGIC_LIRP	0x06
#define	MAGIC_LILP	0x07

/*
 * PLDA timers (in seconds)
 */
#define	PLDA_R_A_TOV	2
#define	PLDA_RR_TOV	2

/*
 * Note that my_alpa field is of 16 bit size. The lowest significant
 * byte contains the real ALPA.  The highest significant bits are
 * used to indicate if the LBIT was set during Loop Initialization.
 *
 * If the NL_Ports on the loop participate in the LIRP and LILP dance
 * as part of Loop Initialization then the presence of an F_Port can
 * be detected by checking for the presence of AL_PA '0x00' in the AL_PA
 * list (That does not however guarantee if there is a violating NL_Port
 * trying to grab AL_PA value of '0x00').
 *
 * Some FCAs may be capable of notifying if the L_BIT was set in the
 * AL_PA bit map. The host should then perform an IMPLICIT LOGO and
 * execute a PLOGI before sending any other command.
 */
#define	LILP_LBIT_SET		0x100	/* Login Required */

typedef struct fc_lilpmap {
	uint16_t	lilp_magic;
	uint16_t	lilp_myalpa;
	uchar_t		lilp_length;
	uchar_t		lilp_alpalist[127];
} fc_lilpmap_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", fc_lilpmap))
#endif	/* __lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FIBRE_CHANNEL_IMPL_FCAL_H */
