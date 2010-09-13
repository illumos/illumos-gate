/*
 *  sfe_mii.h: mii header for gem
 *
 * Copyright (c) 2002-2007 Masayuki Murayama.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * sfe_mii.h : MII registers
 */
#ifndef _SFE_MII_H_
#define	_SFE_MII_H_

#include <sys/miiregs.h>

#define	MII_AN_LPANXT		8
#define	MII_MS_CONTROL		9
#define	MII_MS_STATUS		10
#define	MII_XSTATUS		15

/* for 1000BaseT support */
#define	MII_1000TC		MII_MS_CONTROL
#define	MII_1000TS		MII_MS_STATUS
#define	MII_CONTROL_SPEED	0x2040

#define	MII_CONTROL_10MB	0x0000
#define	MII_CONTROL_1000MB	0x0040

#define	MII_CONTROL_BITS	\
	"\020"	\
	"\020RESET"	\
	"\017LOOPBACK"	\
	"\016100MB"	\
	"\015ANE"	\
	"\014PWRDN"	\
	"\013ISOLATE"	\
	"\012RSAN"	\
	"\011FDUPLEX"	\
	"\010COLTST"	\
	"\0071000M"
#define	MII_STATUS_XSTATUS		0x0100
#define	MII_STATUS_100_BASE_T2_FD	0x0400
#define	MII_STATUS_100_BASE_T2		0x0200

#define	MII_STATUS_ABILITY_TECH	\
	(MII_STATUS_100_BASE_T4	|	\
	MII_STATUS_100_BASEX_FD |	\
	MII_STATUS_100_BASEX |	\
	MII_STATUS_10 |	\
	MII_STATUS_10_FD)


#define	MII_STATUS_BITS	\
	"\020"	\
	"\020100_BASE_T4"	\
	"\017100_BASEX_FD"	\
	"\016100_BASEX"	\
	"\01510_BASE_FD"	\
	"\01410_BASE"	\
	"\013100_BASE_T2_FD"	\
	"\012100_BASE_T2"	\
	"\011XSTATUS"	\
	"\007MFPRMBLSUPR"	\
	"\006ANDONE"	\
	"\005REMFAULT"	\
	"\004CANAUTONEG"	\
	"\003LINKUP"	\
	"\002JABBERING"	\
	"\001EXTENDED"

#define	MII_ABILITY_TECH	\
	(MII_ABILITY_100BASE_T4	|	\
	MII_ABILITY_100BASE_TX_FD |	\
	MII_ABILITY_100BASE_TX |	\
	MII_ABILITY_10BASE_T |	\
	MII_ABILITY_10BASE_T_FD)

#define	MII_ABILITY_ALL	\
	(MII_AN_ADVERT_REMFAULT |	\
	MII_ABILITY_ASMPAUSE |	\
	MII_ABILITY_PAUSE |	\
	MII_ABILITY_TECH)


#define	MII_ABILITY_BITS	\
	"\020"	\
	"\016REMFAULT"	\
	"\014ASM_DIR"	\
	"\013PAUSE"	\
	"\012100BASE_T4"	\
	"\011100BASE_TX_FD"	\
	"\010100BASE_TX"	\
	"\00710BASE_T_FD"	\
	"\00610BASE_T"

#define	MII_AN_EXP_BITS	\
	"\020"	\
	"\005PARFAULT"	\
	"\004LPCANNXTP"	\
	"\003CANNXTPP"	\
	"\002PAGERCVD"	\
	"\001LPCANAN"

#define	MII_1000TC_TESTMODE	0xe000
#define	MII_1000TC_CFG_EN	0x1000
#define	MII_1000TC_CFG_VAL	0x0800
#define	MII_1000TC_PORTTYPE	0x0400
#define	MII_1000TC_ADV_FULL	0x0200
#define	MII_1000TC_ADV_HALF	0x0100

#define	MII_1000TC_BITS	\
	"\020"	\
	"\015CFG_EN"	\
	"\014CFG_VAL"	\
	"\013PORTTYPE"	\
	"\012FULL"	\
	"\011HALF"

#define	MII_1000TS_CFG_FAULT	0x8000
#define	MII_1000TS_CFG_MASTER	0x4000
#define	MII_1000TS_LOCALRXOK	0x2000
#define	MII_1000TS_REMOTERXOK	0x1000
#define	MII_1000TS_LP_FULL	0x0800
#define	MII_1000TS_LP_HALF	0x0400

#define	MII_1000TS_BITS	\
	"\020"	\
	"\020CFG_FAULT"	\
	"\017CFG_MASTER"	\
	"\014CFG_LOCALRXOK"	\
	"\013CFG_REMOTERXOK"	\
	"\012LP_FULL"	\
	"\011LP_HALF"

#define	MII_XSTATUS_1000BASEX_FD	0x8000
#define	MII_XSTATUS_1000BASEX		0x4000
#define	MII_XSTATUS_1000BASET_FD	0x2000
#define	MII_XSTATUS_1000BASET		0x1000

#define	MII_XSTATUS_BITS	\
	"\020"	\
	"\0201000BASEX_FD"	\
	"\0171000BASEX"		\
	"\0161000BASET_FD"	\
	"\0151000BASET"

#define	MII_READ_CMD(p, r)	\
	((6<<(18+5+5)) | ((p)<<(18+5)) | ((r)<<18))

#define	MII_WRITE_CMD(p, r, v)	\
	((5<<(18+5+5)) | ((p)<<(18+5)) | ((r)<<18) | (2 << 16) | (v))

#endif /* _SFE_MII_H_ */
