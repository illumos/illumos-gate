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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Misc ATA definitions
 */
#ifndef	_ATA_H
#define	_ATA_H
#ifdef	__cplusplus
extern "C" {
#endif

#include "ata8-acs.h"
#include "atapi7v3.h"

/*
 * IDENTIFY Data
 */
typedef struct {
	uint16_t	word0;
	uint16_t	word1;
	uint16_t	word2;
	uint16_t	word3;
	uint16_t	word4;
	uint16_t	word5;
	uint16_t	word6;
	uint16_t	word7;
	uint16_t	word8;
	uint16_t	word9;
	uint16_t	serial_number[10];
	uint16_t	word20;
	uint16_t	word21;
	uint16_t	word22;
	uint16_t	firmware_revision[4];
	uint16_t	model_number[20];
	uint16_t	word47;
	uint16_t	word48;
	uint16_t	word49;
	uint16_t	word50;
	uint16_t	word51;
	uint16_t	word52;
	uint16_t	word53;
	uint16_t	word54;
	uint16_t	word55;
	uint16_t	word56;
	uint16_t	word57;
	uint16_t	word58;
	uint16_t	word59;
	uint16_t	word60;
	uint16_t	word61;
	uint16_t	word62;
	uint16_t	word63;
	uint16_t	word64;
	uint16_t	word65;
	uint16_t	word66;
	uint16_t	word67;
	uint16_t	word68;
	uint16_t	word69;
	uint16_t	word70;
	uint16_t	word71;
	uint16_t	word72;
	uint16_t	word73;
	uint16_t	word74;
	uint16_t	word75;
	uint16_t	word76;
	uint16_t	word77;
	uint16_t	word78;
	uint16_t	word79;
	uint16_t	word80;
	uint16_t	word81;
	uint16_t	word82;
	uint16_t	word83;
	uint16_t	word84;
	uint16_t	word85;
	uint16_t	word86;
	uint16_t	word87;
	uint16_t	word88;
	uint16_t	word89;
	uint16_t	word90;
	uint16_t	word91;
	uint16_t	word92;
	uint16_t	word93;
	uint16_t	word94;
	uint16_t	word95;
	uint16_t	word96;
	uint16_t	word97;
	uint16_t	word98;
	uint16_t	word99;
	uint16_t	word100;
	uint16_t	word101;
	uint16_t	word102;
	uint16_t	word103;
	uint16_t	word104;
	uint16_t	word105;
	uint16_t	word106;
	uint16_t	word107;
	uint16_t	word108;
	uint16_t	word109;
	uint16_t	word110;
	uint16_t	word111;
	uint16_t	word112;
	uint16_t	word113;
	uint16_t	word114;
	uint16_t	word115;
	uint16_t	word116;
	uint16_t	word117;
	uint16_t	word118;
	uint16_t	word119;
	uint16_t	word120;
	uint16_t	word121;
	uint16_t	word122;
	uint16_t	word123;
	uint16_t	word124;
	uint16_t	word125;
	uint16_t	word126;
	uint16_t	word127;
	uint16_t	word128;
	uint16_t	word129;
	uint16_t	word130;
	uint16_t	word131;
	uint16_t	word132;
	uint16_t	word133;
	uint16_t	word134;
	uint16_t	word135;
	uint16_t	word136;
	uint16_t	word137;
	uint16_t	word138;
	uint16_t	word139;
	uint16_t	word140;
	uint16_t	word141;
	uint16_t	word142;
	uint16_t	word143;
	uint16_t	word144;
	uint16_t	word145;
	uint16_t	word146;
	uint16_t	word147;
	uint16_t	word148;
	uint16_t	word149;
	uint16_t	word150;
	uint16_t	word151;
	uint16_t	word152;
	uint16_t	word153;
	uint16_t	word154;
	uint16_t	word155;
	uint16_t	word156;
	uint16_t	word157;
	uint16_t	word158;
	uint16_t	word159;
	uint16_t	word160;
	uint16_t	word161;
	uint16_t	word162;
	uint16_t	word163;
	uint16_t	word164;
	uint16_t	word165;
	uint16_t	word166;
	uint16_t	word167;
	uint16_t	word168;
	uint16_t	word169;
	uint16_t	word170;
	uint16_t	word171;
	uint16_t	word172;
	uint16_t	word173;
	uint16_t	word174;
	uint16_t	word175;
	uint16_t	word176;
	uint16_t	word177;
	uint16_t	word178;
	uint16_t	word179;
	uint16_t	word180;
	uint16_t	word181;
	uint16_t	word182;
	uint16_t	word183;
	uint16_t	word184;
	uint16_t	word185;
	uint16_t	word186;
	uint16_t	word187;
	uint16_t	word188;
	uint16_t	word189;
	uint16_t	word190;
	uint16_t	word191;
	uint16_t	word192;
	uint16_t	word193;
	uint16_t	word194;
	uint16_t	word195;
	uint16_t	word196;
	uint16_t	word197;
	uint16_t	word198;
	uint16_t	word199;
	uint16_t	word200;
	uint16_t	word201;
	uint16_t	word202;
	uint16_t	word203;
	uint16_t	word204;
	uint16_t	word205;
	uint16_t	word206;
	uint16_t	word207;
	uint16_t	word208;
	uint16_t	word209;
	uint16_t	word210;
	uint16_t	word211;
	uint16_t	word212;
	uint16_t	word213;
	uint16_t	word214;
	uint16_t	word215;
	uint16_t	word216;
	uint16_t	word217;
	uint16_t	word218;
	uint16_t	word219;
	uint16_t	word220;
	uint16_t	word221;
	uint16_t	word222;
	uint16_t	word223;
	uint16_t	word224;
	uint16_t	word225;
	uint16_t	word226;
	uint16_t	word227;
	uint16_t	word228;
	uint16_t	word229;
	uint16_t	word230;
	uint16_t	word231;
	uint16_t	word232;
	uint16_t	word233;
	uint16_t	word234;
	uint16_t	word235;
	uint16_t	word236;
	uint16_t	word237;
	uint16_t	word238;
	uint16_t	word239;
	uint16_t	word240;
	uint16_t	word241;
	uint16_t	word242;
	uint16_t	word243;
	uint16_t	word244;
	uint16_t	word245;
	uint16_t	word246;
	uint16_t	word247;
	uint16_t	word248;
	uint16_t	word249;
	uint16_t	word250;
	uint16_t	word251;
	uint16_t	word252;
	uint16_t	word253;
	uint16_t	word254;
	uint16_t	word255;
} ata_identify_t;

#define	LBA_CAPACITY(ati)						\
	((LE_16(ati->word83) & (1 << 10)) == 0)?			\
	(LE_16(ati->word60) | ((LE_16(ati->word61)) << 16)) :		\
	((LE_16(ati->word100)) | ((LE_16(ati->word101)) << 16) |	\
	(((uint64_t)LE_16(ati->word102)) << 32) |			\
	(((uint64_t)LE_16(ati->word103)) << 48))


#ifdef	__cplusplus
}
#endif
#endif	/* _ATA_H */
