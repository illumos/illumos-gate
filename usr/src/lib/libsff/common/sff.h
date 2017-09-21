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
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _SFF_H
#define	_SFF_H

/*
 * Definitions internal to libsfp for various SFF versions. This generally
 * contains offsets for each byte and its purpose. The meaning of the values are
 * not generally found in this header.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This table is derived from SFF 8024 Section 4.1, Table 4-1.
 */
typedef enum sff_8024_id {
	SFF_8024_ID_UNKNOWN	= 0x00,
	SFF_8024_ID_GBIC	= 0x01,
	SFF_8024_ID_SOLDERED	= 0x02,
	SFF_8024_ID_SFP		= 0x03, /* SFP, SFP+, SFP28 */
	SFF_8024_ID_XBI		= 0x04,
	SFF_8024_ID_XENPAK	= 0x05,
	SFF_8024_ID_XFP		= 0x06,
	SFF_8024_ID_XFF		= 0x07,
	SFF_8024_ID_XFP_E	= 0x08,
	SFF_8024_ID_XPAK	= 0x09,
	SFF_8024_ID_X2		= 0x0A,
	SFF_8024_ID_DWDM_SFP	= 0x0B,
	SFF_8024_ID_QSFP	= 0x0C,
	SFF_8024_ID_QSFP_PLUS	= 0x0D,
	SFF_8024_ID_CXP		= 0x0E,
	SFF_8024_ID_SMMHD4X	= 0x0F,
	SFF_8024_ID_SMMHD8X	= 0x10,
	SFF_8024_ID_QSFP28	= 0x11,
	SFF_8024_ID_CXP2	= 0x12,
	SFF_8024_ID_CDFP	= 0x13,
	SFF_8024_ID_SMMHD4XF	= 0x14,
	SFF_8024_ID_SMMHD8XF	= 0x15,
	SFF_8024_ID_CDFP3	= 0x16,
	SFF_8024_ID_MICROQSFP	= 0x17,
	SFF_8024_NIDS		= 0x18,
	SFF_8024_VENDOR		= 0x80
} sff_8024_id_t;


/*
 * Byte offsets for SFF-8472. Note that most of this applies to INF-8074.
 * Generally speaking, SFF-8472 is a backwards compatible evolution of INF-8074.
 */
#define	SFF_8472_IDENTIFIER			0
#define	SFF_8472_EXT_IDENTIFER			1
#define	SFF_8472_CONNECTOR			2

/*
 * Note that several constants overlap here as the offset is used for multiple
 * purposes.
 */
#define	SFF_8472_COMPLIANCE_10GE		3
#define	SFF_8472_COMPLIANCE_IB			3
#define	SFF_8472_COMPLIANCE_ESCON		4
#define	SFF_8472_COMPLIANCE_SONET_LOW		4
#define	SFF_8472_COMPLIANCE_SONET_HIGH		5
#define	SFF_8472_COMPLIANCE_ETHERNET		6
#define	SFF_8472_COMPLIANCE_FCLEN		7
#define	SFF_8472_COMPLIANCE_FC_LOW		7
#define	SFF_8472_COMPLIANCE_FC_HIGH		8
#define	SFF_8472_COMPLIANCE_SFP			8
#define	SFF_8472_COMPLIANCE_FC_MEDIA		9
#define	SFF_8472_COMPLIANCE_FC_SPEED		10

#define	SFF_8472_ENCODING			11
#define	SFF_8472_BR_NOMINAL			12
#define	SFF_8472_RATE_IDENTIFIER		13
#define	SFF_8472_LENGTH_SMF_KM			14
#define	SFF_8472_LENGTH_SMF			15
#define	SFF_8472_LENGTH_50UM			16
#define	SFF_8472_LENGTH_62UM			17
#define	SFF_8472_LENGTH_COPPER			18
#define	SFF_8472_LENGTH_OM3			19

#define	SFF_8472_VENDOR				20
#define	SFF_8472_VENDOR_LEN			16
#define	SFF_8472_TRANSCEIVER			36
#define	SFF_8472_OUI				37
#define	SFF_8472_OUI_LEN			3
#define	SFF_8472_VENDOR_PN			40
#define	SFF_8472_VENDOR_PN_LEN			16
#define	SFF_8472_VENDOR_REV			56
#define	SFF_8472_VENDOR_REV_LEN			4

#define	SFF_8472_PASSIVE_SPEC			60
#define	SFF_8472_ACTIVE_SPEC			60
#define	SFF_8472_WAVELENGTH_HI			60
#define	SFF_8472_WAVELENGTH_LOW			61

#define	SFF_8472_CC_BASE			63

#define	SFF_8472_OPTIONS_HI			64
#define	SFF_8472_OPTIONS_LOW			65
#define	SFF_8472_BR_MAX				66
#define	SFF_8472_BR_MIN				67
#define	SFF_8472_VENDOR_SN			68
#define	SFF_8472_VENDOR_SN_LEN			16
#define	SFF_8472_DATE_CODE			84
#define	SFF_8472_DATE_CODE_LEN			8
#define	SFF_8472_DIAG_MONITORING		92
#define	SFF_8472_ENHANCED_OPTIONS		93
#define	SFF_8472_SFF_8472_COMPLIANCE		94

#define	SFF_8472_CC_EXT				95
#define	SFF_8472_VENDOR_SPECIFIC		96
#define	SFF_8472_RESERVED			128

/*
 * These values are factors by which we should multiple or divide various units.
 */
#define	SFF_8472_BR_NOMINAL_FACTOR		100
#define	SFF_8472_BR_MAX_FACTOR			250
#define	SFF_8472_BR_MIN_FACTOR			250
#define	SFF_8472_LENGTH_SMF_KM_FACTOR		1
#define	SFF_8472_LENGTH_SMF_FACTOR		100
#define	SFF_8472_LENGTH_50UM_FACTOR		10
#define	SFF_8472_LENGTH_62UM_FACTOR		10
#define	SFF_8472_LENGTH_COPPER_FACTOR		1
#define	SFF_8472_LENGTH_OM3_FACTOR		10
#define	SFF_8472_WAVELENGTH_FACTOR		1


/*
 * SFF 8636 related constants
 */
#define	SFF_8636_IDENTIFIER			0
#define	SFF_8636_EXT_IDENTIFIER			129
#define	SFF_8636_CONNECTOR			130

#define	SFF_8636_COMPLIANCE_10GBEP		131
#define	SFF_8636_COMPLIANCE_SONET		132
#define	SFF_8636_COMPLIANCE_SAS			133
#define	SFF_8636_COMPLIANCE_ETHERNET		134
#define	SFF_8636_COMPLIANCE_FCLEN		135
#define	SFF_8636_COMPLIANCE_FC_LOW		135
#define	SFF_8636_COMPLIANCE_FC_HIGH		136
#define	SFF_8636_COMPLIANCE_FC_MEDIA		137
#define	SFF_8636_COMPLIANCE_FC_SPEED		138

#define	SFF_8636_ENCODING			139
#define	SFF_8636_BR_NOMINAL			140
#define	SFF_8636_BR_EXT_RATE_SELECT		141
#define	SFF_8636_LENGTH_SMF			142
#define	SFF_8636_LENGTH_OM3			143
#define	SFF_8636_LENGTH_OM2			144
#define	SFF_8636_LENGTH_OM1			145
#define	SFF_8636_LENGTH_COPPER			146
#define	SFF_8636_DEVICE_TECH			147
#define	SFF_8636_VENDOR				148
#define	SFF_8636_VENDOR_LEN			16
#define	SFF_8636_EXTENDED_MODULE		164
#define	SFF_8636_OUI				165
#define	SFF_8636_OUI_LEN			3
#define	SFF_8636_VENDOR_PN			168
#define	SFF_8636_VENDOR_PN_LEN			16
#define	SFF_8636_VENDOR_REV			184
#define	SFF_8636_VENDOR_REV_LEN			2

#define	SFF_8636_ATTENUATE_2G			186
#define	SFF_8636_ATTENUATE_5G			187
#define	SFF_8636_ATTENUATE_7G			188
#define	SFF_8636_ATTENUATE_12G			189
#define	SFF_8636_WAVELENGTH_NOMINAL_HI		186
#define	SFF_8636_WAVELENGTH_NOMINAL_LOW		187
#define	SFF_8636_WAVELENGTH_TOLERANCE_HI	188
#define	SFF_8636_WAVELENGTH_TOLERANCE_LOW	189
#define	SFF_8636_MAX_CASE_TEMP			190
#define	SFF_8636_CC_BASE			191

#define	SFF_8636_LINK_CODES			192
#define	SFF_8636_OPTIONS_HI			193
#define	SFF_8636_OPTIONS_MID			194
#define	SFF_8636_OPTIONS_LOW			195
#define	SFF_8636_VENDOR_SN			196
#define	SFF_8636_VENDOR_SN_LEN			16
#define	SFF_8636_DATE_CODE			212
#define	SFF_8636_DATE_CODE_LEN			8
#define	SFF_8636_DIAG_MONITORING		220
#define	SFF_8636_ENHANCED_OPTIONS		221
#define	SFF_8636_BR_NOMINAL_EXT			222
#define	SFF_8636_CC_EXT				223
#define	SFF_866_VENDOR_SPECIFIC			224

/*
 * SFF 8636 multiplication factors
 */
#define	SFF_8636_BR_NOMINAL_FACTOR		100
#define	SFF_8636_BR_NOMINAL_EXT_FACTOR		250
#define	SFF_8636_LENGTH_SMF_FACTOR		1
#define	SFF_8636_LENGTH_OM3_FACTOR		2
#define	SFF_8636_LENGTH_OM2_FACTOR		1
#define	SFF_8636_LENGTH_OM1_FACTOR		1
#define	SFF_8636_LENGTH_COPPER_FACTOR		1

#ifdef __cplusplus
}
#endif

#endif /* _SFF_H */
