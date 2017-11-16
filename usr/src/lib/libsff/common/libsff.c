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

/*
 * Parse raw SFF data into an nvlist that can be processed by users, providing
 * them with what can be printable strings. At the moment, we handle the
 * majority of parsing page 0xa0 based on SFF 8472 (thus covering INF-8074 and
 * friends) and SFF 8636 (thus covering SFF-8436 and friends). Interfaces that
 * parse data into logical structures may be useful to add when considering
 * monitoring data in page 0xa2.
 *
 * When parsing, we try to make sure that the user has supplied, or at least
 * thinks they have supplied, a buffer of sufficient length. The general design
 * is that we require the buffer to be large enough to cover all of the offsets
 * that we care about. If the buffer isn't this large, then we leave it be.
 *
 * This library is private and subject to change at any time.
 */

#include <assert.h>
#include <strings.h>
#include <libsff.h>
#include <errno.h>
#include <ctype.h>

#include "sff.h"

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

/*
 * Maximum size of a string buffer while parsing.
 */
#define	SFP_STRBUF	128

/*
 * Minimum length of the buffer we require to parse the SFP data.
 */
#define	SFP_MIN_LEN_8472	96
#define	SFP_MIN_LEN_8636	224

/*
 * This table is derived from SFF 8024 Section 4.1, Table 4-1.
 */
static const char *sff_8024_id_strs[SFF_8024_NIDS] = {
	"Unknown or Unspecified",
	"GBIC",
	"Module/connector soldered to motherboard",
	"SFP/SFP+/SFP28",
	"300 pin XBI",
	"XENPAK",
	"XFP",
	"XFF",
	"XFP-E",
	"XPAK",
	"X2",
	"DWDM-SFP/SFP+ (not using SFF-8472)",
	"QSFP",
	"QSFP+ or later",
	"CXP or later",
	"Shielded Mini Multilane HD 4X",
	"Shielded Mini Multilane HD 8X",
	"QSFP28 or later",
	"CXP2 (aka CXP28) or later",
	"CDFP (Style 1/Style2)",
	"Shielded Mini Multilane HD 4X Fanout Cable",
	"Shielded Mini Multilane HD 8X Fanout Cable",
	"CDFP (Style 3)",
	"microQSFP"
};

/*
 * The set of values used for the encoding depends on whether we're a basic SFP
 * device or not. The values are inconsistent between SFP and QSFP based
 * devices.
 *
 * This table is derived from SFF 8024 r3.9 Table 4-2.
 */
#define	SFF_8024_NENCS	9
static const char *sff_8024_enc_sfp[] = {
	"Unspecified",
	"8B/10B",
	"4B/5B",
	"NRZ",
	"Manchester",
	"SONET Scrambled",
	"64B/66B",
	"256B/257B",
	"PAM4"
};

static const char *sff_8024_enc_qsfp[] = {
	"Unspecified",
	"8B/10B",
	"4B/5B",
	"NRZ",
	"SONET Scrambled",
	"64B/66B",
	"Manchester",
	"256B/257B",
	"PAM4"
};

/*
 * This table is derived from SFF 8024 r3.9 Section 4.4.
 */
#define	SFF_8024_EXT_SPEC_NENTRIES	27
static const char *sff_8024_ext_spec[] = {
	"Unspecified",
	"100G AOC or 25GAUI C2M AOC",
	"100GBASE-SR4 or 25GBASE-SR",
	"100GBASE-LR4 or 25GBASE-LR",
	"100GBASE-ER4 or 25GBASE-ER",
	"100GBASE-SR10",
	"100G CWDM4",
	"100G PSM4 Parallel SMF",
	"100G ACC or 25GAUI C2M ACC",
	"Obsolete",
	"Reserved",
	"100GBASE-CR4 or 25GBASE-CR CA-L",
	"25GBASE-CR CA-S",
	"25GBASE-CR CA-N",
	"Reserved",
	"Reserved",
	"40GBASE-ER4",
	"4 x 10GBASE-SR",
	"40G PSM4 Parallel SMF",
	"G959.1 profile P1I1-2D1",
	"G959.1 profile P1S1-2D2",
	"G959.1 profile P1L1-2D2",
	"10GBASE-T with SFI electrical interface",
	"100G CLR4",
	"100G AOC or 25GAUI C2M AOC",
	"100G ACC or 25GAUI C2M ACC",
	"100GE-DWDM2"
};

typedef struct sff_pair {
	uint_t sp_val;
	const char *sp_name;
} sff_pair_t;

/*
 * This table is derived from SFF 8024 r3.9 Section 4.3.
 */
static sff_pair_t sff_8024_connectors[] = {
	{ 0x00, "Unknown" },
	{ 0x01, "SC (Subscriber Connector)" },
	{ 0x02, "Fibre Channel Style 1 copper connector" },
	{ 0x03, "Fibre Channel Style 2 copper connector" },
	{ 0x04, "BNC/TNC (Bayonet/Threaded Neill-Concelman)" },
	{ 0x05, "Fibre Channel coax headers" },
	{ 0x06, "Fiber Jack" },
	{ 0x07, "LC (Lucent Connector)" },
	{ 0x08, "MT-RJ (Mechanical Transfer - Registered Jack)" },
	{ 0x09, "MU (Multiple Optical)" },
	{ 0x0A, "SG" },
	{ 0x0B, "Optical Pigtail" },
	{ 0x0C, "MPO 1x12 (Multifiber Parallel Optic)" },
	{ 0x0D, "MPO 2x16" },
	{ 0x20, "HSSDC II (High Speed Serial Data Connector)" },
	{ 0x21, "Copper pigtail" },
	{ 0x22, "RJ45 (Registered Jack)" },
	{ 0x23, "No separable connector" },
	{ 0x24, "MXC 2x16" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.
 */
#define	SFF_8472_COMP_10GETH_MASK	0xf0
static sff_pair_t sff_8472_comp_10geth[] = {
	{ 0x80, "10G Base-ER" },
	{ 0x40, "10G Base-LRM" },
	{ 0x20, "10G Base-LR" },
	{ 0x10, "10G Base-SR" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.
 */
#define	SFF_8472_COMP_IB_MASK	0x0f
static sff_pair_t sff_8472_comp_ib[] = {
	{ 0x08, "1X SX" },
	{ 0x04,	"1X LX" },
	{ 0x02, "1X Copper Active" },
	{ 0x01, "1X Copper Passive" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.
 */
#define	SFF_8472_COMP_ESCON_MASK	0xc0
static sff_pair_t sff_8472_comp_escon[] = {
	{ 0x80, "ESCON MMF, 1310nm LED" },
	{ 0x40, "ESCON SMF, 1310nm Laser" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.  These values come from both
 * bytes 4 and 5. We treat this as a uint16_t with the low byte as byte 4 and
 * the high byte as byte 5.
 */
#define	SFF_8472_COMP_SOCON_MASK	0x773f
static sff_pair_t sff_8472_comp_sonet[] = {
	{ 0x20, "OC-192, short reach" },
	{ 0x10, "SONET reach specifier bit 1" },
	{ 0x08, "ONET reach specifier bit 2" },
	{ 0x04, "OC-48, long reach" },
	{ 0x02, "OC-48, intermediate reach" },
	{ 0x01, "OC-48, short reach" },
	/* 0x8000 is unallocated */
	{ 0x4000, "OC-12, single mode, long reach" },
	{ 0x2000, "OC-12, single mode, inter. reach" },
	{ 0x1000, "OC-12, short reach" },
	/* 0x800 is unallocted */
	{ 0x0400, "OC-3, single mode, long reach" },
	{ 0x0200, "OC-3, single mode, inter. reach" },
	{ 0x0100, "OC-3, short reach" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.
 */
#define	SFF_8472_COMP_ETH_MASK	0xff
static sff_pair_t sff_8472_comp_eth[] = {
	{ 0x80, "BASE-PX" },
	{ 0x40, "BASE-BX10" },
	{ 0x20, "100BASE-FX" },
	{ 0x10, "100BASE-LX/LX10" },
	{ 0x08, "1000BASE-T" },
	{ 0x04, "1000BASE-CX" },
	{ 0x02, "1000BASE-LX" },
	{ 0x01, "1000BASE-SX" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.
 */
#define	SFF_8472_COMP_FCLEN_MASK	0xf8
static sff_pair_t sff_8472_comp_fclen[] = {
	{ 0x80, "very long distance (V)" },
	{ 0x40, "short distance (S)" },
	{ 0x20, "intermeddiate distance (I)" },
	{ 0x10, "long distance (L)" },
	{ 0x08, "medium distance (M)" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.  These values come from both
 * bytes 7 and 8. We treat this as a uint16_t with the low byte as byte 7 and
 * the high byte as byte 8.
 */
#define	SFF_8472_COMP_TECH_MASK	0xf007
static sff_pair_t sff_8472_comp_tech[] = {
	{ 0x4, "Shortwave laser, linear Rx (SA)" },
	{ 0x2, "Longwave laser (LC)" },
	{ 0x1, "Electrical inter-enclosure (EL)" },
	{ 0x8000, "Electrical intra-enclosure (EL)" },
	{ 0x4000, "Shortwave laser w/o OFC (SN)" },
	{ 0x2000, "Shortwave laser with OFC (SL)" },
	{ 0x1000, "Longwave laser (LL)" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.
 */
#define	SFF_8472_COMP_CABLE_MASK	0x0c
#define	SFF_8472_COMP_CABLE_ACTIVE	0x08
#define	SFF_8472_COMP_CABLE_PASSIVE	0x04
static sff_pair_t sff_8472_comp_cable[] = {
	{ 0x08, "Active Cable" },
	{ 0x04, "Passive Cable" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.
 */
#define	SFF_8472_COMP_MEDIA_MASK	0xfd
static sff_pair_t sff_8472_comp_media[] = {
	{ 0x80, "Twin Axial Pair (TW)" },
	{ 0x40, "Twisted Pair (TP)" },
	{ 0x20, "Miniature Coax (MI)" },
	{ 0x10, "Video Coax (TV)" },
	{ 0x08, "Multimode, 62.5um (M6)" },
	{ 0x04, "Multimode, 50um (M5, M5E)" },
	/* 0x02 is Unallocated */
	{ 0x01, "Single Mode (SM)" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 5-3.
 */
#define	SFF_8472_COMP_SPEED_MASK	0xfd
static sff_pair_t sff_8472_comp_speed[] = {
	{ 0x80, "1200 MBytes/sec" },
	{ 0x40, "800 MBytes/sec" },
	{ 0x20, "1600 MBytes/sec" },
	{ 0x10, "400 MBytes/sec" },
	{ 0x08, "3200 MBytes/sec" },
	{ 0x04, "200 MBytes/sec" },
	/* 0x02 is Unallocated */
	{ 0x01, "100 MBytes/sec" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 8-1.
 * Note, only byte 60 is allocated at this time.
 */
#define	SFF_8472_PCABLE_COMP_MASK	0x3f
static sff_pair_t sff_8472_pcable_comp[] = {
	{ 0x20, "Reserved for SFF-8461" },
	{ 0x10, "Reserved for SFF-8461" },
	{ 0x08, "Reserved for SFF-8461" },
	{ 0x04, "Reserved for SFF-8461" },
	{ 0x02, "Compliant to FC-PI-4 Appendix H" },
	{ 0x01, "Compliant to SFF-8431 Appendix E" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 8-2.
 * Note, only byte 60 is allocated at this time.
 */
#define	SFF_8472_ACABLE_COMP_MASK	0xf
static sff_pair_t sff_8472_acable_comp[] = {
	{ 0x08, "Compliant to FC-PI-4 Limiting" },
	{ 0x04, "Compliant to SFF-8431 Limiting" },
	{ 0x02, "Compliant to FC-PI-4 Appendix H" },
	{ 0x01, "Compliant to SFF-8431 Appendix" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8472 r12.2 Table 8-3.
 * Note that we combined byte 64 and 65. Byte 64 is the upper bit.
 */
#define	SFF_8472_OPTION_MASK	0x3ffe
static sff_pair_t sff_8472_options[] = {
	{ 0x2000, "Power Level 3 Requirement"},
	{ 0x1000, "Paging Implemented"},
	{ 0x0800, "Retimer or CDR implemented"},
	{ 0x0400, "Cooled Transceiver Implemented"},
	{ 0x0200, "Power Level 2 Requirement"},
	{ 0x0100, "Linear Receiver Output Implemented"},
	{ 0x0080, "Receiver decision threshold implemented"},
	{ 0x0040, "Tunable transmitter"},
	{ 0x0020, "RATE_SELECT implemented"},
	{ 0x0010, "TX_DISABLE implemented"},
	{ 0x0008, "TX_FAULT implemented"},
	{ 0x0004, "Rx_LOS inverted"},
	{ 0x0002, "Rx_LOS implemented"},
};

/*
 * This is derived from SFF 8472 r12.2 Table 8-6.
 */
#define	SFF_8472_EXTOPT_MASK	0xfe
static sff_pair_t sff_8472_extopts[] = {
	{ 0x80, "Alarm/Warning flags implemented" },
	{ 0x40, "Soft TX_DISABLE implemented" },
	{ 0x20, "Soft TX_FAULT implemented" },
	{ 0x10, "Soft RX_LOS implemented" },
	{ 0x08, "Soft RATE_SELECT implemented" },
	{ 0x04, "Application Select implemented" },
	{ 0x02, "Soft Rate Select Control Implemented" },
	{ 0x01, "" },
};

/*
 * This is derived from SFF 8472 r12.2 Table 8-8.
 */
#define	SFF_8472_8472_COMP_NENTRIES 9
static const char *sff_8472_8472_comp[] = {
	"Not compliant",
	"Rev 9.3",
	"Rev 9.5",
	"Rev 10.2",
	"Rev 10.4",
	"Rev 11.0",
	"Rev 11.3",
	"Rev 11.4",
	"Rev 12.0"
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-17.
 */
#define	SFF_8636_COMP_10GETH_MASK 0x7f
static sff_pair_t sff_8636_comp_10geth[] = {
	{ 0x40, "10GBASE-LRM" },
	{ 0x20, "10GBASE-LR" },
	{ 0x10, "10GBASE-SR" },
	{ 0x08, "40GBASE-CR4" },
	{ 0x04, "40GBASE-SR4" },
	{ 0x02, "40GBASE-LR4" },
	{ 0x01, "40G Active Cable (XLPPI)" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-17.
 */
#define	SFF_8636_COMP_SONET_MASK 0x07
static sff_pair_t sff_8636_comp_sonet[] = {
	{ 0x04, "OC 48, long reach" },
	{ 0x02, "OC 48, intermediate reach" },
	{ 0x01, "OC 48 short reach" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-17.
 */
#define	SFF_8636_COMP_SAS_MASK	0xf0
static sff_pair_t sff_8636_comp_sas[] = {
	{ 0x80, "SAS 24.0 Gb/s" },
	{ 0x40, "SAS 12.0 Gb/s" },
	{ 0x20, "SAS 6.0 Gb/s" },
	{ 0x10, "SAS 3.0 Gb/s" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-17.
 */
#define	SFF_8636_COMP_ETH_MASK	0x0f
static sff_pair_t sff_8636_comp_eth[] = {
	{ 0x08, "1000BASE-T" },
	{ 0x04, "1000BASE-CX" },
	{ 0x02, "1000BASE-LX" },
	{ 0x01, "1000BASE-SX" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-17.
 */
#define	SFF_8636_COMP_FCLEN_MASK	0xf8
static sff_pair_t sff_8636_comp_fclen[] = {
	{ 0x80, "very long distance (V)" },
	{ 0x40, "short distance (S)" },
	{ 0x20, "intermeddiate distance (I)" },
	{ 0x10, "long distance (L)" },
	{ 0x08, "medium distance (M)" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-17.
 */
#define	SFF_8636_COMP_TECH_MASK	0xf003
static sff_pair_t sff_8636_comp_tech[] = {
	{ 0x2, "Longwave laser (LC)" },
	{ 0x1, "Electrical inter-enclosure (EL)" },
	{ 0x8000, "Electrical intra-enclosure (EL)" },
	{ 0x4000, "Shortwave laser w/o OFC (SN)" },
	{ 0x2000, "Shortwave laser with OFC (SL)" },
	{ 0x1000, "Longwave laser (LL)" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-17.
 */
#define	SFF_8636_COMP_MEDIA_MASK	0xff
static sff_pair_t sff_8636_comp_media[] = {
	{ 0x80, "Twin Axial Pair (TW)" },
	{ 0x40, "Twisted Pair (TP)" },
	{ 0x20, "Miniature Coax (MI)" },
	{ 0x10, "Video Coax (TV)" },
	{ 0x08, "Multimode, 62.5um (M6)" },
	{ 0x04, "Multimode, 50m (M5)" },
	{ 0x02, "Multimode, 50um (OM3)" },
	{ 0x01, "Single Mode (SM)" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-17.
 */
#define	SFF_8636_COMP_SPEED_MASK	0xfd
static sff_pair_t sff_8636_comp_speed[] = {
	{ 0x80, "1200 MBytes/sec" },
	{ 0x40, "800 MBytes/sec" },
	{ 0x20, "1600 MBytes/sec" },
	{ 0x10, "400 MBytes/sec" },
	{ 0x08, "3200 MBytes/sec" },
	{ 0x04, "200 MBytes/sec" },
	{ 0x01, "100 MBytes/sec" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-20.
 */
static const char *sff_8636_trans_tech[] = {
	"850 nm VCSEL",
	"1310 nm VCSEL",
	"1550 nm VCSEL",
	"1310 nm FP",
	"1310 nm DFB",
	"1550 nm DFB",
	"1310 nm EML",
	"1550 nm EML",
	"Other / Undefined",
	"1490 nm DFB",
	"Copper cable unequalized",
	"Copper cable passive equalized",
	"Copper cable, near and far end limiting active equalizers",
	"Copper cable, far end limiting active equalizers",
	"Copper cable, near end limiting active equalizers",
	"Copper cable, linear active equalizers"
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-21.
 */
#define	SFF_8636_EXTMOD_CODES	0x1f
static sff_pair_t sff_8636_extmod_codes[] = {
	{ 0x10, "EDR" },
	{ 0x08, "FDR" },
	{ 0x04, "QDR" },
	{ 0x02, "DDR" },
	{ 0x01, "SDR" },
	{ 0x00, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-22. This combines bytes 193-195.
 * We treat byte 193 as the most significant.
 */
#define	SFF_8636_OPTION_MASK	0x0ffffe
static sff_pair_t sff_8636_options[] = {
	{ 0x080000, "TX Input Equalization Auto Adaptive Capable" },
	{ 0x040000, "TX Input Equalization Fixed Programmable" },
	{ 0x020000, "RX Output Emphasis Fixed Programmable Settings" },
	{ 0x010000, "RX Output Amplitude Fixed Programmable Settings" },
	{ 0x008000, "TX CDR On/Off Control implemented" },
	{ 0x004000, "RX CDR On/Off Control implemented" },
	{ 0x002000, "Tx CDR Loss of Lock Flag implemented" },
	{ 0x001000, "Rx CDR Loss of Lock Flag implemented" },
	{ 0x000800, "Rx Squelch Disable implemented" },
	{ 0x000400, "Rx Output Disable capable" },
	{ 0x000200, "Tx Squelch Disable implemented" },
	{ 0x000100, "Tx Squelch implemented" },
	{ 0x000080, "Memory page 02h provided" },
	{ 0x000040, "Memory page 01h provided" },
	{ 0x000020, "Rate Select implemented" },
	{ 0x000010, "Tx_DISABLE implemented" },
	{ 0x000008, "Tx_FAULT implemented" },
	{ 0x000004, "Tx Squelch for Pave" },
	{ 0x000002, "Tx Loss of Signal implemented" },
	{ 0x0, NULL }
};

/*
 * This is derived from SFF 8636 r2.7 Table 6-25.
 */
#define	SFF_8636_ENHANCED_OPTIONS_MASK	0x1c
static sff_pair_t sff_8636_eopt[] = {
	{ 0x10, "Initialization Complete Flag Implemented" },
	{ 0x08, "Extended Rate Selection Supported" },
	{ 0x04, "Application Select Table Supported" },
	{ 0x0, NULL }
};

static const char *
sff_pair_find(uint_t val, sff_pair_t *pairs)
{
	while (pairs->sp_name != NULL) {
		if (val == pairs->sp_val)
			return (pairs->sp_name);
		pairs++;
	}

	return (NULL);
}

static int
sff_parse_id(uint8_t id, nvlist_t *nvl)
{
	const char *val;

	if (id >= SFF_8024_VENDOR) {
		val = "Vendor Specific";
	} else if (id >= SFF_8024_NIDS) {
		val = "Reserved";
	} else {
		val = sff_8024_id_strs[id];
	}

	return (nvlist_add_string(nvl, LIBSFF_KEY_IDENTIFIER, val));
}

static int
sff_add_unit_string(uint64_t val, uint64_t factor, const char *unit,
    nvlist_t *nvl, const char *key)
{
	char str[SFP_STRBUF];

	val *= factor;
	(void) snprintf(str, sizeof (str), "%" PRIu64 " %s", val, unit);
	return (nvlist_add_string(nvl, key, str));
}

static int
sff_parse_connector(uint8_t con, nvlist_t *nvl)
{
	const char *val;

	if (con >= 0x80) {
		val = "Vendor Specific";
	} else {
		if ((val = sff_pair_find(con, sff_8024_connectors)) == NULL)
			val = "Reserved";
	}

	return (nvlist_add_string(nvl, LIBSFF_KEY_CONNECTOR, val));
}

/*
 * Many of the values in the specifications are bitfields of which one or more
 * bits may be set. We represent that as an array of strings. One entry will be
 * added for each set bit that's found in pairs.
 */
static int
sff_gather_bitfield(uint32_t value, const char *name, sff_pair_t *pairs,
    nvlist_t *nvl)
{
	uint32_t i;
	const char *vals[32];
	uint_t count;

	count = 0;
	for (i = 0; i < 32; i++) {
		uint32_t bit;
		const char *str;

		bit = 1 << i;
		if ((bit & value) == 0)
			continue;

		str = sff_pair_find(bit, pairs);
		if (str != NULL) {
			vals[count++] = str;
		}
	}

	if (count == 0)
		return (0);

	/*
	 * The nvlist routines don't touch the array, so we end up lying about
	 * the type of data so that we can avoid a rash of additional
	 * allocations and strdups.
	 */
	return (nvlist_add_string_array(nvl, name, (char **)vals, count));
}

static int
sff_parse_compliance(const uint8_t *buf, nvlist_t *nvl)
{
	int ret;
	uint16_t v;

	if ((ret = sff_gather_bitfield(buf[SFF_8472_COMPLIANCE_10GE] &
	    SFF_8472_COMP_10GETH_MASK, LIBSFF_KEY_COMPLIANCE_10GBE,
	    sff_8472_comp_10geth, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8472_COMPLIANCE_IB] &
	    SFF_8472_COMP_IB_MASK, LIBSFF_KEY_COMPLIANCE_IB,
	    sff_8472_comp_ib, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8472_COMPLIANCE_ESCON] &
	    SFF_8472_COMP_ESCON_MASK, LIBSFF_KEY_COMPLIANCE_ESCON,
	    sff_8472_comp_escon, nvl)) != 0)
		return (ret);

	v = buf[SFF_8472_COMPLIANCE_SONET_LOW] |
	    (buf[SFF_8472_COMPLIANCE_SONET_HIGH] << 8);
	if ((ret = sff_gather_bitfield(v & SFF_8472_COMP_SOCON_MASK,
	    LIBSFF_KEY_COMPLIANCE_SONET, sff_8472_comp_sonet, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8472_COMPLIANCE_ETHERNET] &
	    SFF_8472_COMP_ETH_MASK, LIBSFF_KEY_COMPLIANCE_GBE,
	    sff_8472_comp_eth, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8472_COMPLIANCE_FCLEN] &
	    SFF_8472_COMP_FCLEN_MASK, LIBSFF_KEY_COMPLIANCE_FC_LEN,
	    sff_8472_comp_fclen, nvl)) != 0)
		return (ret);

	v = buf[SFF_8472_COMPLIANCE_FC_LOW] |
	    (buf[SFF_8472_COMPLIANCE_FC_HIGH] << 8);
	if ((ret = sff_gather_bitfield(v & SFF_8472_COMP_TECH_MASK,
	    LIBSFF_KEY_COMPLIANCE_FC_TECH, sff_8472_comp_tech, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8472_COMPLIANCE_SFP] &
	    SFF_8472_COMP_CABLE_MASK, LIBSFF_KEY_COMPLIANCE_SFP,
	    sff_8472_comp_cable, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8472_COMPLIANCE_FC_MEDIA] &
	    SFF_8472_COMP_MEDIA_MASK, LIBSFF_KEY_COMPLIANCE_FC_MEDIA,
	    sff_8472_comp_media, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8472_COMPLIANCE_FC_SPEED] &
	    SFF_8472_COMP_SPEED_MASK, LIBSFF_KEY_COMPLIANCE_FC_SPEED,
	    sff_8472_comp_speed, nvl)) != 0)
		return (ret);

	return (0);
}

static int
sff_parse_encoding(uint8_t val, nvlist_t *nvl, boolean_t sfp)
{
	const char *str;
	if (val >= SFF_8024_NENCS) {
		str = "Reserved";
	} else if (sfp) {
		str = sff_8024_enc_sfp[val];
	} else {
		str = sff_8024_enc_qsfp[val];
	}

	return (nvlist_add_string(nvl, LIBSFF_KEY_ENCODING, str));
}

static int
sff_parse_br(const uint8_t *buf, nvlist_t *nvl)
{
	if (buf[SFF_8472_BR_NOMINAL] == 0xff) {
		int ret;
		if ((ret = sff_add_unit_string(buf[SFF_8472_BR_MAX],
		    SFF_8472_BR_MAX_FACTOR, "MBd", nvl,
		    LIBSFF_KEY_BR_MAX)) != 0)
			return (ret);
		return (sff_add_unit_string(buf[SFF_8472_BR_MIN],
		    SFF_8472_BR_MIN_FACTOR, "MBd", nvl, LIBSFF_KEY_BR_MIN));
	} else {
		return (sff_add_unit_string(buf[SFF_8472_BR_NOMINAL],
		    SFF_8472_BR_NOMINAL_FACTOR, "MBd", nvl,
		    LIBSFF_KEY_BR_NOMINAL));
	}
}

static int
sff_parse_lengths(const uint8_t *buf, nvlist_t *nvl)
{
	int ret;

	if (buf[SFF_8472_LENGTH_SMF_KM] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8472_LENGTH_SMF_KM],
		    SFF_8472_LENGTH_SMF_KM_FACTOR, "km", nvl,
		    LIBSFF_KEY_LENGTH_SMF_KM)) != 0)
			return (ret);
	}

	if (buf[SFF_8472_LENGTH_SMF] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8472_LENGTH_SMF],
		    SFF_8472_LENGTH_SMF_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_SMF)) != 0)
			return (ret);
	}

	if (buf[SFF_8472_LENGTH_50UM] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8472_LENGTH_50UM],
		    SFF_8472_LENGTH_50UM_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_OM2)) != 0)
			return (ret);
	}

	if (buf[SFF_8472_LENGTH_62UM] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8472_LENGTH_62UM],
		    SFF_8472_LENGTH_62UM_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_OM1)) != 0)
			return (ret);
	}

	if (buf[SFF_8472_LENGTH_COPPER] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8472_LENGTH_COPPER],
		    SFF_8472_LENGTH_COPPER_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_COPPER)) != 0)
			return (ret);
	}

	if (buf[SFF_8472_LENGTH_OM3] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8472_LENGTH_OM3],
		    SFF_8472_LENGTH_OM3_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_OM3)) != 0)
			return (ret);
	}

	return (0);
}

/*
 * Strings in the SFF specification are written into fixed sized buffers. The
 * strings are padded to the right with spaces (ASCII 0x20) and there is no NUL
 * character like in a standard C string. While the string is padded with
 * spaces, spaces may appear in the middle of the string and should not be
 * confused as padding.
 */
static int
sff_parse_string(const uint8_t *buf, uint_t start, uint_t len,
    const char *field, nvlist_t *nvl)
{
	uint_t i;
	char strbuf[SFP_STRBUF];

	assert(len < sizeof (strbuf));
	strbuf[0] = '\0';
	while (len > 0) {
		if (buf[start + len - 1] != ' ')
			break;
		len--;
	}
	if (len == 0)
		return (0);

	/*
	 * This is supposed to be 7-bit printable ASCII. If we find any
	 * characters that aren't, don't include this string.
	 */
	for (i = 0; i < len; i++) {
		if (isascii(buf[start + i]) == 0 ||
		    isprint(buf[start + i]) == 0) {
			return (0);
		}
	}
	bcopy(&buf[start], strbuf, len);
	strbuf[len] = '\0';

	return (nvlist_add_string(nvl, field, strbuf));
}

static int
sff_parse_optical(const uint8_t *buf, nvlist_t *nvl)
{
	/*
	 * The value in byte 8 determines whether we interpret this as
	 * describing aspects of a copper device or if it describes the
	 * wavelength.
	 */
	if (buf[SFF_8472_COMPLIANCE_SFP] & SFF_8472_COMP_CABLE_PASSIVE) {
		return (sff_gather_bitfield(buf[SFF_8472_PASSIVE_SPEC] &
		    SFF_8472_PCABLE_COMP_MASK, LIBSFF_KEY_COMPLIANCE_PASSIVE,
		    sff_8472_pcable_comp, nvl));
	} else if (buf[SFF_8472_COMPLIANCE_SFP] & SFF_8472_COMP_CABLE_ACTIVE) {
		return (sff_gather_bitfield(buf[SFF_8472_ACTIVE_SPEC] &
		    SFF_8472_ACABLE_COMP_MASK, LIBSFF_KEY_COMPLIANCE_ACTIVE,
		    sff_8472_acable_comp, nvl));

	} else {
		uint16_t val = (buf[SFF_8472_WAVELENGTH_HI] << 8) |
		    buf[SFF_8472_WAVELENGTH_LOW];

		return (sff_add_unit_string(val, SFF_8472_WAVELENGTH_FACTOR,
		    "nm", nvl, LIBSFF_KEY_WAVELENGTH));
	}
}

static int
sff_parse_options(const uint8_t *buf, nvlist_t *nvl)
{
	uint16_t val;

	val = (buf[SFF_8472_OPTIONS_HI] << 8) | buf[SFF_8472_OPTIONS_LOW];
	return (sff_gather_bitfield(val & SFF_8472_OPTION_MASK,
	    LIBSFF_KEY_OPTIONS, sff_8472_options, nvl));
}

static int
sff_parse_8472_comp(uint8_t val, nvlist_t *nvl)
{
	const char *str;

	if (val >= SFF_8472_8472_COMP_NENTRIES) {
		str = "Unallocated";
	} else {
		str = sff_8472_8472_comp[val];
	}

	return (nvlist_add_string(nvl, LIBSFF_KEY_COMPLIANCE_8472, str));
}

/*
 * Parse an SFP that is either based on INF 8074 or SFF 8472. These are GBIC,
 * SFP, SFP+, and SFP28 based devices.
 *
 * The SFP parsing into an nvlist_t is incomplete. At the moment we're not
 * parsing the following pieces from SFF 8472 page 0xa0:
 *
 *  o  Rate Selection Logic
 *  o  Diagnostic Monitoring Type
 */
static int
sff_parse_sfp(const uint8_t *buf, nvlist_t *nvl)
{
	int ret;

	if ((ret = sff_parse_id(buf[SFF_8472_IDENTIFIER], nvl)) != 0)
		return (ret);

	/*
	 * The extended identifier is derived from SFF 8472, Table 5-2. It
	 * generally is just the value 4. The other values are not well defined.
	 */
	if ((ret = nvlist_add_uint8(nvl, LIBSFF_KEY_8472_EXT_IDENTIFIER,
	    buf[SFF_8472_EXT_IDENTIFER])) != 0)
		return (ret);

	if ((ret = sff_parse_connector(buf[SFF_8472_CONNECTOR], nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_compliance(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_encoding(buf[SFF_8472_ENCODING], nvl,
	    B_TRUE)) != 0)
		return (ret);

	if ((ret = sff_parse_br(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_lengths(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8472_VENDOR, SFF_8472_VENDOR_LEN,
	    LIBSFF_KEY_VENDOR, nvl)) != 0)
		return (ret);

	if ((ret = nvlist_add_byte_array(nvl, LIBSFF_KEY_OUI,
	    (uchar_t *)&buf[SFF_8472_OUI], SFF_8472_OUI_LEN)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8472_VENDOR_PN,
	    SFF_8472_VENDOR_PN_LEN, LIBSFF_KEY_PART, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8472_VENDOR_REV,
	    SFF_8472_VENDOR_REV_LEN, LIBSFF_KEY_REVISION, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_optical(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_options(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8472_VENDOR_SN,
	    SFF_8472_VENDOR_SN_LEN, LIBSFF_KEY_SERIAL, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8472_DATE_CODE,
	    SFF_8472_DATE_CODE_LEN, LIBSFF_KEY_DATECODE, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8472_ENHANCED_OPTIONS] &
	    SFF_8472_EXTOPT_MASK, LIBSFF_KEY_EXTENDED_OPTIONS,
	    sff_8472_extopts, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_8472_comp(buf[SFF_8472_SFF_8472_COMPLIANCE],
	    nvl)) != 0)
		return (ret);

	return (0);
}

static int
sff_qsfp_parse_compliance(const uint8_t *buf, nvlist_t *nvl)
{
	int ret;
	uint16_t fc_val;

	if ((ret = sff_gather_bitfield(buf[SFF_8636_COMPLIANCE_10GBEP] &
	    SFF_8636_COMP_10GETH_MASK, LIBSFF_KEY_COMPLIANCE_10GBE,
	    sff_8636_comp_10geth, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8636_COMPLIANCE_SONET] &
	    SFF_8636_COMP_SONET_MASK, LIBSFF_KEY_COMPLIANCE_SONET,
	    sff_8636_comp_sonet, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8636_COMPLIANCE_SAS] &
	    SFF_8636_COMP_SAS_MASK, LIBSFF_KEY_COMPLIANCE_SAS,
	    sff_8636_comp_sas, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8636_COMPLIANCE_ETHERNET] &
	    SFF_8636_COMP_ETH_MASK, LIBSFF_KEY_COMPLIANCE_GBE,
	    sff_8636_comp_eth, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8636_COMPLIANCE_FCLEN] &
	    SFF_8636_COMP_FCLEN_MASK, LIBSFF_KEY_COMPLIANCE_FC_LEN,
	    sff_8636_comp_fclen, nvl)) != 0)
		return (ret);

	fc_val = buf[SFF_8636_COMPLIANCE_FC_LOW] |
	    (buf[SFF_8636_COMPLIANCE_FC_HIGH] << 8);
	if ((ret = sff_gather_bitfield(fc_val & SFF_8636_COMP_TECH_MASK,
	    LIBSFF_KEY_COMPLIANCE_FC_TECH, sff_8636_comp_tech, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8636_COMPLIANCE_FC_MEDIA] &
	    SFF_8636_COMP_MEDIA_MASK, LIBSFF_KEY_COMPLIANCE_FC_MEDIA,
	    sff_8636_comp_media, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8636_COMPLIANCE_FC_SPEED] &
	    SFF_8636_COMP_SPEED_MASK, LIBSFF_KEY_COMPLIANCE_FC_SPEED,
	    sff_8636_comp_speed, nvl)) != 0)
		return (ret);

	return (0);
}

static int
sff_qsfp_parse_br(const uint8_t *buf, nvlist_t *nvl)
{
	if (buf[SFF_8636_BR_NOMINAL] == 0xff) {
		return (sff_add_unit_string(buf[SFF_8636_BR_NOMINAL_EXT],
		    SFF_8636_BR_NOMINAL_EXT_FACTOR, "Mbps", nvl,
		    LIBSFF_KEY_BR_NOMINAL));
	} else {
		return (sff_add_unit_string(buf[SFF_8636_BR_NOMINAL],
		    SFF_8636_BR_NOMINAL_FACTOR, "Mbps", nvl,
		    LIBSFF_KEY_BR_NOMINAL));
	}
}

static int
sff_qsfp_parse_lengths(const uint8_t *buf, nvlist_t *nvl)
{
	int ret;

	if (buf[SFF_8636_LENGTH_SMF] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8636_LENGTH_SMF],
		    SFF_8636_LENGTH_SMF_FACTOR, "km", nvl,
		    LIBSFF_KEY_LENGTH_SMF_KM)) != 0)
			return (ret);
	}

	if (buf[SFF_8636_LENGTH_OM3] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8636_LENGTH_OM3],
		    SFF_8636_LENGTH_OM3_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_OM3)) != 0)
			return (ret);
	}

	if (buf[SFF_8636_LENGTH_OM2] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8636_LENGTH_OM2],
		    SFF_8636_LENGTH_OM2_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_OM2)) != 0)
			return (ret);
	}

	if (buf[SFF_8636_LENGTH_OM1] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8636_LENGTH_OM1],
		    SFF_8636_LENGTH_OM1_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_OM1)) != 0)
			return (ret);
	}

	if (buf[SFF_8636_LENGTH_COPPER] != 0) {
		if ((ret = sff_add_unit_string(buf[SFF_8636_LENGTH_COPPER],
		    SFF_8636_LENGTH_COPPER_FACTOR, "m", nvl,
		    LIBSFF_KEY_LENGTH_COPPER)) != 0)
			return (ret);
	}

	return (0);
}

static int
sff_qsfp_parse_tech(uint8_t val, nvlist_t *nvl)
{
	const char *strs[5];

	strs[0] = sff_8636_trans_tech[(val & 0xf0) >> 4];
	if (val & 0x08) {
		strs[1] = "Active Wavelength Control";
	} else {
		strs[1] = "No Wavelength Control";
	}

	if (val & 0x04) {
		strs[2] = "Cooled Transmitter";
	} else {
		strs[2] = "Uncooled Transmitter";
	}

	if (val & 0x02) {
		strs[3] = "APD Detector";
	} else {
		strs[3] = "Pin Detector";
	}

	if (val & 0x01) {
		strs[4] = "Transmitter Tunable";
	} else {
		strs[4] = "Transmitter Not Tunable";
	}

	/*
	 * The nvlist routines don't touch the array, so we end up lying about
	 * the type of data so that we can avoid a rash of additional
	 * allocations and strdups.
	 */
	return (nvlist_add_string_array(nvl, LIBSFF_KEY_TRAN_TECH,
	    (char **)strs, 5));
}

static int
sff_qsfp_parse_copperwave(const uint8_t *buf, nvlist_t *nvl)
{
	int ret;

	/*
	 * The values that we get depend on whether or not we are a copper
	 * device or not. We can determine this based on the identification
	 * information in the device technology field.
	 */
	if ((buf[SFF_8636_DEVICE_TECH] & 0xf0) >= 0xa0) {
		if ((ret = sff_add_unit_string(buf[SFF_8636_ATTENUATE_2G], 1,
		    "dB", nvl, LIBSFF_KEY_ATTENUATE_2G)) != 0)
			return (ret);
		if ((ret = sff_add_unit_string(buf[SFF_8636_ATTENUATE_5G], 1,
		    "dB", nvl, LIBSFF_KEY_ATTENUATE_5G)) != 0)
			return (ret);
		if ((ret = sff_add_unit_string(buf[SFF_8636_ATTENUATE_7G], 1,
		    "dB", nvl, LIBSFF_KEY_ATTENUATE_7G)) != 0)
			return (ret);
		if ((ret = sff_add_unit_string(buf[SFF_8636_ATTENUATE_12G], 1,
		    "dB", nvl, LIBSFF_KEY_ATTENUATE_12G)) != 0)
			return (ret);
	} else {
		uint16_t val;
		double d;
		char strbuf[SFP_STRBUF];

		/*
		 * Because we need to divide the units here into doubles, we
		 * can't use the standard unit routine.
		 */
		val = (buf[SFF_8636_WAVELENGTH_NOMINAL_HI] << 8) |
		    buf[SFF_8636_WAVELENGTH_NOMINAL_LOW];
		if (val != 0) {
			d = val / 20.0;
			(void) snprintf(strbuf, sizeof (strbuf), "%.3lf nm", d);
			if ((ret = nvlist_add_string(nvl, LIBSFF_KEY_WAVELENGTH,
			    strbuf)) != 0)
				return (ret);
		}

		val = (buf[SFF_8636_WAVELENGTH_TOLERANCE_HI] << 8) |
		    buf[SFF_8636_WAVELENGTH_TOLERANCE_LOW];
		if (val != 0) {
			d = val / 20.0;
			(void) snprintf(strbuf, sizeof (strbuf), "%.3lf nm", d);
			if ((ret = nvlist_add_string(nvl,
			    LIBSFF_KEY_WAVE_TOLERANCE, strbuf)) != 0)
				return (ret);
		}
	}

	return (0);
}

static int
sff_qsfp_parse_casetemp(uint8_t val, nvlist_t *nvl)
{
	/*
	 * The default temperature per SFF 8636 r2.7 6.3.21 'Maximum Case
	 * Temperature' is 70 C. If the value is zero, we're supposed to assume
	 * it's the default.
	 */
	if (val == 0)
		val = 70;

	return (sff_add_unit_string(val, 1, "C", nvl,
	    LIBSFF_KEY_MAX_CASE_TEMP));
}

static int
sff_qsfp_parse_extcomp(uint8_t val, nvlist_t *nvl)
{
	const char *str;

	if (val >= SFF_8024_EXT_SPEC_NENTRIES) {
		str = "Reserved";
	} else {
		str = sff_8024_ext_spec[val];
	}

	return (nvlist_add_string(nvl, LIBSFF_KEY_EXT_SPEC, str));
}

static int
sff_qsfp_parse_options(const uint8_t *buf, nvlist_t *nvl)
{
	uint_t val;

	val = (buf[SFF_8636_OPTIONS_HI] << 16) |
	    (buf[SFF_8636_OPTIONS_MID] << 8) | buf[SFF_8636_OPTIONS_LOW];

	return (sff_gather_bitfield(val & SFF_8636_OPTION_MASK,
	    LIBSFF_KEY_OPTIONS, sff_8636_options, nvl));
}

static int
sff_qsfp_parse_diag(uint8_t val, nvlist_t *nvl)
{
	const char *buf[2];
	uint_t count = 1;

	if (val & 0x08) {
		buf[0] = "Received power measurements: Average Power";
	} else {
		buf[0] = "Received power measurements: OMA";
	}

	if (val & 0x04) {
		count++;
		buf[1] = "Transmitter power measurement";
	}

	/*
	 * The nvlist routines don't touch the array, so we end up lying about
	 * the type of data so that we can avoid a rash of additional
	 * allocations and strdups.
	 */
	return (nvlist_add_string_array(nvl, LIBSFF_KEY_DIAG_MONITOR,
	    (char **)buf, count));
}

/*
 * Parse a QSFP family device that is based on SFF-8436 / SFF-8636. Note that we
 * ignore the lower half of page 0xa0 at this time and instead focus on the
 * upper half of page 0xa0 which has identification information.
 *
 * For the moment we're not parsing the following fields:
 *
 *  o  Extended Identifier (byte 129)
 *  o  Extended Rate Select Compliance (byte 141)
 */
static int
sff_parse_qsfp(const uint8_t *buf, nvlist_t *nvl)
{
	int ret;

	if ((ret = sff_parse_id(buf[SFF_8636_IDENTIFIER], nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_connector(buf[SFF_8636_CONNECTOR], nvl)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_compliance(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_encoding(buf[SFF_8636_ENCODING], nvl,
	    B_FALSE)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_br(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_lengths(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_tech(buf[SFF_8636_DEVICE_TECH], nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8636_VENDOR, SFF_8636_VENDOR_LEN,
	    LIBSFF_KEY_VENDOR, nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8636_EXTENDED_MODULE] &
	    SFF_8636_EXTMOD_CODES, LIBSFF_KEY_EXT_MOD_CODES,
	    sff_8636_extmod_codes, nvl)) != 0)
		return (ret);

	if ((ret = nvlist_add_byte_array(nvl, LIBSFF_KEY_OUI,
	    (uchar_t *)&buf[SFF_8636_OUI], SFF_8636_OUI_LEN)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8636_VENDOR_PN,
	    SFF_8636_VENDOR_PN_LEN, LIBSFF_KEY_PART, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8636_VENDOR_REV,
	    SFF_8636_VENDOR_REV_LEN, LIBSFF_KEY_REVISION, nvl)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_copperwave(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_casetemp(buf[SFF_8636_MAX_CASE_TEMP],
	    nvl)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_extcomp(buf[SFF_8636_LINK_CODES], nvl)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_options(buf, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8636_VENDOR_SN,
	    SFF_8636_VENDOR_SN_LEN, LIBSFF_KEY_SERIAL, nvl)) != 0)
		return (ret);

	if ((ret = sff_parse_string(buf, SFF_8636_DATE_CODE,
	    SFF_8636_DATE_CODE_LEN, LIBSFF_KEY_DATECODE, nvl)) != 0)
		return (ret);

	if ((ret = sff_qsfp_parse_diag(buf[SFF_8636_DIAG_MONITORING],
	    nvl)) != 0)
		return (ret);

	if ((ret = sff_gather_bitfield(buf[SFF_8636_ENHANCED_OPTIONS] &
	    SFF_8636_ENHANCED_OPTIONS_MASK, LIBSFF_KEY_ENHANCED_OPTIONS,
	    sff_8636_eopt, nvl)) != 0)
		return (ret);

	return (0);
}

int
libsff_parse(const uint8_t *buf, size_t len, uint_t page, nvlist_t **nvpp)
{
	int ret;
	nvlist_t *nvp = NULL;
	uint8_t ubuf[256];

	/*
	 * At the moment, we only support page a0.
	 */
	if (page != 0xa0 || buf == NULL || len == 0 || nvpp == NULL)
		return (EINVAL);

	*nvpp = NULL;

	/*
	 * Make sure that the library has been given valid data to parse.
	 */
	if (uucopy(buf, ubuf, MIN(sizeof (ubuf), len)) != 0)
		return (errno);

	if ((ret = nvlist_alloc(&nvp, NV_UNIQUE_NAME, 0)) != 0)
		return (ret);

	switch (buf[0]) {
	case SFF_8024_ID_QSFP:
	case SFF_8024_ID_QSFP_PLUS:
	case SFF_8024_ID_QSFP28:
		/*
		 * For QSFP based products, identification information is spread
		 * across both the top and bottom half of page 0xa0.
		 */
		if (len < SFP_MIN_LEN_8636) {
			ret = EINVAL;
			break;
		}
		ret = sff_parse_qsfp(ubuf, nvp);
		break;
	default:
		if (len < SFP_MIN_LEN_8472) {
			ret = EINVAL;
			break;
		}
		ret = sff_parse_sfp(ubuf, nvp);
		break;
	}

	if (ret != 0) {
		nvlist_free(nvp);
	} else {
		*nvpp = nvp;
	}
	return (ret);
}
