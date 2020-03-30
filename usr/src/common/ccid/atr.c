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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * ATR parsing routines shared between userland (ccidadm) and the kernel (CCID
 * driver)
 */

#include "atr.h"
#include <sys/debug.h>
#include <sys/sysmacros.h>

#ifdef	_KERNEL
#include <sys/inttypes.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#else
#include <inttypes.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#endif

/*
 * The ATR must have at least 2 bytes and then may have up to 33 bytes. The
 * first byte is always TS and the second required byte is T0.
 */
#define	ATR_TS_IDX	0
#define	ATR_T0_IDX	1

/*
 * There are two valid values for TS. It must either be 0x3F or 0x3B. This is
 * required per ISO/IEC 7816-3:2006 section 8.1.
 */
#define	ATR_TS_INVERSE	0x3F
#define	ATR_TS_DIRECT	0x3B

/*
 * After TS, each word is used to indicate a combination of protocol and the
 * number of bits defined for that protocol. The lower nibble is treated as the
 * protocol. The upper nibble is treated to indicate which of four defined words
 * are present. These are usually referred to as TA, TB, TC, and TD. TD is
 * always used to indicate the next protocol and the number of bytes present for
 * that. T0 works in a similar way, except that it defines the number of
 * historical bytes present in its protocol section and then it refers to a set
 * of pre-defined global bytes that may be present.
 */
#define	ATR_TD_PROT(x)	((x) & 0x0f)
#define	ATR_TD_NBITS(x)	(((x) & 0xf0) >> 4)
#define	ATR_TA_MASK	0x1
#define	ATR_TB_MASK	0x2
#define	ATR_TC_MASK	0x4
#define	ATR_TD_MASK	0x8

#define	ATR_TA1_FTABLE(x)	(((x) & 0xf0) >> 4)
#define	ATR_TA1_DITABLE(x)	((x) & 0x0f)

#define	ATR_TA2_CANCHANGE(x)	(((x) & 0x80) == 0)
#define	ATR_TA2_HONORTA1(x)	(((x) & 0x10) == 0)
#define	ATR_TA2_PROTOCOL(x)	((x) & 0x0f)

/*
 * When the checksum is required in the ATR, each byte must XOR to zero.
 */
#define	ATR_CKSUM_TARGET	0

/*
 * Maximum number of historic ATR bytes. This is limited by the fact that it's a
 * 4-bit nibble.
 */
#define	ATR_HISTORICAL_MAX	15

/*
 * The maximum number of TA, TB, TC, and TD levels that can be encountered in a
 * given structure. In the best case, there are 30 bytes available (TS, T0, and
 * TCK use the others). Given that each one of these needs 4 bytes to be
 * represented, the maximum number of layers that can fit is seven.
 */
#define	ATR_TI_MAX	7

/*
 * Defined protocol values. See ISO/IEC 7816-3:2006 8.2.3 for this list.
 * Reserved values are noted but not defined.
 */
#define	ATR_PROTOCOL_T0		0
#define	ATR_PROTOCOL_T1		1

#define	ATR_T1_TB0_CWI(x)	((x) & 0x0f)
#define	ATR_T1_TB0_BWI(x)	(((x) & 0xf0) >> 4)
#define	ATR_T1_TC0_CRC(x)	(((x) & 0x01) != 0)

/*
 * T=2 and T=3 are reserved for future full-duplex operation.
 * T=4 is reserved for enhanced half-duplex character transmission.
 * T=5-13 are reserved for future use by ISO/IEC JTC 1/SC 17.
 * T=14 is for protocols not standardized by ISO/IEC JTC 1/SC 17.
 */
#define	ATR_PROTOCOL_T15	15

#define	ATR_T15_TA0_CLOCK(x)	(((x) & 0xc0) >> 6)
#define	ATR_T15_TA0_VOLTAGE(x)	((x) & 0x3f)

#define	ATR_T15_TB0_SPU_STANDARD(x)	(((x & 0x80)) != 0)

/*
 * Various definitions for the configuration of historical data. This comes from
 * ISO/IEC 7816-4:2013 Section 12.1.1.
 */

/*
 * The first historical byte is used to indicate the encoding of the data. Only
 * values 0x00, 0x80-0x8f are defined. All others are proprietary. 0x81-0x8f are
 * reserved for future use.
 */
#define	ATR_HIST_CAT_MAND_STATUS	0x00
#define	ATR_HIST_CAT_TLV_STATUS		0x80
#define	ATR_HIST_CAT_RFU_MIN		0x81
#define	ATR_HIST_CAT_RFU_MAX		0x8f

/*
 * From ISO/IEC 7816-3:2006 Section 8.3.
 *
 * The default value for Fi is 372 which is table entry 1. The default value for
 * Di is 1, which is table entry 1.
 */
#define	ATR_FI_DEFAULT_INDEX	1
#define	ATR_DI_DEFAULT_INDEX	1
#define	ATR_EXTRA_GUARDTIME_DEFAULT	0

/*
 * From ISO/IEC 7816-3:2006 Section 10.2.
 */
#define	ATR_T0_WI_DEFAULT	10

/*
 * From ISO/IEC 7816-3:2006 Section 11.4.3.
 */
#define	ATR_T1_CWI_DEFAULT	13

/*
 * From ISO/IEC 7816-3:2006 Section 11.4.3.
 */
#define	ATR_T1_BWI_DEFAULT	4

/*
 * From ISO/IEC 7816-3:2006 Section 11.4.2.
 */
#define	ATR_T1_IFSC_DEFAULT	32

/*
 * From ISO/IEC 7816-3:2006 Section 11.4.4
 */
#define	ATR_T1_CHECKSUM_DEFAULT	ATR_T1_CHECKSUM_LRC

/*
 * Definitions for PPS construction. These are derived from ISO/IEC 7816-3:2006
 * section 9, Protocol and parameters selection.
 */
#define	PPS_LEN_MIN	3	/* PPSS, PPS0, PCK */
#define	PPS_LEN_MAX	PPS_BUFFER_MAX
#define	PPS_PPSS_INDEX	0
#define	PPS_PPSS_VAL	0xff
#define	PPS_PPS0_INDEX	0x01
#define	PPS_PPS0_PROT(x)	((x) & 0x0f)
#define	PPS_PPS0_PPS1		(1 << 4)
#define	PPS_PPS0_PPS2		(1 << 5)
#define	PPS_PPS0_PPS3		(1 << 6)
#define	PPS_PPS1_SETVAL(f, d)	((((f) & 0x0f) << 4) | ((d) & 0x0f))

/*
 * This enum and subsequent structure is used to represent a single level of
 * 'T'. This includes the possibility for all three values to be set and records
 * the protocol.
 */
typedef enum atr_ti_flags {
	ATR_TI_HAVE_TA	= 1 << 0,
	ATR_TI_HAVE_TB	= 1 << 1,
	ATR_TI_HAVE_TC	= 1 << 2,
	ATR_TI_HAVE_TD	= 1 << 3
} atr_ti_flags_t;

typedef struct atr_ti {
	uint8_t		atrti_protocol;
	uint8_t		atrti_ti_val;
	uint8_t		atrti_td_idx;
	atr_ti_flags_t	atrti_flags;
	uint8_t		atrti_ta;
	uint8_t		atrti_tb;
	uint8_t		atrti_tc;
	uint8_t		atrti_td;
} atr_ti_t;

typedef enum atr_flags {
	ATR_F_USES_DIRECT	= 1 << 0,
	ATR_F_USES_INVERSE	= 1 << 1,
	ATR_F_HAS_CHECKSUM	= 1 << 2,
	ATR_F_VALID		= 1 << 3
} atr_flags_t;


struct atr_data {
	atr_flags_t	atr_flags;
	uint8_t		atr_nti;
	atr_ti_t	atr_ti[ATR_TI_MAX];
	uint8_t		atr_nhistoric;
	uint8_t		atr_historic[ATR_HISTORICAL_MAX];
	uint8_t		atr_cksum;
	uint8_t		atr_raw[ATR_LEN_MAX];
	uint8_t		atr_nraw;
};

/*
 * These tables maps the bit values for Fi from 7816-3:2006 section 8.3 Table 7.
 */
static uint_t atr_fi_valtable[16] = {
	372,		/* 0000 */
	372,		/* 0001 */
	558,		/* 0010 */
	744,		/* 0011 */
	1116,		/* 0100 */
	1488,		/* 0101 */
	1860,		/* 0110 */
	0,		/* 0111 */
	0,		/* 1000 */
	512,		/* 1001 */
	768,		/* 1010 */
	1024,		/* 1011 */
	1536,		/* 1100 */
	2048,		/* 1101 */
	0,		/* 1110 */
	0		/* 1111 */
};

static const char *atr_fi_table[16] = {
	"372",		/* 0000 */
	"372",		/* 0001 */
	"558",		/* 0010 */
	"744",		/* 0011 */
	"1116",		/* 0100 */
	"1488",		/* 0101 */
	"1860",		/* 0110 */
	"RFU",		/* 0111 */
	"RFU",		/* 1000 */
	"512",		/* 1001 */
	"768",		/* 1010 */
	"1024",		/* 1011 */
	"1536",		/* 1100 */
	"2048",		/* 1101 */
	"RFU",		/* 1110 */
	"RFU",		/* 1111 */
};

/*
 * This table maps the bit values for f(max) from 7816-3:2006 section 8.3
 * Table 7.
 */
static const char *atr_fmax_table[16] = {
	"4",		/* 0000 */
	"5",		/* 0001 */
	"6",		/* 0010 */
	"8",		/* 0011 */
	"12",		/* 0100 */
	"16",		/* 0101 */
	"20",		/* 0110 */
	"-",		/* 0111 */
	"-",		/* 1000 */
	"5",		/* 1001 */
	"7.5",		/* 1010 */
	"10",		/* 1011 */
	"15",		/* 1100 */
	"20",		/* 1101 */
	"-",		/* 1110 */
	"-",		/* 1111 */
};

/*
 * This table maps the bit values for Di from 7816-3:2006 section 8.3 Table 8.
 */
static uint_t atr_di_valtable[16] = {
	0,		/* 0000 */
	1,		/* 0001 */
	2,		/* 0010 */
	4,		/* 0011 */
	8,		/* 0100 */
	16,		/* 0101 */
	32,		/* 0110 */
	64,		/* 0111 */
	12,		/* 1000 */
	20,		/* 1001 */
	0,		/* 1010 */
	0,		/* 1011 */
	0,		/* 1100 */
	0,		/* 1101 */
	0,		/* 1110 */
	0		/* 1111 */
};

static const char *atr_di_table[16] = {
	"RFU",		/* 0000 */
	"1",		/* 0001 */
	"2",		/* 0010 */
	"4",		/* 0011 */
	"8",		/* 0100 */
	"16",		/* 0101 */
	"32",		/* 0110 */
	"64",		/* 0111 */
	"12",		/* 1000 */
	"20",		/* 1001 */
	"RFU",		/* 1010 */
	"RFU",		/* 1011 */
	"RFU",		/* 1100 */
	"RFU",		/* 1101 */
	"RFU",		/* 1110 */
	"RFU",		/* 1111 */
};

/*
 * This table maps the bit values for the clock stop indicator from 7816-3:2006
 * section 8.3 Table 9.
 */
static const char *atr_clock_table[4] = {
	"disallowed",		/* 00 */
	"signal low",		/* 01 */
	"signal high",		/* 10 */
	"signal low or high"	/* 11 */
};

uint_t
atr_fi_index_to_value(uint8_t val)
{
	if (val >= ARRAY_SIZE(atr_fi_valtable)) {
		return (0);
	}

	return (atr_fi_valtable[val]);
}

const char *
atr_fi_index_to_string(uint8_t val)
{
	if (val >= ARRAY_SIZE(atr_fi_table)) {
		return ("<invalid>");
	}

	return (atr_fi_table[val]);
}

const char *
atr_fmax_index_to_string(uint8_t val)
{
	if (val >= ARRAY_SIZE(atr_fmax_table)) {
		return ("<invalid>");
	}

	return (atr_fmax_table[val]);
}

uint_t
atr_di_index_to_value(uint8_t val)
{
	if (val >= ARRAY_SIZE(atr_di_valtable)) {
		return (0);
	}

	return (atr_di_valtable[val]);
}
const char *
atr_di_index_to_string(uint8_t val)
{
	if (val >= ARRAY_SIZE(atr_di_table)) {
		return ("<invalid>");
	}

	return (atr_di_table[val]);
}

const char *
atr_clock_stop_to_string(atr_clock_stop_t val)
{
	if (val >= ARRAY_SIZE(atr_clock_table)) {
		return ("<invalid>");
	}

	return (atr_clock_table[val]);
}

const char *
atr_protocol_to_string(atr_protocol_t prot)
{
	if (prot == ATR_P_NONE) {
		return ("none");
	}

	if ((prot & ATR_P_T0) == ATR_P_T0) {
		return ("T=0");
	} else if ((prot & ATR_P_T1) == ATR_P_T1) {
		return ("T=1");
	} else {
		return ("T=0, T=1");
	}
}

const char *
atr_convention_to_string(atr_convention_t conv)
{
	if (conv == ATR_CONVENTION_DIRECT) {
		return ("direct");
	} else if (conv == ATR_CONVENTION_INVERSE) {
		return ("inverse");
	} else {
		return ("<invalid convention>");
	}
}

const char *
atr_strerror(atr_parsecode_t code)
{
	switch (code) {
	case ATR_CODE_OK:
		return ("ATR parsed successfully");
	case ATR_CODE_TOO_SHORT:
		return ("Specified buffer too short");
	case ATR_CODE_TOO_LONG:
		return ("Specified buffer too long");
	case ATR_CODE_INVALID_TS:
		return ("ATR has invalid TS byte value");
	case ATR_CODE_OVERRUN:
		return ("ATR data requires more bytes than provided");
	case ATR_CODE_UNDERRUN:
		return ("ATR data did not use all provided bytes");
	case ATR_CODE_CHECKSUM_ERROR:
		return ("ATR data did not checksum correctly");
	case ATR_CODE_INVALID_TD1:
		return ("ATR data has invalid protocol in TD1");
	default:
		return ("Unknown Parse Code");
	}
}

static uint_t
atr_count_cbits(uint8_t x)
{
	uint_t ret = 0;

	if (x & ATR_TA_MASK)
		ret++;
	if (x & ATR_TB_MASK)
		ret++;
	if (x & ATR_TC_MASK)
		ret++;
	if (x & ATR_TD_MASK)
		ret++;
	return (ret);
}

/*
 * Parse out ATR values. Focus on only parsing it and not interpreting it.
 * Interpretation should be done in other functions that can walk over the data
 * and be more protocol-aware.
 */
atr_parsecode_t
atr_parse(const uint8_t *buf, size_t len, atr_data_t *data)
{
	uint_t nhist, cbits, ncbits, idx, Ti, prot;
	uint_t ncksum = 0;
	atr_ti_t *atp;

	/*
	 * Zero out data in case someone's come back around for another loop on
	 * the same data.
	 */
	bzero(data, sizeof (atr_data_t));

	if (len < ATR_LEN_MIN) {
		return (ATR_CODE_TOO_SHORT);
	}

	if (len > ATR_LEN_MAX) {
		return (ATR_CODE_TOO_LONG);
	}

	if (buf[ATR_TS_IDX] != ATR_TS_INVERSE &&
	    buf[ATR_TS_IDX] != ATR_TS_DIRECT) {
		return (ATR_CODE_INVALID_TS);
	}

	bcopy(buf, data->atr_raw, len);
	data->atr_nraw = len;

	if (buf[ATR_TS_IDX] == ATR_TS_DIRECT) {
		data->atr_flags |= ATR_F_USES_DIRECT;
	} else {
		data->atr_flags |= ATR_F_USES_INVERSE;
	}

	/*
	 * The protocol of T0 is the number of historical bits present.
	 */
	nhist = ATR_TD_PROT(buf[ATR_T0_IDX]);
	cbits = ATR_TD_NBITS(buf[ATR_T0_IDX]);
	idx = ATR_T0_IDX + 1;
	ncbits = atr_count_cbits(cbits);

	/*
	 * Ti is used to track the current iteration of T[A,B,C,D] that we are
	 * on, as the ISO/IEC standard suggests. The way that values are
	 * interpreted depends on the value of Ti.
	 *
	 * When Ti is one, TA, TB, and TC represent global properties. TD's
	 * protocol represents the preferred protocol.
	 *
	 * When Ti is two, TA, TB, and TC also represent global properties.
	 * However, TC only has meaning if the protocol is T=0.
	 *
	 * When Ti is 15, it indicates more global properties.
	 *
	 * For all other values of Ti, the meaning depends on the protocol in
	 * question and they are all properties specific to that protocol.
	 */
	Ti = 1;
	/*
	 * Initialize prot to an invalid protocol to help us deal with the
	 * normal workflow and make sure that we don't mistakenly do anything.
	 */
	prot = UINT32_MAX;
	for (;;) {
		atp = &data->atr_ti[data->atr_nti];
		data->atr_nti++;
		ASSERT3U(data->atr_nti, <=, ATR_TI_MAX);

		/*
		 * Make sure that we have enough space to read all the cbits.
		 * idx points to the first cbit, which could also potentially be
		 * over the length of the buffer. This is why we subtract one
		 * from idx when doing the calculation.
		 */
		if (idx - 1 + ncbits >= len) {
			return (ATR_CODE_OVERRUN);
		}

		ASSERT3U(Ti, !=, 0);

		/*
		 * At the moment we opt to ignore reserved protocols.
		 */
		atp->atrti_protocol = prot;
		atp->atrti_ti_val = Ti;
		atp->atrti_td_idx = idx - 1;

		if (cbits & ATR_TA_MASK) {
			atp->atrti_flags |= ATR_TI_HAVE_TA;
			atp->atrti_ta = buf[idx];
			idx++;
		}

		if (cbits & ATR_TB_MASK) {
			atp->atrti_flags |= ATR_TI_HAVE_TB;
			atp->atrti_tb = buf[idx];
			idx++;
		}

		if (cbits & ATR_TC_MASK) {
			atp->atrti_flags |= ATR_TI_HAVE_TC;
			atp->atrti_tc = buf[idx];
			idx++;
		}

		if (cbits & ATR_TD_MASK) {
			atp->atrti_flags |= ATR_TI_HAVE_TD;
			atp->atrti_td = buf[idx];
			cbits = ATR_TD_NBITS(buf[idx]);
			prot = ATR_TD_PROT(buf[idx]);
			ncbits = atr_count_cbits(cbits);
			if (prot != 0)
				ncksum = 1;

			/*
			 * T=15 is not allowed in TD1 per 8.2.3.
			 */
			if (Ti == 1 && prot == 0xf)
				return (ATR_CODE_INVALID_TD1);

			idx++;
			/*
			 * Encountering TD means that once we take the next loop
			 * and we need to increment Ti.
			 */
			Ti++;
		} else {
			break;
		}
	}

	/*
	 * We've parsed all of the cbits. At this point, we should take into
	 * account all of the historical bits and potentially the checksum.
	 */
	if (idx - 1 + nhist + ncksum >= len) {
		return (ATR_CODE_OVERRUN);
	}

	if (idx + nhist + ncksum != len) {
		return (ATR_CODE_UNDERRUN);
	}

	if (nhist > 0) {
		data->atr_nhistoric = nhist;
		bcopy(&buf[idx], data->atr_historic, nhist);
	}

	if (ncksum > 0) {
		size_t i;
		uint8_t val;

		/*
		 * Per ISO/IEC 7816-3:2006 Section 8.2.5 the checksum is all
		 * bytes excluding TS. Therefore, we must start at byte 1.
		 */
		for (val = 0, i = 1; i < len; i++) {
			val ^= buf[i];
		}

		if (val != ATR_CKSUM_TARGET) {
			return (ATR_CODE_CHECKSUM_ERROR);
		}
		data->atr_flags |= ATR_F_HAS_CHECKSUM;
		data->atr_cksum = buf[len - 1];
	}

	data->atr_flags |= ATR_F_VALID;
	return (ATR_CODE_OK);
}

uint8_t
atr_fi_default_index(void)
{
	return (ATR_FI_DEFAULT_INDEX);
}

uint8_t
atr_di_default_index(void)
{
	return (ATR_DI_DEFAULT_INDEX);
}

/*
 * Parse the data to determine which protocols are supported in this atr data.
 * Based on this, users can come and ask us to fill in protocol information.
 */
atr_protocol_t
atr_supported_protocols(atr_data_t *data)
{
	uint_t i;
	atr_protocol_t prot;

	if ((data->atr_flags & ATR_F_VALID) == 0)
		return (ATR_P_NONE);

	/*
	 * Based on 8.2.3 of ISO/IEC 7816-3:2006, if TD1 is present, then that
	 * indicates the first protocol. However, if it is not present, then
	 * that implies that T=0 is the only supported protocol. Otherwise, all
	 * protocols are referenced in ascending order. The first entry in
	 * atr_ti refers to data from T0, so the protocol in the second entry
	 * would have the TD1 data.
	 */
	if (data->atr_nti < 2) {
		return (ATR_P_T0);
	}

	prot = ATR_P_NONE;
	for (i = 0; i < data->atr_nti; i++) {
		switch (data->atr_ti[i].atrti_protocol) {
		case ATR_PROTOCOL_T0:
			prot |= ATR_P_T0;
			break;
		case ATR_PROTOCOL_T1:
			prot |= ATR_P_T1;
			break;
		default:
			/*
			 * T=15 is not a protocol, and all other protocol values
			 * are currently reserved for future use.
			 */
			continue;
		}
	}

	/*
	 * It's possible we've found nothing specific in the above loop (for
	 * example, only T=15 global bits were found). In that case, the card
	 * defaults to T=0.
	 */
	if (prot == ATR_P_NONE)
		prot = ATR_P_T0;

	return (prot);
}

boolean_t
atr_params_negotiable(atr_data_t *data)
{
	/* If for some reason we're called with invalid data, assume it's not */
	if ((data->atr_flags & ATR_F_VALID) == 0)
		return (B_FALSE);


	/*
	 * Whether or not we're negotiable is in the second global page, so atr
	 * index 1. If TA2 is missing, then the card always is negotiable.
	 */
	if (data->atr_nti < 2 ||
	    (data->atr_ti[1].atrti_flags & ATR_TI_HAVE_TA) == 0) {
		return (B_TRUE);
	}

	if (ATR_TA2_CANCHANGE(data->atr_ti[1].atrti_ta)) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

atr_protocol_t
atr_default_protocol(atr_data_t *data)
{
	uint8_t prot;

	if ((data->atr_flags & ATR_F_VALID) == 0)
		return (ATR_P_NONE);
	/*
	 * If we don't have an TA2 byte, then the system defaults to T=0.
	 */
	if (data->atr_nti < 2) {
		return (ATR_P_T0);
	}

	/*
	 * If TA2 is present, then it encodes the default protocol. Otherwise,
	 * we have to grab the protocol value from TD1, which is called the
	 * 'first offered protocol'.
	 */
	if ((data->atr_ti[1].atrti_flags & ATR_TI_HAVE_TA) != 0) {
		prot = ATR_TA2_PROTOCOL(data->atr_ti[1].atrti_ta);
	} else {
		prot = data->atr_ti[1].atrti_protocol;
	}

	switch (prot) {
	case ATR_PROTOCOL_T0:
		return (ATR_P_T0);
	case ATR_PROTOCOL_T1:
		return (ATR_P_T1);
	default:
		return (ATR_P_NONE);
	}
}

uint8_t
atr_fi_index(atr_data_t *data)
{
	if (data->atr_nti < 1) {
		return (ATR_FI_DEFAULT_INDEX);
	}

	/*
	 * If TA is specified, it is present in TA1. TA2 may override its
	 * presence, so if it is here, check that first to determine whether or
	 * not we should check TA1.
	 */
	if (data->atr_nti >= 2 &&
	    (data->atr_ti[1].atrti_flags & ATR_TI_HAVE_TA) != 0) {
		if (!ATR_TA2_HONORTA1(data->atr_ti[1].atrti_ta)) {
			return (ATR_FI_DEFAULT_INDEX);
		}
	}

	if ((data->atr_ti[0].atrti_flags & ATR_TI_HAVE_TA) != 0) {
		return (ATR_TA1_FTABLE(data->atr_ti[0].atrti_ta));
	}

	return (ATR_FI_DEFAULT_INDEX);
}

uint8_t
atr_di_index(atr_data_t *data)
{
	if (data->atr_nti < 1) {
		return (ATR_DI_DEFAULT_INDEX);
	}

	/*
	 * If TA is specified, it is present in TA1. TA2 may override its
	 * presence, so if it is here, check that first to determine whether or
	 * not we should check TA1.
	 */
	if (data->atr_nti >= 2 &&
	    (data->atr_ti[1].atrti_flags & ATR_TI_HAVE_TA) != 0) {
		if (!ATR_TA2_HONORTA1(data->atr_ti[1].atrti_ta)) {
			return (ATR_DI_DEFAULT_INDEX);
		}
	}

	if ((data->atr_ti[0].atrti_flags & ATR_TI_HAVE_TA) != 0) {
		return (ATR_TA1_DITABLE(data->atr_ti[0].atrti_ta));
	}

	return (ATR_DI_DEFAULT_INDEX);
}

atr_convention_t
atr_convention(atr_data_t *data)
{
	if ((data->atr_flags & ATR_F_USES_DIRECT) != 0) {
		return (ATR_CONVENTION_DIRECT);
	}
	return (ATR_CONVENTION_INVERSE);
}

uint8_t
atr_extra_guardtime(atr_data_t *data)
{
	if ((data->atr_flags & ATR_F_VALID) == 0)
		return (ATR_EXTRA_GUARDTIME_DEFAULT);

	if (data->atr_nti >= 1 &&
	    (data->atr_ti[0].atrti_flags & ATR_TI_HAVE_TC) != 0) {
		return (data->atr_ti[0].atrti_tc);
	}

	return (ATR_EXTRA_GUARDTIME_DEFAULT);
}

uint8_t
atr_t0_wi(atr_data_t *data)
{
	if ((data->atr_flags & ATR_F_VALID) == 0)
		return (ATR_T0_WI_DEFAULT);

	/*
	 * This is stored in the optional global byte in TC2; however, it only
	 * applies to T=0.
	 */
	if (data->atr_nti >= 2 &&
	    data->atr_ti[1].atrti_protocol == ATR_PROTOCOL_T0 &&
	    (data->atr_ti[1].atrti_flags & ATR_TI_HAVE_TC) != 0) {
		return (data->atr_ti[1].atrti_tc);
	}

	return (ATR_T0_WI_DEFAULT);
}

uint8_t
atr_t1_cwi(atr_data_t *data)
{
	uint8_t i;

	if (data->atr_nti <= 2) {
		return (ATR_T1_CWI_DEFAULT);
	}

	for (i = 2; i < data->atr_nti; i++) {
		if (data->atr_ti[i].atrti_protocol == ATR_PROTOCOL_T1) {
			if ((data->atr_ti[i].atrti_flags & ATR_TI_HAVE_TB) !=
			    0) {
				uint8_t tb = data->atr_ti[i].atrti_tb;
				return (ATR_T1_TB0_CWI(tb));
			}

			return (ATR_T1_CWI_DEFAULT);
		}
	}

	return (ATR_T1_CWI_DEFAULT);
}

atr_clock_stop_t
atr_clock_stop(atr_data_t *data)
{
	uint8_t i;

	for (i = 0; i < data->atr_nti; i++) {
		if (data->atr_ti[i].atrti_protocol == ATR_PROTOCOL_T15) {
			if ((data->atr_ti[i].atrti_flags & ATR_TI_HAVE_TA) !=
			    0) {
				uint8_t ta = data->atr_ti[i].atrti_ta;
				return (ATR_T15_TA0_CLOCK(ta));
			}

			return (ATR_CLOCK_STOP_NONE);
		}
	}

	return (ATR_CLOCK_STOP_NONE);
}

atr_t1_checksum_t
atr_t1_checksum(atr_data_t *data)
{
	uint8_t i;

	if (data->atr_nti <= 2) {
		return (ATR_T1_CHECKSUM_DEFAULT);
	}

	for (i = 2; i < data->atr_nti; i++) {
		if (data->atr_ti[i].atrti_protocol == ATR_PROTOCOL_T1) {
			if ((data->atr_ti[i].atrti_flags & ATR_TI_HAVE_TC) !=
			    0) {
				if (ATR_T1_TC0_CRC(data->atr_ti[i].atrti_tc)) {
					return (ATR_T1_CHECKSUM_CRC);
				} else {
					return (ATR_T1_CHECKSUM_LRC);
				}
			}

			return (ATR_T1_CHECKSUM_DEFAULT);
		}
	}

	return (ATR_T1_CHECKSUM_DEFAULT);

}

uint8_t
atr_t1_bwi(atr_data_t *data)
{
	uint8_t i;

	if (data->atr_nti <= 2) {
		return (ATR_T1_BWI_DEFAULT);
	}

	for (i = 2; i < data->atr_nti; i++) {
		if (data->atr_ti[i].atrti_protocol == ATR_PROTOCOL_T1) {
			if ((data->atr_ti[i].atrti_flags & ATR_TI_HAVE_TB) !=
			    0) {
				uint8_t tb = data->atr_ti[i].atrti_tb;
				return (ATR_T1_TB0_BWI(tb));
			}

			return (ATR_T1_BWI_DEFAULT);
		}
	}

	return (ATR_T1_BWI_DEFAULT);
}

uint8_t
atr_t1_ifsc(atr_data_t *data)
{
	uint8_t i;

	if (data->atr_nti <= 2) {
		return (ATR_T1_IFSC_DEFAULT);
	}

	for (i = 2; i < data->atr_nti; i++) {
		if (data->atr_ti[i].atrti_protocol == ATR_PROTOCOL_T1) {
			if ((data->atr_ti[i].atrti_flags & ATR_TI_HAVE_TA) !=
			    0) {
				return (data->atr_ti[i].atrti_ta);
			}

			return (ATR_T1_IFSC_DEFAULT);
		}
	}

	return (ATR_T1_IFSC_DEFAULT);
}

/*
 * Attempt to determine which set of data rates we should be able to use for a
 * given class of protocol. Here we want to do the calculation based on the CCID
 * specification, section 9.4.x. To use these higher rates we need:
 *
 * + Reader's data rate > frequency * Di / Fi.
 *
 * To determine which rate and frequency we use, we look at the reader's
 * features. If the reader supports both the Automatic baud rate and automatic
 * ICC clock frequency change, then we use the _maximum_ rate. Otherwise we will
 * indicate that we can use the ATR's properties, but will require changing the
 * default data rate.
 *
 * Now, some ICC devices are not negotiable. In those cases, we'll see if we can
 * fit it in with either the default or maximum data rates. If not, then we'll
 * not be able to support this card.
 *
 * There are two wrinkles that exist in this. The first is supported frequencies
 * and data rates. If there are no additional data rates supported, then all of
 * the data rates between the default and max are supported. If not, then only
 * those specified in the data rates array are supported.
 *
 * The second hurdle is that we need to do this division and try and avoid the
 * pitfalls of floating point arithmetic, as floating point is not allowed in
 * the kernel (and this is shared). Importantly that means only integers are
 * allowed here.
 */
atr_data_rate_choice_t
atr_data_rate(atr_data_t *data, ccid_class_descr_t *class, uint32_t *rates,
    uint_t nrates, uint32_t *dataratep)
{
	uint_t nfeats = CCID_CLASS_F_AUTO_ICC_CLOCK | CCID_CLASS_F_AUTO_BAUD;
	uint8_t di, fi;
	uint_t dival, fival;
	boolean_t autospeed, negotiable, exprates;
	uint64_t maxval, defval;

	if ((data->atr_flags & ATR_F_VALID) == 0)
		return (ATR_RATE_UNSUPPORTED);

	di = atr_di_index(data);
	fi = atr_fi_index(data);
	dival = atr_di_index_to_value(di);
	fival = atr_fi_index_to_value(fi);
	autospeed = (class->ccd_dwFeatures & nfeats) == nfeats;
	exprates = class->ccd_bNumDataRatesSupported != 0;
	negotiable = atr_params_negotiable(data);

	/*
	 * We don't support cards with fixed rates at this time as it's not
	 * clear what that rate should be. If it's negotiable, we'll let them
	 * run at the default. Otherwise, we have to fail the request until
	 * we implement the logic to search their data rates.
	 */
	if (exprates) {
		if (negotiable) {
			return (ATR_RATE_USEDEFAULT);
		}
		return (ATR_RATE_UNSUPPORTED);
	}

	/*
	 * This indicates that the card gave us values that were reserved for
	 * future use. If we could negotiate it, then just stick with the
	 * default paramters. Otherwise, return that we can't support this ICC.
	 */
	if (dival == 0 || fival == 0) {
		if (negotiable)
			return (ATR_RATE_USEDEFAULT);
		return (ATR_RATE_UNSUPPORTED);
	}

	/*
	 * Calculate the maximum and default values.
	 */
	maxval = class->ccd_dwMaximumClock * 1000;
	maxval *= dival;
	maxval /= fival;

	defval = class->ccd_dwDefaultClock * 1000;
	defval *= dival;
	defval /= fival;

	/*
	 * We're allowed any set of data rates between the default and the
	 * maximum. Check if the maximum data rate will work for either the
	 * default or maximum clock. If so, then we can use the cards rates.
	 *
	 * To account for the fact that we may have had a fractional value,
	 * we require a strict greater than comparison.
	 */
	if ((uint64_t)class->ccd_dwMaxDataRate > maxval ||
	    (uint64_t)class->ccd_dwMaxDataRate > defval) {
		if (autospeed) {
			return (ATR_RATE_USEATR);
		}
	}

	/*
	 * If the CCID reader can't handle the ICC's proposed rates, then fall
	 * back to the defaults if we're allowed to negotiate. Otherwise, we're
	 * not able to use this ICC.
	 */
	if (negotiable) {
		return (ATR_RATE_USEDEFAULT);
	}

	return (ATR_RATE_UNSUPPORTED);
}

void
atr_data_reset(atr_data_t *data)
{
	bzero(data, sizeof (*data));
}

#ifdef	_KERNEL
atr_data_t *
atr_data_alloc(void)
{
	return (kmem_zalloc(sizeof (atr_data_t), KM_SLEEP));
}

void
atr_data_free(atr_data_t *data)
{
	kmem_free(data, sizeof (atr_data_t));
}

/*
 * Make sure that the response we got from the ICC is valid. It must pass
 * checksum and have the PPSS value set correctly. The protocol must match
 * what we requested; however, the PPS1-3 bits are a bit different. They may
 * only be set in the response if we set them in the request. However, they
 * do not have to be set in the response.
 */
boolean_t
atr_pps_valid(void *reqbuf, size_t reqlen, void *respbuf, size_t resplen)
{
	uint8_t val, i, reqidx, respidx;
	uint8_t *req = reqbuf, *resp = respbuf;

	if (resplen > PPS_LEN_MAX || resplen < PPS_LEN_MIN)
		return (B_FALSE);

	/*
	 * Before we validate the data, make sure the checksum is valid.
	 */
	for (i = 0, val = 0; i < resplen; i++) {
		val ^= resp[i];
	}

	/* Checksum failure */
	if (val != 0) {
		return (B_FALSE);
	}

	/*
	 * We should always have PPSS echoed back as we set it.
	 */
	if (resp[PPS_PPSS_INDEX] != PPS_PPSS_VAL) {
		return (B_FALSE);
	}

	/*
	 * Go through and make sure the number of bytes present makes sense for
	 * the number of bits set in PPS1.
	 */
	val = PPS_LEN_MIN;
	if (resp[PPS_PPS0_INDEX] & PPS_PPS0_PPS1)
		val++;
	if (resp[PPS_PPS0_INDEX] & PPS_PPS0_PPS2)
		val++;
	if (resp[PPS_PPS0_INDEX] & PPS_PPS0_PPS3)
		val++;
	if (val != resplen)
		return (B_FALSE);

	/*
	 * Now we've finally verified that the response is syntactically valid.
	 * We must go through and make sure that it is semantically valid.
	 */
	if (PPS_PPS0_PROT(req[PPS_PPS0_INDEX]) !=
	    PPS_PPS0_PROT(resp[PPS_PPS0_INDEX])) {
		return (B_FALSE);
	}

	/*
	 * When checking the PPS bit and extensions, we first check in the
	 * response as a bit in the request is allowed to not be in the
	 * response. But not the opposite way around. We also have to keep track
	 * of the fact that the index for values will vary.
	 */
	reqidx = respidx = PPS_PPS0_INDEX + 1;
	if ((resp[PPS_PPS0_INDEX] & PPS_PPS0_PPS1) != 0) {
		if ((req[PPS_PPS0_INDEX] & PPS_PPS0_PPS1) == 0) {
			return (B_FALSE);
		}

		if (req[reqidx] != resp[respidx]) {
			return (B_FALSE);
		}

		reqidx++;
		respidx++;
	} else if ((req[PPS_PPS0_INDEX] & PPS_PPS0_PPS1) != 0) {
		reqidx++;
	}

	if ((resp[PPS_PPS0_INDEX] & PPS_PPS0_PPS2) != 0) {
		if ((req[PPS_PPS0_INDEX] & PPS_PPS0_PPS2) == 0) {
			return (B_FALSE);
		}

		if (req[reqidx] != resp[respidx]) {
			return (B_FALSE);
		}

		reqidx++;
		respidx++;
	} else if ((req[PPS_PPS0_INDEX] & PPS_PPS0_PPS2) != 0) {
		reqidx++;
	}

	if ((resp[PPS_PPS0_INDEX] & PPS_PPS0_PPS3) != 0) {
		/*
		 * At this time, we never specify PPS3 in a request. Therefore
		 * if it is present in the response, treat this as an invalid
		 * request.
		 */
		return (B_FALSE);
	}

	return (B_TRUE);
}

uint_t
atr_pps_generate(uint8_t *buf, size_t buflen, atr_protocol_t prot,
    boolean_t pps1, uint8_t fi, uint8_t di, boolean_t pps2, uint8_t spu)
{
	uint8_t protval, cksum, i;
	uint_t len = 0;

	if (buflen < PPS_BUFFER_MAX)
		return (0);

	buf[PPS_PPSS_INDEX] = PPS_PPSS_VAL;
	switch (prot) {
	case ATR_P_T0:
		protval = 0;
		break;
	case ATR_P_T1:
		protval = 1;
		break;
	default:
		return (0);
	}

	buf[PPS_PPS0_INDEX] = PPS_PPS0_PROT(protval);
	len = 2;
	if (pps1) {
		buf[PPS_PPS0_INDEX] |= PPS_PPS0_PPS1;
		buf[len++] = PPS_PPS1_SETVAL(fi, di);
	}

	if (pps2) {
		buf[PPS_PPS0_INDEX] |= PPS_PPS0_PPS2;
		buf[len++] = spu;
	}

	/*
	 * The checksum must xor to zero.
	 */
	for (i = 0, cksum = 0; i < len; i++) {
		cksum ^= buf[i];
	}
	buf[len++] = cksum;
	return (len);
}

/*
 * The caller of this wants to know if the Fi/Di values that they proposed were
 * accepted. The caller must have already called atr_pps_valid(). At this point,
 * we can say that the value was accepted if the PPS1 bit is set.
 */
boolean_t
atr_pps_fidi_accepted(void *respbuf, size_t len)
{
	uint8_t *resp = respbuf;
	return ((resp[PPS_PPS0_INDEX] & PPS_PPS0_PPS1) != 0);
}

#else	/* !_KERNEL */
atr_data_t *
atr_data_alloc(void)
{
	return (calloc(1, sizeof (atr_data_t)));
}

void
atr_data_free(atr_data_t *data)
{
	if (data == NULL)
		return;
	free(data);
}

/*
 * This table maps the bit values for Fi from 7816-3:2006 section 8.3 Table 9.
 * The table is up to 6 bits wide. Entries not present are RFU. We use NULL as a
 * sentinel to indicate that.
 */
static const char *atr_voltage_table[64] = {
	NULL,			/* 00 0000 */
	"5V",			/* 00 0001 */
	"3V",			/* 00 0010 */
	"5V, 3V",		/* 00 0011 */
	"1.5V",			/* 00 0100 */
	NULL,			/* 00 0101 */
	"3V, 1.5V",		/* 00 0110 */
	"5V, 3V, 1.5V"		/* 00 0111 */
};

static void
atr_data_dump_ta(atr_ti_t *atp, FILE *out, uint_t level)
{
	uint8_t ta;

	if (!(atp->atrti_flags & ATR_TI_HAVE_TA)) {
		return;
	}

	ta = atp->atrti_ta;
	(void) fprintf(out, "   %c%c%c+-> TA%u 0x%02x",
	    atp->atrti_flags & ATR_TI_HAVE_TD ? '|' : ' ',
	    atp->atrti_flags & ATR_TI_HAVE_TC ? '|' : ' ',
	    atp->atrti_flags & ATR_TI_HAVE_TB ? '|' : ' ',
	    atp->atrti_ti_val, ta);
	switch (atp->atrti_ti_val) {
	case 1:
		(void) fprintf(out, "; Fi: %s, F(max): %s MHz, Di: %s",
		    atr_fi_table[ATR_TA1_FTABLE(ta)],
		    atr_fmax_table[ATR_TA1_FTABLE(ta)],
		    atr_di_table[ATR_TA1_DITABLE(ta)]);
		break;
	case 2:
		(void) fprintf(out, "; ICC in %s mode; %shonoring TA1; default "
		    "T=%u",
		    ATR_TA2_CANCHANGE(ta) ? "negotiable" : "specific",
		    ATR_TA2_HONORTA1(ta) ? "" : "not ",
		    ATR_TA2_PROTOCOL(ta));
		break;
	default:
		switch (atp->atrti_protocol) {
		case ATR_PROTOCOL_T1:
			if (level != 0)
				break;
			if (ta == 0 || ta == 0xff) {
				(void) fprintf(out, "; IFSC: RFU");
			} else {
				(void) fprintf(out, "; IFSC: %u", ta);
			}
			break;
		case ATR_PROTOCOL_T15:
			if (level != 0)
				break;
			(void) fprintf(out, "; Clock stop: %s, Supported "
			    "Voltage: %s",
			    atr_clock_table[ATR_T15_TA0_CLOCK(ta)],
			    atr_voltage_table[ATR_T15_TA0_VOLTAGE(ta)] != NULL ?
			    atr_voltage_table[ATR_T15_TA0_VOLTAGE(ta)] : "RFU");
			break;
		default:
			break;
		}
	}
	(void) fprintf(out, "\n");
}

static void
atr_data_dump_tb(atr_ti_t *atp, FILE *out, uint_t level)
{
	uint8_t tb;

	if (!(atp->atrti_flags & ATR_TI_HAVE_TB)) {
		return;
	}

	tb = atp->atrti_tb;
	(void) fprintf(out, "   %c%c+--> TB%u 0x%02x",
	    atp->atrti_flags & ATR_TI_HAVE_TD ? '|' : ' ',
	    atp->atrti_flags & ATR_TI_HAVE_TC ? '|' : ' ',
	    atp->atrti_ti_val, tb);
	switch (atp->atrti_ti_val) {
	case 1:
	case 2:
		(void) fprintf(out, "; deprecated");
		break;
	default:
		switch (atp->atrti_protocol) {
		case ATR_PROTOCOL_T1:
			if (level != 0)
				break;
			(void) fprintf(out, "; CWI: %u, BWI: %u\n",
			    ATR_T1_TB0_CWI(tb),
			    ATR_T1_TB0_BWI(tb));
			break;
		case ATR_PROTOCOL_T15:
			if (level != 0)
				break;
			(void) fprintf(out, "; SPU: %s", tb == 0 ? "not used" :
			    ATR_T15_TB0_SPU_STANDARD(tb) ? "standard" :
			    "proprietary");
			break;
		default:
			break;
		}
	}
	(void) fprintf(out, "\n");
}

static void
atr_data_dump_tc(atr_ti_t *atp, FILE *out, uint_t level)
{
	uint8_t tc;

	if (!(atp->atrti_flags & ATR_TI_HAVE_TC)) {
		return;
	}

	tc = atp->atrti_tc;
	(void) fprintf(out, "   %c+---> TC%u 0x%02x",
	    atp->atrti_flags & ATR_TI_HAVE_TD ? '|' : ' ',
	    atp->atrti_ti_val, tc);

	switch (atp->atrti_ti_val) {
	case 1:
		(void) fprintf(out, "; Extra Guard Time Integer: %u", tc);
		break;
	case 2:
		if (atp->atrti_protocol != ATR_PROTOCOL_T0) {
			(void) fprintf(out, "; illegal value -- only valid for "
			    "T=0");
		} else {
			(void) fprintf(out, "; Waiting Time Integer: %u", tc);
		}
		break;
	default:
		switch (atp->atrti_protocol) {
		case ATR_PROTOCOL_T1:
			if (level != 0)
				break;
			(void) fprintf(out, "; Error Detection Code: %s",
			    ATR_T1_TC0_CRC(tc) ? "CRC" : "LRC");
			break;
		default:
			break;
		}
	}
	(void) fprintf(out, "\n");
}

void
atr_data_hexdump(const uint8_t *buf, size_t nbytes, FILE *out)
{
	size_t i, j;

	/* Print out the header */
	(void) fprintf(out, "%*s    0", 4, "");
	for (i = 1; i < 16; i++) {
		if (i % 4 == 0 && i % 16 != 0) {
			(void) fprintf(out, " ");
		}

		(void) fprintf(out, "%2x", i);
	}
	(void) fprintf(out, "  0123456789abcdef\n");

	/* Print out data */
	for (i = 0; i < nbytes; i++) {

		if (i % 16 == 0) {
			(void) fprintf(out, "%04x:  ", i);
		}

		if (i % 4 == 0 && i % 16 != 0) {
			(void) fprintf(out, " ");
		}

		(void) fprintf(out, "%02x", buf[i]);

		if (i % 16 == 15 || i + 1 == nbytes) {
			for (j = (i % 16) + 1; j < 16; j++) {
				if (j % 4 == 0 && j % 16 != 0) {
					(void) fprintf(out, " ");
				}

				(void) fprintf(out, "  ");
			}

			(void) fprintf(out, "  ");
			for (j = i - (i % 16); j <= i; j++) {
				(void) fprintf(out, "%c",
				    isprint(buf[j]) ? buf[j] : '.');
			}
			(void) printf("\n");
		}
	}
}

static void
atr_data_hexdump_historical(atr_data_t *data, FILE *out)
{
	(void) fprintf(out, "Dumping raw historical bytes\n");

	atr_data_hexdump(data->atr_historic, data->atr_nhistoric, out);
}

static void
atr_data_dump_historical(atr_data_t *data, FILE *out)
{
	uint8_t cat;

	(void) fprintf(out, "Historic Data: %u bytes", data->atr_nhistoric);
	if (data->atr_nhistoric == 0) {
		(void) fprintf(out, "\n");
		return;
	}

	cat = data->atr_historic[0];
	(void) fprintf(out, "; format (0x%02x) ", cat);
	if (cat == ATR_HIST_CAT_MAND_STATUS) {
		(void) fprintf(out, "card status, not shown");
	} else if (cat == ATR_HIST_CAT_TLV_STATUS) {
		(void) fprintf(out, "COMPACT-TLV, not shown");
	} else if (cat >= ATR_HIST_CAT_RFU_MIN && cat <= ATR_HIST_CAT_RFU_MAX) {
		(void) fprintf(out, "reserved\n");
		atr_data_hexdump_historical(data, out);
		return;
	} else {
		(void) fprintf(out, "proprietary\n");
		atr_data_hexdump_historical(data, out);
		return;
	}
}

void
atr_data_dump(atr_data_t *data, FILE *out)
{
	uint8_t i, level;
	if ((data->atr_flags & ATR_F_VALID) == 0)
		return;

	(void) fprintf(out, "TS  0x%02u - ", data->atr_raw[0]);
	if (data->atr_flags & ATR_F_USES_DIRECT) {
		(void) fprintf(out, "direct convention\n");
	} else {
		(void) fprintf(out, "inverse convention\n");
	}

	level = 0;
	for (i = 0; i < data->atr_nti; i++) {
		atr_ti_t *atp = &data->atr_ti[i];

		/*
		 * Various protocols may appear multiple times, indicating
		 * different sets of bits each time. When dealing with T0 and
		 * TD1, the protocol doesn't matter. Otherwise if we have the
		 * same value, we should increment this.
		 */
		if (i <= 2) {
			level = 0;
		} else if (atp->atrti_protocol ==
		    data->atr_ti[i - 1].atrti_protocol) {
			level++;
		} else {
			level = 0;
		}

		if (i == 0) {
			(void) fprintf(out, "T0  ");
		} else {
			(void) fprintf(out, "TD%u ", i);
		}
		(void) fprintf(out, "0x%02x\n",
		    data->atr_raw[atp->atrti_td_idx]);
		(void) fprintf(out, "      |+-> ");
		if (i == 0) {
			(void) fprintf(out, "%u historical bytes\n",
			    data->atr_nhistoric);
		} else {
			(void) fprintf(out, "protocol T=%u\n",
			    atp->atrti_protocol);
		}
		(void) fprintf(out, "      v\n");
		(void) fprintf(out, " 0r%u%u%u%u\n",
		    atp->atrti_flags & ATR_TI_HAVE_TD ? 1 : 0,
		    atp->atrti_flags & ATR_TI_HAVE_TC ? 1 : 0,
		    atp->atrti_flags & ATR_TI_HAVE_TB ? 1 : 0,
		    atp->atrti_flags & ATR_TI_HAVE_TA ? 1 : 0);

		atr_data_dump_ta(atp, out, level);
		atr_data_dump_tb(atp, out, level);
		atr_data_dump_tc(atp, out, level);
		if (atp->atrti_flags & ATR_TI_HAVE_TD) {
			(void) fprintf(out, "   v\n");
		}
	}

	atr_data_dump_historical(data, out);

	if (data->atr_flags & ATR_F_HAS_CHECKSUM) {
		(void) fprintf(out, "TCK  0x%02x\n", data->atr_cksum);
	} else {
		(void) fprintf(out, "TCK  ----; Checksum not present\n");
	}

}
#endif	/* _KERNEL */
