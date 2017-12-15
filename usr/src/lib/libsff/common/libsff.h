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

#ifndef _LIBSFF_H
#define	_LIBSFF_H

/*
 * Parse SFF structures and values and return an nvlist_t of keys. This library
 * is private and subject to change and break compat at any time.
 */

#include <libnvpair.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int libsff_parse(const uint8_t *, size_t, uint_t, nvlist_t **);

/*
 * Supported Keys in the resulting nvlist. Not every key will be present in
 * every SFF compatible device.
 */
#define	LIBSFF_KEY_IDENTIFIER	"Identifier"		/* String */
#define	LIBSFF_KEY_CONNECTOR	"Connector"		/* String */
#define	LIBSFF_KEY_ENCODING	"Encoding"		/* String */
#define	LIBSFF_KEY_VENDOR	"Vendor"		/* String */
#define	LIBSFF_KEY_OUI		"OUI"			/* Byte Array [3] */
#define	LIBSFF_KEY_PART		"Part Number"		/* String */
#define	LIBSFF_KEY_REVISION	"Revision"		/* String */
#define	LIBSFF_KEY_SERIAL	"Serial Number"		/* String */
#define	LIBSFF_KEY_DATECODE	"Date Code"		/* String */
#define	LIBSFF_KEY_BR_NOMINAL	"BR, nominal"		/* String */
#define	LIBSFF_KEY_BR_MAX	"BR, maximum"		/* String */
#define	LIBSFF_KEY_BR_MIN	"BR, minimum"		/* String */
#define	LIBSFF_KEY_LENGTH_SMF_KM "Length SMF (km)"	/* String */
#define	LIBSFF_KEY_LENGTH_SMF	"Length SMF (m)"	/* String */
#define	LIBSFF_KEY_LENGTH_OM2	"Length 50um OM2"	/* String */
#define	LIBSFF_KEY_LENGTH_OM1	"Length 62.5um OM1"	/* String */
#define	LIBSFF_KEY_LENGTH_COPPER "Length Copper"	/* String */
#define	LIBSFF_KEY_LENGTH_OM3	"Length OM3"		/* String */
#define	LIBSFF_KEY_WAVELENGTH	"Laser Wavelength"	/* String */
#define	LIBSFF_KEY_WAVE_TOLERANCE "Wavelength Tolerance" /* String */
#define	LIBSFF_KEY_OPTIONS	"Options"		/* String Array */
#define	LIBSFF_KEY_COMPLIANCE_8472 "8472 Compliance"	/* String */
#define	LIBSFF_KEY_EXTENDED_OPTIONS "Extended Options"	/* String Array */
#define	LIBSFF_KEY_ENHANCED_OPTIONS "Enhanced Options"	/* String Array */
#define	LIBSFF_KEY_EXT_MOD_CODES "Extended Module Codes" /* String Array */
#define	LIBSFF_KEY_DIAG_MONITOR	"Diagnostic Monitoring"	/* String */
#define	LIBSFF_KEY_EXT_SPEC	"Extended Specification" /* String */
#define	LIBSFF_KEY_MAX_CASE_TEMP "Maximum Case Temperature" /* String */
#define	LIBSFF_KEY_ATTENUATE_2G	"Cable Attenuation at 2.5 GHz"	/* String */
#define	LIBSFF_KEY_ATTENUATE_5G	"Cable Attenuation at 5.0 GHz"	/* String */
#define	LIBSFF_KEY_ATTENUATE_7G	"Cable Attenuation at 7.0 GHz"	/* String */
#define	LIBSFF_KEY_ATTENUATE_12G "Cable Attenuation at 12.9 GHz" /* String */
#define	LIBSFF_KEY_TRAN_TECH	"Transmitter Technology"	/* String */

/*
 * Note, different revisions of the SFF standard have different compliance
 * values available. We try to use a common set of compliance keys when
 * possible, even if the values will be different. All entries here are String
 * Arrays.
 */
#define	LIBSFF_KEY_COMPLIANCE_10GBE	"10G+ Ethernet Compliance Codes"
#define	LIBSFF_KEY_COMPLIANCE_IB	"Infiniband Compliance Codes"
#define	LIBSFF_KEY_COMPLIANCE_ESCON	"ESCON Compliance Codes"
#define	LIBSFF_KEY_COMPLIANCE_SONET	"SONET Compliance Codes"
#define	LIBSFF_KEY_COMPLIANCE_GBE	"Ethernet Compliance Codes"
#define	LIBSFF_KEY_COMPLIANCE_FC_LEN	"Fibre Channel Link Lengths"
#define	LIBSFF_KEY_COMPLIANCE_FC_TECH	"Fibre Channel Technology"
#define	LIBSFF_KEY_COMPLIANCE_SFP	"SFP+ Cable Technology"
#define	LIBSFF_KEY_COMPLIANCE_FC_MEDIA	"Fibre Channel Transmission Media"
#define	LIBSFF_KEY_COMPLIANCE_FC_SPEED	"Fibre Channel Speed"
#define	LIBSFF_KEY_COMPLIANCE_SAS	"SAS Compliance Codes"
#define	LIBSFF_KEY_COMPLIANCE_ACTIVE	"Active Cable Specification Compliance"
#define	LIBSFF_KEY_COMPLIANCE_PASSIVE	"Passive Cable Specification Compliance"


/*
 * The following keys have meaning that varies based on the standard.
 */
#define	LIBSFF_KEY_8472_EXT_IDENTIFIER	"Extended Identifier"	/* uint8_t */

#ifdef __cplusplus
}
#endif

#endif /* _LIBSFF_H */
