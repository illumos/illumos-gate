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

#ifndef _ATR_H
#define	_ATR_H

/*
 * Parse Answer-To-Reset values. This header file is private to illumos and
 * should not be shipped or used by applications.
 *
 * This is based on ISO/IEC 7816-3:2006. It has been designed such that if newer
 * revisions come out that define reserved values, they will be ignored until
 * this code is updated.
 */

#include <sys/types.h>
#include <sys/usb/clients/ccid/ccid.h>
#ifndef	_KERNEL
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The ATR must have at least 2 bytes and then may have up to 33 bytes.
 */
#define	ATR_LEN_MIN	2
#define	ATR_LEN_MAX	33

typedef enum atr_parsecode {
	ATR_CODE_OK	= 0,
	ATR_CODE_TOO_SHORT,
	ATR_CODE_TOO_LONG,
	ATR_CODE_INVALID_TS,
	ATR_CODE_OVERRUN,
	ATR_CODE_UNDERRUN,
	ATR_CODE_CHECKSUM_ERROR,
	ATR_CODE_INVALID_TD1
} atr_parsecode_t;

typedef enum atr_protocol {
	ATR_P_NONE	= 0,
	ATR_P_T0	= 1 << 0,
	ATR_P_T1	= 1 << 1
} atr_protocol_t;

typedef enum atr_convention {
	ATR_CONVENTION_DIRECT	= 0x00,
	ATR_CONVENTION_INVERSE	= 0x01
} atr_convention_t;

typedef enum atr_clock_stop {
	ATR_CLOCK_STOP_NONE	= 0x00,
	ATR_CLOCK_STOP_LOW	= 0x01,
	ATR_CLOCK_STOP_HI	= 0x02,
	ATR_CLOCK_STOP_BOTH	= 0x03
} atr_clock_stop_t;

typedef enum atr_data_rate_choice {
	/*
	 * Indicates that the reader cannot support the data rate needed for the
	 * ICC.
	 */
	ATR_RATE_UNSUPPORTED	= 0x00,
	/*
	 * Indicates that the reader supports the ICC present, but must run at
	 * the protocol's default rate (Di index = Fi index = 1)
	 */
	ATR_RATE_USEDEFAULT	= 0x01,
	/*
	 * The reader supports the Di/Fi values that the ICC proposed in its ATR
	 * and no action beyond setting the parameters of the reader is required
	 * (this may be automatic depending on the reader's dwFeatures).
	 */
	ATR_RATE_USEATR		= 0x02,
	/*
	 * The reader can use the features of the ATR specified. However, it
	 * must change the data rate or frequency that the card is running at to
	 * proceed.
	 */
	ATR_RATE_USEATR_SETRATE	= 0x03
} atr_data_rate_choice_t;

typedef enum atr_t1_checksum {
	ATR_T1_CHECKSUM_LRC	= 0x00,
	ATR_T1_CHECKSUM_CRC	= 0x01
} atr_t1_checksum_t;

typedef struct atr_data atr_data_t;

/*
 * Allocate and free ATR data.
 */
extern atr_data_t *atr_data_alloc(void);
extern void atr_data_free(atr_data_t *);

/*
 * Reset an allocated ATR data to be ready to parse something else.
 */
extern void atr_data_reset(atr_data_t *);

/*
 * Parse the ATR data into an opaque structure that organizes the data and
 * allows for various queries to be made on it later.
 */
extern atr_parsecode_t atr_parse(const uint8_t *, size_t, atr_data_t *data);
extern const char *atr_strerror(atr_parsecode_t);

/*
 * Get an eumeration of supported protocols in this ATR data. Note that if a
 * reserved protocol is encountered, we may not report it as we don't know of it
 * at this time.
 */
extern atr_protocol_t atr_supported_protocols(atr_data_t *);

/*
 * Based on the ATR determine what the default protocol is and whether or not it
 * supports negotiation. When a ICC is not negotiable, it will always start up
 * with a specific protocol and parameters based on the ATR and be ready to use.
 * Otherwise, the card will be in a negotiable mode and be set to a default set
 * of parameters.
 */
extern boolean_t atr_params_negotiable(atr_data_t *);
extern atr_protocol_t atr_default_protocol(atr_data_t *);

/*
 * Protocol default values.
 */
extern uint8_t atr_fi_default_index(void);
extern uint8_t atr_di_default_index(void);

/*
 * Obtain the table indexes that should be used by the device.
 */
extern uint8_t atr_fi_index(atr_data_t *);
extern uint8_t atr_di_index(atr_data_t *);
extern atr_convention_t atr_convention(atr_data_t *);
extern uint8_t atr_extra_guardtime(atr_data_t *);
extern uint8_t atr_t0_wi(atr_data_t *);
extern atr_t1_checksum_t atr_t1_checksum(atr_data_t *);
extern uint8_t atr_t1_bwi(atr_data_t *);
extern uint8_t atr_t1_cwi(atr_data_t *);
extern atr_clock_stop_t atr_clock_stop(atr_data_t *);
extern uint8_t atr_t1_ifsc(atr_data_t *);

/*
 * Use this function to determine what set of Di and Fi values should be used by
 * a reader, based on the parameters from the ATR and the reader's cclass.
 */
extern atr_data_rate_choice_t atr_data_rate(atr_data_t *, ccid_class_descr_t *,
    uint32_t *, uint_t, uint32_t *);

#ifndef	_KERNEL
extern void atr_data_hexdump(const uint8_t *, size_t, FILE *);
extern void atr_data_dump(atr_data_t *, FILE *);
#endif

/*
 * String and table index values.
 */
extern const char *atr_protocol_to_string(atr_protocol_t);
extern uint_t atr_fi_index_to_value(uint8_t);
extern const char *atr_fi_index_to_string(uint8_t);
extern const char *atr_fmax_index_to_string(uint8_t);
extern uint_t atr_di_index_to_value(uint8_t);
extern const char *atr_di_index_to_string(uint8_t);
extern const char *atr_clock_stop_to_string(atr_clock_stop_t);
extern const char *atr_convention_to_string(atr_convention_t);

/*
 * Functions for generating and testing PPS values. Before calling
 * atr_pps_fidi_accepted(), one must call atr_pps_valid().
 */
#define	PPS_BUFFER_MAX	6
extern uint_t atr_pps_generate(uint8_t *, size_t, atr_protocol_t, boolean_t,
    uint8_t, uint8_t, boolean_t, uint8_t);
extern boolean_t atr_pps_valid(void *, size_t, void *, size_t);
extern boolean_t atr_pps_fidi_accepted(void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _ATR_H */
