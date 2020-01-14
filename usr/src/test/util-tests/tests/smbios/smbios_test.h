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
 * Copyright 2019 Robert Mustacchi
 */

#ifndef _SMBIOS_TEST_H
#define	_SMBIOS_TEST_H

/*
 * Test framework for SMBIOS tests
 */

#include <smbios.h>
#include <sys/smbios.h>
#include <sys/smbios_impl.h>
#include <err.h>
#include <stdint.h>
#include <endian.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Number of bytes we allocate at a given time for an SMBIOS table.
 */
#define	SMBIOS_TEST_ALLOC_SIZE	1024

typedef struct smbios_test_table {
	smbios_entry_point_t	stt_type;
	void			*stt_data;
	size_t			stt_buflen;
	size_t			stt_offset;
	uint_t			stt_nents;
	uint_t			stt_version;
	uint_t			stt_nextid;
	smbios_entry_t		stt_entry;
} smbios_test_table_t;

/*
 * General Interfaces used to construct tables.
 */
extern smbios_test_table_t *smbios_test_table_init(smbios_entry_point_t,
    uint_t);
extern void smbios_test_table_append_raw(smbios_test_table_t *, const void *,
    size_t);
extern void smbios_test_table_append_string(smbios_test_table_t *,
    const char *);
extern uint16_t smbios_test_table_append(smbios_test_table_t *, const void *,
    size_t);
extern void smbios_test_table_append_eot(smbios_test_table_t *);

typedef boolean_t (*smbios_test_mktable_f)(smbios_test_table_t *);
typedef boolean_t (*smbios_test_verify_f)(smbios_hdl_t *);

typedef struct smbios_test {
	int			st_entry;
	int			st_tvers;
	int			st_libvers;
	smbios_test_mktable_f	st_mktable;
	boolean_t		st_canopen;
	smbios_test_verify_f	st_verify;
	const char		*st_desc;
} smbios_test_t;

/*
 * Test functions
 */
extern boolean_t smbios_test_slot_mktable(smbios_test_table_t *);
extern boolean_t smbios_test_slot_verify(smbios_hdl_t *);
extern boolean_t smbios_test_badvers_mktable(smbios_test_table_t *);

extern boolean_t smbios_test_memdevice_mktable_32(smbios_test_table_t *);
extern boolean_t smbios_test_memdevice_mktable_33(smbios_test_table_t *);
extern boolean_t smbios_test_memdevice_mktable_33ext(smbios_test_table_t *);
extern boolean_t smbios_test_memdevice_verify_32(smbios_hdl_t *);
extern boolean_t smbios_test_memdevice_verify_32_33(smbios_hdl_t *);
extern boolean_t smbios_test_memdevice_verify_33(smbios_hdl_t *);
extern boolean_t smbios_test_memdevice_verify_33ext(smbios_hdl_t *);

extern boolean_t smbios_test_pinfo_mktable_amd64(smbios_test_table_t *);
extern boolean_t smbios_test_pinfo_verify_amd64(smbios_hdl_t *);
extern boolean_t smbios_test_pinfo_mktable_riscv(smbios_test_table_t *);
extern boolean_t smbios_test_pinfo_verify_riscv(smbios_hdl_t *);
extern boolean_t smbios_test_pinfo_mktable_invlen1(smbios_test_table_t *);
extern boolean_t smbios_test_pinfo_mktable_invlen2(smbios_test_table_t *);
extern boolean_t smbios_test_pinfo_mktable_invlen3(smbios_test_table_t *);
extern boolean_t smbios_test_pinfo_mktable_invlen4(smbios_test_table_t *);
extern boolean_t smbios_test_pinfo_verify_invlen1(smbios_hdl_t *);
extern boolean_t smbios_test_pinfo_verify_invlen2(smbios_hdl_t *);
extern boolean_t smbios_test_pinfo_verify_invlen3(smbios_hdl_t *);
extern boolean_t smbios_test_pinfo_verify_invlen4(smbios_hdl_t *);
extern boolean_t smbios_test_pinfo_verify_badtype(smbios_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SMBIOS_TEST_H */
