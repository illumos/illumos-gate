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
 * Copyright 2024 Oxide Computer Company
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
extern void smbios_test_table_str_fini(smbios_test_table_t *);
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
extern boolean_t smbios_test_slot_mktable_34_nopeers(smbios_test_table_t *);
extern boolean_t smbios_test_slot_mktable_34_peers(smbios_test_table_t *);
extern boolean_t smbios_test_slot_mktable_35(smbios_test_table_t *);
extern boolean_t smbios_test_slot_verify(smbios_hdl_t *);
extern boolean_t smbios_test_slot_verify_34_nopeers(smbios_hdl_t *);
extern boolean_t smbios_test_slot_verify_34_peers(smbios_hdl_t *);
extern boolean_t smbios_test_slot_verify_34_overrun(smbios_hdl_t *);
extern boolean_t smbios_test_slot_verify_35(smbios_hdl_t *);

extern boolean_t smbios_test_badvers_mktable(smbios_test_table_t *);
extern boolean_t smbios_test_verify_badids(smbios_hdl_t *);

extern boolean_t smbios_test_memdevice_mktable_32(smbios_test_table_t *);
extern boolean_t smbios_test_memdevice_mktable_33(smbios_test_table_t *);
extern boolean_t smbios_test_memdevice_mktable_33ext(smbios_test_table_t *);
extern boolean_t smbios_test_memdevice_mktable_37(smbios_test_table_t *);
extern boolean_t smbios_test_memdevice_verify_32(smbios_hdl_t *);
extern boolean_t smbios_test_memdevice_verify_32_33(smbios_hdl_t *);
extern boolean_t smbios_test_memdevice_verify_32_37(smbios_hdl_t *);
extern boolean_t smbios_test_memdevice_verify_33(smbios_hdl_t *);
extern boolean_t smbios_test_memdevice_verify_33ext(smbios_hdl_t *);
extern boolean_t smbios_test_memdevice_verify_37(smbios_hdl_t *);

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

extern boolean_t smbios_test_strprop_mktable_invlen1(smbios_test_table_t *);
extern boolean_t smbios_test_strprop_mktable_invlen2(smbios_test_table_t *);
extern boolean_t smbios_test_strprop_mktable_badstr(smbios_test_table_t *);
extern boolean_t smbios_test_strprop_mktable_basic(smbios_test_table_t *);
extern boolean_t smbios_test_strprop_verify_invlen1(smbios_hdl_t *);
extern boolean_t smbios_test_strprop_verify_invlen2(smbios_hdl_t *);
extern boolean_t smbios_test_strprop_verify_badstr(smbios_hdl_t *);
extern boolean_t smbios_test_strprop_verify_badtype(smbios_hdl_t *);
extern boolean_t smbios_test_strprop_verify_basic(smbios_hdl_t *);

extern boolean_t smbios_test_fwinfo_mktable_invlen_base(smbios_test_table_t *);
extern boolean_t smbios_test_fwinfo_mktable_invlen_comps(smbios_test_table_t *);
extern boolean_t smbios_test_fwinfo_mktable_nocomps(smbios_test_table_t *);
extern boolean_t smbios_test_fwinfo_mktable_comps(smbios_test_table_t *);
extern boolean_t smbios_test_fwinfo_verify_invlen_base(smbios_hdl_t *);
extern boolean_t smbios_test_fwinfo_verify_invlen_comps(smbios_hdl_t *);
extern boolean_t smbios_test_fwinfo_verify_badtype(smbios_hdl_t *);
extern boolean_t smbios_test_fwinfo_verify_nocomps(smbios_hdl_t *);
extern boolean_t smbios_test_fwinfo_verify_comps(smbios_hdl_t *);

extern boolean_t smbios_test_verify_strings(smbios_hdl_t *);

extern boolean_t smbios_test_chassis_mktable_invlen_base(smbios_test_table_t *);
extern boolean_t smbios_test_chassis_mktable_base(smbios_test_table_t *);
extern boolean_t smbios_test_chassis_mktable_part(smbios_test_table_t *);
extern boolean_t smbios_test_chassis_mktable_comps(smbios_test_table_t *);
extern boolean_t smbios_test_chassis_mktable_sku(smbios_test_table_t *);
extern boolean_t smbios_test_chassis_mktable_sku_nocomps(smbios_test_table_t *);
extern boolean_t smbios_test_chassis_verify_invlen(smbios_hdl_t *);
extern boolean_t smbios_test_chassis_verify_base(smbios_hdl_t *);
extern boolean_t smbios_test_chassis_verify_comps(smbios_hdl_t *);
extern boolean_t smbios_test_chassis_verify_sku_nocomps(smbios_hdl_t *);
extern boolean_t smbios_test_chassis_verify_sku(smbios_hdl_t *);

extern boolean_t smbios_test_proc_mktable_25(smbios_test_table_t *);
extern boolean_t smbios_test_proc_mktable_36(smbios_test_table_t *);
extern boolean_t smbios_test_proc_mktable_38(smbios_test_table_t *);
extern boolean_t smbios_test_proc_verify_25(smbios_hdl_t *);
extern boolean_t smbios_test_proc_verify_36(smbios_hdl_t *);
extern boolean_t smbios_test_proc_verify_36_25(smbios_hdl_t *);
extern boolean_t smbios_test_proc_verify_38(smbios_hdl_t *);

extern boolean_t smbios_test_extmem_mktable_invlen_cs(smbios_test_table_t *);
extern boolean_t smbios_test_extmem_mktable_nocs(smbios_test_table_t *);
extern boolean_t smbios_test_extmem_mktable_cs(smbios_test_table_t *);
extern boolean_t smbios_test_extmem_verify_invlen_cs(smbios_hdl_t *);
extern boolean_t smbios_test_extmem_verify_nocs(smbios_hdl_t *);
extern boolean_t smbios_test_extmem_verify_cs(smbios_hdl_t *);

extern boolean_t smbios_test_addinfo_mktable_noent(smbios_test_table_t *);
extern boolean_t smbios_test_addinfo_mktable_ents(smbios_test_table_t *);
extern boolean_t smbios_test_addinfo_mktable_invlen_base(smbios_test_table_t *);
extern boolean_t smbios_test_addinfo_mktable_invlen_ent(smbios_test_table_t *);
extern boolean_t smbios_test_addinfo_mktable_invlen_multient(
	smbios_test_table_t *);
extern boolean_t smbios_test_addinfo_mktable_invlen_entdata(
	smbios_test_table_t *);
extern boolean_t smbios_test_addinfo_verify_noent(smbios_hdl_t *);
extern boolean_t smbios_test_addinfo_verify_ents(smbios_hdl_t *);
extern boolean_t smbios_test_addinfo_verify_invlen_base(smbios_hdl_t *);
extern boolean_t smbios_test_addinfo_verify_invlen_ent(smbios_hdl_t *);
extern boolean_t smbios_test_addinfo_verify_invlen_multient(smbios_hdl_t *);
extern boolean_t smbios_test_addinfo_verify_invlen_entdata(smbios_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SMBIOS_TEST_H */
