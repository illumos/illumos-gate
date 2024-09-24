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

#ifndef _AMDZEN_CLIENT_H
#define	_AMDZEN_CLIENT_H

/*
 * This header provides client routines to clients of the amdzen nexus driver.
 */

#include <sys/types.h>
#include <sys/amdzen/df.h>
#include <sys/amdzen/smn.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This struct encodes enough information to later be used to compose and
 * decompose a fabric ID and component ID. A fabric ID is broken into its node
 * and component IDs and then a node ID is further decomposed into a socket and
 * die ID.
 */
typedef struct {
	uint32_t	dfd_sock_mask;
	uint32_t	dfd_die_mask;
	uint32_t	dfd_node_mask;
	uint32_t	dfd_comp_mask;
	uint8_t		dfd_sock_shift;
	uint8_t		dfd_die_shift;
	uint8_t		dfd_node_shift;
	uint8_t		dfd_comp_shift;
} df_fabric_decomp_t;

/*
 * This struct is similar to the above, but describes how an APIC ID is broken
 * down into its logical pieces. These are not the same as those above and
 * cannot be assumed to be. The mask is present when decomposing the ID and
 * should be applied before the shift.
 */
typedef struct {
	uint32_t	aad_sock_mask;
	uint32_t	aad_die_mask;
	uint32_t	aad_ccd_mask;
	uint32_t	aad_ccx_mask;
	uint32_t	aad_core_mask;
	uint32_t	aad_thread_mask;
	uint8_t		aad_sock_shift;
	uint8_t		aad_die_shift;
	uint8_t		aad_ccd_shift;
	uint8_t		aad_ccx_shift;
	uint8_t		aad_core_shift;
	uint8_t		aad_thread_shift;
} amdzen_apic_decomp_t;

/*
 * The following routines are used for Fabric and APIC ID decomposition and are
 * suitable either for kernel or userland use. They are found in
 * usr/src/common/zen/zen_fabric_utils.c.
 */
extern boolean_t zen_fabric_id_valid_fabid(const df_fabric_decomp_t *,
    const uint32_t);
extern boolean_t zen_fabric_id_valid_parts(const df_fabric_decomp_t *,
    const uint32_t, const uint32_t, const uint32_t);
extern void zen_fabric_id_decompose(const df_fabric_decomp_t *, const uint32_t,
    uint32_t *, uint32_t *, uint32_t *);
extern void zen_fabric_id_compose(const df_fabric_decomp_t *, const uint32_t,
    const uint32_t, const uint32_t, uint32_t *);

extern void zen_apic_id_compose(const amdzen_apic_decomp_t *, const uint32_t,
    const uint32_t, const uint32_t, const uint32_t, const uint32_t,
    const uint32_t, uint32_t *);

#ifdef	_KERNEL

extern uint_t amdzen_c_df_count(void);
extern df_rev_t amdzen_c_df_rev(void);
extern int amdzen_c_df_fabric_decomp(df_fabric_decomp_t *);

/*
 * SMN and DF access routines.
 */
extern int amdzen_c_smn_read(uint_t, const smn_reg_t, uint32_t *);
extern int amdzen_c_smn_write(uint_t, const smn_reg_t, const uint32_t);
extern int amdzen_c_df_read32(uint_t, uint8_t, const df_reg_def_t, uint32_t *);
extern int amdzen_c_df_read64(uint_t, uint8_t, const df_reg_def_t, uint64_t *);

extern int amdzen_c_df_read32_bcast(uint_t, const df_reg_def_t, uint32_t *);

/*
 * The following are logical types that we can iterate over. Note, that these
 * are a combination of a DF type and subtype. This is used to smooth over the
 * differences between different DF revisions and how they indicate these types.
 */
typedef enum {
	/*
	 * Iterate over only DDR memory controllers.
	 */
	ZEN_DF_TYPE_CS_UMC,
	/*
	 * Iterate only over CPU based CCMs.
	 */
	ZEN_DF_TYPE_CCM_CPU
} zen_df_type_t;

typedef int (*amdzen_c_iter_f)(uint_t, uint32_t, uint32_t, void *);
extern int amdzen_c_df_iter(uint_t, zen_df_type_t, amdzen_c_iter_f, void *);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _AMDZEN_CLIENT_H */
