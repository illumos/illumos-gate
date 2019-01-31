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
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * mdb dcmds for selected structures from
 * usr/src/uts/common/sys/crypto/spi.h
 *
 * Also the mdb module housekeeping
 */

#include <sys/mdb_modapi.h>
#include <sys/modctl.h>
#include <sys/crypto/api.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/impl.h>
#include "crypto_cmds.h"


const mdb_bitmask_t extf_flags[] = {
	{ "NIL", (ulong_t)-1, 0L },
	{ "CRYPTO_EXTF_RNG", CRYPTO_EXTF_RNG, CRYPTO_EXTF_RNG },
	{ "CRYPTO_EXTF_WRITE_PROTECTED", CRYPTO_EXTF_WRITE_PROTECTED,
		CRYPTO_EXTF_WRITE_PROTECTED },
	{ "CRYPTO_EXTF_LOGIN_REQUIRED", CRYPTO_EXTF_LOGIN_REQUIRED,
		CRYPTO_EXTF_LOGIN_REQUIRED },
	{ "CRYPTO_EXTF_USER_PIN_INITIALIZED", CRYPTO_EXTF_USER_PIN_INITIALIZED,
		CRYPTO_EXTF_USER_PIN_INITIALIZED },
	{ "CRYPTO_EXTF_CLOCK_ON_TOKEN", CRYPTO_EXTF_CLOCK_ON_TOKEN,
		CRYPTO_EXTF_CLOCK_ON_TOKEN },
	{ "CRYPTO_EXTF_PROTECTED_AUTHENTICATION_PATH",
		CRYPTO_EXTF_PROTECTED_AUTHENTICATION_PATH,
		CRYPTO_EXTF_PROTECTED_AUTHENTICATION_PATH },
	{ "CRYPTO_EXTF_DUAL_CRYPTO_OPERATIONS",
		CRYPTO_EXTF_DUAL_CRYPTO_OPERATIONS,
		CRYPTO_EXTF_DUAL_CRYPTO_OPERATIONS },
	{ "CRYPTO_EXTF_TOKEN_INITIALIZED", CRYPTO_EXTF_TOKEN_INITIALIZED,
		CRYPTO_EXTF_TOKEN_INITIALIZED },
	{ "CRYPTO_EXTF_USER_PIN_COUNT_LOW", CRYPTO_EXTF_USER_PIN_COUNT_LOW,
		CRYPTO_EXTF_USER_PIN_COUNT_LOW },
	{ "CRYPTO_EXTF_USER_PIN_FINAL_TRY", CRYPTO_EXTF_USER_PIN_FINAL_TRY,
		CRYPTO_EXTF_USER_PIN_FINAL_TRY },
	{ "CRYPTO_EXTF_USER_PIN_LOCKED", CRYPTO_EXTF_USER_PIN_LOCKED,
		CRYPTO_EXTF_USER_PIN_LOCKED },
	{ "CRYPTO_EXTF_USER_PIN_TO_BE_CHANGED",
		CRYPTO_EXTF_USER_PIN_TO_BE_CHANGED,
		CRYPTO_EXTF_USER_PIN_TO_BE_CHANGED },
	{ "CRYPTO_EXTF_SO_PIN_COUNT_LOW", CRYPTO_EXTF_SO_PIN_COUNT_LOW,
		CRYPTO_EXTF_SO_PIN_COUNT_LOW },
	{ "CRYPTO_EXTF_SO_PIN_FINAL_TRY", CRYPTO_EXTF_SO_PIN_FINAL_TRY,
		CRYPTO_EXTF_SO_PIN_FINAL_TRY },
	{ "CRYPTO_EXTF_SO_PIN_LOCKED", CRYPTO_EXTF_SO_PIN_LOCKED,
		CRYPTO_EXTF_SO_PIN_LOCKED },
	{ "CRYPTO_EXTF_SO_PIN_TO_BE_CHANGED", CRYPTO_EXTF_SO_PIN_TO_BE_CHANGED,
		CRYPTO_EXTF_SO_PIN_TO_BE_CHANGED },
	{ NULL, 0, 0 }
};

/*ARGSUSED*/
int
crypto_provider_ext_info(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	crypto_provider_ext_info_t ext_prov;
	/*
	 * 33 is 1 + MAX(CRYPTO_EXT_SIZE_LABEL, CRYPTO_EXT_SIZE_MANUF,
	 *		 CRYPTO_EXT_SIZE_MODEL, CRYPTO_EXT_SIZE_SERIAL)
	 */
	char scratch[33];

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&ext_prov, sizeof (crypto_provider_ext_info_t), addr)
	    == -1) {
		mdb_warn("cannot read addr");
		return (DCMD_ERR);
	}
	bcopy(ext_prov.ei_label, scratch, CRYPTO_EXT_SIZE_LABEL);
	scratch[CRYPTO_EXT_SIZE_LABEL] = '\0';
	mdb_printf("ei_label\t\t%s\n", scratch);

	bcopy(ext_prov.ei_manufacturerID, scratch, CRYPTO_EXT_SIZE_MANUF);
	scratch[CRYPTO_EXT_SIZE_MANUF] = '\0';
	mdb_printf("ei_manufacturerID\t%s\n", scratch);

	bcopy(ext_prov.ei_model, scratch, CRYPTO_EXT_SIZE_MODEL);
	scratch[CRYPTO_EXT_SIZE_MODEL] = '\0';
	mdb_printf("ei_model\t\t%s\n", scratch);

	bcopy(ext_prov.ei_serial_number, scratch, CRYPTO_EXT_SIZE_SERIAL);
	scratch[CRYPTO_EXT_SIZE_SERIAL] = '\0';
	mdb_printf("ei_serial_number\t%s\n", scratch);

	mdb_printf("ei_flags\t0x%x:\t<%lb>\n", ext_prov.ei_flags,
	    ext_prov.ei_flags, extf_flags);
	mdb_printf("ei_max_session_count\t%lu\n",
	    ext_prov.ei_max_session_count);
	mdb_printf("ei_max_pin_len\t\t%lu\n", ext_prov.ei_max_pin_len);
	mdb_printf("ei_min_pin_len\t\t%lu\n", ext_prov.ei_min_pin_len);
	mdb_printf("ei_total_public_memory\t%lu\n",
	    ext_prov.ei_total_public_memory);
	mdb_printf("ei_free_public_memory\t%lu\n",
	    ext_prov.ei_free_public_memory);
	mdb_printf("ei_total_private_memory\t%lu\n",
	    ext_prov.ei_total_private_memory);
	mdb_printf("ei_free_private_memory\t%lu\n",
	    ext_prov.ei_free_private_memory);
	mdb_printf("ei_hardware_version\tmajor %c minor %c\n",
	    ext_prov.ei_hardware_version.cv_major,
	    ext_prov.ei_hardware_version.cv_minor);
	mdb_printf("ei_firmware_version\tmajor %c minor %c\n",
	    ext_prov.ei_firmware_version.cv_major,
	    ext_prov.ei_firmware_version.cv_minor);
	mdb_printf("ei_time\t%s\n", ext_prov.ei_time);
	return (DCMD_OK);
}

const mdb_bitmask_t mech_bits[] = {
	{ "NIL", (uint32_t)-1, 0 },
	{ "CRYPTO_FG_ENCRYPT", CRYPTO_FG_ENCRYPT, CRYPTO_FG_ENCRYPT },
	{ "CRYPTO_FG_DECRYPT", CRYPTO_FG_DECRYPT, CRYPTO_FG_DECRYPT },
	{ "CRYPTO_FG_DIGEST", CRYPTO_FG_DIGEST, CRYPTO_FG_DIGEST },
	{ "CRYPTO_FG_SIGN", CRYPTO_FG_SIGN, CRYPTO_FG_SIGN },
	{ "CRYPTO_FG_SIGN_RECOVER", CRYPTO_FG_SIGN_RECOVER,
		CRYPTO_FG_SIGN_RECOVER },
	{ "CRYPTO_FG_VERIFY", CRYPTO_FG_VERIFY, CRYPTO_FG_VERIFY },
	{ "CRYPTO_FG_VERIFY_RECOVER", CRYPTO_FG_VERIFY_RECOVER,
		CRYPTO_FG_VERIFY_RECOVER },
	{ "CRYPTO_FG_GENERATE", CRYPTO_FG_GENERATE, CRYPTO_FG_GENERATE },
	{ "CRYPTO_FG_GENERATE_KEY_PAIR", CRYPTO_FG_GENERATE_KEY_PAIR,
		CRYPTO_FG_GENERATE_KEY_PAIR },
	{ "CRYPTO_FG_WRAP", CRYPTO_FG_WRAP, CRYPTO_FG_WRAP },
	{ "CRYPTO_FG_UNWRAP", CRYPTO_FG_UNWRAP, CRYPTO_FG_UNWRAP },
	{ "CRYPTO_FG_DERIVE", CRYPTO_FG_DERIVE, CRYPTO_FG_DERIVE },
	{ "CRYPTO_FG_MAC", CRYPTO_FG_MAC, CRYPTO_FG_MAC },
	{ "CRYPTO_FG_ENCRYPT_MAC", CRYPTO_FG_ENCRYPT_MAC,
		CRYPTO_FG_ENCRYPT_MAC },
	{ "CRYPTO_FG_MAC_DECRYPT", CRYPTO_FG_MAC_DECRYPT,
		CRYPTO_FG_MAC_DECRYPT },
	{ "CRYPTO_FG_ENCRYPT_ATOMIC", CRYPTO_FG_ENCRYPT_ATOMIC,
		CRYPTO_FG_ENCRYPT_ATOMIC },
	{ "CRYPTO_FG_DECRYPT_ATOMIC", CRYPTO_FG_DECRYPT_ATOMIC,
		CRYPTO_FG_DECRYPT_ATOMIC },
	{ "CRYPTO_FG_MAC_ATOMIC", CRYPTO_FG_MAC_ATOMIC, CRYPTO_FG_MAC_ATOMIC },
	{ "CRYPTO_FG_DIGEST_ATOMIC", CRYPTO_FG_DIGEST_ATOMIC,
		CRYPTO_FG_DIGEST_ATOMIC },
	{ "CRYPTO_FG_SIGN_ATOMIC", CRYPTO_FG_SIGN_ATOMIC,
		CRYPTO_FG_SIGN_ATOMIC },
	{ "CRYPTO_FG_SIGN_RECOVER_ATOMIC", CRYPTO_FG_SIGN_RECOVER_ATOMIC,
		CRYPTO_FG_SIGN_RECOVER_ATOMIC },
	{ "CRYPTO_FG_VERIFY_ATOMIC", CRYPTO_FG_VERIFY_ATOMIC,
		CRYPTO_FG_VERIFY_ATOMIC },
	{ "CRYPTO_FG_VERIFY_RECOVER_ATOMIC", CRYPTO_FG_VERIFY_RECOVER_ATOMIC,
		CRYPTO_FG_VERIFY_RECOVER_ATOMIC },
	{ "CRYPTO_FG_ENCRYPT_MAC_ATOMIC", CRYPTO_FG_ENCRYPT_MAC_ATOMIC,
		CRYPTO_FG_ENCRYPT_MAC_ATOMIC },
	{ "CRYPTO_FG_MAC_DECRYPT_ATOMIC", CRYPTO_FG_MAC_DECRYPT_ATOMIC,
		CRYPTO_FG_MAC_DECRYPT_ATOMIC },
	{ "CRYPTO_FG_RANDOM", CRYPTO_FG_RANDOM, CRYPTO_FG_RANDOM},
	{ NULL, 0, 0 }
};

/*ARGSUSED*/
int
crypto_mech_info(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	crypto_mech_info_t minfo;
	const char *unit = "bits";

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&minfo, sizeof (crypto_mech_info_t), addr)
	    == -1) {
		mdb_warn("cannot read addr %p", addr);
		return (DCMD_ERR);
	}
	mdb_printf("cm_mech_name_t\t%s\n", minfo.cm_mech_name);
	mdb_printf("cm_mech_number\t%lld\n", minfo.cm_mech_number);
	mdb_printf("cm_func_group_mask\t0x%x:\t<%b>\n",
	    minfo.cm_func_group_mask, minfo.cm_func_group_mask, mech_bits);
	if (minfo.cm_keysize_unit & CRYPTO_KEYSIZE_UNIT_IN_BYTES)
		unit = "bytes";
	mdb_printf("cm_min_key_length\t%lu %s\n", minfo.cm_min_key_length,
	    unit);
	mdb_printf("cm_max_key_length\t%lu %s\n", minfo.cm_max_key_length,
	    unit);

	return (DCMD_OK);
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, and a function
 * named _mdb_init to return a pointer to our module information.
 */

static const mdb_dcmd_t dcmds[] = {

	/* spi.c */
	{ "crypto_provider_ext_info", ":",
	    "module-private crypto provider info",
	    crypto_provider_ext_info, NULL },
	{ "crypto_mech_info", ":",
	    "print as crypto_mech_info",
	    crypto_mech_info, NULL },

	/* common.c */
	{ "crypto_mechanism", ":",
	    "details about a crypto mechanism", crypto_mechanism, NULL },
	{ "crypto_data", ":",
	    "print as crypto_data",
	    crypto_data, NULL },
	{ "crypto_dual_data", ":",
	    "print as crypto_dual_data",
	    crypto_dual_data, NULL },
	{ "crypto_key", ":",
	    "print as crypto_key", crypto_key, NULL },


	/* impl.c */
	{ "kcf_provider_desc", ":",
	    "crypto provider description struct", kcf_provider_desc, NULL },

	{ "prov_tab", "",
	    "global table of crypto providers ", prov_tab, NULL },

	{ "policy_tab", "",
	    "print global policy_tab", policy_tab, NULL },

	/* sched_impl.c */
	{ "kcf_areq_node", ":[-v]",
	    "print asynchronous crypto request struct, [ verbose ]",
		kcf_areq_node, NULL },

	{ "kcf_global_swq", "?[-v]",
	    "global or addr global crypto queue.  [ -v = verbose ]",
		kcf_global_swq, NULL },
	{ "crypto_find_reqid", "?[-v] reqid",
	    "look for reqid, print if found [ -v = verbose ]",
		crypto_find_reqid, NULL },

	{ "kcf_reqid_table", ":[-v]",
	    "print contents of a request ID hash table [ -v = verbose ]",
		kcf_reqid_table_dcmd, NULL },

	{ "kcf_soft_conf_entry", "?",
	    "head or addr of configured software crypto providers",
		kcf_soft_conf_entry, NULL },

	{ "kcf_policy_desc", ":", "policy descriptors for crypto",
		kcf_policy_desc, NULL },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "an_next", "walk kcf_areq_node's by an_next",
		areq_first_walk_init, an_next_walk_step, areq_walk_fini },
	{ "an_prev", "walk kcf_areq_node's by an_prev",
		areq_last_walk_init, an_prev_walk_step, areq_walk_fini },
	{ "an_idnext", "walk kcf_areq_node's by an_idnext",
		an_idnext_walk_init, an_idnext_walk_step, areq_walk_fini },
	{ "an_idprev", "walk kcf_areq_node's by an_idprev",
		an_idprev_walk_init, an_idprev_walk_step, areq_walk_fini },
	{ "an_ctxchain_next",
		"walk kcf_areq_node's by an_ctxchain_next",
		an_ctxchain_walk_init, an_ctxchain_walk_step, areq_walk_fini },
	{ "kcf_reqid_table", "table of asynchronous crypto requests",
		reqid_table_walk_init, reqid_table_walk_step,
		    reqid_table_walk_fini },
	{ "soft_conf_entry", "table of software providers or addr",
		soft_conf_walk_init, soft_conf_walk_step,
		    soft_conf_walk_fini },
	{ NULL }
};


static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
