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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/dditypes.h>
#include <sys/mdb_modapi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>

#include <lpif.h>
#include <stmf.h>
#include <stmf_ioctl.h>
#include <portif.h>
#include <stmf_sbd.h>
#include <sbd_impl.h>
#include <scsi/generic/persist.h>

#define	STMF_SBD_FLAG_ARY_SZ	32
#define	STMF_SBD_STR_MAX	2048
#define	STMF_SBD_VERBOSE	0x00000001

/* structure to pass arguments to mdb_walker callback function */
typedef struct stmf_sbd_cb_s {
	uint32_t flag;
} stmf_sbd_cb_t;

char stmf_protocol_str [9][STMF_SBD_FLAG_ARY_SZ] = {
	"FIBRE_CHANNEL",	/* PROTOCOL_FIBRE_CHANNEL	0 */
	"PARALLEL_SCSI",	/* PROTOCOL_PARALLEL_SCSI	1 */
	"SSA",			/* PROTOCOL_SSA			2 */
	"IEEE_1394",		/* PROTOCOL_IEEE_1394		3 */
	"SRP",			/* PROTOCOL_SRP			4 */
	"iSCSI",		/* PROTOCOL_iSCSI		5 */
	"SAS",			/* PROTOCOL_SAS			6 */
	"ADT",			/* PROTOCOL_ADT			7 */
	"ATAPI",		/* PROTOCOL_ATAPI		8 */
};

/*
 * Support functions.
 */

/*
 *        Variable 'bits' is a collection of flags for which a corresponding
 *        description string is available at flag_ary.
 *        So flag_ary should be an ary of strings with total_bits + 1 strings.
 */
static void
stmf_sbd_print_bit_flags(char flag_ary[][STMF_SBD_FLAG_ARY_SZ],
					int total_bits, uint32_t bits) {
	uint32_t curbit = 0x01;
	int i, delim = 0;

	for (i = 0; i < total_bits; i++) {
		if (bits & curbit) {
			mdb_printf("%s%s", (delim) ? " | " : "", flag_ary[i]);
			delim = 1;
		}
		curbit <<= 1;
	}
	mdb_printf("\n");
}


static void
stmf_sbd_print_pgr_info(sbd_pgr_t *pgr)
{
	char pgr_flag_str [5][STMF_SBD_FLAG_ARY_SZ] = {
		"SBD_PGR_APTPL",			/* 0x01 */
		"SBD_PGR_RSVD_ONE",			/* 0x02 */
		"SBD_PGR_RSVD_ALL_REGISTRANTS",		/* 0x04 */
		"SBD_PGR_ALL_KEYS_HAS_IT"		/* 0x08 */
	};
	char pgr_type_desc[9][48] = {"ILLEGAL",
	    "Write Exclusive",				/* 0x1 */
	    "ILLEGAL",
	    "Exclusive Access",				/* 0x3 */
	    "Write Exclusive, Registrants Only",	/* 0x5 */
	    "Exclusive Access, Registrants Only",	/* 0x6 */
	    "Write Exclusive, All Registrants",		/* 0x7 */
	    "Exclusive Access, All Registrants"		/* 0x8 */
	};
	char *type_str = pgr_type_desc[0];


	mdb_printf("PGR flags: ");
	stmf_sbd_print_bit_flags(pgr_flag_str, 4, pgr->pgr_flags);
	if (pgr->pgr_rsvholder || pgr->pgr_flags &
	    SBD_PGR_RSVD_ALL_REGISTRANTS) {
		mdb_printf("Reservation Details \n");
		mdb_printf("\tReservation holder: ");
		if (pgr->pgr_rsvholder)
			mdb_printf("%p\n", pgr->pgr_rsvholder);
		else
			mdb_printf("All Registrants\n");
		if (pgr->pgr_rsv_type < 8)
			type_str = pgr_type_desc[pgr->pgr_rsv_type];
		mdb_printf("\t            type  : %d => %s\n",
		    pgr->pgr_rsv_type, type_str);
		mdb_printf("\t            scope : %d\n", pgr->pgr_rsv_scope);
	} else {
		mdb_printf("No reservations.\n");
	}
}

void
print_scsi_devid_desc(uintptr_t addr, uint16_t len, char *s)
{
	scsi_devid_desc_t   *id;

	id = mdb_zalloc(len, UM_SLEEP);
	if (mdb_vread(id, len, addr) == -1) {
		mdb_warn("failed to read scsi_devid_desc at %p\n", addr);
		mdb_free(id, len);
		return;
	}

	mdb_printf("%sTotal length:\t%d\n", s, len);
	mdb_printf("%sProtocol:\t%d => %-16s\n", s, id->protocol_id,
	    (id->protocol_id < 8) ? stmf_protocol_str[id->protocol_id] : "");
	mdb_printf("%sCode Set:\t%d\n", s, id->code_set);
	mdb_printf("%sIdent Length:\t%d\n", s, id->ident_length);

	if (len > id->ident_length + 3) {
		id->ident[id->ident_length] = '\0';
		mdb_printf("%sIdent:\t%s\n", s, id->ident);
	} else {
		mdb_printf("%s(Can not recognize ident data)\n", s);
	}
	mdb_free(id, len);
	mdb_printf("\n");
}

void
stmf_sbd_pgr_key_dcmd_help(void)
{
	mdb_printf(
	    "Prints info about pgr keys and reservations on the given lun.\n\n"
	    "Usage:  <addr>::stmf_sbd_pgr_key [-akv]\n"
	    "    where <addr> represent the address of\n"
	    "          sbd_lu_t by default\n"
	    "             or\n"
	    "          sbd_pgr_key_t if '-a' option is specified.\n"
	    "Options:\n"
	    "   -a   if specified, <addr> represents address of sbd_pgr_key_t\n"
	    "   -k   if specified, only prints key information\n"
	    "   -v   verbose output\n");
}


/*
 * MDB WALKERS implementations
 */

static int
stmf_sbd_lu_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		if (mdb_readvar(&wsp->walk_addr, "sbd_lu_list") == -1) {
			mdb_warn("failed to read sbd_lu_list\n");
			return (WALK_ERR);
		}
	}
	return (WALK_NEXT);
}

static int
stmf_sbd_lu_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t	addr = wsp->walk_addr;
	sbd_lu_t	slu;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&slu, sizeof (sbd_lu_t), addr) == -1) {
		mdb_warn("failed to read sbd_lu_t at %p\n", addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)slu.sl_next;
	return (wsp->walk_callback(addr, &slu, wsp->walk_cbdata));
}

char *
stmf_sbd_getstr(uintptr_t addr, char *str) {
	if ((addr == 0) || (mdb_readstr(str, STMF_SBD_STR_MAX, addr) == -1))
		str = NULL;
	return (str);
}

static int
stmf_sbd_lu_cb(uintptr_t addr, const sbd_lu_t *slu, stmf_sbd_cb_t *cb_st)
{
	if (cb_st->flag & STMF_SBD_VERBOSE) {
		char str[STMF_SBD_STR_MAX];

		mdb_printf("sbd_lu - %p\n", addr);
		mdb_printf("\tsl_name:          %-?p  %s\n", slu->sl_name,
		    stmf_sbd_getstr((uintptr_t)slu->sl_name, str));
		mdb_printf("\tsl_alias:         %-?p  %s\n", slu->sl_alias,
		    stmf_sbd_getstr((uintptr_t)slu->sl_alias, str));
		mdb_printf("\tsl_meta_filename: %-?p  %s\n",
		    slu->sl_meta_filename,
		    stmf_sbd_getstr((uintptr_t)slu->sl_meta_filename, str));
		mdb_printf("\tsl_data_filename: %-?p  %s\n",
		    slu->sl_data_filename,
		    stmf_sbd_getstr((uintptr_t)slu->sl_data_filename, str));
		mdb_printf("\tsl_mgmt_url:      %-?p  %s\n", slu->sl_mgmt_url,
		    stmf_sbd_getstr((uintptr_t)slu->sl_mgmt_url, str));
		mdb_printf("\tsl_zfs_meta:      %-?p\n", slu->sl_zfs_meta);
		mdb_printf("\tsl_it_list:       %-?p\n", slu->sl_it_list);
		mdb_printf("\tsl_pgr:           %-?p\n", slu->sl_pgr);
		mdb_printf("\n");
	} else {
		mdb_printf("%p\n", addr);
	}
	return (WALK_NEXT);
}

static int
stmf_sbd_pgr_key_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("<pgr_key_list addr>::walk stmf_sbd_pgr_key\n");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
stmf_sbd_pgr_key_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t	addr = wsp->walk_addr;
	sbd_pgr_key_t	key;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&key, sizeof (sbd_pgr_key_t), addr) == -1) {
		mdb_warn("failed to read sbd_pgr_key_t at %p\n", addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)key.pgr_key_next;
	return (wsp->walk_callback(addr, &key, wsp->walk_cbdata));
}

static int
stmf_sbd_pgr_key_cb(uintptr_t addr, const sbd_pgr_key_t *key,
					stmf_sbd_cb_t *cb_st)
{
	char key_flag_str [5][STMF_SBD_FLAG_ARY_SZ] = {
		"SBD_PGR_KEY_ALL_TG_PT",   /* 0x01 */
		"SBD_PGR_KEY_TPT_ID_FLAG", /* 0x02 */
	};

	if (cb_st->flag & STMF_SBD_VERBOSE) {
		mdb_printf("sbd_pgr_key - %p\n", addr);
		mdb_printf("\tRegistered key:      0x%llx\n", key->pgr_key);
		mdb_printf("\tKey Flags:           ");
		stmf_sbd_print_bit_flags(key_flag_str, 2, key->pgr_key_flags);
		mdb_printf("\tpgr_key_it:          %?-p\n", key->pgr_key_it);
		mdb_printf("\tLocal Device ID:     %?-p\n",
		    key->pgr_key_lpt_id);
		print_scsi_devid_desc((uintptr_t)key->pgr_key_lpt_id,
		    key->pgr_key_lpt_len, "		");
		mdb_printf("\tRemote scsi devid desc: %?-p\n",
		    key->pgr_key_rpt_id);
		print_scsi_devid_desc((uintptr_t)key->pgr_key_rpt_id,
		    key->pgr_key_rpt_len, "		");
	} else {
		mdb_printf("%p\n", addr);
	}
	return (WALK_NEXT);
}

static int
stmf_sbd_it_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("<sbd_it_list addr>::walk stmf_sbd_pgr_key\n");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
stmf_sbd_it_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t	addr = wsp->walk_addr;
	sbd_it_data_t	it;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&it, sizeof (sbd_it_data_t), addr) == -1) {
		mdb_warn("failed to read sbd_it_data_t at %p\n", addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)it.sbd_it_next;
	return (wsp->walk_callback(addr, &it, wsp->walk_cbdata));
}

static int
stmf_sbd_it_cb(uintptr_t addr, const sbd_it_data_t *it, stmf_sbd_cb_t *cb_st)
{
	char it_flag_str [5][STMF_SBD_FLAG_ARY_SZ] = {
		"SBD_IT_HAS_SCSI2_RESERVATION",		/* 0x0001 */
		"SBD_IT_PGR_REGISTERED",		/* 0x0002 */
		"SBD_IT_PGR_EXCLUSIVE_RSV_HOLDER",	/* 0x0004 */
		"SBD_IT_PGR_CHECK_FLAG",		/* 0x0008 */
	};

	if (cb_st->flag & STMF_SBD_VERBOSE) {
		mdb_printf("SBD IT DATA - %p\n", addr);
		mdb_printf("\tSession ID: 0x%0-lx\n", it->sbd_it_session_id);
		mdb_printf("\tIT Flags:   ");
		stmf_sbd_print_bit_flags(it_flag_str, 4, it->sbd_it_flags);
		mdb_printf("\tPGR Key:    %-p\n", it->pgr_key_ptr);
		mdb_printf("\n");
	} else {
		mdb_printf("%p\n", addr);
	}
	return (WALK_NEXT);
}

/*
 * MDB DCMDS implementations.
 */

int
stmf_sbd_lu(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		verbose = FALSE;
	sbd_lu_t	slu;
	stmf_sbd_cb_t	cb_st = {0};

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL)
	    != argc)
		return (DCMD_USAGE);
	if (verbose)
		cb_st.flag |= STMF_SBD_VERBOSE;

	if (flags & DCMD_ADDRSPEC) {
		cb_st.flag |= STMF_SBD_VERBOSE;
		if (mdb_vread(&slu, sizeof (sbd_lu_t), addr) == -1) {
			mdb_warn("failed to read sbd_lu_t at %p\n", addr);
			return (DCMD_ERR);
		}
		if (stmf_sbd_lu_cb(addr, &slu, &cb_st) == WALK_ERR)
			return (DCMD_ERR);
	} else {
		if (mdb_walk("stmf_sbd_lu", (mdb_walk_cb_t)stmf_sbd_lu_cb,
		    &cb_st) == -1) {
			mdb_warn("failed to walk sbd_lu_list\n");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

static int
stmf_sbd_pgr_key(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		verbose = FALSE, keyonly = FALSE, pgrkeyaddr = FALSE;
	sbd_lu_t	slu;
	sbd_pgr_t	pgr;
	sbd_pgr_key_t	key;
	stmf_sbd_cb_t	cb_st = {0};

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &pgrkeyaddr,
	    'k', MDB_OPT_SETBITS, TRUE, &keyonly,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (pgrkeyaddr || verbose)
		cb_st.flag |= STMF_SBD_VERBOSE;

	/* If address of pgr_key is given, just print that key and return */
	if (pgrkeyaddr) {
		if (mdb_vread(&key, sizeof (sbd_pgr_key_t), addr) == -1) {
			mdb_warn("failed to read sbd_pgr_key at %p\n", addr);
			return (DCMD_ERR);
		}
		if (stmf_sbd_pgr_key_cb(addr, &key, &cb_st) == WALK_ERR) {
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	} else {
		if (mdb_vread(&slu, sizeof (sbd_lu_t), addr) == -1) {
			mdb_warn("failed to read sbd_lu at %p\n", addr);
			return (DCMD_ERR);
		}
	}

	if (verbose) {
		mdb_printf("\nLU:- %p\n", addr);
	}
	/* Just a sanity check, not necessarily needed */
	if (slu.sl_pgr == NULL) {
		if (verbose)
			mdb_warn("pgr structure not found for lun %p\n", addr);
		return (DCMD_OK);
	}

	if (mdb_vread(&pgr, sizeof (sbd_pgr_t), (uintptr_t)slu.sl_pgr) == -1) {
		mdb_warn("failed to read sbd_lu at %p\n", slu.sl_pgr);
		return (DCMD_ERR);
	}

	if (!keyonly)
		stmf_sbd_print_pgr_info(&pgr);

	if (pgr.pgr_keylist == NULL) {
		if (verbose)
			mdb_printf("No registered pgr keys found\n");
		return (DCMD_OK);
	} else {
		if (!keyonly)
			mdb_printf("\nKeys\n");
	}

	if (mdb_pwalk("stmf_sbd_pgr_key", (mdb_walk_cb_t)stmf_sbd_pgr_key_cb,
	    &cb_st, (uintptr_t)pgr.pgr_keylist) == -1) {
		mdb_warn("failed to walk pgr_keylist\n");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

static int
stmf_sbd_it(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		verbose = FALSE;
	sbd_lu_t	slu;
	stmf_sbd_cb_t	cb_st = {0};

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (verbose) {
		cb_st.flag |= STMF_SBD_VERBOSE;
		mdb_printf("LU:- %p\n", addr);
	}

	/* If address of pgr_key is given, just print that key and return */
	if (mdb_vread(&slu, sizeof (sbd_lu_t), addr) == -1) {
		mdb_warn("failed to read sbd_lu at %p\n", addr);
		return (DCMD_ERR);
	}

	/* Just a sanity check, not necessarily needed */
	if (slu.sl_it_list == NULL) {
		if (verbose)
			mdb_warn("sbd_it_list is empty%p\n", addr);
		return (DCMD_OK);
	}

	if (mdb_pwalk("stmf_sbd_it", (mdb_walk_cb_t)stmf_sbd_it_cb, &cb_st,
	    (uintptr_t)slu.sl_it_list) == -1) {
		mdb_warn("failed to walk sbd_lu_it_list\n");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

/*
 * MDB dmcds and walkers definitions
 */

static const mdb_dcmd_t dcmds[] = {
	{ "stmf_sbd_lu", "?[-v]", "Print the list of sbd_lu_t",
	    stmf_sbd_lu, NULL },
	{ "stmf_sbd_it", ":[-v]", "Print the list of sbd_it_data for given lu",
	    stmf_sbd_it, NULL },
	{ "stmf_sbd_pgr_key", ":[-kov]", "Print the list of pgr keys",
	    stmf_sbd_pgr_key, stmf_sbd_pgr_key_dcmd_help },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "stmf_sbd_lu", "walk list of stmf_sbd_lu structures",
	    stmf_sbd_lu_walk_init, stmf_sbd_lu_walk_step, NULL },
	{ "stmf_sbd_pgr_key", "walk the pgr keys of the given pgr key list",
	    stmf_sbd_pgr_key_walk_init, stmf_sbd_pgr_key_walk_step, NULL },
	{ "stmf_sbd_it", "walk the sbd_it_data for the given it list",
	    stmf_sbd_it_walk_init, stmf_sbd_it_walk_step, NULL },
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
