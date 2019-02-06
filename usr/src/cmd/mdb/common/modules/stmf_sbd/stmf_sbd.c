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

#define	STMF_SBD_STR_MAX	2048
#define	STMF_SBD_VERBOSE	0x00000001

#define	ARRAY_SIZE(a)	(sizeof (a) / sizeof (*a))

/* structure to pass arguments to mdb_walker callback function */
typedef struct stmf_sbd_cb_s {
	uint32_t flag;
} stmf_sbd_cb_t;


static const char *stmf_protocol_str[] = {
	"FIBRE_CHANNEL",	/* PROTOCOL_FIBRE_CHANNEL	0 */
	"PARALLEL_SCSI",	/* PROTOCOL_PARALLEL_SCSI	1 */
	"SSA",			/* PROTOCOL_SSA			2 */
	"IEEE_1394",		/* PROTOCOL_IEEE_1394		3 */
	"SRP",			/* PROTOCOL_SRP			4 */
	"iSCSI",		/* PROTOCOL_iSCSI		5 */
	"SAS",			/* PROTOCOL_SAS			6 */
	"ADT",			/* PROTOCOL_ADT			7 */
	"ATAPI"			/* PROTOCOL_ATAPI		8 */
};


/*
 * Support functions.
 */

static uint64_t
nhconvert_8bytes(const void *src) {
	uint64_t dest;
	mdb_nhconvert(&dest, src, 8);
	return (dest);
}

/*
 *        Variable 'bits' is a collection of flags for which a corresponding
 *        description string is available at flag_ary.
 *        So flag_ary should be an ary of strings with total_bits strings.
 */
static void
stmf_sbd_print_bit_flags(const char *flag_ary[],
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
	static const char *pgr_flag_str[] = {
		"SBD_PGR_APTPL",			/* 0x01 */
		"SBD_PGR_RSVD_ONE",			/* 0x02 */
		"SBD_PGR_RSVD_ALL_REGISTRANTS",		/* 0x04 */
		"SBD_PGR_ALL_KEYS_HAS_IT"		/* 0x08 */
	};

	static const char *pgr_type_desc[] = {
		"ILLEGAL",				/* 0x0 */
		"Write Exclusive",			/* 0x1 */
		"ILLEGAL",				/* 0x2 */
		"Exclusive Access",			/* 0x3 */
		"ILLEGAL",				/* 0x4 */
		"Write Exclusive, Registrants Only",	/* 0x5 */
		"Exclusive Access, Registrants Only",	/* 0x6 */
		"Write Exclusive, All Registrants",	/* 0x7 */
		"Exclusive Access, All Registrants"	/* 0x8 */
	};

	mdb_printf("PGR flags: ");
	stmf_sbd_print_bit_flags(pgr_flag_str, ARRAY_SIZE(pgr_flag_str),
	    pgr->pgr_flags);
	if (pgr->pgr_rsvholder || pgr->pgr_flags &
	    SBD_PGR_RSVD_ALL_REGISTRANTS) {
		mdb_printf("Reservation Details \n");
		mdb_printf("\tReservation holder: ");
		if (pgr->pgr_rsvholder)
			mdb_printf("%p\n", pgr->pgr_rsvholder);
		else
			mdb_printf("All Registrants\n");

		mdb_printf("\t            type  : %d => %s\n",
		    pgr->pgr_rsv_type,
		    (pgr->pgr_rsv_type < ARRAY_SIZE(pgr_type_desc)) ?
		    pgr_type_desc[pgr->pgr_rsv_type] : "ILLEGAL");
		mdb_printf("\t            scope : %d\n", pgr->pgr_rsv_scope);
	} else {
		mdb_printf("No reservations.\n");
	}
}

void
print_scsi_devid_desc(uintptr_t addr, uint16_t len, char *spacer)
{
	scsi_devid_desc_t   *id;

	if (len < sizeof (*id)) {
		mdb_warn("%sError: Devid Size = %d < sizeof(scsi_devid_desc_t)"
		    "\n", spacer, len);
		return;
	}

	id = mdb_zalloc(len, UM_SLEEP);
	if (mdb_vread(id, len, addr) == -1) {
		mdb_warn("failed to read scsi_devid_desc at %p\n", addr);
		mdb_free(id, len);
		return;
	}

	mdb_printf("%sTotal length:\t%d\n", spacer, len);
	mdb_printf("%sProtocol:\t%d => %-16s\n", spacer, id->protocol_id,
	    (id->protocol_id < ARRAY_SIZE(stmf_protocol_str)) ?
	    stmf_protocol_str[id->protocol_id] : "");
	mdb_printf("%sCode Set:\t%d\n", spacer, id->code_set);
	mdb_printf("%sIdent Length:\t%d\n", spacer, id->ident_length);

	if (len < sizeof (*id) + id->ident_length - 1) {
		mdb_printf("%s(Can not recognize ident data)\n", spacer);
	} else {
		id->ident[id->ident_length] = '\0';
		mdb_printf("%sIdent:\t\t%s\n", spacer, id->ident);
	}
	mdb_free(id, len);
	mdb_printf("\n");
}

/*
 * Decipher and print transport id  which is pointed by addr variable.
 */
static int
print_transport_id(uintptr_t addr, uint16_t tpd_len, char *spacer)
{
	scsi_transport_id_t *tpd;

	if (tpd_len < sizeof (*tpd)) {
		mdb_warn("%sError: Transport ID Size = %d < "
		    "sizeof (scsi_transport_id_t)\n", spacer, tpd_len);
		return (DCMD_ERR);
	}

	tpd = mdb_zalloc(tpd_len, UM_SLEEP);
	if (mdb_vread(tpd, tpd_len, addr) == -1) {
		mdb_warn("failed to read scsi_transport_id at %p\n", addr);
		mdb_free(tpd, tpd_len);
		return (DCMD_ERR);
	}

	mdb_printf("%sTotal length:\t%d\n", spacer, tpd_len);
	mdb_printf("%sProtocol:\t%d => %16s\n", spacer, tpd->protocol_id,
	    (tpd->protocol_id < ARRAY_SIZE(stmf_protocol_str)) ?
	    stmf_protocol_str[tpd->protocol_id] : "");
	mdb_printf("%sFormat Code:\t0x%x\n", spacer, tpd->format_code);

	switch (tpd->protocol_id) {
	case PROTOCOL_FIBRE_CHANNEL:
		{
		uint8_t *p = ((scsi_fc_transport_id_t *)tpd)->port_name;
		mdb_printf("%sFC Port Name:\t%016llX\n", spacer,
		    nhconvert_8bytes(p));
		}
		break;
	case PROTOCOL_PARALLEL_SCSI:
	case PROTOCOL_SSA:
	case PROTOCOL_IEEE_1394:
		break;
	case PROTOCOL_SRP:
		{
		uint8_t *p = ((scsi_srp_transport_id_t *)tpd)->srp_name;
		/* Print 8 byte initiator extention and guid in order */
		mdb_printf("%sSRP Name:\t%016llX:%016llX\n", spacer,
		    nhconvert_8bytes(&p[8]), nhconvert_8bytes(&p[0]));
		}
		break;
	case PROTOCOL_iSCSI:
		mdb_printf("%sISCSI Name:\t%s\n", spacer,
		    ((iscsi_transport_id_t *)tpd)->iscsi_name);
		break;
	case PROTOCOL_SAS:
	case PROTOCOL_ADT:
	case PROTOCOL_ATAPI:
	default:
		break;
	}

	mdb_free(tpd, tpd_len);
	return (DCMD_OK);
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
	if (wsp->walk_addr == 0) {
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

	if (wsp->walk_addr == 0)
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

		mdb_printf("\nsbd_lu - %p\n", addr);

		/* sl_device_id contains 4 bytes hdr + 16 bytes(GUID) */
		mdb_printf("\tsl_deviceid:      %-?p  GUID => %016llX%016llX\n",
		    slu->sl_device_id, nhconvert_8bytes(&slu->sl_device_id[4]),
		    nhconvert_8bytes(&slu->sl_device_id[12]));
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
	} else {
		mdb_printf("%p\n", addr);
	}
	return (WALK_NEXT);
}

static int
stmf_sbd_pgr_key_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
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

	if (wsp->walk_addr == 0)
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
	static const char *key_flag_str [] = {
		"SBD_PGR_KEY_ALL_TG_PT",   /* 0x01 */
		"SBD_PGR_KEY_TPT_ID_FLAG"  /* 0x02 */
	};

	if (cb_st->flag & STMF_SBD_VERBOSE) {
		mdb_printf("sbd_pgr_key - %p\n", addr);
		mdb_printf("\tRegistered key:      0x%016llx\n", key->pgr_key);
		mdb_printf("\tKey Flags:           ");
		stmf_sbd_print_bit_flags(key_flag_str, ARRAY_SIZE(key_flag_str),
		    key->pgr_key_flags);
		mdb_printf("\tpgr_key_it:          %?-p\n", key->pgr_key_it);
		mdb_printf("\tLocal Device ID:     %?-p\n",
		    key->pgr_key_lpt_id);
		print_scsi_devid_desc((uintptr_t)key->pgr_key_lpt_id,
		    key->pgr_key_lpt_len, "		");
		mdb_printf("\tRemote Transport ID: %?-p\n",
		    key->pgr_key_rpt_id);
		print_transport_id((uintptr_t)key->pgr_key_rpt_id,
		    key->pgr_key_rpt_len, "		");
	} else {
		mdb_printf("%p\n", addr);
	}
	return (WALK_NEXT);
}

static int
stmf_sbd_it_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
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

	if (wsp->walk_addr == 0)
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
	static const char *it_flag_str [] = {
		"SBD_IT_HAS_SCSI2_RESERVATION",		/* 0x0001 */
		"SBD_IT_PGR_REGISTERED",		/* 0x0002 */
		"SBD_IT_PGR_EXCLUSIVE_RSV_HOLDER",	/* 0x0004 */
		"SBD_IT_PGR_CHECK_FLAG"			/* 0x0008 */
	};

	if (cb_st->flag & STMF_SBD_VERBOSE) {
		mdb_printf("SBD IT DATA - %p\n", addr);
		mdb_printf("\tSession ID: 0x%0-lx\n", it->sbd_it_session_id);
		mdb_printf("\tIT Flags:   ");
		stmf_sbd_print_bit_flags(it_flag_str, ARRAY_SIZE(it_flag_str),
		    it->sbd_it_flags);
		mdb_printf("\tPGR Key:    %-p\n", it->pgr_key_ptr);
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

/*ARGSUSED*/
static int
stmf_remote_port(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	stmf_remote_port_t rpt;
	int	ret = DCMD_OK;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&rpt, sizeof (stmf_remote_port_t), addr) == -1) {
		mdb_warn("failed to read stmf_remote_port_t at %p\n", addr);
		return (DCMD_ERR);
	}

	ret = print_transport_id((uintptr_t)rpt.rport_tptid,
	    rpt.rport_tptid_sz, "		");
	return (ret);
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
		mdb_printf("\nLU:- %p\n", addr);
	}

	/* If address of pgr_key is given, just print that key and return */
	if (mdb_vread(&slu, sizeof (sbd_lu_t), addr) == -1) {
		mdb_warn("failed to read sbd_lu at %p\n", addr);
		return (DCMD_ERR);
	}

	/* Just a sanity check, not necessarily needed */
	if (slu.sl_it_list == NULL) {
		if (verbose)
			mdb_printf("sbd_it_list is empty\n", addr);
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
	{ "stmf_remote_port", ":", "decipher info in a stmf_remote_port",
	    stmf_remote_port, NULL },
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
