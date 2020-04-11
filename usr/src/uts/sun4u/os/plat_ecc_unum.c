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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/plat_ecc_unum.h>
#include <sys/utsname.h>
#include <sys/cmn_err.h>
#include <sys/async.h>
#include <sys/errno.h>
#include <sys/fm/protocol.h>
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <sys/bl.h>
#include <sys/taskq.h>
#include <sys/condvar.h>
#include <sys/plat_ecc_dimm.h>

/*
 * Pointer to platform specific function to initialize a cache of DIMM
 * serial ids
 */
int (*p2init_sid_cache)(void);

/*
 * This file contains the common code that is used for parsing
 * ecc unum data and logging it appropriately as the platform
 * that calls this code implements.
 */

int plat_ecc_dispatch_task(plat_ecc_message_t *);
static void plat_ecc_send_msg(void *);

#define	CHECK_UNUM \
	if (unum_ptr == NULL) { \
		break; \
	}

/*
 * See plat_ecc_unum.h for the meaning of these variables.
 */
int ecc_log_fruid_enable = ECC_FRUID_ENABLE_DEFAULT;

uint32_t plat_ecc_capability_map_domain = PLAT_ECC_CAPABILITY_DOMAIN_DEFAULT;
uint32_t plat_ecc_capability_map_sc = PLAT_ECC_CAPABILITY_SC_DEFAULT;
uint16_t ecc_error2_mailbox_flags = PLAT_ECC_ERROR2_SEND_DEFAULT;
uint16_t ecc_indictment2_mailbox_flags = PLAT_ECC_SEND_INDICT2_DEFAULT;

/*
 * We log all ECC errors using the function that is defined as
 * plat_send_ecc_mailbox_msg(); We first parse the unum string and
 * then pass the data to be logged to the plat_send_ecc_mailbox_msg
 * function for logging. Each platform that uses this code needs to
 * implement a suitable function for this purpose.
 */
void
plat_log_fruid_error(int synd_code, struct async_flt *ecc, char *unum,
    uint64_t afsr_bit)
{
	plat_ecc_error_data_t ecc_error_data;
	enum plat_ecc_type ecc_type = PLAT_ECC_UNKNOWN;
	int board_num;
	int proc_position;
	int invalid_unum = 1;

	bzero(&ecc_error_data, sizeof (plat_ecc_error_data_t));
	ecc_error_data.version = PLAT_ECC_VERSION;

	switch (afsr_bit) {
	case C_AFSR_CE:
		ecc_error_data.error_code = PLAT_ERROR_CODE_CE;
		break;
	case C_AFSR_UE:
		ecc_error_data.error_code = PLAT_ERROR_CODE_UE;
		break;
	case C_AFSR_EDC:
		ecc_error_data.error_code = PLAT_ERROR_CODE_EDC;
		break;
	case C_AFSR_EDU:
		ecc_error_data.error_code = PLAT_ERROR_CODE_EDU;
		break;
	case C_AFSR_WDC:
		ecc_error_data.error_code = PLAT_ERROR_CODE_WDC;
		break;
	case C_AFSR_WDU:
		ecc_error_data.error_code = PLAT_ERROR_CODE_WDU;
		break;
	case C_AFSR_CPC:
		ecc_error_data.error_code = PLAT_ERROR_CODE_CPC;
		break;
	case C_AFSR_CPU:
		ecc_error_data.error_code = PLAT_ERROR_CODE_CPU;
		break;
	case C_AFSR_UCC:
		ecc_error_data.error_code = PLAT_ERROR_CODE_UCC;
		break;
	case C_AFSR_UCU:
		ecc_error_data.error_code = PLAT_ERROR_CODE_UCU;
		break;
	case C_AFSR_EMC:
		ecc_error_data.error_code = PLAT_ERROR_CODE_EMC;
		break;
	case C_AFSR_EMU:
		ecc_error_data.error_code = PLAT_ERROR_CODE_EMU;
		break;
	default:
		/*
		 * Do not send messages with unknown error codes, since
		 * the SC will not be able to tell what type of error
		 * occurred.
		 */
		return;
	}

	ecc_error_data.detecting_proc = ecc->flt_bus_id;

	if (ecc->flt_in_memory)
		ecc_type = PLAT_ECC_MEMORY;
	else if (ecc->flt_status & ECC_ECACHE)
		ecc_type = PLAT_ECC_ECACHE;

	switch (ecc_type) {
	case PLAT_ECC_MEMORY: {
		/*
		 * The unum string is expected to be in this form:
		 * "/N0/SB12/P0/B0/D2 J13500, ..."
		 * for serengeti.  As this code is shared with Starcat
		 * if N is missing then it is set to 0.
		 * From that we will extract the bank number, dimm
		 * number, and Jnumber.
		 */
		char *unum_ptr = unum;
		char *jno_ptr = ecc_error_data.Jnumber;
		int i;

		/*
		 * On Serengeti we expect to find 'N' in the unum string
		 * however, on Starcat 'N' does not appear in the unum string.
		 * We do not want this code to break at this point, so the
		 * unum_ptr is reset to the start of unum string if we fail
		 * to find an 'N'.
		 */
		unum_ptr = strchr(unum_ptr, 'N');
		if (unum_ptr == NULL) {
			ecc_error_data.node_no = 0;
			unum_ptr = unum;
		} else {
			unum_ptr++;
			ecc_error_data.node_no = stoi(&unum_ptr);
		}

		/*
		 * Now pull out the SB number
		 */
		unum_ptr = strstr(unum_ptr, "SB");
		CHECK_UNUM;
		unum_ptr += 2;
		board_num = stoi(&unum_ptr);

		/*
		 * Now pull out the Proc position (relative to the board)
		 */
		unum_ptr = strchr(unum_ptr, 'P');
		CHECK_UNUM;
		unum_ptr++;
		proc_position = stoi(&unum_ptr);

		/*
		 * Using the SB number and Proc position we create a FRU
		 * cpu id.
		 */
		ecc_error_data.proc_num =
		    plat_make_fru_cpuid(board_num, 0, proc_position);

		/*
		 * Now pull out the Memory Bank number
		 */
		unum_ptr = strchr(unum_ptr, 'B');
		CHECK_UNUM;
		unum_ptr++;
		ecc_error_data.bank_no = (stoi(&unum_ptr) & 0x01);

		/*
		 * Now pull out the Dimm number within the Memory Bank.
		 */
		unum_ptr = strchr(unum_ptr, 'D');
		CHECK_UNUM;
		unum_ptr++;
		ecc_error_data.ecache_dimm_no = (stoi(&unum_ptr) & 0x03);

		/*
		 * Now pull out the J-number.
		 */
		unum_ptr = strchr(unum_ptr, 'J');
		CHECK_UNUM;
		unum_ptr++;
		for (i = PLAT_ECC_JNUMBER_LENGTH;
		    i > 0 && *unum_ptr >= '0' && *unum_ptr <= '9'; i--)
			*jno_ptr++ = *unum_ptr++;
		*jno_ptr = '\0';

		/*
		 * If we get here, we can assume the unum is valid
		 */
		invalid_unum = 0;
		break;
	}
	case PLAT_ECC_ECACHE: {
		/*
		 * The unum string is expected to be in this form:
		 * "[/N0/][SB|IO]12/P0/E0 J13500, ..."
		 * for serengeti.  As this code is shared with Starcat
		 * if N is missing then it is set to 0.  IO may only appear
		 * on Starcats.  From that we will extract the bank number,
		 * dimm number, and Jnumber.
		 */
		char *unum_ptr = unum;
		char *jno_ptr = ecc_error_data.Jnumber;
		int is_maxcat = 0;
		int i;

		/*
		 * On Serengeti we expect to find 'N' in the unum string
		 * however, on Starcat 'N' does not appear in the unum string.
		 * We do not want this code to break at this point, so the
		 * unum_ptr is reset to the start of unum string if we fail
		 * to find an 'N'.
		 */
		unum_ptr = strchr(unum_ptr, 'N');
		if (unum_ptr == NULL) {
			ecc_error_data.node_no = 0;
			unum_ptr = unum;
		} else {
			unum_ptr++;
			ecc_error_data.node_no = stoi(&unum_ptr);
		}

		/*
		 * Now pull out the SB/IO number
		 */
		unum_ptr = strstr(unum_ptr, "SB");
		if (unum_ptr == NULL) {

			/*
			 * Since this is an E$ error, it must have occurred on
			 * either a System Board (represented by "SB" in the
			 * unum string) or a Maxcat board ("IO" in the unum
			 * string).  Since we failed the "SB" check, we'll
			 * assume this is a maxcat board.
			 */
			is_maxcat = 1;
			unum_ptr = strstr(unum, "IO");
		}
		CHECK_UNUM;
		unum_ptr += 2;
		board_num = stoi(&unum_ptr);

		/*
		 * Now pull out the Proc position (relative to the board)
		 */
		unum_ptr = strchr(unum_ptr, 'P');
		CHECK_UNUM;
		unum_ptr++;
		proc_position = stoi(&unum_ptr);

		/*
		 * Using the SB/IO number, slot 0/1 value (is_maxcat), and
		 * proc position, we create the cpu id.
		 */
		ecc_error_data.proc_num = plat_make_fru_cpuid(board_num,
		    is_maxcat, proc_position);

		ecc_error_data.bank_no = 0;	/* not used */

		unum_ptr = strchr(unum_ptr, 'E');
		CHECK_UNUM;
		unum_ptr++;
		ecc_error_data.ecache_dimm_no = (stoi(&unum_ptr) & 0x01);

		unum_ptr = strchr(unum_ptr, 'J');
		CHECK_UNUM;
		unum_ptr++;
		for (i = PLAT_ECC_JNUMBER_LENGTH;
		    i > 0 && *unum_ptr >= '0' && *unum_ptr <= '9'; i--)
			*jno_ptr++ = *unum_ptr++;
		*jno_ptr = '\0';

		/*
		 * If we get here, we can assume the unum is valid
		 */
		invalid_unum = 0;
		break;
	}
	default:
		/*
		 * Unknown error
		 */
		break;
	}

	/*
	 * This is where CHECK_UNUM goes when it finds an error
	 */

	if (ECC_SYND_DATA_BEGIN <= synd_code &&
	    synd_code < ECC_SYND_ECC_BEGIN) {
		ecc_error_data.error_type = PLAT_ERROR_TYPE_SINGLE;
		ecc_error_data.databit_type = PLAT_BIT_TYPE_DATA;
		ecc_error_data.databit_no = synd_code;
	} else if (ECC_SYND_ECC_BEGIN <= synd_code &&
	    synd_code < ECC_SYND_MTAG_BEGIN) {
		ecc_error_data.error_type = PLAT_ERROR_TYPE_SINGLE;
		ecc_error_data.databit_type = PLAT_BIT_TYPE_ECC;
		ecc_error_data.databit_no = synd_code - ECC_SYND_ECC_BEGIN;
	} else if (ECC_SYND_MTAG_BEGIN <= synd_code &&
	    synd_code < ECC_SYND_MECC_BEGIN) {
		ecc_error_data.error_type = PLAT_ERROR_TYPE_SINGLE;
		ecc_error_data.databit_type = PLAT_BIT_TYPE_MTAG_D;
		ecc_error_data.databit_no = synd_code - ECC_SYND_MTAG_BEGIN;
	} else if (ECC_SYND_MECC_BEGIN <= synd_code &&
	    synd_code < ECC_SYND_M2) {
		ecc_error_data.error_type = PLAT_ERROR_TYPE_SINGLE;
		ecc_error_data.databit_type = PLAT_BIT_TYPE_MTAG_E;
		ecc_error_data.databit_no = synd_code - ECC_SYND_MECC_BEGIN;
	} else {
		switch (synd_code) {
		case ECC_SYND_M2:
			ecc_error_data.error_type = PLAT_ERROR_TYPE_M2;
			break;
		case ECC_SYND_M3:
			ecc_error_data.error_type = PLAT_ERROR_TYPE_M3;
			break;
		case ECC_SYND_M4:
			ecc_error_data.error_type = PLAT_ERROR_TYPE_M4;
			break;
		case ECC_SYND_M:
			ecc_error_data.error_type = PLAT_ERROR_TYPE_M;
			break;
		default:
			ecc_error_data.error_type = PLAT_ERROR_TYPE_UNK;
			break;
		}
		ecc_error_data.databit_type = PLAT_BIT_TYPE_MULTI;
		ecc_error_data.databit_no = 0; /* not used */
	}

#ifdef DEBUG
	if (invalid_unum &&
	    (ecc_error_data.error_code != PLAT_ERROR_CODE_UE) &&
	    unum && *unum)
		cmn_err(CE_WARN, "Unexpected unum string format: %s\n", unum);
#endif

	/*
	 * Send this data off as a mailbox message to the SC.
	 */
	(void) plat_send_ecc_mailbox_msg(PLAT_ECC_ERROR_MESSAGE,
	    &ecc_error_data);
}

/*
 * The unum string for memory is expected to be in this form:
 * "[/N0/]SB12/P0/B0/D2 [J13500]"
 * Or if the unum was generated as the result of a UE:
 * "[/N0/]SB12/P0/B0 [J13500, ...]"
 * From that we will extract the board number, processor position,
 * bank number and jnumber.
 *
 * Return (1) for an invalid unum string.  If the unum is for an
 * individual DIMM and there is no jnumber, jnumber will be set
 * to -1 and the caller can decide if the unum is valid.  This
 * is because Serengeti does not have jnumbers for bank unums
 * which may be used to create DIMM unums (e.g. for acquiring
 * DIMM serial ids).
 */

int
parse_unum_memory(char *unum, int *board, int *pos, int *bank, int *dimm,
    int *jnumber)
{
	char *c;

	if ((c = strstr(unum, "SB")) == NULL)
		return (1);
	c += 2;
	*board = (uint8_t)stoi(&c);

	if (*c++ != '/' || *c++ != 'P')
		return (1);
	*pos = stoi(&c);

	if (*c++ != '/' || *c++ != 'B')
		return (1);
	*bank = stoi(&c);

	if ((c = strchr(c, 'D')) == NULL) {
		*dimm = -1;
		*jnumber = 0;
		return (0);
	}
	c++;
	*dimm = stoi(&c);

	if ((c = strchr(c, 'J')) == NULL) {
		*jnumber = -1;
		return (0);
	}

	c++;
	*jnumber = (uint16_t)stoi(&c);

	return (0);
}

/*
 * The unum string for ecache is expected to be in this form:
 * "[/N0/][SB|IO]12/P0/E0 J13500, ..."
 * From that we will extract the board number, processor position and
 * junmber.
 *
 * return (1) for any invalid unum string.
 */
static int
parse_unum_ecache(char *unum, int *board, int *pos, int *jnumber, int *maxcat)
{
	char *c;

	if ((c = strstr(unum, "SB")) == NULL) {
		/*
		 * Since this is an E$ error, it must have occurred on
		 * either a System Board (represented by "SB" in the
		 * unum string) or a Maxcat board ("IO" in the unum
		 * string).
		 */
		if ((c = strstr(unum, "IO")) == NULL)
			return (1);
		*maxcat = 1;
	}

	c += 2;
	*board = (uint8_t)stoi(&c);

	if (*c++ != '/' || *c++ != 'P')
		return (1);
	*pos = stoi(&c);

	if ((c = strchr(c, 'J')) == NULL)
		return (1);

	c++;
	*jnumber = (uint16_t)stoi(&c);

	return (0);
}

/* The following array maps the error to its corresponding set */
static int plat_ecc_e2d_map[PLAT_ECC_ERROR2_NUMVALS] = {
	PLAT_ECC_ERROR2_NONE,			/* 0x00 */
	PLAT_ECC_ERROR2_SEND_L2_XXC,		/* 0x01 */
	PLAT_ECC_ERROR2_SEND_L2_XXU,		/* 0x02 */
	PLAT_ECC_ERROR2_SEND_L3_XXC,		/* 0x03 */
	PLAT_ECC_ERROR2_SEND_L3_XXU,		/* 0x04 */
	PLAT_ECC_ERROR2_SEND_MEM_ERRS,		/* 0x05 */
	PLAT_ECC_ERROR2_SEND_MEM_ERRS,		/* 0x06 */
	PLAT_ECC_ERROR2_SEND_MEM_ERRS,		/* 0x07 */
	PLAT_ECC_ERROR2_SEND_BUS_ERRS,		/* 0x08 */
	PLAT_ECC_ERROR2_SEND_BUS_ERRS,		/* 0x09 */
	PLAT_ECC_ERROR2_SEND_BUS_ERRS,		/* 0x0a */
	PLAT_ECC_ERROR2_SEND_BUS_ERRS,		/* 0x0b */
	PLAT_ECC_ERROR2_SEND_L2_TAG_ERRS,	/* 0x0c */
	PLAT_ECC_ERROR2_SEND_L2_TAG_ERRS,	/* 0x0d */
	PLAT_ECC_ERROR2_SEND_L3_TAG_ERRS,	/* 0x0e */
	PLAT_ECC_ERROR2_SEND_L3_TAG_ERRS,	/* 0x0f */
	PLAT_ECC_ERROR2_SEND_L1_PARITY,		/* 0x10 */
	PLAT_ECC_ERROR2_SEND_L1_PARITY,		/* 0x11 */
	PLAT_ECC_ERROR2_SEND_TLB_PARITY,	/* 0x12 */
	PLAT_ECC_ERROR2_SEND_TLB_PARITY,	/* 0x13 */
	PLAT_ECC_ERROR2_SEND_IV_ERRS,		/* 0x14 */
	PLAT_ECC_ERROR2_SEND_IV_ERRS,		/* 0x15 */
	PLAT_ECC_ERROR2_SEND_MTAG_XXC,		/* 0x16 */
	PLAT_ECC_ERROR2_SEND_IV_MTAG_XXC,	/* 0x17 */
	PLAT_ECC_ERROR2_SEND_L3_XXC,		/* 0x18 */
	PLAT_ECC_ERROR2_SEND_PCACHE		/* 0x19 */
};

/*
 * log enhanced error information to SC.
 */
void
plat_log_fruid_error2(int msg_type, char *unum, struct async_flt *aflt,
    plat_ecc_ch_async_flt_t *ecc_ch_flt)
{
	plat_ecc_error2_data_t e2d = {0};
	int board, pos, bank, dimm, jnumber;
	int maxcat = 0;
	uint16_t flags;

	/* Check the flags */
	flags = plat_ecc_e2d_map[msg_type];
	if ((ecc_error2_mailbox_flags & flags) == 0)
		return;

	/* Fill the header */
	e2d.ee2d_major_version = PLAT_ECC_ERROR2_VERSION_MAJOR;
	e2d.ee2d_minor_version = PLAT_ECC_ERROR2_VERSION_MINOR;
	e2d.ee2d_msg_type = PLAT_ECC_ERROR2_MESSAGE;
	e2d.ee2d_msg_length = sizeof (plat_ecc_error2_data_t);

	/* Fill the data */
	if (aflt->flt_in_memory) {
		if (parse_unum_memory(unum, &board, &pos, &bank, &dimm,
		    &jnumber) || (dimm != -1 && jnumber == -1))
			return;
		/*
		 * Using the SB number and Proc position we create a FRU
		 * cpu id.
		 */
		e2d.ee2d_owning_proc = plat_make_fru_cpuid(board, 0, pos);
		e2d.ee2d_jnumber = jnumber;
		e2d.ee2d_bank_number = bank;
	} else if (aflt->flt_status & ECC_ECACHE) {
		if (parse_unum_ecache(unum, &board, &pos, &jnumber, &maxcat))
			return;
		/*
		 * Using the SB number and Proc position we create a FRU
		 * cpu id.
		 */
		e2d.ee2d_owning_proc = plat_make_fru_cpuid(board, maxcat, pos);
		e2d.ee2d_jnumber = jnumber;
		e2d.ee2d_bank_number = (uint8_t)-1;
	} else {
		/*
		 * L1 Cache
		 */
		e2d.ee2d_owning_proc = aflt->flt_bus_id;
		e2d.ee2d_jnumber = (uint16_t)-1;
		e2d.ee2d_bank_number = (uint8_t)-1;
	}

	e2d.ee2d_type = (uint8_t)msg_type;
	e2d.ee2d_afar_status = (uint8_t)ecc_ch_flt->ecaf_afar_status;
	e2d.ee2d_synd_status = (uint8_t)ecc_ch_flt->ecaf_synd_status;
	e2d.ee2d_detecting_proc = aflt->flt_bus_id;
	e2d.ee2d_cpu_impl = cpunodes[e2d.ee2d_owning_proc].implementation;
	e2d.ee2d_timestamp = aflt->flt_id;
	e2d.ee2d_afsr = aflt->flt_stat;
	e2d.ee2d_afar = aflt->flt_addr;

	e2d.ee2d_sdw_afsr = ecc_ch_flt->ecaf_sdw_afsr;
	e2d.ee2d_sdw_afar = ecc_ch_flt->ecaf_sdw_afar;
	e2d.ee2d_afsr_ext = ecc_ch_flt->ecaf_afsr_ext;
	e2d.ee2d_sdw_afsr_ext = ecc_ch_flt->ecaf_sdw_afsr_ext;

	/* Send the message to SC */
	(void) plat_send_ecc_mailbox_msg(PLAT_ECC_ERROR2_MESSAGE, &e2d);
}

uint8_t ecc_indictment_mailbox_disable = PLAT_ECC_INDICTMENT_OK;
uint8_t ecc_indictment_mailbox_flags = PLAT_ECC_SEND_DEFAULT_INDICT;

/*
 * We log all Solaris indictments of failing hardware.  We pull the system
 * board number and jnumber out of the unum string, and calculate the cpuid
 * from some members of the unum string.  The rest of the structure is filled
 * in through the other arguments.  The data structure is then passed to
 * plat_ecc_dispatch_task().  This function should only be loaded into memory
 * or called on platforms that define a plat_send_ecc_mailbox_msg() function.
 */
static int
plat_log_fruid_indictment(int msg_type, struct async_flt *aflt, char *unum)
{
	plat_ecc_message_t *wrapperp;
	plat_ecc_indict_msg_contents_t *contentsp;
	char *unum_ptr;
	int is_maxcat = 0;

	switch (ecc_indictment_mailbox_disable) {
	case (PLAT_ECC_INDICTMENT_OK):
	case (PLAT_ECC_INDICTMENT_SUSPECT):
		break;
	case (PLAT_ECC_INDICTMENT_NO_SEND):
	default:
		return (ECONNREFUSED);
	}

	switch (msg_type) {
	case (PLAT_ECC_INDICT_DIMM):
		if ((ecc_indictment_mailbox_flags &
		    PLAT_ECC_SEND_DIMM_INDICT) == 0)
			return (ECONNREFUSED);
		break;
	case (PLAT_ECC_INDICT_ECACHE_CORRECTABLES):
		if ((ecc_indictment_mailbox_flags &
		    PLAT_ECC_SEND_ECACHE_XXC_INDICT) == 0)
			return (ECONNREFUSED);
		break;
	case (PLAT_ECC_INDICT_ECACHE_UNCORRECTABLE):
		if ((ecc_indictment_mailbox_flags &
		    PLAT_ECC_SEND_ECACHE_XXU_INDICT) == 0)
			return (ECONNREFUSED);
		break;
	default:
		return (ECONNREFUSED);
	}

	/* LINTED: E_TRUE_LOGICAL_EXPR */
	ASSERT(sizeof (plat_ecc_indictment_data_t) == PLAT_ECC_INDICT_SIZE);

	wrapperp = (plat_ecc_message_t *)
	    kmem_zalloc(sizeof (plat_ecc_message_t), KM_SLEEP);

	wrapperp->ecc_msg_status = PLAT_ECC_NO_MSG_ACTIVE;
	wrapperp->ecc_msg_type = PLAT_ECC_INDICTMENT_MESSAGE;
	wrapperp->ecc_msg_len = sizeof (plat_ecc_indictment_data_t);
	wrapperp->ecc_msg_data = kmem_zalloc(wrapperp->ecc_msg_len, KM_SLEEP);

	contentsp = &(((plat_ecc_indictment_data_t *)
	    wrapperp->ecc_msg_data)->msg_contents);

	/*
	 * Find board_num, jnumber, and proc position from the unum string.
	 * Use the board number, is_maxcat, and proc position to calculate
	 * cpuid.
	 */
	unum_ptr = strstr(unum, "SB");
	if (unum_ptr == NULL) {
		is_maxcat = 1;
		unum_ptr = strstr(unum, "IO");
		if (unum_ptr == NULL) {
			kmem_free(wrapperp->ecc_msg_data,
			    wrapperp->ecc_msg_len);
			kmem_free(wrapperp, sizeof (plat_ecc_message_t));
			return (EINVAL);
		}
	}
	unum_ptr += 2;
	contentsp->board_num = (uint8_t)stoi(&unum_ptr);

	unum_ptr = strchr(unum_ptr, 'P');
	if (unum_ptr == NULL) {
		kmem_free(wrapperp->ecc_msg_data, wrapperp->ecc_msg_len);
		kmem_free(wrapperp, sizeof (plat_ecc_message_t));
		return (EINVAL);
	}
	unum_ptr++;
	contentsp->detecting_proc =
	    (uint16_t)plat_make_fru_cpuid(contentsp->board_num, is_maxcat,
	    stoi(&unum_ptr));

	unum_ptr = strchr(unum_ptr, 'J');
	if (unum_ptr == NULL) {
		kmem_free(wrapperp->ecc_msg_data, wrapperp->ecc_msg_len);
		kmem_free(wrapperp, sizeof (plat_ecc_message_t));
		return (EINVAL);
	}
	unum_ptr++;
	contentsp->jnumber = (uint16_t)stoi(&unum_ptr);

	/*
	 * Fill in the rest of the data
	 */
	contentsp->version = PLAT_ECC_INDICTMENT_VERSION;
	contentsp->indictment_type = msg_type;
	contentsp->indictment_uncertain = ecc_indictment_mailbox_disable;
	contentsp->syndrome = aflt->flt_synd;
	contentsp->afsr = aflt->flt_stat;
	contentsp->afar = aflt->flt_addr;

	/*
	 * Build the solaris_version string:
	 */
	(void) snprintf(contentsp->solaris_version,
	    PLAT_ECC_VERSION_LENGTH, "%s %s", utsname.release, utsname.version);

	/*
	 * Send the data on to the queuing function
	 */
	return (plat_ecc_dispatch_task(wrapperp));
}

/* The following array maps the indictment to its corresponding set */
static int plat_ecc_i2d_map[PLAT_ECC_INDICT2_NUMVALS] = {
	PLAT_ECC_INDICT2_NONE,			/* 0x00 */
	PLAT_ECC_SEND_INDICT2_L2_XXU,		/* 0x01 */
	PLAT_ECC_SEND_INDICT2_L2_XXC_SERD,	/* 0x02 */
	PLAT_ECC_SEND_INDICT2_L2_TAG_SERD,	/* 0x03 */
	PLAT_ECC_SEND_INDICT2_L3_XXU,		/* 0x04 */
	PLAT_ECC_SEND_INDICT2_L3_XXC_SERD,	/* 0x05 */
	PLAT_ECC_SEND_INDICT2_L3_TAG_SERD,	/* 0x06 */
	PLAT_ECC_SEND_INDICT2_L1_SERD,		/* 0x07 */
	PLAT_ECC_SEND_INDICT2_L1_SERD,		/* 0x08 */
	PLAT_ECC_SEND_INDICT2_TLB_SERD,		/* 0x09 */
	PLAT_ECC_SEND_INDICT2_TLB_SERD,		/* 0x0a */
	PLAT_ECC_SEND_INDICT2_FPU,		/* 0x0b */
	PLAT_ECC_SEND_INDICT2_PCACHE_SERD	/* 0x0c */
};

static int
plat_log_fruid_indictment2(int msg_type, struct async_flt *aflt, char *unum)
{
	plat_ecc_message_t *wrapperp;
	plat_ecc_indictment2_data_t *i2d;
	int board, pos, jnumber;
	int maxcat = 0;
	uint16_t flags;

	/*
	 * If the unum is null or empty, skip parsing it
	 */
	if (unum && unum[0] != '\0') {
		if (parse_unum_ecache(unum, &board, &pos, &jnumber, &maxcat))
			return (EINVAL);
	}

	if ((ecc_indictment_mailbox_disable != PLAT_ECC_INDICTMENT_OK) &&
	    (ecc_indictment_mailbox_disable != PLAT_ECC_INDICTMENT_SUSPECT))
		return (ECONNREFUSED);

	/* Check the flags */
	flags = plat_ecc_i2d_map[msg_type];
	if ((ecc_indictment2_mailbox_flags & flags) == 0)
		return (ECONNREFUSED);

	wrapperp = (plat_ecc_message_t *)
	    kmem_zalloc(sizeof (plat_ecc_message_t), KM_SLEEP);

	/* Initialize the wrapper */
	wrapperp->ecc_msg_status = PLAT_ECC_NO_MSG_ACTIVE;
	wrapperp->ecc_msg_type = PLAT_ECC_INDICTMENT2_MESSAGE;
	wrapperp->ecc_msg_len = sizeof (plat_ecc_indictment2_data_t);
	wrapperp->ecc_msg_data = kmem_zalloc(wrapperp->ecc_msg_len, KM_SLEEP);

	i2d = (plat_ecc_indictment2_data_t *)wrapperp->ecc_msg_data;

	/* Fill the header */
	i2d->ei2d_major_version = PLAT_ECC_INDICT2_MAJOR_VERSION;
	i2d->ei2d_minor_version = PLAT_ECC_INDICT2_MINOR_VERSION;
	i2d->ei2d_msg_type = PLAT_ECC_INDICTMENT2_MESSAGE;
	i2d->ei2d_msg_length = sizeof (plat_ecc_indictment2_data_t);

	/* Fill the data */
	if (unum && unum[0] != '\0') {
		i2d->ei2d_arraigned_proc = plat_make_fru_cpuid(board, maxcat,
		    pos);
		i2d->ei2d_board_num = board;
		i2d->ei2d_jnumber = jnumber;
	} else {
		i2d->ei2d_arraigned_proc = aflt->flt_inst;
		i2d->ei2d_board_num = (uint8_t)
		    plat_make_fru_boardnum(i2d->ei2d_arraigned_proc);
		i2d->ei2d_jnumber = (uint16_t)-1;
	}

	i2d->ei2d_type = msg_type;
	i2d->ei2d_uncertain = ecc_indictment_mailbox_disable;
	i2d->ei2d_cpu_impl = cpunodes[i2d->ei2d_arraigned_proc].implementation;
	i2d->ei2d_timestamp = aflt->flt_id;

	/*
	 * Send the data on to the queuing function
	 */
	return (plat_ecc_dispatch_task(wrapperp));
}

int
plat_ecc_capability_send(void)
{
	plat_ecc_message_t *wrapperp;
	plat_capability_data_t	*cap;
	int ver_len;

	wrapperp = kmem_zalloc(sizeof (plat_ecc_message_t), KM_SLEEP);

	ver_len = strlen(utsname.release) + strlen(utsname.version) + 2;

	/* Initialize the wrapper */
	wrapperp->ecc_msg_status = PLAT_ECC_NO_MSG_ACTIVE;
	wrapperp->ecc_msg_type = PLAT_ECC_CAPABILITY_MESSAGE;
	wrapperp->ecc_msg_len = sizeof (plat_capability_data_t) + ver_len;
	wrapperp->ecc_msg_data = kmem_zalloc(wrapperp->ecc_msg_len, KM_SLEEP);

	cap = (plat_capability_data_t *)wrapperp->ecc_msg_data;

	/* Fill the header */
	cap->capd_major_version = PLAT_ECC_CAP_VERSION_MAJOR;
	cap->capd_minor_version = PLAT_ECC_CAP_VERSION_MINOR;
	cap->capd_msg_type = PLAT_ECC_CAPABILITY_MESSAGE;
	cap->capd_msg_length = wrapperp->ecc_msg_len;

	/* Set the default domain capability */
	cap->capd_capability = PLAT_ECC_CAPABILITY_DOMAIN_DEFAULT;

	/*
	 * Build the solaris_version string:
	 * utsname.release + " " + utsname.version
	 */
	(void) snprintf(cap->capd_solaris_version, ver_len, "%s %s",
	    utsname.release, utsname.version);

	/*
	 * Send the data on to the queuing function
	 */
	return (plat_ecc_dispatch_task(wrapperp));
}

int
plat_ecc_capability_sc_get(int type)
{
	switch (type) {
		case PLAT_ECC_ERROR_MESSAGE:
			if (ecc_log_fruid_enable &&
			    (!(plat_ecc_capability_map_sc &
			    PLAT_ECC_CAPABILITY_ERROR2)))
				return (1);
			break;
		case PLAT_ECC_ERROR2_MESSAGE:
			if (plat_ecc_capability_map_sc &
			    PLAT_ECC_CAPABILITY_ERROR2)
				return (1);
			break;
		case PLAT_ECC_INDICTMENT_MESSAGE:
			if (!(plat_ecc_capability_map_sc &
			    PLAT_ECC_CAPABILITY_INDICT2) ||
			    !(plat_ecc_capability_map_domain &
			    PLAT_ECC_CAPABILITY_FMA))
				return (1);
			break;
		case PLAT_ECC_INDICTMENT2_MESSAGE:
			if (plat_ecc_capability_map_sc &
			    PLAT_ECC_CAPABILITY_INDICT2)
				return (1);
			break;
		case PLAT_ECC_DIMM_SID_MESSAGE:
			if (plat_ecc_capability_map_sc &
			    PLAT_ECC_CAPABILITY_DIMM_SID)
				return (1);
		default:
			return (0);
	}
	return (0);
}

int plat_ecc_cap_sc_set_cnt = 0;

void
plat_ecc_capability_sc_set(uint32_t cap)
{
	plat_ecc_capability_map_sc = cap;

	if (!plat_ecc_cap_sc_set_cnt && (cap & PLAT_ECC_CAPABILITY_DIMM_SID))
		if (p2init_sid_cache)
			p2init_sid_cache();

	plat_ecc_cap_sc_set_cnt++;
}

/*
 * The following table represents mapping between the indictment1 reason
 * to its type.
 */

static plat_ecc_bl_map_t plat_ecc_bl_map_v1[] = {
	{ "l2cachedata",	PLAT_ECC_INDICT_ECACHE_CORRECTABLES	},
	{ "l3cachedata",	PLAT_ECC_INDICT_ECACHE_CORRECTABLES	},
	{ "l2cachedata",	PLAT_ECC_INDICT_ECACHE_UNCORRECTABLE	},
	{ "l3cachedata",	PLAT_ECC_INDICT_ECACHE_UNCORRECTABLE	}
};

/*
 * The following table represents mapping between the indictment2 reason
 * to its type.
 */

static plat_ecc_bl_map_t plat_ecc_bl_map_v2[] = {
	{ "l2cachedata",	PLAT_ECC_INDICT2_L2_SERD	},
	{ "l3cachedata",	PLAT_ECC_INDICT2_L3_SERD	},
	{ "l2cachedata",	PLAT_ECC_INDICT2_L2_UE		},
	{ "l3cachedata",	PLAT_ECC_INDICT2_L3_UE		},
	{ "l2cachetag",		PLAT_ECC_INDICT2_L2_TAG_SERD	},
	{ "l3cachetag",		PLAT_ECC_INDICT2_L3_TAG_SERD	},
	{ "icache",		PLAT_ECC_INDICT2_ICACHE_SERD	},
	{ "dcache",		PLAT_ECC_INDICT2_DCACHE_SERD	},
	{ "pcache",		PLAT_ECC_INDICT2_PCACHE_SERD	},
	{ "itlb",		PLAT_ECC_INDICT2_ITLB_SERD	},
	{ "dtlb",		PLAT_ECC_INDICT2_DTLB_SERD	},
	{ "fpu",		PLAT_ECC_INDICT2_FPU		}
};

/*
 * The following function returns the indictment type for a given version
 */
static int
flt_name_to_msg_type(const char *fault, int indict_version)
{
	plat_ecc_bl_map_t *mapp;
	char *fltnm = "fault.cpu.";
	int mapsz;
	char *p;
	int i;

	/* Check if it starts with proper fault name */
	if (strncmp(fault, fltnm, strlen(fltnm)) != 0)
		return (PLAT_ECC_INDICT_NONE);

	fault += strlen(fltnm); /* c = "ultraSPARC-IV.icache" */

	/* Skip the cpu type */
	if ((p = strchr(fault, '.')) == NULL)
		return (PLAT_ECC_INDICT_NONE);

	p++;	/* skip the "." */

	if (indict_version ==  0) {
		mapp = plat_ecc_bl_map_v1;
		mapsz = sizeof (plat_ecc_bl_map_v1) /
		    sizeof (plat_ecc_bl_map_t);
	} else {
		mapp = plat_ecc_bl_map_v2;
		mapsz = sizeof (plat_ecc_bl_map_v2) /
		    sizeof (plat_ecc_bl_map_t);
	}
	for (i = 0; i < mapsz; i++) {
		if (strcmp(p, mapp[i].ebm_reason) == 0) {
			return (mapp[i].ebm_type);
		}
	}
	return (PLAT_ECC_INDICT_NONE);
}

/*
 * Blacklisting
 */
int
plat_blacklist(int cmd, const char *scheme, nvlist_t *fmri, const char *class)
{
	struct async_flt aflt;
	char *unum;
	int msg_type, is_old_indict;

	if (fmri == NULL)
		return (EINVAL);
	if (cmd != BLIOC_INSERT)
		return (ENOTSUP);

	/*
	 * We support both the blacklisting of CPUs via mem-schemed
	 * FMRIs that name E$ J-numbers, and CPUs via cpu-schemed FMRIs
	 * that name the cpuid.
	 */
	if (strcmp(scheme, FM_FMRI_SCHEME_MEM) == 0) {
		if (nvlist_lookup_string(fmri, FM_FMRI_MEM_UNUM, &unum))
			return (EINVAL);
		aflt.flt_inst = (uint_t)-1;
	} else if (strcmp(scheme, FM_FMRI_SCHEME_CPU) == 0) {
		if (nvlist_lookup_uint32(fmri, FM_FMRI_CPU_ID, &aflt.flt_inst))
			return (EINVAL);
		unum = NULL;
	} else {
		return (ENOTSUP);
	}

	/*
	 * If the SC cannot handle indictment2, so fall back to old one.
	 * Also if the domain does not support FMA, then send only the old one.
	 */

	is_old_indict = plat_ecc_capability_sc_get(PLAT_ECC_INDICTMENT_MESSAGE);

	if (is_old_indict)
		msg_type = flt_name_to_msg_type(class, 0);
	else
		msg_type = flt_name_to_msg_type(class, 1);

	if (msg_type == PLAT_ECC_INDICT_NONE)
		return (ENOTSUP);

	/*
	 * The current blacklisting interfaces are designed for a world where
	 * the SC is much more involved in the diagnosis and error reporting
	 * process than it is in the FMA world.  As such, the existing
	 * interfaces want all kinds of information about the error that's
	 * triggering the blacklist.  In the FMA world, we don't have access
	 * to any of that information by the time we're doing the blacklist,
	 * so we fake values.
	 */
	aflt.flt_id = gethrtime();
	aflt.flt_addr = -1;
	aflt.flt_stat = -1;
	aflt.flt_synd = (ushort_t)-1;

	if (is_old_indict) {
		if (unum && unum[0] != '\0')
			return (plat_log_fruid_indictment(msg_type, &aflt,
			    unum));
		else
			return (ENOTSUP);
	} else {
		return (plat_log_fruid_indictment2(msg_type, &aflt, unum));
	}
}

static kcondvar_t plat_ecc_condvar;
static kmutex_t plat_ecc_mutex;
static taskq_t *plat_ecc_taskq;

/*
 * plat_ecc_dispatch_task: Dispatch the task on a taskq and wait for the
 * return value.  We use cv_wait_sig to wait for the return values.  If a
 * signal interrupts us, we return EINTR.  Otherwise, we return the value
 * returned by the mailbox functions.
 *
 * To avoid overloading the lower-level mailbox routines, we use a taskq
 * to serialize all messages.  Currently, it is expected that only one
 * process (fmd) will use this ioctl, so the delay caused by the taskq
 * should not have much of an effect.
 */
int
plat_ecc_dispatch_task(plat_ecc_message_t *msg)
{
	int ret;

	ASSERT(msg != NULL);
	ASSERT(plat_ecc_taskq != NULL);

	if (taskq_dispatch(plat_ecc_taskq, plat_ecc_send_msg,
	    (void *)msg, TQ_NOSLEEP) == TASKQID_INVALID) {
		kmem_free(msg->ecc_msg_data, msg->ecc_msg_len);
		kmem_free(msg, sizeof (plat_ecc_message_t));
		return (ENOMEM);
	}
	mutex_enter(&plat_ecc_mutex);

	/*
	 * It's possible that the taskq function completed before we
	 * acquired the mutex.  Check for this first.  If this did not
	 * happen, we wait for the taskq function to signal us, or an
	 * interrupt.  We also check ecc_msg_status to protect against
	 * spurious wakeups from cv_wait_sig.
	 */
	if (msg->ecc_msg_status == PLAT_ECC_MSG_SENT) {
		ret = msg->ecc_msg_ret;
		kmem_free(msg->ecc_msg_data, msg->ecc_msg_len);
		kmem_free(msg, sizeof (plat_ecc_message_t));
	} else {
		msg->ecc_msg_status = PLAT_ECC_TASK_DISPATCHED;

		while ((ret = cv_wait_sig(&plat_ecc_condvar,
		    &plat_ecc_mutex)) != 0 &&
		    msg->ecc_msg_status == PLAT_ECC_TASK_DISPATCHED)
			;

		if ((ret == 0) && (msg->ecc_msg_status != PLAT_ECC_MSG_SENT)) {
			/* An interrupt was received */
			msg->ecc_msg_status = PLAT_ECC_INTERRUPT_RECEIVED;
			ret = EINTR;
		} else {
			ret = msg->ecc_msg_ret;
			kmem_free(msg->ecc_msg_data, msg->ecc_msg_len);
			kmem_free(msg, sizeof (plat_ecc_message_t));
		}
	}
	mutex_exit(&plat_ecc_mutex);
	return (ret);
}

static void
plat_ecc_send_msg(void *arg)
{
	plat_ecc_message_t *msg = arg;
	int ret;

	/*
	 * Send this data off as a mailbox message to the SC.
	 */
	ret = plat_send_ecc_mailbox_msg(msg->ecc_msg_type, msg->ecc_msg_data);

	mutex_enter(&plat_ecc_mutex);

	/*
	 * If the dispatching function received an interrupt, don't bother
	 * signalling it, and throw away the results.  Otherwise, set the
	 * return value and signal the condvar.
	 */
	if (msg->ecc_msg_status == PLAT_ECC_INTERRUPT_RECEIVED) {
		kmem_free(msg->ecc_msg_data, msg->ecc_msg_len);
		kmem_free(msg, sizeof (plat_ecc_message_t));
	} else {
		msg->ecc_msg_ret = ret;
		msg->ecc_msg_status = PLAT_ECC_MSG_SENT;
		cv_broadcast(&plat_ecc_condvar);
	}

	mutex_exit(&plat_ecc_mutex);
}

void
plat_ecc_init(void)
{
	int	bd;

	mutex_init(&plat_ecc_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&plat_ecc_condvar, NULL, CV_DEFAULT, NULL);
	plat_ecc_taskq = taskq_create("plat_ecc_taskq", 1, minclsyspri,
	    PLAT_ECC_TASKQ_MIN, PLAT_ECC_TASKQ_MAX, TASKQ_PREPOPULATE);
	ASSERT(plat_ecc_taskq != NULL);

	for (bd = 0; bd < plat_max_cpumem_boards(); bd++) {
		mutex_init(&domain_dimm_sids[bd].pdsb_lock,
		    NULL, MUTEX_DEFAULT, NULL);
	}

}
