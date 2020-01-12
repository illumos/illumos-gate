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
 * Print out information about a CCID device.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <ofmt.h>
#include <libgen.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <libcmdutils.h>
#include <fts.h>

#include <sys/usb/clients/ccid/uccid.h>
#include <atr.h>

#define	EXIT_USAGE	2

static const char *ccidadm_pname;

#define	CCID_ROOT	"/dev/ccid/"

typedef enum {
	CCIDADM_LIST_DEVICE,
	CCIDADM_LIST_PRODUCT,
	CCIDADM_LIST_STATE,
	CCIDADM_LIST_TRANSPORT,
	CCIDADM_LIST_SUPPORTED,
} ccidadm_list_index_t;

typedef struct ccidadm_pair {
	uint32_t	ccp_val;
	const char	*ccp_name;
} ccidadm_pair_t;

typedef struct ccid_list_ofmt_arg {
	const char		*cloa_name;
	uccid_cmd_status_t	*cloa_status;
} ccid_list_ofmt_arg_t;

/*
 * Attempt to open a CCID slot specified by a user. In general, we expect that
 * users will use a path like "ccid0/slot0". However, they may also specify a
 * full path. If the card boolean is set to true, that means that they may have
 * just specified "ccid0", so we need to try to open up the default slot.
 */
static int
ccidadm_open(const char *base, boolean_t card)
{
	int fd;
	char buf[PATH_MAX];

	/*
	 * If it's an absolute path, just try to open it.
	 */
	if (base[0] == '/') {
		return (open(base, O_RDWR));
	}

	/*
	 * For a card, try to append slot0 first.
	 */
	if (card) {
		if (snprintf(buf, sizeof (buf), "%s/%s/slot0", CCID_ROOT,
		    base) >= sizeof (buf)) {
			errno = ENAMETOOLONG;
			return (-1);
		}

		if ((fd = open(buf, O_RDWR)) >= 0) {
			return (fd);
		}

		if (errno != ENOENT && errno != ENOTDIR) {
			return (fd);
		}
	}

	if (snprintf(buf, sizeof (buf), "%s/%s", CCID_ROOT, base) >=
	    sizeof (buf)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (open(buf, O_RDWR));
}

static void
ccidadm_iter(boolean_t readeronly, boolean_t newline,
    void(*cb)(int, const char *, void *), void *arg)
{
	FTS *fts;
	FTSENT *ent;
	char *const paths[] = { CCID_ROOT, NULL };
	int fd;
	boolean_t first = B_TRUE;

	fts = fts_open(paths, FTS_LOGICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		err(EXIT_FAILURE, "failed to create directory stream");
	}

	while ((ent = fts_read(fts)) != NULL) {
		const char *name;

		/* Skip the root and post-order dirs */
		if (ent->fts_level == 0 || ent->fts_info == FTS_DP) {
			continue;
		}
		if (readeronly && ent->fts_level != 1) {
			continue;
		} else if (!readeronly && ent->fts_level != 2) {
			continue;
		}

		if (ent->fts_info == FTS_ERR || ent->fts_info == FTS_NS) {
			warn("skipping %s, failed to get information: %s",
			    ent->fts_name, strerror(ent->fts_errno));
			continue;
		}

		name = ent->fts_path + strlen(CCID_ROOT);
		if ((fd = ccidadm_open(name, readeronly)) < 0) {
			err(EXIT_FAILURE, "failed to open %s", name);
		}

		if (!first && newline) {
			(void) printf("\n");
		}
		first = B_FALSE;
		cb(fd, name, arg);
		(void) close(fd);
	}

	(void) fts_close(fts);
}

static void
ccidadm_list_slot_status_str(uccid_cmd_status_t *ucs, char *buf, uint_t buflen)
{
	if (!(ucs->ucs_status & UCCID_STATUS_F_CARD_PRESENT)) {
		(void) snprintf(buf, buflen, "missing");
		return;
	}

	if (ucs->ucs_status & UCCID_STATUS_F_CARD_ACTIVE) {
		(void) snprintf(buf, buflen, "activated");
		return;
	}

	(void) snprintf(buf, buflen, "unactivated");
}

static boolean_t
ccidadm_list_slot_transport_str(uccid_cmd_status_t *ucs, char *buf,
    uint_t buflen)
{
	const char *prot;
	const char *tran;
	uint_t bits = CCID_CLASS_F_TPDU_XCHG | CCID_CLASS_F_SHORT_APDU_XCHG |
	    CCID_CLASS_F_EXT_APDU_XCHG;

	switch (ucs->ucs_class.ccd_dwFeatures & bits) {
	case 0:
		tran = "character";
		break;
	case CCID_CLASS_F_TPDU_XCHG:
		tran = "TPDU";
		break;
	case CCID_CLASS_F_SHORT_APDU_XCHG:
	case CCID_CLASS_F_EXT_APDU_XCHG:
		tran = "APDU";
		break;
	default:
		tran = "unknown";
		break;
	}

	if ((ucs->ucs_status & UCCID_STATUS_F_PARAMS_VALID) != 0) {
		switch (ucs->ucs_prot) {
		case UCCID_PROT_T0:
			prot = " (T=0)";
			break;
		case UCCID_PROT_T1:
			prot = " (T=1)";
			break;
		default:
			prot = "";
			break;
		}
	} else {
		prot = "";
	}

	return (snprintf(buf, buflen, "%s%s", tran, prot) < buflen);
}

static boolean_t
ccidadm_list_slot_usable_str(uccid_cmd_status_t *ucs, char *buf,
    uint_t buflen)
{
	char *un = "";
	ccid_class_features_t feat;
	uint_t prot = CCID_CLASS_F_SHORT_APDU_XCHG | CCID_CLASS_F_EXT_APDU_XCHG;
	uint_t param = CCID_CLASS_F_AUTO_PARAM_NEG | CCID_CLASS_F_AUTO_PPS;
	uint_t clock = CCID_CLASS_F_AUTO_BAUD | CCID_CLASS_F_AUTO_ICC_CLOCK;

	feat = ucs->ucs_class.ccd_dwFeatures;

	if ((feat & prot) == 0 ||
	    (feat & param) != param ||
	    (feat & clock) != clock) {
		un = "un";
	}

	return (snprintf(buf, buflen, "%ssupported", un) < buflen);
}

static boolean_t
ccidadm_list_ofmt_cb(ofmt_arg_t *ofmt, char *buf, uint_t buflen)
{
	ccid_list_ofmt_arg_t *cloa = ofmt->ofmt_cbarg;

	switch (ofmt->ofmt_id) {
	case CCIDADM_LIST_DEVICE:
		if (snprintf(buf, buflen, "%s", cloa->cloa_name) >= buflen) {
			return (B_FALSE);
		}
		break;
	case CCIDADM_LIST_PRODUCT:
		if (snprintf(buf, buflen, "%s",
		    cloa->cloa_status->ucs_product) >= buflen) {
			return (B_FALSE);
		}
		break;
	case CCIDADM_LIST_STATE:
		ccidadm_list_slot_status_str(cloa->cloa_status, buf, buflen);
		break;
	case CCIDADM_LIST_TRANSPORT:
		return (ccidadm_list_slot_transport_str(cloa->cloa_status, buf,
		    buflen));
		break;
	case CCIDADM_LIST_SUPPORTED:
		return (ccidadm_list_slot_usable_str(cloa->cloa_status, buf,
		    buflen));
		break;
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
ccidadm_list_slot(int slotfd, const char *name, void *arg)
{
	uccid_cmd_status_t ucs;
	ofmt_handle_t ofmt = arg;
	ccid_list_ofmt_arg_t cloa;

	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;

	if (ioctl(slotfd, UCCID_CMD_STATUS, &ucs) != 0) {
		err(EXIT_FAILURE, "failed to issue status ioctl to %s", name);
	}

	if ((ucs.ucs_status & UCCID_STATUS_F_PRODUCT_VALID) == 0) {
		(void) strlcpy(ucs.ucs_product, "<unknown>",
		    sizeof (ucs.ucs_product));
	}

	cloa.cloa_name = name;
	cloa.cloa_status = &ucs;
	ofmt_print(ofmt, &cloa);
}

static ofmt_field_t ccidadm_list_fields[] = {
	{ "PRODUCT",	24,	CCIDADM_LIST_PRODUCT,	ccidadm_list_ofmt_cb },
	{ "DEVICE",	16,	CCIDADM_LIST_DEVICE,	ccidadm_list_ofmt_cb },
	{ "CARD STATE",	12,	CCIDADM_LIST_STATE,	ccidadm_list_ofmt_cb },
	{ "TRANSPORT",	12,	CCIDADM_LIST_TRANSPORT,	ccidadm_list_ofmt_cb },
	{ "SUPPORTED",	12,	CCIDADM_LIST_SUPPORTED,	ccidadm_list_ofmt_cb },
	{ NULL,		0,	0,			NULL	}
};

static void
ccidadm_do_list(int argc, char *argv[])
{
	ofmt_handle_t ofmt;

	if (argc != 0) {
		errx(EXIT_USAGE, "list command does not take arguments\n");
	}

	if (ofmt_open(NULL, ccidadm_list_fields, 0, 0, &ofmt) != OFMT_SUCCESS) {
		errx(EXIT_FAILURE, "failed to initialize ofmt state");
	}

	ccidadm_iter(B_FALSE, B_FALSE, ccidadm_list_slot, ofmt);
	ofmt_close(ofmt);
}

static void
ccidadm_list_usage(FILE *out)
{
	(void) fprintf(out, "\tlist\n");
}

/*
 * Print out logical information about the ICC's ATR. This includes information
 * about what protocols it supports, required negotiation, etc.
 */
static void
ccidadm_atr_props(uccid_cmd_status_t *ucs)
{
	int ret;
	atr_data_t *data;
	atr_protocol_t prots, defprot;
	boolean_t negotiate;
	atr_data_rate_choice_t rate;
	uint32_t bps;

	if ((data = atr_data_alloc()) == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory for "
		    "ATR data");
	}

	ret = atr_parse(ucs->ucs_atr, ucs->ucs_atrlen, data);
	if (ret != ATR_CODE_OK) {
		errx(EXIT_FAILURE, "failed to parse ATR data: %s",
		    atr_strerror(ret));
	}

	prots = atr_supported_protocols(data);
	(void) printf("ICC supports protocol(s): ");
	if (prots == ATR_P_NONE) {
		(void) printf("none\n");
		atr_data_free(data);
		return;
	}

	(void) printf("%s\n", atr_protocol_to_string(prots));

	negotiate = atr_params_negotiable(data);
	defprot = atr_default_protocol(data);

	if (negotiate) {
		(void) printf("Card protocol is negotiable; starts with "
		    "default %s parameters\n", atr_protocol_to_string(defprot));
	} else {
		(void) printf("Card protocol is not negotiable; starts with "
		    "specific %s parameters\n",
		    atr_protocol_to_string(defprot));
	}

	/*
	 * For each supported protocol, figure out parameters we would
	 * negotiate. We only need to warn about auto-negotiation if this
	 * is TPDU or character and specific bits are missing.
	 */
	if (((ucs->ucs_class.ccd_dwFeatures & (CCID_CLASS_F_SHORT_APDU_XCHG |
	    CCID_CLASS_F_EXT_APDU_XCHG)) == 0) &&
	    ((ucs->ucs_class.ccd_dwFeatures & (CCID_CLASS_F_AUTO_PARAM_NEG |
	    CCID_CLASS_F_AUTO_PPS)) == 0)) {
		(void) printf("CCID/ICC require explicit TPDU parameter/PPS "
		    "negotiation\n");
	}

	/*
	 * Determine which set of Di/Fi values we should use and how we should
	 * get there (note a reader may not have to set them).
	 */
	rate = atr_data_rate(data, &ucs->ucs_class, NULL, 0, &bps);
	switch (rate) {
	case ATR_RATE_USEDEFAULT:
		(void) printf("Reader will run ICC at the default (Di=1/Fi=1) "
		    "speed\n");
		break;
	case ATR_RATE_USEATR:
		(void) printf("Reader will run ICC at ICC's Di/Fi values\n");
		break;
	case ATR_RATE_USEATR_SETRATE:
		(void) printf("Reader will run ICC at ICC's Di/Fi values, but "
		    "must set data rate to %u bps\n", bps);
		break;
	case ATR_RATE_UNSUPPORTED:
		(void) printf("Reader cannot run ICC due to Di/Fi mismatch\n");
		break;
	default:
		(void) printf("Cannot determine Di/Fi rate, unexpected "
		    "value: %u\n", rate);
		break;
	}
	if (prots & ATR_P_T0) {
		uint8_t fi, di;
		atr_convention_t conv;
		atr_clock_stop_t clock;

		fi = atr_fi_index(data);
		di = atr_di_index(data);
		conv = atr_convention(data);
		clock = atr_clock_stop(data);
		(void) printf("T=0 properties that would be negotiated:\n");
		(void) printf("  + Fi/Fmax Index: %u (Fi %s/Fmax %s MHz)\n",
		    fi, atr_fi_index_to_string(fi),
		    atr_fmax_index_to_string(fi));
		(void) printf("  + Di Index: %u (Di %s)\n", di,
		    atr_di_index_to_string(di));
		(void) printf("  + Clock Convention: %u (%s)\n", conv,
		    atr_convention_to_string(conv));
		(void) printf("  + Extra Guardtime: %u\n",
		    atr_extra_guardtime(data));
		(void) printf("  + WI: %u\n", atr_t0_wi(data));
		(void) printf("  + Clock Stop: %u (%s)\n", clock,
		    atr_clock_stop_to_string(clock));
	}

	if (prots & ATR_P_T1) {
		uint8_t fi, di;
		atr_clock_stop_t clock;
		atr_t1_checksum_t cksum;

		fi = atr_fi_index(data);
		di = atr_di_index(data);
		clock = atr_clock_stop(data);
		cksum = atr_t1_checksum(data);
		(void) printf("T=1 properties that would be negotiated:\n");
		(void) printf("  + Fi/Fmax Index: %u (Fi %s/Fmax %s MHz)\n",
		    fi, atr_fi_index_to_string(fi),
		    atr_fmax_index_to_string(fi));
		(void) printf("  + Di Index: %u (Di %s)\n", di,
		    atr_di_index_to_string(di));
		(void) printf("  + Checksum: %s\n",
		    cksum == ATR_T1_CHECKSUM_CRC ? "CRC" : "LRC");
		(void) printf("  + Extra Guardtime: %u\n",
		    atr_extra_guardtime(data));
		(void) printf("  + BWI: %u\n", atr_t1_bwi(data));
		(void) printf("  + CWI: %u\n", atr_t1_cwi(data));
		(void) printf("  + Clock Stop: %u (%s)\n", clock,
		    atr_clock_stop_to_string(clock));
		(void) printf("  + IFSC: %u\n", atr_t1_ifsc(data));
		(void) printf("  + CCID Supports NAD: %s\n",
		    ucs->ucs_class.ccd_dwFeatures & CCID_CLASS_F_ALTNAD_SUP ?
		    "yes" : "no");
	}

	atr_data_free(data);
}

static void
ccidadm_atr_verbose(uccid_cmd_status_t *ucs)
{
	int ret;
	atr_data_t *data;

	if ((data = atr_data_alloc()) == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory for "
		    "ATR data");
	}

	ret = atr_parse(ucs->ucs_atr, ucs->ucs_atrlen, data);
	if (ret != ATR_CODE_OK) {
		errx(EXIT_FAILURE, "failed to parse ATR data: %s",
		    atr_strerror(ret));
	}
	atr_data_dump(data, stdout);
	atr_data_free(data);
}

typedef struct cciadm_atr_args {
	boolean_t caa_hex;
	boolean_t caa_props;
	boolean_t caa_verbose;
} ccidadm_atr_args_t;

static void
ccidadm_atr_fetch(int fd, const char *name, void *arg)
{
	uccid_cmd_status_t ucs;
	ccidadm_atr_args_t *caa = arg;

	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;

	if (ioctl(fd, UCCID_CMD_STATUS, &ucs) != 0) {
		err(EXIT_FAILURE, "failed to issue status ioctl to %s",
		    name);
	}

	if (ucs.ucs_atrlen == 0) {
		warnx("slot %s has no card inserted or activated", name);
		return;
	}

	(void) printf("ATR for %s (%u bytes):\n", name, ucs.ucs_atrlen);
	if (caa->caa_props) {
		ccidadm_atr_props(&ucs);
	}

	if (caa->caa_hex) {
		atr_data_hexdump(ucs.ucs_atr, ucs.ucs_atrlen, stdout);
	}

	if (caa->caa_verbose) {
		ccidadm_atr_verbose(&ucs);
	}
}

static void
ccidadm_do_atr(int argc, char *argv[])
{
	uint_t i;
	int c;
	ccidadm_atr_args_t caa;

	bzero(&caa, sizeof (caa));
	optind = 0;
	while ((c = getopt(argc, argv, "vx")) != -1) {
		switch (c) {
		case 'v':
			caa.caa_verbose = B_TRUE;
			break;
		case 'x':
			caa.caa_hex = B_TRUE;
			break;
		case ':':
			errx(EXIT_USAGE, "Option -%c requires an argument\n",
			    optopt);
			break;
		case '?':
			errx(EXIT_USAGE, "Unknown option: -%c\n", optopt);
			break;
		}
	}

	if (!caa.caa_verbose && !caa.caa_props && !caa.caa_hex) {
		caa.caa_props = B_TRUE;
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		ccidadm_iter(B_FALSE, B_TRUE, ccidadm_atr_fetch, &caa);
		return;
	}

	for (i = 0; i < argc; i++) {
		int fd;

		if ((fd = ccidadm_open(argv[i], B_FALSE)) < 0) {
			warn("failed to open %s", argv[i]);
			errx(EXIT_FAILURE, "valid CCID slot?");
		}

		ccidadm_atr_fetch(fd, argv[i], &caa);
		(void) close(fd);
		if (i + 1 < argc) {
			(void) printf("\n");
		}
	}
}

static void
ccidadm_atr_usage(FILE *out)
{
	(void) fprintf(out, "\tatr [-vx]\t[device] ...\n");
}

static void
ccidadm_print_pairs(uint32_t val, ccidadm_pair_t *ccp)
{
	while (ccp->ccp_name != NULL) {
		if ((val & ccp->ccp_val) == ccp->ccp_val) {
			(void) printf("    + %s\n", ccp->ccp_name);
		}
		ccp++;
	}
}

static ccidadm_pair_t ccidadm_p_protocols[] = {
	{ 0x01, "T=0" },
	{ 0x02, "T=1" },
	{ 0x0, NULL }
};

static ccidadm_pair_t ccidadm_p_voltages[] = {
	{ CCID_CLASS_VOLT_5_0, "5.0 V" },
	{ CCID_CLASS_VOLT_3_0, "3.0 V" },
	{ CCID_CLASS_VOLT_1_8, "1.8 V" },
	{ 0x0, NULL }
};

static ccidadm_pair_t ccidadm_p_syncprots[] = {
	{ 0x01, "2-Wire Support" },
	{ 0x02, "3-Wire Support" },
	{ 0x04, "I2C Support" },
	{ 0x0, NULL }
};

static ccidadm_pair_t ccidadm_p_mechanical[] = {
	{ CCID_CLASS_MECH_CARD_ACCEPT, "Card Accept Mechanism" },
	{ CCID_CLASS_MECH_CARD_EJECT, "Card Eject Mechanism" },
	{ CCID_CLASS_MECH_CARD_CAPTURE, "Card Capture Mechanism" },
	{ CCID_CLASS_MECH_CARD_LOCK, "Card Lock/Unlock Mechanism" },
	{ 0x0, NULL }
};

static ccidadm_pair_t ccidadm_p_features[] = {
	{ CCID_CLASS_F_AUTO_PARAM_ATR,
	    "Automatic parameter configuration based on ATR data" },
	{ CCID_CLASS_F_AUTO_ICC_ACTIVATE,
	    "Automatic activation on ICC insertion" },
	{ CCID_CLASS_F_AUTO_ICC_VOLTAGE, "Automatic ICC voltage selection" },
	{ CCID_CLASS_F_AUTO_ICC_CLOCK,
	    "Automatic ICC clock frequency change" },
	{ CCID_CLASS_F_AUTO_BAUD, "Automatic baud rate change" },
	{ CCID_CLASS_F_AUTO_PARAM_NEG,
	    "Automatic parameter negotiation by CCID" },
	{ CCID_CLASS_F_AUTO_PPS, "Automatic PPS made by CCID" },
	{ CCID_CLASS_F_ICC_CLOCK_STOP, "CCID can set ICC in clock stop mode" },
	{ CCID_CLASS_F_ALTNAD_SUP, "NAD value other than zero accepted" },
	{ CCID_CLASS_F_AUTO_IFSD, "Automatic IFSD exchange" },
	{ CCID_CLASS_F_TPDU_XCHG, "TPDU support" },
	{ CCID_CLASS_F_SHORT_APDU_XCHG, "Short APDU support" },
	{ CCID_CLASS_F_EXT_APDU_XCHG, "Short and Extended APDU support" },
	{ CCID_CLASS_F_WAKE_UP, "USB Wake Up signaling support" },
	{ 0x0, NULL }
};

static ccidadm_pair_t ccidadm_p_pin[] = {
	{ CCID_CLASS_PIN_VERIFICATION, "PIN verification" },
	{ CCID_CLASS_PIN_MODIFICATION, "PIN modification" },
	{ 0x0, NULL }
};

static void
ccidadm_reader_print(int fd, const char *name, void *unused __unused)
{
	uccid_cmd_status_t ucs;
	ccid_class_descr_t *cd;
	char nnbuf[NN_NUMBUF_SZ + 1];

	bzero(&ucs, sizeof (uccid_cmd_status_t));
	ucs.ucs_version = UCCID_CURRENT_VERSION;

	if (ioctl(fd, UCCID_CMD_STATUS, &ucs) != 0) {
		err(EXIT_FAILURE, "failed to issue status ioctl to %s",
		    name);
	}

	cd = &ucs.ucs_class;
	(void) printf("Reader %s, CCID class v%u.%u device:\n", name,
	    CCID_VERSION_MAJOR(cd->ccd_bcdCCID),
	    CCID_VERSION_MINOR(cd->ccd_bcdCCID));

	if ((ucs.ucs_status & UCCID_STATUS_F_PRODUCT_VALID) == 0) {
		(void) strlcpy(ucs.ucs_product, "<unknown>",
		    sizeof (ucs.ucs_product));
	}

	if ((ucs.ucs_status & UCCID_STATUS_F_SERIAL_VALID) == 0) {
		(void) strlcpy(ucs.ucs_serial, "<unknown>",
		    sizeof (ucs.ucs_serial));
	}

	(void) printf("  Product: %s\n", ucs.ucs_product);
	(void) printf("  Serial: %s\n", ucs.ucs_serial);
	(void) printf("  Slots Present: %u\n", cd->ccd_bMaxSlotIndex + 1);
	(void) printf("  Maximum Busy Slots: %u\n", cd->ccd_bMaxCCIDBusySlots);
	(void) printf("  Supported Voltages:\n");
	ccidadm_print_pairs(cd->ccd_bVoltageSupport, ccidadm_p_voltages);
	(void) printf("  Supported Protocols:\n");
	ccidadm_print_pairs(cd->ccd_dwProtocols, ccidadm_p_protocols);
	nicenum_scale(cd->ccd_dwDefaultClock, 1000, nnbuf,
	    sizeof (nnbuf), NN_DIVISOR_1000 | NN_UNIT_SPACE);
	(void) printf("  Default Clock: %sHz\n", nnbuf);
	nicenum_scale(cd->ccd_dwMaximumClock, 1000, nnbuf,
	    sizeof (nnbuf), NN_DIVISOR_1000 | NN_UNIT_SPACE);
	(void) printf("  Maximum Clock: %sHz\n", nnbuf);
	(void) printf("  Supported Clock Rates: %u\n",
	    cd->ccd_bNumClockSupported);
	nicenum_scale(cd->ccd_dwDataRate, 1, nnbuf, sizeof (nnbuf),
	    NN_DIVISOR_1000 | NN_UNIT_SPACE);
	(void) printf("  Default Data Rate: %sbps\n", nnbuf);
	nicenum_scale(cd->ccd_dwMaxDataRate, 1, nnbuf, sizeof (nnbuf),
	    NN_DIVISOR_1000 | NN_UNIT_SPACE);
	(void) printf("  Maximum Data Rate: %sbps\n", nnbuf);
	(void) printf("  Supported Data Rates: %u\n",
	    cd->ccd_bNumDataRatesSupported);
	(void) printf("  Maximum IFSD (T=1 only): %u\n", cd->ccd_dwMaxIFSD);
	if (cd->ccd_dwSyncProtocols != 0) {
		(void) printf("  Synchronous Protocols Supported:\n");
		ccidadm_print_pairs(cd->ccd_dwSyncProtocols,
		    ccidadm_p_syncprots);
	}
	if (cd->ccd_dwMechanical != 0) {
		(void) printf("  Mechanical Features:\n");
		ccidadm_print_pairs(cd->ccd_dwMechanical, ccidadm_p_mechanical);
	}
	if (cd->ccd_dwFeatures != 0) {
		(void) printf("  Device Features:\n");
		ccidadm_print_pairs(cd->ccd_dwFeatures, ccidadm_p_features);
	}
	(void) printf("  Maximum Message Length: %u bytes\n",
	    cd->ccd_dwMaxCCIDMessageLength);
	if (cd->ccd_dwFeatures & CCID_CLASS_F_EXT_APDU_XCHG) {
		if (cd->ccd_bClassGetResponse == 0xff) {
			(void) printf("  Default Get Response Class: echo\n");
		} else {
			(void) printf("  Default Get Response Class: %u\n",
			    cd->ccd_bClassGetResponse);
		}
		if (cd->ccd_bClassEnvelope == 0xff) {
			(void) printf("  Default Envelope Class: echo\n");
		} else {
			(void) printf("  Default Envelope Class: %u\n",
			    cd->ccd_bClassEnvelope);
		}
	}
	if (cd->ccd_wLcdLayout != 0) {
		(void) printf("  %2ux%2u LCD present\n",
		    cd->ccd_wLcdLayout >> 8, cd->ccd_wLcdLayout & 0xff);
	}

	if (cd->ccd_bPinSupport) {
		(void) printf("  Pin Support:\n");
		ccidadm_print_pairs(cd->ccd_bPinSupport, ccidadm_p_pin);
	}
}

static void
ccidadm_do_reader(int argc, char *argv[])
{
	int i;

	if (argc == 0) {
		ccidadm_iter(B_TRUE, B_TRUE, ccidadm_reader_print, NULL);
		return;
	}

	for (i = 0; i < argc; i++) {
		int fd;

		if ((fd = ccidadm_open(argv[i], B_TRUE)) < 0) {
			warn("failed to open %s", argv[i]);
			errx(EXIT_FAILURE, "valid ccid reader");
		}

		ccidadm_reader_print(fd, argv[i], NULL);
		(void) close(fd);
		if (i + 1 < argc) {
			(void) printf("\n");
		}
	}
}

static void
ccidadm_reader_usage(FILE *out)
{
	(void) fprintf(out, "\treader\t\t[reader] ...\n");
}

typedef struct ccidadm_cmdtab {
	const char *cc_name;
	void (*cc_op)(int, char *[]);
	void (*cc_usage)(FILE *);
} ccidadm_cmdtab_t;

static ccidadm_cmdtab_t ccidadm_cmds[] = {
	{ "list", ccidadm_do_list, ccidadm_list_usage },
	{ "atr", ccidadm_do_atr, ccidadm_atr_usage },
	{ "reader", ccidadm_do_reader, ccidadm_reader_usage },
	{ NULL }
};

static int
ccidadm_usage(const char *format, ...)
{
	ccidadm_cmdtab_t *tab;

	if (format != NULL) {
		va_list ap;

		va_start(ap, format);
		(void) fprintf(stderr, "%s: ", ccidadm_pname);
		(void) vfprintf(stderr, format, ap);
		(void) fprintf(stderr, "\n");
		va_end(ap);
	}

	(void) fprintf(stderr, "usage:  %s <subcommand> <args> ...\n\n",
	    ccidadm_pname);
	(void) fprintf(stderr, "Subcommands:\n");
	for (tab = ccidadm_cmds; tab->cc_name != NULL; tab++) {
		tab->cc_usage(stderr);
	}

	return (EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	ccidadm_cmdtab_t *tab;

	ccidadm_pname = basename(argv[0]);
	if (argc < 2) {
		return (ccidadm_usage("missing required subcommand"));
	}

	for (tab = ccidadm_cmds; tab->cc_name != NULL; tab++) {
		if (strcmp(argv[1], tab->cc_name) == 0) {
			argc -= 2;
			argv += 2;
			tab->cc_op(argc, argv);
			return (EXIT_SUCCESS);
		}
	}

	return (ccidadm_usage("unknown command: %s", argv[1]));
}
