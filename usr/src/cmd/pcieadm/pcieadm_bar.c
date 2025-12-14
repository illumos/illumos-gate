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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Implement logic related to listing, reading, and writing BARs.
 */

#include <err.h>
#include <stdio.h>
#include <sys/pci.h>
#include <ofmt.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "pcieadm.h"

static void
pcieadm_bar_list_usage(FILE *f)
{
	(void) fprintf(f, "\tbar list\t[-H] [-o field,... [-p]] -d device "
	    "[filter...]\n");
}

static void
pcieadm_bar_list_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:  %s bar list [-H] [-o field,... [-p]] "
	    "-d device [filter,...]\n", pcieadm_progname);
	(void) fprintf(stderr, "List BARs specific to a single device.\n\n"
	    "\t-d device\tlist BARs from the specified device (driver instance,"
	    "\n\t\t\t/devices path, or b/d/f)\n"
	    "\t-H\t\tomit the column header\n"
	    "\t-o field\toutput fields to print (required for -p)\n"
	    "\t-p\t\tparsable output (requires -o)\n\n");
	(void) fprintf(stderr, "The following fields are supported:\n"
	    "\taddress\t\tthe address programmed in the BAR\n"
	    "\tbar\t\tthe bar's numeric identifier\n"
	    "\tdesc\t\ta human description of the BAR\n"
	    "\tmtype\t\tthe memory type of the BAR\n"
	    "\tprefetech\tindicates whether or not the BAR is pre-fetchable\n"
	    "\traw\t\tthe raw contents of the hardware BAR register\n"
	    "\tsize\t\tthe size of the bar\n"
	    "\tspace\t\tthe type of space the BAR represents\n"
	    "\twidth\t\tindicates the width of the BAR in bytes\n");
	(void) fprintf(stderr, "The following filters are supported:\n"
	    "\t<index>\t\tthe BAR matches the specified index\n"
	    "\tio\t\tthe BAR is an I/O BAR\n"
	    "\tmem\t\tthe BAR is a memory BAR\n"
	    "\tmem32\t\tthe BAR is a 32-bit memory BAR\n"
	    "\tmem64\t\tthe BAR is a 64-bit memory BAR\n"
	    "\tprefetch\tthe BAR is prefetchable\n");
}

typedef enum pcieadm_bar_list_otype {
	PCIEADM_BAR_LIST_BAR,
	PCIEADM_BAR_LIST_ADDRESS,
	PCIEADM_BAR_LIST_DESC,
	PCIEADM_BAR_LIST_MTYPE,
	PCIEADM_BAR_LIST_SIZE,
	PCIEADM_BAR_LIST_SPACE,
	PCIEADM_BAR_LIST_PREFETCH,
	PCIEADM_BAR_LIST_WIDTH,
	PCIEADM_BAR_LIST_RAW
} pcieadm_bar_list_otpye_t;

typedef struct pcieadm_bar_list_ofmt {
	uint8_t pblo_idx;
	uint8_t pblo_width;
	bool pblo_mem;
	bool pblo_prefetch;
	uint64_t pblo_addr;
	uint64_t pblo_size;
	uint64_t pblo_raw;
	const char *pblo_mtype;
} pcieadm_bar_list_ofmt_t;

static boolean_t
pcieadm_bar_list_ofmt_cb(ofmt_arg_t *ofarg, char *buf, uint_t buflen)
{
	size_t ret;
	const pcieadm_bar_list_ofmt_t *pblo = ofarg->ofmt_cbarg;

	switch (ofarg->ofmt_id) {
	case PCIEADM_BAR_LIST_BAR:
		ret = snprintf(buf, buflen, "%u", pblo->pblo_idx);
		break;
	case PCIEADM_BAR_LIST_ADDRESS:
		ret = snprintf(buf, buflen, "0x%" PRIx64, pblo->pblo_addr);
		break;
	case PCIEADM_BAR_LIST_DESC:
		if (pblo->pblo_mem) {
			ret = snprintf(buf, buflen, "%s%s Memory",
			    pblo->pblo_mtype, pblo->pblo_prefetch ?
			    " Prefetchable" : "");
		} else {
			ret = strlcat(buf, "I/O", buflen);
		}
		break;
	case PCIEADM_BAR_LIST_MTYPE:
		ret = strlcat(buf, pblo->pblo_mtype, buflen);
		break;
	case PCIEADM_BAR_LIST_SIZE:
		ret = snprintf(buf, buflen, "0x%" PRIx64, pblo->pblo_size);
		break;
	case PCIEADM_BAR_LIST_SPACE:
		ret = strlcat(buf, pblo->pblo_mem ? "Memory" : "I/O", buflen);
		break;
	case PCIEADM_BAR_LIST_PREFETCH:
		ret = strlcat(buf, pblo->pblo_prefetch ? "yes" : "no", buflen);
		break;
	case PCIEADM_BAR_LIST_WIDTH:
		ret = snprintf(buf, buflen, "%u", pblo->pblo_width);
		break;
	case PCIEADM_BAR_LIST_RAW:
		ret = snprintf(buf, buflen, "0x%" PRIx64, pblo->pblo_raw);
		break;
	default:
		return (B_FALSE);
	}

	return (buflen > ret);
}

static const char *pcieadm_bar_list_fields = "bar,size,address,desc";
static const ofmt_field_t pcieadm_bar_list_ofmt[] = {
	{ "BAR", 8, PCIEADM_BAR_LIST_BAR, pcieadm_bar_list_ofmt_cb },
	{ "ADDRESS", 16, PCIEADM_BAR_LIST_ADDRESS, pcieadm_bar_list_ofmt_cb },
	{ "DESC", 32, PCIEADM_BAR_LIST_DESC, pcieadm_bar_list_ofmt_cb },
	{ "MTYPE", 8, PCIEADM_BAR_LIST_MTYPE, pcieadm_bar_list_ofmt_cb },
	{ "SIZE", 12, PCIEADM_BAR_LIST_SIZE, pcieadm_bar_list_ofmt_cb },
	{ "SPACE", 10, PCIEADM_BAR_LIST_SPACE, pcieadm_bar_list_ofmt_cb },
	{ "PREFETCH", 4, PCIEADM_BAR_LIST_PREFETCH, pcieadm_bar_list_ofmt_cb },
	{ "WIDTH", 6, PCIEADM_BAR_LIST_WIDTH, pcieadm_bar_list_ofmt_cb },
	{ "RAW", 16, PCIEADM_BAR_LIST_RAW, pcieadm_bar_list_ofmt_cb },
};

static bool
pcieadm_show_bar_match(const pcieadm_bar_list_ofmt_t *pblo, int nfilts,
    char **filts, bool *used)
{
	bool match = false;

	if (nfilts <= 0) {
		return (true);
	}

	for (int i = 0; i < nfilts; i++) {
		if (strcmp(filts[i], "io") == 0 && !pblo->pblo_mem) {
			used[i] = true;
			match = true;
			continue;
		}

		if (strcmp(filts[i], "mem32") == 0 &&
		    strcmp(pblo->pblo_mtype, "32-bit") == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		if (strcmp(filts[i], "mem64") == 0 &&
		    strcmp(pblo->pblo_mtype, "64-bit") == 0) {
			used[i] = true;
			match = true;
			continue;
		}

		if (strcmp(filts[i], "mem") == 0 && pblo->pblo_mem) {
			used[i] = true;
			match = true;
			continue;
		}

		if (strcmp(filts[i], "prefetch") == 0 && pblo->pblo_prefetch) {
			used[i] = true;
			match = true;
			continue;
		}

		/*
		 * Attempt to parse anything left as an integer indicating a BAR
		 * index.
		 */
		const char *errstr;
		long long l = strtonumx(filts[i], 0, UINT32_MAX, &errstr, 0);
		if (errstr == NULL && l == pblo->pblo_idx) {
			used[i] = true;
			match = true;
			continue;
		}
	}

	return (match);
}

/*
 * Read information about BARs. There are basically two different sources that
 * we want to combine information from: reg[] and the device itself. We prefer
 * reg[] over assigned-addresses[] because the latter may not exist if we have
 * some kind of resource error.
 *
 * We prefer to walk the device itself and then augment it with size information
 * from reg[] as reg[] will skip unimplemented BARs and we want to be able to
 * accurately indicate the type and other information of a BAR with zero size.
 */
static int
pcieadm_bar_list(pcieadm_t *pcip, int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	const char *device = NULL;
	const pcieadm_ops_t *ops;
	void *readarg;
	uint8_t hdr, nbar;
	uint_t flags = 0;
	bool parse = false, *filts = NULL, found = false;
	const char *fields = NULL;
	ofmt_status_t oferr;
	ofmt_handle_t ofmt;

	while ((c = getopt(argc, argv, ":d:Ho:p")) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 'H':
			flags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'p':
			parse = true;
			flags |= OFMT_PARSABLE;
			break;
		case ':':
			pcieadm_bar_list_help("Option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
		default:
			pcieadm_bar_list_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	if (device == NULL) {
		pcieadm_bar_list_help("missing required device argument (-d)");
		exit(EXIT_USAGE);
	}

	if (parse && fields == NULL) {
		errx(EXIT_USAGE, "-p requires fields specified with -o");
	}

	if (fields == NULL) {
		fields = pcieadm_bar_list_fields;
	}

	argc -= optind;
	argv += optind;

	if (argc > 0) {
		filts = calloc(argc, sizeof (bool));
		if (filts == NULL) {
			err(EXIT_FAILURE, "failed to allocate filter tracking "
			    "memory");
		}
	}

	oferr = ofmt_open(fields, pcieadm_bar_list_ofmt, flags, 0, &ofmt);
	ofmt_check(oferr, parse, ofmt, pcieadm_ofmt_errx, warnx);

	/*
	 * We will need full privileges to get information from the device.
	 */
	priv_fillset(pcip->pia_priv_eff);

	pcieadm_find_dip(pcip, device);
	int *reg;
	int nreg = di_prop_lookup_ints(DDI_DEV_T_ANY, pcip->pia_devi,
	    "reg", &reg);
	if (nreg < 0 && errno != ENXIO) {
		err(EXIT_FAILURE, "failed to look up reg[] property");
	} else if (nreg < 0) {
		nreg = 0;
	} else if (nreg % 5 != 0) {
		errx(EXIT_FAILURE, "reg[] property has wrong shape, found %d "
		    "integers but expected a multiple of 5", nreg);
	}
	nreg /= 5;

	pcieadm_init_ops_kernel(pcip, &ops, &readarg);
	if (!ops->pop_cfg(PCI_CONF_HEADER, sizeof (hdr), &hdr, readarg)) {
		errx(EXIT_FAILURE, "failed to read offset %u from device "
		    "configuration space", PCI_CONF_HEADER);
	}

	switch (hdr & PCI_HEADER_TYPE_M) {
	case PCI_HEADER_ZERO:
		nbar = PCI_BASE_NUM;
		break;
	case PCI_HEADER_ONE:
		nbar = PCI_BCNF_BASE_NUM;
		break;
	case PCI_HEADER_TWO:
	default:
		errx(EXIT_FAILURE, "unsupported PCI header type: 0x%x",
		    hdr & PCI_HEADER_TYPE_M);
	}

	/*
	 * First do a pass where we read all of the raw BAR registers from the
	 * device.
	 */
	uint32_t raw[PCI_BASE_NUM];
	for (uint8_t i = 0; i < nbar; i++) {
		if (!ops->pop_cfg(PCI_CONF_BASE0 + i * 4, sizeof (uint32_t),
		    &raw[i], readarg)) {
			errx(EXIT_FAILURE, "failed to read BAR data form "
			    "device at offset 0x%x", PCI_CONF_BASE0 + i * 4);
		}
	}

	/*
	 * Go through and process each BAR entry. Determine where we have a
	 * 64-bit BAR and therefore need to account for two entries here. This
	 * is also where we try to marry things up to assigned-addresses to
	 * determine the size.
	 */
	for (uint8_t i = 0; i < nbar; i++) {
		pcieadm_bar_list_ofmt_t arg;

		(void) memset(&arg, 0, sizeof (arg));
		arg.pblo_idx = i;
		arg.pblo_width = PCI_BAR_SZ_32;
		arg.pblo_raw = raw[i];
		arg.pblo_prefetch = false;

		if ((raw[i] & PCI_BASE_SPACE_M) == PCI_BASE_SPACE_IO) {
			arg.pblo_mem = false;
			arg.pblo_addr = raw[i] & PCI_BASE_IO_ADDR_M;
			arg.pblo_mtype = "--";
		} else {
			arg.pblo_mem = true;
			arg.pblo_addr = raw[i] & PCI_BASE_M_ADDR_M;

			if ((raw[i] & PCI_BASE_TYPE_M) == PCI_BASE_TYPE_ALL) {
				i++;
				if (i == nbar) {
					warnx("device %s has corrupt BAR %u: "
					    "no additional BARs exist for "
					    "upper 32-bit data", device,
					    arg.pblo_idx);
					ret = EXIT_FAILURE;
					continue;
				}
				arg.pblo_width = PCI_BAR_SZ_64;
				arg.pblo_raw |= (uint64_t)raw[i] << 32;
				arg.pblo_addr |= (uint64_t)raw[i] << 32;
			}

			if ((arg.pblo_raw & PCI_BASE_PREF_M) != 0) {
				arg.pblo_prefetch = true;
			}

			switch (arg.pblo_raw & PCI_BASE_TYPE_M) {
			case PCI_BASE_TYPE_MEM:
				arg.pblo_mtype = "32-bit";
				break;
			case PCI_BASE_TYPE_LOW:
				arg.pblo_mtype = "1M";
				break;
			case PCI_BASE_TYPE_ALL:
				arg.pblo_mtype = "64-bit";
				break;
			case PCI_BASE_TYPE_RES:
				arg.pblo_mtype = "reserved";
				break;
			}
		}

		/*
		 * Finally, before we call back, determine what the size of this
		 * BAR is. We walk reg[] to try to find a matching register
		 * index, which is considered the offset into configuration
		 * space of the start of this BAR.
		 *
		 * If we can't find a match, then it likely is because the BAR
		 * has no size. Using reg[] versus assigned-addresses[] gives us
		 * a reasonable confidence here, though this doesn't account for
		 * resizable BAR support.
		 */
		arg.pblo_size = 0;
		uint32_t targ = PCI_CONF_BASE0 + arg.pblo_idx *
		    sizeof (uint32_t);
		const pci_regspec_t *rsp = (pci_regspec_t *)reg;
		for (int ridx = 0; ridx < nreg; ridx++, rsp++) {
			uint32_t check = PCI_REG_REG_G(rsp->pci_phys_hi);

			if (targ == check) {
				arg.pblo_size = (uint64_t)rsp->pci_size_hi <<
				    32;
				arg.pblo_size |= rsp->pci_size_low;
				break;
			}
		}

		if (pcieadm_show_bar_match(&arg, argc, argv, filts)) {
			found = true;
			ofmt_print(ofmt, &arg);
		}
	}

	for (int i = 0; i < argc; i++) {
		if (!filts[i]) {
			warnx("filter '%s' did not match any BARs", argv[i]);
			ret = EXIT_FAILURE;
		}
	}

	if (!found) {
		ret = EXIT_FAILURE;
	}

	free(filts);
	pcieadm_fini_ops_kernel(readarg);
	ofmt_close(ofmt);

	return (ret);
}

static void
pcieadm_bar_read_usage(FILE *f)
{
	(void) fprintf(f, "\tbar read\t[-l length] -d device -b bar reg\n");
}

static void
pcieadm_bar_read_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:  %s bar read [-l length] -d device "
	    "-b bar reg\n", pcieadm_progname);
	(void) fprintf(stderr, "Read data at offset <reg> from a device "
	    "BAR.\n\n"
	    "\t-b bar\t\tthe index of the BAR to read from\n"
	    "\t-d device\tread BAR from the specified device (driver instance,"
	    "\n\t\t\t/devices path, or b/d/f)\n"
	    "\t-l length\tspecify the number of bytes to read: 1, 2, 4 "
	    "(default),\n\t\t\tor 8\n");
}

/*
 * We can't use strtonumx here as its maximum values are all based in signed
 * integers.
 */
static uint64_t
pcieadm_bar_parse_u64(const char *reg, const char *desc)
{
	char *eptr;
	unsigned long long ull;

	errno = 0;
	ull = strtoull(reg, &eptr, 0);
	if (errno != 0 || *eptr != '\0') {
		errx(EXIT_FAILURE, "failed to parse %s %s", desc, reg);
	}

	return ((uint64_t)ull);
}

static uint8_t
pcieadm_bar_parse_len(const char *len)
{
	char *eptr;
	unsigned long ul;

	errno = 0;
	ul = strtoul(len, &eptr, 0);
	if (errno != 0 || *eptr != '\0') {
		errx(EXIT_FAILURE, "failed to parse length %s", len);
	}

	if (ul != 1 && ul != 2 && ul != 4 && ul != 8) {
		errx(EXIT_FAILURE, "invalid byte length 0x%lx: only 1, 2, 4, "
		    "and 8 byte I/Os are supported", ul);
	}

	return ((uint8_t)ul);
}

static uint8_t
pcieadm_bar_parse_bar(const char *bar)
{
	uint8_t val;
	const char *errstr;
	val = (uint8_t)strtonumx(bar, 0, PCI_BASE_NUM - 1, &errstr, 0);
	if (errstr != NULL) {
		errx(EXIT_FAILURE, "failed to parse BAR %s: value is %s", bar,
		    errstr);
	}

	return (val);
}

static int
pcieadm_bar_read(pcieadm_t *pcip, int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	const char *device = NULL, *barstr = NULL, *lenstr = NULL;
	const pcieadm_ops_t *ops;
	void *karg;

	while ((c = getopt(argc, argv, ":b:d:l:")) != -1) {
		switch (c) {
		case 'b':
			barstr = optarg;
			break;
		case 'd':
			device = optarg;
			break;
		case 'l':
			lenstr = optarg;
			break;
		case ':':
			pcieadm_bar_read_help("Option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
		default:
			pcieadm_bar_read_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	if (device == NULL) {
		pcieadm_bar_read_help("missing required device argument (-d)");
		exit(EXIT_USAGE);
	}

	if (barstr == NULL) {
		pcieadm_bar_read_help("missing required bar argument (-b)");
		exit(EXIT_USAGE);
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		errx(EXIT_FAILURE, "missing required register");
	} else if (argc > 1) {
		errx(EXIT_FAILURE, "only a single register may be read");
	}

	uint8_t bar = pcieadm_bar_parse_bar(barstr);
	uint8_t len = 4;
	if (lenstr != NULL) {
		len = pcieadm_bar_parse_len(lenstr);
	}
	uint64_t reg = pcieadm_bar_parse_u64(argv[0], "register");
	void *buf = calloc(1, len);
	if (buf == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory for read request");
	}

	/*
	 * We will need full privileges to read a BAR.
	 */
	priv_fillset(pcip->pia_priv_eff);

	pcieadm_find_dip(pcip, device);
	pcieadm_init_ops_kernel(pcip, &ops, &karg);

	if (!ops->pop_bar(bar, len, reg, buf, karg, B_FALSE)) {
		errx(EXIT_FAILURE, "failed to read %u bytes at 0x%" PRIx64
		    " from BAR %u", len, reg, bar);
	}

	switch (len) {
	case 1:
		(void) printf("0x%x\n", *(uint8_t *)buf);
		break;
	case 2:
		(void) printf("0x%x\n", *(uint16_t *)buf);
		break;
	case 4:
		(void) printf("0x%x\n", *(uint32_t *)buf);
		break;
	case 8:
		(void) printf("0x%x\n", *(uint64_t *)buf);
		break;
	default:
		abort();
	}

	free(buf);
	pcieadm_fini_ops_kernel(karg);

	return (ret);
}

static void
pcieadm_bar_write_usage(FILE *f)
{
	(void) fprintf(f, "\tbar write\t[-l length] -d device -b bar "
	    "reg=value\n");
}

static void
pcieadm_bar_write_help(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "Usage:  %s bar write [-l length] -d device "
	    "-b bar reg=value", pcieadm_progname);
	(void) fprintf(stderr, "Usage:  %s bar write [-l length] -d device "
	    "-b bar reg=value\n", pcieadm_progname);
	(void) fprintf(stderr, "Write data to a device BAR at offset <reg>.\n\n"
	    "\t-b bar\t\tthe index of the BAR to write to\n"
	    "\t-d device\tread BAR from the specified device (driver instance,"
	    "\n\t\t\t/devices path, or b/d/f)\n"
	    "\t-l length\tspecify the number of bytes to read: 1, 2, 4 "
	    "(default),\n\t\t\tor 8\n");

}

static int
pcieadm_bar_write(pcieadm_t *pcip, int argc, char *argv[])
{
	int c, ret = EXIT_SUCCESS;
	const char *device = NULL, *barstr = NULL, *lenstr = NULL;
	const pcieadm_ops_t *ops;
	void *karg;

	while ((c = getopt(argc, argv, ":b:d:l:")) != -1) {
		switch (c) {
		case 'b':
			barstr = optarg;
			break;
		case 'd':
			device = optarg;
			break;
		case 'l':
			lenstr = optarg;
			break;
		case ':':
			pcieadm_bar_write_help("Option -%c requires an "
			    "argument", optopt);
			exit(EXIT_USAGE);
		case '?':
		default:
			pcieadm_bar_write_help("unknown option: -%c",
			    optopt);
			exit(EXIT_USAGE);
		}
	}

	if (device == NULL) {
		pcieadm_bar_write_help("missing required device argument (-d)");
		exit(EXIT_USAGE);
	}

	if (barstr == NULL) {
		pcieadm_bar_write_help("missing required bar argument (-b)");
		exit(EXIT_USAGE);
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		errx(EXIT_FAILURE, "missing required register");
	} else if (argc > 1) {
		errx(EXIT_FAILURE, "only a single register may be read");
	}
	char *eq = strchr(argv[0], '=');
	if (eq == NULL) {
		errx(EXIT_FAILURE, "failed to parse value string %s: missing "
		    "equals ('=') separator", argv[0]);
	} else if (eq[1] == '\0') {
		errx(EXIT_FAILURE, "missing a value after the equals ('=') "
		    "separator");
	}
	*eq = '\0';

	uint8_t bar = pcieadm_bar_parse_bar(barstr);
	uint8_t len = 4;
	if (lenstr != NULL) {
		len = pcieadm_bar_parse_len(lenstr);
	}
	void *buf = malloc(len);
	if (buf == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory for read request");
	}
	uint64_t reg = pcieadm_bar_parse_u64(argv[0], "register");
	uint64_t value = pcieadm_bar_parse_u64(eq + 1, "value");

	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	switch (len) {
	case 1:
		if (value > UINT8_MAX) {
			errx(EXIT_FAILURE, "value %s is too large for a "
			    "1 byte write", eq + 1);
		}
		u8 = (uint8_t)value;
		(void) memcpy(buf, &u8, sizeof (uint8_t));
		break;
	case 2:
		if (value > UINT16_MAX) {
			errx(EXIT_FAILURE, "value %s is too large for a "
			    "2 byte write", eq + 1);
		}
		u16 = (uint8_t)value;
		(void) memcpy(buf, &u16, sizeof (uint16_t));
		break;
	case 4:
		if (value > UINT32_MAX) {
			errx(EXIT_FAILURE, "value %s is too large for a "
			    "4 byte write", eq + 1);
		}
		u32 = (uint32_t)value;
		(void) memcpy(buf, &u32, sizeof (uint32_t));
		break;
	case 8:
		(void) memcpy(buf, &value, sizeof (uint64_t));
		break;
	default:
		abort();
	}


	/*
	 * We will need full privileges to read a BAR.
	 */
	priv_fillset(pcip->pia_priv_eff);

	pcieadm_find_dip(pcip, device);
	pcieadm_init_ops_kernel(pcip, &ops, &karg);

	if (!ops->pop_bar(bar, len, reg, buf, karg, B_TRUE)) {
		errx(EXIT_FAILURE, "failed to write %u bytes at 0x%" PRIx64
		    " from BAR %u", len, reg, bar);
	}

	pcieadm_fini_ops_kernel(karg);

	return (ret);
}


static const pcieadm_cmdtab_t pcieadm_cmds_dev[] = {
	{ "list", pcieadm_bar_list, pcieadm_bar_list_usage },
	{ "read", pcieadm_bar_read, pcieadm_bar_read_usage },
	{ "write", pcieadm_bar_write, pcieadm_bar_write_usage },
	{ NULL }
};

int
pcieadm_bar(pcieadm_t *pcip, int argc, char *argv[])
{
	return (pcieadm_walk_tab(pcip, pcieadm_cmds_dev, argc, argv));
}

void
pcieadm_bar_usage(FILE *f)
{
	pcieadm_walk_usage(pcieadm_cmds_dev, f);
}
